//! BFD UDP transport (RFC 5881 single-hop, RFC 5883 multihop).
//!
//! BFD Control packets ride UDP between the well-known ports — this
//! module owns the socket model BIRD uses, so lr speakers and BIRD
//! interoperate out of the box:
//!
//! - One **shared receive socket** per (address family, mode) bound
//!   to the well-known port: 3784 single-hop (RFC 5881 §4) or 4784
//!   multihop (RFC 5883 §5). Incoming packets are demultiplexed to
//!   sessions by Your Discriminator (or by source address for
//!   discovery packets) one layer up, in the daemon.
//! - One **transmit socket per session** bound to an ephemeral source
//!   port in 49152-65535, the same port for every packet of the
//!   session (RFC 5881 §4).
//! - Single-hop packets are sent with TTL/hop limit 255 and any
//!   received packet with a TTL below 255 is discarded (RFC 5881 §5
//!   — the GTSM-style anti-spoofing rule). Multihop packets are sent
//!   with the default TTL and accepted at any TTL (RFC 5883 §3).
//!
//! ## Platform support
//!
//! | Platform | TTL 255 on transmit | TTL check on receive |
//! |----------|---------------------|----------------------|
//! | Linux    | yes (`IP_TTL` / `IPV6_UNICAST_HOPS`) | yes (`IP_RECVTTL` / `IPV6_RECVHOPLIMIT` + `recvmsg` cmsg) |
//! | other    | IPv4 via `set_ttl` | unavailable — packets pass through with an unknown TTL |
//!
//! Echo packets (port 3785) are not used: the echo function is
//! single-hop-only and optional, and multihop MUST NOT use it
//! (RFC 5883 §3).
//!
//! ## Example
//!
//! ```no_run
//! use std::net::{IpAddr, Ipv4Addr, SocketAddr};
//! use lr_osroute::bfd_transport::{BfdMode, BfdRxSocket, BfdTxSocket};
//!
//! let local = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
//! let mut rx = BfdRxSocket::bind(Some(local), BfdMode::SingleHop).unwrap();
//! let tx = BfdTxSocket::bind_session(Some(local), BfdMode::SingleHop).unwrap();
//! let peer = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2)), 3784);
//! tx.send_to(b"\x20\x00\x03\x18", peer).unwrap();
//! let mut buf = [0u8; 64];
//! match rx.recv_from(&mut buf).unwrap() {
//!     Some((n, src, ttl)) => println!("{} bytes from {} ttl {:?}", n, src, ttl),
//!     None => println!("nothing pending"),
//! }
//! ```

use std::fmt;
use std::net::{IpAddr, SocketAddr, UdpSocket};

/// UDP destination port for single-hop BFD Control (RFC 5881 §4).
pub const BFD_CONTROL_PORT: u16 = 3784;
/// UDP destination port for multihop BFD Control (RFC 5883 §5).
pub const BFD_MULTIHOP_PORT: u16 = 4784;
/// Lower bound of the BFD Control source-port range (RFC 5881 §4).
pub const BFD_SOURCE_PORT_MIN: u16 = 49152;
/// Upper bound of the BFD Control source-port range (RFC 5881 §4).
pub const BFD_SOURCE_PORT_MAX: u16 = 65535;

/// Which UDP encapsulation a session uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BfdMode {
    /// RFC 5881: port 3784, TTL 255 on transmit and receive.
    SingleHop,
    /// RFC 5883: port 4784, default TTL, no receive-side TTL check.
    Multihop,
}

impl BfdMode {
    /// The well-known UDP destination port for this mode.
    pub fn port(self) -> u16 {
        match self {
            Self::SingleHop => BFD_CONTROL_PORT,
            Self::Multihop => BFD_MULTIHOP_PORT,
        }
    }
}

impl fmt::Display for BfdMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::SingleHop => "single-hop",
            Self::Multihop => "multihop",
        })
    }
}

/// Errors from the BFD transport.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BfdTransportError {
    /// A socket syscall failed.
    Os { context: &'static str, errno: i32 },
    /// The ephemeral source-port range is exhausted.
    NoSourcePort,
}

impl fmt::Display for BfdTransportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Os { context, errno } => write!(f, "{context} failed (errno {errno})"),
            Self::NoSourcePort => f.write_str("no free UDP source port in 49152-65535"),
        }
    }
}

impl std::error::Error for BfdTransportError {}

fn os_error(context: &'static str) -> BfdTransportError {
    BfdTransportError::Os {
        context,
        errno: std::io::Error::last_os_error().raw_os_error().unwrap_or(0),
    }
}

fn bind_address(local: Option<IpAddr>, port: u16) -> SocketAddr {
    let ip = local.unwrap_or(IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED));
    SocketAddr::new(ip, port)
}

/// True when the receive-side TTL check (RFC 5881 §5) is enforced on
/// this platform.
pub fn ttl_check_enforced() -> bool {
    cfg!(all(feature = "std", target_os = "linux"))
}

// ---------------------------------------------------------------------------
// Linux: socket options + recvmsg with the TTL ancillary message.
// ---------------------------------------------------------------------------

#[cfg(all(feature = "std", target_os = "linux"))]
mod imp {
    use std::net::{IpAddr, SocketAddr, UdpSocket};
    use std::os::fd::AsRawFd;

    use super::{bind_address, os_error, BfdMode, BfdTransportError};

    const AF_INET: i32 = 2;
    const AF_INET6: i32 = 10;
    const IPPROTO_IP: i32 = 0;
    const IPPROTO_IPV6: i32 = 41;
    const IP_TTL: i32 = 2;
    const IP_RECVTTL: i32 = 12;
    const IPV6_UNICAST_HOPS: i32 = 16;
    const IPV6_HOPLIMIT: i32 = 52;
    const IPV6_RECVHOPLIMIT: i32 = 51;
    const MSG_DONTWAIT: i32 = 0x40;
    const EAGAIN: i32 = 11;

    #[repr(C)]
    struct Iovec {
        iov_base: *mut u8,
        iov_len: usize,
    }

    #[repr(C)]
    struct Msghdr {
        msg_name: *mut core::ffi::c_void,
        msg_namelen: u32,
        msg_iov: *mut Iovec,
        msg_iovlen: usize,
        msg_control: *mut core::ffi::c_void,
        msg_controllen: usize,
        msg_flags: i32,
    }

    #[repr(C)]
    struct Cmsghdr {
        cmsg_len: usize,
        cmsg_level: i32,
        cmsg_type: i32,
    }

    extern "C" {
        fn setsockopt(
            fd: i32,
            level: i32,
            optname: i32,
            optval: *const core::ffi::c_void,
            optlen: u32,
        ) -> i32;
        fn recvmsg(fd: i32, msg: *mut Msghdr, flags: i32) -> isize;
    }

    fn set_sockopt_i32(
        sock: &UdpSocket,
        level: i32,
        optname: i32,
        value: i32,
        context: &'static str,
    ) -> Result<(), BfdTransportError> {
        let fd = sock.as_raw_fd();
        // SAFETY: plain setsockopt with a 4-byte value.
        let rc = unsafe { setsockopt(fd, level, optname, &value as *const i32 as _, 4) };
        if rc < 0 {
            return Err(os_error(context));
        }
        Ok(())
    }

    /// Ask the kernel to attach the received TTL / hop limit to every
    /// datagram as an ancillary message.
    pub fn arm_ttl_rx(sock: &UdpSocket, v6: bool) -> Result<(), BfdTransportError> {
        if v6 {
            set_sockopt_i32(
                sock,
                IPPROTO_IPV6,
                IPV6_RECVHOPLIMIT,
                1,
                "IPV6_RECVHOPLIMIT",
            )
        } else {
            set_sockopt_i32(sock, IPPROTO_IP, IP_RECVTTL, 1, "IP_RECVTTL")
        }
    }

    /// Transmit with TTL / hop limit 255 (RFC 5881 §5).
    pub fn arm_ttl_tx(sock: &UdpSocket, v6: bool) -> Result<(), BfdTransportError> {
        if v6 {
            set_sockopt_i32(
                sock,
                IPPROTO_IPV6,
                IPV6_UNICAST_HOPS,
                255,
                "IPV6_UNICAST_HOPS",
            )
        } else {
            set_sockopt_i32(sock, IPPROTO_IP, IP_TTL, 255, "IP_TTL")
        }
    }

    /// Non-blocking receive returning the payload, source and the
    /// received TTL when the kernel reports it.
    pub fn recv_from_with_ttl(
        sock: &UdpSocket,
        buf: &mut [u8],
    ) -> Result<Option<(usize, SocketAddr, Option<u8>)>, BfdTransportError> {
        let fd = sock.as_raw_fd();
        let mut name = [0u8; 128];
        let mut control = [0u8; 128];
        let mut iov = Iovec {
            iov_base: buf.as_mut_ptr(),
            iov_len: buf.len(),
        };
        let mut msg = Msghdr {
            msg_name: name.as_mut_ptr() as *mut _,
            msg_namelen: name.len() as u32,
            msg_iov: &mut iov,
            msg_iovlen: 1,
            msg_control: control.as_mut_ptr() as *mut _,
            msg_controllen: control.len(),
            msg_flags: 0,
        };
        // SAFETY: msghdr points at valid local buffers.
        let n = unsafe { recvmsg(fd, &mut msg, MSG_DONTWAIT) };
        if n < 0 {
            let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
            if errno == EAGAIN {
                return Ok(None);
            }
            return Err(BfdTransportError::Os {
                context: "recvmsg",
                errno,
            });
        }
        if n == 0 {
            return Ok(None);
        }
        let src = parse_sockaddr(&name[..msg.msg_namelen as usize]);
        let ttl = parse_ttl_cmsg(&control[..msg.msg_controllen]);
        Ok(Some((n as usize, src, ttl)))
    }

    fn parse_sockaddr(raw: &[u8]) -> SocketAddr {
        let unspecified =
            || SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED), 0);
        if raw.len() < 2 {
            return unspecified();
        }
        let family = u16::from_ne_bytes([raw[0], raw[1]]);
        if family as i32 == AF_INET && raw.len() >= 8 {
            let port = u16::from_be_bytes([raw[2], raw[3]]);
            let ip = std::net::Ipv4Addr::new(raw[4], raw[5], raw[6], raw[7]);
            return SocketAddr::new(IpAddr::V4(ip), port);
        }
        if family as i32 == AF_INET6 && raw.len() >= 28 {
            let port = u16::from_be_bytes([raw[2], raw[3]]);
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&raw[8..24]);
            let ip = std::net::Ipv6Addr::from(octets);
            // The scope id (bytes 24-27) is not representable in
            // `SocketAddr`; link-local IPv6 BFD peers would need it —
            // out of scope until v6 link-local sessions are wired.
            return SocketAddr::new(IpAddr::V6(ip), port);
        }
        unspecified()
    }

    /// Walk the ancillary-data chain for the received TTL (IP_TTL) or
    /// hop limit (IPV6_HOPLIMIT) message.
    fn parse_ttl_cmsg(control: &[u8]) -> Option<u8> {
        const CMSGHDR_LEN: usize = core::mem::size_of::<Cmsghdr>();
        let mut off = 0usize;
        while off + CMSGHDR_LEN <= control.len() {
            let len = usize::from_ne_bytes(control[off..off + 8].try_into().ok()?);
            let level = i32::from_ne_bytes(control[off + 8..off + 12].try_into().ok()?);
            let ctype = i32::from_ne_bytes(control[off + 12..off + 16].try_into().ok()?);
            if len < CMSGHDR_LEN || off + len > control.len() {
                break;
            }
            let data = &control[off + CMSGHDR_LEN..off + len];
            if level == IPPROTO_IP && ctype == IP_TTL && !data.is_empty() {
                return Some(data[0]);
            }
            if level == IPPROTO_IPV6 && ctype == IPV6_HOPLIMIT && !data.is_empty() {
                return Some(data[0]);
            }
            // cmsg entries are aligned to the word size.
            off = (off + len + 7) & !7;
        }
        None
    }

    pub fn bind_rx(local: Option<IpAddr>, mode: BfdMode) -> Result<UdpSocket, BfdTransportError> {
        let addr = bind_address(local, mode.port());
        let sock = UdpSocket::bind(addr).map_err(|_| os_error("bind"))?;
        sock.set_nonblocking(true).map_err(|_| os_error("fcntl"))?;
        let v6 = sock
            .local_addr()
            .map_err(|_| os_error("getsockname"))?
            .is_ipv6();
        arm_ttl_rx(&sock, v6)?;
        Ok(sock)
    }
}

// ---------------------------------------------------------------------------
// Portable fallback (non-Linux): plain UDP, no receive-side TTL info.
// ---------------------------------------------------------------------------

#[cfg(all(feature = "std", not(target_os = "linux")))]
mod imp {
    use std::net::{IpAddr, SocketAddr, UdpSocket};

    use super::{bind_address, os_error, BfdMode, BfdTransportError};

    pub fn arm_ttl_rx(_sock: &UdpSocket, _v6: bool) -> Result<(), BfdTransportError> {
        // No ancillary TTL on this platform.
        Ok(())
    }

    pub fn arm_ttl_tx(sock: &UdpSocket, v6: bool) -> Result<(), BfdTransportError> {
        if v6 {
            // No portable std API for the IPv6 unicast hop limit.
            Ok(())
        } else {
            sock.set_ttl(255).map_err(|_| os_error("IP_TTL"))
        }
    }

    pub fn recv_from_with_ttl(
        sock: &UdpSocket,
        buf: &mut [u8],
    ) -> Result<Option<(usize, SocketAddr, Option<u8>)>, BfdTransportError> {
        match sock.recv_from(buf) {
            Ok((n, src)) => Ok(Some((n, src, None))),
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => Ok(None),
            Err(e) => Err(BfdTransportError::Os {
                context: "recvfrom",
                errno: e.raw_os_error().unwrap_or(0),
            }),
        }
    }

    pub fn bind_rx(local: Option<IpAddr>, mode: BfdMode) -> Result<UdpSocket, BfdTransportError> {
        let addr = bind_address(local, mode.port());
        let sock = UdpSocket::bind(addr).map_err(|_| os_error("bind"))?;
        sock.set_nonblocking(true).map_err(|_| os_error("fcntl"))?;
        Ok(sock)
    }
}

/// The shared receive socket on the mode's well-known port. All BFD
/// sessions of the daemon arrive here; demultiplex by Your
/// Discriminator above this layer.
pub struct BfdRxSocket {
    sock: UdpSocket,
    mode: BfdMode,
}

impl BfdRxSocket {
    /// Bind the shared receive socket. `local` selects the address
    /// (family and binding); `None` binds the wildcard.
    pub fn bind(local: Option<IpAddr>, mode: BfdMode) -> Result<Self, BfdTransportError> {
        let sock = imp::bind_rx(local, mode)?;
        Ok(Self { sock, mode })
    }

    pub fn mode(&self) -> BfdMode {
        self.mode
    }

    pub fn local_addr(&self) -> Result<SocketAddr, BfdTransportError> {
        self.sock.local_addr().map_err(|_| os_error("getsockname"))
    }

    /// Non-blocking receive of one BFD Control datagram. Returns
    /// `None` when nothing is pending. In single-hop mode a datagram
    /// whose received TTL is known and below 255 is discarded here
    /// (RFC 5881 §5); in multihop mode any TTL is accepted
    /// (RFC 5883 §3). The TTL is returned alongside for diagnostics.
    pub fn recv_from(
        &mut self,
        buf: &mut [u8],
    ) -> Result<Option<(usize, SocketAddr, Option<u8>)>, BfdTransportError> {
        let Some((n, src, ttl)) = imp::recv_from_with_ttl(&self.sock, buf)? else {
            return Ok(None);
        };
        if self.mode == BfdMode::SingleHop {
            if let Some(t) = ttl {
                if t < 255 {
                    // RFC 5881 §5: discard — the packet cannot have
                    // come from the immediate neighbor.
                    return Ok(None);
                }
            }
        }
        Ok(Some((n, src, ttl)))
    }
}

/// The per-session transmit socket: ephemeral source port in
/// 49152-65535 (RFC 5881 §4), TTL 255 when single-hop.
pub struct BfdTxSocket {
    sock: UdpSocket,
}

impl BfdTxSocket {
    /// Bind a session transmit socket on `local` (or the wildcard)
    /// with a source port from the RFC 5881 §4 range.
    pub fn bind_session(local: Option<IpAddr>, mode: BfdMode) -> Result<Self, BfdTransportError> {
        // Random-ish start inside the range; walk until a port is free.
        let mut seed = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.subsec_nanos())
            .unwrap_or(0)
            | 1;
        for _ in 0..64 {
            seed ^= seed << 13;
            seed ^= seed >> 17;
            seed ^= seed << 5;
            let port = BFD_SOURCE_PORT_MIN
                + (seed % (BFD_SOURCE_PORT_MAX - BFD_SOURCE_PORT_MIN + 1) as u32) as u16;
            let addr = bind_address(local, port);
            match UdpSocket::bind(addr) {
                Ok(sock) => {
                    let v6 = sock.local_addr().map(|a| a.is_ipv6()).unwrap_or(false);
                    if mode == BfdMode::SingleHop {
                        imp::arm_ttl_tx(&sock, v6)?;
                    }
                    return Ok(Self { sock });
                }
                Err(e)
                    if e.kind() == std::io::ErrorKind::AddrInUse
                        || e.kind() == std::io::ErrorKind::PermissionDenied =>
                {
                    continue;
                }
                Err(_) => return Err(os_error("bind")),
            }
        }
        Err(BfdTransportError::NoSourcePort)
    }

    /// Send one datagram to the peer's well-known port.
    pub fn send_to(&self, buf: &[u8], peer: SocketAddr) -> Result<usize, BfdTransportError> {
        self.sock.send_to(buf, peer).map_err(|_| os_error("sendto"))
    }

    /// The local (source) address of this session's packets.
    pub fn local_addr(&self) -> Result<SocketAddr, BfdTransportError> {
        self.sock.local_addr().map_err(|_| os_error("getsockname"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    fn loopback(offset: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(127, 0, 0, offset))
    }

    /// Bind rx + tx, exchange a datagram and observe the source-port
    /// range, TTL 255 and the single-hop TTL filter.
    #[test]
    fn single_hop_roundtrip_with_ttl() {
        if !ttl_check_enforced() {
            eprintln!("skipped: TTL check not enforced on this platform");
            return;
        }
        let local = loopback(9);
        let mut rx = match BfdRxSocket::bind(Some(local), BfdMode::SingleHop) {
            Ok(rx) => rx,
            Err(e) => {
                eprintln!("skipped (bind 127.0.0.9): {e}");
                return;
            }
        };
        let tx =
            BfdTxSocket::bind_session(Some(local), BfdMode::SingleHop).expect("session tx socket");
        // Source port inside the RFC 5881 §4 range.
        let src_port = tx.local_addr().unwrap().port();
        assert!(
            (BFD_SOURCE_PORT_MIN..=BFD_SOURCE_PORT_MAX).contains(&src_port),
            "source port {src_port} outside 49152-65535"
        );
        let peer = SocketAddr::new(local, BFD_CONTROL_PORT);
        let payload = [0x20u8, 0x00, 0x03, 0x18];
        tx.send_to(&payload, peer).unwrap();

        let mut buf = [0u8; 64];
        let mut got = None;
        for _ in 0..50 {
            match rx.recv_from(&mut buf).unwrap() {
                Some((n, src, ttl)) => {
                    got = Some((n, src, ttl));
                    break;
                }
                None => std::thread::sleep(std::time::Duration::from_millis(10)),
            }
        }
        let (n, src, ttl) = got.expect("datagram received");
        assert_eq!(&buf[..n], &payload);
        assert_eq!(src.ip(), local);
        assert_eq!(src.port(), src_port);
        // Loopback does not decrement the TTL: 255 must survive.
        assert_eq!(ttl, Some(255));
    }

    /// A single-hop datagram arriving with TTL < 255 is discarded
    /// (RFC 5881 §5) — it cannot have come from the immediate
    /// neighbor.
    #[test]
    fn single_hop_low_ttl_discarded() {
        if !ttl_check_enforced() {
            eprintln!("skipped: TTL check not enforced on this platform");
            return;
        }
        let local = loopback(10);
        let mut rx = match BfdRxSocket::bind(Some(local), BfdMode::SingleHop) {
            Ok(rx) => rx,
            Err(e) => {
                eprintln!("skipped (bind 127.0.0.10): {e}");
                return;
            }
        };
        // A plain socket sending with the default TTL 64.
        let spoofer = UdpSocket::bind(SocketAddr::new(local, 0)).expect("bind spoofer");
        spoofer.set_ttl(64).unwrap();
        spoofer
            .send_to(b"packet", SocketAddr::new(local, BFD_CONTROL_PORT))
            .unwrap();
        let mut buf = [0u8; 64];
        std::thread::sleep(std::time::Duration::from_millis(50));
        assert!(rx.recv_from(&mut buf).unwrap().is_none());
    }

    /// Multihop accepts any TTL (RFC 5883 §3) — a decremented TTL is
    /// the whole point of multihop BFD.
    #[test]
    fn multihop_accepts_reduced_ttl() {
        if !ttl_check_enforced() {
            eprintln!("skipped: TTL check not enforced on this platform");
            return;
        }
        let local = loopback(11);
        let mut rx = match BfdRxSocket::bind(Some(local), BfdMode::Multihop) {
            Ok(rx) => rx,
            Err(e) => {
                eprintln!("skipped (bind 127.0.0.11): {e}");
                return;
            }
        };
        let sender = UdpSocket::bind(SocketAddr::new(local, 0)).expect("bind sender");
        sender.set_ttl(63).unwrap();
        sender
            .send_to(b"packet", SocketAddr::new(local, BFD_MULTIHOP_PORT))
            .unwrap();
        let mut buf = [0u8; 64];
        let mut got = None;
        for _ in 0..50 {
            match rx.recv_from(&mut buf).unwrap() {
                Some((n, _src, ttl)) => {
                    got = Some((n, ttl));
                    break;
                }
                None => std::thread::sleep(std::time::Duration::from_millis(10)),
            }
        }
        let (n, ttl) = got.expect("multihop datagram received");
        assert_eq!(n, 6);
        assert_eq!(ttl, Some(63));
    }

    #[test]
    fn mode_ports() {
        assert_eq!(BfdMode::SingleHop.port(), 3784);
        assert_eq!(BfdMode::Multihop.port(), 4784);
        assert_eq!(BfdMode::SingleHop.to_string(), "single-hop");
        assert_eq!(BfdMode::Multihop.to_string(), "multihop");
    }
}
