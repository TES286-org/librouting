//! RFC 5082 Generalized TTL Security Mechanism (GTSM) for BGP.
//!
//! GTSM is a *transport* concern: the kernel sets the TTL on outbound
//! segments and drops inbound segments whose TTL is below the configured
//! minimum. The library never inspects TTL on the wire — it only arms
//! the socket before the connection is established.
//!
//! ## Model
//!
//! - **Single-hop eBGP** (the common case): set TTL=255 on send and
//!   require TTL>=255 on receive. A remote attacker's packets arrive
//!   with a decremented TTL and are silently dropped by the kernel.
//! - **Multihop eBGP / iBGP**: set TTL to the configured hop count
//!   (e.g. 2 for a 2-hop path) and require TTL >= `255 - hops + 1` on
//!   receive. The peer must set its own TTL symmetrically.
//!
//! ## Sockets and roles
//!
//! - **Listener** ([`arm_listener_gtsm`]): sets `IP_TTL` /
//!   `IPV6_UNICAST_HOPS` + a per-socket minimum-TTL filter
//!   (`IP_MINTTL` / `IPV6_MINHOPLIMIT`) on the listener so every
//!   accepted connection inherits the policy.
//! - **Connector** ([`connect_gtsm`]): creates the socket, sets the
//!   outbound TTL, then connects. The SYN itself carries the high TTL.
//!
//! ## Platform support
//!
//! | Platform | IPv4 | IPv6 |
//! |----------|------|------|
//! | Linux    | `IP_TTL` + `IP_MINTTL` | `IPV6_UNICAST_HOPS` + `IPV6_MINHOPLIMIT` |
//! | Other    | `set_ttl` on `TcpStream` / `TcpListener` (send side only — no kernel min-TTL filter) |
//!
//! On non-Linux platforms the send side is still enforced (TTL=255 on
//! outbound), but the receive-side filter must be implemented by the
//! embedder if required. The configuration model stays portable.
//!
//! ## Example
//!
//! ```no_run
//! use std::net::TcpListener;
//! use lr_osroute::gtsm::{Gtsm, arm_listener_gtsm, connect_gtsm};
//! use std::time::Duration;
//!
//! // Single-hop: TTL=255 both directions.
//! let gtsm = Gtsm::single_hop();
//! let listener = TcpListener::bind("127.0.0.1:1179").unwrap();
//! arm_listener_gtsm(&listener, &gtsm).unwrap();
//! let stream = connect_gtsm("127.0.0.1:1179".parse().unwrap(), &gtsm,
//!                          Duration::from_secs(5)).unwrap();
//! # let _ = stream;
//! ```

/// GTSM configuration. The outbound TTL is always set on the socket;
/// the minimum-TTL filter is enforced when the kernel supports it
/// (Linux `IP_MINTTL` / `IPV6_MINHOPLIMIT`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Gtsm {
    /// TTL set on every outbound segment. 255 for single-hop; the
    /// configured hop count for multihop.
    pub outbound_ttl: u8,
    /// Minimum TTL required on inbound segments. The kernel drops
    /// anything below this. 255 for single-hop; `255 - hops + 1` for
    /// multihop.
    pub min_ttl: u8,
}

impl Gtsm {
    /// Single-hop GTSM (RFC 5082 §4.1): TTL=255 both directions.
    /// This is the standard configuration for directly connected eBGP.
    pub const fn single_hop() -> Self {
        Self {
            outbound_ttl: 255,
            min_ttl: 255,
        }
    }

    /// Multihop GTSM (RFC 5082 §4.2): outbound TTL = `hops`, minimum
    /// inbound TTL = `255 - hops + 1`. The peer must configure the same
    /// hop count symmetrically.
    ///
    /// # Panics
    /// `hops` must be in `1..=254` (255 is single-hop; 0 is meaningless).
    pub fn multihop(hops: u8) -> Self {
        assert!(
            (1..=254).contains(&hops),
            "multihop TTL must be 1..=254 (got {hops})"
        );
        Self {
            outbound_ttl: hops,
            min_ttl: 255 - hops + 1,
        }
    }

    /// True when GTSM is effectively a no-op (no TTL enforcement).
    /// The daemon uses this to skip the setsockopt calls.
    pub fn is_disabled(&self) -> bool {
        self.outbound_ttl == 0 && self.min_ttl == 0
    }
}

impl std::fmt::Display for Gtsm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.is_disabled() {
            return f.write_str("none");
        }
        if self.outbound_ttl == 255 && self.min_ttl == 255 {
            return f.write_str("gtsm(single-hop, ttl=255)");
        }
        write!(
            f,
            "gtsm(multihop, ttl={}, min={})",
            self.outbound_ttl, self.min_ttl
        )
    }
}

/// Error returned by GTSM socket operations.
#[derive(Debug)]
pub enum GtsmError {
    /// The platform does not support the required socket option.
    Unsupported(&'static str),
    /// A raw OS error from a `setsockopt` / `socket` / `connect` call.
    Os { context: &'static str, errno: i32 },
    /// The non-blocking connect did not complete within the timeout.
    ConnectTimeout,
}

impl std::fmt::Display for GtsmError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unsupported(msg) => write!(f, "GTSM unsupported: {msg}"),
            Self::Os { context, errno } => {
                write!(f, "GTSM {context} failed (errno {errno})")
            }
            Self::ConnectTimeout => write!(f, "GTSM connect timeout"),
        }
    }
}

impl std::error::Error for GtsmError {}

impl GtsmError {
    /// True when the error is a permanent "kernel does not support this
    /// option" condition (e.g. `IP_MINTTL` on a non-Linux OS). The
    /// caller should fail closed rather than retry.
    pub fn is_kernel_unsupported(&self) -> bool {
        matches!(self, Self::Unsupported(_))
    }
}

// ---------------------------------------------------------------------------
// Linux implementation — IP_TTL / IP_MINTTL / IPV6_UNICAST_HOPS /
// IPV6_MINHOPLIMIT. The min-TTL filter is what makes GTSM effective: the
// kernel drops low-TTL packets before they reach userspace.
//
// We declare the FFI surface inline (matching the tcp_auth module) so the
// crate does not depend on the `libc` crate.
// ---------------------------------------------------------------------------

#[cfg(all(feature = "std", target_os = "linux"))]
#[allow(clashing_extern_declarations)]
mod imp {
    use super::{Gtsm, GtsmError};
    use std::net::{SocketAddr, TcpListener, TcpStream};
    use std::time::{Duration, Instant};

    use core::ffi::c_void;
    use std::os::fd::{AsRawFd, FromRawFd};

    // Socket constants (Linux x86_64 / aarch64 — same values everywhere
    // Linux runs BGP). Kept private; the public API is portable.
    const AF_INET: u16 = 2;
    const AF_INET6: u16 = 10;
    const SOL_SOCKET: i32 = 1;
    const SO_REUSEADDR: i32 = 2;
    const SO_ERROR: i32 = 4;
    const SOL_IP: i32 = 0;
    const IP_TTL: i32 = 2;
    const IP_MINTTL: i32 = 21;
    const SOL_IPV6: i32 = 41;
    const IPV6_UNICAST_HOPS: i32 = 16;
    const IPV6_MINHOPLIMIT: i32 = 74;
    const SOCK_STREAM: i32 = 1;
    const SOCK_NONBLOCK: i32 = 0o4000;
    const O_NONBLOCK: i32 = 0o4000;
    const F_GETFL: i32 = 3;
    const F_SETFL: i32 = 4;
    const POLL_OUT: i16 = 0x4;
    const POLL_ERR: i16 = 0x8;
    const POLL_HUP: i16 = 0x10;
    const EINPROGRESS: i32 = 115;
    const EINTR: i32 = 4;
    const ENOPROTOOPT: i32 = 92;

    #[repr(C)]
    #[derive(Clone, Copy)]
    struct SockaddrStorage {
        ss_family: u16,
        __pad: [u8; 126],
    }

    #[repr(C)]
    struct PollFd {
        fd: i32,
        events: i16,
        revents: i16,
    }

    extern "C" {
        fn socket(domain: i32, ty: i32, protocol: i32) -> i32;
        fn setsockopt(fd: i32, level: i32, optname: i32, optval: *const c_void, optlen: u32)
            -> i32;
        fn getsockopt(
            fd: i32,
            level: i32,
            optname: i32,
            optval: *mut c_void,
            optlen: *mut u32,
        ) -> i32;
        fn connect(fd: i32, addr: *const SockaddrStorage, addrlen: u32) -> i32;
        fn poll(fds: *mut PollFd, nfds: u64, timeout_ms: i32) -> i32;
        fn fcntl(fd: i32, cmd: i32, ...) -> i32;
        fn close(fd: i32) -> i32;
    }

    fn errno() -> i32 {
        std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
    }

    fn os_error(context: &'static str) -> GtsmError {
        GtsmError::Os {
            context,
            errno: errno(),
        }
    }

    fn family_of(addr: &SocketAddr) -> u16 {
        match addr {
            SocketAddr::V4(_) => AF_INET,
            SocketAddr::V6(_) => AF_INET6,
        }
    }

    /// Fill a `SockaddrStorage` from a `SocketAddr`, returning the
    /// address length the kernel expects. The layout matches
    /// `sockaddr_in` / `sockaddr_in6` byte-for-byte: family at offset 0,
    /// port at offset 2, address at offset 4 (v4) or 8 (v6).
    fn sock_addr(addr: SocketAddr) -> (SockaddrStorage, u32) {
        let mut s: SockaddrStorage = unsafe { std::mem::zeroed() };
        let port = addr.port().to_be_bytes();
        match addr {
            SocketAddr::V4(v4) => {
                s.ss_family = AF_INET;
                s.__pad[0..2].copy_from_slice(&port);
                s.__pad[2..6].copy_from_slice(&v4.ip().octets());
                (s, 16)
            }
            SocketAddr::V6(v6) => {
                s.ss_family = AF_INET6;
                s.__pad[0..2].copy_from_slice(&port);
                // __pad[2..6] is sin6_flowinfo, left zeroed.
                s.__pad[6..22].copy_from_slice(&v6.ip().octets());
                s.__pad[22..26].copy_from_slice(&v6.scope_id().to_be_bytes());
                (s, 28)
            }
        }
    }

    /// Set an integer socket option. Returns the OS error on failure.
    fn set_opt_int(fd: i32, level: i32, optname: i32, val: i32) -> Result<(), GtsmError> {
        let v = val;
        // SAFETY: `v` is a stack c_int; the pointer is valid for the call.
        let rc = unsafe {
            setsockopt(
                fd,
                level,
                optname,
                (&raw const v) as *const c_void,
                std::mem::size_of::<i32>() as u32,
            )
        };
        if rc < 0 {
            return Err(os_error("setsockopt"));
        }
        Ok(())
    }

    /// Install GTSM on a raw fd. The outbound TTL is always set; the
    /// min-TTL receive filter is set only when `set_min_ttl` is true
    /// (listener side). Setting `IP_MINTTL` on a *connector* socket is
    /// wrong — it would drop the SYN-ACK, which arrives with a
    /// decremented TTL (64 on loopback, lower on real links).
    fn arm_fd(fd: i32, addr_family: u16, gtsm: &Gtsm, set_min_ttl: bool) -> Result<(), GtsmError> {
        if gtsm.outbound_ttl > 0 {
            match addr_family {
                AF_INET => set_opt_int(fd, SOL_IP, IP_TTL, gtsm.outbound_ttl as i32)?,
                AF_INET6 => set_opt_int(fd, SOL_IPV6, IPV6_UNICAST_HOPS, gtsm.outbound_ttl as i32)?,
                _ => return Err(GtsmError::Unsupported("unknown address family")),
            }
        }
        if set_min_ttl && gtsm.min_ttl > 0 {
            // IP_MINTTL silently fails on some kernels if the module is not
            // loaded; treat ENOPROTOOPT as "unsupported" so the caller can
            // fail closed or degrade gracefully.
            match addr_family {
                AF_INET => {
                    if let Err(GtsmError::Os { errno, .. }) =
                        set_opt_int(fd, SOL_IP, IP_MINTTL, gtsm.min_ttl as i32)
                    {
                        if errno == ENOPROTOOPT {
                            return Err(GtsmError::Unsupported(
                                "IP_MINTTL not supported by kernel",
                            ));
                        }
                        return Err(GtsmError::Os {
                            context: "setsockopt(IP_MINTTL)",
                            errno,
                        });
                    }
                }
                AF_INET6 => {
                    if let Err(GtsmError::Os { errno, .. }) =
                        set_opt_int(fd, SOL_IPV6, IPV6_MINHOPLIMIT, gtsm.min_ttl as i32)
                    {
                        if errno == ENOPROTOOPT {
                            return Err(GtsmError::Unsupported(
                                "IPV6_MINHOPLIMIT not supported by kernel",
                            ));
                        }
                        return Err(GtsmError::Os {
                            context: "setsockopt(IPV6_MINHOPLIMIT)",
                            errno,
                        });
                    }
                }
                _ => return Err(GtsmError::Unsupported("unknown address family")),
            }
        }
        Ok(())
    }

    pub fn arm_listener_impl(listener: &TcpListener, gtsm: &Gtsm) -> Result<(), GtsmError> {
        if gtsm.is_disabled() {
            return Ok(());
        }
        let fd = listener.as_raw_fd();
        let family = match listener.local_addr() {
            Ok(SocketAddr::V4(_)) => AF_INET,
            Ok(SocketAddr::V6(_)) => AF_INET6,
            _ => return Err(GtsmError::Unsupported("cannot determine listener family")),
        };
        // Listener: set both outbound TTL and the min-TTL receive filter.
        // Accepted sockets inherit both.
        arm_fd(fd, family, gtsm, true)
    }

    pub fn connect_impl(
        addr: SocketAddr,
        gtsm: &Gtsm,
        timeout: Duration,
    ) -> Result<TcpStream, GtsmError> {
        if gtsm.is_disabled() {
            return TcpStream::connect_timeout(&addr, timeout).map_err(|e| GtsmError::Os {
                context: "connect",
                errno: e.raw_os_error().unwrap_or(0),
            });
        }
        // SAFETY: raw socket helpers below check every return value; the fd
        // is closed on every error path and handed to TcpStream (which then
        // owns it) on success.
        unsafe {
            let ty = SOCK_STREAM | SOCK_NONBLOCK;
            let fd = socket(family_of(&addr) as i32, ty, 0);
            if fd < 0 {
                return Err(os_error("socket"));
            }
            // SO_REUSEADDR so a quick restart does not hit TIME_WAIT.
            let _ = set_opt_int(fd, SOL_SOCKET, SO_REUSEADDR, 1);
            // Connector: outbound TTL only. The min-TTL filter is the
            // listener's job — setting it here would drop the SYN-ACK.
            if let Err(e) = arm_fd(fd, family_of(&addr), gtsm, false) {
                close(fd);
                return Err(e);
            }
            let (sa, len) = sock_addr(addr);
            let rc = connect(fd, &sa, len);
            if rc < 0 && errno() != EINPROGRESS {
                let e = os_error("connect");
                close(fd);
                return Err(e);
            }
            if !wait_writable(fd, timeout) {
                close(fd);
                return Err(GtsmError::ConnectTimeout);
            }
            let mut so_err: i32 = 0;
            let mut so_len = std::mem::size_of::<i32>() as u32;
            let rc = getsockopt(
                fd,
                SOL_SOCKET,
                SO_ERROR,
                (&raw mut so_err) as *mut c_void,
                &mut so_len,
            );
            if rc < 0 {
                let e = os_error("getsockopt(SO_ERROR)");
                close(fd);
                return Err(e);
            }
            if so_err != 0 {
                let e = GtsmError::Os {
                    context: "connect",
                    errno: so_err,
                };
                close(fd);
                return Err(e);
            }
            // Back to blocking mode for the TcpStream consumer.
            let flags = fcntl(fd, F_GETFL);
            if flags >= 0 {
                fcntl(fd, F_SETFL, flags & !O_NONBLOCK);
            }
            Ok(TcpStream::from_raw_fd(fd))
        }
    }

    /// Polls until the socket is writable (connected) or the timeout hits.
    fn wait_writable(fd: i32, timeout: Duration) -> bool {
        let deadline = Instant::now() + timeout;
        loop {
            let now = Instant::now();
            if now >= deadline {
                return false;
            }
            let mut pfd = PollFd {
                fd,
                events: POLL_OUT,
                revents: 0,
            };
            let remaining = deadline - now;
            let ms = remaining.as_millis().min(i32::MAX as u128) as i32;
            // SAFETY: `pfd` is a valid single-element pollfd array.
            let rc = unsafe { poll(&mut pfd, 1, ms.max(0)) };
            if rc < 0 {
                if errno() == EINTR {
                    continue;
                }
                return false;
            }
            if pfd.revents & (POLL_ERR | POLL_HUP) != 0 {
                return true;
            }
            if pfd.revents & POLL_OUT != 0 {
                return true;
            }
        }
    }
}

#[cfg(all(feature = "std", target_os = "linux"))]
pub use imp::{arm_listener_impl as arm_listener_gtsm, connect_impl as connect_gtsm};

// ---------------------------------------------------------------------------
// Portable fallback — send-side TTL only (no kernel min-TTL filter).
// ---------------------------------------------------------------------------

#[cfg(all(feature = "std", not(target_os = "linux")))]
mod fallback {
    use super::{Gtsm, GtsmError};
    use std::net::{SocketAddr, TcpListener, TcpStream};
    use std::time::Duration;

    pub fn arm_listener_impl(listener: &TcpListener, gtsm: &Gtsm) -> Result<(), GtsmError> {
        if gtsm.is_disabled() {
            return Ok(());
        }
        // std::net::TcpListener exposes set_ttl (IP_TTL / IPV6_UNICAST_HOPS)
        // on every platform. The min-TTL filter is Linux-specific; on other
        // platforms we set the outbound TTL only and document that the
        // receive-side filter must be enforced by the embedder if needed.
        if gtsm.outbound_ttl > 0 {
            listener
                .set_ttl(gtsm.outbound_ttl as u32)
                .map_err(|e| GtsmError::Os {
                    context: "set_ttl",
                    errno: e.raw_os_error().unwrap_or(0),
                })?;
        }
        if gtsm.min_ttl > 0 {
            // No portable min-TTL socket option. The caller should be
            // aware that the receive-side filter is not enforced by the
            // kernel on this platform.
            return Err(GtsmError::Unsupported(
                "min-TTL filter is Linux-only; outbound TTL set successfully",
            ));
        }
        Ok(())
    }

    pub fn connect_impl(
        addr: SocketAddr,
        gtsm: &Gtsm,
        timeout: Duration,
    ) -> Result<TcpStream, GtsmError> {
        if gtsm.is_disabled() {
            return TcpStream::connect_timeout(&addr, timeout).map_err(|e| GtsmError::Os {
                context: "connect",
                errno: e.raw_os_error().unwrap_or(0),
            });
        }
        let stream = TcpStream::connect_timeout(&addr, timeout).map_err(|e| GtsmError::Os {
            context: "connect",
            errno: e.raw_os_error().unwrap_or(0),
        })?;
        if gtsm.outbound_ttl > 0 {
            stream
                .set_ttl(gtsm.outbound_ttl as u32)
                .map_err(|e| GtsmError::Os {
                    context: "set_ttl",
                    errno: e.raw_os_error().unwrap_or(0),
                })?;
        }
        if gtsm.min_ttl > 0 {
            // Same caveat as arm_listener: no portable min-TTL filter.
            return Err(GtsmError::Unsupported(
                "min-TTL filter is Linux-only; outbound TTL set successfully",
            ));
        }
        Ok(stream)
    }
}

#[cfg(all(feature = "std", not(target_os = "linux")))]
pub use fallback::{arm_listener_impl as arm_listener_gtsm, connect_impl as connect_gtsm};

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{TcpListener, TcpStream};
    use std::time::Duration;

    #[test]
    fn single_hop_is_ttl_255() {
        let g = Gtsm::single_hop();
        assert_eq!(g.outbound_ttl, 255);
        assert_eq!(g.min_ttl, 255);
        assert!(!g.is_disabled());
    }

    #[test]
    fn multihop_computes_min_ttl() {
        // 1 hop → ttl=1, min=255 (same as single-hop on the wire, but
        // expressed through the multihop formula).
        let g = Gtsm::multihop(1);
        assert_eq!(g.outbound_ttl, 1);
        assert_eq!(g.min_ttl, 255);

        // 2 hops → ttl=2, min=254
        let g = Gtsm::multihop(2);
        assert_eq!(g.outbound_ttl, 2);
        assert_eq!(g.min_ttl, 254);
    }

    #[test]
    #[should_panic(expected = "multihop TTL must be 1..=254")]
    fn multihop_rejects_zero() {
        let _ = Gtsm::multihop(0);
    }

    #[test]
    #[should_panic(expected = "multihop TTL must be 1..=254")]
    fn multihop_rejects_255() {
        let _ = Gtsm::multihop(255);
    }

    #[test]
    fn default_is_disabled() {
        let g = Gtsm::default();
        assert!(g.is_disabled());
        assert_eq!(format!("{g}"), "none");
    }

    #[test]
    fn display_single_hop() {
        let g = Gtsm::single_hop();
        assert_eq!(format!("{g}"), "gtsm(single-hop, ttl=255)");
    }

    #[test]
    fn display_multihop() {
        let g = Gtsm::multihop(3);
        assert_eq!(format!("{g}"), "gtsm(multihop, ttl=3, min=253)");
    }

    /// Live socket test: arm a listener with single-hop GTSM and connect
    /// to it. The connector also uses GTSM (TTL=255), so the SYN arrives
    /// with TTL=255 and passes the min-TTL filter.
    #[cfg(target_os = "linux")]
    #[test]
    fn single_hop_loopback_connects() {
        use std::io::{Read, Write};
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let gtsm = Gtsm::single_hop();
        arm_listener_gtsm(&listener, &gtsm).expect("arm listener");

        let mut stream = connect_gtsm(addr, &gtsm, Duration::from_secs(2)).expect("connect");
        let (mut accepted, _) = listener.accept().expect("accept");

        // Round-trip a byte to prove the connection is usable.
        stream.write_all(b"hi").unwrap();
        let mut buf = [0u8; 2];
        accepted.read_exact(&mut buf).unwrap();
        assert_eq!(&buf, b"hi");
    }

    /// A connector without GTSM (TTL=64 default) is rejected by a
    /// single-hop GTSM listener on Linux — the SYN arrives with TTL=64
    /// (Linux loopback does not decrement TTL) which is below 255, so
    /// the min-TTL filter drops it.
    #[cfg(target_os = "linux")]
    #[test]
    fn plain_connect_rejected_by_gtsm_listener() {
        use std::io::Read;
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let gtsm = Gtsm::single_hop();
        arm_listener_gtsm(&listener, &gtsm).expect("arm listener");

        // Plain connect: TTL=64 (kernel default), below min=255.
        // The connect call itself may return Ok (the SYN is queued) but
        // no SYN-ACK is sent because IP_MINTTL drops the inbound SYN.
        let stream = TcpStream::connect_timeout(&addr, Duration::from_millis(500));
        if let Ok(mut s) = stream {
            s.set_read_timeout(Some(Duration::from_millis(200)))
                .unwrap();
            let mut buf = [0u8; 1];
            let _ = s.read(&mut buf);
            listener.set_nonblocking(true).unwrap();
            if listener.accept().is_ok() {
                panic!("GTSM listener accepted a low-TTL connection");
            }
        }
    }
}
