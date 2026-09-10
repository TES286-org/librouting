//! Linux implementation: raw `IPPROTO_OSPF` sockets with per-interface
//! multicast scoping (`SO_BINDTODEVICE` + `ip_mreqn`), and `getifaddrs`
//! for interface address enumeration.

use std::ffi::c_char;
use std::net::{Ipv4Addr, Ipv6Addr};

use super::{
    InterfaceV4Addr, InterfaceV6Addr, OspfTransportError, ALL_D_ROUTERS, ALL_D_ROUTERS_V6,
    ALL_SPF_ROUTERS, ALL_SPF_ROUTERS_V6, IPPROTO_OSPF,
};

// socket(2) / fcntl(2) constants (Linux).
const AF_INET: i32 = 2;
const AF_INET6: i32 = 10;
const SOCK_RAW: i32 = 3;
const SOL_SOCKET: i32 = 1;
const SO_BINDTODEVICE: i32 = 25;
const SO_RCVBUF: i32 = 8;

/// Receive-buffer target for the raw OSPF socket (bytes). The kernel
/// doubles the value and caps it at net.core.rmem_max; 1 MiB absorbs
/// bursty flooding (DBD/LSU exchanges plus Hello background) on
/// loaded machines where the default (~200 KiB) can overflow and
/// silently drop an LS-Update — an unacknowledged LSA keeps the
/// peer's retransmission list occupied, which RFC 3623 §3.1 (2)
/// helper checks (BIRD `changes_in_lsrtl`) read as a topology change
/// and refuse the helper role.
const RCVBUF_TARGET: i32 = 1024 * 1024;
const F_GETFL: i32 = 3;
const F_SETFL: i32 = 4;
const O_NONBLOCK: i32 = 0o4000;

// IPv4 socket options (ip(7)).
const IPPROTO_IP: i32 = 0;
const IP_MULTICAST_IF: i32 = 32;
const IP_MULTICAST_TTL: i32 = 33;
const IP_MULTICAST_LOOP: i32 = 34;
const IP_ADD_MEMBERSHIP: i32 = 35;

/// `EAGAIN`/`EWOULDBLOCK` — both 11 on Linux.
const EAGAIN: i32 = 11;

/// `struct sockaddr_in` (the 8 bytes of padding included).
#[repr(C)]
struct SockaddrIn {
    sin_family: u16,
    sin_port: u16,
    sin_addr: [u8; 4],
    sin_zero: [u8; 8],
}

/// `struct sockaddr_in6` (only the fields this module reads; the
/// layout matches glibc's netinet/in.h).
#[repr(C)]
struct SockaddrIn6 {
    sin6_family: u16,
    sin6_port: u16,
    sin6_flowinfo: u32,
    sin6_addr: [u8; 16],
    sin6_scope_id: u32,
}

impl SockaddrIn {
    fn new(addr: [u8; 4]) -> Self {
        Self {
            sin_family: AF_INET as u16,
            sin_port: 0,
            sin_addr: addr,
            sin_zero: [0; 8],
        }
    }
}

/// `struct ip_mreqn` — multicast group + interface, selectable by index
/// so unnumbered interfaces work (ip(7)).
#[repr(C)]
struct IpMreqn {
    imr_multiaddr: [u8; 4],
    imr_address: [u8; 4],
    imr_ifindex: i32,
}

/// `struct ifaddrs` (getifaddrs(3)) — only the fields we read.
#[repr(C)]
struct Ifaddrs {
    ifa_next: *mut Ifaddrs,
    ifa_name: *mut c_char,
    ifa_flags: u32,
    ifa_addr: *mut core::ffi::c_void,
    ifa_netmask: *mut core::ffi::c_void,
    ifa_ifu: *mut core::ffi::c_void,
    ifa_data: *mut core::ffi::c_void,
}

extern "C" {
    fn socket(domain: i32, ty: i32, protocol: i32) -> i32;
    fn setsockopt(
        fd: i32,
        level: i32,
        optname: i32,
        optval: *const core::ffi::c_void,
        optlen: u32,
    ) -> i32;
    fn close(fd: i32) -> i32;
    fn fcntl(fd: i32, cmd: i32, ...) -> i32;
    fn sendto(
        fd: i32,
        buf: *const core::ffi::c_void,
        len: usize,
        flags: i32,
        addr: *const SockaddrIn,
        addrlen: u32,
    ) -> isize;
    fn recvfrom(
        fd: i32,
        buf: *mut core::ffi::c_void,
        len: usize,
        flags: i32,
        addr: *mut SockaddrIn,
        addrlen: *mut u32,
    ) -> isize;
    fn if_nametoindex(ifname: *const c_char) -> u32;
    fn getifaddrs(ifap: *mut *mut Ifaddrs) -> i32;
    fn freeifaddrs(ifa: *mut Ifaddrs);
}

/// Resolve an interface name to its kernel index (0 = unknown).
pub fn ifindex_of(interface: &str) -> Option<u32> {
    let cname = std::ffi::CString::new(interface).ok()?;
    // SAFETY: plain syscall with a valid NUL-terminated name.
    let idx = unsafe { if_nametoindex(cname.as_ptr()) };
    if idx == 0 {
        None
    } else {
        Some(idx)
    }
}

fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

fn os_error(context: &'static str) -> OspfTransportError {
    OspfTransportError::Os {
        context,
        errno: errno(),
    }
}

/// Read the `sin_addr` octets out of a `struct sockaddr*` pointer when
/// it is an AF_INET one.
///
/// # Safety
/// `ptr` must be NULL or point at a valid `struct sockaddr`.
unsafe fn sockaddr_ipv4(ptr: *mut core::ffi::c_void) -> Option<[u8; 4]> {
    if ptr.is_null() {
        return None;
    }
    // SAFETY: sockaddr and sockaddr_in share the leading family field;
    // reading the first two bytes as u16 is alignment-safe.
    let family = unsafe { *(ptr as *const u16) };
    if family != AF_INET as u16 {
        return None;
    }
    // SAFETY: for AF_INET the pointer really is a sockaddr_in; the
    // address field sits at offset 4..8.
    let s = unsafe { &*(ptr as *const SockaddrIn) };
    Some(s.sin_addr)
}

/// Read the `sin6_addr` octets, prefix length (from the netmask) and
/// scope id out of AF_INET6 `struct sockaddr*` pointers.
///
/// # Safety
/// `addr`/`mask` must be NULL or point at valid `struct sockaddr`s.
unsafe fn sockaddr_ipv6(
    addr: *mut core::ffi::c_void,
    mask: *mut core::ffi::c_void,
) -> Option<([u8; 16], u8, u32)> {
    if addr.is_null() {
        return None;
    }
    // SAFETY: the leading family field is alignment-safe to read.
    let family = unsafe { *(addr as *const u16) };
    if family != AF_INET6 as u16 {
        return None;
    }
    // SAFETY: for AF_INET6 the pointer is a sockaddr_in6: address at
    // offset 8..24, scope id at 24..28.
    let s = unsafe { &*(addr as *const SockaddrIn6) };
    let prefix_len = if mask.is_null() {
        128
    } else {
        // SAFETY: the netmask pointer shares the sockaddr_in6 layout.
        let m = unsafe { &*(mask as *const SockaddrIn6) };
        v6_mask_to_prefix_len(m.sin6_addr)
    };
    Some((s.sin6_addr, prefix_len, s.sin6_scope_id))
}

/// Prefix length of a (contiguous, network-byte-order) IPv6 netmask.
fn v6_mask_to_prefix_len(mask: [u8; 16]) -> u8 {
    let mut len: u8 = 0;
    let mut seen_zero = false;
    for byte in mask {
        for bit in (0..8).rev() {
            let set = (byte >> bit) & 1 == 1;
            if set {
                if seen_zero {
                    return len; // gap: treat the prefix as counted so far
                }
                len += 1;
            } else {
                seen_zero = true;
            }
        }
    }
    len
}

/// Enumerate the IPv6 addresses and prefix lengths of `interface`.
///
/// Loopback (::1) is skipped; link-local entries carry their scope id
/// (the interface index) so callers can scope multicast operations and
/// connect() calls. An interface that exists but has no IPv6 address
/// yields an empty vector; a missing interface is an error.
pub fn interface_v6_addrs(interface: &str) -> Result<Vec<InterfaceV6Addr>, OspfTransportError> {
    let mut head: *mut Ifaddrs = std::ptr::null_mut();
    // SAFETY: getifaddrs writes one fresh, self-linked list into head.
    let rc = unsafe { getifaddrs(&mut head) };
    if rc != 0 {
        return Err(os_error("getifaddrs"));
    }
    let mut out = Vec::new();
    let mut exists = false;
    // SAFETY: the list stays valid until freeifaddrs below.
    unsafe {
        let mut cur = head;
        while !cur.is_null() {
            let entry = &*cur;
            // SAFETY: ifa_name is a NUL-terminated C string owned by
            // the list.
            let name = std::ffi::CStr::from_ptr(entry.ifa_name);
            if name.to_bytes() == interface.as_bytes() {
                exists = true;
                if let Some((addr, prefix_len, scope_id)) =
                    sockaddr_ipv6(entry.ifa_addr, entry.ifa_netmask)
                {
                    let ip = Ipv6Addr::from(addr);
                    if ip.is_loopback() {
                        cur = entry.ifa_next;
                        continue;
                    }
                    out.push(InterfaceV6Addr {
                        addr: ip,
                        prefix_len,
                        scope_id,
                    });
                }
            }
            cur = entry.ifa_next;
        }
    }
    // SAFETY: hand the borrowed list back.
    unsafe { freeifaddrs(head) };
    if !exists {
        return Err(OspfTransportError::UnknownInterface(interface.to_string()));
    }
    Ok(out)
}

/// Enumerate the IPv4 addresses and prefix lengths of `interface`.
///
/// The mask is converted to a prefix length; non-contiguous masks
/// (legal historically, never used by OSPF) are skipped rather than
/// approximated. An interface that exists but has no IPv4 address
/// yields an empty vector; a missing interface is an error.
pub fn interface_v4_addrs(interface: &str) -> Result<Vec<InterfaceV4Addr>, OspfTransportError> {
    let mut head: *mut Ifaddrs = std::ptr::null_mut();
    // SAFETY: getifaddrs writes one fresh, self-linked list into head.
    let rc = unsafe { getifaddrs(&mut head) };
    if rc != 0 {
        return Err(os_error("getifaddrs"));
    }
    let mut out = Vec::new();
    let mut exists = false;
    // SAFETY: the list stays valid until freeifaddrs below; we only
    // read through the borrowed pointers.
    unsafe {
        let mut cur = head;
        while !cur.is_null() {
            let entry = &*cur;
            // SAFETY: ifa_name is a NUL-terminated C string owned by
            // the list.
            let name = std::ffi::CStr::from_ptr(entry.ifa_name);
            if name.to_bytes() == interface.as_bytes() {
                exists = true;
                if let (Some(addr), Some(mask)) = (
                    sockaddr_ipv4(entry.ifa_addr),
                    sockaddr_ipv4(entry.ifa_netmask),
                ) {
                    if let Some(prefix_len) = mask_to_prefix_len(mask) {
                        out.push(InterfaceV4Addr {
                            addr: Ipv4Addr::new(addr[0], addr[1], addr[2], addr[3]),
                            prefix_len,
                        });
                    }
                }
            }
            cur = entry.ifa_next;
        }
    }
    // SAFETY: hand the borrowed list back.
    unsafe { freeifaddrs(head) };
    if !exists {
        return Err(OspfTransportError::UnknownInterface(interface.to_string()));
    }
    Ok(out)
}

/// Convert a dotted-quad mask to a prefix length; `None` when the mask
/// is non-contiguous.
fn mask_to_prefix_len(mask: [u8; 4]) -> Option<u8> {
    let mut len: u8 = 0;
    let mut seen_zero = false;
    for byte in mask {
        for bit in (0..8).rev() {
            let set = (byte >> bit) & 1 == 1;
            if set {
                if seen_zero {
                    return None; // gap: non-contiguous
                }
                len += 1;
            } else {
                seen_zero = true;
            }
        }
    }
    Some(len)
}

/// One raw OSPFv2 socket bound to a single interface.
pub struct OspfV2Transport {
    fd: i32,
    #[allow(dead_code)]
    interface: String,
    ifindex: u32,
}

impl OspfV2Transport {
    /// Open the raw socket for `interface`, join both multicast groups,
    /// and arm multicast egress (TTL 1, loopback per `multicast_loop`).
    ///
    /// `multicast_loop = false` (the daemon default) keeps the socket
    /// from receiving its own multicasts; tests turn it on to verify
    /// the full send/receive path on a single host.
    pub fn bind(interface: &str, multicast_loop: bool) -> Result<Self, OspfTransportError> {
        let cname = std::ffi::CString::new(interface)
            .map_err(|_| OspfTransportError::UnknownInterface(interface.to_string()))?;
        // SAFETY: plain syscall with a valid NUL-terminated name.
        let ifindex = unsafe { if_nametoindex(cname.as_ptr()) };
        if ifindex == 0 {
            return Err(OspfTransportError::UnknownInterface(interface.to_string()));
        }
        // SAFETY: plain socket(2) call.
        let fd = unsafe { socket(AF_INET, SOCK_RAW, IPPROTO_OSPF) };
        if fd < 0 {
            return Err(os_error("socket"));
        }
        let transport = Self {
            fd,
            interface: interface.to_string(),
            ifindex,
        };
        // Scope the socket to the interface (receive + egress).
        if let Err(e) =
            transport.set_sockopt_bytes(SOL_SOCKET, SO_BINDTODEVICE, cname.as_bytes_with_nul())
        {
            unsafe { close(fd) };
            return Err(e);
        }
        // Deep receive queue: flooding bursts on loaded machines must
        // not overflow the default buffer (see RCVBUF_TARGET).
        let _ = transport.set_sockopt_i32(SOL_SOCKET, SO_RCVBUF, RCVBUF_TARGET);
        // Multicast egress: choose the interface by index (works on
        // unnumbered links), TTL 1 (link-local groups, RFC 2328 A.1),
        // loopback per caller.
        if let Err(e) = transport.set_multicast_if() {
            unsafe { close(fd) };
            return Err(e);
        }
        if let Err(e) = transport.set_sockopt_u8(IPPROTO_IP, IP_MULTICAST_TTL, 1) {
            unsafe { close(fd) };
            return Err(e);
        }
        let loop_on = if multicast_loop { 1u8 } else { 0u8 };
        if let Err(e) = transport.set_sockopt_u8(IPPROTO_IP, IP_MULTICAST_LOOP, loop_on) {
            unsafe { close(fd) };
            return Err(e);
        }
        for group in [ALL_SPF_ROUTERS, ALL_D_ROUTERS] {
            if let Err(e) = transport.join_group(group) {
                unsafe { close(fd) };
                return Err(e);
            }
        }
        Ok(transport)
    }

    fn set_multicast_if(&self) -> Result<(), OspfTransportError> {
        let mreqn = IpMreqn {
            imr_multiaddr: [0; 4],
            imr_address: [0; 4],
            imr_ifindex: self.ifindex as i32,
        };
        // SAFETY: fd and optval are valid for the duration of the call.
        let rc = unsafe {
            setsockopt(
                self.fd,
                IPPROTO_IP,
                IP_MULTICAST_IF,
                &mreqn as *const IpMreqn as *const core::ffi::c_void,
                std::mem::size_of::<IpMreqn>() as u32,
            )
        };
        if rc != 0 {
            return Err(os_error("IP_MULTICAST_IF"));
        }
        Ok(())
    }

    fn join_group(&self, group: [u8; 4]) -> Result<(), OspfTransportError> {
        let mreqn = IpMreqn {
            imr_multiaddr: group,
            imr_address: [0; 4],
            imr_ifindex: self.ifindex as i32,
        };
        // SAFETY: fd and optval are valid for the duration of the call.
        let rc = unsafe {
            setsockopt(
                self.fd,
                IPPROTO_IP,
                IP_ADD_MEMBERSHIP,
                &mreqn as *const IpMreqn as *const core::ffi::c_void,
                std::mem::size_of::<IpMreqn>() as u32,
            )
        };
        if rc != 0 {
            return Err(os_error("IP_ADD_MEMBERSHIP"));
        }
        Ok(())
    }

    fn set_sockopt_u8(
        &self,
        level: i32,
        optname: i32,
        value: u8,
    ) -> Result<(), OspfTransportError> {
        // SAFETY: fd and optval are valid for the duration of the call.
        let rc = unsafe {
            setsockopt(
                self.fd,
                level,
                optname,
                &value as *const u8 as *const core::ffi::c_void,
                std::mem::size_of::<u8>() as u32,
            )
        };
        if rc != 0 {
            return Err(os_error("setsockopt"));
        }
        Ok(())
    }

    fn set_sockopt_i32(
        &self,
        level: i32,
        optname: i32,
        value: i32,
    ) -> Result<(), OspfTransportError> {
        // SAFETY: fd and optval are valid for the duration of the call.
        let rc = unsafe {
            setsockopt(
                self.fd,
                level,
                optname,
                &value as *const i32 as *const core::ffi::c_void,
                std::mem::size_of::<i32>() as u32,
            )
        };
        if rc != 0 {
            return Err(os_error("setsockopt"));
        }
        Ok(())
    }

    fn set_sockopt_bytes(
        &self,
        level: i32,
        optname: i32,
        value: &[u8],
    ) -> Result<(), OspfTransportError> {
        // SAFETY: fd and optval are valid for the duration of the call.
        let rc = unsafe {
            setsockopt(
                self.fd,
                level,
                optname,
                value.as_ptr() as *const core::ffi::c_void,
                value.len() as u32,
            )
        };
        if rc != 0 {
            return Err(os_error("setsockopt"));
        }
        Ok(())
    }

    /// Toggle non-blocking mode (`false` = blocking, the default).
    pub fn set_nonblocking(&self, on: bool) -> Result<(), OspfTransportError> {
        // SAFETY: fcntl(F_GETFL) on our own fd.
        let flags = unsafe { fcntl(self.fd, F_GETFL) };
        if flags < 0 {
            return Err(os_error("fcntl(F_GETFL)"));
        }
        let new_flags = if on {
            flags | O_NONBLOCK
        } else {
            flags & !O_NONBLOCK
        };
        // SAFETY: fcntl(F_SETFL) with the flag word we just read.
        let rc = unsafe { fcntl(self.fd, F_SETFL, new_flags) };
        if rc < 0 {
            return Err(os_error("fcntl(F_SETFL)"));
        }
        Ok(())
    }

    /// Receive one pending packet. `Ok(None)` means nothing to read
    /// (non-blocking mode).
    pub fn recv_from(
        &self,
        buf: &mut [u8],
    ) -> Result<Option<(usize, Ipv4Addr)>, OspfTransportError> {
        let mut src = SockaddrIn::new([0; 4]);
        let mut srclen = std::mem::size_of::<SockaddrIn>() as u32;
        // SAFETY: buf and src outlive the call; both are plain memory.
        let n = unsafe {
            recvfrom(
                self.fd,
                buf.as_mut_ptr() as *mut core::ffi::c_void,
                buf.len(),
                0,
                &mut src,
                &mut srclen,
            )
        };
        if n < 0 {
            let e = errno();
            return if e == EAGAIN {
                Ok(None) // nothing pending
            } else {
                Err(OspfTransportError::Os {
                    context: "recvfrom",
                    errno: e,
                })
            };
        }
        Ok(Some((
            n as usize,
            Ipv4Addr::new(
                src.sin_addr[0],
                src.sin_addr[1],
                src.sin_addr[2],
                src.sin_addr[3],
            ),
        )))
    }

    /// Multicast `bytes` to AllSPFRouters (224.0.0.5) on the bound
    /// interface.
    pub fn send_multicast(&self, bytes: &[u8]) -> Result<usize, OspfTransportError> {
        let dest = SockaddrIn::new(ALL_SPF_ROUTERS);
        // SAFETY: bytes and dest outlive the call.
        let n = unsafe {
            sendto(
                self.fd,
                bytes.as_ptr() as *const core::ffi::c_void,
                bytes.len(),
                0,
                &dest,
                std::mem::size_of::<SockaddrIn>() as u32,
            )
        };
        if n < 0 {
            return Err(os_error("sendto"));
        }
        Ok(n as usize)
    }

    /// Unicast `bytes` to `dst` on the bound interface (RFC 2328
    /// §13.5: the direct form of flooding — LS retransmissions on
    /// broadcast networks go straight to the neighbor's address). The
    /// raw socket's `SO_BINDTODEVICE` scopes egress to the interface
    /// without a routing-table lookup.
    pub fn send_unicast(
        &self,
        dst: core::net::Ipv4Addr,
        bytes: &[u8],
    ) -> Result<usize, OspfTransportError> {
        let o = dst.octets();
        let dest = SockaddrIn::new(o);
        // SAFETY: bytes and dest outlive the call.
        let n = unsafe {
            sendto(
                self.fd,
                bytes.as_ptr() as *const core::ffi::c_void,
                bytes.len(),
                0,
                &dest,
                std::mem::size_of::<SockaddrIn>() as u32,
            )
        };
        if n < 0 {
            return Err(os_error("sendto"));
        }
        Ok(n as usize)
    }

    /// The kernel interface index the socket is bound to.
    pub fn ifindex(&self) -> u32 {
        self.ifindex
    }

    /// The interface MTU (SIOCGIFMTU) — DBD packets must advertise it
    /// (RFC 2328 §10.6; peers reject a larger value).
    pub fn mtu(&self) -> Result<u16, OspfTransportError> {
        let mut ifr: [u8; 40] = [0; 40];
        // Prepend the interface name (16 bytes, NUL-padded) in the
        // first half of the ifreq; the MTU lands at offset 16.
        let name = self.interface.as_bytes();
        ifr[..name.len().min(15)].copy_from_slice(&name[..name.len().min(15)]);
        // SAFETY: ioctl on our own fd with a valid ifreq buffer.
        let rc = unsafe { ioctl(self.fd, SIOCGIFMTU, ifr.as_mut_ptr()) };
        if rc < 0 {
            return Err(os_error("SIOCGIFMTU"));
        }
        // ifru_mtu is a host-endian int; BIRD enforces exact equality
        // on the DBD MTU field, so this must be the real value.
        let mtu = u16::from_le_bytes([ifr[16], ifr[17]]);
        Ok(mtu.max(576))
    }
}

// ---------------------------------------------------------------------------
// OSPFv3 transport: raw IPv6 sockets (RFC 5340 §8 / §A.3.1)
// ---------------------------------------------------------------------------

// IPv6 socket options (ipv6(7)).
const IPPROTO_IPV6: i32 = 41;
const IPV6_MULTICAST_IF: i32 = 17;
const IPV6_MULTICAST_HOPS: i32 = 18;
const IPV6_MULTICAST_LOOP: i32 = 19;
const IPV6_ADD_MEMBERSHIP: i32 = 20;

/// `struct ipv6_mreq` (RFC 3493 §5.3).
#[repr(C)]
struct Ipv6Mreq {
    ipv6mr_multiaddr: [u8; 16],
    ipv6mr_ifindex: i32,
}

impl SockaddrIn6 {
    fn new(addr: [u8; 16], scope_id: u32) -> Self {
        Self {
            sin6_family: AF_INET6 as u16,
            sin6_port: 0,
            sin6_flowinfo: 0,
            sin6_addr: addr,
            sin6_scope_id: scope_id,
        }
    }
}

extern "C" {
    // The same libc symbols as the v4 declarations above, retyped for
    // sockaddr_in6 (the address family lives in the struct, not the ABI).
    #[link_name = "sendto"]
    fn sendto6(
        fd: i32,
        buf: *const core::ffi::c_void,
        len: usize,
        flags: i32,
        addr: *const SockaddrIn6,
        addrlen: u32,
    ) -> isize;
    #[link_name = "recvfrom"]
    fn recvfrom6(
        fd: i32,
        buf: *mut core::ffi::c_void,
        len: usize,
        flags: i32,
        addr: *mut SockaddrIn6,
        addrlen: *mut u32,
    ) -> isize;
}

/// One raw OSPFv3 socket bound to a single interface. OSPFv3 packets
/// ride IPv6 protocol 89 straight over the link: Hellos and most
/// flooding is multicast to ff02::5/ff02::6 with a link-local source
/// (RFC 5340 §4.2.1), which is why no interface address is required at
/// all. Linux AF_INET6 raw sockets deliver the OSPF packet *without*
/// the IPv6 header (unlike IPv4 raw sockets), so recv data starts at
/// the 16-byte OSPF header.
pub struct OspfV6Transport {
    fd: i32,
    #[allow(dead_code)]
    interface: String,
    ifindex: u32,
}

impl OspfV6Transport {
    /// Open the raw IPv6 socket for `interface`, join both multicast
    /// groups on it, and arm multicast egress (hop limit 1, loopback
    /// per `multicast_loop`).
    pub fn bind(interface: &str, multicast_loop: bool) -> Result<Self, OspfTransportError> {
        let cname = std::ffi::CString::new(interface)
            .map_err(|_| OspfTransportError::UnknownInterface(interface.to_string()))?;
        // SAFETY: plain syscall with a valid NUL-terminated name.
        let ifindex = unsafe { if_nametoindex(cname.as_ptr()) };
        if ifindex == 0 {
            return Err(OspfTransportError::UnknownInterface(interface.to_string()));
        }
        // SAFETY: plain socket(2) call.
        let fd = unsafe { socket(AF_INET6, SOCK_RAW, IPPROTO_OSPF) };
        if fd < 0 {
            return Err(os_error("socket6"));
        }
        let transport = Self {
            fd,
            interface: interface.to_string(),
            ifindex,
        };
        // Scope the socket to the interface (receive + egress).
        if let Err(e) =
            transport.set_sockopt_bytes(SOL_SOCKET, SO_BINDTODEVICE, cname.as_bytes_with_nul())
        {
            unsafe { close(fd) };
            return Err(e);
        }
        let _ = transport.set_sockopt_i32(SOL_SOCKET, SO_RCVBUF, RCVBUF_TARGET);
        // Multicast egress: interface by index, hop limit 1 (the OSPFv3
        // counterpart of the v2 TTL 1), loopback per caller.
        if let Err(e) = transport.set_sockopt_i32(IPPROTO_IPV6, IPV6_MULTICAST_IF, ifindex as i32) {
            unsafe { close(fd) };
            return Err(e);
        }
        if let Err(e) = transport.set_sockopt_i32(IPPROTO_IPV6, IPV6_MULTICAST_HOPS, 1) {
            unsafe { close(fd) };
            return Err(e);
        }
        if let Err(e) = transport.set_sockopt_i32(
            IPPROTO_IPV6,
            IPV6_MULTICAST_LOOP,
            if multicast_loop { 1 } else { 0 },
        ) {
            unsafe { close(fd) };
            return Err(e);
        }
        for group in [ALL_SPF_ROUTERS_V6, ALL_D_ROUTERS_V6] {
            let mreq = Ipv6Mreq {
                ipv6mr_multiaddr: group,
                ipv6mr_ifindex: ifindex as i32,
            };
            // SAFETY: fd and optval are valid for the duration of the call.
            let rc = unsafe {
                setsockopt(
                    fd,
                    IPPROTO_IPV6,
                    IPV6_ADD_MEMBERSHIP,
                    &mreq as *const Ipv6Mreq as *const core::ffi::c_void,
                    std::mem::size_of::<Ipv6Mreq>() as u32,
                )
            };
            if rc != 0 {
                unsafe { close(fd) };
                return Err(os_error("IPV6_ADD_MEMBERSHIP"));
            }
        }
        Ok(transport)
    }

    fn set_sockopt_i32(
        &self,
        level: i32,
        optname: i32,
        value: i32,
    ) -> Result<(), OspfTransportError> {
        // SAFETY: fd and optval are valid for the duration of the call.
        let rc = unsafe {
            setsockopt(
                self.fd,
                level,
                optname,
                &value as *const i32 as *const core::ffi::c_void,
                std::mem::size_of::<i32>() as u32,
            )
        };
        if rc != 0 {
            return Err(os_error("setsockopt6"));
        }
        Ok(())
    }

    fn set_sockopt_bytes(
        &self,
        level: i32,
        optname: i32,
        value: &[u8],
    ) -> Result<(), OspfTransportError> {
        // SAFETY: fd and optval are valid for the duration of the call.
        let rc = unsafe {
            setsockopt(
                self.fd,
                level,
                optname,
                value.as_ptr() as *const core::ffi::c_void,
                value.len() as u32,
            )
        };
        if rc != 0 {
            return Err(os_error("setsockopt6"));
        }
        Ok(())
    }

    /// Toggle non-blocking mode (`false` = blocking, the default).
    pub fn set_nonblocking(&self, on: bool) -> Result<(), OspfTransportError> {
        // SAFETY: fcntl(F_GETFL) on our own fd.
        let flags = unsafe { fcntl(self.fd, F_GETFL) };
        if flags < 0 {
            return Err(os_error("fcntl(F_GETFL)"));
        }
        let new_flags = if on {
            flags | O_NONBLOCK
        } else {
            flags & !O_NONBLOCK
        };
        // SAFETY: fcntl(F_SETFL) with the flag word we just read.
        let rc = unsafe { fcntl(self.fd, F_SETFL, new_flags) };
        if rc < 0 {
            return Err(os_error("fcntl(F_SETFL)"));
        }
        Ok(())
    }

    /// Receive one pending packet. `Ok(None)` means nothing to read
    /// (non-blocking mode). Returns the source address — a link-local
    /// for every peer packet, RFC 5340 §4.2.2 requires it — which the
    /// daemon records as the neighbor's link-local for unicast egress
    /// and next-hop bookkeeping.
    pub fn recv_from(
        &self,
        buf: &mut [u8],
    ) -> Result<Option<(usize, Ipv6Addr)>, OspfTransportError> {
        let mut src = SockaddrIn6::new([0; 16], 0);
        let mut srclen = std::mem::size_of::<SockaddrIn6>() as u32;
        // SAFETY: buf and src outlive the call; both are plain memory.
        let n = unsafe {
            recvfrom6(
                self.fd,
                buf.as_mut_ptr() as *mut core::ffi::c_void,
                buf.len(),
                0,
                &mut src,
                &mut srclen,
            )
        };
        if n < 0 {
            let e = errno();
            return if e == EAGAIN {
                Ok(None) // nothing pending
            } else {
                Err(OspfTransportError::Os {
                    context: "recvfrom6",
                    errno: e,
                })
            };
        }
        Ok(Some((n as usize, Ipv6Addr::from(src.sin6_addr))))
    }

    /// Multicast `bytes` to AllSPFRouters (ff02::5) on the bound
    /// interface.
    pub fn send_multicast(&self, bytes: &[u8]) -> Result<usize, OspfTransportError> {
        self.send_to(ALL_SPF_ROUTERS_V6, bytes)
    }

    /// Unicast `bytes` to `dst` on the bound interface — the RFC 5340
    /// §4.2.1 direct form: the destination is the neighbor's link-local
    /// address, and the sin6_scope_id carries the interface so the
    /// kernel resolves the link scope without a routing lookup.
    pub fn send_unicast(
        &self,
        dst: core::net::Ipv6Addr,
        bytes: &[u8],
    ) -> Result<usize, OspfTransportError> {
        self.send_to(dst.octets(), bytes)
    }

    fn send_to(&self, dst: [u8; 16], bytes: &[u8]) -> Result<usize, OspfTransportError> {
        let dest = SockaddrIn6::new(dst, self.ifindex);
        // SAFETY: bytes and dest outlive the call.
        let n = unsafe {
            sendto6(
                self.fd,
                bytes.as_ptr() as *const core::ffi::c_void,
                bytes.len(),
                0,
                &dest,
                std::mem::size_of::<SockaddrIn6>() as u32,
            )
        };
        if n < 0 {
            return Err(os_error("sendto6"));
        }
        Ok(n as usize)
    }

    /// The kernel interface index the socket is bound to — also the
    /// OSPFv3 Interface ID by the daemon's convention (FRR parity).
    pub fn ifindex(&self) -> u32 {
        self.ifindex
    }

    /// The interface MTU (SIOCGIFMTU) — DBD packets must advertise it
    /// (RFC 2328 §10.6 semantics apply to v3; BIRD enforces equality).
    pub fn mtu(&self) -> Result<u16, OspfTransportError> {
        let mut ifr: [u8; 40] = [0; 40];
        let name = self.interface.as_bytes();
        ifr[..name.len().min(15)].copy_from_slice(&name[..name.len().min(15)]);
        // SAFETY: ioctl on our own fd with a valid ifreq buffer.
        let rc = unsafe { ioctl(self.fd, SIOCGIFMTU, ifr.as_mut_ptr()) };
        if rc < 0 {
            return Err(os_error("SIOCGIFMTU"));
        }
        let mtu = u16::from_le_bytes([ifr[16], ifr[17]]);
        Ok(mtu.max(576))
    }
}

impl Drop for OspfV6Transport {
    fn drop(&mut self) {
        // SAFETY: we own the fd; close exactly once.
        unsafe { close(self.fd) };
    }
}

/// SIOCGIFMTU (linux/sockios.h) — read the interface MTU.
const SIOCGIFMTU: libc_ulong = 0x8921;

#[allow(non_camel_case_types)]
type libc_ulong = core::ffi::c_ulong;

extern "C" {
    fn ioctl(fd: i32, request: libc_ulong, ...) -> i32;
}

impl Drop for OspfV2Transport {
    fn drop(&mut self) {
        // SAFETY: we own the fd; close exactly once.
        unsafe { close(self.fd) };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn masks_roundtrip() {
        assert_eq!(mask_to_prefix_len([255, 255, 255, 0]), Some(24));
        assert_eq!(mask_to_prefix_len([255, 255, 255, 255]), Some(32));
        assert_eq!(mask_to_prefix_len([0, 0, 0, 0]), Some(0));
        assert_eq!(mask_to_prefix_len([255, 0, 255, 0]), None);
        assert_eq!(mask_to_prefix_len([254, 255, 255, 0]), None);
    }

    #[test]
    fn interface_lookup_lo() {
        // `lo` always exists with 127.0.0.1/8 — even in containers.
        let addrs = interface_v4_addrs("lo").expect("lo lookup");
        assert!(
            addrs.iter().any(|a| a.addr == Ipv4Addr::LOCALHOST),
            "127.0.0.1 must be listed: {addrs:?}"
        );
    }

    #[test]
    fn interface_lookup_unknown() {
        let e = interface_v4_addrs("no-such-if-xyz").unwrap_err();
        assert!(matches!(e, OspfTransportError::UnknownInterface(_)));
    }
}
