//! BSD-family implementation — `getifaddrs(3)` for interface enumeration
//! with BSD-style `struct sockaddr` (a leading `sa_len` byte at offset 0,
//! then `sa_family` at offset 1).
//!
//! Built for macOS, FreeBSD, NetBSD and OpenBSD. The raw OSPF transport
//! types stay stubs (returns [`OspfTransportError::Unsupported`]) — the
//! OSPF daemon remains Linux-only — but `list_interfaces`,
//! `interface_v4_addrs`, `interface_v6_addrs` and `ifindex_of` work, so
//! Babel's `[[babel.interface]]` glob matcher is fully operational.
//!
//! ## Why a separate file from `imp_linux.rs`
//!
//! The Linux `struct sockaddr` lays out `sa_family: u16` at offset 0
//! (no `sa_len` field). BSD-derived kernels add an `sa_len: u8` byte
//! at offset 0, so `sa_family` shifts to offset 1 and is itself a
//! single byte. `AF_INET6` also differs per platform (macOS 30,
//! FreeBSD 28, NetBSD 24, OpenBSD 24, Linux 10) — see
//! `imp_bsd::AF_INET6`.
//!
//! Everything else (`getifaddrs`/`freeifaddrs` FFI, `Ifaddrs` struct,
//! `IFF_UP`/`IFF_RUNNING` flag bits, `if_nametoindex`) is byte-identical
//! to the Linux impl, so this file mirrors `imp_linux.rs` closely and
//! only diverges where the sockaddr layout actually differs.

use std::ffi::c_char;
use std::net::{Ipv4Addr, Ipv6Addr};

use super::{InterfaceEntry, InterfaceV4Addr, InterfaceV6Addr, OspfTransportError};

// ---------------------------------------------------------------------------
// Constants — *BSD/macOS values
// ---------------------------------------------------------------------------

/// `AF_INET` — identical on every BSD-flavoured Unix (and Linux).
const AF_INET: u8 = 2;

/// `AF_INET6` — differs per BSD. macOS/iOS use 30, FreeBSD 28, NetBSD
/// and OpenBSD 24. We pick the per-target value at compile time so the
/// family check matches what `getifaddrs` reports.
#[cfg(target_os = "macos")]
const AF_INET6: u8 = 30;
#[cfg(target_os = "ios")]
const AF_INET6: u8 = 30;
#[cfg(target_os = "freebsd")]
const AF_INET6: u8 = 28;
#[cfg(target_os = "netbsd")]
const AF_INET6: u8 = 24;
#[cfg(target_os = "openbsd")]
const AF_INET6: u8 = 24;
#[cfg(target_os = "dragonfly")]
const AF_INET6: u8 = 28;

/// `IFF_UP` — administratively up (BSD `<net/if.h>`).
const IFF_UP: u32 = 0x1;
/// `IFF_RUNNING` — carrier present (BSD `<net/if.h>`).
const IFF_RUNNING: u32 = 0x40;

// ---------------------------------------------------------------------------
// FFI
// ---------------------------------------------------------------------------

/// `struct sockaddr_in` — the BSD layout (4-byte family+len area is
/// shared between Linux and BSD; the only material difference is the
/// family width, which we read via `read_family` instead of touching
/// `sin_family` directly).
#[repr(C)]
struct SockaddrIn {
    /// `_sin_family[0] = sa_len`, `_sin_family[1] = sa_family` on BSD.
    _sin_family: [u8; 2],
    sin_port: u16,
    sin_addr: [u8; 4],
    sin_zero: [u8; 8],
}

/// `struct sockaddr_in6` — BSD layout. The address and scope-id fields
/// sit at the same offsets as on Linux (8..24 and 24..28), so the same
/// struct works for both.
#[repr(C)]
struct SockaddrIn6 {
    /// `_sin6_family[0] = sa_len`, `_sin6_family[1] = sa_family` on BSD.
    _sin6_family: [u8; 2],
    sin6_port: u16,
    sin6_flowinfo: u32,
    sin6_addr: [u8; 16],
    sin6_scope_id: u32,
}

/// `struct ifaddrs` (BSD `<ifaddrs.h>`) — only the fields we read. The
/// layout matches glibc's, and on BSD `ifa_flags` is `unsigned int`
/// (u32) — same width as the Linux code assumes.
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

/// Read the `sa_family` field out of a `struct sockaddr*` pointer using
/// the BSD layout (`sa_len` at offset 0, `sa_family` at offset 1).
///
/// # Safety
/// `ptr` must point at a valid `struct sockaddr` (or be NULL).
unsafe fn read_family(ptr: *mut core::ffi::c_void) -> Option<u8> {
    if ptr.is_null() {
        return None;
    }
    // SAFETY: the family byte sits at offset 1 in BSD sockaddr; reading
    // one byte is alignment-safe.
    unsafe { Some(*((ptr as *const u8).add(1))) }
}

/// Read the `sin_addr` octets when `ptr` points at an `AF_INET`
/// `struct sockaddr_in`.
///
/// # Safety
/// `ptr` must be NULL or point at a valid `struct sockaddr`.
unsafe fn sockaddr_ipv4(ptr: *mut core::ffi::c_void) -> Option<[u8; 4]> {
    if read_family(ptr)? != AF_INET {
        return None;
    }
    // SAFETY: for AF_INET the pointer is a sockaddr_in; the address
    // field sits at offset 4..8 (after the 2-byte family+len and the
    // 2-byte port).
    let s = unsafe { &*(ptr as *const SockaddrIn) };
    Some(s.sin_addr)
}

/// Read the `sin6_addr` octets, prefix length and scope id from an
/// `AF_INET6` `struct sockaddr*` pair.
///
/// # Safety
/// `addr`/`mask` must be NULL or point at valid `struct sockaddr`s.
unsafe fn sockaddr_ipv6(
    addr: *mut core::ffi::c_void,
    mask: *mut core::ffi::c_void,
) -> Option<([u8; 16], u8, u32)> {
    if read_family(addr)? != AF_INET6 {
        return None;
    }
    // SAFETY: for AF_INET6 the pointer is a sockaddr_in6; address at
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

/// Enumerate the IPv4 addresses and prefix lengths of `interface`
/// (mirrors `imp_linux::interface_v4_addrs`).
pub fn interface_v4_addrs(interface: &str) -> Result<Vec<InterfaceV4Addr>, OspfTransportError> {
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

/// Enumerate the IPv6 addresses and prefix lengths of `interface`
/// (mirrors `imp_linux::interface_v6_addrs`).
pub fn interface_v6_addrs(interface: &str) -> Result<Vec<InterfaceV6Addr>, OspfTransportError> {
    let mut head: *mut Ifaddrs = std::ptr::null_mut();
    let rc = unsafe { getifaddrs(&mut head) };
    if rc != 0 {
        return Err(os_error("getifaddrs"));
    }
    let mut out = Vec::new();
    let mut exists = false;
    unsafe {
        let mut cur = head;
        while !cur.is_null() {
            let entry = &*cur;
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

/// Enumerate every interface on the system with its IPv4 and IPv6
/// addresses — same contract as `imp_linux::list_interfaces`.
pub fn list_interfaces() -> Result<Vec<InterfaceEntry>, OspfTransportError> {
    let mut head: *mut Ifaddrs = std::ptr::null_mut();
    let rc = unsafe { getifaddrs(&mut head) };
    if rc != 0 {
        return Err(os_error("getifaddrs"));
    }
    let mut by_name: std::collections::BTreeMap<String, InterfaceEntry> =
        std::collections::BTreeMap::new();
    unsafe {
        let mut cur = head;
        while !cur.is_null() {
            let entry = &*cur;
            if !entry.ifa_name.is_null() {
                let name = std::ffi::CStr::from_ptr(entry.ifa_name)
                    .to_string_lossy()
                    .into_owned();
                let iface = by_name.entry(name.clone()).or_insert(InterfaceEntry {
                    name,
                    v4: Vec::new(),
                    v6: Vec::new(),
                    up: entry.ifa_flags & IFF_UP != 0,
                    running: entry.ifa_flags & IFF_RUNNING != 0,
                });
                if let Some(v4) = sockaddr_ipv4(entry.ifa_addr) {
                    iface
                        .v4
                        .push(std::net::Ipv4Addr::new(v4[0], v4[1], v4[2], v4[3]));
                }
                if let Some((v6, _, _)) = sockaddr_ipv6(entry.ifa_addr, entry.ifa_netmask) {
                    iface.v6.push(std::net::Ipv6Addr::from(v6));
                }
            }
            cur = entry.ifa_next;
        }
    }
    unsafe { freeifaddrs(head) };
    Ok(by_name.into_values().collect())
}

// ---------------------------------------------------------------------------
// OSPF raw-socket transport — BSD stub
// ---------------------------------------------------------------------------
//
// Raw IPPROTO_OSPF sockets are not implemented on BSD in librouting.
// The OSPF daemon itself is Linux-only (it depends on `SO_BINDTODEVICE`
// and `ip_mreqn`-by-index membership). Embedders on BSD who need OSPF
// must feed the protocol's bytes through the router's session API
// themselves (see docs/OS-INTEGRATION.md).

/// BSD placeholder for the raw `IPPROTO_OSPF` socket — returns
/// [`OspfTransportError::Unsupported`] from every method.
pub struct OspfV2Transport {
    _private: (),
}

impl OspfV2Transport {
    pub fn bind(_interface: &str, _multicast_loop: bool) -> Result<Self, OspfTransportError> {
        Err(OspfTransportError::Unsupported(
            "OSPF raw sockets exist only on Linux in librouting",
        ))
    }

    pub fn set_nonblocking(&self, _on: bool) -> Result<(), OspfTransportError> {
        Err(OspfTransportError::Unsupported(
            "OSPF raw sockets exist only on Linux in librouting",
        ))
    }

    pub fn recv_from(
        &self,
        _buf: &mut [u8],
    ) -> Result<Option<(usize, std::net::Ipv4Addr)>, OspfTransportError> {
        Err(OspfTransportError::Unsupported(
            "OSPF raw sockets exist only on Linux in librouting",
        ))
    }

    pub fn send_multicast(&self, _bytes: &[u8]) -> Result<usize, OspfTransportError> {
        Err(OspfTransportError::Unsupported(
            "OSPF raw sockets exist only on Linux in librouting",
        ))
    }

    pub fn send_unicast(
        &self,
        _dst: core::net::Ipv4Addr,
        _bytes: &[u8],
    ) -> Result<usize, OspfTransportError> {
        Err(OspfTransportError::Unsupported(
            "OSPF raw sockets exist only on Linux in librouting",
        ))
    }

    pub fn ifindex(&self) -> u32 {
        0
    }

    pub fn mtu(&self) -> Result<u16, super::OspfTransportError> {
        Err(super::OspfTransportError::Unsupported(
            "OSPF raw sockets exist only on Linux in librouting",
        ))
    }
}

/// BSD placeholder for the OSPFv3 raw socket — same contract as the
/// v2 placeholder.
pub struct OspfV6Transport {
    _private: (),
}

impl OspfV6Transport {
    pub fn bind(_interface: &str, _multicast_loop: bool) -> Result<Self, OspfTransportError> {
        Err(OspfTransportError::Unsupported(
            "OSPF raw sockets exist only on Linux in librouting",
        ))
    }

    pub fn set_nonblocking(&self, _on: bool) -> Result<(), OspfTransportError> {
        Err(OspfTransportError::Unsupported(
            "OSPF raw sockets exist only on Linux in librouting",
        ))
    }

    pub fn recv_from(
        &self,
        _buf: &mut [u8],
    ) -> Result<Option<(usize, std::net::Ipv6Addr)>, OspfTransportError> {
        Err(OspfTransportError::Unsupported(
            "OSPF raw sockets exist only on Linux in librouting",
        ))
    }

    pub fn send_multicast(&self, _bytes: &[u8]) -> Result<usize, OspfTransportError> {
        Err(OspfTransportError::Unsupported(
            "OSPF raw sockets exist only on Linux in librouting",
        ))
    }

    pub fn send_unicast(
        &self,
        _dst: core::net::Ipv6Addr,
        _bytes: &[u8],
    ) -> Result<usize, OspfTransportError> {
        Err(OspfTransportError::Unsupported(
            "OSPF raw sockets exist only on Linux in librouting",
        ))
    }

    pub fn ifindex(&self) -> u32 {
        0
    }

    pub fn mtu(&self) -> Result<u16, super::OspfTransportError> {
        Err(super::OspfTransportError::Unsupported(
            "OSPF raw sockets exist only on Linux in librouting",
        ))
    }
}
