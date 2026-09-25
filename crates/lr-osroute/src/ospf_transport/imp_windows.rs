//! Windows implementation — interface enumeration via the IP Helper
//! API (`GetAdaptersAddresses`).
//!
//! Built for `target_os = "windows"`. The raw OSPF transport types
//! stay stubs (returns [`OspfTransportError::Unsupported`]) — the
//! OSPF daemon itself is Linux-only — but `list_interfaces`,
//! `interface_v4_addrs`, `interface_v6_addrs` and `ifindex_of` work,
//! so Babel's `[[babel.interface]]` glob matcher is fully operational.
//!
//! ## Struct layouts
//!
//! All Win32 structs (`IP_ADAPTER_ADDRESSES`, `IP_ADAPTER_UNICAST_ADDRESS`,
//! `SOCKET_ADDRESS`) and the `GetAdaptersAddresses` function are imported
//! from the `windows-sys` crate — Microsoft's auto-generated, zero-overhead
//! FFI binding. The struct layouts are machine-generated from the official
//! Windows SDK metadata (win32metadata), so they cannot drift from the
//! SDK the way hand-rolled `#[repr(C)]` structs can. Two struct-layout
//! bugs on Windows in this crate's history (a misaligned pointer
//! dereference and a swapped field order) motivated the migration.

use std::net::{Ipv4Addr, Ipv6Addr};
use std::ptr;

use windows_sys::Win32::Foundation::{ERROR_BUFFER_OVERFLOW, ERROR_SUCCESS};
use windows_sys::Win32::NetworkManagement::IpHelper::{
    GetAdaptersAddresses, GAA_FLAG_INCLUDE_PREFIX, GAA_FLAG_SKIP_ANYCAST, GAA_FLAG_SKIP_DNS_SERVER,
    GAA_FLAG_SKIP_MULTICAST, IP_ADAPTER_ADDRESSES_LH, IP_ADAPTER_UNICAST_ADDRESS_LH,
};
use windows_sys::Win32::NetworkManagement::Ndis::IfOperStatusUp;
use windows_sys::Win32::Networking::WinSock::{AF_INET, AF_INET6, SOCKADDR_IN, SOCKADDR_IN6};

use super::{InterfaceEntry, InterfaceV4Addr, InterfaceV6Addr, OspfTransportError};

/// Owned adapter list — the `Box<[u8]>` holds the backing allocation
/// returned by `GetAdaptersAddresses`, and `head` is the typed head
/// pointer into that buffer. Drop reclaims the memory automatically.
struct AdapterList {
    #[allow(dead_code)]
    buf: Box<[u8]>,
    head: *mut IP_ADAPTER_ADDRESSES_LH,
}

/// Call `GetAdaptersAddresses` for both IPv4 and IPv6, with the
/// "skip anycast/multicast/DNS, include prefix" flags.
fn get_adapters_addresses() -> Result<AdapterList, OspfTransportError> {
    let flags = GAA_FLAG_SKIP_ANYCAST
        | GAA_FLAG_SKIP_MULTICAST
        | GAA_FLAG_INCLUDE_PREFIX
        | GAA_FLAG_SKIP_DNS_SERVER;
    let mut size: u32 = 0;
    // First call: ask for the buffer size. ERROR_BUFFER_OVERFLOW is
    // the documented "buffer too small" code; ERROR_SUCCESS with a
    // zero-sized list means "no adapters" — return it as a soft
    // failure so callers can degrade gracefully.
    let rc = unsafe { GetAdaptersAddresses(0, flags, ptr::null_mut(), ptr::null_mut(), &mut size) };
    if rc != ERROR_BUFFER_OVERFLOW && rc != ERROR_SUCCESS {
        return Err(OspfTransportError::Os {
            context: "GetAdaptersAddresses(size)",
            errno: rc as i32,
        });
    }
    if size == 0 {
        return Err(OspfTransportError::Os {
            context: "GetAdaptersAddresses",
            errno: 0,
        });
    }
    let mut buf: Vec<u8> = vec![0u8; size as usize];
    let rc = unsafe {
        GetAdaptersAddresses(
            0,
            flags,
            ptr::null_mut(),
            buf.as_mut_ptr() as *mut IP_ADAPTER_ADDRESSES_LH,
            &mut size,
        )
    };
    if rc != ERROR_SUCCESS {
        return Err(OspfTransportError::Os {
            context: "GetAdaptersAddresses(fill)",
            errno: rc as i32,
        });
    }
    let head = buf.as_mut_ptr() as *mut IP_ADAPTER_ADDRESSES_LH;
    Ok(AdapterList {
        buf: buf.into_boxed_slice(),
        head,
    })
}

/// Resolve an interface name (the FriendlyName) to its kernel index.
pub fn ifindex_of(interface: &str) -> Option<u32> {
    let list = get_adapters_addresses().ok()?;
    let mut cur = list.head;
    while !cur.is_null() {
        // SAFETY: `cur` was returned by GetAdaptersAddresses inside
        // the buffer owned by `list`.
        let entry = unsafe { &*cur };
        if let Some(name) = unsafe { friendly_name(entry.FriendlyName) } {
            if name == interface {
                // IfIndex is inside the alignment union at offset 4
                // (the union overlays {ULONGLONG Alignment} and
                // {ULONG Length, IF_INDEX IfIndex}). We read it via
                // the Anonymous variant of the union.
                let if_index = unsafe { entry.Anonymous1.Anonymous.IfIndex };
                return Some(if_index);
            }
        }
        cur = entry.Next;
    }
    None
}

/// Resolve an interface name (the FriendlyName) to its **IPv6** scope
/// id — the index IPv6 sockets, group memberships and link-local
/// addresses are scoped by. `IP_ADAPTER_ADDRESSES_LH` carries this as a
/// *separate* `Ipv6IfIndex` field: it usually equals `IfIndex`, but the
/// two can diverge (adapters that gained IPv6 late, stack resets), and
/// a membership joined on `IfIndex` when the scope is `Ipv6IfIndex`
/// never matches an arriving datagram — the socket goes deaf while its
/// own multicast egress keeps working. Falls back to `IfIndex` when
/// the IPv6 index reads zero.
pub fn ipv6_ifindex_of(interface: &str) -> Option<u32> {
    let list = get_adapters_addresses().ok()?;
    let mut cur = list.head;
    while !cur.is_null() {
        // SAFETY: `cur` was returned by GetAdaptersAddresses inside
        // the buffer owned by `list`.
        let entry = unsafe { &*cur };
        if let Some(name) = unsafe { friendly_name(entry.FriendlyName) } {
            if name == interface {
                // A plain struct field on the `windows-sys` binding — no
                // union is crossed, so no `unsafe` is needed (unlike the
                // `Anonymous1` union reads above).
                let v6 = entry.Ipv6IfIndex;
                if v6 != 0 {
                    return Some(v6);
                }
                return Some(unsafe { entry.Anonymous1.Anonymous.IfIndex });
            }
        }
        cur = entry.Next;
    }
    None
}

/// Read a NUL-terminated UTF-16 wide string into a Rust `String`.
///
/// # Safety
/// `ptr` must be NULL or point at a NUL-terminated `wchar_t*` buffer.
unsafe fn friendly_name(ptr: *const u16) -> Option<String> {
    if ptr.is_null() {
        return None;
    }
    let mut len = 0usize;
    unsafe {
        while *ptr.add(len) != 0 {
            len += 1;
        }
    }
    let slice = unsafe { std::slice::from_raw_parts(ptr, len) };
    String::from_utf16(slice).ok()
}

fn os_error(context: &'static str) -> OspfTransportError {
    OspfTransportError::Os {
        context,
        errno: std::io::Error::last_os_error().raw_os_error().unwrap_or(0),
    }
}

/// Read `(Ipv4Addr, prefix_len)` out of an `IP_ADAPTER_UNICAST_ADDRESS_LH`
/// when its embedded `SOCKET_ADDRESS` points at an `AF_INET`
/// `sockaddr_in`.
///
/// # Safety
/// `u` must point at a valid `IP_ADAPTER_UNICAST_ADDRESS_LH` returned by
/// `GetAdaptersAddresses`.
unsafe fn read_v4(u: &IP_ADAPTER_UNICAST_ADDRESS_LH) -> Option<(Ipv4Addr, u8)> {
    let sa = &u.Address;
    if sa.iSockaddrLength < 16 || sa.lpSockaddr.is_null() {
        return None;
    }
    // `lpSockaddr` is `*mut SOCKADDR` (a typed pointer, 16-byte struct).
    // Cast to `*const SOCKADDR_IN` and read through that — the SDK
    // guarantees the pointer points at a `sockaddr_in` when the family
    // is `AF_INET`. This avoids manual byte offset arithmetic which is
    // error-prone with typed pointers (`.add(4)` on `*mut SOCKADDR`
    // would advance by 4 structs, not 4 bytes).
    let sa_in = sa.lpSockaddr as *const SOCKADDR_IN;
    // SAFETY: `sa_in` is valid for `iSockaddrLength` bytes (≥ 16), and
    // `SOCKADDR_IN` is 16 bytes. `read_unaligned` handles any alignment.
    let sa_in = unsafe { ptr::read_unaligned(sa_in) };
    if sa_in.sin_family != AF_INET {
        return None;
    }
    let s = &sa_in.sin_addr.S_un.S_un_b;
    let addr = Ipv4Addr::new(s.s_b1, s.s_b2, s.s_b3, s.s_b4);
    Some((addr, u.OnLinkPrefixLength))
}

/// Read `(Ipv6Addr, prefix_len)` out of an `IP_ADAPTER_UNICAST_ADDRESS_LH`
/// when its embedded `SOCKET_ADDRESS` points at an `AF_INET6`
/// `sockaddr_in6`.
///
/// # Safety
/// `u` must point at a valid `IP_ADAPTER_UNICAST_ADDRESS_LH` returned by
/// `GetAdaptersAddresses`.
unsafe fn read_v6(u: &IP_ADAPTER_UNICAST_ADDRESS_LH) -> Option<(Ipv6Addr, u8)> {
    let sa = &u.Address;
    if sa.iSockaddrLength < 28 || sa.lpSockaddr.is_null() {
        return None;
    }
    // Cast to `*const SOCKADDR_IN6` — same rationale as `read_v4`.
    let sa_in6 = sa.lpSockaddr as *const SOCKADDR_IN6;
    // SAFETY: `sa_in6` is valid for `iSockaddrLength` bytes (≥ 28),
    // and `SOCKADDR_IN6` is 28 bytes.
    let sa_in6 = unsafe { ptr::read_unaligned(sa_in6) };
    if sa_in6.sin6_family != AF_INET6 {
        return None;
    }
    Some((
        Ipv6Addr::from(sa_in6.sin6_addr.u.Byte),
        u.OnLinkPrefixLength,
    ))
}

/// Enumerate every adapter on the system with its IPv4 and IPv6
/// addresses — same contract as `imp_linux::list_interfaces`.
pub fn list_interfaces() -> Result<Vec<InterfaceEntry>, OspfTransportError> {
    let list = get_adapters_addresses()?;
    let mut out = Vec::new();
    let mut cur = list.head;
    while !cur.is_null() {
        // SAFETY: `cur` was returned by GetAdaptersAddresses inside
        // the buffer owned by `list`.
        let entry = unsafe { &*cur };
        let name = unsafe { friendly_name(entry.FriendlyName) }.unwrap_or_default();
        if name.is_empty() {
            cur = entry.Next;
            continue;
        }
        let up = entry.OperStatus == IfOperStatusUp;
        // Windows has no direct `IFF_RUNNING` analogue; treat `up` as
        // `running` (the carrier state is folded into OperStatus when
        // the media is disconnected).
        let running = up;
        let mut v4 = Vec::new();
        let mut v6 = Vec::new();
        let mut ua = entry.FirstUnicastAddress;
        while !ua.is_null() {
            // SAFETY: `ua` was returned by GetAdaptersAddresses.
            let u = unsafe { &*ua };
            if let Some((addr, _)) = unsafe { read_v4(u) } {
                v4.push(addr);
            }
            if let Some((addr, _)) = unsafe { read_v6(u) } {
                v6.push(addr);
            }
            ua = u.Next;
        }
        out.push(InterfaceEntry {
            name,
            v4,
            v6,
            up,
            running,
        });
        cur = entry.Next;
    }
    Ok(out)
}

/// Enumerate the IPv4 addresses and prefix lengths of `interface`.
pub fn interface_v4_addrs(interface: &str) -> Result<Vec<InterfaceV4Addr>, OspfTransportError> {
    let list = get_adapters_addresses().map_err(|_| os_error("GetAdaptersAddresses"))?;
    let mut out = Vec::new();
    let mut exists = false;
    let mut cur = list.head;
    while !cur.is_null() {
        let entry = unsafe { &*cur };
        if let Some(name) = unsafe { friendly_name(entry.FriendlyName) } {
            if name == interface {
                exists = true;
                let mut ua = entry.FirstUnicastAddress;
                while !ua.is_null() {
                    let u = unsafe { &*ua };
                    if let Some((addr, prefix_len)) = unsafe { read_v4(u) } {
                        out.push(InterfaceV4Addr { addr, prefix_len });
                    }
                    ua = u.Next;
                }
            }
        }
        cur = entry.Next;
    }
    if !exists {
        return Err(OspfTransportError::UnknownInterface(interface.to_string()));
    }
    Ok(out)
}

/// Enumerate the IPv6 addresses and prefix lengths of `interface`.
pub fn interface_v6_addrs(interface: &str) -> Result<Vec<InterfaceV6Addr>, OspfTransportError> {
    let list = get_adapters_addresses().map_err(|_| os_error("GetAdaptersAddresses"))?;
    let mut out = Vec::new();
    let mut exists = false;
    let mut cur = list.head;
    while !cur.is_null() {
        let entry = unsafe { &*cur };
        if let Some(name) = unsafe { friendly_name(entry.FriendlyName) } {
            if name == interface {
                exists = true;
                let mut ua = entry.FirstUnicastAddress;
                while !ua.is_null() {
                    let u = unsafe { &*ua };
                    if let Some((addr, prefix_len)) = unsafe { read_v6(u) } {
                        if !addr.is_loopback() {
                            out.push(InterfaceV6Addr {
                                addr,
                                prefix_len,
                                // Windows encodes the scope id in
                                // the sockaddr_in6 `sin6_scope_id`;
                                // Babel resolves its own scope id at
                                // bind time on Windows too.
                                scope_id: 0,
                            });
                        }
                    }
                    ua = u.Next;
                }
            }
        }
        cur = entry.Next;
    }
    if !exists {
        return Err(OspfTransportError::UnknownInterface(interface.to_string()));
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// OSPF raw-socket transport — Windows stub
// ---------------------------------------------------------------------------

/// Windows placeholder for the raw `IPPROTO_OSPF` socket — returns
/// [`OspfTransportError::Unsupported`] from every method. Windows
/// would need `WSASocket` with `IPPROTO_OSPF` and per-adapter
/// multicast scoping; that path is not implemented in librouting.
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

/// Windows placeholder for the OSPFv3 raw socket — same contract as
/// the v2 placeholder.
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

#[cfg(test)]
mod tests {
    use super::*;

    /// Live test — enumerates this machine's adapters. Windows only.
    /// Skips on CI containers that have no network adapters by
    /// returning early when the list is empty. When adapters ARE
    /// present, verifies the names look like real Windows adapter
    /// names (not garbage like "@" which was the symptom of a struct
    /// layout bug where FriendlyName was at the wrong offset).
    #[test]
    fn list_interfaces_smoke() {
        let ifaces = match list_interfaces() {
            Ok(v) => v,
            Err(e) => {
                eprintln!("skipped (no adapters available): {e}");
                return;
            }
        };
        if ifaces.is_empty() {
            eprintln!("skipped (no adapters returned)");
            return;
        }
        for i in &ifaces {
            assert!(!i.name.is_empty(), "adapter name empty: {i:?}");
            // Real Windows adapter names are human-readable ("Ethernet",
            // "Wi-Fi", "Loopback Pseudo-Interface 1"). The struct layout
            // bug produced 1-character names like "@" — assert the name
            // has at least 3 characters and contains alphabetic code
            // points to catch any future struct-layout regression.
            assert!(
                i.name.chars().count() >= 3,
                "adapter name too short (likely a struct layout bug): '{}' ({:?})",
                i.name,
                i
            );
            assert!(
                i.name.chars().any(|c| c.is_alphabetic()),
                "adapter name has no alphabetic chars (likely a struct layout bug): '{}' ({:?})",
                i.name,
                i
            );
        }
    }
}
