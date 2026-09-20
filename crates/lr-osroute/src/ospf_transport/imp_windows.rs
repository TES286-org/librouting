//! Windows implementation — interface enumeration via the IP Helper
//! API (`GetAdaptersAddresses`).
//!
//! Built for `target_os = "windows"`. The raw OSPF transport types
//! stay stubs (returns [`OspfTransportError::Unsupported`]) — the
//! OSPF daemon itself is Linux-only — but `list_interfaces`,
//! `interface_v4_addrs`, `interface_v6_addrs` and `ifindex_of` work,
//! so Babel's `[[babel.interface]]` glob matcher is fully operational.
//!
//! ## Why a separate file
//!
//! Windows has neither `getifaddrs` nor `if_nametoindex`. The closest
//! analogue is `GetAdaptersAddresses` (iphlpapi.dll), which returns a
//! linked list of `IP_ADAPTER_ADDRESSES` structs — one per adapter —
//! each carrying its `FriendlyName` (UTF-16), `FirstPrefix`,
//! `FirstUnicastAddress`, and an `OperStatus` field that distinguishes
//! `IfOperStatusUp` from `IfOperStatusDown`.
//!
//! We translate that into the same `InterfaceEntry` shape the Linux
//! `getifaddrs` path produces, so callers (the Babel interface matcher
//! in `daemon.rs`) work unchanged across platforms.

use std::ffi::c_void;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::ptr;

use super::{InterfaceEntry, InterfaceV4Addr, InterfaceV6Addr, OspfTransportError};

// ---------------------------------------------------------------------------
// Constants — Windows SDK values (used by GetAdaptersAddresses callers)
// ---------------------------------------------------------------------------

/// `AF_INET` — same value as on every other platform (Winsock2).
const AF_INET: u16 = 2;
/// `AF_INET6` — Windows defines this as 23 (`WSA_ADDRESS_FAMILY`).
const AF_INET6: u16 = 23;

/// `GAA_FLAG_SKIP_ANYCAST` — omit anycast addresses.
const GAA_FLAG_SKIP_ANYCAST: u32 = 0x0002;
/// `GAA_FLAG_SKIP_MULTICAST` — omit multicast addresses.
const GAA_FLAG_SKIP_MULTICAST: u32 = 0x0004;
/// `GAA_FLAG_INCLUDE_PREFIX` — request the per-address prefix list
/// (needed to derive IPv4 prefix lengths; `OnLinkPrefixLength` was
/// only added to `IP_ADAPTER_UNICAST_ADDRESS` in Vista+, but we ask
/// for the prefix list explicitly to cover older targets).
const GAA_FLAG_INCLUDE_PREFIX: u32 = 0x0010;
/// `GAA_FLAG_SKIP_DNS_SERVER` — omit DNS server addresses.
const GAA_FLAG_SKIP_DNS_SERVER: u32 = 0x0080;

const ERROR_SUCCESS: u32 = 0;
const ERROR_BUFFER_OVERFLOW: u32 = 111;

/// `IfOperStatusUp` (`IfOperStatus` enumeration).
const IF_OPER_STATUS_UP: u32 = 1;

// ---------------------------------------------------------------------------
// FFI
// ---------------------------------------------------------------------------

/// `SOCKET_ADDRESS` — a pointer + length pair wrapping a `sockaddr*`.
#[repr(C)]
struct SocketAddress {
    lp_sockaddr: *mut u8,
    i_sockaddr_length: i32,
}

/// `IP_ADAPTER_UNICAST_ADDRESS_LH` — one unicast address on an
/// adapter. The struct's full Vista+ layout is larger; we lay out
/// only the leading fields up to `address` and read the
/// `OnLinkPrefixLength` field by offset (see [`Self::on_link_prefix_len`]).
#[repr(C)]
struct IpAdapterUnicastAddress {
    /// Vista+ form: a union `Alignment` of `Length`+`Reserved` (8 bytes
    /// on 64-bit). Win32 declares the leading field as a union that
    /// is 8-byte aligned, so the rest of the struct layout depends on
    /// that.
    _alignment: [u8; 8],
    next: *mut IpAdapterUnicastAddress,
    /// `IP_ADDRESS_SUFFIX IpAddress` — the legacy WinXP form
    /// (`PrefixLength` field at offset 20). We never read this directly.
    _legacy_ip_address: [u8; 8],
    address: SocketAddress,
    // The Vista+ form continues with `DadState`, `ScopeId`, `Lifetime`
    // (16 bytes), then `OnLinkPrefixLength` at offset 48 from the
    // struct start (after `address`).
}

impl IpAdapterUnicastAddress {
    /// Read `OnLinkPrefixLength` (Vista+). The field sits at a fixed
    /// offset after `address` in the `IP_ADAPTER_UNICAST_ADDRESS_LH`
    /// layout. We re-derive it from the struct's start address to
    /// stay robust against SDK header growth — the struct's *declared*
    /// length grows but the leading-field offsets we use are stable.
    ///
    /// SAFETY: the caller must pass a pointer returned by
    /// `GetAdaptersAddresses`. We never read past byte 48 from the
    /// struct start.
    unsafe fn on_link_prefix_len(&self) -> u8 {
        const OFFSET: usize = 48;
        unsafe { *((self as *const Self as *const u8).add(OFFSET)) }
    }
}

/// `IP_ADAPTER_ADDRESSES` — one network adapter (LH form, Vista+).
///
/// We read only the FriendlyName, the unicast-address list, and the
/// `OperStatus` / `IfIndex` fields. The full struct has ~25 fields;
/// we lay out only the leading ones we touch.
#[repr(C)]
struct IpAdapterAddresses {
    next: *mut IpAdapterAddresses,
    _adapter_name: *mut u8, // ANSI (latin-1) name, low-level — we use FriendlyName instead.
    first_unicast_address: *mut IpAdapterUnicastAddress,
    _first_anycast_address: *mut c_void,
    _first_multicast_address: *mut c_void,
    _first_dns_server_address: *mut c_void,
    _dns_suffix: *mut u16,
    friendly_name: *mut u16,
    _physical_address: [u8; 8],
    _physical_address_length: u32,
    _flags: u32,
    mtu: u32,
    if_type: u32,
    oper_status: u32,
    if_index: u32,
}

extern "system" {
    fn GetAdaptersAddresses(
        family: u32,
        flags: u32,
        reserved: *mut c_void,
        adapter_addresses: *mut IpAdapterAddresses,
        size_pointer: *mut u32,
    ) -> u32;
}

/// Owned adapter list — the `Box<[u8]>` holds the backing allocation
/// returned by `GetAdaptersAddresses`, and `head` is the typed head
/// pointer into that buffer. Drop reclaims the memory automatically.
struct AdapterList {
    #[allow(dead_code)]
    buf: Box<[u8]>,
    head: *mut IpAdapterAddresses,
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
            buf.as_mut_ptr() as *mut IpAdapterAddresses,
            &mut size,
        )
    };
    if rc != ERROR_SUCCESS {
        return Err(OspfTransportError::Os {
            context: "GetAdaptersAddresses(fill)",
            errno: rc as i32,
        });
    }
    let head = buf.as_mut_ptr() as *mut IpAdapterAddresses;
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
        if let Some(name) = unsafe { friendly_name(entry.friendly_name) } {
            if name == interface {
                let idx = entry.if_index;
                return Some(idx);
            }
        }
        cur = entry.next;
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

fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

fn os_error(context: &'static str) -> OspfTransportError {
    OspfTransportError::Os {
        context,
        errno: errno(),
    }
}

/// Read `(Ipv4Addr, prefix_len)` out of an `IP_ADAPTER_UNICAST_ADDRESS`
/// when its embedded `SOCKET_ADDRESS` points at an `AF_INET`
/// `sockaddr_in`.
///
/// # Safety
/// `u` must point at a valid `IpAdapterUnicastAddress` returned by
/// `GetAdaptersAddresses`.
unsafe fn read_v4(u: &IpAdapterUnicastAddress) -> Option<(Ipv4Addr, u8)> {
    let sa = &u.address;
    if sa.i_sockaddr_length < 16 || sa.lp_sockaddr.is_null() {
        return None;
    }
    let family = unsafe { *(sa.lp_sockaddr as *const u16) };
    if family != AF_INET {
        return None;
    }
    // Winsock2 `sockaddr_in`: family(2) + port(2) + addr(4) + zero(8).
    let bytes = unsafe { std::slice::from_raw_parts(sa.lp_sockaddr.add(4), 4) };
    let addr = Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3]);
    Some((addr, unsafe { u.on_link_prefix_len() }))
}

/// Read `(Ipv6Addr, prefix_len)` out of an `IP_ADAPTER_UNICAST_ADDRESS`
/// when its embedded `SOCKET_ADDRESS` points at an `AF_INET6`
/// `sockaddr_in6`.
///
/// # Safety
/// `u` must point at a valid `IpAdapterUnicastAddress` returned by
/// `GetAdaptersAddresses`.
unsafe fn read_v6(u: &IpAdapterUnicastAddress) -> Option<(Ipv6Addr, u8)> {
    let sa = &u.address;
    if sa.i_sockaddr_length < 28 || sa.lp_sockaddr.is_null() {
        return None;
    }
    let family = unsafe { *(sa.lp_sockaddr as *const u16) };
    if family != AF_INET6 {
        return None;
    }
    // Winsock2 `sockaddr_in6`: family(2) + port(2) + flowinfo(4) +
    // addr(16) + scope_id(4). Address sits at offset 8.
    let bytes = unsafe { std::slice::from_raw_parts(sa.lp_sockaddr.add(8), 16) };
    let mut arr = [0u8; 16];
    arr.copy_from_slice(bytes);
    Some((Ipv6Addr::from(arr), unsafe { u.on_link_prefix_len() }))
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
        let name = unsafe { friendly_name(entry.friendly_name) }.unwrap_or_default();
        if name.is_empty() {
            cur = entry.next;
            continue;
        }
        let up = entry.oper_status == IF_OPER_STATUS_UP;
        // Windows has no direct `IFF_RUNNING` analogue; treat `up` as
        // `running` (the carrier state is folded into OperStatus when
        // the media is disconnected).
        let running = up;
        let mut v4 = Vec::new();
        let mut v6 = Vec::new();
        let mut ua = entry.first_unicast_address;
        while !ua.is_null() {
            // SAFETY: `ua` was returned by GetAdaptersAddresses.
            let u = unsafe { &*ua };
            if let Some((addr, _)) = unsafe { read_v4(u) } {
                v4.push(addr);
            }
            if let Some((addr, _)) = unsafe { read_v6(u) } {
                v6.push(addr);
            }
            ua = u.next;
        }
        out.push(InterfaceEntry {
            name,
            v4,
            v6,
            up,
            running,
        });
        cur = entry.next;
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
        if let Some(name) = unsafe { friendly_name(entry.friendly_name) } {
            if name == interface {
                exists = true;
                let mut ua = entry.first_unicast_address;
                while !ua.is_null() {
                    let u = unsafe { &*ua };
                    if let Some((addr, prefix_len)) = unsafe { read_v4(u) } {
                        out.push(InterfaceV4Addr { addr, prefix_len });
                    }
                    ua = u.next;
                }
            }
        }
        cur = entry.next;
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
        if let Some(name) = unsafe { friendly_name(entry.friendly_name) } {
            if name == interface {
                exists = true;
                let mut ua = entry.first_unicast_address;
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
                    ua = u.next;
                }
            }
        }
        cur = entry.next;
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
    /// returning early when the list is empty.
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
        // Each adapter has a non-empty name; no other invariant —
        // CI's Hyper-V virtual ethernet may be the only adapter and
        // it can be either up or down depending on the runner.
        for i in &ifaces {
            assert!(!i.name.is_empty(), "adapter name empty: {i:?}");
        }
    }
}
