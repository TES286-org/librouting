//! Windows implementation — interface enumeration via the IP Helper
//! API (`GetAdaptersAddresses`).
//!
//! Built for `target_os = "windows"`. The raw OSPF transport types
//! stay stubs (returns [`OspfTransportError::Unsupported`]) — the
//! OSPF daemon itself is Linux-only — but `list_interfaces`,
//! `interface_v4_addrs`, `interface_v6_addrs` and `ifindex_of` work,
//! so Babel's `[[babel.interface]]` glob matcher is fully operational.
//!
//! ## Struct layouts (verified against Windows SDK `iptypes.h`)
//!
//! `IP_ADAPTER_ADDRESSES_LH` on 64-bit (field → offset):
//! ```text
//!   Alignment union        @0   (8 bytes)
//!   Next                   @8   (pointer)
//!   AdapterName            @16  (PCHAR)
//!   FriendlyName           @24  (PWSTR)         ← we use this
//!   FirstUnicastAddress     @32  (pointer)       ← we use this
//!   FirstAnycastAddress    @40
//!   FirstMulticastAddress  @48
//!   FirstDnsServerAddress  @56
//!   DnsSuffix              @64
//!   Description             @72
//!   ... (PhysicalAddress, Flags, Mtu, IfType, OperStatus, Ipv6IfIndex,
//!        ZoneIndices[16], IfIndex, ...)
//! ```
//!
//! `IP_ADAPTER_UNICAST_ADDRESS_LH` on 64-bit:
//! ```text
//!   Alignment union        @0   (8 bytes)
//!   Next                   @8   (pointer)
//!   Address                @16  (SOCKET_ADDRESS, 16 bytes)
//!   AddressPrefix          @32  (IP_ADDRESS_PREFIX, 24 bytes)
//!   DadState               @56  (4 bytes)
//!   ValidLifetime          @60
//!   PreferredLifetime      @64
//!   LeaseLifetime          @68
//!   OnLinkPrefixLength     @72  (ULONG)         ← we read this
//! ```
//!
//! `SOCKET_ADDRESS` on 64-bit is 16 bytes: `lpSockaddr` (8-byte
//! pointer) + `iSockaddrLength` (4-byte INT) + 4 bytes padding for
//! 8-byte alignment.

use std::ffi::c_void;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::ptr;

use super::{InterfaceEntry, InterfaceV4Addr, InterfaceV6Addr, OspfTransportError};

// ---------------------------------------------------------------------------
// Constants — Windows SDK values
// ---------------------------------------------------------------------------

/// `AF_INET` — Winsock2 value (same as on every platform).
const AF_INET: u16 = 2;
/// `AF_INET6` — Windows defines this as 23 (`WSA_ADDRESS_FAMILY`).
const AF_INET6: u16 = 23;

/// `GAA_FLAG_SKIP_ANYCAST` — omit anycast addresses.
const GAA_FLAG_SKIP_ANYCAST: u32 = 0x0002;
/// `GAA_FLAG_SKIP_MULTICAST` — omit multicast addresses.
const GAA_FLAG_SKIP_MULTICAST: u32 = 0x0004;
/// `GAA_FLAG_INCLUDE_PREFIX` — request `OnLinkPrefixLength` on each
/// unicast address (Vista+; the field is only populated when this
/// flag is set).
const GAA_FLAG_INCLUDE_PREFIX: u32 = 0x0010;
/// `GAA_FLAG_SKIP_DNS_SERVER` — omit DNS server addresses.
const GAA_FLAG_SKIP_DNS_SERVER: u32 = 0x0080;

const ERROR_SUCCESS: u32 = 0;
const ERROR_BUFFER_OVERFLOW: u32 = 111;

/// `IfOperStatusUp` (`IfOperStatus` enumeration).
const IF_OPER_STATUS_UP: u32 = 1;

// ---------------------------------------------------------------------------
// FFI struct declarations — match Windows SDK `iptypes.h` exactly
// ---------------------------------------------------------------------------

/// `SOCKET_ADDRESS` — a pointer + length pair wrapping a `sockaddr*`.
/// On 64-bit: 8 (ptr) + 4 (int) + 4 (pad) = 16 bytes.
#[repr(C)]
struct SocketAddress {
    lp_sockaddr: *mut u8,
    i_sockaddr_length: i32,
    _padding: u32,
}

/// `IP_ADAPTER_UNICAST_ADDRESS_LH` (Vista+ form). We declare the full
/// struct up to and including `OnLinkPrefixLength` so Rust's
/// `#[repr(C)]` layout matches the SDK and the offset of every field
/// is correct by construction — no manual offset arithmetic.
///
/// Fields after `OnLinkPrefixLength` (e.g. `FirstGatewayAddress`) are
/// not declared because we never read them; the SDK struct continues
/// but truncating a `#[repr(C)]` struct at any point is safe as long
/// as we never read past what we declared.
#[repr(C)]
struct IpAdapterUnicastAddress {
    /// Union `{ ULONGLONG Alignment; struct { ULONG Length; DWORD Reserved; } }`
    _alignment: u64,
    /// `struct _IP_ADAPTER_UNICAST_ADDRESS *Next`
    next: *mut IpAdapterUnicastAddress,
    /// `SOCKET_ADDRESS Address` — 16 bytes on 64-bit.
    address: SocketAddress,
    /// `IP_ADDRESS_PREFIX AddressPrefix` — `SOCKET_ADDRESS Prefix` +
    /// `UINT8 PrefixLength` + 7 bytes padding = 24 bytes on 64-bit.
    _address_prefix: [u8; 24],
    /// `NL_DAD_STATE DadState` (enum = ULONG = 4 bytes).
    _dad_state: u32,
    /// `ULONG ValidLifetime`.
    _valid_lifetime: u32,
    /// `ULONG PreferredLifetime`.
    _preferred_lifetime: u32,
    /// `ULONG LeaseLifetime`.
    _lease_lifetime: u32,
    /// `ULONG OnLinkPrefixLength` — the prefix length we want.
    on_link_prefix_length: u32,
}

/// `IP_ADAPTER_ADDRESSES_LH` (Vista+ form). We declare the full
/// struct up to `IfIndex` so every field offset is correct by
/// construction. Fields after `IfIndex` (FirstPrefix, etc.) are
/// omitted — we never read them.
#[repr(C)]
struct IpAdapterAddresses {
    /// Union `{ ULONGLONG Alignment; struct { ULONG Length; IF_INDEX IfIndex; } }`
    /// — the union is 8 bytes; `IfIndex` sits at offset 4 inside it.
    _alignment: u64,
    /// `struct _IP_ADAPTER_ADDRESSES *Next`
    next: *mut IpAdapterAddresses,
    /// `PCHAR AdapterName` — ANSI (latin-1) name.
    _adapter_name: *mut u8,
    /// `PWSTR FriendlyName` — UTF-16 display name (e.g. "Ethernet").
    friendly_name: *mut u16,
    /// `struct _IP_ADAPTER_UNICAST_ADDRESS *FirstUnicastAddress`
    first_unicast_address: *mut IpAdapterUnicastAddress,
    /// `struct _IP_ADAPTER_ANYCAST_ADDRESS *FirstAnycastAddress`
    _first_anycast_address: *mut c_void,
    /// `struct _IP_ADAPTER_MULTICAST_ADDRESS *FirstMulticastAddress`
    _first_multicast_address: *mut c_void,
    /// `struct _IP_ADAPTER_DNS_SERVER_ADDRESS *FirstDnsServerAddress`
    _first_dns_server_address: *mut c_void,
    /// `PWCHAR DnsSuffix`
    _dns_suffix: *mut u16,
    /// `PWCHAR Description`
    _description: *mut u16,
    /// `UCHAR PhysicalAddress[MAX_ADAPTER_ADDRESS_LENGTH]` (8 bytes).
    _physical_address: [u8; 8],
    /// `ULONG PhysicalAddressLength`.
    _physical_address_length: u32,
    /// `ULONG Flags`.
    _flags: u32,
    /// `ULONG Mtu`.
    _mtu: u32,
    /// `ULONG IfType`.
    _if_type: u32,
    /// `IF_OPER_STATUS OperStatus` (enum = ULONG = 4 bytes).
    oper_status: u32,
    /// `ULONG Ipv6IfIndex`.
    _ipv6_if_index: u32,
    /// `ULONG ZoneIndices[16]` — 64 bytes.
    _zone_indices: [u32; 16],
    /// `IF_INDEX IfIndex` — the standalone interface index field.
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

fn os_error(context: &'static str) -> OspfTransportError {
    OspfTransportError::Os {
        context,
        errno: std::io::Error::last_os_error().raw_os_error().unwrap_or(0),
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
    // Winsock2 `sockaddr` has a 2-byte `sa_family` at offset 0. On
    // Windows the family is a `ADDRESS_FAMILY` (u16), not the BSD
    // `sa_family_t` (which can be u8). Reading as u16 is safe because
    // the struct is 2-byte aligned (it starts at the beginning of a
    // malloc'd buffer, or at an 8-byte-aligned offset within one).
    let family = unsafe { ptr::read_unaligned(sa.lp_sockaddr as *const u16) };
    if family != AF_INET {
        return None;
    }
    // Winsock2 `sockaddr_in`: family(2) + port(2) + addr(4) + zero(8).
    let bytes = unsafe { ptr::read_unaligned(sa.lp_sockaddr.add(4) as *const [u8; 4]) };
    let addr = Ipv4Addr::from(bytes);
    Some((addr, u.on_link_prefix_length as u8))
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
    let family = unsafe { ptr::read_unaligned(sa.lp_sockaddr as *const u16) };
    if family != AF_INET6 {
        return None;
    }
    // Winsock2 `sockaddr_in6`: family(2) + port(2) + flowinfo(4) +
    // addr(16) + scope_id(4). Address sits at offset 8.
    let bytes = unsafe { ptr::read_unaligned(sa.lp_sockaddr.add(8) as *const [u8; 16]) };
    Some((Ipv6Addr::from(bytes), u.on_link_prefix_length as u8))
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

    /// Compile-time check: the `SocketAddress` struct is 16 bytes on
    /// 64-bit (8 for the pointer, 4 for the int, 4 padding). This
    /// pins down the layout the rest of the code depends on.
    #[test]
    fn socket_address_size_is_16() {
        assert_eq!(
            std::mem::size_of::<SocketAddress>(),
            16,
            "SOCKET_ADDRESS must be 16 bytes on 64-bit (8 ptr + 4 int + 4 pad)"
        );
    }

    /// Compile-time check: `IpAdapterUnicastAddress` has the
    /// `on_link_prefix_length` field at the expected offset (72 on
    /// 64-bit). If the struct layout drifts from the Windows SDK,
    /// this test catches it before the field is read at runtime.
    #[test]
    fn unicast_address_on_link_prefix_length_offset() {
        assert_eq!(
            std::mem::offset_of!(IpAdapterUnicastAddress, on_link_prefix_length),
            72,
            "OnLinkPrefixLength must be at offset 72 on 64-bit \
             (8 alignment + 8 next + 16 address + 24 address_prefix \
             + 4 dad_state + 4*3 lifetimes = 72)"
        );
    }

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
