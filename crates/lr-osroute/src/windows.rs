//! Windows IP Helper API route table implementation.
//!
//! Windows exposes the forwarding information base (FIB) through the IP
//! Helper API (`iphlpapi.dll`). The relevant entry points are:
//!
//! * [`CreateIpForwardEntry2`] / [`DeleteIpForwardEntry2`] — add/remove a
//!   row described by `MIB_IPFORWARD_ROW2`.
//! * [`GetIpForwardTable2`] — snapshot the whole table as an array of
//!   `MIB_IPFORWARD_ROW2`.
//! * [`FreeMibTable`] — release the buffer returned by the getter.
//!
//! ## Struct layout (win32/64, verified against `netioapi.h` in the
//! Windows SDK)
//!
//! ```text
//! typedef struct _MIB_IPFORWARD_ROW2 {
//!     NET_LUID          InterfaceLuid;        // u64   @0
//!     NET_IFINDEX       InterfaceIndex;       // u32   @8
//!     IP_ADDRESS_PREFIX DestinationPrefix;    //       @12 (32 bytes)
//!     SOCKADDR_INET     NextHop;              //       @44 (28 bytes)
//!     ULONG             SitePrefixLength;     // u32   @72
//!     ULONG             ValidLifetime;        // u32   @76
//!     ULONG             PreferredLifetime;    // u32   @80
//!     ULONG             Metric;               // u32   @84
//!     NL_ROUTE_PROTOCOL Protocol;             // u32   @88
//!     BOOLEAN           Loopback;             // u8    @92
//!     BOOLEAN           AutoconfigureAddress; // u8    @93
//!     BOOLEAN           Publish;              // u8    @94
//!     BOOLEAN           Immortal;             // u8    @95
//!     ULONG             Age;                  // u32   @96
//!     NL_ROUTE_ORIGIN   Origin;               // u32   @100
//! } MIB_IPFORWARD_ROW2;                       //       = 104 bytes
//!
//! typedef struct _MIB_IPFORWARD_TABLE2 {
//!     ULONG NumEntries;                        // u32   @0
//!     MIB_IPFORWARD_ROW2 Table[1];             //       @8 (8-byte aligned)
//! } MIB_IPFORWARD_TABLE2;
//! ```
//!
//! `SOCKADDR_INET` is a union of `sockaddr_in` (16 bytes) and
//! `sockaddr_in6` (28 bytes) where the first 2 bytes alias the family:
//! `AF_INET = 2`, `AF_INET6 = 23` (note: *not* the BSD values).
//!
//! ## Lifetime semantics
//!
//! Rows created with `ValidLifetime = PreferredLifetime = 0xffffffff`
//! (infinite) survive reboots only when also registered as persistent by
//! an external agent; for a routing daemon the standard pattern is to
//! re-install best paths after restart, which is what `lr-daemon` does.
//!
//! ## Implementation notes
//!
//! * No `windows-sys` dependency: the handful of structs and entry points
//!   are declared by hand, mirroring the Linux/BSD backends' zero-dependency
//!   approach. `#[link(name = "iphlpapi")]` pulls the import library that
//!   ships with every mingw-w64 and MSVC toolchain.
//! * The row is zeroed and then initialised with the same defaults the
//!   documented `InitializeIpForwardEntry` helper applies (infinite
//!   lifetimes, not published, immortal) so we do not depend on that
//!   export being present in older import libraries.
//! * When `if_index == 0` the interface is resolved by finding the
//!   longest-prefix match for the next hop in the current table — the
//!   same behaviour as `route add ... mask ... gw` accepting an interface
//!   inferred from the gateway.

use crate::{KernelRoute, OsRouteError, OsRouteTable};
use lr_core::addr::{IpAddr, Prefix};
use lr_core::rib::Protocol;

// Address families (Windows values).
const AF_INET: u16 = 2;
const AF_INET6: u16 = 23;

// NL_ROUTE_PROTOCOL values (netioapi.h).
const MIB_PROTOCOL_BGP: u32 = 14;
const MIB_PROTOCOL_LOCAL: u32 = 2;
const MIB_PROTOCOL_NETMGMT: u32 = 3;

// Common Win32 error codes returned by the IP Helper API.
const NO_ERROR: u32 = 0;
const ERROR_INVALID_PARAMETER: u32 = 87;
const ERROR_NOT_FOUND: u32 = 1168;
const ERROR_OBJECT_ALREADY_EXISTS: u32 = 5010;

const SIZEOF_ROW: usize = 104;
const SIZEOF_TABLE_HEADER: usize = 8; // ULONG + alignment padding

#[repr(C)]
#[derive(Clone, Copy)]
union SockaddrInet {
    v4: SockaddrIn,
    v6: SockaddrIn6,
    family: u16,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct SockaddrIn {
    family: u16,
    port: u16,
    addr: [u8; 4],
    zero: [u8; 8],
}

#[repr(C)]
#[derive(Clone, Copy)]
struct SockaddrIn6 {
    family: u16,
    port: u16,
    flowinfo: u32,
    addr: [u8; 16],
    scope_id: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct IpAddressPrefix {
    prefix: SockaddrInet,
    prefix_length: u8,
    _pad: [u8; 3],
}

#[repr(C)]
#[derive(Clone, Copy)]
struct MibIpForwardRow2 {
    interface_luid: u64,
    interface_index: u32,
    destination_prefix: IpAddressPrefix,
    next_hop: SockaddrInet,
    site_prefix_length: u32,
    valid_lifetime: u32,
    preferred_lifetime: u32,
    metric: u32,
    protocol: u32,
    loopback: u8,
    autoconfigure_address: u8,
    publish: u8,
    immortal: u8,
    age: u32,
    origin: u32,
}

const _: () = assert!(core::mem::size_of::<MibIpForwardRow2>() == SIZEOF_ROW);
const _: () = assert!(core::mem::size_of::<SockaddrInet>() == 28);
const _: () = assert!(core::mem::size_of::<IpAddressPrefix>() == 32);

#[repr(C)]
struct MibIpForwardTable2 {
    num_entries: u32,
    // Flexible-array style: rows follow the header at offset 8.
    _table_first: MibIpForwardRow2,
}

#[link(name = "iphlpapi")]
extern "system" {
    fn CreateIpForwardEntry2(row: *const MibIpForwardRow2) -> u32;
    fn DeleteIpForwardEntry2(row: *const MibIpForwardRow2) -> u32;
    fn GetIpForwardTable2(family: u16, table: *mut *mut MibIpForwardTable2) -> u32;
    fn FreeMibTable(buffer: *mut core::ffi::c_void);
}

/// IP Helper backed implementation of [`OsRouteTable`].
pub struct IpHelper {
    /// Cached interface index (0 = resolve per operation).
    if_index: u32,
}

impl IpHelper {
    pub fn connect() -> Result<Self, OsRouteError> {
        // Windows needs no handle; the API is stateless. Probe the table
        // once so a missing/unusable iphlpapi surfaces immediately.
        let mut table: *mut MibIpForwardTable2 = core::ptr::null_mut();
        // SAFETY: `table` is an out-pointer; the allocation it receives is
        // owned by us and freed below with FreeMibTable.
        let rc = unsafe { GetIpForwardTable2(0, &mut table) };
        if rc != NO_ERROR {
            return Err(win_err("GetIpForwardTable2", rc));
        }
        if !table.is_null() {
            // SAFETY: pointer came from GetIpForwardTable2.
            unsafe { FreeMibTable(table as *mut core::ffi::c_void) };
        }
        Ok(Self { if_index: 0 })
    }

    fn make_row(prefix: &Prefix, next_hop: &IpAddr, if_index: u32) -> MibIpForwardRow2 {
        let mut row = MibIpForwardRow2 {
            interface_luid: 0,
            interface_index: if_index,
            destination_prefix: IpAddressPrefix {
                prefix: sockaddr_for(&prefix.addr),
                prefix_length: prefix.prefix_len,
                _pad: [0; 3],
            },
            next_hop: sockaddr_for(next_hop),
            site_prefix_length: 0,
            // Infinite lifetimes = permanent entry (mirrors the defaults of
            // InitializeIpForwardEntry).
            valid_lifetime: u32::MAX,
            preferred_lifetime: u32::MAX,
            metric: 0,
            protocol: MIB_PROTOCOL_BGP,
            loopback: 0,
            autoconfigure_address: 0,
            publish: 0,
            immortal: 1,
            age: 0,
            origin: 0, // NlroManual
        };
        if prefix.prefix_len == 0 {
            // A /0 destination carries no address bits.
            row.destination_prefix.prefix_length = 0;
        }
        row
    }

    /// Resolve the interface leading towards `next_hop` by longest-prefix
    /// match against the current table. Returns 0 when nothing matches.
    fn resolve_interface(next_hop: &IpAddr) -> u32 {
        let mut table: *mut MibIpForwardTable2 = core::ptr::null_mut();
        // SAFETY: out-pointer, ownership transferred to us.
        let rc = unsafe { GetIpForwardTable2(0, &mut table) };
        if rc != NO_ERROR || table.is_null() {
            return 0;
        }
        // SAFETY: rows live inside the allocation `table` points to; we
        // only read while it is alive and free it before returning.
        let (rows, len) = unsafe { table_rows(table) };
        let mut best: Option<(u8, u32)> = None;
        if !rows.is_null() {
            for row in unsafe { core::slice::from_raw_parts(rows, len) } {
                // SAFETY: reading the union through its family alias is the
                // documented way to inspect a SOCKADDR_INET.
                let (dst, plen) = unsafe { prefix_of(row) };
                if prefix_contains(dst, plen, next_hop) {
                    let better = best.map(|(b, _)| plen > b).unwrap_or(true);
                    if better && row.interface_index != 0 {
                        best = Some((plen, row.interface_index));
                    }
                }
            }
        }
        // SAFETY: release the API-allocated buffer.
        unsafe { FreeMibTable(table as *mut core::ffi::c_void) };
        best.map(|(_, idx)| idx).unwrap_or(0)
    }
}

impl OsRouteTable for IpHelper {
    type Error = OsRouteError;

    fn add_route(
        &mut self,
        prefix: Prefix,
        next_hop: IpAddr,
        if_index: u32,
    ) -> Result<(), Self::Error> {
        let if_index = if if_index != 0 {
            if_index
        } else if self.if_index != 0 {
            self.if_index
        } else {
            Self::resolve_interface(&next_hop)
        };
        let row = Self::make_row(&prefix, &next_hop, if_index);
        // SAFETY: `row` is a fully-initialised stack value; the API only
        // reads from it.
        let mut rc = unsafe { CreateIpForwardEntry2(&row) };
        if rc == ERROR_OBJECT_ALREADY_EXISTS {
            // Idempotent add: update the existing row in place.
            rc = unsafe { DeleteIpForwardEntry2(&row) };
            if rc == NO_ERROR || rc == ERROR_NOT_FOUND {
                rc = unsafe { CreateIpForwardEntry2(&row) };
            }
        }
        if rc != NO_ERROR {
            return Err(win_err("CreateIpForwardEntry2", rc));
        }
        self.if_index = if_index;
        Ok(())
    }

    fn delete_route(&mut self, prefix: Prefix) -> Result<(), Self::Error> {
        // Deleting requires the full key (prefix + next hop + interface);
        // scan the table for rows matching the prefix and delete each.
        let mut table: *mut MibIpForwardTable2 = core::ptr::null_mut();
        // SAFETY: out-pointer, ownership transferred to us.
        let rc = unsafe { GetIpForwardTable2(0, &mut table) };
        if rc != NO_ERROR {
            return Err(win_err("GetIpForwardTable2", rc));
        }
        if table.is_null() {
            return Ok(());
        }
        // SAFETY: rows are read while the allocation is alive.
        let (rows, len) = unsafe { table_rows(table) };
        let mut last_rc = ERROR_NOT_FOUND;
        if !rows.is_null() {
            for row in unsafe { core::slice::from_raw_parts(rows, len) } {
                let (dst, plen) = unsafe { prefix_of(row) };
                if plen != prefix.prefix_len {
                    continue;
                }
                if !addr_eq(&dst, &prefix.addr) {
                    continue;
                }
                if row.protocol != MIB_PROTOCOL_BGP {
                    continue; // never touch rows we did not install
                }
                // SAFETY: row is a copy of a table entry; the API matches on
                // destination prefix + next hop + interface.
                let rc2 = unsafe { DeleteIpForwardEntry2(row) };
                if rc2 != NO_ERROR {
                    last_rc = rc2;
                }
            }
        }
        // SAFETY: release the API-allocated buffer.
        unsafe { FreeMibTable(table as *mut core::ffi::c_void) };
        if last_rc == ERROR_NOT_FOUND {
            // Nothing matched — an idempotent delete succeeds.
            return Ok(());
        }
        if last_rc != NO_ERROR {
            return Err(win_err("DeleteIpForwardEntry2", last_rc));
        }
        Ok(())
    }

    fn list_routes(&mut self) -> Result<Vec<KernelRoute>, Self::Error> {
        let mut table: *mut MibIpForwardTable2 = core::ptr::null_mut();
        // SAFETY: out-pointer, ownership transferred to us.
        let rc = unsafe { GetIpForwardTable2(0, &mut table) };
        if rc != NO_ERROR {
            return Err(win_err("GetIpForwardTable2", rc));
        }
        if table.is_null() {
            return Ok(Vec::new());
        }
        // SAFETY: rows are read while the allocation is alive.
        let (rows, len) = unsafe { table_rows(table) };
        let mut out = Vec::with_capacity(len);
        if !rows.is_null() {
            for row in unsafe { core::slice::from_raw_parts(rows, len) } {
                let (dst, plen) = unsafe { prefix_of(row) };
                let prefix = match dst {
                    IpAddr::V4(b) => Prefix::new_v4(b, plen.min(32)),
                    IpAddr::V6(b) => Prefix::new_v6(b, plen.min(128)),
                };
                // SAFETY: reading the union's family alias then the matching
                // arm is the documented SOCKADDR_INET access pattern.
                let next_hop = unsafe { next_hop_of(row) };
                let protocol = match row.protocol {
                    MIB_PROTOCOL_LOCAL => Protocol::Connected,
                    MIB_PROTOCOL_NETMGMT => Protocol::Static,
                    MIB_PROTOCOL_BGP => Protocol::Bgp,
                    _ => Protocol::Other(row.protocol as u16),
                };
                out.push(KernelRoute {
                    prefix,
                    next_hop,
                    if_index: Some(row.interface_index),
                    metric: row.metric,
                    protocol,
                });
            }
        }
        // SAFETY: release the API-allocated buffer.
        unsafe { FreeMibTable(table as *mut core::ffi::c_void) };
        Ok(out)
    }
}

// ===== helpers =====

fn sockaddr_for(addr: &IpAddr) -> SockaddrInet {
    match addr {
        IpAddr::V4(b) => SockaddrInet {
            v4: SockaddrIn {
                family: AF_INET,
                port: 0,
                addr: *b,
                zero: [0; 8],
            },
        },
        IpAddr::V6(b) => SockaddrInet {
            v6: SockaddrIn6 {
                family: AF_INET6,
                port: 0,
                flowinfo: 0,
                addr: *b,
                scope_id: 0,
            },
        },
    }
}

/// # Safety
/// The caller must guarantee the union holds a valid socket address.
unsafe fn inet_addr_of(sa: &SockaddrInet) -> IpAddr {
    // SAFETY: family aliases the first two bytes of both arms.
    match unsafe { sa.family } {
        AF_INET6 => IpAddr::V6(unsafe { sa.v6.addr }),
        _ => IpAddr::V4(unsafe { sa.v4.addr }),
    }
}

/// # Safety
/// `table` must point to a live MIB_IPFORWARD_TABLE2 allocation.
unsafe fn table_rows(table: *mut MibIpForwardTable2) -> (*const MibIpForwardRow2, usize) {
    // SAFETY: the table header is followed by `num_entries` rows.
    let n = unsafe { (*table).num_entries } as usize;
    if n == 0 {
        return (core::ptr::null(), 0);
    }
    let rows = (table as *const u8).add(SIZEOF_TABLE_HEADER) as *const MibIpForwardRow2;
    (rows, n)
}

/// # Safety
/// `row` must be a valid MIB_IPFORWARD_ROW2.
unsafe fn prefix_of(row: &MibIpForwardRow2) -> (IpAddr, u8) {
    // SAFETY: reading the destination prefix union.
    let addr = unsafe { inet_addr_of(&row.destination_prefix.prefix) };
    (addr, row.destination_prefix.prefix_length)
}

/// # Safety
/// `row` must be a valid MIB_IPFORWARD_ROW2.
unsafe fn next_hop_of(row: &MibIpForwardRow2) -> Option<IpAddr> {
    // SAFETY: reading the next-hop union.
    let addr = unsafe { inet_addr_of(&row.next_hop) };
    match addr {
        IpAddr::V4([0, 0, 0, 0]) => None,
        _ => Some(addr),
    }
}

fn addr_eq(a: &IpAddr, b: &IpAddr) -> bool {
    a == b
}

/// Longest-prefix containment check used for interface resolution.
fn prefix_contains(prefix_addr: IpAddr, plen: u8, addr: &IpAddr) -> bool {
    match (prefix_addr, addr) {
        (IpAddr::V4(p), IpAddr::V4(a)) => {
            let bits = plen.min(32) as u32;
            if bits == 0 {
                return true;
            }
            let mask = u32::MAX << (32 - bits);
            let p = u32::from_be_bytes(p);
            let a = u32::from_be_bytes(*a);
            (p & mask) == (a & mask)
        }
        (IpAddr::V6(p), IpAddr::V6(a)) => {
            let bits = plen.min(128) as usize;
            if bits == 0 {
                return true;
            }
            for i in 0..bits / 8 {
                if p[i] != a[i] {
                    return false;
                }
            }
            let rem = bits % 8;
            if rem > 0 {
                let mask = 0xffu8 << (8 - rem);
                if p[bits / 8] & mask != a[bits / 8] & mask {
                    return false;
                }
            }
            true
        }
        _ => false,
    }
}

fn win_err(api: &str, code: u32) -> OsRouteError {
    let hint = match code {
        ERROR_INVALID_PARAMETER => " (invalid parameter — check prefix/next-hop family)",
        ERROR_NOT_FOUND => " (element not found)",
        5 => " (access denied — requires elevation)",
        _ => "",
    };
    OsRouteError(format!("{} failed: error {}{}", api, code, hint))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn struct_sizes_match_sdk() {
        // Compile-time layout guards (see const asserts above); this test
        // documents the expected numbers explicitly.
        assert_eq!(core::mem::size_of::<MibIpForwardRow2>(), 104);
        assert_eq!(core::mem::size_of::<SockaddrInet>(), 28);
        assert_eq!(core::mem::size_of::<IpAddressPrefix>(), 32);
        assert_eq!(core::mem::size_of::<SockaddrIn>(), 16);
    }

    #[test]
    fn prefix_contains_v4() {
        let net = IpAddr::V4([10, 1, 0, 0]);
        assert!(prefix_contains(net, 16, &IpAddr::V4([10, 1, 99, 5])));
        assert!(!prefix_contains(net, 16, &IpAddr::V4([10, 2, 0, 0])));
        assert!(prefix_contains(net, 0, &IpAddr::V4([192, 0, 2, 1])));
    }

    #[test]
    fn prefix_contains_v6() {
        let net = IpAddr::V6([0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        assert!(prefix_contains(
            net,
            32,
            &IpAddr::V6([0x20, 0x01, 0x0d, 0xb8, 0xff, 0xff, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,])
        ));
        assert!(!prefix_contains(
            net,
            32,
            &IpAddr::V6([0x20, 0x01, 0x0d, 0xb9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,])
        ));
    }
}
