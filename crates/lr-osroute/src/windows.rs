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
//! * [`InitializeIpForwardEntry`] — zero a `MIB_IPFORWARD_ROW2` and apply
//!   the documented defaults (infinite lifetimes, not published, immortal).
//!
//! ## Struct layouts
//!
//! All Win32 structs (`MIB_IPFORWARD_ROW2`, `MIB_IPFORWARD_TABLE2`,
//! `SOCKADDR_INET`, `IP_ADDRESS_PREFIX`, `SOCKADDR_IN`, `SOCKADDR_IN6`,
//! `IN_ADDR`, `IN6_ADDR`) and the FFI functions are imported from the
//! `windows-sys` crate — Microsoft's auto-generated, zero-overhead FFI
//! binding. The struct layouts are machine-generated from the official
//! Windows SDK metadata, so they cannot drift from the SDK the way
//! hand-rolled `#[repr(C)]` structs can.
//!
//! ## Lifetime semantics
//!
//! Rows created with `ValidLifetime = PreferredLifetime = 0xffffffff`
//! (infinite) survive reboots only when also registered as persistent by
//! an external agent; for a routing daemon the standard pattern is to
//! re-install best paths after restart, which is what `lr-daemon` does.

use crate::{KernelRoute, OsRouteError, OsRouteTable};
use lr_core::addr::{IpAddr, Prefix};
use lr_core::rib::Protocol;

use windows_sys::Win32::Foundation::{
    ERROR_INVALID_PARAMETER, ERROR_NOT_FOUND, ERROR_OBJECT_ALREADY_EXISTS, NO_ERROR,
};
use windows_sys::Win32::NetworkManagement::IpHelper::{
    CreateIpForwardEntry2, DeleteIpForwardEntry2, FreeMibTable, GetBestRoute2, GetIpForwardTable2,
    InitializeIpForwardEntry, IP_ADDRESS_PREFIX, MIB_IPFORWARD_ROW2, MIB_IPFORWARD_TABLE2,
};
use windows_sys::Win32::Networking::WinSock::{
    RouteProtocolBgp, RouteProtocolLocal, RouteProtocolNetMgmt, RouteProtocolOspf,
    RouteProtocolRip, AF_INET, AF_INET6, SOCKADDR_IN, SOCKADDR_IN6, SOCKADDR_INET,
};

/// IP Helper backed implementation of [`OsRouteTable`].
pub struct IpHelper;

/// The loopback interface index on Windows — always 1 (the "Loopback
/// Pseudo-Interface 1"). Used as the egress for blackhole routes.
const LOOPBACK_IF_INDEX: u32 = 1;

/// The loopback *gateway* of a blackhole route. Microsoft's documented
/// `route add PREFIX mask MASK 127.0.0.1` idiom (in force since
/// Windows NT, and what `route.exe ?` still prints): forwarding the
/// packet toward the loopback address makes the stack treat it as a
/// transit delivery to a non-local destination, which is discarded.
/// A zero next-hop with the loopback interface — what lr previously
/// installed — is an *on-link* route on loopback instead: the stack
/// then accepts packets for the covered space as addressed to the
/// local machine (weak host model), so a daemon listening on
/// 0.0.0.0 answers SYNs for addresses it never owned. That turned a
/// configured blackhole into a live loopback service and produced
/// TCP "peer closed connection" storms against lr's own listener.
fn loopback_gateway(prefix: &Prefix) -> IpAddr {
    match prefix.addr {
        IpAddr::V4(_) => IpAddr::V4([127, 0, 0, 1]),
        IpAddr::V6(_) => IpAddr::V6([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]),
    }
}

/// Map the library's route origin to the MIB `RouteProtocol` tag the
/// row is created with (and `list_routes` maps back). The tag is what
/// `route print`/`Get-NetRoute` and `lr routes list` show as the route
/// origin — tagging every installed row `Bgp` made static blackholes
/// appear as BGP-learned routes in the operator's FIB dumps.
fn mib_protocol(protocol: Protocol) -> i32 {
    match protocol {
        Protocol::Bgp => RouteProtocolBgp,
        Protocol::Ospfv2 | Protocol::Ospfv3 => RouteProtocolOspf,
        Protocol::Babel => RouteProtocolRip,
        Protocol::Static | Protocol::Connected => RouteProtocolNetMgmt,
        Protocol::Other(_) => RouteProtocolNetMgmt,
    }
}

impl IpHelper {
    pub fn connect() -> Result<Self, OsRouteError> {
        // Windows needs no handle; the API is stateless. Probe the table
        // once so a missing/unusable iphlpapi surfaces immediately.
        let mut table: *mut MIB_IPFORWARD_TABLE2 = core::ptr::null_mut();
        // SAFETY: `table` is an out-pointer; the allocation it receives is
        // owned by us and freed below with FreeMibTable.
        let rc = unsafe { GetIpForwardTable2(0, &mut table) };
        if rc != NO_ERROR {
            return Err(win_err("GetIpForwardTable2", rc));
        }
        if !table.is_null() {
            // SAFETY: pointer came from GetIpForwardTable2.
            unsafe { FreeMibTable(table as *const core::ffi::c_void) };
        }
        Ok(Self)
    }

    fn make_row(
        prefix: &Prefix,
        next_hop: &IpAddr,
        if_index: u32,
        protocol: Protocol,
    ) -> MIB_IPFORWARD_ROW2 {
        // SAFETY: InitializeIpForwardEntry zeroes the struct and applies
        // the documented defaults (infinite lifetimes, not published,
        // immortal). The `Default` impl does the same via `mem::zeroed`
        // but does NOT set the lifetime defaults.
        let mut row: MIB_IPFORWARD_ROW2 = unsafe { core::mem::zeroed() };
        unsafe { InitializeIpForwardEntry(&mut row) };
        row.InterfaceIndex = if_index;
        row.DestinationPrefix = IP_ADDRESS_PREFIX {
            Prefix: sockaddr_for(&prefix.addr, 0),
            PrefixLength: prefix.prefix_len,
        };
        row.NextHop = sockaddr_for(next_hop, if_index);
        row.Protocol = mib_protocol(protocol);
        row.Immortal = true;
        if prefix.prefix_len == 0 {
            // A /0 destination carries no address bits.
            row.DestinationPrefix.PrefixLength = 0;
        }
        row
    }

    /// Build a blackhole route row — packets matching `prefix` are
    /// discarded by the kernel. Windows has no explicit "discard" flag
    /// in `MIB_IPFORWARD_ROW2`; the documented convention is the
    /// `route add PREFIX mask MASK 127.0.0.1` idiom — point the route at
    /// the loopback *gateway*, which makes the forwarding stack treat
    /// matching packets as transit deliveries to a non-local
    /// destination and silently discard them. See [`loopback_gateway`]
    /// for why the previous zero-next-hop form was wrong.
    fn make_blackhole_row(prefix: &Prefix) -> MIB_IPFORWARD_ROW2 {
        // SAFETY: same defaults as `make_row`.
        let mut row: MIB_IPFORWARD_ROW2 = unsafe { core::mem::zeroed() };
        unsafe { InitializeIpForwardEntry(&mut row) };
        row.InterfaceIndex = LOOPBACK_IF_INDEX;
        row.DestinationPrefix = IP_ADDRESS_PREFIX {
            Prefix: sockaddr_for(&prefix.addr, 0),
            PrefixLength: prefix.prefix_len,
        };
        row.NextHop = sockaddr_for(&loopback_gateway(prefix), 0);
        row.Protocol = RouteProtocolNetMgmt;
        row.Immortal = true;
        if prefix.prefix_len == 0 {
            row.DestinationPrefix.PrefixLength = 0;
        }
        row
    }

    /// Ask Windows to resolve the interface leading towards `next_hop`.
    /// `GetBestRoute2` applies the same policy and interface metrics as the
    /// forwarding stack; a local table scan cannot reproduce those rules.
    fn resolve_interface(next_hop: &IpAddr) -> Result<u32, OsRouteError> {
        let destination = sockaddr_for(next_hop, 0);
        let mut best_route: MIB_IPFORWARD_ROW2 = unsafe { core::mem::zeroed() };
        let mut best_source: SOCKADDR_INET = unsafe { core::mem::zeroed() };
        // SAFETY: null InterfaceLuid/source select the current compartment
        // and any source; both output pointers refer to live stack values.
        let rc = unsafe {
            GetBestRoute2(
                core::ptr::null(),
                0,
                core::ptr::null(),
                &destination,
                0,
                &mut best_route,
                &mut best_source,
            )
        };
        if rc != NO_ERROR {
            return Err(win_err("GetBestRoute2", rc));
        }
        if best_route.InterfaceIndex == 0 {
            return Err(OsRouteError(format!(
                "GetBestRoute2 returned no interface for next hop {next_hop}"
            )));
        }
        Ok(best_route.InterfaceIndex)
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
        self.add_route_tagged(prefix, next_hop, if_index, Protocol::Bgp)
    }

    fn add_route_tagged(
        &mut self,
        prefix: Prefix,
        next_hop: IpAddr,
        if_index: u32,
        protocol: Protocol,
    ) -> Result<(), Self::Error> {
        let if_index = if if_index != 0 {
            if_index
        } else {
            Self::resolve_interface(&next_hop)?
        };
        let row = Self::make_row(&prefix, &next_hop, if_index, protocol);
        // SAFETY: `row` is a fully initialised stack value; the API only
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
        Ok(())
    }

    fn add_blackhole_route(&mut self, prefix: Prefix) -> Result<(), Self::Error> {
        let row = Self::make_blackhole_row(&prefix);
        // SAFETY: `row` is a fully initialised stack value; the API only
        // reads from it.
        let mut rc = unsafe { CreateIpForwardEntry2(&row) };
        if rc == ERROR_OBJECT_ALREADY_EXISTS {
            rc = unsafe { DeleteIpForwardEntry2(&row) };
            if rc == NO_ERROR || rc == ERROR_NOT_FOUND {
                rc = unsafe { CreateIpForwardEntry2(&row) };
            }
        }
        if rc != NO_ERROR {
            return Err(win_err("CreateIpForwardEntry2 (blackhole)", rc));
        }
        Ok(())
    }

    fn delete_route(&mut self, prefix: Prefix) -> Result<(), Self::Error> {
        // Deleting requires the full key (prefix + next hop + interface);
        // scan the table for rows matching the prefix and delete each.
        let mut table: *mut MIB_IPFORWARD_TABLE2 = core::ptr::null_mut();
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
                if !matches!(
                    row.Protocol,
                    p if p == RouteProtocolBgp
                        || p == RouteProtocolOspf
                        || p == RouteProtocolRip
                        || p == RouteProtocolNetMgmt
                ) {
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
        unsafe { FreeMibTable(table as *const core::ffi::c_void) };
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
        let mut table: *mut MIB_IPFORWARD_TABLE2 = core::ptr::null_mut();
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
                let next_hop = unsafe { next_hop_of(row) };
                let protocol = match row.Protocol {
                    p if p == RouteProtocolLocal => Protocol::Connected,
                    p if p == RouteProtocolNetMgmt => Protocol::Static,
                    p if p == RouteProtocolBgp => Protocol::Bgp,
                    p if p == RouteProtocolOspf => Protocol::Ospfv2,
                    p if p == RouteProtocolRip => Protocol::Babel,
                    other => Protocol::Other(other as u16),
                };
                out.push(KernelRoute {
                    prefix,
                    next_hop,
                    if_index: Some(row.InterfaceIndex),
                    metric: row.Metric,
                    protocol,
                });
            }
        }
        // SAFETY: release the API-allocated buffer.
        unsafe { FreeMibTable(table as *const core::ffi::c_void) };
        Ok(out)
    }
}

// ===== helpers =====

/// Build a `SOCKADDR_INET` from an `IpAddr`. The union is zeroed first
/// so unused arms (and padding) are deterministic.
fn sockaddr_for(addr: &IpAddr, scope_id: u32) -> SOCKADDR_INET {
    // SAFETY: SOCKADDR_INET implements Default via mem::zeroed, which
    // is safe for this POD union.
    let mut sa: SOCKADDR_INET = unsafe { core::mem::zeroed() };
    match addr {
        IpAddr::V4(b) => {
            // SAFETY: writing the Ipv4 arm of the union. The union is
            // zeroed so unused fields are 0.
            let v4 = unsafe { &mut *core::ptr::addr_of_mut!(sa).cast::<SOCKADDR_IN>() };
            v4.sin_family = AF_INET;
            v4.sin_addr.S_un.S_un_b.s_b1 = b[0];
            v4.sin_addr.S_un.S_un_b.s_b2 = b[1];
            v4.sin_addr.S_un.S_un_b.s_b3 = b[2];
            v4.sin_addr.S_un.S_un_b.s_b4 = b[3];
        }
        IpAddr::V6(b) => {
            // SAFETY: writing the Ipv6 arm of the union.
            let v6 = unsafe { &mut *core::ptr::addr_of_mut!(sa).cast::<SOCKADDR_IN6>() };
            v6.sin6_family = AF_INET6;
            v6.sin6_addr.u.Byte = *b;
            if b[..2] == [0xfe, 0x80] {
                v6.Anonymous.sin6_scope_id = scope_id;
            }
        }
    }
    sa
}

/// # Safety
/// The caller must guarantee the union holds a valid socket address.
unsafe fn inet_addr_of(sa: &SOCKADDR_INET) -> IpAddr {
    // SAFETY: `si_family` aliases the first two bytes of both arms.
    let family = unsafe { sa.si_family };
    match family {
        AF_INET6 => {
            // SAFETY: reading the Ipv6 arm.
            let v6 = unsafe { &*core::ptr::addr_of!(*sa).cast::<SOCKADDR_IN6>() };
            IpAddr::V6(v6.sin6_addr.u.Byte)
        }
        _ => {
            // SAFETY: reading the Ipv4 arm.
            let v4 = unsafe { &*core::ptr::addr_of!(*sa).cast::<SOCKADDR_IN>() };
            let s = &v4.sin_addr.S_un.S_un_b;
            IpAddr::V4([s.s_b1, s.s_b2, s.s_b3, s.s_b4])
        }
    }
}

/// # Safety
/// `table` must point to a live MIB_IPFORWARD_TABLE2 allocation.
unsafe fn table_rows(table: *mut MIB_IPFORWARD_TABLE2) -> (*const MIB_IPFORWARD_ROW2, usize) {
    // SAFETY: the table header is followed by `num_entries` rows.
    let n = unsafe { (*table).NumEntries } as usize;
    if n == 0 {
        return (core::ptr::null(), 0);
    }
    // `Table` is a `[MIB_IPFORWARD_ROW2; 1]` flexible-array-style
    // member at offset 8 (after `NumEntries: u32` + 4 bytes padding).
    // We compute the first row address from the struct's `Table`
    // field directly — the SDK declares it as `[MIB_IPFORWARD_ROW2; 1]`
    // and the rows are contiguous from there.
    let rows = unsafe { core::ptr::addr_of!((*table).Table) as *const MIB_IPFORWARD_ROW2 };
    (rows, n)
}

/// # Safety
/// `row` must be a valid MIB_IPFORWARD_ROW2.
unsafe fn prefix_of(row: &MIB_IPFORWARD_ROW2) -> (IpAddr, u8) {
    // SAFETY: reading the destination prefix.
    let addr = unsafe { inet_addr_of(&row.DestinationPrefix.Prefix) };
    (addr, row.DestinationPrefix.PrefixLength)
}

/// # Safety
/// `row` must be a valid MIB_IPFORWARD_ROW2.
unsafe fn next_hop_of(row: &MIB_IPFORWARD_ROW2) -> Option<IpAddr> {
    // SAFETY: reading the next-hop union.
    let addr = unsafe { inet_addr_of(&row.NextHop) };
    match addr {
        IpAddr::V4([0, 0, 0, 0]) => None,
        _ => Some(addr),
    }
}

fn addr_eq(a: &IpAddr, b: &IpAddr) -> bool {
    a == b
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
    fn explicit_interface_scopes_link_local_gateway() {
        let prefix = Prefix::new_v6([0x20, 1, 0xdb, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], 64);
        let gateway = IpAddr::V6([0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        let row = IpHelper::make_row(&prefix, &gateway, 42, Protocol::Babel);
        assert_eq!(row.InterfaceIndex, 42);
        // SAFETY: make_row populated the IPv6 arm for an IPv6 gateway.
        let next_hop = unsafe { &*core::ptr::addr_of!(row.NextHop).cast::<SOCKADDR_IN6>() };
        // SAFETY: the anonymous union holds the scope-id member initialized
        // by make_row for this link-local gateway.
        assert_eq!(unsafe { next_hop.Anonymous.sin6_scope_id }, 42);
    }

    #[test]
    fn best_route_resolves_loopback_interface() {
        let index = IpHelper::resolve_interface(&IpAddr::V4([127, 0, 0, 1])).unwrap();
        assert_ne!(index, 0);
    }

    #[test]
    fn blackhole_row_v4_uses_loopback_gateway() {
        let prefix = Prefix::new_v4([192, 0, 2, 0], 24);
        let row = IpHelper::make_blackhole_row(&prefix);
        assert_eq!(row.InterfaceIndex, LOOPBACK_IF_INDEX);
        // SAFETY: make_blackhole_row populated the IPv4 arm for an IPv4 prefix.
        let next_hop = unsafe { &*core::ptr::addr_of!(row.NextHop).cast::<SOCKADDR_IN>() };
        assert_eq!(next_hop.sin_family, AF_INET);
        // SAFETY: accessing the S_un union — the Ipv4 arm was initialized.
        let s = unsafe { next_hop.sin_addr.S_un.S_un_b };
        // The Microsoft `route add PREFIX mask MASK 127.0.0.1` blackhole
        // idiom — NOT the zero gateway (which makes an on-link loopback
        // route the local stack happily accepts packets for).
        assert_eq!([s.s_b1, s.s_b2, s.s_b3, s.s_b4], [127, 0, 0, 1]);
    }

    #[test]
    fn blackhole_row_v6_uses_loopback_gateway() {
        let prefix = Prefix::new_v6(
            [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            64,
        );
        let row = IpHelper::make_blackhole_row(&prefix);
        assert_eq!(row.InterfaceIndex, LOOPBACK_IF_INDEX);
        // SAFETY: make_blackhole_row populated the IPv6 arm for an IPv6 prefix.
        let next_hop = unsafe { &*core::ptr::addr_of!(row.NextHop).cast::<SOCKADDR_IN6>() };
        assert_eq!(next_hop.sin6_family, AF_INET6);
        // SAFETY: accessing the u union — the Byte array was initialized.
        let bytes = unsafe { next_hop.sin6_addr.u.Byte };
        assert_eq!(bytes[..15], [0u8; 15]);
        assert_eq!(bytes[15], 1);
    }
}
