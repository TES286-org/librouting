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
///
/// The struct carries an install ledger (see [`InstalledRow`]) so
/// withdrawals delete exactly the rows this instance created — never
/// a foreign row that happens to share the prefix.
pub struct IpHelper {
    /// Rows this instance installed: `(prefix, (next hop, interface
    /// index))` pairs. `delete_route` matches these exactly; only when
    /// the ledger has no entry for a prefix (fresh process, routes
    /// left by a predecessor) does it fall back to deleting every
    /// protocol-tagged row for the prefix.
    installed: std::collections::HashMap<Prefix, Vec<InstalledRow>>,
    /// Lazily-resolved blackhole egress interfaces, one per family
    /// (`[v4, v6]`, `None` until the first install of that family):
    /// resolution walks the FIB and the adapter list once per family
    /// for the instance's lifetime, not once per installed anchor.
    blackhole_if: [Option<u32>; 2],
}

/// One ledger entry — the row identity Windows routes are keyed by
/// (`CreateIpForwardEntry2` duplicates = same prefix **and** next hop
/// **and** interface).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct InstalledRow {
    next_hop: IpAddr,
    if_index: u32,
}

/// The loopback interface index on Windows — always 1 (the "Loopback
/// Pseudo-Interface 1"). **Not** usable as a blackhole egress: every
/// delivery form on it is local delivery (weak host), so a daemon
/// listening on 0.0.0.0 answers SYNs for the covered space — observed
/// live in production as lr's own BGP listener accepting its own
/// outbound connections (the "peer closed connection" storm).
const LOOPBACK_IF_INDEX: u32 = 1;

/// The zero next hop of `prefix`'s family, with the sockaddr family
/// set — the documented on-link form (`route print` shows it as the
/// "On-link" gateway). This is the row shape WireGuard for Windows
/// installs for every AllowedIPs route, so it is the best-supported
/// `CreateIpForwardEntry2` form on real interfaces.
fn on_link_next_hop(prefix: &Prefix) -> IpAddr {
    match prefix.addr {
        IpAddr::V4(_) => IpAddr::V4([0, 0, 0, 0]),
        IpAddr::V6(_) => IpAddr::V6([0u8; 16]),
    }
}

/// The egress interface for a blackhole route: the interface that owns
/// the family's default route (the box's real uplink), else the first
/// up interface with a family-matching address. Windows has **no**
/// blackhole route type — every loopback-delivery form is local
/// delivery (weak host), and `CreateIpForwardEntry2` rejects loopback
/// gateways outright with `ERROR_INVALID_PARAMETER` — so the discard
/// idiom is an on-link row on a *real* interface: the stack resolves
/// the covered destination itself as a neighbour, the resolution
/// fails, and matching traffic dies as host-unreachable instead of
/// being forwarded (the Windows null-route convention: an unroutable
/// delivery, `ERROR_NOT_FOUND` semantics rather than Linux's silent
/// `RTN_BLACKHOLE`).
fn blackhole_if_index(prefix: &Prefix) -> u32 {
    let family_probe = match prefix.addr {
        IpAddr::V4(_) => IpAddr::V4([0, 0, 0, 0]),
        IpAddr::V6(_) => IpAddr::V6([0u8; 16]),
    };
    if let Ok(idx) = IpHelper::resolve_interface(&family_probe) {
        if idx != LOOPBACK_IF_INDEX {
            return idx;
        }
    }
    // No default route for the family (lab boxes, v6-less hosts): any
    // up adapter with a family address still gives ARP-fail discard.
    blackhole_if_index_by_scan(prefix)
}

/// The enumeration fallback of [`blackhole_if_index`] — also the
/// cache-miss path: one `GetAdaptersAddresses` scan serving every
/// blackhole install of the family.
fn blackhole_if_index_by_scan(prefix: &Prefix) -> u32 {
    let want_v4 = prefix.addr.is_ipv4();
    if let Ok(ifaces) = crate::ospf_transport::list_interfaces() {
        for i in ifaces {
            if !i.up {
                continue;
            }
            let family_ok = if want_v4 {
                !i.v4.is_empty()
            } else {
                !i.v6.is_empty()
            };
            if family_ok {
                if let Some(idx) = crate::ospf_transport::ifindex_of(&i.name) {
                    if idx != LOOPBACK_IF_INDEX {
                        return idx;
                    }
                }
            }
        }
    }
    // Degenerate host (only loopback exists): the local-accept caveat
    // applies, but a route beats no route — and this path is all but
    // unreachable in practice.
    LOOPBACK_IF_INDEX
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
        Ok(Self {
            installed: std::collections::HashMap::new(),
            blackhole_if: [None, None],
        })
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
    /// discarded (as host-unreachable) instead of forwarded.
    ///
    /// Windows has no discard route type, and the historically
    /// suggested forms are all unusable from `CreateIpForwardEntry2`:
    ///
    /// * loopback *gateway* (the `route add ... 127.0.0.1` idiom) —
    ///   rejected with `ERROR_INVALID_PARAMETER` (87); netio refuses
    ///   loopback next hops (observed on production Windows 11, and
    ///   already documented in `tests/interop/bgp_kernel_install.sh`'s
    ///   Windows next-hop selection note);
    /// * any delivery through the loopback *interface* (zero next hop
    ///   or the `MIB_IPFORWARD_ROW2.Loopback` flag) — local delivery
    ///   under the weak host model, so a daemon listening on 0.0.0.0
    ///   answers SYNs for the covered space (the production "peer
    ///   closed connection" storm).
    ///
    /// The idiom this installs is the Windows null-route convention —
    /// an on-link row on a real egress interface (see
    /// [`blackhole_if_index`]): the stack tries to resolve the covered
    /// destination itself as a neighbour on that link, resolution
    /// fails, and the traffic dies. This is `unreachable`-flavoured
    /// discard (ARP-fail → host-unreachable), not Linux's silent
    /// `RTN_BLACKHOLE` — the distinction is invisible to routing
    /// correctness (nothing is forwarded, nothing loops), which is
    /// what a BGP aggregate anchor or a `next_hop "blackhole"`
    /// static needs.
    fn make_blackhole_row(prefix: &Prefix, if_index: u32) -> MIB_IPFORWARD_ROW2 {
        // SAFETY: same defaults as `make_row`.
        let mut row: MIB_IPFORWARD_ROW2 = unsafe { core::mem::zeroed() };
        unsafe { InitializeIpForwardEntry(&mut row) };
        row.InterfaceIndex = if_index;
        row.DestinationPrefix = IP_ADDRESS_PREFIX {
            Prefix: sockaddr_for(&prefix.addr, 0),
            PrefixLength: prefix.prefix_len,
        };
        // The on-link form: family set, address all zeros ("On-link"
        // in `route print`). Not the `Loopback` flag — see the method
        // docs for why every loopback-delivery form is a trap.
        row.NextHop = sockaddr_for(&on_link_next_hop(prefix), if_index);
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

    /// Record an installed row in the ledger (deduplicated — repeated
    /// idempotent installs of the same row are a no-op).
    fn remember(&mut self, prefix: Prefix, row: InstalledRow) {
        let entry = self.installed.entry(prefix).or_default();
        if !entry.contains(&row) {
            entry.push(row);
        }
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
        self.remember(prefix, InstalledRow { next_hop, if_index });
        Ok(())
    }

    fn add_blackhole_route(&mut self, prefix: Prefix) -> Result<(), Self::Error> {
        // Family-indexed cache: the default-route owner and adapter
        // scan run once per family for the daemon's lifetime, not once
        // per installed anchor.
        let fam = usize::from(prefix.addr.is_ipv6());
        let if_index = match self.blackhole_if[fam] {
            Some(idx) => idx,
            None => {
                let idx = blackhole_if_index(&prefix);
                self.blackhole_if[fam] = Some(idx);
                idx
            }
        };
        let row = Self::make_blackhole_row(&prefix, if_index);
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
        self.remember(
            prefix,
            InstalledRow {
                next_hop: on_link_next_hop(&prefix),
                if_index,
            },
        );
        Ok(())
    }

    fn delete_route(&mut self, prefix: Prefix) -> Result<(), Self::Error> {
        // Deleting requires the full row key (prefix + next hop +
        // interface). With an install ledger for the prefix (the normal
        // lifecycle) delete exactly the rows this instance created —
        // a foreign row that happens to share the prefix (a VPN's
        // on-link route for the same allowed-IP, for instance) is
        // never touched. Without a ledger entry (a fresh process
        // withdrawing routes a predecessor installed) fall back to
        // deleting every protocol-tagged row for the prefix — the
        // pre-ledger recovery semantics.
        let ledger: Vec<InstalledRow> = self.installed.get(&prefix).cloned().unwrap_or_default();
        let scoped = !ledger.is_empty();
        let mut table: *mut MIB_IPFORWARD_TABLE2 = core::ptr::null_mut();
        // SAFETY: out-pointer, ownership transferred to us.
        let rc = unsafe { GetIpForwardTable2(0, &mut table) };
        if rc != NO_ERROR {
            return Err(win_err("GetIpForwardTable2", rc));
        }
        if table.is_null() {
            self.installed.remove(&prefix);
            return Ok(());
        }
        // SAFETY: rows are read while the allocation is alive.
        let (rows, len) = unsafe { table_rows(table) };
        let mut last_rc = ERROR_NOT_FOUND;
        let mut removed_all = true;
        if !rows.is_null() {
            for row in unsafe { core::slice::from_raw_parts(rows, len) } {
                let (dst, plen) = unsafe { prefix_of(row) };
                if plen != prefix.prefix_len {
                    continue;
                }
                if !addr_eq(&dst, &prefix.addr) {
                    continue;
                }
                if scoped {
                    // Exact-ledger mode: next hop + interface must both
                    // match a row this instance installed.
                    // SAFETY: reading the next-hop union.
                    let row_nh = unsafe { inet_addr_of(&row.NextHop) };
                    if !ledger
                        .iter()
                        .any(|e| e.next_hop == row_nh && e.if_index == row.InterfaceIndex)
                    {
                        continue;
                    }
                } else if !matches!(
                    row.Protocol,
                    p if p == RouteProtocolBgp
                        || p == RouteProtocolOspf
                        || p == RouteProtocolRip
                        || p == RouteProtocolNetMgmt
                ) {
                    // Legacy fallback: never touch rows routing
                    // protocols do not own (Local, DHCP, ...).
                    continue;
                }
                // SAFETY: row is a copy of a table entry; the API matches on
                // destination prefix + next hop + interface.
                let rc2 = unsafe { DeleteIpForwardEntry2(row) };
                if rc2 != NO_ERROR {
                    last_rc = rc2;
                    removed_all = false;
                }
            }
        }
        // SAFETY: release the API-allocated buffer.
        unsafe { FreeMibTable(table as *const core::ffi::c_void) };
        if scoped && removed_all {
            self.installed.remove(&prefix);
        }
        if last_rc == ERROR_NOT_FOUND {
            // Nothing matched — an idempotent delete succeeds.
            if scoped {
                self.installed.remove(&prefix);
            }
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

    /// The blackhole row is the on-link form — family set, address all
    /// zeros — NOT a loopback gateway: netio rejects 127/8 and ::1 next
    /// hops with `ERROR_INVALID_PARAMETER` (the rc.4 production
    /// failure), and any loopback-delivery form is local delivery
    /// under the weak host model.
    #[test]
    fn blackhole_row_v4_is_on_link_with_family_set() {
        let prefix = Prefix::new_v4([192, 0, 2, 0], 24);
        let row = IpHelper::make_blackhole_row(&prefix, 7);
        assert_eq!(row.InterfaceIndex, 7);
        assert_ne!(row.InterfaceIndex, LOOPBACK_IF_INDEX);
        assert!(!row.Loopback);
        // SAFETY: make_blackhole_row populated the IPv4 arm for an IPv4
        // prefix.
        let next_hop = unsafe { &*core::ptr::addr_of!(row.NextHop).cast::<SOCKADDR_IN>() };
        assert_eq!(next_hop.sin_family, AF_INET);
        // SAFETY: accessing the S_un union — the Ipv4 arm was initialized.
        let s = unsafe { next_hop.sin_addr.S_un.S_un_b };
        assert_eq!([s.s_b1, s.s_b2, s.s_b3, s.s_b4], [0, 0, 0, 0]);
    }

    #[test]
    fn blackhole_row_v6_is_on_link_with_family_set() {
        let prefix = Prefix::new_v6(
            [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            64,
        );
        let row = IpHelper::make_blackhole_row(&prefix, 7);
        assert_eq!(row.InterfaceIndex, 7);
        assert!(!row.Loopback);
        // SAFETY: make_blackhole_row populated the IPv6 arm for an IPv6
        // prefix.
        let next_hop = unsafe { &*core::ptr::addr_of!(row.NextHop).cast::<SOCKADDR_IN6>() };
        assert_eq!(next_hop.sin6_family, AF_INET6);
        // SAFETY: accessing the u union — the Byte array was initialized.
        let bytes = unsafe { next_hop.sin6_addr.u.Byte };
        assert_eq!(bytes, [0u8; 16]);
    }

    /// The install ledger deduplicates repeated installs of the same
    /// row identity and `delete_route` only removes what the ledger
    /// knows about.
    #[test]
    fn ledger_deduplicates_and_scopes_deletes() {
        let prefix = Prefix::new_v4([198, 51, 100, 0], 24);
        let mut helper = IpHelper {
            installed: std::collections::HashMap::new(),
            blackhole_if: [None, None],
        };
        helper.remember(
            prefix,
            InstalledRow {
                next_hop: IpAddr::V4([10, 0, 0, 1]),
                if_index: 7,
            },
        );
        helper.remember(
            prefix,
            InstalledRow {
                next_hop: IpAddr::V4([10, 0, 0, 1]),
                if_index: 7,
            },
        );
        helper.remember(
            prefix,
            InstalledRow {
                next_hop: IpAddr::V4([10, 0, 0, 2]),
                if_index: 8,
            },
        );
        assert_eq!(helper.installed[&prefix].len(), 2);
    }
}
