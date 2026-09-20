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
    CreateIpForwardEntry2, DeleteIpForwardEntry2, FreeMibTable, GetIpForwardTable2,
    InitializeIpForwardEntry, IP_ADDRESS_PREFIX, MIB_IPFORWARD_ROW2, MIB_IPFORWARD_TABLE2,
};
use windows_sys::Win32::Networking::WinSock::{
    RouteProtocolBgp, RouteProtocolLocal, RouteProtocolNetMgmt, AF_INET, AF_INET6, SOCKADDR_IN,
    SOCKADDR_IN6, SOCKADDR_INET,
};

/// IP Helper backed implementation of [`OsRouteTable`].
pub struct IpHelper {
    /// Cached interface index (0 = resolve per operation).
    if_index: u32,
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
        Ok(Self { if_index: 0 })
    }

    fn make_row(prefix: &Prefix, next_hop: &IpAddr, if_index: u32) -> MIB_IPFORWARD_ROW2 {
        // SAFETY: InitializeIpForwardEntry zeroes the struct and applies
        // the documented defaults (infinite lifetimes, not published,
        // immortal). The `Default` impl does the same via `mem::zeroed`
        // but does NOT set the lifetime defaults.
        let mut row: MIB_IPFORWARD_ROW2 = unsafe { core::mem::zeroed() };
        unsafe { InitializeIpForwardEntry(&mut row) };
        row.InterfaceIndex = if_index;
        row.DestinationPrefix = IP_ADDRESS_PREFIX {
            Prefix: sockaddr_for(&prefix.addr),
            PrefixLength: prefix.prefix_len,
        };
        row.NextHop = sockaddr_for(next_hop);
        row.Protocol = RouteProtocolBgp;
        row.Immortal = true;
        if prefix.prefix_len == 0 {
            // A /0 destination carries no address bits.
            row.DestinationPrefix.PrefixLength = 0;
        }
        row
    }

    /// Resolve the interface leading towards `next_hop` by longest-prefix
    /// match against the current table. Returns 0 when nothing matches.
    fn resolve_interface(next_hop: &IpAddr) -> u32 {
        let mut table: *mut MIB_IPFORWARD_TABLE2 = core::ptr::null_mut();
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
                let (dst, plen) = unsafe { prefix_of(row) };
                if prefix_contains(dst, plen, next_hop) {
                    let better = best.map(|(b, _)| plen > b).unwrap_or(true);
                    if better && row.InterfaceIndex != 0 {
                        best = Some((plen, row.InterfaceIndex));
                    }
                }
            }
        }
        // SAFETY: release the API-allocated buffer.
        unsafe { FreeMibTable(table as *const core::ffi::c_void) };
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
        self.if_index = if_index;
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
                if row.Protocol != RouteProtocolBgp as i32 {
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
                let protocol = match row.Protocol as u32 {
                    p if p == RouteProtocolLocal as u32 => Protocol::Connected,
                    p if p == RouteProtocolNetMgmt as u32 => Protocol::Static,
                    p if p == RouteProtocolBgp as u32 => Protocol::Bgp,
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
fn sockaddr_for(addr: &IpAddr) -> SOCKADDR_INET {
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
