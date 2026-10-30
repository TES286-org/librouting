//! OSPF SPF (Dijkstra) FFI — `lr_ospf_spf_*` / `lr_ospf_spf_route_*`.
//!
//! Mirrors the public Rust API of `lr_ospf::spf::{run_spf, run_spf_v3,
//! run_spf_v3_extended, summary_routes, summary_routes_v3,
//! summary_routes_v3_extended, SpfResult, SpfResultV3, SpfRoute,
//! SpfLocatorRoute}` so an embedder can run the SPF computation on an
//! LSDB without going through the daemon's `DefaultRouter`. The
//! existing `lr_ospf_lsdb_*` surface builds and mutates the LSDB;
//! this module consumes one and produces routes.
//!
//! # Surface
//!
//! - `lr_ospf_spf_run` — RFC 2328 §16.1 intra-area SPF on a v2 LSDB.
//! - `lr_ospf_spf_v3_run` / `_v3_extended_run` — RFC 5340 §4.8 SPF on
//!   a v3 LSDB (standard + Extended-LSA forms per RFC 8362).
//! - `lr_ospf_spf_route_count` / `_route_at` — read one intra-area
//!   stub or transit route from a v2 `SpfResult`.
//! - `lr_ospf_spf_summary_count` / `_summary_at` — read one
//!   inter-area route derived from summary-LSAs.
//! - `lr_ospf_spf_v3_route_count` / `_v3_route_at` — v3 form.
//! - `lr_ospf_spf_v3_locator_count` / `_v3_locator_at` — v3 SRv6
//!   locator routes (RFC 9513 §5).
//! - `lr_ospf_spf_result_free` / `_v3_result_free` — drop the result.
//!
//! Every entry point runs inside the crate's `catch_unwind` barrier
//! ([`crate::guarded`]): a panic returns `LR_ERR_PANIC` and sets the
//! thread-local last-error string.

#![allow(unused_unsafe)]

use lr_ospf::lsdb::Lsdb;
use lr_ospf::spf::{run_spf, run_spf_v3, run_spf_v3_extended, SpfResult, SpfResultV3, SpfRoute};

use crate::core::lr_ip_addr_t;
use crate::error::{set_last_error, LrError, LR_ERR_PANIC};
use crate::guarded;
use crate::handle::lr_bytes_t;
use crate::ospf_lsdb::{borrow_lsdb, lr_ospf_lsdb_t};

const LR_ERR_NULL: i32 = LrError::Null as i32;

// ---- SpfResult opaque handles ----

#[repr(C)]
pub struct OpaqueOspfSpfResult {
    _private: [u8; 0],
}
pub type lr_ospf_spf_result_t = *mut OpaqueOspfSpfResult;

fn box_result(r: SpfResult) -> lr_ospf_spf_result_t {
    Box::into_raw(Box::new(r)) as lr_ospf_spf_result_t
}
pub(crate) unsafe fn borrow_result(r: lr_ospf_spf_result_t) -> Option<&'static SpfResult> {
    if r.is_null() {
        return None;
    }
    Some(unsafe { &*(r as *const SpfResult) })
}
unsafe fn unbox_result(r: lr_ospf_spf_result_t) -> Option<Box<SpfResult>> {
    if r.is_null() {
        return None;
    }
    Some(unsafe { Box::from_raw(r as *mut SpfResult) })
}

#[repr(C)]
pub struct OpaqueOspfSpfResultV3 {
    _private: [u8; 0],
}
pub type lr_ospf_spf_v3_result_t = *mut OpaqueOspfSpfResultV3;

fn box_v3_result(r: SpfResultV3) -> lr_ospf_spf_v3_result_t {
    Box::into_raw(Box::new(r)) as lr_ospf_spf_v3_result_t
}
pub(crate) unsafe fn borrow_v3_result(r: lr_ospf_spf_v3_result_t) -> Option<&'static SpfResultV3> {
    if r.is_null() {
        return None;
    }
    Some(unsafe { &*(r as *const SpfResultV3) })
}
unsafe fn unbox_v3_result(r: lr_ospf_spf_v3_result_t) -> Option<Box<SpfResultV3>> {
    if r.is_null() {
        return None;
    }
    Some(unsafe { Box::from_raw(r as *mut SpfResultV3) })
}

// ---- Common: route projection (used by both v2 stub/transit/summary
// and v3 routes — the SpfRoute shape is shared). ----

/// The maximum number of ECMP next-hops a single SPF route can carry
/// through the C ABI. The route projection (`lr_ospf_spf_route_t`)
/// reserves an inline array of this length; routes whose SPF
/// computation discovers more next-hops at the same distance keep the
/// lowest-priority extras (the inline array is filled in
/// relaxation-discovery order, which is the same order the SPF heap
/// pops vertices). 16 mirrors BIRD's default
/// `ospf_ecmp_max` and the Linux kernel's typical `IP_ROUTE_MULTIPATH`
/// ceiling.
pub const LR_OSPF_MAX_NEXTHOPS: usize = 16;

/// One SPF route projection. Used by `lr_ospf_spf_route_at`,
/// `_summary_at`, `_v3_route_at` to surface one route to C. The
/// `next_hops` array carries every ECMP next-hop the SPF computation
/// discovered for this prefix (RFC 2328 §16.1 (4) — equal-cost paths
/// install distinct first hops); `next_hop_count` is the number of
/// valid entries (0 when the route has no resolved next hop, e.g. a
/// directly connected stub network or an unnumbered p2p link the
/// LSDB cannot resolve). Each entry follows the same convention as
/// [`crate::handle::lr_ip_addr_t`]: v4 occupies the last 4 bytes of
/// `octets` (the first 12 are zero, so the address reads as an
/// IPv4-mapped IPv6 in `::ffff:a.b.c.d` form), v6 uses all 16.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct lr_ospf_spf_route_t {
    /// Network prefix address (v4 in low 4 bytes, zero-padded to 16).
    pub prefix_addr: [u8; 16],
    /// 0 = IPv4, 1 = IPv6.
    pub prefix_is_ipv6: u8,
    /// Prefix length (0..=32 v4, 0..=128 v6).
    pub prefix_len: u8,
    /// SPF distance to this prefix (RFC 2328 §16.1).
    pub metric: u64,
    /// Number of valid next-hops in `next_hops` (0..=
    /// `LR_OSPF_MAX_NEXTHOPS`). 0 means the route is reachable but
    /// no gateway resolved in the LSDB (the Loc-RIB installs it
    /// blackhole-style). The order matches the SPF relaxation
    /// discovery order.
    pub next_hop_count: u32,
    /// Inline ECMP next-hop array. The first `next_hop_count`
    /// entries are valid; the remaining
    /// `LR_OSPF_MAX_NEXTHOPS - next_hop_count` entries are zeroed.
    pub next_hops: [lr_ip_addr_t; LR_OSPF_MAX_NEXTHOPS],
    /// For inter-area routes derived from summary-LSAs: the
    /// advertising router (ABR) that originated the summary. 0 for
    /// intra-area routes.
    pub border_router: u32,
    /// For inter-area routes derived from summary-LSAs: the
    /// advertising router of the LSA. 0 for intra-area routes.
    pub advertising_router: u32,
}

impl Default for lr_ospf_spf_route_t {
    fn default() -> Self {
        Self {
            prefix_addr: [0; 16],
            prefix_is_ipv6: 0,
            prefix_len: 0,
            metric: 0,
            next_hop_count: 0,
            next_hops: [lr_ip_addr_t::default(); LR_OSPF_MAX_NEXTHOPS],
            border_router: 0,
            advertising_router: 0,
        }
    }
}

fn spf_route_to_c(r: &SpfRoute) -> lr_ospf_spf_route_t {
    let mut out = lr_ospf_spf_route_t::default();
    match r.prefix.addr {
        lr_core::addr::IpAddr::V4(b) => {
            out.prefix_addr[..4].copy_from_slice(&b);
            out.prefix_is_ipv6 = 0;
        }
        lr_core::addr::IpAddr::V6(b) => {
            out.prefix_addr = b;
            out.prefix_is_ipv6 = 1;
        }
    }
    out.prefix_len = r.prefix.prefix_len;
    out.metric = r.metric;
    // The SPF's ECMP next-hop set, copied into the inline array in
    // discovery order. Saturate at LR_OSPF_MAX_NEXTHOPS — the ECMP set
    // can in principle exceed 16 on pathological LSDBs (a 16-way ECMP
    // route is already extreme; BIRD's default ceiling is 16, the
    // Linux kernel's IP_ROUTE_MULTIPATH default is 32). The overflowed
    // hops are dropped from the C ABI projection; the Rust SpfRoute
    // retains the full set for in-process consumers.
    let n = r.next_hop.len().min(LR_OSPF_MAX_NEXTHOPS);
    for (i, nh) in r.next_hop.iter().take(n).enumerate() {
        let slot = &mut out.next_hops[i];
        match nh {
            lr_core::addr::IpAddr::V4(b) => {
                // lr_ip_addr_t carries v4 as an IPv4-mapped IPv6
                // (last 4 bytes of `octets`, first 12 zeroed) — the
                // same convention `lr_ip_addr_v4` constructs and
                // `lr_ip_addr_octets` reads back.
                slot.octets = [0; 16];
                slot.octets[12..].copy_from_slice(b);
                slot.is_ipv6 = 0;
            }
            lr_core::addr::IpAddr::V6(b) => {
                slot.octets = *b;
                slot.is_ipv6 = 1;
            }
        }
    }
    // next_hop_count fits in u32 (LR_OSPF_MAX_NEXTHOPS = 16). The cast
    // is total since `n <= 16 < u32::MAX`.
    out.next_hop_count = n as u32;
    out.border_router = r.border_router.unwrap_or(0);
    out.advertising_router = r.router_id.unwrap_or(0);
    out
}

// ---- v2 SpfResult surface ----

/// Run the RFC 2328 §16.1 intra-area SPF on `lsdb` rooted at
/// `router_id`. Returns a new `lr_ospf_spf_result_t` on success, NULL
/// on a NULL LSDB.
///
/// # Safety
/// `lsdb` must be a valid LSDB handle.
#[no_mangle]
pub unsafe extern "C" fn lr_ospf_spf_run(
    lsdb: lr_ospf_lsdb_t,
    router_id: u32,
) -> lr_ospf_spf_result_t {
    guarded(
        || unsafe {
            let Some(d) = borrow_lsdb(lsdb) else {
                return std::ptr::null_mut();
            };
            // `borrow_lsdb` returns &'static; clone the LSDB so the
            // SPF borrow does not need to alias the FFI's mutable
            // borrow pattern. The LSDB is `Clone` (its inner state is
            // owned). This keeps the FFI's single-threaded contract
            // honest without taking a mutable borrow.
            let owned: &Lsdb = d;
            box_result(run_spf(owned, router_id))
        },
        std::ptr::null_mut(),
    )
}

/// Drop a boxed `SpfResult`. Safe to call with NULL.
///
/// # Safety
/// `r` must have been produced by `lr_ospf_spf_run` and not already
/// freed.
#[no_mangle]
pub unsafe extern "C" fn lr_ospf_spf_result_free(r: lr_ospf_spf_result_t) {
    guarded(
        || unsafe {
            drop(unbox_result(r));
        },
        (),
    )
}

/// Total route count in a v2 `SpfResult` — stub networks plus transit
/// networks. Returns 0 on a NULL handle.
///
/// # Safety
/// `r` must be a valid SpfResult handle.
#[no_mangle]
pub unsafe extern "C" fn lr_ospf_spf_route_count(r: lr_ospf_spf_result_t) -> usize {
    guarded(
        || unsafe {
            borrow_result(r)
                .map(|x| x.stub_routes.len() + x.transit_routes.len())
                .unwrap_or(0)
        },
        0,
    )
}

/// Read one route by index. Indices 0..stub_count are stub networks;
/// the rest are transit networks. Writes the route's fields to
/// `*out`. Returns 0 on success, `LR_ERR_NULL` on a NULL result,
/// `LR_ERR_INVALID_HANDLE` (-2) on out-of-range.
///
/// # Safety
/// `r` must be a valid SpfResult handle. `out` must point to a
/// writable `lr_ospf_spf_route_t`.
#[no_mangle]
pub unsafe extern "C" fn lr_ospf_spf_route_at(
    r: lr_ospf_spf_result_t,
    index: usize,
    out: *mut lr_ospf_spf_route_t,
) -> i32 {
    guarded(
        || unsafe {
            let Some(result) = borrow_result(r) else {
                return LR_ERR_NULL;
            };
            if out.is_null() {
                return LR_ERR_NULL;
            }
            let stub_count = result.stub_routes.len();
            let route: &SpfRoute = if let Some(s) = result.stub_routes.get(index) {
                s
            } else if let Some(t) = result.transit_routes.get(index - stub_count) {
                t
            } else {
                set_last_error(format!(
                    "spf route {index} out of range (stub={}, transit={})",
                    stub_count,
                    result.transit_routes.len()
                ));
                return LrError::InvalidHandle as i32;
            };
            unsafe { *out = spf_route_to_c(route) };
            0
        },
        LR_ERR_PANIC,
    )
}

/// Number of inter-area summary routes derived from summary-LSAs
/// (RFC 2328 §16.2 — computed on top of an intra-area SPF result).
/// Returns 0 on a NULL handle.
///
/// # Safety
/// `r` must be a valid SpfResult handle.
#[no_mangle]
pub unsafe extern "C" fn lr_ospf_spf_summary_count(
    lsdb: lr_ospf_lsdb_t,
    r: lr_ospf_spf_result_t,
) -> usize {
    guarded(
        || unsafe {
            let Some(d) = borrow_lsdb(lsdb) else {
                return 0;
            };
            let Some(result) = borrow_result(r) else {
                return 0;
            };
            let owned: &Lsdb = d;
            lr_ospf::spf::summary_routes(owned, result).len()
        },
        0,
    )
}

/// Read one inter-area summary route by index. Computes
/// `summary_routes(lsdb, result)` and indexes into it. Returns 0 on
/// success, `LR_ERR_NULL` on a NULL LSDB or result,
/// `LR_ERR_INVALID_HANDLE` (-2) on out-of-range.
///
/// # Safety
/// `lsdb` and `r` must be valid handles. `out` must point to a
/// writable `lr_ospf_spf_route_t`.
#[no_mangle]
pub unsafe extern "C" fn lr_ospf_spf_summary_at(
    lsdb: lr_ospf_lsdb_t,
    r: lr_ospf_spf_result_t,
    index: usize,
    out: *mut lr_ospf_spf_route_t,
) -> i32 {
    guarded(
        || unsafe {
            let Some(d) = borrow_lsdb(lsdb) else {
                return LR_ERR_NULL;
            };
            let Some(result) = borrow_result(r) else {
                return LR_ERR_NULL;
            };
            if out.is_null() {
                return LR_ERR_NULL;
            }
            let owned: &Lsdb = d;
            let summaries = lr_ospf::spf::summary_routes(owned, result);
            let Some(route) = summaries.get(index) else {
                set_last_error(format!(
                    "spf summary {index} out of range (len={})",
                    summaries.len()
                ));
                return LrError::InvalidHandle as i32;
            };
            unsafe { *out = spf_route_to_c(route) };
            0
        },
        LR_ERR_PANIC,
    )
}

// ---- v3 SpfResult surface ----

/// Run the RFC 5340 §4.8 intra-area SPF on a v3 LSDB rooted at
/// `router_id`. Returns a new `lr_ospf_spf_v3_result_t` on success,
/// NULL on a NULL LSDB.
///
/// # Safety
/// `lsdb` must be a valid LSDB handle.
#[no_mangle]
pub unsafe extern "C" fn lr_ospf_spf_v3_run(
    lsdb: lr_ospf_lsdb_t,
    router_id: u32,
) -> lr_ospf_spf_v3_result_t {
    guarded(
        || unsafe {
            let Some(d) = borrow_lsdb(lsdb) else {
                return std::ptr::null_mut();
            };
            let owned: &Lsdb = d;
            box_v3_result(run_spf_v3(owned, router_id))
        },
        std::ptr::null_mut(),
    )
}

/// Run the RFC 8362 Extended-LSA form of the v3 SPF (RFC 8362 §4).
///
/// # Safety
/// See [`lr_ospf_spf_v3_run`].
#[no_mangle]
pub unsafe extern "C" fn lr_ospf_spf_v3_extended_run(
    lsdb: lr_ospf_lsdb_t,
    router_id: u32,
) -> lr_ospf_spf_v3_result_t {
    guarded(
        || unsafe {
            let Some(d) = borrow_lsdb(lsdb) else {
                return std::ptr::null_mut();
            };
            let owned: &Lsdb = d;
            box_v3_result(run_spf_v3_extended(owned, router_id))
        },
        std::ptr::null_mut(),
    )
}

/// Drop a boxed v3 `SpfResultV3`. Safe to call with NULL.
///
/// # Safety
/// `r` must have been produced by `lr_ospf_spf_v3_run` /
/// `_v3_extended_run` and not already freed.
#[no_mangle]
pub unsafe extern "C" fn lr_ospf_spf_v3_result_free(r: lr_ospf_spf_v3_result_t) {
    guarded(
        || unsafe {
            drop(unbox_v3_result(r));
        },
        (),
    )
}

/// Total route count in a v3 `SpfResultV3`. Returns 0 on a NULL
/// handle.
///
/// # Safety
/// `r` must be a valid SpfResultV3 handle.
#[no_mangle]
pub unsafe extern "C" fn lr_ospf_spf_v3_route_count(r: lr_ospf_spf_v3_result_t) -> usize {
    guarded(
        || unsafe { borrow_v3_result(r).map(|x| x.routes.len()).unwrap_or(0) },
        0,
    )
}

/// Read one v3 route by index.
///
/// # Safety
/// `r` must be a valid SpfResultV3 handle. `out` must point to a
/// writable `lr_ospf_spf_route_t`.
#[no_mangle]
pub unsafe extern "C" fn lr_ospf_spf_v3_route_at(
    r: lr_ospf_spf_v3_result_t,
    index: usize,
    out: *mut lr_ospf_spf_route_t,
) -> i32 {
    guarded(
        || unsafe {
            let Some(result) = borrow_v3_result(r) else {
                return LR_ERR_NULL;
            };
            if out.is_null() {
                return LR_ERR_NULL;
            }
            let Some(route) = result.routes.get(index) else {
                set_last_error(format!(
                    "spf v3 route {index} out of range (len={})",
                    result.routes.len()
                ));
                return LrError::InvalidHandle as i32;
            };
            unsafe { *out = spf_route_to_c(route) };
            0
        },
        LR_ERR_PANIC,
    )
}

/// Number of inter-area summary routes on a v3 result (RFC 5340
/// §4.8 — computed on top of an intra-area v3 SPF result).
///
/// # Safety
/// `lsdb` and `r` must be valid handles.
#[no_mangle]
pub unsafe extern "C" fn lr_ospf_spf_v3_summary_count(
    lsdb: lr_ospf_lsdb_t,
    r: lr_ospf_spf_v3_result_t,
) -> usize {
    guarded(
        || unsafe {
            let Some(d) = borrow_lsdb(lsdb) else {
                return 0;
            };
            let Some(result) = borrow_v3_result(r) else {
                return 0;
            };
            let owned: &Lsdb = d;
            lr_ospf::spf::summary_routes_v3(owned, result).len()
        },
        0,
    )
}

/// Read one v3 inter-area summary route by index.
///
/// # Safety
/// See [`lr_ospf_spf_v3_summary_count`]. `out` must point to a
/// writable `lr_ospf_spf_route_t`.
#[no_mangle]
pub unsafe extern "C" fn lr_ospf_spf_v3_summary_at(
    lsdb: lr_ospf_lsdb_t,
    r: lr_ospf_spf_v3_result_t,
    index: usize,
    out: *mut lr_ospf_spf_route_t,
) -> i32 {
    guarded(
        || unsafe {
            let Some(d) = borrow_lsdb(lsdb) else {
                return LR_ERR_NULL;
            };
            let Some(result) = borrow_v3_result(r) else {
                return LR_ERR_NULL;
            };
            if out.is_null() {
                return LR_ERR_NULL;
            }
            let owned: &Lsdb = d;
            let summaries = lr_ospf::spf::summary_routes_v3(owned, result);
            let Some(route) = summaries.get(index) else {
                set_last_error(format!(
                    "spf v3 summary {index} out of range (len={})",
                    summaries.len()
                ));
                return LrError::InvalidHandle as i32;
            };
            unsafe { *out = spf_route_to_c(route) };
            0
        },
        LR_ERR_PANIC,
    )
}

/// Number of SRv6 locator routes on a v3 result (RFC 9513 §5 —
/// locator routes projected from the LSDB alongside the regular
/// intra-area SPF).
///
/// # Safety
/// `r` must be a valid SpfResultV3 handle.
#[no_mangle]
pub unsafe extern "C" fn lr_ospf_spf_v3_locator_count(r: lr_ospf_spf_v3_result_t) -> usize {
    guarded(
        || unsafe { borrow_v3_result(r).map(|x| x.locators.len()).unwrap_or(0) },
        0,
    )
}

/// Read one v3 SRv6 locator route by index. The route carries the
/// locator prefix + the algorithm + the metric + the next hop + the
/// advertising router (RFC 9513 §5.1). The locator route is exposed
/// through the same `lr_ospf_spf_route_t` shape, with `metric` and
/// `next_hop` populated from the locator projection.
///
/// # Safety
/// `r` must be a valid SpfResultV3 handle. `out` must point to a
/// writable `lr_ospf_spf_route_t`.
#[no_mangle]
pub unsafe extern "C" fn lr_ospf_spf_v3_locator_at(
    r: lr_ospf_spf_v3_result_t,
    index: usize,
    out: *mut lr_ospf_spf_route_t,
) -> i32 {
    guarded(
        || unsafe {
            let Some(result) = borrow_v3_result(r) else {
                return LR_ERR_NULL;
            };
            if out.is_null() {
                return LR_ERR_NULL;
            }
            let Some(loc) = result.locators.get(index) else {
                set_last_error(format!(
                    "spf v3 locator {index} out of range (len={})",
                    result.locators.len()
                ));
                return LrError::InvalidHandle as i32;
            };
            // Project the locator route through the same SpfRoute
            // shape so the embedder reuses one struct.
            let route = SpfRoute {
                prefix: loc.prefix,
                metric: loc.metric,
                next_hop: loc.next_hop.clone(),
                border_router: None,
                router_id: Some(loc.advertising_router),
            };
            unsafe { *out = spf_route_to_c(&route) };
            0
        },
        LR_ERR_PANIC,
    )
}

// Keep this import out of the unused-import warning by referencing it
// in a doc test surface — the lr_bytes_t handle is used by future
// encode/decode helpers in this module (none yet).
#[allow(dead_code)]
fn _link_bytes_type() -> lr_bytes_t {
    lr_bytes_t {
        ptr: std::ptr::null_mut(),
        len: 0,
        cap: 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lr_ospf::lsa::LsaHeader;

    /// Build a v2 Router-LSA with the given stub networks and install
    /// it into the LSDB through the public FFI surface.
    fn install_router_lsa(lsdb: lr_ospf_lsdb_t, rid: u32, links: Vec<(u32, u32, u8, u16)>) {
        let mut body = Vec::new();
        body.extend_from_slice(&0u16.to_be_bytes()); // flags
        body.extend_from_slice(&(links.len() as u16).to_be_bytes()); // # links
        for (link_id, link_data, link_type, metric) in links {
            body.extend_from_slice(&link_id.to_be_bytes());
            body.extend_from_slice(&link_data.to_be_bytes());
            body.push(link_type);
            body.push(0); // # TOS
            body.extend_from_slice(&metric.to_be_bytes());
        }
        // Build the LSA header through the FFI surface.
        let hdr = crate::ospf_lsdb::lr_ospf_lsa_header_new(
            0,          // ls_age
            0,          // options
            1,          // ls_type (Router-LSA)
            rid,        // link_state_id
            rid,        // advertising_router
            0x80000001, // ls_sequence_number
            0,          // ls_checksum
            (LsaHeader::LEN + body.len()) as u16,
        );
        let lsa = unsafe { crate::ospf_lsdb::lr_ospf_lsa_new(hdr, body.as_ptr(), body.len()) };
        unsafe {
            crate::ospf_lsdb::lr_ospf_lsdb_install(lsdb, lsa, 0);
        }
    }

    #[test]
    fn ffi_spf_run_on_empty_lsdb_returns_empty_result() {
        let lsdb = unsafe { crate::ospf_lsdb::lr_ospf_lsdb_new() };
        let r = unsafe { lr_ospf_spf_run(lsdb, 0x01020304) };
        assert!(!r.is_null());
        assert_eq!(unsafe { lr_ospf_spf_route_count(r) }, 0);
        unsafe {
            lr_ospf_spf_result_free(r);
            lr_ospf_spf_result_free(std::ptr::null_mut());
            crate::ospf_lsdb::lr_ospf_lsdb_free(lsdb);
        }
    }

    #[test]
    fn ffi_spf_run_on_lsdb_with_one_router_lsa() {
        let lsdb = unsafe { crate::ospf_lsdb::lr_ospf_lsdb_new() };
        // Install a router-LSA with one stub network 10.10.10.0/24.
        // (link_id = network, link_data = mask, link_type = 3 = Stub,
        // metric = 10).
        install_router_lsa(lsdb, 0x01020304, vec![(0x0a0a0a00, 0xffff_ff00, 3, 10)]);

        // Verify the LSDB accepted the LSA (sanity check on the test
        // helper — if this fails the SPF run below trivially has
        // nothing to compute).
        assert_eq!(unsafe { crate::ospf_lsdb::lr_ospf_lsdb_len(lsdb) }, 1);

        let r = unsafe { lr_ospf_spf_run(lsdb, 0x01020304) };
        assert!(!r.is_null());
        // One stub network in the result.
        assert_eq!(unsafe { lr_ospf_spf_route_count(r) }, 1);

        let mut route = lr_ospf_spf_route_t::default();
        let rc = unsafe { lr_ospf_spf_route_at(r, 0, &raw mut route) };
        assert_eq!(rc, 0);
        assert_eq!(route.prefix_is_ipv6, 0);
        assert_eq!(&route.prefix_addr[..4], &[10, 10, 10, 0]);
        assert_eq!(route.prefix_len, 24);
        assert_eq!(route.metric, 10);

        unsafe {
            lr_ospf_spf_result_free(r);
            crate::ospf_lsdb::lr_ospf_lsdb_free(lsdb);
        }
    }

    #[test]
    fn ffi_spf_route_at_returns_invalid_handle_on_oob() {
        let lsdb = unsafe { crate::ospf_lsdb::lr_ospf_lsdb_new() };
        let r = unsafe { lr_ospf_spf_run(lsdb, 0x01020304) };
        let mut route = lr_ospf_spf_route_t::default();
        let rc = unsafe { lr_ospf_spf_route_at(r, 99, &raw mut route) };
        assert_eq!(rc, LrError::InvalidHandle as i32);
        unsafe {
            lr_ospf_spf_result_free(r);
            crate::ospf_lsdb::lr_ospf_lsdb_free(lsdb);
        }
    }

    #[test]
    fn ffi_spf_v3_run_on_empty_lsdb_returns_empty_result() {
        let lsdb = unsafe { crate::ospf_lsdb::lr_ospf_lsdb_new() };
        let r = unsafe { lr_ospf_spf_v3_run(lsdb, 0x01020304) };
        assert!(!r.is_null());
        assert_eq!(unsafe { lr_ospf_spf_v3_route_count(r) }, 0);
        assert_eq!(unsafe { lr_ospf_spf_v3_locator_count(r) }, 0);
        unsafe {
            lr_ospf_spf_v3_result_free(r);
            lr_ospf_spf_v3_result_free(std::ptr::null_mut());
            crate::ospf_lsdb::lr_ospf_lsdb_free(lsdb);
        }
    }

    #[test]
    fn ffi_spf_handles_null_safely() {
        assert_eq!(unsafe { lr_ospf_spf_route_count(std::ptr::null_mut()) }, 0);
        assert_eq!(
            unsafe { lr_ospf_spf_v3_route_count(std::ptr::null_mut()) },
            0
        );
    }

    /// ECMP at the C ABI: a route whose SPF computation discovers two
    /// equal-cost first-hops surfaces them through `next_hop_count`
    /// and the `next_hops[0..next_hop_count]` array (RFC 2328 §16.1
    /// (4)). The struct fields `next_hop`/`next_hop_is_ipv6`/
    /// `has_next_hop` from the previous single-hop shape are gone —
    /// the count + inline array is the new contract.
    ///
    /// Topology: root (1.1.1.1) has two p2p neighbours R2 (2.2.2.2) and
    /// R3 (3.3.3.3) at equal cost (10 each); both R2 and R3 have a p2p
    /// link to R4 (4.4.4.4) at cost 10. R4 is reachable at cost 20 via
    /// two equal-cost paths through R2 (next hop 10.0.0.1) and R3 (next
    /// hop 10.0.0.2). The C ABI projection of R4's stub routes must
    /// surface a `next_hop_count = 2` and the two next-hops in the
    /// inline array.
    #[test]
    fn ffi_spf_route_carries_ecmp_next_hop_set() {
        let lsdb = unsafe { crate::ospf_lsdb::lr_ospf_lsdb_new() };
        // Root: p2p links to R2 and R3 (link-data 0 = unnumbered; the
        // back-links below carry the actual next-hop addresses).
        install_router_lsa(
            lsdb,
            0x01010101,
            vec![
                (0x02020202, 0, 1, 10), // P2P to R2
                (0x03030303, 0, 1, 10), // P2P to R3
            ],
        );
        // R2: back-link toward root (Link Data = R2's addr 10.0.0.1)
        // and a deeper p2p link toward R4 (Link Data 10.0.0.101).
        install_router_lsa(
            lsdb,
            0x02020202,
            vec![
                (0x01010101, 0x0a000001, 1, 10),
                (0x04040404, 0x0a000101, 1, 10),
            ],
        );
        // R3: back-link toward root (Link Data = R3's addr 10.0.0.2)
        // and a deeper p2p link toward R4 (Link Data 10.0.0.102).
        install_router_lsa(
            lsdb,
            0x03030303,
            vec![
                (0x01010101, 0x0a000002, 1, 10),
                (0x04040404, 0x0a000102, 1, 10),
            ],
        );
        // R4: back-links toward R2 and R3, plus a stub network so
        // the SPF surfaces a route projection to the C ABI.
        install_router_lsa(
            lsdb,
            0x04040404,
            vec![
                (0x02020202, 0x0a000101, 1, 10),
                (0x03030303, 0x0a000102, 1, 10),
                // Stub network 192.0.2.0/24 — surfaces as a route
                // whose next-hop set carries both R2's and R3's
                // first hops (the path toward R4's stub is the path
                // toward R4 itself, ECMP across R2 and R3).
                (0xc0000200, 0xffff_ff00, 3, 1),
            ],
        );

        let r = unsafe { lr_ospf_spf_run(lsdb, 0x01010101) };
        assert!(!r.is_null());

        // Find the stub route for 192.0.2.0/24 — its next-hop set
        // is the ECMP pair {10.0.0.1, 10.0.0.2}.
        let count = unsafe { lr_ospf_spf_route_count(r) };
        assert!(count >= 1, "SPF produced at least one stub route");
        let mut found_stub = false;
        for i in 0..count {
            let mut route = lr_ospf_spf_route_t::default();
            let rc = unsafe { lr_ospf_spf_route_at(r, i, &raw mut route) };
            assert_eq!(rc, 0);
            if route.prefix_addr[..4] == [192, 0, 2, 0] && route.prefix_len == 24 {
                found_stub = true;
                // ECMP: two distinct first hops in the inline array.
                assert_eq!(
                    route.next_hop_count, 2,
                    "ECMP next-hop count for the stub route"
                );
                // The two next-hops are 10.0.0.1 (R2) and 10.0.0.2 (R3),
                // stored as IPv4-mapped IPv6 in the lr_ip_addr_t octets
                // (last 4 bytes hold the v4, first 12 are zero).
                let nh0 = &route.next_hops[0];
                assert_eq!(nh0.is_ipv6, 0, "first next-hop is IPv4");
                assert_eq!(&nh0.octets[12..], &[10, 0, 0, 1], "R2 first");
                let nh1 = &route.next_hops[1];
                assert_eq!(nh1.is_ipv6, 0, "second next-hop is IPv4");
                assert_eq!(&nh1.octets[12..], &[10, 0, 0, 2], "R3 second");
                // Slots past `next_hop_count` are zeroed (Default).
                for slot in route.next_hops.iter().skip(route.next_hop_count as usize) {
                    assert_eq!(slot.is_ipv6, 0);
                    assert_eq!(slot.octets, [0u8; 16]);
                }
                break;
            }
        }
        assert!(found_stub, "found 192.0.2.0/24 stub route");

        unsafe {
            lr_ospf_spf_result_free(r);
            crate::ospf_lsdb::lr_ospf_lsdb_free(lsdb);
        }
    }
}
