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

/// One SPF route projection. Used by `lr_ospf_spf_route_at`,
/// `_summary_at`, `_v3_route_at` to surface one route to C. The
/// `next_hop` field carries v4 in the low 4 bytes (is_ipv6=0) or all
/// 16 bytes (is_ipv6=1); `has_next_hop` is 0 when the route has no
/// resolved next hop (Loc-RIB will install it blackhole-style).
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct lr_ospf_spf_route_t {
    /// Network prefix address (v4 in low 4 bytes, zero-padded to 16).
    pub prefix_addr: [u8; 16],
    /// 0 = IPv4, 1 = IPv6.
    pub prefix_is_ipv6: u8,
    /// Prefix length (0..=32 v4, 0..=128 v6).
    pub prefix_len: u8,
    /// SPF distance to this prefix (RFC 2328 §16.1).
    pub metric: u64,
    /// Next-hop address bytes (v4 in low 4 bytes when is_ipv6=0).
    pub next_hop: [u8; 16],
    /// 0 = IPv4 next hop, 1 = IPv6 next hop.
    pub next_hop_is_ipv6: u8,
    /// 1 when `next_hop` carries a value, 0 when the route has no
    /// resolved next hop.
    pub has_next_hop: u8,
    /// For inter-area routes derived from summary-LSAs: the
    /// advertising router (ABR) that originated the summary. 0 for
    /// intra-area routes.
    pub border_router: u32,
    /// For inter-area routes derived from summary-LSAs: the
    /// advertising router of the LSA. 0 for intra-area routes.
    pub advertising_router: u32,
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
    match r.next_hop {
        Some(lr_core::addr::IpAddr::V4(b)) => {
            out.next_hop[..4].copy_from_slice(&b);
            out.next_hop_is_ipv6 = 0;
            out.has_next_hop = 1;
        }
        Some(lr_core::addr::IpAddr::V6(b)) => {
            out.next_hop = b;
            out.next_hop_is_ipv6 = 1;
            out.has_next_hop = 1;
        }
        None => {
            out.has_next_hop = 0;
        }
    }
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
                next_hop: loc.next_hop,
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
}
