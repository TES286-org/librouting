//! BGP best-path algorithm FFI (RFC 4271 §9.1.2.2).
//!
//! Stateless. Mirrors the public Rust API of `lr_bgp::best_path::
//! {BestPathConfig, BestPath}` so an embedder can build a
//! `BestPathConfig` and run the best-path algorithm against a slice of
//! routes without going through the daemon.
//!
//! Every entry point runs inside the crate's `catch_unwind` barrier
//! ([`crate::guarded`]): a panic returns `LR_ERR_PANIC` and sets the
//! thread-local last-error string.

// The closure body passed to `guarded` is wrapped in a single `unsafe`
// block to mirror the `pub unsafe extern "C" fn` shape — the inner
// `unsafe { ... }` blocks would otherwise trip `unused_unsafe` under
// the crate's `-D warnings` clippy gate.
#![allow(unused_unsafe)]

use lr_bgp::best_path::{BestPath, BestPathConfig};

use crate::error::LR_ERR_PANIC;
use crate::guarded;

// ---- BestPathConfig ----

/// Repr-C `BestPathConfig`. Mirrors `lr_bgp::best_path::BestPathConfig`.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct lr_best_path_config_t {
    pub always_compare_med: u8,
    pub missing_med_as_infinity: u8,
    pub deterministic_router_id: u8,
    pub prefer_externals: u8,
    pub count_confed_in_path_len: u8,
    pub multipath: u32,
    pub multipath_relax: u8,
    pub graceful_shutdown_least_preferred: u8,
    pub compare_igp_metric: u8,
    pub prefer_next_hop_self: u8,
}

impl Default for lr_best_path_config_t {
    fn default() -> Self {
        let d = BestPathConfig::default();
        Self {
            always_compare_med: d.always_compare_med as u8,
            missing_med_as_infinity: d.missing_med_as_infinity as u8,
            deterministic_router_id: d.deterministic_router_id as u8,
            prefer_externals: d.prefer_externals as u8,
            count_confed_in_path_len: d.count_confed_in_path_len as u8,
            multipath: d.multipath,
            multipath_relax: d.multipath_relax as u8,
            graceful_shutdown_least_preferred: d.graceful_shutdown_least_preferred as u8,
            compare_igp_metric: d.compare_igp_metric as u8,
            prefer_next_hop_self: d.prefer_next_hop_self as u8,
        }
    }
}

impl From<lr_best_path_config_t> for BestPathConfig {
    fn from(c: lr_best_path_config_t) -> Self {
        Self {
            always_compare_med: c.always_compare_med != 0,
            missing_med_as_infinity: c.missing_med_as_infinity != 0,
            deterministic_router_id: c.deterministic_router_id != 0,
            prefer_externals: c.prefer_externals != 0,
            count_confed_in_path_len: c.count_confed_in_path_len != 0,
            multipath: c.multipath,
            multipath_relax: c.multipath_relax != 0,
            graceful_shutdown_least_preferred: c.graceful_shutdown_least_preferred != 0,
            compare_igp_metric: c.compare_igp_metric != 0,
            prefer_next_hop_self: c.prefer_next_hop_self != 0,
        }
    }
}

impl From<BestPathConfig> for lr_best_path_config_t {
    fn from(c: BestPathConfig) -> Self {
        Self {
            always_compare_med: c.always_compare_med as u8,
            missing_med_as_infinity: c.missing_med_as_infinity as u8,
            deterministic_router_id: c.deterministic_router_id as u8,
            prefer_externals: c.prefer_externals as u8,
            count_confed_in_path_len: c.count_confed_in_path_len as u8,
            multipath: c.multipath,
            multipath_relax: c.multipath_relax as u8,
            graceful_shutdown_least_preferred: c.graceful_shutdown_least_preferred as u8,
            compare_igp_metric: c.compare_igp_metric as u8,
            prefer_next_hop_self: c.prefer_next_hop_self as u8,
        }
    }
}

/// Construct a `BestPathConfig` with the RFC 4271 §9.1.2.2 defaults.
#[no_mangle]
pub extern "C" fn lr_best_path_config_default() -> lr_best_path_config_t {
    guarded(
        lr_best_path_config_t::default,
        lr_best_path_config_t::default(),
    )
}

/// Construct a `BestPathConfig` with the explicit values the caller
/// supplies. The `*_u8` fields are interpreted as booleans (0 = false,
/// non-zero = true).
#[no_mangle]
pub extern "C" fn lr_best_path_config_new(
    always_compare_med: u8,
    missing_med_as_infinity: u8,
    deterministic_router_id: u8,
    prefer_externals: u8,
    count_confed_in_path_len: u8,
    multipath: u32,
    multipath_relax: u8,
    graceful_shutdown_least_preferred: u8,
    compare_igp_metric: u8,
    prefer_next_hop_self: u8,
) -> lr_best_path_config_t {
    guarded(
        || lr_best_path_config_t {
            always_compare_med,
            missing_med_as_infinity,
            deterministic_router_id,
            prefer_externals,
            count_confed_in_path_len,
            multipath,
            multipath_relax,
            graceful_shutdown_least_preferred,
            compare_igp_metric,
            prefer_next_hop_self,
        },
        lr_best_path_config_t::default(),
    )
}

/// Convert a Rust `BestPathConfig` to its C form. Mostly useful for
/// testing the round-trip.
pub fn best_path_config_to_c(c: &BestPathConfig) -> lr_best_path_config_t {
    let cloned = BestPathConfig {
        always_compare_med: c.always_compare_med,
        missing_med_as_infinity: c.missing_med_as_infinity,
        deterministic_router_id: c.deterministic_router_id,
        prefer_externals: c.prefer_externals,
        count_confed_in_path_len: c.count_confed_in_path_len,
        multipath: c.multipath,
        multipath_relax: c.multipath_relax,
        graceful_shutdown_least_preferred: c.graceful_shutdown_least_preferred,
        compare_igp_metric: c.compare_igp_metric,
        prefer_next_hop_self: c.prefer_next_hop_self,
    };
    cloned.into()
}

/// Convert a C `lr_best_path_config_t` to its Rust form.
pub fn best_path_config_from_c(c: lr_best_path_config_t) -> BestPathConfig {
    c.into()
}

/// Run the BGP best-path comparison between two route handles and
/// return the comparison result. The two routes are passed as opaque
/// `lr_route_t` handles (the same type the policy module uses).
///
/// Returns:
/// - `-1` when `a` is preferred.
/// - `0` when the two routes tie (the caller should fall through to
///   the next tiebreaker).
/// - `1` when `b` is preferred.
/// - `LR_ERR_NULL` (-1) when either handle is NULL.
///
/// # Safety
/// Both handles must be valid (produced by `lr_route_new_v4` /
/// `lr_route_new_v6` or another `lr_route_*` constructor).
#[no_mangle]
pub unsafe extern "C" fn lr_best_path_compare(
    a: crate::handle::lr_route_t,
    b: crate::handle::lr_route_t,
    cfg: lr_best_path_config_t,
) -> i32 {
    guarded(
        || unsafe {
            if a.is_null() || b.is_null() {
                return crate::error::LrError::Null as i32;
            }
            let ra = unsafe { &*(a as *const lr_core::rib::Route) };
            let rb = unsafe { &*(b as *const lr_core::rib::Route) };
            let rust_cfg: BestPathConfig = cfg.into();
            let ord = BestPath::compare(ra, rb, &rust_cfg);
            match ord {
                core::cmp::Ordering::Less => -1,
                core::cmp::Ordering::Equal => 0,
                core::cmp::Ordering::Greater => 1,
            }
        },
        LR_ERR_PANIC,
    )
}

// ---- BestPath::select / rank / multipath / compare_multipath ----

use crate::handle::lr_route_t;
use lr_core::rib::Route;

/// Borrow a `lr_route_t` as `&Route`. Returns `None` on a NULL handle.
///
/// # Safety
/// `h` must have been produced by a `lr_route_*` constructor and not
/// be freed while the returned reference is live.
unsafe fn borrow_route(h: lr_route_t) -> Option<&'static Route> {
    if h.is_null() {
        return None;
    }
    Some(unsafe { &*(h as *const Route) })
}

/// Select the single best route from a slice. Returns the chosen
/// route handle (a pointer into `routes`, NOT a fresh allocation —
/// the caller must NOT free it separately), or NULL when `routes` is
/// NULL or empty.
///
/// # Safety
/// `routes` must point to `count` readable `lr_route_t` handles,
/// each non-NULL and produced by `lr_route_new_v4` / `_v6`.
#[no_mangle]
pub unsafe extern "C" fn lr_best_path_select(
    routes: *const lr_route_t,
    count: usize,
    cfg: lr_best_path_config_t,
) -> lr_route_t {
    guarded(
        || unsafe {
            if routes.is_null() || count == 0 {
                return std::ptr::null_mut();
            }
            let slice = unsafe { std::slice::from_raw_parts(routes, count) };
            // The Rust API takes `&[Route]`; clone into a temporary
            // Vec<Route> (Route: Clone) so we can call `select`; the
            // chosen Route is then matched back to its source handle
            // by PartialEq.
            let route_vec: Vec<Route> = slice
                .iter()
                .filter_map(|h| unsafe { borrow_route(*h) })
                .cloned()
                .collect();
            if route_vec.is_empty() {
                return std::ptr::null_mut();
            }
            let rust_cfg: BestPathConfig = cfg.into();
            let best = BestPath::select(&route_vec, &rust_cfg);
            match best {
                Some(b) => {
                    for (i, r) in route_vec.iter().enumerate() {
                        if r == b {
                            let mut idx = 0;
                            for &h in slice.iter() {
                                if h.is_null() {
                                    continue;
                                }
                                if idx == i {
                                    return h;
                                }
                                idx += 1;
                            }
                        }
                    }
                    std::ptr::null_mut()
                }
                None => std::ptr::null_mut(),
            }
        },
        std::ptr::null_mut(),
    )
}

/// Rank the routes best-first. Returns a freshly-allocated array of
/// `lr_route_t` handles (a permutation of the input — same pointers,
/// different order) packed as `lr_bytes_t` (caller frees with
/// `lr_bytes_free`).
///
/// # Safety
/// `routes` must point to `count` readable `lr_route_t` handles.
#[no_mangle]
pub unsafe extern "C" fn lr_best_path_rank(
    routes: *const lr_route_t,
    count: usize,
    cfg: lr_best_path_config_t,
    out: *mut crate::handle::lr_bytes_t,
) -> i32 {
    guarded(
        || unsafe {
            if routes.is_null() || out.is_null() {
                return crate::error::LrError::Null as i32;
            }
            if count == 0 {
                unsafe {
                    *out = crate::handle::lr_bytes_t {
                        ptr: std::ptr::null_mut(),
                        len: 0,
                        cap: 0,
                    }
                }
                return 0;
            }
            let slice = unsafe { std::slice::from_raw_parts(routes, count) };
            let route_vec: Vec<Route> = slice
                .iter()
                .filter_map(|h| unsafe { borrow_route(*h) })
                .cloned()
                .collect();
            let rust_cfg: BestPathConfig = cfg.into();
            let ranked = BestPath::rank(&route_vec, &rust_cfg);
            let out_handles = map_routes_back_by_eq(&ranked, slice);
            pack_route_handles(&out_handles, out);
            0
        },
        LR_ERR_PANIC,
    )
}

/// Extract the equal-cost multipath set from `routes`. Returns 0 on
/// success and writes a freshly-allocated `lr_bytes_t` to `*out`.
/// `*out` is NULL with `len = 0` when there is no multipath set
/// (only a single best path).
///
/// # Safety
/// See [`lr_best_path_rank`].
#[no_mangle]
pub unsafe extern "C" fn lr_best_path_multipath(
    routes: *const lr_route_t,
    count: usize,
    cfg: lr_best_path_config_t,
    out: *mut crate::handle::lr_bytes_t,
) -> i32 {
    guarded(
        || unsafe {
            if routes.is_null() || out.is_null() {
                return crate::error::LrError::Null as i32;
            }
            unsafe {
                *out = crate::handle::lr_bytes_t {
                    ptr: std::ptr::null_mut(),
                    len: 0,
                    cap: 0,
                }
            }
            if count == 0 {
                return 0;
            }
            let slice = unsafe { std::slice::from_raw_parts(routes, count) };
            let route_vec: Vec<Route> = slice
                .iter()
                .filter_map(|h| unsafe { borrow_route(*h) })
                .cloned()
                .collect();
            let rust_cfg: BestPathConfig = cfg.into();
            let mp = BestPath::multipath(&route_vec, &rust_cfg);
            match mp {
                Some(paths) => {
                    let out_handles = map_routes_back_by_eq(&paths, slice);
                    pack_route_handles(&out_handles, out);
                    0
                }
                None => 0,
            }
        },
        LR_ERR_PANIC,
    )
}

/// Compare two routes under the multipath-equality rules (RFC 7911).
///
/// # Safety
/// See [`lr_best_path_compare`].
#[no_mangle]
pub unsafe extern "C" fn lr_best_path_compare_multipath(
    a: lr_route_t,
    b: lr_route_t,
    cfg: lr_best_path_config_t,
) -> i32 {
    guarded(
        || unsafe {
            let (Some(ra), Some(rb)) = (unsafe { borrow_route(a) }, unsafe { borrow_route(b) })
            else {
                return crate::error::LrError::Null as i32;
            };
            let rust_cfg: BestPathConfig = cfg.into();
            let ord = BestPath::compare_multipath(ra, rb, &rust_cfg);
            match ord {
                core::cmp::Ordering::Less => -1,
                core::cmp::Ordering::Equal => 0,
                core::cmp::Ordering::Greater => 1,
            }
        },
        LR_ERR_PANIC,
    )
}

/// Map a slice of `&Route` references back to the input handles they
/// came from, by PartialEq.
///
/// # Safety
/// `slice` must be the same slice `routes` was built from.
unsafe fn map_routes_back_by_eq(routes: &[&Route], slice: &[lr_route_t]) -> Vec<lr_route_t> {
    let mut out = Vec::with_capacity(routes.len());
    'outer: for r in routes {
        for &h in slice.iter() {
            if let Some(rr) = unsafe { borrow_route(h) } {
                if rr == *r {
                    out.push(h);
                    continue 'outer;
                }
            }
        }
        out.push(std::ptr::null_mut());
    }
    out
}

/// Pack a `&[lr_route_t]` into a freshly-allocated `lr_bytes_t` whose
/// `len` is `handles.len() * size_of::<lr_route_t>()`.
unsafe fn pack_route_handles(handles: &[lr_route_t], out: *mut crate::handle::lr_bytes_t) {
    if handles.is_empty() {
        unsafe {
            *out = crate::handle::lr_bytes_t {
                ptr: std::ptr::null_mut(),
                len: 0,
                cap: 0,
            }
        }
        return;
    }
    let byte_len = std::mem::size_of_val(handles);
    let mut byte_vec: Vec<u8> = Vec::with_capacity(byte_len);
    for h in handles {
        let bytes = unsafe {
            std::slice::from_raw_parts(
                h as *const lr_route_t as *const u8,
                std::mem::size_of::<lr_route_t>(),
            )
        };
        byte_vec.extend_from_slice(bytes);
    }
    unsafe {
        *out = crate::handle::lr_bytes_t::from_vec(byte_vec);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ffi_config_default_matches_rust_default() {
        let c = lr_best_path_config_default();
        let rust: BestPathConfig = c.into();
        let default = BestPathConfig::default();
        assert_eq!(rust.always_compare_med, default.always_compare_med);
        assert_eq!(
            rust.missing_med_as_infinity,
            default.missing_med_as_infinity
        );
        assert_eq!(
            rust.deterministic_router_id,
            default.deterministic_router_id
        );
        assert_eq!(rust.prefer_externals, default.prefer_externals);
        assert_eq!(
            rust.count_confed_in_path_len,
            default.count_confed_in_path_len
        );
        assert_eq!(rust.multipath, default.multipath);
        assert_eq!(rust.multipath_relax, default.multipath_relax);
        assert_eq!(
            rust.graceful_shutdown_least_preferred,
            default.graceful_shutdown_least_preferred
        );
        assert_eq!(rust.compare_igp_metric, default.compare_igp_metric);
        assert_eq!(rust.prefer_next_hop_self, default.prefer_next_hop_self);
    }

    #[test]
    fn ffi_config_new_sets_all_fields() {
        let c = lr_best_path_config_new(
            1, // always_compare_med
            1, // missing_med_as_infinity
            0, // deterministic_router_id (off — non-default)
            0, // prefer_externals (off)
            1, // count_confed_in_path_len
            8, // multipath
            1, // multipath_relax
            0, // graceful_shutdown_least_preferred (off)
            0, // compare_igp_metric (off)
            1, // prefer_next_hop_self
        );
        assert_eq!(c.always_compare_med, 1);
        assert_eq!(c.deterministic_router_id, 0);
        assert_eq!(c.multipath, 8);
        assert_eq!(c.prefer_next_hop_self, 1);
    }

    #[test]
    fn ffi_config_roundtrip() {
        let c = lr_best_path_config_new(1, 0, 1, 0, 1, 4, 1, 0, 1, 0);
        let rust: BestPathConfig = c.into();
        let c2: lr_best_path_config_t = rust.into();
        assert_eq!(c.always_compare_med, c2.always_compare_med);
        assert_eq!(c.multipath, c2.multipath);
        assert_eq!(c.multipath_relax, c2.multipath_relax);
    }

    #[test]
    fn ffi_compare_returns_null_on_null_handles() {
        let cfg = lr_best_path_config_default();
        let rc = unsafe { lr_best_path_compare(std::ptr::null_mut(), std::ptr::null_mut(), cfg) };
        assert_eq!(rc, crate::error::LrError::Null as i32);
    }

    /// Helper: build a real `lr_route_t` for a v4 prefix with an
    /// AS_PATH of the given length.
    fn build_route(prefix: [u8; 4], plen: u8, as_path: &[u32]) -> lr_route_t {
        let r = unsafe { crate::policy_objects::lr_route_new_v4(prefix.as_ptr(), plen, 0) };
        assert!(!r.is_null());
        if !as_path.is_empty() {
            let rc = unsafe {
                crate::policy_objects::lr_route_set_as_path(r, as_path.as_ptr(), as_path.len())
            };
            assert_eq!(rc, 0, "set_as_path failed");
        }
        r
    }

    #[test]
    fn ffi_select_picks_shorter_as_path() {
        // Two routes for the same prefix; r2 has the shorter AS_PATH.
        let r1 = build_route([10, 0, 0, 0], 24, &[65001, 65002, 65003]);
        let r2 = build_route([10, 0, 0, 0], 24, &[65001]);
        let routes = [r1, r2];
        let cfg = lr_best_path_config_default();
        let best = unsafe { lr_best_path_select(routes.as_ptr(), 2, cfg) };
        assert!(!best.is_null(), "select must not return NULL for 2 routes");
        assert_eq!(best, r2, "select must pick the shorter-AS_PATH route");
        unsafe {
            crate::policy_objects::lr_route_free(r1);
            crate::policy_objects::lr_route_free(r2);
        }
    }

    #[test]
    fn ffi_select_returns_null_on_empty() {
        let cfg = lr_best_path_config_default();
        let best = unsafe { lr_best_path_select(std::ptr::null(), 0, cfg) };
        assert!(best.is_null());
    }

    #[test]
    fn ffi_select_returns_null_on_null_pointer() {
        let cfg = lr_best_path_config_default();
        let best = unsafe { lr_best_path_select(std::ptr::null(), 5, cfg) };
        assert!(best.is_null());
    }

    #[test]
    fn ffi_rank_returns_all_handles_best_first() {
        let r1 = build_route([10, 0, 0, 0], 24, &[65001, 65002, 65003]);
        let r2 = build_route([10, 0, 0, 0], 24, &[65001]);
        let r3 = build_route([10, 0, 0, 0], 24, &[65001, 65002]);
        let routes = [r1, r2, r3];
        let cfg = lr_best_path_config_default();
        let mut out = crate::handle::lr_bytes_t {
            ptr: std::ptr::null_mut(),
            len: 0,
            cap: 0,
        };
        let rc = unsafe { lr_best_path_rank(routes.as_ptr(), 3, cfg, &mut out) };
        assert_eq!(rc, 0);
        assert_eq!(out.len, 3 * std::mem::size_of::<lr_route_t>());
        // The first ranked handle should be r2 (shortest AS_PATH = 1 AS).
        let ptr = out.ptr as *const lr_route_t;
        let first = unsafe { *ptr };
        assert_eq!(first, r2, "rank must put shortest-AS_PATH first");
        let _ = unsafe { Vec::from_raw_parts(out.ptr, out.len, out.cap) };
        unsafe {
            crate::policy_objects::lr_route_free(r1);
            crate::policy_objects::lr_route_free(r2);
            crate::policy_objects::lr_route_free(r3);
        }
    }

    #[test]
    fn ffi_rank_null_inputs_return_err() {
        let cfg = lr_best_path_config_default();
        let mut out = crate::handle::lr_bytes_t {
            ptr: std::ptr::null_mut(),
            len: 0,
            cap: 0,
        };
        let rc = unsafe { lr_best_path_rank(std::ptr::null(), 0, cfg, &mut out) };
        assert_eq!(rc, crate::error::LrError::Null as i32);
    }

    #[test]
    fn ffi_multipath_empty_input_returns_zero() {
        let cfg = lr_best_path_config_default();
        let mut out = crate::handle::lr_bytes_t {
            ptr: std::ptr::null_mut(),
            len: 0,
            cap: 0,
        };
        let rc = unsafe { lr_best_path_multipath(std::ptr::null(), 0, cfg, &mut out) };
        assert_eq!(rc, crate::error::LrError::Null as i32);
    }

    #[test]
    fn ffi_compare_multipath_null_returns_err() {
        let cfg = lr_best_path_config_default();
        let rc = unsafe {
            lr_best_path_compare_multipath(std::ptr::null_mut(), std::ptr::null_mut(), cfg)
        };
        assert_eq!(rc, crate::error::LrError::Null as i32);
    }
}
