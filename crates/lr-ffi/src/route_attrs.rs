//! Route attribute accessors across the C ABI — fills the gaps left by
//! `crates/lr-ffi/src/policy_objects.rs` (the original D5.3 surface).
//!
//! Mirrors the public Rust API of:
//!
//! - `lr_policy::bgp::{aggregator, aigp, atomic_aggregate, cluster_list,
//!    has_cluster_list, otc, has_otc, pmsi_tunnel, has_pmsi_tunnel,
//!    prepend_as, remove_community, set_as_sequence, originator_id,
//!    as_sequence, has_aggregator, aggregator_asn, aggregator_speaker}`
//! - `lr_policy::babel::{metric, has_metric, seqno, has_seqno, router_id,
//!    has_router_id}`
//! - `lr_policy::ospf::{metric1, has_metric1, metric2, has_metric2, tag,
//!    has_tag, router_id, has_router_id}`
//! - `lr_policy::lrxp::{store_kind, verified, partial_transit, hint_rank,
//!    hint_damp_fom, hint_igp_cost, policy_role, origin_as,
//!    origin_max_valid_len, origin_expiry}` (feature `exchange-plane`)
//!
//! Each entry point takes an `lr_route_t` (the existing opaque handle to
//! a boxed `lr_core::rib::Route`); reads return `LR_ERR_NULL` (-1) on
//! a NULL handle and `0` on success, with the value written through
//! out-pointers. `Option<u32>`-shaped reads surface absence as
//! `LR_ERR_INVALID_HANDLE` (-2) so the embedder can distinguish "no
//! attribute" from "attribute is zero".
//!
//! Every entry point runs inside the crate's `catch_unwind` barrier
//! ([`crate::guarded`]): a panic returns `LR_ERR_PANIC` and sets the
//! thread-local last-error string.

// The closure body passed to `guarded` is wrapped in a single `unsafe`
// block to mirror the `pub unsafe extern "C" fn` shape — the inner
// `unsafe { ... }` blocks would otherwise trip `unused_unsafe` under
// the crate's `-D warnings` clippy gate.
#![allow(unused_unsafe)]

use lr_core::addr::{Asn, IpAddr};
use lr_core::rib::Route;
use lr_policy::{babel as policy_babel, bgp as policy_bgp, ospf as policy_ospf};

#[cfg(feature = "exchange-plane")]
use lr_policy::lrxp as policy_lrxp;

use crate::error::{set_last_error, LR_ERR_PANIC};
use crate::guarded;
use crate::handle::lr_route_t;

const LR_ERR_NULL: i32 = -1;
const LR_ERR_INVALID_HANDLE: i32 = -2;

/// Borrow a route handle as `&Route` for read-only access.
///
/// # Safety
/// `r` must have been produced by `lr_route_new_v4` / `lr_route_new_v6`
/// and not be freed while the returned reference is live.
unsafe fn borrow_route(r: lr_route_t) -> Option<&'static Route> {
    if r.is_null() {
        return None;
    }
    Some(unsafe { &*(r as *const Route) })
}

/// Borrow a route handle as `&mut Route` for mutation.
///
/// # Safety
/// `r` must have been produced by `lr_route_new_v4` / `lr_route_new_v6`
/// and not be freed while the returned reference is live. The handle is
/// `*mut`, so the borrow checker cannot help enforce the no-race
/// contract — the embedder must.
unsafe fn borrow_route_mut(r: lr_route_t) -> Option<&'static mut Route> {
    if r.is_null() {
        return None;
    }
    Some(unsafe { &mut *(r as *mut Route) })
}

// ---- BGP ATOMIC_AGGREGATE (RFC 4271 §5.1.6) ----

/// True when the route carries an ATOMIC_AGGREGATE attribute (RFC 4271
/// §5.1.6). Writes `1` to `*out` when present, `0` when absent. Returns
/// `LR_ERR_NULL` (-1) on a NULL handle.
///
/// # Safety
/// `route` must be a valid handle; `out` must point to writable `uint8_t`.
#[no_mangle]
pub unsafe extern "C" fn lr_route_atomic_aggregate(route: lr_route_t, out: *mut u8) -> i32 {
    guarded(
        || unsafe {
            let Some(r) = borrow_route(route) else {
                return LR_ERR_NULL;
            };
            if out.is_null() {
                return LR_ERR_NULL;
            }
            unsafe { *out = policy_bgp::atomic_aggregate(r) as u8 };
            0
        },
        LR_ERR_PANIC,
    )
}

// ---- BGP ORIGINATOR_ID (RFC 4456 §8) ----

/// The route's ORIGINATOR_ID (RFC 4456 §8) — writes the 4-byte IPv4
/// address to `*out_addr` and `1` to `*out_present` when the attribute
/// is present; `0` to `*out_present` when absent.
///
/// # Safety
/// `route` must be a valid handle; `out_addr` must point to 4 writable
/// bytes; `out_present` must point to a writable `uint8_t`.
#[no_mangle]
pub unsafe extern "C" fn lr_route_originator_id(
    route: lr_route_t,
    out_addr: *mut u8,
    out_present: *mut u8,
) -> i32 {
    guarded(
        || unsafe {
            let Some(r) = borrow_route(route) else {
                return LR_ERR_NULL;
            };
            if out_addr.is_null() || out_present.is_null() {
                return LR_ERR_NULL;
            }
            match policy_bgp::originator_id(r) {
                Some(IpAddr::V4(b)) => unsafe {
                    core::ptr::copy_nonoverlapping(b.as_ptr(), out_addr, 4);
                    *out_present = 1;
                },
                _ => unsafe { *out_present = 0 },
            }
            0
        },
        LR_ERR_PANIC,
    )
}

// ---- BGP CLUSTER_LIST (RFC 4456 §8) ----

/// True when the route carries a CLUSTER_LIST attribute (RFC 4456 §8).
/// Writes `1` to `*out` when present, `0` when absent.
///
/// # Safety
/// See [`lr_route_atomic_aggregate`].
#[no_mangle]
pub unsafe extern "C" fn lr_route_has_cluster_list(route: lr_route_t, out: *mut u8) -> i32 {
    guarded(
        || unsafe {
            let Some(r) = borrow_route(route) else {
                return LR_ERR_NULL;
            };
            if out.is_null() {
                return LR_ERR_NULL;
            }
            unsafe { *out = policy_bgp::has_cluster_list(r) as u8 };
            0
        },
        LR_ERR_PANIC,
    )
}

/// The CLUSTER_LIST length (number of Cluster-ID entries). `0` when
/// the attribute is absent.
///
/// # Safety
/// See [`lr_route_atomic_aggregate`].
#[no_mangle]
pub unsafe extern "C" fn lr_route_cluster_list_len(route: lr_route_t, out: *mut usize) -> i32 {
    guarded(
        || unsafe {
            let Some(r) = borrow_route(route) else {
                return LR_ERR_NULL;
            };
            if out.is_null() {
                return LR_ERR_NULL;
            }
            unsafe { *out = policy_bgp::cluster_list(r).len() };
            0
        },
        LR_ERR_PANIC,
    )
}

/// Read one Cluster-ID at `index`. Writes the 4-byte IPv4 address to
/// `*out_addr`. Returns `LR_ERR_NULL` (-1) on a NULL handle, and
/// `LR_ERR_INVALID_HANDLE` (-2) when the index is out of range.
///
/// # Safety
/// `route` must be a valid handle; `out_addr` must point to 4 writable
/// bytes.
#[no_mangle]
pub unsafe extern "C" fn lr_route_cluster_list_at(
    route: lr_route_t,
    index: usize,
    out_addr: *mut u8,
) -> i32 {
    guarded(
        || unsafe {
            let Some(r) = borrow_route(route) else {
                return LR_ERR_NULL;
            };
            if out_addr.is_null() {
                return LR_ERR_NULL;
            }
            let list = policy_bgp::cluster_list(r);
            let Some(addr) = list.get(index) else {
                set_last_error(format!(
                    "cluster_list index {index} out of range (len={})",
                    list.len()
                ));
                return LR_ERR_INVALID_HANDLE;
            };
            match addr {
                IpAddr::V4(b) => unsafe {
                    core::ptr::copy_nonoverlapping(b.as_ptr(), out_addr, 4);
                },
                _ => unsafe { *out_addr = 0 },
            }
            0
        },
        LR_ERR_PANIC,
    )
}

// ---- BGP OTC (RFC 9231) ----

/// True when the route carries an OTC (Only To Customer) attribute
/// (RFC 9231 §4).
///
/// # Safety
/// See [`lr_route_atomic_aggregate`].
#[no_mangle]
pub unsafe extern "C" fn lr_route_has_otc(route: lr_route_t, out: *mut u8) -> i32 {
    guarded(
        || unsafe {
            let Some(r) = borrow_route(route) else {
                return LR_ERR_NULL;
            };
            if out.is_null() {
                return LR_ERR_NULL;
            }
            unsafe { *out = policy_bgp::has_otc(r) as u8 };
            0
        },
        LR_ERR_PANIC,
    )
}

/// The OTC value (RFC 9231 §4). Writes the 4-byte value to `*out` and
/// `1` to `*out_present` when present; `0` to `*out_present` when
/// absent.
///
/// # Safety
/// See [`lr_route_atomic_aggregate`].
#[no_mangle]
pub unsafe extern "C" fn lr_route_otc(
    route: lr_route_t,
    out: *mut u32,
    out_present: *mut u8,
) -> i32 {
    guarded(
        || unsafe {
            let Some(r) = borrow_route(route) else {
                return LR_ERR_NULL;
            };
            if out.is_null() || out_present.is_null() {
                return LR_ERR_NULL;
            }
            match policy_bgp::otc(r) {
                Some(v) => unsafe {
                    *out = v;
                    *out_present = 1;
                },
                None => unsafe { *out_present = 0 },
            }
            0
        },
        LR_ERR_PANIC,
    )
}

// ---- BGP AIGP (RFC 7311) ----

/// True when the route carries an AIGP attribute (RFC 7311).
///
/// # Safety
/// See [`lr_route_atomic_aggregate`].
#[no_mangle]
pub unsafe extern "C" fn lr_route_has_aigp(route: lr_route_t, out: *mut u8) -> i32 {
    guarded(
        || unsafe {
            let Some(r) = borrow_route(route) else {
                return LR_ERR_NULL;
            };
            if out.is_null() {
                return LR_ERR_NULL;
            }
            unsafe { *out = policy_bgp::has_aigp(r) as u8 };
            0
        },
        LR_ERR_PANIC,
    )
}

/// The AIGP value (RFC 7311). Writes the 8-byte value to `*out` and
/// `1` to `*out_present` when present; `0` to `*out_present` when
/// absent.
///
/// # Safety
/// `out` must point to a writable `uint64_t`.
#[no_mangle]
pub unsafe extern "C" fn lr_route_aigp(
    route: lr_route_t,
    out: *mut u64,
    out_present: *mut u8,
) -> i32 {
    guarded(
        || unsafe {
            let Some(r) = borrow_route(route) else {
                return LR_ERR_NULL;
            };
            if out.is_null() || out_present.is_null() {
                return LR_ERR_NULL;
            }
            match policy_bgp::aigp(r) {
                Some(v) => unsafe {
                    *out = v;
                    *out_present = 1;
                },
                None => unsafe { *out_present = 0 },
            }
            0
        },
        LR_ERR_PANIC,
    )
}

// ---- BGP AGGREGATOR (RFC 4271 §5.1.7) + AS4_AGGREGATOR (RFC 6793) ----

/// True when the route carries an AGGREGATOR attribute (RFC 4271
/// §5.1.7 / RFC 6793 §4).
///
/// # Safety
/// See [`lr_route_atomic_aggregate`].
#[no_mangle]
pub unsafe extern "C" fn lr_route_has_aggregator(route: lr_route_t, out: *mut u8) -> i32 {
    guarded(
        || unsafe {
            let Some(r) = borrow_route(route) else {
                return LR_ERR_NULL;
            };
            if out.is_null() {
                return LR_ERR_NULL;
            }
            unsafe { *out = policy_bgp::has_aggregator(r) as u8 };
            0
        },
        LR_ERR_PANIC,
    )
}

/// The AGGREGATOR AS number (RFC 4271 §5.1.7 / RFC 6793 §4). Writes the
/// 4-byte value to `*out` and `1` to `*out_present` when present; `0`
/// to `*out_present` when absent.
///
/// # Safety
/// See [`lr_route_otc`].
#[no_mangle]
pub unsafe extern "C" fn lr_route_aggregator_asn(
    route: lr_route_t,
    out: *mut u32,
    out_present: *mut u8,
) -> i32 {
    guarded(
        || unsafe {
            let Some(r) = borrow_route(route) else {
                return LR_ERR_NULL;
            };
            if out.is_null() || out_present.is_null() {
                return LR_ERR_NULL;
            }
            match policy_bgp::aggregator_asn(r) {
                Some(v) => unsafe {
                    *out = v;
                    *out_present = 1;
                },
                None => unsafe { *out_present = 0 },
            }
            0
        },
        LR_ERR_PANIC,
    )
}

/// The AGGREGATOR speaker IPv4 address (RFC 4271 §5.1.7 / RFC 6793
/// §4). Writes the 4 bytes to `*out_addr` and `1` to `*out_present`
/// when present; `0` to `*out_present` when absent.
///
/// # Safety
/// `out_addr` must point to 4 writable bytes.
#[no_mangle]
pub unsafe extern "C" fn lr_route_aggregator_speaker(
    route: lr_route_t,
    out_addr: *mut u8,
    out_present: *mut u8,
) -> i32 {
    guarded(
        || unsafe {
            let Some(r) = borrow_route(route) else {
                return LR_ERR_NULL;
            };
            if out_addr.is_null() || out_present.is_null() {
                return LR_ERR_NULL;
            }
            match policy_bgp::aggregator_speaker(r) {
                Some(IpAddr::V4(b)) => unsafe {
                    core::ptr::copy_nonoverlapping(b.as_ptr(), out_addr, 4);
                    *out_present = 1;
                },
                _ => unsafe { *out_present = 0 },
            }
            0
        },
        LR_ERR_PANIC,
    )
}

// ---- BGP PMSI_TUNNEL (RFC 6514 §5) ----

/// True when the route carries a PMSI_TUNNEL attribute (RFC 6514 §5).
///
/// # Safety
/// See [`lr_route_atomic_aggregate`].
#[no_mangle]
pub unsafe extern "C" fn lr_route_has_pmsi_tunnel(route: lr_route_t, out: *mut u8) -> i32 {
    guarded(
        || unsafe {
            let Some(r) = borrow_route(route) else {
                return LR_ERR_NULL;
            };
            if out.is_null() {
                return LR_ERR_NULL;
            }
            unsafe { *out = policy_bgp::has_pmsi_tunnel(r) as u8 };
            0
        },
        LR_ERR_PANIC,
    )
}

/// The PMSI_TUNNEL flags (RFC 6514 §5). Writes the 1-byte value to
/// `*out_flags` and `1` to `*out_present` when present; `0` to
/// `*out_present` when absent.
///
/// # Safety
/// See [`lr_route_atomic_aggregate`].
#[no_mangle]
pub unsafe extern "C" fn lr_route_pmsi_tunnel_flags(
    route: lr_route_t,
    out_flags: *mut u8,
    out_present: *mut u8,
) -> i32 {
    guarded(
        || unsafe {
            let Some(r) = borrow_route(route) else {
                return LR_ERR_NULL;
            };
            if out_flags.is_null() || out_present.is_null() {
                return LR_ERR_NULL;
            }
            match policy_bgp::pmsi_tunnel(r) {
                Some(t) => unsafe {
                    *out_flags = t.flags;
                    *out_present = 1;
                },
                None => unsafe { *out_present = 0 },
            }
            0
        },
        LR_ERR_PANIC,
    )
}

// ---- BGP AS_SEQUENCE (RFC 4271 §5.1.2) ----

/// The flat AS sequence length (sets flattened in order).
///
/// # Safety
/// See [`lr_route_atomic_aggregate`].
#[no_mangle]
pub unsafe extern "C" fn lr_route_as_sequence_len(route: lr_route_t, out: *mut usize) -> i32 {
    guarded(
        || unsafe {
            let Some(r) = borrow_route(route) else {
                return LR_ERR_NULL;
            };
            if out.is_null() {
                return LR_ERR_NULL;
            }
            unsafe { *out = policy_bgp::as_sequence(r).len() };
            0
        },
        LR_ERR_PANIC,
    )
}

/// Read one AS from the flat AS sequence at `index`. Returns
/// `LR_ERR_INVALID_HANDLE` (-2) when the index is out of range.
///
/// # Safety
/// See [`lr_route_atomic_aggregate`].
#[no_mangle]
pub unsafe extern "C" fn lr_route_as_sequence_at(
    route: lr_route_t,
    index: usize,
    out: *mut u32,
) -> i32 {
    guarded(
        || unsafe {
            let Some(r) = borrow_route(route) else {
                return LR_ERR_NULL;
            };
            if out.is_null() {
                return LR_ERR_NULL;
            }
            let seq = policy_bgp::as_sequence(r);
            let Some(asn) = seq.get(index) else {
                set_last_error(format!(
                    "as_sequence index {index} out of range (len={})",
                    seq.len()
                ));
                return LR_ERR_INVALID_HANDLE;
            };
            unsafe { *out = asn.0 };
            0
        },
        LR_ERR_PANIC,
    )
}

/// Replace the route's AS_PATH with a flat AS_SEQUENCE of the given
/// ASNs (RFC 4271 §5.1.2). The previous AS_PATH is overwritten.
///
/// # Safety
/// `asns` must point to `count` readable `uint32_t` values.
#[no_mangle]
pub unsafe extern "C" fn lr_route_set_as_sequence(
    route: lr_route_t,
    asns: *const u32,
    count: usize,
) -> i32 {
    guarded(
        || unsafe {
            let Some(r) = borrow_route_mut(route) else {
                return LR_ERR_NULL;
            };
            if asns.is_null() && count != 0 {
                return LR_ERR_NULL;
            }
            let slice: &[u32] = if count == 0 {
                &[]
            } else {
                unsafe { core::slice::from_raw_parts(asns, count) }
            };
            let seq: Vec<Asn> = slice.iter().map(|v| Asn(*v)).collect();
            policy_bgp::set_as_sequence(r, seq);
            0
        },
        LR_ERR_PANIC,
    )
}

/// Prepend `asn` to the route's AS_PATH (RFC 4271 §5.1.2 — the
/// standard eBGP AS_PATH prepend action). Creates an AS_PATH if absent.
///
/// # Safety
/// See [`lr_route_atomic_aggregate`].
#[no_mangle]
pub unsafe extern "C" fn lr_route_prepend_as(route: lr_route_t, asn: u32) -> i32 {
    guarded(
        || unsafe {
            let Some(r) = borrow_route_mut(route) else {
                return LR_ERR_NULL;
            };
            policy_bgp::prepend_as(r, Asn(asn));
            0
        },
        LR_ERR_PANIC,
    )
}

/// Remove `community` from the route's COMMUNITIES attribute (RFC 1997
/// §4). No-op when the route carries no COMMUNITIES or the community
/// is not present.
///
/// # Safety
/// See [`lr_route_atomic_aggregate`].
#[no_mangle]
pub unsafe extern "C" fn lr_route_remove_community(route: lr_route_t, asn: u32, value: u16) -> i32 {
    guarded(
        || unsafe {
            let Some(r) = borrow_route_mut(route) else {
                return LR_ERR_NULL;
            };
            // COMMUNITIES (RFC 1997 §4) carry a 2-byte AS — mask to 16 bits
            // so an out-of-range value does not silently mismatch.
            let asn16 = (asn & 0xffff) as u16;
            let community = lr_bgp::path::communities::Community::new(asn16, value);
            policy_bgp::remove_community(r, community);
            0
        },
        LR_ERR_PANIC,
    )
}

// ---- Babel per-route attributes (RFC 8966 §3.2 + §3.4.3 + §4.6.9) ----

/// True when the route carries a Babel metric attribute.
#[no_mangle]
pub unsafe extern "C" fn lr_route_has_babel_metric(route: lr_route_t, out: *mut u8) -> i32 {
    guarded(
        || unsafe {
            let Some(r) = borrow_route(route) else {
                return LR_ERR_NULL;
            };
            if out.is_null() {
                return LR_ERR_NULL;
            }
            unsafe { *out = policy_babel::has_metric(r) as u8 };
            0
        },
        LR_ERR_PANIC,
    )
}

/// The Babel primary metric (RFC 8966 §3.2 + §3.4.3).
#[no_mangle]
pub unsafe extern "C" fn lr_route_babel_metric(
    route: lr_route_t,
    out: *mut u32,
    out_present: *mut u8,
) -> i32 {
    guarded(
        || unsafe {
            let Some(r) = borrow_route(route) else {
                return LR_ERR_NULL;
            };
            if out.is_null() || out_present.is_null() {
                return LR_ERR_NULL;
            }
            match policy_babel::metric(r) {
                Some(v) => unsafe {
                    *out = v;
                    *out_present = 1;
                },
                None => unsafe { *out_present = 0 },
            }
            0
        },
        LR_ERR_PANIC,
    )
}

/// True when the route carries a Babel sequence number attribute.
#[no_mangle]
pub unsafe extern "C" fn lr_route_has_babel_seqno(route: lr_route_t, out: *mut u8) -> i32 {
    guarded(
        || unsafe {
            let Some(r) = borrow_route(route) else {
                return LR_ERR_NULL;
            };
            if out.is_null() {
                return LR_ERR_NULL;
            }
            unsafe { *out = policy_babel::has_seqno(r) as u8 };
            0
        },
        LR_ERR_PANIC,
    )
}

/// The Babel sequence number (RFC 8966 §3.2 + §4.6.9).
#[no_mangle]
pub unsafe extern "C" fn lr_route_babel_seqno(
    route: lr_route_t,
    out: *mut u16,
    out_present: *mut u8,
) -> i32 {
    guarded(
        || unsafe {
            let Some(r) = borrow_route(route) else {
                return LR_ERR_NULL;
            };
            if out.is_null() || out_present.is_null() {
                return LR_ERR_NULL;
            }
            match policy_babel::seqno(r) {
                Some(v) => unsafe {
                    *out = v;
                    *out_present = 1;
                },
                None => unsafe { *out_present = 0 },
            }
            0
        },
        LR_ERR_PANIC,
    )
}

/// True when the route carries a Babel router-id attribute.
#[no_mangle]
pub unsafe extern "C" fn lr_route_has_babel_router_id(route: lr_route_t, out: *mut u8) -> i32 {
    guarded(
        || unsafe {
            let Some(r) = borrow_route(route) else {
                return LR_ERR_NULL;
            };
            if out.is_null() {
                return LR_ERR_NULL;
            }
            unsafe { *out = policy_babel::has_router_id(r) as u8 };
            0
        },
        LR_ERR_PANIC,
    )
}

/// The Babel router-id (RFC 8966 §3.2 + §4.6.9) — 8 bytes, written
/// through `*out_router_id` (which must point to 8 writable bytes).
#[no_mangle]
pub unsafe extern "C" fn lr_route_babel_router_id(
    route: lr_route_t,
    out_router_id: *mut u8,
    out_present: *mut u8,
) -> i32 {
    guarded(
        || unsafe {
            let Some(r) = borrow_route(route) else {
                return LR_ERR_NULL;
            };
            if out_router_id.is_null() || out_present.is_null() {
                return LR_ERR_NULL;
            }
            match policy_babel::router_id(r) {
                Some(v) => unsafe {
                    let bytes = v.to_be_bytes();
                    core::ptr::copy_nonoverlapping(bytes.as_ptr(), out_router_id, 8);
                    *out_present = 1;
                },
                None => unsafe { *out_present = 0 },
            }
            0
        },
        LR_ERR_PANIC,
    )
}

// ---- OSPF per-route attributes (RFC 2328 §16 / RFC 5340 §4.1) ----

/// True when the route carries an OSPF metric1 attribute.
#[no_mangle]
pub unsafe extern "C" fn lr_route_has_ospf_metric1(route: lr_route_t, out: *mut u8) -> i32 {
    guarded(
        || unsafe {
            let Some(r) = borrow_route(route) else {
                return LR_ERR_NULL;
            };
            if out.is_null() {
                return LR_ERR_NULL;
            }
            unsafe { *out = policy_ospf::has_metric1(r) as u8 };
            0
        },
        LR_ERR_PANIC,
    )
}

/// The OSPF primary metric (RFC 2328 §16 / RFC 5340 §4.1).
#[no_mangle]
pub unsafe extern "C" fn lr_route_ospf_metric1(
    route: lr_route_t,
    out: *mut u32,
    out_present: *mut u8,
) -> i32 {
    guarded(
        || unsafe {
            let Some(r) = borrow_route(route) else {
                return LR_ERR_NULL;
            };
            if out.is_null() || out_present.is_null() {
                return LR_ERR_NULL;
            }
            match policy_ospf::metric1(r) {
                Some(v) => unsafe {
                    *out = v;
                    *out_present = 1;
                },
                None => unsafe { *out_present = 0 },
            }
            0
        },
        LR_ERR_PANIC,
    )
}

/// True when the route carries an OSPF metric2 attribute.
#[no_mangle]
pub unsafe extern "C" fn lr_route_has_ospf_metric2(route: lr_route_t, out: *mut u8) -> i32 {
    guarded(
        || unsafe {
            let Some(r) = borrow_route(route) else {
                return LR_ERR_NULL;
            };
            if out.is_null() {
                return LR_ERR_NULL;
            }
            unsafe { *out = policy_ospf::has_metric2(r) as u8 };
            0
        },
        LR_ERR_PANIC,
    )
}

/// The OSPF type-2 external metric (RFC 2328 §16.4 / RFC 5340 §4.8.5).
#[no_mangle]
pub unsafe extern "C" fn lr_route_ospf_metric2(
    route: lr_route_t,
    out: *mut u32,
    out_present: *mut u8,
) -> i32 {
    guarded(
        || unsafe {
            let Some(r) = borrow_route(route) else {
                return LR_ERR_NULL;
            };
            if out.is_null() || out_present.is_null() {
                return LR_ERR_NULL;
            }
            match policy_ospf::metric2(r) {
                Some(v) => unsafe {
                    *out = v;
                    *out_present = 1;
                },
                None => unsafe { *out_present = 0 },
            }
            0
        },
        LR_ERR_PANIC,
    )
}

/// True when the route carries an OSPF tag attribute.
#[no_mangle]
pub unsafe extern "C" fn lr_route_has_ospf_tag(route: lr_route_t, out: *mut u8) -> i32 {
    guarded(
        || unsafe {
            let Some(r) = borrow_route(route) else {
                return LR_ERR_NULL;
            };
            if out.is_null() {
                return LR_ERR_NULL;
            }
            unsafe { *out = policy_ospf::has_tag(r) as u8 };
            0
        },
        LR_ERR_PANIC,
    )
}

/// The OSPF external route tag (RFC 2328 §A.4.5 bullet h / RFC 3101
/// §2.3 / RFC 5340 §A.4.7 T bit / RFC 8362 §3.6 External-Prefix
/// sub-TLV 3).
#[no_mangle]
pub unsafe extern "C" fn lr_route_ospf_tag(
    route: lr_route_t,
    out: *mut u32,
    out_present: *mut u8,
) -> i32 {
    guarded(
        || unsafe {
            let Some(r) = borrow_route(route) else {
                return LR_ERR_NULL;
            };
            if out.is_null() || out_present.is_null() {
                return LR_ERR_NULL;
            }
            match policy_ospf::tag(r) {
                Some(v) => unsafe {
                    *out = v;
                    *out_present = 1;
                },
                None => unsafe { *out_present = 0 },
            }
            0
        },
        LR_ERR_PANIC,
    )
}

/// True when the route carries an OSPF router-id attribute.
#[no_mangle]
pub unsafe extern "C" fn lr_route_has_ospf_router_id(route: lr_route_t, out: *mut u8) -> i32 {
    guarded(
        || unsafe {
            let Some(r) = borrow_route(route) else {
                return LR_ERR_NULL;
            };
            if out.is_null() {
                return LR_ERR_NULL;
            }
            unsafe { *out = policy_ospf::has_router_id(r) as u8 };
            0
        },
        LR_ERR_PANIC,
    )
}

/// The OSPF advertising router (RFC 2328 §A.4 / RFC 5340 §A.4).
#[no_mangle]
pub unsafe extern "C" fn lr_route_ospf_router_id(
    route: lr_route_t,
    out: *mut u32,
    out_present: *mut u8,
) -> i32 {
    guarded(
        || unsafe {
            let Some(r) = borrow_route(route) else {
                return LR_ERR_NULL;
            };
            if out.is_null() || out_present.is_null() {
                return LR_ERR_NULL;
            }
            match policy_ospf::router_id(r) {
                Some(v) => unsafe {
                    *out = v;
                    *out_present = 1;
                },
                None => unsafe { *out_present = 0 },
            }
            0
        },
        LR_ERR_PANIC,
    )
}

// ---- LRXP exchange-plane record access (feature `exchange-plane`) ----

#[cfg(feature = "exchange-plane")]
mod lrxp_ffi {
    use super::*;

    /// The LRXP store kind tag (0 = absent, 1 = verified, 2 =
    /// partial-raw). Writes `0` to `*out` when the route carries no
    /// LRXP attribute (the fallback case).
    #[no_mangle]
    pub unsafe extern "C" fn lr_route_lrxp_store_kind(
        route: lr_route_t,
        out: *mut u8,
        out_present: *mut u8,
    ) -> i32 {
        guarded(
            || unsafe {
                let Some(r) = borrow_route(route) else {
                    return LR_ERR_NULL;
                };
                if out.is_null() || out_present.is_null() {
                    return LR_ERR_NULL;
                }
                match policy_lrxp::store_kind(r) {
                    Some(v) => unsafe {
                        *out = v;
                        *out_present = 1;
                    },
                    None => unsafe { *out_present = 0 },
                }
                0
            },
            LR_ERR_PANIC,
        )
    }

    /// True when the route carries a verified LRXP record set.
    #[no_mangle]
    pub unsafe extern "C" fn lr_route_lrxp_verified(route: lr_route_t, out: *mut u8) -> i32 {
        guarded(
            || unsafe {
                let Some(r) = borrow_route(route) else {
                    return LR_ERR_NULL;
                };
                if out.is_null() {
                    return LR_ERR_NULL;
                }
                unsafe { *out = policy_lrxp::verified(r) as u8 };
                0
            },
            LR_ERR_PANIC,
        )
    }

    /// True when the route carries partial-transit LRXP forwarding
    /// material.
    #[no_mangle]
    pub unsafe extern "C" fn lr_route_lrxp_partial_transit(route: lr_route_t, out: *mut u8) -> i32 {
        guarded(
            || unsafe {
                let Some(r) = borrow_route(route) else {
                    return LR_ERR_NULL;
                };
                if out.is_null() {
                    return LR_ERR_NULL;
                }
                unsafe { *out = policy_lrxp::partial_transit(r) as u8 };
                0
            },
            LR_ERR_PANIC,
        )
    }

    /// The sender's best-path rank for this path among its alternates
    /// (design §5.1: 1 = the path the sender itself uses). `0` when
    /// the route carries no verified hint record.
    #[no_mangle]
    pub unsafe extern "C" fn lr_route_lrxp_hint_rank(route: lr_route_t, out: *mut u8) -> i32 {
        guarded(
            || unsafe {
                let Some(r) = borrow_route(route) else {
                    return LR_ERR_NULL;
                };
                if out.is_null() {
                    return LR_ERR_NULL;
                }
                unsafe { *out = policy_lrxp::hint_rank(r) };
                0
            },
            LR_ERR_PANIC,
        )
    }

    /// The sender's route-flap figure of merit for the prefix (design
    /// §5.1: 0 when damping is off). `0` when the route carries no
    /// verified hint record.
    #[no_mangle]
    pub unsafe extern "C" fn lr_route_lrxp_hint_damp_fom(route: lr_route_t, out: *mut u16) -> i32 {
        guarded(
            || unsafe {
                let Some(r) = borrow_route(route) else {
                    return LR_ERR_NULL;
                };
                if out.is_null() {
                    return LR_ERR_NULL;
                }
                unsafe { *out = policy_lrxp::hint_damp_fom(r) };
                0
            },
            LR_ERR_PANIC,
        )
    }

    /// The sender's IGP cost from its decision point to this path's
    /// next hop (design §5.1). `0` when the route carries no verified
    /// hint record.
    #[no_mangle]
    pub unsafe extern "C" fn lr_route_lrxp_hint_igp_cost(route: lr_route_t, out: *mut u32) -> i32 {
        guarded(
            || unsafe {
                let Some(r) = borrow_route(route) else {
                    return LR_ERR_NULL;
                };
                if out.is_null() {
                    return LR_ERR_NULL;
                }
                unsafe { *out = policy_lrxp::hint_igp_cost(r) };
                0
            },
            LR_ERR_PANIC,
        )
    }

    /// The sender's RFC 9234 role claim for this session (design
    /// §5.2: 0 = provider, 1 = customer, 2 = RS, 3 = RS-client, 4 =
    /// peer, 255 = unspecified; advisory — the receiver cross-checks
    /// against its own configured role). `255` (unspecified) when the
    /// route carries no verified policy record.
    #[no_mangle]
    pub unsafe extern "C" fn lr_route_lrxp_policy_role(route: lr_route_t, out: *mut u8) -> i32 {
        guarded(
            || unsafe {
                let Some(r) = borrow_route(route) else {
                    return LR_ERR_NULL;
                };
                if out.is_null() {
                    return LR_ERR_NULL;
                }
                unsafe { *out = policy_lrxp::policy_role(r) };
                0
            },
            LR_ERR_PANIC,
        )
    }

    /// The origin AS the attestation authorises for this announcement
    /// set (design §5.3). `0` when the route carries no verified origin
    /// record.
    #[no_mangle]
    pub unsafe extern "C" fn lr_route_lrxp_origin_as(route: lr_route_t, out: *mut u32) -> i32 {
        guarded(
            || unsafe {
                let Some(r) = borrow_route(route) else {
                    return LR_ERR_NULL;
                };
                if out.is_null() {
                    return LR_ERR_NULL;
                }
                unsafe { *out = policy_lrxp::origin_as(r) };
                0
            },
            LR_ERR_PANIC,
        )
    }

    /// The maximum prefix length the origin authorises for this
    /// announcement set (design §5.3: the ROA maxLength idea, RFC 6811
    /// §3, without the PKI). `0` when the route carries no verified
    /// origin record.
    #[no_mangle]
    pub unsafe extern "C" fn lr_route_lrxp_origin_max_valid_len(
        route: lr_route_t,
        out: *mut u8,
    ) -> i32 {
        guarded(
            || unsafe {
                let Some(r) = borrow_route(route) else {
                    return LR_ERR_NULL;
                };
                if out.is_null() {
                    return LR_ERR_NULL;
                }
                unsafe { *out = policy_lrxp::origin_max_valid_len(r) };
                0
            },
            LR_ERR_PANIC,
        )
    }

    /// The absolute timestamp after which downstream speakers stop
    /// trusting the record (design §5.3). `0` when the route carries
    /// no verified origin record.
    #[no_mangle]
    pub unsafe extern "C" fn lr_route_lrxp_origin_expiry(route: lr_route_t, out: *mut u32) -> i32 {
        guarded(
            || unsafe {
                let Some(r) = borrow_route(route) else {
                    return LR_ERR_NULL;
                };
                if out.is_null() {
                    return LR_ERR_NULL;
                }
                unsafe { *out = policy_lrxp::origin_expiry(r) };
                0
            },
            LR_ERR_PANIC,
        )
    }
}

// Re-export the LRXP FFI symbols at the crate root level so they
// appear in the same flat `lr_route_lrxp_*` namespace as the rest of
// the route-attribute surface. The cfg-gated mod keeps the symbols
// out of the build when `exchange-plane` is off.
#[cfg(feature = "exchange-plane")]
pub use lrxp_ffi::*;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::handle::lr_route_t;
    use lr_core::addr::Prefix;
    use lr_core::rib::{Protocol, Route, RouteKey, RouteOrigin};

    fn new_v4_route() -> lr_route_t {
        let route = Route {
            key: RouteKey::new(
                Prefix::new_v4([10, 0, 0, 0], 24),
                lr_core::nlri::NlriFamily::IPV4_UNICAST,
            ),
            origin: RouteOrigin { proto: 0, peer: 0 },
            protocol: Protocol::Bgp,
            preference: lr_core::rib::Preference::new(100, 0),
            next_hop: None,
            attributes: lr_core::attr::Attributes::new(),
            age_ms: 0,
            path_id: 0,
            tag: None,
        };
        // SAFETY: tests are single-threaded; the route is owned by the
        // caller through the opaque handle.
        Box::into_raw(Box::new(route)) as lr_route_t
    }

    unsafe fn free_route(r: lr_route_t) {
        if !r.is_null() {
            drop(unsafe { Box::from_raw(r as *mut Route) });
        }
    }

    #[test]
    fn atomic_aggregate_absent_by_default() {
        let r = new_v4_route();
        let mut out = 1u8;
        let rc = unsafe { lr_route_atomic_aggregate(r, &raw mut out) };
        assert_eq!(rc, 0);
        assert_eq!(out, 0, "ATOMIC_AGGREGATE absent on a fresh route");
        unsafe { free_route(r) };
    }

    #[test]
    fn cluster_list_absent_by_default() {
        let r = new_v4_route();
        let mut present = 1u8;
        let rc = unsafe { lr_route_has_cluster_list(r, &raw mut present) };
        assert_eq!(rc, 0);
        assert_eq!(present, 0);
        let mut len = 999usize;
        let rc = unsafe { lr_route_cluster_list_len(r, &raw mut len) };
        assert_eq!(rc, 0);
        assert_eq!(len, 0);
        unsafe { free_route(r) };
    }

    #[test]
    fn otc_absent_by_default() {
        let r = new_v4_route();
        let mut present = 1u8;
        let rc = unsafe { lr_route_has_otc(r, &raw mut present) };
        assert_eq!(rc, 0);
        assert_eq!(present, 0);
        let mut value = 999u32;
        let rc = unsafe { lr_route_otc(r, &raw mut value, &raw mut present) };
        assert_eq!(rc, 0);
        assert_eq!(present, 0);
        unsafe { free_route(r) };
    }

    #[test]
    fn aigp_absent_by_default() {
        let r = new_v4_route();
        let mut present = 1u8;
        let rc = unsafe { lr_route_has_aigp(r, &raw mut present) };
        assert_eq!(rc, 0);
        assert_eq!(present, 0);
        let mut value = 999u64;
        let rc = unsafe { lr_route_aigp(r, &raw mut value, &raw mut present) };
        assert_eq!(rc, 0);
        assert_eq!(present, 0);
        unsafe { free_route(r) };
    }

    #[test]
    fn aggregator_absent_by_default() {
        let r = new_v4_route();
        let mut present = 1u8;
        let rc = unsafe { lr_route_has_aggregator(r, &raw mut present) };
        assert_eq!(rc, 0);
        assert_eq!(present, 0);
        unsafe { free_route(r) };
    }

    #[test]
    fn pmsi_tunnel_absent_by_default() {
        let r = new_v4_route();
        let mut present = 1u8;
        let rc = unsafe { lr_route_has_pmsi_tunnel(r, &raw mut present) };
        assert_eq!(rc, 0);
        assert_eq!(present, 0);
        unsafe { free_route(r) };
    }

    #[test]
    fn as_sequence_empty_by_default() {
        let r = new_v4_route();
        let mut len = 999usize;
        let rc = unsafe { lr_route_as_sequence_len(r, &raw mut len) };
        assert_eq!(rc, 0);
        assert_eq!(len, 0);
        let mut value = 999u32;
        let rc = unsafe { lr_route_as_sequence_at(r, 0, &raw mut value) };
        assert_eq!(rc, LR_ERR_INVALID_HANDLE, "OOB index returns -2");
        unsafe { free_route(r) };
    }

    #[test]
    fn set_as_sequence_round_trips() {
        let r = new_v4_route();
        let asns = [64512u32, 64513, 64514];
        let rc = unsafe { lr_route_set_as_sequence(r, asns.as_ptr(), asns.len()) };
        assert_eq!(rc, 0);
        let mut len = 0usize;
        let rc = unsafe { lr_route_as_sequence_len(r, &raw mut len) };
        assert_eq!(rc, 0);
        assert_eq!(len, 3);
        let mut v0 = 0u32;
        let rc = unsafe { lr_route_as_sequence_at(r, 0, &raw mut v0) };
        assert_eq!(rc, 0);
        assert_eq!(v0, 64512);
        let mut v2 = 0u32;
        let rc = unsafe { lr_route_as_sequence_at(r, 2, &raw mut v2) };
        assert_eq!(rc, 0);
        assert_eq!(v2, 64514);
        unsafe { free_route(r) };
    }

    #[test]
    fn prepend_as_creates_as_path() {
        let r = new_v4_route();
        let rc = unsafe { lr_route_prepend_as(r, 64512) };
        assert_eq!(rc, 0);
        let mut len = 0usize;
        let rc = unsafe { lr_route_as_sequence_len(r, &raw mut len) };
        assert_eq!(rc, 0);
        assert_eq!(len, 1);
        let mut v = 0u32;
        let rc = unsafe { lr_route_as_sequence_at(r, 0, &raw mut v) };
        assert_eq!(rc, 0);
        assert_eq!(v, 64512);
        // Prepend again — should now be 2 long.
        let rc = unsafe { lr_route_prepend_as(r, 64513) };
        assert_eq!(rc, 0);
        let rc = unsafe { lr_route_as_sequence_len(r, &raw mut len) };
        assert_eq!(rc, 0);
        assert_eq!(len, 2);
        unsafe { free_route(r) };
    }

    #[test]
    fn babel_attrs_absent_by_default() {
        let r = new_v4_route();
        let mut present = 1u8;
        let rc = unsafe { lr_route_has_babel_metric(r, &raw mut present) };
        assert_eq!(rc, 0);
        assert_eq!(present, 0);
        let rc = unsafe { lr_route_has_babel_seqno(r, &raw mut present) };
        assert_eq!(rc, 0);
        assert_eq!(present, 0);
        let rc = unsafe { lr_route_has_babel_router_id(r, &raw mut present) };
        assert_eq!(rc, 0);
        assert_eq!(present, 0);
        unsafe { free_route(r) };
    }

    #[test]
    fn ospf_attrs_absent_by_default() {
        let r = new_v4_route();
        let mut present = 1u8;
        let rc = unsafe { lr_route_has_ospf_metric1(r, &raw mut present) };
        assert_eq!(rc, 0);
        assert_eq!(present, 0);
        let rc = unsafe { lr_route_has_ospf_metric2(r, &raw mut present) };
        assert_eq!(rc, 0);
        assert_eq!(present, 0);
        let rc = unsafe { lr_route_has_ospf_tag(r, &raw mut present) };
        assert_eq!(rc, 0);
        assert_eq!(present, 0);
        let rc = unsafe { lr_route_has_ospf_router_id(r, &raw mut present) };
        assert_eq!(rc, 0);
        assert_eq!(present, 0);
        unsafe { free_route(r) };
    }

    #[test]
    fn null_handle_returns_err_null() {
        let mut out = 0u8;
        let rc = unsafe { lr_route_atomic_aggregate(std::ptr::null_mut(), &raw mut out) };
        assert_eq!(rc, LR_ERR_NULL);
        let rc = unsafe { lr_route_has_cluster_list(std::ptr::null_mut(), &raw mut out) };
        assert_eq!(rc, LR_ERR_NULL);
        let rc = unsafe { lr_route_has_otc(std::ptr::null_mut(), &raw mut out) };
        assert_eq!(rc, LR_ERR_NULL);
        let rc = unsafe { lr_route_has_aigp(std::ptr::null_mut(), &raw mut out) };
        assert_eq!(rc, LR_ERR_NULL);
    }

    #[cfg(feature = "exchange-plane")]
    #[test]
    fn lrxp_attrs_absent_by_default() {
        let r = new_v4_route();
        let mut present = 1u8;
        let mut kind = 0u8;
        let rc = unsafe { lr_route_lrxp_store_kind(r, &raw mut kind, &raw mut present) };
        assert_eq!(rc, 0);
        assert_eq!(present, 0);
        let mut verified = 1u8;
        let rc = unsafe { lr_route_lrxp_verified(r, &raw mut verified) };
        assert_eq!(rc, 0);
        assert_eq!(verified, 0, "fresh route has no LRXP attribute");
        let mut rank = 99u8;
        let rc = unsafe { lr_route_lrxp_hint_rank(r, &raw mut rank) };
        assert_eq!(rc, 0);
        assert_eq!(rank, 0, "absent hint yields 0");
        unsafe { free_route(r) };
    }
}
