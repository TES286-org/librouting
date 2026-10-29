//! Loc-RIB + Adj-RIB-In/Out + cross-protocol mux FFI (RFC 4271 §9).
//!
//! Mirrors the public Rust API of `lr_rib::{LocRib, AdjRibIn, AdjRibOut,
//! RibMux, RouteSelector, RibDiff}` so an embedder can build, populate
//! and inspect a Loc-RIB (and the Adj-RIBs around it) without going
//! through the daemon's `DefaultRouter`. This is the foundation for
//! embedders that want to bring their own protocol plumbing (e.g. a
//! custom BGP daemon that wires `BgpPeer` to its own Adj-RIB-In and a
//! `LocRib` for selection).
//!
//! # Surface
//!
//! - `lr_loc_rib_new` / `lr_loc_rib_free` — Loc-RIB lifecycle.
//! - `lr_loc_rib_install` — install one path (RFC 7911 path-id aware).
//! - `lr_loc_rib_uninstall` — withdraw a key.
//! - `lr_loc_rib_len` / `lr_loc_rib_is_empty` / `lr_loc_rib_paths_len`
//!   / `lr_loc_rib_generation` — readers.
//! - `lr_loc_rib_best_present` / `lr_loc_rib_best` — best-path reader
//!   (returns 1/0 for presence; the route handle is a *copy* the
//!   caller frees via `lr_route_free`).
//!
//! - `lr_adj_rib_in_new` / `lr_adj_rib_in_free` — Adj-RIB-In lifecycle.
//! - `lr_adj_rib_in_feed` — install one pre-policy route.
//! - `lr_adj_rib_in_withdraw` — withdraw by origin + key + path-id.
//! - `lr_adj_rib_in_len` / `lr_adj_rib_in_is_empty`.
//!
//! - `lr_adj_rib_out_new` / `lr_adj_rib_out_free` — Adj-RIB-Out lifecycle.
//! - `lr_adj_rib_out_advertise` — advertise a route to a destination.
//! - `lr_adj_rib_out_suppress` — withdraw a route from a destination.
//! - `lr_adj_rib_out_len` / `lr_adj_rib_out_is_empty`.
//!
//! - `lr_rib_mux_new` / `lr_rib_mux_free` — cross-protocol mux lifecycle.
//! - `lr_rib_mux_install` / `lr_rib_mux_uninstall` / `lr_rib_mux_get` /
//!   `lr_rib_mux_len` / `lr_rib_mux_is_empty`.
//!
//! - `lr_route_selector_select` / `lr_route_selector_select_bgp` —
//!   apply the BIRD/FRR best-path selector to a flat array of route
//!   handles; returns the index of the winner, or -1 if no route.
//!
//! Every entry point runs inside the crate's `catch_unwind` barrier
//! ([`crate::guarded`]): a panic returns `LR_ERR_PANIC` and sets the
//! thread-local last-error string.

#![allow(unused_unsafe)]

use lr_core::addr::Prefix;
use lr_core::nlri::NlriFamily;
use lr_core::rib::{Route, RouteKey, RouteOrigin};
use lr_rib::{AdjRibIn, AdjRibOut, LocRib, RibMux, RouteSelector};

use crate::error::{set_last_error, LrError, LR_ERR_PANIC};
use crate::guarded;
use crate::handle::{lr_route_t, OpaqueRoute};
use crate::policy::lr_prefix_t;

const LR_ERR_NULL: i32 = LrError::Null as i32;
#[allow(dead_code)]
const LR_ERR_INVALID_HANDLE: i32 = LrError::InvalidHandle as i32;
const LR_ERR_OTHER: i32 = LrError::Other as i32;

// ---- Opaque handle types ----

#[repr(C)]
pub struct OpaqueLocRib {
    _private: [u8; 0],
}
pub type lr_loc_rib_t = *mut OpaqueLocRib;

#[repr(C)]
pub struct OpaqueAdjRibIn {
    _private: [u8; 0],
}
pub type lr_adj_rib_in_t = *mut OpaqueAdjRibIn;

#[repr(C)]
pub struct OpaqueAdjRibOut {
    _private: [u8; 0],
}
pub type lr_adj_rib_out_t = *mut OpaqueAdjRibOut;

#[repr(C)]
pub struct OpaqueRibMux {
    _private: [u8; 0],
}
pub type lr_rib_mux_t = *mut OpaqueRibMux;

// ---- Box / unbox helpers ----

fn box_loc_rib(r: LocRib) -> lr_loc_rib_t {
    Box::into_raw(Box::new(r)) as lr_loc_rib_t
}
unsafe fn unbox_loc_rib(r: lr_loc_rib_t) -> Option<Box<LocRib>> {
    if r.is_null() {
        return None;
    }
    Some(unsafe { Box::from_raw(r as *mut LocRib) })
}
unsafe fn borrow_loc_rib(r: lr_loc_rib_t) -> Option<&'static LocRib> {
    if r.is_null() {
        return None;
    }
    Some(unsafe { &*(r as *const LocRib) })
}
unsafe fn borrow_loc_rib_mut(r: lr_loc_rib_t) -> Option<&'static mut LocRib> {
    if r.is_null() {
        return None;
    }
    Some(unsafe { &mut *(r as *mut LocRib) })
}

fn box_adj_rib_in(r: AdjRibIn) -> lr_adj_rib_in_t {
    Box::into_raw(Box::new(r)) as lr_adj_rib_in_t
}
unsafe fn borrow_adj_rib_in_mut(r: lr_adj_rib_in_t) -> Option<&'static mut AdjRibIn> {
    if r.is_null() {
        return None;
    }
    Some(unsafe { &mut *(r as *mut AdjRibIn) })
}
pub(crate) unsafe fn borrow_adj_rib_in_mut_pub(
    r: lr_adj_rib_in_t,
) -> Option<&'static mut AdjRibIn> {
    if r.is_null() {
        return None;
    }
    Some(unsafe { &mut *(r as *mut AdjRibIn) })
}
unsafe fn borrow_adj_rib_in(r: lr_adj_rib_in_t) -> Option<&'static AdjRibIn> {
    if r.is_null() {
        return None;
    }
    Some(unsafe { &*(r as *const AdjRibIn) })
}
pub(crate) unsafe fn borrow_adj_rib_in_pub(r: lr_adj_rib_in_t) -> Option<&'static AdjRibIn> {
    if r.is_null() {
        return None;
    }
    Some(unsafe { &*(r as *const AdjRibIn) })
}
unsafe fn unbox_adj_rib_in(r: lr_adj_rib_in_t) -> Option<Box<AdjRibIn>> {
    if r.is_null() {
        return None;
    }
    Some(unsafe { Box::from_raw(r as *mut AdjRibIn) })
}

fn box_adj_rib_out(r: AdjRibOut) -> lr_adj_rib_out_t {
    Box::into_raw(Box::new(r)) as lr_adj_rib_out_t
}
unsafe fn borrow_adj_rib_out_mut(r: lr_adj_rib_out_t) -> Option<&'static mut AdjRibOut> {
    if r.is_null() {
        return None;
    }
    Some(unsafe { &mut *(r as *mut AdjRibOut) })
}
pub(crate) unsafe fn borrow_adj_rib_out_mut_pub(
    r: lr_adj_rib_out_t,
) -> Option<&'static mut AdjRibOut> {
    if r.is_null() {
        return None;
    }
    Some(unsafe { &mut *(r as *mut AdjRibOut) })
}
unsafe fn borrow_adj_rib_out(r: lr_adj_rib_out_t) -> Option<&'static AdjRibOut> {
    if r.is_null() {
        return None;
    }
    Some(unsafe { &*(r as *const AdjRibOut) })
}
pub(crate) unsafe fn borrow_adj_rib_out_pub(r: lr_adj_rib_out_t) -> Option<&'static AdjRibOut> {
    if r.is_null() {
        return None;
    }
    Some(unsafe { &*(r as *const AdjRibOut) })
}
unsafe fn unbox_adj_rib_out(r: lr_adj_rib_out_t) -> Option<Box<AdjRibOut>> {
    if r.is_null() {
        return None;
    }
    Some(unsafe { Box::from_raw(r as *mut AdjRibOut) })
}

fn box_rib_mux(r: RibMux) -> lr_rib_mux_t {
    Box::into_raw(Box::new(r)) as lr_rib_mux_t
}
unsafe fn borrow_rib_mux_mut(r: lr_rib_mux_t) -> Option<&'static mut RibMux> {
    if r.is_null() {
        return None;
    }
    Some(unsafe { &mut *(r as *mut RibMux) })
}
unsafe fn borrow_rib_mux(r: lr_rib_mux_t) -> Option<&'static RibMux> {
    if r.is_null() {
        return None;
    }
    Some(unsafe { &*(r as *const RibMux) })
}
unsafe fn unbox_rib_mux(r: lr_rib_mux_t) -> Option<Box<RibMux>> {
    if r.is_null() {
        return None;
    }
    Some(unsafe { Box::from_raw(r as *mut RibMux) })
}

// ---- RouteKey + RouteOrigin helpers (mirror lr_prefix_t) ----

/// Build a `RouteKey` from a C-side `lr_prefix_t` plus protocol id.
/// `source` may be NULL when the route has no source prefix.
fn route_key_from_c(
    prefix: &lr_prefix_t,
    afi: u16,
    safi: u8,
    source: Option<&lr_prefix_t>,
) -> Option<RouteKey> {
    let p = prefix_to_rust(prefix)?;
    let family = NlriFamily { afi, safi };
    match source {
        None => Some(RouteKey::new(p, family)),
        Some(s) => {
            let src = prefix_to_rust(s)?;
            Some(RouteKey::with_source(p, family, src))
        }
    }
}

fn prefix_to_rust(p: &lr_prefix_t) -> Option<Prefix> {
    if p.is_ipv6 == 0 {
        if p.prefix_len > 32 {
            return None;
        }
        Some(Prefix::new_v4(
            [p.addr[0], p.addr[1], p.addr[2], p.addr[3]],
            p.prefix_len,
        ))
    } else {
        if p.prefix_len > 128 {
            return None;
        }
        Some(Prefix::new_v6(p.addr, p.prefix_len))
    }
}

/// Take ownership of a `lr_route_t` (the route is *moved* into the
/// Loc-RIB / Adj-RIB). Returns `None` on a NULL handle.
unsafe fn take_route(r: lr_route_t) -> Option<Route> {
    if r.is_null() {
        return None;
    }
    let boxed: Box<Route> = unsafe { Box::from_raw(r as *mut Route) };
    Some(*boxed)
}

/// Clone a `lr_route_t` so the caller keeps ownership. The returned
/// handle is owned by the caller and must be freed via `lr_route_free`.
fn clone_route_handle(r: &Route) -> lr_route_t {
    Box::into_raw(Box::new(r.clone())) as lr_route_t
}

// ---- Loc-RIB surface ----

/// Construct an empty Loc-RIB (RFC 4271 §9).
#[no_mangle]
pub extern "C" fn lr_loc_rib_new() -> lr_loc_rib_t {
    guarded(|| box_loc_rib(LocRib::new()), std::ptr::null_mut())
}

/// Drop a boxed Loc-RIB. Safe to call with NULL.
///
/// # Safety
/// `r` must have been produced by `lr_loc_rib_new` and not already
/// freed. Double-free is undefined behaviour.
#[no_mangle]
pub unsafe extern "C" fn lr_loc_rib_free(r: lr_loc_rib_t) {
    guarded(
        || unsafe {
            drop(unbox_loc_rib(r));
        },
        (),
    )
}

/// Install one path into the Loc-RIB (RFC 4271 §9.1, RFC 7911
/// path-id aware). The `route` handle is *consumed* — the caller
/// must not use it after this call.
///
/// Returns 1 when the install actually changed the Loc-RIB (a new
/// path was added or an existing one replaced with non-identical
/// content); 0 for a byte-identical no-op (no generation bump).
/// Negative on error.
///
/// # Safety
/// `r` must be a valid Loc-RIB handle. `route` must be a valid route
/// handle produced by `lr_route_new_v4` / `lr_route_new_v6`.
#[no_mangle]
pub unsafe extern "C" fn lr_loc_rib_install(r: lr_loc_rib_t, route: lr_route_t) -> i32 {
    guarded(
        || unsafe {
            let Some(rib) = borrow_loc_rib_mut(r) else {
                return LR_ERR_NULL;
            };
            let Some(route) = take_route(route) else {
                return LR_ERR_NULL;
            };
            if rib.install(route) {
                1
            } else {
                0
            }
        },
        LR_ERR_PANIC,
    )
}

/// Uninstall a key (RFC 4271 §9.1 withdraw). Returns 1 when a route
/// was withdrawn, 0 when the key was not present.
///
/// # Safety
/// `r` must be a valid Loc-RIB handle. `prefix` must be a readable
/// `lr_prefix_t`.
#[no_mangle]
pub unsafe extern "C" fn lr_loc_rib_uninstall(
    r: lr_loc_rib_t,
    prefix: *const lr_prefix_t,
    afi: u16,
    safi: u8,
    source: *const lr_prefix_t,
) -> i32 {
    guarded(
        || unsafe {
            let Some(rib) = borrow_loc_rib_mut(r) else {
                return LR_ERR_NULL;
            };
            if prefix.is_null() {
                return LR_ERR_NULL;
            }
            let prefix_c = unsafe { &*prefix };
            let source_c = if source.is_null() {
                None
            } else {
                Some(unsafe { &*source })
            };
            let Some(key) = route_key_from_c(prefix_c, afi, safi, source_c) else {
                set_last_error("invalid prefix in lr_loc_rib_uninstall".into());
                return LR_ERR_OTHER;
            };
            if rib.uninstall(&key).is_some() {
                1
            } else {
                0
            }
        },
        LR_ERR_PANIC,
    )
}

/// Number of keys (prefixes) in the Loc-RIB. Returns 0 on a NULL handle.
///
/// # Safety
/// `r` must be a valid Loc-RIB handle.
#[no_mangle]
pub unsafe extern "C" fn lr_loc_rib_len(r: lr_loc_rib_t) -> usize {
    guarded(
        || unsafe { borrow_loc_rib(r).map(|rib| rib.len()).unwrap_or(0) },
        0,
    )
}

/// True when the Loc-RIB holds no keys. Returns 1 (true) on a NULL
/// handle (the safe default for "no routes to advertise").
///
/// # Safety
/// See [`lr_loc_rib_len`].
#[no_mangle]
pub unsafe extern "C" fn lr_loc_rib_is_empty(r: lr_loc_rib_t) -> u8 {
    guarded(
        || unsafe {
            borrow_loc_rib(r)
                .map(|rib| rib.is_empty() as u8)
                .unwrap_or(1)
        },
        1,
    )
}

/// Total number of stored paths (>= `len()` under RFC 7911 Add-Path).
/// Returns 0 on a NULL handle.
///
/// # Safety
/// See [`lr_loc_rib_len`].
#[no_mangle]
pub unsafe extern "C" fn lr_loc_rib_paths_len(r: lr_loc_rib_t) -> usize {
    guarded(
        || unsafe { borrow_loc_rib(r).map(|rib| rib.paths_len()).unwrap_or(0) },
        0,
    )
}

/// Monotonic generation counter — callers can ask "what changed since
/// generation X?". Returns 0 on a NULL handle.
///
/// # Safety
/// See [`lr_loc_rib_len`].
#[no_mangle]
pub unsafe extern "C" fn lr_loc_rib_generation(r: lr_loc_rib_t) -> u64 {
    guarded(
        || unsafe { borrow_loc_rib(r).map(|rib| rib.generation()).unwrap_or(0) },
        0,
    )
}

/// True when a route is present for the given key. Returns 0 on a NULL
/// handle or when the key is absent.
///
/// # Safety
/// `r` must be a valid Loc-RIB handle. `prefix` must be a readable
/// `lr_prefix_t`.
#[no_mangle]
pub unsafe extern "C" fn lr_loc_rib_best_present(
    r: lr_loc_rib_t,
    prefix: *const lr_prefix_t,
    afi: u16,
    safi: u8,
    source: *const lr_prefix_t,
) -> u8 {
    guarded(
        || unsafe {
            let Some(rib) = borrow_loc_rib(r) else {
                return 0;
            };
            if prefix.is_null() {
                return 0;
            }
            let prefix_c = unsafe { &*prefix };
            let source_c = if source.is_null() {
                None
            } else {
                Some(unsafe { &*source })
            };
            let Some(key) = route_key_from_c(prefix_c, afi, safi, source_c) else {
                return 0;
            };
            if rib.best(&key).is_some() {
                1
            } else {
                0
            }
        },
        0,
    )
}

/// Read the best path for a key. Returns 0 on success and writes a
/// NEW `lr_route_t` handle (a *copy* of the Loc-RIB's internal route)
/// to `*out`. The caller owns the copy and must free it via
/// `lr_route_free`. Returns `LR_ERR_NULL` on a NULL Loc-RIB, 0 with
/// `*out = NULL` when the key is absent.
///
/// # Safety
/// `r` must be a valid Loc-RIB handle. `prefix` and `out` must point
/// to writable memory.
#[no_mangle]
pub unsafe extern "C" fn lr_loc_rib_best(
    r: lr_loc_rib_t,
    prefix: *const lr_prefix_t,
    afi: u16,
    safi: u8,
    source: *const lr_prefix_t,
    out: *mut lr_route_t,
) -> i32 {
    guarded(
        || unsafe {
            if out.is_null() {
                return LR_ERR_NULL;
            }
            let Some(rib) = borrow_loc_rib(r) else {
                return LR_ERR_NULL;
            };
            if prefix.is_null() {
                return LR_ERR_NULL;
            }
            let prefix_c = unsafe { &*prefix };
            let source_c = if source.is_null() {
                None
            } else {
                Some(unsafe { &*source })
            };
            let Some(key) = route_key_from_c(prefix_c, afi, safi, source_c) else {
                set_last_error("invalid prefix in lr_loc_rib_best".into());
                return LR_ERR_OTHER;
            };
            match rib.best(&key) {
                None => {
                    unsafe { *out = std::ptr::null_mut() }
                    0
                }
                Some(route) => {
                    unsafe { *out = clone_route_handle(route) }
                    0
                }
            }
        },
        LR_ERR_PANIC,
    )
}

// ---- Adj-RIB-In surface ----

/// Construct an empty Adj-RIB-In (RFC 4271 §9).
#[no_mangle]
pub extern "C" fn lr_adj_rib_in_new() -> lr_adj_rib_in_t {
    guarded(|| box_adj_rib_in(AdjRibIn::new()), std::ptr::null_mut())
}

/// Drop a boxed Adj-RIB-In. Safe to call with NULL.
///
/// # Safety
/// `r` must have been produced by `lr_adj_rib_in_new` and not already
/// freed.
#[no_mangle]
pub unsafe extern "C" fn lr_adj_rib_in_free(r: lr_adj_rib_in_t) {
    guarded(
        || unsafe {
            drop(unbox_adj_rib_in(r));
        },
        (),
    )
}

/// Install one pre-policy route from `origin`. The `route` handle is
/// *consumed* — the caller must not use it after this call.
///
/// `origin_peer` is the peer's session handle (the `RouteOrigin::peer`
/// field); `origin_proto` is the `RouteOrigin::proto` field (one of
/// the `LR_PROTO_*` constants).
///
/// # Safety
/// `r` must be a valid Adj-RIB-In handle. `route` must be a valid route
/// handle.
#[no_mangle]
pub unsafe extern "C" fn lr_adj_rib_in_feed(
    r: lr_adj_rib_in_t,
    origin_peer: u64,
    origin_proto: i32,
    route: lr_route_t,
) -> i32 {
    guarded(
        || unsafe {
            let Some(rib) = borrow_adj_rib_in_mut(r) else {
                return LR_ERR_NULL;
            };
            let Some(route) = take_route(route) else {
                return LR_ERR_NULL;
            };
            // Map the C-side proto id to the Rust Protocol enum by
            // reusing LrProtocol::from_i32 from policy.rs. Treat
            // unknown ids as Protocol::Other(0).
            let proto_u32 = match crate::policy::LrProtocol::from_i32(origin_proto) {
                Some(p) => p.to_proto_u32(),
                None => 0,
            };
            let origin = RouteOrigin {
                peer: origin_peer,
                proto: proto_u32,
            };
            rib.feed_pre_policy(origin, route);
            0
        },
        LR_ERR_PANIC,
    )
}

/// Withdraw one (origin, key, path-id) tuple. Returns 1 when a route
/// was withdrawn, 0 when no matching entry existed.
///
/// # Safety
/// `r` must be a valid Adj-RIB-In handle. `prefix` must be readable.
#[no_mangle]
pub unsafe extern "C" fn lr_adj_rib_in_withdraw(
    r: lr_adj_rib_in_t,
    origin_peer: u64,
    origin_proto: i32,
    prefix: *const lr_prefix_t,
    afi: u16,
    safi: u8,
    source: *const lr_prefix_t,
    path_id: u32,
) -> i32 {
    guarded(
        || unsafe {
            let Some(rib) = borrow_adj_rib_in_mut(r) else {
                return LR_ERR_NULL;
            };
            if prefix.is_null() {
                return LR_ERR_NULL;
            }
            let prefix_c = unsafe { &*prefix };
            let source_c = if source.is_null() {
                None
            } else {
                Some(unsafe { &*source })
            };
            let Some(key) = route_key_from_c(prefix_c, afi, safi, source_c) else {
                set_last_error("invalid prefix in lr_adj_rib_in_withdraw".into());
                return LR_ERR_OTHER;
            };
            let proto_u32 = match crate::policy::LrProtocol::from_i32(origin_proto) {
                Some(p) => p.to_proto_u32(),
                None => 0,
            };
            let origin = RouteOrigin {
                peer: origin_peer,
                proto: proto_u32,
            };
            if rib.withdraw(origin, &key, path_id).is_some() {
                1
            } else {
                0
            }
        },
        LR_ERR_PANIC,
    )
}

/// Total number of stored routes. Returns 0 on a NULL handle.
///
/// # Safety
/// `r` must be a valid Adj-RIB-In handle.
#[no_mangle]
pub unsafe extern "C" fn lr_adj_rib_in_len(r: lr_adj_rib_in_t) -> usize {
    guarded(
        || unsafe { borrow_adj_rib_in(r).map(|rib| rib.len()).unwrap_or(0) },
        0,
    )
}

/// True when the Adj-RIB-In holds no routes. Returns 1 on a NULL handle.
///
/// # Safety
/// See [`lr_adj_rib_in_len`].
#[no_mangle]
pub unsafe extern "C" fn lr_adj_rib_in_is_empty(r: lr_adj_rib_in_t) -> u8 {
    guarded(
        || unsafe {
            borrow_adj_rib_in(r)
                .map(|rib| rib.is_empty() as u8)
                .unwrap_or(1)
        },
        1,
    )
}

// ---- Adj-RIB-Out surface ----

/// Construct an empty Adj-RIB-Out (RFC 4271 §9).
#[no_mangle]
pub extern "C" fn lr_adj_rib_out_new() -> lr_adj_rib_out_t {
    guarded(|| box_adj_rib_out(AdjRibOut::new()), std::ptr::null_mut())
}

/// Drop a boxed Adj-RIB-Out. Safe to call with NULL.
///
/// # Safety
/// `r` must have been produced by `lr_adj_rib_out_new` and not already
/// freed.
#[no_mangle]
pub unsafe extern "C" fn lr_adj_rib_out_free(r: lr_adj_rib_out_t) {
    guarded(
        || unsafe {
            drop(unbox_adj_rib_out(r));
        },
        (),
    )
}

/// Advertise one route to a destination. The `route` handle is *not*
/// consumed (the Adj-RIB-Out stores a clone). `tx_path_id` is the
/// RFC 7911 path identifier sent on the wire.
///
/// # Safety
/// `r` must be a valid Adj-RIB-Out handle. `route` must be a valid
/// route handle.
#[no_mangle]
pub unsafe extern "C" fn lr_adj_rib_out_advertise(
    r: lr_adj_rib_out_t,
    dest_peer: u64,
    dest_proto: i32,
    route: lr_route_t,
    tx_path_id: u32,
) -> i32 {
    guarded(
        || unsafe {
            let Some(rib) = borrow_adj_rib_out_mut(r) else {
                return LR_ERR_NULL;
            };
            if route.is_null() {
                return LR_ERR_NULL;
            }
            let route_ref: &Route = unsafe { &*(route as *const Route) };
            let proto_u32 = match crate::policy::LrProtocol::from_i32(dest_proto) {
                Some(p) => p.to_proto_u32(),
                None => 0,
            };
            let dest = RouteOrigin {
                peer: dest_peer,
                proto: proto_u32,
            };
            rib.advertise(dest, route_ref, tx_path_id);
            0
        },
        LR_ERR_PANIC,
    )
}

/// Suppress (withdraw) one (dest, key, path-id) tuple. Returns 1 when
/// a route was suppressed, 0 when no matching entry existed.
///
/// # Safety
/// `r` must be a valid Adj-RIB-Out handle. `prefix` must be readable.
#[no_mangle]
pub unsafe extern "C" fn lr_adj_rib_out_suppress(
    r: lr_adj_rib_out_t,
    dest_peer: u64,
    dest_proto: i32,
    prefix: *const lr_prefix_t,
    afi: u16,
    safi: u8,
    source: *const lr_prefix_t,
    tx_path_id: u32,
) -> i32 {
    guarded(
        || unsafe {
            let Some(rib) = borrow_adj_rib_out_mut(r) else {
                return LR_ERR_NULL;
            };
            if prefix.is_null() {
                return LR_ERR_NULL;
            }
            let prefix_c = unsafe { &*prefix };
            let source_c = if source.is_null() {
                None
            } else {
                Some(unsafe { &*source })
            };
            let Some(key) = route_key_from_c(prefix_c, afi, safi, source_c) else {
                set_last_error("invalid prefix in lr_adj_rib_out_suppress".into());
                return LR_ERR_OTHER;
            };
            let proto_u32 = match crate::policy::LrProtocol::from_i32(dest_proto) {
                Some(p) => p.to_proto_u32(),
                None => 0,
            };
            let dest = RouteOrigin {
                peer: dest_peer,
                proto: proto_u32,
            };
            rib.suppress(dest, &key, tx_path_id);
            0
        },
        LR_ERR_PANIC,
    )
}

/// Total number of stored routes. Returns 0 on a NULL handle.
///
/// # Safety
/// `r` must be a valid Adj-RIB-Out handle.
#[no_mangle]
pub unsafe extern "C" fn lr_adj_rib_out_len(r: lr_adj_rib_out_t) -> usize {
    guarded(
        || unsafe { borrow_adj_rib_out(r).map(|rib| rib.len()).unwrap_or(0) },
        0,
    )
}

/// True when the Adj-RIB-Out holds no routes. Returns 1 on a NULL handle.
///
/// # Safety
/// See [`lr_adj_rib_out_len`].
#[no_mangle]
pub unsafe extern "C" fn lr_adj_rib_out_is_empty(r: lr_adj_rib_out_t) -> u8 {
    guarded(
        || unsafe {
            borrow_adj_rib_out(r)
                .map(|rib| rib.is_empty() as u8)
                .unwrap_or(1)
        },
        1,
    )
}

// ---- RibMux surface (cross-protocol merge by admin distance) ----

/// Construct an empty RibMux — cross-protocol mux (RFC 4271 §9 + the
/// admin-distance model the daemon uses to merge BGP / OSPF / Babel
/// routes into one FIB).
#[no_mangle]
pub extern "C" fn lr_rib_mux_new() -> lr_rib_mux_t {
    guarded(|| box_rib_mux(RibMux::new()), std::ptr::null_mut())
}

/// Drop a boxed RibMux. Safe to call with NULL.
///
/// # Safety
/// `r` must have been produced by `lr_rib_mux_new` and not already freed.
#[no_mangle]
pub unsafe extern "C" fn lr_rib_mux_free(r: lr_rib_mux_t) {
    guarded(
        || unsafe {
            drop(unbox_rib_mux(r));
        },
        (),
    )
}

/// Install one route into the mux. The `route` handle is *consumed*.
///
/// # Safety
/// `r` must be a valid RibMux handle. `route` must be a valid route handle.
#[no_mangle]
pub unsafe extern "C" fn lr_rib_mux_install(r: lr_rib_mux_t, route: lr_route_t) -> i32 {
    guarded(
        || unsafe {
            let Some(mux) = borrow_rib_mux_mut(r) else {
                return LR_ERR_NULL;
            };
            let Some(route) = take_route(route) else {
                return LR_ERR_NULL;
            };
            mux.install(route);
            0
        },
        LR_ERR_PANIC,
    )
}

/// Uninstall a key. Returns 1 when a route was withdrawn, 0 when the
/// key was not present.
///
/// # Safety
/// `r` must be a valid RibMux handle. `prefix` must be readable.
#[no_mangle]
pub unsafe extern "C" fn lr_rib_mux_uninstall(
    r: lr_rib_mux_t,
    prefix: *const lr_prefix_t,
    afi: u16,
    safi: u8,
    source: *const lr_prefix_t,
) -> i32 {
    guarded(
        || unsafe {
            let Some(mux) = borrow_rib_mux_mut(r) else {
                return LR_ERR_NULL;
            };
            if prefix.is_null() {
                return LR_ERR_NULL;
            }
            let prefix_c = unsafe { &*prefix };
            let source_c = if source.is_null() {
                None
            } else {
                Some(unsafe { &*source })
            };
            let Some(key) = route_key_from_c(prefix_c, afi, safi, source_c) else {
                set_last_error("invalid prefix in lr_rib_mux_uninstall".into());
                return LR_ERR_OTHER;
            };
            if mux.uninstall(&key).is_some() {
                1
            } else {
                0
            }
        },
        LR_ERR_PANIC,
    )
}

/// Read the merged route for a key. Returns 0 on success and writes a
/// NEW `lr_route_t` handle (a *copy*) to `*out`. `LR_ERR_NULL` on a
/// NULL mux; 0 with `*out = NULL` when the key is absent.
///
/// # Safety
/// `r` must be a valid RibMux handle. `prefix` and `out` must be readable.
#[no_mangle]
pub unsafe extern "C" fn lr_rib_mux_get(
    r: lr_rib_mux_t,
    prefix: *const lr_prefix_t,
    afi: u16,
    safi: u8,
    source: *const lr_prefix_t,
    out: *mut lr_route_t,
) -> i32 {
    guarded(
        || unsafe {
            if out.is_null() {
                return LR_ERR_NULL;
            }
            let Some(mux) = borrow_rib_mux(r) else {
                return LR_ERR_NULL;
            };
            if prefix.is_null() {
                return LR_ERR_NULL;
            }
            let prefix_c = unsafe { &*prefix };
            let source_c = if source.is_null() {
                None
            } else {
                Some(unsafe { &*source })
            };
            let Some(key) = route_key_from_c(prefix_c, afi, safi, source_c) else {
                set_last_error("invalid prefix in lr_rib_mux_get".into());
                return LR_ERR_OTHER;
            };
            match mux.get(&key) {
                None => {
                    unsafe { *out = std::ptr::null_mut() }
                    0
                }
                Some(route) => {
                    unsafe { *out = clone_route_handle(route) }
                    0
                }
            }
        },
        LR_ERR_PANIC,
    )
}

/// Number of merged routes. Returns 0 on a NULL handle.
///
/// # Safety
/// `r` must be a valid RibMux handle.
#[no_mangle]
pub unsafe extern "C" fn lr_rib_mux_len(r: lr_rib_mux_t) -> usize {
    guarded(
        || unsafe { borrow_rib_mux(r).map(|mux| mux.len()).unwrap_or(0) },
        0,
    )
}

/// True when the mux holds no routes. Returns 1 on a NULL handle.
///
/// # Safety
/// See [`lr_rib_mux_len`].
#[no_mangle]
pub unsafe extern "C" fn lr_rib_mux_is_empty(r: lr_rib_mux_t) -> u8 {
    guarded(
        || unsafe {
            borrow_rib_mux(r)
                .map(|mux| mux.is_empty() as u8)
                .unwrap_or(1)
        },
        1,
    )
}

// ---- RouteSelector ----

/// Apply the BIRD/FRR best-path selector to a flat array of route
/// handles. Returns the index of the winning route (>= 0), or -1 when
/// `count == 0` or every handle is NULL. The handles are *not*
/// consumed — the caller keeps ownership.
///
/// # Safety
/// `routes` must point to `count` readable `lr_route_t` values.
#[no_mangle]
pub unsafe extern "C" fn lr_route_selector_select(routes: *const lr_route_t, count: usize) -> i64 {
    guarded(
        || unsafe {
            if routes.is_null() || count == 0 {
                return -1;
            }
            let slice = unsafe { std::slice::from_raw_parts(routes, count) };
            // Build a Vec<Route> by cloning the routes the handles
            // point at. RouteSelector::select takes &[Route], not
            // &[&Route] — cloning is the simplest correct shape.
            let mut cloned: Vec<Route> = Vec::with_capacity(count);
            let mut index_map: Vec<usize> = Vec::with_capacity(count);
            for (i, &h) in slice.iter().enumerate() {
                if h.is_null() {
                    continue;
                }
                let r: &Route = unsafe { &*(h as *const Route) };
                cloned.push(r.clone());
                index_map.push(i);
            }
            if cloned.is_empty() {
                return -1;
            }
            let Some(winner) = RouteSelector::select(&cloned) else {
                return -1;
            };
            // Find which original index the winner came from. Compare by
            // pointer-equivalent identity: the winner is a reference into
            // `cloned`, so find the index in `cloned` and map back.
            let winner_ptr = winner as *const Route;
            for (rank, r) in cloned.iter().enumerate() {
                if std::ptr::eq(r as *const Route, winner_ptr) {
                    return index_map[rank] as i64;
                }
            }
            -1
        },
        -1,
    )
}

/// Apply the BGP-specific best-path selector (RFC 4271 §9.1). Same
/// contract as [`lr_route_selector_select`].
///
/// # Safety
/// See [`lr_route_selector_select`].
#[no_mangle]
pub unsafe extern "C" fn lr_route_selector_select_bgp(
    routes: *const lr_route_t,
    count: usize,
) -> i64 {
    guarded(
        || unsafe {
            if routes.is_null() || count == 0 {
                return -1;
            }
            let slice = unsafe { std::slice::from_raw_parts(routes, count) };
            let mut cloned: Vec<Route> = Vec::with_capacity(count);
            let mut index_map: Vec<usize> = Vec::with_capacity(count);
            for (i, &h) in slice.iter().enumerate() {
                if h.is_null() {
                    continue;
                }
                let r: &Route = unsafe { &*(h as *const Route) };
                cloned.push(r.clone());
                index_map.push(i);
            }
            if cloned.is_empty() {
                return -1;
            }
            let Some(winner) = RouteSelector::select_bgp(&cloned) else {
                return -1;
            };
            let winner_ptr = winner as *const Route;
            for (rank, r) in cloned.iter().enumerate() {
                if std::ptr::eq(r as *const Route, winner_ptr) {
                    return index_map[rank] as i64;
                }
            }
            -1
        },
        -1,
    )
}

// ---- LocRib: install_set / paths / iter_best / diff_since (issue #92) ----
//
// The remaining LocRib pub API: install_set (RFC 7911 multi-path
// install), paths (read the multipath set for a key), iter_best
// (walk every best route), and diff_since (the generation-based
// delta the daemon uses to drive the BMP mirror / API socket
// thread / redistribution pipe).

/// Install a ranked set of paths for a key (RFC 7911 — Add-Path
/// keeps more than one path per prefix; the first element is the
/// best path the non-Add-Path consumers see). The `routes` array
/// carries `count` route handles; ownership is **transferred** —
/// each handle is consumed and freed by this call (the LocRib
/// clones the underlying `Route` value).
///
/// Returns 0 on success, `LR_ERR_NULL` (-1) on a NULL LocRib / NULL
/// routes / NULL key, `LR_ERR_OTHER` (-6) on a malformed key.
///
/// # Safety
/// `r` must be a valid LocRib handle. `routes` (when `count > 0`)
/// must point to `count` valid `lr_route_t` handles. `key` must
/// point to a readable `lr_route_key_t`.
#[no_mangle]
pub unsafe extern "C" fn lr_loc_rib_install_set(
    r: lr_loc_rib_t,
    key: *const lr_route_key_t,
    routes: *const lr_route_t,
    count: usize,
) -> i32 {
    guarded(
        || unsafe {
            let Some(rib) = borrow_loc_rib_mut(r) else {
                return LR_ERR_NULL;
            };
            if key.is_null() {
                return LR_ERR_NULL;
            }
            if count == 0 {
                return LR_ERR_NULL;
            }
            if routes.is_null() {
                return LR_ERR_NULL;
            }
            let key_c: lr_route_key_t = unsafe { *key };
            let Some(key) = key_c.to_key() else {
                set_last_error("malformed route key".to_string());
                return LrError::Other as i32;
            };
            let mut ranked: Vec<Route> = Vec::with_capacity(count);
            for i in 0..count {
                let h = unsafe { *routes.add(i) };
                if h.is_null() {
                    return LR_ERR_NULL;
                }
                let route: &'static Route = unsafe { &*(h as *const Route) };
                ranked.push(route.clone());
            }
            rib.install_set(&key, ranked);
            0
        },
        LR_ERR_PANIC,
    )
}

/// Number of paths stored for a key (RFC 7911 — Add-Path keeps more
/// than one). Returns 0 on a NULL handle or an unknown key.
///
/// # Safety
/// `r` must be a valid LocRib handle. `key` must point to a
/// readable `lr_route_key_t`.
#[no_mangle]
pub unsafe extern "C" fn lr_loc_rib_paths(r: lr_loc_rib_t, key: *const lr_route_key_t) -> usize {
    guarded(
        || unsafe {
            let Some(rib) = borrow_loc_rib(r) else {
                return 0;
            };
            if key.is_null() {
                return 0;
            }
            let key_c: lr_route_key_t = unsafe { *key };
            let Some(key) = key_c.to_key() else {
                return 0;
            };
            rib.paths(&key).len()
        },
        0,
    )
}

/// One route-key projection — (prefix, family_afi, family_safi) +
/// optional source prefix. Used by `lr_loc_rib_iter_best` /
/// `lr_loc_rib_install_set` so the C side can pass / receive keys
/// without going through a separate handle type.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct lr_route_key_t {
    /// Network address octets (first 4 for IPv4, all 16 for IPv6).
    pub addr: [u8; 16],
    /// 0 = IPv4 (first 4 bytes of `addr`), 1 = IPv6 (all 16 bytes).
    pub is_ipv6: u8,
    /// Prefix length (0..=32 for IPv4, 0..=128 for IPv6).
    pub prefix_len: u8,
    /// Address-family identifier (1 = IPv4, 2 = IPv6, etc.).
    pub family_afi: u16,
    /// Subsequent address-family identifier (1 = unicast, etc.).
    pub family_safi: u8,
    /// 1 when `source_addr` / `source_prefix_len` carry a source
    /// prefix (RFC 8277 / flow-spec), 0 otherwise.
    pub has_source: u8,
    /// Source-prefix address octets (zero-padded to 16).
    pub source_addr: [u8; 16],
    /// 0 = IPv4 source, 1 = IPv6 source.
    pub source_is_ipv6: u8,
    /// Source-prefix length.
    pub source_prefix_len: u8,
}

impl lr_route_key_t {
    fn to_key(self) -> Option<lr_core::rib::RouteKey> {
        let addr = if self.is_ipv6 == 0 {
            lr_core::addr::IpAddr::V4([self.addr[0], self.addr[1], self.addr[2], self.addr[3]])
        } else {
            lr_core::addr::IpAddr::V6(self.addr)
        };
        let prefix = if self.is_ipv6 == 0 {
            if self.prefix_len > 32 {
                return None;
            }
            lr_core::addr::Prefix::new_v4(
                [self.addr[0], self.addr[1], self.addr[2], self.addr[3]],
                self.prefix_len,
            )
        } else {
            if self.prefix_len > 128 {
                return None;
            }
            lr_core::addr::Prefix::new_v6(self.addr, self.prefix_len)
        };
        let family = lr_core::nlri::NlriFamily {
            afi: self.family_afi,
            safi: self.family_safi,
        };
        if self.has_source == 0 {
            Some(lr_core::rib::RouteKey::new(prefix, family))
        } else {
            let src_addr = if self.source_is_ipv6 == 0 {
                lr_core::addr::IpAddr::V4([
                    self.source_addr[0],
                    self.source_addr[1],
                    self.source_addr[2],
                    self.source_addr[3],
                ])
            } else {
                lr_core::addr::IpAddr::V6(self.source_addr)
            };
            let src_prefix = if self.source_is_ipv6 == 0 {
                if self.source_prefix_len > 32 {
                    return None;
                }
                lr_core::addr::Prefix::new_v4(
                    [
                        self.source_addr[0],
                        self.source_addr[1],
                        self.source_addr[2],
                        self.source_addr[3],
                    ],
                    self.source_prefix_len,
                )
            } else {
                if self.source_prefix_len > 128 {
                    return None;
                }
                lr_core::addr::Prefix::new_v6(self.source_addr, self.source_prefix_len)
            };
            let _ = (addr, src_addr);
            Some(lr_core::rib::RouteKey::with_source(
                prefix, family, src_prefix,
            ))
        }
    }
}

/// Walk every best route in the Loc-RIB. The caller provides a
/// callback that receives one route handle per iteration (the
/// handle is borrowed — the caller must NOT free it). Returns the
/// number of routes visited, or `LR_ERR_NULL` (-1) on a NULL LocRib
/// / NULL callback.
///
/// The callback signature is `void (*)(lr_route_t route, void
/// *user)`. The `user` pointer is passed through unchanged.
///
/// # Safety
/// `r` must be a valid LocRib handle. `cb` must be a non-NULL
/// function pointer that does not free `route` and does not call
/// back into the FFI on the same LocRib handle (re-entrancy is
/// undefined — the LocRib borrow is held for the duration of the
/// walk).
#[no_mangle]
pub unsafe extern "C" fn lr_loc_rib_iter_best(
    r: lr_loc_rib_t,
    cb: Option<unsafe extern "C" fn(route: lr_route_t, user: *mut core::ffi::c_void)>,
    user: *mut core::ffi::c_void,
) -> i64 {
    guarded(
        || unsafe {
            let Some(rib) = borrow_loc_rib(r) else {
                return -1;
            };
            let Some(cb_fn) = cb else {
                return -1;
            };
            let mut count: i64 = 0;
            for route in rib.iter_best() {
                // SAFETY: the caller's cb must not free the handle.
                let h: lr_route_t = route as *const lr_core::rib::Route as *mut OpaqueRoute;
                unsafe { cb_fn(h, user) };
                count += 1;
            }
            count
        },
        -1,
    )
}

/// Compute the diff between the Loc-RIB's current state and its
/// state at generation `since_gen` (RFC 8277 §3 / BMP §3 — the
/// generation-based delta the daemon uses to drive the BMP mirror,
/// the API socket thread and the redistribution pipe). Writes the
/// added / modified / removed counts to `*out_added` /
/// `*out_modified` / `*out_removed` and returns 0 on success,
/// `LR_ERR_NULL` on a NULL handle / NULL out-pointer.
///
/// The diff is computed against the LocRib's history ring (16
/// entries deep); for older diffs the function returns 0 in all
/// three out-fields (no changes since the requested generation).
///
/// # Safety
/// `r` must be a valid LocRib handle. All three out-pointers must
/// point to writable `uintptr_t`.
#[no_mangle]
pub unsafe extern "C" fn lr_loc_rib_diff_since(
    r: lr_loc_rib_t,
    since_gen: u64,
    out_added: *mut usize,
    out_modified: *mut usize,
    out_removed: *mut usize,
) -> i32 {
    guarded(
        || unsafe {
            let Some(rib) = borrow_loc_rib(r) else {
                return -1;
            };
            if out_added.is_null() || out_modified.is_null() || out_removed.is_null() {
                return -1;
            }
            let diff = rib.diff_since(since_gen);
            unsafe {
                *out_added = diff.added.len();
                *out_modified = diff.modified.len();
                *out_removed = diff.removed.len();
            }
            0
        },
        LR_ERR_PANIC,
    )
}

/// Walk every path (every multipath entry, not just the best) in the
/// Loc-RIB. The caller provides a callback that receives one route
/// handle per iteration (the handle is borrowed — the caller must NOT
/// free it). Returns the number of routes visited, or `LR_ERR_NULL`
/// (-1) on a NULL LocRib / NULL callback.
///
/// Use [`lr_loc_rib_iter_best`] when only the best path per prefix is
/// needed; use [`lr_loc_rib_iter_paths`] when multipath entries must
/// be enumerated (RFC 4271 §9.1.2.2 step 12).
///
/// # Safety
/// `r` must be a valid LocRib handle. `cb` must be a non-NULL function
/// pointer that does not free `route` and does not call back into the
/// FFI on the same LocRib handle (re-entrancy is undefined).
#[no_mangle]
pub unsafe extern "C" fn lr_loc_rib_iter_paths(
    r: lr_loc_rib_t,
    cb: Option<unsafe extern "C" fn(route: lr_route_t, user: *mut core::ffi::c_void)>,
    user: *mut core::ffi::c_void,
) -> i64 {
    guarded(
        || unsafe {
            let Some(rib) = borrow_loc_rib(r) else {
                return -1;
            };
            let Some(cb_fn) = cb else {
                return -1;
            };
            let mut count: i64 = 0;
            for route in rib.iter_paths() {
                let h: lr_route_t = route as *const Route as *mut OpaqueRoute;
                unsafe { cb_fn(h, user) };
                count += 1;
            }
            count
        },
        -1,
    )
}

/// Walk every `(RouteKey, paths)` set in the Loc-RIB. The caller
/// provides a callback that receives the prefix (as a flat
/// `(is_ipv6 u8, prefix_len u8, addr 16 bytes)` tuple via the
/// `prefix_out` pointer) plus the number of paths in that set. Returns
/// the number of sets visited, or `LR_ERR_NULL` (-1) on a NULL LocRib
/// / NULL callback / NULL prefix_out.
///
/// # Safety
/// `r` must be a valid LocRib handle. `cb` must be a non-NULL function
/// pointer. `prefix_out` must point to at least 18 writable bytes per
/// call (the FFI writes the first 4 for IPv4, all 16 for IPv6).
#[no_mangle]
pub unsafe extern "C" fn lr_loc_rib_iter_sets(
    r: lr_loc_rib_t,
    cb: Option<
        unsafe extern "C" fn(
            prefix_out: *mut u8,
            prefix_len: u8,
            is_ipv6: u8,
            path_count: usize,
            user: *mut core::ffi::c_void,
        ),
    >,
    user: *mut core::ffi::c_void,
) -> i64 {
    guarded(
        || unsafe {
            let Some(rib) = borrow_loc_rib(r) else {
                return -1;
            };
            let Some(cb_fn) = cb else {
                return -1;
            };
            let mut count: i64 = 0;
            for (key, paths) in rib.iter_sets() {
                let (is_ipv6, mut addr_buf) = match key.prefix.addr {
                    lr_core::addr::IpAddr::V4(b) => {
                        let mut buf = [0u8; 16];
                        buf[..4].copy_from_slice(&b);
                        (0u8, buf)
                    }
                    lr_core::addr::IpAddr::V6(b) => (1u8, b),
                };
                unsafe {
                    cb_fn(
                        addr_buf.as_mut_ptr(),
                        key.prefix.prefix_len,
                        is_ipv6,
                        paths.len(),
                        user,
                    );
                }
                count += 1;
            }
            count
        },
        -1,
    )
}

/// Walk every route in the Adj-RIB-In, regardless of origin. The
/// caller provides a callback that receives one route handle per
/// iteration (borrowed — do not free). Returns the number of routes
/// visited, or `LR_ERR_NULL` (-1) on a NULL AdjRibIn / NULL callback.
///
/// # Safety
/// `r` must be a valid AdjRibIn handle. `cb` must be a non-NULL
/// function pointer that does not free `route` and does not call back
/// into the FFI on the same AdjRibIn handle.
#[no_mangle]
pub unsafe extern "C" fn lr_adj_rib_in_iter_all(
    r: lr_adj_rib_in_t,
    cb: Option<unsafe extern "C" fn(route: lr_route_t, user: *mut core::ffi::c_void)>,
    user: *mut core::ffi::c_void,
) -> i64 {
    guarded(
        || unsafe {
            let Some(rib) = borrow_adj_rib_in(r) else {
                return -1;
            };
            let Some(cb_fn) = cb else {
                return -1;
            };
            let mut count: i64 = 0;
            for route in rib.iter_all() {
                let h: lr_route_t = route as *const Route as *mut OpaqueRoute;
                unsafe { cb_fn(h, user) };
                count += 1;
            }
            count
        },
        -1,
    )
}

/// Walk every route in the Adj-RIB-In that originated from the given
/// peer/protocol origin. `origin_peer` is the session handle,
/// `origin_proto` is one of the `LR_PROTO_*` constants. Returns the
/// number of routes visited, or `LR_ERR_NULL` (-1) on a NULL AdjRibIn
/// / NULL callback.
///
/// # Safety
/// See [`lr_adj_rib_in_iter_all`].
#[no_mangle]
pub unsafe extern "C" fn lr_adj_rib_in_iter_origin(
    r: lr_adj_rib_in_t,
    origin_peer: u64,
    origin_proto: i32,
    cb: Option<unsafe extern "C" fn(route: lr_route_t, user: *mut core::ffi::c_void)>,
    user: *mut core::ffi::c_void,
) -> i64 {
    guarded(
        || unsafe {
            let Some(rib) = borrow_adj_rib_in(r) else {
                return -1;
            };
            let Some(cb_fn) = cb else {
                return -1;
            };
            let proto = crate::policy::LrProtocol::from_i32(origin_proto)
                .ok_or_else(|| {
                    crate::error::set_last_error(format!("unknown protocol id {origin_proto}"));
                })
                .map(|p| p.to_proto_u32())
                .unwrap_or(u32::MAX);
            if proto == u32::MAX {
                return -2;
            }
            let origin = RouteOrigin {
                peer: origin_peer,
                proto,
            };
            let mut count: i64 = 0;
            for route in rib.iter_origin(origin) {
                let h: lr_route_t = route as *const Route as *mut OpaqueRoute;
                unsafe { cb_fn(h, user) };
                count += 1;
            }
            count
        },
        -1,
    )
}

/// Walk every route advertised to a given destination in the
/// Adj-RIB-Out. `origin_peer` is the destination session handle,
/// `origin_proto` is one of the `LR_PROTO_*` constants. Returns the
/// number of routes visited, or `LR_ERR_NULL` (-1) on a NULL
/// AdjRibOut / NULL callback.
///
/// # Safety
/// See [`lr_adj_rib_in_iter_all`].
#[no_mangle]
pub unsafe extern "C" fn lr_adj_rib_out_iter_for(
    r: lr_adj_rib_out_t,
    origin_peer: u64,
    origin_proto: i32,
    cb: Option<unsafe extern "C" fn(route: lr_route_t, user: *mut core::ffi::c_void)>,
    user: *mut core::ffi::c_void,
) -> i64 {
    guarded(
        || unsafe {
            let Some(rib) = borrow_adj_rib_out(r) else {
                return -1;
            };
            let Some(cb_fn) = cb else {
                return -1;
            };
            let proto = crate::policy::LrProtocol::from_i32(origin_proto)
                .ok_or_else(|| {
                    crate::error::set_last_error(format!("unknown protocol id {origin_proto}"));
                })
                .map(|p| p.to_proto_u32())
                .unwrap_or(u32::MAX);
            if proto == u32::MAX {
                return -2;
            }
            let origin = RouteOrigin {
                peer: origin_peer,
                proto,
            };
            let mut count: i64 = 0;
            for route in rib.iter_for(origin) {
                let h: lr_route_t = route as *const Route as *mut OpaqueRoute;
                unsafe { cb_fn(h, user) };
                count += 1;
            }
            count
        },
        -1,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use lr_core::rib::Protocol;

    /// Build a Route for tests — minimal v4 with the given prefix,
    /// local-pref, and AS path.
    fn build_route(prefix: [u8; 4], plen: u8, local_pref: u32) -> lr_route_t {
        let route = Route {
            key: RouteKey::new(Prefix::new_v4(prefix, plen), NlriFamily::IPV4_UNICAST),
            origin: RouteOrigin {
                peer: 1,
                proto: crate::policy::LrProtocol::Bgp.to_proto_u32(),
            },
            protocol: Protocol::Bgp,
            preference: lr_core::rib::Preference::new(100, 0),
            next_hop: Some(lr_core::addr::IpAddr::V4([10, 0, 0, 1])),
            attributes: lr_core::attr::Attributes::new(),
            age_ms: 0,
            path_id: 0,
            tag: None,
        };
        let mut route = route;
        // Use the public path-attribute API to set LOCAL_PREF.
        route.attributes.insert(lr_core::attr::Attribute {
            tag: lr_core::attr::AttrTag::raw(lr_bgp::path::AttrType::LocalPref.to_u8()),
            flags: 0x40,
            value: local_pref.to_be_bytes().to_vec(),
        });
        Box::into_raw(Box::new(route)) as lr_route_t
    }

    /// Build a Route with a specific metric in `preference.metric`
    /// (the field RouteSelector::compare actually looks at — unlike
    /// `local_pref`, which is a BGP attribute the generic selector
    /// does not consult).
    fn build_route_with_metric(prefix: [u8; 4], plen: u8, metric: u32) -> lr_route_t {
        let route = Route {
            key: RouteKey::new(Prefix::new_v4(prefix, plen), NlriFamily::IPV4_UNICAST),
            origin: RouteOrigin {
                peer: 1,
                proto: crate::policy::LrProtocol::Bgp.to_proto_u32(),
            },
            protocol: Protocol::Bgp,
            preference: lr_core::rib::Preference::new(100, metric),
            next_hop: Some(lr_core::addr::IpAddr::V4([10, 0, 0, 1])),
            attributes: lr_core::attr::Attributes::new(),
            age_ms: 0,
            path_id: 0,
            tag: None,
        };
        Box::into_raw(Box::new(route)) as lr_route_t
    }

    fn v4_prefix(addr: [u8; 4], plen: u8) -> lr_prefix_t {
        let mut p = lr_prefix_t {
            addr: [0; 16],
            is_ipv6: 0,
            prefix_len: plen,
        };
        p.addr[..4].copy_from_slice(&addr);
        p
    }

    #[test]
    fn ffi_loc_rib_install_and_best() {
        let rib = lr_loc_rib_new();
        assert!(!rib.is_null());

        let r = build_route([10, 0, 0, 0], 24, 100);
        let rc = unsafe { lr_loc_rib_install(rib, r) };
        assert_eq!(rc, 1, "first install changes the Loc-RIB");

        // Re-install identical route — no change.
        let r2 = build_route([10, 0, 0, 0], 24, 100);
        let rc = unsafe { lr_loc_rib_install(rib, r2) };
        assert_eq!(rc, 0, "byte-identical reinstall is a no-op");

        assert_eq!(unsafe { lr_loc_rib_len(rib) }, 1);
        assert_eq!(unsafe { lr_loc_rib_is_empty(rib) }, 0);
        assert_eq!(unsafe { lr_loc_rib_paths_len(rib) }, 1);
        assert!(unsafe { lr_loc_rib_generation(rib) } >= 1);

        let p = v4_prefix([10, 0, 0, 0], 24);
        assert_eq!(
            unsafe { lr_loc_rib_best_present(rib, &p, 1, 1, std::ptr::null()) },
            1
        );

        let mut out: lr_route_t = std::ptr::null_mut();
        let rc = unsafe { lr_loc_rib_best(rib, &p, 1, 1, std::ptr::null(), &raw mut out) };
        assert_eq!(rc, 0);
        assert!(!out.is_null());
        unsafe { crate::policy_objects::lr_route_free(out) };

        // Uninstall.
        let rc = unsafe { lr_loc_rib_uninstall(rib, &p, 1, 1, std::ptr::null()) };
        assert_eq!(rc, 1);
        assert_eq!(unsafe { lr_loc_rib_is_empty(rib) }, 1);

        unsafe { lr_loc_rib_free(rib) };
    }

    #[test]
    fn ffi_loc_rib_handles_null_safely() {
        assert_eq!(unsafe { lr_loc_rib_len(std::ptr::null_mut()) }, 0);
        assert_eq!(unsafe { lr_loc_rib_is_empty(std::ptr::null_mut()) }, 1);
        unsafe { lr_loc_rib_free(std::ptr::null_mut()) };
    }

    #[test]
    fn ffi_adj_rib_in_feed_and_len() {
        let rib = lr_adj_rib_in_new();
        assert!(!rib.is_null());
        assert_eq!(unsafe { lr_adj_rib_in_is_empty(rib) }, 1);

        let r = build_route([10, 0, 0, 0], 24, 100);
        let rc = unsafe {
            lr_adj_rib_in_feed(rib, 1, 0 /* LR_PROTO_BGP */, r)
        };
        assert_eq!(rc, 0);
        assert_eq!(unsafe { lr_adj_rib_in_len(rib) }, 1);
        assert_eq!(unsafe { lr_adj_rib_in_is_empty(rib) }, 0);

        let p = v4_prefix([10, 0, 0, 0], 24);
        let rc = unsafe { lr_adj_rib_in_withdraw(rib, 1, 0, &p, 1, 1, std::ptr::null(), 0) };
        assert_eq!(rc, 1);
        assert_eq!(unsafe { lr_adj_rib_in_len(rib) }, 0);

        unsafe { lr_adj_rib_in_free(rib) };
    }

    #[test]
    fn ffi_adj_rib_out_advertise_and_len() {
        let rib = lr_adj_rib_out_new();
        assert!(!rib.is_null());
        assert_eq!(unsafe { lr_adj_rib_out_is_empty(rib) }, 1);

        let r = build_route([10, 0, 0, 0], 24, 100);
        let rc = unsafe { lr_adj_rib_out_advertise(rib, 1, 0, r, 0) };
        assert_eq!(rc, 0);
        assert_eq!(unsafe { lr_adj_rib_out_len(rib) }, 1);
        assert_eq!(unsafe { lr_adj_rib_out_is_empty(rib) }, 0);

        // The route handle is NOT consumed — free it.
        unsafe { crate::policy_objects::lr_route_free(r) };

        let p = v4_prefix([10, 0, 0, 0], 24);
        let rc = unsafe { lr_adj_rib_out_suppress(rib, 1, 0, &p, 1, 1, std::ptr::null(), 0) };
        assert_eq!(rc, 0);
        assert_eq!(unsafe { lr_adj_rib_out_len(rib) }, 0);

        unsafe { lr_adj_rib_out_free(rib) };
    }

    #[test]
    fn ffi_rib_mux_install_and_get() {
        let mux = lr_rib_mux_new();
        assert!(!mux.is_null());

        let r = build_route([10, 0, 0, 0], 24, 100);
        let rc = unsafe { lr_rib_mux_install(mux, r) };
        assert_eq!(rc, 0);
        assert_eq!(unsafe { lr_rib_mux_len(mux) }, 1);
        assert_eq!(unsafe { lr_rib_mux_is_empty(mux) }, 0);

        let p = v4_prefix([10, 0, 0, 0], 24);
        let mut out: lr_route_t = std::ptr::null_mut();
        let rc = unsafe { lr_rib_mux_get(mux, &p, 1, 1, std::ptr::null(), &raw mut out) };
        assert_eq!(rc, 0);
        assert!(!out.is_null());
        unsafe { crate::policy_objects::lr_route_free(out) };

        let rc = unsafe { lr_rib_mux_uninstall(mux, &p, 1, 1, std::ptr::null()) };
        assert_eq!(rc, 1);
        assert_eq!(unsafe { lr_rib_mux_is_empty(mux) }, 1);

        unsafe { lr_rib_mux_free(mux) };
    }

    #[test]
    fn ffi_route_selector_select_picks_lower_metric() {
        // Two routes for the same prefix; the one with metric=10 must
        // beat the one with metric=100 (RouteSelector::compare orders
        // by admin_distance, then metric, then age).
        let r1 = build_route_with_metric([10, 0, 0, 0], 24, 100);
        let r2 = build_route_with_metric([10, 0, 0, 0], 24, 10);
        let routes = [r1, r2];
        let winner = unsafe { lr_route_selector_select(routes.as_ptr(), routes.len()) };
        assert_eq!(winner, 1, "the lower-metric route wins");

        let winner_bgp = unsafe { lr_route_selector_select_bgp(routes.as_ptr(), routes.len()) };
        assert_eq!(winner_bgp, 1, "BGP selector agrees");

        // Cleanup: both handles are still owned by the test.
        for r in routes {
            unsafe { crate::policy_objects::lr_route_free(r) };
        }
    }

    #[test]
    fn ffi_route_selector_select_returns_minus_one_on_empty() {
        let winner = unsafe { lr_route_selector_select(std::ptr::null(), 0) };
        assert_eq!(winner, -1);
    }

    // ---- LocRib: install_set / paths / iter_best / diff_since ----

    fn build_key_v4(addr: [u8; 4], prefix_len: u8) -> lr_route_key_t {
        let mut k = lr_route_key_t::default();
        k.addr[..4].copy_from_slice(&addr);
        k.is_ipv6 = 0;
        k.prefix_len = prefix_len;
        k.family_afi = 1;
        k.family_safi = 1;
        k.has_source = 0;
        k
    }

    #[test]
    fn ffi_loc_rib_install_set_and_paths() {
        let rib = lr_loc_rib_new();
        // Build two route handles for the same key.
        let r1 = build_route_with_metric([203, 0, 113, 0], 24, 100);
        let r2 = build_route_with_metric([203, 0, 113, 0], 24, 200);
        let key = build_key_v4([203, 0, 113, 0], 24);
        let routes = [r1, r2];
        let rc = unsafe { lr_loc_rib_install_set(rib, &key, routes.as_ptr(), routes.len()) };
        assert_eq!(rc, 0);
        // The LocRib holds 2 paths for this key.
        assert_eq!(unsafe { lr_loc_rib_paths(rib, &key) }, 2);
        // An unknown key returns 0 paths.
        let key2 = build_key_v4([198, 51, 100, 0], 24);
        assert_eq!(unsafe { lr_loc_rib_paths(rib, &key2) }, 0);
        unsafe {
            crate::policy_objects::lr_route_free(r1);
            crate::policy_objects::lr_route_free(r2);
            lr_loc_rib_free(rib);
        }
    }

    #[test]
    fn ffi_loc_rib_install_set_handles_null_safely() {
        let rib = lr_loc_rib_new();
        let key = build_key_v4([203, 0, 113, 0], 24);
        let r1 = build_route_with_metric([203, 0, 113, 0], 24, 100);
        let routes = [r1];
        // NULL LocRib → LR_ERR_NULL.
        let rc = unsafe { lr_loc_rib_install_set(std::ptr::null_mut(), &key, routes.as_ptr(), 1) };
        assert_eq!(rc, LR_ERR_NULL);
        // NULL key → LR_ERR_NULL.
        let rc = unsafe { lr_loc_rib_install_set(rib, std::ptr::null(), routes.as_ptr(), 1) };
        assert_eq!(rc, LR_ERR_NULL);
        // NULL routes → LR_ERR_NULL.
        let rc = unsafe { lr_loc_rib_install_set(rib, &key, std::ptr::null(), 1) };
        assert_eq!(rc, LR_ERR_NULL);
        // Zero count → LR_ERR_NULL.
        let rc = unsafe { lr_loc_rib_install_set(rib, &key, routes.as_ptr(), 0) };
        assert_eq!(rc, LR_ERR_NULL);
        unsafe {
            crate::policy_objects::lr_route_free(r1);
            lr_loc_rib_free(rib);
        }
    }

    #[test]
    fn ffi_loc_rib_paths_handles_null_safely() {
        let rib = lr_loc_rib_new();
        let key = build_key_v4([203, 0, 113, 0], 24);
        // NULL LocRib → 0.
        assert_eq!(unsafe { lr_loc_rib_paths(std::ptr::null_mut(), &key) }, 0);
        // NULL key → 0.
        assert_eq!(unsafe { lr_loc_rib_paths(rib, std::ptr::null()) }, 0);
        // Empty LocRib → 0.
        assert_eq!(unsafe { lr_loc_rib_paths(rib, &key) }, 0);
        unsafe { lr_loc_rib_free(rib) };
    }

    #[test]
    fn ffi_loc_rib_iter_best_walks_installed_routes() {
        let rib = lr_loc_rib_new();
        // Install one route so the iterator has something to walk.
        // NOTE: `lr_loc_rib_install` takes ownership of the route
        // handle (calls `take_route`), so we must NOT free r1
        // afterwards — the LocRib owns it now.
        let r1 = build_route_with_metric([203, 0, 113, 0], 24, 100);
        let rc = unsafe { lr_loc_rib_install(rib, r1) };
        // install returns 1 when the install actually changed the
        // Loc-RIB (a fresh route always does).
        assert_eq!(rc, 1);
        // NULL LocRib → -1.
        let count =
            unsafe { lr_loc_rib_iter_best(std::ptr::null_mut(), None, std::ptr::null_mut()) };
        assert_eq!(count, -1);
        // NULL callback → -1.
        let count = unsafe { lr_loc_rib_iter_best(rib, None, std::ptr::null_mut()) };
        assert_eq!(count, -1);
        // Real callback — count the routes visited.
        extern "C" fn counter(_route: lr_route_t, user: *mut core::ffi::c_void) {
            unsafe {
                let n: *mut i64 = user as *mut i64;
                *n += 1;
            }
        }
        let mut n: i64 = 0;
        let count = unsafe {
            lr_loc_rib_iter_best(rib, Some(counter), &raw mut n as *mut core::ffi::c_void)
        };
        assert_eq!(count, 1);
        assert_eq!(n, 1);
        unsafe {
            lr_loc_rib_free(rib);
        }
    }

    #[test]
    fn ffi_loc_rib_diff_since_returns_zero_on_no_changes() {
        let rib = lr_loc_rib_new();
        let mut added = 0usize;
        let mut modified = 0usize;
        let mut removed = 0usize;
        // diff_since against the current generation returns 0/0/0
        // (no changes since "now").
        let gen = unsafe { lr_loc_rib_generation(rib) };
        let rc = unsafe {
            lr_loc_rib_diff_since(
                rib,
                gen,
                &raw mut added,
                &raw mut modified,
                &raw mut removed,
            )
        };
        assert_eq!(rc, 0);
        assert_eq!(added, 0);
        assert_eq!(modified, 0);
        assert_eq!(removed, 0);
        // NULL handle → -1.
        let rc = unsafe {
            lr_loc_rib_diff_since(
                std::ptr::null_mut(),
                gen,
                &raw mut added,
                &raw mut modified,
                &raw mut removed,
            )
        };
        assert_eq!(rc, -1);
        // NULL out-pointer → -1.
        let rc = unsafe {
            lr_loc_rib_diff_since(
                rib,
                gen,
                std::ptr::null_mut(),
                &raw mut modified,
                &raw mut removed,
            )
        };
        assert_eq!(rc, -1);
        unsafe { lr_loc_rib_free(rib) };
    }

    #[test]
    fn loc_rib_iter_paths_walks_multipath_entries() {
        let rib = lr_loc_rib_new();
        // Install one route.
        let r1 = build_route([10, 0, 0, 0], 24, 100);
        unsafe { lr_loc_rib_install(rib, r1) };
        // Install_set with two paths for the same prefix → multipath.
        let r2 = build_route_with_metric([10, 0, 1, 0], 24, 50);
        let r3 = build_route_with_metric([10, 0, 1, 0], 24, 60);
        let key = build_key_v4([10, 0, 1, 0], 24);
        let routes = [r2, r3];
        unsafe { lr_loc_rib_install_set(rib, &key, routes.as_ptr(), routes.len()) };
        // iter_paths walks every installed path (1 + 2 = 3).
        extern "C" fn counter(_route: lr_route_t, user: *mut core::ffi::c_void) {
            unsafe {
                let c: *mut i64 = user as *mut i64;
                *c += 1;
            }
        }
        let mut count: i64 = 0;
        unsafe {
            count =
                lr_loc_rib_iter_paths(rib, Some(counter), &raw mut count as *mut core::ffi::c_void);
        }
        assert_eq!(count, 3, "iter_paths visited {count} routes, expected 3");
        unsafe { lr_loc_rib_free(rib) };
    }

    #[test]
    fn loc_rib_iter_paths_rejects_null_handle_and_null_cb() {
        extern "C" fn noop(_route: lr_route_t, _user: *mut core::ffi::c_void) {}
        // NULL handle → -1.
        let rc = unsafe {
            lr_loc_rib_iter_paths(std::ptr::null_mut(), Some(noop), std::ptr::null_mut())
        };
        assert_eq!(rc, -1);
        // NULL cb → -1.
        let rib = lr_loc_rib_new();
        let rc = unsafe { lr_loc_rib_iter_paths(rib, None, std::ptr::null_mut()) };
        assert_eq!(rc, -1);
        unsafe { lr_loc_rib_free(rib) };
    }

    #[test]
    fn loc_rib_iter_sets_walks_keys() {
        let rib = lr_loc_rib_new();
        let r1 = build_route([10, 0, 0, 0], 24, 100);
        unsafe { lr_loc_rib_install(rib, r1) };
        let r2 = build_route([10, 0, 1, 0], 24, 100);
        unsafe { lr_loc_rib_install(rib, r2) };
        // iter_sets walks every (key, paths) pair → 2 sets.
        extern "C" fn counter(
            _prefix: *mut u8,
            _prefix_len: u8,
            _is_ipv6: u8,
            _path_count: usize,
            user: *mut core::ffi::c_void,
        ) {
            unsafe {
                let c: *mut i64 = user as *mut i64;
                *c += 1;
            }
        }
        let mut seen: i64 = 0;
        unsafe {
            seen =
                lr_loc_rib_iter_sets(rib, Some(counter), &raw mut seen as *mut core::ffi::c_void);
        }
        assert_eq!(seen, 2, "iter_sets visited {seen} sets, expected 2");
        unsafe { lr_loc_rib_free(rib) };
    }

    #[test]
    fn adj_rib_in_iter_all_walks_every_route() {
        extern "C" fn noop(_route: lr_route_t, _user: *mut core::ffi::c_void) {}
        extern "C" fn counter(_route: lr_route_t, user: *mut core::ffi::c_void) {
            unsafe {
                let c: *mut i64 = user as *mut i64;
                *c += 1;
            }
        }
        let rib = lr_adj_rib_in_new();
        // NULL handle → -1.
        let rc = unsafe {
            lr_adj_rib_in_iter_all(std::ptr::null_mut(), Some(noop), std::ptr::null_mut())
        };
        assert_eq!(rc, -1);
        // NULL cb → -1.
        let rc = unsafe { lr_adj_rib_in_iter_all(rib, None, std::ptr::null_mut()) };
        assert_eq!(rc, -1);
        // Empty rib → 0 routes.
        let mut count: i64 = 0;
        unsafe {
            count = lr_adj_rib_in_iter_all(
                rib,
                Some(counter),
                &raw mut count as *mut core::ffi::c_void,
            );
        }
        assert_eq!(
            count, 0,
            "iter_all on empty AdjRibIn visited {count} routes, expected 0"
        );
        unsafe { lr_adj_rib_in_free(rib) };
    }

    #[test]
    fn adj_rib_out_iter_for_rejects_null_handle_and_bad_proto() {
        extern "C" fn noop(_route: lr_route_t, _user: *mut core::ffi::c_void) {}
        // NULL handle → -1.
        let rc = unsafe {
            lr_adj_rib_out_iter_for(std::ptr::null_mut(), 0, 0, Some(noop), std::ptr::null_mut())
        };
        assert_eq!(rc, -1);
        let rib = lr_adj_rib_out_new();
        // NULL cb → -1.
        let rc = unsafe { lr_adj_rib_out_iter_for(rib, 0, 0, None, std::ptr::null_mut()) };
        assert_eq!(rc, -1);
        // Bad protocol id → -2.
        let rc = unsafe { lr_adj_rib_out_iter_for(rib, 0, 99, Some(noop), std::ptr::null_mut()) };
        assert_eq!(rc, -2);
        unsafe { lr_adj_rib_out_free(rib) };
    }
}
