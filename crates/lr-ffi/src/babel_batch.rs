//! lr-babel gap-closure FFI — mirrors `BabelFrame::new` /
//! `BabelFrame::empty`, the `BabelRouteTable` mutator surface
//! (insert / insert_timed / withdraw / expire / get / iter /
//! best_routes), the `Tlv` opaque handle, and `RouteKey` /
//! `BabelRoute` opaque handles.
//!
//! Issue #92 — gap closure: the existing FFI covered the codec, the
//! individual message types, the `BabelNeighbor` and `BabelRouteTable`
//! constructors but NOT the table mutators, the TLV opaque handle,
//! or the `BabelFrame::new` / `empty` constructors. This batch fills
//! those gaps so a C embedder can build a Babel frame from scratch
//! and feed routes into the table.

#![allow(unused_unsafe)]
#![allow(dead_code)]

use lr_babel::route::{BabelRoute, RouteKey};
use lr_babel::source::SourcePrefix;
use lr_babel::tlv::{Tlv, TlvType};
use lr_babel::BabelFrame;
use lr_core::addr::{IpAddr, Prefix};

use crate::babel::{box_frame, lr_babel_frame_t};
use crate::babel_neighbor::{borrow_route_table, borrow_route_table_mut, lr_babel_route_table_t};
use crate::error::LrError;
use crate::guarded;
use crate::handle::lr_bytes_t;

const LR_ERR_NULL: i32 = LrError::Null as i32;
const LR_ERR_INVALID_HANDLE: i32 = LrError::InvalidHandle as i32;

// ---- opaque handles (BabelFrame is reused from babel.rs; the
// Tlv/Route/RouteKey handles below are new to this module). ----

#[repr(C)]
pub struct OpaqueBabelTlv {
    _private: [u8; 0],
}
pub type lr_babel_tlv_t = *mut OpaqueBabelTlv;

#[repr(C)]
pub struct OpaqueBabelRoute {
    _private: [u8; 0],
}
pub type lr_babel_route_t = *mut OpaqueBabelRoute;

#[repr(C)]
pub struct OpaqueBabelRouteKey {
    _private: [u8; 0],
}
pub type lr_babel_route_key_t = *mut OpaqueBabelRouteKey;

fn box_tlv(t: Tlv) -> lr_babel_tlv_t {
    Box::into_raw(Box::new(t)) as lr_babel_tlv_t
}

unsafe fn unbox_tlv(t: lr_babel_tlv_t) -> Option<Box<Tlv>> {
    if t.is_null() {
        return None;
    }
    Some(unsafe { Box::from_raw(t as *mut Tlv) })
}

unsafe fn borrow_tlv(t: lr_babel_tlv_t) -> Option<&'static Tlv> {
    if t.is_null() {
        return None;
    }
    Some(unsafe { &*(t as *const Tlv) })
}

fn box_route(r: BabelRoute) -> lr_babel_route_t {
    Box::into_raw(Box::new(r)) as lr_babel_route_t
}

unsafe fn borrow_route(r: lr_babel_route_t) -> Option<&'static BabelRoute> {
    if r.is_null() {
        return None;
    }
    Some(unsafe { &*(r as *const BabelRoute) })
}

fn box_route_key(k: RouteKey) -> lr_babel_route_key_t {
    Box::into_raw(Box::new(k)) as lr_babel_route_key_t
}

unsafe fn borrow_route_key(k: lr_babel_route_key_t) -> Option<&'static RouteKey> {
    if k.is_null() {
        return None;
    }
    Some(unsafe { &*(k as *const RouteKey) })
}

unsafe fn borrow_frame_mut(f: lr_babel_frame_t) -> Option<&'static mut BabelFrame> {
    if f.is_null() {
        return None;
    }
    Some(unsafe { &mut *(f as *mut BabelFrame) })
}

// =========================================================================
// BabelFrame constructors
// =========================================================================

/// Construct an empty Babel frame (RFC 8966 §4.1). Useful as a builder
/// starting point — call [`lr_babel_frame_push_tlv`] to add TLVs.
#[no_mangle]
pub extern "C" fn lr_babel_frame_new_empty() -> lr_babel_frame_t {
    guarded(|| box_frame(BabelFrame::empty()), std::ptr::null_mut())
}

/// Construct a Babel frame from a flat array of TLV handles. The
/// frame takes ownership of the TLV handles — they are consumed and
/// must not be reused. The `tlvs` array itself is borrowed (the
/// caller owns the buffer).
///
/// Returns NULL on a NULL `tlvs` pointer with non-zero `count`, or on
/// a panic. An empty `tlvs` array produces an empty frame (same as
/// [`lr_babel_frame_new_empty`]).
///
/// # Safety
/// `tlvs` must point to `count` readable `lr_babel_tlv_t` values.
/// Each TLV handle must have been produced by `lr_babel_tlv_new` /
/// `_pad1` / `_pad_n` and must not be reused after this call.
#[no_mangle]
pub unsafe extern "C" fn lr_babel_frame_new_from_tlvs(
    tlvs: *const lr_babel_tlv_t,
    count: usize,
) -> lr_babel_frame_t {
    guarded(
        || unsafe {
            if tlvs.is_null() && count != 0 {
                return std::ptr::null_mut();
            }
            let slice: &[lr_babel_tlv_t] = if count == 0 {
                &[]
            } else {
                unsafe { std::slice::from_raw_parts(tlvs, count) }
            };
            let mut body = Vec::with_capacity(count);
            for &t in slice {
                let Some(b) = unbox_tlv(t) else {
                    continue;
                };
                body.push(*b);
            }
            box_frame(BabelFrame::new(body))
        },
        std::ptr::null_mut(),
    )
}

/// Push one TLV onto the frame's body. The TLV handle is consumed
/// and freed. Returns 0 on success, `LR_ERR_NULL` (-1) on a NULL
/// frame or TLV handle.
///
/// # Safety
/// `frame` must be a valid handle. `tlv` must be a valid handle and
/// is invalid after this call.
#[no_mangle]
pub unsafe extern "C" fn lr_babel_frame_push_tlv(
    frame: lr_babel_frame_t,
    tlv: lr_babel_tlv_t,
) -> i32 {
    guarded(
        || unsafe {
            let Some(f) = borrow_frame_mut(frame) else {
                return LR_ERR_NULL;
            };
            let Some(t) = unbox_tlv(tlv) else {
                return LR_ERR_NULL;
            };
            f.body.push(*t);
            0
        },
        LrError::Panic as i32,
    )
}

// =========================================================================
// Tlv opaque handle
// =========================================================================

/// Construct a TLV with a kind and a value (RFC 8966 §4.4). `kind`
/// is a `LR_BABEL_TLV_*` constant. Returns NULL on a panic.
#[no_mangle]
pub unsafe extern "C" fn lr_babel_tlv_new(
    kind: u8,
    value: *const u8,
    value_len: usize,
) -> lr_babel_tlv_t {
    guarded(
        || unsafe {
            let kind_enum = TlvType::from_u8(kind);
            let value = if value.is_null() || value_len == 0 {
                Vec::new()
            } else {
                unsafe { std::slice::from_raw_parts(value, value_len).to_vec() }
            };
            box_tlv(Tlv::new(kind_enum, value))
        },
        std::ptr::null_mut(),
    )
}

/// Construct a Pad1 TLV (RFC 8966 §4.4.1 — single-byte pad, no
/// value field).
#[no_mangle]
pub extern "C" fn lr_babel_tlv_pad1() -> lr_babel_tlv_t {
    guarded(|| box_tlv(Tlv::pad1()), std::ptr::null_mut())
}

/// Construct a PadN TLV (RFC 8966 §4.4.2 — N bytes of zero padding).
#[no_mangle]
pub extern "C" fn lr_babel_tlv_pad_n(n: usize) -> lr_babel_tlv_t {
    guarded(|| box_tlv(Tlv::pad_n(n)), std::ptr::null_mut())
}

/// Read the TLV's kind code (`LR_BABEL_TLV_*`). Returns 0 on a NULL
/// handle.
///
/// # Safety
/// `t` must be a valid handle.
#[no_mangle]
pub unsafe extern "C" fn lr_babel_tlv_kind(t: lr_babel_tlv_t) -> u8 {
    guarded(
        || unsafe { borrow_tlv(t).map(|t| t.kind.to_u8()).unwrap_or(0) },
        0,
    )
}

/// Read the TLV's value bytes into a freshly-allocated
/// `lr_bytes_t`. The caller owns the bytes and must free them via
/// `lr_bytes_free`.
///
/// # Safety
/// `t` must be a valid handle. `out` must point to a writable
/// `lr_bytes_t`.
#[no_mangle]
pub unsafe extern "C" fn lr_babel_tlv_value(t: lr_babel_tlv_t, out: *mut lr_bytes_t) -> i32 {
    guarded(
        || unsafe {
            let Some(t) = borrow_tlv(t) else {
                return LR_ERR_NULL;
            };
            if out.is_null() {
                return LR_ERR_NULL;
            }
            unsafe { *out = lr_bytes_t::from_vec(t.value.clone()) }
            0
        },
        LrError::Panic as i32,
    )
}

/// Drop a TLV. Safe to call with NULL.
///
/// # Safety
/// `t` must have been produced by `lr_babel_tlv_new` / `_pad1` /
/// `_pad_n` and not already freed.
#[no_mangle]
pub unsafe extern "C" fn lr_babel_tlv_free(t: lr_babel_tlv_t) {
    guarded(
        || unsafe {
            drop(unbox_tlv(t));
        },
        (),
    )
}

// =========================================================================
// BabelRoute + RouteKey opaque handles
// =========================================================================

/// Construct a RouteKey for a destination prefix (RFC 8966 §3.2).
/// `router_id` is the 8-byte Babel router identifier of the source.
///
/// Returns NULL on a panic. The optional `source_prefix` arguments
/// build a source-specific RouteKey; pass `source_present = 0` for a
/// plain (non-source-specific) route.
///
/// # Safety
/// `dest_addr` and `source_addr` must point to readable bytes of the
/// right length for the address family.
#[no_mangle]
pub unsafe extern "C" fn lr_babel_route_key_new(
    dest_is_ipv6: u8,
    dest_addr: *const u8,
    dest_prefix_len: u8,
    source_present: u8,
    source_is_ipv6: u8,
    source_addr: *const u8,
    source_prefix_len: u8,
    router_id: *const u8,
) -> lr_babel_route_key_t {
    guarded(
        || unsafe {
            if dest_addr.is_null() || router_id.is_null() {
                return std::ptr::null_mut();
            }
            let dest = if dest_is_ipv6 != 0 {
                let mut b = [0u8; 16];
                b.copy_from_slice(unsafe { std::slice::from_raw_parts(dest_addr, 16) });
                Prefix::new_v6(b, dest_prefix_len)
            } else {
                let mut b = [0u8; 4];
                b.copy_from_slice(unsafe { std::slice::from_raw_parts(dest_addr, 4) });
                Prefix::new_v4(b, dest_prefix_len)
            };
            let source = if source_present != 0 && !source_addr.is_null() {
                let p = if source_is_ipv6 != 0 {
                    let mut b = [0u8; 16];
                    b.copy_from_slice(unsafe { std::slice::from_raw_parts(source_addr, 16) });
                    Prefix::new_v6(b, source_prefix_len)
                } else {
                    let mut b = [0u8; 4];
                    b.copy_from_slice(unsafe { std::slice::from_raw_parts(source_addr, 4) });
                    Prefix::new_v4(b, source_prefix_len)
                };
                Some(SourcePrefix::new(p))
            } else {
                None
            };
            let mut rid = [0u8; 8];
            rid.copy_from_slice(unsafe { std::slice::from_raw_parts(router_id, 8) });
            box_route_key(RouteKey {
                destination: dest,
                source,
                router_id: rid,
            })
        },
        std::ptr::null_mut(),
    )
}

/// Drop a RouteKey. Safe to call with NULL.
///
/// # Safety
/// `k` must have been produced by `lr_babel_route_key_new` and not
/// already freed.
#[no_mangle]
pub unsafe extern "C" fn lr_babel_route_key_free(k: lr_babel_route_key_t) {
    guarded(
        || unsafe {
            if k.is_null() {
                return;
            }
            drop(Box::from_raw(k as *mut RouteKey));
        },
        (),
    )
}

/// Construct a BabelRoute. `next_hop` is the IPv4 or IPv6 next hop
/// (16 bytes for IPv6, 4 for IPv4). `feasible` and `installed` are
/// initial state flags (typically 0 / 0).
///
/// # Safety
/// `next_hop` must point to 4 (IPv4) or 16 (IPv6) readable bytes.
#[no_mangle]
pub unsafe extern "C" fn lr_babel_route_new(
    key: lr_babel_route_key_t,
    seqno: u16,
    metric: u32,
    next_hop_is_ipv6: u8,
    next_hop: *const u8,
    feasible: u8,
    installed: u8,
) -> lr_babel_route_t {
    guarded(
        || unsafe {
            let Some(k) = borrow_route_key(key) else {
                return std::ptr::null_mut();
            };
            if next_hop.is_null() {
                return std::ptr::null_mut();
            }
            let next = if next_hop_is_ipv6 != 0 {
                let mut b = [0u8; 16];
                b.copy_from_slice(unsafe { std::slice::from_raw_parts(next_hop, 16) });
                IpAddr::V6(b)
            } else {
                let mut b = [0u8; 4];
                b.copy_from_slice(unsafe { std::slice::from_raw_parts(next_hop, 4) });
                IpAddr::V4(b)
            };
            box_route(BabelRoute {
                key: k.clone(),
                seqno,
                metric,
                next_hop: next,
                feasible: feasible != 0,
                installed: installed != 0,
            })
        },
        std::ptr::null_mut(),
    )
}

/// Drop a BabelRoute. Safe to call with NULL.
///
/// # Safety
/// `r` must have been produced by `lr_babel_route_new` and not
/// already freed.
#[no_mangle]
pub unsafe extern "C" fn lr_babel_route_free(r: lr_babel_route_t) {
    guarded(
        || unsafe {
            if r.is_null() {
                return;
            }
            drop(Box::from_raw(r as *mut BabelRoute));
        },
        (),
    )
}

// =========================================================================
// BabelRouteTable mutators — RFC 8966 §3.2.5 / §3.5
// =========================================================================

/// Insert a route into the table. The route is cloned (the caller
/// retains ownership of the handle). Returns 0 on success,
/// `LR_ERR_NULL` (-1) on a NULL table or route handle.
///
/// Mirrors `BabelRouteTable::insert`. Routes are kept in a `BTreeMap`
/// keyed by `RouteKey` so duplicate inserts update in place.
///
/// # Safety
/// `table` must be a valid handle returned by `lr_babel_route_table_new`.
/// `route` must be a valid handle.
#[no_mangle]
pub unsafe extern "C" fn lr_babel_route_table_insert(
    table: lr_babel_route_table_t,
    route: lr_babel_route_t,
) -> i32 {
    guarded(
        || unsafe {
            let Some(t) = borrow_route_table_mut(table) else {
                return LR_ERR_NULL;
            };
            let Some(r) = borrow_route(route) else {
                return LR_ERR_NULL;
            };
            t.insert(r.clone());
            0
        },
        LrError::Panic as i32,
    )
}

/// Insert a route together with its reception time and the interval
/// its Update announced (RFC 8966 §3.2.5). An exact re-announcement
/// of the same claim (same source, same seqno, same metric) is a
/// refresh — it must not re-enter the feasibility machinery but it
/// does push the expiry deadline out.
///
/// # Safety
/// See [`lr_babel_route_table_insert`].
#[no_mangle]
pub unsafe extern "C" fn lr_babel_route_table_insert_timed(
    table: lr_babel_route_table_t,
    route: lr_babel_route_t,
    interval_cs: u16,
    now_ms: u64,
) -> i32 {
    guarded(
        || unsafe {
            let Some(t) = borrow_route_table_mut(table) else {
                return LR_ERR_NULL;
            };
            let Some(r) = borrow_route(route) else {
                return LR_ERR_NULL;
            };
            t.insert_timed(r.clone(), interval_cs, now_ms);
            0
        },
        LrError::Panic as i32,
    )
}

/// Withdraw a route by key. Returns 0 on success, `LR_ERR_NULL` (-1)
/// on a NULL table or key handle.
///
/// # Safety
/// `table` and `key` must be valid handles.
#[no_mangle]
pub unsafe extern "C" fn lr_babel_route_table_withdraw(
    table: lr_babel_route_table_t,
    key: lr_babel_route_key_t,
) -> i32 {
    guarded(
        || unsafe {
            let Some(t) = borrow_route_table_mut(table) else {
                return LR_ERR_NULL;
            };
            let Some(k) = borrow_route_key(key) else {
                return LR_ERR_NULL;
            };
            t.withdraw(k);
            0
        },
        LrError::Panic as i32,
    )
}

/// Expire the routes whose re-announcement hold time lapsed
/// (RFC 8966 §3.2.5). Returns the number of routes withdrawn. The
/// caller can then walk the table to discover which keys are gone.
///
/// # Safety
/// `table` must be a valid handle.
#[no_mangle]
pub unsafe extern "C" fn lr_babel_route_table_expire(
    table: lr_babel_route_table_t,
    now_ms: u64,
) -> usize {
    guarded(
        || unsafe {
            let Some(t) = borrow_route_table_mut(table) else {
                return 0;
            };
            t.expire(now_ms).len()
        },
        0,
    )
}

/// True when the table holds a route for the given key.
///
/// # Safety
/// `table` and `key` must be valid handles.
#[no_mangle]
pub unsafe extern "C" fn lr_babel_route_table_contains(
    table: lr_babel_route_table_t,
    key: lr_babel_route_key_t,
) -> u8 {
    guarded(
        || unsafe {
            let Some(t) = borrow_route_table(table) else {
                return 0;
            };
            let Some(k) = borrow_route_key(key) else {
                return 0;
            };
            t.get(k).is_some() as u8
        },
        0,
    )
}

/// Number of best (lowest-metric, feasible) routes per destination.
/// Mirrors `BabelRouteTable::best_routes().len()`. Useful for
/// diagnostics — the full routes themselves are not enumerated via
/// this entry point.
///
/// # Safety
/// `table` must be a valid handle.
#[no_mangle]
pub unsafe extern "C" fn lr_babel_route_table_best_routes_count(
    table: lr_babel_route_table_t,
) -> usize {
    guarded(
        || unsafe {
            let Some(t) = borrow_route_table(table) else {
                return 0;
            };
            t.best_routes().len()
        },
        0,
    )
}

/// Look up the route stored under `key`. Returns a borrowed
/// `lr_babel_route_t` (the table retains ownership — DO NOT pass the
/// returned handle to `lr_babel_route_free`). Returns NULL when the
/// key is not present, when either handle is NULL, or on a panic.
///
/// The returned handle is invalidated by any subsequent mutation of
/// the table (insert / withdraw / expire) — embedders that need a
/// stable handle across mutations must clone the route fields out via
/// the reader entry points below.
///
/// # Safety
/// `table` and `key` must be valid handles. The returned pointer is
/// borrowed from the table and is only valid until the next table
/// mutation.
#[no_mangle]
pub unsafe extern "C" fn lr_babel_route_table_get(
    table: lr_babel_route_table_t,
    key: lr_babel_route_key_t,
) -> lr_babel_route_t {
    guarded(
        || unsafe {
            let Some(t) = borrow_route_table(table) else {
                return std::ptr::null_mut();
            };
            let Some(k) = borrow_route_key(key) else {
                return std::ptr::null_mut();
            };
            match t.get(k) {
                Some(r) => r as *const BabelRoute as lr_babel_route_t,
                None => std::ptr::null_mut(),
            }
        },
        std::ptr::null_mut(),
    )
}

/// Callback shape for [`lr_babel_route_table_iter`] /
/// [`lr_babel_route_table_best_routes_iter`]. The callback receives
/// a borrowed `route` handle (DO NOT free) and the `user` pointer
/// passed to the iter call. Return 0 to continue iteration,
/// non-zero to stop early (the non-zero value is returned to the
/// caller of the iter entry point).
pub type lr_babel_route_iter_cb =
    Option<unsafe extern "C" fn(route: lr_babel_route_t, user: *mut std::ffi::c_void) -> i32>;

/// Iterate over every route in the table (RFC 8966 §3.5). The
/// callback is invoked once per route, in `BTreeMap<RouteKey, _>`
/// order (deterministic). The route handle passed to the callback
/// is borrowed from the table — DO NOT free it.
///
/// Returns 0 if the callback returned 0 for every entry, the
/// callback's non-zero return value if it stopped early, or
/// `LR_ERR_NULL` (-1) on a NULL `table` or `cb`.
///
/// Iteration is invalidated by any table mutation that runs
/// concurrently on another thread (the table is not `Sync`).
///
/// # Safety
/// `table` must be a valid handle. `cb` must be a valid function
/// pointer. `user` is opaque to the library and is passed through
/// unchanged.
#[no_mangle]
pub unsafe extern "C" fn lr_babel_route_table_iter(
    table: lr_babel_route_table_t,
    cb: lr_babel_route_iter_cb,
    user: *mut std::ffi::c_void,
) -> i32 {
    guarded(
        || unsafe {
            let Some(t) = borrow_route_table(table) else {
                return LR_ERR_NULL;
            };
            let cb = match cb {
                Some(cb) => cb,
                None => return LR_ERR_NULL,
            };
            for (_, r) in t.iter() {
                let rc = unsafe { cb(r as *const BabelRoute as lr_babel_route_t, user) };
                if rc != 0 {
                    return rc;
                }
            }
            0
        },
        LrError::Panic as i32,
    )
}

/// Iterate over the best (lowest-metric, feasible) route per
/// destination (RFC 8966 §3.5 — the routes eligible for FIB
/// install). The callback gets a borrowed route handle — DO NOT
/// free it. Iteration order is `BTreeMap<RouteKey, _>` order, the
/// same order `BabelRouteTable::best_routes()` yields in Rust.
///
/// Returns 0 if the callback returned 0 for every entry, the
/// callback's non-zero return value if it stopped early, or
/// `LR_ERR_NULL` (-1) on a NULL `table` or `cb`.
///
/// # Safety
/// See [`lr_babel_route_table_iter`].
#[no_mangle]
pub unsafe extern "C" fn lr_babel_route_table_best_routes_iter(
    table: lr_babel_route_table_t,
    cb: lr_babel_route_iter_cb,
    user: *mut std::ffi::c_void,
) -> i32 {
    guarded(
        || unsafe {
            let Some(t) = borrow_route_table(table) else {
                return LR_ERR_NULL;
            };
            let cb = match cb {
                Some(cb) => cb,
                None => return LR_ERR_NULL,
            };
            for r in t.best_routes() {
                let rc = unsafe { cb(r as *const BabelRoute as lr_babel_route_t, user) };
                if rc != 0 {
                    return rc;
                }
            }
            0
        },
        LrError::Panic as i32,
    )
}

// =========================================================================
// RouteKey + BabelRoute field accessors — let embedders read the
// stored state without going through the daemon. The accessors
// mirror the field readers `BabelRouteTable::iter` / `get` yield in
// Rust; the C ABI surface was previously write-only.
// =========================================================================

/// 1 when the destination prefix is IPv6, 0 for IPv4. Returns 0 on
/// a NULL handle.
///
/// # Safety
/// `k` must be a valid handle (owned or borrowed).
#[no_mangle]
pub unsafe extern "C" fn lr_babel_route_key_destination_is_ipv6(
    k: lr_babel_route_key_t,
) -> u8 {
    guarded(
        || unsafe {
            borrow_route_key(k)
                .map(|k| matches!(k.destination.addr, IpAddr::V6(_)) as u8)
                .unwrap_or(0)
        },
        0,
    )
}

/// Copy the destination address into the 16-byte `out` buffer (the
/// IPv4 address is written to the last 4 bytes, matching the
/// `IpAddr::V4([u8;4])` → `[u8;16]` IPv4-mapped layout the rest of
/// the C ABI uses). Returns 0 on success, `LR_ERR_NULL` (-1) on a
/// NULL `k` or `out`.
///
/// # Safety
/// `k` must be a valid handle. `out` must point to 16 writable bytes.
#[no_mangle]
pub unsafe extern "C" fn lr_babel_route_key_destination_addr(
    k: lr_babel_route_key_t,
    out: *mut u8,
) -> i32 {
    guarded(
        || unsafe {
            let Some(k) = borrow_route_key(k) else {
                return LR_ERR_NULL;
            };
            if out.is_null() {
                return LR_ERR_NULL;
            }
            let mut buf = [0u8; 16];
            match k.destination.addr {
                IpAddr::V4(b) => buf[12..16].copy_from_slice(&b),
                IpAddr::V6(b) => buf.copy_from_slice(&b),
            }
            unsafe { std::ptr::copy_nonoverlapping(buf.as_ptr(), out, 16) };
            0
        },
        LrError::Panic as i32,
    )
}

/// Destination prefix length in bits. Returns 0 on a NULL handle.
#[no_mangle]
pub unsafe extern "C" fn lr_babel_route_key_destination_prefix_len(
    k: lr_babel_route_key_t,
) -> u8 {
    guarded(
        || unsafe {
            borrow_route_key(k)
                .map(|k| k.destination.prefix_len)
                .unwrap_or(0)
        },
        0,
    )
}

/// 1 when the RouteKey is source-specific (RFC 8966 §3.1 — a
/// source-specific route narrows the match to a source prefix). 0
/// otherwise or on a NULL handle.
#[no_mangle]
pub unsafe extern "C" fn lr_babel_route_key_source_present(k: lr_babel_route_key_t) -> u8 {
    guarded(
        || unsafe {
            borrow_route_key(k)
                .map(|k| k.source.is_some() as u8)
                .unwrap_or(0)
        },
        0,
    )
}

/// 1 when the source prefix (if present) is IPv6, 0 for IPv4. Returns
/// 0 when the key is not source-specific or the handle is NULL.
#[no_mangle]
pub unsafe extern "C" fn lr_babel_route_key_source_is_ipv6(k: lr_babel_route_key_t) -> u8 {
    guarded(
        || unsafe {
            borrow_route_key(k)
                .and_then(|k| k.source.as_ref())
                .map(|s| matches!(s.prefix.addr, IpAddr::V6(_)) as u8)
                .unwrap_or(0)
        },
        0,
    )
}

/// Copy the source prefix address into the 16-byte `out` buffer (the
/// IPv4 address is written to the last 4 bytes). Returns 0 on
/// success, `LR_ERR_NULL` (-1) on a NULL `k` or `out`, and
/// `LR_ERR_INVALID_HANDLE` (-2) when the key is not source-specific.
///
/// # Safety
/// `k` must be a valid handle. `out` must point to 16 writable bytes.
#[no_mangle]
pub unsafe extern "C" fn lr_babel_route_key_source_addr(
    k: lr_babel_route_key_t,
    out: *mut u8,
) -> i32 {
    guarded(
        || unsafe {
            let Some(k) = borrow_route_key(k) else {
                return LR_ERR_NULL;
            };
            if out.is_null() {
                return LR_ERR_NULL;
            }
            let Some(s) = k.source.as_ref() else {
                return LR_ERR_INVALID_HANDLE;
            };
            let mut buf = [0u8; 16];
            match s.prefix.addr {
                IpAddr::V4(b) => buf[12..16].copy_from_slice(&b),
                IpAddr::V6(b) => buf.copy_from_slice(&b),
            }
            unsafe { std::ptr::copy_nonoverlapping(buf.as_ptr(), out, 16) };
            0
        },
        LrError::Panic as i32,
    )
}

/// Source prefix length in bits. Returns 0 when the key is not
/// source-specific or the handle is NULL.
#[no_mangle]
pub unsafe extern "C" fn lr_babel_route_key_source_prefix_len(
    k: lr_babel_route_key_t,
) -> u8 {
    guarded(
        || unsafe {
            borrow_route_key(k)
                .and_then(|k| k.source.as_ref())
                .map(|s| s.prefix.prefix_len)
                .unwrap_or(0)
        },
        0,
    )
}

/// Copy the 8-byte Babel router identifier into `out`. Returns 0 on
/// success, `LR_ERR_NULL` (-1) on a NULL `k` or `out`.
///
/// # Safety
/// `k` must be a valid handle. `out` must point to 8 writable bytes.
#[no_mangle]
pub unsafe extern "C" fn lr_babel_route_key_router_id(
    k: lr_babel_route_key_t,
    out: *mut u8,
) -> i32 {
    guarded(
        || unsafe {
            let Some(k) = borrow_route_key(k) else {
                return LR_ERR_NULL;
            };
            if out.is_null() {
                return LR_ERR_NULL;
            }
            unsafe { std::ptr::copy_nonoverlapping(k.router_id.as_ptr(), out, 8) };
            0
        },
        LrError::Panic as i32,
    )
}

// ---- BabelRoute field accessors ----

/// Read the route's seqno (RFC 8966 §3.2 — the 16-bit monotonically
/// increasing sequence number from the source). Returns 0 on a NULL
/// handle.
#[no_mangle]
pub unsafe extern "C" fn lr_babel_route_seqno(r: lr_babel_route_t) -> u16 {
    guarded(
        || unsafe { borrow_route(r).map(|r| r.seqno).unwrap_or(0) },
        0,
    )
}

/// Read the route's metric (RFC 8966 §3.4.4 — link cost + neighbour
/// cost). Returns 0 on a NULL handle.
#[no_mangle]
pub unsafe extern "C" fn lr_babel_route_metric(r: lr_babel_route_t) -> u32 {
    guarded(
        || unsafe { borrow_route(r).map(|r| r.metric).unwrap_or(0) },
        0,
    )
}

/// 1 when the route's next hop is IPv6, 0 for IPv4. Returns 0 on a
/// NULL handle.
#[no_mangle]
pub unsafe extern "C" fn lr_babel_route_next_hop_is_ipv6(r: lr_babel_route_t) -> u8 {
    guarded(
        || unsafe {
            borrow_route(r)
                .map(|r| matches!(r.next_hop, IpAddr::V6(_)) as u8)
                .unwrap_or(0)
        },
        0,
    )
}

/// Copy the route's next-hop address into the 16-byte `out` buffer
/// (the IPv4 address is written to the last 4 bytes). Returns 0 on
/// success, `LR_ERR_NULL` (-1) on a NULL `r` or `out`.
///
/// # Safety
/// `r` must be a valid handle (owned or borrowed). `out` must point
/// to 16 writable bytes.
#[no_mangle]
pub unsafe extern "C" fn lr_babel_route_next_hop(
    r: lr_babel_route_t,
    out: *mut u8,
) -> i32 {
    guarded(
        || unsafe {
            let Some(r) = borrow_route(r) else {
                return LR_ERR_NULL;
            };
            if out.is_null() {
                return LR_ERR_NULL;
            }
            let mut buf = [0u8; 16];
            match r.next_hop {
                IpAddr::V4(b) => buf[12..16].copy_from_slice(&b),
                IpAddr::V6(b) => buf.copy_from_slice(&b),
            }
            unsafe { std::ptr::copy_nonoverlapping(buf.as_ptr(), out, 16) };
            0
        },
        LrError::Panic as i32,
    )
}

/// 1 when the route's feasibility predicate is satisfied (RFC 8966
/// §3.4.4 — the route's seqno is strictly greater than the source's
/// feas-seqno, or the metric is lower). 0 otherwise or on a NULL
/// handle.
#[no_mangle]
pub unsafe extern "C" fn lr_babel_route_feasible(r: lr_babel_route_t) -> u8 {
    guarded(
        || unsafe { borrow_route(r).map(|r| r.feasible as u8).unwrap_or(0) },
        0,
    )
}

/// 1 when the route has been installed into the FIB by the
/// embedder. This is a per-route flag the daemon sets; lr itself
/// never mutates it after `BabelRoute::new`. 0 otherwise or on a
/// NULL handle.
#[no_mangle]
pub unsafe extern "C" fn lr_babel_route_installed(r: lr_babel_route_t) -> u8 {
    guarded(
        || unsafe { borrow_route(r).map(|r| r.installed as u8).unwrap_or(0) },
        0,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::babel::{lr_babel_frame_free, lr_babel_frame_tlv_count};

    fn make_route_key() -> lr_babel_route_key_t {
        let addr = [10u8, 0, 0, 0];
        let rid = [1u8; 8];
        unsafe {
            lr_babel_route_key_new(0, addr.as_ptr(), 8, 0, 0, std::ptr::null(), 0, rid.as_ptr())
        }
    }

    #[test]
    fn ffi_babel_frame_new_empty_round_trip() {
        let f = lr_babel_frame_new_empty();
        assert!(!f.is_null());
        assert_eq!(unsafe { lr_babel_frame_tlv_count(f) }, 0);
        unsafe { lr_babel_frame_free(f) };
    }

    #[test]
    fn ffi_babel_frame_push_tlv_round_trip() {
        let f = lr_babel_frame_new_empty();
        let tlv = lr_babel_tlv_pad1();
        let rc = unsafe { lr_babel_frame_push_tlv(f, tlv) };
        assert_eq!(rc, 0);
        assert_eq!(unsafe { lr_babel_frame_tlv_count(f) }, 1);
        unsafe { lr_babel_frame_free(f) };
    }

    #[test]
    fn ffi_babel_frame_new_from_tlvs_round_trip() {
        let t1 = lr_babel_tlv_pad1();
        let t2 = lr_babel_tlv_pad_n(4);
        let tlvs = [t1, t2];
        let f = unsafe { lr_babel_frame_new_from_tlvs(tlvs.as_ptr(), 2) };
        assert!(!f.is_null());
        assert_eq!(unsafe { lr_babel_frame_tlv_count(f) }, 2);
        unsafe { lr_babel_frame_free(f) };
    }

    #[test]
    fn ffi_babel_tlv_new_round_trip() {
        let value = [0u8; 4];
        let t = unsafe { lr_babel_tlv_new(1, value.as_ptr(), 4) };
        assert!(!t.is_null());
        assert_eq!(unsafe { lr_babel_tlv_kind(t) }, 1); // AckReq
        let mut bytes = lr_bytes_t {
            ptr: std::ptr::null_mut(),
            len: 0,
            cap: 0,
        };
        let rc = unsafe { lr_babel_tlv_value(t, &raw mut bytes) };
        assert_eq!(rc, 0);
        assert_eq!(bytes.len, 4);
        unsafe {
            crate::bytes::lr_bytes_free(&raw mut bytes);
            lr_babel_tlv_free(t);
        }
    }

    #[test]
    fn ffi_babel_tlv_pad_n_zero() {
        let t = lr_babel_tlv_pad_n(0);
        assert!(!t.is_null());
        let mut bytes = lr_bytes_t {
            ptr: std::ptr::null_mut(),
            len: 0,
            cap: 0,
        };
        let rc = unsafe { lr_babel_tlv_value(t, &raw mut bytes) };
        assert_eq!(rc, 0);
        assert_eq!(bytes.len, 0);
        unsafe { lr_babel_tlv_free(t) };
    }

    #[test]
    fn ffi_babel_route_key_round_trip() {
        let k = make_route_key();
        assert!(!k.is_null());
        unsafe { lr_babel_route_key_free(k) };
    }

    #[test]
    fn ffi_babel_route_new_round_trip() {
        let k = make_route_key();
        let next_hop = [10u8, 0, 0, 1];
        let r = unsafe { lr_babel_route_new(k, 1, 100, 0, next_hop.as_ptr(), 0, 0) };
        assert!(!r.is_null());
        unsafe {
            lr_babel_route_free(r);
            lr_babel_route_key_free(k);
        }
    }

    #[test]
    fn ffi_babel_route_new_rejects_null_key() {
        let next_hop = [10u8, 0, 0, 1];
        let r =
            unsafe { lr_babel_route_new(std::ptr::null_mut(), 1, 100, 0, next_hop.as_ptr(), 0, 0) };
        assert!(r.is_null());
    }

    #[test]
    fn ffi_babel_route_table_insert_round_trip() {
        // Round-trip a route through the C ABI mutators. The type fix
        // (lr_babel_route_table_* now take lr_babel_route_table_t,
        // not the generic lr_route_t) is what makes the chain below
        // compile without an explicit cast.
        let t = crate::babel_neighbor::lr_babel_route_table_new();
        assert!(!t.is_null());
        let k = make_route_key();
        let next_hop = [10u8, 0, 0, 1];
        let r = unsafe { lr_babel_route_new(k, 1, 100, 0, next_hop.as_ptr(), 0, 0) };
        assert!(!r.is_null());

        assert_eq!(unsafe { lr_babel_route_table_insert(t, r) }, 0);
        assert_eq!(unsafe { crate::babel_neighbor::lr_babel_route_table_len(t) }, 1);
        assert_eq!(
            unsafe { crate::babel_neighbor::lr_babel_route_table_is_empty(t) },
            0
        );
        assert_eq!(unsafe { lr_babel_route_table_contains(t, k) }, 1);

        let borrowed = unsafe { lr_babel_route_table_get(t, k) };
        assert!(!borrowed.is_null());
        assert_eq!(unsafe { lr_babel_route_seqno(borrowed) }, 1);
        assert_eq!(unsafe { lr_babel_route_metric(borrowed) }, 100);
        assert_eq!(unsafe { lr_babel_route_next_hop_is_ipv6(borrowed) }, 0);
        let mut out = [0u8; 16];
        assert_eq!(unsafe { lr_babel_route_next_hop(borrowed, out.as_mut_ptr()) }, 0);
        assert_eq!(&out[12..16], &[10, 0, 0, 1]);
        // The table marks a freshly-inserted route feasible when no
        // prior feasibility record exists (RFC 8966 §3.5.2 — a route
        // from a new source is feasible by default). The `feasible=0`
        // flag passed at construction is overwritten on insert.
        assert_eq!(unsafe { lr_babel_route_feasible(borrowed) }, 1);
        assert_eq!(unsafe { lr_babel_route_installed(borrowed) }, 0);

        assert_eq!(unsafe { lr_babel_route_table_withdraw(t, k) }, 0);
        assert_eq!(unsafe { crate::babel_neighbor::lr_babel_route_table_len(t) }, 0);

        unsafe {
            lr_babel_route_free(r);
            lr_babel_route_key_free(k);
            crate::babel_neighbor::lr_babel_route_table_free(t);
        }
    }

    #[test]
    fn ffi_babel_route_table_best_routes_count_round_trip() {
        let t = crate::babel_neighbor::lr_babel_route_table_new();
        let k = make_route_key();
        let next_hop = [10u8, 0, 0, 1];
        let r = unsafe { lr_babel_route_new(k, 1, 100, 0, next_hop.as_ptr(), 0, 0) };
        assert_eq!(unsafe { lr_babel_route_table_insert(t, r) }, 0);
        assert_eq!(unsafe { lr_babel_route_table_best_routes_count(t) }, 1);
        unsafe {
            lr_babel_route_free(r);
            lr_babel_route_key_free(k);
            crate::babel_neighbor::lr_babel_route_table_free(t);
        }
    }

    #[test]
    fn ffi_babel_route_table_iter_walks_inserted_routes() {
        let t = crate::babel_neighbor::lr_babel_route_table_new();
        let k = make_route_key();
        let next_hop = [10u8, 0, 0, 1];
        let r = unsafe { lr_babel_route_new(k, 1, 100, 0, next_hop.as_ptr(), 0, 0) };
        assert_eq!(unsafe { lr_babel_route_table_insert(t, r) }, 0);

        extern "C" fn cb(_route: lr_babel_route_t, user: *mut std::ffi::c_void) -> i32 {
            unsafe {
                let count: *mut usize = user as *mut usize;
                *count += 1;
            }
            0
        }
        let mut count: usize = 0;
        let rc = unsafe { lr_babel_route_table_iter(t, Some(cb), &mut count as *mut _ as *mut _) };
        assert_eq!(rc, 0);
        assert_eq!(count, 1);

        let rc = unsafe {
            lr_babel_route_table_best_routes_iter(t, Some(cb), &mut count as *mut _ as *mut _)
        };
        assert_eq!(rc, 0);
        assert_eq!(count, 2);

        unsafe {
            lr_babel_route_free(r);
            lr_babel_route_key_free(k);
            crate::babel_neighbor::lr_babel_route_table_free(t);
        }
    }

    #[test]
    fn ffi_babel_route_table_iter_stops_early_on_nonzero_callback() {
        let t = crate::babel_neighbor::lr_babel_route_table_new();
        let k = make_route_key();
        let next_hop = [10u8, 0, 0, 1];
        let r = unsafe { lr_babel_route_new(k, 1, 100, 0, next_hop.as_ptr(), 0, 0) };
        assert_eq!(unsafe { lr_babel_route_table_insert(t, r) }, 0);

        extern "C" fn cb(_r: lr_babel_route_t, _u: *mut std::ffi::c_void) -> i32 {
            42
        }
        let rc = unsafe { lr_babel_route_table_iter(t, Some(cb), std::ptr::null_mut()) };
        assert_eq!(rc, 42);

        unsafe {
            lr_babel_route_free(r);
            lr_babel_route_key_free(k);
            crate::babel_neighbor::lr_babel_route_table_free(t);
        }
    }

    #[test]
    fn ffi_babel_route_table_iter_rejects_null_cb() {
        let t = crate::babel_neighbor::lr_babel_route_table_new();
        let rc = unsafe { lr_babel_route_table_iter(t, None, std::ptr::null_mut()) };
        assert_eq!(rc, LR_ERR_NULL);
        unsafe { crate::babel_neighbor::lr_babel_route_table_free(t) };
    }

    #[test]
    fn ffi_babel_route_table_get_returns_null_for_missing_key() {
        let t = crate::babel_neighbor::lr_babel_route_table_new();
        let k = make_route_key();
        let r = unsafe { lr_babel_route_table_get(t, k) };
        assert!(r.is_null());
        unsafe {
            lr_babel_route_key_free(k);
            crate::babel_neighbor::lr_babel_route_table_free(t);
        }
    }

    #[test]
    fn ffi_babel_route_key_accessors_round_trip_v4() {
        let addr = [10u8, 0, 0, 0];
        let rid = [1u8; 8];
        let k = unsafe {
            lr_babel_route_key_new(0, addr.as_ptr(), 8, 0, 0, std::ptr::null(), 0, rid.as_ptr())
        };
        assert!(!k.is_null());
        assert_eq!(unsafe { lr_babel_route_key_destination_is_ipv6(k) }, 0);
        let mut out = [0u8; 16];
        assert_eq!(unsafe { lr_babel_route_key_destination_addr(k, out.as_mut_ptr()) }, 0);
        assert_eq!(&out[12..16], &[10, 0, 0, 0]);
        assert_eq!(unsafe { lr_babel_route_key_destination_prefix_len(k) }, 8);
        assert_eq!(unsafe { lr_babel_route_key_source_present(k) }, 0);
        let mut rid_out = [0u8; 8];
        assert_eq!(unsafe { lr_babel_route_key_router_id(k, rid_out.as_mut_ptr()) }, 0);
        assert_eq!(rid_out, rid);
        unsafe { lr_babel_route_key_free(k) };
    }

    #[test]
    fn ffi_babel_route_key_accessors_round_trip_v6_with_source() {
        let addr = [0xfe_u8, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let src = [0xfd_u8, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let rid = [2u8; 8];
        let k = unsafe {
            lr_babel_route_key_new(
                1,
                addr.as_ptr(),
                64,
                1,
                1,
                src.as_ptr(),
                48,
                rid.as_ptr(),
            )
        };
        assert!(!k.is_null());
        assert_eq!(unsafe { lr_babel_route_key_destination_is_ipv6(k) }, 1);
        let mut out = [0u8; 16];
        assert_eq!(unsafe { lr_babel_route_key_destination_addr(k, out.as_mut_ptr()) }, 0);
        assert_eq!(out, addr);
        assert_eq!(unsafe { lr_babel_route_key_destination_prefix_len(k) }, 64);
        assert_eq!(unsafe { lr_babel_route_key_source_present(k) }, 1);
        assert_eq!(unsafe { lr_babel_route_key_source_is_ipv6(k) }, 1);
        let mut sout = [0u8; 16];
        assert_eq!(unsafe { lr_babel_route_key_source_addr(k, sout.as_mut_ptr()) }, 0);
        assert_eq!(sout, src);
        assert_eq!(unsafe { lr_babel_route_key_source_prefix_len(k) }, 48);
        unsafe { lr_babel_route_key_free(k) };
    }

    #[test]
    fn ffi_babel_route_key_source_addr_rejects_missing_source() {
        let addr = [10u8, 0, 0, 0];
        let rid = [1u8; 8];
        let k = unsafe {
            lr_babel_route_key_new(0, addr.as_ptr(), 8, 0, 0, std::ptr::null(), 0, rid.as_ptr())
        };
        let mut sout = [0u8; 16];
        let rc = unsafe { lr_babel_route_key_source_addr(k, sout.as_mut_ptr()) };
        assert_eq!(rc, LR_ERR_INVALID_HANDLE);
        unsafe { lr_babel_route_key_free(k) };
    }

    #[test]
    fn ffi_babel_route_table_insert_rejects_null_table() {
        let k = make_route_key();
        let next_hop = [10u8, 0, 0, 1];
        let r = unsafe { lr_babel_route_new(k, 1, 100, 0, next_hop.as_ptr(), 0, 0) };
        let rc = unsafe { lr_babel_route_table_insert(std::ptr::null_mut(), r) };
        assert_eq!(rc, LR_ERR_NULL);
        unsafe {
            lr_babel_route_free(r);
            lr_babel_route_key_free(k);
        }
    }

    #[test]
    fn ffi_babel_route_table_insert_rejects_null_route() {
        let t = crate::babel_neighbor::lr_babel_route_table_new();
        let rc = unsafe { lr_babel_route_table_insert(t, std::ptr::null_mut()) };
        assert_eq!(rc, LR_ERR_NULL);
        unsafe { crate::babel_neighbor::lr_babel_route_table_free(t) };
    }

    #[test]
    fn ffi_babel_route_table_withdraw_rejects_null_table() {
        let k = make_route_key();
        let rc = unsafe { lr_babel_route_table_withdraw(std::ptr::null_mut(), k) };
        assert_eq!(rc, LR_ERR_NULL);
        unsafe { lr_babel_route_key_free(k) };
    }

    #[test]
    fn ffi_babel_route_table_expire_returns_zero_on_null() {
        let n = unsafe { lr_babel_route_table_expire(std::ptr::null_mut(), 0) };
        assert_eq!(n, 0);
    }

    #[test]
    fn ffi_babel_frame_push_tlv_rejects_null() {
        let tlv = lr_babel_tlv_pad1();
        let rc = unsafe { lr_babel_frame_push_tlv(std::ptr::null_mut(), tlv) };
        assert_eq!(rc, LR_ERR_NULL);
        // The TLV handle is NOT consumed on the null-frame path —
        // free it explicitly.
        unsafe { lr_babel_tlv_free(tlv) };
    }

    #[test]
    fn ffi_babel_tlv_value_rejects_null() {
        let t = lr_babel_tlv_pad1();
        let rc = unsafe { lr_babel_tlv_value(t, std::ptr::null_mut()) };
        assert_eq!(rc, LR_ERR_NULL);
        unsafe { lr_babel_tlv_free(t) };
    }

    #[test]
    fn ffi_babel_tlv_value_rejects_null_handle() {
        let mut bytes = lr_bytes_t {
            ptr: std::ptr::null_mut(),
            len: 0,
            cap: 0,
        };
        let rc = unsafe { lr_babel_tlv_value(std::ptr::null_mut(), &raw mut bytes) };
        assert_eq!(rc, LR_ERR_NULL);
    }

    #[test]
    fn ffi_babel_route_key_new_rejects_null_addr() {
        let rid = [1u8; 8];
        let k = unsafe {
            lr_babel_route_key_new(
                0,
                std::ptr::null(),
                8,
                0,
                0,
                std::ptr::null(),
                0,
                rid.as_ptr(),
            )
        };
        assert!(k.is_null());
    }

    #[test]
    fn ffi_babel_route_key_new_rejects_null_router_id() {
        let addr = [10u8, 0, 0, 0];
        let k = unsafe {
            lr_babel_route_key_new(
                0,
                addr.as_ptr(),
                8,
                0,
                0,
                std::ptr::null(),
                0,
                std::ptr::null(),
            )
        };
        assert!(k.is_null());
    }
}
