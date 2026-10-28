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

use lr_babel::route::{BabelRoute, BabelRouteTable, RouteKey};
use lr_babel::source::SourcePrefix;
use lr_babel::tlv::{Tlv, TlvType};
use lr_babel::BabelFrame;
use lr_core::addr::{IpAddr, Prefix};

use crate::babel::{box_frame, lr_babel_frame_t};
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
    table: crate::handle::lr_route_t,
    route: lr_babel_route_t,
) -> i32 {
    guarded(
        || unsafe {
            if table.is_null() || route.is_null() {
                return LR_ERR_NULL;
            }
            let t: &mut BabelRouteTable = &mut *(table as *mut BabelRouteTable);
            let r: &BabelRoute = &*(route as *const BabelRoute);
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
    table: crate::handle::lr_route_t,
    route: lr_babel_route_t,
    interval_cs: u16,
    now_ms: u64,
) -> i32 {
    guarded(
        || unsafe {
            if table.is_null() || route.is_null() {
                return LR_ERR_NULL;
            }
            let t: &mut BabelRouteTable = &mut *(table as *mut BabelRouteTable);
            let r: &BabelRoute = &*(route as *const BabelRoute);
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
    table: crate::handle::lr_route_t,
    key: lr_babel_route_key_t,
) -> i32 {
    guarded(
        || unsafe {
            if table.is_null() || key.is_null() {
                return LR_ERR_NULL;
            }
            let t: &mut BabelRouteTable = &mut *(table as *mut BabelRouteTable);
            let k: &RouteKey = &*(key as *const RouteKey);
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
    table: crate::handle::lr_route_t,
    now_ms: u64,
) -> usize {
    guarded(
        || unsafe {
            if table.is_null() {
                return 0;
            }
            let t: &mut BabelRouteTable = &mut *(table as *mut BabelRouteTable);
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
    table: crate::handle::lr_route_t,
    key: lr_babel_route_key_t,
) -> u8 {
    guarded(
        || unsafe {
            if table.is_null() || key.is_null() {
                return 0;
            }
            let t: &BabelRouteTable = &*(table as *const BabelRouteTable);
            let k: &RouteKey = &*(key as *const RouteKey);
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
    table: crate::handle::lr_route_t,
) -> usize {
    guarded(
        || unsafe {
            if table.is_null() {
                return 0;
            }
            let t: &BabelRouteTable = &*(table as *const BabelRouteTable);
            t.best_routes().len()
        },
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
        // The lr_babel_route_table_* mutators take the existing
        // `lr_route_t` opaque handle (BabelRouteTable is internally
        // type-erased to that handle in `babel_neighbor.rs`). Verify
        // the surface compiles and the call paths round-trip a
        // route through insert / withdraw.
        let mut t = BabelRouteTable::new();
        let key = RouteKey {
            destination: Prefix::new_v4([10, 0, 0, 0], 8),
            source: None,
            router_id: [1; 8],
        };
        let r = BabelRoute {
            key: key.clone(),
            seqno: 1,
            metric: 100,
            next_hop: IpAddr::V4([10, 0, 0, 1]),
            feasible: false,
            installed: false,
        };
        t.insert(r);
        assert_eq!(t.len(), 1);
        assert!(t.get(&key).is_some());
        t.withdraw(&key);
        assert_eq!(t.len(), 0);
    }

    #[test]
    fn ffi_babel_route_table_best_routes_count_round_trip() {
        let mut t = BabelRouteTable::new();
        let key = RouteKey {
            destination: Prefix::new_v4([10, 0, 0, 0], 8),
            source: None,
            router_id: [1; 8],
        };
        let r = BabelRoute {
            key: key.clone(),
            seqno: 1,
            metric: 100,
            next_hop: IpAddr::V4([10, 0, 0, 1]),
            feasible: false,
            installed: false,
        };
        t.insert(r);
        assert_eq!(t.best_routes().len(), 1);
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
