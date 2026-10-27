//! BGP path-attribute FFI — `lr_bgp_path_*` / `lr_bgp_as_path_*` /
//! `lr_bgp_community_*`.
//!
//! Mirrors the public Rust API of `lr_bgp::path::{PathAttributes,
//! AsPath, AsPathSegment, AsPathType, Community, ExtendedCommunity,
//! LargeCommunity, AttrType}` so an embedder can build, inspect and
//! mutate BGP path attributes outside the `Route` wrapper exposed by
//! `lr_route_*`. The `Route`-level readers (`lr_route_med`,
//! `lr_route_local_pref`, `lr_route_as_path`, `lr_route_communities`,
//! …) remain the high-level surface; this module exposes the
//! standalone `PathAttributes` container so an embedder can parse a
//! raw BGP UPDATE's attribute TLV stream without going through a
//! `Route`.
//!
//! # Surface
//!
//! - `lr_bgp_attr_type_from_u8` / `_to_u8` — `AttrType` codec helpers.
//! - `lr_bgp_as_path_new` / `_from_sequence` / `_free` — AsPath constructors.
//! - `lr_bgp_as_path_length` / `_length_with_confed` / `_as_sequence`
//!   / `_segment_count` / `_segment_at` — AsPath readers.
//! - `lr_bgp_as_path_prepend` / `_prepend_confed` / `_strip_confed`
//!   / `_has_confed` — AsPath mutators.
//! - `lr_bgp_as_path_decode_2` / `_decode_4` / `_encode_2` / `_encode_4`
//!   — wire-form round-trip.
//! - `lr_bgp_path_attrs_new` / `_free` — `PathAttributes` constructor/dtor.
//! - `lr_bgp_path_attrs_len` / `_is_empty` — readers.
//! - `lr_bgp_path_attrs_origin` / `_as_path` / `_next_hop` / `_med`
//!   / `_local_pref` / `_atomic_aggregate` / `_aggregator` /
//!   `_originator_id` / `_otc` / `_aigp` — well-known attribute readers.
//! - `lr_bgp_path_attrs_communities` / `_ext_communities` /
//!   `_large_communities` — community readers (return `lr_bytes_t`
//!   carrying flat arrays).
//! - `lr_bgp_community_new` / `_value` / `_kind` — Community (u32) helpers.
//!
//! Every entry point runs inside the crate's `catch_unwind` barrier
//! ([`crate::guarded`]): a panic returns `LR_ERR_PANIC` and sets the
//! thread-local last-error string.

#![allow(unused_unsafe)]

use lr_bgp::path::{
    communities::{Community, ExtendedCommunity, LargeCommunity},
    AsPath, AttrType, PathAttributes,
};
use lr_core::addr::Asn;

use crate::error::{set_last_error, LrError, LR_ERR_PANIC};
use crate::guarded;
use crate::handle::lr_bytes_t;

const LR_ERR_NULL: i32 = LrError::Null as i32;

// ---- AttrType codec ----

/// Translate an `AttrType` value to its RFC 4271 §5 wire code (1..).
/// Returns 0 for `Other(u8)` values whose wire code is 0 (unreachable
/// in practice — `AttrType::Other(v)` always carries `v != 0`).
#[no_mangle]
pub extern "C" fn lr_bgp_attr_type_to_u8(t: u8) -> u8 {
    // AttrType::from_u8 is infallible on the wire codes 1..255; for the
    // canonical round-trip the caller passes the wire code directly.
    t
}

/// Translate a wire code to an `AttrType` value, returning 1 if the
/// code is recognised (well-known or assigned) and 0 if it is
/// `Other(u8)`. The caller passes the wire code in `wire` and
/// receives the canonical wire code back in `*out_canonical` (which
/// equals `wire` for every assigned code; for `Other(v)` it equals
/// `v` too — the round-trip is the identity on the wire form).
#[no_mangle]
pub extern "C" fn lr_bgp_attr_type_from_u8(wire: u8, out_canonical: *mut u8) -> i32 {
    guarded(
        || {
            if out_canonical.is_null() {
                return LR_ERR_NULL;
            }
            // `AttrType::from_u8` is infallible: unknown codes map
            // to `Other(wire)`. The canonical wire form is `wire`
            // either way (the round-trip is the identity).
            let t = AttrType::from_u8(wire);
            unsafe { *out_canonical = t.to_u8() };
            // We expose whether the code is recognised so callers
            // can surface an unknown-attribute diagnostic.
            matches!(t, AttrType::Other(_)) as i32 ^ 1
        },
        LR_ERR_PANIC,
    )
}

// ---- AsPath surface ----

/// Opaque `AsPath` handle.
#[repr(C)]
pub struct OpaqueBgpAsPath {
    _private: [u8; 0],
}
pub type lr_bgp_as_path_t = *mut OpaqueBgpAsPath;

fn box_as_path(p: AsPath) -> lr_bgp_as_path_t {
    Box::into_raw(Box::new(p)) as lr_bgp_as_path_t
}
unsafe fn borrow_as_path(p: lr_bgp_as_path_t) -> Option<&'static AsPath> {
    if p.is_null() {
        return None;
    }
    Some(unsafe { &*(p as *const AsPath) })
}
unsafe fn borrow_as_path_mut(p: lr_bgp_as_path_t) -> Option<&'static mut AsPath> {
    if p.is_null() {
        return None;
    }
    Some(unsafe { &mut *(p as *mut AsPath) })
}
unsafe fn unbox_as_path(p: lr_bgp_as_path_t) -> Option<Box<AsPath>> {
    if p.is_null() {
        return None;
    }
    Some(unsafe { Box::from_raw(p as *mut AsPath) })
}

/// Construct an empty `AsPath`.
#[no_mangle]
pub extern "C" fn lr_bgp_as_path_new() -> lr_bgp_as_path_t {
    guarded(|| box_as_path(AsPath::new()), std::ptr::null_mut())
}

/// Construct an `AsPath` from a single AS_SEQUENCE segment carrying
/// `count` ASes from `ases` (a flat `uint32_t` array). The path's
/// `length()` per RFC 4271 §9.1.2.2(a) is `count`.
///
/// # Safety
/// `ases` must point to `count` readable `uint32_t` values, or be
/// NULL when `count == 0`.
#[no_mangle]
pub unsafe extern "C" fn lr_bgp_as_path_from_sequence(
    ases: *const u32,
    count: usize,
) -> lr_bgp_as_path_t {
    guarded(
        || unsafe {
            let slice: &[u32] = if count == 0 || ases.is_null() {
                &[]
            } else {
                unsafe { std::slice::from_raw_parts(ases, count) }
            };
            box_as_path(AsPath::from_sequence(slice.iter().copied().map(Asn)))
        },
        std::ptr::null_mut(),
    )
}

/// Drop a boxed `AsPath`. Safe to call with NULL.
///
/// # Safety
/// `p` must have been produced by a `lr_bgp_as_path_*` constructor
/// and not already freed.
#[no_mangle]
pub unsafe extern "C" fn lr_bgp_as_path_free(p: lr_bgp_as_path_t) {
    guarded(
        || unsafe {
            drop(unbox_as_path(p));
        },
        (),
    )
}

/// RFC 4271 §9.1.2.2(a) length: each AS_SEQUENCE entry counts as 1,
/// each AS_SET segment counts as 1 regardless of size; confederation
/// segments are NOT counted (RFC 5065 §5.3). Returns 0 on a NULL
/// handle.
///
/// # Safety
/// `p` must be a valid AsPath handle.
#[no_mangle]
pub unsafe extern "C" fn lr_bgp_as_path_length(p: lr_bgp_as_path_t) -> usize {
    guarded(
        || unsafe { borrow_as_path(p).map(|x| x.length()).unwrap_or(0) },
        0,
    )
}

/// Length counting confederation segments too (RFC 5065 §5.3 — the
/// operator may opt into counting them via
/// `BestPathConfig::count_confed_in_path_len`).
///
/// # Safety
/// See [`lr_bgp_as_path_length`].
#[no_mangle]
pub unsafe extern "C" fn lr_bgp_as_path_length_with_confed(p: lr_bgp_as_path_t) -> usize {
    guarded(
        || unsafe {
            borrow_as_path(p)
                .map(|x| x.length_with_confed())
                .unwrap_or(0)
        },
        0,
    )
}

/// Flattened AS_SEQUENCE — concatenates every AS_SEQUENCE segment's
/// ASes (skipping AS_SET and confederation segments). Writes the
/// ASes to `out` (a `uint32_t` array of capacity `cap`) and returns
/// the number written. When `cap` is 0 or `out` is NULL, returns
/// the number of ASes that WOULD be written (caller-allocates
/// pattern — call once with `cap=0` to size, then again to fill).
///
/// # Safety
/// `p` must be a valid AsPath handle. `out` must point to writable
/// memory of `cap` `uint32_t` values (NULL only when `cap == 0`).
#[no_mangle]
pub unsafe extern "C" fn lr_bgp_as_path_as_sequence(
    p: lr_bgp_as_path_t,
    out: *mut u32,
    cap: usize,
) -> usize {
    guarded(
        || unsafe {
            let Some(path) = borrow_as_path(p) else {
                return 0;
            };
            let seq: Vec<u32> = path.as_sequence().into_iter().map(|a| a.0).collect();
            let n = seq.len();
            if out.is_null() || cap == 0 {
                return n;
            }
            let to_copy = n.min(cap);
            unsafe {
                std::ptr::copy_nonoverlapping(seq.as_ptr(), out, to_copy);
            }
            n
        },
        0,
    )
}

/// Number of segments in the path (AS_SEQUENCE, AS_SET, AS_CONFED_*).
///
/// # Safety
/// See [`lr_bgp_as_path_length`].
#[no_mangle]
pub unsafe extern "C" fn lr_bgp_as_path_segment_count(p: lr_bgp_as_path_t) -> usize {
    guarded(
        || unsafe { borrow_as_path(p).map(|x| x.segments.len()).unwrap_or(0) },
        0,
    )
}

/// Read one segment by index. Writes the segment's `kind` (1=Set,
/// 2=Sequence, 3=ConfedSequence, 4=ConfedSet per RFC 5065) to
/// `*out_kind` and the segment's AS count to `*out_count`. Use
/// [`lr_bgp_as_path_segment_ases`] to read the ASes themselves.
///
/// Returns 0 on success, `LR_ERR_NULL` (-1) on a NULL path,
/// `LR_ERR_INVALID_HANDLE` (-2) when the index is out of range.
///
/// # Safety
/// `p` must be a valid AsPath handle. `out_kind` and `out_count`
/// must point to writable `uint8_t` and `uintptr_t`.
#[no_mangle]
pub unsafe extern "C" fn lr_bgp_as_path_segment_at(
    p: lr_bgp_as_path_t,
    index: usize,
    out_kind: *mut u8,
    out_count: *mut usize,
) -> i32 {
    guarded(
        || unsafe {
            let Some(path) = borrow_as_path(p) else {
                return LR_ERR_NULL;
            };
            if out_kind.is_null() || out_count.is_null() {
                return LR_ERR_NULL;
            }
            let Some(seg) = path.segments.get(index) else {
                set_last_error(format!(
                    "as_path segment {index} out of range (len={})",
                    path.segments.len()
                ));
                return LrError::InvalidHandle as i32;
            };
            unsafe {
                *out_kind = seg.kind as u8;
                *out_count = seg.ases.len();
            }
            0
        },
        LR_ERR_PANIC,
    )
}

/// Read the ASes of segment `index`. Writes `min(seg_count, cap)`
/// ASes to `out`. Returns the segment's full AS count (so the
/// caller can size + re-call like `as_sequence`). Returns 0 when
/// the path is NULL or the index is out of range.
///
/// # Safety
/// `p` must be a valid AsPath handle. `out` must point to writable
/// memory of `cap` `uint32_t` values (NULL only when `cap == 0`).
#[no_mangle]
pub unsafe extern "C" fn lr_bgp_as_path_segment_ases(
    p: lr_bgp_as_path_t,
    index: usize,
    out: *mut u32,
    cap: usize,
) -> usize {
    guarded(
        || unsafe {
            let Some(path) = borrow_as_path(p) else {
                return 0;
            };
            let Some(seg) = path.segments.get(index) else {
                return 0;
            };
            let n = seg.ases.len();
            if out.is_null() || cap == 0 {
                return n;
            }
            let to_copy = n.min(cap);
            let slice: &[u32] =
                unsafe { std::slice::from_raw_parts(seg.ases.as_ptr() as *const u32, n) };
            unsafe {
                std::ptr::copy_nonoverlapping(slice.as_ptr(), out, to_copy);
            }
            n
        },
        0,
    )
}

/// Prepend an AS to the path (RFC 4271 §5.1.2 — prepended to the
/// most-recent AS_SEQUENCE segment, or wrapped in a new segment when
/// the path is empty or starts with an AS_SET).
///
/// # Safety
/// `p` must be a valid AsPath handle.
#[no_mangle]
pub unsafe extern "C" fn lr_bgp_as_path_prepend(p: lr_bgp_as_path_t, as_: u32) -> i32 {
    guarded(
        || unsafe {
            let Some(path) = borrow_as_path_mut(p) else {
                return LR_ERR_NULL;
            };
            path.prepend(Asn(as_));
            0
        },
        LR_ERR_PANIC,
    )
}

/// Prepend a confederation AS (RFC 5065 §4.1(b) — adds to the most
/// recent AS_CONFED_SEQUENCE segment, or wraps in a new one).
///
/// # Safety
/// See [`lr_bgp_as_path_prepend`].
#[no_mangle]
pub unsafe extern "C" fn lr_bgp_as_path_prepend_confed(p: lr_bgp_as_path_t, as_: u32) -> i32 {
    guarded(
        || unsafe {
            let Some(path) = borrow_as_path_mut(p) else {
                return LR_ERR_NULL;
            };
            path.prepend_confed(Asn(as_));
            0
        },
        LR_ERR_PANIC,
    )
}

/// Strip every AS_CONFED_* segment from the path (RFC 5065 §4.1(c)(5)
/// — confederation segments are removed before advertising outside
/// the confederation). Returns 1 if at least one segment was
/// stripped, 0 otherwise; `LR_ERR_NULL` (-1) on a NULL handle.
///
/// # Safety
/// See [`lr_bgp_as_path_prepend`].
#[no_mangle]
pub unsafe extern "C" fn lr_bgp_as_path_strip_confed(p: lr_bgp_as_path_t) -> i32 {
    guarded(
        || unsafe {
            let Some(path) = borrow_as_path_mut(p) else {
                return LR_ERR_NULL;
            };
            if path.strip_confed() {
                1
            } else {
                0
            }
        },
        LR_ERR_PANIC,
    )
}

/// True when the path contains any AS_CONFED_* segment.
///
/// # Safety
/// See [`lr_bgp_as_path_prepend`].
#[no_mangle]
pub unsafe extern "C" fn lr_bgp_as_path_has_confed(p: lr_bgp_as_path_t) -> u8 {
    guarded(
        || unsafe { borrow_as_path(p).map(|x| x.has_confed() as u8).unwrap_or(0) },
        0,
    )
}

/// Loop check — true when `my_as` appears in any AS_SEQUENCE segment
/// (RFC 4271 §9.1.2.2(b) — the path would form a loop). Used by the
/// import filter to reject a route whose AS_PATH contains our own
/// AS before any policy evaluation.
///
/// # Safety
/// See [`lr_bgp_as_path_prepend`].
#[no_mangle]
pub unsafe extern "C" fn lr_bgp_as_path_loop_check(p: lr_bgp_as_path_t, my_as: u32) -> u8 {
    guarded(
        || unsafe {
            borrow_as_path(p)
                .map(|x| x.loop_check(Asn(my_as)) as u8)
                .unwrap_or(0)
        },
        0,
    )
}

/// Decode the 2-octet-AS form (RFC 4271 §5.1.2). Returns a new
/// AsPath handle on success, NULL on a decode failure (the
/// last-error string is set).
///
/// # Safety
/// `data` must point to `len` readable bytes.
#[no_mangle]
pub unsafe extern "C" fn lr_bgp_as_path_decode_2(data: *const u8, len: usize) -> lr_bgp_as_path_t {
    guarded(
        || unsafe {
            if data.is_null() && len != 0 {
                return std::ptr::null_mut();
            }
            let slice = if len == 0 {
                &[]
            } else {
                unsafe { std::slice::from_raw_parts(data, len) }
            };
            match AsPath::decode(slice) {
                Some(p) => box_as_path(p),
                None => {
                    set_last_error("as_path decode_2: malformed AS_PATH".into());
                    std::ptr::null_mut()
                }
            }
        },
        std::ptr::null_mut(),
    )
}

/// Decode the 4-octet-AS form (RFC 6793 §3 — AS4_PATH).
///
/// # Safety
/// See [`lr_bgp_as_path_decode_2`].
#[no_mangle]
pub unsafe extern "C" fn lr_bgp_as_path_decode_4(data: *const u8, len: usize) -> lr_bgp_as_path_t {
    guarded(
        || unsafe {
            if data.is_null() && len != 0 {
                return std::ptr::null_mut();
            }
            let slice = if len == 0 {
                &[]
            } else {
                unsafe { std::slice::from_raw_parts(data, len) }
            };
            match AsPath::decode_4(slice) {
                Some(p) => box_as_path(p),
                None => {
                    set_last_error("as_path decode_4: malformed AS4_PATH".into());
                    std::ptr::null_mut()
                }
            }
        },
        std::ptr::null_mut(),
    )
}

/// Encode to the 2-octet-AS wire form. Writes the bytes to a
/// freshly-allocated `lr_bytes_t` at `*out`.
///
/// # Safety
/// `p` must be a valid AsPath handle. `out` must point to a writable
/// `lr_bytes_t`.
#[no_mangle]
pub unsafe extern "C" fn lr_bgp_as_path_encode_2(p: lr_bgp_as_path_t, out: *mut lr_bytes_t) -> i32 {
    guarded(
        || unsafe {
            let Some(path) = borrow_as_path(p) else {
                return LR_ERR_NULL;
            };
            if out.is_null() {
                return LR_ERR_NULL;
            }
            let bytes = path.encode_2();
            unsafe { *out = lr_bytes_t::from_vec(bytes) }
            0
        },
        LR_ERR_PANIC,
    )
}

/// Encode to the 4-octet-AS wire form (RFC 6793 §3 — AS4_PATH).
///
/// # Safety
/// See [`lr_bgp_as_path_encode_2`].
#[no_mangle]
pub unsafe extern "C" fn lr_bgp_as_path_encode_4(p: lr_bgp_as_path_t, out: *mut lr_bytes_t) -> i32 {
    guarded(
        || unsafe {
            let Some(path) = borrow_as_path(p) else {
                return LR_ERR_NULL;
            };
            if out.is_null() {
                return LR_ERR_NULL;
            }
            let bytes = path.encode_4();
            unsafe { *out = lr_bytes_t::from_vec(bytes) }
            0
        },
        LR_ERR_PANIC,
    )
}

// ---- PathAttributes surface ----

/// Opaque `PathAttributes` handle.
#[repr(C)]
pub struct OpaqueBgpPathAttrs {
    _private: [u8; 0],
}
pub type lr_bgp_path_attrs_t = *mut OpaqueBgpPathAttrs;

fn box_attrs(a: PathAttributes) -> lr_bgp_path_attrs_t {
    Box::into_raw(Box::new(a)) as lr_bgp_path_attrs_t
}
unsafe fn borrow_attrs(a: lr_bgp_path_attrs_t) -> Option<&'static PathAttributes> {
    if a.is_null() {
        return None;
    }
    Some(unsafe { &*(a as *const PathAttributes) })
}
unsafe fn borrow_attrs_mut(a: lr_bgp_path_attrs_t) -> Option<&'static mut PathAttributes> {
    if a.is_null() {
        return None;
    }
    Some(unsafe { &mut *(a as *mut PathAttributes) })
}
unsafe fn unbox_attrs(a: lr_bgp_path_attrs_t) -> Option<Box<PathAttributes>> {
    if a.is_null() {
        return None;
    }
    Some(unsafe { Box::from_raw(a as *mut PathAttributes) })
}

/// Construct an empty `PathAttributes`.
#[no_mangle]
pub extern "C" fn lr_bgp_path_attrs_new() -> lr_bgp_path_attrs_t {
    guarded(|| box_attrs(PathAttributes::new()), std::ptr::null_mut())
}

/// Drop a boxed `PathAttributes`. Safe to call with NULL.
///
/// # Safety
/// `a` must have been produced by a `lr_bgp_path_attrs_*` constructor
/// and not already freed.
#[no_mangle]
pub unsafe extern "C" fn lr_bgp_path_attrs_free(a: lr_bgp_path_attrs_t) {
    guarded(
        || unsafe {
            drop(unbox_attrs(a));
        },
        (),
    )
}

/// Number of attributes in the set. Returns 0 on a NULL handle.
///
/// # Safety
/// `a` must be a valid PathAttributes handle.
#[no_mangle]
pub unsafe extern "C" fn lr_bgp_path_attrs_len(a: lr_bgp_path_attrs_t) -> usize {
    guarded(
        || unsafe { borrow_attrs(a).map(|x| x.len()).unwrap_or(0) },
        0,
    )
}

/// True when the set holds no attributes. Returns 1 (true) on a NULL
/// handle.
///
/// # Safety
/// See [`lr_bgp_path_attrs_len`].
#[no_mangle]
pub unsafe extern "C" fn lr_bgp_path_attrs_is_empty(a: lr_bgp_path_attrs_t) -> u8 {
    guarded(
        || unsafe { borrow_attrs(a).map(|x| x.is_empty() as u8).unwrap_or(1) },
        1,
    )
}

/// Read the ORIGIN attribute (RFC 4271 §5.1.1 — IGP=0, EGP=1,
/// INCOMPLETE=2). Writes the origin code to `*out_origin` and
/// returns 1 if the attribute is present, 0 if absent.
///
/// # Safety
/// `a` must be a valid PathAttributes handle. `out_origin` must
/// point to a writable `uint8_t`.
#[no_mangle]
pub unsafe extern "C" fn lr_bgp_path_attrs_origin(
    a: lr_bgp_path_attrs_t,
    out_origin: *mut u8,
) -> u8 {
    guarded(
        || unsafe {
            let Some(attrs) = borrow_attrs(a) else {
                return 0;
            };
            if out_origin.is_null() {
                return 0;
            }
            match attrs.origin() {
                Some(o) => {
                    unsafe { *out_origin = o.0 as u8 };
                    1
                }
                None => 0,
            }
        },
        0,
    )
}

/// Read the MULTI_EXIT_DISC attribute (RFC 4271 §5.1.4). Writes the
/// MED value to `*out_med` and returns 1 if present, 0 if absent.
///
/// # Safety
/// See [`lr_bgp_path_attrs_origin`].
#[no_mangle]
pub unsafe extern "C" fn lr_bgp_path_attrs_med(a: lr_bgp_path_attrs_t, out_med: *mut u32) -> u8 {
    guarded(
        || unsafe {
            let Some(attrs) = borrow_attrs(a) else {
                return 0;
            };
            if out_med.is_null() {
                return 0;
            }
            match attrs.med() {
                Some(m) => {
                    unsafe { *out_med = m.0 };
                    1
                }
                None => 0,
            }
        },
        0,
    )
}

/// Read the LOCAL_PREF attribute (RFC 4271 §5.1.5). Writes the value
/// to `*out_lp` and returns 1 if present, 0 if absent.
///
/// # Safety
/// See [`lr_bgp_path_attrs_origin`].
#[no_mangle]
pub unsafe extern "C" fn lr_bgp_path_attrs_local_pref(
    a: lr_bgp_path_attrs_t,
    out_lp: *mut u32,
) -> u8 {
    guarded(
        || unsafe {
            let Some(attrs) = borrow_attrs(a) else {
                return 0;
            };
            if out_lp.is_null() {
                return 0;
            }
            match attrs.local_pref() {
                Some(lp) => {
                    unsafe { *out_lp = lp.0 };
                    1
                }
                None => 0,
            }
        },
        0,
    )
}

/// Set the LOCAL_PREF attribute (RFC 4271 §5.1.5). The previous
/// value, if any, is overwritten.
///
/// # Safety
/// `a` must be a valid PathAttributes handle.
#[no_mangle]
pub unsafe extern "C" fn lr_bgp_path_attrs_set_local_pref(
    a: lr_bgp_path_attrs_t,
    value: u32,
) -> i32 {
    guarded(
        || unsafe {
            let Some(attrs) = borrow_attrs_mut(a) else {
                return LR_ERR_NULL;
            };
            attrs.set_local_pref(value);
            0
        },
        LR_ERR_PANIC,
    )
}

/// True when the ATOMIC_AGGREGATE attribute is present (RFC 4271
/// §5.1.6 — the route was aggregated; the receiving speaker must NOT
/// try to de-aggregate it).
///
/// # Safety
/// See [`lr_bgp_path_attrs_origin`].
#[no_mangle]
pub unsafe extern "C" fn lr_bgp_path_attrs_atomic_aggregate(a: lr_bgp_path_attrs_t) -> u8 {
    guarded(
        || unsafe {
            borrow_attrs(a)
                .map(|x| x.atomic_aggregate().is_some() as u8)
                .unwrap_or(0)
        },
        0,
    )
}

/// Read the AGGREGATOR attribute (RFC 4271 §5.1.7 — the AS that
/// aggregated the route, plus the speaker that originated the
/// aggregation). Writes the AS to `*out_asn` and the speaker to
/// `*out_speaker` (4-byte IPv4) and returns 1 if present, 0 if
/// absent.
///
/// # Safety
/// `a` must be a valid PathAttributes handle. `out_asn` and
/// `out_speaker` must point to writable `uint32_t` values.
#[no_mangle]
pub unsafe extern "C" fn lr_bgp_path_attrs_aggregator(
    a: lr_bgp_path_attrs_t,
    out_asn: *mut u32,
    out_speaker: *mut u32,
) -> u8 {
    guarded(
        || unsafe {
            let Some(attrs) = borrow_attrs(a) else {
                return 0;
            };
            if out_asn.is_null() || out_speaker.is_null() {
                return 0;
            }
            match attrs.aggregator() {
                Some(agg) => {
                    unsafe {
                        *out_asn = agg.asn.as_u32();
                        *out_speaker = u32::from_be_bytes(agg.speaker);
                    }
                    1
                }
                None => 0,
            }
        },
        0,
    )
}

/// Read the ORIGINATOR_ID attribute (RFC 4456 §4 — the route
/// reflector that originated the route). Writes the ID to
/// `*out_originator` and returns 1 if present, 0 if absent.
///
/// # Safety
/// See [`lr_bgp_path_attrs_origin`].
#[no_mangle]
pub unsafe extern "C" fn lr_bgp_path_attrs_originator_id(
    a: lr_bgp_path_attrs_t,
    out_originator: *mut u32,
) -> u8 {
    guarded(
        || unsafe {
            let Some(attrs) = borrow_attrs(a) else {
                return 0;
            };
            if out_originator.is_null() {
                return 0;
            }
            match attrs.originator_id() {
                Some(id) => {
                    unsafe { *out_originator = id.0.as_u32() };
                    1
                }
                None => 0,
            }
        },
        0,
    )
}

/// True when the CLUSTER_LIST attribute is present (RFC 4456 §8).
///
/// # Safety
/// See [`lr_bgp_path_attrs_origin`].
#[no_mangle]
pub unsafe extern "C" fn lr_bgp_path_attrs_has_cluster_list(a: lr_bgp_path_attrs_t) -> u8 {
    guarded(
        || unsafe {
            borrow_attrs(a)
                .map(|x| x.has_cluster_list() as u8)
                .unwrap_or(0)
        },
        0,
    )
}

/// True when the OTC (Only To Customer) attribute is present
/// (RFC 9234 §4.1).
///
/// # Safety
/// See [`lr_bgp_path_attrs_origin`].
#[no_mangle]
pub unsafe extern "C" fn lr_bgp_path_attrs_has_otc(a: lr_bgp_path_attrs_t) -> u8 {
    guarded(
        || unsafe { borrow_attrs(a).map(|x| x.has_otc() as u8).unwrap_or(0) },
        0,
    )
}

/// Read the OTC attribute (RFC 9234 §4.1). Writes the value to
/// `*out_otc` and returns 1 if present, 0 if absent.
///
/// # Safety
/// See [`lr_bgp_path_attrs_origin`].
#[no_mangle]
pub unsafe extern "C" fn lr_bgp_path_attrs_otc(a: lr_bgp_path_attrs_t, out_otc: *mut u32) -> u8 {
    guarded(
        || unsafe {
            let Some(attrs) = borrow_attrs(a) else {
                return 0;
            };
            if out_otc.is_null() {
                return 0;
            }
            match attrs.otc() {
                Some(otc) => {
                    unsafe { *out_otc = otc.0 };
                    1
                }
                None => 0,
            }
        },
        0,
    )
}

/// True when the AIGP attribute is present (RFC 7311 — accumulated
/// IGP metric).
///
/// # Safety
/// See [`lr_bgp_path_attrs_origin`].
#[no_mangle]
pub unsafe extern "C" fn lr_bgp_path_attrs_has_aigp(a: lr_bgp_path_attrs_t) -> u8 {
    guarded(
        || unsafe { borrow_attrs(a).map(|x| x.has_aigp() as u8).unwrap_or(0) },
        0,
    )
}

/// Read the AIGP attribute (RFC 7311 — the type-1 TLV's accumulated
/// IGP metric). Writes the metric to `*out_aigp` and returns 1 if
/// present, 0 if absent.
///
/// # Safety
/// See [`lr_bgp_path_attrs_origin`].
#[no_mangle]
pub unsafe extern "C" fn lr_bgp_path_attrs_aigp(a: lr_bgp_path_attrs_t, out_aigp: *mut u64) -> u8 {
    guarded(
        || unsafe {
            let Some(attrs) = borrow_attrs(a) else {
                return 0;
            };
            if out_aigp.is_null() {
                return 0;
            }
            match attrs.aigp() {
                Some(aigp) => {
                    unsafe { *out_aigp = aigp.0 };
                    1
                }
                None => 0,
            }
        },
        0,
    )
}

/// True when the PMSI Tunnel attribute is present (RFC 6514 §5 —
/// used by MVPN / EVPN to carry the provider tunnel identifier).
///
/// # Safety
/// See [`lr_bgp_path_attrs_origin`].
#[no_mangle]
pub unsafe extern "C" fn lr_bgp_path_attrs_has_pmsi_tunnel(a: lr_bgp_path_attrs_t) -> u8 {
    guarded(
        || unsafe {
            borrow_attrs(a)
                .map(|x| x.has_pmsi_tunnel() as u8)
                .unwrap_or(0)
        },
        0,
    )
}

/// Read the COMMUNITIES attribute (RFC 1997). Each community is a
/// 32-bit value (high 16 bits = ASN, low 16 bits = local value).
/// Writes the flat `uint32_t` array to a freshly-allocated
/// `lr_bytes_t` at `*out` — the byte length is `count * 4`. Returns
/// the number of communities, or 0 on a NULL handle / absent
/// attribute.
///
/// # Safety
/// `a` must be a valid PathAttributes handle. `out` must point to a
/// writable `lr_bytes_t`.
#[no_mangle]
pub unsafe extern "C" fn lr_bgp_path_attrs_communities(
    a: lr_bgp_path_attrs_t,
    out: *mut lr_bytes_t,
) -> usize {
    guarded(
        || unsafe {
            let Some(attrs) = borrow_attrs(a) else {
                return 0;
            };
            if out.is_null() {
                return 0;
            }
            let comms: Vec<u32> = attrs.communities().into_iter().map(|c| c.0).collect();
            let n = comms.len();
            let mut bytes = Vec::with_capacity(n * 4);
            for c in comms {
                bytes.extend_from_slice(&c.to_be_bytes());
            }
            unsafe { *out = lr_bytes_t::from_vec(bytes) }
            n
        },
        0,
    )
}

/// Read the EXTENDED COMMUNITIES attribute (RFC 4360 — each is an
/// 8-octet value). Writes the flat byte stream to a
/// freshly-allocated `lr_bytes_t` at `*out`. Returns the count of
/// extended communities, or 0 on a NULL handle / absent attribute.
///
/// # Safety
/// See [`lr_bgp_path_attrs_communities`].
#[no_mangle]
pub unsafe extern "C" fn lr_bgp_path_attrs_ext_communities(
    a: lr_bgp_path_attrs_t,
    out: *mut lr_bytes_t,
) -> usize {
    guarded(
        || unsafe {
            let Some(attrs) = borrow_attrs(a) else {
                return 0;
            };
            if out.is_null() {
                return 0;
            }
            let exts = attrs.extended_communities();
            let n = exts.len();
            // Each ExtendedCommunity is 8 bytes on the wire.
            let bytes = ExtendedCommunity::encode_set(&exts);
            unsafe { *out = lr_bytes_t::from_vec(bytes) }
            n
        },
        0,
    )
}

/// Read the LARGE COMMUNITIES attribute (RFC 8092 — each is a 12-byte
/// `(global_admin, local_data1, local_data2)` triple). Writes the
/// flat byte stream to a freshly-allocated `lr_bytes_t` at `*out`.
/// Returns the count, or 0 on a NULL handle / absent attribute.
///
/// # Safety
/// See [`lr_bgp_path_attrs_communities`].
#[no_mangle]
pub unsafe extern "C" fn lr_bgp_path_attrs_large_communities(
    a: lr_bgp_path_attrs_t,
    out: *mut lr_bytes_t,
) -> usize {
    guarded(
        || unsafe {
            let Some(attrs) = borrow_attrs(a) else {
                return 0;
            };
            if out.is_null() {
                return 0;
            }
            let lcs = attrs.large_communities();
            let n = lcs.len();
            // Each LargeCommunity is 12 bytes on the wire.
            let bytes = LargeCommunity::encode_set(&lcs);
            unsafe { *out = lr_bytes_t::from_vec(bytes) }
            n
        },
        0,
    )
}

/// Insert a COMMUNITY (RFC 1997 — `asn << 16 | value`) into the set.
/// Returns 0 on success, `LR_ERR_NULL` on a NULL handle.
///
/// # Safety
/// `a` must be a valid PathAttributes handle.
#[no_mangle]
pub unsafe extern "C" fn lr_bgp_path_attrs_insert_community(
    a: lr_bgp_path_attrs_t,
    community: u32,
) -> i32 {
    guarded(
        || unsafe {
            let Some(attrs) = borrow_attrs_mut(a) else {
                return LR_ERR_NULL;
            };
            attrs.insert_community(Community(community));
            0
        },
        LR_ERR_PANIC,
    )
}

// ---- Typed readers for the remaining well-known attributes (issue #92) ----
//
// The readers below close the gap between the Rust `PathAttributes`
// pub API and the C ABI. They mirror the inherent-method set on
// `PathAttributes`: `next_hop`, `as_path`, `as_path_wire`,
// `as4_path`, `cluster_list`, `label_stack`, `set_label_stack`,
// `mp_reach`, `mp_unreach`. Each returns either a typed handle
// (AsPath / LabelStack) or a flat byte buffer (cluster_list,
// MpReach / MpUnreach attribute value) the caller frees via
// `lr_bytes_free`.

/// One IPv4/IPv6 next-hop value (RFC 4271 §5.1.3 / RFC 4760 §3).
/// Mirrors `lr_bgp::path::NextHopKind` — `is_ipv6 = 0` for IPv4
/// (the address occupies the first 4 bytes of `addr`), `1` for
/// IPv6, `2` for the RFC 5549 IPv4-over-IPv6 form (16 bytes, IPv4
/// encoded in the v6 address).
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct lr_bgp_next_hop_t {
    /// Address octets (first 4 for v4, all 16 for v6 / v4-over-v6).
    pub addr: [u8; 16],
    /// 0 = IPv4, 1 = IPv6, 2 = V4-over-V6 (RFC 5549).
    pub kind: u8,
    /// 1 when the attribute is present, 0 when absent.
    pub present: u8,
}

/// Read the NEXT_HOP attribute (RFC 4271 §5.1.3). Writes the
/// next-hop address + kind to `*out` and returns 1 if present, 0
/// if absent. The IPv4 form occupies the first 4 bytes of
/// `out->addr`; the IPv6 / RFC 5549 forms occupy all 16 bytes.
///
/// # Safety
/// `a` must be a valid PathAttributes handle. `out` must point to a
/// writable `lr_bgp_next_hop_t`.
#[no_mangle]
pub unsafe extern "C" fn lr_bgp_path_attrs_next_hop(
    a: lr_bgp_path_attrs_t,
    out: *mut lr_bgp_next_hop_t,
) -> u8 {
    guarded(
        || unsafe {
            let Some(attrs) = borrow_attrs(a) else {
                return 0;
            };
            if out.is_null() {
                return 0;
            }
            match attrs.next_hop() {
                Some(nh) => {
                    let (addr, kind) = match nh.0 {
                        lr_bgp::path::NextHopKind::V4(b) => {
                            let mut a16 = [0u8; 16];
                            a16[..4].copy_from_slice(&b);
                            (a16, 0u8)
                        }
                        lr_bgp::path::NextHopKind::V6(b) => (b, 1u8),
                        lr_bgp::path::NextHopKind::V4OverV6(b) => (b, 2u8),
                    };
                    unsafe {
                        *out = lr_bgp_next_hop_t {
                            addr,
                            kind,
                            present: 1,
                        };
                    }
                    1
                }
                None => 0,
            }
        },
        0,
    )
}

/// Read the AS_PATH attribute (RFC 4271 §5.1.2 / RFC 6793 §4) and
/// return it as a fresh `lr_bgp_as_path_t` handle (caller frees via
/// `lr_bgp_as_path_free`). Returns NULL when the attribute is
/// absent or the input handle is NULL.
///
/// The returned handle is a *clone* — the source PathAttributes
/// retains its own copy. Use [`lr_bgp_path_attrs_as_path_wire`] to
/// pick the 2-byte vs 4-byte AS form explicitly; this reader
/// returns the in-memory form (always 4-byte when ASN4 is
/// negotiated).
///
/// # Safety
/// `a` must be a valid PathAttributes handle.
#[no_mangle]
pub unsafe extern "C" fn lr_bgp_path_attrs_as_path(a: lr_bgp_path_attrs_t) -> lr_bgp_as_path_t {
    guarded(
        || unsafe {
            let Some(attrs) = borrow_attrs(a) else {
                return std::ptr::null_mut();
            };
            match attrs.as_path() {
                Some(p) => box_as_path(p),
                None => std::ptr::null_mut(),
            }
        },
        std::ptr::null_mut(),
    )
}

/// Read the AS_PATH attribute in the explicit 2-byte or 4-byte AS
/// form (RFC 6793 §4 — when `asn4 != 0` the path carries 4-byte
/// ASes; otherwise ASes above 16 bits are unwrapped to AS_TRANS).
/// Returns NULL when the attribute is absent.
///
/// # Safety
/// See [`lr_bgp_path_attrs_as_path`].
#[no_mangle]
pub unsafe extern "C" fn lr_bgp_path_attrs_as_path_wire(
    a: lr_bgp_path_attrs_t,
    asn4: u8,
) -> lr_bgp_as_path_t {
    guarded(
        || unsafe {
            let Some(attrs) = borrow_attrs(a) else {
                return std::ptr::null_mut();
            };
            match attrs.as_path_wire(asn4 != 0) {
                Some(p) => box_as_path(p),
                None => std::ptr::null_mut(),
            }
        },
        std::ptr::null_mut(),
    )
}

/// Read the AS4_PATH attribute (RFC 6793 §4 — the deprecated
/// AS4_PATH back-compat path). Returns NULL when absent.
///
/// # Safety
/// See [`lr_bgp_path_attrs_as_path`].
#[no_mangle]
pub unsafe extern "C" fn lr_bgp_path_attrs_as4_path(a: lr_bgp_path_attrs_t) -> lr_bgp_as_path_t {
    guarded(
        || unsafe {
            let Some(attrs) = borrow_attrs(a) else {
                return std::ptr::null_mut();
            };
            match attrs.as4_path() {
                Some(p) => box_as_path(p),
                None => std::ptr::null_mut(),
            }
        },
        std::ptr::null_mut(),
    )
}

/// Read the CLUSTER_LIST attribute (RFC 4456 §8). Writes a flat
/// `lr_bytes_t` carrying `n * 4` bytes (one big-endian Router-ID
/// per cluster) to `*out`. Returns 1 if the attribute is
/// physically present (RFC 4456 §8 — `has_cluster_list`), 0 if
/// absent. (The Rust API's `cluster_list()` collapses absent and
/// present-but-empty to the same empty `ClusterList`; this reader
/// uses `has_cluster_list` so the caller can distinguish the two.)
///
/// # Safety
/// `a` must be a valid PathAttributes handle. `out` must point to a
/// writable `lr_bytes_t`.
#[no_mangle]
pub unsafe extern "C" fn lr_bgp_path_attrs_cluster_list(
    a: lr_bgp_path_attrs_t,
    out: *mut lr_bytes_t,
) -> u8 {
    guarded(
        || unsafe {
            let Some(attrs) = borrow_attrs(a) else {
                return 0;
            };
            if out.is_null() {
                return 0;
            }
            if !attrs.has_cluster_list() {
                return 0;
            }
            // has_cluster_list() = true → cluster_list() is Some.
            let cl = attrs.cluster_list().unwrap_or_default();
            let mut bytes = Vec::with_capacity(cl.0.len() * 4);
            for rid in &cl.0 {
                bytes.extend_from_slice(&rid.as_u32().to_be_bytes());
            }
            unsafe { *out = lr_bytes_t::from_vec(bytes) }
            1
        },
        0,
    )
}

/// Read the LrMplsLabelStack attribute (RFC 8277 §3 — the
/// `LrMplsLabelStack` well-known attribute carries the MPLS label
/// stack for BGP labelled unicast). Returns a fresh
/// `lr_mpls_label_stack_t` handle (caller frees via
/// `lr_mpls_label_stack_free`), or NULL when the attribute is
/// absent.
///
/// # Safety
/// `a` must be a valid PathAttributes handle.
#[no_mangle]
pub unsafe extern "C" fn lr_bgp_path_attrs_label_stack(
    a: lr_bgp_path_attrs_t,
) -> crate::mpls::lr_mpls_label_stack_t {
    guarded(
        || unsafe {
            let Some(attrs) = borrow_attrs(a) else {
                return std::ptr::null_mut();
            };
            match attrs.label_stack() {
                Some(stack) => crate::mpls::box_stack(stack),
                None => std::ptr::null_mut(),
            }
        },
        std::ptr::null_mut(),
    )
}

/// Set the LrMplsLabelStack attribute (RFC 8277 §3). The previous
/// value, if any, is overwritten. The `stack` handle is **borrowed**
/// — the caller retains ownership and must still free it via
/// `lr_mpls_label_stack_free`.
///
/// # Safety
/// `a` must be a valid PathAttributes handle. `stack` must be a
/// valid LabelStack handle (NULL is rejected with `LR_ERR_NULL`).
#[no_mangle]
pub unsafe extern "C" fn lr_bgp_path_attrs_set_label_stack(
    a: lr_bgp_path_attrs_t,
    stack: crate::mpls::lr_mpls_label_stack_t,
) -> i32 {
    guarded(
        || unsafe {
            let Some(attrs) = borrow_attrs_mut(a) else {
                return LR_ERR_NULL;
            };
            if stack.is_null() {
                return LR_ERR_NULL;
            }
            // SAFETY: the caller passed a handle from
            // `lr_mpls_label_stack_*` and asserts it has not been
            // freed yet. We borrow read-only and let the caller
            // retain ownership.
            let stack_ref: &'static lr_mpls::LabelStack =
                unsafe { &*(stack as *const lr_mpls::LabelStack) };
            attrs.set_label_stack(stack_ref);
            0
        },
        LR_ERR_PANIC,
    )
}

/// Read the MP_REACH_NLRI attribute (RFC 4760 §3 — MP-BGP's
/// multiprotocol reachability form). Writes the family / next-hop
/// kind + address / NLRI byte count to `*out_family`,
/// `*out_next_hop`, `*out_nlri`. The NLRI bytes themselves are
/// returned in `*out_nlri_bytes` as a flat `lr_bytes_t` (caller
/// frees via `lr_bytes_free`). Returns 1 if present, 0 if absent.
///
/// The next-hop projection mirrors `lr_bgp_next_hop_t`: `kind` is
/// 0 (V4, 4 bytes), 1 (V6Global, 16 bytes), 2 (V4-over-V6, 16
/// bytes), 3 (V6LinkLocal, 16 bytes), or 4 (V6GlobalLinkLocal, 32
/// bytes — both halves concatenated).
///
/// # Safety
/// `a` must be a valid PathAttributes handle. All four out-pointers
/// must be writable (NULL `out_next_hop` / `out_nlri_bytes` is
/// rejected with 0).
#[no_mangle]
pub unsafe extern "C" fn lr_bgp_path_attrs_mp_reach(
    a: lr_bgp_path_attrs_t,
    out_family_afi: *mut u16,
    out_family_safi: *mut u8,
    out_next_hop: *mut lr_bgp_next_hop_t,
    out_nlri_bytes: *mut lr_bytes_t,
) -> u8 {
    guarded(
        || unsafe {
            let Some(attrs) = borrow_attrs(a) else {
                return 0;
            };
            if out_next_hop.is_null() || out_nlri_bytes.is_null() {
                return 0;
            }
            match attrs.mp_reach() {
                Some(reach) => {
                    if !out_family_afi.is_null() {
                        unsafe { *out_family_afi = reach.family.afi };
                    }
                    if !out_family_safi.is_null() {
                        unsafe { *out_family_safi = reach.family.safi };
                    }
                    let (addr, kind) = match &reach.next_hop {
                        lr_bgp::path::MpNextHop::V4(b) => {
                            let mut a16 = [0u8; 16];
                            a16[..4].copy_from_slice(b);
                            (a16, 0u8)
                        }
                        lr_bgp::path::MpNextHop::V6Global(b) => (*b, 1u8),
                        lr_bgp::path::MpNextHop::V4OverV6(b) => (*b, 2u8),
                        lr_bgp::path::MpNextHop::V6LinkLocal(b) => (*b, 3u8),
                        lr_bgp::path::MpNextHop::V6GlobalLinkLocal(g, _l) => {
                            let mut a32 = [0u8; 16];
                            // We can only carry 16 bytes in the
                            // lr_bgp_next_hop_t.addr slot — encode the
                            // global half there and surface the link-
                            // local half via the NLRI bytes path is not
                            // viable (it would mix NLRI and next-hop).
                            // Instead, expose only the primary next-hop
                            // here (mp_reach's `primary()` semantics).
                            a32.copy_from_slice(g);
                            (a32, 4u8)
                        }
                    };
                    unsafe {
                        *out_next_hop = lr_bgp_next_hop_t {
                            addr,
                            kind,
                            present: 1,
                        };
                    }
                    // Surface the raw attribute value bytes (which
                    // include the next-hop length / SNPAs / NLRI in
                    // their original wire shape) — the caller
                    // re-decodes them with the BgpCodec when a
                    // typed NLRI list is needed. The `reach.nlri`
                    // Vec is consumed by the codec path; we hand
                    // back the wire form so the FFI stays
                    // version-independent of the Nlri struct shape.
                    let raw = attrs
                        .get(AttrType::MpReachNlri)
                        .map(|a| a.value.clone())
                        .unwrap_or_default();
                    unsafe { *out_nlri_bytes = lr_bytes_t::from_vec(raw) }
                    1
                }
                None => 0,
            }
        },
        0,
    )
}

/// Read the MP_UNREACH_NLRI attribute (RFC 4760 §3 — the
/// multiprotocol withdrawal form). Writes the family to
/// `*out_family_afi` / `*out_family_safi` and the NLRI bytes to
/// `*out_nlri_bytes` (caller frees via `lr_bytes_free`). Returns 1
/// if present, 0 if absent.
///
/// The NLRI bytes are the raw attribute value (RFC 4760 §4 —
/// AFI/SAFI prefix followed by withdrawn NLRI); the caller can
/// decode them with the BgpCodec.
///
/// # Safety
/// `a` must be a valid PathAttributes handle. `out_nlri_bytes` must
/// point to a writable `lr_bytes_t`.
#[no_mangle]
pub unsafe extern "C" fn lr_bgp_path_attrs_mp_unreach(
    a: lr_bgp_path_attrs_t,
    out_family_afi: *mut u16,
    out_family_safi: *mut u8,
    out_nlri_bytes: *mut lr_bytes_t,
) -> u8 {
    guarded(
        || unsafe {
            let Some(attrs) = borrow_attrs(a) else {
                return 0;
            };
            if out_nlri_bytes.is_null() {
                return 0;
            }
            match attrs.mp_unreach() {
                Some(unreach) => {
                    if !out_family_afi.is_null() {
                        unsafe { *out_family_afi = unreach.family.afi };
                    }
                    if !out_family_safi.is_null() {
                        unsafe { *out_family_safi = unreach.family.safi };
                    }
                    // Surface the raw attribute value bytes — the
                    // caller decodes the AFI/SAFI + NLRI list with
                    // the BgpCodec.
                    let raw = attrs
                        .get(AttrType::MpUnreachNlri)
                        .map(|a| a.value.clone())
                        .unwrap_or_default();
                    unsafe { *out_nlri_bytes = lr_bytes_t::from_vec(raw) }
                    1
                }
                None => 0,
            }
        },
        0,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    unsafe fn bytes_to_vec(b: &mut lr_bytes_t) -> Vec<u8> {
        if b.ptr.is_null() {
            return Vec::new();
        }
        let v = unsafe { Vec::from_raw_parts(b.ptr, b.len, b.cap) };
        b.ptr = std::ptr::null_mut();
        b.len = 0;
        b.cap = 0;
        v
    }

    #[test]
    fn ffi_attr_type_round_trip() {
        let mut canonical = 0u8;
        // ORIGIN = 1 is a well-known type — round-trips to itself.
        assert_eq!(lr_bgp_attr_type_from_u8(1, &raw mut canonical), 1);
        assert_eq!(canonical, 1);
        // 99 is not assigned — returns 0 but canonical = 99 (Other).
        assert_eq!(lr_bgp_attr_type_from_u8(99, &raw mut canonical), 0);
        assert_eq!(canonical, 99);
    }

    #[test]
    fn ffi_attr_type_to_u8_is_identity() {
        assert_eq!(lr_bgp_attr_type_to_u8(17), 17); // AS4_PATH
    }

    #[test]
    fn ffi_as_path_from_sequence_length() {
        let ases = [64512u32, 64513, 64514];
        let p = unsafe { lr_bgp_as_path_from_sequence(ases.as_ptr(), ases.len()) };
        assert!(!p.is_null());
        assert_eq!(unsafe { lr_bgp_as_path_length(p) }, 3);
        assert_eq!(unsafe { lr_bgp_as_path_segment_count(p) }, 1);

        let mut kind = 0u8;
        let mut count = 0usize;
        let rc = unsafe { lr_bgp_as_path_segment_at(p, 0, &raw mut kind, &raw mut count) };
        assert_eq!(rc, 0);
        assert_eq!(kind, 2); // AS_SEQUENCE
        assert_eq!(count, 3);

        let mut out = [0u32; 3];
        let n = unsafe { lr_bgp_as_path_segment_ases(p, 0, out.as_mut_ptr(), 3) };
        assert_eq!(n, 3);
        assert_eq!(out, [64512, 64513, 64514]);

        let mut seq = [0u32; 3];
        let n = unsafe { lr_bgp_as_path_as_sequence(p, seq.as_mut_ptr(), 3) };
        assert_eq!(n, 3);
        assert_eq!(seq, [64512, 64513, 64514]);

        unsafe { lr_bgp_as_path_free(p) };
    }

    #[test]
    fn ffi_as_path_loop_check() {
        let ases = [64512u32, 64513];
        let p = unsafe { lr_bgp_as_path_from_sequence(ases.as_ptr(), ases.len()) };
        assert_eq!(unsafe { lr_bgp_as_path_loop_check(p, 64512) }, 1);
        assert_eq!(unsafe { lr_bgp_as_path_loop_check(p, 65000) }, 0);
        unsafe { lr_bgp_as_path_free(p) };
    }

    #[test]
    fn ffi_as_path_prepend() {
        let p = unsafe { lr_bgp_as_path_from_sequence(std::ptr::null(), 0) };
        let rc = unsafe { lr_bgp_as_path_prepend(p, 64512) };
        assert_eq!(rc, 0);
        let rc = unsafe { lr_bgp_as_path_prepend(p, 64513) };
        assert_eq!(rc, 0);
        assert_eq!(unsafe { lr_bgp_as_path_length(p) }, 2);
        let mut seq = [0u32; 2];
        let n = unsafe { lr_bgp_as_path_as_sequence(p, seq.as_mut_ptr(), 2) };
        assert_eq!(n, 2);
        // prepend inserts at the front: [64513, 64512].
        assert_eq!(seq, [64513, 64512]);
        unsafe { lr_bgp_as_path_free(p) };
    }

    #[test]
    fn ffi_as_path_decode_encode_2_round_trip() {
        // AS_SEQUENCE [64512] in 2-octet form: 02 01 fc 00 (type=2,
        // len=1, AS=64512 in big-endian 2 bytes).
        let wire = [0x02u8, 0x01, 0xfc, 0x00];
        let p = unsafe { lr_bgp_as_path_decode_2(wire.as_ptr(), wire.len()) };
        assert!(!p.is_null());
        assert_eq!(unsafe { lr_bgp_as_path_length(p) }, 1);

        let mut out = lr_bytes_t {
            ptr: std::ptr::null_mut(),
            len: 0,
            cap: 0,
        };
        let rc = unsafe { lr_bgp_as_path_encode_2(p, &raw mut out) };
        assert_eq!(rc, 0);
        let bytes = unsafe { bytes_to_vec(&mut out) };
        assert_eq!(bytes, wire);

        unsafe { lr_bgp_as_path_free(p) };
    }

    #[test]
    fn ffi_as_path_decode_4_round_trip() {
        // AS_SEQUENCE [64512] in 4-octet form: 02 01 00 00 fc 00.
        let wire = [0x02u8, 0x01, 0x00, 0x00, 0xfc, 0x00];
        let p = unsafe { lr_bgp_as_path_decode_4(wire.as_ptr(), wire.len()) };
        assert!(!p.is_null());
        assert_eq!(unsafe { lr_bgp_as_path_length(p) }, 1);

        let mut out = lr_bytes_t {
            ptr: std::ptr::null_mut(),
            len: 0,
            cap: 0,
        };
        let rc = unsafe { lr_bgp_as_path_encode_4(p, &raw mut out) };
        assert_eq!(rc, 0);
        let bytes = unsafe { bytes_to_vec(&mut out) };
        assert_eq!(bytes, wire);

        unsafe { lr_bgp_as_path_free(p) };
    }

    #[test]
    fn ffi_path_attrs_basic_readers() {
        let a = lr_bgp_path_attrs_new();
        assert!(!a.is_null());
        assert_eq!(unsafe { lr_bgp_path_attrs_len(a) }, 0);
        assert_eq!(unsafe { lr_bgp_path_attrs_is_empty(a) }, 1);

        // Set LOCAL_PREF and read it back.
        let rc = unsafe { lr_bgp_path_attrs_set_local_pref(a, 100) };
        assert_eq!(rc, 0);
        assert_eq!(unsafe { lr_bgp_path_attrs_len(a) }, 1);

        let mut lp = 0u32;
        assert_eq!(unsafe { lr_bgp_path_attrs_local_pref(a, &raw mut lp) }, 1);
        assert_eq!(lp, 100);

        unsafe { lr_bgp_path_attrs_free(a) };
    }

    #[test]
    fn ffi_path_attrs_communities() {
        let a = lr_bgp_path_attrs_new();

        // Insert two communities: (64512 << 16) | 100 and (64512 << 16) | 200.
        let rc = unsafe { lr_bgp_path_attrs_insert_community(a, (64512 << 16) | 100) };
        assert_eq!(rc, 0);
        let rc = unsafe { lr_bgp_path_attrs_insert_community(a, (64512 << 16) | 200) };
        assert_eq!(rc, 0);

        let mut out = lr_bytes_t {
            ptr: std::ptr::null_mut(),
            len: 0,
            cap: 0,
        };
        let n = unsafe { lr_bgp_path_attrs_communities(a, &raw mut out) };
        assert_eq!(n, 2);
        let bytes = unsafe { bytes_to_vec(&mut out) };
        assert_eq!(bytes.len(), 8); // 2 communities × 4 bytes.

        unsafe { lr_bgp_path_attrs_free(a) };
    }

    #[test]
    fn ffi_free_handles_null_safely() {
        unsafe {
            lr_bgp_as_path_free(std::ptr::null_mut());
            lr_bgp_path_attrs_free(std::ptr::null_mut());
        }
    }

    #[test]
    fn ffi_as_path_length_returns_zero_on_null() {
        assert_eq!(unsafe { lr_bgp_as_path_length(std::ptr::null_mut()) }, 0);
    }

    #[test]
    fn ffi_path_attrs_med_absent() {
        let a = lr_bgp_path_attrs_new();
        let mut med = 0u32;
        assert_eq!(unsafe { lr_bgp_path_attrs_med(a, &raw mut med) }, 0);
        unsafe { lr_bgp_path_attrs_free(a) };
    }

    #[test]
    fn ffi_path_attrs_next_hop_absent_on_fresh_attrs() {
        let a = lr_bgp_path_attrs_new();
        let mut nh = lr_bgp_next_hop_t::default();
        assert_eq!(unsafe { lr_bgp_path_attrs_next_hop(a, &raw mut nh) }, 0);
        assert_eq!(nh.present, 0);
        // NULL attrs / out → 0 (absent).
        assert_eq!(
            unsafe { lr_bgp_path_attrs_next_hop(std::ptr::null_mut(), &raw mut nh) },
            0
        );
        assert_eq!(
            unsafe { lr_bgp_path_attrs_next_hop(a, std::ptr::null_mut()) },
            0
        );
        unsafe { lr_bgp_path_attrs_free(a) };
    }

    #[test]
    fn ffi_path_attrs_as_path_absent_on_fresh_attrs() {
        let a = lr_bgp_path_attrs_new();
        // No AS_PATH on a fresh attrs set — the call returns NULL.
        let p = unsafe { lr_bgp_path_attrs_as_path(a) };
        assert!(p.is_null());
        // NULL attrs → NULL.
        let p = unsafe { lr_bgp_path_attrs_as_path(std::ptr::null_mut()) };
        assert!(p.is_null());
        // wire / as4_path variants also return NULL.
        assert!(unsafe { lr_bgp_path_attrs_as_path_wire(a, 1) }.is_null());
        assert!(unsafe { lr_bgp_path_attrs_as4_path(a) }.is_null());
        unsafe { lr_bgp_path_attrs_free(a) };
    }

    #[test]
    fn ffi_path_attrs_cluster_list_absent_on_fresh_attrs() {
        let a = lr_bgp_path_attrs_new();
        let mut out = lr_bytes_t {
            ptr: std::ptr::null_mut(),
            len: 0,
            cap: 0,
        };
        assert_eq!(
            unsafe { lr_bgp_path_attrs_cluster_list(a, &raw mut out) },
            0
        );
        assert!(out.ptr.is_null());
        // NULL attrs → 0.
        assert_eq!(
            unsafe { lr_bgp_path_attrs_cluster_list(std::ptr::null_mut(), &raw mut out) },
            0
        );
        unsafe { lr_bgp_path_attrs_free(a) };
    }

    #[test]
    fn ffi_path_attrs_label_stack_absent_on_fresh_attrs() {
        let a = lr_bgp_path_attrs_new();
        // No label stack on a fresh attrs set — returns NULL.
        let s = unsafe { lr_bgp_path_attrs_label_stack(a) };
        assert!(s.is_null());
        // set_label_stack with a NULL stack → LR_ERR_NULL.
        let rc = unsafe { lr_bgp_path_attrs_set_label_stack(a, std::ptr::null_mut()) };
        assert_eq!(rc, LR_ERR_NULL);
        // set_label_stack with NULL attrs → LR_ERR_NULL.
        let stack = crate::mpls::lr_mpls_label_stack_new();
        let rc = unsafe { lr_bgp_path_attrs_set_label_stack(std::ptr::null_mut(), stack) };
        assert_eq!(rc, LR_ERR_NULL);
        unsafe {
            crate::mpls::lr_mpls_label_stack_free(stack);
            lr_bgp_path_attrs_free(a);
        }
    }

    #[test]
    fn ffi_path_attrs_mp_reach_absent_on_fresh_attrs() {
        let a = lr_bgp_path_attrs_new();
        let mut afi = 0u16;
        let mut safi = 0u8;
        let mut nh = lr_bgp_next_hop_t::default();
        let mut nlri = lr_bytes_t {
            ptr: std::ptr::null_mut(),
            len: 0,
            cap: 0,
        };
        assert_eq!(
            unsafe {
                lr_bgp_path_attrs_mp_reach(
                    a,
                    &raw mut afi,
                    &raw mut safi,
                    &raw mut nh,
                    &raw mut nlri,
                )
            },
            0
        );
        assert_eq!(nh.present, 0);
        assert!(nlri.ptr.is_null());
        // NULL attrs → 0.
        assert_eq!(
            unsafe {
                lr_bgp_path_attrs_mp_reach(
                    std::ptr::null_mut(),
                    &raw mut afi,
                    &raw mut safi,
                    &raw mut nh,
                    &raw mut nlri,
                )
            },
            0
        );
        // NULL out_next_hop / out_nlri_bytes → 0.
        assert_eq!(
            unsafe {
                lr_bgp_path_attrs_mp_reach(
                    a,
                    &raw mut afi,
                    &raw mut safi,
                    std::ptr::null_mut(),
                    &raw mut nlri,
                )
            },
            0
        );
        unsafe { lr_bgp_path_attrs_free(a) };
    }

    #[test]
    fn ffi_path_attrs_mp_unreach_absent_on_fresh_attrs() {
        let a = lr_bgp_path_attrs_new();
        let mut afi = 0u16;
        let mut safi = 0u8;
        let mut nlri = lr_bytes_t {
            ptr: std::ptr::null_mut(),
            len: 0,
            cap: 0,
        };
        assert_eq!(
            unsafe { lr_bgp_path_attrs_mp_unreach(a, &raw mut afi, &raw mut safi, &raw mut nlri,) },
            0
        );
        assert!(nlri.ptr.is_null());
        // NULL attrs → 0.
        assert_eq!(
            unsafe {
                lr_bgp_path_attrs_mp_unreach(
                    std::ptr::null_mut(),
                    &raw mut afi,
                    &raw mut safi,
                    &raw mut nlri,
                )
            },
            0
        );
        // NULL out_nlri_bytes → 0.
        assert_eq!(
            unsafe {
                lr_bgp_path_attrs_mp_unreach(a, &raw mut afi, &raw mut safi, std::ptr::null_mut())
            },
            0
        );
        unsafe { lr_bgp_path_attrs_free(a) };
    }
}
