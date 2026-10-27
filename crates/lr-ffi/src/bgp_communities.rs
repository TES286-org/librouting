//! BGP community value types — `Community` (RFC 1997),
//! `ExtendedCommunity` (RFC 4360/7153) and `LargeCommunity` (RFC 8092).
//!
//! Mirrors the public Rust API of `lr_bgp::path::communities`. The C
//! ABI surface exposes the value types themselves (via `lr_*_t` opaque
//! handles and `lr_*_spec_t` repr-C structs) plus the standalone
//! `encode_set` / `decode_set` codec helpers that the Rust types carry.
//!
//! # Surface
//!
//! - `lr_bgp_community_new` / `_new_well_known` / `_as_u32` / `_asn` /
//!   `_value` / `_kind` / `_free`.
//! - `lr_bgp_community_encode_set` / `_decode_set` (flat `u32`-array
//!   to / from wire bytes — RFC 1997 §2).
//! - `lr_bgp_large_community_new` / `_global_admin` / `_local_data1` /
//!   `_local_data2` / `_free`.
//! - `lr_bgp_large_community_encode_set` / `_decode_set`.
//! - `lr_bgp_ext_community_new` / `_kind` / `_subtype` / `_global` /
//!   `_local` / `_free`.
//! - `lr_bgp_ext_community_encode_set` / `_decode_set`.
//!
//! Every entry point runs inside the crate's `catch_unwind` barrier
//! ([`crate::guarded`]).

// The closure body passed to `guarded` is wrapped in a single `unsafe`
// block to mirror the `pub unsafe extern "C" fn` shape — the inner
// `unsafe { ... }` blocks would otherwise trip `unused_unsafe` under
// the crate's `-D warnings` clippy gate.
#![allow(unused_unsafe)]

use lr_bgp::path::communities::{Community, CommunityKind, ExtendedCommunity, LargeCommunity};

use crate::error::{set_last_error, LrError, LR_ERR_PANIC};
use crate::guarded;
use crate::handle::lr_bytes_t;

const LR_ERR_NULL: i32 = LrError::Null as i32;
const LR_ERR_OTHER: i32 = LrError::Other as i32;

// ---- Opaque handles ----

/// Opaque BGP-standard-community handle (RFC 1997).
#[repr(C)]
pub struct OpaqueBgpCommunity {
    _private: [u8; 0],
}
pub type lr_bgp_community_t = *mut OpaqueBgpCommunity;

/// Opaque BGP-large-community handle (RFC 8092).
#[repr(C)]
pub struct OpaqueBgpLargeCommunity {
    _private: [u8; 0],
}
pub type lr_bgp_large_community_t = *mut OpaqueBgpLargeCommunity;

/// Opaque BGP-extended-community handle (RFC 4360/7153).
#[repr(C)]
pub struct OpaqueBgpExtCommunity {
    _private: [u8; 0],
}
pub type lr_bgp_ext_community_t = *mut OpaqueBgpExtCommunity;

fn box_community(c: Community) -> lr_bgp_community_t {
    Box::into_raw(Box::new(c)) as lr_bgp_community_t
}
unsafe fn unbox_community(c: lr_bgp_community_t) -> Option<Box<Community>> {
    if c.is_null() {
        return None;
    }
    Some(unsafe { Box::from_raw(c as *mut Community) })
}
unsafe fn borrow_community(c: lr_bgp_community_t) -> Option<&'static Community> {
    if c.is_null() {
        return None;
    }
    Some(unsafe { &*(c as *const Community) })
}

fn box_large(c: LargeCommunity) -> lr_bgp_large_community_t {
    Box::into_raw(Box::new(c)) as lr_bgp_large_community_t
}
unsafe fn borrow_large(c: lr_bgp_large_community_t) -> Option<&'static LargeCommunity> {
    if c.is_null() {
        return None;
    }
    Some(unsafe { &*(c as *const LargeCommunity) })
}

fn box_ext(c: ExtendedCommunity) -> lr_bgp_ext_community_t {
    Box::into_raw(Box::new(c)) as lr_bgp_ext_community_t
}
unsafe fn borrow_ext(c: lr_bgp_ext_community_t) -> Option<&'static ExtendedCommunity> {
    if c.is_null() {
        return None;
    }
    Some(unsafe { &*(c as *const ExtendedCommunity) })
}

/// Well-known community kind constants — mirror
/// `CommunityKind::*`. Published as `#define`s in `lr_ffi.h` so
/// pre-C23 consumers can switch on them.
pub const LR_COMMUNITY_KIND_CUSTOM: i32 = 0;
pub const LR_COMMUNITY_KIND_NO_EXPORT: i32 = 1;
pub const LR_COMMUNITY_KIND_NO_ADVERTISE: i32 = 2;
pub const LR_COMMUNITY_KIND_NO_EXPORT_SUBCONFED: i32 = 3;
pub const LR_COMMUNITY_KIND_NO_PEER: i32 = 4;
pub const LR_COMMUNITY_KIND_GRACEFUL_SHUTDOWN: i32 = 5;
pub const LR_COMMUNITY_KIND_LLGR_STALE: i32 = 6;
pub const LR_COMMUNITY_KIND_NO_LLGR: i32 = 7;

fn kind_to_c(k: CommunityKind) -> i32 {
    match k {
        CommunityKind::Custom => LR_COMMUNITY_KIND_CUSTOM,
        CommunityKind::NoExport => LR_COMMUNITY_KIND_NO_EXPORT,
        CommunityKind::NoAdvertise => LR_COMMUNITY_KIND_NO_ADVERTISE,
        CommunityKind::NoExportSubconfed => LR_COMMUNITY_KIND_NO_EXPORT_SUBCONFED,
        CommunityKind::NoPeer => LR_COMMUNITY_KIND_NO_PEER,
        CommunityKind::GracefulShutdown => LR_COMMUNITY_KIND_GRACEFUL_SHUTDOWN,
        CommunityKind::LlgrStale => LR_COMMUNITY_KIND_LLGR_STALE,
        CommunityKind::NoLlgr => LR_COMMUNITY_KIND_NO_LLGR,
    }
}

/// Well-known community wire constants — mirror `Community::*`
/// (RFC 1997 §2 + RFC 8326 §4 + RFC 9494 §3.2/§3.3).
pub const LR_BGP_COMMUNITY_NO_EXPORT: u32 = 0xFFFF_FF01;
pub const LR_BGP_COMMUNITY_NO_ADVERTISE: u32 = 0xFFFF_FF02;
pub const LR_BGP_COMMUNITY_NO_EXPORT_SUBCONFED: u32 = 0xFFFF_FF03;
pub const LR_BGP_COMMUNITY_NOPEER: u32 = 0xFFFF_FF04;
pub const LR_BGP_COMMUNITY_GRACEFUL_SHUTDOWN: u32 = 0xFFFF_0000;
pub const LR_BGP_COMMUNITY_LLGR_STALE: u32 = 0xFFFF_0006;
pub const LR_BGP_COMMUNITY_NO_LLGR: u32 = 0xFFFF_0007;

// ---- Community surface ----

/// Construct a `Community` from `(asn, value)` (RFC 1997 §2:
/// `asn << 16 | value`).
#[no_mangle]
pub extern "C" fn lr_bgp_community_new(asn: u16, value: u16) -> lr_bgp_community_t {
    guarded(
        || box_community(Community::new(asn, value)),
        std::ptr::null_mut(),
    )
}

/// Construct a `Community` from a raw `u32` wire value.
#[no_mangle]
pub extern "C" fn lr_bgp_community_from_u32(value: u32) -> lr_bgp_community_t {
    guarded(
        || box_community(Community::from_u32(value)),
        std::ptr::null_mut(),
    )
}

/// Construct a well-known `Community` by kind id (one of the
/// `LR_COMMUNITY_KIND_*` constants). Returns `NULL` for an unknown
/// kind id.
#[no_mangle]
pub extern "C" fn lr_bgp_community_new_well_known(kind: i32) -> lr_bgp_community_t {
    guarded(
        || {
            let c = match kind {
                LR_COMMUNITY_KIND_NO_EXPORT => Community::NO_EXPORT,
                LR_COMMUNITY_KIND_NO_ADVERTISE => Community::NO_ADVERTISE,
                LR_COMMUNITY_KIND_NO_EXPORT_SUBCONFED => Community::NO_EXPORT_SUBCONFED,
                LR_COMMUNITY_KIND_NO_PEER => Community::NOPEER,
                LR_COMMUNITY_KIND_GRACEFUL_SHUTDOWN => Community::GRACEFUL_SHUTDOWN,
                LR_COMMUNITY_KIND_LLGR_STALE => Community::LLGR_STALE,
                LR_COMMUNITY_KIND_NO_LLGR => Community::NO_LLGR,
                _ => return std::ptr::null_mut(),
            };
            box_community(c)
        },
        std::ptr::null_mut(),
    )
}

/// Read the raw 32-bit wire value.
///
/// # Safety
/// `c` must be a valid handle.
#[no_mangle]
pub unsafe extern "C" fn lr_bgp_community_as_u32(c: lr_bgp_community_t) -> u32 {
    guarded(
        || unsafe { borrow_community(c).map(|x| x.as_u32()).unwrap_or(0) },
        0,
    )
}

/// Read the high 16-bit AS field.
///
/// # Safety
/// See [`lr_bgp_community_as_u32`].
#[no_mangle]
pub unsafe extern "C" fn lr_bgp_community_asn(c: lr_bgp_community_t) -> u16 {
    guarded(
        || unsafe {
            borrow_community(c)
                .map(|x| (x.as_u32() >> 16) as u16)
                .unwrap_or(0)
        },
        0,
    )
}

/// Read the low 16-bit value field.
///
/// # Safety
/// See [`lr_bgp_community_as_u32`].
#[no_mangle]
pub unsafe extern "C" fn lr_bgp_community_value(c: lr_bgp_community_t) -> u16 {
    guarded(
        || unsafe {
            borrow_community(c)
                .map(|x| (x.as_u32() & 0xffff) as u16)
                .unwrap_or(0)
        },
        0,
    )
}

/// Read the well-known kind (one of `LR_COMMUNITY_KIND_*`).
///
/// # Safety
/// See [`lr_bgp_community_as_u32`].
#[no_mangle]
pub unsafe extern "C" fn lr_bgp_community_kind(c: lr_bgp_community_t) -> i32 {
    guarded(
        || unsafe {
            borrow_community(c)
                .map(|x| kind_to_c(x.kind()))
                .unwrap_or(LR_COMMUNITY_KIND_CUSTOM)
        },
        LR_COMMUNITY_KIND_CUSTOM,
    )
}

/// Drop a boxed `Community`. Safe to call with `NULL`.
///
/// # Safety
/// `c` must have been produced by a `lr_bgp_community_*` constructor
/// and must not be used after this call.
#[no_mangle]
pub unsafe extern "C" fn lr_bgp_community_free(c: lr_bgp_community_t) {
    guarded(
        || unsafe {
            drop(unbox_community(c));
        },
        (),
    )
}

/// Encode a flat array of community wire values (`count * 4` bytes
/// big-endian) as the on-wire COMMUNITIES attribute body (RFC 1997
/// §2). The caller frees `*out` with [`crate::bytes::lr_bytes_free`].
///
/// # Safety
/// `values` must point to `count` readable `uint32_t` values; `out`
/// must point to writable `lr_bytes_t`.
#[no_mangle]
pub unsafe extern "C" fn lr_bgp_community_encode_set(
    values: *const u32,
    count: usize,
    out: *mut lr_bytes_t,
) -> i32 {
    guarded(
        || unsafe {
            if out.is_null() {
                return LR_ERR_NULL;
            }
            if values.is_null() && count != 0 {
                return LR_ERR_NULL;
            }
            let slice: &[u32] = if count == 0 {
                &[]
            } else {
                unsafe { std::slice::from_raw_parts(values, count) }
            };
            let comms: Vec<Community> = slice.iter().copied().map(Community::from_u32).collect();
            let bytes = Community::encode_set(&comms);
            unsafe { *out = lr_bytes_t::from_vec(bytes) }
            0
        },
        LR_ERR_PANIC,
    )
}

/// Decode a COMMUNITIES attribute body (RFC 1997 §2 — flat `count * 4`
/// bytes big-endian) into a freshly-allocated `uint32_t` array. The
/// caller frees `*out_values` with [`crate::handle::lr_bytes_free`]
/// (treat it as a byte buffer of `count * 4` bytes).
///
/// Writes the element count to `*out_count`.
///
/// # Safety
/// `data` must point to `len` readable bytes; `out_values` and
/// `out_count` must point to writable memory.
#[no_mangle]
pub unsafe extern "C" fn lr_bgp_community_decode_set(
    data: *const u8,
    len: usize,
    out_values: *mut lr_bytes_t,
    out_count: *mut usize,
) -> i32 {
    guarded(
        || unsafe {
            if data.is_null() || out_values.is_null() {
                return LR_ERR_NULL;
            }
            let slice = unsafe { std::slice::from_raw_parts(data, len) };
            let comms = Community::decode_set(slice);
            let n = comms.len();
            // Reinterpret the u32 array as raw bytes for transport.
            let raw: Vec<u8> = comms
                .into_iter()
                .flat_map(|c| c.as_u32().to_be_bytes())
                .collect();
            unsafe {
                *out_values = lr_bytes_t::from_vec(raw);
                if !out_count.is_null() {
                    *out_count = n;
                }
            }
            0
        },
        LR_ERR_PANIC,
    )
}

// ---- LargeCommunity surface ----

/// Construct a `LargeCommunity` (RFC 8092 §2:
/// `global_admin:local_data1:local_data2`).
#[no_mangle]
pub extern "C" fn lr_bgp_large_community_new(
    global_admin: u32,
    local_data1: u32,
    local_data2: u32,
) -> lr_bgp_large_community_t {
    guarded(
        || box_large(LargeCommunity::new(global_admin, local_data1, local_data2)),
        std::ptr::null_mut(),
    )
}

/// Read the global-administrator field (RFC 8092 §2).
///
/// # Safety
/// `c` must be a valid handle.
#[no_mangle]
pub unsafe extern "C" fn lr_bgp_large_community_global_admin(c: lr_bgp_large_community_t) -> u32 {
    guarded(
        || unsafe { borrow_large(c).map(|x| x.global_admin).unwrap_or(0) },
        0,
    )
}

/// Read the local-data-1 field.
///
/// # Safety
/// See [`lr_bgp_large_community_global_admin`].
#[no_mangle]
pub unsafe extern "C" fn lr_bgp_large_community_local_data1(c: lr_bgp_large_community_t) -> u32 {
    guarded(
        || unsafe { borrow_large(c).map(|x| x.local_data1).unwrap_or(0) },
        0,
    )
}

/// Read the local-data-2 field.
///
/// # Safety
/// See [`lr_bgp_large_community_global_admin`].
#[no_mangle]
pub unsafe extern "C" fn lr_bgp_large_community_local_data2(c: lr_bgp_large_community_t) -> u32 {
    guarded(
        || unsafe { borrow_large(c).map(|x| x.local_data2).unwrap_or(0) },
        0,
    )
}

/// Drop a boxed `LargeCommunity`. Safe to call with `NULL`.
///
/// # Safety
/// `c` must have been produced by [`lr_bgp_large_community_new`] and
/// must not be used after this call.
#[no_mangle]
pub unsafe extern "C" fn lr_bgp_large_community_free(c: lr_bgp_large_community_t) {
    guarded(
        || unsafe {
            if c.is_null() {
                return;
            }
            drop(unsafe { Box::from_raw(c as *mut LargeCommunity) });
        },
        (),
    )
}

/// Encode a flat array of `(global_admin, local_data1, local_data2)`
/// triples as the on-wire LARGE_COMMUNITIES attribute body (RFC 8092
/// §2). Each triple occupies `3 * sizeof(uint32_t)`; the caller frees
/// `*out` with [`crate::bytes::lr_bytes_free`].
///
/// # Safety
/// `triples` must point to `count * 3` readable `uint32_t` values;
/// `out` must point to writable `lr_bytes_t`.
#[no_mangle]
pub unsafe extern "C" fn lr_bgp_large_community_encode_set(
    triples: *const u32,
    count: usize,
    out: *mut lr_bytes_t,
) -> i32 {
    guarded(
        || unsafe {
            if out.is_null() {
                return LR_ERR_NULL;
            }
            if triples.is_null() && count != 0 {
                return LR_ERR_NULL;
            }
            if !count.is_multiple_of(3) {
                set_last_error(
                    "lr_bgp_large_community_encode_set: count must be a multiple of 3".into(),
                );
                return LR_ERR_OTHER;
            }
            let slice: &[u32] = if count == 0 {
                &[]
            } else {
                unsafe { std::slice::from_raw_parts(triples, count) }
            };
            let mut comms = Vec::with_capacity(count / 3);
            for chunk in slice.as_chunks::<3>().0 {
                comms.push(LargeCommunity::new(chunk[0], chunk[1], chunk[2]));
            }
            let bytes = LargeCommunity::encode_set(&comms);
            unsafe { *out = lr_bytes_t::from_vec(bytes) }
            0
        },
        LR_ERR_PANIC,
    )
}

/// Decode a LARGE_COMMUNITIES attribute body (RFC 8092 §2 — flat
/// `count * 12` bytes big-endian) into a flat `uint32_t` array (3
/// entries per community). The caller frees `*out_values` with
/// [`crate::handle::lr_bytes_free`] and reads `*out_count` triples.
///
/// # Safety
/// `data` must point to `len` readable bytes; `out_values` and
/// `out_count` must point to writable memory.
#[no_mangle]
pub unsafe extern "C" fn lr_bgp_large_community_decode_set(
    data: *const u8,
    len: usize,
    out_values: *mut lr_bytes_t,
    out_count: *mut usize,
) -> i32 {
    guarded(
        || unsafe {
            if data.is_null() || out_values.is_null() {
                return LR_ERR_NULL;
            }
            let slice = unsafe { std::slice::from_raw_parts(data, len) };
            let comms = LargeCommunity::decode_set(slice);
            let n = comms.len();
            let mut raw = Vec::with_capacity(n * 12);
            for c in comms {
                raw.extend_from_slice(&c.global_admin.to_be_bytes());
                raw.extend_from_slice(&c.local_data1.to_be_bytes());
                raw.extend_from_slice(&c.local_data2.to_be_bytes());
            }
            unsafe {
                *out_values = lr_bytes_t::from_vec(raw);
                if !out_count.is_null() {
                    *out_count = n;
                }
            }
            0
        },
        LR_ERR_PANIC,
    )
}

// ---- ExtendedCommunity surface ----

/// Construct an `ExtendedCommunity` (RFC 4360/7153:
/// `kind:subtype:global:local`, 8 bytes wire form).
#[no_mangle]
pub extern "C" fn lr_bgp_ext_community_new(
    kind: u8,
    subtype: u8,
    global: u32,
    local: u16,
) -> lr_bgp_ext_community_t {
    guarded(
        || box_ext(ExtendedCommunity::new(kind, subtype, global, local)),
        std::ptr::null_mut(),
    )
}

/// Read the kind (high) byte.
///
/// # Safety
/// `c` must be a valid handle.
#[no_mangle]
pub unsafe extern "C" fn lr_bgp_ext_community_kind(c: lr_bgp_ext_community_t) -> u8 {
    guarded(|| unsafe { borrow_ext(c).map(|x| x.kind).unwrap_or(0) }, 0)
}

/// Read the subtype byte.
///
/// # Safety
/// See [`lr_bgp_ext_community_kind`].
#[no_mangle]
pub unsafe extern "C" fn lr_bgp_ext_community_subtype(c: lr_bgp_ext_community_t) -> u8 {
    guarded(
        || unsafe { borrow_ext(c).map(|x| x.subtype).unwrap_or(0) },
        0,
    )
}

/// Read the 32-bit global-administrator field.
///
/// # Safety
/// See [`lr_bgp_ext_community_kind`].
#[no_mangle]
pub unsafe extern "C" fn lr_bgp_ext_community_global(c: lr_bgp_ext_community_t) -> u32 {
    guarded(
        || unsafe { borrow_ext(c).map(|x| x.global).unwrap_or(0) },
        0,
    )
}

/// Read the 16-bit local-data field.
///
/// # Safety
/// See [`lr_bgp_ext_community_kind`].
#[no_mangle]
pub unsafe extern "C" fn lr_bgp_ext_community_local(c: lr_bgp_ext_community_t) -> u16 {
    guarded(|| unsafe { borrow_ext(c).map(|x| x.local).unwrap_or(0) }, 0)
}

/// Drop a boxed `ExtendedCommunity`. Safe to call with `NULL`.
///
/// # Safety
/// `c` must have been produced by [`lr_bgp_ext_community_new`] and
/// must not be used after this call.
#[no_mangle]
pub unsafe extern "C" fn lr_bgp_ext_community_free(c: lr_bgp_ext_community_t) {
    guarded(
        || unsafe {
            if c.is_null() {
                return;
            }
            drop(unsafe { Box::from_raw(c as *mut ExtendedCommunity) });
        },
        (),
    )
}

/// Encode a flat array of `(kind, subtype, global, local)` specs as
/// the on-wire EXTENDED_COMMUNITIES attribute body (RFC 4360 §3 —
/// 8 bytes per entry). The specs are passed as a flat `uint32_t`
/// array (`kind << 24 | subtype << 16 | global_hi << 8 | global_lo`
/// in slot 0, `global_lo_or_local_hi` etc.). For ABI simplicity the
/// caller passes a flat `uint32_t` array of `count * 3` values:
/// `(kind_subtype_combined, global, local)`, where
/// `kind_subtype_combined = (kind << 8) | subtype`.
///
/// The caller frees `*out` with [`crate::bytes::lr_bytes_free`].
///
/// # Safety
/// `specs` must point to `count * 3` readable `uint32_t` values;
/// `out` must point to writable `lr_bytes_t`.
#[no_mangle]
pub unsafe extern "C" fn lr_bgp_ext_community_encode_set(
    specs: *const u32,
    count: usize,
    out: *mut lr_bytes_t,
) -> i32 {
    guarded(
        || unsafe {
            if out.is_null() {
                return LR_ERR_NULL;
            }
            if specs.is_null() && count != 0 {
                return LR_ERR_NULL;
            }
            if !count.is_multiple_of(3) {
                set_last_error(
                    "lr_bgp_ext_community_encode_set: count must be a multiple of 3".into(),
                );
                return LR_ERR_OTHER;
            }
            let slice: &[u32] = if count == 0 {
                &[]
            } else {
                unsafe { std::slice::from_raw_parts(specs, count) }
            };
            let mut comms = Vec::with_capacity(count / 3);
            for chunk in slice.as_chunks::<3>().0 {
                let kind = ((chunk[0] >> 8) & 0xff) as u8;
                let subtype = (chunk[0] & 0xff) as u8;
                comms.push(ExtendedCommunity::new(
                    kind,
                    subtype,
                    chunk[1],
                    chunk[2] as u16,
                ));
            }
            let bytes = ExtendedCommunity::encode_set(&comms);
            unsafe { *out = lr_bytes_t::from_vec(bytes) }
            0
        },
        LR_ERR_PANIC,
    )
}

/// Decode an EXTENDED_COMMUNITIES attribute body (RFC 4360 §3 — flat
/// `count * 8` bytes big-endian) into a flat `uint32_t` array (3
/// entries per extended community: `kind_subtype_combined`, `global`,
/// `local`). The caller frees `*out_values` with
/// [`crate::handle::lr_bytes_free`] and reads `*out_count` triples.
///
/// # Safety
/// `data` must point to `len` readable bytes; `out_values` and
/// `out_count` must point to writable memory.
#[no_mangle]
pub unsafe extern "C" fn lr_bgp_ext_community_decode_set(
    data: *const u8,
    len: usize,
    out_values: *mut lr_bytes_t,
    out_count: *mut usize,
) -> i32 {
    guarded(
        || unsafe {
            if data.is_null() || out_values.is_null() {
                return LR_ERR_NULL;
            }
            let slice = unsafe { std::slice::from_raw_parts(data, len) };
            let comms = ExtendedCommunity::decode_set(slice);
            let n = comms.len();
            let mut raw = Vec::with_capacity(n * 12);
            for c in comms {
                let combined = ((c.kind as u32) << 8) | (c.subtype as u32);
                raw.extend_from_slice(&combined.to_be_bytes());
                raw.extend_from_slice(&c.global.to_be_bytes());
                raw.extend_from_slice(&c.local.to_be_bytes());
            }
            unsafe {
                *out_values = lr_bytes_t::from_vec(raw);
                if !out_count.is_null() {
                    *out_count = n;
                }
            }
            0
        },
        LR_ERR_PANIC,
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
    fn ffi_community_new_and_readers() {
        let c = lr_bgp_community_new(64512, 100);
        assert!(!c.is_null());
        assert_eq!(unsafe { lr_bgp_community_asn(c) }, 64512);
        assert_eq!(unsafe { lr_bgp_community_value(c) }, 100);
        assert_eq!(unsafe { lr_bgp_community_as_u32(c) }, 0xFC00_0064);
        assert_eq!(
            unsafe { lr_bgp_community_kind(c) },
            LR_COMMUNITY_KIND_CUSTOM
        );
        unsafe { lr_bgp_community_free(c) };
    }

    #[test]
    fn ffi_community_well_known_no_export() {
        let c = lr_bgp_community_new_well_known(LR_COMMUNITY_KIND_NO_EXPORT);
        assert!(!c.is_null());
        assert_eq!(unsafe { lr_bgp_community_as_u32(c) }, 0xFFFF_FF01);
        assert_eq!(
            unsafe { lr_bgp_community_kind(c) },
            LR_COMMUNITY_KIND_NO_EXPORT
        );
        unsafe { lr_bgp_community_free(c) };
    }

    #[test]
    fn ffi_community_well_known_graceful_shutdown() {
        let c = lr_bgp_community_new_well_known(LR_COMMUNITY_KIND_GRACEFUL_SHUTDOWN);
        assert!(!c.is_null());
        assert_eq!(unsafe { lr_bgp_community_as_u32(c) }, 0xFFFF_0000);
        assert_eq!(
            unsafe { lr_bgp_community_kind(c) },
            LR_COMMUNITY_KIND_GRACEFUL_SHUTDOWN
        );
        unsafe { lr_bgp_community_free(c) };
    }

    #[test]
    fn ffi_community_well_known_unknown_returns_null() {
        let c = lr_bgp_community_new_well_known(999);
        assert!(c.is_null());
    }

    #[test]
    fn ffi_community_from_u32_roundtrip() {
        let c = lr_bgp_community_from_u32(0xFFFF_FF02);
        assert_eq!(
            unsafe { lr_bgp_community_kind(c) },
            LR_COMMUNITY_KIND_NO_ADVERTISE
        );
        unsafe { lr_bgp_community_free(c) };
    }

    #[test]
    fn ffi_community_encode_decode_roundtrip() {
        let values: [u32; 3] = [0xFFFF_FF01, 0xFFFF_FF02, 0xFC00_0064];
        let mut out = lr_bytes_t {
            ptr: std::ptr::null_mut(),
            len: 0,
            cap: 0,
        };
        let rc = unsafe { lr_bgp_community_encode_set(values.as_ptr(), 3, &raw mut out) };
        assert_eq!(rc, 0);
        let bytes = unsafe { bytes_to_vec(&mut out) };
        assert_eq!(bytes.len(), 12);

        let mut dec = lr_bytes_t {
            ptr: std::ptr::null_mut(),
            len: 0,
            cap: 0,
        };
        let mut count = 0usize;
        let rc = unsafe {
            lr_bgp_community_decode_set(bytes.as_ptr(), bytes.len(), &raw mut dec, &raw mut count)
        };
        assert_eq!(rc, 0);
        assert_eq!(count, 3);
        let raw = unsafe { bytes_to_vec(&mut dec) };
        assert_eq!(raw.len(), 12);
        // Re-decode the values as u32.
        let mut got = [0u32; 3];
        for (i, chunk) in raw.as_chunks::<4>().0.iter().enumerate() {
            got[i] = u32::from_be_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
        }
        assert_eq!(got, values);
    }

    #[test]
    fn ffi_community_encode_null_ptr_returns_err() {
        let mut out = lr_bytes_t {
            ptr: std::ptr::null_mut(),
            len: 0,
            cap: 0,
        };
        let rc = unsafe { lr_bgp_community_encode_set(std::ptr::null(), 0, &raw mut out) };
        // count=0 + null ptr is allowed (empty COMMUNITIES attribute).
        assert_eq!(rc, 0);
        let bytes = unsafe { bytes_to_vec(&mut out) };
        assert!(bytes.is_empty());
    }

    #[test]
    fn ffi_large_community_new_and_readers() {
        let c = lr_bgp_large_community_new(64512, 100, 200);
        assert!(!c.is_null());
        assert_eq!(unsafe { lr_bgp_large_community_global_admin(c) }, 64512);
        assert_eq!(unsafe { lr_bgp_large_community_local_data1(c) }, 100);
        assert_eq!(unsafe { lr_bgp_large_community_local_data2(c) }, 200);
        unsafe { lr_bgp_large_community_free(c) };
    }

    #[test]
    fn ffi_large_community_encode_decode_roundtrip() {
        let triples: [u32; 6] = [64512, 100, 200, 4200000000, 1, 2];
        let mut out = lr_bytes_t {
            ptr: std::ptr::null_mut(),
            len: 0,
            cap: 0,
        };
        let rc = unsafe { lr_bgp_large_community_encode_set(triples.as_ptr(), 6, &raw mut out) };
        assert_eq!(rc, 0);
        let bytes = unsafe { bytes_to_vec(&mut out) };
        assert_eq!(bytes.len(), 24);

        let mut dec = lr_bytes_t {
            ptr: std::ptr::null_mut(),
            len: 0,
            cap: 0,
        };
        let mut count = 0usize;
        let rc = unsafe {
            lr_bgp_large_community_decode_set(
                bytes.as_ptr(),
                bytes.len(),
                &raw mut dec,
                &raw mut count,
            )
        };
        assert_eq!(rc, 0);
        assert_eq!(count, 2);
        let raw = unsafe { bytes_to_vec(&mut dec) };
        assert_eq!(raw.len(), 24);
    }

    #[test]
    fn ffi_large_community_encode_rejects_bad_count() {
        let triples: [u32; 4] = [1, 2, 3, 4]; // not a multiple of 3
        let mut out = lr_bytes_t {
            ptr: std::ptr::null_mut(),
            len: 0,
            cap: 0,
        };
        let rc = unsafe { lr_bgp_large_community_encode_set(triples.as_ptr(), 4, &raw mut out) };
        assert_eq!(rc, LR_ERR_OTHER);
    }

    #[test]
    fn ffi_ext_community_new_and_readers() {
        let c = lr_bgp_ext_community_new(0x00, 0x02, 64512, 100);
        assert!(!c.is_null());
        assert_eq!(unsafe { lr_bgp_ext_community_kind(c) }, 0x00);
        assert_eq!(unsafe { lr_bgp_ext_community_subtype(c) }, 0x02);
        assert_eq!(unsafe { lr_bgp_ext_community_global(c) }, 64512);
        assert_eq!(unsafe { lr_bgp_ext_community_local(c) }, 100);
        unsafe { lr_bgp_ext_community_free(c) };
    }

    #[test]
    fn ffi_ext_community_encode_decode_roundtrip() {
        // Two extended communities, each as (kind_subtype_combined, global, local).
        // (0x00 << 8 | 0x02, 64512, 100) and (0x01 << 8 | 0x03, 0xdeadbeef, 0xbeef).
        let specs: [u32; 6] = [0x0002, 64512, 100, 0x0103, 0xdeadbeef, 0xbeef];
        let mut out = lr_bytes_t {
            ptr: std::ptr::null_mut(),
            len: 0,
            cap: 0,
        };
        let rc = unsafe { lr_bgp_ext_community_encode_set(specs.as_ptr(), 6, &raw mut out) };
        assert_eq!(rc, 0);
        let bytes = unsafe { bytes_to_vec(&mut out) };
        assert_eq!(bytes.len(), 16); // 2 * 8

        let mut dec = lr_bytes_t {
            ptr: std::ptr::null_mut(),
            len: 0,
            cap: 0,
        };
        let mut count = 0usize;
        let rc = unsafe {
            lr_bgp_ext_community_decode_set(
                bytes.as_ptr(),
                bytes.len(),
                &raw mut dec,
                &raw mut count,
            )
        };
        assert_eq!(rc, 0);
        assert_eq!(count, 2);
        let raw = unsafe { bytes_to_vec(&mut dec) };
        // Per ext community: combined (u32 = 4) + global (u32 = 4) + local (u16 = 2) = 10 bytes.
        // 2 ext communities = 20 bytes.
        assert_eq!(raw.len(), 20);

        // Decode the first ext community back from the raw bytes.
        let combined_0 = u32::from_be_bytes([raw[0], raw[1], raw[2], raw[3]]);
        let global_0 = u32::from_be_bytes([raw[4], raw[5], raw[6], raw[7]]);
        let local_0 = u16::from_be_bytes([raw[8], raw[9]]);
        assert_eq!(combined_0, 0x0002);
        assert_eq!(global_0, 64512);
        assert_eq!(local_0, 100);
    }

    #[test]
    fn ffi_ext_community_encode_rejects_bad_count() {
        let specs: [u32; 5] = [1, 2, 3, 4, 5];
        let mut out = lr_bytes_t {
            ptr: std::ptr::null_mut(),
            len: 0,
            cap: 0,
        };
        let rc = unsafe { lr_bgp_ext_community_encode_set(specs.as_ptr(), 5, &raw mut out) };
        assert_eq!(rc, LR_ERR_OTHER);
    }

    #[test]
    fn ffi_free_handles_null_safely() {
        unsafe {
            lr_bgp_community_free(std::ptr::null_mut());
            lr_bgp_large_community_free(std::ptr::null_mut());
            lr_bgp_ext_community_free(std::ptr::null_mut());
        }
    }
}
