//! BGP-LS Attribute (`BgpLsAttr`) opaque handle + readers (issue #92 gap
//! closure).
//!
//! Mirrors the public Rust API of `lr_bgp::path::bgp_ls_attr::BgpLsAttr`
//! (RFC 7752 §3.3 + RFC 9514 §7-§8) so an embedder can build, inspect
//! and round-trip the BGP-LS Attribute that accompanies every BGP-LS
//! NLRI. Previously only the inner `BgpLsAttrTlv` was wrapped; the
//! outer attribute container was unreachable from C.

#![allow(unused_unsafe)]

use lr_bgp::path::bgp_ls_attr::BgpLsAttr;

use crate::error::{set_last_error, LrError, LR_ERR_PANIC};
use crate::guarded;
use crate::handle::lr_bytes_t;

const LR_ERR_NULL: i32 = LrError::Null as i32;
const LR_ERR_OTHER: i32 = LrError::Other as i32;

/// Opaque `BgpLsAttr` handle. C side never touches internals.
#[repr(C)]
pub struct OpaqueBgpLsAttr {
    _private: [u8; 0],
}
pub type lr_bgp_ls_attr_t = *mut OpaqueBgpLsAttr;

fn box_attr(a: BgpLsAttr) -> lr_bgp_ls_attr_t {
    Box::into_raw(Box::new(a)) as lr_bgp_ls_attr_t
}
unsafe fn unbox_attr(a: lr_bgp_ls_attr_t) -> Option<Box<BgpLsAttr>> {
    if a.is_null() {
        return None;
    }
    Some(unsafe { Box::from_raw(a as *mut BgpLsAttr) })
}
unsafe fn borrow_attr(a: lr_bgp_ls_attr_t) -> Option<&'static BgpLsAttr> {
    if a.is_null() {
        return None;
    }
    Some(unsafe { &*(a as *const BgpLsAttr) })
}

/// Construct an empty `BgpLsAttr` (no TLVs).
#[no_mangle]
pub extern "C" fn lr_bgp_ls_attr_new() -> lr_bgp_ls_attr_t {
    guarded(
        || box_attr(BgpLsAttr::new(Vec::new())),
        std::ptr::null_mut(),
    )
}

/// Drop a boxed `BgpLsAttr`. Safe to call with NULL.
///
/// # Safety
/// `a` must have been produced by a `lr_bgp_ls_attr_*` constructor and
/// must not be used after this call.
#[no_mangle]
pub unsafe extern "C" fn lr_bgp_ls_attr_free(a: lr_bgp_ls_attr_t) {
    guarded(
        || unsafe {
            drop(unbox_attr(a));
        },
        (),
    )
}

/// Number of TLVs in the attribute.
///
/// # Safety
/// `a` must be a live handle.
#[no_mangle]
pub unsafe extern "C" fn lr_bgp_ls_attr_len(a: lr_bgp_ls_attr_t) -> usize {
    guarded(
        || unsafe { borrow_attr(a).map(|x| x.len()).unwrap_or(0) },
        0,
    )
}

/// True when no TLVs are present. Returns 1 on a NULL handle (the
/// safe default for "nothing to encode").
///
/// # Safety
/// See [`lr_bgp_ls_attr_len`].
#[no_mangle]
pub unsafe extern "C" fn lr_bgp_ls_attr_is_empty(a: lr_bgp_ls_attr_t) -> u8 {
    guarded(
        || unsafe { borrow_attr(a).map(|x| x.is_empty() as u8).unwrap_or(1) },
        1,
    )
}

/// Wire length of the attribute value (concatenation of all TLVs,
/// excluding the BGP path attribute header).
///
/// # Safety
/// See [`lr_bgp_ls_attr_len`].
#[no_mangle]
pub unsafe extern "C" fn lr_bgp_ls_attr_value_len(a: lr_bgp_ls_attr_t) -> usize {
    guarded(
        || unsafe { borrow_attr(a).map(|x| x.value_len()).unwrap_or(0) },
        0,
    )
}

/// Encode the attribute value (the TLV stream) into a freshly
/// allocated `lr_bytes_t`. The caller frees it via `lr_bytes_free`.
///
/// # Safety
/// `a` must be a live handle. `out` must point to a writable
/// `lr_bytes_t`.
#[no_mangle]
pub unsafe extern "C" fn lr_bgp_ls_attr_encode(a: lr_bgp_ls_attr_t, out: *mut lr_bytes_t) -> i32 {
    guarded(
        || unsafe {
            let Some(x) = borrow_attr(a) else {
                return LR_ERR_NULL;
            };
            if out.is_null() {
                return LR_ERR_NULL;
            }
            match x.encode() {
                Ok(bytes) => {
                    unsafe { *out = lr_bytes_t::from_vec(bytes) }
                    0
                }
                Err(e) => {
                    set_last_error(e.to_string());
                    LR_ERR_OTHER
                }
            }
        },
        LR_ERR_PANIC,
    )
}

/// Decode the attribute value (a TLV stream) from `data`. On success
/// writes a freshly-allocated `lr_bgp_ls_attr_t` to `*out`. Returns 0
/// on success, `LR_ERR_NULL` on a NULL pointer, `LR_ERR_OTHER` on a
/// parse error (the last-error string carries the detail).
///
/// # Safety
/// `data` must point to `len` readable bytes. `out` must point to a
/// writable `lr_bgp_ls_attr_t`.
#[no_mangle]
pub unsafe extern "C" fn lr_bgp_ls_attr_decode(
    data: *const u8,
    len: usize,
    out: *mut lr_bgp_ls_attr_t,
) -> i32 {
    guarded(
        || unsafe {
            if data.is_null() || out.is_null() {
                return LR_ERR_NULL;
            }
            let slice = unsafe { std::slice::from_raw_parts(data, len) };
            match BgpLsAttr::decode(slice) {
                Ok(a) => {
                    unsafe { *out = box_attr(a) }
                    0
                }
                Err(e) => {
                    set_last_error(e.to_string());
                    LR_ERR_OTHER
                }
            }
        },
        LR_ERR_PANIC,
    )
}

/// Find the first TLV of a given `ty`. Returns 1 when one was found
/// (and writes the index to `*out_index`), 0 when the type is
/// absent, `LR_ERR_NULL` on a NULL handle.
///
/// The C side reads the TLV via `lr_bgp_ls_tlv_vec_at` with the
/// returned index — the `BgpLsAttrTlv` itself is not re-boxed here.
///
/// # Safety
/// `a` must be a live handle. `out_index` must point to a writable
/// `uintptr_t`.
#[no_mangle]
pub unsafe extern "C" fn lr_bgp_ls_attr_find(
    a: lr_bgp_ls_attr_t,
    ty: u16,
    out_index: *mut usize,
) -> i32 {
    guarded(
        || unsafe {
            let Some(x) = borrow_attr(a) else {
                return LR_ERR_NULL;
            };
            if out_index.is_null() {
                return LR_ERR_NULL;
            }
            // The Rust API returns `Option<&BgpLsAttrTlv>`; the C side
            // surfaces the index so the caller can fetch the TLV via
            // the existing `lr_bgp_ls_tlv_vec_at` accessor.
            for (i, t) in x.tlvs.iter().enumerate() {
                if t.ty() == ty {
                    unsafe { *out_index = i }
                    return 1;
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
    use lr_bgp::path::bgp_ls_attr::BgpLsAttrTlv;

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
    fn ffi_bgp_ls_attr_new_is_empty() {
        let a = lr_bgp_ls_attr_new();
        assert!(!a.is_null());
        assert_eq!(unsafe { lr_bgp_ls_attr_len(a) }, 0);
        assert_eq!(unsafe { lr_bgp_ls_attr_is_empty(a) }, 1);
        unsafe { lr_bgp_ls_attr_free(a) };
    }

    #[test]
    fn ffi_bgp_ls_attr_free_handles_null() {
        unsafe { lr_bgp_ls_attr_free(std::ptr::null_mut()) };
    }

    #[test]
    fn ffi_bgp_ls_attr_round_trip_empty() {
        let a = lr_bgp_ls_attr_new();
        let mut out = lr_bytes_t {
            ptr: std::ptr::null_mut(),
            len: 0,
            cap: 0,
        };
        let rc = unsafe { lr_bgp_ls_attr_encode(a, &raw mut out) };
        assert_eq!(rc, 0);
        let bytes = unsafe { bytes_to_vec(&mut out) };
        assert!(bytes.is_empty());
        unsafe { lr_bgp_ls_attr_free(a) };
    }

    #[test]
    fn ffi_bgp_ls_attr_decode_then_find() {
        // Build a one-TLV attribute in Rust, encode it, then decode
        // through the FFI and find the TLV by type.
        use lr_bgp::path::bgp_ls_attr::tlv_type::OPAQUE_NODE_ATTRIBUTE;
        let tlvs: Vec<BgpLsAttrTlv> = vec![BgpLsAttrTlv::OpaqueNodeAttribute(vec![0xab, 0xcd])];
        let rust_attr = BgpLsAttr::new(tlvs);
        let bytes = rust_attr.encode().unwrap();

        let mut decoded: lr_bgp_ls_attr_t = std::ptr::null_mut();
        let rc = unsafe { lr_bgp_ls_attr_decode(bytes.as_ptr(), bytes.len(), &raw mut decoded) };
        assert_eq!(rc, 0);
        assert!(!decoded.is_null());
        assert_eq!(unsafe { lr_bgp_ls_attr_len(decoded) }, 1);
        assert_eq!(unsafe { lr_bgp_ls_attr_is_empty(decoded) }, 0);

        // Find the TLV at its registered type.
        let mut idx = 0usize;
        let found = unsafe { lr_bgp_ls_attr_find(decoded, OPAQUE_NODE_ATTRIBUTE, &raw mut idx) };
        assert_eq!(found, 1);
        assert_eq!(idx, 0);

        // Find for an absent type.
        let mut idx2 = 0usize;
        let found2 = unsafe { lr_bgp_ls_attr_find(decoded, 0xFFFF, &raw mut idx2) };
        assert_eq!(found2, 0);

        unsafe { lr_bgp_ls_attr_free(decoded) };
    }

    #[test]
    fn ffi_bgp_ls_attr_decode_rejects_null() {
        let mut out: lr_bgp_ls_attr_t = std::ptr::null_mut();
        let rc = unsafe { lr_bgp_ls_attr_decode(std::ptr::null(), 0, &raw mut out) };
        assert_eq!(rc, LR_ERR_NULL);
    }

    #[test]
    fn ffi_bgp_ls_attr_len_returns_zero_on_null() {
        assert_eq!(unsafe { lr_bgp_ls_attr_len(std::ptr::null_mut()) }, 0);
        assert_eq!(unsafe { lr_bgp_ls_attr_value_len(std::ptr::null_mut()) }, 0);
    }
}
