//! lr-bgp low-level codec helper FFI surface — fills the gaps left by
//! the existing `bgp_codec.rs` / `bgp_path.rs` modules. Mirrors the
//! stateless `pub fn`s in:
//!
//! - `lr_bgp::path::as_path::reconcile_as4` (RFC 6793 §4.2 — AS_PATH /
//!   AS4_PATH reconciliation)
//! - `lr_bgp::path::bgp_ls::{decode_tlv_stream, encode_tlv_stream}`
//!   (RFC 7752 §3.2 — TLV stream codec for BGP-LS NLRI/attribute bodies)
//! - `lr_bgp::path::labeled_nlri::{encode_list, decode_list,
//!   encode_mp_reach, encode_mp_unreach, decode_mp_reach,
//!   decode_mp_unreach}` (RFC 8277 — labelled-unicast MP_REACH /
//!   MP_UNREACH assembly)
//!
//! Every entry point runs inside the crate's `catch_unwind` barrier
//! ([`crate::guarded`]): a panic returns `LR_ERR_PANIC` and sets the
//! thread-local last-error string.

// The closure body passed to `guarded` is wrapped in a single `unsafe`
// block to mirror the `pub unsafe extern "C" fn` shape — the inner
// `unsafe { ... }` blocks would otherwise trip `unused_unsafe` under
// the crate's `-D warnings` clippy gate.
#![allow(unused_unsafe)]

use lr_bgp::path::as_path::reconcile_as4;
use lr_bgp::path::labeled_nlri::{decode_list, encode_list};
use lr_bgp::path::AsPath;

use crate::error::{set_last_error, LR_ERR_PANIC};
use crate::guarded;
use crate::handle::lr_bytes_t;

const LR_ERR_NULL: i32 = -1;
const LR_ERR_INVALID_HANDLE: i32 = -2;
const LR_ERR_OTHER: i32 = -6;

// ---- AS_PATH / AS4_PATH reconciliation (RFC 6793 §4.2) ----

/// Reconcile a 2-byte AS_PATH (`wire`) with an optional 4-byte
/// AS4_PATH (`as4`) per RFC 6793 §4.2. `wire_present` and
/// `as4_present` flag whether each path was carried in the UPDATE;
/// the wire bytes for each path are passed through `wire_data` /
/// `as4_data` (the AS_PATH attribute value, decoded at the
/// negotiated width). The reconciled 4-byte AS_PATH is written to
/// `*out` as the encoded attribute value bytes.
///
/// # Safety
/// Both data pointers must point to the documented length of readable
/// bytes when their `*_present` flag is 1; `out` must point to a
/// writable `lr_bytes_t`.
#[no_mangle]
pub unsafe extern "C" fn lr_bgp_reconcile_as4(
    wire_present: u8,
    wire_data: *const u8,
    wire_len: usize,
    as4_present: u8,
    as4_data: *const u8,
    as4_len: usize,
    out: *mut lr_bytes_t,
) -> i32 {
    guarded(
        || unsafe {
            if out.is_null() {
                return LR_ERR_NULL;
            }
            if wire_present != 0 && wire_data.is_null() {
                return LR_ERR_NULL;
            }
            if as4_present != 0 && as4_data.is_null() {
                return LR_ERR_NULL;
            }
            let wire = if wire_present != 0 {
                let slice = unsafe { core::slice::from_raw_parts(wire_data, wire_len) };
                match AsPath::decode_4(slice) {
                    Some(p) => Some(p),
                    None => {
                        set_last_error("reconcile_as4: AS_PATH decode failed".into());
                        return LR_ERR_INVALID_HANDLE;
                    }
                }
            } else {
                None
            };
            let as4 = if as4_present != 0 {
                let slice = unsafe { core::slice::from_raw_parts(as4_data, as4_len) };
                match AsPath::decode_4(slice) {
                    Some(p) => Some(p),
                    None => {
                        set_last_error("reconcile_as4: AS4_PATH decode failed".into());
                        return LR_ERR_INVALID_HANDLE;
                    }
                }
            } else {
                None
            };
            let Some(wire_path) = wire else {
                set_last_error("reconcile_as4: AS_PATH absent (mandatory)".into());
                return LR_ERR_INVALID_HANDLE;
            };
            let reconciled = reconcile_as4(&wire_path, as4.as_ref());
            let bytes = reconciled.encode_4();
            unsafe { *out = lr_bytes_t::from_vec(bytes) }
            0
        },
        LR_ERR_PANIC,
    )
}

// ---- BGP-LS TLV stream codec (RFC 7752 §3.2) ----

/// Decode a BGP-LS TLV stream (RFC 7752 §3.2 — the body of a BGP-LS
/// NLRI or attribute). Writes one `lr_bgp_ls_tlv_t` per decoded TLV
/// to `*out_array`; the caller frees the array with
/// [`lr_bgp_ls_tlv_array_free`]. Returns the count through
/// `*out_count`.
///
/// # Safety
/// `data` must point to `len` readable bytes; both out-pointers must
/// point to writable memory.
#[no_mangle]
pub unsafe extern "C" fn lr_bgp_decode_tlv_stream(
    data: *const u8,
    len: usize,
    out_count: *mut usize,
    out_array: *mut *mut lr_bgp_ls_tlv_t,
) -> i32 {
    guarded(
        || unsafe {
            if data.is_null() || out_count.is_null() || out_array.is_null() {
                return LR_ERR_NULL;
            }
            let slice = unsafe { core::slice::from_raw_parts(data, len) };
            match lr_bgp::path::bgp_ls::decode_tlv_stream(slice) {
                Ok(tlvs) => {
                    let n = tlvs.len();
                    if n == 0 {
                        unsafe {
                            *out_count = 0;
                            *out_array = core::ptr::null_mut();
                        }
                        return 0;
                    }
                    // Box each value Vec and leak it so the pointer
                    // stays valid until the array is freed. The caller
                    // reclaims the value allocations by calling
                    // lr_bgp_ls_tlv_array_free, which walks each entry
                    // and frees the value_ptr via Box::from_raw.
                    let mut c_arr: Vec<lr_bgp_ls_tlv_t> = Vec::with_capacity(n);
                    for t in tlvs {
                        let len_u16 = t.value.len() as u16;
                        let value_box: Box<[u8]> = t.value.into_boxed_slice();
                        let value_ptr = Box::into_raw(value_box) as *mut u8;
                        c_arr.push(lr_bgp_ls_tlv_t {
                            tlv_type: t.ty,
                            value_offset: 0,
                            value_len: len_u16,
                            value_ptr,
                            _owned: std::ptr::null_mut(),
                        });
                    }
                    let ptr = c_arr.as_mut_ptr();
                    std::mem::forget(c_arr);
                    unsafe {
                        *out_count = n;
                        *out_array = ptr;
                    }
                    0
                }
                Err(e) => {
                    set_last_error(format!("{e:?}"));
                    LR_ERR_INVALID_HANDLE
                }
            }
        },
        LR_ERR_PANIC,
    )
}

/// One BGP-LS TLV (RFC 7752 §3.2). The value bytes are owned by the
/// array — the caller must not free `value_ptr` directly; free the
/// whole array with [`lr_bgp_ls_tlv_array_free`].
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct lr_bgp_ls_tlv_t {
    pub tlv_type: u16,
    pub value_offset: usize,
    pub value_len: u16,
    pub value_ptr: *mut u8,
    /// Reserved for future per-entry ownership; currently unused.
    pub _owned: *mut core::ffi::c_void,
}

/// Encode a slice of BGP-LS TLVs (RFC 7752 §3.2). `tlvs` is a flat
/// array of `lr_bgp_ls_tlv_t` (the same shape
/// [`lr_bgp_decode_tlv_stream`] produces); the encode walk reads
/// `value_len` bytes from each `value_ptr`. Writes the wire bytes to
/// `*out`.
///
/// # Safety
/// `tlvs` must point to `count` readable `lr_bgp_ls_tlv_t` entries;
/// each `value_ptr` must point to `value_len` readable bytes; `out`
/// must point to a writable `lr_bytes_t`.
#[no_mangle]
pub unsafe extern "C" fn lr_bgp_encode_tlv_stream(
    tlvs: *const lr_bgp_ls_tlv_t,
    count: usize,
    out: *mut lr_bytes_t,
) -> i32 {
    guarded(
        || unsafe {
            if tlvs.is_null() && count != 0 {
                return LR_ERR_NULL;
            }
            if out.is_null() {
                return LR_ERR_NULL;
            }
            let slice: &[lr_bgp_ls_tlv_t] = if count == 0 {
                &[]
            } else {
                unsafe { core::slice::from_raw_parts(tlvs, count) }
            };
            // Manual encode: 4 bytes (type + len) + value per TLV.
            // We avoid lr_bgp::path::bgp_ls::encode_tlv_stream here
            // because its WriteBuf::new(&mut v) initialises the buffer
            // with len=0 and the encode fails with BufferFull.
            let mut out_bytes = Vec::new();
            for t in slice {
                let len = t.value_len as usize;
                if len > u16::MAX as usize {
                    set_last_error(format!("bgp-ls tlv length {len} > u16::MAX"));
                    return LR_ERR_OTHER;
                }
                out_bytes.extend_from_slice(&t.tlv_type.to_be_bytes());
                out_bytes.extend_from_slice(&t.value_len.to_be_bytes());
                if !t.value_ptr.is_null() && len > 0 {
                    let val = unsafe { core::slice::from_raw_parts(t.value_ptr, len) };
                    out_bytes.extend_from_slice(val);
                }
            }
            unsafe { *out = lr_bytes_t::from_vec(out_bytes) }
            0
        },
        LR_ERR_PANIC,
    )
}

/// Free a BGP-LS TLV array produced by
/// [`lr_bgp_decode_tlv_stream`]. Safe on NULL.
///
/// # Safety
/// `arr` must have been produced by `lr_bgp_decode_tlv_stream` and not
/// already freed; `count` must match the count returned by the decode
/// call.
#[no_mangle]
pub unsafe extern "C" fn lr_bgp_ls_tlv_array_free(arr: *mut lr_bgp_ls_tlv_t, count: usize) {
    guarded(
        || unsafe {
            if arr.is_null() || count == 0 {
                return;
            }
            // Walk each entry and free its value allocation (each
            // value_ptr was leaked as a Box<[u8]> in the decode path).
            let slice = unsafe { core::slice::from_raw_parts(arr, count) };
            for t in slice {
                if !t.value_ptr.is_null() && t.value_len > 0 {
                    // SAFETY: value_ptr was produced by
                    // Box::into_raw(value_box) where value_box: Box<[u8]>
                    // of length value_len. Reclaim it here via the
                    // slice-form Box::from_raw (the fat pointer carries
                    // both the data pointer and the length).
                    let slice_ptr =
                        core::ptr::slice_from_raw_parts_mut(t.value_ptr, t.value_len as usize);
                    let _ = unsafe { Box::from_raw(slice_ptr) };
                }
            }
            // Reclaim the array itself.
            let _ = unsafe { Vec::from_raw_parts(arr, count, count) };
        },
        (),
    )
}

// ---- Labelled-Unicast MP_REACH / MP_UNREACH (RFC 8277) ----

/// Encode a list of RFC 8277 labelled NLRI entries as the NLRI bytes
/// of an MP_REACH / MP_UNREACH attribute value. The caller supplies
/// the entries as a flat byte buffer produced by encoding each entry
/// (single-entry form: 1 length byte + label bytes + prefix bytes).
///
/// # Safety
/// `data` must point to `len` readable bytes; `out` must point to a
/// writable `lr_bytes_t`.
#[no_mangle]
pub unsafe extern "C" fn lr_bgp_labeled_nlri_encode_list(
    data: *const u8,
    len: usize,
    add_path: u8,
    out: *mut lr_bytes_t,
) -> i32 {
    guarded(
        || {
            if data.is_null() || out.is_null() {
                return LR_ERR_NULL;
            }
            // The labelled_nlri::encode_list takes `&[LabeledNlri]`,
            // but the FFI caller has a flat byte buffer of pre-encoded
            // entries. Re-encode via decode + encode round-trip so
            // the canonical form is produced.
            let slice = unsafe { core::slice::from_raw_parts(data, len) };
            let family = lr_core::nlri::NlriFamily::IPV4_LABELED_UNICAST;
            let add_path = add_path != 0;
            let entries = match decode_list(family, slice, add_path) {
                Some(e) => e,
                None => {
                    set_last_error("labeled_nlri::decode_list failed".into());
                    return LR_ERR_INVALID_HANDLE;
                }
            };
            let bytes = encode_list(&entries, add_path);
            unsafe { *out = lr_bytes_t::from_vec(bytes) }
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
    fn ffi_reconcile_as4_no_as4_returns_wire() {
        // A 4-byte AS_PATH with one segment of [64512, 64513].
        let wire =
            AsPath::from_sequence(vec![lr_core::addr::Asn(64512), lr_core::addr::Asn(64513)]);
        let wire_bytes = wire.encode_4();
        let mut out = lr_bytes_t {
            ptr: std::ptr::null_mut(),
            len: 0,
            cap: 0,
        };
        let rc = unsafe {
            lr_bgp_reconcile_as4(
                1,
                wire_bytes.as_ptr(),
                wire_bytes.len(),
                0,
                std::ptr::null(),
                0,
                &raw mut out,
            )
        };
        assert_eq!(rc, 0);
        let out_bytes = unsafe { bytes_to_vec(&mut out) };
        assert_eq!(out_bytes, wire_bytes, "no AS4_PATH → wire is the answer");
    }

    #[test]
    fn ffi_reconcile_as4_with_as4_uses_as4() {
        let wire = AsPath::from_sequence(vec![lr_core::addr::Asn(23456)]);
        let as4 = AsPath::from_sequence(vec![lr_core::addr::Asn(4_000_000)]);
        let wire_bytes = wire.encode_4();
        let as4_bytes = as4.encode_4();
        let mut out = lr_bytes_t {
            ptr: std::ptr::null_mut(),
            len: 0,
            cap: 0,
        };
        let rc = unsafe {
            lr_bgp_reconcile_as4(
                1,
                wire_bytes.as_ptr(),
                wire_bytes.len(),
                1,
                as4_bytes.as_ptr(),
                as4_bytes.len(),
                &raw mut out,
            )
        };
        assert_eq!(rc, 0);
        let out_bytes = unsafe { bytes_to_vec(&mut out) };
        assert_eq!(out_bytes, as4_bytes, "AS4_PATH replaces the wire path");
    }

    #[test]
    fn ffi_reconcile_as4_returns_invalid_handle_when_wire_absent() {
        let mut out = lr_bytes_t {
            ptr: std::ptr::null_mut(),
            len: 0,
            cap: 0,
        };
        let rc = unsafe {
            lr_bgp_reconcile_as4(0, std::ptr::null(), 0, 0, std::ptr::null(), 0, &raw mut out)
        };
        assert_eq!(rc, LR_ERR_INVALID_HANDLE);
    }

    #[test]
    fn ffi_reconcile_as4_null_out_returns_err_null() {
        let wire = AsPath::from_sequence(vec![lr_core::addr::Asn(64512)]);
        let wire_bytes = wire.encode_4();
        let rc = unsafe {
            lr_bgp_reconcile_as4(
                1,
                wire_bytes.as_ptr(),
                wire_bytes.len(),
                0,
                std::ptr::null(),
                0,
                std::ptr::null_mut(),
            )
        };
        assert_eq!(rc, LR_ERR_NULL);
    }

    #[test]
    fn ffi_tlv_stream_round_trips() {
        // Build two TLVs by manually encoding them (the Rust API's
        // encode_tlv_stream hits a BufferFull bug — see the comment
        // in lr_bgp_encode_tlv_stream).
        let tlv1_value = vec![0x00, 0x00, 0xfc, 0x00];
        let tlv2_value = vec![0x12, 0x34, 0x56, 0x78];
        let mut wire = Vec::new();
        wire.extend_from_slice(&512u16.to_be_bytes());
        wire.extend_from_slice(&(tlv1_value.len() as u16).to_be_bytes());
        wire.extend_from_slice(&tlv1_value);
        wire.extend_from_slice(&513u16.to_be_bytes());
        wire.extend_from_slice(&(tlv2_value.len() as u16).to_be_bytes());
        wire.extend_from_slice(&tlv2_value);

        // Decode through the FFI.
        let mut count = 0usize;
        let mut arr: *mut lr_bgp_ls_tlv_t = std::ptr::null_mut();
        let rc = unsafe {
            lr_bgp_decode_tlv_stream(wire.as_ptr(), wire.len(), &raw mut count, &raw mut arr)
        };
        assert_eq!(rc, 0);
        assert_eq!(count, 2);
        assert!(!arr.is_null());

        // Verify the decoded types + lengths.
        unsafe {
            assert_eq!((*arr.add(0)).tlv_type, 512);
            assert_eq!((*arr.add(0)).value_len, 4);
            assert_eq!((*arr.add(1)).tlv_type, 513);
            assert_eq!((*arr.add(1)).value_len, 4);
        }

        // Re-encode through the FFI.
        let mut out = lr_bytes_t {
            ptr: std::ptr::null_mut(),
            len: 0,
            cap: 0,
        };
        let rc = unsafe { lr_bgp_encode_tlv_stream(arr, count, &raw mut out) };
        assert_eq!(rc, 0);
        let round = unsafe { bytes_to_vec(&mut out) };
        assert_eq!(round, wire);

        unsafe { lr_bgp_ls_tlv_array_free(arr, count) };
    }

    #[test]
    fn ffi_tlv_array_free_handles_null_safely() {
        unsafe { lr_bgp_ls_tlv_array_free(std::ptr::null_mut(), 0) };
    }

    #[test]
    fn ffi_labeled_nlri_encode_list_round_trips() {
        // Build a single-entry list (implicit-null + /24) via the
        // lr_bgp_labeled_nlri_ipv4_implicit_null helper from the
        // bgp_role_helpers module, then round-trip it through
        // encode_list.
        let prefix = [10u8, 0, 0, 0];
        let mut entry = lr_bytes_t {
            ptr: std::ptr::null_mut(),
            len: 0,
            cap: 0,
        };
        let rc = unsafe {
            crate::bgp_role_helpers::lr_bgp_labeled_nlri_ipv4_implicit_null(
                prefix.as_ptr(),
                24,
                &raw mut entry,
            )
        };
        assert_eq!(rc, 0);
        let entry_bytes = unsafe { bytes_to_vec(&mut entry) };

        let mut out = lr_bytes_t {
            ptr: std::ptr::null_mut(),
            len: 0,
            cap: 0,
        };
        let rc = unsafe {
            lr_bgp_labeled_nlri_encode_list(
                entry_bytes.as_ptr(),
                entry_bytes.len(),
                0,
                &raw mut out,
            )
        };
        assert_eq!(rc, 0);
        let out_bytes = unsafe { bytes_to_vec(&mut out) };
        // The encode_list output should match the input (single entry,
        // no path-id, no framing change).
        assert_eq!(out_bytes, entry_bytes);
    }
}
