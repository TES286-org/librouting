//! SRv6 codec FFI: `lr_srv6_encode_srh`, `lr_srv6_decode_srh`.
//!
//! Stateless. Accepts raw byte slices / SIDs; returns `lr_bytes_t`
//! carrying the SRH wire bytes (RFC 8754 §2). The C surface is
//! documented in `include/lr_ffi.h` (cbindgen-generated).
//!
//! Every entry point runs inside the crate's `catch_unwind` barrier
//! ([`crate::guarded`]): a panic returns `LR_ERR_PANIC` and sets the
//! thread-local last-error string.

use lr_srv6::{Sid, Srh};

use crate::error::{set_last_error, LR_ERR_PANIC};
use crate::guarded;
use crate::handle::lr_bytes_t;

/// Encode an SRH from a list of SID bytes. Each SID is 16 bytes; the
/// caller passes a flat `data` of `len = n * 16` bytes. The encoded
/// SRH (RFC 8754 §2 wire form) is written to `*out`.
///
/// Returns 0 on success, negative on error:
/// - `-1`: null pointer or `len` not a multiple of 16.
/// - `-4`: panic.
/// - `-5`: SRH encode error (set via `lr_last_error`).
#[no_mangle]
pub extern "C" fn lr_srv6_encode_srh(data: *const u8, len: usize, out: *mut lr_bytes_t) -> i32 {
    guarded(
        || {
            if data.is_null() || out.is_null() {
                return -1;
            }
            if !len.is_multiple_of(16) {
                set_last_error("SRH input length must be a multiple of 16".into());
                return -1;
            }
            let slice = unsafe { core::slice::from_raw_parts(data, len) };
            let mut sids = Vec::with_capacity(len / 16);
            for chunk in slice.as_chunks::<16>().0 {
                sids.push(Sid::from_octets(*chunk));
            }
            match Srh::new(sids) {
                Ok(srh) => match srh.encode_vec() {
                    Ok(bytes) => {
                        unsafe { *out = lr_bytes_t::from_vec(bytes) }
                        0
                    }
                    Err(e) => {
                        set_last_error(e.to_string());
                        -5
                    }
                },
                Err(e) => {
                    set_last_error(e.to_string());
                    -5
                }
            }
        },
        LR_ERR_PANIC,
    )
}

/// Decode an SRH from `data` (RFC 8754 §2 wire form). On success,
/// writes a freshly-allocated `lr_bytes_t` to `*out` carrying the
/// segment list bytes (16 octets per SID, concatenated in wire
/// order). The TLV bytes are appended after the segment list so the
/// caller can recover the full SRH body, but the typical caller
/// only needs the segment list.
///
/// Returns 0 on success, negative on error:
/// - `-1`: null pointer.
/// - `-3`: input too short.
/// - `-4`: panic.
/// - `-5`: SRH decode error (set via `lr_last_error`).
#[no_mangle]
pub extern "C" fn lr_srv6_decode_srh(data: *const u8, len: usize, out: *mut lr_bytes_t) -> i32 {
    guarded(
        || {
            if data.is_null() || out.is_null() {
                return -1;
            }
            let slice = unsafe { core::slice::from_raw_parts(data, len) };
            match Srh::decode(slice) {
                Ok(srh) => {
                    let mut bytes = Vec::with_capacity(srh.len() * 16);
                    for sid in srh.segments.iter() {
                        bytes.extend_from_slice(sid.as_bytes());
                    }
                    bytes.extend_from_slice(&srh.tlvs);
                    unsafe { *out = lr_bytes_t::from_vec(bytes) }
                    0
                }
                Err(e) => {
                    set_last_error(e.to_string());
                    -5
                }
            }
        },
        LR_ERR_PANIC,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::str::FromStr;

    /// Reclaim a `lr_bytes_t` into a Rust `Vec<u8>` for assertions.
    /// Takes ownership — the caller must not use the handle afterwards.
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
    fn ffi_srh_roundtrip() {
        let sid1 = Sid::from_str("fcbb:bb00::1").unwrap();
        let sid2 = Sid::from_str("fcbb:bb01::1").unwrap();
        let mut input = Vec::new();
        input.extend_from_slice(sid1.as_bytes());
        input.extend_from_slice(sid2.as_bytes());
        let mut out = lr_bytes_t {
            ptr: std::ptr::null_mut(),
            len: 0,
            cap: 0,
        };
        let rc = lr_srv6_encode_srh(input.as_ptr(), input.len(), &mut out);
        assert_eq!(rc, 0);
        // SAFETY: `out` was populated by `lr_srv6_encode_srh` above and
        // owns its bytes; we reclaim them into a Vec for assertions and
        // null out the handle so the cleanup is no-op.
        let srh_bytes = unsafe { bytes_to_vec(&mut out) };
        // SRH length: 8 fixed + 2*16 segments = 40.
        assert_eq!(srh_bytes.len(), 40);
        // Routing type at offset 2.
        assert_eq!(srh_bytes[2], lr_srv6::SRH_ROUTING_TYPE);

        // Decode back.
        let mut out2 = lr_bytes_t {
            ptr: std::ptr::null_mut(),
            len: 0,
            cap: 0,
        };
        let rc = lr_srv6_decode_srh(srh_bytes.as_ptr(), srh_bytes.len(), &mut out2);
        assert_eq!(rc, 0);
        let decoded = unsafe { bytes_to_vec(&mut out2) };
        assert_eq!(decoded, input);
    }

    #[test]
    fn ffi_srh_encode_rejects_bad_length() {
        let input = [0u8; 17]; // not a multiple of 16
        let mut out = lr_bytes_t {
            ptr: std::ptr::null_mut(),
            len: 0,
            cap: 0,
        };
        let rc = lr_srv6_encode_srh(input.as_ptr(), input.len(), &mut out);
        assert_eq!(rc, -1);
    }

    #[test]
    fn ffi_srh_encode_rejects_null() {
        let rc = lr_srv6_encode_srh(core::ptr::null(), 0, core::ptr::null_mut());
        assert_eq!(rc, -1);
    }
}
