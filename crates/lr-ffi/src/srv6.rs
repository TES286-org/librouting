//! SRv6 codec FFI: `lr_srv6_encode_srh`, `lr_srv6_decode_srh` plus
//! the `Behavior` / `Locator` / `Sid` type-level surface.
//!
//! Stateless. Accepts raw byte slices / SIDs; returns `lr_bytes_t`
//! carrying the SRH wire bytes (RFC 8754 §2). The C surface is
//! documented in `include/lr_ffi.h` (cbindgen-generated).
//!
//! Every entry point runs inside the crate's `catch_unwind` barrier
//! ([`crate::guarded`]): a panic returns `LR_ERR_PANIC` and sets the
//! thread-local last-error string.

// The closure body passed to `guarded` is wrapped in a single `unsafe`
// block to mirror the `pub unsafe extern "C" fn` shape — the inner
// `unsafe { ... }` blocks would otherwise trip `unused_unsafe` under
// the crate's `-D warnings` clippy gate.
#![allow(unused_unsafe)]

use lr_srv6::{Behavior, Locator, Sid, Srh};

use crate::error::{set_last_error, LrError, LR_ERR_PANIC};
use crate::guarded;
use crate::handle::lr_bytes_t;

/// Encode an SRH from a list of SID bytes. Each SID is 16 bytes; the
/// caller passes a flat `data` of `len = n * 16` bytes. The encoded
/// SRH (RFC 8754 §2 wire form) is written to `*out`.
///
/// Returns 0 on success, negative on error:
/// - `-1`: null pointer or `len` not a multiple of 16.
/// - `-4`: panic.
/// - `LR_ERR_CODEC` (-5): SRH encode error (set via `lr_last_error`).
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
                        LrError::Codec as i32
                    }
                },
                Err(e) => {
                    set_last_error(e.to_string());
                    LrError::Codec as i32
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
/// - `LR_ERR_CODEC` (-5): SRH decode error (set via `lr_last_error`).
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

// ---- Behavior (RFC 8986 endpoint behavior registry) ----

/// Look up a `Behavior` by its 16-bit wire value (RFC 8986 §9.2,
/// IANA registry). Returns 1 when the value maps to a known behavior,
/// 0 when it is unassigned. The 16-bit wire value is written to
/// `*out_value` and the behavior's mnemonic name (e.g. `"End"`,
/// `"End.X with PSP"`) is written to `*out_name` as a NUL-terminated
/// C string copied into the caller-supplied `name_cap`-byte buffer.
///
/// # Safety
/// `out_name` must point to at least `name_cap` writable bytes (NULL
/// skips the name copy). `out_value` must be a writable `uint16_t*`
/// (NULL skips the value copy).
#[no_mangle]
pub unsafe extern "C" fn lr_srv6_behavior_from_wire(
    wire: u16,
    out_value: *mut u16,
    out_name: *mut std::os::raw::c_char,
    name_cap: usize,
) -> u8 {
    guarded(
        || {
            let Some(b) = Behavior::from_wire(wire) else {
                return 0;
            };
            if !out_value.is_null() {
                unsafe { *out_value = b.wire_value() };
            }
            if !out_name.is_null() && name_cap > 0 {
                let name = b.name();
                let bytes = name.as_bytes();
                let take = bytes.len().min(name_cap - 1);
                unsafe {
                    std::ptr::copy_nonoverlapping(
                        bytes.as_ptr(),
                        out_name as *mut u8,
                        take,
                    );
                    *out_name.add(take) = 0;
                }
            }
            1
        },
        0,
    )
}

/// Get the 16-bit wire value of a `Behavior`. The behavior is identified
/// by its wire value `wire` — invalid values return 0.
#[no_mangle]
pub extern "C" fn lr_srv6_behavior_wire_value(wire: u16) -> u16 {
    guarded(
        || {
            Behavior::from_wire(wire)
                .map(|b| b.wire_value())
                .unwrap_or(0)
        },
        0,
    )
}

/// True when `wire` is one of the PSP-flavored End.* behaviors (PSP =
/// Penultimate Segment Pop, RFC 8986 §4.16). Returns 0 for unknown
/// values.
#[no_mangle]
pub extern "C" fn lr_srv6_behavior_is_psp(wire: u16) -> u8 {
    guarded(
        || {
            Behavior::from_wire(wire)
                .map(|b| b.is_psp() as u8)
                .unwrap_or(0)
        },
        0,
    )
}

/// True when `wire` is one of the USP-flavored End.* behaviors (USP =
/// Ultimate Segment Pop, RFC 8986 §4.16).
#[no_mangle]
pub extern "C" fn lr_srv6_behavior_is_usp(wire: u16) -> u8 {
    guarded(
        || {
            Behavior::from_wire(wire)
                .map(|b| b.is_usp() as u8)
                .unwrap_or(0)
        },
        0,
    )
}

/// True when `wire` is one of the USD-flavored End.* behaviors (USD =
/// Ultimate Segment Decap, RFC 8986 §4.16).
#[no_mangle]
pub extern "C" fn lr_srv6_behavior_is_usd(wire: u16) -> u8 {
    guarded(
        || {
            Behavior::from_wire(wire)
                .map(|b| b.is_usd() as u8)
                .unwrap_or(0)
        },
        0,
    )
}

/// True when `wire` is a decap behavior (End.D*, RFC 8986 §4.5-§4.13).
#[no_mangle]
pub extern "C" fn lr_srv6_behavior_is_decap(wire: u16) -> u8 {
    guarded(
        || {
            Behavior::from_wire(wire)
                .map(|b| b.is_decap() as u8)
                .unwrap_or(0)
        },
        0,
    )
}

/// True when `wire` is a cross-connect behavior (End.X*, RFC 8986 §4.2).
#[no_mangle]
pub extern "C" fn lr_srv6_behavior_is_cross_connect(wire: u16) -> u8 {
    guarded(
        || {
            Behavior::from_wire(wire)
                .map(|b| b.is_cross_connect() as u8)
                .unwrap_or(0)
        },
        0,
    )
}

/// True when `wire` is a table-lookup behavior (End.DT*, RFC 8986
/// §4.7-§4.9).
#[no_mangle]
pub extern "C" fn lr_srv6_behavior_is_table_lookup(wire: u16) -> u8 {
    guarded(
        || {
            Behavior::from_wire(wire)
                .map(|b| b.is_table_lookup() as u8)
                .unwrap_or(0)
        },
        0,
    )
}

/// Write the behavior's mnemonic name (e.g. `"End"`, `"End.DX6"`) into
/// the caller-supplied buffer. Returns the number of bytes written
/// (excluding the NUL terminator), or 0 if `wire` is unknown or
/// `out_name` is NULL.
///
/// # Safety
/// `out_name` must point to at least `name_cap` writable bytes.
#[no_mangle]
pub unsafe extern "C" fn lr_srv6_behavior_name(
    wire: u16,
    out_name: *mut std::os::raw::c_char,
    name_cap: usize,
) -> usize {
    guarded(
        || unsafe {
            let Some(b) = Behavior::from_wire(wire) else {
                return 0;
            };
            if out_name.is_null() || name_cap == 0 {
                return 0;
            }
            let name = b.name();
            let bytes = name.as_bytes();
            let take = bytes.len().min(name_cap - 1);
            unsafe {
                std::ptr::copy_nonoverlapping(
                    bytes.as_ptr(),
                    out_name as *mut u8,
                    take,
                );
                *out_name.add(take) = 0;
            }
            take
        },
        0,
    )
}

// ---- Sid (RFC 8754 §3) ----

/// Construct a `Sid` from 16 raw octets.
///
/// # Safety
/// `octets` must point to 16 readable bytes.
#[no_mangle]
pub unsafe extern "C" fn lr_srv6_sid_new(octets: *const u8) -> *mut OpaqueSrv6Sid {
    guarded(
        || unsafe {
            if octets.is_null() {
                return std::ptr::null_mut();
            }
            let mut buf = [0u8; 16];
            let src = unsafe { std::slice::from_raw_parts(octets, 16) };
            buf.copy_from_slice(src);
            Box::into_raw(Box::new(Sid::from_octets(buf))) as *mut OpaqueSrv6Sid
        },
        std::ptr::null_mut(),
    )
}

/// Opaque `Sid` handle.
#[repr(C)]
pub struct OpaqueSrv6Sid {
    _private: [u8; 0],
}

pub type lr_srv6_sid_t = *mut OpaqueSrv6Sid;

/// Write the SID's 16 octets to `out_octets`.
///
/// # Safety
/// `sid` must be a valid handle. `out_octets` must point to 16 writable
/// bytes.
#[no_mangle]
pub unsafe extern "C" fn lr_srv6_sid_octets(sid: lr_srv6_sid_t, out_octets: *mut u8) -> i32 {
    guarded(
        || unsafe {
            if sid.is_null() || out_octets.is_null() {
                return LrError::Null as i32;
            }
            let s = unsafe { &*(sid as *const Sid) };
            let octets = s.octets();
            unsafe {
                std::ptr::copy_nonoverlapping(octets.as_ptr(), out_octets, 16);
            }
            0
        },
        LR_ERR_PANIC,
    )
}

/// 1 when `sid` is the unspecified SID (`::`), 0 otherwise.
///
/// # Safety
/// `sid` must be a valid handle.
#[no_mangle]
pub unsafe extern "C" fn lr_srv6_sid_is_unspecified(sid: lr_srv6_sid_t) -> u8 {
    guarded(
        || unsafe {
            if sid.is_null() {
                return 0;
            }
            let s = unsafe { &*(sid as *const Sid) };
            s.is_unspecified() as u8
        },
        0,
    )
}

/// Drop a boxed `Sid`. Safe to call with NULL.
///
/// # Safety
/// `sid` must have been produced by [`lr_srv6_sid_new`] and must not
/// be used after this call.
#[no_mangle]
pub unsafe extern "C" fn lr_srv6_sid_free(sid: lr_srv6_sid_t) {
    guarded(
        || unsafe {
            if sid.is_null() {
                return;
            }
            let boxed: Box<Sid> = Box::from_raw(sid as *mut Sid);
            drop(boxed);
        },
        (),
    )
}

// ---- Locator (RFC 8754 §3.1) ----

/// Opaque `Locator` handle.
#[repr(C)]
pub struct OpaqueSrv6Locator {
    _private: [u8; 0],
}

pub type lr_srv6_locator_t = *mut OpaqueSrv6Locator;

/// Construct a `Locator` from a 16-byte address and a block-bit width.
/// Returns NULL when `block_bits > 128` or `addr` is NULL.
///
/// # Safety
/// `addr` must point to 16 readable bytes.
#[no_mangle]
pub unsafe extern "C" fn lr_srv6_locator_new(addr: *const u8, block_bits: u8) -> lr_srv6_locator_t {
    guarded(
        || unsafe {
            if addr.is_null() {
                return std::ptr::null_mut();
            }
            let mut buf = [0u8; 16];
            let src = unsafe { std::slice::from_raw_parts(addr, 16) };
            buf.copy_from_slice(src);
            match Locator::new(buf, block_bits) {
                Some(l) => Box::into_raw(Box::new(l)) as lr_srv6_locator_t,
                None => std::ptr::null_mut(),
            }
        },
        std::ptr::null_mut(),
    )
}

/// Drop a boxed `Locator`. Safe to call with NULL.
///
/// # Safety
/// `loc` must have been produced by [`lr_srv6_locator_new`] and must
/// not be used after this call.
#[no_mangle]
pub unsafe extern "C" fn lr_srv6_locator_free(loc: lr_srv6_locator_t) {
    guarded(
        || unsafe {
            if loc.is_null() {
                return;
            }
            let boxed: Box<Locator> = Box::from_raw(loc as *mut Locator);
            drop(boxed);
        },
        (),
    )
}

/// Write the locator's 16-byte address to `out_addr`.
///
/// # Safety
/// `loc` must be a valid handle. `out_addr` must point to 16 writable
/// bytes.
#[no_mangle]
pub unsafe extern "C" fn lr_srv6_locator_addr(loc: lr_srv6_locator_t, out_addr: *mut u8) -> i32 {
    guarded(
        || unsafe {
            if loc.is_null() || out_addr.is_null() {
                return LrError::Null as i32;
            }
            let l = unsafe { &*(loc as *const Locator) };
            let addr = l.addr();
            unsafe {
                std::ptr::copy_nonoverlapping(addr.as_ptr(), out_addr, 16);
            }
            0
        },
        LR_ERR_PANIC,
    )
}

/// Read the locator's block-bit width.
///
/// # Safety
/// `loc` must be a valid handle.
#[no_mangle]
pub unsafe extern "C" fn lr_srv6_locator_block_bits(loc: lr_srv6_locator_t) -> u8 {
    guarded(
        || unsafe {
            if loc.is_null() {
                return 0;
            }
            let l = unsafe { &*(loc as *const Locator) };
            l.block_bits()
        },
        0,
    )
}

/// 1 when `sid` falls inside this locator, 0 otherwise. Returns 0 on a
/// NULL handle.
///
/// # Safety
/// `loc` and `sid` must be valid handles.
#[no_mangle]
pub unsafe extern "C" fn lr_srv6_locator_contains_sid(
    loc: lr_srv6_locator_t,
    sid: lr_srv6_sid_t,
) -> u8 {
    guarded(
        || unsafe {
            if loc.is_null() || sid.is_null() {
                return 0;
            }
            let l = unsafe { &*(loc as *const Locator) };
            let s = unsafe { &*(sid as *const Sid) };
            l.contains_sid(*s) as u8
        },
        0,
    )
}

/// Build a SID by combining this locator's prefix with a 16-byte tail.
/// Returns NULL on a NULL locator or when the tail address is NULL.
///
/// # Safety
/// `loc` must be a valid handle. `tail` must point to 16 readable bytes.
#[no_mangle]
pub unsafe extern "C" fn lr_srv6_locator_sid_with_tail(
    loc: lr_srv6_locator_t,
    tail: *const u8,
) -> lr_srv6_sid_t {
    guarded(
        || unsafe {
            if loc.is_null() || tail.is_null() {
                return std::ptr::null_mut();
            }
            let l = unsafe { &*(loc as *const Locator) };
            let mut buf = [0u8; 16];
            let src = unsafe { std::slice::from_raw_parts(tail, 16) };
            buf.copy_from_slice(src);
            let sid = l.sid_with_tail(buf);
            Box::into_raw(Box::new(sid)) as lr_srv6_sid_t
        },
        std::ptr::null_mut(),
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

    // ---- Behavior / Sid / Locator type-level tests ----

    #[test]
    fn ffi_behavior_from_wire_returns_known() {
        let mut v: u16 = 0;
        let mut name = [0u8; 64];
        let rc = unsafe {
            lr_srv6_behavior_from_wire(
                1, // End
                &raw mut v,
                name.as_mut_ptr() as *mut std::os::raw::c_char,
                name.len(),
            )
        };
        assert_eq!(rc, 1);
        assert_eq!(v, 1);
        let nul = name.iter().position(|&b| b == 0).unwrap();
        assert_eq!(&name[..nul], b"End");
    }

    #[test]
    fn ffi_behavior_from_wire_returns_zero_for_unknown() {
        let rc =
            unsafe { lr_srv6_behavior_from_wire(0, std::ptr::null_mut(), std::ptr::null_mut(), 0) };
        assert_eq!(rc, 0);
    }

    #[test]
    fn ffi_behavior_is_psp() {
        assert_eq!(lr_srv6_behavior_is_psp(2), 1); // EndPsp
        assert_eq!(lr_srv6_behavior_is_psp(1), 0); // End (no PSP)
    }

    #[test]
    fn ffi_behavior_is_decap() {
        // End.DX6 = 16, End.DX4 = 17, End.DT6 = 18.
        assert_eq!(lr_srv6_behavior_is_decap(16), 1);
        assert_eq!(lr_srv6_behavior_is_decap(17), 1);
        assert_eq!(lr_srv6_behavior_is_decap(18), 1);
        assert_eq!(lr_srv6_behavior_is_decap(1), 0); // End
    }

    #[test]
    fn ffi_behavior_is_cross_connect() {
        // End.X = 5, End.X with PSP = 6.
        assert_eq!(lr_srv6_behavior_is_cross_connect(5), 1);
        assert_eq!(lr_srv6_behavior_is_cross_connect(6), 1);
        assert_eq!(lr_srv6_behavior_is_cross_connect(1), 0);
    }

    #[test]
    fn ffi_behavior_name_writes_buffer() {
        let mut name = [0u8; 32];
        let n = unsafe {
            lr_srv6_behavior_name(
                16, // End.DX6
                name.as_mut_ptr() as *mut std::os::raw::c_char,
                name.len(),
            )
        };
        assert_eq!(n, 7); // "End.DX6"
        assert_eq!(&name[..n], b"End.DX6");
    }

    #[test]
    fn ffi_sid_roundtrip() {
        let octets: [u8; 16] = [0xfc, 0xbb, 0xbb, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let sid = unsafe { lr_srv6_sid_new(octets.as_ptr()) };
        assert!(!sid.is_null());
        let mut out = [0u8; 16];
        unsafe {
            assert_eq!(lr_srv6_sid_octets(sid, out.as_mut_ptr()), 0);
            assert_eq!(out, octets);
            assert_eq!(lr_srv6_sid_is_unspecified(sid), 0);
            lr_srv6_sid_free(sid);
        }
    }

    #[test]
    fn ffi_sid_is_unspecified_for_zero() {
        let octets: [u8; 16] = [0; 16];
        let sid = unsafe { lr_srv6_sid_new(octets.as_ptr()) };
        unsafe {
            assert_eq!(lr_srv6_sid_is_unspecified(sid), 1);
            lr_srv6_sid_free(sid);
        }
    }

    #[test]
    fn ffi_sid_new_returns_null_on_null() {
        let sid = unsafe { lr_srv6_sid_new(core::ptr::null()) };
        assert!(sid.is_null());
    }

    #[test]
    fn ffi_locator_roundtrip() {
        let addr: [u8; 16] = [0xfc, 0xbb, 0xbb, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let loc = unsafe { lr_srv6_locator_new(addr.as_ptr(), 32) };
        assert!(!loc.is_null());
        let mut out = [0u8; 16];
        unsafe {
            assert_eq!(lr_srv6_locator_addr(loc, out.as_mut_ptr()), 0);
            assert_eq!(out, addr);
            assert_eq!(lr_srv6_locator_block_bits(loc), 32);
            lr_srv6_locator_free(loc);
        }
    }

    #[test]
    fn ffi_locator_rejects_oversize_block_bits() {
        let addr: [u8; 16] = [0; 16];
        let loc = unsafe { lr_srv6_locator_new(addr.as_ptr(), 200) };
        assert!(loc.is_null());
    }

    #[test]
    fn ffi_locator_contains_sid() {
        // Locator fcbb:bb00::/32 should contain fcbb:bb00::1.
        let loc_addr: [u8; 16] = [0xfc, 0xbb, 0xbb, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let sid_octets: [u8; 16] = [0xfc, 0xbb, 0xbb, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let loc = unsafe { lr_srv6_locator_new(loc_addr.as_ptr(), 32) };
        let sid = unsafe { lr_srv6_sid_new(sid_octets.as_ptr()) };
        unsafe {
            assert_eq!(lr_srv6_locator_contains_sid(loc, sid), 1);
            lr_srv6_locator_free(loc);
            lr_srv6_sid_free(sid);
        }
    }

    #[test]
    fn ffi_locator_sid_with_tail() {
        let loc_addr: [u8; 16] = [0xfc, 0xbb, 0xbb, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let tail: [u8; 16] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let loc = unsafe { lr_srv6_locator_new(loc_addr.as_ptr(), 32) };
        let sid = unsafe { lr_srv6_locator_sid_with_tail(loc, tail.as_ptr()) };
        assert!(!sid.is_null());
        let mut out = [0u8; 16];
        unsafe {
            assert_eq!(lr_srv6_sid_octets(sid, out.as_mut_ptr()), 0);
            // First 4 bytes are the locator prefix; last byte is the tail's last byte.
            assert_eq!(&out[..4], &loc_addr[..4]);
            assert_eq!(out[15], 1);
            lr_srv6_sid_free(sid);
            lr_srv6_locator_free(loc);
        }
    }

    #[test]
    fn ffi_sid_free_handles_null() {
        unsafe { lr_srv6_sid_free(std::ptr::null_mut()) };
    }

    #[test]
    fn ffi_locator_free_handles_null() {
        unsafe { lr_srv6_locator_free(std::ptr::null_mut()) };
    }
}
