//! lr-srv6 gap-closure FFI — `Srh` opaque handle + builder methods +
//! `Sid` / `Locator` FromStr / Display.
//!
//! Issue #92 — gap closure: the SRH FFI exposed only the flat-bytes
//! `lr_srv6_encode_srh` / `_decode_srh` codec pair. The structured
//! `Srh` struct (with builder methods for `next_header`, `flags`,
//! `tag`, `tlvs`, `segments_left`) was unreachable from C — a C
//! embedder could encode a basic SRH but could not set any of the
//! header fields beyond the segment list. This batch reifies the
//! SRH as an opaque handle so the full builder surface is available.
//!
//! Also adds the missing `Sid::from_str` / `to_str` and
//! `Locator::from_str` / `to_str` helpers (RFC 4291 textual form)
//! that were uniformly absent from the C ABI per the gap analysis.

#![allow(unused_unsafe)]
#![allow(dead_code)]

use lr_srv6::{Locator, Sid, Srh};
use std::ffi::{CStr, CString};

use crate::error::{set_last_error, LrError, LR_ERR_PANIC};
use crate::guarded;
use crate::handle::lr_bytes_t;

const LR_ERR_NULL: i32 = LrError::Null as i32;

// ---- opaque handles ----

#[repr(C)]
pub struct OpaqueSrv6Srh {
    _private: [u8; 0],
}
pub type lr_srv6_srh_t = *mut OpaqueSrv6Srh;

fn box_srh(s: Srh) -> lr_srv6_srh_t {
    Box::into_raw(Box::new(s)) as lr_srv6_srh_t
}

unsafe fn unbox_srh(s: lr_srv6_srh_t) -> Option<Box<Srh>> {
    if s.is_null() {
        return None;
    }
    Some(unsafe { Box::from_raw(s as *mut Srh) })
}

unsafe fn borrow_srh(s: lr_srv6_srh_t) -> Option<&'static Srh> {
    if s.is_null() {
        return None;
    }
    Some(unsafe { &*(s as *const Srh) })
}
pub(crate) unsafe fn borrow_srh_pub(s: lr_srv6_srh_t) -> Option<&'static Srh> {
    if s.is_null() {
        return None;
    }
    Some(unsafe { &*(s as *const Srh) })
}

unsafe fn borrow_srh_mut(s: lr_srv6_srh_t) -> Option<&'static mut Srh> {
    if s.is_null() {
        return None;
    }
    Some(unsafe { &mut *(s as *mut Srh) })
}

// =========================================================================
// Srh opaque handle (RFC 8754 §2 — IPv6 Segment Routing Header)
// =========================================================================

/// Construct an SRH from a flat array of SID bytes. Each SID is 16
/// bytes; `data` must be `count * 16` bytes long. `segments_left`
/// defaults to `count - 1` (RFC 8754 §4.2 — the sender's view).
///
/// Returns NULL on a panic or on an SRH construction error (empty
/// segment list, too many segments, segments_left out of range).
///
/// # Safety
/// `data` must point to `count * 16` readable bytes.
#[no_mangle]
pub unsafe extern "C" fn lr_srv6_srh_new(data: *const u8, count: usize) -> lr_srv6_srh_t {
    guarded(
        || unsafe {
            if data.is_null() || count == 0 {
                set_last_error("SRH segment list is empty".into());
                return std::ptr::null_mut();
            }
            let slice = unsafe { std::slice::from_raw_parts(data, count * 16) };
            let mut sids = Vec::with_capacity(count);
            for chunk in slice.as_chunks::<16>().0 {
                sids.push(Sid::from_octets(*chunk));
            }
            match Srh::new(sids) {
                Ok(srh) => box_srh(srh),
                Err(e) => {
                    set_last_error(e.to_string());
                    std::ptr::null_mut()
                }
            }
        },
        std::ptr::null_mut(),
    )
}

/// Construct an SRH with an explicit `segments_left` (RFC 8754 §4.2).
/// `segments_left_present = 0` defaults to `count - 1`.
///
/// # Safety
/// See [`lr_srv6_srh_new`].
#[no_mangle]
pub unsafe extern "C" fn lr_srv6_srh_new_with_segments_left(
    data: *const u8,
    count: usize,
    segments_left: u8,
    segments_left_present: u8,
) -> lr_srv6_srh_t {
    guarded(
        || unsafe {
            if data.is_null() || count == 0 {
                set_last_error("SRH segment list is empty".into());
                return std::ptr::null_mut();
            }
            let slice = unsafe { std::slice::from_raw_parts(data, count * 16) };
            let mut sids = Vec::with_capacity(count);
            for chunk in slice.as_chunks::<16>().0 {
                sids.push(Sid::from_octets(*chunk));
            }
            let opt = if segments_left_present != 0 {
                Some(segments_left)
            } else {
                None
            };
            match Srh::with_segments_left(sids, opt) {
                Ok(srh) => box_srh(srh),
                Err(e) => {
                    set_last_error(e.to_string());
                    std::ptr::null_mut()
                }
            }
        },
        std::ptr::null_mut(),
    )
}

/// Set the Next Header field (RFC 8200 §2). Builder-style — returns
/// 0 on success. The handle is modified in place.
///
/// # Safety
/// `srh` must be a valid handle.
#[no_mangle]
pub unsafe extern "C" fn lr_srv6_srh_set_next_header(srh: lr_srv6_srh_t, next_header: u8) -> i32 {
    guarded(
        || unsafe {
            let Some(s) = borrow_srh_mut(srh) else {
                return LR_ERR_NULL;
            };
            // with_next_header consumes self; emulate in-place mutation
            // by taking the field out and putting it back.
            s.next_header = next_header;
            0
        },
        LR_ERR_PANIC,
    )
}

/// Set the SRH flags byte (RFC 8754 §2.1 — currently only OAM/HMAC
/// bits are defined).
///
/// # Safety
/// `srh` must be a valid handle.
#[no_mangle]
pub unsafe extern "C" fn lr_srv6_srh_set_flags(srh: lr_srv6_srh_t, flags: u8) -> i32 {
    guarded(
        || unsafe {
            let Some(s) = borrow_srh_mut(srh) else {
                return LR_ERR_NULL;
            };
            s.flags = flags;
            0
        },
        LR_ERR_PANIC,
    )
}

/// Set the SRH tag field (RFC 8754 §2.4 — opaque to the data plane).
///
/// # Safety
/// `srh` must be a valid handle.
#[no_mangle]
pub unsafe extern "C" fn lr_srv6_srh_set_tag(srh: lr_srv6_srh_t, tag: u16) -> i32 {
    guarded(
        || unsafe {
            let Some(s) = borrow_srh_mut(srh) else {
                return LR_ERR_NULL;
            };
            s.tag = tag;
            0
        },
        LR_ERR_PANIC,
    )
}

/// Set the SRH TLVs (RFC 8754 §2.5 — variable-length TLV bytes
/// appended after the segment list).
///
/// # Safety
/// `srh` must be a valid handle. `tlvs` must point to `tlvs_len`
/// readable bytes (NULL with `tlvs_len == 0` clears the TLVs).
#[no_mangle]
pub unsafe extern "C" fn lr_srv6_srh_set_tlvs(
    srh: lr_srv6_srh_t,
    tlvs: *const u8,
    tlvs_len: usize,
) -> i32 {
    guarded(
        || unsafe {
            let Some(s) = borrow_srh_mut(srh) else {
                return LR_ERR_NULL;
            };
            if tlvs.is_null() || tlvs_len == 0 {
                s.tlvs = Vec::new();
            } else {
                s.tlvs = unsafe { std::slice::from_raw_parts(tlvs, tlvs_len).to_vec() };
            }
            0
        },
        LR_ERR_PANIC,
    )
}

/// Read the Next Header field. Returns 0 on a NULL handle.
#[no_mangle]
pub unsafe extern "C" fn lr_srv6_srh_next_header(srh: lr_srv6_srh_t) -> u8 {
    guarded(
        || unsafe { borrow_srh(srh).map(|s| s.next_header).unwrap_or(0) },
        0,
    )
}

/// Read the segments_left field (RFC 8754 §2.3 — index of the
/// current destination in the segment list). Returns 0 on a NULL
/// handle.
#[no_mangle]
pub unsafe extern "C" fn lr_srv6_srh_segments_left(srh: lr_srv6_srh_t) -> u8 {
    guarded(
        || unsafe { borrow_srh(srh).map(|s| s.segments_left).unwrap_or(0) },
        0,
    )
}

/// Read the last_entry field (RFC 8754 §2.3 — index of the last
/// segment in the list). Returns 0 on a NULL handle.
#[no_mangle]
pub unsafe extern "C" fn lr_srv6_srh_last_entry(srh: lr_srv6_srh_t) -> u8 {
    guarded(
        || unsafe { borrow_srh(srh).map(|s| s.last_entry).unwrap_or(0) },
        0,
    )
}

/// Read the flags byte. Returns 0 on a NULL handle.
#[no_mangle]
pub unsafe extern "C" fn lr_srv6_srh_flags(srh: lr_srv6_srh_t) -> u8 {
    guarded(
        || unsafe { borrow_srh(srh).map(|s| s.flags).unwrap_or(0) },
        0,
    )
}

/// Read the tag field. Returns 0 on a NULL handle.
#[no_mangle]
pub unsafe extern "C" fn lr_srv6_srh_tag(srh: lr_srv6_srh_t) -> u16 {
    guarded(|| unsafe { borrow_srh(srh).map(|s| s.tag).unwrap_or(0) }, 0)
}

/// Read the segment count. Returns 0 on a NULL handle.
#[no_mangle]
pub unsafe extern "C" fn lr_srv6_srh_segment_count(srh: lr_srv6_srh_t) -> usize {
    guarded(
        || unsafe { borrow_srh(srh).map(|s| s.segments.len()).unwrap_or(0) },
        0,
    )
}

/// Read one segment by index into `*out` (16 bytes). Returns 0 on
/// success, `LR_ERR_NULL` (-1) on a NULL handle or NULL `out`,
/// `LR_ERR_INVALID_HANDLE` (-2) when the index is out of range.
///
/// # Safety
/// `srh` must be a valid handle. `out` must point to 16 writable bytes.
#[no_mangle]
pub unsafe extern "C" fn lr_srv6_srh_segment_at(
    srh: lr_srv6_srh_t,
    index: usize,
    out: *mut u8,
) -> i32 {
    guarded(
        || unsafe {
            if out.is_null() {
                return LR_ERR_NULL;
            }
            let Some(s) = borrow_srh(srh) else {
                return LR_ERR_NULL;
            };
            let Some(sid) = s.segments.get(index) else {
                return LrError::InvalidHandle as i32;
            };
            unsafe { std::ptr::copy_nonoverlapping(sid.as_bytes().as_ptr(), out, 16) };
            0
        },
        LR_ERR_PANIC,
    )
}

/// Read the TLV bytes into a freshly-allocated `lr_bytes_t`. The
/// caller owns the bytes and must free them via `lr_bytes_free`.
///
/// # Safety
/// `srh` must be a valid handle. `out` must point to a writable
/// `lr_bytes_t`.
#[no_mangle]
pub unsafe extern "C" fn lr_srv6_srh_tlvs(srh: lr_srv6_srh_t, out: *mut lr_bytes_t) -> i32 {
    guarded(
        || unsafe {
            let Some(s) = borrow_srh(srh) else {
                return LR_ERR_NULL;
            };
            if out.is_null() {
                return LR_ERR_NULL;
            }
            unsafe { *out = lr_bytes_t::from_vec(s.tlvs.clone()) }
            0
        },
        LR_ERR_PANIC,
    )
}

/// Read the first segment (the destination address at the sender per
/// RFC 8754 §4.2) into `*out` (16 bytes). Returns 0 on success,
/// `LR_ERR_NULL` on a NULL handle or NULL `out`, `LR_ERR_INVALID_HANDLE`
/// when the SRH has no segments.
///
/// # Safety
/// `srh` must be a valid handle. `out` must point to 16 writable bytes.
#[no_mangle]
pub unsafe extern "C" fn lr_srv6_srh_first_segment(srh: lr_srv6_srh_t, out: *mut u8) -> i32 {
    guarded(
        || unsafe {
            if out.is_null() {
                return LR_ERR_NULL;
            }
            let Some(s) = borrow_srh(srh) else {
                return LR_ERR_NULL;
            };
            let Some(sid) = s.first_segment() else {
                return LrError::InvalidHandle as i32;
            };
            unsafe { std::ptr::copy_nonoverlapping(sid.as_bytes().as_ptr(), out, 16) };
            0
        },
        LR_ERR_PANIC,
    )
}

/// Encode the SRH into a freshly-allocated `lr_bytes_t` (RFC 8754
/// §2 wire form — 8-octet fixed header + segment list + TLVs). The
/// caller owns the bytes and must free them via `lr_bytes_free`.
///
/// # Safety
/// `srh` must be a valid handle. `out` must point to a writable
/// `lr_bytes_t`.
#[no_mangle]
pub unsafe extern "C" fn lr_srv6_srh_encode(srh: lr_srv6_srh_t, out: *mut lr_bytes_t) -> i32 {
    guarded(
        || unsafe {
            let Some(s) = borrow_srh(srh) else {
                return LR_ERR_NULL;
            };
            if out.is_null() {
                return LR_ERR_NULL;
            }
            match s.encode_vec() {
                Ok(bytes) => {
                    unsafe { *out = lr_bytes_t::from_vec(bytes) }
                    0
                }
                Err(e) => {
                    set_last_error(e.to_string());
                    LrError::Codec as i32
                }
            }
        },
        LR_ERR_PANIC,
    )
}

/// Drop an SRH handle. Safe to call with NULL.
///
/// # Safety
/// `srh` must have been produced by `lr_srv6_srh_new` and not already
/// freed.
#[no_mangle]
pub unsafe extern "C" fn lr_srv6_srh_free(srh: lr_srv6_srh_t) {
    guarded(
        || unsafe {
            drop(unbox_srh(srh));
        },
        (),
    )
}

// =========================================================================
// Sid / Locator FromStr + Display (RFC 4291 textual form)
// =========================================================================

/// Parse a NUL-terminated IPv6 address string (RFC 4291 §2.2 textual
/// form) into a `Sid` (16-byte octet array). Returns 0 on success
/// and writes the 16 bytes to `out`; returns `LR_ERR_NULL` on a
/// NULL pointer; returns `LR_ERR_BAD_UTF8` (-3) on a parse error.
///
/// # Safety
/// `s` must point to a NUL-terminated UTF-8 string. `out` must point
/// to 16 writable bytes.
#[no_mangle]
pub unsafe extern "C" fn lr_srv6_sid_from_str(s: *const std::os::raw::c_char, out: *mut u8) -> i32 {
    guarded(
        || unsafe {
            if s.is_null() || out.is_null() {
                return LR_ERR_NULL;
            }
            let cstr = unsafe { CStr::from_ptr(s) };
            let Ok(text) = cstr.to_str() else {
                return LrError::BadUtf8 as i32;
            };
            let Ok(sid) = Sid::from_str(text) else {
                set_last_error(format!("invalid SID string: {text}"));
                return LrError::BadUtf8 as i32;
            };
            let octets = sid.octets();
            unsafe { std::ptr::copy_nonoverlapping(octets.as_ptr(), out, 16) };
            0
        },
        LR_ERR_PANIC,
    )
}

/// Format a `Sid` (16 raw bytes) as an IPv6 address string. Returns
/// a pointer to a thread-local NUL-terminated buffer (valid until
/// the next call to `lr_srv6_sid_to_str` / `lr_srv6_locator_to_str`
/// on this thread). Returns NULL on a NULL `sid` pointer.
///
/// # Safety
/// `sid` must point to 16 readable bytes.
#[no_mangle]
pub unsafe extern "C" fn lr_srv6_sid_to_str(sid: *const u8) -> *const std::os::raw::c_char {
    guarded(
        || unsafe {
            if sid.is_null() {
                return std::ptr::null();
            }
            let mut octets = [0u8; 16];
            octets.copy_from_slice(unsafe { std::slice::from_raw_parts(sid, 16) });
            let sid_obj = Sid::from_octets(octets);
            let s = format!("{sid_obj}");
            let cstr = CString::new(s).unwrap_or_default();
            // Leak into a thread-local so the pointer stays valid
            // until the next call.
            thread_local! {
                static BUF: std::cell::RefCell<Option<CString>> = const { std::cell::RefCell::new(None) };
            }
            BUF.with(|b| {
                let mut slot = b.borrow_mut();
                *slot = Some(cstr);
                slot.as_ref()
                    .map(|c| c.as_ptr())
                    .unwrap_or(std::ptr::null())
            })
        },
        std::ptr::null(),
    )
}

/// Parse a NUL-terminated `<addr>/<block_bits>` string (RFC 4291 +
/// RFC 8754 §3.1 textual form) into a `Locator`. Writes the 16-byte
/// address to `out_addr` and the block_bits to `*out_block_bits`.
/// Returns 0 on success, `LR_ERR_NULL` on a NULL pointer,
/// `LR_ERR_BAD_UTF8` on a parse error.
///
/// # Safety
/// `s` must point to a NUL-terminated UTF-8 string. `out_addr` must
/// point to 16 writable bytes and `out_block_bits` to a writable
/// `uint8_t`.
#[no_mangle]
pub unsafe extern "C" fn lr_srv6_locator_from_str(
    s: *const std::os::raw::c_char,
    out_addr: *mut u8,
    out_block_bits: *mut u8,
) -> i32 {
    guarded(
        || unsafe {
            if s.is_null() || out_addr.is_null() || out_block_bits.is_null() {
                return LR_ERR_NULL;
            }
            let cstr = unsafe { CStr::from_ptr(s) };
            let Ok(text) = cstr.to_str() else {
                return LrError::BadUtf8 as i32;
            };
            // Locator::FromStr expects "<addr>/<bits>" form.
            let Ok(loc) = Locator::from_str(text) else {
                set_last_error(format!("invalid locator string: {text}"));
                return LrError::BadUtf8 as i32;
            };
            let octets = loc.as_bytes();
            unsafe { std::ptr::copy_nonoverlapping(octets.as_ptr(), out_addr, 16) };
            unsafe { *out_block_bits = loc.block_bits() };
            0
        },
        LR_ERR_PANIC,
    )
}

/// Format a `Locator` (16 raw address bytes + block_bits) as an
/// `<addr>/<bits>` string. Returns a thread-local pointer (valid
/// until the next call to `lr_srv6_sid_to_str` / `lr_srv6_locator_to_str`
/// on this thread).
///
/// # Safety
/// `addr` must point to 16 readable bytes.
#[no_mangle]
pub unsafe extern "C" fn lr_srv6_locator_to_str(
    addr: *const u8,
    block_bits: u8,
) -> *const std::os::raw::c_char {
    guarded(
        || unsafe {
            if addr.is_null() {
                return std::ptr::null();
            }
            let mut octets = [0u8; 16];
            octets.copy_from_slice(unsafe { std::slice::from_raw_parts(addr, 16) });
            // The Locator::Display format is "<addr>/<bits>". Construct
            // manually since Locator::new returns Option<Self>.
            let addr_str = format!(
                "{:x}:{:x}:{:x}:{:x}:{:x}:{:x}:{:x}:{:x}",
                u16::from_be_bytes([octets[0], octets[1]]),
                u16::from_be_bytes([octets[2], octets[3]]),
                u16::from_be_bytes([octets[4], octets[5]]),
                u16::from_be_bytes([octets[6], octets[7]]),
                u16::from_be_bytes([octets[8], octets[9]]),
                u16::from_be_bytes([octets[10], octets[11]]),
                u16::from_be_bytes([octets[12], octets[13]]),
                u16::from_be_bytes([octets[14], octets[15]]),
            );
            let s = format!("{addr_str}/{block_bits}");
            let cstr = CString::new(s).unwrap_or_default();
            thread_local! {
                static BUF: std::cell::RefCell<Option<CString>> = const { std::cell::RefCell::new(None) };
            }
            BUF.with(|b| {
                let mut slot = b.borrow_mut();
                *slot = Some(cstr);
                slot.as_ref()
                    .map(|c| c.as_ptr())
                    .unwrap_or(std::ptr::null())
            })
        },
        std::ptr::null(),
    )
}

// Need the FromStr / Display imports.
use core::str::FromStr;

#[cfg(test)]
mod tests {
    use super::*;

    fn sid_bytes(s: &str) -> [u8; 16] {
        let sid = Sid::from_str(s).unwrap();
        sid.octets()
    }

    #[test]
    fn ffi_srh_new_round_trip() {
        let sid1 = sid_bytes("fcbb:bb00::1");
        let sid2 = sid_bytes("fcbb:bb01::1");
        let mut input = Vec::new();
        input.extend_from_slice(&sid1);
        input.extend_from_slice(&sid2);
        let srh = unsafe { lr_srv6_srh_new(input.as_ptr(), 2) };
        assert!(!srh.is_null());
        assert_eq!(unsafe { lr_srv6_srh_segment_count(srh) }, 2);
        unsafe { lr_srv6_srh_free(srh) };
    }

    #[test]
    fn ffi_srh_setters_round_trip() {
        let sid = sid_bytes("fcbb:bb00::1");
        let srh = unsafe { lr_srv6_srh_new(sid.as_ptr(), 1) };
        assert_eq!(unsafe { lr_srv6_srh_set_next_header(srh, 59) }, 0);
        assert_eq!(unsafe { lr_srv6_srh_set_flags(srh, 0x01) }, 0);
        assert_eq!(unsafe { lr_srv6_srh_set_tag(srh, 0xabcd) }, 0);
        let tlvs = [0u8, 1, 2];
        assert_eq!(unsafe { lr_srv6_srh_set_tlvs(srh, tlvs.as_ptr(), 3) }, 0);

        assert_eq!(unsafe { lr_srv6_srh_next_header(srh) }, 59);
        assert_eq!(unsafe { lr_srv6_srh_flags(srh) }, 0x01);
        assert_eq!(unsafe { lr_srv6_srh_tag(srh) }, 0xabcd);

        let mut bytes = lr_bytes_t {
            ptr: std::ptr::null_mut(),
            len: 0,
            cap: 0,
        };
        let rc = unsafe { lr_srv6_srh_tlvs(srh, &raw mut bytes) };
        assert_eq!(rc, 0);
        assert_eq!(bytes.len, 3);
        unsafe {
            crate::bytes::lr_bytes_free(&raw mut bytes);
            lr_srv6_srh_free(srh);
        }
    }

    #[test]
    fn ffi_srh_segment_at_round_trip() {
        let sid1 = sid_bytes("fcbb:bb00::1");
        let sid2 = sid_bytes("fcbb:bb01::1");
        let mut input = Vec::new();
        input.extend_from_slice(&sid1);
        input.extend_from_slice(&sid2);
        let srh = unsafe { lr_srv6_srh_new(input.as_ptr(), 2) };
        let mut out = [0u8; 16];
        let rc = unsafe { lr_srv6_srh_segment_at(srh, 0, out.as_mut_ptr()) };
        assert_eq!(rc, 0);
        assert_eq!(out, sid1);
        let rc = unsafe { lr_srv6_srh_segment_at(srh, 1, out.as_mut_ptr()) };
        assert_eq!(rc, 0);
        assert_eq!(out, sid2);
        let rc = unsafe { lr_srv6_srh_segment_at(srh, 99, out.as_mut_ptr()) };
        assert_eq!(rc, LrError::InvalidHandle as i32);
        unsafe { lr_srv6_srh_free(srh) };
    }

    #[test]
    fn ffi_srh_first_segment() {
        let sid1 = sid_bytes("fcbb:bb00::1");
        let sid2 = sid_bytes("fcbb:bb01::1");
        let mut input = Vec::new();
        input.extend_from_slice(&sid1);
        input.extend_from_slice(&sid2);
        let srh = unsafe { lr_srv6_srh_new(input.as_ptr(), 2) };
        let mut out = [0u8; 16];
        let rc = unsafe { lr_srv6_srh_first_segment(srh, out.as_mut_ptr()) };
        assert_eq!(rc, 0);
        assert_eq!(out, sid1);
        unsafe { lr_srv6_srh_free(srh) };
    }

    #[test]
    fn ffi_srh_encode_round_trip() {
        let sid1 = sid_bytes("fcbb:bb00::1");
        let sid2 = sid_bytes("fcbb:bb01::1");
        let mut input = Vec::new();
        input.extend_from_slice(&sid1);
        input.extend_from_slice(&sid2);
        let srh = unsafe { lr_srv6_srh_new(input.as_ptr(), 2) };
        let mut bytes = lr_bytes_t {
            ptr: std::ptr::null_mut(),
            len: 0,
            cap: 0,
        };
        let rc = unsafe { lr_srv6_srh_encode(srh, &raw mut bytes) };
        assert_eq!(rc, 0);
        // 8 fixed + 2 * 16 segments = 40 bytes (no TLVs).
        assert_eq!(bytes.len, 40);
        unsafe {
            crate::bytes::lr_bytes_free(&raw mut bytes);
            lr_srv6_srh_free(srh);
        }
    }

    #[test]
    fn ffi_srh_new_rejects_empty() {
        let srh = unsafe { lr_srv6_srh_new(std::ptr::null(), 0) };
        assert!(srh.is_null());
    }

    #[test]
    fn ffi_srh_setters_reject_null() {
        let rc = unsafe { lr_srv6_srh_set_next_header(std::ptr::null_mut(), 59) };
        assert_eq!(rc, LR_ERR_NULL);
        let rc = unsafe { lr_srv6_srh_set_flags(std::ptr::null_mut(), 0) };
        assert_eq!(rc, LR_ERR_NULL);
        let rc = unsafe { lr_srv6_srh_set_tag(std::ptr::null_mut(), 0) };
        assert_eq!(rc, LR_ERR_NULL);
    }

    #[test]
    fn ffi_srh_free_handles_null_safely() {
        unsafe { lr_srv6_srh_free(std::ptr::null_mut()) };
    }

    #[test]
    fn ffi_sid_from_str_round_trip() {
        let cstr = std::ffi::CString::new("fcbb:bb00::1").unwrap();
        let mut out = [0u8; 16];
        let rc = unsafe { lr_srv6_sid_from_str(cstr.as_ptr(), out.as_mut_ptr()) };
        assert_eq!(rc, 0);
        assert_eq!(out, sid_bytes("fcbb:bb00::1"));
    }

    #[test]
    fn ffi_sid_from_str_rejects_null() {
        let mut out = [0u8; 16];
        let rc = unsafe { lr_srv6_sid_from_str(std::ptr::null(), out.as_mut_ptr()) };
        assert_eq!(rc, LR_ERR_NULL);
    }

    #[test]
    fn ffi_sid_from_str_rejects_bad_string() {
        let cstr = std::ffi::CString::new("not-an-ipv6-addr").unwrap();
        let mut out = [0u8; 16];
        let rc = unsafe { lr_srv6_sid_from_str(cstr.as_ptr(), out.as_mut_ptr()) };
        assert_eq!(rc, LrError::BadUtf8 as i32);
    }

    #[test]
    fn ffi_sid_to_str_round_trip() {
        let sid = sid_bytes("fcbb:bb00::1");
        let ptr = unsafe { lr_srv6_sid_to_str(sid.as_ptr()) };
        assert!(!ptr.is_null());
        let s = unsafe { CStr::from_ptr(ptr) }.to_str().unwrap();
        // The Display format may compress zero groups differently;
        // verify the address parses back to the same octets.
        let parsed = Sid::from_str(s).unwrap();
        assert_eq!(parsed.octets(), sid);
    }

    #[test]
    fn ffi_sid_to_str_rejects_null() {
        let ptr = unsafe { lr_srv6_sid_to_str(std::ptr::null()) };
        assert!(ptr.is_null());
    }

    #[test]
    fn ffi_locator_from_str_round_trip() {
        let cstr = std::ffi::CString::new("fcbb:bb00::/48").unwrap();
        let mut addr = [0u8; 16];
        let mut bits = 0u8;
        let rc =
            unsafe { lr_srv6_locator_from_str(cstr.as_ptr(), addr.as_mut_ptr(), &raw mut bits) };
        assert_eq!(rc, 0);
        assert_eq!(bits, 48);
    }

    #[test]
    fn ffi_locator_from_str_rejects_null() {
        let mut addr = [0u8; 16];
        let mut bits = 0u8;
        let rc =
            unsafe { lr_srv6_locator_from_str(std::ptr::null(), addr.as_mut_ptr(), &raw mut bits) };
        assert_eq!(rc, LR_ERR_NULL);
    }

    #[test]
    fn ffi_locator_from_str_rejects_bad_string() {
        let cstr = std::ffi::CString::new("not-a-locator").unwrap();
        let mut addr = [0u8; 16];
        let mut bits = 0u8;
        let rc =
            unsafe { lr_srv6_locator_from_str(cstr.as_ptr(), addr.as_mut_ptr(), &raw mut bits) };
        assert_eq!(rc, LrError::BadUtf8 as i32);
    }

    #[test]
    fn ffi_locator_to_str_round_trip() {
        let sid = sid_bytes("fcbb:bb00::1");
        let ptr = unsafe { lr_srv6_locator_to_str(sid.as_ptr(), 48) };
        assert!(!ptr.is_null());
        let s = unsafe { CStr::from_ptr(ptr) }.to_str().unwrap();
        assert!(s.ends_with("/48"));
    }

    #[test]
    fn ffi_locator_to_str_rejects_null() {
        let ptr = unsafe { lr_srv6_locator_to_str(std::ptr::null(), 48) };
        assert!(ptr.is_null());
    }
}
