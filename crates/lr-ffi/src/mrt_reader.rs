//! MRT reader FFI — `lr_mrt_reader_*` exposes the streaming
//! `lr_mrt::MrtReader` (RFC 6396 §3) so an embedder can feed
//! arbitrary chunks to the decoder and drain one record at a time.

#![allow(unused_unsafe)]

use lr_mrt::MrtReader;

use crate::error::{set_last_error, LrError, LR_ERR_PANIC};
use crate::guarded;
use crate::mrt::{box_record, lr_mrt_record_t};

const LR_ERR_NULL: i32 = LrError::Null as i32;
const LR_ERR_CODEC: i32 = LrError::Codec as i32;

#[repr(C)]
pub struct OpaqueMrtReader {
    _private: [u8; 0],
}

pub type lr_mrt_reader_t = *mut OpaqueMrtReader;

fn box_reader(r: MrtReader) -> lr_mrt_reader_t {
    Box::into_raw(Box::new(r)) as lr_mrt_reader_t
}

unsafe fn borrow_reader_mut(r: lr_mrt_reader_t) -> Option<&'static mut MrtReader> {
    if r.is_null() {
        return None;
    }
    Some(unsafe { &mut *(r as *mut MrtReader) })
}

#[no_mangle]
pub extern "C" fn lr_mrt_reader_new() -> lr_mrt_reader_t {
    guarded(|| box_reader(MrtReader::new()), std::ptr::null_mut())
}

#[no_mangle]
pub unsafe extern "C" fn lr_mrt_reader_decode_slice(
    r: lr_mrt_reader_t,
    data: *const u8,
    len: usize,
    out: *mut lr_mrt_record_t,
) -> i32 {
    guarded(
        || unsafe {
            let Some(reader) = borrow_reader_mut(r) else {
                return LR_ERR_NULL;
            };
            if data.is_null() || out.is_null() {
                return LR_ERR_NULL;
            }
            let slice = unsafe { std::slice::from_raw_parts(data, len) };
            match reader.decode_slice(slice) {
                Ok(Some(rec)) => {
                    unsafe { *out = box_record(rec) }
                    0
                }
                Ok(None) => 1,
                Err(e) => {
                    set_last_error(format!("{e:?}"));
                    LR_ERR_CODEC
                }
            }
        },
        LR_ERR_PANIC,
    )
}

/// Buffer raw chunk bytes without decoding anything. The records
/// stay buffered; `lr_mrt_reader_decode_slice` and
/// `lr_mrt_reader_next_record` pop them one at a time. Feeding a
/// chunk that holds exactly one complete record keeps that record
/// buffered — nothing is decoded or discarded here. Returns 0, or
/// `LR_ERR_NULL` on a NULL handle / null data pointer.
///
/// # Safety
/// `r` must be a valid reader handle; `data` must point to `len`
/// readable bytes.
#[no_mangle]
pub unsafe extern "C" fn lr_mrt_reader_feed(
    r: lr_mrt_reader_t,
    data: *const u8,
    len: usize,
) -> i32 {
    guarded(
        || unsafe {
            let Some(reader) = borrow_reader_mut(r) else {
                return LR_ERR_NULL;
            };
            if data.is_null() {
                return LR_ERR_NULL;
            }
            let slice = unsafe { std::slice::from_raw_parts(data, len) };
            reader.feed(slice);
            0
        },
        LR_ERR_PANIC,
    )
}

#[no_mangle]
pub unsafe extern "C" fn lr_mrt_reader_next_record(
    r: lr_mrt_reader_t,
    out: *mut lr_mrt_record_t,
) -> i32 {
    guarded(
        || unsafe {
            let Some(reader) = borrow_reader_mut(r) else {
                return LR_ERR_NULL;
            };
            if out.is_null() {
                return LR_ERR_NULL;
            }
            match reader.next_record() {
                Ok(Some(rec)) => {
                    unsafe { *out = box_record(rec) }
                    0
                }
                Ok(None) => 1,
                Err(e) => {
                    set_last_error(format!("{e:?}"));
                    LR_ERR_CODEC
                }
            }
        },
        LR_ERR_PANIC,
    )
}

#[no_mangle]
pub unsafe extern "C" fn lr_mrt_reader_free(r: lr_mrt_reader_t) {
    guarded(
        || unsafe {
            if r.is_null() {
                return;
            }
            drop(Box::from_raw(r as *mut MrtReader));
        },
        (),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ffi_reader_new_default() {
        let r = lr_mrt_reader_new();
        assert!(!r.is_null());
        unsafe { lr_mrt_reader_free(r) };
    }

    #[test]
    fn ffi_reader_free_null_safe() {
        unsafe { lr_mrt_reader_free(std::ptr::null_mut()) };
    }

    #[test]
    fn ffi_reader_decode_truncated_returns_one() {
        let bytes = [0u8; 5];
        let r = lr_mrt_reader_new();
        let mut out: lr_mrt_record_t = std::ptr::null_mut();
        let rc = unsafe { lr_mrt_reader_decode_slice(r, bytes.as_ptr(), bytes.len(), &mut out) };
        assert_eq!(rc, 1);
        assert!(out.is_null());
        unsafe { lr_mrt_reader_free(r) };
    }

    #[test]
    fn ffi_reader_decode_null_returns_err() {
        let bytes = [0u8; 12];
        let r = lr_mrt_reader_new();
        let mut out: lr_mrt_record_t = std::ptr::null_mut();
        assert_eq!(
            unsafe {
                lr_mrt_reader_decode_slice(
                    std::ptr::null_mut(),
                    bytes.as_ptr(),
                    bytes.len(),
                    &mut out,
                )
            },
            LR_ERR_NULL
        );
        assert_eq!(
            unsafe { lr_mrt_reader_decode_slice(r, std::ptr::null(), 0, &mut out) },
            LR_ERR_NULL
        );
        assert_eq!(
            unsafe {
                lr_mrt_reader_decode_slice(r, bytes.as_ptr(), bytes.len(), std::ptr::null_mut())
            },
            LR_ERR_NULL
        );
        unsafe { lr_mrt_reader_free(r) };
    }

    #[test]
    fn ffi_reader_next_record_null_returns_err() {
        let r = lr_mrt_reader_new();
        let rc = unsafe { lr_mrt_reader_next_record(r, std::ptr::null_mut()) };
        assert_eq!(rc, LR_ERR_NULL);
        unsafe { lr_mrt_reader_free(r) };
    }

    #[test]
    fn ffi_reader_feed_null_returns_err() {
        let r = lr_mrt_reader_new();
        let bytes = [0u8; 4];
        assert_eq!(
            unsafe { lr_mrt_reader_feed(std::ptr::null_mut(), bytes.as_ptr(), bytes.len()) },
            LR_ERR_NULL
        );
        assert_eq!(
            unsafe { lr_mrt_reader_feed(r, std::ptr::null(), 0) },
            LR_ERR_NULL
        );
        unsafe { lr_mrt_reader_free(r) };
    }

    /// `feed` buffers; `next_record` pops. A chunk holding exactly
    /// one complete record must survive the feed and come back out
    /// of the drain — the previous implementation ran the
    /// feed+decode pair and discarded the decoded record, silently
    /// losing every chunk's first record.
    #[test]
    fn ffi_reader_feed_then_next_record_round_trips() {
        // One TABLE_DUMP record: header (ts, type, subtype, len) + 4
        // body bytes. TABLE_DUMP decodes to `MrtRecord::Unknown`
        // regardless of the body, so the shape is guaranteed to pop
        // out as a record.
        let mut record = Vec::new();
        record.extend_from_slice(&0u32.to_be_bytes()); // timestamp
        record.extend_from_slice(&12u16.to_be_bytes()); // TABLE_DUMP
        record.extend_from_slice(&0u16.to_be_bytes()); // subtype
        record.extend_from_slice(&4u32.to_be_bytes()); // body length
        record.extend_from_slice(&[0xde, 0xad, 0xbe, 0xef]);

        let r = lr_mrt_reader_new();
        assert_eq!(
            unsafe { lr_mrt_reader_feed(r, record.as_ptr(), record.len()) },
            0
        );

        let mut out: lr_mrt_record_t = std::ptr::null_mut();
        let rc = unsafe { lr_mrt_reader_next_record(r, &mut out) };
        assert_eq!(rc, 0, "the fed record is buffered and pops back out");
        assert!(!out.is_null(), "a record handle came back");

        // Nothing else is buffered.
        let mut out2: lr_mrt_record_t = std::ptr::null_mut();
        assert_eq!(unsafe { lr_mrt_reader_next_record(r, &mut out2) }, 1);
        assert!(out2.is_null());
        unsafe { crate::mrt::lr_mrt_record_free(out) };
        unsafe { lr_mrt_reader_free(r) };
    }
}
