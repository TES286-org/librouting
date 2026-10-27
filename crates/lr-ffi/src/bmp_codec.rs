//! BMP message codec FFI — `lr_bmp_codec_*` exposes the standalone
//! `lr_bmp::BmpCodec` (RFC 7854 §4) so an embedder can drive
//! encode/decode without going through the daemon.

#![allow(unused_unsafe)]

use lr_bmp::{BmpCodec, BmpMessage};

use crate::bmp::{box_message, lr_bmp_message_t};
use crate::error::{set_last_error, LrError, LR_ERR_PANIC};
use crate::guarded;
use crate::handle::lr_bytes_t;

const LR_ERR_NULL: i32 = LrError::Null as i32;
const LR_ERR_CODEC: i32 = LrError::Codec as i32;

#[repr(C)]
pub struct OpaqueBmpCodec {
    _private: [u8; 0],
}

pub type lr_bmp_codec_t = *mut OpaqueBmpCodec;

fn box_codec(c: BmpCodec) -> lr_bmp_codec_t {
    Box::into_raw(Box::new(c)) as lr_bmp_codec_t
}

unsafe fn borrow_codec_mut(c: lr_bmp_codec_t) -> Option<&'static mut BmpCodec> {
    if c.is_null() {
        return None;
    }
    Some(unsafe { &mut *(c as *mut BmpCodec) })
}

unsafe fn borrow_codec(c: lr_bmp_codec_t) -> Option<&'static BmpCodec> {
    if c.is_null() {
        return None;
    }
    Some(unsafe { &*(c as *const BmpCodec) })
}

#[no_mangle]
pub extern "C" fn lr_bmp_codec_new() -> lr_bmp_codec_t {
    guarded(|| box_codec(BmpCodec::new()), std::ptr::null_mut())
}

#[no_mangle]
pub unsafe extern "C" fn lr_bmp_codec_decode_slice(
    c: lr_bmp_codec_t,
    data: *const u8,
    len: usize,
    out: *mut lr_bmp_message_t,
) -> i32 {
    guarded(
        || unsafe {
            let Some(codec) = borrow_codec_mut(c) else {
                return LR_ERR_NULL;
            };
            if data.is_null() || out.is_null() {
                return LR_ERR_NULL;
            }
            let slice = unsafe { std::slice::from_raw_parts(data, len) };
            match codec.decode_slice(slice) {
                Ok(Some(m)) => {
                    unsafe { *out = box_message(m) }
                    0
                }
                Ok(None) => {
                    set_last_error("truncated".into());
                    LR_ERR_NULL
                }
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
pub unsafe extern "C" fn lr_bmp_codec_feed(c: lr_bmp_codec_t, data: *const u8, len: usize) -> i32 {
    guarded(
        || unsafe {
            let Some(codec) = borrow_codec_mut(c) else {
                return LR_ERR_NULL;
            };
            if data.is_null() {
                return LR_ERR_NULL;
            }
            let slice = unsafe { std::slice::from_raw_parts(data, len) };
            codec.feed(slice);
            0
        },
        LR_ERR_PANIC,
    )
}

#[no_mangle]
pub unsafe extern "C" fn lr_bmp_codec_next_message(
    c: lr_bmp_codec_t,
    out: *mut lr_bmp_message_t,
) -> i32 {
    guarded(
        || unsafe {
            let Some(codec) = borrow_codec_mut(c) else {
                return LR_ERR_NULL;
            };
            if out.is_null() {
                return LR_ERR_NULL;
            }
            match codec.next_message() {
                Ok(Some(m)) => {
                    unsafe { *out = box_message(m) }
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
pub unsafe extern "C" fn lr_bmp_codec_encode_vec(
    c: lr_bmp_codec_t,
    m: lr_bmp_message_t,
    out: *mut lr_bytes_t,
) -> i32 {
    guarded(
        || unsafe {
            let Some(codec) = borrow_codec(c) else {
                return LR_ERR_NULL;
            };
            if m.is_null() || out.is_null() {
                return LR_ERR_NULL;
            }
            let msg: &BmpMessage = &*(m as *const BmpMessage);
            match codec.encode_vec(msg) {
                Ok(b) => {
                    unsafe { *out = lr_bytes_t::from_vec(b) }
                    0
                }
                Err(e) => {
                    set_last_error(e.to_string());
                    LR_ERR_CODEC
                }
            }
        },
        LR_ERR_PANIC,
    )
}

#[no_mangle]
pub unsafe extern "C" fn lr_bmp_codec_free(c: lr_bmp_codec_t) {
    guarded(
        || unsafe {
            if c.is_null() {
                return;
            }
            drop(Box::from_raw(c as *mut BmpCodec));
        },
        (),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ffi_codec_new_default() {
        let c = lr_bmp_codec_new();
        assert!(!c.is_null());
        unsafe { lr_bmp_codec_free(c) };
    }

    #[test]
    fn ffi_codec_free_null_safe() {
        unsafe { lr_bmp_codec_free(std::ptr::null_mut()) };
    }

    #[test]
    fn ffi_codec_decode_truncated_returns_null() {
        let bytes = [0u8; 5];
        let c = lr_bmp_codec_new();
        let mut out: lr_bmp_message_t = std::ptr::null_mut();
        let rc = unsafe { lr_bmp_codec_decode_slice(c, bytes.as_ptr(), bytes.len(), &mut out) };
        assert_eq!(rc, LR_ERR_NULL);
        assert!(out.is_null());
        unsafe { lr_bmp_codec_free(c) };
    }

    #[test]
    fn ffi_codec_decode_null_returns_err() {
        let bytes = [0u8; 6];
        let c = lr_bmp_codec_new();
        let mut out: lr_bmp_message_t = std::ptr::null_mut();
        assert_eq!(
            unsafe {
                lr_bmp_codec_decode_slice(
                    std::ptr::null_mut(),
                    bytes.as_ptr(),
                    bytes.len(),
                    &mut out,
                )
            },
            LR_ERR_NULL
        );
        assert_eq!(
            unsafe { lr_bmp_codec_decode_slice(c, std::ptr::null(), 0, &mut out) },
            LR_ERR_NULL
        );
        assert_eq!(
            unsafe {
                lr_bmp_codec_decode_slice(c, bytes.as_ptr(), bytes.len(), std::ptr::null_mut())
            },
            LR_ERR_NULL
        );
        unsafe { lr_bmp_codec_free(c) };
    }

    #[test]
    fn ffi_codec_feed_then_next_message() {
        let msg = BmpMessage::initiation(&[(1, b"hello")]);
        let codec = BmpCodec::new();
        let bytes = codec.encode_vec(&msg).unwrap();
        assert!(bytes.len() >= 6);
        let c = lr_bmp_codec_new();
        let rc = unsafe { lr_bmp_codec_feed(c, bytes.as_ptr(), bytes.len()) };
        assert_eq!(rc, 0);
        let mut out: lr_bmp_message_t = std::ptr::null_mut();
        let rc = unsafe { lr_bmp_codec_next_message(c, &mut out) };
        assert_eq!(rc, 0);
        assert!(!out.is_null());
        let mut out2: lr_bmp_message_t = std::ptr::null_mut();
        let rc = unsafe { lr_bmp_codec_next_message(c, &mut out2) };
        assert_eq!(rc, 1);
        assert!(out2.is_null());
        unsafe {
            crate::bmp::lr_bmp_message_free(out);
            lr_bmp_codec_free(c);
        };
    }

    #[test]
    fn ffi_codec_next_message_null_returns_err() {
        let c = lr_bmp_codec_new();
        let rc = unsafe { lr_bmp_codec_next_message(c, std::ptr::null_mut()) };
        assert_eq!(rc, LR_ERR_NULL);
        unsafe { lr_bmp_codec_free(c) };
    }

    #[test]
    fn ffi_codec_encode_vec_round_trip() {
        let msg = BmpMessage::initiation(&[(1, b"hi")]);
        let codec = BmpCodec::new();
        let bytes = codec.encode_vec(&msg).unwrap();
        let m = box_message(msg);
        let c = lr_bmp_codec_new();
        let mut out = lr_bytes_t {
            ptr: std::ptr::null_mut(),
            len: 0,
            cap: 0,
        };
        let rc = unsafe { lr_bmp_codec_encode_vec(c, m, &mut out) };
        assert_eq!(rc, 0);
        assert_eq!(out.len, bytes.len());
        let _ = unsafe { Vec::from_raw_parts(out.ptr, out.len, out.cap) };
        unsafe {
            crate::bmp::lr_bmp_message_free(m);
            lr_bmp_codec_free(c);
        };
    }
}
