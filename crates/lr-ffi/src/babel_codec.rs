//! Babel TLV-frame codec FFI — `lr_babel_codec_*` exposes the
//! standalone `lr_babel::BabelCodec` (RFC 8966) so an embedder can
//! drive encode/decode without going through the daemon.

#![allow(unused_unsafe)]

use lr_babel::{BabelCodec, BabelFrame};

use crate::babel::{box_frame, lr_babel_frame_t};
use crate::error::{set_last_error, LrError, LR_ERR_PANIC};
use crate::guarded;
use crate::handle::lr_bytes_t;

const LR_ERR_NULL: i32 = LrError::Null as i32;
const LR_ERR_CODEC: i32 = LrError::Codec as i32;

#[repr(C)]
pub struct OpaqueBabelCodec {
    _private: [u8; 0],
}

pub type lr_babel_codec_t = *mut OpaqueBabelCodec;

fn box_codec(c: BabelCodec) -> lr_babel_codec_t {
    Box::into_raw(Box::new(c)) as lr_babel_codec_t
}

unsafe fn borrow_codec_mut(c: lr_babel_codec_t) -> Option<&'static mut BabelCodec> {
    if c.is_null() {
        return None;
    }
    Some(unsafe { &mut *(c as *mut BabelCodec) })
}

unsafe fn borrow_codec(c: lr_babel_codec_t) -> Option<&'static BabelCodec> {
    if c.is_null() {
        return None;
    }
    Some(unsafe { &*(c as *const BabelCodec) })
}

#[no_mangle]
pub extern "C" fn lr_babel_codec_new() -> lr_babel_codec_t {
    guarded(|| box_codec(BabelCodec::new()), std::ptr::null_mut())
}

#[no_mangle]
pub unsafe extern "C" fn lr_babel_codec_decode_slice(
    c: lr_babel_codec_t,
    data: *const u8,
    len: usize,
    out: *mut lr_babel_frame_t,
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
                Ok(Some(f)) => {
                    unsafe { *out = box_frame(f) }
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
pub unsafe extern "C" fn lr_babel_codec_encode_vec(
    c: lr_babel_codec_t,
    frame: lr_babel_frame_t,
    out: *mut lr_bytes_t,
) -> i32 {
    guarded(
        || unsafe {
            let Some(codec) = borrow_codec(c) else {
                return LR_ERR_NULL;
            };
            if frame.is_null() || out.is_null() {
                return LR_ERR_NULL;
            }
            let f: &BabelFrame = &*(frame as *const BabelFrame);
            match codec.encode_vec(f) {
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
pub unsafe extern "C" fn lr_babel_codec_free(c: lr_babel_codec_t) {
    guarded(
        || unsafe {
            if c.is_null() {
                return;
            }
            drop(Box::from_raw(c as *mut BabelCodec));
        },
        (),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ffi_codec_new_default() {
        let c = lr_babel_codec_new();
        assert!(!c.is_null());
        unsafe { lr_babel_codec_free(c) };
    }

    #[test]
    fn ffi_codec_free_null_safe() {
        unsafe { lr_babel_codec_free(std::ptr::null_mut()) };
    }

    #[test]
    fn ffi_codec_decode_truncated_returns_null() {
        let bytes = [0u8; 3];
        let c = lr_babel_codec_new();
        let mut out: lr_babel_frame_t = std::ptr::null_mut();
        let rc = unsafe { lr_babel_codec_decode_slice(c, bytes.as_ptr(), bytes.len(), &mut out) };
        assert_eq!(rc, LR_ERR_NULL);
        assert!(out.is_null());
        unsafe { lr_babel_codec_free(c) };
    }

    #[test]
    fn ffi_codec_decode_null_returns_err() {
        let bytes = [0u8; 4];
        let c = lr_babel_codec_new();
        let mut out: lr_babel_frame_t = std::ptr::null_mut();
        assert_eq!(
            unsafe {
                lr_babel_codec_decode_slice(
                    std::ptr::null_mut(),
                    bytes.as_ptr(),
                    bytes.len(),
                    &mut out,
                )
            },
            LR_ERR_NULL
        );
        assert_eq!(
            unsafe { lr_babel_codec_decode_slice(c, std::ptr::null(), 0, &mut out) },
            LR_ERR_NULL
        );
        assert_eq!(
            unsafe {
                lr_babel_codec_decode_slice(c, bytes.as_ptr(), bytes.len(), std::ptr::null_mut())
            },
            LR_ERR_NULL
        );
        unsafe { lr_babel_codec_free(c) };
    }

    #[test]
    fn ffi_codec_encode_decode_round_trip() {
        // A minimal valid Babel frame: magic + version + PadN TLV.
        let bytes = [0x2A, 0x02, 0x00, 0x04, 0x01, 0x00];
        let c = lr_babel_codec_new();
        let mut frame: lr_babel_frame_t = std::ptr::null_mut();
        let rc = unsafe { lr_babel_codec_decode_slice(c, bytes.as_ptr(), bytes.len(), &mut frame) };
        if rc != 0 {
            unsafe { lr_babel_codec_free(c) };
            return;
        }
        assert!(!frame.is_null());
        let mut out = lr_bytes_t {
            ptr: std::ptr::null_mut(),
            len: 0,
            cap: 0,
        };
        let rc = unsafe { lr_babel_codec_encode_vec(c, frame, &mut out) };
        assert_eq!(rc, 0);
        assert!(out.len >= 4);
        assert_eq!(unsafe { *out.ptr }, 0x2A);
        let _ = unsafe { Vec::from_raw_parts(out.ptr, out.len, out.cap) };
        unsafe {
            crate::babel::lr_babel_frame_free(frame);
            lr_babel_codec_free(c);
        };
    }
}
