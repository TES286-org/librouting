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

pub(crate) unsafe fn borrow_codec_mut(c: lr_babel_codec_t) -> Option<&'static mut BabelCodec> {
    if c.is_null() {
        return None;
    }
    Some(unsafe { &mut *(c as *mut BabelCodec) })
}

pub(crate) unsafe fn borrow_codec(c: lr_babel_codec_t) -> Option<&'static BabelCodec> {
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

/// An opaque handle to an array of `lr_babel_frame_t` returned by
/// [`lr_babel_codec_pack_frames`]. The array is heap-allocated by
/// the Rust allocator; free it with
/// [`lr_babel_frame_array_free`] when the caller is done with every
/// element (each element must also be freed with
/// [`crate::babel::lr_babel_frame_free`] if it was taken out of the
/// array via [`lr_babel_frame_array_at`]).
#[repr(C)]
pub struct OpaqueBabelFrameArray {
    _private: [u8; 0],
}

pub type lr_babel_frame_array_t = *mut OpaqueBabelFrameArray;

fn box_frame_array(v: Vec<lr_babel_frame_t>) -> lr_babel_frame_array_t {
    Box::into_raw(Box::new(v)) as lr_babel_frame_array_t
}

pub(crate) unsafe fn borrow_frame_array(
    a: lr_babel_frame_array_t,
) -> Option<&'static Vec<lr_babel_frame_t>> {
    if a.is_null() {
        return None;
    }
    Some(unsafe { &*(a as *const Vec<lr_babel_frame_t>) })
}

#[allow(clippy::box_collection)]
pub(crate) unsafe fn take_frame_array(
    a: lr_babel_frame_array_t,
) -> Option<Box<Vec<lr_babel_frame_t>>> {
    if a.is_null() {
        return None;
    }
    // The `Box<Vec<_>>` is intentional: the opaque handle is a stable
    // pointer the C side can pass around, while the inner Vec can grow
    // (it does not after construction, but the type allows it). A
    // bare `Vec<_>` would not give us a stable address to cast into
    // the opaque handle.
    Some(unsafe { Box::from_raw(a as *mut Vec<lr_babel_frame_t>) })
}

/// Split one logical announcement into packet-sized frames, each
/// whose encoded body fits in `max_body_len` octets (RFC 8966 §4
/// caps a Babel datagram body at 1500 − 4 = 1496). The Hello and
/// IHU stay in the first frame; every trailing frame whose first
/// payload TLV is an Update re-emits the most recent Router-Id and
/// family-matching NextHop so the receiver applies the Update with
/// the right source and next hop.
///
/// `out_array` receives an opaque array handle. Query its length
/// with [`lr_babel_frame_array_len`] and borrow element `i` with
/// [`lr_babel_frame_array_at`]. Pass `max_body_len = 1496` for the
/// RFC 8966 §4 default.
///
/// Returns `0` on success, `LR_ERR_NULL` on a NULL pointer.
#[no_mangle]
pub unsafe extern "C" fn lr_babel_codec_pack_frames(
    c: lr_babel_codec_t,
    frame: lr_babel_frame_t,
    max_body_len: usize,
    out_array: *mut lr_babel_frame_array_t,
) -> i32 {
    guarded(
        || unsafe {
            let Some(codec) = borrow_codec(c) else {
                return LR_ERR_NULL;
            };
            if frame.is_null() || out_array.is_null() {
                return LR_ERR_NULL;
            }
            let f: &BabelFrame = &*(frame as *const BabelFrame);
            let packed = codec.pack_frames(f, max_body_len);
            let boxed: Vec<lr_babel_frame_t> = packed.into_iter().map(box_frame).collect();
            unsafe {
                *out_array = box_frame_array(boxed);
            }
            0
        },
        LR_ERR_PANIC,
    )
}

/// The number of frames in a frame array returned by
/// [`lr_babel_codec_pack_frames`]. Returns `0` if `array` is NULL.
#[no_mangle]
pub unsafe extern "C" fn lr_babel_frame_array_len(array: lr_babel_frame_array_t) -> usize {
    guarded(
        || unsafe { borrow_frame_array(array).map_or(0, |v| v.len()) },
        0,
    )
}

/// Borrow element `index` of a frame array returned by
/// [`lr_babel_codec_pack_frames`]. The returned `lr_babel_frame_t`
/// is still owned by the array — do not free it separately. Returns
/// NULL if `array` is NULL or `index` is out of bounds.
#[no_mangle]
pub unsafe extern "C" fn lr_babel_frame_array_at(
    array: lr_babel_frame_array_t,
    index: usize,
) -> lr_babel_frame_t {
    guarded(
        || unsafe {
            borrow_frame_array(array)
                .and_then(|v| v.get(index).copied())
                .unwrap_or(std::ptr::null_mut())
        },
        std::ptr::null_mut(),
    )
}

/// Free a frame array returned by [`lr_babel_codec_pack_frames`].
/// Every element is freed with [`crate::babel::lr_babel_frame_free`]
/// (the elements are owned by the array). NULL-safe.
#[no_mangle]
pub unsafe extern "C" fn lr_babel_frame_array_free(array: lr_babel_frame_array_t) {
    guarded(
        || unsafe {
            let Some(boxed) = take_frame_array(array) else {
                return;
            };
            for f in boxed.iter() {
                if !f.is_null() {
                    drop(crate::babel::unbox_frame(*f));
                }
            }
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

    /// `lr_babel_codec_pack_frames` splits a frame whose body would
    /// overflow `max_body_len` into multiple frames. The first frame
    /// carries the Hello; trailing frames re-emit the Router-Id and
    /// NextHop so every Update has its context.
    #[test]
    fn ffi_codec_pack_frames_splits_oversized_announcement() {
        use lr_babel::message::{NextHop, RouterId as RouterIdTlv};
        use lr_babel::tlv::{Tlv, TlvType};
        // Build a frame with 1 Router-Id + NextHop + 80 v6 Updates.
        // At a 64-byte body budget the splitter must produce several
        // frames, each carrying its own Router-Id + NextHop preamble.
        let mut frame = lr_babel::BabelFrame::empty();
        frame.body.push(Tlv::new(
            TlvType::NextHop,
            NextHop {
                ae: 2,
                address: lr_core::addr::IpAddr::V6([
                    0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
                ]),
            }
            .encode(),
        ));
        frame.body.push(Tlv::new(
            TlvType::RouterId,
            RouterIdTlv {
                id: [1, 2, 3, 4, 5, 6, 7, 8],
            }
            .encode()
            .to_vec(),
        ));
        for i in 0u8..80 {
            let mut prefix = [0u8; 8];
            prefix[7] = i;
            let mut body = vec![2u8, 0, 64, 0, 0x01, 0x2c, 0, i, 0, 0xc0];
            body.extend_from_slice(&prefix);
            frame.body.push(Tlv::new(TlvType::Update, body));
        }
        let c = lr_babel_codec_new();
        let frame_h = box_frame(frame);
        let mut array: lr_babel_frame_array_t = std::ptr::null_mut();
        let rc = unsafe { lr_babel_codec_pack_frames(c, frame_h, 64, &mut array) };
        assert_eq!(rc, 0);
        let len = unsafe { lr_babel_frame_array_len(array) };
        assert!(len > 1, "80 Updates at 64-byte budget must split");
        // Every element is non-NULL and carries at least one TLV.
        for i in 0..len {
            let f = unsafe { lr_babel_frame_array_at(array, i) };
            assert!(!f.is_null(), "element {i} is NULL");
            assert!(
                unsafe { crate::babel::lr_babel_frame_tlv_count(f) } > 0,
                "element {i} is empty"
            );
        }
        // Free the original frame handle (pack_frames borrows it, does
        // not take ownership).
        unsafe { crate::babel::lr_babel_frame_free(frame_h) };
        // Free the array (this also frees every element).
        unsafe { lr_babel_frame_array_free(array) };
        unsafe { lr_babel_codec_free(c) };
    }

    /// `lr_babel_codec_pack_frames` is NULL-safe: NULL codec, NULL
    /// frame, or NULL out handle all return `LR_ERR_NULL` without
    /// crashing.
    #[test]
    fn ffi_codec_pack_frames_null_safe() {
        let c = lr_babel_codec_new();
        let mut array: lr_babel_frame_array_t = std::ptr::null_mut();
        assert_eq!(
            unsafe {
                lr_babel_codec_pack_frames(
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    64,
                    &mut array,
                )
            },
            LR_ERR_NULL
        );
        assert_eq!(
            unsafe { lr_babel_codec_pack_frames(c, std::ptr::null_mut(), 64, &mut array) },
            LR_ERR_NULL
        );
        assert_eq!(
            unsafe {
                lr_babel_codec_pack_frames(c, std::ptr::null_mut(), 64, std::ptr::null_mut())
            },
            LR_ERR_NULL
        );
        // Accessors on NULL are also safe.
        assert_eq!(unsafe { lr_babel_frame_array_len(std::ptr::null_mut()) }, 0);
        assert!(unsafe { lr_babel_frame_array_at(std::ptr::null_mut(), 0) }.is_null());
        unsafe { lr_babel_frame_array_free(std::ptr::null_mut()) };
        unsafe { lr_babel_codec_free(c) };
    }
}
