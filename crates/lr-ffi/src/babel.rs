//! Babel wire codec FFI (RFC 8966).
//!
//! Stateless. Mirrors the public Rust API of `lr_babel::{BabelCodec,
//! BabelFrame, Tlv, TlvType}` so an embedder can build, inspect and
//! round-trip Babel datagrams without going through the Rust compiler.
//!
//! Every entry point runs inside the crate's `catch_unwind` barrier
//! ([`crate::guarded`]): a panic returns `LR_ERR_PANIC` and sets the
//! thread-local last-error string.

// The closure body passed to `guarded` is wrapped in a single `unsafe`
// block to mirror the `pub unsafe extern "C" fn` shape — the inner
// `unsafe { ... }` blocks would otherwise trip `unused_unsafe` under
// the crate's `-D warnings` clippy gate.
#![allow(unused_unsafe)]

use lr_babel::{BabelCodec, BabelFrame, TlvType};

use crate::error::{set_last_error, LrError, LR_ERR_PANIC};
use crate::guarded;
use crate::handle::lr_bytes_t;

const LR_ERR_NULL: i32 = LrError::Null as i32;
const LR_ERR_OTHER: i32 = LrError::Other as i32;

/// Opaque `BabelFrame` handle.
#[repr(C)]
pub struct OpaqueBabelFrame {
    _private: [u8; 0],
}

pub type lr_babel_frame_t = *mut OpaqueBabelFrame;

pub(crate) fn box_frame(f: BabelFrame) -> lr_babel_frame_t {
    Box::into_raw(Box::new(f)) as lr_babel_frame_t
}

/// Reclaim a frame handle.
///
/// # Safety
/// `f` must have been produced by [`box_frame`] and not freed.
unsafe fn unbox_frame(f: lr_babel_frame_t) -> Option<Box<BabelFrame>> {
    if f.is_null() {
        return None;
    }
    Some(unsafe { Box::from_raw(f as *mut BabelFrame) })
}

/// Borrow a frame handle as `&BabelFrame`.
///
/// # Safety
/// `f` must have been produced by [`box_frame`] and not be freed while
/// the returned reference is live.
unsafe fn borrow_frame(f: lr_babel_frame_t) -> Option<&'static BabelFrame> {
    if f.is_null() {
        return None;
    }
    Some(unsafe { &*(f as *const BabelFrame) })
}

// ---- Constants (mirrors lr_babel pub consts) ----

pub const LR_BABEL_MAGIC: u8 = lr_babel::MAGIC;
pub const LR_BABEL_VERSION: u8 = lr_babel::VERSION;

pub const LR_BABEL_TLV_PAD1: u8 = 0;
pub const LR_BABEL_TLV_PADN: u8 = 1;
pub const LR_BABEL_TLV_ACK_REQ: u8 = 2;
pub const LR_BABEL_TLV_ACK: u8 = 3;
pub const LR_BABEL_TLV_HELLO: u8 = 4;
pub const LR_BABEL_TLV_IHU: u8 = 5;
pub const LR_BABEL_TLV_ROUTER_ID: u8 = 6;
pub const LR_BABEL_TLV_NEXT_HOP: u8 = 7;
pub const LR_BABEL_TLV_UPDATE: u8 = 8;
pub const LR_BABEL_TLV_ROUTE_REQUEST: u8 = 9;
pub const LR_BABEL_TLV_SEQNO_REQUEST: u8 = 10;
pub const LR_BABEL_TLV_TS_PC: u8 = 11;
pub const LR_BABEL_TLV_HMAC: u8 = 12;
pub const LR_BABEL_TLV_MAC: u8 = 16;
pub const LR_BABEL_TLV_PC: u8 = 17;
pub const LR_BABEL_TLV_CHALLENGE_REQUEST: u8 = 18;
pub const LR_BABEL_TLV_CHALLENGE_REPLY: u8 = 19;

// ---- Decode / encode ----

/// Decode one Babel frame from `data`. On success, writes a freshly-
/// allocated `lr_babel_frame_t` to `*out`.
///
/// # Safety
/// `data` must point to `len` readable bytes. `out` must point to a
/// writable `lr_babel_frame_t`.
#[no_mangle]
pub unsafe extern "C" fn lr_babel_decode_frame(
    data: *const u8,
    len: usize,
    out: *mut lr_babel_frame_t,
) -> i32 {
    guarded(
        || unsafe {
            if data.is_null() || out.is_null() {
                return LR_ERR_NULL;
            }
            let slice = unsafe { std::slice::from_raw_parts(data, len) };
            let mut codec = BabelCodec::new();
            match codec.decode_slice(slice) {
                Ok(Some(f)) => {
                    unsafe { *out = box_frame(f) }
                    0
                }
                Ok(None) => {
                    set_last_error("truncated".into());
                    LR_ERR_OTHER
                }
                Err(e) => {
                    set_last_error(format!("{e:?}"));
                    LrError::Codec as i32
                }
            }
        },
        LR_ERR_PANIC,
    )
}

/// Encode a Babel frame to its wire form.
///
/// # Safety
/// `frame` must be a valid handle. `out` must point to a writable
/// `lr_bytes_t`.
#[no_mangle]
pub unsafe extern "C" fn lr_babel_encode_frame(
    frame: lr_babel_frame_t,
    out: *mut lr_bytes_t,
) -> i32 {
    guarded(
        || unsafe {
            let Some(f) = borrow_frame(frame) else {
                return LR_ERR_NULL;
            };
            if out.is_null() {
                return LR_ERR_NULL;
            }
            let codec = BabelCodec::new();
            match codec.encode_vec(f) {
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

// ---- Readers ----

/// Read the number of TLVs the frame carries.
///
/// # Safety
/// `frame` must be a valid handle.
#[no_mangle]
pub unsafe extern "C" fn lr_babel_frame_tlv_count(frame: lr_babel_frame_t) -> usize {
    guarded(
        || unsafe { borrow_frame(frame).map(|f| f.body.len()).unwrap_or(0) },
        0,
    )
}

/// Read the TLV-type code of TLV `index` (one of the
/// `LR_BABEL_TLV_*` constants). Returns 0 on a NULL handle or an
/// out-of-range index.
///
/// # Safety
/// `frame` must be a valid handle.
#[no_mangle]
pub unsafe extern "C" fn lr_babel_frame_tlv_type_at(frame: lr_babel_frame_t, index: usize) -> u8 {
    guarded(
        || unsafe {
            let Some(f) = borrow_frame(frame) else {
                return 0;
            };
            f.body
                .get(index)
                .map(|t| match t.kind {
                    TlvType::Pad1 => LR_BABEL_TLV_PAD1,
                    TlvType::PadN => LR_BABEL_TLV_PADN,
                    TlvType::AckReq => LR_BABEL_TLV_ACK_REQ,
                    TlvType::Ack => LR_BABEL_TLV_ACK,
                    TlvType::Hello => LR_BABEL_TLV_HELLO,
                    TlvType::Ihu => LR_BABEL_TLV_IHU,
                    TlvType::RouterId => LR_BABEL_TLV_ROUTER_ID,
                    TlvType::NextHop => LR_BABEL_TLV_NEXT_HOP,
                    TlvType::Update => LR_BABEL_TLV_UPDATE,
                    TlvType::RouteRequest => LR_BABEL_TLV_ROUTE_REQUEST,
                    TlvType::SeqnoRequest => LR_BABEL_TLV_SEQNO_REQUEST,
                    TlvType::TsPc => LR_BABEL_TLV_TS_PC,
                    TlvType::Hmac => LR_BABEL_TLV_HMAC,
                    TlvType::Mac => LR_BABEL_TLV_MAC,
                    TlvType::Pc => LR_BABEL_TLV_PC,
                    TlvType::ChallengeRequest => LR_BABEL_TLV_CHALLENGE_REQUEST,
                    TlvType::ChallengeReply => LR_BABEL_TLV_CHALLENGE_REPLY,
                    TlvType::SourcePrefixSubTlv => 128,
                    TlvType::Other(v) => v,
                })
                .unwrap_or(0)
        },
        0,
    )
}

/// Read the TLV value length of TLV `index`. Returns 0 on a NULL
/// handle or an out-of-range index.
///
/// # Safety
/// `frame` must be a valid handle.
#[no_mangle]
pub unsafe extern "C" fn lr_babel_frame_tlv_value_len_at(
    frame: lr_babel_frame_t,
    index: usize,
) -> usize {
    guarded(
        || unsafe {
            let Some(f) = borrow_frame(frame) else {
                return 0;
            };
            f.body.get(index).map(|t| t.value.len()).unwrap_or(0)
        },
        0,
    )
}

/// Copy the TLV value bytes of TLV `index` into the caller-supplied
/// buffer. Returns the number of bytes copied (0 on a NULL handle,
/// an out-of-range index, or a NULL `out`).
///
/// # Safety
/// `frame` must be a valid handle. `out` must point to at least `cap`
/// writable bytes.
#[no_mangle]
pub unsafe extern "C" fn lr_babel_frame_tlv_value_at(
    frame: lr_babel_frame_t,
    index: usize,
    out: *mut u8,
    cap: usize,
) -> usize {
    guarded(
        || unsafe {
            let Some(f) = borrow_frame(frame) else {
                return 0;
            };
            if out.is_null() || cap == 0 {
                return 0;
            }
            let Some(t) = f.body.get(index) else {
                return 0;
            };
            let take = t.value.len().min(cap);
            unsafe {
                std::ptr::copy_nonoverlapping(t.value.as_ptr(), out, take);
            }
            take
        },
        0,
    )
}

/// Drop a boxed `BabelFrame`. Safe to call with NULL.
///
/// # Safety
/// `frame` must have been produced by a `lr_babel_*_frame` constructor
/// and must not be used after this call.
#[no_mangle]
pub unsafe extern "C" fn lr_babel_frame_free(frame: lr_babel_frame_t) {
    guarded(
        || unsafe {
            drop(unbox_frame(frame));
        },
        (),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use lr_babel::Tlv;

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

    fn build_frame() -> BabelFrame {
        // A minimal frame: magic(0x2a) + version(2) + body_len(0) +
        // one Pad1 TLV (type=0). BabelCodec finalizes body_len.
        let tlv = Tlv::pad1();
        BabelFrame::new(vec![tlv])
    }

    #[test]
    fn ffi_decode_frame_roundtrip() {
        let frame = build_frame();
        let codec = BabelCodec::new();
        let bytes = codec.encode_vec(&frame).expect("encode");
        let mut f: lr_babel_frame_t = std::ptr::null_mut();
        let rc = unsafe { lr_babel_decode_frame(bytes.as_ptr(), bytes.len(), &raw mut f) };
        assert_eq!(rc, 0);
        assert!(!f.is_null());
        unsafe {
            assert!(lr_babel_frame_tlv_count(f) >= 1);
            assert_eq!(lr_babel_frame_tlv_type_at(f, 0), LR_BABEL_TLV_PAD1);

            // Encode it back.
            let mut out = lr_bytes_t {
                ptr: std::ptr::null_mut(),
                len: 0,
                cap: 0,
            };
            assert_eq!(lr_babel_encode_frame(f, &raw mut out), 0);
            let bytes2 = bytes_to_vec(&mut out);
            assert_eq!(bytes2, bytes);
            lr_babel_frame_free(f);
        }
    }

    #[test]
    fn ffi_decode_rejects_null_input() {
        let mut f: lr_babel_frame_t = std::ptr::null_mut();
        let rc = unsafe { lr_babel_decode_frame(std::ptr::null(), 0, &raw mut f) };
        assert_eq!(rc, LR_ERR_NULL);
    }

    #[test]
    fn ffi_decode_rejects_too_short() {
        let bytes = [0u8; 2];
        let mut f: lr_babel_frame_t = std::ptr::null_mut();
        let rc = unsafe { lr_babel_decode_frame(bytes.as_ptr(), bytes.len(), &raw mut f) };
        assert!(rc < 0);
        assert!(f.is_null());
    }

    #[test]
    fn ffi_free_handles_null() {
        unsafe { lr_babel_frame_free(std::ptr::null_mut()) };
    }

    #[test]
    fn ffi_tlv_count_returns_zero_on_null() {
        assert_eq!(unsafe { lr_babel_frame_tlv_count(std::ptr::null_mut()) }, 0);
    }

    #[test]
    fn ffi_tlv_type_at_returns_zero_for_oob() {
        let frame = build_frame();
        let codec = BabelCodec::new();
        let bytes = codec.encode_vec(&frame).expect("encode");
        let mut f: lr_babel_frame_t = std::ptr::null_mut();
        unsafe {
            assert_eq!(
                lr_babel_decode_frame(bytes.as_ptr(), bytes.len(), &raw mut f),
                0
            );
            assert_eq!(lr_babel_frame_tlv_type_at(f, 99), 0);
            lr_babel_frame_free(f);
        }
    }

    #[test]
    fn ffi_constants_match_rfc_8966() {
        assert_eq!(LR_BABEL_MAGIC, 0x2a);
        assert_eq!(LR_BABEL_VERSION, 2);
        assert_eq!(LR_BABEL_TLV_PAD1, 0);
        assert_eq!(LR_BABEL_TLV_PADN, 1);
        assert_eq!(LR_BABEL_TLV_HELLO, 4);
        assert_eq!(LR_BABEL_TLV_UPDATE, 8);
    }
}
