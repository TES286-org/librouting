//! Layer-1 codec FFI: `lr_bgp_decode`, `lr_bgp_encode`, `lr_ospf_decode`,
//! `lr_babel_decode`.
//!
//! Stateless. Accepts raw byte slices; returns `lr_bytes_t` of decoded JSON
//! (or some structured form — for now, the bytes of the parsed message).

use lr_babel::BabelCodec as BabelC;
use lr_bgp::{BgpCodec as BgpC, BgpMessage};
use lr_ospf::OspfCodec as OspfC;

use crate::error::set_last_error;
use crate::handle::lr_bytes_t;

/// Decode one BGP message from `data`. Returns 0 on success (and writes a
/// `lr_bytes_t` containing the message type byte at offset 0 + body to
/// `out`). Negative on error.
#[no_mangle]
pub extern "C" fn lr_bgp_decode(data: *const u8, len: usize, out: *mut lr_bytes_t) -> i32 {
    if data.is_null() || out.is_null() {
        return -1;
    }
    let slice = unsafe { std::slice::from_raw_parts(data, len) };
    let mut codec = BgpC::new();
    match codec.decode_slice(slice) {
        Ok(Some(m)) => {
            // Encode the message back into bytes (round-trip) — this gives
            // callers a canonical bytes form. The first byte is the type.
            let bytes = match codec.encode_vec(&m) {
                Ok(b) => b,
                Err(e) => {
                    set_last_error(e.to_string());
                    return -4;
                }
            };
            unsafe { *out = lr_bytes_t::from_vec(bytes) }
            0
        }
        Ok(None) => {
            set_last_error("truncated".into());
            -3
        }
        Err(e) => {
            set_last_error(format!("{:?}", e));
            -5
        }
    }
}

/// Encode a BGP message given the body bytes. The first byte of `data` is the
/// message type (1=OPEN, 2=UPDATE, 3=NOTIF, 4=KEEPALIVE, 5=ROUTE-REFRESH).
/// Currently only KEEPALIVE is supported for round-trip FFI testing.
#[no_mangle]
pub extern "C" fn lr_bgp_encode_keepalive(out: *mut lr_bytes_t) -> i32 {
    if out.is_null() {
        return -1;
    }
    let codec = BgpC::new();
    match codec.encode_vec(&BgpMessage::Keepalive(
        lr_bgp::message::keepalive::Keepalive,
    )) {
        Ok(b) => {
            unsafe { *out = lr_bytes_t::from_vec(b) }
            0
        }
        Err(e) => {
            set_last_error(e.to_string());
            -2
        }
    }
}

#[no_mangle]
pub extern "C" fn lr_ospf_decode_v2(data: *const u8, len: usize, out: *mut lr_bytes_t) -> i32 {
    if data.is_null() || out.is_null() {
        return -1;
    }
    let slice = unsafe { std::slice::from_raw_parts(data, len) };
    let mut codec = OspfC::v2();
    match codec.decode_slice(slice) {
        Ok(Some(_p)) => {
            // For FFI we just return the raw input bytes for now.
            unsafe { *out = lr_bytes_t::from_vec(slice.to_vec()) }
            0
        }
        Ok(None) => {
            set_last_error("truncated".into());
            -3
        }
        Err(e) => {
            set_last_error(e.to_string());
            -5
        }
    }
}

#[no_mangle]
pub extern "C" fn lr_babel_decode(data: *const u8, len: usize, out: *mut lr_bytes_t) -> i32 {
    if data.is_null() || out.is_null() {
        return -1;
    }
    let slice = unsafe { std::slice::from_raw_parts(data, len) };
    let mut codec = BabelC::new();
    match codec.decode_slice(slice) {
        Ok(Some(_f)) => {
            unsafe { *out = lr_bytes_t::from_vec(slice.to_vec()) }
            0
        }
        Ok(None) => {
            set_last_error("truncated".into());
            -3
        }
        Err(e) => {
            set_last_error(e.to_string());
            -5
        }
    }
}
