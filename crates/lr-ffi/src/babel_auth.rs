//! Babel RFC 8967 HMAC authentication FFI.
#![allow(unused_unsafe)]

use lr_babel::auth::{
    BabelAuthError, BabelMacAlgorithm, BabelMacKey, BabelPacketCounter, BabelPseudoHeader,
    BabelReplayProtection,
};

use crate::error::{set_last_error, LrError, LR_ERR_PANIC};
use crate::guarded;
use crate::handle::lr_bytes_t;

const LR_ERR_NULL: i32 = LrError::Null as i32;
const LR_ERR_INVALID_HANDLE: i32 = LrError::InvalidHandle as i32;

pub const LR_BABEL_MAC_HMAC_SHA256: i32 = 1;
pub const LR_BABEL_MAC_BLAKE2S128: i32 = 2;

fn algo_to_i32(a: BabelMacAlgorithm) -> i32 {
    match a {
        BabelMacAlgorithm::HmacSha256 => LR_BABEL_MAC_HMAC_SHA256,
        BabelMacAlgorithm::Blake2s128 => LR_BABEL_MAC_BLAKE2S128,
    }
}

fn i32_to_algo(v: i32) -> Option<BabelMacAlgorithm> {
    match v {
        LR_BABEL_MAC_HMAC_SHA256 => Some(BabelMacAlgorithm::HmacSha256),
        LR_BABEL_MAC_BLAKE2S128 => Some(BabelMacAlgorithm::Blake2s128),
        _ => None,
    }
}

fn err_code(e: &BabelAuthError) -> i32 {
    let _ = e;
    LrError::Other as i32
}

#[repr(C)]
pub struct OpaqueBabelMacKey {
    _private: [u8; 0],
}
pub type lr_babel_mac_key_t = *mut OpaqueBabelMacKey;

fn box_key(k: BabelMacKey) -> lr_babel_mac_key_t {
    Box::into_raw(Box::new(k)) as lr_babel_mac_key_t
}
unsafe fn borrow_key(k: lr_babel_mac_key_t) -> Option<&'static BabelMacKey> {
    if k.is_null() {
        return None;
    }
    Some(unsafe { &*(k as *const BabelMacKey) })
}
unsafe fn unbox_key(k: lr_babel_mac_key_t) -> Option<Box<BabelMacKey>> {
    if k.is_null() {
        return None;
    }
    Some(unsafe { Box::from_raw(k as *mut BabelMacKey) })
}

#[no_mangle]
pub unsafe extern "C" fn lr_babel_mac_key_new(
    algorithm: i32,
    secret: *const u8,
    secret_len: usize,
) -> lr_babel_mac_key_t {
    guarded(
        || unsafe {
            let Some(algo) = i32_to_algo(algorithm) else {
                set_last_error(format!("unknown Babel MAC algorithm id {algorithm}"));
                return std::ptr::null_mut();
            };
            if secret.is_null() && secret_len != 0 {
                return std::ptr::null_mut();
            }
            let s = if secret_len == 0 {
                &[][..]
            } else {
                unsafe { std::slice::from_raw_parts(secret, secret_len) }
            };
            box_key(BabelMacKey {
                algorithm: algo,
                secret: s.to_vec(),
            })
        },
        std::ptr::null_mut(),
    )
}

#[no_mangle]
pub unsafe extern "C" fn lr_babel_mac_key_hmac_sha256(
    secret: *const u8,
    secret_len: usize,
) -> lr_babel_mac_key_t {
    guarded(
        || unsafe { lr_babel_mac_key_new(LR_BABEL_MAC_HMAC_SHA256, secret, secret_len) },
        std::ptr::null_mut(),
    )
}

#[no_mangle]
pub unsafe extern "C" fn lr_babel_mac_key_blake2s128(
    secret: *const u8,
    secret_len: usize,
) -> lr_babel_mac_key_t {
    guarded(
        || unsafe { lr_babel_mac_key_new(LR_BABEL_MAC_BLAKE2S128, secret, secret_len) },
        std::ptr::null_mut(),
    )
}

#[no_mangle]
pub unsafe extern "C" fn lr_babel_mac_key_algorithm(k: lr_babel_mac_key_t) -> i32 {
    guarded(
        || unsafe { borrow_key(k).map(|x| algo_to_i32(x.algorithm)).unwrap_or(0) },
        0,
    )
}
#[no_mangle]
pub unsafe extern "C" fn lr_babel_mac_key_digest_len(k: lr_babel_mac_key_t) -> usize {
    guarded(
        || unsafe { borrow_key(k).map(|x| x.algorithm.digest_len()).unwrap_or(0) },
        0,
    )
}
#[no_mangle]
pub unsafe extern "C" fn lr_babel_mac_key_secret_len(k: lr_babel_mac_key_t) -> usize {
    guarded(
        || unsafe { borrow_key(k).map(|x| x.secret.len()).unwrap_or(0) },
        0,
    )
}
#[no_mangle]
pub unsafe extern "C" fn lr_babel_mac_key_secret_copy(
    k: lr_babel_mac_key_t,
    out: *mut u8,
    cap: usize,
) -> usize {
    guarded(
        || unsafe {
            let Some(key) = borrow_key(k) else {
                return 0;
            };
            if out.is_null() || cap == 0 {
                return 0;
            }
            let n = key.secret.len().min(cap);
            unsafe {
                std::ptr::copy_nonoverlapping(key.secret.as_ptr(), out, n);
            }
            n
        },
        0,
    )
}
#[no_mangle]
pub unsafe extern "C" fn lr_babel_mac_key_free(k: lr_babel_mac_key_t) {
    guarded(
        || unsafe {
            drop(unbox_key(k));
        },
        (),
    )
}

#[repr(C)]
pub struct OpaqueBabelPseudoHeader {
    _private: [u8; 0],
}
pub type lr_babel_pseudo_header_t = *mut OpaqueBabelPseudoHeader;
fn box_ph(p: BabelPseudoHeader) -> lr_babel_pseudo_header_t {
    Box::into_raw(Box::new(p)) as lr_babel_pseudo_header_t
}
unsafe fn borrow_ph(p: lr_babel_pseudo_header_t) -> Option<&'static BabelPseudoHeader> {
    if p.is_null() {
        return None;
    }
    Some(unsafe { &*(p as *const BabelPseudoHeader) })
}
unsafe fn unbox_ph(p: lr_babel_pseudo_header_t) -> Option<Box<BabelPseudoHeader>> {
    if p.is_null() {
        return None;
    }
    Some(unsafe { Box::from_raw(p as *mut BabelPseudoHeader) })
}

#[no_mangle]
pub unsafe extern "C" fn lr_babel_pseudo_header_new_v4(
    src_v4: *const u8,
    src_port: u16,
    dst_v4: *const u8,
    dst_port: u16,
) -> lr_babel_pseudo_header_t {
    guarded(
        || unsafe {
            if src_v4.is_null() || dst_v4.is_null() {
                return std::ptr::null_mut();
            }
            let mut s = [0u8; 4];
            let mut d = [0u8; 4];
            unsafe {
                s.copy_from_slice(std::slice::from_raw_parts(src_v4, 4));
                d.copy_from_slice(std::slice::from_raw_parts(dst_v4, 4));
            }
            box_ph(BabelPseudoHeader {
                source: lr_core::addr::IpAddr::V4(s),
                source_port: src_port,
                destination: lr_core::addr::IpAddr::V4(d),
                destination_port: dst_port,
            })
        },
        std::ptr::null_mut(),
    )
}

#[no_mangle]
pub unsafe extern "C" fn lr_babel_pseudo_header_new_v6(
    src_v6: *const u8,
    src_port: u16,
    dst_v6: *const u8,
    dst_port: u16,
) -> lr_babel_pseudo_header_t {
    guarded(
        || unsafe {
            if src_v6.is_null() || dst_v6.is_null() {
                return std::ptr::null_mut();
            }
            let mut s = [0u8; 16];
            let mut d = [0u8; 16];
            unsafe {
                s.copy_from_slice(std::slice::from_raw_parts(src_v6, 16));
                d.copy_from_slice(std::slice::from_raw_parts(dst_v6, 16));
            }
            box_ph(BabelPseudoHeader {
                source: lr_core::addr::IpAddr::V6(s),
                source_port: src_port,
                destination: lr_core::addr::IpAddr::V6(d),
                destination_port: dst_port,
            })
        },
        std::ptr::null_mut(),
    )
}

#[no_mangle]
pub unsafe extern "C" fn lr_babel_pseudo_header_encode(
    p: lr_babel_pseudo_header_t,
    out: *mut lr_bytes_t,
) -> i32 {
    guarded(
        || unsafe {
            let Some(ph) = borrow_ph(p) else {
                return LR_ERR_NULL;
            };
            if out.is_null() {
                return LR_ERR_NULL;
            }
            unsafe { *out = lr_bytes_t::from_vec(ph.encode()) }
            0
        },
        LR_ERR_PANIC,
    )
}

#[no_mangle]
pub unsafe extern "C" fn lr_babel_pseudo_header_free(p: lr_babel_pseudo_header_t) {
    guarded(
        || unsafe {
            drop(unbox_ph(p));
        },
        (),
    )
}

#[repr(C)]
pub struct OpaqueBabelPacketCounter {
    _private: [u8; 0],
}
pub type lr_babel_packet_counter_t = *mut OpaqueBabelPacketCounter;
fn box_counter(c: BabelPacketCounter) -> lr_babel_packet_counter_t {
    Box::into_raw(Box::new(c)) as lr_babel_packet_counter_t
}
unsafe fn borrow_counter_mut(
    c: lr_babel_packet_counter_t,
) -> Option<&'static mut BabelPacketCounter> {
    if c.is_null() {
        return None;
    }
    Some(unsafe { &mut *(c as *mut BabelPacketCounter) })
}
unsafe fn unbox_counter(c: lr_babel_packet_counter_t) -> Option<Box<BabelPacketCounter>> {
    if c.is_null() {
        return None;
    }
    Some(unsafe { Box::from_raw(c as *mut BabelPacketCounter) })
}

#[no_mangle]
pub unsafe extern "C" fn lr_babel_packet_counter_new(
    index: *const u8,
    index_len: usize,
    initial: u32,
) -> lr_babel_packet_counter_t {
    guarded(
        || unsafe {
            if index.is_null() || index_len == 0 || index_len > 32 {
                set_last_error("lr_babel_packet_counter_new: index must be 1..=32 bytes".into());
                return std::ptr::null_mut();
            }
            let s = unsafe { std::slice::from_raw_parts(index, index_len) };
            match BabelPacketCounter::new(s.to_vec(), initial) {
                Ok(c) => box_counter(c),
                Err(e) => {
                    set_last_error(e.to_string());
                    std::ptr::null_mut()
                }
            }
        },
        std::ptr::null_mut(),
    )
}

#[no_mangle]
pub unsafe extern "C" fn lr_babel_packet_counter_peek_counter(c: lr_babel_packet_counter_t) -> u32 {
    guarded(
        || unsafe { borrow_counter_mut(c).map(|x| x.peek().0).unwrap_or(0) },
        0,
    )
}
#[no_mangle]
pub unsafe extern "C" fn lr_babel_packet_counter_peek_index_len(
    c: lr_babel_packet_counter_t,
) -> usize {
    guarded(
        || unsafe { borrow_counter_mut(c).map(|x| x.peek().1.len()).unwrap_or(0) },
        0,
    )
}
#[no_mangle]
pub unsafe extern "C" fn lr_babel_packet_counter_peek_index_copy(
    c: lr_babel_packet_counter_t,
    out: *mut u8,
    cap: usize,
) -> usize {
    guarded(
        || unsafe {
            let Some(counter) = borrow_counter_mut(c) else {
                return 0;
            };
            if out.is_null() || cap == 0 {
                return 0;
            }
            let (_, index) = counter.peek();
            let n = index.len().min(cap);
            unsafe {
                std::ptr::copy_nonoverlapping(index.as_ptr(), out, n);
            }
            n
        },
        0,
    )
}
#[no_mangle]
pub unsafe extern "C" fn lr_babel_packet_counter_free(c: lr_babel_packet_counter_t) {
    guarded(
        || unsafe {
            drop(unbox_counter(c));
        },
        (),
    )
}

#[repr(C)]
pub struct OpaqueBabelReplayProtection {
    _private: [u8; 0],
}
pub type lr_babel_replay_protection_t = *mut OpaqueBabelReplayProtection;
fn box_rp(r: BabelReplayProtection) -> lr_babel_replay_protection_t {
    Box::into_raw(Box::new(r)) as lr_babel_replay_protection_t
}
unsafe fn borrow_rp_mut(
    r: lr_babel_replay_protection_t,
) -> Option<&'static mut BabelReplayProtection> {
    if r.is_null() {
        return None;
    }
    Some(unsafe { &mut *(r as *mut BabelReplayProtection) })
}
unsafe fn unbox_rp(r: lr_babel_replay_protection_t) -> Option<Box<BabelReplayProtection>> {
    if r.is_null() {
        return None;
    }
    Some(unsafe { Box::from_raw(r as *mut BabelReplayProtection) })
}

#[no_mangle]
pub extern "C" fn lr_babel_replay_protection_new() -> lr_babel_replay_protection_t {
    guarded(
        || box_rp(BabelReplayProtection::default()),
        std::ptr::null_mut(),
    )
}

#[no_mangle]
pub unsafe extern "C" fn lr_babel_replay_protection_accept(
    r: lr_babel_replay_protection_t,
    index: *const u8,
    index_len: usize,
    counter: u32,
) -> u8 {
    guarded(
        || unsafe {
            let Some(rp) = borrow_rp_mut(r) else {
                return 0;
            };
            if index.is_null() || index_len == 0 {
                return 0;
            }
            let s = unsafe { std::slice::from_raw_parts(index, index_len) };
            rp.accept(s, counter) as u8
        },
        0,
    )
}

#[no_mangle]
pub unsafe extern "C" fn lr_babel_replay_protection_free(r: lr_babel_replay_protection_t) {
    guarded(
        || unsafe {
            drop(unbox_rp(r));
        },
        (),
    )
}

// ---- BabelCodec authenticated encode/decode ----

#[no_mangle]
pub unsafe extern "C" fn lr_babel_codec_encode_authenticated(
    codec: crate::babel_codec::lr_babel_codec_t,
    frame: crate::babel::lr_babel_frame_t,
    pseudo_header: lr_babel_pseudo_header_t,
    key: lr_babel_mac_key_t,
    counter: lr_babel_packet_counter_t,
    out: *mut lr_bytes_t,
) -> i32 {
    guarded(
        || unsafe {
            let Some(codec_ref) = crate::babel_codec::borrow_codec(codec) else {
                return LR_ERR_NULL;
            };
            let Some(frame_ref) = crate::babel::borrow_frame(frame) else {
                return LR_ERR_NULL;
            };
            let Some(ph) = borrow_ph(pseudo_header) else {
                return LR_ERR_NULL;
            };
            let Some(k) = borrow_key(key) else {
                return LR_ERR_NULL;
            };
            let Some(c) = borrow_counter_mut(counter) else {
                return LR_ERR_NULL;
            };
            if out.is_null() {
                return LR_ERR_NULL;
            }
            match codec_ref.encode_authenticated(frame_ref, *ph, k, c) {
                Ok(bytes) => {
                    unsafe { *out = lr_bytes_t::from_vec(bytes) }
                    0
                }
                Err(e) => {
                    set_last_error(e.to_string());
                    err_code(&e)
                }
            }
        },
        LR_ERR_PANIC,
    )
}

#[no_mangle]
pub unsafe extern "C" fn lr_babel_codec_decode_authenticated_slice(
    codec: crate::babel_codec::lr_babel_codec_t,
    packet: *const u8,
    len: usize,
    pseudo_header: lr_babel_pseudo_header_t,
    keys: *const lr_babel_mac_key_t,
    keys_count: usize,
    replay: lr_babel_replay_protection_t,
    out: *mut crate::babel::lr_babel_frame_t,
) -> i32 {
    guarded(
        || unsafe {
            if packet.is_null() && len != 0 {
                return LR_ERR_NULL;
            }
            let packet_slice = if len == 0 {
                &[][..]
            } else {
                unsafe { std::slice::from_raw_parts(packet, len) }
            };
            let Some(ph) = borrow_ph(pseudo_header) else {
                return LR_ERR_NULL;
            };
            let keys_handles: &[lr_babel_mac_key_t] = if keys_count == 0 {
                &[]
            } else {
                unsafe { std::slice::from_raw_parts(keys, keys_count) }
            };
            let mut key_vec: Vec<BabelMacKey> = Vec::with_capacity(keys_handles.len());
            for kh in keys_handles {
                let Some(k) = borrow_key(*kh) else {
                    return LR_ERR_INVALID_HANDLE;
                };
                key_vec.push(k.clone());
            }
            let Some(rp) = borrow_rp_mut(replay) else {
                return LR_ERR_NULL;
            };
            if out.is_null() {
                return LR_ERR_NULL;
            }
            let Some(codec_obj) = crate::babel_codec::borrow_codec_mut(codec) else {
                return LR_ERR_NULL;
            };
            match codec_obj.decode_authenticated_slice(packet_slice, *ph, &key_vec, rp) {
                Ok(Some(frame)) => {
                    unsafe { *out = crate::babel::box_frame(frame) }
                    0
                }
                Ok(None) => {
                    set_last_error("decode_authenticated_slice: truncated".into());
                    LrError::Codec as i32
                }
                Err(e) => {
                    set_last_error(e.to_string());
                    err_code(&e)
                }
            }
        },
        LR_ERR_PANIC,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn ffi_mac_key_hmac_sha256() {
        let secret = b"0123456789abcdef";
        let k = unsafe { lr_babel_mac_key_hmac_sha256(secret.as_ptr(), secret.len()) };
        assert!(!k.is_null());
        assert_eq!(
            unsafe { lr_babel_mac_key_algorithm(k) },
            LR_BABEL_MAC_HMAC_SHA256
        );
        assert_eq!(unsafe { lr_babel_mac_key_digest_len(k) }, 32);
        unsafe { lr_babel_mac_key_free(k) };
    }
    #[test]
    fn ffi_mac_key_blake2s128() {
        let secret = b"0123456789abcdef0123";
        let k = unsafe { lr_babel_mac_key_blake2s128(secret.as_ptr(), secret.len()) };
        assert!(!k.is_null());
        assert_eq!(unsafe { lr_babel_mac_key_digest_len(k) }, 16);
        unsafe { lr_babel_mac_key_free(k) };
    }
    #[test]
    fn ffi_pseudo_header_v4_encode() {
        let src = [10, 0, 0, 1];
        let dst = [10, 0, 0, 2];
        let ph = unsafe { lr_babel_pseudo_header_new_v4(src.as_ptr(), 6666, dst.as_ptr(), 6666) };
        let mut out = lr_bytes_t {
            ptr: std::ptr::null_mut(),
            len: 0,
            cap: 0,
        };
        assert_eq!(
            unsafe { lr_babel_pseudo_header_encode(ph, &raw mut out) },
            0
        );
        assert_eq!(out.len, 12);
        unsafe {
            lr_babel_pseudo_header_free(ph);
            crate::bytes::lr_bytes_free(&raw mut out);
        }
    }
    #[test]
    fn ffi_packet_counter_round_trip() {
        let index = b"index-1";
        let c = unsafe { lr_babel_packet_counter_new(index.as_ptr(), index.len(), 0) };
        assert!(!c.is_null());
        assert_eq!(unsafe { lr_babel_packet_counter_peek_counter(c) }, 0);
        assert_eq!(
            unsafe { lr_babel_packet_counter_peek_index_len(c) },
            index.len()
        );
        unsafe { lr_babel_packet_counter_free(c) };
    }
    #[test]
    fn ffi_replay_protection_accept() {
        let rp = lr_babel_replay_protection_new();
        let index = b"peer-A";
        assert_eq!(
            unsafe { lr_babel_replay_protection_accept(rp, index.as_ptr(), index.len(), 100) },
            1
        );
        assert_eq!(
            unsafe { lr_babel_replay_protection_accept(rp, index.as_ptr(), index.len(), 100) },
            0
        );
        assert_eq!(
            unsafe { lr_babel_replay_protection_accept(rp, index.as_ptr(), index.len(), 101) },
            1
        );
        unsafe { lr_babel_replay_protection_free(rp) };
    }
    #[test]
    fn ffi_free_handles_null() {
        unsafe {
            lr_babel_mac_key_free(std::ptr::null_mut());
            lr_babel_pseudo_header_free(std::ptr::null_mut());
            lr_babel_packet_counter_free(std::ptr::null_mut());
            lr_babel_replay_protection_free(std::ptr::null_mut());
        }
    }
    #[test]
    fn ffi_encode_decode_round_trip() {
        use lr_babel::codec::BabelCodec;
        use lr_babel::{BabelFrame, Tlv};
        let frame = BabelFrame {
            body: vec![Tlv::pad1()],
        };
        let mut codec = BabelCodec::new();
        let secret = b"0123456789abcdef";
        let key = BabelMacKey::hmac_sha256(secret.to_vec());
        let index = b"index-1".to_vec();
        let mut counter = BabelPacketCounter::new(index.clone(), 0).expect("counter");
        let ph = BabelPseudoHeader {
            source: lr_core::addr::IpAddr::V4([10, 0, 0, 1]),
            source_port: 6666,
            destination: lr_core::addr::IpAddr::V4([10, 0, 0, 2]),
            destination_port: 6666,
        };
        let authed = codec
            .encode_authenticated(&frame, ph, &key, &mut counter)
            .expect("encode");
        assert!(!authed.is_empty());
        let mut replay = BabelReplayProtection::default();
        let decoded = codec
            .decode_authenticated_slice(&authed, ph, std::slice::from_ref(&key), &mut replay)
            .expect("decode");
        assert!(decoded.is_some());
    }
}
