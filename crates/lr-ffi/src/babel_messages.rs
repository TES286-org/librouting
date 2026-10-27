//! Babel message TLV bodies (RFC 8966 §4.6).
//!
//! Mirrors the public Rust API of `lr_babel::message::{Hello, Ihu,
//! RouterId, NextHop, Update, RouteRequest, SeqnoRequest, AckReq,
//! Ack}`. Each message is a typed view over the raw TLV body bytes —
//! the codec lives in `lr_babel::tlv::{Tlv, TlvType}` and is already
//! exposed via the `lr_babel_frame_*` FFI; this module adds the
//! structured per-message-type constructors, readers and encoders so
//! a C embedder can build / inspect a single Babel TLV without going
//! through the codec.

#![allow(unused_unsafe)]
#![allow(unused_imports)]
#![allow(dead_code)]

use lr_babel::message::{Ack, AckReq, Hello, Ihu, NextHop, RouteRequest, RouterId, SeqnoRequest};

use crate::error::{set_last_error, LrError, LR_ERR_PANIC};
use crate::guarded;
use crate::handle::lr_bytes_t;

const LR_ERR_NULL: i32 = LrError::Null as i32;
const LR_ERR_OTHER: i32 = LrError::Other as i32;

// ---- Hello ----

/// Opaque `Hello` handle (RFC 8966 §4.6.5).
#[repr(C)]
pub struct OpaqueBabelHello {
    _private: [u8; 0],
}
pub type lr_babel_hello_t = *mut OpaqueBabelHello;

fn box_hello(m: Hello) -> lr_babel_hello_t {
    Box::into_raw(Box::new(m)) as lr_babel_hello_t
}
unsafe fn borrow_hello(h: lr_babel_hello_t) -> Option<&'static Hello> {
    if h.is_null() {
        return None;
    }
    Some(unsafe { &*(h as *const Hello) })
}

/// Construct a `Hello` (RFC 8966 §4.6.5).
#[no_mangle]
pub extern "C" fn lr_babel_hello_new(seqno: u16, interval_cs: u16) -> lr_babel_hello_t {
    guarded(
        || box_hello(Hello::new(seqno, interval_cs)),
        std::ptr::null_mut(),
    )
}

/// Set the Unicast flag (RFC 8966 §4.6.5 — `Hello::UNICAST`).
///
/// # Safety
/// `h` must be a valid handle.
#[no_mangle]
pub unsafe extern "C" fn lr_babel_hello_set_unicast(h: lr_babel_hello_t, on: u8) -> i32 {
    guarded(
        || unsafe {
            if h.is_null() {
                return LR_ERR_NULL;
            }
            let hello = unsafe { &mut *(h as *mut Hello) };
            if on != 0 {
                hello.flags |= Hello::UNICAST;
            } else {
                hello.flags &= !Hello::UNICAST;
            }
            0
        },
        LR_ERR_PANIC,
    )
}

/// Read the seqno.
///
/// # Safety
/// `h` must be a valid handle.
#[no_mangle]
pub unsafe extern "C" fn lr_babel_hello_seqno(h: lr_babel_hello_t) -> u16 {
    guarded(
        || unsafe { borrow_hello(h).map(|x| x.seqno).unwrap_or(0) },
        0,
    )
}

/// Read the interval (centiseconds).
///
/// # Safety
/// `h` must be a valid handle.
#[no_mangle]
pub unsafe extern "C" fn lr_babel_hello_interval_cs(h: lr_babel_hello_t) -> u16 {
    guarded(
        || unsafe { borrow_hello(h).map(|x| x.interval_cs).unwrap_or(0) },
        0,
    )
}

/// Read the flags word (Unicast is bit 0x8000).
///
/// # Safety
/// `h` must be a valid handle.
#[no_mangle]
pub unsafe extern "C" fn lr_babel_hello_flags(h: lr_babel_hello_t) -> u16 {
    guarded(
        || unsafe { borrow_hello(h).map(|x| x.flags).unwrap_or(0) },
        0,
    )
}

/// Read the timestamp (BABEL-RTT). Writes 1 to `*present` and the
/// value to `*ts_us`, or 0 to `*present` when no timestamp is set.
///
/// # Safety
/// `h` must be a valid handle; `present` and `ts_us` must point to
/// writable memory.
#[no_mangle]
pub unsafe extern "C" fn lr_babel_hello_timestamp(
    h: lr_babel_hello_t,
    present: *mut u8,
    ts_us: *mut u32,
) -> i32 {
    guarded(
        || unsafe {
            let Some(hello) = borrow_hello(h) else {
                return LR_ERR_NULL;
            };
            if present.is_null() || ts_us.is_null() {
                return LR_ERR_NULL;
            }
            match hello.timestamp {
                Some(t) => unsafe {
                    *present = 1;
                    *ts_us = t;
                },
                None => unsafe {
                    *present = 0;
                    *ts_us = 0;
                },
            }
            0
        },
        LR_ERR_PANIC,
    )
}

/// Encode the Hello body (RFC 8966 §4.6.5). The caller frees `*out`
/// with [`crate::bytes::lr_bytes_free`].
///
/// # Safety
/// `h` must be a valid handle; `out` must point to writable
/// `lr_bytes_t`.
#[no_mangle]
pub unsafe extern "C" fn lr_babel_hello_encode(h: lr_babel_hello_t, out: *mut lr_bytes_t) -> i32 {
    guarded(
        || unsafe {
            let Some(hello) = borrow_hello(h) else {
                return LR_ERR_NULL;
            };
            if out.is_null() {
                return LR_ERR_NULL;
            }
            let bytes = hello.encode();
            unsafe { *out = lr_bytes_t::from_vec(bytes) }
            0
        },
        LR_ERR_PANIC,
    )
}

/// Drop a boxed `Hello`. Safe to call with `NULL`.
///
/// # Safety
/// `h` must have been produced by [`lr_babel_hello_new`] and not
/// already freed.
#[no_mangle]
pub unsafe extern "C" fn lr_babel_hello_free(h: lr_babel_hello_t) {
    guarded(
        || unsafe {
            if h.is_null() {
                return;
            }
            drop(unsafe { Box::from_raw(h as *mut Hello) });
        },
        (),
    )
}

// ---- Ihu ----

/// Opaque `Ihu` handle (RFC 8966 §4.6.6).
#[repr(C)]
pub struct OpaqueBabelIhu {
    _private: [u8; 0],
}
pub type lr_babel_ihu_t = *mut OpaqueBabelIhu;

fn box_ihu(m: Ihu) -> lr_babel_ihu_t {
    Box::into_raw(Box::new(m)) as lr_babel_ihu_t
}
unsafe fn borrow_ihu(h: lr_babel_ihu_t) -> Option<&'static Ihu> {
    if h.is_null() {
        return None;
    }
    Some(unsafe { &*(h as *const Ihu) })
}

/// Construct an `Ihu` (RFC 8966 §4.6.6).
#[no_mangle]
pub extern "C" fn lr_babel_ihu_new(rxcost: u16, interval_cs: u16) -> lr_babel_ihu_t {
    guarded(
        || box_ihu(Ihu::new(rxcost, interval_cs)),
        std::ptr::null_mut(),
    )
}

/// Read the rxcost.
///
/// # Safety
/// `h` must be a valid handle.
#[no_mangle]
pub unsafe extern "C" fn lr_babel_ihu_rxcost(h: lr_babel_ihu_t) -> u16 {
    guarded(
        || unsafe { borrow_ihu(h).map(|x| x.rxcost).unwrap_or(0) },
        0,
    )
}

/// Read the interval (centiseconds).
///
/// # Safety
/// `h` must be a valid handle.
#[no_mangle]
pub unsafe extern "C" fn lr_babel_ihu_interval_cs(h: lr_babel_ihu_t) -> u16 {
    guarded(
        || unsafe { borrow_ihu(h).map(|x| x.interval_cs).unwrap_or(0) },
        0,
    )
}

/// Read the AE (Address Encoding).
///
/// # Safety
/// `h` must be a valid handle.
#[no_mangle]
pub unsafe extern "C" fn lr_babel_ihu_ae(h: lr_babel_ihu_t) -> u8 {
    guarded(|| unsafe { borrow_ihu(h).map(|x| x.ae).unwrap_or(0) }, 0)
}

/// Read the address as `(is_ipv6, octets_out[16], present_out)`.
/// Writes 1 to `*present` when an address is set, 0 otherwise.
///
/// # Safety
/// `h` must be a valid handle; `octets_out` and `present_out` must
/// point to writable memory.
#[no_mangle]
pub unsafe extern "C" fn lr_babel_ihu_address(
    h: lr_babel_ihu_t,
    octets_out: *mut u8,
    present_out: *mut u8,
) -> i32 {
    guarded(
        || unsafe {
            let Some(ihu) = borrow_ihu(h) else {
                return LR_ERR_NULL;
            };
            if octets_out.is_null() || present_out.is_null() {
                return LR_ERR_NULL;
            }
            match &ihu.address {
                Some(lr_core::addr::IpAddr::V4(b)) => {
                    let mut buf = [0u8; 16];
                    buf[..4].copy_from_slice(b);
                    unsafe {
                        std::ptr::copy_nonoverlapping(buf.as_ptr(), octets_out, 16);
                        *present_out = 1;
                    }
                }
                Some(lr_core::addr::IpAddr::V6(b)) => unsafe {
                    std::ptr::copy_nonoverlapping(b.as_ptr(), octets_out, 16);
                    *present_out = 1;
                },
                None => unsafe {
                    std::ptr::write_bytes(octets_out, 0, 16);
                    *present_out = 0;
                },
            }
            0
        },
        LR_ERR_PANIC,
    )
}

/// Encode the Ihu body (RFC 8966 §4.6.6).
///
/// # Safety
/// `h` must be a valid handle; `out` must point to writable
/// `lr_bytes_t`.
#[no_mangle]
pub unsafe extern "C" fn lr_babel_ihu_encode(h: lr_babel_ihu_t, out: *mut lr_bytes_t) -> i32 {
    guarded(
        || unsafe {
            let Some(ihu) = borrow_ihu(h) else {
                return LR_ERR_NULL;
            };
            if out.is_null() {
                return LR_ERR_NULL;
            }
            let bytes = ihu.encode();
            unsafe { *out = lr_bytes_t::from_vec(bytes) }
            0
        },
        LR_ERR_PANIC,
    )
}

/// Drop a boxed `Ihu`. Safe to call with `NULL`.
///
/// # Safety
/// `h` must have been produced by [`lr_babel_ihu_new`] and not
/// already freed.
#[no_mangle]
pub unsafe extern "C" fn lr_babel_ihu_free(h: lr_babel_ihu_t) {
    guarded(
        || unsafe {
            if h.is_null() {
                return;
            }
            drop(unsafe { Box::from_raw(h as *mut Ihu) });
        },
        (),
    )
}

// ---- RouterId ----

/// Opaque `RouterId` handle (RFC 8966 §4.6.7).
#[repr(C)]
pub struct OpaqueBabelRouterId {
    _private: [u8; 0],
}
pub type lr_babel_router_id_t = *mut OpaqueBabelRouterId;

/// Construct a `RouterId` (RFC 8966 §4.6.7) from the 8-octet value.
///
/// # Safety
/// `bytes` must point to 8 readable bytes.
#[no_mangle]
pub unsafe extern "C" fn lr_babel_router_id_new(bytes: *const u8) -> lr_babel_router_id_t {
    guarded(
        || unsafe {
            if bytes.is_null() {
                return std::ptr::null_mut();
            }
            let mut id = [0u8; 8];
            id.copy_from_slice(unsafe { std::slice::from_raw_parts(bytes, 8) });
            Box::into_raw(Box::new(RouterId { id })) as lr_babel_router_id_t
        },
        std::ptr::null_mut(),
    )
}

/// Read the 8-octet Router-ID into `*out` (must point to 8 writable
/// bytes).
///
/// # Safety
/// `r` must be a valid handle; `out` must point to 8 writable bytes.
#[no_mangle]
pub unsafe extern "C" fn lr_babel_router_id_bytes(r: lr_babel_router_id_t, out: *mut u8) -> i32 {
    guarded(
        || unsafe {
            if r.is_null() || out.is_null() {
                return LR_ERR_NULL;
            }
            let rid: &RouterId = unsafe { &*(r as *const RouterId) };
            let bytes = rid.encode();
            unsafe {
                std::ptr::copy_nonoverlapping(bytes.as_ptr(), out, 10);
            }
            0
        },
        LR_ERR_PANIC,
    )
}

/// Drop a boxed `RouterId`. Safe to call with `NULL`.
///
/// # Safety
/// `r` must have been produced by [`lr_babel_router_id_new`] and not
/// already freed.
#[no_mangle]
pub unsafe extern "C" fn lr_babel_router_id_free(r: lr_babel_router_id_t) {
    guarded(
        || unsafe {
            if r.is_null() {
                return;
            }
            drop(unsafe { Box::from_raw(r as *mut RouterId) });
        },
        (),
    )
}

// ---- AckReq / Ack ----

/// Opaque `AckReq` handle (RFC 8966 §4.6.10).
#[repr(C)]
pub struct OpaqueBabelAckReq {
    _private: [u8; 0],
}
pub type lr_babel_ack_req_t = *mut OpaqueBabelAckReq;

/// Construct an `AckReq` (RFC 8966 §4.6.10).
#[no_mangle]
pub extern "C" fn lr_babel_ack_req_new(nonce: u16, interval_cs: u16) -> lr_babel_ack_req_t {
    guarded(
        || {
            Box::into_raw(Box::new(AckReq {
                opaque: nonce,
                interval_cs,
            })) as lr_babel_ack_req_t
        },
        std::ptr::null_mut(),
    )
}

/// Read the nonce.
///
/// # Safety
/// `a` must be a valid handle.
#[no_mangle]
pub unsafe extern "C" fn lr_babel_ack_req_nonce(a: lr_babel_ack_req_t) -> u16 {
    guarded(
        || unsafe {
            if a.is_null() {
                return 0;
            }
            let req: &AckReq = unsafe { &*(a as *const AckReq) };
            req.opaque
        },
        0,
    )
}

/// Read the interval (centiseconds).
///
/// # Safety
/// `a` must be a valid handle.
#[no_mangle]
pub unsafe extern "C" fn lr_babel_ack_req_interval_cs(a: lr_babel_ack_req_t) -> u16 {
    guarded(
        || unsafe {
            if a.is_null() {
                return 0;
            }
            let req: &AckReq = unsafe { &*(a as *const AckReq) };
            req.interval_cs
        },
        0,
    )
}

/// Drop a boxed `AckReq`. Safe to call with `NULL`.
///
/// # Safety
/// `a` must have been produced by [`lr_babel_ack_req_new`] and not
/// already freed.
#[no_mangle]
pub unsafe extern "C" fn lr_babel_ack_req_free(a: lr_babel_ack_req_t) {
    guarded(
        || unsafe {
            if a.is_null() {
                return;
            }
            drop(unsafe { Box::from_raw(a as *mut AckReq) });
        },
        (),
    )
}

// ---- RouteRequest / SeqnoRequest ----

/// Opaque `RouteRequest` handle (RFC 8966 §4.6.8).
#[repr(C)]
pub struct OpaqueBabelRouteRequest {
    _private: [u8; 0],
}
pub type lr_babel_route_request_t = *mut OpaqueBabelRouteRequest;

/// Construct a wildcard `RouteRequest` (RFC 8966 §4.6.8 — AE=0
/// requests the whole routing table).
#[no_mangle]
pub extern "C" fn lr_babel_route_request_new_wildcard() -> lr_babel_route_request_t {
    guarded(
        || {
            Box::into_raw(Box::new(RouteRequest {
                ae: 0,
                prefix_len: 0,
                prefix: Vec::new(),
            })) as lr_babel_route_request_t
        },
        std::ptr::null_mut(),
    )
}

/// Drop a boxed `RouteRequest`. Safe to call with `NULL`.
///
/// # Safety
/// `r` must have been produced by [`lr_babel_route_request_new_wildcard`]
/// and not already freed.
#[no_mangle]
pub unsafe extern "C" fn lr_babel_route_request_free(r: lr_babel_route_request_t) {
    guarded(
        || unsafe {
            if r.is_null() {
                return;
            }
            drop(unsafe { Box::from_raw(r as *mut RouteRequest) });
        },
        (),
    )
}

/// Opaque `SeqnoRequest` handle (RFC 8966 §4.6.9).
#[repr(C)]
pub struct OpaqueBabelSeqnoRequest {
    _private: [u8; 0],
}
pub type lr_babel_seqno_request_t = *mut OpaqueBabelSeqnoRequest;

/// Construct a `SeqnoRequest` (RFC 8966 §4.6.9).
///
/// # Safety
/// `router_id` must point to 8 readable bytes.
#[no_mangle]
pub unsafe extern "C" fn lr_babel_seqno_request_new(
    prefix_v4: *const u8,
    prefix_v6: *const u8,
    prefix_len: u8,
    seqno: u16,
    router_id: *const u8,
    hop_count: u8,
) -> lr_babel_seqno_request_t {
    guarded(
        || unsafe {
            let addr = if !prefix_v4.is_null() {
                let b = unsafe { std::slice::from_raw_parts(prefix_v4, 4) };
                lr_core::addr::IpAddr::V4([b[0], b[1], b[2], b[3]])
            } else if !prefix_v6.is_null() {
                let b = unsafe { std::slice::from_raw_parts(prefix_v6, 16) };
                let mut octets = [0u8; 16];
                octets.copy_from_slice(b);
                lr_core::addr::IpAddr::V6(octets)
            } else {
                set_last_error("lr_babel_seqno_request_new: both prefix pointers NULL".into());
                return std::ptr::null_mut();
            };
            if router_id.is_null() {
                set_last_error("lr_babel_seqno_request_new: router_id NULL".into());
                return std::ptr::null_mut();
            }
            let mut rid_bytes = [0u8; 8];
            rid_bytes.copy_from_slice(unsafe { std::slice::from_raw_parts(router_id, 8) });
            // AE = 1 for v4, 2 for v6.
            let ae = match addr {
                lr_core::addr::IpAddr::V4(_) => 1u8,
                lr_core::addr::IpAddr::V6(_) => 2u8,
            };
            // Pack prefix octets (truncated to plen bits, RFC 8966
            // §4.6.9 — the prefix's body form is ceil(plen/8) bytes).
            let n = (prefix_len as usize).div_ceil(8);
            let mut prefix = vec![0u8; n];
            match addr {
                lr_core::addr::IpAddr::V4(b) => {
                    prefix[..n.min(4)].copy_from_slice(&b[..n.min(4)]);
                }
                lr_core::addr::IpAddr::V6(b) => {
                    prefix[..n.min(16)].copy_from_slice(&b[..n.min(16)]);
                }
            }
            let req = SeqnoRequest {
                ae,
                prefix_len,
                prefix,
                seqno,
                hop_count,
                router_id: rid_bytes,
            };
            Box::into_raw(Box::new(req)) as lr_babel_seqno_request_t
        },
        std::ptr::null_mut(),
    )
}

/// Drop a boxed `SeqnoRequest`. Safe to call with `NULL`.
///
/// # Safety
/// `r` must have been produced by [`lr_babel_seqno_request_new`] and
/// not already freed.
#[no_mangle]
pub unsafe extern "C" fn lr_babel_seqno_request_free(r: lr_babel_seqno_request_t) {
    guarded(
        || unsafe {
            if r.is_null() {
                return;
            }
            drop(unsafe { Box::from_raw(r as *mut SeqnoRequest) });
        },
        (),
    )
}

// ---- TLV type constants (RFC 8966 §4.6) ----

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
pub const LR_BABEL_TLV_SOURCE_PREFIX_SUBTLV: u8 = 128;

pub const LR_BABEL_HELLO_UNICAST: u16 = 0x8000;
pub const LR_BABEL_SOURCE_PREFIX_SUBTLV: u8 = 128;
pub const LR_BABEL_TIMESTAMP_SUBTLV: u8 = 3;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ffi_hello_new_and_readers() {
        let h = lr_babel_hello_new(42, 100);
        assert!(!h.is_null());
        assert_eq!(unsafe { lr_babel_hello_seqno(h) }, 42);
        assert_eq!(unsafe { lr_babel_hello_interval_cs(h) }, 100);
        assert_eq!(unsafe { lr_babel_hello_flags(h) }, 0);

        let mut present = 0u8;
        let mut ts = 0u32;
        let rc = unsafe { lr_babel_hello_timestamp(h, &raw mut present, &raw mut ts) };
        assert_eq!(rc, 0);
        assert_eq!(present, 0);

        unsafe { lr_babel_hello_free(h) };
    }

    #[test]
    fn ffi_hello_set_unicast() {
        let h = lr_babel_hello_new(1, 100);
        assert_eq!(unsafe { lr_babel_hello_set_unicast(h, 1) }, 0);
        assert_ne!(
            unsafe { lr_babel_hello_flags(h) } & LR_BABEL_HELLO_UNICAST,
            0
        );
        assert_eq!(unsafe { lr_babel_hello_set_unicast(h, 0) }, 0);
        assert_eq!(
            unsafe { lr_babel_hello_flags(h) } & LR_BABEL_HELLO_UNICAST,
            0
        );
        unsafe { lr_babel_hello_free(h) };
    }

    #[test]
    fn ffi_hello_encode() {
        let h = lr_babel_hello_new(42, 100);
        let mut out = lr_bytes_t {
            ptr: std::ptr::null_mut(),
            len: 0,
            cap: 0,
        };
        let rc = unsafe { lr_babel_hello_encode(h, &raw mut out) };
        assert_eq!(rc, 0);
        assert_eq!(out.len, 6); // flags(2) + seqno(2) + interval(2)
        unsafe {
            let v = Vec::from_raw_parts(out.ptr, out.len, out.cap);
            // flags=0, seqno=42 (BE), interval=100 (BE)
            assert_eq!(&v[..], &[0, 0, 0, 42, 0, 100]);
            lr_babel_hello_free(h);
        }
    }

    #[test]
    fn ffi_ihu_new_and_readers() {
        let h = lr_babel_ihu_new(96, 200);
        assert!(!h.is_null());
        assert_eq!(unsafe { lr_babel_ihu_rxcost(h) }, 96);
        assert_eq!(unsafe { lr_babel_ihu_interval_cs(h) }, 200);
        assert_eq!(unsafe { lr_babel_ihu_ae(h) }, 0);
        let mut octets = [0u8; 16];
        let mut present = 0u8;
        let rc = unsafe { lr_babel_ihu_address(h, octets.as_mut_ptr(), &raw mut present) };
        assert_eq!(rc, 0);
        assert_eq!(present, 0);
        unsafe { lr_babel_ihu_free(h) };
    }

    #[test]
    fn ffi_ihu_encode() {
        let h = lr_babel_ihu_new(96, 200);
        let mut out = lr_bytes_t {
            ptr: std::ptr::null_mut(),
            len: 0,
            cap: 0,
        };
        let rc = unsafe { lr_babel_ihu_encode(h, &raw mut out) };
        assert_eq!(rc, 0);
        assert_eq!(out.len, 6); // AE(1) + reserved(1) + rxcost(2) + interval(2)
        unsafe {
            let _ = Vec::from_raw_parts(out.ptr, out.len, out.cap);
            lr_babel_ihu_free(h);
        }
    }

    #[test]
    fn ffi_router_id_new_and_bytes() {
        let bytes_in = [1u8, 2, 3, 4, 5, 6, 7, 8];
        let r = unsafe { lr_babel_router_id_new(bytes_in.as_ptr()) };
        assert!(!r.is_null());
        let mut bytes_out = [0u8; 10];
        let rc = unsafe { lr_babel_router_id_bytes(r, bytes_out.as_mut_ptr()) };
        assert_eq!(rc, 0);
        // RouterId::encode is `Reserved(2) | Router-Id(8)` (RFC 8966
        // §4.6.7) — the first two bytes are reserved (zero), then
        // the 8-byte Router-ID follows.
        assert_eq!(&bytes_out[..2], &[0, 0]);
        assert_eq!(&bytes_out[2..], &bytes_in);
        unsafe { lr_babel_router_id_free(r) };
    }

    #[test]
    fn ffi_ack_req_new_and_readers() {
        let a = lr_babel_ack_req_new(123, 90);
        assert!(!a.is_null());
        assert_eq!(unsafe { lr_babel_ack_req_nonce(a) }, 123);
        assert_eq!(unsafe { lr_babel_ack_req_interval_cs(a) }, 90);
        unsafe { lr_babel_ack_req_free(a) };
    }

    #[test]
    fn ffi_route_request_new_wildcard() {
        let r = lr_babel_route_request_new_wildcard();
        assert!(!r.is_null());
        unsafe { lr_babel_route_request_free(r) };
    }

    #[test]
    fn ffi_seqno_request_new() {
        let prefix = [10u8, 0, 0, 0];
        let router_id = [1u8, 2, 3, 4, 5, 6, 7, 8];
        let r = unsafe {
            lr_babel_seqno_request_new(
                prefix.as_ptr(),
                std::ptr::null(),
                24,
                5,
                router_id.as_ptr(),
                1,
            )
        };
        assert!(!r.is_null());
        unsafe { lr_babel_seqno_request_free(r) };
    }

    #[test]
    fn ffi_seqno_request_new_rejects_null_router_id() {
        let prefix = [10u8, 0, 0, 0];
        let r = unsafe {
            lr_babel_seqno_request_new(
                prefix.as_ptr(),
                std::ptr::null(),
                24,
                5,
                std::ptr::null(),
                1,
            )
        };
        assert!(r.is_null());
    }

    #[test]
    fn ffi_free_handles_null_safely() {
        unsafe {
            lr_babel_hello_free(std::ptr::null_mut());
            lr_babel_ihu_free(std::ptr::null_mut());
            lr_babel_router_id_free(std::ptr::null_mut());
            lr_babel_ack_req_free(std::ptr::null_mut());
            lr_babel_route_request_free(std::ptr::null_mut());
            lr_babel_seqno_request_free(std::ptr::null_mut());
        }
    }
}
