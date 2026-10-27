//! BMP (RFC 7854) wire codec FFI.
//!
//! Stateless. Mirrors the public Rust API of `lr_bmp::{BmpCodec,
//! BmpMessage, BmpHeader, PeerHeader, BmpMsgType, PeerType, PeerFlags,
//! PeerDownReason}` so an embedder can build, inspect and round-trip
//! BMP messages without going through the Rust compiler.
//!
//! # Surface
//!
//! - `lr_bmp_decode` — decode one BMP message, return an opaque handle.
//! - `lr_bmp_encode` — encode a message to wire bytes.
//! - `lr_bmp_message_route_monitoring` / `_peer_up` / `_peer_down` /
//!   `_initiation` / `_termination` — message constructors.
//! - `lr_bmp_message_*` readers: msg_type, peer_present, peer_type,
//!   peer_flags, peer_distinguisher, peer_address (v4/v6), peer_as,
//!   peer_bgp_id, payload.
//! - `lr_bmp_message_free` — drop the boxed message.
//!
//! Every entry point runs inside the crate's `catch_unwind` barrier
//! ([`crate::guarded`]): a panic returns `LR_ERR_PANIC` and sets the
//! thread-local last-error string.

// The closure body passed to `guarded` is wrapped in a single `unsafe`
// block to mirror the `pub unsafe extern "C" fn` shape — the inner
// `unsafe { ... }` blocks would otherwise trip `unused_unsafe` under
// the crate's `-D warnings` clippy gate.
#![allow(unused_unsafe)]

use lr_bmp::{
    BmpCodec, BmpMessage, BmpMsgType, PeerDownReason, PeerFlags, PeerHeader, PeerType, VERSION,
};
use lr_core::buf::WriteBuf;
use lr_core::codec::Encoder;

use crate::error::{set_last_error, LrError, LR_ERR_PANIC};
use crate::guarded;
use crate::handle::lr_bytes_t;

const LR_ERR_NULL: i32 = LrError::Null as i32;
const LR_ERR_OTHER: i32 = LrError::Other as i32;

/// Opaque `BmpMessage` handle.
#[repr(C)]
pub struct OpaqueBmpMessage {
    _private: [u8; 0],
}

pub type lr_bmp_message_t = *mut OpaqueBmpMessage;

pub(crate) fn box_message(m: BmpMessage) -> lr_bmp_message_t {
    Box::into_raw(Box::new(m)) as lr_bmp_message_t
}

/// Reclaim a message handle.
///
/// # Safety
/// `m` must have been produced by [`box_message`] and not freed.
unsafe fn unbox_message(m: lr_bmp_message_t) -> Option<Box<BmpMessage>> {
    if m.is_null() {
        return None;
    }
    Some(unsafe { Box::from_raw(m as *mut BmpMessage) })
}

/// Borrow a message handle as `&BmpMessage` for read-only access.
///
/// # Safety
/// `m` must have been produced by [`box_message`] and not be freed while
/// the returned reference is live.
unsafe fn borrow_message(m: lr_bmp_message_t) -> Option<&'static BmpMessage> {
    if m.is_null() {
        return None;
    }
    Some(unsafe { &*(m as *const BmpMessage) })
}

// ---- Constants (mirrors lr_bmp pub consts) ----

pub const LR_BMP_VERSION: u8 = VERSION;
pub const LR_BMP_MSG_ROUTE_MONITORING: u8 = BmpMsgType::RouteMonitoring as u8;
pub const LR_BMP_MSG_STATISTICS_REPORT: u8 = BmpMsgType::StatisticsReport as u8;
pub const LR_BMP_MSG_PEER_DOWN: u8 = BmpMsgType::PeerDown as u8;
pub const LR_BMP_MSG_PEER_UP: u8 = BmpMsgType::PeerUp as u8;
pub const LR_BMP_MSG_INITIATION: u8 = BmpMsgType::Initiation as u8;
pub const LR_BMP_MSG_TERMINATION: u8 = BmpMsgType::Termination as u8;
pub const LR_BMP_MSG_ROUTE_MIRRORING: u8 = BmpMsgType::RouteMirroring as u8;

pub const LR_BMP_PEER_TYPE_GLOBAL: u8 = PeerType::Global as u8;
pub const LR_BMP_PEER_TYPE_RD: u8 = PeerType::Rd as u8;
pub const LR_BMP_PEER_TYPE_LOCAL: u8 = PeerType::Local as u8;

pub const LR_BMP_PEER_FLAG_V: u8 = 0x80; // IPv6 address
pub const LR_BMP_PEER_FLAG_L: u8 = 0x40; // post-policy
pub const LR_BMP_PEER_FLAG_A: u8 = 0x20; // legacy AS_PATH

/// One BMP peer header (RFC 7854 §4.2). Mirrors `lr_bmp::PeerHeader`.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct lr_bmp_peer_header_t {
    pub peer_type: u8,
    pub peer_flags: u8,
    pub peer_distinguisher: u64,
    /// Always 16 bytes; v4 occupies the last 4 (RFC 7854 §4.2).
    pub peer_address: [u8; 16],
    pub peer_as: u32,
    pub peer_bgp_id: u32,
    pub timestamp_secs: u32,
    pub timestamp_fraction: u32,
}

impl From<&PeerHeader> for lr_bmp_peer_header_t {
    fn from(p: &PeerHeader) -> Self {
        Self {
            peer_type: p.peer_type as u8,
            peer_flags: p.peer_flags.0,
            peer_distinguisher: p.peer_distinguisher,
            peer_address: p.peer_address,
            peer_as: p.peer_as,
            peer_bgp_id: p.peer_bgp_id,
            timestamp_secs: p.timestamp_secs,
            timestamp_fraction: p.timestamp_fraction,
        }
    }
}

// ---- Decode / encode ----

/// Decode one BMP message from `data`. On success, writes a freshly-
/// allocated `lr_bmp_message_t` to `*out`.
///
/// # Safety
/// `data` must point to `len` readable bytes. `out` must point to a
/// writable `lr_bmp_message_t`.
#[no_mangle]
pub unsafe extern "C" fn lr_bmp_decode(
    data: *const u8,
    len: usize,
    out: *mut lr_bmp_message_t,
) -> i32 {
    guarded(
        || unsafe {
            if data.is_null() || out.is_null() {
                return LR_ERR_NULL;
            }
            let slice = unsafe { std::slice::from_raw_parts(data, len) };
            let mut codec = BmpCodec::new();
            match codec.decode_slice(slice) {
                Ok(Some(m)) => {
                    unsafe { *out = box_message(m) }
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

/// Encode a `lr_bmp_message_t` to its wire form.
///
/// # Safety
/// `message` must be a valid handle. `out` must point to a writable
/// `lr_bytes_t`.
#[no_mangle]
pub unsafe extern "C" fn lr_bmp_encode(message: lr_bmp_message_t, out: *mut lr_bytes_t) -> i32 {
    guarded(
        || unsafe {
            let Some(m) = borrow_message(message) else {
                return LR_ERR_NULL;
            };
            if out.is_null() {
                return LR_ERR_NULL;
            }
            let codec = BmpCodec::new();
            // BMP messages can be large (Route Monitoring carries a full
            // BGP UPDATE); 65k + slack is the practical cap.
            let mut buf = vec![0u8; 65_535 + 256];
            let mut wb = WriteBuf::new(&mut buf);
            match codec.encode(m, &mut wb) {
                Ok(n) => {
                    let bytes: Vec<u8> = buf[..n].to_vec();
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

// ---- Constructors ----

/// Build a Route Monitoring message (type 0) wrapping a BGP UPDATE.
/// `peer` MUST be non-NULL — Route Monitoring always carries a peer
/// header (RFC 7854 §4.3).
///
/// # Safety
/// `peer` must point to a `lr_bmp_peer_header_t`. `bgp_update` must
/// point to `bgp_len` readable bytes.
#[no_mangle]
pub unsafe extern "C" fn lr_bmp_message_route_monitoring(
    peer: *const lr_bmp_peer_header_t,
    bgp_update: *const u8,
    bgp_len: usize,
) -> lr_bmp_message_t {
    guarded(
        || unsafe {
            if peer.is_null() {
                return std::ptr::null_mut();
            }
            let peer = to_rust_peer_header(&*peer);
            let update = if bgp_update.is_null() || bgp_len == 0 {
                Vec::new()
            } else {
                unsafe { std::slice::from_raw_parts(bgp_update, bgp_len) }.to_vec()
            };
            box_message(BmpMessage::route_monitoring(peer, update.as_slice()))
        },
        std::ptr::null_mut(),
    )
}

/// Build a Termination message (type 5). The `info` argument is a flat
/// array of `lr_bmp_tlv_t` (type + value pointer); pass NULL for an
/// empty TLV list.
///
/// # Safety
/// `info` must point to `count` readable `lr_bmp_tlv_t` entries; each
/// `value` pointer inside must point to `value_len` readable bytes.
#[no_mangle]
pub unsafe extern "C" fn lr_bmp_message_termination(
    info: *const lr_bmp_tlv_t,
    count: usize,
) -> lr_bmp_message_t {
    guarded(
        || unsafe {
            let info_vec: Vec<(u16, Vec<u8>)> = if info.is_null() || count == 0 {
                Vec::new()
            } else {
                let slice = unsafe { std::slice::from_raw_parts(info, count) };
                slice
                    .iter()
                    .map(|t| {
                        let value = if t.value.is_null() || t.value_len == 0 {
                            Vec::new()
                        } else {
                            unsafe { std::slice::from_raw_parts(t.value, t.value_len) }.to_vec()
                        };
                        (t.tlv_type, value)
                    })
                    .collect()
            };
            let info_refs: Vec<(u16, &[u8])> =
                info_vec.iter().map(|(t, v)| (*t, v.as_slice())).collect();
            box_message(BmpMessage::termination(&info_refs))
        },
        std::ptr::null_mut(),
    )
}

/// Build an Initiation message (type 4). Same TLV shape as Termination.
///
/// # Safety
/// See [`lr_bmp_message_termination`].
#[no_mangle]
pub unsafe extern "C" fn lr_bmp_message_initiation(
    info: *const lr_bmp_tlv_t,
    count: usize,
) -> lr_bmp_message_t {
    guarded(
        || unsafe {
            let info_vec: Vec<(u16, Vec<u8>)> = if info.is_null() || count == 0 {
                Vec::new()
            } else {
                let slice = unsafe { std::slice::from_raw_parts(info, count) };
                slice
                    .iter()
                    .map(|t| {
                        let value = if t.value.is_null() || t.value_len == 0 {
                            Vec::new()
                        } else {
                            unsafe { std::slice::from_raw_parts(t.value, t.value_len) }.to_vec()
                        };
                        (t.tlv_type, value)
                    })
                    .collect()
            };
            let info_refs: Vec<(u16, &[u8])> =
                info_vec.iter().map(|(t, v)| (*t, v.as_slice())).collect();
            box_message(BmpMessage::initiation(&info_refs))
        },
        std::ptr::null_mut(),
    )
}

/// One BMP TLV (RFC 7854 §4.7/§4.8) used by the Initiation and
/// Termination constructors. The `value` pointer is borrowed for the
/// duration of the constructor call only — the constructor copies the
/// bytes into the message payload.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct lr_bmp_tlv_t {
    pub tlv_type: u16,
    pub value: *const u8,
    pub value_len: usize,
}

/// Build a Peer Down message (type 2). `reason` is one of the
/// `LR_BMP_PEER_DOWN_*` constants (1=LocalClose, 2=RemoteClose,
/// 3=RemoteNotification, 4=DepletedResource, 5=AdminReset); values
/// outside that range are clamped to LocalClose. `peer` MUST be
/// non-NULL. `data` is the optional reason-specific payload (NULL when
/// `data_len == 0`).
///
/// # Safety
/// `peer` must point to a `lr_bmp_peer_header_t`. `data` must point to
/// `data_len` readable bytes.
#[no_mangle]
pub unsafe extern "C" fn lr_bmp_message_peer_down(
    peer: *const lr_bmp_peer_header_t,
    reason: u8,
    data: *const u8,
    data_len: usize,
) -> lr_bmp_message_t {
    guarded(
        || unsafe {
            if peer.is_null() {
                return std::ptr::null_mut();
            }
            let peer = to_rust_peer_header(&*peer);
            let data_vec = if data.is_null() || data_len == 0 {
                Vec::new()
            } else {
                unsafe { std::slice::from_raw_parts(data, data_len) }.to_vec()
            };
            let r = match reason {
                1 => PeerDownReason::LocalClose,
                2 => PeerDownReason::RemoteClose,
                3 => PeerDownReason::RemoteNotification,
                4 => PeerDownReason::DepletedResource,
                5 => PeerDownReason::AdminReset,
                _ => PeerDownReason::LocalClose,
            };
            box_message(BmpMessage::peer_down(peer, r, data_vec.as_slice()))
        },
        std::ptr::null_mut(),
    )
}

/// Build a Peer Up message (type 3). The four BGP message bodies are
/// passed as flat byte slices; any may be NULL/0-length.
///
/// # Safety
/// `peer` MUST point to a `lr_bmp_peer_header_t`. Each `*_msg` pointer
/// must point to its matching `*_len` readable bytes.
#[no_mangle]
pub unsafe extern "C" fn lr_bmp_message_peer_up(
    peer: *const lr_bmp_peer_header_t,
    local_addr: *const u8,
    local_addr_len: usize,
    local_port: u16,
    remote_port: u16,
    sent_open: *const u8,
    sent_open_len: usize,
    received_open: *const u8,
    received_open_len: usize,
) -> lr_bmp_message_t {
    guarded(
        || unsafe {
            if peer.is_null() {
                return std::ptr::null_mut();
            }
            let peer = to_rust_peer_header(&*peer);
            // local_addr is always 16 bytes per RFC 7854 §4.6 — but the
            // FFI accepts whatever the caller passes (zero-padded if
            // shorter). Build a fixed-size 16-byte array.
            let mut local_addr_buf = [0u8; 16];
            if !local_addr.is_null() && local_addr_len > 0 {
                let take = local_addr_len.min(16);
                let src = unsafe { std::slice::from_raw_parts(local_addr, take) };
                local_addr_buf[..take].copy_from_slice(src);
            }
            let sent_open_slice = if sent_open.is_null() || sent_open_len == 0 {
                Vec::new()
            } else {
                unsafe { std::slice::from_raw_parts(sent_open, sent_open_len) }.to_vec()
            };
            let received_open_slice = if received_open.is_null() || received_open_len == 0 {
                Vec::new()
            } else {
                unsafe { std::slice::from_raw_parts(received_open, received_open_len) }.to_vec()
            };
            box_message(BmpMessage::peer_up(
                peer,
                local_addr_buf,
                local_port,
                remote_port,
                sent_open_slice.as_slice(),
                received_open_slice.as_slice(),
            ))
        },
        std::ptr::null_mut(),
    )
}

// ---- Readers ----

/// Read the message type (`LR_BMP_MSG_*`).
///
/// # Safety
/// `message` must be a valid handle.
#[no_mangle]
pub unsafe extern "C" fn lr_bmp_message_type(message: lr_bmp_message_t) -> u8 {
    guarded(
        || unsafe {
            borrow_message(message)
                .map(|m| m.header.msg_type as u8)
                .unwrap_or(0)
        },
        0,
    )
}

/// 1 when the message carries a Peer Header, 0 otherwise (Initiation
/// and Termination carry no peer header).
///
/// # Safety
/// `message` must be a valid handle.
#[no_mangle]
pub unsafe extern "C" fn lr_bmp_message_peer_present(message: lr_bmp_message_t) -> u8 {
    guarded(
        || unsafe {
            borrow_message(message)
                .map(|m| m.peer.is_some() as u8)
                .unwrap_or(0)
        },
        0,
    )
}

/// Copy the Peer Header into `*out` when one is present. Returns 0 on
/// success, `LR_ERR_NULL` on a NULL handle, `LR_ERR_INVALID_HANDLE`
/// (-2) when the message has no peer header.
///
/// # Safety
/// `message` must be a valid handle. `out` must point to a writable
/// `lr_bmp_peer_header_t`.
#[no_mangle]
pub unsafe extern "C" fn lr_bmp_message_peer_header(
    message: lr_bmp_message_t,
    out: *mut lr_bmp_peer_header_t,
) -> i32 {
    guarded(
        || unsafe {
            let Some(m) = borrow_message(message) else {
                return LR_ERR_NULL;
            };
            if out.is_null() {
                return LR_ERR_NULL;
            }
            let Some(peer) = m.peer.as_ref() else {
                return LrError::InvalidHandle as i32;
            };
            unsafe { *out = lr_bmp_peer_header_t::from(peer) }
            0
        },
        LR_ERR_PANIC,
    )
}

/// Read the payload length (bytes). The payload bytes themselves are
/// accessed via [`lr_bmp_message_payload`].
///
/// # Safety
/// `message` must be a valid handle.
#[no_mangle]
pub unsafe extern "C" fn lr_bmp_message_payload_len(message: lr_bmp_message_t) -> usize {
    guarded(
        || unsafe {
            borrow_message(message)
                .map(|m| m.payload.len())
                .unwrap_or(0)
        },
        0,
    )
}

/// Copy the payload into a freshly-allocated `lr_bytes_t`. The caller
/// owns the bytes and must free them with `lr_bytes_free`.
///
/// # Safety
/// `message` must be a valid handle. `out` must point to a writable
/// `lr_bytes_t`.
#[no_mangle]
pub unsafe extern "C" fn lr_bmp_message_payload(
    message: lr_bmp_message_t,
    out: *mut lr_bytes_t,
) -> i32 {
    guarded(
        || unsafe {
            let Some(m) = borrow_message(message) else {
                return LR_ERR_NULL;
            };
            if out.is_null() {
                return LR_ERR_NULL;
            }
            unsafe { *out = lr_bytes_t::from_vec(m.payload.clone()) }
            0
        },
        LR_ERR_PANIC,
    )
}

/// Drop a boxed `BmpMessage`. Safe to call with NULL.
///
/// # Safety
/// `message` must have been produced by a `lr_bmp_message_*`
/// constructor and must not be used after this call.
#[no_mangle]
pub unsafe extern "C" fn lr_bmp_message_free(message: lr_bmp_message_t) {
    guarded(
        || unsafe {
            drop(unbox_message(message));
        },
        (),
    )
}

// ---- Helpers ----

fn to_rust_peer_header(p: &lr_bmp_peer_header_t) -> PeerHeader {
    PeerHeader {
        peer_type: match p.peer_type {
            1 => PeerType::Rd,
            2 => PeerType::Local,
            _ => PeerType::Global,
        },
        peer_flags: PeerFlags(p.peer_flags),
        peer_distinguisher: p.peer_distinguisher,
        peer_address: p.peer_address,
        peer_as: p.peer_as,
        peer_bgp_id: p.peer_bgp_id,
        timestamp_secs: p.timestamp_secs,
        timestamp_fraction: p.timestamp_fraction,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn ffi_termination_roundtrip() {
        let m = unsafe { lr_bmp_message_termination(std::ptr::null(), 0) };
        assert!(!m.is_null());
        unsafe {
            assert_eq!(lr_bmp_message_type(m), LR_BMP_MSG_TERMINATION);
            assert_eq!(lr_bmp_message_peer_present(m), 0);
            assert_eq!(lr_bmp_message_payload_len(m), 0);

            let mut out = lr_bytes_t {
                ptr: std::ptr::null_mut(),
                len: 0,
                cap: 0,
            };
            assert_eq!(lr_bmp_encode(m, &raw mut out), 0);
            let bytes = bytes_to_vec(&mut out);
            assert!(bytes.len() >= 6); // 6-byte BMP header minimum.

            let mut dec: lr_bmp_message_t = std::ptr::null_mut();
            assert_eq!(lr_bmp_decode(bytes.as_ptr(), bytes.len(), &raw mut dec), 0);
            assert!(!dec.is_null());
            assert_eq!(lr_bmp_message_type(dec), LR_BMP_MSG_TERMINATION);
            lr_bmp_message_free(dec);
            lr_bmp_message_free(m);
        }
    }

    #[test]
    fn ffi_initiation_roundtrip_with_tlv() {
        let val = b"router1.example.com".to_vec();
        let mut tlv = lr_bmp_tlv_t {
            tlv_type: 0, // STRING
            value: val.as_ptr(),
            value_len: val.len(),
        };
        let m = unsafe { lr_bmp_message_initiation(&tlv, 1) };
        assert!(!m.is_null());
        unsafe {
            assert_eq!(lr_bmp_message_type(m), LR_BMP_MSG_INITIATION);
            assert_eq!(lr_bmp_message_peer_present(m), 0);
            assert!(lr_bmp_message_payload_len(m) > 0);
            lr_bmp_message_free(m);
        }
        drop(val);
        let _ = &mut tlv;
    }

    #[test]
    fn ffi_route_monitoring_with_peer() {
        let peer = lr_bmp_peer_header_t {
            peer_type: LR_BMP_PEER_TYPE_GLOBAL,
            peer_flags: 0,
            peer_distinguisher: 0,
            peer_address: [0; 16],
            peer_as: 64512,
            peer_bgp_id: 0x0a000001,
            timestamp_secs: 1_700_000_000,
            timestamp_fraction: 0,
        };
        let update = [0xffu8; 19]; // marker
        let m = unsafe { lr_bmp_message_route_monitoring(&peer, update.as_ptr(), update.len()) };
        assert!(!m.is_null());
        unsafe {
            assert_eq!(lr_bmp_message_type(m), LR_BMP_MSG_ROUTE_MONITORING);
            assert_eq!(lr_bmp_message_peer_present(m), 1);

            let mut out_peer = lr_bmp_peer_header_t::default();
            assert_eq!(lr_bmp_message_peer_header(m, &raw mut out_peer), 0);
            assert_eq!(out_peer.peer_as, 64512);
            assert_eq!(out_peer.peer_bgp_id, 0x0a000001);

            let mut payload = lr_bytes_t {
                ptr: std::ptr::null_mut(),
                len: 0,
                cap: 0,
            };
            assert_eq!(lr_bmp_message_payload(m, &raw mut payload), 0);
            assert_eq!(bytes_to_vec(&mut payload), update.to_vec());

            lr_bmp_message_free(m);
        }
    }

    #[test]
    fn ffi_peer_header_returns_invalid_handle_for_initiation() {
        let m = unsafe { lr_bmp_message_termination(std::ptr::null(), 0) };
        let mut out = lr_bmp_peer_header_t::default();
        let rc = unsafe { lr_bmp_message_peer_header(m, &raw mut out) };
        assert_eq!(rc, LrError::InvalidHandle as i32);
        unsafe { lr_bmp_message_free(m) };
    }

    #[test]
    fn ffi_decode_rejects_null_input() {
        let mut dec: lr_bmp_message_t = std::ptr::null_mut();
        let rc = unsafe { lr_bmp_decode(std::ptr::null(), 0, &raw mut dec) };
        assert_eq!(rc, LR_ERR_NULL);
    }

    #[test]
    fn ffi_decode_rejects_too_short() {
        let bytes = [0u8; 3];
        let mut dec: lr_bmp_message_t = std::ptr::null_mut();
        let rc = unsafe { lr_bmp_decode(bytes.as_ptr(), bytes.len(), &raw mut dec) };
        assert!(rc < 0);
        assert!(dec.is_null());
    }

    #[test]
    fn ffi_free_handles_null_safely() {
        unsafe { lr_bmp_message_free(std::ptr::null_mut()) };
    }

    #[test]
    fn ffi_message_type_returns_zero_on_null() {
        assert_eq!(unsafe { lr_bmp_message_type(std::ptr::null_mut()) }, 0);
    }

    #[test]
    fn ffi_constants_match_rfc_7854() {
        assert_eq!(LR_BMP_VERSION, 3);
        assert_eq!(LR_BMP_MSG_ROUTE_MONITORING, 0);
        assert_eq!(LR_BMP_MSG_STATISTICS_REPORT, 1);
        assert_eq!(LR_BMP_MSG_PEER_DOWN, 2);
        assert_eq!(LR_BMP_MSG_PEER_UP, 3);
        assert_eq!(LR_BMP_MSG_INITIATION, 4);
        assert_eq!(LR_BMP_MSG_TERMINATION, 5);
        assert_eq!(LR_BMP_MSG_ROUTE_MIRRORING, 6);
    }

    #[test]
    fn ffi_peer_up_roundtrip() {
        let peer = lr_bmp_peer_header_t {
            peer_type: LR_BMP_PEER_TYPE_GLOBAL,
            peer_flags: 0,
            peer_distinguisher: 0,
            peer_address: [0; 16],
            peer_as: 64512,
            peer_bgp_id: 0x0a000001,
            timestamp_secs: 1_700_000_000,
            timestamp_fraction: 0,
        };
        let local_addr = [10u8, 0, 0, 1];
        let sent_open = [0xffu8; 29];
        let received_open = [0xffu8; 29];
        let m = unsafe {
            lr_bmp_message_peer_up(
                &peer,
                local_addr.as_ptr(),
                local_addr.len(),
                179,
                179,
                sent_open.as_ptr(),
                sent_open.len(),
                received_open.as_ptr(),
                received_open.len(),
            )
        };
        assert!(!m.is_null());
        unsafe {
            assert_eq!(lr_bmp_message_type(m), LR_BMP_MSG_PEER_UP);
            assert_eq!(lr_bmp_message_peer_present(m), 1);
            lr_bmp_message_free(m);
        }
    }

    #[test]
    fn ffi_peer_down_roundtrip() {
        let peer = lr_bmp_peer_header_t {
            peer_type: LR_BMP_PEER_TYPE_GLOBAL,
            peer_flags: 0,
            peer_distinguisher: 0,
            peer_address: [0; 16],
            peer_as: 64512,
            peer_bgp_id: 0x0a000001,
            timestamp_secs: 1_700_000_000,
            timestamp_fraction: 0,
        };
        let data = [1u8, 2, 3]; // reason-specific payload
        let m = unsafe { lr_bmp_message_peer_down(&peer, 1, data.as_ptr(), data.len()) };
        assert!(!m.is_null());
        unsafe {
            assert_eq!(lr_bmp_message_type(m), LR_BMP_MSG_PEER_DOWN);
            assert_eq!(lr_bmp_message_peer_present(m), 1);
            lr_bmp_message_free(m);
        }
    }
}
