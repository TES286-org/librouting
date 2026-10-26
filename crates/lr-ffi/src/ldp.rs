//! LDP wire codec FFI (RFC 5036).
//!
//! Stateless. Mirrors the public Rust API of `lr_ldp::{LdpId, LdpPdu,
//! LdpCodec, LdpMessage, MessageType}` so an embedder can build, inspect
//! and round-trip the most common LDP messages without going through
//! the Rust compiler.
//!
//! The full LDP engine (sessions, discovery, label-mapping store,
//! transit allocator) lives in `lr_ldp::engine` and is too large to
//! expose in a single FFI round; this module covers the foundational
//! types every LDP speaker needs.
//!
//! Every entry point runs inside the crate's `catch_unwind` barrier
//! ([`crate::guarded`]): a panic returns `LR_ERR_PANIC` and sets the
//! thread-local last-error string.

// The closure body passed to `guarded` is wrapped in a single `unsafe`
// block to mirror the `pub unsafe extern "C" fn` shape — the inner
// `unsafe { ... }` blocks would otherwise trip `unused_unsafe` under
// the crate's `-D warnings` clippy gate.
#![allow(unused_unsafe)]

use lr_core::buf::{ReadBuf, WriteBuf};
use lr_core::codec::{Decoder, Encoder};
use lr_ldp::message::HelloMsg;
use lr_ldp::pdu::{LdpId, LDP_PORT, LDP_VERSION};
use lr_ldp::tlv::HelloParams;
use lr_ldp::{LdpCodec, LdpMessage, LdpPdu};

use crate::error::{set_last_error, LrError, LR_ERR_PANIC};
use crate::guarded;
use crate::handle::lr_bytes_t;

const LR_ERR_NULL: i32 = LrError::Null as i32;
const LR_ERR_OTHER: i32 = LrError::Other as i32;

// ---- Constants (mirrors lr_ldp pub consts) ----

pub const LR_LDP_VERSION: u16 = LDP_VERSION;
pub const LR_LDP_PORT: u16 = LDP_PORT;

// ---- LdpId ----

/// Repr-C LdpId. Mirrors `lr_ldp::pdu::LdpId` (4-byte LSR ID + 2-byte
/// label space).
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct lr_ldp_id_t {
    pub lsr_id: [u8; 4],
    pub label_space: u16,
}

impl From<LdpId> for lr_ldp_id_t {
    fn from(id: LdpId) -> Self {
        Self {
            lsr_id: id.lsr_id,
            label_space: id.label_space,
        }
    }
}

impl From<lr_ldp_id_t> for LdpId {
    fn from(c: lr_ldp_id_t) -> Self {
        Self::new(c.lsr_id, c.label_space)
    }
}

/// Construct an LdpId from 4 LSR-ID bytes + a label-space id.
///
/// # Safety
/// `lsr_id` must point to 4 readable bytes.
#[no_mangle]
pub unsafe extern "C" fn lr_ldp_id_new(lsr_id: *const u8, label_space: u16) -> lr_ldp_id_t {
    guarded(
        || unsafe {
            if lsr_id.is_null() {
                return lr_ldp_id_t::default();
            }
            let mut buf = [0u8; 4];
            let src = unsafe { std::slice::from_raw_parts(lsr_id, 4) };
            buf.copy_from_slice(src);
            LdpId::new(buf, label_space).into()
        },
        lr_ldp_id_t::default(),
    )
}

/// Write the LdpId's 6 wire bytes (LSR ID + label space, big-endian)
/// into `out`. Returns 0 on success.
///
/// # Safety
/// `out` must point to 6 writable bytes.
#[no_mangle]
pub unsafe extern "C" fn lr_ldp_id_to_bytes(id: lr_ldp_id_t, out: *mut u8) -> i32 {
    guarded(
        || unsafe {
            if out.is_null() {
                return LR_ERR_NULL;
            }
            let rust: LdpId = id.into();
            let bytes = rust.as_bytes();
            unsafe {
                std::ptr::copy_nonoverlapping(bytes.as_ptr(), out, 6);
            }
            0
        },
        LR_ERR_PANIC,
    )
}

/// Parse an LdpId from 6 wire bytes.
///
/// # Safety
/// `bytes` must point to 6 readable bytes.
#[no_mangle]
pub unsafe extern "C" fn lr_ldp_id_from_bytes(bytes: *const u8) -> lr_ldp_id_t {
    guarded(
        || unsafe {
            if bytes.is_null() {
                return lr_ldp_id_t::default();
            }
            let slice = unsafe { std::slice::from_raw_parts(bytes, 6) };
            match LdpId::from_bytes(slice) {
                Some(id) => id.into(),
                None => lr_ldp_id_t::default(),
            }
        },
        lr_ldp_id_t::default(),
    )
}

// ---- PDU encode / decode ----

/// Encode an LDP Hello PDU (RFC 5036 §3.5.2) — the most common LDP
/// message used by both link and targeted discovery. The PDU carries
/// one `HelloMsg` with the supplied parameters. The encoded bytes
/// are written to `*out`.
///
/// # Safety
/// `out` must point to a writable `lr_bytes_t`.
#[no_mangle]
pub unsafe extern "C" fn lr_ldp_encode_hello_pdu(
    sender: lr_ldp_id_t,
    message_id: u32,
    hold_time: u16,
    target: u8,
    out: *mut lr_bytes_t,
) -> i32 {
    guarded(
        || unsafe {
            if out.is_null() {
                return LR_ERR_NULL;
            }
            let hello = HelloMsg {
                message_id,
                params: HelloParams {
                    hold_time,
                    targeted: target != 0,
                    request_targeted: false,
                },
                transport_addr: None,
                transport_addr_v6: None,
                config_seq: None,
                dual_stack: None,
                unknown_tlvs: Vec::new(),
            };
            let pdu = LdpPdu {
                version: LDP_VERSION,
                sender: sender.into(),
                messages: vec![LdpMessage::Hello(hello)],
            };
            let codec = LdpCodec;
            let mut buf = vec![0u8; 4096];
            let mut wb = WriteBuf::new(&mut buf);
            match codec.encode(&pdu, &mut wb) {
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

/// Decode one LDP PDU from `data`. On success, writes a freshly-
/// allocated `lr_ldp_pdu_t` to `*out`. Returns 0 on success, negative
/// on error.
///
/// # Safety
/// `data` must point to `len` readable bytes. `out` must point to a
/// writable `lr_ldp_pdu_t`.
#[no_mangle]
pub unsafe extern "C" fn lr_ldp_decode(data: *const u8, len: usize, out: *mut lr_ldp_pdu_t) -> i32 {
    guarded(
        || unsafe {
            if data.is_null() || out.is_null() {
                return LR_ERR_NULL;
            }
            let slice = unsafe { std::slice::from_raw_parts(data, len) };
            let mut codec = LdpCodec;
            let mut r = ReadBuf::new(slice);
            match codec.decode(&mut r) {
                Ok(Some(pdu)) => {
                    unsafe { *out = box_pdu(pdu) }
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

/// Opaque `LdpPdu` handle.
#[repr(C)]
pub struct OpaqueLdpPdu {
    _private: [u8; 0],
}

pub type lr_ldp_pdu_t = *mut OpaqueLdpPdu;

fn box_pdu(p: LdpPdu) -> lr_ldp_pdu_t {
    Box::into_raw(Box::new(p)) as lr_ldp_pdu_t
}

/// Borrow a PDU handle as `&LdpPdu`.
///
/// # Safety
/// `p` must have been produced by [`box_pdu`] and not be freed while
/// the returned reference is live.
unsafe fn borrow_pdu(p: lr_ldp_pdu_t) -> Option<&'static LdpPdu> {
    if p.is_null() {
        return None;
    }
    Some(unsafe { &*(p as *const LdpPdu) })
}

/// Read the PDU's sender LdpId.
///
/// # Safety
/// `pdu` must be a valid handle.
#[no_mangle]
pub unsafe extern "C" fn lr_ldp_pdu_sender(pdu: lr_ldp_pdu_t) -> lr_ldp_id_t {
    guarded(
        || unsafe { borrow_pdu(pdu).map(|p| p.sender.into()).unwrap_or_default() },
        lr_ldp_id_t::default(),
    )
}

/// Read the PDU's version field (always 1 per RFC 5036).
///
/// # Safety
/// `pdu` must be a valid handle.
#[no_mangle]
pub unsafe extern "C" fn lr_ldp_pdu_version(pdu: lr_ldp_pdu_t) -> u16 {
    guarded(
        || unsafe { borrow_pdu(pdu).map(|p| p.version).unwrap_or(0) },
        0,
    )
}

/// Read the number of messages carried by the PDU.
///
/// # Safety
/// `pdu` must be a valid handle.
#[no_mangle]
pub unsafe extern "C" fn lr_ldp_pdu_message_count(pdu: lr_ldp_pdu_t) -> usize {
    guarded(
        || unsafe { borrow_pdu(pdu).map(|p| p.messages.len()).unwrap_or(0) },
        0,
    )
}

/// Read the message-type code of message `index` (one of the
/// `LR_LDP_MSG_*` constants). Returns 0 on a NULL handle or an
/// out-of-range index.
///
/// # Safety
/// `pdu` must be a valid handle.
#[no_mangle]
pub unsafe extern "C" fn lr_ldp_pdu_message_type_at(pdu: lr_ldp_pdu_t, index: usize) -> u16 {
    guarded(
        || unsafe {
            let Some(p) = borrow_pdu(pdu) else {
                return 0;
            };
            p.messages.get(index).map(message_type_code).unwrap_or(0)
        },
        0,
    )
}

/// Read the message-id of message `index`. Returns 0 on a NULL handle
/// or an out-of-range index.
///
/// # Safety
/// `pdu` must be a valid handle.
#[no_mangle]
pub unsafe extern "C" fn lr_ldp_pdu_message_id_at(pdu: lr_ldp_pdu_t, index: usize) -> u32 {
    guarded(
        || unsafe {
            let Some(p) = borrow_pdu(pdu) else {
                return 0;
            };
            p.messages.get(index).map(message_id).unwrap_or(0)
        },
        0,
    )
}

/// Drop a boxed `LdpPdu`. Safe to call with NULL.
///
/// # Safety
/// `pdu` must have been produced by [`lr_ldp_decode`] and must not be
/// used after this call.
#[no_mangle]
pub unsafe extern "C" fn lr_ldp_pdu_free(pdu: lr_ldp_pdu_t) {
    guarded(
        || unsafe {
            if pdu.is_null() {
                return;
            }
            let boxed: Box<LdpPdu> = Box::from_raw(pdu as *mut LdpPdu);
            drop(boxed);
        },
        (),
    )
}

// ---- Message-type constants ----

pub const LR_LDP_MSG_NOTIFICATION: u16 = 0x0001;
pub const LR_LDP_MSG_HELLO: u16 = 0x0100;
pub const LR_LDP_MSG_INITIALIZATION: u16 = 0x0200;
pub const LR_LDP_MSG_KEEPALIVE: u16 = 0x0201;
pub const LR_LDP_MSG_CAPABILITY: u16 = 0x0202;
pub const LR_LDP_MSG_ADDRESS: u16 = 0x0300;
pub const LR_LDP_MSG_ADDRESS_WITHDRAW: u16 = 0x0301;
pub const LR_LDP_MSG_LABEL_MAPPING: u16 = 0x0400;
pub const LR_LDP_MSG_LABEL_REQUEST: u16 = 0x0401;
pub const LR_LDP_MSG_LABEL_WITHDRAW: u16 = 0x0402;
pub const LR_LDP_MSG_LABEL_RELEASE: u16 = 0x0403;
pub const LR_LDP_MSG_LABEL_ABORT: u16 = 0x0404;

fn message_type_code(m: &LdpMessage) -> u16 {
    match m {
        LdpMessage::Notification(_) => LR_LDP_MSG_NOTIFICATION,
        LdpMessage::Hello(_) => LR_LDP_MSG_HELLO,
        LdpMessage::Initialization(_) => LR_LDP_MSG_INITIALIZATION,
        LdpMessage::KeepAlive(_) => LR_LDP_MSG_KEEPALIVE,
        LdpMessage::Address(_) => LR_LDP_MSG_ADDRESS,
        LdpMessage::AddressWithdraw(_) => LR_LDP_MSG_ADDRESS_WITHDRAW,
        LdpMessage::LabelMapping(_) => LR_LDP_MSG_LABEL_MAPPING,
        LdpMessage::LabelRequest(_) => LR_LDP_MSG_LABEL_REQUEST,
        LdpMessage::LabelWithdraw(_) => LR_LDP_MSG_LABEL_WITHDRAW,
        LdpMessage::LabelRelease(_) => LR_LDP_MSG_LABEL_RELEASE,
        LdpMessage::LabelAbortRequest(_) => LR_LDP_MSG_LABEL_ABORT,
        LdpMessage::Unknown(_) => 0,
    }
}

fn message_id(m: &LdpMessage) -> u32 {
    match m {
        LdpMessage::Notification(m) => m.message_id,
        LdpMessage::Hello(m) => m.message_id,
        LdpMessage::Initialization(m) => m.message_id,
        LdpMessage::KeepAlive(m) => m.message_id,
        LdpMessage::Address(m) => m.message_id,
        LdpMessage::AddressWithdraw(m) => m.message_id,
        LdpMessage::LabelMapping(m) => m.message_id,
        LdpMessage::LabelRequest(m) => m.message_id,
        LdpMessage::LabelWithdraw(m) => m.message_id,
        LdpMessage::LabelRelease(m) => m.message_id,
        LdpMessage::LabelAbortRequest(m) => m.message_id,
        LdpMessage::Unknown(_) => 0,
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
    fn ffi_constants_match_rfc_5036() {
        assert_eq!(LR_LDP_VERSION, 1);
        assert_eq!(LR_LDP_PORT, 646);
        assert_eq!(LR_LDP_MSG_NOTIFICATION, 0x0001);
        assert_eq!(LR_LDP_MSG_HELLO, 0x0100);
        assert_eq!(LR_LDP_MSG_INITIALIZATION, 0x0200);
        assert_eq!(LR_LDP_MSG_KEEPALIVE, 0x0201);
        assert_eq!(LR_LDP_MSG_LABEL_MAPPING, 0x0400);
    }

    #[test]
    fn ffi_ldp_id_new_and_to_bytes() {
        let bytes_in = [10u8, 0, 0, 1];
        let id = unsafe { lr_ldp_id_new(bytes_in.as_ptr(), 0) };
        assert_eq!(id.lsr_id, [10, 0, 0, 1]);
        assert_eq!(id.label_space, 0);
        let mut bytes = [0u8; 6];
        unsafe {
            assert_eq!(lr_ldp_id_to_bytes(id, bytes.as_mut_ptr()), 0);
            assert_eq!(bytes, [10, 0, 0, 1, 0, 0]);
        }
    }

    #[test]
    fn ffi_ldp_id_from_bytes() {
        let bytes = [10u8, 0, 0, 1, 0, 5];
        let id = unsafe { lr_ldp_id_from_bytes(bytes.as_ptr()) };
        assert_eq!(id.lsr_id, [10, 0, 0, 1]);
        assert_eq!(id.label_space, 5);
    }

    #[test]
    fn ffi_ldp_id_roundtrip() {
        let bytes_in = [192u8, 168, 1, 1];
        let id = unsafe { lr_ldp_id_new(bytes_in.as_ptr(), 100) };
        let mut bytes = [0u8; 6];
        unsafe {
            assert_eq!(lr_ldp_id_to_bytes(id, bytes.as_mut_ptr()), 0);
            let id2 = lr_ldp_id_from_bytes(bytes.as_ptr());
            assert_eq!(id, id2);
        }
    }

    #[test]
    fn ffi_encode_hello_pdu_roundtrip() {
        let bytes_in = [10u8, 0, 0, 1];
        let sender = unsafe { lr_ldp_id_new(bytes_in.as_ptr(), 0) };
        let mut out = lr_bytes_t {
            ptr: std::ptr::null_mut(),
            len: 0,
            cap: 0,
        };
        let rc = unsafe { lr_ldp_encode_hello_pdu(sender, 0xdeadbeef, 15, 0, &raw mut out) };
        assert_eq!(rc, 0);
        let bytes = unsafe { bytes_to_vec(&mut out) };
        assert!(bytes.len() > 10);

        // Decode back.
        let mut pdu: lr_ldp_pdu_t = std::ptr::null_mut();
        let rc = unsafe { lr_ldp_decode(bytes.as_ptr(), bytes.len(), &raw mut pdu) };
        assert_eq!(rc, 0);
        assert!(!pdu.is_null());
        unsafe {
            assert_eq!(lr_ldp_pdu_version(pdu), LR_LDP_VERSION);
            assert_eq!(lr_ldp_pdu_sender(pdu), sender);
            assert_eq!(lr_ldp_pdu_message_count(pdu), 1);
            assert_eq!(lr_ldp_pdu_message_type_at(pdu, 0), LR_LDP_MSG_HELLO);
            assert_eq!(lr_ldp_pdu_message_id_at(pdu, 0), 0xdeadbeef);
            lr_ldp_pdu_free(pdu);
        }
    }

    #[test]
    fn ffi_decode_rejects_null_input() {
        let mut pdu: lr_ldp_pdu_t = std::ptr::null_mut();
        let rc = unsafe { lr_ldp_decode(std::ptr::null(), 0, &raw mut pdu) };
        assert_eq!(rc, LR_ERR_NULL);
    }

    #[test]
    fn ffi_decode_rejects_too_short() {
        let bytes = [0u8; 5];
        let mut pdu: lr_ldp_pdu_t = std::ptr::null_mut();
        let rc = unsafe { lr_ldp_decode(bytes.as_ptr(), bytes.len(), &raw mut pdu) };
        assert!(rc < 0);
        assert!(pdu.is_null());
    }

    #[test]
    fn ffi_free_handles_null() {
        unsafe { lr_ldp_pdu_free(std::ptr::null_mut()) };
    }

    #[test]
    fn ffi_pdu_message_type_at_returns_zero_for_oob() {
        let bytes_in = [10u8, 0, 0, 1];
        let sender = unsafe { lr_ldp_id_new(bytes_in.as_ptr(), 0) };
        let mut out = lr_bytes_t {
            ptr: std::ptr::null_mut(),
            len: 0,
            cap: 0,
        };
        unsafe {
            lr_ldp_encode_hello_pdu(sender, 1, 15, 0, &raw mut out);
            let bytes = bytes_to_vec(&mut out);
            let mut pdu: lr_ldp_pdu_t = std::ptr::null_mut();
            lr_ldp_decode(bytes.as_ptr(), bytes.len(), &raw mut pdu);
            assert_eq!(lr_ldp_pdu_message_type_at(pdu, 99), 0);
            lr_ldp_pdu_free(pdu);
        }
    }

    #[test]
    fn ffi_pdu_version_returns_zero_on_null() {
        assert_eq!(unsafe { lr_ldp_pdu_version(std::ptr::null_mut()) }, 0);
    }
}
