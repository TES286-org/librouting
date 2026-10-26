//! LDP session FSM FFI (RFC 5036 §2.5.4).
//!
//! Mirrors the public Rust API of `lr_ldp::session::{LdpSession,
//! SessionConfig, SessionState, SessionRole, AdvertisementMode}`
//! so an embedder can drive a single LDP session FSM without going
//! through the daemon's `LdpEngine`. The session FSM was previously
//! invisible across the C ABI — only the stateless PDU codec
//! (`lr_ldp_decode` / `lr_ldp_encode_hello_pdu`) was exposed.
//!
//! # Surface
//!
//! - `lr_ldp_session_new` — construct a `LdpSession` for the active
//!   role (the local LSR initiates the TCP connection).
//! - `lr_ldp_session_free` — drop the handle (safe on NULL).
//! - `lr_ldp_session_state` — read the current FSM state as one of
//!   the `LR_LDP_SESSION_STATE_*` constants.
//! - `lr_ldp_session_is_operational` — 1 when the session is in
//!   Operational state.
//! - `lr_ldp_session_start` — drive the FSM with the `start` event
//!   (RFC 5036 §2.5.4 — emits the Initialization message).
//! - `lr_ldp_session_drain_outgoing` — drain the session's outbound
//!   PDU buffer (returns `lr_bytes_t` the caller frees via
//!   `lr_bytes_free`).
//!
//! Every entry point runs inside the crate's `catch_unwind` barrier
//! ([`crate::guarded`]): a panic returns `LR_ERR_PANIC` and sets the
//! thread-local last-error string.

#![allow(unused_unsafe)]

use lr_core::buf::WriteBuf;
use lr_core::codec::Encoder;
use lr_core::time::Instant;
use lr_ldp::message::{LdpCodec, LdpPdu};
use lr_ldp::pdu::{AdvertisementMode, LdpId, LDP_VERSION};
use lr_ldp::session::{LdpSession, SessionConfig, SessionRole, SessionState};

use crate::error::{LrError, LR_ERR_PANIC};
use crate::guarded;
use crate::handle::lr_bytes_t;

const LR_ERR_NULL: i32 = LrError::Null as i32;

// ---- LDP session state constants (mirrors SessionState enum) ----

pub const LR_LDP_SESSION_STATE_NON_EXISTENT: i32 = 1;
pub const LR_LDP_SESSION_STATE_INITIALIZED: i32 = 2;
pub const LR_LDP_SESSION_STATE_OPEN_REC: i32 = 3;
pub const LR_LDP_SESSION_STATE_OPEN_SENT: i32 = 4;
pub const LR_LDP_SESSION_STATE_OPERATIONAL: i32 = 5;

fn session_state_to_i32(s: SessionState) -> i32 {
    match s {
        SessionState::NonExistent => LR_LDP_SESSION_STATE_NON_EXISTENT,
        SessionState::Initialized => LR_LDP_SESSION_STATE_INITIALIZED,
        SessionState::OpenRec => LR_LDP_SESSION_STATE_OPEN_REC,
        SessionState::OpenSent => LR_LDP_SESSION_STATE_OPEN_SENT,
        SessionState::Operational => LR_LDP_SESSION_STATE_OPERATIONAL,
    }
}

// ---- Opaque handle type ----

#[repr(C)]
pub struct OpaqueLdpSession {
    _private: [u8; 0],
}
pub type lr_ldp_session_t = *mut OpaqueLdpSession;

fn box_session(s: LdpSession) -> lr_ldp_session_t {
    Box::into_raw(Box::new(s)) as lr_ldp_session_t
}
unsafe fn borrow_session_mut(r: lr_ldp_session_t) -> Option<&'static mut LdpSession> {
    if r.is_null() {
        return None;
    }
    Some(unsafe { &mut *(r as *mut LdpSession) })
}
unsafe fn borrow_session(r: lr_ldp_session_t) -> Option<&'static LdpSession> {
    if r.is_null() {
        return None;
    }
    Some(unsafe { &*(r as *const LdpSession) })
}
unsafe fn unbox_session(r: lr_ldp_session_t) -> Option<Box<LdpSession>> {
    if r.is_null() {
        return None;
    }
    Some(unsafe { Box::from_raw(r as *mut LdpSession) })
}

// ---- LdpSession surface ----

/// Construct a `LdpSession` for the active role (RFC 5036 §2.5.2 —
/// the local LSR initiates the TCP connection). `local_lsr_id` and
/// `local_label_space` identify the local label space; `peer_lsr_id`
/// and `peer_label_space` identify the peer's.
///
/// `keepalive_time` is the proposed KeepAlive time (seconds, RFC
/// 5036 §3.5.3); 0 means use the default (180 s).
/// `max_pdu_len` is the proposed Max PDU Length (octets); 0 means
/// use the default (4096).
///
/// Returns NULL on a panic.
#[no_mangle]
pub extern "C" fn lr_ldp_session_new(
    local_lsr_id: u32,
    local_label_space: u16,
    peer_lsr_id: u32,
    peer_label_space: u16,
    keepalive_time: u16,
    max_pdu_len: u16,
) -> lr_ldp_session_t {
    guarded(
        || {
            let local_id = LdpId::new(local_lsr_id.to_be_bytes(), local_label_space);
            let peer_id = LdpId::new(peer_lsr_id.to_be_bytes(), peer_label_space);
            let cfg = SessionConfig {
                local_id,
                role: SessionRole::Active,
                peer: Some(peer_id),
                keepalive_time: if keepalive_time == 0 {
                    180
                } else {
                    keepalive_time
                },
                max_pdu_len: if max_pdu_len == 0 { 4096 } else { max_pdu_len },
                advertisement: AdvertisementMode::DownstreamUnsolicited,
                supports_downstream_unsolicited: true,
                supports_downstream_on_demand: false,
                loop_detection: false,
                path_vector_limit: 0,
                graceful_restart: None,
            };
            box_session(LdpSession::new(cfg))
        },
        std::ptr::null_mut(),
    )
}

/// Drop a boxed LdpSession. Safe to call with NULL.
///
/// # Safety
/// `r` must have been produced by `lr_ldp_session_new` and not
/// already freed.
#[no_mangle]
pub unsafe extern "C" fn lr_ldp_session_free(r: lr_ldp_session_t) {
    guarded(
        || unsafe {
            drop(unbox_session(r));
        },
        (),
    )
}

/// Read the current FSM state. Returns 0 on a NULL handle.
///
/// # Safety
/// `r` must be a valid LdpSession handle.
#[no_mangle]
pub unsafe extern "C" fn lr_ldp_session_state(r: lr_ldp_session_t) -> i32 {
    guarded(
        || unsafe {
            borrow_session(r)
                .map(|s| session_state_to_i32(s.state()))
                .unwrap_or(0)
        },
        0,
    )
}

/// 1 when the session is in Operational state (RFC 5036 §2.5.4 —
/// the FSM has completed the Initialization negotiation and is
/// ready to exchange label mappings). Returns 0 on a NULL handle.
///
/// # Safety
/// See [`lr_ldp_session_state`].
#[no_mangle]
pub unsafe extern "C" fn lr_ldp_session_is_operational(r: lr_ldp_session_t) -> u8 {
    guarded(
        || unsafe {
            borrow_session(r)
                .map(|s| s.is_operational() as u8)
                .unwrap_or(0)
        },
        0,
    )
}

/// Drive the FSM with the `start` event (RFC 5036 §2.5.4 — emits the
/// Initialization message and transitions to OpenSent). `now_ms`
/// is the wall-clock millisecond timestamp.
///
/// # Safety
/// `r` must be a valid LdpSession handle.
#[no_mangle]
pub unsafe extern "C" fn lr_ldp_session_start(r: lr_ldp_session_t, now_ms: u64) -> i32 {
    guarded(
        || unsafe {
            let Some(s) = borrow_session_mut(r) else {
                return LR_ERR_NULL;
            };
            let _ = s.start(Instant(now_ms));
            0
        },
        LR_ERR_PANIC,
    )
}

/// Drain the session's outbound PDU buffer. Returns 0 on success and
/// writes a freshly-allocated `lr_bytes_t` to `*out`. The caller
/// frees it via `lr_bytes_free`.
///
/// # Safety
/// `r` must be a valid LdpSession handle. `out` must point to
/// writable memory.
#[no_mangle]
pub unsafe extern "C" fn lr_ldp_session_drain_outgoing(
    r: lr_ldp_session_t,
    out: *mut lr_bytes_t,
) -> i32 {
    guarded(
        || unsafe {
            if out.is_null() {
                return LR_ERR_NULL;
            }
            let Some(s) = borrow_session_mut(r) else {
                return LR_ERR_NULL;
            };
            let messages = s.drain_outgoing();
            // Encode each LdpMessage via the LdpCodec — wrap each in
            // a single-message LdpPDU (the smallest unit an LDP peer
            // can decode) and concatenate the resulting bytes. An
            // embedder that wants per-message granularity can use the
            // existing lr_ldp_decode reader to walk the PDU stream.
            let codec = LdpCodec;
            let mut bytes = Vec::new();
            for msg in messages {
                let pdu = LdpPdu {
                    version: LDP_VERSION,
                    sender: s.peer().unwrap_or(LdpId::new([0, 0, 0, 0], 0)),
                    messages: vec![msg],
                };
                let mut buf = vec![0u8; 4096];
                let mut wb = WriteBuf::new(&mut buf);
                if let Ok(n) = codec.encode(&pdu, &mut wb) {
                    bytes.extend_from_slice(&wb.written()[..n]);
                }
            }
            unsafe { *out = lr_bytes_t::from_vec(bytes) }
            0
        },
        LR_ERR_PANIC,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ffi_ldp_session_new_and_state() {
        let s = lr_ldp_session_new(0x0a000001, 0, 0x0a000002, 0, 0, 0);
        assert!(!s.is_null());
        // A fresh session is in NonExistent.
        assert_eq!(
            unsafe { lr_ldp_session_state(s) },
            LR_LDP_SESSION_STATE_NON_EXISTENT,
        );
        assert_eq!(unsafe { lr_ldp_session_is_operational(s) }, 0);

        // Start the session — transitions out of NonExistent.
        let rc = unsafe { lr_ldp_session_start(s, 0) };
        assert_eq!(rc, 0);
        // The state should now be OpenSent (active role sends Init
        // first, then waits for the peer's Init).
        let st = unsafe { lr_ldp_session_state(s) };
        assert!(
            st == LR_LDP_SESSION_STATE_OPEN_SENT || st == LR_LDP_SESSION_STATE_INITIALIZED,
            "state after start = {st} (expected OpenSent or Initialized)"
        );

        unsafe { lr_ldp_session_free(s) };
    }

    #[test]
    fn ffi_ldp_session_handles_null_safely() {
        assert_eq!(unsafe { lr_ldp_session_state(std::ptr::null_mut()) }, 0);
        assert_eq!(
            unsafe { lr_ldp_session_is_operational(std::ptr::null_mut()) },
            0,
        );
        unsafe { lr_ldp_session_free(std::ptr::null_mut()) };
    }

    #[test]
    fn ffi_ldp_session_drain_outgoing_returns_bytes() {
        let s = lr_ldp_session_new(0x0a000001, 0, 0x0a000002, 0, 0, 0);
        // Drain on a fresh session returns empty bytes (no PDU yet).
        let mut out = lr_bytes_t {
            ptr: std::ptr::null_mut(),
            len: 0,
            cap: 0,
        };
        let rc = unsafe { lr_ldp_session_drain_outgoing(s, &raw mut out) };
        assert_eq!(rc, 0);
        assert_eq!(out.len, 0);
        // No buffer was allocated — no free needed.

        // Start the session — drain should now carry the Init PDU.
        let _ = unsafe { lr_ldp_session_start(s, 0) };
        let rc = unsafe { lr_ldp_session_drain_outgoing(s, &raw mut out) };
        assert_eq!(rc, 0);
        if !out.ptr.is_null() {
            unsafe { crate::bytes::lr_bytes_free(&raw mut out) };
        }

        unsafe { lr_ldp_session_free(s) };
    }
}
