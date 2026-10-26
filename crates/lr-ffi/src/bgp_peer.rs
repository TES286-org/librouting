//! BGP peer FSM FFI (RFC 4271 §8).
//!
//! Mirrors the public Rust API of `lr_bgp::fsm::{BgpPeer, BgpState,
//! BgpEvent, BgpAction}` and `lr_bgp::peer::PeerConfig` so an
//! embedder can drive a single BGP peer FSM without going through
//! the daemon's `DefaultRouter`. The BGP FSM was previously
//! invisible across the C ABI at the FSM granularity — only the
//! stateless codec (`lr_bgp_decode` / `lr_bgp_encode_*`) was
//! exposed.
//!
//! # Surface
//!
//! - `lr_bgp_peer_new` — construct a `BgpPeer` from (local_as,
//!   peer_as, local_bgp_id, hold_time, keepalive, asn4). Returns an
//!   opaque boxed handle.
//! - `lr_bgp_peer_free` — drop the handle (safe on NULL).
//! - `lr_bgp_peer_state` — read the current FSM state as one of the
//!   `LR_BGP_STATE_*` constants.
//! - `lr_bgp_peer_is_established` — 1 when the peer is in Established.
//! - `lr_bgp_peer_peer_bgp_id` — read the negotiated peer BGP id
//!   (returns 1/0 for presence; the id is written to `*out`).
//! - `lr_bgp_peer_peer_as` — read the negotiated peer AS.
//! - `lr_bgp_peer_negotiated_hold_time` — read the negotiated hold
//!   time (seconds).
//! - `lr_bgp_peer_feed_bytes` — feed inbound wire bytes into the
//!   peer's stream-decoder; the resulting outbound bytes are
//!   appended to the peer's drain buffer (use
//!   `lr_bgp_peer_drain_outgoing` to read them).
//! - `lr_bgp_peer_drain_outgoing` — drain the peer's outbound byte
//!   buffer (returns `lr_bytes_t` the caller frees via
//!   `lr_bytes_free`).
//! - `lr_bgp_peer_step_manual_start` / `_manual_stop` /
//!   `_transport_open` / `_transport_close` / `_timer_connect_retry`
//!   / `_timer_hold_expired` / `_timer_keepalive` / `_timer_idle_hold`
//!   — drive the FSM with one of the named events. Outbound bytes /
//!   timer actions accumulate; use `lr_bgp_peer_drain_outgoing` to
//!   read them.
//!
//! Every entry point runs inside the crate's `catch_unwind` barrier
//! ([`crate::guarded`]): a panic returns `LR_ERR_PANIC` and sets the
//! thread-local last-error string.

#![allow(unused_unsafe)]

use lr_bgp::fsm::{BgpEvent, BgpPeer, BgpState};
use lr_bgp::peer::PeerConfig;
use lr_core::addr::{Asn, RouterId};

use crate::error::{LrError, LR_ERR_PANIC};
use crate::guarded;
use crate::handle::lr_bytes_t;

const LR_ERR_NULL: i32 = LrError::Null as i32;

// ---- BGP state constants (mirrors BgpState enum) ----

pub const LR_BGP_STATE_IDLE: i32 = 1;
pub const LR_BGP_STATE_CONNECT: i32 = 2;
pub const LR_BGP_STATE_ACTIVE: i32 = 3;
pub const LR_BGP_STATE_OPEN_SENT: i32 = 4;
pub const LR_BGP_STATE_OPEN_CONFIRM: i32 = 5;
pub const LR_BGP_STATE_ESTABLISHED: i32 = 6;

fn bgp_state_to_i32(s: BgpState) -> i32 {
    match s {
        BgpState::Idle => LR_BGP_STATE_IDLE,
        BgpState::Connect => LR_BGP_STATE_CONNECT,
        BgpState::Active => LR_BGP_STATE_ACTIVE,
        BgpState::OpenSent => LR_BGP_STATE_OPEN_SENT,
        BgpState::OpenConfirm => LR_BGP_STATE_OPEN_CONFIRM,
        BgpState::Established => LR_BGP_STATE_ESTABLISHED,
    }
}

// ---- Opaque handle type ----

#[repr(C)]
pub struct OpaqueBgpPeer {
    _private: [u8; 0],
}
pub type lr_bgp_peer_t = *mut OpaqueBgpPeer;

fn box_peer(p: BgpPeer) -> lr_bgp_peer_t {
    Box::into_raw(Box::new(p)) as lr_bgp_peer_t
}
unsafe fn borrow_peer_mut(r: lr_bgp_peer_t) -> Option<&'static mut BgpPeer> {
    if r.is_null() {
        return None;
    }
    Some(unsafe { &mut *(r as *mut BgpPeer) })
}
unsafe fn borrow_peer(r: lr_bgp_peer_t) -> Option<&'static BgpPeer> {
    if r.is_null() {
        return None;
    }
    Some(unsafe { &*(r as *const BgpPeer) })
}
unsafe fn unbox_peer(r: lr_bgp_peer_t) -> Option<Box<BgpPeer>> {
    if r.is_null() {
        return None;
    }
    Some(unsafe { Box::from_raw(r as *mut BgpPeer) })
}

// ---- BgpPeer surface ----

/// Construct a `BgpPeer` from the BGP-4 mandatory parameters (RFC
/// 4271 §4.2, §8). Returns NULL on a panic.
///
/// `local_bgp_id` is the 32-bit BGP identifier (network byte order
/// is irrelevant — the value is stored as a `u32` and the codec
/// writes it big-endian on the wire).
///
/// `hold_time` is the seconds the peer proposes for the hold timer;
/// 0 means "use the negotiated default (90 s)".
/// `keepalive` is the seconds the peer proposes for the keepalive
/// timer; 0 means "use hold_time / 3".
/// `asn4` selects RFC 6793 four-octet-AS support.
#[no_mangle]
pub extern "C" fn lr_bgp_peer_new(
    local_as: u32,
    peer_as: u32,
    local_bgp_id: u32,
    hold_time: u16,
    keepalive: u16,
    asn4: u8,
) -> lr_bgp_peer_t {
    guarded(
        || {
            let mut cfg = PeerConfig::new(
                Asn::new(local_as),
                Asn::new(peer_as),
                RouterId::from_u32(local_bgp_id),
            );
            cfg.hold_time = if hold_time == 0 { 90 } else { hold_time };
            cfg.keepalive = if keepalive == 0 {
                cfg.hold_time / 3
            } else {
                keepalive
            };
            cfg.asn4 = asn4 != 0;
            box_peer(BgpPeer::new(cfg))
        },
        std::ptr::null_mut(),
    )
}

/// Drop a boxed BgpPeer. Safe to call with NULL.
///
/// # Safety
/// `r` must have been produced by `lr_bgp_peer_new` and not already freed.
#[no_mangle]
pub unsafe extern "C" fn lr_bgp_peer_free(r: lr_bgp_peer_t) {
    guarded(
        || unsafe {
            drop(unbox_peer(r));
        },
        (),
    )
}

/// Read the current FSM state. Returns 0 on a NULL handle.
///
/// # Safety
/// `r` must be a valid BgpPeer handle.
#[no_mangle]
pub unsafe extern "C" fn lr_bgp_peer_state(r: lr_bgp_peer_t) -> i32 {
    guarded(
        || unsafe {
            borrow_peer(r)
                .map(|p| bgp_state_to_i32(p.state()))
                .unwrap_or(0)
        },
        0,
    )
}

/// 1 when the peer is in Established state, 0 otherwise. Returns 0 on
/// a NULL handle.
///
/// # Safety
/// See [`lr_bgp_peer_state`].
#[no_mangle]
pub unsafe extern "C" fn lr_bgp_peer_is_established(r: lr_bgp_peer_t) -> u8 {
    guarded(
        || unsafe {
            borrow_peer(r)
                .map(|p| p.is_established() as u8)
                .unwrap_or(0)
        },
        0,
    )
}

/// Read the peer's BGP identifier (post-OPEN). Returns 1 when the
/// peer has advertised a BGP id; 0 when no OPEN has been received
/// yet (in which case `*out` is left unchanged).
///
/// # Safety
/// `r` must be a valid BgpPeer handle. `out` must point to writable
/// `uint32_t`.
#[no_mangle]
pub unsafe extern "C" fn lr_bgp_peer_peer_bgp_id(r: lr_bgp_peer_t, out: *mut u32) -> i32 {
    guarded(
        || unsafe {
            if out.is_null() {
                return LR_ERR_NULL;
            }
            let Some(p) = borrow_peer(r) else {
                return LR_ERR_NULL;
            };
            match p.peer_bgp_id() {
                None => 0,
                Some(id) => {
                    unsafe { *out = id.as_u32() }
                    1
                }
            }
        },
        LR_ERR_PANIC,
    )
}

/// Read the peer's AS (post-OPEN). Returns 1 when the peer has
/// advertised an AS; 0 when no OPEN has been received yet.
///
/// # Safety
/// See [`lr_bgp_peer_peer_bgp_id`].
#[no_mangle]
pub unsafe extern "C" fn lr_bgp_peer_peer_as(r: lr_bgp_peer_t, out: *mut u32) -> i32 {
    guarded(
        || unsafe {
            if out.is_null() {
                return LR_ERR_NULL;
            }
            let Some(p) = borrow_peer(r) else {
                return LR_ERR_NULL;
            };
            match p.peer_as() {
                None => 0,
                Some(asn) => {
                    unsafe { *out = asn.as_u32() }
                    1
                }
            }
        },
        LR_ERR_PANIC,
    )
}

/// Read the negotiated hold time (seconds). Returns 0 on a NULL
/// handle or when negotiation has not completed.
///
/// # Safety
/// See [`lr_bgp_peer_state`].
#[no_mangle]
pub unsafe extern "C" fn lr_bgp_peer_negotiated_hold_time(r: lr_bgp_peer_t) -> u16 {
    guarded(
        || unsafe {
            borrow_peer(r)
                .map(|p| p.negotiated_hold_time())
                .unwrap_or(0)
        },
        0,
    )
}

/// Feed inbound wire bytes into the peer's stream-decoder. The
/// resulting outbound bytes (OPEN / KEEPALIVE / UPDATE /
/// NOTIFICATION responses) are appended to the peer's drain buffer
/// — use [`lr_bgp_peer_drain_outgoing`] to read them.
///
/// Returns 0 on success, `LR_ERR_NULL` on a NULL handle, -5
/// (`LR_ERR_CODEC`) on a parse error (the last-error string is set).
///
/// # Safety
/// `r` must be a valid BgpPeer handle. `data` must point to `len`
/// readable bytes.
#[no_mangle]
pub unsafe extern "C" fn lr_bgp_peer_feed_bytes(
    r: lr_bgp_peer_t,
    data: *const u8,
    len: usize,
) -> i32 {
    guarded(
        || unsafe {
            let Some(p) = borrow_peer_mut(r) else {
                return LR_ERR_NULL;
            };
            if data.is_null() && len != 0 {
                return LR_ERR_NULL;
            }
            let slice = if len == 0 {
                &[]
            } else {
                unsafe { std::slice::from_raw_parts(data, len) }
            };
            match p.feed_bytes(slice) {
                Ok(_actions) => 0,
                Err(e) => {
                    crate::error::set_last_error(format!("{:?}", e));
                    LrError::Codec as i32
                }
            }
        },
        LR_ERR_PANIC,
    )
}

/// Drain the peer's outbound byte buffer. Returns 0 on success and
/// writes a freshly-allocated `lr_bytes_t` to `*out`. The caller
/// frees it via `lr_bytes_free`.
///
/// # Safety
/// `r` must be a valid BgpPeer handle. `out` must point to writable
/// memory.
#[no_mangle]
pub unsafe extern "C" fn lr_bgp_peer_drain_outgoing(r: lr_bgp_peer_t, out: *mut lr_bytes_t) -> i32 {
    guarded(
        || unsafe {
            if out.is_null() {
                return LR_ERR_NULL;
            }
            let Some(p) = borrow_peer_mut(r) else {
                return LR_ERR_NULL;
            };
            let bytes = p.drain_outgoing();
            unsafe { *out = lr_bytes_t::from_vec(bytes) }
            0
        },
        LR_ERR_PANIC,
    )
}

// ---- FSM event drivers ----
//
// Each `lr_bgp_peer_step_*` function drives the FSM with one of the
// named events (RFC 4271 §8.1.2). The resulting BgpAction Vec is
// dropped — the side effects the embedder cares about (outbound
// bytes, timer arms) accumulate inside the peer and are read back
// via `lr_bgp_peer_drain_outgoing` and the negotiated-state readers.

/// Drive the FSM with `ManualStart` (RFC 4271 §8.1.2).
///
/// # Safety
/// `r` must be a valid BgpPeer handle.
#[no_mangle]
pub unsafe extern "C" fn lr_bgp_peer_step_manual_start(r: lr_bgp_peer_t) -> i32 {
    guarded(
        || unsafe {
            let Some(p) = borrow_peer_mut(r) else {
                return LR_ERR_NULL;
            };
            let _ = p.step(BgpEvent::ManualStart);
            0
        },
        LR_ERR_PANIC,
    )
}

/// Drive the FSM with `ManualStop` (RFC 4271 §8.1.2).
///
/// # Safety
/// See [`lr_bgp_peer_step_manual_start`].
#[no_mangle]
pub unsafe extern "C" fn lr_bgp_peer_step_manual_stop(r: lr_bgp_peer_t) -> i32 {
    guarded(
        || unsafe {
            let Some(p) = borrow_peer_mut(r) else {
                return LR_ERR_NULL;
            };
            let _ = p.step(BgpEvent::ManualStop);
            0
        },
        LR_ERR_PANIC,
    )
}

/// Drive the FSM with `TransportOpen` (RFC 4271 §8.1.2).
///
/// # Safety
/// See [`lr_bgp_peer_step_manual_start`].
#[no_mangle]
pub unsafe extern "C" fn lr_bgp_peer_step_transport_open(r: lr_bgp_peer_t) -> i32 {
    guarded(
        || unsafe {
            let Some(p) = borrow_peer_mut(r) else {
                return LR_ERR_NULL;
            };
            let _ = p.step(BgpEvent::TransportOpen);
            0
        },
        LR_ERR_PANIC,
    )
}

/// Drive the FSM with `TransportFatal` (RFC 4271 §8.1.2).
///
/// # Safety
/// See [`lr_bgp_peer_step_manual_start`].
#[no_mangle]
pub unsafe extern "C" fn lr_bgp_peer_step_transport_fatal(r: lr_bgp_peer_t) -> i32 {
    guarded(
        || unsafe {
            let Some(p) = borrow_peer_mut(r) else {
                return LR_ERR_NULL;
            };
            let _ = p.step(BgpEvent::TransportFatal);
            0
        },
        LR_ERR_PANIC,
    )
}

/// Drive the FSM with `TransportClose` (RFC 4271 §8.1.2).
///
/// # Safety
/// See [`lr_bgp_peer_step_manual_start`].
#[no_mangle]
pub unsafe extern "C" fn lr_bgp_peer_step_transport_close(r: lr_bgp_peer_t) -> i32 {
    guarded(
        || unsafe {
            let Some(p) = borrow_peer_mut(r) else {
                return LR_ERR_NULL;
            };
            let _ = p.step(BgpEvent::TransportClose);
            0
        },
        LR_ERR_PANIC,
    )
}

/// Drive the FSM with `TimerConnectRetry` (RFC 4271 §8.1.3).
///
/// # Safety
/// See [`lr_bgp_peer_step_manual_start`].
#[no_mangle]
pub unsafe extern "C" fn lr_bgp_peer_step_timer_connect_retry(r: lr_bgp_peer_t) -> i32 {
    guarded(
        || unsafe {
            let Some(p) = borrow_peer_mut(r) else {
                return LR_ERR_NULL;
            };
            let _ = p.step(BgpEvent::TimerConnectRetry);
            0
        },
        LR_ERR_PANIC,
    )
}

/// Drive the FSM with `TimerHoldExpired` (RFC 4271 §8.1.3).
///
/// # Safety
/// See [`lr_bgp_peer_step_manual_start`].
#[no_mangle]
pub unsafe extern "C" fn lr_bgp_peer_step_timer_hold_expired(r: lr_bgp_peer_t) -> i32 {
    guarded(
        || unsafe {
            let Some(p) = borrow_peer_mut(r) else {
                return LR_ERR_NULL;
            };
            let _ = p.step(BgpEvent::TimerHoldExpired);
            0
        },
        LR_ERR_PANIC,
    )
}

/// Drive the FSM with `TimerKeepalive` (RFC 4271 §8.1.3).
///
/// # Safety
/// See [`lr_bgp_peer_step_manual_start`].
#[no_mangle]
pub unsafe extern "C" fn lr_bgp_peer_step_timer_keepalive(r: lr_bgp_peer_t) -> i32 {
    guarded(
        || unsafe {
            let Some(p) = borrow_peer_mut(r) else {
                return LR_ERR_NULL;
            };
            let _ = p.step(BgpEvent::TimerKeepalive);
            0
        },
        LR_ERR_PANIC,
    )
}

/// Drive the FSM with `TimerIdleHold` (RFC 4271 §8.1.3).
///
/// # Safety
/// See [`lr_bgp_peer_step_manual_start`].
#[no_mangle]
pub unsafe extern "C" fn lr_bgp_peer_step_timer_idle_hold(r: lr_bgp_peer_t) -> i32 {
    guarded(
        || unsafe {
            let Some(p) = borrow_peer_mut(r) else {
                return LR_ERR_NULL;
            };
            let _ = p.step(BgpEvent::TimerIdleHold);
            0
        },
        LR_ERR_PANIC,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ffi_bgp_peer_new_and_state() {
        let p = lr_bgp_peer_new(64512, 64513, 0x0a000001, 90, 30, 1);
        assert!(!p.is_null());
        // A fresh peer is in Idle.
        assert_eq!(unsafe { lr_bgp_peer_state(p) }, LR_BGP_STATE_IDLE);
        assert_eq!(unsafe { lr_bgp_peer_is_established(p) }, 0);

        // No OPEN received yet — peer_bgp_id returns 0 (absent).
        let mut id = 0u32;
        let rc = unsafe { lr_bgp_peer_peer_bgp_id(p, &raw mut id) };
        assert_eq!(rc, 0);

        unsafe { lr_bgp_peer_free(p) };
    }

    #[test]
    fn ffi_bgp_peer_manual_start_transitions_to_connect() {
        let p = lr_bgp_peer_new(64512, 64513, 0x0a000001, 90, 30, 1);
        // ManualStart on an Idle peer transitions to Connect (RFC 4271
        // §8.1.2 — the peer initiates a TCP connect).
        let rc = unsafe { lr_bgp_peer_step_manual_start(p) };
        assert_eq!(rc, 0);
        assert_eq!(unsafe { lr_bgp_peer_state(p) }, LR_BGP_STATE_CONNECT);

        // The peer should have queued an outbound OPEN (and possibly a
        // KEEPALIVE). Drain it and check the bytes are non-empty.
        let mut out = lr_bytes_t {
            ptr: std::ptr::null_mut(),
            len: 0,
            cap: 0,
        };
        let rc = unsafe { lr_bgp_peer_drain_outgoing(p, &raw mut out) };
        assert_eq!(rc, 0);
        // The peer emits an OPEN once a transport is opened. Without
        // a TransportOpen event the queue may be empty — that is also
        // a valid outcome.
        if !out.ptr.is_null() {
            unsafe { crate::bytes::lr_bytes_free(&raw mut out) };
        }

        unsafe { lr_bgp_peer_free(p) };
    }

    #[test]
    fn ffi_bgp_peer_handles_null_safely() {
        assert_eq!(unsafe { lr_bgp_peer_state(std::ptr::null_mut()) }, 0);
        assert_eq!(
            unsafe { lr_bgp_peer_is_established(std::ptr::null_mut()) },
            0
        );
        assert_eq!(
            unsafe { lr_bgp_peer_negotiated_hold_time(std::ptr::null_mut()) },
            0
        );
        unsafe { lr_bgp_peer_free(std::ptr::null_mut()) };
    }

    #[test]
    fn ffi_bgp_peer_feed_bytes_rejects_null_handle() {
        let rc = unsafe { lr_bgp_peer_feed_bytes(std::ptr::null_mut(), std::ptr::null(), 0) };
        assert_eq!(rc, LR_ERR_NULL);
    }
}
