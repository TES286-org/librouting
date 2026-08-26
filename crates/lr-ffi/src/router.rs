//! Router lifecycle — `lr_router_new`, `lr_router_destroy`, `lr_router_tick`,
//! `lr_router_add_session`, `lr_router_feed_input`, `lr_router_drain_output`,
//! `lr_router_poll_events`.

use lr_core::addr::{Asn, RouterId};
use lr_core::time::Instant;
use lr_router::{DefaultRouter, RouterInstance, SessionConfig, SessionHandle, SessionKind};

use crate::error::set_last_error;
use crate::handle::{box_router, lock_router, lr_bytes_t, lr_router_t, unbox_router};

/// Create a new router instance.
#[no_mangle]
pub extern "C" fn lr_router_new() -> lr_router_t {
    box_router(DefaultRouter::new())
}

/// Destroy a router instance. Safe to call with NULL.
///
/// # Safety
/// `r` must have been returned by `lr_router_new` and not yet destroyed.
#[no_mangle]
pub unsafe extern "C" fn lr_router_destroy(r: lr_router_t) {
    unsafe { unbox_router(r) }
}

/// Add a BGP session. Returns 0 on success, negative on error. The session
/// handle is written to `out_handle`.
#[no_mangle]
pub extern "C" fn lr_router_add_bgp_session(
    r: lr_router_t,
    local_as: u32,
    peer_as: u32,
    local_bgp_id: u32,
    hold_time: u16,
    keepalive: u16,
    asn4: u8,
    out_handle: *mut u64,
) -> i32 {
    let mut router = match unsafe { lock_router(r) } {
        Some(g) => g,
        None => return -1,
    };
    let cfg = SessionConfig {
        kind: SessionKind::Bgp,
        local_as: Asn(local_as),
        peer_as: Asn(peer_as),
        local_bgp_id: RouterId::from_u32(local_bgp_id),
        hold_time,
        keepalive,
        asn4: asn4 != 0,
        mp_families: Vec::new(),
    };
    match router.add_session(cfg) {
        Ok(h) => {
            if !out_handle.is_null() {
                unsafe { *out_handle = h.0 }
            }
            0
        }
        Err(e) => {
            set_last_error(e);
            -3
        }
    }
}

/// Push bytes from the peer transport into a session.
///
/// # Safety
/// `bytes` must be a valid pointer to `len` bytes.
#[no_mangle]
pub unsafe extern "C" fn lr_router_feed_input(
    r: lr_router_t,
    session: u64,
    bytes: *const u8,
    len: usize,
) -> i32 {
    if bytes.is_null() {
        return -1;
    }
    let mut router = match unsafe { lock_router(r) } {
        Some(g) => g,
        None => return -2,
    };
    let slice = unsafe { std::slice::from_raw_parts(bytes, len) };
    match router.feed_input(SessionHandle(session), slice) {
        Ok(_) => 0,
        Err(e) => {
            set_last_error(e);
            -3
        }
    }
}

/// Drain bytes from a session to send to the peer transport.
///
/// # Safety
/// `out` must point to a valid `lr_bytes_t` slot.
#[no_mangle]
pub unsafe extern "C" fn lr_router_drain_output(
    r: lr_router_t,
    session: u64,
    out: *mut lr_bytes_t,
) -> i32 {
    if out.is_null() {
        return -1;
    }
    let mut router = match unsafe { lock_router(r) } {
        Some(g) => g,
        None => return -2,
    };
    let bytes = router.drain_output(SessionHandle(session));
    unsafe { *out = lr_bytes_t::from_vec(bytes) }
    0
}

/// Advance the router clock.
#[no_mangle]
pub extern "C" fn lr_router_tick(r: lr_router_t, now_ms: u64) -> i32 {
    let mut router = match unsafe { lock_router(r) } {
        Some(g) => g,
        None => return -2,
    };
    router.tick(Instant(now_ms));
    0
}

/// Start a BGP session (no-op placeholder; FSM is driven by tick/feed).
#[no_mangle]
pub extern "C" fn lr_router_start_session(r: lr_router_t, session: u64) -> i32 {
    let _router = match unsafe { lock_router(r) } {
        Some(g) => g,
        None => return -2,
    };
    let _ = session;
    0
}
