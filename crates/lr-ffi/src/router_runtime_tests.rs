//! Unit tests for `crates/lr-ffi/src/router_runtime.rs`.
//!
//! Coverage strategy: every new entry point is exercised against a
//! fresh `DefaultRouter` (no protocol handshake) so the tests focus
//! on the FFI shape — null checks, invalid handles, the
//! success/cooldown/no-sample return trichotomy — rather than on
//! reproducing a full BGP/Babel run (those scenarios are already
//! covered by the `lr-router` integration tests).

#![allow(unused_unsafe)]

use super::*;
use crate::error::lr_last_error;
use crate::handle::{box_router, unbox_router};
use lr_router::DefaultRouter;
use std::ffi::CStr;
use std::os::raw::c_char;

fn last_error() -> String {
    unsafe { CStr::from_ptr(lr_last_error()) }
        .to_string_lossy()
        .into_owned()
}

fn fresh_router() -> lr_router_t {
    box_router(DefaultRouter::new())
}

fn drop_router(r: lr_router_t) {
    unsafe { unbox_router(r) };
}

/// Add a BGP session to a fresh router and return its handle.
fn add_bgp(r: lr_router_t) -> u64 {
    let mut h: u64 = 0;
    let rc = unsafe {
        crate::router::lr_router_add_bgp_session(r, 65001, 65002, 0x0102_0304, 90, 30, 1, &mut h)
    };
    assert_eq!(rc, 0, "lr_router_add_bgp_session: {}", last_error());
    h
}

/// Add a Babel session to a fresh router and return its handle.
fn add_babel(r: lr_router_t, want_v6: bool) -> u64 {
    let mut h: u64 = 0;
    let v4 = [192, 0, 2, 1];
    let v6 = [0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
    let (ptr, is_v6) = if want_v6 {
        (v6.as_ptr(), 1)
    } else {
        (v4.as_ptr(), 0)
    };
    let rc = unsafe { crate::sessions::lr_router_add_babel_session(r, ptr, is_v6, &mut h) };
    assert_eq!(rc, 0, "lr_router_add_babel_session: {}", last_error());
    h
}

// ---- session_peer_state -------------------------------------------------

#[test]
fn session_peer_state_returns_static_cstr_for_bgp() {
    let r = fresh_router();
    let h = add_bgp(r);
    let ptr = unsafe { lr_router_session_peer_state(r, h) };
    assert!(
        !ptr.is_null(),
        "BGP session should have a peer state, got NULL"
    );
    let name = unsafe { CStr::from_ptr(ptr as *const c_char) }
        .to_string_lossy()
        .into_owned();
    // A freshly-added BGP session sits at Idle until `start_session`
    // is called; the FSM names match `BgpState::name()` in lr-bgp.
    assert!(
        matches!(
            name.as_str(),
            "Idle" | "Connect" | "Active" | "OpenSent" | "OpenConfirm" | "Established"
        ),
        "unexpected FSM state name {name:?}"
    );
    drop_router(r);
}

#[test]
fn session_peer_state_returns_null_for_babel() {
    let r = fresh_router();
    let h = add_babel(r, true);
    let ptr = unsafe { lr_router_session_peer_state(r, h) };
    assert!(ptr.is_null(), "Babel sessions have no BGP FSM state");
    drop_router(r);
}

#[test]
fn session_peer_state_returns_null_for_unknown_handle() {
    let r = fresh_router();
    let ptr = unsafe { lr_router_session_peer_state(r, 0xFFFF_FFFF) };
    assert!(ptr.is_null(), "unknown session handle should map to NULL");
    drop_router(r);
}

#[test]
fn session_peer_state_returns_null_for_invalid_router() {
    let ptr = unsafe { lr_router_session_peer_state(std::ptr::null_mut(), 0) };
    assert!(ptr.is_null());
}

// ---- session_restart_cooldown_remaining --------------------------------

#[test]
fn restart_cooldown_returns_zero_initially() {
    let r = fresh_router();
    let h = add_bgp(r);
    let mut ms: u64 = 0xDEAD_BEEF;
    let rc = unsafe { lr_router_session_restart_cooldown_remaining(r, h, &mut ms) };
    assert_eq!(rc, 0, "no cooldown has been configured yet");
    // rc 0 means "no cooldown in effect"; the out_ms slot is left
    // untouched by the FFI layer (we do not zero it on the "no
    // cooldown" branch).
    drop_router(r);
}

#[test]
fn restart_cooldown_null_out_is_an_error() {
    let r = fresh_router();
    let h = add_bgp(r);
    let rc = unsafe { lr_router_session_restart_cooldown_remaining(r, h, std::ptr::null_mut()) };
    assert_eq!(rc, -1);
    assert!(last_error().contains("NULL"), "{}", last_error());
    drop_router(r);
}

#[test]
fn restart_cooldown_invalid_router_is_an_error() {
    let mut ms: u64 = 0;
    let rc =
        unsafe { lr_router_session_restart_cooldown_remaining(std::ptr::null_mut(), 0, &mut ms) };
    assert_eq!(rc, -2);
}

// ---- take_collision_lost ------------------------------------------------

#[test]
fn take_collision_lost_returns_zero_initially() {
    let r = fresh_router();
    let h = add_bgp(r);
    let rc = unsafe { lr_router_take_collision_lost(r, h) };
    assert_eq!(rc, 0, "no collision has been recorded yet");
    drop_router(r);
}

#[test]
fn take_collision_lost_invalid_router_is_an_error() {
    let rc = unsafe { lr_router_take_collision_lost(std::ptr::null_mut(), 0) };
    assert_eq!(rc, -2);
}

// ---- session_was_established -------------------------------------------

#[test]
fn session_was_established_returns_zero_initially() {
    let r = fresh_router();
    let h = add_bgp(r);
    let rc = unsafe { lr_router_session_was_established(r, h) };
    assert_eq!(rc, 0, "freshly-added session has not reached Established");
    drop_router(r);
}

#[test]
fn session_was_established_invalid_router_is_an_error() {
    let rc = unsafe { lr_router_session_was_established(std::ptr::null_mut(), 0) };
    assert_eq!(rc, -2);
}

// ---- rib_paths_count / rib_path_at -------------------------------------

#[test]
fn rib_paths_count_starts_at_zero() {
    let r = fresh_router();
    let n = unsafe { lr_router_rib_paths_count(r) };
    assert_eq!(n, 0, "fresh router has no paths in its Loc-RIB");
    drop_router(r);
}

#[test]
fn rib_paths_count_invalid_router_is_an_error() {
    let n = unsafe { lr_router_rib_paths_count(std::ptr::null_mut()) };
    assert_eq!(n, -2);
}

#[test]
fn rib_path_at_out_of_range_is_other() {
    let r = fresh_router();
    let mut route: lr_route_t = std::ptr::null_mut();
    let rc = unsafe { lr_router_rib_path_at(r, 0, &mut route) };
    assert_eq!(rc, -6, "index 0 is out of range on an empty RIB");
    assert!(last_error().contains("out of range"), "{}", last_error());
    drop_router(r);
}

#[test]
fn rib_path_at_null_out_is_an_error() {
    let r = fresh_router();
    let rc = unsafe { lr_router_rib_path_at(r, 0, std::ptr::null_mut()) };
    assert_eq!(rc, -1);
    drop_router(r);
}

#[test]
fn rib_path_at_invalid_router_is_an_error() {
    let mut route: lr_route_t = std::ptr::null_mut();
    let rc = unsafe { lr_router_rib_path_at(std::ptr::null_mut(), 0, &mut route) };
    assert_eq!(rc, -2);
}

#[test]
fn rib_path_at_returns_owned_handle_for_originated_route() {
    let r = fresh_router();
    // Originate one v4 route so the Add-Path view has a single entry.
    let prefix = [10u8, 0, 0, 1];
    let rc =
        unsafe { crate::router::lr_router_originate_v4(r, prefix.as_ptr(), 24, std::ptr::null()) };
    assert_eq!(rc, 0, "originate_v4: {}", last_error());

    let n = unsafe { lr_router_rib_paths_count(r) };
    assert_eq!(n, 1, "one originated route should be in the Add-Path view");

    let mut route: lr_route_t = std::ptr::null_mut();
    let rc = unsafe { lr_router_rib_path_at(r, 0, &mut route) };
    assert_eq!(rc, 0, "rib_path_at: {}", last_error());
    assert!(
        !route.is_null(),
        "the route handle should be non-NULL on success"
    );

    // The caller owns the handle and MUST release it with lr_route_free.
    unsafe { crate::policy_objects::lr_route_free(route) };
    drop_router(r);
}

// ---- flush_rib_for_shutdown --------------------------------------------

#[test]
fn flush_rib_for_shutdown_succeeds_and_is_idempotent() {
    let r = fresh_router();
    // Originate one route so the shutdown flush has something to do.
    let prefix = [10u8, 0, 0, 1];
    unsafe {
        assert_eq!(
            crate::router::lr_router_originate_v4(r, prefix.as_ptr(), 24, std::ptr::null()),
            0
        );
    }
    // First flush: queues one RouteWithdrawn event per Loc-RIB key.
    assert_eq!(unsafe { lr_router_flush_rib_for_shutdown(r) }, 0);
    // Second flush: Loc-RIB is empty, no-op, still success.
    assert_eq!(unsafe { lr_router_flush_rib_for_shutdown(r) }, 0);
    drop_router(r);
}

#[test]
fn flush_rib_for_shutdown_invalid_router_is_an_error() {
    let rc = unsafe { lr_router_flush_rib_for_shutdown(std::ptr::null_mut()) };
    assert_eq!(rc, -2);
}

// ---- babel_flush_session / babel_gc ------------------------------------

#[test]
fn babel_flush_session_succeeds_on_babel_session() {
    let r = fresh_router();
    let h = add_babel(r, true);
    assert_eq!(unsafe { lr_router_babel_flush_session(r, h) }, 0);
    drop_router(r);
}

#[test]
fn babel_flush_session_succeeds_on_non_babel_session() {
    // The trait's default is no-op; the FFI mirrors that so a
    // caller that does not know the session kind is still safe.
    let r = fresh_router();
    let h = add_bgp(r);
    assert_eq!(unsafe { lr_router_babel_flush_session(r, h) }, 0);
    drop_router(r);
}

#[test]
fn babel_flush_session_invalid_router_is_an_error() {
    let rc = unsafe { lr_router_babel_flush_session(std::ptr::null_mut(), 0) };
    assert_eq!(rc, -2);
}

#[test]
fn babel_gc_succeeds() {
    let r = fresh_router();
    let _ = add_babel(r, true);
    assert_eq!(unsafe { lr_router_babel_gc(r, 1_000) }, 0);
    drop_router(r);
}

#[test]
fn babel_gc_invalid_router_is_an_error() {
    let rc = unsafe { lr_router_babel_gc(std::ptr::null_mut(), 0) };
    assert_eq!(rc, -2);
}

// ---- set_babel_own_router_id -------------------------------------------

#[test]
fn set_babel_own_router_id_succeeds_with_eight_bytes() {
    let r = fresh_router();
    let h = add_babel(r, true);
    let id = [1u8, 2, 3, 4, 5, 6, 7, 8];
    assert_eq!(
        unsafe { lr_router_set_babel_own_router_id(r, h, id.as_ptr()) },
        0
    );
    drop_router(r);
}

#[test]
fn set_babel_own_router_id_null_id_is_an_error() {
    let r = fresh_router();
    let h = add_babel(r, true);
    let rc = unsafe { lr_router_set_babel_own_router_id(r, h, std::ptr::null()) };
    assert_eq!(rc, -1);
    drop_router(r);
}

#[test]
fn set_babel_own_router_id_invalid_router_is_an_error() {
    let id = [0u8; 8];
    let rc = unsafe { lr_router_set_babel_own_router_id(std::ptr::null_mut(), 0, id.as_ptr()) };
    assert_eq!(rc, -2);
}

// ---- set_babel_link_cost_params ----------------------------------------

#[test]
fn set_babel_link_cost_params_succeeds() {
    let r = fresh_router();
    let h = add_babel(r, true);
    assert_eq!(
        unsafe { lr_router_set_babel_link_cost_params(r, h, 1_000, 100_000, 96) },
        0
    );
    drop_router(r);
}

#[test]
fn set_babel_link_cost_params_invalid_router_is_an_error() {
    let rc = unsafe { lr_router_set_babel_link_cost_params(std::ptr::null_mut(), 0, 0, 0, 0) };
    assert_eq!(rc, -2);
}

// ---- babel_note_peer ---------------------------------------------------

#[test]
fn babel_note_peer_v4_succeeds() {
    let r = fresh_router();
    let h = add_babel(r, false);
    let addr = [192u8, 0, 2, 100];
    assert_eq!(
        unsafe { lr_router_babel_note_peer(r, h, 0, addr.as_ptr()) },
        0
    );
    drop_router(r);
}

#[test]
fn babel_note_peer_v6_succeeds() {
    let r = fresh_router();
    let h = add_babel(r, true);
    let addr = [0xfeu8, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 99];
    assert_eq!(
        unsafe { lr_router_babel_note_peer(r, h, 1, addr.as_ptr()) },
        0
    );
    drop_router(r);
}

#[test]
fn babel_note_peer_invalid_is_v6_is_an_error() {
    let r = fresh_router();
    let h = add_babel(r, true);
    let addr = [0u8; 16];
    let rc = unsafe { lr_router_babel_note_peer(r, h, 9, addr.as_ptr()) };
    assert_eq!(rc, -3);
    assert!(last_error().contains("is_v6"), "{}", last_error());
    drop_router(r);
}

#[test]
fn babel_note_peer_null_addr_is_an_error() {
    let r = fresh_router();
    let h = add_babel(r, true);
    let rc = unsafe { lr_router_babel_note_peer(r, h, 0, std::ptr::null()) };
    assert_eq!(rc, -1);
    drop_router(r);
}

#[test]
fn babel_note_peer_invalid_router_is_an_error() {
    let addr = [0u8; 4];
    let rc = unsafe { lr_router_babel_note_peer(std::ptr::null_mut(), 0, 0, addr.as_ptr()) };
    assert_eq!(rc, -2);
}

// ---- babel_rtt_us ------------------------------------------------------

#[test]
fn babel_rtt_us_returns_zero_without_a_sample() {
    let r = fresh_router();
    let h = add_babel(r, true);
    let mut us: u32 = 0xFFFF_FFFF;
    let rc = unsafe { lr_router_babel_rtt_us(r, h, 0, &mut us) };
    assert_eq!(rc, 0, "no fresh RTT sample has been recorded yet");
    // rc 0 means "no sample" — out_us is left untouched by the FFI layer.
    drop_router(r);
}

#[test]
fn babel_rtt_us_null_out_is_an_error() {
    let r = fresh_router();
    let h = add_babel(r, true);
    let rc = unsafe { lr_router_babel_rtt_us(r, h, 0, std::ptr::null_mut()) };
    assert_eq!(rc, -1);
    drop_router(r);
}

#[test]
fn babel_rtt_us_invalid_router_is_an_error() {
    let mut us: u32 = 0;
    let rc = unsafe { lr_router_babel_rtt_us(std::ptr::null_mut(), 0, 0, &mut us) };
    assert_eq!(rc, -2);
}

// ---- babel_rtt_echo ----------------------------------------------------

#[test]
fn babel_rtt_echo_returns_zero_without_a_sample() {
    let r = fresh_router();
    let h = add_babel(r, true);
    let mut echo: u32 = 0xFFFF_FFFF;
    let mut recv: u32 = 0xFFFF_FFFF;
    let rc = unsafe { lr_router_babel_rtt_echo(r, h, 0, &mut echo, &mut recv) };
    assert_eq!(rc, 0);
    drop_router(r);
}

#[test]
fn babel_rtt_echo_null_out_is_an_error() {
    let r = fresh_router();
    let h = add_babel(r, true);
    let mut echo: u32 = 0;
    let rc = unsafe { lr_router_babel_rtt_echo(r, h, 0, std::ptr::null_mut(), &mut echo) };
    assert_eq!(rc, -1);
    drop_router(r);
}

#[test]
fn babel_rtt_echo_invalid_router_is_an_error() {
    let mut echo: u32 = 0;
    let mut recv: u32 = 0;
    let rc = unsafe { lr_router_babel_rtt_echo(std::ptr::null_mut(), 0, 0, &mut echo, &mut recv) };
    assert_eq!(rc, -2);
}

// ---- babel_egress_nexthops ---------------------------------------------

#[test]
fn babel_egress_nexthops_zeroes_outputs_for_unknown_session() {
    let r = fresh_router();
    // Use a BGP handle — `babel_egress_nexthops` should return 1
    // ("not a Babel session / no info") and zero the output buffers.
    let h = add_bgp(r);
    let mut v4_p: u8 = 0xAA;
    let mut v6_p: u8 = 0xAA;
    let mut v4 = [0xFFu8; 4];
    let mut v6 = [0xFFu8; 16];
    let rc = unsafe {
        lr_router_babel_egress_nexthops(
            r,
            h,
            &mut v4_p,
            v4.as_mut_ptr(),
            &mut v6_p,
            v6.as_mut_ptr(),
        )
    };
    assert_eq!(rc, 1, "non-Babel session should return 1 (no info)");
    assert_eq!(v4_p, 0, "v4_present should be zeroed for non-Babel");
    assert_eq!(v6_p, 0, "v6_present should be zeroed for non-Babel");
    assert_eq!(v4, [0u8; 4], "v4 buffer should be zeroed");
    assert_eq!(v6, [0u8; 16], "v6 buffer should be zeroed");
    drop_router(r);
}

#[test]
fn babel_egress_nexthops_succeeds_on_babel_session_with_no_address() {
    let r = fresh_router();
    let h = add_babel(r, true);
    let mut v4_p: u8 = 1;
    let mut v6_p: u8 = 1;
    let mut v4 = [0xFFu8; 4];
    let mut v6 = [0xFFu8; 16];
    let rc = unsafe {
        lr_router_babel_egress_nexthops(
            r,
            h,
            &mut v4_p,
            v4.as_mut_ptr(),
            &mut v6_p,
            v6.as_mut_ptr(),
        )
    };
    // 0 = success. The session was constructed with the local
    // address fe80::1; that local address is also the BabelNeighbor
    // initial address (the peer's address fallback per RFC 8966
    // §3.5.3) so v6_p should be 1 and v6 carries the local v6.
    // No v4 next hop has been advertised, so v4_p is 0.
    assert_eq!(rc, 0);
    assert_eq!(v4_p, 0);
    assert_eq!(v6_p, 1);
    // The local v6 address is the fe80::1 we passed to add_babel.
    let expected = [0xfeu8, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
    assert_eq!(v6, expected);
    drop_router(r);
}

#[test]
fn babel_egress_nexthops_after_note_peer_v4_returns_v4_address() {
    let r = fresh_router();
    let h = add_babel(r, false);
    // Note a v4 peer address.
    let peer = [192u8, 0, 2, 100];
    unsafe {
        assert_eq!(lr_router_babel_note_peer(r, h, 0, peer.as_ptr()), 0);
    }
    let mut v4_p: u8 = 0;
    let mut v6_p: u8 = 0;
    let mut v4 = [0u8; 4];
    let mut v6 = [0u8; 16];
    let rc = unsafe {
        lr_router_babel_egress_nexthops(
            r,
            h,
            &mut v4_p,
            v4.as_mut_ptr(),
            &mut v6_p,
            v6.as_mut_ptr(),
        )
    };
    assert_eq!(rc, 0);
    assert_eq!(v4_p, 1, "v4 should be present after noting a v4 peer");
    assert_eq!(v4, peer);
    assert_eq!(v6_p, 0, "v6 should still be absent");
    drop_router(r);
}

#[test]
fn babel_egress_nexthops_null_out_is_an_error() {
    let r = fresh_router();
    let h = add_babel(r, true);
    let mut v4_p: u8 = 0;
    let mut v6_p: u8 = 0;
    let mut v6 = [0u8; 16];
    let rc = unsafe {
        lr_router_babel_egress_nexthops(
            r,
            h,
            &mut v4_p,
            std::ptr::null_mut(),
            &mut v6_p,
            v6.as_mut_ptr(),
        )
    };
    assert_eq!(rc, -1);
    drop_router(r);
}

#[test]
fn babel_egress_nexthops_invalid_router_is_an_error() {
    let mut v4_p: u8 = 0;
    let mut v4 = [0u8; 4];
    let mut v6_p: u8 = 0;
    let mut v6 = [0u8; 16];
    let rc = unsafe {
        lr_router_babel_egress_nexthops(
            std::ptr::null_mut(),
            0,
            &mut v4_p,
            v4.as_mut_ptr(),
            &mut v6_p,
            v6.as_mut_ptr(),
        )
    };
    assert_eq!(rc, -2);
}

// ---- babel_take_route_request ------------------------------------------

#[test]
fn babel_take_route_request_returns_zero_initially() {
    let r = fresh_router();
    let h = add_babel(r, true);
    let rc = unsafe { lr_router_babel_take_route_request(r, h) };
    assert_eq!(rc, 0, "no Route Request has been seen yet");
    drop_router(r);
}

#[test]
fn babel_take_route_request_invalid_router_is_an_error() {
    let rc = unsafe { lr_router_babel_take_route_request(std::ptr::null_mut(), 0) };
    assert_eq!(rc, -2);
}

// ---- babel_take_own_seqno_request -------------------------------------

#[test]
fn babel_take_own_seqno_request_returns_zero_initially() {
    let r = fresh_router();
    let h = add_babel(r, true);
    let mut seqno: u16 = 0xFFFF;
    let rc = unsafe { lr_router_babel_take_own_seqno_request(r, h, &mut seqno) };
    assert_eq!(rc, 0, "no own-seqno request yet");
    drop_router(r);
}

#[test]
fn babel_take_own_seqno_request_null_out_is_an_error() {
    let r = fresh_router();
    let h = add_babel(r, true);
    let rc = unsafe { lr_router_babel_take_own_seqno_request(r, h, std::ptr::null_mut()) };
    assert_eq!(rc, -1);
    drop_router(r);
}

#[test]
fn babel_take_own_seqno_request_invalid_router_is_an_error() {
    let mut seqno: u16 = 0;
    let rc = unsafe { lr_router_babel_take_own_seqno_request(std::ptr::null_mut(), 0, &mut seqno) };
    assert_eq!(rc, -2);
}
