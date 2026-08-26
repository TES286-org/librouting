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
        route_refresh: true,
        enhanced_route_refresh: true,
        mp_families: Vec::new(),
        local_address: None,
        area_id: 0,
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

/// Start a session: drives the protocol FSM into operation (BGP:
/// ManualStart + TransportOpen). Call once the transport is connected.
#[no_mangle]
pub extern "C" fn lr_router_start_session(r: lr_router_t, session: u64) -> i32 {
    let mut router = match unsafe { lock_router(r) } {
        Some(g) => g,
        None => return -2,
    };
    match router.start_session(SessionHandle(session)) {
        Ok(_) => 0,
        Err(e) => {
            set_last_error(e);
            -3
        }
    }
}

/// Request an RFC 2918 route refresh from an established BGP peer.
///
/// Returns 1 when a request was queued, 0 when the session has not negotiated
/// route refresh, and a negative value for invalid handles or inputs.
#[no_mangle]
pub extern "C" fn lr_router_request_route_refresh(
    r: lr_router_t,
    session: u64,
    afi: u16,
    safi: u8,
) -> i32 {
    let mut router = match unsafe { lock_router(r) } {
        Some(g) => g,
        None => return -1,
    };
    if afi == 0 || safi == 0 {
        set_last_error("AFI and SAFI must be non-zero".to_string());
        return -2;
    }
    if router.request_route_refresh(
        SessionHandle(session),
        lr_core::nlri::NlriFamily { afi, safi },
    ) {
        1
    } else {
        0
    }
}

/// Originate a local IPv4 route: `prefix_addr` is 4 bytes, `prefix_len` is
/// the prefix length, `next_hop` is 4 bytes or NULL. The route is injected
/// into Loc-RIB and advertised to all established BGP peers.
///
/// # Safety
/// `prefix_addr` and `next_hop` (when non-NULL) must be valid pointers to
/// 4 readable bytes.
#[no_mangle]
pub unsafe extern "C" fn lr_router_originate_v4(
    r: lr_router_t,
    prefix_addr: *const u8,
    prefix_len: u8,
    next_hop: *const u8,
) -> i32 {
    if prefix_addr.is_null() {
        return -1;
    }
    let mut router = match unsafe { lock_router(r) } {
        Some(g) => g,
        None => return -2,
    };
    let mut addr = [0u8; 4];
    unsafe { addr.copy_from_slice(std::slice::from_raw_parts(prefix_addr, 4)) };
    let nh = if next_hop.is_null() {
        None
    } else {
        let mut n = [0u8; 4];
        unsafe { n.copy_from_slice(std::slice::from_raw_parts(next_hop, 4)) };
        Some(lr_core::addr::IpAddr::V4(n))
    };
    router.originate(lr_core::addr::Prefix::new_v4(addr, prefix_len), nh);
    0
}

/// Number of routes currently in Loc-RIB.
#[no_mangle]
pub extern "C" fn lr_router_rib_len(r: lr_router_t) -> i64 {
    let router = match unsafe { lock_router(r) } {
        Some(g) => g,
        None => return -1,
    };
    router.rib_len() as i64
}

/// Dump the Loc-RIB as a text table (one route per line). The caller owns
/// the returned bytes and must free them with `lr_bytes_free`.
///
/// # Safety
/// `out` must point to a valid `lr_bytes_t` slot.
#[no_mangle]
pub unsafe extern "C" fn lr_router_rib_dump(r: lr_router_t, out: *mut lr_bytes_t) -> i32 {
    if out.is_null() {
        return -1;
    }
    let router = match unsafe { lock_router(r) } {
        Some(g) => g,
        None => return -2,
    };
    let mut text = String::new();
    for route in router.rib_snapshot() {
        use std::fmt::Write as _;
        let _ = writeln!(
            text,
            "{}/{} via {} proto={:?} metric={}",
            route.key.prefix,
            route.key.prefix.prefix_len,
            route
                .next_hop
                .map(|n| n.to_string())
                .unwrap_or_else(|| "(none)".to_string()),
            route.protocol,
            route.preference.metric
        );
    }
    unsafe { *out = lr_bytes_t::from_vec(text.into_bytes()) }
    0
}
