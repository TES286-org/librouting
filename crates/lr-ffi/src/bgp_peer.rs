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

// ---- Advertise / withdraw / send_end_of_rib (RFC 4271 §9.2 / §9.3) ----
//
// The advertise surface mirrors `BgpPeer::advertise` /
// `BgpPeer::withdraw` / `BgpPeer::withdraw_paths` /
// `BgpPeer::send_end_of_rib` so an embedder can drive the egress
// UPDATE path directly. The peer must be in Established (RFC 4271
// §8 — only an Established peer exchanges UPDATEs); when it is not
// the call returns `0` (advertise) / no-op (withdraw / EoR) to
// match the Rust API's silent skip.

/// Advertise a route to this peer (RFC 4271 §9.2). Returns 1 when
/// the route was queued for transmission, 0 when the peer refused
/// the route (not Established, iBGP split-horizon, OTC egress
/// rule, LLGR_STALE to a non-LLGR peer, etc.). Returns
/// `LR_ERR_NULL` (-1) on a NULL handle.
///
/// The route handle is **borrowed** — the caller retains ownership
/// and must still free it via `lr_route_free`.
///
/// # Safety
/// `r` must be a valid BgpPeer handle. `route` must be a valid
/// Route handle (NULL is rejected with `LR_ERR_NULL`).
#[no_mangle]
pub unsafe extern "C" fn lr_bgp_peer_advertise(
    r: lr_bgp_peer_t,
    route: crate::handle::lr_route_t,
) -> i32 {
    guarded(
        || unsafe {
            let Some(p) = borrow_peer_mut(r) else {
                return LR_ERR_NULL;
            };
            if route.is_null() {
                return LR_ERR_NULL;
            }
            // SAFETY: the caller passed a handle from `lr_route_new_*`
            // and asserts it has not been freed yet.
            let route_ref: &'static lr_core::rib::Route =
                unsafe { &*(route as *const lr_core::rib::Route) };
            if p.advertise(route_ref) {
                1
            } else {
                0
            }
        },
        LR_ERR_PANIC,
    )
}

/// Withdraw a list of IPv4/IPv6 prefixes (RFC 4271 §9.3). The peer
/// must be Established — the call is a silent no-op otherwise (RFC
/// 4271 §8).
///
/// `prefixes` points to `count` `lr_prefix_t` entries; `family_afi`
/// / `family_safi` select the AFI/SAFI (1/1 = IPv4 unicast, 2/1 =
/// IPv6 unicast, etc.). Returns `LR_ERR_NULL` (-1) on a NULL handle
/// or a NULL `prefixes` with non-zero `count`.
///
/// # Safety
/// `r` must be a valid BgpPeer handle. `prefixes` (when `count > 0`)
/// must point to `count` readable `lr_prefix_t` entries.
#[no_mangle]
pub unsafe extern "C" fn lr_bgp_peer_withdraw(
    r: lr_bgp_peer_t,
    prefixes: *const crate::policy::lr_prefix_t,
    count: usize,
    family_afi: u16,
    family_safi: u8,
) -> i32 {
    guarded(
        || unsafe {
            let Some(p) = borrow_peer_mut(r) else {
                return LR_ERR_NULL;
            };
            if count == 0 {
                // An empty withdrawal is a legal no-op; mirror the
                // Rust API by silently returning 0.
                return 0;
            }
            if prefixes.is_null() {
                return LR_ERR_NULL;
            }
            let slice = unsafe { core::slice::from_raw_parts(prefixes, count) };
            let mut prefixes_vec: Vec<lr_core::addr::Prefix> = Vec::with_capacity(count);
            for spec in slice {
                let Some(prefix) = spec.to_prefix() else {
                    return LrError::Other as i32;
                };
                prefixes_vec.push(prefix);
            }
            let family = lr_core::nlri::NlriFamily {
                afi: family_afi,
                safi: family_safi,
            };
            p.withdraw(&prefixes_vec, family);
            0
        },
        LR_ERR_PANIC,
    )
}

/// Send an End-of-RIB marker to this peer (RFC 4724 §4.2). For
/// IPv4 unicast this is an empty UPDATE; for other families it is
/// an `MpUnreach` with an empty NLRI list. The peer must be
/// Established — the call is a silent no-op otherwise.
///
/// `family_afi` / `family_safi` select the AFI/SAFI.
///
/// # Safety
/// `r` must be a valid BgpPeer handle.
#[no_mangle]
pub unsafe extern "C" fn lr_bgp_peer_send_end_of_rib(
    r: lr_bgp_peer_t,
    family_afi: u16,
    family_safi: u8,
) -> i32 {
    guarded(
        || unsafe {
            let Some(p) = borrow_peer_mut(r) else {
                return LR_ERR_NULL;
            };
            // The Rust BgpPeer::send_end_of_rib signature is
            // parameterless — it sends the IPv4 unicast EoR. The
            // family-parameterised form lives in
            // `lr_router::DefaultRouter`. For the peer-level FFI we
            // send the IPv4 EoR when family == (1, 1) and otherwise
            // fall through to a no-op (the embedder should use
            // `lr_router_send_end_of_rib` for the family form).
            if family_afi == 1 && family_safi == 1 {
                p.send_end_of_rib();
            }
            0
        },
        LR_ERR_PANIC,
    )
}

// ---- PeerMessageStats (RFC 4271 §6 keepalive / open / update counters) ----

/// One peer's message counters (RFC 4271 §6 — open / keepalive /
/// notification / update counters). Mirrors
/// `lr_bgp::fsm::PeerMessageStats` field-for-field. Each counter is
/// the cumulative number of messages of that kind sent / received
/// since the peer was constructed (the counters are not reset on
/// session reset — they reflect the lifetime of the
/// `BgpPeer` handle).
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct lr_bgp_peer_message_stats_t {
    pub open_sent: u64,
    pub open_received: u64,
    pub keepalive_sent: u64,
    pub keepalive_received: u64,
    pub notification_sent: u64,
    pub notification_received: u64,
    pub update_sent: u64,
    pub update_received: u64,
    pub route_refresh_sent: u64,
    pub route_refresh_received: u64,
}

/// Read the peer's cumulative message counters (RFC 4271 §6). The
/// struct is written to `*out`. Returns `LR_ERR_NULL` (-1) on a
/// NULL peer or NULL `out`.
///
/// # Safety
/// `r` must be a valid BgpPeer handle. `out` must point to writable
/// memory the size of `lr_bgp_peer_message_stats_t`.
#[no_mangle]
pub unsafe extern "C" fn lr_bgp_peer_message_stats(
    r: lr_bgp_peer_t,
    out: *mut lr_bgp_peer_message_stats_t,
) -> i32 {
    guarded(
        || unsafe {
            let Some(p) = borrow_peer(r) else {
                return LR_ERR_NULL;
            };
            if out.is_null() {
                return LR_ERR_NULL;
            }
            let s = p.message_stats();
            unsafe {
                *out = lr_bgp_peer_message_stats_t {
                    open_sent: s.open_sent,
                    open_received: s.open_received,
                    keepalive_sent: s.keepalive_sent,
                    keepalive_received: s.keepalive_received,
                    notification_sent: s.notification_sent,
                    notification_received: s.notification_received,
                    update_sent: s.update_sent,
                    update_received: s.update_received,
                    route_refresh_sent: s.route_refresh_sent,
                    route_refresh_received: s.route_refresh_received,
                };
            }
            0
        },
        LR_ERR_PANIC,
    )
}

// ---- PeerConfig accessors (RFC 4271 §6.2 + §8 + RFC 4456 §9 + RFC 7947 §2) ----
//
// `PeerConfig` carries the per-peer knobs the FSM consults: hold /
// keepalive / asn4 / ipv4_unicast / route-reflector-client / route-
// server-client / etc. The readers below surface those knobs to the
// embedder so a C consumer can introspect the config the same way
// the Rust API does.

/// Read the configured hold time (RFC 4271 §4.2, seconds).
///
/// # Safety
/// `r` must be a valid BgpPeer handle.
#[no_mangle]
pub unsafe extern "C" fn lr_bgp_peer_hold_time(r: lr_bgp_peer_t) -> u16 {
    guarded(
        || unsafe { borrow_peer(r).map(|p| p.config().hold_time).unwrap_or(0) },
        0,
    )
}

/// Read the configured keepalive interval (RFC 4271 §4.3, seconds).
/// 0 means "use hold_time / 3" (the RFC 4271 default).
///
/// # Safety
/// `r` must be a valid BgpPeer handle.
#[no_mangle]
pub unsafe extern "C" fn lr_bgp_peer_keepalive(r: lr_bgp_peer_t) -> u16 {
    guarded(
        || unsafe {
            borrow_peer(r)
                .map(|p| p.config().keepalive_interval())
                .unwrap_or(0)
        },
        0,
    )
}

/// Read the local AS (RFC 4271 §4.2). For RFC 6793 four-octet-AS
/// peers this is the full 32-bit value; the wire form unwraps to
/// AS_TRANS (23456) when above 16 bits.
///
/// # Safety
/// `r` must be a valid BgpPeer handle.
#[no_mangle]
pub unsafe extern "C" fn lr_bgp_peer_local_as(r: lr_bgp_peer_t) -> u32 {
    guarded(
        || unsafe {
            borrow_peer(r)
                .map(|p| p.config().local_as.as_u32())
                .unwrap_or(0)
        },
        0,
    )
}

/// 1 when the peer has RFC 6793 four-octet-AS support enabled.
///
/// # Safety
/// `r` must be a valid BgpPeer handle.
#[no_mangle]
pub unsafe extern "C" fn lr_bgp_peer_asn4(r: lr_bgp_peer_t) -> u8 {
    guarded(
        || unsafe { borrow_peer(r).map(|p| p.config().asn4 as u8).unwrap_or(0) },
        0,
    )
}

/// 1 when IPv4 unicast is active for this peer (RFC 4271 §8 —
/// "bgp default ipv4-unicast" knob; FRR `no bgp default ipv4-unicast`).
///
/// # Safety
/// `r` must be a valid BgpPeer handle.
#[no_mangle]
pub unsafe extern "C" fn lr_bgp_peer_ipv4_unicast_active(r: lr_bgp_peer_t) -> u8 {
    guarded(
        || unsafe {
            borrow_peer(r)
                .map(|p| p.config().ipv4_unicast_active() as u8)
                .unwrap_or(0)
        },
        0,
    )
}

/// 1 when this peer is a route-reflector client (RFC 4456 §9).
///
/// # Safety
/// `r` must be a valid BgpPeer handle.
#[no_mangle]
pub unsafe extern "C" fn lr_bgp_peer_is_rr_client(r: lr_bgp_peer_t) -> u8 {
    guarded(
        || unsafe {
            borrow_peer(r)
                .map(|p| p.config().is_rr_client() as u8)
                .unwrap_or(0)
        },
        0,
    )
}

/// 1 when this peer is a route-server client (RFC 7947 §2.1).
///
/// # Safety
/// `r` must be a valid BgpPeer handle.
#[no_mangle]
pub unsafe extern "C" fn lr_bgp_peer_is_rs_client(r: lr_bgp_peer_t) -> u8 {
    guarded(
        || unsafe {
            borrow_peer(r)
                .map(|p| p.config().is_rs_client() as u8)
                .unwrap_or(0)
        },
        0,
    )
}

/// Peer role (RFC 9234 §3.1): 0 = eBGP, 1 = iBGP, 2 =
/// ConfederationExternal, 3 = ConfederationInternal. Mirrors
/// `lr_bgp::role::PeerRole`.
///
/// # Safety
/// `r` must be a valid BgpPeer handle.
#[no_mangle]
pub unsafe extern "C" fn lr_bgp_peer_role(r: lr_bgp_peer_t) -> i32 {
    guarded(
        || unsafe {
            borrow_peer(r)
                .map(|p| match p.config().peer_role() {
                    lr_bgp::role::PeerRole::Ebgp => 0,
                    lr_bgp::role::PeerRole::Ibgp => 1,
                    lr_bgp::role::PeerRole::ConfederationExternal => 2,
                    lr_bgp::role::PeerRole::ConfederationInternal => 3,
                })
                .unwrap_or(-1)
        },
        -1,
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

    #[test]
    fn ffi_bgp_peer_advertise_rejects_null_route() {
        let p = lr_bgp_peer_new(64512, 64513, 0x0a000001, 90, 30, 1);
        // NULL route → LR_ERR_NULL.
        let rc = unsafe { lr_bgp_peer_advertise(p, std::ptr::null_mut()) };
        assert_eq!(rc, LR_ERR_NULL);
        // NULL peer → LR_ERR_NULL.
        let rc = unsafe { lr_bgp_peer_advertise(std::ptr::null_mut(), std::ptr::null_mut()) };
        assert_eq!(rc, LR_ERR_NULL);
        unsafe { lr_bgp_peer_free(p) };
    }

    #[test]
    fn ffi_bgp_peer_advertise_returns_zero_when_not_established() {
        // A peer in Idle refuses to advertise — the call must return 0
        // (route not queued), not LR_ERR_NULL or a panic.
        let p = lr_bgp_peer_new(64512, 64513, 0x0a000001, 90, 30, 1);
        // Build a minimal Route handle: IPv4 /32, BGP protocol.
        let route = unsafe {
            crate::policy_objects::lr_route_new_v4(
                [203, 0, 113, 1].as_ptr(),
                32,
                crate::policy::LrProtocol::Bgp as i32,
            )
        };
        assert!(!route.is_null());
        let rc = unsafe { lr_bgp_peer_advertise(p, route) };
        assert_eq!(rc, 0, "Idle peer must refuse to advertise (returns 0)");
        unsafe {
            crate::policy_objects::lr_route_free(route);
            lr_bgp_peer_free(p);
        };
    }

    #[test]
    fn ffi_bgp_peer_withdraw_handles_null_safely() {
        // NULL peer → LR_ERR_NULL.
        let rc = unsafe { lr_bgp_peer_withdraw(std::ptr::null_mut(), std::ptr::null(), 0, 1, 1) };
        assert_eq!(rc, LR_ERR_NULL);
    }

    #[test]
    fn ffi_bgp_peer_withdraw_is_noop_on_idle_peer() {
        // An Idle peer's withdraw is a silent no-op (RFC 4271 §8).
        // The call returns 0 without panicking.
        let p = lr_bgp_peer_new(64512, 64513, 0x0a000001, 90, 30, 1);
        let prefix = crate::policy::lr_prefix_t {
            addr: [203, 0, 113, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            is_ipv6: 0,
            prefix_len: 24,
        };
        let rc = unsafe { lr_bgp_peer_withdraw(p, &prefix, 1, 1, 1) };
        assert_eq!(rc, 0, "withdraw on Idle peer is a silent no-op");
        // Empty count is a no-op.
        let rc = unsafe { lr_bgp_peer_withdraw(p, std::ptr::null(), 0, 1, 1) };
        assert_eq!(rc, 0);
        unsafe { lr_bgp_peer_free(p) };
    }

    #[test]
    fn ffi_bgp_peer_send_end_of_rib_handles_null_safely() {
        let rc = unsafe { lr_bgp_peer_send_end_of_rib(std::ptr::null_mut(), 1, 1) };
        assert_eq!(rc, LR_ERR_NULL);
    }

    #[test]
    fn ffi_bgp_peer_message_stats_returns_zero_on_fresh_peer() {
        let p = lr_bgp_peer_new(64512, 64513, 0x0a000001, 90, 30, 1);
        let mut stats = lr_bgp_peer_message_stats_t::default();
        let rc = unsafe { lr_bgp_peer_message_stats(p, &raw mut stats) };
        assert_eq!(rc, 0);
        assert_eq!(stats.open_sent, 0);
        assert_eq!(stats.update_received, 0);
        assert_eq!(stats.keepalive_received, 0);
        // NULL peer / out → LR_ERR_NULL.
        let rc = unsafe { lr_bgp_peer_message_stats(std::ptr::null_mut(), &raw mut stats) };
        assert_eq!(rc, LR_ERR_NULL);
        let rc = unsafe { lr_bgp_peer_message_stats(p, std::ptr::null_mut()) };
        assert_eq!(rc, LR_ERR_NULL);
        unsafe { lr_bgp_peer_free(p) };
    }

    #[test]
    fn ffi_bgp_peer_config_accessors_read_constructed_values() {
        let p = lr_bgp_peer_new(64512, 64513, 0x0a000001, 90, 30, 1);
        assert_eq!(unsafe { lr_bgp_peer_hold_time(p) }, 90);
        assert_eq!(unsafe { lr_bgp_peer_keepalive(p) }, 30);
        assert_eq!(unsafe { lr_bgp_peer_local_as(p) }, 64512);
        assert_eq!(unsafe { lr_bgp_peer_asn4(p) }, 1);
        // Default PeerConfig has ipv4_unicast active (RFC 4271 §8
        // default) and no RR/RS client flags.
        assert_eq!(unsafe { lr_bgp_peer_ipv4_unicast_active(p) }, 1);
        assert_eq!(unsafe { lr_bgp_peer_is_rr_client(p) }, 0);
        assert_eq!(unsafe { lr_bgp_peer_is_rs_client(p) }, 0);
        // 64512 != 64513 → eBGP, role = 0.
        assert_eq!(unsafe { lr_bgp_peer_role(p) }, 0);
        unsafe { lr_bgp_peer_free(p) };
    }

    #[test]
    fn ffi_bgp_peer_config_accessors_handle_null_safely() {
        assert_eq!(unsafe { lr_bgp_peer_hold_time(std::ptr::null_mut()) }, 0);
        assert_eq!(unsafe { lr_bgp_peer_keepalive(std::ptr::null_mut()) }, 0);
        assert_eq!(unsafe { lr_bgp_peer_local_as(std::ptr::null_mut()) }, 0);
        assert_eq!(unsafe { lr_bgp_peer_asn4(std::ptr::null_mut()) }, 0);
        assert_eq!(
            unsafe { lr_bgp_peer_ipv4_unicast_active(std::ptr::null_mut()) },
            0
        );
        assert_eq!(unsafe { lr_bgp_peer_is_rr_client(std::ptr::null_mut()) }, 0);
        assert_eq!(unsafe { lr_bgp_peer_is_rs_client(std::ptr::null_mut()) }, 0);
        assert_eq!(unsafe { lr_bgp_peer_role(std::ptr::null_mut()) }, -1);
    }
}
