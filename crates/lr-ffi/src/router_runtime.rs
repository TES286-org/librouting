//! `RouterInstance` trait method exposure — the per-session hooks the
//! daemon uses for BGP FSM state inspection, Babel runtime control and
//! graceful shutdown that were previously unreachable from the C ABI
//! (the trait's default no-op implementations kept mock
//! implementations source-compatible, but the `DefaultRouter` overrides
//! that actually do the work were never wired to FFI entry points).
//!
//! The functions here mirror the trait surface in
//! `crates/lr-router/src/instance/mod.rs` one-to-one so a C embedder
//! driving the daemon-equivalent runtime can:
//!
//! - inspect the BGP FSM state of a session by *handle*
//!   ([`lr_router_session_peer_state`]) — the index-based
//!   `lr_router_session_summary_at` already exists, but a transport
//!   that owns a single `SessionHandle` previously had to walk the
//!   whole summary list to find its own row;
//! - read the max-prefix `Restart` cooldown remaining for a session
//!   so the outbound connector can keep the backoff (BIRD `restart
//!   time` / FRR `bgp maximum-prefix restart <secs>` parity);
//! - consume the RFC 4271 §6.8 collision-loss latch so the connector
//!   does not redial into a peer that already holds a live session;
//! - ask whether the *current* transport incarnation ever reached
//!   Established (so a handshake that died at OpenConfirm keeps the
//!   exponential backoff growing);
//! - flush every Loc-RIB route at shutdown so the kernel mirror
//!   retires the routes this daemon installed with it (BIRD `krt`
//!   parity);
//! - drive the Babel runtime hooks (`babel_gc`, `babel_flush_session`,
//!   `set_babel_own_router_id`, `set_babel_link_cost_params`,
//!   `babel_note_peer`, `babel_rtt_us`, `babel_rtt_echo`,
//!   `babel_egress_nexthops`, `babel_take_route_request`,
//!   `babel_take_own_seqno_request`) — these are the per-session
//!   knobs RFC 8966 / RFC 8967 expect a Babel speaker to honor and the
//!   ones the daemon's per-interface Babel loop already turns.
//!
//! Every entry point runs inside the crate's `catch_unwind` barrier
//! ([`crate::guarded`]): a panic returns `LR_ERR_PANIC` and sets the
//! thread-local last-error string. The router handle is locked for
//! the duration of the call so the per-session maps cannot race with
//! a parallel `lr_router_tick` or `lr_router_feed_input`.

#![allow(unused_unsafe)]

use lr_core::addr::IpAddr;
use lr_router::{RouterInstance, SessionHandle};

use crate::enum_extras::name_ptr;
use crate::error::{set_last_error, LR_ERR_PANIC};
use crate::guarded;
use crate::handle::{lock_router, lr_route_t, lr_router_t};

// ---- Session-state inspection (handle-keyed) ---------------------------

/// Read the BGP FSM state name of a session by handle (one of
/// `"Idle"`, `"Connect"`, `"Active"`, `"OpenSent"`, `"OpenConfirm"`,
/// `"Established"` for BGP; non-BGP / unknown sessions return NULL).
///
/// The index-based [`lr_router_session_summary_at`] already exposes
/// the same string, but a transport that owns a single session
/// handle previously had to walk the whole summary list to find its
/// own row — the handle-keyed reader makes the common-case O(1).
///
/// Returns a NUL-terminated UTF-8 string (the FSM state name), or
/// NULL when the router handle is invalid, the session is unknown,
/// or the session is not a BGP session. The returned pointer aliases
/// a thread-local buffer reused by every `lr_*_name` entry point in
/// the C ABI (the same pattern `lr_bfd_auth_type_name`,
/// `lr_ospf_network_type_name` etc. use); the caller MUST copy the
/// bytes out before the next such call on the same thread. The
/// caller MUST NOT free the pointer.
///
/// # Safety
/// `r` must be a valid `lr_router_t` (or NULL — NULL returns NULL
/// rather than panicking).
#[no_mangle]
pub unsafe extern "C" fn lr_router_session_peer_state(
    r: lr_router_t,
    session: u64,
) -> *const std::os::raw::c_char {
    guarded(
        || unsafe {
            let router = match unsafe { lock_router(r) } {
                Some(g) => g,
                None => return std::ptr::null(),
            };
            match router.session_peer_state(SessionHandle(session)) {
                Some(name) => name_ptr(name),
                None => std::ptr::null(),
            }
        },
        std::ptr::null(),
    )
}

/// Read the remaining milliseconds of the max-prefix `Restart`
/// cooldown for a session (BIRD `restart time`, FRR `bgp maximum-prefix
/// restart <secs>`). Returns 1 when a cooldown is in effect (the
/// caller's `*out_ms` is set to the remaining milliseconds), 0 when
/// the session never tripped `Restart` or the configured cooldown has
/// elapsed, negative on error.
///
/// The daemon's outbound connector reads this before dialing so a
/// peer that exceeded its prefix limit cannot re-establish until the
/// configured cooldown elapses. Driven by the router clock advanced
/// in [`lr_router_tick`].
///
/// # Safety
/// `r` must be a valid `lr_router_t`. `out_ms` must point to a
/// writable `uint64_t` slot when non-null; NULL is an error.
#[no_mangle]
pub unsafe extern "C" fn lr_router_session_restart_cooldown_remaining(
    r: lr_router_t,
    session: u64,
    out_ms: *mut u64,
) -> i32 {
    guarded(
        || unsafe {
            if out_ms.is_null() {
                set_last_error("out_ms is NULL".to_string());
                return LR_ERR_NULL;
            }
            let router = match unsafe { lock_router(r) } {
                Some(g) => g,
                None => return LR_ERR_INVALID_HANDLE,
            };
            match router.session_restart_cooldown_remaining(SessionHandle(session)) {
                Some(remaining) => {
                    unsafe { *out_ms = remaining };
                    1
                }
                None => 0,
            }
        },
        LR_ERR_PANIC,
    )
}

/// Consume the §6.8 collision-loss latch of a session: returns 1 when
/// the session lost an RFC 4271 §6.8 collision — its own resolver
/// closed it, or a Cease / Connection Collision Resolution
/// NOTIFICATION (RFC 4486 subcode 7) arrived — since the latch was
/// last consumed (or the session last started). Returns 0 when no
/// collision was lost since the last call, negative on error. The
/// latch is consumed on read: a subsequent call returns 0 until the
/// next collision.
///
/// Embedders use it to back the connector off instead of redialing
/// into a peer that already holds a live session (BIRD parity: the
/// collision loser waits out its ConnectRetry, it does not hammer).
///
/// # Safety
/// `r` must be a valid `lr_router_t`.
#[no_mangle]
pub unsafe extern "C" fn lr_router_take_collision_lost(r: lr_router_t, session: u64) -> i32 {
    guarded(
        || unsafe {
            let mut router = match unsafe { lock_router(r) } {
                Some(g) => g,
                None => return LR_ERR_INVALID_HANDLE,
            };
            i32::from(router.take_collision_lost(SessionHandle(session)))
        },
        LR_ERR_PANIC,
    )
}

/// Whether the session's CURRENT transport incarnation ever reached
/// Established. Returns 1 when the session reached Established at
/// least once on the current transport, 0 otherwise, negative on
/// error. Used by embedders to reset reconnect backoff only after a
/// genuinely working session — a handshake that died at OpenConfirm
/// must keep the exponential backoff growing.
///
/// # Safety
/// `r` must be a valid `lr_router_t`.
#[no_mangle]
pub unsafe extern "C" fn lr_router_session_was_established(r: lr_router_t, session: u64) -> i32 {
    guarded(
        || unsafe {
            let router = match unsafe { lock_router(r) } {
                Some(g) => g,
                None => return LR_ERR_INVALID_HANDLE,
            };
            i32::from(router.session_was_established(SessionHandle(session)))
        },
        LR_ERR_PANIC,
    )
}

// ---- Add-Path snapshot (RFC 7911) --------------------------------------

/// Number of paths currently in the Loc-RIB's Add-Path view
/// ([`RouterInstance::rib_paths_snapshot`]). The default
/// `lr_router_rib_len` returns the best-path count (one per prefix);
/// this reader returns the full multiplicity count when Add-Path is
/// configured (RFC 7911 §2 — "the BGP speaker MAY advertise more than
/// one path per destination"). Returns the count, or negative on
/// error.
///
/// Pair with [`lr_router_rib_path_at`] to walk the typed view; the
/// existing text-only [`lr_router_rib_dump`] is unchanged and still
/// the cheapest way to render the table for human inspection.
///
/// # Safety
/// `r` must be a valid `lr_router_t`.
#[no_mangle]
pub extern "C" fn lr_router_rib_paths_count(r: lr_router_t) -> i64 {
    guarded(
        || unsafe {
            let router = match unsafe { lock_router(r) } {
                Some(g) => g,
                None => return LR_ERR_INVALID_HANDLE as i64,
            };
            router.rib_paths_snapshot().len() as i64
        },
        LR_ERR_PANIC as i64,
    )
}

/// Borrow one path from the Loc-RIB's Add-Path view at index `idx`
/// (0-based). On success, ownership of a fresh [`lr_route_t`] handle
/// (boxing a `Route` clone) is transferred to the caller; the handle
/// MUST be released with [`lr_route_free`]. Returns 0 on success,
/// `LR_ERR_NULL` (-1) on null `out_route`, `LR_ERR_INVALID_HANDLE`
/// (-2) on an invalid router, `LR_ERR_OTHER` (-6) on out-of-range
/// index (the last-error string carries the index and the count).
///
/// Routes are returned in `rib_paths_snapshot` order — the same order
/// `lr_router_rib_dump` walks. The clone is unavoidable across the
/// C ABI: the inner `&Route` cannot outlive the router lock that
/// guards the Loc-RIB, so the entry point hands the caller an owned
/// snapshot.
///
/// # Safety
/// `r` must be a valid `lr_router_t`. `out_route` must point to a
/// writable `lr_route_t` slot when non-null.
#[no_mangle]
pub unsafe extern "C" fn lr_router_rib_path_at(
    r: lr_router_t,
    idx: usize,
    out_route: *mut lr_route_t,
) -> i32 {
    guarded(
        || unsafe {
            if out_route.is_null() {
                set_last_error("out_route is NULL".to_string());
                return LR_ERR_NULL;
            }
            let router = match unsafe { lock_router(r) } {
                Some(g) => g,
                None => return LR_ERR_INVALID_HANDLE,
            };
            let snap = router.rib_paths_snapshot();
            match snap.get(idx) {
                Some(route) => {
                    // `rib_paths_snapshot` returns `Vec<&Route>` so
                    // `snap.get(idx)` is `Option<&&Route>`; double-deref
                    // before `clone` so we clone the inner `Route`
                    // (the clippy `suspicious_double_ref_op` lint
                    // otherwise catches a `.clone()` that returns
                    // `&Route` rather than the owned `Route`).
                    let boxed = Box::new((**route).clone());
                    unsafe { *out_route = Box::into_raw(boxed) as lr_route_t };
                    0
                }
                None => {
                    set_last_error(format!(
                        "rib path index {idx} out of range (count {})",
                        snap.len()
                    ));
                    LR_ERR_OTHER
                }
            }
        },
        LR_ERR_PANIC,
    )
}

// ---- Lifecycle ---------------------------------------------------------

/// Flush every Loc-RIB route — the daemon shutdown hook RFC 4271
/// leaves to the implementor. Queues one `RouteWithdrawn` event per
/// Loc-RIB key (the event consumer / ticker's final drain hands them
/// to the kernel mirror so the routes this daemon installed leave
/// the kernel with it — BIRD's `krt` parity). Returns 0 on success,
/// `LR_ERR_INVALID_HANDLE` (-2) on an invalid router.
///
/// Idempotent: calling twice queues the withdrawals twice (the second
/// call sees an empty Loc-RIB and queues nothing). The intended
/// sequence is `flush_rib_for_shutdown` → `drain_output` per session
/// → `lr_router_destroy`.
///
/// # Safety
/// `r` must be a valid `lr_router_t`.
#[no_mangle]
pub unsafe extern "C" fn lr_router_flush_rib_for_shutdown(r: lr_router_t) -> i32 {
    guarded(
        || unsafe {
            let mut router = match unsafe { lock_router(r) } {
                Some(g) => g,
                None => return LR_ERR_INVALID_HANDLE,
            };
            router.flush_rib_for_shutdown();
            0
        },
        LR_ERR_PANIC,
    )
}

// ---- Babel runtime hooks (RFC 8966 / RFC 8967) -------------------------

/// Drop every route learned over the Babel session `h` and apply the
/// withdrawal delta to Loc-RIB — the `check link` response when an
/// interface goes operationally down (BIRD `check link yes`,
/// RFC 8966 §A.2). Returns 0 on success (incl. when the session is not
/// a Babel session — the no-op matches the Rust trait's default),
/// `LR_ERR_INVALID_HANDLE` (-2) on an invalid router.
///
/// The session stays alive for the link's return: routes re-learn
/// from the peer's Updates when the interface comes back.
///
/// # Safety
/// `r` must be a valid `lr_router_t`.
#[no_mangle]
pub unsafe extern "C" fn lr_router_babel_flush_session(r: lr_router_t, session: u64) -> i32 {
    guarded(
        || unsafe {
            let mut router = match unsafe { lock_router(r) } {
                Some(g) => g,
                None => return LR_ERR_INVALID_HANDLE,
            };
            router.babel_flush_session(SessionHandle(session));
            0
        },
        LR_ERR_PANIC,
    )
}

/// One Babel expiry sweep (RFC 8966 §3.2.5): expire routes whose
/// re-announcement hold time lapsed and retract everything a dead
/// neighbour taught us, applying the Loc-RIB deltas. Returns 0 on
/// success, `LR_ERR_INVALID_HANDLE` (-2) on an invalid router. The
/// transport should call this about once a second (`now_ms` is the
/// same wall-clock milliseconds `lr_router_tick` advances).
///
/// # Safety
/// `r` must be a valid `lr_router_t`.
#[no_mangle]
pub unsafe extern "C" fn lr_router_babel_gc(r: lr_router_t, now_ms: u64) -> i32 {
    guarded(
        || unsafe {
            let mut router = match unsafe { lock_router(r) } {
                Some(g) => g,
                None => return LR_ERR_INVALID_HANDLE,
            };
            router.babel_gc(now_ms);
            0
        },
        LR_ERR_PANIC,
    )
}

/// Pin the Babel router-id this node announces on session `h`
/// (RFC 8966 §3.3). Updates that echo it back — a peer re-advertising
/// our own claims — are then ignored, exactly like BIRD's
/// `babel_handle_update` self-router-id guard. Returns 0 on success
/// (incl. non-Babel session, matching the trait's no-op default),
/// `LR_ERR_INVALID_HANDLE` (-2) on an invalid router, `LR_ERR_NULL`
/// (-1) on a NULL `id` pointer.
///
/// # Safety
/// `r` must be a valid `lr_router_t`. `id` must point to 8 readable
/// bytes (the Babel router-id, RFC 8966 §3.3.1 — the EUI-64 or any
/// other unique 64-bit value).
#[no_mangle]
pub unsafe extern "C" fn lr_router_set_babel_own_router_id(
    r: lr_router_t,
    session: u64,
    id: *const u8,
) -> i32 {
    guarded(
        || unsafe {
            if id.is_null() {
                set_last_error("id is NULL".to_string());
                return LR_ERR_NULL;
            }
            let mut bytes = [0u8; 8];
            unsafe { std::ptr::copy_nonoverlapping(id, bytes.as_mut_ptr(), 8) };
            let mut router = match unsafe { lock_router(r) } {
                Some(g) => g,
                None => return LR_ERR_INVALID_HANDLE,
            };
            router.set_babel_own_router_id(SessionHandle(session), bytes);
            0
        },
        LR_ERR_PANIC,
    )
}

/// Configure the reception-side link-cost ramp of Babel session `h`
/// (RFC 8966 §A.2.4): the RTT penalty bounds and the maximum applied
/// on top of the txcost learned from the peer's IHU when an Update's
/// advertised metric is folded into the local route metric.
/// `rtt_cost` 0 (babeld's default) keeps the RTT feature off. Returns
/// 0 on success (incl. non-Babel session), `LR_ERR_INVALID_HANDLE`
/// (-2) on an invalid router.
///
/// The three parameters are microseconds: rtt_min_us is the lower
/// bound below which no penalty is applied, rtt_max_us is the upper
/// bound above which the penalty saturates at `rtt_cost`.
///
/// # Safety
/// `r` must be a valid `lr_router_t`.
#[no_mangle]
pub unsafe extern "C" fn lr_router_set_babel_link_cost_params(
    r: lr_router_t,
    session: u64,
    rtt_min_us: u32,
    rtt_max_us: u32,
    rtt_cost: u16,
) -> i32 {
    guarded(
        || unsafe {
            let mut router = match unsafe { lock_router(r) } {
                Some(g) => g,
                None => return LR_ERR_INVALID_HANDLE,
            };
            router.set_babel_link_cost_params(
                SessionHandle(session),
                rtt_min_us,
                rtt_max_us,
                rtt_cost,
            );
            0
        },
        LR_ERR_PANIC,
    )
}

/// Tell the Babel runtime the address the peer's datagrams come from.
/// RFC 8966 §3.5.3: an Update with no preceding NextHop TLV resolves
/// its next hop to the *sender* — BIRD relies on this and omits the
/// v6 NextHop TLV for its own announcements. The runtime is
/// constructed with the local bind address, so the transport MUST
/// call this per datagram or v6 routes fall back to our own address
/// as the next hop. Returns 0 on success (incl. non-Babel session),
/// `LR_ERR_INVALID_HANDLE` (-2) on an invalid router, `LR_ERR_NULL`
/// (-1) on a NULL `addr` pointer, `LR_ERR_BAD_UTF8` (-3) on an
/// `is_v6` value other than 0 / 1.
///
/// # Safety
/// `r` must be a valid `lr_router_t`. `addr` must point to 4 readable
/// bytes when `is_v6` is 0, 16 readable bytes when `is_v6` is 1.
#[no_mangle]
pub unsafe extern "C" fn lr_router_babel_note_peer(
    r: lr_router_t,
    session: u64,
    is_v6: u8,
    addr: *const u8,
) -> i32 {
    guarded(
        || unsafe {
            if addr.is_null() {
                set_last_error("addr is NULL".to_string());
                return LR_ERR_NULL;
            }
            let peer = match is_v6 {
                0 => {
                    let mut a = [0u8; 4];
                    unsafe { std::ptr::copy_nonoverlapping(addr, a.as_mut_ptr(), 4) };
                    IpAddr::V4(a)
                }
                1 => {
                    let mut a = [0u8; 16];
                    unsafe { std::ptr::copy_nonoverlapping(addr, a.as_mut_ptr(), 16) };
                    IpAddr::V6(a)
                }
                _ => {
                    set_last_error(format!("is_v6 must be 0 or 1, got {is_v6}"));
                    return LR_ERR_BAD_UTF8;
                }
            };
            let mut router = match unsafe { lock_router(r) } {
                Some(g) => g,
                None => return LR_ERR_INVALID_HANDLE,
            };
            router.babel_note_peer(SessionHandle(session), peer);
            0
        },
        LR_ERR_PANIC,
    )
}

/// The smoothed RTT measured toward the peer of Babel session `h`
/// (BABEL-RTT, RFC 8966 §A.2.4), when a fresh sample exists. Returns 1
/// when a sample is available (the caller's `*out_us` is set to the
/// smoothed RTT in microseconds), 0 when no fresh sample exists or the
/// session is not a Babel session, negative on error.
///
/// # Safety
/// `r` must be a valid `lr_router_t`. `out_us` must point to a
/// writable `uint32_t` slot when non-null.
#[no_mangle]
pub unsafe extern "C" fn lr_router_babel_rtt_us(
    r: lr_router_t,
    session: u64,
    now_ms: u64,
    out_us: *mut u32,
) -> i32 {
    guarded(
        || unsafe {
            if out_us.is_null() {
                set_last_error("out_us is NULL".to_string());
                return LR_ERR_NULL;
            }
            let router = match unsafe { lock_router(r) } {
                Some(g) => g,
                None => return LR_ERR_INVALID_HANDLE,
            };
            match router.babel_rtt_us(SessionHandle(session), now_ms) {
                Some(us) => {
                    unsafe { *out_us = us };
                    1
                }
                None => 0,
            }
        },
        LR_ERR_PANIC,
    )
}

/// The BABEL-RTT pair the next IHU toward the session's peer should
/// echo — `(peer Hello timestamp, our receive time)`, valid only
/// while the Hello is fresh (RFC 8966 §A.2.4; babeld's 1 s echo
/// window). Returns 1 when a fresh echo pair is available (the
/// caller's `*out_echo_ts` and `*out_recv_us` are set — the peer's
/// Hello timestamp and our receive time, both in microseconds),
/// 0 when no fresh pair exists or the session is not a Babel session,
/// negative on error.
///
/// # Safety
/// `r` must be a valid `lr_router_t`. `out_echo_ts` and `out_recv_us`
/// must point to writable `uint32_t` slots when non-null.
#[no_mangle]
pub unsafe extern "C" fn lr_router_babel_rtt_echo(
    r: lr_router_t,
    session: u64,
    now_ms: u64,
    out_echo_ts: *mut u32,
    out_recv_us: *mut u32,
) -> i32 {
    guarded(
        || unsafe {
            if out_echo_ts.is_null() || out_recv_us.is_null() {
                set_last_error("out_echo_ts or out_recv_us is NULL".to_string());
                return LR_ERR_NULL;
            }
            let router = match unsafe { lock_router(r) } {
                Some(g) => g,
                None => return LR_ERR_INVALID_HANDLE,
            };
            match router.babel_rtt_echo(SessionHandle(session), now_ms) {
                Some((echo_ts, recv_us)) => {
                    unsafe {
                        *out_echo_ts = echo_ts;
                        *out_recv_us = recv_us;
                    }
                    1
                }
                None => 0,
            }
        },
        LR_ERR_PANIC,
    )
}

/// The current next-hop addresses the Babel peer of session `h`
/// advertises in its Update streams — `(AE 1 v4, AE 2/3 v6)` as
/// learned from the NextHop TLVs (RFC 8966 §4.6.4), plus the
/// implicit peer-address fallbacks once a datagram has been seen.
///
/// The egress interface for every route learned on the session is
/// the session's own interface (babeld installs kernel routes with
/// `neigh->ifp`; BIRD resolves through the neighbour's iface) —
/// *not* whatever interface the kernel's own next-hop resolution
/// prefers. Embedders that mirror the Loc-RIB into the kernel FIB
/// use these addresses to pin the egress interface per next hop,
/// especially for v4-in-v6 transport where the v4 next hop is not
/// on-link anywhere and longest-prefix resolution can land the
/// route on an unrelated adapter.
///
/// Returns 0 on success (the `*out_v4_present` / `*out_v6_present`
/// flags are set to 1 / 0; when 1, the corresponding address buffer
/// is filled — 4 bytes for v4, 16 bytes for v6). Returns
/// `LR_ERR_NULL` (-1) on a NULL output pointer, `LR_ERR_INVALID_HANDLE`
/// (-2) on an invalid router, 1 when the session is not a Babel
/// session or the runtime has no next-hop information — the output
/// buffers are zeroed in that case so the caller can distinguish
/// "session not Babel" from "Babel session with no next hops yet".
///
/// # Safety
/// `r` must be a valid `lr_router_t`. `out_v4_present` /
/// `out_v4` (4 bytes) / `out_v6_present` / `out_v6` (16 bytes) must
/// point to writable slots when non-null.
#[no_mangle]
pub unsafe extern "C" fn lr_router_babel_egress_nexthops(
    r: lr_router_t,
    session: u64,
    out_v4_present: *mut u8,
    out_v4: *mut u8,
    out_v6_present: *mut u8,
    out_v6: *mut u8,
) -> i32 {
    guarded(
        || unsafe {
            if out_v4_present.is_null()
                || out_v4.is_null()
                || out_v6_present.is_null()
                || out_v6.is_null()
            {
                set_last_error(
                    "lr_router_babel_egress_nexthops: all four output pointers must be non-NULL"
                        .to_string(),
                );
                return LR_ERR_NULL;
            }
            let router = match unsafe { lock_router(r) } {
                Some(g) => g,
                None => return LR_ERR_INVALID_HANDLE,
            };
            let nexthops = router.babel_egress_nexthops(SessionHandle(session));
            // Zero the output buffers up front so the "session not
            // Babel" path leaves them blank and the caller can
            // distinguish it from a Babel session with no next hops
            // yet (which is the same shape but reached by a
            // different code path).
            unsafe {
                *out_v4_present = 0;
                *out_v6_present = 0;
                std::ptr::write_bytes(out_v4, 0, 4);
                std::ptr::write_bytes(out_v6, 0, 16);
            }
            let Some((v4_opt, v6_opt)) = nexthops else {
                // Not a Babel session, or session unknown.
                return 1;
            };
            if let Some(IpAddr::V4(a)) = v4_opt {
                unsafe {
                    *out_v4_present = 1;
                    std::ptr::copy_nonoverlapping(a.as_ptr(), out_v4, 4);
                }
            }
            if let Some(IpAddr::V6(a)) = v6_opt {
                unsafe {
                    *out_v6_present = 1;
                    std::ptr::copy_nonoverlapping(a.as_ptr(), out_v6, 16);
                }
            }
            0
        },
        LR_ERR_PANIC,
    )
}

/// Take the pending "a Route Request arrived" flag (RFC 8966
/// §3.2.6): returns 1 exactly once after any Route Request TLV
/// (wildcard or specific) was seen on session `h`. The transport
/// answers by announcing immediately instead of waiting for the
/// periodic tick. Returns 0 when no request is pending, 1 when one
/// was consumed, negative on error.
///
/// # Safety
/// `r` must be a valid `lr_router_t`.
#[no_mangle]
pub unsafe extern "C" fn lr_router_babel_take_route_request(r: lr_router_t, session: u64) -> i32 {
    guarded(
        || unsafe {
            let mut router = match unsafe { lock_router(r) } {
                Some(g) => g,
                None => return LR_ERR_INVALID_HANDLE,
            };
            i32::from(router.babel_take_route_request(SessionHandle(session)))
        },
        LR_ERR_PANIC,
    )
}

/// Take the pending "a Seqno Request for *our own* router-id arrived"
/// event (RFC 8966 §3.2.6.2): returns 1 exactly once after a peer
/// asked us to re-announce with (at least) the seqno the caller's
/// `*out_seqno` is set to — the restart-recovery path when a peer
/// remembers a higher seqno than our fresh boot value. The transport
/// bumps its announcement seqno to at least `seqno` and re-announces.
/// Returns 0 when no request is pending, 1 when one was consumed,
/// negative on error.
///
/// # Safety
/// `r` must be a valid `lr_router_t`. `out_seqno` must point to a
/// writable `uint16_t` slot when non-null.
#[no_mangle]
pub unsafe extern "C" fn lr_router_babel_take_own_seqno_request(
    r: lr_router_t,
    session: u64,
    out_seqno: *mut u16,
) -> i32 {
    guarded(
        || unsafe {
            if out_seqno.is_null() {
                set_last_error("out_seqno is NULL".to_string());
                return LR_ERR_NULL;
            }
            let mut router = match unsafe { lock_router(r) } {
                Some(g) => g,
                None => return LR_ERR_INVALID_HANDLE,
            };
            match router.babel_take_own_seqno_request(SessionHandle(session)) {
                Some(seqno) => {
                    unsafe { *out_seqno = seqno };
                    1
                }
                None => 0,
            }
        },
        LR_ERR_PANIC,
    )
}

// ---- Error code constants mirrored locally for readability -------------
//
// These mirror the public `LR_ERR_*` macros in `include/lr_ffi.h`
// (auto-generated by cbindgen from the build.rs after_includes block).
// Re-declaring them as `const i32` here keeps the FFI bodies readable
// without a `use crate::error::LrError::*` that would shadow the
// macro forms embedders see on the C side.

const LR_ERR_NULL: i32 = -1;
const LR_ERR_INVALID_HANDLE: i32 = -2;
const LR_ERR_BAD_UTF8: i32 = -3;
const LR_ERR_OTHER: i32 = -6;

#[cfg(test)]
#[path = "router_runtime_tests.rs"]
mod tests;
