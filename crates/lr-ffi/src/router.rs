//! Router lifecycle — `lr_router_new`, `lr_router_destroy`, `lr_router_tick`,
//! `lr_router_add_session`, `lr_router_feed_input`, `lr_router_drain_output`,
//! `lr_router_poll_events`.

use lr_core::addr::{Asn, RouterId};
use lr_core::time::Instant;
use lr_router::{
    DefaultRouter, OspfAreaType, RouterInstance, SessionConfig, SessionHandle, SessionKind,
};

use crate::error::{set_last_error, LR_ERR_PANIC};
use crate::guarded;
use crate::handle::{box_router, lock_router, lr_bytes_t, lr_router_t, unbox_router};

/// Sanity cap for `lr_router_set_extended_next_hop` tuple counts. A caller
/// can never legitimately configure more than this many RFC 5549 tuples, and
/// the cap bounds the `count * 5` byte-length computation before it feeds
/// `std::slice::from_raw_parts` (no overflow, no garbage-length slice).
const MAX_EXT_NEXT_HOP_TUPLES: usize = 1024;

/// Sanity cap for `lr_router_set_mp_families` entries (see
/// [`MAX_EXT_NEXT_HOP_TUPLES`]).
const MAX_MP_FAMILIES: usize = 1024;

/// Sanity cap for RFC 8277 label stacks built by `build_label_stack`
/// (real-world stacks are a handful of labels; 16 is generous). Bounds the
/// `n_labels` value before it feeds `std::slice::from_raw_parts`.
const MAX_LABEL_STACK_DEPTH: usize = 16;

/// Create a new router instance.
#[no_mangle]
pub extern "C" fn lr_router_new() -> lr_router_t {
    guarded(|| box_router(DefaultRouter::new()), std::ptr::null_mut())
}

/// Destroy a router instance. Safe to call with NULL.
///
/// # Safety
/// `r` must have been returned by `lr_router_new` and not yet destroyed.
#[no_mangle]
pub unsafe extern "C" fn lr_router_destroy(r: lr_router_t) {
    guarded(|| unsafe { unbox_router(r) }, ())
}

/// Add a BGP session. Returns 0 on success, negative on error. The session
/// handle is written to `out_handle`.
///
/// Graceful restart (RFC 4724) is enabled with a 120 s restart time;
/// Long-Lived Graceful Restart (RFC 9494) is disabled. Use
/// [`lr_router_add_bgp_session_ext`] to configure both.
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
    guarded(
        || unsafe {
            lr_router_add_bgp_session_ext(
                r,
                local_as,
                peer_as,
                local_bgp_id,
                hold_time,
                keepalive,
                asn4,
                1,
                120,
                0,
                0,
                0,
                out_handle,
            )
        },
        LR_ERR_PANIC,
    )
}

/// Extended session creation with graceful-restart knobs.
///
/// - `graceful_restart` / `gr_restart_time`: RFC 4724 advertisement and
///   stale-route retention (seconds; restart time is clamped to 12 bits).
/// - `long_lived_gr` / `llgr_stale_time`: RFC 9494 Long-Lived Graceful
///   Restart — LLGR requires GR per RFC 9494 §4.1, so when
///   `long_lived_gr` is set with `graceful_restart` clear the LLGR
///   capability is not advertised.
/// - `llgr_max_stale_time`: optional local cap (seconds) on the stale time
///   received from the peer; 0 disables the cap (RFC 9494 §4.2).
#[no_mangle]
pub unsafe extern "C" fn lr_router_add_bgp_session_ext(
    r: lr_router_t,
    local_as: u32,
    peer_as: u32,
    local_bgp_id: u32,
    hold_time: u16,
    keepalive: u16,
    asn4: u8,
    graceful_restart: u8,
    gr_restart_time: u16,
    long_lived_gr: u8,
    llgr_stale_time: u32,
    llgr_max_stale_time: u32,
    out_handle: *mut u64,
) -> i32 {
    guarded(
        || {
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
                add_path: false,
                extended_next_hop: Vec::new(),
                graceful_restart: graceful_restart != 0,
                graceful_restart_time: gr_restart_time,
                long_lived_gr: long_lived_gr != 0,
                long_lived_stale_time: llgr_stale_time,
                llgr_max_stale_time: if llgr_max_stale_time != 0 {
                    Some(llgr_max_stale_time)
                } else {
                    None
                },
                mrai_ms: if local_as == peer_as { 5_000 } else { 30_000 },
                // W2.1: FRR `bgp default ipv4-unicast` defaults to on, and
                // the library default for a session with no explicit
                // families is `[IPV4_UNICAST]` (SessionConfig::bgp). The
                // FFI's ext entry point has no parameter for the default —
                // it is always on here — so advertise the IPv4-unicast
                // MP-BGP capability in OPEN: BIRD 2 refuses sessions whose
                // required capability is missing. This mirrors the daemon's
                // family-list builder (crates/lr-cli/src/daemon.rs), which
                // inserts IPV4_UNICAST when the effective default is on.
                // Embedders who want the `no bgp default ipv4-unicast`
                // posture call `lr_router_set_default_ipv4_unicast(0)` and
                // `lr_router_set_mp_families` before starting the session.
                mp_families: vec![lr_core::nlri::NlriFamily::IPV4_UNICAST],
                default_ipv4_unicast: true,
                // W2.3: FRR `neighbor X allowas-in N` defaults to 0 (reject any
                // local AS in the AS_PATH). Embedders flip it via
                // `lr_router_set_local_as_tolerance`.
                local_as_tolerance: 0,
                // W2.4: FRR `neighbor X soft-reconfiguration inbound` defaults
                // to off. Embedders flip it via
                // `lr_router_set_soft_reconfig_inbound`.
                soft_reconfig_inbound: false,
                local_address: None,
                area_id: 0,
                ospf_area_type: OspfAreaType::Normal,
                ospf_mtu: 1500,
                maximum_prefix: None,
                maximum_prefix_action: lr_bgp::MaxPrefixAction::Warn,
                maximum_prefix_threshold: 75,
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
        },
        LR_ERR_PANIC,
    )
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
    guarded(
        || {
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
        },
        LR_ERR_PANIC,
    )
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
    guarded(
        || {
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
        },
        LR_ERR_PANIC,
    )
}

/// Advance the router clock.
#[no_mangle]
pub extern "C" fn lr_router_tick(r: lr_router_t, now_ms: u64) -> i32 {
    guarded(
        || {
            let mut router = match unsafe { lock_router(r) } {
                Some(g) => g,
                None => return -2,
            };
            router.tick(Instant(now_ms));
            0
        },
        LR_ERR_PANIC,
    )
}

/// Start a session: drives the protocol FSM into operation (BGP:
/// ManualStart + TransportOpen). Call once the transport is connected.
#[no_mangle]
pub extern "C" fn lr_router_start_session(r: lr_router_t, session: u64) -> i32 {
    guarded(
        || {
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
        },
        LR_ERR_PANIC,
    )
}

/// Set the per-prefix RFC 4271 MRAI interval for a BGP session.
///
/// A zero interval disables batching and flushes any pending UPDATEs.
#[no_mangle]
pub extern "C" fn lr_router_set_mrai(r: lr_router_t, session: u64, interval_ms: u64) -> i32 {
    guarded(
        || {
            let mut router = match unsafe { lock_router(r) } {
                Some(g) => g,
                None => return -1,
            };
            match router.set_mrai(SessionHandle(session), interval_ms) {
                Ok(()) => 0,
                Err(error) => {
                    set_last_error(error);
                    -2
                }
            }
        },
        LR_ERR_PANIC,
    )
}

/// Enable or disable RFC 7911 Add-Path on one BGP session.
///
/// Must be called after `lr_router_add_bgp_session*` and before
/// `lr_router_start_session` — the capability is negotiated in OPEN.
/// `enabled` is 0 (off) or non-zero (on).
#[no_mangle]
pub extern "C" fn lr_router_set_add_path(r: lr_router_t, session: u64, enabled: u8) -> i32 {
    guarded(
        || {
            let mut router = match unsafe { lock_router(r) } {
                Some(g) => g,
                None => return -1,
            };
            match router.set_session_add_path(SessionHandle(session), enabled != 0) {
                Ok(()) => 0,
                Err(error) => {
                    set_last_error(error);
                    -2
                }
            }
        },
        LR_ERR_PANIC,
    )
}

/// Set how many paths per prefix the RFC 7911 decision process keeps in
/// Loc-RIB and advertises to Add-Path peers (router-wide).
///
/// Values below 1 are clamped to 1 (single-path). Takes effect for
/// sessions whose Add-Path capability was negotiated.
#[no_mangle]
pub extern "C" fn lr_router_set_add_path_max_paths(r: lr_router_t, max_paths: u32) -> i32 {
    guarded(
        || {
            let mut router = match unsafe { lock_router(r) } {
                Some(g) => g,
                None => return -1,
            };
            router.set_add_path_max_paths(max_paths.max(1) as usize);
            0
        },
        LR_ERR_PANIC,
    )
}

/// Enable or disable the RFC 8212 default eBGP route behaviors
/// (router-wide).
///
/// When enabled, an external BGP session (eBGP or a confederation
/// boundary) with no explicit import policy declared via
/// `lr_router_set_session_policy` discards received routes, and one
/// with no export policy advertises nothing (RFC 8212 §3). `enabled`
/// is 0 (off — the RFC 4271 default-accept) or non-zero (on).
#[no_mangle]
pub extern "C" fn lr_router_set_ebgp_requires_policy(r: lr_router_t, enabled: u8) -> i32 {
    guarded(
        || {
            let mut router = match unsafe { lock_router(r) } {
                Some(g) => g,
                None => return -1,
            };
            router.set_ebgp_requires_policy(enabled != 0);
            0
        },
        LR_ERR_PANIC,
    )
}

/// Enable or disable FRR `bgp enforce-first-as` (W2.2).
///
/// When on, an UPDATE received from an external BGP peer (eBGP or a
/// confederation boundary) whose AS_PATH leftmost sequence segment's
/// first AS is not the peer's negotiated AS is rejected before the
/// Adj-RIB-In. When off (the default — `no bgp enforce-first-as`),
/// the route is admitted subject to the ordinary policy and safety
/// checks. `enabled` is 0 (off) or non-zero (on).
#[no_mangle]
pub extern "C" fn lr_router_set_enforce_first_as(r: lr_router_t, enabled: u8) -> i32 {
    guarded(
        || {
            let mut router = match unsafe { lock_router(r) } {
                Some(g) => g,
                None => return -1,
            };
            router.set_enforce_first_as(enabled != 0);
            0
        },
        LR_ERR_PANIC,
    )
}

/// Declare which directions of a BGP session carry an explicit policy
/// (RFC 8212 §3).
///
/// `import`/`export` are 0 (no policy — the direction is subject to
/// the RFC 8212 default deny when enabled) or non-zero (explicit
/// policy attached; the policy itself runs through the hook chain).
/// Call after `lr_router_add_bgp_session*`; unknown handles fail with
/// -2 and set the last-error string.
#[no_mangle]
pub extern "C" fn lr_router_set_session_policy(
    r: lr_router_t,
    session: u64,
    import: u8,
    export: u8,
) -> i32 {
    guarded(
        || {
            let mut router = match unsafe { lock_router(r) } {
                Some(g) => g,
                None => return -1,
            };
            match router.set_session_policy(SessionHandle(session), import != 0, export != 0) {
                Ok(()) => 0,
                Err(error) => {
                    set_last_error(error);
                    -2
                }
            }
        },
        LR_ERR_PANIC,
    )
}

/// Configure RFC 5549 Extended Next-Hop on a BGP session.
///
/// `tuples` points to `count` 5-byte records, each laid out as
/// `<NLRI AFI:2 (big-endian), NLRI SAFI:1, Nexthop AFI:2 (big-endian)>`.
/// The canonical tuple is `00 01 01 00 02` — IPv4 unicast NLRI resolved
/// over an IPv6 next-hop. Pass `count = 0` to clear the configuration.
/// (This is the FFI input layout, not the wire form: RFC 5549 §4
/// encodes the capability on the wire as 6-byte tuples with a 2-octet
/// SAFI — librouting performs that conversion internally.)
///
/// Must be called after `lr_router_add_bgp_session*` and before
/// `lr_router_start_session` — the capability is negotiated in OPEN.
///
/// `count` must not exceed [`MAX_EXT_NEXT_HOP_TUPLES`]; larger values are
/// rejected with -3 (the cap keeps `count * 5` free of overflow before the
/// caller's memory is read).
///
/// # Safety
/// `tuples` must point to at least `count * 5` readable bytes when
/// `count > 0`.
#[no_mangle]
pub unsafe extern "C" fn lr_router_set_extended_next_hop(
    r: lr_router_t,
    session: u64,
    tuples: *const u8,
    count: usize,
) -> i32 {
    guarded(
        || {
            let mut router = match unsafe { lock_router(r) } {
                Some(g) => g,
                None => return -1,
            };
            let parsed: Vec<(u16, u8, u16)> = if count == 0 || tuples.is_null() {
                Vec::new()
            } else if count > MAX_EXT_NEXT_HOP_TUPLES || count.checked_mul(5).is_none() {
                set_last_error(format!(
                    "count {count} too large for extended-next-hop tuples \
                     (max {MAX_EXT_NEXT_HOP_TUPLES})"
                ));
                return -3;
            } else {
                let slice = unsafe { std::slice::from_raw_parts(tuples, count * 5) };
                let mut out = Vec::with_capacity(count);
                for t in slice.as_chunks::<5>().0 {
                    let nlri_afi = u16::from_be_bytes([t[0], t[1]]);
                    let nlri_safi = t[2];
                    let nh_afi = u16::from_be_bytes([t[3], t[4]]);
                    out.push((nlri_afi, nlri_safi, nh_afi));
                }
                out
            };
            match router.set_session_extended_next_hop(SessionHandle(session), &parsed) {
                Ok(()) => 0,
                Err(error) => {
                    set_last_error(error);
                    -2
                }
            }
        },
        LR_ERR_PANIC,
    )
}

/// Override the MP-BGP address families advertised in OPEN.
///
/// `families` points to `count` 4-byte records, each laid out as
/// `<AFI:2 (big-endian), reserved:1, SAFI:1>` — the same encoding used
/// by the RFC 4760 multiprotocol capability. The two well-known values
/// are `00 01 00 01` (IPv4 unicast) and `00 02 00 01` (IPv6 unicast).
///
/// Must be called before `lr_router_start_session`. Replaces the default
/// IPv4-unicast-only family list.
///
/// `count` must not exceed [`MAX_MP_FAMILIES`]; larger values are rejected
/// with -3 (the cap keeps `count * 4` free of overflow before the caller's
/// memory is read).
///
/// # Safety
/// `families` must point to at least `count * 4` readable bytes when
/// `count > 0`.
#[no_mangle]
pub unsafe extern "C" fn lr_router_set_mp_families(
    r: lr_router_t,
    session: u64,
    families: *const u8,
    count: usize,
) -> i32 {
    guarded(
        || {
            let mut router = match unsafe { lock_router(r) } {
                Some(g) => g,
                None => return -1,
            };
            let parsed: Vec<lr_core::nlri::NlriFamily> = if count == 0 || families.is_null() {
                Vec::new()
            } else if count > MAX_MP_FAMILIES || count.checked_mul(4).is_none() {
                set_last_error(format!(
                    "count {count} too large for mp_families (max {MAX_MP_FAMILIES})"
                ));
                return -3;
            } else {
                let slice = unsafe { std::slice::from_raw_parts(families, count * 4) };
                let mut out = Vec::with_capacity(count);
                for t in slice.as_chunks::<4>().0 {
                    let afi = u16::from_be_bytes([t[0], t[1]]);
                    let safi = t[3];
                    out.push(lr_core::nlri::NlriFamily { afi, safi });
                }
                out
            };
            match router.set_session_mp_families(SessionHandle(session), &parsed) {
                Ok(()) => 0,
                Err(error) => {
                    set_last_error(error);
                    -2
                }
            }
        },
        LR_ERR_PANIC,
    )
}

/// Set the local source address for next-hop-self egress on a BGP session.
///
/// `addr_family` is `1` for IPv4 (4 bytes) or `2` for IPv6 (16 bytes).
/// `addr_bytes` must point to the appropriate number of bytes. Must be
/// called before `lr_router_start_session`.
///
/// # Safety
/// `addr_bytes` must point to 4 (IPv4) or 16 (IPv6) readable bytes.
#[no_mangle]
pub unsafe extern "C" fn lr_router_set_local_address(
    r: lr_router_t,
    session: u64,
    addr_family: u16,
    addr_bytes: *const u8,
    addr_len: usize,
) -> i32 {
    guarded(
        || {
            let mut router = match unsafe { lock_router(r) } {
                Some(g) => g,
                None => return -1,
            };
            if addr_bytes.is_null() {
                set_last_error("null address".into());
                return -3;
            }
            // Validate the family/length pairing BEFORE touching the
            // caller's memory: `from_raw_parts` must only ever see a length
            // we have already verified (4 or 16), never a caller-supplied
            // garbage length.
            let (is_v4, expected_len) = match addr_family {
                1 => (true, 4),
                2 => (false, 16),
                _ => {
                    set_last_error(format!("bad address family: afi={addr_family}"));
                    return -3;
                }
            };
            if addr_len != expected_len {
                set_last_error(format!(
                    "bad address family/length: afi={addr_family} len={addr_len}"
                ));
                return -3;
            }
            let slice = unsafe { std::slice::from_raw_parts(addr_bytes, addr_len) };
            let addr = if is_v4 {
                let mut a = [0u8; 4];
                a.copy_from_slice(slice);
                lr_core::addr::IpAddr::V4(a)
            } else {
                let mut a = [0u8; 16];
                a.copy_from_slice(slice);
                lr_core::addr::IpAddr::V6(a)
            };
            match router.set_session_local_address(SessionHandle(session), addr) {
                Ok(()) => 0,
                Err(error) => {
                    set_last_error(error);
                    -2
                }
            }
        },
        LR_ERR_PANIC,
    )
}

/// Configure FRR `bgp default ipv4-unicast` (W2.1) for a BGP session.
///
/// When `enabled` is non-zero (the default), IPv4 unicast is implicitly
/// active even when `lr_router_set_mp_families` did not list it. When
/// zero, IPv4 unicast must be added explicitly via
/// `lr_router_set_mp_families` to be active — the FRR
/// `no bgp default ipv4-unicast` posture. Must be called after
/// `lr_router_add_bgp_session*` and before `lr_router_start_session`;
/// unknown handles or already-established sessions fail with -2.
#[no_mangle]
pub extern "C" fn lr_router_set_default_ipv4_unicast(
    r: lr_router_t,
    session: u64,
    enabled: u8,
) -> i32 {
    guarded(
        || {
            let mut router = match unsafe { lock_router(r) } {
                Some(g) => g,
                None => return -1,
            };
            match router.set_session_default_ipv4_unicast(SessionHandle(session), enabled != 0) {
                Ok(()) => 0,
                Err(error) => {
                    set_last_error(error);
                    -2
                }
            }
        },
        LR_ERR_PANIC,
    )
}

/// Configure FRR `neighbor X allowas-in N` / BIRD `allow local as`
/// (W2.3) for a BGP session.
///
/// `tolerance = 0` (the default) rejects any occurrence of the local
/// AS in a received AS_PATH (RFC 4271 §9.1.2.15). `N > 0` admits a
/// route whose AS_PATH contains the local AS up to N times (FRR
/// `allowas-in N`, default N=1). The special value `u32::MAX` admits
/// any number (FRR `allowas-any`). iBGP sessions are exempt
/// (FRR/BIRD scope the relaxation to eBGP). Must be called after
/// `lr_router_add_bgp_session*` and before `lr_router_start_session`;
/// unknown handles or already-established sessions fail with -2.
#[no_mangle]
pub extern "C" fn lr_router_set_local_as_tolerance(
    r: lr_router_t,
    session: u64,
    tolerance: u32,
) -> i32 {
    guarded(
        || {
            let mut router = match unsafe { lock_router(r) } {
                Some(g) => g,
                None => return -1,
            };
            match router.set_session_local_as_tolerance(SessionHandle(session), tolerance) {
                Ok(()) => 0,
                Err(error) => {
                    set_last_error(error);
                    -2
                }
            }
        },
        LR_ERR_PANIC,
    )
}

/// Configure FRR `neighbor X soft-reconfiguration inbound` (W2.4) for
/// a BGP session.
///
/// When `enabled` is non-zero, the router retains the pre-policy
/// Adj-RIB-In for this session — the raw received routes before the
/// import hook chain runs — so [`lr_router_soft_reconfig_inbound`] can
/// re-evaluate the policy without re-fetching from the peer. Off by
/// default (FRR's default; the cost is duplicate RIB memory per peer).
/// Must be called after `lr_router_add_bgp_session*` and before
/// `lr_router_start_session`; unknown handles or already-established
/// sessions fail with -2.
#[no_mangle]
pub extern "C" fn lr_router_set_soft_reconfig_inbound(
    r: lr_router_t,
    session: u64,
    enabled: u8,
) -> i32 {
    guarded(
        || {
            let mut router = match unsafe { lock_router(r) } {
                Some(g) => g,
                None => return -1,
            };
            match router.set_session_soft_reconfig_inbound(SessionHandle(session), enabled != 0) {
                Ok(()) => 0,
                Err(error) => {
                    set_last_error(error);
                    -2
                }
            }
        },
        LR_ERR_PANIC,
    )
}

/// FRR `clear ip bgp * soft in` (W2.4): re-evaluate the import policy
/// against the pre-policy Adj-RIB-In for `session`, replacing the
/// session's entries in the post-policy RIB with the re-imported
/// routes.
///
/// Returns the number of routes re-evaluated (as a non-negative
/// integer), or a negative value on error (-1 for an invalid router
/// handle, -2 on unknown session handles). No-ops (returns 0) when
/// the session did not have `soft_reconfig_inbound` enabled — the
/// pre-policy RIB was not retained.
#[no_mangle]
pub extern "C" fn lr_router_soft_reconfig_inbound(r: lr_router_t, session: u64) -> i64 {
    guarded(
        || {
            let mut router = match unsafe { lock_router(r) } {
                Some(g) => g,
                None => return -1,
            };
            match router.soft_reconfig_inbound(SessionHandle(session)) {
                Ok(count) => count as i64,
                Err(error) => {
                    set_last_error(error);
                    -2
                }
            }
        },
        LR_ERR_PANIC as i64,
    )
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
    guarded(
        || {
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
        },
        LR_ERR_PANIC,
    )
}

/// Originate a local IPv4 route: `prefix_addr` is 4 bytes, `prefix_len` is
/// the prefix length, `next_hop` is 4 bytes or NULL. The route is injected
/// into Loc-RIB and advertised to all established BGP peers.
///
/// `prefix_len` must be <= 32; larger values are rejected with -3 before any
/// NLRI is encoded (an out-of-range length would otherwise panic inside the
/// BGP NLRI encoder the first time the route is exported).
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
    guarded(
        || {
            if prefix_addr.is_null() {
                return -1;
            }
            if prefix_len > 32 {
                set_last_error(format!(
                    "invalid IPv4 prefix length {prefix_len}: must be <= 32"
                ));
                return -3;
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
        },
        LR_ERR_PANIC,
    )
}

/// Originate an RFC 8277 labelled IPv4 BGP route (AFI=1, SAFI=4). The
/// label stack is supplied as a flat array of 20-bit label values; the
/// codec wraps each into a `Label` with TC=0, TTL=64, and sets the
/// bottom-of-stack bit on the last entry. Returns 0 on success, negative
/// on error.
///
/// `prefix_len` must be <= 32 (see [`lr_router_originate_v4`]) and
/// `n_labels` must not exceed [`MAX_LABEL_STACK_DEPTH`].
///
/// # Safety
/// `prefix_addr` and `next_hop` (when non-NULL) must point to 4 readable
/// bytes; `labels` must point to `n_labels` readable `uint32_t` values.
#[no_mangle]
pub unsafe extern "C" fn lr_router_originate_labeled_v4(
    r: lr_router_t,
    prefix_addr: *const u8,
    prefix_len: u8,
    labels: *const u32,
    n_labels: usize,
    next_hop: *const u8,
) -> i32 {
    guarded(
        || {
            if prefix_addr.is_null() || (n_labels > 0 && labels.is_null()) {
                return -1;
            }
            if prefix_len > 32 {
                set_last_error(format!(
                    "invalid IPv4 prefix length {prefix_len}: must be <= 32"
                ));
                return -3;
            }
            let mut router = match unsafe { lock_router(r) } {
                Some(g) => g,
                None => return -2,
            };
            let mut addr = [0u8; 4];
            unsafe { addr.copy_from_slice(std::slice::from_raw_parts(prefix_addr, 4)) };
            let stack = build_label_stack(labels, n_labels);
            let Some(stack) = stack else {
                return -3; // invalid label stack (value out of 20-bit range or too deep)
            };
            let nh = if next_hop.is_null() {
                None
            } else {
                let mut n = [0u8; 4];
                unsafe { n.copy_from_slice(std::slice::from_raw_parts(next_hop, 4)) };
                Some(lr_core::addr::IpAddr::V4(n))
            };
            router.originate_labeled(
                lr_core::addr::Prefix::new_v4(addr, prefix_len),
                lr_core::nlri::NlriFamily::IPV4_LABELED_UNICAST,
                stack,
                nh,
            );
            0
        },
        LR_ERR_PANIC,
    )
}

/// Originate an RFC 8277 labelled IPv6 BGP route (AFI=2, SAFI=4). See
/// [`lr_router_originate_labeled_v4`] for the label-stack semantics.
///
/// `prefix_len` must be <= 128; larger values are rejected with -3 before
/// any NLRI is encoded.
///
/// # Safety
/// `prefix_addr` and `next_hop` (when non-NULL) must point to 16 readable
/// bytes; `labels` must point to `n_labels` readable `uint32_t` values.
#[no_mangle]
pub unsafe extern "C" fn lr_router_originate_labeled_v6(
    r: lr_router_t,
    prefix_addr: *const u8,
    prefix_len: u8,
    labels: *const u32,
    n_labels: usize,
    next_hop: *const u8,
) -> i32 {
    guarded(
        || {
            if prefix_addr.is_null() || (n_labels > 0 && labels.is_null()) {
                return -1;
            }
            if prefix_len > 128 {
                set_last_error(format!(
                    "invalid IPv6 prefix length {prefix_len}: must be <= 128"
                ));
                return -3;
            }
            let mut router = match unsafe { lock_router(r) } {
                Some(g) => g,
                None => return -2,
            };
            let mut addr = [0u8; 16];
            unsafe { addr.copy_from_slice(std::slice::from_raw_parts(prefix_addr, 16)) };
            let stack = build_label_stack(labels, n_labels);
            let Some(stack) = stack else {
                return -3; // invalid label stack (value out of 20-bit range or too deep)
            };
            let nh = if next_hop.is_null() {
                None
            } else {
                let mut n = [0u8; 16];
                unsafe { n.copy_from_slice(std::slice::from_raw_parts(next_hop, 16)) };
                Some(lr_core::addr::IpAddr::V6(n))
            };
            router.originate_labeled(
                lr_core::addr::Prefix::new_v6(addr, prefix_len),
                lr_core::nlri::NlriFamily::IPV6_LABELED_UNICAST,
                stack,
                nh,
            );
            0
        },
        LR_ERR_PANIC,
    )
}

/// Build a `LabelStack` from a flat C array of 20-bit label values.
/// Returns `None` (after recording the last error) when any value exceeds
/// `Label::MAX_VALUE` or when `n_labels` exceeds [`MAX_LABEL_STACK_DEPTH`] —
/// the length is validated *before* `from_raw_parts` so a garbage
/// `n_labels` can never construct an invalid slice.
unsafe fn build_label_stack(labels: *const u32, n_labels: usize) -> Option<lr_mpls::LabelStack> {
    if n_labels == 0 {
        return Some(lr_mpls::LabelStack::new());
    }
    if n_labels > MAX_LABEL_STACK_DEPTH {
        set_last_error(format!(
            "label stack too deep: {n_labels} > {MAX_LABEL_STACK_DEPTH}"
        ));
        return None;
    }
    let slice = unsafe { std::slice::from_raw_parts(labels, n_labels) };
    let mut out = Vec::with_capacity(n_labels);
    for v in slice {
        if !lr_mpls::Label::is_valid_value(*v) {
            set_last_error(format!("label value {v} exceeds the 20-bit range"));
            return None;
        }
        out.push(lr_mpls::Label::new(*v));
    }
    Some(lr_mpls::LabelStack::from_vec(out))
}

/// Query the kernel's MPLS platform-labels capability (Linux only).
/// Returns the value of `/proc/sys/net/mpls/platform_labels` (0 when
/// MPLS routing is not enabled, 16 or 20 when it is). On non-Linux
/// platforms this always returns 0.
#[no_mangle]
pub extern "C" fn lr_mpls_platform_labels() -> u32 {
    guarded(
        || {
            #[cfg(target_os = "linux")]
            {
                std::fs::read_to_string("/proc/sys/net/mpls/platform_labels")
                    .ok()
                    .and_then(|s| s.trim().parse().ok())
                    .unwrap_or(0)
            }
            #[cfg(not(target_os = "linux"))]
            {
                0
            }
        },
        0,
    )
}

/// Number of routes currently in Loc-RIB.
#[no_mangle]
pub extern "C" fn lr_router_rib_len(r: lr_router_t) -> i64 {
    guarded(
        || {
            let router = match unsafe { lock_router(r) } {
                Some(g) => g,
                None => return -1,
            };
            router.rib_len() as i64
        },
        LR_ERR_PANIC as i64,
    )
}

/// Dump the Loc-RIB as a text table (one route per line). The caller owns
/// the returned bytes and must free them with `lr_bytes_free`.
///
/// # Safety
/// `out` must point to a valid `lr_bytes_t` slot.
#[no_mangle]
pub unsafe extern "C" fn lr_router_rib_dump(r: lr_router_t, out: *mut lr_bytes_t) -> i32 {
    guarded(
        || {
            if out.is_null() {
                return -1;
            }
            let router = match unsafe { lock_router(r) } {
                Some(g) => g,
                None => return -2,
            };
            let mut text = String::new();
            for route in router.rib_paths_snapshot() {
                use std::fmt::Write as _;
                let _ = writeln!(
                    text,
                    "{}/{} via {} proto={:?} metric={} path-id={}",
                    route.key.prefix,
                    route.key.prefix.prefix_len,
                    route
                        .next_hop
                        .map(|n| n.to_string())
                        .unwrap_or_else(|| "(none)".to_string()),
                    route.protocol,
                    route.preference.metric,
                    route.path_id
                );
            }
            unsafe { *out = lr_bytes_t::from_vec(text.into_bytes()) }
            0
        },
        LR_ERR_PANIC,
    )
}

/// Dump every session's operational summary as a text table (one line
/// per session: handle, kind, ASNs, state, establishment, peer BGP id,
/// negotiated hold time, Adj-RIB-In size). The caller owns the returned
/// bytes and must free them with `lr_bytes_free`.
///
/// # Safety
/// `out` must point to a valid `lr_bytes_t` slot.
#[no_mangle]
pub unsafe extern "C" fn lr_router_sessions_dump(r: lr_router_t, out: *mut lr_bytes_t) -> i32 {
    guarded(
        || {
            if out.is_null() {
                return -1;
            }
            let router = match unsafe { lock_router(r) } {
                Some(g) => g,
                None => return -2,
            };
            let mut text = String::new();
            for s in router.session_summaries() {
                use std::fmt::Write as _;
                let _ = writeln!(
                    text,
                    "#{} kind={} local-as={} peer-as={} state={} established={} peer-id={} \
                     hold-time={} adj-rib-in={}",
                    s.handle.0,
                    s.kind,
                    s.local_as.0,
                    s.peer_as.0,
                    s.state,
                    s.established,
                    s.peer_bgp_id
                        .map(|i| i.to_string())
                        .unwrap_or_else(|| "-".to_string()),
                    s.negotiated_hold_time,
                    s.adj_rib_in_len
                );
            }
            unsafe { *out = lr_bytes_t::from_vec(text.into_bytes()) }
            0
        },
        LR_ERR_PANIC,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::lr_last_error;
    use crate::guard;
    use std::ffi::CStr;

    fn last_error() -> String {
        unsafe { CStr::from_ptr(lr_last_error()) }
            .to_string_lossy()
            .into_owned()
    }

    fn drain_all(r: lr_router_t, session: u64) -> Vec<u8> {
        let mut out = lr_bytes_t {
            ptr: std::ptr::null_mut(),
            len: 0,
            cap: 0,
        };
        assert_eq!(unsafe { lr_router_drain_output(r, session, &mut out) }, 0);
        let bytes = unsafe { std::slice::from_raw_parts(out.ptr, out.len) }.to_vec();
        unsafe { crate::bytes::lr_bytes_free(&mut out) };
        bytes
    }

    /// The `catch_unwind` barrier catches panics and the wrapper records the
    /// documented panic error + last-error string instead of unwinding.
    #[test]
    fn guard_catches_panics_and_guarded_returns_fallback() {
        assert_eq!(guard(|| 42), Some(42));
        assert!(guard(|| -> i32 { panic!("boom") }).is_none());
        // The exact wrapper path used by every entry point:
        assert_eq!(
            guarded(|| -> i32 { panic!("boom") }, LR_ERR_PANIC),
            LR_ERR_PANIC
        );
        assert_eq!(last_error(), "panic caught in FFI");
    }

    #[test]
    fn originate_v4_rejects_prefix_len_33() {
        let r = lr_router_new();
        let addr = [10u8, 0, 0, 1];
        // 33 > 32 must be rejected up front (no panic in the NLRI encoder).
        assert_eq!(
            unsafe { lr_router_originate_v4(r, addr.as_ptr(), 33, std::ptr::null()) },
            -3
        );
        assert!(last_error().contains("prefix length"), "{}", last_error());
        // 32 is the legal maximum.
        assert_eq!(
            unsafe { lr_router_originate_v4(r, addr.as_ptr(), 32, std::ptr::null()) },
            0
        );
        unsafe { unbox_router(r) };
    }

    #[test]
    fn originate_labeled_rejects_out_of_range_prefix_lens() {
        let r = lr_router_new();
        let v4 = [10u8, 0, 0, 1];
        let labels = [100u32];
        assert_eq!(
            unsafe {
                lr_router_originate_labeled_v4(
                    r,
                    v4.as_ptr(),
                    33,
                    labels.as_ptr(),
                    1,
                    std::ptr::null(),
                )
            },
            -3
        );
        let v6 = [0x20u8, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        assert_eq!(
            unsafe {
                lr_router_originate_labeled_v6(
                    r,
                    v6.as_ptr(),
                    129,
                    labels.as_ptr(),
                    1,
                    std::ptr::null(),
                )
            },
            -3
        );
        assert!(last_error().contains("prefix length"), "{}", last_error());
        assert_eq!(
            unsafe {
                lr_router_originate_labeled_v6(
                    r,
                    v6.as_ptr(),
                    128,
                    labels.as_ptr(),
                    1,
                    std::ptr::null(),
                )
            },
            0
        );
        unsafe { unbox_router(r) };
    }

    #[test]
    fn set_local_address_rejects_bad_length_without_ub() {
        let r = lr_router_new();
        let bytes = [1u8, 2, 3]; // 3 bytes: neither 4 (v4) nor 16 (v6)
                                 // Must fail with -3 before any slice of length 3 is constructed.
        assert_eq!(
            unsafe { lr_router_set_local_address(r, 0, 1, bytes.as_ptr(), 3) },
            -3
        );
        // Same for an unknown address family.
        assert_eq!(
            unsafe { lr_router_set_local_address(r, 0, 7, bytes.as_ptr(), 4) },
            -3
        );
        // A valid length reaches the router, which rejects the unknown
        // session handle with -2.
        assert_eq!(
            unsafe { lr_router_set_local_address(r, 0, 1, bytes.as_ptr(), 4) },
            -2
        );
        unsafe { unbox_router(r) };
    }

    #[test]
    fn tuple_count_overflow_is_rejected_before_from_raw_parts() {
        let r = lr_router_new();
        let buf = [0u8; 8];
        // usize::MAX * 5 and usize::MAX * 4 would wrap; both must be
        // rejected before any slice is built.
        assert_eq!(
            unsafe { lr_router_set_extended_next_hop(r, 0, buf.as_ptr(), usize::MAX) },
            -3
        );
        assert_eq!(
            unsafe { lr_router_set_mp_families(r, 0, buf.as_ptr(), usize::MAX) },
            -3
        );
        assert!(last_error().contains("too large"), "{}", last_error());
        unsafe { unbox_router(r) };
    }

    #[test]
    fn label_stack_depth_is_capped() {
        let r = lr_router_new();
        let v4 = [10u8, 0, 0, 1];
        let labels = [0u32; MAX_LABEL_STACK_DEPTH + 1];
        assert_eq!(
            unsafe {
                lr_router_originate_labeled_v4(
                    r,
                    v4.as_ptr(),
                    24,
                    labels.as_ptr(),
                    labels.len(),
                    std::ptr::null(),
                )
            },
            -3
        );
        assert!(last_error().contains("label stack"), "{}", last_error());
        unsafe { unbox_router(r) };
    }

    /// W2.1/BIRD: with the default `default_ipv4_unicast` on and no explicit
    /// families, the OPEN must still advertise the IPv4-unicast MP-BGP
    /// capability (BIRD 2 refuses sessions whose required capability is
    /// missing).
    #[test]
    fn add_bgp_session_ext_advertises_ipv4_unicast_mp_by_default() {
        let r = lr_router_new();
        let mut h = 0u64;
        assert_eq!(
            unsafe {
                lr_router_add_bgp_session_ext(
                    r,
                    64512,
                    64513,
                    0x0a00_0001,
                    90,
                    30,
                    1,
                    1,
                    120,
                    0,
                    0,
                    0,
                    &mut h,
                )
            },
            0
        );
        assert_ne!(h, 0);
        assert_eq!(lr_router_start_session(r, h), 0);
        let open = drain_all(r, h);
        // RFC 4760 multiprotocol capability for (AFI=1, SAFI=1):
        // cap-code 1, cap-len 4, value 00 01 00 01.
        let mp_v4: &[u8] = &[0x01, 0x04, 0x00, 0x01, 0x00, 0x01];
        assert!(
            open.windows(6).any(|w| w == mp_v4),
            "OPEN should advertise the IPv4-unicast MP capability, got {open:?}"
        );
        unsafe { unbox_router(r) };
    }

    /// The FRR `no bgp default ipv4-unicast` posture: with the default
    /// flipped off and no explicit families, the OPEN must NOT advertise
    /// the IPv4-unicast MP capability.
    #[test]
    fn add_bgp_session_ext_omits_ipv4_unicast_mp_when_disabled() {
        let r = lr_router_new();
        let mut h = 0u64;
        assert_eq!(
            unsafe {
                lr_router_add_bgp_session_ext(
                    r,
                    64512,
                    64513,
                    0x0a00_0002,
                    90,
                    30,
                    1,
                    1,
                    120,
                    0,
                    0,
                    0,
                    &mut h,
                )
            },
            0
        );
        // Flip the default off and clear the family list (the embedder's
        // equivalent of FRR `no bgp default ipv4-unicast` with no
        // `neighbor X address-family`).
        assert_eq!(lr_router_set_default_ipv4_unicast(r, h, 0), 0);
        assert_eq!(
            unsafe { lr_router_set_mp_families(r, h, std::ptr::null(), 0) },
            0
        );
        assert_eq!(lr_router_start_session(r, h), 0);
        let open = drain_all(r, h);
        let mp_v4: &[u8] = &[0x01, 0x04, 0x00, 0x01, 0x00, 0x01];
        assert!(
            !open.windows(6).any(|w| w == mp_v4),
            "OPEN must not advertise the IPv4-unicast MP capability, got {open:?}"
        );
        unsafe { unbox_router(r) };
    }
}
