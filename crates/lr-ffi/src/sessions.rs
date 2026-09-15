//! OSPFv2 / OSPFv3 / Babel session management (ROADMAP-v3 D5.1).
//!
//! BGP sessions already had dedicated entries (`lr_router_add_bgp_session`
//! and its `_ext` variant). The link-state and distance-vector engines were
//! unreachable from the C ABI: an embedder could not attach an OSPF area
//! or a Babel interface to a router handle at all.
//!
//! The entries here mirror `SessionConfig`'s protocol builders on
//! `lr-router`:
//!
//! * [`lr_router_add_ospf_session`] / [`lr_router_add_ospfv3_session`] —
//!   the defaults BIRD/FRR ship for a `type ptp` interface (MTU 1500,
//!   point-to-point network, Normal area).
//! * [`lr_router_add_ospf_session_ext`] — the full knob set: area kind
//!   (RFC 2328 §3.6 stub / RFC 3101 NSSA with their totally- variants),
//!   MTU (§10.6), network type (§9.1) and the §10.4 segment identities.
//! * [`lr_router_add_babel_session`] — one interface session keyed by
//!   the local (link-local) address (RFC 8966 §4.2.1).
//!
//! Sessions created here are the router's in-memory sessions: drive them
//! with `lr_router_start_session`, `lr_router_feed_input`,
//! `lr_router_drain_output` and `lr_router_tick`, and read their
//! liveness through `lr_router_poll_events` / `lr_router_sessions_dump` —
//! exactly like BGP.
//!
//! LDP is deliberately absent: `lr-router` has no LDP session kind — the
//! `LdpEngine` lives in `lr-ldp` and is driven by the daemon's discovery
//! and transport threads (UDP/TCP 646), not by `RouterInstance`. An
//! `lr_router_add_ldp_session` would advertise a capability the library
//! does not have; if the engine ever grows a router-level session model
//! the entry lands then (tracked in ROADMAP-v3 D5).
//!
//! # Safety
//!
//! Same contract as the rest of the crate: `catch_unwind` barrier,
//! null checks, documented error codes (`-1` null argument, `-2`
//! invalid router handle, `-3` malformed argument / rejected by the
//! router, [`LR_ERR_PANIC`] on panic).

use crate::error::{set_last_error, LR_ERR_PANIC};
use crate::guarded;
use crate::handle::{lock_router, lr_router_t};
use lr_core::addr::IpAddr;
use lr_router::{OspfAreaType, OspfNetworkType, RouterInstance, SessionConfig, SessionKind};

/// Area kind ids shared by `lr_router_add_ospf_session_ext`. The stub
/// and NSSA kinds carry a `default_metric` (the border-router-injected
/// default route, RFC 2328 §3.6 / RFC 3101 §2.7); the `*_NO_SUMMARY`
/// variants suppress inter-area summaries ("totally stubby / totally
/// NSSA").
pub const LR_AREA_NORMAL: i32 = 0;
pub const LR_AREA_STUB: i32 = 1;
pub const LR_AREA_STUB_NO_SUMMARY: i32 = 2;
pub const LR_AREA_NSSA: i32 = 3;
pub const LR_AREA_NSSA_NO_SUMMARY: i32 = 4;

/// Interface network-type ids (RFC 2328 §9.1), shared by
/// `lr_router_add_ospf_session_ext`.
pub const LR_NET_PTP: i32 = 0;
pub const LR_NET_BROADCAST: i32 = 1;

/// OSPF protocol version selector for `lr_router_add_ospf_session_ext`.
pub const LR_OSPF_V2: i32 = 2;
pub const LR_OSPF_V3: i32 = 3;

fn area_type_from(kind: i32, default_metric: u32) -> Option<OspfAreaType> {
    match kind {
        LR_AREA_NORMAL => Some(OspfAreaType::Normal),
        LR_AREA_STUB => Some(OspfAreaType::stub(default_metric)),
        LR_AREA_STUB_NO_SUMMARY => Some(OspfAreaType::stub_no_summary(default_metric)),
        LR_AREA_NSSA => Some(OspfAreaType::nssa(default_metric)),
        LR_AREA_NSSA_NO_SUMMARY => Some(OspfAreaType::nssa_no_summary(default_metric)),
        _ => None,
    }
}

fn network_type_from(net: i32) -> Option<OspfNetworkType> {
    match net {
        LR_NET_PTP => Some(OspfNetworkType::PointToPoint),
        LR_NET_BROADCAST => Some(OspfNetworkType::Broadcast),
        _ => None,
    }
}

/// Add an OSPFv2 session with the library defaults: MTU 1500,
/// point-to-point network type, Normal (non-stub) area. Returns 0 with
/// the handle written to `out_handle`, `-1` on a null out pointer,
/// `-2` on an invalid router handle, `-3` when the router rejects the
/// configuration (mismatched router-id, area kind conflict, backbone
/// stub — the last-error string says which).
///
/// # Safety
/// `out_handle` must be a writable `u64` when non-null.
#[no_mangle]
pub unsafe extern "C" fn lr_router_add_ospf_session(
    r: lr_router_t,
    router_id: u32,
    area_id: u32,
    out_handle: *mut u64,
) -> i32 {
    guarded(
        || unsafe {
            lr_router_add_ospf_session_ext(
                r,
                LR_OSPF_V2,
                router_id,
                area_id,
                LR_AREA_NORMAL,
                0,
                1500,
                LR_NET_PTP,
                0,
                0,
                0,
                0,
                out_handle,
            )
        },
        LR_ERR_PANIC,
    )
}

/// Add an OSPFv3 session (RFC 5340) with the library defaults. Router
/// IDs stay 32-bit and shared with OSPFv2 within one router; areas are
/// version-exclusive. Return/error codes as
/// [`lr_router_add_ospf_session`].
///
/// # Safety
/// `out_handle` must be a writable `u64` when non-null.
#[no_mangle]
pub unsafe extern "C" fn lr_router_add_ospfv3_session(
    r: lr_router_t,
    router_id: u32,
    area_id: u32,
    out_handle: *mut u64,
) -> i32 {
    guarded(
        || unsafe {
            lr_router_add_ospf_session_ext(
                r,
                LR_OSPF_V3,
                router_id,
                area_id,
                LR_AREA_NORMAL,
                0,
                1500,
                LR_NET_PTP,
                0,
                0,
                0,
                0,
                out_handle,
            )
        },
        LR_ERR_PANIC,
    )
}

/// Add an OSPF session with the full knob set.
///
/// * `version` — [`LR_OSPF_V2`] or [`LR_OSPF_V3`].
/// * `area_kind` — [`LR_AREA_NORMAL`], [`LR_AREA_STUB`],
///   [`LR_AREA_STUB_NO_SUMMARY`], [`LR_AREA_NSSA`],
///   [`LR_AREA_NSSA_NO_SUMMARY`]. The stub/NSSA kinds use
///   `default_metric` for the border-router-injected default route.
/// * `mtu` — interface MTU announced in DBD packets (§10.6); 0 falls
///   back to the 1500 default.
/// * `network_type` — [`LR_NET_PTP`] or [`LR_NET_BROADCAST`] (§9.4;
///   broadcast gates adjacency on the elected DR/BDR, §10.4).
/// * `has_interface_ip` / `interface_ip` — our identity on the segment:
///   the IPv4 interface address on v2 (§10.4, §12.4.1.2) or the Router
///   ID on v3 (RFC 5340 §4.1.2). Ignored when `has_interface_ip` is 0.
/// * `has_neighbor_ip` / `neighbor_ip` — the neighbor's identity on
///   the segment (v2 interface address / v3 Router ID), what the
///   elected DR/BDR is compared against. Ignored when 0.
///
/// Return codes: 0 ok, -1 null out pointer, -2 invalid handle, -3
/// malformed argument (unknown version/area kind/network type) or
/// rejected by the router, [`LR_ERR_PANIC`] on panic.
///
/// # Safety
/// `out_handle` must be a writable `u64` when non-null.
#[no_mangle]
pub unsafe extern "C" fn lr_router_add_ospf_session_ext(
    r: lr_router_t,
    version: i32,
    router_id: u32,
    area_id: u32,
    area_kind: i32,
    default_metric: u32,
    mtu: u16,
    network_type: i32,
    has_interface_ip: i32,
    interface_ip: u32,
    has_neighbor_ip: i32,
    neighbor_ip: u32,
    out_handle: *mut u64,
) -> i32 {
    guarded(
        || {
            if out_handle.is_null() {
                return -1;
            }
            let kind = match version {
                LR_OSPF_V2 => SessionKind::Ospfv2,
                LR_OSPF_V3 => SessionKind::Ospfv3,
                other => {
                    set_last_error(format!("unknown OSPF version {other} (expected 2 or 3)"));
                    return -3;
                }
            };
            let Some(area_type) = area_type_from(area_kind, default_metric) else {
                set_last_error(format!("unknown OSPF area kind {area_kind}"));
                return -3;
            };
            let Some(net) = network_type_from(network_type) else {
                set_last_error(format!("unknown OSPF network type {network_type}"));
                return -3;
            };
            let mut cfg = if version == LR_OSPF_V3 {
                SessionConfig::ospfv3(lr_core::addr::RouterId::from_u32(router_id), area_id)
            } else {
                SessionConfig::ospfv2(lr_core::addr::RouterId::from_u32(router_id), area_id)
            };
            cfg.kind = kind;
            cfg = cfg
                .with_ospf_area_type(area_type)
                .with_ospf_mtu(if mtu == 0 { 1500 } else { mtu })
                .with_ospf_network_type(net);
            if has_interface_ip != 0 {
                cfg = cfg.with_ospf_interface_ip(interface_ip);
            }
            if has_neighbor_ip != 0 {
                cfg = cfg.with_ospf_neighbor_ip(neighbor_ip);
            }
            let mut router = match unsafe { lock_router(r) } {
                Some(g) => g,
                None => return -2,
            };
            match router.add_session(cfg) {
                Ok(h) => {
                    unsafe { *out_handle = h.0 };
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

/// Add one Babel interface session (RFC 8966). `local_addr` is the
/// 16-byte IPv6 address the interface announces in Hellos (§4.2.1) —
/// for IPv4 operation the embedder passes the v4-mapped form
/// (`::ffff:a.b.c.d`, `is_ipv6 = 0` selects the first four bytes).
///
/// Return codes: 0 ok with the handle in `out_handle`, -1 null out
/// pointer, -2 invalid handle, [`LR_ERR_PANIC`] on panic.
///
/// # Safety
/// `local_addr` must be a readable 16-byte array when non-null;
/// `out_handle` must be a writable `u64` when non-null.
#[no_mangle]
pub unsafe extern "C" fn lr_router_add_babel_session(
    r: lr_router_t,
    local_addr: *const u8,
    is_ipv6: i32,
    out_handle: *mut u64,
) -> i32 {
    guarded(
        || {
            if out_handle.is_null() {
                return -1;
            }
            let addr = if is_ipv6 != 0 {
                let mut a = [0u8; 16];
                if !local_addr.is_null() {
                    unsafe { std::ptr::copy_nonoverlapping(local_addr, a.as_mut_ptr(), 16) };
                }
                IpAddr::V6(a)
            } else if local_addr.is_null() {
                IpAddr::V4([0, 0, 0, 0])
            } else {
                let mut a = [0u8; 4];
                unsafe { std::ptr::copy_nonoverlapping(local_addr, a.as_mut_ptr(), 4) };
                IpAddr::V4(a)
            };
            let cfg = SessionConfig::babel(addr);
            let mut router = match unsafe { lock_router(r) } {
                Some(g) => g,
                None => return -2,
            };
            match router.add_session(cfg) {
                Ok(h) => {
                    unsafe { *out_handle = h.0 };
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::handle::box_router;
    use lr_router::DefaultRouter;

    fn r() -> lr_router_t {
        box_router(DefaultRouter::new())
    }

    fn drop_router(r: lr_router_t) {
        unsafe { crate::handle::unbox_router(r) }
    }

    #[test]
    fn ospf_v2_session_attaches_with_defaults() {
        let r = r();
        let mut h: u64 = 0;
        assert_eq!(
            unsafe { lr_router_add_ospf_session(r, 0x0102_0304, 0, &mut h) },
            0
        );
        assert_ne!(h, 0);
        // The router must list exactly one OSPF session now.
        let router = unsafe { lock_router(r) }.unwrap();
        let sums = router.session_summaries();
        assert_eq!(sums.len(), 1);
        assert_eq!(sums[0].kind, "ospf");
        drop(router);
        drop_router(r);
    }

    #[test]
    fn ospf_v3_session_attaches_and_shares_router_id_domain() {
        let r = r();
        let mut h: u64 = 0;
        assert_eq!(
            unsafe { lr_router_add_ospfv3_session(r, 0x0102_0304, 0, &mut h) },
            0
        );
        // A second area on the same router id is fine.
        assert_eq!(
            unsafe { lr_router_add_ospfv3_session(r, 0x0102_0304, 1, &mut h) },
            0
        );
        // A different router id is rejected by the router.
        assert_eq!(
            unsafe { lr_router_add_ospfv3_session(r, 0x0A0B_0C0D, 2, &mut h) },
            -3
        );
        let router = unsafe { lock_router(r) }.unwrap();
        assert_eq!(router.session_summaries().len(), 2);
        drop(router);
        drop_router(r);
    }

    #[test]
    fn ospf_ext_rejects_unknown_enums_but_accepts_stub_area() {
        let r = r();
        let mut h: u64 = 0;
        // Unknown version.
        assert_eq!(
            unsafe {
                lr_router_add_ospf_session_ext(
                    r,
                    4,
                    1,
                    0,
                    LR_AREA_NORMAL,
                    0,
                    1500,
                    LR_NET_PTP,
                    0,
                    0,
                    0,
                    0,
                    &mut h,
                )
            },
            -3
        );
        // Unknown area kind.
        assert_eq!(
            unsafe {
                lr_router_add_ospf_session_ext(
                    r, LR_OSPF_V2, 1, 0, 9, 0, 1500, LR_NET_PTP, 0, 0, 0, 0, &mut h,
                )
            },
            -3
        );
        // Unknown network type.
        assert_eq!(
            unsafe {
                lr_router_add_ospf_session_ext(
                    r,
                    LR_OSPF_V2,
                    1,
                    0,
                    LR_AREA_NORMAL,
                    0,
                    1500,
                    7,
                    0,
                    0,
                    0,
                    0,
                    &mut h,
                )
            },
            -3
        );
        // Null out pointer.
        assert_eq!(
            unsafe {
                lr_router_add_ospf_session_ext(
                    r,
                    LR_OSPF_V2,
                    1,
                    0,
                    LR_AREA_NORMAL,
                    0,
                    1500,
                    LR_NET_PTP,
                    0,
                    0,
                    0,
                    0,
                    std::ptr::null_mut(),
                )
            },
            -1
        );
        // RFC 2328 §3.6: the backbone cannot be a stub.
        assert_eq!(
            unsafe {
                lr_router_add_ospf_session_ext(
                    r,
                    LR_OSPF_V2,
                    1,
                    0,
                    LR_AREA_STUB,
                    1000,
                    1500,
                    LR_NET_PTP,
                    0,
                    0,
                    0,
                    0,
                    &mut h,
                )
            },
            -3
        );
        // A legal stub area with the segment identities attaches.
        assert_eq!(
            unsafe {
                lr_router_add_ospf_session_ext(
                    r,
                    LR_OSPF_V2,
                    1,
                    1,
                    LR_AREA_STUB_NO_SUMMARY,
                    1000,
                    1500,
                    LR_NET_BROADCAST,
                    1,
                    0x0A00_0001,
                    1,
                    0x0A00_0002,
                    &mut h,
                )
            },
            0
        );
        drop_router(r);
    }

    #[test]
    fn babel_session_attaches_v4_and_v6() {
        let r = r();
        let mut h: u64 = 0;
        // fe80::1
        let v6 = [0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        assert_eq!(
            unsafe { lr_router_add_babel_session(r, v6.as_ptr(), 1, &mut h) },
            0
        );
        // 192.0.2.1 in the v4-mapped short form.
        let v4 = [192, 0, 2, 1];
        assert_eq!(
            unsafe { lr_router_add_babel_session(r, v4.as_ptr(), 0, &mut h) },
            0
        );
        let router = unsafe { lock_router(r) }.unwrap();
        let sums = router.session_summaries();
        assert_eq!(sums.len(), 2);
        assert!(sums.iter().all(|s| s.kind == "babel"));
        drop(router);
        drop_router(r);
    }

    #[test]
    fn babel_null_out_pointer_is_an_error() {
        let r = r();
        let v6 = [0xfeu8; 16];
        assert_eq!(
            unsafe { lr_router_add_babel_session(r, v6.as_ptr(), 1, std::ptr::null_mut()) },
            -1
        );
        drop_router(r);
    }

    #[test]
    fn invalid_router_handle_is_an_error() {
        let mut h: u64 = 0;
        assert_eq!(
            unsafe { lr_router_add_ospf_session(std::ptr::null_mut(), 1, 0, &mut h) },
            -2
        );
        assert_eq!(
            unsafe {
                lr_router_add_babel_session(std::ptr::null_mut(), std::ptr::null(), 0, &mut h)
            },
            -2
        );
    }
}
