//! lr-bgp `PeerConfig` + lr-srv6 `Srh` accessors + lr-rib `AdjRib`
//! accessors gap closure (issue #92).
//!
//! Mirrors the public Rust API of:
//! - `lr_bgp::peer::PeerConfig` — per-peer configuration, foundational
//!   type used by `BgpPeer::new`. Previously unreachable from C.
//! - `lr_srv6::srh::Srh::current_destination` / `len` / `is_empty` /
//!   `hdr_ext_len` / `decode` standalone.
//! - `lr_rib::adj_rib_in::AdjRibIn::get` / `origins_for` / `clear` /
//!   `clear_for`.
//! - `lr_rib::adj_rib_out::AdjRibOut::tx_path_ids` / `paths_for` /
//!   `advertised_keys` / `clear` / `clear_for`.

#![allow(unused_unsafe)]
#![allow(clippy::field_reassign_with_default)]

use lr_bgp::peer::PeerConfig;
use lr_core::addr::{Asn, RouterId};

use crate::core::{lr_route_key_t, lr_route_origin_t};
use crate::error::{LrError, LR_ERR_PANIC};
use crate::guarded;
use crate::handle::lr_route_t;
use crate::rib::{lr_adj_rib_in_t, lr_adj_rib_out_t};

const LR_ERR_NULL: i32 = LrError::Null as i32;

// ---- PeerConfig surface ----

/// Opaque `PeerConfig` handle. C side never touches internals.
#[repr(C)]
pub struct OpaquePeerConfig {
    _private: [u8; 0],
}
pub type lr_bgp_peer_config_t = *mut OpaquePeerConfig;

fn box_cfg(c: PeerConfig) -> lr_bgp_peer_config_t {
    Box::into_raw(Box::new(c)) as lr_bgp_peer_config_t
}
unsafe fn unbox_cfg(c: lr_bgp_peer_config_t) -> Option<Box<PeerConfig>> {
    if c.is_null() {
        return None;
    }
    Some(unsafe { Box::from_raw(c as *mut PeerConfig) })
}
unsafe fn borrow_cfg(c: lr_bgp_peer_config_t) -> Option<&'static PeerConfig> {
    if c.is_null() {
        return None;
    }
    Some(unsafe { &*(c as *const PeerConfig) })
}
unsafe fn borrow_cfg_mut(c: lr_bgp_peer_config_t) -> Option<&'static mut PeerConfig> {
    if c.is_null() {
        return None;
    }
    Some(unsafe { &mut *(c as *mut PeerConfig) })
}

/// Construct a `PeerConfig` with default hold_time=90, asn4=true,
/// route_refresh=true, enhanced_rr=true, default_ipv4_unicast=true.
///
/// # Safety
/// `local_bgp_id` must point to 4 readable bytes (the BGP identifier
/// in network byte order).
#[no_mangle]
pub unsafe extern "C" fn lr_bgp_peer_config_new(
    local_as: u32,
    peer_as: u32,
    local_bgp_id: *const u8,
) -> lr_bgp_peer_config_t {
    guarded(
        || unsafe {
            if local_bgp_id.is_null() {
                return std::ptr::null_mut();
            }
            let mut id = [0u8; 4];
            id.copy_from_slice(unsafe { std::slice::from_raw_parts(local_bgp_id, 4) });
            let cfg = PeerConfig::new(Asn(local_as), Asn(peer_as), RouterId::from_v4(id));
            box_cfg(cfg)
        },
        std::ptr::null_mut(),
    )
}

/// Drop a boxed `PeerConfig`. Safe to call with NULL.
///
/// # Safety
/// `c` must have been produced by a `lr_bgp_peer_config_*` constructor
/// and must not be used after this call.
#[no_mangle]
pub unsafe extern "C" fn lr_bgp_peer_config_free(c: lr_bgp_peer_config_t) {
    guarded(
        || unsafe {
            drop(unbox_cfg(c));
        },
        (),
    )
}

/// Read the local AS.
#[no_mangle]
pub unsafe extern "C" fn lr_bgp_peer_config_local_as(c: lr_bgp_peer_config_t) -> u32 {
    guarded(
        || unsafe { borrow_cfg(c).map(|x| x.local_as.0).unwrap_or(0) },
        0,
    )
}

/// Read the peer AS.
#[no_mangle]
pub unsafe extern "C" fn lr_bgp_peer_config_peer_as(c: lr_bgp_peer_config_t) -> u32 {
    guarded(
        || unsafe { borrow_cfg(c).map(|x| x.peer_as.0).unwrap_or(0) },
        0,
    )
}

/// Read the local BGP identifier as a 32-bit value (network byte
/// order — write `*out`'s bytes back to a `RouterId::from_v4` to
/// reconstruct).
#[no_mangle]
pub unsafe extern "C" fn lr_bgp_peer_config_local_bgp_id(
    c: lr_bgp_peer_config_t,
    out: *mut u32,
) -> i32 {
    guarded(
        || unsafe {
            let Some(x) = borrow_cfg(c) else {
                return LR_ERR_NULL;
            };
            if out.is_null() {
                return LR_ERR_NULL;
            }
            unsafe { *out = x.local_bgp_id.0 }
            0
        },
        LR_ERR_PANIC,
    )
}

/// Read the proposed hold time (seconds). 0 = use peer's value.
#[no_mangle]
pub unsafe extern "C" fn lr_bgp_peer_config_hold_time(c: lr_bgp_peer_config_t) -> u16 {
    guarded(
        || unsafe { borrow_cfg(c).map(|x| x.hold_time).unwrap_or(0) },
        0,
    )
}

/// Read the keepalive interval (seconds). 0 = hold_time / 3.
#[no_mangle]
pub unsafe extern "C" fn lr_bgp_peer_config_keepalive(c: lr_bgp_peer_config_t) -> u16 {
    guarded(
        || unsafe { borrow_cfg(c).map(|x| x.keepalive).unwrap_or(0) },
        0,
    )
}

/// True when 4-byte AS capability is enabled.
#[no_mangle]
pub unsafe extern "C" fn lr_bgp_peer_config_asn4(c: lr_bgp_peer_config_t) -> u8 {
    guarded(
        || unsafe { borrow_cfg(c).map(|x| x.asn4 as u8).unwrap_or(0) },
        0,
    )
}

/// True when route-refresh (RFC 2918) is enabled.
#[no_mangle]
pub unsafe extern "C" fn lr_bgp_peer_config_route_refresh(c: lr_bgp_peer_config_t) -> u8 {
    guarded(
        || unsafe { borrow_cfg(c).map(|x| x.route_refresh as u8).unwrap_or(0) },
        0,
    )
}

/// True when enhanced route-refresh (RFC 7313) is enabled.
#[no_mangle]
pub unsafe extern "C" fn lr_bgp_peer_config_enhanced_rr(c: lr_bgp_peer_config_t) -> u8 {
    guarded(
        || unsafe { borrow_cfg(c).map(|x| x.enhanced_rr as u8).unwrap_or(0) },
        0,
    )
}

/// True when graceful restart (RFC 4724) is enabled.
#[no_mangle]
pub unsafe extern "C" fn lr_bgp_peer_config_graceful_restart(c: lr_bgp_peer_config_t) -> u8 {
    guarded(
        || unsafe { borrow_cfg(c).map(|x| x.graceful_restart as u8).unwrap_or(0) },
        0,
    )
}

/// Read the graceful-restart time (seconds).
#[no_mangle]
pub unsafe extern "C" fn lr_bgp_peer_config_graceful_restart_time(c: lr_bgp_peer_config_t) -> u16 {
    guarded(
        || unsafe { borrow_cfg(c).map(|x| x.graceful_restart_time).unwrap_or(0) },
        0,
    )
}

/// True when long-lived graceful restart (RFC 9494) is enabled.
#[no_mangle]
pub unsafe extern "C" fn lr_bgp_peer_config_long_lived(c: lr_bgp_peer_config_t) -> u8 {
    guarded(
        || unsafe { borrow_cfg(c).map(|x| x.long_lived as u8).unwrap_or(0) },
        0,
    )
}

/// Read the LLGR stale time (seconds).
#[no_mangle]
pub unsafe extern "C" fn lr_bgp_peer_config_long_lived_stale_time(c: lr_bgp_peer_config_t) -> u32 {
    guarded(
        || unsafe { borrow_cfg(c).map(|x| x.long_lived_stale_time).unwrap_or(0) },
        0,
    )
}

/// True when this is a route-reflector client.
#[no_mangle]
pub unsafe extern "C" fn lr_bgp_peer_config_is_rr_client(c: lr_bgp_peer_config_t) -> u8 {
    guarded(
        || unsafe {
            borrow_cfg(c)
                .map(|x| x.route_reflector_client as u8)
                .unwrap_or(0)
        },
        0,
    )
}

/// True when this is a route-server client.
#[no_mangle]
pub unsafe extern "C" fn lr_bgp_peer_config_is_rs_client(c: lr_bgp_peer_config_t) -> u8 {
    guarded(
        || unsafe {
            borrow_cfg(c)
                .map(|x| x.route_server.client as u8)
                .unwrap_or(0)
        },
        0,
    )
}

/// True when default IPv4 unicast is active.
#[no_mangle]
pub unsafe extern "C" fn lr_bgp_peer_config_default_ipv4_unicast(c: lr_bgp_peer_config_t) -> u8 {
    guarded(
        || unsafe {
            borrow_cfg(c)
                .map(|x| x.default_ipv4_unicast as u8)
                .unwrap_or(0)
        },
        0,
    )
}

/// True when AddPath (RFC 7911) is enabled.
#[no_mangle]
pub unsafe extern "C" fn lr_bgp_peer_config_add_path(c: lr_bgp_peer_config_t) -> u8 {
    guarded(
        || unsafe { borrow_cfg(c).map(|x| x.add_path as u8).unwrap_or(0) },
        0,
    )
}

/// True when this is an eBGP session (peer in a different AS).
#[no_mangle]
pub unsafe extern "C" fn lr_bgp_peer_config_is_ebgp(c: lr_bgp_peer_config_t) -> u8 {
    guarded(
        || unsafe { borrow_cfg(c).map(|x| x.is_ebgp() as u8).unwrap_or(0) },
        0,
    )
}

/// Read the keepalive interval derived from hold_time (RFC 4271
/// §10 — `hold_time / 3` when `keepalive == 0`).
#[no_mangle]
pub unsafe extern "C" fn lr_bgp_peer_config_keepalive_interval(c: lr_bgp_peer_config_t) -> u16 {
    guarded(
        || unsafe { borrow_cfg(c).map(|x| x.keepalive_interval()).unwrap_or(0) },
        0,
    )
}

/// True when IPv4 unicast is active (either explicit MP family or the
/// implicit default).
#[no_mangle]
pub unsafe extern "C" fn lr_bgp_peer_config_ipv4_unicast_active(c: lr_bgp_peer_config_t) -> u8 {
    guarded(
        || unsafe {
            borrow_cfg(c)
                .map(|x| x.ipv4_unicast_active() as u8)
                .unwrap_or(0)
        },
        0,
    )
}

/// Read the peer role (one of `LR_PEER_ROLE_*` constants). Returns 255
/// on a NULL handle (no valid role).
#[no_mangle]
pub unsafe extern "C" fn lr_bgp_peer_config_peer_role(c: lr_bgp_peer_config_t) -> u8 {
    guarded(
        || unsafe { borrow_cfg(c).map(|x| x.peer_role() as u8).unwrap_or(255) },
        255,
    )
}

/// Set the hold time (seconds). 0 = use peer's value.
///
/// # Safety
/// `c` must be a live handle.
#[no_mangle]
pub unsafe extern "C" fn lr_bgp_peer_config_set_hold_time(
    c: lr_bgp_peer_config_t,
    hold_time: u16,
) -> i32 {
    guarded(
        || unsafe {
            let Some(x) = borrow_cfg_mut(c) else {
                return LR_ERR_NULL;
            };
            x.hold_time = hold_time;
            0
        },
        LR_ERR_PANIC,
    )
}

/// Set the keepalive interval (seconds). 0 = hold_time / 3.
///
/// # Safety
/// `c` must be a live handle.
#[no_mangle]
pub unsafe extern "C" fn lr_bgp_peer_config_set_keepalive(
    c: lr_bgp_peer_config_t,
    keepalive: u16,
) -> i32 {
    guarded(
        || unsafe {
            let Some(x) = borrow_cfg_mut(c) else {
                return LR_ERR_NULL;
            };
            x.keepalive = keepalive;
            0
        },
        LR_ERR_PANIC,
    )
}

/// Enable or disable 4-byte AS capability.
///
/// # Safety
/// `c` must be a live handle.
#[no_mangle]
pub unsafe extern "C" fn lr_bgp_peer_config_set_asn4(c: lr_bgp_peer_config_t, asn4: u8) -> i32 {
    guarded(
        || unsafe {
            let Some(x) = borrow_cfg_mut(c) else {
                return LR_ERR_NULL;
            };
            x.asn4 = asn4 != 0;
            0
        },
        LR_ERR_PANIC,
    )
}

/// Enable or disable the route-reflector-client flag.
///
/// # Safety
/// `c` must be a live handle.
#[no_mangle]
pub unsafe extern "C" fn lr_bgp_peer_config_set_rr_client(
    c: lr_bgp_peer_config_t,
    enabled: u8,
) -> i32 {
    guarded(
        || unsafe {
            let Some(x) = borrow_cfg_mut(c) else {
                return LR_ERR_NULL;
            };
            x.route_reflector_client = enabled != 0;
            0
        },
        LR_ERR_PANIC,
    )
}

/// Enable or disable graceful restart.
///
/// # Safety
/// `c` must be a live handle.
#[no_mangle]
pub unsafe extern "C" fn lr_bgp_peer_config_set_graceful_restart(
    c: lr_bgp_peer_config_t,
    enabled: u8,
) -> i32 {
    guarded(
        || unsafe {
            let Some(x) = borrow_cfg_mut(c) else {
                return LR_ERR_NULL;
            };
            x.graceful_restart = enabled != 0;
            0
        },
        LR_ERR_PANIC,
    )
}

// ---- SRv6 Srh accessors ----

use crate::srv6_srh::{borrow_srh_pub, lr_srv6_srh_t};

/// Read the SRH's `current_destination` — the SID at
/// `segments_left` (the destination the packet is currently
/// forwarded to). Writes the 16-byte SID to `*out`. Returns 0 on
/// success, 1 when the SRH has no segments, `LR_ERR_NULL` on a NULL
/// handle / pointer.
///
/// # Safety
/// `srh` must be a live handle. `out` must point to 16 writable bytes.
#[no_mangle]
pub unsafe extern "C" fn lr_srv6_srh_current_destination(srh: lr_srv6_srh_t, out: *mut u8) -> i32 {
    guarded(
        || unsafe {
            let Some(s) = borrow_srh_pub(srh) else {
                return LR_ERR_NULL;
            };
            if out.is_null() {
                return LR_ERR_NULL;
            }
            match s.current_destination() {
                Some(sid) => {
                    unsafe {
                        std::ptr::copy_nonoverlapping(sid.as_slice().as_ptr(), out, 16);
                    }
                    0
                }
                None => 1,
            }
        },
        LR_ERR_PANIC,
    )
}

/// Wire length of the SRH (8 fixed + 16 per segment). Returns 0 on a
/// NULL handle (the safe default).
#[no_mangle]
pub unsafe extern "C" fn lr_srv6_srh_len(srh: lr_srv6_srh_t) -> usize {
    guarded(
        || unsafe { borrow_srh_pub(srh).map(|s| s.len()).unwrap_or(0) },
        0,
    )
}

/// True when the SRH carries no segments. Returns 1 on a NULL handle
/// (the safe default).
#[no_mangle]
pub unsafe extern "C" fn lr_srv6_srh_is_empty(srh: lr_srv6_srh_t) -> u8 {
    guarded(
        || unsafe { borrow_srh_pub(srh).map(|s| s.is_empty() as u8).unwrap_or(1) },
        1,
    )
}

/// `Hdr Ext Len` field (RFC 8754 §2.1 — the routing extension
/// header's length in 8-octet units, excluding the first 8 octets).
#[no_mangle]
pub unsafe extern "C" fn lr_srv6_srh_hdr_ext_len(srh: lr_srv6_srh_t) -> u8 {
    guarded(
        || unsafe { borrow_srh_pub(srh).map(|s| s.hdr_ext_len()).unwrap_or(0) },
        0,
    )
}

// ---- AdjRibIn accessors ----

use lr_core::rib::RouteOrigin;

fn origin_to_rust(o: lr_route_origin_t) -> RouteOrigin {
    RouteOrigin {
        proto: o.protocol as u32,
        peer: o.peer,
    }
}

/// Look up a route by `(origin, key, path_id)`. Returns 1 when found
/// (and writes a copy of the route's bytes to `*out_route` —
/// embedder frees with `lr_route_free`), 0 when absent, `LR_ERR_NULL`
/// on a NULL handle / pointer.
///
/// # Safety
/// `r` must be a live AdjRibIn handle. `key` must point to a readable
/// `lr_route_key_t`. `out_route` must point to a writable
/// `lr_route_t`.
#[no_mangle]
pub unsafe extern "C" fn lr_adj_rib_in_get(
    r: lr_adj_rib_in_t,
    origin: lr_route_origin_t,
    key: *const lr_route_key_t,
    path_id: u32,
    out_route: *mut lr_route_t,
) -> i32 {
    guarded(
        || unsafe {
            if key.is_null() || out_route.is_null() {
                return LR_ERR_NULL;
            }
            let Some(rib) = crate::rib::borrow_adj_rib_in_pub(r) else {
                return LR_ERR_NULL;
            };
            let key_rust = crate::core::route_key_from_c(&unsafe { *key });
            let origin_rust = origin_to_rust(origin);
            match rib.get(origin_rust, &key_rust, path_id) {
                Some(route) => {
                    // Box a clone so the caller owns it via lr_route_free.
                    let boxed = Box::new(route.clone());
                    unsafe { *out_route = Box::into_raw(boxed) as lr_route_t }
                    1
                }
                None => 0,
            }
        },
        LR_ERR_PANIC,
    )
}

/// Count the origins that have a route for `key`. Returns the count,
/// or `LR_ERR_NULL` (-1) on a NULL handle / pointer.
///
/// # Safety
/// `r` must be a live AdjRibIn handle. `key` must point to a readable
/// `lr_route_key_t`. `out_origins` must point to a writable array of
/// `lr_route_origin_t` with capacity `cap`. The actual count is
/// written to `*out_count`.
#[no_mangle]
pub unsafe extern "C" fn lr_adj_rib_in_origins_for(
    r: lr_adj_rib_in_t,
    key: *const lr_route_key_t,
    out_origins: *mut lr_route_origin_t,
    cap: usize,
    out_count: *mut usize,
) -> i32 {
    guarded(
        || unsafe {
            if key.is_null() || out_count.is_null() {
                return LR_ERR_NULL;
            }
            let Some(rib) = crate::rib::borrow_adj_rib_in_pub(r) else {
                return LR_ERR_NULL;
            };
            let key_rust = crate::core::route_key_from_c(&unsafe { *key });
            let mut count = 0usize;
            for o in rib.origins_for(&key_rust) {
                if count < cap && !out_origins.is_null() {
                    unsafe {
                        *out_origins.add(count) = lr_route_origin_t {
                            protocol: o.proto as u8,
                            peer: o.peer,
                        };
                    }
                }
                count += 1;
            }
            unsafe { *out_count = count }
            0
        },
        LR_ERR_PANIC,
    )
}

/// Drop every route from every origin. The RIB becomes empty.
///
/// # Safety
/// `r` must be a live AdjRibIn handle.
#[no_mangle]
pub unsafe extern "C" fn lr_adj_rib_in_clear(r: lr_adj_rib_in_t) -> i32 {
    guarded(
        || unsafe {
            let Some(rib) = crate::rib::borrow_adj_rib_in_mut_pub(r) else {
                return LR_ERR_NULL;
            };
            rib.clear();
            0
        },
        LR_ERR_PANIC,
    )
}

/// Drop every route from one origin.
///
/// # Safety
/// `r` must be a live AdjRibIn handle.
#[no_mangle]
pub unsafe extern "C" fn lr_adj_rib_in_clear_for(
    r: lr_adj_rib_in_t,
    origin: lr_route_origin_t,
) -> i32 {
    guarded(
        || unsafe {
            let Some(rib) = crate::rib::borrow_adj_rib_in_mut_pub(r) else {
                return LR_ERR_NULL;
            };
            rib.clear_for(origin_to_rust(origin));
            0
        },
        LR_ERR_PANIC,
    )
}

// ---- AdjRibOut accessors ----

/// Read the TX path IDs advertised to `dest` for `key`. Writes up to
/// `cap` IDs to `*out_path_ids` and the actual count to
/// `*out_count`.
///
/// # Safety
/// `r` must be a live AdjRibOut handle. `key` must point to a
/// readable `lr_route_key_t`. `out_path_ids` must point to a
/// writable array of `uint32_t` with capacity `cap`.
#[no_mangle]
pub unsafe extern "C" fn lr_adj_rib_out_tx_path_ids(
    r: lr_adj_rib_out_t,
    dest: lr_route_origin_t,
    key: *const lr_route_key_t,
    out_path_ids: *mut u32,
    cap: usize,
    out_count: *mut usize,
) -> i32 {
    guarded(
        || unsafe {
            if key.is_null() || out_count.is_null() {
                return LR_ERR_NULL;
            }
            let Some(rib) = crate::rib::borrow_adj_rib_out_pub(r) else {
                return LR_ERR_NULL;
            };
            let key_rust = crate::core::route_key_from_c(&unsafe { *key });
            let ids = rib.tx_path_ids(origin_to_rust(dest), &key_rust);
            let count = ids.len().min(cap);
            if !out_path_ids.is_null() {
                for (i, id) in ids.iter().take(count).enumerate() {
                    unsafe { *out_path_ids.add(i) = *id }
                }
            }
            unsafe { *out_count = ids.len() }
            0
        },
        LR_ERR_PANIC,
    )
}

/// Drop every advertised route. The RIB becomes empty.
///
/// # Safety
/// `r` must be a live AdjRibOut handle.
#[no_mangle]
pub unsafe extern "C" fn lr_adj_rib_out_clear(r: lr_adj_rib_out_t) -> i32 {
    guarded(
        || unsafe {
            let Some(rib) = crate::rib::borrow_adj_rib_out_mut_pub(r) else {
                return LR_ERR_NULL;
            };
            rib.clear();
            0
        },
        LR_ERR_PANIC,
    )
}

/// Drop every advertised route for one destination.
///
/// # Safety
/// `r` must be a live AdjRibOut handle.
#[no_mangle]
pub unsafe extern "C" fn lr_adj_rib_out_clear_for(
    r: lr_adj_rib_out_t,
    dest: lr_route_origin_t,
) -> i32 {
    guarded(
        || unsafe {
            let Some(rib) = crate::rib::borrow_adj_rib_out_mut_pub(r) else {
                return LR_ERR_NULL;
            };
            rib.clear_for(origin_to_rust(dest));
            0
        },
        LR_ERR_PANIC,
    )
}

/// Walk every advertised path of `(dest, key)` — the full
/// `(tx_path_id, route)` pair, not just the TX path identifiers
/// [`lr_adj_rib_out_tx_path_ids`] surfaces. The callback fires once per
/// stored path, ascending by `tx_path_id`. Returns the number of
/// paths visited, or `LR_ERR_NULL` (-1) on a NULL handle / pointer /
/// callback.
///
/// The route handle passed to the callback is *borrowed* — the
/// Adj-RIB-Out owns the underlying `Route` for the duration of the
/// walk. The callback MUST NOT call `lr_route_free` on it, and MUST NOT
/// mutate the Adj-RIB-Out (the borrow is held for the duration of the
/// walk; re-entrancy is undefined).
///
/// Mirrors `lr_rib::adj_rib_out::AdjRibOut::paths_for`.
///
/// # Safety
/// `r` must be a live AdjRibOut handle. `key` must point to a readable
/// `lr_route_key_t`. `cb` must be a non-NULL function pointer that
/// respects the borrowing contract above.
#[no_mangle]
pub unsafe extern "C" fn lr_adj_rib_out_paths_for(
    r: lr_adj_rib_out_t,
    dest: lr_route_origin_t,
    key: *const lr_route_key_t,
    cb: Option<unsafe extern "C" fn(path_id: u32, route: lr_route_t, user: *mut core::ffi::c_void)>,
    user: *mut core::ffi::c_void,
) -> i64 {
    guarded(
        || unsafe {
            if key.is_null() {
                return -1;
            }
            let Some(cb_fn) = cb else {
                return -1;
            };
            let Some(rib) = crate::rib::borrow_adj_rib_out_pub(r) else {
                return -1;
            };
            let key_rust = crate::core::route_key_from_c(&unsafe { *key });
            let paths = rib.paths_for(origin_to_rust(dest), &key_rust);
            let mut count: i64 = 0;
            for (path_id, route) in paths.iter() {
                // SAFETY: caller's cb must not free the handle and must
                // not re-enter the Adj-RIB-Out for the duration of the
                // walk (the borrow is held).
                let h: lr_route_t =
                    route as *const lr_core::rib::Route as *mut crate::handle::OpaqueRoute;
                unsafe { cb_fn(*path_id, h, user) };
                count += 1;
            }
            count
        },
        -1,
    )
}

/// Walk every key advertised to `dest` belonging to `family` — the
/// full `(RouteKey, Vec<tx_path_id>)` pair, ascending by `RouteKey`.
/// Returns the number of keys visited, or `LR_ERR_NULL` (-1) on a
/// NULL handle / callback.
///
/// The callback receives a *borrowed* `lr_route_key_t` pointer and a
/// *borrowed* `uint32_t` array; the underlying storage lives only for
/// the duration of one callback invocation. The callback MUST copy any
/// data it needs to persist before returning.
///
/// Mirrors `lr_rib::adj_rib_out::AdjRibOut::advertised_keys`.
///
/// # Safety
/// `r` must be a live AdjRibOut handle. `cb` must be a non-NULL
/// function pointer that respects the borrowing contract above.
#[no_mangle]
pub unsafe extern "C" fn lr_adj_rib_out_advertised_keys(
    r: lr_adj_rib_out_t,
    dest: lr_route_origin_t,
    afi: u16,
    safi: u8,
    cb: Option<
        unsafe extern "C" fn(
            key: *const lr_route_key_t,
            path_ids: *const u32,
            path_id_count: usize,
            user: *mut core::ffi::c_void,
        ),
    >,
    user: *mut core::ffi::c_void,
) -> i64 {
    guarded(
        || unsafe {
            let Some(cb_fn) = cb else {
                return -1;
            };
            let Some(rib) = crate::rib::borrow_adj_rib_out_pub(r) else {
                return -1;
            };
            let family = lr_core::nlri::NlriFamily { afi, safi };
            let entries = rib.advertised_keys(origin_to_rust(dest), family);
            let mut count: i64 = 0;
            for (key, ids) in entries.iter() {
                let key_c = crate::core::route_key_to_c(key);
                // Pass the ids slice as a raw pointer + length. The
                // slice lives only for this callback invocation.
                let ids_ptr = if ids.is_empty() {
                    std::ptr::null()
                } else {
                    ids.as_ptr()
                };
                unsafe { cb_fn(&key_c, ids_ptr, ids.len(), user) };
                count += 1;
            }
            count
        },
        -1,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ffi_peer_config_new_and_readers() {
        let id = [10u8, 0, 0, 1];
        let c = unsafe { lr_bgp_peer_config_new(64512, 64513, id.as_ptr()) };
        assert!(!c.is_null());
        assert_eq!(unsafe { lr_bgp_peer_config_local_as(c) }, 64512);
        assert_eq!(unsafe { lr_bgp_peer_config_peer_as(c) }, 64513);
        let mut bgp_id = 0u32;
        assert_eq!(
            unsafe { lr_bgp_peer_config_local_bgp_id(c, &raw mut bgp_id) },
            0
        );
        assert_eq!(bgp_id, 0x0a000001);
        assert_eq!(unsafe { lr_bgp_peer_config_hold_time(c) }, 90);
        assert_eq!(unsafe { lr_bgp_peer_config_asn4(c) }, 1);
        assert_eq!(unsafe { lr_bgp_peer_config_route_refresh(c) }, 1);
        assert_eq!(unsafe { lr_bgp_peer_config_enhanced_rr(c) }, 1);
        assert_eq!(unsafe { lr_bgp_peer_config_graceful_restart(c) }, 0);
        assert_eq!(unsafe { lr_bgp_peer_config_default_ipv4_unicast(c) }, 1);
        assert_eq!(unsafe { lr_bgp_peer_config_add_path(c) }, 0);
        assert_eq!(unsafe { lr_bgp_peer_config_is_ebgp(c) }, 1);
        assert_eq!(unsafe { lr_bgp_peer_config_ipv4_unicast_active(c) }, 1);
        // keepalive_interval is hold_time / 3 = 30.
        assert_eq!(unsafe { lr_bgp_peer_config_keepalive_interval(c) }, 30);
        unsafe { lr_bgp_peer_config_free(c) };
    }

    #[test]
    fn ffi_peer_config_setters() {
        let id = [10u8, 0, 0, 1];
        let c = unsafe { lr_bgp_peer_config_new(64512, 64513, id.as_ptr()) };
        assert_eq!(unsafe { lr_bgp_peer_config_set_hold_time(c, 180) }, 0);
        assert_eq!(unsafe { lr_bgp_peer_config_set_keepalive(c, 60) }, 0);
        assert_eq!(unsafe { lr_bgp_peer_config_set_asn4(c, 0) }, 0);
        assert_eq!(unsafe { lr_bgp_peer_config_set_rr_client(c, 1) }, 0);
        assert_eq!(unsafe { lr_bgp_peer_config_set_graceful_restart(c, 1) }, 0);
        assert_eq!(unsafe { lr_bgp_peer_config_hold_time(c) }, 180);
        assert_eq!(unsafe { lr_bgp_peer_config_keepalive(c) }, 60);
        assert_eq!(unsafe { lr_bgp_peer_config_asn4(c) }, 0);
        assert_eq!(unsafe { lr_bgp_peer_config_is_rr_client(c) }, 1);
        assert_eq!(unsafe { lr_bgp_peer_config_graceful_restart(c) }, 1);
        unsafe { lr_bgp_peer_config_free(c) };
    }

    #[test]
    fn ffi_peer_config_free_handles_null() {
        unsafe { lr_bgp_peer_config_free(std::ptr::null_mut()) };
    }

    #[test]
    fn ffi_peer_config_local_as_returns_zero_on_null() {
        assert_eq!(
            unsafe { lr_bgp_peer_config_local_as(std::ptr::null_mut()) },
            0
        );
    }

    #[test]
    fn ffi_adj_rib_in_clear_on_empty() {
        let r = crate::rib::lr_adj_rib_in_new();
        assert_eq!(unsafe { lr_adj_rib_in_clear(r) }, 0);
        assert_eq!(unsafe { crate::rib::lr_adj_rib_in_len(r) }, 0);
        assert_eq!(unsafe { crate::rib::lr_adj_rib_in_is_empty(r) }, 1);
        unsafe { crate::rib::lr_adj_rib_in_free(r) };
    }

    #[test]
    fn ffi_adj_rib_in_clear_for_origin() {
        let r = crate::rib::lr_adj_rib_in_new();
        let origin = lr_route_origin_t {
            protocol: 0, // BGP
            peer: 1,
        };
        assert_eq!(unsafe { lr_adj_rib_in_clear_for(r, origin) }, 0);
        unsafe { crate::rib::lr_adj_rib_in_free(r) };
    }

    #[test]
    fn ffi_adj_rib_out_clear_on_empty() {
        let r = crate::rib::lr_adj_rib_out_new();
        assert_eq!(unsafe { lr_adj_rib_out_clear(r) }, 0);
        assert_eq!(unsafe { crate::rib::lr_adj_rib_out_is_empty(r) }, 1);
        unsafe { crate::rib::lr_adj_rib_out_free(r) };
    }

    // ---- AdjRibOut::paths_for / advertised_keys ----

    /// Minimal v4 route for AdjRibOut tests — the Adj-RIB-Out clones
    /// every advertised route, so we can drop the handle immediately.
    fn build_route_v4(prefix: [u8; 4], plen: u8) -> lr_route_t {
        let route = lr_core::rib::Route {
            key: lr_core::rib::RouteKey::new(
                lr_core::addr::Prefix::new_v4(prefix, plen),
                lr_core::nlri::NlriFamily::IPV4_UNICAST,
            ),
            origin: RouteOrigin { proto: 0, peer: 0 },
            protocol: lr_core::rib::Protocol::Bgp,
            preference: lr_core::rib::Preference::new(100, 0),
            next_hop: None,
            attributes: lr_core::attr::Attributes::new(),
            age_ms: 0,
            path_id: 0,
            tag: None,
        };
        Box::into_raw(Box::new(route)) as lr_route_t
    }

    fn build_route_v6(prefix: [u8; 16], plen: u8) -> lr_route_t {
        let route = lr_core::rib::Route {
            key: lr_core::rib::RouteKey::new(
                lr_core::addr::Prefix::new_v6(prefix, plen),
                lr_core::nlri::NlriFamily::IPV6_UNICAST,
            ),
            origin: RouteOrigin { proto: 0, peer: 0 },
            protocol: lr_core::rib::Protocol::Bgp,
            preference: lr_core::rib::Preference::new(100, 0),
            next_hop: None,
            attributes: lr_core::attr::Attributes::new(),
            age_ms: 0,
            path_id: 0,
            tag: None,
        };
        Box::into_raw(Box::new(route)) as lr_route_t
    }

    fn build_key_v4(addr: [u8; 4], prefix_len: u8) -> lr_route_key_t {
        let mut k = lr_route_key_t::default();
        k.prefix.addr.is_ipv6 = 0;
        k.prefix.addr.octets[12..16].copy_from_slice(&addr);
        k.prefix.prefix_len = prefix_len;
        k.afi_safi = (1u16 << 8) | 1u16;
        k.has_source = 0;
        k
    }

    #[test]
    fn ffi_adj_rib_out_paths_for_visits_each_advertised_path() {
        // Counter callback: records the (path_id, route_addr) pairs.
        extern "C" fn collector(path_id: u32, route: lr_route_t, user: *mut core::ffi::c_void) {
            unsafe {
                let r: &lr_core::rib::Route = &*(route as *const lr_core::rib::Route);
                let (addr, plen) = match r.key.prefix.addr {
                    lr_core::addr::IpAddr::V4(b) => (b.to_vec(), r.key.prefix.prefix_len),
                    lr_core::addr::IpAddr::V6(b) => (b.to_vec(), r.key.prefix.prefix_len),
                };
                let bag: &mut Vec<(u32, Vec<u8>, u8)> =
                    &mut *(user as *mut Vec<(u32, Vec<u8>, u8)>);
                bag.push((path_id, addr, plen));
            }
        }

        let rib = crate::rib::lr_adj_rib_out_new();
        let dest = lr_route_origin_t {
            protocol: 0, // BGP
            peer: 7,
        };
        let key = build_key_v4([203, 0, 113, 0], 24);
        // Advertise two paths for the same key under different path IDs.
        let r1 = build_route_v4([203, 0, 113, 0], 24);
        let rc = unsafe {
            crate::rib::lr_adj_rib_out_advertise(rib, dest.peer, dest.protocol as i32, r1, 1)
        };
        assert_eq!(rc, 0);
        // r1 was cloned into the RIB; drop our copy.
        unsafe { crate::policy_objects::lr_route_free(r1) };
        let r2 = build_route_v4([203, 0, 113, 0], 24);
        let rc = unsafe {
            crate::rib::lr_adj_rib_out_advertise(rib, dest.peer, dest.protocol as i32, r2, 2)
        };
        assert_eq!(rc, 0);
        unsafe { crate::policy_objects::lr_route_free(r2) };

        let mut seen: Vec<(u32, Vec<u8>, u8)> = Vec::new();
        let rc = unsafe {
            lr_adj_rib_out_paths_for(
                rib,
                dest,
                &key,
                Some(collector),
                &raw mut seen as *mut core::ffi::c_void,
            )
        };
        assert_eq!(rc, 2, "paths_for visited {rc} paths, expected 2");
        assert_eq!(seen.len(), 2);
        // Path IDs ascending.
        assert_eq!(seen[0].0, 1);
        assert_eq!(seen[1].0, 2);
        // Each route is the v4 prefix we advertised.
        assert_eq!(seen[0].1, vec![203, 0, 113, 0]);
        assert_eq!(seen[0].2, 24);

        // NULL handle / NULL key / NULL cb → -1.
        let rc = unsafe {
            lr_adj_rib_out_paths_for(
                std::ptr::null_mut(),
                dest,
                &key,
                Some(collector),
                std::ptr::null_mut(),
            )
        };
        assert_eq!(rc, -1);
        let rc = unsafe {
            lr_adj_rib_out_paths_for(
                rib,
                dest,
                std::ptr::null(),
                Some(collector),
                std::ptr::null_mut(),
            )
        };
        assert_eq!(rc, -1);
        let rc = unsafe { lr_adj_rib_out_paths_for(rib, dest, &key, None, std::ptr::null_mut()) };
        assert_eq!(rc, -1);

        // Empty result for an unknown key.
        let unknown_key = build_key_v4([10, 0, 0, 0], 8);
        let mut empty: Vec<(u32, Vec<u8>, u8)> = Vec::new();
        let rc = unsafe {
            lr_adj_rib_out_paths_for(
                rib,
                dest,
                &unknown_key,
                Some(collector),
                &raw mut empty as *mut core::ffi::c_void,
            )
        };
        assert_eq!(rc, 0, "paths_for on unknown key returns 0 visited");
        assert!(empty.is_empty());

        unsafe { crate::rib::lr_adj_rib_out_free(rib) };
    }

    #[test]
    fn ffi_adj_rib_out_advertised_keys_filters_by_dest_and_family() {
        // Collector: record (key_prefix, key_is_ipv6, path_ids).
        extern "C" fn collector(
            key: *const lr_route_key_t,
            path_ids: *const u32,
            path_id_count: usize,
            user: *mut core::ffi::c_void,
        ) {
            unsafe {
                let k = &*key;
                let (addr, is_ipv6) = if k.prefix.addr.is_ipv6 != 0 {
                    (k.prefix.addr.octets.to_vec(), true)
                } else {
                    (k.prefix.addr.octets[12..16].to_vec(), false)
                };
                let ids: Vec<u32> = if path_ids.is_null() || path_id_count == 0 {
                    Vec::new()
                } else {
                    std::slice::from_raw_parts(path_ids, path_id_count).to_vec()
                };
                let bag: &mut Vec<(Vec<u8>, u8, bool, Vec<u32>)> =
                    &mut *(user as *mut Vec<(Vec<u8>, u8, bool, Vec<u32>)>);
                bag.push((addr, k.prefix.prefix_len, is_ipv6, ids));
            }
        }

        let rib = crate::rib::lr_adj_rib_out_new();
        let dest = lr_route_origin_t {
            protocol: 0,
            peer: 7,
        };
        // v4 path under tx_path_id = 1.
        let r_v4 = build_route_v4([203, 0, 113, 0], 24);
        let rc = unsafe {
            crate::rib::lr_adj_rib_out_advertise(rib, dest.peer, dest.protocol as i32, r_v4, 1)
        };
        assert_eq!(rc, 0);
        unsafe { crate::policy_objects::lr_route_free(r_v4) };
        // v6 path under tx_path_id = 1.
        let r_v6 = build_route_v6(
            [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            32,
        );
        let rc = unsafe {
            crate::rib::lr_adj_rib_out_advertise(rib, dest.peer, dest.protocol as i32, r_v6, 1)
        };
        assert_eq!(rc, 0);
        unsafe { crate::policy_objects::lr_route_free(r_v6) };

        // Filter: v4 unicast (AFI=1, SAFI=1) → only the v4 key.
        let mut seen: Vec<(Vec<u8>, u8, bool, Vec<u32>)> = Vec::new();
        let rc = unsafe {
            lr_adj_rib_out_advertised_keys(
                rib,
                dest,
                1, // AFI_IPV4
                1, // SAFI_UNICAST
                Some(collector),
                &raw mut seen as *mut core::ffi::c_void,
            )
        };
        assert_eq!(
            rc, 1,
            "advertised_keys for v4 returned {rc} keys, expected 1"
        );
        assert_eq!(seen.len(), 1);
        assert!(!seen[0].2, "v4 key has is_ipv6=false");
        assert_eq!(seen[0].0, vec![203, 0, 113, 0]);
        assert_eq!(seen[0].1, 24);
        assert_eq!(seen[0].3, vec![1], "one tx path id");

        // Filter: v6 unicast (AFI=2, SAFI=1) → only the v6 key.
        let mut seen: Vec<(Vec<u8>, u8, bool, Vec<u32>)> = Vec::new();
        let rc = unsafe {
            lr_adj_rib_out_advertised_keys(
                rib,
                dest,
                2, // AFI_IPV6
                1, // SAFI_UNICAST
                Some(collector),
                &raw mut seen as *mut core::ffi::c_void,
            )
        };
        assert_eq!(
            rc, 1,
            "advertised_keys for v6 returned {rc} keys, expected 1"
        );
        assert_eq!(seen.len(), 1);
        assert!(seen[0].2, "v6 key has is_ipv6=true");

        // Filter: v4 labelled-unicast (AFI=1, SAFI=4) → no keys.
        let mut seen: Vec<(Vec<u8>, u8, bool, Vec<u32>)> = Vec::new();
        let rc = unsafe {
            lr_adj_rib_out_advertised_keys(
                rib,
                dest,
                1,
                4, // SAFI_LABELED_UNICAST
                Some(collector),
                &raw mut seen as *mut core::ffi::c_void,
            )
        };
        assert_eq!(rc, 0);
        assert!(seen.is_empty());

        // Wrong destination peer → no keys.
        let other_dest = lr_route_origin_t {
            protocol: 0,
            peer: 99,
        };
        let mut seen: Vec<(Vec<u8>, u8, bool, Vec<u32>)> = Vec::new();
        let rc = unsafe {
            lr_adj_rib_out_advertised_keys(
                rib,
                other_dest,
                1,
                1,
                Some(collector),
                &raw mut seen as *mut core::ffi::c_void,
            )
        };
        assert_eq!(rc, 0);

        // NULL handle / NULL cb → -1.
        let rc = unsafe {
            lr_adj_rib_out_advertised_keys(
                std::ptr::null_mut(),
                dest,
                1,
                1,
                Some(collector),
                std::ptr::null_mut(),
            )
        };
        assert_eq!(rc, -1);
        let rc =
            unsafe { lr_adj_rib_out_advertised_keys(rib, dest, 1, 1, None, std::ptr::null_mut()) };
        assert_eq!(rc, -1);

        unsafe { crate::rib::lr_adj_rib_out_free(rib) };
    }
}
