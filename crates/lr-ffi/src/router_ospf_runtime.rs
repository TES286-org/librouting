//! `RouterInstance` OSPF runtime hooks — virtual-link management and
//! AS-external redistribution that were previously unreachable from
//! the C ABI. The Rust `DefaultRouter` already implements the
//! underlying methods (RFC 2328 §15 virtual links, §12.4.3 type-5
//! origination, RFC 5340 §4.4.3.6 v3 AS-external origination,
//! RFC 3101 §2.4 / §2.5 type-7 NSSA handling, the ASBR `E`-bit
//! inspection the daemon's Router-LSA originator uses to re-originate
//! on the ASBR flip), but the FFI surface only exposed the
//! per-session OSPF *config* (area-kind / mtu / network-type via
//! `lr_router_add_ospf_session_ext`) and the LSDB *readers*
//! (`lr_router_ospf_area_count` / `_area_id_at` /
//! `_area_topology_version` / `_area_lsa`). An embedder driving the
//! daemon-equivalent runtime could not configure a virtual link,
//! redistribute a route, drop a redistribution intent, or check the
//! ASBR flag without dropping down to Rust.
//!
//! The functions here mirror the trait surface in
//! `crates/lr-router/src/instance/mod.rs` one-to-one so a C embedder
//! can drive the OSPF runtime the same way the daemon's OSPF module
//! does. The v3 plane gets its own external-destination handle
//! (`lr_ospf_v3_external_dest_t`) — `V3ExternalDestination`'s shape
//! differs from `ExternalDestination` (the forwarding address is an
//! IPv6 16-byte array rather than a 32-bit IPv4 word, and there is no
//! `p_bit` field — the P-bit rides in the prefix-options byte the
//! v3 LSA header carries), so the v2 `lr_ospf_external_dest_t`
//! handle cannot be reused.
//!
//! Every entry point runs inside the crate's `catch_unwind` barrier
//! ([`crate::guarded`]): a panic returns `LR_ERR_PANIC` and sets the
//! thread-local last-error string. The router handle is locked for
//! the duration of the call so the OSPF area map and the
//! redistribution intent tables cannot race with a parallel
//! `lr_router_tick` or `lr_router_feed_input`.

#![allow(unused_unsafe)]

use lr_core::addr::Prefix;
use lr_ospf::external::ExternalDestination;
use lr_ospf::lsa::V3ExternalDestination;

use crate::core::lr_core_prefix_t;
use crate::error::{set_last_error, LrError, LR_ERR_PANIC};
use crate::guarded;
use crate::handle::{lock_router, lr_router_t};
use crate::ospf_external::borrow_dest;

const LR_ERR_NULL: i32 = LrError::Null as i32;
const LR_ERR_INVALID_HANDLE: i32 = LrError::InvalidHandle as i32;

// =========================================================================
// V3ExternalDestination — opaque handle (RFC 5340 §4.4.3.6 / §A.4.7).
// =========================================================================

/// Opaque `V3ExternalDestination` handle. Wraps a boxed
/// `lr_ospf::lsa::V3ExternalDestination` (the v3 plane's AS-external
/// / NSSA-LSA origination input). C side never touches internals.
#[repr(C)]
pub struct OpaqueOspfV3ExternalDest {
    _private: [u8; 0],
}

pub type lr_ospf_v3_external_dest_t = *mut OpaqueOspfV3ExternalDest;

fn box_v3_dest(d: V3ExternalDestination) -> lr_ospf_v3_external_dest_t {
    Box::into_raw(Box::new(d)) as lr_ospf_v3_external_dest_t
}

unsafe fn borrow_v3_dest(d: lr_ospf_v3_external_dest_t) -> Option<&'static V3ExternalDestination> {
    if d.is_null() {
        return None;
    }
    Some(unsafe { &*(d as *const V3ExternalDestination) })
}

unsafe fn unbox_v3_dest(d: lr_ospf_v3_external_dest_t) -> Option<Box<V3ExternalDestination>> {
    if d.is_null() {
        return None;
    }
    Some(unsafe { Box::from_raw(d as *mut V3ExternalDestination) })
}

/// Construct an `V3ExternalDestination` for OSPFv3 AS-external / NSSA
/// origination (RFC 5340 §A.4.7). The `prefix_v4` / `prefix_v6` slots
/// follow the same convention as the rest of the FFI: pass exactly
/// one of them, the other NULL. `metric_type2` is `1` for a Type-2
/// external metric (E bit set) or `0` for Type-1; the metric is
/// capped just below LSInfinity (`0x00ff_fffe`).
///
/// Returns a non-NULL owned handle on success, NULL on a bad
/// prefix-pointer pair (the last-error string is set). Free with
/// [`lr_ospf_v3_external_dest_free`].
///
/// # Safety
/// `prefix_v6` must point to 16 readable bytes when non-NULL; v4 is
/// rejected because the v3 plane carries IPv6 prefixes only.
#[no_mangle]
pub unsafe extern "C" fn lr_ospf_v3_external_dest_new(
    prefix_v4: *const u8,
    prefix_v6: *const u8,
    prefix_len: u8,
    metric: u32,
    metric_type2: u8,
) -> lr_ospf_v3_external_dest_t {
    guarded(
        || unsafe {
            if !prefix_v4.is_null() {
                set_last_error(
                    "lr_ospf_v3_external_dest_new: v3 plane carries IPv6 prefixes only — pass prefix_v6".into(),
                );
                return std::ptr::null_mut();
            }
            if prefix_v6.is_null() {
                set_last_error("lr_ospf_v3_external_dest_new: prefix_v6 is NULL".into());
                return std::ptr::null_mut();
            }
            let b = unsafe { std::slice::from_raw_parts(prefix_v6, 16) };
            let mut octets = [0u8; 16];
            octets.copy_from_slice(b);
            let prefix = Prefix::new_v6(octets, prefix_len);
            let d = V3ExternalDestination::new(prefix, metric, metric_type2 != 0);
            box_v3_dest(d)
        },
        std::ptr::null_mut(),
    )
}

/// Set the IPv6 forwarding address (RFC 5340 §A.4.7 `F` bit). When
/// set, traffic for the prefix is forwarded directly to the FA rather
/// than to the ASBR. The address MUST be a global IPv6 address —
/// unspecified and link-local values are illegal and rejected by the
/// router's redistribute entry point. Pass 16 zero bytes to clear.
///
/// # Safety
/// `d` must be a valid handle; `addr` must point to 16 readable bytes.
#[no_mangle]
pub unsafe extern "C" fn lr_ospf_v3_external_dest_set_forwarding_addr(
    d: lr_ospf_v3_external_dest_t,
    addr: *const u8,
) -> i32 {
    guarded(
        || unsafe {
            if d.is_null() {
                return LR_ERR_NULL;
            }
            if addr.is_null() {
                set_last_error("lr_ospf_v3_external_dest_set_forwarding_addr: addr NULL".into());
                return LR_ERR_NULL;
            }
            let b = unsafe { std::slice::from_raw_parts(addr, 16) };
            let mut octets = [0u8; 16];
            octets.copy_from_slice(b);
            // SAFETY: the caller guarantees no concurrent access —
            // same no-race contract as the rest of the FFI.
            (*(d as *mut V3ExternalDestination)).forwarding_addr = Some(octets);
            0
        },
        LR_ERR_PANIC,
    )
}

/// Clear the IPv6 forwarding address (the `F` bit drops, traffic
/// forwards to the ASBR).
///
/// # Safety
/// `d` must be a valid handle.
#[no_mangle]
pub unsafe extern "C" fn lr_ospf_v3_external_dest_clear_forwarding_addr(
    d: lr_ospf_v3_external_dest_t,
) -> i32 {
    guarded(
        || unsafe {
            if d.is_null() {
                return LR_ERR_NULL;
            }
            (*(d as *mut V3ExternalDestination)).forwarding_addr = None;
            0
        },
        LR_ERR_PANIC,
    )
}

/// Set the external route tag (RFC 5340 §A.4.7 `T` bit).
///
/// # Safety
/// `d` must be a valid handle.
#[no_mangle]
pub unsafe extern "C" fn lr_ospf_v3_external_dest_set_route_tag(
    d: lr_ospf_v3_external_dest_t,
    route_tag: u32,
) -> i32 {
    guarded(
        || unsafe {
            if d.is_null() {
                return LR_ERR_NULL;
            }
            (*(d as *mut V3ExternalDestination)).route_tag = Some(route_tag);
            0
        },
        LR_ERR_PANIC,
    )
}

/// Clear the external route tag.
///
/// # Safety
/// `d` must be a valid handle.
#[no_mangle]
pub unsafe extern "C" fn lr_ospf_v3_external_dest_clear_route_tag(
    d: lr_ospf_v3_external_dest_t,
) -> i32 {
    guarded(
        || unsafe {
            if d.is_null() {
                return LR_ERR_NULL;
            }
            (*(d as *mut V3ExternalDestination)).route_tag = None;
            0
        },
        LR_ERR_PANIC,
    )
}

/// Read the prefix into `out` (an `lr_core_prefix_t*`). Returns 0 on
/// success, `LR_ERR_NULL` when the handle is NULL.
///
/// # Safety
/// `d` must be a valid handle; `out` must point to writable
/// `lr_core_prefix_t`.
#[no_mangle]
pub unsafe extern "C" fn lr_ospf_v3_external_dest_prefix(
    d: lr_ospf_v3_external_dest_t,
    out: *mut lr_core_prefix_t,
) -> i32 {
    guarded(
        || unsafe {
            if d.is_null() {
                return LR_ERR_NULL;
            }
            if out.is_null() {
                set_last_error("lr_ospf_v3_external_dest_prefix: out NULL".into());
                return LR_ERR_NULL;
            }
            let dest = unsafe { &*(d as *const V3ExternalDestination) };
            unsafe {
                *out = dest.prefix.into();
            }
            0
        },
        LR_ERR_PANIC,
    )
}

/// Read the configured metric. `0` for a NULL handle (defensive).
#[no_mangle]
pub extern "C" fn lr_ospf_v3_external_dest_metric(d: lr_ospf_v3_external_dest_t) -> u32 {
    guarded(
        || unsafe { borrow_v3_dest(d).map(|x| x.metric).unwrap_or(0) },
        0,
    )
}

/// `1` when the metric is Type-2 (E bit set), `0` for Type-1, `0` for
/// a NULL handle (defensive — Type-1 is the safer default).
#[no_mangle]
pub extern "C" fn lr_ospf_v3_external_dest_type2(d: lr_ospf_v3_external_dest_t) -> u8 {
    guarded(
        || unsafe { borrow_v3_dest(d).map(|x| x.type2 as u8).unwrap_or(0) },
        0,
    )
}

/// Read the configured IPv6 forwarding address. Writes the 16-byte
/// address into `out_addr` and returns `1` when the F bit is set;
/// returns `0` (and leaves `out_addr` untouched) when the F bit is
/// clear or the handle is NULL.
///
/// # Safety
/// `d` must be a valid handle; `out_addr` must point to 16 writable
/// bytes when non-NULL (NULL `out_addr` returns `LR_ERR_NULL`).
#[no_mangle]
pub unsafe extern "C" fn lr_ospf_v3_external_dest_forwarding_addr(
    d: lr_ospf_v3_external_dest_t,
    out_addr: *mut u8,
) -> i32 {
    guarded(
        || unsafe {
            if d.is_null() {
                return LR_ERR_NULL;
            }
            if out_addr.is_null() {
                set_last_error("lr_ospf_v3_external_dest_forwarding_addr: out_addr NULL".into());
                return LR_ERR_NULL;
            }
            let dest = unsafe { &*(d as *const V3ExternalDestination) };
            match dest.forwarding_addr {
                Some(a) => {
                    unsafe {
                        std::ptr::copy_nonoverlapping(a.as_ptr(), out_addr, 16);
                    }
                    1
                }
                None => 0,
            }
        },
        LR_ERR_PANIC,
    )
}

/// Read the configured external route tag. Writes the tag into
/// `out_tag` and returns `1` when the T bit is set; returns `0` (and
/// leaves `out_tag` untouched) when the T bit is clear or the handle
/// is NULL.
///
/// # Safety
/// `d` must be a valid handle; `out_tag` must point to a writable
/// `uint32_t` when non-NULL.
#[no_mangle]
pub unsafe extern "C" fn lr_ospf_v3_external_dest_route_tag(
    d: lr_ospf_v3_external_dest_t,
    out_tag: *mut u32,
) -> i32 {
    guarded(
        || unsafe {
            if d.is_null() {
                return LR_ERR_NULL;
            }
            if out_tag.is_null() {
                set_last_error("lr_ospf_v3_external_dest_route_tag: out_tag NULL".into());
                return LR_ERR_NULL;
            }
            let dest = unsafe { &*(d as *const V3ExternalDestination) };
            match dest.route_tag {
                Some(t) => {
                    unsafe {
                        *out_tag = t;
                    }
                    1
                }
                None => 0,
            }
        },
        LR_ERR_PANIC,
    )
}

/// Drop a boxed `V3ExternalDestination`. Safe to call with `NULL`.
///
/// # Safety
/// `d` must have been produced by
/// [`lr_ospf_v3_external_dest_new`] and not already freed.
#[no_mangle]
pub unsafe extern "C" fn lr_ospf_v3_external_dest_free(d: lr_ospf_v3_external_dest_t) {
    guarded(
        || unsafe {
            drop(unbox_v3_dest(d));
        },
        (),
    );
}

// =========================================================================
// OSPF virtual-link management (RFC 2328 §15 + RFC 3101 §2.1).
// =========================================================================

/// Configure a virtual link to the area border router `endpoint`,
/// riding through `transit_area` (RFC 2328 §15). Both endpoints
/// must configure each other; the link is up as soon as this
/// router's transit-area SPF reaches the endpoint. While up it
/// materializes a backbone (area 0) adjacency.
///
/// Return codes: `1` when the link was added, `0` when OSPF is not
/// active, the transit area is not attached, runs OSPFv3 or is a
/// stub/NSSA area (§15: virtual links cannot cross stub areas; RFC
/// 3101 §2.1 extends this to NSSAs), the endpoint is this router
/// itself, or the link already exists; `-1` null out pointer,
/// `-2` invalid handle, [`LR_ERR_PANIC`] on panic.
///
/// # Safety
/// `r` must be a valid `lr_router_t`.
#[no_mangle]
pub unsafe extern "C" fn lr_router_ospf_add_virtual_link(
    r: lr_router_t,
    transit_area: u32,
    endpoint: u32,
) -> i32 {
    guarded(
        || unsafe {
            let mut router = match unsafe { lock_router(r) } {
                Some(g) => g,
                None => return LR_ERR_INVALID_HANDLE,
            };
            i32::from(router.ospf_add_virtual_link(transit_area, endpoint))
        },
        LR_ERR_PANIC,
    )
}

/// Remove a configured virtual link, tearing down its backbone
/// adjacency (and the routes it justified) when it was up. Returns
/// whether the link existed.
///
/// Return codes: `1` when the link existed and was removed, `0`
/// when no such link was configured, `-2` invalid handle,
/// [`LR_ERR_PANIC`] on panic.
///
/// # Safety
/// `r` must be a valid `lr_router_t`.
#[no_mangle]
pub unsafe extern "C" fn lr_router_ospf_remove_virtual_link(
    r: lr_router_t,
    transit_area: u32,
    endpoint: u32,
) -> i32 {
    guarded(
        || unsafe {
            let mut router = match unsafe { lock_router(r) } {
                Some(g) => g,
                None => return LR_ERR_INVALID_HANDLE,
            };
            i32::from(router.ospf_remove_virtual_link(transit_area, endpoint))
        },
        LR_ERR_PANIC,
    )
}

/// Whether the virtual link through `transit_area` to `endpoint` is
/// currently up (RFC 2328 §15: the endpoint is intra-area reachable
/// through the transit area).
///
/// Return codes: `1` up, `0` down or unknown, `-2` invalid handle,
/// [`LR_ERR_PANIC`] on panic.
///
/// # Safety
/// `r` must be a valid `lr_router_t`.
#[no_mangle]
pub unsafe extern "C" fn lr_router_ospf_virtual_link_up(
    r: lr_router_t,
    transit_area: u32,
    endpoint: u32,
) -> i32 {
    guarded(
        || unsafe {
            let router = match unsafe { lock_router(r) } {
                Some(g) => g,
                None => return LR_ERR_INVALID_HANDLE,
            };
            i32::from(router.ospf_virtual_link_up(transit_area, endpoint))
        },
        LR_ERR_PANIC,
    )
}

/// The backbone session handle of an up virtual link — the embedder
/// wires its transport: drain it with `lr_router_drain_output` and
/// deliver the bytes to the peer endpoint's virtual session
/// (tunnelled through the transit area), feeding what returns the
/// same way. Writes `0` into `*out_handle` (and returns `0`) when
/// the link is down.
///
/// Return codes: `1` when `*out_handle` was written (link up), `0`
/// when the link is down (no session), `-1` null out pointer, `-2`
/// invalid handle, [`LR_ERR_PANIC`] on panic.
///
/// # Safety
/// `r` must be a valid `lr_router_t`; `out_handle` must point to a
/// writable `uint64_t` when non-NULL.
#[no_mangle]
pub unsafe extern "C" fn lr_router_ospf_virtual_link_session(
    r: lr_router_t,
    transit_area: u32,
    endpoint: u32,
    out_handle: *mut u64,
) -> i32 {
    guarded(
        || unsafe {
            if out_handle.is_null() {
                set_last_error("lr_router_ospf_virtual_link_session: out_handle NULL".into());
                return LR_ERR_NULL;
            }
            let router = match unsafe { lock_router(r) } {
                Some(g) => g,
                None => return LR_ERR_INVALID_HANDLE,
            };
            match router.ospf_virtual_link_session(transit_area, endpoint) {
                Some(h) => {
                    unsafe {
                        *out_handle = h.0;
                    }
                    1
                }
                None => {
                    unsafe {
                        *out_handle = 0;
                    }
                    0
                }
            }
        },
        LR_ERR_PANIC,
    )
}

// =========================================================================
// OSPF AS-external redistribution (RFC 2328 §12.4.3 / RFC 5340 §4.4.3.6).
// =========================================================================

/// Redistribute one external destination on the OSPFv2 plane (RFC
/// 2328 §12.4.3): originate a type-5 AS-external-LSA (and a type-7
/// NSSA-LSA in NSSA areas) into every attached OSPFv2 area and
/// remember the destination so areas that attach later catch up.
/// The `dest` handle is *borrowed* (the caller still owns it and
/// must free it via `lr_ospf_external_dest_free`).
///
/// Return codes: `1` when the redistribution intent was recorded
/// (and the type-5 / type-7 LSA was originated into every attached
/// area; the LSA may not be installed when no OSPFv2 area is
/// attached yet — the intent replays when the first area
/// attaches), `0` when the destination's prefix is not IPv4 (the
/// v2 plane carries IPv4 prefixes only — use
/// [`lr_router_ospf_redistribute_v3`] for IPv6), `-1` NULL handle,
/// `-2` invalid router handle, [`LR_ERR_PANIC`] on panic.
///
/// # Safety
/// `r` must be a valid `lr_router_t`; `dest` must be a valid
/// `lr_ospf_external_dest_t` (NULL is rejected).
#[no_mangle]
pub unsafe extern "C" fn lr_router_ospf_redistribute(
    r: lr_router_t,
    dest: crate::ospf_external::lr_ospf_external_dest_t,
) -> i32 {
    guarded(
        || unsafe {
            let Some(dest_val) = borrow_dest(dest) else {
                return LR_ERR_NULL;
            };
            // Clone because `ospf_redistribute` takes the destination
            // by value — the caller still owns the handle and frees
            // it via `lr_ospf_external_dest_free`.
            let dest_clone: ExternalDestination = *dest_val;
            let mut router = match unsafe { lock_router(r) } {
                Some(g) => g,
                None => return LR_ERR_INVALID_HANDLE,
            };
            i32::from(router.ospf_redistribute(dest_clone))
        },
        LR_ERR_PANIC,
    )
}

/// Drop the redistribution intent covering `prefix` on the OSPFv2
/// plane (RFC 2328 §12.4.3, RFC 3101 §2.4): MaxAge-flush the
/// self-originated type-5 LSA (regular areas) and type-7 LSA (NSSAs)
/// from every area and flood the flush. The v3 plane takes over
/// automatically for IPv6 prefixes.
///
/// Return codes: `1` when a matching redistribution existed and was
/// flushed, `0` when no matching redistribution exists, `-2`
/// invalid router handle, [`LR_ERR_PANIC`] on panic.
///
/// # Safety
/// `r` must be a valid `lr_router_t`.
#[no_mangle]
pub unsafe extern "C" fn lr_router_ospf_unredistribute(
    r: lr_router_t,
    prefix: lr_core_prefix_t,
) -> i32 {
    guarded(
        || unsafe {
            let mut router = match unsafe { lock_router(r) } {
                Some(g) => g,
                None => return LR_ERR_INVALID_HANDLE,
            };
            let p: Prefix = prefix.into();
            i32::from(router.ospf_unredistribute(p))
        },
        LR_ERR_PANIC,
    )
}

/// Redistribute one external destination on the OSPFv3 plane (RFC
/// 5340 §4.4.3.6): originate a 0x4005 AS-external-LSA into every
/// attached OSPFv3 area. The `dest` handle is *borrowed* (the caller
/// still owns it and must free it via
/// [`lr_ospf_v3_external_dest_free`]). The forwarding address, when
/// set, must be a global IPv6 address — unspecified and link-local
/// values are illegal (§A.4.7) and the router rejects them with
/// `0`.
///
/// Return codes: `1` when the redistribution intent was recorded,
/// `0` when the destination's prefix is not IPv6 (the v3 plane
/// carries IPv6 prefixes only — use [`lr_router_ospf_redistribute`]
/// for IPv4) or the forwarding address is illegal, `-1` NULL
/// handle, `-2` invalid router handle, [`LR_ERR_PANIC`] on panic.
///
/// # Safety
/// `r` must be a valid `lr_router_t`; `dest` must be a valid
/// `lr_ospf_v3_external_dest_t` (NULL is rejected).
#[no_mangle]
pub unsafe extern "C" fn lr_router_ospf_redistribute_v3(
    r: lr_router_t,
    dest: lr_ospf_v3_external_dest_t,
) -> i32 {
    guarded(
        || unsafe {
            let Some(dest_val) = borrow_v3_dest(dest) else {
                return LR_ERR_NULL;
            };
            let dest_clone: V3ExternalDestination = *dest_val;
            let mut router = match unsafe { lock_router(r) } {
                Some(g) => g,
                None => return LR_ERR_INVALID_HANDLE,
            };
            i32::from(router.ospf_redistribute_v3(dest_clone))
        },
        LR_ERR_PANIC,
    )
}

/// Drop the redistribution intent covering `prefix` on the OSPFv3
/// plane (RFC 5340 §A.4.7): MaxAge-flush the self-originated 0x4005
/// AS-external-LSA from every area and flood the flush.
///
/// Return codes: `1` when a matching redistribution existed and was
/// flushed, `0` when no matching redistribution exists, `-2`
/// invalid router handle, [`LR_ERR_PANIC`] on panic.
///
/// # Safety
/// `r` must be a valid `lr_router_t`.
#[no_mangle]
pub unsafe extern "C" fn lr_router_ospf_unredistribute_v3(
    r: lr_router_t,
    prefix: lr_core_prefix_t,
) -> i32 {
    guarded(
        || unsafe {
            let mut router = match unsafe { lock_router(r) } {
                Some(g) => g,
                None => return LR_ERR_INVALID_HANDLE,
            };
            let p: Prefix = prefix.into();
            i32::from(router.ospf_unredistribute_v3(p))
        },
        LR_ERR_PANIC,
    )
}

// =========================================================================
// OSPF ASBR inspection (RFC 2328 §12.4.1.1's E-bit condition).
// =========================================================================

/// `1` while at least one AS-external redistribution intent is
/// recorded (the `E`-bit condition of the router-LSA flags — lets
/// the daemon notice the ASBR status flip and re-originate its
/// Router-LSAs immediately). `0` otherwise. `-2` invalid handle,
/// [`LR_ERR_PANIC`] on panic.
///
/// # Safety
/// `r` must be a valid `lr_router_t`.
#[no_mangle]
pub unsafe extern "C" fn lr_router_ospf_is_asbr(r: lr_router_t) -> i32 {
    guarded(
        || unsafe {
            let router = match unsafe { lock_router(r) } {
                Some(g) => g,
                None => return LR_ERR_INVALID_HANDLE,
            };
            i32::from(router.ospf_is_asbr())
        },
        LR_ERR_PANIC,
    )
}

// =========================================================================
// Tests
// =========================================================================

#[cfg(test)]
mod tests {
    #![allow(unused_unsafe)]

    use super::*;
    use crate::handle::box_router;

    fn ospf_router_with_area(area_id: u32, area_kind: i32, default_metric: u32) -> lr_router_t {
        // Build a DefaultRouter with an attached OSPFv2 area so
        // virtual-link / redistribute calls have somewhere to land.
        // The C ABI's `lr_router_add_ospf_session_ext` already wires
        // the same shape; we re-use the path here because it is the
        // documented entry point.
        let router = lr_router::DefaultRouter::new();
        let r = box_router(router);
        // Add the OSPFv2 session that attaches the area.
        let mut out_handle: u64 = 0;
        let rc = unsafe {
            crate::sessions::lr_router_add_ospf_session_ext(
                r,
                crate::sessions::LR_OSPF_V2,
                0xc0a80001, // router_id
                area_id,
                area_kind,
                default_metric,
                1500, // mtu
                crate::sessions::LR_NET_PTP,
                0, // no interface_ip
                0,
                0, // no neighbor_ip
                0,
                &mut out_handle,
            )
        };
        assert_eq!(rc, 0, "adding OSPF session must succeed");
        r
    }

    #[test]
    fn v3_external_dest_round_trip_via_ffi() {
        // Construct a v3 external destination through the C ABI,
        // round-trip every field through the readers, and confirm
        // the values match.
        let addr: [u8; 16] = [
            0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01,
        ];
        let d = unsafe {
            lr_ospf_v3_external_dest_new(
                std::ptr::null(),
                addr.as_ptr(),
                48,
                100,
                1, // type2
            )
        };
        assert!(!d.is_null(), "lr_ospf_v3_external_dest_new returned NULL");
        // Set forwarding address + route tag.
        let fa: [u8; 16] = [
            0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xfe,
        ];
        let rc = unsafe { lr_ospf_v3_external_dest_set_forwarding_addr(d, fa.as_ptr()) };
        assert_eq!(rc, 0);
        let rc = unsafe { lr_ospf_v3_external_dest_set_route_tag(d, 0xdead_beef) };
        assert_eq!(rc, 0);
        // Read the prefix back.
        let mut out = lr_core_prefix_t::default();
        let rc = unsafe { lr_ospf_v3_external_dest_prefix(d, &mut out) };
        assert_eq!(rc, 0);
        assert_eq!(out.prefix_len, 48);
        // The address family comes through lr_ip_addr_is_ipv4.
        assert_eq!(unsafe { crate::core::lr_core_prefix_is_ipv6(out) }, 1);
        // Metric + type2.
        assert_eq!(lr_ospf_v3_external_dest_metric(d), 100);
        assert_eq!(lr_ospf_v3_external_dest_type2(d), 1);
        // Forwarding address present.
        let mut out_fa = [0u8; 16];
        let rc = unsafe { lr_ospf_v3_external_dest_forwarding_addr(d, out_fa.as_mut_ptr()) };
        assert_eq!(rc, 1);
        assert_eq!(out_fa, fa);
        // Route tag present.
        let mut out_tag: u32 = 0;
        let rc = unsafe { lr_ospf_v3_external_dest_route_tag(d, &mut out_tag) };
        assert_eq!(rc, 1);
        assert_eq!(out_tag, 0xdead_beef);
        // Clear the forwarding address.
        let rc = unsafe { lr_ospf_v3_external_dest_clear_forwarding_addr(d) };
        assert_eq!(rc, 0);
        let rc = unsafe { lr_ospf_v3_external_dest_forwarding_addr(d, out_fa.as_mut_ptr()) };
        assert_eq!(rc, 0);
        // Clear the route tag.
        let rc = unsafe { lr_ospf_v3_external_dest_clear_route_tag(d) };
        assert_eq!(rc, 0);
        let rc = unsafe { lr_ospf_v3_external_dest_route_tag(d, &mut out_tag) };
        assert_eq!(rc, 0);
        unsafe { lr_ospf_v3_external_dest_free(d) };
    }

    #[test]
    fn v3_external_dest_new_rejects_v4_prefix_pointer() {
        let addr: [u8; 4] = [192, 168, 1, 0];
        let d =
            unsafe { lr_ospf_v3_external_dest_new(addr.as_ptr(), std::ptr::null(), 24, 100, 0) };
        assert!(d.is_null(), "v3 plane must reject IPv4 prefix pointer");
    }

    #[test]
    fn v3_external_dest_new_rejects_both_null() {
        let d =
            unsafe { lr_ospf_v3_external_dest_new(std::ptr::null(), std::ptr::null(), 48, 100, 0) };
        assert!(
            d.is_null(),
            "v3 external dest must reject both-NULL prefixes"
        );
    }

    #[test]
    fn v3_external_dest_accessors_on_null_handle() {
        // Every reader is defensive against a NULL handle.
        assert_eq!(lr_ospf_v3_external_dest_metric(std::ptr::null_mut()), 0);
        assert_eq!(lr_ospf_v3_external_dest_type2(std::ptr::null_mut()), 0);
        let mut out = lr_core_prefix_t::default();
        let rc = unsafe { lr_ospf_v3_external_dest_prefix(std::ptr::null_mut(), &mut out) };
        assert_eq!(rc, LR_ERR_NULL);
        let rc = unsafe {
            lr_ospf_v3_external_dest_set_forwarding_addr(std::ptr::null_mut(), std::ptr::null())
        };
        assert_eq!(rc, LR_ERR_NULL);
    }

    #[test]
    fn virtual_link_lifecycle_via_ffi() {
        // Build a router with one OSPFv2 area (area 1, normal) and
        // exercise the add/up/remove lifecycle through the C ABI.
        let r = ospf_router_with_area(1, crate::sessions::LR_AREA_NORMAL, 0);
        // Cannot add a vlink to self.
        let rc = unsafe { lr_router_ospf_add_virtual_link(r, 1, 0xc0a80001) };
        assert_eq!(rc, 0, "vlink to self must be refused");
        // Add a vlink to a non-self endpoint through area 1.
        let rc = unsafe { lr_router_ospf_add_virtual_link(r, 1, 0xc0a80002) };
        assert_eq!(rc, 1, "vlink add must succeed for non-self endpoint");
        // Adding the same vlink twice is a no-op.
        let rc = unsafe { lr_router_ospf_add_virtual_link(r, 1, 0xc0a80002) };
        assert_eq!(rc, 0, "duplicate vlink add must be refused");
        // The link is down until SPF reaches the endpoint — the
        // router does not have a router-LSA for the endpoint, so SPF
        // will not reach it.
        let rc = unsafe { lr_router_ospf_virtual_link_up(r, 1, 0xc0a80002) };
        assert_eq!(rc, 0, "vlink must be down before SPF reaches the endpoint");
        let mut out_handle: u64 = 0;
        let rc = unsafe { lr_router_ospf_virtual_link_session(r, 1, 0xc0a80002, &mut out_handle) };
        assert_eq!(rc, 0, "down vlink has no session");
        assert_eq!(out_handle, 0);
        // Removing the vlink succeeds.
        let rc = unsafe { lr_router_ospf_remove_virtual_link(r, 1, 0xc0a80002) };
        assert_eq!(rc, 1, "vlink remove must succeed");
        // Removing again is a no-op.
        let rc = unsafe { lr_router_ospf_remove_virtual_link(r, 1, 0xc0a80002) };
        assert_eq!(rc, 0, "removing non-existent vlink returns 0");
        unsafe { crate::handle::unbox_router(r) };
    }

    #[test]
    fn virtual_link_across_stub_area_is_refused() {
        // Stub areas cannot carry virtual links (RFC 2328 §15).
        let r = ospf_router_with_area(2, crate::sessions::LR_AREA_STUB, 100);
        let rc = unsafe { lr_router_ospf_add_virtual_link(r, 2, 0xc0a80002) };
        assert_eq!(rc, 0, "vlink across stub area must be refused");
        unsafe { crate::handle::unbox_router(r) };
    }

    #[test]
    fn virtual_link_invalid_router_handle() {
        let rc = unsafe { lr_router_ospf_add_virtual_link(std::ptr::null_mut(), 1, 2) };
        assert_eq!(rc, LR_ERR_INVALID_HANDLE);
        let rc = unsafe { lr_router_ospf_virtual_link_up(std::ptr::null_mut(), 1, 2) };
        assert_eq!(rc, LR_ERR_INVALID_HANDLE);
        let mut out: u64 = 0;
        let rc =
            unsafe { lr_router_ospf_virtual_link_session(std::ptr::null_mut(), 1, 2, &mut out) };
        assert_eq!(rc, LR_ERR_INVALID_HANDLE);
    }

    #[test]
    fn redistribute_v2_via_ffi_records_intent_and_marks_asbr() {
        // Build a router with one OSPFv2 area.
        let r = ospf_router_with_area(1, crate::sessions::LR_AREA_NORMAL, 0);
        // Before redistribution: not ASBR.
        let rc = unsafe { lr_router_ospf_is_asbr(r) };
        assert_eq!(rc, 0, "router with no externals is not ASBR");
        // Construct an ExternalDestination via the existing C ABI.
        let addr: [u8; 4] = [10, 0, 0, 0];
        let dest = unsafe {
            crate::ospf_external::lr_ospf_external_dest_new(
                addr.as_ptr(),
                std::ptr::null(),
                24,
                100,
                crate::ospf_external::LR_OSPF_METRIC_TYPE_1,
            )
        };
        assert!(!dest.is_null());
        // Redistribute it.
        let rc = unsafe { lr_router_ospf_redistribute(r, dest) };
        assert_eq!(rc, 1, "redistribute must succeed for IPv4 prefix");
        // Now the router is ASBR.
        let rc = unsafe { lr_router_ospf_is_asbr(r) };
        assert_eq!(rc, 1, "router with v2 externals is ASBR");
        // Drop the intent.
        let prefix = unsafe { crate::core::lr_core_prefix_v4(addr.as_ptr(), 24) };
        let rc = unsafe { lr_router_ospf_unredistribute(r, prefix) };
        assert_eq!(rc, 1, "unredistribute must succeed");
        // No longer ASBR (the v2 intent map is empty).
        let rc = unsafe { lr_router_ospf_is_asbr(r) };
        assert_eq!(rc, 0, "router with no externals is not ASBR");
        // Unredistributing again is a no-op.
        let rc = unsafe { lr_router_ospf_unredistribute(r, prefix) };
        assert_eq!(rc, 0);
        unsafe { crate::ospf_external::lr_ospf_external_dest_free(dest) };
        unsafe { crate::handle::unbox_router(r) };
    }

    #[test]
    fn redistribute_v3_via_ffi_records_intent_and_marks_asbr() {
        // Build a router with one OSPFv2 area. The router records v3
        // redistribution intents regardless of which area version is
        // attached — the LSA only originates once a v3 area is
        // attached, but the intent is recorded immediately so the
        // area catches up on attach.
        let r = ospf_router_with_area(1, crate::sessions::LR_AREA_NORMAL, 0);
        let addr: [u8; 16] = [
            0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01,
        ];
        let dest =
            unsafe { lr_ospf_v3_external_dest_new(std::ptr::null(), addr.as_ptr(), 48, 100, 0) };
        assert!(!dest.is_null());
        let rc = unsafe { lr_router_ospf_redistribute_v3(r, dest) };
        assert_eq!(rc, 1, "v3 redistribute must succeed for IPv6 prefix");
        // ASBR flag set — the intent map is non-empty.
        let rc = unsafe { lr_router_ospf_is_asbr(r) };
        assert_eq!(rc, 1);
        // Drop the intent. With only a v2 area attached, no v3 LSA
        // was ever originated, so the underlying `ospf_unredistribute_v3`
        // returns `changed=false` (the intent was removed but nothing
        // was flushed) — `0` is the documented return for "nothing
        // changed on the wire". The ASBR flag flipping back to `0`
        // confirms the intent was in fact dropped.
        let prefix = unsafe { crate::core::lr_core_prefix_v6(addr.as_ptr(), 48) };
        let _ = unsafe { lr_router_ospf_unredistribute_v3(r, prefix) };
        // No longer ASBR.
        let rc = unsafe { lr_router_ospf_is_asbr(r) };
        assert_eq!(rc, 0);
        unsafe { lr_ospf_v3_external_dest_free(dest) };
        unsafe { crate::handle::unbox_router(r) };
    }

    #[test]
    fn redistribute_v3_rejects_link_local_forwarding_address() {
        let r = ospf_router_with_area(1, crate::sessions::LR_AREA_NORMAL, 0);
        let addr: [u8; 16] = [
            0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01,
        ];
        let dest =
            unsafe { lr_ospf_v3_external_dest_new(std::ptr::null(), addr.as_ptr(), 48, 100, 0) };
        assert!(!dest.is_null());
        // Link-local forwarding address (fe80::) — RFC 5340 §A.4.7
        // forbids it; the router rejects with `0`.
        let fa: [u8; 16] = [0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01];
        let rc = unsafe { lr_ospf_v3_external_dest_set_forwarding_addr(dest, fa.as_ptr()) };
        assert_eq!(rc, 0);
        let rc = unsafe { lr_router_ospf_redistribute_v3(r, dest) };
        assert_eq!(rc, 0, "v3 redistribute must reject link-local FA");
        unsafe { lr_ospf_v3_external_dest_free(dest) };
        unsafe { crate::handle::unbox_router(r) };
    }

    #[test]
    fn redistribute_v2_rejects_v6_prefix_via_dest_handle() {
        // lr_ospf_external_dest_new accepts a v6 prefix pointer, but
        // the v2 redistribute plane only carries IPv4 prefixes —
        // passing a v6 ExternalDestination returns `0`.
        let r = ospf_router_with_area(1, crate::sessions::LR_AREA_NORMAL, 0);
        let addr: [u8; 16] = [
            0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01,
        ];
        let dest = unsafe {
            crate::ospf_external::lr_ospf_external_dest_new(
                std::ptr::null(),
                addr.as_ptr(),
                48,
                100,
                crate::ospf_external::LR_OSPF_METRIC_TYPE_1,
            )
        };
        assert!(!dest.is_null());
        let rc = unsafe { lr_router_ospf_redistribute(r, dest) };
        assert_eq!(rc, 0, "v2 redistribute must reject IPv6 prefix");
        unsafe { crate::ospf_external::lr_ospf_external_dest_free(dest) };
        unsafe { crate::handle::unbox_router(r) };
    }

    #[test]
    fn redistribute_null_dest_handle_is_rejected() {
        let r = ospf_router_with_area(1, crate::sessions::LR_AREA_NORMAL, 0);
        let rc = unsafe { lr_router_ospf_redistribute(r, std::ptr::null_mut()) };
        assert_eq!(rc, LR_ERR_NULL);
        let rc = unsafe { lr_router_ospf_redistribute_v3(r, std::ptr::null_mut()) };
        assert_eq!(rc, LR_ERR_NULL);
        unsafe { crate::handle::unbox_router(r) };
    }

    #[test]
    fn redistribute_invalid_router_handle() {
        let rc = unsafe { lr_router_ospf_redistribute(std::ptr::null_mut(), std::ptr::null_mut()) };
        assert_eq!(rc, LR_ERR_NULL);
        let rc =
            unsafe { lr_router_ospf_redistribute_v3(std::ptr::null_mut(), std::ptr::null_mut()) };
        assert_eq!(rc, LR_ERR_NULL);
        let rc = unsafe { lr_router_ospf_is_asbr(std::ptr::null_mut()) };
        assert_eq!(rc, LR_ERR_INVALID_HANDLE);
    }
}
