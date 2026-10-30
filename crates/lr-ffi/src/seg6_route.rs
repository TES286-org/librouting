//! SRv6 netlink route-table FFI — `lr_seg6_route_*` /
//! `lr_seg6_local_route_*` / `lr_seg6_netlink_*`.
//!
//! Mirrors the public Rust API of `lr_osroute::seg6_route`:
//!
//! - [`Seg6Route`] — `seg6` lwtunnel encap route ("to reach `prefix`,
//!   push this SRH").
//! - [`Seg6LocalRoute`] — `seg6local` endpoint route ("when a packet
//!   arrives addressed to `sid`, run this behavior").
//! - [`Seg6Netlink`] — `NETLINK_ROUTE` backend for installing /
//!   deleting both route kinds.
//! - [`Seg6EncapMode`] — `Inline` (insert SRH) vs `Encap` (outer
//!   IPv6 + SRH).
//! - [`Seg6RouteError`] — backend error enum.
//!
//! The previous FFI surface only exposed
//! [`lr_osroute_seg6_enabled`] (the global capability check) via
//! `osroute_helpers.rs`; an embedder had to drop down to Rust to
//! construct or install a route. This module closes that gap.
//!
//! # Surface
//!
//! Constants:
//! - `LR_SEG6_ENCAP_INLINE` / `LR_SEG6_ENCAP_ENCAP` — `Seg6EncapMode`
//!   wire values (mirrors `uapi/linux/seg6_iptunnel.h`).
//! - `LR_SEG6_ERR_*` — `Seg6RouteError` discriminants (positive
//!   integers; the global `LR_ERR_*` codes remain negative).
//!
//! `Seg6Route`:
//! - `lr_seg6_route_new(prefix, srh) -> lr_seg6_route_t`
//! - `lr_seg6_route_set_mode(r, mode) -> i32`
//! - `lr_seg6_route_set_if_index(r, if_index) -> i32`
//! - `lr_seg6_route_free(r)`
//!
//! `Seg6LocalRoute`:
//! - `lr_seg6_local_route_new(sid, behavior_wire) -> lr_seg6_local_route_t`
//! - `lr_seg6_local_route_set_if_index` / `_set_nh4` / `_set_nh6` /
//!   `_set_iif` / `_set_oif` / `_set_table` / `_set_vrf_table` /
//!   `_set_srh` — builder-style mutators.
//! - `lr_seg6_local_route_free(r)`
//!
//! `Seg6Netlink`:
//! - `lr_seg6_netlink_connect() -> lr_seg6_netlink_t` (NULL on
//!   failure — call `lr_seg6_route_err_code` for the discriminant).
//! - `lr_seg6_netlink_add_seg6_route(nl, route) -> i32`
//! - `lr_seg6_netlink_delete_seg6_route(nl, prefix) -> i32`
//! - `lr_seg6_netlink_add_seg6local_route(nl, route) -> i32`
//! - `lr_seg6_netlink_delete_seg6local_route(nl, sid) -> i32`
//! - `lr_seg6_netlink_last_request_bytes(nl, *out_lr_bytes_t) -> i32`
//! - `lr_seg6_netlink_last_response_bytes(nl, *out_lr_bytes_t) -> i32`
//! - `lr_seg6_netlink_free(nl)`
//!
//! Error helpers:
//! - `lr_seg6_route_err_code() -> i32` — discriminant of the most
//!   recent `Seg6RouteError` recorded in the thread-local
//!   last-error string.
//! - `lr_seg6_route_err_name(code) -> *const c_char` — stable name
//!   for a discriminant.
//!
//! Every entry point runs inside the crate's `catch_unwind` barrier
//! ([`crate::guarded`]): a panic returns `LR_ERR_PANIC` and sets the
//! thread-local last-error string.

// The closure body passed to `guarded` is wrapped in a single `unsafe`
// block to mirror the `pub unsafe extern "C" fn` shape — the inner
// `unsafe { ... }` blocks would otherwise trip `unused_unsafe` under the
// crate's `-D warnings` clippy gate.
#![allow(unused_unsafe)]

use lr_osroute::seg6_route::{
    Seg6EncapMode, Seg6LocalRoute, Seg6Netlink, Seg6Route, Seg6RouteError,
};
use lr_srv6::{Behavior, Sid};

use crate::error::{last_error_string, set_last_error, LrError, LR_ERR_PANIC};
use crate::guarded;
use crate::handle::lr_bytes_t;
use crate::policy::lr_prefix_t;
use crate::srv6::lr_srv6_sid_t;
use crate::srv6_srh::lr_srv6_srh_t;

const LR_ERR_NULL: i32 = LrError::Null as i32;
const LR_ERR_INVALID_HANDLE: i32 = LrError::InvalidHandle as i32;

// =========================================================================
// Constants — Seg6EncapMode (mirrors uapi/linux/seg6_iptunnel.h)
// =========================================================================

/// `Seg6EncapMode::Inline` (`SEG6_IPTUN_MODE_INLINE` — insert the SRH
/// into the existing IPv6 packet without adding an outer header).
pub const LR_SEG6_ENCAP_INLINE: u32 = 0;

/// `Seg6EncapMode::Encap` (`SEG6_IPTUN_MODE_ENCAP` — wrap the original
/// packet in an outer IPv6 header carrying the SRH; default).
pub const LR_SEG6_ENCAP_ENCAP: u32 = 1;

// =========================================================================
// Constants — Seg6RouteError discriminants
// =========================================================================

/// `Seg6RouteError::Unsupported` (the platform has no SRv6 — non-Linux
/// builds).
pub const LR_SEG6_ERR_UNSUPPORTED: i32 = 1;
/// `Seg6RouteError::NotEnabled` (the kernel's `seg6_enabled` sysctl
/// is 0 — the embedder must `sysctl -w
/// net.ipv6.conf.all.seg6_enabled=1` first).
pub const LR_SEG6_ERR_NOT_ENABLED: i32 = 2;
/// `Seg6RouteError::Syscall` — a netlink syscall failed (sendmsg /
/// recv / socket / bind).
pub const LR_SEG6_ERR_SYSCALL: i32 = 3;
/// `Seg6RouteError::Kernel` — the kernel rejected the request (e.g.
/// EEXIST on a duplicate SID, ENODEV on a device-less IPv6 route).
pub const LR_SEG6_ERR_KERNEL: i32 = 4;
/// `Seg6RouteError::BadSrh` — the SRH encode failed (RFC 8754 §2
/// validation: empty segment list, reserved flag bits, out-of-range
/// segments_left, etc.).
pub const LR_SEG6_ERR_BAD_SRH: i32 = 5;
/// `Seg6RouteError::UnsupportedAction` — the behavior cannot be
/// encoded as a `seg6local` action (the kernel's
/// `seg6_action_table` has no descriptor for it, or the route's
/// parameter set does not satisfy the kernel's contract for it).
pub const LR_SEG6_ERR_UNSUPPORTED_ACTION: i32 = 6;
/// Unknown `Seg6RouteError` variant (forward-compat sentinel — kept
/// in the discriminant space so a future variant is visible to a C
/// embedder as a distinct code).
pub const LR_SEG6_ERR_UNKNOWN: i32 = -1;

/// Translate a `Seg6RouteError` to its discriminant code. Public so
/// the C ABI entry points can call it when surfacing the code from a
/// failed call without going through the last-error string.
fn seg6_route_err_code(e: &Seg6RouteError) -> i32 {
    match e {
        Seg6RouteError::Unsupported => LR_SEG6_ERR_UNSUPPORTED,
        Seg6RouteError::NotEnabled => LR_SEG6_ERR_NOT_ENABLED,
        Seg6RouteError::Syscall(_) => LR_SEG6_ERR_SYSCALL,
        Seg6RouteError::Kernel(_) => LR_SEG6_ERR_KERNEL,
        Seg6RouteError::BadSrh(_) => LR_SEG6_ERR_BAD_SRH,
        Seg6RouteError::UnsupportedAction(_) => LR_SEG6_ERR_UNSUPPORTED_ACTION,
    }
}

/// Record a `Seg6RouteError` in the thread-local last-error string
/// (Display form) and return the discriminant. The C ABI entry points
/// use this so a caller can `lr_seg6_route_err_code()` to recover the
/// discriminant from a failed call.
fn record_seg6_route_err(e: &Seg6RouteError) -> i32 {
    let s = e.to_string();
    let code = seg6_route_err_code(e);
    set_last_error(s);
    code
}

// =========================================================================
// Opaque handles
// =========================================================================

/// Opaque `Seg6Route` handle (boxed `Seg6Route`).
#[repr(C)]
pub struct OpaqueSeg6Route {
    _private: [u8; 0],
}
pub type lr_seg6_route_t = *mut OpaqueSeg6Route;

/// Opaque `Seg6LocalRoute` handle (boxed `Seg6LocalRoute`).
#[repr(C)]
pub struct OpaqueSeg6LocalRoute {
    _private: [u8; 0],
}
pub type lr_seg6_local_route_t = *mut OpaqueSeg6LocalRoute;

/// Opaque `Seg6Netlink` handle (boxed `Seg6Netlink`).
#[repr(C)]
pub struct OpaqueSeg6Netlink {
    _private: [u8; 0],
}
pub type lr_seg6_netlink_t = *mut OpaqueSeg6Netlink;

fn box_seg6_route(r: Seg6Route) -> lr_seg6_route_t {
    Box::into_raw(Box::new(r)) as lr_seg6_route_t
}
unsafe fn borrow_seg6_route(r: lr_seg6_route_t) -> Option<&'static Seg6Route> {
    if r.is_null() {
        return None;
    }
    Some(unsafe { &*(r as *const Seg6Route) })
}
unsafe fn borrow_seg6_route_mut(r: lr_seg6_route_t) -> Option<&'static mut Seg6Route> {
    if r.is_null() {
        return None;
    }
    Some(unsafe { &mut *(r as *mut Seg6Route) })
}
unsafe fn unbox_seg6_route(r: lr_seg6_route_t) -> Option<Box<Seg6Route>> {
    if r.is_null() {
        return None;
    }
    Some(unsafe { Box::from_raw(r as *mut Seg6Route) })
}

fn box_seg6_local_route(r: Seg6LocalRoute) -> lr_seg6_local_route_t {
    Box::into_raw(Box::new(r)) as lr_seg6_local_route_t
}
unsafe fn borrow_seg6_local_route_mut(
    r: lr_seg6_local_route_t,
) -> Option<&'static mut Seg6LocalRoute> {
    if r.is_null() {
        return None;
    }
    Some(unsafe { &mut *(r as *mut Seg6LocalRoute) })
}
unsafe fn unbox_seg6_local_route(r: lr_seg6_local_route_t) -> Option<Box<Seg6LocalRoute>> {
    if r.is_null() {
        return None;
    }
    Some(unsafe { Box::from_raw(r as *mut Seg6LocalRoute) })
}

fn box_seg6_netlink(n: Seg6Netlink) -> lr_seg6_netlink_t {
    Box::into_raw(Box::new(n)) as lr_seg6_netlink_t
}
unsafe fn borrow_seg6_netlink(n: lr_seg6_netlink_t) -> Option<&'static Seg6Netlink> {
    if n.is_null() {
        return None;
    }
    Some(unsafe { &*(n as *const Seg6Netlink) })
}
unsafe fn borrow_seg6_netlink_mut(n: lr_seg6_netlink_t) -> Option<&'static mut Seg6Netlink> {
    if n.is_null() {
        return None;
    }
    Some(unsafe { &mut *(n as *mut Seg6Netlink) })
}
unsafe fn unbox_seg6_netlink(n: lr_seg6_netlink_t) -> Option<Box<Seg6Netlink>> {
    if n.is_null() {
        return None;
    }
    Some(unsafe { Box::from_raw(n as *mut Seg6Netlink) })
}

// =========================================================================
// Seg6Route surface
// =========================================================================

/// Construct a `Seg6Route` (RFC 8754 §2 — `seg6` lwtunnel encap
/// route) from an IPv6 prefix and an SRH handle. The default encap
/// mode is `Encap` (mirrors `ip route add ... encap seg6 mode encap
/// ...` and is what most operators want); pass the SRH by value
/// (the handle is borrowed — the constructor clones the inner `Srh`).
///
/// Returns NULL on a NULL `srh` or when `prefix` carries an IPv4
/// address (the `seg6` lwtunnel only accepts IPv6 routes — `ip -6
/// route add ... encap seg6 ...` rejects an IPv4 prefix at the
/// iproute2 layer too). The error code is recorded in the
/// thread-local last-error string — recover it with
/// [`lr_seg6_route_err_code`].
///
/// # Safety
/// `srh` must be a valid `lr_srv6_srh_t` produced by
/// `lr_srv6_srh_new` / `lr_srv6_srh_new_with_segments_left` and not
/// already freed.
#[no_mangle]
pub unsafe extern "C" fn lr_seg6_route_new(
    prefix: lr_prefix_t,
    srh: lr_srv6_srh_t,
) -> lr_seg6_route_t {
    guarded(
        || unsafe {
            if srh.is_null() {
                set_last_error("lr_seg6_route_new: srh is NULL".into());
                return std::ptr::null_mut();
            }
            // Borrow the SRH without taking ownership.
            let srh_ref = match unsafe { crate::srv6_srh::borrow_srh_pub(srh) } {
                Some(r) => r,
                None => {
                    set_last_error("lr_seg6_route_new: srh is invalid".into());
                    return std::ptr::null_mut();
                }
            };
            let Some(p) = prefix.to_prefix() else {
                set_last_error("lr_seg6_route_new: invalid prefix length".into());
                return std::ptr::null_mut();
            };
            if !p.addr.is_ipv6() {
                set_last_error(
                    "lr_seg6_route_new: prefix must be IPv6 (seg6 lwtunnel is IPv6-only)".into(),
                );
                return std::ptr::null_mut();
            }
            box_seg6_route(Seg6Route::new(p, srh_ref.clone()))
        },
        std::ptr::null_mut(),
    )
}

/// Set the encap mode on a `Seg6Route` (RFC 8754 §2 — `Inline`
/// inserts the SRH into the existing IPv6 packet; `Encap` wraps it
/// in an outer IPv6 header carrying the SRH).
///
/// Returns 0 on success, `LR_ERR_NULL` on a NULL handle, `LR_ERR_OTHER`
/// on an unknown mode value (the caller passes one of
/// `LR_SEG6_ENCAP_INLINE` / `LR_SEG6_ENCAP_ENCAP`).
///
/// # Safety
/// `r` must be a valid `lr_seg6_route_t` produced by
/// `lr_seg6_route_new` and not already freed.
#[no_mangle]
pub unsafe extern "C" fn lr_seg6_route_set_mode(r: lr_seg6_route_t, mode: u32) -> i32 {
    guarded(
        || unsafe {
            let Some(route) = borrow_seg6_route_mut(r) else {
                return LR_ERR_NULL;
            };
            let m = match mode {
                LR_SEG6_ENCAP_INLINE => Seg6EncapMode::Inline,
                LR_SEG6_ENCAP_ENCAP => Seg6EncapMode::Encap,
                _ => {
                    set_last_error(format!("lr_seg6_route_set_mode: unknown mode {mode}"));
                    return LrError::Other as i32;
                }
            };
            route.mode = m;
            0
        },
        LR_ERR_PANIC,
    )
}

/// Set the output interface index (`RTA_OIF`) on a `Seg6Route`. The
/// kernel's `fib6_nh_init` rejects an IPv6 route that names neither
/// an egress device nor a gateway with `ENODEV`, so callers usually
/// set this. 0 means "let the kernel resolve via the gateway".
///
/// Returns 0 on success, `LR_ERR_NULL` on a NULL handle.
///
/// # Safety
/// See [`lr_seg6_route_set_mode`].
#[no_mangle]
pub unsafe extern "C" fn lr_seg6_route_set_if_index(r: lr_seg6_route_t, if_index: u32) -> i32 {
    guarded(
        || unsafe {
            let Some(route) = borrow_seg6_route_mut(r) else {
                return LR_ERR_NULL;
            };
            route.if_index = if_index;
            0
        },
        LR_ERR_PANIC,
    )
}

/// Drop a boxed `Seg6Route`. Safe to call with NULL.
///
/// # Safety
/// `r` must have been produced by `lr_seg6_route_new` and not
/// already freed.
#[no_mangle]
pub unsafe extern "C" fn lr_seg6_route_free(r: lr_seg6_route_t) {
    guarded(
        || unsafe {
            drop(unbox_seg6_route(r));
        },
        (),
    )
}

// =========================================================================
// Seg6LocalRoute surface
// =========================================================================

/// Construct a `Seg6LocalRoute` (RFC 8986 §4 — `seg6local` endpoint
/// route) from a SID handle and an IANA behavior wire value (one of
/// the `lr_srv6::Behavior` wire codes — End=1, End.X=5, End.T=9, …).
/// The behavior is resolved via `Behavior::from_wire`; an unknown
/// wire value (40+ which the crate does not yet model) is rejected
/// with `LR_ERR_OTHER`.
///
/// Returns NULL on a NULL `sid` or an unrecognized behavior. The
/// error code is recorded in the thread-local last-error string —
/// recover it with [`lr_seg6_route_err_code`].
///
/// # Safety
/// `sid` must be a valid `lr_srv6_sid_t` produced by
/// `lr_srv6_sid_new` / `lr_srv6_locator_sid_with_tail` / ... and not
/// already freed.
#[no_mangle]
pub unsafe extern "C" fn lr_seg6_local_route_new(
    sid: lr_srv6_sid_t,
    behavior_wire: u16,
) -> lr_seg6_local_route_t {
    guarded(
        || unsafe {
            if sid.is_null() {
                set_last_error("lr_seg6_local_route_new: sid is NULL".into());
                return std::ptr::null_mut();
            }
            // Borrow the SID's 16 bytes without taking ownership.
            let sid_ptr = crate::srv6::lr_srv6_sid_as_ptr(sid);
            if sid_ptr.is_null() {
                set_last_error("lr_seg6_local_route_new: sid is invalid".into());
                return std::ptr::null_mut();
            }
            let mut octets = [0u8; 16];
            // SAFETY: sid_ptr points to 16 readable bytes inside the
            // boxed Sid (see lr_srv6_sid_as_ptr).
            unsafe { std::ptr::copy_nonoverlapping(sid_ptr, octets.as_mut_ptr(), 16) };
            let sid_obj = Sid::from_octets(octets);
            let Some(behavior) = Behavior::from_wire(behavior_wire) else {
                set_last_error(format!(
                    "lr_seg6_local_route_new: unknown Behavior wire value {behavior_wire}"
                ));
                return std::ptr::null_mut();
            };
            box_seg6_local_route(Seg6LocalRoute::new(sid_obj, behavior))
        },
        std::ptr::null_mut(),
    )
}

/// Set the route-level egress interface index (`RTA_OIF`) on a
/// `Seg6LocalRoute`. Required for the install to be accepted: the
/// kernel's `fib6_nh_init` rejects a route that names neither an
/// egress device nor a gateway with `ENODEV`.
///
/// Returns 0 on success, `LR_ERR_NULL` on a NULL handle.
///
/// # Safety
/// `r` must be a valid `lr_seg6_local_route_t` produced by
/// `lr_seg6_local_route_new` and not already freed.
#[no_mangle]
pub unsafe extern "C" fn lr_seg6_local_route_set_if_index(
    r: lr_seg6_local_route_t,
    if_index: u32,
) -> i32 {
    guarded(
        || unsafe {
            let Some(route) = borrow_seg6_local_route_mut(r) else {
                return LR_ERR_NULL;
            };
            route.if_index = if_index;
            0
        },
        LR_ERR_PANIC,
    )
}

/// Set the IPv4 next-hop (`SEG6_LOCAL_NH4` — the `End.DX4` parameter).
/// `nh4` is a 4-byte buffer in network byte order.
///
/// Returns 0 on success, `LR_ERR_NULL` on a NULL handle or a NULL
/// `nh4` pointer.
///
/// # Safety
/// `nh4` must point to 4 readable bytes (or be NULL — the call returns
/// `LR_ERR_NULL` early without reading).
#[no_mangle]
pub unsafe extern "C" fn lr_seg6_local_route_set_nh4(
    r: lr_seg6_local_route_t,
    nh4: *const u8,
) -> i32 {
    guarded(
        || unsafe {
            if nh4.is_null() {
                return LR_ERR_NULL;
            }
            let Some(route) = borrow_seg6_local_route_mut(r) else {
                return LR_ERR_NULL;
            };
            let mut buf = [0u8; 4];
            unsafe { std::ptr::copy_nonoverlapping(nh4, buf.as_mut_ptr(), 4) };
            route.nh4 = Some(buf);
            0
        },
        LR_ERR_PANIC,
    )
}

/// Set the IPv6 next-hop (`SEG6_LOCAL_NH6` — the `End.X` /
/// `End.DX6` parameter). `nh6` is a 16-byte buffer in network byte
/// order.
///
/// Returns 0 on success, `LR_ERR_NULL` on a NULL handle or a NULL
/// `nh6` pointer.
///
/// # Safety
/// `nh6` must point to 16 readable bytes (or be NULL — the call
/// returns `LR_ERR_NULL` early without reading).
#[no_mangle]
pub unsafe extern "C" fn lr_seg6_local_route_set_nh6(
    r: lr_seg6_local_route_t,
    nh6: *const u8,
) -> i32 {
    guarded(
        || unsafe {
            if nh6.is_null() {
                return LR_ERR_NULL;
            }
            let Some(route) = borrow_seg6_local_route_mut(r) else {
                return LR_ERR_NULL;
            };
            let mut buf = [0u8; 16];
            unsafe { std::ptr::copy_nonoverlapping(nh6, buf.as_mut_ptr(), 16) };
            route.nh6 = Some(buf);
            0
        },
        LR_ERR_PANIC,
    )
}

/// Set the input interface index (`SEG6_LOCAL_IIF`). Note: no
/// mainline kernel `seg6local` action consumes the IIF parameter
/// today — the install will fail with a descriptive error until a
/// kernel action adopts it.
///
/// Returns 0 on success, `LR_ERR_NULL` on a NULL handle.
///
/// # Safety
/// See [`lr_seg6_local_route_set_if_index`].
#[no_mangle]
pub unsafe extern "C" fn lr_seg6_local_route_set_iif(r: lr_seg6_local_route_t, iif: u32) -> i32 {
    guarded(
        || unsafe {
            let Some(route) = borrow_seg6_local_route_mut(r) else {
                return LR_ERR_NULL;
            };
            route.iif = Some(iif);
            0
        },
        LR_ERR_PANIC,
    )
}

/// Set the output interface index (`SEG6_LOCAL_OIF` — the
/// `End.DX2` parameter; an optional `End.X` steering parameter).
///
/// Returns 0 on success, `LR_ERR_NULL` on a NULL handle.
///
/// # Safety
/// See [`lr_seg6_local_route_set_if_index`].
#[no_mangle]
pub unsafe extern "C" fn lr_seg6_local_route_set_oif(r: lr_seg6_local_route_t, oif: u32) -> i32 {
    guarded(
        || unsafe {
            let Some(route) = borrow_seg6_local_route_mut(r) else {
                return LR_ERR_NULL;
            };
            route.oif = Some(oif);
            0
        },
        LR_ERR_PANIC,
    )
}

/// Set the routing table ID (`SEG6_LOCAL_TABLE` — the `End.T`
/// parameter; also tolerated by the legacy `End.DT6` path on a
/// non-L3-master kernel). Mutually exclusive with
/// [`lr_seg6_local_route_set_vrf_table`] in practice — the encoder's
/// parameter contract check rejects a route that sets both.
///
/// Returns 0 on success, `LR_ERR_NULL` on a NULL handle.
///
/// # Safety
/// See [`lr_seg6_local_route_set_if_index`].
#[no_mangle]
pub unsafe extern "C" fn lr_seg6_local_route_set_table(
    r: lr_seg6_local_route_t,
    table: u32,
) -> i32 {
    guarded(
        || unsafe {
            let Some(route) = borrow_seg6_local_route_mut(r) else {
                return LR_ERR_NULL;
            };
            route.table = Some(table);
            0
        },
        LR_ERR_PANIC,
    )
}

/// Set the VRF table ID (`SEG6_LOCAL_VRFTABLE` — the `End.DT4` /
/// `End.DT46` parameter; also accepted by the L3-master-dev form of
/// `End.DT6`). Mutually exclusive with
/// [`lr_seg6_local_route_set_table`].
///
/// Returns 0 on success, `LR_ERR_NULL` on a NULL handle.
///
/// # Safety
/// See [`lr_seg6_local_route_set_if_index`].
#[no_mangle]
pub unsafe extern "C" fn lr_seg6_local_route_set_vrf_table(
    r: lr_seg6_local_route_t,
    vrf_table: u32,
) -> i32 {
    guarded(
        || unsafe {
            let Some(route) = borrow_seg6_local_route_mut(r) else {
                return LR_ERR_NULL;
            };
            route.vrf_table = Some(vrf_table);
            0
        },
        LR_ERR_PANIC,
    )
}

/// Set the SRv6 Routing Header (`SEG6_LOCAL_SRH` — the
/// `End.B6.Insert` / `End.B6.Encaps` parameter). The SRH is the
/// same wire form a `seg6` encap route pushes (RFC 8754 §2); the
/// endpoint inserts (End.B6.Insert) or wraps (End.B6.Encaps) it
/// onto the packet at the binding-SID endpoint. The handle is
/// borrowed — the setter clones the inner `Srh`.
///
/// Returns 0 on success, `LR_ERR_NULL` on a NULL handle or a NULL
/// `srh`.
///
/// # Safety
/// `srh` must be a valid `lr_srv6_srh_t` produced by
/// `lr_srv6_srh_new` / `lr_srv6_srh_new_with_segments_left` and not
/// already freed.
#[no_mangle]
pub unsafe extern "C" fn lr_seg6_local_route_set_srh(
    r: lr_seg6_local_route_t,
    srh: lr_srv6_srh_t,
) -> i32 {
    guarded(
        || unsafe {
            if srh.is_null() {
                return LR_ERR_NULL;
            }
            let Some(route) = borrow_seg6_local_route_mut(r) else {
                return LR_ERR_NULL;
            };
            let srh_ref = match unsafe { crate::srv6_srh::borrow_srh_pub(srh) } {
                Some(r) => r,
                None => return LR_ERR_INVALID_HANDLE,
            };
            route.srh = Some(srh_ref.clone());
            0
        },
        LR_ERR_PANIC,
    )
}

/// Drop a boxed `Seg6LocalRoute`. Safe to call with NULL.
///
/// # Safety
/// `r` must have been produced by `lr_seg6_local_route_new` and not
/// already freed.
#[no_mangle]
pub unsafe extern "C" fn lr_seg6_local_route_free(r: lr_seg6_local_route_t) {
    guarded(
        || unsafe {
            drop(unbox_seg6_local_route(r));
        },
        (),
    )
}

// =========================================================================
// Seg6Netlink surface
// =========================================================================

/// Open a `NETLINK_ROUTE` socket for SRv6 route installation.
///
/// Returns a handle on success, NULL on failure. On failure the
/// thread-local last-error string carries the `Display` form of the
/// `Seg6RouteError` and [`lr_seg6_route_err_code`] returns the
/// discriminant. The most common failure on a Linux CI runner is
/// `NotEnabled` (the kernel's `seg6_enabled` sysctl is 0); a
/// non-Linux build returns `Unsupported`.
///
/// # Safety
/// The returned handle must be released with
/// [`lr_seg6_netlink_free`] to avoid a memory leak.
#[no_mangle]
pub extern "C" fn lr_seg6_netlink_connect() -> lr_seg6_netlink_t {
    guarded(
        || match Seg6Netlink::connect() {
            Ok(n) => box_seg6_netlink(n),
            Err(e) => {
                record_seg6_route_err(&e);
                std::ptr::null_mut()
            }
        },
        std::ptr::null_mut(),
    )
}

/// Install a `seg6` encap route (RFC 8754 §2 — the LSP head-end:
/// push an SRH on packets matching `prefix`). The kernel's
/// `fib6_nh_init` rejects a route that names neither an egress
/// device nor a gateway, so the caller usually sets `if_index` via
/// [`lr_seg6_route_set_if_index`].
///
/// Returns 0 on success, `LR_ERR_NULL` on a NULL handle / route,
/// `LR_ERR_INVALID_HANDLE` on an invalid handle, and a positive
/// `LR_SEG6_ERR_*` discriminant on a backend error (recorded in the
/// last-error string too).
///
/// # Safety
/// `nl` must be a valid `lr_seg6_netlink_t` produced by
/// `lr_seg6_netlink_connect`; `route` must be a valid
/// `lr_seg6_route_t` produced by `lr_seg6_route_new`. Both must not
/// have been freed.
#[no_mangle]
pub unsafe extern "C" fn lr_seg6_netlink_add_seg6_route(
    nl: lr_seg6_netlink_t,
    route: lr_seg6_route_t,
) -> i32 {
    guarded(
        || unsafe {
            let Some(n) = borrow_seg6_netlink_mut(nl) else {
                return LR_ERR_NULL;
            };
            let Some(r) = borrow_seg6_route(route) else {
                return LR_ERR_NULL;
            };
            match n.add_seg6_route(r) {
                Ok(()) => 0,
                Err(e) => record_seg6_route_err(&e),
            }
        },
        LR_ERR_PANIC,
    )
}

/// Delete a `seg6` encap route by prefix (the minimal
/// prefix-shaped delete iproute2 sends: `ip route del PREFIX`).
///
/// Returns 0 on success, `LR_ERR_NULL` on a NULL handle, and a
/// positive `LR_SEG6_ERR_*` discriminant on a backend error.
///
/// # Safety
/// `nl` must be a valid `lr_seg6_netlink_t` produced by
/// `lr_seg6_netlink_connect`.
#[no_mangle]
pub unsafe extern "C" fn lr_seg6_netlink_delete_seg6_route(
    nl: lr_seg6_netlink_t,
    prefix: lr_prefix_t,
) -> i32 {
    guarded(
        || unsafe {
            let Some(n) = borrow_seg6_netlink_mut(nl) else {
                return LR_ERR_NULL;
            };
            let Some(p) = prefix.to_prefix() else {
                set_last_error("lr_seg6_netlink_delete_seg6_route: invalid prefix length".into());
                return LrError::Other as i32;
            };
            match n.delete_seg6_route(p) {
                Ok(()) => 0,
                Err(e) => record_seg6_route_err(&e),
            }
        },
        LR_ERR_PANIC,
    )
}

/// Install a `seg6local` endpoint route (RFC 8986 §4 — the LSP
/// tail-end: run `behavior` when a packet arrives addressed to
/// `sid`). The kernel's `seg6_action_table` requires a per-behavior
/// parameter set; the encoder fails fast with
/// `UnsupportedAction` for behaviors or parameter sets the kernel
/// would reject with a bare `EINVAL`.
///
/// Returns 0 on success, `LR_ERR_NULL` on a NULL handle / route,
/// and a positive `LR_SEG6_ERR_*` discriminant on a backend error.
///
/// # Safety
/// `nl` must be a valid `lr_seg6_netlink_t` produced by
/// `lr_seg6_netlink_connect`; `route` must be a valid
/// `lr_seg6_local_route_t` produced by `lr_seg6_local_route_new`.
/// Both must not have been freed.
#[no_mangle]
pub unsafe extern "C" fn lr_seg6_netlink_add_seg6local_route(
    nl: lr_seg6_netlink_t,
    route: lr_seg6_local_route_t,
) -> i32 {
    guarded(
        || unsafe {
            let Some(n) = borrow_seg6_netlink_mut(nl) else {
                return LR_ERR_NULL;
            };
            if route.is_null() {
                return LR_ERR_NULL;
            }
            let r = unsafe { &*(route as *const Seg6LocalRoute) };
            match n.add_seg6local_route(r) {
                Ok(()) => 0,
                Err(e) => record_seg6_route_err(&e),
            }
        },
        LR_ERR_PANIC,
    )
}

/// Delete a `seg6local` endpoint route by SID (the same minimal
/// prefix-shaped delete as `lr_seg6_netlink_delete_seg6_route`,
/// against the local table — seg6local rows are /128 SIDs).
///
/// Returns 0 on success, `LR_ERR_NULL` on a NULL handle / sid, and
/// a positive `LR_SEG6_ERR_*` discriminant on a backend error.
///
/// # Safety
/// `nl` must be a valid `lr_seg6_netlink_t`; `sid` must be a valid
/// `lr_srv6_sid_t` produced by `lr_srv6_sid_new` / siblings.
#[no_mangle]
pub unsafe extern "C" fn lr_seg6_netlink_delete_seg6local_route(
    nl: lr_seg6_netlink_t,
    sid: lr_srv6_sid_t,
) -> i32 {
    guarded(
        || unsafe {
            let Some(n) = borrow_seg6_netlink_mut(nl) else {
                return LR_ERR_NULL;
            };
            if sid.is_null() {
                return LR_ERR_NULL;
            }
            let sid_ptr = crate::srv6::lr_srv6_sid_as_ptr(sid);
            if sid_ptr.is_null() {
                return LR_ERR_INVALID_HANDLE;
            }
            let mut octets = [0u8; 16];
            unsafe { std::ptr::copy_nonoverlapping(sid_ptr, octets.as_mut_ptr(), 16) };
            let sid_obj = Sid::from_octets(octets);
            match n.delete_seg6local_route(sid_obj) {
                Ok(()) => 0,
                Err(e) => record_seg6_route_err(&e),
            }
        },
        LR_ERR_PANIC,
    )
}

/// Write the most recent request bytes (the diagnostic for "the
/// kernel rejected this and I need to see what \"this\" was" —
/// hex-dump it on failure and compare against a reference
/// implementation's bytes) to `*out`. The bytes are owned by the
/// caller and must be released with [`lr_bytes_free`].
///
/// Returns 0 on success (including the no-bytes case — `out` is set
/// to an empty `lr_bytes_t`), `LR_ERR_NULL` on a NULL handle / out
/// pointer.
///
/// # Safety
/// `nl` must be a valid `lr_seg6_netlink_t`; `out` must point to a
/// writable `lr_bytes_t` (uninitialized is fine — the function writes
/// the whole struct).
#[no_mangle]
pub unsafe extern "C" fn lr_seg6_netlink_last_request_bytes(
    nl: lr_seg6_netlink_t,
    out: *mut lr_bytes_t,
) -> i32 {
    guarded(
        || unsafe {
            if out.is_null() {
                return LR_ERR_NULL;
            }
            let Some(n) = borrow_seg6_netlink(nl) else {
                return LR_ERR_NULL;
            };
            let v = n.last_request_bytes().unwrap_or_default();
            unsafe { out.write(lr_bytes_t::from_vec(v)) };
            0
        },
        LR_ERR_PANIC,
    )
}

/// Write the most recent response bytes (the raw NAK, extack
/// attributes included, for the same purpose as
/// [`lr_seg6_netlink_last_request_bytes`]) to `*out`. The bytes are
/// owned by the caller and must be released with [`lr_bytes_free`].
///
/// Returns 0 on success (including the no-bytes case), `LR_ERR_NULL`
/// on a NULL handle / out pointer.
///
/// # Safety
/// See [`lr_seg6_netlink_last_request_bytes`].
#[no_mangle]
pub unsafe extern "C" fn lr_seg6_netlink_last_response_bytes(
    nl: lr_seg6_netlink_t,
    out: *mut lr_bytes_t,
) -> i32 {
    guarded(
        || unsafe {
            if out.is_null() {
                return LR_ERR_NULL;
            }
            let Some(n) = borrow_seg6_netlink(nl) else {
                return LR_ERR_NULL;
            };
            let v = n.last_response_bytes().unwrap_or_default();
            unsafe { out.write(lr_bytes_t::from_vec(v)) };
            0
        },
        LR_ERR_PANIC,
    )
}

/// Drop a boxed `Seg6Netlink`. Safe to call with NULL.
///
/// # Safety
/// `nl` must have been produced by `lr_seg6_netlink_connect` and not
/// already freed.
#[no_mangle]
pub unsafe extern "C" fn lr_seg6_netlink_free(nl: lr_seg6_netlink_t) {
    guarded(
        || unsafe {
            drop(unbox_seg6_netlink(nl));
        },
        (),
    )
}

// =========================================================================
// Error helpers
// =========================================================================

/// Return the discriminant of the most recent `Seg6RouteError`
/// recorded in the thread-local last-error string. The Display form
/// is parsed back into a discriminant by substring match — kept in
/// the C ABI's own surface so a future typed-error-pointer surface
/// can call into `seg6_route_err_code` directly without going
/// through the thread-local string. Returns `LR_SEG6_ERR_UNKNOWN`
/// (-1) when no seg6 error is recorded.
///
/// This is a peek-only helper: it does not clear the last-error
/// string. Callers that need the human-readable message should still
/// call `lr_last_error`.
#[no_mangle]
pub extern "C" fn lr_seg6_route_err_code() -> i32 {
    let s = last_error_string();
    if s.is_empty() {
        return LR_SEG6_ERR_UNKNOWN;
    }
    // Match the Display form's stable prefixes (see
    // Seg6RouteError::fmt).
    if s.starts_with("SRv6 is not supported on this platform") {
        LR_SEG6_ERR_UNSUPPORTED
    } else if s.starts_with("SRv6 is not enabled") {
        LR_SEG6_ERR_NOT_ENABLED
    } else if s.starts_with("seg6 netlink syscall") {
        LR_SEG6_ERR_SYSCALL
    } else if s.starts_with("seg6 kernel error") {
        LR_SEG6_ERR_KERNEL
    } else if s.starts_with("bad SRH") {
        LR_SEG6_ERR_BAD_SRH
    } else if s.starts_with("unsupported seg6local action") {
        LR_SEG6_ERR_UNSUPPORTED_ACTION
    } else {
        LR_SEG6_ERR_UNKNOWN
    }
}

/// Return a stable, NUL-terminated name for a `Seg6RouteError`
/// discriminant. Returns `"unknown"` for an unrecognized code. The
/// returned pointer is valid until the next
/// `lr_seg6_route_err_name` call on this thread — same lifetime
/// contract as `lr_rtr_error_code_name` (the function writes the
/// name into a thread-local buffer).
#[no_mangle]
pub extern "C" fn lr_seg6_route_err_name(code: i32) -> *const std::os::raw::c_char {
    thread_local! {
        static BUF: std::cell::RefCell<Vec<u8>> = const { std::cell::RefCell::new(Vec::new()) };
    }
    guarded(
        || {
            let name: &'static [u8] = match code {
                LR_SEG6_ERR_UNSUPPORTED => b"unsupported",
                LR_SEG6_ERR_NOT_ENABLED => b"not-enabled",
                LR_SEG6_ERR_SYSCALL => b"syscall",
                LR_SEG6_ERR_KERNEL => b"kernel",
                LR_SEG6_ERR_BAD_SRH => b"bad-srh",
                LR_SEG6_ERR_UNSUPPORTED_ACTION => b"unsupported-action",
                _ => b"unknown",
            };
            BUF.with(|b| {
                let mut b = b.borrow_mut();
                b.clear();
                b.extend_from_slice(name);
                b.push(0);
                b.as_ptr() as *const std::os::raw::c_char
            })
        },
        std::ptr::null(),
    )
}

// =========================================================================
// Tests
// =========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::srv6::lr_srv6_sid_new;
    use crate::srv6_srh::lr_srv6_srh_new;

    fn make_v6_prefix() -> lr_prefix_t {
        lr_prefix_t {
            addr: [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            is_ipv6: 1,
            prefix_len: 64,
        }
    }

    fn make_srh_handle() -> lr_srv6_srh_t {
        let segs: [[u8; 16]; 1] = [[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]];
        let mut flat = Vec::with_capacity(16);
        for s in &segs {
            flat.extend_from_slice(s);
        }
        unsafe { lr_srv6_srh_new(flat.as_ptr(), segs.len()) }
    }

    fn make_sid_handle() -> lr_srv6_sid_t {
        let octets: [u8; 16] = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        unsafe { lr_srv6_sid_new(octets.as_ptr()) }
    }

    #[test]
    fn seg6_route_new_returns_handle() {
        let srh = make_srh_handle();
        let r = unsafe { lr_seg6_route_new(make_v6_prefix(), srh) };
        assert!(!r.is_null(), "lr_seg6_route_new returned NULL");
        unsafe { lr_seg6_route_free(r) };
        unsafe { crate::srv6_srh::lr_srv6_srh_free(srh) };
    }

    #[test]
    fn seg6_route_new_rejects_null_srh() {
        let r = unsafe { lr_seg6_route_new(make_v6_prefix(), std::ptr::null_mut()) };
        assert!(r.is_null(), "lr_seg6_route_new accepted a NULL srh");
        // The error string carries a human-readable diagnostic.
        assert!(crate::error::last_error_string().contains("NULL"));
    }

    #[test]
    fn seg6_route_new_rejects_ipv4_prefix() {
        let srh = make_srh_handle();
        let prefix = lr_prefix_t {
            addr: [0; 16],
            is_ipv6: 0,
            prefix_len: 24,
        };
        let r = unsafe { lr_seg6_route_new(prefix, srh) };
        assert!(r.is_null(), "lr_seg6_route_new accepted an IPv4 prefix");
        assert!(crate::error::last_error_string().contains("IPv6"));
        unsafe { crate::srv6_srh::lr_srv6_srh_free(srh) };
    }

    #[test]
    fn seg6_route_set_mode_round_trip() {
        let srh = make_srh_handle();
        let r = unsafe { lr_seg6_route_new(make_v6_prefix(), srh) };
        assert!(!r.is_null());

        assert_eq!(
            unsafe { lr_seg6_route_set_mode(r, LR_SEG6_ENCAP_INLINE) },
            0
        );
        assert_eq!(unsafe { lr_seg6_route_set_mode(r, LR_SEG6_ENCAP_ENCAP) }, 0);
        // Unknown mode is rejected.
        assert!(unsafe { lr_seg6_route_set_mode(r, 0xFFFFFFFF) } != 0);

        unsafe { lr_seg6_route_free(r) };
        unsafe { crate::srv6_srh::lr_srv6_srh_free(srh) };
    }

    #[test]
    fn seg6_route_set_mode_null_handle_returns_err_null() {
        assert_eq!(
            unsafe { lr_seg6_route_set_mode(std::ptr::null_mut(), LR_SEG6_ENCAP_INLINE) },
            LR_ERR_NULL
        );
    }

    #[test]
    fn seg6_route_set_if_index_round_trip() {
        let srh = make_srh_handle();
        let r = unsafe { lr_seg6_route_new(make_v6_prefix(), srh) };
        assert_eq!(unsafe { lr_seg6_route_set_if_index(r, 7) }, 0);
        assert_eq!(
            unsafe { lr_seg6_route_set_if_index(std::ptr::null_mut(), 7) },
            LR_ERR_NULL
        );
        unsafe { lr_seg6_route_free(r) };
        unsafe { crate::srv6_srh::lr_srv6_srh_free(srh) };
    }

    #[test]
    fn seg6_route_free_is_safe_on_null() {
        unsafe { lr_seg6_route_free(std::ptr::null_mut()) };
    }

    #[test]
    fn seg6_local_route_new_returns_handle() {
        let sid = make_sid_handle();
        // End behavior (RFC 8986 §4.1) — IANA wire value 1.
        let r = unsafe { lr_seg6_local_route_new(sid, 1) };
        assert!(!r.is_null(), "lr_seg6_local_route_new returned NULL");
        unsafe { lr_seg6_local_route_free(r) };
        unsafe { crate::srv6::lr_srv6_sid_free(sid) };
    }

    #[test]
    fn seg6_local_route_new_rejects_null_sid() {
        let r = unsafe { lr_seg6_local_route_new(std::ptr::null_mut(), 1) };
        assert!(r.is_null());
    }

    #[test]
    fn seg6_local_route_new_rejects_unknown_behavior() {
        let sid = make_sid_handle();
        // 0xFFFF is not in the IANA registry.
        let r = unsafe { lr_seg6_local_route_new(sid, 0xFFFF) };
        assert!(r.is_null());
        assert!(crate::error::last_error_string().contains("unknown Behavior"));
        unsafe { crate::srv6::lr_srv6_sid_free(sid) };
    }

    #[test]
    fn seg6_local_route_setters_round_trip() {
        let sid = make_sid_handle();
        let r = unsafe { lr_seg6_local_route_new(sid, 1) };
        assert!(!r.is_null());

        assert_eq!(unsafe { lr_seg6_local_route_set_if_index(r, 1) }, 0);
        let nh4: [u8; 4] = [203, 0, 113, 1];
        assert_eq!(unsafe { lr_seg6_local_route_set_nh4(r, nh4.as_ptr()) }, 0);
        let nh6: [u8; 16] = [0xfe; 16];
        assert_eq!(unsafe { lr_seg6_local_route_set_nh6(r, nh6.as_ptr()) }, 0);
        assert_eq!(unsafe { lr_seg6_local_route_set_iif(r, 2) }, 0);
        assert_eq!(unsafe { lr_seg6_local_route_set_oif(r, 3) }, 0);
        assert_eq!(unsafe { lr_seg6_local_route_set_table(r, 254) }, 0);
        assert_eq!(unsafe { lr_seg6_local_route_set_vrf_table(r, 100) }, 0);

        // SRH setter — borrow the SRH handle from a real one.
        let srh = make_srh_handle();
        assert_eq!(unsafe { lr_seg6_local_route_set_srh(r, srh) }, 0);
        unsafe { crate::srv6_srh::lr_srv6_srh_free(srh) };

        // NULL handle returns LR_ERR_NULL.
        assert_eq!(
            unsafe { lr_seg6_local_route_set_if_index(std::ptr::null_mut(), 1) },
            LR_ERR_NULL
        );

        unsafe { lr_seg6_local_route_free(r) };
        unsafe { crate::srv6::lr_srv6_sid_free(sid) };
    }

    #[test]
    fn seg6_local_route_set_nh4_null_pointer_returns_err_null() {
        let sid = make_sid_handle();
        let r = unsafe { lr_seg6_local_route_new(sid, 1) };
        assert_eq!(
            unsafe { lr_seg6_local_route_set_nh4(r, std::ptr::null()) },
            LR_ERR_NULL
        );
        unsafe { lr_seg6_local_route_free(r) };
        unsafe { crate::srv6::lr_srv6_sid_free(sid) };
    }

    #[test]
    fn seg6_local_route_free_is_safe_on_null() {
        unsafe { lr_seg6_local_route_free(std::ptr::null_mut()) };
    }

    #[test]
    fn seg6_netlink_connect_returns_null_or_handle() {
        // On Linux the seg6_enabled sysctl may be 0 (typical CI runner).
        // The connect call must NOT panic; it returns NULL with the
        // discriminant recorded in the last-error string.
        let nl = lr_seg6_netlink_connect();
        if nl.is_null() {
            // Either NotEnabled or Unsupported — both are valid outcomes
            // depending on the platform.
            let code = lr_seg6_route_err_code();
            assert!(
                code == LR_SEG6_ERR_NOT_ENABLED || code == LR_SEG6_ERR_UNSUPPORTED,
                "expected NotEnabled or Unsupported, got {code}"
            );
            return;
        }
        // On a system with SRv6 enabled we leak a handle — release it.
        unsafe { lr_seg6_netlink_free(nl) };
    }

    #[test]
    fn seg6_netlink_add_seg6_route_null_returns_err_null() {
        let srh = make_srh_handle();
        let r = unsafe { lr_seg6_route_new(make_v6_prefix(), srh) };
        assert_eq!(
            unsafe { lr_seg6_netlink_add_seg6_route(std::ptr::null_mut(), r) },
            LR_ERR_NULL
        );
        assert_eq!(
            unsafe { lr_seg6_netlink_add_seg6_route(std::ptr::null_mut(), std::ptr::null_mut()) },
            LR_ERR_NULL
        );
        unsafe { lr_seg6_route_free(r) };
        unsafe { crate::srv6_srh::lr_srv6_srh_free(srh) };
    }

    #[test]
    fn seg6_netlink_last_request_bytes_null_handle_returns_err_null() {
        let mut out = lr_bytes_t {
            ptr: std::ptr::null_mut(),
            len: 0,
            cap: 0,
        };
        assert_eq!(
            unsafe { lr_seg6_netlink_last_request_bytes(std::ptr::null_mut(), &raw mut out) },
            LR_ERR_NULL
        );
    }

    #[test]
    fn seg6_netlink_free_is_safe_on_null() {
        unsafe { lr_seg6_netlink_free(std::ptr::null_mut()) };
    }

    #[test]
    fn seg6_route_err_code_parses_display_forms() {
        // Record each error variant via the Display form and verify the
        // discriminant is recovered correctly.
        let cases: &[(Seg6RouteError, i32)] = &[
            (Seg6RouteError::Unsupported, LR_SEG6_ERR_UNSUPPORTED),
            (Seg6RouteError::NotEnabled, LR_SEG6_ERR_NOT_ENABLED),
            (Seg6RouteError::Syscall("test".into()), LR_SEG6_ERR_SYSCALL),
            (Seg6RouteError::Kernel("test".into()), LR_SEG6_ERR_KERNEL),
            (Seg6RouteError::BadSrh("test".into()), LR_SEG6_ERR_BAD_SRH),
            (
                Seg6RouteError::UnsupportedAction("test".into()),
                LR_SEG6_ERR_UNSUPPORTED_ACTION,
            ),
        ];
        for (e, expected) in cases {
            let _ = record_seg6_route_err(e);
            assert_eq!(lr_seg6_route_err_code(), *expected, "Display: {e}");
        }
    }

    #[test]
    fn seg6_route_err_name_returns_known_names() {
        assert_eq!(
            unsafe { std::ffi::CStr::from_ptr(lr_seg6_route_err_name(LR_SEG6_ERR_UNSUPPORTED)) }
                .to_str()
                .unwrap(),
            "unsupported"
        );
        assert_eq!(
            unsafe { std::ffi::CStr::from_ptr(lr_seg6_route_err_name(LR_SEG6_ERR_NOT_ENABLED)) }
                .to_str()
                .unwrap(),
            "not-enabled"
        );
        assert_eq!(
            unsafe { std::ffi::CStr::from_ptr(lr_seg6_route_err_name(LR_SEG6_ERR_SYSCALL)) }
                .to_str()
                .unwrap(),
            "syscall"
        );
        assert_eq!(
            unsafe { std::ffi::CStr::from_ptr(lr_seg6_route_err_name(LR_SEG6_ERR_KERNEL)) }
                .to_str()
                .unwrap(),
            "kernel"
        );
        assert_eq!(
            unsafe { std::ffi::CStr::from_ptr(lr_seg6_route_err_name(LR_SEG6_ERR_BAD_SRH)) }
                .to_str()
                .unwrap(),
            "bad-srh"
        );
        assert_eq!(
            unsafe {
                std::ffi::CStr::from_ptr(lr_seg6_route_err_name(LR_SEG6_ERR_UNSUPPORTED_ACTION))
            }
            .to_str()
            .unwrap(),
            "unsupported-action"
        );
        // Unknown code returns "unknown".
        assert_eq!(
            unsafe { std::ffi::CStr::from_ptr(lr_seg6_route_err_name(999)) }
                .to_str()
                .unwrap(),
            "unknown"
        );
    }
}
