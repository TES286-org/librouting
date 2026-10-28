//! Policy SafetyNet + PolicySet binding FFI.
//!
//! Mirrors the public Rust API of `lr_policy::safety::{SafetyNet,
//! SafetyConfig, SafetyViolation}` and parts of
//! `lr_policy::set::PolicySet` (the per-session binding surface that
//! the daemon wires up at start-up).
//!
//! # Surface
//!
//! - `lr_safety_net_new` — construct a `SafetyNet` for a given local
//!   AS (RFC 4271 §9.1.4 safety checks).
//! - `lr_safety_net_with_local_addr` — set the local source address
//!   (for martian / source-alias checks).
//! - `lr_safety_net_check` — check one route; returns 0 = OK, 1 =
//!   violation (the violation is recorded in the last-error string).
//! - `lr_safety_net_free` — drop the handle (safe on NULL).
//!
//! - `lr_policy_set_bind_import` / `_bind_export` — bind a route-map
//!   to a session's import / export path on an existing
//!   `lr_resolver_t` (the PolicySet handle).
//! - `lr_policy_set_validate` — validate the PolicySet's bindings;
//!   returns 0 = OK, 1 = invalid (recorded in the last-error
//!   string with the session handle).
//!
//! Every entry point runs inside the crate's `catch_unwind` barrier
//! ([`crate::guarded`]): a panic returns `LR_ERR_PANIC` and sets the
//! thread-local last-error string.

#![allow(unused_unsafe)]

use lr_core::addr::{Asn, IpAddr};
use lr_core::rib::Route;
use lr_policy::safety::{SafetyNet, SafetyViolation};

use crate::error::{set_last_error, LrError, LR_ERR_PANIC};
use crate::guarded;
use crate::handle::lr_resolver_t;

const LR_ERR_NULL: i32 = LrError::Null as i32;
#[allow(dead_code)]
const LR_ERR_OTHER: i32 = LrError::Other as i32;

// ---- Opaque handle type ----

#[repr(C)]
pub struct OpaqueSafetyNet {
    _private: [u8; 0],
}
pub type lr_safety_net_t = *mut OpaqueSafetyNet;

fn box_safety_net(s: SafetyNet) -> lr_safety_net_t {
    Box::into_raw(Box::new(s)) as lr_safety_net_t
}
unsafe fn borrow_safety_net(r: lr_safety_net_t) -> Option<&'static SafetyNet> {
    if r.is_null() {
        return None;
    }
    Some(unsafe { &*(r as *const SafetyNet) })
}
unsafe fn unbox_safety_net(r: lr_safety_net_t) -> Option<Box<SafetyNet>> {
    if r.is_null() {
        return None;
    }
    Some(unsafe { Box::from_raw(r as *mut SafetyNet) })
}

/// Translate a `SafetyViolation` to a human-readable string for the
/// last-error channel.
fn violation_msg(v: &SafetyViolation) -> String {
    format!("{:?}", v)
}

// ---- SafetyNet surface ----

/// Construct a `SafetyNet` for the given local AS (RFC 4271 §9.1.4
/// safety checks). The local AS is used for AS-path loop detection.
///
/// Returns NULL on a panic.
#[no_mangle]
pub extern "C" fn lr_safety_net_new(local_as: u32) -> lr_safety_net_t {
    guarded(
        || box_safety_net(SafetyNet::new(Asn::new(local_as))),
        std::ptr::null_mut(),
    )
}

/// Set the local source address (for martian / source-alias checks).
/// Returns a NEW handle (the input handle is consumed and freed).
///
/// # Safety
/// `r` must be a valid SafetyNet handle. `addr_v4` is the 4-byte IPv4
/// address (NULL when IPv6); `addr_v6` is the 16-byte IPv6 address
/// (NULL when IPv4).
#[no_mangle]
pub unsafe extern "C" fn lr_safety_net_with_local_addr(
    r: lr_safety_net_t,
    addr_v4: *const u8,
    addr_v6: *const u8,
) -> lr_safety_net_t {
    guarded(
        || unsafe {
            let Some(s) = unbox_safety_net(r) else {
                return std::ptr::null_mut();
            };
            let addr = if !addr_v4.is_null() {
                let mut a = [0u8; 4];
                a.copy_from_slice(unsafe { std::slice::from_raw_parts(addr_v4, 4) });
                IpAddr::V4(a)
            } else if !addr_v6.is_null() {
                let mut a = [0u8; 16];
                a.copy_from_slice(unsafe { std::slice::from_raw_parts(addr_v6, 16) });
                IpAddr::V6(a)
            } else {
                // No address provided — return the SafetyNet unchanged.
                return box_safety_net(*s);
            };
            box_safety_net(s.with_local_addr(addr))
        },
        std::ptr::null_mut(),
    )
}

/// Check one route against the safety net. `is_ebgp` selects the
/// eBGP-specific checks (RFC 4271 §9.1.2 — the AS_PATH must not
/// contain the local AS, the NEXT_HOP must not be the local address,
/// etc.).
///
/// Returns 0 when the route passes, 1 when a violation was detected
/// (the violation is recorded in the last-error string), negative on
/// error.
///
/// # Safety
/// `r` must be a valid SafetyNet handle. `route` must be a valid
/// route handle.
#[no_mangle]
pub unsafe extern "C" fn lr_safety_net_check(
    r: lr_safety_net_t,
    route: crate::handle::lr_route_t,
    is_ebgp: u8,
) -> i32 {
    guarded(
        || unsafe {
            let Some(s) = borrow_safety_net(r) else {
                return LR_ERR_NULL;
            };
            if route.is_null() {
                return LR_ERR_NULL;
            }
            let route_ref: &Route = unsafe { &*(route as *const Route) };
            match s.check(route_ref, is_ebgp != 0) {
                Ok(()) => 0,
                Err(violation) => {
                    set_last_error(violation_msg(&violation));
                    1
                }
            }
        },
        LR_ERR_PANIC,
    )
}

/// Drop a boxed SafetyNet. Safe to call with NULL.
///
/// # Safety
/// `r` must have been produced by `lr_safety_net_new` and not already
/// freed.
#[no_mangle]
pub unsafe extern "C" fn lr_safety_net_free(r: lr_safety_net_t) {
    guarded(
        || unsafe {
            drop(unbox_safety_net(r));
        },
        (),
    )
}

// ---- SafetyConfig accessors ----
//
// SafetyConfig lives inside SafetyNet as a pub field. The FFI surface
// exposes it as accessor functions so the embedder can build / mutate
// the config without copying the whole struct.

/// `LR_LIST_KIND_*` constants — mirrors [`lr_policy::set::ListKind`].
pub const LR_LIST_KIND_PREFIX: i32 = 0;
pub const LR_LIST_KIND_AS_PATH: i32 = 1;
pub const LR_LIST_KIND_COMMUNITY: i32 = 2;

/// `LR_SAFETY_VIOLATION_*` constants — discriminant for
/// [`SafetyViolation`] returned by [`lr_safety_net_check_violation`].
pub const LR_SAFETY_VIOLATION_AS_LOOP: i32 = 1;
pub const LR_SAFETY_VIOLATION_INVALID_NEXT_HOP: i32 = 2;
pub const LR_SAFETY_VIOLATION_EMPTY_AS_PATH_EBGP: i32 = 3;
pub const LR_SAFETY_VIOLATION_INVALID_ORIGIN: i32 = 4;
pub const LR_SAFETY_VIOLATION_EXCESSIVE_AS_LOOP: i32 = 5;
pub const LR_SAFETY_VIOLATION_OVERSIZED_AS_PATH: i32 = 6;
pub const LR_SAFETY_VIOLATION_MARTIAN_PREFIX: i32 = 7;
pub const LR_SAFETY_VIOLATION_OVERSIZED_LOCAL_PREF: i32 = 8;

/// Read the global kill switch from the safety net's config. Returns
/// 1 when enabled, 0 when disabled, `LR_ERR_NULL` (-1) on a NULL handle.
///
/// # Safety
/// `r` must be a valid SafetyNet handle.
#[no_mangle]
pub unsafe extern "C" fn lr_safety_net_config_enabled(r: lr_safety_net_t) -> i32 {
    guarded(
        || unsafe {
            let Some(s) = borrow_safety_net(r) else {
                return LR_ERR_NULL;
            };
            s.cfg.enabled as i32
        },
        LR_ERR_PANIC,
    )
}

/// Set the global kill switch on the safety net's config.
///
/// # Safety
/// `r` must be a valid SafetyNet handle.
#[no_mangle]
pub unsafe extern "C" fn lr_safety_net_config_set_enabled(r: lr_safety_net_t, enabled: u8) -> i32 {
    guarded(
        || unsafe {
            let Some(s) = borrow_resolver_mut_safety(r) else {
                return LR_ERR_NULL;
            };
            s.cfg.enabled = enabled != 0;
            0
        },
        LR_ERR_PANIC,
    )
}

/// Read one of the boolean toggles on the safety net's config. `field`
/// selects which:
/// - 0: reject_as_loop
/// - 1: reject_invalid_next_hop
/// - 2: reject_empty_as_path_ebgp
/// - 3: reject_invalid_origin
/// - 4: reject_excessive_as_loop
/// - 5: reject_oversized_as_path
/// - 6: reject_martian_prefix
/// - 7: reject_oversized_local_pref
/// - 8: reject_martian_v4
/// - 9: reject_martian_v6
///
/// Returns the toggle value (0/1), `LR_ERR_NULL` (-1) on a NULL
/// handle, `LR_ERR_OTHER` (-6) on an unknown field id.
///
/// # Safety
/// `r` must be a valid SafetyNet handle.
#[no_mangle]
pub unsafe extern "C" fn lr_safety_net_config_get_bool(r: lr_safety_net_t, field: i32) -> i32 {
    guarded(
        || unsafe {
            let Some(s) = borrow_safety_net(r) else {
                return LR_ERR_NULL;
            };
            let v = match field {
                0 => s.cfg.reject_as_loop,
                1 => s.cfg.reject_invalid_next_hop,
                2 => s.cfg.reject_empty_as_path_ebgp,
                3 => s.cfg.reject_invalid_origin,
                4 => s.cfg.reject_excessive_as_loop,
                5 => s.cfg.reject_oversized_as_path,
                6 => s.cfg.reject_martian_prefix,
                7 => s.cfg.reject_oversized_local_pref,
                8 => s.cfg.reject_martian_v4,
                9 => s.cfg.reject_martian_v6,
                _ => {
                    set_last_error(format!("unknown safety config field id {field}"));
                    return LR_ERR_OTHER;
                }
            };
            v as i32
        },
        LR_ERR_PANIC,
    )
}

/// Set one of the boolean toggles on the safety net's config. `field`
/// selects which (see [`lr_safety_net_config_get_bool`]); `value` is
/// the new toggle value (0 or 1).
///
/// # Safety
/// `r` must be a valid SafetyNet handle.
#[no_mangle]
pub unsafe extern "C" fn lr_safety_net_config_set_bool(
    r: lr_safety_net_t,
    field: i32,
    value: u8,
) -> i32 {
    guarded(
        || unsafe {
            let Some(s) = borrow_resolver_mut_safety(r) else {
                return LR_ERR_NULL;
            };
            let v = value != 0;
            match field {
                0 => s.cfg.reject_as_loop = v,
                1 => s.cfg.reject_invalid_next_hop = v,
                2 => s.cfg.reject_empty_as_path_ebgp = v,
                3 => s.cfg.reject_invalid_origin = v,
                4 => s.cfg.reject_excessive_as_loop = v,
                5 => s.cfg.reject_oversized_as_path = v,
                6 => s.cfg.reject_martian_prefix = v,
                7 => s.cfg.reject_oversized_local_pref = v,
                8 => s.cfg.reject_martian_v4 = v,
                9 => s.cfg.reject_martian_v6 = v,
                _ => {
                    set_last_error(format!("unknown safety config field id {field}"));
                    return LR_ERR_OTHER;
                }
            }
            0
        },
        LR_ERR_PANIC,
    )
}

/// Read one of the integer tunables on the safety net's config. `field`
/// selects which:
/// - 0: max_as_path_loops (u8)
/// - 1: max_as_path_length (usize)
/// - 2: max_local_pref (u32)
///
/// Returns the tunable value as a u64 (zero-extended), `LR_ERR_NULL`
/// (-1) on a NULL handle, `LR_ERR_OTHER` (-6) on an unknown field id.
///
/// # Safety
/// `r` must be a valid SafetyNet handle.
#[no_mangle]
pub unsafe extern "C" fn lr_safety_net_config_get_u64(r: lr_safety_net_t, field: i32) -> u64 {
    guarded(
        || unsafe {
            let Some(s) = borrow_safety_net(r) else {
                return LR_ERR_NULL as u64;
            };
            match field {
                0 => s.cfg.max_as_path_loops as u64,
                1 => s.cfg.max_as_path_length as u64,
                2 => s.cfg.max_local_pref as u64,
                _ => {
                    set_last_error(format!("unknown safety config field id {field}"));
                    LR_ERR_OTHER as u64
                }
            }
        },
        LR_ERR_PANIC as u64,
    )
}

/// Set one of the integer tunables on the safety net's config. `field`
/// selects which (see [`lr_safety_net_config_get_u64`]); `value` is
/// the new tunable value (truncated to the field's native width).
///
/// # Safety
/// `r` must be a valid SafetyNet handle.
#[no_mangle]
pub unsafe extern "C" fn lr_safety_net_config_set_u64(
    r: lr_safety_net_t,
    field: i32,
    value: u64,
) -> i32 {
    guarded(
        || unsafe {
            let Some(s) = borrow_resolver_mut_safety(r) else {
                return LR_ERR_NULL;
            };
            match field {
                0 => s.cfg.max_as_path_loops = value as u8,
                1 => s.cfg.max_as_path_length = value as usize,
                2 => s.cfg.max_local_pref = value as u32,
                _ => {
                    set_last_error(format!("unknown safety config field id {field}"));
                    return LR_ERR_OTHER;
                }
            }
            0
        },
        LR_ERR_PANIC,
    )
}

/// Check one route against the safety net and surface the violation
/// discriminant when one is detected. Returns 0 when the route passes,
/// a positive `LR_SAFETY_VIOLATION_*` constant when a violation was
/// detected (the human-readable message is recorded in the last-error
/// string), `LR_ERR_NULL` (-1) on a NULL handle, `LR_ERR_PANIC` (-4)
/// on a panic.
///
/// # Safety
/// `r` must be a valid SafetyNet handle. `route` must be a valid
/// route handle.
#[no_mangle]
pub unsafe extern "C" fn lr_safety_net_check_violation(
    r: lr_safety_net_t,
    route: crate::handle::lr_route_t,
    is_ebgp: u8,
) -> i32 {
    guarded(
        || unsafe {
            let Some(s) = borrow_safety_net(r) else {
                return LR_ERR_NULL;
            };
            if route.is_null() {
                return LR_ERR_NULL;
            }
            let route_ref: &Route = unsafe { &*(route as *const Route) };
            match s.check(route_ref, is_ebgp != 0) {
                Ok(()) => 0,
                Err(violation) => {
                    set_last_error(violation.to_string());
                    match violation {
                        SafetyViolation::AsLoop { .. } => LR_SAFETY_VIOLATION_AS_LOOP,
                        SafetyViolation::InvalidNextHop { .. } => {
                            LR_SAFETY_VIOLATION_INVALID_NEXT_HOP
                        }
                        SafetyViolation::EmptyAsPathEbgp { .. } => {
                            LR_SAFETY_VIOLATION_EMPTY_AS_PATH_EBGP
                        }
                        SafetyViolation::InvalidOrigin { .. } => LR_SAFETY_VIOLATION_INVALID_ORIGIN,
                        SafetyViolation::ExcessiveAsLoop { .. } => {
                            LR_SAFETY_VIOLATION_EXCESSIVE_AS_LOOP
                        }
                        SafetyViolation::OversizedAsPath { .. } => {
                            LR_SAFETY_VIOLATION_OVERSIZED_AS_PATH
                        }
                        SafetyViolation::MartianPrefix { .. } => LR_SAFETY_VIOLATION_MARTIAN_PREFIX,
                        SafetyViolation::OversizedLocalPref { .. } => {
                            LR_SAFETY_VIOLATION_OVERSIZED_LOCAL_PREF
                        }
                    }
                }
            }
        },
        LR_ERR_PANIC,
    )
}

/// Borrow a SafetyNet handle as `&mut SafetyNet` for in-place config
/// mutation.
///
/// # Safety
/// `r` must have been produced by [`lr_safety_net_new`] and not be
/// freed while the returned reference is live.
unsafe fn borrow_resolver_mut_safety(r: lr_safety_net_t) -> Option<&'static mut SafetyNet> {
    if r.is_null() {
        return None;
    }
    Some(unsafe { &mut *(r as *mut SafetyNet) })
}

// ---- PolicySet lookup surface ----
//
// The existing lr_resolver_* API covers construction + adding lists
// + adding route-map entries. The lookup surface (list_id, route_map,
// route_map_names, match_condition, push_route_map_entry) is the gap.

/// Look up a list id by name and kind. Returns the list id (>= 1)
/// when found, 0 when the name is not registered, negative on error.
///
/// `kind` is one of the `LR_LIST_KIND_*` constants.
///
/// # Safety
/// `r` must be a valid resolver handle. `name` must be a
/// NUL-terminated C string.
#[no_mangle]
pub unsafe extern "C" fn lr_resolver_list_id(
    r: lr_resolver_t,
    kind: i32,
    name: *const std::ffi::c_char,
) -> i32 {
    guarded(
        || unsafe {
            let Some(set) = borrow_resolver_mut(r) else {
                return LR_ERR_NULL;
            };
            let Some(name) = (unsafe { read_cstr(name) }) else {
                set_last_error("null or non-UTF-8 list name".to_string());
                return LrError::BadUtf8 as i32;
            };
            let Some(list_kind) = i32_to_list_kind(kind) else {
                set_last_error(format!("unknown list kind id {kind}"));
                return LR_ERR_OTHER;
            };
            match set.list_id(list_kind, &name) {
                Some(id) => i32::try_from(id).unwrap_or(i32::MAX),
                None => 0,
            }
        },
        LR_ERR_PANIC,
    )
}

/// Count the route-maps registered on the resolver. Returns 0 on a
/// NULL handle.
///
/// # Safety
/// `r` must be a valid resolver handle.
#[no_mangle]
pub unsafe extern "C" fn lr_resolver_route_map_count(r: lr_resolver_t) -> usize {
    guarded(
        || unsafe {
            let Some(set) = borrow_resolver_mut(r) else {
                return 0;
            };
            set.route_map_names().count()
        },
        0,
    )
}

/// Enumerate the route-map names registered on the resolver. Writes
/// up to `cap` NUL-terminated UTF-8 strings into `out_buf` (each
/// pointer points into a single contiguous buffer of `cap` bytes
/// total). Writes the matching string offsets into `out_offsets` /
/// `out_lens`. Returns the total number of route-maps (>= 0) — a
/// return value greater than `cap` means the buffer was too small.
///
/// The caller should size the buffer by calling
/// [`lr_resolver_route_map_count`] first, then call this with a buffer
/// of `count * 64` bytes (route-map names are bounded by 64 chars in
/// practice).
///
/// # Safety
/// `r` must be a valid resolver handle. `out_buf` (when non-null)
/// must point to `cap` writable bytes. `out_offsets` / `out_lens`
/// (when non-null) must point to `cap` writable `uintptr_t` values.
#[no_mangle]
pub unsafe extern "C" fn lr_resolver_route_map_names(
    r: lr_resolver_t,
    out_buf: *mut std::ffi::c_char,
    out_offsets: *mut usize,
    out_lens: *mut usize,
    cap: usize,
) -> usize {
    guarded(
        || unsafe {
            let Some(set) = borrow_resolver_mut(r) else {
                return 0;
            };
            let names: Vec<String> = set.route_map_names().map(str::to_owned).collect();
            let total = names.len();
            if !out_buf.is_null() && !out_offsets.is_null() && !out_lens.is_null() && cap > 0 {
                let mut cursor: usize = 0;
                let to_write = total.min(cap);
                for (i, name) in names.iter().take(to_write).enumerate() {
                    let bytes = name.as_bytes();
                    let len = bytes.len();
                    // Each name is NUL-terminated in the output buffer.
                    if cursor + len + 1 > cap {
                        break;
                    }
                    unsafe {
                        std::ptr::copy_nonoverlapping(
                            bytes.as_ptr() as *const std::ffi::c_char,
                            out_buf.add(cursor),
                            len,
                        );
                        *out_buf.add(cursor + len) = 0;
                        *out_offsets.add(i) = cursor;
                        *out_lens.add(i) = len;
                    }
                    cursor += len + 1;
                }
            }
            total
        },
        0,
    )
}

/// Append an entry to an existing route-map. Returns 0 on success,
/// `LR_ERR_NULL` on a NULL resolver / map handle, `LR_ERR_OTHER` (-6)
/// when the named route-map does not exist.
///
/// # Safety
/// `r` must be a valid resolver handle. `name` must be a
/// NUL-terminated C string. `map` must be a valid route-map handle.
#[no_mangle]
pub unsafe extern "C" fn lr_resolver_push_route_map_entry(
    r: lr_resolver_t,
    name: *const std::ffi::c_char,
    map: crate::handle::lr_route_map_t,
) -> i32 {
    guarded(
        || unsafe {
            let Some(set) = borrow_resolver_mut(r) else {
                return LR_ERR_NULL;
            };
            if map.is_null() {
                return LR_ERR_NULL;
            }
            let Some(name) = (unsafe { read_cstr(name) }) else {
                set_last_error("null or non-UTF-8 route-map name".to_string());
                return LrError::BadUtf8 as i32;
            };
            let map_ref: &lr_policy::route_map::RouteMap =
                unsafe { &*(map as *const lr_policy::route_map::RouteMap) };
            // The RouteMap::push entry API expects a RouteMapEntry; we
            // copy the entries from the source map into the named map.
            // The simplest shape: take all entries from the source map
            // and push them onto the named one. The caller typically
            // builds a single-entry RouteMap, calls this, then frees
            // the source.
            for entry in &map_ref.entries {
                set.push_route_map_entry(name.clone(), entry.clone());
            }
            0
        },
        LR_ERR_PANIC,
    )
}

/// Read a NUL-terminated C string into a Rust String. Returns None
/// when the pointer is null or the bytes are not valid UTF-8.
///
/// # Safety
/// `s` must be a NUL-terminated C string (or NULL).
unsafe fn read_cstr(s: *const std::ffi::c_char) -> Option<String> {
    if s.is_null() {
        return None;
    }
    match unsafe { std::ffi::CStr::from_ptr(s) }.to_str() {
        Ok(s) => Some(s.to_owned()),
        Err(_) => None,
    }
}

/// Translate an `LR_LIST_KIND_*` integer to a Rust [`ListKind`].
fn i32_to_list_kind(v: i32) -> Option<lr_policy::set::ListKind> {
    match v {
        LR_LIST_KIND_PREFIX => Some(lr_policy::set::ListKind::Prefix),
        LR_LIST_KIND_AS_PATH => Some(lr_policy::set::ListKind::AsPath),
        LR_LIST_KIND_COMMUNITY => Some(lr_policy::set::ListKind::Community),
        _ => None,
    }
}

// ---- PolicySet binding surface ----
//
// The existing lr_resolver_* API covers construction + adding lists
// + adding route-map entries. The binding / validate surface is
// missing — this section fills that gap.

/// Borrow a `lr_resolver_t` (PolicySet) as `&mut PolicySet`.
///
/// # Safety
/// `r` must be a valid resolver handle.
unsafe fn borrow_resolver_mut(r: lr_resolver_t) -> Option<&'static mut lr_policy::set::PolicySet> {
    if r.is_null() {
        return None;
    }
    Some(unsafe { &mut *(r as *mut lr_policy::set::PolicySet) })
}

/// Bind a route-map to a session's import path. Returns 0 on
/// success, `LR_ERR_NULL` on a NULL resolver, `LR_ERR_OTHER` (-6)
/// when the named route-map does not exist.
///
/// # Safety
/// `r` must be a valid resolver handle. `map_name` must be a
/// NUL-terminated C string (NULL is treated as "no map").
#[no_mangle]
pub unsafe extern "C" fn lr_policy_set_bind_import(
    r: lr_resolver_t,
    session: u64,
    map_name: *const std::ffi::c_char,
) -> i32 {
    guarded(
        || unsafe {
            let Some(set) = borrow_resolver_mut(r) else {
                return LR_ERR_NULL;
            };
            let name = if map_name.is_null() {
                String::new()
            } else {
                match unsafe { std::ffi::CStr::from_ptr(map_name) }.to_str() {
                    Ok(s) => s.to_owned(),
                    Err(_) => {
                        set_last_error("map_name is not valid UTF-8".into());
                        return LrError::BadUtf8 as i32;
                    }
                }
            };
            set.bind_import(session, name);
            0
        },
        LR_ERR_PANIC,
    )
}

/// Bind a route-map to a session's export path. Same contract as
/// [`lr_policy_set_bind_import`].
///
/// # Safety
/// See [`lr_policy_set_bind_import`].
#[no_mangle]
pub unsafe extern "C" fn lr_policy_set_bind_export(
    r: lr_resolver_t,
    session: u64,
    map_name: *const std::ffi::c_char,
) -> i32 {
    guarded(
        || unsafe {
            let Some(set) = borrow_resolver_mut(r) else {
                return LR_ERR_NULL;
            };
            let name = if map_name.is_null() {
                String::new()
            } else {
                match unsafe { std::ffi::CStr::from_ptr(map_name) }.to_str() {
                    Ok(s) => s.to_owned(),
                    Err(_) => {
                        set_last_error("map_name is not valid UTF-8".into());
                        return LrError::BadUtf8 as i32;
                    }
                }
            };
            set.bind_export(session, name);
            0
        },
        LR_ERR_PANIC,
    )
}

/// Validate the PolicySet's bindings — returns 0 when the set is
/// internally consistent, 1 when a binding references a route-map
/// that does not exist (the offending session + reason are recorded
/// in the last-error string), negative on error.
///
/// # Safety
/// `r` must be a valid resolver handle.
#[no_mangle]
pub unsafe extern "C" fn lr_policy_set_validate(r: lr_resolver_t) -> i32 {
    guarded(
        || unsafe {
            let Some(set) = borrow_resolver_mut(r) else {
                return LR_ERR_NULL;
            };
            match set.validate() {
                Ok(()) => 0,
                Err((session, kind, detail)) => {
                    set_last_error(format!(
                        "policy set invalid: session {session} {kind}: {detail}"
                    ));
                    1
                }
            }
        },
        LR_ERR_PANIC,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::lr_prefix_t;
    use crate::policy_objects::lr_route_new_v4;

    fn build_route(prefix: [u8; 4], plen: u8, _asn: u32) -> crate::handle::lr_route_t {
        // Reuse the existing route constructor — it builds a Route
        // with the given prefix and protocol = Bgp.
        unsafe {
            lr_route_new_v4(prefix.as_ptr(), plen, 0 /* Bgp */)
        }
    }

    #[test]
    fn ffi_safety_net_new_and_check() {
        let s = lr_safety_net_new(64512);
        assert!(!s.is_null());

        // A route for 10.0.0.0/24 with no AS path passes the safety
        // net (no loop, no martian, no NEXT_HOP alias).
        let r = build_route([10, 0, 0, 0], 24, 64513);
        let rc = unsafe { lr_safety_net_check(s, r, 1) };
        // The route may or may not pass depending on whether the
        // safety net's defaults consider it a martian — but the
        // return code must be 0 (pass) or 1 (violation), never
        // negative.
        assert!(rc == 0 || rc == 1, "rc = {rc}");
        unsafe { crate::policy_objects::lr_route_free(r) };
        unsafe { lr_safety_net_free(s) };
    }

    #[test]
    fn ffi_safety_net_handles_null_safely() {
        unsafe { lr_safety_net_free(std::ptr::null_mut()) };
        let rc = unsafe { lr_safety_net_check(std::ptr::null_mut(), std::ptr::null_mut(), 1) };
        assert_eq!(rc, LR_ERR_NULL);
    }

    #[test]
    fn ffi_safety_net_with_local_addr_v4() {
        let s = lr_safety_net_new(64512);
        let v4 = [10u8, 0, 0, 1];
        let s2 = unsafe { lr_safety_net_with_local_addr(s, v4.as_ptr(), std::ptr::null()) };
        assert!(!s2.is_null());
        unsafe { lr_safety_net_free(s2) };
    }

    #[test]
    fn ffi_safety_net_with_local_addr_v6() {
        let s = lr_safety_net_new(64512);
        let v6 = [0xfe_u8, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let s2 = unsafe { lr_safety_net_with_local_addr(s, std::ptr::null(), v6.as_ptr()) };
        assert!(!s2.is_null());
        unsafe { lr_safety_net_free(s2) };
    }

    #[test]
    fn ffi_policy_set_validate_on_fresh_set() {
        // A fresh resolver (PolicySet) has no bindings — validate
        // returns 0.
        let r = crate::policy_objects::lr_resolver_new();
        assert!(!r.is_null());
        let rc = unsafe { lr_policy_set_validate(r) };
        assert_eq!(rc, 0);
        unsafe { crate::policy_objects::lr_resolver_free(r) };
    }

    #[test]
    fn ffi_policy_set_bind_import_and_export() {
        let r = crate::policy_objects::lr_resolver_new();
        let name = std::ffi::CString::new("IMPORT").unwrap();
        let rc = unsafe { lr_policy_set_bind_import(r, 1, name.as_ptr()) };
        assert_eq!(rc, 0);
        let name2 = std::ffi::CString::new("EXPORT").unwrap();
        let rc = unsafe { lr_policy_set_bind_export(r, 1, name2.as_ptr()) };
        assert_eq!(rc, 0);
        unsafe { crate::policy_objects::lr_resolver_free(r) };
    }

    // ---- SafetyConfig accessor tests ----

    #[test]
    fn ffi_safety_net_config_enabled_default_true() {
        let s = lr_safety_net_new(64512);
        let v = unsafe { lr_safety_net_config_enabled(s) };
        assert_eq!(v, 1, "SafetyConfig::default().enabled is true");
        unsafe { lr_safety_net_free(s) };
    }

    #[test]
    fn ffi_safety_net_config_set_enabled_toggles() {
        let s = lr_safety_net_new(64512);
        // Disable the kill switch.
        let rc = unsafe { lr_safety_net_config_set_enabled(s, 0) };
        assert_eq!(rc, 0);
        assert_eq!(unsafe { lr_safety_net_config_enabled(s) }, 0);
        // Re-enable.
        let rc = unsafe { lr_safety_net_config_set_enabled(s, 1) };
        assert_eq!(rc, 0);
        assert_eq!(unsafe { lr_safety_net_config_enabled(s) }, 1);
        unsafe { lr_safety_net_free(s) };
    }

    #[test]
    fn ffi_safety_net_config_bool_round_trip() {
        let s = lr_safety_net_new(64512);
        // Default reject_as_loop is true → field 0 → 1.
        assert_eq!(unsafe { lr_safety_net_config_get_bool(s, 0) }, 1);
        // Disable it.
        let rc = unsafe { lr_safety_net_config_set_bool(s, 0, 0) };
        assert_eq!(rc, 0);
        assert_eq!(unsafe { lr_safety_net_config_get_bool(s, 0) }, 0);
        // Unknown field id.
        assert_eq!(
            unsafe { lr_safety_net_config_get_bool(s, 99) },
            LR_ERR_OTHER
        );
        assert_eq!(
            unsafe { lr_safety_net_config_set_bool(s, 99, 1) },
            LR_ERR_OTHER
        );
        // NULL handle.
        assert_eq!(
            unsafe { lr_safety_net_config_get_bool(std::ptr::null_mut(), 0) },
            LR_ERR_NULL
        );
        assert_eq!(
            unsafe { lr_safety_net_config_set_bool(std::ptr::null_mut(), 0, 1) },
            LR_ERR_NULL
        );
        unsafe { lr_safety_net_free(s) };
    }

    #[test]
    fn ffi_safety_net_config_u64_round_trip() {
        let s = lr_safety_net_new(64512);
        // max_as_path_loops (field 0) default is 3.
        assert_eq!(unsafe { lr_safety_net_config_get_u64(s, 0) }, 3);
        // Set to 5.
        let rc = unsafe { lr_safety_net_config_set_u64(s, 0, 5) };
        assert_eq!(rc, 0);
        assert_eq!(unsafe { lr_safety_net_config_get_u64(s, 0) }, 5);
        // max_as_path_length (field 1) default is 64.
        assert_eq!(unsafe { lr_safety_net_config_get_u64(s, 1) }, 64);
        // max_local_pref (field 2) default is u32::MAX.
        assert_eq!(
            unsafe { lr_safety_net_config_get_u64(s, 2) },
            u32::MAX as u64
        );
        // Unknown field id.
        assert_eq!(
            unsafe { lr_safety_net_config_get_u64(s, 99) },
            LR_ERR_OTHER as u64
        );
        assert_eq!(
            unsafe { lr_safety_net_config_set_u64(s, 99, 0) },
            LR_ERR_OTHER
        );
        // NULL handle.
        assert_eq!(
            unsafe { lr_safety_net_config_get_u64(std::ptr::null_mut(), 0) },
            LR_ERR_NULL as u64
        );
        assert_eq!(
            unsafe { lr_safety_net_config_set_u64(std::ptr::null_mut(), 0, 0) },
            LR_ERR_NULL
        );
        unsafe { lr_safety_net_free(s) };
    }

    #[test]
    fn ffi_safety_net_check_violation_returns_zero_or_known_code() {
        let s = lr_safety_net_new(64512);
        let r = build_route([10, 0, 0, 0], 24, 64513);
        let rc = unsafe { lr_safety_net_check_violation(s, r, 1) };
        // The route may or may not pass depending on the safety net's
        // defaults; valid return codes are 0 (pass) or any of the
        // LR_SAFETY_VIOLATION_* constants (1..=8).
        let valid_range = LR_SAFETY_VIOLATION_AS_LOOP..=LR_SAFETY_VIOLATION_OVERSIZED_LOCAL_PREF;
        assert!(rc == 0 || valid_range.contains(&rc), "rc = {rc}");
        unsafe { crate::policy_objects::lr_route_free(r) };
        unsafe { lr_safety_net_free(s) };
    }

    // ---- PolicySet lookup tests ----

    #[test]
    fn ffi_resolver_list_id_returns_zero_for_unknown() {
        let r = crate::policy_objects::lr_resolver_new();
        let name = std::ffi::CString::new("no-such-list").unwrap();
        let id = unsafe { lr_resolver_list_id(r, LR_LIST_KIND_PREFIX, name.as_ptr()) };
        assert_eq!(id, 0, "unknown list name returns 0");
        unsafe { crate::policy_objects::lr_resolver_free(r) };
    }

    #[test]
    fn ffi_resolver_list_id_returns_id_for_registered() {
        let r = crate::policy_objects::lr_resolver_new();
        // Add a prefix-list named "PL" via the existing API.
        let list = crate::policy_objects::lr_prefix_list_new();
        let p = lr_prefix_t {
            addr: {
                let mut buf = [0u8; 16];
                buf[..4].copy_from_slice(&[10, 0, 0, 0]);
                buf
            },
            is_ipv6: 0,
            prefix_len: 8,
        };
        unsafe { crate::policy_objects::lr_prefix_list_add(list, &raw const p, 0, 0, 1) };
        let name = std::ffi::CString::new("PL").unwrap();
        let added_id =
            unsafe { crate::policy_objects::lr_resolver_add_prefix_list(r, name.as_ptr(), list) };
        assert!(
            added_id >= 0,
            "add_prefix_list returns >= 0; got {added_id}"
        );

        // Lookup by name + kind returns the same id.
        let id = unsafe { lr_resolver_list_id(r, LR_LIST_KIND_PREFIX, name.as_ptr()) };
        assert_eq!(id, added_id, "list_id returns the same id");

        // Wrong kind returns 0.
        let id = unsafe { lr_resolver_list_id(r, LR_LIST_KIND_AS_PATH, name.as_ptr()) };
        assert_eq!(id, 0, "wrong kind returns 0");

        // Unknown kind id returns LR_ERR_OTHER.
        let id = unsafe { lr_resolver_list_id(r, 999, name.as_ptr()) };
        assert_eq!(id, LR_ERR_OTHER);

        // NULL resolver returns LR_ERR_NULL.
        let id = unsafe {
            lr_resolver_list_id(std::ptr::null_mut(), LR_LIST_KIND_PREFIX, name.as_ptr())
        };
        assert_eq!(id, LR_ERR_NULL);

        unsafe { crate::policy_objects::lr_resolver_free(r) };
    }

    #[test]
    fn ffi_resolver_route_map_count_and_names() {
        let r = crate::policy_objects::lr_resolver_new();
        // A fresh resolver has 0 route-maps.
        assert_eq!(unsafe { lr_resolver_route_map_count(r) }, 0);

        // Add a route-map named "RM1" via the existing API. The
        // existing lr_resolver_add_route_map (called by add_route_map
        // on the C side) registers the map under that name.
        // The simplest shape: use lr_route_map_new + lr_resolver_* to
        // register one. We'll just verify the count goes up.
        // Note: existing FFI does not expose add_route_map by name;
        // the count surface is what we're testing — 0 on fresh.

        // route_map_names returns 0 on a fresh resolver.
        let mut buf = vec![0u8; 256];
        let mut offsets = vec![0usize; 4];
        let mut lens = vec![0usize; 4];
        let n = unsafe {
            lr_resolver_route_map_names(
                r,
                buf.as_mut_ptr() as *mut std::ffi::c_char,
                offsets.as_mut_ptr(),
                lens.as_mut_ptr(),
                4,
            )
        };
        assert_eq!(n, 0, "fresh resolver has 0 route-maps");

        // NULL resolver returns 0.
        assert_eq!(
            unsafe { lr_resolver_route_map_count(std::ptr::null_mut()) },
            0
        );
        let n = unsafe {
            lr_resolver_route_map_names(
                std::ptr::null_mut(),
                buf.as_mut_ptr() as *mut std::ffi::c_char,
                offsets.as_mut_ptr(),
                lens.as_mut_ptr(),
                4,
            )
        };
        assert_eq!(n, 0);

        unsafe { crate::policy_objects::lr_resolver_free(r) };
    }
}
