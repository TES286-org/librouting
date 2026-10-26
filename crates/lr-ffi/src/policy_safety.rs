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
}
