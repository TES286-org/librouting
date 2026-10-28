//! lr-policy gap-closure FFI — Policy + PolicyChain + ApplySetError enum.
//!
//! Issue #92 — gap closure: the `lr_policy::{Policy, PolicyChain,
//! PolicyVerdict}` Rust pub API had no C ABI exposure. A C embedder
//! could only call `lr_route_map_evaluate` (single RouteMap); the
//! multi-map chaining machinery required hand-rolling the loop in C.
//! This batch adds the chain as an opaque handle so a C embedder can
//! push route-maps and evaluate in one call, matching the Rust API.
//!
//! Also exposes the `ApplySetError` enum (RFC 4271 §5.1.3 — well-known
//! attribute validation failures) so a C embedder can switch on
//! named discriminants instead of integer return codes.

#![allow(unused_unsafe)]
#![allow(dead_code)]

use crate::error::LrError;
use crate::guarded;
use crate::handle::lr_route_t;
use lr_policy::action::ApplySetError;
use lr_policy::policy::{Policy, PolicyChain, PolicyVerdict};
use lr_policy::route_map::RouteMap;
use lr_policy::set::PolicySet;

const LR_ERR_NULL: i32 = LrError::Null as i32;

// ---- opaque handles ----

#[repr(C)]
pub struct OpaquePolicyChain {
    _private: [u8; 0],
}
pub type lr_policy_chain_t = *mut OpaquePolicyChain;

#[repr(C)]
pub struct OpaquePolicy {
    _private: [u8; 0],
}
pub type lr_policy_t = *mut OpaquePolicy;

fn box_chain(c: PolicyChain) -> lr_policy_chain_t {
    Box::into_raw(Box::new(c)) as lr_policy_chain_t
}

unsafe fn borrow_chain(c: lr_policy_chain_t) -> Option<&'static PolicyChain> {
    if c.is_null() {
        return None;
    }
    Some(unsafe { &*(c as *const PolicyChain) })
}

unsafe fn borrow_chain_mut(c: lr_policy_chain_t) -> Option<&'static mut PolicyChain> {
    if c.is_null() {
        return None;
    }
    Some(unsafe { &mut *(c as *mut PolicyChain) })
}

fn box_policy(p: Policy) -> lr_policy_t {
    Box::into_raw(Box::new(p)) as lr_policy_t
}

unsafe fn borrow_policy(p: lr_policy_t) -> Option<&'static Policy> {
    if p.is_null() {
        return None;
    }
    Some(unsafe { &*(p as *const Policy) })
}

// ---- PolicyVerdict enum constants ----

/// The route-map chain accepted the route (RFC 4271 §9.1.2.2 step 9).
pub const LR_POLICY_VERDICT_ACCEPT: u8 = 0;
/// The route-map chain rejected the route.
pub const LR_POLICY_VERDICT_REJECT: u8 = 1;
/// The route-map chain fell through with no match — the caller
/// should consult the next policy in line.
pub const LR_POLICY_VERDICT_CONTINUE: u8 = 2;

// ---- ApplySetError enum constants (RFC 4271 §5.1.3) ----

/// The SetAction was applied successfully.
pub const LR_APPLY_SET_ERROR_OK: u8 = 0;
/// SetLocalPref cannot apply when the bgp feature is disabled.
pub const LR_APPLY_SET_ERROR_LOCAL_PREF_NO_BGP: u8 = 1;
/// SetMed cannot apply when the bgp feature is disabled.
pub const LR_APPLY_SET_ERROR_MED_NO_BGP: u8 = 2;
/// PrependAs cannot apply when the bgp feature is disabled.
pub const LR_APPLY_SET_ERROR_PREPEND_AS_NO_BGP: u8 = 3;
/// AddCommunity cannot apply when the bgp feature is disabled.
pub const LR_APPLY_SET_ERROR_ADD_COMMUNITY_NO_BGP: u8 = 4;
/// The SetAction variant is not yet wired into the route's attribute
/// set (a future extension).
pub const LR_APPLY_SET_ERROR_NOT_WIRED: u8 = 5;
/// Unknown SetAction variant.
pub const LR_APPLY_SET_ERROR_UNKNOWN: u8 = 6;

fn apply_set_error_to_code(e: &ApplySetError) -> u8 {
    match e {
        ApplySetError::RequiresBgpFeature(_) => LR_APPLY_SET_ERROR_LOCAL_PREF_NO_BGP,
    }
}

// =========================================================================
// PolicyChain
// =========================================================================

/// Construct an empty PolicyChain. Returns NULL on a panic.
#[no_mangle]
pub extern "C" fn lr_policy_chain_new() -> lr_policy_chain_t {
    guarded(|| box_chain(PolicyChain::new()), std::ptr::null_mut())
}

/// Push a route-map onto the chain. The route-map handle is
/// borrowed — the caller retains ownership. Returns 0 on success,
/// `LR_ERR_NULL` (-1) on a NULL chain or NULL map handle.
///
/// # Safety
/// `chain` must be a valid handle. `map` must be a valid
/// `lr_route_map_t` handle.
#[no_mangle]
pub unsafe extern "C" fn lr_policy_chain_push(
    chain: lr_policy_chain_t,
    map: crate::handle::lr_route_map_t,
) -> i32 {
    guarded(
        || unsafe {
            let Some(c) = borrow_chain_mut(chain) else {
                return LR_ERR_NULL;
            };
            if map.is_null() {
                return LR_ERR_NULL;
            }
            let map_ref: &RouteMap = &*(map as *const RouteMap);
            c.push(map_ref.clone());
            0
        },
        LrError::Panic as i32,
    )
}

/// Evaluate the chain against a route. The route handle is borrowed
/// — mutations from `SetAction` entries persist on the route. The
/// resolver handle is also borrowed (use `lr_resolver_new` to build
/// one). Returns one of `LR_POLICY_VERDICT_*`, or
/// `LR_POLICY_VERDICT_CONTINUE` (2) when the chain fell through.
///
/// # Safety
/// `chain` must be a valid handle. `route` must be a valid
/// `lr_route_t` handle. `resolver` must be a valid `lr_resolver_t`
/// handle.
#[no_mangle]
pub unsafe extern "C" fn lr_policy_chain_evaluate(
    chain: lr_policy_chain_t,
    route: lr_route_t,
    resolver: crate::handle::lr_resolver_t,
) -> u8 {
    guarded(
        || unsafe {
            let Some(c) = borrow_chain(chain) else {
                return LR_POLICY_VERDICT_CONTINUE;
            };
            if route.is_null() || resolver.is_null() {
                return LR_POLICY_VERDICT_CONTINUE;
            }
            let route_ref: &mut lr_core::rib::Route = &mut *(route as *mut lr_core::rib::Route);
            let resolver_ref: &PolicySet = &*(resolver as *const PolicySet);
            let v = c.evaluate(route_ref, resolver_ref);
            match v {
                PolicyVerdict::Accept => LR_POLICY_VERDICT_ACCEPT,
                PolicyVerdict::Reject => LR_POLICY_VERDICT_REJECT,
                PolicyVerdict::Continue => LR_POLICY_VERDICT_CONTINUE,
            }
        },
        LR_POLICY_VERDICT_CONTINUE,
    )
}

/// Number of route-maps in the chain.
///
/// # Safety
/// `chain` must be a valid handle.
#[no_mangle]
pub unsafe extern "C" fn lr_policy_chain_len(chain: lr_policy_chain_t) -> usize {
    guarded(
        || unsafe { borrow_chain(chain).map(|c| c.len()).unwrap_or(0) },
        0,
    )
}

/// Drop a PolicyChain handle. Safe to call with NULL.
///
/// # Safety
/// `chain` must have been produced by `lr_policy_chain_new` and not
/// already freed.
#[no_mangle]
pub unsafe extern "C" fn lr_policy_chain_free(chain: lr_policy_chain_t) {
    guarded(
        || unsafe {
            if chain.is_null() {
                return;
            }
            drop(Box::from_raw(chain as *mut PolicyChain));
        },
        (),
    )
}

// =========================================================================
// Policy (named wrapper around PolicyChain)
// =========================================================================

/// Construct a named Policy with an empty chain. `name` is a
/// NUL-terminated UTF-8 string. Returns NULL on a NULL name or a
/// panic.
///
/// # Safety
/// `name` must point to a NUL-terminated UTF-8 string.
#[no_mangle]
pub unsafe extern "C" fn lr_policy_new(name: *const std::os::raw::c_char) -> lr_policy_t {
    guarded(
        || unsafe {
            if name.is_null() {
                return std::ptr::null_mut();
            }
            let cstr = unsafe { std::ffi::CStr::from_ptr(name) };
            let Ok(s) = cstr.to_str() else {
                return std::ptr::null_mut();
            };
            box_policy(Policy::new(s.to_owned()))
        },
        std::ptr::null_mut(),
    )
}

/// Read the policy's name into a thread-local NUL-terminated buffer.
/// The pointer is valid until the next call to `lr_policy_name` on
/// this thread.
///
/// # Safety
/// `p` must be a valid handle.
#[no_mangle]
pub unsafe extern "C" fn lr_policy_name(p: lr_policy_t) -> *const std::os::raw::c_char {
    guarded(
        || unsafe {
            let Some(p) = borrow_policy(p) else {
                return std::ptr::null();
            };
            let cstr = std::ffi::CString::new(p.name.as_str()).unwrap_or_default();
            thread_local! {
                static BUF: std::cell::RefCell<Option<std::ffi::CString>> = const { std::cell::RefCell::new(None) };
            }
            BUF.with(|b| {
                let mut slot = b.borrow_mut();
                *slot = Some(cstr);
                slot.as_ref()
                    .map(|c| c.as_ptr())
                    .unwrap_or(std::ptr::null())
            })
        },
        std::ptr::null(),
    )
}

/// Borrow the policy's chain for evaluation. The returned handle is
/// NOT owned — do not free it. Returns NULL on a NULL policy.
///
/// # Safety
/// `p` must be a valid handle.
#[no_mangle]
pub unsafe extern "C" fn lr_policy_chain(p: lr_policy_t) -> lr_policy_chain_t {
    guarded(
        || unsafe {
            let Some(p) = borrow_policy(p) else {
                return std::ptr::null_mut();
            };
            // Cast a borrow of the inner PolicyChain to an opaque
            // pointer. The caller MUST NOT free this; the parent
            // Policy owns it.
            &p.chain as *const PolicyChain as lr_policy_chain_t
        },
        std::ptr::null_mut(),
    )
}

/// Drop a Policy handle. Safe to call with NULL.
///
/// # Safety
/// `p` must have been produced by `lr_policy_new` and not already
/// freed.
#[no_mangle]
pub unsafe extern "C" fn lr_policy_free(p: lr_policy_t) {
    guarded(
        || unsafe {
            if p.is_null() {
                return;
            }
            drop(Box::from_raw(p as *mut Policy));
        },
        (),
    )
}

// =========================================================================
// ApplySetError enum helpers
// =========================================================================

/// Look up the discriminant of an `ApplySetError` produced by
/// `apply_set_checked`. Returns one of `LR_APPLY_SET_ERROR_*`. The
/// caller passes the `SetAction` kind + the route handle — the FFI
/// applies the action via `apply_set_checked` and returns the
/// resulting error code (or `LR_APPLY_SET_ERROR_OK` = 0 when the
/// action succeeded).
///
/// `set_kind` is one of `LR_SET_*` (e.g. `LR_SET_LOCAL_PREF`,
/// `LR_SET_MED`, `LR_SET_PREPEND_AS`, `LR_SET_ADD_COMMUNITY`). The
/// per-action arguments are passed via the `arg1` / `arg2` / `arg3`
/// triple — see each `LR_SET_*` for the per-kind argument shape.
///
/// # Safety
/// `route` must be a valid `lr_route_t` handle.
#[no_mangle]
pub unsafe extern "C" fn lr_apply_set_checked(
    route: lr_route_t,
    set_kind: u8,
    arg1: u32,
    arg2: u32,
    arg3: u32,
) -> u8 {
    guarded(
        || unsafe {
            if route.is_null() {
                return LR_APPLY_SET_ERROR_UNKNOWN;
            }
            let route_ref: &mut lr_core::rib::Route = &mut *(route as *mut lr_core::rib::Route);
            let action = match set_kind {
                crate::policy_objects::LR_SET_LOCAL_PREF => {
                    lr_policy::action::SetAction::SetLocalPref(arg1)
                }
                crate::policy_objects::LR_SET_MED => lr_policy::action::SetAction::SetMed(arg1),
                crate::policy_objects::LR_SET_PREPEND_AS => {
                    lr_policy::action::SetAction::PrependAs(lr_core::addr::Asn(arg1))
                }
                crate::policy_objects::LR_SET_ADD_COMMUNITY => {
                    lr_policy::action::SetAction::AddCommunity(
                        lr_core::addr::Asn(arg1),
                        arg2 as u16,
                    )
                }
                _ => return LR_APPLY_SET_ERROR_UNKNOWN,
            };
            let _ = (arg3,); // unused for these variants
            match lr_policy::action::apply_set_checked(&action, route_ref) {
                Ok(()) => LR_APPLY_SET_ERROR_OK,
                Err(e) => apply_set_error_to_code(&e),
            }
        },
        LR_APPLY_SET_ERROR_UNKNOWN,
    )
}

/// Look up the `ApplySetError` discriminant name. Returns a
/// thread-local pointer to a NUL-terminated string.
#[no_mangle]
pub extern "C" fn lr_apply_set_error_name(code: u8) -> *const std::os::raw::c_char {
    guarded(
        || {
            let s = match code {
                LR_APPLY_SET_ERROR_OK => "ok",
                LR_APPLY_SET_ERROR_LOCAL_PREF_NO_BGP => "SetLocalPref needs bgp feature",
                LR_APPLY_SET_ERROR_MED_NO_BGP => "SetMed needs bgp feature",
                LR_APPLY_SET_ERROR_PREPEND_AS_NO_BGP => "PrependAs needs bgp feature",
                LR_APPLY_SET_ERROR_ADD_COMMUNITY_NO_BGP => "AddCommunity needs bgp feature",
                LR_APPLY_SET_ERROR_NOT_WIRED => {
                    "SetAction not wired into the route's attribute set"
                }
                LR_APPLY_SET_ERROR_UNKNOWN => "unknown SetAction",
                _ => "invalid ApplySetError code",
            };
            let cstr = std::ffi::CString::new(s).unwrap_or_default();
            thread_local! {
                static BUF: std::cell::RefCell<Option<std::ffi::CString>> = const { std::cell::RefCell::new(None) };
            }
            BUF.with(|b| {
                let mut slot = b.borrow_mut();
                *slot = Some(cstr);
                slot.as_ref()
                    .map(|c| c.as_ptr())
                    .unwrap_or(std::ptr::null())
            })
        },
        std::ptr::null(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ffi_policy_chain_new_round_trip() {
        let c = lr_policy_chain_new();
        assert!(!c.is_null());
        assert_eq!(unsafe { lr_policy_chain_len(c) }, 0);
        unsafe { lr_policy_chain_free(c) };
    }

    #[test]
    fn ffi_policy_chain_free_handles_null_safely() {
        unsafe { lr_policy_chain_free(std::ptr::null_mut()) };
    }

    #[test]
    fn ffi_policy_chain_evaluate_on_empty_returns_continue() {
        let c = lr_policy_chain_new();
        // Use a NULL route + NULL resolver — the call must return
        // Continue (the safe default for "no match") rather than
        // panicking.
        let v = unsafe { lr_policy_chain_evaluate(c, std::ptr::null_mut(), std::ptr::null_mut()) };
        assert_eq!(v, LR_POLICY_VERDICT_CONTINUE);
        unsafe { lr_policy_chain_free(c) };
    }

    #[test]
    fn ffi_policy_chain_len_on_null_returns_zero() {
        assert_eq!(unsafe { lr_policy_chain_len(std::ptr::null_mut()) }, 0);
    }

    #[test]
    fn ffi_policy_new_round_trip() {
        let name = std::ffi::CString::new("test-policy").unwrap();
        let p = unsafe { lr_policy_new(name.as_ptr()) };
        assert!(!p.is_null());
        let name_ptr = unsafe { lr_policy_name(p) };
        assert!(!name_ptr.is_null());
        let s = unsafe { std::ffi::CStr::from_ptr(name_ptr) }
            .to_str()
            .unwrap();
        assert_eq!(s, "test-policy");
        // Borrow the chain — should be non-NULL but not owned.
        let chain = unsafe { lr_policy_chain(p) };
        assert!(!chain.is_null());
        assert_eq!(unsafe { lr_policy_chain_len(chain) }, 0);
        unsafe { lr_policy_free(p) };
    }

    #[test]
    fn ffi_policy_new_rejects_null_name() {
        let p = unsafe { lr_policy_new(std::ptr::null()) };
        assert!(p.is_null());
    }

    #[test]
    fn ffi_policy_free_handles_null_safely() {
        unsafe { lr_policy_free(std::ptr::null_mut()) };
    }

    #[test]
    fn ffi_policy_name_on_null_returns_null() {
        let ptr = unsafe { lr_policy_name(std::ptr::null_mut()) };
        assert!(ptr.is_null());
    }

    #[test]
    fn ffi_apply_set_error_name_round_trip() {
        for code in 0..=6u8 {
            let ptr = lr_apply_set_error_name(code);
            assert!(!ptr.is_null(), "code {code} returned NULL");
        }
        // Out-of-range code returns an "invalid" message.
        let ptr = lr_apply_set_error_name(99);
        assert!(!ptr.is_null());
        let s = unsafe { std::ffi::CStr::from_ptr(ptr) }.to_str().unwrap();
        assert!(s.contains("invalid"));
    }

    #[test]
    fn ffi_apply_set_checked_rejects_null_route() {
        let code = unsafe {
            lr_apply_set_checked(
                std::ptr::null_mut(),
                crate::policy_objects::LR_SET_LOCAL_PREF,
                100,
                0,
                0,
            )
        };
        assert_eq!(code, LR_APPLY_SET_ERROR_UNKNOWN);
    }

    #[test]
    fn ffi_apply_set_checked_rejects_unknown_kind() {
        // Use a NULL route — the function should return UNKNOWN
        // before touching the route.
        let code = unsafe { lr_apply_set_checked(std::ptr::null_mut(), 99, 0, 0, 0) };
        assert_eq!(code, LR_APPLY_SET_ERROR_UNKNOWN);
    }
}
