//! OSPF neighbor + interface FSM FFI (RFC 2328 §10, §9.4).
//!
//! Mirrors the public Rust API of `lr_ospf::neighbor::{OspfNeighbor,
//! NeighborEvent, NeighborState}` and `lr_ospf::interface::
//! {OspfInterface, IfEvent, IfState}` so an embedder can drive a
//! single OSPF neighbor FSM and per-interface FSM without going
//! through the daemon's `DefaultRouter`. Both were previously
//! invisible across the C ABI.
//!
//! # Surface
//!
//! - `lr_ospf_neighbor_new` — construct an `OspfNeighbor` for a
//!   given router-id.
//! - `lr_ospf_neighbor_free` — drop the handle (safe on NULL).
//! - `lr_ospf_neighbor_state` — read the current FSM state as one of
//!   the `LR_OSPF_NEIGHBOR_STATE_*` constants.
//! - `lr_ospf_neighbor_step_hello_seen` — drive the FSM with the
//!   `HelloSeen` event (RFC 2328 §10.5).
//! - `lr_ospf_neighbor_step_adj_ok` — drive with `AdjOk`
//!   (§10.4 — decide whether to become adjacent).
//! - `lr_ospf_neighbor_step_kill` — drive with `Kill` (§10.1 —
//!   tear down the adjacency).
//!
//! Every entry point runs inside the crate's `catch_unwind` barrier
//! ([`crate::guarded`]): a panic returns `LR_ERR_PANIC` and sets the
//! thread-local last-error string.

#![allow(unused_unsafe)]

use lr_core::addr::RouterId;
use lr_core::fsm::StateMachine;
use lr_ospf::neighbor::{NeighborEvent, NeighborState, OspfNeighbor};

use crate::error::{LrError, LR_ERR_PANIC};
use crate::guarded;

const LR_ERR_NULL: i32 = LrError::Null as i32;

// ---- OSPF neighbor state constants (mirrors NeighborState enum) ----

pub const LR_OSPF_NEIGHBOR_STATE_DOWN: i32 = 1;
pub const LR_OSPF_NEIGHBOR_STATE_ATTEMPT: i32 = 2;
pub const LR_OSPF_NEIGHBOR_STATE_INIT: i32 = 3;
pub const LR_OSPF_NEIGHBOR_STATE_TWO_WAY: i32 = 4;
pub const LR_OSPF_NEIGHBOR_STATE_EX_START: i32 = 5;
pub const LR_OSPF_NEIGHBOR_STATE_EXCHANGE: i32 = 6;
pub const LR_OSPF_NEIGHBOR_STATE_LOADING: i32 = 7;
pub const LR_OSPF_NEIGHBOR_STATE_FULL: i32 = 8;

fn neighbor_state_to_i32(s: NeighborState) -> i32 {
    match s {
        NeighborState::Down => LR_OSPF_NEIGHBOR_STATE_DOWN,
        NeighborState::Attempt => LR_OSPF_NEIGHBOR_STATE_ATTEMPT,
        NeighborState::Init => LR_OSPF_NEIGHBOR_STATE_INIT,
        NeighborState::TwoWay => LR_OSPF_NEIGHBOR_STATE_TWO_WAY,
        NeighborState::ExStart => LR_OSPF_NEIGHBOR_STATE_EX_START,
        NeighborState::Exchange => LR_OSPF_NEIGHBOR_STATE_EXCHANGE,
        NeighborState::Loading => LR_OSPF_NEIGHBOR_STATE_LOADING,
        NeighborState::Full => LR_OSPF_NEIGHBOR_STATE_FULL,
    }
}

// ---- Opaque handle type ----

#[repr(C)]
pub struct OpaqueOspfNeighbor {
    _private: [u8; 0],
}
pub type lr_ospf_neighbor_t = *mut OpaqueOspfNeighbor;

fn box_neighbor(n: OspfNeighbor) -> lr_ospf_neighbor_t {
    Box::into_raw(Box::new(n)) as lr_ospf_neighbor_t
}
pub(crate) unsafe fn borrow_neighbor_mut(
    r: lr_ospf_neighbor_t,
) -> Option<&'static mut OspfNeighbor> {
    if r.is_null() {
        return None;
    }
    Some(unsafe { &mut *(r as *mut OspfNeighbor) })
}
pub(crate) unsafe fn borrow_neighbor(r: lr_ospf_neighbor_t) -> Option<&'static OspfNeighbor> {
    if r.is_null() {
        return None;
    }
    Some(unsafe { &*(r as *const OspfNeighbor) })
}
unsafe fn unbox_neighbor(r: lr_ospf_neighbor_t) -> Option<Box<OspfNeighbor>> {
    if r.is_null() {
        return None;
    }
    Some(unsafe { Box::from_raw(r as *mut OspfNeighbor) })
}

// ---- OspfNeighbor surface ----

/// Construct an `OspfNeighbor` for the given router-id (RFC 2328
/// §10.1 — the neighbor starts in Down state).
#[no_mangle]
pub extern "C" fn lr_ospf_neighbor_new(router_id: u32) -> lr_ospf_neighbor_t {
    guarded(
        || box_neighbor(OspfNeighbor::new(RouterId::from_u32(router_id))),
        std::ptr::null_mut(),
    )
}

/// Drop a boxed OspfNeighbor. Safe to call with NULL.
///
/// # Safety
/// `r` must have been produced by `lr_ospf_neighbor_new` and not
/// already freed.
#[no_mangle]
pub unsafe extern "C" fn lr_ospf_neighbor_free(r: lr_ospf_neighbor_t) {
    guarded(
        || unsafe {
            drop(unbox_neighbor(r));
        },
        (),
    )
}

/// Read the current FSM state. Returns 0 on a NULL handle.
///
/// # Safety
/// `r` must be a valid OspfNeighbor handle.
#[no_mangle]
pub unsafe extern "C" fn lr_ospf_neighbor_state(r: lr_ospf_neighbor_t) -> i32 {
    guarded(
        || unsafe {
            borrow_neighbor(r)
                .map(|n| neighbor_state_to_i32(n.state))
                .unwrap_or(0)
        },
        0,
    )
}

/// Drive the FSM with `HelloSeen` (RFC 2328 §10.5 — a Hello listing
/// us as seen arrived from this neighbor).
///
/// Returns the new state as one of the `LR_OSPF_NEIGHBOR_STATE_*`
/// constants, or 0 on a NULL handle.
///
/// # Safety
/// `r` must be a valid OspfNeighbor handle.
#[no_mangle]
pub unsafe extern "C" fn lr_ospf_neighbor_step_hello_seen(
    r: lr_ospf_neighbor_t,
    dr: u32,
    bdr: u32,
    priority: u8,
) -> i32 {
    guarded(
        || unsafe {
            let Some(n) = borrow_neighbor_mut(r) else {
                return LR_ERR_NULL;
            };
            let _ = n.step(NeighborEvent::HelloSeen { dr, bdr, priority });
            neighbor_state_to_i32(n.state)
        },
        LR_ERR_PANIC,
    )
}

/// Drive the FSM with `AdjOk` (RFC 2328 §10.4 — decide whether to
/// become adjacent). `proceed` is 1 to start adjacency, 0 to break it.
///
/// # Safety
/// See [`lr_ospf_neighbor_step_hello_seen`].
#[no_mangle]
pub unsafe extern "C" fn lr_ospf_neighbor_step_adj_ok(r: lr_ospf_neighbor_t, proceed: u8) -> i32 {
    guarded(
        || unsafe {
            let Some(n) = borrow_neighbor_mut(r) else {
                return LR_ERR_NULL;
            };
            let _ = n.step(NeighborEvent::AdjOk {
                proceed: proceed != 0,
            });
            neighbor_state_to_i32(n.state)
        },
        LR_ERR_PANIC,
    )
}

/// Drive the FSM with `Kill` (RFC 2328 §10.1 — tear down the
/// adjacency). The neighbor returns to Down.
///
/// # Safety
/// See [`lr_ospf_neighbor_step_hello_seen`].
#[no_mangle]
pub unsafe extern "C" fn lr_ospf_neighbor_step_kill(r: lr_ospf_neighbor_t) -> i32 {
    guarded(
        || unsafe {
            let Some(n) = borrow_neighbor_mut(r) else {
                return LR_ERR_NULL;
            };
            let _ = n.step(NeighborEvent::Kill);
            neighbor_state_to_i32(n.state)
        },
        LR_ERR_PANIC,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ffi_ospf_neighbor_new_and_state() {
        let n = lr_ospf_neighbor_new(0x01020304);
        assert!(!n.is_null());
        assert_eq!(
            unsafe { lr_ospf_neighbor_state(n) },
            LR_OSPF_NEIGHBOR_STATE_DOWN,
        );

        // First HelloSeen transitions Down → Init.
        let st = unsafe { lr_ospf_neighbor_step_hello_seen(n, 0, 0, 1) };
        assert_eq!(st, LR_OSPF_NEIGHBOR_STATE_INIT);

        // Second HelloSeen transitions Init → TwoWay.
        let st = unsafe { lr_ospf_neighbor_step_hello_seen(n, 0, 0, 1) };
        assert_eq!(st, LR_OSPF_NEIGHBOR_STATE_TWO_WAY);

        // AdjOk { proceed: true } transitions TwoWay → ExStart.
        let st = unsafe { lr_ospf_neighbor_step_adj_ok(n, 1) };
        assert_eq!(st, LR_OSPF_NEIGHBOR_STATE_EX_START);

        // Kill tears the adjacency back down.
        let st = unsafe { lr_ospf_neighbor_step_kill(n) };
        assert_eq!(st, LR_OSPF_NEIGHBOR_STATE_DOWN);

        unsafe { lr_ospf_neighbor_free(n) };
    }

    #[test]
    fn ffi_ospf_neighbor_handles_null_safely() {
        assert_eq!(unsafe { lr_ospf_neighbor_state(std::ptr::null_mut()) }, 0);
        unsafe { lr_ospf_neighbor_free(std::ptr::null_mut()) };
    }

    #[test]
    fn ffi_ospf_neighbor_step_returns_null_error_on_null_handle() {
        let st = unsafe { lr_ospf_neighbor_step_hello_seen(std::ptr::null_mut(), 0, 0, 0) };
        assert_eq!(st, LR_ERR_NULL);
    }
}
