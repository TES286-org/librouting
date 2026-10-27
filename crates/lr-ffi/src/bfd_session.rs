//! BFD Session FSM C ABI (RFC 5880 §6). Exposes
//! lr_bfd::session::{BfdSession, BfdConfig, BfdSessionEvent,
//! SessionRole}.

#![allow(unused_unsafe)]
#![allow(dead_code)]
#![allow(unused_imports)]

use lr_bfd::packet::{Diagnostic, State};
use lr_bfd::session::{BfdConfig, BfdSession, BfdSessionEvent, SessionRole};
use lr_core::time::Instant;

use crate::bfd::{
    LR_BFD_DIAG_ADMIN_DOWN, LR_BFD_DIAG_CTRL_EXPIRED, LR_BFD_DIAG_ECHO_FAILED,
    LR_BFD_DIAG_FWD_RESET, LR_BFD_DIAG_MISCONN_DEFECT, LR_BFD_DIAG_NEIGHBOR_SIGNALLED,
    LR_BFD_DIAG_NONE, LR_BFD_DIAG_PATH_DOWN, LR_BFD_DIAG_REV_PATH_DOWN, LR_BFD_STATE_ADMIN_DOWN,
    LR_BFD_STATE_DOWN, LR_BFD_STATE_INIT, LR_BFD_STATE_UP,
};
use crate::error::{LrError, LR_ERR_PANIC};
use crate::guarded;
use crate::handle::lr_bytes_t;

const LR_ERR_NULL: i32 = LrError::Null as i32;
const LR_ERR_INVALID_HANDLE: i32 = LrError::InvalidHandle as i32;

pub const LR_BFD_ROLE_ACTIVE: u8 = 0;
pub const LR_BFD_ROLE_PASSIVE: u8 = 1;

pub const LR_BFD_EVENT_STATE_CHANGED: u8 = 1;
pub const LR_BFD_EVENT_PEER_DIAGNOSTIC: u8 = 2;
pub const LR_BFD_EVENT_TIMEOUT: u8 = 3;
pub const LR_BFD_EVENT_AUTH_FAILED: u8 = 4;
pub const LR_BFD_EVENT_OUTBOUND_QUEUED: u8 = 5;

fn role_from_u8(v: u8) -> SessionRole {
    match v {
        LR_BFD_ROLE_PASSIVE => SessionRole::Passive,
        _ => SessionRole::Active,
    }
}

fn role_to_u8(r: SessionRole) -> u8 {
    match r {
        SessionRole::Active => LR_BFD_ROLE_ACTIVE,
        SessionRole::Passive => LR_BFD_ROLE_PASSIVE,
    }
}

fn state_to_u8(s: State) -> u8 {
    match s {
        State::AdminDown => LR_BFD_STATE_ADMIN_DOWN,
        State::Down => LR_BFD_STATE_DOWN,
        State::Init => LR_BFD_STATE_INIT,
        State::Up => LR_BFD_STATE_UP,
    }
}

fn diag_to_u8(d: Diagnostic) -> u8 {
    match d {
        Diagnostic::None => LR_BFD_DIAG_NONE,
        Diagnostic::CtrlExpired => LR_BFD_DIAG_CTRL_EXPIRED,
        Diagnostic::EchoFailed => LR_BFD_DIAG_ECHO_FAILED,
        Diagnostic::NeighborSignaled => LR_BFD_DIAG_NEIGHBOR_SIGNALLED,
        Diagnostic::FwdReset => LR_BFD_DIAG_FWD_RESET,
        Diagnostic::PathDown => LR_BFD_DIAG_PATH_DOWN,
        Diagnostic::ConcatPathDown => 6,
        Diagnostic::AdminDown => LR_BFD_DIAG_ADMIN_DOWN,
        Diagnostic::RevPathDown => LR_BFD_DIAG_REV_PATH_DOWN,
        Diagnostic::MisConnDefect => LR_BFD_DIAG_MISCONN_DEFECT,
        Diagnostic::Unknown(v) => v,
    }
}

// ---- Opaque handles ----

#[repr(C)]
pub struct OpaqueBfdSession {
    _private: [u8; 0],
}
pub type lr_bfd_session_t = *mut OpaqueBfdSession;

#[repr(C)]
pub struct OpaqueBfdConfig {
    _private: [u8; 0],
}
pub type lr_bfd_config_t = *mut OpaqueBfdConfig;

#[repr(C)]
pub struct OpaqueBfdSessionEvent {
    _private: [u8; 0],
}
pub type lr_bfd_session_event_t = *mut OpaqueBfdSessionEvent;

fn box_session(s: BfdSession) -> lr_bfd_session_t {
    Box::into_raw(Box::new(s)) as lr_bfd_session_t
}

unsafe fn unbox_session(s: lr_bfd_session_t) -> Option<Box<BfdSession>> {
    if s.is_null() {
        return None;
    }
    Some(unsafe { Box::from_raw(s as *mut BfdSession) })
}

unsafe fn borrow_session(s: lr_bfd_session_t) -> Option<&'static BfdSession> {
    if s.is_null() {
        return None;
    }
    Some(unsafe { &*(s as *const BfdSession) })
}

unsafe fn borrow_session_mut(s: lr_bfd_session_t) -> Option<&'static mut BfdSession> {
    if s.is_null() {
        return None;
    }
    Some(unsafe { &mut *(s as *mut BfdSession) })
}

fn box_config(c: BfdConfig) -> lr_bfd_config_t {
    Box::into_raw(Box::new(c)) as lr_bfd_config_t
}

unsafe fn unbox_config(c: lr_bfd_config_t) -> Option<Box<BfdConfig>> {
    if c.is_null() {
        return None;
    }
    Some(unsafe { Box::from_raw(c as *mut BfdConfig) })
}

unsafe fn borrow_config(c: lr_bfd_config_t) -> Option<&'static BfdConfig> {
    if c.is_null() {
        return None;
    }
    Some(unsafe { &*(c as *const BfdConfig) })
}

fn box_event(e: BfdSessionEvent) -> lr_bfd_session_event_t {
    Box::into_raw(Box::new(e)) as lr_bfd_session_event_t
}

unsafe fn unbox_event(e: lr_bfd_session_event_t) -> Option<Box<BfdSessionEvent>> {
    if e.is_null() {
        return None;
    }
    Some(unsafe { Box::from_raw(e as *mut BfdSessionEvent) })
}

unsafe fn borrow_event(e: lr_bfd_session_event_t) -> Option<&'static BfdSessionEvent> {
    if e.is_null() {
        return None;
    }
    Some(unsafe { &*(e as *const BfdSessionEvent) })
}

// ---- BfdConfig ----

#[no_mangle]
pub extern "C" fn lr_bfd_config_new(
    detect_mult: u8,
    desired_min_tx_interval_us: u32,
    required_min_rx_interval_us: u32,
    required_min_echo_interval_us: u32,
    role: u8,
) -> lr_bfd_config_t {
    guarded(
        || {
            let cfg = BfdConfig {
                detect_mult: detect_mult.max(1),
                desired_min_tx_interval: desired_min_tx_interval_us,
                required_min_rx_interval: required_min_rx_interval_us,
                required_min_echo_interval: required_min_echo_interval_us,
                role: role_from_u8(role),
                auth_key: None,
            };
            box_config(cfg)
        },
        std::ptr::null_mut(),
    )
}

#[no_mangle]
pub unsafe extern "C" fn lr_bfd_config_free(c: lr_bfd_config_t) {
    guarded(
        || unsafe {
            drop(unbox_config(c));
        },
        (),
    )
}

#[no_mangle]
pub unsafe extern "C" fn lr_bfd_config_detect_mult(c: lr_bfd_config_t) -> u8 {
    guarded(
        || unsafe { borrow_config(c).map(|c| c.detect_mult).unwrap_or(0) },
        0,
    )
}

#[no_mangle]
pub unsafe extern "C" fn lr_bfd_config_role(c: lr_bfd_config_t) -> u8 {
    guarded(
        || unsafe {
            borrow_config(c)
                .map(|c| role_to_u8(c.role))
                .unwrap_or(LR_BFD_ROLE_ACTIVE)
        },
        LR_BFD_ROLE_ACTIVE,
    )
}

// ---- BfdSession ----

#[no_mangle]
pub unsafe extern "C" fn lr_bfd_session_new(
    cfg: lr_bfd_config_t,
    my_disc: u32,
) -> lr_bfd_session_t {
    guarded(
        || unsafe {
            let Some(c) = borrow_config(cfg) else {
                return std::ptr::null_mut();
            };
            box_session(BfdSession::new(c.clone(), my_disc))
        },
        std::ptr::null_mut(),
    )
}

#[no_mangle]
pub unsafe extern "C" fn lr_bfd_session_free(s: lr_bfd_session_t) {
    guarded(
        || unsafe {
            drop(unbox_session(s));
        },
        (),
    )
}

#[no_mangle]
pub unsafe extern "C" fn lr_bfd_session_state(s: lr_bfd_session_t) -> u8 {
    guarded(
        || unsafe {
            borrow_session(s)
                .map(|s| state_to_u8(s.state()))
                .unwrap_or(LR_BFD_STATE_DOWN)
        },
        LR_BFD_STATE_DOWN,
    )
}

#[no_mangle]
pub unsafe extern "C" fn lr_bfd_session_is_up(s: lr_bfd_session_t) -> u8 {
    guarded(
        || unsafe { borrow_session(s).map(|s| s.is_up() as u8).unwrap_or(0) },
        0,
    )
}

#[no_mangle]
pub unsafe extern "C" fn lr_bfd_session_my_discriminator(s: lr_bfd_session_t) -> u32 {
    guarded(
        || unsafe { borrow_session(s).map(|s| s.my_discriminator()).unwrap_or(0) },
        0,
    )
}

#[no_mangle]
pub unsafe extern "C" fn lr_bfd_session_remote_discriminator(s: lr_bfd_session_t) -> u32 {
    guarded(
        || unsafe {
            borrow_session(s)
                .map(|s| s.remote_discriminator())
                .unwrap_or(0)
        },
        0,
    )
}

#[no_mangle]
pub unsafe extern "C" fn lr_bfd_session_local_diag(s: lr_bfd_session_t) -> u8 {
    guarded(
        || unsafe {
            borrow_session(s)
                .map(|s| diag_to_u8(s.local_diag()))
                .unwrap_or(LR_BFD_DIAG_NONE)
        },
        LR_BFD_DIAG_NONE,
    )
}

#[no_mangle]
pub unsafe extern "C" fn lr_bfd_session_remote_state(s: lr_bfd_session_t) -> u8 {
    guarded(
        || unsafe {
            borrow_session(s)
                .map(|s| state_to_u8(s.remote_state()))
                .unwrap_or(LR_BFD_STATE_DOWN)
        },
        LR_BFD_STATE_DOWN,
    )
}

#[no_mangle]
pub unsafe extern "C" fn lr_bfd_session_tx_interval_us(s: lr_bfd_session_t) -> u32 {
    guarded(
        || unsafe { borrow_session(s).map(|s| s.tx_interval_us()).unwrap_or(0) },
        0,
    )
}

#[no_mangle]
pub unsafe extern "C" fn lr_bfd_session_detection_time_us(s: lr_bfd_session_t) -> u64 {
    guarded(
        || unsafe {
            borrow_session(s)
                .map(|s| s.detection_time_us())
                .unwrap_or(0)
        },
        0,
    )
}

#[no_mangle]
pub unsafe extern "C" fn lr_bfd_session_drain_outgoing(
    s: lr_bfd_session_t,
    out: *mut lr_bytes_t,
) -> i32 {
    guarded(
        || unsafe {
            let Some(sess) = borrow_session_mut(s) else {
                return LR_ERR_NULL;
            };
            if out.is_null() {
                return LR_ERR_NULL;
            }
            let bytes = sess.drain_outgoing();
            unsafe { *out = lr_bytes_t::from_vec(bytes) }
            0
        },
        LR_ERR_PANIC,
    )
}

unsafe fn write_event_array(
    events: Vec<BfdSessionEvent>,
    out_array: *mut *mut lr_bfd_session_event_t,
    out_count: *mut usize,
) -> i32 {
    let n = events.len();
    if n == 0 {
        unsafe {
            *out_array = std::ptr::null_mut();
            *out_count = 0;
        }
        return 0;
    }
    let boxed: Vec<lr_bfd_session_event_t> = events.into_iter().map(box_event).collect();
    let mut boxed = boxed.into_boxed_slice();
    let ptr = boxed.as_mut_ptr();
    std::mem::forget(boxed);
    unsafe {
        *out_array = ptr;
        *out_count = n;
    }
    0
}

#[no_mangle]
pub unsafe extern "C" fn lr_bfd_session_feed_bytes(
    s: lr_bfd_session_t,
    now_ms: u64,
    data: *const u8,
    len: usize,
    out_array: *mut *mut lr_bfd_session_event_t,
    out_count: *mut usize,
) -> i32 {
    guarded(
        || unsafe {
            let Some(sess) = borrow_session_mut(s) else {
                return LR_ERR_NULL;
            };
            if out_array.is_null() || out_count.is_null() {
                return LR_ERR_NULL;
            }
            let bytes = if data.is_null() || len == 0 {
                &[]
            } else {
                unsafe { std::slice::from_raw_parts(data, len) }
            };
            let events = sess.feed_bytes(Instant(now_ms), bytes);
            write_event_array(events, out_array, out_count)
        },
        LR_ERR_PANIC,
    )
}

#[no_mangle]
pub unsafe extern "C" fn lr_bfd_session_tick(
    s: lr_bfd_session_t,
    now_ms: u64,
    out_array: *mut *mut lr_bfd_session_event_t,
    out_count: *mut usize,
) -> i32 {
    guarded(
        || unsafe {
            let Some(sess) = borrow_session_mut(s) else {
                return LR_ERR_NULL;
            };
            if out_array.is_null() || out_count.is_null() {
                return LR_ERR_NULL;
            };
            let events = sess.tick(Instant(now_ms));
            write_event_array(events, out_array, out_count)
        },
        LR_ERR_PANIC,
    )
}

#[no_mangle]
pub unsafe extern "C" fn lr_bfd_session_start(
    s: lr_bfd_session_t,
    now_ms: u64,
    out_array: *mut *mut lr_bfd_session_event_t,
    out_count: *mut usize,
) -> i32 {
    guarded(
        || unsafe {
            let Some(sess) = borrow_session_mut(s) else {
                return LR_ERR_NULL;
            };
            if out_array.is_null() || out_count.is_null() {
                return LR_ERR_NULL;
            };
            let events = sess.start(Instant(now_ms));
            write_event_array(events, out_array, out_count)
        },
        LR_ERR_PANIC,
    )
}

#[no_mangle]
pub unsafe extern "C" fn lr_bfd_session_admin_down(
    s: lr_bfd_session_t,
    out_array: *mut *mut lr_bfd_session_event_t,
    out_count: *mut usize,
) -> i32 {
    guarded(
        || unsafe {
            let Some(sess) = borrow_session_mut(s) else {
                return LR_ERR_NULL;
            };
            if out_array.is_null() || out_count.is_null() {
                return LR_ERR_NULL;
            };
            let events = sess.admin_down();
            write_event_array(events, out_array, out_count)
        },
        LR_ERR_PANIC,
    )
}

#[no_mangle]
pub unsafe extern "C" fn lr_bfd_session_event_kind(e: lr_bfd_session_event_t) -> u8 {
    guarded(
        || unsafe {
            let Some(ev) = borrow_event(e) else {
                return 0;
            };
            match ev {
                BfdSessionEvent::StateChanged { .. } => LR_BFD_EVENT_STATE_CHANGED,
                BfdSessionEvent::PeerDiagnostic(_) => LR_BFD_EVENT_PEER_DIAGNOSTIC,
                BfdSessionEvent::Timeout => LR_BFD_EVENT_TIMEOUT,
                BfdSessionEvent::AuthFailed => LR_BFD_EVENT_AUTH_FAILED,
                BfdSessionEvent::OutboundQueued => LR_BFD_EVENT_OUTBOUND_QUEUED,
            }
        },
        0,
    )
}

#[no_mangle]
pub unsafe extern "C" fn lr_bfd_session_event_state_change_fields(
    e: lr_bfd_session_event_t,
    out_from: *mut u8,
    out_to: *mut u8,
    out_diag: *mut u8,
) -> i32 {
    guarded(
        || unsafe {
            let Some(ev) = borrow_event(e) else {
                return LR_ERR_NULL;
            };
            if out_from.is_null() || out_to.is_null() || out_diag.is_null() {
                return LR_ERR_NULL;
            }
            match ev {
                BfdSessionEvent::StateChanged { from, to, diag } => {
                    unsafe {
                        *out_from = state_to_u8(*from);
                        *out_to = state_to_u8(*to);
                        *out_diag = diag_to_u8(*diag);
                    }
                    0
                }
                _ => LR_ERR_INVALID_HANDLE,
            }
        },
        LR_ERR_PANIC,
    )
}

#[no_mangle]
pub unsafe extern "C" fn lr_bfd_session_event_free(e: lr_bfd_session_event_t) {
    guarded(
        || unsafe {
            drop(unbox_event(e));
        },
        (),
    )
}

#[no_mangle]
pub unsafe extern "C" fn lr_bfd_session_event_array_free(
    array: *mut lr_bfd_session_event_t,
    count: usize,
) {
    guarded(
        || unsafe {
            if array.is_null() || count == 0 {
                return;
            }
            let slice = unsafe { std::slice::from_raw_parts_mut(array, count) };
            for h in slice.iter_mut() {
                if !h.is_null() {
                    drop(unbox_event(*h));
                    *h = std::ptr::null_mut();
                }
            }
            let _ = unsafe { Vec::from_raw_parts(array, count, count) };
        },
        (),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ffi_bfd_config_new_and_readers() {
        let c = lr_bfd_config_new(3, 1_000_000, 1_000_000, 0, LR_BFD_ROLE_ACTIVE);
        assert_eq!(unsafe { lr_bfd_config_detect_mult(c) }, 3);
        assert_eq!(unsafe { lr_bfd_config_role(c) }, LR_BFD_ROLE_ACTIVE);
        unsafe { lr_bfd_config_free(c) };
    }

    #[test]
    fn ffi_bfd_config_clamps_detect_mult() {
        let c = lr_bfd_config_new(0, 1_000_000, 1_000_000, 0, LR_BFD_ROLE_ACTIVE);
        assert_eq!(unsafe { lr_bfd_config_detect_mult(c) }, 1);
        unsafe { lr_bfd_config_free(c) };
    }

    #[test]
    fn ffi_bfd_session_new_and_initial_state() {
        let cfg = lr_bfd_config_new(3, 1_000_000, 1_000_000, 0, LR_BFD_ROLE_ACTIVE);
        let s = unsafe { lr_bfd_session_new(cfg, 0xdead_beef) };
        assert!(!s.is_null());
        assert_eq!(unsafe { lr_bfd_session_state(s) }, LR_BFD_STATE_DOWN);
        assert_eq!(unsafe { lr_bfd_session_is_up(s) }, 0);
        assert_eq!(unsafe { lr_bfd_session_my_discriminator(s) }, 0xdead_beef);
        unsafe {
            lr_bfd_session_free(s);
            lr_bfd_config_free(cfg);
        };
    }

    #[test]
    fn ffi_bfd_session_new_on_null_config_returns_null() {
        let s = unsafe { lr_bfd_session_new(std::ptr::null_mut(), 1) };
        assert!(s.is_null());
    }

    #[test]
    fn ffi_bfd_session_start_queues_packet() {
        let cfg = lr_bfd_config_new(3, 1_000_000, 1_000_000, 0, LR_BFD_ROLE_ACTIVE);
        let s = unsafe { lr_bfd_session_new(cfg, 1) };
        let mut array: *mut lr_bfd_session_event_t = std::ptr::null_mut();
        let mut count: usize = 0;
        assert_eq!(
            unsafe { lr_bfd_session_start(s, 0, &raw mut array, &raw mut count) },
            0
        );
        unsafe { lr_bfd_session_event_array_free(array, count) };

        let mut out = lr_bytes_t {
            ptr: std::ptr::null_mut(),
            len: 0,
            cap: 0,
        };
        assert_eq!(unsafe { lr_bfd_session_drain_outgoing(s, &raw mut out) }, 0);
        assert!(out.len >= 24, "BFD control packet is at least 24 bytes");

        unsafe {
            crate::bytes::lr_bytes_free(&raw mut out);
            lr_bfd_session_free(s);
            lr_bfd_config_free(cfg);
        };
    }

    #[test]
    fn ffi_bfd_session_admin_down_emits_state_change() {
        let cfg = lr_bfd_config_new(3, 1_000_000, 1_000_000, 0, LR_BFD_ROLE_ACTIVE);
        let s = unsafe { lr_bfd_session_new(cfg, 1) };
        let mut array: *mut lr_bfd_session_event_t = std::ptr::null_mut();
        let mut count: usize = 0;
        unsafe {
            assert_eq!(
                lr_bfd_session_start(s, 0, &raw mut array, &raw mut count),
                0
            );
            lr_bfd_session_event_array_free(array, count);
        }
        let mut array2: *mut lr_bfd_session_event_t = std::ptr::null_mut();
        let mut count2: usize = 0;
        assert_eq!(
            unsafe { lr_bfd_session_admin_down(s, &raw mut array2, &raw mut count2) },
            0
        );
        assert!(count2 >= 1);
        let mut saw_admin_down = false;
        for i in 0..count2 {
            let e = unsafe { *array2.add(i) };
            if unsafe { lr_bfd_session_event_kind(e) } == LR_BFD_EVENT_STATE_CHANGED {
                let mut from = 0u8;
                let mut to = 0u8;
                let mut diag = 0u8;
                let rc = unsafe {
                    lr_bfd_session_event_state_change_fields(
                        e,
                        &raw mut from,
                        &raw mut to,
                        &raw mut diag,
                    )
                };
                if rc == 0 && to == LR_BFD_STATE_ADMIN_DOWN {
                    saw_admin_down = true;
                }
            }
        }
        assert!(saw_admin_down);
        assert_eq!(unsafe { lr_bfd_session_state(s) }, LR_BFD_STATE_ADMIN_DOWN);
        unsafe {
            lr_bfd_session_event_array_free(array2, count2);
            lr_bfd_session_free(s);
            lr_bfd_config_free(cfg);
        };
    }

    #[test]
    fn ffi_bfd_session_event_kind_on_null() {
        assert_eq!(
            unsafe { lr_bfd_session_event_kind(std::ptr::null_mut()) },
            0
        );
    }

    #[test]
    fn ffi_bfd_session_event_wrong_variant() {
        let e = box_event(BfdSessionEvent::Timeout);
        let mut from = 0u8;
        let mut to = 0u8;
        let mut diag = 0u8;
        assert_eq!(
            unsafe {
                lr_bfd_session_event_state_change_fields(
                    e,
                    &raw mut from,
                    &raw mut to,
                    &raw mut diag,
                )
            },
            LR_ERR_INVALID_HANDLE
        );
        unsafe { lr_bfd_session_event_free(e) };
    }

    #[test]
    fn ffi_bfd_session_free_handles_null_safely() {
        unsafe {
            lr_bfd_session_free(std::ptr::null_mut());
            lr_bfd_config_free(std::ptr::null_mut());
            lr_bfd_session_event_free(std::ptr::null_mut());
            lr_bfd_session_event_array_free(std::ptr::null_mut(), 0);
        }
    }
}
