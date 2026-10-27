//! OSPF Interface FSM + DR/BDR election C ABI (RFC 2328 §9).
//! Exposes lr_ospf::interface::{OspfInterface, IfState, IfEvent,
//! Elector, V3Elector, elect, elect_v3}.

#![allow(unused_unsafe)]
#![allow(dead_code)]
#![allow(unused_imports)]

use lr_core::fsm::{Action, StateMachine};
use lr_ospf::interface::{elect, elect_v3, Elector, IfEvent, IfState, OspfInterface, V3Elector};

use crate::error::{LrError, LR_ERR_PANIC};
use crate::guarded;

const LR_ERR_NULL: i32 = LrError::Null as i32;
const LR_ERR_INVALID_HANDLE: i32 = LrError::InvalidHandle as i32;

pub const LR_OSPF_IF_STATE_DOWN: u8 = 1;
pub const LR_OSPF_IF_STATE_LOOPBACK: u8 = 2;
pub const LR_OSPF_IF_STATE_WAITING: u8 = 3;
pub const LR_OSPF_IF_STATE_POINT_TO_POINT: u8 = 4;
pub const LR_OSPF_IF_STATE_DR_OTHER: u8 = 5;
pub const LR_OSPF_IF_STATE_BACKUP: u8 = 6;
pub const LR_OSPF_IF_STATE_DR: u8 = 7;

fn if_state_to_u8(s: IfState) -> u8 {
    s as u8
}

#[repr(C)]
pub struct OpaqueOspfInterface {
    _private: [u8; 0],
}
pub type lr_ospf_interface_t = *mut OpaqueOspfInterface;

#[repr(C)]
pub struct OpaqueOspfIfAction {
    _private: [u8; 0],
}
pub type lr_ospf_if_action_t = *mut OpaqueOspfIfAction;

fn box_iface(i: OspfInterface) -> lr_ospf_interface_t {
    Box::into_raw(Box::new(i)) as lr_ospf_interface_t
}

unsafe fn unbox_iface(i: lr_ospf_interface_t) -> Option<Box<OspfInterface>> {
    if i.is_null() {
        return None;
    }
    Some(unsafe { Box::from_raw(i as *mut OspfInterface) })
}

unsafe fn borrow_iface(i: lr_ospf_interface_t) -> Option<&'static OspfInterface> {
    if i.is_null() {
        return None;
    }
    Some(unsafe { &*(i as *const OspfInterface) })
}

unsafe fn borrow_iface_mut(i: lr_ospf_interface_t) -> Option<&'static mut OspfInterface> {
    if i.is_null() {
        return None;
    }
    Some(unsafe { &mut *(i as *mut OspfInterface) })
}

fn box_action(a: Action) -> lr_ospf_if_action_t {
    Box::into_raw(Box::new(a)) as lr_ospf_if_action_t
}

unsafe fn unbox_action(a: lr_ospf_if_action_t) -> Option<Box<Action>> {
    if a.is_null() {
        return None;
    }
    Some(unsafe { Box::from_raw(a as *mut Action) })
}

unsafe fn borrow_action(a: lr_ospf_if_action_t) -> Option<&'static Action> {
    if a.is_null() {
        return None;
    }
    Some(unsafe { &*(a as *const Action) })
}

pub const LR_OSPF_IF_ACTION_NONE: u8 = 0;
pub const LR_OSPF_IF_ACTION_PEER_STATE_CHANGE: u8 = 1;
pub const LR_OSPF_IF_ACTION_LOG: u8 = 2;
pub const LR_OSPF_IF_ACTION_OTHER: u8 = 3;

fn action_kind(a: &Action) -> u8 {
    match a {
        Action::None => LR_OSPF_IF_ACTION_NONE,
        Action::EmitEvent(ev) => match ev {
            lr_core::event::Event::PeerStateChange { .. } => LR_OSPF_IF_ACTION_PEER_STATE_CHANGE,
            lr_core::event::Event::Log(_) => LR_OSPF_IF_ACTION_LOG,
            _ => LR_OSPF_IF_ACTION_OTHER,
        },
        _ => LR_OSPF_IF_ACTION_OTHER,
    }
}

#[no_mangle]
pub extern "C" fn lr_ospf_interface_new(area_id: u32) -> lr_ospf_interface_t {
    guarded(
        || box_iface(OspfInterface::new(area_id)),
        std::ptr::null_mut(),
    )
}

#[no_mangle]
pub unsafe extern "C" fn lr_ospf_interface_free(i: lr_ospf_interface_t) {
    guarded(
        || unsafe {
            drop(unbox_iface(i));
        },
        (),
    )
}

#[no_mangle]
pub unsafe extern "C" fn lr_ospf_interface_state(i: lr_ospf_interface_t) -> u8 {
    guarded(
        || unsafe {
            borrow_iface(i)
                .map(|i| if_state_to_u8(i.state))
                .unwrap_or(LR_OSPF_IF_STATE_DOWN)
        },
        LR_OSPF_IF_STATE_DOWN,
    )
}

#[no_mangle]
pub unsafe extern "C" fn lr_ospf_interface_priority(i: lr_ospf_interface_t) -> u8 {
    guarded(
        || unsafe { borrow_iface(i).map(|i| i.priority).unwrap_or(0) },
        0,
    )
}

#[no_mangle]
pub unsafe extern "C" fn lr_ospf_interface_hello_interval(i: lr_ospf_interface_t) -> u16 {
    guarded(
        || unsafe { borrow_iface(i).map(|i| i.hello_interval).unwrap_or(0) },
        0,
    )
}

#[no_mangle]
pub unsafe extern "C" fn lr_ospf_interface_dead_interval(i: lr_ospf_interface_t) -> u32 {
    guarded(
        || unsafe { borrow_iface(i).map(|i| i.dead_interval).unwrap_or(0) },
        0,
    )
}

#[no_mangle]
pub unsafe extern "C" fn lr_ospf_interface_dr(i: lr_ospf_interface_t) -> u32 {
    guarded(|| unsafe { borrow_iface(i).map(|i| i.dr).unwrap_or(0) }, 0)
}

#[no_mangle]
pub unsafe extern "C" fn lr_ospf_interface_bdr(i: lr_ospf_interface_t) -> u32 {
    guarded(|| unsafe { borrow_iface(i).map(|i| i.bdr).unwrap_or(0) }, 0)
}

#[no_mangle]
pub unsafe extern "C" fn lr_ospf_interface_area_id(i: lr_ospf_interface_t) -> u32 {
    guarded(
        || unsafe { borrow_iface(i).map(|i| i.area_id).unwrap_or(0) },
        0,
    )
}

#[no_mangle]
pub unsafe extern "C" fn lr_ospf_interface_router_id(i: lr_ospf_interface_t) -> u32 {
    guarded(
        || unsafe { borrow_iface(i).map(|i| i.router_id).unwrap_or(0) },
        0,
    )
}

#[no_mangle]
pub unsafe extern "C" fn lr_ospf_interface_ip(i: lr_ospf_interface_t) -> u32 {
    guarded(|| unsafe { borrow_iface(i).map(|i| i.ip).unwrap_or(0) }, 0)
}

#[no_mangle]
pub unsafe extern "C" fn lr_ospf_interface_set_priority(
    i: lr_ospf_interface_t,
    priority: u8,
) -> i32 {
    guarded(
        || unsafe {
            let Some(iface) = borrow_iface_mut(i) else {
                return LR_ERR_NULL;
            };
            iface.priority = priority;
            0
        },
        LR_ERR_PANIC,
    )
}

#[no_mangle]
pub unsafe extern "C" fn lr_ospf_interface_set_hello_interval(
    i: lr_ospf_interface_t,
    hello_interval: u16,
) -> i32 {
    guarded(
        || unsafe {
            let Some(iface) = borrow_iface_mut(i) else {
                return LR_ERR_NULL;
            };
            iface.hello_interval = hello_interval;
            0
        },
        LR_ERR_PANIC,
    )
}

#[no_mangle]
pub unsafe extern "C" fn lr_ospf_interface_set_dead_interval(
    i: lr_ospf_interface_t,
    dead_interval: u32,
) -> i32 {
    guarded(
        || unsafe {
            let Some(iface) = borrow_iface_mut(i) else {
                return LR_ERR_NULL;
            };
            iface.dead_interval = dead_interval;
            0
        },
        LR_ERR_PANIC,
    )
}

#[no_mangle]
pub unsafe extern "C" fn lr_ospf_interface_set_router_id(
    i: lr_ospf_interface_t,
    router_id: u32,
) -> i32 {
    guarded(
        || unsafe {
            let Some(iface) = borrow_iface_mut(i) else {
                return LR_ERR_NULL;
            };
            iface.router_id = router_id;
            0
        },
        LR_ERR_PANIC,
    )
}

#[no_mangle]
pub unsafe extern "C" fn lr_ospf_interface_set_ip(i: lr_ospf_interface_t, ip: u32) -> i32 {
    guarded(
        || unsafe {
            let Some(iface) = borrow_iface_mut(i) else {
                return LR_ERR_NULL;
            };
            iface.ip = ip;
            0
        },
        LR_ERR_PANIC,
    )
}

unsafe fn write_actions(
    actions: Vec<Action>,
    out_array: *mut *mut lr_ospf_if_action_t,
    out_count: *mut usize,
) -> i32 {
    let n = actions.len();
    if n == 0 {
        unsafe {
            *out_array = std::ptr::null_mut();
            *out_count = 0;
        }
        return 0;
    }
    let boxed: Vec<lr_ospf_if_action_t> = actions.into_iter().map(box_action).collect();
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
pub unsafe extern "C" fn lr_ospf_interface_step_interface_up(
    i: lr_ospf_interface_t,
    out_array: *mut *mut lr_ospf_if_action_t,
    out_count: *mut usize,
) -> i32 {
    guarded(
        || unsafe {
            let Some(iface) = borrow_iface_mut(i) else {
                return LR_ERR_NULL;
            };
            if out_array.is_null() || out_count.is_null() {
                return LR_ERR_NULL;
            }
            let actions = iface.step(IfEvent::InterfaceUp);
            write_actions(actions, out_array, out_count)
        },
        LR_ERR_PANIC,
    )
}

#[no_mangle]
pub unsafe extern "C" fn lr_ospf_interface_step_interface_down(
    i: lr_ospf_interface_t,
    out_array: *mut *mut lr_ospf_if_action_t,
    out_count: *mut usize,
) -> i32 {
    guarded(
        || unsafe {
            let Some(iface) = borrow_iface_mut(i) else {
                return LR_ERR_NULL;
            };
            if out_array.is_null() || out_count.is_null() {
                return LR_ERR_NULL;
            }
            let actions = iface.step(IfEvent::InterfaceDown);
            write_actions(actions, out_array, out_count)
        },
        LR_ERR_PANIC,
    )
}

#[no_mangle]
pub unsafe extern "C" fn lr_ospf_interface_step_wait_timer(
    i: lr_ospf_interface_t,
    out_array: *mut *mut lr_ospf_if_action_t,
    out_count: *mut usize,
) -> i32 {
    guarded(
        || unsafe {
            let Some(iface) = borrow_iface_mut(i) else {
                return LR_ERR_NULL;
            };
            if out_array.is_null() || out_count.is_null() {
                return LR_ERR_NULL;
            }
            let actions = iface.step(IfEvent::WaitTimer);
            write_actions(actions, out_array, out_count)
        },
        LR_ERR_PANIC,
    )
}

#[no_mangle]
pub unsafe extern "C" fn lr_ospf_interface_step_backup_seen(
    i: lr_ospf_interface_t,
    out_array: *mut *mut lr_ospf_if_action_t,
    out_count: *mut usize,
) -> i32 {
    guarded(
        || unsafe {
            let Some(iface) = borrow_iface_mut(i) else {
                return LR_ERR_NULL;
            };
            if out_array.is_null() || out_count.is_null() {
                return LR_ERR_NULL;
            }
            let actions = iface.step(IfEvent::BackupSeen);
            write_actions(actions, out_array, out_count)
        },
        LR_ERR_PANIC,
    )
}

#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct lr_ospf_elector_t {
    pub router_id: u32,
    pub ip: u32,
    pub priority: u8,
    pub stated_dr: u32,
    pub stated_bdr: u32,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct lr_ospf_v3_elector_t {
    pub router_id: u32,
    pub priority: u8,
    pub stated_dr: u32,
    pub stated_bdr: u32,
}

#[no_mangle]
pub unsafe extern "C" fn lr_ospf_interface_step_neighbor_change(
    i: lr_ospf_interface_t,
    electors: *const lr_ospf_elector_t,
    count: usize,
    out_array: *mut *mut lr_ospf_if_action_t,
    out_count: *mut usize,
) -> i32 {
    guarded(
        || unsafe {
            let Some(iface) = borrow_iface_mut(i) else {
                return LR_ERR_NULL;
            };
            if out_array.is_null() || out_count.is_null() {
                return LR_ERR_NULL;
            }
            let electors_vec: Vec<Elector> = if count == 0 || electors.is_null() {
                Vec::new()
            } else {
                let slice = unsafe { std::slice::from_raw_parts(electors, count) };
                slice
                    .iter()
                    .map(|e| Elector {
                        router_id: e.router_id,
                        ip: e.ip,
                        priority: e.priority,
                        stated_dr: e.stated_dr,
                        stated_bdr: e.stated_bdr,
                    })
                    .collect()
            };
            let actions = iface.step(IfEvent::NeighborChange {
                elector: electors_vec,
            });
            write_actions(actions, out_array, out_count)
        },
        LR_ERR_PANIC,
    )
}

#[no_mangle]
pub unsafe extern "C" fn lr_ospf_interface_action_kind(a: lr_ospf_if_action_t) -> u8 {
    guarded(
        || unsafe { borrow_action(a).map(action_kind).unwrap_or(0) },
        0,
    )
}

#[no_mangle]
pub unsafe extern "C" fn lr_ospf_interface_action_peer_state_name(
    a: lr_ospf_if_action_t,
    out: *mut u8,
    cap: usize,
) -> i32 {
    guarded(
        || unsafe {
            let Some(action) = borrow_action(a) else {
                return LR_ERR_NULL;
            };
            if out.is_null() || cap == 0 {
                return LR_ERR_NULL;
            }
            match action {
                Action::EmitEvent(lr_core::event::Event::PeerStateChange {
                    peer_state, ..
                }) => {
                    let bytes = peer_state.as_bytes();
                    let n = bytes.len().min(cap - 1);
                    unsafe {
                        std::ptr::copy_nonoverlapping(bytes.as_ptr(), out, n);
                        *out.add(n) = 0;
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
pub unsafe extern "C" fn lr_ospf_interface_action_free(a: lr_ospf_if_action_t) {
    guarded(
        || unsafe {
            drop(unbox_action(a));
        },
        (),
    )
}

#[no_mangle]
pub unsafe extern "C" fn lr_ospf_interface_action_array_free(
    array: *mut lr_ospf_if_action_t,
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
                    drop(unbox_action(*h));
                    *h = std::ptr::null_mut();
                }
            }
            let _ = unsafe { Vec::from_raw_parts(array, count, count) };
        },
        (),
    )
}

#[no_mangle]
pub unsafe extern "C" fn lr_ospf_elect(
    electors: *const lr_ospf_elector_t,
    count: usize,
    self_router_id: u32,
    self_ip: u32,
    self_priority: u8,
    self_stated_dr: u32,
    self_stated_bdr: u32,
    out_dr: *mut u32,
    out_bdr: *mut u32,
) -> i32 {
    guarded(
        || unsafe {
            if out_dr.is_null() || out_bdr.is_null() {
                return LR_ERR_NULL;
            }
            let mut all: Vec<Elector> = if count == 0 || electors.is_null() {
                Vec::new()
            } else {
                let slice = unsafe { std::slice::from_raw_parts(electors, count) };
                slice
                    .iter()
                    .map(|e| Elector {
                        router_id: e.router_id,
                        ip: e.ip,
                        priority: e.priority,
                        stated_dr: e.stated_dr,
                        stated_bdr: e.stated_bdr,
                    })
                    .collect()
            };
            all.push(Elector {
                router_id: self_router_id,
                ip: self_ip,
                priority: self_priority,
                stated_dr: self_stated_dr,
                stated_bdr: self_stated_bdr,
            });
            let (dr, bdr) = elect(&all, self_ip);
            unsafe {
                *out_dr = dr;
                *out_bdr = bdr;
            }
            0
        },
        LR_ERR_PANIC,
    )
}

#[no_mangle]
pub unsafe extern "C" fn lr_ospf_elect_v3(
    electors: *const lr_ospf_v3_elector_t,
    count: usize,
    self_router_id: u32,
    self_priority: u8,
    self_stated_dr: u32,
    self_stated_bdr: u32,
    out_dr: *mut u32,
    out_bdr: *mut u32,
) -> i32 {
    guarded(
        || unsafe {
            if out_dr.is_null() || out_bdr.is_null() {
                return LR_ERR_NULL;
            }
            let mut all: Vec<V3Elector> = if count == 0 || electors.is_null() {
                Vec::new()
            } else {
                let slice = unsafe { std::slice::from_raw_parts(electors, count) };
                slice
                    .iter()
                    .map(|e| V3Elector {
                        router_id: e.router_id,
                        priority: e.priority,
                        stated_dr: e.stated_dr,
                        stated_bdr: e.stated_bdr,
                    })
                    .collect()
            };
            all.push(V3Elector {
                router_id: self_router_id,
                priority: self_priority,
                stated_dr: self_stated_dr,
                stated_bdr: self_stated_bdr,
            });
            let (dr, bdr) = elect_v3(&all, self_router_id);
            unsafe {
                *out_dr = dr;
                *out_bdr = bdr;
            }
            0
        },
        LR_ERR_PANIC,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ffi_iface_new_is_down() {
        let i = lr_ospf_interface_new(0);
        assert!(!i.is_null());
        assert_eq!(unsafe { lr_ospf_interface_state(i) }, LR_OSPF_IF_STATE_DOWN);
        assert_eq!(unsafe { lr_ospf_interface_priority(i) }, 1);
        assert_eq!(unsafe { lr_ospf_interface_hello_interval(i) }, 10);
        assert_eq!(unsafe { lr_ospf_interface_dead_interval(i) }, 40);
        unsafe { lr_ospf_interface_free(i) };
    }

    #[test]
    fn ffi_iface_setters_round_trip() {
        let i = lr_ospf_interface_new(0);
        unsafe {
            assert_eq!(lr_ospf_interface_set_priority(i, 200), 0);
            assert_eq!(lr_ospf_interface_set_hello_interval(i, 5), 0);
            assert_eq!(lr_ospf_interface_set_dead_interval(i, 20), 0);
            assert_eq!(lr_ospf_interface_set_router_id(i, 0x0a000001), 0);
            assert_eq!(lr_ospf_interface_set_ip(i, 0xc0a80101), 0);
        }
        assert_eq!(unsafe { lr_ospf_interface_priority(i) }, 200);
        assert_eq!(unsafe { lr_ospf_interface_hello_interval(i) }, 5);
        assert_eq!(unsafe { lr_ospf_interface_dead_interval(i) }, 20);
        assert_eq!(unsafe { lr_ospf_interface_router_id(i) }, 0x0a000001);
        assert_eq!(unsafe { lr_ospf_interface_ip(i) }, 0xc0a80101);
        unsafe { lr_ospf_interface_free(i) };
    }

    #[test]
    fn ffi_iface_step_interface_up_transitions_to_waiting() {
        let i = lr_ospf_interface_new(0);
        let mut array: *mut lr_ospf_if_action_t = std::ptr::null_mut();
        let mut count: usize = 0;
        assert_eq!(
            unsafe { lr_ospf_interface_step_interface_up(i, &raw mut array, &raw mut count) },
            0
        );
        assert!(count >= 1);
        let e = unsafe { *array.add(0) };
        assert_eq!(
            unsafe { lr_ospf_interface_action_kind(e) },
            LR_OSPF_IF_ACTION_PEER_STATE_CHANGE
        );
        let mut name = [0u8; 32];
        assert_eq!(
            unsafe { lr_ospf_interface_action_peer_state_name(e, name.as_mut_ptr(), name.len()) },
            0
        );
        let name_str = std::str::from_utf8(&name[..7]).unwrap_or("");
        assert_eq!(name_str, "Waiting");
        assert_eq!(
            unsafe { lr_ospf_interface_state(i) },
            LR_OSPF_IF_STATE_WAITING
        );
        unsafe {
            lr_ospf_interface_action_array_free(array, count);
            lr_ospf_interface_free(i);
        };
    }

    #[test]
    fn ffi_iface_step_wait_timer_transitions_to_drother() {
        let i = lr_ospf_interface_new(0);
        let mut array: *mut lr_ospf_if_action_t = std::ptr::null_mut();
        let mut count: usize = 0;
        unsafe {
            assert_eq!(
                lr_ospf_interface_step_interface_up(i, &raw mut array, &raw mut count),
                0
            );
            lr_ospf_interface_action_array_free(array, count);
        }
        let mut array2: *mut lr_ospf_if_action_t = std::ptr::null_mut();
        let mut count2: usize = 0;
        assert_eq!(
            unsafe { lr_ospf_interface_step_wait_timer(i, &raw mut array2, &raw mut count2) },
            0
        );
        assert_eq!(
            unsafe { lr_ospf_interface_state(i) },
            LR_OSPF_IF_STATE_DR_OTHER
        );
        unsafe {
            lr_ospf_interface_action_array_free(array2, count2);
            lr_ospf_interface_free(i);
        };
    }

    #[test]
    fn ffi_iface_step_neighbor_change_elects_self_as_dr() {
        let i = lr_ospf_interface_new(0);
        unsafe {
            assert_eq!(lr_ospf_interface_set_priority(i, 200), 0);
            assert_eq!(lr_ospf_interface_set_router_id(i, 0x0a000001), 0);
            assert_eq!(lr_ospf_interface_set_ip(i, 0xc0a80101), 0);
        }
        let neighbor = lr_ospf_elector_t {
            router_id: 0x0a000002,
            ip: 0xc0a80102,
            priority: 1,
            stated_dr: 0,
            stated_bdr: 0,
        };
        let electors = [neighbor];
        let mut array: *mut lr_ospf_if_action_t = std::ptr::null_mut();
        let mut count: usize = 0;
        assert_eq!(
            unsafe {
                lr_ospf_interface_step_neighbor_change(
                    i,
                    electors.as_ptr(),
                    electors.len(),
                    &raw mut array,
                    &raw mut count,
                )
            },
            0
        );
        assert_eq!(unsafe { lr_ospf_interface_dr(i) }, 0xc0a80101);
        assert_eq!(unsafe { lr_ospf_interface_bdr(i) }, 0xc0a80102);
        assert_eq!(unsafe { lr_ospf_interface_state(i) }, LR_OSPF_IF_STATE_DR);
        unsafe {
            lr_ospf_interface_action_array_free(array, count);
            lr_ospf_interface_free(i);
        };
    }

    #[test]
    fn ffi_elect_runs_standalone() {
        let electors = [
            lr_ospf_elector_t {
                router_id: 0x0a000002,
                ip: 0xc0a80102,
                priority: 100,
                stated_dr: 0,
                stated_bdr: 0,
            },
            lr_ospf_elector_t {
                router_id: 0x0a000003,
                ip: 0xc0a80103,
                priority: 1,
                stated_dr: 0,
                stated_bdr: 0,
            },
        ];
        let mut dr = 0u32;
        let mut bdr = 0u32;
        assert_eq!(
            unsafe {
                lr_ospf_elect(
                    electors.as_ptr(),
                    electors.len(),
                    0x0a000001,
                    0xc0a80101,
                    200,
                    0,
                    0,
                    &raw mut dr,
                    &raw mut bdr,
                )
            },
            0
        );
        assert_eq!(dr, 0xc0a80101);
        assert_eq!(bdr, 0xc0a80102);
    }

    #[test]
    fn ffi_elect_v3_runs_standalone() {
        let electors = [
            lr_ospf_v3_elector_t {
                router_id: 0x0a000002,
                priority: 100,
                stated_dr: 0,
                stated_bdr: 0,
            },
            lr_ospf_v3_elector_t {
                router_id: 0x0a000003,
                priority: 1,
                stated_dr: 0,
                stated_bdr: 0,
            },
        ];
        let mut dr = 0u32;
        let mut bdr = 0u32;
        assert_eq!(
            unsafe {
                lr_ospf_elect_v3(
                    electors.as_ptr(),
                    electors.len(),
                    0x0a000001,
                    200,
                    0,
                    0,
                    &raw mut dr,
                    &raw mut bdr,
                )
            },
            0
        );
        assert_eq!(dr, 0x0a000001);
        assert_eq!(bdr, 0x0a000002);
    }

    #[test]
    fn ffi_iface_step_on_null_returns_error() {
        let mut array: *mut lr_ospf_if_action_t = std::ptr::null_mut();
        let mut count: usize = 0;
        assert_eq!(
            unsafe {
                lr_ospf_interface_step_interface_up(
                    std::ptr::null_mut(),
                    &raw mut array,
                    &raw mut count,
                )
            },
            LR_ERR_NULL
        );
    }

    #[test]
    fn ffi_iface_free_null_safely() {
        unsafe {
            lr_ospf_interface_free(std::ptr::null_mut());
            lr_ospf_interface_action_free(std::ptr::null_mut());
            lr_ospf_interface_action_array_free(std::ptr::null_mut(), 0);
        }
    }
}
