//! OSPF Link State Retransmission List FFI (RFC 2328 §13.5/§13.6/§13.7).
//!
//! Mirrors `lr_ospf::retransmit::{LinkStateRetransmissionList,
//! RetransmitEntry}`. Every entry point runs inside catch_unwind.

#![allow(unused_unsafe)]
#![allow(dead_code)]
#![allow(unused_imports)]

use lr_ospf::lsa::{Lsa, LsaKey};
use lr_ospf::retransmit::LinkStateRetransmissionList;

use crate::error::{LrError, LR_ERR_PANIC};
use crate::guarded;
use crate::ospf_lsdb::lr_ospf_lsa_box_t;

const LR_ERR_NULL: i32 = LrError::Null as i32;
const LR_ERR_INVALID_HANDLE: i32 = LrError::InvalidHandle as i32;

#[repr(C)]
pub struct OpaqueOspfRetransmitList {
    _private: [u8; 0],
}
pub type lr_ospf_retransmit_t = *mut OpaqueOspfRetransmitList;

fn box_list(l: LinkStateRetransmissionList) -> lr_ospf_retransmit_t {
    Box::into_raw(Box::new(l)) as lr_ospf_retransmit_t
}

unsafe fn unbox_list(r: lr_ospf_retransmit_t) -> Option<Box<LinkStateRetransmissionList>> {
    if r.is_null() {
        return None;
    }
    Some(unsafe { Box::from_raw(r as *mut LinkStateRetransmissionList) })
}

unsafe fn borrow_list(r: lr_ospf_retransmit_t) -> Option<&'static LinkStateRetransmissionList> {
    if r.is_null() {
        return None;
    }
    Some(unsafe { &*(r as *const LinkStateRetransmissionList) })
}

unsafe fn borrow_list_mut(
    r: lr_ospf_retransmit_t,
) -> Option<&'static mut LinkStateRetransmissionList> {
    if r.is_null() {
        return None;
    }
    Some(unsafe { &mut *(r as *mut LinkStateRetransmissionList) })
}

fn box_lsa_local(l: Lsa) -> lr_ospf_lsa_box_t {
    Box::into_raw(Box::new(l)) as lr_ospf_lsa_box_t
}

unsafe fn unbox_lsa_local(l: lr_ospf_lsa_box_t) -> Option<Box<Lsa>> {
    if l.is_null() {
        return None;
    }
    Some(unsafe { Box::from_raw(l as *mut Lsa) })
}

#[no_mangle]
pub extern "C" fn lr_ospf_retransmit_new() -> lr_ospf_retransmit_t {
    guarded(
        || box_list(LinkStateRetransmissionList::new()),
        std::ptr::null_mut(),
    )
}

#[no_mangle]
pub unsafe extern "C" fn lr_ospf_retransmit_free(r: lr_ospf_retransmit_t) {
    guarded(
        || unsafe {
            drop(unbox_list(r));
        },
        (),
    )
}

#[no_mangle]
pub unsafe extern "C" fn lr_ospf_retransmit_len(r: lr_ospf_retransmit_t) -> usize {
    guarded(
        || unsafe { borrow_list(r).map(|l| l.len()).unwrap_or(0) },
        0,
    )
}

#[no_mangle]
pub unsafe extern "C" fn lr_ospf_retransmit_is_empty(r: lr_ospf_retransmit_t) -> u8 {
    guarded(
        || unsafe { borrow_list(r).map(|l| l.is_empty() as u8).unwrap_or(1) },
        1,
    )
}

#[no_mangle]
pub unsafe extern "C" fn lr_ospf_retransmit_contains(
    r: lr_ospf_retransmit_t,
    ls_type: u16,
    ls_id: u32,
    adv_router: u32,
) -> u8 {
    guarded(
        || unsafe {
            let key = LsaKey {
                ls_type,
                link_state_id: ls_id,
                advertising_router: adv_router,
            };
            borrow_list(r)
                .map(|l| l.contains(&key) as u8)
                .unwrap_or(0)
        },
        0,
    )
}

#[no_mangle]
pub unsafe extern "C" fn lr_ospf_retransmit_record_flood(
    r: lr_ospf_retransmit_t,
    lsa: lr_ospf_lsa_box_t,
    now_ms: u64,
) -> i32 {
    guarded(
        || unsafe {
            let Some(l) = borrow_list_mut(r) else {
                return LR_ERR_NULL;
            };
            let Some(boxed) = unbox_lsa_local(lsa) else {
                return LR_ERR_NULL;
            };
            l.record_flood(*boxed, now_ms);
            0
        },
        LR_ERR_PANIC,
    )
}

#[no_mangle]
pub unsafe extern "C" fn lr_ospf_retransmit_remove(
    r: lr_ospf_retransmit_t,
    ls_type: u16,
    ls_id: u32,
    adv_router: u32,
) -> u8 {
    guarded(
        || unsafe {
            let Some(l) = borrow_list_mut(r) else {
                return 0;
            };
            let key = LsaKey {
                ls_type,
                link_state_id: ls_id,
                advertising_router: adv_router,
            };
            l.remove(&key) as u8
        },
        0,
    )
}

#[no_mangle]
pub unsafe extern "C" fn lr_ospf_retransmit_clear(r: lr_ospf_retransmit_t) {
    guarded(
        || unsafe {
            if let Some(l) = borrow_list_mut(r) {
                l.clear();
            }
        },
        (),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use lr_ospf::lsa::LsaHeader;

    fn make_lsa(ls_type: u16, ls_id: u32, adv: u32) -> Lsa {
        Lsa {
            header: LsaHeader {
                ls_age: 1,
                options: 0,
                ls_type,
                link_state_id: ls_id,
                advertising_router: adv,
                ls_sequence_number: 1,
                ls_checksum: 0,
                length: 20,
            },
            body: Vec::new(),
        }
    }

    fn make_lsa_box(l: Lsa) -> lr_ospf_lsa_box_t {
        Box::into_raw(Box::new(l)) as lr_ospf_lsa_box_t
    }

    #[test]
    fn ffi_retransmit_new_is_empty() {
        let r = lr_ospf_retransmit_new();
        assert!(!r.is_null());
        assert_eq!(unsafe { lr_ospf_retransmit_len(r) }, 0);
        assert_eq!(unsafe { lr_ospf_retransmit_is_empty(r) }, 1);
        unsafe { lr_ospf_retransmit_free(r) };
    }

    #[test]
    fn ffi_retransmit_record_and_contains() {
        let r = lr_ospf_retransmit_new();
        let lsa = make_lsa_box(make_lsa(1, 0xa, 0xa));
        assert_eq!(unsafe { lr_ospf_retransmit_record_flood(r, lsa, 0) }, 0);
        assert_eq!(unsafe { lr_ospf_retransmit_len(r) }, 1);
        assert_eq!(unsafe { lr_ospf_retransmit_contains(r, 1, 0xa, 0xa) }, 1);
        assert_eq!(unsafe { lr_ospf_retransmit_contains(r, 1, 0xb, 0xa) }, 0);
        unsafe { lr_ospf_retransmit_free(r) };
    }

    #[test]
    fn ffi_retransmit_remove() {
        let r = lr_ospf_retransmit_new();
        let lsa = make_lsa_box(make_lsa(1, 0xa, 0xa));
        unsafe { assert_eq!(lr_ospf_retransmit_record_flood(r, lsa, 0), 0) };
        assert_eq!(unsafe { lr_ospf_retransmit_remove(r, 1, 0xa, 0xa) }, 1);
        assert_eq!(unsafe { lr_ospf_retransmit_len(r) }, 0);
        unsafe { lr_ospf_retransmit_free(r) };
    }

    #[test]
    fn ffi_retransmit_clear() {
        let r = lr_ospf_retransmit_new();
        let lsa1 = make_lsa_box(make_lsa(1, 1, 0xa));
        let lsa2 = make_lsa_box(make_lsa(1, 2, 0xa));
        unsafe {
            assert_eq!(lr_ospf_retransmit_record_flood(r, lsa1, 0), 0);
            assert_eq!(lr_ospf_retransmit_record_flood(r, lsa2, 0), 0);
        }
        assert_eq!(unsafe { lr_ospf_retransmit_len(r) }, 2);
        unsafe { lr_ospf_retransmit_clear(r) };
        assert_eq!(unsafe { lr_ospf_retransmit_is_empty(r) }, 1);
        unsafe { lr_ospf_retransmit_free(r) };
    }

    #[test]
    fn ffi_retransmit_record_null_returns_error() {
        let r = lr_ospf_retransmit_new();
        let rc = unsafe { lr_ospf_retransmit_record_flood(r, std::ptr::null_mut(), 0) };
        assert_eq!(rc, LR_ERR_NULL);
        unsafe { lr_ospf_retransmit_free(r) };
    }

    #[test]
    fn ffi_retransmit_free_null_safely() {
        unsafe { lr_ospf_retransmit_free(std::ptr::null_mut()) };
    }

    #[test]
    fn ffi_retransmit_len_on_null() {
        assert_eq!(unsafe { lr_ospf_retransmit_len(std::ptr::null_mut()) }, 0);
    }
}
