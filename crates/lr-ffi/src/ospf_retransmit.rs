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
            borrow_list(r).map(|l| l.contains(&key) as u8).unwrap_or(0)
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

/// Apply one LS-Acknowledgment packet (RFC 2328 §13.7) to the
/// retransmission list: for every header in `acks`, the matching
/// entry is removed. Returns the number of entries actually
/// removed — useful for diagnostics when an ack references LSAs we
/// never flooded (a stray / duplicate ack per §13.7 step 5).
///
/// Matching is by LSA identity (type / LS-ID / advertising router),
/// NOT by sequence number or checksum, per §13.7 step 5: the
/// receiver may acknowledge an older instance, which still clears
/// the entry because the receiver is signaling "I have a more
/// recent instance than the one you sent".
///
/// `acks` is a flat array of `lr_ospf_lsa_hdr_t` structs (the
/// same C struct used by `lr_ospf_lsa_header_*`); `count` is the
/// number of headers.
///
/// # Safety
/// `r` must be a valid handle. `acks` must point to `count` readable
/// `lr_ospf_lsa_hdr_t` entries (or be NULL when `count == 0`).
#[no_mangle]
pub unsafe extern "C" fn lr_ospf_retransmit_apply_acks(
    r: lr_ospf_retransmit_t,
    acks: *const crate::ospf_lsdb::lr_ospf_lsa_hdr_t,
    count: usize,
) -> usize {
    guarded(
        || unsafe {
            let Some(l) = borrow_list_mut(r) else {
                return 0;
            };
            if acks.is_null() || count == 0 {
                return 0;
            }
            let slice = unsafe { std::slice::from_raw_parts(acks, count) };
            let headers: Vec<lr_ospf::lsa::LsaHeader> = slice
                .iter()
                .map(|h| lr_ospf::lsa::LsaHeader {
                    ls_age: h.ls_age,
                    options: h.options,
                    ls_type: h.ls_type,
                    link_state_id: h.link_state_id,
                    advertising_router: h.advertising_router,
                    ls_sequence_number: h.ls_sequence_number,
                    ls_checksum: h.ls_checksum,
                    length: h.length,
                })
                .collect();
            l.apply_acks(&headers)
        },
        0,
    )
}

/// Walk the list and return the LSAs whose `now_ms - last_sent_ms >=
/// rxmt_interval` (RFC 2328 §13.6). The returned LSAs are NOT
/// removed from the list; their `last_sent_ms` is bumped to `now_ms`
/// so the next retransmit cycle waits another full `rxmt_interval`.
/// The caller owns the returned `lr_ospf_lsa_box_t*` array and must
/// free it via [`lr_ospf_lsa_array_free`].
///
/// # Safety
/// `r` must be a valid handle. `out` must point to a writable
/// `lr_ospf_lsa_box_t*` (initialized to NULL); `out_count` must
/// point to a writable `usize` (initialized to 0).
#[no_mangle]
pub unsafe extern "C" fn lr_ospf_retransmit_poll(
    r: lr_ospf_retransmit_t,
    now_ms: u64,
    rxmt_interval_ms: u64,
    out: *mut *mut crate::ospf_lsdb::lr_ospf_lsa_box_t,
    out_count: *mut usize,
) -> i32 {
    guarded(
        || unsafe {
            let Some(l) = borrow_list_mut(r) else {
                return LR_ERR_NULL;
            };
            if out.is_null() || out_count.is_null() {
                return LR_ERR_NULL;
            }
            let lsas = l.poll(now_ms, rxmt_interval_ms);
            if lsas.is_empty() {
                unsafe {
                    *out = std::ptr::null_mut();
                    *out_count = 0;
                }
                return 0;
            }
            // Build a flat array of boxed LSAs the caller can walk via
            // lr_ospf_lsa_at and free via lr_ospf_lsa_array_free.
            let handles: Vec<lr_ospf_lsa_box_t> = lsas.into_iter().map(box_lsa_local).collect();
            let n = handles.len();
            let boxed = handles.into_boxed_slice();
            let ptr = Box::into_raw(boxed) as *mut lr_ospf_lsa_box_t;
            unsafe {
                *out = ptr;
                *out_count = n;
            }
            0
        },
        LR_ERR_PANIC,
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

    #[test]
    fn ffi_retransmit_apply_acks_removes_entries() {
        let r = lr_ospf_retransmit_new();
        let lsa1 = make_lsa_box(make_lsa(1, 0xa, 0xa));
        let lsa2 = make_lsa_box(make_lsa(1, 0xb, 0xa));
        unsafe {
            assert_eq!(lr_ospf_retransmit_record_flood(r, lsa1, 0), 0);
            assert_eq!(lr_ospf_retransmit_record_flood(r, lsa2, 0), 0);
        }
        assert_eq!(unsafe { lr_ospf_retransmit_len(r) }, 2);
        // Ack the first LSA — only one entry should be removed.
        let acks = [crate::ospf_lsdb::lr_ospf_lsa_hdr_t {
            ls_age: 0,
            options: 0,
            ls_type: 1,
            link_state_id: 0xa,
            advertising_router: 0xa,
            ls_sequence_number: 1,
            ls_checksum: 0,
            length: 20,
        }];
        let removed = unsafe { lr_ospf_retransmit_apply_acks(r, acks.as_ptr(), 1) };
        assert_eq!(removed, 1);
        assert_eq!(unsafe { lr_ospf_retransmit_len(r) }, 1);
        // The remaining LSA is the one we did not ack.
        assert_eq!(unsafe { lr_ospf_retransmit_contains(r, 1, 0xb, 0xa) }, 1);
        unsafe { lr_ospf_retransmit_free(r) };
    }

    #[test]
    fn ffi_retransmit_apply_acks_silent_on_stray_ack() {
        let r = lr_ospf_retransmit_new();
        let lsa = make_lsa_box(make_lsa(1, 0xa, 0xa));
        unsafe { assert_eq!(lr_ospf_retransmit_record_flood(r, lsa, 0), 0) };
        // Ack a stray LSA — 0 entries removed (§13.7 step 5 silent
        // acceptance).
        let acks = [crate::ospf_lsdb::lr_ospf_lsa_hdr_t {
            ls_age: 0,
            options: 0,
            ls_type: 1,
            link_state_id: 0xdead,
            advertising_router: 0xbeef,
            ls_sequence_number: 1,
            ls_checksum: 0,
            length: 20,
        }];
        let removed = unsafe { lr_ospf_retransmit_apply_acks(r, acks.as_ptr(), 1) };
        assert_eq!(removed, 0);
        assert_eq!(unsafe { lr_ospf_retransmit_len(r) }, 1);
        unsafe { lr_ospf_retransmit_free(r) };
    }

    #[test]
    fn ffi_retransmit_apply_acks_rejects_null() {
        let r = lr_ospf_retransmit_new();
        let removed = unsafe { lr_ospf_retransmit_apply_acks(r, std::ptr::null(), 0) };
        assert_eq!(removed, 0);
        let removed =
            unsafe { lr_ospf_retransmit_apply_acks(std::ptr::null_mut(), std::ptr::null(), 0) };
        assert_eq!(removed, 0);
        unsafe { lr_ospf_retransmit_free(r) };
    }

    #[test]
    fn ffi_retransmit_poll_returns_nothing_when_interval_not_elapsed() {
        let r = lr_ospf_retransmit_new();
        let lsa = make_lsa_box(make_lsa(1, 0xa, 0xa));
        unsafe { assert_eq!(lr_ospf_retransmit_record_flood(r, lsa, 1_000), 0) };
        let mut out: *mut lr_ospf_lsa_box_t = std::ptr::null_mut();
        let mut count = 0usize;
        let rc = unsafe { lr_ospf_retransmit_poll(r, 1_500, 5_000, &raw mut out, &raw mut count) };
        assert_eq!(rc, 0);
        assert_eq!(count, 0);
        assert!(out.is_null());
        unsafe { lr_ospf_retransmit_free(r) };
    }

    #[test]
    fn ffi_retransmit_poll_returns_aged_lsas() {
        let r = lr_ospf_retransmit_new();
        let lsa = make_lsa_box(make_lsa(1, 0xa, 0xa));
        unsafe { assert_eq!(lr_ospf_retransmit_record_flood(r, lsa, 1_000), 0) };
        // Tick to past RxmtInterval — the LSA must retransmit.
        let mut out: *mut lr_ospf_lsa_box_t = std::ptr::null_mut();
        let mut count = 0usize;
        let rc = unsafe { lr_ospf_retransmit_poll(r, 6_000, 5_000, &raw mut out, &raw mut count) };
        assert_eq!(rc, 0);
        assert_eq!(count, 1);
        assert!(!out.is_null());
        // Free the returned array.
        unsafe { crate::ospf_lsdb::lr_ospf_lsa_array_free(out, count) };
        unsafe { lr_ospf_retransmit_free(r) };
    }

    #[test]
    fn ffi_retransmit_poll_rejects_null() {
        let r = lr_ospf_retransmit_new();
        let mut out: *mut lr_ospf_lsa_box_t = std::ptr::null_mut();
        let mut count = 0usize;
        let rc = unsafe {
            lr_ospf_retransmit_poll(std::ptr::null_mut(), 0, 0, &raw mut out, &raw mut count)
        };
        assert_eq!(rc, LR_ERR_NULL);
        let rc =
            unsafe { lr_ospf_retransmit_poll(r, 0, 0, std::ptr::null_mut(), std::ptr::null_mut()) };
        assert_eq!(rc, LR_ERR_NULL);
        unsafe { lr_ospf_retransmit_free(r) };
    }
}
