//! LDP transit label allocator FFI — `lr_ldp_transit_*`.
//!
//! Mirrors the public Rust API of `lr_ldp::transit::TransitAllocator`
//! so an embedder can manage the local transit label space (RFC 5036
//! §3.5.7.1.1 — the labels a transit LSR assigns to FEC→next-hop
//! bindings). The allocator owns a contiguous `[label_min, label_max]`
//! range, reserves a set of operator-configured labels, and tracks
//! which prefixes currently hold a transit label.
//!
//! Every entry point runs inside the crate's `catch_unwind` barrier
//! ([`crate::guarded`]): a panic returns `LR_ERR_PANIC` and sets the
//! thread-local last-error string.

#![allow(unused_unsafe)]

use lr_core::addr::Prefix;
use lr_ldp::transit::TransitAllocator;

use crate::guarded;

/// Opaque `TransitAllocator` handle.
#[repr(C)]
pub struct OpaqueLdpTransit {
    _private: [u8; 0],
}
pub type lr_ldp_transit_t = *mut OpaqueLdpTransit;

fn box_alloc(a: TransitAllocator) -> lr_ldp_transit_t {
    Box::into_raw(Box::new(a)) as lr_ldp_transit_t
}
unsafe fn borrow_alloc(a: lr_ldp_transit_t) -> Option<&'static TransitAllocator> {
    if a.is_null() {
        return None;
    }
    Some(unsafe { &*(a as *const TransitAllocator) })
}
unsafe fn borrow_alloc_mut(a: lr_ldp_transit_t) -> Option<&'static mut TransitAllocator> {
    if a.is_null() {
        return None;
    }
    Some(unsafe { &mut *(a as *mut TransitAllocator) })
}
unsafe fn unbox_alloc(a: lr_ldp_transit_t) -> Option<Box<TransitAllocator>> {
    if a.is_null() {
        return None;
    }
    Some(unsafe { Box::from_raw(a as *mut TransitAllocator) })
}

/// Construct a `TransitAllocator` over `[label_min, label_max]`,
/// reserving the labels in `reserved` (RFC 5036 §3.5.7.1.1 — the
/// operator's static label range; new allocations never reuse them).
/// `label_min` must be <= `label_max`; `reserved` may be NULL when
/// `reserved_count == 0`.
///
/// # Safety
/// `reserved` must point to `reserved_count` readable `uint32_t`
/// values (NULL only when `reserved_count == 0`).
#[no_mangle]
pub unsafe extern "C" fn lr_ldp_transit_new(
    label_min: u32,
    label_max: u32,
    reserved: *const u32,
    reserved_count: usize,
) -> lr_ldp_transit_t {
    guarded(
        || unsafe {
            let reserved_slice: &[u32] = if reserved_count == 0 || reserved.is_null() {
                &[]
            } else {
                unsafe { std::slice::from_raw_parts(reserved, reserved_count) }
            };
            box_alloc(TransitAllocator::new(label_min, label_max, reserved_slice))
        },
        std::ptr::null_mut(),
    )
}

/// Drop a boxed `TransitAllocator`. Safe to call with NULL.
///
/// # Safety
/// `a` must have been produced by `lr_ldp_transit_new` and not already
/// freed.
#[no_mangle]
pub unsafe extern "C" fn lr_ldp_transit_free(a: lr_ldp_transit_t) {
    guarded(
        || unsafe {
            drop(unbox_alloc(a));
        },
        (),
    )
}

/// Read the transit label already allocated to `prefix`, if any.
/// Returns 1 and writes the label to `*out_label` when allocated,
/// 0 otherwise (or NULL handle).
///
/// # Safety
/// `a` must be a valid TransitAllocator handle. `out_label` must
/// point to a writable `uint32_t`. `prefix_addr` must point to 4
/// (v4) or 16 (v6) readable bytes.
#[no_mangle]
pub unsafe extern "C" fn lr_ldp_transit_label_of(
    a: lr_ldp_transit_t,
    prefix_addr: *const u8,
    is_ipv6: u8,
    prefix_len: u8,
    out_label: *mut u32,
) -> u8 {
    guarded(
        || unsafe {
            let Some(alloc) = borrow_alloc(a) else {
                return 0;
            };
            if prefix_addr.is_null() || out_label.is_null() {
                return 0;
            }
            let prefix = build_prefix(prefix_addr, is_ipv6, prefix_len);
            match alloc.label_of(&prefix) {
                Some(label) => {
                    unsafe { *out_label = label.0 };
                    1
                }
                None => 0,
            }
        },
        0,
    )
}

/// True when `prefix` already holds a transit label.
///
/// # Safety
/// See [`lr_ldp_transit_label_of`].
#[no_mangle]
pub unsafe extern "C" fn lr_ldp_transit_is_allocated(
    a: lr_ldp_transit_t,
    prefix_addr: *const u8,
    is_ipv6: u8,
    prefix_len: u8,
) -> u8 {
    guarded(
        || unsafe {
            let Some(alloc) = borrow_alloc(a) else {
                return 0;
            };
            if prefix_addr.is_null() {
                return 0;
            }
            let prefix = build_prefix(prefix_addr, is_ipv6, prefix_len);
            alloc.is_allocated(&prefix) as u8
        },
        0,
    )
}

/// Number of prefixes currently holding a transit label. Returns 0
/// on a NULL handle.
///
/// # Safety
/// `a` must be a valid TransitAllocator handle.
#[no_mangle]
pub unsafe extern "C" fn lr_ldp_transit_allocated_count(a: lr_ldp_transit_t) -> usize {
    guarded(
        || unsafe { borrow_alloc(a).map(|x| x.allocated_count()).unwrap_or(0) },
        0,
    )
}

/// Allocate a fresh transit label for `prefix` (RFC 5036 §3.5.7.1.1).
/// Returns 1 and writes the label to `*out_label` on success, 0
/// when the range is exhausted (or the prefix already holds a label
/// — use `label_of` to read the existing one).
///
/// # Safety
/// See [`lr_ldp_transit_label_of`].
#[no_mangle]
pub unsafe extern "C" fn lr_ldp_transit_allocate(
    a: lr_ldp_transit_t,
    prefix_addr: *const u8,
    is_ipv6: u8,
    prefix_len: u8,
    out_label: *mut u32,
) -> u8 {
    guarded(
        || unsafe {
            let Some(alloc) = borrow_alloc_mut(a) else {
                return 0;
            };
            if prefix_addr.is_null() || out_label.is_null() {
                return 0;
            }
            let prefix = build_prefix(prefix_addr, is_ipv6, prefix_len);
            match alloc.allocate(prefix) {
                Some(label) => {
                    unsafe { *out_label = label.0 };
                    1
                }
                None => 0,
            }
        },
        0,
    )
}

/// Release the transit label held by `prefix` (RFC 5036 §3.5.7.1.1 —
/// the label returns to the free pool). Returns 1 and writes the
/// released label to `*out_label` when the prefix held one, 0
/// otherwise.
///
/// # Safety
/// See [`lr_ldp_transit_label_of`].
#[no_mangle]
pub unsafe extern "C" fn lr_ldp_transit_release(
    a: lr_ldp_transit_t,
    prefix_addr: *const u8,
    is_ipv6: u8,
    prefix_len: u8,
    out_label: *mut u32,
) -> u8 {
    guarded(
        || unsafe {
            let Some(alloc) = borrow_alloc_mut(a) else {
                return 0;
            };
            if prefix_addr.is_null() {
                return 0;
            }
            let prefix = build_prefix(prefix_addr, is_ipv6, prefix_len);
            match alloc.release(&prefix) {
                Some(label) => {
                    if !out_label.is_null() {
                        unsafe { *out_label = label.0 };
                    }
                    1
                }
                None => 0,
            }
        },
        0,
    )
}

// ---- helpers ----

unsafe fn build_prefix(addr: *const u8, is_ipv6: u8, prefix_len: u8) -> Prefix {
    if is_ipv6 == 0 {
        let mut o = [0u8; 4];
        unsafe { o.copy_from_slice(std::slice::from_raw_parts(addr, 4)) };
        Prefix::new_v4(o, prefix_len)
    } else {
        let mut o = [0u8; 16];
        unsafe { o.copy_from_slice(std::slice::from_raw_parts(addr, 16)) };
        Prefix::new_v6(o, prefix_len)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ffi_ldp_transit_new_and_allocated_count() {
        let a = unsafe { lr_ldp_transit_new(1000, 2000, std::ptr::null(), 0) };
        assert!(!a.is_null());
        assert_eq!(unsafe { lr_ldp_transit_allocated_count(a) }, 0);
        unsafe { lr_ldp_transit_free(a) };
    }

    #[test]
    fn ffi_ldp_transit_allocate_and_release() {
        let a = unsafe { lr_ldp_transit_new(1000, 2000, std::ptr::null(), 0) };

        // Allocate a label for 10.0.0.0/8.
        let prefix = [10u8, 0, 0, 0];
        let mut label = 0u32;
        let rc = unsafe { lr_ldp_transit_allocate(a, prefix.as_ptr(), 0, 8, &raw mut label) };
        assert_eq!(rc, 1);
        assert!((1000..=2000).contains(&label));

        // allocated_count is now 1.
        assert_eq!(unsafe { lr_ldp_transit_allocated_count(a) }, 1);

        // label_of returns the same label.
        let mut label2 = 0u32;
        let rc = unsafe { lr_ldp_transit_label_of(a, prefix.as_ptr(), 0, 8, &raw mut label2) };
        assert_eq!(rc, 1);
        assert_eq!(label2, label);

        // is_allocated is now true.
        let rc = unsafe { lr_ldp_transit_is_allocated(a, prefix.as_ptr(), 0, 8) };
        assert_eq!(rc, 1);

        // Release the label.
        let mut released = 0u32;
        let rc = unsafe { lr_ldp_transit_release(a, prefix.as_ptr(), 0, 8, &raw mut released) };
        assert_eq!(rc, 1);
        assert_eq!(released, label);

        // allocated_count is now 0.
        assert_eq!(unsafe { lr_ldp_transit_allocated_count(a) }, 0);

        // Releasing again returns 0.
        let mut dummy = 0u32;
        let rc = unsafe { lr_ldp_transit_release(a, prefix.as_ptr(), 0, 8, &raw mut dummy) };
        assert_eq!(rc, 0);

        unsafe { lr_ldp_transit_free(a) };
    }

    #[test]
    fn ffi_ldp_transit_reserved_labels_are_skipped() {
        // Reserve label 1000; the first allocation should be 1001.
        let reserved = [1000u32];
        let a = unsafe { lr_ldp_transit_new(1000, 2000, reserved.as_ptr(), 1) };
        let prefix = [10u8, 0, 0, 0];
        let mut label = 0u32;
        let rc = unsafe { lr_ldp_transit_allocate(a, prefix.as_ptr(), 0, 8, &raw mut label) };
        assert_eq!(rc, 1);
        assert_ne!(label, 1000);
        assert!((1001..=2000).contains(&label));
        unsafe { lr_ldp_transit_free(a) };
    }

    #[test]
    fn ffi_ldp_transit_allocate_returns_zero_on_exhaustion() {
        // A 1-label range — only one allocation succeeds.
        let a = unsafe { lr_ldp_transit_new(1000, 1000, std::ptr::null(), 0) };
        let p1 = [10u8, 0, 0, 0];
        let p2 = [10u8, 0, 0, 1];
        let mut l1 = 0u32;
        let mut l2 = 0u32;
        assert_eq!(
            unsafe { lr_ldp_transit_allocate(a, p1.as_ptr(), 0, 32, &raw mut l1) },
            1
        );
        assert_eq!(
            unsafe { lr_ldp_transit_allocate(a, p2.as_ptr(), 0, 32, &raw mut l2) },
            0,
            "range exhausted"
        );
        unsafe { lr_ldp_transit_free(a) };
    }

    #[test]
    fn ffi_ldp_transit_ipv6_round_trip() {
        let a = unsafe { lr_ldp_transit_new(1000, 2000, std::ptr::null(), 0) };
        let prefix = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let mut label = 0u32;
        let rc = unsafe { lr_ldp_transit_allocate(a, prefix.as_ptr(), 1, 64, &raw mut label) };
        assert_eq!(rc, 1);
        assert_eq!(unsafe { lr_ldp_transit_allocated_count(a) }, 1);
        unsafe { lr_ldp_transit_free(a) };
    }

    #[test]
    fn ffi_ldp_transit_handles_null_safely() {
        assert_eq!(
            unsafe { lr_ldp_transit_allocated_count(std::ptr::null_mut()) },
            0
        );
        unsafe { lr_ldp_transit_free(std::ptr::null_mut()) };
    }
}
