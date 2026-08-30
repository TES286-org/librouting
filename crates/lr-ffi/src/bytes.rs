//! `lr_bytes_t` helpers — free + clone + length.
//!
//! Every entry point runs inside the crate's `catch_unwind` barrier
//! ([`crate::guarded`]): on panic `lr_bytes_free` becomes a no-op, and
//! `lr_bytes_len`/`lr_bytes_ptr` return 0/NULL and set the thread-local
//! last-error string.

use crate::guarded;
use crate::handle::lr_bytes_t;

/// Free an `lr_bytes_t` previously returned from any `lr_*` function. Safe to
/// call with a NULL pointer.
///
/// # Safety
/// The pointer must have been produced by an `lr_*` function.
#[no_mangle]
pub unsafe extern "C" fn lr_bytes_free(b: *mut lr_bytes_t) {
    guarded(
        || unsafe {
            if b.is_null() {
                return;
            }
            let b_ref = &mut *b;
            let _ = b_ref.reclaim_into_vec();
            // Drop the lr_bytes_t itself.
            drop(std::ptr::read(b));
        },
        (),
    )
}

/// Length of an `lr_bytes_t`.
#[no_mangle]
pub extern "C" fn lr_bytes_len(b: *const lr_bytes_t) -> usize {
    guarded(
        || {
            if b.is_null() {
                return 0;
            }
            unsafe { (*b).len }
        },
        0,
    )
}

/// Pointer to the data of an `lr_bytes_t`. NULL if `b` is NULL.
#[no_mangle]
pub extern "C" fn lr_bytes_ptr(b: *const lr_bytes_t) -> *const u8 {
    guarded(
        || {
            if b.is_null() {
                return std::ptr::null();
            }
            unsafe { (*b).ptr }
        },
        std::ptr::null(),
    )
}
