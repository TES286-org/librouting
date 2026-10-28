//! lr_core::attr::{Attributes, Attribute, AttrTag} FFI.
//!
//! Mirrors the public Rust API of `lr_core::attr::{Attributes,
//! Attribute, AttrTag}` so an embedder can build, populate, read and
//! round-trip a generic ordered attribute set across the C ABI. The
//! type is used internally by `Route::attributes` (BGP path attributes
//! and OSPF/Babel extra-metadata) but was previously only reachable
//! through the typed BGP path-attribute accessors in
//! `crates/lr-ffi/src/bgp_path.rs`.
//!
//! # Surface
//!
//! - `lr_attributes_new` — empty attribute set.
//! - `lr_attributes_insert(attrs, tag, flags, value, value_len)` —
//!   insert / replace one attribute by tag.
//! - `lr_attributes_get(attrs, tag, out_flags, out_value, out_value_len)`
//!   — read one attribute by tag (caller-allocates the value buffer).
//! - `lr_attributes_get_u32_be / _u64_be / _u8` — typed readers for
//!   the common 4-byte / 8-byte / 1-byte big-endian shapes.
//! - `lr_attributes_remove(attrs, tag)` — drop one attribute by tag.
//! - `lr_attributes_len / _is_empty` — readers.
//! - `lr_attributes_at(attrs, index, out_tag, out_flags, out_value,
//!   out_value_len)` — read one attribute by index (caller-allocates
//!   the value buffer; returns the total length even if larger than
//!   cap).
//! - `lr_attributes_free` — drop the boxed set (safe on NULL).
//!
//! Every entry point runs inside the crate's `catch_unwind` barrier
//! ([`crate::guarded`]); a panic returns `LR_ERR_PANIC` and sets the
//! thread-local last-error string.

// The closure body passed to `guarded` is wrapped in a single `unsafe`
// block to mirror the `pub unsafe extern "C" fn` shape — the inner
// `unsafe { ... }` blocks would otherwise trip `unused_unsafe` under
// the crate's `-D warnings` clippy gate.
#![allow(unused_unsafe)]

use lr_core::attr::{AttrTag, Attribute, Attributes};

use crate::error::{set_last_error, LrError, LR_ERR_PANIC};
use crate::guarded;

const LR_ERR_NULL: i32 = LrError::Null as i32;
const LR_ERR_INVALID_HANDLE: i32 = LrError::InvalidHandle as i32;

/// Opaque `Attributes` handle. C side never touches internals.
#[repr(C)]
pub struct OpaqueAttributes {
    _private: [u8; 0],
}

pub type lr_attributes_t = *mut OpaqueAttributes;

/// Box an `Attributes` into an opaque handle.
fn box_attrs(a: Attributes) -> lr_attributes_t {
    Box::into_raw(Box::new(a)) as lr_attributes_t
}

/// Reclaim an `Attributes` handle back into its boxed form.
///
/// # Safety
/// `a` must have been produced by [`box_attrs`] and not already freed.
unsafe fn unbox_attrs(a: lr_attributes_t) -> Option<Box<Attributes>> {
    if a.is_null() {
        return None;
    }
    Some(unsafe { Box::from_raw(a as *mut Attributes) })
}

/// Borrow an `Attributes` handle as `&Attributes` for read-only access.
///
/// # Safety
/// `a` must have been produced by [`box_attrs`] and not be freed while
/// the returned reference is live.
pub(crate) unsafe fn borrow_attrs(a: lr_attributes_t) -> Option<&'static Attributes> {
    if a.is_null() {
        return None;
    }
    Some(unsafe { &*(a as *const Attributes) })
}

/// Borrow an `Attributes` handle as `&mut Attributes` for in-place
/// mutation.
///
/// # Safety
/// `a` must have been produced by [`box_attrs`] and not be freed while
/// the returned reference is live.
unsafe fn borrow_attrs_mut(a: lr_attributes_t) -> Option<&'static mut Attributes> {
    if a.is_null() {
        return None;
    }
    Some(unsafe { &mut *(a as *mut Attributes) })
}

/// Construct an empty `Attributes`.
#[no_mangle]
pub extern "C" fn lr_attributes_new() -> lr_attributes_t {
    guarded(|| box_attrs(Attributes::new()), std::ptr::null_mut())
}

/// Insert / replace one attribute by tag. `value` points to
/// `value_len` raw bytes (NULL only when `value_len == 0`).
///
/// # Safety
/// `a` must be a valid handle. `value` (when non-null) must point to
/// `value_len` readable bytes.
#[no_mangle]
pub unsafe extern "C" fn lr_attributes_insert(
    a: lr_attributes_t,
    tag: u8,
    flags: u8,
    value: *const u8,
    value_len: usize,
) -> i32 {
    guarded(
        || unsafe {
            let Some(attrs) = borrow_attrs_mut(a) else {
                return LR_ERR_NULL;
            };
            if value.is_null() && value_len != 0 {
                return LR_ERR_NULL;
            }
            let value_vec = if value.is_null() {
                Vec::new()
            } else {
                unsafe { std::slice::from_raw_parts(value, value_len).to_vec() }
            };
            attrs.insert(Attribute {
                tag: AttrTag(tag),
                flags,
                value: value_vec,
            });
            0
        },
        LR_ERR_PANIC,
    )
}

/// Read one attribute by tag. On success writes `flags` to
/// `*out_flags`, the raw value bytes to `out_value` (caller-allocated,
/// at most `cap` bytes), and returns the total value length (>= 0).
/// A return value of -1 (`LR_ERR_NULL`) means a null handle / null
/// out pointer; a return value of -2 means the tag is not present.
///
/// # Safety
/// `a` must be a valid handle. `out_flags` must point to a writable
/// `uint8_t`. `out_value` (when non-null) must point to `cap`
/// writable bytes.
#[no_mangle]
pub unsafe extern "C" fn lr_attributes_get(
    a: lr_attributes_t,
    tag: u8,
    out_flags: *mut u8,
    out_value: *mut u8,
    cap: usize,
) -> i64 {
    guarded(
        || unsafe {
            let Some(attrs) = borrow_attrs(a) else {
                return LR_ERR_NULL as i64;
            };
            if out_flags.is_null() {
                return LR_ERR_NULL as i64;
            }
            let Some(attr) = attrs.get(AttrTag(tag)) else {
                return LR_ERR_INVALID_HANDLE as i64;
            };
            unsafe { *out_flags = attr.flags };
            let n = attr.value.len();
            if !out_value.is_null() && cap > 0 {
                let to_write = n.min(cap);
                unsafe {
                    std::ptr::copy_nonoverlapping(attr.value.as_ptr(), out_value, to_write);
                }
            }
            n as i64
        },
        LR_ERR_PANIC as i64,
    )
}

/// Read a 4-byte big-endian unsigned integer attribute. Returns 0
/// when the tag is absent or the value is not exactly 4 bytes long
/// (the caller cannot distinguish "absent" from "value is 0" — use
/// [`lr_attributes_get`] when the distinction matters).
///
/// # Safety
/// `a` must be a valid handle.
#[no_mangle]
pub unsafe extern "C" fn lr_attributes_get_u32_be(a: lr_attributes_t, tag: u8) -> u32 {
    guarded(
        || unsafe {
            borrow_attrs(a)
                .and_then(|attrs| attrs.get_u32_be(AttrTag(tag)))
                .unwrap_or(0)
        },
        0,
    )
}

/// Read an 8-byte big-endian unsigned integer attribute. Returns 0
/// when the tag is absent or the value is not exactly 8 bytes long.
///
/// # Safety
/// See [`lr_attributes_get_u32_be`].
#[no_mangle]
pub unsafe extern "C" fn lr_attributes_get_u64_be(a: lr_attributes_t, tag: u8) -> u64 {
    guarded(
        || unsafe {
            borrow_attrs(a)
                .and_then(|attrs| attrs.get_u64_be(AttrTag(tag)))
                .unwrap_or(0)
        },
        0,
    )
}

/// Read a 1-byte unsigned integer attribute. Returns 0 when the tag
/// is absent.
///
/// # Safety
/// See [`lr_attributes_get_u32_be`].
#[no_mangle]
pub unsafe extern "C" fn lr_attributes_get_u8(a: lr_attributes_t, tag: u8) -> u8 {
    guarded(
        || unsafe {
            borrow_attrs(a)
                .and_then(|attrs| attrs.get_u8(AttrTag(tag)))
                .unwrap_or(0)
        },
        0,
    )
}

/// Remove one attribute by tag. Returns 1 when the attribute was
/// present (and is now removed), 0 when it was not in the set.
///
/// # Safety
/// `a` must be a valid handle.
#[no_mangle]
pub unsafe extern "C" fn lr_attributes_remove(a: lr_attributes_t, tag: u8) -> i32 {
    guarded(
        || unsafe {
            let Some(attrs) = borrow_attrs_mut(a) else {
                return LR_ERR_NULL;
            };
            if attrs.remove(AttrTag(tag)).is_some() {
                1
            } else {
                0
            }
        },
        LR_ERR_PANIC,
    )
}

/// Number of attributes in the set. Returns 0 on a NULL handle.
///
/// # Safety
/// `a` must be a valid handle.
#[no_mangle]
pub unsafe extern "C" fn lr_attributes_len(a: lr_attributes_t) -> usize {
    guarded(
        || unsafe { borrow_attrs(a).map(|a| a.len()).unwrap_or(0) },
        0,
    )
}

/// True (1) when the set holds no attributes, false (0) otherwise.
/// Returns 1 (true) on a NULL handle (the safe default for "no
/// attributes to read").
///
/// # Safety
/// `a` must be a valid handle.
#[no_mangle]
pub unsafe extern "C" fn lr_attributes_is_empty(a: lr_attributes_t) -> u8 {
    guarded(
        || unsafe { borrow_attrs(a).map(|a| a.is_empty() as u8).unwrap_or(1) },
        1,
    )
}

/// Read one attribute by index. On success writes `tag` and `flags`
/// to `*out_tag` and `*out_flags`, the raw value bytes to `out_value`
/// (caller-allocated, at most `cap` bytes), and returns the total
/// value length (>= 0). A return value greater than `cap` means the
/// buffer was too small. Returns -1 (`LR_ERR_NULL`) on a null handle /
/// null out pointer, -2 (`LR_ERR_INVALID_HANDLE`) when the index is
/// out of range.
///
/// # Safety
/// `a` must be a valid handle. `out_tag` and `out_flags` must point
/// to writable `uint8_t` values. `out_value` (when non-null) must
/// point to `cap` writable bytes.
#[no_mangle]
pub unsafe extern "C" fn lr_attributes_at(
    a: lr_attributes_t,
    index: usize,
    out_tag: *mut u8,
    out_flags: *mut u8,
    out_value: *mut u8,
    cap: usize,
) -> i64 {
    guarded(
        || unsafe {
            let Some(attrs) = borrow_attrs(a) else {
                return LR_ERR_NULL as i64;
            };
            if out_tag.is_null() || out_flags.is_null() {
                return LR_ERR_NULL as i64;
            }
            let Some(attr) = attrs.iter().nth(index) else {
                set_last_error(format!(
                    "attribute index {index} out of range (len={})",
                    attrs.len()
                ));
                return LR_ERR_INVALID_HANDLE as i64;
            };
            unsafe {
                *out_tag = attr.tag.0;
                *out_flags = attr.flags;
            }
            let n = attr.value.len();
            if !out_value.is_null() && cap > 0 {
                let to_write = n.min(cap);
                unsafe {
                    std::ptr::copy_nonoverlapping(attr.value.as_ptr(), out_value, to_write);
                }
            }
            n as i64
        },
        LR_ERR_PANIC as i64,
    )
}

/// Drop a boxed `Attributes`. Safe to call with NULL.
///
/// # Safety
/// `a` must have been produced by [`lr_attributes_new`] and must not
/// be used after this call. Double-free is undefined behaviour.
#[no_mangle]
pub unsafe extern "C" fn lr_attributes_free(a: lr_attributes_t) {
    guarded(
        || unsafe {
            drop(unbox_attrs(a));
        },
        (),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ffi_attributes_new_is_empty() {
        let a = lr_attributes_new();
        assert!(!a.is_null());
        assert_eq!(unsafe { lr_attributes_len(a) }, 0);
        assert_eq!(unsafe { lr_attributes_is_empty(a) }, 1);
        unsafe { lr_attributes_free(a) };
    }

    #[test]
    fn ffi_attributes_insert_and_get_round_trip() {
        let a = lr_attributes_new();
        let value = [0u8, 0, 0, 100]; // 100 as u32 BE
        let rc = unsafe { lr_attributes_insert(a, 5, 0x40, value.as_ptr(), 4) };
        assert_eq!(rc, 0);
        assert_eq!(unsafe { lr_attributes_len(a) }, 1);
        assert_eq!(unsafe { lr_attributes_is_empty(a) }, 0);

        // Read back flags + value.
        let mut flags = 0u8;
        let mut out = [0u8; 4];
        let n = unsafe { lr_attributes_get(a, 5, &raw mut flags, out.as_mut_ptr(), 4) };
        assert_eq!(n, 4);
        assert_eq!(flags, 0x40);
        assert_eq!(out, value);

        // Typed reader.
        let v = unsafe { lr_attributes_get_u32_be(a, 5) };
        assert_eq!(v, 100);
        unsafe { lr_attributes_free(a) };
    }

    #[test]
    fn ffi_attributes_get_returns_invalid_handle_for_missing_tag() {
        let a = lr_attributes_new();
        let mut flags = 0u8;
        let n = unsafe { lr_attributes_get(a, 99, &raw mut flags, std::ptr::null_mut(), 0) };
        assert_eq!(n, LR_ERR_INVALID_HANDLE as i64);
        unsafe { lr_attributes_free(a) };
    }

    #[test]
    fn ffi_attributes_get_returns_partial_when_buffer_too_small() {
        let a = lr_attributes_new();
        let value = [1u8, 2, 3, 4, 5, 6, 7, 8];
        unsafe { lr_attributes_insert(a, 7, 0, value.as_ptr(), 8) };
        let mut flags = 0u8;
        let mut out = [0u8; 4]; // too small
        let n = unsafe { lr_attributes_get(a, 7, &raw mut flags, out.as_mut_ptr(), 4) };
        assert_eq!(n, 8, "returns total length even when buffer too small");
        assert_eq!(&out, &value[..4], "writes only what fits");
        unsafe { lr_attributes_free(a) };
    }

    #[test]
    fn ffi_attributes_u64_be_round_trip() {
        let a = lr_attributes_new();
        let value = 0x0123_4567_89ab_cdefu64.to_be_bytes();
        unsafe { lr_attributes_insert(a, 9, 0, value.as_ptr(), 8) };
        let v = unsafe { lr_attributes_get_u64_be(a, 9) };
        assert_eq!(v, 0x0123_4567_89ab_cdef);
        unsafe { lr_attributes_free(a) };
    }

    #[test]
    fn ffi_attributes_u8_round_trip() {
        let a = lr_attributes_new();
        let value = [42u8];
        unsafe { lr_attributes_insert(a, 11, 0, value.as_ptr(), 1) };
        let v = unsafe { lr_attributes_get_u8(a, 11) };
        assert_eq!(v, 42);
        unsafe { lr_attributes_free(a) };
    }

    #[test]
    fn ffi_attributes_remove_returns_presence() {
        let a = lr_attributes_new();
        let value = [0u8; 4];
        unsafe { lr_attributes_insert(a, 5, 0, value.as_ptr(), 4) };
        assert_eq!(unsafe { lr_attributes_remove(a, 5) }, 1);
        assert_eq!(unsafe { lr_attributes_remove(a, 5) }, 0);
        assert_eq!(unsafe { lr_attributes_len(a) }, 0);
        unsafe { lr_attributes_free(a) };
    }

    #[test]
    fn ffi_attributes_at_round_trip() {
        let a = lr_attributes_new();
        let v1 = [0u8, 0, 0, 1];
        let v2 = [0u8, 0, 0, 2];
        unsafe {
            lr_attributes_insert(a, 5, 0, v1.as_ptr(), 4);
            lr_attributes_insert(a, 7, 0x80, v2.as_ptr(), 4);
        }
        assert_eq!(unsafe { lr_attributes_len(a) }, 2);

        let mut tag = 0u8;
        let mut flags = 0u8;
        let mut out = [0u8; 4];
        let n =
            unsafe { lr_attributes_at(a, 1, &raw mut tag, &raw mut flags, out.as_mut_ptr(), 4) };
        assert_eq!(n, 4);
        // BTreeMap ordering: tag 5 before tag 7 — index 1 is tag 7.
        assert_eq!(tag, 7);
        assert_eq!(flags, 0x80);
        assert_eq!(out, v2);

        // Out of range.
        let n =
            unsafe { lr_attributes_at(a, 99, &raw mut tag, &raw mut flags, out.as_mut_ptr(), 4) };
        assert_eq!(n, LR_ERR_INVALID_HANDLE as i64);

        unsafe { lr_attributes_free(a) };
    }

    #[test]
    fn ffi_attributes_null_handle_returns_lr_err_null() {
        let mut flags = 0u8;
        let n = unsafe {
            lr_attributes_get(
                std::ptr::null_mut(),
                5,
                &raw mut flags,
                std::ptr::null_mut(),
                0,
            )
        };
        assert_eq!(n, LR_ERR_NULL as i64);
        assert_eq!(unsafe { lr_attributes_len(std::ptr::null_mut()) }, 0);
        assert_eq!(unsafe { lr_attributes_is_empty(std::ptr::null_mut()) }, 1);
        assert_eq!(
            unsafe { lr_attributes_remove(std::ptr::null_mut(), 5) },
            LR_ERR_NULL
        );
    }

    #[test]
    fn ffi_attributes_free_handles_null_safely() {
        unsafe { lr_attributes_free(std::ptr::null_mut()) };
    }

    #[test]
    fn ffi_attributes_insert_replaces_on_same_tag() {
        let a = lr_attributes_new();
        let v1 = [0u8, 0, 0, 1];
        let v2 = [0u8, 0, 0, 2];
        unsafe {
            lr_attributes_insert(a, 5, 0, v1.as_ptr(), 4);
            lr_attributes_insert(a, 5, 0x40, v2.as_ptr(), 4);
        }
        assert_eq!(unsafe { lr_attributes_len(a) }, 1, "same tag → replace");
        let v = unsafe { lr_attributes_get_u32_be(a, 5) };
        assert_eq!(v, 2, "latest value wins");
        let mut flags = 0u8;
        let _ = unsafe { lr_attributes_get(a, 5, &raw mut flags, std::ptr::null_mut(), 0) };
        assert_eq!(flags, 0x40, "latest flags win");
        unsafe { lr_attributes_free(a) };
    }
}
