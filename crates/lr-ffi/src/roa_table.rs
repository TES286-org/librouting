//! Immutable `RoaTable` + `RoaTableBuilder` FFI (RFC 6482 / RFC 6811).
//!
//! Mirrors the public Rust API of `lr_bgp::roa::{RoaTable,
//! RoaTableBuilder, RoaEntry, RoaState}` so an embedder can build an
//! immutable ROA validation table without going through the
//! thread-safe dual-layer [`lr_bgp::RoaStore`] (which is the surface
//! `lr_roa_store_*` already exposes). The immutable table is the
//! right shape for an embedder that loads a static ROA set once at
//! startup and validates against it without ever mutating — half
//! the allocation of a `RoaStore` and no lock contention.
//!
//! Reuses the `lr_roa_entry_t` and `lr_roa_delta_t` types from
//! `crates/lr-ffi/src/roa_store.rs` so the embedder's existing
//! entry-construction code is reusable.
//!
//! Every entry point runs inside the crate's `catch_unwind` barrier
//! ([`crate::guarded`]): a panic returns `LR_ERR_PANIC` and sets the
//! thread-local last-error string.

#![allow(unused_unsafe)]

use lr_bgp::roa::{RoaState, RoaTable, RoaTableBuilder};
use lr_core::addr::{Asn, Prefix};

use crate::error::{set_last_error, LrError, LR_ERR_PANIC};
use crate::guarded;
use crate::roa_store::lr_roa_entry_t;

const LR_ERR_NULL: i32 = LrError::Null as i32;

/// Opaque `RoaTable` handle.
#[repr(C)]
pub struct OpaqueRoaTable {
    _private: [u8; 0],
}
pub type lr_roa_table_t = *mut OpaqueRoaTable;

fn box_table(t: RoaTable) -> lr_roa_table_t {
    Box::into_raw(Box::new(t)) as lr_roa_table_t
}
unsafe fn borrow_table(t: lr_roa_table_t) -> Option<&'static RoaTable> {
    if t.is_null() {
        return None;
    }
    Some(unsafe { &*(t as *const RoaTable) })
}
unsafe fn unbox_table(t: lr_roa_table_t) -> Option<Box<RoaTable>> {
    if t.is_null() {
        return None;
    }
    Some(unsafe { Box::from_raw(t as *mut RoaTable) })
}

/// Opaque `RoaTableBuilder` handle.
#[repr(C)]
pub struct OpaqueRoaTableBuilder {
    _private: [u8; 0],
}
pub type lr_roa_table_builder_t = *mut OpaqueRoaTableBuilder;

fn box_builder(b: RoaTableBuilder) -> lr_roa_table_builder_t {
    Box::into_raw(Box::new(b)) as lr_roa_table_builder_t
}
unsafe fn borrow_builder_mut(b: lr_roa_table_builder_t) -> Option<&'static mut RoaTableBuilder> {
    if b.is_null() {
        return None;
    }
    Some(unsafe { &mut *(b as *mut RoaTableBuilder) })
}
unsafe fn unbox_builder(b: lr_roa_table_builder_t) -> Option<Box<RoaTableBuilder>> {
    if b.is_null() {
        return None;
    }
    Some(unsafe { Box::from_raw(b as *mut RoaTableBuilder) })
}

/// Construct an empty `RoaTableBuilder` (RFC 6482 — add entries via
/// `lr_roa_table_builder_add` / `_add_entry`, then call
/// `lr_roa_table_builder_build` to finalize).
#[no_mangle]
pub extern "C" fn lr_roa_table_builder_new() -> lr_roa_table_builder_t {
    guarded(|| box_builder(RoaTableBuilder::new()), std::ptr::null_mut())
}

/// Drop a boxed `RoaTableBuilder`. Safe to call with NULL.
///
/// # Safety
/// `b` must have been produced by `lr_roa_table_builder_new` and not
/// already freed (or consumed by `_build`).
#[no_mangle]
pub unsafe extern "C" fn lr_roa_table_builder_free(b: lr_roa_table_builder_t) {
    guarded(
        || unsafe {
            drop(unbox_builder(b));
        },
        (),
    )
}

/// Add one ROA by parsed-prefix string (RFC 6482 §3.1). The prefix
/// string follows the standard `"a.b.c.d/len"` (v4) or
/// `"xxxx:yyyy::/len"` (v6) form. `max_length` is `0` to use the
/// exact prefix length, otherwise must be `>= prefix_len` and `<=`
/// the address family width (32 v4 / 128 v6).
///
/// Returns 0 on success, negative on error.
///
/// # Safety
/// `b` must be a valid builder handle. `prefix` must point to a
/// NUL-terminated UTF-8 string.
#[no_mangle]
pub unsafe extern "C" fn lr_roa_table_builder_add(
    b: lr_roa_table_builder_t,
    prefix: *const std::os::raw::c_char,
    max_length: u8,
    asn: u32,
) -> i32 {
    guarded(
        || unsafe {
            let Some(builder) = borrow_builder_mut(b) else {
                return LR_ERR_NULL;
            };
            if prefix.is_null() {
                return LR_ERR_NULL;
            }
            let s = match unsafe { std::ffi::CStr::from_ptr(prefix) }.to_str() {
                Ok(s) => s,
                Err(e) => {
                    set_last_error(format!("prefix is not valid UTF-8: {e}"));
                    return LrError::BadUtf8 as i32;
                }
            };
            let ml = if max_length == 0 {
                None
            } else {
                Some(max_length)
            };
            match builder.add(s, ml, asn) {
                Ok(_) => 0,
                Err(e) => {
                    set_last_error(e.to_string());
                    LrError::Other as i32
                }
            }
        },
        LR_ERR_PANIC,
    )
}

/// Add one already-parsed ROA entry (the same `lr_roa_entry_t` shape
/// `lr_roa_store_replace_static` consumes). Returns 0 on success,
/// `LR_ERR_NULL` on a NULL builder, `LR_ERR_OTHER` (-6) when the
/// entry fails the RFC 6482 invariants.
///
/// # Safety
/// `b` must be a valid builder handle. `entry` must point to a
/// readable `lr_roa_entry_t`.
#[no_mangle]
pub unsafe extern "C" fn lr_roa_table_builder_add_entry(
    b: lr_roa_table_builder_t,
    entry: lr_roa_entry_t,
) -> i32 {
    guarded(
        || unsafe {
            let Some(builder) = borrow_builder_mut(b) else {
                return LR_ERR_NULL;
            };
            match entry.parse() {
                Ok(parsed) => {
                    builder.add_entry(parsed);
                    0
                }
                Err(e) => {
                    set_last_error(e);
                    LrError::Other as i32
                }
            }
        },
        LR_ERR_PANIC,
    )
}

/// Finalize the builder into an immutable `RoaTable`. Entries are
/// deduplicated and sorted; the trie index is built once. The
/// builder handle is consumed and freed.
///
/// Returns a new `lr_roa_table_t` on success, NULL on a NULL
/// builder.
///
/// # Safety
/// `b` must be a valid builder handle and is invalid after this call.
#[no_mangle]
pub unsafe extern "C" fn lr_roa_table_builder_build(b: lr_roa_table_builder_t) -> lr_roa_table_t {
    guarded(
        || unsafe {
            let Some(builder) = unbox_builder(b) else {
                return std::ptr::null_mut();
            };
            box_table(builder.build())
        },
        std::ptr::null_mut(),
    )
}

/// Construct an empty `RoaTable` directly (no builder needed — use
/// `lr_roa_table_builder_add_entry` + `_build` to populate).
#[no_mangle]
pub extern "C" fn lr_roa_table_new() -> lr_roa_table_t {
    guarded(|| box_table(RoaTable::new()), std::ptr::null_mut())
}

/// Drop a boxed `RoaTable`. Safe to call with NULL.
///
/// # Safety
/// `t` must have been produced by a `lr_roa_table_*` constructor and
/// not already freed.
#[no_mangle]
pub unsafe extern "C" fn lr_roa_table_free(t: lr_roa_table_t) {
    guarded(
        || unsafe {
            drop(unbox_table(t));
        },
        (),
    )
}

/// Number of ROA entries in the table. Returns 0 on a NULL handle.
///
/// # Safety
/// `t` must be a valid RoaTable handle.
#[no_mangle]
pub unsafe extern "C" fn lr_roa_table_len(t: lr_roa_table_t) -> usize {
    guarded(
        || unsafe { borrow_table(t).map(|x| x.len()).unwrap_or(0) },
        0,
    )
}

/// True when the table holds no entries. Returns 1 (true) on a NULL
/// handle.
///
/// # Safety
/// See [`lr_roa_table_len`].
#[no_mangle]
pub unsafe extern "C" fn lr_roa_table_is_empty(t: lr_roa_table_t) -> u8 {
    guarded(
        || unsafe { borrow_table(t).map(|x| x.is_empty() as u8).unwrap_or(1) },
        1,
    )
}

/// Validate `(prefix, origin_as)` per RFC 6811 §2. `has_origin` is 0
/// to mean "no AS_PATH" (locally originated routes — returns
/// `NotFound`); otherwise `origin_as` carries the AS to validate
/// against.
///
/// Returns one of the `LR_ROA_*` constants (`LR_ROA_VALID` = 0,
/// `LR_ROA_NOT_FOUND` = 1, `LR_ROA_INVALID` = 2 — matching the
/// values already exported by `roa_store.rs`).
///
/// # Safety
/// `t` must be a valid RoaTable handle. `addr` must point to 4
/// (v4) or 16 (v6) readable bytes.
#[no_mangle]
pub unsafe extern "C" fn lr_roa_table_validate(
    t: lr_roa_table_t,
    addr: *const u8,
    is_ipv6: u8,
    prefix_len: u8,
    origin_as: u32,
    has_origin: u8,
) -> u8 {
    guarded(
        || unsafe {
            let Some(table) = borrow_table(t) else {
                // Mirror the not-found value the way the store does
                // on a NULL handle.
                return crate::roa_store::LR_ROA_NOT_FOUND;
            };
            if addr.is_null() {
                return crate::roa_store::LR_ROA_NOT_FOUND;
            }
            let prefix = if is_ipv6 == 0 {
                let mut o = [0u8; 4];
                unsafe { o.copy_from_slice(std::slice::from_raw_parts(addr, 4)) };
                Prefix::new_v4(o, prefix_len)
            } else {
                let mut o = [0u8; 16];
                unsafe { o.copy_from_slice(std::slice::from_raw_parts(addr, 16)) };
                Prefix::new_v6(o, prefix_len)
            };
            let origin = if has_origin == 0 {
                None
            } else {
                Some(Asn(origin_as))
            };
            match table.validate(&prefix, origin) {
                RoaState::Valid => crate::roa_store::LR_ROA_VALID,
                RoaState::NotFound => crate::roa_store::LR_ROA_NOT_FOUND,
                RoaState::Invalid => crate::roa_store::LR_ROA_INVALID,
            }
        },
        crate::roa_store::LR_ROA_NOT_FOUND,
    )
}

/// Read one ROA entry by index. Writes the entry's fields to the
/// out-pointers (`addr` carries v4 in the low 4 bytes when
/// `*out_is_ipv6 == 0`, all 16 bytes when `*out_is_ipv6 == 1`).
/// Returns 0 on success, `LR_ERR_NULL` on a NULL table,
/// `LR_ERR_INVALID_HANDLE` (-2) when the index is out of range.
///
/// # Safety
/// `t` must be a valid RoaTable handle. The out-pointers must point
/// to writable memory of the right type.
#[no_mangle]
pub unsafe extern "C" fn lr_roa_table_entry_at(
    t: lr_roa_table_t,
    index: usize,
    out_addr: *mut u8,
    out_is_ipv6: *mut u8,
    out_prefix_len: *mut u8,
    out_max_length: *mut u8,
    out_asn: *mut u32,
) -> i32 {
    guarded(
        || unsafe {
            let Some(table) = borrow_table(t) else {
                return LR_ERR_NULL;
            };
            if out_addr.is_null()
                || out_is_ipv6.is_null()
                || out_prefix_len.is_null()
                || out_max_length.is_null()
                || out_asn.is_null()
            {
                return LR_ERR_NULL;
            }
            let Some(entry) = table.entries().get(index) else {
                set_last_error(format!(
                    "roa_table entry {index} out of range (len={})",
                    table.len()
                ));
                return LrError::InvalidHandle as i32;
            };
            unsafe {
                match entry.prefix.addr {
                    lr_core::addr::IpAddr::V4(b) => {
                        std::ptr::copy_nonoverlapping(b.as_ptr(), out_addr, 4);
                        // Zero out the high 12 bytes so the caller
                        // does not see stale data.
                        std::ptr::write_bytes(out_addr.add(4), 0, 12);
                        *out_is_ipv6 = 0;
                    }
                    lr_core::addr::IpAddr::V6(b) => {
                        std::ptr::copy_nonoverlapping(b.as_ptr(), out_addr, 16);
                        *out_is_ipv6 = 1;
                    }
                }
                *out_prefix_len = entry.prefix.prefix_len;
                *out_max_length = entry.max_length;
                *out_asn = entry.asn.as_u32();
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
    fn ffi_roa_table_builder_add_and_validate() {
        let b = lr_roa_table_builder_new();
        assert!(!b.is_null());

        let prefix = std::ffi::CString::new("203.0.113.0/24").unwrap();
        let rc = unsafe { lr_roa_table_builder_add(b, prefix.as_ptr(), 0, 64512) };
        assert_eq!(rc, 0);

        let t = unsafe { lr_roa_table_builder_build(b) };
        assert!(!t.is_null());
        assert_eq!(unsafe { lr_roa_table_len(t) }, 1);

        // Validate the exact prefix with the right AS — Valid.
        let addr = [203u8, 0, 113, 0];
        let st = unsafe { lr_roa_table_validate(t, addr.as_ptr(), 0, 24, 64512, 1) };
        assert_eq!(st, crate::roa_store::LR_ROA_VALID);

        // Validate with a wrong AS — Invalid.
        let st = unsafe { lr_roa_table_validate(t, addr.as_ptr(), 0, 24, 64513, 1) };
        assert_eq!(st, crate::roa_store::LR_ROA_INVALID);

        // Validate a prefix that no ROA covers — NotFound.
        let other = [198u8, 51, 100, 0];
        let st = unsafe { lr_roa_table_validate(t, other.as_ptr(), 0, 24, 64512, 1) };
        assert_eq!(st, crate::roa_store::LR_ROA_NOT_FOUND);

        // has_origin=0 means no AS_PATH → NotFound.
        let st = unsafe { lr_roa_table_validate(t, addr.as_ptr(), 0, 24, 0, 0) };
        assert_eq!(st, crate::roa_store::LR_ROA_NOT_FOUND);

        unsafe { lr_roa_table_free(t) };
    }

    #[test]
    fn ffi_roa_table_builder_add_entry() {
        let b = lr_roa_table_builder_new();
        let entry = lr_roa_entry_t {
            addr: {
                let mut a = [0u8; 16];
                a[..4].copy_from_slice(&[203, 0, 113, 0]);
                a
            },
            is_ipv6: 0,
            prefix_len: 24,
            max_length: 24,
            asn: 64512,
        };
        let rc = unsafe { lr_roa_table_builder_add_entry(b, entry) };
        assert_eq!(rc, 0);
        let t = unsafe { lr_roa_table_builder_build(b) };
        assert_eq!(unsafe { lr_roa_table_len(t) }, 1);

        // Read the entry back.
        let mut addr = [0u8; 16];
        let mut is_v6 = 0u8;
        let mut plen = 0u8;
        let mut mlen = 0u8;
        let mut asn = 0u32;
        let rc = unsafe {
            lr_roa_table_entry_at(
                t,
                0,
                addr.as_mut_ptr(),
                &raw mut is_v6,
                &raw mut plen,
                &raw mut mlen,
                &raw mut asn,
            )
        };
        assert_eq!(rc, 0);
        assert_eq!(is_v6, 0);
        assert_eq!(&addr[..4], &[203, 0, 113, 0]);
        assert_eq!(plen, 24);
        assert_eq!(mlen, 24);
        assert_eq!(asn, 64512);

        unsafe { lr_roa_table_free(t) };
    }

    #[test]
    fn ffi_roa_table_builder_add_rejects_bad_prefix() {
        let b = lr_roa_table_builder_new();
        let bad = std::ffi::CString::new("not-a-prefix").unwrap();
        let rc = unsafe { lr_roa_table_builder_add(b, bad.as_ptr(), 0, 64512) };
        assert!(rc < 0);
        unsafe { lr_roa_table_builder_free(b) };
    }

    #[test]
    fn ffi_roa_table_builder_add_rejects_bad_max_length() {
        let b = lr_roa_table_builder_new();
        let prefix = std::ffi::CString::new("203.0.113.0/24").unwrap();
        // max_length=16 < prefix_len=24 — invalid per RFC 6482.
        let rc = unsafe { lr_roa_table_builder_add(b, prefix.as_ptr(), 16, 64512) };
        assert!(rc < 0);
        unsafe { lr_roa_table_builder_free(b) };
    }

    #[test]
    fn ffi_roa_table_empty() {
        let t = lr_roa_table_new();
        assert!(!t.is_null());
        assert_eq!(unsafe { lr_roa_table_len(t) }, 0);
        assert_eq!(unsafe { lr_roa_table_is_empty(t) }, 1);
        unsafe { lr_roa_table_free(t) };
    }

    #[test]
    fn ffi_roa_table_entry_at_returns_invalid_handle_on_oob() {
        let t = lr_roa_table_new();
        let mut addr = [0u8; 16];
        let mut is_v6 = 0u8;
        let mut plen = 0u8;
        let mut mlen = 0u8;
        let mut asn = 0u32;
        let rc = unsafe {
            lr_roa_table_entry_at(
                t,
                0,
                addr.as_mut_ptr(),
                &raw mut is_v6,
                &raw mut plen,
                &raw mut mlen,
                &raw mut asn,
            )
        };
        assert_eq!(rc, LrError::InvalidHandle as i32);
        unsafe { lr_roa_table_free(t) };
    }

    #[test]
    fn ffi_free_handles_null_safely() {
        unsafe {
            lr_roa_table_free(std::ptr::null_mut());
            lr_roa_table_builder_free(std::ptr::null_mut());
        }
    }

    #[test]
    fn ffi_roa_table_ipv6_round_trip() {
        let b = lr_roa_table_builder_new();
        let prefix = std::ffi::CString::new("2001:db8::/32").unwrap();
        let rc = unsafe { lr_roa_table_builder_add(b, prefix.as_ptr(), 48, 65001) };
        assert_eq!(rc, 0);
        let t = unsafe { lr_roa_table_builder_build(b) };
        assert_eq!(unsafe { lr_roa_table_len(t) }, 1);

        // Validate a /48 inside the /32 — Valid.
        let addr = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let st = unsafe { lr_roa_table_validate(t, addr.as_ptr(), 1, 48, 65001, 1) };
        assert_eq!(st, crate::roa_store::LR_ROA_VALID);

        // Validate a /64 — exceeds max_length 48 — Invalid.
        let st = unsafe { lr_roa_table_validate(t, addr.as_ptr(), 1, 64, 65001, 1) };
        assert_eq!(st, crate::roa_store::LR_ROA_INVALID);

        unsafe { lr_roa_table_free(t) };
    }
}
