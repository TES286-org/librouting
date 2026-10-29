//! lr-core gap closure — `WriteBuf` mutators, `ReadBuf::chunk`,
//! `RouteKey` / `Preference` constructors (issue #92).
//!
//! Mirrors the remaining public Rust API of:
//! - `lr_core::buf::{ReadBuf, WriteBuf}` (`patch`, `reserve`, `written`,
//!   `capacity`, `chunk`).
//! - `lr_core::rib::{RouteKey, Preference}` (typed constructors).
//!
//! All run inside the crate's `catch_unwind` barrier.

#![allow(unused_unsafe)]

use lr_core::addr::Prefix;
use lr_core::nlri::NlriFamily;
use lr_core::rib::{Preference, RouteKey};

use crate::core::{lr_core_prefix_t, lr_route_key_t};
use crate::core_buf::{
    borrow_read_buf_mut_pub, borrow_write_buf_mut_pub, lr_read_buf_t, lr_write_buf_t,
};
use crate::error::{set_last_error, LrError, LR_ERR_PANIC};
use crate::guarded;
use crate::handle::lr_bytes_t;

const LR_ERR_NULL: i32 = LrError::Null as i32;
const LR_ERR_OTHER: i32 = LrError::Other as i32;

// ---- WriteBuf mutators ----

/// Back-patch `len` bytes at offset `at` with `data`. The WriteBuf
/// must already contain at least `at + len` bytes (write ahead, patch
/// behind — the standard pattern for back-filling a length field after
/// the body is encoded). Returns 0 on success, `LR_ERR_NULL` on a
/// NULL handle / pointer, `LR_ERR_OTHER` when `at + len` overflows the
/// written-so-far range.
///
/// # Safety
/// `w` must be a live handle. `data` must point to `len` readable bytes.
#[no_mangle]
pub unsafe extern "C" fn lr_write_buf_patch(
    w: lr_write_buf_t,
    at: usize,
    data: *const u8,
    len: usize,
) -> i32 {
    guarded(
        || unsafe {
            let Some(s) = borrow_write_buf_mut_pub(w) else {
                return LR_ERR_NULL;
            };
            if data.is_null() && len != 0 {
                return LR_ERR_NULL;
            }
            let slice = if len == 0 {
                &[][..]
            } else {
                unsafe { std::slice::from_raw_parts(data, len) }
            };
            if s.patch(at, slice).is_err() {
                set_last_error(format!(
                    "WriteBuf::patch out-of-range: at={}, len={}, written={}",
                    at,
                    len,
                    s.written_slice().len()
                ));
                return LR_ERR_OTHER;
            }
            0
        },
        LR_ERR_PANIC,
    )
}

/// Reserve at least `additional` more bytes of capacity. On the
/// growable FFI buffer this is a no-op when capacity already exceeds
/// the request; otherwise it triggers a Vec reallocation. Returns 0 on
/// success, `LR_ERR_NULL` on a NULL handle.
///
/// # Safety
/// `w` must be a live handle.
#[no_mangle]
pub unsafe extern "C" fn lr_write_buf_reserve(w: lr_write_buf_t, additional: usize) -> i32 {
    guarded(
        || unsafe {
            let Some(s) = borrow_write_buf_mut_pub(w) else {
                return LR_ERR_NULL;
            };
            s.buf.reserve(additional);
            0
        },
        LR_ERR_PANIC,
    )
}

/// Total capacity (allocated bytes; may grow). Returns 0 on a NULL
/// handle.
///
/// # Safety
/// `w` must be a live handle.
#[no_mangle]
pub unsafe extern "C" fn lr_write_buf_capacity(w: lr_write_buf_t) -> usize {
    guarded(
        || unsafe {
            borrow_write_buf_mut_pub(w)
                .map(|s| s.buf.capacity())
                .unwrap_or(0)
        },
        0,
    )
}

/// Take the bytes written so far as a freshly-allocated
/// `lr_bytes_t` WITHOUT resetting the buffer (a snapshot). Use
/// [`lr_write_buf_take_bytes`] for the consuming variant.
///
/// # Safety
/// `w` must be a live handle. `out` must point to a writable
/// `lr_bytes_t`.
#[no_mangle]
pub unsafe extern "C" fn lr_write_buf_written(w: lr_write_buf_t, out: *mut lr_bytes_t) -> i32 {
    guarded(
        || unsafe {
            let Some(s) = borrow_write_buf_mut_pub(w) else {
                return LR_ERR_NULL;
            };
            if out.is_null() {
                return LR_ERR_NULL;
            }
            unsafe { *out = lr_bytes_t::from_vec(s.written_slice().to_vec()) }
            0
        },
        LR_ERR_PANIC,
    )
}

// ---- ReadBuf::chunk ----

/// Borrow the remaining bytes as a freshly-allocated `lr_bytes_t`
/// snapshot (does not advance the position). Returns 0 on success,
/// `LR_ERR_NULL` on a NULL handle / pointer.
///
/// # Safety
/// `r` must be a live handle. `out` must point to a writable
/// `lr_bytes_t`.
#[no_mangle]
pub unsafe extern "C" fn lr_read_buf_chunk(r: lr_read_buf_t, out: *mut lr_bytes_t) -> i32 {
    guarded(
        || unsafe {
            let Some(s) = borrow_read_buf_mut_pub(r) else {
                return LR_ERR_NULL;
            };
            if out.is_null() {
                return LR_ERR_NULL;
            }
            let bytes = s.remaining_slice().to_vec();
            unsafe { *out = lr_bytes_t::from_vec(bytes) }
            0
        },
        LR_ERR_PANIC,
    )
}

// ---- RouteKey / Preference constructors ----

/// AFI/SAFI pack helper — `afi << 8 | safi` matches the
/// `lr_route_key_t::afi_safi` field's documented layout.
fn pack_afi_safi(f: NlriFamily) -> u16 {
    (f.afi << 8) | (f.safi as u16)
}

/// AFI/SAFI unpack helper — inverse of [`pack_afi_safi`].
fn unpack_afi_safi(packed: u16) -> NlriFamily {
    NlriFamily {
        afi: packed >> 8,
        safi: (packed & 0xff) as u8,
    }
}

/// Construct a `RouteKey` from a prefix + AFI/SAFI packed as
/// `afi << 8 | safi`. Writes the result to `*out`.
///
/// # Safety
/// `out` must point to a writable `lr_route_key_t`.
#[no_mangle]
pub unsafe extern "C" fn lr_route_key_new(
    prefix: lr_core_prefix_t,
    afi_safi: u16,
    out: *mut lr_route_key_t,
) -> i32 {
    guarded(
        || unsafe {
            if out.is_null() {
                return LR_ERR_NULL;
            }
            let p: Prefix = prefix.into();
            let key = RouteKey::new(p, unpack_afi_safi(afi_safi));
            unsafe {
                *out = route_key_to_c(&key);
            }
            0
        },
        LR_ERR_PANIC,
    )
}

/// Construct a `RouteKey` with an explicit source prefix (RFC 8966
/// §3.1 source-specific routing). Writes the result to `*out`.
///
/// # Safety
/// `out` must point to a writable `lr_route_key_t`.
#[no_mangle]
pub unsafe extern "C" fn lr_route_key_with_source(
    prefix: lr_core_prefix_t,
    afi_safi: u16,
    source: lr_core_prefix_t,
    out: *mut lr_route_key_t,
) -> i32 {
    guarded(
        || unsafe {
            if out.is_null() {
                return LR_ERR_NULL;
            }
            let p: Prefix = prefix.into();
            let s: Prefix = source.into();
            let key = RouteKey::with_source(p, unpack_afi_safi(afi_safi), s);
            unsafe {
                *out = route_key_to_c(&key);
            }
            0
        },
        LR_ERR_PANIC,
    )
}

/// Construct a `Preference` (admin_distance + metric). Returns the
/// value by value (a 64-bit repr-C struct — small enough to return in
/// registers on most ABIs).
#[no_mangle]
pub extern "C" fn lr_preference_new(admin_distance: u32, metric: u32) -> lr_preference_t {
    guarded(
        || {
            let p = Preference::new(admin_distance, metric);
            lr_preference_t {
                admin_distance: p.admin_distance,
                metric: p.metric,
            }
        },
        lr_preference_t::default(),
    )
}

/// Repr-C `Preference` mirror.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct lr_preference_t {
    pub admin_distance: u32,
    pub metric: u32,
}

// ---- helpers ----

fn route_key_to_c(k: &RouteKey) -> lr_route_key_t {
    let source_prefix = k
        .source
        .map_or_else(lr_core_prefix_t::default, |s| s.into());
    lr_route_key_t {
        prefix: k.prefix.into(),
        afi_safi: pack_afi_safi(k.family),
        has_source: k.source.is_some() as u8,
        source_prefix,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::lr_ip_addr_t;
    use crate::core_buf::{
        lr_read_buf_free, lr_read_buf_new, lr_write_buf_free, lr_write_buf_new,
        lr_write_buf_position, lr_write_buf_put_u16_be, lr_write_buf_put_u8,
    };

    unsafe fn bytes_to_vec(b: &mut lr_bytes_t) -> Vec<u8> {
        if b.ptr.is_null() {
            return Vec::new();
        }
        let v = unsafe { Vec::from_raw_parts(b.ptr, b.len, b.cap) };
        b.ptr = std::ptr::null_mut();
        b.len = 0;
        b.cap = 0;
        v
    }

    fn v4_prefix(addr: [u8; 4], len: u8) -> lr_core_prefix_t {
        let mut octets = [0u8; 16];
        octets[12..16].copy_from_slice(&addr);
        lr_core_prefix_t {
            addr: lr_ip_addr_t { is_ipv6: 0, octets },
            prefix_len: len,
        }
    }

    #[test]
    fn ffi_write_buf_patch_backfills_length() {
        // Write 3 placeholder bytes, then patch the first 2 bytes
        // with a real length value.
        let w = lr_write_buf_new(8);
        assert_eq!(unsafe { lr_write_buf_put_u16_be(w, 0) }, 0); // placeholder
        assert_eq!(unsafe { lr_write_buf_put_u8(w, 0xAB) }, 0); // body
        assert_eq!(unsafe { lr_write_buf_position(w) }, 3);

        let patch = [0x00u8, 0x01];
        let rc = unsafe { lr_write_buf_patch(w, 0, patch.as_ptr(), 2) };
        assert_eq!(rc, 0);

        let mut out = lr_bytes_t {
            ptr: std::ptr::null_mut(),
            len: 0,
            cap: 0,
        };
        let rc = unsafe { lr_write_buf_written(w, &raw mut out) };
        assert_eq!(rc, 0);
        let bytes = unsafe { bytes_to_vec(&mut out) };
        assert_eq!(bytes, vec![0x00, 0x01, 0xAB]);

        unsafe { lr_write_buf_free(w) };
    }

    #[test]
    fn ffi_write_buf_patch_rejects_out_of_range() {
        let w = lr_write_buf_new(8);
        let patch = [0u8; 4];
        // Buffer is empty; patching at offset 0 with len 4 must fail.
        let rc = unsafe { lr_write_buf_patch(w, 0, patch.as_ptr(), 4) };
        assert_eq!(rc, LR_ERR_OTHER);
        unsafe { lr_write_buf_free(w) };
    }

    #[test]
    fn ffi_write_buf_patch_rejects_null() {
        let w = lr_write_buf_new(8);
        let rc = unsafe { lr_write_buf_patch(w, 0, std::ptr::null(), 4) };
        assert_eq!(rc, LR_ERR_NULL);
        let rc = unsafe { lr_write_buf_patch(std::ptr::null_mut(), 0, std::ptr::null(), 0) };
        assert_eq!(rc, LR_ERR_NULL);
        unsafe { lr_write_buf_free(w) };
    }

    #[test]
    fn ffi_write_buf_reserve_grows_capacity() {
        let w = lr_write_buf_new(4);
        let initial_cap = unsafe { lr_write_buf_capacity(w) };
        assert_eq!(initial_cap, 4);
        let rc = unsafe { lr_write_buf_reserve(w, 1024) };
        assert_eq!(rc, 0);
        let grown_cap = unsafe { lr_write_buf_capacity(w) };
        assert!(grown_cap >= 1024, "capacity {grown_cap} should be >= 1024");
        unsafe { lr_write_buf_free(w) };
    }

    #[test]
    fn ffi_write_buf_written_snapshots_without_reset() {
        let w = lr_write_buf_new(8);
        unsafe { lr_write_buf_put_u8(w, 0xAB) };
        unsafe { lr_write_buf_put_u8(w, 0xCD) };

        let mut out = lr_bytes_t {
            ptr: std::ptr::null_mut(),
            len: 0,
            cap: 0,
        };
        let rc = unsafe { lr_write_buf_written(w, &raw mut out) };
        assert_eq!(rc, 0);
        let bytes = unsafe { bytes_to_vec(&mut out) };
        assert_eq!(bytes, vec![0xAB, 0xCD]);

        // Position is unchanged — buffer still writable.
        assert_eq!(unsafe { lr_write_buf_position(w) }, 2);
        unsafe { lr_write_buf_put_u8(w, 0xEF) };
        assert_eq!(unsafe { lr_write_buf_position(w) }, 3);

        unsafe { lr_write_buf_free(w) };
    }

    #[test]
    fn ffi_read_buf_chunk_does_not_advance() {
        let data: [u8; 4] = [1, 2, 3, 4];
        let r = unsafe { lr_read_buf_new(data.as_ptr(), data.len()) };

        let mut out = lr_bytes_t {
            ptr: std::ptr::null_mut(),
            len: 0,
            cap: 0,
        };
        let rc = unsafe { lr_read_buf_chunk(r, &raw mut out) };
        assert_eq!(rc, 0);
        let bytes = unsafe { bytes_to_vec(&mut out) };
        assert_eq!(bytes, vec![1, 2, 3, 4]);
        assert_eq!(unsafe { crate::core_buf::lr_read_buf_position(r) }, 0);

        unsafe { lr_read_buf_free(r) };
    }

    #[test]
    fn ffi_route_key_new_v4() {
        let prefix = v4_prefix([10, 0, 0, 0], 24);
        let mut key = lr_route_key_t::default();
        let rc = unsafe { lr_route_key_new(prefix, 0x0101, &raw mut key) };
        assert_eq!(rc, 0);
        assert_eq!(key.afi_safi, 0x0101);
        assert_eq!(key.has_source, 0);
    }

    #[test]
    fn ffi_route_key_with_source_v4() {
        let prefix = v4_prefix([10, 0, 0, 0], 24);
        let source = v4_prefix([192, 168, 1, 0], 24);
        let mut key = lr_route_key_t::default();
        let rc = unsafe { lr_route_key_with_source(prefix, 0x0101, source, &raw mut key) };
        assert_eq!(rc, 0);
        assert_eq!(key.afi_safi, 0x0101);
        assert_eq!(key.has_source, 1);
    }

    #[test]
    fn ffi_route_key_new_rejects_null() {
        let prefix = v4_prefix([10, 0, 0, 0], 24);
        let rc = unsafe { lr_route_key_new(prefix, 0x0101, std::ptr::null_mut()) };
        assert_eq!(rc, LR_ERR_NULL);
    }

    #[test]
    fn ffi_preference_new_carries_values() {
        let p = lr_preference_new(20, 100);
        assert_eq!(p.admin_distance, 20);
        assert_eq!(p.metric, 100);
    }
}
