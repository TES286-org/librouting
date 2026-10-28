//! `lr_core::buf::{ReadBuf, WriteBuf}` FFI — `lr_read_buf_*` / `lr_write_buf_*`.
//!
//! Mirrors the public Rust API of `lr_core::buf::{ReadBuf, WriteBuf}` so
//! an embedder can build / parse wire forms using the same primitives
//! the protocol codecs use internally, without re-implementing
//! big-endian integer encoding or position tracking in C.
//!
//! The Rust types are slice-borrowing views with a lifetime
//! parameter; the FFI surface owns the underlying buffer so the
//! handle is `'static`-shaped and matches the rest of the C ABI's
//! ownership model:
//!
//! - `lr_read_buf_new` allocates a fresh `Vec<u8>`-backed buffer
//!   populated with the caller's bytes and wraps it in a
//!   `ReadBuf`-equivalent opaque handle.
//! - `lr_write_buf_new` allocates an empty `Vec<u8>` of capacity
//!   `cap` and wraps it in a `WriteBuf`-equivalent opaque handle.
//!
//! Every entry point runs inside the crate's `catch_unwind` barrier.

#![allow(unused_unsafe)]

use lr_core::buf::ReadBuf;

use crate::error::{set_last_error, LrError, LR_ERR_PANIC};
use crate::guarded;
use crate::handle::lr_bytes_t;

const LR_ERR_NULL: i32 = LrError::Null as i32;
const LR_ERR_OTHER: i32 = LrError::Other as i32;

/// Opaque owned `ReadBuf` handle. The underlying buffer is owned by
/// the handle so the lifetime is `'static` from the C side.
#[repr(C)]
pub struct OpaqueReadBuf {
    _private: [u8; 0],
}
pub type lr_read_buf_t = *mut OpaqueReadBuf;

/// Internal storage: an owned byte buffer + a `ReadBuf` view over
/// it. The `ReadBuf` borrows from the buffer for the lifetime of
/// the storage, which is `'static` from the FFI's perspective because
/// the box pins both.
struct ReadBufStorage {
    buf: Vec<u8>,
    pos: usize,
}

impl ReadBufStorage {
    fn new(buf: Vec<u8>) -> Self {
        Self { buf, pos: 0 }
    }

    fn as_read_buf(&mut self) -> ReadBuf<'_> {
        ReadBuf::new(&self.buf[self.pos..])
    }
}

fn box_read_buf(r: ReadBufStorage) -> lr_read_buf_t {
    Box::into_raw(Box::new(r)) as lr_read_buf_t
}
unsafe fn borrow_read_buf_mut(r: lr_read_buf_t) -> Option<&'static mut ReadBufStorage> {
    if r.is_null() {
        return None;
    }
    Some(unsafe { &mut *(r as *mut ReadBufStorage) })
}
unsafe fn unbox_read_buf(r: lr_read_buf_t) -> Option<Box<ReadBufStorage>> {
    if r.is_null() {
        return None;
    }
    Some(unsafe { Box::from_raw(r as *mut ReadBufStorage) })
}

/// Opaque owned `WriteBuf` handle.
#[repr(C)]
pub struct OpaqueWriteBuf {
    _private: [u8; 0],
}
pub type lr_write_buf_t = *mut OpaqueWriteBuf;

/// Internal storage: an owned growable `Vec<u8>`. The `WriteBuf` Rust
/// type borrows a `&mut [u8]` slice; the FFI surface grows the Vec
/// on demand so callers do not need to pre-size the buffer.
struct WriteBufStorage {
    buf: Vec<u8>,
}

impl WriteBufStorage {
    fn new(cap: usize) -> Self {
        Self {
            buf: Vec::with_capacity(cap),
        }
    }

    /// Push `b` to the end of the buffer.
    fn put_bytes(&mut self, b: &[u8]) -> Option<()> {
        self.buf.extend_from_slice(b);
        Some(())
    }

    fn put_u8(&mut self, v: u8) -> Option<()> {
        self.buf.push(v);
        Some(())
    }

    fn put_u16_be(&mut self, v: u16) -> Option<()> {
        self.buf.extend_from_slice(&v.to_be_bytes());
        Some(())
    }

    fn put_u32_be(&mut self, v: u32) -> Option<()> {
        self.buf.extend_from_slice(&v.to_be_bytes());
        Some(())
    }

    fn put_u64_be(&mut self, v: u64) -> Option<()> {
        self.buf.extend_from_slice(&v.to_be_bytes());
        Some(())
    }
}

fn box_write_buf(w: WriteBufStorage) -> lr_write_buf_t {
    Box::into_raw(Box::new(w)) as lr_write_buf_t
}
unsafe fn borrow_write_buf_mut(w: lr_write_buf_t) -> Option<&'static mut WriteBufStorage> {
    if w.is_null() {
        return None;
    }
    Some(unsafe { &mut *(w as *mut WriteBufStorage) })
}
unsafe fn unbox_write_buf(w: lr_write_buf_t) -> Option<Box<WriteBufStorage>> {
    if w.is_null() {
        return None;
    }
    Some(unsafe { Box::from_raw(w as *mut WriteBufStorage) })
}

// ---- ReadBuf surface ----

/// Construct a `ReadBuf` from `data` (a copy is made). Returns NULL
/// on a NULL pointer or panic.
///
/// # Safety
/// `data` must point to `len` readable bytes (NULL only when
/// `len == 0`).
#[no_mangle]
pub unsafe extern "C" fn lr_read_buf_new(data: *const u8, len: usize) -> lr_read_buf_t {
    guarded(
        || unsafe {
            let buf = if data.is_null() || len == 0 {
                Vec::new()
            } else {
                unsafe { std::slice::from_raw_parts(data, len).to_vec() }
            };
            box_read_buf(ReadBufStorage::new(buf))
        },
        std::ptr::null_mut(),
    )
}

/// Drop a boxed `ReadBuf`. Safe to call with NULL.
///
/// # Safety
/// `r` must have been produced by [`lr_read_buf_new`] and must not
/// be used after this call.
#[no_mangle]
pub unsafe extern "C" fn lr_read_buf_free(r: lr_read_buf_t) {
    guarded(
        || unsafe {
            drop(unbox_read_buf(r));
        },
        (),
    )
}

/// Number of bytes remaining in the buffer at the current position.
///
/// # Safety
/// `r` must be a live handle.
#[no_mangle]
pub unsafe extern "C" fn lr_read_buf_remaining(r: lr_read_buf_t) -> usize {
    guarded(
        || unsafe {
            borrow_read_buf_mut(r)
                .map(|s| s.buf.len() - s.pos)
                .unwrap_or(0)
        },
        0,
    )
}

/// Current read position.
///
/// # Safety
/// See [`lr_read_buf_remaining`].
#[no_mangle]
pub unsafe extern "C" fn lr_read_buf_position(r: lr_read_buf_t) -> usize {
    guarded(
        || unsafe { borrow_read_buf_mut(r).map(|s| s.pos).unwrap_or(0) },
        0,
    )
}

/// Advance the read position by `n` bytes. Returns 0 on success,
/// `LR_ERR_NULL` on a NULL handle, `LR_ERR_OTHER` on overflow.
///
/// # Safety
/// `r` must be a live handle.
#[no_mangle]
pub unsafe extern "C" fn lr_read_buf_advance(r: lr_read_buf_t, n: usize) -> i32 {
    guarded(
        || unsafe {
            let Some(s) = borrow_read_buf_mut(r) else {
                return LR_ERR_NULL;
            };
            if s.pos + n > s.buf.len() {
                set_last_error(format!(
                    "ReadBuf advance overflow: pos={}, advance={}, len={}",
                    s.pos,
                    n,
                    s.buf.len()
                ));
                return LR_ERR_OTHER;
            }
            s.pos += n;
            0
        },
        LR_ERR_PANIC,
    )
}

/// Peek the next byte without advancing the position. Returns 0 on
/// success and writes the byte to `*out`, 1 when the buffer is
/// empty, `LR_ERR_NULL` on a NULL handle.
///
/// # Safety
/// `r` must be a live handle. `out` must point to a writable `uint8_t`.
#[no_mangle]
pub unsafe extern "C" fn lr_read_buf_peek_u8(r: lr_read_buf_t, out: *mut u8) -> i32 {
    guarded(
        || unsafe {
            let Some(s) = borrow_read_buf_mut(r) else {
                return LR_ERR_NULL;
            };
            if out.is_null() {
                return LR_ERR_NULL;
            }
            match s.as_read_buf().peek_u8() {
                Some(v) => {
                    unsafe { *out = v }
                    0
                }
                None => 1,
            }
        },
        LR_ERR_PANIC,
    )
}

/// Read the next byte and advance the position. Returns 0 on success
/// and writes the byte to `*out`, 1 when the buffer is empty,
/// `LR_ERR_NULL` on a NULL handle.
///
/// # Safety
/// See [`lr_read_buf_peek_u8`].
#[no_mangle]
pub unsafe extern "C" fn lr_read_buf_get_u8(r: lr_read_buf_t, out: *mut u8) -> i32 {
    guarded(
        || unsafe {
            let Some(s) = borrow_read_buf_mut(r) else {
                return LR_ERR_NULL;
            };
            if out.is_null() {
                return LR_ERR_NULL;
            }
            match s.as_read_buf().get_u8() {
                Some(v) => {
                    s.pos += 1;
                    unsafe { *out = v }
                    0
                }
                None => 1,
            }
        },
        LR_ERR_PANIC,
    )
}

/// Read the next 2 bytes big-endian and advance by 2. Returns 0 on
/// success, 1 when the buffer is too short, `LR_ERR_NULL` on a NULL
/// handle.
///
/// # Safety
/// `r` must be a live handle. `out` must point to a writable `uint16_t`.
#[no_mangle]
pub unsafe extern "C" fn lr_read_buf_get_u16_be(r: lr_read_buf_t, out: *mut u16) -> i32 {
    guarded(
        || unsafe {
            let Some(s) = borrow_read_buf_mut(r) else {
                return LR_ERR_NULL;
            };
            if out.is_null() {
                return LR_ERR_NULL;
            }
            match s.as_read_buf().get_u16_be() {
                Some(v) => {
                    s.pos += 2;
                    unsafe { *out = v }
                    0
                }
                None => 1,
            }
        },
        LR_ERR_PANIC,
    )
}

/// Read the next 4 bytes big-endian and advance by 4.
///
/// # Safety
/// `r` must be a live handle. `out` must point to a writable `uint32_t`.
#[no_mangle]
pub unsafe extern "C" fn lr_read_buf_get_u32_be(r: lr_read_buf_t, out: *mut u32) -> i32 {
    guarded(
        || unsafe {
            let Some(s) = borrow_read_buf_mut(r) else {
                return LR_ERR_NULL;
            };
            if out.is_null() {
                return LR_ERR_NULL;
            }
            match s.as_read_buf().get_u32_be() {
                Some(v) => {
                    s.pos += 4;
                    unsafe { *out = v }
                    0
                }
                None => 1,
            }
        },
        LR_ERR_PANIC,
    )
}

/// Read the next 8 bytes big-endian and advance by 8.
///
/// # Safety
/// `r` must be a live handle. `out` must point to a writable `uint64_t`.
#[no_mangle]
pub unsafe extern "C" fn lr_read_buf_get_u64_be(r: lr_read_buf_t, out: *mut u64) -> i32 {
    guarded(
        || unsafe {
            let Some(s) = borrow_read_buf_mut(r) else {
                return LR_ERR_NULL;
            };
            if out.is_null() {
                return LR_ERR_NULL;
            }
            match s.as_read_buf().get_u64_be() {
                Some(v) => {
                    s.pos += 8;
                    unsafe { *out = v }
                    0
                }
                None => 1,
            }
        },
        LR_ERR_PANIC,
    )
}

/// Read `n` bytes and write them to a freshly-allocated `lr_bytes_t`.
/// Returns 0 on success, 1 when the buffer is too short, `LR_ERR_NULL`
/// on a NULL handle.
///
/// # Safety
/// `r` must be a live handle. `out` must point to a writable `lr_bytes_t`.
#[no_mangle]
pub unsafe extern "C" fn lr_read_buf_get_bytes(
    r: lr_read_buf_t,
    n: usize,
    out: *mut lr_bytes_t,
) -> i32 {
    guarded(
        || unsafe {
            let Some(s) = borrow_read_buf_mut(r) else {
                return LR_ERR_NULL;
            };
            if out.is_null() {
                return LR_ERR_NULL;
            }
            if s.pos + n > s.buf.len() {
                return 1;
            }
            let bytes = s.buf[s.pos..s.pos + n].to_vec();
            s.pos += n;
            unsafe { *out = lr_bytes_t::from_vec(bytes) }
            0
        },
        LR_ERR_PANIC,
    )
}

// ---- WriteBuf surface ----

/// Construct an empty `WriteBuf` with capacity `cap`.
#[no_mangle]
pub extern "C" fn lr_write_buf_new(cap: usize) -> lr_write_buf_t {
    guarded(
        || box_write_buf(WriteBufStorage::new(cap)),
        std::ptr::null_mut(),
    )
}

/// Drop a boxed `WriteBuf`. Safe to call with NULL.
///
/// # Safety
/// `w` must have been produced by [`lr_write_buf_new`] and must not
/// be used after this call.
#[no_mangle]
pub unsafe extern "C" fn lr_write_buf_free(w: lr_write_buf_t) {
    guarded(
        || unsafe {
            drop(unbox_write_buf(w));
        },
        (),
    )
}

/// Current write position (= number of bytes written so far).
///
/// # Safety
/// `w` must be a live handle.
#[no_mangle]
pub unsafe extern "C" fn lr_write_buf_position(w: lr_write_buf_t) -> usize {
    guarded(
        || unsafe { borrow_write_buf_mut(w).map(|s| s.buf.len()).unwrap_or(0) },
        0,
    )
}

/// Remaining capacity (= `cap - position`). On a growable buffer this
/// is the headroom before a reallocation; the embedder should treat
/// it as advisory.
///
/// # Safety
/// See [`lr_write_buf_position`].
#[no_mangle]
pub unsafe extern "C" fn lr_write_buf_remaining_mut(w: lr_write_buf_t) -> usize {
    guarded(
        || unsafe {
            borrow_write_buf_mut(w)
                .map(|s| s.buf.capacity().saturating_sub(s.buf.len()))
                .unwrap_or(0)
        },
        0,
    )
}

/// Push one byte. Returns 0 on success, `LR_ERR_NULL` on a NULL handle.
///
/// # Safety
/// `w` must be a live handle.
#[no_mangle]
pub unsafe extern "C" fn lr_write_buf_put_u8(w: lr_write_buf_t, v: u8) -> i32 {
    guarded(
        || unsafe {
            let Some(s) = borrow_write_buf_mut(w) else {
                return LR_ERR_NULL;
            };
            s.put_u8(v);
            0
        },
        LR_ERR_PANIC,
    )
}

/// Push `b` bytes. Returns 0 on success, `LR_ERR_NULL` on a NULL
/// handle or pointer.
///
/// # Safety
/// `w` must be a live handle. `b` must point to `len` readable bytes
/// (NULL only when `len == 0`).
#[no_mangle]
pub unsafe extern "C" fn lr_write_buf_put_bytes(
    w: lr_write_buf_t,
    b: *const u8,
    len: usize,
) -> i32 {
    guarded(
        || unsafe {
            let Some(s) = borrow_write_buf_mut(w) else {
                return LR_ERR_NULL;
            };
            if b.is_null() && len != 0 {
                return LR_ERR_NULL;
            }
            let slice = if len == 0 {
                &[]
            } else {
                unsafe { std::slice::from_raw_parts(b, len) }
            };
            s.put_bytes(slice);
            0
        },
        LR_ERR_PANIC,
    )
}

/// Push a 2-byte big-endian value.
///
/// # Safety
/// See [`lr_write_buf_put_u8`].
#[no_mangle]
pub unsafe extern "C" fn lr_write_buf_put_u16_be(w: lr_write_buf_t, v: u16) -> i32 {
    guarded(
        || unsafe {
            let Some(s) = borrow_write_buf_mut(w) else {
                return LR_ERR_NULL;
            };
            s.put_u16_be(v);
            0
        },
        LR_ERR_PANIC,
    )
}

/// Push a 4-byte big-endian value.
///
/// # Safety
/// See [`lr_write_buf_put_u8`].
#[no_mangle]
pub unsafe extern "C" fn lr_write_buf_put_u32_be(w: lr_write_buf_t, v: u32) -> i32 {
    guarded(
        || unsafe {
            let Some(s) = borrow_write_buf_mut(w) else {
                return LR_ERR_NULL;
            };
            s.put_u32_be(v);
            0
        },
        LR_ERR_PANIC,
    )
}

/// Push an 8-byte big-endian value.
///
/// # Safety
/// See [`lr_write_buf_put_u8`].
#[no_mangle]
pub unsafe extern "C" fn lr_write_buf_put_u64_be(w: lr_write_buf_t, v: u64) -> i32 {
    guarded(
        || unsafe {
            let Some(s) = borrow_write_buf_mut(w) else {
                return LR_ERR_NULL;
            };
            s.put_u64_be(v);
            0
        },
        LR_ERR_PANIC,
    )
}

/// Take the written bytes out of the buffer as a freshly-allocated
/// `lr_bytes_t`. The WriteBuf is reset to empty after this call.
///
/// # Safety
/// `w` must be a live handle. `out` must point to a writable `lr_bytes_t`.
#[no_mangle]
pub unsafe extern "C" fn lr_write_buf_take_bytes(w: lr_write_buf_t, out: *mut lr_bytes_t) -> i32 {
    guarded(
        || unsafe {
            let Some(s) = borrow_write_buf_mut(w) else {
                return LR_ERR_NULL;
            };
            if out.is_null() {
                return LR_ERR_NULL;
            }
            let bytes = core::mem::take(&mut s.buf);
            unsafe { *out = lr_bytes_t::from_vec(bytes) }
            0
        },
        LR_ERR_PANIC,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

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

    #[test]
    fn ffi_read_buf_get_ints_be_correct() {
        let data: [u8; 15] = [
            0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66,
            0x77,
        ];
        let r = unsafe { lr_read_buf_new(data.as_ptr(), data.len()) };
        assert!(!r.is_null());

        let mut v8 = 0u8;
        let mut v16 = 0u16;
        let mut v32 = 0u32;
        let mut v64 = 0u64;

        assert_eq!(unsafe { lr_read_buf_get_u8(r, &raw mut v8) }, 0);
        assert_eq!(v8, 0x12);
        assert_eq!(unsafe { lr_read_buf_get_u16_be(r, &raw mut v16) }, 0);
        assert_eq!(v16, 0x3456);
        assert_eq!(unsafe { lr_read_buf_get_u32_be(r, &raw mut v32) }, 0);
        assert_eq!(v32, 0x789abcde);
        assert_eq!(unsafe { lr_read_buf_get_u64_be(r, &raw mut v64) }, 0);
        assert_eq!(v64, 0xf011223344556677_u64);

        // Position is now 15, buffer is empty.
        assert_eq!(unsafe { lr_read_buf_remaining(r) }, 0);
        assert_eq!(unsafe { lr_read_buf_position(r) }, 15);

        unsafe { lr_read_buf_free(r) };
    }

    #[test]
    fn ffi_read_buf_get_returns_one_when_empty() {
        let r = unsafe { lr_read_buf_new(std::ptr::null(), 0) };
        let mut v = 0u8;
        assert_eq!(unsafe { lr_read_buf_get_u8(r, &raw mut v) }, 1);
        unsafe { lr_read_buf_free(r) };
    }

    #[test]
    fn ffi_read_buf_peek_does_not_advance() {
        let data: [u8; 2] = [0xab, 0xcd];
        let r = unsafe { lr_read_buf_new(data.as_ptr(), data.len()) };
        let mut v = 0u8;
        assert_eq!(unsafe { lr_read_buf_peek_u8(r, &raw mut v) }, 0);
        assert_eq!(v, 0xab);
        assert_eq!(unsafe { lr_read_buf_position(r) }, 0);
        assert_eq!(unsafe { lr_read_buf_get_u8(r, &raw mut v) }, 0);
        assert_eq!(v, 0xab);
        assert_eq!(unsafe { lr_read_buf_position(r) }, 1);
        unsafe { lr_read_buf_free(r) };
    }

    #[test]
    fn ffi_read_buf_get_bytes() {
        let data: [u8; 4] = [1, 2, 3, 4];
        let r = unsafe { lr_read_buf_new(data.as_ptr(), data.len()) };
        let mut out = lr_bytes_t {
            ptr: std::ptr::null_mut(),
            len: 0,
            cap: 0,
        };
        let rc = unsafe { lr_read_buf_get_bytes(r, 2, &raw mut out) };
        assert_eq!(rc, 0);
        let bytes = unsafe { bytes_to_vec(&mut out) };
        assert_eq!(bytes, vec![1, 2]);
        assert_eq!(unsafe { lr_read_buf_position(r) }, 2);

        // Try to read 5 bytes — only 2 remain.
        let rc = unsafe { lr_read_buf_get_bytes(r, 5, &raw mut out) };
        assert_eq!(rc, 1);
        unsafe { lr_read_buf_free(r) };
    }

    #[test]
    fn ffi_write_buf_put_ints_be_and_take() {
        let w = lr_write_buf_new(64);
        assert_eq!(unsafe { lr_write_buf_put_u8(w, 0x12) }, 0);
        assert_eq!(unsafe { lr_write_buf_put_u16_be(w, 0x3456) }, 0);
        assert_eq!(unsafe { lr_write_buf_put_u32_be(w, 0x789abcde) }, 0);
        assert_eq!(unsafe { lr_write_buf_put_u64_be(w, 0xf011223344556677) }, 0);

        let mut out = lr_bytes_t {
            ptr: std::ptr::null_mut(),
            len: 0,
            cap: 0,
        };
        let rc = unsafe { lr_write_buf_take_bytes(w, &raw mut out) };
        assert_eq!(rc, 0);
        let bytes = unsafe { bytes_to_vec(&mut out) };
        assert_eq!(
            bytes,
            vec![
                0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66,
                0x77
            ]
        );

        // Buffer is empty after take.
        assert_eq!(unsafe { lr_write_buf_position(w) }, 0);

        unsafe { lr_write_buf_free(w) };
    }

    #[test]
    fn ffi_write_buf_put_bytes() {
        let w = lr_write_buf_new(8);
        let data = [10u8, 20, 30, 40];
        let rc = unsafe { lr_write_buf_put_bytes(w, data.as_ptr(), data.len()) };
        assert_eq!(rc, 0);
        assert_eq!(unsafe { lr_write_buf_position(w) }, 4);

        let mut out = lr_bytes_t {
            ptr: std::ptr::null_mut(),
            len: 0,
            cap: 0,
        };
        let rc = unsafe { lr_write_buf_take_bytes(w, &raw mut out) };
        assert_eq!(rc, 0);
        let bytes = unsafe { bytes_to_vec(&mut out) };
        assert_eq!(bytes, vec![10, 20, 30, 40]);

        unsafe { lr_write_buf_free(w) };
    }

    #[test]
    fn ffi_bufs_free_handles_null() {
        unsafe {
            lr_read_buf_free(std::ptr::null_mut());
            lr_write_buf_free(std::ptr::null_mut());
        }
    }

    #[test]
    fn ffi_bufs_null_handle_returns_null_error() {
        let mut v = 0u8;
        let rc = unsafe { lr_read_buf_get_u8(std::ptr::null_mut(), &raw mut v) };
        assert_eq!(rc, LR_ERR_NULL);
        let rc = unsafe { lr_write_buf_put_u8(std::ptr::null_mut(), 0) };
        assert_eq!(rc, LR_ERR_NULL);
    }
}
