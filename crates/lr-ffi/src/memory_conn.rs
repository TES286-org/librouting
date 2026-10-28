//! MemoryConn FFI — `lr_memory_conn_*`.
//!
//! Mirrors the public Rust API of `lr_router::connection::MemoryConn`
//! so C embedders can build deterministic loopback test transports
//! without going through a real network. The `MemoryConn` is a
//! byte-pipe: bytes pushed via `lr_memory_conn_push_input` are
//! retrievable via `lr_memory_conn_take_input`, and bytes put via
//! `lr_memory_conn_put_output` are drained via
//! `lr_memory_conn_drain_output`. Two MemoryConns paired with
//! [`lr_memory_conn_pair`] form a loopback where each side's drain
//! is the other's input.
//!
//! # Surface
//!
//! - `lr_memory_conn_new` — empty MemoryConn.
//! - `lr_memory_conn_pair` — write two freshly-allocated handles to
//!   `*out_a` and `*out_b`.
//! - `lr_memory_conn_push_input` — append bytes to the inbound queue.
//! - `lr_memory_conn_take_input` — drain the inbound queue into a
//!   freshly-allocated `lr_bytes_t`.
//! - `lr_memory_conn_put_output` — append bytes to the outbound queue.
//! - `lr_memory_conn_drain_output` — drain the outbound queue.
//! - `lr_memory_conn_free` — drop the boxed MemoryConn.
//!
//! Every entry point runs inside the crate's `catch_unwind` barrier.

#![allow(unused_unsafe)]

use lr_router::connection::{Connection, MemoryConn};

use crate::error::{LrError, LR_ERR_PANIC};
use crate::guarded;
use crate::handle::lr_bytes_t;

const LR_ERR_NULL: i32 = LrError::Null as i32;

/// Opaque `MemoryConn` handle. C side never touches internals.
#[repr(C)]
pub struct OpaqueMemoryConn {
    _private: [u8; 0],
}
pub type lr_memory_conn_t = *mut OpaqueMemoryConn;

fn box_conn(c: MemoryConn) -> lr_memory_conn_t {
    Box::into_raw(Box::new(c)) as lr_memory_conn_t
}
unsafe fn borrow_conn_mut(c: lr_memory_conn_t) -> Option<&'static mut MemoryConn> {
    if c.is_null() {
        return None;
    }
    Some(unsafe { &mut *(c as *mut MemoryConn) })
}
unsafe fn unbox_conn(c: lr_memory_conn_t) -> Option<Box<MemoryConn>> {
    if c.is_null() {
        return None;
    }
    Some(unsafe { Box::from_raw(c as *mut MemoryConn) })
}

/// Construct an empty MemoryConn.
#[no_mangle]
pub extern "C" fn lr_memory_conn_new() -> lr_memory_conn_t {
    guarded(|| box_conn(MemoryConn::new()), std::ptr::null_mut())
}

/// Make a paired pair of MemoryConns. Bytes drained from one are
/// pushed into the other when the embedder wires them together (the
/// `MemoryConn::pair` Rust constructor returns two new empty conns;
/// the loopback wiring is the embedder's job).
///
/// # Safety
/// `out_a` and `out_b` must point to writable `lr_memory_conn_t`.
#[no_mangle]
pub extern "C" fn lr_memory_conn_pair(
    out_a: *mut lr_memory_conn_t,
    out_b: *mut lr_memory_conn_t,
) -> i32 {
    guarded(
        || {
            if out_a.is_null() || out_b.is_null() {
                return LR_ERR_NULL;
            }
            let (a, b) = MemoryConn::pair();
            unsafe {
                *out_a = box_conn(a);
                *out_b = box_conn(b);
            }
            0
        },
        LR_ERR_PANIC,
    )
}

/// Append `bytes` to the inbound queue (the bytes the peer sent to
/// us). Returns 0 on success, `LR_ERR_NULL` on a NULL handle or
/// pointer.
///
/// # Safety
/// `c` must be a live handle. `bytes` must point to `len` readable
/// bytes (NULL only when `len == 0`).
#[no_mangle]
pub unsafe extern "C" fn lr_memory_conn_push_input(
    c: lr_memory_conn_t,
    bytes: *const u8,
    len: usize,
) -> i32 {
    guarded(
        || unsafe {
            let Some(conn) = borrow_conn_mut(c) else {
                return LR_ERR_NULL;
            };
            if bytes.is_null() && len != 0 {
                return LR_ERR_NULL;
            }
            let slice = if len == 0 {
                &[]
            } else {
                unsafe { std::slice::from_raw_parts(bytes, len) }
            };
            conn.push_input(slice);
            0
        },
        LR_ERR_PANIC,
    )
}

/// Drain the inbound queue into a freshly-allocated `lr_bytes_t`. The
/// queue is empty after this call.
///
/// # Safety
/// `c` must be a live handle. `out` must point to a writable
/// `lr_bytes_t`.
#[no_mangle]
pub unsafe extern "C" fn lr_memory_conn_take_input(
    c: lr_memory_conn_t,
    out: *mut lr_bytes_t,
) -> i32 {
    guarded(
        || unsafe {
            let Some(conn) = borrow_conn_mut(c) else {
                return LR_ERR_NULL;
            };
            if out.is_null() {
                return LR_ERR_NULL;
            }
            let bytes = conn.take_input();
            unsafe { *out = lr_bytes_t::from_vec(bytes) }
            0
        },
        LR_ERR_PANIC,
    )
}

/// Append `bytes` to the outbound queue (the bytes we prepared for
/// the peer).
///
/// # Safety
/// See [`lr_memory_conn_push_input`].
#[no_mangle]
pub unsafe extern "C" fn lr_memory_conn_put_output(
    c: lr_memory_conn_t,
    bytes: *const u8,
    len: usize,
) -> i32 {
    guarded(
        || unsafe {
            let Some(conn) = borrow_conn_mut(c) else {
                return LR_ERR_NULL;
            };
            if bytes.is_null() && len != 0 {
                return LR_ERR_NULL;
            }
            let slice = if len == 0 {
                &[]
            } else {
                unsafe { std::slice::from_raw_parts(bytes, len) }
            };
            conn.put_output(slice);
            0
        },
        LR_ERR_PANIC,
    )
}

/// Drain the outbound queue into a freshly-allocated `lr_bytes_t`.
/// The queue is empty after this call.
///
/// # Safety
/// See [`lr_memory_conn_take_input`].
#[no_mangle]
pub unsafe extern "C" fn lr_memory_conn_drain_output(
    c: lr_memory_conn_t,
    out: *mut lr_bytes_t,
) -> i32 {
    guarded(
        || unsafe {
            let Some(conn) = borrow_conn_mut(c) else {
                return LR_ERR_NULL;
            };
            if out.is_null() {
                return LR_ERR_NULL;
            }
            let bytes = conn.drain_output();
            unsafe { *out = lr_bytes_t::from_vec(bytes) }
            0
        },
        LR_ERR_PANIC,
    )
}

/// Drop a boxed MemoryConn. Safe to call with NULL.
///
/// # Safety
/// `c` must have been produced by [`lr_memory_conn_new`] or
/// [`lr_memory_conn_pair`] and must not be used after this call.
#[no_mangle]
pub unsafe extern "C" fn lr_memory_conn_free(c: lr_memory_conn_t) {
    guarded(
        || unsafe {
            drop(unbox_conn(c));
        },
        (),
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
    fn ffi_memory_conn_push_take_roundtrip() {
        let c = lr_memory_conn_new();
        assert!(!c.is_null());

        let data = [1u8, 2, 3, 4];
        let rc = unsafe { lr_memory_conn_push_input(c, data.as_ptr(), data.len()) };
        assert_eq!(rc, 0);

        let mut out = lr_bytes_t {
            ptr: std::ptr::null_mut(),
            len: 0,
            cap: 0,
        };
        let rc = unsafe { lr_memory_conn_take_input(c, &raw mut out) };
        assert_eq!(rc, 0);
        let bytes = unsafe { bytes_to_vec(&mut out) };
        assert_eq!(bytes, vec![1, 2, 3, 4]);

        // Take again — queue is empty now.
        let rc = unsafe { lr_memory_conn_take_input(c, &raw mut out) };
        assert_eq!(rc, 0);
        let bytes = unsafe { bytes_to_vec(&mut out) };
        assert!(bytes.is_empty());

        unsafe { lr_memory_conn_free(c) };
    }

    #[test]
    fn ffi_memory_conn_put_drain_roundtrip() {
        let c = lr_memory_conn_new();
        let data = [10u8, 20, 30];
        let rc = unsafe { lr_memory_conn_put_output(c, data.as_ptr(), data.len()) };
        assert_eq!(rc, 0);

        let mut out = lr_bytes_t {
            ptr: std::ptr::null_mut(),
            len: 0,
            cap: 0,
        };
        let rc = unsafe { lr_memory_conn_drain_output(c, &raw mut out) };
        assert_eq!(rc, 0);
        let bytes = unsafe { bytes_to_vec(&mut out) };
        assert_eq!(bytes, vec![10, 20, 30]);

        unsafe { lr_memory_conn_free(c) };
    }

    #[test]
    fn ffi_memory_conn_pair_returns_two_handles() {
        let mut a: lr_memory_conn_t = std::ptr::null_mut();
        let mut b: lr_memory_conn_t = std::ptr::null_mut();
        let rc = lr_memory_conn_pair(&raw mut a, &raw mut b);
        assert_eq!(rc, 0);
        assert!(!a.is_null());
        assert!(!b.is_null());

        // Push into a, take from a.
        let data = [42u8];
        let rc = unsafe { lr_memory_conn_push_input(a, data.as_ptr(), 1) };
        assert_eq!(rc, 0);
        let mut out = lr_bytes_t {
            ptr: std::ptr::null_mut(),
            len: 0,
            cap: 0,
        };
        let rc = unsafe { lr_memory_conn_take_input(a, &raw mut out) };
        assert_eq!(rc, 0);
        let bytes = unsafe { bytes_to_vec(&mut out) };
        assert_eq!(bytes, vec![42]);

        // b is independent — its queue is empty.
        let rc = unsafe { lr_memory_conn_take_input(b, &raw mut out) };
        assert_eq!(rc, 0);
        let bytes = unsafe { bytes_to_vec(&mut out) };
        assert!(bytes.is_empty());

        unsafe {
            lr_memory_conn_free(a);
            lr_memory_conn_free(b);
        }
    }

    #[test]
    fn ffi_memory_conn_null_handle_returns_null_error() {
        let rc = unsafe { lr_memory_conn_push_input(std::ptr::null_mut(), std::ptr::null(), 0) };
        assert_eq!(rc, LR_ERR_NULL);

        let mut out = lr_bytes_t {
            ptr: std::ptr::null_mut(),
            len: 0,
            cap: 0,
        };
        let rc = unsafe { lr_memory_conn_take_input(std::ptr::null_mut(), &raw mut out) };
        assert_eq!(rc, LR_ERR_NULL);
    }

    #[test]
    fn ffi_memory_conn_free_handles_null() {
        unsafe { lr_memory_conn_free(std::ptr::null_mut()) };
    }
}
