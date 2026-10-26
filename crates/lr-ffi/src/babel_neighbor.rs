//! Babel neighbor + route-table FFI (RFC 8966 §3.3, §3.4, §3.5).
//!
//! Mirrors the public Rust API of `lr_babel::neighbor::BabelNeighbor`
//! and `lr_babel::route::BabelRouteTable` so an embedder can drive a
//! Babel neighbor FSM and route table without going through the
//! daemon's `DefaultRouter`. The neighbor FSM and route table were
//! previously invisible across the C ABI — only the stateless codec
//! (`lr_babel_decode_frame` / `lr_babel_encode_frame`) was exposed.
//!
//! # Surface
//!
//! - `lr_babel_neighbor_new` — construct a `BabelNeighbor` for a
//!   given remote address (v4 or v6).
//! - `lr_babel_neighbor_free` — drop the handle (safe on NULL).
//! - `lr_babel_neighbor_hello` — feed one Hello TLV (RFC 8966 §3.4.1).
//! - `lr_babel_neighbor_ihu` — feed one IHU TLV (RFC 8966 §3.4.2).
//! - `lr_babel_neighbor_rtt_us` — read the current RTT estimate (or
//!   0 when no valid RTT sample is available).
//! - `lr_babel_neighbor_rtt_valid` — 1 when the RTT estimate is
//!   within the validity window.
//!
//! - `lr_babel_route_table_new` / `_free` — `BabelRouteTable`
//!   lifecycle (RFC 8966 §3.5).
//! - `lr_babel_route_table_len` / `_is_empty` — readers.
//!
//! Every entry point runs inside the crate's `catch_unwind` barrier
//! ([`crate::guarded`]): a panic returns `LR_ERR_PANIC` and sets the
//! thread-local last-error string.

#![allow(unused_unsafe)]

use lr_babel::neighbor::BabelNeighbor;
use lr_babel::route::BabelRouteTable;
use lr_core::addr::IpAddr;

use crate::error::{LrError, LR_ERR_PANIC};
use crate::guarded;

const LR_ERR_NULL: i32 = LrError::Null as i32;

// ---- Opaque handle types ----

#[repr(C)]
pub struct OpaqueBabelNeighbor {
    _private: [u8; 0],
}
pub type lr_babel_neighbor_t = *mut OpaqueBabelNeighbor;

#[repr(C)]
pub struct OpaqueBabelRouteTable {
    _private: [u8; 0],
}
pub type lr_babel_route_table_t = *mut OpaqueBabelRouteTable;

// ---- BabelNeighbor box / unbox helpers ----

fn box_neighbor(n: BabelNeighbor) -> lr_babel_neighbor_t {
    Box::into_raw(Box::new(n)) as lr_babel_neighbor_t
}
unsafe fn borrow_neighbor_mut(r: lr_babel_neighbor_t) -> Option<&'static mut BabelNeighbor> {
    if r.is_null() {
        return None;
    }
    Some(unsafe { &mut *(r as *mut BabelNeighbor) })
}
unsafe fn borrow_neighbor(r: lr_babel_neighbor_t) -> Option<&'static BabelNeighbor> {
    if r.is_null() {
        return None;
    }
    Some(unsafe { &*(r as *const BabelNeighbor) })
}
unsafe fn unbox_neighbor(r: lr_babel_neighbor_t) -> Option<Box<BabelNeighbor>> {
    if r.is_null() {
        return None;
    }
    Some(unsafe { Box::from_raw(r as *mut BabelNeighbor) })
}

// ---- BabelRouteTable box / unbox helpers ----

fn box_route_table(t: BabelRouteTable) -> lr_babel_route_table_t {
    Box::into_raw(Box::new(t)) as lr_babel_route_table_t
}
unsafe fn borrow_route_table(r: lr_babel_route_table_t) -> Option<&'static BabelRouteTable> {
    if r.is_null() {
        return None;
    }
    Some(unsafe { &*(r as *const BabelRouteTable) })
}
unsafe fn unbox_route_table(r: lr_babel_route_table_t) -> Option<Box<BabelRouteTable>> {
    if r.is_null() {
        return None;
    }
    Some(unsafe { Box::from_raw(r as *mut BabelRouteTable) })
}

// ---- BabelNeighbor surface ----

/// Construct a `BabelNeighbor` for the given remote address (RFC
/// 8966 §3.4.1). `addr_v4` is the 4-byte IPv4 address (NULL when
/// IPv6); `addr_v6` is the 16-byte IPv6 address (NULL when IPv4).
/// `now_ms` is the wall-clock millisecond timestamp of construction.
///
/// Returns NULL when both pointers are NULL or on a panic.
///
/// # Safety
/// At most one of `addr_v4` / `addr_v6` is non-NULL. The non-NULL
/// pointer must point to 4 (v4) or 16 (v6) readable bytes.
#[no_mangle]
pub unsafe extern "C" fn lr_babel_neighbor_new(
    addr_v4: *const u8,
    addr_v6: *const u8,
    now_ms: u64,
) -> lr_babel_neighbor_t {
    guarded(
        || unsafe {
            let addr = if !addr_v4.is_null() {
                let mut a = [0u8; 4];
                a.copy_from_slice(unsafe { std::slice::from_raw_parts(addr_v4, 4) });
                IpAddr::V4(a)
            } else if !addr_v6.is_null() {
                let mut a = [0u8; 16];
                a.copy_from_slice(unsafe { std::slice::from_raw_parts(addr_v6, 16) });
                IpAddr::V6(a)
            } else {
                return std::ptr::null_mut();
            };
            box_neighbor(BabelNeighbor::new(addr, now_ms))
        },
        std::ptr::null_mut(),
    )
}

/// Drop a boxed BabelNeighbor. Safe to call with NULL.
///
/// # Safety
/// `r` must have been produced by `lr_babel_neighbor_new` and not
/// already freed.
#[no_mangle]
pub unsafe extern "C" fn lr_babel_neighbor_free(r: lr_babel_neighbor_t) {
    guarded(
        || unsafe {
            drop(unbox_neighbor(r));
        },
        (),
    )
}

/// Feed one Hello TLV into the neighbor (RFC 8966 §3.4.1). Updates
/// the neighbor's hello history and rxcost.
///
/// # Safety
/// `r` must be a valid BabelNeighbor handle.
#[no_mangle]
pub unsafe extern "C" fn lr_babel_neighbor_hello(
    r: lr_babel_neighbor_t,
    seqno: u16,
    interval_cs: u16,
    now_ms: u64,
) -> i32 {
    guarded(
        || unsafe {
            let Some(n) = borrow_neighbor_mut(r) else {
                return LR_ERR_NULL;
            };
            n.hello(seqno, interval_cs, now_ms);
            0
        },
        LR_ERR_PANIC,
    )
}

/// Feed one IHU TLV into the neighbor (RFC 8966 §3.4.2). Updates the
/// neighbor's rxcost.
///
/// # Safety
/// See [`lr_babel_neighbor_hello`].
#[no_mangle]
pub unsafe extern "C" fn lr_babel_neighbor_ihu(
    r: lr_babel_neighbor_t,
    rxcost: u16,
    interval_cs: u16,
    now_ms: u64,
) -> i32 {
    guarded(
        || unsafe {
            let Some(n) = borrow_neighbor_mut(r) else {
                return LR_ERR_NULL;
            };
            n.ihu(rxcost, interval_cs, now_ms);
            0
        },
        LR_ERR_PANIC,
    )
}

/// Read the current RTT estimate in microseconds, or 0 when no
/// valid RTT sample is available (RFC 8966 §3.4.3 — the RTT is
/// valid for `RTT_VALIDITY_MS` after the last sample).
///
/// # Safety
/// `r` must be a valid BabelNeighbor handle.
#[no_mangle]
pub unsafe extern "C" fn lr_babel_neighbor_rtt_us(r: lr_babel_neighbor_t, now_ms: u64) -> u32 {
    guarded(
        || unsafe {
            borrow_neighbor(r)
                .and_then(|n| n.rtt_us(now_ms))
                .unwrap_or(0)
        },
        0,
    )
}

/// 1 when the RTT estimate is within the validity window (RFC 8966
/// §3.4.3 — `RTT_VALIDITY_MS` after the last sample), 0 otherwise.
///
/// # Safety
/// See [`lr_babel_neighbor_rtt_us`].
#[no_mangle]
pub unsafe extern "C" fn lr_babel_neighbor_rtt_valid(r: lr_babel_neighbor_t, now_ms: u64) -> u8 {
    guarded(
        || unsafe {
            borrow_neighbor(r)
                .map(|n| n.rtt_valid(now_ms) as u8)
                .unwrap_or(0)
        },
        0,
    )
}

// ---- BabelRouteTable surface ----

/// Construct an empty `BabelRouteTable` (RFC 8966 §3.5).
#[no_mangle]
pub extern "C" fn lr_babel_route_table_new() -> lr_babel_route_table_t {
    guarded(
        || box_route_table(BabelRouteTable::new()),
        std::ptr::null_mut(),
    )
}

/// Drop a boxed BabelRouteTable. Safe to call with NULL.
///
/// # Safety
/// `r` must have been produced by `lr_babel_route_table_new` and not
/// already freed.
#[no_mangle]
pub unsafe extern "C" fn lr_babel_route_table_free(r: lr_babel_route_table_t) {
    guarded(
        || unsafe {
            drop(unbox_route_table(r));
        },
        (),
    )
}

/// Number of routes in the table. Returns 0 on a NULL handle.
///
/// # Safety
/// `r` must be a valid BabelRouteTable handle.
#[no_mangle]
pub unsafe extern "C" fn lr_babel_route_table_len(r: lr_babel_route_table_t) -> usize {
    guarded(
        || unsafe { borrow_route_table(r).map(|t| t.len()).unwrap_or(0) },
        0,
    )
}

/// True when the table holds no routes. Returns 1 on a NULL handle.
///
/// # Safety
/// See [`lr_babel_route_table_len`].
#[no_mangle]
pub unsafe extern "C" fn lr_babel_route_table_is_empty(r: lr_babel_route_table_t) -> u8 {
    guarded(
        || unsafe {
            borrow_route_table(r)
                .map(|t| t.is_empty() as u8)
                .unwrap_or(1)
        },
        1,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ffi_babel_neighbor_new_and_hello() {
        let v4 = [10u8, 0, 0, 1];
        let n = unsafe { lr_babel_neighbor_new(v4.as_ptr(), std::ptr::null(), 1_000) };
        assert!(!n.is_null());

        // Feed a Hello — should not error.
        let rc = unsafe { lr_babel_neighbor_hello(n, 1, 100, 1_100) };
        assert_eq!(rc, 0);

        // Feed an IHU.
        let rc = unsafe { lr_babel_neighbor_ihu(n, 96, 100, 1_100) };
        assert_eq!(rc, 0);

        // RTT is not valid yet (no timestamped Hello received).
        assert_eq!(unsafe { lr_babel_neighbor_rtt_valid(n, 1_200) }, 0);
        assert_eq!(unsafe { lr_babel_neighbor_rtt_us(n, 1_200) }, 0);

        unsafe { lr_babel_neighbor_free(n) };
    }

    #[test]
    fn ffi_babel_neighbor_new_rejects_null_addr() {
        let n = unsafe { lr_babel_neighbor_new(std::ptr::null(), std::ptr::null(), 0) };
        assert!(n.is_null());
    }

    #[test]
    fn ffi_babel_neighbor_v6() {
        let v6 = [0xfe_u8, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let n = unsafe { lr_babel_neighbor_new(std::ptr::null(), v6.as_ptr(), 0) };
        assert!(!n.is_null());
        unsafe { lr_babel_neighbor_free(n) };
    }

    #[test]
    fn ffi_babel_route_table_lifecycle() {
        let t = lr_babel_route_table_new();
        assert!(!t.is_null());
        assert_eq!(unsafe { lr_babel_route_table_is_empty(t) }, 1);
        assert_eq!(unsafe { lr_babel_route_table_len(t) }, 0);
        unsafe { lr_babel_route_table_free(t) };
    }

    #[test]
    fn ffi_babel_handles_null_safely() {
        unsafe {
            lr_babel_neighbor_free(std::ptr::null_mut());
            lr_babel_route_table_free(std::ptr::null_mut());
        }
        assert_eq!(unsafe { lr_babel_route_table_len(std::ptr::null_mut()) }, 0);
        assert_eq!(
            unsafe { lr_babel_route_table_is_empty(std::ptr::null_mut()) },
            1
        );
    }
}
