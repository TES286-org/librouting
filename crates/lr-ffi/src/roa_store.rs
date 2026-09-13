//! RPKI ROA store FFI — a live, thread-safe ROA database for C
//! embedders (RFC 6482 / RFC 6811 / RFC 8210; ROADMAP-v3 D2.3/D2.5).
//!
//! `lr_roa_store_t` wraps `lr_bgp::RoaStore`: two provenance layers
//! (static configuration entries + RTR cache entries), atomic
//! whole-table snapshot swaps, and lock-free validation reads. This
//! is the surface `lr_router_add_roa_entry` was stubbed for — a real,
//! mutable table a C embedder can drive from their own RTR client or
//! configuration loader:
//!
//! ```c
//! lr_roa_store_t *s = lr_roa_store_new();
//! lr_roa_entry_t e = { .asn = 64512, .prefix_len = 24, .max_length = 24 };
//! memcpy(e.addr, "\xc6\x33\x64\x00", 4);     /* 198.51.100.0 */
//! lr_roa_store_replace_static(s, &e, 1);
//! uint8_t state = 0;
//! /* lr_roa_store_validate(...) -> LR_ROA_VALID / _NOT_FOUND / _INVALID */
//! lr_roa_store_free(s);
//! ```
//!
//! # Ownership
//!
//! The store is Rust-allocated; free it with `lr_roa_store_free`.
//! Entry/delta arrays passed to `replace_static` / `apply_deltas` are
//! borrowed for the duration of the call only.

use crate::error::{set_last_error, LrError};
use crate::guarded;
use crate::handle::{box_roa_store, lr_roa_store_t, unbox_roa_store};
use lr_bgp::roa::{RoaEntry, RoaState};
use lr_core::addr::{Asn, IpAddr, Prefix};

/// Validation outcome constants (`lr_roa_store_validate` out param).
pub const LR_ROA_VALID: u8 = 0;
pub const LR_ROA_NOT_FOUND: u8 = 1;
pub const LR_ROA_INVALID: u8 = 2;

/// One ROA entry for the FFI surface. IPv4 addresses go in the first
/// four bytes of `addr` with `is_ipv6 = 0`; IPv6 uses all sixteen
/// bytes with `is_ipv6 = 1`. `max_length` must be >= `prefix_len`
/// (and <= 32 / 128) — malformed entries fail the whole batch with
/// `LrError::Other` semantics (rc != 0) and never reach the store.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct lr_roa_entry_t {
    /// Address bytes (v4 in the low four bytes, zero-padded).
    pub addr: [u8; 16],
    /// 0 = IPv4, anything else = IPv6.
    pub is_ipv6: u8,
    /// Prefix length (0..=32 for v4, 0..=128 for v6).
    pub prefix_len: u8,
    /// Maximum authorized prefix length.
    pub max_length: u8,
    /// Authorized origin AS. AS 0 marks the blackhole range
    /// (RFC 6483 §4).
    pub asn: u32,
}

/// One record delta for `lr_roa_store_apply_deltas` — the wire shape
/// of an RTR Prefix PDU (RFC 8210 §5.6/§5.7).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct lr_roa_delta_t {
    /// 0 = withdraw, anything else = announce.
    pub announce: u8,
    /// The record the delta applies to.
    pub entry: lr_roa_entry_t,
}

impl lr_roa_entry_t {
    /// Convert a validated wire entry into a checked `RoaEntry`.
    fn parse(&self) -> Result<RoaEntry, String> {
        let (addr, family_max) = if self.is_ipv6 == 0 {
            let mut o = [0u8; 4];
            o.copy_from_slice(&self.addr[..4]);
            (IpAddr::V4(o), 32u8)
        } else {
            (IpAddr::V6(self.addr), 128u8)
        };
        let prefix = Prefix {
            addr,
            prefix_len: self.prefix_len,
        };
        if self.prefix_len > family_max {
            return Err(format!(
                "prefix_len {} exceeds the family width {family_max}",
                self.prefix_len
            ));
        }
        let asn = Asn(self.asn);
        if self.max_length == self.prefix_len {
            Ok(RoaEntry::exact(prefix, asn))
        } else {
            RoaEntry::with_max_length(prefix, self.max_length, asn).map_err(|e| e.to_string())
        }
    }
}

/// Create an empty ROA store. NULL on panic (last-error set).
#[no_mangle]
pub extern "C" fn lr_roa_store_new() -> lr_roa_store_t {
    guarded(
        || box_roa_store(lr_bgp::RoaStore::new()),
        std::ptr::null_mut(),
    )
}

/// Free a ROA store. NULL is a no-op. Must not run concurrently with
/// any other call on the same handle.
///
/// # Safety
/// `s` must have been produced by [`lr_roa_store_new`] and must not
/// be freed twice.
#[no_mangle]
pub unsafe extern "C" fn lr_roa_store_free(s: lr_roa_store_t) {
    guarded(
        || {
            if !s.is_null() {
                unsafe { unbox_roa_store(s) };
            }
        },
        (),
    )
}

/// Atomically replace the **static** layer (local configuration) with
/// `len` entries. RTR-learned entries are preserved. Returns 0 on
/// success; -6 (`Other`) with the last-error string set when any
/// entry is malformed — in that case nothing is applied.
///
/// # Safety
/// `s` must be a live store handle; `entries` must point at `len`
/// readable `lr_roa_entry_t`s (NULL with len 0 clears the layer).
#[no_mangle]
pub unsafe extern "C" fn lr_roa_store_replace_static(
    s: lr_roa_store_t,
    entries: *const lr_roa_entry_t,
    len: usize,
) -> i32 {
    guarded(
        || {
            let Some(store) = (unsafe { lock_roa_store(s) }) else {
                set_last_error("lr_roa_store_replace_static: bad handle".to_string());
                return LrError::InvalidHandle as i32;
            };
            let parsed = match parse_entries(entries, len) {
                Ok(v) => v,
                Err(e) => {
                    set_last_error(format!("lr_roa_store_replace_static: {e}"));
                    return LrError::Other as i32;
                }
            };
            store.replace_static(parsed);
            LrError::Ok as i32
        },
        LrError::Panic as i32,
    )
}

/// Apply a batch of RTR deltas atomically (one completed sync).
/// Duplicates coalesce and unknown withdrawals are no-ops — the RFC
/// 8210 §5.6 / §12 code-6 semantics live in the set math. Returns 0
/// on success, -6 with last-error on a malformed entry (nothing
/// applied), -1/-4 as usual.
///
/// # Safety
/// `s` must be a live store handle; `deltas` must point at `len`
/// readable `lr_roa_delta_t`s (NULL with len 0 is a no-op).
#[no_mangle]
pub unsafe extern "C" fn lr_roa_store_apply_deltas(
    s: lr_roa_store_t,
    deltas: *const lr_roa_delta_t,
    len: usize,
) -> i32 {
    guarded(
        || {
            let Some(store) = (unsafe { lock_roa_store(s) }) else {
                set_last_error("lr_roa_store_apply_deltas: bad handle".to_string());
                return LrError::InvalidHandle as i32;
            };
            if len == 0 {
                return LrError::Ok as i32;
            }
            if deltas.is_null() {
                set_last_error("lr_roa_store_apply_deltas: NULL deltas with len > 0".to_string());
                return LrError::Null as i32;
            }
            let slice = unsafe { std::slice::from_raw_parts(deltas, len) };
            let mut parsed = Vec::with_capacity(len);
            for (i, d) in slice.iter().enumerate() {
                match d.entry.parse() {
                    Ok(entry) => parsed.push(lr_bgp::rtr::client::RoaDelta {
                        announce: d.announce != 0,
                        entry,
                    }),
                    Err(e) => {
                        set_last_error(format!("lr_roa_store_apply_deltas: delta {i}: {e}"));
                        return LrError::Other as i32;
                    }
                }
            }
            store.apply_rtr_deltas(&parsed);
            LrError::Ok as i32
        },
        LrError::Panic as i32,
    )
}

/// Withdraw every RTR-learned entry — the RFC 8210 §6 data-expiry and
/// cache-change response. Static entries survive.
///
/// # Safety
/// `s` must be a live store handle.
#[no_mangle]
pub unsafe extern "C" fn lr_roa_store_clear_rtr(s: lr_roa_store_t) -> i32 {
    guarded(
        || {
            let Some(store) = (unsafe { lock_roa_store(s) }) else {
                set_last_error("lr_roa_store_clear_rtr: bad handle".to_string());
                return LrError::InvalidHandle as i32;
            };
            store.clear_rtr();
            LrError::Ok as i32
        },
        LrError::Panic as i32,
    )
}

/// Current merged entry count (static + RTR layers, deduplicated).
/// 0 on NULL / panic.
///
/// # Safety
/// `s` must be NULL or a live store handle.
#[no_mangle]
pub unsafe extern "C" fn lr_roa_store_len(s: lr_roa_store_t) -> usize {
    guarded(
        || match unsafe { lock_roa_store(s) } {
            Some(store) => store.len(),
            None => 0,
        },
        0,
    )
}

/// RFC 6811 §2 validation against the current snapshot. Writes
/// `LR_ROA_VALID` / `LR_ROA_NOT_FOUND` / `LR_ROA_INVALID` to
/// `out_state`. A NULL `origin_as` (no AS_PATH) validates as
/// `LR_ROA_NOT_FOUND` — a route without an origin AS is not covered
/// by any ROA.
///
/// # Safety
/// `s` must be a live store handle; `addr_v4` (4 bytes) or `addr_v6`
/// (16 bytes) must be readable; `out_state` must be writable.
#[no_mangle]
pub unsafe extern "C" fn lr_roa_store_validate(
    s: lr_roa_store_t,
    addr_v4: *const u8,
    addr_v6: *const u8,
    prefix_len: u8,
    origin_as: u32,
    has_origin_as: u8,
    out_state: *mut u8,
) -> i32 {
    guarded(
        || {
            let Some(store) = (unsafe { lock_roa_store(s) }) else {
                set_last_error("lr_roa_store_validate: bad handle".to_string());
                return LrError::InvalidHandle as i32;
            };
            if out_state.is_null() {
                set_last_error("lr_roa_store_validate: out_state is NULL".to_string());
                return LrError::Null as i32;
            }
            let addr = match parse_addr(addr_v4, addr_v6) {
                Ok(a) => a,
                Err(e) => {
                    set_last_error(format!("lr_roa_store_validate: {e}"));
                    return LrError::Null as i32;
                }
            };
            let prefix = Prefix { addr, prefix_len };
            let origin = if has_origin_as == 0 {
                None
            } else {
                Some(Asn(origin_as))
            };
            let state = store.load().validate(&prefix, origin);
            unsafe {
                *out_state = match state {
                    RoaState::Valid => LR_ROA_VALID,
                    RoaState::NotFound => LR_ROA_NOT_FOUND,
                    RoaState::Invalid => LR_ROA_INVALID,
                };
            }
            LrError::Ok as i32
        },
        LrError::Panic as i32,
    )
}

/// Shared helper: parse at most one of v4 / v6 address bytes.
fn parse_addr(addr_v4: *const u8, addr_v6: *const u8) -> Result<IpAddr, String> {
    if !addr_v4.is_null() {
        let b = unsafe { std::slice::from_raw_parts(addr_v4, 4) };
        Ok(IpAddr::V4([b[0], b[1], b[2], b[3]]))
    } else if !addr_v6.is_null() {
        let b = unsafe { std::slice::from_raw_parts(addr_v6, 16) };
        let mut octets = [0u8; 16];
        octets.copy_from_slice(b);
        Ok(IpAddr::V6(octets))
    } else {
        Err("both addr_v4 and addr_v6 are NULL".to_string())
    }
}

/// Parse a borrowed C entry array into checked `RoaEntry`s.
fn parse_entries(entries: *const lr_roa_entry_t, len: usize) -> Result<Vec<RoaEntry>, String> {
    if len == 0 {
        return Ok(Vec::new());
    }
    if entries.is_null() {
        return Err("NULL entries with len > 0".to_string());
    }
    let slice = unsafe { std::slice::from_raw_parts(entries, len) };
    let mut out = Vec::with_capacity(len);
    for (i, e) in slice.iter().enumerate() {
        out.push(e.parse().map_err(|err| format!("entry {i}: {err}"))?);
    }
    Ok(out)
}

/// Shared-reference accessor mirroring `lock_router`'s shape. No lock:
/// `RoaStore` is `Send + Sync` and its internal `RwLock` already
/// serializes writers; wrapping the handle in a `Mutex` would defeat
/// the concurrent lock-free validation reads the type advertises.
/// Only `lr_roa_store_free` excludes concurrent calls (destroy
/// contract, as with the router handle).
unsafe fn lock_roa_store(s: lr_roa_store_t) -> Option<&'static lr_bgp::RoaStore> {
    if s.is_null() {
        return None;
    }
    Some(unsafe { &*(s as *const lr_bgp::RoaStore) })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::lr_last_error;

    fn make_entry(addr: [u8; 4], prefix_len: u8, max_length: u8, asn: u32) -> lr_roa_entry_t {
        let mut a = [0u8; 16];
        a[..4].copy_from_slice(&addr);
        lr_roa_entry_t {
            addr: a,
            is_ipv6: 0,
            prefix_len,
            max_length,
            asn,
        }
    }

    fn last_error() -> String {
        unsafe { std::ffi::CStr::from_ptr(lr_last_error()) }
            .to_string_lossy()
            .into_owned()
    }

    #[test]
    fn store_lifecycle_len_and_validate() {
        let s = lr_roa_store_new();
        assert!(!s.is_null());
        assert_eq!(unsafe { lr_roa_store_len(s) }, 0);

        let entries = [
            make_entry([203, 0, 113, 0], 24, 24, 64512),
            make_entry([198, 51, 100, 0], 24, 26, 64513),
        ];
        let rc = unsafe { lr_roa_store_replace_static(s, entries.as_ptr(), 2) };
        assert_eq!(rc, 0, "last error: {}", last_error());
        assert_eq!(unsafe { lr_roa_store_len(s) }, 2);

        let mut state = 0u8;
        let mut v4 = [203u8, 0, 113, 0];
        let rc = unsafe {
            lr_roa_store_validate(
                s,
                v4.as_mut_ptr(),
                std::ptr::null(),
                24,
                64512,
                1,
                &mut state,
            )
        };
        assert_eq!(rc, 0);
        assert_eq!(state, LR_ROA_VALID);

        // Wrong origin → Invalid; uncovered prefix → NotFound; no
        // origin AS → NotFound (RFC 6811 §2).
        let rc = unsafe {
            lr_roa_store_validate(
                s,
                v4.as_mut_ptr(),
                std::ptr::null(),
                24,
                64514,
                1,
                &mut state,
            )
        };
        assert_eq!(rc, 0);
        assert_eq!(state, LR_ROA_INVALID);
        let mut other = [198u8, 51, 100, 0];
        let rc = unsafe {
            lr_roa_store_validate(
                s,
                other.as_mut_ptr(),
                std::ptr::null(),
                27,
                64513,
                1,
                &mut state,
            )
        };
        assert_eq!(rc, 0);
        assert_eq!(state, LR_ROA_INVALID, "max_length 26 covers /27? no");
        let rc = unsafe {
            lr_roa_store_validate(
                s,
                other.as_mut_ptr(),
                std::ptr::null(),
                24,
                64513,
                1,
                &mut state,
            )
        };
        assert_eq!(rc, 0);
        assert_eq!(state, LR_ROA_VALID);
        let rc = unsafe {
            lr_roa_store_validate(s, v4.as_mut_ptr(), std::ptr::null(), 24, 0, 0, &mut state)
        };
        assert_eq!(rc, 0);
        assert_eq!(state, LR_ROA_NOT_FOUND);

        unsafe { lr_roa_store_free(s) };
    }

    #[test]
    fn deltas_apply_and_clear_rtr_preserves_static() {
        let s = lr_roa_store_new();
        let statics = [make_entry([203, 0, 113, 0], 24, 24, 64512)];
        assert_eq!(
            unsafe { lr_roa_store_replace_static(s, statics.as_ptr(), 1) },
            0
        );

        let e = make_entry([192, 0, 2, 0], 24, 24, 64512);
        let deltas = [
            lr_roa_delta_t {
                announce: 1,
                entry: e,
            },
            lr_roa_delta_t {
                announce: 1,
                entry: e,
            }, // duplicate coalesces
        ];
        assert_eq!(
            unsafe { lr_roa_store_apply_deltas(s, deltas.as_ptr(), 2) },
            0
        );
        assert_eq!(
            unsafe { lr_roa_store_len(s) },
            2,
            "1 static + 1 deduped rtr"
        );

        // Expiry: the cache layer goes, the static layer stays.
        assert_eq!(unsafe { lr_roa_store_clear_rtr(s) }, 0);
        assert_eq!(unsafe { lr_roa_store_len(s) }, 1);

        // Empty batch is a no-op; NULL with len 0 too.
        assert_eq!(
            unsafe { lr_roa_store_apply_deltas(s, std::ptr::null(), 0) },
            0
        );

        // Malformed entry fails the whole batch.
        let mut bad = make_entry([10, 0, 0, 0], 8, 4, 64512); // max < prefix
        bad.max_length = 4;
        let batch = [lr_roa_delta_t {
            announce: 1,
            entry: bad,
        }];
        let rc = unsafe { lr_roa_store_apply_deltas(s, batch.as_ptr(), 1) };
        assert_eq!(rc, LrError::Other as i32);
        assert!(
            last_error().contains("max_length"),
            "last: {}",
            last_error()
        );

        unsafe { lr_roa_store_free(s) };
    }

    #[test]
    fn null_handle_and_null_entries_are_reported() {
        let rc = unsafe { lr_roa_store_replace_static(std::ptr::null_mut(), std::ptr::null(), 0) };
        assert_eq!(rc, LrError::InvalidHandle as i32);

        let s = lr_roa_store_new();
        let rc = unsafe { lr_roa_store_replace_static(s, std::ptr::null(), 1) };
        assert_eq!(rc, LrError::Other as i32);
        assert!(last_error().contains("NULL"), "last: {}", last_error());

        let mut state = 9u8;
        let rc = unsafe {
            lr_roa_store_validate(s, std::ptr::null(), std::ptr::null(), 24, 0, 1, &mut state)
        };
        assert_eq!(rc, LrError::Null as i32);
        unsafe { lr_roa_store_free(s) };
        // Freeing NULL is a no-op.
        unsafe { lr_roa_store_free(std::ptr::null_mut()) };
    }
}
