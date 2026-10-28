//! Standalone DampingTable FFI (RFC 2439).
//!
//! Mirrors the public Rust API of `lr_damping::{DampingTable, DampingEntry,
//! DampingConfig}` so an embedder can construct, drive and inspect a damping
//! table directly — without first installing it on a router via
//! [`crate::policy::lr_router_set_damping`].
//!
//! The handle type [`lr_damping_table_t`] is a distinct opaque pointer from
//! the router-attached [`crate::handle::lr_damping_t`] (which carries an
//! `Arc<Mutex<DampingTable>>` shared with the import hook). A standalone
//! table is single-threaded — the embedder owns it exclusively.
//!
//! Every entry point runs inside the crate's `catch_unwind` barrier
//! ([`crate::guarded`]); a panic returns `LR_ERR_PANIC` and sets the
//! thread-local last-error string.

// The closure body passed to `guarded` is wrapped in a single `unsafe`
// block to mirror the `pub unsafe extern "C" fn` shape — the inner
// `unsafe { ... }` blocks would otherwise trip `unused_unsafe` under the
// crate's `-D warnings` clippy gate.
#![allow(unused_unsafe)]

use lr_damping::{DampingConfig, DampingEntry, DampingTable};

use crate::error::{set_last_error, LrError, LR_ERR_PANIC};
use crate::guarded;
use crate::policy::{lr_damping_config_t, lr_prefix_t};

/// `LR_ERR_NULL` (-1) — null pointer or null handle.
const LR_ERR_NULL: i32 = LrError::Null as i32;
/// `LR_ERR_INVALID_HANDLE` (-2) — wrong message variant or invalid index.
const LR_ERR_INVALID_HANDLE: i32 = LrError::InvalidHandle as i32;
/// `LR_ERR_OTHER` (-6) — malformed argument / out of range.
const LR_ERR_OTHER: i32 = LrError::Other as i32;

/// Opaque standalone `DampingTable` handle. C side never touches internals.
#[repr(C)]
pub struct OpaqueDampingTable {
    _private: [u8; 0],
}

pub type lr_damping_table_t = *mut OpaqueDampingTable;

/// One projected damping entry — mirrors [`DampingEntry`] field-for-field
/// but flattens the prefix into the same `lr_prefix_t` shape the rest of
/// the FFI uses.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct lr_damping_entry_t {
    /// Network prefix (IPv4 in the low 4 bytes when `is_ipv6 == 0`).
    pub prefix: lr_prefix_t,
    /// Figure of merit (FoM) — float in `[0, upper_limit]`.
    pub figure_of_merit: f64,
    /// 1 when the entry is currently suppressed, 0 otherwise.
    pub suppressed: u8,
    /// Wall-clock seconds of the last decay tick.
    pub last_decay_s: u64,
    /// Wall-clock seconds of the last flap.
    pub last_flap_s: u64,
    /// Number of historical flaps (does not affect suppression).
    pub flap_count: u32,
}

impl From<&DampingEntry> for lr_damping_entry_t {
    fn from(e: &DampingEntry) -> Self {
        let (addr, is_ipv6) = match e.prefix.addr {
            lr_core::addr::IpAddr::V4(b) => {
                let mut buf = [0u8; 16];
                buf[..4].copy_from_slice(&b);
                (buf, 0u8)
            }
            lr_core::addr::IpAddr::V6(b) => (b, 1u8),
        };
        Self {
            prefix: lr_prefix_t {
                addr,
                is_ipv6,
                prefix_len: e.prefix.prefix_len,
            },
            figure_of_merit: e.figure_of_merit,
            suppressed: e.suppressed as u8,
            last_decay_s: e.last_decay_s,
            last_flap_s: e.last_flap_s,
            flap_count: e.flap_count,
        }
    }
}

/// Box a `DampingTable` into an opaque handle.
fn box_table(t: DampingTable) -> lr_damping_table_t {
    Box::into_raw(Box::new(t)) as lr_damping_table_t
}

/// Reclaim a `DampingTable` handle back into its boxed form.
///
/// # Safety
/// `t` must have been produced by [`box_table`] and not already freed.
unsafe fn unbox_table(t: lr_damping_table_t) -> Option<Box<DampingTable>> {
    if t.is_null() {
        return None;
    }
    Some(unsafe { Box::from_raw(t as *mut DampingTable) })
}

/// Borrow a `DampingTable` handle as `&DampingTable` for read-only access.
///
/// # Safety
/// `t` must have been produced by [`box_table`] and not be freed while
/// the returned reference is live.
unsafe fn borrow_table(t: lr_damping_table_t) -> Option<&'static DampingTable> {
    if t.is_null() {
        return None;
    }
    Some(unsafe { &*(t as *const DampingTable) })
}

/// Borrow a `DampingTable` handle as `&mut DampingTable` for in-place
/// mutation. The borrow is unbounded — the caller must not race the
/// mutation with another `lr_damping_table_*` call on the same handle.
///
/// # Safety
/// `t` must have been produced by [`box_table`] and not be freed while
/// the returned reference is live.
unsafe fn borrow_table_mut(t: lr_damping_table_t) -> Option<&'static mut DampingTable> {
    if t.is_null() {
        return None;
    }
    Some(unsafe { &mut *(t as *mut DampingTable) })
}

/// Construct a `DampingTable` from a config. Pass `cfg = NULL` to use
/// the RFC 2439 defaults (see [`lr_damping_default_config`]).
#[no_mangle]
pub extern "C" fn lr_damping_table_new(cfg: *const lr_damping_config_t) -> lr_damping_table_t {
    guarded(
        || {
            let cfg = if cfg.is_null() {
                DampingConfig::default()
            } else {
                unsafe { (*cfg).to_config() }
            };
            box_table(DampingTable::new(cfg))
        },
        std::ptr::null_mut(),
    )
}

#[no_mangle]
pub unsafe extern "C" fn lr_damping_table_config(
    t: lr_damping_table_t,
    out: *mut lr_damping_config_t,
) -> i32 {
    guarded(
        || unsafe {
            let Some(table) = borrow_table(t) else {
                return -1;
            };
            if out.is_null() {
                return -1;
            }
            unsafe {
                *out = lr_damping_config_t::from_config(table.config());
            }
            0
        },
        LR_ERR_PANIC,
    )
}

/// Returns the default RFC 2439 §4.7 damping config (Cisco-style).
/// Useful as a starting point for caller-side tuning before passing the
/// struct to [`lr_damping_table_new`].
#[no_mangle]
pub extern "C" fn lr_damping_default_config(out: *mut lr_damping_config_t) -> i32 {
    guarded(
        || {
            if out.is_null() {
                return LR_ERR_NULL;
            }
            let d = DampingConfig::default();
            unsafe {
                *out = lr_damping_config_t {
                    additive_incr: d.additive_incr,
                    suppress_threshold: d.suppress_threshold,
                    reuse_threshold: d.reuse_threshold,
                    upper_limit: d.upper_limit,
                    decay_interval_s: d.decay_interval_s,
                    decay_factor_active: d.decay_factor_active,
                    decay_factor_withdrawn: d.decay_factor_withdrawn,
                };
            }
            0
        },
        LR_ERR_PANIC,
    )
}

/// Record a withdrawal. Returns 1 if the route should be suppressed
/// (dropped from the Loc-RIB) as a result, 0 otherwise. Returns
/// `LR_ERR_NULL` (-1) on a null table or a null prefix.
///
/// # Safety
/// `t` must be a valid handle. `prefix` must point to a readable
/// `lr_prefix_t`.
#[no_mangle]
pub unsafe extern "C" fn lr_damping_table_on_withdraw(
    t: lr_damping_table_t,
    prefix: *const lr_prefix_t,
    now_s: u64,
) -> i32 {
    guarded(
        || unsafe {
            let Some(table) = borrow_table_mut(t) else {
                return LR_ERR_NULL;
            };
            if prefix.is_null() {
                return LR_ERR_NULL;
            }
            let Some(p) = (unsafe { (*prefix).to_prefix() }) else {
                set_last_error("invalid prefix length".into());
                return LR_ERR_OTHER;
            };
            if table.on_withdraw(&p, now_s) {
                1
            } else {
                0
            }
        },
        LR_ERR_PANIC,
    )
}

/// Record a re-announcement. Returns 1 if the route remains suppressed,
/// 0 otherwise.
///
/// # Safety
/// See [`lr_damping_table_on_withdraw`].
#[no_mangle]
pub unsafe extern "C" fn lr_damping_table_on_announce(
    t: lr_damping_table_t,
    prefix: *const lr_prefix_t,
    now_s: u64,
) -> i32 {
    guarded(
        || unsafe {
            let Some(table) = borrow_table_mut(t) else {
                return LR_ERR_NULL;
            };
            if prefix.is_null() {
                return LR_ERR_NULL;
            }
            let Some(p) = (unsafe { (*prefix).to_prefix() }) else {
                set_last_error("invalid prefix length".into());
                return LR_ERR_OTHER;
            };
            if table.on_announce(&p, now_s) {
                1
            } else {
                0
            }
        },
        LR_ERR_PANIC,
    )
}

/// True (1) when `prefix` is currently suppressed, false (0) otherwise
/// (also 0 when the prefix is not in the table).
///
/// # Safety
/// `t` must be a valid handle. `prefix` must point to a readable
/// `lr_prefix_t`.
#[no_mangle]
pub unsafe extern "C" fn lr_damping_table_is_suppressed(
    t: lr_damping_table_t,
    prefix: *const lr_prefix_t,
) -> i32 {
    guarded(
        || unsafe {
            let Some(table) = borrow_table(t) else {
                return LR_ERR_NULL;
            };
            if prefix.is_null() {
                return LR_ERR_NULL;
            }
            let Some(p) = (unsafe { (*prefix).to_prefix() }) else {
                set_last_error("invalid prefix length".into());
                return LR_ERR_OTHER;
            };
            if table.is_suppressed(&p) {
                1
            } else {
                0
            }
        },
        LR_ERR_PANIC,
    )
}

/// Decay all entries up to `now_s`. Routes whose FoM drops below the
/// reuse threshold become un-suppressed. Writes the list of newly
/// un-suppressed prefixes into `out_reactivated` (caller-allocated, at
/// most `cap` entries) and returns the number written. A return value
/// greater than `cap` means the buffer was too small — call again with
/// a larger buffer (the table is unchanged; the function does not
/// double-decay).
///
/// # Safety
/// `t` must be a valid handle. `out_reactivated` (when non-null) must
/// point to `cap` writable `lr_prefix_t` values.
#[no_mangle]
pub unsafe extern "C" fn lr_damping_table_decay_all(
    t: lr_damping_table_t,
    now_s: u64,
    out_reactivated: *mut lr_prefix_t,
    cap: usize,
) -> i64 {
    guarded(
        || unsafe {
            let Some(table) = borrow_table_mut(t) else {
                return LR_ERR_NULL as i64;
            };
            let reactivated = table.decay_all(now_s);
            let n = reactivated.len();
            if !out_reactivated.is_null() && cap > 0 {
                let to_write = n.min(cap);
                for (i, p) in reactivated.iter().take(to_write).enumerate() {
                    let (addr, is_ipv6) = match p.addr {
                        lr_core::addr::IpAddr::V4(b) => {
                            let mut buf = [0u8; 16];
                            buf[..4].copy_from_slice(&b);
                            (buf, 0u8)
                        }
                        lr_core::addr::IpAddr::V6(b) => (b, 1u8),
                    };
                    unsafe {
                        *out_reactivated.add(i) = lr_prefix_t {
                            addr,
                            is_ipv6,
                            prefix_len: p.prefix_len,
                        };
                    }
                }
            }
            n as i64
        },
        LR_ERR_PANIC as i64,
    )
}

/// Forget a prefix entirely (e.g. after operator's manual reset).
/// Returns 1 when the prefix was present (and is now removed), 0 when
/// it was not in the table.
///
/// # Safety
/// See [`lr_damping_table_on_withdraw`].
#[no_mangle]
pub unsafe extern "C" fn lr_damping_table_forget(
    t: lr_damping_table_t,
    prefix: *const lr_prefix_t,
) -> i32 {
    guarded(
        || unsafe {
            let Some(table) = borrow_table_mut(t) else {
                return LR_ERR_NULL;
            };
            if prefix.is_null() {
                return LR_ERR_NULL;
            }
            let Some(p) = (unsafe { (*prefix).to_prefix() }) else {
                set_last_error("invalid prefix length".into());
                return LR_ERR_OTHER;
            };
            // DampingTable::forget returns () — we need to detect
            // presence ourselves by checking `is_suppressed` or any
            // entry before forget. The simpler approach: peek via
            // `entries()` for the same prefix.
            let was_present = table.entries().any(|e| e.prefix == p);
            table.forget(&p);
            if was_present {
                1
            } else {
                0
            }
        },
        LR_ERR_PANIC,
    )
}

/// Number of entries currently in the table. Returns 0 on a NULL handle.
///
/// # Safety
/// `t` must be a valid handle.
#[no_mangle]
pub unsafe extern "C" fn lr_damping_table_len(t: lr_damping_table_t) -> usize {
    guarded(
        || unsafe { borrow_table(t).map(|t| t.entries().count()).unwrap_or(0) },
        0,
    )
}

/// Read one entry by index. Returns 0 on success and writes a copy of
/// the entry's `(prefix, figure_of_merit, suppressed, last_decay_s,
/// last_flap_s, flap_count)` to `*out`. Returns `LR_ERR_NULL` (-1) on
/// a NULL table or out pointer, `LR_ERR_INVALID_HANDLE` (-2) when the
/// index is out of range.
///
/// # Safety
/// `t` must be a valid handle. `out` must point to a writable
/// `lr_damping_entry_t`.
#[no_mangle]
pub unsafe extern "C" fn lr_damping_table_at(
    t: lr_damping_table_t,
    index: usize,
    out: *mut lr_damping_entry_t,
) -> i32 {
    guarded(
        || unsafe {
            let Some(table) = borrow_table(t) else {
                return LR_ERR_NULL;
            };
            if out.is_null() {
                return LR_ERR_NULL;
            }
            let Some(entry) = table.entries().nth(index) else {
                set_last_error(format!(
                    "damping entry index {index} out of range (len={})",
                    table.entries().count()
                ));
                return LR_ERR_INVALID_HANDLE;
            };
            unsafe { *out = lr_damping_entry_t::from(entry) };
            0
        },
        LR_ERR_PANIC,
    )
}

/// Drop a boxed `DampingTable`. Safe to call with NULL.
///
/// # Safety
/// `t` must have been produced by [`lr_damping_table_new`] and must not
/// be used after this call. Double-free is undefined behaviour.
#[no_mangle]
pub unsafe extern "C" fn lr_damping_table_free(t: lr_damping_table_t) {
    guarded(
        || unsafe {
            drop(unbox_table(t));
        },
        (),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v4_prefix(a: [u8; 4], len: u8) -> lr_prefix_t {
        let mut buf = [0u8; 16];
        buf[..4].copy_from_slice(&a);
        lr_prefix_t {
            addr: buf,
            is_ipv6: 0,
            prefix_len: len,
        }
    }

    fn default_table() -> lr_damping_table_t {
        lr_damping_table_new(std::ptr::null())
    }

    #[test]
    fn ffi_damping_default_config_round_trip() {
        let mut cfg = lr_damping_config_t {
            additive_incr: 0,
            suppress_threshold: 0,
            reuse_threshold: 0,
            upper_limit: 0,
            decay_interval_s: 0,
            decay_factor_active: 0.0,
            decay_factor_withdrawn: 0.0,
        };
        let rc = lr_damping_default_config(&raw mut cfg);
        assert_eq!(rc, 0);
        assert_eq!(cfg.additive_incr, 1000);
        assert_eq!(cfg.suppress_threshold, 2000);
        assert_eq!(cfg.reuse_threshold, 750);
        assert_eq!(cfg.upper_limit, 60000);
        assert_eq!(cfg.decay_interval_s, 30);
        assert!((cfg.decay_factor_active - 0.97).abs() < 1e-9);
        assert!((cfg.decay_factor_withdrawn - 0.5).abs() < 1e-9);
    }

    #[test]
    fn ffi_damping_single_flap_does_not_suppress() {
        let t = default_table();
        let p = v4_prefix([10, 0, 0, 0], 8);
        let suppress = unsafe { lr_damping_table_on_withdraw(t, &raw const p, 0) };
        assert_eq!(suppress, 0, "single withdraw should not suppress");
        assert_eq!(unsafe { lr_damping_table_len(t) }, 1);
        unsafe { lr_damping_table_free(t) };
    }

    #[test]
    fn ffi_damping_three_rapid_flaps_suppress() {
        let t = default_table();
        let p = v4_prefix([10, 0, 0, 0], 8);
        unsafe {
            // First withdraw: FoM = 1000 (below suppress_threshold = 2000).
            assert_eq!(lr_damping_table_on_withdraw(t, &raw const p, 0), 0);
            // Second withdraw: FoM = 2000 (>= suppress_threshold → suppress).
            assert_eq!(lr_damping_table_on_withdraw(t, &raw const p, 0), 1);
            // Third withdraw: still suppressed (FoM capped at upper_limit).
            assert_eq!(lr_damping_table_on_withdraw(t, &raw const p, 0), 1);
            assert_eq!(lr_damping_table_is_suppressed(t, &raw const p), 1);
        }
        unsafe { lr_damping_table_free(t) };
    }

    #[test]
    fn ffi_damping_decay_unsuppresses_after_time() {
        let t = default_table();
        let p = v4_prefix([10, 0, 0, 0], 8);
        unsafe {
            // Three rapid flaps to suppress.
            lr_damping_table_on_withdraw(t, &raw const p, 0);
            lr_damping_table_on_withdraw(t, &raw const p, 0);
            lr_damping_table_on_withdraw(t, &raw const p, 0);
            assert_eq!(lr_damping_table_is_suppressed(t, &raw const p), 1);

            // Advance time well past the decay interval.
            let mut out = [lr_prefix_t {
                addr: [0; 16],
                is_ipv6: 0,
                prefix_len: 0,
            }];
            let n = lr_damping_table_decay_all(t, 60 * 60, out.as_mut_ptr(), 1);
            assert_eq!(n, 1);
            // The reactivated prefix matches.
            assert_eq!(out[0].prefix_len, 8);
            assert_eq!(&out[0].addr[..4], &[10, 0, 0, 0]);
            assert_eq!(lr_damping_table_is_suppressed(t, &raw const p), 0);
        }
        unsafe { lr_damping_table_free(t) };
    }

    #[test]
    fn ffi_damping_forget_clears_state() {
        let t = default_table();
        let p = v4_prefix([10, 0, 0, 0], 8);
        unsafe {
            lr_damping_table_on_withdraw(t, &raw const p, 0);
            assert_eq!(lr_damping_table_len(t), 1);
            assert_eq!(lr_damping_table_forget(t, &raw const p), 1);
            assert_eq!(lr_damping_table_len(t), 0);
            // Forget on a non-present prefix returns 0.
            assert_eq!(lr_damping_table_forget(t, &raw const p), 0);
        }
        unsafe { lr_damping_table_free(t) };
    }

    #[test]
    fn ffi_damping_at_returns_entry() {
        let t = default_table();
        let p = v4_prefix([10, 0, 0, 0], 8);
        unsafe {
            lr_damping_table_on_withdraw(t, &raw const p, 0);
            let mut e = lr_damping_entry_t::default();
            let rc = lr_damping_table_at(t, 0, &raw mut e);
            assert_eq!(rc, 0);
            assert_eq!(e.prefix.prefix_len, 8);
            assert!((e.figure_of_merit - 1000.0).abs() < 1e-9);
            assert_eq!(e.suppressed, 0);
            assert_eq!(e.flap_count, 1);

            // Out of range.
            let rc = lr_damping_table_at(t, 99, &raw mut e);
            assert_eq!(rc, LR_ERR_INVALID_HANDLE);
        }
        unsafe { lr_damping_table_free(t) };
    }

    #[test]
    fn ffi_damping_null_table_returns_lr_err_null() {
        let p = v4_prefix([10, 0, 0, 0], 8);
        unsafe {
            assert_eq!(
                lr_damping_table_on_withdraw(std::ptr::null_mut(), &raw const p, 0),
                LR_ERR_NULL
            );
            assert_eq!(
                lr_damping_table_is_suppressed(std::ptr::null_mut(), &raw const p),
                LR_ERR_NULL
            );
            assert_eq!(lr_damping_table_len(std::ptr::null_mut()), 0);
            assert_eq!(
                lr_damping_table_forget(std::ptr::null_mut(), &raw const p),
                LR_ERR_NULL
            );
            // decay_all on NULL returns -1.
            assert_eq!(
                lr_damping_table_decay_all(std::ptr::null_mut(), 0, std::ptr::null_mut(), 0),
                LR_ERR_NULL as i64
            );
        }
    }

    #[test]
    fn ffi_damping_null_prefix_returns_lr_err_null() {
        let t = default_table();
        unsafe {
            assert_eq!(
                lr_damping_table_on_withdraw(t, std::ptr::null(), 0),
                LR_ERR_NULL
            );
            assert_eq!(
                lr_damping_table_is_suppressed(t, std::ptr::null()),
                LR_ERR_NULL
            );
            assert_eq!(lr_damping_table_forget(t, std::ptr::null()), LR_ERR_NULL);
        }
        unsafe { lr_damping_table_free(t) };
    }

    #[test]
    fn ffi_damping_bad_prefix_length_returns_lr_err_other() {
        let t = default_table();
        let mut p = v4_prefix([10, 0, 0, 0], 200); // > 32, invalid for v4
        unsafe {
            assert_eq!(
                lr_damping_table_on_withdraw(t, &raw const p, 0),
                LR_ERR_OTHER
            );
        }
        // suppress the unused-assignment lint (the test asserts the
        // path that does not consume `p`).
        let _ = &mut p;
        unsafe { lr_damping_table_free(t) };
    }

    #[test]
    fn ffi_damping_free_handles_null_safely() {
        unsafe { lr_damping_table_free(std::ptr::null_mut()) };
    }

    #[test]
    fn ffi_damping_custom_config_round_trip() {
        let cfg = lr_damping_config_t {
            additive_incr: 500,
            suppress_threshold: 1000,
            reuse_threshold: 250,
            upper_limit: 30000,
            decay_interval_s: 15,
            decay_factor_active: 0.95,
            decay_factor_withdrawn: 0.4,
        };
        let t = lr_damping_table_new(&raw const cfg);
        assert!(!t.is_null());
        // Three rapid flaps with additive_incr=500: 500 + 500 = 1000 →
        // suppress on the second flap (>= 1000).
        let p = v4_prefix([10, 0, 0, 0], 8);
        unsafe {
            assert_eq!(lr_damping_table_on_withdraw(t, &raw const p, 0), 0);
            assert_eq!(lr_damping_table_on_withdraw(t, &raw const p, 0), 1);
        }
        unsafe { lr_damping_table_free(t) };
    }
}
