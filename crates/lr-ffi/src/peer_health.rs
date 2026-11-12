//! Standalone PeerHealthTable FFI (issue #99).
//!
//! Mirrors the public Rust API of `lr_peer_health::PeerHealthTable`
//! so an embedder can construct, drive and inspect a peer-health
//! table directly. The handle type [`lr_peer_health_table_t`] is
//! an opaque pointer; every entry point runs inside the crate's
//! `catch_unwind` barrier.

#![allow(unused_unsafe)]

use lr_peer_health::{PeerHealthConfig, PeerHealthTable, RolloutMode};

use crate::error::{set_last_error, LrError, LR_ERR_PANIC};
use crate::guarded;

const LR_ERR_NULL: i32 = LrError::Null as i32;
const LR_ERR_OTHER: i32 = LrError::Other as i32;

/// Opaque standalone `PeerHealthTable` handle.
#[repr(C)]
pub struct OpaquePeerHealthTable {
    _private: [u8; 0],
}

pub type lr_peer_health_table_t = *mut OpaquePeerHealthTable;

/// C-side configuration struct. Mirrors the key fields of
/// [`PeerHealthConfig`]; fields not exposed here pick up the
/// Rust-side default.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct lr_peer_health_config_t {
    /// Rollout mode: 0=Off, 1=Observe, 2=Shadow, 3=ShadowBestPath,
    /// 4=Limited, 5=Full.
    pub rollout: u8,
    /// Short window length in seconds.
    pub short_window_s: u64,
    /// Mid window length in seconds.
    pub mid_window_s: u64,
    /// Long window length in seconds.
    pub long_window_s: u64,
    /// Baseline window length in seconds.
    pub baseline_window_s: u64,
    /// Minimum transition interval in seconds.
    pub min_transition_interval_s: u64,
    /// Recovery cooldown in seconds.
    pub min_recovery_interval_s: u64,
    /// Maximum stale age in seconds.
    pub max_stale_age_s: u64,
    /// Tick interval in seconds.
    pub tick_interval_s: u64,
    /// Global soft degraded budget.
    pub soft_degraded: u32,
    /// Global hard degraded budget.
    pub hard_degraded: u32,
}

/// One projected session snapshot.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct lr_peer_health_session_t {
    pub peer_id: u64,
    pub afi: u16,
    pub safi: u8,
    pub baseline_rate: f64,
    /// Current effective tier (0..=3).
    pub tier: u8,
    pub updates: u64,
    pub withdraws: u64,
    pub escalations: u64,
    pub recoveries: u64,
    pub peak_tier: u8,
    pub stale_count: u64,
}

impl lr_peer_health_config_t {
    fn into_rust(self) -> PeerHealthConfig {
        let mut cfg = PeerHealthConfig::default();
        if let Some(r) = RolloutMode::from_u8(self.rollout) {
            cfg.rollout = r;
        }
        if self.short_window_s > 0 {
            cfg.short_window.window_s = self.short_window_s;
        }
        if self.mid_window_s > 0 {
            cfg.mid_window.window_s = self.mid_window_s;
        }
        if self.long_window_s > 0 {
            cfg.long_window.window_s = self.long_window_s;
        }
        if self.baseline_window_s > 0 {
            cfg.baseline_window_s = self.baseline_window_s;
        }
        if self.min_transition_interval_s > 0 {
            cfg.min_transition_interval_s = self.min_transition_interval_s;
        }
        if self.min_recovery_interval_s > 0 {
            cfg.min_recovery_interval_s = self.min_recovery_interval_s;
        }
        if self.max_stale_age_s > 0 {
            cfg.max_stale_age_s = self.max_stale_age_s;
        }
        if self.tick_interval_s > 0 {
            cfg.tick_interval_s = self.tick_interval_s;
        }
        if self.soft_degraded > 0 {
            cfg.global_budgets.soft_degraded = self.soft_degraded;
        }
        if self.hard_degraded > 0 {
            cfg.global_budgets.hard_degraded = self.hard_degraded;
        }
        cfg
    }
}

/// Construct a new standalone PeerHealthTable. The caller owns the
/// handle and must free it with [`lr_peer_health_table_free`].
///
/// Returns NULL on failure (panic or null config pointer).
#[no_mangle]
pub unsafe extern "C" fn lr_peer_health_table_new(
    cfg: *const lr_peer_health_config_t,
) -> lr_peer_health_table_t {
    guarded(
        || {
            if cfg.is_null() {
                set_last_error("null config pointer".to_string());
                return std::ptr::null_mut();
            }
            let rust_cfg = (*cfg).into_rust();
            let table = Box::new(PeerHealthTable::new(rust_cfg));
            Box::into_raw(table) as lr_peer_health_table_t
        },
        std::ptr::null_mut(),
    )
}

/// Free a table created with [`lr_peer_health_table_new`]. Safe to
/// call with NULL (no-op).
#[no_mangle]
pub unsafe extern "C" fn lr_peer_health_table_free(t: lr_peer_health_table_t) {
    guarded(
        || {
            if !t.is_null() {
                unsafe {
                    drop(Box::from_raw(t));
                }
            }
        },
        (),
    )
}

/// Account an UPDATE event. Returns the session's effective tier
/// (0..=3) after the state machine ran.
#[no_mangle]
pub unsafe extern "C" fn lr_peer_health_table_account_update(
    t: lr_peer_health_table_t,
    peer_id: u64,
    afi: u16,
    safi: u8,
    now_ms: u64,
) -> u8 {
    guarded(
        || {
            if t.is_null() {
                return 0;
            }
            let table = unsafe { &mut *(t as *mut PeerHealthTable) };
            let fam = lr_core::nlri::NlriFamily { afi, safi };
            table.account_update(peer_id, fam, now_ms).as_u8()
        },
        0,
    )
}

/// Account a withdraw event. Returns the effective tier.
#[no_mangle]
pub unsafe extern "C" fn lr_peer_health_table_account_withdraw(
    t: lr_peer_health_table_t,
    peer_id: u64,
    afi: u16,
    safi: u8,
    now_ms: u64,
) -> u8 {
    guarded(
        || {
            if t.is_null() {
                return 0;
            }
            let table = unsafe { &mut *(t as *mut PeerHealthTable) };
            let fam = lr_core::nlri::NlriFamily { afi, safi };
            table.account_withdraw(peer_id, fam, now_ms).as_u8()
        },
        0,
    )
}

/// Query the current effective tier for `(peer_id, family)`.
#[no_mangle]
pub unsafe extern "C" fn lr_peer_health_table_tier(
    t: lr_peer_health_table_t,
    peer_id: u64,
    afi: u16,
    safi: u8,
) -> u8 {
    guarded(
        || {
            if t.is_null() {
                return 0;
            }
            let table = unsafe { &*(t as *const PeerHealthTable) };
            let fam = lr_core::nlri::NlriFamily { afi, safi };
            table.tier(peer_id, fam).as_u8()
        },
        0,
    )
}

/// Run a periodic tick: transition tiers, sweep stale prefixes.
/// Returns the number of tier changes that fired.
#[no_mangle]
pub unsafe extern "C" fn lr_peer_health_table_tick(
    t: lr_peer_health_table_t,
    now_ms: u64,
) -> usize {
    guarded(
        || {
            if t.is_null() {
                return 0;
            }
            let table = unsafe { &mut *(t as *mut PeerHealthTable) };
            table.tick(now_ms).tier_changes.len()
        },
        0,
    )
}

/// Number of sessions the table has observed.
#[no_mangle]
pub unsafe extern "C" fn lr_peer_health_table_session_count(t: lr_peer_health_table_t) -> usize {
    guarded(
        || {
            if t.is_null() {
                return 0;
            }
            let table = unsafe { &*(t as *const PeerHealthTable) };
            table.len()
        },
        0,
    )
}

/// Number of currently-degraded sessions (tier > L0).
#[no_mangle]
pub unsafe extern "C" fn lr_peer_health_table_degraded_count(t: lr_peer_health_table_t) -> u32 {
    guarded(
        || {
            if t.is_null() {
                return 0;
            }
            let table = unsafe { &*(t as *const PeerHealthTable) };
            table.degraded_session_count()
        },
        0,
    )
}

/// Fill `out` with the session snapshot for `(peer_id, afi, safi)`.
/// Returns 0 on success, negative on error (session not found =
/// `LR_ERR_OTHER`).
#[no_mangle]
pub unsafe extern "C" fn lr_peer_health_table_session_snapshot(
    t: lr_peer_health_table_t,
    peer_id: u64,
    afi: u16,
    safi: u8,
    out: *mut lr_peer_health_session_t,
) -> i32 {
    guarded(
        || {
            if t.is_null() || out.is_null() {
                return LR_ERR_NULL;
            }
            let table = unsafe { &*(t as *const PeerHealthTable) };
            let fam = lr_core::nlri::NlriFamily { afi, safi };
            match table.session_snapshot(peer_id, fam) {
                Some(s) => {
                    unsafe {
                        *out = lr_peer_health_session_t {
                            peer_id: s.peer_id,
                            afi,
                            safi,
                            baseline_rate: s.baseline_rate,
                            tier: s.tier.as_u8(),
                            updates: s.counters.updates,
                            withdraws: s.counters.withdraws,
                            escalations: s.counters.escalations,
                            recoveries: s.counters.recoveries,
                            peak_tier: s.counters.peak_tier.as_u8(),
                            stale_count: s.stale_count as u64,
                        };
                    }
                    0
                }
                None => LR_ERR_OTHER,
            }
        },
        LR_ERR_PANIC,
    )
}
