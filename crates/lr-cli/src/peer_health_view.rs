//! `show peer-health` renderer — the runtime API surface for issue
//! #99's per-peer flap suppression.
//!
//! Reads the live [`lr_peer_health::PeerHealthTable`] snapshot and
//! emits a summary line plus one line per `(peer, AFI/SAFI)` session:
//!
//! ```text
//! peer-health rollout=full sessions=2 degraded=1 peak-tier=L2
//! peer=1 afi=IPv4 safi=Unicast tier=L2 baseline=0.10 \
//!   short=212 mid=210 long=210 stale=3 updates=212 withdraws=0 \
//!   escalations=2 recoveries=0 peak-tier=L2
//! peer=2 afi=IPv4 safi=Unicast tier=L0 baseline=0.00 \
//!   short=0 mid=0 long=0 stale=0 updates=1 withdraws=0 \
//!   escalations=0 recoveries=0 peak-tier=L0
//! ```
//!
//! The summary line is always emitted, even when peer-health is off
//! (`rollout=off sessions=0 degraded=0 peak-tier=L0`) so a script can
//! rely on the line shape regardless of the daemon mode. Per-session
//! lines follow, sorted by `(peer_id, afi, safi)` (the canonical
//! order the snapshot iterator already enforces).
//!
//! AFI / SAFI names mirror the BIRD `show protocols address` output:
//! `IPv4` / `IPv6` for AFI and `Unicast` / `Multicast` /
//! `Labeled-Unicast` / `MPLS-VPN` / `Flow-Spec` for SAFI. Unknown
//! values render as their numeric form so new address families are
//! visible without a renderer update.

use std::fmt::Write as _;
use std::sync::{Arc, Mutex};

use lr_peer_health::PeerHealthTable;

/// Render the `show peer-health` body. `table` is `None` when the
/// daemon was started without `[bgp.peer_health]` (rollout = `off`);
/// the renderer then emits the summary line with `rollout=off
/// sessions=0` so the command is always safe to call.
pub fn render(table: Option<&Arc<Mutex<PeerHealthTable>>>) -> String {
    let mut out = String::with_capacity(512);
    let Some(table) = table else {
        let _ = writeln!(
            out,
            "peer-health rollout=off sessions=0 degraded=0 peak-tier=L0"
        );
        let _ = writeln!(out, "note: peer-health flap suppression is not enabled (set [bgp.peer_health] rollout to observe/shadow/limited/full)");
        return out;
    };
    let table = match table.lock() {
        Ok(g) => g,
        Err(_) => {
            let _ = writeln!(out, "peer-health: error: table mutex poisoned");
            return out;
        }
    };
    let cfg = table.config();
    let sessions = table.len();
    let degraded = table.degraded_session_count();
    let peak = table.peak_tier();
    let _ = writeln!(
        out,
        "peer-health rollout={} sessions={} degraded={} peak-tier={}",
        cfg.rollout.name(),
        sessions,
        degraded,
        peak.name(),
    );
    for snap in table.snapshots() {
        let _ = writeln!(
            out,
            "peer={} afi={} safi={} tier={} baseline={:.4} \
             short={} mid={} long={} stale={} \
             updates={} withdraws={} escalations={} recoveries={} \
             peak-tier={} prefixes={}",
            snap.peer_id,
            afi_name(snap.family.afi),
            safi_name(snap.family.safi),
            snap.tier.name(),
            snap.baseline_rate,
            snap.short_window_count,
            snap.mid_window_count,
            snap.long_window_count,
            snap.stale_count,
            snap.counters.updates,
            snap.counters.withdraws,
            snap.counters.escalations,
            snap.counters.recoveries,
            snap.counters.peak_tier.name(),
            table.prefix_count(snap.peer_id, snap.family),
        );
    }
    out
}

/// AFI name mirror BIRD's `show protocols address` output.
fn afi_name(afi: u16) -> String {
    match afi {
        1 => "IPv4".to_string(),
        2 => "IPv6".to_string(),
        _ => format!("AFI({afi})"),
    }
}

/// SAFI name mirror BIRD's `show protocols address` output.
fn safi_name(safi: u8) -> String {
    match safi {
        1 => "Unicast".to_string(),
        2 => "Multicast".to_string(),
        4 => "Labeled-Unicast".to_string(),
        5 => "MPLS-VPN".to_string(),
        6 => "Flow-Spec".to_string(),
        _ => format!("SAFI({safi})"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lr_core::nlri::NlriFamily;
    use lr_peer_health::{
        GlobalBudgets, PeerHealthConfig, PeerHealthTable, RolloutMode, WindowBudget,
    };

    fn cfg_test(mode: RolloutMode) -> PeerHealthConfig {
        let mut c = PeerHealthConfig::default();
        c.rollout = mode;
        c.short_window = WindowBudget {
            window_s: 5,
            enter_multiplier: 10.0,
            exit_multiplier: 5.0,
            emergency_multiplier: 50.0,
        };
        c.mid_window = WindowBudget {
            window_s: 30,
            enter_multiplier: 10.0,
            exit_multiplier: 5.0,
            emergency_multiplier: 50.0,
        };
        c.long_window = WindowBudget {
            window_s: 120,
            enter_multiplier: 10.0,
            exit_multiplier: 5.0,
            emergency_multiplier: 50.0,
        };
        c.baseline_window_s = 480;
        c.min_baseline_rate_eps = 0.1;
        c.min_transition_interval_s = 0;
        c.min_recovery_interval_s = 0;
        c.dwell_s = [0, 0, 0, 0];
        c.max_stale_age_s = 60;
        c.tick_interval_s = 1;
        c.global_budgets = GlobalBudgets {
            soft_degraded: 100,
            hard_degraded: 0,
        };
        c
    }

    #[test]
    fn render_none_reports_off() {
        let body = render(None);
        assert!(
            body.contains("rollout=off sessions=0 degraded=0 peak-tier=L0"),
            "body: {body}"
        );
    }

    #[test]
    fn render_empty_table_shows_summary() {
        let table = Arc::new(Mutex::new(PeerHealthTable::new(cfg_test(
            RolloutMode::Observe,
        ))));
        let body = render(Some(&table));
        assert!(body.contains("rollout=observe sessions=0"), "body: {body}");
    }

    #[test]
    fn render_session_shows_tier_and_counts() {
        let table = Arc::new(Mutex::new(PeerHealthTable::new(cfg_test(
            RolloutMode::Full,
        ))));
        {
            let mut t = table.lock().unwrap();
            t.account_update(1, NlriFamily::IPV4_UNICAST, 1_000);
        }
        let body = render(Some(&table));
        assert!(
            body.contains("peer=1 afi=IPv4 safi=Unicast"),
            "body: {body}"
        );
        assert!(
            body.contains("updates=1"),
            "body should contain update count: {body}"
        );
    }
}
