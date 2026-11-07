//! Unit tests for the LDP daemon's SIGHUP-driven `[[ldp.bind]]` reload.
//!
//! The diff + queue shape is pure (no engine, no sockets), so the
//! tests stay in the unit-test crate and exercise the contract
//! end-to-end through [`compute_rebind_diff`], [`parse_ldp_binds`]
//! and [`reload_ldp_binds`] without spinning up a full daemon.
//!
//! End-to-end coverage (the SIGHUP-driven apply path through the
//! pump's `drain_rebinds` and the kernel MPLS mirror) lives in the
//! `tests/daemon_ldp_reload.rs` integration test, which spawns the
//! real `lr-daemon --protocol ldp` binary against an in-process LDP
//! peer and asserts the wire-level Label Mapping / Label Withdraw
//! messages flow on SIGHUP.

use super::*;
use crate::daemon_config::DaemonConfig;
use lr_core::addr::Prefix;
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

fn p(octets: [u8; 4], plen: u8) -> Prefix {
    Prefix::new_v4(octets, plen)
}

fn lbl(v: u32) -> GenericLabel {
    GenericLabel(v)
}

/// Two empty bind sets produce no ops.
#[test]
fn compute_rebind_diff_empty_to_empty() {
    let cur = BTreeMap::new();
    let tgt = BTreeMap::new();
    assert!(compute_rebind_diff(&cur, &tgt).is_empty());
}

/// Identical bind sets produce no ops — the steady-state SIGHUP that
/// re-parses the same config the daemon is already running.
#[test]
fn compute_rebind_diff_identical() {
    let mut cur = BTreeMap::new();
    cur.insert(p([10, 0, 0, 0], 24), lbl(100));
    cur.insert(p([10, 0, 1, 0], 24), lbl(101));
    let tgt = cur.clone();
    assert!(
        compute_rebind_diff(&cur, &tgt).is_empty(),
        "identical bind sets must produce zero ops"
    );
}

/// A new prefix advertises.
#[test]
fn compute_rebind_diff_add_prefix() {
    let cur = BTreeMap::new();
    let mut tgt = BTreeMap::new();
    tgt.insert(p([10, 0, 0, 0], 24), lbl(100));
    let ops = compute_rebind_diff(&cur, &tgt);
    assert_eq!(ops.len(), 1);
    assert_eq!(
        ops[0],
        RebindOp::Advertise {
            prefix: p([10, 0, 0, 0], 24),
            label: lbl(100)
        }
    );
}

/// A removed prefix withdraws.
#[test]
fn compute_rebind_diff_remove_prefix() {
    let mut cur = BTreeMap::new();
    cur.insert(p([10, 0, 0, 0], 24), lbl(100));
    let tgt = BTreeMap::new();
    let ops = compute_rebind_diff(&cur, &tgt);
    assert_eq!(ops.len(), 1);
    assert_eq!(
        ops[0],
        RebindOp::Withdraw {
            prefix: p([10, 0, 0, 0], 24),
            label: lbl(100)
        }
    );
}

/// A label change emits withdraw(OLD) then advertise(NEW) — RFC 5036
/// §3.5.7 ordering: a peer that has the old label must release it
/// before installing the new one.
#[test]
fn compute_rebind_diff_label_change_emits_withdraw_then_advertise() {
    let mut cur = BTreeMap::new();
    cur.insert(p([10, 0, 0, 0], 24), lbl(100));
    let mut tgt = BTreeMap::new();
    tgt.insert(p([10, 0, 0, 0], 24), lbl(200));
    let ops = compute_rebind_diff(&cur, &tgt);
    assert_eq!(ops.len(), 2);
    assert_eq!(
        ops[0],
        RebindOp::Withdraw {
            prefix: p([10, 0, 0, 0], 24),
            label: lbl(100)
        }
    );
    assert_eq!(
        ops[1],
        RebindOp::Advertise {
            prefix: p([10, 0, 0, 0], 24),
            label: lbl(200)
        }
    );
}

/// A SIGHUP that adds, removes, and changes labels all at once
/// produces the right mix in the right order — withdraws first
/// (regardless of cause), then advertises.
#[test]
fn compute_rebind_diff_mixed_change_orders_withdraws_first() {
    let mut cur = BTreeMap::new();
    cur.insert(p([10, 0, 0, 0], 24), lbl(100)); // kept
    cur.insert(p([10, 0, 1, 0], 24), lbl(101)); // removed
    cur.insert(p([10, 0, 2, 0], 24), lbl(102)); // label-changed
    let mut tgt = BTreeMap::new();
    tgt.insert(p([10, 0, 0, 0], 24), lbl(100)); // kept
    tgt.insert(p([10, 0, 2, 0], 24), lbl(200)); // label-changed
    tgt.insert(p([10, 0, 3, 0], 24), lbl(103)); // new
    let ops = compute_rebind_diff(&cur, &tgt);
    // Two withdraws (10.0.1.0/24 removed, 10.0.2.0/24 label-changed)
    // then two advertises (10.0.2.0/24 new label, 10.0.3.0/24 new).
    assert_eq!(ops.len(), 4);
    // First two are withdraws.
    assert!(matches!(ops[0], RebindOp::Withdraw { .. }));
    assert!(matches!(ops[1], RebindOp::Withdraw { .. }));
    // Last two are advertises.
    assert!(matches!(ops[2], RebindOp::Advertise { .. }));
    assert!(matches!(ops[3], RebindOp::Advertise { .. }));
    // The withdraws are in BTreeMap key-ascending order:
    // 10.0.1.0/24 then 10.0.2.0/24.
    assert_eq!(
        ops[0],
        RebindOp::Withdraw {
            prefix: p([10, 0, 1, 0], 24),
            label: lbl(101)
        }
    );
    assert_eq!(
        ops[1],
        RebindOp::Withdraw {
            prefix: p([10, 0, 2, 0], 24),
            label: lbl(102)
        }
    );
    // The advertises are also in key-ascending order:
    // 10.0.2.0/24 (new label) then 10.0.3.0/24 (new prefix).
    assert_eq!(
        ops[2],
        RebindOp::Advertise {
            prefix: p([10, 0, 2, 0], 24),
            label: lbl(200)
        }
    );
    assert_eq!(
        ops[3],
        RebindOp::Advertise {
            prefix: p([10, 0, 3, 0], 24),
            label: lbl(103)
        }
    );
}

/// `parse_ldp_binds` rounds a `DaemonConfig` with no binds to an
/// empty map (the startup path with no `[[ldp.bind]]` table).
#[test]
fn parse_ldp_binds_empty() {
    let cfg = DaemonConfig::default();
    let binds = parse_ldp_binds(&cfg).expect("empty config has no binds");
    assert!(binds.is_empty());
}

/// `parse_ldp_binds` parses a `[[ldp.bind]]` table with explicit
/// labels into a `BTreeMap<Prefix, GenericLabel>`. The label value
/// is what the daemon advertises downstream — auto-allocation (label
/// 0) was already resolved by `finalize_ldp` before this function
/// runs, so `parse_ldp_binds` sees the resolved value.
#[test]
fn parse_ldp_binds_explicit_labels() {
    let cfg = DaemonConfig {
        ldp_binds: vec![
            crate::daemon_config::LdpBindSpec {
                prefix: Some("10.0.0.0/24".into()),
                label: 100,
            },
            crate::daemon_config::LdpBindSpec {
                prefix: Some("10.0.1.0/24".into()),
                label: 101,
            },
        ],
        ..Default::default()
    };
    let binds = parse_ldp_binds(&cfg).expect("parses");
    assert_eq!(binds.len(), 2);
    assert_eq!(binds.get(&p([10, 0, 0, 0], 24)), Some(&lbl(100)));
    assert_eq!(binds.get(&p([10, 0, 1, 0], 24)), Some(&lbl(101)));
}

/// `parse_ldp_binds` skips a `[[ldp.bind]]` entry whose `prefix` is
/// `None` (`finalize_ldp` would already have rejected it; the
/// defensive skip keeps `parse_ldp_binds` safe to call on a
/// partially-finalized config in tests).
#[test]
fn parse_ldp_binds_skips_none_prefix() {
    let cfg = DaemonConfig {
        ldp_binds: vec![
            crate::daemon_config::LdpBindSpec {
                prefix: None,
                label: 100,
            },
            crate::daemon_config::LdpBindSpec {
                prefix: Some("10.0.0.0/24".into()),
                label: 101,
            },
        ],
        ..Default::default()
    };
    let binds = parse_ldp_binds(&cfg).expect("parses");
    assert_eq!(binds.len(), 1);
    assert_eq!(binds.get(&p([10, 0, 0, 0], 24)), Some(&lbl(101)));
}

/// `parse_ldp_binds` returns Err on a malformed prefix. The error
/// message names the offending entry so the operator can grep for it
/// in the config.
#[test]
fn parse_ldp_binds_rejects_bad_prefix() {
    let cfg = DaemonConfig {
        ldp_binds: vec![crate::daemon_config::LdpBindSpec {
            prefix: Some("not a prefix".into()),
            label: 100,
        }],
        ..Default::default()
    };
    let err = parse_ldp_binds(&cfg).expect_err("malformed prefix must Err");
    assert!(
        err.contains("not a prefix"),
        "error names the offending entry: {err}"
    );
}

/// `reload_ldp_binds` with `path = None` (a daemon started without
/// `--config`, e.g. via CLI flags) re-opens the log file and reports
/// "nothing to reload" — the queue and `current_binds` stay empty.
#[test]
fn reload_ldp_binds_no_path_no_op() {
    let pending = Arc::new(Mutex::new(Vec::<RebindOp>::new()));
    let current = Arc::new(Mutex::new(BTreeMap::new()));
    let lines = reload_ldp_binds(None, None, &pending, &current);
    // The log file reopen line is always present (best-effort).
    assert!(
        lines
            .iter()
            .any(|l| l.contains("log file re-opened") || l.contains("log file reopen failed")),
        "reload always reports log file reopen status: {lines:?}"
    );
    assert!(
        lines.iter().any(|l| l.contains("no config file in use")),
        "no-path reload reports 'no config file': {lines:?}"
    );
    assert!(pending.lock().unwrap().is_empty(), "queue untouched");
    assert!(
        current.lock().unwrap().is_empty(),
        "current_binds untouched"
    );
}

/// `reload_ldp_binds` with a path that does not exist reports the
/// read failure and keeps the queue + current_binds untouched —
/// never half-apply a SIGHUP that failed to parse.
#[test]
fn reload_ldp_binds_missing_file_keeps_state() {
    let pending = Arc::new(Mutex::new(vec![RebindOp::Advertise {
        prefix: p([10, 0, 0, 0], 24),
        label: lbl(100),
    }]));
    let mut current = BTreeMap::new();
    current.insert(p([10, 0, 0, 0], 24), lbl(100));
    let current = Arc::new(Mutex::new(current));
    let lines = reload_ldp_binds(
        Some("/nonexistent/ldp-config-that-does-not-exist.toml"),
        None,
        &pending,
        &current,
    );
    assert!(
        lines.iter().any(|l| l.contains("keeping current config")),
        "missing-file reload reports 'keeping current config': {lines:?}"
    );
    // The pre-existing op stays in the queue (the reload did not
    // touch it); the pre-existing bind stays in current_binds.
    assert_eq!(pending.lock().unwrap().len(), 1, "queue untouched");
    assert_eq!(current.lock().unwrap().len(), 1, "current_binds untouched");
}

/// A SIGHUP that re-parses the same config the daemon is already
/// running (the steady-state case) re-opens the log, reports zero
/// ops queued, and leaves the queue empty — a no-op SIGHUP that
/// the operator can run as a heartbeat.
#[test]
fn reload_ldp_binds_same_config_zero_ops() {
    // Write a TOML config file with one [[ldp.bind]] entry, then
    // re-parse it through the same path the daemon's reload closure
    // uses.
    let tmp = std::env::temp_dir().join(format!("lr-ldp-reload-same-{}.toml", std::process::id()));
    std::fs::write(
        &tmp,
        "[ldp]\n\
         [[ldp.bind]]\n\
         prefix = \"10.0.0.0/24\"\n\
         label = 100\n",
    )
    .expect("write tmp config");
    let pending = Arc::new(Mutex::new(Vec::<RebindOp>::new()));
    let mut current = BTreeMap::new();
    current.insert(p([10, 0, 0, 0], 24), lbl(100));
    let current = Arc::new(Mutex::new(current));
    let lines = reload_ldp_binds(tmp.to_str(), Some("toml"), &pending, &current);
    let _ = std::fs::remove_file(&tmp);
    assert!(
        lines
            .iter()
            .any(|l| l.contains("0 op(s) queued") || l.contains("0 ops queued")),
        "same-config reload reports zero ops: {lines:?}"
    );
    assert!(pending.lock().unwrap().is_empty(), "no ops queued");
}

/// A SIGHUP that adds a new `[[ldp.bind]]` entry to the running
/// config pushes exactly one `Advertise` op onto the queue and
/// updates `current_binds` to the new target.
#[test]
fn reload_ldp_binds_adds_new_bind() {
    let tmp = std::env::temp_dir().join(format!("lr-ldp-reload-add-{}.toml", std::process::id()));
    std::fs::write(
        &tmp,
        "[ldp]\n\
         [[ldp.bind]]\n\
         prefix = \"10.0.0.0/24\"\n\
         label = 100\n\
         [[ldp.bind]]\n\
         prefix = \"10.0.1.0/24\"\n\
         label = 101\n",
    )
    .expect("write tmp config");
    let pending = Arc::new(Mutex::new(Vec::<RebindOp>::new()));
    let mut current = BTreeMap::new();
    current.insert(p([10, 0, 0, 0], 24), lbl(100));
    let current = Arc::new(Mutex::new(current));
    let lines = reload_ldp_binds(tmp.to_str(), Some("toml"), &pending, &current);
    let _ = std::fs::remove_file(&tmp);
    assert!(
        lines
            .iter()
            .any(|l| l.contains("1 op(s) queued") || l.contains("1 ops queued")),
        "reload-with-one-add reports 1 op queued: {lines:?}"
    );
    let ops = pending.lock().unwrap().clone();
    assert_eq!(ops.len(), 1);
    assert_eq!(
        ops[0],
        RebindOp::Advertise {
            prefix: p([10, 0, 1, 0], 24),
            label: lbl(101)
        }
    );
    // `current_binds` is updated to the new target.
    let live = current.lock().unwrap();
    assert_eq!(live.len(), 2, "current_binds reflects the new target");
    assert_eq!(live.get(&p([10, 0, 1, 0], 24)), Some(&lbl(101)));
}

/// A SIGHUP that changes a label for an existing `[[ldp.bind]]` and
/// removes another pushes a withdraw+advertise pair for the
/// label-changed one and a withdraw for the removed one — withdraws
/// first, then advertises.
#[test]
fn reload_ldp_binds_label_change_and_remove() {
    let tmp = std::env::temp_dir().join(format!("lr-ldp-reload-mix-{}.toml", std::process::id()));
    std::fs::write(
        &tmp,
        "[ldp]\n\
         [[ldp.bind]]\n\
         prefix = \"10.0.0.0/24\"\n\
         label = 200\n",
    )
    .expect("write tmp config");
    let pending = Arc::new(Mutex::new(Vec::<RebindOp>::new()));
    let mut current = BTreeMap::new();
    current.insert(p([10, 0, 0, 0], 24), lbl(100));
    current.insert(p([10, 0, 1, 0], 24), lbl(101));
    let current = Arc::new(Mutex::new(current));
    let lines = reload_ldp_binds(tmp.to_str(), Some("toml"), &pending, &current);
    let _ = std::fs::remove_file(&tmp);
    assert!(
        lines
            .iter()
            .any(|l| l.contains("3 op(s) queued") || l.contains("3 ops queued")),
        "reload-with-label-change-and-remove reports 3 ops queued: {lines:?}"
    );
    let ops = pending.lock().unwrap().clone();
    assert_eq!(ops.len(), 3);
    // Withdraws first: 10.0.0.0/24 (label 100, label-change case)
    // then 10.0.1.0/24 (label 101, removed).
    assert!(matches!(ops[0], RebindOp::Withdraw { .. }));
    assert!(matches!(ops[1], RebindOp::Withdraw { .. }));
    // Advertise last: 10.0.0.0/24 with new label 200.
    assert!(matches!(ops[2], RebindOp::Advertise { .. }));
    assert_eq!(
        ops[0],
        RebindOp::Withdraw {
            prefix: p([10, 0, 0, 0], 24),
            label: lbl(100)
        }
    );
    assert_eq!(
        ops[1],
        RebindOp::Withdraw {
            prefix: p([10, 0, 1, 0], 24),
            label: lbl(101)
        }
    );
    assert_eq!(
        ops[2],
        RebindOp::Advertise {
            prefix: p([10, 0, 0, 0], 24),
            label: lbl(200)
        }
    );
}
