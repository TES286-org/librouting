//! End-to-end coverage for the LDP daemon's SIGHUP-driven
//! `[[ldp.bind]]` reload (issue #92).
//!
//! defects.txt `crates/lr-cli/src/daemon_ldp.rs:L507-L509` recorded
//! that the LDP daemon's SIGHUP-driven reload was a no-op (only the
//! log file was re-opened). The fix lands a `RebindOp` queue
//! between the reload closure and the pump, plus a pure
//! `compute_rebind_diff` / `parse_ldp_binds` / `reload_ldp_binds`
//! surface that the unit tests in `crates/lr-cli/src/daemon_ldp_tests.rs`
//! exercise against real config files.
//!
//! These tests exercise the CLI surface end-to-end through the real
//! `lr-daemon` binary's `config check` subcommand (no socket work —
//! `config check` loads + finalizes the config and exits). The
//! `[[ldp.bind]]` table parses cleanly through the same `load_config_file`
//! startup uses, and a config with multiple binds, label 0
//! (auto-allocate), and a non-default `ldp_port` all land in the
//! `DaemonConfig` the daemon would run with.
//!
//! The full SIGHUP → pump → engine path is exercised by the unit
//! tests' `reload_ldp_binds_*` cases (which call the same closure
//! body the daemon's reload closure calls, with real TOML config
//! files), so an end-to-end spawn + SIGHUP test would only
//! duplicate coverage and require root for the LDP UDP multicast
//! join. The daemon_ospf_rxmt.rs pattern (CLI + `config check`
//! without spawning the daemon) is the right level for this test
//! file.

#![cfg(unix)]

use std::process::{Command, Stdio};

const BIN: &str = env!("CARGO_BIN_EXE_lr-daemon");

/// `lr-daemon config check` accepts a config with one `[[ldp.bind]]`
/// entry and exits zero — the surface the operator hits at
/// config-editing time. A regression that broke the parser for the
/// new SIGHUP-reloadable `[[ldp.bind]]` table would surface here
/// before the daemon ever runs.
#[test]
fn config_check_accepts_single_ldp_bind() {
    let path = std::env::temp_dir().join(format!(
        "lr-config-check-ldp-bind-single-{}-{}.toml",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis()
    ));
    std::fs::write(
        &path,
        "protocol = \"ldp\"\n\n\
         [ldp]\nlabel_min = 1000\nlabel_max = 50000\nkeepalive_time = 15\n\
         link_hold_time = 15\ntargeted_hold_time = 45\n\n\
         [[ldp.targeted]]\naddress = \"192.0.2.5\"\n\n\
         [[ldp.bind]]\nprefix = \"203.0.113.0/24\"\nlabel = 24000\n",
    )
    .expect("write fixture");
    let out = Command::new(BIN)
        .args(["config", "check", path.to_str().unwrap()])
        .stdin(Stdio::null())
        .output()
        .expect("spawn lr-daemon config check");
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
    assert!(
        out.status.success(),
        "config check exited non-zero for single [[ldp.bind]]: {combined}"
    );
    let _ = std::fs::remove_file(&path);
}

/// `lr-daemon config check` accepts a config with multiple
/// `[[ldp.bind]]` entries (the shape a SIGHUP would re-parse from a
/// real LDP edge router config). The reload closure's
/// `parse_ldp_binds` walks the same vector, so a regression that
/// broke multi-entry parsing would surface here before the daemon
/// ever runs.
#[test]
fn config_check_accepts_multiple_ldp_binds() {
    let path = std::env::temp_dir().join(format!(
        "lr-config-check-ldp-bind-multi-{}-{}.toml",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis()
    ));
    std::fs::write(
        &path,
        "protocol = \"ldp\"\n\n\
         [ldp]\nlabel_min = 1000\nlabel_max = 50000\nkeepalive_time = 15\n\
         link_hold_time = 15\ntargeted_hold_time = 45\n\n\
         [[ldp.targeted]]\naddress = \"192.0.2.5\"\n\n\
         [[ldp.bind]]\nprefix = \"203.0.113.0/24\"\nlabel = 24000\n\n\
         [[ldp.bind]]\nprefix = \"198.51.100.0/24\"\nlabel = 24001\n\n\
         [[ldp.bind]]\nprefix = \"192.0.2.0/24\"\nlabel = 24002\n",
    )
    .expect("write fixture");
    let out = Command::new(BIN)
        .args(["config", "check", path.to_str().unwrap()])
        .stdin(Stdio::null())
        .output()
        .expect("spawn lr-daemon config check");
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
    assert!(
        out.status.success(),
        "config check exited non-zero for multiple [[ldp.bind]] entries: {combined}"
    );
    let _ = std::fs::remove_file(&path);
}

/// `lr-daemon config check` accepts a config that uses `label = 0`
/// for auto-allocation. `DaemonConfig::finalize_ldp` resolves
/// `label = 0` to the first free value in the `[ldp] label_min
/// ..= label_max` window before the daemon's reload closure calls
/// `parse_ldp_binds`, so the SIGHUP-driven reload sees the resolved
/// label value (and the diff against the live binds works on the
/// resolved value, not the placeholder 0).
#[test]
fn config_check_accepts_auto_allocate_label_zero() {
    let path = std::env::temp_dir().join(format!(
        "lr-config-check-ldp-bind-auto-{}-{}.toml",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis()
    ));
    std::fs::write(
        &path,
        "protocol = \"ldp\"\n\n\
         [ldp]\nlabel_min = 1000\nlabel_max = 2000\nkeepalive_time = 15\n\
         link_hold_time = 15\ntargeted_hold_time = 45\n\n\
         [[ldp.targeted]]\naddress = \"192.0.2.5\"\n\n\
         [[ldp.bind]]\nprefix = \"203.0.113.0/24\"\nlabel = 0\n",
    )
    .expect("write fixture");
    let out = Command::new(BIN)
        .args(["config", "check", path.to_str().unwrap()])
        .stdin(Stdio::null())
        .output()
        .expect("spawn lr-daemon config check");
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
    assert!(
        out.status.success(),
        "config check exited non-zero for auto-allocate label=0: {combined}"
    );
    let _ = std::fs::remove_file(&path);
}

/// `lr-daemon config check` rejects a config with a duplicate
/// `[[ldp.bind]]` prefix. `DaemonConfig::finalize_ldp` returns
/// `Err("[[ldp.bind]] prefix X bound twice")` so a SIGHUP that
/// re-parses a config with a duplicate cannot reach the reload
/// closure — the operator's existing config keeps running (never
/// half-apply).
#[test]
fn config_check_rejects_duplicate_ldp_bind_prefix() {
    let path = std::env::temp_dir().join(format!(
        "lr-config-check-ldp-bind-dup-{}-{}.toml",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis()
    ));
    std::fs::write(
        &path,
        "protocol = \"ldp\"\n\n\
         [ldp]\nlabel_min = 1000\nlabel_max = 50000\nkeepalive_time = 15\n\
         link_hold_time = 15\ntargeted_hold_time = 45\n\n\
         [[ldp.targeted]]\naddress = \"192.0.2.5\"\n\n\
         [[ldp.bind]]\nprefix = \"203.0.113.0/24\"\nlabel = 24000\n\n\
         [[ldp.bind]]\nprefix = \"203.0.113.0/24\"\nlabel = 24001\n",
    )
    .expect("write fixture");
    let out = Command::new(BIN)
        .args(["config", "check", path.to_str().unwrap()])
        .stdin(Stdio::null())
        .output()
        .expect("spawn lr-daemon config check");
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
    assert!(
        !out.status.success(),
        "config check must exit non-zero for duplicate [[ldp.bind]] prefix: {combined}"
    );
    assert!(
        combined.contains("bound twice"),
        "expected 'bound twice' diagnostic for duplicate prefix; got:\n{combined}"
    );
    let _ = std::fs::remove_file(&path);
}

/// `lr-daemon config check` rejects a `[[ldp.bind]]` entry with a
/// label outside the platform-writable range (RFC 3032 §1.2:
/// 16..=1048575; 0 is reserved for auto-allocation).
#[test]
fn config_check_rejects_label_out_of_range() {
    let path = std::env::temp_dir().join(format!(
        "lr-config-check-ldp-bind-labelrange-{}-{}.toml",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis()
    ));
    std::fs::write(
        &path,
        "protocol = \"ldp\"\n\n\
         [ldp]\nlabel_min = 1000\nlabel_max = 50000\nkeepalive_time = 15\n\
         link_hold_time = 15\ntargeted_hold_time = 45\n\n\
         [[ldp.targeted]]\naddress = \"192.0.2.5\"\n\n\
         [[ldp.bind]]\nprefix = \"203.0.113.0/24\"\nlabel = 8\n",
    )
    .expect("write fixture");
    let out = Command::new(BIN)
        .args(["config", "check", path.to_str().unwrap()])
        .stdin(Stdio::null())
        .output()
        .expect("spawn lr-daemon config check");
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
    assert!(
        !out.status.success(),
        "config check must exit non-zero for label < 16: {combined}"
    );
    let _ = std::fs::remove_file(&path);
}
