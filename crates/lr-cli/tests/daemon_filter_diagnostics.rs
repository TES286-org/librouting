//! End-to-end tests for positioned filter diagnostics (issue #18
//! Phase 0 — spans + structured diagnostics).
//!
//! The daemon compiles every `[[filter]]` body at startup
//! (`daemon_policy::build_filters`). When a body fails to parse, the
//! startup error must carry the position of the offending construct
//! *and* a caret snippet rendered from the body source, so the
//! operator sees exactly which part of the filter failed without
//! re-counting lines by hand.

#![cfg(unix)]

use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

const DAEMON: &str = env!("CARGO_BIN_EXE_lr-daemon");

/// Write `text` to a unique temp config path and spawn `lr-daemon
/// --config <path>`, returning (exit status, combined output). The
/// daemon is expected to fail fast on an invalid filter, so a bounded
/// wait on process exit is enough.
fn run_daemon_with_config(tag: &str, toml: &str) -> (Option<i32>, String) {
    let path =
        std::env::temp_dir().join(format!("lr-filter-diag-{tag}-{}.toml", std::process::id()));
    std::fs::write(&path, toml).expect("write config");
    let log = std::env::temp_dir().join(format!("lr-filter-diag-{tag}-{}.log", std::process::id()));
    let log_file = std::fs::File::create(&log).expect("create log file");
    let mut child = Command::new(DAEMON)
        // Base identity flags: the CLI validates these before any
        // config-file content is examined.
        .args([
            "--local-as",
            "64512",
            "--peer-as",
            "64513",
            "--router-id",
            "203.0.113.1",
        ])
        .arg("--config")
        .arg(&path)
        .stdout(Stdio::from(log_file.try_clone().expect("clone stdout")))
        .stderr(Stdio::from(log_file))
        .spawn()
        .expect("spawn lr-daemon");
    // Invalid filters abort startup; give the process a bounded window.
    let deadline = Instant::now() + Duration::from_secs(15);
    let mut status = None;
    while Instant::now() < deadline {
        if let Ok(Some(s)) = child.try_wait() {
            status = s.code();
            break;
        }
        thread::sleep(Duration::from_millis(100));
    }
    let _ = child.kill();
    let _ = child.wait();
    let output = std::fs::read_to_string(&log).unwrap_or_default();
    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(&log);
    (status, output)
}

#[test]
fn invalid_filter_body_fails_startup_with_positioned_snippet() {
    // `bgp.typo` is an unknown bgp field — a parse-time error whose
    // span points at the `typo` identifier on the body's second line.
    // The multi-line body (a TOML `\n` escape) proves the reported
    // line/col are body-relative, not config-file-relative.
    let toml = "[[filter]]\nname = \"bad-in\"\nbody = \"accept;\\nbgp.typo = 1;\"\n";
    let (code, out) = run_daemon_with_config("bad-filter", toml);
    assert_eq!(
        code,
        Some(2),
        "daemon should exit 2 on a filter error; output:\n{out}"
    );
    // The error names the filter and the offending token's position.
    assert!(
        out.contains("filter 'bad-in': parse error at line 2 col 5"),
        "positioned error expected; output:\n{out}"
    );
    // The snippet shows the source line and a caret under the token.
    assert!(
        out.contains("bgp.typo = 1;"),
        "source line expected; output:\n{out}"
    );
    assert!(out.contains('^'), "caret expected; output:\n{out}");
}

#[test]
fn valid_filter_body_still_starts_clean() {
    // Sanity: the same shape with a valid body must not report a
    // filter error (the daemon proceeds past filter compilation — it
    // will fail later on missing peer/protocol config, or idle; we
    // only assert the filter error is absent).
    let toml = "[[filter]]\nname = \"ok-in\"\nbody = \"accept;\"\n";
    let (_code, out) = run_daemon_with_config("ok-filter", toml);
    assert!(
        !out.contains("filter 'ok-in': parse error"),
        "no filter error expected; output:\n{out}"
    );
}
