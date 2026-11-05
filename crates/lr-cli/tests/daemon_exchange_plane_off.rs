//! Complementary test for the exchange-plane feature gate (issue #92,
//! defects.txt `crates/lr-cli/tests/daemon_exchange_plane.rs:L21`).
//!
//! `daemon_exchange_plane.rs` is gated with
//! `#![cfg(all(unix, feature = "exchange-plane"))]` and proves the
//! daemon's opt-in path *works* when the W6.3 prototype is compiled
//! in: the session establishes, the record set flows, the key
//! mismatch drops records while keeping the route, and a one-sided
//! opt-in stays inert.
//!
//! This test exercises the opposite side of the gate. When the
//! binary is built WITHOUT the `exchange-plane` feature (the default
//! release build — `crates/lr-cli/Cargo.toml` declares the feature
//! off by default), an operator who writes `exchange_plane = true`
//! (or passes `--exchange-plane-key`) is asking for a surface the
//! binary cannot honour. The daemon must fail closed at startup
//! rather than silently run with a half-configured plane — the
//! `cfg(not(feature = "exchange-plane"))` arm in
//! `daemon.rs`'s peer loop returns `ExitCode::from(2)` and logs
//! `peer {label}: exchange_plane requested but this binary was built
//! without the exchange-plane feature`.
//!
//! Together the two tests cover both branches of the feature gate.
//! `cargo test` (default features) runs this test and skips
//! `daemon_exchange_plane.rs`; `cargo test --features exchange-plane`
//! runs the converse. The `CI` matrix exercises both shapes.

#![cfg(all(unix, not(feature = "exchange-plane")))]

use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

const BIN: &str = env!("CARGO_BIN_EXE_lr-daemon");

/// `--exchange-plane` flag alone: the global `cfg.exchange_plane = true`
/// triggers the fail-closed arm even when no key is configured.
#[test]
fn exchange_plane_flag_fails_closed_without_feature() {
    let log = spawn_and_wait(
        "xp-flag",
        &[
            "--local-as",
            "64512",
            "--peer-as",
            "64513",
            "--router-id",
            "10.0.0.1",
            "--local-address",
            "192.0.2.1",
            // Unreachable port: the daemon never dials before the
            // fail-closed gate fires (the per-peer `add_session`
            // registers the session synchronously; the dial is
            // deferred to the main loop the gate pre-empts).
            "--peer",
            "127.0.0.1:1",
            "--ebgp-policy",
            "accept-all",
            "--exchange-plane",
        ],
    );
    assert!(
        log.contains(
            "exchange_plane requested but this binary was built without the exchange-plane feature"
        ),
        "log must name the missing feature; got: {log}",
    );
}

/// `--exchange-plane-key` alone: a non-empty key list triggers the
/// same fail-closed arm even when the global `exchange_plane` flag is
/// not set. The contract is "asked for the plane, got no plane" — the
/// key surface is sufficient evidence of intent.
#[test]
fn exchange_plane_key_fails_closed_without_feature() {
    let log = spawn_and_wait(
        "xp-key",
        &[
            "--local-as",
            "64512",
            "--peer-as",
            "64513",
            "--router-id",
            "10.0.0.1",
            "--local-address",
            "192.0.2.1",
            "--peer",
            "127.0.0.1:1",
            "--ebgp-policy",
            "accept-all",
            // RFC 8452-style key id:secret. The daemon's feature-off
            // arm checks only the key list's emptiness; the bytes'
            // validity is the feature-on path's problem.
            "--exchange-plane-key",
            "1:000102030405060708090a0b0c0d0e0f",
        ],
    );
    assert!(
        log.contains(
            "exchange_plane requested but this binary was built without the exchange-plane feature"
        ),
        "log must name the missing feature; got: {log}",
    );
}

/// A config that asks for neither the flag nor a key must NOT trip
/// the fail-closed gate even when the feature is off — the binary
/// runs as a plain BGP daemon. This is the regression guard: a
/// future refactor that drops the `xp_requested` predicate onto a
/// wrong arm would silently break the plain-daemon path, and this
/// test fails first.
#[test]
fn plain_daemon_does_not_trip_exchange_plane_gate() {
    let log = spawn_and_wait_short(
        "xp-plain",
        &[
            "--local-as",
            "64512",
            "--peer-as",
            "64513",
            "--router-id",
            "10.0.0.1",
            "--local-address",
            "192.0.2.1",
            "--peer",
            "127.0.0.1:1",
            "--ebgp-policy",
            "accept-all",
        ],
    );
    assert!(
        !log.contains(
            "exchange_plane requested but this binary was built without the exchange-plane feature"
        ),
        "plain-daemon log must not name the exchange-plane gate; got: {log}",
    );
    // The startup banner still names the (off) plane, so a quick
    // sanity check that the banner printed keeps the test from
    // trivially passing on a daemon that crashed before the peer
    // loop.
    assert!(
        log.contains("exchange-plane: off"),
        "startup banner must show exchange-plane off; got: {log}",
    );
}

/// Spawn the daemon with `args`, wait for it to exit, assert exit
/// code 2 (the documented fail-closed code) and return the captured
/// log text. Panics if the daemon does not exit within 30 s or exits
/// with the wrong code — both shapes mean the gate regressed.
fn spawn_and_wait(tag: &str, args: &[&str]) -> String {
    spawn(tag, args, |child, log_path| {
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            match child.try_wait() {
                Ok(Some(status)) => {
                    assert!(
                        status.code() == Some(2),
                        "expected exit code 2 (fail-closed), got {status:?}; log: {}",
                        std::fs::read_to_string(log_path).unwrap_or_default(),
                    );
                    return;
                }
                Ok(None) => {
                    if Instant::now() >= deadline {
                        let _ = child.kill();
                        let _ = child.wait();
                        panic!(
                            "daemon did not exit within 30 s; log: {}",
                            std::fs::read_to_string(log_path).unwrap_or_default(),
                        );
                    }
                    thread::sleep(Duration::from_millis(50));
                }
                Err(e) => panic!("try_wait failed: {e}"),
            }
        }
    })
}

/// Same as [`spawn_and_wait`] but for the negative test (the plain
/// daemon must NOT trip the gate). The daemon reaches the main loop
/// and is then killed; we only assert the gate's log line is absent
/// and the startup banner printed the plane off.
fn spawn_and_wait_short(tag: &str, args: &[&str]) -> String {
    spawn(tag, args, |child, log_path| {
        // Wait long enough for the daemon to print the banner and
        // enter the peer loop. The fail-closed gate (if it fired)
        // would have exited within milliseconds; the plain-daemon
        // path stays in the main loop.
        let deadline = Instant::now() + Duration::from_secs(3);
        loop {
            match child.try_wait() {
                Ok(Some(status)) => {
                    panic!(
                        "plain daemon exited unexpectedly ({status:?}); log: {}",
                        std::fs::read_to_string(log_path).unwrap_or_default(),
                    );
                }
                Ok(None) => {
                    if Instant::now() >= deadline {
                        // Reached the main loop without tripping the
                        // gate — that is the success path. Kill the
                        // daemon and let the caller assert the log.
                        let _ = child.kill();
                        let _ = child.wait();
                        return;
                    }
                    thread::sleep(Duration::from_millis(50));
                }
                Err(e) => panic!("try_wait failed: {e}"),
            }
        }
    })
}

/// Common spawn helper: open a unique log file under `$TMPDIR`,
/// spawn the daemon with stdout+stderr redirected into it, run
/// `interact` to wait for the daemon (or kill it), then read the log
/// back. Returns the log text.
fn spawn<F: FnOnce(&mut std::process::Child, &std::path::Path)>(
    tag: &str,
    args: &[&str],
    interact: F,
) -> String {
    static LOG_SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let seq = LOG_SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let log_path = std::env::temp_dir().join(format!(
        "lr-daemon-xp-off-{tag}-{}-{seq}.log",
        std::process::id(),
    ));
    let _ = std::fs::remove_file(&log_path);
    let log_file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log_path)
        .expect("create log file");
    let mut child = Command::new(BIN)
        .args(args)
        .stdout(Stdio::from(log_file.try_clone().expect("clone stdout")))
        .stderr(Stdio::from(log_file))
        .spawn()
        .expect("spawn lr-daemon");
    interact(&mut child, &log_path);
    let log_text = std::fs::read_to_string(&log_path).unwrap_or_default();
    let _ = std::fs::remove_file(&log_path);
    log_text
}
