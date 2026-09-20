//! End-to-end tests for the `lrctl` operational CLI (ROADMAP-v3 D12).
//!
//! Each test spawns the real `lr-daemon` binary (`CARGO_BIN_EXE_lr-daemon`)
//! on a loopback port with `--api-socket`, then runs the real `lrctl`
//! binary (`CARGO_BIN_EXE_lrctl`) as a subprocess and asserts the
//! stdout. This is the same shape `daemon_runtime.rs` uses for the
//! API-socket round-trip tests; the difference is the client side is
//! the `lrctl` binary, not a hand-rolled `UnixStream` write.
//!
//! `filter compile` is a client-side command (no daemon), so its
//! tests live in the same file but do not spawn a daemon.

#![cfg(unix)]

use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

const DAEMON: &str = env!("CARGO_BIN_EXE_lr-daemon");
const LRCTL: &str = env!("CARGO_BIN_EXE_lrctl");

/// A spawned `lr-daemon` with its log file path so the test can wait
/// for the "runtime API on" marker before issuing `lrctl` commands.
struct Daemon {
    child: std::process::Child,
    log: std::path::PathBuf,
}

impl Daemon {
    fn spawn(args: &[&str], tag: &str) -> Self {
        let log = std::env::temp_dir().join(format!(
            "lrctl-daemon-test-{tag}-{}.log",
            std::process::id()
        ));
        let log_file = std::fs::File::create(&log).expect("create log file");
        let child = Command::new(DAEMON)
            .args(args)
            .stdout(Stdio::from(log_file.try_clone().expect("clone stdout")))
            .stderr(Stdio::from(log_file))
            .spawn()
            .expect("spawn lr-daemon");
        Self { child, log }
    }

    /// Block until the daemon's log contains `needle` (5 s deadline).
    fn wait_log(&self, needle: &str, what: &str) {
        let deadline = Instant::now() + Duration::from_secs(15);
        while Instant::now() < deadline {
            if let Ok(text) = std::fs::read_to_string(&self.log) {
                if text.contains(needle) {
                    return;
                }
            }
            thread::sleep(Duration::from_millis(100));
        }
        let text = std::fs::read_to_string(&self.log).unwrap_or_default();
        panic!("daemon did not report '{what}' within 15 s; log:\n{text}");
    }

    /// Block until the process exits; return (exit_ok, log_text).
    fn wait_exit(mut self) -> (bool, String) {
        let deadline = Instant::now() + Duration::from_secs(15);
        loop {
            match self.child.try_wait() {
                Ok(Some(status)) => {
                    let log = std::fs::read_to_string(&self.log).unwrap_or_default();
                    return (status.success(), log);
                }
                Ok(None) => {
                    if Instant::now() >= deadline {
                        let _ = self.child.kill();
                        let _ = self.child.wait();
                        let log = std::fs::read_to_string(&self.log).unwrap_or_default();
                        panic!("daemon did not exit within 15 s; log:\n{log}");
                    }
                    thread::sleep(Duration::from_millis(50));
                }
                Err(_) => break,
            }
        }
        let log = std::fs::read_to_string(&self.log).unwrap_or_default();
        (false, log)
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        // Belt-and-braces: a panic before `shutdown` leaves the daemon
        // running, which would hang the test harness. Kill on drop.
        let _ = self.child.kill();
        // Bounded wait: a daemon wedged in a syscall (D-state,
        // e.g. a TCP close that never returns) cannot be reaped
        // immediately even after SIGKILL — the kernel queues the
        // signal but does not deliver it until the syscall exits.
        // A blocking `wait()` here would then stall the test binary
        // indefinitely, which is the historic macOS CI hang pattern.
        // Poll `try_wait()` for up to 10 s; if the process is still
        // alive after SIGKILL + 10 s, leave the zombie for init to
        // reap when the test process exits.
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            match self.child.try_wait() {
                Ok(Some(_)) => break,
                Ok(None) => {
                    if Instant::now() >= deadline {
                        let _ = self.child.kill();
                        let _ = self.child.wait();
                        break;
                    }
                    thread::sleep(Duration::from_millis(50));
                }
                Err(_) => break,
            }
        }
    }
}

/// Run `lrctl` with the given args; return (exit_status_ok, stdout, stderr).
fn lrctl(args: &[&str]) -> (bool, String, String) {
    let output = Command::new(LRCTL).args(args).output().expect("run lrctl");
    (
        output.status.success(),
        String::from_utf8_lossy(&output.stdout).into_owned(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
    )
}

/// `lrctl status` returns the daemon's `status` reply verbatim.
#[test]
fn lrctl_status_proxies_daemon_reply() {
    let socket =
        std::env::temp_dir().join(format!("lrctl-test-status-{}.sock", std::process::id()));
    let _ = std::fs::remove_file(&socket);
    let d = Daemon::spawn(
        &[
            "--local-as",
            "64512",
            "--peer-as",
            "64513",
            "--router-id",
            "10.0.0.1",
            "--listen",
            "127.0.0.1:18091",
            "--network",
            "203.0.113.0/24",
            "--api-socket",
            socket.to_str().unwrap(),
        ],
        "status",
    );
    d.wait_log("runtime API on", "api socket up");

    let (ok, stdout, stderr) = lrctl(&["--socket", socket.to_str().unwrap(), "status"]);
    assert!(ok, "lrctl status failed: stderr={stderr}");
    assert!(stdout.contains("version "), "status stdout: {stdout}");
    assert!(stdout.contains("local-as 64512"), "status stdout: {stdout}");
    assert!(
        stdout.contains("router-id 10.0.0.1"),
        "status stdout: {stdout}"
    );
    assert!(stdout.contains("rib-entries 1"), "status stdout: {stdout}");

    // `--socket` placement after the subcommand works too.
    let (ok, stdout, _stderr) = lrctl(&["status", "--socket", socket.to_str().unwrap()]);
    assert!(ok, "lrctl status (post-flag) failed");
    assert!(stdout.contains("local-as 64512"));

    // Clean up via `lrctl shutdown` — exercises the shutdown path too.
    let (ok, stdout, _stderr) = lrctl(&["--socket", socket.to_str().unwrap(), "shutdown"]);
    assert!(ok, "lrctl shutdown failed: stderr={stderr}");
    assert!(stdout.contains("shutting down"));
    let (exit_ok, _log) = d.wait_exit();
    assert!(exit_ok, "daemon must exit 0 after lrctl shutdown");
}

/// `lrctl sessions` returns one line per configured session.
#[test]
fn lrctl_sessions_lists_configured_session() {
    let socket =
        std::env::temp_dir().join(format!("lrctl-test-sessions-{}.sock", std::process::id()));
    let _ = std::fs::remove_file(&socket);
    let d = Daemon::spawn(
        &[
            "--local-as",
            "64512",
            "--peer-as",
            "64513",
            "--router-id",
            "10.0.0.1",
            "--listen",
            "127.0.0.1:18092",
            "--api-socket",
            socket.to_str().unwrap(),
        ],
        "sessions",
    );
    d.wait_log("runtime API on", "api socket up");

    let (ok, stdout, stderr) = lrctl(&["--socket", socket.to_str().unwrap(), "sessions"]);
    assert!(ok, "lrctl sessions failed: stderr={stderr}");
    assert!(stdout.contains("kind=bgp"), "sessions stdout: {stdout}");
    assert!(
        stdout.contains("local-as=64512"),
        "sessions stdout: {stdout}"
    );
    assert!(
        stdout.contains("peer-as=64513"),
        "sessions stdout: {stdout}"
    );

    // `sessions list` is the alias form the D12 roadmap names.
    let (ok, stdout, _stderr) = lrctl(&["--socket", socket.to_str().unwrap(), "sessions", "list"]);
    assert!(ok, "lrctl sessions list failed");
    assert!(stdout.contains("kind=bgp"));

    lrctl(&["--socket", socket.to_str().unwrap(), "shutdown"]);
    let _ = d.wait_exit();
}

/// `lrctl routes show` dumps the Loc-RIB; `routes show <prefix>`
/// filters to the matching prefix only.
#[test]
fn lrctl_routes_show_and_filter() {
    let socket =
        std::env::temp_dir().join(format!("lrctl-test-routes-{}.sock", std::process::id()));
    let _ = std::fs::remove_file(&socket);
    let d = Daemon::spawn(
        &[
            "--local-as",
            "64512",
            "--peer-as",
            "64513",
            "--router-id",
            "10.0.0.1",
            "--listen",
            "127.0.0.1:18093",
            "--network",
            "203.0.113.0/24",
            "--network",
            "198.51.100.0/24",
            "--api-socket",
            socket.to_str().unwrap(),
        ],
        "routes",
    );
    d.wait_log("runtime API on", "api socket up");

    // Full dump — both prefixes present.
    let (ok, stdout, stderr) = lrctl(&["--socket", socket.to_str().unwrap(), "routes", "show"]);
    assert!(ok, "lrctl routes show failed: stderr={stderr}");
    assert!(stdout.contains("203.0.113.0/24"), "routes stdout: {stdout}");
    assert!(
        stdout.contains("198.51.100.0/24"),
        "routes stdout: {stdout}"
    );

    // Filtered — only the requested prefix.
    let (ok, stdout, stderr) = lrctl(&[
        "--socket",
        socket.to_str().unwrap(),
        "routes",
        "show",
        "203.0.113.0/24",
    ]);
    assert!(ok, "lrctl routes show <prefix> failed: stderr={stderr}");
    assert!(
        stdout.contains("203.0.113.0/24"),
        "filtered stdout: {stdout}"
    );
    assert!(
        !stdout.contains("198.51.100.0/24"),
        "filtered stdout should not contain unrequested prefix: {stdout}"
    );

    // Non-existent prefix — exit 0, empty stdout, stderr note.
    let (ok, stdout, stderr) = lrctl(&[
        "--socket",
        socket.to_str().unwrap(),
        "routes",
        "show",
        "10.99.99.0/24",
    ]);
    assert!(ok, "lrctl routes show <missing> should exit 0");
    assert!(!stdout.contains("/24"), "stdout should be empty: {stdout}");
    assert!(
        stderr.contains("no route"),
        "stderr should note absence: {stderr}"
    );

    lrctl(&["--socket", socket.to_str().unwrap(), "shutdown"]);
    let _ = d.wait_exit();
}

/// `lrctl routes dump <path>` writes an MRT dump through the daemon's
/// `mrt <path>` command. Verifies the file exists and the daemon's
/// reply contains `mrt-dump`.
#[test]
fn lrctl_routes_dump_writes_mrt_file() {
    let socket = std::env::temp_dir().join(format!("lrctl-test-dump-{}.sock", std::process::id()));
    let _ = std::fs::remove_file(&socket);
    let dump_path =
        std::env::temp_dir().join(format!("lrctl-test-dump-{}.mrt", std::process::id()));
    let _ = std::fs::remove_file(&dump_path);

    let d = Daemon::spawn(
        &[
            "--local-as",
            "64512",
            "--peer-as",
            "64513",
            "--router-id",
            "10.0.0.1",
            "--listen",
            "127.0.0.1:18094",
            "--network",
            "203.0.113.0/24",
            "--api-socket",
            socket.to_str().unwrap(),
        ],
        "dump",
    );
    d.wait_log("runtime API on", "api socket up");

    let (ok, stdout, stderr) = lrctl(&[
        "--socket",
        socket.to_str().unwrap(),
        "routes",
        "dump",
        dump_path.to_str().unwrap(),
    ]);
    assert!(ok, "lrctl routes dump failed: stderr={stderr}");
    assert!(stdout.contains("mrt-dump"), "dump stdout: {stdout}");
    assert!(
        dump_path.exists(),
        "MRT dump file should exist at {}",
        dump_path.display()
    );
    // The dump file should be non-empty (peer table + RIB entry).
    let meta = std::fs::metadata(&dump_path).expect("dump metadata");
    assert!(meta.len() > 0, "MRT dump file should be non-empty");

    let _ = std::fs::remove_file(&dump_path);
    lrctl(&["--socket", socket.to_str().unwrap(), "shutdown"]);
    let _ = d.wait_exit();
}

/// `lrctl reload` proxies the daemon's `reload` command.
#[test]
fn lrctl_reload_proxies_reload_command() {
    let socket =
        std::env::temp_dir().join(format!("lrctl-test-reload-{}.sock", std::process::id()));
    let _ = std::fs::remove_file(&socket);
    let d = Daemon::spawn(
        &[
            "--local-as",
            "64512",
            "--peer-as",
            "64513",
            "--router-id",
            "10.0.0.1",
            "--listen",
            "127.0.0.1:18095",
            "--network",
            "203.0.113.0/24",
            "--api-socket",
            socket.to_str().unwrap(),
        ],
        "reload",
    );
    d.wait_log("runtime API on", "api socket up");

    let (ok, _stdout, _stderr) = lrctl(&["--socket", socket.to_str().unwrap(), "reload"]);
    // The daemon's `reload` callback returns the apply log lines; the
    // exit code is 0 unless the transport fails. We do not assert on
    // the body because the daemon's reload output depends on whether
    // the networks list changed (here it did not, so the apply log is
    // typically empty / "no change").
    assert!(ok, "lrctl reload should succeed");

    lrctl(&["--socket", socket.to_str().unwrap(), "shutdown"]);
    let _ = d.wait_exit();
}

/// `lrctl filter compile <body>` validates a filter DSL body
/// client-side — no daemon connection required. Positive and negative
/// cases pin the two paths.
#[test]
fn lrctl_filter_compile_validates_body() {
    // Positive: a simple accept-on-prefix filter.
    let (ok, stdout, stderr) = lrctl(&[
        "filter",
        "compile",
        "if net ~ 10.0.0.0/8 then accept; reject;",
    ]);
    assert!(ok, "valid filter should compile: stderr={stderr}");
    assert!(stdout.contains("ok"), "stdout: {stdout}");

    // Positive: a body spread across multiple args is re-joined.
    let (ok, stdout, _stderr) = lrctl(&[
        "filter",
        "compile",
        "let",
        "p",
        "=",
        "100;",
        "if",
        "bgp.local_pref",
        ">",
        "p",
        "then",
        "accept;",
        "reject;",
    ]);
    assert!(ok, "multi-arg body should compile");
    assert!(stdout.contains("ok"), "stdout: {stdout}");

    // Negative: an undeclared function call fails at parse time.
    let (ok, _stdout, stderr) = lrctl(&[
        "filter",
        "compile",
        "if typo_function(net) then accept; reject;",
    ]);
    assert!(!ok, "invalid filter should fail");
    assert!(
        stderr.contains("parse error"),
        "stderr should mention parse error: {stderr}"
    );
    // Issue #18 Phase 0: the diagnostic is rendered with a caret
    // snippet under the offending source line.
    assert!(
        stderr.contains("1 | if typo_function(net) then accept; reject;"),
        "stderr should show the source line: {stderr}"
    );
    assert!(stderr.contains('^'), "stderr should show a caret: {stderr}");
    assert!(
        stderr.contains("parse error at 1:4:"),
        "stderr should carry the 1-indexed position: {stderr}"
    );

    // Negative: empty body.
    let (ok, _stdout, stderr) = lrctl(&["filter", "compile", "{}"]);
    assert!(!ok, "empty body should fail");
    assert!(stderr.contains("parse error"), "stderr: {stderr}");
}

/// `lrctl help` exits 0 and lists every subcommand.
#[test]
fn lrctl_help_lists_subcommands() {
    let (ok, stdout, _stderr) = lrctl(&["help"]);
    assert!(ok);
    for needle in [
        "status",
        "sessions",
        "routes show",
        "routes dump",
        "reload",
        "shutdown",
        "filter compile",
    ] {
        assert!(
            stdout.contains(needle),
            "help should mention {needle}: {stdout}"
        );
    }
}

/// `lrctl` with no args prints usage and exits non-zero.
#[test]
fn lrctl_no_args_prints_usage_and_fails() {
    let (ok, _stdout, _stderr) = lrctl(&[]);
    assert!(!ok, "no args should exit non-zero");
}

/// `lrctl` against a non-existent socket exits non-zero with a
/// transport error on stderr.
#[test]
fn lrctl_transport_failure_exits_nonzero() {
    let bogus = std::env::temp_dir().join(format!("lrctl-test-bogus-{}.sock", std::process::id()));
    let _ = std::fs::remove_file(&bogus);
    let (ok, _stdout, stderr) = lrctl(&["--socket", bogus.to_str().unwrap(), "status"]);
    assert!(!ok, "transport failure should exit non-zero");
    assert!(
        stderr.contains("lrctl:"),
        "stderr should mention lrctl: {stderr}"
    );
}

/// `lrctl version` prints the binary version.
#[test]
fn lrctl_version_prints_version() {
    let (ok, stdout, _stderr) = lrctl(&["version"]);
    assert!(ok);
    assert!(stdout.contains("lrctl "), "version stdout: {stdout}");
}
