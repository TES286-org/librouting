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
        static LOG_SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let seq = LOG_SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let log = std::env::temp_dir().join(format!(
            "lrctl-daemon-test-{tag}-{}-{seq}.log",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&log);
        let log_file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&log)
            .expect("create log file");
        let child = Command::new(DAEMON)
            .args(args)
            .stdout(Stdio::from(log_file.try_clone().expect("clone stdout")))
            .stderr(Stdio::from(log_file))
            .spawn()
            .expect("spawn lr-daemon");
        Self { child, log }
    }

    /// Block until the daemon's log contains `needle`. The deadline
    /// is generous (60 s) to tolerate tarpaulin's per-process
    /// instrumentation overhead, which can slow daemon startup
    /// well past the 15 s that was enough under plain `cargo test`.
    /// A real failure still surfaces — the deadline is bounded, and
    /// the panic message includes the full daemon log so the cause
    /// (bind failure, parse error, etc.) is visible.
    fn wait_log(&self, needle: &str, what: &str) {
        let deadline = Instant::now() + Duration::from_secs(60);
        while Instant::now() < deadline {
            if let Ok(text) = std::fs::read_to_string(&self.log) {
                if text.contains(needle) {
                    return;
                }
            }
            thread::sleep(Duration::from_millis(100));
        }
        let text = std::fs::read_to_string(&self.log).unwrap_or_default();
        panic!("daemon did not report '{what}' within 60 s; log:\n{text}");
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
        "roa list",
        "roa count",
        "reload",
        "shutdown",
        "filter compile",
        // Issue #52 BIRD-style `show` family.
        "show status",
        "show sessions [detail]",
        "show session <handle>",
        "show routes count",
        "show memory",
        // Issue #52 follow-up: write-side `session` ops.
        "session <handle> soft-in",
        "session <handle> refresh-in",
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

// ---------------------------------------------------------------------------

// Issue #52 — BIRD-style `lrctl show …` family.
//
// One e2e test per subcommand. Each spawns a real `lr-daemon` on a
// loopback port with `--api-socket`, then runs the real `lrctl`
// binary as a subprocess and asserts the stdout. Same shape as the
// `lrctl_status_proxies_daemon_reply` family above; kept in their own
// block so a regression in one does not mask the others.
// ---------------------------------------------------------------------------

/// Helper: spawn a daemon configured the way the `show …` tests need
/// (one BGP session + one originated prefix). Each test passes its
/// own `port` so parallel `cargo test` execution does not collide
/// on the listen socket (the existing tests above use distinct ports
/// 18091..18095 for the same reason).
fn spawn_show_daemon(tag: &str, port: &str) -> (std::path::PathBuf, Daemon) {
    let socket =
        std::env::temp_dir().join(format!("lrctl-test-show-{tag}-{}.sock", std::process::id()));
    let _ = std::fs::remove_file(&socket);
    let listen = format!("127.0.0.1:{port}");
    let d = Daemon::spawn(
        &[
            "--local-as",
            "64512",
            "--peer-as",
            "64513",
            "--router-id",
            "10.0.0.1",
            "--listen",
            &listen,
            "--network",
            "203.0.113.0/24",
            "--api-socket",
            socket.to_str().unwrap(),
        ],
        tag,
    );
    d.wait_log("runtime API on", "api socket up");
    (socket, d)
}

#[test]
fn lrctl_show_status_renders_extended_summary() {
    let (socket, d) = spawn_show_daemon("status", "18101");
    let (ok, stdout, stderr) = lrctl(&["--socket", socket.to_str().unwrap(), "show", "status"]);
    assert!(ok, "lrctl show status failed: stderr={stderr}");
    assert!(stdout.contains("version "), "show status stdout: {stdout}");
    assert!(
        stdout.contains("local-as 64512"),
        "show status stdout: {stdout}"
    );
    assert!(
        stdout.contains("sessions 1 established 0"),
        "show status stdout: {stdout}"
    );
    assert!(
        stdout.contains("rib-entries 1"),
        "show status stdout: {stdout}"
    );
    assert!(
        stdout.contains("kind=bgp total=1 established=0"),
        "show status stdout: {stdout}"
    );
    assert!(
        stdout.contains("memory rss-bytes="),
        "show status stdout: {stdout}"
    );

    // `lrctl show` with no sub maps to `show status` (BIRD shortcut).
    let (ok, stdout, _stderr) = lrctl(&["--socket", socket.to_str().unwrap(), "show"]);
    assert!(ok, "lrctl show (bare) failed");
    assert!(stdout.contains("sessions 1 established 0"));

    lrctl(&["--socket", socket.to_str().unwrap(), "shutdown"]);
    let _ = d.wait_exit();
}

#[test]
fn lrctl_show_sessions_extends_legacy_output() {
    let (socket, d) = spawn_show_daemon("sessions", "18102");
    let (ok, stdout, stderr) = lrctl(&["--socket", socket.to_str().unwrap(), "show", "sessions"]);
    assert!(ok, "lrctl show sessions failed: stderr={stderr}");
    // Legacy fields preserved.
    assert!(
        stdout.contains("kind=bgp"),
        "show sessions stdout: {stdout}"
    );
    assert!(
        stdout.contains("local-as=64512"),
        "show sessions stdout: {stdout}"
    );
    assert!(
        stdout.contains("peer-as=64513"),
        "show sessions stdout: {stdout}"
    );
    // New issue #52 fields present.
    assert!(
        stdout.contains("transitions="),
        "show sessions stdout: {stdout}"
    );
    assert!(
        stdout.contains("uptime-ms="),
        "show sessions stdout: {stdout}"
    );
    assert!(
        stdout.contains("last-error="),
        "show sessions stdout: {stdout}"
    );
    assert!(
        stdout.contains("last-keepalive-rx-ms="),
        "show sessions stdout: {stdout}"
    );

    // Detail block: multi-line, appended under the session line.
    let (ok, stdout, _stderr) = lrctl(&[
        "--socket",
        socket.to_str().unwrap(),
        "show",
        "sessions",
        "detail",
    ]);
    assert!(ok, "lrctl show sessions detail failed");
    assert!(
        stdout.contains("stats: established-at-ms="),
        "show sessions detail stdout: {stdout}"
    );
    assert!(
        stdout.contains("last-error: kind="),
        "show sessions detail stdout: {stdout}"
    );
    assert!(
        stdout.contains("last-keepalive-rx-ms="),
        "show sessions detail stdout: {stdout}"
    );

    // `show sessions list` is rejected — `list` belongs to the
    // legacy `sessions` command, not the new `show` family.
    let (ok, _stdout, stderr) = lrctl(&[
        "--socket",
        socket.to_str().unwrap(),
        "show",
        "sessions",
        "list",
    ]);
    assert!(!ok, "show sessions list should fail");
    assert!(
        stderr.contains("usage: lrctl show sessions [detail]"),
        "show sessions list stderr: {stderr}"
    );

    lrctl(&["--socket", socket.to_str().unwrap(), "shutdown"]);
    let _ = d.wait_exit();
}

#[test]
fn lrctl_show_session_handle_renders_deep_dive() {
    let (socket, d) = spawn_show_daemon("session", "18103");
    let (ok, stdout, stderr) =
        lrctl(&["--socket", socket.to_str().unwrap(), "show", "session", "1"]);
    assert!(ok, "lrctl show session 1 failed: stderr={stderr}");
    assert!(stdout.contains("handle 1"), "show session stdout: {stdout}");
    assert!(stdout.contains("kind bgp"), "show session stdout: {stdout}");
    assert!(
        stdout.contains("negotiated-hold-time"),
        "show session stdout: {stdout}"
    );
    assert!(
        stdout.contains("stats: established-at-ms="),
        "show session stdout: {stdout}"
    );
    assert!(
        stdout.contains("last-keepalive-rx-ms="),
        "show session stdout: {stdout}"
    );

    // Unknown handle: the daemon returns an error line, but the
    // transport itself succeeded — `lrctl` exits 1 because the
    // daemon's reply starts with `error:`.
    let (ok, stdout, _stderr) = lrctl(&[
        "--socket",
        socket.to_str().unwrap(),
        "show",
        "session",
        "999",
    ]);
    assert!(!ok, "lrctl show session 999 should exit non-zero");
    assert!(
        stdout.contains("error: no session with handle 999"),
        "show session 999 stdout: {stdout}"
    );

    // Non-numeric handle: client-side rejection, exit 2.
    let (ok, _stdout, stderr) = lrctl(&[
        "--socket",
        socket.to_str().unwrap(),
        "show",
        "session",
        "not-a-number",
    ]);
    assert!(!ok, "non-numeric handle should fail");
    assert!(
        stderr.contains("invalid session handle"),
        "non-numeric stderr: {stderr}"
    );

    lrctl(&["--socket", socket.to_str().unwrap(), "shutdown"]);
    let _ = d.wait_exit();
}

#[test]
fn lrctl_show_routes_count_groups_by_protocol() {
    let (socket, d) = spawn_show_daemon("routes-count", "18104");
    let (ok, stdout, stderr) = lrctl(&[
        "--socket",
        socket.to_str().unwrap(),
        "show",
        "routes",
        "count",
    ]);
    assert!(ok, "lrctl show routes count failed: stderr={stderr}");
    assert!(
        stdout.contains("total 1"),
        "show routes count stdout: {stdout}"
    );
    assert!(
        stdout.contains("proto="),
        "show routes count stdout: {stdout}"
    );

    lrctl(&["--socket", socket.to_str().unwrap(), "shutdown"]);
    let _ = d.wait_exit();
}

#[test]
fn lrctl_show_memory_renders_rss_and_vsize() {
    let (socket, d) = spawn_show_daemon("memory", "18105");
    let (ok, stdout, stderr) = lrctl(&["--socket", socket.to_str().unwrap(), "show", "memory"]);
    assert!(ok, "lrctl show memory failed: stderr={stderr}");
    assert!(
        stdout.contains("uptime-secs "),
        "show memory stdout: {stdout}"
    );
    assert!(
        stdout.contains("rss-bytes "),
        "show memory stdout: {stdout}"
    );
    assert!(
        stdout.contains("vsize-bytes "),
        "show memory stdout: {stdout}"
    );

    lrctl(&["--socket", socket.to_str().unwrap(), "shutdown"]);
    let _ = d.wait_exit();
}

#[test]
fn lrctl_show_unknown_subcommand_exits_nonzero() {
    let (socket, d) = spawn_show_daemon("unknown", "18106");
    // The client validates the sub-command locally (matches the
    // existing `routes dump`/`shutdown <bogus>` family that returns
    // exit 2 with a usage hint on stderr, without round-tripping to
    // the daemon). The daemon's own `show bogus` reply (which would
    // surface `error: unknown show sub-command 'bogus'`) is covered
    // by the api.rs unit test instead.
    let (ok, _stdout, stderr) = lrctl(&["--socket", socket.to_str().unwrap(), "show", "bogus"]);
    assert!(!ok, "lrctl show bogus should exit non-zero");
    assert!(
        stderr.contains("error: unknown show subcommand 'bogus'"),
        "show bogus stderr: {stderr}"
    );
    assert!(
        stderr.contains("usage: lrctl show"),
        "show bogus stderr should print usage: {stderr}"
    );

    lrctl(&["--socket", socket.to_str().unwrap(), "shutdown"]);
    let _ = d.wait_exit();
}

// `lrctl ping` — round-trip health check. The daemon is up; `ping`
// must exit 0 with `ok Nms` (or a JSON object under --json).
// ---------------------------------------------------------------------------
#[test]
fn lrctl_ping_returns_ok_when_daemon_is_up() {
    let (socket, d) = spawn_show_daemon("ping", "18110");
    let (ok, stdout, stderr) = lrctl(&["--socket", socket.to_str().unwrap(), "ping"]);
    assert!(
        ok,
        "lrctl ping should exit 0 when daemon is up: stderr={stderr}"
    );
    assert!(
        stdout.starts_with("ok "),
        "ping stdout should start with 'ok ': {stdout}"
    );
    assert!(
        stdout.ends_with("ms\n"),
        "ping stdout should end with 'ms\\n': {stdout}"
    );

    lrctl(&["--socket", socket.to_str().unwrap(), "shutdown"]);
    let _ = d.wait_exit();
}

#[test]
fn lrctl_ping_json_emits_object_with_round_trip_ms() {
    let (socket, d) = spawn_show_daemon("ping-json", "18111");
    let (ok, stdout, stderr) = lrctl(&["--socket", socket.to_str().unwrap(), "--json", "ping"]);
    assert!(ok, "lrctl --json ping should exit 0: stderr={stderr}");
    // The JSON shape is `{"ok":true,"round_trip_ms":N}`. Parse just
    // enough to assert the keys are present.
    assert!(
        stdout.contains("\"ok\":true"),
        "ping JSON should have ok:true: {stdout}"
    );
    assert!(
        stdout.contains("\"round_trip_ms\":"),
        "ping JSON should have round_trip_ms: {stdout}"
    );

    lrctl(&["--socket", socket.to_str().unwrap(), "shutdown"]);
    let _ = d.wait_exit();
}

#[test]
fn lrctl_ping_fails_when_daemon_is_down() {
    // No daemon spawned — connect should fail.
    let socket =
        std::env::temp_dir().join(format!("lrctl-test-ping-down-{}.sock", std::process::id()));
    let _ = std::fs::remove_file(&socket);
    let (ok, stdout, _stderr) = lrctl(&["--socket", socket.to_str().unwrap(), "ping"]);
    assert!(!ok, "lrctl ping against no daemon should exit non-zero");
    assert!(
        stdout.starts_with("fail "),
        "ping stdout against no daemon should start with 'fail ': {stdout}"
    );
}

// `lrctl neighbor` — BIRD-style alias for `sessions`/`show session`.
// ---------------------------------------------------------------------------
#[test]
fn lrctl_neighbor_lists_sessions() {
    let (socket, d) = spawn_show_daemon("neighbor", "18112");
    let (ok, stdout, stderr) = lrctl(&["--socket", socket.to_str().unwrap(), "neighbor"]);
    assert!(ok, "lrctl neighbor should exit 0: stderr={stderr}");
    // The alias must produce the same shape as `lrctl sessions`:
    // one line per session, starting with `#1`.
    assert!(
        stdout.contains("#1 kind=bgp"),
        "neighbor stdout should list session #1: {stdout}"
    );
    assert!(
        stdout.contains("local-as=64512"),
        "neighbor stdout should carry the configured local-as: {stdout}"
    );

    // `neighbor 1` is an alias for `show session 1`.
    let (ok, stdout, _stderr) = lrctl(&["--socket", socket.to_str().unwrap(), "neighbor", "1"]);
    assert!(ok, "lrctl neighbor 1 should exit 0");
    assert!(
        stdout.contains("handle 1"),
        "neighbor 1 stdout should show handle 1: {stdout}"
    );
    assert!(
        stdout.contains("kind bgp"),
        "neighbor 1 stdout should show kind=bgp: {stdout}"
    );

    lrctl(&["--socket", socket.to_str().unwrap(), "shutdown"]);
    let _ = d.wait_exit();
}

#[test]
fn lrctl_neighbor_rejects_non_numeric_handle() {
    let (socket, d) = spawn_show_daemon("neighbor-bad", "18113");
    let (ok, _stdout, stderr) = lrctl(&[
        "--socket",
        socket.to_str().unwrap(),
        "neighbor",
        "not-a-number",
    ]);
    assert!(!ok, "lrctl neighbor <non-numeric> should exit non-zero");
    assert!(
        stderr.contains("error: invalid session handle"),
        "neighbor non-numeric stderr: {stderr}"
    );

    lrctl(&["--socket", socket.to_str().unwrap(), "shutdown"]);
    let _ = d.wait_exit();
}

// `lrctl routes count` — alias for `show routes count`.
// ---------------------------------------------------------------------------
#[test]
fn lrctl_routes_count_alias_matches_show_routes_count() {
    let (socket, d) = spawn_show_daemon("routes-count-alias", "18114");
    let (ok, stdout, stderr) = lrctl(&["--socket", socket.to_str().unwrap(), "routes", "count"]);
    assert!(ok, "lrctl routes count should exit 0: stderr={stderr}");
    assert!(
        stdout.contains("total 1"),
        "routes count stdout should report total 1: {stdout}"
    );
    assert!(
        stdout.contains("proto="),
        "routes count stdout should list per-protocol lines: {stdout}"
    );

    lrctl(&["--socket", socket.to_str().unwrap(), "shutdown"]);
    let _ = d.wait_exit();
}

// `lrctl --json status` / `--json sessions` / `--json show status` —
// machine-readable JSON output for the line-oriented commands.
// ---------------------------------------------------------------------------
#[test]
fn lrctl_json_status_emits_compact_object() {
    let (socket, d) = spawn_show_daemon("json-status", "18115");
    let (ok, stdout, stderr) = lrctl(&["--socket", socket.to_str().unwrap(), "--json", "status"]);
    assert!(ok, "lrctl --json status should exit 0: stderr={stderr}");
    // The body must be a single-line JSON object starting with `{`.
    let line = stdout.lines().next().unwrap_or("").trim();
    assert!(line.starts_with('{'), "json status stdout: {stdout}");
    assert!(line.ends_with('}'), "json status stdout: {stdout}");
    // Keys are normalised to snake_case (the daemon's `local-as`
    // becomes `local_as`).
    assert!(
        line.contains("\"local_as\":64512"),
        "json status should carry local_as as integer: {stdout}"
    );
    assert!(
        line.contains("\"peer_as\":64513"),
        "json status should carry peer_as as integer: {stdout}"
    );
    assert!(
        line.contains("\"router_id\":\"10.0.0.1\""),
        "json status should carry router_id as string: {stdout}"
    );
    assert!(
        line.contains("\"uptime_secs\":"),
        "json status should carry uptime_secs as integer: {stdout}"
    );
    assert!(
        line.contains("\"sessions\":"),
        "json status should carry sessions count: {stdout}"
    );
    assert!(
        line.contains("\"rib_entries\":"),
        "json status should carry rib_entries count: {stdout}"
    );

    lrctl(&["--socket", socket.to_str().unwrap(), "shutdown"]);
    let _ = d.wait_exit();
}

#[test]
fn lrctl_json_sessions_emits_array_of_objects() {
    let (socket, d) = spawn_show_daemon("json-sessions", "18116");
    let (ok, stdout, stderr) = lrctl(&["--socket", socket.to_str().unwrap(), "--json", "sessions"]);
    assert!(ok, "lrctl --json sessions should exit 0: stderr={stderr}");
    let line = stdout.lines().next().unwrap_or("").trim();
    assert!(
        line.starts_with('['),
        "json sessions stdout should be a JSON array: {stdout}"
    );
    assert!(line.ends_with(']'), "json sessions stdout: {stdout}");
    // The first array element is the session object with its handle.
    assert!(
        line.contains("\"handle\":\"1\""),
        "json sessions should carry the handle: {stdout}"
    );
    assert!(
        line.contains("\"kind\":\"bgp\""),
        "json sessions should carry the kind: {stdout}"
    );
    assert!(
        line.contains("\"local_as\":64512"),
        "json sessions should carry local_as as integer: {stdout}"
    );

    lrctl(&["--socket", socket.to_str().unwrap(), "shutdown"]);
    let _ = d.wait_exit();
}

#[test]
fn lrctl_json_show_status_includes_by_protocol_and_memory() {
    let (socket, d) = spawn_show_daemon("json-show-status", "18117");
    let (ok, stdout, stderr) = lrctl(&[
        "--socket",
        socket.to_str().unwrap(),
        "--json",
        "show",
        "status",
    ]);
    assert!(
        ok,
        "lrctl --json show status should exit 0: stderr={stderr}"
    );
    // The JSON shape nests `by_protocol` (one entry per protocol
    // kind) and a `memory` object.
    assert!(
        stdout.contains("\"by_protocol\":["),
        "json show status should carry a by_protocol array: {stdout}"
    );
    assert!(
        stdout.contains("\"kind\":\"bgp\""),
        "json show status by_protocol should include the bgp kind: {stdout}"
    );
    assert!(
        stdout.contains("\"total\":"),
        "json show status by_protocol entry should carry a total: {stdout}"
    );
    assert!(
        stdout.contains("\"memory\":{"),
        "json show status should carry a memory object: {stdout}"
    );

    lrctl(&["--socket", socket.to_str().unwrap(), "shutdown"]);
    let _ = d.wait_exit();
}

#[test]
fn lrctl_json_pretty_indents_two_spaces() {
    let (socket, d) = spawn_show_daemon("json-pretty", "18118");
    let (ok, stdout, stderr) = lrctl(&[
        "--socket",
        socket.to_str().unwrap(),
        "--json=pretty",
        "status",
    ]);
    assert!(
        ok,
        "lrctl --json=pretty status should exit 0: stderr={stderr}"
    );
    // Pretty-printed JSON contains newlines + 2-space indent; the
    // compact form does not.
    assert!(
        stdout.contains("\n  \""),
        "pretty JSON should contain newline + 2-space indent: {stdout}"
    );

    lrctl(&["--socket", socket.to_str().unwrap(), "shutdown"]);
    let _ = d.wait_exit();
}

#[test]
fn lrctl_json_rejects_unknown_format() {
    // `--json=bogus` should exit 2 with a usage hint — the parser
    // is strict so a typo is loud.
    let (ok, _stdout, stderr) = lrctl(&["--json=bogus", "status"]);
    assert!(!ok, "lrctl --json=bogus should exit non-zero");
    assert!(
        stderr.contains("error: --json=bogus"),
        "--json=bogus stderr should explain the bad format: {stderr}"
    );
}

// `lrctl metrics` — scrape the daemon's HTTP /metrics endpoint. The
// daemon needs to be started with `--metrics-addr ADDR` for the test
// (the default `spawn_show_daemon` helper does not configure it).
// ---------------------------------------------------------------------------
#[test]
fn lrctl_metrics_proxies_prometheus_exposition() {
    // Pick a free TCP port for the metrics endpoint.
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind :0");
    let metrics_port = listener.local_addr().unwrap().port();
    drop(listener);
    std::thread::sleep(Duration::from_millis(10));

    let socket = std::env::temp_dir().join(format!(
        "lrctl-test-metrics-{}-{}.sock",
        std::process::id(),
        metrics_port,
    ));
    let _ = std::fs::remove_file(&socket);
    let listen_port = 18200u16 + (metrics_port & 0xff);
    let d = Daemon::spawn(
        &[
            "--local-as",
            "64512",
            "--peer-as",
            "64513",
            "--router-id",
            "10.0.0.1",
            "--listen",
            &format!("127.0.0.1:{listen_port}"),
            "--network",
            "203.0.113.0/24",
            "--api-socket",
            socket.to_str().unwrap(),
            "--metrics-addr",
            &format!("127.0.0.1:{metrics_port}"),
        ],
        "metrics-cmd",
    );
    d.wait_log("metrics endpoint on", "metrics endpoint up");

    let (ok, stdout, stderr) = lrctl(&[
        "--socket",
        socket.to_str().unwrap(),
        "metrics",
        "--metrics-addr",
        &format!("127.0.0.1:{metrics_port}"),
    ]);
    assert!(ok, "lrctl metrics should exit 0: stderr={stderr}");
    // The body is the Prometheus exposition format — at minimum,
    // the lr_info gauge and the lr_uptime_seconds gauge must be
    // present.
    assert!(
        stdout.contains("# TYPE lr_info gauge"),
        "metrics stdout should carry lr_info: {stdout}"
    );
    assert!(
        stdout.contains("lr_info{"),
        "metrics stdout should carry lr_info value: {stdout}"
    );
    assert!(
        stdout.contains("# TYPE lr_uptime_seconds gauge"),
        "metrics stdout should carry lr_uptime_seconds: {stdout}"
    );

    lrctl(&["--socket", socket.to_str().unwrap(), "shutdown"]);
    let _ = d.wait_exit();
}

// `lrctl roa list` / `lrctl roa count` — ROADMAP "lrctl roa list", issue #52
// follow-up. The e2e tests load a TOML config with two `[[roa]]` entries
// so the daemon's ROA store is populated at startup, then exercise the
// client sub-commands against the running daemon.
// ---------------------------------------------------------------------------

/// Build a minimal TOML config file with two `[[roa]]` entries: one
/// IPv4 exact-match and one IPv4 with `max_length`. Returns the path
/// the daemon can be pointed at with `--config`.
fn write_roa_config(dir: &std::path::Path) -> std::path::PathBuf {
    let cfg = dir.join("daemon.toml");
    std::fs::write(
        &cfg,
        r#"# Minimal test config: two [[roa]] entries, no peers.
# The daemon does not need a BGP listener to populate the ROA store —
# `build_roa_table` runs unconditionally at startup (so the filter DSL's
# `roa.state` accessor works even when `roa_validate = false`).
[bgp]
local_as = 64512
peer_as  = 64513
router_id = "10.0.0.1"

[[roa]]
prefix = "203.0.113.0/24"
asn = 64512
# max_length defaults to 24 (exact match).

[[roa]]
prefix = "198.51.100.0/24"
asn = 64513
max_length = 26
"#,
    )
    .expect("write test config");
    cfg
}

#[test]
fn lrctl_roa_list_dumps_entries() {
    // Use a short, unique-enough dir name: macOS caps a Unix domain
    // socket path at SUN_LEN (104 bytes), and the OS temp dir on the
    // macOS runner is itself ~50 chars, so a long suffix trips the
    // limit (the existing tests above use the same `process::id()`
    // only). Each test gets its own port so parallel runs do not
    // collide on the listener socket.
    let dir = std::env::temp_dir().join(format!("lrctl-test-roa-list-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let cfg_path = write_roa_config(&dir);
    let socket = dir.join("daemon.api");
    let _ = std::fs::remove_file(&socket);
    let d = Daemon::spawn(
        &[
            "--config",
            cfg_path.to_str().unwrap(),
            "--listen",
            "127.0.0.1:18121",
            "--api-socket",
            socket.to_str().unwrap(),
        ],
        "roa-list",
    );
    d.wait_log("runtime API on", "api socket up");

    let (ok, stdout, stderr) = lrctl(&["--socket", socket.to_str().unwrap(), "roa", "list"]);
    assert!(ok, "lrctl roa list failed: stderr={stderr}");
    // Summary line: 2 entries, all static, no RTR.
    assert!(
        stdout.contains("roa-total 2 static 2 rtr 0"),
        "roa list stdout: {stdout}"
    );
    // Per-entry lines, sorted (198.x before 203.x — the store's
    // canonical order, not the config file's order).
    let lines: Vec<&str> = stdout
        .lines()
        .filter(|l| l.contains("max-length"))
        .collect();
    assert_eq!(lines.len(), 2, "roa list stdout: {stdout}");
    assert!(
        lines[0].starts_with("198.51.100.0/24 max-length 26 as 64513 source static"),
        "roa list lines: {lines:?}"
    );
    assert!(
        lines[1].starts_with("203.0.113.0/24 max-length 24 as 64512 source static"),
        "roa list lines: {lines:?}"
    );

    lrctl(&["--socket", socket.to_str().unwrap(), "shutdown"]);
    let _ = d.wait_exit();
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn lrctl_roa_count_prints_summary_only() {
    let dir = std::env::temp_dir().join(format!("lrctl-test-roa-count-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let cfg_path = write_roa_config(&dir);
    let socket = dir.join("daemon.api");
    let _ = std::fs::remove_file(&socket);
    let d = Daemon::spawn(
        &[
            "--config",
            cfg_path.to_str().unwrap(),
            "--listen",
            "127.0.0.1:18122",
            "--api-socket",
            socket.to_str().unwrap(),
        ],
        "roa-count",
    );
    d.wait_log("runtime API on", "api socket up");

    let (ok, stdout, stderr) = lrctl(&["--socket", socket.to_str().unwrap(), "roa", "count"]);
    assert!(ok, "lrctl roa count failed: stderr={stderr}");
    // `roa count` strips per-entry lines: stdout is exactly the
    // summary line.
    let lines: Vec<&str> = stdout.lines().collect();
    assert_eq!(lines.len(), 1, "roa count should print one line: {stdout}");
    assert!(
        lines[0].starts_with("roa-total 2 static 2 rtr 0"),
        "roa count line: {lines:?}"
    );

    lrctl(&["--socket", socket.to_str().unwrap(), "shutdown"]);
    let _ = d.wait_exit();
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn lrctl_roa_unknown_subcommand_exits_nonzero() {
    let dir = std::env::temp_dir().join(format!("lrctl-test-roa-bogus-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let cfg_path = write_roa_config(&dir);
    let socket = dir.join("daemon.api");
    let _ = std::fs::remove_file(&socket);
    let d = Daemon::spawn(
        &[
            "--config",
            cfg_path.to_str().unwrap(),
            "--listen",
            "127.0.0.1:18123",
            "--api-socket",
            socket.to_str().unwrap(),
        ],
        "roa-bogus",
    );
    d.wait_log("runtime API on", "api socket up");

    // `lrctl roa bogus` — client-side rejection, exit 2.
    let (ok, _stdout, stderr) = lrctl(&["--socket", socket.to_str().unwrap(), "roa", "bogus"]);
    assert!(!ok, "lrctl roa bogus should exit non-zero");
    assert!(
        stderr.contains("error: unknown roa subcommand 'bogus'"),
        "roa bogus stderr: {stderr}"
    );

    // `lrctl roa` (no sub) — same rejection.
    let (ok, _stdout, stderr) = lrctl(&["--socket", socket.to_str().unwrap(), "roa"]);
    assert!(!ok, "lrctl roa (no sub) should exit non-zero");
    assert!(
        stderr.contains("usage: lrctl roa <list | count>"),
        "roa (no sub) stderr: {stderr}"
    );

    lrctl(&["--socket", socket.to_str().unwrap(), "shutdown"]);
    let _ = d.wait_exit();
    let _ = std::fs::remove_dir_all(&dir);
}

// `lrctl session <handle> soft-in` / `refresh-in` — issue #52 follow-up:
// write-side fine-grained operations on the running daemon. The e2e
// tests exercise the client surface against a real `lr-daemon` with one
// Idle BGP session — the session never connects, so `soft-in` reports
// `re-evaluated=0` and `refresh-in` reports an error (RFC 2918 needs
// an Established session).
// ---------------------------------------------------------------------------

#[test]
fn lrctl_session_soft_in_reports_zero_for_idle_session() {
    let (socket, d) = spawn_show_daemon("soft-in", "18111");
    let (ok, stdout, stderr) = lrctl(&[
        "--socket",
        socket.to_str().unwrap(),
        "session",
        "1",
        "soft-in",
    ]);
    assert!(ok, "lrctl session 1 soft-in failed: stderr={stderr}");
    assert!(
        stdout.contains("session 1 soft-in ok re-evaluated=0"),
        "session 1 soft-in stdout: {stdout}"
    );

    lrctl(&["--socket", socket.to_str().unwrap(), "shutdown"]);
    let _ = d.wait_exit();
}

#[test]
fn lrctl_session_refresh_in_fails_for_idle_session() {
    let (socket, d) = spawn_show_daemon("refresh-in", "18112");
    let (ok, stdout, _stderr) = lrctl(&[
        "--socket",
        socket.to_str().unwrap(),
        "session",
        "1",
        "refresh-in",
    ]);
    // The daemon returns an error line; `lrctl` exits 1 because the
    // reply starts with `error:`.
    assert!(
        !ok,
        "lrctl session 1 refresh-in should exit non-zero (idle session)"
    );
    assert!(
        stdout.contains("error: session 1 refresh-in failed"),
        "session 1 refresh-in stdout: {stdout}"
    );

    lrctl(&["--socket", socket.to_str().unwrap(), "shutdown"]);
    let _ = d.wait_exit();
}

#[test]
fn lrctl_session_refresh_in_with_explicit_family() {
    let (socket, d) = spawn_show_daemon("refresh-in-v6", "18113");
    // Explicit family — still fails because the session is Idle,
    // but the family parse succeeds (the daemon does not report
    // "unknown family").
    let (ok, stdout, _stderr) = lrctl(&[
        "--socket",
        socket.to_str().unwrap(),
        "session",
        "1",
        "refresh-in",
        "ipv6-unicast",
    ]);
    assert!(
        !ok,
        "lrctl session 1 refresh-in ipv6-unicast should exit non-zero"
    );
    assert!(
        stdout.contains("error: session 1 refresh-in failed"),
        "session 1 refresh-in ipv6-unicast stdout: {stdout}"
    );

    lrctl(&["--socket", socket.to_str().unwrap(), "shutdown"]);
    let _ = d.wait_exit();
}

#[test]
fn lrctl_session_refresh_in_unknown_family_exits_nonzero() {
    let (socket, d) = spawn_show_daemon("refresh-in-bad", "18114");
    // Unknown family — the daemon bounces it. `lrctl` exits 1
    // because the reply starts with `error:`.
    let (ok, stdout, _stderr) = lrctl(&[
        "--socket",
        socket.to_str().unwrap(),
        "session",
        "1",
        "refresh-in",
        "bogus",
    ]);
    assert!(!ok, "lrctl session 1 refresh-in bogus should exit non-zero");
    assert!(
        stdout.contains("error: session 1 refresh-in: unknown family 'bogus'"),
        "session 1 refresh-in bogus stdout: {stdout}"
    );

    lrctl(&["--socket", socket.to_str().unwrap(), "shutdown"]);
    let _ = d.wait_exit();
}

#[test]
fn lrctl_session_unknown_op_exits_nonzero() {
    let (socket, d) = spawn_show_daemon("bad-op", "18115");
    // Unknown op — client-side rejection, exit 2.
    let (ok, _stdout, stderr) = lrctl(&[
        "--socket",
        socket.to_str().unwrap(),
        "session",
        "1",
        "bogus",
    ]);
    assert!(!ok, "lrctl session 1 bogus should exit non-zero");
    assert!(
        stderr.contains("error: unknown session op 'bogus'"),
        "session 1 bogus stderr: {stderr}"
    );

    lrctl(&["--socket", socket.to_str().unwrap(), "shutdown"]);
    let _ = d.wait_exit();
}

#[test]
fn lrctl_session_non_numeric_handle_exits_nonzero() {
    let (socket, d) = spawn_show_daemon("bad-handle", "18116");
    // Non-numeric handle — client-side rejection, exit 2.
    let (ok, _stdout, stderr) = lrctl(&[
        "--socket",
        socket.to_str().unwrap(),
        "session",
        "not-a-number",
        "soft-in",
    ]);
    assert!(
        !ok,
        "lrctl session not-a-number soft-in should exit non-zero"
    );
    assert!(
        stderr.contains("error: invalid session handle 'not-a-number'"),
        "non-numeric handle stderr: {stderr}"
    );

    lrctl(&["--socket", socket.to_str().unwrap(), "shutdown"]);
    let _ = d.wait_exit();
}

#[test]
fn lrctl_session_missing_op_exits_nonzero() {
    let (socket, d) = spawn_show_daemon("no-op", "18117");
    // `lrctl session 1` (no op) — client-side rejection, exit 2.
    let (ok, _stdout, stderr) = lrctl(&["--socket", socket.to_str().unwrap(), "session", "1"]);
    assert!(!ok, "lrctl session 1 (no op) should exit non-zero");
    assert!(
        stderr.contains("error: session 1 requires an op"),
        "session no op stderr: {stderr}"
    );

    lrctl(&["--socket", socket.to_str().unwrap(), "shutdown"]);
    let _ = d.wait_exit();
}
