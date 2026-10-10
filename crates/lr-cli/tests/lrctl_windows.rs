//! Windows end-to-end test for `lrctl` ↔ `lr-daemon` over a named pipe
//! (issue #43: the runtime API was inconsistent across the CLI binaries —
//! `lr-daemon` listened on a named pipe, `lrctl` had no client transport).
//!
//! Mirrors `tests/lrctl.rs`'s shape: spawn the real `lr-daemon` binary
//! with `--api-socket`, wait for the "runtime API on" marker, then run
//! the real `lrctl` binary as a subprocess and assert its stdout. The
//! only difference is the transport — a named pipe (`\\.\pipe\…`)
//! instead of a Unix domain socket.
//!
//! Runs on the windows-2022 CI leg of the "Native" matrix.

#![cfg(windows)]

use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

const DAEMON: &str = env!("CARGO_BIN_EXE_lr-daemon");
const LRCTL: &str = env!("CARGO_BIN_EXE_lrctl");

/// A unique pipe name for one test. Named pipes live in a flat kernel
/// namespace, so the name must not collide with a parallel test or a
/// stale instance from a previous run. The PID + counter suffix is
/// enough — the daemon closes its end on exit, and the name is reused
/// only within this process.
fn unique_pipe(tag: &str) -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let n = COUNTER.fetch_add(1, Ordering::SeqCst);
    format!(r"\\.\pipe\lr-ctl-test-{}-{}-{}", std::process::id(), tag, n)
}

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
            "lrctl-win-test-{tag}-{}-{seq}.log",
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

    /// Block until the daemon's log contains `needle` (15 s deadline).
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

/// `lrctl status` round-trips through the daemon's named pipe and
/// returns the daemon's `status` reply verbatim. This is the core
/// regression for issue #43: before the Windows named-pipe transport
/// landed, `lrctl` refused with "runtime API requires Unix domain
/// sockets (not supported here)".
#[test]
fn lrctl_status_round_trips_over_named_pipe() {
    let pipe = unique_pipe("status");
    let d = Daemon::spawn(
        &[
            "--local-as",
            "64512",
            "--peer-as",
            "64513",
            "--router-id",
            "10.0.0.1",
            "--listen",
            "127.0.0.1:18101",
            "--network",
            "203.0.113.0/24",
            "--api-socket",
            &pipe,
        ],
        "status",
    );
    d.wait_log("runtime API on", "named pipe up");

    let (ok, stdout, stderr) = lrctl(&["--socket", &pipe, "status"]);
    assert!(ok, "lrctl status failed: stderr={stderr}");
    assert!(stdout.contains("version "), "status stdout: {stdout}");
    assert!(stdout.contains("local-as 64512"), "status stdout: {stdout}");
    assert!(
        stdout.contains("router-id 10.0.0.1"),
        "status stdout: {stdout}"
    );
    assert!(stdout.contains("rib-entries 1"), "status stdout: {stdout}");

    // Clean up via `lrctl shutdown` — exercises the shutdown path too.
    let (ok, stdout, _stderr) = lrctl(&["--socket", &pipe, "shutdown"]);
    assert!(ok, "lrctl shutdown failed");
    assert!(stdout.contains("shutting down"));
    let (exit_ok, _log) = d.wait_exit();
    assert!(exit_ok, "daemon must exit 0 after lrctl shutdown");
}

/// `lrctl sessions` lists the configured BGP session through the pipe.
#[test]
fn lrctl_sessions_lists_configured_session() {
    let pipe = unique_pipe("sessions");
    let d = Daemon::spawn(
        &[
            "--local-as",
            "64512",
            "--peer-as",
            "64513",
            "--router-id",
            "10.0.0.1",
            "--listen",
            "127.0.0.1:18102",
            "--api-socket",
            &pipe,
        ],
        "sessions",
    );
    d.wait_log("runtime API on", "named pipe up");

    let (ok, stdout, stderr) = lrctl(&["--socket", &pipe, "sessions"]);
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

    lrctl(&["--socket", &pipe, "shutdown"]);
    let _ = d.wait_exit();
}

/// A Unix-style `--api-socket` path (the `templates/daemon.toml`
/// default `/run/lr-daemon.api`) is normalized to a valid pipe name by
/// both the daemon and `lrctl`, so the same config string works on
/// every platform. This is the cross-platform-config regression: an
/// operator who copies the Unix default to Windows must not need to
/// edit it.
#[test]
fn unix_style_socket_path_works_on_windows() {
    // Use a bare name (no `\\.\pipe\` prefix, no directory) so the
    // daemon normalizes it to `\\.\pipe\<name>` and `lrctl` resolves
    // the same name.
    let pipe_name = format!("lr-ctl-test-unixstyle-{}", std::process::id());
    let d = Daemon::spawn(
        &[
            "--local-as",
            "64512",
            "--peer-as",
            "64513",
            "--router-id",
            "10.0.0.1",
            "--listen",
            "127.0.0.1:18103",
            "--api-socket",
            &pipe_name,
        ],
        "unixstyle",
    );
    d.wait_log("runtime API on", "named pipe up");

    let (ok, stdout, stderr) = lrctl(&["--socket", &pipe_name, "status"]);
    assert!(ok, "lrctl status (unix-style path) failed: stderr={stderr}");
    assert!(stdout.contains("local-as 64512"), "status stdout: {stdout}");

    lrctl(&["--socket", &pipe_name, "shutdown"]);
    let _ = d.wait_exit();
}
