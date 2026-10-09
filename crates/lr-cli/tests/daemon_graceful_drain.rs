//! End-to-end tests for the daemon-wide graceful drain (issue #53).
//!
//! The drain is a new shutdown mode: stop accepting new routes, walk
//! the Loc-RIB at a rate-limited pace, exit when the queue is empty or
//! the deadline elapses. These tests drive the full binary so the
//! drain controller, the import hook and the worker thread all run
//! through the real `lr-daemon` startup path.
//!
//! Cases:
//!
//! 1. `drain_status_reports_running_before_drain` — fresh daemon with
//!    `[shutdown] mode = "drain"` reports `state=running` plus the
//!    queued-route count.
//! 2. `drain_command_exits_daemon_with_empty_queue` — `lrctl shutdown
//!    drain` on a daemon with one locally-originated route observes
//!    `state=draining`, then `state=drained`, then the process exits
//!    with code 0.
//! 3. `drain_refused_when_not_configured` — a daemon in immediate
//!    mode refuses `shutdown drain` with a clear "drain not
//!    configured" diagnostic, so the operator cannot accidentally
//!    trigger a no-op drain.

#![cfg(unix)]

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

const BIN: &str = env!("CARGO_BIN_EXE_lr-daemon");

struct Daemon {
    child: Child,
    log: std::path::PathBuf,
}

impl Daemon {
    fn spawn(args: &[&str], tag: &str) -> Self {
        let log =
            std::env::temp_dir().join(format!("lr-daemon-drain-{tag}-{}.log", std::process::id()));
        let log_file = std::fs::File::create(&log).expect("create log file");
        let child = Command::new(BIN)
            .args(args)
            .stdout(Stdio::from(log_file.try_clone().expect("clone stdout")))
            .stderr(Stdio::from(log_file))
            .spawn()
            .expect("spawn lr-daemon");
        Self { child, log }
    }

    fn wait_log(&self, needle: &str, what: &str) -> String {
        let deadline = Instant::now() + Duration::from_secs(15);
        while Instant::now() < deadline {
            if let Ok(text) = std::fs::read_to_string(&self.log) {
                if text.contains(needle) {
                    return text;
                }
            }
            thread::sleep(Duration::from_millis(100));
        }
        panic!(
            "daemon did not report '{what}' within 15 s; log:\n{}",
            std::fs::read_to_string(&self.log).unwrap_or_default()
        );
    }

    /// Wait for exit with a 30 s timeout; returns (success?, log text).
    fn wait_exit(&mut self) -> (bool, String) {
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            match self.child.try_wait() {
                Ok(Some(status)) => {
                    let text = std::fs::read_to_string(&self.log).unwrap_or_default();
                    return (status.success(), text);
                }
                Ok(None) => {
                    if Instant::now() >= deadline {
                        let _ = self.child.kill();
                        let _ = self.child.wait();
                        let text = std::fs::read_to_string(&self.log).unwrap_or_default();
                        return (false, text);
                    }
                    thread::sleep(Duration::from_millis(100));
                }
                Err(_) => {
                    let text = std::fs::read_to_string(&self.log).unwrap_or_default();
                    return (false, text);
                }
            }
        }
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
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
        let _ = std::fs::remove_file(&self.log);
    }
}

/// One round trip on the runtime API socket: send a command, collect
/// the reply bytes until a short idle silence. Retries the connect
/// for up to 5 s — under parallel test execution the accept loop's
/// 100 ms poll gap can leave a fresh connection's first attempt
/// refused for a brief window after the daemon logs "runtime API
/// on".
fn api_ask(socket: &std::path::Path, cmd: &str) -> String {
    let connect_deadline = Instant::now() + Duration::from_secs(5);
    let mut conn = loop {
        match UnixStream::connect(socket) {
            Ok(c) => break c,
            Err(e) if e.kind() == std::io::ErrorKind::ConnectionRefused => {
                if Instant::now() >= connect_deadline {
                    panic!("connect to api socket timed out: {e}");
                }
                thread::sleep(Duration::from_millis(20));
            }
            Err(e) => panic!("connect to api socket: {e}"),
        }
    };
    conn.write_all(format!("{cmd}\n").as_bytes()).unwrap();
    conn.flush().unwrap();
    conn.set_nonblocking(true).unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut buf = Vec::new();
    loop {
        let mut chunk = [0u8; 4096];
        match conn.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
            Err(ref e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut =>
            {
                if !buf.is_empty() || Instant::now() >= deadline {
                    break;
                }
                thread::sleep(Duration::from_millis(20));
            }
            Err(_) => break,
        }
    }
    String::from_utf8_lossy(&buf).into_owned()
}

/// Fresh drain-configured daemon: `shutdown status` reports
/// `state=running` and the count of routes queued for withdrawal
/// (one per `--network`).
#[test]
fn drain_status_reports_running_before_drain() {
    let socket = std::env::temp_dir().join(format!(
        "lr-daemon-drain-running-{}.sock",
        std::process::id()
    ));
    let _d = Daemon::spawn(
        &[
            "--local-as",
            "64512",
            "--peer-as",
            "64513",
            "--router-id",
            "10.0.0.1",
            "--listen",
            "127.0.0.1:17991",
            "--network",
            "203.0.113.0/24",
            "--network",
            "198.51.100.0/24",
            "--api-socket",
            socket.to_str().unwrap(),
            "--shutdown-mode",
            "drain",
            "--shutdown-drain-rate",
            "5",
            "--shutdown-drain-max-wait",
            "10",
        ],
        "running",
    );
    // Wait for the daemon to come up (it prints the API socket path
    // once the listener is bound).
    let _ = Daemon::wait_log(&_d, "runtime API on", "api socket up");
    // The drain-configured daemon also logs the configuration once
    // at startup. Either needle is sufficient.
    let _ = Daemon::wait_log(&_d, "graceful drain configured", "drain config");

    let status = api_ask(&socket, "shutdown status");
    assert!(
        status.contains("state=running"),
        "shutdown status: {status}"
    );
    // Two --network flags → two queued routes.
    assert!(
        status.contains("remaining=2"),
        "shutdown status should report 2 remaining routes: {status}"
    );
}

/// `lrctl shutdown drain` on a daemon with one locally-originated
/// route: the API replies `drain started`, `shutdown status` polls
/// through `draining` → `drained`, then the process exits with code 0.
#[test]
fn drain_command_exits_daemon_with_empty_queue() {
    let socket =
        std::env::temp_dir().join(format!("lr-daemon-drain-cmd-{}.sock", std::process::id()));
    let mut d = Daemon::spawn(
        &[
            "--local-as",
            "64512",
            "--peer-as",
            "64513",
            "--router-id",
            "10.0.0.1",
            "--listen",
            "127.0.0.1:17992",
            "--network",
            "203.0.113.0/24",
            "--api-socket",
            socket.to_str().unwrap(),
            "--shutdown-mode",
            "drain",
            "--shutdown-drain-rate",
            "5",
            "--shutdown-drain-max-wait",
            "10",
        ],
        "drain",
    );
    d.wait_log("runtime API on", "api socket up");

    let started = api_ask(&socket, "shutdown drain");
    assert!(
        started.contains("drain started"),
        "shutdown drain reply: {started}"
    );

    // Poll until the drain reaches Drained. The queue is one route,
    // the rate is 5/s, so this should resolve in well under a second;
    // allow up to 5 s for slow CI runners.
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut last_status = String::new();
    while Instant::now() < deadline {
        last_status = api_ask(&socket, "shutdown status");
        if last_status.contains("state=drained") {
            break;
        }
        thread::sleep(Duration::from_millis(50));
    }
    assert!(
        last_status.contains("state=drained"),
        "shutdown status never reported drained: {last_status}"
    );

    // The drain worker flips `running` to false; the main loop
    // notices on its next poll and exits. The drain worker's own
    // log line should appear in the daemon log.
    let (ok, log) = d.wait_exit();
    assert!(ok, "daemon must exit 0 after drain; log:\n{log}");
    assert!(
        log.contains("graceful drain complete"),
        "log should record the drain completion: {log}"
    );
}

/// A daemon in immediate mode (no `[shutdown]` block, the default)
/// must refuse `shutdown drain` with a clear "not configured"
/// diagnostic so the operator cannot accidentally trigger a no-op
/// drain. The plain `shutdown` (immediate) path stays unchanged.
#[test]
fn drain_refused_when_not_configured() {
    let socket = std::env::temp_dir().join(format!(
        "lr-daemon-drain-refused-{}.sock",
        std::process::id()
    ));
    let _d = Daemon::spawn(
        &[
            "--local-as",
            "64512",
            "--peer-as",
            "64513",
            "--router-id",
            "10.0.0.1",
            "--listen",
            "127.0.0.1:17993",
            "--network",
            "203.0.113.0/24",
            "--api-socket",
            socket.to_str().unwrap(),
            // No --shutdown-mode: default is "immediate".
        ],
        "refused",
    );
    _d.wait_log("runtime API on", "api socket up");

    let refused = api_ask(&socket, "shutdown drain");
    assert!(
        refused.contains("drain not configured"),
        "drain in immediate mode must be refused: {refused}"
    );

    let status = api_ask(&socket, "shutdown status");
    assert!(
        status.contains("drain not configured") || status.contains("immediate mode"),
        "status in immediate mode must report: {status}"
    );

    // The daemon is still running — plain `shutdown` exits it.
    let shutting = api_ask(&socket, "shutdown");
    assert!(
        shutting.contains("shutting down"),
        "plain shutdown still works: {shutting}"
    );
}
