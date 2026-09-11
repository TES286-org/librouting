//! End-to-end tests for the hardened `lr-daemon` runtime behaviour:
//! runtime API socket, signal-driven graceful shutdown and SIGHUP
//! configuration reload, and privilege-drop error handling.
//!
//! Each test spawns the real binary (`CARGO_BIN_EXE_lr-daemon`) on
//! distinct loopback ports so they can run concurrently.

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
            std::env::temp_dir().join(format!("lr-daemon-test-{tag}-{}.log", std::process::id()));
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
        panic!("daemon did not report '{what}' within 15 s");
    }

    fn pid(&self) -> i32 {
        self.child.id() as i32
    }

    fn signal(&mut self, sig: i32) {
        let rc = unsafe { kill(self.pid(), sig) };
        assert_eq!(rc, 0, "kill({}) failed", sig);
    }

    /// Wait for exit; returns (success?, log text).
    fn wait_exit(&mut self) -> (bool, String) {
        let status = self.child.wait().expect("wait for daemon exit");
        let text = std::fs::read_to_string(&self.log).unwrap_or_default();
        (status.success(), text)
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_file(&self.log);
    }
}

extern "C" {
    fn kill(pid: i32, sig: i32) -> i32;
}

const SIGHUP: i32 = 1;
const SIGTERM: i32 = 15;

/// One round trip on the runtime API socket: send a command, collect the
/// reply bytes until a short idle silence.
fn api_ask(socket: &std::path::Path, cmd: &str) -> String {
    let mut conn = UnixStream::connect(socket).expect("connect to api socket");
    conn.write_all(format!("{cmd}\n").as_bytes()).unwrap();
    conn.flush().unwrap();
    // Poll for the response with a 5 s deadline instead of a fixed
    // 150 ms sleep: on macOS the listener's accept loop polls every
    // 100 ms, so a fresh connection's first command can land during
    // a poll gap, and the original fixed-150 ms sleep sometimes
    // expired before the server thread had a chance to write the
    // reply (the bogus-command round-trip reproduced exactly that
    // on the macos-14 leg of the cross-platform CI matrix). The
    // non-blocking read returns on the first WouldBlock with data in
    // the buffer, so the typical latency is still a single poll.
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

/// Read a log file until it contains every needle (bounded wait).
fn wait_log_all(path: &std::path::Path, needles: &[&str]) -> String {
    let deadline = Instant::now() + Duration::from_secs(15);
    let mut text = String::new();
    while Instant::now() < deadline {
        text = std::fs::read_to_string(path).unwrap_or_default();
        if needles.iter().all(|n| text.contains(n)) {
            return text;
        }
        thread::sleep(Duration::from_millis(100));
    }
    panic!("log never contained all of {needles:?}; last: {text}");
}

#[test]
fn api_socket_serves_status_sessions_routes_and_shutdown() {
    let socket =
        std::env::temp_dir().join(format!("lr-daemon-test-api-{}.sock", std::process::id()));
    let mut d = Daemon::spawn(
        &[
            "--local-as",
            "64512",
            "--peer-as",
            "64513",
            "--router-id",
            "10.0.0.1",
            "--listen",
            "127.0.0.1:17981",
            "--network",
            "203.0.113.0/24",
            "--api-socket",
            socket.to_str().unwrap(),
        ],
        "api",
    );
    d.wait_log("runtime API on", "api socket up");

    let status = api_ask(&socket, "status");
    assert!(status.contains("local-as 64512"), "status: {status}");
    assert!(status.contains("router-id 10.0.0.1"));
    assert!(status.contains("rib-entries 1"), "status: {status}");
    assert!(status.contains("sessions 1"));

    let sessions = api_ask(&socket, "sessions");
    assert!(sessions.contains("kind=bgp"), "sessions: {sessions}");
    assert!(sessions.contains("local-as=64512"));
    assert!(sessions.contains("state=Idle"), "sessions: {sessions}");

    let routes = api_ask(&socket, "routes");
    assert!(routes.contains("203.0.113.0/24"), "routes: {routes}");

    let help = api_ask(&socket, "help");
    assert!(help.contains("shutdown"), "help: {help}");

    let unknown = api_ask(&socket, "bogus");
    assert!(
        unknown.contains("error: unknown command"),
        "unknown: {unknown}"
    );

    // `shutdown` must stop the daemon gracefully: exit code 0 and a
    // completed-shutdown log line.
    let shutting = api_ask(&socket, "shutdown");
    assert!(shutting.contains("shutting down"), "shutdown: {shutting}");
    let (ok, log) = d.wait_exit();
    assert!(ok, "daemon must exit 0 after api shutdown; log:\n{log}");
    assert!(log.contains("shutdown complete"));
    assert!(
        !socket.exists(),
        "api socket file must be cleaned up on shutdown"
    );
}

#[test]
fn sigterm_shuts_down_gracefully() {
    let socket =
        std::env::temp_dir().join(format!("lr-daemon-test-term-{}.sock", std::process::id()));
    let mut d = Daemon::spawn(
        &[
            "--local-as",
            "64512",
            "--peer-as",
            "64513",
            "--router-id",
            "10.0.0.1",
            "--listen",
            "127.0.0.1:17982",
            "--api-socket",
            socket.to_str().unwrap(),
        ],
        "term",
    );
    d.wait_log("listening on", "listener bound");

    d.signal(SIGTERM);
    let (ok, log) = d.wait_exit();
    assert!(ok, "SIGTERM must lead to a clean exit; log:\n{log}");
    assert!(log.contains("signal 15 received"), "log: {log}");
    assert!(log.contains("shutdown complete"), "log: {log}");
}

#[test]
fn sighup_reloads_networks_from_config_file() {
    let dir = std::env::temp_dir().join(format!("lr-daemon-test-hup-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let conf = dir.join("daemon.toml");
    let socket = dir.join("daemon.api");

    std::fs::write(
        &conf,
        "[bgp]\nlocal_as = 64512\npeer_as = 64513\nrouter_id = \"10.0.0.1\"\n\
         listen_addr = \"127.0.0.1:17983\"\n\nnetworks = [\"203.0.113.0/24\"]\n",
    )
    .unwrap();

    let mut d = Daemon::spawn(
        &[
            "--config",
            conf.to_str().unwrap(),
            "--api-socket",
            socket.to_str().unwrap(),
        ],
        "hup",
    );
    wait_log_all(&d.log, &["originating 203.0.113.0/24", "listening on"]);

    // Rewrite the config: drop the old network, add a new one, and send
    // SIGHUP — both changes must be applied without a restart.
    std::fs::write(
        &conf,
        "[bgp]\nlocal_as = 64512\npeer_as = 64513\nrouter_id = \"10.0.0.1\"\n\
         listen_addr = \"127.0.0.1:17983\"\n\nnetworks = [\"198.51.100.0/24\"]\n",
    )
    .unwrap();
    d.signal(SIGHUP);
    let text = wait_log_all(
        &d.log,
        &[
            "SIGHUP received",
            "reload: originating 198.51.100.0/24",
            "reload: unoriginating 203.0.113.0/24",
        ],
    );
    assert!(text.contains("require a restart"), "log: {text}");

    // The runtime API sees the reloaded RIB.
    let routes = api_ask(&socket, "routes");
    assert!(routes.contains("198.51.100.0/24"), "routes: {routes}");
    assert!(!routes.contains("203.0.113.0/24"), "routes: {routes}");

    // A config that cannot be parsed must NOT take the daemon down (the
    // parser tolerates unknown keys, so use a line without `=`).
    std::fs::write(&conf, "utter garbage without an equals sign\n").unwrap();
    d.signal(SIGHUP);
    let text = wait_log_all(&d.log, &["keeping current config"]);
    assert!(text.contains("reload:"), "log: {text}");

    d.signal(SIGTERM);
    let (ok, log) = d.wait_exit();
    assert!(
        ok,
        "daemon must survive a bad reload and stop cleanly; log:\n{log}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn unprivileged_user_switch_is_refused_cleanly() {
    // We are (almost certainly) not root in the test environment: asking
    // to become uid 1 must fail with a clear message and a nonzero exit
    // instead of pretending the drop happened.
    let out = Command::new(BIN)
        .args([
            "--local-as",
            "64512",
            "--peer-as",
            "64513",
            "--router-id",
            "10.0.0.1",
            "--listen",
            "127.0.0.1:17984",
            "--user",
            "1",
        ])
        .output()
        .expect("spawn lr-daemon");
    if out.status.success() {
        // Running as root (some CI images do): switching to uid 1 is then
        // legitimate, and the daemon must report the successful drop.
        let text = String::from_utf8_lossy(&out.stdout);
        assert!(text.contains("privileges dropped"), "stdout: {text}");
    } else {
        let text = String::from_utf8_lossy(&out.stderr);
        assert!(
            text.contains("cannot switch") || text.contains("privilege drop"),
            "stderr: {text}"
        );
    }
}

#[test]
fn api_reload_command_matches_sighup() {
    let dir = std::env::temp_dir().join(format!("lr-daemon-test-areload-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let conf = dir.join("daemon.toml");
    let socket = dir.join("daemon.api");

    std::fs::write(
        &conf,
        "[bgp]\nlocal_as = 64512\npeer_as = 64513\nrouter_id = \"10.0.0.1\"\n\
         listen_addr = \"127.0.0.1:17985\"\n\nnetworks = [\"203.0.113.0/24\"]\n",
    )
    .unwrap();

    let mut d = Daemon::spawn(
        &[
            "--config",
            conf.to_str().unwrap(),
            "--api-socket",
            socket.to_str().unwrap(),
        ],
        "areload",
    );
    // The API socket is spawned after the networks are originated, so wait
    // for BOTH markers before connecting (waiting for "originating" alone
    // races the socket bind on slow runners).
    wait_log_all(&d.log, &["originating 203.0.113.0/24", "runtime API on"]);

    std::fs::write(
        &conf,
        "[bgp]\nlocal_as = 64512\npeer_as = 64513\nrouter_id = \"10.0.0.1\"\n\
         listen_addr = \"127.0.0.1:17985\"\n\nnetworks = [\"203.0.113.0/24\", \"198.51.100.0/24\"]\n",
    )
    .unwrap();

    let reply = api_ask(&socket, "reload");
    assert!(
        reply.contains("originating 198.51.100.0/24"),
        "reply: {reply}"
    );

    let routes = api_ask(&socket, "routes");
    assert!(routes.contains("198.51.100.0/24"), "routes: {routes}");
    assert!(routes.contains("203.0.113.0/24"), "routes: {routes}");

    d.signal(SIGTERM);
    let (ok, log) = d.wait_exit();
    assert!(ok, "log:\n{log}");
    let _ = std::fs::remove_dir_all(&dir);
}

/// The daemon must refuse to start when the runtime API socket cannot be
/// created (fail closed, like auth arming).
#[test]
fn api_socket_failure_is_fatal() {
    let out = Command::new(BIN)
        .args([
            "--local-as",
            "64512",
            "--peer-as",
            "64513",
            "--router-id",
            "10.0.0.1",
            "--listen",
            "127.0.0.1:17986",
            // A path whose parent directory does not exist.
            "--api-socket",
            "/nonexistent-dir/lr-daemon.api",
        ])
        .output()
        .expect("spawn lr-daemon");
    assert!(!out.status.success(), "daemon must exit nonzero");
    let text = String::from_utf8_lossy(&out.stderr);
    assert!(text.contains("runtime API"), "stderr: {text}");
}
