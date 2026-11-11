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
        static LOG_SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let seq = LOG_SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let log = std::env::temp_dir().join(format!(
            "lr-daemon-test-{tag}-{}-{seq}.log",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&log);
        let log_file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&log)
            .expect("create log file");
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

    /// Wait for exit with a 30s timeout; returns (success?, log text).
    /// The timeout prevents a hung daemon from stalling the test
    /// binary (seen on macOS CI runners).
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
        // Preserve the capture log when the test is unwinding so the
        // daemon's stderr/stdout tail is available in the panic
        // message (the test reads it explicitly before this Drop
        // runs, but if the panic originated from an assertion that
        // did not dump the capture log, the file is still on disk
        // under $TMPDIR for a developer or CI artifact scrubber to
        // pick up). On a clean exit the file is removed as before —
        // keeping temp-dir hygiene tight for the green-run case.
        if !std::thread::panicking() {
            let _ = std::fs::remove_file(&self.log);
        }
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

/// Derive a unique loopback TCP port for a test daemon so two tests
/// running in parallel under `cargo nextest` cannot collide on the
/// same `bind(127.0.0.1:PORT)`. The historical hardcoded ports
/// (17981..=17987) were stable across runs but shared between named
/// tests — on the slower RISC-V and s390x CI runners the parallel
/// windows overlapped and one test's `bind` failed with
/// `Address already in use (os error 98)` while the other test's
/// daemon was still coming up.
///
/// `cargo nextest` runs each test in its **own process** (process
/// isolation is nextest's default). A per-process static counter
/// alone is therefore not enough — every test process would start
/// at the same base port and two parallel tests would collide. The
/// derivation folds the PID into the port so two processes get
/// different base offsets, then increments a per-process counter
/// for tests that need multiple ports (e.g. one for the listen
/// address and one for a reload).
///
/// The range is 20_000..=39_999 (well clear of the privileged
/// range, the daemon's other test ports 17981..=17987, and the
/// BFD/Babel UDP ports 3784/4784/6696). The range never crosses
/// into the IANA ephemeral range Linux assigns to outgoing
/// connections (32768+).
fn unique_listen_port() -> u16 {
    static NEXT_PORT: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
    let p = NEXT_PORT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    // Fold the PID into the port derivation: two nextest test
    // processes have different PIDs, so their base offsets differ.
    // The per-process counter handles multiple ports within one
    // test process.
    let pid = std::process::id();
    let offset = (pid.wrapping_add(p)) % 20_000;
    20_000 + (offset as u16)
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
    // The Loc-RIB carries the BGP-originated `--network 203.0.113.0/24`
    // route plus any connected routes the daemon enumerated from the
    // kernel interface table at startup (`install_connected` — BIRD
    // `protocol direct` / FRR `redistribute connected` parity). A CI
    // runner with a non-loopback UP interface contributes one extra
    // `proto=direct` route, so the exact `rib-entries` total is
    // host-dependent — assert the BGP-originated route is present via
    // `routes count`'s per-protocol breakdown instead of the exact
    // total.
    let routes_count = api_ask(&socket, "show routes count");
    assert!(
        routes_count.contains("proto=bgp routes=1"),
        "show routes count must show the BGP-originated network: {routes_count}"
    );
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
    wait_log_all(
        &d.log,
        &[
            "originating 203.0.113.0/24",
            "listening on",
            // The deprecated dialect announces its window at startup
            // (issue #18 Phase 4) — stderr is captured into the log.
            "config deprecation:",
        ],
    );

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
            // Every reload re-states the deprecation window, through
            // the same channel as the parse warnings.
            "reload: config deprecation:",
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

/// SIGHUP re-opens the daemon's `--log-file` destination so the
/// operator's `logrotate` postrotate workflow works: rename the live
/// log file aside, send SIGHUP, verify the next log line lands in the
/// re-opened path (and NOT in the rotated file).
///
/// Defects.txt `daemon_logger.rs:L272 | FUTURE-WORK | "The file is
/// opened append-only and never re-opened, so a log rotation tool must
/// signal the daemon to reopen"` — this test pins the SIGHUP-driven
/// reopen contract: a successful reload reports
/// `reload: log destination re-opened (SIGHUP)` and the new fd writes
/// to the original path the rotation tool just left in place.
#[test]
fn sighup_reopens_log_file_for_rotation() {
    // Short dir name: macOS's $TMPDIR is typically
    // /var/folders/<xx>/<rest>/T/ (~50 chars), and the daemon's
    // Unix-socket runtime API bind fails with `path must be shorter
    // than SUN_LEN` (104 bytes) when the api-socket path exceeds
    // that limit. The historical dir name
    // `lr-daemon-test-hup-logrotate-{PID}-{NANOS}` was ~53 chars on
    // its own; combined with $TMPDIR + `daemon.api` it crossed 104
    // on the macOS CI runner and the daemon died at startup with
    // `ERROR [api] runtime API: bind ...: path must be shorter than
    // SUN_LEN` — which surfaced as the test's `got: ` (empty)
    // symptom because the daemon exited before SIGHUP could be
    // delivered. The short prefix `lr-hup-` + PID + nanos keeps the
    // full socket path under ~80 chars on macOS.
    let dir = std::env::temp_dir().join(format!(
        "lr-hup-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos(),
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let conf = dir.join("daemon.toml");
    let socket = dir.join("daemon.api");
    let log_path = dir.join("daemon.log");
    let rotated_path = dir.join("daemon.log.1");
    // Unique port so the parallel `static_routes_install_and_reload`
    // test (which used to share 17987 with this test) cannot race us
    // for the bind on slow runners.
    let port = unique_listen_port();
    let listen_addr = format!("127.0.0.1:{port}");

    std::fs::write(
        &conf,
        format!(
            "[bgp]\nlocal_as = 64512\npeer_as = 64513\nrouter_id = \"10.0.0.1\"\n\
             listen_addr = \"{listen_addr}\"\n\nnetworks = [\"203.0.113.0/24\"]\n",
        ),
    )
    .unwrap();
    let _ = std::fs::remove_file(&log_path);
    let _ = std::fs::remove_file(&rotated_path);

    let mut d = Daemon::spawn(
        &[
            "--config",
            conf.to_str().unwrap(),
            "--api-socket",
            socket.to_str().unwrap(),
            "--log-file",
            log_path.to_str().unwrap(),
        ],
        "hup-logrotate",
    );
    // Wait for the daemon's first record to land in the log file
    // (the daemon opens the file at startup; the test's stdout/stderr
    // capture is separate from the daemon's own logging destination).
    let deadline = Instant::now() + Duration::from_secs(15);
    while Instant::now() < deadline {
        if let Ok(text) = std::fs::read_to_string(&log_path) {
            if text.contains("originating 203.0.113.0/24") {
                break;
            }
        }
        thread::sleep(Duration::from_millis(100));
    }
    let initial = std::fs::read_to_string(&log_path).unwrap_or_default();
    assert!(
        initial.contains("originating 203.0.113.0/24"),
        "log file should contain the originating line; got: {initial}"
    );
    let initial_len = initial.len();

    // Simulate logrotate: move the file aside. The daemon still holds
    // the old fd, so without a SIGHUP the next log line would land in
    // the rotated file (the kernel keeps the inode alive until the
    // last writer closes). Rename is the rotation tool's atomic move.
    std::fs::rename(&log_path, &rotated_path)
        .expect("logrotate rename — move the live log file aside");

    // Send SIGHUP — the daemon must re-open the original path so the
    // next record lands in the new file (not the rotated one).
    d.signal(SIGHUP);

    // Wait for the reload report to surface in the daemon's log file
    // (re-opened). The "reload: log destination re-opened (SIGHUP)"
    // line is written AFTER init_logger re-opened the file, so it
    // lands in the new file by construction. A reload that *failed*
    // to reopen would still write the failure line — but to the old
    // fd (which now points at the rotated path), so the new path
    // would stay empty.
    //
    // The wait ceiling is 30 s (was 15 s): the macOS CI runner
    // (Apple Silicon macos-latest) sometimes schedules the daemon's
    // SIGHUP dispatch up to ~2 s after the test's `kill(pid, SIGHUP)`
    // returns, and the reopen + first `writeln!` to the new fd can
    // land another ~100 ms behind that. 15 s was plenty on Linux but
    // occasionally tripped the macOS runner's slower signal delivery;
    // 30 s gives 10x slack over the worst observed macOS latency
    // without losing the "this should be sub-second" intent — the
    // poll cadence is still 100 ms, so a successful reopen surfaces
    // in the first or second iteration.
    let deadline = Instant::now() + Duration::from_secs(30);
    let mut new_text = String::new();
    while Instant::now() < deadline {
        new_text = std::fs::read_to_string(&log_path).unwrap_or_default();
        if new_text.contains("reload: log destination re-opened (SIGHUP)") {
            break;
        }
        thread::sleep(Duration::from_millis(100));
    }
    if !new_text.contains("reload: log destination re-opened (SIGHUP)") {
        // Diagnostic dump: surface every clue the test has so a
        // failure on a remote CI runner (macOS, RISC-V, s390x) is
        // triageable from the log alone — without having to reproduce
        // locally. The capture log carries the daemon's stderr
        // (the `reload:` lines are also `log_record`-mirrored to
        // stderr); the rotated file carries the pre-reopen fd's
        // tail (so a `reload: log destination reopen failed (...)`
        // error message — which would land in the rotated file,
        // not the new one — is visible).
        let capture_tail = std::fs::read_to_string(&d.log).unwrap_or_default();
        let rotated_tail = std::fs::read_to_string(&rotated_path).unwrap_or_default();
        panic!(
            "new log file should contain the reopen notice; got: {new_text}\n\
             --- daemon capture log (stderr/stdout tail) ---\n{capture_tail}\n\
             --- rotated file (pre-reopen fd tail) ---\n{rotated_tail}"
        );
    }
    // The reload's "SIGHUP received" line is logged BEFORE init_logger
    // re-opens the file, so it lands in the rotated file (the old fd
    // the daemon still held at that instant). The "log destination
    // re-opened" line lands in the new file (the reopened fd).
    let rotated_text = std::fs::read_to_string(&rotated_path).unwrap_or_default();
    assert!(
        rotated_text.contains("SIGHUP received"),
        "rotated file should carry the pre-reopen SIGHUP marker; got: {rotated_text}"
    );
    assert!(
        !rotated_text.contains("reload: log destination re-opened"),
        "rotated file should NOT carry the post-reopen notice; got: {rotated_text}"
    );
    assert!(
        !new_text.contains("originating 203.0.113.0/24"),
        "new log file should NOT carry pre-rotation records; got: {new_text}"
    );
    // Sanity: the new file grew past its initial empty state.
    assert!(
        !new_text.is_empty(),
        "new log file should be non-empty after SIGHUP; got: {new_text}"
    );
    let _ = initial_len; // silence unused warning if the assertion
                         // above is ever relaxed.

    d.signal(SIGTERM);
    let (ok, log) = d.wait_exit();
    assert!(ok, "log:\n{log}");
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

/// The standalone Babel daemon's reload closure must re-read the
/// configuration file from disk — historically the closure was wired
/// with `None` for the path and reported "no config file in use;
/// nothing to reload" for every reload attempt. This test pins down
/// the fix: writing a new network and sending SIGHUP applies it.
#[test]
fn babel_sighup_reloads_networks_from_config_file() {
    let dir = std::env::temp_dir().join(format!("lr-daemon-test-bhup-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let conf = dir.join("daemon.toml");
    let socket = dir.join("daemon.api");

    // 127.0.0.1 + a non-privileged port: the babel UDP transport binds
    // a normal datagram socket, so the test does not need CAP_NET_RAW.
    // An odd port avoids colliding with a system babeld.
    std::fs::write(
        &conf,
        "protocol = \"babel\"\n\
         [bgp]\n\
         router_id = \"10.0.0.1\"\n\
         local_address = \"127.0.0.1\"\n\
         networks = [\"203.0.113.0/24\"]\n\
         [babel]\n\
         port = 16697\n",
    )
    .unwrap();

    let mut d = Daemon::spawn(
        &[
            "--config",
            conf.to_str().unwrap(),
            "--api-socket",
            socket.to_str().unwrap(),
        ],
        "bhup",
    );
    wait_log_all(
        &d.log,
        &[
            "babel listening on",
            "originating 203.0.113.0/24",
            "runtime API on",
        ],
    );

    // Rewrite the config: drop the old network and add a new one.
    // SIGHUP must apply the change without a restart.
    std::fs::write(
        &conf,
        "protocol = \"babel\"\n\
         [bgp]\n\
         router_id = \"10.0.0.1\"\n\
         local_address = \"127.0.0.1\"\n\
         networks = [\"198.51.100.0/24\"]\n\
         [babel]\n\
         port = 16697\n",
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

    d.signal(SIGTERM);
    let (ok, log) = d.wait_exit();
    assert!(ok, "babel daemon must exit 0 after SIGTERM; log:\n{log}");
    let _ = std::fs::remove_dir_all(&dir);
}

/// A Babel daemon with `import_filter` and `export_filter` keys
/// configured must attach both filters at startup and log a
/// line naming them. An unknown filter name must fail closed (exit
/// code 2, like every other policy typo).
#[test]
fn babel_filters_attach_at_startup_and_unknown_name_fails() {
    let dir = std::env::temp_dir().join(format!("lr-daemon-test-bflt-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();

    // Happy path: declared filters are attached.
    let conf = dir.join("daemon.toml");
    let socket = dir.join("daemon.api");
    std::fs::write(
        &conf,
        "protocol = \"babel\"\n\
         [bgp]\n\
         router_id = \"10.0.0.1\"\n\
         local_address = \"127.0.0.1\"\n\
         networks = [\"203.0.113.0/24\"]\n\
         [babel]\n\
         port = 16698\n\
         import_filter = \"babel-in\"\n\
         export_filter = \"babel-out\"\n\
         [[filter]]\n\
         name = \"babel-in\"\n\
         body = \"if net ~ [ 10.0.0.0/8 ] then accept; reject;\"\n\
         [[filter]]\n\
         name = \"babel-out\"\n\
         body = \"accept;\"\n",
    )
    .unwrap();

    let mut d = Daemon::spawn(
        &[
            "--config",
            conf.to_str().unwrap(),
            "--api-socket",
            socket.to_str().unwrap(),
        ],
        "bflt",
    );
    wait_log_all(
        &d.log,
        &[
            "babel listening on",
            "babel import filter 'babel-in' attached",
            "babel export filter 'babel-out' attached",
            "runtime API on",
        ],
    );
    d.signal(SIGTERM);
    let (ok, _log) = d.wait_exit();
    assert!(ok, "daemon must exit cleanly");

    // Failure path: an unknown filter name is a typo that must stop
    // the daemon at startup, not silently run with no filter.
    let conf2 = dir.join("daemon-bad.toml");
    std::fs::write(
        &conf2,
        "protocol = \"babel\"\n\
         [bgp]\n\
         router_id = \"10.0.0.1\"\n\
         local_address = \"127.0.0.1\"\n\
         [babel]\n\
         port = 16699\n\
         import_filter = \"ghost\"\n",
    )
    .unwrap();
    let out = Command::new(BIN)
        .args([
            "--config",
            conf2.to_str().unwrap(),
            "--api-socket",
            "/tmp/lr-daemon-bad-bflt.sock",
        ])
        .output()
        .expect("spawn lr-daemon");
    assert!(!out.status.success(), "daemon must exit nonzero");
    let text = String::from_utf8_lossy(&out.stderr);
    assert!(
        text.contains("unknown filter 'ghost'"),
        "stderr must name the typo; got: {text}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// A daemon with `[[static.route]]` tables installs them at startup
/// (BIRD `protocol static`, FRR `ip route`). The Loc-RIB surfaces
/// them via the runtime API `routes` command, marked `Static`. A
/// SIGHUP rewrites the table — added routes install, removed routes
/// withdraw, identical routes are left alone.
#[test]
fn static_routes_install_and_reload() {
    let dir = std::env::temp_dir().join(format!("lr-daemon-test-srt-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let conf = dir.join("daemon.toml");
    let socket = dir.join("daemon.api");
    // Unique port so the parallel `sighup_reopens_log_file_for_rotation`
    // test (which used to share 17987 with this test) cannot race us
    // for the bind on slow runners (RISC-V failed with `Address already
    // in use` before this derivation landed).
    let port = unique_listen_port();
    let listen_addr = format!("127.0.0.1:{port}");

    std::fs::write(
        &conf,
        format!(
            "[bgp]\nlocal_as = 64512\npeer_as = 64513\nrouter_id = \"10.0.0.1\"\n\
             listen_addr = \"{listen_addr}\"\n\n\
             [[static.route]]\nprefix = \"203.0.113.0/24\"\nnext_hop = \"198.51.100.1\"\nmetric = 10\n\n\
             [[static.route]]\nprefix = \"10.0.0.0/8\"\nnext_hop = \"blackhole\"\n",
        ),
    )
    .unwrap();

    let mut d = Daemon::spawn(
        &[
            "--config",
            conf.to_str().unwrap(),
            "--api-socket",
            socket.to_str().unwrap(),
        ],
        "srt",
    );
    wait_log_all(
        &d.log,
        &[
            "static:      203.0.113.0/24 via 198.51.100.1 metric=10",
            "static:      10.0.0.0/8 blackhole metric=0",
            "runtime API on",
        ],
    );

    // The Loc-RIB shows both static routes installed.
    let routes = api_ask(&socket, "routes");
    assert!(routes.contains("203.0.113.0/24"), "routes: {routes}");
    assert!(routes.contains("10.0.0.0/8"), "routes: {routes}");
    // Static protocol surfaces as `Static` in the route dump.
    assert!(routes.contains("proto=Static"), "routes: {routes}");

    // Rewrite the config: drop 10.0.0.0/8, change 203.0.113.0/24's
    // next-hop, add a new 198.51.100.0/24 blackhole. Keep the same
    // listen_addr — the daemon's TCP listener is already bound from
    // startup and a SIGHUP does not rebind, so the port stays the
    // same across the reload.
    std::fs::write(
        &conf,
        format!(
            "[bgp]\nlocal_as = 64512\npeer_as = 64513\nrouter_id = \"10.0.0.1\"\n\
             listen_addr = \"{listen_addr}\"\n\n\
             [[static.route]]\nprefix = \"203.0.113.0/24\"\nnext_hop = \"198.51.100.2\"\nmetric = 10\n\n\
             [[static.route]]\nprefix = \"198.51.100.0/24\"\nnext_hop = \"blackhole\"\n",
        ),
    )
    .unwrap();
    d.signal(SIGHUP);
    wait_log_all(
        &d.log,
        &[
            "SIGHUP received",
            "reload: static 203.0.113.0/24 withdrawn (replaced)",
            "reload: static 203.0.113.0/24 installed",
            "reload: static 198.51.100.0/24 installed",
            "reload: static 10.0.0.0/8 withdrawn",
        ],
    );

    let routes = api_ask(&socket, "routes");
    assert!(routes.contains("203.0.113.0/24"), "routes: {routes}");
    assert!(routes.contains("198.51.100.0/24"), "routes: {routes}");
    assert!(!routes.contains("10.0.0.0/8"), "routes: {routes}");

    d.signal(SIGTERM);
    let (ok, _log) = d.wait_exit();
    assert!(ok, "daemon must exit cleanly");
    let _ = std::fs::remove_dir_all(&dir);
}
