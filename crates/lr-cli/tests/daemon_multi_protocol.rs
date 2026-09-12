//! End-to-end tests for the rc.3 multi-protocol daemon: one process
//! running a combination of protocols (`--protocol bgp,babel`) through
//! the shared-router supervisor.
//!
//! Coverage:
//!
//! - a real `bgp,babel` daemon establishes a BGP session with a peer
//!   daemon, originates a network, and serves both engines' state
//!   through the one runtime API socket; SIGTERM shuts every engine
//!   down gracefully
//! - a startup failure in one engine aborts the whole combination with
//!   the failing engine's exit code
//! - combinations that rc.3 does not support (bmp/ldp, degenerate
//!   values) fail closed at dispatch
//! - the TOML `protocols = [...]` array selects the same combination
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
            std::env::temp_dir().join(format!("lr-daemon-multi-{tag}-{}.log", std::process::id()));
        let log_file = std::fs::File::create(&log).expect("create log file");
        let child = Command::new(BIN)
            .args(args)
            .stdout(Stdio::from(log_file.try_clone().expect("clone stdout")))
            .stderr(Stdio::from(log_file))
            .spawn()
            .expect("spawn lr-daemon");
        Self { child, log }
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

const SIGTERM: i32 = 15;

/// Read a log file until it contains every needle (bounded wait).
fn wait_log_all(path: &std::path::Path, needles: &[&str]) -> String {
    let deadline = Instant::now() + Duration::from_secs(30);
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

/// One round trip on the runtime API socket: send a command, collect
/// the reply bytes until a short idle silence.
fn api_ask(socket: &std::path::Path, cmd: &str) -> String {
    let mut conn = UnixStream::connect(socket).expect("connect to api socket");
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

/// The full combination e2e: one `bgp,babel` daemon (the subject)
/// peering with a plain BGP daemon (the counterpart) over loopback.
///
/// The subject proves the rc.3 supervisor end to end: the BGP engine
/// establishes a session and originates a network the peer installs;
/// the Babel engine binds its UDP transport next to the BGP listener;
/// one runtime API socket serves both engines' sessions and the shared
/// Loc-RIB; SIGTERM stops both engines and the supervisor joins them
/// cleanly.
///
/// Linux-only, like the BFD e2e: the Babel engine binds the local
/// address (127.0.0.2 — Linux binds the whole 127/8 without aliases,
/// while macOS lo0 carries only 127.0.0.1), and the import safety net
/// rejects an announced NEXT_HOP of exactly 127.0.0.1, so the
/// babel-bindable address and the BGP-announcable next hop must be the
/// same non-127.0.0.1 loopback address. The full data path also runs
/// in tests/interop/multi_protocol.sh on the CI Linux leg.
#[test]
#[cfg(target_os = "linux")]
fn multi_protocol_bgp_babel_share_one_process() {
    let tag = std::process::id();
    let socket = std::env::temp_dir().join(format!("lr-daemon-multi-bb-{tag}.sock", tag = tag));
    let _ = std::fs::remove_file(&socket);
    let port_peer = 18190u16;
    let babel_port = 18696u16;

    // The counterpart: a plain single-protocol BGP daemon listening for
    // the subject's connector.
    let peer = Daemon::spawn(
        &[
            "--local-as",
            "64513",
            "--peer-as",
            "64512",
            "--router-id",
            "10.0.0.2",
            "--listen",
            &format!("127.0.0.1:{port_peer}"),
            "--ebgp-policy",
            "accept-all",
        ],
        "peer",
    );
    wait_log_all(&peer.log, &["listening on"]);

    // The subject: bgp + babel in one process, one shared Loc-RIB,
    // one API socket. The Babel engine gets its own UDP port so the
    // test never collides with anything else bound on 6696.
    let mut subject = Daemon::spawn(
        &[
            "--protocol",
            "bgp,babel",
            "--local-as",
            "64512",
            "--peer-as",
            "64513",
            "--router-id",
            "10.0.0.1",
            "--peer",
            &format!("127.0.0.1:{port_peer}"),
            "--local-address",
            "127.0.0.2",
            "--babel-port",
            &babel_port.to_string(),
            "--network",
            "203.0.113.0/24",
            "--api-socket",
            socket.to_str().unwrap(),
            "--ebgp-policy",
            "accept-all",
        ],
        "subject",
    );

    // The supervisor brought both engines up and the BGP engine
    // established the session with the counterpart.
    wait_log_all(
        &subject.log,
        &[
            "protocols:   bgp,babel (one shared Loc-RIB)",
            "babel listening on 127.0.0.2:18696",
            "daemon: 2 engine(s) running",
            // The session handle numbering between engines is racy
            // (both engines add their session to the shared router at
            // startup); only the BGP engine's session can establish.
            "→ Established",
        ],
    );
    wait_log_all(&peer.log, &["route installed 203.0.113.0/24"]);

    // One API socket serves the whole combination: the status summary,
    // both engines' sessions and the shared Loc-RIB.
    let status = api_ask(&socket, "status");
    assert!(
        status.contains("sessions 2"),
        "status must count both engines' sessions: {status}"
    );
    assert!(
        status.contains("rib-entries 1"),
        "status must count the shared Loc-RIB: {status}"
    );
    let sessions = api_ask(&socket, "sessions");
    assert!(
        sessions.contains("kind=babel"),
        "sessions must include the babel engine's session: {sessions}"
    );
    assert!(
        sessions.contains("kind=bgp") && sessions.contains("Established"),
        "sessions must include the established bgp engine session: {sessions}"
    );
    let routes = api_ask(&socket, "routes");
    assert!(
        routes.contains("203.0.113.0/24"),
        "routes must show the originated network: {routes}"
    );

    // SIGTERM stops every engine and the supervisor joins them cleanly.
    subject.signal(SIGTERM);
    let (ok, text) = subject.wait_exit();
    assert!(ok, "graceful multi-protocol shutdown must exit 0");
    assert!(
        text.contains("babel shutdown complete"),
        "the babel engine must report shutdown: {text}"
    );
    assert!(
        text.contains("daemon: multi-protocol shutdown complete"),
        "the supervisor must report shutdown: {text}"
    );
    let _ = std::fs::remove_file(&socket);
}

/// A startup failure in one engine aborts the whole combination: the
/// OSPF engine has no interfaces configured, so it fails while the BGP
/// engine is already running — the supervisor must abort the gates,
/// stop the BGP engine and exit with the OSPF engine's code.
#[test]
fn multi_protocol_startup_failure_aborts_the_combination() {
    let mut d = Daemon::spawn(
        &[
            "--protocol",
            "bgp,ospf",
            "--local-as",
            "64512",
            "--router-id",
            "10.0.0.1",
        ],
        "abort",
    );
    let (ok, text) = d.wait_exit();
    assert!(!ok, "a failed combination must not exit 0");
    assert!(
        text.contains("--protocol ospf needs at least one interface"),
        "the failing engine's diagnostic must surface: {text}"
    );
    assert!(
        text.contains("ospf engine failed during startup"),
        "the supervisor must name the failed engine: {text}"
    );
    assert!(
        text.contains("bgp engine startup aborted"),
        "the sibling engine must be aborted: {text}"
    );
    assert!(
        text.contains("multi-protocol startup aborted"),
        "the supervisor must report the abort: {text}"
    );
}

/// Combinations rc.3 does not support fail closed at dispatch instead
/// of silently dropping the unsupported protocol.
#[test]
fn multi_protocol_unsupported_combinations_fail_closed() {
    // bmp and ldp cannot combine (bmp target would be needed to even
    // parse, so give ldp a discovery source to reach the dispatcher).
    let mut d = Daemon::spawn(
        &[
            "--protocol",
            "bgp,ldp",
            "--local-as",
            "64512",
            "--router-id",
            "10.0.0.1",
            "--ldp-targeted",
            "192.0.2.1",
        ],
        "ldp",
    );
    let (ok, text) = d.wait_exit();
    assert!(!ok);
    assert!(
        text.contains("--protocol ldp cannot run in a combination"),
        "ldp combinations must fail closed: {text}"
    );

    let mut d = Daemon::spawn(
        &[
            "--protocol",
            "babel,bmp",
            "--router-id",
            "10.0.0.1",
            "--local-address",
            "127.0.0.1",
        ],
        "bmp",
    );
    let (ok, text) = d.wait_exit();
    assert!(!ok);
    assert!(
        text.contains("--protocol bmp cannot run in a combination"),
        "bmp combinations must fail closed: {text}"
    );

    // A degenerate value (all commas) names nothing — an error, not a
    // silent fallback to BGP.
    let mut d = Daemon::spawn(&["--protocol", " , "], "degenerate");
    let (ok, text) = d.wait_exit();
    assert!(!ok);
    assert!(
        text.contains("unknown --protocol"),
        "a degenerate protocol value must fail closed: {text}"
    );
}

/// The TOML `protocols = [...]` array selects the same combination as
/// the comma-separated CLI form.
#[test]
fn multi_protocol_toml_array_selects_the_combination() {
    let tag = std::process::id();
    let dir = std::env::temp_dir().join(format!("lr-daemon-multi-toml-{tag}", tag = tag));
    std::fs::create_dir_all(&dir).unwrap();
    let conf = dir.join("multi.toml");
    std::fs::write(
        &conf,
        "protocols = [\"bgp\", \"babel\"]\n\
         [bgp]\nlocal_as = 64512\nrouter_id = \"10.0.0.1\"\n\
         ebgp_policy = \"accept-all\"\nlocal_address = \"127.0.0.1\"\n\
         networks = [\"203.0.113.0/24\"]\n\
         [babel]\nport = 18697\n",
    )
    .unwrap();
    let mut d = Daemon::spawn(&["--config", conf.to_str().unwrap()], "toml");
    wait_log_all(
        &d.log,
        &[
            "protocols:   bgp,babel (one shared Loc-RIB)",
            "babel listening on 127.0.0.1:18697",
            "daemon: 2 engine(s) running",
            "daemon: no --peer/--listen given; idling (tick loop only)",
        ],
    );
    d.signal(SIGTERM);
    let (ok, text) = d.wait_exit();
    assert!(ok, "clean shutdown from the TOML-selected combination");
    assert!(text.contains("multi-protocol shutdown complete"));
    let _ = std::fs::remove_dir_all(&dir);
}
