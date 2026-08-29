//! End-to-end tests for the multi-peer `lr-daemon`: `[[peer]]` TOML
//! configuration, concurrent sessions with independent connectors,
//! inbound source-address matching and fan-out between peers.
//!
//! Each test spawns the real binary (`CARGO_BIN_EXE_lr-daemon`) on
//! distinct loopback ports so they can run concurrently.

#![cfg(unix)]

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
            std::env::temp_dir().join(format!("lr-daemon-mp-{tag}-{}.log", std::process::id()));
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
}

impl Drop for Daemon {
    fn drop(&mut self) {
        unsafe {
            kill(self.pid(), 15);
        }
        let _ = self.child.wait();
        let _ = std::fs::remove_file(&self.log);
    }
}

extern "C" {
    fn kill(pid: i32, sig: i32) -> i32;
}

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

/// Three-daemon topology over real TCP on loopback:
///
/// ```text
///   B (AS64513, listens :PB, originates 198.51.100.0/24)
///        ▲          A (AS64512, two outbound [[peer]]s,
///        │              originates 203.0.113.0/24)
///   C (AS64514, listens :PC) ◄──┘
/// ```
///
/// A's multi-peer fan-out must deliver its own prefix to both B and C,
/// and B's prefix must reach C through A (transit).
#[test]
fn multi_peer_fanout_and_transit() {
    let dir = std::env::temp_dir().join(format!("lr-daemon-mp-fanout-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let port_b = 18101u16;
    let port_c = 18102u16;

    // B and C first: A's connectors dial them. The subject here is
    // A's multi-peer fan-out, so all three run the RFC 8212
    // accept-all deviation instead of attaching route-maps.
    let b = Daemon::spawn(
        &[
            "--local-as",
            "64513",
            "--peer-as",
            "64512",
            "--router-id",
            "10.0.0.2",
            "--listen",
            &format!("127.0.0.1:{port_b}"),
            "--local-address",
            "192.0.2.2",
            "--network",
            "198.51.100.0/24",
            "--ebgp-policy",
            "accept-all",
        ],
        "fanout-b",
    );
    wait_log_all(&b.log, &["listening on"]);
    let c = Daemon::spawn(
        &[
            "--local-as",
            "64514",
            "--peer-as",
            "64512",
            "--router-id",
            "10.0.0.3",
            "--listen",
            &format!("127.0.0.1:{port_c}"),
            "--ebgp-policy",
            "accept-all",
        ],
        "fanout-c",
    );
    wait_log_all(&c.log, &["listening on"]);

    // A: two [[peer]] entries with distinct ASNs — impossible to express
    // with the legacy single-peer flags. `networks` must precede the
    // [[peer]] tables (TOML: keys after an array-of-tables header belong
    // to that table).
    let conf = dir.join("a.toml");
    std::fs::write(
        &conf,
        format!(
            "[bgp]\nlocal_as = 64512\nrouter_id = \"10.0.0.1\"\nebgp_policy = \"accept-all\"\n\
             local_address = \"192.0.2.1\"\nnetworks = [\"203.0.113.0/24\"]\n\n\
             [[peer]]\nname = \"b\"\nremote = \"127.0.0.1:{port_b}\"\npeer_as = 64513\n\n\
             [[peer]]\nname = \"c\"\nremote = \"127.0.0.1:{port_c}\"\npeer_as = 64514\n"
        ),
    )
    .unwrap();
    let a = Daemon::spawn(&["--config", conf.to_str().unwrap()], "fanout-a");

    // Both of A's sessions establish and both peers see A's prefix.
    wait_log_all(
        &a.log,
        &["session #1 → Established", "session #2 → Established"],
    );
    wait_log_all(&b.log, &["route installed 203.0.113.0/24"]);
    wait_log_all(&c.log, &["route installed 203.0.113.0/24"]);

    // Transit: B's prefix reaches A and is re-advertised to C.
    wait_log_all(&a.log, &["route installed 198.51.100.0/24"]);
    wait_log_all(&c.log, &["route installed 198.51.100.0/24"]);

    let _ = std::fs::remove_dir_all(&dir);
}

/// Inbound source-address matching: the listener runs in explicit-peer
/// mode (`[[peer]]` with `address`), and an inbound connection from the
/// configured address is bound to that peer's session.
#[test]
fn inbound_peer_matching_by_source_address() {
    let dir = std::env::temp_dir().join(format!("lr-daemon-mp-inbound-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let port_a = 18201u16;

    let conf = dir.join("a.toml");
    std::fs::write(
        &conf,
        format!(
            "[bgp]\nlocal_as = 64512\npeer_as = 64513\nrouter_id = \"10.0.0.1\"\nebgp_policy = \"accept-all\"\n\
             listen_addr = \"127.0.0.1:{port_a}\"\nlocal_address = \"192.0.2.1\"\n\
             networks = [\"203.0.113.0/24\"]\n\n\
             [[peer]]\nname = \"b\"\naddress = \"127.0.0.1\"\n"
        ),
    )
    .unwrap();
    let a = Daemon::spawn(&["--config", conf.to_str().unwrap()], "inbound-a");
    wait_log_all(&a.log, &["listening on"]);

    let b = Daemon::spawn(
        &[
            "--local-as",
            "64513",
            "--peer-as",
            "64512",
            "--router-id",
            "10.0.0.2",
            "--peer",
            &format!("127.0.0.1:{port_a}"),
            "--local-address",
            "192.0.2.2",
            "--ebgp-policy",
            "accept-all",
        ],
        "inbound-b",
    );

    // A accepts B's connection on the matched peer session and B sees
    // A's originated prefix.
    wait_log_all(&a.log, &["session #1 → Established"]);
    wait_log_all(&b.log, &["route installed 203.0.113.0/24"]);

    let _ = std::fs::remove_dir_all(&dir);
}

/// Fail-closed matching: with explicit `[[peer]]` entries, an inbound
/// connection whose source address matches no peer is rejected and the
/// session never establishes.
#[test]
fn unmatched_inbound_connection_is_rejected() {
    let dir = std::env::temp_dir().join(format!("lr-daemon-mp-reject-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let port_a = 18301u16;

    // The configured peer expects connections from 127.0.0.99 — the
    // connector below dials from 127.0.0.1 and must be rejected.
    let conf = dir.join("a.toml");
    std::fs::write(
        &conf,
        format!(
            "[bgp]\nlocal_as = 64512\npeer_as = 64513\nrouter_id = \"10.0.0.1\"\n\
             listen_addr = \"127.0.0.1:{port_a}\"\n\n\
             [[peer]]\nname = \"b\"\naddress = \"127.0.0.99\"\n"
        ),
    )
    .unwrap();
    let a = Daemon::spawn(&["--config", conf.to_str().unwrap()], "reject-a");
    wait_log_all(&a.log, &["listening on"]);

    let b = Daemon::spawn(
        &[
            "--local-as",
            "64513",
            "--peer-as",
            "64512",
            "--router-id",
            "10.0.0.2",
            "--peer",
            &format!("127.0.0.1:{port_a}"),
        ],
        "reject-b",
    );

    // A logs the rejection; neither side ever reaches Established.
    wait_log_all(&a.log, &["rejected: no configured peer matches"]);
    thread::sleep(Duration::from_secs(1));
    let a_text = std::fs::read_to_string(&a.log).unwrap_or_default();
    let b_text = std::fs::read_to_string(&b.log).unwrap_or_default();
    assert!(
        !a_text.contains("Established"),
        "A must not establish with an unmatched peer; log:\n{a_text}"
    );
    assert!(
        !b_text.contains("Established"),
        "B must not establish when rejected; log:\n{b_text}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// Per-peer settings must actually reach the session: peer B inherits
/// the global hold time (90) while peer C overrides it (30). Both
/// sessions establish against real listeners, so the negotiated hold
/// time is visible through the runtime API `sessions` output.
#[test]
fn per_peer_hold_time_reaches_the_session() {
    let dir = std::env::temp_dir().join(format!("lr-daemon-mp-hold-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let socket = dir.join("a.api");
    let port_b = 18401u16;
    let port_c = 18402u16;

    // B and C: plain listeners (legacy accept-any mode).
    let b = Daemon::spawn(
        &[
            "--local-as",
            "64513",
            "--peer-as",
            "64512",
            "--router-id",
            "10.0.0.2",
            "--listen",
            &format!("127.0.0.1:{port_b}"),
            "--local-address",
            "192.0.2.2",
        ],
        "hold-b",
    );
    wait_log_all(&b.log, &["listening on"]);
    let c = Daemon::spawn(
        &[
            "--local-as",
            "64514",
            "--peer-as",
            "64512",
            "--router-id",
            "10.0.0.3",
            "--listen",
            &format!("127.0.0.1:{port_c}"),
            "--local-address",
            "192.0.2.3",
            "--hold-time",
            "30",
        ],
        "hold-c",
    );
    wait_log_all(&c.log, &["listening on"]);

    let conf = dir.join("a.toml");
    std::fs::write(
        &conf,
        format!(
            "[bgp]\nlocal_as = 64512\nrouter_id = \"10.0.0.1\"\nhold_time = 90\n\
             local_address = \"192.0.2.1\"\n\n\
             [[peer]]\nname = \"b\"\nremote = \"127.0.0.1:{port_b}\"\npeer_as = 64513\n\n\
             [[peer]]\nname = \"c\"\nremote = \"127.0.0.1:{port_c}\"\npeer_as = 64514\nhold_time = 30\n"
        ),
    )
    .unwrap();
    let a = Daemon::spawn(
        &[
            "--config",
            conf.to_str().unwrap(),
            "--api-socket",
            socket.to_str().unwrap(),
        ],
        "hold-a",
    );
    wait_log_all(
        &a.log,
        &["session #1 → Established", "session #2 → Established"],
    );

    let mut conn = std::os::unix::net::UnixStream::connect(&socket).expect("connect api");
    use std::io::{Read, Write};
    conn.write_all(b"sessions\n").unwrap();
    conn.flush().unwrap();
    thread::sleep(Duration::from_millis(300));
    let mut buf = Vec::new();
    conn.set_nonblocking(true).unwrap();
    let _ = conn.read_to_end(&mut buf);
    let sessions = String::from_utf8_lossy(&buf).into_owned();
    // Negotiated hold time: min of the two sides' offers — 90 with B,
    // 30 with C (C offers 30 via its own --hold-time flag).
    assert!(sessions.contains("hold-time=90"), "sessions: {sessions}");
    assert!(sessions.contains("hold-time=30"), "sessions: {sessions}");
    assert!(sessions.contains("peer-as=64513"), "sessions: {sessions}");
    assert!(sessions.contains("peer-as=64514"), "sessions: {sessions}");

    let _ = std::fs::remove_dir_all(&dir);
}
