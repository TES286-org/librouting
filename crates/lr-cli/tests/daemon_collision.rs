//! End-to-end tests for RFC 4271 §6.8 connection collision detection:
//! two `lr-daemon` processes configured as BIDIRECTIONAL peers of each
//! other (`remote` + `address` on one `[[peer]]`), both connectors
//! dialing simultaneously, so a genuine connection collision occurs.
//!
//! Two §6.8-legal outcomes exist, and the test asserts the invariants
//! they share instead of picking a winner:
//!
//! - **Truly simultaneous dials** — both sides hold two half-open
//!   connections and compare BGP Identifiers: the connection initiated
//!   by the higher identifier survives (B, 10.0.0.2 > 10.0.0.1), so
//!   B's outbound session (#1) and A's inbound challenger (#2)
//!   establish while the other two transports close with a
//!   Cease / Connection Collision Resolution NOTIFICATION. The
//!   selection rule itself is pinned by the `collision_tests` unit
//!   tests in `lr-router`.
//! - **Desynchronized dials** (skewed or heavily instrumented
//!   scheduling, e.g. tarpaulin): the first connection to complete its
//!   handshake reaches Established, and the late arrival is closed by
//!   the "an Established connection wins" rule — whichever transport
//!   happened to finish first survives.
//!
//! Either way each daemon must converge to exactly one Established
//! session for the peer, the collision must be resolved by the router
//! (not by accident of transport failure), and both prefixes must
//! propagate across the surviving connection.

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
        let log = std::env::temp_dir().join(format!(
            "lr-daemon-collide-{tag}-{}.log",
            std::process::id()
        ));
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
    let deadline = Instant::now() + Duration::from_secs(60);
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

/// Read a log file until it contains any one of the needles (bounded
/// wait); returns the needle that matched.
fn wait_log_any(path: &std::path::Path, needles: &[&str]) -> String {
    let deadline = Instant::now() + Duration::from_secs(60);
    let mut text = String::new();
    while Instant::now() < deadline {
        text = std::fs::read_to_string(path).unwrap_or_default();
        if let Some(hit) = needles.iter().find(|n| text.contains(*n)) {
            return (*hit).to_string();
        }
        thread::sleep(Duration::from_millis(100));
    }
    panic!("log never contained any of {needles:?}; last: {text}");
}

/// Bidirectional peers: both daemons dial and listen at the same time.
/// The higher BGP Identifier (B) initiates the surviving connection, so
/// exactly one session per side reaches Established and both prefixes
/// propagate across it.
#[test]
fn bidirectional_collision_converges_to_one_session() {
    let dir = std::env::temp_dir().join(format!("lr-daemon-collide-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let port_a = 18301u16;
    let port_b = 18302u16;

    let conf_a = dir.join("a.toml");
    std::fs::write(
        &conf_a,
        format!(
            "[bgp]\nlocal_as = 64512\nrouter_id = \"10.0.0.1\"\nebgp_policy = \"accept-all\"\n\
             local_address = \"192.0.2.1\"\nlisten_addr = \"127.0.0.1:{port_a}\"\n\
             networks = [\"203.0.113.0/24\"]\n\n\
             [[peer]]\nname = \"b\"\nremote = \"127.0.0.1:{port_b}\"\n\
             address = \"127.0.0.1\"\npeer_as = 64513\n"
        ),
    )
    .unwrap();
    let conf_b = dir.join("b.toml");
    std::fs::write(
        &conf_b,
        format!(
            "[bgp]\nlocal_as = 64513\nrouter_id = \"10.0.0.2\"\nebgp_policy = \"accept-all\"\n\
             local_address = \"192.0.2.2\"\nlisten_addr = \"127.0.0.1:{port_b}\"\n\
             networks = [\"198.51.100.0/24\"]\n\n\
             [[peer]]\nname = \"a\"\nremote = \"127.0.0.1:{port_a}\"\n\
             address = \"127.0.0.1\"\npeer_as = 64512\n"
        ),
    )
    .unwrap();

    let a = Daemon::spawn(&["--config", conf_a.to_str().unwrap()], "a");
    let b = Daemon::spawn(&["--config", conf_b.to_str().unwrap()], "b");

    // Convergence: exactly one session per daemon reaches Established —
    // either transport may legally win (see the module docs). Wait for
    // whichever appears, then verify the other never establishes.
    wait_log_any(
        &a.log,
        &["session #1 → Established", "session #2 → Established"],
    );
    wait_log_any(
        &b.log,
        &["session #1 → Established", "session #2 → Established"],
    );

    // Both prefixes propagate across the surviving connection.
    wait_log_all(&a.log, &["route installed 198.51.100.0/24"]);
    wait_log_all(&b.log, &["route installed 203.0.113.0/24"]);

    // The collision was detected and resolved by the router (RFC 4271
    // §6.8) on at least one side. Under slow/skewed scheduling (e.g.
    // coverage instrumentation) the first dial may fail with ECONNREFUSED
    // before the other listener is up; the retry then collides with the
    // now-established winner, so wait a bounded while for the evidence
    // on either daemon.
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        let a_text = std::fs::read_to_string(&a.log).unwrap();
        let b_text = std::fs::read_to_string(&b.log).unwrap();
        if a_text.contains("connection collision") || b_text.contains("connection collision") {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "neither daemon logged a collision resolution; a:\n{a_text}\nb:\n{b_text}"
        );
        thread::sleep(Duration::from_millis(100));
    }

    // Exactly one Established session per daemon: the losing transport
    // — whichever it was — never reaches Established for the whole run.
    // (Two Established sessions for one peer would mean the collision
    // resolution failed to converge, not just a different winner.)
    for log in [&a.log, &b.log] {
        let text = std::fs::read_to_string(log).unwrap();
        let one = text.contains("session #1 → Established");
        let two = text.contains("session #2 → Established");
        assert!(
            one ^ two,
            "expected exactly one of the two sessions Established, got #1={one} #2={two}; log:\n{text}"
        );
    }

    let _ = std::fs::remove_dir_all(&dir);
}
