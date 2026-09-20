//! End-to-end tests for the daemon-level cross-protocol surfaces:
//! `[[redistribute]]` (ROADMAP-v3 D4.1) and `[[aggregate]]`
//! (ROADMAP-v3 D4.2) on the real `lr-daemon` binary.
//!
//! Topology: the same loopback BGP shape the policy tests use — real
//! TCP sessions between real daemon processes, assertions against the
//! daemons' logs.
//!
//! - redistribution: A (AS64512, two prefixes) → B (AS64513) with a
//!   `bgp → bgp` pipe whose allow-list covers only one of them. The
//!   router logs `redistribute: <prefix> -> BGP` exactly for the
//!   re-originated prefixes, so the allow-list decision is directly
//!   observable.
//! - aggregation: A (two covering specifics) → B (AS64513) with
//!   `[[aggregate]] 198.51.100.0/23`, B → C (AS64514). The aggregate
//!   exists only when the daemon registered it, so C installing
//!   198.51.100.0/23 proves the whole chain (origination at B,
//!   export, install at C).

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
            std::env::temp_dir().join(format!("lr-daemon-xproto-{tag}-{}.log", std::process::id()));
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

extern "C" {
    fn kill(pid: i32, sig: i32) -> i32;
}

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

/// Wait until the log stops growing for 1s (convergence), then
/// return it — used for negative assertions (a line must NOT appear).
fn wait_quiet(path: &std::path::Path) -> String {
    let deadline = Instant::now() + Duration::from_secs(30);
    let mut last = String::new();
    let mut last_change = Instant::now();
    while Instant::now() < deadline {
        thread::sleep(Duration::from_millis(200));
        let text = std::fs::read_to_string(path).unwrap_or_default();
        if text == last {
            if last_change.elapsed() > Duration::from_secs(1) && !text.is_empty() {
                return text;
            }
        } else {
            last = text;
            last_change = Instant::now();
        }
    }
    last
}

fn free_port() -> u16 {
    for _ in 0..5 {
        if let Ok(listener) = std::net::TcpListener::bind("127.0.0.1:0") {
            let port = listener.local_addr().unwrap().port();
            drop(listener);
            std::thread::sleep(std::time::Duration::from_millis(10));
            return port;
        }
    }
    panic!("could not bind a free port after 5 attempts");
}

/// A `bgp → bgp` pipe with an allow-list re-originates exactly the
/// covered prefix. The router emits one `redistribute: <prefix> ->
/// BGP` log event per re-originated route, so both the positive and
/// the (allow-listed-out) negative case are observable in B's log.
#[test]
fn redistribute_pipe_honours_allow_list() {
    let port_a = free_port();
    let port_b = free_port();
    let cfg_b = std::env::temp_dir().join(format!("lr-xproto-b-{}.toml", std::process::id()));
    std::fs::write(
        &cfg_b,
        format!(
            r#"
[bgp]
local_as = 64513
router_id = "10.0.0.2"
listen_addr = "127.0.0.1:{port_b}"
local_address = "192.0.2.2"
ebgp_policy = "accept-all"

[[peer]]
remote = "127.0.0.1:{port_a}"
peer_as = 64512

[[redistribute]]
source = "bgp"
target = "bgp"
allow = ["203.0.113.0/24"]
"#,
        ),
    )
    .unwrap();

    let a = Daemon::spawn(
        &[
            "--local-as",
            "64512",
            "--peer-as",
            "64513",
            "--router-id",
            "10.0.0.1",
            "--listen",
            &format!("127.0.0.1:{port_a}"),
            "--local-address",
            "192.0.2.1",
            "--ebgp-policy",
            "accept-all",
            "--network",
            "203.0.113.0/24",
            "--network",
            "198.51.100.0/24",
        ],
        "redist-a",
    );
    let b = Daemon::spawn(&["--config", cfg_b.to_str().unwrap()], "redist-b");

    // The startup banner must show the pipe; the router must log the
    // re-origination for the allowed prefix once it arrives from A.
    wait_log_all(
        &b.log,
        &[
            "redistribute: bgp -> bgp",
            "redistribute: 203.0.113.0/24 -> BGP",
        ],
    );

    // Negative: the uncovered prefix never crosses the pipe.
    let quiet = wait_quiet(&b.log);
    assert!(
        !quiet.contains("redistribute: 198.51.100.0/24 -> BGP"),
        "allow-listed-out prefix must not be redistributed; log: {quiet}"
    );
    let _ = a;
    std::fs::remove_file(&cfg_b).ok();
}

/// The `[[aggregate]]` table registers a real RFC 4271 §9.2.2.2
/// aggregate on the router: C (one hop past the aggregating daemon)
/// installs 198.51.100.0/23, which exists only because B registered
/// it, originated it when A's specifics landed, and exported it.
#[test]
fn aggregate_reaches_a_downstream_peer() {
    let port_a = free_port();
    let port_b = free_port();
    let port_c = free_port();
    let cfg_b = std::env::temp_dir().join(format!("lr-xproto-agg-b-{}.toml", std::process::id()));
    std::fs::write(
        &cfg_b,
        format!(
            r#"
[bgp]
local_as = 64513
router_id = "10.0.0.2"
listen_addr = "127.0.0.1:{port_b}"
local_address = "192.0.2.2"
ebgp_policy = "accept-all"

[[peer]]
remote = "127.0.0.1:{port_a}"
peer_as = 64512

[[peer]]
remote = "127.0.0.1:{port_c}"
peer_as = 64514

[[aggregate]]
prefix = "198.51.100.0/23"
"#,
        ),
    )
    .unwrap();

    // A and C listen; B dials both.
    let a = Daemon::spawn(
        &[
            "--local-as",
            "64512",
            "--peer-as",
            "64513",
            "--router-id",
            "10.0.0.1",
            "--listen",
            &format!("127.0.0.1:{port_a}"),
            "--local-address",
            "192.0.2.1",
            "--ebgp-policy",
            "accept-all",
            "--network",
            "198.51.100.0/24",
            "--network",
            "198.51.101.0/24",
        ],
        "agg-a",
    );
    let c = Daemon::spawn(
        &[
            "--local-as",
            "64514",
            "--peer-as",
            "64513",
            "--router-id",
            "10.0.0.3",
            "--listen",
            &format!("127.0.0.1:{port_c}"),
            "--local-address",
            "192.0.2.3",
            "--ebgp-policy",
            "accept-all",
        ],
        "agg-c",
    );
    let b = Daemon::spawn(&["--config", cfg_b.to_str().unwrap()], "agg-b");

    // B's banner shows the registered aggregate; C installs the
    // aggregate itself (never advertised as a plain specific).
    wait_log_all(&b.log, &["aggregate:    198.51.100.0/23"]);
    wait_log_all(&c.log, &["route installed 198.51.100.0/23"]);
    let _ = a;
    std::fs::remove_file(&cfg_b).ok();
}
