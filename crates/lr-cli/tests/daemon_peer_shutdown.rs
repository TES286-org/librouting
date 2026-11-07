//! End-to-end tests for the per-peer administrative-down flag
//! (FRR `neighbor X shutdown` / BIRD `disabled`).
//!
//! A peer with `shutdown = true` set in its `[[peer]]` block:
//!  * keeps the daemon's outbound connector passive — no TCP SYN ever
//!    leaves the local speaker;
//!  * makes the listener refuse inbound SYNs from that peer's
//!    address with a `peer X admin-down` log line.
//!
//! Each test spawns the real binary (`CARGO_BIN_EXE_lr-daemon`) on a
//! distinct loopback port so they can run concurrently.

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
        static LOG_SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let seq = LOG_SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let log = std::env::temp_dir().join(format!(
            "lr-daemon-shutdown-{tag}-{}-{seq}.log",
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

/// `shutdown = true` on an outbound peer keeps the connector passive.
///
/// Topology: A (AS64512) has one outbound peer B (AS64513) marked
/// `shutdown = true`. B is listening but A's daemon never dials it.
/// The test pins:
///   * A logs the `admin-down (shutdown = true); connector stays passive`
///     line at startup;
///   * A's log never reaches Established (no dial happened);
///   * B's log never sees an inbound connection from A.
#[test]
fn shutdown_true_keeps_connector_passive() {
    let dir = std::env::temp_dir().join(format!(
        "lr-daemon-shutdown-out-{}",
        std::process::id()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let port_b = 19101u16;

    // B: plain listener. A's connector never dials, so B sees no
    // inbound from A.
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
            "--ebgp-policy",
            "accept-all",
        ],
        "out-b",
    );
    wait_log_all(&b.log, &["listening on"]);

    // A: one [[peer]] entry, peer B marked shutdown = true.
    let conf = dir.join("a.toml");
    std::fs::write(
        &conf,
        format!(
            "[bgp]\nlocal_as = 64512\nrouter_id = \"10.0.0.1\"\n\
             local_address = \"192.0.2.1\"\nebgp_policy = \"accept-all\"\n\
             networks = [\"203.0.113.0/24\"]\n\n\
             [[peer]]\nname = \"b\"\nremote = \"127.0.0.1:{port_b}\"\n\
             peer_as = 64513\nshutdown = true\n"
        ),
    )
    .unwrap();
    let a = Daemon::spawn(&["--config", conf.to_str().unwrap()], "out-a");

    // A's startup banner logs the admin-down state.
    wait_log_all(
        &a.log,
        &["admin-down (shutdown = true); connector stays passive"],
    );

    // Give the connector ample time to dial if it ever would — the
    // happy path (shutdown = false) reaches Established in well under
    // 5 s. A 5 s wait with no Established line is a strong signal the
    // connector stayed passive.
    thread::sleep(Duration::from_secs(3));
    let a_text = std::fs::read_to_string(&a.log).unwrap_or_default();
    let b_text = std::fs::read_to_string(&b.log).unwrap_or_default();
    assert!(
        !a_text.contains("Established"),
        "A must not establish with shutdown = true peer; log:\n{a_text}"
    );
    assert!(
        !a_text.contains("connect 127.0.0.1"),
        "A must not even attempt a connect to the shutdown peer; log:\n{a_text}"
    );
    assert!(
        !b_text.contains("inbound connection"),
        "B must not see any inbound from A; log:\n{b_text}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// `shutdown = true` on an inbound-only peer refuses inbound SYNs.
///
/// Topology: A (AS64512) listens with one inbound-only peer B
/// (configured via `address = "127.0.0.1"`) marked `shutdown = true`.
/// B dials A; A's listener rejects the inbound with the
/// `peer X admin-down` log line and never establishes.
#[test]
fn shutdown_true_refuses_inbound_syns() {
    let dir = std::env::temp_dir().join(format!(
        "lr-daemon-shutdown-in-{}",
        std::process::id()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let port_a = 19201u16;

    let conf = dir.join("a.toml");
    std::fs::write(
        &conf,
        format!(
            "[bgp]\nlocal_as = 64512\npeer_as = 64513\nrouter_id = \"10.0.0.1\"\n\
             listen_addr = \"127.0.0.1:{port_a}\"\nebgp_policy = \"accept-all\"\n\
             networks = [\"203.0.113.0/24\"]\n\n\
             [[peer]]\nname = \"b\"\naddress = \"127.0.0.1\"\nshutdown = true\n"
        ),
    )
    .unwrap();
    let a = Daemon::spawn(&["--config", conf.to_str().unwrap()], "in-a");
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
        "in-b",
    );

    // A's listener rejects the inbound with the admin-down message.
    wait_log_all(
        &a.log,
        &["inbound connection from 127.0.0.1", "admin-down (shutdown = true)"],
    );

    // B's connector retries but A never accepts; B never establishes.
    thread::sleep(Duration::from_secs(2));
    let b_text = std::fs::read_to_string(&b.log).unwrap_or_default();
    assert!(
        !b_text.contains("Established"),
        "B must not establish when A rejects with admin-down; log:\n{b_text}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// `shutdown = false` is the explicit un-shutdown — the peer behaves
/// exactly as if the key were absent. Sanity check that the new field
/// did not silently flip the default-on posture for a peer that
/// explicitly opts back in (FRR `no neighbor X shutdown`, BIRD
/// `disabled no`).
#[test]
fn shutdown_false_is_un_shutdown() {
    let dir = std::env::temp_dir().join(format!(
        "lr-daemon-shutdown-false-{}",
        std::process::id()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let port_b = 19301u16;

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
            "--ebgp-policy",
            "accept-all",
        ],
        "false-b",
    );
    wait_log_all(&b.log, &["listening on"]);

    let conf = dir.join("a.toml");
    std::fs::write(
        &conf,
        format!(
            "[bgp]\nlocal_as = 64512\nrouter_id = \"10.0.0.1\"\n\
             local_address = \"192.0.2.1\"\nebgp_policy = \"accept-all\"\n\
             networks = [\"203.0.113.0/24\"]\n\n\
             [[peer]]\nname = \"b\"\nremote = \"127.0.0.1:{port_b}\"\n\
             peer_as = 64513\nshutdown = false\n"
        ),
    )
    .unwrap();
    let a = Daemon::spawn(&["--config", conf.to_str().unwrap()], "false-a");

    // `shutdown = false` must NOT trigger the admin-down startup line
    // and the session must establish normally — i.e. the explicit
    // false is the same as the absent key.
    wait_log_all(&a.log, &["session #1 → Established"]);
    wait_log_all(&b.log, &["route installed 203.0.113.0/24"]);
    let a_text = std::fs::read_to_string(&a.log).unwrap_or_default();
    assert!(
        !a_text.contains("admin-down"),
        "shutdown = false must not log admin-down; log:\n{a_text}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}
