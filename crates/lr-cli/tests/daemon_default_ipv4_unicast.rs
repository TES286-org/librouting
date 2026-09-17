//! End-to-end tests for FRR `bgp default ipv4-unicast` (W2.1) on the
//! real `lr-daemon` binary.
//!
//! FRR's default is `bgp default ipv4-unicast` (on) — every BGP peer is
//! implicitly activated for IPv4 unicast. The `no bgp default
//! ipv4-unicast` posture requires explicit per-peer activation. The
//! daemon wires this through `[bgp] default_ipv4_unicast = bool` and
//! the `--no-default-ipv4-unicast` CLI flag; per-peer override is
//! `[peer] default_ipv4_unicast = bool`.
//!
//! These tests verify:
//!   1. The flag parses and the daemon starts up; the startup status
//!      printout names the new knob.
//!   2. With `--no-default-ipv4-unicast` and no `mp_families`
//!      configured, no IPv4 unicast routes flow between two daemons
//!      (the family is not active for either peer).
//!   3. With `--no-default-ipv4-unicast` AND an explicit
//!      `--mp-family ipv4-unicast` on both peers, IPv4 routes flow
//!      again — the explicit activation matches FRR
//!      `address-family ipv4 unicast` / `neighbor X activate`.

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
            std::env::temp_dir().join(format!("lr-daemon-w21-{tag}-{}.log", std::process::id()));
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

fn free_port() -> u16 {
    // A fixed range *below* the OS ephemeral allocations (Linux
    // 32768+, macOS 49152+) closes the classic bind(:0)-then-drop
    // TOCTOU: the kernel never hands these ports to a sibling probe
    // or an outbound connection, so the only contenders are sibling
    // tests in this binary — and the per-process counter makes the
    // pick unique per call (observed live as "Address already in
    // use" on a macOS CI runner with the :0 probe).
    use std::sync::atomic::{AtomicU32, Ordering};
    static COUNTER: AtomicU32 = AtomicU32::new(0);
    loop {
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let seed = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.subsec_nanos())
            .unwrap_or(0);
        let port = 20000u32 + (seed.wrapping_add(n.wrapping_mul(7919)) % 12_000);
        if std::net::TcpListener::bind(format!("127.0.0.1:{port}")).is_ok() {
            return port as u16;
        }
    }
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

/// Wait until the log stops growing for 1s (convergence), then return
/// it — used for negative assertions (the route must NOT appear).
fn wait_quiet(path: &std::path::Path) -> String {
    let deadline = Instant::now() + Duration::from_secs(8);
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

/// The default posture: `default_ipv4_unicast = true`, so a `network`
/// statement flows through both daemons normally (regression check).
#[test]
fn default_on_propagates_v4_routes() {
    let port_b = free_port();
    let a = Daemon::spawn(
        &[
            "--local-as",
            "64512",
            "--peer-as",
            "64513",
            "--router-id",
            "10.0.0.1",
            "--peer",
            &format!("127.0.0.1:{port_b}"),
            "--local-address",
            "192.0.2.1",
            "--network",
            "203.0.113.0/24",
            "--ebgp-policy",
            "accept-all",
        ],
        "default-on-a",
    );
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
        "default-on-b",
    );

    wait_log_all(&a.log, &["ipv4-unicast: default=true"]);
    wait_log_all(&a.log, &["session #1 → Established"]);
    wait_log_all(&b.log, &["session #1 → Established"]);
    wait_log_all(&b.log, &["route installed 203.0.113.0/24"]);
}

/// With `--no-default-ipv4-unicast` and no `mp_families` configured on
/// either side, IPv4 unicast is NOT active for either peer — no IPv4
/// routes flow (the originating daemon refuses to advertise IPv4 NLRI
/// and the receiving daemon refuses to install it).
#[test]
fn no_default_ipv4_unicast_suppresses_v4_routes() {
    let port_b = free_port();
    let a = Daemon::spawn(
        &[
            "--local-as",
            "64512",
            "--peer-as",
            "64513",
            "--router-id",
            "10.0.0.1",
            "--peer",
            &format!("127.0.0.1:{port_b}"),
            "--local-address",
            "192.0.2.1",
            "--network",
            "203.0.113.0/24",
            "--ebgp-policy",
            "accept-all",
            "--no-default-ipv4-unicast",
        ],
        "no-default-a",
    );
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
            "--no-default-ipv4-unicast",
        ],
        "no-default-b",
    );

    wait_log_all(&a.log, &["ipv4-unicast: default=false"]);
    wait_log_all(&a.log, &["session #1 → Established"]);
    wait_log_all(&b.log, &["session #1 → Established"]);
    // Convergence without the prefix: neither side is active for IPv4
    // unicast, so A does not advertise and B does not install.
    let _ = wait_quiet(&b.log);
    let b_log = std::fs::read_to_string(&b.log).unwrap_or_default();
    assert!(
        !b_log.contains("route installed 203.0.113.0/24"),
        "no IPv4 route when default_ipv4_unicast is off; log: {b_log}"
    );
}

/// Explicit activation: `--no-default-ipv4-unicast` AND
/// `--mp-family ipv4-unicast` on both peers reactivates IPv4 unicast
/// (FRR `no bgp default ipv4-unicast` + `neighbor X activate`).
#[test]
fn explicit_mp_family_reactivates_v4() {
    let port_b = free_port();
    let a = Daemon::spawn(
        &[
            "--local-as",
            "64512",
            "--peer-as",
            "64513",
            "--router-id",
            "10.0.0.1",
            "--peer",
            &format!("127.0.0.1:{port_b}"),
            "--local-address",
            "192.0.2.1",
            "--network",
            "203.0.113.0/24",
            "--ebgp-policy",
            "accept-all",
            "--no-default-ipv4-unicast",
            "--mp-family",
            "ipv4-unicast",
        ],
        "explicit-a",
    );
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
            "--no-default-ipv4-unicast",
            "--mp-family",
            "ipv4-unicast",
        ],
        "explicit-b",
    );

    wait_log_all(&a.log, &["session #1 → Established"]);
    wait_log_all(&b.log, &["session #1 → Established"]);
    wait_log_all(&b.log, &["route installed 203.0.113.0/24"]);
}
