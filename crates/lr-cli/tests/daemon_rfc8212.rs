//! End-to-end tests for the RFC 8212 default eBGP route behaviors on
//! the real `lr-daemon` binary.
//!
//! RFC 8212 §3 (updating RFC 4271 §9.1/§9.1.3): routes from an
//! external peer without an explicit Import Policy are not eligible
//! for the decision process, and routes must not enter the Adj-RIB-Out
//! of an external peer without an explicit Export Policy. The daemon
//! enables the mode by default (`[bgp] ebgp_policy = "rfc8212"`);
//! `accept-all` restores the legacy default-accept the RFC permits as
//! a deviation (Appendix A "insecure-mode").
//!
//! Topology per test: A (AS64512, originates 203.0.113.0/24) → B
//! (AS64513, receives), over real TCP on loopback.

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
            std::env::temp_dir().join(format!("lr-daemon-8212-{tag}-{}.log", std::process::id()));
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
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// Default mode: the session establishes, but without import/export
/// route-maps nothing flows in either direction — deny-in keeps the
/// prefix out of B's Loc-RIB, deny-out keeps A from announcing — and
/// both sides say so at startup (RFC 8212 Appendix A guidance).
#[test]
fn default_mode_denies_both_directions() {
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
        ],
        "deny-a",
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
        ],
        "deny-b",
    );

    // The session itself must come up — RFC 8212 filters routes, not
    // transport.
    wait_log_all(&a.log, &["session #1 → Established"]);
    wait_log_all(&b.log, &["session #1 → Established"]);

    // Startup warnings name the incomplete configuration on each side.
    wait_log_all(
        &a.log,
        &["no export route-map; announcing nothing (RFC 8212)"],
    );
    wait_log_all(
        &b.log,
        &["no import route-map; discarding received routes (RFC 8212)"],
    );

    // Convergence without the prefix: deny-out on A + deny-in on B.
    let quiet = wait_quiet(&b.log);
    assert!(
        !quiet.contains("route installed 203.0.113.0/24"),
        "policy-less eBGP must not propagate routes; log: {quiet}"
    );
}

/// Explicit policy is the RFC-intended escape hatch: permit-all
/// route-maps on the export (A) and import (B) sides restore the flow
/// while the default mode stays on.
#[test]
fn explicit_permit_all_route_maps_restore_flow() {
    let port_b = free_port();
    let cfg_a = std::env::temp_dir().join(format!("lr-8212-a-{}.toml", std::process::id()));
    std::fs::write(
        &cfg_a,
        format!(
            r#"
[bgp]
local_as = 64512
router_id = "10.0.0.1"
local_address = "192.0.2.1"
networks = ["203.0.113.0/24"]

[[route-map]]
name = "export-all"
entry = 10
permit = true

[[peer]]
remote = "127.0.0.1:{port_b}"
peer_as = 64513
export = "export-all"
"#,
        ),
    )
    .unwrap();

    let cfg_b = std::env::temp_dir().join(format!("lr-8212-b-{}.toml", std::process::id()));
    std::fs::write(
        &cfg_b,
        format!(
            r#"
[bgp]
local_as = 64513
peer_as = 64512
router_id = "10.0.0.2"
listen_addr = "127.0.0.1:{port_b}"
local_address = "192.0.2.2"

[[route-map]]
name = "import-all"
entry = 10
permit = true

[[peer]]
address = "127.0.0.1"
import = "import-all"
"#,
        ),
    )
    .unwrap();

    let _a = Daemon::spawn(&["--config", cfg_a.to_str().unwrap()], "map-a");
    let b = Daemon::spawn(&["--config", cfg_b.to_str().unwrap()], "map-b");

    wait_log_all(&b.log, &["route installed 203.0.113.0/24"]);
    // No policy-less warnings: every direction carries explicit policy.
    let b_text = std::fs::read_to_string(&b.log).unwrap_or_default();
    assert!(
        !b_text.contains("no import route-map"),
        "B has an import route-map; log: {b_text}"
    );
    std::fs::remove_file(&cfg_a).ok();
    std::fs::remove_file(&cfg_b).ok();
}

/// The documented deviation: `accept-all` restores the RFC 4271
/// default-accept without attaching any route-maps.
#[test]
fn accept_all_mode_restores_flow() {
    let port_b = free_port();

    let _a = Daemon::spawn(
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
        "insec-a",
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
        "insec-b",
    );

    wait_log_all(&b.log, &["route installed 203.0.113.0/24"]);
    // The banner records the active mode.
    let b_text = std::fs::read_to_string(&b.log).unwrap_or_default();
    assert!(
        b_text.contains("ebgp policy: accept-all"),
        "banner must record the deviation; log: {b_text}"
    );
}

/// RFC 8212 scopes to EBGP sessions: an iBGP pair (same AS) exchanges
/// routes without any policy, even in the default mode.
#[test]
fn ibgp_sessions_are_exempt() {
    let port_b = free_port();

    let _a = Daemon::spawn(
        &[
            "--local-as",
            "64512",
            "--peer-as",
            "64512",
            "--router-id",
            "10.0.0.1",
            "--peer",
            &format!("127.0.0.1:{port_b}"),
            "--local-address",
            "192.0.2.1",
            "--network",
            "203.0.113.0/24",
        ],
        "ibgp-a",
    );
    let b = Daemon::spawn(
        &[
            "--local-as",
            "64512",
            "--peer-as",
            "64512",
            "--router-id",
            "10.0.0.2",
            "--listen",
            &format!("127.0.0.1:{port_b}"),
            "--local-address",
            "192.0.2.2",
        ],
        "ibgp-b",
    );

    wait_log_all(&b.log, &["route installed 203.0.113.0/24"]);
    // And no policy-less warnings fire for the iBGP peer.
    let b_text = std::fs::read_to_string(&b.log).unwrap_or_default();
    assert!(
        !b_text.contains("no import route-map"),
        "iBGP is exempt from RFC 8212; log: {b_text}"
    );
}

/// An unknown mode is a hard startup error — never silently
/// permissive.
#[test]
fn unknown_mode_fails_startup() {
    let out = Command::new(BIN)
        .args(["--local-as", "64512", "--ebgp-policy", "permissive"])
        .output()
        .expect("run lr-daemon");
    assert!(!out.status.success(), "startup must fail");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("bad --ebgp-policy 'permissive'"),
        "stderr: {stderr}"
    );
}
