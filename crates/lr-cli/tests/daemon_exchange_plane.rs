//! End-to-end tests for the W6.3 exchange-plane prototype on the real
//! `lr-daemon` binary (feature `exchange-plane`).
//!
//! These tests exercise the design's exit criteria that need a live
//! pair of lr speakers (`docs/research/EXCHANGE-PLANE.md` §10):
//!
//!   1. Both daemons opt in with a shared key: the session
//!      establishes, IPv4 routes flow, and the receiving daemon
//!      surfaces the verified record set carrying all three record
//!      classes (hint + policy intent + provenance).
//!   2. Key mismatch: the key *id* still negotiates (the wire carries
//!      ids, never secrets), but every record set fails the tag check
//!      — records are dropped with a log line while the route's
//!      standard content survives (design §8: fail-open for route
//!      data, fail-closed for trust assertions).
//!   3. One-sided opt-in: a plane-configured daemon peers with a
//!      plain daemon — the capability stays inert (RFC 5492 §3), the
//!      session and routing behave exactly as without the feature,
//!      and no records surface anywhere.

#![cfg(all(unix, feature = "exchange-plane"))]

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
            std::env::temp_dir().join(format!("lr-daemon-w63-{tag}-{}.log", std::process::id()));
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
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
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

/// The TOML config for one exchange-plane daemon: the plane on with a
/// key block, an import/export route-map bound to the peer (so the
/// §5.2 policy-intent record has content), and the routing essentials.
/// `outbound` daemons connect to the listener and originate the test
/// prefix; `inbound` daemons listen and expect the peer's address.
fn write_xp_config(path: &std::path::Path, outbound: bool, port: u16, key: &str) {
    let bgp = if outbound {
        format!(
            "[bgp]\nlocal_as = 64512\npeer_as = 64513\nrouter_id = \"10.0.0.1\"\n\
             local_address = \"192.0.2.1\"\nebgp_policy = \"accept-all\"\n\
             networks = [\"203.0.113.0/24\"]\n\
             exchange_plane = true\nexchange_plane_keys = [\"1:{key}\"]\n\n"
        )
    } else {
        format!(
            "[bgp]\nlocal_as = 64513\npeer_as = 64512\nrouter_id = \"10.0.0.2\"\n\
             listen_addr = \"127.0.0.1:{port}\"\n\
             local_address = \"192.0.2.2\"\nebgp_policy = \"accept-all\"\n\
             exchange_plane = true\nexchange_plane_keys = [\"1:{key}\"]\n\n"
        )
    };
    let policy = "\
        [[prefix-list]]\nname = \"all-v4\"\nprefix = \"0.0.0.0/0\"\nge = 0\nle = 32\npermit = true\n\n\
        [[route-map]]\nname = \"pol\"\nentry = 10\nmatch_prefix = \"all-v4\"\npermit = true\n\n";
    let peer = if outbound {
        format!("[[peer]]\nremote = \"127.0.0.1:{port}\"\nimport = \"pol\"\nexport = \"pol\"\n")
    } else {
        // The TCP source of the outbound peer on loopback is 127.0.0.1 —
        // the inbound matcher is fail-closed on the configured address.
        "[[peer]]\naddress = \"127.0.0.1\"\nimport = \"pol\"\nexport = \"pol\"\n".to_string()
    };
    std::fs::write(path, format!("{bgp}{policy}{peer}")).unwrap();
}

/// Both sides opt in with a shared key AND bind import/export
/// route-maps: the session establishes, IPv4 routes flow, and the
/// receiving daemon surfaces the verified record set with all three
/// record classes — hint + policy intent (scope 1) + origin
/// attestation + segment signature (provenance).
#[test]
fn exchange_plane_negotiates_and_records_flow() {
    let port_b = free_port();
    let dir = std::env::temp_dir().join(format!("lr-w63-flow-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let cfg_a = dir.join("a.toml");
    let cfg_b = dir.join("b.toml");
    write_xp_config(&cfg_a, true, port_b, "alpha");
    write_xp_config(&cfg_b, false, port_b, "alpha");

    let a = Daemon::spawn(&["--config", cfg_a.to_str().unwrap()], "flow-a");
    let b = Daemon::spawn(&["--config", cfg_b.to_str().unwrap()], "flow-b");

    wait_log_all(&a.log, &["session #1 → Established"]);
    wait_log_all(&b.log, &["session #1 → Established"]);
    // The route's standard content survives (the plane is additive).
    wait_log_all(&b.log, &["route installed 203.0.113.0/24"]);
    // The verified record set is surfaced with all three classes:
    // hint + policy intent (scope 1) + origin attestation + segment
    // signature (provenance).
    wait_log_all(
        &b.log,
        &["exchange-plane: session 1 4 records for 203.0.113.0/24 [hint+policy+origin+segment]"],
    );
}

/// The key id negotiates but the secrets differ: every record set fails
/// the authentication tag check and is dropped with a log line, while
/// the route itself still installs (design §8).
#[test]
fn exchange_plane_key_mismatch_drops_records_keeps_routes() {
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
            "--exchange-plane",
            "--exchange-plane-key",
            "1:alpha",
        ],
        "mismatch-a",
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
            "--exchange-plane",
            "--exchange-plane-key",
            "1:omega",
        ],
        "mismatch-b",
    );

    wait_log_all(&a.log, &["session #1 → Established"]);
    wait_log_all(&b.log, &["session #1 → Established"]);
    wait_log_all(&b.log, &["route installed 203.0.113.0/24"]);
    wait_log_all(&b.log, &["authentication tag mismatch"]);
    let log = wait_log_all(&b.log, &["route installed 203.0.113.0/24"]);
    assert!(
        !log.contains("exchange-plane: session 1"),
        "no record set may surface under a wrong key; log: {log}"
    );
}

/// One-sided opt-in: the capability is advertised but never echoed, so
/// the plane stays off and nothing about the session changes — the
/// RFC 5492 §3 transparent fallback, end to end.
#[test]
fn exchange_plane_one_sided_is_inert() {
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
            "--exchange-plane",
            "--exchange-plane-key",
            "1:alpha",
        ],
        "one-sided-a",
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
        "one-sided-b",
    );

    wait_log_all(&a.log, &["session #1 → Established"]);
    wait_log_all(&b.log, &["session #1 → Established"]);
    wait_log_all(&b.log, &["route installed 203.0.113.0/24"]);
    let log = wait_log_all(&b.log, &["route installed 203.0.113.0/24"]);
    assert!(
        !log.contains("exchange-plane: session"),
        "an inert plane must not surface records; log: {log}"
    );
}
