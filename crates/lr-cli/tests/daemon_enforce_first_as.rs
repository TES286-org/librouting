//! End-to-end tests for the FRR `bgp enforce-first-as` and
//! `bgp bestpath compare-routerid` knobs (W2.2) on the real `lr-daemon`
//! binary.
//!
//! The router's egress always prepends the local AS to AS_PATH, so a
//! well-formed eBGP UPDATE keeps flowing under `--enforce-first-as` —
//! the check only rejects *forged* UPDATEs (a malformed peer that did
//! not prepend its own AS), which a real lr-daemon cannot produce. We
//! therefore verify:
//!   1. the flags parse and the daemon starts up;
//!   2. the startup status printout names the new knobs; and
//!   3. a well-formed eBGP route still propagates end-to-end under
//!      `--enforce-first-as` (legit traffic must not regress).
//!
//! For the rejection side of the check, see the in-process
//! `enforce_first_as_rejects_mismatched_first_as` unit test in
//! `crates/lr-router/src/instance.rs`, which forges the AS_PATH on the
//! wire and feeds it directly to the router.

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
            std::env::temp_dir().join(format!("lr-daemon-w22-{tag}-{}.log", std::process::id()));
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

/// The daemon accepts `--enforce-first-as` and
/// `--no-bestpath-compare-routerid`, names them in the startup status
/// printout, and a well-formed eBGP route still propagates end-to-end
/// under the new posture (no regression for legit traffic).
#[test]
fn enforce_first_as_keeps_well_formed_route_flowing() {
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
            "--enforce-first-as",
            "--no-bestpath-compare-routerid",
        ],
        "efa-a",
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
        "efa-b",
    );

    // The status printout names the new knobs (acts as a smoke test
    // that the flags parse, the daemon starts, and the wiring is on).
    wait_log_all(
        &a.log,
        &["ebgp:        policy=accept-all enforce_first_as=true compare_routerid=false"],
    );

    // The session establishes and the route propagates (legit traffic
    // must not regress under the new posture).
    wait_log_all(&a.log, &["session #1 → Established"]);
    wait_log_all(&b.log, &["session #1 → Established"]);
    wait_log_all(&b.log, &["route installed 203.0.113.0/24"]);
}

/// The daemon defaults: `enforce_first_as = false` and
/// `bestpath_compare_routerid = true`. Both names appear in the
/// startup status printout so operators can audit at a glance.
#[test]
fn defaults_show_up_in_status_printout() {
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
        "efa-defaults-a",
    );
    let _b = Daemon::spawn(
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
        "efa-defaults-b",
    );

    wait_log_all(
        &a.log,
        &["ebgp:        policy=accept-all enforce_first_as=false compare_routerid=true"],
    );
    // The session establishes regardless of the knobs (transport is
    // independent of the import-time safety check).
    wait_log_all(&a.log, &["session #1 → Established"]);
}
