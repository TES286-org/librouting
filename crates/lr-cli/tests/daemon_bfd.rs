//! End-to-end tests for daemon BFD fast-fail (W1.3, RFC 5880/5881).
//!
//! Two daemons on distinct loopback addresses (127.0.0.2 / 127.0.0.3 —
//! both bind the RFC 5881 port 3784 on their own address), each with
//! BFD at 100 ms × 3 and a long hold time. The test:
//!
//! 1. BFD sessions reach Up on both sides (`bfd: peer … -> Up`) and
//!    BGP establishes with the originated route propagated.
//! 2. Freezes daemon B with SIGSTOP — the TCP connection stays open
//!    (no FIN/RST, no keepalives) so the 60 s hold timer is the ONLY
//!    other thing that could tear the session down.
//! 3. Asserts daemon A's BFD detection (~300 ms) tears the BGP session
//!    down within seconds, proving the fast-fail path: the log shows
//!    the BFD `Up -> Down` transition and the session ending with
//!    reason "bfd session down" long before any hold-time expiry.
//!
//! Linux-only: the test relies on the loopback aliases 127.0.0.2 and
//! 127.0.0.3, which Linux configures on `lo` by default but macOS does
//! not (only 127.0.0.1 is on `lo0` without an `ifconfig lo0 alias`
//! step that needs root, unavailable on CI runners). It also uses the
//! Linux signal numbers for SIGSTOP/SIGCONT (19/18); on macOS those
//! values are swapped (17/19). The BFD fast-fail behavior this test
//! pins is covered end-to-end on Linux by the `tests/interop/bfd_bird.sh`
//! interop lab as well.

#![cfg(target_os = "linux")]

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
            "lr-daemon-bfd-{tag}-{}-{seq}.log",
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
            kill(self.pid(), 18); // SIGCONT, in case a test froze us
            kill(self.pid(), 15);
        }
        let _ = self.child.wait();
        // Preserve the capture log when the test is unwinding so the
        // daemon's stderr/stdout tail is available for triage on a
        // remote CI runner. On a clean exit the file is removed as
        // before — keeping temp-dir hygiene tight for the green run.
        if !std::thread::panicking() {
            let _ = std::fs::remove_file(&self.log);
        }
    }
}

extern "C" {
    fn kill(pid: i32, sig: i32) -> i32;
}

const SIGSTOP: i32 = 19;

/// Read a log file until it contains every needle (bounded wait).
///
/// The ceiling is 90 s (was 30 s, then 60 s): the BFD bring-up
/// sequence (Down, then Init, then Up) on the self-hosted s390x
/// runner (IBM Z hardware, ~3-6x slower than x86_64 for cold-cache
/// compile + BFD UDP packet exchange) can take longer than the
/// x86_64 baseline. The previous 30 s ceiling tripped immediately;
/// 60 s was still not enough on some runs. 90 s gives ~3x slack
/// over the worst observed 60 s timeout while staying well within
/// the nextest slow-timeout (5 min) and the job's
/// `timeout-minutes: 90` ceiling.
///
/// The same ceiling is reused for the fast-fail detection wait
/// (`Up to Down` + `session ended`) - the BFD detection itself is
/// ~0.3 s (3 x 100 ms), so the wait returns on the first poll that
/// observes the Down transition (typically within 1 s of the
/// SIGSTOP). The 90 s ceiling is just the bound; the actual
/// detection-time assertion (`elapsed < Duration::from_secs(5)`)
/// is unchanged.
fn wait_log_all(path: &std::path::Path, needles: &[&str]) -> String {
    let deadline = Instant::now() + Duration::from_secs(90);
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

/// Same as `wait_log_all` but on failure also dumps the sibling
/// daemon's log tail so a BFD bring-up failure on a remote CI
/// runner (s390x) is triageable from the panic message alone -
/// without needing to reproduce locally. The BFD protocol is
/// bidirectional: a failure on A's side is often visible in B's
/// log (e.g. B never received A's BFD packet, or B's BFD listener
/// never started).
fn wait_log_all_with_sibling(
    path: &std::path::Path,
    needles: &[&str],
    sibling: &std::path::Path,
    sibling_label: &str,
) -> String {
    let deadline = Instant::now() + Duration::from_secs(90);
    let mut text = String::new();
    while Instant::now() < deadline {
        text = std::fs::read_to_string(path).unwrap_or_default();
        if needles.iter().all(|n| text.contains(n)) {
            return text;
        }
        thread::sleep(Duration::from_millis(100));
    }
    let sibling_tail = std::fs::read_to_string(sibling).unwrap_or_default();
    panic!(
        "log never contained all of {needles:?}; last: {text}\n\
         --- {sibling_label} daemon log tail ---\n{sibling_tail}"
    );
}

/// BFD fast-fail: a frozen peer (TCP alive, BFD silent) must tear the
/// BGP session down in ~0.3 s (BFD detection) instead of 60 s (hold).
#[test]
fn bfd_fast_fail_beats_hold_time() {
    // Distinct loopback addresses so both daemons can bind UDP 3784.
    let a_addr = "127.0.0.2";
    let b_addr = "127.0.0.3";
    let b_port = 18502u16;

    // A connects out to B.
    let a = Daemon::spawn(
        &[
            "--local-as",
            "64512",
            "--peer-as",
            "64513",
            "--router-id",
            "10.0.0.1",
            "--peer",
            &format!("{b_addr}:{b_port}"),
            "--local-address",
            a_addr,
            "--network",
            "203.0.113.0/24",
            "--hold-time",
            "60",
            "--ebgp-policy",
            "accept-all",
            "--bfd",
            "--bfd-min-tx-ms",
            "100",
            "--bfd-min-rx-ms",
            "100",
            "--bfd-multiplier",
            "3",
        ],
        "a",
    );

    // B listens and matches A by source address; its BFD session needs
    // A's address, which the implicit listen-mode peer cannot express —
    // an explicit inbound [[peer]] with `address` provides it.
    let b_config =
        std::env::temp_dir().join(format!("lr-daemon-bfd-b-{}.toml", std::process::id()));
    std::fs::write(
        &b_config,
        format!(
            "[bgp]\n\
             local_as = 64513\n\
             peer_as = 64512\n\
             router_id = \"10.0.0.2\"\n\
             listen_addr = \"{b_addr}:{b_port}\"\n\
             local_address = \"{b_addr}\"\n\
             hold_time = 60\n\
             ebgp_policy = \"accept-all\"\n\
             bfd = true\n\
             bfd_min_tx_ms = 100\n\
             bfd_min_rx_ms = 100\n\
             bfd_multiplier = 3\n\n\
             [[peer]]\n\
             address = \"{a_addr}\"\n\
             bfd = true\n"
        ),
    )
    .expect("write b config");
    let b = Daemon::spawn(&["--config", b_config.to_str().unwrap()], "b");

    // BFD sessions come up on both sides... (any transition to Up —
    // the FSM may go Down -> Up directly per RFC 5880 §6.8.6).
    // Use the sibling-dumping variant for A's bring-up wait so a
    // failure on the s390x runner (where BFD packets may not cross
    // the loopback the same way as x86_64) is triageable from the
    // panic message alone — B's log tail reveals whether B's BFD
    // listener ever started and whether B received A's BFD packet.
    wait_log_all_with_sibling(&a.log, &["[bfd]", "-> Up"], &b.log, "B");
    wait_log_all_with_sibling(&b.log, &["[bfd]", "-> Up"], &a.log, "A");
    // ...and BGP establishes with the route propagated to B.
    wait_log_all(&a.log, &["session #1 → Established"]);
    wait_log_all(
        &b.log,
        &["session #1 → Established", "route installed 203.0.113.0/24"],
    );

    // Freeze B: TCP stays open (kernel holds the connection, no FIN),
    // BFD goes silent. Hold time is 60 s; BFD detection is 300 ms.
    let froze = Instant::now();
    unsafe {
        kill(b.pid(), SIGSTOP);
    }

    // A must log the BFD Down transition and tear the BGP session down
    // with reason "bfd session down" — well within any hold-time
    // horizon (5 s generously; hold would be 60 s).
    let a_text = wait_log_all(&a.log, &["Up -> Down", "session ended: bfd session down"]);
    let elapsed = froze.elapsed();
    assert!(
        elapsed < Duration::from_secs(5),
        "BFD fast-fail took {elapsed:?} — hold time was 60 s, BFD detection should be ~0.3 s"
    );
    assert!(a_text.contains("bfd session down"));

    // Cleanup: SIGCONT so the Drop handler can terminate B normally.
    unsafe {
        kill(b.pid(), 18); // SIGCONT
    }
    let _ = std::fs::remove_file(&b_config);
}
