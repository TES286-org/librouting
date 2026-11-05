//! End-to-end coverage for `lr_osroute::source_check::check_source_compatibility`
//! as driven from the daemon's startup dial path on Linux.
//!
//! The unit tests in `lr-osroute/src/source_check.rs` pin the
//! `RTM_GETROUTE` helper against the loopback / routable-peer /
//! documentation-IP cases. This file pins the *daemon wiring* — the
//! log lines `check_source_compatibility` produces when the daemon
//! boots, before any TCP dial. Two shapes are covered:
//!
//! - **Loopback-to-loopback** — the kernel's preferred source for
//!   `127.0.0.1` is `127.0.0.1`, so a `local_address = 127.0.0.1`
//!   peer on `127.0.0.1` produces `SourceCheck::Ok`. The daemon
//!   startup log must NOT carry the `kernel default source for`
//!   info line (no mismatch).
//! - **Loopback `local`, routable `peer`** — the kernel's preferred
//!   source for `1.1.1.1` is the egress interface's address (NOT
//!   `127.0.0.1`), so a `local_address = 127.0.0.1` peer on `1.1.1.1`
//!   produces `SourceCheck::Mismatch` and the daemon startup log
//!   must carry the info line. The daemon still dials (the
//!   diagnostic is a hint, not a gate).
//!
//! Both tests run only on Linux because `source_check`'s Linux `imp`
//! is the one that does the real `RTM_GETROUTE`. On other platforms
//! the diagnostic is a no-op (`Ok`) and the `Mismatch` log line never
//! fires, so the loopback test would still pass but the mismatch
//! test would not.

#![cfg(all(unix, target_os = "linux"))]

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
            "lr-daemon-source-check-{tag}-{}-{seq}.log",
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

/// Read a log file until it contains any one of the needles (bounded wait).
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

/// Loopback-to-loopback: the kernel's preferred source for `127.0.0.1`
/// is `127.0.0.1`, so a daemon bound to `local_address = 127.0.0.1`
/// dialing `127.0.0.1:<port>` produces `SourceCheck::Ok` and the
/// daemon log carries no `kernel default source for` mismatch line.
///
/// The peer listener is unreachable (no real daemon on the far side),
/// so the dial eventually fails — but the diagnostic runs *before*
/// the dial, so its absence is observable in the log before the
/// connection-failure retry loop fills the file.
#[test]
fn loopback_local_loopback_peer_is_ok() {
    let dir =
        std::env::temp_dir().join(format!("lr-daemon-source-check-lo-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    // A port nothing listens on — the dial fails fast, but the
    // diagnostic runs first.
    let port = 18471u16;

    let conf = dir.join("a.toml");
    std::fs::write(
        &conf,
        format!(
            "[bgp]\nlocal_as = 64512\nrouter_id = \"10.0.0.1\"\nebgp_policy = \"accept-all\"\n\
             listen_addr = \"127.0.0.1:18481\"\n\
             local_address = \"127.0.0.1\"\n\
             networks = [\"203.0.113.0/24\"]\n\n\
             [[peer]]\nname = \"unreachable\"\nremote = \"127.0.0.1:{port}\"\npeer_as = 64513\n"
        ),
    )
    .unwrap();

    let daemon = Daemon::spawn(&["--config", conf.to_str().unwrap()], "lo");

    // The daemon reaches the dial phase — its log shows either an
    // outbound TCP attempt or a connect failure for the unreachable
    // peer. This is the proof the diagnostic ran without blocking
    // the daemon.
    wait_log_any(&daemon.log, &["outbound TCP established", "connect failed"]);

    // The diagnostic ran and matched: no mismatch info line for a
    // loopback-to-loopback configuration. Give the log a short
    // settledown so a late mismatch line would surface if it ever
    // fired.
    thread::sleep(Duration::from_millis(500));
    let text = std::fs::read_to_string(&daemon.log).unwrap_or_default();
    assert!(
        !text.contains("kernel default source for"),
        "loopback-to-loopback must agree, no mismatch info line; log:\n{text}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// Loopback `local`, routable `peer`: the kernel's preferred source
/// for `1.1.1.1` is the egress interface's address (NOT `127.0.0.1`),
/// so a daemon bound to `local_address = 127.0.0.1` dialing
/// `1.1.1.1:<port>` produces `SourceCheck::Mismatch` and the daemon
/// log carries the `kernel default source for` info line. The
/// daemon still dials (the diagnostic is a hint, not a gate).
///
/// This test is the e2e counterpart of the unit test
/// `source_check::tests::loopback_against_routable_peer_is_not_ok`
/// and pins the same Mismatch path through the daemon's wiring.
#[test]
fn loopback_local_routable_peer_logs_mismatch() {
    let dir = std::env::temp_dir().join(format!(
        "lr-daemon-source-check-mismatch-{}",
        std::process::id()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    // 1.1.1.1 is a stable globally routed anycast address — the
    // kernel's RTM_GETROUTE returns a real route with a non-loopback
    // preferred source (the egress interface's address). No listener
    // is on the far side, but the diagnostic runs before the dial.
    let conf = dir.join("a.toml");
    std::fs::write(
        &conf,
        "[bgp]\nlocal_as = 64512\nrouter_id = \"10.0.0.1\"\nebgp_policy = \"accept-all\"\n\
         listen_addr = \"127.0.0.1:18491\"\n\
         local_address = \"127.0.0.1\"\n\
         networks = [\"203.0.113.0/24\"]\n\n\
         [[peer]]\nname = \"cloudflare-dns\"\nremote = \"1.1.1.1:179\"\npeer_as = 64513\n",
    )
    .unwrap();

    let daemon = Daemon::spawn(&["--config", conf.to_str().unwrap()], "mismatch");

    // The daemon reaches the dial phase, so the diagnostic has run.
    // Either the dial completes (unlikely — 1.1.1.1:179 is filtered)
    // or it fails; either way the log shows the daemon got past the
    // startup source check.
    wait_log_any(&daemon.log, &["outbound TCP established", "connect failed"]);

    // The mismatch info line must appear: the kernel's preferred
    // source for 1.1.1.1 is NOT 127.0.0.1, so the diagnostic surfaces
    // the egress interface's address.
    wait_log_all(&daemon.log, &["kernel default source for"]);

    let _ = std::fs::remove_dir_all(&dir);
}
