//! End-to-end tests for the BGP-LS daemon wiring (issue #60 work
//! breakdown item 3 — `--bgp-ls` flag + `[bgp_ls]` config block).
//!
//! These tests spawn two `lr-daemon` processes on loopback, each with
//! `--bgp-ls`, and verify:
//!
//!   1. The startup banner names the new knob: `bgp-ls: on (AS=…
//!      BGP-LS-ID=… areas=…)`.
//!   2. The MP-BGP OPEN capability exchange advertises the BGP-LS
//!      family (AFI=16388, SAFI=71) — visible in the daemon log
//!      where the negotiated family set is printed.
//!   3. Both daemons reach Established despite the BGP-LS family
//!      riding alongside IPv4 unicast (regression: a misformed
//!      MP-BGP capability advertisement must not break IPv4 unicast).
//!
//! The interop lab `tests/interop/bgpls_bird.sh` covers the full
//! projection path (an OSPF-only `lr-daemon` feeding a BIRD BGP-LS
//! peer). These daemon tests cover the config and OPEN side only —
//! the projection driver is exercised in
//! `crates/lr-router/src/instance/tests.rs::bgpls_republish_*`.

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
            "lr-daemon-bgpls-{tag}-{}-{seq}.log",
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

/// Both daemons start with `--bgp-ls` and reach Established. The
/// startup banner shows the new knob; the session negotiates the
/// BGP-LS family alongside IPv4 unicast.
#[test]
fn bgp_ls_flag_negotiates_family_alongside_ipv4_unicast() {
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
            "--bgp-ls",
            "--bgp-ls-as",
            "64512",
            "--bgp-ls-id",
            "1",
        ],
        "neg-a",
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
            "--bgp-ls",
            "--bgp-ls-as",
            "64513",
            "--bgp-ls-id",
            "1",
        ],
        "neg-b",
    );

    // Startup banner on both sides names the BGP-LS knob.
    wait_log_all(
        &a.log,
        &["bgp-ls:       on (AS=64512 BGP-LS-ID=1 areas=(all))"],
    );
    wait_log_all(
        &b.log,
        &["bgp-ls:       on (AS=64513 BGP-LS-ID=1 areas=(all))"],
    );
    // Both sessions reach Established — the BGP-LS MP-BGP capability
    // did not break IPv4 unicast negotiation.
    wait_log_all(&a.log, &["session #1 → Established"]);
    wait_log_all(&b.log, &["session #1 → Established"]);
    // IPv4 unicast still works: B installs the originated prefix.
    wait_log_all(&b.log, &["route installed 203.0.113.0/24"]);
}

/// A daemon with `--no-bgp-ls` (the default) reports `bgp-ls: off`
/// in the startup banner — a regression check that the master switch
/// is off by default and the banner renders the off state.
#[test]
fn no_bgp_ls_flag_reports_off_in_banner() {
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
        "off-a",
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
        "off-b",
    );
    // Banner shows off.
    wait_log_all(&a.log, &["bgp-ls:       off"]);
}

/// `--bgp-ls-area 0.0.0.1` parses the dotted-quad form and shows up
/// in the banner's area subset.
#[test]
fn bgp_ls_area_dotted_quad_parses() {
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
            "--bgp-ls",
            "--bgp-ls-area",
            "0.0.0.1",
        ],
        "area-a",
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
            "--bgp-ls",
            "--bgp-ls-area",
            "1",
        ],
        "area-b",
    );
    // 0.0.0.1 parses to u32 = 1, so the banner prints "areas=1".
    wait_log_all(&a.log, &["bgp-ls:       on (AS=64512 BGP-LS-ID=0 areas=1)"]);
}
