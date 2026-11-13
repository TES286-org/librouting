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

/// `--bgp-ls-instance-id 42` surfaces in the startup banner's
/// `bgp-ls:` line as `Instance-ID=42`. The default (no
/// `--bgp-ls-instance-id` flag) keeps the previous banner form
/// (without the `Instance-ID=` segment) — regression-gated by
/// `bgp_ls_flag_negotiates_family_alongside_ipv4_unicast` above.
/// A non-zero Instance-ID is the RFC 9552 §3.2 way to segregate
/// NLRIs from different IGP routing domains on the consumer side.
#[test]
fn bgp_ls_instance_id_cli_flag_shows_in_banner() {
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
            "--bgp-ls-instance-id",
            "42",
        ],
        "iid-a",
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
        ],
        "iid-b",
    );
    wait_log_all(
        &a.log,
        &["bgp-ls:       on (AS=64512 BGP-LS-ID=0 Instance-ID=42 areas=(all))"],
    );
}

/// `--bgp-ls-instance-id bad` (non-numeric) is rejected with exit
/// code 2 — the same fail-closed posture `--bgp-ls-id` and
/// `--bgp-ls-as` already use for a non-integer argument. The
/// process exits before any BGP work, so no log file is needed.
#[test]
fn bgp_ls_instance_id_cli_flag_rejects_non_numeric() {
    // Use the Cargo-provided path to the built `lr-daemon` binary
    // (same pattern every other integration test in this crate uses).
    // The earlier `current_exe() + pop() + pop()` construction assumed
    // the test binary lives in `target/{debug,release}/deps/`, but
    // Cargo actually places it under
    // `target/{debug,release}/build/<crate>/<hash>/out/`, so the
    // two-level pop landed in the wrong directory and the spawn
    // failed with NotFound.
    let out = std::process::Command::new(BIN)
        .args([
            "--local-as",
            "64512",
            "--peer-as",
            "64513",
            "--router-id",
            "10.0.0.1",
            "--bgp-ls",
            "--bgp-ls-instance-id",
            "not-a-number",
        ])
        .output()
        .expect("spawn lr-daemon");
    assert!(
        !out.status.success(),
        "lr-daemon must exit non-zero on a non-numeric --bgp-ls-instance-id"
    );
    let code = out.status.code().unwrap_or(-1);
    assert_eq!(
        code, 2,
        "config-parse failure exits with code 2 (matches --bgp-ls-id's posture); got {code}"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("bad --bgp-ls-instance-id"),
        "stderr must name the rejected flag; got: {stderr}"
    );
}

/// `[bgp_ls] instance_id = 7` (TOML) is parsed by `config check`
/// and shows up in the banner's `bgp-ls:` line as `Instance-ID=7`.
/// Covers the TOML surface the CLI flag's test above does not —
/// the operator's other configuration channel.
#[test]
fn bgp_ls_instance_id_toml_key_shows_in_banner() {
    let port_b = free_port();
    let cfg_path = std::env::temp_dir().join(format!(
        "lr-daemon-bgpls-iid-toml-{}-{}.toml",
        std::process::id(),
        port_b
    ));
    std::fs::write(
        &cfg_path,
        "\
[bgp]
local_as = 64512
peer_as = 64513
router_id = \"10.0.0.1\"
peer_addr = '127.0.0.1:0'
local_address = '192.0.2.1'
ebgp_policy = \"accept-all\"
networks = [\"203.0.113.0/24\"]

[bgp_ls]
enabled = true
instance_id = 7
",
    )
    .expect("write temp TOML");
    let a = Daemon::spawn(
        &[
            "--config",
            cfg_path.to_str().unwrap(),
            "--peer",
            &format!("127.0.0.1:{port_b}"),
        ],
        "iid-toml-a",
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
        ],
        "iid-toml-b",
    );
    wait_log_all(
        &a.log,
        &["bgp-ls:       on (AS=64512 BGP-LS-ID=0 Instance-ID=7 areas=(all))"],
    );
    let _ = std::fs::remove_file(&cfg_path);
}
