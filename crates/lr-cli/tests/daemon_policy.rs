//! End-to-end tests for TOML policy objects: `[[prefix-list]]`,
//! `[[route-map]]` and per-peer `import`/`export` attachment on the
//! real `lr-daemon` binary.
//!
//! Topology per test: A (AS64512, originates two prefixes) → B
//! (AS64513, receives). Policy on either side decides which prefixes
//! survive; assertions run against the daemons' logs
//! (`daemon: route installed <prefix> via <nh>`).

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
            std::env::temp_dir().join(format!("lr-daemon-pol-{tag}-{}.log", std::process::id()));
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

/// Wait until the log stops growing for 1s (convergence), then
/// return it — used for negative assertions (prefix must NOT appear).
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

/// A exports two prefixes; its export route-map only permits
/// 203.0.113.0/24 (the other is implicitly denied by the final
/// entry). B must install exactly one.
#[test]
fn export_route_map_filters_prefixes() {
    let port_a = free_port();
    let port_b = free_port();
    let cfg_a = std::env::temp_dir().join(format!("lr-pol-a-{}.toml", std::process::id()));
    std::fs::write(
        &cfg_a,
        format!(
            r#"
[bgp]
local_as = 64512
router_id = "10.0.0.1"
listen_addr = "127.0.0.1:{port_a}"
local_address = "192.0.2.1"
networks = ["203.0.113.0/24", "198.51.100.0/24"]

[[prefix-list]]
name = "allowed-out"
prefix = "203.0.113.0/24"

[[route-map]]
name = "to-b"
entry = 10
match_prefix = "allowed-out"
permit = true

[[route-map]]
name = "to-b"
entry = 20
permit = false

[[peer]]
remote = "127.0.0.1:{port_b}"
peer_as = 64513
export = "to-b"
"#,
        ),
    )
    .unwrap();

    let a = Daemon::spawn(&["--config", cfg_a.to_str().unwrap()], "exp-a");
    // B is a plain sink for this test (A's export policy is the
    // subject), so it opts into the RFC 8212 accept-all deviation.
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
        "exp-b",
    );

    let log = wait_log_all(&b.log, &["daemon: route installed 203.0.113.0/24"]);
    // A's own startup must show the policy wiring.
    let a_log = std::fs::read_to_string(&a.log).unwrap_or_default();
    assert!(
        a_log.contains("policy:      2 route-maps, 0 import / 1 export"),
        "{a_log}"
    );

    // Negative: the denied prefix never lands after convergence.
    let quiet = wait_quiet(&b.log);
    assert!(
        !quiet.contains("daemon: route installed 198.51.100.0/24"),
        "denied prefix must not be installed; log: {quiet}"
    );
    let _ = log;
    std::fs::remove_file(&cfg_a).ok();
}

/// A exports both prefixes; B's import route-map denies
/// 198.51.100.0/24. B installs exactly one.
#[test]
fn import_route_map_filters_prefixes() {
    let port_a = free_port();
    let port_b = free_port();
    let cfg_b = std::env::temp_dir().join(format!("lr-pol-b-{}.toml", std::process::id()));
    std::fs::write(
        &cfg_b,
        format!(
            r#"
[bgp]
local_as = 64513
router_id = "10.0.0.2"
listen_addr = "127.0.0.1:{port_b}"
local_address = "192.0.2.2"

[[prefix-list]]
name = "reject-doc"
prefix = "198.51.100.0/24"

[[route-map]]
name = "from-a"
entry = 10
match_prefix = "reject-doc"
permit = false

[[route-map]]
name = "from-a"
entry = 20
permit = true

[[peer]]
remote = "127.0.0.1:{port_a}"
peer_as = 64512
import = "from-a"
"#,
        ),
    )
    .unwrap();

    // A is a plain originator for this test (B's import policy is
    // the subject), so it opts into the RFC 8212 accept-all deviation.
    let _a = Daemon::spawn(
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
            "--network",
            "203.0.113.0/24",
            "--network",
            "198.51.100.0/24",
            "--ebgp-policy",
            "accept-all",
        ],
        "imp-a",
    );
    let b = Daemon::spawn(&["--config", cfg_b.to_str().unwrap()], "imp-b");

    wait_log_all(&b.log, &["daemon: route installed 203.0.113.0/24"]);
    let quiet = wait_quiet(&b.log);
    assert!(
        !quiet.contains("daemon: route installed 198.51.100.0/24"),
        "denied prefix must not be installed; log: {quiet}"
    );
    std::fs::remove_file(&cfg_b).ok();
}

/// An export route-map that sets attributes must still deliver the
/// prefix: B receives 203.0.113.0/24 (set actions must not drop it).
#[test]
fn export_route_map_set_actions_keep_route() {
    let port_a = free_port();
    let port_b = free_port();
    let cfg_a = std::env::temp_dir().join(format!("lr-pol-s-{}.toml", std::process::id()));
    std::fs::write(
        &cfg_a,
        format!(
            r#"
[bgp]
local_as = 64512
router_id = "10.0.0.1"
listen_addr = "127.0.0.1:{port_a}"
local_address = "192.0.2.1"
networks = ["203.0.113.0/24"]

[[route-map]]
name = "mark"
entry = 10
set_local_pref = 250
set_med = 42
add_community = "64512:100"
prepend = "64512"
permit = true

[[peer]]
remote = "127.0.0.1:{port_b}"
peer_as = 64513
export = "mark"
"#,
        ),
    )
    .unwrap();

    let _a = Daemon::spawn(&["--config", cfg_a.to_str().unwrap()], "set-a");
    // B is a plain sink (A's export set-actions are the subject).
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
        "set-b",
    );

    wait_log_all(&b.log, &["daemon: route installed 203.0.113.0/24"]);
    std::fs::remove_file(&cfg_a).ok();
}

/// A peer referencing an unknown route-map must fail at startup
/// (fail closed), not silently pass traffic.
#[test]
fn unknown_route_map_reference_fails_startup() {
    let cfg = std::env::temp_dir().join(format!("lr-pol-x-{}.toml", std::process::id()));
    std::fs::write(
        &cfg,
        r#"
[bgp]
local_as = 64512
router_id = "10.0.0.1"

[[peer]]
remote = "127.0.0.1:1179"
peer_as = 64513
import = "ghost"
"#,
    )
    .unwrap();

    let out = Command::new(BIN)
        .args(["--config", cfg.to_str().unwrap()])
        .output()
        .expect("run lr-daemon");
    assert!(!out.status.success(), "startup must fail");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("unknown route-map 'ghost'"),
        "stderr: {stderr}"
    );
    std::fs::remove_file(&cfg).ok();
}

/// Two peers extending one template (shared AS + policy binding via
/// the template) must both establish and carry policy — the reuse
/// mechanism works end-to-end.
#[test]
fn peer_templates_share_policy_and_establish() {
    let port_a = free_port();
    let port_b = free_port();
    let port_c = free_port();
    let cfg_a = std::env::temp_dir().join(format!("lr-pol-t-{}.toml", std::process::id()));
    std::fs::write(
        &cfg_a,
        format!(
            r#"
[bgp]
local_as = 64512
router_id = "10.0.0.1"
local_address = "192.0.2.1"
listen_addr = "127.0.0.1:{port_a}"
networks = ["203.0.113.0/24"]

[[prefix-list]]
name = "allowed"
prefix = "203.0.113.0/24"

[[route-map]]
name = "out"
entry = 10
match_prefix = "allowed"
permit = true

[peer-template.customer]
peer_as = 64513
hold_time = 30
export = "out"

[[peer]]
extends = "customer"
remote = "127.0.0.1:{port_b}"

[[peer]]
extends = "customer"
remote = "127.0.0.1:{port_c}"
"#
        ),
    )
    .unwrap();

    let _a = Daemon::spawn(&["--config", cfg_a.to_str().unwrap()], "tpl-a");
    // B and C are plain sinks (the template export policy is the
    // subject), so both opt into the accept-all deviation.
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
        "tpl-b",
    );
    let c = Daemon::spawn(
        &[
            "--local-as",
            "64513",
            "--peer-as",
            "64512",
            "--router-id",
            "10.0.0.3",
            "--listen",
            &format!("127.0.0.1:{port_c}"),
            "--local-address",
            "192.0.2.3",
            "--ebgp-policy",
            "accept-all",
        ],
        "tpl-c",
    );

    // Both template peers establish and receive the exported prefix.
    wait_log_all(&b.log, &["daemon: route installed 203.0.113.0/24"]);
    wait_log_all(&c.log, &["daemon: route installed 203.0.113.0/24"]);
    // A's banner shows two policy bindings from ONE template.
    let a_log = std::fs::read_to_string(&_a.log).unwrap_or_default();
    assert!(
        a_log.contains("policy:      1 route-maps, 0 import / 2 export"),
        "{a_log}"
    );
    std::fs::remove_file(&cfg_a).ok();
}
