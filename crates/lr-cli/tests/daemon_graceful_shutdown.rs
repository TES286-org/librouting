//! End-to-end tests for the RFC 8326 Graceful Session Shutdown knobs
//! on the real `lr-daemon` binary.
//!
//! Three behaviours, all over real TCP on loopback:
//!
//! 1. `tagged_route_loses_to_untagged_candidate` — the §4 best-path
//!    step: an export carrying `GRACEFUL_SHUTDOWN` (`0xFFFF:0000`) is
//!    de-preferenced at the receiver in favour of an untagged
//!    candidate, even when the tagged one would win the plain RFC 4271
//!    comparison (here: the lower originator-id tiebreak).
//! 2. `knob_off_restores_plain_rfc4271_selection` — `[bgp]
//!    graceful_shutdown = false` turns the receiver step off; the
//!    tagged route wins again on the plain comparison.
//! 3. `per_peer_override_skips_sender_side_lp_zeroing` (two variants) —
//!    the §3.1 sender-side exemption observed through a receiver with
//!    graceful shutdown disabled (a pure RFC 4271 speaker): the iBGP
//!    route competes with an eBGP alternative purely on LOCAL_PREF.
//!    Without the override the export hook zeroes LOCAL_PREF and the
//!    eBGP route wins; with `graceful_shutdown = false` on the sender's
//!    peer entry the LOCAL_PREF survives the wire and the iBGP route
//!    wins on the AS-path tiebreak.
//!
//! Selection is asserted through the daemon's own event log
//! (`route installed <prefix> via <next-hop>`); every peer carries a
//! distinct `local_address` so the installed next-hop names the winner.

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
            std::env::temp_dir().join(format!("lr-daemon-gshut-{tag}-{}.log", std::process::id()));
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

/// The next-hop of the LAST `route installed <prefix>` line in the log,
/// or None when the prefix was never installed.
fn last_installed_hop(text: &str, prefix: &str) -> Option<String> {
    text.lines()
        .filter(|l| l.contains("route installed") && l.contains(prefix))
        .last()
        .and_then(|l| l.rsplit(" via ").next().map(|s| s.trim().to_string()))
}

/// Wait until the last installed route for `prefix` is `next_hop` AND
/// the log has stopped growing for 1s (convergence) — earlier
/// installations of the same prefix (before all candidates arrived)
/// must not mask the final state.
fn wait_installed_hop(path: &std::path::Path, prefix: &str, next_hop: &str) -> String {
    let deadline = Instant::now() + Duration::from_secs(30);
    let mut text = String::new();
    let mut quiet_since = Instant::now();
    while Instant::now() < deadline {
        thread::sleep(Duration::from_millis(100));
        let new_text = std::fs::read_to_string(path).unwrap_or_default();
        if new_text != text {
            text = new_text;
            quiet_since = Instant::now();
            continue;
        }
        if quiet_since.elapsed() > Duration::from_secs(1)
            && last_installed_hop(&text, prefix).as_deref() == Some(next_hop)
        {
            return text;
        }
    }
    panic!("last installed route for {prefix} never became {next_hop}; log: {text}");
}

fn free_port() -> u16 {
    use std::sync::atomic::{AtomicU32, Ordering};
    static COUNTER: AtomicU32 = AtomicU32::new(0);
    loop {
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let seed = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.subsec_nanos())
            .unwrap_or(0);
        let port = 32000u32 + (seed.wrapping_add(n.wrapping_mul(7919)) % 12_000);
        if std::net::TcpListener::bind(format!("127.0.0.1:{port}")).is_ok() {
            return port as u16;
        }
    }
}

/// Shared topology for the §4 receiver tests:
///
/// ```text
///   A (AS64512, 10.0.0.1, 192.0.2.1, listens, originates 198.51.100.0/24,
///      export to B tagged GRACEFUL_SHUTDOWN via the filter DSL)
///   C (AS64514, 10.0.0.3, 192.0.2.3, listens, originates 198.51.100.0/24,
///      export to B untagged)
///        └────────────┬────────────────┘
///                B (AS64513, connects out to both)
/// ```
///
/// Both candidates have a single-AS path and IGP origin, so the plain
/// RFC 4271 process reaches the originator-id tiebreak, which A wins
/// (10.0.0.1 < 10.0.0.3). The §4 step runs before that: the tagged
/// route loses to C's untagged one while the knob is on.
fn spawn_receiver_topology(tag: &str, b_graceful_shutdown: bool) -> (Daemon, Daemon, Daemon) {
    let port_a = free_port();
    let port_c = free_port();
    let gs_line = if b_graceful_shutdown {
        String::new()
    } else {
        "graceful_shutdown = false\n".to_string()
    };

    let cfg_a = std::env::temp_dir().join(format!("lr-gshut-{tag}-a.toml"));
    std::fs::write(
        &cfg_a,
        format!(
            r#"
[bgp]
local_as = 64512
router_id = "10.0.0.1"
listen_addr = "127.0.0.1:{port_a}"
local_address = "192.0.2.1"
networks = ["198.51.100.0/24"]

[[filter]]
name = "tag-gs"
body = "bgp.communities += [ 65535:0 ];"

[[peer]]
address = "127.0.0.1"
peer_as = 64513
export_filter = "tag-gs"
"#
        ),
    )
    .unwrap();

    let cfg_c = std::env::temp_dir().join(format!("lr-gshut-{tag}-c.toml"));
    std::fs::write(
        &cfg_c,
        format!(
            r#"
[bgp]
local_as = 64514
router_id = "10.0.0.3"
listen_addr = "127.0.0.1:{port_c}"
local_address = "192.0.2.3"
networks = ["198.51.100.0/24"]

[[route-map]]
name = "export-all"
entry = 10
permit = true

[[peer]]
address = "127.0.0.1"
peer_as = 64513
export = "export-all"
"#
        ),
    )
    .unwrap();

    let cfg_b = std::env::temp_dir().join(format!("lr-gshut-{tag}-b.toml"));
    std::fs::write(
        &cfg_b,
        format!(
            r#"
[bgp]
local_as = 64513
router_id = "10.0.0.2"
local_address = "192.0.2.2"
{gs_line}[[route-map]]
name = "pass-all"
entry = 10
permit = true

[[peer]]
name = "from-a"
remote = "127.0.0.1:{port_a}"
peer_as = 64512
import = "pass-all"
export = "pass-all"

[[peer]]
name = "from-c"
remote = "127.0.0.1:{port_c}"
peer_as = 64514
import = "pass-all"
export = "pass-all"
"#
        ),
    )
    .unwrap();

    let a = Daemon::spawn(&["--config", cfg_a.to_str().unwrap()], &format!("{tag}-a"));
    let c = Daemon::spawn(&["--config", cfg_c.to_str().unwrap()], &format!("{tag}-c"));
    let b = Daemon::spawn(&["--config", cfg_b.to_str().unwrap()], &format!("{tag}-b"));

    // Both sessions must come up — the test filters routes, not transport.
    wait_log_all(
        &b.log,
        &["session #1 → Established", "session #2 → Established"],
    );

    (a, c, b)
}

/// §4 receiver behaviour with the knob on (the default): B must install
/// C's untagged route even though A's tagged one wins the plain
/// originator-id tiebreak.
#[test]
fn tagged_route_loses_to_untagged_candidate() {
    let (_a, _c, b) = spawn_receiver_topology("recv", true);
    wait_installed_hop(&b.log, "198.51.100.0/24", "192.0.2.3");
}

/// The knob off restores the plain RFC 4271 decision process: the GS
/// community is inert for selection and A's lower originator-id wins.
#[test]
fn knob_off_restores_plain_rfc4271_selection() {
    let (_a, _c, b) = spawn_receiver_topology("off", false);
    wait_installed_hop(&b.log, "198.51.100.0/24", "192.0.2.1");
}

/// Topology for the §3.1 sender-side exemption test:
///
/// ```text
///   R (AS64512, 10.0.0.1, 192.0.2.1)  iBGP   Q (AS64515, 10.0.0.3, 192.0.2.3)
///     │ originates 198.51.100.0/24;    │ eBGP    │ originates 198.51.100.0/24
///     │ export to P tagged GS           │         │
///     └───────────────┬────────────────┴─────────┘
///                P (AS64512, listens, graceful_shutdown = false)
/// ```
///
/// P is a pure RFC 4271 speaker (its own knob is off), so it decides
/// between R's iBGP route and Q's eBGP route on LOCAL_PREF alone: the
/// iBGP route carries whatever survived R's export hook, the eBGP
/// route is pinned at the default 100. With the §3.1 zeroing in effect
/// the iBGP route arrives at LOCAL_PREF 0 and Q wins; with the
/// per-peer override the LOCAL_PREF is untouched (absent), the
/// comparison ties at 100, and the empty AS path of R's locally
/// originated route beats Q's single-AS path.
fn spawn_sender_topology(tag: &str, r_exempt_p: bool) -> (Daemon, Daemon, Daemon) {
    let port_r = free_port();
    let port_q = free_port();
    let override_line = if r_exempt_p {
        "graceful_shutdown = false\n"
    } else {
        ""
    };

    let cfg_r = std::env::temp_dir().join(format!("lr-gshut-{tag}-r.toml"));
    std::fs::write(
        &cfg_r,
        format!(
            r#"
[bgp]
local_as = 64512
router_id = "10.0.0.1"
listen_addr = "127.0.0.1:{port_r}"
local_address = "192.0.2.1"
networks = ["198.51.100.0/24"]

[[filter]]
name = "tag-gs"
body = "bgp.communities += [ 65535:0 ];"

[[peer]]
address = "127.0.0.1"
peer_as = 64512
export_filter = "tag-gs"
{override_line}
"#
        ),
    )
    .unwrap();

    let cfg_q = std::env::temp_dir().join(format!("lr-gshut-{tag}-q.toml"));
    std::fs::write(
        &cfg_q,
        format!(
            r#"
[bgp]
local_as = 64515
router_id = "10.0.0.3"
listen_addr = "127.0.0.1:{port_q}"
local_address = "192.0.2.3"
networks = ["198.51.100.0/24"]

[[route-map]]
name = "export-all"
entry = 10
permit = true

[[peer]]
address = "127.0.0.1"
peer_as = 64512
export = "export-all"
"#
        ),
    )
    .unwrap();

    let cfg_p = std::env::temp_dir().join(format!("lr-gshut-{tag}-p.toml"));
    std::fs::write(
        &cfg_p,
        format!(
            r#"
[bgp]
local_as = 64512
router_id = "10.0.0.2"
local_address = "192.0.2.2"
graceful_shutdown = false

[[route-map]]
name = "pass-all"
entry = 10
permit = true

[[peer]]
name = "from-r"
remote = "127.0.0.1:{port_r}"
peer_as = 64512
import = "pass-all"
export = "pass-all"

[[peer]]
name = "from-q"
remote = "127.0.0.1:{port_q}"
peer_as = 64515
import = "pass-all"
export = "pass-all"
"#
        ),
    )
    .unwrap();

    let r = Daemon::spawn(&["--config", cfg_r.to_str().unwrap()], &format!("{tag}-r"));
    let q = Daemon::spawn(&["--config", cfg_q.to_str().unwrap()], &format!("{tag}-q"));
    let p = Daemon::spawn(&["--config", cfg_p.to_str().unwrap()], &format!("{tag}-p"));

    wait_log_all(
        &p.log,
        &["session #1 → Established", "session #2 → Established"],
    );

    (r, q, p)
}

/// Default: R's export hook zeroes LOCAL_PREF on the GS-tagged export
/// copy, so P (a plain RFC 4271 receiver) sees LOCAL_PREF 0 over iBGP
/// and keeps Q's eBGP route at the default 100.
#[test]
fn sender_zeroes_lp_for_gs_tagged_exports() {
    let (_r, _q, p) = spawn_sender_topology("send", false);
    wait_installed_hop(&p.log, "198.51.100.0/24", "192.0.2.3");
}

/// The per-peer `graceful_shutdown = false` override on R's peer entry
/// exempts P's session from the §3.1 zeroing: the export copy keeps
/// its LOCAL_PREF, the comparison ties at 100, and R's locally
/// originated route wins on the shorter (empty) AS path.
#[test]
fn per_peer_override_skips_sender_side_lp_zeroing() {
    let (_r, _q, p) = spawn_sender_topology("peer", true);
    wait_installed_hop(&p.log, "198.51.100.0/24", "192.0.2.1");
}
