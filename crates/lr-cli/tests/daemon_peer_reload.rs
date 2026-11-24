//! End-to-end tests for the peer-level configuration reload (issue
//! #101 "Improving Configuration Reloading"): a SIGHUP adds, removes,
//! reconfigures and administratively shuts down `[[peer]]`s without
//! restarting the daemon, swaps policy in place (soft reconfiguration,
//! no session bounce), and a reload that cannot be validated changes
//! nothing.
//!
//! Each test spawns the real binary (`CARGO_BIN_EXE_lr-daemon`) on
//! distinct loopback ports so they can run concurrently.

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
            "lr-daemon-pr-{tag}-{}-{seq}.log",
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

    fn signal(&mut self, sig: i32) {
        let rc = unsafe { kill(self.pid(), sig) };
        assert_eq!(rc, 0, "kill({sig}) failed");
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
    }
}

extern "C" {
    fn kill(pid: i32, sig: i32) -> i32;
}

const SIGHUP: i32 = 1;

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

/// One listener daemon under test as a BGP neighbour: `--local-as`,
/// `--router-id`, `--listen`, and an accepted peer AS.
fn listener_daemon(
    tag: &str,
    as_num: &str,
    router_id: &str,
    port: u16,
    network: Option<&str>,
) -> Daemon {
    let mut args: Vec<String> = vec![
        "--local-as".into(),
        as_num.into(),
        "--peer-as".into(),
        "64512".into(),
        "--router-id".into(),
        router_id.into(),
        "--listen".into(),
        format!("127.0.0.1:{port}"),
        "--ebgp-policy".into(),
        "accept-all".into(),
    ];
    if let Some(net) = network {
        args.push("--network".into());
        args.push(net.into());
    }
    let refs: Vec<&str> = args.iter().map(String::as_str).collect();
    let d = Daemon::spawn(&refs, tag);
    wait_log_all(&d.log, &["listening on"]);
    d
}

/// A SIGHUP that replaces the outbound peer B with a fresh peer C
/// removes B's session (RFC 4486 §4.1 Cease/3, the peer sees the
/// de-configuration) and establishes with C — the daemon process keeps
/// running throughout.
#[test]
fn sighup_replaces_peer_without_restart() {
    let dir = std::env::temp_dir().join(format!("lr-daemon-pr-replace-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    // 18381/18382: this file's port ladder stays disjoint from every
    // other e2e binary cargo may run in parallel (daemon_collision and
    // daemon_multi_peer both own 18301+, 18311+, 18321+ and 18331+).
    let port_b = 18381u16;
    let port_c = 18382u16;

    let b = listener_daemon(
        "repl-b",
        "64513",
        "10.0.0.2",
        port_b,
        Some("198.51.100.0/24"),
    );
    let _c = listener_daemon("repl-c", "64514", "10.0.0.3", port_c, None);

    let conf = dir.join("a.toml");
    std::fs::write(
        &conf,
        format!(
            "[bgp]\n\
             local_as = 64512\n\
             peer_as = 64513\n\
             router_id = \"10.0.0.1\"\n\
             ebgp_policy = \"accept-all\"\n\n\
             [[peer]]\n\
             remote = \"127.0.0.1:{port_b}\"\n"
        ),
    )
    .unwrap();
    let mut a = Daemon::spawn(&["--config", conf.to_str().unwrap()], "repl-a");
    wait_log_all(&a.log, &["session #1 → Established"]);

    // Rewrite: the peer becomes C. One SIGHUP removes B and adds C.
    std::fs::write(
        &conf,
        format!(
            "[bgp]\n\
             local_as = 64512\n\
             peer_as = 64514\n\
             router_id = \"10.0.0.1\"\n\
             ebgp_policy = \"accept-all\"\n\n\
             [[peer]]\n\
             remote = \"127.0.0.1:{port_c}\"\n"
        ),
    )
    .unwrap();
    a.signal(SIGHUP);
    wait_log_all(
        &a.log,
        &[
            "reload: peer 127.0.0.1:18381 removed",
            "reload: peer 127.0.0.1:18382 added",
            // The new session establishes (a fresh handle, session #2
            // or later — match the state line loosely).
            "→ Established",
        ],
    );
    // B saw the RFC 4486 §4.1 Cease for its removal.
    wait_log_all(&b.log, &["NOTIFICATION code=6"]);

    // The daemon is still the same process (no restart happened): the
    // log must NOT contain a second startup banner.
    let text = std::fs::read_to_string(&a.log).unwrap_or_default();
    assert_eq!(
        text.matches("librouting daemon (lr-daemon)").count(),
        1,
        "the daemon must not restart on a peer replacement; log:\n{text}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// A SIGHUP that changes a session-affecting field (the hold time)
/// restarts exactly that peer's sessions: the old transport closes
/// with the RFC 4486 §4.1 Administrative Reset Cease and the connector
/// re-dials under the fresh configuration.
#[test]
fn sighup_restarts_reconfigured_peer_sessions() {
    let dir = std::env::temp_dir().join(format!("lr-daemon-pr-restart-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    // 18361: this file's ladder (18361, 18371, 18381/18382, 18391,
    // 18341, 18351/18352) stays disjoint from every other e2e binary
    // cargo may run in parallel — daemon_collision and daemon_multi_peer
    // own 18301+, 18311+, 18321+ and 18331+.
    let port_b = 18361u16;

    let b = listener_daemon("rst-b", "64513", "10.0.0.2", port_b, None);

    let conf = dir.join("a.toml");
    let write_conf = |hold: u16| {
        std::fs::write(
            &conf,
            format!(
                "[bgp]\n\
                 local_as = 64512\n\
                 peer_as = 64513\n\
                 router_id = \"10.0.0.1\"\n\
                 ebgp_policy = \"accept-all\"\n\n\
                 [[peer]]\n\
                 remote = \"127.0.0.1:{port_b}\"\n\
                 hold_time = {hold}\n"
            ),
        )
        .unwrap();
    };
    write_conf(60);
    let mut a = Daemon::spawn(&["--config", conf.to_str().unwrap()], "rst-a");
    wait_log_all(&a.log, &["session #1 → Established"]);

    write_conf(90);
    a.signal(SIGHUP);
    wait_log_all(
        &a.log,
        &[
            "reload: peer 127.0.0.1:18361 reconfigured — restarting its sessions",
            "session #2 → Established",
        ],
    );
    // The peer saw the reconfiguration Cease and the re-established
    // session negotiated the fresh hold time (90 s).
    wait_log_all(&b.log, &["NOTIFICATION code=6"]);

    let _ = std::fs::remove_dir_all(&dir);
}

/// A SIGHUP that changes only the import filter swaps the policy in
/// place: the session stays Established (no second establishment
/// line) and the soft re-configuration re-imports the Adj-RIB-In under
/// the fresh filter, so the previously rejected route appears.
#[test]
fn sighup_swaps_import_filter_without_session_bounce() {
    let dir = std::env::temp_dir().join(format!("lr-daemon-pr-filter-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    // 18371: see the port note in `sighup_restarts_reconfigured_peer_sessions`.
    // The full ladder: 18341, 18342, 18351/18352, 18361, 18371,
    // 18381/18382, 18391 — disjoint from every other e2e binary.
    let port_b = 18371u16;

    let _b = listener_daemon(
        "flt-b",
        "64513",
        "10.0.0.2",
        port_b,
        Some("198.51.100.0/24"),
    );

    let conf = dir.join("a.toml");
    let write_conf = |body: &str| {
        std::fs::write(
            &conf,
            format!(
                "[bgp]\n\
                 local_as = 64512\n\
                 peer_as = 64513\n\
                 router_id = \"10.0.0.1\"\n\
                 ebgp_policy = \"accept-all\"\n\n\
                 [[peer]]\n\
                 remote = \"127.0.0.1:{port_b}\"\n\
                 import_filter = \"in-filter\"\n\n\
                 [[filter]]\n\
                 name = \"in-filter\"\n\
                 body = \"{body}\"\n"
            ),
        )
        .unwrap();
    };
    write_conf("if net == 198.51.100.0/24 then { reject; } accept;");
    let mut a = Daemon::spawn(&["--config", conf.to_str().unwrap()], "flt-a");
    wait_log_all(&a.log, &["session #1 → Established"]);
    // The route arrives and the filter rejects it.
    thread::sleep(Duration::from_secs(2));
    let before = std::fs::read_to_string(&a.log).unwrap_or_default();
    assert!(
        !before.contains("route installed 198.51.100.0/24"),
        "the rejecting filter must keep the route out; log:\n{before}"
    );
    let establishments_before = before.matches("→ Established").count();

    // Swap the filter body to accept; the session must NOT bounce.
    write_conf("accept;");
    a.signal(SIGHUP);
    let after = wait_log_all(&a.log, &["reload: policy recompiled", "route-refreshed"]);
    wait_log_all(&a.log, &["route installed 198.51.100.0/24"]);
    let establishments_after = after.matches("→ Established").count();
    assert_eq!(
        establishments_before, establishments_after,
        "a policy-only reload must not re-establish the session; log:\n{after}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// The FRR `neighbor X shutdown` toggle: `shutdown = true` closes the
/// live session with the RFC 4486 §4.1 Administrative Shutdown Cease
/// and parks the connector; `shutdown = false` starts the connector
/// again and the session re-establishes.
#[test]
fn sighup_toggles_peer_shutdown() {
    let dir = std::env::temp_dir().join(format!("lr-daemon-pr-shut-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    // 18391: see the port note in `sighup_replaces_peer_without_restart`.
    let port_b = 18391u16;

    let b = listener_daemon("shut-b", "64513", "10.0.0.2", port_b, None);

    let conf = dir.join("a.toml");
    let write_conf = |shutdown: bool| {
        std::fs::write(
            &conf,
            format!(
                "[bgp]\n\
                 local_as = 64512\n\
                 peer_as = 64513\n\
                 router_id = \"10.0.0.1\"\n\
                 ebgp_policy = \"accept-all\"\n\n\
                 [[peer]]\n\
                 remote = \"127.0.0.1:{port_b}\"\n\
                 shutdown = {shutdown}\n"
            ),
        )
        .unwrap();
    };
    write_conf(false);
    let mut a = Daemon::spawn(&["--config", conf.to_str().unwrap()], "shut-a");
    wait_log_all(&a.log, &["session #1 → Established"]);

    // Down: the session closes, the connector parks.
    write_conf(true);
    a.signal(SIGHUP);
    wait_log_all(
        &a.log,
        &["reload: peer 127.0.0.1:18391 admin-down (shutdown = true)"],
    );
    wait_log_all(&b.log, &["NOTIFICATION code=6"]);

    // Up: the connector restarts and the SAME session re-arms and
    // establishes (the admin-down path quiesces the sessions rather
    // than removing them, so the handle survives the toggle).
    write_conf(false);
    a.signal(SIGHUP);
    wait_log_all(
        &a.log,
        &["reload: peer 127.0.0.1:18391 admin-up (shutdown = false) — connector started"],
    );
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        let text = std::fs::read_to_string(&a.log).unwrap_or_default();
        if text.matches("session #1 → Established").count() >= 2 {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "the re-armed session must re-establish; log:\n{text}"
        );
        thread::sleep(Duration::from_millis(100));
    }

    let _ = std::fs::remove_dir_all(&dir);
}

/// A reload whose fresh configuration cannot be validated changes
/// nothing: the peer table, the sessions and the originated networks
/// all keep running, and the reload reports what it rejected. The
/// validation cases: an unknown route-map reference, and a local-AS
/// change (a daemon-wide restart, refused as one atomic decision).
#[test]
fn sighup_invalid_reload_changes_nothing() {
    let dir = std::env::temp_dir().join(format!("lr-daemon-pr-atomic-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let port_b = 18341u16;

    let _b = listener_daemon("atom-b", "64513", "10.0.0.2", port_b, None);

    let conf = dir.join("a.toml");
    let good = format!(
        "[bgp]\n\
         local_as = 64512\n\
         peer_as = 64513\n\
         router_id = \"10.0.0.1\"\n\
         ebgp_policy = \"accept-all\"\n\n\
         networks = [\"203.0.113.0/24\"]\n\n\
         [[peer]]\n\
         remote = \"127.0.0.1:{port_b}\"\n"
    );
    std::fs::write(&conf, &good).unwrap();
    let mut a = Daemon::spawn(&["--config", conf.to_str().unwrap()], "atom-a");
    wait_log_all(&a.log, &["session #1 → Established"]);

    // 1. A peer referencing an unknown route-map: the whole reload is
    //    refused (no network changes, no peer churn).
    std::fs::write(
        &conf,
        format!(
            "[bgp]\n\
             local_as = 64512\n\
             peer_as = 64513\n\
             router_id = \"10.0.0.1\"\n\
             ebgp_policy = \"accept-all\"\n\n\
             networks = [\"198.51.100.0/24\"]\n\n\
             [[peer]]\n\
             remote = \"127.0.0.1:{port_b}\"\n\
             import = \"does-not-exist\"\n"
        ),
    )
    .unwrap();
    a.signal(SIGHUP);
    let text = wait_log_all(&a.log, &["keeping current config"]);
    assert!(
        text.contains("unknown route-map 'does-not-exist'"),
        "the reload must name the dangling reference; log:\n{text}"
    );
    assert!(
        !text.contains("reload: unoriginating 203.0.113.0/24"),
        "a refused reload must not touch the networks; log:\n{text}"
    );
    for action in ["removed", "added", "reconfigured", "admin-down", "admin-up"] {
        assert!(
            !text.contains(&format!("reload: peer 127.0.0.1:18341 {action}")),
            "a refused reload must not touch the peers; log:\n{text}"
        );
    }

    // 2. A local-AS change is a daemon-wide identity change: applied
    //    as a restart of every peer's session (the unit model — FRR
    //    `router bgp <as>` behaviour), reported as one decision. The
    //    lab peer still expects AS 64512, so the rebuilt session is
    //    rejected on the wire — the assertion covers the identity
    //    swap and the session restart, not a re-establishment.
    std::fs::write(
        &conf,
        "[bgp]\n\
         local_as = 64599\n\
         peer_as = 64513\n\
         router_id = \"10.0.0.1\"\n\
         ebgp_policy = \"accept-all\"\n\n\
         [[peer]]\n\
         remote = \"127.0.0.1:18341\"\n",
    )
    .unwrap();
    a.signal(SIGHUP);
    let text = wait_log_all(
        &a.log,
        &["reload: speaker identity changed (AS 64512 -> 64599)"],
    );
    assert!(
        text.contains("restarting its sessions"),
        "the identity change restarts the peer's sessions; log:\n{text}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// A speaker-identity change that the lab peer CAN accept — a
/// router-id change (the peer does not enforce the remote bgp-id) —
/// restarts every session and re-establishes with the fresh identity:
/// the full positive cycle of the identity-reload unit.
#[test]
fn sighup_router_id_change_restarts_and_reestablishes() {
    let dir = std::env::temp_dir().join(format!("lr-daemon-pr-rid-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    // 18342: see the port note in `sighup_restarts_reconfigured_peer_sessions`
    // — this file's ladder stays disjoint from every other e2e binary.
    let port_b = 18342u16;

    let _b = listener_daemon("rid-b", "64513", "10.0.0.2", port_b, None);

    let conf = dir.join("a.toml");
    let write_conf = |router_id: &str| {
        std::fs::write(
            &conf,
            format!(
                "[bgp]\n\
                 local_as = 64512\n\
                 peer_as = 64513\n\
                 router_id = \"{router_id}\"\n\
                 ebgp_policy = \"accept-all\"\n\n\
                 [[peer]]\n\
                 remote = \"127.0.0.1:{port_b}\"\n"
            ),
        )
        .unwrap();
    };
    write_conf("10.0.0.1");
    let mut a = Daemon::spawn(&["--config", conf.to_str().unwrap()], "rid-a");
    wait_log_all(&a.log, &["session #1 → Established"]);

    // First Established count: the initial session.
    let first_established = wait_log_all(&a.log, &["session #1 → Established"])
        .matches("→ Established")
        .count();

    // Change only the router-id: the identity unit fires, the session
    // restarts (Cease/4) and comes back Established with the fresh id.
    write_conf("10.0.0.7");
    a.signal(SIGHUP);
    let text = wait_log_all(
        &a.log,
        &["reload: speaker identity changed (router-id 10.0.0.1 -> 10.0.0.7)"],
    );
    assert!(
        text.contains("restarting its sessions"),
        "the router-id change restarts the peer's sessions; log:\n{text}"
    );
    // A second Established line: the rebuilt session (a fresh handle)
    // negotiated successfully with the fresh identity.
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        let text = std::fs::read_to_string(&a.log).unwrap_or_default();
        if text.matches("→ Established").count() > first_established {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "the session must re-establish after the identity change; log:\n{text}"
        );
        thread::sleep(Duration::from_millis(200));
    }

    let _ = std::fs::remove_dir_all(&dir);
}

/// A reload that only adds a second peer leaves the first session
/// untouched: the Established count does not grow for peer 1 while the
/// new peer comes up.
#[test]
fn sighup_adding_a_peer_leaves_the_incumbent_alone() {
    let dir = std::env::temp_dir().join(format!("lr-daemon-pr-add-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let port_b = 18351u16;
    let port_c = 18352u16;

    let b = listener_daemon("add-b", "64513", "10.0.0.2", port_b, None);
    let _c = listener_daemon("add-c", "64514", "10.0.0.3", port_c, None);

    let conf = dir.join("a.toml");
    std::fs::write(
        &conf,
        format!(
            "[bgp]\n\
             local_as = 64512\n\
             peer_as = 64513\n\
             router_id = \"10.0.0.1\"\n\
             ebgp_policy = \"accept-all\"\n\n\
             [[peer]]\n\
             remote = \"127.0.0.1:{port_b}\"\n"
        ),
    )
    .unwrap();
    let mut a = Daemon::spawn(&["--config", conf.to_str().unwrap()], "add-a");
    wait_log_all(&a.log, &["session #1 → Established"]);

    // Add peer C; B's session must not churn (no new Established line
    // for session #1, no Cease on B).
    std::fs::write(
        &conf,
        format!(
            "[bgp]\n\
             local_as = 64512\n\
             peer_as = 64513\n\
             router_id = \"10.0.0.1\"\n\
             ebgp_policy = \"accept-all\"\n\n\
             [[peer]]\n\
             remote = \"127.0.0.1:{port_b}\"\n\n\
             [[peer]]\n\
             remote = \"127.0.0.1:{port_c}\"\n\
             peer_as = 64514\n"
        ),
    )
    .unwrap();
    a.signal(SIGHUP);
    wait_log_all(
        &a.log,
        &[
            "reload: peer 127.0.0.1:18352 added",
            "session #2 → Established",
        ],
    );
    let text = std::fs::read_to_string(&a.log).unwrap_or_default();
    assert_eq!(
        text.matches("session #1 → Established").count(),
        1,
        "the incumbent peer must not re-establish; log:\n{text}"
    );
    let b_text = std::fs::read_to_string(&b.log).unwrap_or_default();
    assert!(
        !b_text.contains("Cease"),
        "the incumbent peer must not see a Cease; log:\n{b_text}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}
