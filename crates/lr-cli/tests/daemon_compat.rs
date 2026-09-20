//! End-to-end tests for the W5.4 compat surface: `lr-daemon
//! --config` loading BIRD 2 and FRR configurations *natively* and
//! exchanging real BGP routes with a regular lr-daemon peer.
//!
//! The dialect-loaded daemon is the connector (BIRD `neighbor … port`
//! / FRR `neighbor … port` map onto its outbound `remote`); the peer
//! is spawned from plain CLI flags and listens. Both directions of
//! route flow are asserted, plus the startup warnings that prove the
//! compat path (and its dialect defaults) was taken, and the
//! `lr:`-directive `api-socket` side effect.

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
            std::env::temp_dir().join(format!("lr-daemon-compat-{tag}-{}.log", std::process::id()));
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

/// Read a log file until it contains every needle (bounded wait).
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
    panic!(
        "log did not reach {needles:?} within 30 s; last contents:\n{text}",
        needles = needles,
        text = text
    );
}

fn wait_file(path: &std::path::Path, what: &str) {
    let deadline = Instant::now() + Duration::from_secs(15);
    while Instant::now() < deadline {
        if path.exists() {
            return;
        }
        thread::sleep(Duration::from_millis(100));
    }
    panic!("{} did not appear within 15 s", what);
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

/// A BIRD 2 configuration runs natively: the daemon parses it, applies
/// the BIRD dialect defaults (accept-all eBGP policy) and the `lr:`
/// directives, then exchanges routes with a flag-spawned peer.
#[test]
fn bird_dialect_config_runs_end_to_end() {
    let port = free_port();
    let dir = std::env::temp_dir().join(format!("lr-daemon-compat-bird-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let sock = dir.join("api.sock");
    let sock = sock.display().to_string();

    // The subject: a BIRD-shaped config, loaded directly. The static
    // protocol seeds the originated prefix, the channel declares the
    // IPv4 family, and the `lr:` directives carry what BIRD has no
    // syntax for (the runtime API socket).
    let conf = dir.join("bird.conf");
    std::fs::write(
        &conf,
        format!(
            r#"router id 10.0.0.1;

protocol static seed {{
    ipv4;
    route 203.0.113.0/24 blackhole;
}}

protocol bgp peer {{
    local as 64512;
    local address 192.0.2.1;
    neighbor 127.0.0.1 port {port} as 64513;
    hold time 30;
    ipv4 {{
        import all;
        export all;
    }};
}}

# lr: api-socket {sock}
"#
        ),
    )
    .unwrap();

    let bird_side = Daemon::spawn(&["--config", conf.to_str().unwrap()], "bird-side");
    // Wait for the compat warnings that prove the dialect path ran.
    wait_log_all(
        &bird_side.log,
        &["config warning: bird dialect defaults applied: accept-all eBGP policy"],
    );

    // The reference peer: plain lr-daemon flags, listening.
    let peer = Daemon::spawn(
        &[
            "--local-as",
            "64513",
            "--peer-as",
            "64512",
            "--router-id",
            "10.0.0.2",
            "--listen",
            &format!("127.0.0.1:{port}"),
            "--local-address",
            "192.0.2.2",
            "--network",
            "198.51.100.0/24",
            "--ebgp-policy",
            "accept-all",
        ],
        "bird-peer",
    );
    wait_log_all(&peer.log, &["listening on"]);

    // Session both ways, routes both ways.
    wait_log_all(
        &bird_side.log,
        &[
            "session #1 → Established",
            "route installed 198.51.100.0/24",
        ],
    );
    wait_log_all(&peer.log, &["route installed 203.0.113.0/24"]);

    // The `lr: api-socket` directive took effect (the extension
    // channel actually reached the daemon, not just the parser).
    wait_file(std::path::Path::new(&sock), "api socket");
}

/// An FRR configuration runs natively, keeping FRR's documented
/// `bgp enforce-first-as` default and the `# lr: neighbor …`
/// per-peer directives.
#[test]
fn frr_dialect_config_runs_end_to_end() {
    let port = free_port();
    let dir = std::env::temp_dir().join(format!("lr-daemon-compat-frr-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let sock = dir.join("api.sock");
    let sock = sock.display().to_string();

    let conf = dir.join("frr.conf");
    std::fs::write(
        &conf,
        format!(
            "frr version 10.3\n\
             !\n\
             router bgp 64512\n\
              bgp router-id 10.0.0.3\n\
              neighbor 127.0.0.1 port {port} remote-as 64513\n\
              neighbor 127.0.0.1 update-source 192.0.2.3\n\
              network 203.0.113.0/24\n\
             !\n\
             # lr: neighbor 127.0.0.1 add-path\n\
             # lr: api-socket {sock}\n\
             !\n"
        ),
    )
    .unwrap();

    let frr_side = Daemon::spawn(&["--config", conf.to_str().unwrap()], "frr-side");
    wait_log_all(
        &frr_side.log,
        &[
            "config warning: frr dialect defaults applied: enforce-first-as on, accept-all eBGP policy",
        ],
    );

    let peer = Daemon::spawn(
        &[
            "--local-as",
            "64513",
            "--peer-as",
            "64512",
            "--router-id",
            "10.0.0.4",
            "--listen",
            &format!("127.0.0.1:{port}"),
            "--local-address",
            "192.0.2.4",
            "--network",
            "198.51.100.0/24",
            "--ebgp-policy",
            "accept-all",
        ],
        "frr-peer",
    );
    wait_log_all(&peer.log, &["listening on"]);

    wait_log_all(
        &frr_side.log,
        &[
            "session #1 → Established",
            "route installed 198.51.100.0/24",
        ],
    );
    wait_log_all(&peer.log, &["route installed 203.0.113.0/24"]);
    wait_file(std::path::Path::new(&sock), "api socket");
}

/// A BIRD config that also carries non-BGP routing protocols still
/// runs the BGP control plane, and the ignored stanzas surface as
/// startup warnings instead of vanishing.
#[test]
fn non_bgp_stanzas_warn_but_do_not_block() {
    let port = free_port();
    let dir = std::env::temp_dir().join(format!("lr-daemon-compat-mixed-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();

    let conf = dir.join("bird-mixed.conf");
    std::fs::write(
        &conf,
        format!(
            "router id 10.0.0.1;\n\
             \n\
             protocol ospf my_ospf {{\n    area 0 {{ interface \"eth0\"; }}\n}}\n\
             \n\
             protocol bgp peer {{\n    local as 64512;\n    neighbor 127.0.0.1 port {port} as 64513;\n}}\n"
        ),
    )
    .unwrap();

    let mixed = Daemon::spawn(&["--config", conf.to_str().unwrap()], "mixed");
    wait_log_all(
        &mixed.log,
        &["config warning: protocol ospf my_ospf: ignored"],
    );

    // The BGP side still comes up (connect to a one-shot listener).
    let peer = Daemon::spawn(
        &[
            "--local-as",
            "64513",
            "--peer-as",
            "64512",
            "--router-id",
            "10.0.0.2",
            "--listen",
            &format!("127.0.0.1:{port}"),
            "--local-address",
            "192.0.2.2",
            "--ebgp-policy",
            "accept-all",
        ],
        "mixed-peer",
    );
    // Wait for the peer's listener before expecting Established: the
    // mixed daemon is the outbound connector and starts trying to
    // connect as soon as config parse finishes. Without this gate the
    // first connect attempt hits a port that is not yet open, the
    // connector's exponential backoff (1 s → 2 s → 4 s → 8 s → 16 s)
    // eats the 30 s `wait_log_all` budget on a loaded macOS runner
    // before the retry can land. The other two compat tests
    // (`bird_dialect_config_runs_end_to_end`,
    // `frr_dialect_config_runs_end_to_end`) already wait for
    // `"listening on"` on the peer's log before waiting for
    // Established — this test was the outlier.
    wait_log_all(&peer.log, &["listening on"]);
    wait_log_all(&mixed.log, &["session #1 → Established"]);
    let _ = peer;
}
