//! End-to-end tests for the lr-daemon running on native `.lr`
//! configurations (ROADMAP-v3 D16 Phase 3, GitHub #18).
//!
//! Phase 2 wired the DSL frontend into the shared load path; Phase 3
//! proves the daemon runs *on* it: content detection (no
//! `--config-dialect` flag), a multi-peer session topology configured
//! entirely in the DSL, route exchange across it, and SIGHUP reload
//! of a rewritten `.lr` file — the same runtime paths the TOML
//! frontend exercises, driven end to end through the native one.
//!
//! Each test spawns the real binary (`CARGO_BIN_EXE_lr-daemon`) on
//! distinct loopback ports so they can run concurrently.

#![cfg(unix)]

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
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
            std::env::temp_dir().join(format!("lr-daemon-lrcfg-{tag}-{}.log", std::process::id()));
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

    fn signal(&mut self, sig: i32) {
        let rc = unsafe { kill(self.pid(), sig) };
        assert_eq!(rc, 0, "kill({}) failed", sig);
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

const SIGHUP: i32 = 1;
const SIGTERM: i32 = 15;

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
    panic!("log never contained all of {needles:?}; last: {text}");
}

/// Ask the runtime API one question; return the reply (bounded wait).
fn api_ask(socket: &std::path::Path, cmd: &str) -> String {
    let mut conn = UnixStream::connect(socket).expect("connect to api socket");
    conn.write_all(format!("{cmd}\n").as_bytes()).unwrap();
    conn.flush().unwrap();
    conn.set_nonblocking(true).unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut buf = Vec::new();
    loop {
        let mut chunk = [0u8; 4096];
        match conn.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
            Err(ref e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut =>
            {
                if !buf.is_empty() || Instant::now() >= deadline {
                    break;
                }
                thread::sleep(Duration::from_millis(20));
            }
            Err(_) => break,
        }
    }
    String::from_utf8_lossy(&buf).into_owned()
}

/// Three-daemon topology over real TCP on loopback — the subject is
/// A, whose configuration is written entirely in the native `.lr`
/// DSL and picked up by content detection (no `--config-dialect`
/// flag anywhere):
///
/// ```text
///   B (AS64513, listens :18701, originates 198.51.100.0/24)
///        ▲          A (AS64512, two outbound `peer` blocks,
///        │              originates 203.0.113.0/24)
///   C (AS64514, listens :18702) ◄──┘
/// ```
///
/// A's DSL fan-out must deliver its own prefix to both B and C, and
/// B's prefix must reach C through A (transit) — proving the DSL
/// frontend drives the exact same session, policy and RIB machinery
/// the TOML frontend does.
#[test]
fn lr_config_drives_a_multi_peer_session() {
    let dir = std::env::temp_dir().join(format!("lr-daemon-lrcfg-fanout-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let port_b = 18701u16;
    let port_c = 18702u16;

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
            "--network",
            "198.51.100.0/24",
            "--ebgp-policy",
            "accept-all",
        ],
        "lr-b",
    );
    wait_log_all(&b.log, &["listening on"]);
    let c = Daemon::spawn(
        &[
            "--local-as",
            "64514",
            "--peer-as",
            "64512",
            "--router-id",
            "10.0.0.3",
            "--listen",
            &format!("127.0.0.1:{port_c}"),
            "--ebgp-policy",
            "accept-all",
        ],
        "lr-c",
    );
    wait_log_all(&c.log, &["listening on"]);

    // A: the native dialect — bgp block, two named peer blocks, the
    // policy knob and the originated network, all in `.lr` spelling.
    // Unit suffixes ride along for free (`hold_time 30s`).
    let conf = dir.join("a.lr");
    std::fs::write(
        &conf,
        format!(
            "# A's native configuration (content detection must pick this up).\n\
             bgp {{\n\
             \x20   local_as 64512;\n\
             \x20   router_id \"10.0.0.1\";\n\
             \x20   ebgp_policy \"accept-all\";\n\
             \x20   local_address \"192.0.2.1\";\n\
             \x20   hold_time 30s;\n\
             \x20   networks [\"203.0.113.0/24\"];\n\
             }}\n\n\
             peer \"b\" {{\n\
             \x20   remote \"127.0.0.1:{port_b}\";\n\
             \x20   peer_as 64513;\n\
             }}\n\n\
             peer \"c\" {{\n\
             \x20   remote \"127.0.0.1:{port_c}\";\n\
             \x20   peer_as 64514;\n\
             }}\n"
        ),
    )
    .unwrap();
    let a = Daemon::spawn(&["--config", conf.to_str().unwrap()], "lr-a");

    // Both of A's sessions establish and both peers see A's prefix.
    wait_log_all(
        &a.log,
        &["session #1 → Established", "session #2 → Established"],
    );
    wait_log_all(&b.log, &["route installed 203.0.113.0/24"]);
    wait_log_all(&c.log, &["route installed 203.0.113.0/24"]);

    // Transit: B's prefix reaches A and is re-advertised to C.
    wait_log_all(&a.log, &["route installed 198.51.100.0/24"]);
    wait_log_all(&c.log, &["route installed 198.51.100.0/24"]);

    let _ = std::fs::remove_dir_all(&dir);
}

/// SIGHUP reload of a rewritten `.lr` file: the reload path resolves
/// the dialect per load, so an edited native config applies without a
/// restart (originate/unoriginate), the runtime API sees the new RIB,
/// and a file that no longer parses keeps the current config instead
/// of taking the daemon down.
#[test]
fn sighup_reloads_an_lr_config() {
    let dir = std::env::temp_dir().join(format!("lr-daemon-lrcfg-hup-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let conf = dir.join("daemon.lr");
    let socket = dir.join("daemon.api");

    std::fs::write(
        &conf,
        "bgp {\n\
         \x20   local_as 64512;\n\
         \x20   peer_as 64513;\n\
         \x20   router_id \"10.0.0.1\";\n\
         \x20   listen_addr \"127.0.0.1:18703\";\n\
         \x20   networks [\"203.0.113.0/24\"];\n\
         }\n",
    )
    .unwrap();

    let mut d = Daemon::spawn(
        &[
            "--config",
            conf.to_str().unwrap(),
            "--api-socket",
            socket.to_str().unwrap(),
        ],
        "lr-hup",
    );
    wait_log_all(&d.log, &["originating 203.0.113.0/24", "listening on"]);

    // Rewrite the config (still `.lr`): drop the old network, add a
    // new one, and send SIGHUP — both changes must apply live.
    std::fs::write(
        &conf,
        "bgp {\n\
         \x20   local_as 64512;\n\
         \x20   peer_as 64513;\n\
         \x20   router_id \"10.0.0.1\";\n\
         \x20   listen_addr \"127.0.0.1:18703\";\n\
         \x20   networks [\"198.51.100.0/24\"];\n\
         }\n",
    )
    .unwrap();
    d.signal(SIGHUP);
    let text = wait_log_all(
        &d.log,
        &[
            "SIGHUP received",
            "reload: originating 198.51.100.0/24",
            "reload: unoriginating 203.0.113.0/24",
        ],
    );
    assert!(text.contains("require a restart"), "log: {text}");

    // The runtime API sees the reloaded RIB.
    let routes = api_ask(&socket, "routes");
    assert!(routes.contains("198.51.100.0/24"), "routes: {routes}");
    assert!(!routes.contains("203.0.113.0/24"), "routes: {routes}");

    // A `.lr` file that no longer parses must NOT take the daemon
    // down: the DSL frontend fails closed and the reload keeps the
    // current configuration.
    std::fs::write(&conf, "bgp {\n    local_as 64512\n}\n").unwrap(); // missing `;`
    d.signal(SIGHUP);
    let text = wait_log_all(&d.log, &["keeping current config"]);
    assert!(text.contains("reload:"), "log: {text}");

    d.signal(SIGTERM);
    let _ = d.child.wait();
    let _ = std::fs::remove_dir_all(&dir);
}
