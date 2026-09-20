//! End-to-end tests for the daemon's RPKI-RTR cache client
//! (`[bgp.rpki]` / `--rpki-cache`, ROADMAP-v3 D2.4/D2.5): a real
//! `lr-daemon` process against an in-test mock RTR cache, verified
//! through the runtime API `status` command and the daemon log.
//!
//! The mock cache speaks RFC 8210 v1 through `lr_bgp::rtr` (the same
//! codec BIRD's client validated in `tests/interop/rtr_bird.sh`):
//! Reset Query → Cache Response + Prefix PDUs + End of Data, then
//! empty-diff End of Data answers for refresh Serial Queries.

#![cfg(unix)]

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::os::unix::net::UnixStream;
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use lr_bgp::rtr::{self, RtrPdu, RTR_VERSION_1};
use lr_core::addr::Prefix;

const BIN: &str = env!("CARGO_BIN_EXE_lr-daemon");

// ---------------------------------------------------------------------
// Mock RTR cache
// ---------------------------------------------------------------------

struct MockCache {
    port: u16,
    shutdown: Arc<std::sync::atomic::AtomicBool>,
    handle: Option<thread::JoinHandle<()>>,
}

impl Drop for MockCache {
    fn drop(&mut self) {
        self.shutdown
            .store(true, std::sync::atomic::Ordering::Relaxed);
        // Connect-and-drop to wake the accept loop, then reap.
        let _ = TcpStream::connect(("127.0.0.1", self.port));
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}

/// Spawn a mock RTR cache serving `dataset` at session `session`.
/// With `keep_alive` the connection stays open after a completed
/// sync (the steady-state shape); otherwise the cache closes the
/// connection after every answered query, which drives the daemon's
/// client through reconnect + incremental re-sync.
fn spawn_mock_cache(
    session: u16,
    serial: u32,
    dataset: Vec<RtrPdu>,
    keep_alive: bool,
) -> MockCache {
    let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind mock cache");
    let port = listener.local_addr().unwrap().port();
    let shutdown = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let shutdown_t = Arc::clone(&shutdown);
    let handle = thread::spawn(move || {
        listener
            .set_nonblocking(true)
            .expect("set mock cache nonblocking");
        loop {
            if shutdown_t.load(std::sync::atomic::Ordering::Relaxed) {
                return;
            }
            match listener.accept() {
                Ok((stream, _)) => {
                    serve_client(stream, session, serial, &dataset, keep_alive);
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(20));
                }
                Err(_) => return,
            }
        }
    });
    MockCache {
        port,
        shutdown,
        handle: Some(handle),
    }
}

/// Serve one client connection: answer every query with the full
/// dataset + End of Data (our client diffs, so re-announcing known
/// records coalesces to empty deltas — the §5.6 duplicate rule). With
/// `keep_alive` false the connection closes after the first answer,
/// forcing the client through its reconnect path.
fn serve_client(
    mut stream: TcpStream,
    session: u16,
    serial: u32,
    dataset: &[RtrPdu],
    keep_alive: bool,
) {
    let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
    loop {
        let Some(pdu) = recv_pdu(&mut stream) else {
            return;
        };
        match pdu {
            RtrPdu::ResetQuery | RtrPdu::SerialQuery { .. } => {
                let mut out = Vec::new();
                rtr::encode(
                    &RtrPdu::CacheResponse {
                        session_id: session,
                    },
                    RTR_VERSION_1,
                    &mut out,
                );
                for d in dataset {
                    rtr::encode(d, RTR_VERSION_1, &mut out);
                }
                // End of Data v1: session, serial, refresh, retry,
                // expire (RFC 8210 §5.10 — the 24-byte v1 form). The
                // 1 s retry keeps the test's reconnect quick — the
                // daemon honors the cache-provided intervals (§6).
                rtr::encode(
                    &RtrPdu::EndOfData {
                        session_id: session,
                        serial,
                        refresh_interval: Some(60),
                        retry_interval: Some(1),
                        expire_interval: Some(120),
                    },
                    RTR_VERSION_1,
                    &mut out,
                );
                if stream.write_all(&out).is_err() {
                    return;
                }
                if !keep_alive {
                    return;
                }
            }
            _ => return,
        }
    }
}

/// Read exactly one PDU (framing-aware: 8-byte header, then body).
fn recv_pdu(stream: &mut TcpStream) -> Option<RtrPdu> {
    let mut header = [0u8; 8];
    stream.read_exact(&mut header).ok()?;
    let len = u32::from_be_bytes([header[4], header[5], header[6], header[7]]) as usize;
    let mut body = vec![0u8; len - 8];
    stream.read_exact(&mut body).ok()?;
    let mut full = header.to_vec();
    full.extend_from_slice(&body);
    match rtr::decode(&full) {
        Ok(Some((_, pdu, _))) => Some(pdu),
        _ => None,
    }
}

fn dataset() -> Vec<RtrPdu> {
    vec![
        RtrPdu::Ipv4Prefix {
            announce: true,
            prefix: Prefix::new_v4([192, 0, 2, 0], 24),
            max_length: 24,
            asn: 64512,
        },
        RtrPdu::Ipv6Prefix {
            announce: true,
            prefix: Prefix::new_v6(
                [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                48,
            ),
            max_length: 64,
            asn: 64512,
        },
    ]
}

// ---------------------------------------------------------------------
// Daemon harness (the daemon_runtime.rs pattern)
// ---------------------------------------------------------------------

struct Daemon {
    child: std::process::Child,
    log: std::path::PathBuf,
}

impl Daemon {
    fn spawn(args: &[&str], tag: &str) -> Self {
        let log =
            std::env::temp_dir().join(format!("lr-daemon-rpki-{tag}-{}.log", std::process::id()));
        let log_file = std::fs::File::create(&log).expect("create log file");
        let child = std::process::Command::new(BIN)
            .args(args)
            .stdout(std::process::Stdio::from(
                log_file.try_clone().expect("clone stdout"),
            ))
            .stderr(std::process::Stdio::from(log_file))
            .spawn()
            .expect("spawn lr-daemon");
        Self { child, log }
    }

    fn wait_log(&self, needle: &str, what: &str) -> String {
        let deadline = Instant::now() + Duration::from_secs(15);
        loop {
            let text = std::fs::read_to_string(&self.log).unwrap_or_default();
            if text.contains(needle) {
                return text;
            }
            if Instant::now() >= deadline {
                panic!("daemon did not report '{what}' within 15 s; last: {text}");
            }
            thread::sleep(Duration::from_millis(100));
        }
    }

    fn signal(&self, sig: i32) {
        let rc = unsafe { kill(self.child.id() as i32, sig) };
        assert_eq!(rc, 0, "kill({sig}) failed");
    }
}

extern "C" {
    fn kill(pid: i32, sig: i32) -> i32;
}

const SIGHUP: i32 = 1;

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.child.kill();
        // Bounded wait: a daemon wedged in a syscall (D-state,
        // e.g. a TCP close that never returns) cannot be reaped
        // immediately even after SIGKILL — the kernel queues the
        // signal but does not deliver it until the syscall exits.
        // A blocking `wait()` here would then stall the test
        // binary indefinitely, which is the historic macOS CI
        // hang pattern. Poll `try_wait()` for up to 10 s; if the
        // process is still alive after SIGKILL + 10 s, leave the
        // zombie for init to reap when the test process exits.
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

/// One round trip on the runtime API socket (the daemon_runtime.rs
/// pattern): send a command, collect the reply until a short idle.
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

// ---------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------

#[test]
fn rpki_sync_populates_the_roa_store() {
    let cache = spawn_mock_cache(0x00ff, 1, dataset(), true);

    let socket =
        std::env::temp_dir().join(format!("lr-daemon-rpki-sync-{}.sock", std::process::id()));
    let config =
        std::env::temp_dir().join(format!("lr-daemon-rpki-sync-{}.toml", std::process::id()));
    std::fs::write(
        &config,
        format!(
            "[bgp]\nlocal_as = 64512\npeer_as = 64513\nrouter_id = \"10.0.0.1\"\n\n\
             [bgp.rpki]\ncache = \"127.0.0.1:{}\"\nretry_interval = 1\n\n\
             [[roa]]\nprefix = \"198.51.100.0/24\"\nasn = 64513\n",
            cache.port
        ),
    )
    .unwrap();

    let d = Daemon::spawn(
        &[
            "--config",
            config.to_str().unwrap(),
            "--api-socket",
            socket.to_str().unwrap(),
        ],
        "sync",
    );
    d.wait_log("rpki: sync complete", "first RTR sync");

    // The API status line reports the live store: two cache ROAs plus
    // one static [[roa]] entry, the session/serial from End of Data,
    // and the cache-provided refresh interval. The transport state
    // (state=) is deliberately NOT asserted: after a sync the client
    // may legitimately be inside a reconnect cycle, which is a
    // transient the data assertions do not depend on. Poll until the
    // sync's status snapshot is visible (it refreshes at sync time,
    // but the API query may race the thread's very first update).
    let line = {
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            let status = api_ask(&socket, "status");
            let matched = status.lines().find(|l| l.starts_with("rpki: cache="));
            if let Some(l) = matched {
                if l.contains("session=0x00ff")
                    && l.contains("serial=1")
                    && l.contains("roas=3 (static=1 rtr=2)")
                    && l.contains("refresh=60s")
                {
                    break l.to_string();
                }
            }
            if Instant::now() >= deadline {
                panic!("rpki status never reflected the sync: {status}");
            }
            thread::sleep(Duration::from_millis(100));
        }
    };
    // The status line carries the cache-provided refresh interval —
    // proof the End-of-Data values reached the live client.
    assert!(line.contains("refresh=60s"), "rpki status: {line}");
}

#[test]
fn rpki_client_reconnects_and_resyncs() {
    // keep_alive = false: the cache closes after every answered
    // query, so the daemon must notice the drop, wait out the retry
    // backoff, reconnect and complete an incremental re-sync.
    let cache = spawn_mock_cache(0x00ff, 1, dataset(), false);

    let config =
        std::env::temp_dir().join(format!("lr-daemon-rpki-reconn-{}.toml", std::process::id()));
    std::fs::write(
        &config,
        format!(
            "[bgp]\nlocal_as = 64512\npeer_as = 64513\nrouter_id = \"10.0.0.1\"\n\n\
             [bgp.rpki]\ncache = \"127.0.0.1:{}\"\nretry_interval = 1\n",
            cache.port
        ),
    )
    .unwrap();

    let d = Daemon::spawn(&["--config", config.to_str().unwrap()], "reconn");
    let first = d.wait_log("rpki: sync complete", "first RTR sync");
    assert_eq!(first.matches("rpki: sync complete").count(), 1);

    // The client reconnects and completes a second sync (Serial
    // Query with the remembered session, answered with an empty
    // diff).
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        let text = std::fs::read_to_string(&d.log).unwrap_or_default();
        if text.matches("rpki: sync complete").count() >= 2
            && text.contains("rpki: connected to")
            && text.matches("rpki: connected to").count() >= 2
        {
            break;
        }
        if Instant::now() >= deadline {
            panic!("no second sync within 15 s; last: {text}");
        }
        thread::sleep(Duration::from_millis(100));
    }
}

#[test]
fn rpki_reload_repoints_the_cache_and_roa_table() {
    // D2.5: SIGHUP re-applies the configuration. Cache A syncs first;
    // the rewritten config points at cache B (different session and
    // dataset serialization) and adds a second static [[roa]]. The
    // reload must swap the static table and re-sync from B.
    let cache_a = spawn_mock_cache(0x00ff, 1, dataset(), true);
    let cache_b = spawn_mock_cache(0x00fe, 7, dataset(), true);

    let socket =
        std::env::temp_dir().join(format!("lr-daemon-rpki-reload-{}.sock", std::process::id()));
    let config =
        std::env::temp_dir().join(format!("lr-daemon-rpki-reload-{}.toml", std::process::id()));
    std::fs::write(
        &config,
        format!(
            "[bgp]\nlocal_as = 64512\npeer_as = 64513\nrouter_id = \"10.0.0.1\"\n\n\
             [bgp.rpki]\ncache = \"127.0.0.1:{}\"\nretry_interval = 1\n\n\
             [[roa]]\nprefix = \"198.51.100.0/24\"\nasn = 64513\n",
            cache_a.port
        ),
    )
    .unwrap();

    let d = Daemon::spawn(
        &[
            "--config",
            config.to_str().unwrap(),
            "--api-socket",
            socket.to_str().unwrap(),
        ],
        "reload",
    );
    d.wait_log("rpki: sync complete", "sync from cache A");

    // Rewrite the config: new cache address + one more static ROA.
    std::fs::write(
        &config,
        format!(
            "[bgp]\nlocal_as = 64512\npeer_as = 64513\nrouter_id = \"10.0.0.1\"\n\n\
             [bgp.rpki]\ncache = \"127.0.0.1:{}\"\nretry_interval = 1\n\n\
             [[roa]]\nprefix = \"198.51.100.0/24\"\nasn = 64513\n\n\
             [[roa]]\nprefix = \"203.0.113.0/24\"\nasn = 64512\n",
            cache_b.port
        ),
    )
    .unwrap();

    d.signal(SIGHUP);

    // The reload re-points the client and re-applies the static table.
    d.wait_log("rpki: cache changed", "cache re-point");
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        let status = api_ask(&socket, "status");
        if let Some(line) = status.lines().find(|l| l.starts_with("rpki: cache=")) {
            if line.contains(&format!("cache=127.0.0.1:{}", cache_b.port))
                && line.contains("roas=4 (static=2 rtr=2)")
            {
                break;
            }
        }
        if Instant::now() >= deadline {
            let text = std::fs::read_to_string(&d.log).unwrap_or_default();
            panic!("no sync from cache B within 15 s; log: {text}");
        }
        thread::sleep(Duration::from_millis(100));
    }
}
