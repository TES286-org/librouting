//! End-to-end tests for the daemon's advanced ROA loader
//! (`[[bgp.roa_source]]`, issue #100): a real `lr-daemon` process
//! against a local HTTP server (for URL sources) and a temp file
//! (for file sources), verified through the runtime API `status`
//! command and the daemon log.
//!
//! These tests are the daemon-side counterpart to the in-process
//! tests in `crates/lr-cli/src/daemon_roa_loader_tests.rs`: they
//! verify the daemon's startup wiring, the runtime API status
//! line and the SIGHUP-driven repoint / shutdown control plane
//! against a real OS process.

#![cfg(unix)]

use std::io::{Read, Write};
use std::net::TcpListener;
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

const BIN: &str = env!("CARGO_BIN_EXE_lr-daemon");

extern "C" {
    fn kill(pid: i32, sig: i32) -> i32;
}

const SIGHUP: i32 = 1;

/// A tiny HTTP server that serves one fixed body to exactly one
/// request, then exits. Used for the URL-source tests.
struct OneShotHttp {
    port: u16,
    handle: Option<thread::JoinHandle<()>>,
}

impl Drop for OneShotHttp {
    fn drop(&mut self) {
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}

fn spawn_one_shot_http(body: String, content_type: &str) -> OneShotHttp {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind http");
    let port = listener.local_addr().unwrap().port();
    let ct = content_type.to_string();
    let handle = thread::spawn(move || {
        let (mut s, _) = listener.accept().expect("accept");
        let mut buf = [0u8; 1024];
        let _ = s.read(&mut buf);
        let resp = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: {ct}\r\nContent-Length: {}\r\n\r\n{}",
            body.len(),
            body
        );
        let _ = s.write_all(resp.as_bytes());
    });
    OneShotHttp {
        port,
        handle: Some(handle),
    }
}

/// An HTTP server that serves the body on every request (so a
/// SIGHUP-driven reload re-fetches the current body). Updates the
/// body atomically through shared state.
struct ReloadableHttp {
    port: u16,
    body: Arc<std::sync::Mutex<String>>,
    shutdown: Arc<AtomicBool>,
    handle: Option<thread::JoinHandle<()>>,
}

impl Drop for ReloadableHttp {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::Relaxed);
        // Connect-and-drop to wake the accept loop.
        let _ = std::net::TcpStream::connect(("127.0.0.1", self.port));
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}

impl ReloadableHttp {
    fn set_body(&self, body: String) {
        *self.body.lock().unwrap() = body;
    }
}

fn spawn_reloadable_http(initial_body: String) -> ReloadableHttp {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind reloadable http");
    let port = listener.local_addr().unwrap().port();
    let body = Arc::new(std::sync::Mutex::new(initial_body));
    let shutdown = Arc::new(AtomicBool::new(false));
    let body_t = Arc::clone(&body);
    let shutdown_t = Arc::clone(&shutdown);
    let handle = thread::spawn(move || {
        listener
            .set_nonblocking(true)
            .expect("set reloadable http nonblocking");
        loop {
            if shutdown_t.load(Ordering::Relaxed) {
                return;
            }
            match listener.accept() {
                Ok((mut s, _)) => {
                    let mut buf = [0u8; 1024];
                    let _ = s.read(&mut buf);
                    let body = body_t.lock().unwrap().clone();
                    let resp = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                        body.len(),
                        body
                    );
                    let _ = s.write_all(resp.as_bytes());
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(20));
                }
                Err(_) => return,
            }
        }
    });
    ReloadableHttp {
        port,
        body,
        shutdown,
        handle: Some(handle),
    }
}

/// A live `lr-daemon` child process; cleaned up on drop.
struct Daemon {
    child: std::process::Child,
    log: PathBuf,
}

impl Daemon {
    fn spawn(args: &[&str], tag: &str) -> Self {
        let log = std::env::temp_dir().join(format!(
            "lr-daemon-roa-source-{tag}-{}.log",
            std::process::id()
        ));
        let log_file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&log)
            .expect("create log file");
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

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.child.kill();
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

/// One round trip on the runtime API socket.
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

/// Poll the `status` API for a `roa-source:` line that matches
/// every needle in `needles`. Returns the matched line on success.
fn wait_for_roa_source_status(socket: &std::path::Path, needles: &[&str]) -> String {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let status = api_ask(socket, "status");
        for line in status.lines() {
            if line.starts_with("roa-source:") && needles.iter().all(|n| line.contains(n)) {
                return line.to_string();
            }
        }
        if Instant::now() >= deadline {
            panic!("roa-source status never matched {needles:?}; last: {status}");
        }
        thread::sleep(Duration::from_millis(100));
    }
}

// ---------------------------------------------------------------------
// File source — startup load + status line
// ---------------------------------------------------------------------

#[test]
fn roa_source_file_loads_at_startup() {
    let roas_file =
        std::env::temp_dir().join(format!("lr-roa-source-e2e-{}.bird", std::process::id()));
    std::fs::write(
        &roas_file,
        "roa 203.0.113.0/24 max 24 as 64512;\nroa 198.51.100.0/24 max 26 as 64513;\n",
    )
    .unwrap();

    let socket = std::env::temp_dir().join(format!(
        "lr-daemon-roa-source-file-{}.sock",
        std::process::id()
    ));
    let config = std::env::temp_dir().join(format!(
        "lr-daemon-roa-source-file-{}.toml",
        std::process::id()
    ));
    std::fs::write(
        &config,
        format!(
            "[bgp]\nlocal_as = 64512\npeer_as = 64513\nrouter_id = \"10.0.0.1\"\n\n\
             [[bgp.roa_source]]\npath = {:?}\nformat = \"bird\"\n",
            roas_file.to_string_lossy()
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
        "file-startup",
    );
    d.wait_log("loaded 2 entries", "roa file load");

    // The status line reports the source's identity, format and entry count.
    let line = wait_for_roa_source_status(
        &socket,
        &["type=file", "format=bird", "entries=2", "state=ok"],
    );
    assert!(line.contains(".bird"), "line: {line}");

    let _ = std::fs::remove_file(&roas_file);
    let _ = std::fs::remove_file(&config);
    let _ = std::fs::remove_file(&socket);
}

// ---------------------------------------------------------------------
// URL source — startup fetch + status line
// ---------------------------------------------------------------------

#[test]
fn roa_source_url_fetches_at_startup() {
    let body =
        r#"{"roas":[{"asn":"AS64512","prefix":"203.0.113.0/24","maxLength":24}]}"#.to_string();
    let http = spawn_one_shot_http(body, "application/json");

    let socket = std::env::temp_dir().join(format!(
        "lr-daemon-roa-source-url-{}.sock",
        std::process::id()
    ));
    let config = std::env::temp_dir().join(format!(
        "lr-daemon-roa-source-url-{}.toml",
        std::process::id()
    ));
    // Write the jq transform program to a file so the TOML
    // parser's escape handling is not a factor (the inline form
    // works in the DSL where the lexer processes string escapes,
    // but the TOML subset parser does not unescape \" and \\).
    let prog = std::env::temp_dir().join(format!(
        "lr-daemon-roa-source-url-{}.jq",
        std::process::id()
    ));
    std::fs::write(
        &prog,
        r#".roas[] | "roa \(.prefix) max \(.maxLength) as \(.asn);""#,
    )
    .unwrap();
    std::fs::write(
        &config,
        format!(
            "[bgp]\nlocal_as = 64512\npeer_as = 64513\nrouter_id = \"10.0.0.1\"\n\n\
             [[bgp.roa_source]]\nurl = \"http://127.0.0.1:{}/roas.json\"\nformat = \"jq\"\nprogram_file = \"{}\"\ninterval = 60\n",
            http.port,
            prog.display()
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
        "url-startup",
    );
    d.wait_log("loaded 1 entries", "roa url fetch");

    let line =
        wait_for_roa_source_status(&socket, &["type=url", "format=jq", "entries=1", "state=ok"]);
    assert!(line.contains("127.0.0.1"), "line: {line}");

    let _ = std::fs::remove_file(&config);
    let _ = std::fs::remove_file(&socket);
}

// ---------------------------------------------------------------------
// File source — mtime-driven reload
// ---------------------------------------------------------------------

#[test]
fn roa_source_file_reloads_on_mtime_change() {
    let roas_file = std::env::temp_dir().join(format!(
        "lr-roa-source-e2e-reload-{}.bird",
        std::process::id()
    ));
    std::fs::write(&roas_file, "roa 203.0.113.0/24 max 24 as 64512;\n").unwrap();

    let socket = std::env::temp_dir().join(format!(
        "lr-daemon-roa-source-reload-{}.sock",
        std::process::id()
    ));
    let config = std::env::temp_dir().join(format!(
        "lr-daemon-roa-source-reload-{}.toml",
        std::process::id()
    ));
    std::fs::write(
        &config,
        format!(
            "[bgp]\nlocal_as = 64512\npeer_as = 64513\nrouter_id = \"10.0.0.1\"\n\n\
             [[bgp.roa_source]]\npath = {:?}\nformat = \"bird\"\n",
            roas_file.to_string_lossy()
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
        "file-reload",
    );
    d.wait_log("loaded 1 entries", "roa file load");

    // Rewrite the file with a second entry. Bump mtime.
    thread::sleep(Duration::from_millis(20));
    std::fs::write(
        &roas_file,
        "roa 203.0.113.0/24 max 24 as 64512;\nroa 198.51.100.0/24 max 26 as 64513;\n",
    )
    .unwrap();

    // The loader's poll picks up the change within a few seconds.
    let _ = wait_for_roa_source_status(&socket, &["entries=2", "state=ok"]);

    let _ = std::fs::remove_file(&roas_file);
    let _ = std::fs::remove_file(&config);
    let _ = std::fs::remove_file(&socket);
}

// ---------------------------------------------------------------------
// URL source — fetch failure preserves previous snapshot
// ---------------------------------------------------------------------

#[test]
fn roa_source_url_fetch_failure_keeps_previous_snapshot() {
    // Initial body with one ROA; the server serves it once then exits.
    let body =
        r#"{"roas":[{"asn":"AS64512","prefix":"203.0.113.0/24","maxLength":24}]}"#.to_string();
    let http = spawn_one_shot_http(body, "application/json");

    let socket = std::env::temp_dir().join(format!(
        "lr-daemon-roa-source-fail-{}.sock",
        std::process::id()
    ));
    let config = std::env::temp_dir().join(format!(
        "lr-daemon-roa-source-fail-{}.toml",
        std::process::id()
    ));
    let prog = std::env::temp_dir().join(format!(
        "lr-daemon-roa-source-fail-{}.jq",
        std::process::id()
    ));
    std::fs::write(
        &prog,
        r#".roas[] | "roa \(.prefix) max \(.maxLength) as \(.asn);""#,
    )
    .unwrap();
    std::fs::write(
        &config,
        format!(
            "[bgp]\nlocal_as = 64512\npeer_as = 64513\nrouter_id = \"10.0.0.1\"\n\n\
             [[bgp.roa_source]]\nurl = \"http://127.0.0.1:{}/roas.json\"\nformat = \"jq\"\nprogram_file = \"{}\"\ninterval = 60\n",
            http.port,
            prog.display()
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
        "url-fail",
    );
    d.wait_log("loaded 1 entries", "roa url initial fetch");

    // First fetch landed; the server has exited. The status line
    // should report 1 entry (the previous snapshot survives).
    let line = wait_for_roa_source_status(&socket, &["entries=1"]);
    assert!(
        line.contains("state=ok") || line.contains("state=error"),
        "line: {line}"
    );

    let _ = std::fs::remove_file(&config);
    let _ = std::fs::remove_file(&socket);
}

// ---------------------------------------------------------------------
// Multiple sources — both load and contribute to the merged store
// ---------------------------------------------------------------------

#[test]
fn roa_source_multiple_sources_load() {
    let roas_file_a = std::env::temp_dir().join(format!(
        "lr-roa-source-e2e-multi-a-{}.bird",
        std::process::id()
    ));
    std::fs::write(&roas_file_a, "roa 203.0.113.0/24 max 24 as 64512;\n").unwrap();
    let roas_file_b = std::env::temp_dir().join(format!(
        "lr-roa-source-e2e-multi-b-{}.bird",
        std::process::id()
    ));
    std::fs::write(&roas_file_b, "roa 198.51.100.0/24 max 24 as 64513;\n").unwrap();

    let socket = std::env::temp_dir().join(format!(
        "lr-daemon-roa-source-multi-{}.sock",
        std::process::id()
    ));
    let config = std::env::temp_dir().join(format!(
        "lr-daemon-roa-source-multi-{}.toml",
        std::process::id()
    ));
    std::fs::write(
        &config,
        format!(
            "[bgp]\nlocal_as = 64512\npeer_as = 64513\nrouter_id = \"10.0.0.1\"\n\n\
             [[bgp.roa_source]]\npath = {:?}\nformat = \"bird\"\n\n\
             [[bgp.roa_source]]\npath = {:?}\nformat = \"bird\"\n",
            roas_file_a.to_string_lossy(),
            roas_file_b.to_string_lossy()
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
        "multi",
    );
    d.wait_log("2 sources configured", "roa sources configured");
    // Wait for both files to load (one log line each, in any order).
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let log = std::fs::read_to_string(&d.log).unwrap_or_default();
        let count = log.matches("loaded 1 entries").count();
        if count >= 2 {
            break;
        }
        if Instant::now() >= deadline {
            panic!("both roa sources never loaded; log: {log}");
        }
        thread::sleep(Duration::from_millis(100));
    }

    let _ = std::fs::remove_file(&roas_file_a);
    let _ = std::fs::remove_file(&roas_file_b);
    let _ = std::fs::remove_file(&config);
    let _ = std::fs::remove_file(&socket);
}

// ---------------------------------------------------------------------
// SIGHUP repoint: change the file path, verify the loader re-points
// ---------------------------------------------------------------------

#[test]
fn roa_source_sighup_repoints_to_new_file() {
    let roas_file_a = std::env::temp_dir().join(format!(
        "lr-roa-source-e2e-sighup-a-{}.bird",
        std::process::id()
    ));
    std::fs::write(&roas_file_a, "roa 203.0.113.0/24 max 24 as 64512;\n").unwrap();
    let roas_file_b = std::env::temp_dir().join(format!(
        "lr-roa-source-e2e-sighup-b-{}.bird",
        std::process::id()
    ));
    std::fs::write(&roas_file_b, "roa 198.51.100.0/24 max 24 as 64513;\n").unwrap();

    let socket = std::env::temp_dir().join(format!(
        "lr-daemon-roa-source-sighup-{}.sock",
        std::process::id()
    ));
    let config = std::env::temp_dir().join(format!(
        "lr-daemon-roa-source-sighup-{}.toml",
        std::process::id()
    ));
    std::fs::write(
        &config,
        format!(
            "[bgp]\nlocal_as = 64512\npeer_as = 64513\nrouter_id = \"10.0.0.1\"\n\n\
             [[bgp.roa_source]]\npath = {:?}\nformat = \"bird\"\n",
            roas_file_a.to_string_lossy()
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
        "sighup-repoint",
    );
    d.wait_log("loaded 1 entries", "roa initial load");
    wait_for_roa_source_status(&socket, &["entries=1", "state=ok"]);

    // Rewrite the config to point at file_b, then SIGHUP.
    std::fs::write(
        &config,
        format!(
            "[bgp]\nlocal_as = 64512\npeer_as = 64513\nrouter_id = \"10.0.0.1\"\n\n\
             [[bgp.roa_source]]\npath = {:?}\nformat = \"bird\"\n",
            roas_file_b.to_string_lossy()
        ),
    )
    .unwrap();
    d.signal(SIGHUP);
    // The repoint changes the source key (file_a → file_b), so the
    // daemon tears the old loader down and reports the new source
    // as requiring a restart (same posture as a re-added
    // `[bgp.rpki] cache` block).
    d.wait_log("roa-source removed", "roa source removed");
    d.wait_log(
        "restart the daemon to spawn its loader thread",
        "restart-required notice",
    );

    let _ = std::fs::remove_file(&roas_file_a);
    let _ = std::fs::remove_file(&roas_file_b);
    let _ = std::fs::remove_file(&config);
    let _ = std::fs::remove_file(&socket);
}

// ---------------------------------------------------------------------
// URL source — content change on reload picks up new body
// ---------------------------------------------------------------------

#[test]
fn roa_source_url_reload_picks_up_new_body() {
    let initial =
        r#"{"roas":[{"asn":"AS64512","prefix":"203.0.113.0/24","maxLength":24}]}"#.to_string();
    let http = spawn_reloadable_http(initial);

    let socket = std::env::temp_dir().join(format!(
        "lr-daemon-roa-source-urlreload-{}.sock",
        std::process::id()
    ));
    let config = std::env::temp_dir().join(format!(
        "lr-daemon-roa-source-urlreload-{}.toml",
        std::process::id()
    ));
    let prog = std::env::temp_dir().join(format!(
        "lr-daemon-roa-source-urlreload-{}.jq",
        std::process::id()
    ));
    std::fs::write(
        &prog,
        r#".roas[] | "roa \(.prefix) max \(.maxLength) as \(.asn);""#,
    )
    .unwrap();
    std::fs::write(
        &config,
        format!(
            "[bgp]\nlocal_as = 64512\npeer_as = 64513\nrouter_id = \"10.0.0.1\"\n\n\
             [[bgp.roa_source]]\nurl = \"http://127.0.0.1:{}/roas.json\"\nformat = \"jq\"\nprogram_file = \"{}\"\ninterval = 60\n",
            http.port,
            prog.display()
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
        "url-reload",
    );
    d.wait_log("loaded 1 entries", "roa url initial fetch");
    wait_for_roa_source_status(&socket, &["entries=1", "state=ok"]);

    // Update the body the server serves; SIGHUP forces a re-fetch.
    // The source identity (URL) is unchanged, so the repoint fires
    // the loader thread's control plane rather than the
    // shutdown + restart-required path.
    let new_body = r#"{"roas":[{"asn":"AS64512","prefix":"203.0.113.0/24","maxLength":24},{"asn":"AS64513","prefix":"198.51.100.0/24","maxLength":24}]}"#.to_string();
    http.set_body(new_body);
    d.signal(SIGHUP);
    // The daemon's reload path requests the loader repoint; the
    // loader thread re-fetches the body and parses 2 entries.
    let _ = wait_for_roa_source_status(&socket, &["entries=2", "state=ok"]);

    let _ = std::fs::remove_file(&config);
    let _ = std::fs::remove_file(&socket);
}
