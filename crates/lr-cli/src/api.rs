//! Runtime API for `lr-daemon` — operational visibility over a Unix
//! stream socket (the BIRD control-socket / FRR vty pattern, kept
//! deliberately minimal).
//!
//! The daemon exposes a line-oriented command protocol:
//!
//! ```text
//! $ socat - UNIX-CONNECT:/run/lr-daemon.api
//! status
//! version 0.1.0
//! local-as 64512
//! ...
//! sessions
//! #1 kind=bgp local-as=64512 peer-as=64513 state=Established ...
//! routes
//! 203.0.113.0/24 via 192.0.2.1 proto=Bgp metric=0
//! shutdown
//! shutting down
//! ```
//!
//! One command per line; the connection stays open until `quit` or EOF.
//! A stale socket file (left over from an unclean shutdown) is unlinked
//! before binding, and the socket is restricted to its owner (0600).
//!
//! The server thread never holds the router lock while blocking on I/O:
//! it locks only for the duration of a single command.
//!
//! The context types are platform-independent data; only the transport
//! (`spawn` and friends) is Unix-specific. Platforms without Unix domain
//! sockets compile the same caller code against the same types and get a
//! clear refusal at startup instead of a pretend API.

use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex};

use lr_router::DefaultRouter;

/// Static daemon facts served by `status`.
///
/// The fields are only read by the Unix server below; on other targets
/// the type exists so callers compile unchanged (`spawn` refuses there).
#[cfg_attr(not(unix), expect(dead_code))]
pub struct DaemonInfo {
    pub version: String,
    pub local_as: u32,
    pub peer_as: u32,
    pub router_id: String,
    pub config_path: Option<String>,
}

/// Everything the API thread needs to answer commands.
///
/// See [`DaemonInfo`] for why some fields are unread on non-Unix targets.
#[cfg_attr(not(unix), expect(dead_code))]
pub struct ApiContext {
    pub info: DaemonInfo,
    pub router: Arc<Mutex<DefaultRouter>>,
    pub running: Arc<AtomicBool>,
    /// Re-apply configuration (SIGHUP equivalent); returns the log
    /// lines describing what was (not) applied.
    pub reload: Box<dyn Fn() -> Vec<String> + Send + Sync>,
}

#[cfg(unix)]
mod imp {
    use std::io::{BufRead, BufReader, Write};
    use std::os::unix::net::{UnixListener, UnixStream};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex};
    use std::thread;
    use std::time::Duration;

    use lr_router::{DefaultRouter, RouterInstance};

    use super::{ApiContext, DaemonInfo};

    // `Read` is only needed by the test helper below.
    #[cfg(test)]
    use std::io::Read as _;

    extern "C" {
        fn chmod(path: *const std::ffi::c_char, mode: u32) -> i32;
    }

    fn chmod_0600(path: &str) {
        if let Ok(c) = std::ffi::CString::new(path) {
            // Best effort: management access is also guarded by the
            // socket directory's permissions.
            unsafe { chmod(c.as_ptr(), 0o600) };
        }
    }

    /// Bind the API socket and spawn the serving thread. Returns the
    /// canonical path on success.
    pub fn spawn(path: &str, ctx: ApiContext) -> Result<String, String> {
        // A socket file from an unclean shutdown would make bind fail
        // with EADDRINUSE; stale sockets are never clients.
        let _ = std::fs::remove_file(path);
        let listener = UnixListener::bind(path).map_err(|e| format!("bind {path}: {e}"))?;
        chmod_0600(path);
        listener
            .set_nonblocking(true)
            .map_err(|e| format!("nonblocking {path}: {e}"))?;

        let path_owned = path.to_string();
        let info = Arc::new(ctx.info);
        let router = Arc::clone(&ctx.router);
        let running = Arc::clone(&ctx.running);
        let reload: Arc<dyn Fn() -> Vec<String> + Send + Sync> = Arc::from(ctx.reload);
        let started = std::time::Instant::now();

        thread::Builder::new()
            .name("lr-api".into())
            .spawn(move || {
                accept_loop(&listener, &running, |stream| {
                    // Serve each connection on its own thread so a slow or
                    // idle client cannot hold the management socket hostage.
                    let info = Arc::clone(&info);
                    let router = Arc::clone(&router);
                    let running = Arc::clone(&running);
                    let reload = Arc::clone(&reload);
                    let started = started;
                    let path_owned = path_owned.clone();
                    thread::Builder::new()
                        .name("lr-api-conn".into())
                        .spawn(move || {
                            // `shutdown` removes the socket file itself so
                            // the cleanup does not race the process exit.
                            serve_connection(
                                stream,
                                &info,
                                &router,
                                &running,
                                &reload,
                                started,
                                Some(&path_owned),
                            );
                        })
                        .ok();
                });
                let _ = std::fs::remove_file(&path_owned);
            })
            .map_err(|e| format!("spawn api thread: {e}"))?;
        Ok(path.to_string())
    }

    /// Poll the listener until the daemon stops; hand live connections
    /// to `on_conn`.
    fn accept_loop(
        listener: &UnixListener,
        running: &AtomicBool,
        mut on_conn: impl FnMut(UnixStream),
    ) {
        while running.load(Ordering::Relaxed) {
            match listener.accept() {
                Ok((stream, _)) => on_conn(stream),
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(100));
                }
                Err(_) => thread::sleep(Duration::from_millis(100)),
            }
        }
    }

    /// One connection: read a command line, answer, repeat.
    /// `socket_path` lets the `shutdown` command remove the socket file
    /// synchronously (the accept loop's cleanup may race process exit).
    fn serve_connection(
        stream: UnixStream,
        info: &DaemonInfo,
        router: &Arc<Mutex<DefaultRouter>>,
        running: &Arc<AtomicBool>,
        reload: &Arc<dyn Fn() -> Vec<String> + Send + Sync>,
        started: std::time::Instant,
        socket_path: Option<&str>,
    ) {
        let _ = stream.set_read_timeout(Some(Duration::from_millis(250)));
        let Ok(write_half) = stream.try_clone() else {
            return;
        };
        let mut reader = BufReader::new(stream);
        let mut out = write_half;
        let mut line = String::new();
        loop {
            line.clear();
            // Tolerate idle clients without blocking shutdown forever:
            // read timeouts return 0 bytes; check `running` between tries.
            // Cap the command length so a slow-drip client cannot grow
            // the line unboundedly.
            const MAX_CMD: usize = 4096;
            let mut idle_rounds = 0;
            let mut n = 0usize;
            loop {
                match reader.read_line(&mut line) {
                    Ok(0) => break, // EOF
                    Ok(read) => {
                        n += read;
                        if line.ends_with('\n') || n >= MAX_CMD {
                            break;
                        }
                    }
                    Err(e)
                        if e.kind() == std::io::ErrorKind::WouldBlock
                            || e.kind() == std::io::ErrorKind::TimedOut =>
                    {
                        idle_rounds += 1;
                        if idle_rounds > 40 || !running.load(Ordering::Relaxed) {
                            return; // ~10 s idle timeout or shutdown
                        }
                    }
                    Err(_) => return,
                }
            }
            if n == 0 {
                return; // EOF
            }
            if n >= MAX_CMD && !line.ends_with('\n') {
                let _ = writeln!(out, "error: command too long");
                let _ = out.flush();
                continue; // discard the oversized line
            }
            let cmd = line.trim();
            if cmd.is_empty() {
                continue;
            }
            // Argument-bearing command: `mrt <path>` writes a dump of
            // the current Loc-RIB (RFC 6396 TABLE_DUMP_V2).
            if let Some(path) = cmd.strip_prefix("mrt ") {
                let path = path.trim();
                if path.is_empty() {
                    let _ = writeln!(out, "usage: mrt <path>");
                } else {
                    let router_id = core::str::FromStr::from_str(&info.router_id)
                        .unwrap_or(lr_core::addr::RouterId::from_u32(0));
                    // Copy the RIB snapshot and session summaries under the
                    // lock, then write the file outside it: disk I/O on a
                    // hung filesystem must not stall the router (BGP hold
                    // timers expire).
                    let (routes, summaries) = {
                        let r = router.lock().unwrap();
                        (
                            r.rib_paths_snapshot().into_iter().cloned().collect::<Vec<_>>(),
                            r.session_summaries(),
                        )
                    };
                    let records = crate::write_mrt_rib_dump(&routes, &summaries, router_id, path);
                    match records {
                        Ok(n) => {
                            let _ = writeln!(out, "mrt-dump {path} records={n}");
                        }
                        Err(e) => {
                            let _ = writeln!(out, "mrt-dump failed: {e}");
                        }
                    }
                }
                if out.flush().is_err() {
                    return;
                }
                continue;
            }
            match cmd {
                "quit" => return,
                "help" => {
                    let _ = writeln!(
                        out,
                        "commands:\n  \
                         status    daemon summary (version, identity, uptime, counters)\n  \
                         sessions  one line per configured session\n  \
                         routes    Loc-RIB dump (one route per line)\n  \
                         mrt PATH  write the Loc-RIB as an MRT dump (RFC 6396)\n  \
                         reload    re-apply configuration (SIGHUP equivalent)\n  \
                         shutdown  graceful shutdown\n  \
                         help      this text\n  \
                         quit      close this connection"
                    );
                }
                "status" => {
                    let (sessions, rib) = {
                        let r = router.lock().unwrap();
                        (r.session_summaries().len(), r.rib_len())
                    };
                    let _ = writeln!(out, "version {}", info.version);
                    let _ = writeln!(out, "local-as {}", info.local_as);
                    let _ = writeln!(out, "peer-as {}", info.peer_as);
                    let _ = writeln!(out, "router-id {}", info.router_id);
                    let _ = writeln!(
                        out,
                        "config {}",
                        info.config_path.as_deref().unwrap_or("(none)")
                    );
                    let _ = writeln!(out, "uptime-secs {}", started.elapsed().as_secs());
                    let _ = writeln!(out, "sessions {}", sessions);
                    let _ = writeln!(out, "rib-entries {}", rib);
                }
                "sessions" => {
                    let summaries = router.lock().unwrap().session_summaries();
                    for s in summaries {
                        let _ = writeln!(
                            out,
                            "#{handle} kind={kind} local-as={la} peer-as={pa} \
                             state={state} established={est} peer-id={id} \
                             hold-time={hold} adj-rib-in={ar}",
                            handle = s.handle.0,
                            kind = s.kind,
                            la = s.local_as.0,
                            pa = s.peer_as.0,
                            state = s.state,
                            est = s.established,
                            id = s
                                .peer_bgp_id
                                .map(|i| i.to_string())
                                .unwrap_or_else(|| "-".into()),
                            hold = s.negotiated_hold_time,
                            ar = s.adj_rib_in_len,
                        );
                    }
                }
                "routes" => {
                    // Hold the lock only for the dump: rib_paths_snapshot()
                    // borrows from the router. One line per path: with
                    // RFC 7911 Add-Path a prefix can hold several ranked
                    // paths, distinguished by their path identifiers.
                    let r = router.lock().unwrap();
                    for route in r.rib_paths_snapshot() {
                        let _ = writeln!(
                            out,
                            "{} via {} proto={:?} metric={} path-id={}",
                            route.key.prefix,
                            route
                                .next_hop
                                .map(|n| n.to_string())
                                .unwrap_or_else(|| "(none)".to_string()),
                            route.protocol,
                            route.preference.metric,
                            route.path_id
                        );
                    }
                }
                "reload" => {
                    for line in reload() {
                        let _ = writeln!(out, "{}", line);
                    }
                }
                "shutdown" => {
                    running.store(false, Ordering::Relaxed);
                    let _ = writeln!(out, "shutting down");
                    if let Some(path) = socket_path {
                        let _ = std::fs::remove_file(path);
                    }
                    return;
                }
                other => {
                    let _ = writeln!(out, "error: unknown command '{other}' (try 'help')");
                }
            }
            if out.flush().is_err() {
                return;
            }
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        fn test_ctx(router: Arc<Mutex<DefaultRouter>>, running: Arc<AtomicBool>) -> ApiContext {
            ApiContext {
                info: DaemonInfo {
                    version: "test".into(),
                    local_as: 64512,
                    peer_as: 64513,
                    router_id: "10.0.0.1".into(),
                    config_path: None,
                },
                router,
                running,
                reload: Box::new(|| vec!["reloaded".into()]),
            }
        }

        #[test]
        fn api_serves_status_sessions_routes_and_shutdown() {
            let dir = std::env::temp_dir().join(format!("lr-api-test-{}", std::process::id()));
            std::fs::create_dir_all(&dir).unwrap();
            let path = dir.join("daemon.api");
            let path_str = path.to_str().unwrap().to_string();

            let router = Arc::new(Mutex::new(DefaultRouter::new()));
            {
                let mut r = router.lock().unwrap();
                r.add_session(lr_router::SessionConfig::bgp(
                    lr_core::addr::Asn(64512),
                    lr_core::addr::Asn(64513),
                    lr_core::addr::RouterId::from_v4([10, 0, 0, 1]),
                ))
                .unwrap();
                r.originate(
                    lr_core::addr::Prefix::new_v4([203, 0, 113, 0], 24),
                    Some(lr_core::addr::IpAddr::V4([192, 0, 2, 1])),
                );
            }
            let running = Arc::new(AtomicBool::new(true));

            spawn(
                &path_str,
                test_ctx(Arc::clone(&router), Arc::clone(&running)),
            )
            .expect("api server spawns");

            let mut conn = UnixStream::connect(&path_str).expect("connect");
            let mut probe = conn.try_clone().unwrap();

            let ask = |conn: &mut UnixStream, cmd: &str| -> String {
                conn.write_all(format!("{cmd}\n").as_bytes()).unwrap();
                conn.flush().unwrap();
                // Poll for the response with a timeout — robust under
                // CI load where the original fixed 100ms sleep was
                // too short. Read in a loop until the socket has no
                // more data (non-blocking read returns WouldBlock).
                use std::io::ErrorKind;
                let deadline = std::time::Instant::now() + Duration::from_secs(5);
                let mut buf = Vec::new();
                conn.set_nonblocking(true).unwrap();
                loop {
                    let mut chunk = [0u8; 4096];
                    match conn.read(&mut chunk) {
                        Ok(0) => break,
                        Ok(n) => buf.extend_from_slice(&chunk[..n]),
                        Err(ref e) if e.kind() == ErrorKind::WouldBlock => {
                            if !buf.is_empty() || std::time::Instant::now() >= deadline {
                                break;
                            }
                            thread::sleep(Duration::from_millis(20));
                        }
                        Err(_) => break,
                    }
                }
                conn.set_nonblocking(false).unwrap();
                String::from_utf8_lossy(&buf).into_owned()
            };

            let status = ask(&mut conn, "status");
            assert!(status.contains("version test"), "status: {status}");
            assert!(status.contains("local-as 64512"));
            assert!(status.contains("rib-entries 1"));

            // New connection per command (read_to_end above drained the
            // first one); reuse of `probe` for a second round.
            let sessions = ask(&mut probe, "sessions");
            assert!(sessions.contains("kind=bgp"), "sessions: {sessions}");
            assert!(sessions.contains("state=Idle"));

            let routes = ask(&mut probe, "routes");
            assert!(routes.contains("203.0.113.0/24"), "routes: {routes}");

            let unknown = ask(&mut probe, "bogus");
            assert!(unknown.contains("error: unknown command"));

            let help = ask(&mut probe, "help");
            assert!(help.contains("shutdown"));

            // Shutdown flips the daemon's running flag.
            let shutting = ask(&mut probe, "shutdown");
            assert!(shutting.contains("shutting down"));
            let deadline = std::time::Instant::now() + Duration::from_secs(5);
            while running.load(Ordering::Relaxed) && std::time::Instant::now() < deadline {
                thread::sleep(Duration::from_millis(50));
            }
            assert!(
                !running.load(Ordering::Relaxed),
                "shutdown must stop the daemon"
            );

            let _ = std::fs::remove_dir_all(&dir);
        }
    }
}

#[cfg(not(unix))]
mod imp {
    use super::ApiContext;

    /// Unix domain sockets are the transport; other platforms get a
    /// clear refusal instead of a pretend API.
    pub fn spawn(_path: &str, _ctx: ApiContext) -> Result<String, String> {
        Err("runtime API requires Unix domain sockets (not supported here)".to_string())
    }
}

pub use imp::spawn;
