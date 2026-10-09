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
use std::sync::{Arc, RwLock};

use lr_router::DefaultRouter;

/// Static daemon facts served by `status`.
///
/// Read by the platform-specific `spawn` implementation (Unix
/// domain socket on Unix, named pipe on Windows).
pub struct DaemonInfo {
    pub version: String,
    pub local_as: u32,
    pub peer_as: u32,
    pub router_id: String,
    pub config_path: Option<String>,
}

/// Everything the API thread needs to answer commands.
///
/// See [`DaemonInfo`] for the platform-specific use of these fields.
#[cfg_attr(not(any(unix, windows)), expect(dead_code))]
pub struct ApiContext {
    pub info: DaemonInfo,
    pub router: Arc<RwLock<DefaultRouter>>,
    pub running: Arc<AtomicBool>,
    /// Re-apply configuration (SIGHUP equivalent); returns the log
    /// lines describing what was (not) applied.
    pub reload: Box<dyn Fn() -> Vec<String> + Send + Sync>,
    /// Protocol-specific extra `status` lines (e.g. LDP adjacency /
    /// session / binding counters). Returns the lines verbatim.
    pub status_lines: Box<dyn Fn() -> Vec<String> + Send + Sync>,
    /// Daemon-wide graceful drain controller (issue #53). Wired by
    /// the daemon startup path; the API's `shutdown drain` and
    /// `shutdown status` commands delegate to it. `None` when the
    /// daemon does not expose drain (a library embedder wiring
    /// [`ApiContext`] by hand can leave this out and the API simply
    /// refuses `shutdown drain`).
    pub shutdown: Option<Arc<crate::shutdown::ShutdownController>>,
    /// Live ROA store (issue #52 follow-up — `lrctl roa list` /
    /// `show roa`). The BGP daemon populates this with the same
    /// `Arc<RoaStore>` the metrics endpoint already reads through
    /// [`crate::metrics::MetricsContext::roa_len`]; the RTR client
    /// thread swaps snapshots under it. `None` for daemon modes that
    /// have no ROA store (OSPF-only, Babel-only, BMP) — `show roa`
    /// then reports `roa-total 0` rather than a misleading "no
    /// data".
    pub roa_store: Option<Arc<lr_bgp::RoaStore>>,
}

#[cfg(unix)]
mod imp {
    use std::io::{BufRead, BufReader, BufWriter, Write};
    use std::os::unix::net::{UnixListener, UnixStream};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, RwLock};
    use std::thread;
    use std::time::Duration;

    use lr_router::{DefaultRouter, RouterInstance};

    use super::{ApiContext, DaemonInfo};

    /// The top MPLS label of a route's private label stack (the
    /// `LrMplsLabelStack` attribute BGP-LU and OSPF SR reception use),
    /// for the `routes` output. `None` for unlabelled routes.
    fn route_label(route: &lr_core::rib::Route) -> Option<u32> {
        let attr = route.attributes.get(lr_core::attr::AttrTag(
            lr_bgp::path::AttrType::LrMplsLabelStack.to_u8(),
        ))?;
        let stack = lr_mpls::LabelStack::decode_4octet(&attr.value).ok()?;
        stack.labels().first().map(|l| l.value)
    }

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
        let status_lines: Arc<dyn Fn() -> Vec<String> + Send + Sync> = Arc::from(ctx.status_lines);
        let shutdown = ctx.shutdown;
        let roa_store = ctx.roa_store;
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
                    let status_lines = Arc::clone(&status_lines);
                    let shutdown = shutdown.clone();
                    let roa_store = roa_store.clone();
                    let path_owned = path_owned.clone();
                    thread::Builder::new()
                        .name("lr-api-conn".into())
                        .spawn(move || {
                            // `shutdown` removes the socket file itself so
                            // the cleanup does not race the process exit.
                            let deps = ConnDeps {
                                info: &info,
                                router: &router,
                                running: &running,
                                reload: &reload,
                                status_lines: &status_lines,
                                shutdown: shutdown.as_ref(),
                                roa_store: roa_store.as_ref(),
                                started,
                                socket_path: Some(&path_owned),
                            };
                            serve_connection(stream, &deps);
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

    /// Shared state one API connection reads. Bundled so the serve
    /// function keeps a short parameter list as per-protocol surfaces
    /// grow (`status_lines`, …).
    struct ConnDeps<'a> {
        info: &'a DaemonInfo,
        router: &'a Arc<RwLock<DefaultRouter>>,
        running: &'a Arc<AtomicBool>,
        reload: &'a Arc<dyn Fn() -> Vec<String> + Send + Sync>,
        status_lines: &'a Arc<dyn Fn() -> Vec<String> + Send + Sync>,
        /// Daemon-wide graceful drain controller (issue #53). `None`
        /// when the daemon was started without a `[shutdown]` block
        /// (immediate mode); the API simply refuses `shutdown drain`
        /// in that case so the operator gets a clear "not configured"
        /// diagnostic instead of silent acceptance.
        shutdown: Option<&'a Arc<crate::shutdown::ShutdownController>>,
        /// Live ROA store for `show roa` (issue #52 follow-up). `None`
        /// on daemon modes without a ROA store (OSPF/Babel/BMP) — the
        /// renderer then reports `roa-total 0` instead of refusing.
        roa_store: Option<&'a Arc<lr_bgp::RoaStore>>,
        started: std::time::Instant,
        /// The `shutdown` command removes the socket file itself so the
        /// cleanup does not race the process exit.
        socket_path: Option<&'a str>,
    }

    /// One connection: read a command line, answer, repeat.
    fn serve_connection(stream: UnixStream, deps: &ConnDeps<'_>) {
        let _ = stream.set_read_timeout(Some(Duration::from_millis(250)));
        let Ok(write_half) = stream.try_clone() else {
            return;
        };
        let mut reader = BufReader::new(stream);
        // Buffer each command's response and push it with a single write
        // at the bottom of the loop: per-line write syscalls let a fast
        // reader observe a half-written response (the tarpaulin run hit
        // exactly that — `status` split after `local-as`, so the client's
        // "stop at the first quiet read" loop never saw `rib-entries`).
        let mut out = BufWriter::new(write_half);
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
                        if idle_rounds > 40 || !deps.running.load(Ordering::Relaxed) {
                            return; // ~10 s idle timeout or shutdown
                        }
                        // Defensive throttle: `set_read_timeout` is
                        // honored as 250 ms per call on Linux (giving
                        // the nominal 10 s idle window) but on macOS
                        // SO_RCVTIMEO is not applied to AF_UNIX socket
                        // reads the same way — `read_line` can return
                        // `WouldBlock` immediately, which would
                        // accumulate `idle_rounds` to the 40 cap in
                        // microseconds and close the connection out
                        // from under a slow client (the macOS CI leg
                        // of the new cross-platform matrix reproduced
                        // exactly that). Sleep briefly so the spin is
                        // bounded regardless of whether the kernel
                        // honors the timeout.
                        thread::sleep(Duration::from_millis(50));
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
                    let router_id = core::str::FromStr::from_str(&deps.info.router_id)
                        .unwrap_or(lr_core::addr::RouterId::from_u32(0));
                    // Copy the RIB snapshot and session summaries under the
                    // lock, then write the file outside it: disk I/O on a
                    // hung filesystem must not stall the router (BGP hold
                    // timers expire).
                    let (routes, summaries) = {
                        let r = deps.router.read().unwrap();
                        (
                            r.rib_paths_snapshot()
                                .into_iter()
                                .cloned()
                                .collect::<Vec<_>>(),
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
            // Issue #52 BIRD-style `show …` family. Delegated to the
            // shared `show` module so the Unix and Windows surfaces
            // render identically. `show` (no sub) maps to `show status`,
            // matching BIRD's `show` shortcut.
            if cmd == "show" || cmd.starts_with("show ") {
                let cx = crate::show::ShowCtx {
                    info: deps.info,
                    router: deps.router,
                    status_lines: deps.status_lines,
                    started: deps.started,
                };
                if let Some(body) = crate::show::dispatch(cmd, &cx) {
                    let _ = out.write_all(body.as_bytes());
                    if out.flush().is_err() {
                        return;
                    }
                    continue;
                }
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
                         show status            extended summary (per-protocol counts, memory)\n  \
                         show sessions [detail] per-session stats (transitions, uptime, last error)\n  \
                         show session <handle>  deep dive for one session\n  \
                         show routes count     Loc-RIB grouped by protocol\n  \
                         show memory           process RSS and virtual size\n  \
                         reload    re-apply configuration (SIGHUP equivalent)\n  \
                         shutdown           graceful shutdown (immediate)\n  \
                         shutdown drain     issue #53 graceful drain (rate-limited)\n  \
                         shutdown status    drain lifecycle (running | draining | drained)\n  \
                         shutdown abort     cancel a drain in progress (best-effort)\n  \
                         help      this text\n  \
                         quit      close this connection"
                    );
                }
                "status" => {
                    let (sessions, rib) = {
                        let r = deps.router.read().unwrap();
                        (r.session_summaries().len(), r.rib_len())
                    };
                    let _ = writeln!(out, "version {}", deps.info.version);
                    let _ = writeln!(out, "local-as {}", deps.info.local_as);
                    let _ = writeln!(out, "peer-as {}", deps.info.peer_as);
                    let _ = writeln!(out, "router-id {}", deps.info.router_id);
                    let _ = writeln!(
                        out,
                        "config {}",
                        deps.info.config_path.as_deref().unwrap_or("(none)")
                    );
                    let _ = writeln!(out, "uptime-secs {}", deps.started.elapsed().as_secs());
                    let _ = writeln!(out, "sessions {}", sessions);
                    let _ = writeln!(out, "rib-entries {}", rib);
                    for line in (deps.status_lines)() {
                        let _ = writeln!(out, "{line}");
                    }
                }
                "sessions" => {
                    let summaries = deps.router.read().unwrap().session_summaries();
                    for s in summaries {
                        let _ = writeln!(
                            out,
                            "#{handle} kind={kind} local-as={la} peer-as={pa} \
                             state={state} established={est} peer-id={id} \
                             hold-time={hold} adj-rib-in={ar} \
                             updates-rx={urx} updates-tx={utx}",
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
                            urx = s.updates_received,
                            utx = s.updates_sent,
                        );
                        // W6.3 exchange-plane (feature `exchange-plane`):
                        // per-session record stats — how many prefixes
                        // carry a verified record set from this peer and
                        // how many partial-transit sets arrived (design
                        // §7). Printed only when non-zero so the default
                        // output stays unchanged.
                        #[cfg(feature = "exchange-plane")]
                        {
                            let r = deps.router.read().unwrap();
                            let h = s.handle;
                            let records = r.exchange_plane_records(h).len();
                            let partial = r.exchange_plane_partial_transit(h);
                            if records > 0 || partial > 0 {
                                let _ = writeln!(
                                    out,
                                    "  exchange-plane: records={} partial-transit={}",
                                    records, partial
                                );
                            }
                        }
                    }
                }
                "routes" => {
                    // Hold the lock only for the dump: rib_paths_snapshot()
                    // borrows from the router. One line per path: with
                    // RFC 7911 Add-Path a prefix can hold several ranked
                    // paths, distinguished by their path identifiers.
                    // Labelled routes (RFC 8277 BGP-LU, RFC 8665 OSPF
                    // prefix-SIDs) append `label=<top>` — the MPLS
                    // label the kernel mirror installs, what `show
                    // mpls table` on FRR would print.
                    let r = deps.router.read().unwrap();
                    for route in r.rib_paths_snapshot() {
                        let _ = writeln!(
                            out,
                            "{} via {} proto={:?} metric={} path-id={}{}",
                            route.key.prefix,
                            route
                                .next_hop
                                .map(|n| n.to_string())
                                .unwrap_or_else(|| "(none)".to_string()),
                            route.protocol,
                            route.preference.metric,
                            route.path_id,
                            match route_label(route) {
                                Some(label) => format!(" label={label}"),
                                None => String::new(),
                            }
                        );
                    }
                }
                "reload" => {
                    for line in (deps.reload)() {
                        let _ = writeln!(out, "{}", line);
                    }
                }
                "shutdown" => {
                    // `shutdown` is the immediate path: flip `running`
                    // to false, remove the socket file, return. The
                    // daemon's main loop notices on its next poll and
                    // exits. The `shutdown drain` and
                    // `shutdown status` sub-commands are stripped off
                    // the command line first (see the prefix matches
                    // above the `match cmd` block).
                    deps.running.store(false, Ordering::Relaxed);
                    let _ = writeln!(out, "shutting down");
                    let _ = out.flush();
                    if let Some(path) = deps.socket_path {
                        let _ = std::fs::remove_file(path);
                    }
                    return;
                }
                other if other.starts_with("shutdown ") => {
                    // Issue #53 daemon-wide graceful drain sub-commands.
                    // Strip the `shutdown ` prefix and dispatch the
                    // remainder: `drain` enters the drain state machine;
                    // `status` queries the lifecycle without changing
                    // it. Any other sub-command is an error so a
                    // typo'd `shutdown drain2` is loud, not silent.
                    let sub = other["shutdown ".len()..].trim();
                    match sub {
                        "drain" => {
                            let Some(ctrl) = deps.shutdown else {
                                let _ = writeln!(
                                    out,
                                    "error: drain not configured \
                                     (set [shutdown] mode = \"drain\" \
                                     and restart, or use plain `shutdown` \
                                     for immediate exit)"
                                );
                                let _ = out.flush();
                                continue;
                            };
                            let started = Arc::clone(ctrl)
                                .begin_drain(Arc::clone(deps.router), Arc::clone(deps.running));
                            if started {
                                let _ = writeln!(
                                    out,
                                    "drain started (state=draining); \
                                     use `shutdown status` to poll"
                                );
                            } else {
                                let _ = writeln!(
                                    out,
                                    "drain already in progress \
                                     (state={})",
                                    ctrl.state().as_str()
                                );
                            }
                        }
                        "status" => {
                            let Some(ctrl) = deps.shutdown else {
                                let _ = writeln!(out, "drain not configured (immediate mode)");
                                let _ = out.flush();
                                continue;
                            };
                            let remaining = ctrl.routes_remaining(deps.router);
                            let _ = writeln!(
                                out,
                                "state={} remaining={}",
                                ctrl.state().as_str(),
                                remaining
                            );
                        }
                        "abort" => {
                            let Some(ctrl) = deps.shutdown else {
                                let _ = writeln!(out, "drain not configured (immediate mode)");
                                let _ = out.flush();
                                continue;
                            };
                            // Abort is best-effort: the worker notices
                            // on its next iteration and exits without
                            // further work. Report the before-abort
                            // state — that's what an operator
                            // inspecting the log wants to see, since
                            // after the call the state is always
                            // `running`.
                            let before = ctrl.state();
                            ctrl.abort();
                            let _ = writeln!(
                                out,
                                "drain aborted (was {}, now running); \
                                 {} routes still queued",
                                before.as_str(),
                                ctrl.routes_remaining(deps.router)
                            );
                        }
                        other => {
                            let _ = writeln!(
                                out,
                                "error: unknown shutdown sub-command '{other}' \
                                 (try 'drain', 'status' or 'abort')"
                            );
                        }
                    }
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

        fn test_ctx(router: Arc<RwLock<DefaultRouter>>, running: Arc<AtomicBool>) -> ApiContext {
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
                status_lines: Box::new(Vec::new),
                shutdown: None,
                roa_store: None,
            }
        }

        #[test]
        fn api_serves_status_sessions_routes_and_shutdown() {
            let dir = std::env::temp_dir().join(format!("lr-api-test-{}", std::process::id()));
            std::fs::create_dir_all(&dir).unwrap();
            let path = dir.join("daemon.api");
            let path_str = path.to_str().unwrap().to_string();

            let router = Arc::new(RwLock::new(DefaultRouter::new()));
            {
                let mut r = router.write().unwrap();
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

            // Issue #52 BIRD-style `show` family — covered end-to-end
            // over the same Unix socket the daemon ships in production.
            let show_status = ask(&mut probe, "show status");
            assert!(
                show_status.contains("sessions 1 established 0"),
                "show status: {show_status}"
            );
            assert!(show_status.contains("kind=bgp total=1 established=0"));
            assert!(show_status.contains("memory rss-bytes="));

            let show_sessions = ask(&mut probe, "show sessions");
            assert!(
                show_sessions.contains("kind=bgp"),
                "show sessions: {show_sessions}"
            );
            assert!(show_sessions.contains("transitions="));
            assert!(show_sessions.contains("uptime-ms="));
            assert!(show_sessions.contains("last-error="));

            let show_sessions_detail = ask(&mut probe, "show sessions detail");
            assert!(
                show_sessions_detail.contains("stats: established-at-ms="),
                "show sessions detail: {show_sessions_detail}"
            );

            let show_session_handle = ask(&mut probe, "show session 1");
            assert!(
                show_session_handle.contains("handle 1"),
                "show session 1: {show_session_handle}"
            );
            assert!(show_session_handle.contains("kind bgp"));
            assert!(show_session_handle.contains("negotiated-hold-time"));

            let show_session_unknown = ask(&mut probe, "show session 999");
            assert!(
                show_session_unknown.contains("error: no session with handle 999"),
                "show session unknown: {show_session_unknown}"
            );

            let show_routes_count = ask(&mut probe, "show routes count");
            assert!(
                show_routes_count.contains("total 1"),
                "show routes count: {show_routes_count}"
            );
            assert!(show_routes_count.contains("proto="));

            let show_memory = ask(&mut probe, "show memory");
            assert!(
                show_memory.contains("uptime-secs "),
                "show memory: {show_memory}"
            );
            assert!(show_memory.contains("rss-bytes "));
            assert!(show_memory.contains("vsize-bytes "));

            let show_unknown = ask(&mut probe, "show bogus");
            assert!(
                show_unknown.contains("error: unknown show sub-command 'bogus'"),
                "show bogus: {show_unknown}"
            );

            let unknown = ask(&mut probe, "bogus");
            assert!(unknown.contains("error: unknown command"));

            let help = ask(&mut probe, "help");
            assert!(help.contains("shutdown"));
            assert!(help.contains("show status"));
            assert!(help.contains("show session <handle>"));
            assert!(help.contains("show routes count"));

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
#[path = "api_imp_windows.rs"]
mod imp;

#[cfg(unix)]
pub use imp::spawn;

#[cfg(not(unix))]
pub use imp::spawn;
