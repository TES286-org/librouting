//! Windows implementation — runtime API over a named pipe
//! (`\\.\pipe\<name>`), the Windows analogue of a Unix domain socket.
//!
//! The same line-oriented command protocol runs over the pipe:
//! `status` / `sessions` / `routes` / `reload` / `shutdown` / `help`.
//! One server thread creates pipe instances and hands live client
//! connections off to per-connection worker threads, mirroring the
//! Unix `UnixListener::accept` loop.
//!
//! ## Why named pipes (not TCP)
//!
//! Named pipes are the closest Windows analogue of Unix domain
//! sockets: they live in their own kernel namespace
//! (`\\.\pipe\<name>`), support in-process and cross-process
//! communication without a network stack, and carry a Windows
//! security descriptor the operator can scope to specific accounts
//! (the Unix `chmod 0600` parity). TCP would require port
//! allocation, expose the management surface to the network stack,
//! and add an authentication requirement that does not exist on the
//! Unix side — named pipes are the right primitive for the
//! management channel on Windows.

use std::io::{self, BufRead, BufReader, BufWriter, Read, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, RwLock};
use std::thread;
use std::time::Duration;

use lr_router::{DefaultRouter, RouterInstance};

use windows_sys::Win32::Foundation::{
    CloseHandle, DuplicateHandle, GetLastError, DUPLICATE_SAME_ACCESS, ERROR_BROKEN_PIPE,
    ERROR_PIPE_CONNECTED, HANDLE, INVALID_HANDLE_VALUE,
};
use windows_sys::Win32::Storage::FileSystem::{
    FlushFileBuffers, ReadFile, WriteFile, PIPE_ACCESS_DUPLEX,
};
use windows_sys::Win32::System::Pipes::{
    ConnectNamedPipe, CreateNamedPipeW, DisconnectNamedPipe, PeekNamedPipe, PIPE_TYPE_BYTE,
    PIPE_UNLIMITED_INSTANCES, PIPE_WAIT,
};
use windows_sys::Win32::System::Threading::GetCurrentProcess;

use super::{ApiContext, DaemonInfo};

/// Named-pipe handles are safe to move between threads — the kernel
/// handles the synchronization. `HANDLE` is `*mut c_void` which is
/// not `Send` by default; we store the handle as `isize` (the same
/// bit pattern) and cast to `HANDLE` at the FFI boundary, mirroring
/// the original hand-rolled approach.
unsafe impl Send for NamedPipeStream {}

/// `route_label` — same as the Unix side; defined here so the
/// `routes` command's output is byte-identical across platforms.
fn route_label(route: &lr_core::rib::Route) -> Option<u32> {
    let attr = route.attributes.get(lr_core::attr::AttrTag(
        lr_bgp::path::AttrType::LrMplsLabelStack.to_u8(),
    ))?;
    let stack = lr_mpls::LabelStack::decode_4octet(&attr.value).ok()?;
    stack.labels().first().map(|l| l.value)
}

// ---------------------------------------------------------------------------
// NamedPipeStream — Read/Write wrapper over a raw pipe handle
// ---------------------------------------------------------------------------

/// One end of an established named-pipe connection. `Read` and
/// `Write` delegate to `ReadFile`/`WriteFile` on the underlying
/// handle. The handle is closed when the stream is dropped.
struct NamedPipeStream {
    handle: isize,
}

impl NamedPipeStream {
    fn new(handle: isize) -> Self {
        Self { handle }
    }

    /// Duplicate the underlying handle (the Windows analogue of
    /// `UnixStream::try_clone`). Used by `serve_connection` to give
    /// the BufReader and BufWriter independent owned handles so the
    /// borrow checker accepts the read+write loop.
    fn try_clone(&self) -> io::Result<NamedPipeStream> {
        let mut new_handle: isize = 0;
        let current = unsafe { GetCurrentProcess() };
        let rc = unsafe {
            DuplicateHandle(
                current,
                self.handle as HANDLE,
                current,
                &mut new_handle as *mut isize as *mut HANDLE,
                0,
                1, // TRUE — inherit handle
                DUPLICATE_SAME_ACCESS,
            )
        };
        if rc == 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(NamedPipeStream { handle: new_handle })
        }
    }

    /// Switch the pipe between blocking and non-blocking mode.
    ///
    /// Kept as a no-op stub for structural parity with the Unix
    /// side's `set_nonblocking` call sites, but the non-blocking
    /// behaviour now lives in the `Read` impl: it probes the pipe
    /// with `PeekNamedPipe` and returns `WouldBlock` when no bytes
    /// are buffered. The legacy `PIPE_NOWAIT` mode it used to set
    /// fails with `ERROR_PIPE_BUSY` on some pipe handles, so the mode
    /// switch is no longer the mechanism — the `Read` impl is.
    #[allow(dead_code)]
    fn set_nonblocking(&self, _on: bool) -> io::Result<()> {
        Ok(())
    }
}

impl Read for NamedPipeStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        // Probe the pipe's input buffer without blocking — the modern
        // alternative to the legacy `PIPE_NOWAIT` mode (which fails
        // with `ERROR_PIPE_BUSY` on some pipe handles).
        // `PeekNamedPipe` returns immediately with the number of bytes
        // the next `ReadFile` would yield; 0 means the read would
        // block, which surfaces as `WouldBlock` so the caller's
        // idle-rounds loop can poll on its own cadence.
        let mut available: u32 = 0;
        let rc = unsafe {
            PeekNamedPipe(
                self.handle as HANDLE,
                std::ptr::null_mut(),
                0,
                std::ptr::null_mut(),
                &mut available,
                std::ptr::null_mut(),
            )
        };
        if rc == 0 {
            let err = io::Error::last_os_error();
            // ERROR_BROKEN_PIPE is EOF on a named pipe.
            if err.raw_os_error() == Some(ERROR_BROKEN_PIPE as i32) {
                return Ok(0);
            }
            return Err(err);
        }
        if available == 0 {
            return Err(io::Error::from(io::ErrorKind::WouldBlock));
        }
        // Data is buffered — `ReadFile` returns immediately with up
        // to `buf.len()` of it.
        let mut bytes_read: u32 = 0;
        let rc = unsafe {
            ReadFile(
                self.handle as HANDLE,
                buf.as_mut_ptr(),
                buf.len() as u32,
                &mut bytes_read,
                std::ptr::null_mut(),
            )
        };
        if rc == 0 {
            let err = io::Error::last_os_error();
            if err.raw_os_error() == Some(ERROR_BROKEN_PIPE as i32) {
                return Ok(0);
            }
            return Err(err);
        }
        Ok(bytes_read as usize)
    }
}

impl Write for NamedPipeStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let mut bytes_written: u32 = 0;
        let rc = unsafe {
            WriteFile(
                self.handle as HANDLE,
                buf.as_ptr(),
                buf.len() as u32,
                &mut bytes_written,
                std::ptr::null_mut(),
            )
        };
        if rc == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(bytes_written as usize)
    }

    fn flush(&mut self) -> io::Result<()> {
        let rc = unsafe { FlushFileBuffers(self.handle as HANDLE) };
        if rc == 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }
}

impl Drop for NamedPipeStream {
    fn drop(&mut self) {
        // Best-effort cleanup; the handle is going away with the
        // stream either way.
        unsafe {
            let _ = DisconnectNamedPipe(self.handle as HANDLE);
            let _ = CloseHandle(self.handle as HANDLE);
        }
    }
}

// ---------------------------------------------------------------------------
// Spawn + accept loop + per-connection serve (mirrors the Unix side)
// ---------------------------------------------------------------------------

/// Bind the named pipe and spawn the serving thread. `path` is the
/// pipe name the operator configures via `api_socket` / `--api-socket`;
/// [`crate::pipe_name::normalize_pipe_name`] maps the Unix-style
/// default (`/run/lr-daemon.api`) to a valid `\\.\pipe\<name>` so the
/// same config works on every platform.
pub fn spawn(path: &str, ctx: ApiContext) -> Result<String, String> {
    let pipe_name = crate::pipe_name::normalize_pipe_name(path);
    let name_wide: Vec<u16> = pipe_name.encode_utf16().chain(std::iter::once(0)).collect();

    let info = Arc::new(ctx.info);
    let router = Arc::clone(&ctx.router);
    let running = Arc::clone(&ctx.running);
    let reload: Arc<dyn Fn() -> Vec<String> + Send + Sync> = Arc::from(ctx.reload);
    let status_lines: Arc<dyn Fn() -> Vec<String> + Send + Sync> = Arc::from(ctx.status_lines);
    let shutdown = ctx.shutdown;
    let roa_store = ctx.roa_store;
    let started = std::time::Instant::now();
    let path_owned = pipe_name.clone();

    // Pre-create the first pipe instance so a bind failure shows up
    // at startup, not on the first client connect.
    let probe = unsafe {
        CreateNamedPipeW(
            name_wide.as_ptr(),
            PIPE_ACCESS_DUPLEX,
            PIPE_TYPE_BYTE | PIPE_WAIT,
            PIPE_UNLIMITED_INSTANCES,
            65536,
            65536,
            0,
            std::ptr::null(),
        ) as isize
    };
    if probe == INVALID_HANDLE_VALUE as isize {
        let err = unsafe { GetLastError() };
        return Err(format!(
            "bind {pipe_name}: CreateNamedPipeW failed (error {err})"
        ));
    }

    thread::Builder::new()
        .name("lr-api".into())
        .spawn(move || {
            accept_loop(probe, &name_wide, &running, |stream| {
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
        })
        .map_err(|e| format!("spawn api thread: {e}"))?;
    Ok(path.to_string())
}

/// Poll the named pipe for new connections. Hands live client
/// connections to `on_conn`. The first pipe instance is pre-created
/// by [`spawn`]; subsequent instances are created here after each
/// accept, so the next client can connect immediately.
fn accept_loop(
    mut first_handle: isize,
    name_wide: &[u16],
    running: &AtomicBool,
    mut on_conn: impl FnMut(NamedPipeStream),
) {
    while running.load(Ordering::Relaxed) {
        let handle = first_handle;
        // Wait for a client to connect. Blocks until a client opens
        // the pipe or the daemon stops; the latter is noticed on the
        // next loop iteration after the client disconnects.
        let connected = unsafe { ConnectNamedPipe(handle as HANDLE, std::ptr::null_mut()) };
        if connected == 0 {
            let err = unsafe { GetLastError() };
            if err != ERROR_PIPE_CONNECTED {
                // Anything other than the benign "already connected"
                // race: close the handle, sleep briefly to avoid a
                // busy loop, and recreate the pipe instance.
                unsafe { CloseHandle(handle as HANDLE) };
                thread::sleep(Duration::from_millis(100));
                first_handle = unsafe {
                    CreateNamedPipeW(
                        name_wide.as_ptr(),
                        PIPE_ACCESS_DUPLEX,
                        PIPE_TYPE_BYTE | PIPE_WAIT,
                        PIPE_UNLIMITED_INSTANCES,
                        65536,
                        65536,
                        0,
                        std::ptr::null(),
                    ) as isize
                };
                if first_handle == INVALID_HANDLE_VALUE as isize {
                    thread::sleep(Duration::from_millis(100));
                }
                continue;
            }
        }
        // The client is connected; hand the stream off and create a
        // fresh pipe instance for the next client.
        let stream = NamedPipeStream::new(handle);
        first_handle = unsafe {
            CreateNamedPipeW(
                name_wide.as_ptr(),
                PIPE_ACCESS_DUPLEX,
                PIPE_TYPE_BYTE | PIPE_WAIT,
                PIPE_UNLIMITED_INSTANCES,
                65536,
                65536,
                0,
                std::ptr::null(),
            ) as isize
        };
        if first_handle == INVALID_HANDLE_VALUE as isize {
            // No fresh instance — the next iteration's
            // ConnectNamedPipe would fail. Close the current stream
            // and sleep until the next round.
            drop(stream);
            thread::sleep(Duration::from_millis(100));
        } else {
            on_conn(stream);
        }
    }
}

/// Shared state one API connection reads. Bundled so the serve
/// function keeps a short parameter list (same shape as the Unix
/// side's `ConnDeps`).
struct ConnDeps<'a> {
    info: &'a DaemonInfo,
    router: &'a Arc<RwLock<DefaultRouter>>,
    running: &'a Arc<AtomicBool>,
    reload: &'a Arc<dyn Fn() -> Vec<String> + Send + Sync>,
    status_lines: &'a Arc<dyn Fn() -> Vec<String> + Send + Sync>,
    /// Daemon-wide graceful drain controller (issue #53). `None`
    /// when the daemon was started in immediate mode — the API
    /// refuses `shutdown drain` with a clear "not configured"
    /// diagnostic instead of silently accepting.
    shutdown: Option<&'a Arc<crate::shutdown::ShutdownController>>,
    /// Live ROA store for `show roa` (issue #52 follow-up). `None`
    /// on daemon modes without a ROA store (OSPF/Babel/BMP) — the
    /// renderer then reports `roa-total 0` instead of refusing.
    roa_store: Option<&'a Arc<lr_bgp::RoaStore>>,
    started: std::time::Instant,
    /// `shutdown` does not need to remove a socket file on Windows
    /// (named pipes are kernel-namespace objects that vanish when
    /// the last handle closes), so this field exists only for
    /// structural parity with the Unix `ConnDeps` — it is never
    /// read on Windows.
    #[allow(dead_code)]
    socket_path: Option<&'a str>,
}

/// One connection: read a command line, answer, repeat. Mirrors the
/// Unix `serve_connection` line for line.
fn serve_connection(stream: NamedPipeStream, deps: &ConnDeps<'_>) {
    // Duplicate the handle so the BufReader (read half) and
    // BufWriter (write half) own independent handles — the borrow
    // checker would reject sharing `&mut stream` between both.
    let Ok(write_half) = stream.try_clone() else {
        return;
    };
    let mut reader = BufReader::new(stream);
    let mut out = BufWriter::new(write_half);
    let mut line = String::new();
    loop {
        line.clear();
        // Tolerate idle clients without blocking shutdown forever:
        // the `Read` impl returns `WouldBlock` when `PeekNamedPipe`
        // sees no bytes, so `read_line` surfaces it here. Cap the
        // command length so a slow-drip client cannot grow the line
        // unboundedly. (The legacy `PIPE_NOWAIT` mode switch that
        // used to bracket this loop is gone — `PeekNamedPipe` is the
        // modern non-blocking probe and does not need a mode flip.)
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
            continue;
        }
        let cmd = line.trim();
        if cmd.is_empty() {
            continue;
        }
        // The MRT dump command takes a path argument.
        if let Some(path) = cmd.strip_prefix("mrt ") {
            let path = path.trim();
            if path.is_empty() {
                let _ = writeln!(out, "usage: mrt <path>");
            } else {
                let router_id = core::str::FromStr::from_str(&deps.info.router_id)
                    .unwrap_or(lr_core::addr::RouterId::from_u32(0));
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
        // `show roa` — the runtime API half of `lrctl roa list`
        // (ROADMAP "lrctl roa list", issue #52 follow-up). Rendered
        // by the shared `roa_view` module so the Unix and Windows
        // paths stay byte-identical. Lives ahead of the `show …`
        // family below so it wins for `show roa` specifically —
        // the family's dispatcher does not (yet) recognise `roa`
        // as a sub-command.
        if cmd == "show roa" {
            let body = crate::roa_view::render(deps.roa_store);
            let _ = out.write_all(body.as_bytes());
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
        // `session <handle> <op>` — write-side fine-grained
        // operations on one session (issue #52 follow-up). Mirrors
        // the Unix `handle_session_op` verbatim so the two
        // transports stay byte-identical.
        if let Some(rest) = cmd.strip_prefix("session ") {
            let reply = handle_session_op(rest, deps);
            let _ = out.write_all(reply.as_bytes());
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
                     show status            extended summary (per-protocol counts, memory)\n  \
                     show sessions [detail] per-session stats (transitions, uptime, last error)\n  \
                     show session <handle>  deep dive for one session\n  \
                     show routes count     Loc-RIB grouped by protocol\n  \
                     show memory           process RSS and virtual size\n  \
                     show roa  ROA table dump (BIRD `show roa` parity)\n  \
                     session <handle> soft-in     re-evaluate import policy (FRR `clear ip bgp * soft in`)\n  \
                     session <handle> refresh-in [family]  RFC 2918 route-refresh request\n  \
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
                }
            }
            "routes" => {
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
                // to false and return. The daemon's main loop notices
                // on its next poll and exits. The `shutdown drain` and
                // `shutdown status` sub-commands are stripped off the
                // command line first (see the prefix match arm below).
                deps.running.store(false, Ordering::Relaxed);
                let _ = writeln!(out, "shutting down");
                let _ = out.flush();
                return;
            }
            other if other.starts_with("shutdown ") => {
                // Issue #53 daemon-wide graceful drain sub-commands.
                // Mirrors the Unix serve_connection dispatch verbatim
                // so a `lrctl shutdown drain` on Windows hits the same
                // code path as on Unix.
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
                        // Abort is best-effort: the worker notices on
                        // its next iteration and exits without further
                        // work. Returns the state at the time of the
                        // abort (Running after the call, but the
                        // before-abort state is what an operator
                        // inspecting the log wants to see).
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

/// Dispatch `session <handle> <op>` — write-side fine-grained
/// operations on one session (issue #52 follow-up). Mirrors the Unix
/// `handle_session_op` verbatim so the two transports stay
/// byte-identical.
///
/// Supported ops:
/// - `soft-in` — re-evaluate the import policy against the
///   pre-policy Adj-RIB-In for this session (FRR `clear ip bgp *
///   soft in`). Requires `soft_reconfig_inbound` to have been
///   enabled on the session before it started.
/// - `refresh-in [family]` — send an RFC 2918 ROUTE-REFRESH
///   request to the peer for the given family (default
///   `ipv4-unicast`). Requires the session to be established and
///   the route-refresh capability to have been negotiated.
///
/// Returns the reply string (already newline-terminated). The
/// caller writes it verbatim and flushes.
fn handle_session_op(rest: &str, deps: &ConnDeps<'_>) -> String {
    // Parse `<handle> <op> [args...]`. The handle is a u64; the
    // op is the next token; the rest is op-specific.
    let mut tokens = rest.split_whitespace();
    let Some(handle_str) = tokens.next() else {
        return "error: session requires <handle> <op>\n".to_string();
    };
    let Ok(handle) = handle_str.parse::<u64>() else {
        return format!("error: invalid session handle '{handle_str}'\n");
    };
    let Some(op) = tokens.next() else {
        return format!(
            "error: session {handle} requires an op (try 'soft-in' or 'refresh-in [family]')\n"
        );
    };
    match op {
        "soft-in" => {
            // FRR `clear ip bgp * soft in`: re-evaluate the
            // import policy against the pre-policy Adj-RIB-In.
            // The router core returns Ok(count) on success,
            // Err(msg) when the session is not BGP or the
            // pre-policy RIB was not retained.
            let result = {
                let mut w = deps.router.write().unwrap();
                w.soft_reconfig_inbound(lr_router::SessionHandle(handle))
            };
            match result {
                Ok(count) => format!("session {handle} soft-in ok re-evaluated={count}\n"),
                Err(msg) => format!("error: session {handle} soft-in failed: {msg}\n"),
            }
        }
        "refresh-in" => {
            // RFC 2918 route-refresh request. Parse the optional
            // family argument (default ipv4-unicast).
            let family_str = tokens.next().unwrap_or("ipv4-unicast");
            let Some(family) = super::parse_nlri_family(family_str) else {
                return format!(
                    "error: session {handle} refresh-in: unknown family '{family_str}'\n"
                );
            };
            let requested = {
                let mut w = deps.router.write().unwrap();
                w.request_route_refresh(lr_router::SessionHandle(handle), family)
            };
            if requested {
                format!("session {handle} refresh-in ok family={family_str}\n")
            } else {
                format!(
                    "error: session {handle} refresh-in failed: not established, RFC 2918 not negotiated, or session not BGP\n"
                )
            }
        }
        other => format!(
            "error: session {handle}: unknown op '{other}' (try 'soft-in' or 'refresh-in [family]')\n"
        ),
    }
}
