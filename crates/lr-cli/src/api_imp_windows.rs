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

use super::{ApiContext, DaemonInfo};

// ---------------------------------------------------------------------------
// Win32 constants
// ---------------------------------------------------------------------------

/// `PIPE_ACCESS_DUPLEX` — clients and server can both read and write.
const PIPE_ACCESS_DUPLEX: u32 = 0x00000003;
/// `PIPE_TYPE_BYTE` — data on the pipe is a byte stream (no message
/// boundaries). Matches how the Unix side reads the line protocol.
const PIPE_TYPE_BYTE: u32 = 0x00000000;
/// `PIPE_WAIT` — blocking I/O.
const PIPE_WAIT: u32 = 0x00000000;
/// `PIPE_NOWAIT` — non-blocking I/O, used briefly between idle reads
/// so the connection thread can notice the daemon shutting down.
const PIPE_NOWAIT: u32 = 0x00000001;
/// `PIPE_UNLIMITED_INSTANCES` — the server can create as many
/// concurrent pipe instances as there are clients.
const PIPE_UNLIMITED_INSTANCES: u32 = 255;
/// `INVALID_HANDLE_VALUE` — the sentinel `CreateNamedPipeW` returns
/// on failure.
const INVALID_HANDLE_VALUE: isize = -1;
/// `ERROR_PIPE_CONNECTED` — `ConnectNamedPipe` returns 0 with this
/// last error when a client already connected between the
/// `CreateNamedPipeW` and `ConnectNamedPipe` calls (a race the
/// Windows API documents as benign).
const ERROR_PIPE_CONNECTED: u32 = 535;
/// `ERROR_BROKEN_PIPE` — the client closed the pipe cleanly; the
/// Windows analogue of EOF on a Unix socket.
const ERROR_BROKEN_PIPE: u32 = 109;
/// `DUPLICATE_SAME_ACCESS` — `DuplicateHandle` option that produces a
/// second handle with the same access rights as the source.
const DUPLICATE_SAME_ACCESS: u32 = 0x00000002;

// ---------------------------------------------------------------------------
// FFI
// ---------------------------------------------------------------------------

/// `OVERLAPPED` — declared so we can pass `*mut Overlapped` (NULL)
/// for blocking behaviour without pulling in a crate. The struct's
/// full layout matches the Win32 header.
#[repr(C)]
struct Overlapped {
    internal: usize,
    internal_high: usize,
    offset: u32,
    offset_high: u32,
    event: isize,
}

extern "system" {
    fn CreateNamedPipeW(
        name: *const u16,
        open_mode: u32,
        pipe_mode: u32,
        max_instances: u32,
        out_buffer_size: u32,
        in_buffer_size: u32,
        default_timeout: u32,
        security_attributes: *mut core::ffi::c_void,
    ) -> isize;
    fn ConnectNamedPipe(handle: isize, overlapped: *mut Overlapped) -> i32;
    fn DisconnectNamedPipe(handle: isize) -> i32;
    fn CloseHandle(handle: isize) -> i32;
    fn DuplicateHandle(
        source_process: isize,
        source_handle: isize,
        target_process: isize,
        target_handle: *mut isize,
        desired_access: u32,
        inherit_handle: i32,
        options: u32,
    ) -> i32;
    fn GetCurrentProcess() -> isize;
    fn ReadFile(
        handle: isize,
        buffer: *mut u8,
        bytes_to_read: u32,
        bytes_read: *mut u32,
        overlapped: *mut Overlapped,
    ) -> i32;
    fn WriteFile(
        handle: isize,
        buffer: *const u8,
        bytes_to_write: u32,
        bytes_written: *mut u32,
        overlapped: *mut Overlapped,
    ) -> i32;
    fn FlushFileBuffers(handle: isize) -> i32;
    fn SetNamedPipeHandleState(
        handle: isize,
        mode: *const u32,
        max_collection_count: *const u32,
        collect_data_timeout: *const u32,
    ) -> i32;
    fn GetLastError() -> u32;
}

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
                self.handle,
                current,
                &mut new_handle,
                0,
                1,
                DUPLICATE_SAME_ACCESS,
            )
        };
        if rc == 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(NamedPipeStream { handle: new_handle })
        }
    }

    /// Switch the pipe between blocking and non-blocking mode. The
    /// server uses non-blocking mode briefly between idle reads so
    /// the daemon's `running` flag is polled at least once every
    /// 250 ms (matching the Unix side's `set_read_timeout` cadence).
    fn set_nonblocking(&self, on: bool) -> io::Result<()> {
        let mode: u32 = if on { PIPE_NOWAIT } else { PIPE_WAIT };
        let rc = unsafe { SetNamedPipeHandleState(self.handle, &mode, &0, &0) };
        if rc == 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }
}

impl Read for NamedPipeStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let mut bytes_read: u32 = 0;
        let rc = unsafe {
            ReadFile(
                self.handle,
                buf.as_mut_ptr(),
                buf.len() as u32,
                &mut bytes_read,
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
        Ok(bytes_read as usize)
    }
}

impl Write for NamedPipeStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let mut bytes_written: u32 = 0;
        let rc = unsafe {
            WriteFile(
                self.handle,
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
        let rc = unsafe { FlushFileBuffers(self.handle) };
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
            let _ = DisconnectNamedPipe(self.handle);
            let _ = CloseHandle(self.handle);
        }
    }
}

// ---------------------------------------------------------------------------
// Spawn + accept loop + per-connection serve (mirrors the Unix side)
// ---------------------------------------------------------------------------

/// Bind the named pipe and spawn the serving thread. `path` is the
/// full pipe name (`\\.\pipe\lr-daemon`); the operator configures
/// it via the same `api_socket` key as on Unix.
pub fn spawn(path: &str, ctx: ApiContext) -> Result<String, String> {
    let name_wide: Vec<u16> = path.encode_utf16().chain(std::iter::once(0)).collect();

    let info = Arc::new(ctx.info);
    let router = Arc::clone(&ctx.router);
    let running = Arc::clone(&ctx.running);
    let reload: Arc<dyn Fn() -> Vec<String> + Send + Sync> = Arc::from(ctx.reload);
    let status_lines: Arc<dyn Fn() -> Vec<String> + Send + Sync> = Arc::from(ctx.status_lines);
    let started = std::time::Instant::now();
    let path_owned = path.to_string();

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
            std::ptr::null_mut(),
        )
    };
    if probe == INVALID_HANDLE_VALUE {
        let err = unsafe { GetLastError() };
        return Err(format!(
            "bind {path}: CreateNamedPipeW failed (error {err})"
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
        let connected = unsafe { ConnectNamedPipe(handle, std::ptr::null_mut()) };
        if connected == 0 {
            let err = unsafe { GetLastError() };
            if err != ERROR_PIPE_CONNECTED {
                // Anything other than the benign "already connected"
                // race: close the handle, sleep briefly to avoid a
                // busy loop, and recreate the pipe instance.
                unsafe { CloseHandle(handle) };
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
                        std::ptr::null_mut(),
                    )
                };
                if first_handle == INVALID_HANDLE_VALUE {
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
                std::ptr::null_mut(),
            )
        };
        if first_handle == INVALID_HANDLE_VALUE {
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
        // briefly flip the read handle to non-blocking, poll, then
        // flip back. Cap the command length so a slow-drip client
        // cannot grow the line unboundedly.
        const MAX_CMD: usize = 4096;
        let mut idle_rounds = 0;
        let mut n = 0usize;
        loop {
            let _ = reader.get_mut().set_nonblocking(true);
            match reader.read_line(&mut line) {
                Ok(0) => break, // EOF
                Ok(read) => {
                    n += read;
                    if line.ends_with('\n') || n >= MAX_CMD {
                        let _ = reader.get_mut().set_nonblocking(false);
                        break;
                    }
                }
                Err(e)
                    if e.kind() == std::io::ErrorKind::WouldBlock
                        || e.kind() == std::io::ErrorKind::TimedOut =>
                {
                    let _ = reader.get_mut().set_nonblocking(false);
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
                deps.running.store(false, Ordering::Relaxed);
                let _ = writeln!(out, "shutting down");
                let _ = out.flush();
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
