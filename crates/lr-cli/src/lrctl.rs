//! `lrctl` — the librouting operational CLI (ROADMAP-v3 D12).
//!
//! Connects to a running `lr-daemon` over its Unix API socket (the
//! same line-oriented protocol `socat - UNIX-CONNECT:…` speaks) and
//! proxies the command, returning the daemon's reply verbatim to
//! stdout. A small set of subcommands (`filter compile`) run
//! client-side and never touch the daemon — they reuse the
//! `lr-policy` library directly so the operator can validate a
//! filter body before deploying it.
//!
//! The binary intentionally mirrors the existing `lr` / `lr-daemon`
//! style: hand-rolled `env::args()` parsing, no clap dependency,
//! `ExitCode` returns, platform-split modules. The default socket
//! path matches `templates/daemon.toml` (`/run/lr-daemon.api`) so a
//! stock daemon install works without flags.
//!
//! ```text
//! $ lrctl status
//! version 1.1.0
//! local-as 64512
//! ...
//! $ lrctl sessions
//! #1 kind=bgp local-as=64512 peer-as=64513 state=Established ...
//! $ lrctl routes show 203.0.113.0/24
//! 203.0.113.0/24 via 192.0.2.1 proto=Bgp metric=0 path-id=0
//! $ lrctl filter compile 'if net ~ 10.0.0.0/8 then accept; reject;'
//! ok
//! ```

use std::env;
use std::process::ExitCode;

mod pipe_name;

const VERSION: &str = env!("CARGO_PKG_VERSION");

/// The default API socket path — matches `templates/daemon.toml`'s
/// commented-out `api_socket = "/run/lr-daemon.api"` so a stock
/// daemon install works without `--socket`.
const DEFAULT_SOCKET: &str = "/run/lr-daemon.api";

fn main() -> ExitCode {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        print_usage();
        return ExitCode::from(1);
    }
    // Strip a leading `--socket PATH` / `--socket=PATH` from anywhere
    // in the args so `lrctl --socket /tmp/x status` and
    // `lrctl status --socket /tmp/x` both work. The first occurrence
    // wins (matches the daemon's flag parsing).
    let (socket, cmd_args) = extract_socket_flag(&args[1..]);
    let socket = socket.unwrap_or_else(|| DEFAULT_SOCKET.to_string());
    if cmd_args.is_empty() {
        print_usage();
        return ExitCode::from(1);
    }
    let cmd = cmd_args[0].as_str();
    let rest = &cmd_args[1..];
    match cmd {
        "version" | "--version" | "-v" => {
            println!("lrctl {}", VERSION);
            ExitCode::SUCCESS
        }
        "help" | "--help" | "-h" => {
            print_usage();
            ExitCode::SUCCESS
        }
        "status" => proxy(&socket, "status"),
        "sessions" => {
            // `sessions` and `sessions list` both map to the daemon's
            // `sessions` command — the daemon has no list/detail
            // distinction today.
            if !rest.is_empty() && rest != ["list"] {
                eprintln!("usage: lrctl sessions [list]");
                return ExitCode::from(2);
            }
            proxy(&socket, "sessions")
        }
        "routes" => routes(&socket, rest),
        "show" => show(&socket, rest),
        "reload" => proxy(&socket, "reload"),
        "shutdown" => shutdown(&socket, rest),
        "filter" => filter(rest),
        other => {
            eprintln!("error: unknown command '{other}'");
            print_usage();
            ExitCode::from(2)
        }
    }
}

/// Pull a `--socket PATH` / `--socket=PATH` flag out of the arg list.
/// Returns the socket value (when present) and the remaining args in
/// their original order.
fn extract_socket_flag(args: &[String]) -> (Option<String>, Vec<String>) {
    let mut socket: Option<String> = None;
    let mut rest = Vec::with_capacity(args.len());
    let mut i = 0;
    while i < args.len() {
        let a = &args[i];
        if a == "--socket" || a == "-s" {
            if i + 1 < args.len() {
                socket = Some(args[i + 1].clone());
                i += 2;
                continue;
            } else {
                eprintln!("error: --socket requires a path argument");
                std::process::exit(2);
            }
        } else if let Some(v) = a.strip_prefix("--socket=") {
            socket = Some(v.to_string());
            i += 1;
            continue;
        }
        rest.push(a.clone());
        i += 1;
    }
    (socket, rest)
}

fn print_usage() {
    println!("lrctl {} — librouting operational CLI", VERSION);
    println!();
    println!("USAGE:");
    println!("    lrctl [--socket PATH] <command> [args]");
    println!();
    println!(
        "The default socket is {} (matches templates/daemon.toml).",
        DEFAULT_SOCKET
    );
    println!();
    println!("DAEMON COMMANDS (proxy the runtime API):");
    println!("    status              Daemon summary (version, identity, uptime, counters)");
    println!("    sessions [list]     One line per configured session");
    println!("    routes show [prefix]  Loc-RIB dump, optionally filtered by prefix");
    println!("    routes dump <path>  Write the Loc-RIB as an MRT dump (RFC 6396)");
    println!("    show status         Extended summary (per-protocol session counts, memory)");
    println!("    show sessions [detail]  Per-session stats (transitions, uptime, last error)");
    println!("    show session <handle>  Deep dive for one session");
    println!("    show routes count   Loc-RIB grouped by protocol");
    println!("    show memory         Process RSS and virtual size");
    println!("    reload              Re-apply configuration (SIGHUP equivalent)");
    println!("    shutdown            Graceful shutdown (immediate)");
    println!("    shutdown drain      Issue #53: rate-limited drain (stop accepting");
    println!("                        new routes, withdraw Loc-RIB at the configured");
    println!("                        rate, exit when empty)");
    println!("    shutdown status     Drain lifecycle (running | draining | drained)");
    println!("    shutdown abort      Cancel a drain in progress (best-effort)");
    println!();
    println!("CLIENT-SIDE COMMANDS (no daemon required):");
    println!("    filter compile <body>  Validate a filter DSL body");
    println!();
    println!("OTHER:");
    println!("    version             Print lrctl version");
    println!("    help                Show this message");
}

/// `lrctl routes <show|dump> ...` — split out because `show` and
/// `dump` have different argument shapes.
fn routes(socket: &str, rest: &[String]) -> ExitCode {
    if rest.is_empty() {
        eprintln!("usage: lrctl routes <show [prefix] | dump <path>>");
        return ExitCode::from(2);
    }
    match rest[0].as_str() {
        "show" => {
            // `routes show` → daemon `routes` (no filter, full dump).
            // `routes show <prefix>` → daemon `routes`, client-side
            // prefix filter. The daemon API has no parameterised
            // `routes <prefix>` command today; the filter keeps the
            // operator's terminal quiet without changing the wire
            // protocol.
            let prefix_filter = rest.get(1).map(|s| s.as_str());
            let raw = match proxy_raw(socket, "routes") {
                Ok(out) => out,
                Err(code) => return code,
            };
            match prefix_filter {
                None => {
                    print!("{raw}");
                    ExitCode::SUCCESS
                }
                Some(needle) => {
                    let mut matched = 0u64;
                    for line in raw.lines() {
                        // A `routes` line starts with the prefix; match
                        // the leading token exactly so `203.0.113.0/24`
                        // does not also match `203.0.113.0/25`.
                        let leading = line.split_whitespace().next().unwrap_or("");
                        if leading == needle {
                            println!("{line}");
                            matched += 1;
                        }
                    }
                    if matched == 0 {
                        // No match is not an error for a show command —
                        // FRR `show ip route X` returns 0 with an empty
                        // body when the prefix is absent. Stay quiet on
                        // stdout; the operator sees the empty result.
                        eprintln!("no route for {needle}");
                    }
                    ExitCode::SUCCESS
                }
            }
        }
        "dump" => {
            if rest.len() < 2 {
                eprintln!("usage: lrctl routes dump <path>");
                return ExitCode::from(2);
            }
            let path = &rest[1];
            // The daemon expects `mrt <path>` on the wire — `dump` is
            // the operator-facing verb (FRR `dump bgp updates …`
            // lineage), `mrt` is the on-the-wire protocol keyword.
            proxy(socket, &format!("mrt {path}"))
        }
        other => {
            eprintln!("error: unknown routes subcommand '{other}'");
            ExitCode::from(2)
        }
    }
}

/// `lrctl shutdown [drain|status|abort|now]` — issue #53 daemon-wide
/// graceful drain. The bare `lrctl shutdown` (no args) preserves the
/// historical behaviour: proxy the `shutdown` command and exit
/// immediately. The sub-commands map 1:1 to the runtime API's
/// `shutdown drain`, `shutdown status`, `shutdown abort` and plain
/// `shutdown` keywords, with the same on-the-wire framing (the
/// daemon's line protocol already parses them).
fn shutdown(socket: &str, rest: &[String]) -> ExitCode {
    if rest.is_empty() {
        // `lrctl shutdown` (no subcommand) — immediate.
        return proxy(socket, "shutdown");
    }
    match rest[0].as_str() {
        "drain" => proxy(socket, "shutdown drain"),
        "status" => proxy(socket, "shutdown status"),
        "abort" => proxy(socket, "shutdown abort"),
        "now" => proxy(socket, "shutdown"),
        other => {
            eprintln!("error: unknown shutdown subcommand '{other}'");
            eprintln!("usage: lrctl shutdown [drain | status | abort | now]");
            ExitCode::from(2)
        }
    }
}

/// `lrctl show <subsystem>` — issue #52 BIRD-style operational
/// visibility. Each sub-command is a thin proxy to the daemon's
/// matching `show …` runtime API command, so the wire framing stays
/// in one place (the daemon's `serve_connection`). The client only
/// validates the argument shape so a typo is loud locally rather
/// than round-tripped as `error: unknown show sub-command`.
///
/// `lrctl show` (no sub) maps to `show status`, mirroring BIRD's
/// `show` shortcut.
fn show(socket: &str, rest: &[String]) -> ExitCode {
    if rest.is_empty() {
        return proxy(socket, "show status");
    }
    match rest[0].as_str() {
        "status" => proxy(socket, "show status"),
        "sessions" => {
            // `show sessions detail` and `show sessions` map to
            // distinct daemon commands (the daemon's renderer chooses
            // the per-session block shape based on the trailing
            // keyword). `list` is rejected to keep the surface
            // unambiguous — `sessions list` belongs to the legacy
            // `lrctl sessions` command.
            if rest.len() == 1 {
                proxy(socket, "show sessions")
            } else if rest.len() == 2 && rest[1] == "detail" {
                proxy(socket, "show sessions detail")
            } else {
                eprintln!("usage: lrctl show sessions [detail]");
                ExitCode::from(2)
            }
        }
        "session" => {
            if rest.len() != 2 {
                eprintln!("usage: lrctl show session <handle>");
                return ExitCode::from(2);
            }
            // The daemon validates the handle and reports
            // `error: no session with handle <N>` for unknown ones,
            // so the client does not duplicate the lookup — it just
            // forwards the (syntax-validated) numeric token.
            match rest[1].parse::<u64>() {
                Ok(h) => proxy(socket, &format!("show session {h}")),
                Err(_) => {
                    eprintln!("error: invalid session handle '{}'", rest[1]);
                    eprintln!("usage: lrctl show session <handle>");
                    ExitCode::from(2)
                }
            }
        }
        "routes" => {
            if rest.len() != 2 || rest[1] != "count" {
                eprintln!("usage: lrctl show routes count");
                return ExitCode::from(2);
            }
            proxy(socket, "show routes count")
        }
        "memory" => proxy(socket, "show memory"),
        other => {
            eprintln!("error: unknown show subcommand '{other}'");
            eprintln!(
                "usage: lrctl show [status | sessions [detail] | session <handle> | routes count | memory]"
            );
            ExitCode::from(2)
        }
    }
}

/// `lrctl filter compile <body>` — client-side filter validation.
/// Compiles the body through `lr_policy::filter::compile` and reports
/// `ok` on success or the parse error (with 1-indexed line/column) on
/// failure. No daemon connection is needed: this is the same path the
/// daemon runs at startup, so an `ok` here means the body will compile
/// when the daemon reloads.
fn filter(rest: &[String]) -> ExitCode {
    if rest.is_empty() {
        eprintln!("usage: lrctl filter compile <body>");
        return ExitCode::from(2);
    }
    match rest[0].as_str() {
        "compile" => {
            if rest.len() < 2 {
                eprintln!("usage: lrctl filter compile <body>");
                return ExitCode::from(2);
            }
            // The body is a single shell-quoted argument. Multiple
            // args after `compile` are joined with spaces so the
            // operator does not have to wrap multi-statement bodies
            // in extra quotes (`lrctl filter compile 'if net ~ 10/8 then accept;'`
            // and `lrctl filter compile if net ~ 10/8 then accept;`
            // both work — the shell tokenises the latter into one arg
            // per word, we re-join).
            let body = rest[1..].join(" ");
            match lr_policy::filter::compile("lrctl", &body) {
                Ok(f) => {
                    let n_stmts = f.body.stmts.len();
                    let n_fns = f.functions.len();
                    println!(
                        "ok ({n_stmts} statement(s){})",
                        if n_fns > 0 {
                            format!(", {n_fns} function(s)")
                        } else {
                            String::new()
                        }
                    );
                    ExitCode::SUCCESS
                }
                Err(e) => {
                    // Issue #18 Phase 0: positioned diagnostic with a
                    // caret snippet under the offending source line.
                    eprintln!(
                        "{}",
                        lr_policy::filter::render_snippet(
                            &body,
                            e.span,
                            &format!("parse error at {}:{}: {}", e.line, e.col, e.kind),
                        )
                    );
                    ExitCode::from(1)
                }
            }
        }
        other => {
            eprintln!("error: unknown filter subcommand '{other}'");
            eprintln!("usage: lrctl filter compile <body>");
            ExitCode::from(2)
        }
    }
}

// ---------------------------------------------------------------------------
// Transport — Unix domain socket client on Unix; Windows named-pipe client
// on Windows. Both expose the same `round_trip` shape so the proxy layer
// above stays platform-agnostic.
// ---------------------------------------------------------------------------

#[cfg(unix)]
mod transport {
    use std::io::{Read, Write};
    use std::os::unix::net::UnixStream;
    use std::thread;
    use std::time::{Duration, Instant};

    /// Connect to the API socket, send one command, collect the reply
    /// until a short idle silence, return the body as a `String`.
    ///
    /// Mirrors the read-loop shape `daemon_runtime.rs::api_ask` and
    /// `api.rs::tests` use: non-blocking reads with a deadline so the
    /// client returns promptly on the first WouldBlock-with-data and
    /// never hangs forever on a wedged daemon.
    pub fn round_trip(socket: &str, cmd: &str) -> Result<String, String> {
        let mut conn = UnixStream::connect(socket).map_err(|e| format!("connect {socket}: {e}"))?;
        // The server treats a `\n`-terminated line as one command.
        conn.write_all(cmd.as_bytes())
            .map_err(|e| format!("write: {e}"))?;
        if !cmd.ends_with('\n') {
            conn.write_all(b"\n")
                .map_err(|e| format!("write nl: {e}"))?;
        }
        conn.flush().map_err(|e| format!("flush: {e}"))?;

        // Non-blocking read with an idle-silence terminator: keep
        // reading until the socket would block AND we already have
        // some bytes, OR the 5 s deadline expires. The daemon's
        // response to every command ends with a `\n`-terminated last
        // line, so a WouldBlock-with-data means the daemon has
        // finished writing for now.
        conn.set_nonblocking(true)
            .map_err(|e| format!("nonblocking: {e}"))?;
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut buf = Vec::new();
        loop {
            let mut chunk = [0u8; 4096];
            match conn.read(&mut chunk) {
                Ok(0) => break, // EOF — daemon closed after `shutdown`
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
                Err(e) => return Err(format!("read: {e}")),
            }
        }
        String::from_utf8(buf).map_err(|e| format!("non-utf8 reply: {e}"))
    }
}

// ---------------------------------------------------------------------------
// Windows named-pipe client — the counterpart of `api_imp_windows.rs`'s
// server. `lr-daemon` already listens on `\\.\pipe\<name>`; without this
// transport `lrctl` could not talk to it (issue #43: the runtime API was
// inconsistent across the CLI binaries — the daemon listened, the client
// refused). The shape mirrors the Unix transport: write the command, then
// read with a deadline + idle-silence terminator.
//
// `PIPE_NOWAIT` (the legacy non-blocking mode from LAN Manager 2.0) is
// the same knob the server already uses for its idle read loop; we keep
// the two ends symmetric rather than reaching for overlapped I/O, which
// would not buy anything for a single-shot request/response client.
// ---------------------------------------------------------------------------

#[cfg(windows)]
mod transport {
    use std::io::{Read, Write};
    use std::thread;
    use std::time::{Duration, Instant};

    use windows_sys::Win32::Foundation::{
        CloseHandle, GetLastError, GENERIC_READ, GENERIC_WRITE, HANDLE, INVALID_HANDLE_VALUE,
    };
    use windows_sys::Win32::Storage::FileSystem::{
        CreateFileW, ReadFile, WriteFile, FILE_ATTRIBUTE_NORMAL, OPEN_EXISTING,
    };
    use windows_sys::Win32::System::Pipes::PeekNamedPipe;

    /// Windows system error codes returned by `GetLastError` that the
    /// read loop needs to interpret. Named so the `Read` impl below
    /// does not carry magic numbers.
    ///
    /// `ERROR_BROKEN_PIPE` (109): the server closed its end cleanly — EOF.
    /// `ERROR_NO_DATA` (232): the pipe is in a closing state — also
    /// EOF. Windows returns this variant transiently when the server
    /// has called `CloseHandle` on its end of the pipe but the kernel
    /// has not yet torn down the client's view. Treating it as EOF
    /// (rather than a hard error) lets the client observe the
    /// `shutdown` reply the daemon flushed just before closing.
    /// `ERROR_PIPE_BUSY` (231): all pipe instances are in use; the
    /// client retries (see `connect_with_retry`).
    const ERROR_BROKEN_PIPE: u32 = 109;
    const ERROR_NO_DATA: u32 = 232;
    const ERROR_PIPE_BUSY: u32 = 231;

    /// Connect to the daemon's named pipe, send one command, collect
    /// the reply until a short idle silence, return the body as a
    /// `String`. Mirrors the Unix transport's `round_trip` shape so
    /// `proxy` stays platform-agnostic.
    pub fn round_trip(socket: &str, cmd: &str) -> Result<String, String> {
        let pipe_name = crate::pipe_name::normalize_pipe_name(socket);
        let name_wide: Vec<u16> = pipe_name.encode_utf16().chain(std::iter::once(0)).collect();
        let handle = connect_with_retry(&name_wide, &pipe_name)?;
        let mut stream = NamedPipeClientStream::new(handle);

        // Send the command + trailing newline — the server reads one
        // line per command.
        let mut buf = cmd.as_bytes().to_vec();
        if !cmd.ends_with('\n') {
            buf.push(b'\n');
        }
        stream.write_all(&buf).map_err(|e| format!("write: {e}"))?;
        stream.flush().map_err(|e| format!("flush: {e}"))?;

        // Read with an idle-silence terminator (same shape as the Unix
        // transport): keep reading until the pipe has no data AND we
        // already have some bytes, OR the 5 s deadline expires. The
        // daemon's response ends with a `\n`-terminated last line, so a
        // no-data-with-bytes means the daemon has finished writing for
        // now. `Read` returns `WouldBlock` when `PeekNamedPipe` sees
        // no bytes — no `PIPE_NOWAIT` mode switch needed (that legacy
        // mode fails with `ERROR_PIPE_BUSY` on some pipe handles).
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut out = Vec::new();
        let mut chunk = [0u8; 4096];
        loop {
            match stream.read(&mut chunk) {
                Ok(0) => break, // EOF — daemon closed after `shutdown`
                Ok(n) => out.extend_from_slice(&chunk[..n]),
                Err(e)
                    if e.kind() == std::io::ErrorKind::WouldBlock
                        || e.kind() == std::io::ErrorKind::TimedOut =>
                {
                    if !out.is_empty() || Instant::now() >= deadline {
                        break;
                    }
                    thread::sleep(Duration::from_millis(20));
                }
                Err(e) => return Err(format!("read: {e}")),
            }
        }
        String::from_utf8(out).map_err(|e| format!("non-utf8 reply: {e}"))
    }

    /// Open an existing named pipe via `CreateFileW`. The server hands
    /// out instances one at a time from its accept loop; a client that
    /// connects between instances gets `ERROR_PIPE_BUSY` and retries
    /// (Windows docs recommend `WaitNamedPipe`, but a bounded sleep is
    /// simpler and adequate for the 1-Hz accept cadence).
    fn connect_with_retry(name_wide: &[u16], pipe_name: &str) -> Result<isize, String> {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let handle = unsafe {
                CreateFileW(
                    name_wide.as_ptr(),
                    GENERIC_READ | GENERIC_WRITE,
                    0,
                    std::ptr::null(),
                    OPEN_EXISTING,
                    FILE_ATTRIBUTE_NORMAL,
                    0 as HANDLE,
                ) as isize
            };
            if handle != INVALID_HANDLE_VALUE as isize {
                return Ok(handle);
            }
            let err = unsafe { GetLastError() };
            if err == ERROR_PIPE_BUSY {
                if Instant::now() >= deadline {
                    return Err(format!(
                        "connect {pipe_name}: pipe busy (timed out waiting for server)"
                    ));
                }
                thread::sleep(Duration::from_millis(50));
                continue;
            }
            return Err(format!(
                "connect {pipe_name}: CreateFileW failed (error {err})"
            ));
        }
    }

    /// One end of an established named-pipe client connection. `Read`
    /// and `Write` delegate to `ReadFile`/`WriteFile` on the
    /// underlying handle. The handle is closed when the stream is
    /// dropped. Mirrors `api_imp_windows.rs::NamedPipeStream` on the
    /// server side.
    struct NamedPipeClientStream {
        handle: isize,
    }

    // Named-pipe handles are safe to move between threads — the kernel
    // serializes access. We never share one across threads though;
    // `round_trip` is synchronous.
    unsafe impl Send for NamedPipeClientStream {}

    impl NamedPipeClientStream {
        fn new(handle: isize) -> Self {
            Self { handle }
        }
    }

    impl Read for NamedPipeClientStream {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            // Probe the pipe's input buffer without blocking — the
            // modern alternative to the legacy `PIPE_NOWAIT` mode
            // (which fails with `ERROR_PIPE_BUSY` on some handles).
            // `PeekNamedPipe` returns immediately with the number of
            // bytes the next `ReadFile` would yield; 0 means the read
            // would block, which surfaces as `WouldBlock` so the
            // caller's idle-silence read loop can poll on its own
            // cadence.
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
                let err = unsafe { GetLastError() };
                // ERROR_BROKEN_PIPE / ERROR_NO_DATA: the server closed
                // (or is closing) its end — EOF.
                if err == ERROR_BROKEN_PIPE || err == ERROR_NO_DATA {
                    return Ok(0);
                }
                return Err(std::io::Error::from_raw_os_error(err as i32));
            }
            if available == 0 {
                return Err(std::io::Error::from(std::io::ErrorKind::WouldBlock));
            }
            // Data is buffered — `ReadFile` returns immediately with
            // up to `buf.len()` of it (capped at `available` by the
            // kernel, but the cap does not matter: any non-zero read
            // advances the loop).
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
                let err = unsafe { GetLastError() };
                if err == ERROR_BROKEN_PIPE || err == ERROR_NO_DATA {
                    return Ok(0);
                }
                return Err(std::io::Error::from_raw_os_error(err as i32));
            }
            Ok(bytes_read as usize)
        }
    }

    impl Write for NamedPipeClientStream {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
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
                return Err(std::io::Error::last_os_error());
            }
            Ok(bytes_written as usize)
        }

        fn flush(&mut self) -> std::io::Result<()> {
            // Named pipes transmit on write; the server's BufWriter
            // flushes per response. FlushFileBuffers would block until
            // the server drains, which we do not want here.
            Ok(())
        }
    }

    impl Drop for NamedPipeClientStream {
        fn drop(&mut self) {
            unsafe {
                let _ = CloseHandle(self.handle as HANDLE);
            }
        }
    }
}

// Fallback for platforms with neither Unix domain sockets nor Windows
// named pipes — the original stance that a pretend API is worse than a
// clear refusal. Every platform the project targets (Linux, macOS, the
// BSDs, Windows) is covered above; this is the theoretical remainder.
#[cfg(not(any(unix, windows)))]
mod transport {
    pub fn round_trip(_socket: &str, _cmd: &str) -> Result<String, String> {
        Err(
            "runtime API requires Unix domain sockets or Windows named pipes (not supported here)"
                .to_string(),
        )
    }
}

/// Send one command to the daemon, print the reply to stdout, and
/// return the appropriate `ExitCode`. A transport failure or a daemon
/// `error:` line is a non-zero exit; everything else is success.
fn proxy(socket: &str, cmd: &str) -> ExitCode {
    match transport::round_trip(socket, cmd) {
        Ok(body) => {
            // The daemon emits `error: <reason>` for unknown commands
            // and malformed arguments. Surface those as a non-zero
            // exit so scripts can branch on them, but still print the
            // body so the operator sees the reason.
            let is_error = body.lines().any(|l| l.starts_with("error:"));
            print!("{body}");
            // Ensure a trailing newline so chained shell pipelines see
            // clean output even when the daemon omitted one.
            if !body.ends_with('\n') {
                println!();
            }
            if is_error {
                ExitCode::from(1)
            } else {
                ExitCode::SUCCESS
            }
        }
        Err(e) => {
            eprintln!("lrctl: {e}");
            ExitCode::from(1)
        }
    }
}

/// Like [`proxy`] but returns the raw reply body instead of printing
/// it. Used by `routes show <prefix>` so the client-side filter can
/// walk the lines without re-piping stdout.
fn proxy_raw(socket: &str, cmd: &str) -> Result<String, ExitCode> {
    match transport::round_trip(socket, cmd) {
        Ok(body) => Ok(body),
        Err(e) => {
            eprintln!("lrctl: {e}");
            Err(ExitCode::from(1))
        }
    }
}
