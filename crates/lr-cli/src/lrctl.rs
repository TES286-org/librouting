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
//! version 1.0.0-rc.3
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
        "reload" => proxy(&socket, "reload"),
        "shutdown" => proxy(&socket, "shutdown"),
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
    println!("    reload              Re-apply configuration (SIGHUP equivalent)");
    println!("    shutdown            Graceful shutdown");
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
                    eprintln!("parse error: {e}");
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
// Transport — Unix domain socket client. On non-Unix targets the whole
// module refuses with a clear error, mirroring `api.rs`'s stance that a
// pretend API surface is worse than none.
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

#[cfg(not(unix))]
mod transport {
    pub fn round_trip(_socket: &str, _cmd: &str) -> Result<String, String> {
        Err("runtime API requires Unix domain sockets (not supported here)".to_string())
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
