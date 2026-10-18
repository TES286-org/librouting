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
//! version ...
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

mod lrctl_json;
mod pipe_name;

use lrctl_json::{JArray, JObject, JValue};

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
    // Pull the `--json` / `--json=FORMAT` flag (or its short
    // equivalent `-j`) out of the arg list. Like `--socket`, it
    // may appear anywhere in the args after the command. The flag
    // is *consumed* here so sub-command handlers see the same
    // reduced `rest` they always did — the JSON wrapping is
    // applied centrally in `proxy_raw`/`proxy` rather than per
    // sub-command.
    let (json, cmd_args) = extract_json_flag(&cmd_args);
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
        "status" => proxy_with_json(&socket, "status", json, parse_status_body),
        "sessions" => {
            // `sessions` and `sessions list` both map to the daemon's
            // `sessions` command — the daemon has no list/detail
            // distinction today.
            if !rest.is_empty() && rest != ["list"] {
                eprintln!("usage: lrctl sessions [list]");
                return ExitCode::from(2);
            }
            proxy_with_json(&socket, "sessions", json, parse_sessions_body)
        }
        // BIRD-style alias: `neighbor` / `neighbors` is the
        // operator's muscle-memory word for "show me the peers". The
        // daemon's wire keyword stays `sessions`; the alias just
        // routes there. `neighbor <handle>` is a thin alias for
        // `show session <handle>` so the BIRD `show protocols all
        // <name>` operator gets the deep dive from the same verb.
        "neighbor" | "neighbors" => neighbor(&socket, rest, json),
        // `ping` round-trips the API socket with the cheapest
        // command the daemon answers (`help`): success means the
        // daemon is up, the API socket is reachable, and the
        // round-trip latency is a proxy for "the daemon's event
        // loop is not wedged". BIRD has no direct equivalent;
        // FRR's `vtysh -c 'show version'` is the closest analogue.
        "ping" => ping(&socket, json),
        // `metrics` connects to the daemon's HTTP /metrics
        // endpoint and proxies the scrape to stdout. The address
        // defaults to the daemon's documented default
        // (127.0.0.1:9119) and is overridable with
        // `--metrics-addr ADDR` (kept distinct from `--socket`
        // because the metrics endpoint is TCP, not the Unix API
        // socket).
        "metrics" => metrics(&socket, rest),
        "routes" => routes(&socket, rest, json),
        "roa" => roa(&socket, rest, json),
        "session" => session(&socket, rest),
        "show" => show(&socket, rest, json),
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

/// Pull a `--json` / `--json=FORMAT` / `-j` flag out of the arg list.
/// Returns the JSON mode (None / Some(Json)) and the remaining args
/// in their original order. The flag may appear anywhere — same
/// rule as `--socket`.
///
/// `--json` with no argument defaults to a compact JSON object. The
/// optional `=pretty` form (e.g. `--json=pretty`) pretty-prints with
/// a 2-space indent. Other forms are rejected so a typo is loud
/// rather than silently defaulting.
fn extract_json_flag(args: &[String]) -> (Option<JsonFormat>, Vec<String>) {
    let mut json: Option<JsonFormat> = None;
    let mut rest = Vec::with_capacity(args.len());
    let mut i = 0;
    while i < args.len() {
        let a = &args[i];
        if a == "--json" || a == "-j" {
            if json.is_none() {
                json = Some(JsonFormat::Compact);
            }
            i += 1;
            continue;
        } else if let Some(v) = a.strip_prefix("--json=") {
            if json.is_none() {
                json = match v {
                    "compact" | "" => Some(JsonFormat::Compact),
                    "pretty" => Some(JsonFormat::Pretty),
                    other => {
                        eprintln!(
                            "error: --json={other} is not a valid format (try --json or --json=pretty)"
                        );
                        std::process::exit(2);
                    }
                };
            }
            i += 1;
            continue;
        }
        rest.push(a.clone());
        i += 1;
    }
    (json, rest)
}

/// Output format selected by `--json` / `--json=pretty`.
#[derive(Clone, Copy, PartialEq, Eq)]
enum JsonFormat {
    Compact,
    Pretty,
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
    println!("    lrctl [--socket PATH] [--json[=pretty]] <command> [args]");
    println!();
    println!(
        "The default socket is {} (matches templates/daemon.toml).",
        DEFAULT_SOCKET
    );
    println!();
    println!("GLOBAL FLAGS:");
    println!("    --socket PATH       API socket path (default: {DEFAULT_SOCKET})");
    println!("    --json              Emit machine-readable JSON for supported commands");
    println!("    --json=pretty       Pretty-printed JSON (2-space indent)");
    println!("    -j                  Alias for --json");
    println!();
    println!("DAEMON COMMANDS (proxy the runtime API):");
    println!("    status              Daemon summary (version, identity, uptime, counters)");
    println!("    sessions [list]     One line per configured session");
    println!("    neighbor [handle]   BIRD-style alias for sessions / show session");
    println!("    ping                Round-trip the API socket (health check)");
    println!("    metrics [--metrics-addr ADDR]  Scrape the daemon's /metrics HTTP endpoint");
    println!("    routes show [prefix]  Loc-RIB dump, optionally filtered by prefix");
    println!("    routes count        Loc-RIB grouped by protocol (alias for show routes count)");
    println!("    routes dump <path>  Write the Loc-RIB as an MRT dump (RFC 6396)");
    println!("    show status         Extended summary (per-protocol session counts, memory)");
    println!("    show sessions [detail]  Per-session stats (transitions, uptime, last error)");
    println!("    show session <handle>  Deep dive for one session");
    println!("    show routes count   Loc-RIB grouped by protocol");
    println!("    show memory         Process RSS and virtual size");
    println!("    roa list            ROA table dump (BIRD `show roa` parity)");
    println!("    roa count          ROA table summary line only");
    println!(
        "    session <handle> soft-in     Re-evaluate import policy (FRR `clear ip bgp * soft in`)"
    );
    println!("    session <handle> refresh-in [family]  RFC 2918 route-refresh request");
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
    println!();
    println!("JSON OUTPUT (--json):");
    println!(
        "    status, sessions, ping, neighbor, show status/sessions/session/routes count/memory"
    );
    println!("    emit a JSON value to stdout instead of the line-oriented form. The shape is");
    println!("    documented in docs/bindings/lrctl-json.md. Other commands ignore --json.");
}

/// `lrctl routes <show|count|dump> ...` — split out because the
/// sub-commands have different argument shapes.
fn routes(socket: &str, rest: &[String], json: Option<JsonFormat>) -> ExitCode {
    if rest.is_empty() {
        eprintln!("usage: lrctl routes <show [prefix] | count | dump <path>>");
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
        // `routes count` is a BIRD-style alias for `show routes
        // count`. The daemon's wire command stays `show routes
        // count`; the alias just routes there. The `--json` flag
        // is honoured: the daemon's `total N / proto=P routes=M`
        // body is parsed into `{"total": N, "by_protocol": [{"protocol": P, "routes": M}, ...]}`.
        "count" => proxy_with_json(socket, "show routes count", json, parse_routes_count_body),
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

/// `lrctl roa <list|count>` — ROADMAP "lrctl roa list", issue #52
/// follow-up. Both sub-commands are thin proxies to the daemon's
/// `show roa` runtime API command. The client only validates the
/// argument shape so a typo is loud locally rather than round-tripped.
///
/// `roa list` proxies the full `show roa` output (summary line + one
/// line per entry, BIRD `show roa` parity). `roa count` extracts just
/// the summary line — `roa-total N static S rtr R` — so a script can
/// poll the table size without parsing the entry list.
fn roa(socket: &str, rest: &[String], _json: Option<JsonFormat>) -> ExitCode {
    if rest.is_empty() {
        eprintln!("usage: lrctl roa <list | count>");
        return ExitCode::from(2);
    }
    match rest[0].as_str() {
        "list" => proxy(socket, "show roa"),
        "count" => {
            // The daemon's `show roa` reply starts with the summary
            // line; `roa count` strips the per-entry lines so a
            // script gets just `roa-total N static S rtr R`.
            match proxy_raw(socket, "show roa") {
                Ok(body) => {
                    let summary = body.lines().next().unwrap_or("");
                    println!("{summary}");
                    ExitCode::SUCCESS
                }
                Err(code) => code,
            }
        }
        other => {
            eprintln!("error: unknown roa subcommand '{other}'");
            eprintln!("usage: lrctl roa <list | count>");
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
///
/// `--json` is honoured for `status`, `sessions`, `routes count` and
/// `memory`. For `session <handle>` the JSON view falls back to the
/// raw body — the per-session block is multi-line key=value with
/// nested `stats:` / `last-error:` / `messages:` lines that do not
/// round-trip cleanly into a flat object, so the line-oriented form
/// is preserved verbatim under `--json` (an operator trading off
/// fidelity for JSON-parsability can use the `sessions` JSON view
/// plus a client-side handle filter instead).
fn show(socket: &str, rest: &[String], json: Option<JsonFormat>) -> ExitCode {
    if rest.is_empty() {
        return proxy_with_json(socket, "show status", json, parse_show_status_body);
    }
    match rest[0].as_str() {
        "status" => proxy_with_json(socket, "show status", json, parse_show_status_body),
        "sessions" => {
            // `show sessions detail` and `show sessions` map to
            // distinct daemon commands (the daemon's renderer chooses
            // the per-session block shape based on the trailing
            // keyword). `list` is rejected to keep the surface
            // unambiguous — `sessions list` belongs to the legacy
            // `lrctl sessions` command.
            if rest.len() == 1 {
                proxy_with_json(socket, "show sessions", json, parse_sessions_body)
            } else if rest.len() == 2 && rest[1] == "detail" {
                // `show sessions detail` carries the multi-line
                // per-session block — the JSON view falls back to
                // the raw body for the same reason as `show session
                // <handle>` (see above). The plain `show sessions`
                // one-line form round-trips cleanly.
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
            proxy_with_json(socket, "show routes count", json, parse_routes_count_body)
        }
        "memory" => proxy_with_json(socket, "show memory", json, parse_show_memory_body),
        other => {
            eprintln!("error: unknown show subcommand '{other}'");
            eprintln!(
                "usage: lrctl show [status | sessions [detail] | session <handle> | routes count | memory]"
            );
            ExitCode::from(2)
        }
    }
}

/// `lrctl neighbor [handle]` — BIRD-style alias. With no argument,
/// maps to `sessions` (the daemon's `sessions` wire keyword). With a
/// numeric handle, maps to `show session <handle>` for the deep
/// dive. The `--json` flag is honoured for the no-argument form (the
/// handle form falls back to the raw `show session` body — see
/// `show`'s doc comment for why).
fn neighbor(socket: &str, rest: &[String], json: Option<JsonFormat>) -> ExitCode {
    if rest.is_empty() {
        return proxy_with_json(socket, "sessions", json, parse_sessions_body);
    }
    // `neighbor <handle>` — alias for `show session <handle>`.
    match rest[0].parse::<u64>() {
        Ok(h) => proxy(socket, &format!("show session {h}")),
        Err(_) => {
            eprintln!("error: invalid session handle '{}'", rest[0]);
            eprintln!("usage: lrctl neighbor [handle]");
            ExitCode::from(2)
        }
    }
}

/// `lrctl ping` — round-trip the API socket with the cheapest
/// command the daemon answers (`help`). The reply is discarded; the
/// exit code carries the result. The wall-clock latency is measured
/// around the round-trip and printed as `ok Nms` (or `{"ok": true,
/// "round_trip_ms": N}` under `--json`) so a health-check loop has a
/// single number to alert on.
///
/// The daemon's `help` command is the cheapest always-succeeding
/// reply: it does not touch the router state, it just emits the
/// command list. `status` would also work, but `help` is faster
/// (no router read-lock) and is the canonical "is anyone home"
/// probe in the BIRD / vtysh lineage.
fn ping(socket: &str, json: Option<JsonFormat>) -> ExitCode {
    let start = std::time::Instant::now();
    match transport::round_trip(socket, "help") {
        Ok(body) => {
            let ms = start.elapsed().as_millis();
            // A `help` reply starts with "commands:". Anything else
            // means the daemon is in an unexpected state — surface it
            // as a non-zero exit so a health-check loop sees it.
            let is_help = body.starts_with("commands:") || body.contains("commands:");
            if !is_help {
                return emit_ping_result(json, false, ms, Some(&body));
            }
            emit_ping_result(json, true, ms, None)
        }
        Err(e) => {
            let ms = start.elapsed().as_millis();
            emit_ping_result(json, false, ms, Some(&e))
        }
    }
}

/// Format the `ping` result for stdout according to the JSON flag.
/// Returns the exit code (SUCCESS when ok=true, FAILURE otherwise).
fn emit_ping_result(
    json: Option<JsonFormat>,
    ok: bool,
    ms: u128,
    detail: Option<&str>,
) -> ExitCode {
    match json {
        Some(fmt) => {
            let mut o = JObject::new();
            o.push_bool("ok", ok).push_uint("round_trip_ms", ms as u64);
            if let Some(d) = detail {
                o.push_str("detail", d);
            }
            let v = JValue::Object(o);
            print_json(&v, fmt);
        }
        None => match detail {
            Some(d) => println!("fail {ms}ms: {d}"),
            None => println!("ok {ms}ms"),
        },
    }
    if ok {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(1)
    }
}

/// `lrctl metrics [--metrics-addr ADDR]` — scrape the daemon's
/// HTTP /metrics endpoint and proxy the body to stdout. The address
/// defaults to `127.0.0.1:9119` (the daemon's documented default);
/// `--metrics-addr ADDR` overrides it. `--socket` is unused here —
/// the metrics endpoint is TCP, not the Unix API socket.
///
/// The body is the full Prometheus text exposition, returned
/// verbatim. A 5 s connect+read deadline matches the daemon-side
/// `set_read_timeout(500ms)` per connection — a hung daemon
/// surfaces as a transport error rather than a hang.
fn metrics(_socket: &str, rest: &[String]) -> ExitCode {
    let mut addr = DEFAULT_METRICS_ADDR.to_string();
    let mut i = 0;
    while i < rest.len() {
        let a = &rest[i];
        if a == "--metrics-addr" {
            if i + 1 >= rest.len() {
                eprintln!("error: --metrics-addr requires an argument");
                return ExitCode::from(2);
            }
            addr = rest[i + 1].clone();
            i += 2;
            continue;
        }
        if let Some(v) = a.strip_prefix("--metrics-addr=") {
            addr = v.to_string();
            i += 1;
            continue;
        }
        eprintln!("error: unexpected argument '{a}'");
        eprintln!("usage: lrctl metrics [--metrics-addr ADDR]");
        return ExitCode::from(2);
    }
    // A plain TCP `GET /metrics HTTP/1.0` — the daemon's metrics
    // module answers this exact shape (`serve_connection`).
    use std::io::{Read, Write};
    use std::net::TcpStream;
    use std::time::{Duration, Instant};
    let mut conn = match TcpStream::connect(&addr) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("lrctl: connect {addr}: {e}");
            return ExitCode::from(1);
        }
    };
    let _ = conn.set_read_timeout(Some(Duration::from_secs(5)));
    let _ = conn.set_write_timeout(Some(Duration::from_secs(5)));
    if let Err(e) = write!(
        conn,
        "GET /metrics HTTP/1.0\r\nHost: {addr}\r\nConnection: close\r\n\r\n"
    ) {
        eprintln!("lrctl: write: {e}");
        return ExitCode::from(1);
    }
    let _ = conn.flush();
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut out = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        match conn.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => out.extend_from_slice(&chunk[..n]),
            Err(e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut =>
            {
                if !out.is_empty() || Instant::now() >= deadline {
                    break;
                }
                std::thread::sleep(Duration::from_millis(20));
            }
            Err(e) => {
                eprintln!("lrctl: read: {e}");
                return ExitCode::from(1);
            }
        }
    }
    let body = String::from_utf8_lossy(&out);
    // The HTTP/1.0 response is `HTTP/1.0 200 OK\r\n<headers>\r\n\r\n<body>`.
    // Surface the status line so the operator sees a non-200 scrape
    // (the daemon returns 404 on unknown paths, 200 on /metrics).
    let (status_line, body_part) = match body.find("\r\n\r\n") {
        Some(idx) => {
            let head = &body[..idx];
            let bdy = &body[idx + 4..];
            (head.lines().next().unwrap_or(""), bdy)
        }
        None => ("", body.as_ref()),
    };
    if !status_line.contains(" 200 ") {
        eprintln!("lrctl: {status_line}");
        // Still print the body so the operator sees the error reply.
        print!("{body_part}");
        return ExitCode::from(1);
    }
    print!("{body_part}");
    ExitCode::SUCCESS
}

/// The default metrics HTTP address (matches the daemon's documented
/// default). Kept here rather than read from the daemon so the CLI
/// works on a stock install without consulting the daemon's config.
const DEFAULT_METRICS_ADDR: &str = "127.0.0.1:9119";

/// `lrctl session <handle> <op> [args]` — write-side fine-grained
/// operations on one session (issue #52 follow-up: "the lrctl
/// controller must support fine-grained operations on the running
/// daemon"). Both sub-commands are thin proxies to the daemon's
/// `session <handle> <op>` runtime API command; the client validates
/// the argument shape locally so a typo is loud rather than
/// round-tripped.
///
/// - `session <handle> soft-in` — re-evaluate the import policy
///   against the pre-policy Adj-RIB-In (FRR `clear ip bgp * soft in`).
/// - `session <handle> refresh-in [family]` — send an RFC 2918
///   ROUTE-REFRESH request to the peer for the given family
///   (default `ipv4-unicast`).
fn session(socket: &str, rest: &[String]) -> ExitCode {
    if rest.is_empty() {
        eprintln!("usage: lrctl session <handle> <soft-in | refresh-in [family]>");
        return ExitCode::from(2);
    }
    // `rest[0]` is the handle; `rest[1]` is the op; `rest[2..]` is
    // op-specific. Validate the handle is numeric so the daemon
    // does not bounce it back with the same error.
    let handle_str = &rest[0];
    if handle_str.parse::<u64>().is_err() {
        eprintln!("error: invalid session handle '{handle_str}'");
        eprintln!("usage: lrctl session <handle> <soft-in | refresh-in [family]>");
        return ExitCode::from(2);
    }
    if rest.len() < 2 {
        eprintln!(
            "error: session {handle_str} requires an op (try 'soft-in' or 'refresh-in [family]')"
        );
        return ExitCode::from(2);
    }
    let op = rest[1].as_str();
    match op {
        "soft-in" => {
            // No extra args expected.
            if rest.len() != 2 {
                eprintln!("usage: lrctl session {handle_str} soft-in");
                return ExitCode::from(2);
            }
            proxy(socket, &format!("session {handle_str} soft-in"))
        }
        "refresh-in" => {
            // Optional family argument (default ipv4-unicast).
            let family = if rest.len() == 2 {
                "ipv4-unicast"
            } else if rest.len() == 3 {
                rest[2].as_str()
            } else {
                eprintln!("usage: lrctl session {handle_str} refresh-in [family]");
                return ExitCode::from(2);
            };
            proxy(socket, &format!("session {handle_str} refresh-in {family}"))
        }
        other => {
            eprintln!("error: unknown session op '{other}'");
            eprintln!("usage: lrctl session <handle> <soft-in | refresh-in [family]>");
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

/// Like [`proxy`] but with an optional JSON view. When `json` is
/// `Some`, the daemon's reply is passed through `parser` to produce
/// a [`JValue`], then serialized in the requested format (compact or
/// pretty). When `json` is `None`, the daemon's reply is printed
/// verbatim — the same as `proxy`.
///
/// A transport failure or a daemon `error:` line is a non-zero exit
/// in both modes; the JSON view is only applied to success replies.
/// Under `--json`, a daemon error surfaces as
/// `{"ok":false,"error":"…"}` so a JSON-consuming script sees the
/// same shape across success and failure (and does not have to
/// special-case a non-JSON line).
fn proxy_with_json(
    socket: &str,
    cmd: &str,
    json: Option<JsonFormat>,
    parser: fn(&str) -> JValue,
) -> ExitCode {
    match transport::round_trip(socket, cmd) {
        Ok(body) => {
            let is_error = body.lines().any(|l| l.starts_with("error:"));
            if is_error {
                match json {
                    Some(fmt) => {
                        let mut o = JObject::new();
                        o.push_bool("ok", false);
                        // The first `error:` line carries the reason;
                        // later lines are typically context. Joining
                        // the first error line keeps the JSON shape
                        // flat for the common case.
                        let reason = body
                            .lines()
                            .find(|l| l.starts_with("error:"))
                            .map(|l| l.trim_start_matches("error:").trim())
                            .unwrap_or("");
                        o.push_str("error", reason);
                        let v = JValue::Object(o);
                        print_json(&v, fmt);
                    }
                    None => {
                        print!("{body}");
                        if !body.ends_with('\n') {
                            println!();
                        }
                    }
                }
                return ExitCode::from(1);
            }
            match json {
                Some(fmt) => {
                    let v = parser(&body);
                    print_json(&v, fmt);
                }
                None => {
                    print!("{body}");
                    if !body.ends_with('\n') {
                        println!();
                    }
                }
            }
            ExitCode::SUCCESS
        }
        Err(e) => {
            match json {
                Some(fmt) => {
                    let mut o = JObject::new();
                    o.push_bool("ok", false).push_str("error", &e);
                    let v = JValue::Object(o);
                    print_json(&v, fmt);
                }
                None => eprintln!("lrctl: {e}"),
            }
            ExitCode::from(1)
        }
    }
}

/// Serialise a [`JValue`] to stdout in the requested format, with a
/// trailing newline so shell pipelines see clean output. Lives here
/// (not on `JValue` itself) so the serializer module does not pull
/// `std::io::Write` for a single helper.
fn print_json(v: &JValue, fmt: JsonFormat) {
    let s = match fmt {
        JsonFormat::Compact => v.to_json(),
        JsonFormat::Pretty => v.to_pretty(),
    };
    println!("{s}");
}

// ---------------------------------------------------------------------------
// JSON parsers — one per daemon command. Each parser takes the raw
// line-oriented daemon reply and produces a [`JValue`] that captures
// the same information. The shapes are documented in
// docs/bindings/lrctl-json.md.
// ---------------------------------------------------------------------------

/// Parse the daemon's `status` reply (`key value\n` lines) into a
/// JSON object. The keys are normalised to `snake_case` (the daemon
/// uses `local-as`, the JSON shape uses `local_as`) so a JSON
/// consumer does not have to deal with hyphens-as-key-characters.
fn parse_status_body(body: &str) -> JValue {
    let mut o = JObject::new();
    for line in body.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        // The status body is `key value` (one space). The first
        // space splits the key from the value; the value keeps its
        // own internal spacing.
        let Some((key, value)) = line.split_once(' ') else {
            continue;
        };
        let key = key.replace('-', "_");
        push_typed(&mut o, &key, value);
    }
    JValue::Object(o)
}

/// Parse the daemon's `show status` reply. Same shape as `status`
/// plus a `kind=` summary block and a `memory` line — but the
/// `kind=KIND total=N established=M` lines are nested under a
/// `by_protocol` array, and the `memory rss-bytes=N vsize-bytes=M`
/// line is nested under a `memory` object.
fn parse_show_status_body(body: &str) -> JValue {
    let mut o = JObject::new();
    let mut by_protocol = JArray::new();
    let mut memory = JObject::new();
    for line in body.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        // Indented `  kind=… total=… established=…` line → push to
        // `by_protocol`. The leading spaces were stripped above; the
        // distinguishing token is `kind=`.
        if let Some(rest) = line.strip_prefix("kind=") {
            // rest = "bgp total=1 established=0"
            let mut entry = JObject::new();
            let mut tokens = rest.split_whitespace();
            if let Some(kind) = tokens.next() {
                entry.push_str("kind", kind);
            }
            for tok in tokens {
                if let Some((k, v)) = tok.split_once('=') {
                    push_typed(&mut entry, &k.replace('-', "_"), v);
                }
            }
            by_protocol.push(JValue::Object(entry));
            continue;
        }
        if let Some(rest) = line.strip_prefix("memory ") {
            // rest = "rss-bytes=N vsize-bytes=M"
            for tok in rest.split_whitespace() {
                if let Some((k, v)) = tok.split_once('=') {
                    push_typed(&mut memory, &k.replace('-', "_"), v);
                }
            }
            continue;
        }
        // Fallback: a `key value` line, like the plain `status`
        // command.
        if let Some((key, value)) = line.split_once(' ') {
            let key = key.replace('-', "_");
            push_typed(&mut o, &key, value);
        }
    }
    if !by_protocol.is_empty() {
        o.push("by_protocol", JValue::Array(by_protocol));
    }
    if !memory.is_empty() {
        o.push("memory", JValue::Object(memory));
    }
    JValue::Object(o)
}

/// Parse the daemon's `sessions` reply (one `#N key=value key=value …`
/// line per session) into a JSON array of objects. Each `key=value`
/// pair becomes a field on the per-session object. Keys are
/// normalised to `snake_case`.
fn parse_sessions_body(body: &str) -> JValue {
    let mut a = JArray::new();
    for line in body.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        // A session line starts with `#N ` where N is the numeric
        // handle. The leading `#` is NOT a comment marker (unlike
        // the daemon's `# route installed …` lines, which are
        // routing-log lines and not part of `sessions`). The
        // distinguishing rule: `#` immediately followed by a digit
        // is a session line; `#` followed by anything else is a
        // comment line.
        let line = match line
            .strip_prefix('#')
            .filter(|rest| rest.chars().next().is_some_and(|c| c.is_ascii_digit()))
        {
            Some(rest) => rest,
            None => continue,
        };
        let mut entry = JObject::new();
        let mut tokens = line.split_whitespace();
        if let Some(handle) = tokens.next() {
            entry.push_str("handle", handle);
        }
        for tok in tokens {
            if let Some((k, v)) = tok.split_once('=') {
                push_typed(&mut entry, &k.replace('-', "_"), v);
            }
        }
        a.push(JValue::Object(entry));
    }
    JValue::Array(a)
}

/// Parse the daemon's `show routes count` reply (`total N\n  proto=P
/// routes=M` lines) into a JSON object with `total` and `by_protocol`
/// fields.
fn parse_routes_count_body(body: &str) -> JValue {
    let mut o = JObject::new();
    let mut by_protocol = JArray::new();
    for line in body.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        if let Some(rest) = line.strip_prefix("total ") {
            push_typed(&mut o, "total", rest);
            continue;
        }
        if let Some(rest) = line.strip_prefix("proto=") {
            // rest = "bgp routes=N"
            let mut entry = JObject::new();
            let mut tokens = rest.split_whitespace();
            if let Some(proto) = tokens.next() {
                entry.push_str("protocol", proto);
            }
            for tok in tokens {
                if let Some((k, v)) = tok.split_once('=') {
                    push_typed(&mut entry, &k.replace('-', "_"), v);
                }
            }
            by_protocol.push(JValue::Object(entry));
            continue;
        }
    }
    if !by_protocol.is_empty() {
        o.push("by_protocol", JValue::Array(by_protocol));
    }
    JValue::Object(o)
}

/// Parse the daemon's `show memory` reply (`uptime-secs N\nrss-bytes
/// N\nvsize-bytes N` lines) into a JSON object. Same key-normalisation
/// as `parse_status_body`.
fn parse_show_memory_body(body: &str) -> JValue {
    let mut o = JObject::new();
    for line in body.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        if let Some((k, v)) = line.split_once(' ') {
            push_typed(&mut o, &k.replace('-', "_"), v);
        }
    }
    JValue::Object(o)
}

/// Push a typed `JValue` for `key`/`value` onto `o`. Numeric values
/// parse to `UInt` (so an AS number like `64512` renders as a JSON
/// number, not a string); `true`/`false` parse to `Bool`; the
/// sentinel `unknown` (BIRD parity for "no value available")
/// becomes a JSON `null` so a consumer can distinguish "no value"
/// from the string `"unknown"`. Anything else stays a `Str`.
fn push_typed(o: &mut JObject, key: &str, value: &str) {
    let v = if value == "unknown" {
        JValue::Null
    } else if value == "true" {
        JValue::Bool(true)
    } else if value == "false" {
        JValue::Bool(false)
    } else if let Ok(n) = value.parse::<u64>() {
        JValue::UInt(n)
    } else if let Ok(n) = value.parse::<i64>() {
        JValue::Int(n)
    } else {
        JValue::Str(value.to_string())
    };
    o.push(key, v);
}
