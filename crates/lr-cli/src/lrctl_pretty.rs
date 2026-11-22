//! Pretty (human-readable) output for `lrctl`.
//!
//! The daemon's line-oriented `key value` / `key=value` wire format
//! is what scripts and the JSON view parse. A human at a terminal
//! gets the pretty view instead: section headings, aligned tables,
//! colour-coded session states and human-friendly byte / uptime
//! formatting. The plain wire form stays accessible with
//! `--format=plain` so a shell pipeline can opt out.
//!
//! The pretty renderers take the *raw* daemon reply body — the same
//! bytes `proxy` would print verbatim — and walk it line by line.
//! This keeps the daemon's wire protocol as the single source of
//! truth: a new field added to the daemon's `status` reply shows up
//! in the pretty view through the same parser the JSON view uses,
//! without a second wire format to keep in sync.
//!
//! Colour is ANSI 16-colour, emitted only when the caller passes
//! `color = true`. The main `lrctl` path computes that from the
//! `--color` flag and stdout's TTY status; the unit tests pass
//! `false` so the assertions are deterministic.

use std::fmt::Write as _;

// ---------------------------------------------------------------------------
// ANSI escape codes — the SGR (Select Graphic Rendition) subset that
// every terminal emulator shipped in the last twenty years supports.
// Kept as `&'static str` constants rather than an enum so a renderer
// composes them with `format!` the same way it composes literal text.
// The `color: bool` gate at every call site keeps the no-colour path
// free of escape bytes — a redirect to a file never sees them.
// ---------------------------------------------------------------------------

pub mod ansi {
    pub const RESET: &str = "\x1b[0m";
    pub const BOLD: &str = "\x1b[1m";
    pub const DIM: &str = "\x1b[2m";

    pub const RED: &str = "\x1b[31m";
    pub const GREEN: &str = "\x1b[32m";
    pub const YELLOW: &str = "\x1b[33m";
    pub const BLUE: &str = "\x1b[34m";
    pub const MAGENTA: &str = "\x1b[35m";
    pub const CYAN: &str = "\x1b[36m";
    pub const WHITE: &str = "\x1b[37m";
    pub const GREY: &str = "\x1b[90m";

    pub const BOLD_RED: &str = "\x1b[1;31m";
    pub const BOLD_GREEN: &str = "\x1b[1;32m";
    pub const BOLD_CYAN: &str = "\x1b[1;36m";
}

/// Wrap `s` in `prefix` + `RESET` when `color` is on; otherwise
/// return `s` unchanged. The single helper keeps every renderer's
/// colour path uniform and avoids the `if color { format!(...) } else
/// { s.to_string() }` repetition that previously made the renderers
/// hard to scan.
fn paint(color: bool, prefix: &str, s: &str) -> String {
    if color {
        format!("{prefix}{s}{}", ansi::RESET)
    } else {
        s.to_string()
    }
}

// ---------------------------------------------------------------------------
// Output format and colour mode — resolved once at the top of `main`
// from the parsed flags and stdout's TTY status, then threaded through
// every command handler as a plain `Output` value.
// ---------------------------------------------------------------------------

/// The JSON sub-format selected by `--json` / `--json=pretty`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum JsonFormat {
    Compact,
    Pretty,
}

/// The output format selected by `--format` (or `--json` as the
/// legacy alias for the JSON arm).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Format {
    Plain,
    Pretty,
    Json(JsonFormat),
}

/// Colour emission mode, selected by `--color`.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum ColorMode {
    /// Emit colour when stdout is a TTY (the default).
    #[default]
    Auto,
    /// Emit colour unconditionally (for `less -R` and similar).
    Always,
    /// Suppress colour unconditionally.
    Never,
}

/// Resolved output context: the format plus a single `color: bool`
/// the renderers consult. Colour is enabled iff the format is `Pretty`
/// and (`ColorMode::Always` or (`ColorMode::Auto` and stdout is a
/// TTY)). The plain and JSON paths never carry colour.
#[derive(Clone, Copy, Debug)]
pub struct Output {
    pub format: Format,
    pub color: bool,
}

impl Output {
    /// True iff the format is the pretty, human-readable view.
    #[allow(dead_code)]
    pub fn is_pretty(self) -> bool {
        matches!(self.format, Format::Pretty)
    }

    /// True iff the format is the JSON view (either compact or pretty).
    #[allow(dead_code)]
    pub fn is_json(self) -> bool {
        matches!(self.format, Format::Json(_))
    }
}

/// Pull `--format=plain|pretty|json` / `--format json=pretty` /
/// `--format plain` (with space) out of the arg list. Returns the
/// parsed format (when present) and the remaining args in their
/// original order. The flag may appear anywhere — same rule as
/// `--socket`.
///
/// `--format=json` selects compact JSON; `--format=json:pretty`
/// (or `--format=json=pretty`) selects pretty JSON. The two spellings
/// are accepted because both `--json` and `--format=json` exist, and
/// operators copy whichever shape they last saw in a man page.
pub fn extract_format_flag(args: &[String]) -> (Option<Format>, Vec<String>) {
    let mut format: Option<Format> = None;
    let mut rest = Vec::with_capacity(args.len());
    let mut i = 0;
    while i < args.len() {
        let a = &args[i];
        if a == "--format" {
            if i + 1 < args.len() {
                match parse_format_value(&args[i + 1]) {
                    Ok(f) => format = Some(f),
                    Err(msg) => {
                        eprintln!("error: --format {msg}");
                        std::process::exit(2);
                    }
                }
                i += 2;
                continue;
            } else {
                eprintln!("error: --format requires an argument");
                std::process::exit(2);
            }
        } else if let Some(v) = a.strip_prefix("--format=") {
            match parse_format_value(v) {
                Ok(f) => format = Some(f),
                Err(msg) => {
                    eprintln!("error: --format={v} {msg}");
                    std::process::exit(2);
                }
            }
            i += 1;
            continue;
        }
        rest.push(a.clone());
        i += 1;
    }
    (format, rest)
}

/// Parse one `--format` value. `json` selects compact JSON; `json:pretty`
/// or `json=pretty` selects pretty JSON. Anything else is an error
/// with a message that names the valid set so a typo is loud.
fn parse_format_value(v: &str) -> Result<Format, String> {
    match v {
        "plain" => Ok(Format::Plain),
        "pretty" => Ok(Format::Pretty),
        "json" | "json:compact" => Ok(Format::Json(JsonFormat::Compact)),
        "json:pretty" | "json=pretty" => Ok(Format::Json(JsonFormat::Pretty)),
        other => Err(format!(
            "value '{other}' is not valid (try plain, pretty, json or json:pretty)"
        )),
    }
}

/// Pull `--color=auto|always|never` / `--color auto` (with space) out
/// of the arg list. Returns the parsed mode and the remaining args in
/// their original order.
pub fn extract_color_flag(args: &[String]) -> (Option<ColorMode>, Vec<String>) {
    let mut mode: Option<ColorMode> = None;
    let mut rest = Vec::with_capacity(args.len());
    let mut i = 0;
    while i < args.len() {
        let a = &args[i];
        if a == "--color" {
            if i + 1 < args.len() {
                match parse_color_value(&args[i + 1]) {
                    Ok(m) => mode = Some(m),
                    Err(msg) => {
                        eprintln!("error: --color {msg}");
                        std::process::exit(2);
                    }
                }
                i += 2;
                continue;
            } else {
                eprintln!("error: --color requires an argument");
                std::process::exit(2);
            }
        } else if let Some(v) = a.strip_prefix("--color=") {
            match parse_color_value(v) {
                Ok(m) => mode = Some(m),
                Err(msg) => {
                    eprintln!("error: --color={v} {msg}");
                    std::process::exit(2);
                }
            }
            i += 1;
            continue;
        }
        rest.push(a.clone());
        i += 1;
    }
    (mode, rest)
}

fn parse_color_value(v: &str) -> Result<ColorMode, String> {
    match v {
        "auto" => Ok(ColorMode::Auto),
        "always" => Ok(ColorMode::Always),
        "never" | "none" | "off" => Ok(ColorMode::Never),
        other => Err(format!(
            "value '{other}' is not valid (try auto, always or never)"
        )),
    }
}

/// Resolve the final [`Output`] from the parsed flags and stdout's
/// TTY status. Precedence: `--format` wins over `--json` (so
/// `--format=plain --json` is plain — the operator asked twice and
/// the more specific request wins). When neither flag is given, the
/// default is `Pretty` when stdout is a TTY (a human at a terminal
/// gets the readable view) and `Plain` otherwise (a shell pipeline
/// gets the scriptable wire form).
///
/// Colour: enabled iff the format is `Pretty` and (`Always` or (`Auto`
/// and `is_tty`)). The plain and JSON paths never carry colour.
pub fn resolve_output(
    format: Option<Format>,
    json: Option<JsonFormat>,
    color: Option<ColorMode>,
    is_tty: bool,
) -> Output {
    let resolved = match format {
        Some(f) => f,
        None => match json {
            Some(j) => Format::Json(j),
            None => {
                if is_tty {
                    Format::Pretty
                } else {
                    Format::Plain
                }
            }
        },
    };
    let color = match resolved {
        Format::Pretty => match color.unwrap_or_default() {
            ColorMode::Always => true,
            ColorMode::Auto => is_tty,
            ColorMode::Never => false,
        },
        _ => false,
    };
    Output {
        format: resolved,
        color,
    }
}

// ---------------------------------------------------------------------------
// Pretty renderers — one per daemon command body shape. Each takes
// the raw daemon reply and a `color: bool`, returns a String ready
// for `print!`.
// ---------------------------------------------------------------------------

/// `status` — the daemon's `key value\n` block. Pretty view lays it
/// out as a header line (banner + AS pair) followed by aligned
/// `key  value` rows. Protocol-specific extra lines (`ldp-adjacencies
/// N`, `ospf-sr …`) are kept verbatim under a trailing "More" section
/// so the pretty view never drops information the daemon emitted.
pub fn render_status(body: &str, color: bool) -> String {
    let parsed = parse_kv_block(body);
    render_status_from(&parsed, color)
}

/// `show status` — extends the plain `status` block with
/// `sessions N established M`, the per-protocol `kind=… total=…
/// established=…` breakdown, and the `memory rss-bytes=…
/// vsize-bytes=…` line. Pretty view adds a Sessions and Memory
/// section.
pub fn render_show_status(body: &str, color: bool) -> String {
    let parsed = parse_show_status_block(body);
    render_show_status_from(&parsed, color)
}

/// `sessions` / `show sessions` — one `#N key=value …` line per
/// session. Pretty view lays them out as a table with a header row.
/// `show sessions` carries the extended fields (transitions, uptime,
/// last error); `sessions` carries only the legacy fields. The same
/// renderer handles both: it picks the columns present in the first
/// session line.
pub fn render_sessions(body: &str, color: bool) -> String {
    let rows = parse_session_lines(body);
    render_sessions_table(&rows, color)
}

/// `show sessions detail` — the table above plus a per-session
/// multi-line detail block (the `stats:` / `last-error:` /
/// `messages:` lines). Pretty view appends the detail block under
/// each table row, indented.
pub fn render_sessions_detail(body: &str, color: bool) -> String {
    render_sessions_detail_block(body, color)
}

/// `show session <handle>` — the deep dive for one session. Pretty
/// view renders it as a key-value block plus a detail block.
pub fn render_show_session(body: &str, color: bool) -> String {
    render_show_session_block(body, color)
}

/// `show routes count` / `routes count` — `total N` plus
/// `proto=P routes=M` lines. Pretty view renders it as a small
/// table.
pub fn render_routes_count(body: &str, color: bool) -> String {
    let parsed = parse_routes_count_body(body);
    render_routes_count_from(&parsed, color)
}

/// `show memory` — `uptime-secs N`, `rss-bytes N`, `vsize-bytes N`.
/// Pretty view formats uptime and bytes human-friendly.
pub fn render_show_memory(body: &str, color: bool) -> String {
    let parsed = parse_kv_block(body);
    render_show_memory_from(&parsed, color)
}

/// `routes` / `routes show` — one route per line. Pretty view lays
/// them out as a table.
pub fn render_routes(body: &str, color: bool) -> String {
    render_routes_table(body, color)
}

/// `show roa` — `roa-total N static S rtr R` header plus
/// `prefix max-len origin-as source` per-entry lines. Pretty view
/// renders the header and the per-entry table.
pub fn render_show_roa(body: &str, color: bool) -> String {
    render_roa_block(body, color)
}

/// `shutdown status` — `state=X remaining=N` line. Pretty view
/// formats it as a small block.
pub fn render_shutdown_status(body: &str, color: bool) -> String {
    render_shutdown_status_block(body, color)
}

/// `ping` — `ok Nms` / `fail Nms: <reason>`. Pretty view adds
/// colour and a symbol.
pub fn render_ping(ok: bool, ms: u128, detail: Option<&str>, color: bool) -> String {
    render_ping_result(ok, ms, detail, color)
}

/// Render a daemon `error:` reply under the pretty view. The plain
/// and JSON paths handle errors their own way; this is for pretty
/// mode only — bold-red `Error:` prefix plus the reason.
pub fn render_error(body: &str, color: bool) -> String {
    let mut out = String::with_capacity(body.len() + 16);
    for line in body.lines() {
        if let Some(rest) = line.strip_prefix("error:") {
            let _ = writeln!(
                out,
                "{} {}",
                paint(color, ansi::BOLD_RED, "Error:"),
                rest.trim()
            );
        } else {
            let _ = writeln!(out, "{line}");
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Field-level rendering helpers.
// ---------------------------------------------------------------------------

/// A parsed `key value` block: ordered list of `(key, value)` pairs,
/// preserving the daemon's emission order so the pretty view shows
/// `version` above `local-as` above `peer-as` (matching BIRD's
/// `show status`).
#[derive(Default)]
struct KvBlock {
    pairs: Vec<(String, String)>,
    /// Lines that did not match the `key value` shape (comments,
    /// protocol-specific extras). Kept in encounter order so the
    /// pretty view can surface them in a trailing section.
    extras: Vec<String>,
}

impl KvBlock {
    fn get(&self, key: &str) -> Option<&str> {
        self.pairs
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.as_str())
    }
}

fn parse_kv_block(body: &str) -> KvBlock {
    let mut block = KvBlock::default();
    for line in body.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some((k, v)) = line.split_once(' ') {
            block.pairs.push((k.to_string(), v.to_string()));
        } else {
            block.extras.push(line.to_string());
        }
    }
    block
}

/// A parsed `show status` block: the plain `key value` lines plus
/// the structured `sessions N established M`, per-protocol
/// `kind=… total=… established=…` entries and the
/// `memory rss-bytes=… vsize-bytes=…` line.
struct ShowStatusBlock {
    base: KvBlock,
    sessions_total: Option<u64>,
    sessions_established: Option<u64>,
    by_protocol: Vec<(String, u64, u64)>,
    memory_rss: Option<String>,
    memory_vsize: Option<String>,
}

fn parse_show_status_block(body: &str) -> ShowStatusBlock {
    let mut base = KvBlock::default();
    let mut sessions_total = None;
    let mut sessions_established = None;
    let mut by_protocol = Vec::new();
    let mut memory_rss = None;
    let mut memory_vsize = None;

    for line in body.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some(rest) = line.strip_prefix("kind=") {
            // rest = "bgp total=1 established=0"
            let mut tokens = rest.split_whitespace();
            let kind = tokens.next().unwrap_or("").to_string();
            let mut total = 0u64;
            let mut established = 0u64;
            for tok in tokens {
                if let Some((k, v)) = tok.split_once('=') {
                    if k == "total" {
                        total = v.parse().unwrap_or(0);
                    } else if k == "established" {
                        established = v.parse().unwrap_or(0);
                    }
                }
            }
            by_protocol.push((kind, total, established));
            continue;
        }
        if let Some(rest) = line.strip_prefix("memory ") {
            for tok in rest.split_whitespace() {
                if let Some((k, v)) = tok.split_once('=') {
                    if k == "rss-bytes" {
                        memory_rss = Some(v.to_string());
                    } else if k == "vsize-bytes" {
                        memory_vsize = Some(v.to_string());
                    }
                }
            }
            continue;
        }
        // `sessions N established M` — a single line where two
        // counters are jammed into one `key value` shape. Pull them
        // apart so the pretty view can show them aligned.
        if let Some(rest) = line.strip_prefix("sessions ") {
            let mut tokens = rest.split_whitespace();
            if let Some(t) = tokens.next() {
                sessions_total = t.parse().ok();
            }
            if let Some(rest2) = tokens.next() {
                if let Some(v) = rest2.strip_prefix("established=") {
                    sessions_established = v.parse().ok();
                } else if rest2 == "established" {
                    sessions_established = tokens.next().and_then(|v| v.parse().ok());
                }
            }
            continue;
        }
        if let Some((k, v)) = line.split_once(' ') {
            base.pairs.push((k.to_string(), v.to_string()));
        } else {
            base.extras.push(line.to_string());
        }
    }

    ShowStatusBlock {
        base,
        sessions_total,
        sessions_established,
        by_protocol,
        memory_rss,
        memory_vsize,
    }
}

/// A parsed session line — the `#N key=value key=value …` shape. The
/// handle is the first token; the rest is collected into an ordered
/// map so the renderer can pick columns by name without re-parsing.
struct SessionLine {
    handle: String,
    fields: Vec<(String, String)>,
}

impl SessionLine {
    fn get(&self, key: &str) -> Option<&str> {
        self.fields
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.as_str())
    }
}

fn parse_session_lines(body: &str) -> Vec<SessionLine> {
    let mut out = Vec::new();
    for line in body.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        // A session line starts with `#N ` where N is the numeric
        // handle. The leading `#` is NOT a comment marker (the
        // daemon's `# route installed …` lines are routing-log lines,
        // not sessions). `#` followed by a digit is a session line.
        let Some(rest) = line
            .strip_prefix('#')
            .filter(|r| r.chars().next().is_some_and(|c| c.is_ascii_digit()))
        else {
            continue;
        };
        let mut tokens = rest.split_whitespace();
        let handle = tokens.next().unwrap_or("").to_string();
        let mut fields = Vec::new();
        for tok in tokens {
            if let Some((k, v)) = tok.split_once('=') {
                fields.push((k.to_string(), v.to_string()));
            }
        }
        out.push(SessionLine { handle, fields });
    }
    out
}

/// A parsed `show routes count` block: the total plus the per-protocol
/// `(proto, routes)` entries.
struct RoutesCountBlock {
    total: Option<u64>,
    by_protocol: Vec<(String, u64)>,
}

fn parse_routes_count_body(body: &str) -> RoutesCountBlock {
    let mut total = None;
    let mut by_protocol = Vec::new();
    for line in body.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        if let Some(rest) = line.strip_prefix("total ") {
            total = rest.parse().ok();
            continue;
        }
        if let Some(rest) = line.strip_prefix("proto=") {
            let mut tokens = rest.split_whitespace();
            let proto = tokens.next().unwrap_or("").to_string();
            let mut routes = 0u64;
            for tok in tokens {
                if let Some((k, v)) = tok.split_once('=') {
                    if k == "routes" {
                        routes = v.parse().unwrap_or(0);
                    }
                }
            }
            by_protocol.push((proto, routes));
        }
    }
    RoutesCountBlock { total, by_protocol }
}

// ---------------------------------------------------------------------------
// Renderers — the pretty-format builders. Each consumes the parsed
// block above and emits the human-readable string.
// ---------------------------------------------------------------------------

fn render_status_from(block: &KvBlock, color: bool) -> String {
    let mut out = String::with_capacity(512);
    let version = block.get("version").unwrap_or("?");
    let local_as = block.get("local-as").unwrap_or("?");
    let peer_as = block.get("peer-as").unwrap_or("?");
    // Banner line: bold "librouting lr-daemon" + version + AS pair,
    // colour-coded so the operator's eye lands on the identity at a
    // glance. The AS pair uses the same cyan the rest of the field
    // labels use so the colour budget stays small.
    let banner = paint(color, ansi::BOLD, "librouting lr-daemon");
    let version_field = paint(color, ansi::CYAN, version);
    let _ = writeln!(
        out,
        "{banner}  {version_field}    AS {local_as} → AS {peer_as}"
    );
    let _ = writeln!(out);

    // Identity section.
    let label = |s: &str| paint(color, ansi::GREY, s);
    for (k, v) in &block.pairs {
        if k == "version" || k == "local-as" || k == "peer-as" {
            continue;
        }
        if k == "router-id" {
            let _ = writeln!(
                out,
                "  {}   {}",
                label(&render_label("router-id")),
                paint(color, ansi::BOLD, v)
            );
            continue;
        }
        let _ = writeln!(
            out,
            "  {}   {}",
            label(&render_label(k)),
            render_value(k, v, color)
        );
    }

    // Trailing extras (protocol-specific lines the daemon injected
    // through `status_lines`). Kept verbatim under a "More" heading
    // so the pretty view never drops information.
    if !block.extras.is_empty() {
        let _ = writeln!(out);
        let _ = writeln!(out, "{}", paint(color, ansi::BOLD, "More"));
        for line in &block.extras {
            let _ = writeln!(out, "  {line}");
        }
    }
    out
}

fn render_show_status_from(block: &ShowStatusBlock, color: bool) -> String {
    let mut out = String::with_capacity(768);
    // Identity half — same shape as `status`.
    let banner = paint(color, ansi::BOLD, "librouting lr-daemon");
    let version = block.base.get("version").unwrap_or("?");
    let local_as = block.base.get("local-as").unwrap_or("?");
    let peer_as = block.base.get("peer-as").unwrap_or("?");
    let version_field = paint(color, ansi::CYAN, version);
    let _ = writeln!(
        out,
        "{banner}  {version_field}    AS {local_as} → AS {peer_as}"
    );
    let _ = writeln!(out);

    let label = |s: &str| paint(color, ansi::GREY, s);
    for (k, v) in &block.base.pairs {
        if k == "version" || k == "local-as" || k == "peer-as" {
            continue;
        }
        let _ = writeln!(
            out,
            "  {}   {}",
            label(&render_label(k)),
            render_value(k, v, color)
        );
    }

    // Sessions section.
    let _ = writeln!(out);
    let total = block.sessions_total.unwrap_or(0);
    let established = block.sessions_established.unwrap_or(0);
    let _ = writeln!(
        out,
        "{}  {} total, {} established",
        paint(color, ansi::BOLD, "Sessions"),
        paint(color, ansi::BOLD, &total.to_string()),
        paint(color, ansi::BOLD_GREEN, &established.to_string())
    );
    for (kind, total, established) in &block.by_protocol {
        let _ = writeln!(
            out,
            "  {}   total={}  established={}",
            paint(color, ansi::CYAN, kind),
            total,
            paint(color, ansi::GREEN, &established.to_string())
        );
    }

    // RIB section.
    if let Some(rib) = block.base.get("rib-entries") {
        let _ = writeln!(out);
        let _ = writeln!(
            out,
            "{}  {} entries",
            paint(color, ansi::BOLD, "RIB"),
            paint(color, ansi::BOLD, rib)
        );
    }

    // Memory section.
    let _ = writeln!(out);
    let rss = block
        .memory_rss
        .as_deref()
        .and_then(|s| s.parse::<u64>().ok());
    let vsize = block
        .memory_vsize
        .as_deref()
        .and_then(|s| s.parse::<u64>().ok());
    let rss_str = rss
        .map(fmt_bytes_human)
        .unwrap_or_else(|| "unknown".to_string());
    let vsize_str = vsize
        .map(fmt_bytes_human)
        .unwrap_or_else(|| "unknown".to_string());
    let _ = writeln!(
        out,
        "{}  RSS {}  VSize {}",
        paint(color, ansi::BOLD, "Memory"),
        paint(color, ansi::BOLD, &rss_str),
        paint(color, ansi::BOLD, &vsize_str)
    );

    // Trailing extras.
    if !block.base.extras.is_empty() {
        let _ = writeln!(out);
        let _ = writeln!(out, "{}", paint(color, ansi::BOLD, "More"));
        for line in &block.base.extras {
            let _ = writeln!(out, "  {line}");
        }
    }
    out
}

fn render_show_memory_from(block: &KvBlock, color: bool) -> String {
    let mut out = String::with_capacity(256);
    let _ = writeln!(out, "{}", paint(color, ansi::BOLD, "Memory"));
    let _ = writeln!(out);
    let label = |s: &str| paint(color, ansi::GREY, s);
    for (k, v) in &block.pairs {
        let value = match k.as_str() {
            "uptime-secs" => fmt_uptime(v.parse::<u64>().unwrap_or(0)),
            "rss-bytes" | "vsize-bytes" => v
                .parse::<u64>()
                .map(fmt_bytes_human)
                .unwrap_or_else(|_| v.clone()),
            _ => v.clone(),
        };
        let _ = writeln!(out, "  {}   {}", label(&render_label(k)), value);
    }
    out
}

/// Render a sessions table. Columns are picked from the first session
/// line — `sessions` carries the legacy fields, `show sessions` adds
/// the extended stats. Both flow through the same renderer.
fn render_sessions_table(rows: &[SessionLine], color: bool) -> String {
    if rows.is_empty() {
        return format!(
            "{}\n  (no sessions)\n",
            paint(color, ansi::BOLD, "Sessions")
        );
    }
    // Column order: a stable, human-eye-pleasing order. Each column
    // is included iff at least one session line carries it. The
    // handle column is always present (it is the row's first token,
    // stored separately from the `key=value` fields).
    let preferred: &[&str] = &[
        "kind",
        "local-as",
        "peer-as",
        "state",
        "established",
        "peer-id",
        "hold-time",
        "adj-rib-in",
        "updates-rx",
        "updates-tx",
        "transitions",
        "uptime-ms",
        "last-error",
        "last-error-at-ms",
        "last-keepalive-rx-ms",
    ];
    let present: Vec<&str> = preferred
        .iter()
        .copied()
        .filter(|name| rows.iter().any(|r| r.get(name).is_some()))
        .collect();

    // Column 0 is HANDLE, then the present columns. The header row
    // is uppercased with hyphens turned to spaces so `local-as`
    // reads as `LOCAL AS`.
    let mut headers: Vec<String> = vec!["HANDLE".to_string()];
    headers.extend(present.iter().map(|s| s.to_uppercase().replace('-', " ")));
    let mut widths: Vec<usize> = headers.iter().map(|h| h.len()).collect();
    for r in rows {
        let handle_str = format!("#{}", r.handle);
        widths[0] = widths[0].max(render_visible_len(&handle_str));
        for (i, name) in present.iter().enumerate() {
            let v = r.get(name).unwrap_or("-");
            widths[i + 1] = widths[i + 1].max(render_visible_len(v));
        }
    }

    let mut out = String::with_capacity(rows.len() * (widths.iter().sum::<usize>() + 16));
    // Header row, dim.
    let _ = write!(
        out,
        "{}",
        pad_right(&paint(color, ansi::DIM, &headers[0]), widths[0])
    );
    for (i, h) in headers.iter().enumerate().skip(1) {
        let _ = write!(
            out,
            "  {}",
            pad_right(&paint(color, ansi::DIM, h), widths[i])
        );
    }
    let _ = writeln!(out);
    // Data rows.
    for r in rows {
        let handle_str = format!("#{}", r.handle);
        let _ = write!(out, "{}", pad_right(&handle_str, widths[0]));
        for (i, name) in present.iter().enumerate() {
            let raw = r.get(name).unwrap_or("-");
            let value = render_field(name, raw, color);
            let _ = write!(out, "  {}", pad_right(&value, widths[i + 1]));
        }
        let _ = writeln!(out);
    }
    out
}

/// `show sessions detail` — the table plus per-session detail blocks.
/// The daemon's wire shape interleaves a one-line summary with a
/// multi-line `  stats: …` / `  last-error: …` / `  messages: …`
/// block; the pretty view regroups them as one block per session.
fn render_sessions_detail_block(body: &str, color: bool) -> String {
    // The body is a sequence of:
    //   #N kind=… …
    //     stats: established-at-ms=… last-transition-at-ms=… state-transitions=…
    //     last-error: kind=… at-ms=…
    //     last-keepalive-rx-ms=…
    //     [peer-fqdn …]
    //     [peer-software-version …]
    //     messages: open rx=… tx=… …
    //
    // We split on the leading `#N ` line: each session's block runs
    // from one such line to the next.
    let mut sections: Vec<(String, Vec<String>)> = Vec::new();
    for line in body.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        if let Some(rest) = trimmed
            .strip_prefix('#')
            .filter(|r| r.chars().next().is_some_and(|c| c.is_ascii_digit()))
        {
            let handle = rest.split_whitespace().next().unwrap_or("").to_string();
            sections.push((handle, vec![trimmed.to_string()]));
        } else if let Some(last) = sections.last_mut() {
            last.1.push(trimmed.to_string());
        }
    }
    let mut out = String::with_capacity(sections.len() * 256);
    for (handle, lines) in &sections {
        let _ = writeln!(
            out,
            "{}",
            paint(color, ansi::BOLD_CYAN, &format!("#{}", handle))
        );
        for line in lines {
            // Render the leading key label dim and the value bright
            // for the `key: …` and `key …` shapes; everything else
            // verbatim.
            if let Some((k, v)) = line.split_once(':') {
                let _ = writeln!(
                    out,
                    "  {}  {}",
                    paint(color, ansi::GREY, &format!("{}:", k.trim())),
                    v.trim()
                );
            } else if let Some((k, v)) = line.split_once(' ') {
                let _ = writeln!(out, "  {}  {}", paint(color, ansi::GREY, k), v);
            } else {
                let _ = writeln!(out, "  {line}");
            }
        }
        let _ = writeln!(out);
    }
    out
}

/// `show session <handle>` — a single session's deep dive. Pretty
/// view lays it out as a key-value block with a trailing detail.
fn render_show_session_block(body: &str, color: bool) -> String {
    let mut out = String::with_capacity(384);
    let mut detail: Vec<String> = Vec::new();
    let mut started_detail = false;
    for line in body.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        if line.starts_with("error:") {
            return render_error(line, color);
        }
        if line.starts_with("stats:") || line.starts_with("last-error:") || started_detail {
            started_detail = true;
            detail.push(line.to_string());
            continue;
        }
        if let Some((k, v)) = line.split_once(' ') {
            let _ = writeln!(
                out,
                "  {}   {}",
                paint(color, ansi::GREY, &render_label(k)),
                render_value(k, v, color)
            );
        }
    }
    if !detail.is_empty() {
        let _ = writeln!(out);
        let _ = writeln!(out, "{}", paint(color, ansi::BOLD, "Detail"));
        for line in &detail {
            if let Some((k, v)) = line.split_once(':') {
                let _ = writeln!(
                    out,
                    "  {}  {}",
                    paint(color, ansi::GREY, &format!("{}:", k.trim())),
                    v.trim()
                );
            } else if let Some((k, v)) = line.split_once(' ') {
                let _ = writeln!(out, "  {}  {}", paint(color, ansi::GREY, k), v);
            } else {
                let _ = writeln!(out, "  {line}");
            }
        }
    }
    out
}

/// `show routes count` — total plus per-protocol table.
fn render_routes_count_from(block: &RoutesCountBlock, color: bool) -> String {
    let mut out = String::with_capacity(128);
    let total = block.total.unwrap_or(0);
    let _ = writeln!(
        out,
        "{}  {} routes",
        paint(color, ansi::BOLD, "Total"),
        paint(color, ansi::BOLD, &total.to_string())
    );
    if !block.by_protocol.is_empty() {
        let _ = writeln!(out);
        // Two columns: PROTOCOL / ROUTES, aligned.
        let proto_w = block
            .by_protocol
            .iter()
            .map(|(p, _)| p.len())
            .max()
            .unwrap_or(8)
            .max(8);
        let _ = writeln!(
            out,
            "  {}  {}",
            paint(color, ansi::DIM, &pad_right("PROTOCOL", proto_w)),
            paint(color, ansi::DIM, "ROUTES")
        );
        for (proto, routes) in &block.by_protocol {
            let _ = writeln!(
                out,
                "  {}  {}",
                pad_right(&paint(color, ansi::CYAN, proto), proto_w),
                routes
            );
        }
    }
    out
}

/// `routes` — one route per line, table-formatted.
fn render_routes_table(body: &str, color: bool) -> String {
    // Each route line is `prefix via next-hop proto=P metric=N path-id=N[ label=L]`.
    // Parse into columns, then render as an aligned table.
    #[derive(Default)]
    struct Row {
        prefix: String,
        next_hop: String,
        proto: String,
        metric: String,
        path_id: String,
        label: Option<String>,
    }
    let mut rows: Vec<Row> = Vec::new();
    for line in body.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with("error:") {
            continue;
        }
        // Tokenize on whitespace; the first token is the prefix.
        let mut tokens = line.split_whitespace();
        let prefix = tokens.next().unwrap_or("").to_string();
        let mut row = Row {
            prefix,
            ..Default::default()
        };
        while let Some(tok) = tokens.next() {
            if tok == "via" {
                if let Some(nh) = tokens.next() {
                    row.next_hop = nh.to_string();
                }
            } else if let Some(v) = tok.strip_prefix("proto=") {
                row.proto = v.to_string();
            } else if let Some(v) = tok.strip_prefix("metric=") {
                row.metric = v.to_string();
            } else if let Some(v) = tok.strip_prefix("path-id=") {
                row.path_id = v.to_string();
            } else if let Some(v) = tok.strip_prefix("label=") {
                row.label = Some(v.to_string());
            }
        }
        rows.push(row);
    }
    if rows.is_empty() {
        return format!("{}\n  (no routes)\n", paint(color, ansi::BOLD, "RIB"));
    }
    let mut out = String::with_capacity(rows.len() * 96);
    // Compute column widths.
    let prefix_w = rows
        .iter()
        .map(|r| r.prefix.len())
        .max()
        .unwrap_or(6)
        .max(6);
    let next_hop_w = rows
        .iter()
        .map(|r| r.next_hop.len())
        .max()
        .unwrap_or(8)
        .max(8);
    let proto_w = rows.iter().map(|r| r.proto.len()).max().unwrap_or(5).max(5);
    let has_label = rows.iter().any(|r| r.label.is_some());
    let _ = writeln!(
        out,
        "{}  {}  {}  {}  {}{}",
        paint(color, ansi::DIM, &pad_right("PREFIX", prefix_w)),
        paint(color, ansi::DIM, &pad_right("NEXT-HOP", next_hop_w)),
        paint(color, ansi::DIM, &pad_right("PROTO", proto_w)),
        paint(color, ansi::DIM, "METRIC"),
        paint(color, ansi::DIM, "  PATH-ID"),
        if has_label {
            format!("  {}", paint(color, ansi::DIM, "LABEL"))
        } else {
            String::new()
        }
    );
    for r in &rows {
        let proto_color = match r.proto.as_str() {
            "Bgp" => ansi::CYAN,
            "Babel" => ansi::MAGENTA,
            "Ospf" | "Ospf3" => ansi::BLUE,
            "Direct" | "Connected" => ansi::GREY,
            "Static" => ansi::YELLOW,
            _ => ansi::WHITE,
        };
        let _ = writeln!(
            out,
            "{}  {}  {}  {}  {}{}",
            pad_right(&r.prefix, prefix_w),
            pad_right(&r.next_hop, next_hop_w),
            pad_right(&paint(color, proto_color, &r.proto), proto_w),
            pad_right(&r.metric, 6),
            pad_right(&r.path_id, 7),
            match &r.label {
                Some(l) => format!("  {l}"),
                None => String::new(),
            }
        );
    }
    out
}

/// `show roa` — the daemon's `roa_view` renderer already produces a
/// summary line + per-entry table; the pretty view surfaces the
/// summary in colour and keeps the per-entry rows aligned.
fn render_roa_block(body: &str, color: bool) -> String {
    let mut out = String::with_capacity(body.len() + 32);
    for line in body.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        if let Some(rest) = trimmed.strip_prefix("roa-total ") {
            let _ = writeln!(
                out,
                "{}  {}",
                paint(color, ansi::BOLD, "ROA total"),
                paint(color, ansi::BOLD, rest)
            );
        } else if trimmed.starts_with("prefix ") {
            // Header row of the per-entry table — keep verbatim.
            let _ = writeln!(out, "{}", paint(color, ansi::DIM, trimmed));
        } else {
            let _ = writeln!(out, "{trimmed}");
        }
    }
    out
}

/// `shutdown status` — `state=X remaining=N`.
fn render_shutdown_status_block(body: &str, color: bool) -> String {
    let mut state = "?";
    let mut remaining = "?";
    for tok in body.split_whitespace() {
        if let Some(v) = tok.strip_prefix("state=") {
            state = v;
        } else if let Some(v) = tok.strip_prefix("remaining=") {
            remaining = v;
        }
    }
    let (state_color, state_str) = match state {
        "running" => (ansi::GREEN, "Running"),
        "draining" => (ansi::YELLOW, "Draining"),
        "drained" => (ansi::GREY, "Drained"),
        _ => (ansi::WHITE, state),
    };
    format!(
        "{}  {}  ({} routes remaining)\n",
        paint(color, ansi::BOLD, "Drain"),
        paint(color, state_color, state_str),
        paint(color, ansi::BOLD, remaining)
    )
}

/// `ping` — `ok Nms` / `fail Nms: <reason>`.
fn render_ping_result(ok: bool, ms: u128, detail: Option<&str>, color: bool) -> String {
    let symbol = if ok { "✓" } else { "✗" };
    let symbol_color = if ok { ansi::BOLD_GREEN } else { ansi::BOLD_RED };
    let word = if ok { "ok" } else { "fail" };
    let word_color = if ok { ansi::GREEN } else { ansi::RED };
    match detail {
        Some(d) => format!(
            "{} {} {}ms — {}\n",
            paint(color, symbol_color, symbol),
            paint(color, word_color, word),
            ms,
            d
        ),
        None => format!(
            "{} {} {}ms\n",
            paint(color, symbol_color, symbol),
            paint(color, word_color, word),
            ms
        ),
    }
}

// ---------------------------------------------------------------------------
// Field-level rendering helpers.
// ---------------------------------------------------------------------------

/// Map a daemon key to a pretty label. The daemon emits kebab-case
/// (`local-as`, `peer-as`); the pretty view keeps that shape but
/// title-cases the first letter for the row label.
fn render_label(key: &str) -> String {
    let mut chars = key.chars();
    match chars.next() {
        Some(first) => format!("{}{}", first.to_uppercase(), chars.as_str()),
        None => String::new(),
    }
}

/// Render a single field value with field-specific formatting: AS
/// numbers, uptime, memory, deprecation notices, dialect names.
fn render_value(key: &str, value: &str, color: bool) -> String {
    match key {
        "uptime-secs" => fmt_uptime(value.parse::<u64>().unwrap_or(0)),
        "config-dialect" => match value {
            "toml" => paint(color, ansi::YELLOW, value),
            "lr" => paint(color, ansi::GREEN, value),
            "bird" | "frr" => paint(color, ansi::CYAN, value),
            _ => value.to_string(),
        },
        "config-deprecation" => paint(color, ansi::YELLOW, value),
        "config" => paint(color, ansi::DIM, value),
        "router-id" => paint(color, ansi::BOLD, value),
        _ => value.to_string(),
    }
}

/// Render a session-table field with state-aware colour.
fn render_field(name: &str, value: &str, color: bool) -> String {
    if name == "state" {
        let v = match value {
            "Established" => paint(color, ansi::BOLD_GREEN, value),
            "Active" | "Connect" | "OpenSent" | "OpenConfirm" => paint(color, ansi::YELLOW, value),
            "Idle" => paint(color, ansi::RED, value),
            _ => value.to_string(),
        };
        return v;
    }
    if name == "established" {
        return match value {
            "true" => paint(color, ansi::GREEN, "yes"),
            "false" => paint(color, ansi::GREY, "no"),
            _ => value.to_string(),
        };
    }
    if name == "last-error" {
        return match value {
            "none" | "" | "-" => paint(color, ansi::GREY, "none"),
            _ => paint(color, ansi::YELLOW, value),
        };
    }
    if name == "kind" {
        return paint(color, ansi::CYAN, value);
    }
    value.to_string()
}

/// Pad a string with spaces on the right to `width`. ANSI escape
/// bytes are NOT counted towards the width (they are zero-width on
/// the terminal) — see `render_visible_len`.
fn pad_right(s: &str, width: usize) -> String {
    let visible = render_visible_len(s);
    if visible >= width {
        s.to_string()
    } else {
        let pad = width - visible;
        format!("{s}{}", " ".repeat(pad))
    }
}

/// Visible width of `s` excluding ANSI escape sequences. Used to
/// align columns whose values carry colour codes.
fn render_visible_len(s: &str) -> usize {
    let mut len = 0;
    let mut in_escape = false;
    for b in s.bytes() {
        if in_escape {
            if b == b'm' {
                in_escape = false;
            }
            continue;
        }
        if b == 0x1b {
            in_escape = true;
            continue;
        }
        len += 1;
    }
    len
}

/// Format a byte count as a human-friendly string with binary units
/// (KiB, MiB, GiB). 0 maps to "0 B" so an operator sees a real zero
/// rather than an empty string. `Option<u64>::None` should already
/// have been mapped to "unknown" by the caller.
fn fmt_bytes_human(bytes: u64) -> String {
    const UNITS: &[(&str, u64)] = &[
        ("TiB", 1024u64 * 1024 * 1024 * 1024),
        ("GiB", 1024u64 * 1024 * 1024),
        ("MiB", 1024u64 * 1024),
        ("KiB", 1024),
    ];
    if bytes == 0 {
        return "0 B".to_string();
    }
    for (unit, threshold) in UNITS {
        if bytes >= *threshold {
            let value = bytes as f64 / *threshold as f64;
            // One decimal of precision matches `free -h` / `top`: the
            // operator sees "12.3 MiB" rather than "12345678 B".
            return format!("{:.1} {}", value, unit);
        }
    }
    format!("{} B", bytes)
}

/// Format a duration in seconds as `1h 2m 3s` / `2m 3s` / `3s`. The
/// daemon emits `uptime-secs N` as a bare integer; the pretty view
/// surfaces the human-friendly form so an operator's eye lands on
/// "this daemon has been up for two hours" rather than "7200".
fn fmt_uptime(secs: u64) -> String {
    if secs == 0 {
        return "0s".to_string();
    }
    let h = secs / 3600;
    let m = (secs % 3600) / 60;
    let s = secs % 60;
    let mut out = String::with_capacity(16);
    if h > 0 {
        let _ = write!(out, "{h}h ");
    }
    if m > 0 || h > 0 {
        let _ = write!(out, "{m}m ");
    }
    let _ = write!(out, "{s}s");
    out
}

// ---------------------------------------------------------------------------
// Unit tests — exercise the pretty renderers without spawning the
// daemon. The assertions check both the colourless path (the
// canonical shape a redirect sees) and the colour path (the bytes a
// TTY sees, including the escape codes).
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// A plain `status` body renders under the pretty view as the
    /// banner line plus aligned `key  value` rows. The colourless
    /// path is what a redirect to a file sees; it must not contain
    /// any ANSI escape bytes.
    #[test]
    fn status_pretty_colorless_has_banner_and_aligned_rows() {
        let body = "version 1.0.0\nlocal-as 64512\npeer-as 64513\nrouter-id 10.0.0.1\nconfig /etc/lr/daemon.lr\nuptime-secs 3661\nsessions 1\nrib-entries 42\n";
        let out = render_status(body, false);
        assert!(out.contains("librouting lr-daemon  1.0.0"), "out: {out}");
        assert!(out.contains("AS 64512 → AS 64513"), "out: {out}");
        assert!(out.contains("Router-id   10.0.0.1"), "out: {out}");
        // Uptime human-form.
        assert!(out.contains("1h 1m 1s"), "out: {out}");
        assert!(!out.contains('\x1b'), "no ANSI escapes: {out:?}");
    }

    /// A coloured `status` body emits the ANSI bold prefix on the
    /// banner so a TTY renders it bright.
    #[test]
    fn status_pretty_colored_has_bold_banner() {
        let body = "version 1.0.0\nlocal-as 64512\npeer-as 64513\nrouter-id 10.0.0.1\nconfig /etc/lr/daemon.lr\nuptime-secs 0\nsessions 1\nrib-entries 42\n";
        let out = render_status(body, true);
        assert!(out.contains("\x1b[1m"), "bold banner: {out:?}");
        assert!(out.contains("\x1b[36m1.0.0"), "cyan version: {out:?}");
        assert!(out.ends_with("\x1b[0m") || out.contains("\x1b[0m"));
    }

    /// `show status` body includes the per-protocol and memory
    /// sections; the pretty view surfaces them under bold headings.
    #[test]
    fn show_status_pretty_has_sessions_and_memory_sections() {
        let body = "version 1.0.0\nlocal-as 64512\npeer-as 64513\nrouter-id 10.0.0.1\nconfig /etc/lr/daemon.lr\nuptime-secs 60\nsessions 1 established 0\nrib-entries 42\n  kind=bgp total=1 established=0\nmemory rss-bytes=10485760 vsize-bytes=52428800\n";
        let out = render_show_status(body, false);
        assert!(out.contains("Sessions"), "out: {out}");
        assert!(out.contains("1 total, 0 established"), "out: {out}");
        assert!(out.contains("Memory"), "out: {out}");
        assert!(out.contains("10.0 MiB"), "out: {out}");
        assert!(out.contains("50.0 MiB"), "out: {out}");
        assert!(out.contains("bgp"), "out: {out}");
    }

    /// A TOML dialect config line is yellow under the colour path
    /// (deprecation warning).
    #[test]
    fn status_pretty_toml_dialect_is_yellow() {
        let body = "version 1.0.0\nlocal-as 64512\npeer-as 64513\nrouter-id 10.0.0.1\nconfig /etc/lr/daemon.toml\nconfig-dialect toml\nconfig-deprecation deprecated: use lr dialect\nuptime-secs 0\nsessions 1\nrib-entries 42\n";
        let out = render_status(body, true);
        assert!(
            out.contains("\x1b[33mtoml\x1b[0m"),
            "toml dialect yellow: {out:?}"
        );
    }

    /// A `sessions` body renders as a table with a header row.
    #[test]
    fn sessions_pretty_renders_table() {
        let body = "#1 kind=bgp local-as=64512 peer-as=64513 state=Idle established=false peer-id=- hold-time=0 adj-rib-in=0 updates-rx=0 updates-tx=0\n";
        let out = render_sessions(body, false);
        assert!(out.contains("KIND"), "out: {out}");
        assert!(out.contains("STATE"), "out: {out}");
        assert!(out.contains("#1"), "out: {out}");
        assert!(out.contains("bgp"), "out: {out}");
        assert!(out.contains("Idle"), "out: {out}");
    }

    /// A coloured `sessions` body paints the Established state green
    /// and Idle red.
    #[test]
    fn sessions_pretty_state_colors() {
        let body = "#1 kind=bgp state=Established established=true\n#2 kind=bgp state=Idle established=false\n";
        let out = render_sessions(body, true);
        assert!(
            out.contains("\x1b[1;32mEstablished"),
            "established green: {out:?}"
        );
        assert!(out.contains("\x1b[31mIdle"), "idle red: {out:?}");
    }

    /// `show routes count` body renders as a total line plus a
    /// per-protocol table.
    #[test]
    fn routes_count_pretty_renders_table() {
        let body = "total 42\n  proto=bgp routes=40\n  proto=direct routes=2\n";
        let out = render_routes_count(body, false);
        assert!(out.contains("Total"), "out: {out}");
        assert!(out.contains("42 routes"), "out: {out}");
        assert!(out.contains("PROTOCOL"), "out: {out}");
        assert!(out.contains("bgp"), "out: {out}");
        assert!(out.contains("direct"), "out: {out}");
    }

    /// `routes` body renders as a table with a header row.
    #[test]
    fn routes_pretty_renders_table() {
        let body = "203.0.113.0/24 via 192.0.2.1 proto=Bgp metric=0 path-id=0\n198.51.100.0/24 via 192.0.2.2 proto=Bgp metric=10 path-id=0\n";
        let out = render_routes(body, false);
        assert!(out.contains("PREFIX"), "out: {out}");
        assert!(out.contains("NEXT-HOP"), "out: {out}");
        assert!(out.contains("203.0.113.0/24"), "out: {out}");
        assert!(out.contains("192.0.2.1"), "out: {out}");
        assert!(out.contains("Bgp"), "out: {out}");
    }

    /// `ping ok` formats with a check mark on the colour path.
    #[test]
    fn ping_ok_colored_has_check_mark() {
        let out = render_ping(true, 5, None, true);
        assert!(out.contains("✓"), "out: {out}");
        assert!(out.contains("\x1b[1;32m"), "out: {out:?}");
    }

    /// `ping fail` formats with an X and the reason.
    #[test]
    fn ping_fail_colored_has_x_and_reason() {
        let out = render_ping(false, 5, Some("connection refused"), true);
        assert!(out.contains("✗"), "out: {out}");
        assert!(out.contains("connection refused"), "out: {out}");
    }

    /// `shutdown status` formats the state with colour.
    #[test]
    fn shutdown_status_pretty_draining() {
        let body = "state=draining remaining=42\n";
        let out = render_shutdown_status_block(body, false);
        assert!(out.contains("Draining"), "out: {out}");
        assert!(out.contains("42 routes remaining"), "out: {out}");
    }

    /// A daemon `error:` line gets a bold-red `Error:` prefix on the
    /// colour path.
    #[test]
    fn error_pretty_bold_red_prefix() {
        let body = "error: no session with handle 999\n";
        let out = render_error(body, true);
        assert!(out.contains("\x1b[1;31mError:"), "out: {out:?}");
        assert!(out.contains("no session with handle 999"), "out: {out}");
    }

    /// `--format=plain` parses to `Format::Plain`.
    #[test]
    fn format_flag_plain() {
        assert_eq!(parse_format_value("plain").unwrap(), Format::Plain);
    }

    /// `--format=json:pretty` parses to `Format::Json(Pretty)`.
    #[test]
    fn format_flag_json_pretty() {
        assert_eq!(
            parse_format_value("json:pretty").unwrap(),
            Format::Json(JsonFormat::Pretty)
        );
    }

    /// `--format=bogus` is rejected.
    #[test]
    fn format_flag_rejects_unknown() {
        assert!(parse_format_value("bogus").is_err());
    }

    /// `--color=always` parses to `ColorMode::Always`.
    #[test]
    fn color_flag_always() {
        assert_eq!(parse_color_value("always").unwrap(), ColorMode::Always);
    }

    /// `--color=never` / `--color=none` / `--color=off` all parse to
    /// `ColorMode::Never` (the three spellings operators reach for
    /// when copy-pasting from different man pages).
    #[test]
    fn color_flag_never_aliases() {
        for s in &["never", "none", "off"] {
            assert_eq!(parse_color_value(s).unwrap(), ColorMode::Never, "for {s}");
        }
    }

    /// Default output is Pretty when stdout is a TTY, Plain otherwise.
    #[test]
    fn resolve_default_format_follows_tty() {
        assert!(matches!(
            resolve_output(None, None, None, true).format,
            Format::Pretty
        ));
        assert!(matches!(
            resolve_output(None, None, None, false).format,
            Format::Plain
        ));
    }

    /// `--format=plain` overrides `--json` (the more specific request
    /// wins).
    #[test]
    fn resolve_format_overrides_json() {
        let out = resolve_output(Some(Format::Plain), Some(JsonFormat::Compact), None, true);
        assert!(matches!(out.format, Format::Plain));
    }

    /// Colour is enabled iff the format is Pretty and (Always or
    /// (Auto and TTY)).
    #[test]
    fn resolve_color_only_for_pretty() {
        // Pretty + Always → on, even when not a TTY.
        assert!(resolve_output(Some(Format::Pretty), None, Some(ColorMode::Always), false).color);
        // Pretty + Auto + TTY → on.
        assert!(resolve_output(Some(Format::Pretty), None, Some(ColorMode::Auto), true).color);
        // Pretty + Auto + not TTY → off.
        assert!(!resolve_output(Some(Format::Pretty), None, Some(ColorMode::Auto), false).color);
        // Pretty + Never → off, even on a TTY.
        assert!(!resolve_output(Some(Format::Pretty), None, Some(ColorMode::Never), true).color);
        // Plain → never colour.
        assert!(!resolve_output(Some(Format::Plain), None, Some(ColorMode::Always), true).color);
        // JSON → never colour.
        assert!(
            !resolve_output(
                Some(Format::Json(JsonFormat::Compact)),
                None,
                Some(ColorMode::Always),
                true
            )
            .color
        );
    }

    /// `fmt_bytes_human` produces binary-unit strings.
    #[test]
    fn fmt_bytes_human_units() {
        assert_eq!(fmt_bytes_human(0), "0 B");
        assert_eq!(fmt_bytes_human(1023), "1023 B");
        assert_eq!(fmt_bytes_human(1024), "1.0 KiB");
        assert_eq!(fmt_bytes_human(1048576), "1.0 MiB");
        assert_eq!(fmt_bytes_human(1073741824), "1.0 GiB");
        assert_eq!(fmt_bytes_human(1099511627776), "1.0 TiB");
    }

    /// `fmt_uptime` produces the `1h 2m 3s` shape.
    #[test]
    fn fmt_uptime_shape() {
        assert_eq!(fmt_uptime(0), "0s");
        assert_eq!(fmt_uptime(5), "5s");
        assert_eq!(fmt_uptime(65), "1m 5s");
        assert_eq!(fmt_uptime(3661), "1h 1m 1s");
    }

    /// `pad_right` does not count ANSI escape bytes towards the
    /// width — a coloured value aligns the same as its colourless
    /// counterpart.
    #[test]
    fn pad_right_ignores_ansi_escapes() {
        let s = "\x1b[31mhi\x1b[0m";
        assert_eq!(render_visible_len(s), 2);
        let padded = pad_right(s, 5);
        assert_eq!(render_visible_len(&padded), 5);
    }

    /// The `extract_format_flag` helper pulls `--format=pretty` from
    /// anywhere in the arg list and leaves the rest in order.
    #[test]
    fn extract_format_anywhere() {
        let args: Vec<String> = ["status", "--format=pretty", "--socket", "/tmp/x"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let (fmt, rest) = extract_format_flag(&args);
        assert!(matches!(fmt.unwrap(), Format::Pretty));
        assert_eq!(
            rest,
            ["status", "--socket", "/tmp/x"]
                .iter()
                .map(|s| s.to_string())
                .collect::<Vec<_>>()
        );
    }

    /// The `extract_color_flag` helper accepts the space-separated
    /// form (`--color always`).
    #[test]
    fn extract_color_space_form() {
        let args: Vec<String> = ["sessions", "--color", "always"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let (mode, rest) = extract_color_flag(&args);
        assert_eq!(mode.unwrap(), ColorMode::Always);
        assert_eq!(
            rest,
            ["sessions"]
                .iter()
                .map(|s| s.to_string())
                .collect::<Vec<_>>()
        );
    }
}
