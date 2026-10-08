//! Process-wide logger for `lr-daemon`.
//!
//! The daemon has one thread per transport plus ticker, API, and metrics
//! threads. Standard output and standard error have independent locks, so
//! writes to the two streams can otherwise be interleaved by the console.
//!
//! Two surfaces live here:
//!
//! - **Raw console output** ([`write_line`], used by the daemon-local
//!   `println!` / `eprintln!` macros) for one-shot operational lines that
//!   must always appear: the usage banner, the startup summary, the
//!   `status` reply. These are not log records.
//! - **Categorised log records** ([`log_record`], used by the `log_*!`
//!   macros) for diagnostic output that carries a [`Severity`] and a
//!   [`Component`]. The runtime [`LogConfig`] (installed once by
//!   [`init_logger`]) decides which records reach the console, in what
//!   format, and whether they are mirrored to a file.
//!
//! Filter precedence: a per-component level (e.g. `bgp=debug`) overrides
//! the global default level; records below the effective level are
//! dropped before formatting, so a quiet deployment pays nothing for the
//! disabled paths.

use std::collections::BTreeMap;
use std::fmt;
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::PathBuf;
use std::sync::{Mutex, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

static CONSOLE_LOCK: Mutex<()> = Mutex::new(());

#[derive(Clone, Copy)]
pub(crate) enum Stream {
    Stdout,
    Stderr,
}

/// Write exactly one complete console record while holding the
/// process-wide output lock. A poisoned lock must not disable
/// operational diagnostics.
pub(crate) fn write_line(stream: Stream, args: fmt::Arguments<'_>) {
    let _guard = CONSOLE_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    match stream {
        Stream::Stdout => {
            let mut out = io::stdout().lock();
            let _ = writeln!(out, "{args}");
        }
        Stream::Stderr => {
            let mut out = io::stderr().lock();
            let _ = writeln!(out, "{args}");
        }
    }
}

// ---------------------------------------------------------------------------
// Severity, Component and configuration
// ---------------------------------------------------------------------------

/// Log severity, in increasing order of verbosity. Ordering matters:
/// `severity <= level_for(component)` is the filter test, so `Error` is
/// always emitted when `Info` is enabled, and `Debug` is dropped when
/// only `Info` is enabled.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default)]
pub(crate) enum Severity {
    Error,
    Warn,
    #[default]
    Info,
    Debug,
    Trace,
}

impl Severity {
    pub(crate) fn from_str(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "error" | "err" => Some(Self::Error),
            "warn" | "warning" => Some(Self::Warn),
            "info" => Some(Self::Info),
            "debug" | "dbg" => Some(Self::Debug),
            "trace" => Some(Self::Trace),
            _ => None,
        }
    }

    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Error => "ERROR",
            Self::Warn => "WARN",
            Self::Info => "INFO",
            Self::Debug => "DEBUG",
            Self::Trace => "TRACE",
        }
    }
}

/// The component a record belongs to. Each maps to a short string used
/// both as the on-the-wire category tag and as the key the operator
/// uses in `--log-target bgp=debug` / `[logging.targets]`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) enum Component {
    Bgp,
    Ospf,
    Ospfv3,
    Babel,
    Ldp,
    Bfd,
    Bmp,
    Rib,
    Policy,
    Router,
    Daemon,
    Api,
    Metrics,
    Config,
    Rpki,
    Osroute,
    Interop,
}

impl Component {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Bgp => "bgp",
            Self::Ospf => "ospf",
            Self::Ospfv3 => "ospfv3",
            Self::Babel => "babel",
            Self::Ldp => "ldp",
            Self::Bfd => "bfd",
            Self::Bmp => "bmp",
            Self::Rib => "rib",
            Self::Policy => "policy",
            Self::Router => "router",
            Self::Daemon => "daemon",
            Self::Api => "api",
            Self::Metrics => "metrics",
            Self::Config => "config",
            Self::Rpki => "rpki",
            Self::Osroute => "osroute",
            Self::Interop => "interop",
        }
    }

    pub(crate) fn from_str(s: &str) -> Option<Self> {
        match s {
            "bgp" => Some(Self::Bgp),
            "ospf" => Some(Self::Ospf),
            "ospfv3" => Some(Self::Ospfv3),
            "babel" => Some(Self::Babel),
            "ldp" => Some(Self::Ldp),
            "bfd" => Some(Self::Bfd),
            "bmp" => Some(Self::Bmp),
            "rib" => Some(Self::Rib),
            "policy" => Some(Self::Policy),
            "router" => Some(Self::Router),
            "daemon" => Some(Self::Daemon),
            "api" => Some(Self::Api),
            "metrics" => Some(Self::Metrics),
            "config" => Some(Self::Config),
            "rpki" => Some(Self::Rpki),
            "osroute" => Some(Self::Osroute),
            "interop" => Some(Self::Interop),
            _ => None,
        }
    }

    /// Every variant, in declaration order — used by `--help` and by
    /// config validators that need to enumerate the recognised names.
    pub(crate) fn all() -> &'static [Component] {
        &[
            Self::Bgp,
            Self::Ospf,
            Self::Ospfv3,
            Self::Babel,
            Self::Ldp,
            Self::Bfd,
            Self::Bmp,
            Self::Rib,
            Self::Policy,
            Self::Router,
            Self::Daemon,
            Self::Api,
            Self::Metrics,
            Self::Config,
            Self::Rpki,
            Self::Osroute,
            Self::Interop,
        ]
    }
}

/// Output format for categorised records.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) enum LogFormat {
    /// `2026-10-08T12:34:56Z INFO  [bgp] peer up ...`
    #[default]
    Plain,
    /// `{"ts":"...","level":"INFO","component":"bgp","msg":"..."}` — one
    /// object per line, suitable for structured log shippers.
    Json,
}

impl LogFormat {
    pub(crate) fn from_str(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "plain" | "text" => Some(Self::Plain),
            "json" => Some(Self::Json),
            _ => None,
        }
    }

    /// Stable string form, used by `--help` text and by config
    /// validators that echo back the parsed value.
    #[allow(dead_code)]
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Plain => "plain",
            Self::Json => "json",
        }
    }
}

/// ANSI colour policy. `Auto` enables colour when stderr is a TTY.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) enum ColorMode {
    Auto,
    On,
    #[default]
    Off,
}

impl ColorMode {
    pub(crate) fn from_str(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "auto" => Some(Self::Auto),
            "on" | "yes" | "true" | "always" => Some(Self::On),
            "off" | "no" | "false" | "never" => Some(Self::Off),
            _ => None,
        }
    }

    /// Stable string form. See [`LogFormat::as_str`].
    #[allow(dead_code)]
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::On => "on",
            Self::Off => "off",
        }
    }
}

/// Logger configuration. Installed once at startup by [`init_logger`];
/// read on every [`log_record`] call.
#[derive(Debug, Clone, Default)]
pub(crate) struct LogConfig {
    /// Minimum severity emitted for components without an explicit
    /// override (default: [`Severity::Info`]).
    pub default_level: Severity,
    /// Per-component severity overrides. A component missing from this
    /// map falls back to `default_level`.
    pub component_levels: BTreeMap<Component, Severity>,
    /// Output format (default: [`LogFormat::Plain`]).
    pub format: LogFormat,
    /// ANSI colour policy (default: [`ColorMode::Off`]).
    pub color: ColorMode,
    /// Optional file mirrored in addition to the console. The file is
    /// opened append-only and never re-opened, so a log rotation tool
    /// must signal the daemon to reopen (future work).
    pub file: Option<PathBuf>,
}

impl LogConfig {
    /// Effective severity for `component`: the per-component override
    /// when set, otherwise the default level.
    pub fn level_for(&self, component: Component) -> Severity {
        self.component_levels
            .get(&component)
            .copied()
            .unwrap_or(self.default_level)
    }

    /// Parse a `component=level` directive (e.g. `bgp=debug`,
    /// `*=warn`). `*` sets the default level. Returns `Err(message)`
    /// on an unknown component or level so the caller can surface the
    /// bad input instead of silently dropping it.
    pub fn apply_target_directive(&mut self, directive: &str) -> Result<(), String> {
        let (name, level_str) = directive
            .split_once('=')
            .ok_or_else(|| format!("bad log target '{directive}' (expected name=level)"))?;
        let level = Severity::from_str(level_str).ok_or_else(|| {
            format!(
                "bad log level '{level_str}' in '{directive}' (expected error|warn|info|debug|trace)"
            )
        })?;
        if name == "*" {
            self.default_level = level;
            return Ok(());
        }
        let component = Component::from_str(name).ok_or_else(|| {
            format!(
                "unknown log component '{name}' in '{directive}' (recognised: {})",
                Component::all()
                    .iter()
                    .map(|c| c.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            )
        })?;
        self.component_levels.insert(component, level);
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Installed state
// ---------------------------------------------------------------------------

static LOG_CONFIG: OnceLock<Mutex<LogConfig>> = OnceLock::new();
static LOG_FILE: Mutex<Option<fs::File>> = Mutex::new(None);

/// Install the logger configuration. Call once at startup, before any
/// `log_*!` macro fires. Re-call on a config reload to replace the
/// active configuration and reopen the file destination.
///
/// Returns `Err(message)` if the file destination cannot be opened;
/// the caller decides whether that is fatal.
pub(crate) fn init_logger(cfg: LogConfig) -> Result<(), String> {
    if let Some(path) = &cfg.file {
        let f = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .map_err(|e| format!("cannot open log file {}: {e}", path.display()))?;
        *LOG_FILE
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(f);
    } else {
        *LOG_FILE
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = None;
    }
    // Replace the live config. The first call installs the
    // `Mutex<LogConfig>`; subsequent calls (reload) lock and replace
    // the inner value. `OnceLock::set` returns `Err(value)` when the
    // cell is already occupied, which is the reload path.
    if LOG_CONFIG.get().is_none() {
        let _ = LOG_CONFIG.set(Mutex::new(cfg));
    } else if let Some(m) = LOG_CONFIG.get() {
        *m.lock().unwrap_or_else(std::sync::PoisonError::into_inner) = cfg;
    }
    Ok(())
}

/// True if `init_logger` has run. Tests use this to install a default
/// config before any `log_*!` call. Subcommands that do not parse the
/// daemon's full argument set also call it to decide whether to
/// install a default.
#[allow(dead_code)]
pub(crate) fn logger_initialised() -> bool {
    LOG_CONFIG.get().is_some()
}

/// Install a default `LogConfig` if none is present. Used by tests and
/// by subcommands that do not parse the daemon's full argument set
/// (so a `log_*!` call before the main daemon installs its config
/// still produces output at the default level instead of dropping
/// silently).
#[allow(dead_code)]
pub(crate) fn ensure_logger_default() {
    if LOG_CONFIG.get().is_none() {
        let _ = LOG_CONFIG.set(Mutex::new(LogConfig::default()));
    }
}

fn current_config() -> LogConfig {
    match LOG_CONFIG.get() {
        Some(m) => m
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone(),
        None => LogConfig::default(),
    }
}

/// Emit a categorised log record. Filtered by the live [`LogConfig`];
/// records below the component's effective level return without doing
/// any formatting work.
pub(crate) fn log_record(severity: Severity, component: Component, args: fmt::Arguments<'_>) {
    let cfg = current_config();
    if severity > cfg.level_for(component) {
        return;
    }
    let ts = format_timestamp(SystemTime::now());
    let msg = args.to_string();
    let line = match cfg.format {
        LogFormat::Plain => format_plain(&ts, severity, component, &msg, cfg.color),
        LogFormat::Json => format_json(&ts, severity, component, &msg),
    };
    // Errors and warnings go to stderr; info and below to stdout. This
    // matches the daemon's historical split and keeps `lr-daemon |
    // grep -v daemon:` style pipelines useful.
    let stream = if severity <= Severity::Warn {
        Stream::Stderr
    } else {
        Stream::Stdout
    };
    write_line(stream, format_args!("{line}"));
    // Mirror to the file destination, if any. The file always
    // receives the uncoloured form: structured shippers parse the
    // JSON variant, and a plain log aggregator does not want ANSI
    // escapes in the text.
    let file_line = match cfg.format {
        LogFormat::Plain => format_plain(&ts, severity, component, &msg, ColorMode::Off),
        LogFormat::Json => line,
    };
    let mut guard = LOG_FILE
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if let Some(f) = guard.as_mut() {
        let _ = writeln!(f, "{file_line}");
    }
}

fn format_plain(
    ts: &str,
    severity: Severity,
    component: Component,
    msg: &str,
    color: ColorMode,
) -> String {
    let level_str = severity.as_str();
    let component_str = component.as_str();
    if color_enabled(color) {
        let level_coloured = colour_level(severity, level_str);
        format!("{ts} {level_coloured:<21} [{component_str}] {msg}")
    } else {
        format!("{ts} {level_str:<5} [{component_str}] {msg}")
    }
}

fn color_enabled(mode: ColorMode) -> bool {
    match mode {
        ColorMode::On => true,
        ColorMode::Off => false,
        ColorMode::Auto => {
            // Auto: colour only when stderr is a terminal. We check
            // stderr because that is where warnings/errors land (the
            // common interactive case); stdout-bound info records
            // inherit the same decision for consistency.
            #[cfg(unix)]
            {
                use std::os::fd::AsRawFd;
                let fd = io::stderr().as_raw_fd();
                unsafe { libc_isatty(fd) }
            }
            #[cfg(not(unix))]
            {
                false
            }
        }
    }
}

#[cfg(unix)]
unsafe extern "C" {
    fn isatty(fd: i32) -> i32;
}

#[cfg(unix)]
unsafe fn libc_isatty(fd: i32) -> bool {
    // Direct extern binding avoids a libc dependency just for one
    // call. The signature matches POSIX `isatty`.
    unsafe { isatty(fd) != 0 }
}

fn colour_level(severity: Severity, label: &str) -> String {
    // ANSI colour codes. The labels are padded to five characters
    // before colouring so the uncoloured columns line up.
    match severity {
        Severity::Error => format!("\x1b[31m{label}\x1b[0m"), // red
        Severity::Warn => format!("\x1b[33m{label}\x1b[0m"),  // yellow
        Severity::Info => format!("\x1b[32m{label}\x1b[0m"),  // green
        Severity::Debug => format!("\x1b[36m{label}\x1b[0m"), // cyan
        Severity::Trace => format!("\x1b[35m{label}\x1b[0m"), // magenta
    }
}

fn format_json(ts: &str, severity: Severity, component: Component, msg: &str) -> String {
    // Hand-rolled JSON: avoids a serde dependency for the logger path,
    // and the shape is fixed (three known strings + one user string).
    let level = match severity {
        Severity::Error => "error",
        Severity::Warn => "warn",
        Severity::Info => "info",
        Severity::Debug => "debug",
        Severity::Trace => "trace",
    };
    let escaped = json_escape(msg);
    format!(
        r#"{{"ts":"{ts}","level":"{level}","component":"{comp}","msg":"{escaped}"}}"#,
        comp = component.as_str(),
    )
}

fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

/// Format `now` as an RFC 3339 / ISO 8601 UTC timestamp:
/// `2026-10-08T12:34:56Z`. Carried in every record so a log shipper
/// can sort and correlate without parsing the message body.
fn format_timestamp(now: SystemTime) -> String {
    let dur = now.duration_since(UNIX_EPOCH).unwrap_or_default();
    let secs = dur.as_secs();
    let (year, month, day, hour, minute, second) = civil_from_unix(secs);
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z")
}

/// Convert a Unix second count to a (year, month, day, hour, minute,
/// second) tuple in UTC. Implemented after the well-known
/// `days_from_civil` algorithm (Howard Hinnant) — no `chrono`
/// dependency, no allocation, O(1).
fn civil_from_unix(secs: u64) -> (i32, u8, u8, u8, u8, u8) {
    let days = (secs / 86_400) as i64;
    let rem = secs % 86_400;
    // Howard Hinnant's `civil_from_days` algorithm: converts a count
    // of days since 1970-01-01 to a (y, m, d) triple.
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u8;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u8;
    let year = if m <= 2 { y + 1 } else { y } as i32;
    let hour = (rem / 3_600) as u8;
    let minute = ((rem % 3_600) / 60) as u8;
    let second = (rem % 60) as u8;
    (year, m, d, hour, minute, second)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn logger_accepts_records_from_many_threads() {
        let handles: Vec<_> = (0..4)
            .map(|worker| {
                std::thread::spawn(move || {
                    for record in 0..2 {
                        write_line(
                            Stream::Stdout,
                            format_args!("logger-test worker={worker} record={record}"),
                        );
                    }
                })
            })
            .collect();
        for handle in handles {
            handle.join().unwrap();
        }
    }

    #[test]
    fn severity_parses_aliases() {
        assert_eq!(Severity::from_str("error"), Some(Severity::Error));
        assert_eq!(Severity::from_str("ERR"), Some(Severity::Error));
        assert_eq!(Severity::from_str("warn"), Some(Severity::Warn));
        assert_eq!(Severity::from_str("warning"), Some(Severity::Warn));
        assert_eq!(Severity::from_str("INFO"), Some(Severity::Info));
        assert_eq!(Severity::from_str("dbg"), Some(Severity::Debug));
        assert_eq!(Severity::from_str("trace"), Some(Severity::Trace));
        assert_eq!(Severity::from_str("nope"), None);
    }

    #[test]
    fn severity_ordering_filters_verbose_levels() {
        // Info is more verbose than Warn, so a record at Warn passes
        // an Info filter; a Debug record does not.
        assert!(Severity::Warn <= Severity::Info);
        assert!(Severity::Debug > Severity::Info);
        assert!(Severity::Error <= Severity::Error);
    }

    #[test]
    fn component_round_trips() {
        for c in Component::all() {
            assert_eq!(Component::from_str(c.as_str()), Some(*c));
        }
        assert_eq!(Component::from_str("unknown"), None);
    }

    #[test]
    fn default_level_is_info() {
        let cfg = LogConfig::default();
        assert_eq!(cfg.default_level, Severity::Info);
        assert_eq!(cfg.level_for(Component::Bgp), Severity::Info);
    }

    #[test]
    fn per_component_override_beats_default() {
        let mut cfg = LogConfig::default();
        cfg.apply_target_directive("bgp=debug").unwrap();
        assert_eq!(cfg.level_for(Component::Bgp), Severity::Debug);
        assert_eq!(cfg.level_for(Component::Ospf), Severity::Info);
    }

    #[test]
    fn wildcard_sets_default_level() {
        let mut cfg = LogConfig::default();
        cfg.apply_target_directive("*=warn").unwrap();
        assert_eq!(cfg.default_level, Severity::Warn);
        assert_eq!(cfg.level_for(Component::Bgp), Severity::Warn);
    }

    #[test]
    fn bad_directives_fail_loud() {
        let mut cfg = LogConfig::default();
        assert!(cfg.apply_target_directive("bgp").is_err());
        assert!(cfg.apply_target_directive("bgp=verbose").is_err());
        assert!(cfg.apply_target_directive("unknown=debug").is_err());
    }

    #[test]
    fn json_format_escapes_special_characters() {
        let line = format_json(
            "2026-10-08T00:00:00Z",
            Severity::Info,
            Component::Bgp,
            "peer \"up\"\nnewline",
        );
        // The message field must escape the embedded quotes and
        // newline so the resulting line is valid JSON.
        assert!(line.contains("\"msg\":\"peer \\\"up\\\"\\nnewline\""));
        assert!(line.contains("\"level\":\"info\""));
        assert!(line.contains("\"component\":\"bgp\""));
    }

    #[test]
    fn plain_format_columns_align_without_colour() {
        let a = format_plain(
            "2026-10-08T00:00:00Z",
            Severity::Info,
            Component::Bgp,
            "msg",
            ColorMode::Off,
        );
        let b = format_plain(
            "2026-10-08T00:00:00Z",
            Severity::Warn,
            Component::Bgp,
            "msg",
            ColorMode::Off,
        );
        // The level column is fixed-width; the component column starts
        // at the same offset in both lines.
        let a_comp = a.find("[bgp]").unwrap();
        let b_comp = b.find("[bgp]").unwrap();
        assert_eq!(a_comp, b_comp);
    }

    #[test]
    fn civil_from_unix_matches_known_dates() {
        // 1970-01-01 00:00:00 UTC.
        assert_eq!(civil_from_unix(0), (1970, 1, 1, 0, 0, 0));
        // 2024-10-07 12:00:00 UTC = 1_728_302_400. Cross-checked
        // against Python's `datetime.datetime(2024,10,7,12,tzinfo=utc).timestamp()`.
        let (y, m, d, h, mi, s) = civil_from_unix(1_728_302_400);
        assert_eq!(y, 2024);
        assert_eq!(m, 10);
        assert_eq!(d, 7);
        assert_eq!(h, 12);
        assert_eq!(mi, 0);
        assert_eq!(s, 0);
        // Leap-year boundary: 2000-03-01 00:00:00 UTC.
        let (y, m, d, _, _, _) = civil_from_unix(951_868_800);
        assert_eq!((y, m, d), (2000, 3, 1));
    }

    #[test]
    fn log_record_respects_filter() {
        // Install a config that drops Debug for the Daemon component,
        // then call log_record at Debug and Info and verify only Info
        // produces output. We cannot easily capture stdout here, so
        // the test is structural: the call must not panic and must
        // return without formatting when filtered.
        let _ = init_logger(LogConfig {
            default_level: Severity::Info,
            ..Default::default()
        });
        // Both calls are no-ops at the console level for Debug when
        // the level is Info; the test asserts they return cleanly.
        log_record(Severity::Debug, Component::Daemon, format_args!("debug"));
        log_record(Severity::Info, Component::Daemon, format_args!("info"));
    }
}
