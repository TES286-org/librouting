//! Cross-module process introspection — RSS / virtual size and
//! future per-platform counters shared by `show …` (operator
//! visibility) and `/metrics` (Prometheus scraping).
//!
//! Lives in `lr-cli` (not a separate crate) because the data is
//! only meaningful for the daemon process; library embedders that
//! never run a daemon do not need it. The module is platform-split
//! at the function level: `process_memory()` reads `/proc/self/status`
//! on Linux and returns `unknown()` on every other target, matching
//! BIRD's `show memory` stance on platforms without a discoverable
//! value.
//!
//! The shape is `Option<u64>` rather than `u64` so a metrics scraper
//! can omit a series entirely on platforms that cannot report it
//! (Prometheus' text exposition format treats a missing gauge as "no
//! data" — better than a misleading `0`).

/// Process memory snapshot.
///
/// Fields are `Option<u64>` so a metric renderer can omit a series
/// entirely when the platform cannot report it (matches BIRD's
/// `show memory` "not available" stance).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ProcessMemory {
    /// Resident set size in bytes (`VmRSS` on Linux; the same field
    /// `top` / `ps` report). `None` when not discoverable.
    pub rss_bytes: Option<u64>,
    /// Virtual memory size in bytes (`VmSize` on Linux). `None` when
    /// not discoverable.
    pub vsize_bytes: Option<u64>,
}

impl ProcessMemory {
    /// A snapshot with both fields `None` — the value platforms without
    /// a discoverable source return.
    pub fn unknown() -> Self {
        Self {
            rss_bytes: None,
            vsize_bytes: None,
        }
    }
}

/// Read the process's resident and virtual memory sizes.
///
/// On Linux, reads `/proc/self/status` for the `VmRSS:` and
/// `VmSize:` lines (the same fields `top` and `ps` report). On
/// every other target, both fields are `None` — BIRD's `show
/// memory` does the same on platforms without a discoverable value.
pub fn process_memory() -> ProcessMemory {
    #[cfg(target_os = "linux")]
    {
        if let Ok(text) = std::fs::read_to_string("/proc/self/status") {
            let mut rss_kb: Option<u64> = None;
            let mut vsize_kb: Option<u64> = None;
            for line in text.lines() {
                if let Some(rest) = line.strip_prefix("VmRSS:") {
                    rss_kb = parse_kb(rest);
                } else if let Some(rest) = line.strip_prefix("VmSize:") {
                    vsize_kb = parse_kb(rest);
                }
                if rss_kb.is_some() && vsize_kb.is_some() {
                    break;
                }
            }
            return ProcessMemory {
                rss_bytes: rss_kb.map(|kb| kb * 1024),
                vsize_bytes: vsize_kb.map(|kb| kb * 1024),
            };
        }
        ProcessMemory::unknown()
    }
    #[cfg(not(target_os = "linux"))]
    {
        ProcessMemory::unknown()
    }
}

/// Parse the `VmRSS:\t   1234 kB` form out of `/proc/self/status`.
/// Returns `None` when the field does not parse as a number (the
/// kernel format is stable, but defensive parsing is cheap).
///
/// Linux-only: lives behind the same `#[cfg(target_os = "linux")]`
/// gate as the only caller (`process_memory`) so non-Linux builds
/// (macOS, Windows) do not see the function and the `dead_code` lint
/// stays clean under `-D warnings`.
#[cfg(target_os = "linux")]
fn parse_kb(rest: &str) -> Option<u64> {
    rest.split_whitespace().next()?.parse::<u64>().ok()
}

/// Format a memory byte count for human-facing output: `None` →
/// the string `unknown` (BIRD parity for "no value available");
/// `Some(n)` → the integer. Prometheus exposition uses the raw
/// integer and never calls this — it is here for the `show memory`
/// and `show status` renderers that share the data.
pub fn fmt_bytes(value: Option<u64>) -> String {
    match value {
        Some(n) => n.to_string(),
        None => "unknown".to_string(),
    }
}
