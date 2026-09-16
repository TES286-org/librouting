//! Prometheus `/metrics` HTTP endpoint (ROADMAP-v3 D12.2).
//!
//! A minimal HTTP/1.0 responder that serves the Prometheus text
//! exposition format (version 0.0.4) on a configurable TCP address.
//! The daemon's router state is read under the same `RwLock` the
//! runtime API uses; the metrics thread never holds the lock while
//! blocking on I/O (same contract as `api.rs`).
//!
//! No HTTP dependency is pulled in: the request line is parsed by
//! hand (the only methods the daemon answers are `GET /metrics` and
//! `GET /` — every other request gets a `404`). This mirrors the
//! project's stance on `api.rs` (hand-rolled Unix-socket server, no
//! `tokio` / `hyper` dependency) and keeps the release-archive binary
//! surface unchanged.
//!
//! The thread model matches `api.rs`'s: one thread polls a
//! `set_nonblocking(true)` `TcpListener` with a 100 ms sleep, and
//! each accepted connection is served on its own short-lived thread
//! so a slow client cannot hold the metrics endpoint hostage.
//!
//! # Exposed metrics
//!
//! | Metric                       | Type    | Labels                          | Source                                   |
//! | ---------------------------- | ------- | ------------------------------- | ---------------------------------------- |
//! | `lr_info`                    | gauge=1 | `version`, `local_as`, `router_id` | daemon identity (for join queries)  |
//! | `lr_uptime_seconds`          | gauge   | —                               | `Instant::elapsed()` since `spawn`       |
//! | `lr_sessions_total`          | gauge   | `kind`, `state`                 | `session_summaries()` count per (kind, state) |
//! | `lr_established_sessions`    | gauge   | `kind`                          | `session_summaries().established` count |
//! | `lr_rib_entries`             | gauge   | —                               | `rib_len()`                              |
//! | `lr_adj_rib_in_entries`      | gauge   | `kind`                          | sum of `adj_rib_in_len` per kind         |
//! | `lr_roa_entries`             | gauge   | —                               | `RoaStore::len()` (when present)        |
//!
//! The exporter is **opt-in** (default off, like `api_socket`):
//! `--metrics-addr 127.0.0.1:9119` / `[bgp] metrics_addr = "…"`.

use std::io::{BufRead, BufReader, Write};
use std::net::TcpListener;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, RwLock};
use std::thread;
use std::time::Duration;

use lr_router::DefaultRouter;

/// Everything the metrics thread needs to render `/metrics`.
///
/// Mirrors [`crate::api::ApiContext`] in shape so a caller can build
/// both from the same `Runtime` snapshot. The `roa_len` closure is
/// optional because the daemon's `Runtime` struct does not yet carry
/// a `RoaStore` reference for every engine — when `None`, the
/// `lr_roa_entries` metric is omitted (rather than emitting a
/// misleading zero).
///
/// The fields are only read by the Unix server below; on other
/// targets the type exists so callers compile unchanged (`spawn`
/// refuses there).
#[cfg_attr(not(unix), expect(dead_code))]
pub struct MetricsContext {
    pub info: MetricsInfo,
    pub router: Arc<RwLock<DefaultRouter>>,
    pub running: Arc<AtomicBool>,
    /// Optional ROA store size reader. `None` → the
    /// `lr_roa_entries` metric is omitted. The closure must be cheap
    /// (a single `Arc<RoaStore>::len()` under no lock — the store is
    /// already `Arc`-swapped atomically, so reads are lock-free).
    pub roa_len: Option<Box<dyn Fn() -> usize + Send + Sync>>,
}

/// Static daemon facts served by `lr_info`.
///
/// See [`MetricsContext`] for why some fields are unread on non-Unix
/// targets.
#[cfg_attr(not(unix), expect(dead_code))]
pub struct MetricsInfo {
    pub version: String,
    pub local_as: u32,
    pub router_id: String,
}

#[cfg(unix)]
mod imp {
    use super::*;
    use std::fmt::Write as _;

    /// Bind the metrics TCP listener and spawn the serving thread.
    ///
    /// Creation failure is fatal: the operator asked for a metrics
    /// endpoint; running without it silently is not an option (same
    /// stance as `api.rs::spawn`).
    pub fn spawn(addr: &str, ctx: MetricsContext) -> Result<String, String> {
        let listener = TcpListener::bind(addr).map_err(|e| format!("bind {addr}: {e}"))?;
        listener
            .set_nonblocking(true)
            .map_err(|e| format!("nonblocking {addr}: {e}"))?;

        let info = Arc::new(ctx.info);
        let router = Arc::clone(&ctx.router);
        let running = Arc::clone(&ctx.running);
        let has_roa = ctx.roa_len.is_some();
        let roa_len: Arc<dyn Fn() -> usize + Send + Sync> = match ctx.roa_len {
            Some(f) => Arc::from(f),
            // Placeholder — only called when `has_roa` is true, so the
            // value here is never observed by a scrape.
            None => Arc::new(|| 0),
        };
        let started = std::time::Instant::now();
        let addr_owned = addr.to_string();

        thread::Builder::new()
            .name("lr-metrics".into())
            .spawn(move || {
                accept_loop(&listener, &running, |stream| {
                    let info = Arc::clone(&info);
                    let router = Arc::clone(&router);
                    let roa_len = Arc::clone(&roa_len);
                    thread::Builder::new()
                        .name("lr-metrics-conn".into())
                        .spawn(move || {
                            serve_connection(stream, &info, &router, has_roa, &roa_len, started);
                        })
                        .ok();
                });
            })
            .map_err(|e| format!("spawn metrics thread: {e}"))?;
        Ok(addr_owned)
    }

    /// Poll the listener until the daemon stops; hand live
    /// connections to `on_conn`. Same shape as
    /// `api.rs::accept_loop` — a 100 ms poll keeps the thread idle
    /// without burning a core.
    fn accept_loop(
        listener: &TcpListener,
        running: &AtomicBool,
        mut on_conn: impl FnMut(std::net::TcpStream),
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

    /// One connection: read the request line, write the response.
    /// The body is always the full `/metrics` exposition; a `GET /`
    /// returns a one-line pointer to `/metrics`, every other path
    /// returns `404 Not Found`. This is the minimum a Prometheus
    /// scrape needs plus a sanity ping for `curl`.
    fn serve_connection(
        stream: std::net::TcpStream,
        info: &MetricsInfo,
        router: &Arc<RwLock<DefaultRouter>>,
        has_roa: bool,
        roa_len: &Arc<dyn Fn() -> usize + Send + Sync>,
        started: std::time::Instant,
    ) {
        let _ = stream.set_read_timeout(Some(Duration::from_millis(500)));
        let mut reader = BufReader::new(&stream);
        let mut request_line = String::new();
        if reader.read_line(&mut request_line).is_err() {
            return;
        }
        // Parse the request line: `METHOD PATH HTTP/1.x`. We only
        // care about METHOD (`GET`) and PATH (`/metrics` or `/`); the
        // version is ignored.
        let mut parts = request_line.split_whitespace();
        let method = parts.next().unwrap_or("");
        let path = parts.next().unwrap_or("/");

        let (status, body, content_type) = if method == "GET" && path == "/metrics" {
            (
                "200 OK",
                render_metrics(info, router, has_roa, roa_len, started),
                "text/plain; version=0.0.4; charset=utf-8",
            )
        } else if method == "GET" && (path == "/" || path == "/metrics/") {
            (
                "200 OK",
                "# librouting metrics endpoint\n# scrape /metrics for the full exposition\n"
                    .to_string(),
                "text/plain; charset=utf-8",
            )
        } else {
            (
                "404 Not Found",
                "not found\n".to_string(),
                "text/plain; charset=utf-8",
            )
        };

        let response = format!(
            "HTTP/1.0 {status}\r\n\
             Content-Type: {content_type}\r\n\
             Content-Length: {len}\r\n\
             Connection: close\r\n\
             \r\n\
             {body}",
            len = body.len(),
        );
        let _ = (&stream).write_all(response.as_bytes());
        let _ = (&stream).flush();
    }

    /// Render the Prometheus text exposition format. The body is
    /// built into a `String` under a single read-lock acquisition
    /// (so the lock is held for microseconds, not for the duration
    /// of the network write — same contract as `api.rs`'s `status`
    /// handler).
    fn render_metrics(
        info: &MetricsInfo,
        router: &Arc<RwLock<DefaultRouter>>,
        has_roa: bool,
        roa_len: &Arc<dyn Fn() -> usize + Send + Sync>,
        started: std::time::Instant,
    ) -> String {
        let (uptime, summaries, rib_len) = match router.read() {
            Ok(r) => (
                started.elapsed().as_secs(),
                r.session_summaries(),
                r.rib_len(),
            ),
            Err(_) => {
                // Router lock poisoned — emit a minimal body so the
                // scrape does not hang. Prometheus treats `up=0` as
                // the "target is down" signal; we still emit `lr_info`
                // so the operator can identify the daemon.
                return format!(
                    "# lr_info\nlr_info{{version=\"{ver}\",local_as=\"{la}\",router_id=\"{rid}\"}} 1\n\
                     # lr_uptime_seconds\nlr_uptime_seconds {up}\n",
                    ver = escape_label(&info.version),
                    la = info.local_as,
                    rid = escape_label(&info.router_id),
                    up = started.elapsed().as_secs(),
                );
            }
        };

        let mut out = String::with_capacity(2048);

        // lr_info — identity gauge (always 1). Useful for `sum by
        // (version)` queries that join against the daemon's release.
        writeln!(out, "# HELP lr_info librouting daemon identity (always 1).").ok();
        writeln!(out, "# TYPE lr_info gauge").ok();
        writeln!(
            out,
            "lr_info{{version=\"{ver}\",local_as=\"{la}\",router_id=\"{rid}\"}} 1",
            ver = escape_label(&info.version),
            la = info.local_as,
            rid = escape_label(&info.router_id),
        )
        .ok();

        // lr_uptime_seconds — daemon uptime since metrics thread spawn.
        writeln!(out, "# HELP lr_uptime_seconds Daemon uptime in seconds.").ok();
        writeln!(out, "# TYPE lr_uptime_seconds gauge").ok();
        writeln!(out, "lr_uptime_seconds {uptime}").ok();

        // lr_sessions_total — count per (kind, state). Gauges because
        // the value can go down (session teardown).
        writeln!(
            out,
            "# HELP lr_sessions_total Number of configured sessions, by protocol kind and state."
        )
        .ok();
        writeln!(out, "# TYPE lr_sessions_total gauge").ok();
        // Group by (kind, state) → count. The summaries are already
        // returned in a deterministic order (BTreeMap-ordered handles),
        // so the output is stable across scrapes.
        let mut by_kind_state: std::collections::BTreeMap<(&'static str, &'static str), u64> =
            std::collections::BTreeMap::new();
        let mut by_kind_established: std::collections::BTreeMap<&'static str, u64> =
            std::collections::BTreeMap::new();
        let mut by_kind_adj_rib: std::collections::BTreeMap<&'static str, u64> =
            std::collections::BTreeMap::new();
        for s in &summaries {
            *by_kind_state.entry((s.kind, s.state)).or_default() += 1;
            if s.established {
                *by_kind_established.entry(s.kind).or_default() += 1;
            }
            *by_kind_adj_rib.entry(s.kind).or_default() += s.adj_rib_in_len as u64;
        }
        for ((kind, state), n) in &by_kind_state {
            writeln!(
                out,
                "lr_sessions_total{{kind=\"{kind}\",state=\"{state}\"}} {n}",
            )
            .ok();
        }

        // lr_established_sessions — count per kind, established only.
        writeln!(
            out,
            "# HELP lr_established_sessions Number of sessions in the established / Full / Up state, by protocol kind."
        )
        .ok();
        writeln!(out, "# TYPE lr_established_sessions gauge").ok();
        for (kind, n) in &by_kind_established {
            writeln!(out, "lr_established_sessions{{kind=\"{kind}\"}} {n}").ok();
        }
        // Emit a zero for every kind that has sessions but none
        // established, so a scrape does not look "missing" to an
        // alert that joins on `kind`.
        let all_kinds: std::collections::BTreeSet<&'static str> =
            by_kind_state.keys().map(|(k, _)| *k).collect();
        for kind in &all_kinds {
            if !by_kind_established.contains_key(kind) {
                writeln!(out, "lr_established_sessions{{kind=\"{kind}\"}} 0").ok();
            }
        }

        // lr_adj_rib_in_entries — sum of adj_rib_in_len per kind.
        writeln!(
            out,
            "# HELP lr_adj_rib_in_entries Total routes held in Adj-RIB-In across all sessions of each protocol kind."
        )
        .ok();
        writeln!(out, "# TYPE lr_adj_rib_in_entries gauge").ok();
        for (kind, n) in &by_kind_adj_rib {
            writeln!(out, "lr_adj_rib_in_entries{{kind=\"{kind}\"}} {n}").ok();
        }

        // lr_rib_entries — the Loc-RIB size.
        writeln!(
            out,
            "# HELP lr_rib_entries Number of routes in the Loc-RIB (best-path selection output)."
        )
        .ok();
        writeln!(out, "# TYPE lr_rib_entries gauge").ok();
        writeln!(out, "lr_rib_entries {rib_len}").ok();

        // lr_roa_entries — the ROA store size (when a store is
        // configured). Omitted entirely when no store is present so
        // scrapes do not see a misleading zero.
        if has_roa {
            writeln!(
                out,
                "# HELP lr_roa_entries Number of ROA entries in the live ROA store (static + RTR cache)."
            )
            .ok();
            writeln!(out, "# TYPE lr_roa_entries gauge").ok();
            writeln!(out, "lr_roa_entries {}", roa_len()).ok();
        }

        out
    }

    /// Escape a string for inclusion in a Prometheus label value:
    /// `\` → `\\`, `"` → `\"`, `\n` → `\n`. Per the exposition
    /// format spec, those are the only three escapes.
    fn escape_label(s: &str) -> String {
        let mut out = String::with_capacity(s.len());
        for ch in s.chars() {
            match ch {
                '\\' => out.push_str("\\\\"),
                '"' => out.push_str("\\\""),
                '\n' => out.push_str("\\n"),
                other => out.push(other),
            }
        }
        out
    }
}

#[cfg(not(unix))]
mod imp {
    use super::*;

    /// On non-Unix targets the metrics endpoint is refused with a
    /// clear error — same stance as `api.rs`. The exposition format
    /// is portable, but the daemon's process model (signals,
    /// privilege drop) is not, so the whole daemon binary refuses to
    /// start there in the first place.
    pub fn spawn(_addr: &str, _ctx: MetricsContext) -> Result<String, String> {
        Err("metrics endpoint requires Unix domain socket support (not supported here)".to_string())
    }
}

pub use imp::spawn;
