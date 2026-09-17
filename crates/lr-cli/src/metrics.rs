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
//! | `lr_bgp_updates_total`       | counter | `session`, `peer`, `direction`  | `SessionSummary::updates_received/sent` per BGP session |
//! | `lr_roa_entries`             | gauge   | —                               | `RoaStore::len()` (when present)        |
//! | `lr_filter_eval_duration_seconds` | histogram | `direction`, `filter`      | `FilterMetricsRegistry` (when present)  |
//!
//! The exporter is **opt-in** (default off, like `api_socket`):
//! `--metrics-addr 127.0.0.1:9119` / `[bgp] metrics_addr = "…"`.
//!
//! The histogram series is emitted only when a registry was wired in
//! (BGP daemon with `--metrics-addr`); recording is likewise gated on
//! the endpoint being configured, so the per-route hot path pays the
//! two `Instant::now()` calls only when someone is scraping.

use std::sync::atomic::AtomicBool;
use std::sync::{Arc, RwLock};

use lr_router::DefaultRouter;

/// A fixed-bucket duration histogram recorded through atomics — no
/// locks on the recording path (the filter hooks run per route).
///
/// The bucket upper bounds are nanosecond values chosen around the
/// measured filter-VM hot path (GitHub #19: 60–430 ns per evaluation
/// for the standard shapes, low microseconds for set-heavy filters):
/// 100 ns … 10 ms plus the implicit `+Inf` bucket. Fixed bounds keep
/// `DurationHistogram` a single allocation-free struct that can be
/// shared as `Arc` between the hooks and the exporter thread.
///
/// Rendering follows the Prometheus text exposition format: bucket
/// lines are cumulative (each counts everything at or below its
/// bound), `_sum` carries the total nanoseconds as seconds, and
/// `_count` equals the `+Inf` bucket.
pub struct DurationHistogram {
    counts: [std::sync::atomic::AtomicU64; Self::BOUNDS.len()],
    sum_ns: std::sync::atomic::AtomicU64,
    count: std::sync::atomic::AtomicU64,
}

impl DurationHistogram {
    /// Cumulative bucket upper bounds, ascending. A duration of
    /// exactly a bound belongs to that bucket.
    const BOUNDS: [u64; 16] = [
        100, 250, 500, 1_000, 2_500, 5_000, 10_000, 25_000, 50_000, 100_000, 250_000, 500_000,
        1_000_000, 2_500_000, 5_000_000, 10_000_000,
    ];

    pub fn new() -> Self {
        Self {
            counts: std::array::from_fn(|_| std::sync::atomic::AtomicU64::new(0)),
            sum_ns: std::sync::atomic::AtomicU64::new(0),
            count: std::sync::atomic::AtomicU64::new(0),
        }
    }

    /// Record one observation (nanoseconds). Relaxed ordering is
    /// sufficient: the counters are independent statistics, not
    /// synchronization flags.
    pub fn record(&self, ns: u64) {
        // Linear scan: 16 well-predicted branches beat a binary
        // search at this size, and the common case (sub-microsecond)
        // exits in the first few iterations.
        for (i, bound) in Self::BOUNDS.iter().enumerate() {
            if ns <= *bound {
                self.counts[i].fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                break;
            }
        }
        self.sum_ns
            .fetch_add(ns, std::sync::atomic::Ordering::Relaxed);
        self.count
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    /// Total observations recorded.
    pub fn count(&self) -> u64 {
        self.count.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Render the Prometheus lines for this histogram (bucket, sum,
    /// count) under one label set. `labels` is a pre-rendered
    /// `{k="v",…}` fragment (possibly empty); the `le` label is
    /// appended per bucket line.
    fn render(&self, out: &mut String, metric: &str, labels: &str) {
        use std::fmt::Write as _;
        // The label-set shape differs between "no labels" (`{le=…}`)
        // and "some labels" (`{…,le=…}`): the `le` label joins the
        // existing set with a comma *inside* the braces (the incoming
        // fragment carries its own `{…}`), so strip the closing brace
        // and let the format string re-add `le=…}`.
        let open = if labels.is_empty() {
            "{".to_string()
        } else {
            format!("{},", &labels[..labels.len() - 1])
        };
        let mut cumulative = 0u64;
        for (i, bound) in Self::BOUNDS.iter().enumerate() {
            cumulative += self.counts[i].load(std::sync::atomic::Ordering::Relaxed);
            let _ = writeln!(
                out,
                "{metric}_bucket{open}le=\"{le}\"}} {cumulative}",
                le = format_secs(*bound),
            );
        }
        let count = self.count();
        let sum = self.sum_ns.load(std::sync::atomic::Ordering::Relaxed);
        let _ = writeln!(out, "{metric}_sum{labels} {}", format_secs(sum));
        let _ = writeln!(out, "{metric}_count{labels} {count}");
    }
}

impl Default for DurationHistogram {
    fn default() -> Self {
        Self::new()
    }
}

/// Format a nanosecond count as a seconds value with nanosecond
/// precision (9 decimals). All histogram bounds are multiples of
/// 50 ns, so the 9-decimal form is exact for them; the running sum
/// is likewise exact to the nanosecond.
fn format_secs(ns: u64) -> String {
    format!("{:.9}", ns as f64 / 1e9)
}

/// Which side of the import/export pipeline a filter evaluation
/// belongs to — the histogram label value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FilterDirection {
    Import,
    Export,
}

impl FilterDirection {
    fn label(self) -> &'static str {
        match self {
            Self::Import => "import",
            Self::Export => "export",
        }
    }
}

/// The registry of per-filter histograms: one
/// [`DurationHistogram`] per (direction, filter name), populated at
/// daemon start-up when the hooks are built and read by the metrics
/// thread when scraping. Hooks hold their own `Arc<DurationHistogram>`
/// clone, so recording never touches this registry (no map lookup, no
/// lock on the hot path).
///
/// The internal `__roa_validate` filter registers like any user
/// filter — its latency is the ROA-validation cost, which is exactly
/// what an operator debugging slow imports wants to see separated
/// from the user policy.
pub struct FilterMetricsRegistry {
    entries: Vec<(FilterDirection, String, Arc<DurationHistogram>)>,
}

impl FilterMetricsRegistry {
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// Register one (direction, filter) series and return the
    /// histogram the hook records into.
    pub fn register(&mut self, direction: FilterDirection, filter: &str) -> Arc<DurationHistogram> {
        let hist = Arc::new(DurationHistogram::new());
        self.entries
            .push((direction, filter.to_string(), Arc::clone(&hist)));
        hist
    }

    /// True when no series registered (the metric block is omitted
    /// from the exposition).
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Render the full histogram block: HELP/TYPE headers plus the
    /// per-series bucket/sum/count lines, series in registration
    /// order (deterministic across scrapes).
    pub fn render(&self, out: &mut String) {
        use std::fmt::Write as _;
        if self.is_empty() {
            return;
        }
        let _ = writeln!(
            out,
            "# HELP lr_filter_eval_duration_seconds Filter DSL evaluation latency, by direction and filter name."
        );
        let _ = writeln!(out, "# TYPE lr_filter_eval_duration_seconds histogram");
        for (direction, name, hist) in &self.entries {
            let labels = format!(
                "{{direction=\"{}\",filter=\"{}\"}}",
                direction.label(),
                name
            );
            hist.render(out, "lr_filter_eval_duration_seconds", &labels);
        }
    }
}

impl Default for FilterMetricsRegistry {
    fn default() -> Self {
        Self::new()
    }
}

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
    /// Per-filter evaluation histograms (ROADMAP-v3 D12.4). `None` →
    /// the `lr_filter_eval_duration_seconds` block is omitted. Built
    /// by the BGP daemon when `--metrics-addr` is configured and
    /// shared with the import/export filter hooks, which record into
    /// it only when it exists.
    pub filter_metrics: Option<Arc<FilterMetricsRegistry>>,
    /// Human-readable label per session handle (the `peer` label of
    /// `lr_bgp_updates_total`): the BGP daemon maps handle →
    /// configured peer name/address. Falls back to `"?"` for
    /// sessions without a label (non-BGP daemons never emit BGP
    /// series, so the fallback is cosmetic).
    pub session_label: Box<dyn Fn(u64) -> String + Send + Sync>,
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
    use std::io::{BufRead, BufReader, Write};
    use std::net::TcpListener;
    use std::sync::atomic::Ordering;
    use std::thread;
    use std::time::Duration;

    /// Everything a connection thread needs to render one scrape —
    /// the [`MetricsContext`] fields, re-shaped for sharing across
    /// the accept loop and its per-connection threads (every field
    /// `Arc`-cloned once per accepted connection).
    struct ScrapeState {
        info: Arc<MetricsInfo>,
        router: Arc<RwLock<DefaultRouter>>,
        has_roa: bool,
        roa_len: Arc<dyn Fn() -> usize + Send + Sync>,
        filter_metrics: Option<Arc<FilterMetricsRegistry>>,
        session_label: Arc<dyn Fn(u64) -> String + Send + Sync>,
        started: std::time::Instant,
    }

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
        let filter_metrics = ctx.filter_metrics;
        let session_label = Arc::from(ctx.session_label);
        let started = std::time::Instant::now();
        let addr_owned = addr.to_string();

        let state = Arc::new(ScrapeState {
            info,
            router,
            has_roa,
            roa_len,
            filter_metrics,
            session_label,
            started,
        });

        thread::Builder::new()
            .name("lr-metrics".into())
            .spawn(move || {
                accept_loop(&listener, &running, |stream| {
                    let state = Arc::clone(&state);
                    thread::Builder::new()
                        .name("lr-metrics-conn".into())
                        .spawn(move || serve_connection(stream, &state))
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
    fn serve_connection(stream: std::net::TcpStream, state: &ScrapeState) {
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
                render_metrics(state),
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
    fn render_metrics(state: &ScrapeState) -> String {
        let ScrapeState {
            info,
            router,
            has_roa,
            roa_len,
            filter_metrics,
            session_label,
            started,
        } = state;
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

        // lr_bgp_updates_total — per-session BGP UPDATE counters
        // (FRR "Message statistics" parity). Counters, not gauges:
        // they are monotonic for the daemon's lifetime (per-neighbor,
        // surviving session flaps). The `peer` label carries the
        // configured name/address when the daemon knows it, so an
        // operator can alert per neighbor; the `session` label keeps
        // series unique (bidirectional peers have two sessions per
        // neighbor for RFC 4271 §6.8 collision resolution).
        let bgp_sessions: Vec<_> = summaries.iter().filter(|s| s.kind == "bgp").collect();
        if !bgp_sessions.is_empty() {
            writeln!(
                out,
                "# HELP lr_bgp_updates_total BGP UPDATE messages exchanged per session, by direction. Monotonic across session re-establishment."
            )
            .ok();
            writeln!(out, "# TYPE lr_bgp_updates_total counter").ok();
            for s in &bgp_sessions {
                let peer = session_label(s.handle.0);
                writeln!(
                    out,
                    "lr_bgp_updates_total{{session=\"{h}\",peer=\"{peer}\",direction=\"received\"}} {rx}",
                    h = s.handle.0,
                    peer = escape_label(&peer),
                    rx = s.updates_received,
                )
                .ok();
                writeln!(
                    out,
                    "lr_bgp_updates_total{{session=\"{h}\",peer=\"{peer}\",direction=\"sent\"}} {tx}",
                    h = s.handle.0,
                    peer = escape_label(&peer),
                    tx = s.updates_sent,
                )
                .ok();
            }
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
        if *has_roa {
            writeln!(
                out,
                "# HELP lr_roa_entries Number of ROA entries in the live ROA store (static + RTR cache)."
            )
            .ok();
            writeln!(out, "# TYPE lr_roa_entries gauge").ok();
            writeln!(out, "lr_roa_entries {}", roa_len()).ok();
        }

        // lr_filter_eval_duration_seconds — the per-filter DSL
        // evaluation histogram. Omitted entirely when no registry
        // was wired in (no `--metrics-addr`, or a daemon mode with
        // no filter hooks).
        if let Some(registry) = filter_metrics {
            registry.render(&mut out);
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

#[cfg(test)]
mod tests {
    use super::*;

    /// Every bucket line is cumulative and monotone, the `+Inf`
    /// bucket equals `_count`, and `_sum` is the exact total.
    #[test]
    fn histogram_buckets_are_cumulative() {
        let h = DurationHistogram::new();
        // One observation per bucket boundary plus one beyond the
        // last bound (lands only in `+Inf` via the count).
        for bound in DurationHistogram::BOUNDS {
            h.record(bound);
        }
        h.record(u64::MAX / 2); // larger than every bound

        let mut out = String::new();
        h.render(&mut out, "test_hist", "{direction=\"import\"}");
        let lines: Vec<&str> = out.lines().collect();
        assert_eq!(lines.len(), DurationHistogram::BOUNDS.len() + 2);
        // Bucket values strictly non-decreasing.
        let mut prev = 0u64;
        for (i, line) in lines.iter().enumerate() {
            if i < DurationHistogram::BOUNDS.len() {
                let value: u64 = line.rsplit(' ').next().unwrap().parse().unwrap();
                assert!(value >= prev, "cumulative buckets must not decrease");
                prev = value;
            }
        }
        // The last bucket (10 ms) holds every in-bounds observation;
        // _count additionally includes the out-of-bounds one.
        let last_bucket: u64 = lines[DurationHistogram::BOUNDS.len() - 1]
            .rsplit(' ')
            .next()
            .unwrap()
            .parse()
            .unwrap();
        let count: u64 = lines[DurationHistogram::BOUNDS.len() + 1]
            .rsplit(' ')
            .next()
            .unwrap()
            .parse()
            .unwrap();
        assert_eq!(last_bucket, DurationHistogram::BOUNDS.len() as u64);
        assert_eq!(count, DurationHistogram::BOUNDS.len() as u64 + 1);
        // `_count` == count() helper.
        assert_eq!(h.count(), count);
        // A bucket label renders with the comma join: the first line
        // carries both the direction and le labels.
        assert!(lines[0].starts_with("test_hist_bucket{direction=\"import\",le=\""));
    }

    /// The seconds rendering is exact at nanosecond precision for the
    /// fixed bounds (all multiples of 50 ns).
    #[test]
    fn seconds_formatting_is_exact() {
        assert_eq!(format_secs(100), "0.000000100");
        assert_eq!(format_secs(250), "0.000000250");
        assert_eq!(format_secs(1_000), "0.000001000");
        assert_eq!(format_secs(10_000_000), "0.010000000");
        assert_eq!(format_secs(0), "0.000000000");
    }

    /// The registry renders the HELP/TYPE headers once and one
    /// bucket/sum/count block per registered series, in registration
    /// order.
    #[test]
    fn registry_renders_prometheus_block() {
        let mut r = FilterMetricsRegistry::new();
        let import = r.register(FilterDirection::Import, "in-filter");
        let export = r.register(FilterDirection::Export, "out-filter");
        import.record(120);
        export.record(240);
        export.record(480);

        let mut out = String::new();
        r.render(&mut out);
        let lines: Vec<&str> = out.lines().collect();
        assert_eq!(
            lines[0],
            "# HELP lr_filter_eval_duration_seconds Filter DSL evaluation latency, by direction and filter name."
        );
        assert_eq!(lines[1], "# TYPE lr_filter_eval_duration_seconds histogram");
        // First series block: 16 buckets + sum + count.
        assert!(lines[2].contains("direction=\"import\""));
        assert!(lines[2].contains("filter=\"in-filter\""));
        assert!(lines[2].contains("le=\"0.000000100\""));
        assert_eq!(
            lines[2 + DurationHistogram::BOUNDS.len()],
            "lr_filter_eval_duration_seconds_sum{direction=\"import\",filter=\"in-filter\"} 0.000000120"
        );
        assert_eq!(
            lines[3 + DurationHistogram::BOUNDS.len()],
            "lr_filter_eval_duration_seconds_count{direction=\"import\",filter=\"in-filter\"} 1"
        );
        // Second series.
        let second = 4 + DurationHistogram::BOUNDS.len();
        assert!(lines[second].contains("direction=\"export\""));
        assert!(lines[second].contains("filter=\"out-filter\""));
        assert_eq!(
            lines[second + DurationHistogram::BOUNDS.len()],
            "lr_filter_eval_duration_seconds_sum{direction=\"export\",filter=\"out-filter\"} 0.000000720"
        );
        assert_eq!(
            lines[second + DurationHistogram::BOUNDS.len() + 1],
            "lr_filter_eval_duration_seconds_count{direction=\"export\",filter=\"out-filter\"} 2"
        );
    }

    /// An empty registry renders nothing (the metric block is omitted
    /// from the exposition rather than emitting bare headers).
    #[test]
    fn empty_registry_renders_nothing() {
        let r = FilterMetricsRegistry::new();
        assert!(r.is_empty());
        let mut out = String::new();
        r.render(&mut out);
        assert!(out.is_empty());
    }

    /// Histograms are shareable across threads: concurrent records
    /// all land (relaxed atomics suffice — the test only checks the
    /// total, not the bucket split).
    #[test]
    fn histogram_concurrent_records_all_land() {
        let h = std::sync::Arc::new(DurationHistogram::new());
        let mut joins = Vec::new();
        for t in 0..4u64 {
            let h = std::sync::Arc::clone(&h);
            joins.push(std::thread::spawn(move || {
                for i in 0..1000u64 {
                    h.record(50 + (t * 1000 + i) % 5_000);
                }
            }));
        }
        for j in joins {
            j.join().unwrap();
        }
        assert_eq!(h.count(), 4 * 1000);
    }
}
