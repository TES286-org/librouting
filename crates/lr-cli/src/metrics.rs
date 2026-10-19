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
//! project's stance on `api.rs` (hand-rolled server, no `tokio` /
//! `hyper` dependency) and keeps the release-archive binary surface
//! unchanged.
//!
//! The thread model matches `api.rs`'s: one thread polls a
//! `set_nonblocking(true)` `TcpListener` with a 100 ms sleep, and
//! each accepted connection is served on its own short-lived thread
//! so a slow client cannot hold the metrics endpoint hostage.
//!
//! Unlike `api.rs` (which switches transport per platform — Unix
//! domain socket on Unix, named pipe on Windows), the metrics
//! endpoint binds a plain TCP listener. `std::net::TcpListener` is
//! available on every target the workspace supports, so the metrics
//! module compiles and serves identically on Linux, the BSDs,
//! macOS and Windows. The daemon's process model (signals,
//! privilege drop, named-pipe API transport) carries its own
//! platform guards; the metrics endpoint does not.
//!
//! # Exposed metrics
//!
//! | Metric                       | Type    | Labels                          | Source                                   |
//! | ---------------------------- | ------- | ------------------------------- | ---------------------------------------- |
//! | `lr_info`                    | gauge=1 | `version`, `local_as`, `peer_as`, `router_id`, `config_path` | daemon identity (for join queries)  |
//! | `lr_uptime_seconds`          | gauge   | —                               | `Instant::elapsed()` since `spawn`       |
//! | `lr_sessions_total`          | gauge   | `kind`, `state`                 | `session_summaries()` count per (kind, state) |
//! | `lr_established_sessions`    | gauge   | `kind`                          | `session_summaries().established` count |
//! | `lr_session_up`              | gauge=0/1 | `kind`, `session`, `peer`     | per-session established flag            |
//! | `lr_session_state_transitions_total` | counter | `kind`, `session`, `peer` | `SessionStats::state_transitions`     |
//! | `lr_session_adj_rib_in_entries` | gauge | `kind`, `session`, `peer`      | per-session `adj_rib_in_len`             |
//! | `lr_session_negotiated_hold_time_seconds` | gauge | `kind`, `session`, `peer` | per-session negotiated hold time     |
//! | `lr_session_last_keepalive_received_ms` | gauge | `kind`, `session`, `peer` | per-session `SessionStats::last_keepalive_received_ms` (BGP only) |
//! | `lr_session_last_error`     | gauge=1 | `kind`, `session`, `peer`, `error_kind` | per-session last error kind (one series holds 1, the rest 0) |
//! | `lr_rib_entries`             | gauge   | —                               | `rib_len()`                              |
//! | `lr_rib_entries_by_protocol` | gauge  | `protocol`                      | `rib_snapshot()` grouped by `Route::protocol` |
//! | `lr_adj_rib_in_entries`      | gauge   | `kind`                          | sum of `adj_rib_in_len` per kind         |
//! | `lr_aggregates_count`        | gauge   | —                               | `aggregate_prefixes().len()`              |
//! | `lr_static_routes_count`     | gauge   | —                               | `static_routes().len()`                   |
//! | `lr_originated_routes_count` | gauge   | —                               | `originated_keys().len()`                 |
//! | `lr_bgp_updates_total`      | counter | `session`, `peer`, `direction`  | `SessionSummary::updates_received/sent` per BGP session (legacy; see `lr_bgp_messages_total{type="update"}` for the comprehensive view) |
//! | `lr_bgp_messages_total`     | counter | `session`, `peer`, `type`, `direction` | `SessionSummary::message_stats` per BGP session (open/update/notification/keepalive/route_refresh) |
//! | `lr_roa_entries`             | gauge   | —                               | `RoaStore::len()` (when present)        |
//! | `lr_process_resident_bytes` | gauge   | —                               | `/proc/self/status` VmRSS (Linux only) |
//! | `lr_process_virtual_bytes`  | gauge   | —                               | `/proc/self/status` VmSize (Linux only) |
//! | `lr_filter_eval_duration_seconds` | histogram | `direction`, `filter`      | `FilterMetricsRegistry` (when present)  |
//!
//! The exporter is **opt-in** (default off, like `api_socket`):
//! `--metrics-addr 127.0.0.1:9119` / top-level `metrics_addr = "…"`.
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
    ///
    /// Read by the exporter's render path on every platform; the
    /// unit tests exercise the same call.
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
/// The exporter binds a plain TCP listener (see [`spawn`]); the
/// context is platform-independent data.
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
pub struct MetricsInfo {
    pub version: String,
    pub local_as: u32,
    pub router_id: String,
    /// Config file path (or the string `(none)` when the daemon
    /// was started without one). Surfaced as a label on `lr_info`
    /// so a scraper can join the daemon's runtime identity to its
    /// config source.
    pub config_path: String,
    /// Configured peer AS (BGP only; `0` when not configured).
    /// Surfaced as a label on `lr_info` so a scraper can tell
    /// single-peer daemons apart from multi-peer ones at a glance.
    pub peer_as: u32,
}

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

    /// One scrape's worth of router state, snapshotted under a single
    /// read-lock acquisition. Carries everything the renderer needs so
    /// the lock is held for microseconds (no I/O while it's held).
    ///
    /// `rib_by_protocol` is a sorted `(protocol, count)` list (sorted
    /// by name for stable diffs). The other fields are scalar counts
    /// or owned `Vec`s that can be cheaply cloned out of the locked
    /// router.
    struct RenderSnapshot {
        uptime: u64,
        summaries: Vec<lr_router::SessionSummary>,
        rib_len: usize,
        rib_by_protocol: Vec<(&'static str, u64)>,
        aggregates_count: u64,
        static_routes_count: u64,
        originated_count: u64,
    }

    impl RenderSnapshot {
        fn collect(r: &DefaultRouter, started: std::time::Instant) -> Self {
            use lr_router::RouterInstance as _;
            let summaries = r.session_summaries();
            let rib_len = r.rib_len();
            // Group Loc-RIB best paths by `Route::protocol`'s
            // BIRD-style name (the same one `show routes count`
            // uses — kept in lockstep via the shared
            // `bird_name()` accessor so the two surfaces never
            // drift).
            let mut by_proto: std::collections::BTreeMap<&'static str, u64> =
                std::collections::BTreeMap::new();
            for route in r.rib_snapshot() {
                let name = route.protocol.bird_name();
                *by_proto.entry(name).or_insert(0) += 1;
            }
            let rib_by_protocol = by_proto.into_iter().collect();
            // `aggregate_prefixes`, `static_routes` and
            // `originated_keys` are all `pub` on `DefaultRouter`
            // (the `RouterInstance` trait only carries the
            // runtime-Loc-RIB accessors, but the configuration
            // helpers are intrinsic to the concrete type — they
            // walk the daemon's `static_routes` / `aggregates`
            // / `originated` tables, not the Loc-RIB).
            let aggregates_count = r.aggregate_prefixes().len() as u64;
            let static_routes_count = r.static_routes().len() as u64;
            let originated_count = r.originated_keys().len() as u64;
            Self {
                uptime: started.elapsed().as_secs(),
                summaries,
                rib_len,
                rib_by_protocol,
                aggregates_count,
                static_routes_count,
                originated_count,
            }
        }
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
        // Snapshot everything we need from the router under one
        // read-lock acquisition. The lock is held for microseconds
        // (no I/O while it's held — same contract as `api.rs`'s
        // `status` handler). Per-session labels are looked up after
        // the lock release; the closure is `Send + Sync` and does
        // not need the router lock.
        let snap = match router.read() {
            Ok(r) => RenderSnapshot::collect(&r, *started),
            Err(_) => {
                // Router lock poisoned — emit a minimal body so the
                // scrape does not hang. Prometheus treats `up=0` as
                // the "target is down" signal; we still emit `lr_info`
                // and `lr_uptime_seconds` so the operator can identify
                // the daemon and see how long the metrics thread has
                // been running (a proxy for "the daemon restarted
                // recently").
                return format!(
                    "# lr_info\nlr_info{{version=\"{ver}\",local_as=\"{la}\",peer_as=\"{pa}\",router_id=\"{rid}\",config_path=\"{cfg}\"}} 1\n\
                     # lr_uptime_seconds\nlr_uptime_seconds {up}\n",
                    ver = escape_label(&info.version),
                    la = info.local_as,
                    pa = info.peer_as,
                    rid = escape_label(&info.router_id),
                    cfg = escape_label(&info.config_path),
                    up = started.elapsed().as_secs(),
                );
            }
        };

        let mut out = String::with_capacity(4096);

        // lr_info — identity gauge (always 1). Useful for `sum by
        // (version)` queries that join against the daemon's release.
        writeln!(out, "# HELP lr_info librouting daemon identity (always 1).").ok();
        writeln!(out, "# TYPE lr_info gauge").ok();
        writeln!(
            out,
            "lr_info{{version=\"{ver}\",local_as=\"{la}\",peer_as=\"{pa}\",router_id=\"{rid}\",config_path=\"{cfg}\"}} 1",
            ver = escape_label(&info.version),
            la = info.local_as,
            pa = info.peer_as,
            rid = escape_label(&info.router_id),
            cfg = escape_label(&info.config_path),
        )
        .ok();

        // lr_uptime_seconds — daemon uptime since metrics thread spawn.
        writeln!(out, "# HELP lr_uptime_seconds Daemon uptime in seconds.").ok();
        writeln!(out, "# TYPE lr_uptime_seconds gauge").ok();
        writeln!(out, "lr_uptime_seconds {}", snap.uptime).ok();

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
        for s in &snap.summaries {
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

        // Per-session gauges — `lr_session_up`, transitions counter,
        // per-session Adj-RIB-In, negotiated hold time, last
        // keepalive, last error. These give an operator per-neighbor
        // visibility that the kind-aggregate above cannot (a single
        // flapping peer looks like a steady-state aggregate). The
        // `session` label is the numeric handle (stable across
        // restarts when the daemon's config is stable); `peer` is the
        // configured name/address when the daemon knows it.
        writeln!(
            out,
            "# HELP lr_session_up 1 when the session is in its fully-established state, 0 otherwise."
        )
        .ok();
        writeln!(out, "# TYPE lr_session_up gauge").ok();
        writeln!(
            out,
            "# HELP lr_session_state_transitions_total Number of FSM state transitions for this session since creation (monotonic)."
        )
        .ok();
        writeln!(out, "# TYPE lr_session_state_transitions_total counter").ok();
        writeln!(
            out,
            "# HELP lr_session_adj_rib_in_entries Routes currently held in this session's Adj-RIB-In."
        )
        .ok();
        writeln!(out, "# TYPE lr_session_adj_rib_in_entries gauge").ok();
        writeln!(
            out,
            "# HELP lr_session_negotiated_hold_time_seconds BGP hold time negotiated on the current connection (0 for non-BGP)."
        )
        .ok();
        writeln!(out, "# TYPE lr_session_negotiated_hold_time_seconds gauge").ok();
        writeln!(
            out,
            "# HELP lr_session_last_keepalive_received_ms Logical-clock ms of the most recent KEEPALIVE received from the peer (BGP only; 0 for non-BGP or never-received)."
        )
        .ok();
        writeln!(out, "# TYPE lr_session_last_keepalive_received_ms gauge").ok();
        writeln!(
            out,
            "# HELP lr_session_last_error 1 for the (kind, session, peer, error_kind) tuple matching this session's most recent error, 0 for every other error_kind of the same session. Stays 0 across the board when no error has been observed."
        )
        .ok();
        writeln!(out, "# TYPE lr_session_last_error gauge").ok();
        // The full error-kind enumeration — emitted as a 0 for every
        // kind the session is NOT currently in, so a scrape can join
        // on `error_kind` and see every session's current or absent
        // classification. Picking 0 for "no error" + 1 for the current
        // kind gives the cheapest join for alerting.
        const ERROR_KINDS: &[&str] = &[
            "none",
            "notification-received",
            "transport-closed",
            "hold-timer-expired",
            "parse-error",
            "manual",
            "other",
        ];
        for s in &snap.summaries {
            let peer = session_label(s.handle.0);
            let peer_e = escape_label(&peer);
            let kind = s.kind;
            let h = s.handle.0;
            let up = if s.established { 1 } else { 0 };
            writeln!(
                out,
                "lr_session_up{{kind=\"{kind}\",session=\"{h}\",peer=\"{peer_e}\"}} {up}",
            )
            .ok();
            writeln!(
                out,
                "lr_session_state_transitions_total{{kind=\"{kind}\",session=\"{h}\",peer=\"{peer_e}\"}} {tr}",
                tr = s.stats.state_transitions,
            )
            .ok();
            writeln!(
                out,
                "lr_session_adj_rib_in_entries{{kind=\"{kind}\",session=\"{h}\",peer=\"{peer_e}\"}} {ar}",
                ar = s.adj_rib_in_len,
            )
            .ok();
            writeln!(
                out,
                "lr_session_negotiated_hold_time_seconds{{kind=\"{kind}\",session=\"{h}\",peer=\"{peer_e}\"}} {hold}",
                hold = s.negotiated_hold_time,
            )
            .ok();
            writeln!(
                out,
                "lr_session_last_keepalive_received_ms{{kind=\"{kind}\",session=\"{h}\",peer=\"{peer_e}\"}} {ka}",
                ka = s.stats.last_keepalive_received_ms,
            )
            .ok();
            let current_err = s.stats.last_error.as_str();
            for kind_str in ERROR_KINDS {
                let v = if *kind_str == current_err { 1 } else { 0 };
                writeln!(
                    out,
                    "lr_session_last_error{{kind=\"{kind}\",session=\"{h}\",peer=\"{peer_e}\",error_kind=\"{kind_str}\"}} {v}",
                )
                .ok();
            }
        }

        // lr_bgp_updates_total — legacy per-session BGP UPDATE
        // counter (FRR "Message statistics" parity). Counters, not
        // gauges: they are monotonic for the daemon's lifetime
        // (per-neighbor, surviving session flaps). Kept for
        // backward compatibility with existing dashboards; the
        // comprehensive view is `lr_bgp_messages_total{type="update"}`
        // below.
        let bgp_sessions: Vec<_> = snap.summaries.iter().filter(|s| s.kind == "bgp").collect();
        if !bgp_sessions.is_empty() {
            writeln!(
                out,
                "# HELP lr_bgp_updates_total BGP UPDATE messages exchanged per session, by direction. Monotonic across session re-establishment. Deprecated: prefer lr_bgp_messages_total{{type=\"update\"}}."
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

            // lr_bgp_messages_total — comprehensive per-PDU counter
            // (BIRD `show protocols all` parity). 5 PDU types × 2
            // directions × N sessions. Each series is monotonic
            // across session re-establishment (the underlying
            // PeerMessageStats survives a session flap). Counters
            // because the value is monotonic for the daemon's lifetime.
            writeln!(
                out,
                "# HELP lr_bgp_messages_total BGP messages exchanged per session, by message type and direction. Monotonic across session re-establishment."
            )
            .ok();
            writeln!(out, "# TYPE lr_bgp_messages_total counter").ok();
            // Order matters for stable diffs: type outer, direction
            // inner — matches how a human reads the BIRD output.
            // `MessageKind` carries the label and the two accessor
            // closures in one place so the loop below does not
            // carry three parallel arrays. `lr_bgp::PeerMessageStats`
            // is `Copy`, so the closures take it by reference (no
            // clone needed to read the counters).
            struct MessageKind {
                label: &'static str,
                rx: fn(&lr_bgp::PeerMessageStats) -> u64,
                tx: fn(&lr_bgp::PeerMessageStats) -> u64,
            }
            const TYPES: &[MessageKind] = &[
                MessageKind {
                    label: "open",
                    rx: |m| m.open_received,
                    tx: |m| m.open_sent,
                },
                MessageKind {
                    label: "update",
                    rx: |m| m.update_received,
                    tx: |m| m.update_sent,
                },
                MessageKind {
                    label: "notification",
                    rx: |m| m.notification_received,
                    tx: |m| m.notification_sent,
                },
                MessageKind {
                    label: "keepalive",
                    rx: |m| m.keepalive_received,
                    tx: |m| m.keepalive_sent,
                },
                MessageKind {
                    label: "route_refresh",
                    rx: |m| m.route_refresh_received,
                    tx: |m| m.route_refresh_sent,
                },
            ];
            for s in &bgp_sessions {
                let peer = session_label(s.handle.0);
                let peer_e = escape_label(&peer);
                let h = s.handle.0;
                let m = &s.message_stats;
                for kind in TYPES {
                    writeln!(
                        out,
                        "lr_bgp_messages_total{{session=\"{h}\",peer=\"{peer_e}\",type=\"{label}\",direction=\"received\"}} {rx}",
                        label = kind.label,
                        rx = (kind.rx)(m),
                    )
                    .ok();
                    writeln!(
                        out,
                        "lr_bgp_messages_total{{session=\"{h}\",peer=\"{peer_e}\",type=\"{label}\",direction=\"sent\"}} {tx}",
                        label = kind.label,
                        tx = (kind.tx)(m),
                    )
                    .ok();
                }
            }
        }

        // lr_rib_entries — the Loc-RIB size.
        writeln!(
            out,
            "# HELP lr_rib_entries Number of routes in the Loc-RIB (best-path selection output)."
        )
        .ok();
        writeln!(out, "# TYPE lr_rib_entries gauge").ok();
        writeln!(out, "lr_rib_entries {}", snap.rib_len).ok();

        // lr_rib_entries_by_protocol — per-protocol breakdown of the
        // Loc-RIB best paths. BIRD `show route count` parity. Gauges
        // because a route's protocol membership can change as
        // sessions flap.
        if !snap.rib_by_protocol.is_empty() {
            writeln!(
                out,
                "# HELP lr_rib_entries_by_protocol Loc-RIB best-path count grouped by Route::protocol (BIRD show route count parity)."
            )
            .ok();
            writeln!(out, "# TYPE lr_rib_entries_by_protocol gauge").ok();
            for (proto, n) in &snap.rib_by_protocol {
                writeln!(
                    out,
                    "lr_rib_entries_by_protocol{{protocol=\"{proto}\"}} {n}"
                )
                .ok();
            }
        }

        // lr_aggregates_count / lr_static_routes_count /
        // lr_originated_routes_count — operator-side configuration
        // gauges so a scrape can answer "is the daemon still
        // originating its aggregates?" at a glance.
        writeln!(
            out,
            "# HELP lr_aggregates_count Number of aggregate prefixes the daemon is configured to originate."
        )
        .ok();
        writeln!(out, "# TYPE lr_aggregates_count gauge").ok();
        writeln!(out, "lr_aggregates_count {}", snap.aggregates_count).ok();

        writeln!(
            out,
            "# HELP lr_static_routes_count Number of static routes the daemon has installed into the Loc-RIB."
        )
        .ok();
        writeln!(out, "# TYPE lr_static_routes_count gauge").ok();
        writeln!(out, "lr_static_routes_count {}", snap.static_routes_count).ok();

        writeln!(
            out,
            "# HELP lr_originated_routes_count Number of prefixes the daemon is originating into the Loc-RIB (network statements + aggregates)."
        )
        .ok();
        writeln!(out, "# TYPE lr_originated_routes_count gauge").ok();
        writeln!(out, "lr_originated_routes_count {}", snap.originated_count).ok();

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

        // lr_process_resident_bytes / lr_process_virtual_bytes —
        // the daemon's memory usage. Linux-only (matches BIRD's
        // `show memory` stance on platforms without a discoverable
        // value). Emitted even when both fields are None so the
        // metric is always present in the exposition (a misleading
        // zero is the lesser evil than a missing series an alert
        // keys on — but on Linux the value is the real RSS/VmSize).
        let mem = crate::sysinfo::process_memory();
        writeln!(
            out,
            "# HELP lr_process_resident_bytes Daemon resident set size (Linux: VmRSS)."
        )
        .ok();
        writeln!(out, "# TYPE lr_process_resident_bytes gauge").ok();
        if let Some(rss) = mem.rss_bytes {
            writeln!(out, "lr_process_resident_bytes {rss}").ok();
        }
        writeln!(
            out,
            "# HELP lr_process_virtual_bytes Daemon virtual memory size (Linux: VmSize)."
        )
        .ok();
        writeln!(out, "# TYPE lr_process_virtual_bytes gauge").ok();
        if let Some(vsz) = mem.vsize_bytes {
            writeln!(out, "lr_process_virtual_bytes {vsz}").ok();
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

pub use imp::spawn;

#[cfg(test)]
#[path = "metrics_tests.rs"]
mod tests;
