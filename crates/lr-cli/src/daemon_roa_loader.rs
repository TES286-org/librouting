//! Advanced ROA loading — periodic URL fetching and file change
//! reloading (issue #100).
//!
//! Two loading methods sit on top of the format parsers in
//! [`lr_bgp::roa_loader`]:
//!
//! * **URL sources** — periodic HTTP(S) fetch with a configurable
//!   interval. The body is parsed with the source's configured
//!   format and the entries replace the [`RoaStore`]'s static
//!   layer atomically. A fetch failure keeps the previous snapshot
//!   (origin validation must never be weakened by a network
//!   hiccup).
//! * **File sources** — mtime-based polling. The daemon watches
//!   the configured file's modification time; when it changes
//!   (the operator ran `routinator vrps -o /etc/lr/roas.json` or
//!   an `awk` pipeline wrote a new file), the daemon re-reads and
//!   re-applies the entries. The same atomic swap applies.
//!
//! # Threading model
//!
//! One thread per configured source, mirroring the RPKI-RTR thread
//! in [`crate::daemon_rpki`]: the daemon owns a handle (status +
//! control channel), the thread owns the I/O loop. The handle
//! stays alive across SIGHUP reloads (the operator may reconfigure
//! the source list); a control command re-points a URL source or
//! tears a source down.
//!
//! # Atomic snapshot discipline
//!
//! Both loading paths go through [`RoaStore::replace_static`],
//! which rebuilds the merged entry set and swaps the snapshot in
//! as one `Arc<RoaTable>`. A reader either sees the previous
//! table or the new one, never a half-applied reload — the same
//! contract the RTR client upholds per sync.
//!
//! # Multiple sources
//!
//! A daemon may configure multiple sources; their static-layer
//! entries are unioned (deduplicated by `RoaEntry`'s `Ord`).
//! A reload of one source replaces only that source's
//! contribution. To keep this contract simple and predictable,
//! the loader maintains per-source entry sets and recomputes the
//! union on every reload.

use std::collections::{BTreeMap, BTreeSet};
use std::io::Read;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant, SystemTime};

use lr_bgp::{RoaEntry, RoaStore};
use lr_bgp::{RoaFormat, RoaLoaderError};

use crate::Component;

/// How often a file source's mtime is polled. Small enough that an
/// operator's `routinator` rewrite lands inside the operator's
/// expected propagation window; large enough that an idle file
/// source does not spin the loader thread. BIRD's default minimum
/// settle time is 1 s (the same window the operator expects here).
const FILE_POLL_INTERVAL: Duration = Duration::from_secs(1);

/// Upper bound on the loader loop's idle sleep. Sliced so a
/// reload or shutdown command lands inside one slice.
const LOOP_SLICE: Duration = Duration::from_millis(200);

/// Default URL fetch interval when the operator does not pin one
/// (matches the RPKI-RTR `refresh_interval` default of one hour,
/// RFC 8210 §6).
const DEFAULT_URL_INTERVAL: Duration = Duration::from_secs(3600);

/// HTTP fetch timeout. Bounds how long a hung URL holds the loader
/// thread before the fetch is abandoned and retried on the next
/// interval. Generous against a slow origin, short enough that a
/// wedged cache does not stall ROA updates indefinitely.
const FETCH_TIMEOUT: Duration = Duration::from_secs(30);

/// Maximum response body size (16 MiB). A larger body is rejected
/// so a misconfigured origin cannot OOM the daemon. The global
/// RPKI ROA set is on the order of 500k entries / 20 MB today;
/// 16 MiB covers the JSON / CSV shape comfortably.
const MAX_BODY_BYTES: usize = 16 * 1024 * 1024;

/// One ROA source — a file on disk or a URL fetched periodically.
///
/// The schema mirrors `[[bgp.roa_source]]` in `daemon.toml`:
///
/// ```toml
/// [[bgp.roa_source]]
/// path = "/etc/lr/roas.bird"
/// format = "bird"
///
/// [[bgp.roa_source]]
/// url = "https://rpki.example.com/roas.json"
/// format = "json"
/// interval = 3600
/// ```
#[derive(Debug, Clone)]
pub(crate) struct RoaSourceSpec {
    /// A local path. Mutually exclusive with `url`.
    pub path: Option<String>,
    /// An HTTP(S) URL. Mutually exclusive with `path`.
    pub url: Option<String>,
    /// The on-the-wire format. When `None`, the loader infers it
    /// from the path extension (a `.bird` file is BIRD, a `.json`
    /// URL is JSON, etc.).
    pub format: Option<RoaFormat>,
    /// Refresh interval for URL sources (seconds). Defaults to
    /// 3600 (RFC 8210 §6 refresh). Ignored for file sources —
    /// files are watched continuously via mtime polling.
    pub interval: Option<u32>,
    /// Optional HTTP `User-Agent` header for URL sources. Some
    /// ROA origins (Cloudflare, Google) require a UA; the default
    /// `lr-daemon/<version>` is sent when unset.
    pub user_agent: Option<String>,
}

impl RoaSourceSpec {
    /// Resolve the source's format, falling back to extension
    /// inference when the operator did not pin one. Returns
    /// `None` for an unknown extension (the daemon's config
    /// parser surfaces a fail-closed error in that case).
    pub(crate) fn resolve_format(&self) -> Result<RoaFormat, RoaLoaderError> {
        if let Some(f) = self.format {
            return Ok(f);
        }
        let name = self
            .path
            .as_deref()
            .or(self.url.as_deref())
            .ok_or_else(|| RoaLoaderError::Missing {
                line_no: 0,
                message: "[[bgp.roa_source]] without 'path' or 'url'".to_string(),
            })?;
        RoaFormat::from_extension(name).ok_or_else(|| {
            RoaLoaderError::UnknownFormat(format!(
                "cannot infer format from path '{name}' (set 'format' explicitly)"
            ))
        })
    }

    /// Resolve the URL fetch interval, applying the default when
    /// the operator did not pin one. Always returns at least one
    /// minute so a misconfigured `interval = 1` does not hammer
    /// the origin (RFC 8210 §6's "SHOULD NOT poll more often
    /// than the cache's refresh_interval" applies here too).
    pub(crate) fn resolve_interval(&self) -> Duration {
        let secs = self
            .interval
            .unwrap_or(DEFAULT_URL_INTERVAL.as_secs() as u32);
        let secs = secs.max(60);
        Duration::from_secs(u64::from(secs))
    }
}

impl PartialEq for RoaSourceSpec {
    fn eq(&self, other: &Self) -> bool {
        self.path == other.path
            && self.url == other.url
            && self.format == other.format
            && self.interval == other.interval
            && self.user_agent == other.user_agent
    }
}

impl Eq for RoaSourceSpec {}

/// Discriminant for [`RoaSourceSpec`] — used to diff an old vs a
/// new config and decide whether a reload should re-point a source
/// (URL or interval change) or leave it alone.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) enum SourceKey {
    File(PathBuf),
    Url(String),
}

impl RoaSourceSpec {
    /// The source's identifying key — the path or URL. Used by the
    /// daemon's reload path to match a configured source against an
    /// existing loader thread (so a SIGHUP that does not change a
    /// source's identity leaves the thread running, while a
    /// removal triggers a `Shutdown`).
    pub(crate) fn key(&self) -> Option<SourceKey> {
        if let Some(p) = &self.path {
            Some(SourceKey::File(PathBuf::from(p)))
        } else {
            self.url.as_ref().map(|s| SourceKey::Url(s.clone()))
        }
    }
}

/// One command from the daemon's control plane (the SIGHUP reload
/// path) to a loader thread. The daemon-wide `running` flag stops
/// the thread on shutdown; this enum carries the live-config
/// changes the reload path needs to push to a still-running thread.
#[derive(Debug)]
pub(crate) enum RoaLoaderCommand {
    /// Drop the current source, re-fetch / re-read the new one.
    /// Sent when the operator changed the path, URL, format or
    /// interval for a source that was already running.
    Repoint { spec: RoaSourceSpec },
    /// Stop the loader thread and clear the source's contribution
    /// to the static layer. Sent when the operator removed the
    /// `[[bgp.roa_source]]` block from the configuration.
    Shutdown,
}

/// Outcome of draining the control channel.
#[derive(Debug)]
enum Control {
    Continue,
    Interrupt,
    Stop,
}

/// Per-thread live state. The thread mutates this in its inner
/// loop; the daemon's API thread reads the [`RoaLoaderStatus`]
/// snapshot (the loader updates it under its mutex on every
/// reload).
#[derive(Debug, Clone)]
pub(crate) struct RoaLoaderStatus {
    /// The source's identifying string — the path or URL.
    pub source: String,
    /// Whether the source is a URL (true) or a file (false).
    pub is_url: bool,
    /// Last successful load's entry count.
    pub entries: usize,
    /// Whether the last load succeeded. `false` after a
    /// fetch / read failure (the previous snapshot is preserved,
    /// so validation keeps running).
    pub healthy: bool,
    /// Age of the last successful load, in seconds. `None` when
    /// no load has completed yet (the source is mid-fetch on
    /// startup).
    pub last_load_age_s: Option<u64>,
    /// Human-readable description of the last error, when
    /// `healthy = false`. Cleared on the next successful load.
    pub last_error: Option<String>,
    /// The source's resolved format name — `"bird"`, `"json"`,
    /// `"csv"` or `"native"`. Rendered by the `status` API so
    /// the operator can verify the loader picked the right
    /// parser.
    pub format: &'static str,
}

impl RoaLoaderStatus {
    /// The one-line `status` output. Keys are `key=value` pairs
    /// so the API stays grep-friendly (mirrors [`RpkiStatus`]).
    pub fn status_line(&self) -> String {
        let age = self
            .last_load_age_s
            .map(|a| format!("{a}s"))
            .unwrap_or_else(|| "-".to_string());
        let state = if self.healthy { "ok" } else { "error" };
        let err = self.last_error.as_deref().unwrap_or("");
        format!(
            "roa-source: {} type={} format={} entries={} state={} last-load={}{}",
            self.source,
            if self.is_url { "url" } else { "file" },
            self.format,
            self.entries,
            state,
            age,
            if err.is_empty() {
                String::new()
            } else {
                format!(" error=\"{err}\"")
            },
        )
    }
}

/// The handle the daemon keeps: status for the API thread, control
/// for the reload path. `Clone` shares the same underlying state.
#[derive(Clone)]
pub(crate) struct RoaLoaderHandle {
    status: Arc<Mutex<RoaLoaderStatus>>,
    control: Sender<RoaLoaderCommand>,
    /// The source key — used by the daemon's reload path to
    /// match a configured source against an existing thread.
    key: SourceKey,
}

impl RoaLoaderHandle {
    pub(crate) fn key(&self) -> &SourceKey {
        &self.key
    }

    /// The rendered `status` line for the runtime API.
    pub(crate) fn status_line(&self) -> String {
        self.status.lock().unwrap().status_line()
    }

    /// Ask the thread to drop the current source and pick up the
    /// new one. Returns the log line describing what was requested.
    pub(crate) fn repoint(&self, spec: RoaSourceSpec) -> String {
        match self.control.send(RoaLoaderCommand::Repoint { spec }) {
            Ok(()) => "roa-source: reload requested".to_string(),
            Err(_) => "roa-source: loader thread is gone (no reload possible)".to_string(),
        }
    }

    /// Ask the thread to stop and clear its contribution to the
    /// static layer. Returns the log line describing what was
    /// requested.
    pub(crate) fn shutdown(&self) -> String {
        match self.control.send(RoaLoaderCommand::Shutdown) {
            Ok(()) => "roa-source: shutdown requested".to_string(),
            Err(_) => "roa-source: loader thread is gone (already shut down)".to_string(),
        }
    }
}

/// The shared state across all loader threads plus the daemon's
/// other static ROA contributors (the `[[roa]]` inline tables).
/// The union is recomputed on every change so a reload of one
/// source replaces only that source's contribution.
#[derive(Debug, Default)]
pub(crate) struct RoaLayerRegistry {
    /// Per-source entry sets, keyed by the source's identity
    /// (path string or URL). The union of all values plus the
    /// inline-table entries is what `RoaStore::replace_static`
    /// installs.
    layers: BTreeMap<String, Vec<RoaEntry>>,
    /// Inline-table entries (the daemon's `[[roa]]` TOML tables).
    /// Set once at startup and on every SIGHUP-driven reload; the
    /// loader threads do not touch this set.
    inline: Vec<RoaEntry>,
}

impl RoaLayerRegistry {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// Replace one source's contribution. Recomputes the union
    /// and swaps it into the live [`RoaStore`].
    pub(crate) fn replace(&mut self, key: String, entries: Vec<RoaEntry>, store: &RoaStore) {
        self.layers.insert(key, entries);
        self.apply(store);
    }

    /// Drop one source's contribution (the operator removed the
    /// `[[bgp.roa_source]]` block). Recomputes the union without
    /// the dropped layer.
    pub(crate) fn remove(&mut self, key: &str, store: &RoaStore) {
        self.layers.remove(key);
        self.apply(store);
    }

    /// Replace the inline-table layer (SIGHUP reload of `[[roa]]`
    /// TOML tables). Recomputes the union.
    pub(crate) fn replace_inline(&mut self, inline: Vec<RoaEntry>, store: &RoaStore) {
        self.inline = inline;
        self.apply(store);
    }

    /// Recompute the merged entry set and swap it into the store.
    /// The union is deduplicated (the same entry in two layers
    /// counts once) and sorted (the same input always produces
    /// the same table, so status output is deterministic).
    fn apply(&self, store: &RoaStore) {
        let mut merged: BTreeSet<RoaEntry> = self.inline.iter().copied().collect();
        for entries in self.layers.values() {
            merged.extend(entries.iter().copied());
        }
        store.replace_static(merged);
    }

    /// Total entry count across all layers (deduplicated).
    pub(crate) fn len(&self) -> usize {
        let mut merged: BTreeSet<RoaEntry> = self.inline.iter().copied().collect();
        for entries in self.layers.values() {
            merged.extend(entries.iter().copied());
        }
        merged.len()
    }
}

/// Spawn a loader thread for one source. The thread runs until
/// either the daemon-wide `running` flag clears or a `Shutdown`
/// command arrives. The handle stays alive across SIGHUP reloads
/// (the operator may reconfigure the source list); a `Repoint`
/// command re-points the source.
pub(crate) fn spawn_roa_loader(
    spec: RoaSourceSpec,
    store: Arc<RoaStore>,
    registry: Arc<Mutex<RoaLayerRegistry>>,
    running: Arc<AtomicBool>,
) -> RoaLoaderHandle {
    let key = spec
        .key()
        .unwrap_or_else(|| SourceKey::File(PathBuf::new()));
    let source_str = spec
        .path
        .clone()
        .or_else(|| spec.url.clone())
        .unwrap_or_default();
    let is_url = spec.url.is_some();
    let format_str = spec
        .resolve_format()
        .map(|f| f.as_str())
        .unwrap_or("native");
    let status = Arc::new(Mutex::new(RoaLoaderStatus {
        source: source_str.clone(),
        is_url,
        entries: 0,
        healthy: false,
        last_load_age_s: None,
        last_error: None,
        format: format_str,
    }));
    let (tx, rx) = mpsc::channel::<RoaLoaderCommand>();
    let handle = RoaLoaderHandle {
        status: Arc::clone(&status),
        control: tx,
        key,
    };
    let thread_status = Arc::clone(&status);
    let spawned = thread::Builder::new()
        .name(format!("lr-roa-loader:{source_str}"))
        .spawn(move || {
            let mut state = LoaderLoop {
                spec,
                store,
                registry,
                running,
                control: rx,
                status: thread_status,
                last_load: None,
                stopped: false,
                file_mtime: None,
            };
            state.run();
        });
    if let Err(e) = spawned {
        panic!("roa-source: cannot spawn loader thread: {e}");
    }
    handle
}

/// The per-thread state machine.
struct LoaderLoop {
    spec: RoaSourceSpec,
    store: Arc<RoaStore>,
    registry: Arc<Mutex<RoaLayerRegistry>>,
    running: Arc<AtomicBool>,
    control: Receiver<RoaLoaderCommand>,
    status: Arc<Mutex<RoaLoaderStatus>>,
    last_load: Option<Instant>,
    /// Latched when a `Shutdown` arrives — the outer loop breaks
    /// and every later control command fails on a closed channel.
    stopped: bool,
    /// Cached mtime of the last applied file source. `None` for
    /// URL sources or before the first successful read.
    file_mtime: Option<SystemTime>,
}

impl LoaderLoop {
    fn run(&mut self) {
        log_info!(
            Component::Rpki,
            "roa-source: loader thread started ({})",
            self.status.lock().unwrap().source
        );
        // Initial load before entering the loop so the first
        // status poll already reports the source's state.
        self.load_once();
        loop {
            if !self.running.load(Ordering::Relaxed) || self.stopped {
                break;
            }
            match self.drain_control() {
                Control::Stop => break,
                Control::Interrupt => {
                    self.load_once();
                    continue;
                }
                Control::Continue => {}
            }
            if !self.running.load(Ordering::Relaxed) || self.stopped {
                break;
            }
            // File sources: poll mtime; URL sources: sleep until
            // the next interval boundary. Both paths slice the
            // sleep so a control command lands inside one slice.
            let now = Instant::now();
            let next = self.next_poll_deadline(now);
            let mut remaining = next.saturating_duration_since(now);
            while !remaining.is_zero() {
                if !self.running.load(Ordering::Relaxed) || self.stopped {
                    break;
                }
                match self.drain_control() {
                    Control::Stop => break,
                    Control::Interrupt => {
                        self.load_once();
                        remaining = Duration::ZERO;
                    }
                    Control::Continue => {}
                }
                let chunk = remaining.min(LOOP_SLICE);
                thread::sleep(chunk);
                remaining = remaining.saturating_sub(chunk);
            }
            if self.stopped {
                break;
            }
            // The poll deadline elapsed — re-load if mtime
            // changed (file) or always (URL).
            self.poll_once();
        }
        log_info!(
            Component::Rpki,
            "roa-source: loader thread stopping ({})",
            self.status.lock().unwrap().source
        );
        // Drop our contribution on shutdown (the operator removed
        // the `[[bgp.roa_source]]` block; the inline-table entries
        // and other sources' contributions stay).
        let source_key = self
            .spec
            .path
            .clone()
            .or_else(|| self.spec.url.clone())
            .unwrap_or_default();
        if let Ok(mut reg) = self.registry.lock() {
            reg.remove(&source_key, &self.store);
        }
    }

    /// Compute when the loop should next wake up to poll. For a
    /// URL source, this is `last_load + interval`. For a file
    /// source, this is `now + FILE_POLL_INTERVAL` (mtime polling
    /// is cheap and the operator expects a rewrite to land
    /// promptly).
    fn next_poll_deadline(&self, now: Instant) -> Instant {
        if self.spec.url.is_some() {
            let interval = self.spec.resolve_interval();
            match self.last_load {
                Some(t) => t + interval,
                None => now + Duration::from_secs(1),
            }
        } else {
            now + FILE_POLL_INTERVAL
        }
    }

    /// Drain one control command (non-blocking).
    fn drain_control(&mut self) -> Control {
        match self.control.try_recv() {
            Ok(RoaLoaderCommand::Repoint { spec }) => {
                let new_source = spec
                    .path
                    .clone()
                    .or_else(|| spec.url.clone())
                    .unwrap_or_default();
                log_info!(
                    Component::Rpki,
                    "roa-source: repoint -> {new_source} (format {}, interval {}s)",
                    spec.resolve_format().map(|f| f.as_str()).unwrap_or("?"),
                    spec.resolve_interval().as_secs()
                );
                // Drop the old source's contribution (the new
                // source may have a different key, in which case
                // the old layer would otherwise linger forever).
                let old_source = self
                    .spec
                    .path
                    .clone()
                    .or_else(|| self.spec.url.clone())
                    .unwrap_or_default();
                if old_source != new_source {
                    if let Ok(mut reg) = self.registry.lock() {
                        reg.remove(&old_source, &self.store);
                    }
                }
                self.spec = spec;
                self.file_mtime = None;
                self.last_load = None;
                {
                    let mut st = self.status.lock().unwrap();
                    st.source = new_source;
                    st.is_url = self.spec.url.is_some();
                    st.healthy = false;
                    st.entries = 0;
                    st.last_load_age_s = None;
                    st.last_error = None;
                    st.format = self
                        .spec
                        .resolve_format()
                        .map(|f| f.as_str())
                        .unwrap_or("native");
                }
                Control::Interrupt
            }
            Ok(RoaLoaderCommand::Shutdown) => {
                self.stopped = true;
                log_info!(Component::Rpki, "roa-source: shutdown requested");
                Control::Stop
            }
            Err(mpsc::TryRecvError::Empty) => Control::Continue,
            Err(mpsc::TryRecvError::Disconnected) => {
                // The handle is gone — the daemon is shutting
                // down. Treat as a stop so the thread exits
                // cleanly.
                self.stopped = true;
                Control::Stop
            }
        }
    }

    /// Always re-load (used by the initial load, by a Repoint
    /// command and by the URL-source poll deadline).
    fn load_once(&mut self) {
        let result = self.fetch_and_apply();
        self.record_result(result);
    }

    /// Poll-on-deadline: for a URL source this is equivalent to
    /// `load_once`; for a file source this only re-loads if the
    /// mtime changed since the last applied read.
    fn poll_once(&mut self) {
        if self.spec.url.is_some() {
            self.load_once();
            return;
        }
        // File source: stat the path, compare mtime.
        let Some(path) = self.spec.path.as_deref() else {
            return;
        };
        let mtime = match std::fs::metadata(path).and_then(|m| m.modified()) {
            Ok(t) => t,
            Err(e) => {
                self.record_result(Err(RoaLoaderError::Io(format!("stat {path} failed: {e}"))));
                return;
            }
        };
        if Some(mtime) == self.file_mtime {
            // No change since the last applied read. Update the
            // status's `last_load_age_s` so the operator sees
            // how old the current snapshot is.
            self.touch_status_age();
            return;
        }
        // mtime advanced — re-read.
        self.file_mtime = Some(mtime);
        self.load_once();
    }

    /// Fetch (URL) or read (file) and apply. The actual I/O is
    /// dispatched through `fetch_url` / `read_file`; this method
    /// feeds the parsed entries to the layer registry.
    fn fetch_and_apply(&self) -> Result<usize, RoaLoaderError> {
        let format = self.spec.resolve_format()?;
        let text = if let Some(url) = self.spec.url.as_deref() {
            self.fetch_url(url)?
        } else if let Some(path) = self.spec.path.as_deref() {
            self.read_file(path)?
        } else {
            return Err(RoaLoaderError::Missing {
                line_no: 0,
                message: "[[bgp.roa_source]] without 'path' or 'url'".to_string(),
            });
        };
        let entries = lr_bgp::parse_roa(&text, format)?;
        let count = entries.len();
        let source_key = self
            .spec
            .path
            .clone()
            .or_else(|| self.spec.url.clone())
            .unwrap_or_default();
        if let Ok(mut reg) = self.registry.lock() {
            reg.replace(source_key, entries, &self.store);
        }
        Ok(count)
    }

    /// Fetch a URL via `ureq`. Enforces the configured timeout
    /// and the maximum body size; honours a custom `User-Agent`.
    fn fetch_url(&self, url: &str) -> Result<String, RoaLoaderError> {
        let agent = ureq::AgentBuilder::new().timeout(FETCH_TIMEOUT).build();
        let mut req = agent.get(url);
        if let Some(ua) = self.spec.user_agent.as_deref() {
            req = req.set("User-Agent", ua);
        } else {
            req = req.set("User-Agent", &default_user_agent());
        }
        let resp = req
            .call()
            .map_err(|e| RoaLoaderError::Io(format!("fetch {url}: {e}")))?;
        // Cap the body size to protect against a misconfigured
        // origin streaming a huge response.
        let mut body = Vec::new();
        let mut reader = resp.into_reader().take(MAX_BODY_BYTES as u64 + 1);
        std::io::copy(&mut reader, &mut body)
            .map_err(|e| RoaLoaderError::Io(format!("read {url}: {e}")))?;
        if body.len() > MAX_BODY_BYTES {
            return Err(RoaLoaderError::Io(format!(
                "body of {url} exceeds {} bytes",
                MAX_BODY_BYTES
            )));
        }
        String::from_utf8(body)
            .map_err(|e| RoaLoaderError::Io(format!("body of {url} is not UTF-8: {e}")))
    }

    /// Read a file from disk into a UTF-8 string.
    fn read_file(&self, path: &str) -> Result<String, RoaLoaderError> {
        std::fs::read_to_string(path).map_err(|e| RoaLoaderError::Io(format!("read {path}: {e}")))
    }

    /// Record the outcome of a fetch / read into the status
    /// snapshot and log the appropriate line. On success the
    /// `last_load` instant advances; on failure the previous
    /// snapshot is preserved (the layer registry's `apply` is
    /// only called from `fetch_and_apply` on success).
    fn record_result(&mut self, result: Result<usize, RoaLoaderError>) {
        let mut st = self.status.lock().unwrap();
        match result {
            Ok(count) => {
                let was_healthy = st.healthy;
                st.healthy = true;
                st.entries = count;
                st.last_load_age_s = Some(0);
                st.last_error = None;
                self.last_load = Some(Instant::now());
                if !was_healthy {
                    log_info!(
                        Component::Rpki,
                        "roa-source: {} loaded {} entries (format {})",
                        st.source,
                        count,
                        st.format
                    );
                } else if st.entries != count {
                    // Healthy→healthy transition with a count
                    // change: log the delta so the operator can
                    // see the refresh.
                    log_info!(
                        Component::Rpki,
                        "roa-source: {} reloaded {} entries",
                        st.source,
                        count
                    );
                }
            }
            Err(e) => {
                let was_healthy = st.healthy;
                st.healthy = false;
                st.last_error = Some(e.to_string());
                if was_healthy {
                    log_warn!(
                        Component::Rpki,
                        "roa-source: {} load failed ({e}) — keeping previous snapshot",
                        st.source
                    );
                } else {
                    log_warn!(
                        Component::Rpki,
                        "roa-source: {} still failing ({e})",
                        st.source
                    );
                }
            }
        }
    }

    /// Refresh the status's `last_load_age_s` field without
    /// triggering a reload (the file's mtime did not change).
    fn touch_status_age(&self) {
        if let Some(t) = self.last_load {
            let mut st = self.status.lock().unwrap();
            st.last_load_age_s = Some(t.elapsed().as_secs());
        }
    }
}

/// Build the default `User-Agent` string sent with URL fetches.
/// Includes the daemon version so a ROA origin can identify lr
/// clients in its access logs.
fn default_user_agent() -> String {
    let version = env!("CARGO_PKG_VERSION");
    format!("lr-daemon/{version}")
}

#[cfg(test)]
#[path = "daemon_roa_loader_tests.rs"]
mod tests;
