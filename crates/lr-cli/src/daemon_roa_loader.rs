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
use std::io::{Read, Write};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant, SystemTime};

use lr_bgp::{RoaEntry, RoaStore};
use lr_bgp::{RoaFormat, RoaLoaderError};

use crate::Component;

// On Unix we put each transform subprocess in its own process group
// (via `CommandExt::process_group`) so a timeout can kill the entire
// tree — `sh -c "sleep 120"` would otherwise leave `sleep 120`
// orphaned but holding the stdout pipe open, blocking the reader
// thread until the sleep finishes. Windows has no process groups in
// the POSIX sense; `child.kill()` terminates the immediate child
// (which on Windows also closes the handles inherited by any
// grandchild), which is sufficient.
#[cfg(unix)]
use std::os::unix::process::CommandExt;

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

/// Maximum response body size (256 MiB). A larger body is rejected
/// so a misconfigured origin cannot OOM the daemon. The global RPKI
/// VRP set crossed 1 million entries in late 2024 (RPKIViews.org),
/// which makes a Routinator JSON dump on the order of 100 MB and a
/// BIRD-format dump on the order of 50 MB. 256 MiB covers both
/// shapes comfortably with roughly 2.5x headroom for the next few
/// years of VRP growth plus operator-local additions.
const MAX_BODY_BYTES: usize = 256 * 1024 * 1024;

/// One ROA source — a file on disk or a URL fetched periodically.
///
/// The schema mirrors the `bgp.roa_source { … }` block in the LR
/// config DSL (and the legacy `[[bgp.roa_source]]` TOML table):
///
/// ```text
/// # Legacy TOML (deprecated; use the .lr DSL instead):
/// [[bgp.roa_source]]
/// path = "/etc/lr/roas.bird"
/// format = "bird"
///
/// [[bgp.roa_source]]
/// url = "https://rpki.example.com/roas.json"
/// format = "jq"
/// program = ".roas[] | \"roa \\(.prefix) max \\(.maxLength) as \\(.asn);\""
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
    /// URL is `jq`, etc.).
    pub format: Option<RoaFormat>,
    /// Refresh interval for URL sources (seconds). Defaults to
    /// 3600 (RFC 8210 §6 refresh). Ignored for file sources —
    /// files are watched continuously via mtime polling.
    pub interval: Option<u32>,
    /// Optional HTTP `User-Agent` header for URL sources. Some
    /// ROA origins (Cloudflare, Google) require a UA; the default
    /// `lr-daemon/<version>` is sent when unset.
    pub user_agent: Option<String>,
    /// Inline transform program for `jq` / `awk` format sources
    /// (issue #100). The program is fed to `jq -r PROGRAM` or
    /// `awk 'PROGRAM'` with the source bytes on stdin; the
    /// program's stdout is parsed as BIRD-format ROA lines.
    /// Mutually exclusive with [`program_file`](Self::program_file);
    /// required (one of the two) when `format` is `jq` or `awk`.
    pub program: Option<String>,
    /// Path to a file holding the transform program. Read at load
    /// time so the operator can update the program without
    /// restarting the daemon (an mtime change on this file is
    /// **not** watched — only the source's own path / URL is;
    /// SIGHUP re-reads the program). Mutually exclusive with
    /// [`program`](Self::program).
    pub program_file: Option<String>,
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
                message: "roa_source without 'path' or 'url'".to_string(),
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

    /// Resolve the transform program for `jq` / `awk` format
    /// sources. Returns the inline [`program`](Self::program) when
    /// set, otherwise reads [`program_file`](Self::program_file).
    /// Returns `Ok(None)` for non-transform formats (the caller
    /// checks `format.requires_program()` first).
    pub(crate) fn resolve_program(&self) -> Result<Option<String>, RoaLoaderError> {
        if let Some(p) = &self.program {
            return Ok(Some(p.clone()));
        }
        if let Some(path) = &self.program_file {
            let text = std::fs::read_to_string(path)
                .map_err(|e| RoaLoaderError::Io(format!("read program_file {path}: {e}")))?;
            return Ok(Some(text));
        }
        Ok(None)
    }
}

impl PartialEq for RoaSourceSpec {
    fn eq(&self, other: &Self) -> bool {
        self.path == other.path
            && self.url == other.url
            && self.format == other.format
            && self.interval == other.interval
            && self.user_agent == other.user_agent
            && self.program == other.program
            && self.program_file == other.program_file
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
    /// The source's resolved format name — `"native"`, `"bird"`,
    /// `"jq"` or `"awk"`. Rendered by the `status` API so
    /// the operator can verify the loader picked the right
    /// parser.
    pub format: &'static str,
    /// Whether the source has a transform program (`jq` / `awk`).
    /// Rendered by the `status` API so the operator can verify
    /// the transform is wired.
    pub has_program: bool,
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
        let program = if self.has_program { "program=yes" } else { "" };
        format!(
            "roa-source: {} type={} format={} entries={} state={} last-load={}{}{}",
            self.source,
            if self.is_url { "url" } else { "file" },
            self.format,
            self.entries,
            state,
            age,
            if program.is_empty() {
                String::new()
            } else {
                format!(" {program}")
            },
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
    let has_program = spec.program.is_some() || spec.program_file.is_some();
    let status = Arc::new(Mutex::new(RoaLoaderStatus {
        source: source_str.clone(),
        is_url,
        entries: 0,
        healthy: false,
        last_load_age_s: None,
        last_error: None,
        format: format_str,
        has_program,
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
                    st.has_program =
                        self.spec.program.is_some() || self.spec.program_file.is_some();
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
    ///
    /// For the transform formats (`jq`, `awk`) the source bytes are
    /// first piped through the operator-supplied program (see
    /// [`run_jq`] / [`run_awk`]); the program's stdout is then
    /// parsed as BIRD-format lines by [`lr_bgp::parse_roa`].
    fn fetch_and_apply(&self) -> Result<usize, RoaLoaderError> {
        let format = self.spec.resolve_format()?;
        let text = if let Some(url) = self.spec.url.as_deref() {
            self.fetch_url(url)?
        } else if let Some(path) = self.spec.path.as_deref() {
            self.read_file(path)?
        } else {
            return Err(RoaLoaderError::Missing {
                line_no: 0,
                message: "roa_source without 'path' or 'url'".to_string(),
            });
        };
        // For transform formats, pipe the source bytes through the
        // operator's jq / awk program; the program's stdout is the
        // canonical BIRD-format text that `parse_roa` consumes.
        let (parse_text, parse_format) = if format.requires_program() {
            let program = self
                .spec
                .resolve_program()?
                .ok_or_else(|| RoaLoaderError::Missing {
                    line_no: 0,
                    message: format!(
                        "roa_source format '{}' requires 'program' or 'program_file'",
                        format.as_str()
                    ),
                })?;
            let transformed = match format {
                RoaFormat::Jq => run_jq(&program, &text)?,
                RoaFormat::Awk => run_awk(&program, &text)?,
                // Unreachable: `requires_program()` is false for
                // Native and Bird.
                _ => text,
            };
            // The transform program's output is BIRD-format text —
            // parse it with the BIRD parser, not the transform format
            // (which `parse_roa` rejects with `TransformFormatDirect`).
            (transformed, RoaFormat::Bird)
        } else {
            (text, format)
        };
        let entries = lr_bgp::parse_roa(&parse_text, parse_format)?;
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

/// Run a `jq` program against `input` and return its stdout.
///
/// The program is invoked as `jq -r -- PROGRAM`, reading `input`
/// on stdin and writing the transform's output on stdout. `-r`
/// (raw output) means string values are emitted without JSON
/// quoting — the canonical shape for BIRD-format lines (`roa
/// PREFIX max N as N;`). The `--` separator protects against a
/// program that starts with `-` being parsed as a jq flag.
///
/// `jq` is found on `PATH`. The daemon's Docker image ships jq;
/// on a bare-metal install the operator installs jq separately
/// (the loader's status line surfaces a clear error if the
/// binary is missing).
///
/// This is an internal daemon helper — it is not exposed through
/// the C ABI (issue #100 follow-up: the transform feature is a
/// daemon-internal concern, not a library API).
fn run_jq(program: &str, input: &str) -> Result<String, RoaLoaderError> {
    run_transform("jq", &["-r", "--", program], input)
}

/// Run an `awk` program against `input` and return its stdout.
///
/// The program is invoked as `awk -- PROGRAM`, reading `input`
/// on stdin. `awk` (whether gawk, mawk or onetrueawk — all ship
/// on every Unix) writes the transform's output on stdout. The
/// `--` separator protects against a program that starts with
/// `-` being parsed as an awk flag.
///
/// `awk` is found on `PATH`; every Unix system ships one. This
/// is an internal daemon helper — not exposed through the C ABI.
fn run_awk(program: &str, input: &str) -> Result<String, RoaLoaderError> {
    run_transform("awk", &["--", program], input)
}

/// Maximum wall-clock time a transform subprocess (`jq` / `awk`) may
/// run before the loader kills it. A program that hangs reading its
/// own state, that deadlocks on a malformed input, or that
/// accidentally infinite-loops would otherwise block the loader
/// thread indefinitely — which would also block the daemon's SIGHUP
/// reload path (a `Repoint` command waits for the loader thread to
/// drain). 60 s is far above the worst observed transform time on a
/// real-world 100 MB Routinator JSON dump (well under 10 s on
/// commodity hardware), short enough that a wedged program does not
/// stall ROA updates for an operator-noticeable interval. The
/// previous snapshot is preserved on timeout, the same contract a
/// fetch failure upholds.
const TRANSFORM_TIMEOUT: Duration = Duration::from_secs(60);

/// Polling interval for the transform-subprocess wait loop. A 50 ms
/// cadence keeps the loader thread responsive to a `Repoint` /
/// `Shutdown` command without burning CPU on an idle wait.
const TRANSFORM_POLL: Duration = Duration::from_millis(50);

/// Spawn a transform binary (`jq` / `awk`), feed `input` on its
/// stdin and capture its stdout. The binary is found on `PATH`;
/// a missing binary surfaces a clear `Io` error so the loader's
/// status line reports it and the previous ROA snapshot is
/// preserved.
///
/// Uses the default [`TRANSFORM_TIMEOUT`] deadline. The
/// `run_transform_with_timeout` helper takes a custom deadline for
/// tests; production code always goes through this entry point so
/// the 60 s contract is uniform.
fn run_transform(bin: &str, args: &[&str], input: &str) -> Result<String, RoaLoaderError> {
    run_transform_with_timeout(bin, args, input, TRANSFORM_TIMEOUT)
}

/// Spawn a transform binary with a custom timeout. Production code
/// uses [`run_transform`] (which passes [`TRANSFORM_TIMEOUT`]); tests
/// pass a shorter timeout to verify the kill path quickly.
///
/// The subprocess is killed if it runs longer than `timeout`; its
/// stdout and stderr are drained concurrently so a large transform
/// output cannot deadlock on a full pipe buffer (the prior
/// `wait_with_output` shape relied on the child finishing its stdout
/// write before the stdin pipe filled, which is fine for small inputs
/// but can deadlock on a real-world 100 MB Routinator JSON dump).
fn run_transform_with_timeout(
    bin: &str,
    args: &[&str],
    input: &str,
    timeout: Duration,
) -> Result<String, RoaLoaderError> {
    let mut cmd = Command::new(bin);
    cmd.args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    // Put the child in its own process group so a timeout can kill
    // the entire tree. A `jq` / `awk` program that spawns helper
    // processes (awk's `system()`, `getline "cmd"`) would otherwise
    // leave orphaned grandchildren holding the stdout pipe open,
    // blocking the reader thread past the kill.
    #[cfg(unix)]
    {
        cmd.process_group(0);
    }
    let mut child = cmd
        .spawn()
        .map_err(|e| RoaLoaderError::Io(format!("spawn {bin}: {e}")))?;

    // Windows equivalent of the Unix process-group kill: assign the
    // child to a kill-on-close Job Object. `Command::kill()` on
    // Windows calls `TerminateProcess`, which only kills the
    // immediate child — a `sh -c "sleep 120"` child spawns a `sleep`
    // grandchild that survives, holding the inherited stdout pipe
    // open and blocking the reader thread past the deadline. The
    // Job Object's kill-on-close semantics kill the entire tree when
    // we close the handle on the timeout path. Created before any
    // I/O starts so the assignment races no grandchildren.
    #[cfg(windows)]
    let mut job = KillOnCloseJob::new();
    #[cfg(windows)]
    if let Some(ref j) = job {
        let _ = j.assign(&child);
    }

    // Move the child's stdio handles into reader / writer threads so
    // the wait loop can poll `try_wait` without the child blocking
    // on a full pipe buffer. The writer thread closes stdin after
    // writing so the child sees EOF.
    let stdin_handle = child.stdin.take();
    let stdout_handle = child.stdout.take();
    let stderr_handle = child.stderr.take();
    let input_bytes = input.as_bytes().to_vec();
    let writer = thread::Builder::new()
        .name(format!("lr-roa-transform:{bin}:stdin"))
        .spawn(move || {
            if let Some(mut stdin) = stdin_handle {
                let _ = stdin.write_all(&input_bytes);
                // Drop stdin to signal EOF. Implicit on return, but
                // explicit so the intent is clear to the reader.
                drop(stdin);
            }
        })
        .map_err(|e| RoaLoaderError::Io(format!("spawn {bin} writer thread: {e}")))?;
    let reader = thread::Builder::new()
        .name(format!("lr-roa-transform:{bin}:stdout"))
        .spawn(move || {
            let mut stdout_buf = Vec::new();
            let mut stderr_buf = Vec::new();
            if let Some(mut s) = stdout_handle {
                let _ = s.read_to_end(&mut stdout_buf);
            }
            if let Some(mut s) = stderr_handle {
                let _ = s.read_to_end(&mut stderr_buf);
            }
            (stdout_buf, stderr_buf)
        })
        .map_err(|e| RoaLoaderError::Io(format!("spawn {bin} reader thread: {e}")))?;

    // Wait for the child to exit, polling so we can enforce the
    // timeout. On timeout we kill the entire process group so
    // grandchildren (which hold inherited pipe fds) die too —
    // otherwise the reader thread would block on `read_to_end`
    // until every grandchild exits.
    let deadline = Instant::now() + timeout;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) => {
                if Instant::now() >= deadline {
                    // Kill the entire process group so orphaned
                    // grandchildren die and release the stdout pipe.
                    #[cfg(unix)]
                    {
                        let _ = kill_process_group(&child);
                    }
                    #[cfg(not(unix))]
                    {
                        // Close the Job Object handle so the kernel
                        // kills the child and any grandchildren
                        // holding the stdout pipe. Falls back to
                        // `child.kill()` (the prior, single-process
                        // kill) if the Job Object APIs were
                        // unavailable at spawn time.
                        if let Some(ref mut j) = job {
                            j.kill_tree();
                        } else {
                            let _ = child.kill();
                        }
                    }
                    let _ = child.wait();
                    let _ = writer.join();
                    let _ = reader.join();
                    return Err(RoaLoaderError::Io(format!(
                        "{bin} did not finish within {} s (killed; previous ROA snapshot preserved)",
                        timeout.as_secs()
                    )));
                }
                thread::sleep(TRANSFORM_POLL);
            }
            Err(e) => {
                let _ = writer.join();
                let _ = reader.join();
                return Err(RoaLoaderError::Io(format!("wait {bin}: {e}")));
            }
        }
    };

    // Join the writer (always finishes quickly — it just writes the
    // input bytes and closes stdin) and the reader (finishes once the
    // child's stdout / stderr fds close on exit).
    let _ = writer.join();
    let (stdout_bytes, stderr_bytes) = reader.join().map_err(|_| {
        RoaLoaderError::Io(format!("{bin} reader thread panicked (no stdout captured)"))
    })?;

    if !status.success() {
        let stderr = String::from_utf8_lossy(&stderr_bytes);
        let code = status
            .code()
            .map(|c| c.to_string())
            .unwrap_or_else(|| "signal".to_string());
        return Err(RoaLoaderError::Io(format!(
            "{bin} exited {code}: {}",
            stderr.trim()
        )));
    }
    String::from_utf8(stdout_bytes)
        .map_err(|e| RoaLoaderError::Io(format!("{bin} stdout is not UTF-8: {e}")))
}

/// Send `SIGKILL` to the process group the child leads. The child
/// was spawned with `process_group(0)`, which makes the child the
/// leader of a new process group whose PGID equals the child's PID.
/// `kill(-PGID, SIGKILL)` (negative PGID) signals every process in
/// the group, including the leader and any helper processes the
/// `jq` / `awk` program spawned. Returns `Ok(())` if the signal was
/// sent (the actual reaping is done by `child.wait()` in the caller).
///
/// We use `extern "C"` declarations instead of pulling in the `libc`
/// crate — the same posture `crate::signal` already takes for its
/// SIGHUP handler. The two functions and one constant are the entire
/// libc surface this module needs.
#[cfg(unix)]
fn kill_process_group(child: &std::process::Child) -> std::io::Result<()> {
    let pid = child.id() as i32;
    // SIGKILL is 9 on every Unix (POSIX §3.3.1.1; signals.h `#define
    // SIGKILL 9`). The macro is stable across Linux, the BSDs and
    // Solaris-derived systems.
    const SIGKILL: i32 = 9;
    let rc = unsafe { kill_c(-pid, SIGKILL) };
    if rc < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}

// `extern "C"` shim around the libc `kill(2)` syscall. We declare
// it directly instead of pulling in the `libc` crate, mirroring
// `crate::signal`'s approach. `#[link_name]` maps our local
// identifier `kill_c` onto the libc symbol `kill` (the local name
// avoids shadowing Rust's `kill` method on `Child`).
#[cfg(unix)]
#[link(name = "c")]
extern "C" {
    // libc `kill(pid_t pid, int sig)` — send a signal to a process
    // or process group. A negative `pid` signals the process group
    // `|pid|`.
    #[link_name = "kill"]
    fn kill_c(pid: i32, sig: i32) -> i32;
}

/// A Windows Job Object created with
/// `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`. When the job handle is
/// closed — either through [`KillOnCloseJob::kill_tree`] or via
/// `Drop` — every process assigned to the job is killed by the
/// kernel. This is the Windows equivalent of Unix's
/// `kill(-PGID, SIGKILL)` for killing a process tree: a
/// `Command::kill()` on Windows calls `TerminateProcess`, which
/// only kills the immediate child and leaves any grandchildren
/// (a `sh -c "sleep 120"` child spawns a `sleep` grandchild)
/// holding inherited pipe handles open, blocking the reader
/// thread past the deadline.
///
/// The job is created right after the child is spawned and the
/// child is assigned to it before any I/O starts. On the timeout
/// path, `kill_tree` closes the handle; the kernel kills the
/// child and any processes it spawned, releasing the stdout
/// pipe the reader thread is blocked on so `reader.join()`
/// unblocks near the deadline instead of after the grandchild's
/// natural exit.
///
/// `new` returns `Option<Self>`: any modern Windows has the Job
/// Object APIs, but a defensive `None` lets the caller fall back
/// to `child.kill()` (the prior behaviour) if the APIs are
/// unavailable.
#[cfg(windows)]
struct KillOnCloseJob {
    handle: windows_sys::Win32::Foundation::HANDLE,
}

#[cfg(windows)]
impl KillOnCloseJob {
    fn new() -> Option<Self> {
        use windows_sys::Win32::Foundation::CloseHandle;
        use windows_sys::Win32::System::JobObjects::{
            CreateJobObjectW, JobObjectExtendedLimitInformation, SetInformationJobObject,
            JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
        };
        // SAFETY: `CreateJobObjectW` with null attributes and name
        // returns a fresh job handle (or NULL on failure, which we
        // check). `SetInformationJobObject` writes our
        // extended-limit struct into the job; the struct is
        // `Copy + Default` and we only set the limit-flags field.
        // The handle is closed on the error path and on `Drop`.
        unsafe {
            let handle = CreateJobObjectW(std::ptr::null(), std::ptr::null());
            if handle.is_null() {
                return None;
            }
            let mut info = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
            info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
            let rc = SetInformationJobObject(
                handle,
                JobObjectExtendedLimitInformation,
                &info as *const _ as *const core::ffi::c_void,
                std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
            );
            if rc == 0 {
                CloseHandle(handle);
                return None;
            }
            Some(Self { handle })
        }
    }

    /// Assign a child process to the job. The child and any
    /// processes it later spawns become members of the job; closing
    /// the job handle kills them all. Uses the child's raw handle
    /// (already held by `std::process::Child` on Windows) — no
    /// `OpenProcess` round-trip needed.
    fn assign(&self, child: &std::process::Child) -> std::io::Result<()> {
        use std::os::windows::io::AsRawHandle;
        use windows_sys::Win32::System::JobObjects::AssignProcessToJobObject;
        // SAFETY: `as_raw_handle` yields the child's process handle
        // (valid for the child's lifetime). `AssignProcessToJobObject`
        // takes the job handle (we hold it) and the process handle.
        // Modern Windows (Vista+) allows a process to be assigned to
        // a job after it has started running.
        let proc_handle = child.as_raw_handle() as windows_sys::Win32::Foundation::HANDLE;
        let rc = unsafe { AssignProcessToJobObject(self.handle, proc_handle) };
        if rc == 0 {
            Err(std::io::Error::last_os_error())
        } else {
            Ok(())
        }
    }

    /// Close the job handle. Every process in the job is killed
    /// immediately by the kernel's kill-on-job-close semantics.
    /// Idempotent — a second call is a no-op (the handle is already
    /// NULL).
    fn kill_tree(&mut self) {
        use windows_sys::Win32::Foundation::CloseHandle;
        if !self.handle.is_null() {
            // SAFETY: we own the handle (created in `new`, not
            // shared). After `CloseHandle` the handle is invalid;
            // we null it so a second call or `Drop` is a no-op.
            unsafe { CloseHandle(self.handle) };
            self.handle = std::ptr::null_mut();
        }
    }
}

#[cfg(windows)]
impl Drop for KillOnCloseJob {
    fn drop(&mut self) {
        // Defensive: if the caller did not explicitly call
        // `kill_tree`, close the handle on drop. If the child has
        // already exited normally, the job is empty and closing the
        // handle is a no-op; if the caller forgot to kill the tree,
        // the kernel reaps the orphans now instead of leaking them.
        self.kill_tree();
    }
}

#[cfg(test)]
#[path = "daemon_roa_loader_tests.rs"]
mod tests;
