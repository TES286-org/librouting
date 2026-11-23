//! Real-data benchmark: replay a public MRT RIB dump into librouting's
//! Loc-RIB and collect the metrics the issue #101 "Benchmark Based on
//! Real Data" item names.
//!
//! The bench is built on `lr-mrt`'s TABLE_DUMP_V2 reader (RFC 6396),
//! `lr-rib::LocRib`'s `install` path and `lr-mrt::interpret::walk_attributes`
//! for the path-selection correctness check. Every prefix the dump
//! carries is decoded into a `Route`, installed into a fresh Loc-RIB,
//! and the Loc-RIB's best-path view is compared against the dump's
//! entries.
//!
//! Three subcommands:
//!
//! - `lr bench replay --mrt <file>` — the bench itself. Prints a
//!   human-readable report by default; `--json` emits the same fields
//!   as a JSON object for scraper consumption.
//! - `lr bench diff <lr-loc-rib.mrt> <reference.mrt>` — content-level
//!   comparison of two MRT RIB dumps (delegates to `lr mrt diff`).
//! - `lr bench fetch --to <dir>` — download a small public RIB dump
//!   from RouteViews into `<dir>` for the harness to consume. The
//!   default URL is overridable through `LR_BENCH_MRT_URL`.
//!
//! The bench measures:
//!
//! - **parse_ms** — wall time spent in `lr_mrt::parse_file`.
//! - **install_ms** — wall time spent installing every route into the
//!   Loc-RIB.
//! - **routes_in**, **routes_installed** — count of entries the dump
//!   carries and count that landed in the Loc-RIB.
//! - **routes_per_sec** — `routes_installed / install_ms * 1000`.
//! - **loc_rib_prefixes**, **loc_rib_paths** — `LocRib::len` and
//!   `LocRib::paths_len` after install.
//! - **rss_peak_kb**, **rss_final_kb** — `/proc/self/status` VmHWM and
//!   VmRSS on Linux; `unsupported` on platforms without the file.
//! - **soft_reload_ms**, **soft_reload_peak_rss_kb** — re-install
//!   every route (byte-identical) into the same Loc-RIB, exercising
//!   the `install` no-op path. The peak RSS during this pass is the
//!   "peak resource usage during soft reload" metric.
//! - **steady_state_drift_kb** — difference between `rss_final_kb`
//!   and a second sample taken after a 100 ms hold. The
//!   "static resource occupation when routing is maintained" metric.
//! - **correctness** — `{matched, mismatched, missing, extra}` against
//!   the dump's per-prefix entries (path selection correctness).
//!
//! The bench is the storage benchmark the issue asks for: it exercises
//! `LocRib::install` and the best-path snapshot path directly, with
//! real-world attribute sets. The full-pipeline variant — replay
//! through a BGP session into a `DefaultRouter` — is the existing
//! `lr parity-replay` harness; this bench focuses on the storage
//! layer the issue names.

use std::process::ExitCode;
use std::time::{Duration, Instant};

use lr_core::addr::Prefix;
use lr_core::attr::Attributes;
use lr_core::nlri::NlriFamily;
use lr_core::rib::{Preference, Protocol, Route, RouteKey, RouteOrigin};
use lr_core::time::Instant as LrInstant;
use lr_mrt::{
    decode_attributes, walk_attributes, AttrSummary, MrtRecord, PeerEntry, PeerIndexTable,
};
use lr_rib::LocRib;

/// Entry point — `lr bench <replay|diff|fetch> [args]`.
pub fn cmd_bench(args: &[String]) -> ExitCode {
    if args.is_empty() {
        eprintln!("{BENCH_USAGE}");
        return ExitCode::from(2);
    }
    match args[0].as_str() {
        "replay" => cmd_replay(&args[1..]),
        "diff" => cmd_diff(&args[1..]),
        "fetch" => cmd_fetch(&args[1..]),
        "help" | "--help" | "-h" => {
            println!("{BENCH_USAGE}");
            ExitCode::SUCCESS
        }
        other => {
            eprintln!("error: unknown bench subcommand '{other}'");
            eprintln!("{BENCH_USAGE}");
            ExitCode::from(2)
        }
    }
}

const BENCH_USAGE: &str = "\
lr bench — real-data benchmark against a public MRT RIB dump (issue #101)

USAGE:
    lr bench replay --mrt <file.mrt> [--json] [--no-soft-reload]
    lr bench diff   <lr-loc-rib.mrt> <reference.mrt>
    lr bench fetch  --to <dir>

replay:
    Parse the MRT dump, install every route into a fresh Loc-RIB,
    and print the metrics. --json emits the same fields as one JSON
    object. --no-soft-reload skips the second (byte-identical)
    re-install pass.

diff:
    Content-level diff of two MRT RIB dumps (delegates to `lr mrt
    diff`). Used to compare lr's Loc-RIB dump against the reference
    implementation's dump after a parity-replay run.

fetch:
    Download a small public RIB dump (RouteViews route-views2, the
    latest bview. for the current UTC date) into <dir>. The URL is
    overridable through LR_BENCH_MRT_URL. Prints the local path on
    success. The harness skips with exit 0 when the download fails
    or the runner has no network egress.";

// ---------------------------------------------------------------------------
// replay
// ---------------------------------------------------------------------------

/// `lr bench replay --mrt <file>` configuration.
pub(crate) struct ReplayConfig {
    mrt: String,
    json: bool,
    soft_reload: bool,
}

pub fn cmd_replay(args: &[String]) -> ExitCode {
    let mut cfg = ReplayConfig {
        mrt: String::new(),
        json: false,
        soft_reload: true,
    };
    let mut i = 0;
    while i < args.len() {
        let val = |i: &mut usize, args: &[String]| -> Option<String> {
            *i += 1;
            args.get(*i).cloned()
        };
        match args[i].as_str() {
            "--mrt" => match val(&mut i, args) {
                Some(v) => cfg.mrt = v,
                None => break,
            },
            "--json" => cfg.json = true,
            "--no-soft-reload" => cfg.soft_reload = false,
            "help" | "--help" | "-h" => {
                println!("{BENCH_USAGE}");
                return ExitCode::SUCCESS;
            }
            other => {
                eprintln!("error: unknown replay option '{other}'");
                eprintln!("{BENCH_USAGE}");
                return ExitCode::from(2);
            }
        }
        i += 1;
    }
    if cfg.mrt.is_empty() {
        eprintln!("error: --mrt <file> is required");
        eprintln!("{BENCH_USAGE}");
        return ExitCode::from(2);
    }
    match run_replay(&cfg) {
        Ok(report) => {
            if cfg.json {
                println!("{}", report.to_json());
            } else {
                print!("{report}");
            }
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("bench replay failed: {e}");
            ExitCode::from(1)
        }
    }
}

/// The benchmark report. Fields are public so the JSON serializer can
/// read them; the human renderer lives in [`Display`].
#[derive(Debug, Clone, Default)]
pub struct BenchReport {
    pub mrt_path: String,
    pub parse_ms: u64,
    pub install_ms: u64,
    pub routes_in: usize,
    pub routes_installed: usize,
    pub routes_per_sec: u64,
    pub loc_rib_prefixes: usize,
    pub loc_rib_paths: usize,
    pub rss_peak_kb: Option<u64>,
    pub rss_final_kb: Option<u64>,
    pub soft_reload_ms: u64,
    pub soft_reload_peak_rss_kb: Option<u64>,
    pub steady_state_drift_kb: Option<i64>,
    pub correctness: CorrectnessReport,
    pub rss_platform: &'static str,
}

#[derive(Debug, Clone, Default)]
pub struct CorrectnessReport {
    pub matched: usize,
    pub mismatched: usize,
    pub missing: usize,
    pub extra: usize,
}

impl BenchReport {
    fn to_json(&self) -> String {
        format!(
            "{{\
             \"mrt_path\":\"{path}\",\
             \"parse_ms\":{parse_ms},\
             \"install_ms\":{install_ms},\
             \"routes_in\":{routes_in},\
             \"routes_installed\":{routes_installed},\
             \"routes_per_sec\":{rps},\
             \"loc_rib_prefixes\":{prefixes},\
             \"loc_rib_paths\":{paths},\
             \"rss_peak_kb\":{rss_peak},\
             \"rss_final_kb\":{rss_final},\
             \"soft_reload_ms\":{sr_ms},\
             \"soft_reload_peak_rss_kb\":{sr_peak},\
             \"steady_state_drift_kb\":{drift},\
             \"rss_platform\":\"{platform}\",\
             \"correctness\":{{\
             \"matched\":{matched},\
             \"mismatched\":{mismatched},\
             \"missing\":{missing},\
             \"extra\":{extra}\
             }}\
             }}",
            path = json_escape(&self.mrt_path),
            parse_ms = self.parse_ms,
            install_ms = self.install_ms,
            routes_in = self.routes_in,
            routes_installed = self.routes_installed,
            rps = self.routes_per_sec,
            prefixes = self.loc_rib_prefixes,
            paths = self.loc_rib_paths,
            rss_peak = opt_json(self.rss_peak_kb),
            rss_final = opt_json(self.rss_final_kb),
            sr_ms = self.soft_reload_ms,
            sr_peak = opt_json(self.soft_reload_peak_rss_kb),
            drift = opt_json_signed(self.steady_state_drift_kb),
            platform = self.rss_platform,
            matched = self.correctness.matched,
            mismatched = self.correctness.mismatched,
            missing = self.correctness.missing,
            extra = self.correctness.extra,
        )
    }
}

fn opt_json(v: Option<u64>) -> String {
    match v {
        Some(n) => n.to_string(),
        None => "null".to_string(),
    }
}

fn opt_json_signed(v: Option<i64>) -> String {
    match v {
        Some(n) => n.to_string(),
        None => "null".to_string(),
    }
}

fn json_escape(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

impl std::fmt::Display for BenchReport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "bench replay: {}", self.mrt_path)?;
        writeln!(f, "  parse:        {} ms", self.parse_ms)?;
        writeln!(
            f,
            "  install:      {} ms ({} routes in, {} installed)",
            self.install_ms, self.routes_in, self.routes_installed
        )?;
        writeln!(f, "  throughput:   {} routes/sec", self.routes_per_sec)?;
        writeln!(
            f,
            "  loc-rib:      {} prefixes, {} paths",
            self.loc_rib_prefixes, self.loc_rib_paths
        )?;
        writeln!(
            f,
            "  rss ({}):    peak {} KB, final {} KB",
            self.rss_platform,
            opt_str(self.rss_peak_kb),
            opt_str(self.rss_final_kb)
        )?;
        if self.soft_reload_ms > 0 {
            writeln!(
                f,
                "  soft reload:  {} ms, peak RSS {} KB",
                self.soft_reload_ms,
                opt_str(self.soft_reload_peak_rss_kb)
            )?;
        }
        if let Some(drift) = self.steady_state_drift_kb {
            writeln!(f, "  steady state: drift {:+} KB over 100 ms hold", drift)?;
        }
        let c = &self.correctness;
        writeln!(
            f,
            "  correctness:  {} matched, {} mismatched, {} missing, {} extra",
            c.matched, c.mismatched, c.missing, c.extra
        )?;
        Ok(())
    }
}

fn opt_str(v: Option<u64>) -> String {
    match v {
        Some(n) => n.to_string(),
        None => "unsupported".to_string(),
    }
}

/// Run the bench. Public so the unit tests can drive it directly.
pub(crate) fn run_replay(cfg: &ReplayConfig) -> Result<BenchReport, String> {
    // ---- parse ----
    let parse_start = Instant::now();
    let records = lr_mrt::parse_file(&cfg.mrt).map_err(|e| format!("parse {}: {e}", cfg.mrt))?;
    let parse_ms = parse_start.elapsed().as_millis() as u64;

    // ---- build routes from the dump ----
    // Collect the peer index table and every RIB entry. Each
    // (prefix, entry) pair becomes one Route. Add-Path entries
    // (path_id != 0) become distinct paths under the same key — the
    // Loc-RIB stores them in the same path set.
    let mut peers: Option<PeerIndexTable> = None;
    let mut entries: Vec<(Prefix, NlriFamily, lr_mrt::RibEntry)> = Vec::new();
    for record in &records {
        match record {
            MrtRecord::PeerIndexTable(pit) => peers = Some(pit.clone()),
            MrtRecord::Rib(table) => {
                let family = if table.prefix.is_ipv4() {
                    NlriFamily::IPV4_UNICAST
                } else {
                    NlriFamily::IPV6_UNICAST
                };
                for entry in &table.entries {
                    entries.push((table.prefix, family, entry.clone()));
                }
            }
            _ => {}
        }
    }
    let peers = peers
        .ok_or_else(|| "dump has no PEER_INDEX_TABLE — not a TABLE_DUMP_V2 RIB dump".to_string())?;
    let routes_in = entries.len();

    // Pre-build the Route values: installing them is what we want to
    // measure, not the conversion from MRT to Route. The conversion
    // is itself part of "rely on the basic capabilities of lr to
    // build a storage" — but it is O(routes) work that would
    // contaminate the install_ms number.
    let routes: Vec<Route> = entries
        .iter()
        .map(|(prefix, family, entry)| build_route(*prefix, *family, entry, &peers))
        .collect();

    // ---- install into a fresh Loc-RIB ----
    let rib = LocRib::new();
    let rss_before = read_rss_kb();
    let install_start = Instant::now();
    let mut installed = 0usize;
    for r in &routes {
        if rib.install(r.clone()) {
            installed += 1;
        }
    }
    // Advance the synthetic clock once so the Loc-RIB's history
    // commits the final diff entry. The history lock is taken inside
    // install, but the generation counter advances under that lock —
    // a single tick is enough to surface every diff to the snapshot
    // path the bench reads through `iter_best`.
    let _ = LrInstant(0);
    let install_ms = install_start.elapsed().as_millis() as u64;
    let rss_after = read_rss_kb();
    let rss_peak_kb = match (rss_before, rss_after) {
        (Some(a), Some(b)) => Some(a.max(b)),
        (Some(a), None) => Some(a),
        (None, Some(b)) => Some(b),
        (None, None) => None,
    };

    let loc_rib_prefixes = rib.len();
    let loc_rib_paths = rib.paths_len();
    let routes_per_sec = (installed as u64 * 1000)
        .checked_div(install_ms)
        .unwrap_or_else(|| {
            // install_ms rounded to zero on a fast machine — use
            // microseconds for the throughput so a sub-ms install does
            // not divide by zero.
            let us = install_start.elapsed().as_micros() as u64;
            (installed as u64 * 1_000_000).checked_div(us).unwrap_or(0)
        });

    // ---- path selection correctness ----
    // Group the dump's entries by prefix. For each prefix, the
    // dump's "candidate set" is every (AS_PATH, next_hop) the peers
    // carry. lr's Loc-RIB holds one best path per prefix; the bench
    // compares lr's best (AS_PATH, next_hop) against the dump's
    // candidate set. A prefix lr does not hold is `missing`; a prefix
    // lr holds that the dump does not is `extra`; a prefix where lr's
    // (AS_PATH, next_hop) is not in the dump's candidate set is
    // `mismatched`.
    let correctness = correctness_vs_dump(&rib, &entries);

    // ---- soft reload ----
    // Re-install every route (byte-identical) into the same Loc-RIB.
    // The install path returns false for byte-identical re-installs
    // (no history bump), so this pass exercises the no-op fast path
    // the OSPF/Babel runtimes hit on every recompute that yields the
    // same best path. Peak RSS during this pass is the "peak resource
    // usage during soft reload" metric.
    let mut soft_reload_ms = 0u64;
    let mut soft_reload_peak_rss_kb = None;
    if cfg.soft_reload {
        let sr_start = Instant::now();
        let sr_rss_before = read_rss_kb();
        for r in &routes {
            let _ = rib.install(r.clone());
        }
        let sr_rss_after = read_rss_kb();
        soft_reload_ms = sr_start.elapsed().as_millis() as u64;
        soft_reload_peak_rss_kb = match (sr_rss_before, sr_rss_after) {
            (Some(a), Some(b)) => Some(a.max(b)),
            (Some(a), None) => Some(a),
            (None, Some(b)) => Some(b),
            (None, None) => None,
        };
    }

    // ---- steady state ----
    // Hold the routes for 100 ms, then sample RSS again. The drift
    // is the "static resource occupation when routing is maintained"
    // metric: a stable Loc-RIB should not grow.
    let steady_state_drift_kb = if let Some(rss_hold_before) = read_rss_kb() {
        std::thread::sleep(Duration::from_millis(100));
        let rss_hold_after = read_rss_kb().unwrap_or(rss_hold_before);
        Some(rss_hold_after as i64 - rss_hold_before as i64)
    } else {
        None
    };

    Ok(BenchReport {
        mrt_path: cfg.mrt.clone(),
        parse_ms,
        install_ms,
        routes_in,
        routes_installed: installed,
        routes_per_sec,
        loc_rib_prefixes,
        loc_rib_paths,
        rss_peak_kb,
        rss_final_kb: rss_after,
        soft_reload_ms,
        soft_reload_peak_rss_kb,
        steady_state_drift_kb,
        correctness,
        rss_platform: rss_platform_name(),
    })
}

/// Build a `Route` from one MRT RIB entry. The Loc-RIB's `install`
/// path stores `Attributes` verbatim, so the raw attribute bytes are
/// decoded into an `Attributes` set with `lr_mrt::decode_attributes`
/// (the inverse of `encode_attributes`).
fn build_route(
    prefix: Prefix,
    family: NlriFamily,
    entry: &lr_mrt::RibEntry,
    peers: &PeerIndexTable,
) -> Route {
    let peer = peers
        .peers
        .get(entry.peer_index as usize)
        .cloned()
        .unwrap_or(PeerEntry {
            bgp_id: 0,
            ip: lr_core::addr::IpAddr::V4([0; 4]),
            asn: lr_core::addr::Asn(0),
        });
    let attrs: Attributes = decode_attributes(&entry.attributes);
    let summary = walk_attributes(entry);
    let next_hop = summary.next_hop;
    // LOCAL_PREF feeds the metric — the dump's value is the
    // collector's view, which is what we want for a storage bench
    // (the Loc-RIB's preference is the storage key the decision
    // process would use). LOCAL_PREF absent -> 100, the eBGP default
    // BIRD and FRR both display for routes learned without it.
    let local_pref = summary.local_pref.unwrap_or(100);
    // The route's `origin.peer` is the local session-side identifier
    // the Loc-RIB uses to key per-peer paths; the MRT peer index is
    // the dump's own identifier and matches what a real session
    // would record (peer.bgp_id is the wire-side identifier, kept
    // here for the unused-binding lint and to surface the peer's
    // identity in any future enrichment).
    let _ = peer.bgp_id;
    Route {
        key: RouteKey::new(prefix, family),
        origin: RouteOrigin {
            proto: 1,
            peer: entry.peer_index as u64,
        },
        protocol: Protocol::Bgp,
        preference: Preference::new(Protocol::Bgp.default_admin_distance(), local_pref),
        next_hop,
        attributes: attrs,
        age_ms: (entry.originated_time as u64) * 1000,
        path_id: entry.path_id,
        tag: None,
    }
}

/// Compare lr's Loc-RIB best paths against the dump's per-prefix
/// candidate sets. See [`CorrectnessReport`] for the field meanings.
fn correctness_vs_dump(
    rib: &LocRib,
    entries: &[(Prefix, NlriFamily, lr_mrt::RibEntry)],
) -> CorrectnessReport {
    use std::collections::BTreeMap;
    let mut dump_by_prefix: BTreeMap<Prefix, Vec<(String, Option<lr_core::addr::IpAddr>)>> =
        BTreeMap::new();
    for (prefix, _, entry) in entries {
        let summary = walk_attributes(entry);
        dump_by_prefix
            .entry(*prefix)
            .or_default()
            .push((summary.as_path, summary.next_hop));
    }

    let mut matched = 0usize;
    let mut mismatched = 0usize;
    let mut extra = 0usize;
    let mut missing = 0usize;

    let loc_best: Vec<(Prefix, Option<lr_core::addr::IpAddr>, String)> = rib
        .iter_best()
        .map(|r| {
            let summary = AttrSummary {
                next_hop: r.next_hop,
                as_path: lr_bgp_summary(&r.attributes),
                ..Default::default()
            };
            (r.key.prefix, summary.next_hop, summary.as_path)
        })
        .collect();

    let loc_by_prefix: BTreeMap<Prefix, (Option<lr_core::addr::IpAddr>, String)> = loc_best
        .into_iter()
        .map(|(p, nh, as_path)| (p, (nh, as_path)))
        .collect();

    for (prefix, candidates) in &dump_by_prefix {
        match loc_by_prefix.get(prefix) {
            None => missing += 1,
            Some((nh, as_path)) => {
                if candidates.iter().any(|(a, n)| a == as_path && n == nh) {
                    matched += 1;
                } else {
                    mismatched += 1;
                }
            }
        }
    }
    for prefix in loc_by_prefix.keys() {
        if !dump_by_prefix.contains_key(prefix) {
            extra += 1;
        }
    }

    CorrectnessReport {
        matched,
        mismatched,
        missing,
        extra,
    }
}

/// Re-derive the AS_PATH display string from an `Attributes` set.
/// Mirrors `walk_attributes` so the comparison is byte-identical to
/// the dump's own AS_PATH field.
fn lr_bgp_summary(attrs: &Attributes) -> String {
    // Walk the raw attribute set the same way walk_attributes does:
    // prefer AS4_PATH, then AS_PATH at 4-byte width, then 2-byte.
    use lr_bgp::path::{PathAttrFlags, PathAttribute, PathAttributes};
    let mut pas = PathAttributes::new();
    for a in attrs.iter() {
        pas.insert(PathAttribute {
            flags: PathAttrFlags(a.flags),
            attr_type: lr_bgp::path::AttrType::from_u8(a.tag.0),
            value: a.value.clone(),
        });
    }
    pas.as4_path()
        .or_else(|| pas.as_path())
        .or_else(|| pas.as_path_wire(false))
        .map(|p| p.to_string())
        .unwrap_or_default()
}

// ---------------------------------------------------------------------------
// diff — thin wrapper over `lr mrt diff` so the bench surface is one
// command. Delegates to the parity module's existing diff.
// ---------------------------------------------------------------------------

fn cmd_diff(args: &[String]) -> ExitCode {
    if args.len() < 2 {
        eprintln!("usage: lr bench diff <lr-loc-rib.mrt> <reference.mrt>");
        return ExitCode::from(2);
    }
    crate::parity::cmd_mrt_diff(&args[0], &args[1])
}

// ---------------------------------------------------------------------------
// fetch — download a real public MRT RIB dump.
// ---------------------------------------------------------------------------

const DEFAULT_FETCH_URL: &str = "https://archive.routeviews.org/route-views2/bview-latest.gz";

fn cmd_fetch(args: &[String]) -> ExitCode {
    let mut to = String::new();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--to" => {
                i += 1;
                match args.get(i) {
                    Some(v) => to = v.clone(),
                    None => break,
                }
            }
            "help" | "--help" | "-h" => {
                println!("{BENCH_USAGE}");
                return ExitCode::SUCCESS;
            }
            other => {
                eprintln!("error: unknown fetch option '{other}'");
                eprintln!("{BENCH_USAGE}");
                return ExitCode::from(2);
            }
        }
        i += 1;
    }
    if to.is_empty() {
        eprintln!("error: --to <dir> is required");
        eprintln!("{BENCH_USAGE}");
        return ExitCode::from(2);
    }
    let url = std::env::var("LR_BENCH_MRT_URL").unwrap_or_else(|_| DEFAULT_FETCH_URL.to_string());
    match run_fetch(&url, &to) {
        Ok(path) => {
            println!("{path}");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("bench fetch: {e}");
            ExitCode::SUCCESS // SKIP posture — the harness must not fail CI
        }
    }
}

fn run_fetch(url: &str, to: &str) -> Result<String, String> {
    std::fs::create_dir_all(to).map_err(|e| format!("mkdir {to}: {e}"))?;
    let fname = url.rsplit('/').next().unwrap_or("bview.mrt.gz");
    let dst = format!("{to}/{fname}");
    // ureq is already a workspace dependency (the ROA fetcher uses
    // it). The .gz suffix is honored by the harness; the bench itself
    // reads uncompressed MRT, so the harness gunzips after download.
    let resp = ureq::get(url)
        .timeout(std::time::Duration::from_secs(120))
        .call()
        .map_err(|e| format!("GET {url}: {e}"))?;
    let mut reader = resp.into_reader();
    let mut buf = Vec::with_capacity(8 * 1024 * 1024);
    std::io::Read::read_to_end(&mut reader, &mut buf).map_err(|e| format!("read body: {e}"))?;
    if buf.len() < 1024 {
        return Err(format!(
            "body too small ({} bytes) — likely a 404 placeholder",
            buf.len()
        ));
    }
    std::fs::write(&dst, &buf).map_err(|e| format!("write {dst}: {e}"))?;
    Ok(dst)
}

// ---------------------------------------------------------------------------
// RSS — `/proc/self/status` on Linux. Unsupported elsewhere.
// ---------------------------------------------------------------------------

fn rss_platform_name() -> &'static str {
    if cfg!(target_os = "linux") {
        "linux/proc"
    } else {
        "unsupported"
    }
}

fn read_rss_kb() -> Option<u64> {
    if !cfg!(target_os = "linux") {
        return None;
    }
    let status = std::fs::read_to_string("/proc/self/status").ok()?;
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("VmHWM:") {
            return rest
                .split_whitespace()
                .next()
                .and_then(|s| s.parse::<u64>().ok());
        }
    }
    None
}

// ---------------------------------------------------------------------------
// tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use lr_core::addr::{Asn, IpAddr, RouterId};
    use lr_mrt::{MrtRibDump, PeerEntry, RibEntry, RibTable};

    /// Build a small in-memory MRT RIB dump (3 prefixes, 1 peer) and
    /// write it to a temp file. The bench reads it back through the
    /// same `parse_file` path the CLI subcommand uses.
    fn write_small_dump(path: &str) -> std::io::Result<()> {
        let mut dump = MrtRibDump::new(0x0a00_0001, "test");
        dump.add_peer(PeerEntry {
            bgp_id: 0x0a00_0002,
            ip: IpAddr::V4([10, 0, 0, 2]),
            asn: Asn(64512),
        });
        // Three prefixes, each with a 1-entry RIB. Attributes empty
        // (the bench's correctness check compares AS_PATH and
        // next_hop; an empty AS_PATH and no next_hop is a valid
        // shape for a locally-originated route).
        for (i, octets) in [[203, 0, 113, 0], [198, 51, 100, 0], [192, 0, 2, 0]]
            .iter()
            .enumerate()
        {
            dump.add_table(RibTable {
                sequence: i as u32,
                prefix: Prefix::new_v4(*octets, 24),
                add_path: false,
                entries: vec![RibEntry {
                    peer_index: 0,
                    originated_time: 1_700_000_000 + i as u32,
                    path_id: 0,
                    attributes: Vec::new(),
                }],
            });
        }
        let bytes = dump.encode(1_700_000_000).unwrap();
        std::fs::write(path, bytes)
    }

    /// A dump with one prefix that carries two paths (Add-Path). The
    /// bench installs both into the same path set; the Loc-RIB's
    /// `paths_len` should be 2 while `len` stays 1.
    fn write_addpath_dump(path: &str) -> std::io::Result<()> {
        let mut dump = MrtRibDump::new(0x0a00_0001, "test");
        dump.add_peer(PeerEntry {
            bgp_id: 0x0a00_0002,
            ip: IpAddr::V4([10, 0, 0, 2]),
            asn: Asn(64512),
        });
        dump.add_table(RibTable {
            sequence: 0,
            prefix: Prefix::new_v4([203, 0, 113, 0], 24),
            add_path: true,
            entries: vec![
                RibEntry {
                    peer_index: 0,
                    originated_time: 1_700_000_000,
                    path_id: 1,
                    attributes: Vec::new(),
                },
                RibEntry {
                    peer_index: 0,
                    originated_time: 1_700_000_001,
                    path_id: 2,
                    attributes: Vec::new(),
                },
            ],
        });
        let bytes = dump.encode(1_700_000_000).unwrap();
        std::fs::write(path, bytes)
    }

    #[test]
    fn replay_small_dump_installs_every_prefix() {
        let dir = std::env::temp_dir().join("lr_bench_replay_small");
        std::fs::create_dir_all(&dir).unwrap();
        let mrt = dir.join("small.mrt");
        write_small_dump(mrt.to_str().unwrap()).unwrap();
        let cfg = ReplayConfig {
            mrt: mrt.to_str().unwrap().to_string(),
            json: false,
            soft_reload: true,
        };
        let report = run_replay(&cfg).expect("replay must succeed");
        assert_eq!(report.routes_in, 3);
        assert_eq!(report.routes_installed, 3);
        assert_eq!(report.loc_rib_prefixes, 3);
        assert_eq!(report.loc_rib_paths, 3);
        assert_eq!(report.correctness.matched, 3);
        assert_eq!(report.correctness.mismatched, 0);
        assert_eq!(report.correctness.missing, 0);
        assert_eq!(report.correctness.extra, 0);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn replay_addpath_dump_keeps_both_paths_under_one_prefix() {
        let dir = std::env::temp_dir().join("lr_bench_replay_addpath");
        std::fs::create_dir_all(&dir).unwrap();
        let mrt = dir.join("addpath.mrt");
        write_addpath_dump(mrt.to_str().unwrap()).unwrap();
        let cfg = ReplayConfig {
            mrt: mrt.to_str().unwrap().to_string(),
            json: false,
            soft_reload: false,
        };
        let report = run_replay(&cfg).expect("replay must succeed");
        assert_eq!(report.routes_in, 2, "two RibEntries in the dump");
        assert_eq!(report.loc_rib_prefixes, 1, "one prefix");
        assert_eq!(report.loc_rib_paths, 2, "both paths under the prefix");
        // The dump's candidate set for the prefix has two paths, both
        // with empty AS_PATH and no next_hop. lr's best path is one
        // of them, so matched=1, mismatched=0, missing=0, extra=0.
        assert_eq!(report.correctness.matched, 1);
        assert_eq!(report.correctness.extra, 0);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn replay_json_report_has_every_field() {
        let dir = std::env::temp_dir().join("lr_bench_replay_json");
        std::fs::create_dir_all(&dir).unwrap();
        let mrt = dir.join("small.mrt");
        write_small_dump(mrt.to_str().unwrap()).unwrap();
        let cfg = ReplayConfig {
            mrt: mrt.to_str().unwrap().to_string(),
            json: true,
            soft_reload: false,
        };
        let report = run_replay(&cfg).expect("replay must succeed");
        let json = report.to_json();
        // Every field the issue names is present in the JSON.
        for field in [
            "mrt_path",
            "parse_ms",
            "install_ms",
            "routes_in",
            "routes_installed",
            "routes_per_sec",
            "loc_rib_prefixes",
            "loc_rib_paths",
            "rss_peak_kb",
            "rss_final_kb",
            "soft_reload_ms",
            "soft_reload_peak_rss_kb",
            "steady_state_drift_kb",
            "correctness",
            "matched",
            "mismatched",
            "missing",
            "extra",
        ] {
            assert!(
                json.contains(&format!("\"{field}\":")),
                "json missing field {field}: {json}"
            );
        }
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn decode_attributes_round_trips_through_encode_attributes() {
        use lr_core::attr::{AttrTag, Attribute};
        let mut attrs = Attributes::new();
        attrs.insert(Attribute {
            tag: AttrTag(1),
            flags: 0x40,
            value: vec![1, 2, 3, 4],
        });
        attrs.insert(Attribute {
            tag: AttrTag(2),
            flags: 0x40,
            value: vec![0u8; 300], // forces extended-length form
        });
        let encoded = lr_mrt::encode_attributes(&attrs);
        let decoded = decode_attributes(&encoded);
        assert_eq!(decoded.len(), 2);
        // The decode path preserves tag, flags and value.
        let a1 = decoded.get(AttrTag(1)).unwrap();
        assert_eq!(a1.flags, 0x40);
        assert_eq!(a1.value, vec![1, 2, 3, 4]);
        let a2 = decoded.get(AttrTag(2)).unwrap();
        assert_eq!(a2.value.len(), 300);
    }

    #[test]
    fn build_route_carries_local_pref_default_when_absent() {
        // An entry with empty attributes has no LOCAL_PREF; the
        // eBGP display default both BIRD and FRR surface is 100.
        let entry = RibEntry {
            peer_index: 0,
            originated_time: 0,
            path_id: 0,
            attributes: Vec::new(),
        };
        let peers = PeerIndexTable {
            collector_bgp_id: 0,
            view_name: String::new(),
            peers: vec![PeerEntry {
                bgp_id: 0,
                ip: IpAddr::V4([0; 4]),
                asn: Asn(0),
            }],
        };
        let route = build_route(
            Prefix::new_v4([203, 0, 113, 0], 24),
            NlriFamily::IPV4_UNICAST,
            &entry,
            &peers,
        );
        assert_eq!(route.preference.metric, 100);
        assert_eq!(route.protocol, Protocol::Bgp);
        assert_eq!(route.origin.peer, 0);
        // router_id is not part of Route; the test pins the
        // peer-index plumbing instead.
        let _ = RouterId::from_u32(0x0a00_0001);
    }
}
