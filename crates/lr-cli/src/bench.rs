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
//! - `lr bench fetch --to <dir>` — download a public RIB dump
//!   (RIPE RIS RRC26 `latest-bview.gz` by default) into `<dir>` for
//!   the harness to consume. The URL is overridable through
//!   `LR_BENCH_MRT_URL`.
//!
//! The bench measures:
//!
//! - **parse_ms** — wall time spent parsing the dump, building the
//!   candidate `Route`s, and ranking each prefix with the BGP decision
//!   process.
//! - **install_ms** — wall time spent installing every ranked set into
//!   the Loc-RIB through `LocRib::install_set`.
//! - **routes_in**, **routes_installed** — count of `(prefix, entry)`
//!   pairs read (the read stops at `--cap` prefixes) and count of
//!   ranked paths that landed in the Loc-RIB.
//! - **routes_per_sec** — `routes_installed / install_ms * 1000`.
//! - **loc_rib_prefixes**, **loc_rib_paths** — `LocRib::len` and
//!   `LocRib::paths_len` after install.
//! - **rss_peak_kb**, **rss_final_kb** — `/proc/self/status` VmHWM and
//!   VmRSS on Linux; `unsupported` on platforms without the file.
//! - **soft_reload_ms**, **soft_reload_peak_rss_kb** — re-run the
//!   decision process over every stored set and re-install the
//!   identical ranking, exercising the reselect/`install_set` no-op
//!   path. The peak RSS during this pass is the "peak resource usage
//!   during soft reload" metric.
//! - **steady_state_drift_kb** — difference between `rss_final_kb`
//!   and a second sample taken after a 100 ms hold. The
//!   "static resource occupation when routing is maintained" metric.
//! - **correctness** — every prefix's stored ranked set must equal the
//!   set the decision process produced from the dump. `matched` counts
//!   exact set matches, `mismatched` a stored set that differs,
//!   `missing` a prefix the Loc-RIB dropped, and `extra` a prefix the
//!   Loc-RIB holds that the feed does not. This is the storage-side
//!   path-selection check; the cross-implementation check is the
//!   prefix-by-prefix diff in `tests/bench/real_data.sh`.
//!
//! The bench is the storage benchmark the issue asks for: it exercises
//! `LocRib::install_set` (ranked best-first) and the best-path
//! snapshot path directly, with real-world attribute sets. The
//! full-pipeline variant — replay through a BGP session into a
//! `DefaultRouter` — is the existing `lr parity-replay` harness and
//! the harness script `tests/bench/real_data.sh`; this bench focuses
//! on the Loc-RIB the daemon itself fills from `--mrt-feed`.

use std::process::ExitCode;
use std::time::{Duration, Instant};

use lr_bgp::best_path::{BestPath, BestPathConfig};
use lr_core::rib::{Route, RouteKey};
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
    lr bench replay --mrt <file.mrt> [--cap N] [--json] [--no-soft-reload]
    lr bench diff   <lr-loc-rib.mrt> <reference.mrt>
    lr bench fetch  --to <dir>

replay:
    Parse the MRT dump, rank each prefix's candidate paths with the
    BGP decision process, install the ranked sets into a fresh
    Loc-RIB, and print the metrics. --json emits the same fields as
    one JSON object. --cap N keeps the first N prefixes (0 = all);
    a full public RIB is hundreds of MiB and millions of entries, so
    the harness caps it. --no-soft-reload skips the decision-process
    re-run pass.

diff:
    Content-level diff of two MRT RIB dumps (delegates to `lr mrt
    diff`). Used to compare lr's Loc-RIB dump against the reference
    implementation's dump after a parity-replay run.

fetch:
    Download a public RIB dump (RIPE RIS RRC26 latest-bview.gz by
    default) into <dir>. The URL is overridable through
    LR_BENCH_MRT_URL. Prints the local path on
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
    /// Cap on prefixes installed (`0` = no cap).
    cap: usize,
}

pub fn cmd_replay(args: &[String]) -> ExitCode {
    let mut cfg = ReplayConfig {
        mrt: String::new(),
        json: false,
        soft_reload: true,
        cap: 0,
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
            "--cap" => match val(&mut i, args) {
                Some(v) => match v.parse() {
                    Ok(n) => cfg.cap = n,
                    Err(_) => {
                        eprintln!("error: bad --cap '{v}'");
                        return ExitCode::from(2);
                    }
                },
                None => break,
            },
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
    // ---- parse + rank ----
    // `mrt_feed::load` owns the whole read side: parse the dump, build
    // one `Route` per entry, group by prefix, and run the BGP decision
    // process. That is the work a daemon does at startup when it seeds
    // its Loc-RIB from a dump.
    let parse_start = Instant::now();
    let feed = crate::mrt_feed::load(&cfg.mrt, cfg.cap, 0)?;
    let parse_ms = parse_start.elapsed().as_millis() as u64;

    // ---- install into a fresh Loc-RIB ----
    // `install_set` takes the ranked set, best first. Installing each
    // candidate through `LocRib::install` would replace the previous
    // one (all non-Add-Path entries share `path_id = 0`).
    let rib = LocRib::new();
    let rss_before = read_rss_kb();
    let install_start = Instant::now();
    let installed = crate::mrt_feed::install(&rib, &feed);
    let install_ms = install_start.elapsed().as_millis() as u64;
    let rss_after = read_rss_kb();
    let rss_peak_kb = match (rss_before, rss_after) {
        (Some(a), Some(b)) => Some(a.max(b)),
        (Some(a), None) => Some(a),
        (None, Some(b)) => Some(b),
        (None, None) => None,
    };

    let routes_in = feed.dump_paths;
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
    // The Loc-RIB must hold exactly the ranked set the decision
    // process produced for each prefix: same paths, same order (best
    // first). A dropped prefix is `missing`, a changed/collapsed set
    // is `mismatched`, and a prefix the feed never carried is `extra`.
    let correctness = correctness_vs_feed(&rib, &feed.sets);

    // ---- soft reload ----
    // A configuration reload re-runs the decision process over the
    // retained candidates. Re-rank each stored set and install the
    // result; the sets are identical, so this exercises the
    // reselect/`install_set` no-op path. Peak RSS during this pass is
    // the "peak resource usage during soft reload" metric.
    let mut soft_reload_ms = 0u64;
    let mut soft_reload_peak_rss_kb = None;
    if cfg.soft_reload {
        let sr_start = Instant::now();
        let sr_rss_before = read_rss_kb();
        let best_path_cfg = BestPathConfig::default();
        for (key, set) in &feed.sets {
            let ranked: Vec<Route> = BestPath::rank(set, &best_path_cfg)
                .into_iter()
                .cloned()
                .collect();
            rib.install_set(key, ranked);
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

/// Compare the Loc-RIB's stored sets against the ranked sets the
/// decision process produced from the dump. See [`CorrectnessReport`]
/// for the field meanings.
fn correctness_vs_feed(rib: &LocRib, sets: &[(RouteKey, Vec<Route>)]) -> CorrectnessReport {
    use std::collections::BTreeSet;
    let expected: BTreeSet<RouteKey> = sets.iter().map(|(key, _)| key.clone()).collect();
    let mut report = CorrectnessReport::default();
    for (key, ranked) in sets {
        match rib.paths(key) {
            stored if stored.is_empty() => report.missing += 1,
            stored if &stored == ranked => report.matched += 1,
            _ => report.mismatched += 1,
        }
    }
    report.extra = rib
        .iter_sets()
        .iter()
        .filter(|(key, _)| !expected.contains(key))
        .count();
    report
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

const DEFAULT_FETCH_URL: &str = "https://data.ris.ripe.net/rrc26/latest-bview.gz";

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
    use lr_core::addr::{Asn, IpAddr, Prefix};
    use lr_core::attr::Attributes;
    use lr_core::nlri::NlriFamily;
    use lr_core::rib::{Preference, Protocol, RouteOrigin};
    use lr_mrt::{decode_attributes, MrtRibDump, PeerEntry, RibEntry, RibTable};

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
            cap: 0,
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
            cap: 0,
        };
        let report = run_replay(&cfg).expect("replay must succeed");
        assert_eq!(report.routes_in, 2, "two RibEntries in the dump");
        assert_eq!(report.loc_rib_prefixes, 1, "one prefix");
        assert_eq!(report.loc_rib_paths, 2, "both paths under the prefix");
        // The ranked set for the prefix is stored as both paths, so
        // the storage invariant holds: matched=1, mismatched=0,
        // missing=0, extra=0.
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
            cap: 0,
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
    fn replay_cap_counts_prefixes_not_entries() {
        let dir = std::env::temp_dir().join("lr_bench_replay_cap");
        std::fs::create_dir_all(&dir).unwrap();
        let mrt = dir.join("small.mrt");
        write_small_dump(mrt.to_str().unwrap()).unwrap();
        let cfg = ReplayConfig {
            mrt: mrt.to_str().unwrap().to_string(),
            json: false,
            soft_reload: false,
            cap: 2,
        };
        let report = run_replay(&cfg).expect("replay must succeed");
        assert_eq!(report.routes_in, 2, "the read stops at two prefixes");
        assert_eq!(report.loc_rib_prefixes, 2, "the cap keeps two prefixes");
        assert_eq!(report.routes_installed, 2);
        assert_eq!(report.correctness.matched, 2);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn correctness_flags_a_loc_rib_that_lost_paths() {
        // `correctness_vs_feed` is a storage invariant, not a check
        // that any dump candidate happens to match: dropping the
        // ranked set must show up as `missing`.
        let key = RouteKey::new(Prefix::new_v4([203, 0, 113, 0], 24), NlriFamily::IPV4_UNICAST);
        let route = Route {
            key: key.clone(),
            origin: RouteOrigin { proto: 0, peer: 0 },
            protocol: Protocol::Bgp,
            preference: Preference::new(Protocol::Bgp.default_admin_distance(), 100),
            next_hop: Some(IpAddr::V4([192, 0, 2, 1])),
            attributes: Attributes::new(),
            age_ms: 0,
            path_id: 0,
            tag: None,
        };
        let feed = crate::mrt_feed::Feed {
            sets: vec![(key, vec![route])],
            dump_paths: 1,
        };
        let empty = LocRib::new();
        let report = correctness_vs_feed(&empty, &feed.sets);
        assert_eq!(report.missing, 1);
        assert_eq!(report.matched, 0);

        crate::mrt_feed::install(&empty, &feed);
        let report = correctness_vs_feed(&empty, &feed.sets);
        assert_eq!(report.matched, 1);
        assert_eq!(report.mismatched, 0);
    }
}
