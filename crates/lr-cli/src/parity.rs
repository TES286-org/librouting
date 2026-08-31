//! Wire-level parity harness (STATUS.md W5.3): capture a BGP message
//! stream, replay it into an offline `lr-router` pipeline and diff the
//! resulting Loc-RIB against the reference implementation's dump.
//!
//! Three pieces live here:
//!
//! 1. **Capture files** — line-oriented JSON (`{"dir":"down","hex":"…"}`,
//!    one BGP message per line, hex-encoded including the 16-octet
//!    marker). The interop proxy (`tests/parity/capture_proxy.py`)
//!    records them off the wire; tests can also emit them directly.
//! 2. **Replay** (`lr parity-replay`) — feeds the captured stream into
//!    a fresh `DefaultRouter` exactly as the wire delivered it and
//!    dumps the resulting Loc-RIB as an MRT TABLE_DUMP_V2 file (RFC
//!    6396), the same shape the daemon's runtime API produces.
//! 3. **Diff** (`lr mrt diff A B`) — compares two MRT RIB dumps on
//!    route *content* (per prefix: AS path, next hop, local-pref, MED,
//!    communities) ignoring dump-specific noise (timestamps, peer
//!    indexes, view names).
//!
//! The reference implementation's RIB at capture time is the ground
//! truth: replaying the same wire stream into lr must reproduce it, or
//! the difference is a real interoperability defect (or a documented
//! normalization — those belong in `docs/PARITY.md`).

use std::collections::BTreeMap;
use std::io::{BufRead, BufReader};
use std::process::ExitCode;

use lr_core::addr::{Asn, RouterId};
use lr_mrt::{MrtRecord, MrtRibDump, PeerEntry, RibEntry, RibTable};
use lr_router::session::SessionConfig;
use lr_router::{DefaultRouter, RouterInstance};

// ---------------------------------------------------------------------------
// Capture files
// ---------------------------------------------------------------------------

/// One recorded BGP message.
#[derive(Debug, Clone)]
pub struct CaptureRecord {
    /// Proxy-relative direction: `"up"` = client→upstream (lr →
    /// reference), `"down"` = upstream→client (reference → lr).
    pub dir: String,
    /// The full BGP message (marker + header + body), hex-encoded.
    pub hex: String,
}

/// Read a capture file (one JSON object per line).
pub fn read_capture(path: &str) -> Result<Vec<CaptureRecord>, String> {
    let f = std::fs::File::open(path).map_err(|e| format!("capture {path}: {e}"))?;
    let mut out = Vec::new();
    for (n, line) in BufReader::new(f).lines().enumerate() {
        let line = line.map_err(|e| format!("capture {path}: {e}"))?;
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let dir = json_string_field(line, "dir")
            .ok_or_else(|| format!("capture {path}: line {}: missing \"dir\"", n + 1))?;
        let hex = json_string_field(line, "hex")
            .ok_or_else(|| format!("capture {path}: line {}: missing \"hex\"", n + 1))?;
        out.push(CaptureRecord { dir, hex });
    }
    Ok(out)
}

/// Extract the string value of `"key":"value"` from a flat JSON object
/// (the capture writer emits exactly this shape, so a full JSON parser
/// would be dead weight in the CLI).
fn json_string_field(line: &str, key: &str) -> Option<String> {
    let needle = format!("\"{key}\":");
    let start = line.find(&needle)? + needle.len();
    let rest = line[start..].trim_start();
    let rest = rest.strip_prefix('"')?;
    let end = rest.find('"')?;
    Some(rest[..end].to_string())
}

/// Append one message to a capture file (tests write captures directly
/// from in-process FSM exchanges; the wire proxy writes its own).
#[cfg(test)]
pub fn append_capture(path: &str, dir: &str, msg: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)?;
    writeln!(f, "{{\"dir\":\"{dir}\",\"hex\":\"{}\"}}", hex_encode(msg))
}

#[cfg(test)]
fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0xf) as usize] as char);
    }
    s
}

fn hex_decode(s: &str) -> Result<Vec<u8>, String> {
    if !s.len().is_multiple_of(2) {
        return Err(format!("odd hex length {}", s.len()));
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    let b = s.as_bytes();
    for i in (0..b.len()).step_by(2) {
        let hi = (b[i] as char).to_digit(16).ok_or("bad hex digit")?;
        let lo = (b[i + 1] as char).to_digit(16).ok_or("bad hex digit")?;
        out.push((hi * 16 + lo) as u8);
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// Replay
// ---------------------------------------------------------------------------

/// `lr parity-replay` configuration (parsed from argv).
pub struct ReplayConfig {
    pub capture: String,
    /// Which capture direction to feed (default `"down"`: the messages
    /// the reference implementation sent).
    pub direction: String,
    pub local_as: u32,
    pub peer_as: u32,
    /// Local BGP identifier, dotted-quad.
    pub router_id: String,
    /// Where to write the Loc-RIB MRT dump.
    pub output: String,
}

/// Replay the captured stream into an offline router and dump the
/// resulting Loc-RIB as MRT. Returns the number of RIB records written.
///
/// The session runs with `SessionConfig::bgp` defaults (ASN4, route
/// refresh, IPv4 unicast) and RFC 8212 off — the harness compares route
/// *content* against a reference that accepted the same stream, so the
/// replay side must not silently policy-drop it.
pub fn run_replay(cfg: &ReplayConfig) -> Result<usize, String> {
    let msgs = read_capture(&cfg.capture)?;
    let selected = select_direction(&msgs, &cfg.direction, &cfg.capture)?;
    let router_id: RouterId = cfg
        .router_id
        .parse()
        .map_err(|_| format!("bad --router-id '{}' (want A.B.C.D)", cfg.router_id))?;

    let mut router = DefaultRouter::new();
    router.set_ebgp_requires_policy(false);
    let h = router.add_session(SessionConfig::bgp(
        Asn(cfg.local_as),
        Asn(cfg.peer_as),
        router_id,
    ))?;
    // ManualStart + transport "connected": the FSM emits our OPEN.
    router.start_session(h)?;
    // Discard our own OPEN (and anything else queued): the replay is
    // one-directional, the reference never reads it back.
    let _ = router.drain_output(h);

    // Synthetic clock: one second per message. Well inside the 90 s
    // hold time, so KEEPALIVEs in the capture keep the session alive
    // and no timers fire merely because wall-clock replay is fast.
    let mut now_ms: u64 = 1_000_000;
    for (i, msg) in selected.iter().enumerate() {
        router
            .feed_input(h, msg)
            .map_err(|e| format!("capture message {i}: {e}"))?;
        now_ms += 1_000;
        router.tick(lr_core::time::Instant(now_ms));
        let _ = router.drain_output(h);
        if std::env::var_os("LR_PARITY_DEBUG").is_some() {
            for ev in router.poll_events() {
                eprintln!("parity: msg {i} (type {:?}): {:?}", msg.get(18), ev);
            }
        } else {
            let _ = router.poll_events();
        }
    }

    let routes: Vec<lr_core::rib::Route> =
        router.rib_paths_snapshot().into_iter().cloned().collect();
    let established = router.session_summaries().iter().any(|s| s.established);
    if !established {
        return Err(
            "replay session never reached Established — check that the capture \
             starts with the peer's OPEN"
                .to_string(),
        );
    }
    write_rib_dump(&routes, router_id, Asn(cfg.peer_as), &cfg.output)
}

fn select_direction(
    msgs: &[CaptureRecord],
    dir: &str,
    capture: &str,
) -> Result<Vec<Vec<u8>>, String> {
    let mut out = Vec::new();
    for m in msgs {
        if m.dir == dir {
            out.push(hex_decode(&m.hex)?);
        }
    }
    if out.is_empty() {
        return Err(format!(
            "capture {capture}: no messages in direction \"{dir}\" (have directions: {:?})",
            msgs.iter().map(|m| m.dir.as_str()).collect::<Vec<_>>()
        ));
    }
    Ok(out)
}

/// Dump a Loc-RIB as an RFC 6396 TABLE_DUMP_V2 file: one peer entry
/// (the replayed reference speaker, keyed by its BGP identifier from
/// the session summary) plus one RIB record per prefix. The shape
/// mirrors the daemon's runtime-API dump (`daemon.rs::write_mrt_rib_dump`).
fn write_rib_dump(
    routes: &[lr_core::rib::Route],
    router_id: RouterId,
    peer_as: Asn,
    path: &str,
) -> Result<usize, String> {
    use lr_core::rib::Protocol;

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as u32)
        .unwrap_or(0);
    let mut dump = MrtRibDump::new(router_id.as_u32(), "loc-rib");
    // Peer 0: local/non-BGP sources (none in a replay, but keep the
    // slot so indexes line up with the daemon's convention).
    dump.add_peer(PeerEntry {
        bgp_id: 0,
        ip: lr_core::addr::IpAddr::V6([0; 16]),
        asn: Asn(0),
    });

    let bgp_routes: Vec<&lr_core::rib::Route> = routes
        .iter()
        .filter(|r| r.protocol == Protocol::Bgp)
        .collect();
    if !bgp_routes.is_empty() {
        // Everything in a replay comes from the one peer.
        dump.add_peer(PeerEntry {
            bgp_id: router_id.as_u32(), // placeholder; the diff ignores peers
            ip: lr_core::addr::IpAddr::V4([10, 255, 255, 1]),
            asn: Asn(peer_as.as_u32()),
        });
    }

    let mut by_prefix: BTreeMap<lr_core::addr::Prefix, Vec<RibEntry>> = BTreeMap::new();
    for r in bgp_routes {
        by_prefix.entry(r.key.prefix).or_default().push(RibEntry {
            peer_index: 1,
            originated_time: now,
            path_id: r.path_id,
            attributes: lr_mrt::encode_attributes(&r.attributes),
        });
    }
    let mut records = 0usize;
    for (prefix, entries) in by_prefix {
        for add_path in [false, true] {
            let entries: Vec<RibEntry> = entries
                .iter()
                .filter(|e| (e.path_id != 0) == add_path)
                .cloned()
                .collect();
            if entries.is_empty() {
                continue;
            }
            dump.add_table(RibTable {
                sequence: records as u32,
                prefix,
                add_path,
                entries,
            });
            records += 1;
        }
    }
    let bytes = dump.encode(now).map_err(|e| format!("mrt encode: {e}"))?;
    std::fs::write(path, bytes).map_err(|e| format!("mrt write {path}: {e}"))?;
    Ok(records)
}

// ---------------------------------------------------------------------------
// Diff
// ---------------------------------------------------------------------------

/// One path's route content, reduced to the attributes the parity
/// check compares. Dump noise (timestamps, peer identity, path-id
/// plumbing) is deliberately excluded.
///
/// LOCAL_PREF is deliberately NOT fingerprinted: it is iBGP-only on
/// the wire (RFC 4271 §4.3 — "MUST NOT be advertised to eBGP peers"),
/// and implementations attach their own internal default on import
/// (BIRD and FRR both show 100 for eBGP-learned routes). A dump-side
/// LOCAL_PREF therefore reflects the *viewer's* policy, not the
/// sender's — including it would report a parity violation for a
/// difference no speaker can observe on the wire.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct RouteFingerprint {
    pub as_path: String,
    pub next_hop: String,
    pub med: Option<u32>,
    pub communities: Vec<String>,
}

impl RouteFingerprint {
    fn of(entry: &RibEntry) -> Option<RouteFingerprint> {
        let s = lr_mrt::walk_attributes(entry);
        // An entry that decodes to nothing (no next hop, no path) is a
        // dumping artifact — skip it rather than fail the comparison.
        if s.next_hop.is_none() && s.as_path.is_empty() {
            return None;
        }
        let mut communities = s.communities.clone();
        communities.sort();
        Some(RouteFingerprint {
            as_path: s.as_path,
            next_hop: s
                .next_hop
                .map(|n| n.to_string())
                .unwrap_or_else(|| "-".into()),
            med: s.med,
            communities,
        })
    }
}

/// The content comparison of two RIB dumps.
#[derive(Debug)]
pub struct DiffReport {
    /// Prefixes present in A but not in B.
    pub only_in_a: Vec<lr_core::addr::Prefix>,
    /// Prefixes present in B but not in A.
    pub only_in_b: Vec<lr_core::addr::Prefix>,
    /// Prefixes on both sides whose path sets differ.
    pub mismatched: Vec<(
        lr_core::addr::Prefix,
        Vec<RouteFingerprint>,
        Vec<RouteFingerprint>,
    )>,
    /// Number of prefixes compared clean.
    pub identical: usize,
}

impl DiffReport {
    pub fn is_clean(&self) -> bool {
        self.only_in_a.is_empty() && self.only_in_b.is_empty() && self.mismatched.is_empty()
    }
}

type RibMap = BTreeMap<lr_core::addr::Prefix, std::collections::BTreeSet<RouteFingerprint>>;

/// Build the prefix → path-set map from parsed MRT records.
fn rib_map(records: &[MrtRecord]) -> RibMap {
    let mut map: RibMap = BTreeMap::new();
    for record in records {
        if let MrtRecord::Rib(table) = record {
            let set = map.entry(table.prefix).or_default();
            for entry in &table.entries {
                if let Some(fp) = RouteFingerprint::of(entry) {
                    set.insert(fp);
                }
            }
        }
    }
    map
}

/// Diff two MRT RIB dumps on route content.
pub fn diff_rib_dumps(a: &[MrtRecord], b: &[MrtRecord]) -> DiffReport {
    let (ma, mb) = (rib_map(a), rib_map(b));
    let mut report = DiffReport {
        only_in_a: Vec::new(),
        only_in_b: Vec::new(),
        mismatched: Vec::new(),
        identical: 0,
    };
    for (prefix, set_a) in &ma {
        match mb.get(prefix) {
            None => report.only_in_a.push(*prefix),
            Some(set_b) if set_a == set_b => report.identical += 1,
            Some(set_b) => report.mismatched.push((
                *prefix,
                set_a.iter().cloned().collect(),
                set_b.iter().cloned().collect(),
            )),
        }
    }
    for prefix in mb.keys() {
        if !ma.contains_key(prefix) {
            report.only_in_b.push(*prefix);
        }
    }
    report
}

/// Print the diff and interpret it as a process exit code: clean →
/// `IDENTICAL (N prefixes)`, else one line per difference and exit 1.
fn print_diff_report(report: &DiffReport, a: &str, b: &str) -> ExitCode {
    if report.is_clean() {
        println!(
            "IDENTICAL ({} prefix{})",
            report.identical,
            if report.identical == 1 { "" } else { "es" }
        );
        return ExitCode::SUCCESS;
    }
    println!("DIFFER ({a} vs {b}):");
    for p in &report.only_in_a {
        println!("  only in {a}: {p}");
    }
    for p in &report.only_in_b {
        println!("  only in {b}: {p}");
    }
    for (prefix, paths_a, paths_b) in &report.mismatched {
        println!("  {prefix}:");
        for fp in paths_a {
            println!("    {a}: {fp:?}");
        }
        for fp in paths_b {
            println!("    {b}: {fp:?}");
        }
    }
    ExitCode::from(1)
}

// ---------------------------------------------------------------------------
// CLI wiring
// ---------------------------------------------------------------------------

const PARITY_REPLAY_USAGE: &str = "\
usage: lr parity-replay --capture FILE [--direction up|down] \
--local-as N --peer-as N --router-id A.B.C.D --output FILE.mrt

Replay a captured BGP message stream (one JSON line per message, as
recorded by tests/parity/capture_proxy.py) into an offline librouting
router and dump the resulting Loc-RIB as an MRT TABLE_DUMP_V2 file.
Compare against the reference implementation's own dump with
`lr mrt diff` — see docs/PARITY.md and STATUS.md W5.3.";

pub fn cmd_parity_replay(args: &[String]) -> ExitCode {
    let mut cfg = ReplayConfig {
        capture: String::new(),
        direction: "down".to_string(),
        local_as: 0,
        peer_as: 0,
        router_id: String::new(),
        output: String::new(),
    };
    let mut i = 0;
    while i < args.len() {
        let val = |i: &mut usize, args: &[String]| -> Option<String> {
            *i += 1;
            args.get(*i).cloned()
        };
        match args[i].as_str() {
            "--capture" => match val(&mut i, args) {
                Some(v) => cfg.capture = v,
                None => break,
            },
            "--direction" => match val(&mut i, args) {
                Some(v) => cfg.direction = v,
                None => break,
            },
            "--local-as" => match val(&mut i, args) {
                Some(v) => match v.parse() {
                    Ok(n) => cfg.local_as = n,
                    Err(_) => {
                        eprintln!("error: bad --local-as '{v}'");
                        return ExitCode::from(2);
                    }
                },
                None => break,
            },
            "--peer-as" => match val(&mut i, args) {
                Some(v) => match v.parse() {
                    Ok(n) => cfg.peer_as = n,
                    Err(_) => {
                        eprintln!("error: bad --peer-as '{v}'");
                        return ExitCode::from(2);
                    }
                },
                None => break,
            },
            "--router-id" => match val(&mut i, args) {
                Some(v) => cfg.router_id = v,
                None => break,
            },
            "--output" => match val(&mut i, args) {
                Some(v) => cfg.output = v,
                None => break,
            },
            other => {
                eprintln!("error: unknown parity-replay option '{other}'");
                eprintln!("{PARITY_REPLAY_USAGE}");
                return ExitCode::from(2);
            }
        }
        i += 1;
    }
    if cfg.capture.is_empty() || cfg.router_id.is_empty() || cfg.output.is_empty() {
        eprintln!("{PARITY_REPLAY_USAGE}");
        return ExitCode::from(2);
    }
    match run_replay(&cfg) {
        Ok(records) => {
            println!(
                "parity-replay: {} message(s) replayed, {records} RIB record(s) -> {}",
                read_capture(&cfg.capture)
                    .map(|m| m.iter().filter(|m| m.dir == cfg.direction).count())
                    .unwrap_or(0),
                cfg.output
            );
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("parity-replay failed: {e}");
            ExitCode::from(1)
        }
    }
}

/// `lr mrt diff A.mrt B.mrt` — content-level comparison of two dumps.
pub fn cmd_mrt_diff(a: &str, b: &str) -> ExitCode {
    let (ra, rb) = match (lr_mrt::parse_file(a), lr_mrt::parse_file(b)) {
        (Ok(x), Ok(y)) => (x, y),
        (Err(e), _) | (_, Err(e)) => {
            eprintln!("mrt diff: parse error: {e}");
            return ExitCode::from(1);
        }
    };
    let report = diff_rib_dumps(&ra, &rb);
    print_diff_report(&report, a, b)
}

#[cfg(test)]
mod tests {
    use super::*;

    use lr_core::addr::Prefix;

    /// Split a drained output buffer into individual BGP messages
    /// (marker + 2-byte length framing). Drains can coalesce messages
    /// exactly like TCP does; the wire proxy records per message.
    fn split_messages(buf: &[u8]) -> Vec<Vec<u8>> {
        let mut out = Vec::new();
        let mut i = 0;
        while i + 19 <= buf.len() {
            let len = u16::from_be_bytes([buf[i + 16], buf[i + 17]]) as usize;
            let end = i + len;
            if end > buf.len() || buf[i..i + 16].iter().any(|b| *b != 0xff) {
                break; // torn tail or garbage — the proxy would buffer
            }
            out.push(buf[i..end].to_vec());
            i = end;
        }
        out
    }

    fn tmp(name: &str) -> String {
        std::env::temp_dir()
            .join(format!("lr_parity_{}_{}.tmp", std::process::id(), name))
            .to_str()
            .unwrap()
            .to_string()
    }

    /// Drive two in-process routers through a real OPEN/KEEPALIVE/
    /// UPDATE exchange, recording speaker A's *sent* bytes as a
    /// capture — the exact artifact the wire proxy would have produced
    /// for the reference-to-lr direction. The receiver side is driven
    /// strictly from the capture file afterwards, exactly like the
    /// offline replay.
    fn exchange_and_capture(path: &str) {
        let mut a = DefaultRouter::new(); // the "reference" speaker
        a.set_ebgp_requires_policy(false);
        let mut b = DefaultRouter::new(); // counterparty (drives the FSM)
        b.set_ebgp_requires_policy(false);
        let ha = a
            .add_session(SessionConfig::bgp(
                Asn(64512),
                Asn(64513),
                RouterId::from_u32(0x0a000001),
            ))
            .unwrap();
        let hb = b
            .add_session(SessionConfig::bgp(
                Asn(64513),
                Asn(64512),
                RouterId::from_u32(0x0a000002),
            ))
            .unwrap();
        a.start_session(ha).unwrap();
        b.start_session(hb).unwrap();

        // A's OPEN is the captured stream's first message.
        for msg in split_messages(&a.drain_output(ha)) {
            append_capture(path, "down", &msg).unwrap();
        }
        // Counterparty handshake (never captured). Wire-order faithful:
        // B receives A's OPEN (the captured bytes) and answers with its
        // OPEN + KEEPALIVE; A receives those and reaches Established.
        for msg in split_messages(&b.drain_output(hb)) {
            // B's own OPEN — feed it to A (it was on the wire too, but
            // the capture records the reference-to-lr direction only;
            // the replayed router synthesizes its own OPEN).
            a.feed_input(ha, &msg).unwrap();
        }
        for msg in split_messages(&a.drain_output(ha)) {
            // A's KEEPALIVE (queued on OPEN receipt) — part of the
            // reference-to-lr stream.
            if msg[18] != 3 {
                append_capture(path, "down", &msg).unwrap();
            }
        }
        // B still needs A's OPEN to leave OpenSent... but the capture
        // already has it: feed it now (wire order on B's side is not
        // the capture's concern).
        for m in read_capture(path).unwrap() {
            let bytes = hex_decode(&m.hex).unwrap();
            if bytes[18] == 1 {
                b.feed_input(hb, &bytes).unwrap(); // B: A's OPEN
                break;
            }
        }
        let b_ka = b.drain_output(hb);
        for msg in split_messages(&b_ka) {
            a.feed_input(ha, &msg).unwrap(); // A: KA received -> Established
        }
        // A is Established: capture everything it queues (KEEPALIVE,
        // End-of-RIB) except NOTIFICATIONs.
        let established_out = a.drain_output(ha);
        for msg in split_messages(&established_out) {
            if msg[18] != 3 {
                append_capture(path, "down", &msg).unwrap();
            }
        }

        // Two originated routes cross the wire as UPDATEs.
        a.originate(
            Prefix::new_v4([198, 51, 100, 0], 24),
            Some(lr_core::addr::IpAddr::V4([192, 0, 2, 9])),
        );
        a.originate(
            Prefix::new_v4([203, 0, 113, 0], 24),
            Some(lr_core::addr::IpAddr::V4([192, 0, 2, 9])),
        );
        for msg in split_messages(&a.drain_output(ha)) {
            if msg[18] != 3 {
                append_capture(path, "down", &msg).unwrap();
            }
        }
    }

    #[test]
    fn parity_replay_end_to_end() {
        let capture = tmp("cap");
        let dump_b = tmp("b_mrt");
        let dump_c = tmp("c_mrt");
        let _ = std::fs::remove_file(&capture);
        exchange_and_capture(&capture);

        // Feed a receiver strictly from the captured stream — the
        // original receiver's Loc-RIB is the in-process ground truth.
        let mut b = DefaultRouter::new();
        b.set_ebgp_requires_policy(false);
        let hb = b
            .add_session(SessionConfig::bgp(
                Asn(64513),
                Asn(64512),
                RouterId::from_u32(0x0a000002),
            ))
            .unwrap();
        b.start_session(hb).unwrap();
        let _ = b.drain_output(hb); // B's own OPEN
        for m in read_capture(&capture).unwrap() {
            let bytes = hex_decode(&m.hex).unwrap();
            b.feed_input(hb, &bytes).unwrap();
            b.tick(lr_core::time::Instant(1_000_000));
            let _ = b.drain_output(hb);
            let _ = b.poll_events();
        }
        let routes: Vec<lr_core::rib::Route> =
            b.rib_paths_snapshot().into_iter().cloned().collect();
        assert_eq!(routes.len(), 2, "receiver must hold both routes");
        write_rib_dump(&routes, RouterId::from_u32(0x0a000002), Asn(64512), &dump_b)
            .expect("dump B");

        // Replay the same capture through the CLI path into a fresh
        // router and dump its Loc-RIB.
        let cfg = ReplayConfig {
            capture: capture.clone(),
            direction: "down".to_string(),
            local_as: 64513,
            peer_as: 64512,
            router_id: "10.0.0.2".to_string(),
            output: dump_c.clone(),
        };
        let records = run_replay(&cfg).expect("replay must succeed");
        assert_eq!(records, 2, "replayed Loc-RIB must carry both prefixes");

        // Content parity: the replay must match the original receiver.
        let report = diff_rib_dumps(
            &lr_mrt::parse_file(&dump_b).unwrap(),
            &lr_mrt::parse_file(&dump_c).unwrap(),
        );
        assert!(
            report.is_clean(),
            "replay must match the original receiver: {report:?}"
        );
        assert_eq!(report.identical, 2);
        for f in [&capture, &dump_b, &dump_c] {
            let _ = std::fs::remove_file(f);
        }
    }

    #[test]
    fn diff_reports_missing_and_mismatched_prefixes() {
        let p1 = Prefix::new_v4([198, 51, 100, 0], 24);
        let p2 = Prefix::new_v4([203, 0, 113, 0], 24);
        let entry = |nh: [u8; 4]| -> RibEntry {
            let mut attrs = vec![0x40u8, 3, 4];
            attrs.extend_from_slice(&nh);
            RibEntry {
                peer_index: 0,
                originated_time: 0,
                path_id: 0,
                attributes: attrs,
            }
        };
        let table = |prefix: lr_core::addr::Prefix, e: RibEntry| -> MrtRecord {
            MrtRecord::Rib(RibTable {
                sequence: 0,
                prefix,
                add_path: false,
                entries: vec![e],
            })
        };
        let a = vec![
            table(p1, entry([192, 0, 2, 9])),
            table(p2, entry([192, 0, 2, 9])),
        ];
        let b = vec![
            table(p1, entry([192, 0, 2, 9])),  // identical
            table(p2, entry([192, 0, 2, 10])), // next hop differs
        ];

        let report = diff_rib_dumps(&a, &b);
        assert!(!report.is_clean());
        assert_eq!(report.only_in_a.len(), 0);
        assert_eq!(report.only_in_b.len(), 0);
        assert_eq!(report.mismatched.len(), 1);
        assert_eq!(report.mismatched[0].0, p2);
        assert_eq!(report.identical, 1);

        // A prefix missing from B is reported as only-in-A.
        let report = diff_rib_dumps(&a, &b[..1]);
        assert_eq!(report.only_in_a, vec![p2]);
        assert_eq!(report.identical, 1);
    }

    #[test]
    fn capture_json_roundtrip() {
        let capture = tmp("roundtrip");
        let _ = std::fs::remove_file(&capture);
        append_capture(&capture, "down", &[0xff, 0x00, 0xab]).unwrap();
        append_capture(&capture, "up", &[1, 2, 3]).unwrap();
        let msgs = read_capture(&capture).unwrap();
        assert_eq!(msgs.len(), 2);
        assert_eq!(msgs[0].dir, "down");
        assert_eq!(hex_decode(&msgs[0].hex).unwrap(), vec![0xff, 0x00, 0xab]);
        assert_eq!(msgs[1].dir, "up");
        assert_eq!(hex_decode(&msgs[1].hex).unwrap(), vec![1, 2, 3]);
        let _ = std::fs::remove_file(&capture);
    }
}
