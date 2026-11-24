//! Feed a TABLE_DUMP_V2 RIB dump into a Loc-RIB.
//!
//! One loader shared by the two consumers of the real-data benchmark
//! (issue #101 "Benchmark Based on Real Data"):
//!
//! - `lr bench replay --mrt <file>` instantiates it in-process and
//!   measures the install/selection path.
//! - `lr-daemon --mrt-feed <file>` uses it to seed the source speaker
//!   that advertises the routes to BIRD / FRR in
//!   `tests/bench/real_data.sh`.
//!
//! A public RIB dump carries many candidate paths per prefix (one per
//! collector peer). The dump has no "best path" marker, so the loader
//! groups the entries by prefix and runs the same decision process the
//! router runs ([`BestPath::rank`]) before handing the ranked set to
//! [`LocRib::install_set`]. Installing the entries one by one through
//! [`LocRib::install`] is wrong for this input: the non-Add-Path
//! entries all carry `path_id = 0`, so every install would replace the
//! previous candidate and the last entry in the dump, not the best
//! path, would become the prefix's selected route.
//!
//! The dump is streamed: `MrtReader` decodes one record at a time from
//! fixed-size reads, so a multi-hundred-megabyte dump never has to be
//! held in memory as a `Vec<MrtRecord>`. `cap` bounds the number of
//! prefixes kept (the read stops once it is reached), and
//! `max_paths` bounds the ranked set stored per prefix (`0` keeps
//! every candidate). The daemon feed keeps the best path only — it
//! advertises over a non-Add-Path session — while the bench keeps the
//! full ranked set to exercise multi-path storage.

use std::collections::BTreeMap;

use lr_bgp::best_path::{BestPath, BestPathConfig};
use lr_core::addr::Prefix;
use lr_core::attr::Attributes;
use lr_core::nlri::NlriFamily;
use lr_core::rib::{Preference, Protocol, Route, RouteKey, RouteOrigin};
use lr_mrt::{decode_attributes, walk_attributes, MrtReader, MrtRecord};
use lr_rib::LocRib;

/// Candidate paths grouped by prefix, ranked best-first, plus the
/// number of dump entries read.
pub(crate) struct Feed {
    /// One `(key, ranked set)` per prefix, in key order.
    pub sets: Vec<(RouteKey, Vec<Route>)>,
    /// `(prefix, entry)` pairs read before the cap stopped the parse.
    pub dump_paths: usize,
}

/// Parse `path`, group its RIB entries by prefix, rank each prefix's
/// candidate set with the BGP decision process, and keep the first
/// `cap` prefixes (`0` = no cap). Each kept set is truncated to
/// `max_paths` after ranking (`0` = keep every candidate).
pub(crate) fn load(path: &str, cap: usize, max_paths: usize) -> Result<Feed, String> {
    let mut have_peer_table = false;
    let mut by_key: BTreeMap<RouteKey, Vec<Route>> = BTreeMap::new();
    let mut dump_paths = 0usize;
    stream_records(path, |record| {
        match record {
            MrtRecord::PeerIndexTable(_) => have_peer_table = true,
            MrtRecord::Rib(table) => {
                let family = if table.prefix.is_ipv4() {
                    NlriFamily::IPV4_UNICAST
                } else {
                    NlriFamily::IPV6_UNICAST
                };
                let key = RouteKey::new(table.prefix, family);
                // TABLE_DUMP_V2 writes one record per prefix in
                // prefix order, so once `cap` distinct prefixes are
                // held, every later record is beyond the cap.
                if cap != 0 && by_key.len() >= cap && !by_key.contains_key(&key) {
                    return false;
                }
                let set = by_key.entry(key).or_default();
                for entry in &table.entries {
                    dump_paths += 1;
                    set.push(build_route(table.prefix, family, entry));
                }
            }
            _ => {}
        }
        true
    })?;
    if !have_peer_table {
        return Err(format!(
            "{path}: no PEER_INDEX_TABLE — not a TABLE_DUMP_V2 RIB dump"
        ));
    }

    let cfg = BestPathConfig::default();
    let mut sets = Vec::with_capacity(by_key.len());
    for (key, candidates) in by_key {
        let mut ranked: Vec<Route> = BestPath::rank(&candidates, &cfg)
            .into_iter()
            .cloned()
            .collect();
        if max_paths != 0 {
            ranked.truncate(max_paths);
        }
        sets.push((key, ranked));
    }
    Ok(Feed { sets, dump_paths })
}

/// Decode every record in `path`, handing each one to `on_record`.
/// Stops early when the callback returns `false`.
fn stream_records(path: &str, mut on_record: impl FnMut(MrtRecord) -> bool) -> Result<(), String> {
    use std::io::Read;

    let file = std::fs::File::open(path).map_err(|e| format!("open {path}: {e}"))?;
    let mut file = std::io::BufReader::with_capacity(1 << 20, file);
    let mut reader = MrtReader::new();
    let mut buf = vec![0u8; 1 << 20];
    loop {
        let n = file
            .read(&mut buf)
            .map_err(|e| format!("read {path}: {e}"))?;
        // Feed the chunk once, then drain every complete record the
        // carryover now holds. `decode_slice(&[])` only advances the
        // read cursor; it never copies the unconsumed tail.
        let mut chunk: &[u8] = &buf[..n];
        loop {
            let record = reader
                .decode_slice(chunk)
                .map_err(|e| format!("decode {path}: {e}"))?;
            chunk = &[];
            match record {
                Some(record) => {
                    if !on_record(record) {
                        return Ok(());
                    }
                }
                None => break,
            }
        }
        if n == 0 {
            return Ok(());
        }
    }
}

/// Install every ranked set into `rib`, best path first. Returns the
/// number of paths installed.
pub(crate) fn install(rib: &LocRib, feed: &Feed) -> usize {
    let mut installed = 0usize;
    for (key, ranked) in &feed.sets {
        installed += ranked.len();
        rib.install_set(key, ranked.clone());
    }
    installed
}

/// Build one Loc-RIB route from an MRT RIB entry.
fn build_route(prefix: Prefix, family: NlriFamily, entry: &lr_mrt::RibEntry) -> Route {
    let attrs: Attributes = decode_attributes(&entry.attributes);
    let summary = walk_attributes(entry);
    // MRT RIB entries are received from a peer, so they are external
    // BGP paths (`origin.proto == 0`). Marking them internal would make
    // the decision process apply iBGP LOCAL_PREF semantics and the
    // export path treat them as iBGP-learned.
    Route {
        key: RouteKey::new(prefix, family),
        origin: RouteOrigin {
            proto: 0,
            peer: entry.peer_index as u64,
        },
        protocol: Protocol::Bgp,
        preference: Preference::new(
            Protocol::Bgp.default_admin_distance(),
            summary.local_pref.unwrap_or(100),
        ),
        next_hop: summary.next_hop,
        attributes: attrs,
        age_ms: (entry.originated_time as u64) * 1000,
        path_id: entry.path_id,
        tag: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lr_core::addr::{Asn, IpAddr};
    use lr_mrt::{MrtRibDump, PeerEntry, RibEntry, RibTable};

    fn attr(flags: u8, typ: u8, value: &[u8]) -> Vec<u8> {
        let mut out = vec![flags, typ, value.len() as u8];
        out.extend_from_slice(value);
        out
    }

    fn as_path(ases: &[u32]) -> Vec<u8> {
        let mut value = vec![2, ases.len() as u8];
        for asn in ases {
            value.extend_from_slice(&asn.to_be_bytes());
        }
        attr(0x40, 2, &value)
    }

    fn next_hop(octets: [u8; 4]) -> Vec<u8> {
        attr(0x40, 3, &octets)
    }

    fn origin() -> Vec<u8> {
        attr(0x40, 1, &[0])
    }

    /// Three candidates for one prefix. The shortest AS path is the
    /// middle entry, so a loader that returns the first or last entry
    /// fails the assertion. A second prefix checks the cap.
    fn write_dump(path: &str, cap_prefixes: usize) -> Feed {
        let mut dump = MrtRibDump::new(0x0a00_0001, "test");
        dump.add_peer(PeerEntry {
            bgp_id: 0x0a00_0002,
            ip: IpAddr::V4([10, 0, 0, 2]),
            asn: Asn(64512),
        });
        let mut path_a = origin();
        path_a.extend_from_slice(&as_path(&[64500, 64500, 64500]));
        path_a.extend_from_slice(&next_hop([192, 0, 2, 2]));
        let mut path_b = origin();
        path_b.extend_from_slice(&as_path(&[64501]));
        path_b.extend_from_slice(&next_hop([192, 0, 2, 3]));
        let mut path_c = origin();
        path_c.extend_from_slice(&as_path(&[64502, 64502]));
        path_c.extend_from_slice(&next_hop([192, 0, 2, 4]));
        let entries = |attrs: [Vec<u8>; 3]| {
            attrs
                .into_iter()
                .enumerate()
                .map(|(i, attributes)| RibEntry {
                    peer_index: i as u16,
                    originated_time: 1_700_000_000 + i as u32,
                    path_id: 0,
                    attributes,
                })
                .collect()
        };
        dump.add_table(RibTable {
            sequence: 0,
            prefix: Prefix::new_v4([100, 64, 0, 0], 10),
            add_path: false,
            entries: entries([path_a, path_b, path_c]),
        });
        dump.add_table(RibTable {
            sequence: 1,
            prefix: Prefix::new_v4([198, 51, 100, 0], 24),
            add_path: false,
            entries: entries([origin(), origin(), origin()]),
        });
        let bytes = dump.encode(1_700_000_000).unwrap();
        std::fs::write(path, bytes).unwrap();
        load(path, cap_prefixes, 0).expect("load must succeed")
    }

    #[test]
    fn ranks_candidates_and_keeps_every_path() {
        let dir = std::env::temp_dir().join(format!("lr_mrt_feed_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("feed.mrt");
        let feed = write_dump(path.to_str().unwrap(), 0);
        assert_eq!(feed.dump_paths, 6);
        assert_eq!(feed.sets.len(), 2);
        assert_eq!(feed.sets.iter().map(|(_, set)| set.len()).sum::<usize>(), 6);
        let (_, set) = &feed.sets[0];
        assert_eq!(set.len(), 3, "all candidates retained");
        assert_eq!(
            set[0].next_hop,
            Some(IpAddr::V4([192, 0, 2, 3])),
            "shortest AS path wins"
        );
        assert_eq!(set[0].origin.proto, 0, "dump entries are external");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn cap_counts_prefixes_not_entries() {
        let dir = std::env::temp_dir().join(format!("lr_mrt_feed_cap_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("feed.mrt");
        let feed = write_dump(path.to_str().unwrap(), 1);
        assert_eq!(feed.dump_paths, 3, "the read stops at the capped prefix");
        assert_eq!(feed.sets.len(), 1);
        assert_eq!(
            feed.sets[0].1.len(),
            3,
            "the kept prefix keeps its candidates"
        );
        std::fs::remove_dir_all(&dir).ok();
    }
}
