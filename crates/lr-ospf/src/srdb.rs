//! Per-node Segment Routing database built from the area LSDB — the
//! receiving half of RFC 8665 (slice 1 shipped the codec and the
//! origination half).
//!
//! Three LSA families feed it:
//!
//! - **Router Information opaque LSAs** (RFC 4970 §2.3 / RFC 8665 §3,
//!   area-scoped, Opaque Type 4): the SRGB Descriptor TLV binds the
//!   advertising router to its Segment Routing Global Block. A node
//!   without an SRGB is not an SR node (RFC 8665 §3.2) and never
//!   contributes labels.
//! - **Extended Prefix opaque LSAs** (RFC 7684 §2.1 / RFC 8665 §5,
//!   area-scoped, Opaque Type 7): one Extended Prefix TLV per
//!   advertised prefix, carrying the Prefix-SID sub-TLV with the SID
//!   index and flags, and **Extended Prefix Range TLVs** (RFC 8665 §4)
//!   — the SR Mapping Server's M-flagged prefix→SID bindings for
//!   prefixes the server does not own (RFC 8661).
//! - **Extended Link opaque LSAs** (RFC 7684 §3 / RFC 8665 §6,
//!   area-scoped, Opaque Type 8): one Extended Link TLV per
//!   advertised link, carrying the Adj-SID / LAN Adj-SID sub-TLVs —
//!   the adjacency segments.
//!
//! The label a receiving router derives for a prefix is the
//! originating node's SRGB base plus the SID index (RFC 8665 §5,
//! guarded per RFC 8665 §5; RFC 8660 §4.2). Selecting among several
//! candidate mappings for one prefix needs SPF reachability data, so
//! it lives with the caller ([`crate::spf::SpfResult`] consumers);
//! this module keeps the database a pure LSDB projection.

use std::collections::BTreeMap;

use crate::lsa::sr::{
    decode_ext_link_lsa_body, decode_ext_prefix_lsa_body_full, decode_ri_sr_lsa_body, remote_label,
    sr_opaque_type, ExtPrefixTlvAdvert, RiSrBlock, SrAdjSidTlv, SrPrefixSidTlv,
    OPAQUE_TYPE_EXT_LINK, OPAQUE_TYPE_EXT_PREFIX, OPAQUE_TYPE_RI,
};
use crate::lsa::LsaTypeV2;
use crate::lsdb::Lsdb;
use lr_core::addr::{IpAddr, Prefix};

/// One candidate Prefix-SID mapping for a prefix (RFC 8665 §5): who
/// advertised it and with which SID sub-TLV.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SrPrefixMapping {
    /// Advertising router of the Extended Prefix Opaque LSA.
    pub advertising_router: u32,
    /// RFC 7684 §2.1 route type (1 intra-area, 3 inter-area, 5 external,
    /// 7 NSSA).
    pub route_type: u8,
    /// RFC 7684 §2.1 N-flag: the prefix identifies the advertising node
    /// itself (an SR-Node / loopback).
    pub node: bool,
    /// The Prefix-SID sub-TLV (flags, MT-ID, algorithm, SID index).
    pub sid: SrPrefixSidTlv,
}

/// One adjacency segment learned from an Extended Link Opaque LSA
/// (RFC 8665 §6 / RFC 7684 §3): a link of the advertising router
/// carrying one or more Adj-SIDs. An adjacency segment steers traffic
/// over that specific link — a one-hop path (RFC 8402 §2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SrAdjSegment {
    /// Advertising router of the Extended Link Opaque LSA.
    pub advertising_router: u32,
    /// RFC 7684 §3.1 link type (1 p2p, 2 transit).
    pub link_type: u8,
    /// RFC 7684 §3.1 Link ID: the neighbour's Router ID (p2p) or the
    /// DR's interface address (transit).
    pub link_id: [u8; 4],
    /// RFC 7684 §3.1 Link Data: the advertising router's interface
    /// address on the link.
    pub link_data: [u8; 4],
    /// The decoded Adj-SID / LAN Adj-SID sub-TLV.
    pub sid: SrAdjSidTlv,
}

/// One mapping-server range learned from an Extended Prefix Range TLV
/// (RFC 8665 §4): `range_size` consecutive prefixes of `prefix_len`
/// bits starting at `prefix`, the first carrying SID index
/// `sid.sid`. Per RFC 8661 §3.2.2 the covered prefixes are labelled
/// exactly as if their owners had advertised the SIDs themselves —
/// the index of prefix P inside the range is
/// `sid.sid + offset(P, prefix)`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SrRangeMapping {
    /// Advertising router of the Extended Prefix Opaque LSA (the
    /// mapping server).
    pub advertising_router: u32,
    /// The range descriptor (prefix base, length, size, IA flag).
    pub range: crate::lsa::sr::SrPrefixRangeCore,
    /// The Prefix-SID sub-TLV of the range (M-flag set, index of the
    /// first covered prefix).
    pub sid: SrPrefixSidTlv,
}

impl SrRangeMapping {
    /// The SID index assigned to `prefix`, per RFC 8665 §4 / RFC 8661
    /// §3.2: the advertised index plus the prefix's offset inside the
    /// range. `None` when `prefix` falls outside the covered span.
    pub fn index_for(&self, prefix: &Prefix) -> Option<u32> {
        let IpAddr::V4(octets) = prefix.addr else {
            return None; // OSPFv2 maps IPv4 unicast only
        };
        if prefix.prefix_len != self.range.prefix_len {
            return None;
        }
        let base = u32::from_be_bytes(self.range.prefix);
        let addr = u32::from_be_bytes(octets);
        if addr < base {
            return None;
        }
        let shift = 32 - u32::from(self.range.prefix_len);
        let offset = if shift == 0 {
            addr - base
        } else {
            (addr - base) >> shift
        };
        if offset >= u32::from(self.range.range_size) {
            return None;
        }
        Some(self.sid.sid.saturating_add(offset))
    }
}

/// The per-node SR database of one area: every node's SRGB, every
/// advertised Prefix-SID mapping, every adjacency segment and every
/// mapping-server range, projected straight from the LSDB.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SrDatabase {
    /// Advertising router → its SRGB (from Router Information LSAs).
    /// A router absent here advertised no (MPLS) SRGB — not an SR node.
    pub srgbs: BTreeMap<u32, RiSrBlock>,
    /// Prefix → candidate Prefix-SID mappings (one per advertising
    /// router; several routers may advertise the same prefix, e.g. an
    /// anycast segment).
    pub prefixes: BTreeMap<Prefix, Vec<SrPrefixMapping>>,
    /// Advertising router → adjacency segments from its Extended Link
    /// opaque LSAs (RFC 8665 §6).
    pub links: BTreeMap<u32, Vec<SrAdjSegment>>,
    /// Mapping-server ranges from Extended Prefix Range TLVs
    /// (RFC 8665 §4).
    pub prefix_ranges: Vec<SrRangeMapping>,
}

impl SrDatabase {
    /// Project the SR content of an area LSDB into a database. Only
    /// area-scoped opaque LSAs (LS type 10) with the RI (4), Extended
    /// Prefix (7) and Extended Link (8) Opaque Types contribute; every
    /// other LSA is ignored. Malformed TLVs drop their own LSA, never
    /// the database.
    pub fn from_lsdb(lsdb: &Lsdb) -> Self {
        let mut db = SrDatabase::default();
        for (key, entry) in lsdb.iter() {
            if key.ls_type != LsaTypeV2::OpaqueAreaLsa as u16 {
                continue;
            }
            match sr_opaque_type(&entry.lsa) {
                OPAQUE_TYPE_RI => {
                    if let Some(Some(block)) = decode_ri_sr_lsa_body(&entry.lsa.body) {
                        db.srgbs.insert(key.advertising_router, block);
                    }
                }
                OPAQUE_TYPE_EXT_PREFIX => {
                    if let Some(adverts) = decode_ext_prefix_lsa_body_full(&entry.lsa.body) {
                        for advert in adverts {
                            match advert {
                                ExtPrefixTlvAdvert::Prefix(core, sid) => {
                                    let Some(sid) = sid else {
                                        continue; // prefix descriptor without a SID: no mapping
                                    };
                                    let prefix = Prefix::new_v4(core.prefix, core.prefix_len);
                                    db.prefixes
                                        .entry(prefix)
                                        .or_default()
                                        .push(SrPrefixMapping {
                                            advertising_router: key.advertising_router,
                                            route_type: core.route_type,
                                            node: core.flags & 0x40 != 0,
                                            sid,
                                        });
                                }
                                ExtPrefixTlvAdvert::Range(range, sid) => {
                                    let Some(sid) = sid else {
                                        continue; // range without a SID: no mapping
                                    };
                                    db.prefix_ranges.push(SrRangeMapping {
                                        advertising_router: key.advertising_router,
                                        range,
                                        sid,
                                    });
                                }
                            }
                        }
                    }
                }
                OPAQUE_TYPE_EXT_LINK => {
                    if let Some(links) = decode_ext_link_lsa_body(&entry.lsa.body) {
                        for (link, sids) in links {
                            let segments = db.links.entry(key.advertising_router).or_default();
                            segments.extend(sids.into_iter().map(|sid| SrAdjSegment {
                                advertising_router: key.advertising_router,
                                link_type: link.link_type,
                                link_id: link.link_id,
                                link_data: link.link_data,
                                sid,
                            }));
                        }
                    }
                }
                _ => {}
            }
        }
        db
    }

    /// Resolve the MPLS label to push for `prefix` given the SPF
    /// outcome: among the mappings whose algorithm is SPF (0) and whose
    /// advertising router is reachable in the SPF tree *with a
    /// resolvable next hop*, the best candidate wins — lowest distance
    /// to the advertising router, ties broken by the lowest router ID
    /// (deterministic). Returns `(label, next_hop)`.
    ///
    /// RFC 8665 §5 PHP rule: when the winning Prefix-SID does not
    /// carry the NP flag and its advertising router is directly
    /// adjacent (one hop away), this router *is* the penultimate hop
    /// and pops instead of pushing — `None` is returned so the caller
    /// forwards unlabeled.
    ///
    /// `None` also when no SR node advertises the prefix, the winning
    /// SID's index falls outside its originator's advertised range (the SID
    /// is discarded) or the SID carries the V/L flags (an absolute/
    /// local label the global mapping does not apply to — the same
    /// guard [`crate::lsa::sr::remote_label`] enforces).
    pub fn label_for(
        &self,
        prefix: &Prefix,
        spf: &crate::spf::SpfResult,
    ) -> Option<(u32, lr_core::addr::IpAddr)> {
        let candidates = self.prefixes.get(prefix)?;
        let mut best: Option<(u64, u32, u32, lr_core::addr::IpAddr)> = None;
        for m in candidates {
            if m.sid.algorithm != 0 {
                continue; // only the SPF algorithm maps into this SRGB path
            }
            let rid = m.advertising_router;
            let vertex = crate::spf::VertexId::Router(rid);
            let Some(&distance) = spf.vertices.get(&vertex) else {
                continue; // originator unreachable: no usable path
            };
            let Some(&next_hop) = spf.next_hops.get(&vertex) else {
                continue; // no resolvable first hop: nothing to point the LSP at
            };
            if !self.srgbs.contains_key(&rid) {
                continue; // originator without an SRGB is not an SR node (RFC 8665 §3.2)
            };
            let better = match best {
                None => true,
                Some((d, r, _, _)) => distance < d || (distance == d && rid < r),
            };
            if better {
                best = Some((distance, rid, m.sid.sid, next_hop));
            }
        }
        let (_, rid, sid_index, next_hop) = best?;
        let srgb = self.srgbs.get(&rid)?;
        let mapping = candidates
            .iter()
            .find(|m| m.advertising_router == rid && m.sid.sid == sid_index)?;
        // PHP: NP clear + directly adjacent originator → we pop.
        if mapping.sid.flags & crate::lsa::sr::sid_flags::NP == 0
            && spf.adjacent_routers.contains(&rid)
        {
            return None;
        }
        let label = remote_label(srgb, &mapping.sid)?;
        Some((label, next_hop))
    }

    /// Resolve the label a **mapping-server range** (RFC 8665 §4) maps
    /// `prefix` to, given the SPF outcome. Only consulted when no
    /// direct Prefix-SID advertisement exists for the prefix — RFC 8661
    /// §3.2.3: direct advertisements beat SRMS mappings. Among the
    /// covering ranges the closest reachable mapping server wins
    /// (lowest router ID on ties), mirroring [`SrDatabase::label_for`].
    ///
    /// The label is the winning server's SRGB base plus the prefix's
    /// index inside the range (`sid.sid + offset`, RFC 8665 §4) — the
    /// homogeneous-SRGB-domain arithmetic the direct path uses too
    /// (RFC 8660 §4.2). The LSP rides the *prefix's own* path, not the
    /// path toward the server: the caller pairs this label with the
    /// route's regular next hop, unlike [`SrDatabase::label_for`],
    /// which returns the next hop itself.
    ///
    /// `None` when no reachable SR-capable server covers the prefix,
    /// the index arithmetic falls outside the advertised range, or the
    /// SID carries the V/L flags (an absolute/local shape the global
    /// mapping does not apply to).
    pub fn mapping_label_for(&self, prefix: &Prefix, spf: &crate::spf::SpfResult) -> Option<u32> {
        let mut best: Option<(u64, u32, &SrRangeMapping)> = None;
        for range in &self.prefix_ranges {
            if range.sid.algorithm != 0 {
                continue; // only the SPF algorithm maps into this SRGB path
            }
            if range.sid.flags & crate::lsa::sr::sid_flags::V != 0 {
                continue; // absolute shape: not a global index mapping
            }
            if range.index_for(prefix).is_none() {
                continue; // prefix outside the advertised span
            };
            let rid = range.advertising_router;
            let Some(&distance) = spf.vertices.get(&crate::spf::VertexId::Router(rid)) else {
                continue; // server unreachable: no usable path
            };
            if !self.srgbs.contains_key(&rid) {
                continue; // server without an SRGB cannot resolve labels
            }
            let better = match best {
                None => true,
                Some((d, r, _)) => distance < d || (distance == d && rid < r),
            };
            if better {
                best = Some((distance, rid, range));
            }
        }
        let (_, rid, range) = best?;
        let index = range.index_for(prefix)?;
        let srgb = self.srgbs.get(&rid)?;
        if index >= srgb.srgb_range {
            return None; // index outside the server's advertised range
        }
        Some(srgb.srgb_base + index)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lsa::sr::{originate_sr_prefix_lsa, originate_sr_ri_lsa, sid_flags, SrPrefixAdvert};
    use crate::lsa::Lsa;

    fn sr_db_with(rid: u32, srgb: Option<(u32, u32)>, adverts: Vec<SrPrefixAdvert>) -> Lsdb {
        let mut db = Lsdb::new();
        if let Some((base, range)) = srgb {
            db.install(originate_sr_ri_lsa(rid, base, range, None).unwrap(), 0);
        }
        for (idx, advert) in adverts.iter().enumerate() {
            db.install(
                originate_sr_prefix_lsa(rid, advert, idx as u32, None).unwrap(),
                0,
            );
        }
        db
    }

    fn advert(prefix: [u8; 4], len: u8, sid: u32, node: bool, sid_flags: u8) -> SrPrefixAdvert {
        SrPrefixAdvert {
            route_type: 1,
            flags: if node { 0x40 } else { 0x00 },
            prefix,
            prefix_len: len,
            sid_flags,
            sid,
            algorithm: 0,
        }
    }

    fn prefix(p: [u8; 4], len: u8) -> Prefix {
        Prefix::new_v4(p, len)
    }

    #[test]
    fn from_lsdb_collects_srgbs_and_prefix_mappings() {
        let lsdb = sr_db_with(
            0x01010101,
            Some((16_000, 8_000)),
            vec![
                advert([10, 0, 0, 0], 24, 100, true, sid_flags::NP),
                advert([10, 0, 1, 0], 24, 101, false, 0),
            ],
        );
        let db = SrDatabase::from_lsdb(&lsdb);
        assert_eq!(
            db.srgbs.get(&0x01010101),
            Some(&RiSrBlock {
                srgb_base: 16_000,
                srgb_range: 8_000
            })
        );
        let mappings = db.prefixes.get(&prefix([10, 0, 0, 0], 24)).unwrap();
        assert_eq!(mappings.len(), 1);
        assert_eq!(mappings[0].advertising_router, 0x01010101);
        assert!(mappings[0].node);
        assert_eq!(mappings[0].sid.sid, 100);
        let mappings = db.prefixes.get(&prefix([10, 0, 1, 0], 24)).unwrap();
        assert!(!mappings[0].node);
        assert_eq!(mappings[0].sid.flags, 0);
    }

    #[test]
    fn from_lsdb_ignores_non_sr_lsas_and_malformed_bodies() {
        let mut lsdb = Lsdb::new();
        // A Router-LSA: not opaque, ignored.
        let mut body = Vec::new();
        body.extend_from_slice(&0u16.to_be_bytes());
        body.extend_from_slice(&0u16.to_be_bytes());
        lsdb.install(
            Lsa {
                header: crate::lsa::LsaHeader {
                    ls_age: 0,
                    options: 2,
                    ls_type: LsaTypeV2::RouterLsa as u16,
                    link_state_id: 0x01010101,
                    advertising_router: 0x01010101,
                    ls_sequence_number: 0x80000001,
                    ls_checksum: 0,
                    length: (crate::lsa::LsaHeader::LEN + body.len()) as u16,
                },
                body,
            },
            0,
        );
        // A Grace-LSA-shaped opaque LSA (Opaque Type 3): ignored.
        let grace = crate::lsa::grace::opaque_lsa_id(crate::lsa::grace::OPAQUE_TYPE_GRACE, 0);
        let mut lsa = Lsa {
            header: crate::lsa::LsaHeader {
                ls_age: 0,
                options: 2,
                ls_type: LsaTypeV2::OpaqueAreaLsa as u16,
                link_state_id: grace,
                advertising_router: 0x02020202,
                ls_sequence_number: 0x80000001,
                ls_checksum: 0,
                length: crate::lsa::LsaHeader::LEN as u16,
            },
            body: vec![0; 8],
        };
        lsa.finalize();
        lsdb.install(lsa, 0);
        // A truncated Extended Prefix LSA: dropped, not fatal.
        let mut lsa =
            originate_sr_prefix_lsa(0x03030303, &advert([10, 9, 9, 0], 24, 9, true, 0), 1, None)
                .unwrap();
        lsa.body.truncate(3);
        lsdb.install(lsa, 0);
        let db = SrDatabase::from_lsdb(&lsdb);
        assert!(db.srgbs.is_empty());
        assert!(db.prefixes.is_empty());
    }

    #[test]
    fn from_lsdb_without_prefix_sid_subtlv_installs_no_mapping() {
        // RFC 7684 shape with the prefix descriptor only: the LSA is
        // valid but carries no SID — no mapping appears.
        let mut wire = Vec::new();
        wire.extend_from_slice(&crate::lsa::sr::TLV_EXT_PREFIX.to_be_bytes());
        wire.extend_from_slice(&8u16.to_be_bytes());
        wire.extend_from_slice(&[1, 0x40, 0, 24, 10, 0, 2, 0]);
        let mut lsa = Lsa {
            header: crate::lsa::LsaHeader {
                ls_age: 0,
                options: 2,
                ls_type: LsaTypeV2::OpaqueAreaLsa as u16,
                link_state_id: crate::lsa::opaque_lsa_id(crate::lsa::sr::OPAQUE_TYPE_EXT_PREFIX, 9),
                advertising_router: 0x04040404,
                ls_sequence_number: 0x80000001,
                ls_checksum: 0,
                length: (crate::lsa::LsaHeader::LEN + wire.len()) as u16,
            },
            body: wire,
        };
        lsa.finalize();
        let mut lsdb = Lsdb::new();
        lsdb.install(
            originate_sr_ri_lsa(0x04040404, 16_000, 8_000, None).unwrap(),
            0,
        );
        lsdb.install(lsa, 0);
        let db = SrDatabase::from_lsdb(&lsdb);
        assert!(db.prefixes.is_empty());
    }

    #[test]
    fn label_for_resolves_base_plus_index_via_the_spf_next_hop() {
        // Topology: us (0x01010101) — B (0x02020202) — C (0x03030303).
        // C advertises the SRGB 16000/8000 and the prefix-SID
        // 10.30.0.0/24 index 200 with NP → label 16200 via B's address.
        let mut lsdb = sr_db_with(
            0x03030303,
            Some((16_000, 8_000)),
            vec![advert([10, 30, 0, 0], 24, 200, true, sid_flags::NP)],
        );
        lsdb.install(
            crate::spf::tests_util::router_lsa(0x01010101, vec![(0x02020202, 0, 1, 10)]),
            0,
        );
        lsdb.install(
            crate::spf::tests_util::router_lsa(
                0x02020202,
                vec![
                    (0x01010101, 0x0a000001, 1, 10),
                    (0x03030303, 0x0a000102, 1, 10),
                ],
            ),
            0,
        );
        lsdb.install(
            crate::spf::tests_util::router_lsa(0x03030303, vec![(0x02020202, 0x0a000102, 1, 10)]),
            0,
        );
        let spf = crate::spf::run_spf(&lsdb, 0x01010101);
        let db = SrDatabase::from_lsdb(&lsdb);
        let (label, nh) = db
            .label_for(&prefix([10, 30, 0, 0], 24), &spf)
            .expect("label mapping");
        assert_eq!(label, 16_200);
        assert_eq!(nh, lr_core::addr::IpAddr::V4([10, 0, 0, 1]));
    }

    #[test]
    fn label_for_pops_when_penultimate_and_np_clear() {
        // Direct neighbour advertises its prefix-SID without NP: we are
        // the penultimate hop — no label (PHP), forward unlabeled.
        let mut lsdb = sr_db_with(
            0x02020202,
            Some((16_000, 8_000)),
            vec![advert([10, 20, 0, 0], 24, 100, true, 0)],
        );
        lsdb.install(
            crate::spf::tests_util::router_lsa(0x01010101, vec![(0x02020202, 0, 1, 10)]),
            0,
        );
        lsdb.install(
            crate::spf::tests_util::router_lsa(0x02020202, vec![(0x01010101, 0x0a000001, 1, 10)]),
            0,
        );
        let spf = crate::spf::run_spf(&lsdb, 0x01010101);
        let db = SrDatabase::from_lsdb(&lsdb);
        assert!(db.label_for(&prefix([10, 20, 0, 0], 24), &spf).is_none());
        // The same topology with NP set pushes the label.
        let mut lsdb = sr_db_with(
            0x02020202,
            Some((16_000, 8_000)),
            vec![advert([10, 20, 0, 0], 24, 100, true, sid_flags::NP)],
        );
        lsdb.install(
            crate::spf::tests_util::router_lsa(0x01010101, vec![(0x02020202, 0, 1, 10)]),
            0,
        );
        lsdb.install(
            crate::spf::tests_util::router_lsa(0x02020202, vec![(0x01010101, 0x0a000001, 1, 10)]),
            0,
        );
        let spf = crate::spf::run_spf(&lsdb, 0x01010101);
        let db = SrDatabase::from_lsdb(&lsdb);
        assert_eq!(
            db.label_for(&prefix([10, 20, 0, 0], 24), &spf),
            Some((16_100, lr_core::addr::IpAddr::V4([10, 0, 0, 1])))
        );
    }

    #[test]
    fn label_for_prefers_the_closest_originator_then_the_lowest_rid() {
        // Two originators advertise the same prefix: the closer one
        // (distance 10 vs 20) wins; with equal distance the lower
        // router ID wins.
        let mut lsdb = sr_db_with(
            0x02020202,
            Some((16_000, 8_000)),
            vec![advert([10, 40, 0, 0], 24, 100, true, sid_flags::NP)],
        );
        lsdb.install(
            originate_sr_ri_lsa(0x05050505, 24_000, 8_000, None).unwrap(),
            0,
        );
        lsdb.install(
            originate_sr_prefix_lsa(
                0x05050505,
                &advert([10, 40, 0, 0], 24, 100, true, sid_flags::NP),
                7,
                None,
            )
            .unwrap(),
            0,
        );
        // us —10— B (0x02020202), us —20— E (0x05050505)
        lsdb.install(
            crate::spf::tests_util::router_lsa(
                0x01010101,
                vec![
                    (0x02020202, 0x0a000001, 1, 10),
                    (0x05050505, 0x0a000003, 1, 20),
                ],
            ),
            0,
        );
        lsdb.install(
            crate::spf::tests_util::router_lsa(0x02020202, vec![(0x01010101, 0x0a000001, 1, 10)]),
            0,
        );
        lsdb.install(
            crate::spf::tests_util::router_lsa(0x05050505, vec![(0x01010101, 0x0a000003, 1, 20)]),
            0,
        );
        let spf = crate::spf::run_spf(&lsdb, 0x01010101);
        let db = SrDatabase::from_lsdb(&lsdb);
        let (label, _) = db
            .label_for(&prefix([10, 40, 0, 0], 24), &spf)
            .expect("mapping from the closer originator");
        assert_eq!(label, 16_100); // B's SRGB base + 100

        // Equal distance: both at 10; the lower router ID (B) wins.
        let mut lsdb = sr_db_with(
            0x02020202,
            Some((16_000, 8_000)),
            vec![advert([10, 40, 0, 0], 24, 100, true, sid_flags::NP)],
        );
        lsdb.install(
            originate_sr_ri_lsa(0x05050505, 24_000, 8_000, None).unwrap(),
            0,
        );
        lsdb.install(
            originate_sr_prefix_lsa(
                0x05050505,
                &advert([10, 40, 0, 0], 24, 100, true, sid_flags::NP),
                7,
                None,
            )
            .unwrap(),
            0,
        );
        lsdb.install(
            crate::spf::tests_util::router_lsa(
                0x01010101,
                vec![
                    (0x02020202, 0x0a000001, 1, 10),
                    (0x05050505, 0x0a000003, 1, 10),
                ],
            ),
            0,
        );
        lsdb.install(
            crate::spf::tests_util::router_lsa(0x02020202, vec![(0x01010101, 0x0a000001, 1, 10)]),
            0,
        );
        lsdb.install(
            crate::spf::tests_util::router_lsa(0x05050505, vec![(0x01010101, 0x0a000003, 1, 10)]),
            0,
        );
        let spf = crate::spf::run_spf(&lsdb, 0x01010101);
        let db = SrDatabase::from_lsdb(&lsdb);
        let (label, _) = db
            .label_for(&prefix([10, 40, 0, 0], 24), &spf)
            .expect("mapping from the lower router ID");
        assert_eq!(label, 16_100);
    }

    #[test]
    fn label_for_skips_unreachable_unresolvable_and_non_sr_originators() {
        // D advertises the prefix but is unreachable (no links to it):
        // no mapping. E is reachable but advertised no SRGB: skipped.
        // F's SID index falls outside its SRGB: discarded (§8.1).
        let mut lsdb = Lsdb::new();
        lsdb.install(
            originate_sr_ri_lsa(0x04040404, 16_000, 8_000, None).unwrap(),
            0,
        );
        lsdb.install(
            originate_sr_prefix_lsa(
                0x04040404,
                &advert([10, 50, 0, 0], 24, 100, true, sid_flags::NP),
                1,
                None,
            )
            .unwrap(),
            0,
        );
        lsdb.install(
            originate_sr_prefix_lsa(
                0x05050505,
                &advert([10, 50, 0, 0], 24, 100, true, sid_flags::NP),
                2,
                None,
            )
            .unwrap(),
            0,
        );
        lsdb.install(
            originate_sr_ri_lsa(0x06060606, 16_000, 100, None).unwrap(),
            0,
        );
        lsdb.install(
            originate_sr_prefix_lsa(
                0x06060606,
                &advert([10, 50, 0, 0], 24, 200, true, sid_flags::NP),
                3,
                None,
            )
            .unwrap(),
            0,
        );
        // us —10— E (0x05050505), us —10— F (0x06060606); D unreachable.
        lsdb.install(
            crate::spf::tests_util::router_lsa(
                0x01010101,
                vec![
                    (0x05050505, 0x0a000005, 1, 10),
                    (0x06060606, 0x0a000006, 1, 10),
                ],
            ),
            0,
        );
        lsdb.install(
            crate::spf::tests_util::router_lsa(0x05050505, vec![(0x01010101, 0x0a000005, 1, 10)]),
            0,
        );
        lsdb.install(
            crate::spf::tests_util::router_lsa(0x06060606, vec![(0x01010101, 0x0a000006, 1, 10)]),
            0,
        );
        let spf = crate::spf::run_spf(&lsdb, 0x01010101);
        let db = SrDatabase::from_lsdb(&lsdb);
        assert!(db.label_for(&prefix([10, 50, 0, 0], 24), &spf).is_none());
    }

    #[test]
    fn label_for_ignores_non_spf_algorithms() {
        // A prefix-SID for algorithm 1 (SR-TE) does not map through the
        // SPF path — only algorithm 0 mappings resolve.
        let mut lsdb = sr_db_with(
            0x02020202,
            Some((16_000, 8_000)),
            vec![SrPrefixAdvert {
                algorithm: 1,
                ..advert([10, 60, 0, 0], 24, 100, true, sid_flags::NP)
            }],
        );
        lsdb.install(
            crate::spf::tests_util::router_lsa(0x01010101, vec![(0x02020202, 0, 1, 10)]),
            0,
        );
        lsdb.install(
            crate::spf::tests_util::router_lsa(0x02020202, vec![(0x01010101, 0x0a000001, 1, 10)]),
            0,
        );
        let spf = crate::spf::run_spf(&lsdb, 0x01010101);
        let db = SrDatabase::from_lsdb(&lsdb);
        assert!(db.label_for(&prefix([10, 60, 0, 0], 24), &spf).is_none());
    }

    // -------------------------------------------------------------
    // RFC 8665 §6: adjacency segments from Extended Link LSAs
    // -------------------------------------------------------------

    use crate::lsa::sr::{adj_flags, originate_sr_link_lsa, SrAdjSidTlv, SrLinkAdvert};

    fn link_lsa(rid: u32, idx: u32, sids: &[(SrLinkAdvert, Vec<SrAdjSidTlv>)]) -> Lsa {
        originate_sr_link_lsa(rid, sids, idx, None).unwrap()
    }

    fn put(lsdb: &mut Lsdb, lsa: Lsa) {
        lsdb.install(lsa, 0);
    }

    #[test]
    fn from_lsdb_projects_adjacency_segments() {
        let mut lsdb = Lsdb::new();
        put(
            &mut lsdb,
            link_lsa(
                0x02020202,
                1,
                &[(
                    SrLinkAdvert {
                        link_type: crate::lsa::sr::link_type::POINT_TO_POINT,
                        link_id: [1, 1, 1, 1],
                        link_data: [10, 0, 0, 2],
                    },
                    vec![SrAdjSidTlv {
                        flags: adj_flags::V | adj_flags::L | adj_flags::P,
                        mt_id: 0,
                        weight: 0,
                        sid: 24_001,
                        neighbor_id: None,
                    }],
                )],
            ),
        );
        let db = SrDatabase::from_lsdb(&lsdb);
        let segments = db.links.get(&0x02020202).expect("segments");
        assert_eq!(segments.len(), 1);
        let s = &segments[0];
        assert_eq!(s.link_type, crate::lsa::sr::link_type::POINT_TO_POINT);
        assert_eq!(s.link_id, [1, 1, 1, 1]);
        assert_eq!(s.link_data, [10, 0, 0, 2]);
        assert_eq!(s.sid.sid, 24_001);
        assert!(!s.sid.is_lan());
    }

    #[test]
    fn adjacency_segment_labels_resolve_local_and_global() {
        // Local (V/L) adjacency SID: the SID is the label. Global
        // (V/L clear): index into the advertising router's SRGB.
        let mut lsdb = Lsdb::new();
        lsdb.install(
            originate_sr_ri_lsa(0x02020202, 16_000, 8_000, None).unwrap(),
            0,
        );
        put(
            &mut lsdb,
            link_lsa(
                0x02020202,
                1,
                &[
                    (
                        SrLinkAdvert {
                            link_type: crate::lsa::sr::link_type::POINT_TO_POINT,
                            link_id: [1, 1, 1, 1],
                            link_data: [10, 0, 0, 2],
                        },
                        vec![SrAdjSidTlv {
                            flags: adj_flags::V | adj_flags::L,
                            mt_id: 0,
                            weight: 0,
                            sid: 24_001,
                            neighbor_id: None,
                        }],
                    ),
                    (
                        SrLinkAdvert {
                            link_type: crate::lsa::sr::link_type::POINT_TO_POINT,
                            link_id: [3, 3, 3, 3],
                            link_data: [10, 0, 1, 2],
                        },
                        vec![SrAdjSidTlv {
                            flags: adj_flags::P,
                            mt_id: 0,
                            weight: 0,
                            sid: 100,
                            neighbor_id: None,
                        }],
                    ),
                ],
            ),
        );
        let db = SrDatabase::from_lsdb(&lsdb);
        let segments = db.links.get(&0x02020202).expect("segments");
        let srgb = db.srgbs.get(&0x02020202).unwrap();
        assert_eq!(segments[0].sid.remote_label(srgb), Some(24_001));
        assert_eq!(segments[1].sid.remote_label(srgb), Some(16_100));
    }

    // -------------------------------------------------------------
    // RFC 8665 §4: mapping-server ranges
    // -------------------------------------------------------------

    use crate::lsa::sr::{originate_sr_prefix_range_lsa, SrPrefixRangeCore, TLV_EXT_PREFIX_RANGE};

    fn range_lsa(rid: u32, range: &SrPrefixRangeCore, sid: &SrPrefixSidTlv, idx: u32) -> Lsa {
        originate_sr_prefix_range_lsa(rid, range, sid, idx, None).unwrap()
    }

    #[test]
    fn range_index_arithmetic_maps_prefixes_inside_the_span() {
        let range = SrRangeMapping {
            advertising_router: 0x0d0d0d0d,
            range: SrPrefixRangeCore {
                prefix_len: 24,
                range_size: 4,
                flags: 0,
                prefix: [10, 77, 0, 0],
            },
            sid: SrPrefixSidTlv {
                flags: sid_flags::M | sid_flags::NP,
                mt_id: 0,
                algorithm: 0,
                sid: 500,
            },
        };
        // First prefix carries the advertised index; later prefixes
        // shift by their offset (RFC 8665 §4 example 2: consecutive
        // /24s differ by one /24 step).
        assert_eq!(range.index_for(&prefix([10, 77, 0, 0], 24)), Some(500));
        assert_eq!(range.index_for(&prefix([10, 77, 1, 0], 24)), Some(501));
        assert_eq!(range.index_for(&prefix([10, 77, 3, 0], 24)), Some(503));
        // Outside the covered span (or a different length): no index.
        assert_eq!(range.index_for(&prefix([10, 77, 4, 0], 24)), None);
        assert_eq!(range.index_for(&prefix([10, 76, 0, 0], 24)), None);
        assert_eq!(range.index_for(&prefix([10, 77, 0, 0], 32)), None);
    }

    #[test]
    fn from_lsdb_projects_mapping_server_ranges() {
        let mut lsdb = Lsdb::new();
        put(
            &mut lsdb,
            range_lsa(
                0x0d0d0d0d,
                &SrPrefixRangeCore {
                    prefix_len: 24,
                    range_size: 4,
                    flags: 0,
                    prefix: [10, 77, 0, 0],
                },
                &SrPrefixSidTlv {
                    flags: sid_flags::M | sid_flags::NP,
                    mt_id: 0,
                    algorithm: 0,
                    sid: 500,
                },
                1,
            ),
        );
        let db = SrDatabase::from_lsdb(&lsdb);
        assert_eq!(db.prefix_ranges.len(), 1);
        assert_eq!(db.prefix_ranges[0].advertising_router, 0x0d0d0d0d);
        assert_eq!(db.prefix_ranges[0].range.range_size, 4);
        assert_eq!(db.prefix_ranges[0].sid.sid, 500);
        // Range TLVs never leak into the direct prefix table.
        assert!(db.prefixes.is_empty());
    }

    #[test]
    fn mapping_label_resolves_via_the_closest_server() {
        // us —10— M1 (0x02020202) —10— M2 (0x05050505). M1 maps
        // 10.77.0.0/24 to index 100, M2 (further away) maps the same
        // prefix to index 900: the closer server wins.
        let mut lsdb = Lsdb::new();
        lsdb.install(
            originate_sr_ri_lsa(0x02020202, 16_000, 8_000, None).unwrap(),
            0,
        );
        lsdb.install(
            originate_sr_ri_lsa(0x05050505, 16_000, 8_000, None).unwrap(),
            0,
        );
        let range = SrPrefixRangeCore {
            prefix_len: 24,
            range_size: 1,
            flags: 0,
            prefix: [10, 77, 0, 0],
        };
        put(
            &mut lsdb,
            range_lsa(
                0x02020202,
                &range,
                &SrPrefixSidTlv {
                    flags: sid_flags::M | sid_flags::NP,
                    mt_id: 0,
                    algorithm: 0,
                    sid: 100,
                },
                1,
            ),
        );
        put(
            &mut lsdb,
            range_lsa(
                0x05050505,
                &range,
                &SrPrefixSidTlv {
                    flags: sid_flags::M | sid_flags::NP,
                    mt_id: 0,
                    algorithm: 0,
                    sid: 900,
                },
                2,
            ),
        );
        // us —10— M1, us —20— M2.
        lsdb.install(
            crate::spf::tests_util::router_lsa(
                0x01010101,
                vec![
                    (0x02020202, 0x0a000001, 1, 10),
                    (0x05050505, 0x0a000003, 1, 20),
                ],
            ),
            0,
        );
        lsdb.install(
            crate::spf::tests_util::router_lsa(0x02020202, vec![(0x01010101, 0x0a000001, 1, 10)]),
            0,
        );
        lsdb.install(
            crate::spf::tests_util::router_lsa(0x05050505, vec![(0x01010101, 0x0a000003, 1, 20)]),
            0,
        );
        let spf = crate::spf::run_spf(&lsdb, 0x01010101);
        let db = SrDatabase::from_lsdb(&lsdb);
        assert_eq!(
            db.mapping_label_for(&prefix([10, 77, 0, 0], 24), &spf),
            Some(16_100) // M1's SRGB base + index 100
        );

        // An unreachable server contributes nothing.
        let mut lsdb = Lsdb::new();
        lsdb.install(
            originate_sr_ri_lsa(0x07070707, 16_000, 8_000, None).unwrap(),
            0,
        );
        put(
            &mut lsdb,
            range_lsa(
                0x07070707,
                &range,
                &SrPrefixSidTlv {
                    flags: sid_flags::M,
                    mt_id: 0,
                    algorithm: 0,
                    sid: 100,
                },
                1,
            ),
        );
        let spf = crate::spf::run_spf(&lsdb, 0x01010101);
        let db = SrDatabase::from_lsdb(&lsdb);
        assert!(db
            .mapping_label_for(&prefix([10, 77, 0, 0], 24), &spf)
            .is_none());
    }

    #[test]
    fn mapping_label_rejects_out_of_range_and_absolute_shapes() {
        let mut lsdb = Lsdb::new();
        // Server SRGB covers indexes 0..99; the range maps index 500.
        lsdb.install(
            originate_sr_ri_lsa(0x02020202, 16_000, 100, None).unwrap(),
            0,
        );
        lsdb.install(
            crate::spf::tests_util::router_lsa(0x01010101, vec![(0x02020202, 0, 1, 10)]),
            0,
        );
        lsdb.install(
            crate::spf::tests_util::router_lsa(0x02020202, vec![(0x01010101, 0x0a000001, 1, 10)]),
            0,
        );
        let range = SrPrefixRangeCore {
            prefix_len: 24,
            range_size: 1,
            flags: 0,
            prefix: [10, 77, 0, 0],
        };
        put(
            &mut lsdb,
            range_lsa(
                0x02020202,
                &range,
                &SrPrefixSidTlv {
                    flags: sid_flags::M | sid_flags::NP,
                    mt_id: 0,
                    algorithm: 0,
                    sid: 500,
                },
                1,
            ),
        );
        // Same range but V-flagged (absolute shape).
        put(
            &mut lsdb,
            range_lsa(
                0x02020202,
                &range,
                &SrPrefixSidTlv {
                    flags: sid_flags::M | sid_flags::V | sid_flags::L,
                    mt_id: 0,
                    algorithm: 0,
                    sid: 500,
                },
                2,
            ),
        );
        let spf = crate::spf::run_spf(&lsdb, 0x01010101);
        let db = SrDatabase::from_lsdb(&lsdb);
        // Index 500 falls outside the server's 100-wide SRGB.
        assert!(db
            .mapping_label_for(&prefix([10, 77, 0, 0], 24), &spf)
            .is_none());
    }

    #[test]
    fn range_tlv_type_is_ext_prefix_range() {
        // The mapping-server TLV rides the Extended Prefix LSA as
        // top-level type 2 (RFC 8665 §4 / RFC 7684 §2.2).
        assert_eq!(TLV_EXT_PREFIX_RANGE, 2);
    }
}
