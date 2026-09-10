//! Per-node Segment Routing database built from the area LSDB — the
//! receiving half of RFC 8667 (slice 1 shipped the codec and the
//! origination half).
//!
//! Two LSA families feed it:
//!
//! - **Router Information opaque LSAs** (RFC 4970 §2.3 / RFC 8667 §3,
//!   area-scoped, Opaque Type 4): the SRGB Descriptor TLV binds the
//!   advertising router to its Segment Routing Global Block. A node
//!   without an SRGB is not an SR node (RFC 8667 §8.1) and never
//!   contributes labels.
//! - **Extended Prefix opaque LSAs** (RFC 7684 §6 / RFC 8667 §6,
//!   area-scoped, Opaque Type 7): one Extended Prefix TLV per
//!   advertised prefix, carrying the Prefix-SID sub-TLV with the SID
//!   index and flags.
//!
//! The label a receiving router derives for a prefix is the
//! originating node's SRGB base plus the SID index (RFC 8667 §6,
//! guarded per §8.1). Selecting among several candidate mappings for
//! one prefix needs SPF reachability data, so it lives with the caller
//! ([`crate::spf::SpfResult`] consumers); this module keeps the
//! database a pure LSDB projection.

use std::collections::BTreeMap;

use crate::lsa::sr::{
    decode_ext_prefix_lsa_body, decode_ri_sr_lsa_body, remote_label, sr_opaque_type, RiSrBlock,
    SrPrefixSidTlv, OPAQUE_TYPE_EXT_PREFIX, OPAQUE_TYPE_RI,
};
use crate::lsa::LsaTypeV2;
use crate::lsdb::Lsdb;
use lr_core::addr::Prefix;

/// One candidate Prefix-SID mapping for a prefix (RFC 8667 §6): who
/// advertised it and with which SID sub-TLV.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SrPrefixMapping {
    /// Advertising router of the Extended Prefix Opaque LSA.
    pub advertising_router: u32,
    /// RFC 7684 §6 route type (1 intra-area, 3 inter-area, 5 external,
    /// 7 NSSA).
    pub route_type: u8,
    /// RFC 7684 §6 N-flag: the prefix identifies the advertising node
    /// itself (an SR-Node / loopback).
    pub node: bool,
    /// The Prefix-SID sub-TLV (flags, MT-ID, algorithm, SID index).
    pub sid: SrPrefixSidTlv,
}

/// The per-node SR database of one area: every node's SRGB plus every
/// advertised Prefix-SID mapping, projected straight from the LSDB.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SrDatabase {
    /// Advertising router → its SRGB (from Router Information LSAs).
    /// A router absent here advertised no (MPLS) SRGB — not an SR node.
    pub srgbs: BTreeMap<u32, RiSrBlock>,
    /// Prefix → candidate Prefix-SID mappings (one per advertising
    /// router; several routers may advertise the same prefix, e.g. an
    /// anycast segment).
    pub prefixes: BTreeMap<Prefix, Vec<SrPrefixMapping>>,
}

impl SrDatabase {
    /// Project the SR content of an area LSDB into a database. Only
    /// area-scoped opaque LSAs (LS type 10) with the RI (4) and
    /// Extended Prefix (7) Opaque Types contribute; every other LSA is
    /// ignored. Malformed TLVs drop their own LSA, never the database.
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
                    if let Some(adverts) = decode_ext_prefix_lsa_body(&entry.lsa.body) {
                        for (core, sid) in adverts {
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
    /// RFC 8667 §5 PHP rule: when the winning Prefix-SID does not
    /// carry the NP flag and its advertising router is directly
    /// adjacent (one hop away), this router *is* the penultimate hop
    /// and pops instead of pushing — `None` is returned so the caller
    /// forwards unlabeled.
    ///
    /// `None` also when no SR node advertises the prefix, the winning
    /// SID's index falls outside its originator's SRGB (§8.1: the SID
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
                continue; // originator without an SRGB is not an SR node (§8.1)
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
}
