//! Per-node SRv6 database projected from the OSPFv3 area LSDB — the
//! receiving half of RFC 9513 (the codecs and the origination helpers
//! live in [`crate::lsa::srv6`]).
//!
//! Two LSA families feed it:
//!
//! - **Router Information LSAs** (RFC 7770 §2.2, function code 12,
//!   any flooding scope — area scope is the RFC 9513 §2 requirement):
//!   the SRv6 Capabilities TLV (§2), the SR-Algorithm TLV (§3, the
//!   RFC 8665 TLV) and the Node MSD TLV (§4, RFC 8476). A node whose
//!   RI LSA carries no SRv6 Capabilities TLV is not an SRv6 node and
//!   contributes nothing.
//! - **SRv6 Locator LSAs** (§7, function code 42): the locators with
//!   their End SIDs, gated per §5/§7.1/§8:
//!   - route types outside 1-6 and locator lengths outside 1-128 make
//!     the TLV ignored (handled by the codec);
//!   - a locator metric of 0xFFFFFFFF is unreachable (§7.1);
//!   - an End SID MUST be allocated from its associated locator —
//!     SIDs outside the covering prefix are ignored (§8);
//!   - End SIDs with behaviors outside the §11 Table 1 End-SID set
//!     are ignored ("unsupported or unrecognized behavior values");
//!   - duplicate advertisements resolve by the §2/§7.1 preference:
//!     the area-scoped LSA wins across flooding scopes, then the
//!     numerically smallest Link State ID, then the first occurrence
//!     within an LSA.
//!
//! The database is a pure LSDB projection: it needs no SPF state and
//! no clock. The locator *routes* (SPF distance to the advertising
//! router, algorithm gating against the receiver's own support) are
//! computed in [`crate::spf::run_spf_v3`] and merged by the router.

use std::collections::BTreeMap;

use lr_core::addr::Prefix;

use crate::lsa::srv6::{
    behavior_valid_for_end_sid, decode_v3_srv6_ri, Srv6LocatorLsaBody, Srv6LocatorTlv, Srv6RiBlock,
    Srv6SidStructure,
};
use crate::lsdb::Lsdb;

/// OSPFv3 LSA function code of the Router Information LSA (RFC 7770
/// §2.2). LSAs are matched by the low 13 bits of the 16-bit type so
/// every flooding scope (link 0x800C, area 0xA00C, AS 0xC00C) feeds
/// the projection; the §2 preference resolves the winner.
const RI_FUNC_CODE: u16 = 0x000C;
/// OSPFv3 LSA function code of the SRv6 Locator LSA (RFC 9513 §7).
const LOCATOR_FUNC_CODE: u16 = 0x002A;

/// Flooding-scope rank for the §2/§7.1 preference: area-scoped
/// advertisements beat link- and AS-scoped ones; the LS ID breaks
/// ties within a scope.
fn scope_rank(ls_type: u16) -> u8 {
    // S1S2 (bits 14-13): 01 = area, 00 = link, 10 = AS.
    match ls_type & 0x6000 {
        0x2000 => 0, // area — preferred
        0x0000 => 1, // link
        _ => 2,      // AS (0x4000) or anything odd
    }
}

/// One SRv6 End SID of a node (RFC 9513 §8).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Srv6EndSid {
    /// RFC 8986 endpoint behavior code point. Only values valid for
    /// End SIDs (RFC 9513 §11 Table 1) survive the projection.
    pub behavior: u16,
    /// The 128-bit SID, network byte order.
    pub sid: [u8; 16],
    /// The §10 SID Structure when advertised.
    pub structure: Option<Srv6SidStructure>,
}

/// One locator of a node (RFC 9513 §7.1) with the End SIDs allocated
/// from it (§8).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Srv6Locator {
    /// [`crate::lsa::srv6::locator_route_type`] value (1-6).
    pub route_type: u8,
    /// The IGP algorithm the locator is bound to (0 = SPF).
    pub algorithm: u8,
    /// RFC 5340 §A.4.1 prefix options, incl. the §6 AC-bit (anycast).
    pub options: u8,
    /// The advertised metric; 0xFFFFFFFF means unreachable (§7.1).
    pub metric: u32,
    /// The locator prefix, host bits zeroed.
    pub prefix: Prefix,
    /// The End SIDs under this locator, deduplicated (first wins) and
    /// gated on §8 containment + §11 behavior validity, in wire order.
    pub end_sids: Vec<Srv6EndSid>,
}

impl Srv6Locator {
    /// §7.1: a metric of 0xFFFFFFFF marks the locator unreachable.
    pub fn is_unreachable(&self) -> bool {
        self.metric == u32::MAX
    }

    /// §8: whether `sid` is allocated from this locator — the SID's
    /// top `self.prefix.prefix_len` bits must equal the locator's.
    pub fn contains(&self, sid: &[u8; 16]) -> bool {
        contains_prefix(sid, &self.prefix)
    }
}

/// Whether `addr`'s top `prefix.prefix_len` bits equal the prefix's
/// (a /0 covers everything).
fn contains_prefix(addr: &[u8; 16], prefix: &Prefix) -> bool {
    let Prefix {
        addr: lr_core::addr::IpAddr::V6(p),
        prefix_len,
    } = prefix
    else {
        return false;
    };
    let len = (*prefix_len).min(128) as usize;
    let full = len / 8;
    if addr[..full] != p[..full] {
        return false;
    }
    let rem = len % 8;
    if rem == 0 {
        return true;
    }
    let mask = !0u8 << (8 - rem);
    addr[full] & mask == p[full] & mask
}

/// The SRv6 view of one advertising router (RFC 9513 §2-§8): its
/// capabilities, algorithms and MSDs from the Router Information LSA,
/// plus the locators and End SIDs from the Locator LSAs.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Srv6Node {
    /// The §2 SRv6 Capabilities TLV flags. `None` when the node's
    /// Router Information LSAs carry no capabilities TLV — the node
    /// is not SRv6-capable and its locators still project (they are
    /// flooded by the LSA, not by the capability), but a consumer can
    /// gate on this to mirror "SRv6-enabled router" semantics.
    pub capabilities: Option<u16>,
    /// The §3 SR-Algorithm TLV values (RFC 8665 §3.1), first
    /// advertisement wins.
    pub algorithms: Vec<u8>,
    /// The §4 Node MSD TLV pairs (RFC 8476 §2), first advertisement
    /// wins.
    pub msds: Vec<(u8, u8)>,
    /// The locators (§7), deduplicated per prefix by the §7.1
    /// preference, in (preference, wire) order.
    pub locators: Vec<Srv6Locator>,
}

impl Srv6Node {
    /// Whether the node advertises the SRv6 Capabilities TLV (§2 —
    /// "MUST be advertised by an SRv6-enabled router").
    pub fn is_srv6_enabled(&self) -> bool {
        self.capabilities.is_some()
    }

    /// The End SIDs whose behavior the §11 Table 1 End-SID set allows,
    /// flat across the locators.
    pub fn end_sids(&self) -> impl Iterator<Item = (&Srv6Locator, &Srv6EndSid)> {
        self.locators
            .iter()
            .flat_map(|l| l.end_sids.iter().map(move |s| (l, s)))
    }
}

/// The per-node SRv6 database of one area (RFC 9513 reception).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Srv6Database {
    /// Advertising router → its SRv6 view. Routers with neither an
    /// RI SRv6 block nor a locator LSA do not appear.
    pub nodes: BTreeMap<u32, Srv6Node>,
}

impl Srv6Database {
    /// Project the area LSDB. Pure: reads the database, applies the
    /// §2/§7.1 preference rules and the §5/§8/§11 gates.
    pub fn from_lsdb(lsdb: &Lsdb) -> Self {
        // Collect the raw advertisements per router, ordered so the
        // preference rules become first-wins: area scope before link
        // before AS, then ascending LS ID. (The LSDB iterates by
        // (type, ls_id, router) — group and re-sort per router.)
        let mut ri_blocks: BTreeMap<u32, Vec<(u8, u32, Srv6RiBlock)>> = BTreeMap::new();
        let mut locator_tlvs: BTreeMap<u32, Vec<(u8, u32, Vec<Srv6LocatorTlv>)>> = BTreeMap::new();
        for (key, entry) in lsdb.iter() {
            match key.ls_type & 0x1FFF {
                RI_FUNC_CODE => {
                    if let Some(block) = decode_v3_srv6_ri(&entry.lsa.body) {
                        ri_blocks.entry(key.advertising_router).or_default().push((
                            scope_rank(key.ls_type),
                            key.link_state_id,
                            block,
                        ));
                    }
                }
                LOCATOR_FUNC_CODE => {
                    if let Some(body) = Srv6LocatorLsaBody::decode(&entry.lsa.body) {
                        locator_tlvs
                            .entry(key.advertising_router)
                            .or_default()
                            .push((scope_rank(key.ls_type), key.link_state_id, body.locators));
                    }
                }
                _ => {}
            }
        }

        let mut nodes = BTreeMap::new();
        let mut router_ids: Vec<u32> = ri_blocks.keys().copied().collect();
        for rid in locator_tlvs.keys().copied() {
            if !router_ids.contains(&rid) {
                router_ids.push(rid);
            }
        }
        for rid in router_ids {
            let mut node = Srv6Node::default();

            // §2: capabilities from the preferred LSA; §3/§4 the same
            // first-preference pattern for the SR-Algorithm and Node
            // MSD TLVs (RFC 8476 §2: "the receiver MUST use the first
            // occurrence").
            if let Some(blocks) = ri_blocks.get_mut(&rid) {
                blocks.sort_by_key(|a| (a.0, a.1));
                for (_, _, block) in blocks.iter() {
                    if node.capabilities.is_none() {
                        node.capabilities = block.capabilities;
                    }
                    if node.algorithms.is_empty() && !block.algorithms.is_empty() {
                        node.algorithms = block.algorithms.clone();
                    }
                    if node.msds.is_empty() && !block.msds.is_empty() {
                        node.msds = block.msds.clone();
                    }
                }
            }

            // §7.1: dedupe locators per prefix under the same
            // preference; within one LSA the first TLV for a locator
            // wins.
            if let Some(candidates) = locator_tlvs.get_mut(&rid) {
                candidates.sort_by_key(|a| (a.0, a.1));
                let mut seen: Vec<Prefix> = Vec::new();
                for (_, _, tlvs) in candidates.iter() {
                    for tlv in tlvs.iter() {
                        let prefix = mask_prefix(&tlv.prefix, tlv.locator_len);
                        if seen.contains(&prefix) {
                            continue;
                        }
                        seen.push(prefix);
                        node.locators.push(project_locator(tlv));
                    }
                }
            }

            if node.capabilities.is_some() || !node.locators.is_empty() {
                nodes.insert(rid, node);
            }
        }
        Self { nodes }
    }

    /// The SRv6 view of one router.
    pub fn node(&self, router_id: u32) -> Option<&Srv6Node> {
        self.nodes.get(&router_id)
    }
}

/// Zero the host bits of a locator advertisement (§A.4.1 leaves the
/// trailing words implicit; a non-zero host nibble would break the
/// §8 containment checks).
fn mask_prefix(addr: &[u8; 16], prefix_len: u8) -> Prefix {
    let len = (prefix_len as usize).min(128);
    let mut out = *addr;
    let full = len / 8;
    if full < 16 {
        out[full..].fill(0);
    }
    let rem = len % 8;
    if rem != 0 && full < 16 {
        let mask = !0u8 << (8 - rem);
        out[full] &= mask;
    }
    Prefix::new_v6(out, prefix_len)
}

/// Project one Locator TLV into a [`Srv6Locator`]: gate the End SIDs
/// on §8 containment and §11 behavior validity, dedupe per SID value
/// (first occurrence wins).
fn project_locator(tlv: &Srv6LocatorTlv) -> Srv6Locator {
    let prefix = mask_prefix(&tlv.prefix, tlv.locator_len);
    let mut end_sids = Vec::new();
    let mut seen: Vec<[u8; 16]> = Vec::new();
    for sid in &tlv.end_sids {
        if !behavior_valid_for_end_sid(sid.behavior) {
            // §11: unsupported or unrecognized behavior values are
            // ignored by the receiver.
            continue;
        }
        if !contains_prefix(&sid.sid, &prefix) {
            // §8: a SID not allocated from the associated locator is
            // ignored.
            continue;
        }
        if seen.contains(&sid.sid) {
            continue;
        }
        seen.push(sid.sid);
        end_sids.push(Srv6EndSid {
            behavior: sid.behavior,
            sid: sid.sid,
            structure: sid.structure,
        });
    }
    Srv6Locator {
        route_type: tlv.route_type,
        algorithm: tlv.algorithm,
        options: tlv.options,
        metric: tlv.metric,
        prefix,
        end_sids,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lsa::srv6::{
        locator_route_type, msd_type, originate_v3_srv6_locator_lsa, originate_v3_srv6_ri_lsa,
        LS_TYPE_SRV6_LOCATOR, PREFIX_OPT_AC, SRV6_CAP_O_FLAG,
    };
    use crate::lsdb::Lsdb;

    /// A /64 locator 2001:db8:1::/48 (kept /48 to leave room for the
    /// function part) with one End SID and one SID outside the
    /// locator; the latter is dropped by §8.
    fn locator_tlv(sids: &[[u8; 16]], behavior: u16) -> Srv6LocatorTlv {
        Srv6LocatorTlv {
            route_type: locator_route_type::INTRA_AREA,
            algorithm: 0,
            locator_len: 48,
            options: 0,
            metric: 0,
            prefix: [
                0x20, 0x01, 0x0d, 0xb8, 0x00, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            ],
            end_sids: sids
                .iter()
                .map(|s| crate::lsa::srv6::Srv6EndSidSubTlv {
                    flags: 0,
                    behavior,
                    sid: *s,
                    structure: None,
                })
                .collect(),
            fwd_addr: None,
            route_tag: None,
        }
    }

    fn sid_in_locator() -> [u8; 16] {
        let mut s = [0u8; 16];
        s[..6].copy_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0x00, 0x01]);
        s[15] = 1;
        s
    }

    fn sid_outside_locator() -> [u8; 16] {
        let mut s = [0u8; 16];
        s[..6].copy_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0x00, 0x09]);
        s[15] = 2;
        s
    }

    #[test]
    fn projects_ri_and_locator_lsas_into_a_node_view() {
        let mut db = Lsdb::new();
        let rid = 0x0a00_0001;
        db.install(
            originate_v3_srv6_ri_lsa(
                rid,
                SRV6_CAP_O_FLAG,
                &[0],
                &[(msd_type::SRH_MAX_SL, 8)],
                None,
            )
            .unwrap(),
            0,
        );
        let in_sid = sid_in_locator();
        db.install(
            originate_v3_srv6_locator_lsa(rid, 0, &[locator_tlv(&[in_sid], 1)], None).unwrap(),
            0,
        );

        let srv6 = Srv6Database::from_lsdb(&db);
        let node = srv6.node(rid).unwrap();
        assert_eq!(node.capabilities, Some(SRV6_CAP_O_FLAG));
        assert!(node.is_srv6_enabled());
        assert_eq!(node.algorithms, vec![0]);
        assert_eq!(node.msds, vec![(msd_type::SRH_MAX_SL, 8)]);
        assert_eq!(node.locators.len(), 1);
        let loc = &node.locators[0];
        assert_eq!(loc.route_type, locator_route_type::INTRA_AREA);
        assert_eq!(loc.algorithm, 0);
        assert_eq!(
            loc.prefix,
            Prefix::new_v6(
                [0x20, 0x01, 0x0d, 0xb8, 0x00, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                48,
            )
        );
        assert_eq!(loc.end_sids.len(), 1);
        assert_eq!(loc.end_sids[0].behavior, 1);
        assert_eq!(loc.end_sids[0].sid, in_sid);
        assert!(!loc.is_unreachable());
    }

    /// §8: SIDs outside the covering locator are ignored; §11:
    /// behaviors outside the End-SID set (here End.X 5) are ignored.
    #[test]
    fn gates_end_sids_on_containment_and_behavior() {
        let mut db = Lsdb::new();
        let rid = 0x0a00_0001;
        let in_sid = sid_in_locator();
        let outside = sid_outside_locator();
        db.install(
            originate_v3_srv6_locator_lsa(
                rid,
                0,
                &[locator_tlv(&[in_sid, outside, in_sid], 5)],
                None,
            )
            .unwrap(),
            0,
        );
        let srv6 = Srv6Database::from_lsdb(&db);
        let node = srv6.node(rid).unwrap();
        // The End.X behavior 5 is not valid for an End SID (§11), and
        // the outside SID fails the §8 containment — nothing survives,
        // while the locator itself still projects.
        assert!(node.locators[0].end_sids.is_empty());

        // A valid behavior keeps the inside SID and drops the outside
        // one; the duplicate inside SID is deduplicated (first wins).
        let mut db = Lsdb::new();
        db.install(
            originate_v3_srv6_locator_lsa(
                rid,
                0,
                &[locator_tlv(&[in_sid, outside, in_sid], 1)],
                None,
            )
            .unwrap(),
            0,
        );
        let srv6 = Srv6Database::from_lsdb(&db);
        let sids = &srv6.node(rid).unwrap().locators[0].end_sids;
        assert_eq!(sids.len(), 1);
        assert_eq!(sids[0].sid, in_sid);
    }

    /// §7.1: an area-scoped locator beats a link-scoped duplicate, and
    /// the smallest LS ID wins within one scope. The winner is told by
    /// its metric (the prefix is identical).
    #[test]
    fn locator_preference_area_scope_then_smallest_ls_id() {
        let rid = 0x0a00_0001;
        let mk = |ls_type: u16, ls_id: u32, metric: u32| {
            let mut prefix = [0u8; 16];
            prefix[..6].copy_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0x00, 0x01]);
            let tlv = Srv6LocatorTlv {
                route_type: locator_route_type::INTRA_AREA,
                algorithm: 0,
                locator_len: 48,
                options: PREFIX_OPT_AC,
                metric,
                prefix,
                end_sids: vec![],
                fwd_addr: None,
                route_tag: None,
            };
            let mut lsa = crate::lsa::srv6::originate_v3_srv6_locator_lsa(
                rid,
                ls_id,
                std::slice::from_ref(&tlv),
                None,
            )
            .unwrap();
            lsa.header.ls_type = ls_type;
            lsa.finalize();
            lsa
        };
        let mut db = Lsdb::new();
        // AS-scoped (metric 9) vs area-scoped LS ID 9 (metric 2) vs
        // area-scoped LS ID 3 (metric 3): area wins, then LS ID 3.
        db.install(mk(0xC02A, 0, 9), 0);
        db.install(mk(0xA02A, 9, 2), 0);
        db.install(mk(0xA02A, 3, 3), 0);

        let srv6 = Srv6Database::from_lsdb(&db);
        let node = srv6.node(rid).unwrap();
        assert_eq!(node.locators.len(), 1);
        assert_eq!(node.locators[0].metric, 3);
    }

    /// §7.1: the same locator repeated in one LSA keeps the first TLV.
    #[test]
    fn duplicate_locator_in_one_lsa_keeps_first() {
        let rid = 0x0a00_0001;
        let mut a = locator_tlv(&[], 1);
        a.metric = 10;
        let mut b = locator_tlv(&[], 1);
        b.metric = 99; // same prefix, different attribute
        let mut db = Lsdb::new();
        db.install(
            originate_v3_srv6_locator_lsa(rid, 0, &[a, b], None).unwrap(),
            0,
        );
        let srv6 = Srv6Database::from_lsdb(&db);
        assert_eq!(srv6.node(rid).unwrap().locators[0].metric, 10);
    }

    /// §7.1: a 0xFFFFFFFF metric is unreachable; a router with neither
    /// an SRv6 RI block nor locators does not appear in the database.
    #[test]
    fn unreachable_metric_and_silent_routers() {
        let mut db = Lsdb::new();
        let rid = 0x0a00_0001;
        let mut tlv = locator_tlv(&[], 1);
        tlv.metric = u32::MAX;
        db.install(
            originate_v3_srv6_locator_lsa(rid, 0, std::slice::from_ref(&tlv), None).unwrap(),
            0,
        );
        let srv6 = Srv6Database::from_lsdb(&db);
        assert!(srv6.node(rid).unwrap().locators[0].is_unreachable());
        // A plain OSPFv3 LSA never lands in the SRv6 view.
        db.install(
            crate::lsa::Lsa {
                header: crate::lsa::LsaHeader {
                    ls_age: 0,
                    options: 0,
                    ls_type: crate::lsa::v3::LS_TYPE_ROUTER,
                    link_state_id: 0,
                    advertising_router: 0x0b00_0002,
                    ls_sequence_number: crate::abr::INITIAL_SEQUENCE_NUMBER,
                    ls_checksum: 0,
                    length: 0,
                },
                body: vec![0u8; 4],
            },
            0,
        );
        let srv6 = Srv6Database::from_lsdb(&db);
        assert!(srv6.node(0x0b00_0002).is_none());
    }

    /// The containment helper: bit-exact on the partial byte, /0
    /// covers everything, and an IPv4 prefix never contains an SRv6
    /// SID.
    #[test]
    fn containment_bit_arithmetic() {
        let mut p48 = [0u8; 16];
        p48[..6].copy_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0x00, 0x01]);
        let prefix = Prefix::new_v6(p48, 48);
        let mut inside = sid_in_locator();
        assert!(contains_prefix(&inside, &prefix));
        inside[5] ^= 0x01; // differ within the /48
        assert!(!contains_prefix(&inside, &prefix));

        let mut p50 = p48;
        p50[6] = 0xc0; // bits 48-49 = 11
        let prefix50 = Prefix::new_v6(p50, 50);
        let mut near = p48;
        near[6] = 0x40; // bits 48-49 = 01 — differs inside the /50
        assert!(!contains_prefix(&near, &prefix50));
        let mut hit = p48;
        hit[6] = 0xff; // bits 48-49 = 11 — same top two bits, rest ignored
        assert!(contains_prefix(&hit, &prefix50));

        let v4 = Prefix::new_v4([10, 0, 0, 0], 8);
        assert!(!contains_prefix(&sid_in_locator(), &v4));
    }

    /// A node advertising only the RI block (no locators yet) still
    /// projects with its capabilities; a locator with no End SIDs is
    /// retained (§8: the End SID advertisement is a SHOULD, not a
    /// MUST).
    #[test]
    fn ri_only_node_and_locator_without_end_sids() {
        let mut db = Lsdb::new();
        let rid = 0x0a00_0001;
        db.install(
            originate_v3_srv6_ri_lsa(rid, 0, &[0], &[], None).unwrap(),
            0,
        );
        let srv6 = Srv6Database::from_lsdb(&db);
        let node = srv6.node(rid).unwrap();
        assert_eq!(node.capabilities, Some(0));
        assert!(node.locators.is_empty());

        db.install(
            originate_v3_srv6_locator_lsa(rid, 0, &[locator_tlv(&[], 1)], None).unwrap(),
            0,
        );
        let srv6 = Srv6Database::from_lsdb(&db);
        assert_eq!(srv6.node(rid).unwrap().locators.len(), 1);
        assert!(srv6.node(rid).unwrap().locators[0].end_sids.is_empty());
    }

    /// The RFC 4970 capability-only RI LSA (no SRv6 Capabilities TLV)
    /// decodes to an empty block and yields a node-less database when
    /// nothing else is present.
    #[test]
    fn non_srv6_ri_lsa_is_inert() {
        let mut db = Lsdb::new();
        let rid = 0x0a00_0001;
        // A bare capabilities TLV (RFC 7770 §2.1, type 1) — the v3 RI
        // carrier parses, the SRv6 block stays empty.
        let body = [
            0x00, 0x01, 0x00, 0x04, 0x00, 0x00, 0x00, 0x09, // cap TLV
        ];
        db.install(
            crate::lsa::Lsa {
                header: crate::lsa::LsaHeader {
                    ls_age: 0,
                    options: 0,
                    ls_type: LS_TYPE_SRV6_LOCATOR & 0x6000 | RI_FUNC_CODE, // 0xA00C
                    link_state_id: 0,
                    advertising_router: rid,
                    ls_sequence_number: crate::abr::INITIAL_SEQUENCE_NUMBER,
                    ls_checksum: 0,
                    length: 0,
                },
                body: body.to_vec(),
            },
            0,
        );
        let srv6 = Srv6Database::from_lsdb(&db);
        assert!(srv6.node(rid).is_none());
    }

    /// §8 containment rides the *masked* prefix: a locator TLV whose
    /// host bits are non-zero (a sender bug) still contains SIDs under
    /// the network address.
    #[test]
    fn host_bits_are_masked_on_projection() {
        let mut tlv = locator_tlv(&[], 1);
        tlv.prefix[15] = 0x7f; // junk host bits on the wire
        let in_sid = sid_in_locator();
        tlv.end_sids.push(crate::lsa::srv6::Srv6EndSidSubTlv {
            flags: 0,
            behavior: 1,
            sid: in_sid,
            structure: None,
        });
        let loc = project_locator(&tlv);
        assert_eq!(loc.prefix.prefix_len, 48);
        assert!(loc.contains(&in_sid));
        assert_eq!(loc.end_sids.len(), 1);
    }
}
