//! ABR summary-LSA origination (RFC 2328 §12.4.3).
//!
//! An area border router re-advertises reachability between the areas it
//! attaches to by originating type-3 summary-LSAs:
//!
//! - into the backbone: the intra-area networks of each non-backbone area;
//! - into a non-backbone area: the routes derived from the backbone
//!   (its intra-area networks plus the inter-area routes other ABRs
//!   summarized into it).
//!
//! This one-direction-via-backbone rule is what keeps inter-area paths
//! loop-free without virtual links (§16.2).
//!
//! All helpers target OSPFv2 LSA encodings (RFC 2328 §A.4.3 bodies,
//! 32-bit link-state IDs). OSPFv3 inter-area-prefix-LSAs use a different
//! body format and are not originated here.
//!
//! # Link-state ID collisions
//!
//! The link-state ID of a summary-LSA is the summarized network
//! address (RFC 2328 §A.4.3). Two prefixes whose network addresses
//! coincide with different lengths (e.g. `10.0.0.0/8` and
//! `10.0.0.0/16`) therefore compete for the same `(ls_type, ls_id,
//! advertising_router)` key — and the OSPF LSDB key collides on the
//! second LSA. RFC 2328 Appendix E specifies the resolution: keep the
//! network address for the less-specific LSA and remap the more-specific
//! one to its broadcast address (host bits all 1). See
//! [`summary_lsa_id_for`] for the algorithm and the limits of the
//! remapping.

use crate::lsa::{
    decode_summary_lsa_body, encode_summary_lsa_body, mask_to_prefix_len, prefix_len_to_mask, Lsa,
    LsaHeader, LsaTypeV2,
};
use lr_core::addr::Prefix;
use std::collections::BTreeMap;

/// RFC 2328 §12.1.2: the first sequence number of a newly originated LSA.
pub const INITIAL_SEQUENCE_NUMBER: u32 = 0x8000_0001;
/// RFC 2328 §12.1.2: the largest sequence number an LSA may carry.
pub const MAX_SEQUENCE_NUMBER: u32 = 0x7fff_ffff;

/// One destination an ABR summarizes into another area: a prefix and the
/// metric to advertise. The metric is capped just below LSInfinity
/// (`0x00ff_ffff`), which is reserved to mean "unreachable".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SummaryDestination {
    pub prefix: Prefix,
    pub metric: u32,
}

impl SummaryDestination {
    pub fn new(prefix: Prefix, metric: u32) -> Self {
        Self {
            prefix,
            metric: metric.min(0x00ff_fffe),
        }
    }
}

/// Compute the 32-bit Link State ID for a summary-LSA summarizing
/// `prefix`, applying the RFC 2328 Appendix E collision-remapping
/// algorithm when the network address collides with another
/// summary-LSA this router has originated (or is about to originate)
/// in the same area.
///
/// `existing` carries the `(LS-ID, prefix length)` pairs for every
/// summary-LSA that already occupies the LS-ID space for the area —
/// the new LSA's LS-ID must not collide with any of those, because
/// `(ls_type, ls_id, advertising_router)` is the LSDB key (RFC 2328
/// §12.1.6) and a collision silently overwrites the prior LSA.
///
/// # Algorithm (RFC 2328 Appendix E)
///
/// 1. Try the network address (network bits only) as the LS-ID.
/// 2. If the network address is taken by an LSA whose prefix length
///    *differs*, the two prefixes overlap. RFC 2328 Appendix E gives
///    the less-specific one the network address and remaps the
///    more-specific one to its broadcast address (host bits all 1):
///    `network | !mask`.
/// 3. If the network address collides with an LSA of the *same* prefix
///    length, this is a refresh of the same LSA — return the network
///    address (the caller overwrites in place).
/// 4. If both the network address and the broadcast address are
///    taken by *different* LSAs, the collision is unsolvable; return
///    `None`. RFC 2328 Appendix E notes this case has no automatic
///    resolution and the operator must use a single summary length for
///    the overlapping prefixes or stop redistributing one of them.
///
/// # Caller invariant: process less-specific prefixes first
///
/// The remap in step 2 assumes the less-specific LSA keeps the network
/// address. Callers MUST process prefixes in ascending prefix length
/// (less-specific first) so each new prefix's `existing` set already
/// contains the less-specific LSAs. Sorting the other way silently
/// keeps the network address on the wrong LSA and remaps the
/// less-specific one to a broadcast address that is no longer the
/// network's broadcast — see [`assign_summary_lsa_ids`] for a batch
/// helper that handles the ordering and the unsolvable case together.
///
/// Returns `None` for non-IPv4 prefixes (the v2 LS-ID is a 32-bit
/// IPv4 network) or when the collision is unsolvable.
pub fn summary_lsa_id_for(prefix: &Prefix, existing: &[(u32, u8)]) -> Option<u32> {
    let lr_core::addr::IpAddr::V4(octets) = prefix.addr else {
        return None; // v2 LS-IDs are 32-bit IPv4 networks.
    };
    let mask = prefix_len_to_mask(prefix.prefix_len);
    let network = u32::from_be_bytes(octets) & mask;

    // Step 1 + step 3: if no LSA with a *different* prefix length
    // occupies the network address, return it.
    let collides_with_diff_mask = existing
        .iter()
        .any(|(lsid, plen)| *lsid == network && *plen != prefix.prefix_len);
    if !collides_with_diff_mask {
        return Some(network);
    }

    // Step 2: remap the more-specific LSA to its broadcast address.
    let broadcast = network | !mask;
    if existing.iter().any(|(lsid, _)| *lsid == broadcast) {
        // Step 4: both candidates taken — unsolvable.
        return None;
    }
    Some(broadcast)
}

/// Assign unique Link State IDs to a batch of summary-LSA destinations,
/// applying the RFC 2328 Appendix E collision-remapping algorithm to
/// prefixes whose network addresses coincide with different lengths.
///
/// This is the batch form of [`summary_lsa_id_for`]: it processes the
/// destinations in ascending prefix length (less-specific first) so the
/// less-specific prefix keeps the network address and the more-specific
/// one is remapped to its broadcast address. `existing_lsas` carries the
/// router's already-installed summary-LSAs in the target area (LS-ID →
/// body), so refreshes keep their LS-ID and a new LSA cannot silently
/// overwrite a prior LSA that happens to share the same network address
/// but a different mask.
///
/// Returns one entry per input destination:
///
/// - `(dest, Some(ls_id))` — originate (or refresh) the LSA under this
///   LS-ID. `ls_id` is `None` for non-IPv4 destinations (v2 summary-LSAs
///   do not carry them) or when the LS-ID collides unsolvably with
///   another summary-LSA in the area (RFC 2328 Appendix E has no
///   automatic resolution for that case). In the `None` case the caller
///   MUST NOT install an LSA; the prior LSA, if any, stays in the LSDB
///   until the operator fixes the configuration.
///
/// The caller derives its `used_lsids` flush-set from the `Some(ls_id)`
/// entries — every existing LS-ID *not* in that set has disappeared and
/// should be flushed.
pub fn assign_summary_lsa_ids<'a, I>(
    destinations: I,
    existing_lsas: &BTreeMap<u32, Lsa>,
) -> Vec<(SummaryDestination, Option<u32>)>
where
    I: IntoIterator<Item = &'a SummaryDestination>,
{
    // Sort by ascending prefix length so the less-specific prefix
    // claims the network address first (RFC 2328 Appendix E).
    let mut sorted: Vec<&SummaryDestination> = destinations.into_iter().collect();
    sorted.sort_by_key(|d| d.prefix.prefix_len);

    // Seed the in-flight `used` set with the existing LSAs' (LS-ID,
    // prefix length) so a new LSA cannot silently overwrite a prior one
    // that happens to share the same network address but a different
    // mask.
    let mut used: Vec<(u32, u8)> = Vec::new();
    for (lsid, lsa) in existing_lsas {
        if let Some(body) = decode_summary_lsa_body(&lsa.body) {
            used.push((*lsid, mask_to_prefix_len(body.network_mask)));
        }
    }

    let mut out: Vec<(SummaryDestination, Option<u32>)> = Vec::with_capacity(sorted.len());
    for dest in sorted {
        let lr_core::addr::IpAddr::V4(_) = dest.prefix.addr else {
            // Non-IPv4 destinations are not originated as v2 summary-LSAs.
            continue;
        };
        let ls_id = summary_lsa_id_for(&dest.prefix, &used);
        if let Some(id) = ls_id {
            used.push((id, dest.prefix.prefix_len));
        }
        out.push((*dest, ls_id));
    }
    out
}

/// Originate a type-3 summary-LSA with an explicit Link State ID
/// (RFC 2328 §12.4.3 + Appendix E).
///
/// `link_state_id` is the 32-bit LS-ID the caller chose via
/// [`summary_lsa_id_for`] (or [`assign_summary_lsa_ids`]). The body's
/// `network_mask` field still carries the destination's mask so peers
/// can disambiguate colliding LS-IDs.
///
/// `prev_seq` carries the sequence number of the router's current
/// instance for this link-state ID (if any): the new LSA continues the
/// sequence space, otherwise it starts at `INITIAL_SEQUENCE_NUMBER`.
/// The returned LSA is finalized — length fixed, RFC 2328 §C.4 checksum
/// computed.
///
/// Returns `None` for non-IPv4 destinations (v3 bodies are not
/// originated here) or when the sequence space is exhausted (the caller
/// must flush the LSA and re-originate, §12.1.2).
pub fn originate_summary_lsa_with_id(
    router_id: u32,
    link_state_id: u32,
    dest: &SummaryDestination,
    prev_seq: Option<u32>,
) -> Option<Lsa> {
    if !matches!(dest.prefix.addr, lr_core::addr::IpAddr::V4(_)) {
        return None; // v2 link-state IDs are 32-bit IPv4 networks.
    }
    let seq = match prev_seq {
        None => INITIAL_SEQUENCE_NUMBER,
        Some(MAX_SEQUENCE_NUMBER) => return None,
        Some(p) => p + 1,
    };
    let mask = prefix_len_to_mask(dest.prefix.prefix_len);
    let body = encode_summary_lsa_body(mask, dest.metric);
    let mut lsa = Lsa {
        header: LsaHeader {
            ls_age: 0,
            options: 0x02,
            ls_type: LsaTypeV2::SummaryIpLsa as u16,
            link_state_id,
            advertising_router: router_id,
            ls_sequence_number: seq,
            ls_checksum: 0,
            length: 0,
        },
        body,
    };
    lsa.finalize();
    Some(lsa)
}

/// Originate a type-3 summary-LSA for `dest` (RFC 2328 §12.4.3).
///
/// `prev_seq` carries the sequence number of the router's current
/// instance for this link-state ID (if any): the new LSA continues the
/// sequence space, otherwise it starts at `INITIAL_SEQUENCE_NUMBER`.
/// The returned LSA is finalized — length fixed, RFC 2328 §C.4 checksum
/// computed.
///
/// This entry point uses the destination's network address (network
/// bits only) as the Link State ID. When the area may carry
/// overlapping summary prefixes (different lengths sharing the same
/// network address), the caller MUST instead compute the LS-ID via
/// [`summary_lsa_id_for`] (or [`assign_summary_lsa_ids`] for a batch)
/// and call [`originate_summary_lsa_with_id`]; otherwise the second
/// LSA overwrites the first under the same `(ls_type, ls_id, adv)`
/// LSDB key (RFC 2328 §12.1.6).
///
/// Returns `None` for non-IPv4 destinations (v3 bodies are not
/// originated) or when the sequence space is exhausted (the caller must
/// flush the LSA and re-originate, §12.1.2).
pub fn originate_summary_lsa(
    router_id: u32,
    dest: &SummaryDestination,
    prev_seq: Option<u32>,
) -> Option<Lsa> {
    let lr_core::addr::IpAddr::V4(octets) = dest.prefix.addr else {
        return None; // v2 link-state IDs are 32-bit IPv4 networks
    };
    let mask = prefix_len_to_mask(dest.prefix.prefix_len);
    let network = u32::from_be_bytes(octets) & mask;
    originate_summary_lsa_with_id(router_id, network, dest, prev_seq)
}

/// Build the MaxAge instance that flushes `existing` from all databases
/// (RFC 2328 §14.1: age the LSA to MaxAge and flood). The sequence number
/// advances so peers accept the flush as newer.
///
/// Returns `None` when the sequence number cannot advance (wrapped past
/// `MAX_SEQUENCE_NUMBER`).
pub fn flush_summary_lsa(existing: &Lsa) -> Option<Lsa> {
    existing.maxage_flush()
}

// ---------------------------------------------------------------------------
// OSPFv3 inter-area-prefix-LSA origination (RFC 5340 §A.4.5 / §4.4.3.1)
// ---------------------------------------------------------------------------

/// Originate an OSPFv3 inter-area-prefix-LSA (type 0x2003) for `dest`
/// (RFC 5340 §A.4.5). The ABR re-advertises reachability to a prefix
/// from one area into another, exactly like the v2 type-3 summary-LSA.
///
/// `ls_id` is the 32-bit link-state ID the ABR assigns to this LSA.
/// Unlike v2 (where the LS-ID is the network address), v3 uses an
/// arbitrary counter because the prefix is 128 bits wide. The caller is
/// responsible for tracking LS-ID → prefix mappings.
///
/// `prev_seq` carries the sequence number of the router's current
/// instance for this link-state ID (if any). The returned LSA is
/// finalized — length fixed, RFC 2328 §C.4 checksum computed.
///
/// Returns `None` when the sequence space is exhausted.
pub fn originate_v3_inter_area_prefix_lsa(
    router_id: u32,
    ls_id: u32,
    dest: &SummaryDestination,
    prev_seq: Option<u32>,
) -> Option<Lsa> {
    let seq = match prev_seq {
        None => INITIAL_SEQUENCE_NUMBER,
        Some(MAX_SEQUENCE_NUMBER) => return None,
        Some(p) => p + 1,
    };
    let body = crate::lsa::encode_v3_inter_area_prefix_body(&dest.prefix, dest.metric);
    let mut lsa = Lsa {
        header: LsaHeader {
            ls_age: 0,
            options: 0x00, // v3 LSA headers have no options field
            ls_type: LsaTypeV3::InterAreaPrefixLsa as u16, // full 0x2003
            link_state_id: ls_id,
            advertising_router: router_id,
            ls_sequence_number: seq,
            ls_checksum: 0,
            length: 0,
        },
        body,
    };
    lsa.finalize();
    Some(lsa)
}

use crate::lsa::LsaTypeV3;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lsa::decode_summary_lsa_body;
    use crate::lsdb::MAX_AGE_SECS;
    use lr_core::addr::IpAddr;

    fn net(a: u32, len: u8) -> Prefix {
        Prefix::new_v4(a.to_be_bytes(), len)
    }

    #[test]
    fn originate_first_instance() {
        let dest = SummaryDestination::new(net(0x0a0a0a00, 24), 10);
        let lsa = originate_summary_lsa(0x01020304, &dest, None).unwrap();
        assert_eq!(lsa.header.ls_type, LsaTypeV2::SummaryIpLsa as u16);
        assert_eq!(lsa.header.link_state_id, 0x0a0a0a00);
        assert_eq!(lsa.header.advertising_router, 0x01020304);
        assert_eq!(lsa.header.ls_sequence_number, INITIAL_SEQUENCE_NUMBER);
        assert_eq!(lsa.header.ls_age, 0);
        assert_eq!(lsa.header.length, 28); // 20 header + 8 body
        let body = decode_summary_lsa_body(&lsa.body).unwrap();
        assert_eq!(body.network_mask, 0xffff_ff00);
        assert_eq!(body.tos0_metric(), Some(10));
        assert!(
            lsa.checksum_ok(),
            "originated LSA must carry a valid checksum"
        );
    }

    #[test]
    fn originate_continues_sequence() {
        let dest = SummaryDestination::new(net(0x0a0a0a00, 24), 20);
        let lsa = originate_summary_lsa(1, &dest, Some(0x80000005)).unwrap();
        assert_eq!(lsa.header.ls_sequence_number, 0x80000006);
        assert!(lsa.checksum_ok());
    }

    #[test]
    fn originate_masks_host_bits() {
        // Host bits must be zero in the link-state ID.
        let dest = SummaryDestination::new(net(0x0a0a0aff, 24), 5);
        let lsa = originate_summary_lsa(1, &dest, None).unwrap();
        assert_eq!(lsa.header.link_state_id, 0x0a0a0a00);
    }

    #[test]
    fn originate_rejects_v6_and_max_sequence() {
        let v6 = Prefix::new_v6([0x20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1], 64);
        assert!(originate_summary_lsa(1, &SummaryDestination::new(v6, 5), None).is_none());
        assert!(originate_summary_lsa(
            1,
            &SummaryDestination::new(net(1, 32), 5),
            Some(MAX_SEQUENCE_NUMBER)
        )
        .is_none());
    }

    #[test]
    fn metric_capped_below_ls_infinity() {
        let dest = SummaryDestination::new(net(1, 32), 0xffff_ffff);
        assert_eq!(dest.metric, 0x00ff_fffe);
    }

    #[test]
    fn flush_ages_to_max_and_advances_sequence() {
        let dest = SummaryDestination::new(net(0x0a0a0a00, 24), 10);
        let lsa = originate_summary_lsa(1, &dest, None).unwrap();
        let flush = flush_summary_lsa(&lsa).unwrap();
        assert_eq!(flush.header.ls_age, MAX_AGE_SECS);
        assert_eq!(flush.header.ls_sequence_number, INITIAL_SEQUENCE_NUMBER + 1);
        assert!(flush.checksum_ok());
        assert!(flush_summary_lsa(&{
            let mut m = lsa.clone();
            m.header.ls_sequence_number = MAX_SEQUENCE_NUMBER;
            m
        })
        .is_none());
    }

    #[test]
    fn v4_assert_covers_ipaddr_import() {
        // Prefix::addr is an IpAddr — keep the import honest for future
        // match arms.
        let p = Prefix::new_v4([10, 0, 0, 0], 8);
        assert!(matches!(p.addr, IpAddr::V4(_)));
    }

    // ---- RFC 2328 Appendix E: LS-ID collision remapping ----

    #[test]
    fn summary_lsa_id_for_no_collision_returns_network() {
        // 10.0.0.0/24, no existing LSAs — LS-ID is the network address.
        let prefix = net(0x0a000000, 24);
        let existing: Vec<(u32, u8)> = Vec::new();
        assert_eq!(summary_lsa_id_for(&prefix, &existing), Some(0x0a000000));
    }

    #[test]
    fn summary_lsa_id_for_refresh_keeps_network() {
        // Existing LSA for 10.0.0.0/24 with the same prefix length —
        // this is a refresh, the LS-ID stays the network address.
        let prefix = net(0x0a000000, 24);
        let existing = vec![(0x0a000000u32, 24u8)];
        assert_eq!(summary_lsa_id_for(&prefix, &existing), Some(0x0a000000));
    }

    #[test]
    fn summary_lsa_id_for_collision_remaps_more_specific_to_broadcast() {
        // RFC 2328 Appendix E: 10.0.0.0/8 (network 10.0.0.0) is
        // already in the area; the new 10.0.0.0/16 (more specific)
        // cannot reuse the same LS-ID. It is remapped to its broadcast
        // address: 10.0.255.255.
        let prefix = net(0x0a000000, 16);
        let existing = vec![(0x0a000000u32, 8u8)];
        assert_eq!(summary_lsa_id_for(&prefix, &existing), Some(0x0a00ffff));
    }

    #[test]
    fn summary_lsa_id_for_unsolvable_collision_returns_none() {
        // RFC 2328 Appendix E: both the network address (10.0.0.0) and
        // the broadcast address (10.0.255.255) are taken — the new
        // 10.0.0.0/16 cannot be originated. Returns None.
        let prefix = net(0x0a000000, 16);
        let existing = vec![(0x0a000000u32, 8u8), (0x0a00ffffu32, 32u8)];
        assert_eq!(summary_lsa_id_for(&prefix, &existing), None);
    }

    #[test]
    fn summary_lsa_id_for_ipv6_returns_none() {
        // v2 LS-IDs are 32-bit IPv4 networks; v6 destinations are not
        // originated as v2 summary-LSAs.
        let prefix = Prefix::new_v6(
            [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
            64,
        );
        let existing: Vec<(u32, u8)> = Vec::new();
        assert_eq!(summary_lsa_id_for(&prefix, &existing), None);
    }

    #[test]
    fn assign_summary_lsa_ids_orders_less_specific_first() {
        // Two prefixes share the network address 10.0.0.0 with
        // different lengths. The batch helper sorts by ascending
        // prefix length so /8 (less specific) keeps the network
        // address and /16 (more specific) is remapped to its
        // broadcast address.
        let destinations = vec![
            SummaryDestination::new(net(0x0a000000, 16), 10),
            SummaryDestination::new(net(0x0a000000, 8), 5),
        ];
        let existing: BTreeMap<u32, Lsa> = BTreeMap::new();
        let mut assigned = assign_summary_lsa_ids(&destinations, &existing);
        // The batch preserves input order for the output Vec — sort
        // by LS-ID for a deterministic assertion.
        assigned.sort_by_key(|(_, lsid)| lsid.unwrap_or(0));
        assert_eq!(assigned.len(), 2);
        assert_eq!(assigned[0].1, Some(0x0a000000)); // /8 network
        assert_eq!(assigned[1].1, Some(0x0a00ffff)); // /16 broadcast
    }

    #[test]
    fn assign_summary_lsa_ids_unsolvable_returns_none_for_collision() {
        // 10.0.0.0/8 already occupies the network address and
        // 10.0.255.255/32 already occupies the broadcast address —
        // 10.0.0.0/16 cannot be originated. The batch reports `None`.
        let mut existing: BTreeMap<u32, Lsa> = BTreeMap::new();
        existing.insert(
            0x0a000000u32,
            originate_summary_lsa(1, &SummaryDestination::new(net(0x0a000000, 8), 5), None)
                .unwrap(),
        );
        existing.insert(
            0x0a00ffffu32,
            originate_summary_lsa(1, &SummaryDestination::new(net(0x0a00ffff, 32), 5), None)
                .unwrap(),
        );
        let destinations = vec![SummaryDestination::new(net(0x0a000000, 16), 10)];
        let assigned = assign_summary_lsa_ids(&destinations, &existing);
        assert_eq!(assigned.len(), 1);
        assert_eq!(assigned[0].1, None);
    }

    #[test]
    fn originate_summary_lsa_with_id_uses_explicit_ls_id() {
        // The /16 destination gets the broadcast address as LS-ID
        // (RFC 2328 Appendix E remap). The LSA's body still carries
        // the /16 mask, so peers can disambiguate it from a /8 LSA
        // that happens to share the network address.
        let dest = SummaryDestination::new(net(0x0a000000, 16), 10);
        let lsa = originate_summary_lsa_with_id(1, 0x0a00ffff, &dest, None).unwrap();
        assert_eq!(lsa.header.link_state_id, 0x0a00ffff);
        let body = decode_summary_lsa_body(&lsa.body).unwrap();
        assert_eq!(body.network_mask, 0xffff0000); // /16 mask
        assert_eq!(body.tos0_metric(), Some(10));
        assert!(lsa.checksum_ok());
    }

    #[test]
    fn originate_summary_lsa_with_id_rejects_v6_and_exhausted_seq() {
        let v6 = Prefix::new_v6(
            [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
            64,
        );
        assert!(
            originate_summary_lsa_with_id(1, 0, &SummaryDestination::new(v6, 5), None).is_none()
        );
        let dest = SummaryDestination::new(net(1, 32), 5);
        assert!(originate_summary_lsa_with_id(1, 0, &dest, Some(MAX_SEQUENCE_NUMBER)).is_none());
    }

    #[test]
    fn originate_summary_lsa_delegates_to_with_id() {
        // The legacy entry point still computes the network address
        // and routes through `originate_summary_lsa_with_id`, so the
        // body / seq / checksum are identical.
        let dest = SummaryDestination::new(net(0x0a0a0a00, 24), 10);
        let legacy = originate_summary_lsa(0x01020304, &dest, None).unwrap();
        let explicit = originate_summary_lsa_with_id(0x01020304, 0x0a0a0a00, &dest, None).unwrap();
        assert_eq!(legacy.header.link_state_id, explicit.header.link_state_id);
        assert_eq!(legacy.body, explicit.body);
        assert_eq!(
            legacy.header.ls_sequence_number,
            explicit.header.ls_sequence_number
        );
    }

    // ---- OSPFv3 inter-area-prefix-LSA tests ----

    fn v6_prefix(a: [u8; 16], len: u8) -> Prefix {
        Prefix::new_v6(a, len)
    }

    #[test]
    fn v3_originate_first_instance() {
        let dest = SummaryDestination::new(
            v6_prefix(
                [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
                64,
            ),
            10,
        );
        let lsa = originate_v3_inter_area_prefix_lsa(0x01020304, 1, &dest, None).unwrap();
        assert_eq!(lsa.header.ls_type, LsaTypeV3::InterAreaPrefixLsa as u16);
        assert_eq!(lsa.header.options, 0, "v3 headers have no options field");
        assert_eq!(lsa.header.link_state_id, 1); // arbitrary LS-ID
        assert_eq!(lsa.header.advertising_router, 0x01020304);
        assert_eq!(lsa.header.ls_sequence_number, INITIAL_SEQUENCE_NUMBER);
        assert_eq!(lsa.header.ls_age, 0);
        assert!(lsa.checksum_ok(), "v3 LSA must carry a valid checksum");

        // The full 16-bit type must reach the wire: bytes 2-3 = 0x2003
        // (RFC 5340 §A.4.2 — no options byte in the v3 LSA header).
        let wire = lsa.to_wire();
        assert_eq!(&wire[2..4], &[0x20, 0x03]);

        let body = crate::lsa::decode_v3_inter_area_prefix_body(&lsa.body).unwrap();
        assert_eq!(body.metric, 10);
        assert_eq!(body.prefix_len, 64);
        // 64 bits = 8 bytes of prefix
        assert_eq!(body.prefix_bytes.len(), 8);
        assert_eq!(&body.prefix_bytes, &[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0]);
    }

    #[test]
    fn v3_originate_continues_sequence() {
        let dest = SummaryDestination::new(
            v6_prefix([0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1], 128),
            20,
        );
        let lsa = originate_v3_inter_area_prefix_lsa(1, 5, &dest, Some(0x80000005)).unwrap();
        assert_eq!(lsa.header.ls_sequence_number, 0x80000006);
        assert_eq!(lsa.header.link_state_id, 5);
        assert!(lsa.checksum_ok());

        // 128 bits = 16 bytes of prefix
        let body = crate::lsa::decode_v3_inter_area_prefix_body(&lsa.body).unwrap();
        assert_eq!(body.prefix_len, 128);
        assert_eq!(body.prefix_bytes.len(), 16);
    }

    #[test]
    fn v3_originate_caps_metric() {
        let dest = SummaryDestination::new(
            v6_prefix(
                [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
                64,
            ),
            0xffff_ffff,
        );
        assert_eq!(dest.metric, 0x00ff_fffe);
        let lsa = originate_v3_inter_area_prefix_lsa(1, 1, &dest, None).unwrap();
        let body = crate::lsa::decode_v3_inter_area_prefix_body(&lsa.body).unwrap();
        // The v3 inter-area-prefix metric is a 24-bit field (RFC 5340
        // §A.4.5); the encoder caps just below LSInfinity (0x00ff_ffff).
        assert_eq!(body.metric, 0x00ff_fffe);
    }

    #[test]
    fn v3_originate_rejects_max_sequence() {
        let dest = SummaryDestination::new(
            v6_prefix(
                [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
                64,
            ),
            5,
        );
        assert!(
            originate_v3_inter_area_prefix_lsa(1, 1, &dest, Some(MAX_SEQUENCE_NUMBER)).is_none()
        );
    }

    #[test]
    fn v3_inter_area_body_matches_literal_rfc5340_layout() {
        // RFC 5340 §A.4.5 + §4.4.3.4, using the RFC's own worked example
        // (metric 4, prefix 2001:0db8:c001::/48 padded to 64 bits):
        //
        //   0(1) | Metric(3) | PrefixLength(1) | PrefixOptions(1) |
        //   0(2) | Address Prefix (32-bit padded)
        let dest = SummaryDestination::new(
            v6_prefix(
                [
                    0x20, 0x01, 0x0d, 0xb8, 0xc0, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                ],
                48,
            ),
            4,
        );
        let body = crate::lsa::encode_v3_inter_area_prefix_body(&dest.prefix, dest.metric);
        let expected: [u8; 16] = [
            0x00, 0x00, 0x00, 0x04, // reserved | metric(24)
            0x30, // PrefixLength = 48
            0x00, // PrefixOptions
            0x00, 0x00, // reserved
            0x20, 0x01, 0x0d, 0xb8, 0xc0, 0x01, 0x00, 0x00, // /48 padded to 64 bits
        ];
        assert_eq!(body, expected.to_vec(), "literal RFC 5340 A.4.5 layout");
        let decoded = crate::lsa::decode_v3_inter_area_prefix_body(&body).unwrap();
        assert_eq!(decoded.metric, 4);
        assert_eq!(decoded.prefix_len, 48);
        assert_eq!(decoded.prefix_bytes.len(), 6);
        assert_eq!(&decoded.prefix_bytes, &[0x20, 0x01, 0x0d, 0xb8, 0xc0, 0x01]);
    }

    #[test]
    fn v3_roundtrip_preserves_prefix() {
        let prefix = v6_prefix(
            [
                0x20, 0x01, 0x0d, 0xb8, 0xca, 0xfe, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
            ],
            48,
        );
        let dest = SummaryDestination::new(prefix, 42);
        let lsa = originate_v3_inter_area_prefix_lsa(0x0a0a0a0a, 7, &dest, None).unwrap();
        let body = crate::lsa::decode_v3_inter_area_prefix_body(&lsa.body).unwrap();
        let decoded = body.to_prefix().unwrap();
        assert_eq!(decoded.prefix_len, 48);
        // 48 bits = 6 bytes; the decoded prefix is zero-padded to 16
        assert_eq!(
            &decoded.addr,
            &lr_core::addr::IpAddr::V6({
                let mut b = [0u8; 16];
                b[..6].copy_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0xca, 0xfe]);
                b
            })
        );
    }
}
