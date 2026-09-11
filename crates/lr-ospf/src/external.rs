//! AS-external LSA origination and the external route calculation
//! (RFC 2328 §12.4.3, §16.4, §16.5).
//!
//! An AS boundary router (ASBR) advertises routes learned from outside
//! OSPF by originating type-5 AS-external-LSAs. Unlike area-scoped LSAs,
//! type-5s flood across the whole AS: ABRs re-flood them into every
//! attached (non-stub) area. Their link-state ID is the external
//! destination's network address — the same collision semantics as
//! summary-LSAs (see [`crate::abr`]).
//!
//! [`external_routes`] implements §16.4 for one area: for every type-5
//! LSA it resolves the cost to the advertising ASBR — intra-area from the
//! §16.1 SPF tree, inter-area from type-4 summary-ASBR-LSAs (§16.4 (b)) —
//! validates the forwarding address against the §16.1/§16.2 routing
//! table (§16.4 (c)) and produces [`ExternalRoute`] candidates with
//! type-1/type-2 metric semantics.
//!
//! All helpers target OSPFv2 LSA encodings (RFC 2328 §A.4.5 bodies).

use std::collections::BTreeMap;

use crate::abr::{INITIAL_SEQUENCE_NUMBER, MAX_SEQUENCE_NUMBER};
use crate::lsa::{
    decode_as_external_body, decode_summary_lsa_body, encode_as_external_body,
    encode_summary_lsa_body, mask_to_prefix_len, prefix_len_to_mask, AsExternalEntry, Lsa,
    LsaHeader, LsaTypeV2,
};
use crate::lsdb::Lsdb;
use crate::spf::{summary_routes, SpfResult, VertexId};
use lr_core::addr::{IpAddr, Prefix};

/// LSInfinity — an external metric that means "unreachable" (§16.4 (1)).
pub(crate) const LS_INFINITY: u32 = 0x00ff_ffff;

/// External metric type (RFC 2328 §2.3).
///
/// Type 1 metrics are comparable with internal OSPF costs: the route cost
/// is the sum of the path to the ASBR and the external metric. Type 2
/// metrics (E-bit set) are considered "much greater" than any intra-AS
/// path — only the external metric counts, and the cost to the ASBR is a
/// tie-breaker. Type 1 routes always win over type 2 (§16.4 (6)).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ExternalMetricType {
    /// Type 1: added to the internal cost (E-bit clear).
    Type1,
    /// Type 2: fixed external cost, larger than any internal path (E-bit set).
    Type2,
}

impl ExternalMetricType {
    /// Whether the E-bit (RFC 2328 §A.4.5) must be set for this type.
    pub fn e_bit(self) -> bool {
        self == Self::Type2
    }

    pub fn from_e_bit(e: bool) -> Self {
        if e {
            Self::Type2
        } else {
            Self::Type1
        }
    }
}

/// One externally redistributed destination (RFC 2328 §12.4.3).
///
/// The metric is capped just below LSInfinity (`0x00ff_ffff`), which is
/// reserved to mean "unreachable". A forwarding address of `0.0.0.0`
/// routes traffic to the ASBR itself; otherwise traffic is forwarded to
/// that address, which must be reachable through OSPF (§16.4 (c)).
///
/// `p_bit` only matters when the destination is redistributed into an
/// NSSA as a type-7 LSA (RFC 3101 §2.4): set means the originator asks
/// border routers to translate the LSA into a type-5 — which then
/// requires a non-zero `forwarding_addr` (§2.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExternalDestination {
    pub prefix: Prefix,
    pub metric: u32,
    pub metric_type: ExternalMetricType,
    /// 0 means "forward to the ASBR".
    pub forwarding_addr: u32,
    pub route_tag: u32,
    /// Ask NSSA border routers to translate the type-7 into a type-5
    /// (RFC 3101 §2.4). Ignored for type-5 origination.
    pub p_bit: bool,
}

impl ExternalDestination {
    pub fn new(prefix: Prefix, metric: u32, metric_type: ExternalMetricType) -> Self {
        Self {
            prefix,
            metric: metric.min(0x00ff_fffe),
            metric_type,
            forwarding_addr: 0,
            route_tag: 0,
            p_bit: true,
        }
    }
}

/// Originate a type-5 AS-external-LSA for `dest` (RFC 2328 §12.4.3).
///
/// `prev_seq` carries the sequence number of the router's current
/// instance for this link-state ID (if any): the new LSA continues the
/// sequence space, otherwise it starts at
/// [`INITIAL_SEQUENCE_NUMBER`]. The returned LSA is finalized — length
/// fixed, RFC 2328 §C.4 checksum computed.
///
/// Returns `None` for non-IPv4 destinations or when the sequence space is
/// exhausted (the caller must flush the LSA and re-originate, §12.1.2).
pub fn originate_external_lsa(
    router_id: u32,
    dest: &ExternalDestination,
    prev_seq: Option<u32>,
) -> Option<Lsa> {
    let IpAddr::V4(octets) = dest.prefix.addr else {
        return None; // v2 link-state IDs are 32-bit IPv4 networks
    };
    let seq = match prev_seq {
        None => INITIAL_SEQUENCE_NUMBER,
        Some(MAX_SEQUENCE_NUMBER) => return None,
        Some(p) => p + 1,
    };
    let mask = prefix_len_to_mask(dest.prefix.prefix_len);
    let network = u32::from_be_bytes(octets) & mask;
    let metric_word = if dest.metric_type.e_bit() {
        0x8000_0000
    } else {
        0
    } | (dest.metric & LS_INFINITY);
    let body = encode_as_external_body(&AsExternalEntry {
        network_mask: mask,
        metric: metric_word,
        forwarding_addr: dest.forwarding_addr,
        route_tag: dest.route_tag,
    });
    let mut lsa = Lsa {
        header: LsaHeader {
            ls_age: 0,
            options: 0x02,
            ls_type: LsaTypeV2::AsExternalLsa as u16,
            link_state_id: network,
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

/// Build the MaxAge instance that flushes a type-5 LSA from all databases
/// (RFC 2328 §14.1). Delegates to [`Lsa::maxage_flush`].
pub fn flush_external_lsa(existing: &Lsa) -> Option<Lsa> {
    existing.maxage_flush()
}

/// An ASBR whose location an ABR advertises into another area via a
/// type-4 summary-ASBR-LSA (RFC 2328 §12.4.3): the ASBR's router ID plus
/// the metric of the path to it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AsbrDestination {
    pub asbr: u32,
    pub metric: u32,
}

impl AsbrDestination {
    pub fn new(asbr: u32, metric: u32) -> Self {
        Self {
            asbr,
            metric: metric.min(0x00ff_fffe),
        }
    }
}

/// Originate a type-4 summary-ASBR-LSA (RFC 2328 §12.4.3). ABRs
/// originate one per reachable ASBR into each area that cannot reach the
/// ASBR intra-area, so that routers elsewhere in the AS can resolve the
/// ASBR's location (§16.4 (b)). The body uses the summary-LSA format
/// with a zero mask; the link-state ID is the ASBR's router ID.
pub fn originate_summary_asbr_lsa(
    router_id: u32,
    dest: &AsbrDestination,
    prev_seq: Option<u32>,
) -> Option<Lsa> {
    let seq = match prev_seq {
        None => INITIAL_SEQUENCE_NUMBER,
        Some(MAX_SEQUENCE_NUMBER) => return None,
        Some(p) => p + 1,
    };
    let body = encode_summary_lsa_body(0, dest.metric);
    let mut lsa = Lsa {
        header: LsaHeader {
            ls_age: 0,
            options: 0x02,
            ls_type: LsaTypeV2::SummaryAsbrLsa as u16,
            link_state_id: dest.asbr,
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

/// One external route candidate produced by the §16.4 calculation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExternalRoute {
    pub prefix: Prefix,
    /// Type 1: cost-to-ASBR + external metric. Type 2: external metric
    /// only (`internal_cost` breaks ties).
    pub metric: u64,
    pub metric_type: ExternalMetricType,
    /// The cost of the internal path to the ASBR (or forwarding address).
    pub internal_cost: u64,
    /// Advertising router of the winning type-5 LSA.
    pub asbr: u32,
    /// Advertising border router when the ASBR was found through a
    /// type-4 summary-ASBR-LSA (§16.4 (b)); `None` for intra-area paths.
    pub border_router: Option<u32>,
    /// Forwarding address from the type-5 LSA (0 = ASBR itself).
    pub forwarding_addr: u32,
}

impl ExternalRoute {
    /// §16.4 (6) candidate preference for identical prefixes: type 1
    /// beats type 2, then the lowest metric, then (type 2) the lowest
    /// internal cost, then the lowest ASBR router ID for determinism.
    pub(crate) fn beats(&self, prev: &Self) -> bool {
        match self.metric_type.cmp(&prev.metric_type) {
            core::cmp::Ordering::Less => return true,
            core::cmp::Ordering::Greater => return false,
            core::cmp::Ordering::Equal => {}
        }
        if self.metric != prev.metric {
            return self.metric < prev.metric;
        }
        if self.metric_type == ExternalMetricType::Type2 && self.internal_cost != prev.internal_cost
        {
            return self.internal_cost < prev.internal_cost;
        }
        self.asbr < prev.asbr
    }
}

/// The resolved internal leg of an external route: cost to the ASBR plus
/// the border router that advertised it, when reached inter-area.
struct AsbrLeg {
    cost: u64,
    border_router: Option<u32>,
}

/// RFC 2328 §16.4: compute the external route candidates for one area.
///
/// For every type-5 LSA in `lsdb`:
///
/// 1. skip metrics of LSInfinity (§16.4 (1));
/// 2. resolve the cost to the advertising ASBR — intra-area from the
///    §16.1 `spf_result`, else inter-area via type-4 summary-ASBR-LSAs
///    whose border router is intra-area reachable (§16.4 (b));
/// 3. when the LSA carries a forwarding address, it must be covered by an
///    intra-area route or a type-3 summary route (§16.4 (c)) — the
///    covering route's metric becomes the internal leg;
/// 4. build the candidate metric from the metric type (§2.3) and keep
///    the best candidate per prefix (§16.4 (6)).
pub fn external_routes(lsdb: &Lsdb, spf_result: &SpfResult) -> Vec<ExternalRoute> {
    // Fast path: areas without any type-5/type-4 LSAs skip the covering
    // table construction entirely (summary routes are not needed).
    let has_externals = lsdb.iter().any(|(key, _)| {
        key.ls_type == LsaTypeV2::AsExternalLsa as u16
            || key.ls_type == LsaTypeV2::SummaryAsbrLsa as u16
    });
    if !has_externals {
        return Vec::new();
    }

    // §16.4 (b): inter-area ASBR legs from type-4 summary-ASBR-LSAs.
    let mut asbr_legs: BTreeMap<u32, AsbrLeg> = BTreeMap::new();
    for (key, entry) in lsdb.iter() {
        if key.ls_type != LsaTypeV2::SummaryAsbrLsa as u16 {
            continue;
        }
        let Some(&dist) = spf_result
            .vertices
            .get(&VertexId::Router(key.advertising_router))
        else {
            continue; // border router itself unreachable
        };
        let Some(body) = decode_summary_lsa_body(&entry.lsa.body) else {
            continue;
        };
        let Some(metric) = body.tos0_metric() else {
            continue;
        };
        if metric >= LS_INFINITY {
            continue;
        }
        let candidate = AsbrLeg {
            cost: dist + u64::from(metric),
            border_router: Some(key.advertising_router),
        };
        let not_better = matches!(
            asbr_legs.get(&key.link_state_id),
            Some(prev) if prev.cost <= candidate.cost
        );
        if !not_better {
            asbr_legs.insert(key.link_state_id, candidate);
        }
    }

    // §16.4 (c): forwarding-address validation needs the §16.1/§16.2
    // routing table — intra-area prefixes plus type-3 summary routes.
    let mut covering: Vec<(Prefix, u64)> = spf_result
        .stub_routes
        .iter()
        .chain(spf_result.transit_routes.iter())
        .map(|r| (r.prefix, r.metric))
        .collect();
    for r in summary_routes(lsdb, spf_result) {
        covering.push((r.prefix, r.metric));
    }

    let mut best: BTreeMap<Prefix, ExternalRoute> = BTreeMap::new();
    for (key, entry) in lsdb.iter() {
        if key.ls_type != LsaTypeV2::AsExternalLsa as u16 {
            continue;
        }
        let Some(body) = decode_as_external_body(&entry.lsa.body) else {
            continue;
        };
        let metric_type = ExternalMetricType::from_e_bit(body.external_type2());
        let external_metric = body.metric_value();
        if external_metric >= LS_INFINITY {
            continue; // §16.4 (1)
        }

        // (2) Locate the ASBR (or the forwarding address) and its cost.
        let (internal_cost, border_router) = if body.forwarding_addr != 0 {
            // §16.4 (c): the forwarding address must be covered by an
            // intra-area or summary route; the covering route's metric
            // is the internal leg.
            let Some((_, cost)) = longest_covering(&covering, fa_prefix(body.forwarding_addr))
            else {
                continue; // forwarding address unreachable
            };
            (cost, None)
        } else {
            match (
                spf_result
                    .vertices
                    .get(&VertexId::Router(key.advertising_router)),
                asbr_legs.get(&key.advertising_router),
            ) {
                // (a) Intra-area path to the ASBR wins.
                (Some(&dist), _) => (dist, None),
                // (b) Inter-area path via a type-4 summary-ASBR-LSA.
                (None, Some(leg)) => (leg.cost, leg.border_router),
                // ASBR unreachable through OSPF.
                _ => continue,
            }
        };

        let metric = match metric_type {
            ExternalMetricType::Type1 => internal_cost + u64::from(external_metric),
            ExternalMetricType::Type2 => u64::from(external_metric),
        };
        let prefix_len = mask_to_prefix_len(body.network_mask);
        let network = entry.lsa.header.link_state_id & body.network_mask;
        let prefix = Prefix::new_v4(network.to_be_bytes(), prefix_len);
        let candidate = ExternalRoute {
            prefix,
            metric,
            metric_type,
            internal_cost,
            asbr: key.advertising_router,
            border_router,
            forwarding_addr: body.forwarding_addr,
        };
        let replace = match best.get(&prefix) {
            None => true,
            Some(prev) => candidate.beats(prev),
        };
        if replace {
            best.insert(prefix, candidate);
        }
    }
    best.into_values().collect()
}

/// `/32` prefix around a forwarding address.
pub(crate) fn fa_prefix(addr: u32) -> Prefix {
    Prefix::new_v4(addr.to_be_bytes(), 32)
}

/// `/128` prefix around an IPv6 forwarding address.
pub(crate) fn fa_prefix_v6(addr: [u8; 16]) -> Prefix {
    Prefix::new_v6(addr, 128)
}

/// Longest-prefix match of `prefix` against `table`. Returns the covering
/// entry (prefix length, metric) or `None`.
pub(crate) fn longest_covering(table: &[(Prefix, u64)], prefix: Prefix) -> Option<(u8, u64)> {
    let mut best: Option<(u8, u64)> = None;
    for (candidate, metric) in table {
        if candidate.prefix_len <= prefix.prefix_len
            && candidate.contains_prefix(&prefix)
            && best.is_none_or(|(len, _)| candidate.prefix_len > len)
        {
            best = Some((candidate.prefix_len, *metric));
        }
    }
    best
}

// ---------------------------------------------------------------------------
// OSPFv3 AS-external route calculation (RFC 5340 §4.8.5)
// ---------------------------------------------------------------------------

use crate::lsa::v3::{V3AsExternalBody, LS_TYPE_AS_EXTERNAL, LS_TYPE_INTER_ROUTER, PREFIX_OPT_NU};
use crate::spf::{summary_routes_v3, SpfResultV3, V3VertexId};

/// One external route candidate produced by the v3 §4.8.5 calculation.
/// The v3 mirror of [`ExternalRoute`]: the forwarding address is a full
/// IPv6 address gated by the F bit (§A.4.7) instead of a 0.0.0.0
/// sentinel.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExternalRouteV3 {
    pub prefix: Prefix,
    /// Type 1: cost-to-ASBR + external metric. Type 2: external metric
    /// only (`internal_cost` breaks ties).
    pub metric: u64,
    pub metric_type: ExternalMetricType,
    /// The cost of the internal path to the ASBR (or forwarding address).
    pub internal_cost: u64,
    /// Advertising router of the winning 0x4005 LSA.
    pub asbr: u32,
    /// Advertising border router when the ASBR was found through an
    /// inter-area-router-LSA (0x2004, §4.8.5 — the §16.4 (b) v3 form);
    /// `None` for intra-area paths.
    pub border_router: Option<u32>,
    /// The global IPv6 forwarding address (F bit); `None` forwards to
    /// the ASBR.
    pub forwarding_addr: Option<IpAddr>,
}

impl ExternalRouteV3 {
    /// §16.4 (6) candidate preference for identical prefixes — the same
    /// order the v2 [`ExternalRoute::beats`] encodes: type 1 beats
    /// type 2, then the lowest metric, then (type 2) the lowest
    /// internal cost, then the lowest ASBR router ID for determinism.
    pub(crate) fn beats(&self, prev: &Self) -> bool {
        match self.metric_type.cmp(&prev.metric_type) {
            core::cmp::Ordering::Less => return true,
            core::cmp::Ordering::Greater => return false,
            core::cmp::Ordering::Equal => {}
        }
        if self.metric != prev.metric {
            return self.metric < prev.metric;
        }
        if self.metric_type == ExternalMetricType::Type2 && self.internal_cost != prev.internal_cost
        {
            return self.internal_cost < prev.internal_cost;
        }
        self.asbr < prev.asbr
    }
}

/// The resolved internal leg toward one ASBR: cost plus the border
/// router that advertised it, when reached inter-area.
struct AsbrLegV3 {
    cost: u64,
    border_router: Option<u32>,
}

/// RFC 5340 §4.8.5: compute the external route candidates for one area
/// — the v3 form of RFC 2328 §16.4.
///
/// For every 0x4005 LSA in `lsdb`:
///
/// 1. skip metrics of LSInfinity and NU-marked prefixes (§4.8.5; FRR
///    `ospf6_asbr_lsa_add` parity);
/// 2. resolve the cost to the advertising ASBR — intra-area from the
///    §4.8.1 v3 tree, else inter-area via 0x2004 inter-area-router-LSAs
///    whose border router is intra-area reachable (§16.4 (b) v3 form:
///    the destination ASBR travels in the 0x2004 body, not the LS ID);
/// 3. when the F bit is set, the global forwarding address must be
///    covered by an intra-area route or a 0x2003 summary route
///    (§16.4 (c) v3 form) — the covering route's metric becomes the
///    internal leg;
/// 4. build the candidate metric from the metric type (§2.3) and keep
///    the best candidate per prefix (§16.4 (6)).
///
/// The destination ASBR's Router ID travels in the 0x2004 body; the LS
/// ID has lost its addressing semantics (§4.4.3.5), so the ASBR legs
/// are keyed by the body field.
pub fn external_routes_v3(lsdb: &Lsdb, spf_result: &SpfResultV3) -> Vec<ExternalRouteV3> {
    // Fast path: areas without any 0x4005/0x2004 LSAs skip the covering
    // table construction entirely (summary routes are not needed).
    let has_externals = lsdb
        .iter()
        .any(|(key, _)| key.ls_type == LS_TYPE_AS_EXTERNAL || key.ls_type == LS_TYPE_INTER_ROUTER);
    if !has_externals {
        return Vec::new();
    }

    // §16.4 (b) v3 form: inter-area ASBR legs from 0x2004
    // inter-area-router-LSAs, keyed by the destination Router ID in the
    // body. The best (lowest-cost) leg per ASBR wins.
    let mut asbr_legs: BTreeMap<u32, AsbrLegV3> = BTreeMap::new();
    for (key, entry) in lsdb.iter() {
        if key.ls_type != LS_TYPE_INTER_ROUTER {
            continue;
        }
        let Some(&dist) = spf_result
            .vertices
            .get(&V3VertexId::Router(key.advertising_router))
        else {
            continue; // border router itself unreachable
        };
        let Some(body) = crate::lsa::v3::V3InterAreaRouterBody::decode(&entry.lsa.body) else {
            continue;
        };
        if body.metric >= LS_INFINITY {
            continue;
        }
        let candidate = AsbrLegV3 {
            cost: dist + u64::from(body.metric),
            border_router: Some(key.advertising_router),
        };
        let not_better = matches!(
            asbr_legs.get(&body.dest_router_id),
            Some(prev) if prev.cost <= candidate.cost
        );
        if !not_better {
            asbr_legs.insert(body.dest_router_id, candidate);
        }
    }

    // §16.4 (c) v3 form: forwarding-address validation needs the
    // §4.8.1/§4.8.3 routing table — intra-area prefixes plus 0x2003
    // summary routes.
    let mut covering: Vec<(Prefix, u64)> = spf_result
        .routes
        .iter()
        .map(|r| (r.prefix, r.metric))
        .collect();
    for r in summary_routes_v3(lsdb, spf_result) {
        covering.push((r.prefix, r.metric));
    }

    let mut best: BTreeMap<Prefix, ExternalRouteV3> = BTreeMap::new();
    for (key, entry) in lsdb.iter() {
        if key.ls_type != LS_TYPE_AS_EXTERNAL {
            continue;
        }
        let Some(body) = V3AsExternalBody::decode(&entry.lsa.body) else {
            continue;
        };
        if body.metric >= LS_INFINITY {
            continue; // §16.4 (1)
        }
        // §4.8.5: NU-marked prefixes are ignored (FRR
        // `ospf6_asbr_lsa_add` parity).
        if body.prefix.options & PREFIX_OPT_NU != 0 {
            continue;
        }
        let metric_type = ExternalMetricType::from_e_bit(body.e_bit);
        let external_metric = u64::from(body.metric & crate::lsa::v3::AS_EXT_METRIC_MASK);

        // (2) Locate the ASBR (or the forwarding address) and its cost.
        let (internal_cost, border_router, asbr) = if let Some(fa) = body.forwarding_addr {
            // Unspecified and link-local forwarding addresses are
            // illegal (§A.4.7) — treat them as no forwarding address
            // data rather than a crash/loop source.
            let unusable = fa == [0u8; 16] || (fa[0] == 0xfe && (fa[1] & 0xc0) == 0x80);
            if unusable {
                continue;
            }
            // §16.4 (c): the forwarding address must be covered by an
            // intra-area or summary route; the covering route's metric
            // is the internal leg.
            let Some((_, cost)) = longest_covering(&covering, fa_prefix_v6(fa)) else {
                continue; // forwarding address unreachable
            };
            (cost, None, key.advertising_router)
        } else {
            match (
                spf_result
                    .vertices
                    .get(&V3VertexId::Router(key.advertising_router)),
                asbr_legs.get(&key.advertising_router),
            ) {
                // (a) Intra-area path to the ASBR wins.
                (Some(&dist), _) => (dist, None, key.advertising_router),
                // (b) Inter-area path via a 0x2004 inter-area-router-LSA.
                (None, Some(leg)) => (leg.cost, leg.border_router, key.advertising_router),
                // ASBR unreachable through OSPF.
                _ => continue,
            }
        };

        let metric = match metric_type {
            ExternalMetricType::Type1 => internal_cost + external_metric,
            ExternalMetricType::Type2 => external_metric,
        };
        let prefix = Prefix::new_v6(body.prefix.addr, body.prefix.prefix_len);
        let candidate = ExternalRouteV3 {
            prefix,
            metric,
            metric_type,
            internal_cost,
            asbr,
            border_router,
            forwarding_addr: body.forwarding_addr.map(IpAddr::V6),
        };
        let replace = match best.get(&prefix) {
            None => true,
            Some(prev) => candidate.beats(prev),
        };
        if replace {
            best.insert(prefix, candidate);
        }
    }
    best.into_values().collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lsdb::InstallOutcome;
    use crate::spf::run_spf;

    fn net(a: u32, len: u8) -> Prefix {
        Prefix::new_v4(a.to_be_bytes(), len)
    }

    #[test]
    fn originate_external_type2_sets_e_bit() {
        let dest = ExternalDestination::new(net(0xc000_0200, 24), 100, ExternalMetricType::Type2);
        let lsa = originate_external_lsa(0x01020304, &dest, None).unwrap();
        assert_eq!(lsa.header.ls_type, LsaTypeV2::AsExternalLsa as u16);
        assert_eq!(lsa.header.link_state_id, 0xc000_0200);
        assert_eq!(lsa.header.advertising_router, 0x01020304);
        assert_eq!(lsa.header.ls_sequence_number, INITIAL_SEQUENCE_NUMBER);
        assert_eq!(lsa.header.length, 36); // 20 header + 16 body
        assert!(lsa.checksum_ok());
        let body = decode_as_external_body(&lsa.body).unwrap();
        assert!(body.external_type2());
        assert_eq!(body.metric_value(), 100);
        assert_eq!(body.network_mask, 0xffff_ff00);
        assert_eq!(body.forwarding_addr, 0);
        assert_eq!(body.route_tag, 0);
    }

    #[test]
    fn originate_external_type1_and_forwarding_address() {
        let mut dest = ExternalDestination::new(net(0x0a000000, 8), 50, ExternalMetricType::Type1);
        dest.forwarding_addr = 0x0a0a0a01;
        dest.route_tag = 7;
        let lsa = originate_external_lsa(1, &dest, Some(0x80000005)).unwrap();
        assert_eq!(lsa.header.ls_sequence_number, 0x80000006);
        let body = decode_as_external_body(&lsa.body).unwrap();
        assert!(!body.external_type2());
        assert_eq!(body.metric_value(), 50);
        assert_eq!(body.forwarding_addr, 0x0a0a0a01);
        assert_eq!(body.route_tag, 7);
    }

    #[test]
    fn originate_external_rejects_v6_and_sequence_exhaustion() {
        let v6 = Prefix::new_v6([0x20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1], 64);
        assert!(originate_external_lsa(
            1,
            &ExternalDestination::new(v6, 5, ExternalMetricType::Type1),
            None
        )
        .is_none());
        let dest = ExternalDestination::new(net(1, 32), 5, ExternalMetricType::Type1);
        assert!(originate_external_lsa(1, &dest, Some(MAX_SEQUENCE_NUMBER)).is_none());
    }

    #[test]
    fn flush_external_ages_to_maxage() {
        let dest = ExternalDestination::new(net(0xc000_0200, 24), 10, ExternalMetricType::Type1);
        let lsa = originate_external_lsa(1, &dest, None).unwrap();
        let flush = flush_external_lsa(&lsa).unwrap();
        assert_eq!(flush.header.ls_age, crate::lsdb::MAX_AGE_SECS);
        assert_eq!(flush.header.ls_sequence_number, INITIAL_SEQUENCE_NUMBER + 1);
        assert!(flush.checksum_ok());
    }

    #[test]
    fn originate_summary_asbr_uses_router_id_as_ls_id() {
        let dest = AsbrDestination::new(0x09090909, 30);
        let lsa = originate_summary_asbr_lsa(0x01020304, &dest, None).unwrap();
        assert_eq!(lsa.header.ls_type, LsaTypeV2::SummaryAsbrLsa as u16);
        assert_eq!(lsa.header.link_state_id, 0x09090909);
        assert_eq!(lsa.header.length, 28); // 20 header + 8 body
        assert!(lsa.checksum_ok());
        let body = decode_summary_lsa_body(&lsa.body).unwrap();
        assert_eq!(body.network_mask, 0);
        assert_eq!(body.tos0_metric(), Some(30));
    }

    /// Topology: root R1 (router-id 1) — R2 (ASBR, router-id 2) with a
    /// p2p link of metric 10, and R2 redistributes 198.51.100.0/24 as a
    /// type-1 external with metric 5.
    fn externals_with_asbr_reachable() -> Vec<ExternalRoute> {
        let mut lsdb = Lsdb::new();
        // R1's router-LSA: p2p link to R2, metric 10 + stub net.
        let mut r1 = Lsa {
            header: LsaHeader {
                ls_age: 0,
                options: 0x02,
                ls_type: LsaTypeV2::RouterLsa as u16,
                link_state_id: 1,
                advertising_router: 1,
                ls_sequence_number: INITIAL_SEQUENCE_NUMBER,
                ls_checksum: 0,
                length: 0,
            },
            body: crate::spf::encode_router_lsa_body(
                0,
                vec![crate::lsa::RouterLink {
                    link_id: 2,
                    link_data: 0,
                    link_type: 1,
                    tos: 0,
                    metric: 10,
                }],
            ),
        };
        r1.finalize();
        assert_eq!(lsdb.install(r1, 0), InstallOutcome::New);
        // R2's router-LSA: link back to R1.
        let mut r2 = Lsa {
            header: LsaHeader {
                ls_age: 0,
                options: 0x02,
                ls_type: LsaTypeV2::RouterLsa as u16,
                link_state_id: 2,
                advertising_router: 2,
                ls_sequence_number: INITIAL_SEQUENCE_NUMBER,
                ls_checksum: 0,
                length: 0,
            },
            body: crate::spf::encode_router_lsa_body(
                0,
                vec![crate::lsa::RouterLink {
                    link_id: 1,
                    link_data: 0,
                    link_type: 1,
                    tos: 0,
                    metric: 10,
                }],
            ),
        };
        r2.finalize();
        assert_eq!(lsdb.install(r2, 0), InstallOutcome::New);
        // R2's external: 198.51.100.0/24 type-1 metric 5.
        let dest = ExternalDestination::new(net(0xc6336400, 24), 5, ExternalMetricType::Type1);
        let ext = originate_external_lsa(2, &dest, None).unwrap();
        assert_eq!(lsdb.install(ext, 0), InstallOutcome::New);
        let result = run_spf(&lsdb, 1);
        external_routes(&lsdb, &result)
    }

    #[test]
    fn type1_external_adds_asbr_cost() {
        let routes = externals_with_asbr_reachable();
        assert_eq!(routes.len(), 1);
        let r = &routes[0];
        assert_eq!(r.prefix, net(0xc6336400, 24));
        assert_eq!(r.metric_type, ExternalMetricType::Type1);
        assert_eq!(r.metric, 15); // 10 to ASBR + 5 external
        assert_eq!(r.internal_cost, 10);
        assert_eq!(r.asbr, 2);
        assert_eq!(r.border_router, None);
    }

    #[test]
    fn type2_external_keeps_external_metric_only() {
        let mut lsdb = Lsdb::new();
        let mut r1 = Lsa {
            header: LsaHeader {
                ls_age: 0,
                options: 0x02,
                ls_type: LsaTypeV2::RouterLsa as u16,
                link_state_id: 1,
                advertising_router: 1,
                ls_sequence_number: INITIAL_SEQUENCE_NUMBER,
                ls_checksum: 0,
                length: 0,
            },
            body: crate::spf::encode_router_lsa_body(
                0,
                vec![crate::lsa::RouterLink {
                    link_id: 2,
                    link_data: 0,
                    link_type: 1,
                    tos: 0,
                    metric: 10,
                }],
            ),
        };
        r1.finalize();
        lsdb.install(r1, 0);
        let mut r2 = Lsa {
            header: LsaHeader {
                ls_age: 0,
                options: 0x02,
                ls_type: LsaTypeV2::RouterLsa as u16,
                link_state_id: 2,
                advertising_router: 2,
                ls_sequence_number: INITIAL_SEQUENCE_NUMBER,
                ls_checksum: 0,
                length: 0,
            },
            body: crate::spf::encode_router_lsa_body(
                0,
                vec![crate::lsa::RouterLink {
                    link_id: 1,
                    link_data: 0,
                    link_type: 1,
                    tos: 0,
                    metric: 10,
                }],
            ),
        };
        r2.finalize();
        lsdb.install(r2, 0);
        let dest = ExternalDestination::new(net(0xc6336400, 24), 7, ExternalMetricType::Type2);
        lsdb.install(originate_external_lsa(2, &dest, None).unwrap(), 0);
        let result = run_spf(&lsdb, 1);
        let routes = external_routes(&lsdb, &result);
        assert_eq!(routes.len(), 1);
        assert_eq!(routes[0].metric, 7);
        assert_eq!(routes[0].internal_cost, 10);
    }

    #[test]
    fn unreachable_asbr_is_skipped() {
        let mut lsdb = Lsdb::new();
        // Only the external LSA — its ASBR (router 9) has no router-LSA
        // here, so §16.4 cannot locate it.
        let dest = ExternalDestination::new(net(0xc6336400, 24), 5, ExternalMetricType::Type1);
        lsdb.install(originate_external_lsa(9, &dest, None).unwrap(), 0);
        let result = run_spf(&lsdb, 1);
        assert!(external_routes(&lsdb, &result).is_empty());
    }

    #[test]
    fn ls_infinity_external_is_skipped() {
        let mut lsdb = Lsdb::new();
        let dest =
            ExternalDestination::new(net(0xc6336400, 24), LS_INFINITY, ExternalMetricType::Type1);
        lsdb.install(originate_external_lsa(2, &dest, None).unwrap(), 0);
        let result = run_spf(&lsdb, 1);
        assert!(external_routes(&lsdb, &result).is_empty());
    }

    #[test]
    fn type1_preferred_over_type2_and_asbr_leg_via_type4() {
        // R1 — (metric 4) — ABR(3) — type-4 says ASBR 9 reachable at 20.
        // Two externals for 203.0.113.0/24: type-2 metric 1 from ASBR 9
        // and type-1 metric 50 from ASBR 3 (reachable intra-area).
        let mut lsdb = Lsdb::new();
        let link = |adv: u32, to: u32, metric: u16| {
            let mut lsa = Lsa {
                header: LsaHeader {
                    ls_age: 0,
                    options: 0x02,
                    ls_type: LsaTypeV2::RouterLsa as u16,
                    link_state_id: adv,
                    advertising_router: adv,
                    ls_sequence_number: INITIAL_SEQUENCE_NUMBER,
                    ls_checksum: 0,
                    length: 0,
                },
                body: crate::spf::encode_router_lsa_body(
                    0,
                    vec![crate::lsa::RouterLink {
                        link_id: to,
                        link_data: 0,
                        link_type: 1,
                        tos: 0,
                        metric,
                    }],
                ),
            };
            lsa.finalize();
            lsa
        };
        lsdb.install(link(1, 3, 4), 0);
        lsdb.install(link(3, 1, 4), 0);
        // ABR 3's type-4: ASBR 9 at metric 20.
        lsdb.install(
            originate_summary_asbr_lsa(3, &AsbrDestination::new(9, 20), None).unwrap(),
            0,
        );
        // ASBR 9's type-2 external (metric 1) and ASBR 3's type-1 (metric 50).
        lsdb.install(
            originate_external_lsa(
                9,
                &ExternalDestination::new(net(0xcb007100, 24), 1, ExternalMetricType::Type2),
                None,
            )
            .unwrap(),
            0,
        );
        lsdb.install(
            originate_external_lsa(
                3,
                &ExternalDestination::new(net(0xcb007100, 24), 50, ExternalMetricType::Type1),
                None,
            )
            .unwrap(),
            0,
        );
        let result = run_spf(&lsdb, 1);
        let routes = external_routes(&lsdb, &result);
        assert_eq!(routes.len(), 1);
        // Type 1 always beats type 2 (§16.4 (6)): 4 + 50 = 54 < type-2's 1.
        assert_eq!(routes[0].metric_type, ExternalMetricType::Type1);
        assert_eq!(routes[0].metric, 54);
        assert_eq!(routes[0].asbr, 3);
    }

    #[test]
    fn type2_ties_broken_by_internal_cost() {
        // ASBR 8 and ASBR 9 both advertise 198.51.100.0/24 type-2 metric
        // 5; ASBR 8 is nearer. The nearer one must win.
        let mut lsdb = Lsdb::new();
        let link = |adv: u32, to: u32, metric: u16| {
            let mut lsa = Lsa {
                header: LsaHeader {
                    ls_age: 0,
                    options: 0x02,
                    ls_type: LsaTypeV2::RouterLsa as u16,
                    link_state_id: adv,
                    advertising_router: adv,
                    ls_sequence_number: INITIAL_SEQUENCE_NUMBER,
                    ls_checksum: 0,
                    length: 0,
                },
                body: crate::spf::encode_router_lsa_body(
                    0,
                    vec![crate::lsa::RouterLink {
                        link_id: to,
                        link_data: 0,
                        link_type: 1,
                        tos: 0,
                        metric,
                    }],
                ),
            };
            lsa.finalize();
            lsa
        };
        lsdb.install(link(1, 8, 3), 0);
        lsdb.install(link(8, 1, 3), 0);
        lsdb.install(link(1, 9, 9), 0);
        lsdb.install(link(9, 1, 9), 0);
        for asbr in [8u32, 9u32] {
            lsdb.install(
                originate_external_lsa(
                    asbr,
                    &ExternalDestination::new(net(0xc6336400, 24), 5, ExternalMetricType::Type2),
                    None,
                )
                .unwrap(),
                0,
            );
        }
        let result = run_spf(&lsdb, 1);
        let routes = external_routes(&lsdb, &result);
        assert_eq!(routes.len(), 1);
        assert_eq!(routes[0].asbr, 8);
        assert_eq!(routes[0].internal_cost, 3);
    }

    #[test]
    fn forwarding_address_must_be_covered() {
        // R1's stub network 10.1.0.0/16 (metric 2) covers the forwarding
        // address 10.1.7.7; an external via that FA is usable, one via an
        // uncovered FA is not.
        let mut lsdb = Lsdb::new();
        let mut r1 = Lsa {
            header: LsaHeader {
                ls_age: 0,
                options: 0x02,
                ls_type: LsaTypeV2::RouterLsa as u16,
                link_state_id: 1,
                advertising_router: 1,
                ls_sequence_number: INITIAL_SEQUENCE_NUMBER,
                ls_checksum: 0,
                length: 0,
            },
            body: crate::spf::encode_router_lsa_body(
                0,
                vec![crate::lsa::RouterLink {
                    link_id: 0x0a010000,
                    link_data: 0xffff0000,
                    link_type: 3,
                    tos: 0,
                    metric: 2,
                }],
            ),
        };
        r1.finalize();
        lsdb.install(r1, 0);
        // ASBR 2 is a direct neighbor.
        let mut r2 = Lsa {
            header: LsaHeader {
                ls_age: 0,
                options: 0x02,
                ls_type: LsaTypeV2::RouterLsa as u16,
                link_state_id: 2,
                advertising_router: 2,
                ls_sequence_number: INITIAL_SEQUENCE_NUMBER,
                ls_checksum: 0,
                length: 0,
            },
            body: crate::spf::encode_router_lsa_body(
                0,
                vec![crate::lsa::RouterLink {
                    link_id: 1,
                    link_data: 0,
                    link_type: 1,
                    tos: 0,
                    metric: 6,
                }],
            ),
        };
        r2.finalize();
        lsdb.install(r2, 0);
        // Covering FA: 10.1.7.7 inside 10.1.0.0/16.
        let mut covered =
            ExternalDestination::new(net(0xc6336400, 24), 9, ExternalMetricType::Type2);
        covered.forwarding_addr = 0x0a010707;
        lsdb.install(originate_external_lsa(2, &covered, None).unwrap(), 0);
        // Uncovering FA: 10.99.0.1 outside every known prefix.
        let mut uncovered =
            ExternalDestination::new(net(0xc6336500, 24), 9, ExternalMetricType::Type2);
        uncovered.forwarding_addr = 0x0a630001;
        lsdb.install(originate_external_lsa(2, &uncovered, None).unwrap(), 0);
        let result = run_spf(&lsdb, 1);
        let routes = external_routes(&lsdb, &result);
        assert_eq!(routes.len(), 1);
        assert_eq!(routes[0].prefix, net(0xc6336400, 24));
        assert_eq!(routes[0].forwarding_addr, 0x0a010707);
    }
}

// ---------------------------------------------------------------------------
// OSPFv3 §4.8.5 tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod v3_tests {
    use super::*;
    use crate::lsa::v3::{
        originate_v3_as_external_lsa, originate_v3_inter_area_router_lsa, V3ExternalDestination,
        V3Prefix,
    };
    use crate::lsa::v3::{
        originate_v3_intra_area_prefix_lsa, originate_v3_link_lsa, originate_v3_router_lsa,
        LINK_TYPE_POINTTOPOINT, ROUTER_BIT_V6,
    };
    use crate::spf::run_spf_v3;

    fn fe80(host: u8) -> [u8; 16] {
        let mut a = [0u8; 16];
        a[0] = 0xfe;
        a[1] = 0x80;
        a[15] = host;
        a
    }

    /// 2001:db8:0:hn::/64 — a /64 whose significant bits fit the wire.
    fn net64(host: u8) -> V3Prefix {
        let mut a = [0u8; 16];
        a[0] = 0x20;
        a[1] = 0x01;
        a[2] = 0x0d;
        a[3] = 0xb8;
        a[7] = host;
        V3Prefix {
            prefix_len: 64,
            options: 0,
            metric: 0,
            addr: a,
        }
    }

    fn ext_prefix(bytes6: [u8; 6], len: u8) -> Prefix {
        let mut a = [0u8; 16];
        a[..6].copy_from_slice(&bytes6);
        Prefix::new_v6(a, len)
    }

    /// r1 - r2 p2p LSDB (Router-LSAs + Link-LSAs), metric 10.
    fn v3_p2p_lsdb(r1: u32, r2: u32) -> Lsdb {
        let mut db = Lsdb::new();
        let mk = |from_if: u32, to_if: u32, to: u32| crate::lsa::v3::V3RouterLink {
            link_type: LINK_TYPE_POINTTOPOINT,
            metric: 10,
            interface_id: from_if,
            neighbor_interface_id: to_if,
            neighbor_router_id: to,
        };
        db.install(
            originate_v3_router_lsa(r1, ROUTER_BIT_V6, 0x13, &[mk(5, 3, r2)], None).unwrap(),
            0,
        );
        db.install(
            originate_v3_router_lsa(r2, ROUTER_BIT_V6, 0x13, &[mk(3, 5, r1)], None).unwrap(),
            0,
        );
        db.install(
            originate_v3_link_lsa(r1, 5, 1, 0x13, fe80(1), vec![], None).unwrap(),
            0,
        );
        db.install(
            originate_v3_link_lsa(r2, 3, 1, 0x13, fe80(2), vec![], None).unwrap(),
            0,
        );
        db
    }

    /// An intra-area ASBR: r2's 0x4005 (type 2, metric 100) installs at
    /// the external metric with the SPF distance as the internal leg;
    /// the type 1 form adds it.
    #[test]
    fn v3_external_intra_area_asbr() {
        let (r1, r2) = (0x0a00_0001, 0x0a00_0002);
        let mut db = v3_p2p_lsdb(r1, r2);
        let p = ext_prefix([0x20, 0x01, 0x0d, 0xb8, 0xbe, 0xef], 48);
        let dest = V3ExternalDestination::new(p, 100, true);
        db.install(originate_v3_as_external_lsa(r2, 1, &dest, None).unwrap(), 0);

        let spf = run_spf_v3(&db, r1);
        let routes = external_routes_v3(&db, &spf);
        assert_eq!(routes.len(), 1);
        let r = &routes[0];
        assert_eq!(r.prefix, p);
        assert_eq!(r.metric, 100, "type 2: external metric only");
        assert_eq!(r.metric_type, ExternalMetricType::Type2);
        assert_eq!(r.internal_cost, 10, "the SPF distance to the ASBR");
        assert_eq!(r.asbr, r2);
        assert_eq!(r.border_router, None);
        assert_eq!(r.forwarding_addr, None);

        // The type 1 form: cost-to-ASBR + external metric.
        let dest1 = V3ExternalDestination::new(p, 100, false);
        let mut db1 = v3_p2p_lsdb(r1, r2);
        db1.install(
            originate_v3_as_external_lsa(r2, 1, &dest1, None).unwrap(),
            0,
        );
        let spf1 = run_spf_v3(&db1, r1);
        let routes1 = external_routes_v3(&db1, &spf1);
        assert_eq!(routes1[0].metric, 110, "type 1: internal + external");
        assert_eq!(routes1[0].metric_type, ExternalMetricType::Type1);
    }

    /// §16.4 (b) v3 form: the ASBR sits in another area — a 0x2004 from
    /// the reachable border router r2 resolves r3's leg
    /// (dist(r2) + 0x2004 metric); the 0x4005's LS ID is irrelevant.
    #[test]
    fn v3_external_inter_area_asbr_via_2004() {
        let (r1, r2, r3) = (0x0a00_0001, 0x0a00_0002, 0x0a00_0003);
        let mut db = v3_p2p_lsdb(r1, r2);
        // r2's inter-area-router-LSA: destination ASBR r3, metric 5.
        db.install(
            originate_v3_inter_area_router_lsa(r2, r3, 0x13, r3, 5, None).unwrap(),
            0,
        );
        // r3's external: type 2 metric 100. LS ID arbitrary (99).
        let p = ext_prefix([0x20, 0x01, 0x0d, 0xb8, 0xca, 0xfe], 48);
        let dest = V3ExternalDestination::new(p, 100, true);
        db.install(
            originate_v3_as_external_lsa(r3, 99, &dest, None).unwrap(),
            0,
        );

        let spf = run_spf_v3(&db, r1);
        let routes = external_routes_v3(&db, &spf);
        assert_eq!(routes.len(), 1);
        let r = &routes[0];
        assert_eq!(r.prefix, p);
        assert_eq!(r.metric, 100);
        assert_eq!(r.internal_cost, 15, "dist(r2)=10 + 0x2004 metric 5");
        assert_eq!(r.border_router, Some(r2), "the ASBR leg came via r2");
        assert_eq!(r.asbr, r3);
    }

    /// §16.4 (c) v3 form: an F-bit forwarding address must be covered by
    /// an intra-area or summary route; the covering route's metric is
    /// the internal leg. Link-local and uncovered FAs yield nothing.
    #[test]
    fn v3_external_forwarding_address_validation() {
        let (r1, r2) = (0x0a00_0001, 0x0a00_0002);
        let mut db = v3_p2p_lsdb(r1, r2);
        // r2's own /64 — covers a FA inside it at metric 10.
        let p2 = net64(2);
        db.install(
            originate_v3_intra_area_prefix_lsa(
                r2,
                1,
                crate::lsa::v3::LS_TYPE_ROUTER,
                0,
                r2,
                vec![p2.clone()],
                None,
            )
            .unwrap(),
            0,
        );
        let fa_in: [u8; 16] = p2.addr; // inside 2001:db8:0:2::/64
                                       // (a) FA covered by the intra-area route.
        let p_a = ext_prefix([0x20, 0x01, 0x0d, 0xb8, 0xaa, 0x00], 48);
        let mut dest_a = V3ExternalDestination::new(p_a, 30, true);
        dest_a.forwarding_addr = Some(fa_in);
        db.install(
            originate_v3_as_external_lsa(r2, 1, &dest_a, None).unwrap(),
            0,
        );
        // (b) FA outside every known prefix.
        let p_b = ext_prefix([0x20, 0x01, 0x0d, 0xb8, 0xbb, 0x00], 48);
        let mut dest_b = V3ExternalDestination::new(p_b, 30, true);
        dest_b.forwarding_addr = Some([0x20, 0x01, 0x0d, 0xb9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        db.install(
            originate_v3_as_external_lsa(r2, 2, &dest_b, None).unwrap(),
            0,
        );
        // (c) Link-local FA — illegal per §A.4.7, dropped.
        let p_c = ext_prefix([0x20, 0x01, 0x0d, 0xb8, 0xcc, 0x00], 48);
        let mut dest_c = V3ExternalDestination::new(p_c, 30, true);
        dest_c.forwarding_addr = Some(fe80(9));
        db.install(
            originate_v3_as_external_lsa(r2, 3, &dest_c, None).unwrap(),
            0,
        );

        let spf = run_spf_v3(&db, r1);
        let routes = external_routes_v3(&db, &spf);
        assert_eq!(routes.len(), 1, "only the covered FA survives");
        assert_eq!(routes[0].prefix, p_a);
        assert_eq!(routes[0].internal_cost, 10, "the covering /64's metric");
        assert_eq!(routes[0].forwarding_addr, Some(IpAddr::V6(fa_in)));
        assert_eq!(routes[0].asbr, r2, "the LSA's advertising router");
    }

    /// §16.4 (1)/(6) filters: LSInfinity and NU-marked externals are
    /// skipped; for identical prefixes type 1 beats type 2 and the
    /// lower external metric wins within a type.
    #[test]
    fn v3_external_filters_and_preference() {
        let (r1, r2) = (0x0a00_0001, 0x0a00_0002);
        let mut db = v3_p2p_lsdb(r1, r2);
        let p = ext_prefix([0x20, 0x01, 0x0d, 0xb8, 0x0d, 0x00], 48);
        // Type 1 metric 10 → 20; type 2 metric 300 (loses); type 2
        // metric 50 (wins among type 2 but still loses to type 1).
        let t1 = V3ExternalDestination::new(p, 10, false);
        let t2_big = V3ExternalDestination::new(p, 300, true);
        let t2_small = V3ExternalDestination::new(p, 50, true);
        db.install(originate_v3_as_external_lsa(r2, 1, &t1, None).unwrap(), 0);
        db.install(
            originate_v3_as_external_lsa(r2, 2, &t2_big, None).unwrap(),
            0,
        );
        db.install(
            originate_v3_as_external_lsa(r2, 3, &t2_small, None).unwrap(),
            0,
        );
        // LSInfinity and NU-marked destinations are skipped.
        let p_inf = ext_prefix([0x20, 0x01, 0x0d, 0xb8, 0x0e, 0x00], 48);
        let mut inf = V3ExternalDestination::new(p_inf, 0x00ff_ffff, true);
        inf.metric = 0x00ff_ffff;
        db.install(originate_v3_as_external_lsa(r2, 4, &inf, None).unwrap(), 0);
        let p_nu = ext_prefix([0x20, 0x01, 0x0d, 0xb8, 0x0f, 0x00], 48);
        let mut nu = V3ExternalDestination::new(p_nu, 10, true);
        nu.prefix = Prefix::new_v6(
            {
                let mut a = [0u8; 16];
                a[..6].copy_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0x0f, 0x00]);
                a
            },
            48,
        );
        db.install(originate_v3_as_external_lsa(r2, 5, &nu, None).unwrap(), 0);
        // Manually set the NU bit on the LSA's prefix (the originator
        // always clears it — §4.4.3.6). A fresh instance with a higher
        // sequence replaces the clean one.
        let key = crate::lsa::LsaKey {
            ls_type: crate::lsa::v3::LS_TYPE_AS_EXTERNAL,
            link_state_id: 5,
            advertising_router: r2,
        };
        if let Some(entry) = db.get(&key) {
            let mut lsa = entry.lsa.clone();
            lsa.body[5] = crate::lsa::v3::PREFIX_OPT_NU;
            lsa.header.ls_sequence_number = entry.lsa.header.ls_sequence_number + 1;
            lsa.finalize();
            db.install(lsa, 0);
        }

        let spf = run_spf_v3(&db, r1);
        let routes = external_routes_v3(&db, &spf);
        assert_eq!(routes.len(), 1, "type 1 wins over both type 2s");
        assert_eq!(routes[0].prefix, p);
        assert_eq!(routes[0].metric, 20);
        assert_eq!(routes[0].metric_type, ExternalMetricType::Type1);
        assert_eq!(routes[0].internal_cost, 10);
    }
}
