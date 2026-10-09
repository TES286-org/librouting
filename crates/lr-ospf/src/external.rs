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
use crate::lsa::{LS_TYPE_E_AS_EXTERNAL, LS_TYPE_E_INTER_ROUTER};
use crate::spf::{SpfResultV3, V3VertexId};

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
    /// The resolved link-local first hop along the ASBR path — the
    /// border router's for inter-area legs, else the ASBR's own (the
    /// v3 next-hop model). Installers override it with the forwarding
    /// address when the F bit is set (a global address needs no
    /// interface disambiguation).
    pub next_hop: Option<IpAddr>,
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

/// The calculation-relevant projection of one external LSA body — the
/// legacy 0x4005 shape (RFC 5340 §A.4.7) and the E-AS-External
/// External-Prefix TLV (RFC 8362 §3.6) decode into this common form.
struct ExternalBodyV3 {
    /// 24-bit external metric (already masked).
    metric: u32,
    e_bit: bool,
    prefix: crate::lsa::v3::V3Prefix,
    /// The global IPv6 forwarding address (F bit / sub-TLV 1).
    forwarding_addr: Option<[u8; 16]>,
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
    external_routes_v3_mode(lsdb, spf_result, false)
}

/// The full Extended-LSA mode of [`external_routes_v3`] (RFC 8362
/// §6.1): E-AS-External-LSAs (0xC025) contribute external prefixes
/// alongside the legacy 0x4005s, E-Inter-Area-Router-LSAs (0xA024)
/// inter-area ASBR legs alongside the 0x2004s, and the
/// forwarding-address covering table admits E-Inter-Area-Prefix
/// summaries (0xA023).
pub fn external_routes_v3_extended(lsdb: &Lsdb, spf_result: &SpfResultV3) -> Vec<ExternalRouteV3> {
    external_routes_v3_mode(lsdb, spf_result, true)
}

fn external_routes_v3_mode(
    lsdb: &Lsdb,
    spf_result: &SpfResultV3,
    extended: bool,
) -> Vec<ExternalRouteV3> {
    // Fast path: areas without any external/ASBR-leg LSA skip the
    // covering table construction entirely (summary routes are not
    // needed).
    let has_externals = lsdb.iter().any(|(key, _)| {
        key.ls_type == LS_TYPE_AS_EXTERNAL
            || key.ls_type == LS_TYPE_INTER_ROUTER
            || (extended
                && (key.ls_type == LS_TYPE_E_AS_EXTERNAL || key.ls_type == LS_TYPE_E_INTER_ROUTER))
    });
    if !has_externals {
        return Vec::new();
    }

    // §16.4 (b) v3 form: inter-area ASBR legs from 0x2004
    // inter-area-router-LSAs, keyed by the destination Router ID in the
    // body. The best (lowest-cost) leg per ASBR wins.
    let mut asbr_legs: BTreeMap<u32, AsbrLegV3> = BTreeMap::new();
    for (key, entry) in lsdb.iter() {
        let e_iar = key.ls_type == LS_TYPE_E_INTER_ROUTER;
        if key.ls_type != LS_TYPE_INTER_ROUTER && !(extended && e_iar) {
            continue;
        }
        let Some(&dist) = spf_result
            .vertices
            .get(&V3VertexId::Router(key.advertising_router))
        else {
            continue; // border router itself unreachable
        };
        let leg = if e_iar {
            match crate::lsa::EInterAreaRouterLsaBody::decode(&entry.lsa.body) {
                Some(b) => (b.0.options, b.0.metric, b.0.dest_router_id),
                None => continue,
            }
        } else {
            match crate::lsa::v3::V3InterAreaRouterBody::decode(&entry.lsa.body) {
                Some(b) => (b.options, b.metric, b.dest_router_id),
                None => continue,
            }
        };
        let (_, metric, dest_router_id) = leg;
        if metric >= LS_INFINITY {
            continue;
        }
        let candidate = AsbrLegV3 {
            cost: dist + u64::from(metric),
            border_router: Some(key.advertising_router),
        };
        let not_better = matches!(
            asbr_legs.get(&dest_router_id),
            Some(prev) if prev.cost <= candidate.cost
        );
        if !not_better {
            asbr_legs.insert(dest_router_id, candidate);
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
    for r in crate::spf::summary_routes_v3_mode(lsdb, spf_result, extended) {
        covering.push((r.prefix, r.metric));
    }

    let mut best: BTreeMap<Prefix, ExternalRouteV3> = BTreeMap::new();
    for (key, entry) in lsdb.iter() {
        let e_ext = key.ls_type == LS_TYPE_E_AS_EXTERNAL;
        if key.ls_type != LS_TYPE_AS_EXTERNAL && !(extended && e_ext) {
            continue;
        }
        let body = if e_ext {
            match crate::lsa::EAsExternalLsaBody::decode(&entry.lsa.body) {
                Some(b) => ExternalBodyV3 {
                    metric: b.0.metric,
                    e_bit: b.0.e_bit,
                    prefix: b.0.prefix,
                    forwarding_addr: b.0.ipv6_fwd_addr,
                },
                None => continue,
            }
        } else {
            match V3AsExternalBody::decode(&entry.lsa.body) {
                Some(b) => ExternalBodyV3 {
                    metric: b.metric & crate::lsa::v3::AS_EXT_METRIC_MASK,
                    e_bit: b.e_bit,
                    prefix: b.prefix,
                    forwarding_addr: b.forwarding_addr,
                },
                None => continue,
            }
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
        let external_metric = u64::from(body.metric);

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
        // The next hop follows the ASBR path: the border router for an
        // inter-area leg, else the ASBR itself.
        let nh_router = border_router.unwrap_or(key.advertising_router);
        let next_hop = spf_result
            .next_hops
            .get(&V3VertexId::Router(nh_router))
            .map(|nh| nh.link_local);
        let candidate = ExternalRouteV3 {
            prefix,
            metric,
            metric_type,
            internal_cost,
            asbr,
            border_router,
            forwarding_addr: body.forwarding_addr.map(IpAddr::V6),
            next_hop,
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
#[path = "external_tests.rs"]
mod tests;

// ---------------------------------------------------------------------------
// OSPFv3 §4.8.5 tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[path = "external_v3_tests.rs"]
mod v3_tests;
