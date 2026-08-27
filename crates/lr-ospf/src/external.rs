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
const LS_INFINITY: u32 = 0x00ff_ffff;

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
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExternalDestination {
    pub prefix: Prefix,
    pub metric: u32,
    pub metric_type: ExternalMetricType,
    /// 0 means "forward to the ASBR".
    pub forwarding_addr: u32,
    pub route_tag: u32,
}

impl ExternalDestination {
    pub fn new(prefix: Prefix, metric: u32, metric_type: ExternalMetricType) -> Self {
        Self {
            prefix,
            metric: metric.min(0x00ff_fffe),
            metric_type,
            forwarding_addr: 0,
            route_tag: 0,
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
            ls_type: LsaTypeV2::AsExternalLsa as u8,
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
            ls_type: LsaTypeV2::SummaryAsbrLsa as u8,
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
    fn beats(&self, prev: &Self) -> bool {
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
        key.ls_type == LsaTypeV2::AsExternalLsa as u8
            || key.ls_type == LsaTypeV2::SummaryAsbrLsa as u8
    });
    if !has_externals {
        return Vec::new();
    }

    // §16.4 (b): inter-area ASBR legs from type-4 summary-ASBR-LSAs.
    let mut asbr_legs: BTreeMap<u32, AsbrLeg> = BTreeMap::new();
    for (key, entry) in lsdb.iter() {
        if key.ls_type != LsaTypeV2::SummaryAsbrLsa as u8 {
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
        if key.ls_type != LsaTypeV2::AsExternalLsa as u8 {
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
fn fa_prefix(addr: u32) -> Prefix {
    Prefix::new_v4(addr.to_be_bytes(), 32)
}

/// Longest-prefix match of `prefix` against `table`. Returns the covering
/// entry (prefix length, metric) or `None`.
fn longest_covering(table: &[(Prefix, u64)], prefix: Prefix) -> Option<(u8, u64)> {
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
        assert_eq!(lsa.header.ls_type, LsaTypeV2::AsExternalLsa as u8);
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
        assert_eq!(lsa.header.ls_type, LsaTypeV2::SummaryAsbrLsa as u8);
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
                ls_type: LsaTypeV2::RouterLsa as u8,
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
                ls_type: LsaTypeV2::RouterLsa as u8,
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
                ls_type: LsaTypeV2::RouterLsa as u8,
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
                ls_type: LsaTypeV2::RouterLsa as u8,
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
                    ls_type: LsaTypeV2::RouterLsa as u8,
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
                    ls_type: LsaTypeV2::RouterLsa as u8,
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
                ls_type: LsaTypeV2::RouterLsa as u8,
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
                ls_type: LsaTypeV2::RouterLsa as u8,
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
