//! Not-So-Stubby Area (NSSA) support — RFC 3101.
//!
//! An NSSA is a stub area (no type-5 AS-external-LSAs and no type-4
//! summary-ASBR-LSAs enter it) whose internal AS boundary routers may
//! still redistribute externals *into* the area as type-7 AS-external
//! LSAs. Type-7s are area-scoped: they flood within their NSSA only.
//! Border routers translate selected type-7s into regular type-5s that
//! then flood the whole AS (§3.2).
//!
//! Wire format notes (RFC 3101 Appendix A/C):
//!
//! - The type-7 body is byte-identical to the type-5 body — mask,
//!   E-bit + 24-bit metric, forwarding address, route tag — so the
//!   [`crate::lsa`] type-5 codec is reused verbatim.
//! - The P-bit ("propagate") lives in the LSA header's options field at
//!   the same position as the Hello/DBD N-bit (bit 3, `0x08`).
//!
//! Selection rules implemented here:
//!
//! - [`originate_nssa_lsa`] enforces §2.3/§2.4: a P-bit-set type-7 must
//!   carry a non-zero forwarding address (otherwise it is not
//!   originated), and the type-7 default (`0.0.0.0/0`) originated by a
//!   border router always has the P-bit clear.
//! - [`nssa_routes`] computes the area's type-7 external candidates
//!   (§2.5): the ASBR — or the forwarding address — must be reachable
//!   through the NSSA itself; a non-zero forwarding address must be
//!   covered by an *intra-area* path within the NSSA (stricter than the
//!   type-5 rule, which also accepts inter-area cover).
//! - [`is_elected_translator`] implements the §3.1 election: among the
//!   area's border routers (B-bit in their router-LSAs, plus the caller
//!   itself) the highest router ID translates; a router with the Nt-bit
//!   set always wins (RFC 3101 Appendix B).

use std::collections::BTreeMap;

use crate::abr::{INITIAL_SEQUENCE_NUMBER, MAX_SEQUENCE_NUMBER};
use crate::external::{
    fa_prefix, longest_covering, ExternalDestination, ExternalMetricType, ExternalRoute,
    LS_INFINITY,
};
use crate::lsa::{
    decode_as_external_body, encode_as_external_body, prefix_len_to_mask, router_lsa_flags,
    AsExternalEntry, Lsa, LsaHeader, LsaTypeV2,
};
use crate::lsdb::Lsdb;
use crate::spf::{SpfResult, VertexId};
use lr_core::addr::{IpAddr, Prefix};

/// The N/P-bit (RFC 3101 Appendix A): options bit 3 (`0x08`). It is the
/// N-bit in Hello/Database Description packets (NSSA capability) and the
/// P-bit in type-7 LSA headers (translation request).
pub const N_P_BIT: u8 = 0x08;

/// Whether a type-7 LSA header carries the P-bit (RFC 3101 §2.4).
pub fn p_bit_set(lsa: &Lsa) -> bool {
    lsa.header.options & N_P_BIT != 0
}

/// One candidate default route an NSSA border router injects into its
/// NSSA (RFC 3101 §2.4): the metric of the default destination.
///
/// With summaries imported (the default, §2.7) the default is advertised
/// as a type-7 LSA with the P-bit clear; when summaries are suppressed
/// the caller originates a plain type-3 summary default instead (see
/// [`crate::abr::SummaryDestination`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NssaDefault {
    pub metric: u32,
}

impl NssaDefault {
    pub fn new(metric: u32) -> Self {
        Self {
            metric: metric.min(LS_INFINITY.saturating_sub(1)),
        }
    }
}

/// Originate a type-7 AS-external-LSA for `dest` (RFC 3101 §2.4).
///
/// The LSA is area-scoped: install it only into the originating NSSA's
/// LSDB. The P-bit is taken from [`ExternalDestination::p_bit`]. The
/// default destination (`0.0.0.0/0`) may carry the P-bit only when
/// originated by an internal NSSA ASBR (§2.4) — border routers use
/// [`originate_nssa_default_lsa`], which forces it clear. Defaults are
/// never translated regardless (§3.2 step (1)).
///
/// Returns `None` for non-IPv4 destinations, when the sequence space is
/// exhausted (§12.1.2), or when the P-bit is set but the forwarding
/// address is zero — §2.3: such a type-7 is not originated at all.
pub fn originate_nssa_lsa(
    router_id: u32,
    dest: &ExternalDestination,
    prev_seq: Option<u32>,
) -> Option<Lsa> {
    let IpAddr::V4(octets) = dest.prefix.addr else {
        return None; // v2 link-state IDs are 32-bit IPv4 networks
    };
    let mask = prefix_len_to_mask(dest.prefix.prefix_len);
    let network = u32::from_be_bytes(octets) & mask;
    // §2.3: "If the P-bit is set, the forwarding address must be
    // non-zero" — otherwise the type-7 is not originated.
    if dest.p_bit && dest.forwarding_addr == 0 {
        return None;
    }
    let seq = match prev_seq {
        None => INITIAL_SEQUENCE_NUMBER,
        Some(MAX_SEQUENCE_NUMBER) => return None,
        Some(p) => p + 1,
    };
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
            options: if dest.p_bit { N_P_BIT } else { 0 },
            ls_type: LsaTypeV2::NssaExternalLsa as u16,
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

/// Build the MaxAge instance that flushes a type-7 LSA from the NSSA
/// (RFC 2328 §14.1 via [`Lsa::maxage_flush`]).
pub fn flush_nssa_lsa(existing: &Lsa) -> Option<Lsa> {
    existing.maxage_flush()
}

/// Originate the NSSA default type-7 LSA (RFC 3101 §2.4): a type-7 for
/// `0.0.0.0/0` with the P-bit clear, a zero forwarding address (traffic
/// follows the border router that originated it) and the configured
/// metric.
pub fn originate_nssa_default_lsa(
    router_id: u32,
    default: &NssaDefault,
    prev_seq: Option<u32>,
) -> Option<Lsa> {
    let mut dest = ExternalDestination::new(
        Prefix::new_v4([0, 0, 0, 0], 0),
        default.metric,
        ExternalMetricType::Type2,
    );
    dest.p_bit = false; // §2.4: border-router defaults are never translated
    originate_nssa_lsa(router_id, &dest, prev_seq)
}

/// The NSSA-side inputs of [`nssa_routes`].
#[derive(Debug, Clone, Copy, Default)]
pub struct NssaCalcOpts {
    /// Whether the calculating router is a border router of the NSSA.
    /// Border routers skip type-7 defaults they would not install
    /// (§2.5 step (3): P-bit clear defaults, and all type-7 defaults
    /// when summary import is suppressed).
    pub border_router: bool,
    /// Whether the NSSA suppresses type-3 summary import ("no-summary"
    /// mode). Border routers then ignore type-7 defaults entirely —
    /// the area's default comes from their own type-3 default (§2.7).
    pub summaries_suppressed: bool,
}

/// RFC 3101 §2.5: compute the type-7 external route candidates for one
/// NSSA. This is the type-7 counterpart of
/// [`crate::external::external_routes`]:
///
/// 1. skip metrics of LSInfinity (§16.4 (1) applies via §2.5);
/// 2. type-7 defaults that the calculating border router must not
///    install are skipped (§2.5 step (3) [NSSA]);
/// 3. the internal leg: with a non-zero forwarding address it must be
///    covered by an **intra-area** path of the NSSA (stricter than
///    type-5's §16.4 (c), which also accepts inter-area cover); with a
///    zero forwarding address the ASBR must be reachable within the
///    NSSA (type-4 legs never exist there);
/// 4. candidates carry §16.4 metric semantics — type 1 adds the
///    internal cost, type 2 uses the external metric only — and the
///    best candidate per prefix is kept (§16.4 (6); type-5 and type-7
///    metrics are directly comparable, §2.5 preamble).
///
/// Like `external_routes`, self-originated LSAs are *not* skipped: the
/// library installs the redistributing router's own externals so they
/// stay visible in Loc-RIB (documented deviation from §2.5 step (2) —
/// the router pipeline models no other external route source).
pub fn nssa_routes(lsdb: &Lsdb, spf_result: &SpfResult, opts: NssaCalcOpts) -> Vec<ExternalRoute> {
    // Fast path: areas without any type-7 LSAs skip the covering table
    // construction entirely.
    if !lsdb
        .iter()
        .any(|(key, _)| key.ls_type == LsaTypeV2::NssaExternalLsa as u16)
    {
        return Vec::new();
    }

    // §2.5 step (3): a type-7's forwarding address must be covered by an
    // intra-area path of the NSSA — unlike type-5s, summaries do not
    // qualify.
    let covering: Vec<(Prefix, u64)> = spf_result
        .stub_routes
        .iter()
        .chain(spf_result.transit_routes.iter())
        .map(|r| (r.prefix, r.metric))
        .collect();

    let mut best: BTreeMap<Prefix, ExternalRoute> = BTreeMap::new();
    for (key, entry) in lsdb.iter() {
        if key.ls_type != LsaTypeV2::NssaExternalLsa as u16 {
            continue;
        }
        let Some(body) = decode_as_external_body(&entry.lsa.body) else {
            continue;
        };
        let metric_type = ExternalMetricType::from_e_bit(body.external_type2());
        let external_metric = body.metric_value();
        if external_metric >= LS_INFINITY {
            continue; // §16.4 (1) via §2.5 step (1)
        }
        let prefix_len = crate::lsa::mask_to_prefix_len(body.network_mask);
        let network = entry.lsa.header.link_state_id & body.network_mask;
        let is_default = prefix_len == 0 && network == 0;
        if is_default && opts.border_router && (opts.summaries_suppressed || !p_bit_set(&entry.lsa))
        {
            // §2.5 step (3) [NSSA]: border routers only install type-7
            // defaults with the P-bit set, and none at all when summary
            // import is suppressed (their own default wins then).
            continue;
        }

        // Internal leg (§2.5 step (3)).
        let internal_cost = if body.forwarding_addr != 0 {
            let Some((_, cost)) = longest_covering(&covering, fa_prefix(body.forwarding_addr))
            else {
                continue; // forwarding address not intra-area reachable in the NSSA
            };
            cost
        } else {
            match spf_result
                .vertices
                .get(&VertexId::Router(key.advertising_router))
            {
                // The ASBR must be reachable over the NSSA itself.
                Some(&dist) => dist,
                None => continue,
            }
        };

        let metric = match metric_type {
            ExternalMetricType::Type1 => internal_cost + u64::from(external_metric),
            ExternalMetricType::Type2 => u64::from(external_metric),
        };
        let prefix = Prefix::new_v4(network.to_be_bytes(), prefix_len);
        let candidate = ExternalRoute {
            prefix,
            metric,
            metric_type,
            internal_cost,
            asbr: key.advertising_router,
            border_router: None,
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

/// RFC 3101 §3.1 translator election, simplified: among the NSSA's
/// border routers — every router whose router-LSA in the area carries
/// the B-bit, plus `router_id` (the caller, a border router by
/// construction) — the highest router ID performs type-7 → type-5
/// translation; a router advertising the Nt-bit (unconditional
/// translator, RFC 3101 Appendix B) beats a merely higher router ID.
///
/// The full rule additionally requires candidates to be reachable "as
/// ASBRs over the AS's transit topology"; this implementation considers
/// NSSA reachability only, which matches single-backbone deployments
/// and is the common FRR/BIRD configuration.
pub fn is_elected_translator(lsdb: &Lsdb, router_id: u32) -> bool {
    for (key, entry) in lsdb.iter() {
        if key.ls_type != LsaTypeV2::RouterLsa as u16 || key.advertising_router == router_id {
            continue;
        }
        let Some(flags) = crate::lsa::router_lsa_flags_byte(&entry.lsa.body) else {
            continue;
        };
        if flags & router_lsa_flags::B == 0 {
            continue; // not a border router
        }
        // §3.1: disabled "if there exists another border router ... whose
        // router-LSA has bit Nt set or who has a higher router ID".
        if flags & router_lsa_flags::NT != 0 || key.advertising_router > router_id {
            return false;
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::external::ExternalMetricType;
    use crate::lsa::{decode_as_external_body, LsaHeader, LsaTypeV2};
    use crate::lsdb::MAX_AGE_SECS;
    use crate::spf::{run_spf, SpfRoute};

    fn net(a: u32, len: u8) -> Prefix {
        Prefix::new_v4(a.to_be_bytes(), len)
    }

    /// A minimal router-LSA: `flags` byte + one p2p link to `neighbor`
    /// at `metric` (enough for both SPF and the election scan). The
    /// V/E/B/Nt bits live in the *high* byte of the 16-bit flags word
    /// (RFC 2328 §A.4.2 diagram).
    fn router_lsa(rid: u32, flags: u8, neighbor: u32, metric: u16) -> Lsa {
        let mut body = Vec::new();
        body.extend_from_slice(&(u16::from(flags) << 8).to_be_bytes());
        body.extend_from_slice(&1u16.to_be_bytes());
        body.extend_from_slice(&neighbor.to_be_bytes());
        body.extend_from_slice(&0u32.to_be_bytes());
        body.push(1); // p2p
        body.push(0); // tos
        body.extend_from_slice(&metric.to_be_bytes());
        Lsa {
            header: LsaHeader {
                ls_age: 0,
                options: 0x02,
                ls_type: LsaTypeV2::RouterLsa as u16,
                link_state_id: rid,
                advertising_router: rid,
                ls_sequence_number: 0x8000_0001,
                ls_checksum: 0,
                length: (LsaHeader::LEN + body.len()) as u16,
            },
            body,
        }
    }

    #[test]
    fn originate_nssa_sets_type_p_bit_and_forwarding_address() {
        let mut dest =
            ExternalDestination::new(net(0xc000_0200, 24), 40, ExternalMetricType::Type2);
        dest.forwarding_addr = 0x0a40_4001; // required with the P-bit set
        let lsa = originate_nssa_lsa(0x0202_0202, &dest, None).unwrap();
        assert_eq!(lsa.header.ls_type, LsaTypeV2::NssaExternalLsa as u16);
        assert_eq!(lsa.header.link_state_id, 0xc000_0200);
        assert_eq!(lsa.header.advertising_router, 0x0202_0202);
        assert_eq!(lsa.header.ls_sequence_number, INITIAL_SEQUENCE_NUMBER);
        assert_eq!(lsa.header.length, 36); // 20 header + 16 body
        assert!(p_bit_set(&lsa), "P-bit from the destination config");
        assert!(lsa.checksum_ok());
        let body = decode_as_external_body(&lsa.body).unwrap();
        assert!(body.external_type2());
        assert_eq!(body.metric_value(), 40);
        assert_eq!(body.forwarding_addr, 0x0a40_4001);
    }

    #[test]
    fn originate_nssa_clear_bit_omits_p() {
        let mut dest = ExternalDestination::new(net(0x0a000000, 8), 50, ExternalMetricType::Type1);
        dest.p_bit = false;
        let lsa = originate_nssa_lsa(1, &dest, Some(0x80000005)).unwrap();
        assert!(!p_bit_set(&lsa));
        assert_eq!(lsa.header.ls_sequence_number, 0x80000006);
        let body = decode_as_external_body(&lsa.body).unwrap();
        assert!(!body.external_type2());
        assert_eq!(body.metric_value(), 50);
    }

    #[test]
    fn originate_nssa_rejects_p_bit_with_zero_forwarding_address() {
        // §2.3: a P-bit-set type-7 must carry a non-zero forwarding
        // address; without one the LSA is not originated.
        let dest = ExternalDestination::new(net(0x0a000000, 8), 50, ExternalMetricType::Type2);
        assert!(dest.p_bit);
        assert!(originate_nssa_lsa(1, &dest, None).is_none());
    }

    #[test]
    fn originate_nssa_rejects_v6_and_sequence_exhaustion() {
        let v6 = Prefix::new_v6([0x20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1], 64);
        let mut dest = ExternalDestination::new(v6, 5, ExternalMetricType::Type2);
        dest.forwarding_addr = 1;
        assert!(originate_nssa_lsa(1, &dest, None).is_none());
        let mut dest = ExternalDestination::new(net(1, 32), 5, ExternalMetricType::Type2);
        dest.forwarding_addr = 1;
        assert!(originate_nssa_lsa(1, &dest, Some(MAX_SEQUENCE_NUMBER)).is_none());
    }

    #[test]
    fn nssa_default_lsa_has_clear_p_and_zero_forwarding() {
        let lsa = originate_nssa_default_lsa(0x0101_0101, &NssaDefault::new(10), None).unwrap();
        assert_eq!(lsa.header.ls_type, LsaTypeV2::NssaExternalLsa as u16);
        assert_eq!(lsa.header.link_state_id, 0);
        assert!(
            !p_bit_set(&lsa),
            "border-router defaults are never translated (§2.4)"
        );
        let body = decode_as_external_body(&lsa.body).unwrap();
        assert_eq!(body.network_mask, 0);
        assert_eq!(body.metric_value(), 10);
        assert!(body.external_type2());
        assert_eq!(body.forwarding_addr, 0);
        // A generic (internal-ASBR) default obeys the same §2.3 rule as
        // every P-bit-set type-7: non-zero forwarding address required.
        let mut dest = ExternalDestination::new(net(0, 0), 10, ExternalMetricType::Type2);
        dest.p_bit = true;
        assert!(originate_nssa_lsa(1, &dest, None).is_none());
        dest.forwarding_addr = 1;
        let lsa = originate_nssa_lsa(1, &dest, None).unwrap();
        assert!(
            p_bit_set(&lsa),
            "internal ASBRs may set P on a default (§2.4)"
        );
    }

    #[test]
    fn flush_ages_to_max() {
        let mut dest = ExternalDestination::new(net(0x0a000000, 8), 50, ExternalMetricType::Type2);
        dest.p_bit = false;
        let lsa = originate_nssa_lsa(1, &dest, None).unwrap();
        let flush = flush_nssa_lsa(&lsa).unwrap();
        assert_eq!(flush.header.ls_age, MAX_AGE_SECS);
        assert_eq!(flush.header.ls_sequence_number, INITIAL_SEQUENCE_NUMBER + 1);
        assert!(flush.checksum_ok());
    }

    #[test]
    fn nssa_routes_type2_with_forwarding_address_intra_cover() {
        // Root 1 -- ASBR 5 (stub net 10.64.64.0/24 metric 2); ASBR 5
        // redistributes a type-7 with the forwarding address inside that
        // stub network.
        let mut lsdb = Lsdb::new();
        lsdb.install(router_lsa(1, 0, 5, 7), 0);
        let mut body = Vec::new();
        body.extend_from_slice(&0u16.to_be_bytes());
        body.extend_from_slice(&1u16.to_be_bytes());
        body.extend_from_slice(&0x0a40_4000u32.to_be_bytes()); // stub network
        body.extend_from_slice(&0x0000_ff00u32.to_be_bytes()); // stub mask
        body.push(3); // stub network
        body.push(0);
        body.extend_from_slice(&2u16.to_be_bytes());
        let asbr_lsa = Lsa {
            header: LsaHeader {
                ls_age: 0,
                options: 0x02,
                ls_type: LsaTypeV2::RouterLsa as u16,
                link_state_id: 5,
                advertising_router: 5,
                ls_sequence_number: 0x8000_0001,
                ls_checksum: 0,
                length: (LsaHeader::LEN + body.len()) as u16,
            },
            body,
        };
        lsdb.install(asbr_lsa, 0);

        let mut dest =
            ExternalDestination::new(net(0xc000_0200, 24), 40, ExternalMetricType::Type2);
        dest.forwarding_addr = 0x0a40_4001;
        let t7 = originate_nssa_lsa(5, &dest, None).unwrap();
        lsdb.install(t7, 0);

        let spf = run_spf(&lsdb, 1);
        let routes = nssa_routes(&lsdb, &spf, NssaCalcOpts::default());
        assert_eq!(routes.len(), 1);
        assert_eq!(routes[0].prefix, net(0xc000_0200, 24));
        assert_eq!(routes[0].metric, 40, "type-2 metric is external-only");
        assert_eq!(
            routes[0].internal_cost, 9,
            "7 to the ASBR + 2 across its stub"
        );
        assert_eq!(routes[0].forwarding_addr, 0x0a40_4001);
        assert_eq!(routes[0].asbr, 5);
    }

    #[test]
    fn nssa_routes_forwarding_address_needs_intra_cover() {
        // The forwarding address is only covered by a type-3 summary —
        // §2.5 step (3) requires an intra-area path, so the type-7 is
        // skipped even though the summary exists.
        let mut lsdb = Lsdb::new();
        let mut dest =
            ExternalDestination::new(net(0xc000_0200, 24), 40, ExternalMetricType::Type2);
        dest.forwarding_addr = 0x0a40_4001;
        let t7 = originate_nssa_lsa(5, &dest, None).unwrap();
        lsdb.install(t7, 0);
        // Summary-LSA covering 10.64.64.0/24 (but no intra-area route).
        let summary = crate::abr::originate_summary_lsa(
            9,
            &crate::abr::SummaryDestination::new(net(0x0a40_4000, 24), 3),
            None,
        )
        .unwrap();
        lsdb.install(summary, 0);

        let spf = run_spf(&lsdb, 1);
        assert!(nssa_routes(&lsdb, &spf, NssaCalcOpts::default()).is_empty());
    }

    #[test]
    fn nssa_routes_type1_sums_internal_cost() {
        // FA = 0: the ASBR itself is the internal leg (intra-area via a
        // p2p link from the calculating root 1 to ASBR 5 at metric 7).
        let mut lsdb = Lsdb::new();
        lsdb.install(router_lsa(1, 0, 5, 7), 0);
        lsdb.install(router_lsa(5, 0, 1, 7), 0);
        let mut dest =
            ExternalDestination::new(net(0xc000_0200, 24), 40, ExternalMetricType::Type1);
        dest.p_bit = false; // FA stays 0
        let t7 = originate_nssa_lsa(5, &dest, None).unwrap();
        lsdb.install(t7, 0);

        let spf = run_spf(&lsdb, 1);
        let routes = nssa_routes(&lsdb, &spf, NssaCalcOpts::default());
        assert_eq!(routes.len(), 1);
        assert_eq!(routes[0].metric, 47, "type-1: internal 7 + external 40");
        assert_eq!(routes[0].internal_cost, 7);
    }

    #[test]
    fn nssa_routes_skips_unreachable_asbr_and_ls_infinity() {
        let mut lsdb = Lsdb::new();
        // No router-LSA for the ASBR at all → unreachable → skipped.
        let mut dest =
            ExternalDestination::new(net(0xc000_0200, 24), 40, ExternalMetricType::Type2);
        dest.p_bit = false;
        lsdb.install(originate_nssa_lsa(5, &dest, None).unwrap(), 0);
        // LSInfinity external → skipped.
        let mut inf =
            ExternalDestination::new(net(0xc000_0300, 24), LS_INFINITY, ExternalMetricType::Type2);
        inf.p_bit = false;
        lsdb.install(originate_nssa_lsa(5, &inf, None).unwrap(), 0);

        let spf = run_spf(&lsdb, 1);
        assert!(nssa_routes(&lsdb, &spf, NssaCalcOpts::default()).is_empty());
    }

    #[test]
    fn nssa_routes_default_install_rules_for_border_routers() {
        // Root 1 -- ASBR 5 (stub 10.64.64.0/24); ASBR 5 originates the
        // type-7 default. P-bit-set defaults carry FA 10.64.64.1 (inside
        // the stub network, so it is intra-area covered).
        fn area_with_default(p_bit: bool) -> Lsdb {
            let mut lsdb = Lsdb::new();
            lsdb.install(router_lsa(1, 0, 5, 7), 0);
            let mut body = Vec::new();
            body.extend_from_slice(&0u16.to_be_bytes());
            body.extend_from_slice(&2u16.to_be_bytes());
            body.extend_from_slice(&1u32.to_be_bytes()); // p2p to root
            body.extend_from_slice(&0u32.to_be_bytes());
            body.push(1);
            body.push(0);
            body.extend_from_slice(&7u16.to_be_bytes());
            body.extend_from_slice(&0x0a40_4000u32.to_be_bytes()); // stub net
            body.extend_from_slice(&0x0000_ff00u32.to_be_bytes()); // mask
            body.push(3);
            body.push(0);
            body.extend_from_slice(&2u16.to_be_bytes());
            lsdb.install(
                Lsa {
                    header: LsaHeader {
                        ls_age: 0,
                        options: 0x02,
                        ls_type: LsaTypeV2::RouterLsa as u16,
                        link_state_id: 5,
                        advertising_router: 5,
                        ls_sequence_number: 0x8000_0001,
                        ls_checksum: 0,
                        length: (LsaHeader::LEN + body.len()) as u16,
                    },
                    body,
                },
                0,
            );
            let mut dest = ExternalDestination::new(net(0, 0), 10, ExternalMetricType::Type2);
            dest.p_bit = p_bit;
            dest.forwarding_addr = if p_bit { 0x0a40_4001 } else { 0 };
            lsdb.install(originate_nssa_lsa(5, &dest, None).unwrap(), 0);
            lsdb
        }
        let spf_of = |lsdb: &Lsdb| run_spf(lsdb, 1);

        // Internal router installs any type-7 default.
        let lsdb = area_with_default(false);
        assert_eq!(
            nssa_routes(&lsdb, &spf_of(&lsdb), NssaCalcOpts::default()).len(),
            1
        );

        // Border router: P-bit clear default skipped (§2.5 step (3))...
        assert_eq!(
            nssa_routes(
                &lsdb,
                &spf_of(&lsdb),
                NssaCalcOpts {
                    border_router: true,
                    summaries_suppressed: false,
                }
            )
            .len(),
            0
        );

        // ...P-bit set default installed...
        let lsdb = area_with_default(true);
        assert_eq!(
            nssa_routes(
                &lsdb,
                &spf_of(&lsdb),
                NssaCalcOpts {
                    border_router: true,
                    summaries_suppressed: false,
                }
            )
            .len(),
            1
        );

        // ...but with suppressed summaries all type-7 defaults are
        // skipped at border routers (§2.7 — the type-3 default wins).
        assert_eq!(
            nssa_routes(
                &lsdb,
                &spf_of(&lsdb),
                NssaCalcOpts {
                    border_router: true,
                    summaries_suppressed: true,
                }
            )
            .len(),
            0
        );
    }

    #[test]
    fn nssa_routes_empty_area_fast_path() {
        let lsdb = Lsdb::new();
        assert!(nssa_routes(&lsdb, &SpfResult::default(), NssaCalcOpts::default()).is_empty());
    }

    #[test]
    fn translator_election_by_b_bit_and_router_id() {
        // Only our own (implicit) candidacy: elected.
        let mut lsdb = Lsdb::new();
        lsdb.install(router_lsa(9, 0, 1, 1), 0); // plain internal router
        assert!(is_elected_translator(&lsdb, 3));

        // A higher-ID border router beats us.
        let mut lsdb = Lsdb::new();
        lsdb.install(router_lsa(9, router_lsa_flags::B, 1, 1), 0);
        assert!(!is_elected_translator(&lsdb, 3), "higher B-bit router wins");

        // A lower-ID border router does not.
        let mut lsdb = Lsdb::new();
        lsdb.install(router_lsa(2, router_lsa_flags::B, 1, 1), 0);
        assert!(is_elected_translator(&lsdb, 3));

        // Nt-bit (unconditional translator) wins regardless of router ID.
        let mut lsdb = Lsdb::new();
        lsdb.install(
            router_lsa(2, router_lsa_flags::B | router_lsa_flags::NT, 1, 1),
            0,
        );
        assert!(!is_elected_translator(&lsdb, 3), "Nt-bit beats higher ID");
    }

    #[test]
    fn n_p_bit_position() {
        // RFC 3101 Appendix A: options bit 3.
        assert_eq!(N_P_BIT, 0x08);
        assert_eq!(router_lsa_flags::B, 0x01);
        assert_eq!(router_lsa_flags::E, 0x02);
        assert_eq!(router_lsa_flags::V, 0x04);
        assert_eq!(router_lsa_flags::NT, 0x10);
    }

    #[test]
    fn spf_route_struct_field_coverage() {
        // Keeps the SpfRoute import honest for future next-hop wiring.
        let r = SpfRoute {
            prefix: net(1, 24),
            metric: 5,
            next_hop: None,
            border_router: None,
        };
        assert_eq!(r.metric, 5);
    }
}
