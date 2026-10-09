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
#[path = "nssa_tests.rs"]
mod tests;
