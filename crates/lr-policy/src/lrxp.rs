//! LRXP exchange-plane record access for policy evaluation (issue #81).
//!
//! The filter DSL exposes the scope-1 records a route carries under the
//! private `LrExchangePlaneRecords` attribute tag (`lr-bgp::path::AttrType`,
//! value 254) so an operator can adjust `local-pref` / `MED` based on
//! them. The store is populated at ingress by `lr-bgp::fsm` (the
//! `consume_exchange_plane` hook) and rides the route through Adj-RIB-In
//! to the filter; this module decodes it just-in-time for the filter
//! read.
//!
//! All accessors are `#[cfg(feature = "exchange-plane")]` — the codec
//! lives in `lr-bgp::extensions::exchange_plane`, gated by the same
//! feature. The module compiles to nothing on a feature-less build.
//!
//! ## Fallback (issue #81 requirement)
//!
//! When the peer does not advertise the LRXP capability, the route
//! carries no `LrExchangePlaneRecords` attribute and every accessor
//! returns its absent default (`0` for ints, `false` for bools, `None`
//! for `Option`, an empty `String` for the policy digests). A filter
//! that adjusts `local-pref` based on `bgp.lrxp.hint.rank` therefore
//! no-ops on non-LRXP peers — the graceful degradation the issue
//! requires. The `bgp.lrxp.verified` predicate is the single bool an
//! operator gates on when a policy should apply only to LRXP-carrying
//! routes; `bgp.lrxp.partial_transit` distinguishes the
//! forwarding-material case (the attribute crossed a non-lr hop).
//!
//! ## Session-level vs per-route (issue #81 requirement)
//!
//! Policy-intent records are nominally per-session (one per address
//! family per session), but the wire shape re-attaches them to every
//! NLRI the session advertises, so the per-route read is the correct
//! granularity for a filter that adjusts `local-pref` — the route the
//! filter sees carries its session's current policy intent. Hints and
//! provenance are per-route by construction (the sender builds one
//! record set per advertised prefix). The per-session snapshot the
//! daemon keeps (`DefaultRouter::exchange_plane_records`) is the
//! embedder API; the per-route store these accessors read is the filter
//! API — same record set, two views.
//!
//! ## Performance
//!
//! The store decode is a single pass over the TLV stream; the codec is
//! allocation-light (one `Vec<Record>` per record set). A hot-path
//! filter that reads `bgp.lrxp.hint.rank` pays one BTreeMap lookup +
//! one TLV decode per route. The peephole pass does not fuse
//! `bgp.lrxp.*` reads into `BranchFieldIntCmp` (the read is not a
//! single `get_u32_be`), so the unfused `LoadField; Push; Bin; JumpIf*`
//! sequence runs — acceptable for an advisory attribute that rides a
//! minority of routes.

#![cfg(feature = "exchange-plane")]

use lr_bgp::extensions::exchange_plane as xp;
use lr_bgp::path::AttrType;
use lr_core::attr::AttrTag;
use lr_core::rib::Route;

/// The LRXP store kind the route carries, or `None` when the route has
/// no `LrExchangePlaneRecords` attribute (the fallback case — the peer
/// did not advertise the capability, or the record set was dropped at
/// ingress). Exposed so the filter DSL's `defined(bgp.lrxp.verified)`
/// can distinguish "no attribute" from "present but unverified".
pub fn store_kind(route: &Route) -> Option<u8> {
    let a = route
        .attributes
        .get(AttrTag::raw(AttrType::LrExchangePlaneRecords.to_u8()))?;
    let (kind, _payload) = xp::load_store(&a.value)?;
    Some(kind)
}

/// True when the route carries a verified LRXP record set (the tag
/// checked at ingress; the record set is consumable). `false` when the
/// route carries no LRXP attribute (the fallback case), when it
/// carries partial-transit forwarding material (a non-lr hop crossed
/// the path — `bgp.lrxp.partial_transit` reports that case), or when
/// the store is malformed.
pub fn verified(route: &Route) -> bool {
    matches!(store_kind(route), Some(k) if k == xp::STORE_VERIFIED)
}

/// True when the route carries partial-transit LRXP forwarding material
/// (the attribute arrived with the Partial bit set — a non-lr speaker
/// between two lr speakers re-emitted it byte-identically, design §7).
/// The record set is not consumable here; the filter should treat the
/// route as if it carried no LRXP for policy purposes but can log the
/// partial-transit signal.
pub fn partial_transit(route: &Route) -> bool {
    matches!(store_kind(route), Some(k) if k == xp::STORE_PARTIAL_RAW)
}

/// The decoded record set the route carries, or `None` when the route
/// has no verified store (absent, partial-transit, or malformed). The
/// internal helper the typed accessors consult — kept `pub` so an
/// embedder writing a custom filter context can read the full record
/// set the way the DSL does.
pub fn record_set(route: &Route) -> Option<xp::ExchangeRecord> {
    let a = route
        .attributes
        .get(AttrTag::raw(AttrType::LrExchangePlaneRecords.to_u8()))?;
    let (kind, payload) = xp::load_store(&a.value)?;
    if kind != xp::STORE_VERIFIED {
        return None;
    }
    xp::ExchangeRecord::decode(payload).ok()
}

/// The first `HintRecord` in the route's record set (design §5.1: one
/// hint per announced prefix; the prototype attaches exactly one).
/// `None` when the route carries no verified store or no hint record.
pub fn hint(route: &Route) -> Option<xp::HintRecord> {
    let set = record_set(route)?;
    set.records.iter().find_map(|r| match r {
        xp::Record::Hint(h) => Some(*h),
        _ => None,
    })
}

/// The sender's best-path rank for this path among its alternates
/// (design §5.1: 1 = the path the sender itself uses). `0` when the
/// route carries no verified hint record — the absent default a filter
/// reads when the peer does not run the plane.
pub fn hint_rank(route: &Route) -> u8 {
    hint(route).map(|h| h.rank).unwrap_or(0)
}

/// The sender's route-flap figure of merit for the prefix (design
/// §5.1: 0 when damping is off). `0` when the route carries no verified
/// hint record.
pub fn hint_damp_fom(route: &Route) -> u16 {
    hint(route).map(|h| h.damp_fom).unwrap_or(0)
}

/// The sender's IGP cost from its decision point to this path's next
/// hop (design §5.1: the quantity the RFC 4271 §9.1.2.2 tie-break rules
/// assume "all the BGP speakers within an autonomous system can
/// ascertain" and that inter-AS receivers otherwise cannot see). `0`
/// when the route carries no verified hint record.
pub fn hint_igp_cost(route: &Route) -> u32 {
    hint(route).map(|h| h.igp_cost).unwrap_or(0)
}

/// The first `PolicyIntent` record in the route's record set (design
/// §5.2: one per address family per session). `None` when the route
/// carries no verified store or no policy record.
pub fn policy(route: &Route) -> Option<xp::PolicyIntent> {
    let set = record_set(route)?;
    set.records.iter().find_map(|r| match r {
        xp::Record::Policy(p) => Some(*p),
        _ => None,
    })
}

/// The sender's RFC 9234 role claim for this session (design §5.2:
/// 0 = provider, 1 = customer, 2 = RS, 3 = RS-client, 4 = peer, 255 =
/// unspecified; advisory — the receiver cross-checks against its own
/// configured role). `255` (unspecified) when the route carries no
/// verified policy record.
pub fn policy_role(route: &Route) -> u8 {
    policy(route).map(|p| p.role).unwrap_or(255)
}

/// The sender's SipHash-2-4 import-filter digest as a lowercase hex
/// string (design §5.2: a fingerprint of the filter set, not the filter
/// set itself — two sessions reporting the same digest announce the
/// same effective filter). Empty string when the route carries no
/// verified policy record. The hex shape lets a filter compare digests
/// across sessions with `==` without a byte-literal extension to the
/// DSL.
pub fn policy_import_digest_hex(route: &Route) -> String {
    policy(route)
        .map(|p| digest_to_hex(&p.import_digest))
        .unwrap_or_default()
}

/// The sender's SipHash-2-4 export-filter digest as a lowercase hex
/// string — see [`policy_import_digest_hex`].
pub fn policy_export_digest_hex(route: &Route) -> String {
    policy(route)
        .map(|p| digest_to_hex(&p.export_digest))
        .unwrap_or_default()
}

/// Lowercase hex encoding of an 8-byte digest. Inline so the compiler
/// can fold the constant-length loop; avoids pulling a `hex` dependency
/// for a fixed-width conversion.
fn digest_to_hex(digest: &[u8; 8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(16);
    for b in digest {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

/// The first `OriginAttestation` record in the route's record set
/// (design §5.3: added by the originating lr speaker). `None` when the
/// route carries no verified store or no origin record.
pub fn origin(route: &Route) -> Option<xp::OriginAttestation> {
    let set = record_set(route)?;
    set.records.iter().find_map(|r| match r {
        xp::Record::Origin(o) => Some(*o),
        _ => None,
    })
}

/// The origin AS the attestation authorises for this announcement set
/// (design §5.3). `0` when the route carries no verified origin record.
pub fn origin_as(route: &Route) -> u32 {
    origin(route).map(|o| o.origin_as).unwrap_or(0)
}

/// The maximum prefix length the origin authorises for this
/// announcement set (design §5.3: the ROA maxLength idea, RFC 6811 §3,
/// without the PKI). `0` when the route carries no verified origin
/// record.
pub fn origin_max_valid_len(route: &Route) -> u8 {
    origin(route).map(|o| o.max_valid_len).unwrap_or(0)
}

/// The absolute timestamp after which downstream speakers stop
/// trusting the record (design §5.3). `0` when the route carries no
/// verified origin record.
pub fn origin_expiry(route: &Route) -> u32 {
    origin(route).map(|o| o.expiry).unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use lr_bgp::extensions::exchange_plane::{
        ExchangeKey, ExchangePlaneConfig, ExchangeRecord, HintRecord, OriginAttestation,
        PolicyIntent, Record, STORE_PARTIAL_RAW, STORE_VERIFIED,
    };
    use lr_core::addr::Prefix;
    use lr_core::attr::Attribute;
    use lr_core::nlri::NlriFamily;
    use lr_core::rib::{Preference, Protocol, RouteKey, RouteOrigin};

    fn route_with(store: Option<(u8, &[u8])>) -> Route {
        let prefix: Prefix = "203.0.113.0/24".parse().unwrap();
        let mut r = Route {
            key: RouteKey::new(prefix, NlriFamily::IPV4_UNICAST),
            origin: RouteOrigin { proto: 1, peer: 0 },
            protocol: Protocol::Bgp,
            preference: Preference::new(20, 100),
            next_hop: None,
            attributes: lr_core::attr::Attributes::new(),
            age_ms: 0,
            path_id: 0,
            tag: None,
        };
        if let Some((kind, payload)) = store {
            let mut value = Vec::with_capacity(1 + payload.len());
            value.push(kind);
            value.extend_from_slice(payload);
            r.attributes.insert(Attribute {
                tag: AttrTag::raw(AttrType::LrExchangePlaneRecords.to_u8()),
                flags: 0x80,
                value,
            });
        }
        r
    }

    fn signed_record_set(records: Vec<Record>) -> Vec<u8> {
        let key = ExchangeKey::hmac_sha256(1, "test-key");
        let mut record = ExchangeRecord::new(1, key.id, [0u8; 8], 1);
        record.records = records;
        record.sign(&key);
        record.encode()
    }

    fn hint_record() -> Vec<u8> {
        signed_record_set(vec![Record::Hint(HintRecord {
            rank: 2,
            damp_fom: 500,
            igp_cost: 1234,
        })])
    }

    fn policy_record() -> Vec<u8> {
        signed_record_set(vec![Record::Policy(PolicyIntent {
            role: 1,
            import_digest: [0xaa; 8],
            export_digest: [0xbb; 8],
        })])
    }

    fn origin_record() -> Vec<u8> {
        signed_record_set(vec![Record::Origin(OriginAttestation {
            origin_as: 64512,
            max_valid_len: 24,
            expiry: 1_700_000_000,
        })])
    }

    fn combined_record() -> Vec<u8> {
        signed_record_set(vec![
            Record::Hint(HintRecord {
                rank: 3,
                damp_fom: 100,
                igp_cost: 50,
            }),
            Record::Policy(PolicyIntent {
                role: 4,
                import_digest: [0x01; 8],
                export_digest: [0x02; 8],
            }),
            Record::Origin(OriginAttestation {
                origin_as: 65000,
                max_valid_len: 48,
                expiry: 1_800_000_000,
            }),
        ])
    }

    #[test]
    fn absent_route_reads_as_defaults() {
        // Issue #81 fallback: a route with no LRXP attribute (the peer
        // did not advertise the capability) reads as 0 / false / "".
        let r = route_with(None);
        assert!(!verified(&r));
        assert!(!partial_transit(&r));
        assert_eq!(hint_rank(&r), 0);
        assert_eq!(hint_damp_fom(&r), 0);
        assert_eq!(hint_igp_cost(&r), 0);
        assert_eq!(policy_role(&r), 255);
        assert!(policy_import_digest_hex(&r).is_empty());
        assert!(policy_export_digest_hex(&r).is_empty());
        assert_eq!(origin_as(&r), 0);
        assert_eq!(origin_max_valid_len(&r), 0);
        assert_eq!(origin_expiry(&r), 0);
    }

    #[test]
    fn verified_hint_round_trips() {
        let payload = hint_record();
        let r = route_with(Some((STORE_VERIFIED, &payload)));
        assert!(verified(&r));
        assert!(!partial_transit(&r));
        assert_eq!(hint_rank(&r), 2);
        assert_eq!(hint_damp_fom(&r), 500);
        assert_eq!(hint_igp_cost(&r), 1234);
    }

    #[test]
    fn verified_policy_round_trips() {
        let payload = policy_record();
        let r = route_with(Some((STORE_VERIFIED, &payload)));
        assert!(verified(&r));
        assert_eq!(policy_role(&r), 1);
        assert_eq!(policy_import_digest_hex(&r), "aaaaaaaaaaaaaaaa");
        assert_eq!(policy_export_digest_hex(&r), "bbbbbbbbbbbbbbbb");
    }

    #[test]
    fn verified_origin_round_trips() {
        let payload = origin_record();
        let r = route_with(Some((STORE_VERIFIED, &payload)));
        assert!(verified(&r));
        assert_eq!(origin_as(&r), 64512);
        assert_eq!(origin_max_valid_len(&r), 24);
        assert_eq!(origin_expiry(&r), 1_700_000_000);
    }

    #[test]
    fn verified_combined_record_reads_all_classes() {
        let payload = combined_record();
        let r = route_with(Some((STORE_VERIFIED, &payload)));
        assert!(verified(&r));
        // Hint reads.
        assert_eq!(hint_rank(&r), 3);
        assert_eq!(hint_damp_fom(&r), 100);
        assert_eq!(hint_igp_cost(&r), 50);
        // Policy reads.
        assert_eq!(policy_role(&r), 4);
        assert_eq!(policy_import_digest_hex(&r), "0101010101010101");
        assert_eq!(policy_export_digest_hex(&r), "0202020202020202");
        // Origin reads.
        assert_eq!(origin_as(&r), 65000);
        assert_eq!(origin_max_valid_len(&r), 48);
        assert_eq!(origin_expiry(&r), 1_800_000_000);
    }

    #[test]
    fn partial_transit_store_is_not_verified() {
        // Design §7: a Partial-bit record crossed a non-lr hop — it
        // is forwarding material, not consumable here. The store kind
        // is STORE_PARTIAL_RAW; `verified` is false,
        // `partial_transit` is true, and the typed record accessors
        // return their absent defaults.
        let raw = [0xde, 0xad, 0xbe, 0xef];
        let r = route_with(Some((STORE_PARTIAL_RAW, &raw)));
        assert!(!verified(&r));
        assert!(partial_transit(&r));
        assert_eq!(hint_rank(&r), 0);
        assert_eq!(policy_role(&r), 255);
        assert_eq!(origin_as(&r), 0);
    }

    #[test]
    fn malformed_store_reads_as_absent() {
        // A store with a bad kind prefix or a truncated payload is
        // treated as absent (design §8: fail-open for route data).
        let r = route_with(Some((99u8, &[])));
        assert!(!verified(&r));
        assert!(!partial_transit(&r));
        assert_eq!(hint_rank(&r), 0);

        // A STORE_VERIFIED prefix with a payload that does not decode
        // as an ExchangeRecord is also absent.
        let bad = [0xff; 10];
        let r2 = route_with(Some((STORE_VERIFIED, &bad)));
        assert!(!verified(&r2));
        assert_eq!(hint_rank(&r2), 0);
    }

    #[test]
    fn issue_81_canonical_idiom_no_ops_on_non_lrxp_peer() {
        // The graceful-degradation check: a filter that adjusts
        // local-pref based on `bgp.lrxp.hint.rank` no-ops on a route
        // from a non-LRXP peer. The accessor returns 0; the filter's
        // `rank > 1` test is false; the local-pref write does not
        // fire. This is the issue #81 fallback requirement.
        let r = route_with(None);
        assert_eq!(hint_rank(&r), 0);
        assert!(hint_rank(&r) <= 1);
    }

    // Suppress the unused-import warning for ExchangePlaneConfig — it
    // is part of the public codec surface the embedder pairs with
    // these accessors, and keeping it in the test imports documents
    // the shape without pulling it into the helper bodies.
    #[allow(dead_code)]
    fn _config_doc_anchor() -> ExchangePlaneConfig {
        ExchangePlaneConfig {
            hints: true,
            provenance: true,
            nonce: [0u8; 8],
            keys: vec![ExchangeKey::hmac_sha256(1, "k")],
            policy_role: None,
            policy_import_digest: None,
            policy_export_digest: None,
            provenance_scope: 8,
            origin_base_secs: 0,
            origin_ttl_secs: 0,
        }
    }
}
