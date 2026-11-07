//! End-to-end tests for BGP route aggregation (RFC 4271 §9.2.2.2).
//!
//! Route aggregation combines more-specific prefixes into a less-
//! specific aggregate. When at least one specific route exists in the
//! Loc-RIB, the aggregate is originated with:
//! - AS_PATH zeroed (empty AS_SEQUENCE)
//! - ATOMIC_AGGREGATE attribute set
//! - AGGREGATOR attribute (local AS + router ID)
//!
//! When all specifics disappear, the aggregate is withdrawn.

use lr_core::addr::{Asn, IpAddr, Prefix, RouterId};
use lr_router::{AggregateOptions, DefaultRouter, RouterInstance, SessionConfig, SessionHandle};

fn pump(a: &mut DefaultRouter, ha: SessionHandle, b: &mut DefaultRouter, hb: SessionHandle) {
    for _ in 0..32 {
        let out_a = a.drain_output(ha);
        if !out_a.is_empty() {
            b.feed_input(hb, &out_a).unwrap();
        }
        let out_b = b.drain_output(hb);
        if !out_b.is_empty() {
            a.feed_input(ha, &out_b).unwrap();
        }
        if out_a.is_empty() && out_b.is_empty() {
            let late_a = a.drain_output(ha);
            if !late_a.is_empty() {
                b.feed_input(hb, &late_a).unwrap();
                continue;
            }
            return;
        }
    }
}

const V4_A: RouterId = RouterId::from_v4([10, 0, 0, 1]);
const V4_B: RouterId = RouterId::from_v4([10, 0, 0, 2]);

/// When a specific route exists, the aggregate is originated.
#[test]
fn aggregate_originates_when_specific_exists() {
    let mut a = DefaultRouter::new();
    let mut b = DefaultRouter::new();
    let ha = a
        .add_session(
            SessionConfig::bgp(Asn(64512), Asn(64513), V4_A)
                .with_local_address(IpAddr::V4([192, 0, 2, 1])),
        )
        .unwrap();
    let hb = b
        .add_session(
            SessionConfig::bgp(Asn(64513), Asn(64512), V4_B)
                .with_local_address(IpAddr::V4([192, 0, 2, 2])),
        )
        .unwrap();
    a.start_session(ha).unwrap();
    b.start_session(hb).unwrap();
    pump(&mut a, ha, &mut b, hb);

    // Register the aggregate BEFORE any specific exists.
    a.add_aggregate(Prefix::new_v4([203, 0, 113, 0], 24));

    // B originates a /32 within the /24 aggregate.
    b.originate(
        Prefix::new_v4([203, 0, 113, 1], 32),
        Some(IpAddr::V4([192, 0, 2, 2])),
    );
    pump(&mut a, ha, &mut b, hb);

    // A's Loc-RIB must have both the /32 and the /24 aggregate.
    let snap = a.rib_snapshot();
    let has_specific = snap
        .iter()
        .any(|r| r.key.prefix == Prefix::new_v4([203, 0, 113, 1], 32));
    let has_aggregate = snap
        .iter()
        .any(|r| r.key.prefix == Prefix::new_v4([203, 0, 113, 0], 24));
    assert!(has_specific, "the /32 specific must be in Loc-RIB");
    assert!(has_aggregate, "the /24 aggregate must be originated");
}

/// When all specifics disappear, the aggregate is withdrawn.
#[test]
fn aggregate_withdraws_when_specifics_disappear() {
    let mut a = DefaultRouter::new();
    let mut b = DefaultRouter::new();
    let ha = a
        .add_session(
            SessionConfig::bgp(Asn(64512), Asn(64513), V4_A)
                .with_local_address(IpAddr::V4([192, 0, 2, 1])),
        )
        .unwrap();
    let hb = b
        .add_session(
            SessionConfig::bgp(Asn(64513), Asn(64512), V4_B)
                .with_local_address(IpAddr::V4([192, 0, 2, 2])),
        )
        .unwrap();
    a.start_session(ha).unwrap();
    b.start_session(hb).unwrap();
    pump(&mut a, ha, &mut b, hb);

    a.add_aggregate(Prefix::new_v4([203, 0, 113, 0], 24));

    let key = b.originate(
        Prefix::new_v4([203, 0, 113, 1], 32),
        Some(IpAddr::V4([192, 0, 2, 2])),
    );
    pump(&mut a, ha, &mut b, hb);
    assert!(a
        .rib_snapshot()
        .iter()
        .any(|r| r.key.prefix == Prefix::new_v4([203, 0, 113, 0], 24)));

    // B withdraws the specific.
    b.unoriginate(&key);
    pump(&mut a, ha, &mut b, hb);

    // The aggregate must be withdrawn.
    let snap = a.rib_snapshot();
    let has_aggregate = snap
        .iter()
        .any(|r| r.key.prefix == Prefix::new_v4([203, 0, 113, 0], 24));
    assert!(
        !has_aggregate,
        "aggregate must be withdrawn when no specifics remain"
    );
}

/// The aggregate carries ATOMIC_AGGREGATE and AGGREGATOR attributes.
#[test]
fn aggregate_has_atomic_aggregate_and_aggregator() {
    let mut a = DefaultRouter::new();
    let mut b = DefaultRouter::new();
    let ha = a
        .add_session(
            SessionConfig::bgp(Asn(64512), Asn(64513), V4_A)
                .with_local_address(IpAddr::V4([192, 0, 2, 1])),
        )
        .unwrap();
    let hb = b
        .add_session(
            SessionConfig::bgp(Asn(64513), Asn(64512), V4_B)
                .with_local_address(IpAddr::V4([192, 0, 2, 2])),
        )
        .unwrap();
    a.start_session(ha).unwrap();
    b.start_session(hb).unwrap();
    pump(&mut a, ha, &mut b, hb);

    a.add_aggregate(Prefix::new_v4([203, 0, 113, 0], 24));

    b.originate(
        Prefix::new_v4([203, 0, 113, 1], 32),
        Some(IpAddr::V4([192, 0, 2, 2])),
    );
    pump(&mut a, ha, &mut b, hb);

    let snap = a.rib_snapshot();
    let agg = snap
        .iter()
        .find(|r| r.key.prefix == Prefix::new_v4([203, 0, 113, 0], 24))
        .expect("aggregate route exists");

    // Decode the attributes and check for ATOMIC_AGGREGATE (type 6)
    // and AGGREGATOR (type 7).
    let attrs: lr_bgp::path::PathAttributes = agg.attributes.clone().into();
    assert!(
        attrs.get(lr_bgp::path::AttrType::AtomicAggregate).is_some(),
        "ATOMIC_AGGREGATE must be present"
    );
    let aggregator = attrs
        .get(lr_bgp::path::AttrType::Aggregator)
        .expect("AGGREGATOR must be present");
    // RFC 4271 §4.3: AGGREGATOR is optional transitive (flags 0xC0).
    // BIRD rejects a non-optional AGGREGATOR with "Malformed attribute -
    // conflicting flags" (caught live by tests/interop/aggregate_bird.sh).
    assert!(
        aggregator.flags.optional(),
        "AGGREGATOR must set the optional bit (RFC 4271 §4.3)"
    );
    assert!(
        aggregator.flags.transitive(),
        "AGGREGATOR must set the transitive bit (RFC 4271 §4.3)"
    );
    // RFC 4271 §9.2.2.2: the AGGREGATOR value is the 4-octet AS number
    // followed by the BGP Identifier of the aggregating speaker.
    let decoded = lr_bgp::path::Aggregator::decode(&aggregator.value)
        .expect("AGGREGATOR value decodes as AS + speaker");
    assert_eq!(decoded.asn.0, 64512, "AGGREGATOR carries the local AS");
    assert_eq!(
        decoded.speaker,
        [10, 0, 0, 1],
        "AGGREGATOR carries the local BGP Identifier (V4_A)"
    );
}

/// A route outside the aggregate does not trigger it.
#[test]
fn aggregate_not_triggered_by_unrelated_route() {
    let mut a = DefaultRouter::new();
    let mut b = DefaultRouter::new();
    let ha = a
        .add_session(
            SessionConfig::bgp(Asn(64512), Asn(64513), V4_A)
                .with_local_address(IpAddr::V4([192, 0, 2, 1])),
        )
        .unwrap();
    let hb = b
        .add_session(
            SessionConfig::bgp(Asn(64513), Asn(64512), V4_B)
                .with_local_address(IpAddr::V4([192, 0, 2, 2])),
        )
        .unwrap();
    a.start_session(ha).unwrap();
    b.start_session(hb).unwrap();
    pump(&mut a, ha, &mut b, hb);

    a.add_aggregate(Prefix::new_v4([203, 0, 113, 0], 24));

    // B originates a /32 in a DIFFERENT /24.
    b.originate(
        Prefix::new_v4([198, 51, 100, 1], 32),
        Some(IpAddr::V4([192, 0, 2, 2])),
    );
    pump(&mut a, ha, &mut b, hb);

    // The /24 aggregate must NOT be originated.
    let snap = a.rib_snapshot();
    let has_aggregate = snap
        .iter()
        .any(|r| r.key.prefix == Prefix::new_v4([203, 0, 113, 0], 24));
    assert!(
        !has_aggregate,
        "aggregate must not fire for unrelated routes"
    );
}

/// remove_aggregate withdraws the aggregate if it was originated.
#[test]
fn remove_aggregate_withdraws() {
    let mut a = DefaultRouter::new();
    let mut b = DefaultRouter::new();
    let ha = a
        .add_session(
            SessionConfig::bgp(Asn(64512), Asn(64513), V4_A)
                .with_local_address(IpAddr::V4([192, 0, 2, 1])),
        )
        .unwrap();
    let hb = b
        .add_session(
            SessionConfig::bgp(Asn(64513), Asn(64512), V4_B)
                .with_local_address(IpAddr::V4([192, 0, 2, 2])),
        )
        .unwrap();
    a.start_session(ha).unwrap();
    b.start_session(hb).unwrap();
    pump(&mut a, ha, &mut b, hb);

    let agg_prefix = Prefix::new_v4([203, 0, 113, 0], 24);
    a.add_aggregate(agg_prefix);

    b.originate(
        Prefix::new_v4([203, 0, 113, 1], 32),
        Some(IpAddr::V4([192, 0, 2, 2])),
    );
    pump(&mut a, ha, &mut b, hb);
    assert!(a.rib_snapshot().iter().any(|r| r.key.prefix == agg_prefix));

    // Remove the aggregate.
    a.remove_aggregate(&agg_prefix);

    // The aggregate must be gone.
    let snap = a.rib_snapshot();
    let has_aggregate = snap.iter().any(|r| r.key.prefix == agg_prefix);
    assert!(!has_aggregate, "aggregate must be withdrawn after removal");
}

/// Regression (ROADMAP-v3 D4.2 daemon wiring): the aggregate is
/// originated from `apply_selection` (a specific just arrived) while
/// the peer session is already Established — the newly originated
/// route must still be flushed through the export pipeline and reach
/// the peer, not merely appear in the local Loc-RIB. The daemon e2e
/// surfaced this: the aggregating daemon's downstream peer never saw
/// the aggregate because `recompute_aggregates` bypassed
/// `export_selection`.
#[test]
fn aggregate_originated_after_session_up_reaches_the_peer() {
    let mut a = DefaultRouter::new();
    let mut b = DefaultRouter::new();
    let ha = a
        .add_session(
            SessionConfig::bgp(Asn(64512), Asn(64513), V4_A)
                .with_local_address(IpAddr::V4([192, 0, 2, 1])),
        )
        .unwrap();
    let hb = b
        .add_session(
            SessionConfig::bgp(Asn(64513), Asn(64512), V4_B)
                .with_local_address(IpAddr::V4([192, 0, 2, 2])),
        )
        .unwrap();
    a.start_session(ha).unwrap();
    b.start_session(hb).unwrap();
    pump(&mut a, ha, &mut b, hb);

    let agg_prefix = Prefix::new_v4([203, 0, 113, 0], 24);
    a.add_aggregate(agg_prefix);

    // B originates the /32 AFTER the session is up; A's aggregate
    // originates in reaction to it.
    b.originate(
        Prefix::new_v4([203, 0, 113, 1], 32),
        Some(IpAddr::V4([192, 0, 2, 2])),
    );
    pump(&mut a, ha, &mut b, hb);

    // A originated the aggregate (Loc-RIB) AND advertised it: B's
    // Loc-RIB must hold a copy learned over the session.
    assert!(
        a.rib_snapshot().iter().any(|r| r.key.prefix == agg_prefix),
        "A must originate the aggregate into its own Loc-RIB"
    );
    assert!(
        b.rib_snapshot().iter().any(|r| r.key.prefix == agg_prefix),
        "B must learn the aggregate over the established session \
         (the origination must reach the export pipeline)"
    );
}

// ===== RFC 4271 §9.2.2.2 c/d: summary-only and as-set qualifiers =====
//
// Topology for the qualifier tests (eBGP everywhere):
//
//   B (AS 64513) — ha — A (AS 64512) — hb — C (AS 64514)
//                                  + [[aggregate]] 203.0.113.0/24
//
// B and C originate /32s inside A's /24 aggregate. A learns the
// specifics over its eBGP sessions, originates the /24 aggregate while
// any specific is present, and re-advertises both the specifics and
// the aggregate to its peers (eBGP split-horizon allows re-advertising
// routes learned over eBGP). The summary-only / as-set knobs change
// how A exports to B and C; the assertions inspect C's Loc-RIB to
// verify the egress behavior A applied.

/// `summary-only`: the daemon suppresses every more-specific route
/// that falls inside the aggregate from the Adj-RIB-Out toward every
/// BGP peer — only the aggregate is advertised. The Loc-RIB is
/// unchanged (the specifics stay reachable inside the daemon and
/// feed the aggregate's presence/withdraw decision).
#[test]
fn aggregate_summary_only_suppresses_specifics_from_export() {
    let mut a = DefaultRouter::new();
    let mut b = DefaultRouter::new();
    let mut c = DefaultRouter::new();
    // A (AS 64512) peers with B (AS 64513) and C (AS 64514).
    let ha_b = a
        .add_session(
            SessionConfig::bgp(Asn(64512), Asn(64513), V4_A)
                .with_local_address(IpAddr::V4([192, 0, 2, 1])),
        )
        .unwrap();
    let ha_c = a
        .add_session(
            SessionConfig::bgp(Asn(64512), Asn(64514), RouterId::from_v4([10, 0, 0, 1]))
                .with_local_address(IpAddr::V4([192, 0, 2, 1])),
        )
        .unwrap();
    let hb = b
        .add_session(
            SessionConfig::bgp(Asn(64513), Asn(64512), V4_B)
                .with_local_address(IpAddr::V4([192, 0, 2, 2])),
        )
        .unwrap();
    let hc = c
        .add_session(
            SessionConfig::bgp(Asn(64514), Asn(64512), RouterId::from_v4([10, 0, 0, 3]))
                .with_local_address(IpAddr::V4([192, 0, 2, 3])),
        )
        .unwrap();
    a.start_session(ha_b).unwrap();
    a.start_session(ha_c).unwrap();
    b.start_session(hb).unwrap();
    c.start_session(hc).unwrap();
    pump(&mut a, ha_b, &mut b, hb);
    pump(&mut a, ha_c, &mut c, hc);

    let agg_prefix = Prefix::new_v4([203, 0, 113, 0], 24);
    a.add_aggregate_with_options(
        agg_prefix,
        AggregateOptions {
            summary_only: true,
            as_set: false,
        },
    );

    // B originates a /32 inside the /24 aggregate.
    let spec_prefix = Prefix::new_v4([203, 0, 113, 1], 32);
    b.originate(spec_prefix, Some(IpAddr::V4([192, 0, 2, 2])));
    pump(&mut b, hb, &mut a, ha_b);
    pump(&mut a, ha_c, &mut c, hc);

    // A's Loc-RIB must hold both the specific and the aggregate —
    // summary-only is purely an egress filter, the Loc-RIB keeps the
    // specific (so the daemon can reach it for local forwarding and
    // so the aggregate's presence/withdraw decision is unaffected).
    let a_snap = a.rib_snapshot();
    assert!(
        a_snap.iter().any(|r| r.key.prefix == spec_prefix),
        "the /32 specific stays in A's Loc-RIB under summary-only"
    );
    assert!(
        a_snap.iter().any(|r| r.key.prefix == agg_prefix),
        "the /24 aggregate is originated in A's Loc-RIB"
    );

    // C learns the aggregate, but NOT the more-specific /32: the
    // egress filter suppressed it from the Adj-RIB-Out toward C.
    // (Without summary-only, A would re-advertise B's /32 to C over
    // eBGP — split-horizon is per session, not per protocol.)
    let c_snap = c.rib_snapshot();
    assert!(
        c_snap.iter().any(|r| r.key.prefix == agg_prefix),
        "C must learn the aggregate over the established session"
    );
    assert!(
        !c_snap.iter().any(|r| r.key.prefix == spec_prefix),
        "C must NOT learn the more-specific /32 — summary-only \
         suppresses it from A's Adj-RIB-Out"
    );
}

/// `summary-only` flips suppress to unsuppress when the aggregate is
/// removed (or re-registered without the flag): a regression that
/// latched the suppression forever would leave the more-specific
/// routes invisible to peers even after the operator removed the
/// `summary-only` knob. Pinned by re-registering the aggregate
/// without `summary_only` after the suppression window opened.
#[test]
fn aggregate_summary_only_release_re_advertises_specifics() {
    let mut a = DefaultRouter::new();
    let mut b = DefaultRouter::new();
    let mut c = DefaultRouter::new();
    let ha_b = a
        .add_session(
            SessionConfig::bgp(Asn(64512), Asn(64513), V4_A)
                .with_local_address(IpAddr::V4([192, 0, 2, 1])),
        )
        .unwrap();
    let ha_c = a
        .add_session(
            SessionConfig::bgp(Asn(64512), Asn(64514), RouterId::from_v4([10, 0, 0, 1]))
                .with_local_address(IpAddr::V4([192, 0, 2, 1])),
        )
        .unwrap();
    let hb = b
        .add_session(
            SessionConfig::bgp(Asn(64513), Asn(64512), V4_B)
                .with_local_address(IpAddr::V4([192, 0, 2, 2])),
        )
        .unwrap();
    let hc = c
        .add_session(
            SessionConfig::bgp(Asn(64514), Asn(64512), RouterId::from_v4([10, 0, 0, 3]))
                .with_local_address(IpAddr::V4([192, 0, 2, 3])),
        )
        .unwrap();
    a.start_session(ha_b).unwrap();
    a.start_session(ha_c).unwrap();
    b.start_session(hb).unwrap();
    c.start_session(hc).unwrap();
    pump(&mut a, ha_b, &mut b, hb);
    pump(&mut a, ha_c, &mut c, hc);

    let agg_prefix = Prefix::new_v4([203, 0, 113, 0], 24);
    a.add_aggregate_with_options(
        agg_prefix,
        AggregateOptions {
            summary_only: true,
            as_set: false,
        },
    );
    let spec_prefix = Prefix::new_v4([203, 0, 113, 1], 32);
    b.originate(spec_prefix, Some(IpAddr::V4([192, 0, 2, 2])));
    pump(&mut b, hb, &mut a, ha_b);
    pump(&mut a, ha_c, &mut c, hc);
    assert!(
        !c.rib_snapshot().iter().any(|r| r.key.prefix == spec_prefix),
        "summary-only suppresses the specific from C's view"
    );

    // Re-register the aggregate WITHOUT summary-only (mirrors the
    // operator editing `summary_only = false` on SIGHUP). The
    // re-registration triggers `recompute_aggregates`, which in turn
    // calls `export_selection` for the aggregate prefix key — but
    // the specific's prefix key needs a fresh `export_selection` run
    // too (so its `desired` no longer skips under summary-only). A
    // re-originated specific from B re-enters A's Loc-RIB and triggers
    // `apply_selection` -> `export_selection` for the specific prefix
    // key, so the Adj-RIB-Out diff re-advertises it to C.
    a.add_aggregate_with_options(
        agg_prefix,
        AggregateOptions {
            summary_only: false,
            as_set: false,
        },
    );
    b.originate(spec_prefix, Some(IpAddr::V4([192, 0, 2, 2])));
    pump(&mut b, hb, &mut a, ha_b);
    pump(&mut a, ha_c, &mut c, hc);

    let c_snap = c.rib_snapshot();
    assert!(
        c_snap.iter().any(|r| r.key.prefix == agg_prefix),
        "C must still learn the aggregate"
    );
    assert!(
        c_snap.iter().any(|r| r.key.prefix == spec_prefix),
        "C must re-learn the specific after summary-only is released"
    );
}

/// `as-set`: the aggregate's AS_PATH carries an `AS_SET` segment
/// enumerating every AS that contributed a more-specific route, and
/// `ATOMIC_AGGREGATE` is omitted (RFC 4271 §5.1.4: the AS_SET itself
/// signals the path may be incomplete).
#[test]
fn aggregate_as_set_builds_as_set_segment_in_as_path() {
    let mut a = DefaultRouter::new();
    let mut b = DefaultRouter::new();
    let mut c = DefaultRouter::new();
    let ha_b = a
        .add_session(
            SessionConfig::bgp(Asn(64512), Asn(64513), V4_A)
                .with_local_address(IpAddr::V4([192, 0, 2, 1])),
        )
        .unwrap();
    let ha_c = a
        .add_session(
            SessionConfig::bgp(Asn(64512), Asn(64514), V4_A)
                .with_local_address(IpAddr::V4([192, 0, 2, 1])),
        )
        .unwrap();
    let hb = b
        .add_session(
            SessionConfig::bgp(Asn(64513), Asn(64512), V4_B)
                .with_local_address(IpAddr::V4([192, 0, 2, 2])),
        )
        .unwrap();
    let hc = c
        .add_session(
            SessionConfig::bgp(Asn(64514), Asn(64512), RouterId::from_v4([10, 0, 0, 3]))
                .with_local_address(IpAddr::V4([192, 0, 2, 3])),
        )
        .unwrap();
    a.start_session(ha_b).unwrap();
    a.start_session(ha_c).unwrap();
    b.start_session(hb).unwrap();
    c.start_session(hc).unwrap();
    pump(&mut a, ha_b, &mut b, hb);
    pump(&mut a, ha_c, &mut c, hc);

    let agg_prefix = Prefix::new_v4([203, 0, 113, 0], 24);
    a.add_aggregate_with_options(
        agg_prefix,
        AggregateOptions {
            summary_only: false,
            as_set: true,
        },
    );

    // B originates a /32 inside the /24 aggregate. B's AS (64513)
    // becomes a contributing AS — the aggregate's AS_SET must list it.
    let spec_b = Prefix::new_v4([203, 0, 113, 1], 32);
    b.originate(spec_b, Some(IpAddr::V4([192, 0, 2, 2])));
    pump(&mut a, ha_b, &mut b, hb);

    let snap = a.rib_snapshot();
    let agg = snap
        .iter()
        .find(|r| r.key.prefix == agg_prefix)
        .expect("aggregate route exists");
    let attrs: lr_bgp::path::PathAttributes = agg.attributes.clone().into();

    // RFC 4271 §9.2.2.2 d: the AS_PATH carries an AS_SET segment with
    // the contributing ASes. ATOMIC_AGGREGATE is omitted in this mode.
    let path = attrs
        .as_path()
        .expect("AS_PATH must be present on an as-set aggregate");
    assert!(
        !path.segments.is_empty(),
        "AS_PATH must carry at least one segment under as-set"
    );
    let set_seg = path
        .segments
        .iter()
        .find(|s| s.kind == lr_bgp::path::AsPathType::Set)
        .expect("AS_PATH must contain an AS_SET segment under as-set");
    assert!(
        set_seg.ases.contains(&Asn(64513)),
        "AS_SET must include the contributing peer's AS (64513)"
    );
    // RFC 4271 §5.1.4: ATOMIC_AGGREGATE MUST NOT be set when the
    // aggregate carries an AS_SET (the AS_SET is the "incomplete path"
    // signal).
    assert!(
        attrs.get(lr_bgp::path::AttrType::AtomicAggregate).is_none(),
        "ATOMIC_AGGREGATE must be absent under as-set"
    );
    // RFC 4271 §9.2.2.2: AGGREGATOR is still present (the aggregator's
    // AS + BGP Identifier — the local speaker that built the AS_SET).
    assert!(
        attrs.get(lr_bgp::path::AttrType::Aggregator).is_some(),
        "AGGREGATOR must be present (the aggregating speaker)"
    );
}

/// `as-set` AS_SET tracks the live Loc-RIB: a new contributing peer's
/// AS appears in the set when its route arrives, and a withdrawing
/// peer's AS disappears when the last specific from that AS leaves.
/// Pinned by adding a third router that contributes a /32 from a
/// different AS, then withdrawing it.
#[test]
fn aggregate_as_set_tracks_live_loc_rib() {
    let mut a = DefaultRouter::new();
    let mut b = DefaultRouter::new();
    let mut c = DefaultRouter::new();
    let ha_b = a
        .add_session(
            SessionConfig::bgp(Asn(64512), Asn(64513), V4_A)
                .with_local_address(IpAddr::V4([192, 0, 2, 1])),
        )
        .unwrap();
    let ha_c = a
        .add_session(
            SessionConfig::bgp(Asn(64512), Asn(64514), V4_A)
                .with_local_address(IpAddr::V4([192, 0, 2, 1])),
        )
        .unwrap();
    // C is a third router in AS 64514 — a second contributing AS.
    let hb = b
        .add_session(
            SessionConfig::bgp(Asn(64513), Asn(64512), V4_B)
                .with_local_address(IpAddr::V4([192, 0, 2, 2])),
        )
        .unwrap();
    let hc = c
        .add_session(
            SessionConfig::bgp(Asn(64514), Asn(64512), RouterId::from_v4([10, 0, 0, 3]))
                .with_local_address(IpAddr::V4([192, 0, 2, 3])),
        )
        .unwrap();
    a.start_session(ha_b).unwrap();
    a.start_session(ha_c).unwrap();
    b.start_session(hb).unwrap();
    c.start_session(hc).unwrap();
    pump(&mut a, ha_b, &mut b, hb);
    pump(&mut a, ha_c, &mut c, hc);

    let agg_prefix = Prefix::new_v4([203, 0, 113, 0], 24);
    a.add_aggregate_with_options(
        agg_prefix,
        AggregateOptions {
            summary_only: false,
            as_set: true,
        },
    );

    // B contributes a /32 — AS 64513 enters the AS_SET.
    let spec_b = Prefix::new_v4([203, 0, 113, 1], 32);
    b.originate(spec_b, Some(IpAddr::V4([192, 0, 2, 2])));
    pump(&mut a, ha_b, &mut b, hb);

    let snap = a.rib_snapshot();
    let agg = snap
        .iter()
        .find(|r| r.key.prefix == agg_prefix)
        .expect("aggregate exists after B's specific arrives");
    let attrs: lr_bgp::path::PathAttributes = agg.attributes.clone().into();
    let path = attrs.as_path().expect("AS_PATH present");
    let set_seg = path
        .segments
        .iter()
        .find(|s| s.kind == lr_bgp::path::AsPathType::Set)
        .expect("AS_SET present");
    assert!(set_seg.ases.contains(&Asn(64513)));
    assert!(
        !set_seg.ases.contains(&Asn(64514)),
        "AS 64514 has not contributed yet"
    );

    // C contributes a /32 in the same aggregate — AS 64514 enters the
    // AS_SET. The aggregate must be re-originated with the new AS_SET.
    let spec_c = Prefix::new_v4([203, 0, 113, 2], 32);
    c.originate(spec_c, Some(IpAddr::V4([192, 0, 2, 3])));
    pump(&mut a, ha_c, &mut c, hc);

    let snap = a.rib_snapshot();
    let agg = snap
        .iter()
        .find(|r| r.key.prefix == agg_prefix)
        .expect("aggregate still exists");
    let attrs: lr_bgp::path::PathAttributes = agg.attributes.clone().into();
    let path = attrs.as_path().expect("AS_PATH present");
    let set_seg = path
        .segments
        .iter()
        .find(|s| s.kind == lr_bgp::path::AsPathType::Set)
        .expect("AS_SET present");
    assert!(
        set_seg.ases.contains(&Asn(64513)),
        "AS 64513 stays in the AS_SET after C contributes"
    );
    assert!(
        set_seg.ases.contains(&Asn(64514)),
        "AS 64514 enters the AS_SET after C contributes a specific"
    );

    // C withdraws its /32 — AS 64514 leaves the AS_SET.
    c.unoriginate(&lr_core::rib::RouteKey::new(
        spec_c,
        lr_core::nlri::NlriFamily::IPV4_UNICAST,
    ));
    pump(&mut a, ha_c, &mut c, hc);

    let snap = a.rib_snapshot();
    let agg = snap
        .iter()
        .find(|r| r.key.prefix == agg_prefix)
        .expect("aggregate still exists after C withdraws (B's specific remains)");
    let attrs: lr_bgp::path::PathAttributes = agg.attributes.clone().into();
    let path = attrs.as_path().expect("AS_PATH present");
    let set_seg = path
        .segments
        .iter()
        .find(|s| s.kind == lr_bgp::path::AsPathType::Set)
        .expect("AS_SET present");
    assert!(set_seg.ases.contains(&Asn(64513)));
    assert!(
        !set_seg.ases.contains(&Asn(64514)),
        "AS 64514 leaves the AS_SET after C withdraws its specific"
    );
}
