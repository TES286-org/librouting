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
use lr_router::{DefaultRouter, RouterInstance, SessionConfig, SessionHandle};

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
    assert!(
        attrs.get(lr_bgp::path::AttrType::Aggregator).is_some(),
        "AGGREGATOR must be present"
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
