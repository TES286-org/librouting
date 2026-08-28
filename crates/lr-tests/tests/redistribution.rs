//! End-to-end tests for the cross-protocol redistribution engine.
//!
//! The redistribution engine bridges routes between protocols:
//! - BGP → OSPF (via type-5 AS-external LSAs)
//! - OSPF → BGP (re-originated as locally originated BGP routes)
//! - Babel → BGP
//! - Metric policy (inherit / fixed / add)
//! - Prefix-list filtering
//!
//! These tests use the in-process byte pump — the same pattern as
//! `route_propagation.rs` and `bgp_session_modes.rs`.

use lr_core::addr::{Asn, IpAddr, Prefix, RouterId};
use lr_core::nlri::NlriFamily;
use lr_core::rib::Protocol;
use lr_router::{
    DefaultRouter, MetricPolicy, RedistributionPipe, RouterEvent, RouterInstance, SessionConfig,
    SessionHandle,
};

/// Pump bytes between two routers' sessions until no output remains.
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

// ===========================================================================
// BGP → BGP redistribution (re-originate)
// ===========================================================================

/// A pipe from BGP to BGP re-originates learned routes as locally
/// originated. This is the simplest case — the route's protocol stays
/// BGP, but `origin.proto` becomes 2 (locally originated).
#[test]
fn bgp_to_bgp_redistribution_re_originates() {
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

    // Add a BGP → BGP pipe before the route arrives.
    a.add_redistribution_pipe(RedistributionPipe::new(Protocol::Bgp, Protocol::Bgp));

    // B originates a route; A learns it via BGP.
    b.originate(
        Prefix::new_v4([203, 0, 113, 0], 24),
        Some(IpAddr::V4([192, 0, 2, 2])),
    );
    pump(&mut a, ha, &mut b, hb);

    // A's Loc-RIB must have the route.
    let snap = a.rib_snapshot();
    assert_eq!(snap.len(), 1, "A must have the BGP route");
    assert_eq!(snap[0].key.prefix, Prefix::new_v4([203, 0, 113, 0], 24));

    // The redistribute log event must fire.
    let events = a.poll_events();
    let redistributed = events.iter().any(|e| {
        matches!(
            e,
            RouterEvent::Log(msg) if msg.contains("redistribute")
        )
    });
    assert!(redistributed, "redistribute log event must fire");
}

// ===========================================================================
// Metric policy: fixed
// ===========================================================================

/// A BGP → BGP pipe with `MetricPolicy::Fixed(100)` overrides the
/// route's metric to 100.
#[test]
fn redistribution_fixed_metric() {
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

    a.add_redistribution_pipe(
        RedistributionPipe::new(Protocol::Bgp, Protocol::Bgp).with_metric(MetricPolicy::Fixed(100)),
    );

    b.originate(
        Prefix::new_v4([203, 0, 113, 0], 24),
        Some(IpAddr::V4([192, 0, 2, 2])),
    );
    pump(&mut a, ha, &mut b, hb);

    let snap = a.rib_snapshot();
    assert_eq!(snap.len(), 1);
    // The redistributed route's metric should be 100 (fixed).
    assert_eq!(
        snap[0].preference.metric, 100,
        "metric must be fixed at 100"
    );
}

// ===========================================================================
// Prefix-list filter
// ===========================================================================

/// A BGP → BGP pipe with an allow-list only redistributes matching
/// prefixes. Non-matching prefixes pass through unchanged.
#[test]
fn redistribution_prefix_filter() {
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

    // Only redistribute 203.0.113.0/24, not 198.51.100.0/24.
    a.add_redistribution_pipe(
        RedistributionPipe::new(Protocol::Bgp, Protocol::Bgp)
            .with_allow_prefixes(vec![(IpAddr::V4([203, 0, 113, 0]), 24)]),
    );

    b.originate(
        Prefix::new_v4([203, 0, 113, 0], 24),
        Some(IpAddr::V4([192, 0, 2, 2])),
    );
    b.originate(
        Prefix::new_v4([198, 51, 100, 0], 24),
        Some(IpAddr::V4([192, 0, 2, 2])),
    );
    pump(&mut a, ha, &mut b, hb);

    let events = a.poll_events();
    // Only 203.0.113.0/24 should trigger a redistribute log.
    let redistribute_count = events
        .iter()
        .filter(|e| matches!(e, RouterEvent::Log(msg) if msg.contains("redistribute")))
        .count();
    assert_eq!(
        redistribute_count, 1,
        "only the matching prefix triggers redistribution"
    );
}

// ===========================================================================
// Withdrawal propagation
// ===========================================================================

/// When the source route is withdrawn, the redistributed route is also
/// withdrawn.
#[test]
fn redistribution_withdraw_propagates() {
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

    a.add_redistribution_pipe(RedistributionPipe::new(Protocol::Bgp, Protocol::Bgp));

    let key = b.originate(
        Prefix::new_v4([203, 0, 113, 0], 24),
        Some(IpAddr::V4([192, 0, 2, 2])),
    );
    pump(&mut a, ha, &mut b, hb);
    assert_eq!(a.rib_snapshot().len(), 1);

    // B withdraws the route; A's redistributed copy must disappear.
    b.unoriginate(&key);
    pump(&mut a, ha, &mut b, hb);

    // A's Loc-RIB should now be empty (the route was withdrawn and the
    // redistributed copy was cleaned up).
    let snap = a.rib_snapshot();
    assert!(
        snap.is_empty()
            || snap
                .iter()
                .all(|r| r.key.prefix != Prefix::new_v4([203, 0, 113, 0], 24)),
        "redistributed route must be withdrawn when source disappears"
    );

    let events = a.poll_events();
    let withdraw_log = events.iter().any(|e| {
        matches!(
            e,
            RouterEvent::Log(msg) if msg.contains("redistribute: withdraw")
        )
    });
    assert!(withdraw_log, "withdraw log must fire");
}

// ===========================================================================
// Pipe removal
// ===========================================================================

/// `remove_redistribution_pipe` removes matching pipes and returns the
/// count.
#[test]
fn remove_redistribution_pipe() {
    let mut a = DefaultRouter::new();
    a.add_redistribution_pipe(RedistributionPipe::new(Protocol::Bgp, Protocol::Bgp));
    a.add_redistribution_pipe(RedistributionPipe::new(Protocol::Bgp, Protocol::Ospfv2));
    a.add_redistribution_pipe(RedistributionPipe::new(Protocol::Ospfv2, Protocol::Bgp));

    let removed = a.remove_redistribution_pipe(Protocol::Bgp, Protocol::Bgp);
    assert_eq!(removed, 1);

    let removed = a.remove_redistribution_pipe(Protocol::Bgp, Protocol::Bgp);
    assert_eq!(removed, 0, "already removed");
}

// ===========================================================================
// Metric policy: add
// ===========================================================================

/// `MetricPolicy::Add(N)` adds N to the source metric.
#[test]
fn redistribution_add_metric() {
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

    a.add_redistribution_pipe(
        RedistributionPipe::new(Protocol::Bgp, Protocol::Bgp).with_metric(MetricPolicy::Add(50)),
    );

    // B originates with AS_PATH length 1 (metric = 1 from AS_PATH).
    b.originate(
        Prefix::new_v4([203, 0, 113, 0], 24),
        Some(IpAddr::V4([192, 0, 2, 2])),
    );
    pump(&mut a, ha, &mut b, hb);

    let snap = a.rib_snapshot();
    assert_eq!(snap.len(), 1);
    // The source metric for a locally originated route with empty AS_PATH
    // is 1 (AS_PATH length); Add(50) → metric = 51.
    assert_eq!(snap[0].preference.metric, 51, "metric must be 1 + 50 = 51");
}

// ===========================================================================
// IPv6 redistribution
// ===========================================================================

/// BGP → BGP redistribution works for IPv6 prefixes too.
#[test]
fn redistribution_ipv6() {
    let mut a = DefaultRouter::new();
    let mut b = DefaultRouter::new();
    let ha = a
        .add_session(
            SessionConfig::bgp(Asn(64512), Asn(64513), V4_A)
                .with_mp_families(vec![NlriFamily::IPV4_UNICAST, NlriFamily::IPV6_UNICAST])
                .with_local_address(IpAddr::V6([
                    0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
                ])),
        )
        .unwrap();
    let hb = b
        .add_session(
            SessionConfig::bgp(Asn(64513), Asn(64512), V4_B)
                .with_mp_families(vec![NlriFamily::IPV4_UNICAST, NlriFamily::IPV6_UNICAST])
                .with_local_address(IpAddr::V6([
                    0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2,
                ])),
        )
        .unwrap();
    a.start_session(ha).unwrap();
    b.start_session(hb).unwrap();
    pump(&mut a, ha, &mut b, hb);

    a.add_redistribution_pipe(RedistributionPipe::new(Protocol::Bgp, Protocol::Bgp));

    b.originate_family(
        Prefix::new_v6(
            [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
            64,
        ),
        NlriFamily::IPV6_UNICAST,
        Some(IpAddr::V6([
            0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2,
        ])),
    );
    pump(&mut a, ha, &mut b, hb);

    let snap = a.rib_snapshot();
    assert_eq!(snap.len(), 1, "A must have the IPv6 route");
    assert_eq!(snap[0].key.family, NlriFamily::IPV6_UNICAST);

    let events = a.poll_events();
    let redistributed = events.iter().any(|e| {
        matches!(
            e,
            RouterEvent::Log(msg) if msg.contains("redistribute")
        )
    });
    assert!(redistributed, "IPv6 redistribute must fire");
}
