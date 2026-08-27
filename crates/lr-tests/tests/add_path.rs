//! RFC 7911 Add-Path end-to-end tests over the full stack:
//! two upstreams advertise the same prefix into a middle router, which
//! keeps both ranked paths in its Loc-RIB and forwards them — with wire
//! path identifiers — to a downstream Add-Path peer.

use lr_core::addr::{Asn, IpAddr, Prefix, RouterId};
use lr_router::{DefaultRouter, RouterEvent, RouterInstance, SessionConfig, SessionHandle};

fn pump(a: &mut DefaultRouter, ha: SessionHandle, b: &mut DefaultRouter, hb: SessionHandle) {
    for _ in 0..16 {
        let out_a = a.drain_output(ha);
        if !out_a.is_empty() {
            b.feed_input(hb, &out_a).unwrap();
        }
        let out_b = b.drain_output(hb);
        if !out_b.is_empty() {
            a.feed_input(ha, &out_b).unwrap();
        }
        if out_a.is_empty() && out_b.is_empty() {
            return;
        }
    }
    panic!("byte pump did not converge");
}

fn drain_events(r: &mut DefaultRouter) -> Vec<RouterEvent> {
    r.poll_events()
}

/// Wire one session between two routers (established by pumping).
fn wire(
    a: &mut DefaultRouter,
    b: &mut DefaultRouter,
    a_cfg: SessionConfig,
    b_cfg: SessionConfig,
) -> (SessionHandle, SessionHandle) {
    let ha = a.add_session(a_cfg).unwrap();
    let hb = b.add_session(b_cfg).unwrap();
    a.start_session(ha).unwrap();
    b.start_session(hb).unwrap();
    pump(a, ha, b, hb);
    (ha, hb)
}

/// A1 and A2 both originate 203.0.113.0/24; B (Add-Path, max 2 paths)
/// forwards both to C (Add-Path, max 2 paths).
#[test]
fn add_path_carries_two_paths_to_downstream() {
    let prefix = Prefix::new_v4([203, 0, 113, 0], 24);

    let mut a1 = DefaultRouter::new();
    let mut a2 = DefaultRouter::new();
    let mut b = DefaultRouter::new();
    let mut c = DefaultRouter::new();
    b.set_add_path_max_paths(2);
    c.set_add_path_max_paths(2);

    let (_a1s, _b1s) = wire(
        &mut a1,
        &mut b,
        SessionConfig::bgp(Asn(64520), Asn(64519), RouterId::from_v4([10, 0, 0, 11]))
            .with_local_address(IpAddr::V4([192, 0, 2, 11])),
        SessionConfig::bgp(Asn(64519), Asn(64520), RouterId::from_v4([10, 0, 0, 1]))
            .with_local_address(IpAddr::V4([192, 0, 2, 1])),
    );
    let (_a2s, _b2s) = wire(
        &mut a2,
        &mut b,
        SessionConfig::bgp(Asn(64521), Asn(64519), RouterId::from_v4([10, 0, 0, 12]))
            .with_local_address(IpAddr::V4([192, 0, 2, 12])),
        SessionConfig::bgp(Asn(64519), Asn(64521), RouterId::from_v4([10, 0, 0, 1]))
            .with_local_address(IpAddr::V4([192, 0, 2, 1])),
    );
    let (_bs, _cs) = wire(
        &mut b,
        &mut c,
        SessionConfig::bgp(Asn(64519), Asn(64518), RouterId::from_v4([10, 0, 0, 1]))
            .with_local_address(IpAddr::V4([192, 0, 2, 1]))
            .with_add_path()
            .with_mrai_ms(0),
        SessionConfig::bgp(Asn(64518), Asn(64519), RouterId::from_v4([10, 0, 0, 3]))
            .with_local_address(IpAddr::V4([192, 0, 2, 3]))
            .with_add_path(),
    );

    let _ = drain_events(&mut a1);
    let _ = drain_events(&mut a2);
    let _ = drain_events(&mut b);
    let _ = drain_events(&mut c);

    a1.originate(prefix, Some(IpAddr::V4([192, 0, 2, 11])));
    a2.originate(prefix, Some(IpAddr::V4([192, 0, 2, 12])));

    // A1 → B, A2 → B.
    let (_, b1) = (_a1s, _b1s);
    let (_, b2) = (_a2s, _b2s);
    pump(&mut a1, _a1s, &mut b, b1);
    pump(&mut a2, _a2s, &mut b, b2);
    let _ = drain_events(&mut b);

    // B now holds both paths for the prefix (one per upstream).
    let b_paths: Vec<_> = b
        .rib_paths_snapshot()
        .into_iter()
        .filter(|r| r.key.prefix == prefix)
        .cloned()
        .collect();
    assert_eq!(b_paths.len(), 2, "B must keep both ranked paths");
    assert_eq!(
        b.rib_snapshot()
            .into_iter()
            .filter(|r| r.key.prefix == prefix)
            .count(),
        1,
        "best-path view still sees one prefix"
    );
    // Both paths survived with distinct AS paths.
    let ases: std::collections::BTreeSet<u32> =
        b_paths.iter().map(|r| r.preference.metric).collect();
    assert_eq!(ases.len(), 1, "same AS-path length is fine");
    let next_hops: std::collections::BTreeSet<_> =
        b_paths.iter().filter_map(|r| r.next_hop).collect();
    assert_eq!(next_hops.len(), 2, "paths must differ by next-hop");

    // B → C: both paths propagate with distinct wire path identifiers.
    pump(&mut b, _bs, &mut c, _cs);
    let _ = drain_events(&mut c);
    let c_paths: Vec<_> = c
        .rib_paths_snapshot()
        .into_iter()
        .filter(|r| r.key.prefix == prefix)
        .cloned()
        .collect();
    assert_eq!(c_paths.len(), 2, "C must receive both paths");
    let ids: std::collections::BTreeSet<u32> = c_paths.iter().map(|r| r.path_id).collect();
    assert_eq!(ids.len(), 2, "path identifiers must be distinct");
    assert!(
        ids.iter().all(|id| *id >= 1),
        "transmit identifiers are rank slots + 1"
    );
}

/// Withdrawing one upstream path leaves exactly one path downstream, and
/// the surviving path is not disturbed.
#[test]
fn add_path_withdraw_leaves_surviving_path() {
    let prefix = Prefix::new_v4([203, 0, 113, 0], 24);

    let mut a1 = DefaultRouter::new();
    let mut a2 = DefaultRouter::new();
    let mut b = DefaultRouter::new();
    let mut c = DefaultRouter::new();
    b.set_add_path_max_paths(2);
    c.set_add_path_max_paths(2);

    let (a1s, b1) = wire(
        &mut a1,
        &mut b,
        SessionConfig::bgp(Asn(64520), Asn(64519), RouterId::from_v4([10, 0, 0, 11]))
            .with_local_address(IpAddr::V4([192, 0, 2, 11])),
        SessionConfig::bgp(Asn(64519), Asn(64520), RouterId::from_v4([10, 0, 0, 1]))
            .with_local_address(IpAddr::V4([192, 0, 2, 1])),
    );
    let (a2s, b2) = wire(
        &mut a2,
        &mut b,
        SessionConfig::bgp(Asn(64521), Asn(64519), RouterId::from_v4([10, 0, 0, 12]))
            .with_local_address(IpAddr::V4([192, 0, 2, 12])),
        SessionConfig::bgp(Asn(64519), Asn(64521), RouterId::from_v4([10, 0, 0, 1]))
            .with_local_address(IpAddr::V4([192, 0, 2, 1])),
    );
    let (bs, cs) = wire(
        &mut b,
        &mut c,
        SessionConfig::bgp(Asn(64519), Asn(64518), RouterId::from_v4([10, 0, 0, 1]))
            .with_local_address(IpAddr::V4([192, 0, 2, 1]))
            .with_add_path()
            .with_mrai_ms(0),
        SessionConfig::bgp(Asn(64518), Asn(64519), RouterId::from_v4([10, 0, 0, 3]))
            .with_local_address(IpAddr::V4([192, 0, 2, 3]))
            .with_add_path(),
    );

    let _ = drain_events(&mut a1);
    let _ = drain_events(&mut a2);
    let _ = drain_events(&mut b);
    let _ = drain_events(&mut c);

    a1.originate(prefix, Some(IpAddr::V4([192, 0, 2, 11])));
    a2.originate(prefix, Some(IpAddr::V4([192, 0, 2, 12])));
    pump(&mut a1, a1s, &mut b, b1);
    pump(&mut a2, a2s, &mut b, b2);
    let _ = drain_events(&mut b);
    pump(&mut b, bs, &mut c, cs);
    let _ = drain_events(&mut c);

    assert_eq!(
        c.rib_paths_snapshot()
            .into_iter()
            .filter(|r| r.key.prefix == prefix)
            .count(),
        2
    );

    // A2 withdraws the prefix: its path disappears everywhere, A1's path
    // survives.
    a2.unoriginate(&lr_core::rib::RouteKey::new(
        prefix,
        lr_core::nlri::NlriFamily::IPV4_UNICAST,
    ));
    pump(&mut a2, a2s, &mut b, b2);
    let _ = drain_events(&mut b);
    pump(&mut b, bs, &mut c, cs);
    let _ = drain_events(&mut c);

    let c_remaining: Vec<_> = c
        .rib_paths_snapshot()
        .into_iter()
        .filter(|r| r.key.prefix == prefix)
        .cloned()
        .collect();
    assert_eq!(c_remaining.len(), 1, "exactly one path remains");
    // The survivor is the A1-originated path (next-hop 192.0.2.1 after
    // B's next-hop-self).
    assert_eq!(
        c_remaining[0].next_hop,
        Some(IpAddr::V4([192, 0, 2, 1])),
        "survivor must be A1's path via B"
    );
    assert_eq!(
        c.rib_snapshot()
            .into_iter()
            .filter(|r| r.key.prefix == prefix)
            .count(),
        1
    );
}

/// A single-path downstream peer of a multi-path router still sees only
/// the best path (RFC 7911 peers and plain peers coexist).
#[test]
fn add_path_router_serves_plain_peer_best_only() {
    let prefix = Prefix::new_v4([203, 0, 113, 0], 24);

    let mut a1 = DefaultRouter::new();
    let mut a2 = DefaultRouter::new();
    let mut b = DefaultRouter::new();
    let mut c = DefaultRouter::new();
    b.set_add_path_max_paths(2);

    let (a1s, b1) = wire(
        &mut a1,
        &mut b,
        SessionConfig::bgp(Asn(64520), Asn(64519), RouterId::from_v4([10, 0, 0, 11]))
            .with_local_address(IpAddr::V4([192, 0, 2, 11])),
        SessionConfig::bgp(Asn(64519), Asn(64520), RouterId::from_v4([10, 0, 0, 1]))
            .with_local_address(IpAddr::V4([192, 0, 2, 1])),
    );
    let (a2s, b2) = wire(
        &mut a2,
        &mut b,
        SessionConfig::bgp(Asn(64521), Asn(64519), RouterId::from_v4([10, 0, 0, 12]))
            .with_local_address(IpAddr::V4([192, 0, 2, 12])),
        SessionConfig::bgp(Asn(64519), Asn(64521), RouterId::from_v4([10, 0, 0, 1]))
            .with_local_address(IpAddr::V4([192, 0, 2, 1])),
    );
    // C is a plain peer: no add-path anywhere.
    let (bs, cs) = wire(
        &mut b,
        &mut c,
        SessionConfig::bgp(Asn(64519), Asn(64518), RouterId::from_v4([10, 0, 0, 1]))
            .with_local_address(IpAddr::V4([192, 0, 2, 1]))
            .with_mrai_ms(0),
        SessionConfig::bgp(Asn(64518), Asn(64519), RouterId::from_v4([10, 0, 0, 3]))
            .with_local_address(IpAddr::V4([192, 0, 2, 3])),
    );

    let _ = drain_events(&mut a1);
    let _ = drain_events(&mut a2);
    let _ = drain_events(&mut b);
    let _ = drain_events(&mut c);

    a1.originate(prefix, Some(IpAddr::V4([192, 0, 2, 11])));
    a2.originate(prefix, Some(IpAddr::V4([192, 0, 2, 12])));
    pump(&mut a1, a1s, &mut b, b1);
    pump(&mut a2, a2s, &mut b, b2);
    let _ = drain_events(&mut b);
    pump(&mut b, bs, &mut c, cs);
    let _ = drain_events(&mut c);

    // B keeps 2 paths internally but C sees exactly one.
    assert_eq!(
        b.rib_paths_snapshot()
            .into_iter()
            .filter(|r| r.key.prefix == prefix)
            .count(),
        2
    );
    assert_eq!(
        c.rib_paths_snapshot()
            .into_iter()
            .filter(|r| r.key.prefix == prefix)
            .count(),
        1,
        "plain peer receives the best path only"
    );
    assert_eq!(
        c.rib_paths_snapshot()
            .into_iter()
            .find(|r| r.key.prefix == prefix)
            .unwrap()
            .path_id,
        0,
        "plain-peer routes carry no path identifier"
    );
}
