use super::*;
use crate::lsa::v3::{
    originate_v3_intra_area_prefix_lsa, originate_v3_link_lsa, originate_v3_network_lsa,
    originate_v3_router_lsa, LINK_TYPE_POINTTOPOINT, LINK_TYPE_TRANSIT, LS_TYPE_ROUTER,
    ROUTER_BIT_V6,
};

/// Two routers on a p2p link (interface ids 5 and 3), each with one
/// /64 on the link. r1 must learn r2's prefix via r2's link-local,
/// with our outgoing interface id 5.
#[test]
fn v3_p2p_two_routers_exchange_prefixes() {
    let mut db = Lsdb::new();
    let ll2 = fe80(2);
    let ll1 = fe80(1);
    // r1's Router-LSA: one p2p link to r2 (metric 10).
    db.install(
        originate_v3_router_lsa(
            0x0a00_0001,
            ROUTER_BIT_V6,
            0x13,
            &[crate::lsa::v3::V3RouterLink {
                link_type: LINK_TYPE_POINTTOPOINT,
                metric: 10,
                interface_id: 5,
                neighbor_interface_id: 3,
                neighbor_router_id: 0x0a00_0002,
            }],
            None,
        )
        .unwrap(),
        0,
    );
    // r2's Router-LSA: the back-link.
    db.install(
        originate_v3_router_lsa(
            0x0a00_0002,
            ROUTER_BIT_V6,
            0x13,
            &[crate::lsa::v3::V3RouterLink {
                link_type: LINK_TYPE_POINTTOPOINT,
                metric: 10,
                interface_id: 3,
                neighbor_interface_id: 5,
                neighbor_router_id: 0x0a00_0001,
            }],
            None,
        )
        .unwrap(),
        0,
    );
    // Link-LSAs: each router's link-local on the shared link, LS ID
    // = its interface id there.
    db.install(
        originate_v3_link_lsa(0x0a00_0001, 5, 1, 0x13, ll1, vec![], None).unwrap(),
        0,
    );
    db.install(
        originate_v3_link_lsa(0x0a00_0002, 3, 1, 0x13, ll2, vec![], None).unwrap(),
        0,
    );
    // Intra-Area-Prefix-LSAs: each router's own /64 (the addresses
    // of the link, NU/LA clear).
    let p1 = net64(1);
    let p2 = net64(2);
    db.install(
        originate_v3_intra_area_prefix_lsa(
            0x0a00_0001,
            1,
            LS_TYPE_ROUTER,
            0,
            0x0a00_0001,
            vec![p1.clone()],
            None,
        )
        .unwrap(),
        0,
    );
    db.install(
        originate_v3_intra_area_prefix_lsa(
            0x0a00_0002,
            1,
            LS_TYPE_ROUTER,
            0,
            0x0a00_0002,
            vec![p2.clone()],
            None,
        )
        .unwrap(),
        0,
    );

    let spf = run_spf_v3(&db, 0x0a00_0001);
    // r2 is reachable at cost 10 with r2's link-local as next hop
    // and our interface 5 as oif.
    let r2 = V3VertexId::Router(0x0a00_0002);
    assert_eq!(spf.vertices.get(&r2), Some(&10));
    let nh = spf.next_hops.get(&r2).expect("next hop resolved");
    assert_eq!(nh.link_local, IpAddr::V6(ll2));
    assert_eq!(nh.interface_id, 5, "our p2p link's interface id");
    assert!(spf.adjacent_routers.contains(&0x0a00_0002));
    // Routes: r1's own prefix (connected, metric 0) and r2's prefix
    // (metric 10 via r2's link-local).
    let find = |p: &Prefix| {
        spf.routes
            .iter()
            .find(|r| r.prefix == *p)
            .cloned()
            .unwrap_or_else(|| panic!("route {} missing", p))
    };
    let own = find(&route_of(&p1));
    assert_eq!(own.metric, 0);
    assert_eq!(own.next_hop, None, "own prefixes are connected");
    let remote = find(&route_of(&p2));
    assert_eq!(remote.metric, 10);
    assert_eq!(remote.next_hop, Some(IpAddr::V6(ll2)));
}

/// A three-router chain r1 - r2 - r3 (p2p): r1 must reach r3 through
/// r2's link-local (inherited next hop), at cost 20.
#[test]
fn v3_three_hop_chain_inherits_next_hop() {
    let mut db = Lsdb::new();
    let (r1, r2, r3) = (0x0a00_0001, 0x0a00_0002, 0x0a00_0003);
    let link = |metric: u16, ifid: u32, nifid: u32, nrid: u32| crate::lsa::v3::V3RouterLink {
        link_type: LINK_TYPE_POINTTOPOINT,
        metric,
        interface_id: ifid,
        neighbor_interface_id: nifid,
        neighbor_router_id: nrid,
    };
    db.install(
        originate_v3_router_lsa(r1, ROUTER_BIT_V6, 0x13, &[link(10, 5, 3, r2)], None).unwrap(),
        0,
    );
    db.install(
        originate_v3_router_lsa(
            r2,
            ROUTER_BIT_V6,
            0x13,
            &[link(10, 3, 5, r1), link(10, 6, 7, r3)],
            None,
        )
        .unwrap(),
        0,
    );
    db.install(
        originate_v3_router_lsa(r3, ROUTER_BIT_V6, 0x13, &[link(10, 7, 6, r2)], None).unwrap(),
        0,
    );
    // Link-LSAs for every interface.
    db.install(
        originate_v3_link_lsa(r1, 5, 1, 0x13, fe80(1), vec![], None).unwrap(),
        0,
    );
    db.install(
        originate_v3_link_lsa(r2, 3, 1, 0x13, fe80(2), vec![], None).unwrap(),
        0,
    );
    db.install(
        originate_v3_link_lsa(r2, 6, 1, 0x13, fe80(22), vec![], None).unwrap(),
        0,
    );
    db.install(
        originate_v3_link_lsa(r3, 7, 1, 0x13, fe80(3), vec![], None).unwrap(),
        0,
    );
    // r3's own /64.
    let p3 = net64(3);
    db.install(
        originate_v3_intra_area_prefix_lsa(r3, 1, LS_TYPE_ROUTER, 0, r3, vec![p3.clone()], None)
            .unwrap(),
        0,
    );

    let spf = run_spf_v3(&db, r1);
    let v3v = V3VertexId::Router(r3);
    assert_eq!(spf.vertices.get(&v3v), Some(&20), "10 + 10");
    let nh = spf.next_hops.get(&v3v).expect("inherited next hop");
    assert_eq!(nh.link_local, IpAddr::V6(fe80(2)), "via r2");
    let route = spf
        .routes
        .iter()
        .find(|r| r.prefix == route_of(&p3))
        .expect("r3's prefix");
    assert_eq!(route.metric, 20);
    assert_eq!(route.next_hop, Some(IpAddr::V6(fe80(2))));
}

/// A transit segment with an elected DR: the DR originates the
/// Network-LSA and the segment's Intra-Area-Prefix-LSA. A router on
/// the segment (r1) resolves the other member's (r3's) link-local
/// through the back-link, without a p2p adjacency.
#[test]
fn v3_transit_network_resolves_members() {
    let mut db = Lsdb::new();
    let (r1, r2, r3) = (0x0a00_0001, 0x0a00_0002, 0x0a00_0003);
    // r2 is the DR; its interface id on the segment is 9; r1's is 5,
    // r3's is 7. r1 and r3 are fully adjacent to r2 only.
    db.install(
        originate_v3_router_lsa(
            r1,
            ROUTER_BIT_V6,
            0x13,
            &[crate::lsa::v3::V3RouterLink {
                link_type: LINK_TYPE_TRANSIT,
                metric: 10,
                interface_id: 5,
                neighbor_interface_id: 9,
                neighbor_router_id: r2,
            }],
            None,
        )
        .unwrap(),
        0,
    );
    db.install(
        originate_v3_router_lsa(
            r2,
            ROUTER_BIT_V6,
            0x13,
            &[crate::lsa::v3::V3RouterLink {
                link_type: LINK_TYPE_TRANSIT,
                metric: 10,
                interface_id: 9,
                neighbor_interface_id: 9,
                neighbor_router_id: r2,
            }],
            None,
        )
        .unwrap(),
        0,
    );
    db.install(
        originate_v3_router_lsa(
            r3,
            ROUTER_BIT_V6,
            0x13,
            &[crate::lsa::v3::V3RouterLink {
                link_type: LINK_TYPE_TRANSIT,
                metric: 10,
                interface_id: 7,
                neighbor_interface_id: 9,
                neighbor_router_id: r2,
            }],
            None,
        )
        .unwrap(),
        0,
    );
    // Network-LSA: DR r2, LS ID = its interface id 9, all three
    // attached.
    db.install(
        originate_v3_network_lsa(r2, 9, 0x13, &[r1, r2, r3], None).unwrap(),
        0,
    );
    // Link-LSAs on the segment.
    db.install(
        originate_v3_link_lsa(r1, 5, 1, 0x13, fe80(1), vec![], None).unwrap(),
        0,
    );
    db.install(
        originate_v3_link_lsa(r2, 9, 1, 0x13, fe80(2), vec![], None).unwrap(),
        0,
    );
    db.install(
        originate_v3_link_lsa(r3, 7, 1, 0x13, fe80(3), vec![], None).unwrap(),
        0,
    );
    // The segment's prefix, attached to the Network-LSA.
    let seg = net64(9);
    let seg_prefix = Prefix::new_v6(seg.addr, seg.prefix_len);
    db.install(
        originate_v3_intra_area_prefix_lsa(
            r2,
            1,
            crate::lsa::v3::LS_TYPE_NETWORK,
            9,
            r2,
            vec![seg.clone()],
            None,
        )
        .unwrap(),
        0,
    );

    let spf = run_spf_v3(&db, r1);
    // The network vertex: cost 10.
    let net = V3VertexId::Network(r2, 9);
    assert_eq!(spf.vertices.get(&net), Some(&10));
    // r2 and r3 ride the segment: both at cost 10, r3's link-local
    // resolved via its back-link transit entry (interface id 7 →
    // Link-LSA 7).
    for (rid, ll) in [(r2, fe80(2)), (r3, fe80(3))] {
        let v = V3VertexId::Router(rid);
        assert_eq!(spf.vertices.get(&v), Some(&10));
        let nh = spf
            .next_hops
            .get(&v)
            .unwrap_or_else(|| panic!("nh for {rid}"));
        assert_eq!(nh.link_local, IpAddr::V6(ll));
        assert_eq!(nh.interface_id, 5, "our interface on the segment");
        assert!(spf.adjacent_routers.contains(&rid));
    }
    // The segment prefix is connected for r1 (directly attached).
    let route = spf.routes.iter().find(|r| r.prefix == seg_prefix).unwrap();
    assert_eq!(route.metric, 10);
    assert_eq!(route.next_hop, None);
}

/// RFC 5340 §4.8.1 excludes NU prefixes; LA interface addresses
/// remain reachable through their advertising router (§A.4.1).
#[test]
fn v3_la_prefixes_are_reachable_unless_nu_is_set() {
    let mut db = Lsdb::new();
    let (r1, r2) = (0x0a00_0001, 0x0a00_0002);
    let link = crate::lsa::v3::V3RouterLink {
        link_type: LINK_TYPE_POINTTOPOINT,
        metric: 10,
        interface_id: 5,
        neighbor_interface_id: 3,
        neighbor_router_id: r2,
    };
    db.install(
        originate_v3_router_lsa(r1, ROUTER_BIT_V6, 0x13, &[link], None).unwrap(),
        0,
    );
    let back = crate::lsa::v3::V3RouterLink {
        link_type: LINK_TYPE_POINTTOPOINT,
        metric: 10,
        interface_id: 3,
        neighbor_interface_id: 5,
        neighbor_router_id: r1,
    };
    db.install(
        originate_v3_router_lsa(r2, ROUTER_BIT_V6, 0x13, &[back], None).unwrap(),
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
    // r2 advertises normal, NU, LA and LA+NU prefixes.
    let normal = net64(3);
    let mut nu = net64(4);
    nu.options = crate::lsa::v3::PREFIX_OPT_NU;
    let mut la = net64(5);
    la.prefix_len = 128;
    la.options = crate::lsa::v3::PREFIX_OPT_LA;
    let mut la_nu = net64(6);
    la_nu.prefix_len = 128;
    la_nu.options = crate::lsa::v3::PREFIX_OPT_LA | crate::lsa::v3::PREFIX_OPT_NU;
    db.install(
        originate_v3_intra_area_prefix_lsa(
            r2,
            1,
            LS_TYPE_ROUTER,
            0,
            r2,
            vec![normal.clone(), nu.clone(), la.clone(), la_nu.clone()],
            None,
        )
        .unwrap(),
        0,
    );
    for spf in [run_spf_v3(&db, r1), run_spf_v3_extended(&db, r1)] {
        assert!(spf.routes.iter().any(|r| r.prefix == route_of(&normal)));
        assert!(!spf.routes.iter().any(|r| r.prefix == route_of(&nu)));
        assert!(!spf.routes.iter().any(|r| r.prefix == route_of(&la_nu)));
        let host = spf
            .routes
            .iter()
            .find(|r| r.prefix == route_of(&la))
            .unwrap();
        assert_eq!(host.metric, 10);
        assert_eq!(host.next_hop, Some(IpAddr::V6(fe80(2))));
    }
}

/// A missing Link-LSA leaves the vertex reachable but without a
/// next hop — the route survives without a gateway.
#[test]
fn v3_missing_link_lsa_yields_no_next_hop() {
    let mut db = Lsdb::new();
    let (r1, r2) = (0x0a00_0001, 0x0a00_0002);
    let link = crate::lsa::v3::V3RouterLink {
        link_type: LINK_TYPE_POINTTOPOINT,
        metric: 10,
        interface_id: 5,
        neighbor_interface_id: 3,
        neighbor_router_id: r2,
    };
    db.install(
        originate_v3_router_lsa(r1, ROUTER_BIT_V6, 0x13, &[link], None).unwrap(),
        0,
    );
    let back = crate::lsa::v3::V3RouterLink {
        link_type: LINK_TYPE_POINTTOPOINT,
        metric: 10,
        interface_id: 3,
        neighbor_interface_id: 5,
        neighbor_router_id: r1,
    };
    db.install(
        originate_v3_router_lsa(r2, ROUTER_BIT_V6, 0x13, &[back], None).unwrap(),
        0,
    );
    // Only r1's Link-LSA: r2's link-local is unknown.
    db.install(
        originate_v3_link_lsa(r1, 5, 1, 0x13, fe80(1), vec![], None).unwrap(),
        0,
    );
    let p2 = net64(2);
    db.install(
        originate_v3_intra_area_prefix_lsa(r2, 1, LS_TYPE_ROUTER, 0, r2, vec![p2.clone()], None)
            .unwrap(),
        0,
    );
    let spf = run_spf_v3(&db, r1);
    let v2v = V3VertexId::Router(r2);
    assert_eq!(spf.vertices.get(&v2v), Some(&10), "reachable");
    assert!(!spf.next_hops.contains_key(&v2v), "no Link-LSA, no nh");
    let route = spf
        .routes
        .iter()
        .find(|r| r.prefix == route_of(&p2))
        .unwrap();
    assert_eq!(route.next_hop, None);
}

fn route_of(p: &crate::lsa::v3::V3Prefix) -> Prefix {
    Prefix::new_v6(p.addr, p.prefix_len)
}

fn fe80(host: u8) -> [u8; 16] {
    let mut a = [0u8; 16];
    a[0] = 0xfe;
    a[1] = 0x80;
    a[15] = host;
    a
}

/// A /64 whose significant bits fit the 8 wire bytes: 2001:db8:0:hn::/64.
fn net64(host: u8) -> crate::lsa::v3::V3Prefix {
    let mut a = [0u8; 16];
    a[0] = 0x20;
    a[1] = 0x01;
    a[2] = 0x0d;
    a[3] = 0xb8;
    a[7] = host;
    crate::lsa::v3::V3Prefix {
        prefix_len: 64,
        options: 0,
        metric: 0,
        addr: a,
    }
}

/// RFC 9513 §5: an SRv6 locator is reachable through its
/// advertising router. r2's locator becomes a locator route with
/// the p2p metric and r2's link-local first hop.
#[test]
fn v3_locator_route_follows_the_advertising_router() {
    use crate::lsa::srv6::{
        locator_route_type, originate_v3_srv6_locator_lsa, Srv6EndSidSubTlv, Srv6LocatorTlv,
        PREFIX_OPT_AC,
    };
    let mut db = Lsdb::new();
    let (r1, r2) = (0x0a00_0001, 0x0a00_0002);
    let ll2 = fe80(2);
    db.install(
        originate_v3_router_lsa(
            r1,
            ROUTER_BIT_V6,
            0x13,
            &[crate::lsa::v3::V3RouterLink {
                link_type: LINK_TYPE_POINTTOPOINT,
                metric: 10,
                interface_id: 5,
                neighbor_interface_id: 3,
                neighbor_router_id: r2,
            }],
            None,
        )
        .unwrap(),
        0,
    );
    db.install(
        originate_v3_router_lsa(
            r2,
            ROUTER_BIT_V6,
            0x13,
            &[crate::lsa::v3::V3RouterLink {
                link_type: LINK_TYPE_POINTTOPOINT,
                metric: 10,
                interface_id: 3,
                neighbor_interface_id: 5,
                neighbor_router_id: r1,
            }],
            None,
        )
        .unwrap(),
        0,
    );
    db.install(
        originate_v3_link_lsa(r1, 5, 1, 0x13, fe80(1), vec![], None).unwrap(),
        0,
    );
    db.install(
        originate_v3_link_lsa(r2, 3, 1, 0x13, ll2, vec![], None).unwrap(),
        0,
    );

    // r2's locator 2001:db8:1::/48 with one End SID.
    let mut prefix = [0u8; 16];
    prefix[..6].copy_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0x00, 0x01]);
    let mut end_sid = [0u8; 16];
    end_sid[..6].copy_from_slice(&prefix[..6]);
    end_sid[15] = 1;
    let tlv = Srv6LocatorTlv {
        route_type: locator_route_type::INTRA_AREA,
        algorithm: 0,
        locator_len: 48,
        options: PREFIX_OPT_AC,
        metric: 0,
        prefix,
        end_sids: vec![Srv6EndSidSubTlv {
            flags: 0,
            behavior: 1,
            sid: end_sid,
            structure: None,
        }],
        fwd_addr: None,
        route_tag: None,
    };
    db.install(
        originate_v3_srv6_locator_lsa(r2, 0, std::slice::from_ref(&tlv), None).unwrap(),
        0,
    );

    let spf = run_spf_v3(&db, r1);
    assert_eq!(spf.locators.len(), 1, "the locator is the only route");
    let loc = &spf.locators[0];
    assert_eq!(loc.prefix, Prefix::new_v6(prefix, 48));
    assert_eq!(loc.algorithm, 0);
    assert_eq!(loc.metric, 10, "the router's p2p distance");
    assert_eq!(loc.next_hop, Some(IpAddr::V6(ll2)));
    assert_eq!(loc.advertising_router, r2);
}

/// The root's own locator is directly connected: metric 0 and no
/// first hop. Locators of routers unreachable from the root (no
/// Router-LSA) never become routes.
#[test]
fn v3_own_locator_connected_and_unreachable_locator_dropped() {
    use crate::lsa::srv6::{locator_route_type, originate_v3_srv6_locator_lsa, Srv6LocatorTlv};
    let mut db = Lsdb::new();
    let (r1, r2) = (0x0a00_0001, 0x0a00_0002);
    let mk_tlv = |byte6: u8| {
        let mut prefix = [0u8; 16];
        prefix[..6].copy_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0x00, 0x01]);
        prefix[6] = byte6;
        Srv6LocatorTlv {
            route_type: locator_route_type::INTRA_AREA,
            algorithm: 0,
            locator_len: 56,
            options: 0,
            metric: 0,
            prefix,
            end_sids: vec![],
            fwd_addr: None,
            route_tag: None,
        }
    };
    // r1's own locator.
    db.install(
        originate_v3_srv6_locator_lsa(r1, 0, &[mk_tlv(0)], None).unwrap(),
        0,
    );
    // r2's locator — but r2 has no Router-LSA, so it is
    // unreachable and §5 installs nothing for it.
    db.install(
        originate_v3_srv6_locator_lsa(r2, 0, &[mk_tlv(1)], None).unwrap(),
        0,
    );

    let spf = run_spf_v3(&db, r1);
    assert_eq!(spf.locators.len(), 1, "r2's locator is unreachable");
    let loc = &spf.locators[0];
    assert_eq!(loc.advertising_router, r1);
    assert_eq!(loc.metric, 0);
    assert_eq!(loc.next_hop, None);
}

/// An inter-area locator (route type 2) is not computed until the
/// v3 inter-area calculation exists — it stays out of the locator
/// routes.
#[test]
fn v3_non_intra_area_locator_not_computed() {
    use crate::lsa::srv6::{locator_route_type, originate_v3_srv6_locator_lsa, Srv6LocatorTlv};
    let mut db = Lsdb::new();
    let r1 = 0x0a00_0001;
    let mut prefix = [0u8; 16];
    prefix[..6].copy_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0x00, 0x01]);
    let tlv = Srv6LocatorTlv {
        route_type: locator_route_type::INTER_AREA,
        algorithm: 0,
        locator_len: 48,
        options: 0,
        metric: 10,
        prefix,
        end_sids: vec![],
        fwd_addr: None,
        route_tag: None,
    };
    db.install(
        originate_v3_srv6_locator_lsa(r1, 0, std::slice::from_ref(&tlv), None).unwrap(),
        0,
    );
    let spf = run_spf_v3(&db, r1);
    assert!(spf.locators.is_empty());
}

/// r1 - r2 p2p backbone with both Router-LSAs, Link-LSAs and the
/// shared /64. Returns the LSDB and the routers' link-locals.
fn v3_p2p_lsdb(
    r1: u32,
    r2: u32,
    ifid1: u32,
    ifid2: u32,
    metric: u16,
) -> (Lsdb, [u8; 16], [u8; 16]) {
    let mut db = Lsdb::new();
    let mk = |_from: u32, from_if: u32, to_if: u32, to: u32| crate::lsa::v3::V3RouterLink {
        link_type: LINK_TYPE_POINTTOPOINT,
        metric,
        interface_id: from_if,
        neighbor_interface_id: to_if,
        neighbor_router_id: to,
    };
    db.install(
        originate_v3_router_lsa(r1, ROUTER_BIT_V6, 0x13, &[mk(r1, ifid1, ifid2, r2)], None)
            .unwrap(),
        0,
    );
    db.install(
        originate_v3_router_lsa(r2, ROUTER_BIT_V6, 0x13, &[mk(r2, ifid2, ifid1, r1)], None)
            .unwrap(),
        0,
    );
    let ll1 = fe80(1);
    let ll2 = fe80(2);
    db.install(
        originate_v3_link_lsa(r1, ifid1, 1, 0x13, ll1, vec![], None).unwrap(),
        0,
    );
    db.install(
        originate_v3_link_lsa(r2, ifid2, 1, 0x13, ll2, vec![], None).unwrap(),
        0,
    );
    (db, ll1, ll2)
}

/// A 0x2003 inter-area-prefix-LSA body for `prefix` at `metric`.
fn inter_prefix_body(prefix: Prefix, metric: u32, options: u8) -> Vec<u8> {
    let mut body = vec![0u8];
    body.extend_from_slice(&metric.to_be_bytes()[1..4]);
    body.push(prefix.prefix_len);
    body.push(options);
    body.extend_from_slice(&0u16.to_be_bytes());
    let n = (prefix.prefix_len as usize).div_ceil(8);
    let padded = n.next_multiple_of(4);
    match prefix.addr {
        IpAddr::V6(b) => body.extend_from_slice(&b[..n.min(16)]),
        IpAddr::V4(b) => body.extend_from_slice(&b[..n.min(4)]),
    }
    body.resize(body.len() + (padded - n), 0);
    body
}

/// A finalized 0x2003 inter-area-prefix-LSA from `adv`.
fn inter_prefix_lsa(
    ls_id: u32,
    adv: u32,
    prefix: Prefix,
    metric: u32,
    options: u8,
) -> crate::lsa::Lsa {
    let mut lsa = crate::lsa::Lsa {
        header: crate::lsa::LsaHeader {
            ls_age: 0,
            options: 0,
            ls_type: LS_TYPE_INTER_PREFIX,
            link_state_id: ls_id,
            advertising_router: adv,
            ls_sequence_number: 0x8000_0001,
            ls_checksum: 0,
            length: 0,
        },
        body: inter_prefix_body(prefix, metric, options),
    };
    lsa.finalize();
    lsa
}

/// §4.8.3: a 0x2003 from a reachable border router yields an
/// inter-area candidate with dist(border) + metric; LSInfinity and
/// NU-marked prefixes are skipped; unreachable border routers
/// contribute nothing.
#[test]
fn v3_inter_area_prefix_calc() {
    let (r1, r2) = (0x0a00_0001, 0x0a00_0002);
    let (mut db, _ll1, ll2) = v3_p2p_lsdb(r1, r2, 5, 3, 10);
    let p_a = Prefix::new_v6(
        {
            let mut a = [0u8; 16];
            a[..6].copy_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 1]);
            a
        },
        48,
    );
    let p_nu = Prefix::new_v6(
        {
            let mut a = [0u8; 16];
            a[..6].copy_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 2]);
            a
        },
        48,
    );
    // r2's summaries: p_a at metric 7, p_nu NU-marked, and an
    // LSInfinity default.
    db.install(inter_prefix_lsa(1, r2, p_a, 7, 0), 0);
    db.install(inter_prefix_lsa(2, r2, p_nu, 7, PREFIX_OPT_NU), 0);
    db.install(
        inter_prefix_lsa(3, r2, Prefix::new_v6([0u8; 16], 0), 0x00ff_ffff, 0),
        0,
    );
    // A summary from a router with no Router-LSA: unreachable.
    db.install(inter_prefix_lsa(4, 0x0a00_0009, p_a, 1, 0), 0);

    let spf = run_spf_v3(&db, r1);
    let inter = summary_routes_v3(&db, &spf);
    assert_eq!(inter.len(), 1, "only p_a survives");
    let route = &inter[0];
    assert_eq!(route.prefix, p_a);
    assert_eq!(route.metric, 17, "dist(r2)=10 + metric 7");
    assert_eq!(route.border_router, Some(r2));
    assert_eq!(route.next_hop, Some(IpAddr::V6(ll2)));
}

/// Candidate selection for identical prefixes: the lowest metric
/// wins across border routers; an exact tie falls to the lower
/// border router ID; duplicate LSAs from one border router keep the
/// lowest metric.
#[test]
fn v3_inter_area_prefix_best_candidate_wins() {
    let (r1, r2) = (0x0a00_0001, 0x0a00_0002);
    let mut db = Lsdb::new();
    let p = Prefix::new_v6(
        {
            let mut a = [0u8; 16];
            a[..6].copy_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 3]);
            a
        },
        48,
    );
    // r1 p2p-connects to r2, r4 and r5 (all metric 10) so all three
    // border routers are intra-area reachable.
    let r4 = 0x0a00_0004;
    let r5 = 0x0a00_0005;
    let mk_link = |ifid: u32, nifid: u32, nrid: u32| crate::lsa::v3::V3RouterLink {
        link_type: LINK_TYPE_POINTTOPOINT,
        metric: 10,
        interface_id: ifid,
        neighbor_interface_id: nifid,
        neighbor_router_id: nrid,
    };
    let back = |ifid: u32, nifid: u32, nrid: u32| crate::lsa::v3::V3RouterLink {
        link_type: LINK_TYPE_POINTTOPOINT,
        metric: 10,
        interface_id: ifid,
        neighbor_interface_id: nifid,
        neighbor_router_id: nrid,
    };
    db.install(
        originate_v3_router_lsa(
            r1,
            ROUTER_BIT_V6,
            0x13,
            &[mk_link(5, 3, r2), mk_link(6, 8, r4), mk_link(7, 9, r5)],
            None,
        )
        .unwrap(),
        0,
    );
    db.install(
        originate_v3_router_lsa(r2, ROUTER_BIT_V6, 0x13, &[back(3, 5, r1)], None).unwrap(),
        0,
    );
    db.install(
        originate_v3_router_lsa(r4, ROUTER_BIT_V6, 0x13, &[back(8, 6, r1)], None).unwrap(),
        0,
    );
    db.install(
        originate_v3_router_lsa(r5, ROUTER_BIT_V6, 0x13, &[back(9, 7, r1)], None).unwrap(),
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
    db.install(
        originate_v3_link_lsa(r4, 8, 1, 0x13, fe80(4), vec![], None).unwrap(),
        0,
    );
    db.install(
        originate_v3_link_lsa(r5, 9, 1, 0x13, fe80(5), vec![], None).unwrap(),
        0,
    );
    // Candidates: r2 metric 5 → 15, r4 metric 1 → 11 (wins on
    // metric), r5 metric 5 → 15 (ties with r2 but r2's ID is
    // lower). r2's duplicate metric 9 LSA loses to its own metric 5.
    db.install(inter_prefix_lsa(10, r2, p, 5, 0), 0);
    db.install(inter_prefix_lsa(11, r2, p, 9, 0), 0);
    db.install(inter_prefix_lsa(12, r4, p, 1, 0), 0);
    db.install(inter_prefix_lsa(13, r5, p, 5, 0), 0);

    let spf = run_spf_v3(&db, r1);
    let inter = summary_routes_v3(&db, &spf);
    assert_eq!(inter.len(), 1);
    assert_eq!(inter[0].metric, 11, "r4's metric-1 candidate wins");
    assert_eq!(inter[0].border_router, Some(r4));
}

// ------------------------------------------------------------------
// RFC 8362 Extended-LSA reception
// ------------------------------------------------------------------

/// Helper: the p2p link descriptor for the E-Router-LSA.
fn e_link(metric: u16, ifid: u32, nifid: u32, nrid: u32) -> crate::lsa::ERouterLinkTlv {
    crate::lsa::ERouterLinkTlv {
        link_type: LINK_TYPE_POINTTOPOINT,
        metric,
        interface_id: ifid,
        neighbor_interface_id: nifid,
        neighbor_router_id: nrid,
        sub_tlvs: Vec::new(),
    }
}

/// Helper: an Intra-Area-Prefix TLV around one prefix.
fn e_prefix_tlv(p: &crate::lsa::v3::V3Prefix) -> crate::lsa::EPrefixTlv {
    crate::lsa::EPrefixTlv {
        metric: 0,
        prefix: p.clone(),
        sub_tlvs: Vec::new(),
    }
}

/// RFC 8362 §6.1: the same two-router p2p topology expressed
/// entirely in Extended LSAs (E-Router, E-Link, E-IAP referencing
/// the E-Router-LSA) computes the same vertices, next hops and
/// routes as the legacy encoding — the acceptance shape for the
/// E-LSA reception path.
#[test]
fn v3_e_lsa_topology_matches_legacy() {
    let r1 = 0x0a00_0001;
    let r2 = 0x0a00_0002;
    let ll1 = fe80(1);
    let ll2 = fe80(2);
    let p1 = net64(1);
    let p2 = net64(2);
    let mut legacy = Lsdb::new();
    legacy.install(
        originate_v3_router_lsa(
            r1,
            ROUTER_BIT_V6,
            0x13,
            &[crate::lsa::v3::V3RouterLink {
                link_type: LINK_TYPE_POINTTOPOINT,
                metric: 10,
                interface_id: 5,
                neighbor_interface_id: 3,
                neighbor_router_id: r2,
            }],
            None,
        )
        .unwrap(),
        0,
    );
    legacy.install(
        originate_v3_router_lsa(
            r2,
            ROUTER_BIT_V6,
            0x13,
            &[crate::lsa::v3::V3RouterLink {
                link_type: LINK_TYPE_POINTTOPOINT,
                metric: 10,
                interface_id: 3,
                neighbor_interface_id: 5,
                neighbor_router_id: r1,
            }],
            None,
        )
        .unwrap(),
        0,
    );
    legacy.install(
        originate_v3_link_lsa(r1, 5, 1, 0x13, ll1, vec![], None).unwrap(),
        0,
    );
    legacy.install(
        originate_v3_link_lsa(r2, 3, 1, 0x13, ll2, vec![], None).unwrap(),
        0,
    );
    legacy.install(
        originate_v3_intra_area_prefix_lsa(r1, 1, LS_TYPE_ROUTER, 0, r1, vec![p1.clone()], None)
            .unwrap(),
        0,
    );
    legacy.install(
        originate_v3_intra_area_prefix_lsa(r2, 1, LS_TYPE_ROUTER, 0, r2, vec![p2.clone()], None)
            .unwrap(),
        0,
    );
    let expect = run_spf_v3(&legacy, r1);

    let mut ext = Lsdb::new();
    ext.install(
        crate::lsa::originate_v3_e_router_lsa(
            r1,
            ROUTER_BIT_V6,
            0x13,
            vec![e_link(10, 5, 3, r2)],
            None,
        )
        .unwrap(),
        0,
    );
    ext.install(
        crate::lsa::originate_v3_e_router_lsa(
            r2,
            ROUTER_BIT_V6,
            0x13,
            vec![e_link(10, 3, 5, r1)],
            None,
        )
        .unwrap(),
        0,
    );
    ext.install(
        crate::lsa::originate_v3_e_link_lsa(r1, 5, 1, 0x13, ll1, vec![], None).unwrap(),
        0,
    );
    ext.install(
        crate::lsa::originate_v3_e_link_lsa(r2, 3, 1, 0x13, ll2, vec![], None).unwrap(),
        0,
    );
    // The E-IAP references the E-Router-LSA type (RFC 8362 §4.8).
    ext.install(
        crate::lsa::originate_v3_e_intra_area_prefix_lsa(
            r1,
            1,
            crate::lsa::LS_TYPE_E_ROUTER,
            0,
            r1,
            vec![e_prefix_tlv(&p1)],
            None,
        )
        .unwrap(),
        0,
    );
    ext.install(
        crate::lsa::originate_v3_e_intra_area_prefix_lsa(
            r2,
            1,
            crate::lsa::LS_TYPE_E_ROUTER,
            0,
            r2,
            vec![e_prefix_tlv(&p2)],
            None,
        )
        .unwrap(),
        0,
    );

    let spf = run_spf_v3_extended(&ext, r1);
    assert_eq!(spf.vertices, expect.vertices);
    assert_eq!(spf.next_hops, expect.next_hops);
    assert_eq!(spf.adjacent_routers, expect.adjacent_routers);
    assert_eq!(spf.routes, expect.routes);
    // And the concrete acceptance: r2 at cost 10 through its
    // link-local, both prefixes present.
    assert_eq!(spf.vertices.get(&V3VertexId::Router(r2)), Some(&10));
    assert_eq!(
        spf.next_hops
            .get(&V3VertexId::Router(r2))
            .unwrap()
            .link_local,
        IpAddr::V6(ll2)
    );
    assert_eq!(spf.routes.len(), 2);
}

/// RFC 8362 §6.1/§6.2: in extended mode a speaker's E-Router-LSA
/// overrides its legacy Router-LSA; in legacy mode the E-LSAs take
/// no part in the calculation at all.
#[test]
fn v3_e_lsa_preference_and_legacy_ignoring() {
    let r1 = 0x0a00_0001;
    let r2 = 0x0a00_0002;
    let mut db = Lsdb::new();
    // r1 legacy only (root).
    db.install(
        originate_v3_router_lsa(
            r1,
            ROUTER_BIT_V6,
            0x13,
            &[crate::lsa::v3::V3RouterLink {
                link_type: LINK_TYPE_POINTTOPOINT,
                metric: 10,
                interface_id: 5,
                neighbor_interface_id: 3,
                neighbor_router_id: r2,
            }],
            None,
        )
        .unwrap(),
        0,
    );
    // r2 BOTH forms: legacy says metric 10, E says metric 42.
    db.install(
        originate_v3_router_lsa(
            r2,
            ROUTER_BIT_V6,
            0x13,
            &[crate::lsa::v3::V3RouterLink {
                link_type: LINK_TYPE_POINTTOPOINT,
                metric: 10,
                interface_id: 3,
                neighbor_interface_id: 5,
                neighbor_router_id: r1,
            }],
            None,
        )
        .unwrap(),
        0,
    );
    db.install(
        crate::lsa::originate_v3_e_router_lsa(
            r2,
            ROUTER_BIT_V6,
            0x13,
            vec![e_link(42, 3, 5, r1)],
            None,
        )
        .unwrap(),
        0,
    );
    db.install(
        originate_v3_link_lsa(r2, 3, 1, 0x13, fe80(2), vec![], None).unwrap(),
        0,
    );

    // Extended mode: r2's E-Router-LSA wins — its back-link carries
    // metric 42, so r2's vertex distance stays 10 (r1's own link
    // metric) but the E form is what provided the back-link.
    let ext = run_spf_v3_extended(&db, r1);
    assert_eq!(ext.vertices.get(&V3VertexId::Router(r2)), Some(&10));
    assert!(ext.next_hops.contains_key(&V3VertexId::Router(r2)));

    // Legacy mode: the E-LSA is invisible — r2 still at 10 (the
    // legacy back-link provides bidirectionality).
    let legacy = run_spf_v3(&db, r1);
    assert_eq!(legacy.vertices.get(&V3VertexId::Router(r2)), Some(&10));

    // E-only topology under legacy mode: nothing but the root —
    // §6.2's "stored, re-flooded, not used for the SPF".
    let mut e_only = Lsdb::new();
    e_only.install(
        crate::lsa::originate_v3_e_router_lsa(
            r2,
            ROUTER_BIT_V6,
            0x13,
            vec![e_link(10, 3, 5, r1)],
            None,
        )
        .unwrap(),
        0,
    );
    let none = run_spf_v3(&e_only, r1);
    assert!(
        none.vertices.is_empty(),
        "no vertex relaxes from an E-only topology in legacy mode"
    );
    assert!(none.routes.is_empty());
}

/// RFC 8362 §4.3: an E-Inter-Area-Prefix-LSA from a reachable
/// border router contributes the inter-area route in extended mode
/// and is ignored in legacy mode.
#[test]
fn summary_routes_v3_e_inter_area_prefix() {
    let r1 = 0x0a00_0001;
    let r2 = 0x0a00_0002;
    let p = Prefix::new_v6(
        [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 9, 0, 0, 0, 0, 0, 0, 0, 0],
        64,
    );
    let mut db = Lsdb::new();
    db.install(
        originate_v3_router_lsa(
            r1,
            ROUTER_BIT_V6,
            0x13,
            &[crate::lsa::v3::V3RouterLink {
                link_type: LINK_TYPE_POINTTOPOINT,
                metric: 5,
                interface_id: 1,
                neighbor_interface_id: 1,
                neighbor_router_id: r2,
            }],
            None,
        )
        .unwrap(),
        0,
    );
    db.install(
        originate_v3_router_lsa(
            r2,
            ROUTER_BIT_V6,
            0x13,
            &[crate::lsa::v3::V3RouterLink {
                link_type: LINK_TYPE_POINTTOPOINT,
                metric: 5,
                interface_id: 1,
                neighbor_interface_id: 1,
                neighbor_router_id: r1,
            }],
            None,
        )
        .unwrap(),
        0,
    );
    db.install(
        crate::lsa::originate_v3_e_inter_area_prefix_lsa(r2, 1, 30, &p, None).unwrap(),
        0,
    );

    let spf = run_spf_v3_extended(&db, r1);
    let inter = summary_routes_v3_extended(&db, &spf);
    assert_eq!(inter.len(), 1);
    assert_eq!(inter[0].prefix, p);
    assert_eq!(inter[0].metric, 35, "dist(r2)=5 + summary metric 30");
    assert_eq!(inter[0].border_router, Some(r2));

    // Legacy mode ignores the 0xA023.
    let spf_legacy = run_spf_v3(&db, r1);
    assert!(summary_routes_v3(&db, &spf_legacy).is_empty());
}
