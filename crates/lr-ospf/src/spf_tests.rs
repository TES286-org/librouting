use super::*;
use crate::lsa::{Lsa, LsaHeader};
use lr_core::addr::Prefix;

fn router_lsa(rid: u32, links: Vec<(u32, u32, u8, u16)>) -> Lsa {
    let mut body = Vec::new();
    body.extend_from_slice(&0u16.to_be_bytes()); // flags
    body.extend_from_slice(&(links.len() as u16).to_be_bytes());
    for (lid, ldata, ltype, metric) in links {
        body.extend_from_slice(&lid.to_be_bytes());
        body.extend_from_slice(&ldata.to_be_bytes());
        body.push(ltype);
        body.push(0); // tos
        body.extend_from_slice(&metric.to_be_bytes());
    }
    Lsa {
        header: LsaHeader {
            ls_age: 0,
            options: 0,
            ls_type: 1,
            link_state_id: rid,
            advertising_router: rid,
            ls_sequence_number: 0x80000001,
            ls_checksum: 0,
            length: (LsaHeader::LEN + body.len()) as u16,
        },
        body,
    }
}

#[allow(dead_code)]
fn stub_lsa(rid: u32, network: u32, mask: u32, metric: u16) -> Lsa {
    router_lsa(
        rid,
        vec![(network, mask, RouterLinkType::StubNetwork as u8, metric)],
    )
}

#[test]
fn dijkstra_basic() {
    let mut db = Lsdb::new();
    // A (1.2.3.4) — link to B (5.6.7.8), metric 10
    db.install(
        router_lsa(
            0x01020304,
            vec![(0x05060708, 0, RouterLinkType::PointToPoint as u8, 10)],
        ),
        0,
    );
    // B (5.6.7.8) — link back to A, stub 10.0.0.0/8 metric 0
    db.install(
        router_lsa(
            0x05060708,
            vec![
                (0x01020304, 0, RouterLinkType::PointToPoint as u8, 10),
                (0x0a000000, 0xff000000, RouterLinkType::StubNetwork as u8, 0),
            ],
        ),
        0,
    );
    let res = run_spf(&db, 0x01020304);
    assert_eq!(res.vertices.get(&VertexId::Router(0x05060708)), Some(&10));
    assert_eq!(res.stub_routes.len(), 1);
    let expected = Prefix::new_v4([10, 0, 0, 0], 8);
    assert_eq!(res.stub_routes[0].prefix, expected);
    assert_eq!(res.stub_routes[0].metric, 10);
}

#[test]
fn mask_to_pl_known() {
    assert_eq!(mask_to_pl(0xff000000), 8);
    assert_eq!(mask_to_pl(0xffffff00), 24);
    assert_eq!(mask_to_pl(0xffffffff), 32);
}

const P2P: u8 = RouterLinkType::PointToPoint as u8;
const STUB: u8 = RouterLinkType::StubNetwork as u8;
const TRANSIT: u8 = RouterLinkType::TransitNetwork as u8;

fn ip(octets: [u8; 4]) -> IpAddr {
    IpAddr::V4(octets)
}

#[test]
fn next_hops_resolve_from_the_back_link_and_inherit() {
    // A (1.1.1.1) —10— B (2.2.2.2) —10— C (3.3.3.3); B's and C's
    // p2p links carry their own interface addresses as Link Data
    // (RFC 2328 §A.4.2), A's stay 0 (its own address is not a next
    // hop for anyone). RFC 2328 §16.1.1 (5)/(2): nh(B) = B's
    // address on the shared link; nh(C) = nh(B) (inheritance).
    let mut db = Lsdb::new();
    db.install(router_lsa(0x01010101, vec![(0x02020202, 0, P2P, 10)]), 0);
    db.install(
        router_lsa(
            0x02020202,
            vec![
                // Back-link toward A: Link Data = B's address on A-B.
                (0x01010101, 0x0a000001, P2P, 10),
                // Link toward C: Link Data = B's address on B-C.
                (0x03030303, 0x0a000102, P2P, 10),
                (0x0a140000, 0xffff0000, STUB, 5),
            ],
        ),
        0,
    );
    db.install(
        // C's back-link toward B: Link Data = C's address on B-C.
        router_lsa(0x03030303, vec![(0x02020202, 0x0a000102, P2P, 10)]),
        0,
    );
    let res = run_spf(&db, 0x01010101);
    assert_eq!(
        res.next_hops.get(&VertexId::Router(0x02020202)),
        Some(&ip([10, 0, 0, 1]))
    );
    assert_eq!(
        res.next_hops.get(&VertexId::Router(0x03030303)),
        Some(&ip([10, 0, 0, 1]))
    );
    // B's stub network routes forward through B (RFC 2328 §16.1.1:
    // a stub network inherits the advertising router vertex's next
    // hop) — the path a mapping-server label rides (RFC 8661
    // §3.2.2).
    assert!(res
        .stub_routes
        .iter()
        .all(|r| r.next_hop == Some(ip([10, 0, 0, 1]))));
    assert!(res.adjacent_routers.contains(&0x02020202));
    assert!(!res.adjacent_routers.contains(&0x03030303));
}

#[test]
fn next_hops_via_transit_network_use_the_attached_router_address() {
    // A (1.1.1.1) has a transit link to the DR address 10.0.0.1;
    // the Network-LSA (ls_id 10.0.0.1, mask /24) attaches A and
    // B (2.2.2.2). §16.1.1 (4): nh(B) = B's address on that
    // network = the Link Data of B's transit link (10.0.0.2).
    let mut db = Lsdb::new();
    db.install(
        router_lsa(0x01010101, vec![(0x0a000001, 0, TRANSIT, 10)]),
        0,
    );
    // B: transit link back to the same DR (its addr 10.0.0.2) plus
    // a deeper p2p neighbor C whose back-link carries C's address.
    db.install(
        router_lsa(
            0x02020202,
            vec![
                (0x0a000001, 0x0a000002, TRANSIT, 10),
                (0x03030303, 0x0a000202, P2P, 10),
            ],
        ),
        0,
    );
    db.install(
        router_lsa(0x03030303, vec![(0x02020202, 0x0a000202, P2P, 10)]),
        0,
    );
    let mut net_body = Vec::new();
    net_body.extend_from_slice(&0xffff_ff00u32.to_be_bytes());
    net_body.extend_from_slice(&0x01010101u32.to_be_bytes());
    net_body.extend_from_slice(&0x02020202u32.to_be_bytes());
    db.install(
        Lsa {
            header: LsaHeader {
                ls_age: 0,
                options: 2,
                ls_type: LsaTypeV2::NetworkLsa as u16,
                link_state_id: 0x0a000001,
                advertising_router: 0x01010101,
                ls_sequence_number: 0x80000001,
                ls_checksum: 0,
                length: (LsaHeader::LEN + net_body.len()) as u16,
            },
            body: net_body,
        },
        0,
    );
    let res = run_spf(&db, 0x01010101);
    assert_eq!(
        res.next_hops.get(&VertexId::Router(0x02020202)),
        Some(&ip([10, 0, 0, 2]))
    );
    // C hangs off B: inherits B's next hop (§16.1.1 (2)).
    assert_eq!(
        res.next_hops.get(&VertexId::Router(0x03030303)),
        Some(&ip([10, 0, 0, 2]))
    );
    // B is one hop away (via the shared network) — penultimate for
    // its prefix-SIDs; C is not.
    assert!(res.adjacent_routers.contains(&0x02020202));
    assert!(!res.adjacent_routers.contains(&0x03030303));
    // The transit prefix route is still present with no next hop.
    let net = res
        .transit_routes
        .iter()
        .find(|r| r.prefix == Prefix::new_v4([10, 0, 0, 0], 24))
        .expect("transit route");
    assert_eq!(net.metric, 10);
    assert!(net.next_hop.is_none());
}

#[test]
fn zero_link_data_keeps_the_next_hop_unresolved() {
    // B's back-link carries Link Data 0 (unnumbered): no next hop
    // can be resolved from the database, so the vertex has none.
    let mut db = Lsdb::new();
    db.install(router_lsa(0x01010101, vec![(0x02020202, 0, P2P, 10)]), 0);
    db.install(router_lsa(0x02020202, vec![(0x01010101, 0, P2P, 10)]), 0);
    let res = run_spf(&db, 0x01010101);
    assert!(!res.next_hops.contains_key(&VertexId::Router(0x02020202)));
    // Topology itself is unaffected.
    assert_eq!(res.vertices.get(&VertexId::Router(0x02020202)), Some(&10));
}

#[test]
fn virtual_links_act_as_router_adjacencies() {
    // Backbone repair (RFC 2328 §15): R1 reaches R3 only through the
    // virtual adjacency R1 == R2 (metric 7, the transit-area path
    // cost); R2 also has a physical p2p link to R3 (metric 3).
    let mut db = Lsdb::new();
    db.install(
        router_lsa(
            0x01010101,
            vec![(0x02020202, 0, RouterLinkType::VirtualLink as u8, 7)],
        ),
        0,
    );
    db.install(
        router_lsa(
            0x02020202,
            vec![
                (0x01010101, 0, RouterLinkType::VirtualLink as u8, 7),
                (0x03030303, 0, RouterLinkType::PointToPoint as u8, 3),
            ],
        ),
        0,
    );
    db.install(
        router_lsa(
            0x03030303,
            vec![
                (0x02020202, 0, RouterLinkType::PointToPoint as u8, 3),
                (0x0a646400, 0xffffff00, RouterLinkType::StubNetwork as u8, 2),
            ],
        ),
        0,
    );
    // From the far side of the virtual link: R3 is 7 + 3 away and its
    // stub network adds 2 more.
    let res = run_spf(&db, 0x01010101);
    assert_eq!(res.vertices.get(&VertexId::Router(0x03030303)), Some(&10));
    assert_eq!(res.vertices.get(&VertexId::Router(0x02020202)), Some(&7));
    assert_eq!(res.stub_routes.len(), 1);
    assert_eq!(res.stub_routes[0].metric, 12);
    // And in the other direction the virtual link is symmetric.
    let res = run_spf(&db, 0x03030303);
    assert_eq!(res.vertices.get(&VertexId::Router(0x01010101)), Some(&10));
}

fn summary_lsa(adv: u32, network: u32, mask: u32, metric: u32, seq: u32) -> Lsa {
    let body = crate::lsa::encode_summary_lsa_body(mask, metric);
    Lsa {
        header: LsaHeader {
            ls_age: 0,
            options: 0x02,
            ls_type: LsaTypeV2::SummaryIpLsa as u16,
            link_state_id: network,
            advertising_router: adv,
            ls_sequence_number: seq,
            ls_checksum: 0,
            length: (LsaHeader::LEN + body.len()) as u16,
        },
        body,
    }
}

/// Area-0 topology: root (1.1.1.1) --10-- BR-a (2.2.2.2),
/// root --20-- BR-b (3.3.3.3); BR-a and BR-b are border routers
/// advertising summaries.
fn two_border_routers() -> Lsdb {
    let mut db = Lsdb::new();
    let root = 0x01010101;
    let br_a = 0x02020202;
    let br_b = 0x03030303;
    db.install(
        router_lsa(
            root,
            vec![(br_a, 0, RouterLinkType::PointToPoint as u8, 10)],
        ),
        0,
    );
    db.install(
        router_lsa(
            br_a,
            vec![(root, 0, RouterLinkType::PointToPoint as u8, 10)],
        ),
        0,
    );
    db.install(
        router_lsa(
            root,
            vec![(br_b, 0, RouterLinkType::PointToPoint as u8, 20)],
        ),
        0,
    );
    db.install(
        router_lsa(
            br_b,
            vec![(root, 0, RouterLinkType::PointToPoint as u8, 20)],
        ),
        0,
    );
    db
}

#[test]
fn summary_route_requires_reachable_border() {
    let mut db = two_border_routers();
    let spf = run_spf(&db, 0x01010101);
    // Summary from unreachable border router 9.9.9.9: ignored.
    db.install(
        summary_lsa(0x09090909, 0x0a000000, 0xff000000, 5, 0x80000001),
        0,
    );
    assert!(summary_routes(&db, &spf).is_empty());
}

#[test]
fn summary_metric_adds_border_distance() {
    let mut db = two_border_routers();
    let spf = run_spf(&db, 0x01010101);
    // BR-a (dist 10) advertises 10.0.0.0/8 metric 7 → 17.
    db.install(
        summary_lsa(0x02020202, 0x0a000000, 0xff000000, 7, 0x80000001),
        0,
    );
    let routes = summary_routes(&db, &spf);
    assert_eq!(routes.len(), 1);
    assert_eq!(routes[0].prefix, Prefix::new_v4([10, 0, 0, 0], 8));
    assert_eq!(routes[0].metric, 17);
}

#[test]
fn summary_prefers_lower_total_metric_then_lower_border() {
    let mut db = two_border_routers();
    let spf = run_spf(&db, 0x01010101);
    // BR-a: dist 10 + 7 = 17; BR-b: dist 20 + 5 = 25 → BR-a wins.
    db.install(
        summary_lsa(0x02020202, 0x0a000000, 0xff000000, 7, 0x80000001),
        0,
    );
    db.install(
        summary_lsa(0x03030303, 0x0a000000, 0xff000000, 5, 0x80000001),
        0,
    );
    let routes = summary_routes(&db, &spf);
    assert_eq!(routes.len(), 1);
    assert_eq!(routes[0].metric, 17);

    // Equal total metric → lower border router ID (BR-a) wins.
    let mut db2 = two_border_routers();
    let spf2 = run_spf(&db2, 0x01010101);
    db2.install(
        summary_lsa(0x02020202, 0x0a000000, 0xff000000, 10, 0x80000001),
        0,
    );
    db2.install(
        summary_lsa(0x03030303, 0x0a000000, 0xff000000, 0, 0x80000001),
        0,
    );
    let routes2 = summary_routes(&db2, &spf2);
    assert_eq!(routes2.len(), 1);
    assert_eq!(routes2[0].metric, 20); // both 20 — deterministic winner
}

#[test]
fn summary_ls_infinity_and_garbage_ignored() {
    let mut db = two_border_routers();
    let spf = run_spf(&db, 0x01010101);
    // LSInfinity means unreachable.
    db.install(
        summary_lsa(0x02020202, 0x0a000000, 0xff000000, 0x00ff_ffff, 0x80000001),
        0,
    );
    // Truncated body (no TOS entry).
    let mut bad = summary_lsa(0x02020202, 0x0b000000, 0xff000000, 1, 0x80000001);
    bad.body.truncate(4);
    db.install(bad, 0);
    assert!(summary_routes(&db, &spf).is_empty());
}
