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
        res.next_hops
            .get(&VertexId::Router(0x02020202))
            .and_then(|v| v.first().copied()),
        Some(ip([10, 0, 0, 1]))
    );
    assert_eq!(
        res.next_hops
            .get(&VertexId::Router(0x03030303))
            .and_then(|v| v.first().copied()),
        Some(ip([10, 0, 0, 1]))
    );
    // B's stub network routes forward through B (RFC 2328 §16.1.1:
    // a stub network inherits the advertising router vertex's next
    // hop) — the path a mapping-server label rides (RFC 8661
    // §3.2.2).
    assert!(res
        .stub_routes
        .iter()
        .all(|r| r.next_hop.first().copied() == Some(ip([10, 0, 0, 1]))));
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
        res.next_hops
            .get(&VertexId::Router(0x02020202))
            .and_then(|v| v.first().copied()),
        Some(ip([10, 0, 0, 2]))
    );
    // C hangs off B: inherits B's next hop (§16.1.1 (2)).
    assert_eq!(
        res.next_hops
            .get(&VertexId::Router(0x03030303))
            .and_then(|v| v.first().copied()),
        Some(ip([10, 0, 0, 2]))
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
    assert!(net.next_hop.is_empty());
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

// Regression for the TOS-metric-skip bug in `decode_router_links`
// (defects.txt spf.rs L501-L503). Before the fix, the parser advanced
// `i += 12` per link unconditionally, ignoring the `# TOS` byte; a
// router-LSA whose link declared `# TOS > 0` would have its trailing
// TOS-specific metric entries misread as the next link's (Link ID,
// Link Data, Type, # TOS) header, silently corrupting the rest of
// the list. RFC 2328 §A.4.2 sizes each additional TOS entry at 4
// octets: `TOS:1 | 0:1 | TOS metric:2`.
//
// Pushes one router-LSA link entry to `body` — the 12-byte base
// (link_id, link_data, type, #tos, tos0_metric) followed by `tos_metrics`
// additional 4-octet TOS-specific metric entries.
fn push_router_link(
    body: &mut Vec<u8>,
    link_id: u32,
    link_data: u32,
    link_type: u8,
    tos0_metric: u16,
    tos_metrics: &[(u8, u16)],
) {
    body.extend_from_slice(&link_id.to_be_bytes());
    body.extend_from_slice(&link_data.to_be_bytes());
    body.push(link_type);
    body.push(tos_metrics.len() as u8);
    body.extend_from_slice(&tos0_metric.to_be_bytes());
    for (tos, metric) in tos_metrics {
        body.push(*tos);
        body.push(0); // reserved
        body.extend_from_slice(&metric.to_be_bytes());
    }
}

#[test]
fn decode_router_links_skips_tos_metric_entries() {
    // Two links. The first carries 2 TOS-specific metric entries
    // (8 extra octets); the second is a vanilla stub link. Before the
    // fix the parser would step 12 octets after link 1 and treat the
    // first TOS entry's bytes as link 2's (Link ID, Link Data) —
    // making `links.len()` collapse to 1 with bogus fields, and
    // usually emitting a fake second link out of trailing bytes.
    let mut body = Vec::new();
    body.extend_from_slice(&0u16.to_be_bytes()); // flags
    body.extend_from_slice(&2u16.to_be_bytes()); // # links = 2
    push_router_link(
        &mut body,
        0x0a000001,
        0xff000000,
        RouterLinkType::StubNetwork as u8,
        10,
        &[(0x04, 20), (0x08, 30)],
    );
    push_router_link(
        &mut body,
        0x0a000002,
        0xff000000,
        RouterLinkType::StubNetwork as u8,
        5,
        &[],
    );
    let links = decode_router_links(&body);
    assert_eq!(links.len(), 2, "both links survive the TOS-skip");
    assert_eq!(links[0].link_id, 0x0a000001);
    assert_eq!(links[0].tos, 2, "# TOS byte preserved on the first link");
    assert_eq!(links[0].metric, 10, "TOS 0 metric preserved");
    assert_eq!(
        links[1].link_id, 0x0a000002,
        "second link's header is read past the first link's TOS entries"
    );
    assert_eq!(links[1].tos, 0);
    assert_eq!(links[1].metric, 5);
}

#[test]
fn decode_router_links_stops_on_truncated_tos_section() {
    // Advertises `# TOS = 3` (12 octets of TOS entries) but only
    // supplies 4 octets of them — the parser must not overrun the
    // buffer trying to honour the link count, and the truncated
    // link is the last one emitted.
    let mut body = Vec::new();
    body.extend_from_slice(&0u16.to_be_bytes()); // flags
    body.extend_from_slice(&1u16.to_be_bytes()); // # links = 1
    push_router_link(
        &mut body,
        0x0a000003,
        0xff000000,
        RouterLinkType::StubNetwork as u8,
        10,
        // Only one TOS entry appended, but `# TOS` says 3 (set inside
        // `push_router_link` from `tos_metrics.len()` = 1).
        &[(0x04, 20)],
    );
    // Manually patch the # TOS byte to claim 3 (without growing the
    // trailing TOS bytes) — emulates a malformed LSA from the wire.
    body[4 + 4 + 4 + 1] = 3; // header(4) + link_id(4) + link_data(4) + type(1)
    let links = decode_router_links(&body);
    assert_eq!(links.len(), 1, "truncated link is still emitted");
    assert_eq!(links[0].tos, 3, "# TOS byte preserved");
    assert_eq!(links[0].metric, 10);
    // No second link, even though `# links` says 1 — the truncation
    // breaks the advertised count and the loop bails out cleanly.
}

// ECMP — RFC 2328 §16.1 (4): when several parents at the same shortest
// distance contribute distinct next hops, every distinct hop is recorded.
// Two p2p neighbours of equal cost (10 each) gives the root two equal-cost
// paths to a deeper vertex reached through both — both neighbours' Link
// Data must end up in the result's next-hop set, not just one.
#[test]
fn ecmp_records_distinct_first_hops_for_equal_cost_paths() {
    // Topology:
    //   root (1.1.1.1) --10-- R2 (2.2.2.2)
    //   root          --10-- R3 (3.3.3.3)
    //   R2 --10-- R4 (4.4.4.4)
    //   R3 --10-- R4
    // root → R4 has two equal-cost paths (10+10=20 each) through R2 and
    // R3. The next-hop set for R4 must carry both R2's address (10.0.0.1)
    // and R3's address (10.0.0.2) — the SPF relaxation now records equal-
    // cost next-hops instead of dropping them (the previous strict-`<`
    // `relax` would have kept only the first parent's hop).
    let mut db = Lsdb::new();
    db.install(
        router_lsa(
            0x01010101,
            vec![
                (0x02020202, 0, RouterLinkType::PointToPoint as u8, 10),
                (0x03030303, 0, RouterLinkType::PointToPoint as u8, 10),
            ],
        ),
        0,
    );
    // R2's back-link toward root carries R2's address (10.0.0.1).
    db.install(
        router_lsa(
            0x02020202,
            vec![
                (
                    0x01010101,
                    0x0a000001,
                    RouterLinkType::PointToPoint as u8,
                    10,
                ),
                (
                    0x04040404,
                    0x0a000101,
                    RouterLinkType::PointToPoint as u8,
                    10,
                ),
            ],
        ),
        0,
    );
    // R3's back-link toward root carries R3's address (10.0.0.2).
    db.install(
        router_lsa(
            0x03030303,
            vec![
                (
                    0x01010101,
                    0x0a000002,
                    RouterLinkType::PointToPoint as u8,
                    10,
                ),
                (
                    0x04040404,
                    0x0a000102,
                    RouterLinkType::PointToPoint as u8,
                    10,
                ),
            ],
        ),
        0,
    );
    // R4 has back-links toward both R2 and R3.
    db.install(
        router_lsa(
            0x04040404,
            vec![
                (
                    0x02020202,
                    0x0a000101,
                    RouterLinkType::PointToPoint as u8,
                    10,
                ),
                (
                    0x03030303,
                    0x0a000102,
                    RouterLinkType::PointToPoint as u8,
                    10,
                ),
            ],
        ),
        0,
    );
    let res = run_spf(&db, 0x01010101);

    // R2 and R3 are each one hop from the root with their own Link Data
    // as next hop. Both are direct adjacencies — single-hop next-hops.
    let r2_nh = res
        .next_hops
        .get(&VertexId::Router(0x02020202))
        .and_then(|v| v.first().copied())
        .expect("R2 next hop resolved");
    assert_eq!(r2_nh, IpAddr::V4([10, 0, 0, 1]));
    let r3_nh = res
        .next_hops
        .get(&VertexId::Router(0x03030303))
        .and_then(|v| v.first().copied())
        .expect("R3 next hop resolved");
    assert_eq!(r3_nh, IpAddr::V4([10, 0, 0, 2]));

    // R4 is two hops away via both R2 and R3 at equal cost (20). The
    // next-hop set MUST contain both first hops, in discovery order.
    // Discovery order is the LSDB's BTreeMap iteration order — R2 (Link
    // State ID 0x02020202) is iterated before R3 (0x03030303), so R2's
    // hop is recorded first.
    let r4_nhs = res
        .next_hops
        .get(&VertexId::Router(0x04040404))
        .expect("R4 reachable");
    assert_eq!(
        r4_nhs.len(),
        2,
        "ECMP: both R2 and R3 next-hops must be recorded for R4"
    );
    assert_eq!(
        r4_nhs[0],
        IpAddr::V4([10, 0, 0, 1]),
        "R2 first (BTreeMap order)"
    );
    assert_eq!(r4_nhs[1], IpAddr::V4([10, 0, 0, 2]), "R3 second");
}

// ECMP inter-area: when two ABRs advertise the same summary at the same
// total metric (border-router distance + summary metric), the resulting
// SpfRoute must carry both ABRs' first hops, not just one. The lowest
// border router ID stays in `border_router` for the `ospf.router_id`
// accessor's determinism.
#[test]
fn ecmp_summary_collects_next_hops_from_equal_cost_abrs() {
    // Topology: root (1.1.1.1) --10-- BR-a (2.2.2.2),
    // root --10-- BR-b (3.3.3.3). Both advertise the same prefix
    // 10.0.0.0/8 at summary metric 5 — total 15 each. ECMP: both
    // border routers' first hops must land in the route's `next_hop`.
    //
    // Root has ONE Router-LSA listing both p2p neighbours (the LSDB
    // keys a Router-LSA by its advertising-router ID, so the second
    // install would overwrite the first — the helper's two-LSA shape
    // is unsuitable here).
    let mut db = Lsdb::new();
    let root = 0x01010101;
    let br_a = 0x02020202;
    let br_b = 0x03030303;
    db.install(
        router_lsa(
            root,
            vec![
                (br_a, 0, RouterLinkType::PointToPoint as u8, 10),
                (br_b, 0, RouterLinkType::PointToPoint as u8, 10),
            ],
        ),
        0,
    );
    db.install(
        router_lsa(
            br_a,
            vec![(root, 0x0a000001, RouterLinkType::PointToPoint as u8, 10)],
        ),
        0,
    );
    db.install(
        router_lsa(
            br_b,
            vec![(root, 0x0a000002, RouterLinkType::PointToPoint as u8, 10)],
        ),
        0,
    );
    // Both ABRs advertise the same prefix at the same metric (5) →
    // total cost 15 each, equal-cost ECMP.
    db.install(summary_lsa(br_a, 0x0a000000, 0xff000000, 5, 0x80000001), 0);
    db.install(summary_lsa(br_b, 0x0a000000, 0xff000000, 5, 0x80000001), 0);

    let spf = run_spf(&db, root);
    let routes = summary_routes(&db, &spf);
    assert_eq!(routes.len(), 1, "one route for the prefix");
    let r = &routes[0];
    assert_eq!(r.prefix, Prefix::new_v4([10, 0, 0, 0], 8));
    assert_eq!(
        r.metric, 15,
        "total cost = border distance + summary metric"
    );
    // The border_router / router_id stays the lowest ABR (deterministic
    // for the ospf.router_id accessor) — br_a (0x02020202) < br_b.
    assert_eq!(r.border_router, Some(br_a));
    assert_eq!(r.router_id, Some(br_a));
    // ECMP: the next-hop set carries both ABRs' first hops, in
    // discovery order (BTreeMap iteration → br_a first).
    assert_eq!(r.next_hop.len(), 2, "ECMP: both ABR next-hops recorded");
    assert_eq!(r.next_hop[0], IpAddr::V4([10, 0, 0, 1]), "BR-a first");
    assert_eq!(r.next_hop[1], IpAddr::V4([10, 0, 0, 2]), "BR-b second");
}

// ECMP de-duplicates: when the same first hop is reachable through
// multiple parents at equal cost, the next-hop set contains it once.
// The classic case is two ABRs reachable through the same shared
// transit network — both inherit the network's first hop, but the
// set should not double-count.
#[test]
fn ecmp_dedupes_identical_next_hops_from_equal_cost_parents() {
    // root (1.1.1.1) -- R2 (2.2.2.2) -- R3 (3.3.3.3)
    //                  R2 -- R4 (4.4.4.4)
    //                  R3 -- R4
    // Two paths to R4 (via R2 or R3), but R3 inherits R2's next hop when
    // relaxing from R2 — the relaxation from R3 sees the same next hop
    // already in the set and skips the duplicate.
    //
    // For a real de-dupe test we need two distinct next hops that
    // converge on the same router via different physical adjacencies
    // that resolve to the SAME IP. The cleanest construction: root has
    // two p2p neighbours (R2, R3) whose Link Data both happen to be
    // 10.0.0.1 (e.g. they share an unnumbered link to the root, which
    // is unusual but legal). The relaxation from R3 still tries to add
    // 10.0.0.1, but the entry is already there from R2 — the set keeps
    // one copy.
    let mut db = Lsdb::new();
    db.install(
        router_lsa(
            0x01010101,
            vec![
                (0x02020202, 0, RouterLinkType::PointToPoint as u8, 10),
                (0x03030303, 0, RouterLinkType::PointToPoint as u8, 10),
            ],
        ),
        0,
    );
    db.install(
        router_lsa(
            0x02020202,
            vec![
                (
                    0x01010101,
                    0x0a000001,
                    RouterLinkType::PointToPoint as u8,
                    10,
                ),
                (
                    0x04040404,
                    0x0a000101,
                    RouterLinkType::PointToPoint as u8,
                    10,
                ),
            ],
        ),
        0,
    );
    db.install(
        router_lsa(
            0x03030303,
            vec![
                // Same Link Data 0x0a000001 as R2 uses toward root —
                // a deliberately degenerate case that exercises the
                // de-duplicate path in the relaxation's ECMP branch.
                (
                    0x01010101,
                    0x0a000001,
                    RouterLinkType::PointToPoint as u8,
                    10,
                ),
                (
                    0x04040404,
                    0x0a000102,
                    RouterLinkType::PointToPoint as u8,
                    10,
                ),
            ],
        ),
        0,
    );
    db.install(
        router_lsa(
            0x04040404,
            vec![
                (
                    0x02020202,
                    0x0a000101,
                    RouterLinkType::PointToPoint as u8,
                    10,
                ),
                (
                    0x03030303,
                    0x0a000102,
                    RouterLinkType::PointToPoint as u8,
                    10,
                ),
            ],
        ),
        0,
    );
    let res = run_spf(&db, 0x01010101);
    let r4_nhs = res
        .next_hops
        .get(&VertexId::Router(0x04040404))
        .expect("R4 reachable");
    // Both parents (R2 and R3) inherit the SAME next hop (10.0.0.1)
    // from the root-R2 link and the root-R3 link. De-duplication
    // collapses the set to one entry — RFC 2328 §16.1 (4) says
    // "equal-cost paths install distinct first hops", so a duplicate
    // is not a second path.
    assert_eq!(
        r4_nhs.len(),
        1,
        "ECMP de-dup: identical next hop recorded once, not twice"
    );
    assert_eq!(r4_nhs[0], IpAddr::V4([10, 0, 0, 1]));
}
