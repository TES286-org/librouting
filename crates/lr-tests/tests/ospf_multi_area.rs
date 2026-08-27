//! End-to-end OSPF multi-area tests: per-area LSDB sharing, ABR summary
//! origination (RFC 2328 §12.4.3), inter-area route calculation (§16.2),
//! the inter-area loop guard, and the summary flush lifecycle.

use lr_core::addr::{Prefix, RouterId};
use lr_core::rib::Protocol;
use lr_ospf::abr::originate_summary_lsa;
use lr_ospf::abr::SummaryDestination;
use lr_ospf::lsa::decode_summary_lsa_body;
use lr_ospf::lsa::{Lsa, LsaHeader, LsaTypeV2};
use lr_ospf::packet::{LsUpdateBody, OspfBody, OspfHeader, OspfPacket, OspfPacketType};
use lr_router::{DefaultRouter, RouterInstance, SessionConfig, SessionHandle};

const ROOT: u32 = 0x0101_0101;
const P2P: u8 = 1;
const STUB: u8 = 3;

/// Router-LSA test constructor: `(link_id, link_data, link_type, metric)`.
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
            options: 0x02,
            ls_type: LsaTypeV2::RouterLsa as u8,
            link_state_id: rid,
            advertising_router: rid,
            ls_sequence_number: 0x8000_0001,
            ls_checksum: 0,
            length: (LsaHeader::LEN + body.len()) as u16,
        },
        body,
    }
}

/// Encode one LS-Update carrying `lsas` as if sent by `sender` in `area`.
fn lsu(sender: u32, area: u32, lsas: Vec<Lsa>) -> Vec<u8> {
    let packet = OspfPacket {
        header: OspfHeader {
            version: 2,
            kind: OspfPacketType::LinkStateUpdate as u8,
            length: 0,
            router_id: sender,
            area_id: area,
            checksum: 0,
            au_type_or_instance: 0,
            auth_data: 0,
        },
        body: OspfBody::LsUpdate(LsUpdateBody {
            lsa_count: lsas.len() as u32,
            lsas,
        }),
    };
    lr_ospf::codec::OspfCodec::v2()
        .encode_vec(&packet)
        .expect("encode LS-Update")
}

/// Decode every LS-Update from a drained output stream.
fn decode_lsus(bytes: &[u8]) -> Vec<LsUpdateBody> {
    let mut out = Vec::new();
    let mut codec = lr_ospf::codec::OspfCodec::v2();
    let mut r = lr_core::buf::ReadBuf::new(bytes);
    while let Ok(Some(pkt)) = lr_core::codec::Decoder::decode(&mut codec, &mut r) {
        if let OspfBody::LsUpdate(u) = pkt.body {
            out.push(u);
        }
    }
    out
}

fn abr_with_two_areas() -> (DefaultRouter, SessionHandle, SessionHandle) {
    let mut r = DefaultRouter::new();
    let backbone = r
        .add_session(SessionConfig::ospfv2(RouterId::from_u32(ROOT), 0))
        .unwrap();
    let area1 = r
        .add_session(SessionConfig::ospfv2(RouterId::from_u32(ROOT), 1))
        .unwrap();
    (r, backbone, area1)
}

/// Area-1 content: our Router-LSA (P2P to R2, metric 5) and R2's Router-LSA
/// (link back, stub 10.10.10.0/24 metric 10) → intra-area net at metric 15.
fn area1_lsas() -> Vec<Lsa> {
    vec![
        router_lsa(ROOT, vec![(0x0202_0202, 0, P2P, 5)]),
        router_lsa(
            0x0202_0202,
            vec![(ROOT, 0, P2P, 5), (0x0a0a_0a00, 0xffff_ff00, STUB, 10)],
        ),
    ]
}

#[test]
fn ospf_area_lsa_sharing_and_abr_summary() {
    let (mut r, backbone, area1) = abr_with_two_areas();

    // Both LSAs arrive on the area-1 session in one LS-Update.
    r.feed_input(area1, &lsu(0x0202_0202, 1, area1_lsas()))
        .unwrap();

    // Intra-area route lands in the RIB: 5 (to R2) + 10 (stub) = 15.
    let snap = r.rib_snapshot();
    let route = snap
        .iter()
        .find(|rt| rt.key.prefix == Prefix::new_v4([10, 10, 10, 0], 24))
        .expect("intra-area route installed");
    assert_eq!(route.protocol, Protocol::Ospfv2);
    assert_eq!(route.preference.metric, 15);

    // The backbone session receives a type-3 summary for the area-1 net.
    let updates = decode_lsus(&r.drain_output(backbone));
    assert_eq!(updates.len(), 1, "one summary LS-Update");
    let lsa = &updates[0].lsas[0];
    assert_eq!(lsa.header.ls_type, LsaTypeV2::SummaryIpLsa as u8);
    assert_eq!(lsa.header.advertising_router, ROOT);
    assert_eq!(lsa.header.link_state_id, 0x0a0a_0a00);
    assert_eq!(lsa.header.ls_sequence_number, 0x8000_0001);
    assert!(lsa.checksum_ok());
    let body = decode_summary_lsa_body(&lsa.body).unwrap();
    assert_eq!(body.network_mask, 0xffff_ff00);
    assert_eq!(body.tos0_metric(), Some(15));

    // The summary targets the backbone only — nothing loops back to area 1.
    assert!(r.drain_output(area1).is_empty());
}

#[test]
fn ospf_inter_area_route_from_remote_abr() {
    // Backbone-only router: border router 3.3.3.3 (metric 5 away)
    // summarizes 10.20.20.0/24 metric 7 → inter-area route at metric 12.
    let mut r = DefaultRouter::new();
    let h = r
        .add_session(SessionConfig::ospfv2(RouterId::from_u32(ROOT), 0))
        .unwrap();
    let lsas = vec![
        router_lsa(ROOT, vec![(0x0303_0303, 0, P2P, 5)]),
        router_lsa(0x0303_0303, vec![(ROOT, 0, P2P, 5)]),
        originate_summary_lsa(
            0x0303_0303,
            &SummaryDestination::new(Prefix::new_v4([10, 20, 20, 0], 24), 7),
            None,
        )
        .unwrap(),
    ];
    r.feed_input(h, &lsu(0x0303_0303, 0, lsas)).unwrap();

    let snap = r.rib_snapshot();
    let route = snap
        .iter()
        .find(|rt| rt.key.prefix == Prefix::new_v4([10, 20, 20, 0], 24))
        .expect("inter-area route installed");
    assert_eq!(route.preference.metric, 12);
    assert_eq!(route.protocol, Protocol::Ospfv2);
}

#[test]
fn ospf_inter_area_loop_guard_e2e() {
    // ABR attached to areas 0, 1 and 2. 10.40.40.0/24 is learned
    // *inter-area* in area 1 (from border router 4.4.4.4). It must be
    // usable in the RIB but never re-advertised into area 2 or the
    // backbone (RFC 2328 §12.4.3: only backbone-derived knowledge is
    // summarized into non-backbone areas).
    let mut r = DefaultRouter::new();
    let h0 = r
        .add_session(SessionConfig::ospfv2(RouterId::from_u32(ROOT), 0))
        .unwrap();
    let h1 = r
        .add_session(SessionConfig::ospfv2(RouterId::from_u32(ROOT), 1))
        .unwrap();
    let h2 = r
        .add_session(SessionConfig::ospfv2(RouterId::from_u32(ROOT), 2))
        .unwrap();

    let area1 = vec![
        router_lsa(ROOT, vec![(0x0404_0404, 0, P2P, 5)]),
        router_lsa(0x0404_0404, vec![(ROOT, 0, P2P, 5)]),
        originate_summary_lsa(
            0x0404_0404,
            &SummaryDestination::new(Prefix::new_v4([10, 40, 40, 0], 24), 7),
            None,
        )
        .unwrap(),
    ];
    r.feed_input(h1, &lsu(0x0404_0404, 1, area1)).unwrap();
    // Area 2 carries our own stub net so it has intra-area content.
    r.feed_input(
        h2,
        &lsu(
            0x0505_0505,
            2,
            vec![router_lsa(ROOT, vec![(0x0a32_3200, 0xffff_ff00, STUB, 3)])],
        ),
    )
    .unwrap();

    // The inter-area route is reachable locally (5 + 7 = 12)...
    let snap = r.rib_snapshot();
    let route = snap
        .iter()
        .find(|rt| rt.key.prefix == Prefix::new_v4([10, 40, 40, 0], 24))
        .expect("inter-area route via area 1");
    assert_eq!(route.preference.metric, 12);

    // ...but area 2 learns nothing (backbone knows nothing beyond area 2's
    // own intra net, which the loop guard excludes)...
    assert!(
        r.drain_output(h2).is_empty(),
        "area-1 inter-area knowledge must not transit into area 2"
    );
    // ...and the backbone sees only area 2's intra net (10.50.50.0/24).
    let backbone_lsas: Vec<u32> = decode_lsus(&r.drain_output(h0))
        .iter()
        .flat_map(|u| u.lsas.iter().map(|l| l.header.link_state_id))
        .collect();
    assert_eq!(backbone_lsas, vec![0x0a32_3200]);
}

#[test]
fn ospf_summary_flush_lifecycle_e2e() {
    // Full lifecycle: net appears in area 1 → summarized into the backbone
    // → net disappears (Router-LSA flushed at MaxAge) → the summary is
    // flushed with a MaxAge instance and the route withdraws.
    let (mut r, backbone, area1) = abr_with_two_areas();

    r.feed_input(area1, &lsu(0x0202_0202, 1, area1_lsas()))
        .unwrap();
    assert!(r
        .rib_snapshot()
        .iter()
        .any(|rt| rt.key.prefix == Prefix::new_v4([10, 10, 10, 0], 24)));
    assert_eq!(decode_lsus(&r.drain_output(backbone)).len(), 1);
    let _ = r.drain_output(area1);

    // R2's Router-LSA ages out: MaxAge instance with advanced sequence.
    let mut r2 = area1_lsas().remove(1);
    r2.header.ls_age = lr_ospf::lsdb::MAX_AGE_SECS;
    r2.header.ls_sequence_number += 1;
    r.feed_input(area1, &lsu(0x0202_0202, 1, vec![r2])).unwrap();

    let updates = decode_lsus(&r.drain_output(backbone));
    let flushed = updates
        .iter()
        .flat_map(|u| u.lsas.iter())
        .find(|l| l.header.ls_type == LsaTypeV2::SummaryIpLsa as u8)
        .expect("backbone summary must be flushed");
    assert_eq!(flushed.header.ls_age, lr_ospf::lsdb::MAX_AGE_SECS);
    assert_eq!(flushed.header.link_state_id, 0x0a0a_0a00);

    assert!(
        !r.rib_snapshot()
            .iter()
            .any(|rt| rt.key.prefix == Prefix::new_v4([10, 10, 10, 0], 24)),
        "route must withdraw with its summary"
    );
}

#[test]
fn ospf_multi_area_two_router_propagation() {
    // Two router instances wired session-to-session: ABR-X (areas 0+1) and
    // a plain backbone router BR-Y (area 0). A net inside area 1 of ABR-X
    // propagates to BR-Y through the backbone summary; BR-Y installs it
    // as an inter-area route at the summarized metric.
    let mut abr = DefaultRouter::new();
    let abr_bb = abr
        .add_session(SessionConfig::ospfv2(RouterId::from_u32(ROOT), 0))
        .unwrap();
    let abr_a1 = abr
        .add_session(SessionConfig::ospfv2(RouterId::from_u32(ROOT), 1))
        .unwrap();

    let mut br_y = DefaultRouter::new();
    let y_bb = br_y
        .add_session(SessionConfig::ospfv2(RouterId::from_u32(0x0303_0303), 0))
        .unwrap();

    // BR-Y's own Router-LSA (stub 10.30.30.0/24 metric 2) plus the link
    // toward ABR-X — both sides see each other via P2P links.
    let y_lsas = vec![router_lsa(
        0x0303_0303,
        vec![(ROOT, 0, P2P, 3), (0x0a1e_1e00, 0xffff_ff00, STUB, 2)],
    )];
    let x_bb_lsas = vec![router_lsa(ROOT, vec![(0x0303_0303, 0, P2P, 3)])];
    // Self-origination: each router's own Router-LSA must enter its own
    // area LSDB (this poll-driven model leaves origination to the
    // embedder), then each learns the other's LSA across the wire.
    br_y.feed_input(y_bb, &lsu(0x0303_0303, 0, y_lsas.clone()))
        .unwrap();
    abr.feed_input(abr_bb, &lsu(ROOT, 0, x_bb_lsas.clone()))
        .unwrap();
    br_y.feed_input(y_bb, &lsu(ROOT, 0, x_bb_lsas.clone()))
        .unwrap();
    abr.feed_input(abr_bb, &lsu(0x0303_0303, 0, y_lsas.clone()))
        .unwrap();

    // Area 1 of ABR-X carries the internal net (metric 15 as above).
    abr.feed_input(abr_a1, &lsu(0x0202_0202, 1, area1_lsas()))
        .unwrap();

    // Pump the backbone sessions to convergence: ABR-X's summary for
    // 10.10.10.0/24 reaches BR-Y; BR-Y's Router-LSA reaches ABR-X.
    for _ in 0..8 {
        let out_x = abr.drain_output(abr_bb);
        if !out_x.is_empty() {
            br_y.feed_input(y_bb, &out_x).unwrap();
        }
        let out_y = br_y.drain_output(y_bb);
        if !out_y.is_empty() {
            abr.feed_input(abr_bb, &out_y).unwrap();
        }
        if out_x.is_empty() && out_y.is_empty() {
            break;
        }
    }

    // BR-Y: inter-area route to 10.10.10.0/24 at 3 (to ABR-X) + 15 = 18,
    // and the intra-area stub 10.30.30.0/24 at metric 2.
    let snap = br_y.rib_snapshot();
    let r1 = snap
        .iter()
        .find(|rt| rt.key.prefix == Prefix::new_v4([10, 10, 10, 0], 24))
        .expect("summary reached BR-Y");
    assert_eq!(r1.preference.metric, 18);
    let r2 = snap
        .iter()
        .find(|rt| rt.key.prefix == Prefix::new_v4([10, 30, 30, 0], 24))
        .expect("BR-Y keeps its own intra-area net");
    assert_eq!(r2.preference.metric, 2);

    // ABR-X: BR-Y's stub net arrives as an inter-area route (3 + 2 = 5)
    // but its own area-1 intra net still wins at metric 15.
    let snap_x = abr.rib_snapshot();
    let r_intra = snap_x
        .iter()
        .find(|rt| rt.key.prefix == Prefix::new_v4([10, 10, 10, 0], 24))
        .expect("area-1 net on ABR-X");
    assert_eq!(r_intra.preference.metric, 15, "intra-area must win");
    let r_inter = snap_x
        .iter()
        .find(|rt| rt.key.prefix == Prefix::new_v4([10, 30, 30, 0], 24))
        .expect("BR-Y net learned inter-area on ABR-X");
    assert_eq!(r_inter.preference.metric, 5);
}
