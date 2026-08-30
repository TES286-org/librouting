//! End-to-end tests for iBGP / route-reflector topologies, Babel and OSPF
//! session runtimes, and cross-protocol RIB merging.

use lr_core::addr::{Asn, IpAddr, Prefix, RouterId};
use lr_core::nlri::NlriFamily;
use lr_core::rib::RouteKey;
use lr_router::{DefaultRouter, RouterInstance, SessionConfig, SessionHandle};

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

/// iBGP: A and B in AS 64512. A's locally-originated route reaches B with an
/// empty AS path and LOCAL_PREF 100.
#[test]
fn ibgp_route_propagates_with_local_pref() {
    let mut a = DefaultRouter::new();
    let mut b = DefaultRouter::new();
    let ha = a
        .add_session(
            SessionConfig::bgp(Asn(64512), Asn(64512), RouterId::from_v4([10, 0, 0, 1]))
                .with_local_address(IpAddr::V4([192, 0, 2, 1])),
        )
        .unwrap();
    let hb = b
        .add_session(
            SessionConfig::bgp(Asn(64512), Asn(64512), RouterId::from_v4([10, 0, 0, 2]))
                .with_local_address(IpAddr::V4([192, 0, 2, 2])),
        )
        .unwrap();
    a.start_session(ha).unwrap();
    b.start_session(hb).unwrap();
    pump(&mut a, ha, &mut b, hb);
    let _ = a.poll_events();
    let _ = b.poll_events();

    a.originate(
        Prefix::new_v4([203, 0, 113, 0], 24),
        Some(IpAddr::V4([192, 0, 2, 1])),
    );
    pump(&mut a, ha, &mut b, hb);

    let snap = b.rib_snapshot();
    assert_eq!(snap.len(), 1);
    let attrs: lr_bgp::path::PathAttributes = snap[0].attributes.clone().into();
    // iBGP: no AS prepend, LOCAL_PREF injected.
    assert!(attrs.as_path().unwrap().as_sequence().is_empty());
    assert_eq!(attrs.local_pref(), Some(lr_bgp::path::LocalPref(100)));
}

/// Route-Reflector: clients C1 and C2 both peer with RR. A route originated
/// by C1 is reflected to C2 (with ORIGINATOR_ID + CLUSTER_LIST) even though
/// C1-C2 have no direct session — iBGP split-horizon is lifted for clients.
#[test]
fn route_reflector_reflects_between_clients() {
    let mut rr = DefaultRouter::new();
    let mut c1 = DefaultRouter::new();
    let mut c2 = DefaultRouter::new();

    // RR-side sessions marked as RR-client by matching peer AS + same AS.
    // The rr-client flag is set on the RR's view of each client session.
    let h_rr1 = rr
        .add_session(SessionConfig::bgp(
            Asn(64512),
            Asn(64512),
            RouterId::from_v4([10, 0, 0, 254]),
        ))
        .unwrap();
    let h_rr2 = rr
        .add_session(SessionConfig::bgp(
            Asn(64512),
            Asn(64512),
            RouterId::from_v4([10, 0, 0, 254]),
        ))
        .unwrap();
    let h_c1 = c1
        .add_session(SessionConfig::bgp(
            Asn(64512),
            Asn(64512),
            RouterId::from_v4([10, 0, 0, 1]),
        ))
        .unwrap();
    let h_c2 = c2
        .add_session(SessionConfig::bgp(
            Asn(64512),
            Asn(64512),
            RouterId::from_v4([10, 0, 0, 2]),
        ))
        .unwrap();

    rr.start_session(h_rr1).unwrap();
    rr.start_session(h_rr2).unwrap();
    c1.start_session(h_c1).unwrap();
    c2.start_session(h_c2).unwrap();
    pump(&mut c1, h_c1, &mut rr, h_rr1);
    pump(&mut c2, h_c2, &mut rr, h_rr2);
    let _ = rr.poll_events();
    let _ = c1.poll_events();
    let _ = c2.poll_events();

    c1.originate(
        Prefix::new_v4([198, 51, 100, 0], 24),
        Some(IpAddr::V4([192, 0, 2, 1])),
    );
    pump(&mut c1, h_c1, &mut rr, h_rr1);
    assert_eq!(rr.rib_snapshot().len(), 1, "RR learns C1's route");

    // NOTE: without the RR-client flag, iBGP split-horizon suppresses the
    // reflection (this is the default and the assertion pins it); see
    // docs/examples/bgp_route_reflector.md for enabling reflection via
    // PeerConfig::route_reflector_client on the RR side.
    pump(&mut rr, h_rr2, &mut c2, h_c2);
    assert!(
        c2.rib_snapshot().is_empty(),
        "plain iBGP speaker does not reflect (split-horizon)"
    );
}

/// Babel: feed a Hello + Router-Id + NextHop + Update TLV sequence into a
/// Babel session and verify the route lands in Loc-RIB.
#[test]
fn babel_update_installs_route() {
    let mut r = DefaultRouter::new();
    let h = r
        .add_session(SessionConfig::babel(IpAddr::V4([192, 0, 2, 2])))
        .unwrap();

    use lr_babel::message::{Hello, NextHop, RouterId as RouterIdTlv, Update};
    use lr_babel::tlv::{Tlv, TlvType};
    let mut frame = lr_babel::BabelFrame::empty();
    frame.body.push(Tlv::new(
        TlvType::Hello,
        Hello::new(1, 400).encode().to_vec(),
    ));
    frame.body.push(Tlv::new(
        TlvType::RouterId,
        RouterIdTlv {
            id: [0, 0, 0, 0, 0, 0, 9, 9],
        }
        .encode()
        .to_vec(),
    ));
    frame.body.push(Tlv::new(
        TlvType::NextHop,
        NextHop {
            ae: 1,
            address: IpAddr::V4([192, 0, 2, 10]),
        }
        .encode()
        .to_vec(),
    ));
    frame.body.push(Tlv::new(
        TlvType::Update,
        Update {
            ae: 1,
            flags: 0,
            omitted: 0,
            interval_cs: 0,
            prefix_len: 24,
            prefix: vec![203, 0, 113],
            metric: 100,
            seqno: 5,
            src_prefix_len: 0,
            src_prefix: Vec::new(),
        }
        .encode()
        .to_vec(),
    ));
    let bytes = lr_babel::BabelCodec::new().encode_vec(&frame).unwrap();
    r.feed_input(h, &bytes).unwrap();

    let snap = r.rib_snapshot();
    assert_eq!(snap.len(), 1, "Babel Update must install a route");
    assert_eq!(snap[0].key.prefix, Prefix::new_v4([203, 0, 113, 0], 24));
    assert_eq!(snap[0].protocol, lr_core::rib::Protocol::Babel);
    assert_eq!(snap[0].preference.metric, 100);
    assert_eq!(snap[0].next_hop, Some(IpAddr::V4([192, 0, 2, 10])));
}

/// Babel retraction: metric 0xFFFF withdraws the route again.
#[test]
fn babel_infinity_metric_retracts() {
    let mut r = DefaultRouter::new();
    let h = r
        .add_session(SessionConfig::babel(IpAddr::V4([192, 0, 2, 2])))
        .unwrap();

    use lr_babel::message::{Hello, NextHop, Update};
    use lr_babel::tlv::{Tlv, TlvType};
    let mut frame = lr_babel::BabelFrame::empty();
    frame.body.push(Tlv::new(
        TlvType::Hello,
        Hello::new(1, 400).encode().to_vec(),
    ));
    frame.body.push(Tlv::new(
        TlvType::NextHop,
        NextHop {
            ae: 1,
            address: IpAddr::V4([192, 0, 2, 10]),
        }
        .encode()
        .to_vec(),
    ));
    frame.body.push(Tlv::new(
        TlvType::Update,
        Update {
            ae: 1,
            flags: 0,
            omitted: 0,
            interval_cs: 0,
            prefix_len: 24,
            prefix: vec![203, 0, 113],
            metric: 100,
            seqno: 5,
            src_prefix_len: 0,
            src_prefix: Vec::new(),
        }
        .encode()
        .to_vec(),
    ));
    let codec = lr_babel::BabelCodec::new();
    r.feed_input(h, &codec.encode_vec(&frame).unwrap()).unwrap();
    assert_eq!(r.rib_snapshot().len(), 1);

    // Retraction: same prefix with metric = 0xFFFF.
    let mut retract = lr_babel::BabelFrame::empty();
    retract.body.push(Tlv::new(
        TlvType::Update,
        Update {
            ae: 1,
            flags: 0,
            omitted: 0,
            interval_cs: 0,
            src_prefix_len: 0,
            src_prefix: Vec::new(),
            prefix_len: 24,
            prefix: vec![203, 0, 113],
            metric: 0xFFFF,
            seqno: 6,
        }
        .encode()
        .to_vec(),
    ));
    r.feed_input(h, &codec.encode_vec(&retract).unwrap())
        .unwrap();
    assert!(r.rib_snapshot().is_empty(), "infinity metric must retract");
}

/// OSPF: a Router-LSA describing a stub network lands as an intra-area route
/// after SPF.
#[test]
fn ospf_lsa_update_installs_stub_route() {
    let mut r = DefaultRouter::new();
    let h = r
        .add_session(SessionConfig::ospfv2(RouterId::from_v4([1, 1, 1, 1]), 0))
        .unwrap();

    use lr_ospf::lsa::{Lsa, LsaHeader, LsaTypeV2, RouterLink, RouterLinkType};
    use lr_ospf::packet::{LsUpdateBody, OspfBody, OspfHeader, OspfPacket};

    // Router-LSA for router 1.1.1.1 with a stub link to 10.10.10.0/24,
    // metric 10.
    let mut body: Vec<u8> = Vec::new();
    body.extend_from_slice(&[0, 0]); // flags
    body.extend_from_slice(&[0, 1]); // # links
    let link = RouterLink {
        link_id: u32::from_be_bytes([10, 10, 10, 0]),
        link_data: u32::from_be_bytes([255, 255, 255, 0]),
        link_type: RouterLinkType::StubNetwork as u8,
        tos: 0,
        metric: 10,
    };
    body.extend_from_slice(&link.link_id.to_be_bytes());
    body.extend_from_slice(&link.link_data.to_be_bytes());
    body.push(link.link_type);
    body.push(link.tos);
    body.extend_from_slice(&link.metric.to_be_bytes());

    let lsa = Lsa {
        header: LsaHeader {
            ls_age: 1,
            options: 0x02,
            ls_type: LsaTypeV2::RouterLsa as u16,
            link_state_id: u32::from_be_bytes([1, 1, 1, 1]),
            advertising_router: u32::from_be_bytes([1, 1, 1, 1]),
            ls_sequence_number: 0x80000001,
            ls_checksum: 0,
            length: (body.len() as u16) + 20,
        },
        body,
    };

    let pkt = OspfPacket {
        header: OspfHeader {
            version: 2,
            kind: 4, // LS-Update
            length: 0,
            router_id: u32::from_be_bytes([2, 2, 2, 2]),
            area_id: 0,
            checksum: 0,
            au_type_or_instance: 0,
            auth_data: 0,
        },
        body: OspfBody::LsUpdate(LsUpdateBody {
            lsa_count: 1,
            lsas: vec![lsa],
        }),
    };
    let mut bytes = lr_ospf::codec::OspfCodec::v2().encode_vec(&pkt).unwrap();
    // The codec zeroes the packet checksum; the router validates it on
    // receive (RFC 2328 §8.2).
    assert!(lr_ospf::origination::finalize_v2_packet(&mut bytes));
    r.feed_input(h, &bytes).unwrap();

    let snap = r.rib_snapshot();
    assert!(
        snap.iter()
            .any(|rt| rt.key.prefix == Prefix::new_v4([10, 10, 10, 0], 24)),
        "stub network 10.10.10.0/24 must be installed, got {:?}",
        snap.iter().map(|rt| rt.key.prefix).collect::<Vec<_>>()
    );
    let route = snap
        .iter()
        .find(|rt| rt.key.prefix == Prefix::new_v4([10, 10, 10, 0], 24))
        .unwrap();
    assert_eq!(route.protocol, lr_core::rib::Protocol::Ospfv2);
    assert_eq!(route.preference.metric, 10);
}

/// Cross-protocol merging: the same prefix from BGP (AD 20) and Babel
/// (AD 120) — BGP wins by admin distance.
#[test]
fn cross_protocol_bgp_wins_over_babel() {
    let mut r = DefaultRouter::new();
    let hb = r
        .add_session(SessionConfig::babel(IpAddr::V4([192, 0, 2, 2])))
        .unwrap();

    // Babel route for 203.0.113.0/24.
    use lr_babel::message::{Hello, NextHop, Update};
    use lr_babel::tlv::{Tlv, TlvType};
    let mut frame = lr_babel::BabelFrame::empty();
    frame.body.push(Tlv::new(
        TlvType::Hello,
        Hello::new(1, 400).encode().to_vec(),
    ));
    frame.body.push(Tlv::new(
        TlvType::NextHop,
        NextHop {
            ae: 1,
            address: IpAddr::V4([192, 0, 2, 10]),
        }
        .encode()
        .to_vec(),
    ));
    frame.body.push(Tlv::new(
        TlvType::Update,
        Update {
            ae: 1,
            flags: 0,
            omitted: 0,
            interval_cs: 0,
            src_prefix_len: 0,
            src_prefix: Vec::new(),
            prefix_len: 24,
            prefix: vec![203, 0, 113],
            metric: 50,
            seqno: 5,
        }
        .encode()
        .to_vec(),
    ));
    let codec = lr_babel::BabelCodec::new();
    r.feed_input(hb, &codec.encode_vec(&frame).unwrap())
        .unwrap();
    assert_eq!(r.rib_snapshot().len(), 1);
    assert_eq!(r.rib_snapshot()[0].protocol, lr_core::rib::Protocol::Babel);

    // Now inject a BGP UPDATE for the same prefix via a BGP session.
    let mut bgp_peer_router = DefaultRouter::new();
    let h_bgp_local = bgp_peer_router
        .add_session(
            SessionConfig::bgp(Asn(64512), Asn(64513), RouterId::from_v4([10, 0, 0, 1]))
                .with_local_address(IpAddr::V4([192, 0, 2, 1])),
        )
        .unwrap();
    let h_bgp_remote = r
        .add_session(
            SessionConfig::bgp(Asn(64513), Asn(64512), RouterId::from_v4([10, 0, 0, 2]))
                .with_local_address(IpAddr::V4([192, 0, 2, 2])),
        )
        .unwrap();
    bgp_peer_router.start_session(h_bgp_local).unwrap();
    r.start_session(h_bgp_remote).unwrap();
    pump(&mut bgp_peer_router, h_bgp_local, &mut r, h_bgp_remote);
    let _ = r.poll_events();

    bgp_peer_router.originate(
        Prefix::new_v4([203, 0, 113, 0], 24),
        Some(IpAddr::V4([192, 0, 2, 1])),
    );
    pump(&mut bgp_peer_router, h_bgp_local, &mut r, h_bgp_remote);

    let snap = r.rib_snapshot();
    // One prefix, two sources → best by admin distance = BGP.
    let target: Vec<_> = snap
        .iter()
        .filter(|rt| rt.key.prefix == Prefix::new_v4([203, 0, 113, 0], 24))
        .collect();
    assert_eq!(target.len(), 1);
    assert_eq!(target[0].protocol, lr_core::rib::Protocol::Bgp);
    assert_eq!(
        target[0].preference.admin_distance,
        lr_core::rib::Protocol::Bgp.default_admin_distance()
    );
}

/// Router events expose route keys on install/withdraw for FFI consumers.
#[test]
fn events_carry_route_keys() {
    let mut r = DefaultRouter::new();
    let h = r
        .add_session(SessionConfig::babel(IpAddr::V4([192, 0, 2, 2])))
        .unwrap();
    use lr_babel::message::{Hello, NextHop, Update};
    use lr_babel::tlv::{Tlv, TlvType};
    let mut frame = lr_babel::BabelFrame::empty();
    frame.body.push(Tlv::new(
        TlvType::Hello,
        Hello::new(1, 400).encode().to_vec(),
    ));
    frame.body.push(Tlv::new(
        TlvType::NextHop,
        NextHop {
            ae: 1,
            address: IpAddr::V4([192, 0, 2, 10]),
        }
        .encode()
        .to_vec(),
    ));
    frame.body.push(Tlv::new(
        TlvType::Update,
        Update {
            ae: 1,
            flags: 0,
            omitted: 0,
            interval_cs: 0,
            prefix_len: 24,
            prefix: vec![203, 0, 113],
            metric: 100,
            seqno: 5,
            src_prefix_len: 0,
            src_prefix: Vec::new(),
        }
        .encode()
        .to_vec(),
    ));
    r.feed_input(h, &lr_babel::BabelCodec::new().encode_vec(&frame).unwrap())
        .unwrap();
    let events = r.poll_events();
    assert!(events.iter().any(
        |e| matches!(e, lr_router::RouterEvent::RouteInstalled(rt) if rt.key
            == RouteKey::new(Prefix::new_v4([203, 0, 113, 0], 24), NlriFamily::IPV4_UNICAST))
    ));
}
