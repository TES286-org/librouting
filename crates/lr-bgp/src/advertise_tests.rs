
use super::*;
use crate::fsm::{BgpEvent, BgpPeer};
use crate::path::AsPath;
use crate::peer::PeerConfig;
use crate::role::ConfederationConfig;
use lr_core::addr::{Asn, IpAddr, RouterId};
use lr_core::codec::Decoder;
use lr_core::rib::{Preference, Protocol, RouteKey, RouteOrigin};

fn established_peer(cfg: PeerConfig) -> BgpPeer {
    // Full OPEN/KEEPALIVE handshake against a dummy partner so the
    // peer under test actually reaches Established.
    let mut p = BgpPeer::new(cfg.clone());
    let mut dummy = BgpPeer::new(PeerConfig::new(
        cfg.peer_as,
        cfg.local_as,
        RouterId::from_v4([10, 9, 9, 9]),
    ));
    p.step(BgpEvent::ManualStart);
    p.step(BgpEvent::TransportOpen);
    dummy.step(BgpEvent::ManualStart);
    dummy.step(BgpEvent::TransportOpen);
    let p_open = p.drain_outgoing();
    let d_open = dummy.drain_outgoing();
    let _ = p.feed_bytes(&d_open);
    let _ = dummy.feed_bytes(&p_open);
    let p_ka = p.drain_outgoing();
    let d_ka = dummy.drain_outgoing();
    let _ = p.feed_bytes(&d_ka);
    let _ = dummy.feed_bytes(&p_ka);
    assert!(p.is_established());
    p
}

fn bgp_route(as_path: &[u32], next_hop: [u8; 4], prefix: [u8; 4], pl: u8, origin: u32) -> Route {
    let mut attrs = PathAttributes::new();
    attrs.insert(PathAttribute::new(
        PathAttrFlags::new().set_transitive(true),
        AttrType::Origin,
        vec![0],
    ));
    let path = AsPath::from_sequence(as_path.iter().copied().map(Asn));
    attrs.insert(PathAttribute::new(
        PathAttrFlags::new().set_transitive(true),
        AttrType::AsPath,
        path.encode_4(),
    ));
    attrs.insert(PathAttribute::new(
        PathAttrFlags::new().set_transitive(true),
        AttrType::NextHop,
        next_hop.to_vec(),
    ));
    Route {
        key: RouteKey::new(Prefix::new_v4(prefix, pl), NlriFamily::IPV4_UNICAST),
        origin: RouteOrigin {
            proto: origin,
            peer: 7,
        },
        protocol: Protocol::Bgp,
        preference: Preference::new(20, as_path.len() as u32),
        next_hop: Some(IpAddr::V4(next_hop)),
        attributes: attrs.into(),
        age_ms: 0,
        path_id: 0,
        tag: None,
    }
}

/// UPDATE egress books one `update_sent` per PDU: advertisement,
/// withdrawal and the End-of-RIB marker each count once, and the
/// receiver's `update_received` follows when the bytes are fed.
#[test]
fn message_stats_count_update_egress() {
    let cfg = PeerConfig::new(Asn(64512), Asn(64513), RouterId::from_v4([10, 0, 0, 1]));
    let mut peer = established_peer(cfg.clone());
    assert_eq!(peer.message_stats().update_sent, 0);

    let route = bgp_route(&[64500], [192, 0, 2, 1], [203, 0, 113, 0], 24, 0);
    assert!(peer.advertise(&route));
    assert_eq!(peer.message_stats().update_sent, 1);

    peer.withdraw(
        &[Prefix::new_v4([203, 0, 113, 0], 24)],
        NlriFamily::IPV4_UNICAST,
    );
    assert_eq!(peer.message_stats().update_sent, 2, "withdrawal counts");

    peer.send_end_of_rib();
    assert_eq!(peer.message_stats().update_sent, 3, "EoR marker counts");

    // Feed the drained bytes into a live partner: the receiving
    // side counts the same PDUs.
    let mut partner = {
        let mut p = BgpPeer::new(PeerConfig::new(
            cfg.peer_as,
            cfg.local_as,
            RouterId::from_v4([10, 9, 9, 9]),
        ));
        let mut dummy = BgpPeer::new(cfg.clone());
        p.step(BgpEvent::ManualStart);
        p.step(BgpEvent::TransportOpen);
        dummy.step(BgpEvent::ManualStart);
        dummy.step(BgpEvent::TransportOpen);
        let _ = p.feed_bytes(&dummy.drain_outgoing()).unwrap();
        let _ = dummy.feed_bytes(&p.drain_outgoing()).unwrap();
        let _ = p.feed_bytes(&dummy.drain_outgoing()).unwrap();
        let _ = dummy.feed_bytes(&p.drain_outgoing()).unwrap();
        assert!(p.is_established());
        p
    };
    let wire = peer.drain_outgoing();
    let _ = partner.feed_bytes(&wire).unwrap();
    assert_eq!(
        partner.message_stats().update_received,
        3,
        "receiver counts all three UPDATEs"
    );
}

/// eBGP egress: AS prepended, LOCAL_PREF stripped.
#[test]
fn ebgp_advertise_prepends_and_strips_local_pref() {
    let cfg = PeerConfig::new(Asn(64512), Asn(64513), RouterId::from_v4([10, 0, 0, 1]));
    let mut peer = established_peer(cfg);
    let route = bgp_route(&[64500], [192, 0, 2, 1], [203, 0, 113, 0], 24, 0);
    assert!(peer.advertise(&route));
    let bytes = peer.drain_outgoing();
    assert_eq!(bytes[18], 2); // UPDATE

    // Feed the UPDATE into a matching peer and verify the AS path grew.
    let remote = established_peer(PeerConfig::new(
        Asn(64513),
        Asn(64512),
        RouterId::from_v4([10, 0, 0, 2]),
    ));
    // bring remote into Established via KEEPALIVE exchange is complex;
    // decode the UPDATE directly instead.
    let mut dec = crate::codec::BgpCodec::new();
    let mut r = lr_core::buf::ReadBuf::new(&bytes);
    if let Ok(Some(BgpMessage::Update(u))) = dec.decode(&mut r) {
        let path = u.attributes.as_path_wire(true).unwrap();
        let ases = path.as_sequence();
        assert_eq!(ases, vec![Asn(64512), Asn(64500)]);
        assert!(u.attributes.local_pref().is_none());
        assert_eq!(u.nlri.len(), 1);
    } else {
        panic!("UPDATE did not decode");
    }
    let _ = remote;
}

/// iBGP egress: no prepend, LOCAL_PREF injected with default 100.
#[test]
fn ibgp_advertise_injects_local_pref() {
    let cfg = PeerConfig::new(Asn(64512), Asn(64512), RouterId::from_v4([10, 0, 0, 1]));
    let mut peer = established_peer(cfg);
    let route = bgp_route(&[], [192, 0, 2, 1], [203, 0, 113, 0], 24, 0);
    assert!(peer.advertise(&route));
    let bytes = peer.drain_outgoing();
    let mut dec = crate::codec::BgpCodec::new();
    let mut r = lr_core::buf::ReadBuf::new(&bytes);
    if let Ok(Some(BgpMessage::Update(u))) = dec.decode(&mut r) {
        let path = u.attributes.as_path_wire(true).unwrap();
        assert!(path.as_sequence().is_empty());
        assert_eq!(u.attributes.local_pref(), Some(LocalPref(100)));
    } else {
        panic!("UPDATE did not decode");
    }
}

/// iBGP split-horizon: an iBGP-learned route is not re-advertised to
/// another non-client iBGP peer.
#[test]
fn ibgp_split_horizon() {
    let cfg = PeerConfig::new(Asn(64512), Asn(64512), RouterId::from_v4([10, 0, 0, 1]));
    let mut peer = established_peer(cfg);
    let route = bgp_route(&[64500], [192, 0, 2, 1], [203, 0, 113, 0], 24, 1);
    assert!(!peer.advertise(&route)); // origin.proto == 1 → iBGP-learned
    assert!(peer.drain_outgoing().is_empty());
}

/// iBGP egress of a locally originated route with no next-hop must
/// synthesize NEXT_HOP from the local address: an UPDATE without
/// the attribute is discarded by the peer (RFC 4271 §6.3, §5.1.3).
#[test]
fn ibgp_locally_originated_route_gets_next_hop() {
    let mut cfg = PeerConfig::new(Asn(64512), Asn(64512), RouterId::from_v4([10, 0, 0, 1]));
    cfg.local_address = Some(lr_core::addr::IpAddr::V4([192, 0, 2, 1]));
    let mut peer = established_peer(cfg);
    // proto 2 = locally originated; no NEXT_HOP attribute either.
    let mut attrs = PathAttributes::new();
    attrs.insert(PathAttribute::new(
        PathAttrFlags::new().set_transitive(true),
        AttrType::Origin,
        vec![0],
    ));
    attrs.insert(PathAttribute::new(
        PathAttrFlags::new().set_transitive(true),
        AttrType::AsPath,
        AsPath::from_sequence([]).encode_4(),
    ));
    let route = Route {
        key: RouteKey::new(
            Prefix::new_v4([203, 0, 113, 0], 24),
            NlriFamily::IPV4_UNICAST,
        ),
        origin: RouteOrigin { proto: 2, peer: 0 },
        protocol: Protocol::Bgp,
        preference: Preference::new(20, 0),
        next_hop: None,
        attributes: attrs.into(),
        age_ms: 0,
        path_id: 0,
        tag: None,
    };
    assert!(peer.advertise(&route));
    let bytes = peer.drain_outgoing();
    let mut dec = crate::codec::BgpCodec::new();
    let mut r = lr_core::buf::ReadBuf::new(&bytes);
    match dec.decode(&mut r) {
        Ok(Some(BgpMessage::Update(u))) => {
            assert_eq!(
                u.attributes.next_hop().map(|n| n.to_ip()),
                Some(lr_core::addr::IpAddr::V4([192, 0, 2, 1])),
                "NEXT_HOP must be synthesized from the local address"
            );
        }
        _ => panic!("UPDATE did not decode"),
    }
}

/// RR reflection: advertising an iBGP-learned route to an RR client
/// succeeds and carries ORIGINATOR_ID + CLUSTER_LIST.
#[test]
fn rr_reflection_to_client() {
    let mut cfg = PeerConfig::new(Asn(64512), Asn(64512), RouterId::from_v4([10, 0, 0, 1]));
    cfg.route_reflector_client = true;
    let mut peer = established_peer(cfg);
    let route = bgp_route(&[64500], [192, 0, 2, 1], [203, 0, 113, 0], 24, 1);
    assert!(peer.advertise(&route));
    let bytes = peer.drain_outgoing();
    let mut dec = crate::codec::BgpCodec::new();
    let mut r = lr_core::buf::ReadBuf::new(&bytes);
    if let Ok(Some(BgpMessage::Update(u))) = dec.decode(&mut r) {
        assert!(u.attributes.get(AttrType::OriginatorId).is_some());
        assert!(u.attributes.get(AttrType::ClusterList).is_some());
    } else {
        panic!("UPDATE did not decode");
    }
}

/// Withdraw encoding: withdraw-only UPDATE roundtrips.
#[test]
fn withdraw_encodes() {
    let cfg = PeerConfig::new(Asn(64512), Asn(64513), RouterId::from_v4([10, 0, 0, 1]));
    let mut peer = established_peer(cfg);
    peer.withdraw(
        &[Prefix::new_v4([203, 0, 113, 0], 24)],
        NlriFamily::IPV4_UNICAST,
    );
    let bytes = peer.drain_outgoing();
    let mut dec = crate::codec::BgpCodec::new();
    let mut r = lr_core::buf::ReadBuf::new(&bytes);
    if let Ok(Some(BgpMessage::Update(u))) = dec.decode(&mut r) {
        assert_eq!(u.withdrawn.len(), 1);
        assert!(u.nlri.is_empty());
    } else {
        panic!("UPDATE did not decode");
    }
}

/// Attribute flag conformance: strict implementations (BIRD, FRR)
/// validate the optional/transitive bits of well-known attributes.
/// LOCAL_PREF is well-known discretionary → 0x40; ORIGINATOR_ID and
/// CLUSTER_LIST are optional non-transitive → 0x80.
#[test]
fn attribute_flags_match_rfc() {
    let mut cfg = PeerConfig::new(Asn(64512), Asn(64512), RouterId::from_v4([10, 0, 0, 1]));
    cfg.route_reflector_client = true;
    let mut peer = established_peer(cfg);
    let route = bgp_route(&[64500], [192, 0, 2, 1], [203, 0, 113, 0], 24, 0);
    assert!(peer.advertise(&route));
    let bytes = peer.drain_outgoing();
    let mut dec = crate::codec::BgpCodec::new();
    let mut r = lr_core::buf::ReadBuf::new(&bytes);
    let msg = dec.decode(&mut r).unwrap().unwrap();
    let BgpMessage::Update(u) = msg else {
        panic!("expected UPDATE");
    };
    let lp = u.attributes.get(AttrType::LocalPref).expect("LOCAL_PREF");
    assert_eq!(lp.flags.0 & 0xc0, 0x40, "LOCAL_PREF must be well-known");
    let oi = u
        .attributes
        .get(AttrType::OriginatorId)
        .expect("ORIGINATOR_ID");
    assert_eq!(
        oi.flags.0 & 0xc0,
        0x80,
        "ORIGINATOR_ID optional non-transitive"
    );
    let cl = u
        .attributes
        .get(AttrType::ClusterList)
        .expect("CLUSTER_LIST");
    assert_eq!(
        cl.flags.0 & 0xc0,
        0x80,
        "CLUSTER_LIST optional non-transitive"
    );
}

/// End-of-RIB marker: an empty UPDATE (no withdrawn, no attributes, no
/// NLRI) per RFC 4724 §4.
#[test]
fn end_of_rib_is_empty_update() {
    let cfg = PeerConfig::new(Asn(64512), Asn(64513), RouterId::from_v4([10, 0, 0, 1]));
    let mut peer = established_peer(cfg);
    peer.send_end_of_rib();
    let bytes = peer.drain_outgoing();
    assert_eq!(bytes.len(), 23); // 19-byte header + 4 zero length fields
    assert_eq!(bytes[18], 2); // UPDATE type
    let mut dec = crate::codec::BgpCodec::new();
    let mut r = lr_core::buf::ReadBuf::new(&bytes);
    match dec.decode(&mut r).unwrap().unwrap() {
        BgpMessage::Update(u) => {
            assert!(u.withdrawn.is_empty());
            assert!(u.nlri.is_empty());
            assert_eq!(u.attributes.len(), 0);
        }
        _ => panic!("expected UPDATE"),
    }
}

fn llgr_peer(long_lived: bool) -> BgpPeer {
    let mut cfg = PeerConfig::new(Asn(64512), Asn(64513), RouterId::from_v4([10, 0, 0, 1]));
    cfg.graceful_restart = true;
    cfg.long_lived = long_lived;
    cfg.long_lived_stale_time = 3600;
    cfg.mp_families = vec![NlriFamily::IPV4_UNICAST];
    // The dummy partner must mirror the LLGR setting so negotiation
    // succeeds/fails on both sides.
    let mut p = BgpPeer::new(cfg.clone());
    let mut dummy_cfg = PeerConfig::new(Asn(64513), Asn(64512), RouterId::from_v4([10, 9, 9, 9]));
    dummy_cfg.graceful_restart = true;
    dummy_cfg.long_lived = long_lived;
    dummy_cfg.long_lived_stale_time = 3600;
    dummy_cfg.mp_families = vec![NlriFamily::IPV4_UNICAST];
    let mut dummy = BgpPeer::new(dummy_cfg);
    p.step(BgpEvent::ManualStart);
    p.step(BgpEvent::TransportOpen);
    dummy.step(BgpEvent::ManualStart);
    dummy.step(BgpEvent::TransportOpen);
    let p_open = p.drain_outgoing();
    let d_open = dummy.drain_outgoing();
    let _ = p.feed_bytes(&d_open);
    let _ = dummy.feed_bytes(&p_open);
    let p_ka = p.drain_outgoing();
    let d_ka = dummy.drain_outgoing();
    let _ = p.feed_bytes(&d_ka);
    let _ = dummy.feed_bytes(&p_ka);
    assert!(p.is_established());
    p
}

fn llgr_stale_route() -> Route {
    let mut route = bgp_route(&[64500], [192, 0, 2, 1], [203, 0, 113, 0], 24, 0);
    let mut attrs: PathAttributes = route.attributes.clone().into();
    attrs.insert_community(Community::LLGR_STALE);
    route.attributes = attrs.into();
    route
}

/// RFC 9494 §4.3: an LLGR_STALE route is not advertised to a neighbor
/// that did not advertise the LLGR capability.
#[test]
fn llgr_stale_route_not_advertised_without_llgr_peer() {
    let mut peer = llgr_peer(false);
    assert!(!peer.llgr_negotiated());
    assert!(!peer.advertise(&llgr_stale_route()));
    assert!(peer.drain_outgoing().is_empty());
}

/// RFC 9494 §4.3: to an LLGR-capable neighbor the stale route is
/// advertised and the LLGR_STALE community is preserved.
#[test]
fn llgr_stale_route_advertised_with_community_intact() {
    let mut peer = llgr_peer(true);
    assert!(peer.llgr_negotiated());
    assert!(peer.advertise(&llgr_stale_route()));
    let bytes = peer.drain_outgoing();
    let mut dec = crate::codec::BgpCodec::new();
    let mut r = lr_core::buf::ReadBuf::new(&bytes);
    match dec.decode(&mut r).unwrap().unwrap() {
        BgpMessage::Update(u) => {
            assert!(
                u.attributes.has_community(Community::LLGR_STALE),
                "LLGR_STALE must survive egress"
            );
        }
        _ => panic!("expected UPDATE"),
    }
}

/// Decode the first UPDATE in `bytes` and return its AS_PATH segments.
fn decode_update_as_path(bytes: &[u8]) -> Vec<crate::path::as_path::AsPathSegment> {
    let mut dec = crate::codec::BgpCodec::new().with_asn4(true);
    let mut r = lr_core::buf::ReadBuf::new(bytes);
    loop {
        match dec.decode(&mut r) {
            Ok(Some(BgpMessage::Update(u))) => {
                return u.attributes.as_path_wire(true).unwrap_or_default().segments;
            }
            Ok(Some(_)) => continue,
            Ok(None) => panic!("no UPDATE in drained bytes"),
            Err(e) => panic!("decode error: {e:?}"),
        }
    }
}

/// RFC 5065 §4.1(b): advertising to a peer in another Member-AS of the
/// same confederation prepends the local AS into an
/// AS_CONFED_SEQUENCE. The segment is invisible to the default path
/// length so best-path comparison is unaffected.
#[test]
fn confederation_external_prepends_confed_sequence() {
    let mut cfg = PeerConfig::new(Asn(64512), Asn(64513), RouterId::from_v4([10, 0, 0, 1]));
    cfg.confederation = Some(ConfederationConfig::new(vec![64512, 64513, 64514]));
    let mut peer = established_peer(cfg);
    let route = bgp_route(&[64500], [192, 0, 2, 1], [203, 0, 113, 0], 24, 0);
    assert!(peer.advertise(&route));
    let segs = decode_update_as_path(&peer.drain_outgoing());
    assert_eq!(
        segs[0].kind,
        crate::path::as_path::AsPathType::ConfedSequence
    );
    assert_eq!(segs[0].ases, vec![Asn(64512)]);
    assert_eq!(segs[1].kind, crate::path::as_path::AsPathType::Sequence);
    assert_eq!(segs[1].ases, vec![Asn(64500)]);
}

/// RFC 5065 §4.1(c)(1) + §4: advertising to a true eBGP peer (outside
/// the confederation) strips every AS_CONFED_* segment and prepends the
/// confederation identifier — not the private Member-AS — as a plain
/// AS_SEQUENCE.
#[test]
fn confederation_external_egress_strips_confed_and_uses_confed_id() {
    let mut cfg = PeerConfig::new(Asn(64512), Asn(200), RouterId::from_v4([10, 0, 0, 1]));
    cfg.confederation = Some(ConfederationConfig::with_id(vec![64512, 64513, 64514], 100));
    let mut peer = established_peer(cfg);
    // The route carries an AS_CONFED_SEQUENCE from a confederation-internal hop.
    let mut route = bgp_route(&[64500], [192, 0, 2, 1], [203, 0, 113, 0], 24, 0);
    let mut attrs: PathAttributes = route.attributes.clone().into();
    let mut confed_path = AsPath::new();
    confed_path.prepend_confed(Asn(64513));
    let mut path = AsPath::from_sequence([Asn(64500)]);
    path.segments.splice(0..0, confed_path.segments);
    attrs.remove(AttrType::AsPath);
    attrs.insert(PathAttribute::new(
        PathAttrFlags::new().set_transitive(true),
        AttrType::AsPath,
        path.encode_4(),
    ));
    route.attributes = attrs.into();
    assert!(peer.advertise(&route));
    let segs = decode_update_as_path(&peer.drain_outgoing());
    // No confederation-private segment survives egress.
    assert!(
        !segs.iter().any(|s| matches!(
            s.kind,
            crate::path::as_path::AsPathType::ConfedSequence
                | crate::path::as_path::AsPathType::ConfedSet
        )),
        "AS_CONFED_* must be stripped before the confederation boundary"
    );
    // A single AS_SEQUENCE remains: the confederation identifier (100)
    // prepended in front of the original [64500] — not the private
    // Member-AS 64512.
    assert_eq!(segs.len(), 1);
    assert_eq!(segs[0].kind, crate::path::as_path::AsPathType::Sequence);
    assert_eq!(segs[0].ases, vec![Asn(100), Asn(64500)]);
}

/// A speaker not in a confederation keeps the plain eBGP prepend: no
/// confederation identifier is invented and no segment is stripped.
#[test]
fn non_confederation_speaker_prepends_local_as() {
    let cfg = PeerConfig::new(Asn(64512), Asn(200), RouterId::from_v4([10, 0, 0, 1]));
    let mut peer = established_peer(cfg);
    let route = bgp_route(&[64500], [192, 0, 2, 1], [203, 0, 113, 0], 24, 0);
    assert!(peer.advertise(&route));
    let segs = decode_update_as_path(&peer.drain_outgoing());
    assert_eq!(segs.len(), 1);
    assert_eq!(segs[0].kind, crate::path::as_path::AsPathType::Sequence);
    assert_eq!(segs[0].ases, vec![Asn(64512), Asn(64500)]);
}
