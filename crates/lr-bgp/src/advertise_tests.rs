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
/// succeeds and carries ORIGINATOR_ID + CLUSTER_LIST. Per RFC 4456 §3,
/// the reflection attributes are stamped only when *both* flags are
/// set — the per-peer `route_reflector_client` flag and the
/// per-speaker `route_reflector.enabled` flag — so the cluster-id
/// is defined before ORIGINATOR_ID is inserted.
#[test]
fn rr_reflection_to_client() {
    let mut cfg = PeerConfig::new(Asn(64512), Asn(64512), RouterId::from_v4([10, 0, 0, 1]));
    cfg.route_reflector_client = true;
    cfg.route_reflector.enabled = true;
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

/// RR reflection is gated on `route_reflector.enabled` as well as the
/// per-peer `route_reflector_client` flag. RFC 4456 §3 makes reflection
/// a per-speaker behavior — a peer marked as an RR-client of a speaker
/// that is itself not a reflector must NOT receive ORIGINATOR_ID /
/// CLUSTER_LIST, because no cluster id is defined for the local
/// speaker. This test pins the gating: with `route_reflector_client =
/// true` and `route_reflector.enabled = false` (the default), the
/// reflected UPDATE carries neither attribute.
#[test]
fn rr_reflection_suppressed_when_route_reflector_disabled() {
    let mut cfg = PeerConfig::new(Asn(64512), Asn(64512), RouterId::from_v4([10, 0, 0, 1]));
    cfg.route_reflector_client = true;
    // `cfg.route_reflector.enabled` stays at its `Default::default()`
    // value of `false` — the speaker is not configured as a reflector.
    let mut peer = established_peer(cfg);
    let route = bgp_route(&[64500], [192, 0, 2, 1], [203, 0, 113, 0], 24, 1);
    assert!(peer.advertise(&route));
    let bytes = peer.drain_outgoing();
    let mut dec = crate::codec::BgpCodec::new();
    let mut r = lr_core::buf::ReadBuf::new(&bytes);
    match dec.decode(&mut r) {
        Ok(Some(BgpMessage::Update(u))) => {
            assert!(
                u.attributes.get(AttrType::OriginatorId).is_none(),
                "ORIGINATOR_ID must not be stamped when route_reflector.enabled = false"
            );
            assert!(
                u.attributes.get(AttrType::ClusterList).is_none(),
                "CLUSTER_LIST must not be stamped when route_reflector.enabled = false"
            );
        }
        _ => panic!("UPDATE did not decode"),
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
    cfg.route_reflector.enabled = true;
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

// ---------------------------------------------------------------------------
// BGP-LS egress (issue #60 daemon wiring) — RFC 7752 §3.
// ---------------------------------------------------------------------------

#[cfg(feature = "bgp_ls")]
fn bgpls_established_peer() -> BgpPeer {
    use lr_core::nlri::NlriFamily;
    let mut cfg = PeerConfig::new(Asn(64512), Asn(64513), RouterId::from_v4([10, 0, 0, 1]));
    cfg.mp_families = vec![NlriFamily::BGP_LS];
    let mut p = BgpPeer::new(cfg.clone());
    // The dummy partner must mirror the BGP-LS family so negotiation
    // of the MP-BGP capability succeeds on both sides.
    let mut dummy_cfg = PeerConfig::new(Asn(64513), Asn(64512), RouterId::from_v4([10, 9, 9, 9]));
    dummy_cfg.mp_families = vec![NlriFamily::BGP_LS];
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

#[cfg(feature = "bgp_ls")]
fn sample_bgpls_node_nlri() -> crate::path::bgp_ls::BgpLsNlri {
    use crate::path::bgp_ls::{
        BgpLsNlri, BgpLsNlriVariant, NodeDescriptor, NodeDescriptorSubTlv, NodeNlri, ProtocolId,
    };
    let local = NodeDescriptor::new(vec![
        NodeDescriptorSubTlv::As(64512),
        NodeDescriptorSubTlv::BgpLsId(1),
        NodeDescriptorSubTlv::OspfAreaId(0),
        NodeDescriptorSubTlv::IgpRouterId(vec![10, 0, 0, 1]),
    ]);
    BgpLsNlri {
        route_distinguisher: None,
        variant: BgpLsNlriVariant::Node(NodeNlri {
            protocol_id: ProtocolId::Ospfv2,
            identifier: 0,
            local_node: local,
        }),
    }
}

/// `advertise_bgpls` emits an UPDATE with MP_REACH_NLRI carrying the
/// NLRI bytes verbatim. The peer's outbound buffer holds the message
/// ready for delivery.
#[cfg(feature = "bgp_ls")]
#[test]
fn advertise_bgpls_emits_mp_reach_update() {
    let mut peer = bgpls_established_peer();
    let nlri = sample_bgpls_node_nlri();
    assert!(peer.advertise_bgpls(std::slice::from_ref(&nlri)));
    let bytes = peer.drain_outgoing();
    // 19-byte BGP header + 4-byte UPDATE length fields + at least
    // one path-attribute (MP_REACH_NLRI).
    assert!(bytes.len() > 19 + 4, "got bytes: {}", bytes.len());
    // Decode the UPDATE and verify the MP_REACH_NLRI attribute is present.
    let mut dec = crate::codec::BgpCodec::new();
    let mut r = lr_core::buf::ReadBuf::new(&bytes);
    let msg = dec.decode(&mut r).unwrap().unwrap();
    match msg {
        BgpMessage::Update(u) => {
            let mp = u
                .attributes
                .get(AttrType::MpReachNlri)
                .expect("MP_REACH_NLRI present");
            // MP_REACH_NLRI body shape: AFI(2) | SAFI(1) | NH-LEN(1) |
            // reserved(1) | NLRI-stream.
            assert_eq!(mp.value[0..2], [0x40, 0x04], "AFI=16388"); // 16388 = 0x4004
            assert_eq!(mp.value[2], 71, "SAFI=71"); // BGP-LS SAFI
            assert_eq!(mp.value[3], 0, "NH-LEN = 0 for BGP-LS");
            assert_eq!(mp.value[4], 0, "reserved = 0");
            // The NLRI stream starts at offset 5; verify it decodes
            // back into a Node NLRI matching the input.
            let decoded = crate::path::bgp_ls::BgpLsNlri::decode(false, &mp.value[5..]);
            let (got, consumed) = decoded.expect("NLRI decodes");
            assert_eq!(consumed, mp.value[5..].len(), "no trailing bytes");
            assert!(matches!(
                got.variant,
                crate::path::bgp_ls::BgpLsNlriVariant::Node(_)
            ));
        }
        _ => panic!("expected UPDATE"),
    }
}

/// `withdraw_bgpls` emits an UPDATE with MP_UNREACH_NLRI.
#[cfg(feature = "bgp_ls")]
#[test]
fn withdraw_bgpls_emits_mp_unreach_update() {
    let mut peer = bgpls_established_peer();
    let nlri = sample_bgpls_node_nlri();
    assert!(peer.withdraw_bgpls(std::slice::from_ref(&nlri)));
    let bytes = peer.drain_outgoing();
    assert!(bytes.len() > 19 + 4, "got bytes: {}", bytes.len());
    let mut dec = crate::codec::BgpCodec::new();
    let mut r = lr_core::buf::ReadBuf::new(&bytes);
    let msg = dec.decode(&mut r).unwrap().unwrap();
    match msg {
        BgpMessage::Update(u) => {
            let mp = u
                .attributes
                .get(AttrType::MpUnreachNlri)
                .expect("MP_UNREACH_NLRI present");
            // MP_UNREACH_NLRI body shape: AFI(2) | SAFI(1) | NLRI-stream.
            assert_eq!(mp.value[0..2], [0x40, 0x04], "AFI=16388");
            assert_eq!(mp.value[2], 71, "SAFI=71");
            let decoded = crate::path::bgp_ls::BgpLsNlri::decode(false, &mp.value[3..]);
            let (got, consumed) = decoded.expect("NLRI decodes");
            assert_eq!(consumed, mp.value[3..].len());
            assert!(matches!(
                got.variant,
                crate::path::bgp_ls::BgpLsNlriVariant::Node(_)
            ));
        }
        _ => panic!("expected UPDATE"),
    }
}

/// `advertise_bgpls` is a no-op for a peer without BGP-LS in its
/// `mp_families` (defensive: a misconfigured session sends nothing
/// rather than a malformed MP_REACH that the peer would reject).
#[cfg(feature = "bgp_ls")]
#[test]
fn advertise_bgpls_skips_peer_without_ls_family() {
    let mut cfg = PeerConfig::new(Asn(64512), Asn(64513), RouterId::from_v4([10, 0, 0, 1]));
    cfg.mp_families = vec![NlriFamily::IPV4_UNICAST];
    let mut peer = established_peer(cfg);
    let nlri = sample_bgpls_node_nlri();
    assert!(!peer.advertise_bgpls(&[nlri]));
    assert!(peer.drain_outgoing().is_empty());
}

/// `advertise_bgpls` with an empty slice is a no-op (the daemon calls
/// it after every diff that turns out to be all-unchanged).
#[cfg(feature = "bgp_ls")]
#[test]
fn advertise_bgpls_empty_is_noop() {
    let mut peer = bgpls_established_peer();
    assert!(!peer.advertise_bgpls(&[]));
    assert!(peer.drain_outgoing().is_empty());
}

// ---------------------------------------------------------------------------
// BGP-LS Attribute egress (RFC 7752 §3.3 + RFC 9514 §7-§8, issue #60).
// ---------------------------------------------------------------------------

/// `advertise_bgpls_with_attr` emits an UPDATE that carries the BGP-LS
/// Attribute (path attribute type 29) alongside MP_REACH_NLRI. The
/// attribute's TLV stream round-trips through the codec — the bytes
/// the peer sees match what the projection built.
#[cfg(feature = "bgp_ls")]
#[test]
fn advertise_bgpls_with_attr_emits_attribute() {
    use crate::path::bgp_ls_attr::{
        BgpLsAttr, BgpLsAttrTlv, Srv6EndpointBehavior, Srv6SidStructure,
    };

    let mut peer = bgpls_established_peer();
    let nlri = sample_bgpls_node_nlri();

    // RFC 9514 §7.1 mandates the SRv6 Endpoint Behavior TLV inside
    // the BGP-LS Attribute for an SRv6 SID NLRI. The test attaches
    // one to a Node NLRI (the simplest path through the egress
    // code) and verifies the attribute bytes round-trip.
    let attr = BgpLsAttr::new(vec![
        BgpLsAttrTlv::NodeFlagBits(0x07),
        BgpLsAttrTlv::Srv6EndpointBehavior {
            behavior: Srv6EndpointBehavior::End,
            flags: 0,
            algorithm: 0,
        },
        BgpLsAttrTlv::Srv6SidStructure(Srv6SidStructure {
            locator_block_len: 32,
            locator_node_len: 16,
            function_len: 16,
            argument_len: 0,
        }),
    ]);

    assert!(peer.advertise_bgpls_with_attr(std::slice::from_ref(&nlri), &attr));
    let bytes = peer.drain_outgoing();
    assert!(bytes.len() > 19 + 4, "got bytes: {}", bytes.len());

    let mut dec = crate::codec::BgpCodec::new();
    let mut r = lr_core::buf::ReadBuf::new(&bytes);
    let msg = dec.decode(&mut r).unwrap().unwrap();
    match msg {
        BgpMessage::Update(u) => {
            // MP_REACH_NLRI present.
            assert!(
                u.attributes.get(AttrType::MpReachNlri).is_some(),
                "MP_REACH_NLRI present"
            );
            // BGP-LS Attribute (type 29) present.
            let attr_pa = u
                .attributes
                .get(AttrType::BgpLsAttribute)
                .expect("BGP-LS Attribute (type 29) present");
            assert_eq!(attr_pa.attr_type, AttrType::BgpLsAttribute);
            assert!(attr_pa.flags.optional(), "BGP-LS Attribute is optional");
            assert!(
                !attr_pa.flags.transitive(),
                "BGP-LS Attribute is non-transitive (RFC 7752 §3.3)"
            );
            // The attribute value is a TLV stream that round-trips
            // back into the same `BgpLsAttr`.
            let decoded = crate::path::bgp_ls_attr::BgpLsAttr::decode(&attr_pa.value)
                .expect("BGP-LS Attribute value decodes");
            assert_eq!(decoded, attr);
        }
        _ => panic!("expected UPDATE"),
    }
}

/// `advertise_bgpls_with_attr` is a no-op when the BGP-LS family is
/// not negotiated — defensive: a misconfigured session sends nothing.
#[cfg(feature = "bgp_ls")]
#[test]
fn advertise_bgpls_with_attr_skips_peer_without_ls_family() {
    use crate::path::bgp_ls_attr::{BgpLsAttr, BgpLsAttrTlv};

    let mut cfg = PeerConfig::new(Asn(64512), Asn(64513), RouterId::from_v4([10, 0, 0, 1]));
    cfg.mp_families = vec![NlriFamily::IPV4_UNICAST];
    let mut peer = established_peer(cfg);
    let nlri = sample_bgpls_node_nlri();
    let attr = BgpLsAttr::new(vec![BgpLsAttrTlv::NodeFlagBits(0x01)]);
    assert!(!peer.advertise_bgpls_with_attr(&[nlri], &attr));
    assert!(peer.drain_outgoing().is_empty());
}

/// `advertise_bgpls_with_attr` with an empty NLRI set is a no-op.
#[cfg(feature = "bgp_ls")]
#[test]
fn advertise_bgpls_with_attr_empty_nlris_is_noop() {
    use crate::path::bgp_ls_attr::{BgpLsAttr, BgpLsAttrTlv};

    let mut peer = bgpls_established_peer();
    let attr = BgpLsAttr::new(vec![BgpLsAttrTlv::NodeFlagBits(0x01)]);
    assert!(!peer.advertise_bgpls_with_attr(&[], &attr));
    assert!(peer.drain_outgoing().is_empty());
}

/// `advertise_bgpls_with_attr` with an empty attribute is a no-op
/// (the caller signals "no metadata for this NLRI set" by passing an
/// empty `BgpLsAttr`; the egress path then falls back to
/// `advertise_bgpls`).
#[cfg(feature = "bgp_ls")]
#[test]
fn advertise_bgpls_with_attr_empty_attr_is_noop() {
    use crate::path::bgp_ls_attr::BgpLsAttr;

    let mut peer = bgpls_established_peer();
    let nlri = sample_bgpls_node_nlri();
    let attr = BgpLsAttr::default();
    assert!(!peer.advertise_bgpls_with_attr(&[nlri], &attr));
    assert!(peer.drain_outgoing().is_empty());
}
