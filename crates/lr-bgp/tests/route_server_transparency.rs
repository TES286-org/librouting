use lr_bgp::path::{AsPath, AttrType, PathAttrFlags, PathAttribute, PathAttributes};
use lr_bgp::{BgpEvent, BgpPeer, PeerConfig};
use lr_core::addr::{Asn, IpAddr, Prefix, RouterId};
use lr_core::nlri::NlriFamily;
use lr_core::rib::{Preference, Protocol, Route, RouteKey, RouteOrigin};

fn config(local: u32, remote: u32, id: u8) -> PeerConfig {
    PeerConfig::new(Asn(local), Asn(remote), RouterId::from_v4([10, 0, 0, id]))
}

fn establish(a: &mut BgpPeer, b: &mut BgpPeer) {
    for peer in [&mut *a, &mut *b] {
        peer.step(BgpEvent::ManualStart);
        peer.step(BgpEvent::TransportOpen);
    }
    let a_open = a.drain_outgoing();
    let b_open = b.drain_outgoing();
    a.feed_bytes(&b_open).unwrap();
    b.feed_bytes(&a_open).unwrap();
    let a_keepalive = a.drain_outgoing();
    let b_keepalive = b.drain_outgoing();
    a.feed_bytes(&b_keepalive).unwrap();
    b.feed_bytes(&a_keepalive).unwrap();
    assert!(a.is_established());
    assert!(b.is_established());
}

fn route() -> Route {
    let mut attrs = PathAttributes::new();
    let flags = PathAttrFlags::new().set_transitive(true);
    attrs.insert(PathAttribute::new(flags, AttrType::Origin, vec![0]));
    attrs.insert(PathAttribute::new(
        flags,
        AttrType::AsPath,
        AsPath::from_sequence([Asn(64500)]).encode_4(),
    ));
    attrs.insert(PathAttribute::new(
        flags,
        AttrType::NextHop,
        vec![192, 0, 2, 1],
    ));
    Route {
        key: RouteKey::new(
            Prefix::new_v4([203, 0, 113, 0], 24),
            NlriFamily::IPV4_UNICAST,
        ),
        origin: RouteOrigin { proto: 0, peer: 7 },
        protocol: Protocol::Bgp,
        preference: Preference::new(20, 1),
        next_hop: Some(IpAddr::V4([192, 0, 2, 1])),
        attributes: attrs.into(),
        age_ms: 0,
        path_id: 0,
        tag: None,
    }
}

#[test]
fn route_server_preserves_client_path_and_next_hop() {
    use lr_bgp::role::RouteServerConfig;
    use lr_bgp::{BgpCodec, BgpMessage};

    for transparent in [false, true] {
        let mut cfg = config(64512, 64513, 1);
        cfg.local_address = Some(IpAddr::V4([192, 0, 2, 254]));
        if transparent {
            cfg.route_server = RouteServerConfig::new_client();
        }
        let mut a = BgpPeer::new(cfg);
        let mut b = BgpPeer::new(config(64513, 64512, 2));
        establish(&mut a, &mut b);
        let original = route();
        assert!(a.advertise(&original));
        let mut codec = BgpCodec::new().with_asn4(true);
        let BgpMessage::Update(update) = codec.decode_slice(&a.drain_outgoing()).unwrap().unwrap()
        else {
            panic!("expected an UPDATE");
        };
        let expected_path = if transparent {
            vec![Asn(64500)]
        } else {
            vec![Asn(64512), Asn(64500)]
        };
        assert_eq!(
            update.attributes.as_path().unwrap().as_sequence(),
            expected_path
        );
        let expected_nh = if transparent {
            [192, 0, 2, 1]
        } else {
            [192, 0, 2, 254]
        };
        assert_eq!(
            update.attributes.next_hop().unwrap().to_ip(),
            IpAddr::V4(expected_nh)
        );
        assert_eq!(original, route(), "egress must preserve the stored route");
    }
}
