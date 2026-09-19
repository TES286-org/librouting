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
fn reconnect_discards_partial_frames_from_previous_transport() {
    for partial_len in [1, 10, 18, 25] {
        let mut a = BgpPeer::new(config(64512, 64513, 1));
        let mut b = BgpPeer::new(config(64513, 64512, 2));
        establish(&mut a, &mut b);
        assert!(b.advertise(&route()));
        let update = b.drain_outgoing();
        assert!(a.feed_bytes(&update[..partial_len]).unwrap().is_empty());
        let open_count = a.message_stats().open_received;
        a.step(BgpEvent::TransportClose);
        a.reset();
        b.reset();
        establish(&mut a, &mut b);
        assert_eq!(a.message_stats().open_received, open_count + 1);
        assert!(b.advertise(&route()));
        let actions = a.feed_bytes(&b.drain_outgoing()).unwrap();
        assert_eq!(
            actions
                .iter()
                .filter(|a| matches!(a, lr_bgp::BgpAction::InstallRoute(_)))
                .count(),
            1,
            "the new transport must decode its own UPDATE after a {partial_len}-byte fragment"
        );
    }
}
