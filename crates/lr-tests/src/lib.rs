//! Cross-crate integration tests for librouting.
//!
//! These tests exercise the full stack: codec → FSM → router instance →
//! Loc-RIB.

#[cfg(test)]
mod tests {
    use lr_bgp::{BgpCodec, BgpEvent, BgpMessage, BgpPeer, PeerConfig};
    use lr_core::addr::{Asn, RouterId};
    use lr_core::time::Instant;
    use lr_router::{RouterInstance, SessionConfig};

    /// End-to-end: spin up two BgpPeers, drive them through OPEN + KEEPALIVE
    /// exchange, both reach Established.
    #[test]
    fn two_sided_bgp_establishment() {
        let cfg1 = PeerConfig::new(Asn(64512), Asn(64513), RouterId::from_v4([10, 0, 0, 1]));
        let cfg2 = PeerConfig::new(Asn(64513), Asn(64512), RouterId::from_v4([10, 0, 0, 2]));
        let mut a = BgpPeer::new(cfg1);
        let mut b = BgpPeer::new(cfg2);
        a.step(BgpEvent::ManualStart);
        a.step(BgpEvent::TransportOpen);
        b.step(BgpEvent::ManualStart);
        b.step(BgpEvent::TransportOpen);
        let a_open = a.drain_outgoing();
        let b_open = b.drain_outgoing();
        a.feed_bytes(&b_open).unwrap();
        b.feed_bytes(&a_open).unwrap();
        let a_ka = a.drain_outgoing();
        let b_ka = b.drain_outgoing();
        a.feed_bytes(&b_ka).unwrap();
        b.feed_bytes(&a_ka).unwrap();
        assert!(a.is_established());
        assert!(b.is_established());
    }

    /// End-to-end: DefaultRouter orchestrates two BGP sessions (one for each
    /// side) and ticks the clock.
    #[test]
    fn router_orchestrates_sessions() {
        let mut r = lr_router::DefaultRouter::new();
        let h1 = r
            .add_session(SessionConfig::bgp(
                Asn(64512),
                Asn(64513),
                RouterId::from_v4([10, 0, 0, 1]),
            ))
            .unwrap();
        let h2 = r
            .add_session(SessionConfig::bgp(
                Asn(64513),
                Asn(64512),
                RouterId::from_v4([10, 0, 0, 2]),
            ))
            .unwrap();
        r.tick(Instant(0));
        assert_eq!(h1.0, 1);
        assert_eq!(h2.0, 2);
        let _events = r.poll_events();
    }

    /// Sanity: codec roundtrip through lr-bgp + lr-core.
    #[test]
    fn codec_keepalive_roundtrip() {
        let codec = BgpCodec::new();
        let bytes = codec
            .encode_vec(&BgpMessage::Keepalive(
                lr_bgp::message::keepalive::Keepalive,
            ))
            .unwrap();
        assert_eq!(bytes.len(), 19);
        let mut dec = BgpCodec::new();
        let m = dec.decode_slice(&bytes).unwrap().unwrap();
        assert!(matches!(m, BgpMessage::Keepalive(_)));
    }

    /// Sanity: an OSPF Hello roundtrips.
    #[test]
    fn ospf_hello_roundtrip() {
        use lr_ospf::codec::OspfCodec;
        use lr_ospf::packet::{HelloBody, OspfBody, OspfHeader, OspfPacket};
        let codec = OspfCodec::v2();
        let pkt = OspfPacket {
            header: OspfHeader {
                version: 2,
                kind: 1,
                length: 0,
                router_id: 0x01020304,
                area_id: 0,
                checksum: 0,
                au_type_or_instance: 0,
                auth_data: 0,
            },
            body: OspfBody::Hello(HelloBody {
                network_mask: 0xffffff00,
                hello_interval: 10,
                options: 0x02,
                priority: 1,
                dead_interval: 40,
                dr: 0,
                bdr: 0,
                neighbors: vec![0x05060708],
            }),
        };
        let bytes = codec.encode_vec(&pkt).unwrap();
        // The codec zeroes the checksum; the decoder now validates it on
        // receive (RFC 2328 §8.2), so finalize before round-tripping.
        let mut finalized = bytes.clone();
        assert!(lr_ospf::origination::finalize_v2_packet(&mut finalized));
        let mut dec = OspfCodec::v2();
        let p2 = dec.decode_slice(&finalized).unwrap().unwrap();
        assert_eq!(p2.header.router_id, pkt.header.router_id);
        // A packet with a bad checksum must be rejected on decode.
        let mut bad = finalized.clone();
        bad[10] ^= 0xff;
        assert!(dec.decode_slice(&bad).is_err());
    }

    /// Sanity: Babel frame roundtrips.
    #[test]
    fn babel_frame_roundtrip() {
        use lr_babel::message::Hello;
        use lr_babel::tlv::{Tlv, TlvType};
        use lr_babel::{BabelCodec, BabelFrame};
        let mut frame = BabelFrame::empty();
        frame.body.push(Tlv::new(
            TlvType::Hello,
            Hello::new(1, 200)
            .encode()
            .to_vec(),
        ));
        let codec = BabelCodec::new();
        let bytes = codec.encode_vec(&frame).unwrap();
        let mut dec = BabelCodec::new();
        let f2 = dec.decode_slice(&bytes).unwrap().unwrap();
        assert_eq!(f2.body.len(), 1);
    }
}
