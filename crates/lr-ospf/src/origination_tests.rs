use super::*;
use crate::codec::OspfCodec;
use crate::packet::{HelloBody, OspfBody, OspfHeader, OspfPacket};

fn hello() -> OspfPacket {
    OspfPacket {
        header: OspfHeader {
            version: 2,
            kind: 1,
            length: 0,
            router_id: 0x0a00_0001,
            area_id: 0,
            checksum: 0,
            au_type_or_instance: 0,
            auth_data: 0,
        },
        body: OspfBody::Hello(HelloBody {
            network_mask: 0xffff_ff00,
            hello_interval: 10,
            options: 0x02,
            priority: 1,
            dead_interval: 40,
            dr: 0,
            bdr: 0,
            neighbors: vec![0x0a00_0002, 0x0a00_0003],
        }),
    }
}

#[test]
fn v2_packet_checksum_roundtrip() {
    let mut wire = OspfCodec::v2().encode_vec(&hello()).unwrap();
    assert_eq!(&wire[12..14], &[0, 0], "codec leaves checksum zeroed");
    assert!(finalize_v2_packet(&mut wire));
    let stored = u16::from_be_bytes([wire[12], wire[13]]);
    assert_ne!(stored, 0);
    assert!(v2_packet_checksum_ok(&wire), "checksum must verify");
    // Corruption anywhere the checksum covers must be detected.
    let mut bad = wire.clone();
    bad[wire.len() - 1] ^= 0x01; // last body byte
    assert!(!v2_packet_checksum_ok(&bad));
    let mut bad2 = wire.clone();
    bad2[4] ^= 0x01; // router-id byte (header, pre-auth)
    assert!(!v2_packet_checksum_ok(&bad2));
    // The authentication field is NOT covered: flipping it keeps the
    // checksum valid.
    let mut auth_only = wire.clone();
    auth_only[20] ^= 0xff; // inside the 64-bit auth field
    assert!(v2_packet_checksum_ok(&auth_only));
}

#[test]
fn v2_stream_finalize_walks_frames() {
    let a = OspfCodec::v2().encode_vec(&hello()).unwrap();
    let mut b = OspfCodec::v2().encode_vec(&hello()).unwrap();
    b[4] ^= 0x02; // different router-id byte so the frames differ
    let mut stream = a.clone();
    stream.extend_from_slice(&b);
    let count = finalize_v2_stream(&mut stream);
    assert_eq!(count, 2);
    let mid = a.len();
    assert!(v2_packet_checksum_ok(&stream[..mid]));
    assert!(v2_packet_checksum_ok(&stream[mid..]));
    // A malformed trailing frame stops the walk without panicking.
    let mut truncated = stream.clone();
    truncated.truncate(truncated.len() - 4);
    assert_eq!(finalize_v2_stream(&mut truncated), 1);
}

#[test]
fn v2_packet_checksum_short_input() {
    let mut short = vec![0u8; 10];
    assert!(!finalize_v2_packet(&mut short));
    assert!(!v2_packet_checksum_ok(&short));
}

#[test]
fn router_lsa_structure_and_checksum() {
    let lsa = originate_router_lsa(
        0x0a00_0001,
        RouterLsaFlags {
            virtual_link: false,
            asbr: true,
            border: false,
        },
        &[
            RouterLsaLink::Stub {
                network: 0x0a0a_0a00,
                mask: 0xffff_ff00,
                metric: 10,
            },
            RouterLsaLink::PointToPoint {
                neighbor: 0x0a00_0002,
                local_addr: 0x0a0a_0a01,
                metric: 5,
            },
        ],
        None,
    )
    .unwrap();
    assert_eq!(lsa.header.ls_type, LsaTypeV2::RouterLsa as u16);
    assert_eq!(lsa.header.link_state_id, 0x0a00_0001);
    assert_eq!(lsa.header.advertising_router, 0x0a00_0001);
    assert_eq!(lsa.header.ls_sequence_number, INITIAL_SEQUENCE_NUMBER);
    // body: 2 flags + 2 count + 2 * 12 link bytes
    assert_eq!(lsa.body.len(), 4 + 24);
    assert_eq!(lsa.header.length as usize, 20 + 4 + 24);
    assert!(lsa.checksum_ok(), "LSA checksum must verify");
    // The E-bit opens the flags word (RFC 2328 A.4.2: the V/E/B
    // bits sit in the word's first byte — 0x0200 on the wire,
    // matching BIRD's htonl(OPT_RT_E << 24) and FRR's
    // stream_putc(ROUTER_LSA_EXTERNAL) + zero byte).
    assert_eq!(&lsa.body[..2], &0x0200u16.to_be_bytes());
    assert!(RouterLsaFlags::from_word(0x0700).asbr);
    // Link encoding: stub first.
    assert_eq!(&lsa.body[4..8], &0x0a0a_0a00u32.to_be_bytes());
    assert_eq!(&lsa.body[8..12], &0xffff_ff00u32.to_be_bytes());
    assert_eq!(lsa.body[12], RouterLinkType::StubNetwork as u8);
    assert_eq!(&lsa.body[14..16], &10u16.to_be_bytes());
    // Second link starts at 4 + 12 = 16; its metric sits at 26..28.
    assert_eq!(&lsa.body[26..28], &5u16.to_be_bytes());
}

#[test]
fn router_lsa_sequence_advances() {
    let first = originate_router_lsa(1, RouterLsaFlags::default(), &[], None).unwrap();
    let seq = first.header.ls_sequence_number;
    let second = originate_router_lsa(
        1,
        RouterLsaFlags::default(),
        &[RouterLsaLink::Stub {
            network: 0,
            mask: 0,
            metric: 1,
        }],
        Some(seq),
    )
    .unwrap();
    assert_eq!(second.header.ls_sequence_number, seq + 1);
    assert!(second.checksum_ok());
    // Exhausted sequence space refuses to originate.
    assert!(
        originate_router_lsa(1, RouterLsaFlags::default(), &[], Some(MAX_SEQUENCE_NUMBER))
            .is_none()
    );
}

#[test]
fn router_lsa_raw_link_passthrough() {
    let raw = RouterLink {
        link_id: 7,
        link_data: 8,
        link_type: RouterLinkType::VirtualLink as u8,
        tos: 0,
        metric: 99,
    };
    let lsa = originate_router_lsa(
        1,
        RouterLsaFlags::default(),
        &[RouterLsaLink::Raw(raw)],
        None,
    )
    .unwrap();
    // metric field is the last 2 bytes of the link entry
    assert_eq!(&lsa.body[14..16], &99u16.to_be_bytes());
    assert_eq!(lsa.body[12], RouterLinkType::VirtualLink as u8);
}
