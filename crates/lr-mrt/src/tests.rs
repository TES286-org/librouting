//! Unit tests: hand-built vectors + the BIRD 2.17.5 dump captured in
//! the interop lab (see tests/interop/mrt.sh for the live variant).

use super::*;
use lr_core::addr::{Asn, IpAddr};

/// The exact PEER_INDEX_TABLE + 2 RIB records BIRD 2.17.5 emitted for
/// `protocol static { route 198.51.100.0/24; route 203.0.113.0/24; }`
/// with router id 2.2.2.2, view "master4" (captured 2026-08-28).
const BIRD_DUMP: &[u8] = &[
    // --- PEER_INDEX_TABLE ---
    0x6a, 0x91, 0xc8, 0x61, // timestamp
    0x00, 0x0d, // TABLE_DUMP_V2
    0x00, 0x01, // PEER_INDEX_TABLE
    0x00, 0x00, 0x00, 0x28, // length 40
    0x02, 0x02, 0x02, 0x02, // collector BGP ID
    0x00, 0x07, // view name length
    b'm', b'a', b's', b't', b'e', b'r', b'4', // "master4"
    0x00, 0x01, // peer count 1
    0x03, // peer type: IPv6 + 32-bit AS (BIRD's synthetic local peer)
    0x00, 0x00, 0x00, 0x00, // peer BGP ID
    // peer IP :: (16 bytes)
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //
    0x00, 0x00, 0x00, 0x00, // peer AS 0
    // --- RIB entry 198.51.100.0/24 ---
    0x6a, 0x91, 0xc8, 0x61, // timestamp
    0x00, 0x0d, // TABLE_DUMP_V2
    0x00, 0x02, // RIB_IPV4_UNICAST
    0x00, 0x00, 0x00, 0x12, // length 18
    0x00, 0x00, 0x00, 0x00, // sequence 0
    0x18, // prefix length 24
    0xc6, 0x33, 0x64, // 198.51.100
    0x00, 0x01, // entry count 1
    0x00, 0x00, // peer index 0
    0x6a, 0x91, 0xc8, 0x5f, // originated time
    0x00, 0x00, // attribute length 0
    // --- RIB entry 203.0.113.0/24 ---
    0x6a, 0x91, 0xc8, 0x61, // timestamp
    0x00, 0x0d, // TABLE_DUMP_V2
    0x00, 0x02, // RIB_IPV4_UNICAST
    0x00, 0x00, 0x00, 0x12, // length 18
    0x00, 0x00, 0x00, 0x01, // sequence 1
    0x18, // prefix length 24
    0xcb, 0x00, 0x71, // 203.0.113
    0x00, 0x01, // entry count 1
    0x00, 0x00, // peer index 0
    0x6a, 0x91, 0xc8, 0x5f, // originated time
    0x00, 0x00, // attribute length 0
];

fn reader_drain(bytes: &[u8]) -> Vec<MrtRecord> {
    let mut reader = MrtReader::new();
    let mut records = Vec::new();
    // Feed in odd-sized chunks to exercise the carryover; after each
    // chunk, drain every complete buffered record.
    for chunk in bytes.chunks(7) {
        if let Some(record) = reader.decode_slice(chunk).unwrap() {
            records.push(record);
        }
        while let Some(record) = reader.decode_slice(&[]).unwrap() {
            records.push(record);
        }
    }
    records
}

#[test]
fn decodes_bird_peer_index_table() {
    let records = reader_drain(BIRD_DUMP);
    assert_eq!(records.len(), 3);
    let MrtRecord::PeerIndexTable(pit) = &records[0] else {
        panic!("first record must be the peer index table");
    };
    assert_eq!(pit.collector_bgp_id, 0x0202_0202);
    assert_eq!(pit.view_name, "master4");
    assert_eq!(pit.peers.len(), 1);
    assert_eq!(pit.peers[0].bgp_id, 0);
    assert_eq!(pit.peers[0].asn, Asn(0));
    assert_eq!(pit.peers[0].ip, IpAddr::V6([0; 16]));
}

#[test]
fn decodes_bird_rib_records() {
    let records = reader_drain(BIRD_DUMP);
    let MrtRecord::Rib(r1) = &records[1] else {
        panic!("second record must be a RIB record");
    };
    assert_eq!(r1.sequence, 0);
    assert_eq!(r1.prefix, "198.51.100.0/24".parse().unwrap());
    assert!(!r1.add_path);
    assert_eq!(r1.entries.len(), 1);
    assert_eq!(r1.entries[0].peer_index, 0);
    assert!(r1.entries[0].attributes.is_empty());
    let MrtRecord::Rib(r2) = &records[2] else {
        panic!("third record must be a RIB record");
    };
    assert_eq!(r2.sequence, 1);
    assert_eq!(r2.prefix, "203.0.113.0/24".parse().unwrap());
}

#[test]
fn encode_matches_bird_layout() {
    // Round-trip the captured dump through our encoder: byte-equal
    // output proves the layout (BIRD compatibility).
    let peers = vec![PeerEntry {
        bgp_id: 0,
        ip: IpAddr::V6([0; 16]),
        asn: Asn(0),
    }];
    let dump = MrtRibDump {
        collector_bgp_id: 0x0202_0202,
        view_name: "master4".to_string(),
        peers,
        tables: vec![
            RibTable {
                sequence: 0,
                prefix: "198.51.100.0/24".parse().unwrap(),
                add_path: false,
                entries: vec![RibEntry {
                    peer_index: 0,
                    originated_time: 0x6a91_c85f,
                    path_id: 0,
                    attributes: vec![],
                }],
            },
            RibTable {
                sequence: 1,
                prefix: "203.0.113.0/24".parse().unwrap(),
                add_path: false,
                entries: vec![RibEntry {
                    peer_index: 0,
                    originated_time: 0x6a91_c85f,
                    path_id: 0,
                    attributes: vec![],
                }],
            },
        ],
    };
    let encoded = dump.encode(0x6a91_c861).unwrap();
    assert_eq!(encoded, BIRD_DUMP, "encoder must reproduce BIRD bytes");
}

#[test]
fn rib_entry_with_attributes_roundtrips() {
    // Path attributes: ORIGIN igp (flags 0x40, type 1, len 1), AS_PATH
    // (type 2, one AS_SEQUENCE segment with AS 65001 at 4-byte width),
    // NEXT_HOP 192.0.2.1.
    let attrs = vec![
        0x40, 0x01, 0x01, 0x00, // ORIGIN = IGP
        0x40, 0x02, 0x06, 0x02, 0x01, 0x00, 0x00, 0xfd, 0xe9, // AS_PATH 65001
        0x40, 0x03, 0x04, 0xc0, 0x00, 0x02, 0x01, // NEXT_HOP
    ];
    let table = RibTable {
        sequence: 7,
        prefix: "2001:db8:1::/48".parse().unwrap(),
        add_path: false,
        entries: vec![RibEntry {
            peer_index: 2,
            originated_time: 12345,
            path_id: 0,
            attributes: attrs.clone(),
        }],
    };
    let wire = encode_rib_table(99, &table).unwrap();
    // v6 unicast subtype selected automatically.
    assert_eq!(
        u16::from_be_bytes([wire[6], wire[7]]),
        tdv2_subtype::RIB_IPV6_UNICAST
    );
    let mut reader = MrtReader::new();
    let record = reader.decode_slice(&wire).unwrap().unwrap();
    let MrtRecord::Rib(decoded) = record else {
        panic!("expected RIB record");
    };
    assert_eq!(decoded, table);
    assert_eq!(wire.len(), 12 + 4 + 1 + 6 + 2 + 2 + 4 + 2 + attrs.len());

    // Typed interpretation.
    let summary = walk_attributes(&decoded.entries[0]);
    assert_eq!(summary.next_hop, Some("192.0.2.1".parse().unwrap()));
    assert_eq!(summary.as_path, "AS65001");
    assert_eq!(summary.raw_len, attrs.len());
}

#[test]
fn addpath_rib_entry_roundtrips() {
    let table = RibTable {
        sequence: 1,
        prefix: "10.0.0.0/24".parse().unwrap(),
        add_path: true,
        entries: vec![RibEntry {
            peer_index: 3,
            originated_time: 1,
            path_id: 42,
            attributes: vec![0x40, 0x01, 0x01, 0x00],
        }],
    };
    let wire = encode_rib_table(5, &table).unwrap();
    assert_eq!(
        u16::from_be_bytes([wire[6], wire[7]]),
        tdv2_subtype::RIB_IPV4_UNICAST_ADDPATH
    );
    let mut reader = MrtReader::new();
    let record = reader.decode_slice(&wire).unwrap().unwrap();
    let MrtRecord::Rib(decoded) = record else {
        panic!("expected RIB record");
    };
    assert_eq!(decoded.entries[0].path_id, 42);
    assert_eq!(decoded, table);
}

#[test]
fn peer_index_table_encodes_and_decodes() {
    let peers = vec![
        PeerEntry {
            bgp_id: 0x0a00_0001,
            ip: IpAddr::V4([192, 0, 2, 1]),
            asn: Asn(65001),
        },
        PeerEntry {
            bgp_id: 0x0a00_0002,
            ip: IpAddr::V6([0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]),
            asn: Asn(65002),
        },
    ];
    let wire = encode_peer_index_table(1234, 0x0a00_00ff, "main", &peers).unwrap();
    let mut reader = MrtReader::new();
    let record = reader.decode_slice(&wire).unwrap().unwrap();
    let MrtRecord::PeerIndexTable(pit) = record else {
        panic!("expected peer index table");
    };
    assert_eq!(pit.collector_bgp_id, 0x0a00_00ff);
    assert_eq!(pit.view_name, "main");
    assert_eq!(pit.peers, peers);
}

#[test]
fn bgp4mp_as4_subtype_numbers_match_rfc_6396() {
    // RFC 6396 §4.4: 0=STATE_CHANGE, 1=MESSAGE, 2=ENTRY (deprecated),
    // 3=SNAPSHOT (deprecated), 4=MESSAGE_AS4, 5=STATE_CHANGE_AS4,
    // 6=MESSAGE_LOCAL, 7=MESSAGE_AS4_LOCAL. The pre-publication Zebra
    // numbering (BGP4MP_ENTRY=2, BGP4MP_SNAPSHOT=3, AS4 at 4/5 swapped
    // with 2/3) is what the constants used to encode, so real AS4 dumps
    // decoded as `Unknown` and real ENTRY records were misparsed as
    // messages.
    assert_eq!(bgp4mp_subtype::STATE_CHANGE, 0);
    assert_eq!(bgp4mp_subtype::MESSAGE, 1);
    assert_eq!(bgp4mp_subtype::ENTRY, 2);
    assert_eq!(bgp4mp_subtype::SNAPSHOT, 3);
    assert_eq!(bgp4mp_subtype::MESSAGE_AS4, 4);
    assert_eq!(bgp4mp_subtype::STATE_CHANGE_AS4, 5);
    assert_eq!(bgp4mp_subtype::MESSAGE_LOCAL, 6);
    assert_eq!(bgp4mp_subtype::MESSAGE_AS4_LOCAL, 7);
}

#[test]
fn bgp4mp_message_as4_decodes() {
    // Hand-built BGP4MP_MESSAGE_AS4 (literal RFC 6396 §4.4 subtype 4):
    // peer AS 65010, local AS 65000, ifindex 4, AF 1, IPv4 peer/local,
    // then a KEEPALIVE (19 bytes, marker all-FF, length 19, type 4).
    let mut body = Vec::new();
    body.extend_from_slice(&65010u32.to_be_bytes());
    body.extend_from_slice(&65000u32.to_be_bytes());
    body.extend_from_slice(&4u16.to_be_bytes());
    body.extend_from_slice(&1u16.to_be_bytes()); // AF IPv4
    body.extend_from_slice(&[192, 0, 2, 2]); // peer IP
    body.extend_from_slice(&[192, 0, 2, 1]); // local IP
    let mut msg = vec![0xff; 16];
    msg.extend_from_slice(&19u16.to_be_bytes());
    msg.push(4); // KEEPALIVE
    body.extend_from_slice(&msg);

    let mut record = Vec::new();
    record.extend_from_slice(&77u32.to_be_bytes()); // timestamp
    record.extend_from_slice(&msg_type::BGP4MP.to_be_bytes());
    record.extend_from_slice(&4u16.to_be_bytes()); // BGP4MP_MESSAGE_AS4
    record.extend_from_slice(&(body.len() as u32).to_be_bytes());
    record.extend_from_slice(&body);

    let mut reader = MrtReader::new();
    let decoded = reader.decode_slice(&record).unwrap().unwrap();
    let MrtRecord::Bgp4MpMessage(m) = decoded else {
        panic!("expected BGP4MP message, got {:?}", decoded);
    };
    assert_eq!(m.common.peer_as, Asn(65010));
    assert_eq!(m.common.local_as, Asn(65000));
    assert_eq!(m.common.ifindex, 4);
    assert_eq!(m.common.af, 1);
    assert_eq!(m.common.peer_ip, IpAddr::V4([192, 0, 2, 2]));
    assert_eq!(m.common.local_ip, IpAddr::V4([192, 0, 2, 1]));
    assert_eq!(m.message.len(), 19);
    assert_eq!(m.message[18], 4);
}

#[test]
fn bgp4mp_entry_subtype_2_is_unknown_not_message() {
    // RFC 6396 §4.4 subtype 2 is the deprecated BGP4MP_ENTRY (a different
    // body layout), NOT BGP4MP_MESSAGE_AS4 (which is 4). A record
    // carrying subtype 2 must decode as Unknown, never as a message —
    // this is what the pre-publication numbering got wrong.
    let mut body = Vec::new();
    body.extend_from_slice(&65010u16.to_be_bytes()); // peer AS (2-byte)
    body.extend_from_slice(&65000u16.to_be_bytes()); // local AS
    body.extend_from_slice(&0u16.to_be_bytes()); // ifindex
    body.extend_from_slice(&1u16.to_be_bytes()); // AF IPv4
    body.extend_from_slice(&[10, 0, 0, 2]); // peer IP
    body.extend_from_slice(&[10, 0, 0, 1]); // local IP
    body.extend_from_slice(&[0xff; 19]); // would-be message bytes

    let mut record = Vec::new();
    record.extend_from_slice(&1u32.to_be_bytes());
    record.extend_from_slice(&msg_type::BGP4MP.to_be_bytes());
    record.extend_from_slice(&2u16.to_be_bytes()); // literal BGP4MP_ENTRY
    record.extend_from_slice(&(body.len() as u32).to_be_bytes());
    record.extend_from_slice(&body);

    let mut reader = MrtReader::new();
    let decoded = reader.decode_slice(&record).unwrap().unwrap();
    assert_eq!(
        decoded,
        MrtRecord::Unknown {
            msg_type: msg_type::BGP4MP,
            subtype: 2
        }
    );
}

#[test]
fn bgp4mp_state_change_as4_subtype_5_decodes() {
    // Literal RFC 6396 §4.4 subtype 5 (BGP4MP_STATE_CHANGE_AS4) with
    // 4-byte AS numbers: 2-byte-AS variants read a 4-byte offset here.
    let mut body = Vec::new();
    body.extend_from_slice(&65010u32.to_be_bytes());
    body.extend_from_slice(&65000u32.to_be_bytes());
    body.extend_from_slice(&3u16.to_be_bytes()); // ifindex
    body.extend_from_slice(&2u16.to_be_bytes()); // AF IPv6
    body.extend_from_slice(&[0; 15]);
    body.push(1); // peer ::1
    body.extend_from_slice(&[0; 15]);
    body.push(2); // local ::2
    body.extend_from_slice(&2u16.to_be_bytes()); // OpenConfirm
    body.extend_from_slice(&6u16.to_be_bytes()); // Established

    let mut record = Vec::new();
    record.extend_from_slice(&77u32.to_be_bytes());
    record.extend_from_slice(&msg_type::BGP4MP.to_be_bytes());
    record.extend_from_slice(&5u16.to_be_bytes()); // BGP4MP_STATE_CHANGE_AS4
    record.extend_from_slice(&(body.len() as u32).to_be_bytes());
    record.extend_from_slice(&body);

    let mut reader = MrtReader::new();
    let decoded = reader.decode_slice(&record).unwrap().unwrap();
    let MrtRecord::Bgp4MpStateChange(sc) = decoded else {
        panic!("expected state change, got {:?}", decoded);
    };
    assert_eq!(sc.common.peer_as, Asn(65010));
    assert_eq!(sc.common.local_as, Asn(65000));
    assert_eq!(sc.common.af, 2);
    assert_eq!(
        sc.common.peer_ip,
        IpAddr::V6([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1])
    );
    assert_eq!(sc.old_state, 2);
    assert_eq!(sc.new_state, 6);
}

#[test]
fn bgp4mp_state_change_2byte_as_decodes() {
    let mut body = Vec::new();
    body.extend_from_slice(&65010u16.to_be_bytes());
    body.extend_from_slice(&65000u16.to_be_bytes());
    body.extend_from_slice(&0u16.to_be_bytes()); // ifindex
    body.extend_from_slice(&1u16.to_be_bytes()); // AF
    body.extend_from_slice(&[10, 0, 0, 2]);
    body.extend_from_slice(&[10, 0, 0, 1]);
    body.extend_from_slice(&1u16.to_be_bytes()); // Idle
    body.extend_from_slice(&6u16.to_be_bytes()); // Established

    let mut record = Vec::new();
    record.extend_from_slice(&77u32.to_be_bytes());
    record.extend_from_slice(&msg_type::BGP4MP.to_be_bytes());
    record.extend_from_slice(&bgp4mp_subtype::STATE_CHANGE.to_be_bytes());
    record.extend_from_slice(&(body.len() as u32).to_be_bytes());
    record.extend_from_slice(&body);

    let mut reader = MrtReader::new();
    let decoded = reader.decode_slice(&record).unwrap().unwrap();
    let MrtRecord::Bgp4MpStateChange(sc) = decoded else {
        panic!("expected state change");
    };
    assert_eq!(sc.common.peer_as, Asn(65010));
    assert_eq!(sc.old_state, 1);
    assert_eq!(sc.new_state, 6);
}

#[test]
fn unknown_record_types_pass_through() {
    // A legacy TABLE_DUMP (type 12) record: header + minimal body.
    let mut record = Vec::new();
    record.extend_from_slice(&1u32.to_be_bytes());
    record.extend_from_slice(&12u16.to_be_bytes());
    record.extend_from_slice(&0u16.to_be_bytes());
    record.extend_from_slice(&4u32.to_be_bytes());
    record.extend_from_slice(&[0xde, 0xad, 0xbe, 0xef]);
    let mut reader = MrtReader::new();
    let decoded = reader.decode_slice(&record).unwrap().unwrap();
    assert_eq!(
        decoded,
        MrtRecord::Unknown {
            msg_type: 12,
            subtype: 0
        }
    );
    // The reader is positioned at the next record.
    let next = reader.decode_slice(&record).unwrap().unwrap();
    assert!(matches!(next, MrtRecord::Unknown { .. }));
}

#[test]
fn truncated_input_is_partial() {
    let wire = encode_peer_index_table(1, 5, "", &[]).unwrap();
    let mut reader = MrtReader::new();
    assert!(reader
        .decode_slice(&wire[..wire.len() - 1])
        .unwrap()
        .is_none());
    assert!(reader
        .decode_slice(&[wire[wire.len() - 1]])
        .unwrap()
        .is_some());
}

#[test]
fn core_attributes_encode_as_wire_tlvs() {
    use lr_core::attr::{AttrTag, Attribute};
    let mut attrs = lr_core::attr::Attributes::new();
    attrs.insert(Attribute {
        tag: AttrTag::raw(1),
        flags: 0x40,
        value: vec![0],
    });
    attrs.insert(Attribute {
        tag: AttrTag::raw(3),
        flags: 0x40,
        value: vec![192, 0, 2, 1],
    });
    let wire = encode_attributes(&attrs);
    assert_eq!(
        wire,
        vec![
            0x40, 0x01, 0x01, 0x00, //
            0x40, 0x03, 0x04, 192, 0, 2, 1
        ]
    );
}

#[test]
fn extended_length_attribute_sets_flag_bit() {
    use lr_core::attr::{AttrTag, Attribute};
    // RFC 4271 §4.3: values > 255 octets need the extended-length form:
    // the 0x10 flag bit set in the flags octet plus a 3-octet length.
    let big = vec![0xabu8; 300];
    let mut attrs = lr_core::attr::Attributes::new();
    attrs.insert(Attribute {
        tag: AttrTag::raw(9),
        flags: 0x40,
        value: big.clone(),
    });
    let wire = encode_attributes(&attrs);
    assert_eq!(wire.len(), 1 + 1 + 1 + 2 + 300);
    assert_eq!(wire[0], 0x40 | 0x10, "extended-length flag must be set");
    assert_eq!(wire[1], 9);
    assert_eq!(wire[2], 0xff);
    assert_eq!(u16::from_be_bytes([wire[3], wire[4]]), 300);
    assert_eq!(&wire[5..], &big[..]);
}

#[test]
fn mp_reach_next_hop_interpretation() {
    // Entry whose only next-hop carrier is MP_REACH_NLRI (IPv6 NLRI
    // style): family ipv6-unicast (AFI 2, SAFI 1), next-hop length 16,
    // ::1, no NLRI.
    let mut mp = Vec::new();
    mp.extend_from_slice(&[0, 2]); // AFI 2
    mp.push(1); // SAFI 1
    mp.push(16); // next-hop length
    mp.extend_from_slice(&[0; 15]);
    mp.push(1); // ::1
    mp.extend_from_slice(&[0]); // reserved
    let mut attrs = Vec::new();
    attrs.extend_from_slice(&[0x80, 0x0e, mp.len() as u8]); // flags, type 14, len
    attrs.extend_from_slice(&mp);

    let entry = RibEntry {
        peer_index: 0,
        originated_time: 0,
        path_id: 0,
        attributes: attrs,
    };
    let summary = walk_attributes(&entry);
    assert_eq!(
        summary.next_hop,
        Some(IpAddr::V6([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]))
    );
}

#[cfg(feature = "std")]
#[test]
fn parse_file_roundtrip() {
    let dump = MrtRibDump::new(0x0a00_0001, "test");
    let wire = dump.encode(42).unwrap();
    let path = std::env::temp_dir().join("lr_mrt_unit_test.mrt");
    std::fs::write(&path, &wire).unwrap();
    let records = parse_file(path.to_str().unwrap()).unwrap();
    assert_eq!(records.len(), 1);
    assert!(matches!(records[0], MrtRecord::PeerIndexTable(_)));
    std::fs::remove_file(&path).ok();
}
