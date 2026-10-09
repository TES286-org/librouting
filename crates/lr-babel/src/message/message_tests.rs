use super::*;

#[test]
fn hello_roundtrip() {
    let h = Hello {
        flags: 0,
        seqno: 42,
        interval_cs: 1000,
        timestamp: None,
    };
    let enc = h.encode();
    assert_eq!(enc, [0, 0, 0, 42, 0x03, 0xe8]);
    assert_eq!(Hello::decode(&enc).unwrap(), h);
}

#[test]
fn ihu_roundtrip_v4() {
    let ihu = Ihu {
        ae: 1,
        rxcost: 256,
        interval_cs: 400,
        address: Some(IpAddr::V4([192, 0, 2, 1])),
        timestamp_echo: None,
    };
    let enc = ihu.encode();
    assert_eq!(enc[0], 1); // AE
    assert_eq!(enc[1], 0); // Reserved
    assert_eq!(Ihu::decode(&enc).unwrap(), ihu);
}

#[test]
fn ihu_wildcard_no_address() {
    let ihu = Ihu {
        ae: 0,
        rxcost: 100,
        interval_cs: 200,
        address: None,
        timestamp_echo: None,
    };
    let enc = ihu.encode();
    assert_eq!(enc.len(), 6);
    assert_eq!(Ihu::decode(&enc).unwrap(), ihu);
}

#[test]
fn router_id_roundtrip() {
    let rid = RouterId {
        id: [1, 2, 3, 4, 5, 6, 7, 8],
    };
    let enc = rid.encode();
    assert_eq!(enc.len(), 10);
    assert_eq!(&enc[..2], &[0, 0]); // Reserved
    assert_eq!(RouterId::decode(&enc).unwrap(), rid);
}

#[test]
fn next_hop_roundtrip() {
    let nh = NextHop {
        ae: 2,
        address: IpAddr::V6([0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]),
    };
    let enc = nh.encode();
    assert_eq!(enc[0], 2);
    assert_eq!(enc[1], 0); // Reserved
    assert_eq!(NextHop::decode(&enc).unwrap(), nh);
}

#[test]
fn update_roundtrip() {
    let u = Update {
        ae: 1,
        flags: 0,
        prefix_len: 24,
        omitted: 0,
        interval_cs: 500,
        seqno: 5,
        metric: 100,
        prefix: vec![203, 0, 113],
        src_prefix_len: 0,
        src_prefix: Vec::new(),
    };
    let enc = u.encode();
    assert_eq!(u8::from_be_bytes([enc[0]]), 1);
    assert_eq!(u16::from_be_bytes([enc[4], enc[5]]), 500); // Interval
    assert_eq!(u16::from_be_bytes([enc[6], enc[7]]), 5); // Seqno
    assert_eq!(u16::from_be_bytes([enc[8], enc[9]]), 100); // Metric
    let dec = Update::decode(&enc).unwrap();
    assert_eq!(dec, u);
    assert_eq!(u.prefix_value(), Some(Prefix::new_v4([203, 0, 113, 0], 24)));
}

#[test]
fn update_with_source_prefix_subtlv() {
    // RFC 9079 source-specific update: Source Prefix sub-TLV 128.
    let u = Update {
        ae: 1,
        flags: 0,
        prefix_len: 24,
        omitted: 0,
        interval_cs: 0,
        seqno: 9,
        metric: 0xFFFF,
        prefix: vec![192, 0, 2],
        src_prefix_len: 8,
        src_prefix: vec![10],
    };
    let enc = u.encode();
    // The Source Prefix sub-TLV follows the 10-byte header + prefix.
    assert_eq!(enc[13], SOURCE_PREFIX_SUBTLV);
    assert_eq!(enc[14], 2); // 1 plen byte + 1 octet
    let dec = Update::decode(&enc).unwrap();
    assert_eq!(dec, u);
}

#[test]
fn update_ignores_invalid_source_subtlv() {
    // Corrupt Source Prefix sub-TLV (length too short) → src cleared.
    let u = Update {
        ae: 1,
        flags: 0,
        prefix_len: 8,
        omitted: 0,
        interval_cs: 0,
        seqno: 1,
        metric: 1,
        prefix: vec![10],
        src_prefix_len: 0,
        src_prefix: Vec::new(),
    };
    let mut enc = u.encode();
    enc.extend_from_slice(&[SOURCE_PREFIX_SUBTLV, 1, 8]); // plen says 1 octet but len=1
    let dec = Update::decode(&enc).unwrap();
    assert_eq!(dec.src_prefix_len, 0);
    assert!(dec.src_prefix.is_empty());
}

#[test]
fn route_request_roundtrip() {
    let r = RouteRequest {
        ae: 1,
        prefix_len: 24,
        prefix: vec![203, 0, 113],
    };
    let enc = r.encode();
    assert_eq!(RouteRequest::decode(&enc).unwrap(), r);
}

#[test]
fn route_request_rejects_wildcard_with_plen() {
    let v = [0u8, 8];
    assert!(RouteRequest::decode(&v).is_none());
}

#[test]
fn seqno_request_roundtrip() {
    let r = SeqnoRequest {
        ae: 1,
        prefix_len: 24,
        prefix: vec![198, 51, 100],
        seqno: 42,
        hop_count: 3,
        router_id: [1, 2, 3, 4, 5, 6, 7, 8],
    };
    let enc = r.encode();
    assert_eq!(SeqnoRequest::decode(&enc).unwrap(), r);
}

#[test]
fn ack_req_roundtrip() {
    let a = AckReq {
        opaque: 0xbeef,
        interval_cs: 100,
    };
    let enc = a.encode();
    assert_eq!(&enc[..2], &[0, 0]); // Reserved
    assert_eq!(AckReq::decode(&enc).unwrap(), a);
}

#[test]
fn ack_roundtrip() {
    let a = Ack { opaque: 0x1234 };
    assert_eq!(Ack::decode(&a.encode()).unwrap(), a);
}

#[test]
fn hello_timestamp_roundtrip() {
    let h = Hello::new(7, 100).with_timestamp(0x1122_3344);
    let enc = h.encode();
    // Fixed body, then sub-TLV: type 3, length 4, big-endian value.
    assert_eq!(enc, [0, 0, 0, 7, 0, 100, 3, 4, 0x11, 0x22, 0x33, 0x44]);
    assert_eq!(Hello::decode(&enc).unwrap(), h);
}

#[test]
fn hello_timestamp_wrong_length_ignored() {
    // A 5-octet Timestamp sub-TLV value is corrupt — the sub-TLV is
    // ignored but the Hello itself stays valid (RFC 8966 §4.4).
    let mut enc = Hello::new(7, 100).encode();
    enc.extend_from_slice(&[3, 5, 1, 2, 3, 4, 5]);
    let h = Hello::decode(&enc).unwrap();
    assert_eq!(h.timestamp, None);
    assert_eq!(h.seqno, 7);
}

#[test]
fn hello_duplicate_timestamp_invalidates_the_subtlv_only() {
    // A second Timestamp sub-TLV corrupts the RTT datum, but the
    // enclosing Hello stays valid — the same graceful policy the
    // RFC 9079 Source Prefix sub-TLV parser applies.
    let mut enc = Hello::new(7, 100).with_timestamp(1).encode();
    enc.extend_from_slice(&[3, 4, 0, 0, 0, 2]);
    let h = Hello::decode(&enc).unwrap();
    assert_eq!(h.timestamp, None);
    assert_eq!(h.seqno, 7);
}

#[test]
fn hello_unknown_subtlv_ignored() {
    let mut enc = Hello::new(7, 100).encode();
    enc.extend_from_slice(&[99, 2, 0xaa, 0xbb]); // unknown sub-TLV
    enc.extend_from_slice(&[3, 4, 0, 0, 0, 42]); // timestamp
    let h = Hello::decode(&enc).unwrap();
    assert_eq!(h.timestamp, Some(42));
}

#[test]
fn hello_pad1_subtlv_tolerated() {
    let mut enc = Hello::new(7, 100).encode();
    enc.push(0); // Pad1
    enc.extend_from_slice(&[3, 4, 0, 0, 0, 9]);
    assert_eq!(Hello::decode(&enc).unwrap().timestamp, Some(9));
}

#[test]
fn ihu_timestamp_echo_roundtrip() {
    let ihu = Ihu::new(96, 300).with_timestamp_echo(0x0102_0304, 0x0506_0708);
    let enc = ihu.encode();
    assert_eq!(enc, [0, 0, 0, 96, 1, 44, 3, 8, 1, 2, 3, 4, 5, 6, 7, 8]);
    assert_eq!(Ihu::decode(&enc).unwrap(), ihu);
}

#[test]
fn ihu_v4_with_timestamp_echo_roundtrip() {
    let ihu = Ihu {
        ae: 1,
        rxcost: 96,
        interval_cs: 300,
        address: Some(IpAddr::V4([192, 0, 2, 1])),
        timestamp_echo: Some((7, 9)),
    };
    let enc = ihu.encode();
    // The sub-TLV follows the 4 address octets.
    assert_eq!(&enc[6..10], &[192, 0, 2, 1]);
    assert_eq!(&enc[10..], &[3, 8, 0, 0, 0, 7, 0, 0, 0, 9]);
    assert_eq!(Ihu::decode(&enc).unwrap(), ihu);
}

#[test]
fn ihu_timestamp_wrong_length_ignored() {
    let mut enc = Ihu::new(96, 300).encode();
    enc.extend_from_slice(&[3, 7, 1, 2, 3, 4, 5, 6, 7]);
    let ihu = Ihu::decode(&enc).unwrap();
    assert_eq!(ihu.timestamp_echo, None);
    assert_eq!(ihu.rxcost, 96);
}

#[test]
fn ihu_truncated_subtlv_drops_the_echo_only() {
    // The sub-TLV claims 8 octets but carries 3 — the echo datum
    // is unusable and dropped; the IHU cost fields stay valid.
    let mut enc = Ihu::new(96, 300).encode();
    enc.extend_from_slice(&[3, 8, 1, 2, 3]);
    let ihu = Ihu::decode(&enc).unwrap();
    assert_eq!(ihu.timestamp_echo, None);
    assert_eq!(ihu.rxcost, 96);
}
