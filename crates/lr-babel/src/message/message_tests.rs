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
fn update_wildcard_retraction_with_nonzero_plen_is_rejected() {
    // RFC 8966 §4.6.9: "If AE is 0, the Update TLV carries a wildcard
    // retraction. In that case, Plen MUST be 0 and Omitted MUST be 0,
    // and the prefix is empty." A malformed AE=0 Update with Plen > 0
    // must be rejected, not decoded into a route with no address
    // family but a non-empty prefix. The body carries the prefix
    // octets Plen implies so the bounds check does not reject the TLV
    // first — the AE=0 shape check has to fire.
    let mut v = vec![0u8; 10 + 3]; // 10-byte header + 3 prefix octets
    v[0] = 0; // AE = wildcard
    v[2] = 24; // Plen non-zero — illegal under AE=0
    v[10] = 203;
    v[11] = 0;
    v[12] = 113;
    assert!(
        Update::decode(&v).is_none(),
        "AE=0 with Plen > 0 must be rejected"
    );
}

#[test]
fn update_wildcard_retraction_with_nonzero_omitted_is_rejected() {
    // AE=0, Plen=24, Omitted > 0 — illegal under RFC 8966 §4.6.9.
    // Plen and Omitted together imply a non-empty in-band prefix
    // (ceil(24/8) - 1 = 2 octets), which we provide so the bounds
    // check does not fire first.
    let mut v = vec![0u8; 10 + 2];
    v[0] = 0; // AE = wildcard
    v[2] = 24; // Plen non-zero
    v[3] = 1; // Omitted > 0 — illegal
    v[10] = 203;
    v[11] = 0;
    assert!(
        Update::decode(&v).is_none(),
        "AE=0 with Omitted > 0 must be rejected"
    );
}

#[test]
fn update_wildcard_retraction_with_zero_plen_and_omitted_decodes() {
    // The matching positive case: AE=0, Plen=0, Omitted=0 — the only
    // legal shape for a wildcard retraction.
    let mut v = vec![0u8; 10];
    v[0] = 0; // AE = wildcard
    v[8] = 0xff;
    v[9] = 0xff; // metric = infinity (retraction)
    let dec = Update::decode(&v).expect("a well-formed AE=0 wildcard retraction decodes");
    assert_eq!(dec.ae, 0);
    assert_eq!(dec.prefix_len, 0);
    assert_eq!(dec.omitted, 0);
    assert!(dec.prefix.is_empty());
    assert_eq!(dec.metric, 0xffff);
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

/// RFC 8966 §4.1.4: "AE 3: Link-local IPv6 address. Compression is not
/// allowed. The value is 8 octets long, a prefix of fe80::/64 is
/// implied." The 8 wire octets are the interface identifier — bytes
/// 8..16 of the reconstructed address. The old codec wrote/expected
/// the first 8 bytes instead, so an AE-3 address round-tripped as
/// `XXXX::` (the fe80 prefix dropped, the interface id lost) and never
/// matched a compliant peer's IHU or next-hop.
#[test]
fn ae3_ihu_roundtrips_with_implied_fe80_prefix() {
    let ihu = Ihu {
        ae: 3,
        rxcost: 96,
        interval_cs: 300,
        // fe80::1 — the wire form is the interface id `...0001`.
        address: Some(IpAddr::V6([
            0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
        ])),
        timestamp_echo: None,
    };
    let enc = ihu.encode();
    // Exactly 8 address octets on the wire, all zero except the last.
    assert_eq!(enc.len(), 6 + 8);
    assert_eq!(&enc[6..14], &[0, 0, 0, 0, 0, 0, 0, 1]);
    // A compliant peer's form decodes back to fe80::1.
    assert_eq!(Ihu::decode(&enc).unwrap(), ihu);
    assert_eq!(
        Ihu::decode(&enc).unwrap().address,
        Some(IpAddr::V6([
            0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1
        ]))
    );
}

/// RFC 8966 §4.6.8 + §4.1.4: the Next Hop TLV's AE-3 form carries the
/// same 8 interface-id octets.
#[test]
fn ae3_next_hop_roundtrips_with_implied_fe80_prefix() {
    let nh = NextHop {
        ae: 3,
        address: IpAddr::V6([
            0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0x20, 0x0, 0xc, 0x9f, 0xfe, 0, 0, 0x1,
        ]),
    };
    let enc = nh.encode();
    assert_eq!(enc.len(), 2 + 8);
    assert_eq!(&enc[2..10], &[0x20, 0x00, 0x0c, 0x9f, 0xfe, 0x00, 0x00, 0x01]);
    assert_eq!(NextHop::decode(&enc).unwrap(), nh);
    // babeld's wire form (from network_prefix) decodes identically.
    let babeld_form = [
        3, 0, 0x20, 0x00, 0x0c, 0x9f, 0xfe, 0x00, 0x00, 0x01,
    ];
    assert_eq!(NextHop::decode(&babeld_form).unwrap(), nh);
}
