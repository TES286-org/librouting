use super::*;

fn u32b(v: u32) -> [u8; 4] {
    v.to_be_bytes()
}

/// Byte-exact vectors against the RFC 8210 §5 figures.
#[test]
fn serial_notify_wire_form() {
    // §5.2: ver=1, type=0, session=0x1234, len=12, serial=5.
    let expected = [
        &[1u8, 0u8][..],
        &0x1234u16.to_be_bytes(),
        &u32b(12),
        &u32b(5),
    ]
    .concat();
    let pdu = RtrPdu::SerialNotify {
        session_id: 0x1234,
        serial: 5,
    };
    assert_eq!(encode_vec(&pdu, RTR_VERSION_1), expected);
    let (_ver, dec, used) = decode(&expected).unwrap().unwrap();
    assert_eq!(used, 12);
    assert_eq!(dec, pdu);
}

#[test]
fn serial_query_wire_form() {
    // §5.3: ver=1, type=1, session=0x2345, len=12, serial=7.
    let expected = [
        &[1u8, 1u8][..],
        &0x2345u16.to_be_bytes(),
        &u32b(12),
        &u32b(7),
    ]
    .concat();
    let pdu = RtrPdu::SerialQuery {
        session_id: 0x2345,
        serial: 7,
    };
    assert_eq!(encode_vec(&pdu, RTR_VERSION_1), expected);
    let (_ver, dec, used) = decode(&expected).unwrap().unwrap();
    assert_eq!(used, 12);
    assert_eq!(dec, pdu);
}

#[test]
fn reset_query_wire_form() {
    // §5.4: ver=1, type=2, zero, len=8.
    let expected = [&[1u8, 2u8, 0, 0][..], &u32b(8)].concat();
    assert_eq!(encode_vec(&RtrPdu::ResetQuery, RTR_VERSION_1), expected);
    let (_ver, dec, used) = decode(&expected).unwrap().unwrap();
    assert_eq!(used, 8);
    assert_eq!(dec, RtrPdu::ResetQuery);
}

#[test]
fn cache_response_wire_form() {
    // §5.5: ver=1, type=3, session=0x00ff, len=8.
    let expected = [&[1u8, 3u8][..], &0x00ffu16.to_be_bytes(), &u32b(8)].concat();
    let pdu = RtrPdu::CacheResponse { session_id: 0x00ff };
    assert_eq!(encode_vec(&pdu, RTR_VERSION_1), expected);
    assert_eq!(decode(&expected).unwrap().unwrap().1, pdu);
}

#[test]
fn ipv4_prefix_wire_form() {
    // §5.6: ver=1, type=4, zero, len=20, flags=1 (announce),
    // prefix_len=24, max_len=24, zero, 192.0.2.0, ASN 64512.
    let expected = [
        &[1u8, 4u8, 0, 0][..],
        &u32b(20),
        &[1u8, 24, 24, 0],
        &[192, 0, 2, 0],
        &u32b(64512),
    ]
    .concat();
    assert_eq!(expected.len(), 20);
    let pdu = RtrPdu::Ipv4Prefix {
        announce: true,
        prefix: Prefix::new_v4([192, 0, 2, 0], 24),
        max_length: 24,
        asn: 64512,
    };
    assert_eq!(encode_vec(&pdu, RTR_VERSION_1), expected);
    assert_eq!(decode(&expected).unwrap().unwrap().1, pdu);
}

#[test]
fn ipv6_prefix_wire_form() {
    // §5.7: ver=1, type=6, zero, len=32, flags=1, prefix_len=48,
    // max_len=64, zero, 2001:db8::, ASN 64512.
    let addr: [u8; 16] = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    let expected = [
        &[1u8, 6u8, 0, 0][..],
        &u32b(32),
        &[1u8, 48, 64, 0],
        &addr,
        &u32b(64512),
    ]
    .concat();
    assert_eq!(expected.len(), 32);
    let pdu = RtrPdu::Ipv6Prefix {
        announce: true,
        prefix: Prefix::new_v6(addr, 48),
        max_length: 64,
        asn: 64512,
    };
    assert_eq!(encode_vec(&pdu, RTR_VERSION_1), expected);
    assert_eq!(decode(&expected).unwrap().unwrap().1, pdu);
}

#[test]
fn end_of_data_v1_wire_form() {
    // §5.8: ver=1, type=7, session=0xabcd, len=24, serial=9,
    // refresh=3600, retry=600, expire=7200.
    let expected = [
        &[1u8, 7u8][..],
        &0xabcdu16.to_be_bytes(),
        &u32b(24),
        &u32b(9),
        &u32b(3600),
        &u32b(600),
        &u32b(7200),
    ]
    .concat();
    assert_eq!(expected.len(), 24);
    let pdu = RtrPdu::EndOfData {
        session_id: 0xabcd,
        serial: 9,
        refresh_interval: Some(3600),
        retry_interval: Some(600),
        expire_interval: Some(7200),
    };
    assert_eq!(encode_vec(&pdu, RTR_VERSION_1), expected);
    assert_eq!(decode(&expected).unwrap().unwrap().1, pdu);
}

#[test]
fn end_of_data_v0_form_omits_intervals() {
    // RFC 6810 form: ver=0, type=7, session, len=12, serial.
    let expected = [
        &[0u8, 7u8][..],
        &0x0001u16.to_be_bytes(),
        &u32b(12),
        &u32b(42),
    ]
    .concat();
    let pdu = RtrPdu::EndOfData {
        session_id: 1,
        serial: 42,
        refresh_interval: None,
        retry_interval: None,
        expire_interval: None,
    };
    assert_eq!(encode_vec(&pdu, RTR_VERSION_0), expected);
    let (_ver, dec, used) = decode(&expected).unwrap().unwrap();
    assert_eq!(used, 12);
    assert_eq!(dec, pdu);
    // The v1 defaults fill in the RFC 8210 §6 recommended values
    // when re-encoded at v1.
    let v1 = encode_vec(&pdu, RTR_VERSION_1);
    assert_eq!(v1.len(), 24);
    assert_eq!(&v1[12..16], &u32b(3600));
}

#[test]
fn cache_reset_wire_form() {
    // §5.9: ver=1, type=8, zero, len=8.
    let expected = [&[1u8, 8u8, 0, 0][..], &u32b(8)].concat();
    assert_eq!(encode_vec(&RtrPdu::CacheReset, RTR_VERSION_1), expected);
    assert_eq!(decode(&expected).unwrap().unwrap().1, RtrPdu::CacheReset);
}

#[test]
fn router_key_wire_form() {
    // §5.10: ver=1, type=9, flags=1, zero, len, SKI (20), ASN,
    // SPKI (variable).
    let ski: [u8; 20] = core::array::from_fn(|i| i as u8);
    let spki = vec![0x30, 0x59, 0x30, 0x13, 0x06, 0x07];
    let len = 8 + 20 + 4 + spki.len();
    let expected = [
        &[1u8, 9u8, 1, 0][..],
        &u32b(len as u32),
        &ski,
        &u32b(64512),
        &spki,
    ]
    .concat();
    let pdu = RtrPdu::RouterKey {
        announce: true,
        ski,
        asn: 64512,
        subject_public_key_info: spki,
    };
    assert_eq!(encode_vec(&pdu, RTR_VERSION_1), expected);
    assert_eq!(decode(&expected).unwrap().unwrap().1, pdu);
}

#[test]
fn error_report_wire_form() {
    // §5.11: ver=1, type=10, code=4 (Unsupported Protocol
    // Version), len, enc_len=0, [no encapsulated PDU], text_len,
    // text.
    let text = b"speaking version 2".to_vec();
    // header + enc_len + text_len fields (no encapsulated PDU).
    let len = 8 + 4 + 4 + text.len();
    let expected = [
        &[1u8, 10u8][..],
        &4u16.to_be_bytes(),
        &u32b(len as u32),
        &u32b(0),
        &u32b(text.len() as u32),
        &text,
    ]
    .concat();
    let pdu = RtrPdu::ErrorReport {
        error_code: RtrErrorCode::UnsupportedProtocolVersion,
        erroneous_pdu: Vec::new(),
        error_text: Some(String::from_utf8(text).unwrap()),
    };
    assert_eq!(encode_vec(&pdu, RTR_VERSION_1), expected);
    assert_eq!(decode(&expected).unwrap().unwrap().1, pdu);
}

#[test]
fn error_report_with_encapsulated_pdu() {
    // An Error Report echoing the PDU that caused it (§5.11).
    let erroneous = encode_vec(&RtrPdu::ResetQuery, RTR_VERSION_1);
    let text = b"bad request".to_vec();
    let len = 8 + 4 + erroneous.len() + 4 + text.len();
    let mut expected = Vec::new();
    expected.extend_from_slice(&[1u8, 10u8]);
    expected.extend_from_slice(&3u16.to_be_bytes());
    expected.extend_from_slice(&u32b(len as u32));
    expected.extend_from_slice(&u32b(erroneous.len() as u32));
    expected.extend_from_slice(&erroneous);
    expected.extend_from_slice(&u32b(text.len() as u32));
    expected.extend_from_slice(&text);
    let pdu = RtrPdu::ErrorReport {
        error_code: RtrErrorCode::InvalidRequest,
        erroneous_pdu: erroneous,
        error_text: Some(String::from_utf8(text).unwrap()),
    };
    assert_eq!(encode_vec(&pdu, RTR_VERSION_1), expected);
    assert_eq!(decode(&expected).unwrap().unwrap().1, pdu);
}

#[test]
fn aspa_wire_form() {
    // SIDROPS ASPA profile: ver=2, type=11, flags=1, zero, len,
    // customer ASN, provider ASNs.
    let providers = vec![64500u32, 64501, 64502];
    let len = 8 + 4 + providers.len() * 4;
    let expected = [
        &[2u8, 11u8, 1, 0][..],
        &u32b(len as u32),
        &u32b(64496),
        &u32b(64500),
        &u32b(64501),
        &u32b(64502),
    ]
    .concat();
    let pdu = RtrPdu::Aspa {
        announce: true,
        customer_asn: 64496,
        providers,
    };
    assert_eq!(encode_vec(&pdu, RTR_VERSION_2), expected);
    let (_ver, dec, used) = decode(&expected).unwrap().unwrap();
    assert_eq!(used, expected.len());
    assert_eq!(dec, pdu);
}

// ----- framing: partial buffers, multiple PDUs -----

#[test]
fn decode_reports_incomplete() {
    let pdu = encode_vec(
        &RtrPdu::Ipv4Prefix {
            announce: true,
            prefix: Prefix::new_v4([10, 0, 0, 0], 8),
            max_length: 8,
            asn: 1,
        },
        RTR_VERSION_1,
    );
    // Fewer than a header: IncompleteHeader-shaped None.
    assert!(decode(&pdu[..4]).unwrap().is_none());
    // Header present, body truncated: None again (the framing
    // layer must read more, not treat this as an error).
    assert!(decode(&pdu[..15]).unwrap().is_none());
    // Exactly one byte short of the full PDU.
    assert!(decode(&pdu[..pdu.len() - 1]).unwrap().is_none());
    assert!(decode(&pdu).unwrap().is_some());
}

#[test]
fn decode_two_back_to_back_pdus() {
    let a = encode_vec(&RtrPdu::CacheResponse { session_id: 7 }, RTR_VERSION_1);
    let b = encode_vec(
        &RtrPdu::SerialNotify {
            session_id: 7,
            serial: 3,
        },
        RTR_VERSION_1,
    );
    let mut stream = a.clone();
    stream.extend_from_slice(&b);
    let (_va, pdu_a, used_a) = decode(&stream).unwrap().unwrap();
    assert_eq!(used_a, a.len());
    assert_eq!(pdu_a, RtrPdu::CacheResponse { session_id: 7 });
    let (_vb, pdu_b, used_b) = decode(&stream[used_a..]).unwrap().unwrap();
    assert_eq!(used_b, b.len());
    assert_eq!(
        pdu_b,
        RtrPdu::SerialNotify {
            session_id: 7,
            serial: 3
        }
    );
}

// ----- validation -----

#[test]
fn rejects_reserved_type_5() {
    let bad = [&[1u8, 5u8, 0, 0][..], &u32b(8)].concat();
    assert_eq!(
        decode(&bad),
        Err(RtrDecodeError::UnsupportedPduType { ty: 5 })
    );
}

#[test]
fn rejects_unknown_type() {
    let bad = [&[1u8, 12u8, 0, 0][..], &u32b(8)].concat();
    assert_eq!(
        decode(&bad),
        Err(RtrDecodeError::UnsupportedPduType { ty: 12 })
    );
}

#[test]
fn router_key_needs_v1() {
    let good = encode_vec(
        &RtrPdu::RouterKey {
            announce: true,
            ski: [0; 20],
            asn: 1,
            subject_public_key_info: vec![0x30],
        },
        RTR_VERSION_1,
    );
    assert!(decode(&good).is_ok());
    let mut v0 = good.clone();
    v0[0] = RTR_VERSION_0; // downgrade the version byte
    assert_eq!(
        decode(&v0),
        Err(RtrDecodeError::UnsupportedVersion { ty: 9, ver: 0 })
    );
}

#[test]
fn aspa_needs_v2() {
    let good = encode_vec(
        &RtrPdu::Aspa {
            announce: true,
            customer_asn: 64496,
            providers: vec![64500],
        },
        RTR_VERSION_2,
    );
    assert!(decode(&good).is_ok());
    let mut v1 = good.clone();
    v1[0] = RTR_VERSION_1;
    assert_eq!(
        decode(&v1),
        Err(RtrDecodeError::UnsupportedVersion { ty: 11, ver: 1 })
    );
}

#[test]
fn rejects_bad_lengths() {
    // Length below the header.
    let bad = [&[1u8, 0u8, 0, 0][..], &u32b(4)].concat();
    assert_eq!(decode(&bad), Err(RtrDecodeError::InvalidLength { len: 4 }));
    // Length over the ceiling.
    let bad = [&[1u8, 0u8, 0, 0][..], &u32b(70_000)].concat();
    assert_eq!(
        decode(&bad),
        Err(RtrDecodeError::InvalidLength { len: 70_000 })
    );
    // Fixed-size PDU with a wrong length: Serial Notify claims 16
    // (and the buffer carries all 16, so the length check is
    // reached rather than framing reporting the body incomplete).
    let bad = [
        &[1u8, 0u8][..],
        &0u16.to_be_bytes(),
        &u32b(16),
        &u32b(1),
        &[0xde, 0xad, 0xbe, 0xef][..],
    ]
    .concat();
    assert_eq!(
        decode(&bad),
        Err(RtrDecodeError::BadFixedLength {
            pdu: "Serial Notify",
            len: 16
        })
    );
}

#[test]
fn rejects_bad_prefix_invariants() {
    // max_length < prefix_len (RFC 6811 §5.1: "MUST NOT be less").
    let bad = [
        &[1u8, 4u8, 0, 0][..],
        &u32b(20),
        &[1u8, 24, 16, 0],
        &[192, 0, 2, 0],
        &u32b(64512),
    ]
    .concat();
    assert_eq!(
        decode(&bad),
        Err(RtrDecodeError::BadPrefix {
            pdu: "IPv4 Prefix",
            reason: "max length below the prefix length"
        })
    );
    // prefix_len > 32 on a v4 PDU.
    let bad = [
        &[1u8, 4u8, 0, 0][..],
        &u32b(20),
        &[1u8, 33, 33, 0],
        &[192, 0, 2, 0],
        &u32b(64512),
    ]
    .concat();
    assert_eq!(
        decode(&bad),
        Err(RtrDecodeError::BadPrefix {
            pdu: "IPv4 Prefix",
            reason: "prefix length exceeds the address family width"
        })
    );
    // v6 max_length > 128.
    let addr = [0u8; 16];
    let bad = [
        &[1u8, 6u8, 0, 0][..],
        &u32b(32),
        &[1u8, 48, 129, 0],
        &addr,
        &u32b(64512),
    ]
    .concat();
    assert_eq!(
        decode(&bad),
        Err(RtrDecodeError::BadPrefix {
            pdu: "IPv6 Prefix",
            reason: "max length exceeds the address family width"
        })
    );
}

#[test]
fn masks_host_bits_on_decode() {
    // The cache sends 192.0.2.128/24 — host bits set inside a
    // /24. BIRD normalizes with ipa_and(mask); so does the codec,
    // keeping the ROA table canonical.
    let wire = [
        &[1u8, 4u8, 0, 0][..],
        &u32b(20),
        &[1u8, 24, 24, 0],
        &[192, 0, 2, 128],
        &u32b(64512),
    ]
    .concat();
    let (_v, pdu, _) = decode(&wire).unwrap().unwrap();
    match pdu {
        RtrPdu::Ipv4Prefix { prefix, .. } => {
            assert_eq!(prefix, Prefix::new_v4([192, 0, 2, 0], 24));
        }
        _ => panic!("expected Ipv4Prefix"),
    }
}

#[test]
fn normalizes_reserved_flag_bits() {
    // §5.1: reserved flag bits MUST be ignored on receipt. Set
    // bit 7 together with the announce bit.
    let wire = [
        &[1u8, 4u8, 0, 0][..],
        &u32b(20),
        &[0x81u8, 24, 24, 0],
        &[192, 0, 2, 0],
        &u32b(64512),
    ]
    .concat();
    let (_v, pdu, _) = decode(&wire).unwrap().unwrap();
    match pdu {
        RtrPdu::Ipv4Prefix { announce, .. } => assert!(announce),
        _ => panic!("expected Ipv4Prefix"),
    }
}

#[test]
fn withdrawal_prefix_decodes() {
    // Flags=0: withdrawal of the {prefix, len, max-len, asn} tuple.
    let wire = [
        &[1u8, 4u8, 0, 0][..],
        &u32b(20),
        &[0u8, 24, 24, 0],
        &[192, 0, 2, 0],
        &u32b(64512),
    ]
    .concat();
    let (_v, pdu, _) = decode(&wire).unwrap().unwrap();
    match pdu {
        RtrPdu::Ipv4Prefix { announce, .. } => assert!(!announce),
        _ => panic!("expected Ipv4Prefix"),
    }
}

#[test]
fn rejects_aspa_partial_provider() {
    // Body has 5 bytes after the customer ASN — not a whole
    // number of providers.
    let wire = [
        &[2u8, 11u8, 1, 0][..],
        &u32b(17),
        &u32b(64496),
        &[0, 0, 0, 1, 0x55],
    ]
    .concat();
    assert_eq!(decode(&wire), Err(RtrDecodeError::BadAspaLength { len: 5 }));
}

#[test]
fn rejects_error_report_overrun() {
    // enc_len claims 40 bytes but the PDU has none.
    let wire = [
        &[1u8, 10u8][..],
        &0u16.to_be_bytes(),
        &u32b(16),
        &u32b(40),
        &[0, 0, 0, 0, 0, 0, 0, 0][..],
    ]
    .concat();
    assert_eq!(
        decode(&wire),
        Err(RtrDecodeError::BadErrorReport {
            reason: "encapsulated PDU length overruns the PDU"
        })
    );
}

#[test]
fn rejects_error_report_text_mismatch() {
    // text_len claims 4 but only 3 bytes follow.
    let wire = [
        &[1u8, 10u8][..],
        &0u16.to_be_bytes(),
        &u32b(19),
        &u32b(0),
        &[0, 0, 0, 0][..],
        &u32b(4),
        &[0x61, 0x62, 0x63][..],
    ]
    .concat();
    assert_eq!(
        decode(&wire),
        Err(RtrDecodeError::BadErrorReport {
            reason: "error text length does not match the PDU"
        })
    );
}

#[test]
fn error_code_classification() {
    assert!(RtrErrorCode::CorruptData.is_fatal());
    assert!(RtrErrorCode::InternalError.is_fatal());
    assert!(!RtrErrorCode::NoDataAvailable.is_fatal());
    assert_eq!(RtrErrorCode::DuplicateAnnouncementReceived as u16, 7);
    assert_eq!(
        RtrErrorCode::UnexpectedProtocolVersion.name(),
        "Unexpected Protocol Version"
    );
}

#[test]
fn pdu_type_metadata() {
    assert_eq!(RtrPduType::Ipv4Prefix.name(), "IPv4 Prefix");
    assert_eq!(RtrPduType::EndOfData.min_len(), 12);
    assert_eq!(RtrPduType::RouterKey.min_len(), 32);
    assert_eq!(
        RtrPdu::Aspa {
            announce: true,
            customer_asn: 1,
            providers: vec![]
        }
        .min_version(),
        RTR_VERSION_2
    );
    assert_eq!(
        RtrPdu::RouterKey {
            announce: true,
            ski: [0; 20],
            asn: 1,
            subject_public_key_info: vec![]
        }
        .min_version(),
        RTR_VERSION_1
    );
    assert_eq!(RtrPdu::ResetQuery.min_version(), RTR_VERSION_0);
}
