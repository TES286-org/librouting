
use super::*;
use crate::pdu::DEFAULT_MAX_PDU_LEN;
use crate::tlv::{FecElement, StatusCode};
use crate::AdvertisementMode;
use lr_core::addr::Prefix;

#[test]
fn init_ft_session_tlv_roundtrip() {
    let pdu = LdpPdu {
        version: 1,
        sender: LdpId::new([1, 0, 0, 1], 0),
        messages: vec![LdpMessage::Initialization(InitMsg {
            message_id: 7,
            params: SessionParams {
                protocol_version: 1,
                keepalive_time: 15,
                advertisement: AdvertisementMode::DownstreamUnsolicited,
                loop_detection: false,
                path_vector_limit: 0,
                max_pdu_len: 4096,
                receiver: LdpId::new([2, 0, 0, 1], 0),
            },
            ft_session: Some(crate::tlv::FtSessionParams {
                reconnect_ms: 15000,
                recovery_ms: 120000,
            }),
            unknown_tlvs: Vec::new(),
        })],
    };
    let decoded = roundtrip(&pdu);
    match &decoded.messages[0] {
        LdpMessage::Initialization(init) => {
            assert_eq!(
                init.ft_session,
                Some(crate::tlv::FtSessionParams {
                    reconnect_ms: 15000,
                    recovery_ms: 120000,
                })
            );
        }
        other => panic!("wrong message: {other:?}"),
    }
}

fn roundtrip(pdu: &LdpPdu) -> LdpPdu {
    let mut buf = [0u8; 4096];
    let mut w = WriteBuf::new(&mut buf);
    let n = LdpCodec.encode(pdu, &mut w).unwrap();
    let mut r = ReadBuf::new(&w.written()[..n]);
    LdpCodec.decode(&mut r).unwrap().unwrap()
}

fn sample_id(v: u8) -> LdpId {
    LdpId::new([v, 0, 0, 1], 0)
}

#[test]
fn keepalive_pdu_roundtrip() {
    let pdu = LdpPdu {
        version: 1,
        sender: sample_id(1),
        messages: vec![LdpMessage::KeepAlive(KeepAliveMsg { message_id: 7 })],
    };
    let out = roundtrip(&pdu);
    assert_eq!(out.sender, sample_id(1));
    assert_eq!(out.messages.len(), 1);
    assert!(matches!(
        out.messages[0],
        LdpMessage::KeepAlive(KeepAliveMsg { message_id: 7 })
    ));
}

#[test]
fn hello_pdu_roundtrip() {
    let pdu = LdpPdu {
        version: 1,
        sender: sample_id(2),
        messages: vec![LdpMessage::Hello(HelloMsg {
            message_id: 1,
            params: HelloParams {
                hold_time: 45,
                targeted: true,
                request_targeted: true,
            },
            transport_addr: Some(TransportAddress(lr_core::addr::IpAddr::V4([192, 0, 2, 9]))),
            transport_addr_v6: None,
            config_seq: Some(ConfigSequenceNumber(42)),
            dual_stack: None,
            unknown_tlvs: vec![],
        })],
    };
    let out = roundtrip(&pdu);
    match &out.messages[0] {
        LdpMessage::Hello(h) => {
            assert_eq!(
                h.params,
                HelloParams {
                    hold_time: 45,
                    targeted: true,
                    request_targeted: true
                }
            );
            assert_eq!(
                h.transport_addr,
                Some(TransportAddress(lr_core::addr::IpAddr::V4([192, 0, 2, 9])))
            );
            assert_eq!(h.config_seq, Some(ConfigSequenceNumber(42)));
        }
        other => panic!("wrong message {other:?}"),
    }
}

#[test]
fn init_pdu_roundtrip() {
    let params = SessionParams {
        protocol_version: 1,
        keepalive_time: 15,
        advertisement: AdvertisementMode::DownstreamUnsolicited,
        loop_detection: false,
        path_vector_limit: 0,
        max_pdu_len: DEFAULT_MAX_PDU_LEN,
        receiver: sample_id(3),
    };
    let pdu = LdpPdu {
        version: 1,
        sender: sample_id(4),
        messages: vec![LdpMessage::Initialization(InitMsg {
            message_id: 5,
            params,
            ft_session: None,
            unknown_tlvs: vec![],
        })],
    };
    let out = roundtrip(&pdu);
    match &out.messages[0] {
        LdpMessage::Initialization(i) => assert_eq!(i.params, params),
        other => panic!("wrong message {other:?}"),
    }
}

#[test]
fn label_messages_roundtrip() {
    let fec = Fec::prefix(Prefix::new_v4([10, 0, 0, 0], 8));
    let pdu = LdpPdu {
        version: 1,
        sender: sample_id(5),
        messages: vec![
            LdpMessage::LabelMapping(LabelMappingMsg {
                message_id: 1,
                fec: fec.clone(),
                label: GenericLabel(100),
                hop_count: Some(HopCount(1)),
                path_vector: None,
                request_message_id: None,
                unknown_tlvs: vec![],
            }),
            LdpMessage::LabelRequest(LabelRequestMsg {
                message_id: 2,
                fec: fec.clone(),
                hop_count: Some(HopCount(1)),
                path_vector: Some(PathVector(Vec::from([0x0a00_0001]))),
                unknown_tlvs: vec![],
            }),
            LdpMessage::LabelWithdraw(LabelWithdrawMsg {
                message_id: 3,
                fec: fec.clone(),
                label: Some(GenericLabel(100)),
                unknown_tlvs: vec![],
            }),
            LdpMessage::LabelRelease(LabelReleaseMsg {
                message_id: 4,
                fec,
                label: None,
                status: None,
                unknown_tlvs: vec![],
            }),
            LdpMessage::LabelAbortRequest(LabelAbortMsg {
                message_id: 5,
                fec: Fec::prefix(Prefix::new_v4([10, 0, 0, 0], 8)),
                request_message_id: LabelRequestMessageId(2),
                unknown_tlvs: vec![],
            }),
        ],
    };
    let out = roundtrip(&pdu);
    assert_eq!(out.messages.len(), 5);
    match &out.messages[0] {
        LdpMessage::LabelMapping(m) => {
            assert_eq!(m.fec.single_prefix().map(|p| p.prefix_len), Some(8));
            assert_eq!(m.label, GenericLabel(100));
            assert_eq!(m.hop_count, Some(HopCount(1)));
        }
        other => panic!("wrong message {other:?}"),
    }
    match &out.messages[2] {
        LdpMessage::LabelWithdraw(m) => assert_eq!(m.label, Some(GenericLabel(100))),
        other => panic!("wrong message {other:?}"),
    }
    match &out.messages[3] {
        LdpMessage::LabelRelease(m) => assert_eq!(m.label, None),
        other => panic!("wrong message {other:?}"),
    }
}

#[test]
fn notification_and_unknown_roundtrip() {
    let pdu = LdpPdu {
        version: 1,
        sender: sample_id(6),
        messages: vec![
            LdpMessage::Notification(NotificationMsg {
                message_id: 1,
                status: Status {
                    code: StatusCode::fatal(0x0a),
                    message_id: 9,
                    message_type: MessageType::Initialization as u16,
                },
                unknown_tlvs: vec![],
            }),
            LdpMessage::Unknown(RawMessage {
                u_bit: true,
                msg_type: 0x1234,
                message_id: 2,
                tlvs: vec![RawTlv {
                    u_bit: true,
                    f_bit: false,
                    tlv_type: 0x5678,
                    value: Vec::from([1, 2, 3]),
                }],
            }),
        ],
    };
    let out = roundtrip(&pdu);
    match &out.messages[0] {
        LdpMessage::Notification(n) => {
            assert_eq!(n.status.code, StatusCode::fatal(0x0a));
            assert_eq!(n.status.message_type, 0x0200);
        }
        other => panic!("wrong message {other:?}"),
    }
    match &out.messages[1] {
        LdpMessage::Unknown(m) => {
            assert_eq!(m.msg_type, 0x1234);
            assert_eq!(m.tlvs.len(), 1);
            assert_eq!(m.tlvs[0].value, Vec::from([1, 2, 3]));
        }
        other => panic!("wrong message {other:?}"),
    }
}

#[test]
fn address_roundtrip() {
    let pdu = LdpPdu {
        version: 1,
        sender: sample_id(7),
        messages: vec![LdpMessage::Address(AddressMsg {
            message_id: 1,
            addresses: AddressList {
                addresses: Vec::from([
                    lr_core::addr::IpAddr::V4([192, 0, 2, 1]),
                    lr_core::addr::IpAddr::V4([192, 0, 2, 2]),
                ]),
            },
            unknown_tlvs: vec![],
        })],
    };
    let out = roundtrip(&pdu);
    match &out.messages[0] {
        LdpMessage::Address(a) => assert_eq!(a.addresses.addresses.len(), 2),
        other => panic!("wrong message {other:?}"),
    }
}

#[test]
fn truncated_pdu_returns_none() {
    let pdu = LdpPdu {
        version: 1,
        sender: sample_id(8),
        messages: vec![LdpMessage::KeepAlive(KeepAliveMsg { message_id: 1 })],
    };
    let mut buf = [0u8; 64];
    let mut w = WriteBuf::new(&mut buf);
    let n = LdpCodec.encode(&pdu, &mut w).unwrap();
    let bytes = &w.written()[..n];
    for cut in 0..n {
        let mut r = ReadBuf::new(&bytes[..cut]);
        assert!(LdpCodec.decode(&mut r).unwrap().is_none(), "cut at {cut}");
    }
    let mut r = ReadBuf::new(bytes);
    assert!(LdpCodec.decode(&mut r).unwrap().is_some());
}

#[test]
fn bad_version_rejected() {
    let mut buf = [0u8; 64];
    let mut w = WriteBuf::new(&mut buf);
    let pdu = LdpPdu {
        version: 1,
        sender: sample_id(9),
        messages: vec![LdpMessage::KeepAlive(KeepAliveMsg { message_id: 1 })],
    };
    let n = LdpCodec.encode(&pdu, &mut w).unwrap();
    let mut bytes = Vec::from(&w.written()[..n]);
    bytes[0] = 0; // version 0x0002
    bytes[1] = 2;
    let mut r = ReadBuf::new(&bytes);
    let err = LdpCodec.decode(&mut r).unwrap_err();
    assert_eq!(err.kind, ErrorKind::InvalidValue);
}

#[test]
fn pdu_boundary_enforced() {
    // A message that claims to extend past the PDU boundary must be
    // rejected rather than consuming into whatever follows.
    // Hand-build: PDU with pdu_len = 16 (6 id + 10 message area),
    // but the inner message claims a 100-octet body.
    let mut bytes: Vec<u8> = Vec::new();
    bytes.extend_from_slice(&1u16.to_be_bytes()); // version
    bytes.extend_from_slice(&16u16.to_be_bytes()); // PDU length
    bytes.extend_from_slice(&[10, 0, 0, 1, 0, 0]); // LDP Id
                                                   // Message: KeepAlive type, msg_len = 100 (id + 96 octets).
    bytes.extend_from_slice(&0x0201u16.to_be_bytes());
    bytes.extend_from_slice(&100u16.to_be_bytes());
    bytes.extend_from_slice(&1u32.to_be_bytes()); // message id
    bytes.extend_from_slice(&[0u8; 96]);
    let mut r = ReadBuf::new(&bytes);
    let err = LdpCodec.decode(&mut r).unwrap_err();
    assert_eq!(err.kind, ErrorKind::BadLength);
}

#[test]
fn hello_without_params_rejected() {
    // Hand-build a Hello with only a Message ID.
    let mut body: Vec<u8> = Vec::new();
    body.extend_from_slice(&0x0100u16.to_be_bytes());
    body.extend_from_slice(&4u16.to_be_bytes());
    body.extend_from_slice(&1u32.to_be_bytes());
    let mut pdu_bytes: Vec<u8> = Vec::new();
    pdu_bytes.extend_from_slice(&1u16.to_be_bytes());
    pdu_bytes.extend_from_slice(&(6 + body.len() as u16).to_be_bytes());
    pdu_bytes.extend_from_slice(&[10, 0, 0, 1, 0, 0]);
    pdu_bytes.extend_from_slice(&body);
    let mut r = ReadBuf::new(&pdu_bytes);
    let err = LdpCodec.decode(&mut r).unwrap_err();
    assert_eq!(err.kind, ErrorKind::BadLength);
}

#[test]
fn wildcard_fec_roundtrip() {
    let pdu = LdpPdu {
        version: 1,
        sender: sample_id(11),
        messages: vec![LdpMessage::LabelWithdraw(LabelWithdrawMsg {
            message_id: 1,
            fec: Fec::wildcard(),
            label: Some(GenericLabel(200)),
            unknown_tlvs: vec![],
        })],
    };
    let out = roundtrip(&pdu);
    match &out.messages[0] {
        LdpMessage::LabelWithdraw(m) => {
            assert!(m.fec.is_wildcard());
            assert_eq!(m.label, Some(GenericLabel(200)));
        }
        other => panic!("wrong message {other:?}"),
    }
}

#[test]
fn ipv6_prefix_and_transport_roundtrip() {
    let pdu = LdpPdu {
        version: 1,
        sender: sample_id(12),
        messages: vec![LdpMessage::Hello(HelloMsg {
            message_id: 1,
            params: HelloParams {
                hold_time: 45,
                targeted: true,
                request_targeted: false,
            },
            transport_addr: None,
            transport_addr_v6: Some(TransportAddress(lr_core::addr::IpAddr::V6([
                0x20, 0x01, 0xd, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
            ]))),
            config_seq: None,
            dual_stack: None,
            unknown_tlvs: vec![],
        })],
    };
    let out = roundtrip(&pdu);
    match &out.messages[0] {
        LdpMessage::Hello(h) => match h.transport_addr_v6 {
            Some(TransportAddress(lr_core::addr::IpAddr::V6(b))) => {
                assert_eq!(b[0], 0x20);
                assert_eq!(b[15], 1);
            }
            other => panic!("wrong transport addr {other:?}"),
        },
        other => panic!("wrong message {other:?}"),
    }
}

#[test]
fn fec_element_unknown_aborts() {
    // A FEC TLV with an unknown element type must abort the message.
    let mut buf = [0u8; 128];
    let mut w = WriteBuf::new(&mut buf);
    // FEC TLV header
    w.put_u16_be(tlv_header_word(false, false, TlvType::Fec as u16))
        .unwrap();
    w.reserve(2).unwrap();
    w.put_u8(0x63).unwrap(); // unknown FEC element type
    let n = w.written().len();
    w.patch(2, &((n - 4) as u16).to_be_bytes()).unwrap();
    let fec_bytes = Vec::from(w.written());
    let err = Fec::decode_value(&fec_bytes[4..]);
    assert!(err.is_err());
    let _ = FecElement::Wildcard; // silence unused when feature-gated
}

#[test]
fn label_release_with_loop_detected_status_roundtrip() {
    // RFC 5036 §3.4.5.1.2 + §3.5.11.2: the Loop Detected release
    // carries a Status TLV referencing the rejected Label Mapping.
    let pdu = LdpPdu {
        version: 1,
        sender: sample_id(3),
        messages: vec![LdpMessage::LabelRelease(LabelReleaseMsg {
            message_id: 42,
            fec: Fec::prefix(Prefix::new_v4([10, 40, 0, 0], 24)),
            label: Some(GenericLabel(301)),
            status: Some(Status {
                code: StatusCode::LOOP_DETECTED,
                message_id: 77,
                message_type: MessageType::LabelMapping as u16,
            }),
            unknown_tlvs: vec![],
        })],
    };
    let out = roundtrip(&pdu);
    match &out.messages[0] {
        LdpMessage::LabelRelease(rel) => {
            assert_eq!(rel.message_id, 42);
            assert_eq!(rel.label, Some(GenericLabel(301)));
            let st = rel
                .status
                .expect("the Status TLV must survive the roundtrip");
            assert_eq!(st.code, StatusCode::LOOP_DETECTED);
            assert!(!st.code.is_fatal(), "Loop Detected is E=0");
            assert_eq!(st.message_id, 77);
            assert_eq!(st.message_type, MessageType::LabelMapping as u16);
        }
        other => panic!("expected a Label Release, got {other:?}"),
    }
}
