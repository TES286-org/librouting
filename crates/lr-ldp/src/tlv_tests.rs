
use super::*;

#[test]
fn label_validity() {
    assert!(GenericLabel::IMPLICIT_NULL.is_valid());
    assert!(GenericLabel(0x000f_ffff).is_valid());
    assert!(!GenericLabel(0x0010_0000).is_valid());
}

#[test]
fn status_code_bits() {
    let fatal = StatusCode::fatal(0x0000_0014); // KeepAlive Timer Expired
    assert!(fatal.is_fatal());
    assert_eq!(fatal.data(), 0x14);
    assert_eq!(fatal, StatusCode::KEEPALIVE_TIMER_EXPIRED);
    assert!(!StatusCode::LOOP_DETECTED.is_fatal());
}

#[test]
fn fec_element_lengths() {
    let p24 = FecElement::Prefix(Prefix::new_v4([10, 1, 2, 3], 24));
    assert_eq!(p24.encoded_len(), 4 + 3);
    let p0 = FecElement::Prefix(Prefix::new_v4([0, 0, 0, 0], 0));
    assert_eq!(p0.encoded_len(), 4);
    let w = FecElement::Wildcard;
    assert_eq!(w.encoded_len(), 1);
    let v6 = FecElement::Prefix(Prefix::new_v6(
        [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        32,
    ));
    assert_eq!(v6.encoded_len(), 4 + 4);
}

#[test]
fn fec_element_prefix_decode_exact_framing() {
    // 10.1.2.0/24 -> type 0x02, AF 1, prelen 24, 3 prefix bytes.
    let mut buf = [0u8; 8];
    buf[0] = 0x02;
    buf[1] = 0x00;
    buf[2] = 0x01;
    buf[3] = 24;
    buf[4] = 10;
    buf[5] = 1;
    buf[6] = 2;
    let mut off = 0;
    let el = FecElement::decode(&buf, &mut off).unwrap();
    assert_eq!(off, 7);
    assert_eq!(el, FecElement::Prefix(Prefix::new_v4([10, 1, 2, 0], 24)));
}

#[test]
fn fec_element_prefix_decode_rejects_bad_family() {
    let mut buf = [0u8; 8];
    buf[0] = 0x02;
    buf[1] = 0x00;
    buf[2] = 0x63; // 99 - unassigned AF
    buf[3] = 24;
    let mut off = 0;
    let err = FecElement::decode(&buf, &mut off).unwrap_err();
    assert_eq!(err.kind, ErrorKind::Unsupported);
}

#[test]
fn fec_element_prefix_decode_rejects_bad_prelen() {
    let mut buf = [0u8; 8];
    buf[0] = 0x02;
    buf[1] = 0x00;
    buf[2] = 0x01;
    buf[3] = 33; // > 32 for IPv4
    let mut off = 0;
    let err = FecElement::decode(&buf, &mut off).unwrap_err();
    assert_eq!(err.kind, ErrorKind::InvalidValue);
}

#[test]
fn fec_element_truncated() {
    let buf = [0x02, 0x00, 0x01, 24, 10, 1]; // missing a prefix byte
    let mut off = 0;
    let err = FecElement::decode(&buf, &mut off).unwrap_err();
    assert_eq!(err.kind, ErrorKind::Truncated);
}

#[test]
fn fec_element_unknown_type() {
    let buf = [0x63];
    let mut off = 0;
    let err = FecElement::decode(&buf, &mut off).unwrap_err();
    assert_eq!(err.kind, ErrorKind::UnknownType);
}

#[test]
fn session_params_default_shape() {
    let p = SessionParams::default();
    assert_eq!(p.protocol_version, 1);
    assert_eq!(p.receiver, LdpId::default());
    assert_eq!(p.max_pdu_len, 4096);
}

#[test]
fn dual_stack_capability_roundtrip() {
    // RFC 7552 §6.1.1 Figure 5: value = TR in the top nibble, the
    // rest zero; LDPoIPv6 is the default (0110).
    let v6 = DualStackCapability {
        preference: TransportPreference::Ipv6,
    };
    let mut buf = Vec::new();
    v6.encode_value(&mut buf);
    assert_eq!(buf, [0x60, 0, 0, 0]);
    let back = DualStackCapability::decode_value(&buf).unwrap();
    assert_eq!(back, v6);

    let v4 = DualStackCapability {
        preference: TransportPreference::Ipv4,
    };
    let mut buf = Vec::new();
    v4.encode_value(&mut buf);
    assert_eq!(buf, [0x40, 0, 0, 0]);
    assert_eq!(DualStackCapability::decode_value(&buf).unwrap(), v4);
}

#[test]
fn dual_stack_capability_rejects_unknown_tr() {
    // TR=0101 is not one of the two defined values: the LSR MUST
    // discard the Hello, so the parse must fail.
    let err = DualStackCapability::decode_value(&[0x50, 0, 0, 0]).unwrap_err();
    assert_eq!(err.kind, ErrorKind::InvalidValue);
    // Short value: same fate.
    assert!(DualStackCapability::decode_value(&[0x60, 0]).is_err());
}

#[test]
fn transport_preference_defaults_to_ipv6() {
    // RFC 7552 §6.1.1: "The default preference is LDPoIPv6".
    assert_eq!(
        TransportPreference::default_preference(),
        TransportPreference::Ipv6
    );
}

#[test]
fn rfc7552_status_codes() {
    // §6.1.1: both are sent as fatal notifications.
    assert!(StatusCode::TRANSPORT_CONNECTION_MISMATCH.is_fatal());
    assert_eq!(StatusCode::TRANSPORT_CONNECTION_MISMATCH.data(), 0x32);
    assert!(StatusCode::DUAL_STACK_NONCOMPLIANCE.is_fatal());
    assert_eq!(StatusCode::DUAL_STACK_NONCOMPLIANCE.data(), 0x33);
}
