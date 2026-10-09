use super::*;

#[test]
fn ipv4_single_label_roundtrip() {
    // 3-octet NLRI form does not carry TTL — decode produces TTL=0.
    let entry = LabeledNlri::new(
        LabelStack::from_labels([Label::new_value(100)]),
        Prefix::new_v4([203, 0, 113, 0], 24),
    );
    let enc = entry.encode(false).unwrap();
    // 1 length octet + 3 label octets + 3 prefix octets = 7
    assert_eq!(enc.len(), 7);
    // Length = 24 (label) + 24 (prefix) = 48
    assert_eq!(enc[0], 48);
    // Last label octet has the S bit set.
    assert_eq!(enc[3] & 0x01, 1);
    let (dec, consumed) =
        LabeledNlri::decode(NlriFamily::IPV4_LABELED_UNICAST, &enc, false).unwrap();
    assert_eq!(dec, entry);
    assert_eq!(consumed, enc.len());
}

#[test]
fn ipv4_two_label_roundtrip() {
    // 3-octet NLRI form does not carry TTL — decode produces TTL=0.
    let entry = LabeledNlri::new(
        LabelStack::from_labels([Label::new_value(100), Label::new_value(200)]),
        Prefix::new_v4([203, 0, 113, 0], 24),
    );
    let enc = entry.encode(false).unwrap();
    // 1 + 6 + 3 = 10
    assert_eq!(enc.len(), 10);
    // Length = 48 (labels) + 24 (prefix) = 72
    assert_eq!(enc[0], 72);
    // First label: no S bit. Last label: S bit set.
    assert_eq!(enc[3] & 0x01, 0);
    assert_eq!(enc[6] & 0x01, 1);
    let (dec, _) = LabeledNlri::decode(NlriFamily::IPV4_LABELED_UNICAST, &enc, false).unwrap();
    assert_eq!(dec, entry);
}

#[test]
fn ipv6_single_label_roundtrip() {
    // 3-octet NLRI form does not carry TTL — decode produces TTL=0.
    let entry = LabeledNlri::new(
        LabelStack::from_labels([Label::new_value(240)]),
        Prefix::new_v6(
            [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            64,
        ),
    );
    let enc = entry.encode(false).unwrap();
    // 1 + 3 + 8 = 12
    assert_eq!(enc.len(), 12);
    // Length = 24 + 64 = 88
    assert_eq!(enc[0], 88);
    let (dec, _) = LabeledNlri::decode(NlriFamily::IPV6_LABELED_UNICAST, &enc, false).unwrap();
    assert_eq!(dec, entry);
}

#[test]
fn add_path_roundtrip() {
    // 3-octet NLRI form does not carry TTL — decode produces TTL=0.
    let entry = LabeledNlri::with_path_id(
        0xdeadbeef,
        LabelStack::from_labels([Label::new_value(16)]),
        Prefix::new_v4([10, 0, 0, 0], 8),
    );
    let enc = entry.encode(true).unwrap();
    // 4 (path-id) + 1 (length) + 3 (label) + 1 (prefix) = 9
    assert_eq!(enc.len(), 9);
    // path-id is the first 4 bytes
    assert_eq!(&enc[..4], &0xdeadbeefu32.to_be_bytes());
    // Length = 24 + 8 = 32
    assert_eq!(enc[4], 32);
    let (dec, _) = LabeledNlri::decode(NlriFamily::IPV4_LABELED_UNICAST, &enc, true).unwrap();
    assert_eq!(dec, entry);
}

#[test]
fn list_roundtrip() {
    // 3-octet NLRI form does not carry TTL — decode produces TTL=0.
    let entries = vec![
        LabeledNlri::new(
            LabelStack::from_labels([Label::new_value(16)]),
            Prefix::new_v4([10, 0, 0, 0], 8),
        ),
        LabeledNlri::new(
            LabelStack::from_labels([Label::new_value(17), Label::new_value(18)]),
            Prefix::new_v4([192, 0, 2, 0], 24),
        ),
    ];
    let enc = encode_list(&entries, false);
    let dec = decode_list(NlriFamily::IPV4_LABELED_UNICAST, &enc, false).unwrap();
    assert_eq!(dec, entries);
}

#[test]
fn empty_label_stack_is_rejected() {
    let entry = LabeledNlri::new(LabelStack::new(), Prefix::new_v4([10, 0, 0, 0], 8));
    assert!(entry.encode(false).is_none());
}

#[test]
fn decode_rejects_missing_s_bit() {
    // total_bits = 24, so the body holds exactly one label (3 octets).
    // With the S bit cleared and no room for a second label, the input
    // is malformed and must be rejected.
    let bytes = vec![24u8, 0, 1, 0];
    assert!(LabeledNlri::decode(NlriFamily::IPV4_LABELED_UNICAST, &bytes, false).is_none());
}

#[test]
fn decode_rejects_short_input() {
    // 0 length octet but no body — fine if length is 0; but length > 0
    // with insufficient body bytes must be rejected.
    let bytes = vec![48u8, 0, 1]; // claims 6 bytes of body, only 2 present
    assert!(LabeledNlri::decode(NlriFamily::IPV4_LABELED_UNICAST, &bytes, false).is_none());
}

#[test]
fn default_route_ipv4() {
    // RFC 8277 §3.2: the default route (0.0.0.0/0) with one label has
    // Length = 24 (24 label bits + 0 prefix bits = 24).
    // 3-octet NLRI form does not carry TTL — decode produces TTL=0.
    let entry = LabeledNlri::new(
        LabelStack::from_labels([Label::new_value(100)]),
        Prefix::new_v4([0, 0, 0, 0], 0),
    );
    let enc = entry.encode(false).unwrap();
    // 1 + 3 + 0 = 4 octets total
    assert_eq!(enc.len(), 4);
    assert_eq!(enc[0], 24);
    let (dec, _) = LabeledNlri::decode(NlriFamily::IPV4_LABELED_UNICAST, &enc, false).unwrap();
    assert_eq!(dec, entry);
}

#[test]
fn implicit_null_round_trips() {
    // 3-octet NLRI form does not carry TTL — decode produces TTL=0,
    // and ipv4_implicit_null uses new_value semantics already.
    let entry = ipv4_implicit_null(Prefix::new_v4([10, 0, 0, 0], 8));
    let enc = entry.encode(false).unwrap();
    let (dec, _) = LabeledNlri::decode(NlriFamily::IPV4_LABELED_UNICAST, &enc, false).unwrap();
    assert_eq!(
        dec.label_stack.labels()[0].value,
        Label::IMPLICIT_NULL.value
    );
    assert_eq!(dec.prefix, entry.prefix);
    assert_eq!(dec, entry);
}

#[test]
fn mp_reach_ipv4_labelled_roundtrip() {
    let family = NlriFamily::IPV4_LABELED_UNICAST;
    let nh = MpNextHop::V4([192, 0, 2, 1]);
    let entries = vec![LabeledNlri::new(
        LabelStack::from_labels([Label::new_value(100)]),
        Prefix::new_v4([203, 0, 113, 0], 24),
    )];
    let enc = encode_mp_reach(family, &nh, &entries, false);
    let (dec_fam, dec_nh, dec_entries) = decode_mp_reach(&enc, false).unwrap();
    assert_eq!(dec_fam, family);
    assert_eq!(dec_nh, nh);
    assert_eq!(dec_entries, entries);
}

#[test]
fn mp_unreach_ipv4_labelled_roundtrip() {
    let family = NlriFamily::IPV4_LABELED_UNICAST;
    let entries = vec![
        LabeledNlri::new(
            LabelStack::from_labels([Label::new_value(100)]),
            Prefix::new_v4([203, 0, 113, 0], 24),
        ),
        LabeledNlri::new(
            LabelStack::from_labels([Label::new_value(200)]),
            Prefix::new_v4([198, 51, 100, 0], 24),
        ),
    ];
    let enc = encode_mp_unreach(family, &entries, false);
    let (dec_fam, dec_entries) = decode_mp_unreach(&enc, false).unwrap();
    assert_eq!(dec_fam, family);
    assert_eq!(dec_entries, entries);
}

#[test]
fn mp_reach_rejects_non_labelled_family() {
    // A plain IPv4-unicast MP_REACH value should be rejected by the
    // labelled decoder.
    let family = NlriFamily::IPV4_UNICAST;
    let nh = MpNextHop::V4([192, 0, 2, 1]);
    let enc = encode_mp_reach(family, &nh, &[], false);
    assert!(decode_mp_reach(&enc, false).is_none());
}
