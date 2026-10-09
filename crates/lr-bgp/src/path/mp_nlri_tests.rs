
use super::*;

#[test]
fn mp_reach_ipv6_roundtrip() {
    let mp = MpReach::new(
        NlriFamily::IPV6_UNICAST,
        MpNextHop::V6Global([0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]),
        vec![Nlri::plain(Prefix::new_v6(
            [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            64,
        ))],
    );
    let enc = mp.encode();
    let dec = MpReach::decode(&enc).unwrap();
    assert_eq!(dec, mp);
}

#[test]
fn mp_unreach_roundtrip() {
    let mp = MpUnreach::new(
        NlriFamily::IPV6_UNICAST,
        vec![
            Nlri::plain(Prefix::new_v6(
                [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                64,
            )),
            Nlri::plain(Prefix::new_v6(
                [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0],
                65,
            )),
        ],
    );
    let enc = mp.encode();
    let dec = MpUnreach::decode(&enc).unwrap();
    assert_eq!(dec, mp);
}

/// RFC 7911 §4.3: with Add-Path negotiated every NLRI entry carries a
/// 4-octet path identifier ahead of the prefix, and the encoding
/// roundtrips. Without Add-Path the identifier is absent.
#[test]
fn mp_reach_add_path_roundtrip() {
    let mp = MpReach::new(
        NlriFamily::IPV6_UNICAST,
        MpNextHop::V6Global([0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]),
        vec![
            Nlri::new(
                7,
                Prefix::new_v6(
                    [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                    64,
                ),
            ),
            Nlri::new(
                9,
                Prefix::new_v6(
                    [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0],
                    64,
                ),
            ),
        ],
    );
    let enc = mp.encode_ex(true);
    let dec = MpReach::decode_ex(&enc, true).unwrap();
    assert_eq!(dec, mp);
    // Each entry grew by exactly the 4 identifier octets.
    assert_eq!(enc.len(), mp.encode_ex(false).len() + 8);
    // Decoding without the flag misparses — negotiated state must match.
    assert!(MpReach::decode_ex(&enc, false).is_none());
}

#[test]
fn mp_unreach_add_path_roundtrip() {
    let mp = MpUnreach::new(
        NlriFamily::IPV4_UNICAST,
        vec![
            Nlri::new(1, Prefix::new_v4([203, 0, 113, 0], 24)),
            Nlri::new(2, Prefix::new_v4([198, 51, 100, 0], 24)),
        ],
    );
    let enc = mp.encode_ex(true);
    let dec = MpUnreach::decode_ex(&enc, true).unwrap();
    assert_eq!(dec, mp);
}

/// RFC 5549: MP_REACH_NLRI for IPv4 unicast (AFI=1, SAFI=1) with a
/// 16-byte IPv6 next-hop. The peer must have advertised the Extended
/// Next-Hop capability for `(1, 1, 2)` — that is enforced by the FSM,
/// not the codec, but the codec must round-trip the wire form.
#[test]
fn mp_reach_ipv4_over_ipv6_roundtrip() {
    let mp = MpReach::new(
        NlriFamily::IPV4_UNICAST,
        MpNextHop::V4OverV6([0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]),
        vec![Nlri::plain(Prefix::new_v4([203, 0, 113, 0], 24))],
    );
    let enc = mp.encode();
    let dec = MpReach::decode(&enc).unwrap();
    assert_eq!(dec, mp);
    // The next-hop field is exactly 16 bytes on the wire.
    assert_eq!(enc[3], 16, "next-hop length byte");
}

/// A 32-byte next-hop on AFI=1 is rejected — RFC 5549 only defines a
/// 16-byte (single IPv6) form for IPv4-over-IPv6. The 32-byte global
/// + link-local pair is only valid for IPv6 NLRI (RFC 2545).
#[test]
fn mp_reach_ipv4_with_32_byte_next_hop_is_rejected() {
    let g = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
    let l = [0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
    let mut enc = vec![0x00, 0x01, 0x01, 32];
    enc.extend_from_slice(&g);
    enc.extend_from_slice(&l);
    enc.push(0); // reserved
    enc.push(24); // prefix length
    enc.extend_from_slice(&[203, 0, 113]);
    assert!(MpReach::decode(&enc).is_none());
}
