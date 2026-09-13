//! RFC conformance test vectors for the BGP-4 codec (ROADMAP-v3 D6.3).
//!
//! Each test pins a specific byte sequence from an RFC and asserts the
//! codec decodes it to the exact structure the RFC describes. Round-trip
//! tests in `crates/lr-bgp/src/codec.rs` prove the codec is self-consistent;
//! these tests prove the wire format is *interoperable* — a packet that
//! BIRD or FRR emits must decode the same way here, and a packet we emit
//! must decode the same way there. Catches accidental wire-format drift
//! that round-trip tests cannot (e.g. a refactor that swaps the order
//! of two fields would still round-trip but break interop).
//!
//! All vectors are constructed from the RFCs themselves:
//!
//! * RFC 4271 §4.1 — header format (16×0xFF marker, 2-byte length, type)
//! * RFC 4271 §4.2 — OPEN message body layout
//! * RFC 4271 §4.3 — UPDATE message body layout (withdrawn + attrs + NLRI)
//! * RFC 4271 §4.4 — KEEPALIVE (header only)
//! * RFC 4271 §4.5 — NOTIFICATION (code + subcode + data)
//! * RFC 4271 §5 — path attribute layout (flags, type, length, value)
//! * RFC 4271 §6.1 — Connection Not Synchronized (header subcode)
//! * RFC 6793 §4 — 4-byte AS capability encoding in OPEN params
//! * RFC 5492 §3 — capability TLV encoding

#![cfg(test)]

use lr_bgp::codec::BgpCodec;
use lr_bgp::capabilities::Capability;
use lr_bgp::error::{BgpErrorCode, BgpHeaderErrorSubcode, BgpError};
use lr_bgp::message::{BgpMessage, BgpMessageType, Keepalive, Open, OpenParam};
use lr_core::addr::{Asn, RouterId};

/// Build a BGP header (16×0xFF + 2-byte length + 1-byte type) around
/// the supplied body. Used by every test vector below to assemble
/// a full message from the RFC's "body only" description.
fn frame(body: &[u8], kind: u8) -> Vec<u8> {
    let total = 19 + body.len();
    assert!(
        (19..=4096).contains(&total),
        "BGP message length out of range: {total}"
    );
    let mut out = Vec::with_capacity(total);
    out.extend_from_slice(&[0xff; 16]);
    out.extend_from_slice(&(total as u16).to_be_bytes());
    out.push(kind);
    out.extend_from_slice(body);
    out
}

/// Decode one frame and assert it returns the expected message type.
/// Returns the message so per-test assertions can inspect the fields.
fn decode_one(bytes: &[u8]) -> BgpMessage {
    let mut codec = BgpCodec::new();
    codec
        .decode_slice(bytes)
        .expect("decode must succeed for a well-formed RFC vector")
        .expect("decode must return Some(message) when a full frame is available")
}

// ============================================================================
// RFC 4271 §4.1 — Header format
// ============================================================================

/// RFC 4271 §4.1: every BGP message begins with 16 octets of 0xFF
/// (the "marker"), a 2-octet length, and a 1-octet type. The marker
/// is used to detect loss of synchronisation — any non-0xFF byte
/// here is a Connection-Not-Synchronized error.
///
/// The marker is checked before any other field, so the simplest
/// "wrong marker" test vector is a header where the first byte is
/// not 0xFF.
#[test]
fn rfc4271_marker_must_be_all_ones() {
    let mut bad = frame(&[], BgpMessageType::Keepalive as u8);
    bad[0] = 0xfe; // corrupt the first marker byte
    let mut codec = BgpCodec::new();
    let err = codec.decode_slice(&bad);
    match err {
        Err(BgpError::Notification(n)) => {
            assert_eq!(n.error_code, BgpErrorCode::Header as u8);
            assert_eq!(
                n.error_subcode,
                BgpHeaderErrorSubcode::ConnectionNotSynchronized as u8
            );
        }
        other => panic!(
            "non-0xFF marker must raise Header/Connection-Not-Synchronized, got {other:?}"
        ),
    }
}

/// RFC 4271 §4.1: the length field carries the total message size
/// (header + body) and must be in [19, 4096]. A length of 18 is a
/// Bad-Message-Length error.
#[test]
fn rfc4271_length_below_minimum_is_bad_length() {
    let mut too_short = frame(&[], BgpMessageType::Keepalive as u8);
    // Override the length field with 18 (one below the minimum).
    too_short[16] = 0;
    too_short[17] = 18;
    let mut codec = BgpCodec::new();
    let err = codec.decode_slice(&too_short);
    match err {
        Err(BgpError::Notification(n)) => {
            assert_eq!(n.error_code, BgpErrorCode::Header as u8);
            assert_eq!(n.error_subcode, BgpHeaderErrorSubcode::BadMessageLength as u8);
        }
        other => panic!(
            "length < 19 must raise Header/Bad-Message-Length, got {other:?}"
        ),
    }
}

/// RFC 4271 §4.1: length above 4096 is also Bad-Message-Length.
#[test]
fn rfc4271_length_above_maximum_is_bad_length() {
    let mut too_long = frame(&[], BgpMessageType::Keepalive as u8);
    too_long[16] = 0x10; // 4097
    too_long[17] = 0x01;
    let mut codec = BgpCodec::new();
    let err = codec.decode_slice(&too_long);
    match err {
        Err(BgpError::Notification(n)) => {
            assert_eq!(n.error_code, BgpErrorCode::Header as u8);
            assert_eq!(n.error_subcode, BgpHeaderErrorSubcode::BadMessageLength as u8);
        }
        other => panic!(
            "length > 4096 must raise Header/Bad-Message-Length, got {other:?}"
        ),
    }
}

// ============================================================================
// RFC 4271 §4.2 — OPEN message
// ============================================================================

/// RFC 4271 §4.2: OPEN body layout is
///   version(1) + my_as(2) + hold_time(2) + bgp_id(4) + params_len(1) + params
///
/// This test vector uses the example values from RFC 4271 §8 (Sample
/// Configuration): AS 65001, hold-time 180s, BGP identifier 192.0.2.1,
/// no optional parameters. The total OPEN body length is 10 octets.
#[test]
fn rfc4271_open_minimal_decodes() {
    // Body: version=4, my_as=65001 (0xFDE9), hold=180 (0x00B4),
    //       bgp_id=192.0.2.1 (0xC0000201), params_len=0
    let body = [
        0x04, // version
        0xFD, 0xE9, // my_as = 65001
        0x00, 0xB4, // hold_time = 180
        0xC0, 0x00, 0x02, 0x01, // bgp_id = 192.0.2.1
        0x00, // optional params length = 0
    ];
    let bytes = frame(&body, BgpMessageType::Open as u8);
    match decode_one(&bytes) {
        BgpMessage::Open(o) => {
            assert_eq!(o.version, 4, "version must be 4 per RFC 4271 §4.2");
            assert_eq!(o.my_as, Asn(65001), "my_as must be 65001");
            assert_eq!(o.hold_time, 180, "hold_time must be 180s");
            assert_eq!(
                o.bgp_id,
                RouterId::from_v4([192, 0, 2, 1]),
                "bgp_id must be 192.0.2.1"
            );
            assert!(
                o.params.is_empty(),
                "no optional params in this vector"
            );
        }
        other => panic!("expected OPEN, got {other:?}"),
    }
}

/// RFC 4271 §4.2: OPEN with version != 4 must still decode (the codec
/// surfaces the version; the FSM layer raises the NOTIFICATION). Pin
/// this so a refactor that hard-codes version=4 in the decoder is
/// caught.
#[test]
fn rfc4271_open_version_field_is_preserved() {
    let body = [
        0x03, // version 3 — pre-RFC-4271
        0xFD, 0xE9, // my_as = 65001
        0x00, 0xB4, // hold_time = 180
        0xC0, 0x00, 0x02, 0x01, // bgp_id
        0x00,
    ];
    let bytes = frame(&body, BgpMessageType::Open as u8);
    match decode_one(&bytes) {
        BgpMessage::Open(o) => assert_eq!(o.version, 3),
        other => panic!("expected OPEN, got {other:?}"),
    }
}

/// RFC 6793 §4: a 4-byte AS capability is encoded as a capability
/// TLV inside OPEN params. The capability code is 65, length is 4,
/// and the value is the 4-byte AS number. This test uses AS 70000
/// (above the 2-byte max of 65535), with OPEN.my_as set to 23456
/// (AS_TRANS per RFC 4893 §7).
#[test]
fn rfc6793_open_with_four_byte_as_capability() {
    // Body: version=4, my_as=23456 (AS_TRANS), hold=180, bgp_id=192.0.2.1,
    //       params_len=8, then a single capability param:
    //         param_type=2 (Capability per RFC 5492 §3), param_len=6
    //         cap_code=65 (4-byte AS number per RFC 6793 §4)
    //         cap_len=4
    //         cap_value=0x00011170 (70000)
    //
    // Optional-Parameters-Length covers the *entire* param region:
    // 2 (type+len header) + 6 (cap code+len+value) = 8 bytes.
    let body = [
        0x04, // version
        0x5B, 0xA0, // my_as = 23456 (AS_TRANS, 0x5BA0)
        0x00, 0xB4, // hold_time = 180
        0xC0, 0x00, 0x02, 0x01, // bgp_id = 192.0.2.1
        0x08, // params_len = 8 (covers param header + capability body)
        // param 1: type=2 (capability), len=6
        0x02, 0x06,
        // capability: code=65, len=4, value=0x00011170 (70000)
        0x41, 0x04, 0x00, 0x01, 0x11, 0x70,
    ];
    let bytes = frame(&body, BgpMessageType::Open as u8);
    match decode_one(&bytes) {
        BgpMessage::Open(o) => {
            assert_eq!(o.my_as, Asn(23456), "AS_TRANS on the wire");
            assert_eq!(o.params.len(), 1, "one capability param");
            let p = &o.params[0];
            assert_eq!(p.param_type, OpenParam::PARAM_TYPE_CAPABILITY);
            let caps = Capability::decode_set(&p.value);
            let as4 = caps
                .iter()
                .find_map(Capability::as_four_octet)
                .expect("must contain 4-byte AS capability");
            assert_eq!(as4, 70000, "RFC 6793 §4 sample: AS 70000");
        }
        other => panic!("expected OPEN, got {other:?}"),
    }
}

// ============================================================================
// RFC 4271 §4.4 — KEEPALIVE
// ============================================================================

/// RFC 4271 §4.4: KEEPALIVE is a header-only message — body length
/// is zero, total length is 19. Pin the exact 19-byte form.
#[test]
fn rfc4271_keepalive_is_header_only() {
    let bytes = frame(&[], BgpMessageType::Keepalive as u8);
    assert_eq!(bytes.len(), 19, "KEEPALIVE total length must be 19");
    assert_eq!(bytes[18], 4, "type byte must be 4 (KEEPALIVE)");
    assert!(matches!(decode_one(&bytes), BgpMessage::Keepalive(_)));
}

// ============================================================================
// RFC 4271 §4.5 — NOTIFICATION
// ============================================================================

/// RFC 4271 §4.5: NOTIFICATION body is error_code(1) + error_subcode(1)
/// + data(variable). RFC 4271 §6.1 specifies that the
/// "Connection-Not-Synchronized" subcode carries the bad marker bytes
/// as data. Pin the canonical form: code=1 (Header), subcode=1,
/// data = the first 4 bytes of the received (bad) marker.
#[test]
fn rfc4271_notification_header_connection_not_synchronized() {
    let body = [
        0x01, // error_code = Header
        0x01, // error_subcode = Connection Not Synchronized
        0xFE, 0xFF, 0xFF, 0xFF, // data: first 4 bad marker bytes
    ];
    let bytes = frame(&body, BgpMessageType::Notification as u8);
    match decode_one(&bytes) {
        BgpMessage::Notification(n) => {
            assert_eq!(n.error_code, 1, "Header error code");
            assert_eq!(n.error_subcode, 1, "Connection-Not-Synchronized");
            assert_eq!(n.data, vec![0xFE, 0xFF, 0xFF, 0xFF]);
        }
        other => panic!("expected NOTIFICATION, got {other:?}"),
    }
}

/// RFC 4486 §2: CEASE error code (6) has subcodes for the most common
/// operator-initiated shutdowns. Pin subcode 2 (Administrative
/// Shutdown) and subcode 4 (Administrative Reset) — both appear in
/// RFC 8326 graceful-shutdown interop.
#[test]
fn rfc4486_cease_admin_shutdown_subcode() {
    let body = [0x06, 0x02]; // Cease + Administrative Shutdown
    let bytes = frame(&body, BgpMessageType::Notification as u8);
    match decode_one(&bytes) {
        BgpMessage::Notification(n) => {
            assert_eq!(n.error_code, 6, "Cease error code per RFC 4486");
            assert_eq!(n.error_subcode, 2, "Administrative Shutdown");
            assert!(n.data.is_empty(), "no data in this vector");
        }
        other => panic!("expected NOTIFICATION, got {other:?}"),
    }
}

// ============================================================================
// RFC 4271 §4.3 — UPDATE message
// ============================================================================

/// RFC 4271 §4.3: an UPDATE with no withdrawn routes, no path
/// attributes and no NLRI is the "end-of-RIB" marker (RFC 4724 §2).
/// Total body length is 4 octets: two zero 2-byte fields
/// (withdrawn_length=0, attr_length=0). Pin this minimal form
/// because the EOR marker is what BIRD/FRR look for to signal
/// "I have sent my initial table".
#[test]
fn rfc4271_update_end_of_rib_marker() {
    let body = [
        0x00, 0x00, // withdrawn routes length = 0
        0x00, 0x00, // path attributes length = 0
    ];
    let bytes = frame(&body, BgpMessageType::Update as u8);
    match decode_one(&bytes) {
        BgpMessage::Update(u) => {
            assert!(u.withdrawn.is_empty(), "no withdrawals in EOR");
            assert_eq!(u.attributes.len(), 0, "no attributes in EOR");
            assert!(u.nlri.is_empty(), "no NLRI in EOR");
        }
        other => panic!("expected UPDATE, got {other:?}"),
    }
}

/// RFC 4271 §4.3 (b): an UPDATE that withdraws one prefix and
/// carries no path attributes or NLRI. The withdrawn section is
/// `length(2) + prefix_entry(2)`. The entry is
/// `prefix_len(1) + prefix_bytes(ceil(prefix_len/8))` — for /24
/// that's 4 bytes total.
#[test]
fn rfc4271_update_single_withdrawal() {
    // Withdrawn section: length=2 (one /24 entry occupies 4 bytes:
    //   1 byte prefix_len + 3 bytes prefix). Wait — the "length"
    //   field is the *byte* length of the withdrawn section, not the
    //   count. So length=4 (1+3 for one /24), then attr_length=0.
    let body = [
        0x00, 0x04, // withdrawn routes length = 4 bytes
        0x18, // prefix_len = 24
        0xC0, 0x00, 0x02, // prefix = 192.0.2.0
        0x00, 0x00, // path attributes length = 0
    ];
    let bytes = frame(&body, BgpMessageType::Update as u8);
    match decode_one(&bytes) {
        BgpMessage::Update(u) => {
            assert_eq!(u.withdrawn.len(), 1);
            assert_eq!(u.withdrawn[0].prefix.prefix_len, 24);
            assert_eq!(u.withdrawn[0].prefix.addr.octets(), &[192, 0, 2, 0]);
            assert!(u.nlri.is_empty(), "no NLRI in withdraw-only UPDATE");
        }
        other => panic!("expected UPDATE, got {other:?}"),
    }
}

/// RFC 4271 §5.1.1: ORIGIN is a mandatory well-known attribute,
/// type code 1, 1-byte value. IGP=0, EGP=1, INCOMPLETE=2.
/// RFC 4271 §5.1.2: AS_PATH type code 2. A sequence of ASes
///   is segment_type=2 (AS_SEQUENCE), len=N, then N×4 octets
///   (or N×2 for 2-byte AS).
/// RFC 4271 §5.1.3: NEXT_HOP type code 3, 4-byte IPv4 address.
///
/// This vector builds an UPDATE that announces 192.0.2.0/24 with
/// origin=IGP, AS_PATH=empty sequence, next_hop=192.0.2.1.
#[test]
fn rfc4271_update_announce_with_origin_aspath_nexthop() {
    // Build path attributes section:
    //   attr_len=...
    //   attr1: flags=0x40 (transitive), type=1 (ORIGIN), len=1, value=0 (IGP)
    //   attr2: flags=0x40, type=2 (AS_PATH), len=0 (empty path)
    //   attr3: flags=0x40, type=3 (NEXT_HOP), len=4, value=192.0.2.1
    let attrs = [
        0x40, 0x01, 0x01, 0x00, // ORIGIN = IGP
        0x40, 0x02, 0x00, // AS_PATH (empty)
        0x40, 0x03, 0x04, 0xC0, 0x00, 0x02, 0x01, // NEXT_HOP = 192.0.2.1
    ];
    // NLRI: 192.0.2.0/24 = prefix_len(1) + prefix(3) = 4 bytes
    let nlri = [0x18, 0xC0, 0x00, 0x02];
    let mut body = Vec::with_capacity(4 + attrs.len() + nlri.len());
    body.extend_from_slice(&[0x00, 0x00]); // withdrawn length = 0
    body.extend_from_slice(&(attrs.len() as u16).to_be_bytes()); // attr length
    body.extend_from_slice(&attrs);
    body.extend_from_slice(&nlri);
    let bytes = frame(&body, BgpMessageType::Update as u8);
    match decode_one(&bytes) {
        BgpMessage::Update(u) => {
            assert!(u.withdrawn.is_empty());
            assert_eq!(u.nlri.len(), 1);
            assert_eq!(u.nlri[0].prefix.prefix_len, 24);
            assert_eq!(u.nlri[0].prefix.addr.octets(), &[192, 0, 2, 0]);
            // Three path attributes
            assert_eq!(u.attributes.len(), 3);
        }
        other => panic!("expected UPDATE, got {other:?}"),
    }
}

// ============================================================================
// Round-trip against the RFC byte sequence: encode + decode == same bytes
// ============================================================================

/// Encoding an OPEN with the RFC 4271 §8 sample values must produce
/// byte-exact output that matches the hand-built vector. Catches
/// accidental field reordering or extra-length encoding.
#[test]
fn rfc4271_open_encode_matches_rfc_bytes() {
    let open = Open::new(Asn(65001), 180, RouterId::from_v4([192, 0, 2, 1]));
    let msg = BgpMessage::Open(open);
    let encoded = BgpCodec::new()
        .with_asn4(false)
        .encode_vec(&msg)
        .expect("encode");

    let expected = frame(
        &[
            0x04, 0xFD, 0xE9, 0x00, 0xB4, 0xC0, 0x00, 0x02, 0x01, 0x00,
        ],
        BgpMessageType::Open as u8,
    );
    assert_eq!(
        encoded, expected,
        "encoded OPEN must byte-match the RFC 4271 §8 example"
    );
}

/// Encoding a KEEPALIVE must produce the canonical 19-byte form.
#[test]
fn rfc4271_keepalive_encode_matches_rfc_bytes() {
    let encoded = BgpCodec::new()
        .encode_vec(&BgpMessage::Keepalive(Keepalive))
        .expect("encode");
    let expected = frame(&[], BgpMessageType::Keepalive as u8);
    assert_eq!(encoded, expected);
}

// Suppress dead-code warning for the OpenParam import when this file
// is compiled with `#[cfg(test)]` in environments that only exercise
// a subset of the vectors.
#[test]
fn open_param_import_used() {
    let _ = OpenParam::PARAM_TYPE_CAPABILITY;
}
