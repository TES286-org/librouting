//! Integration test: a realistic daemon-shaped announcement that
//! exceeds RFC 8966 §4's 1496-octet body cap is split by
//! [`BabelCodec::pack_frames`] into multiple datagrams, each
//! decodable and each preserving the protocol invariants the
//! receiver depends on (Hello in the first, Router-Id + NextHop
//! re-emitted before Updates in trailing frames).
//!
//! Models the production bug: a multi-NIC router whose peers flood
//! hundreds of Updates per cycle. Before `pack_frames` existed, the
//! daemon built one `BabelFrame` with the whole announcement and
//! `BabelCodec::encode_vec` ran out of its 1500-byte buffer; the
//! `unwrap_or_default()` fallback produced an empty `Vec`, which the
//! daemon sent as a zero-byte UDP datagram. tcpdump rendered the
//! empty payload as `babel [|babel]`; the peer (BIRD, babeld) saw
//! no Hello/IHU, declared the neighbour dead, re-flooded every route
//! on the next cycle, and the best-path selection churned.

use lr_babel::message::{Hello, Ihu, NextHop, RouterId as RouterIdTlv};
use lr_babel::tlv::{Tlv, TlvType};
use lr_babel::{BabelCodec, BabelFrame, MAX_BODY_LENGTH};

/// The shape of a daemon announcement: Hello + IHU + NextHop +
/// Router-Id preamble, then a sequence of Updates grouped under
/// Router-Id TLVs (the daemon groups foreign claims by origin).
fn announcement_with_routes(n_routes: u16) -> BabelFrame {
    let mut frame = BabelFrame::empty();
    frame
        .body
        .push(Tlv::new(TlvType::Hello, Hello::new(1, 400).encode()));
    frame
        .body
        .push(Tlv::new(TlvType::Ihu, Ihu::new(96, 1200).encode()));
    frame.body.push(Tlv::new(
        TlvType::NextHop,
        NextHop {
            ae: 2,
            address: lr_core::addr::IpAddr::V6([
                0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
            ]),
        }
        .encode(),
    ));
    // One Router-Id group with all the routes under it — the worst
    // case for splitting, since every trailing frame must re-emit
    // the Router-Id.
    frame.body.push(Tlv::new(
        TlvType::RouterId,
        RouterIdTlv {
            id: [1, 2, 3, 4, 5, 6, 7, 8],
        }
        .encode()
        .to_vec(),
    ));
    for i in 0u16..n_routes {
        let mut prefix = [0u8; 16];
        prefix[0] = 0x20;
        prefix[1] = 0x01;
        prefix[2] = 0x0d;
        prefix[3] = 0xb8;
        prefix[4..6].copy_from_slice(&i.to_be_bytes());
        let seqno: u8 = (i as u8).wrapping_add(1);
        let mut body = vec![2u8, 0, 48, 0, 0x01, 0x2c, 0, seqno, 0, 0xc0];
        body.extend_from_slice(&prefix[..6]);
        frame.body.push(Tlv::new(TlvType::Update, body));
    }
    frame
}

#[test]
fn large_announcement_splits_into_packet_sized_datagrams() {
    let frame = announcement_with_routes(200);
    let codec = BabelCodec::new();
    let packed = codec.pack_frames(&frame, MAX_BODY_LENGTH);
    assert!(
        packed.len() > 1,
        "200 /48 Updates must split across multiple datagrams"
    );
    // Every packed frame encodes to <= 1500 octets (4 header + body).
    for (idx, f) in packed.iter().enumerate() {
        let encoded = codec
            .encode_vec_sized(f)
            .unwrap_or_else(|e| panic!("frame {idx} failed to encode: {e:?}"));
        assert!(
            encoded.len() <= 1500,
            "frame {idx} is {} bytes; RFC 8966 §4 caps a datagram at 1500",
            encoded.len()
        );
        // Every frame is decodable — no empty bodies, no truncations.
        let decoded = BabelCodec::new()
            .decode_slice(&encoded)
            .expect("decode must succeed")
            .expect("a whole frame");
        assert!(
            !decoded.body.is_empty(),
            "frame {idx} decoded to an empty body"
        );
    }
}

#[test]
fn first_frame_carries_hello_and_ihu() {
    let frame = announcement_with_routes(200);
    let codec = BabelCodec::new();
    let packed = codec.pack_frames(&frame, MAX_BODY_LENGTH);
    let first = &packed[0];
    assert!(
        first.body.iter().any(|t| t.kind == TlvType::Hello),
        "the first datagram of an announcement burst carries the Hello"
    );
    assert!(
        first.body.iter().any(|t| t.kind == TlvType::Ihu),
        "the first datagram of an announcement burst carries the IHU"
    );
    // Hello/IHU do NOT appear in trailing frames — RFC 8966 §3.4/§3.5
    // tie their cadence to the Hello interval, not to per-datagram
    // presence.
    for (idx, f) in packed.iter().enumerate().skip(1) {
        assert!(
            !f.body.iter().any(|t| t.kind == TlvType::Hello),
            "trailing frame {idx} carries a stray Hello"
        );
        assert!(
            !f.body.iter().any(|t| t.kind == TlvType::Ihu),
            "trailing frame {idx} carries a stray IHU"
        );
    }
}

#[test]
fn every_update_sits_under_a_router_id_in_its_packet() {
    let frame = announcement_with_routes(200);
    let codec = BabelCodec::new();
    let packed = codec.pack_frames(&frame, MAX_BODY_LENGTH);
    for (idx, f) in packed.iter().enumerate() {
        let mut have_router_id = false;
        for tlv in &f.body {
            match tlv.kind {
                TlvType::RouterId => have_router_id = true,
                TlvType::Update => {
                    assert!(
                        have_router_id,
                        "frame {idx}: an Update is not preceded by a Router-Id in this packet \
                         (the receiver would not know which source owns it)"
                    );
                }
                _ => {}
            }
        }
    }
}

#[test]
fn trailing_update_frames_re_emit_the_next_hop() {
    let frame = announcement_with_routes(200);
    let codec = BabelCodec::new();
    let packed = codec.pack_frames(&frame, MAX_BODY_LENGTH);
    // Every trailing frame that carries an Update must also carry a
    // NextHop (AE 2 for v6) — the receiver applies a Update's next
    // hop from the most recent NextHop TLV *in the same packet*.
    for (idx, f) in packed.iter().enumerate().skip(1) {
        let has_update = f.body.iter().any(|t| t.kind == TlvType::Update);
        if !has_update {
            continue;
        }
        let has_v6_nh = f
            .body
            .iter()
            .any(|t| t.kind == TlvType::NextHop && t.value.first() == Some(&2));
        assert!(
            has_v6_nh,
            "trailing frame {idx} carries v6 Updates without a v6 NextHop TLV"
        );
    }
}

/// The daemon groups foreign claims by origin Router-Id, so a split
/// can land exactly before a Router-Id TLV. With the 1496-byte body
/// budget the preamble (48 bytes) plus 80 v6 /48 Updates (18 bytes
/// each) fills 1488 bytes and leaves 8 — the next 12-byte Router-Id
/// opens the trailing frame. That frame must still carry the NextHop
/// for the Updates behind the Router-Id. The old packer only
/// re-emitted it when the frame's first TLV was an Update, so BIRD
/// rejected the whole datagram ("Update must have next hop") and
/// every route in it was lost.
#[test]
fn router_id_led_trailing_frame_still_carries_next_hop() {
    let mut frame = BabelFrame::empty();
    frame
        .body
        .push(Tlv::new(TlvType::Hello, Hello::new(1, 400).encode()));
    frame
        .body
        .push(Tlv::new(TlvType::Ihu, Ihu::new(96, 1200).encode()));
    frame.body.push(Tlv::new(
        TlvType::NextHop,
        NextHop {
            ae: 2,
            address: lr_core::addr::IpAddr::V6([
                0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
            ]),
        }
        .encode(),
    ));
    frame.body.push(Tlv::new(
        TlvType::RouterId,
        RouterIdTlv { id: [1; 8] }.encode().to_vec(),
    ));
    for i in 0u16..80 {
        let mut prefix = [0u8; 6];
        prefix[..2].copy_from_slice(&i.to_be_bytes());
        let mut body = vec![
            2u8,
            0,
            48,
            0,
            0x01,
            0x2c,
            0,
            (i as u8).wrapping_add(1),
            0,
            0xc0,
        ];
        body.extend_from_slice(&prefix);
        frame.body.push(Tlv::new(TlvType::Update, body));
    }
    // The second origin group. Its Router-Id does not fit in frame 1,
    // so it opens frame 2; the AE 4 Update behind it needs the v6
    // NextHop re-emitted after the Router-Id.
    frame.body.push(Tlv::new(
        TlvType::RouterId,
        RouterIdTlv { id: [2; 8] }.encode().to_vec(),
    ));
    let mut body = vec![4u8, 0, 32, 0, 0x01, 0x2c, 0, 42, 0, 0xc0];
    body.extend_from_slice(&[10, 0, 0, 2]);
    frame.body.push(Tlv::new(TlvType::Update, body));

    let codec = BabelCodec::new();
    let packed = codec.pack_frames(&frame, MAX_BODY_LENGTH);
    assert_eq!(
        packed.len(),
        2,
        "the second Router-Id group opens a trailing datagram"
    );
    let trailing = &packed[1];
    assert_eq!(
        trailing.body.first().map(|t| t.kind),
        Some(TlvType::RouterId),
        "the trailing frame opens with the second group's Router-Id"
    );
    let router_ids: Vec<&Tlv> = trailing
        .body
        .iter()
        .filter(|t| t.kind == TlvType::RouterId)
        .collect();
    assert_eq!(
        router_ids.len(),
        1,
        "the in-frame Router-Id must not be duplicated"
    );
    let next_hop = trailing
        .body
        .iter()
        .position(|t| t.kind == TlvType::NextHop)
        .expect("the Router-Id-led trailing frame must re-emit the v6 NextHop");
    let update = trailing
        .body
        .iter()
        .position(|t| t.kind == TlvType::Update)
        .expect("the trailing frame carries the second group's Update");
    assert!(
        next_hop < update,
        "the NextHop must precede the Update that uses it"
    );
    assert_eq!(
        trailing.body[next_hop].value.first(),
        Some(&2),
        "the AE 4 Update rides the v6 NextHop"
    );
}

#[test]
fn no_packet_is_an_empty_udp_payload() {
    // The production bug's tcpdump signature was 'babel [|babel]' —
    // a zero-byte UDP payload on port 6696. After the split, every
    // datagram carries at least the babel header (4 bytes) plus a
    // Router-Id (or the Hello/IHU preamble in the first frame).
    let frame = announcement_with_routes(200);
    let codec = BabelCodec::new();
    let packed = codec.pack_frames(&frame, MAX_BODY_LENGTH);
    for (idx, f) in packed.iter().enumerate() {
        let encoded = codec.encode_vec_sized(f).expect("encode succeeds");
        assert!(
            encoded.len() >= 4,
            "frame {idx} is shorter than the babel header"
        );
        // Magic + version.
        assert_eq!(encoded[0], lr_babel::MAGIC, "frame {idx}: bad magic");
        assert_eq!(encoded[1], lr_babel::VERSION, "frame {idx}: bad version");
        // Body length matches actual body bytes.
        let body_len = u16::from_be_bytes([encoded[2], encoded[3]]) as usize;
        assert_eq!(
            body_len + 4,
            encoded.len(),
            "frame {idx}: body length field does not match actual body"
        );
        assert!(body_len > 0, "frame {idx}: empty body (the production bug)");
    }
}

#[test]
fn split_preserves_all_routes() {
    let n = 200;
    let frame = announcement_with_routes(n);
    let codec = BabelCodec::new();
    let packed = codec.pack_frames(&frame, MAX_BODY_LENGTH);
    let total_updates: u16 = packed
        .iter()
        .map(|f| f.body.iter().filter(|t| t.kind == TlvType::Update).count() as u16)
        .sum();
    assert_eq!(
        total_updates, n,
        "all {n} Updates must survive the split across datagrams"
    );
}

#[test]
fn small_announcement_does_not_split() {
    // A daemon with one route to announce must not split — the
    // preamble + one Update is well under the 1496 budget.
    let frame = announcement_with_routes(1);
    let codec = BabelCodec::new();
    let packed = codec.pack_frames(&frame, MAX_BODY_LENGTH);
    assert_eq!(
        packed.len(),
        1,
        "a small announcement stays in one datagram"
    );
}
