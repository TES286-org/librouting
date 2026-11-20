//! Babel codec: frame encoder/decoder.

use crate::tlv::Tlv;
use crate::{BabelFrame, BODY_OFFSET, MAGIC, VERSION};
use lr_core::buf::{ReadBuf, WriteBuf};
use lr_core::codec::{Decoder, Encoder};
use lr_core::error::{EncodeError, ParseError};

/// Babel codec. Stateless encoder + stateful decoder.
#[derive(Default)]
pub struct BabelCodec {
    carryover: Vec<u8>,
}

impl BabelCodec {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn decode_slice(&mut self, b: &[u8]) -> Result<Option<BabelFrame>, ParseError> {
        self.carryover.extend_from_slice(b);
        let result = self.try_decode();
        // A malformed frame must not wedge the codec: drop the offending
        // bytes so the decoder can recover on the next call.
        if result.is_err() {
            self.carryover.clear();
        }
        result
    }

    fn try_decode(&mut self) -> Result<Option<BabelFrame>, ParseError> {
        if self.carryover.len() < BODY_OFFSET {
            return Ok(None);
        }
        let magic = self.carryover[0];
        let version = self.carryover[1];
        if magic != MAGIC || version != VERSION {
            // RFC 8966 §4.2: packets with a wrong magic or version MUST be
            // silently ignored — do not wedge the decoder.
            return Err(ParseError::invalid(0, "babel.header.magic"));
        }
        let body_len = u16::from_be_bytes([self.carryover[2], self.carryover[3]]) as usize;
        let total = BODY_OFFSET + body_len;
        if self.carryover.len() < total {
            return Ok(None);
        }
        let body = &self.carryover[BODY_OFFSET..total];
        let frame = decode_frame_body(body)?;
        self.carryover.drain(0..total);
        Ok(Some(frame))
    }

    pub fn encode_vec(&self, frame: &BabelFrame) -> Result<Vec<u8>, EncodeError> {
        let mut out = vec![0u8; 1500];
        let mut w = WriteBuf::new(&mut out);
        let n = self.encode(frame, &mut w)?;
        out.truncate(n);
        Ok(out)
    }

    /// Encode `frame` into a fresh buffer sized for it. Use this when the
    /// caller already knows the frame fits (e.g. after [`pack_frames`]
    /// split a large announcement into packet-sized chunks). Unlike
    /// [`encode_vec`](Self::encode_vec), the buffer is allocated to the
    /// exact size, so encoding fails with [`EncodeError::BufferFull`]
    /// only when a single TLV's value exceeds the budget.
    pub fn encode_vec_sized(&self, frame: &BabelFrame) -> Result<Vec<u8>, EncodeError> {
        let budget = frame.body.iter().map(tlv_wire_len).sum::<usize>() + BODY_OFFSET;
        let mut out = vec![0u8; budget.max(BODY_OFFSET)];
        let n = {
            let mut w = WriteBuf::new(&mut out);
            self.encode(frame, &mut w)?;
            w.position()
        };
        out.truncate(n);
        Ok(out)
    }

    /// Pack one logical announcement (a sequence of TLVs) into one or
    /// more frames, each whose encoded body fits in `max_body_len`
    /// octets. RFC 8966 §4 caps a Babel datagram body at 1500 − 4 = 1496
    /// octets; an embedder that builds a single `BabelFrame` with more
    /// TLVs than fit must split it into multiple datagrams before
    /// sending, otherwise the encoder runs out of buffer and the wire
    /// sees an empty UDP payload — the production multi-NIC symptom
    /// where tcpdump shows `babel [|babel]` for every outgoing packet
    /// on busy interfaces and the peer (BIRD, babeld) never observes a
    /// Hello/IHU, declares the neighbour dead, and re-floods every
    /// route on the next cycle.
    ///
    /// The split preserves TLV-level protocol invariants:
    ///
    /// * `Hello` and `Ihu` are carried once, in the first frame, and
    ///   are not duplicated into trailing frames. RFC 8966 §3.4 / §3.5
    ///   only require their cadence, not their presence in every
    ///   datagram; BIRD and babeld both ship Hellos in a single packet
    ///   per interval.
    /// * `RouterId` and `NextHop` are *state* TLVs: an `Update`
    ///   inherits the most recent one *within the same packet*
    ///   (RFC 8966 §4.5.2 / §4.6.8). Every trailing frame whose first
    ///   payload TLV is an `Update` therefore re-emits the most recent
    ///   `RouterId` and the family-matching `NextHop` so the receiver
    ///   applies the Updates with the right source and next hop.
    /// * A `Pad1` or `PadN` never crosses a frame boundary; padding is
    ///   per-packet and is dropped from trailing frames (the receiver
    ///   does not require it).
    ///
    /// The function never panics. A `Tlv` whose own encoded size
    /// exceeds `max_body_len` is still emitted (in its own frame); the
    /// caller is responsible for not constructing such a TLV (Babel
    /// TLV values are capped at 255 octets by the one-octet length
    /// field, so a frame whose body budget is at least 257 octets can
    /// always carry any single TLV).
    pub fn pack_frames(&self, frame: &BabelFrame, max_body_len: usize) -> Vec<BabelFrame> {
        pack_tlvs(&frame.body, max_body_len)
    }

    /// Encode and authenticate one Babel datagram with RFC 8967 HMAC-SHA256.
    pub fn encode_authenticated(
        &self,
        frame: &BabelFrame,
        pseudo_header: crate::auth::BabelPseudoHeader,
        key: &crate::auth::BabelMacKey,
        counter: &mut crate::auth::BabelPacketCounter,
    ) -> Result<Vec<u8>, crate::auth::BabelAuthError> {
        let packet = self
            .encode_vec(frame)
            .map_err(|_| crate::auth::BabelAuthError::InvalidLength)?;
        crate::auth::authenticate_packet(&packet, pseudo_header, key, counter)
    }

    /// Verify, replay-check and decode an RFC 8967 authenticated datagram.
    /// The PC TLV and MAC trailer are stripped before normal Babel TLV parsing.
    pub fn decode_authenticated_slice(
        &mut self,
        packet: &[u8],
        pseudo_header: crate::auth::BabelPseudoHeader,
        keys: &[crate::auth::BabelMacKey],
        replay: &mut crate::auth::BabelReplayProtection,
    ) -> Result<Option<BabelFrame>, crate::auth::BabelAuthError> {
        let plain = crate::auth::verify_packet(packet, pseudo_header, keys, replay)?;
        self.decode_slice(&plain)
            .map_err(|_| crate::auth::BabelAuthError::InvalidLength)
    }
}

fn decode_frame_body(body: &[u8]) -> Result<BabelFrame, ParseError> {
    let mut tlvs = Vec::new();
    let mut i = 0;
    while i < body.len() {
        let ty = body[i];
        if ty == 0 {
            // Pad1 — single byte.
            tlvs.push(Tlv::pad1());
            i += 1;
            continue;
        }
        if i + 2 > body.len() {
            return Err(ParseError::truncated("babel.tlv.length"));
        }
        let len = body[i + 1] as usize;
        let val_start = i + 2;
        if val_start + len > body.len() {
            return Err(ParseError::bad_length(i + 1, "babel.tlv.length"));
        }
        let value = body[val_start..val_start + len].to_vec();
        tlvs.push(Tlv::new(crate::tlv::TlvType::from_u8(ty), value));
        i = val_start + len;
    }
    Ok(BabelFrame { body: tlvs })
}

impl Encoder<BabelFrame> for BabelCodec {
    fn encode(&self, frame: &BabelFrame, out: &mut WriteBuf<'_>) -> Result<usize, EncodeError> {
        let start = out.position();
        // Write 4-byte header: magic + version + 2-byte body length (patched).
        out.put_u8(crate::MAGIC).ok_or(EncodeError::BufferFull)?;
        out.put_u8(crate::VERSION).ok_or(EncodeError::BufferFull)?;
        let len_pos = out.reserve(2).ok_or(EncodeError::BufferFull)?;
        let body_start = out.position();
        for tlv in &frame.body {
            encode_tlv(tlv, out)?;
        }
        let body_len = (out.position() - body_start) as u16;
        out.patch(len_pos, &body_len.to_be_bytes())
            .ok_or(EncodeError::BufferFull)?;
        Ok(out.position() - start)
    }
}

impl Decoder<BabelFrame> for BabelCodec {
    fn decode(&mut self, src: &mut ReadBuf<'_>) -> Result<Option<BabelFrame>, ParseError> {
        self.carryover.extend_from_slice(src.chunk());
        let n = src.remaining();
        src.advance(n);
        let result = self.try_decode();
        if result.is_err() {
            self.carryover.clear();
        }
        result
    }
}

fn encode_tlv(tlv: &Tlv, out: &mut WriteBuf<'_>) -> Result<(), EncodeError> {
    if tlv.kind == crate::tlv::TlvType::Pad1 && tlv.value.is_empty() {
        out.put_u8(0).ok_or(EncodeError::BufferFull)?;
        return Ok(());
    }
    if tlv.value.len() > 255 {
        return Err(EncodeError::InvalidValue(
            "Babel TLV value too long (>255 bytes)",
        ));
    }
    out.put_u8(tlv.kind.to_u8())
        .ok_or(EncodeError::BufferFull)?;
    out.put_u8(tlv.value.len() as u8)
        .ok_or(EncodeError::BufferFull)?;
    out.put_bytes(&tlv.value).ok_or(EncodeError::BufferFull)?;
    Ok(())
}

/// The encoded wire length of one TLV: 1 octet for a `Pad1`, otherwise
/// 2 (type + length) plus the value's length. Pad1 carries no length
/// field; every other TLV — including `PadN` — does.
fn tlv_wire_len(tlv: &Tlv) -> usize {
    if tlv.kind == crate::tlv::TlvType::Pad1 && tlv.value.is_empty() {
        return 1;
    }
    2 + tlv.value.len()
}

/// The address-encoding byte (`AE` field, RFC 8966 §4.5.2) carried by
/// a `NextHop` TLV, or `None` for a malformed/empty body. The first
/// value octet of a `NextHop` body is the AE; the second is reserved.
fn next_hop_ae(tlv: &Tlv) -> Option<u8> {
    tlv.value.first().copied()
}

/// Split a flat TLV list into packet-sized [`BabelFrame`]s. See
/// [`BabelCodec::pack_frames`] for the protocol-level contract.
///
/// Algorithm: walk the input TLVs in order, appending each to the
/// current frame. When the next TLV would overflow the body budget,
/// close the current frame and open a new one. Before the first
/// `Update` in any frame opened this way, re-emit the most recent
/// `RouterId` TLV and the family-matching `NextHop` TLV — they are
/// per-packet state the receiver needs to interpret the Update.
///
/// `Hello` and `Ihu` are never re-emitted: RFC 8966 §3.4 / §3.5 tie
/// their cadence to the Hello interval, not to per-datagram presence.
/// BIRD and babeld both ship exactly one Hello per interval, in the
/// first datagram of the announcement burst.
fn pack_tlvs(tlvs: &[Tlv], max_body_len: usize) -> Vec<BabelFrame> {
    let mut frames: Vec<BabelFrame> = Vec::new();
    let mut cur = BabelFrame::empty();
    let mut cur_len = 0usize;

    // Per-announcement state: the most recent Router-Id and the most
    // recent NextHop per AE, so a freshly opened frame can re-establish
    // the context the receiver needs for the Updates that follow.
    let mut last_router_id: Option<Tlv> = None;
    let mut last_next_hop_v4: Option<Tlv> = None;
    let mut last_next_hop_v6: Option<Tlv> = None;

    let mut first_in_frame = true;

    for tlv in tlvs {
        // Skip Pad1/PadN at frame boundaries — padding is per-packet
        // and is dropped from trailing frames. Emitting it would only
        // waste budget the next real TLV needs.
        if (tlv.kind == crate::tlv::TlvType::Pad1 && tlv.value.is_empty())
            || tlv.kind == crate::tlv::TlvType::PadN
        {
            if !first_in_frame {
                cur.body.push(tlv.clone());
                cur_len += tlv_wire_len(tlv);
            }
            continue;
        }

        let len = tlv_wire_len(tlv);

        // Would this TLV overflow the current frame? Close it and open
        // a new one. The check is on `cur_len + len` against the
        // budget; a TLV larger than the budget lands in its own frame
        // (which will exceed the budget — the caller must guarantee no
        // such TLV exists, and Babel's 255-octet value cap makes that
        // trivial for any reasonable budget).
        if !first_in_frame && cur_len + len > max_body_len {
            frames.push(std::mem::take(&mut cur));
            cur_len = 0;
            first_in_frame = true;
        }

        // If this is the first real TLV in a frame AND it is an
        // Update, re-emit the most recent Router-Id and family-matching
        // NextHop so the receiver interprets the Update with the right
        // source and next hop. The Router-Id goes first (§4.6.7:
        // precedes the Updates using it); then the NextHop (§4.6.8:
        // ditto). We emit both v4 and v6 NextHops when both are set —
        // the receiver applies the one matching each Update's AE.
        if first_in_frame && tlv.kind == crate::tlv::TlvType::Update {
            if let Some(rid) = &last_router_id {
                let rid_len = tlv_wire_len(rid);
                if cur_len + rid_len <= max_body_len {
                    cur.body.push(rid.clone());
                    cur_len += rid_len;
                }
            }
            for nh in [last_next_hop_v4.as_ref(), last_next_hop_v6.as_ref()]
                .into_iter()
                .flatten()
            {
                let nh_len = tlv_wire_len(nh);
                if cur_len + nh_len <= max_body_len {
                    cur.body.push(nh.clone());
                    cur_len += nh_len;
                }
            }
        }

        // Track state TLVs for re-emission in later frames.
        match tlv.kind {
            crate::tlv::TlvType::RouterId => last_router_id = Some(tlv.clone()),
            crate::tlv::TlvType::NextHop => match next_hop_ae(tlv) {
                Some(1) => last_next_hop_v4 = Some(tlv.clone()),
                Some(2 | 3) => last_next_hop_v6 = Some(tlv.clone()),
                _ => {}
            },
            _ => {}
        }

        cur.body.push(tlv.clone());
        cur_len += len;
        first_in_frame = false;
    }

    if !cur.body.is_empty() {
        frames.push(cur);
    }
    frames
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::message::Hello;
    use crate::tlv::{Tlv, TlvType};

    #[test]
    fn frame_roundtrip() {
        let h = Hello::new(1, 200);
        let mut frame = BabelFrame::empty();
        frame
            .body
            .push(Tlv::new(TlvType::Hello, h.encode().to_vec()));
        frame.body.push(Tlv::pad1());
        frame.body.push(Tlv::pad_n(3));
        let codec = BabelCodec::new();
        let bytes = codec.encode_vec(&frame).unwrap();
        let mut dec = BabelCodec::new();
        let f2 = dec.decode_slice(&bytes).unwrap().unwrap();
        assert_eq!(f2.body.len(), frame.body.len());
        match &f2.body[0] {
            Tlv {
                kind: TlvType::Hello,
                value,
            } => {
                let h2 = Hello::decode(value).unwrap();
                assert_eq!(h2, h);
            }
            _ => panic!("expected Hello TLV"),
        }
    }

    #[test]
    fn authenticated_frame_roundtrip() {
        let frame = BabelFrame::new(vec![Tlv::new(
            TlvType::Hello,
            Hello::new(1, 200).encode().to_vec(),
        )]);
        let pseudo = crate::auth::BabelPseudoHeader {
            source: lr_core::addr::IpAddr::V4([192, 0, 2, 1]),
            source_port: 6696,
            destination: lr_core::addr::IpAddr::V4([224, 0, 0, 111]),
            destination_port: 6696,
        };
        let key = crate::auth::BabelMacKey::new(b"test-key".to_vec());
        let mut counter = crate::auth::BabelPacketCounter::new(b"index".to_vec(), 1).unwrap();
        let packet = BabelCodec::new()
            .encode_authenticated(&frame, pseudo, &key, &mut counter)
            .unwrap();
        let mut replay = crate::auth::BabelReplayProtection::default();
        let decoded = BabelCodec::new()
            .decode_authenticated_slice(&packet, pseudo, &[key], &mut replay)
            .unwrap()
            .unwrap();
        assert_eq!(decoded, frame);
    }

    #[test]
    fn empty_frame() {
        let frame = BabelFrame::empty();
        let codec = BabelCodec::new();
        let bytes = codec.encode_vec(&frame).unwrap();
        let mut dec = BabelCodec::new();
        let f2 = dec.decode_slice(&bytes).unwrap().unwrap();
        assert!(f2.body.is_empty());
    }

    /// A small announcement fits in one frame; `pack_frames` returns
    /// exactly one frame and the encoded body matches the input.
    #[test]
    fn pack_frames_small_fits_one_frame() {
        let mut frame = BabelFrame::empty();
        frame
            .body
            .push(Tlv::new(TlvType::Hello, Hello::new(1, 200).encode()));
        frame.body.push(Tlv::new(
            TlvType::RouterId,
            vec![0, 0, 1, 2, 3, 4, 5, 6, 7, 8],
        ));
        frame.body.push(Tlv::new(
            TlvType::Update,
            vec![1, 0, 24, 0, 0x01, 0x2c, 0, 1, 0, 0xc0, 10, 0, 1],
        ));
        let codec = BabelCodec::new();
        let packed = codec.pack_frames(&frame, 1496);
        assert_eq!(packed.len(), 1, "one small frame stays one frame");
        assert_eq!(packed[0].body.len(), frame.body.len());
    }

    /// The production bug: 200 Updates in one frame overflow the 1496
    /// byte body budget. Before `pack_frames` existed the encoder
    /// returned `BufferFull` and `unwrap_or_default()` produced an
    /// empty `Vec` — the wire saw an empty UDP payload and tcpdump
    /// rendered it as `babel [|babel]`. After `pack_frames`, the same
    /// announcement splits into multiple frames, each ≤ the budget,
    /// and the first frame still carries the Hello and IHU.
    #[test]
    fn pack_frames_large_announcement_splits() {
        use crate::message::{Ihu, NextHop, RouterId as RouterIdTlv, Update};
        let mut frame = BabelFrame::empty();
        // Hello + IHU + NextHop + Router-Id preamble (~40 bytes body).
        frame
            .body
            .push(Tlv::new(TlvType::Hello, Hello::new(1, 200).encode()));
        frame
            .body
            .push(Tlv::new(TlvType::Ihu, Ihu::new(96, 600).encode()));
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
            RouterIdTlv {
                id: [1, 2, 3, 4, 5, 6, 7, 8],
            }
            .encode()
            .to_vec(),
        ));
        // 200 IPv6 Updates, /64 prefixes — each ~22 bytes body (10 fixed
        // + 8 prefix + 4 source-prefix sub-TLV placeholder for
        // source-specific routes). Realistic for a Babel router that
        // has learned a few hundred routes from its peers.
        for i in 0u16..200 {
            let mut prefix = [0u8; 16];
            prefix[0] = 0x20;
            prefix[1] = 0x01;
            prefix[2] = 0x0d;
            prefix[3] = 0xb8;
            prefix[4..6].copy_from_slice(&i.to_be_bytes());
            let seqno = (i as u8).wrapping_add(1);
            let mut update_body = vec![2u8, 0, 64, 0, 0x01, 0x2c, 0, seqno, 0, 0xc0];
            update_body.extend_from_slice(&prefix[..8]);
            frame.body.push(Tlv::new(TlvType::Update, update_body));
        }

        let codec = BabelCodec::new();
        let packed = codec.pack_frames(&frame, 1496);
        // Each frame must encode to ≤ 1500 bytes total (4 header + body).
        for (idx, f) in packed.iter().enumerate() {
            let encoded = codec.encode_vec_sized(f).unwrap_or_else(|e| {
                panic!(
                    "frame {idx} failed to encode: {e:?} (body has {} TLVs)",
                    f.body.len()
                )
            });
            assert!(
                encoded.len() <= 1500,
                "frame {idx} is {} bytes (max 1500)",
                encoded.len()
            );
            assert!(
                encoded.len() >= 4,
                "frame {idx} is shorter than the babel header"
            );
        }
        // The first frame carries the Hello.
        let first = &packed[0].body;
        assert!(
            first.iter().any(|t| t.kind == TlvType::Hello),
            "the first frame must carry the Hello"
        );
        // Every trailing frame whose first real TLV is an Update has
        // a Router-Id TLV before it (the receiver cannot interpret an
        // Update without one).
        for (idx, f) in packed.iter().enumerate().skip(1) {
            let first_kind = f.body.first().map(|t| t.kind);
            if first_kind == Some(TlvType::Update) {
                panic!("frame {idx} starts with an Update — a Router-Id must precede it");
            }
        }
        // All 200 Updates plus the preamble are accounted for across
        // the split frames.
        let total_updates: usize = packed
            .iter()
            .map(|f| f.body.iter().filter(|t| t.kind == TlvType::Update).count())
            .sum();
        assert_eq!(total_updates, 200, "all 200 Updates survived the split");
        // Hello and IHU appear exactly once across the split (RFC 8966
        // §3.4/§3.5 cadence — one per interval, not per packet).
        let hellos: usize = packed
            .iter()
            .map(|f| f.body.iter().filter(|t| t.kind == TlvType::Hello).count())
            .sum();
        let ihus: usize = packed
            .iter()
            .map(|f| f.body.iter().filter(|t| t.kind == TlvType::Ihu).count())
            .sum();
        assert_eq!(hellos, 1, "Hello appears once, not once per packet");
        assert_eq!(ihus, 1, "IHU appears once, not once per packet");
    }

    /// A split frame's trailing packet, opening with an Update, must
    /// re-emit the most recent Router-Id and NextHop so the receiver
    /// applies the Update with the right source and next hop.
    #[test]
    fn pack_frames_trailing_update_has_router_id_and_next_hop() {
        use crate::message::{NextHop, RouterId as RouterIdTlv};
        let v6_nh = NextHop {
            ae: 2,
            address: lr_core::addr::IpAddr::V6([
                0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 9,
            ]),
        };
        let rid_a = RouterIdTlv { id: [1; 8] };
        let rid_b = RouterIdTlv { id: [2; 8] };

        let mut frame = BabelFrame::empty();
        frame.body.push(Tlv::new(TlvType::NextHop, v6_nh.encode()));
        frame
            .body
            .push(Tlv::new(TlvType::RouterId, rid_a.encode().to_vec()));
        // Pad with enough Updates under Router-Id A to force a split
        // before the next Router-Id group.
        for i in 0u8..80 {
            let mut prefix = [0u8; 8];
            prefix[6] = 0;
            prefix[7] = i;
            let mut body = vec![2u8, 0, 64, 0, 0x01, 0x2c, 0, i, 0, 0xc0];
            body.extend_from_slice(&prefix);
            frame.body.push(Tlv::new(TlvType::Update, body));
        }
        // A second Router-Id group with one Update. After splitting,
        // the trailing Update MUST sit under a Router-Id TLV (either
        // the re-emitted A or the new B, depending on where the split
        // landed) — `pack_frames` must not strand an Update without a
        // Router-Id in its packet.
        frame
            .body
            .push(Tlv::new(TlvType::RouterId, rid_b.encode().to_vec()));
        let mut body = vec![2u8, 0, 64, 0, 0x01, 0x2c, 0, 42, 0, 0xc0];
        body.extend_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 1]);
        frame.body.push(Tlv::new(TlvType::Update, body));

        let codec = BabelCodec::new();
        let packed = codec.pack_frames(&frame, 256);
        assert!(
            packed.len() > 1,
            "the announcement is large enough to split at 256-byte budget"
        );
        // Validate every frame: every Update is preceded (within its
        // frame) by a Router-Id, and every Update's packet carries a
        // NextHop matching its AE.
        for (idx, f) in packed.iter().enumerate() {
            let mut have_router_id = false;
            let mut have_v6_nh = false;
            for tlv in &f.body {
                match tlv.kind {
                    TlvType::RouterId => have_router_id = true,
                    TlvType::NextHop => {
                        if let Some(2 | 3) = next_hop_ae(tlv) {
                            have_v6_nh = true;
                        }
                    }
                    TlvType::Update => {
                        assert!(
                            have_router_id,
                            "frame {idx}: Update without a preceding Router-Id"
                        );
                        // Every Update in this test is AE 2 (v6), so
                        // every frame that carries one must have a v6
                        // NextHop. The original NextHop was emitted
                        // once near the head; trailing frames must
                        // re-emit it.
                        assert!(
                            have_v6_nh,
                            "frame {idx}: v6 Update without a v6 NextHop in the same packet"
                        );
                    }
                    _ => {}
                }
            }
        }
    }
}
