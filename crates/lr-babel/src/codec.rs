//! Babel codec: frame encoder/decoder.

use crate::tlv::Tlv;
use crate::{BabelFrame, BODY_OFFSET};
use lr_core::buf::{ReadBuf, WriteBuf};
use lr_core::codec::{Decoder, Encoder};
use lr_core::error::{EncodeError, ParseError};
use lr_core::util::crc::crc32c;

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
        // Babel frames are 4-byte header + body of TLVs. We don't know the
        // total length until we read it (the frame is one UDP datagram,
        // though, so the embedder usually knows). For streaming decode, we
        // assume one frame per buffer.
        if self.carryover.len() < BODY_OFFSET {
            return Ok(None);
        }
        let body = &self.carryover[BODY_OFFSET..];
        let frame = decode_frame_body(body)?;
        self.carryover.clear();
        Ok(Some(frame))
    }

    pub fn encode_vec(&self, frame: &BabelFrame) -> Result<Vec<u8>, EncodeError> {
        let mut out = vec![0u8; 1500];
        let mut w = WriteBuf::new(&mut out);
        let n = self.encode(frame, &mut w)?;
        out.truncate(n);
        Ok(out)
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
        let total = out.position() - start;
        let _ = crc32c(&out.written()[start..]); // unused; embedder may add CRC TLV.
        Ok(total)
    }
}

impl Decoder<BabelFrame> for BabelCodec {
    fn decode(&mut self, src: &mut ReadBuf<'_>) -> Result<Option<BabelFrame>, ParseError> {
        self.carryover.extend_from_slice(src.chunk());
        let n = src.remaining();
        src.advance(n);
        if self.carryover.len() < BODY_OFFSET {
            return Ok(None);
        }
        let body = self.carryover[BODY_OFFSET..].to_vec();
        let frame = decode_frame_body(&body)?;
        self.carryover.clear();
        Ok(Some(frame))
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::message::Hello;
    use crate::tlv::{Tlv, TlvType};

    #[test]
    fn frame_roundtrip() {
        let h = Hello {
            seqno: 1,
            interval_cs: 200,
        };
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
    fn empty_frame() {
        let frame = BabelFrame::empty();
        let codec = BabelCodec::new();
        let bytes = codec.encode_vec(&frame).unwrap();
        let mut dec = BabelCodec::new();
        let f2 = dec.decode_slice(&bytes).unwrap().unwrap();
        assert!(f2.body.is_empty());
    }
}
