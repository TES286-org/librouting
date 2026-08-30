//! OSPF codec for v2 and v3.

use crate::lsa::{Lsa, LsaHeader};
use crate::packet::{
    DbDescBody, HelloBody, LsAckBody, LsRequestBody, LsRequestEntry, LsUpdateBody, OspfBody,
    OspfHeader, OspfPacket, OspfPacketType, OspfVersion,
};

use lr_core::buf::{ReadBuf, WriteBuf};
use lr_core::codec::{Decoder, Encoder};
use lr_core::error::{EncodeError, ParseError};

/// OSPF codec parameterized by version.
pub struct OspfCodec {
    pub version: OspfVersion,
    carryover: Vec<u8>,
}

impl OspfCodec {
    pub fn new(version: OspfVersion) -> Self {
        Self {
            version,
            carryover: Vec::new(),
        }
    }

    pub fn v2() -> Self {
        Self::new(OspfVersion::V2)
    }

    pub fn v3() -> Self {
        Self::new(OspfVersion::V3)
    }

    pub fn decode_slice(&mut self, b: &[u8]) -> Result<Option<OspfPacket>, ParseError> {
        self.carryover.extend_from_slice(b);
        if self.carryover.len() < OspfHeader::LEN {
            return Ok(None);
        }
        // Peek length field at offset 2..3.
        let length = u16::from_be_bytes([self.carryover[2], self.carryover[3]]) as usize;
        if length < OspfHeader::LEN {
            // The declared frame cannot hold even the header — drop the
            // corrupt bytes so the decoder recovers.
            self.carryover.clear();
            return Err(ParseError::bad_length(2, "ospf.header.length"));
        }
        if self.carryover.len() < length {
            return Ok(None);
        }
        let buf = &self.carryover[..length];
        match decode_packet(buf, self.version) {
            Ok(pkt) => {
                self.carryover.drain(0..length);
                Ok(Some(pkt))
            }
            Err(e) => {
                // A malformed frame must not wedge the decoder: advance
                // past the offending frame so the next call starts at
                // the following bytes.
                self.carryover.drain(0..length);
                Err(e)
            }
        }
    }

    pub fn encode_vec(&self, msg: &OspfPacket) -> Result<Vec<u8>, EncodeError> {
        let mut out = vec![0u8; 65535];
        let mut w = WriteBuf::new(&mut out);
        let n = self.encode(msg, &mut w)?;
        out.truncate(n);
        Ok(out)
    }
}

impl Encoder<OspfPacket> for OspfCodec {
    fn encode(&self, msg: &OspfPacket, out: &mut WriteBuf<'_>) -> Result<usize, EncodeError> {
        let start = out.position();
        encode_header(&msg.header, out)?;
        match &msg.body {
            OspfBody::Hello(h) => encode_hello(h, self.version, out)?,
            OspfBody::DbDesc(d) => encode_dbdesc(d, self.version, out)?,
            OspfBody::LsRequest(r) => encode_lsreq(r, self.version, out)?,
            OspfBody::LsUpdate(u) => encode_lsupdate(u, self.version, out)?,
            OspfBody::LsAck(a) => encode_lsack(a, self.version, out)?,
            OspfBody::Raw(b) => out.put_bytes(b).ok_or(EncodeError::BufferFull)?,
        }
        let total = out.position() - start;
        // Patch length
        out.patch(start + 2, &(total as u16).to_be_bytes())
            .ok_or(EncodeError::BufferFull)?;
        // Patch checksum (zero — embedder can recompute if needed).
        // OSPF checksums are typically computed at the egress with the IPv4
        // pseudo-header; for library purposes we leave it to the embedder.
        Ok(total)
    }
}

impl Decoder<OspfPacket> for OspfCodec {
    fn decode(&mut self, src: &mut ReadBuf<'_>) -> Result<Option<OspfPacket>, ParseError> {
        let chunk = src.chunk().to_vec();
        src.advance(chunk.len());
        self.decode_slice(&chunk)
    }
}

fn encode_header(h: &OspfHeader, out: &mut WriteBuf<'_>) -> Result<(), EncodeError> {
    out.put_u8(h.version).ok_or(EncodeError::BufferFull)?;
    out.put_u8(h.kind).ok_or(EncodeError::BufferFull)?;
    out.put_u16_be(h.length).ok_or(EncodeError::BufferFull)?;
    out.put_u32_be(h.router_id).ok_or(EncodeError::BufferFull)?;
    out.put_u32_be(h.area_id).ok_or(EncodeError::BufferFull)?;
    out.put_u16_be(h.checksum).ok_or(EncodeError::BufferFull)?;
    out.put_u16_be(h.au_type_or_instance)
        .ok_or(EncodeError::BufferFull)?;
    out.put_u64_be(h.auth_data).ok_or(EncodeError::BufferFull)?;
    Ok(())
}

fn encode_hello(
    h: &HelloBody,
    version: OspfVersion,
    out: &mut WriteBuf<'_>,
) -> Result<(), EncodeError> {
    if version == OspfVersion::V2 {
        out.put_u32_be(h.network_mask)
            .ok_or(EncodeError::BufferFull)?;
    } else {
        // v3 has a 4-byte Interface ID instead of the network mask
        // (RFC 5340 §A.3.2).
        out.put_u32_be(h.network_mask).ok_or(EncodeError::BufferFull)?;
    }
    out.put_u16_be(h.hello_interval)
        .ok_or(EncodeError::BufferFull)?;
    if version == OspfVersion::V2 {
        out.put_u8(h.options as u8).ok_or(EncodeError::BufferFull)?;
        out.put_u8(h.priority).ok_or(EncodeError::BufferFull)?;
    } else {
        // v3 Options are 24 bits, then Rtr Priority (RFC 5340 §A.3.2).
        out.put_u8((h.options >> 16) as u8)
            .ok_or(EncodeError::BufferFull)?;
        out.put_u16_be(h.options as u16)
            .ok_or(EncodeError::BufferFull)?;
        out.put_u8(h.priority).ok_or(EncodeError::BufferFull)?;
    }
    out.put_u32_be(h.dead_interval)
        .ok_or(EncodeError::BufferFull)?;
    out.put_u32_be(h.dr).ok_or(EncodeError::BufferFull)?;
    out.put_u32_be(h.bdr).ok_or(EncodeError::BufferFull)?;
    for n in &h.neighbors {
        out.put_u32_be(*n).ok_or(EncodeError::BufferFull)?;
    }
    Ok(())
}

fn encode_dbdesc(
    d: &DbDescBody,
    version: OspfVersion,
    out: &mut WriteBuf<'_>,
) -> Result<(), EncodeError> {
    out.put_u16_be(d.mtu).ok_or(EncodeError::BufferFull)?;
    if version == OspfVersion::V2 {
        // RFC 2328 §A.3.3: mtu(2) | options(1) | flags(1) | dd_seq(4).
        out.put_u8(d.options as u8).ok_or(EncodeError::BufferFull)?;
        out.put_u8(d.flags).ok_or(EncodeError::BufferFull)?;
    } else {
        // RFC 5340 §A.3.3: mtu(2) | options(3) | flags(1) | dd_seq(4).
        out.put_u8((d.options >> 16) as u8)
            .ok_or(EncodeError::BufferFull)?;
        out.put_u16_be(d.options as u16)
            .ok_or(EncodeError::BufferFull)?;
        out.put_u8(d.flags).ok_or(EncodeError::BufferFull)?;
    }
    out.put_u32_be(d.dd_seq).ok_or(EncodeError::BufferFull)?;
    for h in &d.lsa_headers {
        encode_lsa_header(h, version, out)?;
    }
    Ok(())
}

fn encode_lsreq(
    r: &LsRequestBody,
    version: OspfVersion,
    out: &mut WriteBuf<'_>,
) -> Result<(), EncodeError> {
    for e in &r.entries {
        if version == OspfVersion::V2 {
            // RFC 2328 §A.3.4: LS type(4) | LS ID(4) | Adv Router(4).
            out.put_u32_be(u32::from(e.ls_type))
                .ok_or(EncodeError::BufferFull)?;
        } else {
            // RFC 5340 §A.3.4: LS type(2) | Unused(2) | LS ID(4) | Adv Router(4).
            out.put_u16_be(e.ls_type).ok_or(EncodeError::BufferFull)?;
            out.put_u16_be(0).ok_or(EncodeError::BufferFull)?;
        }
        out.put_u32_be(e.ls_id).ok_or(EncodeError::BufferFull)?;
        out.put_u32_be(e.adv_router)
            .ok_or(EncodeError::BufferFull)?;
    }
    Ok(())
}

fn encode_lsupdate(u: &LsUpdateBody, _version: OspfVersion, out: &mut WriteBuf<'_>) -> Result<(), EncodeError> {
    out.put_u32_be(u.lsa_count).ok_or(EncodeError::BufferFull)?;
    for lsa in &u.lsas {
        out.put_bytes(&lsa.to_wire())
            .ok_or(EncodeError::BufferFull)?;
    }
    Ok(())
}

fn encode_lsack(a: &LsAckBody, version: OspfVersion, out: &mut WriteBuf<'_>) -> Result<(), EncodeError> {
    for h in &a.lsa_headers {
        encode_lsa_header(h, version, out)?;
    }
    Ok(())
}

fn encode_lsa_header(h: &LsaHeader, version: OspfVersion, out: &mut WriteBuf<'_>) -> Result<(), EncodeError> {
    out.put_u16_be(h.ls_age).ok_or(EncodeError::BufferFull)?;
    if version == OspfVersion::V2 {
        // RFC 2328 §A.4.1: age(2) | options(1) | type(1).
        out.put_u8(h.options).ok_or(EncodeError::BufferFull)?;
        out.put_u8(h.ls_type as u8).ok_or(EncodeError::BufferFull)?;
    } else {
        // RFC 5340 §A.4.2: age(2) | LS type(2) — no options byte.
        out.put_u16_be(h.ls_type).ok_or(EncodeError::BufferFull)?;
    }
    out.put_u32_be(h.link_state_id)
        .ok_or(EncodeError::BufferFull)?;
    out.put_u32_be(h.advertising_router)
        .ok_or(EncodeError::BufferFull)?;
    out.put_u32_be(h.ls_sequence_number)
        .ok_or(EncodeError::BufferFull)?;
    out.put_u16_be(h.ls_checksum)
        .ok_or(EncodeError::BufferFull)?;
    out.put_u16_be(h.length).ok_or(EncodeError::BufferFull)?;
    Ok(())
}

fn decode_packet(b: &[u8], version: OspfVersion) -> Result<OspfPacket, ParseError> {
    if b.len() < OspfHeader::LEN {
        return Err(ParseError::truncated("ospf.header"));
    }
    if b[0] != version as u8 {
        return Err(ParseError::invalid(0, "ospf.header.version"));
    }
    let kind = b[1];
    let length = u16::from_be_bytes([b[2], b[3]]);
    if length as usize != b.len() {
        return Err(
            ParseError::bad_length(2, "ospf.header.length").with_detail(format!(
                "header says {} but buffer is {}",
                length,
                b.len()
            )),
        );
    }
    if version == OspfVersion::V2 && !crate::origination::v2_packet_checksum_ok(b) {
        // RFC 2328 §8.2: packets failing the checksum are discarded.
        return Err(ParseError::invalid(12, "ospf.header.checksum"));
    }
    let header = OspfHeader {
        version: version as u8,
        kind,
        length,
        router_id: u32::from_be_bytes([b[4], b[5], b[6], b[7]]),
        area_id: u32::from_be_bytes([b[8], b[9], b[10], b[11]]),
        checksum: u16::from_be_bytes([b[12], b[13]]),
        au_type_or_instance: u16::from_be_bytes([b[14], b[15]]),
        auth_data: u64::from_be_bytes([b[16], b[17], b[18], b[19], b[20], b[21], b[22], b[23]]),
    };
    let body_bytes = &b[OspfHeader::LEN..];
    let body = decode_body(kind, body_bytes, version)?;
    Ok(OspfPacket { header, body })
}

fn decode_body(kind: u8, b: &[u8], version: OspfVersion) -> Result<OspfBody, ParseError> {
    let pk = OspfPacketType::from_u8(kind)
        .ok_or_else(|| ParseError::unknown_type(1, "ospf.header.kind"))?;
    match pk {
        OspfPacketType::Hello => Ok(OspfBody::Hello(decode_hello(b, version)?)),
        OspfPacketType::DatabaseDescription => Ok(OspfBody::DbDesc(decode_dbdesc(b, version)?)),
        OspfPacketType::LinkStateRequest => Ok(OspfBody::LsRequest(decode_lsreq(b, version)?)),
        OspfPacketType::LinkStateUpdate => Ok(OspfBody::LsUpdate(decode_lsupdate(b, version)?)),
        OspfPacketType::LinkStateAck => Ok(OspfBody::LsAck(decode_lsack(b, version)?)),
    }
}

fn decode_hello(b: &[u8], version: OspfVersion) -> Result<HelloBody, ParseError> {
    if b.len() < 20 {
        return Err(ParseError::truncated("ospf.hello.body"));
    }
    let network_mask = u32::from_be_bytes([b[0], b[1], b[2], b[3]]);
    let hello_interval = u16::from_be_bytes([b[4], b[5]]);
    // The fixed part is 20 bytes in both versions; the option/priority
    // pair differs (v3 Options are 24 bits wide, RFC 5340 §A.3.2).
    let (options, priority, fixed) = if version == OspfVersion::V2 {
        (u32::from(b[6]), b[7], 8usize)
    } else {
        (u32::from_be_bytes([0, b[6], b[7], b[8]]), b[9], 10usize)
    };
    let dead_interval = u32::from_be_bytes([
        b[fixed],
        b[fixed + 1],
        b[fixed + 2],
        b[fixed + 3],
    ]);
    let dr = u32::from_be_bytes([
        b[fixed + 4],
        b[fixed + 5],
        b[fixed + 6],
        b[fixed + 7],
    ]);
    let bdr = u32::from_be_bytes([
        b[fixed + 8],
        b[fixed + 9],
        b[fixed + 10],
        b[fixed + 11],
    ]);
    let mut neighbors = Vec::new();
    let mut i = fixed + 12;
    while i + 4 <= b.len() {
        neighbors.push(u32::from_be_bytes([b[i], b[i + 1], b[i + 2], b[i + 3]]));
        i += 4;
    }
    Ok(HelloBody {
        // For v3 the network_mask slot carries the Interface ID; keep as-is.
        network_mask,
        hello_interval,
        options,
        priority,
        dead_interval,
        dr,
        bdr,
        neighbors,
    })
}

fn decode_dbdesc(b: &[u8], version: OspfVersion) -> Result<DbDescBody, ParseError> {
    let (fixed, opt_off, opt_len, flags_off) = if version == OspfVersion::V2 {
        (8usize, 2usize, 1usize, 3usize)
    } else {
        (10usize, 2usize, 3usize, 5usize)
    };
    if b.len() < fixed {
        return Err(ParseError::truncated("ospf.dbdesc.body"));
    }
    let mtu = u16::from_be_bytes([b[0], b[1]]);
    let options = match opt_len {
        1 => u32::from(b[opt_off]),
        _ => u32::from_be_bytes([0, b[opt_off], b[opt_off + 1], b[opt_off + 2]]),
    };
    let flags = b[flags_off];
    let dd_seq = u32::from_be_bytes([b[flags_off + 1], b[flags_off + 2], b[flags_off + 3], b[flags_off + 4]]);
    let mut lsa_headers = Vec::new();
    let mut i = fixed;
    while i + LsaHeader::LEN <= b.len() {
        let h = decode_lsa_header(&b[i..i + LsaHeader::LEN], version)?;
        lsa_headers.push(h);
        i += LsaHeader::LEN;
    }
    Ok(DbDescBody {
        mtu,
        options,
        flags,
        dd_seq,
        lsa_headers,
    })
}

fn decode_lsreq(b: &[u8], version: OspfVersion) -> Result<LsRequestBody, ParseError> {
    let mut entries = Vec::new();
    let mut i = 0;
    const ENTRY: usize = 12;
    while i + ENTRY <= b.len() {
        let ls_type = if version == OspfVersion::V2 {
            // RFC 2328 §A.3.4: LS type is a 4-byte word.
            u32::from_be_bytes([b[i], b[i + 1], b[i + 2], b[i + 3]]) as u16
        } else {
            // RFC 5340 §A.3.4: LS type(2) | Unused(2) — the 16-bit type
            // is at the start of the entry.
            u16::from_be_bytes([b[i], b[i + 1]])
        };
        let ls_id = u32::from_be_bytes([b[i + 4], b[i + 5], b[i + 6], b[i + 7]]);
        let adv_router = u32::from_be_bytes([b[i + 8], b[i + 9], b[i + 10], b[i + 11]]);
        entries.push(LsRequestEntry {
            ls_type,
            ls_id,
            adv_router,
        });
        i += ENTRY;
    }
    Ok(LsRequestBody { entries })
}

fn decode_lsupdate(b: &[u8], version: OspfVersion) -> Result<LsUpdateBody, ParseError> {
    if b.len() < 4 {
        return Err(ParseError::truncated("ospf.lsupdate.body"));
    }
    let lsa_count = u32::from_be_bytes([b[0], b[1], b[2], b[3]]) as usize;
    let mut lsas = Vec::with_capacity(lsa_count);
    let mut i = 4;
    while i + LsaHeader::LEN <= b.len() && lsas.len() < lsa_count {
        let h = decode_lsa_header(&b[i..i + LsaHeader::LEN], version)?;
        let body_len = h.length as usize;
        if body_len < LsaHeader::LEN {
            return Err(ParseError::bad_length(i + 18, "ospf.lsa.length"));
        }
        let body_total = body_len;
        if i + body_total > b.len() {
            return Err(ParseError::truncated("ospf.lsa.body"));
        }
        let body = b[i + LsaHeader::LEN..i + body_total].to_vec();
        lsas.push(Lsa { header: h, body });
        i += body_total;
    }
    Ok(LsUpdateBody {
        lsa_count: lsa_count as u32,
        lsas,
    })
}

fn decode_lsack(b: &[u8], version: OspfVersion) -> Result<LsAckBody, ParseError> {
    let mut lsa_headers = Vec::new();
    let mut i = 0;
    while i + LsaHeader::LEN <= b.len() {
        let h = decode_lsa_header(&b[i..i + LsaHeader::LEN], version)?;
        lsa_headers.push(h);
        i += LsaHeader::LEN;
    }
    Ok(LsAckBody { lsa_headers })
}

fn decode_lsa_header(b: &[u8], version: OspfVersion) -> Result<LsaHeader, ParseError> {
    if b.len() < LsaHeader::LEN {
        return Err(ParseError::truncated("ospf.lsa.header"));
    }
    let (options, ls_type) = if version == OspfVersion::V2 {
        (b[2], u16::from(b[3]))
    } else {
        // RFC 5340 §A.4.2: bytes 2-3 are the full 16-bit LS type; there
        // is no options byte in the v3 LSA header.
        (0u8, u16::from_be_bytes([b[2], b[3]]))
    };
    Ok(LsaHeader {
        ls_age: u16::from_be_bytes([b[0], b[1]]),
        options,
        ls_type,
        link_state_id: u32::from_be_bytes([b[4], b[5], b[6], b[7]]),
        advertising_router: u32::from_be_bytes([b[8], b[9], b[10], b[11]]),
        ls_sequence_number: u32::from_be_bytes([b[12], b[13], b[14], b[15]]),
        ls_checksum: u16::from_be_bytes([b[16], b[17]]),
        length: u16::from_be_bytes([b[18], b[19]]),
    })
}

#[cfg(test)]
mod lsreq_wire_tests {
    use super::*;
    use crate::packet::{LsRequestBody, LsRequestEntry, OspfBody, OspfHeader, OspfPacket};

    /// RFC 2328 §A.3.4: one LS-Request entry is 12 bytes on the wire.
    #[test]
    fn lsreq_entry_is_twelve_bytes() {
        let pkt = OspfPacket {
            header: OspfHeader {
                version: 2,
                kind: 3,
                length: 0,
                router_id: 1,
                area_id: 0,
                checksum: 0,
                au_type_or_instance: 0,
                auth_data: 0,
            },
            body: OspfBody::LsRequest(LsRequestBody {
                entries: vec![LsRequestEntry {
                    ls_type: 1,
                    ls_id: 0x0a00_0001,
                    adv_router: 0x0a00_0001,
                }],
            }),
        };
        let mut wire = OspfCodec::v2().encode_vec(&pkt).unwrap();
        assert_eq!(wire.len(), 24 + 12, "header + one 12-byte entry");
        crate::origination::finalize_v2_packet(&mut wire);
        // Round-trip through the streaming decoder.
        let mut codec = OspfCodec::v2();
        let mut r = lr_core::buf::ReadBuf::new(&wire);
        let decoded = lr_core::codec::Decoder::decode(&mut codec, &mut r)
            .unwrap()
            .unwrap();
        match decoded.body {
            OspfBody::LsRequest(req) => {
                assert_eq!(req.entries.len(), 1);
                assert_eq!(req.entries[0].ls_type, 1);
                assert_eq!(req.entries[0].ls_id, 0x0a00_0001);
                assert_eq!(req.entries[0].adv_router, 0x0a00_0001);
            }
            other => panic!("expected LsRequest, got {other:?}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::OspfHeader;

    /// Patch the v2 checksum into an encoded packet so the receive-side
    /// validation (RFC 2328 §8.2) accepts it.
    fn finalized_v2(bytes: &mut Vec<u8>) {
        assert!(crate::origination::finalize_v2_packet(bytes));
    }

    fn header(kind: u8, router_id: u32) -> OspfHeader {
        OspfHeader {
            version: 2,
            kind,
            length: 0,
            router_id,
            area_id: 0,
            checksum: 0,
            au_type_or_instance: 0,
            auth_data: 0,
        }
    }

    #[test]
    fn hello_roundtrip() {
        let codec = OspfCodec::v2();
        let pkt = OspfPacket {
            header: header(1, 0x01020304),
            body: OspfBody::Hello(HelloBody {
                network_mask: 0xffffff00,
                hello_interval: 10,
                options: 0x02,
                priority: 1,
                dead_interval: 40,
                dr: 0,
                bdr: 0,
                neighbors: vec![0x01020304, 0x05060708],
            }),
        };
        let mut bytes = codec.encode_vec(&pkt).unwrap();
        finalized_v2(&mut bytes);
        let mut dec = OspfCodec::v2();
        let pkt2 = dec.decode_slice(&bytes).unwrap().unwrap();
        assert_eq!(pkt2.header.router_id, pkt.header.router_id);
        match pkt2.body {
            OspfBody::Hello(h) => {
                assert_eq!(h.hello_interval, 10);
                assert_eq!(h.options, 0x02);
                assert_eq!(h.neighbors, vec![0x01020304, 0x05060708]);
            }
            _ => panic!("expected Hello"),
        }
    }

    #[test]
    fn empty_lsack_roundtrip() {
        let codec = OspfCodec::v2();
        let pkt = OspfPacket {
            header: header(5, 0x01020304),
            body: OspfBody::LsAck(LsAckBody::default()),
        };
        let mut bytes = codec.encode_vec(&pkt).unwrap();
        finalized_v2(&mut bytes);
        let mut dec = OspfCodec::v2();
        let p2 = dec.decode_slice(&bytes).unwrap().unwrap();
        assert!(matches!(p2.body, OspfBody::LsAck(_)));
    }

    #[test]
    fn lsupdate_roundtrip_preserves_lsa_bytes() {
        // A finalized summary-LSA must survive an encode/decode cycle
        // byte-for-byte, checksum included.
        use crate::abr::{originate_summary_lsa, SummaryDestination};
        use lr_core::addr::Prefix;

        let dest = SummaryDestination::new(Prefix::new_v4([10, 10, 10, 0], 24), 10);
        let lsa = originate_summary_lsa(0x01020304, &dest, None).unwrap();
        let expected = lsa.to_wire();

        let codec = OspfCodec::v2();
        let pkt = OspfPacket {
            header: header(4, 0x01020304),
            body: OspfBody::LsUpdate(LsUpdateBody {
                lsa_count: 1,
                lsas: vec![lsa],
            }),
        };
        let mut bytes = codec.encode_vec(&pkt).unwrap();
        finalized_v2(&mut bytes);
        let mut dec = OspfCodec::v2();
        let p2 = dec.decode_slice(&bytes).unwrap().unwrap();
        match p2.body {
            OspfBody::LsUpdate(u) => {
                assert_eq!(u.lsas.len(), 1);
                assert_eq!(u.lsas[0].to_wire(), expected);
                assert!(u.lsas[0].checksum_ok());
            }
            _ => panic!("expected LS Update"),
        }
    }

    // ------------------------------------------------------------------
    // OSPFv3 codec tests (RFC 5340) — previously untested (audit M1).
    // ------------------------------------------------------------------

    fn v3_header(kind: u8, router_id: u32) -> OspfHeader {
        OspfHeader {
            version: 3,
            kind,
            length: 0,
            router_id,
            area_id: 0,
            checksum: 0,
            au_type_or_instance: 0,
            auth_data: 0,
        }
    }

    #[test]
    fn v3_hello_roundtrip_with_24bit_options_and_interface_id() {
        let codec = OspfCodec::v3();
        let pkt = OspfPacket {
            header: v3_header(1, 0x01020304),
            body: OspfBody::Hello(HelloBody {
                network_mask: 0x0000_0007, // Interface ID (v3 has no mask)
                hello_interval: 10,
                options: 0x00_02_01, // 24-bit v3 options
                priority: 3,
                dead_interval: 40,
                dr: 0x0a00_0001,
                bdr: 0,
                neighbors: vec![0x0a00_0002],
            }),
        };
        let bytes = codec.encode_vec(&pkt).unwrap();
        // v3 Hello: interface-id(4) | hello-interval(2) | options(3) |
        // priority(1) | dead(4) | dr(4) | bdr(4) | neighbors.
        assert_eq!(&bytes[24..28], &[0, 0, 0, 7], "interface id");
        assert_eq!(&bytes[30..33], &[0, 2, 1], "24-bit options at offset 6");
        assert_eq!(bytes[33], 3, "priority at offset 9");
        let mut dec = OspfCodec::v3();
        let p2 = dec.decode_slice(&bytes).unwrap().unwrap();
        match p2.body {
            OspfBody::Hello(h) => {
                assert_eq!(h.network_mask, 7);
                assert_eq!(h.options, 0x0002_01);
                assert_eq!(h.priority, 3);
                assert_eq!(h.dr, 0x0a00_0001);
                assert_eq!(h.neighbors, vec![0x0a00_0002]);
            }
            _ => panic!("expected Hello"),
        }
    }

    #[test]
    fn v3_dbdesc_uses_24bit_options_and_flags_at_offset_5() {
        let codec = OspfCodec::v3();
        let pkt = OspfPacket {
            header: v3_header(2, 0x01020304),
            body: OspfBody::DbDesc(DbDescBody {
                mtu: 1500,
                options: 0x00_02_01,
                flags: 0x07, // I|M|MS
                dd_seq: 0x1122_3344,
                lsa_headers: vec![],
            }),
        };
        let bytes = codec.encode_vec(&pkt).unwrap();
        // v3 DBD fixed body is 10 bytes: mtu(2) | options(3) | flags(1) | dd_seq(4).
        assert_eq!(&bytes[24..26], &1500u16.to_be_bytes());
        assert_eq!(&bytes[26..29], &[0, 2, 1], "24-bit options");
        assert_eq!(bytes[29], 0x07, "flags at offset 5 of the body");
        assert_eq!(&bytes[30..34], &0x1122_3344u32.to_be_bytes(), "dd_seq");
        assert_eq!(bytes.len(), 24 + 10, "no LSA headers");

        let mut dec = OspfCodec::v3();
        let p2 = dec.decode_slice(&bytes).unwrap().unwrap();
        match p2.body {
            OspfBody::DbDesc(d) => {
                assert_eq!(d.mtu, 1500);
                assert_eq!(d.options, 0x0002_01);
                assert_eq!(d.flags, 0x07);
                assert_eq!(d.dd_seq, 0x1122_3344);
            }
            _ => panic!("expected DBD"),
        }
    }

    #[test]
    fn v3_ls_request_uses_16bit_type_at_entry_start() {
        let codec = OspfCodec::v3();
        let pkt = OspfPacket {
            header: v3_header(3, 0x01020304),
            body: OspfBody::LsRequest(LsRequestBody {
                entries: vec![
                    LsRequestEntry {
                        ls_type: 0x2003, // inter-area-prefix
                        ls_id: 1,
                        adv_router: 0x0a00_0002,
                    },
                    LsRequestEntry {
                        ls_type: 0x4005, // AS-external
                        ls_id: 0x0a0a_0a00,
                        adv_router: 0x0a00_0003,
                    },
                ],
            }),
        };
        let bytes = codec.encode_vec(&pkt).unwrap();
        // v3 entry: LS type(2) | Unused(2) | LS ID(4) | Adv Router(4).
        assert_eq!(&bytes[24..26], &0x2003u16.to_be_bytes());
        assert_eq!(&bytes[26..28], &[0, 0], "unused word");
        assert_eq!(&bytes[28..32], &1u32.to_be_bytes());
        assert_eq!(&bytes[36..38], &0x4005u16.to_be_bytes());

        let mut dec = OspfCodec::v3();
        let p2 = dec.decode_slice(&bytes).unwrap().unwrap();
        match p2.body {
            OspfBody::LsRequest(r) => {
                assert_eq!(r.entries.len(), 2);
                assert_eq!(r.entries[0].ls_type, 0x2003);
                assert_eq!(r.entries[0].ls_id, 1);
                assert_eq!(r.entries[1].ls_type, 0x4005);
            }
            _ => panic!("expected LS-Request"),
        }
    }

    #[test]
    fn v3_lsu_carries_full_16bit_lsa_type_on_the_wire() {
        // RFC 5340 §A.4.2: the v3 LSA header has no options byte; the
        // 16-bit LS type occupies header bytes 2-3.
        use crate::abr::{originate_v3_inter_area_prefix_lsa, SummaryDestination};
        use lr_core::addr::Prefix;

        let dest = SummaryDestination::new(
            Prefix::new_v6(
                [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
                64,
            ),
            10,
        );
        let lsa = originate_v3_inter_area_prefix_lsa(0x01020304, 1, &dest, None).unwrap();
        let lsa_wire = lsa.to_wire();
        assert_eq!(
            &lsa_wire[2..4],
            &[0x20, 0x03],
            "v3 inter-area-prefix-LSA must carry type 0x2003 on the wire"
        );

        let codec = OspfCodec::v3();
        let pkt = OspfPacket {
            header: v3_header(4, 0x01020304),
            body: OspfBody::LsUpdate(LsUpdateBody {
                lsa_count: 1,
                lsas: vec![lsa.clone()],
            }),
        };
        let bytes = codec.encode_vec(&pkt).unwrap();
        // The LSU body starts with lsa_count(4), then the raw LSA.
        assert_eq!(&bytes[24 + 4 + 2..24 + 4 + 4], &[0x20, 0x03]);
        let mut dec = OspfCodec::v3();
        let p2 = dec.decode_slice(&bytes).unwrap().unwrap();
        match p2.body {
            OspfBody::LsUpdate(u) => {
                assert_eq!(u.lsas.len(), 1);
                assert_eq!(u.lsas[0].header.ls_type, 0x2003);
                assert_eq!(u.lsas[0].to_wire(), lsa_wire);
            }
            _ => panic!("expected LS-Update"),
        }
    }

    #[test]
    fn v3_lsa_header_decode_reads_full_16bit_type() {
        // A v3 LSA header with type 0x4005 (AS-external) must decode to
        // ls_type == 0x4005 (not the low byte 0x05).
        let mut hdr = [0u8; LsaHeader::LEN];
        hdr[2..4].copy_from_slice(&0x4005u16.to_be_bytes());
        hdr[4..8].copy_from_slice(&0x0a0a_0a00u32.to_be_bytes());
        let h = decode_lsa_header(&hdr, OspfVersion::V3).unwrap();
        assert_eq!(h.options, 0, "v3 LSA header has no options field");
        assert_eq!(h.ls_type, 0x4005);
        // The v2 decoder treats bytes 2-3 as options + 8-bit type.
        let h2 = decode_lsa_header(&hdr, OspfVersion::V2).unwrap();
        assert_eq!(h2.options, 0x40);
        assert_eq!(h2.ls_type, 0x05);
    }

    // ------------------------------------------------------------------
    // Robustness: malformed input must not wedge the decoder (audit C3),
    // and bad v2 checksums are dropped on receive (RFC 2328 §8.2).
    // ------------------------------------------------------------------

    #[test]
    fn decoder_recovers_after_malformed_packet() {
        let mut codec = OspfCodec::v2();
        // A frame declaring a body length that cannot be parsed (kind 99).
        let mut bad = vec![0u8; 24 + 8];
        bad[0] = 2; // version
        bad[1] = 99; // unknown packet type
        bad[2..4].copy_from_slice(&32u16.to_be_bytes()); // length 32
        assert!(codec.decode_slice(&bad).is_err(), "bad frame errors");

        // The decoder must not re-parse the bad frame forever: a valid
        // packet offered afterwards decodes fine.
        let codec_e = OspfCodec::v2();
        let mut pkt = OspfPacket {
            header: header(1, 0x01020304),
            body: OspfBody::Hello(HelloBody {
                network_mask: 0xffffff00,
                hello_interval: 10,
                options: 0x02,
                priority: 1,
                dead_interval: 40,
                dr: 0,
                bdr: 0,
                neighbors: vec![],
            }),
        };
        let mut good = codec_e.encode_vec(&pkt).unwrap();
        finalized_v2(&mut good);
        let p2 = codec.decode_slice(&good).unwrap().expect("recovers");
        assert_eq!(p2.header.kind, 1);
        // And a burst of [bad][good] recovers on the second frame.
        let mut burst = bad;
        burst.extend_from_slice(&good);
        let mut codec2 = OspfCodec::v2();
        assert!(codec2.decode_slice(&burst).is_err(), "first frame bad");
        let p3 = codec2.decode_slice(&[]).unwrap().expect("second frame");
        assert_eq!(p3.header.kind, 1);
    }

    #[test]
    fn bad_v2_checksum_dropped_on_receive() {
        let codec = OspfCodec::v2();
        let pkt = OspfPacket {
            header: header(1, 0x01020304),
            body: OspfBody::Hello(HelloBody {
                network_mask: 0xffffff00,
                hello_interval: 10,
                options: 0x02,
                priority: 1,
                dead_interval: 40,
                dr: 0,
                bdr: 0,
                neighbors: vec![],
            }),
        };
        let mut bytes = codec.encode_vec(&pkt).unwrap();
        finalized_v2(&mut bytes);
        // Flip a body byte: the checksum must no longer verify.
        let last = bytes.len() - 1;
        bytes[last] ^= 0x01;
        let mut dec = OspfCodec::v2();
        assert!(
            dec.decode_slice(&bytes).is_err(),
            "bad checksum packet must be dropped"
        );
    }

    #[test]
    fn v3_packets_are_not_checksum_gated() {
        // v3 uses the IPv6 upper-layer checksum (pseudo-header), which
        // the codec cannot compute; v3 packets pass through unverified.
        let codec = OspfCodec::v3();
        let pkt = OspfPacket {
            header: v3_header(5, 0x01020304),
            body: OspfBody::LsAck(LsAckBody::default()),
        };
        let bytes = codec.encode_vec(&pkt).unwrap();
        let mut dec = OspfCodec::v3();
        assert!(dec.decode_slice(&bytes).unwrap().is_some());
    }
}
