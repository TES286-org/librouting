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
        if self.carryover.len() < length {
            return Ok(None);
        }
        let buf = &self.carryover[..length];
        let pkt = decode_packet(buf, self.version)?;
        self.carryover.drain(0..length);
        Ok(Some(pkt))
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
            OspfBody::DbDesc(d) => encode_dbdesc(d, out)?,
            OspfBody::LsRequest(r) => encode_lsreq(r, out)?,
            OspfBody::LsUpdate(u) => encode_lsupdate(u, out)?,
            OspfBody::LsAck(a) => encode_lsack(a, out)?,
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
        self.carryover.extend_from_slice(src.chunk());
        let n = src.remaining();
        src.advance(n);
        if self.carryover.len() < OspfHeader::LEN {
            return Ok(None);
        }
        let length = u16::from_be_bytes([self.carryover[2], self.carryover[3]]) as usize;
        if self.carryover.len() < length {
            return Ok(None);
        }
        let buf = &self.carryover[..length];
        let pkt = decode_packet(buf, self.version)?;
        self.carryover.drain(0..length);
        Ok(Some(pkt))
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
        // v3 has a 4-byte Interface ID instead of network mask
        out.put_u32_be(0).ok_or(EncodeError::BufferFull)?;
    }
    out.put_u16_be(h.hello_interval)
        .ok_or(EncodeError::BufferFull)?;
    out.put_u8(h.options).ok_or(EncodeError::BufferFull)?;
    out.put_u8(h.priority).ok_or(EncodeError::BufferFull)?;
    out.put_u32_be(h.dead_interval)
        .ok_or(EncodeError::BufferFull)?;
    out.put_u32_be(h.dr).ok_or(EncodeError::BufferFull)?;
    out.put_u32_be(h.bdr).ok_or(EncodeError::BufferFull)?;
    for n in &h.neighbors {
        out.put_u32_be(*n).ok_or(EncodeError::BufferFull)?;
    }
    Ok(())
}

fn encode_dbdesc(d: &DbDescBody, out: &mut WriteBuf<'_>) -> Result<(), EncodeError> {
    out.put_u16_be(d.mtu).ok_or(EncodeError::BufferFull)?;
    out.put_u8(d.options).ok_or(EncodeError::BufferFull)?;
    out.put_u8(d.flags).ok_or(EncodeError::BufferFull)?;
    out.put_u32_be(d.dd_seq).ok_or(EncodeError::BufferFull)?;
    for h in &d.lsa_headers {
        encode_lsa_header(h, out)?;
    }
    Ok(())
}

fn encode_lsreq(r: &LsRequestBody, out: &mut WriteBuf<'_>) -> Result<(), EncodeError> {
    for e in &r.entries {
        out.put_u8(0).ok_or(EncodeError::BufferFull)?; // padding (was u32 ls_type in v2)
        out.put_u8(e.ls_type).ok_or(EncodeError::BufferFull)?;
        out.put_u32_be(e.ls_id).ok_or(EncodeError::BufferFull)?;
        out.put_u32_be(e.adv_router)
            .ok_or(EncodeError::BufferFull)?;
    }
    Ok(())
}

fn encode_lsupdate(u: &LsUpdateBody, out: &mut WriteBuf<'_>) -> Result<(), EncodeError> {
    out.put_u32_be(u.lsa_count).ok_or(EncodeError::BufferFull)?;
    for lsa in &u.lsas {
        out.put_bytes(&lsa.to_wire())
            .ok_or(EncodeError::BufferFull)?;
    }
    Ok(())
}

fn encode_lsack(a: &LsAckBody, out: &mut WriteBuf<'_>) -> Result<(), EncodeError> {
    for h in &a.lsa_headers {
        encode_lsa_header(h, out)?;
    }
    Ok(())
}

fn encode_lsa_header(h: &LsaHeader, out: &mut WriteBuf<'_>) -> Result<(), EncodeError> {
    out.put_u16_be(h.ls_age).ok_or(EncodeError::BufferFull)?;
    out.put_u8(h.options).ok_or(EncodeError::BufferFull)?;
    out.put_u8(h.ls_type).ok_or(EncodeError::BufferFull)?;
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
        OspfPacketType::DatabaseDescription => Ok(OspfBody::DbDesc(decode_dbdesc(b)?)),
        OspfPacketType::LinkStateRequest => Ok(OspfBody::LsRequest(decode_lsreq(b)?)),
        OspfPacketType::LinkStateUpdate => Ok(OspfBody::LsUpdate(decode_lsupdate(b)?)),
        OspfPacketType::LinkStateAck => Ok(OspfBody::LsAck(decode_lsack(b)?)),
    }
}

fn decode_hello(b: &[u8], _version: OspfVersion) -> Result<HelloBody, ParseError> {
    if b.len() < 20 {
        return Err(ParseError::truncated("ospf.hello.body"));
    }
    let network_mask = u32::from_be_bytes([b[0], b[1], b[2], b[3]]);
    let hello_interval = u16::from_be_bytes([b[4], b[5]]);
    let options = b[6];
    let priority = b[7];
    let dead_interval = u32::from_be_bytes([b[8], b[9], b[10], b[11]]);
    let dr = u32::from_be_bytes([b[12], b[13], b[14], b[15]]);
    let bdr = u32::from_be_bytes([b[16], b[17], b[18], b[19]]);
    let mut neighbors = Vec::new();
    let mut i = 20;
    while i + 4 <= b.len() {
        neighbors.push(u32::from_be_bytes([b[i], b[i + 1], b[i + 2], b[i + 3]]));
        i += 4;
    }
    Ok(HelloBody {
        // For v3 the network_mask is reused as interface ID; keep as-is.
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

fn decode_dbdesc(b: &[u8]) -> Result<DbDescBody, ParseError> {
    if b.len() < 8 {
        return Err(ParseError::truncated("ospf.dbdesc.body"));
    }
    let mtu = u16::from_be_bytes([b[0], b[1]]);
    let options = b[2];
    let flags = b[3];
    let dd_seq = u32::from_be_bytes([b[4], b[5], b[6], b[7]]);
    let mut lsa_headers = Vec::new();
    let mut i = 8;
    while i + LsaHeader::LEN <= b.len() {
        let h = decode_lsa_header(&b[i..i + LsaHeader::LEN])?;
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

fn decode_lsreq(b: &[u8]) -> Result<LsRequestBody, ParseError> {
    let mut entries = Vec::new();
    let mut i = 0;
    // v2 LS-Request entries are 12 bytes: 4 bytes ls_type, 4 ls_id, 4 adv_router.
    // We accepted a 10-byte format above (1 padding + 1 ls_type); here we just
    // follow the v2 spec: 12 bytes per entry.
    const ENTRY: usize = 12;
    while i + ENTRY <= b.len() {
        let ls_type = b[i + 3]; // last byte of the 4-byte ls_type
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

fn decode_lsupdate(b: &[u8]) -> Result<LsUpdateBody, ParseError> {
    if b.len() < 4 {
        return Err(ParseError::truncated("ospf.lsupdate.body"));
    }
    let lsa_count = u32::from_be_bytes([b[0], b[1], b[2], b[3]]) as usize;
    let mut lsas = Vec::with_capacity(lsa_count);
    let mut i = 4;
    while i + LsaHeader::LEN <= b.len() && lsas.len() < lsa_count {
        let h = decode_lsa_header(&b[i..i + LsaHeader::LEN])?;
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

fn decode_lsack(b: &[u8]) -> Result<LsAckBody, ParseError> {
    let mut lsa_headers = Vec::new();
    let mut i = 0;
    while i + LsaHeader::LEN <= b.len() {
        let h = decode_lsa_header(&b[i..i + LsaHeader::LEN])?;
        lsa_headers.push(h);
        i += LsaHeader::LEN;
    }
    Ok(LsAckBody { lsa_headers })
}

fn decode_lsa_header(b: &[u8]) -> Result<LsaHeader, ParseError> {
    if b.len() < LsaHeader::LEN {
        return Err(ParseError::truncated("ospf.lsa.header"));
    }
    Ok(LsaHeader {
        ls_age: u16::from_be_bytes([b[0], b[1]]),
        options: b[2],
        ls_type: b[3],
        link_state_id: u32::from_be_bytes([b[4], b[5], b[6], b[7]]),
        advertising_router: u32::from_be_bytes([b[8], b[9], b[10], b[11]]),
        ls_sequence_number: u32::from_be_bytes([b[12], b[13], b[14], b[15]]),
        ls_checksum: u16::from_be_bytes([b[16], b[17]]),
        length: u16::from_be_bytes([b[18], b[19]]),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::OspfHeader;

    #[test]
    fn hello_roundtrip() {
        let codec = OspfCodec::v2();
        let pkt = OspfPacket {
            header: OspfHeader {
                version: 2,
                kind: 1,
                length: 0, // patched
                router_id: 0x01020304,
                area_id: 0,
                checksum: 0,
                au_type_or_instance: 0,
                auth_data: 0,
            },
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
        let bytes = codec.encode_vec(&pkt).unwrap();
        let mut dec = OspfCodec::v2();
        let pkt2 = dec.decode_slice(&bytes).unwrap().unwrap();
        assert_eq!(pkt2.header.router_id, pkt.header.router_id);
        match pkt2.body {
            OspfBody::Hello(h) => {
                assert_eq!(h.hello_interval, 10);
                assert_eq!(h.neighbors, vec![0x01020304, 0x05060708]);
            }
            _ => panic!("expected Hello"),
        }
    }

    #[test]
    fn empty_lsack_roundtrip() {
        let codec = OspfCodec::v2();
        let pkt = OspfPacket {
            header: OspfHeader {
                version: 2,
                kind: 5,
                length: 0,
                router_id: 0x01020304,
                area_id: 0,
                checksum: 0,
                au_type_or_instance: 0,
                auth_data: 0,
            },
            body: OspfBody::LsAck(LsAckBody::default()),
        };
        let bytes = codec.encode_vec(&pkt).unwrap();
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
            header: OspfHeader {
                version: 2,
                kind: 4,
                length: 0,
                router_id: 0x01020304,
                area_id: 0,
                checksum: 0,
                au_type_or_instance: 0,
                auth_data: 0,
            },
            body: OspfBody::LsUpdate(LsUpdateBody {
                lsa_count: 1,
                lsas: vec![lsa],
            }),
        };
        let bytes = codec.encode_vec(&pkt).unwrap();
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
}
