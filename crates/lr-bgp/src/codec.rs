//! BGP message codec.
//!
//! Implements [`lr_core::codec::Codec`] for [`BgpMessage`]. The decoder is
//! streaming — it returns `Ok(None)` when the buffer doesn't yet contain a
//! complete message.
//!
//! # Wire format
//!
//! Every BGP message has a 19-byte header (RFC 4271 §4.1):
//! - 16 bytes marker (`0xffffffffffffffffffffffffffffffff`)
//! - 2 bytes total length (big-endian, [19, 4096])
//! - 1 byte message type
//!
//! Then the message body.

use crate::error::{BgpError, BgpNotification};
use crate::message::{
    keepalive::Keepalive,
    open::{Open, OpenParam},
    route_refresh::RouteRefresh,
    update::{Nlri, Update},
    BgpHeader, BgpMessage, BgpMessageType,
};
use crate::path::{AttrType, PathAttrFlags, PathAttribute, PathAttributes};

use lr_core::addr::{IpAddr, Prefix};
use lr_core::buf::{ReadBuf, WriteBuf};
use lr_core::codec::{Decoder, Encoder};
use lr_core::error::EncodeError;
use lr_core::nlri::NlriFamily;

/// BGP-4 message codec. Stateless encoder + stateful decoder (carryover).
///
/// Add-Path (RFC 7911) is a negotiated, per-address-family NLRI framing
/// change: once the OPEN exchange completes, `add_path_tx` lists the
/// families whose outbound NLRI carries 4-octet path identifiers and
/// `add_path_rx` the families whose inbound NLRI does. Both default to
/// empty (plain single-path framing).
#[derive(Default)]
pub struct BgpCodec {
    /// Carryover buffer for partial frames.
    carryover: Vec<u8>,
    /// True if the OPEN has been negotiated and 4-byte AS is in use.
    asn4: bool,
    /// Address families whose outbound NLRI entries carry RFC 7911 path
    /// identifiers (we advertise multiple paths to the peer).
    add_path_tx: Vec<NlriFamily>,
    /// Address families whose inbound NLRI entries carry RFC 7911 path
    /// identifiers (the peer advertises multiple paths to us).
    add_path_rx: Vec<NlriFamily>,
}

impl BgpCodec {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_asn4(mut self, v: bool) -> Self {
        self.asn4 = v;
        self
    }

    pub fn set_asn4(&mut self, v: bool) {
        self.asn4 = v;
    }

    /// Set the address families whose NLRI carries RFC 7911 path
    /// identifiers in each direction (call after OPEN negotiation).
    pub fn set_add_path(&mut self, tx: Vec<NlriFamily>, rx: Vec<NlriFamily>) {
        self.add_path_tx = tx;
        self.add_path_rx = rx;
    }

    fn tx_add_path(&self, family: NlriFamily) -> bool {
        self.add_path_tx.contains(&family)
    }

    fn rx_add_path(&self, family: NlriFamily) -> bool {
        self.add_path_rx.contains(&family)
    }

    /// Direct decode of a complete frame from a slice. Returns None if the
    /// slice doesn't contain a full frame.
    pub fn decode_slice(&mut self, buf: &[u8]) -> Result<Option<BgpMessage>, BgpError> {
        // Append incoming bytes to the carryover, then attempt decode.
        self.carryover.extend_from_slice(buf);
        let rx_v4 = self.rx_add_path(NlriFamily::IPV4_UNICAST);
        let consumed = match try_decode_frame(&self.carryover, rx_v4)? {
            Some((n, msg)) => {
                // Drain the consumed prefix.
                self.carryover.drain(0..n);
                return Ok(Some(msg));
            }
            None => 0,
        };
        let _ = consumed;
        Ok(None)
    }

    /// Direct encode of a message to a fresh Vec.
    pub fn encode_vec(&self, msg: &BgpMessage) -> Result<Vec<u8>, EncodeError> {
        let mut buf = vec![0u8; 4096];
        let mut w = WriteBuf::new(&mut buf);
        let n = self.encode(msg, &mut w)?;
        buf.truncate(n);
        Ok(buf)
    }
}

const MARKER: [u8; 16] = [0xff; 16];

const MIN_LEN: u16 = 19;
const MAX_LEN: u16 = 4096;

/// Attempt to decode one frame from `buf`. Returns `Ok(Some((consumed, msg)))`
/// on success, `Ok(None)` when the buffer doesn't yet contain a full frame,
/// and `Err(BgpError)` on a protocol-level parse failure.
///
/// `rx_v4_add_path` selects the RFC 7911 framing (4-octet path identifier
/// ahead of each prefix) for the plain IPv4 NLRI/withdrawn sections.
fn try_decode_frame(
    buf: &[u8],
    rx_v4_add_path: bool,
) -> Result<Option<(usize, BgpMessage)>, BgpError> {
    if buf.len() < BgpHeader::LEN {
        return Ok(None);
    }
    if buf[0..16] != MARKER {
        return Err(BgpError::Notification(BgpNotification::new(
            crate::error::BgpErrorCode::Header as u8,
            crate::error::BgpHeaderErrorSubcode::ConnectionNotSynchronized as u8,
            buf[..16].iter().take(4).copied().collect(),
        )));
    }
    let len = u16::from_be_bytes([buf[16], buf[17]]);
    if !(MIN_LEN..=MAX_LEN).contains(&len) {
        return Err(BgpError::Notification(BgpNotification::new(
            crate::error::BgpErrorCode::Header as u8,
            crate::error::BgpHeaderErrorSubcode::BadMessageLength as u8,
            len.to_be_bytes().to_vec(),
        )));
    }
    if buf.len() < len as usize {
        return Ok(None);
    }
    let kind = buf[18];
    let body_len = (len as usize) - BgpHeader::LEN;
    let body = &buf[BgpHeader::LEN..BgpHeader::LEN + body_len];
    let msg = decode_body(kind, body, rx_v4_add_path)?;
    Ok(Some((len as usize, msg)))
}

impl Encoder<BgpMessage> for BgpCodec {
    fn encode(&self, msg: &BgpMessage, out: &mut WriteBuf<'_>) -> Result<usize, EncodeError> {
        if out.remaining_mut() < (BgpHeader::LEN + 8) {
            return Err(EncodeError::BufferFull);
        }
        let start = out.position();
        out.put_bytes(&MARKER).ok_or(EncodeError::BufferFull)?;
        let len_pos = out.reserve(2).ok_or(EncodeError::BufferFull)?;
        out.put_u8(msg.kind() as u8)
            .ok_or(EncodeError::BufferFull)?;
        match msg {
            BgpMessage::Open(o) => encode_open(o, out)?,
            BgpMessage::Update(u) => {
                encode_update(u, self.tx_add_path(NlriFamily::IPV4_UNICAST), out)?
            }
            BgpMessage::Notification(n) => encode_notification(n, out)?,
            BgpMessage::Keepalive(_) => {}
            BgpMessage::RouteRefresh(r) => encode_route_refresh(r, out)?,
        }
        let total = out.position() - start;
        out.patch(len_pos, &(total as u16).to_be_bytes())
            .ok_or(EncodeError::BufferFull)?;
        Ok(total)
    }
}

impl Decoder<BgpMessage> for BgpCodec {
    fn decode(
        &mut self,
        src: &mut ReadBuf<'_>,
    ) -> Result<Option<BgpMessage>, lr_core::error::ParseError> {
        // Append the slice into carryover and try decode.
        self.carryover.extend_from_slice(src.chunk());
        let rx_v4 = self.rx_add_path(NlriFamily::IPV4_UNICAST);
        let result = try_decode_frame(&self.carryover, rx_v4).map_err(|e| match e {
            BgpError::Notification(n) => {
                lr_core::error::ParseError::invalid(BgpHeader::LEN, "bgp.body.notification")
                    .with_detail(format!("code={} sub={}", n.error_code, n.error_subcode))
            }
            BgpError::Truncated => lr_core::error::ParseError::truncated("bgp.body"),
            BgpError::Codec(s) => {
                lr_core::error::ParseError::invalid(BgpHeader::LEN, "bgp.body").with_detail(s)
            }
        })?;
        match result {
            Some((n, msg)) => {
                self.carryover.drain(0..n);
                // Reflect consumption on the caller's source buffer too.
                let consume = src.remaining().min(n);
                src.advance(consume);
                Ok(Some(msg))
            }
            None => {
                // Source bytes already appended to carryover; mark them consumed
                // in the caller's view to prevent double-counting.
                let consume = src.remaining();
                src.advance(consume);
                Ok(None)
            }
        }
    }
}

fn decode_body(kind: u8, body: &[u8], rx_v4_add_path: bool) -> Result<BgpMessage, BgpError> {
    let kind = BgpMessageType::from_u8(kind).ok_or_else(|| {
        BgpError::Notification(BgpNotification::new(
            crate::error::BgpErrorCode::Header as u8,
            crate::error::BgpHeaderErrorSubcode::BadMessageType as u8,
            vec![kind],
        ))
    })?;
    match kind {
        BgpMessageType::Open => Ok(BgpMessage::Open(decode_open(body)?)),
        BgpMessageType::Update => Ok(BgpMessage::Update(decode_update(body, rx_v4_add_path)?)),
        BgpMessageType::Notification => Ok(BgpMessage::Notification(decode_notification(body))),
        BgpMessageType::Keepalive => {
            if !body.is_empty() {
                return Err(BgpError::Codec(format!(
                    "KEEPALIVE body must be empty (got {} bytes)",
                    body.len()
                )));
            }
            Ok(BgpMessage::Keepalive(Keepalive))
        }
        BgpMessageType::RouteRefresh => Ok(BgpMessage::RouteRefresh(decode_route_refresh(body)?)),
    }
}

fn decode_open(body: &[u8]) -> Result<Open, BgpError> {
    if body.len() < 10 {
        return Err(BgpError::Notification(BgpNotification::new(
            crate::error::BgpErrorCode::Open as u8,
            crate::error::BgpOpenErrorSubcode::BadOpenLength as u8,
            vec![],
        )));
    }
    let version = body[0];
    let my_as = lr_core::addr::Asn(u16::from_be_bytes([body[1], body[2]]) as u32);
    let hold_time = u16::from_be_bytes([body[3], body[4]]);
    let bgp_id = lr_core::addr::RouterId(u32::from_be_bytes([body[5], body[6], body[7], body[8]]));
    let params_len = body[9] as usize;
    if body.len() < 10 + params_len {
        return Err(BgpError::Notification(BgpNotification::new(
            crate::error::BgpErrorCode::Open as u8,
            crate::error::BgpOpenErrorSubcode::BadOpenLength as u8,
            vec![],
        )));
    }
    let mut params = Vec::new();
    let mut i = 10;
    let end = 10 + params_len;
    while i + 2 <= end {
        let pt = body[i];
        let pl = body[i + 1] as usize;
        i += 2;
        if i + pl > body.len() {
            break;
        }
        params.push(OpenParam {
            param_type: pt,
            value: body[i..i + pl].to_vec(),
        });
        i += pl;
    }
    Ok(Open {
        version,
        my_as,
        hold_time,
        bgp_id,
        params,
    })
}

fn decode_update(body: &[u8], rx_v4_add_path: bool) -> Result<Update, BgpError> {
    if body.len() < 4 {
        return Err(BgpError::Notification(BgpNotification::new(
            crate::error::BgpErrorCode::Update as u8,
            crate::error::BgpUpdateErrorSubcode::MalformedAttributeList as u8,
            vec![],
        )));
    }
    let withdrawn_len = u16::from_be_bytes([body[0], body[1]]) as usize;
    if 2 + withdrawn_len > body.len() {
        return Err(BgpError::Notification(BgpNotification::new(
            crate::error::BgpErrorCode::Update as u8,
            crate::error::BgpUpdateErrorSubcode::MalformedAttributeList as u8,
            vec![],
        )));
    }
    let withdrawn_bytes = &body[2..2 + withdrawn_len];
    let withdrawn = decode_nlri_set(withdrawn_bytes, rx_v4_add_path).map_err(BgpError::Codec)?;
    let mut i = 2 + withdrawn_len;
    if i + 2 > body.len() {
        return Err(BgpError::Notification(BgpNotification::new(
            crate::error::BgpErrorCode::Update as u8,
            crate::error::BgpUpdateErrorSubcode::MalformedAttributeList as u8,
            vec![],
        )));
    }
    let attr_len = u16::from_be_bytes([body[i], body[i + 1]]) as usize;
    i += 2;
    if i + attr_len > body.len() {
        return Err(BgpError::Notification(BgpNotification::new(
            crate::error::BgpErrorCode::Update as u8,
            crate::error::BgpUpdateErrorSubcode::AttributeLengthError as u8,
            vec![],
        )));
    }
    let attr_bytes = &body[i..i + attr_len];
    let attributes = decode_path_attributes(attr_bytes)?;
    i += attr_len;
    let nlri = decode_nlri_set(&body[i..], rx_v4_add_path).map_err(BgpError::Codec)?;
    Ok(Update {
        withdrawn,
        attributes,
        nlri,
    })
}

/// Decode the plain IPv4 NLRI section. With RFC 7911 Add-Path active each
/// entry is `<path-id:4, prefix-len:1, prefix>`; otherwise `<prefix-len:1,
/// prefix>`.
fn decode_nlri_set(bytes: &[u8], add_path: bool) -> Result<Vec<Nlri>, String> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        let path_id = if add_path {
            if i + 4 > bytes.len() {
                return Err(format!("truncated NLRI at offset {}", i));
            }
            let id = u32::from_be_bytes([bytes[i], bytes[i + 1], bytes[i + 2], bytes[i + 3]]);
            i += 4;
            id
        } else {
            0
        };
        let pl = bytes[i];
        i += 1;
        let n = (pl as usize).div_ceil(8);
        if i + n > bytes.len() {
            return Err(format!("truncated NLRI at offset {}", i));
        }
        let mut a = [0u8; 4];
        a[..n].copy_from_slice(&bytes[i..i + n]);
        i += n;
        out.push(Nlri::new(path_id, Prefix::new_v4(a, pl)));
    }
    Ok(out)
}

fn decode_path_attributes(bytes: &[u8]) -> Result<PathAttributes, BgpError> {
    let mut out = PathAttributes::new();
    let mut i = 0;
    while i < bytes.len() {
        if i + 3 > bytes.len() {
            return Err(BgpError::Notification(BgpNotification::new(
                crate::error::BgpErrorCode::Update as u8,
                crate::error::BgpUpdateErrorSubcode::AttributeLengthError as u8,
                vec![],
            )));
        }
        let flags = PathAttrFlags(bytes[i]);
        let ty_byte = bytes[i + 1];
        let len_size = if flags.extended_length() { 2 } else { 1 };
        let attr_len = if flags.extended_length() {
            if i + 4 > bytes.len() {
                return Err(BgpError::Notification(BgpNotification::new(
                    crate::error::BgpErrorCode::Update as u8,
                    crate::error::BgpUpdateErrorSubcode::AttributeLengthError as u8,
                    vec![],
                )));
            }
            u16::from_be_bytes([bytes[i + 2], bytes[i + 3]]) as usize
        } else {
            bytes[i + 2] as usize
        };
        let value_start = i + 2 + len_size;
        if value_start + attr_len > bytes.len() {
            return Err(BgpError::Notification(BgpNotification::new(
                crate::error::BgpErrorCode::Update as u8,
                crate::error::BgpUpdateErrorSubcode::AttributeLengthError as u8,
                vec![],
            )));
        }
        let value = bytes[value_start..value_start + attr_len].to_vec();
        out.insert(PathAttribute {
            flags,
            attr_type: AttrType::from_u8(ty_byte),
            value,
        });
        i = value_start + attr_len;
    }
    Ok(out)
}

fn decode_notification(body: &[u8]) -> BgpNotification {
    if body.len() < 2 {
        return BgpNotification::new(0, 0, body.to_vec());
    }
    let code = body[0];
    let sub = body[1];
    let data = body.get(2..).unwrap_or(&[]).to_vec();
    BgpNotification::new(code, sub, data)
}

fn decode_route_refresh(body: &[u8]) -> Result<RouteRefresh, BgpError> {
    if body.len() < 4 {
        return Err(BgpError::Codec(format!(
            "ROUTE-REFRESH body too short: {}",
            body.len()
        )));
    }
    let afi = u16::from_be_bytes([body[0], body[1]]);
    if body.len() != 4 {
        return Err(BgpError::Codec(format!(
            "invalid ROUTE-REFRESH body length: {}",
            body.len()
        )));
    }
    let subtype = crate::message::RouteRefreshSubtype::from_u8(body[2])
        .ok_or_else(|| BgpError::Codec(format!("invalid ROUTE-REFRESH subtype: {}", body[2])))?;
    let safi = body[3];
    Ok(RouteRefresh {
        family: NlriFamily { afi, safi },
        subtype,
    })
}

// ===== Encoders =====

fn encode_open(o: &Open, out: &mut WriteBuf<'_>) -> Result<(), EncodeError> {
    out.put_u8(o.version).ok_or(EncodeError::BufferFull)?;
    let as16 = o.my_as.as_u16().unwrap_or(23456);
    out.put_u16_be(as16).ok_or(EncodeError::BufferFull)?;
    out.put_u16_be(o.hold_time).ok_or(EncodeError::BufferFull)?;
    out.put_bytes(&o.bgp_id.to_v4_bytes())
        .ok_or(EncodeError::BufferFull)?;
    let params_pos = out.reserve(1).ok_or(EncodeError::BufferFull)?;
    let start = out.position();
    for p in &o.params {
        out.put_u8(p.param_type).ok_or(EncodeError::BufferFull)?;
        out.put_u8(p.value.len() as u8)
            .ok_or(EncodeError::BufferFull)?;
        out.put_bytes(&p.value).ok_or(EncodeError::BufferFull)?;
    }
    let plen = (out.position() - start) as u8;
    out.patch(params_pos, &[plen])
        .ok_or(EncodeError::BufferFull)?;
    Ok(())
}

fn encode_update(
    u: &Update,
    tx_v4_add_path: bool,
    out: &mut WriteBuf<'_>,
) -> Result<(), EncodeError> {
    let withdrawn_len_pos = out.reserve(2).ok_or(EncodeError::BufferFull)?;
    let withdrawn_start = out.position();
    for w in &u.withdrawn {
        encode_nlri(w, tx_v4_add_path, out)?;
    }
    let wlen = (out.position() - withdrawn_start) as u16;
    out.patch(withdrawn_len_pos, &wlen.to_be_bytes())
        .ok_or(EncodeError::BufferFull)?;

    let attr_len_pos = out.reserve(2).ok_or(EncodeError::BufferFull)?;
    let attr_start = out.position();
    for a in u.attributes.iter() {
        // The private LrMplsLabelStack tag carries the RFC 8277 label
        // stack inside the Loc-RIB only — it is never sent on the wire
        // (the labels live in the NLRI). Skip it during encode.
        if a.attr_type == crate::path::AttrType::LrMplsLabelStack {
            continue;
        }
        encode_path_attribute(a, out)?;
    }
    let alen = (out.position() - attr_start) as u16;
    out.patch(attr_len_pos, &alen.to_be_bytes())
        .ok_or(EncodeError::BufferFull)?;

    for n in &u.nlri {
        encode_nlri(n, tx_v4_add_path, out)?;
    }
    Ok(())
}

/// Encode one NLRI entry into the plain IPv4 section. With RFC 7911
/// Add-Path active the 4-octet path identifier precedes the prefix.
fn encode_nlri(entry: &Nlri, add_path: bool, out: &mut WriteBuf<'_>) -> Result<(), EncodeError> {
    let p = &entry.prefix;
    if !p.is_ipv4() {
        return Err(EncodeError::InvalidValue(
            "NLRI in legacy section must be IPv4",
        ));
    }
    if add_path {
        out.put_u32_be(entry.path_id)
            .ok_or(EncodeError::BufferFull)?;
    }
    out.put_u8(p.prefix_len).ok_or(EncodeError::BufferFull)?;
    let n = (p.prefix_len as usize).div_ceil(8);
    let bytes = match &p.addr {
        IpAddr::V4(b) => b,
        _ => unreachable!(),
    };
    out.put_bytes(&bytes[..n]).ok_or(EncodeError::BufferFull)?;
    Ok(())
}

fn encode_path_attribute(a: &PathAttribute, out: &mut WriteBuf<'_>) -> Result<(), EncodeError> {
    let mut flags = a.flags;
    if a.value.len() > 255 {
        flags = flags.set_extended(true);
    }
    out.put_u8(flags.0).ok_or(EncodeError::BufferFull)?;
    out.put_u8(a.attr_type.to_u8())
        .ok_or(EncodeError::BufferFull)?;
    if flags.extended_length() {
        out.put_u16_be(a.value.len() as u16)
            .ok_or(EncodeError::BufferFull)?;
    } else {
        out.put_u8(a.value.len() as u8)
            .ok_or(EncodeError::BufferFull)?;
    }
    out.put_bytes(&a.value).ok_or(EncodeError::BufferFull)?;
    Ok(())
}

fn encode_notification(n: &BgpNotification, out: &mut WriteBuf<'_>) -> Result<(), EncodeError> {
    out.put_u8(n.error_code).ok_or(EncodeError::BufferFull)?;
    out.put_u8(n.error_subcode).ok_or(EncodeError::BufferFull)?;
    out.put_bytes(&n.data).ok_or(EncodeError::BufferFull)?;
    Ok(())
}

fn encode_route_refresh(r: &RouteRefresh, out: &mut WriteBuf<'_>) -> Result<(), EncodeError> {
    out.put_u16_be(r.family.afi)
        .ok_or(EncodeError::BufferFull)?;
    out.put_u8(r.subtype as u8).ok_or(EncodeError::BufferFull)?;
    out.put_u8(r.family.safi).ok_or(EncodeError::BufferFull)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capabilities::Capability;
    use crate::path::{AsPath, AttrType, Med, Origin, OriginKind, PathAttrFlags, PathAttribute};
    use lr_core::addr::{Asn, RouterId};

    fn roundtrip(msg: BgpMessage, asn4: bool) -> BgpMessage {
        let codec = BgpCodec::new().with_asn4(asn4);
        let bytes = codec.encode_vec(&msg).unwrap();
        let mut c2 = BgpCodec::new().with_asn4(asn4);
        c2.decode_slice(&bytes).unwrap().unwrap()
    }

    /// RFC 7911 §4.3: encode and decode an UPDATE whose IPv4 NLRI and
    /// withdrawn sections carry 4-octet path identifiers. The framing only
    /// roundtrips when both sides use the negotiated mode.
    #[test]
    fn update_add_path_roundtrip() {
        let mut u = Update::new();
        u.nlri
            .push(Nlri::new(1, Prefix::new_v4([203, 0, 113, 0], 24)));
        u.nlri
            .push(Nlri::new(2, Prefix::new_v4([203, 0, 113, 0], 24)));
        u.withdrawn
            .push(Nlri::new(7, Prefix::new_v4([198, 51, 100, 0], 24)));
        u.attributes.insert(PathAttribute::new(
            PathAttrFlags::new().set_transitive(true),
            AttrType::Origin,
            vec![0],
        ));

        let mut tx = BgpCodec::new().with_asn4(true);
        tx.set_add_path(vec![NlriFamily::IPV4_UNICAST], vec![]);
        let bytes = tx.encode_vec(&BgpMessage::Update(u.clone())).unwrap();
        // Each of the three entries carries 4 extra identifier octets.
        let plain = BgpCodec::new()
            .with_asn4(true)
            .encode_vec(&BgpMessage::Update(u.clone()))
            .unwrap();
        assert_eq!(bytes.len(), plain.len() + 12);

        let mut rx = BgpCodec::new().with_asn4(true);
        rx.set_add_path(
            vec![NlriFamily::IPV4_UNICAST],
            vec![NlriFamily::IPV4_UNICAST],
        );
        match rx.decode_slice(&bytes).unwrap().unwrap() {
            BgpMessage::Update(d) => {
                assert_eq!(d.nlri.len(), 2);
                assert_eq!(d.nlri[0].path_id, 1);
                assert_eq!(d.nlri[1].path_id, 2);
                assert_eq!(d.withdrawn[0].path_id, 7);
            }
            _ => panic!("expected UPDATE"),
        }

        // Without the negotiated mode the same bytes misparse (the
        // identifier octets are read as prefix data).
        let mut blind = BgpCodec::new().with_asn4(true);
        let mis = blind.decode_slice(&bytes);
        assert!(
            mis.is_err()
                || !matches!(&mis.unwrap().unwrap(), BgpMessage::Update(d)
                if d.nlri.iter().all(|n| n.path_id == 0) && d.nlri.len() == 2),
            "add-path bytes must not decode as clean single-path NLRI"
        );
    }

    #[test]
    fn keepalive_roundtrip() {
        let m = BgpMessage::Keepalive(Keepalive);
        let dec = roundtrip(m, false);
        assert!(matches!(dec, BgpMessage::Keepalive(_)));
    }

    #[test]
    fn open_roundtrip() {
        let mut open = Open::new(Asn(64513), 90, RouterId::from_v4([10, 0, 0, 1]));
        open.params.push(OpenParam {
            param_type: OpenParam::PARAM_TYPE_CAPABILITY,
            value: Capability::encode_set(&[
                Capability::four_octet_as(70000),
                Capability::multiprotocol(2, 1),
            ]),
        });
        let m = BgpMessage::Open(open.clone());
        let dec = roundtrip(m, true);
        match dec {
            BgpMessage::Open(o) => {
                assert_eq!(o.my_as, Asn(64513));
                assert_eq!(o.hold_time, 90);
                assert_eq!(o.bgp_id, RouterId::from_v4([10, 0, 0, 1]));
                assert_eq!(o.params.len(), 1);
                let caps = Capability::decode_set(&o.params[0].value);
                assert_eq!(caps.len(), 2);
                assert_eq!(caps[0].as_four_octet(), Some(70000));
                assert_eq!(caps[1].as_multiprotocol(), Some((2, 1)));
            }
            _ => panic!("expected OPEN"),
        }
    }

    #[test]
    fn update_with_attributes() {
        let mut u = Update::new();
        u.attributes.insert(PathAttribute::new(
            PathAttrFlags::new().set_transitive(true),
            AttrType::Origin,
            vec![OriginKind::Igp as u8],
        ));
        u.attributes.insert(PathAttribute::new(
            PathAttrFlags::new().set_transitive(true),
            AttrType::AsPath,
            AsPath::from_sequence([Asn(100), Asn(200)]).encode_4(),
        ));
        u.attributes.insert(PathAttribute::new(
            PathAttrFlags::new().set_transitive(true),
            AttrType::NextHop,
            vec![10, 0, 0, 1],
        ));
        u.attributes.insert(PathAttribute::new(
            PathAttrFlags::new().set_optional(true),
            AttrType::MultiExitDisc,
            Med(100).encode().to_vec(),
        ));
        u.nlri
            .push(Nlri::plain(Prefix::new_v4([192, 168, 1, 0], 24)));

        let m = BgpMessage::Update(u.clone());
        let dec = roundtrip(m, true);
        match dec {
            BgpMessage::Update(d) => {
                assert_eq!(d.nlri.len(), 1);
                assert_eq!(d.nlri[0].prefix.prefix_len, 24);
                assert_eq!(d.attributes.origin(), Some(Origin::new(OriginKind::Igp)));
                assert!(d.attributes.as_path().is_some());
            }
            _ => panic!("expected UPDATE"),
        }
    }

    #[test]
    fn update_withdrawn() {
        let mut u = Update::new();
        u.withdrawn
            .push(Nlri::plain(Prefix::new_v4([10, 0, 0, 0], 8)));
        u.withdrawn
            .push(Nlri::plain(Prefix::new_v4([192, 168, 0, 0], 16)));
        let m = BgpMessage::Update(u.clone());
        let dec = roundtrip(m, false);
        match dec {
            BgpMessage::Update(d) => {
                assert_eq!(d.withdrawn.len(), 2);
                assert!(d.nlri.is_empty());
            }
            _ => panic!("expected UPDATE"),
        }
    }

    #[test]
    fn notification_roundtrip() {
        let n = BgpNotification::new(6, 2, vec![]);
        let m = BgpMessage::Notification(n.clone());
        let dec = roundtrip(m, false);
        match dec {
            BgpMessage::Notification(d) => {
                assert_eq!(d.error_code, 6);
                assert_eq!(d.error_subcode, 2);
            }
            _ => panic!("expected NOTIFICATION"),
        }
    }

    #[test]
    fn route_refresh_roundtrip() {
        let r = RouteRefresh::new(NlriFamily::IPV4_UNICAST);
        let m = BgpMessage::RouteRefresh(r);
        let dec = roundtrip(m, false);
        match dec {
            BgpMessage::RouteRefresh(d) => {
                assert_eq!(d.family, NlriFamily::IPV4_UNICAST);
                assert_eq!(d.subtype, crate::message::RouteRefreshSubtype::Normal);
            }
            _ => panic!("expected ROUTE-REFRESH"),
        }
    }

    #[test]
    fn enhanced_route_refresh_markers_roundtrip() {
        for refresh in [
            RouteRefresh::begin_of_rib(NlriFamily::IPV4_UNICAST),
            RouteRefresh::end_of_rib(NlriFamily::IPV4_UNICAST),
        ] {
            let decoded = roundtrip(BgpMessage::RouteRefresh(refresh), false);
            assert_eq!(decoded, BgpMessage::RouteRefresh(refresh));
        }
    }

    #[test]
    fn route_refresh_rejects_invalid_subtype_and_length() {
        assert!(decode_route_refresh(&[0, 1, 3, 1]).is_err());
        assert!(decode_route_refresh(&[0, 1, 0, 1, 0]).is_err());
    }

    #[test]
    fn streaming_decoder_accumulates() {
        let codec = BgpCodec::new();
        let msg = BgpMessage::Keepalive(Keepalive);
        let bytes = codec.encode_vec(&msg).unwrap();
        let mut c = BgpCodec::new();
        assert!(c.decode_slice(&bytes[..10]).unwrap().is_none());
        let m = c.decode_slice(&bytes[10..]).unwrap().unwrap();
        assert!(matches!(m, BgpMessage::Keepalive(_)));
    }

    #[test]
    fn bad_marker_returns_error() {
        let mut c = BgpCodec::new();
        let bad = vec![0u8; 19];
        let res = c.decode_slice(&bad);
        assert!(res.is_err());
    }
}
