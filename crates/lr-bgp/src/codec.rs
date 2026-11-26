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
///
/// Extended Message (RFC 8654) raises the per-message length ceiling
/// from the RFC 4271 §4.1 4096-octet limit to 65535 octets once both
/// speakers advertise the capability. The codec accepts the larger
/// inbound length only when `extended_message` is `true` — set after
/// OPEN negotiation completes; the encoder allocates a buffer large
/// enough for the negotiated ceiling.
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
    /// RFC 8654 Extended Message support negotiated for this session.
    /// When `true`, the decoder accepts messages up to 65535 octets
    /// and the encoder allocates a buffer large enough for the
    /// negotiated ceiling. Defaults to `false` (the RFC 4271 §4.1
    /// 4096-octet ceiling).
    extended_message: bool,
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

    /// Whether the codec currently encodes 4-byte AS_PATH (the negotiated
    /// session width, which may differ from the configured capability).
    pub fn asn4_active(&self) -> bool {
        self.asn4
    }

    /// Set the address families whose NLRI carries RFC 7911 path
    /// identifiers in each direction (call after OPEN negotiation).
    pub fn set_add_path(&mut self, tx: Vec<NlriFamily>, rx: Vec<NlriFamily>) {
        self.add_path_tx = tx;
        self.add_path_rx = rx;
    }

    /// Set whether RFC 8654 Extended Message support is negotiated
    /// for this session (call after OPEN negotiation). When `true`,
    /// the decoder accepts messages up to 65535 octets and the
    /// encoder allocates a buffer large enough for the negotiated
    /// ceiling.
    pub fn set_extended_message(&mut self, v: bool) {
        self.extended_message = v;
    }

    /// Whether the codec currently accepts the RFC 8654 65535-octet
    /// message ceiling (the negotiated posture, which may differ
    /// from the configured capability).
    pub fn extended_message_active(&self) -> bool {
        self.extended_message
    }

    /// The maximum BGP message length the codec currently accepts
    /// (RFC 4271 §4.1 4096 by default; RFC 8654 65535 when
    /// [`set_extended_message`] has been called with `true`).
    fn max_len(&self) -> u16 {
        if self.extended_message {
            MAX_LEN_EXTENDED
        } else {
            MAX_LEN
        }
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
        match try_decode_frame(&self.carryover, rx_v4, self.max_len())? {
            Some((n, msg)) => {
                // Drain the consumed prefix.
                self.carryover.drain(0..n);
                Ok(Some(msg))
            }
            None => Ok(None),
        }
    }

    /// Streaming decode preserving the [`BgpError`] payload. Unlike the
    /// [`Decoder`] trait path (which flattens protocol errors into a
    /// generic [`ParseError`]), this lets the FSM raise the exact
    /// NOTIFICATION RFC 4271 requires on malformed input. The whole chunk
    /// is consumed into the carryover; frames are pulled one per call.
    pub fn decode_bgp(&mut self, src: &mut ReadBuf<'_>) -> Result<Option<BgpMessage>, BgpError> {
        self.carryover.extend_from_slice(src.chunk());
        let all = src.remaining();
        src.advance(all);
        let rx_v4 = self.rx_add_path(NlriFamily::IPV4_UNICAST);
        match try_decode_frame(&self.carryover, rx_v4, self.max_len())? {
            Some((n, msg)) => {
                self.carryover.drain(0..n);
                Ok(Some(msg))
            }
            None => Ok(None),
        }
    }

    /// Direct encode of a message to a fresh Vec.
    pub fn encode_vec(&self, msg: &BgpMessage) -> Result<Vec<u8>, EncodeError> {
        // Allocate for the negotiated message ceiling so an
        // Extended Message-sized UPDATE (RFC 8654 §3) does not
        // overflow the buffer. The default 4096-octet ceiling
        // covers every non-extended message.
        let mut buf = vec![0u8; self.max_len() as usize];
        let mut w = WriteBuf::new(&mut buf);
        let n = self.encode(msg, &mut w)?;
        buf.truncate(n);
        Ok(buf)
    }
}

const MARKER: [u8; 16] = [0xff; 16];

const MIN_LEN: u16 = 19;
/// RFC 4271 §4.1 maximum message length.
const MAX_LEN: u16 = 4096;
/// RFC 8654 §3 maximum message length when the Extended Message
/// capability is negotiated.
const MAX_LEN_EXTENDED: u16 = 65535;

/// Attempt to decode one frame from `buf`. Returns `Ok(Some((consumed, msg)))`
/// on success, `Ok(None)` when the buffer doesn't yet contain a full frame,
/// and `Err(BgpError)` on a protocol-level parse failure.
///
/// `rx_v4_add_path` selects the RFC 7911 framing (4-octet path identifier
/// ahead of each prefix) for the plain IPv4 NLRI/withdrawn sections.
/// `max_len` is the per-session message length ceiling (RFC 4271 §4.1
/// 4096 by default; RFC 8654 §3 65535 when Extended Message is
/// negotiated).
fn try_decode_frame(
    buf: &[u8],
    rx_v4_add_path: bool,
    max_len: u16,
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
    let kind = buf[18];
    // RFC 8654 §4: the Extended Message ceiling applies to every
    // message except OPEN and KEEPALIVE, which keep the RFC 4271
    // §4.1 4096-octet limit even after the capability is negotiated.
    let ceiling = if kind == BgpMessageType::Open as u8 || kind == BgpMessageType::Keepalive as u8 {
        MAX_LEN
    } else {
        max_len
    };
    if !(MIN_LEN..=ceiling).contains(&len) {
        return Err(BgpError::Notification(BgpNotification::new(
            crate::error::BgpErrorCode::Header as u8,
            crate::error::BgpHeaderErrorSubcode::BadMessageLength as u8,
            len.to_be_bytes().to_vec(),
        )));
    }
    if buf.len() < len as usize {
        return Ok(None);
    }
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
        // RFC 8654 §4: Extended Message does not raise the OPEN or
        // KEEPALIVE ceiling. Refuse rather than emit a frame a
        // conforming peer would reject with Bad Message Length.
        if total > MAX_LEN as usize && matches!(msg, BgpMessage::Open(_) | BgpMessage::Keepalive(_))
        {
            return Err(EncodeError::InvalidValue(
                "OPEN and KEEPALIVE must not exceed 4096 octets",
            ));
        }
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
        // Append the whole chunk into the carryover and mark it consumed in
        // the caller's view. Frames are then pulled out of the carryover one
        // at a time: a feed that contains several complete frames (or that
        // completes a frame started by an earlier feed) is drained across
        // successive decode() calls without the tail being re-appended.
        self.carryover.extend_from_slice(src.chunk());
        let all = src.remaining();
        src.advance(all);
        let rx_v4 = self.rx_add_path(NlriFamily::IPV4_UNICAST);
        let result =
            try_decode_frame(&self.carryover, rx_v4, self.max_len()).map_err(|e| match e {
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
                Ok(Some(msg))
            }
            None => Ok(None),
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
            // RFC 4271 §6.1: a KEEPALIVE with a non-empty body is a
            // Bad Message Length header error.
            if !body.is_empty() {
                return Err(BgpError::Notification(BgpNotification::new(
                    crate::error::BgpErrorCode::Header as u8,
                    crate::error::BgpHeaderErrorSubcode::BadMessageLength as u8,
                    vec![],
                )));
            }
            Ok(BgpMessage::Keepalive(Keepalive))
        }
        BgpMessageType::RouteRefresh => Ok(BgpMessage::RouteRefresh(decode_route_refresh(body)?)),
    }
}

fn bad_open_length() -> BgpError {
    BgpError::Notification(BgpNotification::new(
        crate::error::BgpErrorCode::Open as u8,
        crate::error::BgpOpenErrorSubcode::BadOpenLength as u8,
        vec![],
    ))
}

fn decode_open(body: &[u8]) -> Result<Open, BgpError> {
    if body.len() < 10 {
        return Err(bad_open_length());
    }
    let version = body[0];
    let my_as = lr_core::addr::Asn(u16::from_be_bytes([body[1], body[2]]) as u32);
    let hold_time = u16::from_be_bytes([body[3], body[4]]);
    let bgp_id = lr_core::addr::RouterId(u32::from_be_bytes([body[5], body[6], body[7], body[8]]));
    let params_len = body[9] as usize;

    // RFC 9072 §2: when the one-octet Optional Parameters Length is
    // non-zero, the octet after it decides the encoding. Type code 255
    // marks the extended format: a two-octet Optional Parameters
    // Length follows, and every parameter carries a two-octet length.
    // The one-octet length is ignored in that case. A speaker MUST
    // accept the extended format even when the parameters fit in 255
    // octets, so the decision is on the type code alone.
    let extended = params_len != 0 && body.get(10) == Some(&OpenParam::PARAM_TYPE_EXTENDED_LENGTH);
    let (mut i, end) = if extended {
        if body.len() < 13 {
            return Err(bad_open_length());
        }
        let ext_len = u16::from_be_bytes([body[11], body[12]]) as usize;
        (13, 13 + ext_len)
    } else {
        (10, 10 + params_len)
    };
    if body.len() < end {
        return Err(bad_open_length());
    }
    let mut params = Vec::new();
    while i < end {
        let header_len = if extended { 3 } else { 2 };
        // A parameter header and its value must fit inside the declared
        // Optional-Parameters-Length region; extending past it is a
        // Bad OPEN Length error, not silently accepted (RFC 4271 §6.2).
        if i + header_len > end {
            return Err(bad_open_length());
        }
        let pt = body[i];
        let pl = if extended {
            u16::from_be_bytes([body[i + 1], body[i + 2]]) as usize
        } else {
            body[i + 1] as usize
        };
        i += header_len;
        if i + pl > end {
            return Err(bad_open_length());
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
/// prefix>`. A prefix length above 32 bits is invalid for IPv4 (RFC 4271
/// §4.3) and rejects the whole set — it must never panic.
fn decode_nlri_set(bytes: &[u8], add_path: bool) -> Result<Vec<Nlri>, String> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        // With Add-Path the entry needs the 4-byte path-id *plus* the
        // prefix-length byte; a trailing 4-byte path-id with no length
        // byte is a truncated entry, not an index-one-past-the-end read.
        let path_id = if add_path {
            if i + 5 > bytes.len() {
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
        if pl > 32 {
            return Err(format!("invalid IPv4 prefix length {} at offset {}", pl, i));
        }
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
        let attr = PathAttribute {
            flags,
            attr_type: AttrType::from_u8(ty_byte),
            value,
        };
        // RFC 4271 §6.3: an attribute appearing more than once is a
        // Malformed Attribute List error — silent last-wins hides peer
        // misbehaviour and is not interoperable.
        if out.get(attr.attr_type).is_some() {
            return Err(BgpError::Notification(BgpNotification::new(
                crate::error::BgpErrorCode::Update as u8,
                crate::error::BgpUpdateErrorSubcode::MalformedAttributeList as u8,
                vec![ty_byte],
            )));
        }
        out.insert(attr);
        i = value_start + attr_len;
    }
    Ok(out)
}

fn decode_notification(body: &[u8]) -> BgpNotification {
    // RFC 4271 §4.5: a NOTIFICATION body is code(1) + subcode(1) + data.
    // A shorter body is a header error (Bad Message Length) rather than
    // a valid notification with code 0.
    if body.len() < 2 {
        return BgpNotification {
            error_code: crate::error::BgpErrorCode::Header as u8,
            error_subcode: crate::error::BgpHeaderErrorSubcode::BadMessageLength as u8,
            data: Vec::new(),
        };
    }
    let code = body[0];
    let sub = body[1];
    let data = body.get(2..).unwrap_or(&[]).to_vec();
    BgpNotification::new(code, sub, data)
}

/// A malformed ROUTE-REFRESH or ORF payload. RFC 7313 §5 assigns
/// subcode 1 "Invalid Message Length" to the ROUTE-REFRESH error code
/// (7); RFC 5291 does not define a more specific code, so a truncated
/// ORF block uses the same notification.
fn bad_route_refresh_length() -> BgpError {
    BgpError::Notification(BgpNotification::new(
        crate::error::BgpErrorCode::RouteRefresh as u8,
        1,
        vec![],
    ))
}

fn decode_route_refresh(body: &[u8]) -> Result<RouteRefresh, BgpError> {
    // RFC 2918 §3: a plain ROUTE-REFRESH is exactly 4 bytes
    // (AFI:2, subtype:1, SAFI:1); RFC 7313 BoRR/EoRR share the layout.
    // RFC 5291 §4 appends When-to-refresh and ORF blocks from the fifth
    // octet on. Anything shorter than the four-octet prefix cannot be
    // either message.
    if body.len() < 4 {
        return Err(bad_route_refresh_length());
    }
    let afi = u16::from_be_bytes([body[0], body[1]]);
    let safi = body[3];
    let family = NlriFamily { afi, safi };
    if body.len() == 4 {
        // RFC 7313 §3.2: a ROUTE-REFRESH with an unknown subtype MUST
        // be ignored — surface it as an unknown subtype the FSM skips
        // rather than tearing the session down.
        let subtype = crate::message::RouteRefreshSubtype::from_u8(body[2])
            .unwrap_or(crate::message::RouteRefreshSubtype::Unknown);
        return Ok(RouteRefresh {
            family,
            subtype,
            orf: None,
        });
    }

    // RFC 5291 §4: the third octet is reserved in an ORF message.
    if body[2] != 0 {
        return Err(bad_route_refresh_length());
    }
    let when =
        crate::message::OrfWhenToRefresh::from_u8(body[4]).ok_or_else(bad_route_refresh_length)?;
    let mut lists = Vec::new();
    let mut r = ReadBuf::new(&body[5..]);
    while r.remaining() > 0 {
        if r.remaining() < 3 {
            return Err(bad_route_refresh_length());
        }
        let orf_type = r.get_u8().ok_or_else(bad_route_refresh_length)?;
        let len = r.get_u16_be().ok_or_else(bad_route_refresh_length)? as usize;
        let bytes = r.get_bytes(len).ok_or_else(bad_route_refresh_length)?;
        lists.push(decode_orf_list(afi, orf_type, bytes)?);
    }
    // RFC 5291 §4: an ORF message carries one or more ORFs.
    if lists.is_empty() {
        return Err(bad_route_refresh_length());
    }
    Ok(RouteRefresh {
        family,
        subtype: crate::message::RouteRefreshSubtype::Normal,
        orf: Some(crate::message::OrfRefresh { when, lists }),
    })
}

/// Decode one `(ORF Type, length, entries)` block (RFC 5291 §4).
///
/// Only the Address Prefix ORF (type 64, RFC 5292) has a known
/// layout. Other types are preserved as one [`OrfEntry::Raw`] block so
/// the receiver can ignore them per RFC 5291 §6 without guessing at
/// their entry boundaries.
fn decode_orf_list(
    afi: u16,
    orf_type: u8,
    bytes: &[u8],
) -> Result<crate::message::OrfList, BgpError> {
    if orf_type != crate::message::OrfList::ADDRESS_PREFIX {
        return Ok(crate::message::OrfList {
            orf_type,
            entries: vec![crate::message::OrfEntry::Raw(bytes.to_vec())],
        });
    }
    let max_bits: u8 = match afi {
        1 => 32,
        2 => 128,
        // RFC 5292 §3: Length/Maxlen are bounded by the address
        // family's host-address length. An ORF for another AFI is not
        // one this implementation advertised, so keep it raw.
        _ => {
            return Ok(crate::message::OrfList {
                orf_type,
                entries: vec![crate::message::OrfEntry::Raw(bytes.to_vec())],
            })
        }
    };
    let mut entries = Vec::new();
    let mut r = ReadBuf::new(bytes);
    while r.remaining() > 0 {
        let common = r.get_u8().ok_or_else(bad_route_refresh_length)?;
        let action = crate::message::OrfAction::from_u8(common >> 6);
        let permit = (common >> 5) & 1 == 0;
        if action == crate::message::OrfAction::RemoveAll {
            entries.push(crate::message::OrfEntry::RemoveAll);
            continue;
        }
        let sequence = r.get_u32_be().ok_or_else(bad_route_refresh_length)?;
        let min_len = r.get_u8().ok_or_else(bad_route_refresh_length)?;
        let max_len = r.get_u8().ok_or_else(bad_route_refresh_length)?;
        let prefix_len = r.get_u8().ok_or_else(bad_route_refresh_length)?;
        let nbytes = usize::from(prefix_len).div_ceil(8);
        let raw = r.get_bytes(nbytes).ok_or_else(bad_route_refresh_length)?;
        // RFC 5292 §3 bounds Length and Maxlen by the family. A
        // semantic violation is not a framing error: RFC 5291 §6
        // removes the whole ORF instead, which the router does when it
        // sees `OrfAction::Unknown`.
        let semantic_bad = prefix_len > max_bits
            || min_len > max_bits
            || max_len > max_bits
            || (min_len != 0 && max_len != 0 && min_len > max_len);
        let action = if semantic_bad {
            crate::message::OrfAction::Unknown
        } else {
            action
        };
        let prefix = if afi == 1 {
            let mut a = [0u8; 4];
            a[..nbytes.min(4)].copy_from_slice(&raw[..nbytes.min(4)]);
            Prefix::new_v4(a, prefix_len.min(max_bits))
        } else {
            let mut a = [0u8; 16];
            a[..nbytes.min(16)].copy_from_slice(&raw[..nbytes.min(16)]);
            Prefix::new_v6(a, prefix_len.min(max_bits))
        };
        entries.push(crate::message::OrfEntry::AddressPrefix(
            crate::message::AddressPrefixOrf {
                sequence,
                action,
                permit,
                prefix: Prefix {
                    addr: prefix.network(),
                    prefix_len: prefix.prefix_len,
                },
                min_len,
                max_len,
            },
        ));
    }
    Ok(crate::message::OrfList { orf_type, entries })
}

// ===== Encoders =====

fn encode_open(o: &Open, out: &mut WriteBuf<'_>) -> Result<(), EncodeError> {
    out.put_u8(o.version).ok_or(EncodeError::BufferFull)?;
    let as16 = o.my_as.as_u16().unwrap_or(23456);
    out.put_u16_be(as16).ok_or(EncodeError::BufferFull)?;
    out.put_u16_be(o.hold_time).ok_or(EncodeError::BufferFull)?;
    out.put_bytes(&o.bgp_id.to_v4_bytes())
        .ok_or(EncodeError::BufferFull)?;

    // RFC 9072 §2: the base encoding caps the Optional Parameters
    // field at 255 octets; past that the extended encoding is
    // mandatory. Compute the size first so the choice is made before
    // any length field is written — the base encoder used to cast the
    // total to `u8` and silently corrupt an oversized OPEN.
    let mut base_len = 0usize;
    let mut extended_len = 0usize;
    for p in &o.params {
        if p.value.len() > u16::MAX as usize {
            return Err(EncodeError::InvalidValue(
                "OPEN optional parameter value exceeds 65535 octets",
            ));
        }
        // The base format has a one-octet, the extended format a
        // two-octet per-parameter length field.
        base_len = base_len
            .checked_add(2 + p.value.len())
            .ok_or(EncodeError::InvalidValue(
                "OPEN optional parameters overflow",
            ))?;
        extended_len =
            extended_len
                .checked_add(3 + p.value.len())
                .ok_or(EncodeError::InvalidValue(
                    "OPEN optional parameters overflow",
                ))?;
    }
    if base_len > u8::MAX as usize {
        if extended_len > u16::MAX as usize {
            return Err(EncodeError::InvalidValue(
                "OPEN optional parameters exceed 65535 octets",
            ));
        }
        // Non-Ext OP Len SHOULD be 255 and MUST NOT be zero; the
        // receiver ignores it once the type code says extended.
        out.put_u8(u8::MAX).ok_or(EncodeError::BufferFull)?;
        out.put_u8(OpenParam::PARAM_TYPE_EXTENDED_LENGTH)
            .ok_or(EncodeError::BufferFull)?;
        out.put_u16_be(extended_len as u16)
            .ok_or(EncodeError::BufferFull)?;
        for p in &o.params {
            out.put_u8(p.param_type).ok_or(EncodeError::BufferFull)?;
            out.put_u16_be(p.value.len() as u16)
                .ok_or(EncodeError::BufferFull)?;
            out.put_bytes(&p.value).ok_or(EncodeError::BufferFull)?;
        }
    } else {
        let params_pos = out.reserve(1).ok_or(EncodeError::BufferFull)?;
        for p in &o.params {
            out.put_u8(p.param_type).ok_or(EncodeError::BufferFull)?;
            out.put_u8(p.value.len() as u8)
                .ok_or(EncodeError::BufferFull)?;
            out.put_bytes(&p.value).ok_or(EncodeError::BufferFull)?;
        }
        out.patch(params_pos, &[base_len as u8])
            .ok_or(EncodeError::BufferFull)?;
    }
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
        // The private LrMplsLabelStack / LrExchangePlaneRecords /
        // LrOspfMetric2 / LrOspfRouterId / LrBabelSeqno /
        // LrBabelRouterId / LrIgpMetric / LrPeerSourceAddress /
        // LrPeerHealthTier / LrPeerHealthStale tags carry
        // router-internal state and are never sent on the wire.
        // Skip all ten during encode.
        if matches!(
            a.attr_type,
            crate::path::AttrType::LrMplsLabelStack
                | crate::path::AttrType::LrExchangePlaneRecords
                | crate::path::AttrType::LrOspfMetric2
                | crate::path::AttrType::LrOspfRouterId
                | crate::path::AttrType::LrBabelSeqno
                | crate::path::AttrType::LrBabelRouterId
                | crate::path::AttrType::LrIgpMetric
                | crate::path::AttrType::LrPeerSourceAddress
                | crate::path::AttrType::LrPeerHealthTier
                | crate::path::AttrType::LrPeerHealthStale
        ) {
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
    // The `!p.is_ipv4()` guard above is the canonical check; the
    // `IpAddr::V6(_)` arm is a defense-in-depth return so a future
    // refactor that drops the guard cannot turn a malformed encode
    // into a `panic!` on the data path.
    let bytes = match &p.addr {
        IpAddr::V4(b) => b,
        IpAddr::V6(_) => {
            return Err(EncodeError::InvalidValue(
                "NLRI in legacy section must be IPv4",
            ));
        }
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
    match &r.orf {
        // RFC 5291 §4: the third octet is reserved in an ORF message.
        Some(_) => out.put_u8(0).ok_or(EncodeError::BufferFull)?,
        None => out.put_u8(r.subtype as u8).ok_or(EncodeError::BufferFull)?,
    }
    out.put_u8(r.family.safi).ok_or(EncodeError::BufferFull)?;
    let Some(orf) = &r.orf else {
        return Ok(());
    };
    out.put_u8(orf.when.as_u8())
        .ok_or(EncodeError::BufferFull)?;
    for list in &orf.lists {
        let mut body = Vec::new();
        for entry in &list.entries {
            encode_orf_entry(entry, &mut body);
        }
        let len = u16::try_from(body.len()).map_err(|_| EncodeError::BufferFull)?;
        out.put_u8(list.orf_type).ok_or(EncodeError::BufferFull)?;
        out.put_u16_be(len).ok_or(EncodeError::BufferFull)?;
        out.put_bytes(&body).ok_or(EncodeError::BufferFull)?;
    }
    Ok(())
}

fn encode_orf_entry(entry: &crate::message::OrfEntry, out: &mut Vec<u8>) {
    use crate::message::{AddressPrefixOrf, OrfAction, OrfEntry};
    let value = match entry {
        OrfEntry::Raw(bytes) => {
            out.extend_from_slice(bytes);
            return;
        }
        OrfEntry::RemoveAll => AddressPrefixOrf {
            sequence: 0,
            action: OrfAction::RemoveAll,
            permit: false,
            prefix: Prefix::new_v4([0, 0, 0, 0], 0),
            min_len: 0,
            max_len: 0,
        },
        OrfEntry::AddressPrefix(e) => *e,
    };
    let action = match value.action {
        OrfAction::Add => 0u8,
        OrfAction::Remove => 1,
        OrfAction::RemoveAll => 2,
        OrfAction::Unknown => 3,
    };
    let common = (action << 6) | (u8::from(!value.permit) << 5);
    out.push(common);
    if value.action == OrfAction::RemoveAll {
        return;
    }
    out.extend_from_slice(&value.sequence.to_be_bytes());
    out.push(value.min_len);
    out.push(value.max_len);
    out.push(value.prefix.prefix_len);
    let nbytes = usize::from(value.prefix.prefix_len).div_ceil(8);
    match value.prefix.addr {
        IpAddr::V4(a) => out.extend_from_slice(&a[..nbytes.min(4)]),
        IpAddr::V6(a) => out.extend_from_slice(&a[..nbytes.min(16)]),
    }
}

#[cfg(test)]
#[path = "codec_tests.rs"]
mod tests;
