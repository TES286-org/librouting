//! LDP messages and PDU framing (RFC 5036 §3.5).
//!
//! Every message starts with a header word (U-bit + 15-bit type), a
//! 16-bit length covering the Message ID and all TLVs, and a 32-bit
//! Message ID, followed by mandatory and optional TLVs. A PDU is the
//! 10-byte header (version, length, 6-byte LDP Identifier) plus one or
//! more messages.
//!
//! [`LdpCodec`] implements the `lr-core` [`Encoder`]/[`Decoder`]
//! traits for [`LdpPdu`]: `decode` returns `Ok(None)` when the buffer
//! does not yet hold a complete PDU (the buffer is left untouched), and
//! parses one PDU at a time. Unknown TLVs are preserved in each
//! message's `unknown_tlvs` so the receiver can apply the §3.3 U-bit
//! rules; unknown messages decode into [`LdpMessage::Unknown`].

use crate::pdu::{
    message_header_word, tlv_header_word, LdpId, MessageType, TlvClass, TlvType, LDP_VERSION,
};
use crate::tlv::{
    wire, AddressList, ConfigSequenceNumber, Fec, GenericLabel, HelloParams, HopCount,
    LabelRequestMessageId, PathVector, RawTlv, SessionParams, Status, TransportAddress,
};
#[cfg(not(feature = "std"))]
use alloc::string::ToString;
use alloc::vec::Vec;
use core::fmt;
use lr_core::buf::{ReadBuf, WriteBuf};
use lr_core::codec::{Decoder, Encoder};
use lr_core::error::{EncodeError, ErrorKind, ParseError};

// ---------------------------------------------------------------------------
// Message payloads
// ---------------------------------------------------------------------------

/// Notification (0x0001): carries a mandatory Status TLV (§3.5.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NotificationMsg {
    pub message_id: u32,
    pub status: Status,
    pub unknown_tlvs: Vec<RawTlv>,
}

/// Hello (0x0100): discovery, sent over UDP (§3.5.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HelloMsg {
    pub message_id: u32,
    pub params: HelloParams,
    /// Optional IPv4/IPv6 Transport Address TLV.
    pub transport_addr: Option<TransportAddress>,
    /// Optional Configuration Sequence Number TLV.
    pub config_seq: Option<ConfigSequenceNumber>,
    pub unknown_tlvs: Vec<RawTlv>,
}

/// Initialization (0x0200): session parameter negotiation (§3.5.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InitMsg {
    pub message_id: u32,
    pub params: SessionParams,
    /// Optional parameters (e.g. RFC 5561 LDP Capability TLVs).
    pub unknown_tlvs: Vec<RawTlv>,
}

/// KeepAlive (0x0201): session liveness (§3.5.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeepAliveMsg {
    pub message_id: u32,
}

/// Address (0x0300): interface address advertisement (§3.5.5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AddressMsg {
    pub message_id: u32,
    pub addresses: AddressList,
    pub unknown_tlvs: Vec<RawTlv>,
}

/// Address Withdraw (0x0301): withdraw advertised addresses (§3.5.6).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AddressWithdrawMsg {
    pub message_id: u32,
    pub addresses: AddressList,
    pub unknown_tlvs: Vec<RawTlv>,
}

/// Label Mapping (0x0400): advertise a FEC-label binding (§3.5.7).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LabelMappingMsg {
    pub message_id: u32,
    pub fec: Fec,
    pub label: GenericLabel,
    pub hop_count: Option<HopCount>,
    pub path_vector: Option<PathVector>,
    /// Present when this mapping answers a Label Request.
    pub request_message_id: Option<LabelRequestMessageId>,
    pub unknown_tlvs: Vec<RawTlv>,
}

/// Label Request (0x0401): request a binding for a FEC (§3.5.8).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LabelRequestMsg {
    pub message_id: u32,
    pub fec: Fec,
    pub hop_count: Option<HopCount>,
    pub path_vector: Option<PathVector>,
    pub unknown_tlvs: Vec<RawTlv>,
}

/// Label Withdraw (0x0402): retract a previously advertised mapping
/// (§3.5.10). The receiver MUST respond with Label Release.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LabelWithdrawMsg {
    pub message_id: u32,
    pub fec: Fec,
    /// When absent, all labels bound to the FEC are withdrawn.
    pub label: Option<GenericLabel>,
    pub unknown_tlvs: Vec<RawTlv>,
}

/// Label Release (0x0403): the peer no longer needs mappings (§3.5.11).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LabelReleaseMsg {
    pub message_id: u32,
    pub fec: Fec,
    pub label: Option<GenericLabel>,
    pub unknown_tlvs: Vec<RawTlv>,
}

/// Label Abort Request (0x0404): abort an outstanding Label Request
/// (§3.5.9).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LabelAbortMsg {
    pub message_id: u32,
    pub fec: Fec,
    /// Message ID of the Label Request being aborted.
    pub request_message_id: LabelRequestMessageId,
    pub unknown_tlvs: Vec<RawTlv>,
}

/// An unrecognized message preserved verbatim (U-bit handling is the
/// receiver's job, §3.5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawMessage {
    pub u_bit: bool,
    pub msg_type: u16,
    pub message_id: u32,
    pub tlvs: Vec<RawTlv>,
}

/// One LDP message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LdpMessage {
    Notification(NotificationMsg),
    Hello(HelloMsg),
    Initialization(InitMsg),
    KeepAlive(KeepAliveMsg),
    Address(AddressMsg),
    AddressWithdraw(AddressWithdrawMsg),
    LabelMapping(LabelMappingMsg),
    LabelRequest(LabelRequestMsg),
    LabelWithdraw(LabelWithdrawMsg),
    LabelRelease(LabelReleaseMsg),
    LabelAbortRequest(LabelAbortMsg),
    Unknown(RawMessage),
}

impl LdpMessage {
    /// The message type for header encoding.
    pub fn message_type(&self) -> u16 {
        match self {
            Self::Notification(_) => MessageType::Notification as u16,
            Self::Hello(_) => MessageType::Hello as u16,
            Self::Initialization(_) => MessageType::Initialization as u16,
            Self::KeepAlive(_) => MessageType::KeepAlive as u16,
            Self::Address(_) => MessageType::Address as u16,
            Self::AddressWithdraw(_) => MessageType::AddressWithdraw as u16,
            Self::LabelMapping(_) => MessageType::LabelMapping as u16,
            Self::LabelRequest(_) => MessageType::LabelRequest as u16,
            Self::LabelWithdraw(_) => MessageType::LabelWithdraw as u16,
            Self::LabelRelease(_) => MessageType::LabelRelease as u16,
            Self::LabelAbortRequest(_) => MessageType::LabelAbortRequest as u16,
            Self::Unknown(m) => m.msg_type & 0x7fff,
        }
    }

    /// The U-bit for header encoding (0 for all RFC 5036 messages;
    /// preserved verbatim for unknown messages).
    pub fn u_bit(&self) -> bool {
        match self {
            Self::Unknown(m) => m.u_bit,
            _ => false,
        }
    }

    /// The Message ID.
    pub fn message_id(&self) -> u32 {
        match self {
            Self::Notification(m) => m.message_id,
            Self::Hello(m) => m.message_id,
            Self::Initialization(m) => m.message_id,
            Self::KeepAlive(m) => m.message_id,
            Self::Address(m) => m.message_id,
            Self::AddressWithdraw(m) => m.message_id,
            Self::LabelMapping(m) => m.message_id,
            Self::LabelRequest(m) => m.message_id,
            Self::LabelWithdraw(m) => m.message_id,
            Self::LabelRelease(m) => m.message_id,
            Self::LabelAbortRequest(m) => m.message_id,
            Self::Unknown(m) => m.message_id,
        }
    }
}

impl fmt::Display for LdpMessage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unknown(m) => write!(f, "Unknown(0x{:04x})", m.msg_type),
            other => write!(f, "{}", type_name_of(other.message_type())),
        }
    }
}

fn type_name_of(t: u16) -> &'static str {
    match MessageType::from_u16(t) {
        Some(m) => match m {
            MessageType::Notification => "Notification",
            MessageType::Hello => "Hello",
            MessageType::Initialization => "Initialization",
            MessageType::KeepAlive => "KeepAlive",
            MessageType::Capability => "Capability",
            MessageType::Address => "Address",
            MessageType::AddressWithdraw => "AddressWithdraw",
            MessageType::LabelMapping => "LabelMapping",
            MessageType::LabelRequest => "LabelRequest",
            MessageType::LabelWithdraw => "LabelWithdraw",
            MessageType::LabelRelease => "LabelRelease",
            MessageType::LabelAbortRequest => "LabelAbortRequest",
        },
        None => "Unknown",
    }
}

/// One LDP PDU: a sender identifier plus one or more messages.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LdpPdu {
    /// Protocol version (must be 1).
    pub version: u16,
    /// The sending LSR's label space.
    pub sender: LdpId,
    pub messages: Vec<LdpMessage>,
}

// ---------------------------------------------------------------------------
// Encoding
// ---------------------------------------------------------------------------

/// Write one TLV (header + patched length + value produced by `value`).
pub fn write_tlv(
    out: &mut WriteBuf<'_>,
    u_bit: bool,
    f_bit: bool,
    tlv_type: u16,
    value: impl FnOnce(&mut WriteBuf<'_>) -> Result<(), EncodeError>,
) -> Result<(), EncodeError> {
    out.put_u16_be(tlv_header_word(u_bit, f_bit, tlv_type))
        .ok_or(EncodeError::BufferFull)?;
    let len_pos = out.reserve(2).ok_or(EncodeError::BufferFull)?;
    value(out)?;
    let written = out.written().len();
    let len = written
        .checked_sub(len_pos + 2)
        .ok_or(EncodeError::InvalidValue("TLV length underflow"))?;
    u16::try_from(len)
        .map_err(|_| EncodeError::InvalidValue("TLV exceeds 65535 octets"))
        .and_then(|l| {
            out.patch(len_pos, &l.to_be_bytes())
                .ok_or(EncodeError::BufferFull)
        })
}

fn write_raw_tlv(out: &mut WriteBuf<'_>, raw: &RawTlv) -> Result<(), EncodeError> {
    write_tlv(out, raw.u_bit, raw.f_bit, raw.tlv_type, |out| {
        out.put_bytes(&raw.value).ok_or(EncodeError::BufferFull)
    })
}

/// Write one message (header + patched length + Message ID + TLVs
/// produced by `tlvs`).
pub fn write_message(
    out: &mut WriteBuf<'_>,
    msg: &LdpMessage,
    tlvs: impl FnOnce(&mut WriteBuf<'_>) -> Result<(), EncodeError>,
) -> Result<(), EncodeError> {
    out.put_u16_be(message_header_word(msg.u_bit(), msg.message_type()))
        .ok_or(EncodeError::BufferFull)?;
    let len_pos = out.reserve(2).ok_or(EncodeError::BufferFull)?;
    out.put_u32_be(msg.message_id())
        .ok_or(EncodeError::BufferFull)?;
    tlvs(out)?;
    let written = out.written().len();
    let len = written
        .checked_sub(len_pos + 2)
        .ok_or(EncodeError::InvalidValue("message length underflow"))?;
    u16::try_from(len)
        .map_err(|_| EncodeError::InvalidValue("message exceeds 65535 octets"))
        .and_then(|l| {
            out.patch(len_pos, &l.to_be_bytes())
                .ok_or(EncodeError::BufferFull)
        })
}

fn encode_message_body(msg: &LdpMessage, out: &mut WriteBuf<'_>) -> Result<(), EncodeError> {
    match msg {
        LdpMessage::Notification(m) => write_message(out, msg, |out| {
            write_tlv(out, false, false, TlvType::Status as u16, |out| {
                wire::status(out, &m.status)
            })?;
            for raw in &m.unknown_tlvs {
                write_raw_tlv(out, raw)?;
            }
            Ok(())
        }),
        LdpMessage::Hello(m) => write_message(out, msg, |out| {
            write_tlv(
                out,
                false,
                false,
                TlvType::CommonHelloParameters as u16,
                |out| wire::hello_params(out, &m.params),
            )?;
            if let Some(t) = &m.transport_addr {
                write_tlv(out, false, false, t.tlv_type() as u16, |out| {
                    wire::transport_address(out, t)
                })?;
            }
            if let Some(c) = &m.config_seq {
                write_tlv(
                    out,
                    false,
                    false,
                    TlvType::ConfigSequenceNumber as u16,
                    |out| wire::config_sequence_number(out, c),
                )?;
            }
            for raw in &m.unknown_tlvs {
                write_raw_tlv(out, raw)?;
            }
            Ok(())
        }),
        LdpMessage::Initialization(m) => write_message(out, msg, |out| {
            write_tlv(
                out,
                false,
                false,
                TlvType::CommonSessionParameters as u16,
                |out| wire::session_params(out, &m.params),
            )?;
            for raw in &m.unknown_tlvs {
                write_raw_tlv(out, raw)?;
            }
            Ok(())
        }),
        LdpMessage::KeepAlive(_) => write_message(out, msg, |_| Ok(())),
        LdpMessage::Address(m) => write_message(out, msg, |out| {
            write_tlv(out, false, false, TlvType::AddressList as u16, |out| {
                wire::address_list(out, &m.addresses)
            })?;
            for raw in &m.unknown_tlvs {
                write_raw_tlv(out, raw)?;
            }
            Ok(())
        }),
        LdpMessage::AddressWithdraw(m) => write_message(out, msg, |out| {
            write_tlv(out, false, false, TlvType::AddressList as u16, |out| {
                wire::address_list(out, &m.addresses)
            })?;
            for raw in &m.unknown_tlvs {
                write_raw_tlv(out, raw)?;
            }
            Ok(())
        }),
        LdpMessage::LabelMapping(m) => write_message(out, msg, |out| {
            write_fec_tlv(out, &m.fec)?;
            write_tlv(out, false, false, TlvType::GenericLabel as u16, |out| {
                wire::generic_label(out, &m.label)
            })?;
            if let Some(h) = &m.hop_count {
                write_tlv(out, false, false, TlvType::HopCount as u16, |out| {
                    wire::hop_count(out, h)
                })?;
            }
            if let Some(pv) = &m.path_vector {
                write_tlv(out, false, false, TlvType::PathVector as u16, |out| {
                    wire::path_vector(out, pv)
                })?;
            }
            if let Some(r) = &m.request_message_id {
                write_tlv(
                    out,
                    false,
                    false,
                    TlvType::LabelRequestMessageId as u16,
                    |out| wire::label_request_message_id(out, r),
                )?;
            }
            for raw in &m.unknown_tlvs {
                write_raw_tlv(out, raw)?;
            }
            Ok(())
        }),
        LdpMessage::LabelRequest(m) => write_message(out, msg, |out| {
            write_fec_tlv(out, &m.fec)?;
            if let Some(h) = &m.hop_count {
                write_tlv(out, false, false, TlvType::HopCount as u16, |out| {
                    wire::hop_count(out, h)
                })?;
            }
            if let Some(pv) = &m.path_vector {
                write_tlv(out, false, false, TlvType::PathVector as u16, |out| {
                    wire::path_vector(out, pv)
                })?;
            }
            for raw in &m.unknown_tlvs {
                write_raw_tlv(out, raw)?;
            }
            Ok(())
        }),
        LdpMessage::LabelWithdraw(m) => write_message(out, msg, |out| {
            write_fec_tlv(out, &m.fec)?;
            if let Some(l) = &m.label {
                write_tlv(out, false, false, TlvType::GenericLabel as u16, |out| {
                    wire::generic_label(out, l)
                })?;
            }
            for raw in &m.unknown_tlvs {
                write_raw_tlv(out, raw)?;
            }
            Ok(())
        }),
        LdpMessage::LabelRelease(m) => write_message(out, msg, |out| {
            write_fec_tlv(out, &m.fec)?;
            if let Some(l) = &m.label {
                write_tlv(out, false, false, TlvType::GenericLabel as u16, |out| {
                    wire::generic_label(out, l)
                })?;
            }
            for raw in &m.unknown_tlvs {
                write_raw_tlv(out, raw)?;
            }
            Ok(())
        }),
        LdpMessage::LabelAbortRequest(m) => write_message(out, msg, |out| {
            write_fec_tlv(out, &m.fec)?;
            write_tlv(
                out,
                false,
                false,
                TlvType::LabelRequestMessageId as u16,
                |out| wire::label_request_message_id(out, &m.request_message_id),
            )?;
            for raw in &m.unknown_tlvs {
                write_raw_tlv(out, raw)?;
            }
            Ok(())
        }),
        LdpMessage::Unknown(m) => write_message(out, msg, |out| {
            for raw in &m.tlvs {
                write_raw_tlv(out, raw)?;
            }
            Ok(())
        }),
    }
}

fn write_fec_tlv(out: &mut WriteBuf<'_>, fec: &Fec) -> Result<(), EncodeError> {
    write_tlv(out, false, false, TlvType::Fec as u16, |out| {
        for el in &fec.elements {
            el.encode(out)?;
        }
        Ok(())
    })
}

// ---------------------------------------------------------------------------
// Decoding
// ---------------------------------------------------------------------------

/// One parsed TLV from a message body: either a recognized type with
/// its decoded value or a raw unknown TLV.
enum ParsedTlv {
    Fec(Fec),
    AddressList(AddressList),
    GenericLabel(GenericLabel),
    HelloParams(HelloParams),
    SessionParams(SessionParams),
    Status(Status),
    HopCount(HopCount),
    PathVector(PathVector),
    TransportAddress(TransportAddress),
    ConfigSequenceNumber(ConfigSequenceNumber),
    LabelRequestMessageId(LabelRequestMessageId),
    Raw(RawTlv),
}

/// Parse a TLV stream from `body` (a message's TLV area). Offsets in
/// errors are relative to `body`.
fn parse_tlv_stream(body: &[u8]) -> Result<Vec<ParsedTlv>, ParseError> {
    let mut out = Vec::new();
    let mut off = 0usize;
    while off < body.len() {
        if body.len() < off + 4 {
            return Err(ParseError::new(
                ErrorKind::Truncated,
                off,
                "truncated TLV header",
            ));
        }
        let header = u16::from_be_bytes([body[off], body[off + 1]]);
        let len = u16::from_be_bytes([body[off + 2], body[off + 3]]) as usize;
        let end = off + 4 + len;
        if body.len() < end {
            return Err(ParseError::new(
                ErrorKind::Truncated,
                off,
                "truncated TLV value",
            ));
        }
        let value = &body[off + 4..end];
        match TlvClass::from_header(header) {
            TlvClass::Known(TlvType::Fec) => {
                out.push(ParsedTlv::Fec(Fec::decode_value(value)?));
            }
            TlvClass::Known(TlvType::AddressList) => {
                out.push(ParsedTlv::AddressList(AddressList::decode_value(value)?));
            }
            TlvClass::Known(TlvType::GenericLabel) => {
                out.push(ParsedTlv::GenericLabel(GenericLabel::decode_value(value)?));
            }
            TlvClass::Known(TlvType::CommonHelloParameters) => {
                out.push(ParsedTlv::HelloParams(HelloParams::decode_value(value)?));
            }
            TlvClass::Known(TlvType::CommonSessionParameters) => {
                out.push(ParsedTlv::SessionParams(SessionParams::decode_value(
                    value,
                )?));
            }
            TlvClass::Known(TlvType::Status) => {
                out.push(ParsedTlv::Status(Status::decode_value(value)?));
            }
            TlvClass::Known(TlvType::HopCount) => {
                out.push(ParsedTlv::HopCount(HopCount::decode_value(value)?));
            }
            TlvClass::Known(TlvType::PathVector) => {
                out.push(ParsedTlv::PathVector(PathVector::decode_value(value)?));
            }
            TlvClass::Known(TlvType::Ipv4TransportAddress)
            | TlvClass::Known(TlvType::Ipv6TransportAddress) => {
                out.push(ParsedTlv::TransportAddress(TransportAddress::decode_value(
                    value,
                )?));
            }
            TlvClass::Known(TlvType::ConfigSequenceNumber) => {
                out.push(ParsedTlv::ConfigSequenceNumber(
                    ConfigSequenceNumber::decode_value(value)?,
                ));
            }
            TlvClass::Known(TlvType::LabelRequestMessageId) => {
                out.push(ParsedTlv::LabelRequestMessageId(
                    LabelRequestMessageId::decode_value(value)?,
                ));
            }
            class => {
                let (u_bit, f_bit, tlv_type) = match class {
                    TlvClass::Unknown {
                        u_bit,
                        f_bit,
                        tlv_type,
                    } => (u_bit, f_bit, tlv_type),
                    TlvClass::Known(t) => (false, false, t as u16),
                };
                out.push(ParsedTlv::Raw(RawTlv {
                    u_bit,
                    f_bit,
                    tlv_type,
                    value: Vec::from(value),
                }));
            }
        }
        off = end;
    }
    Ok(out)
}

/// Collect the unrecognized TLVs of a parsed stream, applying the
/// §3.3 U-bit rule: U=0 TLVs are a notification-worthy error the
/// caller surfaces; here they are simply kept so the receiver can
/// decide (the session layer emits Unknown TLV notifications for them).
fn unknown_of(parsed: &[ParsedTlv]) -> Vec<RawTlv> {
    parsed
        .iter()
        .filter_map(|t| match t {
            ParsedTlv::Raw(r) => Some(r.clone()),
            _ => None,
        })
        .collect()
}

fn parse_message(body: &[u8]) -> Result<LdpMessage, ParseError> {
    if body.len() < 8 {
        return Err(ParseError::new(
            ErrorKind::Truncated,
            0,
            "truncated message header",
        ));
    }
    let header = u16::from_be_bytes([body[0], body[1]]);
    let msg_len = u16::from_be_bytes([body[2], body[3]]) as usize;
    let u_bit = header & 0x8000 != 0;
    let msg_type = header & 0x7fff;
    if msg_len < 4 {
        return Err(ParseError::new(
            ErrorKind::BadLength,
            2,
            "message length smaller than the Message ID",
        ));
    }
    if body.len() < 4 + msg_len {
        return Err(ParseError::new(
            ErrorKind::Truncated,
            4,
            "truncated message body",
        ));
    }
    let message_id = u32::from_be_bytes([body[4], body[5], body[6], body[7]]);
    let tlvs = parse_tlv_stream(&body[8..4 + msg_len])?;

    let unknown = unknown_of(&tlvs);
    let msg = match MessageType::from_u16(msg_type) {
        Some(MessageType::Notification) => {
            let status = tlvs
                .iter()
                .find_map(|t| match t {
                    ParsedTlv::Status(s) => Some(*s),
                    _ => None,
                })
                .ok_or_else(|| {
                    ParseError::new(ErrorKind::BadLength, 8, "Notification without a Status TLV")
                })?;
            LdpMessage::Notification(NotificationMsg {
                message_id,
                status,
                unknown_tlvs: unknown,
            })
        }
        Some(MessageType::Hello) => {
            let params = tlvs
                .iter()
                .find_map(|t| match t {
                    ParsedTlv::HelloParams(p) => Some(*p),
                    _ => None,
                })
                .ok_or_else(|| {
                    ParseError::new(
                        ErrorKind::BadLength,
                        8,
                        "Hello without Common Hello Parameters TLV",
                    )
                })?;
            let transport_addr = tlvs.iter().find_map(|t| match t {
                ParsedTlv::TransportAddress(a) => Some(*a),
                _ => None,
            });
            let config_seq = tlvs.iter().find_map(|t| match t {
                ParsedTlv::ConfigSequenceNumber(c) => Some(*c),
                _ => None,
            });
            LdpMessage::Hello(HelloMsg {
                message_id,
                params,
                transport_addr,
                config_seq,
                unknown_tlvs: unknown,
            })
        }
        Some(MessageType::Initialization) => {
            let params = tlvs
                .iter()
                .find_map(|t| match t {
                    ParsedTlv::SessionParams(p) => Some(*p),
                    _ => None,
                })
                .ok_or_else(|| {
                    ParseError::new(
                        ErrorKind::BadLength,
                        8,
                        "Initialization without Common Session Parameters TLV",
                    )
                })?;
            LdpMessage::Initialization(InitMsg {
                message_id,
                params,
                unknown_tlvs: unknown,
            })
        }
        Some(MessageType::KeepAlive) => LdpMessage::KeepAlive(KeepAliveMsg { message_id }),
        Some(MessageType::Address) => {
            let addresses = tlvs
                .iter()
                .find_map(|t| match t {
                    ParsedTlv::AddressList(a) => Some(a.clone()),
                    _ => None,
                })
                .ok_or_else(|| {
                    ParseError::new(ErrorKind::BadLength, 8, "Address without Address List TLV")
                })?;
            LdpMessage::Address(AddressMsg {
                message_id,
                addresses,
                unknown_tlvs: unknown,
            })
        }
        Some(MessageType::AddressWithdraw) => {
            let addresses = tlvs
                .iter()
                .find_map(|t| match t {
                    ParsedTlv::AddressList(a) => Some(a.clone()),
                    _ => None,
                })
                .ok_or_else(|| {
                    ParseError::new(
                        ErrorKind::BadLength,
                        8,
                        "Address Withdraw without Address List TLV",
                    )
                })?;
            LdpMessage::AddressWithdraw(AddressWithdrawMsg {
                message_id,
                addresses,
                unknown_tlvs: unknown,
            })
        }
        Some(MessageType::LabelMapping) => {
            let fec = tlvs
                .iter()
                .find_map(|t| match t {
                    ParsedTlv::Fec(f) => Some(f.clone()),
                    _ => None,
                })
                .ok_or_else(|| {
                    ParseError::new(ErrorKind::BadLength, 8, "Label Mapping without FEC TLV")
                })?;
            let label = tlvs
                .iter()
                .find_map(|t| match t {
                    ParsedTlv::GenericLabel(l) => Some(*l),
                    _ => None,
                })
                .ok_or_else(|| {
                    ParseError::new(ErrorKind::BadLength, 8, "Label Mapping without Label TLV")
                })?;
            let hop_count = tlvs.iter().find_map(|t| match t {
                ParsedTlv::HopCount(h) => Some(*h),
                _ => None,
            });
            let path_vector = tlvs.iter().find_map(|t| match t {
                ParsedTlv::PathVector(pv) => Some(pv.clone()),
                _ => None,
            });
            let request_message_id = tlvs.iter().find_map(|t| match t {
                ParsedTlv::LabelRequestMessageId(r) => Some(*r),
                _ => None,
            });
            LdpMessage::LabelMapping(LabelMappingMsg {
                message_id,
                fec,
                label,
                hop_count,
                path_vector,
                request_message_id,
                unknown_tlvs: unknown,
            })
        }
        Some(MessageType::LabelRequest) => {
            let fec = tlvs
                .iter()
                .find_map(|t| match t {
                    ParsedTlv::Fec(f) => Some(f.clone()),
                    _ => None,
                })
                .ok_or_else(|| {
                    ParseError::new(ErrorKind::BadLength, 8, "Label Request without FEC TLV")
                })?;
            let hop_count = tlvs.iter().find_map(|t| match t {
                ParsedTlv::HopCount(h) => Some(*h),
                _ => None,
            });
            let path_vector = tlvs.iter().find_map(|t| match t {
                ParsedTlv::PathVector(pv) => Some(pv.clone()),
                _ => None,
            });
            LdpMessage::LabelRequest(LabelRequestMsg {
                message_id,
                fec,
                hop_count,
                path_vector,
                unknown_tlvs: unknown,
            })
        }
        Some(MessageType::LabelWithdraw) => {
            let (fec, label) = parse_fec_label(&tlvs, "Label Withdraw")?;
            LdpMessage::LabelWithdraw(LabelWithdrawMsg {
                message_id,
                fec,
                label,
                unknown_tlvs: unknown,
            })
        }
        Some(MessageType::LabelRelease) => {
            let (fec, label) = parse_fec_label(&tlvs, "Label Release")?;
            LdpMessage::LabelRelease(LabelReleaseMsg {
                message_id,
                fec,
                label,
                unknown_tlvs: unknown,
            })
        }
        Some(MessageType::LabelAbortRequest) => {
            let fec = tlvs
                .iter()
                .find_map(|t| match t {
                    ParsedTlv::Fec(f) => Some(f.clone()),
                    _ => None,
                })
                .ok_or_else(|| {
                    ParseError::new(
                        ErrorKind::BadLength,
                        8,
                        "Label Abort Request without FEC TLV",
                    )
                })?;
            let request_message_id = tlvs
                .iter()
                .find_map(|t| match t {
                    ParsedTlv::LabelRequestMessageId(r) => Some(*r),
                    _ => None,
                })
                .ok_or_else(|| {
                    ParseError::new(
                        ErrorKind::BadLength,
                        8,
                        "Label Abort Request without Label Request Message ID TLV",
                    )
                })?;
            LdpMessage::LabelAbortRequest(LabelAbortMsg {
                message_id,
                fec,
                request_message_id,
                unknown_tlvs: unknown,
            })
        }
        Some(MessageType::Capability) | None => {
            // RFC 5561 Capability messages carry U=1 and are silently
            // ignored by receivers that do not implement them; other
            // unknown messages keep their own U-bit for the receiver.
            LdpMessage::Unknown(RawMessage {
                u_bit,
                msg_type,
                message_id,
                tlvs: unknown,
            })
        }
    };
    Ok(msg)
}

fn parse_fec_label(
    tlvs: &[ParsedTlv],
    what: &'static str,
) -> Result<(Fec, Option<GenericLabel>), ParseError> {
    let fec = tlvs
        .iter()
        .find_map(|t| match t {
            ParsedTlv::Fec(f) => Some(f.clone()),
            _ => None,
        })
        .ok_or_else(|| {
            ParseError::new(ErrorKind::BadLength, 8, "message without FEC TLV").with_detail(what)
        })?;
    let label = tlvs.iter().find_map(|t| match t {
        ParsedTlv::GenericLabel(l) => Some(*l),
        _ => None,
    });
    Ok((fec, label))
}

// ---------------------------------------------------------------------------
// Codec
// ---------------------------------------------------------------------------

/// The LDP PDU codec (RFC 5036 §3.1 framing).
#[derive(Debug, Clone, Copy, Default)]
pub struct LdpCodec;

impl Encoder<LdpPdu> for LdpCodec {
    fn encode(&self, pdu: &LdpPdu, out: &mut WriteBuf<'_>) -> Result<usize, EncodeError> {
        if pdu.version != LDP_VERSION {
            return Err(EncodeError::InvalidValue("LDP version must be 1"));
        }
        if pdu.messages.is_empty() {
            return Err(EncodeError::InvalidValue(
                "PDU must carry at least one message",
            ));
        }
        let start = out.written().len();
        out.put_u16_be(pdu.version).ok_or(EncodeError::BufferFull)?;
        let len_pos = out.reserve(2).ok_or(EncodeError::BufferFull)?;
        out.put_bytes(&pdu.sender.as_bytes())
            .ok_or(EncodeError::BufferFull)?;
        for msg in &pdu.messages {
            encode_message_body(msg, out)?;
        }
        let written = out.written().len();
        let pdu_len = written
            .checked_sub(len_pos + 2)
            .ok_or(EncodeError::InvalidValue("PDU length underflow"))?;
        u16::try_from(pdu_len)
            .map_err(|_| EncodeError::InvalidValue("PDU exceeds 65535 octets"))
            .and_then(|l| {
                out.patch(len_pos, &l.to_be_bytes())
                    .ok_or(EncodeError::BufferFull)
            })?;
        Ok(written - start)
    }
}

impl Decoder<LdpPdu> for LdpCodec {
    fn decode(&mut self, src: &mut ReadBuf<'_>) -> Result<Option<LdpPdu>, ParseError> {
        // Need the 4-byte PDU header first.
        if src.remaining() < 4 {
            return Ok(None);
        }
        let chunk = src.chunk();
        let version = u16::from_be_bytes([chunk[0], chunk[1]]);
        let pdu_len = u16::from_be_bytes([chunk[2], chunk[3]]) as usize;
        if version != LDP_VERSION {
            return Err(ParseError::new(
                ErrorKind::InvalidValue,
                0,
                "unsupported LDP protocol version",
            )
            .with_detail(version.to_string()));
        }
        if pdu_len < 6 {
            return Err(ParseError::new(
                ErrorKind::BadLength,
                2,
                "PDU length smaller than the LDP Identifier",
            ));
        }
        let total = 4 + pdu_len;
        if src.remaining() < total {
            return Ok(None);
        }
        let whole = src.chunk();
        let sender = LdpId::from_bytes(&whole[4..10])
            .ok_or_else(|| ParseError::truncated("LDP Identifier"))?;
        let mut off = 10usize;
        let end = total;
        let mut messages = Vec::new();
        while off < end {
            if end - off < 4 {
                return Err(ParseError::new(
                    ErrorKind::BadLength,
                    off,
                    "trailing garbage instead of a message header",
                ));
            }
            let header = u16::from_be_bytes([whole[off], whole[off + 1]]);
            let msg_len = u16::from_be_bytes([whole[off + 2], whole[off + 3]]) as usize;
            if (header & 0x7fff) == 0 {
                return Err(ParseError::new(
                    ErrorKind::UnknownType,
                    off,
                    "message type 0 is not a valid LDP message",
                ));
            }
            if msg_len < 4 {
                return Err(ParseError::new(
                    ErrorKind::BadLength,
                    off + 2,
                    "message length smaller than the Message ID",
                ));
            }
            let msg_end = off + 4 + msg_len;
            if msg_end > end {
                return Err(ParseError::new(
                    ErrorKind::BadLength,
                    off + 2,
                    "message extends past the PDU boundary",
                ));
            }
            let msg = parse_message(&whole[off..msg_end])?;
            messages.push(msg);
            off = msg_end;
        }
        // PDU fully parsed - consume it.
        src.advance(total);
        debug_assert_eq!(off, end);
        Ok(Some(LdpPdu {
            version,
            sender,
            messages,
        }))
    }
}

/// Encode a single message (used by tests and embedders that build
/// PDUs incrementally).
pub fn encode_message(msg: &LdpMessage, out: &mut WriteBuf<'_>) -> Result<usize, EncodeError> {
    let start = out.written().len();
    encode_message_body(msg, out)?;
    Ok(out.written().len() - start)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pdu::DEFAULT_MAX_PDU_LEN;
    use crate::tlv::{FecElement, StatusCode};
    use crate::AdvertisementMode;
    use lr_core::addr::Prefix;

    fn roundtrip(pdu: &LdpPdu) -> LdpPdu {
        let mut buf = [0u8; 4096];
        let mut w = WriteBuf::new(&mut buf);
        let n = LdpCodec.encode(pdu, &mut w).unwrap();
        let mut r = ReadBuf::new(&w.written()[..n]);
        LdpCodec.decode(&mut r).unwrap().unwrap()
    }

    fn sample_id(v: u8) -> LdpId {
        LdpId::new([v, 0, 0, 1], 0)
    }

    #[test]
    fn keepalive_pdu_roundtrip() {
        let pdu = LdpPdu {
            version: 1,
            sender: sample_id(1),
            messages: vec![LdpMessage::KeepAlive(KeepAliveMsg { message_id: 7 })],
        };
        let out = roundtrip(&pdu);
        assert_eq!(out.sender, sample_id(1));
        assert_eq!(out.messages.len(), 1);
        assert!(matches!(
            out.messages[0],
            LdpMessage::KeepAlive(KeepAliveMsg { message_id: 7 })
        ));
    }

    #[test]
    fn hello_pdu_roundtrip() {
        let pdu = LdpPdu {
            version: 1,
            sender: sample_id(2),
            messages: vec![LdpMessage::Hello(HelloMsg {
                message_id: 1,
                params: HelloParams {
                    hold_time: 45,
                    targeted: true,
                    request_targeted: true,
                },
                transport_addr: Some(TransportAddress(lr_core::addr::IpAddr::V4([192, 0, 2, 9]))),
                config_seq: Some(ConfigSequenceNumber(42)),
                unknown_tlvs: vec![],
            })],
        };
        let out = roundtrip(&pdu);
        match &out.messages[0] {
            LdpMessage::Hello(h) => {
                assert_eq!(
                    h.params,
                    HelloParams {
                        hold_time: 45,
                        targeted: true,
                        request_targeted: true
                    }
                );
                assert_eq!(
                    h.transport_addr,
                    Some(TransportAddress(lr_core::addr::IpAddr::V4([192, 0, 2, 9])))
                );
                assert_eq!(h.config_seq, Some(ConfigSequenceNumber(42)));
            }
            other => panic!("wrong message {other:?}"),
        }
    }

    #[test]
    fn init_pdu_roundtrip() {
        let params = SessionParams {
            protocol_version: 1,
            keepalive_time: 15,
            advertisement: AdvertisementMode::DownstreamUnsolicited,
            loop_detection: false,
            path_vector_limit: 0,
            max_pdu_len: DEFAULT_MAX_PDU_LEN,
            receiver: sample_id(3),
        };
        let pdu = LdpPdu {
            version: 1,
            sender: sample_id(4),
            messages: vec![LdpMessage::Initialization(InitMsg {
                message_id: 5,
                params,
                unknown_tlvs: vec![],
            })],
        };
        let out = roundtrip(&pdu);
        match &out.messages[0] {
            LdpMessage::Initialization(i) => assert_eq!(i.params, params),
            other => panic!("wrong message {other:?}"),
        }
    }

    #[test]
    fn label_messages_roundtrip() {
        let fec = Fec::prefix(Prefix::new_v4([10, 0, 0, 0], 8));
        let pdu = LdpPdu {
            version: 1,
            sender: sample_id(5),
            messages: vec![
                LdpMessage::LabelMapping(LabelMappingMsg {
                    message_id: 1,
                    fec: fec.clone(),
                    label: GenericLabel(100),
                    hop_count: Some(HopCount(1)),
                    path_vector: None,
                    request_message_id: None,
                    unknown_tlvs: vec![],
                }),
                LdpMessage::LabelRequest(LabelRequestMsg {
                    message_id: 2,
                    fec: fec.clone(),
                    hop_count: Some(HopCount(1)),
                    path_vector: Some(PathVector(Vec::from([0x0a00_0001]))),
                    unknown_tlvs: vec![],
                }),
                LdpMessage::LabelWithdraw(LabelWithdrawMsg {
                    message_id: 3,
                    fec: fec.clone(),
                    label: Some(GenericLabel(100)),
                    unknown_tlvs: vec![],
                }),
                LdpMessage::LabelRelease(LabelReleaseMsg {
                    message_id: 4,
                    fec,
                    label: None,
                    unknown_tlvs: vec![],
                }),
                LdpMessage::LabelAbortRequest(LabelAbortMsg {
                    message_id: 5,
                    fec: Fec::prefix(Prefix::new_v4([10, 0, 0, 0], 8)),
                    request_message_id: LabelRequestMessageId(2),
                    unknown_tlvs: vec![],
                }),
            ],
        };
        let out = roundtrip(&pdu);
        assert_eq!(out.messages.len(), 5);
        match &out.messages[0] {
            LdpMessage::LabelMapping(m) => {
                assert_eq!(m.fec.single_prefix().map(|p| p.prefix_len), Some(8));
                assert_eq!(m.label, GenericLabel(100));
                assert_eq!(m.hop_count, Some(HopCount(1)));
            }
            other => panic!("wrong message {other:?}"),
        }
        match &out.messages[2] {
            LdpMessage::LabelWithdraw(m) => assert_eq!(m.label, Some(GenericLabel(100))),
            other => panic!("wrong message {other:?}"),
        }
        match &out.messages[3] {
            LdpMessage::LabelRelease(m) => assert_eq!(m.label, None),
            other => panic!("wrong message {other:?}"),
        }
    }

    #[test]
    fn notification_and_unknown_roundtrip() {
        let pdu = LdpPdu {
            version: 1,
            sender: sample_id(6),
            messages: vec![
                LdpMessage::Notification(NotificationMsg {
                    message_id: 1,
                    status: Status {
                        code: StatusCode::fatal(0x0a),
                        message_id: 9,
                        message_type: MessageType::Initialization as u16,
                    },
                    unknown_tlvs: vec![],
                }),
                LdpMessage::Unknown(RawMessage {
                    u_bit: true,
                    msg_type: 0x1234,
                    message_id: 2,
                    tlvs: vec![RawTlv {
                        u_bit: true,
                        f_bit: false,
                        tlv_type: 0x5678,
                        value: Vec::from([1, 2, 3]),
                    }],
                }),
            ],
        };
        let out = roundtrip(&pdu);
        match &out.messages[0] {
            LdpMessage::Notification(n) => {
                assert_eq!(n.status.code, StatusCode::fatal(0x0a));
                assert_eq!(n.status.message_type, 0x0200);
            }
            other => panic!("wrong message {other:?}"),
        }
        match &out.messages[1] {
            LdpMessage::Unknown(m) => {
                assert_eq!(m.msg_type, 0x1234);
                assert_eq!(m.tlvs.len(), 1);
                assert_eq!(m.tlvs[0].value, Vec::from([1, 2, 3]));
            }
            other => panic!("wrong message {other:?}"),
        }
    }

    #[test]
    fn address_roundtrip() {
        let pdu = LdpPdu {
            version: 1,
            sender: sample_id(7),
            messages: vec![LdpMessage::Address(AddressMsg {
                message_id: 1,
                addresses: AddressList {
                    addresses: Vec::from([
                        lr_core::addr::IpAddr::V4([192, 0, 2, 1]),
                        lr_core::addr::IpAddr::V4([192, 0, 2, 2]),
                    ]),
                },
                unknown_tlvs: vec![],
            })],
        };
        let out = roundtrip(&pdu);
        match &out.messages[0] {
            LdpMessage::Address(a) => assert_eq!(a.addresses.addresses.len(), 2),
            other => panic!("wrong message {other:?}"),
        }
    }

    #[test]
    fn truncated_pdu_returns_none() {
        let pdu = LdpPdu {
            version: 1,
            sender: sample_id(8),
            messages: vec![LdpMessage::KeepAlive(KeepAliveMsg { message_id: 1 })],
        };
        let mut buf = [0u8; 64];
        let mut w = WriteBuf::new(&mut buf);
        let n = LdpCodec.encode(&pdu, &mut w).unwrap();
        let bytes = &w.written()[..n];
        for cut in 0..n {
            let mut r = ReadBuf::new(&bytes[..cut]);
            assert!(LdpCodec.decode(&mut r).unwrap().is_none(), "cut at {cut}");
        }
        let mut r = ReadBuf::new(bytes);
        assert!(LdpCodec.decode(&mut r).unwrap().is_some());
    }

    #[test]
    fn bad_version_rejected() {
        let mut buf = [0u8; 64];
        let mut w = WriteBuf::new(&mut buf);
        let pdu = LdpPdu {
            version: 1,
            sender: sample_id(9),
            messages: vec![LdpMessage::KeepAlive(KeepAliveMsg { message_id: 1 })],
        };
        let n = LdpCodec.encode(&pdu, &mut w).unwrap();
        let mut bytes = Vec::from(&w.written()[..n]);
        bytes[0] = 0; // version 0x0002
        bytes[1] = 2;
        let mut r = ReadBuf::new(&bytes);
        let err = LdpCodec.decode(&mut r).unwrap_err();
        assert_eq!(err.kind, ErrorKind::InvalidValue);
    }

    #[test]
    fn pdu_boundary_enforced() {
        // A message that claims to extend past the PDU boundary must be
        // rejected rather than consuming into whatever follows.
        // Hand-build: PDU with pdu_len = 16 (6 id + 10 message area),
        // but the inner message claims a 100-octet body.
        let mut bytes: Vec<u8> = Vec::new();
        bytes.extend_from_slice(&1u16.to_be_bytes()); // version
        bytes.extend_from_slice(&16u16.to_be_bytes()); // PDU length
        bytes.extend_from_slice(&[10, 0, 0, 1, 0, 0]); // LDP Id
                                                       // Message: KeepAlive type, msg_len = 100 (id + 96 octets).
        bytes.extend_from_slice(&0x0201u16.to_be_bytes());
        bytes.extend_from_slice(&100u16.to_be_bytes());
        bytes.extend_from_slice(&1u32.to_be_bytes()); // message id
        bytes.extend_from_slice(&[0u8; 96]);
        let mut r = ReadBuf::new(&bytes);
        let err = LdpCodec.decode(&mut r).unwrap_err();
        assert_eq!(err.kind, ErrorKind::BadLength);
    }

    #[test]
    fn hello_without_params_rejected() {
        // Hand-build a Hello with only a Message ID.
        let mut body: Vec<u8> = Vec::new();
        body.extend_from_slice(&0x0100u16.to_be_bytes());
        body.extend_from_slice(&4u16.to_be_bytes());
        body.extend_from_slice(&1u32.to_be_bytes());
        let mut pdu_bytes: Vec<u8> = Vec::new();
        pdu_bytes.extend_from_slice(&1u16.to_be_bytes());
        pdu_bytes.extend_from_slice(&(6 + body.len() as u16).to_be_bytes());
        pdu_bytes.extend_from_slice(&[10, 0, 0, 1, 0, 0]);
        pdu_bytes.extend_from_slice(&body);
        let mut r = ReadBuf::new(&pdu_bytes);
        let err = LdpCodec.decode(&mut r).unwrap_err();
        assert_eq!(err.kind, ErrorKind::BadLength);
    }

    #[test]
    fn wildcard_fec_roundtrip() {
        let pdu = LdpPdu {
            version: 1,
            sender: sample_id(11),
            messages: vec![LdpMessage::LabelWithdraw(LabelWithdrawMsg {
                message_id: 1,
                fec: Fec::wildcard(),
                label: Some(GenericLabel(200)),
                unknown_tlvs: vec![],
            })],
        };
        let out = roundtrip(&pdu);
        match &out.messages[0] {
            LdpMessage::LabelWithdraw(m) => {
                assert!(m.fec.is_wildcard());
                assert_eq!(m.label, Some(GenericLabel(200)));
            }
            other => panic!("wrong message {other:?}"),
        }
    }

    #[test]
    fn ipv6_prefix_and_transport_roundtrip() {
        let pdu = LdpPdu {
            version: 1,
            sender: sample_id(12),
            messages: vec![LdpMessage::Hello(HelloMsg {
                message_id: 1,
                params: HelloParams {
                    hold_time: 45,
                    targeted: true,
                    request_targeted: false,
                },
                transport_addr: Some(TransportAddress(lr_core::addr::IpAddr::V6([
                    0x20, 0x01, 0xd, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
                ]))),
                config_seq: None,
                unknown_tlvs: vec![],
            })],
        };
        let out = roundtrip(&pdu);
        match &out.messages[0] {
            LdpMessage::Hello(h) => match h.transport_addr {
                Some(TransportAddress(lr_core::addr::IpAddr::V6(b))) => {
                    assert_eq!(b[0], 0x20);
                    assert_eq!(b[15], 1);
                }
                other => panic!("wrong transport addr {other:?}"),
            },
            other => panic!("wrong message {other:?}"),
        }
    }

    #[test]
    fn fec_element_unknown_aborts() {
        // A FEC TLV with an unknown element type must abort the message.
        let mut buf = [0u8; 128];
        let mut w = WriteBuf::new(&mut buf);
        // FEC TLV header
        w.put_u16_be(tlv_header_word(false, false, TlvType::Fec as u16))
            .unwrap();
        w.reserve(2).unwrap();
        w.put_u8(0x63).unwrap(); // unknown FEC element type
        let n = w.written().len();
        w.patch(2, &((n - 4) as u16).to_be_bytes()).unwrap();
        let fec_bytes = Vec::from(w.written());
        let err = Fec::decode_value(&fec_bytes[4..]);
        assert!(err.is_err());
        let _ = FecElement::Wildcard; // silence unused when feature-gated
    }
}
