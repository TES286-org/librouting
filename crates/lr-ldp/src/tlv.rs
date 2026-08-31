//! LDP TLV value encodings (RFC 5036 §3.4).
//!
//! Each type here owns the *value* bytes of one TLV: `encode_value`
//! writes the Value field and `decode_value` parses it from a slice.
//! The TLV header framing (U/F/type/length) is handled by the message
//! codec in [`crate::message`], which also routes unknown TLVs into
//! [`RawTlv`] buckets per the §3.3 U-bit rules.
//!
//! Handled here: FEC (§3.4.1), Generic Label (§3.4.2.1), Address List
//! (§3.4.3), Hop Count (§3.4.4), Path Vector (§3.4.5), Status (§3.4.6),
//! Common Hello Parameters (§3.5.2), Common Session Parameters
//! (§3.5.3), the IPv4/IPv6 Transport Address TLVs (§3.5.2, RFC 7552),
//! the Configuration Sequence Number (§3.5.2) and the Label Request
//! Message ID (§3.8).

use crate::pdu::{tlv_header_word, AdvertisementMode, LdpId, TlvType, LDP_VERSION};
#[cfg(not(feature = "std"))]
use alloc::format;
#[cfg(not(feature = "std"))]
use alloc::string::ToString;
use lr_core::addr::{IpAddr, Prefix};
use lr_core::buf::WriteBuf;
use lr_core::error::{EncodeError, ErrorKind, ParseError};

// ---------------------------------------------------------------------------
// Generic Label (§3.4.2.1)
// ---------------------------------------------------------------------------

/// A Generic Label TLV value: a 20-bit MPLS label (RFC 3032) in a
/// 4-octet field. The special labels (IPv4 Explicit NULL = 0,
/// Router Alert = 1, IPv6 Explicit NULL = 2, Implicit NULL = 3) are
/// carried as ordinary values; RFC 5036 §3.10.2 notes Implicit NULL is
/// represented as label value 3.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Default)]
pub struct GenericLabel(pub u32);

impl GenericLabel {
    pub const IPV4_EXPLICIT_NULL: Self = Self(0);
    pub const ROUTER_ALERT: Self = Self(1);
    pub const IPV6_EXPLICIT_NULL: Self = Self(2);
    pub const IMPLICIT_NULL: Self = Self(3);

    /// Whether the value fits the 20-bit label field.
    pub const fn is_valid(self) -> bool {
        self.0 <= 0x000f_ffff
    }
}

// ---------------------------------------------------------------------------
// FEC TLV (§3.4.1)
// ---------------------------------------------------------------------------

/// A FEC element. This version of LDP defines the Wildcard element
/// (Label Withdraw / Release only, §3.4.1) and the Prefix element;
/// unknown element types abort message processing per the FEC
/// procedures (§3.4.1.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FecElement {
    /// Prefix FEC element: address family + prefix length + prefix.
    Prefix(Prefix),
    /// Wildcard FEC element (no value octets).
    Wildcard,
}

impl FecElement {
    const TYPE_WILDCARD: u8 = 0x01;
    const TYPE_PREFIX: u8 = 0x02;

    /// Number of octets this element occupies on the wire (type byte
    /// included).
    pub fn encoded_len(&self) -> usize {
        match self {
            // type(1) + af(2) + prelen(1) + prefix bytes
            Self::Prefix(p) => 4 + prefix_wire_bytes(p),
            Self::Wildcard => 1,
        }
    }

    /// Write the element (type byte included).
    pub fn encode(&self, out: &mut WriteBuf<'_>) -> Result<(), EncodeError> {
        let full = |opt: Option<()>| opt.ok_or(EncodeError::BufferFull);
        match self {
            Self::Wildcard => {
                full(out.put_u8(Self::TYPE_WILDCARD))?;
            }
            Self::Prefix(p) => {
                full(out.put_u8(Self::TYPE_PREFIX))?;
                let (af, n, bytes) = prefix_wire_fields(p)?;
                full(out.put_u16_be(af))?;
                full(out.put_u8(p.prefix_len))?;
                // Encode exactly ceil(prelen/8) bytes, matching the RFC
                // "padded to a byte boundary" rule and FRR's
                // PREFIX_SIZE(prelen) framing.
                full(out.put_bytes(&bytes[..n]))?;
            }
        }
        Ok(())
    }

    /// Parse one element from a byte cursor. `off` is advanced past the
    /// element on success.
    pub fn decode(buf: &[u8], off: &mut usize) -> Result<Self, ParseError> {
        let base = *off;
        let typ = *buf.get(base).ok_or(ParseError::truncated("FEC element"))?;
        match typ {
            Self::TYPE_WILDCARD => {
                *off += 1;
                Ok(Self::Wildcard)
            }
            Self::TYPE_PREFIX => {
                if buf.len() < base + 4 {
                    return Err(ParseError::truncated("Prefix FEC element"));
                }
                let af = u16::from_be_bytes([buf[base + 1], buf[base + 2]]);
                let prelen = buf[base + 3];
                let max_bits = match af {
                    1 => 32usize,
                    2 => 128,
                    _ => {
                        return Err(ParseError::new(
                            ErrorKind::Unsupported,
                            base + 1,
                            "unsupported FEC address family",
                        )
                        .with_detail(af.to_string()))
                    }
                };
                if prelen as usize > max_bits {
                    return Err(ParseError::new(
                        ErrorKind::InvalidValue,
                        base + 3,
                        "invalid prefix length for FEC address family",
                    )
                    .with_detail(prelen.to_string()));
                }
                let want = (prelen as usize).div_ceil(8);
                if buf.len() < base + 4 + want {
                    return Err(ParseError::truncated("Prefix FEC element bytes"));
                }
                let mut addr = [0u8; 16];
                addr[..want].copy_from_slice(&buf[base + 4..base + 4 + want]);
                *off = base + 4 + want;
                let prefix = if af == 1 {
                    Prefix::new_v4([addr[0], addr[1], addr[2], addr[3]], prelen)
                } else {
                    Prefix::new_v6(addr, prelen)
                };
                Ok(Self::Prefix(prefix))
            }
            other => Err(
                ParseError::new(ErrorKind::UnknownType, base, "unknown FEC element type")
                    .with_detail(format!("{other:#x}")),
            ),
        }
    }
}

/// Round a prefix length up to the wire byte count.
fn prefix_wire_bytes(p: &Prefix) -> usize {
    (p.prefix_len as usize).div_ceil(8)
}

/// Address family number, wire byte count and padded address bytes for
/// a Prefix FEC element.
fn prefix_wire_fields(p: &Prefix) -> Result<(u16, usize, [u8; 16]), EncodeError> {
    match p.addr {
        IpAddr::V4(b) => {
            if p.prefix_len > 32 {
                return Err(EncodeError::InvalidValue("invalid IPv4 prefix length"));
            }
            let n = (p.prefix_len as usize).div_ceil(8);
            let mut addr = [0u8; 16];
            addr[..4].copy_from_slice(&b);
            Ok((1, n, addr))
        }
        IpAddr::V6(b) => {
            if p.prefix_len > 128 {
                return Err(EncodeError::InvalidValue("invalid IPv6 prefix length"));
            }
            let n = (p.prefix_len as usize).div_ceil(8);
            Ok((2, n, b))
        }
    }
}

/// A FEC TLV value: one or more FEC elements. Multiple elements are
/// only permitted in Label Mapping messages (§3.4.1).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Default)]
pub struct Fec {
    pub elements: alloc::vec::Vec<FecElement>,
}

impl Fec {
    /// Convenience constructor for the common single-Prefix case.
    pub fn prefix(p: Prefix) -> Self {
        Self {
            elements: alloc::vec::Vec::from([FecElement::Prefix(p)]),
        }
    }

    /// Convenience constructor for the Wildcard FEC.
    pub fn wildcard() -> Self {
        Self {
            elements: alloc::vec::Vec::from([FecElement::Wildcard]),
        }
    }

    /// The single prefix, if this FEC is exactly one Prefix element.
    pub fn single_prefix(&self) -> Option<&Prefix> {
        match self.elements.as_slice() {
            [FecElement::Prefix(p)] => Some(p),
            _ => None,
        }
    }

    pub fn is_wildcard(&self) -> bool {
        matches!(self.elements.as_slice(), [FecElement::Wildcard])
    }
}

// ---------------------------------------------------------------------------
// Address List TLV (§3.4.3)
// ---------------------------------------------------------------------------

/// An Address List TLV value: an address family plus a homogeneous list
/// of addresses (4 octets each for IPv4, 16 for IPv6).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Default)]
pub struct AddressList {
    pub addresses: alloc::vec::Vec<IpAddr>,
}

impl AddressList {
    fn family(&self) -> Result<u16, EncodeError> {
        match self.addresses.first() {
            Some(IpAddr::V4(_)) => {
                if self.addresses.iter().any(|a| a.is_ipv6()) {
                    return Err(EncodeError::InvalidValue("mixed-family address list"));
                }
                Ok(1)
            }
            Some(IpAddr::V6(_)) => Ok(2),
            None => Err(EncodeError::InvalidValue("empty address list")),
        }
    }
}

// ---------------------------------------------------------------------------
// Common Hello Parameters TLV (§3.5.2)
// ---------------------------------------------------------------------------

/// The Common Hello Parameters TLV value (4 octets): Hold Time plus the
/// T (Targeted Hello) and R (Request Send Targeted Hellos) flags.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct HelloParams {
    /// Hello hold time in seconds; 0 means the link/targeted default,
    /// 0xffff means infinite.
    pub hold_time: u16,
    /// T-bit: this Hello is a Targeted Hello.
    pub targeted: bool,
    /// R-bit: request the receiver to send periodic Targeted Hellos.
    pub request_targeted: bool,
}

impl Default for HelloParams {
    fn default() -> Self {
        Self {
            hold_time: crate::pdu::DEFAULT_LINK_HELLO_HOLD,
            targeted: false,
            request_targeted: false,
        }
    }
}

// ---------------------------------------------------------------------------
// Common Session Parameters TLV (§3.5.3)
// ---------------------------------------------------------------------------

/// The Common Session Parameters TLV value carried by every
/// Initialization message (14 octets).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SessionParams {
    /// Protocol version (MUST be 1 for this implementation).
    pub protocol_version: u16,
    /// Proposed KeepAlive Time in seconds (non-zero).
    pub keepalive_time: u16,
    /// Label advertisement discipline (A-bit).
    pub advertisement: AdvertisementMode,
    /// Loop Detection flag (D-bit); implies a Path Vector limit.
    pub loop_detection: bool,
    /// Path Vector Limit (PVLim); MUST be 0 when loop detection is off.
    pub path_vector_limit: u8,
    /// Proposed maximum PDU length; <= 255 means the 4096 default.
    pub max_pdu_len: u16,
    /// The receiver's label space (from the sender's point of view).
    pub receiver: LdpId,
}

impl Default for SessionParams {
    fn default() -> Self {
        Self {
            protocol_version: LDP_VERSION,
            keepalive_time: crate::pdu::DEFAULT_KEEPALIVE_TIME,
            advertisement: AdvertisementMode::DownstreamUnsolicited,
            loop_detection: false,
            path_vector_limit: 0,
            max_pdu_len: crate::pdu::DEFAULT_MAX_PDU_LEN,
            receiver: LdpId::default(),
        }
    }
}

// ---------------------------------------------------------------------------
// Status TLV (§3.4.6) and the status code registry (§3.9)
// ---------------------------------------------------------------------------

/// A 32-bit LDP Status Code: the E (fatal) bit, the F (forward) bit and
/// 30 bits of status data (RFC 5036 §3.4.6).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct StatusCode(pub u32);

impl StatusCode {
    /// Status codes carry the RFC 5036 §3.9 "E" (fatal) column baked
    /// into the constant, matching the wire value the RFC requires.
    pub const SUCCESS: Self = Self(0x0000_0000);
    pub const BAD_LDP_IDENTIFIER: Self = Self::fatal(0x0000_0001);
    pub const BAD_PROTOCOL_VERSION: Self = Self::fatal(0x0000_0002);
    pub const BAD_PDU_LENGTH: Self = Self::fatal(0x0000_0003);
    pub const UNKNOWN_MESSAGE_TYPE: Self = Self(0x0000_0004);
    pub const BAD_MESSAGE_LENGTH: Self = Self::fatal(0x0000_0005);
    pub const UNKNOWN_TLV: Self = Self(0x0000_0006);
    pub const BAD_TLV_LENGTH: Self = Self::fatal(0x0000_0007);
    pub const MALFORMED_TLV_VALUE: Self = Self::fatal(0x0000_0008);
    pub const HOLD_TIMER_EXPIRED: Self = Self::fatal(0x0000_0009);
    pub const SHUTDOWN: Self = Self::fatal(0x0000_000a);
    pub const LOOP_DETECTED: Self = Self(0x0000_000b);
    pub const UNKNOWN_FEC: Self = Self(0x0000_000c);
    pub const NO_ROUTE: Self = Self(0x0000_000d);
    pub const NO_LABEL_RESOURCES: Self = Self(0x0000_000e);
    pub const LABEL_RESOURCES_AVAILABLE: Self = Self(0x0000_000f);
    pub const SESSION_REJECTED_NO_HELLO: Self = Self::fatal(0x0000_0010);
    pub const SESSION_REJECTED_PARAMETERS_ADV_MODE: Self = Self::fatal(0x0000_0011);
    pub const SESSION_REJECTED_PARAMETERS_MAX_PDU: Self = Self::fatal(0x0000_0012);
    pub const SESSION_REJECTED_PARAMETERS_LABEL_RANGE: Self = Self::fatal(0x0000_0013);
    pub const KEEPALIVE_TIMER_EXPIRED: Self = Self::fatal(0x0000_0014);
    pub const LABEL_REQUEST_ABORTED: Self = Self(0x0000_0015);
    pub const MISSING_MESSAGE_PARAMETERS: Self = Self(0x0000_0016);
    pub const UNSUPPORTED_ADDRESS_FAMILY: Self = Self(0x0000_0017);
    pub const SESSION_REJECTED_BAD_KEEPALIVE_TIME: Self = Self::fatal(0x0000_0018);
    pub const INTERNAL_ERROR: Self = Self::fatal(0x0000_0019);

    /// E-bit: this is a fatal error notification.
    pub const fn is_fatal(self) -> bool {
        self.0 & 0x8000_0000 != 0
    }

    /// F-bit: forward the notification along the LSP.
    pub const fn is_forward(self) -> bool {
        self.0 & 0x4000_0000 != 0
    }

    /// The 30-bit status data.
    pub const fn data(self) -> u32 {
        self.0 & 0x3fff_ffff
    }

    /// Build a code with the fatal bit set.
    pub const fn fatal(data: u32) -> Self {
        Self(data | 0x8000_0000)
    }
}

/// A Status TLV value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct Status {
    pub code: StatusCode,
    /// Message ID of the message being reported (0 = none).
    pub message_id: u32,
    /// Type of the message being reported (0 = none).
    pub message_type: u16,
}

// ---------------------------------------------------------------------------
// Simple scalar TLVs
// ---------------------------------------------------------------------------

/// Hop Count TLV value (§3.4.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct HopCount(pub u8);

/// Path Vector TLV value (§3.4.5): the LSR Ids traversed so far.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Default)]
pub struct PathVector(pub alloc::vec::Vec<u32>);

/// Configuration Sequence Number TLV value (§3.5.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct ConfigSequenceNumber(pub u32);

/// Label Request Message ID TLV value (§3.8, used by Label Mapping).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct LabelRequestMessageId(pub u32);

/// Transport Address TLV: IPv4 (0x0401) or IPv6 (0x0403, RFC 7552).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TransportAddress(pub IpAddr);

impl TransportAddress {
    pub fn tlv_type(&self) -> TlvType {
        match self.0 {
            IpAddr::V4(_) => TlvType::Ipv4TransportAddress,
            IpAddr::V6(_) => TlvType::Ipv6TransportAddress,
        }
    }
}

// ---------------------------------------------------------------------------
// Raw (unknown) TLVs
// ---------------------------------------------------------------------------

/// An unrecognized TLV preserved verbatim so the receiver can apply the
/// RFC 5036 §3.3 U-bit rules (silently ignore vs notify) and so the
/// codec round-trips bytes it does not interpret.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RawTlv {
    pub u_bit: bool,
    pub f_bit: bool,
    pub tlv_type: u16,
    pub value: alloc::vec::Vec<u8>,
}

impl RawTlv {
    pub fn header_word(&self) -> u16 {
        tlv_header_word(self.u_bit, self.f_bit, self.tlv_type)
    }
}

// ---------------------------------------------------------------------------
// Value encode helpers (called from the message codec)
// ---------------------------------------------------------------------------

/// Write the value octets of a TLV (no header). Kept here so all value
/// layouts stay next to their types.
pub mod wire {
    use super::*;

    pub fn generic_label(out: &mut WriteBuf<'_>, l: &GenericLabel) -> Result<(), EncodeError> {
        if !l.is_valid() {
            return Err(EncodeError::InvalidValue("label exceeds 20 bits"));
        }
        out.put_u32_be(l.0).ok_or(EncodeError::BufferFull)
    }

    pub fn address_list(out: &mut WriteBuf<'_>, a: &AddressList) -> Result<(), EncodeError> {
        out.put_u16_be(a.family()?).ok_or(EncodeError::BufferFull)?;
        for addr in &a.addresses {
            match addr {
                IpAddr::V4(b) => out.put_bytes(b).ok_or(EncodeError::BufferFull)?,
                IpAddr::V6(b) => out.put_bytes(b).ok_or(EncodeError::BufferFull)?,
            }
        }
        Ok(())
    }

    pub fn hello_params(out: &mut WriteBuf<'_>, p: &HelloParams) -> Result<(), EncodeError> {
        out.put_u16_be(p.hold_time).ok_or(EncodeError::BufferFull)?;
        let flags: u16 =
            (if p.targeted { 0x8000 } else { 0 }) | (if p.request_targeted { 0x4000 } else { 0 });
        out.put_u16_be(flags).ok_or(EncodeError::BufferFull)
    }

    pub fn session_params(out: &mut WriteBuf<'_>, p: &SessionParams) -> Result<(), EncodeError> {
        out.put_u16_be(p.protocol_version)
            .ok_or(EncodeError::BufferFull)?;
        out.put_u16_be(p.keepalive_time)
            .ok_or(EncodeError::BufferFull)?;
        let flags: u8 = (if p.advertisement == AdvertisementMode::DownstreamOnDemand {
            0x80
        } else {
            0
        }) | (if p.loop_detection { 0x40 } else { 0 });
        out.put_u8(flags).ok_or(EncodeError::BufferFull)?;
        out.put_u8(p.path_vector_limit)
            .ok_or(EncodeError::BufferFull)?;
        out.put_u16_be(p.max_pdu_len)
            .ok_or(EncodeError::BufferFull)?;
        out.put_bytes(&p.receiver.as_bytes())
            .ok_or(EncodeError::BufferFull)
    }

    pub fn status(out: &mut WriteBuf<'_>, s: &Status) -> Result<(), EncodeError> {
        out.put_u32_be(s.code.0).ok_or(EncodeError::BufferFull)?;
        out.put_u32_be(s.message_id)
            .ok_or(EncodeError::BufferFull)?;
        out.put_u16_be(s.message_type)
            .ok_or(EncodeError::BufferFull)
    }

    pub fn hop_count(out: &mut WriteBuf<'_>, h: &HopCount) -> Result<(), EncodeError> {
        out.put_u8(h.0).ok_or(EncodeError::BufferFull)
    }

    pub fn path_vector(out: &mut WriteBuf<'_>, pv: &PathVector) -> Result<(), EncodeError> {
        for id in &pv.0 {
            out.put_u32_be(*id).ok_or(EncodeError::BufferFull)?;
        }
        Ok(())
    }

    pub fn config_sequence_number(
        out: &mut WriteBuf<'_>,
        c: &ConfigSequenceNumber,
    ) -> Result<(), EncodeError> {
        out.put_u32_be(c.0).ok_or(EncodeError::BufferFull)
    }

    pub fn label_request_message_id(
        out: &mut WriteBuf<'_>,
        r: &LabelRequestMessageId,
    ) -> Result<(), EncodeError> {
        out.put_u32_be(r.0).ok_or(EncodeError::BufferFull)
    }

    pub fn transport_address(
        out: &mut WriteBuf<'_>,
        t: &TransportAddress,
    ) -> Result<(), EncodeError> {
        match t.0 {
            IpAddr::V4(b) => out.put_bytes(&b).ok_or(EncodeError::BufferFull),
            IpAddr::V6(b) => out.put_bytes(&b).ok_or(EncodeError::BufferFull),
        }
    }
}

// ---------------------------------------------------------------------------
// Value decode helpers (called from the message codec)
// ---------------------------------------------------------------------------

/// Decode the value octets of a FEC TLV into elements (§3.4.1). The
/// whole value must decode cleanly; a trailing partial element is a
/// truncation error.
impl Fec {
    pub fn decode_value(v: &[u8]) -> Result<Self, ParseError> {
        let mut off = 0usize;
        let mut elements = alloc::vec::Vec::new();
        while off < v.len() {
            elements.push(FecElement::decode(v, &mut off)?);
        }
        Ok(Self { elements })
    }
}

impl GenericLabel {
    pub fn decode_value(v: &[u8]) -> Result<Self, ParseError> {
        if v.len() != 4 {
            return Err(ParseError::new(
                ErrorKind::BadLength,
                0,
                "Generic Label value must be 4 octets",
            ));
        }
        Ok(Self(u32::from_be_bytes([v[0], v[1], v[2], v[3]])))
    }
}

impl AddressList {
    pub fn decode_value(v: &[u8]) -> Result<Self, ParseError> {
        if v.len() < 2 {
            return Err(ParseError::truncated("Address List family"));
        }
        let af = u16::from_be_bytes([v[0], v[1]]);
        let rest = &v[2..];
        let (addr_len, af_name) = match af {
            1 => (4usize, "IPv4"),
            2 => (16, "IPv6"),
            _ => {
                return Err(ParseError::new(
                    ErrorKind::Unsupported,
                    0,
                    "unsupported Address List family",
                )
                .with_detail(af.to_string()))
            }
        };
        if !rest.len().is_multiple_of(addr_len) {
            return Err(ParseError::new(
                ErrorKind::BadLength,
                2,
                "Address List body is not a multiple of the family size",
            )
            .with_detail(af_name));
        }
        let mut addresses = alloc::vec::Vec::with_capacity(rest.len() / addr_len);
        let mut off = 0usize;
        while off < rest.len() {
            if af == 1 {
                addresses.push(IpAddr::V4([
                    rest[off],
                    rest[off + 1],
                    rest[off + 2],
                    rest[off + 3],
                ]));
            } else {
                let mut b = [0u8; 16];
                b.copy_from_slice(&rest[off..off + 16]);
                addresses.push(IpAddr::V6(b));
            }
            off += addr_len;
        }
        Ok(Self { addresses })
    }
}

impl HelloParams {
    pub fn decode_value(v: &[u8]) -> Result<Self, ParseError> {
        if v.len() != 4 {
            return Err(ParseError::new(
                ErrorKind::BadLength,
                0,
                "Common Hello Parameters value must be 4 octets",
            ));
        }
        let hold_time = u16::from_be_bytes([v[0], v[1]]);
        let flags = u16::from_be_bytes([v[2], v[3]]);
        Ok(Self {
            hold_time,
            targeted: flags & 0x8000 != 0,
            request_targeted: flags & 0x4000 != 0,
        })
    }
}

impl SessionParams {
    pub fn decode_value(v: &[u8]) -> Result<Self, ParseError> {
        if v.len() != 14 {
            return Err(ParseError::new(
                ErrorKind::BadLength,
                0,
                "Common Session Parameters value must be 14 octets",
            ));
        }
        let protocol_version = u16::from_be_bytes([v[0], v[1]]);
        let keepalive_time = u16::from_be_bytes([v[2], v[3]]);
        let flags = v[4];
        let path_vector_limit = v[5];
        let max_pdu_len = u16::from_be_bytes([v[6], v[7]]);
        let receiver = LdpId::from_bytes(&v[8..14])
            .ok_or_else(|| ParseError::truncated("session parameters receiver id"))?;
        Ok(Self {
            protocol_version,
            keepalive_time,
            advertisement: if flags & 0x80 != 0 {
                AdvertisementMode::DownstreamOnDemand
            } else {
                AdvertisementMode::DownstreamUnsolicited
            },
            loop_detection: flags & 0x40 != 0,
            path_vector_limit,
            max_pdu_len,
            receiver,
        })
    }
}

impl Status {
    pub fn decode_value(v: &[u8]) -> Result<Self, ParseError> {
        if v.len() != 10 {
            return Err(ParseError::new(
                ErrorKind::BadLength,
                0,
                "Status value must be 10 octets",
            ));
        }
        Ok(Self {
            code: StatusCode(u32::from_be_bytes([v[0], v[1], v[2], v[3]])),
            message_id: u32::from_be_bytes([v[4], v[5], v[6], v[7]]),
            message_type: u16::from_be_bytes([v[8], v[9]]),
        })
    }
}

impl HopCount {
    pub fn decode_value(v: &[u8]) -> Result<Self, ParseError> {
        if v.len() != 1 {
            return Err(ParseError::new(
                ErrorKind::BadLength,
                0,
                "Hop Count value must be 1 octet",
            ));
        }
        Ok(Self(v[0]))
    }
}

impl PathVector {
    pub fn decode_value(v: &[u8]) -> Result<Self, ParseError> {
        if !v.len().is_multiple_of(4) {
            return Err(ParseError::new(
                ErrorKind::BadLength,
                0,
                "Path Vector value must be a multiple of 4 octets",
            ));
        }
        let (chunks, rest) = v.as_chunks::<4>();
        let mut ids = alloc::vec::Vec::with_capacity(chunks.len());
        for chunk in chunks {
            ids.push(u32::from_be_bytes(*chunk));
        }
        debug_assert!(rest.is_empty());
        Ok(Self(ids))
    }
}

impl ConfigSequenceNumber {
    pub fn decode_value(v: &[u8]) -> Result<Self, ParseError> {
        if v.len() != 4 {
            return Err(ParseError::new(
                ErrorKind::BadLength,
                0,
                "Config Sequence Number value must be 4 octets",
            ));
        }
        Ok(Self(u32::from_be_bytes([v[0], v[1], v[2], v[3]])))
    }
}

impl LabelRequestMessageId {
    pub fn decode_value(v: &[u8]) -> Result<Self, ParseError> {
        if v.len() != 4 {
            return Err(ParseError::new(
                ErrorKind::BadLength,
                0,
                "Label Request Message ID value must be 4 octets",
            ));
        }
        Ok(Self(u32::from_be_bytes([v[0], v[1], v[2], v[3]])))
    }
}

impl TransportAddress {
    pub fn decode_value(v: &[u8]) -> Result<Self, ParseError> {
        match v.len() {
            4 => Ok(Self(IpAddr::V4([v[0], v[1], v[2], v[3]]))),
            16 => {
                let mut b = [0u8; 16];
                b.copy_from_slice(v);
                Ok(Self(IpAddr::V6(b)))
            }
            _ => Err(ParseError::new(
                ErrorKind::BadLength,
                0,
                "Transport Address value must be 4 or 16 octets",
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn label_validity() {
        assert!(GenericLabel::IMPLICIT_NULL.is_valid());
        assert!(GenericLabel(0x000f_ffff).is_valid());
        assert!(!GenericLabel(0x0010_0000).is_valid());
    }

    #[test]
    fn status_code_bits() {
        let fatal = StatusCode::fatal(0x0000_0014); // KeepAlive Timer Expired
        assert!(fatal.is_fatal());
        assert_eq!(fatal.data(), 0x14);
        assert_eq!(fatal, StatusCode::KEEPALIVE_TIMER_EXPIRED);
        assert!(!StatusCode::LOOP_DETECTED.is_fatal());
    }

    #[test]
    fn fec_element_lengths() {
        let p24 = FecElement::Prefix(Prefix::new_v4([10, 1, 2, 3], 24));
        assert_eq!(p24.encoded_len(), 4 + 3);
        let p0 = FecElement::Prefix(Prefix::new_v4([0, 0, 0, 0], 0));
        assert_eq!(p0.encoded_len(), 4);
        let w = FecElement::Wildcard;
        assert_eq!(w.encoded_len(), 1);
        let v6 = FecElement::Prefix(Prefix::new_v6(
            [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            32,
        ));
        assert_eq!(v6.encoded_len(), 4 + 4);
    }

    #[test]
    fn fec_element_prefix_decode_exact_framing() {
        // 10.1.2.0/24 -> type 0x02, AF 1, prelen 24, 3 prefix bytes.
        let mut buf = [0u8; 8];
        buf[0] = 0x02;
        buf[1] = 0x00;
        buf[2] = 0x01;
        buf[3] = 24;
        buf[4] = 10;
        buf[5] = 1;
        buf[6] = 2;
        let mut off = 0;
        let el = FecElement::decode(&buf, &mut off).unwrap();
        assert_eq!(off, 7);
        assert_eq!(el, FecElement::Prefix(Prefix::new_v4([10, 1, 2, 0], 24)));
    }

    #[test]
    fn fec_element_prefix_decode_rejects_bad_family() {
        let mut buf = [0u8; 8];
        buf[0] = 0x02;
        buf[1] = 0x00;
        buf[2] = 0x63; // 99 - unassigned AF
        buf[3] = 24;
        let mut off = 0;
        let err = FecElement::decode(&buf, &mut off).unwrap_err();
        assert_eq!(err.kind, ErrorKind::Unsupported);
    }

    #[test]
    fn fec_element_prefix_decode_rejects_bad_prelen() {
        let mut buf = [0u8; 8];
        buf[0] = 0x02;
        buf[1] = 0x00;
        buf[2] = 0x01;
        buf[3] = 33; // > 32 for IPv4
        let mut off = 0;
        let err = FecElement::decode(&buf, &mut off).unwrap_err();
        assert_eq!(err.kind, ErrorKind::InvalidValue);
    }

    #[test]
    fn fec_element_truncated() {
        let buf = [0x02, 0x00, 0x01, 24, 10, 1]; // missing a prefix byte
        let mut off = 0;
        let err = FecElement::decode(&buf, &mut off).unwrap_err();
        assert_eq!(err.kind, ErrorKind::Truncated);
    }

    #[test]
    fn fec_element_unknown_type() {
        let buf = [0x63];
        let mut off = 0;
        let err = FecElement::decode(&buf, &mut off).unwrap_err();
        assert_eq!(err.kind, ErrorKind::UnknownType);
    }

    #[test]
    fn session_params_default_shape() {
        let p = SessionParams::default();
        assert_eq!(p.protocol_version, 1);
        assert_eq!(p.receiver, LdpId::default());
        assert_eq!(p.max_pdu_len, 4096);
    }
}
