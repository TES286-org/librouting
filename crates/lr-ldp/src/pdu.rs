//! LDP wire primitives: LDP Identifier, PDU header, message and TLV
//! type registries (RFC 5036 §3.1, §3.3, §3.5, §3.8).
//!
//! Wire layout of the LDP PDU header:
//!
//! ```text
//!  0                   1                   2                   3
//!  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |  Version                      |         PDU Length            |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                         LDP Identifier                        |
//! +                               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                               |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! ```
//!
//! `PDU Length` is the total length in octets excluding the Version and
//! PDU Length fields (i.e. the 6-byte LDP Identifier plus every message).

use core::fmt;

/// LDP protocol version (RFC 5036 §3.1: version 1).
pub const LDP_VERSION: u16 = 1;

/// The well-known LDP port for both UDP discovery (Hellos) and TCP
/// session connections (RFC 5036 §3.10.1).
pub const LDP_PORT: u16 = 646;

/// Default maximum PDU length before / without negotiation
/// (RFC 5036 §3.5.3: "A value of 255 or less specifies the default
/// maximum length of 4096 octets"; pre-negotiation the maximum is 4096).
pub const DEFAULT_MAX_PDU_LEN: u16 = 4096;

/// Default Link Hello hold time in seconds (RFC 5036 §3.5.2: a Hold
/// Time of 0 means 15 seconds for Link Hellos).
pub const DEFAULT_LINK_HELLO_HOLD: u16 = 15;

/// Default Targeted Hello hold time in seconds (RFC 5036 §3.5.2: a Hold
/// Time of 0 means 45 seconds for Targeted Hellos).
pub const DEFAULT_TARGETED_HELLO_HOLD: u16 = 45;

/// Default KeepAlive time in seconds proposed in the Initialization
/// message. The RFC leaves the value to implementation; 15 seconds
/// matches FRR/ldpd and the keepalive interval is hold/3.
pub const DEFAULT_KEEPALIVE_TIME: u16 = 15;

/// The six-octet LDP Identifier (RFC 5036 §3.1): a 32-bit LSR Id
/// (globally unique, typically the router Id) plus a 16-bit label
/// space Id (both zero for a platform-wide label space).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Default)]
pub struct LdpId {
    /// 32-bit LSR Id, network byte order as bytes.
    pub lsr_id: [u8; 4],
    /// 16-bit label space Id (0 for platform-wide).
    pub label_space: u16,
}

impl LdpId {
    /// Build from raw parts.
    pub const fn new(lsr_id: [u8; 4], label_space: u16) -> Self {
        Self {
            lsr_id,
            label_space,
        }
    }

    /// Encode the six wire bytes.
    pub const fn as_bytes(&self) -> [u8; 6] {
        [
            self.lsr_id[0],
            self.lsr_id[1],
            self.lsr_id[2],
            self.lsr_id[3],
            (self.label_space >> 8) as u8,
            (self.label_space & 0xff) as u8,
        ]
    }

    /// Parse the six wire bytes.
    pub fn from_bytes(b: &[u8]) -> Option<Self> {
        if b.len() < 6 {
            return None;
        }
        Some(Self {
            lsr_id: [b[0], b[1], b[2], b[3]],
            label_space: u16::from_be_bytes([b[4], b[5]]),
        })
    }
}

impl fmt::Display for LdpId {
    /// Renders as `a.b.c.d:ls` (the conventional `LSR Id : label space`).
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}.{}.{}.{}:{}",
            self.lsr_id[0], self.lsr_id[1], self.lsr_id[2], self.lsr_id[3], self.label_space
        )
    }
}

/// The label advertisement discipline negotiated by the Initialization
/// message (RFC 5036 §3.5.3, the A-bit).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum AdvertisementMode {
    /// Downstream Unsolicited (A-bit 0) — the mode used by mainstream
    /// implementations and the resolved winner when the two peers
    /// disagree (§3.5.3).
    #[default]
    DownstreamUnsolicited,
    /// Downstream On Demand (A-bit 1).
    DownstreamOnDemand,
}

/// Message types (RFC 5036 §3.5; RFC 5561 adds the Capability message).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum MessageType {
    Notification = 0x0001,
    Hello = 0x0100,
    Initialization = 0x0200,
    KeepAlive = 0x0201,
    Capability = 0x0202,
    Address = 0x0300,
    AddressWithdraw = 0x0301,
    LabelMapping = 0x0400,
    LabelRequest = 0x0401,
    LabelWithdraw = 0x0402,
    LabelRelease = 0x0403,
    LabelAbortRequest = 0x0404,
}

impl MessageType {
    /// Map a raw 15-bit type field.
    pub fn from_u16(v: u16) -> Option<Self> {
        Some(match v {
            0x0001 => Self::Notification,
            0x0100 => Self::Hello,
            0x0200 => Self::Initialization,
            0x0201 => Self::KeepAlive,
            0x0202 => Self::Capability,
            0x0300 => Self::Address,
            0x0301 => Self::AddressWithdraw,
            0x0400 => Self::LabelMapping,
            0x0401 => Self::LabelRequest,
            0x0402 => Self::LabelWithdraw,
            0x0403 => Self::LabelRelease,
            0x0404 => Self::LabelAbortRequest,
            _ => return None,
        })
    }
}

impl fmt::Display for MessageType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Self::Notification => "Notification",
            Self::Hello => "Hello",
            Self::Initialization => "Initialization",
            Self::KeepAlive => "KeepAlive",
            Self::Capability => "Capability",
            Self::Address => "Address",
            Self::AddressWithdraw => "AddressWithdraw",
            Self::LabelMapping => "LabelMapping",
            Self::LabelRequest => "LabelRequest",
            Self::LabelWithdraw => "LabelWithdraw",
            Self::LabelRelease => "LabelRelease",
            Self::LabelAbortRequest => "LabelAbortRequest",
        };
        f.write_str(name)
    }
}

/// TLV types (RFC 5036 §3.8; RFC 5561 adds the LDP Capability TLV).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum TlvType {
    Fec = 0x0100,
    AddressList = 0x0101,
    HopCount = 0x0103,
    PathVector = 0x0104,
    GenericLabel = 0x0200,
    AtmLabel = 0x0201,
    FrameRelayLabel = 0x0202,
    Status = 0x0300,
    ExtendedStatus = 0x0301,
    ReturnedPdu = 0x0302,
    ReturnedMessage = 0x0303,
    CommonHelloParameters = 0x0400,
    Ipv4TransportAddress = 0x0401,
    ConfigSequenceNumber = 0x0402,
    Ipv6TransportAddress = 0x0403,
    CommonSessionParameters = 0x0500,
    AtmSessionParameters = 0x0501,
    FrameRelaySessionParameters = 0x0502,
    LabelRequestMessageId = 0x0600,
    LdpCapability = 0x0601,
    /// Dual-Stack capability (RFC 7552 §6.1.1). Carried in Hellos with
    /// U=1, F=0.
    DualStackCapability = 0x0701,
}

impl TlvType {
    /// Map a raw 14-bit type field.
    pub fn from_u16(v: u16) -> Option<Self> {
        Some(match v {
            0x0100 => Self::Fec,
            0x0101 => Self::AddressList,
            0x0103 => Self::HopCount,
            0x0104 => Self::PathVector,
            0x0200 => Self::GenericLabel,
            0x0201 => Self::AtmLabel,
            0x0202 => Self::FrameRelayLabel,
            0x0300 => Self::Status,
            0x0301 => Self::ExtendedStatus,
            0x0302 => Self::ReturnedPdu,
            0x0303 => Self::ReturnedMessage,
            0x0400 => Self::CommonHelloParameters,
            0x0401 => Self::Ipv4TransportAddress,
            0x0402 => Self::ConfigSequenceNumber,
            0x0403 => Self::Ipv6TransportAddress,
            0x0500 => Self::CommonSessionParameters,
            0x0501 => Self::AtmSessionParameters,
            0x0502 => Self::FrameRelaySessionParameters,
            0x0600 => Self::LabelRequestMessageId,
            0x0601 => Self::LdpCapability,
            0x0701 => Self::DualStackCapability,
            _ => return None,
        })
    }
}

/// Result of classifying a TLV found in a message: either a recognized
/// type or an opaque unknown one (kept for U/F-bit processing by the
/// caller).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlvClass {
    Known(TlvType),
    Unknown {
        u_bit: bool,
        f_bit: bool,
        tlv_type: u16,
    },
}

impl TlvClass {
    /// Split the raw 16-bit TLV header word into its class and flag bits.
    pub fn from_header(word: u16) -> Self {
        let u_bit = word & 0x8000 != 0;
        let f_bit = word & 0x4000 != 0;
        let raw = word & 0x3fff;
        match TlvType::from_u16(raw) {
            Some(t) => Self::Known(t),
            None => Self::Unknown {
                u_bit,
                f_bit,
                tlv_type: raw,
            },
        }
    }

    /// Whether an unrecognized TLV must be silently ignored (U-bit 1)
    /// or answered with a notification (U-bit 0), RFC 5036 §3.3.
    pub fn unknown_silent(self) -> bool {
        match self {
            Self::Known(_) => true,
            Self::Unknown { u_bit, .. } => u_bit,
        }
    }
}

/// Assemble a TLV header word from the U/F bits and the type.
pub const fn tlv_header_word(u_bit: bool, f_bit: bool, tlv_type: u16) -> u16 {
    (if u_bit { 0x8000 } else { 0 }) | (if f_bit { 0x4000 } else { 0 }) | (tlv_type & 0x3fff)
}

/// Assemble a message header word from the U bit and the type.
pub const fn message_header_word(u_bit: bool, msg_type: u16) -> u16 {
    (if u_bit { 0x8000 } else { 0 }) | (msg_type & 0x7fff)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ldp_id_roundtrip() {
        let id = LdpId::new([192, 0, 2, 1], 0);
        assert_eq!(id.to_string(), "192.0.2.1:0");
        let bytes = id.as_bytes();
        assert_eq!(bytes, [192, 0, 2, 1, 0, 0]);
        assert_eq!(LdpId::from_bytes(&bytes), Some(id));
        assert_eq!(LdpId::from_bytes(&bytes[..5]), None);
    }

    #[test]
    fn ldp_id_nonzero_label_space() {
        let id = LdpId::new([1, 2, 3, 4], 0x1234);
        assert_eq!(id.to_string(), "1.2.3.4:4660");
        let bytes = id.as_bytes();
        assert_eq!(bytes[4], 0x12);
        assert_eq!(bytes[5], 0x34);
    }

    #[test]
    fn ldp_id_ordering_is_byte_order() {
        let a = LdpId::new([10, 0, 0, 1], 0);
        let b = LdpId::new([10, 0, 0, 2], 0);
        assert!(a < b);
    }

    #[test]
    fn message_type_registry() {
        assert_eq!(
            MessageType::from_u16(0x0001),
            Some(MessageType::Notification)
        );
        assert_eq!(MessageType::from_u16(0x0100), Some(MessageType::Hello));
        assert_eq!(
            MessageType::from_u16(0x0200),
            Some(MessageType::Initialization)
        );
        assert_eq!(MessageType::from_u16(0x0201), Some(MessageType::KeepAlive));
        assert_eq!(MessageType::from_u16(0x0202), Some(MessageType::Capability));
        assert_eq!(
            MessageType::from_u16(0x0402),
            Some(MessageType::LabelWithdraw)
        );
        assert_eq!(
            MessageType::from_u16(0x0404),
            Some(MessageType::LabelAbortRequest)
        );
        assert_eq!(MessageType::from_u16(0x0405), None);
    }

    #[test]
    fn tlv_type_registry() {
        assert_eq!(TlvType::from_u16(0x0100), Some(TlvType::Fec));
        assert_eq!(TlvType::from_u16(0x0200), Some(TlvType::GenericLabel));
        assert_eq!(
            TlvType::from_u16(0x0403),
            Some(TlvType::Ipv6TransportAddress)
        );
        assert_eq!(TlvType::from_u16(0x0601), Some(TlvType::LdpCapability));
        assert_eq!(TlvType::from_u16(0x0602), None);
    }

    #[test]
    fn tlv_header_word_flags() {
        let w = tlv_header_word(true, true, 0x0100);
        assert_eq!(w, 0xc100);
        assert_eq!(TlvClass::from_header(w), TlvClass::Known(TlvType::Fec));

        let w = tlv_header_word(false, false, 0x1234);
        assert_eq!(
            TlvClass::from_header(w),
            TlvClass::Unknown {
                u_bit: false,
                f_bit: false,
                tlv_type: 0x1234
            }
        );
        assert!(!TlvClass::from_header(w).unknown_silent());

        let w = tlv_header_word(true, false, 0x1234);
        assert!(TlvClass::from_header(w).unknown_silent());
    }

    #[test]
    fn message_header_word_u_bit() {
        assert_eq!(message_header_word(false, 0x0100), 0x0100);
        assert_eq!(message_header_word(true, 0x0202), 0x8202);
    }
}
