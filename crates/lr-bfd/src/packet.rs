//! BFD Control packet wire codec (RFC 5880 §4.1).
//!
//! Wire layout (24 bytes + optional auth trailer):
//! ```text
//!  0                   1                   2                   3
//!  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |Vers|  Diag    |St|  Flags   |  Detect Mult  |    Length     |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                       My Discriminator                        |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                      Your Discriminator                       |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                    Desired Min TX Interval                    |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                   Required Min RX Interval                    |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                 Required Min Echo Interval                    |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! ```
//!
//! Total length: 24 bytes without authentication, 24 + (auth-section length)
//! with authentication. Authentication is encoded as an extra section at
//! the end of the packet (RFC 5880 §4.2).

use lr_core::buf::{ReadBuf, WriteBuf};
use lr_core::codec::{Decoder, Encoder};
use lr_core::error::{EncodeError, ParseError};

/// BFD version (RFC 5880 §4.1: "Version MUST be 1").
pub const BFD_VERSION: u8 = 1;

/// BFD peer state (RFC 5880 §6.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum State {
    AdminDown = 0,
    Down = 1,
    Init = 2,
    Up = 3,
}

impl State {
    pub fn from_u8(v: u8) -> Option<Self> {
        Some(match v {
            0 => Self::AdminDown,
            1 => Self::Down,
            2 => Self::Init,
            3 => Self::Up,
            _ => return None,
        })
    }
    pub fn name(self) -> &'static str {
        match self {
            Self::AdminDown => "AdminDown",
            Self::Down => "Down",
            Self::Init => "Init",
            Self::Up => "Up",
        }
    }
}

impl core::fmt::Display for State {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.name())
    }
}

impl core::fmt::Display for Diagnostic {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.name())
    }
}

/// Diagnostic code (RFC 5880 §4.1 + §A.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum Diagnostic {
    None = 0,
    CtrlExpired = 1,
    EchoFailed = 2,
    NeighborSignaled = 3,
    FwdReset = 4,
    PathDown = 5,
    ConcatPathDown = 6,
    AdminDown = 7,
    RevPathDown = 8,
    MisConnDefect = 9,
    Unknown(u8),
}

impl Diagnostic {
    /// The RFC 5880 §A.1 name (for logs).
    pub fn name(self) -> &'static str {
        match self {
            Self::None => "No Diagnostic",
            Self::CtrlExpired => "Control Detection Time Expired",
            Self::EchoFailed => "Echo Function Failed",
            Self::NeighborSignaled => "Neighbor Signaled Session Down",
            Self::FwdReset => "Forwarding Plane Reset",
            Self::PathDown => "Path Down",
            Self::ConcatPathDown => "Concatenated Path Down",
            Self::AdminDown => "Administratively Down",
            Self::RevPathDown => "Reverse Concatenated Path Down",
            Self::MisConnDefect => "Mis-Connectivity Defect",
            Self::Unknown(_) => "Unknown",
        }
    }

    pub fn from_u8(v: u8) -> Self {
        match v {
            0 => Self::None,
            1 => Self::CtrlExpired,
            2 => Self::EchoFailed,
            3 => Self::NeighborSignaled,
            4 => Self::FwdReset,
            5 => Self::PathDown,
            6 => Self::ConcatPathDown,
            7 => Self::AdminDown,
            8 => Self::RevPathDown,
            9 => Self::MisConnDefect,
            _ => Self::Unknown(v),
        }
    }
    pub fn to_u8(self) -> u8 {
        match self {
            Self::None => 0,
            Self::CtrlExpired => 1,
            Self::EchoFailed => 2,
            Self::NeighborSignaled => 3,
            Self::FwdReset => 4,
            Self::PathDown => 5,
            Self::ConcatPathDown => 6,
            Self::AdminDown => 7,
            Self::RevPathDown => 8,
            Self::MisConnDefect => 9,
            Self::Unknown(v) => v,
        }
    }
}

bitflags::bitflags! {
    /// BFD Control packet flags — the six bits after the State field in
    /// byte 1, which RFC 5880 §4.1 lays out as `|Sta|P|F|C|A|D|M|`:
    ///
    /// ```text
    /// bit 7-6: State  bit 5: P  bit 4: F  bit 3: C  bit 2: A
    /// bit 1:   D      bit 0: M
    /// ```
    ///
    /// Note there is no "echo" flag in the BFD Control packet — the
    /// Echo function is signalled through the Required Min Echo RX
    /// Interval field, not a header bit.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct PacketFlags: u8 {
        /// Multipoint (M, bit 0). Reserved for future point-to-
        /// multipoint extensions; MUST be zero on transmit and receipt
        /// (RFC 5880 §4.1).
        const MULTIPOINT = 0b0000_0001;
        /// Demand (D, bit 1). Demand mode is active in the transmitting
        /// system (RFC 5880 §6.6).
        const DEMAND = 0b0000_0010;
        /// Authentication Present (A, bit 2). The Authentication
        /// Section is present (RFC 5880 §6.7).
        const AUTH = 0b0000_0100;
        /// Control Plane Independent (C, bit 3).
        const CPI = 0b0000_1000;
        /// Final (F, bit 4). The transmitter is responding to a
        /// received Poll (RFC 5880 §6.5).
        const FINAL = 0b0001_0000;
        /// Poll (P, bit 5). The transmitter is requesting connectivity
        /// / parameter-change verification and expects Final in reply
        /// (RFC 5880 §6.5).
        const POLL = 0b0010_0000;
    }
}

/// A BFD Control packet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BfdPacket {
    pub diag: Diagnostic,
    pub state: State,
    pub flags: PacketFlags,
    pub detect_mult: u8,
    pub my_discriminator: u32,
    pub your_discriminator: u32,
    pub desired_min_tx_interval: u32,
    pub required_min_rx_interval: u32,
    pub required_min_echo_interval: u32,
    /// Optional authentication section.
    pub auth: Option<crate::auth::AuthSection>,
}

impl BfdPacket {
    /// Minimum packet length (no auth).
    pub const MIN_LEN: usize = 24;

    /// Build a new packet with sensible defaults for an "Up" control packet.
    pub fn heartbeat(my_disc: u32, your_disc: u32) -> Self {
        Self {
            diag: Diagnostic::None,
            state: State::Up,
            flags: PacketFlags::empty(),
            detect_mult: 3,
            my_discriminator: my_disc,
            your_discriminator: your_disc,
            desired_min_tx_interval: 1_000_000, // 1s in microseconds
            required_min_rx_interval: 1_000_000,
            required_min_echo_interval: 0,
            auth: None,
        }
    }

    /// Total length of this packet on the wire (the Length field,
    /// RFC 5880 §4.1): 24 without authentication, plus the auth
    /// section length when present (28-40 for Simple Password,
    /// 48 for Keyed MD5, 52 for Keyed SHA1).
    pub fn length(&self) -> u8 {
        BfdPacket::MIN_LEN as u8 + self.auth.as_ref().map_or(0, |a| a.wire_len() as u8)
    }
}

/// BFD Control packet encoder/decoder.
#[derive(Debug, Clone, Default)]
pub struct BfdCodec;

impl BfdCodec {
    pub fn new() -> Self {
        Self
    }
}

impl Encoder<BfdPacket> for BfdCodec {
    fn encode(&self, p: &BfdPacket, out: &mut WriteBuf<'_>) -> Result<usize, EncodeError> {
        if out.remaining_mut() < BfdPacket::MIN_LEN {
            return Err(EncodeError::BufferFull);
        }
        out.put_u8((BFD_VERSION << 5) | (p.diag.to_u8() & 0x1f));
        // RFC 5880 §6.8.7: the Authentication Present bit is set iff
        // authentication is in use — derive it from the section's
        // presence so the two can never disagree.
        let mut flags = p.flags;
        if p.auth.is_some() {
            flags |= PacketFlags::AUTH;
        }
        out.put_u8((p.state as u8) << 6 | (flags.bits() & 0x3f));
        // RFC 5880 §6.8.4/§4.1: Detect Mult must be nonzero; a config
        // error (0) must not be silently rewritten to 1 on the wire.
        if p.detect_mult == 0 {
            return Err(EncodeError::InvalidValue("bfd detect_mult is zero"));
        }
        out.put_u8(p.detect_mult);
        out.put_u8(p.length());
        out.put_u32_be(p.my_discriminator);
        out.put_u32_be(p.your_discriminator);
        out.put_u32_be(p.desired_min_tx_interval);
        out.put_u32_be(p.required_min_rx_interval);
        out.put_u32_be(p.required_min_echo_interval);
        let mut written = BfdPacket::MIN_LEN;
        if let Some(a) = &p.auth {
            written += a.encode(out)?;
        }
        Ok(written)
    }
}

impl Decoder<BfdPacket> for BfdCodec {
    fn decode(&mut self, r: &mut ReadBuf<'_>) -> Result<Option<BfdPacket>, ParseError> {
        if r.remaining() < BfdPacket::MIN_LEN {
            return Ok(None);
        }
        let b0 = r
            .get_u8()
            .ok_or_else(|| ParseError::truncated("bfd.byte0"))?;
        let version = b0 >> 5;
        if version != BFD_VERSION {
            return Err(ParseError::invalid(0, "bfd.version"));
        }
        let diag = Diagnostic::from_u8(b0 & 0x1f);
        let b1 = r
            .get_u8()
            .ok_or_else(|| ParseError::truncated("bfd.byte1"))?;
        let state =
            State::from_u8((b1 >> 6) & 0x3).ok_or_else(|| ParseError::invalid(1, "bfd.state"))?;
        let flags = PacketFlags::from_bits_truncate(b1 & 0x3f);
        let detect_mult = r
            .get_u8()
            .ok_or_else(|| ParseError::truncated("bfd.detect_mult"))?;
        // RFC 5880 §6.8.6: "If the Detect Mult field is zero, the packet
        // MUST be discarded." Enforced at the codec so direct BfdCodec
        // users get the same rule as the session layer.
        if detect_mult == 0 {
            return Err(ParseError::invalid(2, "bfd.detect_mult"));
        }
        let length_field =
            r.get_u8()
                .ok_or_else(|| ParseError::truncated("bfd.length"))? as usize;
        // RFC 5880 §6.8.6: discard when the Length field is smaller
        // than the minimum correct value (24 without auth, 26 with) or
        // larger than the available payload (4 header bytes are
        // already consumed here).
        let min_len = if flags.contains(PacketFlags::AUTH) {
            26
        } else {
            BfdPacket::MIN_LEN
        };
        if length_field < min_len || length_field > r.remaining() + 4 {
            return Err(ParseError::invalid(3, "bfd.length"));
        }
        let my_disc = r
            .get_u32_be()
            .ok_or_else(|| ParseError::truncated("bfd.my_disc"))?;
        let your_disc = r
            .get_u32_be()
            .ok_or_else(|| ParseError::truncated("bfd.your_disc"))?;
        let desired_tx = r
            .get_u32_be()
            .ok_or_else(|| ParseError::truncated("bfd.desired_tx"))?;
        let required_rx = r
            .get_u32_be()
            .ok_or_else(|| ParseError::truncated("bfd.required_rx"))?;
        let required_echo = r
            .get_u32_be()
            .ok_or_else(|| ParseError::truncated("bfd.required_echo"))?;
        let auth = if flags.contains(PacketFlags::AUTH) {
            Some(crate::auth::AuthSection::decode(r)?)
        } else {
            None
        };
        Ok(Some(BfdPacket {
            diag,
            state,
            flags,
            detect_mult,
            my_discriminator: my_disc,
            your_discriminator: your_disc,
            desired_min_tx_interval: desired_tx,
            required_min_rx_interval: required_rx,
            required_min_echo_interval: required_echo,
            auth,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_heartbeat() {
        let mut codec = BfdCodec::new();
        let p = BfdPacket::heartbeat(0x11223344, 0x55667788);
        let mut buf = [0u8; BfdPacket::MIN_LEN];
        let mut w = WriteBuf::new(&mut buf);
        let n = codec.encode(&p, &mut w).unwrap();
        assert_eq!(n, BfdPacket::MIN_LEN);
        let mut r = ReadBuf::new(&buf);
        let decoded = codec.decode(&mut r).unwrap().unwrap();
        assert_eq!(decoded, p);
        assert_eq!(decoded.state, State::Up);
        assert_eq!(decoded.diag, Diagnostic::None);
        assert_eq!(decoded.my_discriminator, 0x11223344);
        assert_eq!(decoded.your_discriminator, 0x55667788);
        assert_eq!(decoded.desired_min_tx_interval, 1_000_000);
    }

    #[test]
    fn flag_bit_positions_match_rfc_5880_4_1() {
        // Byte 1 layout is |Sta|P|F|C|A|D|M| (RFC 5880 §4.1):
        // State << 6 | P(0x20) | F(0x10) | C(0x08) | A(0x04) | D(0x02)
        // | M(0x01).
        let mut codec = BfdCodec::new();
        let p = BfdPacket {
            flags: PacketFlags::POLL
                | PacketFlags::FINAL
                | PacketFlags::CPI
                | PacketFlags::AUTH
                | PacketFlags::DEMAND
                | PacketFlags::MULTIPOINT,
            ..BfdPacket::heartbeat(1, 2)
        };
        let mut buf = [0u8; BfdPacket::MIN_LEN];
        let mut w = WriteBuf::new(&mut buf);
        codec.encode(&p, &mut w).unwrap();
        assert_eq!(buf[1], (State::Up as u8) << 6 | 0b0011_1111);
        // State alone.
        let p2 = BfdPacket::heartbeat(1, 2);
        let mut w = WriteBuf::new(&mut buf);
        codec.encode(&p2, &mut w).unwrap();
        assert_eq!(buf[1], (State::Up as u8) << 6);
        // Round-trip the flags.
        let mut r = ReadBuf::new(&buf);
        assert_eq!(codec.decode(&mut r).unwrap().unwrap().flags, p2.flags);
    }

    #[test]
    fn poll_final_roundtrip() {
        let mut codec = BfdCodec::new();
        let p = BfdPacket {
            flags: PacketFlags::POLL,
            state: State::Up,
            ..BfdPacket::heartbeat(0x11111111, 0x22222222)
        };
        let mut buf = [0u8; BfdPacket::MIN_LEN];
        let mut w = WriteBuf::new(&mut buf);
        codec.encode(&p, &mut w).unwrap();
        let mut r = ReadBuf::new(&buf);
        let decoded = codec.decode(&mut r).unwrap().unwrap();
        assert!(decoded.flags.contains(PacketFlags::POLL));
        assert!(!decoded.flags.contains(PacketFlags::FINAL));
    }

    #[test]
    fn length_field_with_auth() {
        let mut codec = BfdCodec::new();
        // Keyed MD5 section (24 bytes): Length = 24 + 24 = 48.
        let md5 = BfdPacket {
            flags: PacketFlags::AUTH,
            auth: Some(crate::auth::AuthSection::keyed_md5(1, 0, vec![0u8; 16])),
            ..BfdPacket::heartbeat(1, 2)
        };
        assert_eq!(md5.length(), 48);
        let mut buf = [0u8; 96];
        let mut w = WriteBuf::new(&mut buf);
        let n = codec.encode(&md5, &mut w).unwrap();
        assert_eq!(n, 48);
        let mut r = ReadBuf::new(&buf[..n]);
        assert_eq!(codec.decode(&mut r).unwrap().unwrap(), md5);

        // Simple Password (3 + 8 bytes): Length = 24 + 11 = 35.
        let sp = BfdPacket {
            flags: PacketFlags::AUTH,
            auth: Some(crate::auth::AuthSection::simple_password(
                b"hunter22".to_vec(),
                1,
            )),
            ..BfdPacket::heartbeat(1, 2)
        };
        assert_eq!(sp.length(), 35);
        let mut w = WriteBuf::new(&mut buf);
        let n = codec.encode(&sp, &mut w).unwrap();
        assert_eq!(n, 35);
        let mut r = ReadBuf::new(&buf[..n]);
        assert_eq!(codec.decode(&mut r).unwrap().unwrap(), sp);
    }

    #[test]
    fn encoder_sets_auth_bit_from_section() {
        // A packet with an auth section but no explicit A bit still
        // encodes the bit (§6.8.7: A is set iff auth is in use).
        let mut codec = BfdCodec::new();
        let p = BfdPacket {
            auth: Some(crate::auth::AuthSection::simple_password(b"pw".to_vec(), 1)),
            ..BfdPacket::heartbeat(1, 2)
        };
        let mut buf = [0u8; 96];
        let mut w = WriteBuf::new(&mut buf);
        let n = codec.encode(&p, &mut w).unwrap();
        assert_eq!(buf[1] & 0x04, 0x04);
        let mut r = ReadBuf::new(&buf[..n]);
        assert!(codec.decode(&mut r).unwrap().unwrap().auth.is_some());
    }

    #[test]
    fn length_field_validation() {
        let mut codec = BfdCodec::new();
        let p = BfdPacket::heartbeat(1, 2);
        let mut buf = [0u8; BfdPacket::MIN_LEN];
        let mut w = WriteBuf::new(&mut buf);
        codec.encode(&p, &mut w).unwrap();
        // Length < 24 is invalid.
        buf[3] = 20;
        let mut r = ReadBuf::new(&buf);
        assert!(codec.decode(&mut r).is_err());
        // Length > payload is invalid.
        buf[3] = 200;
        let mut r = ReadBuf::new(&buf);
        assert!(codec.decode(&mut r).is_err());
    }

    #[test]
    fn rejects_bad_version() {
        let mut codec = BfdCodec::new();
        let mut bytes = vec![0u8; 24];
        bytes[0] = 0x00; // version 0
        let mut r = ReadBuf::new(&bytes);
        assert!(codec.decode(&mut r).is_err());
    }

    #[test]
    fn truncated_returns_none() {
        let mut codec = BfdCodec::new();
        let bytes = vec![0u8; 10];
        let mut r = ReadBuf::new(&bytes);
        assert!(codec.decode(&mut r).unwrap().is_none());
    }
}
