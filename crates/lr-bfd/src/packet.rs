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
    /// BFD packet flags (RFC 5880 §4.1, low 6 bits of byte 2).
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct PacketFlags: u8 {
        /// Multi-hop session indicator.
        const MULTIPOINT = 0b0000_0001;
        /// Demand mode enabled.
        const DEMAND = 0b0000_0010;
        /// Authentication section is present.
        const AUTH = 0b0000_0100;
        /// Control-plane independent (e.g. via hardware-offloaded BFD-for-PL).
        const CPI = 0b0000_1000;
        /// Echo function active.
        const ECHO = 0b0001_0000;
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

    /// Length field for this packet (24 without auth, 24 + 28 = 52 with
    /// MD5/SHA1 keyed auth trailer).
    pub fn length(&self, has_auth: bool) -> u8 {
        if !has_auth {
            24
        } else {
            // Auth section is 4-byte header + variable data. MD5: 24 bytes
            // of data + 4 header = 28 total. SHA1: 24 + 4 = 28. So 24+28=52.
            52
        }
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
        out.put_u8((p.state as u8) << 6 | (p.flags.bits() & 0x3f));
        out.put_u8(p.detect_mult.clamp(1, 255));
        out.put_u8(p.length(p.auth.is_some()));
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
        let _length = r
            .get_u8()
            .ok_or_else(|| ParseError::truncated("bfd.length"))?;
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
        assert_eq!(decoded.state, State::Up);
        assert_eq!(decoded.diag, Diagnostic::None);
        assert_eq!(decoded.my_discriminator, 0x11223344);
        assert_eq!(decoded.your_discriminator, 0x55667788);
        assert_eq!(decoded.desired_min_tx_interval, 1_000_000);
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
