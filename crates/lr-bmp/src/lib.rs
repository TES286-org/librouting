//! BGP Monitoring Protocol (BMP) — RFC 7854.
//!
//! BMP is a one-way monitoring protocol: a BGP router sends a mirror
//! copy of every BGP UPDATE (pre- and post-policy) plus session state
//! changes to an external BMP collector. The collector never sends data
//! back. This crate implements the BMP message codec and a collector
//! sink; the router wires it into its event pipeline.
//!
//! # Message types (RFC 7854 §4)
//!
//! | Type | Name              | Purpose |
//! |------|-------------------|---------|
//! | 0    | Route Monitoring  | Mirror of a BGP UPDATE |
//! | 1    | Statistics Report| Per-peer counters |
//! | 2    | Peer Down        | Session went down |
//! | 3    | Peer Up          | Session came up |
//! | 4    | Initiation       | Collector handshake (sent on connect) |
//! | 5    | Termination      | Collector goodbye (sent on disconnect) |
//! | 6    | Route Mirroring  | Exact copy of a received BGP message |
//!
//! # Wire format
//!
//! Every BMP message has a common header followed by a per-type
//! header and payload:
//!
//! ```text
//!  Common Header (RFC 7854 §4.1):
//!    +0  Version        (u8, always 3)
//!    +1  Message Length (u32, big-endian, includes header)
//!    +5  Message Type   (u8)
//!
//!  Per-Peer Header (RFC 7854 §4.2, for types 0-2, 6):
//!    +0  Peer Type      (u8, 0=global, 1=RD, 2=L3VPN)
//!    +1  Peer Flags     (u8, V=0x80 bit 7, L=0x40 bit 6, A=0x20 bit 5)
//!    +2  Peer Distinguisher (u64, big-endian, RD or 0)
//!   +10  Peer Address   (16 bytes, IPv4 in last 4 or full IPv6)
//!   +26  Peer AS        (u32, big-endian)
//!   +30  Peer BGP ID    (u32, big-endian)
//!   +34  Timestamp      (u32 seconds + u32 fraction, big-endian)
//! ```

#![forbid(unsafe_code)]

use core::fmt;

use lr_core::buf::{ReadBuf, WriteBuf};
use lr_core::codec::{Decoder, Encoder};
use lr_core::error::{EncodeError, ParseError};

/// BMP version (RFC 7854 §4.1: always 3).
pub const VERSION: u8 = 3;

/// BMP message types (RFC 7854 §4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum BmpMsgType {
    /// Route Monitoring (§4.3): a BGP UPDATE mirror.
    RouteMonitoring = 0,
    /// Statistics Report (§4.4): per-peer counters.
    StatisticsReport = 1,
    /// Peer Down (§4.5): session went down.
    PeerDown = 2,
    /// Peer Up (§4.6): session came up.
    PeerUp = 3,
    /// Initiation (§4.7): sent on connect.
    Initiation = 4,
    /// Termination (§4.8): sent on disconnect.
    Termination = 5,
    /// Route Mirroring (§4.9): exact copy of a received BGP message.
    RouteMirroring = 6,
}

impl BmpMsgType {
    pub fn from_u8(v: u8) -> Option<Self> {
        Some(match v {
            0 => Self::RouteMonitoring,
            1 => Self::StatisticsReport,
            2 => Self::PeerDown,
            3 => Self::PeerUp,
            4 => Self::Initiation,
            5 => Self::Termination,
            6 => Self::RouteMirroring,
            _ => return None,
        })
    }
}

impl fmt::Display for BmpMsgType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::RouteMonitoring => "RouteMonitoring",
            Self::StatisticsReport => "StatisticsReport",
            Self::PeerDown => "PeerDown",
            Self::PeerUp => "PeerUp",
            Self::Initiation => "Initiation",
            Self::Termination => "Termination",
            Self::RouteMirroring => "RouteMirroring",
        })
    }
}

/// Peer type (RFC 7854 §4.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[repr(u8)]
pub enum PeerType {
    /// Global instance peer (the common case).
    #[default]
    Global = 0,
    /// RD instance peer (L3VPN).
    Rd = 1,
    /// Local instance peer (VRF).
    Local = 2,
}

/// Peer flags (RFC 7854 §4.2): `V` (bit 7, 0x80) = the peer address is
/// IPv6 (full 16 bytes); `L` (bit 6, 0x40) = the message reflects the
/// post-policy Adj-RIB-In; `A` (bit 5, 0x20) = the peer AS is encoded in
/// the legacy 2-byte AS_PATH format.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct PeerFlags(pub u8);

impl PeerFlags {
    /// V flag (bit 7, 0x80): peer address is IPv6 (full 16 bytes).
    pub const V: u8 = 0x80;
    /// L flag (bit 6, 0x40): the message reflects the post-policy
    /// Adj-RIB-In (RFC 7854 §4.2).
    pub const L: u8 = 0x40;
    /// A flag (bit 5, 0x20): the peer AS is in the legacy 2-byte AS_PATH
    /// format (RFC 7854 §4.2).
    pub const A: u8 = 0x20;

    pub fn ipv6() -> Self {
        Self(Self::V)
    }
    pub fn ipv4() -> Self {
        Self(0)
    }
    /// Post-policy flag (L): the message reflects the post-policy
    /// Adj-RIB-In (RFC 7854 §4.2).
    pub fn post_policy() -> Self {
        Self(Self::L)
    }
    pub fn pre_policy() -> Self {
        Self(0)
    }
    /// Legacy-AS flag (A): the peer AS is in the 2-byte AS_PATH format
    /// (RFC 7854 §4.2).
    pub fn legacy_as_path() -> Self {
        Self(Self::A)
    }
    pub fn is_ipv6(self) -> bool {
        self.0 & Self::V != 0
    }
    pub fn is_post_policy(self) -> bool {
        self.0 & Self::L != 0
    }
    pub fn is_legacy_as_path(self) -> bool {
        self.0 & Self::A != 0
    }
}

/// BMP common header (RFC 7854 §4.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BmpHeader {
    pub version: u8,
    pub msg_len: u32,
    pub msg_type: BmpMsgType,
}

impl BmpHeader {
    pub const LEN: usize = 6;
}

/// Per-peer header (RFC 7854 §4.2). Present on messages of type 0-2, 6.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerHeader {
    pub peer_type: PeerType,
    pub peer_flags: PeerFlags,
    pub peer_distinguisher: u64,
    /// Peer address: IPv4 in the last 4 bytes (when !V flag) or full
    /// 16-byte IPv6 (when V flag).
    pub peer_address: [u8; 16],
    pub peer_as: u32,
    pub peer_bgp_id: u32,
    /// Timestamp: seconds + fraction (NTP-style, RFC 7854 §4.2).
    pub timestamp_secs: u32,
    pub timestamp_fraction: u32,
}

impl PeerHeader {
    pub const LEN: usize = 42;
}

/// One BMP message (common header + optional peer header + payload).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BmpMessage {
    pub header: BmpHeader,
    pub peer: Option<PeerHeader>,
    /// Payload bytes: a raw BGP message for RouteMonitoring/RouteMirroring,
    /// or a type-specific body for PeerUp/PeerDown/StatisticsReport.
    pub payload: Vec<u8>,
}

impl BmpMessage {
    /// Build a Route Monitoring message (type 0): mirrors a BGP UPDATE.
    pub fn route_monitoring(peer: PeerHeader, bgp_update: &[u8]) -> Self {
        Self {
            header: BmpHeader {
                version: VERSION,
                msg_len: 0, // patched by encoder
                msg_type: BmpMsgType::RouteMonitoring,
            },
            peer: Some(peer),
            payload: bgp_update.to_vec(),
        }
    }

    /// Build a Peer Up message (type 3).
    pub fn peer_up(
        peer: PeerHeader,
        local_addr: [u8; 16],
        local_port: u16,
        remote_port: u16,
        sent_open: &[u8],
        received_open: &[u8],
    ) -> Self {
        let mut payload = Vec::with_capacity(36 + sent_open.len() + received_open.len());
        payload.extend_from_slice(&local_addr);
        payload.extend_from_slice(&local_port.to_be_bytes());
        payload.extend_from_slice(&remote_port.to_be_bytes());
        payload.extend_from_slice(&(sent_open.len() as u16).to_be_bytes());
        payload.extend_from_slice(&(received_open.len() as u16).to_be_bytes());
        payload.extend_from_slice(sent_open);
        payload.extend_from_slice(received_open);
        Self {
            header: BmpHeader {
                version: VERSION,
                msg_len: 0,
                msg_type: BmpMsgType::PeerUp,
            },
            peer: Some(peer),
            payload,
        }
    }

    /// Build a Peer Down message (type 2).
    pub fn peer_down(peer: PeerHeader, reason: PeerDownReason, data: &[u8]) -> Self {
        let mut payload = Vec::with_capacity(1 + data.len());
        payload.push(reason as u8);
        payload.extend_from_slice(data);
        Self {
            header: BmpHeader {
                version: VERSION,
                msg_len: 0,
                msg_type: BmpMsgType::PeerDown,
            },
            peer: Some(peer),
            payload,
        }
    }

    /// Build an Initiation message (type 4).
    pub fn initiation(info: &[(u16, &[u8])]) -> Self {
        let mut payload = Vec::new();
        for (tlv_type, tlv_value) in info {
            payload.extend_from_slice(&tlv_type.to_be_bytes());
            payload.extend_from_slice(&(tlv_value.len() as u16).to_be_bytes());
            payload.extend_from_slice(tlv_value);
        }
        Self {
            header: BmpHeader {
                version: VERSION,
                msg_len: 0,
                msg_type: BmpMsgType::Initiation,
            },
            peer: None,
            payload,
        }
    }

    /// Build a Termination message (type 5).
    pub fn termination(info: &[(u16, &[u8])]) -> Self {
        let mut payload = Vec::new();
        for (tlv_type, tlv_value) in info {
            payload.extend_from_slice(&tlv_type.to_be_bytes());
            payload.extend_from_slice(&(tlv_value.len() as u16).to_be_bytes());
            payload.extend_from_slice(tlv_value);
        }
        Self {
            header: BmpHeader {
                version: VERSION,
                msg_len: 0,
                msg_type: BmpMsgType::Termination,
            },
            peer: None,
            payload,
        }
    }
}

/// Peer Down reason (RFC 7854 §4.5).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum PeerDownReason {
    /// The local system closed the session.
    LocalClose = 1,
    /// The remote peer closed the session.
    RemoteClose = 2,
    /// The remote peer sent a NOTIFICATION.
    RemoteNotification = 3,
    /// The local system depleted a resource.
    DepletedResource = 4,
    /// The peer was administratively removed.
    AdminReset = 5,
}

/// BMP codec: encodes/decodes BMP messages to/from the wire format.
#[derive(Default)]
pub struct BmpCodec {
    carryover: Vec<u8>,
}

impl BmpCodec {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn encode_vec(&self, msg: &BmpMessage) -> Result<Vec<u8>, EncodeError> {
        let mut out = vec![0u8; 65535];
        let mut w = WriteBuf::new(&mut out);
        let n = self.encode(msg, &mut w)?;
        out.truncate(n);
        Ok(out)
    }

    /// Buffer raw bytes (split feed/decode API for read loops that
    /// carry several messages per `read(2)`).
    pub fn feed(&mut self, b: &[u8]) {
        self.carryover.extend_from_slice(b);
    }

    /// Decode the next complete buffered message, if any.
    /// `Ok(None)` = need more bytes.
    pub fn next_message(&mut self) -> Result<Option<BmpMessage>, ParseError> {
        if self.carryover.len() < BmpHeader::LEN {
            return Ok(None);
        }
        let msg_len = u32::from_be_bytes([
            self.carryover[1],
            self.carryover[2],
            self.carryover[3],
            self.carryover[4],
        ]) as usize;
        if self.carryover.len() < msg_len {
            return Ok(None);
        }
        let buf = &self.carryover[..msg_len];
        let msg = decode_message(buf)?;
        self.carryover.drain(0..msg_len);
        Ok(Some(msg))
    }

    pub fn decode_slice(&mut self, b: &[u8]) -> Result<Option<BmpMessage>, ParseError> {
        self.feed(b);
        self.next_message()
    }
}

impl Encoder<BmpMessage> for BmpCodec {
    fn encode(&self, msg: &BmpMessage, out: &mut WriteBuf<'_>) -> Result<usize, EncodeError> {
        let start = out.position();
        // Common header.
        out.put_u8(VERSION).ok_or(EncodeError::BufferFull)?;
        // Length placeholder — patched after we know the total size.
        out.put_u32_be(0).ok_or(EncodeError::BufferFull)?;
        out.put_u8(msg.header.msg_type as u8)
            .ok_or(EncodeError::BufferFull)?;
        // Per-peer header (when present).
        if let Some(peer) = &msg.peer {
            encode_peer_header(peer, out)?;
        }
        // Payload.
        out.put_bytes(&msg.payload).ok_or(EncodeError::BufferFull)?;
        let total = out.position() - start;
        // Patch the length field.
        out.patch(start + 1, &(total as u32).to_be_bytes())
            .ok_or(EncodeError::BufferFull)?;
        Ok(total)
    }
}

impl Decoder<BmpMessage> for BmpCodec {
    fn decode(&mut self, src: &mut ReadBuf<'_>) -> Result<Option<BmpMessage>, ParseError> {
        self.carryover.extend_from_slice(src.chunk());
        let n = src.remaining();
        src.advance(n);
        if self.carryover.len() < BmpHeader::LEN {
            return Ok(None);
        }
        let msg_len = u32::from_be_bytes([
            self.carryover[1],
            self.carryover[2],
            self.carryover[3],
            self.carryover[4],
        ]) as usize;
        if self.carryover.len() < msg_len {
            return Ok(None);
        }
        let buf = &self.carryover[..msg_len];
        let msg = decode_message(buf)?;
        self.carryover.drain(0..msg_len);
        Ok(Some(msg))
    }
}

fn encode_peer_header(peer: &PeerHeader, out: &mut WriteBuf<'_>) -> Result<(), EncodeError> {
    out.put_u8(peer.peer_type as u8)
        .ok_or(EncodeError::BufferFull)?;
    out.put_u8(peer.peer_flags.0)
        .ok_or(EncodeError::BufferFull)?;
    out.put_u64_be(peer.peer_distinguisher)
        .ok_or(EncodeError::BufferFull)?;
    out.put_bytes(&peer.peer_address)
        .ok_or(EncodeError::BufferFull)?;
    out.put_u32_be(peer.peer_as)
        .ok_or(EncodeError::BufferFull)?;
    out.put_u32_be(peer.peer_bgp_id)
        .ok_or(EncodeError::BufferFull)?;
    out.put_u32_be(peer.timestamp_secs)
        .ok_or(EncodeError::BufferFull)?;
    out.put_u32_be(peer.timestamp_fraction)
        .ok_or(EncodeError::BufferFull)?;
    Ok(())
}

fn decode_message(buf: &[u8]) -> Result<BmpMessage, ParseError> {
    if buf.len() < BmpHeader::LEN {
        return Err(ParseError::truncated("bmp.header"));
    }
    let version = buf[0];
    if version != VERSION {
        return Err(ParseError::invalid(0, "bmp.header.version"));
    }
    let msg_len = u32::from_be_bytes([buf[1], buf[2], buf[3], buf[4]]);
    if msg_len as usize != buf.len() {
        return Err(ParseError::bad_length(1, "bmp.header.length"));
    }
    let msg_type = BmpMsgType::from_u8(buf[5])
        .ok_or_else(|| ParseError::unknown_type(5, "bmp.header.type"))?;
    let mut offset = BmpHeader::LEN;
    // Messages of type 0-2, 6 carry a per-peer header.
    let peer = match msg_type {
        BmpMsgType::RouteMonitoring
        | BmpMsgType::StatisticsReport
        | BmpMsgType::PeerDown
        | BmpMsgType::PeerUp
        | BmpMsgType::RouteMirroring => {
            if buf.len() < offset + PeerHeader::LEN {
                return Err(ParseError::truncated("bmp.peer_header"));
            }
            let ph = decode_peer_header(&buf[offset..offset + PeerHeader::LEN])?;
            offset += PeerHeader::LEN;
            Some(ph)
        }
        BmpMsgType::Initiation | BmpMsgType::Termination => None,
    };
    let payload = buf[offset..].to_vec();
    Ok(BmpMessage {
        header: BmpHeader {
            version,
            msg_len,
            msg_type,
        },
        peer,
        payload,
    })
}

fn decode_peer_header(buf: &[u8]) -> Result<PeerHeader, ParseError> {
    if buf.len() < PeerHeader::LEN {
        return Err(ParseError::truncated("bmp.peer_header"));
    }
    let peer_type = match buf[0] {
        0 => PeerType::Global,
        1 => PeerType::Rd,
        2 => PeerType::Local,
        _ => PeerType::Global, // lenient: treat unknown as global
    };
    let peer_flags = PeerFlags(buf[1]);
    let peer_distinguisher = u64::from_be_bytes([
        buf[2], buf[3], buf[4], buf[5], buf[6], buf[7], buf[8], buf[9],
    ]);
    let mut peer_address = [0u8; 16];
    peer_address.copy_from_slice(&buf[10..26]);
    let peer_as = u32::from_be_bytes([buf[26], buf[27], buf[28], buf[29]]);
    let peer_bgp_id = u32::from_be_bytes([buf[30], buf[31], buf[32], buf[33]]);
    let timestamp_secs = u32::from_be_bytes([buf[34], buf[35], buf[36], buf[37]]);
    let timestamp_fraction = u32::from_be_bytes([buf[38], buf[39], buf[40], buf[41]]);
    Ok(PeerHeader {
        peer_type,
        peer_flags,
        peer_distinguisher,
        peer_address,
        peer_as,
        peer_bgp_id,
        timestamp_secs,
        timestamp_fraction,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_peer_header() -> PeerHeader {
        let mut addr = [0u8; 16];
        addr[12..16].copy_from_slice(&[10, 0, 0, 1]);
        PeerHeader {
            peer_type: PeerType::Global,
            peer_flags: PeerFlags::ipv4(),
            peer_distinguisher: 0,
            peer_address: addr,
            peer_as: 64512,
            peer_bgp_id: 0x0a000001,
            timestamp_secs: 1000,
            timestamp_fraction: 0,
        }
    }

    #[test]
    fn route_monitoring_roundtrip() {
        let peer = sample_peer_header();
        let bgp_update = vec![0xff; 19]; // minimal BGP marker + header
        let msg = BmpMessage::route_monitoring(peer.clone(), &bgp_update);
        let enc = BmpCodec::new().encode_vec(&msg).unwrap();
        // Common header (6) + peer header (42) + payload (19) = 67
        assert_eq!(enc.len(), 67);
        let mut codec = BmpCodec::new();
        let dec = codec.decode_slice(&enc).unwrap().unwrap();
        assert_eq!(dec.header.msg_type, BmpMsgType::RouteMonitoring);
        assert_eq!(dec.peer.as_ref().unwrap().peer_as, 64512);
        assert_eq!(dec.payload, bgp_update);
    }

    #[test]
    fn initiation_roundtrip() {
        let info: &[(u16, &[u8])] = &[(0, b"test-string")];
        let msg = BmpMessage::initiation(info);
        let enc = BmpCodec::new().encode_vec(&msg).unwrap();
        let mut codec = BmpCodec::new();
        let dec = codec.decode_slice(&enc).unwrap().unwrap();
        assert_eq!(dec.header.msg_type, BmpMsgType::Initiation);
        assert!(dec.peer.is_none());
        // Payload: type(2) + len(2) + "test-string"(11) = 15
        assert_eq!(dec.payload.len(), 15);
    }

    #[test]
    fn termination_roundtrip() {
        let info: &[(u16, &[u8])] = &[(1, b"bye")];
        let msg = BmpMessage::termination(info);
        let enc = BmpCodec::new().encode_vec(&msg).unwrap();
        let mut codec = BmpCodec::new();
        let dec = codec.decode_slice(&enc).unwrap().unwrap();
        assert_eq!(dec.header.msg_type, BmpMsgType::Termination);
    }

    #[test]
    fn peer_up_roundtrip() {
        let peer = sample_peer_header();
        let local_addr = [0u8; 16];
        let sent_open = vec![0xff; 29]; // minimal OPEN
        let received_open = vec![0xff; 29];
        let msg = BmpMessage::peer_up(
            peer.clone(),
            local_addr,
            179,
            50000,
            &sent_open,
            &received_open,
        );
        let enc = BmpCodec::new().encode_vec(&msg).unwrap();
        let mut codec = BmpCodec::new();
        let dec = codec.decode_slice(&enc).unwrap().unwrap();
        assert_eq!(dec.header.msg_type, BmpMsgType::PeerUp);
        assert!(dec.peer.is_some());
        // Payload: local_addr(16) + local_port(2) + remote_port(2) +
        // sent_open_len(2) + recv_open_len(2) + sent_open(29) +
        // recv_open(29) = 82
        assert_eq!(dec.payload.len(), 82);
    }

    #[test]
    fn peer_down_roundtrip() {
        let peer = sample_peer_header();
        let msg = BmpMessage::peer_down(
            peer.clone(),
            PeerDownReason::RemoteNotification,
            &[0x06, 0x08], // CEASE code+subcode
        );
        let enc = BmpCodec::new().encode_vec(&msg).unwrap();
        let mut codec = BmpCodec::new();
        let dec = codec.decode_slice(&enc).unwrap().unwrap();
        assert_eq!(dec.header.msg_type, BmpMsgType::PeerDown);
        assert_eq!(dec.payload[0], PeerDownReason::RemoteNotification as u8);
        assert_eq!(&dec.payload[1..], &[0x06, 0x08]);
    }

    #[test]
    fn ipv6_peer_address() {
        let mut addr = [0u8; 16];
        addr.copy_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        let peer = PeerHeader {
            peer_type: PeerType::Global,
            peer_flags: PeerFlags::ipv6(),
            peer_distinguisher: 0,
            peer_address: addr,
            peer_as: 64512,
            peer_bgp_id: 0x0a000001,
            timestamp_secs: 0,
            timestamp_fraction: 0,
        };
        let msg = BmpMessage::route_monitoring(peer, &[0xff; 19]);
        let enc = BmpCodec::new().encode_vec(&msg).unwrap();
        let mut codec = BmpCodec::new();
        let dec = codec.decode_slice(&enc).unwrap().unwrap();
        let p = dec.peer.unwrap();
        assert!(p.peer_flags.is_ipv6());
        assert_eq!(p.peer_address, addr);
    }

    #[test]
    fn post_policy_flag() {
        let peer = PeerHeader {
            peer_type: PeerType::Global,
            peer_flags: PeerFlags::post_policy(),
            peer_distinguisher: 0,
            peer_address: [0u8; 16],
            peer_as: 64512,
            peer_bgp_id: 0,
            timestamp_secs: 0,
            timestamp_fraction: 0,
        };
        let msg = BmpMessage::route_monitoring(peer, &[]);
        let enc = BmpCodec::new().encode_vec(&msg).unwrap();
        // Post-policy is the L flag (0x40, bit 6) — byte 7 is the peer
        // flags octet (6-byte common header + 1).
        assert_eq!(enc[7], PeerFlags::L);
        let mut codec = BmpCodec::new();
        let dec = codec.decode_slice(&enc).unwrap().unwrap();
        assert!(dec.peer.unwrap().peer_flags.is_post_policy());
    }

    #[test]
    fn peer_flags_match_rfc_7854_4_2() {
        // RFC 7854 §4.2 peer flags: |V|L|A|Reserved| — V=0x80 (bit 7, IPv6
        // peer address), L=0x40 (bit 6, message reflects the post-policy
        // Adj-RIB-In), A=0x20 (bit 5, legacy 2-byte AS_PATH).
        assert_eq!(PeerFlags::V, 0x80);
        assert_eq!(PeerFlags::L, 0x40);
        assert_eq!(PeerFlags::A, 0x20);
        assert!(PeerFlags(0x80).is_ipv6());
        assert!(!PeerFlags(0x40).is_ipv6());
        assert!(PeerFlags(0x40).is_post_policy());
        assert!(!PeerFlags(0x80).is_post_policy());
        assert!(PeerFlags(0x20).is_legacy_as_path());
        assert!(!PeerFlags(0x40).is_legacy_as_path());
        assert_eq!(PeerFlags::post_policy().0, 0x40);
        assert_eq!(PeerFlags::legacy_as_path().0, 0x20);

        // All three bits together round-trip through the codec as the
        // literal byte 0xE0.
        let peer = PeerHeader {
            peer_type: PeerType::Global,
            peer_flags: PeerFlags(0xE0),
            peer_distinguisher: 0,
            peer_address: [0u8; 16],
            peer_as: 64512,
            peer_bgp_id: 0,
            timestamp_secs: 0,
            timestamp_fraction: 0,
        };
        let msg = BmpMessage::route_monitoring(peer, &[]);
        let enc = BmpCodec::new().encode_vec(&msg).unwrap();
        assert_eq!(enc[7], 0xE0, "peer flags octet on the wire");
        let mut codec = BmpCodec::new();
        let dec = codec.decode_slice(&enc).unwrap().unwrap();
        let flags = dec.peer.unwrap().peer_flags;
        assert!(flags.is_ipv6() && flags.is_post_policy() && flags.is_legacy_as_path());
    }

    #[test]
    fn streaming_decode() {
        let peer = sample_peer_header();
        let msg1 = BmpMessage::route_monitoring(peer.clone(), &[0xAA]);
        let msg2 = BmpMessage::route_monitoring(peer, &[0xBB]);
        let enc1 = BmpCodec::new().encode_vec(&msg1).unwrap();
        let enc2 = BmpCodec::new().encode_vec(&msg2).unwrap();
        // Feed both in one chunk.
        let combined = [enc1.as_slice(), enc2.as_slice()].concat();
        let mut codec = BmpCodec::new();
        let dec1 = codec.decode_slice(&combined).unwrap().unwrap();
        assert_eq!(dec1.payload, vec![0xAA]);
        let dec2 = codec.decode_slice(&[]).unwrap().unwrap();
        assert_eq!(dec2.payload, vec![0xBB]);
        assert!(codec.decode_slice(&[]).unwrap().is_none());
    }

    #[test]
    fn partial_message_buffered() {
        let peer = sample_peer_header();
        let msg = BmpMessage::route_monitoring(peer, &[0xCC]);
        let enc = BmpCodec::new().encode_vec(&msg).unwrap();
        let mut codec = BmpCodec::new();
        // Feed first half.
        assert!(codec.decode_slice(&enc[..enc.len() / 2]).unwrap().is_none());
        // Feed the rest.
        let dec = codec.decode_slice(&enc[enc.len() / 2..]).unwrap().unwrap();
        assert_eq!(dec.payload, vec![0xCC]);
    }

    #[test]
    fn msg_type_display() {
        assert_eq!(BmpMsgType::RouteMonitoring.to_string(), "RouteMonitoring");
        assert_eq!(BmpMsgType::PeerUp.to_string(), "PeerUp");
    }
}
