//! BGP Monitoring Protocol (BMP) — RFC 7854.
//!
//! BMP is a one-way monitoring protocol: a BGP router sends a mirror
//! copy of every BGP UPDATE (pre- and post-policy) plus session state
//! changes to an external BMP collector. The collector never sends data
//! back. This crate implements the BMP message codec; the router wires
//! the sending station into its event pipeline and the daemon the
//! collector sink.
//!
//! # Message types (RFC 7854 §4.1)
//!
//! | Type | Name              | Purpose |
//! |------|-------------------|---------|
//! | 0    | Route Monitoring  | Mirror of a BGP UPDATE (§4.6) |
//! | 1    | Statistics Report | Per-peer counters (§4.8) |
//! | 2    | Peer Down         | Session went down (§4.9) |
//! | 3    | Peer Up           | Session came up (§4.10) |
//! | 4    | Initiation        | Sender handshake (§4.3) |
//! | 5    | Termination       | Sender goodbye (§4.5) |
//! | 6    | Route Mirroring   | TLV-framed copy of a received BGP message (§4.7) |
//!
//! Unrecognized type bytes are skipped whole per RFC 7854 §4.1
//! ("A BMP implementation MUST ignore unrecognized message types
//! upon receipt").
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
//!  Per-Peer Header (RFC 7854 §4.2, for every type except
//!  Initiation and Termination):
//!    +0  Peer Type      (u8, 0=global, 1=RD, 2=local instance,
//!                        3=Loc-RIB per RFC 9069 §4.1)
//!    +1  Peer Flags     (u8, V=0x80 bit 7, L=0x40 bit 6, A=0x20 bit 5)
//!    +2  Peer Distinguisher (u64, big-endian, RD or 0)
//!   +10  Peer Address   (16 bytes, IPv4 in last 4 or full IPv6)
//!   +26  Peer AS        (u32, big-endian)
//!   +30  Peer BGP ID    (u32, big-endian)
//!   +34  Timestamp      (u32 seconds + u32 microseconds since the
//!                        Unix epoch, big-endian)
//! ```

#![forbid(unsafe_code)]

use core::fmt;

use lr_core::buf::{ReadBuf, WriteBuf};
use lr_core::codec::{Decoder, Encoder};
use lr_core::error::{EncodeError, ParseError};

/// BMP version (RFC 7854 §4.1: always 3).
pub const VERSION: u8 = 3;

/// BMP message types (RFC 7854 §4.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum BmpMsgType {
    /// Route Monitoring (§4.6): a BGP UPDATE mirror.
    RouteMonitoring = 0,
    /// Statistics Report (§4.8): per-peer counters.
    StatisticsReport = 1,
    /// Peer Down (§4.9): session went down.
    PeerDown = 2,
    /// Peer Up (§4.10): session came up.
    PeerUp = 3,
    /// Initiation (§4.3): sent on connect.
    Initiation = 4,
    /// Termination (§4.5): sent on disconnect.
    Termination = 5,
    /// Route Mirroring (§4.7): a received BGP message in TLV form.
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

/// Peer type (RFC 7854 §4.2; Loc-RIB per RFC 9069 §4.1).
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
    /// Loc-RIB instance peer (RFC 9069 §4.1): the message mirrors
    /// the local router's own Loc-RIB, not a peer's Adj-RIB-In.
    /// Locally sourced routes MUST be conveyed with this peer type
    /// (RFC 9069 §4.2).
    LocRib = 3,
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

    /// Upper bound on a single BMP message: a Route Monitoring
    /// message wraps one BGP UPDATE, which RFC 8654 lets grow to
    /// 65 535 octets once the Extended Message capability is
    /// negotiated — the common header and the per-peer header ride
    /// on top (RFC 7854 §4.1: the length includes headers, data and
    /// encapsulated messages). A declared length beyond this bound
    /// is treated as malformed.
    pub const MAX_MESSAGE: usize = 65_535 + Self::LEN + PeerHeader::LEN;
}

/// Per-peer header (RFC 7854 §4.2). Present on every message type
/// except Initiation and Termination.
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
    /// Timestamp: seconds + microseconds since the Unix epoch
    /// (RFC 7854 §4.2).
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

    /// Build a Peer Up message (type 3). The body is RFC 7854 §4.10:
    /// local address (16), local port, remote port, then the full
    /// Sent and Received OPEN messages — self-delimiting BGP PDUs
    /// with no length prefixes ("The full OPEN message transmitted
    /// by the monitored router to its peer").
    pub fn peer_up(
        peer: PeerHeader,
        local_addr: [u8; 16],
        local_port: u16,
        remote_port: u16,
        sent_open: &[u8],
        received_open: &[u8],
    ) -> Self {
        let mut payload = Vec::with_capacity(20 + sent_open.len() + received_open.len());
        payload.extend_from_slice(&local_addr);
        payload.extend_from_slice(&local_port.to_be_bytes());
        payload.extend_from_slice(&remote_port.to_be_bytes());
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

    /// Build an Initiation message (type 4). Each
    /// `(&[(info_type, info_value)])` pair becomes one §4.4
    /// Information TLV; values longer than 65 535 octets cannot be
    /// expressed in the 2-octet Information Length and fail at
    /// encode time.
    pub fn initiation(info: &[(u16, &[u8])]) -> Result<Self, EncodeError> {
        let mut payload = Vec::new();
        for (tlv_type, tlv_value) in info {
            payload.extend_from_slice(&tlv_type.to_be_bytes());
            payload.extend_from_slice(&checked_tlv_len(tlv_value.len())?.to_be_bytes());
            payload.extend_from_slice(tlv_value);
        }
        Ok(Self {
            header: BmpHeader {
                version: VERSION,
                msg_len: 0,
                msg_type: BmpMsgType::Initiation,
            },
            peer: None,
            payload,
        })
    }

    /// Build a Termination message (type 5), same TLV framing as
    /// [`Self::initiation`].
    pub fn termination(info: &[(u16, &[u8])]) -> Result<Self, EncodeError> {
        let mut payload = Vec::new();
        for (tlv_type, tlv_value) in info {
            payload.extend_from_slice(&tlv_type.to_be_bytes());
            payload.extend_from_slice(&checked_tlv_len(tlv_value.len())?.to_be_bytes());
            payload.extend_from_slice(tlv_value);
        }
        Ok(Self {
            header: BmpHeader {
                version: VERSION,
                msg_len: 0,
                msg_type: BmpMsgType::Termination,
            },
            peer: None,
            payload,
        })
    }
}

/// The §4.4 Information Length is two octets — a longer value is an
/// encode error, not a silent wrap.
fn checked_tlv_len(len: usize) -> Result<u16, EncodeError> {
    u16::try_from(len)
        .map_err(|_| EncodeError::InvalidValue("bmp info TLV value exceeds 65535 bytes"))
}

/// Peer Down reason (RFC 7854 §4.9). The data that must follow the
/// reason byte differs per reason — the variants below name it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum PeerDownReason {
    /// Reason 1: the local system closed the session. The data is a
    /// BGP PDU carrying the NOTIFICATION that would have been sent
    /// to the peer.
    LocalCloseNotification = 1,
    /// Reason 2: the local system closed the session without a
    /// notification. The data is the 2-byte FSM event code that
    /// caused the close (RFC 4271 §8.1); `0, 0` means no relevant
    /// event code is defined.
    LocalCloseNoNotification = 2,
    /// Reason 3: the remote system closed the session with a
    /// notification. The data is the received BGP PDU carrying the
    /// NOTIFICATION.
    RemoteCloseNotification = 3,
    /// Reason 4: the remote system closed the session without a
    /// notification — including any unexpected termination of the
    /// transport session. No data follows.
    RemoteClose = 4,
    /// Reason 5: the peer will no longer be reported for
    /// configuration reasons. No data follows.
    PeerConfigRemoved = 5,
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
        let mut out = vec![0u8; BmpHeader::MAX_MESSAGE];
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
    ///
    /// A frame whose declared length is below the header size or
    /// beyond [`BmpHeader::MAX_MESSAGE`] is malformed and the whole
    /// buffer is dropped (the declared length cannot be trusted to
    /// skip). A frame of sane length that fails to decode — unknown
    /// version, unknown peer type, truncated peer header — is
    /// dropped alone and the error is returned; the next call
    /// resynchronizes on the following frame instead of re-failing
    /// on the same bytes forever. Unknown MESSAGE TYPE bytes are
    /// skipped silently per RFC 7854 §4.1 ("A BMP implementation
    /// MUST ignore unrecognized message types upon receipt").
    pub fn next_message(&mut self) -> Result<Option<BmpMessage>, ParseError> {
        loop {
            if self.carryover.len() < BmpHeader::LEN {
                return Ok(None);
            }
            let msg_len = u32::from_be_bytes([
                self.carryover[1],
                self.carryover[2],
                self.carryover[3],
                self.carryover[4],
            ]) as usize;
            // A declared length below the header size or beyond any
            // sane BMP message is malformed — do not buffer
            // unboundedly waiting for a huge length an attacker
            // keeps feeding.
            if !(BmpHeader::LEN..=BmpHeader::MAX_MESSAGE).contains(&msg_len) {
                self.carryover.clear();
                return Err(ParseError::bad_length(1, "bmp.msg_len"));
            }
            if self.carryover.len() < msg_len {
                return Ok(None);
            }
            let buf = &self.carryover[..msg_len];
            match decode_message(buf) {
                Ok(Some(msg)) => {
                    self.carryover.drain(0..msg_len);
                    return Ok(Some(msg));
                }
                // RFC 7854 §4.1: ignore unrecognized message types.
                // The frame is length-framed, so skipping it is
                // exact; continue with whatever follows in the
                // buffer.
                Ok(None) => {
                    self.carryover.drain(0..msg_len);
                    continue;
                }
                Err(e) => {
                    // Drop the offending frame only — the stream can
                    // resynchronize on the next one.
                    self.carryover.drain(0..msg_len);
                    return Err(e);
                }
            }
        }
    }

    pub fn decode_slice(&mut self, b: &[u8]) -> Result<Option<BmpMessage>, ParseError> {
        self.feed(b);
        self.next_message()
    }
}

impl Encoder<BmpMessage> for BmpCodec {
    fn encode(&self, msg: &BmpMessage, out: &mut WriteBuf<'_>) -> Result<usize, EncodeError> {
        let start = out.position();
        // A per-peer header is required on every type except
        // Initiation and Termination (RFC 7854 §4.2); refuse the
        // combinations the decoder would reject, so the encoder can
        // never emit a frame this crate cannot read back.
        let needs_peer = !matches!(
            msg.header.msg_type,
            BmpMsgType::Initiation | BmpMsgType::Termination
        );
        if needs_peer != msg.peer.is_some() {
            return Err(EncodeError::InvalidValue(
                "bmp message type and per-peer header presence disagree",
            ));
        }
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
        // Same sanity bound as `next_message`: a declared length
        // outside it can never be completed, so `Ok(None)` ("need
        // more bytes") would buffer unboundedly, and a length below
        // the header size can never decode. Surface it as a length
        // error instead.
        if !(BmpHeader::LEN..=BmpHeader::MAX_MESSAGE).contains(&msg_len) {
            self.carryover.clear();
            return Err(ParseError::bad_length(1, "bmp.msg_len"));
        }
        if self.carryover.len() < msg_len {
            return Ok(None);
        }
        let buf = &self.carryover[..msg_len];
        match decode_message(buf) {
            // RFC 7854 §4.1: ignore unrecognized message types.
            Ok(None) => {
                self.carryover.drain(0..msg_len);
                self.decode(src)
            }
            Ok(Some(msg)) => {
                self.carryover.drain(0..msg_len);
                Ok(Some(msg))
            }
            Err(e) => {
                self.carryover.drain(0..msg_len);
                Err(e)
            }
        }
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

/// Decode one complete frame. `Ok(None)` = the message type byte
/// is not one of the seven assigned values — the caller skips the
/// frame per RFC 7854 §4.1.
fn decode_message(buf: &[u8]) -> Result<Option<BmpMessage>, ParseError> {
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
    let Some(msg_type) = BmpMsgType::from_u8(buf[5]) else {
        return Ok(None);
    };
    let mut offset = BmpHeader::LEN;
    // Every type except Initiation and Termination carries a
    // per-peer header (RFC 7854 §4.2).
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
    Ok(Some(BmpMessage {
        header: BmpHeader {
            version,
            msg_len,
            msg_type,
        },
        peer,
        payload,
    }))
}

fn decode_peer_header(buf: &[u8]) -> Result<PeerHeader, ParseError> {
    if buf.len() < PeerHeader::LEN {
        return Err(ParseError::truncated("bmp.peer_header"));
    }
    // Peer Type is one of the IANA-registered values: 0=Global,
    // 1=RD, 2=Local Instance (RFC 7854 §4.2) and 3=Loc-RIB
    // Instance Peer (RFC 9069 §4.1). Values 4..=255 are unassigned
    // — surface the wire byte as an `UnknownType` parse error so
    // the collector can drop the frame and log the peer byte
    // instead of installing routes attributed to a peer that did
    // not really send them.
    let peer_type = match buf[0] {
        0 => PeerType::Global,
        1 => PeerType::Rd,
        2 => PeerType::Local,
        3 => PeerType::LocRib,
        other => {
            return Err(
                ParseError::unknown_type(0, "bmp.peer_header.peer_type").with_detail(format!(
                    "peer_type {other} is unassigned (RFC 7854 §4.2 / RFC 9069 §4.1)"
                )),
            );
        }
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
        let msg = BmpMessage::initiation(info).unwrap();
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
        let msg = BmpMessage::termination(info).unwrap();
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
        // Payload per RFC 7854 §4.10: local_addr(16) + local_port(2)
        // + remote_port(2) + sent_open(29) + recv_open(29) = 78. The
        // OPENs are self-delimiting BGP PDUs — no length prefixes.
        assert_eq!(dec.payload.len(), 78);
        assert_eq!(&dec.payload[20..20 + 29], &sent_open[..]);
        assert_eq!(&dec.payload[20 + 29..], &received_open[..]);
    }

    #[test]
    fn peer_down_roundtrip() {
        let peer = sample_peer_header();
        let msg = BmpMessage::peer_down(
            peer.clone(),
            PeerDownReason::RemoteCloseNotification,
            &[0x06, 0x08], // CEASE code+subcode
        );
        let enc = BmpCodec::new().encode_vec(&msg).unwrap();
        let mut codec = BmpCodec::new();
        let dec = codec.decode_slice(&enc).unwrap().unwrap();
        assert_eq!(dec.header.msg_type, BmpMsgType::PeerDown);
        assert_eq!(
            dec.payload[0],
            PeerDownReason::RemoteCloseNotification as u8
        );
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

    // Regression for the silent peer_type → Global fallback. Before
    // the fix, `decode_peer_header` mapped unassigned peer_type values
    // to `Global`, masking malformed input as a real global peer. The
    // strict decoder surfaces an `UnknownType` error so the collector
    // can drop the frame and log the wire byte instead. Byte 3 is the
    // assigned Loc-RIB type (RFC 9069 §4.1) and must decode; byte 4 is
    // unassigned and must not.
    #[test]
    fn decode_rejects_unassigned_peer_type() {
        let peer = sample_peer_header();
        let msg = BmpMessage::route_monitoring(peer, &[]);
        let mut enc = BmpCodec::new().encode_vec(&msg).unwrap();
        // Common header (6) puts the peer header at byte 6. The first
        // peer-header octet is the peer_type byte (RFC 7854 §4.2).
        enc[6] = 4;
        let mut codec = BmpCodec::new();
        let err = codec.decode_slice(&enc).unwrap_err();
        // The error kind matches `ParseError::unknown_type(...).kind`
        // without naming the `ErrorKind` variant directly (it lives
        // in `lr-core::error`, not in this crate's prelude).
        let expected_kind = ParseError::unknown_type(0, "x").kind;
        assert_eq!(err.kind, expected_kind);
        assert_eq!(err.context, "bmp.peer_header.peer_type");
        assert!(
            err.detail
                .as_deref()
                .unwrap_or_default()
                .contains("unassigned"),
            "error should mention the unassigned status, got: {:?}",
            err.detail
        );
    }

    #[test]
    fn decode_accepts_each_assigned_peer_type() {
        // RFC 7854 §4.2 assigns 0-2; RFC 9069 §4.1 assigns 3
        // (Loc-RIB). Each must round-trip.
        for (byte, expected) in [
            (0u8, PeerType::Global),
            (1, PeerType::Rd),
            (2, PeerType::Local),
            (3, PeerType::LocRib),
        ] {
            let peer = sample_peer_header();
            let msg = BmpMessage::route_monitoring(peer, &[]);
            let mut enc = BmpCodec::new().encode_vec(&msg).unwrap();
            enc[6] = byte;
            let mut codec = BmpCodec::new();
            let dec = codec.decode_slice(&enc).unwrap().unwrap();
            assert_eq!(
                dec.peer.unwrap().peer_type,
                expected,
                "peer_type byte {byte} should decode to {expected:?}"
            );
        }
    }

    // ---------------------------------------------------------------------------
    // Audit H65 batch: error-path resynchronization, unknown-type skip,
    // the peer-header presence check and the extended-UPDATE size bound.
    // ---------------------------------------------------------------------------

    #[test]
    fn decode_error_drops_only_the_bad_frame() {
        // A frame with an unassigned peer type is followed by a good
        // Route Monitoring frame in the same buffer. The first
        // next_message call reports the error but consumes only the bad
        // frame; the second call decodes the good one — the stream
        // resynchronizes instead of re-failing on the same bytes.
        let peer = sample_peer_header();
        let good = BmpMessage::route_monitoring(peer, &[0xAB]);
        let mut bad = BmpCodec::new().encode_vec(&good).unwrap();
        bad[6] = 9; // unassigned peer type
        let good_wire = BmpCodec::new().encode_vec(&good).unwrap();
        let mut codec = BmpCodec::new();
        codec.feed(&bad);
        codec.feed(&good_wire);
        assert!(codec.next_message().is_err(), "the bad frame errors");
        let dec = codec.next_message().unwrap().unwrap();
        assert_eq!(dec.payload, vec![0xAB], "the following frame decodes");
    }

    #[test]
    fn unknown_message_type_is_skipped_not_fatal() {
        // RFC 7854 §4.1: "A BMP implementation MUST ignore unrecognized
        // message types upon receipt." An experimental type-251 frame
        // between two Route Monitoring frames must not kill the stream.
        let peer = sample_peer_header();
        let m1 = BmpMessage::route_monitoring(peer.clone(), &[0x01]);
        let m2 = BmpMessage::route_monitoring(peer, &[0x02]);
        let w1 = BmpCodec::new().encode_vec(&m1).unwrap();
        let w2 = BmpCodec::new().encode_vec(&m2).unwrap();
        // Hand-build a type-251 frame: valid header, unknown type byte.
        let mut unknown = vec![0u8; 6 + 4];
        unknown[0] = VERSION;
        unknown[1..5].copy_from_slice(&(6u32 + 4).to_be_bytes());
        unknown[5] = 251;
        unknown[6] = 0xde;
        unknown[7] = 0xad;
        unknown[8] = 0xbe;
        unknown[9] = 0xef;
        let mut codec = BmpCodec::new();
        codec.feed(&w1);
        codec.feed(&unknown);
        codec.feed(&w2);
        let d1 = codec.next_message().unwrap().unwrap();
        assert_eq!(d1.payload, vec![0x01]);
        // The unknown frame is skipped silently and the next good frame
        // comes back out of the same drain.
        let d2 = codec.next_message().unwrap().unwrap();
        assert_eq!(d2.payload, vec![0x02]);
        assert!(codec.next_message().unwrap().is_none());
    }

    #[test]
    fn extended_update_sized_route_monitoring_decodes() {
        // An RFC 8654 extended UPDATE (65 535 octets) wrapped in a Route
        // Monitoring message is 65 535 + 6 + 42 bytes — above the old
        // 65 535 cap, which rejected it as bad_length and cleared the
        // buffer.
        let peer = sample_peer_header();
        let update = vec![0xAA; 65_535];
        let msg = BmpMessage::route_monitoring(peer, &update);
        let enc = BmpCodec::new().encode_vec(&msg).unwrap();
        assert_eq!(enc.len(), 65_535 + BmpHeader::LEN + PeerHeader::LEN);
        let mut codec = BmpCodec::new();
        let dec = codec.decode_slice(&enc).unwrap().unwrap();
        assert_eq!(dec.payload.len(), 65_535);
    }

    #[test]
    fn encode_rejects_peer_header_presence_mismatch() {
        // Initiation carries no per-peer header; Route Monitoring
        // requires one. The encoder must refuse the wrong combinations so
        // it can never emit a frame its own decoder rejects.
        let err = BmpCodec::new()
            .encode_vec(&BmpMessage {
                header: BmpHeader {
                    version: VERSION,
                    msg_len: 0,
                    msg_type: BmpMsgType::RouteMonitoring,
                },
                peer: None,
                payload: vec![],
            })
            .unwrap_err();
        assert!(matches!(err, EncodeError::InvalidValue(_)));
        let info: &[(u16, &[u8])] = &[];
        let with_peer = BmpMessage::initiation(info).unwrap();
        let with_peer = BmpMessage {
            peer: Some(sample_peer_header()),
            ..with_peer
        };
        assert!(BmpCodec::new().encode_vec(&with_peer).is_err());
    }

    #[test]
    fn initiation_tlv_over_u16_fails_to_encode() {
        // The §4.4 Information Length is two octets; a longer value is an
        // error, not a silent wrap.
        let big = vec![0u8; 65_536];
        let info: &[(u16, &[u8])] = &[(0, &big)];
        assert!(BmpMessage::initiation(info).is_err());
    }

    #[test]
    fn peer_down_reason_values_match_rfc_7854_4_9() {
        assert_eq!(PeerDownReason::LocalCloseNotification as u8, 1);
        assert_eq!(PeerDownReason::LocalCloseNoNotification as u8, 2);
        assert_eq!(PeerDownReason::RemoteCloseNotification as u8, 3);
        assert_eq!(PeerDownReason::RemoteClose as u8, 4);
        assert_eq!(PeerDownReason::PeerConfigRemoved as u8, 5);
    }
}
