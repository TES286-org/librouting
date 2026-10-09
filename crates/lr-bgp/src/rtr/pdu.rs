//! RPKI-Router (RTR) protocol PDU codec — RFC 8210 versions 0-2,
//! ASPA PDU per the SIDROPS ASPA profile (BIRD `proto/rpki` parity).
//!
//! The RTR protocol (RFC 8210, successor of RFC 6810) lets a router
//! pull validated RPKI payload — ROAs, Router Keys, ASPA records —
//! from a caching server over a TCP session (default port 8282).
//! This module is the wire layer: the 11-variant [`RtrPdu`] enum — the
//! ten PDU types RFC 8210 §5 defines plus the ASPA PDU — and the
//! framing-aware [`decode`] / [`encode`]. The client state machine
//! (§6: Serial Query, session ID/serial tracking, cache reset
//! handling) layers on top; the daemon wires it to a live cache in
//! `lr-cli`.
//!
//! # PDU set (RFC 8210 §5)
//!
//! | Type | PDU | Versions | Direction |
//! |------|-----|----------|-----------|
//! | 0 | Serial Notify | 0+ | cache → router |
//! | 1 | Serial Query | 0+ | router → cache |
//! | 2 | Reset Query | 0+ | router → cache |
//! | 3 | Cache Response | 0+ | cache → router |
//! | 4 | IPv4 Prefix | 0+ | cache → router |
//! | 5 | *reserved* | — | — |
//! | 6 | IPv6 Prefix | 0+ | cache → router |
//! | 7 | End of Data | 0 (12 B) / 1+ (24 B) | cache → router |
//! | 8 | Cache Reset | 0+ | cache → router |
//! | 9 | Router Key | 1+ | cache → router |
//! | 10 | Error Report | 0+ | both |
//! | 11 | ASPA | 2+ | cache → router |
//!
//! Every PDU starts with the 8-byte header
//! `ver(1) | type(1) | flags_or_session_id_or_error_code(2) |
//! length(4)` where *length* counts the whole PDU including the
//! header. Fixed-size PDUs carry their exact length; variable-size
//! PDUs (Router Key, Error Report, ASPA) compute it from their
//! bodies.
//!
//! # Validation performed on decode
//!
//! * version-gated PDU types: Router Key requires version ≥ 1
//!   (RFC 8210 §5.10), ASPA requires version ≥ 2 — the same gating
//!   BIRD applies in `rpki_check_pdu` (`proto/rpki/packets.c`);
//! * minimum PDU lengths per type, plus exact lengths for the
//!   fixed-size PDUs the RFC pins byte-for-byte;
//! * prefix invariants: `prefix_len ≤ family width`, `max_len ≥
//!   prefix_len`, `max_len ≤ family width` (RFC 8210 §5.1 "Max
//!   Length ... MUST NOT be less than the Prefix Length");
//!   host bits beyond `prefix_len` are masked, mirroring BIRD's
//!   `ipa_and(addr, ipa_mkmask(len))`;
//! * Error Report and ASPA internal length consistency (encapsulated
//!   PDU length and provider-ASN count must divide the body exactly);
//! * announced/withdrawn flags: only bit 0 is meaningful (§5.1); the
//!   reserved bits MUST be zero on transmission and are ignored on
//!   receipt — the codec normalizes them away on decode.
//!
//! The overall PDU length is bounded by [`RTR_PDU_MAX_LEN`] (BIRD's
//! `RPKI_PDU_MAX_LEN`); anything larger is rejected as corrupt so a
//! hostile cache cannot make the router allocate unbounded memory.

use lr_core::addr::Prefix;

/// RTR protocol version 0 (RFC 6810).
pub const RTR_VERSION_0: u8 = 0;
/// RTR protocol version 1 (RFC 8210) — adds Router Key PDUs and the
/// End-of-Data timing intervals.
pub const RTR_VERSION_1: u8 = 1;
/// RTR protocol version 2 — adds the ASPA PDU (SIDROPS ASPA profile;
/// BIRD `RPKI_VERSION_2`).
pub const RTR_VERSION_2: u8 = 2;
/// The highest version this codec speaks (offered on connect, then
/// downgraded per §7 negotiation).
pub const RTR_VERSION_MAX: u8 = RTR_VERSION_2;

/// Fixed header size: `ver | type | flags/session/error | length`.
pub const RTR_HEADER_LEN: usize = 8;
/// Upper bound on any PDU (BIRD `RPKI_PDU_MAX_LEN`).
pub const RTR_PDU_MAX_LEN: usize = 65536;

/// Announce/withdraw bit of the Prefix/Router Key/ASPA Flags field
/// (RFC 8210 §5.1): 1 = announcement, 0 = withdrawal.
pub const RTR_FLAG_ANNOUNCE: u8 = 0x01;

/// PDU type codes (RFC 8210 §5.1.2 / BIRD `pdu_type`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum RtrPduType {
    SerialNotify = 0,
    SerialQuery = 1,
    ResetQuery = 2,
    CacheResponse = 3,
    Ipv4Prefix = 4,
    /// Type 5 is reserved and never valid on the wire.
    Ipv6Prefix = 6,
    EndOfData = 7,
    CacheReset = 8,
    RouterKey = 9,
    ErrorReport = 10,
    Aspa = 11,
}

impl RtrPduType {
    /// The BIRD-style display name (`str_pdu_type` parity).
    pub const fn name(self) -> &'static str {
        match self {
            Self::SerialNotify => "Serial Notify",
            Self::SerialQuery => "Serial Query",
            Self::ResetQuery => "Reset Query",
            Self::CacheResponse => "Cache Response",
            Self::Ipv4Prefix => "IPv4 Prefix",
            Self::Ipv6Prefix => "IPv6 Prefix",
            Self::EndOfData => "End of Data",
            Self::CacheReset => "Cache Reset",
            Self::RouterKey => "Router Key",
            Self::ErrorReport => "Error Report",
            Self::Aspa => "ASPA",
        }
    }

    /// Minimum PDU length for the type (BIRD `min_pdu_size` parity;
    /// Router Key and the variable-size PDUs use their fixed prologue
    /// sizes).
    pub const fn min_len(self) -> usize {
        match self {
            Self::SerialNotify | Self::SerialQuery => 12,
            Self::ResetQuery | Self::CacheResponse | Self::CacheReset => 8,
            Self::Ipv4Prefix => 20,
            Self::Ipv6Prefix => 32,
            // v0 End-of-Data; the v1 form is 24 bytes, checked in
            // decode with the version in hand.
            Self::EndOfData => 12,
            // 8-byte header + 20-octet SKI + 4-octet ASN; the SPKI is
            // variable.
            Self::RouterKey => 32,
            // 8-byte header + 4-octet encapsulated-PDU length; the
            // erroneous PDU and text are variable.
            Self::ErrorReport => 12,
            // 8-byte header + 4-octet customer ASN; providers follow.
            Self::Aspa => 12,
        }
    }
}

/// Error codes (RFC 8210 §12). Fatal codes should drop the session;
/// No Data Available is the documented exception.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum RtrErrorCode {
    CorruptData = 0,
    InternalError = 1,
    NoDataAvailable = 2,
    InvalidRequest = 3,
    UnsupportedProtocolVersion = 4,
    UnsupportedPduType = 5,
    WithdrawalOfUnknownRecord = 6,
    DuplicateAnnouncementReceived = 7,
    UnexpectedProtocolVersion = 8,
}

impl RtrErrorCode {
    /// RFC §12: everything except NoDataAvailable is fatal.
    pub const fn is_fatal(self) -> bool {
        !matches!(self, Self::NoDataAvailable)
    }

    /// The BIRD-style diagnostic name.
    pub const fn name(self) -> &'static str {
        match self {
            Self::CorruptData => "Corrupt Data",
            Self::InternalError => "Internal Error",
            Self::NoDataAvailable => "No Data Available",
            Self::InvalidRequest => "Invalid Request",
            Self::UnsupportedProtocolVersion => "Unsupported Protocol Version",
            Self::UnsupportedPduType => "Unsupported PDU Type",
            Self::WithdrawalOfUnknownRecord => "Withdrawal of Unknown Record",
            Self::DuplicateAnnouncementReceived => "Duplicate Announcement Received",
            Self::UnexpectedProtocolVersion => "Unexpected Protocol Version",
        }
    }
}

/// Decode error kinds. The fatal/protocol distinction matters to the
/// client state machine: [`RtrDecodeError::UnsupportedPduType`] and
/// [`RtrDecodeError::UnsupportedVersion`] map onto Error Report PDUs
/// a well-behaved cache would have sent, while the rest are corrupt
/// input.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RtrDecodeError {
    /// Fewer than [`RTR_HEADER_LEN`] bytes buffered (the framing
    /// layer should read more, then retry).
    #[error("incomplete PDU header")]
    IncompleteHeader,
    /// Header parsed but the body is not fully buffered yet.
    #[error("incomplete PDU body: need {need} bytes, have {have}")]
    IncompleteBody { need: usize, have: usize },
    /// Length below the 8-byte header or above [`RTR_PDU_MAX_LEN`].
    #[error("invalid PDU length {len}")]
    InvalidLength { len: u32 },
    /// PDU type ≥ 12 or the reserved type 5 (RFC §5.1.2).
    #[error("unsupported PDU type {ty}")]
    UnsupportedPduType { ty: u8 },
    /// Router Key on version 0, or ASPA on version < 2.
    #[error("PDU type {ty} not valid at version {ver}")]
    UnsupportedVersion { ty: u8, ver: u8 },
    /// Fixed-size PDU with a length that does not match the RFC form.
    #[error("corrupt {pdu} PDU: length {len} does not match the wire form")]
    BadFixedLength { pdu: &'static str, len: u32 },
    /// Prefix invariants violated (RFC §5.6/§5.7).
    #[error("corrupt {pdu} PDU: {reason}")]
    BadPrefix {
        pdu: &'static str,
        reason: &'static str,
    },
    /// ASPA provider count does not divide the body (SIDROPS profile:
    /// the body after the customer ASN is a whole number of 4-octet
    /// providers).
    #[error("corrupt ASPA PDU: {len} body bytes leave a partial provider ASN")]
    BadAspaLength { len: usize },
    /// Error Report with internally inconsistent lengths.
    #[error("corrupt Error Report PDU: {reason}")]
    BadErrorReport { reason: &'static str },
}

/// One RTR PDU, decoded from (or destined for) the wire. Version-
/// dependent shapes are carried explicitly: End-of-Data keeps the
/// timing intervals as `Option` (v0 omits them, §5.8) and the flags
/// normalize to the announce/withdraw bit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RtrPdu {
    /// Type 0 (§5.2): the cache has new data at `serial`. The only
    /// cache-initiated PDU.
    SerialNotify { session_id: u16, serial: u32 },
    /// Type 1 (§5.3): ask for all changes since `serial`.
    SerialQuery { session_id: u16, serial: u32 },
    /// Type 2 (§5.4): ask for the full current database.
    ResetQuery,
    /// Type 3 (§5.5): the payload PDUs that follow answer a query.
    /// In response to a Reset Query every payload PDU carries the
    /// announce flag.
    CacheResponse { session_id: u16 },
    /// Type 4 (§5.6): one ROA for the v4 space.
    Ipv4Prefix {
        announce: bool,
        prefix: Prefix,
        max_length: u8,
        asn: u32,
    },
    /// Type 6 (§5.7): one ROA for the v6 space.
    Ipv6Prefix {
        announce: bool,
        prefix: Prefix,
        max_length: u8,
        asn: u32,
    },
    /// Type 7 (§5.8): end of a Cache Response batch. The timing
    /// intervals are v1+; v0 decodes with `None` and the client then
    /// applies its configured defaults (RFC 8210 §6: "A cache
    /// ... version 0 ... MAY omit these values").
    EndOfData {
        session_id: u16,
        serial: u32,
        refresh_interval: Option<u32>,
        retry_interval: Option<u32>,
        expire_interval: Option<u32>,
    },
    /// Type 8 (§5.9): the cache cannot serve a Serial Query
    /// incrementally — the client should Reset Query.
    CacheReset,
    /// Type 9 (§5.10, v1+): a BGPsec router key. The SPKI is the full
    /// DER `subjectPublicKeyInfo` (tag + length + value).
    RouterKey {
        announce: bool,
        ski: [u8; 20],
        asn: u32,
        subject_public_key_info: Vec<u8>,
    },
    /// Type 10 (§5.11): error report, either direction. The
    /// encapsulated PDU is the raw bytes of the PDU that caused the
    /// error (empty when the error is not PDU-specific).
    ErrorReport {
        error_code: RtrErrorCode,
        erroneous_pdu: Vec<u8>,
        error_text: Option<String>,
    },
    /// Type 11 (v2+, SIDROPS ASPA profile): the provider set of one
    /// customer AS. A withdrawal (`announce = false`) deletes the
    /// whole customer record.
    Aspa {
        announce: bool,
        customer_asn: u32,
        providers: Vec<u32>,
    },
}

impl RtrPdu {
    /// The RFC §5.1.2 type code of this PDU.
    pub const fn pdu_type(&self) -> RtrPduType {
        match self {
            Self::SerialNotify { .. } => RtrPduType::SerialNotify,
            Self::SerialQuery { .. } => RtrPduType::SerialQuery,
            Self::ResetQuery => RtrPduType::ResetQuery,
            Self::CacheResponse { .. } => RtrPduType::CacheResponse,
            Self::Ipv4Prefix { .. } => RtrPduType::Ipv4Prefix,
            Self::Ipv6Prefix { .. } => RtrPduType::Ipv6Prefix,
            Self::EndOfData { .. } => RtrPduType::EndOfData,
            Self::CacheReset => RtrPduType::CacheReset,
            Self::RouterKey { .. } => RtrPduType::RouterKey,
            Self::ErrorReport { .. } => RtrPduType::ErrorReport,
            Self::Aspa { .. } => RtrPduType::Aspa,
        }
    }

    /// The version this PDU requires at minimum (Router Key: 1,
    /// ASPA: 2, everything else: 0).
    pub const fn min_version(&self) -> u8 {
        match self {
            Self::RouterKey { .. } => RTR_VERSION_1,
            Self::Aspa { .. } => RTR_VERSION_2,
            _ => RTR_VERSION_0,
        }
    }
}

/// Encode `pdu` at protocol `version` and append the wire bytes to
/// `out`. The version must satisfy [`RtrPdu::min_version`] —
/// otherwise the wire form would be a cache-side protocol violation.
///
/// The End-of-Data shape follows the version: 24 bytes with the
/// timing intervals on v1+, 12 bytes without on v0 (§5.8).
pub fn encode(pdu: &RtrPdu, version: u8, out: &mut Vec<u8>) {
    assert!(
        version >= pdu.min_version(),
        "PDU {:?} requires version >= {}",
        pdu.pdu_type(),
        pdu.min_version()
    );
    let start = out.len();
    let ty = pdu.pdu_type() as u8;
    match pdu {
        RtrPdu::SerialNotify { session_id, serial }
        | RtrPdu::SerialQuery { session_id, serial } => {
            out.push(version);
            out.push(ty);
            out.extend_from_slice(&session_id.to_be_bytes());
            out.extend_from_slice(&12u32.to_be_bytes());
            out.extend_from_slice(&serial.to_be_bytes());
        }
        RtrPdu::ResetQuery => {
            // §5.4: the 16-bit field after the type is zero.
            out.push(version);
            out.push(ty);
            out.extend_from_slice(&0u16.to_be_bytes());
            out.extend_from_slice(&8u32.to_be_bytes());
        }
        RtrPdu::CacheResponse { session_id } => {
            out.push(version);
            out.push(ty);
            out.extend_from_slice(&session_id.to_be_bytes());
            out.extend_from_slice(&8u32.to_be_bytes());
        }
        RtrPdu::CacheReset => {
            out.push(version);
            out.push(ty);
            out.extend_from_slice(&0u16.to_be_bytes());
            out.extend_from_slice(&8u32.to_be_bytes());
        }
        RtrPdu::Ipv4Prefix {
            announce,
            prefix,
            max_length,
            asn,
        } => {
            let [a, b, c, d] = v4_bytes(prefix);
            out.push(version);
            out.push(ty);
            out.extend_from_slice(&0u16.to_be_bytes());
            out.extend_from_slice(&20u32.to_be_bytes());
            out.push(flags_byte(*announce));
            out.push(prefix.prefix_len);
            out.push(*max_length);
            out.push(0);
            out.extend_from_slice(&[a, b, c, d]);
            out.extend_from_slice(&asn.to_be_bytes());
        }
        RtrPdu::Ipv6Prefix {
            announce,
            prefix,
            max_length,
            asn,
        } => {
            let bytes = v6_bytes(prefix);
            out.push(version);
            out.push(ty);
            out.extend_from_slice(&0u16.to_be_bytes());
            out.extend_from_slice(&32u32.to_be_bytes());
            out.push(flags_byte(*announce));
            out.push(prefix.prefix_len);
            out.push(*max_length);
            out.push(0);
            out.extend_from_slice(&bytes);
            out.extend_from_slice(&asn.to_be_bytes());
        }
        RtrPdu::EndOfData {
            session_id,
            serial,
            refresh_interval,
            retry_interval,
            expire_interval,
        } => {
            out.push(version);
            out.push(ty);
            out.extend_from_slice(&session_id.to_be_bytes());
            if version >= RTR_VERSION_1 {
                out.extend_from_slice(&24u32.to_be_bytes());
                out.extend_from_slice(&serial.to_be_bytes());
                out.extend_from_slice(&refresh_interval.unwrap_or(3600).to_be_bytes());
                out.extend_from_slice(&retry_interval.unwrap_or(600).to_be_bytes());
                out.extend_from_slice(&expire_interval.unwrap_or(7200).to_be_bytes());
            } else {
                out.extend_from_slice(&12u32.to_be_bytes());
                out.extend_from_slice(&serial.to_be_bytes());
            }
        }
        RtrPdu::RouterKey {
            announce,
            ski,
            asn,
            subject_public_key_info,
        } => {
            let len = RTR_HEADER_LEN + ski.len() + 4 + subject_public_key_info.len();
            out.push(version);
            out.push(ty);
            out.push(flags_byte(*announce));
            out.push(0);
            out.extend_from_slice(&(len as u32).to_be_bytes());
            out.extend_from_slice(ski);
            out.extend_from_slice(&asn.to_be_bytes());
            out.extend_from_slice(subject_public_key_info);
        }
        RtrPdu::ErrorReport {
            error_code,
            erroneous_pdu,
            error_text,
        } => {
            let text_bytes = error_text.as_deref().map(str::as_bytes).unwrap_or(&[]);
            let len = RTR_HEADER_LEN + 4 + erroneous_pdu.len() + 4 + text_bytes.len();
            out.push(version);
            out.push(ty);
            out.extend_from_slice(&(*error_code as u16).to_be_bytes());
            out.extend_from_slice(&(len as u32).to_be_bytes());
            out.extend_from_slice(&(erroneous_pdu.len() as u32).to_be_bytes());
            out.extend_from_slice(erroneous_pdu);
            out.extend_from_slice(&(text_bytes.len() as u32).to_be_bytes());
            out.extend_from_slice(text_bytes);
        }
        RtrPdu::Aspa {
            announce,
            customer_asn,
            providers,
        } => {
            let len = RTR_HEADER_LEN + 4 + providers.len() * 4;
            out.push(version);
            out.push(ty);
            out.push(flags_byte(*announce));
            out.push(0);
            out.extend_from_slice(&(len as u32).to_be_bytes());
            out.extend_from_slice(&customer_asn.to_be_bytes());
            for p in providers {
                out.extend_from_slice(&p.to_be_bytes());
            }
        }
    }
    debug_assert_eq!(
        out.len() - start,
        u32::from_be_bytes([
            out[start + 4],
            out[start + 5],
            out[start + 6],
            out[start + 7]
        ]) as usize,
        "encoded length field must match the bytes written"
    );
}

/// Encode into a fresh buffer.
pub fn encode_vec(pdu: &RtrPdu, version: u8) -> Vec<u8> {
    let mut out = Vec::new();
    encode(pdu, version, &mut out);
    out
}

/// The Flags byte with only the announce bit (§5.1: reserved bits
/// MUST be zero on transmission).
const fn flags_byte(announce: bool) -> u8 {
    if announce {
        RTR_FLAG_ANNOUNCE
    } else {
        0
    }
}

/// The v4 bytes of a prefix (zero-padded from the family-agnostic
/// `IpAddr` when malformed input reaches the encoder — the decoder
/// guarantees family/type agreement).
fn v4_bytes(prefix: &Prefix) -> [u8; 4] {
    match prefix.addr {
        lr_core::addr::IpAddr::V4(b) => b,
        lr_core::addr::IpAddr::V6(_) => [0; 4],
    }
}

/// The v6 bytes of a prefix.
fn v6_bytes(prefix: &Prefix) -> [u8; 16] {
    match prefix.addr {
        lr_core::addr::IpAddr::V6(b) => b,
        lr_core::addr::IpAddr::V4(b) => {
            let mut out = [0u8; 16];
            out[..4].copy_from_slice(&b);
            out
        }
    }
}

/// Decode one PDU from the front of `buf`.
///
/// Returns `Ok(None)` while fewer bytes are buffered than the PDU
/// header/body announce (the framing layer reads more and retries),
/// `Ok(Some((version, pdu, consumed)))` on success. The protocol
/// version is returned alongside the PDU — the §7 version
/// negotiation needs the version of *every* received PDU, not just
/// the first. A version a full `decode` pass rejects as
/// [`RtrDecodeError::UnsupportedVersion`] is one where the PDU *type*
/// itself cannot exist at that version; other version mismatches are
/// the client state machine's business.
pub fn decode(buf: &[u8]) -> Result<Option<(u8, RtrPdu, usize)>, RtrDecodeError> {
    if buf.len() < RTR_HEADER_LEN {
        return Ok(None);
    }
    let version = buf[0];
    let ty = buf[1];
    let len = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);
    if len < RTR_HEADER_LEN as u32 || len as usize > RTR_PDU_MAX_LEN {
        return Err(RtrDecodeError::InvalidLength { len });
    }
    if buf.len() < len as usize {
        return Ok(None);
    }
    let body = &buf[..len as usize];

    // Type validation (§5.1.2): 5 is reserved, 0-11 are the defined
    // set. The version gates mirror BIRD's rpki_check_pdu (Router
    // Key needs v1+, ASPA v2+); a gated-out type is reported as
    // unsupported rather than corrupt so the client can send the
    // correct Error Report back.
    let pdu_type = match ty {
        0 => RtrPduType::SerialNotify,
        1 => RtrPduType::SerialQuery,
        2 => RtrPduType::ResetQuery,
        3 => RtrPduType::CacheResponse,
        4 => RtrPduType::Ipv4Prefix,
        6 => RtrPduType::Ipv6Prefix,
        7 => RtrPduType::EndOfData,
        8 => RtrPduType::CacheReset,
        9 if version >= RTR_VERSION_1 => RtrPduType::RouterKey,
        10 => RtrPduType::ErrorReport,
        11 if version >= RTR_VERSION_2 => RtrPduType::Aspa,
        9 | 11 => {
            return Err(RtrDecodeError::UnsupportedVersion { ty, ver: version });
        }
        _ => {
            return Err(RtrDecodeError::UnsupportedPduType { ty });
        }
    };

    let pdu = match pdu_type {
        RtrPduType::SerialNotify | RtrPduType::SerialQuery => {
            expect_len(pdu_type, len, 12)?;
            let session_id = u16::from_be_bytes([body[2], body[3]]);
            let serial = u32::from_be_bytes([body[8], body[9], body[10], body[11]]);
            if pdu_type == RtrPduType::SerialNotify {
                RtrPdu::SerialNotify { session_id, serial }
            } else {
                RtrPdu::SerialQuery { session_id, serial }
            }
        }
        RtrPduType::ResetQuery | RtrPduType::CacheReset => {
            expect_len(pdu_type, len, 8)?;
            if pdu_type == RtrPduType::ResetQuery {
                RtrPdu::ResetQuery
            } else {
                RtrPdu::CacheReset
            }
        }
        RtrPduType::CacheResponse => {
            expect_len(pdu_type, len, 8)?;
            let session_id = u16::from_be_bytes([body[2], body[3]]);
            RtrPdu::CacheResponse { session_id }
        }
        RtrPduType::Ipv4Prefix => {
            expect_len(pdu_type, len, 20)?;
            let announce = body[8] & RTR_FLAG_ANNOUNCE != 0;
            let prefix_len = body[9];
            let max_length = body[10];
            check_prefix(pdu_type, prefix_len, max_length, 32)?;
            let addr = [body[12], body[13], body[14], body[15]];
            let asn = u32::from_be_bytes([body[16], body[17], body[18], body[19]]);
            // Host bits beyond prefix_len are masked (BIRD parity).
            let prefix = mask_host_bits(Prefix::new_v4(addr, prefix_len));
            RtrPdu::Ipv4Prefix {
                announce,
                prefix,
                max_length,
                asn,
            }
        }
        RtrPduType::Ipv6Prefix => {
            expect_len(pdu_type, len, 32)?;
            let announce = body[8] & RTR_FLAG_ANNOUNCE != 0;
            let prefix_len = body[9];
            let max_length = body[10];
            check_prefix(pdu_type, prefix_len, max_length, 128)?;
            let mut addr = [0u8; 16];
            addr.copy_from_slice(&body[12..28]);
            let asn = u32::from_be_bytes([body[28], body[29], body[30], body[31]]);
            let prefix = mask_host_bits(Prefix::new_v6(addr, prefix_len));
            RtrPdu::Ipv6Prefix {
                announce,
                prefix,
                max_length,
                asn,
            }
        }
        RtrPduType::EndOfData => {
            // §5.8: v0 = 12 bytes (session + serial only); v1+ = 24
            // bytes with the three timing intervals.
            let session_id = u16::from_be_bytes([body[2], body[3]]);
            let serial = u32::from_be_bytes([body[8], body[9], body[10], body[11]]);
            if version >= RTR_VERSION_1 {
                expect_len(pdu_type, len, 24)?;
                let refresh_interval =
                    Some(u32::from_be_bytes([body[12], body[13], body[14], body[15]]));
                let retry_interval =
                    Some(u32::from_be_bytes([body[16], body[17], body[18], body[19]]));
                let expire_interval =
                    Some(u32::from_be_bytes([body[20], body[21], body[22], body[23]]));
                RtrPdu::EndOfData {
                    session_id,
                    serial,
                    refresh_interval,
                    retry_interval,
                    expire_interval,
                }
            } else {
                expect_len(pdu_type, len, 12)?;
                RtrPdu::EndOfData {
                    session_id,
                    serial,
                    refresh_interval: None,
                    retry_interval: None,
                    expire_interval: None,
                }
            }
        }
        RtrPduType::RouterKey => {
            // §5.10: header + 20-octet SKI + 4-octet ASN + variable
            // SPKI.
            if (len as usize) < 32 {
                return Err(RtrDecodeError::BadFixedLength {
                    pdu: pdu_type.name(),
                    len,
                });
            }
            let announce = body[2] & RTR_FLAG_ANNOUNCE != 0;
            let mut ski = [0u8; 20];
            ski.copy_from_slice(&body[8..28]);
            let asn = u32::from_be_bytes([body[28], body[29], body[30], body[31]]);
            let subject_public_key_info = body[32..].to_vec();
            RtrPdu::RouterKey {
                announce,
                ski,
                asn,
                subject_public_key_info,
            }
        }
        RtrPduType::ErrorReport => {
            // §5.11: error code (u16) | len | len_enc_pdu (u32) |
            // erroneous PDU | len_text (u32) | text.
            if (len as usize) < 12 {
                return Err(RtrDecodeError::BadFixedLength {
                    pdu: pdu_type.name(),
                    len,
                });
            }
            let error_code = u16::from_be_bytes([body[2], body[3]]);
            let error_code = match error_code {
                0 => RtrErrorCode::CorruptData,
                1 => RtrErrorCode::InternalError,
                2 => RtrErrorCode::NoDataAvailable,
                3 => RtrErrorCode::InvalidRequest,
                4 => RtrErrorCode::UnsupportedProtocolVersion,
                5 => RtrErrorCode::UnsupportedPduType,
                6 => RtrErrorCode::WithdrawalOfUnknownRecord,
                7 => RtrErrorCode::DuplicateAnnouncementReceived,
                8 => RtrErrorCode::UnexpectedProtocolVersion,
                other => {
                    // §12: the registry may grow; carry unknown codes
                    // through as Corrupt Data is wrong — but the enum
                    // is closed. A cache sending an unknown code is
                    // still speaking a valid protocol frame, so map
                    // to the closest diagnostic-preserving error.
                    let _ = other;
                    return Err(RtrDecodeError::BadErrorReport {
                        reason: "unknown error code",
                    });
                }
            };
            let enc_len = u32::from_be_bytes([body[8], body[9], body[10], body[11]]) as usize;
            // 12 = header + enc_len field; then the encapsulated PDU,
            // then the text length field and text.
            let rest = &body[12..];
            if rest.len() < enc_len + 4 {
                return Err(RtrDecodeError::BadErrorReport {
                    reason: "encapsulated PDU length overruns the PDU",
                });
            }
            let erroneous_pdu = rest[..enc_len].to_vec();
            let text_len = u32::from_be_bytes([
                rest[enc_len],
                rest[enc_len + 1],
                rest[enc_len + 2],
                rest[enc_len + 3],
            ]) as usize;
            let text_bytes = &rest[enc_len + 4..];
            if text_bytes.len() != text_len {
                return Err(RtrDecodeError::BadErrorReport {
                    reason: "error text length does not match the PDU",
                });
            }
            let error_text = if text_len == 0 {
                None
            } else {
                Some(String::from_utf8_lossy(text_bytes).into_owned())
            };
            RtrPdu::ErrorReport {
                error_code,
                erroneous_pdu,
                error_text,
            }
        }
        RtrPduType::Aspa => {
            // SIDROPS ASPA profile: flags | zero | len | customer ASN
            // | provider ASNs (4 bytes each).
            if (len as usize) < 12 {
                return Err(RtrDecodeError::BadFixedLength {
                    pdu: pdu_type.name(),
                    len,
                });
            }
            let announce = body[2] & RTR_FLAG_ANNOUNCE != 0;
            let customer_asn = u32::from_be_bytes([body[8], body[9], body[10], body[11]]);
            let provider_bytes = body.len() - 12;
            if !provider_bytes.is_multiple_of(4) {
                return Err(RtrDecodeError::BadAspaLength {
                    len: provider_bytes,
                });
            }
            let mut providers = Vec::with_capacity(provider_bytes / 4);
            for chunk in body[12..].as_chunks::<4>().0 {
                providers.push(u32::from_be_bytes(*chunk));
            }
            RtrPdu::Aspa {
                announce,
                customer_asn,
                providers,
            }
        }
    };
    Ok(Some((version, pdu, len as usize)))
}

/// Fixed-length check helper.
fn expect_len(pdu: RtrPduType, len: u32, expected: u32) -> Result<(), RtrDecodeError> {
    if len != expected {
        return Err(RtrDecodeError::BadFixedLength {
            pdu: pdu.name(),
            len,
        });
    }
    Ok(())
}

/// Prefix invariant check (§5.6/§5.7).
fn check_prefix(
    pdu: RtrPduType,
    prefix_len: u8,
    max_length: u8,
    width: u8,
) -> Result<(), RtrDecodeError> {
    if prefix_len > width {
        return Err(RtrDecodeError::BadPrefix {
            pdu: pdu.name(),
            reason: "prefix length exceeds the address family width",
        });
    }
    if max_length < prefix_len {
        return Err(RtrDecodeError::BadPrefix {
            pdu: pdu.name(),
            reason: "max length below the prefix length",
        });
    }
    if max_length > width {
        return Err(RtrDecodeError::BadPrefix {
            pdu: pdu.name(),
            reason: "max length exceeds the address family width",
        });
    }
    Ok(())
}

/// Zero the host bits of a prefix (BIRD's `ipa_and(mask)`
/// normalization; keeps the ROA table canonical).
fn mask_host_bits(prefix: Prefix) -> Prefix {
    let net = prefix.network();
    Prefix {
        addr: net,
        prefix_len: prefix.prefix_len,
    }
}

#[cfg(test)]
#[path = "pdu_tests.rs"]
mod tests;
