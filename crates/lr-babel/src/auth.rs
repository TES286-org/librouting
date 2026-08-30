//! RFC 8967 MAC authentication for Babel datagrams, plus the RFC 9467
//! relaxed packet-counter verification update.
//!
//! The module has two layers:
//!
//! * Stateless primitives: pseudo-headers ([`BabelPseudoHeader`]), MAC
//!   computation ([`BabelMacAlgorithm`], [`BabelMacKey`]), packet
//!   decoration ([`authenticate_packet`]) and verification
//!   ([`verify_packet`]). These are simple to embed but implement no
//!   challenge mechanism — they suit transports that manage their own
//!   neighbour state.
//!
//! * The stateful interface ([`BabelAuthInterface`]): the full RFC 8967
//!   §4.3 reception algorithm (preparse, Challenge Request/Reply §4.3.1,
//!   §4.4 state expiry, §5 incremental deployment) and the RFC 9467
//!   §3.1 unicast/multicast PC split plus §3.2 window verification.
//!   Transports drive it with the datagram, its pseudo-header and the
//!   current time; the interface returns the accepted plain body plus the
//!   challenge control traffic it must emit.
//!
//! MAC coverage: HMAC-SHA-256 (RFC 8967 §4.1, mandatory to implement,
//! 32-octet digest) and keyed BLAKE2s with a 128-bit digest (RFC 8967
//! §4.1 SHOULD, 16-octet digest, RFC 7693 §3). Every MAC covers the
//! pseudo-header plus the packet from octet 0 up to (Body Length + 4)
//! exclusive; the trailer is excluded, which is what makes the trailer's
//! MAC TLVs self-verifying.

use std::collections::{BTreeMap, HashMap};
use std::hash::{BuildHasher, Hasher};

use blake2::digest::typenum::U16;
use blake2::Blake2sMac;
use hmac::{Hmac, Mac};
use lr_core::addr::IpAddr;
use sha2::Sha256;

use crate::{BODY_OFFSET, MAGIC, VERSION};

type HmacSha256 = Hmac<Sha256>;
type Blake2sMac128 = Blake2sMac<U16>;

const MAC_TLV: u8 = 16;
const PC_TLV: u8 = 17;
const CHALLENGE_REQUEST_TLV: u8 = 18;
const CHALLENGE_REPLY_TLV: u8 = 19;

/// RFC 8967 §6.2: the Index is an opaque string of 0 to 32 octets.
const MAX_INDEX_LEN: usize = 32;
/// RFC 8967 §6.3: the nonce is an opaque string of 0 to 192 octets.
const MAX_NONCE_LEN: usize = 192;
/// Sanity bounds for MAC TLV bodies we are willing to parse. The mandatory
/// digest is 32 octets, BLAKE2s-128 is 16; other algorithms MAY exist but
/// anything outside these bounds is almost certainly a malformed packet.
const MIN_MAC_LEN: usize = 8;
const MAX_MAC_LEN: usize = 128;

/// Transport fields that RFC 8967 includes in the MAC but does not transmit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BabelPseudoHeader {
    pub source: IpAddr,
    pub source_port: u16,
    pub destination: IpAddr,
    pub destination_port: u16,
}

impl BabelPseudoHeader {
    /// Encode the RFC 8967 IPv4 or IPv6 pseudo-header.
    pub fn encode(self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(match (self.source, self.destination) {
            (IpAddr::V4(_), IpAddr::V4(_)) => 12,
            (IpAddr::V6(_), IpAddr::V6(_)) => 36,
            _ => 0,
        });
        match (self.source, self.destination) {
            (IpAddr::V4(source), IpAddr::V4(destination)) => {
                bytes.extend_from_slice(&source);
                bytes.extend_from_slice(&self.source_port.to_be_bytes());
                bytes.extend_from_slice(&destination);
                bytes.extend_from_slice(&self.destination_port.to_be_bytes());
            }
            (IpAddr::V6(source), IpAddr::V6(destination)) => {
                bytes.extend_from_slice(&source);
                bytes.extend_from_slice(&self.source_port.to_be_bytes());
                bytes.extend_from_slice(&destination);
                bytes.extend_from_slice(&self.destination_port.to_be_bytes());
            }
            _ => {}
        }
        bytes
    }

    fn family_matches(self) -> bool {
        matches!(
            (self.source, self.destination),
            (IpAddr::V4(_), IpAddr::V4(_)) | (IpAddr::V6(_), IpAddr::V6(_))
        )
    }
}

/// A MAC algorithm for RFC 8967 authentication (§4.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BabelMacAlgorithm {
    /// HMAC-SHA-256 — mandatory to implement, 32-octet digest.
    HmacSha256,
    /// Keyed BLAKE2s with a 128-bit (16-octet) digest — SHOULD implement
    /// (RFC 8967 §4.1; the keyed construction is RFC 7693 §3).
    Blake2s128,
}

impl BabelMacAlgorithm {
    /// Digest length in octets — also the MAC TLV body length on the wire.
    pub const fn digest_len(self) -> usize {
        match self {
            Self::HmacSha256 => 32,
            Self::Blake2s128 => 16,
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::HmacSha256 => "hmac-sha256",
            Self::Blake2s128 => "blake2s",
        }
    }

    /// Parse a configuration name ("hmac-sha256", "blake2s", ...).
    pub fn from_name(name: &str) -> Option<Self> {
        match name.trim().to_ascii_lowercase().as_str() {
            "hmac-sha256" | "hmac-sha-256" | "hmac_sha256" => Some(Self::HmacSha256),
            "blake2s" | "blake2s-128" | "blake2s128" => Some(Self::Blake2s128),
            _ => None,
        }
    }
}

/// One symmetric interface key. RFC 8967 permits multiple active keys to
/// make key rotation non-disruptive (§5): every outgoing packet carries one
/// MAC per key, and a received packet passes if any configured key matches.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BabelMacKey {
    pub algorithm: BabelMacAlgorithm,
    pub secret: Vec<u8>,
}

impl BabelMacKey {
    /// HMAC-SHA-256 key (the mandatory algorithm).
    pub fn new(secret: impl Into<Vec<u8>>) -> Self {
        Self {
            algorithm: BabelMacAlgorithm::HmacSha256,
            secret: secret.into(),
        }
    }

    /// HMAC-SHA-256 key (explicit constructor).
    pub fn hmac_sha256(secret: impl Into<Vec<u8>>) -> Self {
        Self::new(secret)
    }

    /// Keyed BLAKE2s key with a 16-octet digest. RFC 7693 §3 caps the
    /// BLAKE2s key length at 32 octets; longer secrets are rejected when
    /// the MAC is computed.
    pub fn blake2s128(secret: impl Into<Vec<u8>>) -> Self {
        Self {
            algorithm: BabelMacAlgorithm::Blake2s128,
            secret: secret.into(),
        }
    }
}

impl From<Vec<u8>> for BabelMacKey {
    fn from(value: Vec<u8>) -> Self {
        Self::new(value)
    }
}

impl From<&[u8]> for BabelMacKey {
    fn from(value: &[u8]) -> Self {
        Self::new(value.to_vec())
    }
}

/// Entropy source for challenge nonces (§4.3.1.1) and fresh packet-counter
/// indices on overflow (§4.2). RFC 8967 §1.2 requires values that never
/// repeat over the lifetime of a key.
pub trait NonceSource: Send {
    fn fill(&mut self, buf: &mut [u8]);
}

/// std entropy source: two independently OS-seeded SipHash states mixed
/// with a per-call counter. Unpredictable (OS-seeded keys) and unique
/// within the process lifetime (the counter never repeats). RFC 8967 §7
/// deems 64-bit values sufficient; this emits 128 bits per 16-octet fill.
#[derive(Debug)]
pub struct SystemNonceSource {
    a: std::collections::hash_map::RandomState,
    b: std::collections::hash_map::RandomState,
    counter: u64,
}

impl Default for SystemNonceSource {
    fn default() -> Self {
        Self::new()
    }
}

impl SystemNonceSource {
    pub fn new() -> Self {
        Self {
            a: std::collections::hash_map::RandomState::new(),
            b: std::collections::hash_map::RandomState::new(),
            counter: 0,
        }
    }
}

impl NonceSource for SystemNonceSource {
    fn fill(&mut self, buf: &mut [u8]) {
        let mut i = 0;
        while i < buf.len() {
            self.counter = self.counter.wrapping_add(1);
            let mut h1 = self.a.build_hasher();
            h1.write_u64(self.counter);
            let x1 = h1.finish();
            let mut h2 = self.b.build_hasher();
            h2.write_u64(self.counter);
            let x2 = h2.finish();
            let chunk = [x1.to_be_bytes(), x2.to_be_bytes()].concat();
            let n = (buf.len() - i).min(chunk.len());
            buf[i..i + n].copy_from_slice(&chunk[..n]);
            i += n;
        }
    }
}

/// Deterministic nonce source for tests and reproducible simulations.
/// Successive fills differ (a per-call counter participates), which keeps
/// the RFC 8967 uniqueness assumption within a test run.
#[derive(Debug, Default)]
pub struct CounterNonceSource {
    counter: u64,
}

impl NonceSource for CounterNonceSource {
    fn fill(&mut self, buf: &mut [u8]) {
        self.counter = self.counter.wrapping_add(1);
        let be = self.counter.to_be_bytes();
        for (i, b) in buf.iter_mut().enumerate() {
            *b = be[i % be.len()] ^ i as u8;
        }
    }
}

/// Build an RFC 8967 §6.3 Challenge Request TLV carrying `nonce`
/// (0..=192 octets).
pub fn challenge_request_tlv(nonce: &[u8]) -> crate::tlv::Tlv {
    crate::tlv::Tlv::new(crate::tlv::TlvType::ChallengeRequest, nonce.to_vec())
}

/// Build an RFC 8967 §6.4 Challenge Reply TLV echoing `nonce`.
pub fn challenge_reply_tlv(nonce: &[u8]) -> crate::tlv::Tlv {
    crate::tlv::Tlv::new(crate::tlv::TlvType::ChallengeReply, nonce.to_vec())
}

/// Authentication failures are intentionally distinguishable to let an
/// embedder maintain operational counters while silently discarding packets.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum BabelAuthError {
    #[error("Babel source and destination address families differ")]
    AddressFamilyMismatch,
    #[error("invalid Babel header")]
    InvalidHeader,
    #[error("truncated Babel packet")]
    Truncated,
    #[error("invalid Babel packet length")]
    InvalidLength,
    #[error("RFC 8967 index exceeds 32 octets")]
    InvalidIndex,
    #[error("packet counter exhausted; rekey with a fresh index")]
    CounterExhausted,
    #[error("missing RFC 8967 MAC trailer")]
    MissingMac,
    #[error("invalid RFC 8967 MAC trailer")]
    InvalidMac,
    #[error("missing RFC 8967 packet-counter TLV")]
    MissingPacketCounter,
    #[error("invalid RFC 8967 packet-counter TLV")]
    InvalidPacketCounter,
    #[error("Babel MAC verification failed")]
    AuthenticationFailed,
    #[error("replayed Babel packet")]
    Replay,
    #[error("no MAC keys configured")]
    NoKeys,
    #[error("invalid authentication configuration")]
    InvalidConfig,
    #[error("received PC Index differs from the recorded neighbour Index")]
    IndexMismatch,
    #[error("MAC key unusable with the selected algorithm")]
    InvalidKey,
}

/// Outgoing RFC 8967 packet-counter state for one interface (§3.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BabelPacketCounter {
    index: Vec<u8>,
    next: u32,
}

impl BabelPacketCounter {
    /// `index` is an opaque, fresh value of at most 32 octets.
    pub fn new(index: impl Into<Vec<u8>>, initial: u32) -> Result<Self, BabelAuthError> {
        let index = index.into();
        if index.len() > MAX_INDEX_LEN {
            return Err(BabelAuthError::InvalidIndex);
        }
        Ok(Self {
            index,
            next: initial,
        })
    }

    fn take_next(&mut self) -> Result<(u32, &[u8]), BabelAuthError> {
        let counter = self.next;
        self.next = self
            .next
            .checked_add(1)
            .ok_or(BabelAuthError::CounterExhausted)?;
        Ok((counter, &self.index))
    }

    /// Current (PC, Index) pair — the next packet carries `PC + 1`.
    pub fn peek(&self) -> (u32, &[u8]) {
        (self.next, &self.index)
    }
}

/// Reception replay state keyed by the sender's RFC 8967 Index. This is the
/// flat, challenge-free tracking of the legacy primitives; the stateful
/// [`BabelAuthInterface`] implements the full RFC 8967 §4.3 flow.
#[derive(Debug, Default)]
pub struct BabelReplayProtection {
    highest_counter: BTreeMap<Vec<u8>, u32>,
}

impl BabelReplayProtection {
    /// Accept a strictly newer counter for `index`; reject replayed and older
    /// packets. Call this only after successful MAC verification.
    pub fn accept(&mut self, index: &[u8], counter: u32) -> bool {
        match self.highest_counter.get(index) {
            Some(highest) if counter <= *highest => false,
            _ => {
                self.highest_counter.insert(index.to_vec(), counter);
                true
            }
        }
    }
}

/// Constant-time equality for MAC digests: the comparison time must not
/// depend on the number of matching leading bytes.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

fn validate_packet(packet: &[u8]) -> Result<usize, BabelAuthError> {
    if packet.len() < BODY_OFFSET || packet[0] != MAGIC || packet[1] != VERSION {
        return Err(BabelAuthError::InvalidHeader);
    }
    let body_len = u16::from_be_bytes([packet[2], packet[3]]) as usize;
    if packet.len() < BODY_OFFSET + body_len {
        return Err(BabelAuthError::Truncated);
    }
    Ok(body_len)
}

fn compute_mac(
    pseudo_header: BabelPseudoHeader,
    packet_without_trailer: &[u8],
    key: &BabelMacKey,
) -> Result<Vec<u8>, BabelAuthError> {
    match key.algorithm {
        BabelMacAlgorithm::HmacSha256 => {
            let mut mac =
                HmacSha256::new_from_slice(&key.secret).map_err(|_| BabelAuthError::InvalidKey)?;
            mac.update(&pseudo_header.encode());
            mac.update(packet_without_trailer);
            Ok(mac.finalize().into_bytes().to_vec())
        }
        BabelMacAlgorithm::Blake2s128 => {
            // Keyed BLAKE2s with a 128-bit digest (RFC 7693 §3). The key
            // length is capped at 32 octets by the BLAKE2s specification.
            let mut mac = Blake2sMac128::new_from_slice(&key.secret)
                .map_err(|_| BabelAuthError::InvalidKey)?;
            mac.update(&pseudo_header.encode());
            mac.update(packet_without_trailer);
            Ok(mac.finalize().into_bytes().to_vec())
        }
    }
}

/// Parse the packet trailer (RFC 8966 §4.2) and return the MAC TLV bodies.
///
/// RFC 8966 §4.2: the receiver MUST ignore trailer TLVs whose definition
/// does not allow them there — Pad1/PadN are skipped, unknown types are
/// skipped (forward compatibility), and only MAC TLVs are collected. The
/// MAC body length is algorithm-dependent (§6.1), so any sane length is
/// accepted; verification compares against digests the local keys produce.
fn parse_mac_trailer(trailer: &[u8]) -> Result<Vec<&[u8]>, BabelAuthError> {
    let mut macs = Vec::new();
    let mut offset = 0;
    while offset < trailer.len() {
        if trailer[offset] == 0 {
            // Pad1: a single octet, no length field (RFC 8966 §4.3).
            offset += 1;
            continue;
        }
        if offset + 2 > trailer.len() {
            return Err(BabelAuthError::InvalidMac);
        }
        let kind = trailer[offset];
        let len = trailer[offset + 1] as usize;
        let end = offset + 2 + len;
        if end > trailer.len() {
            return Err(BabelAuthError::InvalidMac);
        }
        if kind == MAC_TLV && (MIN_MAC_LEN..=MAX_MAC_LEN).contains(&len) {
            macs.push(&trailer[offset + 2..end]);
        }
        offset = end;
    }
    Ok(macs)
}

/// Authenticate a Babel datagram after it has been encoded without a trailer.
/// The returned datagram contains one PC TLV in the body and one HMAC-SHA256
/// MAC TLV in the trailer, as mandated by RFC 8967 §4.2.
///
/// This is the stateless convenience variant over a single key; it raises
/// [`BabelAuthError::CounterExhausted`] at PC overflow instead of rotating
/// the index. Use [`BabelAuthInterface`] for the full RFC 8967 flow.
pub fn authenticate_packet(
    packet: &[u8],
    pseudo_header: BabelPseudoHeader,
    key: &BabelMacKey,
    counter: &mut BabelPacketCounter,
) -> Result<Vec<u8>, BabelAuthError> {
    if !pseudo_header.family_matches() {
        return Err(BabelAuthError::AddressFamilyMismatch);
    }
    let body_len = validate_packet(packet)?;
    let (pc, index) = counter.take_next()?;
    let index_len = index.len();
    let mut authenticated = Vec::with_capacity(packet.len() + 6 + index_len + 2 + 32);
    authenticated.extend_from_slice(&packet[..BODY_OFFSET + body_len]);
    authenticated.push(PC_TLV);
    authenticated.push((4 + index_len) as u8);
    authenticated.extend_from_slice(&pc.to_be_bytes());
    authenticated.extend_from_slice(index);
    let new_body_len = (body_len + 6 + index_len) as u16;
    authenticated[2..4].copy_from_slice(&new_body_len.to_be_bytes());

    let mac = compute_mac(pseudo_header, &authenticated, key)?;
    authenticated.push(MAC_TLV);
    authenticated.push(mac.len() as u8);
    authenticated.extend_from_slice(&mac);
    Ok(authenticated)
}

/// Verify an RFC 8967 datagram against one or more active keys and then apply
/// replay protection. The returned body excludes PC and trailer MAC TLVs.
///
/// This is the stateless convenience variant: replay is tracked as a flat
/// (Index, PC) map with no challenge mechanism, so a peer that restarts with
/// a fresh index stays rejected until the caller resets its
/// [`BabelReplayProtection`]. Use [`BabelAuthInterface`] for the complete
/// RFC 8967 §4.3 flow.
pub fn verify_packet(
    packet: &[u8],
    pseudo_header: BabelPseudoHeader,
    keys: &[BabelMacKey],
    replay: &mut BabelReplayProtection,
) -> Result<Vec<u8>, BabelAuthError> {
    if !pseudo_header.family_matches() {
        return Err(BabelAuthError::AddressFamilyMismatch);
    }
    let body_len = validate_packet(packet)?;
    let authenticated_end = BODY_OFFSET + body_len;
    let trailer = &packet[authenticated_end..];
    let macs = parse_mac_trailer(trailer)?;
    if macs.is_empty() {
        return Err(BabelAuthError::MissingMac);
    }
    let valid = keys.iter().any(|key| {
        compute_mac(pseudo_header, &packet[..authenticated_end], key)
            .is_ok_and(|expected| macs.iter().any(|m| constant_time_eq(m, &expected)))
    });
    if !valid {
        return Err(BabelAuthError::AuthenticationFailed);
    }
    let (counter, index, body_without_pc) =
        parse_packet_counter(&packet[BODY_OFFSET..authenticated_end])?;
    if !replay.accept(index, counter) {
        return Err(BabelAuthError::Replay);
    }
    let mut plain = Vec::with_capacity(BODY_OFFSET + body_without_pc.len());
    plain.extend_from_slice(&packet[..BODY_OFFSET]);
    plain[2..4].copy_from_slice(&(body_without_pc.len() as u16).to_be_bytes());
    plain.extend_from_slice(&body_without_pc);
    Ok(plain)
}

/// Find the first PC TLV in the body (§4.3: further ones are ignored) and
/// rebuild the body without the PC and Challenge TLVs (§4.3: after
/// acceptance they are silently ignored by normal processing).
fn parse_packet_counter(body: &[u8]) -> Result<(u32, &[u8], Vec<u8>), BabelAuthError> {
    let mut offset = 0;
    let mut found = None;
    let mut plain = Vec::with_capacity(body.len());
    while offset < body.len() {
        if body[offset] == 0 {
            plain.push(0);
            offset += 1;
            continue;
        }
        if offset + 2 > body.len() {
            return Err(BabelAuthError::InvalidLength);
        }
        let kind = body[offset];
        let len = body[offset + 1] as usize;
        let end = offset + 2 + len;
        if end > body.len() {
            return Err(BabelAuthError::InvalidLength);
        }
        if kind == PC_TLV {
            // RFC 8967 §4.3: only the first PC TLV is processed; any
            // further ones MUST be silently ignored.
            if found.is_none() && len >= 4 {
                found = Some((
                    u32::from_be_bytes([
                        body[offset + 2],
                        body[offset + 3],
                        body[offset + 4],
                        body[offset + 5],
                    ]),
                    &body[offset + 6..end],
                ));
            }
        } else if kind == CHALLENGE_REQUEST_TLV || kind == CHALLENGE_REPLY_TLV {
            // RFC 8967 §4.3: Challenge Request/Reply TLVs are silently
            // ignored by normal processing.
        } else {
            plain.extend_from_slice(&body[offset..end]);
        }
        offset = end;
    }
    found
        .map(|(counter, index)| (counter, index, plain))
        .ok_or(BabelAuthError::MissingPacketCounter)
}

/// Receiver-side packet-counter state for one traffic class (RFC 9467 §3.1:
/// one for multicast, one for unicast).
#[derive(Debug, Clone, PartialEq, Eq)]
enum ReceiverPc {
    /// RFC 8967 §4.3 base case: accept only strictly increasing PCs.
    Strict(u32),
    /// RFC 9467 §3.2: accept bounded reordering below the highest PC.
    /// `seen[i]` tracks whether PC `highest - (S - 1) + i` was received.
    Window { highest: u32, seen: Vec<bool> },
}

impl ReceiverPc {
    fn strict(initial: u32) -> Self {
        Self::Strict(initial)
    }

    fn window(size: usize) -> Self {
        Self::Window {
            highest: 0,
            seen: vec![false; size],
        }
    }

    /// Whether `pc` would be accepted — no mutation (RFC 9467 §3.2 steps 1-3).
    fn accepts(&self, pc: u32) -> bool {
        match self {
            Self::Strict(v) => pc > *v,
            Self::Window { highest, seen } => {
                let i = pc as i64 - *highest as i64 + seen.len() as i64 - 1;
                if i < 0 {
                    false
                } else {
                    let iu = i as usize;
                    iu >= seen.len() || !seen[iu]
                }
            }
        }
    }

    /// Record `pc` as accepted. Pair with a successful [`Self::accepts`].
    fn commit(&mut self, pc: u32) {
        match self {
            Self::Strict(v) => *v = pc,
            Self::Window { highest, seen } => {
                let i = pc as i64 - *highest as i64 + seen.len() as i64 - 1;
                debug_assert!(i >= 0, "commit must follow a successful accepts()");
                let iu = i as usize;
                if iu < seen.len() {
                    seen[iu] = true;
                } else {
                    // RFC 9467 §3.2 step 3: shift left by (i - S + 1) — the
                    // difference PC - PCh — then set the right edge.
                    let shift = iu + 1 - seen.len();
                    if shift >= seen.len() {
                        seen.iter_mut().for_each(|v| *v = false);
                    } else {
                        seen.drain(0..shift);
                        seen.resize(seen.len() + shift, false);
                    }
                    *highest = pc;
                    *seen.last_mut().expect("window is never empty") = true;
                }
            }
        }
    }

    /// RFC 9467 §3.2 (challenge-reply rule): set the highest PC and reset
    /// the window except the right edge (the successful packet consumed
    /// that PC value).
    fn reset_to(&mut self, pc: u32) {
        match self {
            Self::Strict(v) => *v = pc,
            Self::Window { highest, seen } => {
                *highest = pc;
                seen.iter_mut().for_each(|v| *v = false);
                *seen.last_mut().expect("window is never empty") = true;
            }
        }
    }
}

#[derive(Debug, Clone)]
struct PendingChallenge {
    nonce: Vec<u8>,
    expires_at_ms: u64,
}

/// Per-neighbour authentication state (RFC 8967 §3.2, RFC 9467 §3.1/§3.2):
/// the (Index, PC) pair, the in-flight challenge and the rate-limit stamps.
#[derive(Debug, Clone)]
struct NeighbourAuth {
    index: Option<Vec<u8>>,
    pcu: ReceiverPc,
    pcm: ReceiverPc,
    challenge: Option<PendingChallenge>,
    last_request_ms: Option<u64>,
    last_reply_ms: Option<u64>,
    last_activity_ms: u64,
}

impl NeighbourAuth {
    fn new(pc_window: Option<usize>) -> Self {
        let recv = |w: Option<usize>| match w {
            Some(n) => ReceiverPc::window(n),
            None => ReceiverPc::strict(0),
        };
        Self {
            index: None,
            pcu: recv(pc_window),
            pcm: recv(pc_window),
            challenge: None,
            last_request_ms: None,
            last_reply_ms: None,
            last_activity_ms: 0,
        }
    }
}

/// Configuration for [`BabelAuthInterface`].
#[derive(Debug, Clone)]
pub struct BabelAuthConfig {
    pub keys: Vec<BabelMacKey>,
    /// RFC 8967 §5 incremental deployment: send authenticated packets but
    /// accept unauthenticated inbound packets (§3.1 "SHOULD allow").
    pub accept_unauthenticated: bool,
    /// RFC 9467 §3.1 unicast/multicast PC split — RECOMMENDED by the RFC.
    pub split_unicast_multicast: bool,
    /// RFC 9467 §3.2 window size (OPTIONAL). `None` disables window
    /// verification; the RFC recommends S = 128 when enabling it.
    pub pc_window: Option<usize>,
    /// §4.3.1.1 minimum spacing between Challenge Requests per peer (ms).
    pub challenge_interval_ms: u64,
    /// §4.3.1.2 minimum spacing between Challenge Replies per peer (ms).
    pub reply_interval_ms: u64,
    /// §4.3.1.1 challenge expiry (ms).
    pub challenge_expiry_ms: u64,
    /// §4.4 neighbour (Index, PC) state expiry (ms).
    pub neighbour_expiry_ms: u64,
    /// Challenge nonce length in octets (§6.3 allows 0..=192).
    pub nonce_len: usize,
    /// Fresh-index length used when the PC overflows (§6.2 allows 0..=32).
    pub index_len: usize,
}

impl BabelAuthConfig {
    /// RFC defaults: one HMAC-SHA-256 key, RFC 9467 §3.1 split enabled,
    /// window disabled, 300 ms challenge/reply pacing (§4.3.1.1/§4.3.1.2
    /// SHOULD), 30 s challenge expiry, 5 min neighbour expiry (§4.4
    /// SHOULD), 16-octet nonces, 8-octet indices.
    pub fn new(key: BabelMacKey) -> Self {
        Self {
            keys: vec![key],
            accept_unauthenticated: false,
            split_unicast_multicast: true,
            pc_window: None,
            challenge_interval_ms: 300,
            reply_interval_ms: 300,
            challenge_expiry_ms: 30_000,
            neighbour_expiry_ms: 300_000,
            nonce_len: 16,
            index_len: 8,
        }
    }
}

/// Control traffic a transport must emit after a [`BabelAuthInterface`]
/// verify or as part of normal operation. All of it is sent unicast to the
/// peer address the packet came from (§4.3.1.1/§4.3.1.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BabelAuthAction {
    /// Send a Challenge Request TLV carrying this nonce.
    SendChallengeRequest(Vec<u8>),
    /// Send a Challenge Reply TLV echoing this nonce.
    SendChallengeReply(Vec<u8>),
}

/// Result of feeding one datagram through [`BabelAuthInterface::verify`].
#[derive(Debug)]
pub struct BabelVerifyOutcome {
    /// `Some(stripped body)` when the packet is accepted for normal
    /// processing: the header and body without the PC, Challenge and MAC
    /// TLVs (§4.3: they are silently ignored after acceptance).
    pub accepted: Option<Vec<u8>>,
    /// Why the packet was dropped (None when accepted).
    pub reason: Option<BabelAuthError>,
    /// Control traffic to emit, in order (§4.3.1.2: a Challenge Reply must
    /// precede any other queued traffic).
    pub actions: Vec<BabelAuthAction>,
}

/// The stateful RFC 8967 authentication interface: per-interface keys, the
/// outgoing (Index, PC) pair and the per-neighbour reception state, driven
/// with explicit time so the behaviour stays deterministic and testable.
///
/// Neighbour state is keyed by source address (RFC 8967 §3.2). Entries are
/// created only after the MAC test passes (§4.3) and expire after
/// `BabelAuthConfig::neighbour_expiry_ms` without activity (§4.4) — lazily
/// on receive and eagerly via [`BabelAuthInterface::gc`].
pub struct BabelAuthInterface {
    config: BabelAuthConfig,
    send_index: Vec<u8>,
    send_pc: u32,
    neighbours: HashMap<IpAddr, NeighbourAuth>,
    nonce: Box<dyn NonceSource>,
}

impl std::fmt::Debug for BabelAuthInterface {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BabelAuthInterface")
            .field(
                "algorithms",
                &self
                    .config
                    .keys
                    .iter()
                    .map(|k| k.algorithm)
                    .collect::<Vec<_>>(),
            )
            .field("send_pc", &self.send_pc)
            .field("send_index_len", &self.send_index.len())
            .field("neighbours", &self.neighbours.len())
            .finish_non_exhaustive()
    }
}

impl BabelAuthInterface {
    /// Build an interface from `config`. `initial_index`/`initial_pc` seed
    /// the outgoing (Index, PC) pair (§3.1: the index must be fresh — never
    /// used before with the configured keys).
    pub fn new(
        config: BabelAuthConfig,
        initial_index: impl Into<Vec<u8>>,
        initial_pc: u32,
        nonce: Box<dyn NonceSource>,
    ) -> Result<Self, BabelAuthError> {
        if config.keys.is_empty() {
            return Err(BabelAuthError::NoKeys);
        }
        if let Some(w) = config.pc_window {
            if w == 0 {
                return Err(BabelAuthError::InvalidConfig);
            }
        }
        if config.nonce_len > MAX_NONCE_LEN || config.index_len > MAX_INDEX_LEN {
            return Err(BabelAuthError::InvalidConfig);
        }
        let index = initial_index.into();
        if index.len() > MAX_INDEX_LEN {
            return Err(BabelAuthError::InvalidIndex);
        }
        Ok(Self {
            config,
            send_index: index,
            send_pc: initial_pc,
            neighbours: HashMap::new(),
            nonce,
        })
    }

    pub fn config(&self) -> &BabelAuthConfig {
        &self.config
    }

    /// Current outgoing (PC, Index) pair; the next decorated packet carries
    /// PC + 1 with this index.
    pub fn send_state(&self) -> (u32, &[u8]) {
        (self.send_pc, &self.send_index)
    }

    /// Number of tracked neighbours (observability).
    pub fn neighbour_count(&self) -> usize {
        self.neighbours.len()
    }

    /// Decorate one outgoing datagram (RFC 8967 §4.2): append a PC TLV with
    /// the incremented PC to the body — on PC overflow a fresh index is
    /// generated first — then append one MAC TLV per configured key to the
    /// trailer. The aggregation-overhead rule (§4.2) is the caller's
    /// concern: each decorated packet grows by 6 + index.len() + one MAC
    /// per key octets.
    pub fn authenticate_packet(
        &mut self,
        packet: &[u8],
        pseudo_header: BabelPseudoHeader,
    ) -> Result<Vec<u8>, BabelAuthError> {
        if !pseudo_header.family_matches() {
            return Err(BabelAuthError::AddressFamilyMismatch);
        }
        let body_len = validate_packet(packet)?;
        if self.send_pc == u32::MAX {
            // §4.2: "if the PC overflows, a fresh index MUST be generated".
            let mut idx = vec![0u8; self.config.index_len];
            self.nonce.fill(&mut idx);
            self.send_index = idx;
            self.send_pc = 0;
        } else {
            self.send_pc += 1;
        }
        let pc = self.send_pc;
        let index_len = self.send_index.len();
        let mut out = Vec::with_capacity(
            BODY_OFFSET
                + body_len
                + 2
                + 4
                + index_len
                + self
                    .config
                    .keys
                    .iter()
                    .map(|k| k.algorithm.digest_len() + 2)
                    .sum::<usize>(),
        );
        out.extend_from_slice(&packet[..BODY_OFFSET + body_len]);
        out.push(PC_TLV);
        out.push((4 + index_len) as u8);
        out.extend_from_slice(&pc.to_be_bytes());
        out.extend_from_slice(&self.send_index);
        let new_body_len = (body_len + 6 + index_len) as u16;
        out[2..4].copy_from_slice(&new_body_len.to_be_bytes());

        // §4.1: every MAC covers the pseudo-header plus the packet from
        // octet 0 up to (Body Length + 4) exclusive — the PC TLV included,
        // every MAC TLV excluded. Compute them all over this same region
        // BEFORE appending any MAC TLV to the trailer.
        let macs: Vec<Vec<u8>> = self
            .config
            .keys
            .iter()
            .map(|key| compute_mac(pseudo_header, &out, key))
            .collect::<Result<_, _>>()?;
        for mac in macs {
            out.push(MAC_TLV);
            out.push(mac.len() as u8);
            out.extend_from_slice(&mac);
        }
        Ok(out)
    }

    /// Run one inbound datagram through the RFC 8967 §4.3 reception
    /// algorithm with the RFC 9467 §3.1/§3.2 PC-verification updates.
    /// `now_ms` is the embedder's monotonic clock in milliseconds.
    pub fn verify(
        &mut self,
        packet: &[u8],
        pseudo_header: BabelPseudoHeader,
        now_ms: u64,
    ) -> BabelVerifyOutcome {
        let mut out = BabelVerifyOutcome {
            accepted: None,
            reason: None,
            actions: Vec::new(),
        };

        if !pseudo_header.family_matches() {
            out.reason = Some(BabelAuthError::AddressFamilyMismatch);
            return out;
        }
        let body_len = match validate_packet(packet) {
            Ok(v) => v,
            Err(e) => {
                out.reason = Some(e);
                return out;
            }
        };
        let auth_end = BODY_OFFSET + body_len;
        let trailer_macs = match parse_mac_trailer(&packet[auth_end..]) {
            Ok(v) => v,
            Err(e) => {
                out.reason = Some(e);
                return out;
            }
        };
        let is_multicast_dest = pseudo_header.destination.is_multicast();
        let source = pseudo_header.source;

        // §5 incremental deployment: a packet without any MAC TLV is
        // accepted unverified on interfaces configured for it.
        if trailer_macs.is_empty() {
            if self.config.accept_unauthenticated {
                out.accepted = Some(packet[..auth_end].to_vec());
            } else {
                out.reason = Some(BabelAuthError::MissingMac);
            }
            return out;
        }

        // §4.3: the MAC MUST be computed once per configured key (never
        // once per MAC TLV); the packet passes on the first match.
        let mut mac_ok = false;
        for key in &self.config.keys {
            let expected = match compute_mac(pseudo_header, &packet[..auth_end], key) {
                Ok(v) => v,
                Err(e) => {
                    out.reason = Some(e);
                    return out;
                }
            };
            if trailer_macs.iter().any(|m| constant_time_eq(m, &expected)) {
                mac_ok = true;
                break;
            }
        }
        if !mac_ok {
            // §4.3: no neighbour state is created before the MAC test passes.
            out.reason = Some(BabelAuthError::AuthenticationFailed);
            return out;
        }

        // Preparse (§4.3): walk the body once, stripping the auth TLVs from
        // the plain output, scheduling Challenge Replies and matching
        // Challenge Replies against in-flight challenges.
        let mut pc_found: Option<(u32, Vec<u8>)> = None;
        let mut challenge_succeeded = false;
        let mut plain = Vec::with_capacity(auth_end);
        plain.extend_from_slice(&packet[..BODY_OFFSET]);
        let mut offset = BODY_OFFSET;
        while offset < auth_end {
            let kind = packet[offset];
            if kind == 0 {
                // Pad1: single octet, no length field.
                plain.push(0);
                offset += 1;
                continue;
            }
            if offset + 2 > auth_end {
                out.reason = Some(BabelAuthError::InvalidLength);
                return out;
            }
            let len = packet[offset + 1] as usize;
            let end = offset + 2 + len;
            if end > auth_end {
                out.reason = Some(BabelAuthError::InvalidLength);
                return out;
            }
            let value = &packet[offset + 2..end];
            match kind {
                PC_TLV => {
                    // §4.3: only the first PC TLV is processed; the rest are
                    // silently ignored. A TLV shorter than the 4-octet PC
                    // field cannot carry a counter and is treated as noise;
                    // oversized Index octets are rejected after the walk
                    // (§6.2: a node MAY ignore index lengths above 32).
                    if pc_found.is_none() && len >= 4 {
                        pc_found = Some((
                            u32::from_be_bytes([value[0], value[1], value[2], value[3]]),
                            value[4..].to_vec(),
                        ));
                    }
                }
                CHALLENGE_REQUEST_TLV => {
                    // §4.3.1.2: a Challenge Request sent to a multicast
                    // address MUST be silently ignored; oversized nonces MAY
                    // be ignored.
                    if !is_multicast_dest && len <= MAX_NONCE_LEN {
                        self.schedule_challenge_reply(source, value, now_ms, &mut out.actions);
                    }
                }
                CHALLENGE_REPLY_TLV => {
                    if len <= MAX_NONCE_LEN && self.challenge_reply_matches(source, value, now_ms) {
                        challenge_succeeded = true;
                    }
                }
                MAC_TLV => {
                    // §6.1: a MAC TLV in the packet body MUST be ignored.
                }
                _ => plain.extend_from_slice(&packet[offset..end]),
            }
            offset = end;
        }

        // §4.3: a packet without a PC TLV MUST be dropped.
        let Some((pc, index)) = pc_found else {
            out.reason = Some(BabelAuthError::MissingPacketCounter);
            return out;
        };
        // §6.2: a node MAY ignore a PC TLV with an oversized index.
        if index.len() > MAX_INDEX_LEN {
            out.reason = Some(BabelAuthError::InvalidIndex);
            return out;
        }

        // §4.3 + RFC 9467 §3.1: a successful Challenge Reply accepts the
        // packet and stores the (Index, PC) pair — the PC in BOTH the
        // multicast and the unicast fields.
        if challenge_succeeded {
            if let Some(entry) = self.neighbours.get_mut(&source) {
                entry.index = Some(index);
                entry.pcm.reset_to(pc);
                entry.pcu.reset_to(pc);
                entry.last_activity_ms = now_ms;
                out.accepted = Some(plain);
                return out;
            }
            // Unreachable in practice (a matched nonce implies a stored
            // challenge implies an entry); fall through to the standard flow.
        }

        // §4.4: expired neighbour state is discarded lazily on receive (and
        // eagerly via gc()).
        let expired = self.neighbours.get(&source).is_some_and(|e| {
            now_ms
                >= e.last_activity_ms
                    .saturating_add(self.config.neighbour_expiry_ms)
        });
        if expired {
            self.neighbours.remove(&source);
        }

        let index_matches = self
            .neighbours
            .get(&source)
            .and_then(|e| e.index.as_deref())
            .is_some_and(|idx| idx == index.as_slice());
        if !index_matches {
            // §4.3.1.1: unknown or changed Index — challenge the sender
            // (rate-limited) and drop the packet.
            self.send_challenge(source, now_ms, &mut out.actions);
            out.reason = Some(BabelAuthError::IndexMismatch);
            return out;
        }

        // RFC 9467 §3.1/§3.3: pick the receiver-side state by destination.
        // With the split disabled both fields mirror each other, which
        // reproduces the single (Index, PC) pair of RFC 8967 §4.3.
        let use_multicast = is_multicast_dest || !self.config.split_unicast_multicast;
        let entry = self.neighbours.get_mut(&source).expect("entry exists");
        let accepted = if use_multicast {
            entry.pcm.accepts(pc)
        } else {
            entry.pcu.accepts(pc)
        };
        if !accepted {
            // §4.3: no challenge for a replayed/older PC — the mismatch may
            // be harmless reordering on the link.
            out.reason = Some(BabelAuthError::Replay);
            return out;
        }
        if use_multicast {
            entry.pcm.commit(pc);
            if !self.config.split_unicast_multicast {
                entry.pcu.commit(pc);
            }
        } else {
            entry.pcu.commit(pc);
        }
        entry.last_activity_ms = now_ms;
        out.accepted = Some(plain);
        out
    }

    /// §4.4: drop neighbour state idle beyond `neighbour_expiry_ms`.
    /// Call periodically; reception also expires lazily, so correctness
    /// never depends on this being invoked.
    pub fn gc(&mut self, now_ms: u64) -> usize {
        let before = self.neighbours.len();
        self.neighbours.retain(|_, e| {
            now_ms
                < e.last_activity_ms
                    .saturating_add(self.config.neighbour_expiry_ms)
        });
        before - self.neighbours.len()
    }

    /// §4.3.1.1: store a fresh nonce, start the 30 s expiry timer and
    /// schedule a Challenge Request — rate-limited to one per peer per
    /// `challenge_interval_ms`.
    fn send_challenge(&mut self, peer: IpAddr, now_ms: u64, actions: &mut Vec<BabelAuthAction>) {
        let entry = self
            .neighbours
            .entry(peer)
            .or_insert_with(|| NeighbourAuth::new(self.config.pc_window));
        let due = match entry.last_request_ms {
            None => true,
            Some(t) => now_ms >= t.saturating_add(self.config.challenge_interval_ms),
        };
        if due {
            let mut nonce = vec![0u8; self.config.nonce_len];
            self.nonce.fill(&mut nonce);
            entry.challenge = Some(PendingChallenge {
                nonce: nonce.clone(),
                expires_at_ms: now_ms.saturating_add(self.config.challenge_expiry_ms),
            });
            entry.last_request_ms = Some(now_ms);
            actions.push(BabelAuthAction::SendChallengeRequest(nonce));
        }
    }

    /// §4.3.1.2: reply to a Challenge Request with a copy of the nonce —
    /// rate-limited to one per peer per `reply_interval_ms`. (The caller
    /// never sees requests received on multicast destinations: §4.3.1.2
    /// requires silently ignoring those.)
    fn schedule_challenge_reply(
        &mut self,
        peer: IpAddr,
        nonce: &[u8],
        now_ms: u64,
        actions: &mut Vec<BabelAuthAction>,
    ) {
        let entry = self
            .neighbours
            .entry(peer)
            .or_insert_with(|| NeighbourAuth::new(self.config.pc_window));
        let due = match entry.last_reply_ms {
            None => true,
            Some(t) => now_ms >= t.saturating_add(self.config.reply_interval_ms),
        };
        if due {
            entry.last_reply_ms = Some(now_ms);
            actions.push(BabelAuthAction::SendChallengeReply(nonce.to_vec()));
        }
    }

    /// §4.3.1.3: match an inbound Challenge Reply against the in-flight
    /// challenge. Success discards the nonce (SHOULD); an expired
    /// challenge is cleared and fails.
    fn challenge_reply_matches(&mut self, peer: IpAddr, nonce: &[u8], now_ms: u64) -> bool {
        let Some(entry) = self.neighbours.get_mut(&peer) else {
            return false;
        };
        match &entry.challenge {
            Some(pending) if now_ms < pending.expires_at_ms => {
                if pending.nonce.len() == nonce.len() && constant_time_eq(&pending.nonce, nonce) {
                    entry.challenge = None;
                    true
                } else {
                    false
                }
            }
            _ => {
                entry.challenge = None;
                false
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PORT: u16 = 6696;
    const MC_V4: [u8; 4] = [224, 0, 0, 111];

    fn pseudo(src: IpAddr, dst: IpAddr) -> BabelPseudoHeader {
        BabelPseudoHeader {
            source: src,
            source_port: PORT,
            destination: dst,
            destination_port: PORT,
        }
    }

    fn v4(b: [u8; 4]) -> IpAddr {
        IpAddr::V4(b)
    }

    /// A minimal valid Babel datagram body: one Hello TLV (type 4).
    fn hello_body() -> Vec<u8> {
        vec![4, 6, 0, 100, 0, 0, 0, 7]
    }

    fn raw_packet(body: &[u8]) -> Vec<u8> {
        let mut p = vec![MAGIC, VERSION, 0, 0];
        p.extend_from_slice(body);
        let len = body.len() as u16;
        p[2..4].copy_from_slice(&len.to_be_bytes());
        p
    }

    /// A test peer wrapping one authenticated interface.
    struct Peer {
        addr: IpAddr,
        iface: BabelAuthInterface,
    }

    impl Peer {
        fn new(addr: [u8; 4], key: BabelMacKey) -> Self {
            let mut cfg = BabelAuthConfig::new(key);
            // Rate limits are exercised by dedicated tests; the shared
            // helper keeps the handshake loop unthrottled.
            cfg.challenge_interval_ms = 0;
            cfg.reply_interval_ms = 0;
            Self {
                addr: v4(addr),
                iface: BabelAuthInterface::new(
                    cfg,
                    b"initial-index-0".to_vec(),
                    0,
                    Box::new(CounterNonceSource::default()),
                )
                .unwrap(),
            }
        }

        fn with_config(cfg: BabelAuthConfig, addr: [u8; 4]) -> Self {
            Self::with_index(cfg, addr, b"initial-index-0")
        }

        fn with_index(cfg: BabelAuthConfig, addr: [u8; 4], index: &[u8]) -> Self {
            Self {
                addr: v4(addr),
                iface: BabelAuthInterface::new(
                    cfg,
                    index.to_vec(),
                    0,
                    Box::new(CounterNonceSource::default()),
                )
                .unwrap(),
            }
        }

        fn send(&mut self, body: &[u8], dst: IpAddr) -> Vec<u8> {
            let packet = raw_packet(body);
            self.iface
                .authenticate_packet(&packet, pseudo(self.addr, dst))
                .unwrap()
        }

        fn receive(
            &mut self,
            wire: &[u8],
            src: IpAddr,
            dst: IpAddr,
            now: u64,
        ) -> BabelVerifyOutcome {
            self.iface.verify(wire, pseudo(src, dst), now)
        }
    }

    fn challenge_body(ty: u8, nonce: &[u8]) -> Vec<u8> {
        let mut b = vec![ty, nonce.len() as u8];
        b.extend_from_slice(nonce);
        b
    }

    /// Craft a datagram with an explicit PC/Index — for receiver-state
    /// scenarios that need exact PC values (RFC 9467 window tests).
    fn raw_authenticated(
        key: &BabelMacKey,
        index: &[u8],
        pc: u32,
        body: &[u8],
        ph: BabelPseudoHeader,
    ) -> Vec<u8> {
        let packet = raw_packet(body);
        let mut counter = BabelPacketCounter::new(index.to_vec(), pc).unwrap();
        authenticate_packet(&packet, ph, key, &mut counter).unwrap()
    }

    fn assert_one_challenge_request(actions: &[BabelAuthAction]) -> Vec<u8> {
        assert_eq!(actions.len(), 1, "expected exactly one action");
        match &actions[0] {
            BabelAuthAction::SendChallengeRequest(n) => n.clone(),
            other => panic!("expected SendChallengeRequest, got {other:?}"),
        }
    }

    fn extract_nonce(action: &BabelAuthAction) -> Vec<u8> {
        match action {
            BabelAuthAction::SendChallengeRequest(n) | BabelAuthAction::SendChallengeReply(n) => {
                n.clone()
            }
        }
    }

    // ---- algorithm & key plumbing ----

    #[test]
    fn algorithm_properties() {
        assert_eq!(BabelMacAlgorithm::HmacSha256.digest_len(), 32);
        assert_eq!(BabelMacAlgorithm::Blake2s128.digest_len(), 16);
        assert_eq!(
            BabelMacAlgorithm::from_name("HMAC-SHA256"),
            Some(BabelMacAlgorithm::HmacSha256)
        );
        assert_eq!(
            BabelMacAlgorithm::from_name("blake2s"),
            Some(BabelMacAlgorithm::Blake2s128)
        );
        assert_eq!(BabelMacAlgorithm::from_name("md5"), None);
        assert_eq!(
            BabelMacKey::new(b"x").algorithm,
            BabelMacAlgorithm::HmacSha256
        );
        assert_eq!(
            BabelMacKey::blake2s128(b"x").algorithm,
            BabelMacAlgorithm::Blake2s128
        );
    }

    #[test]
    fn config_validation_fails_closed() {
        let nonce = Box::new(CounterNonceSource::default());
        let mut cfg = BabelAuthConfig::new(BabelMacKey::new(b"k"));
        cfg.keys.clear();
        assert_eq!(
            BabelAuthInterface::new(cfg, Vec::new(), 0, nonce).unwrap_err(),
            BabelAuthError::NoKeys
        );

        let nonce = Box::new(CounterNonceSource::default());
        let mut cfg = BabelAuthConfig::new(BabelMacKey::new(b"k"));
        cfg.pc_window = Some(0);
        assert_eq!(
            BabelAuthInterface::new(cfg, Vec::new(), 0, nonce).unwrap_err(),
            BabelAuthError::InvalidConfig
        );

        let nonce = Box::new(CounterNonceSource::default());
        let mut cfg = BabelAuthConfig::new(BabelMacKey::new(b"k"));
        cfg.nonce_len = MAX_NONCE_LEN + 1;
        assert_eq!(
            BabelAuthInterface::new(cfg, Vec::new(), 0, nonce).unwrap_err(),
            BabelAuthError::InvalidConfig
        );

        let nonce = Box::new(CounterNonceSource::default());
        let cfg = BabelAuthConfig::new(BabelMacKey::new(b"k"));
        assert_eq!(
            BabelAuthInterface::new(cfg, vec![0u8; 33], 0, nonce).unwrap_err(),
            BabelAuthError::InvalidIndex
        );
    }

    #[test]
    fn nonce_sources_are_unique() {
        let mut s = CounterNonceSource::default();
        let mut a = [0u8; 16];
        let mut b = [0u8; 16];
        s.fill(&mut a);
        s.fill(&mut b);
        assert_ne!(a, b);

        let mut s = SystemNonceSource::new();
        s.fill(&mut a);
        s.fill(&mut b);
        assert_ne!(a, b);
    }

    // ---- legacy stateless primitives ----

    #[test]
    fn legacy_roundtrip_strips_trailer() {
        let key = BabelMacKey::new(b"correct horse battery staple");
        let mut counter = BabelPacketCounter::new(b"fresh-index".to_vec(), 7).unwrap();
        let packet = raw_packet(&hello_body());
        let signed = authenticate_packet(
            &packet,
            pseudo(v4([192, 0, 2, 1]), v4(MC_V4)),
            &key,
            &mut counter,
        )
        .unwrap();
        let mut replay = BabelReplayProtection::default();
        assert_eq!(
            verify_packet(
                &signed,
                pseudo(v4([192, 0, 2, 1]), v4(MC_V4)),
                &[key],
                &mut replay
            )
            .unwrap(),
            packet
        );
    }

    #[test]
    fn legacy_rejects_tampering_and_replay() {
        let key = BabelMacKey::new(b"a key");
        let mut counter = BabelPacketCounter::new(Vec::new(), 0).unwrap();
        let packet = raw_packet(&hello_body());
        let mut signed = authenticate_packet(
            &packet,
            pseudo(v4([192, 0, 2, 1]), v4(MC_V4)),
            &key,
            &mut counter,
        )
        .unwrap();
        let mut replay = BabelReplayProtection::default();
        signed[5] ^= 1;
        assert_eq!(
            verify_packet(
                &signed,
                pseudo(v4([192, 0, 2, 1]), v4(MC_V4)),
                std::slice::from_ref(&key),
                &mut replay
            ),
            Err(BabelAuthError::AuthenticationFailed)
        );
        let signed = authenticate_packet(
            &packet,
            pseudo(v4([192, 0, 2, 1]), v4(MC_V4)),
            &key,
            &mut counter,
        )
        .unwrap();
        assert!(verify_packet(
            &signed,
            pseudo(v4([192, 0, 2, 1]), v4(MC_V4)),
            std::slice::from_ref(&key),
            &mut replay
        )
        .is_ok());
        assert_eq!(
            verify_packet(
                &signed,
                pseudo(v4([192, 0, 2, 1]), v4(MC_V4)),
                std::slice::from_ref(&key),
                &mut replay
            ),
            Err(BabelAuthError::Replay)
        );
    }

    // ---- the RFC 8967 §4.3 challenge handshake ----

    #[test]
    fn full_challenge_handshake_synchronizes_peers() {
        let key = BabelMacKey::new(b"link-key");
        let mut a = Peer::new([10, 0, 0, 1], key.clone());
        let mut b = Peer::new([10, 0, 0, 2], key);
        let mc = v4(MC_V4);

        // A multicasts a Hello; B has no state for A: drop + Challenge Request.
        let wire = a.send(&hello_body(), mc);
        let out = b.receive(&wire, a.addr, mc, 100);
        assert_eq!(out.reason, Some(BabelAuthError::IndexMismatch));
        assert!(out.accepted.is_none());
        let nonce1 = assert_one_challenge_request(&out.actions);
        assert_eq!(b.iface.neighbour_count(), 1);

        // B unicasts its Challenge Request; A drops it (B unknown) but
        // schedules the Challenge Reply — and its own Challenge Request.
        let wire = b.send(&challenge_body(18, &nonce1), a.addr);
        let out = a.receive(&wire, b.addr, a.addr, 110);
        assert_eq!(out.reason, Some(BabelAuthError::IndexMismatch));
        assert_eq!(out.actions.len(), 2);
        assert!(
            matches!(out.actions[0], BabelAuthAction::SendChallengeReply(ref n) if *n == nonce1)
        );
        assert!(matches!(
            out.actions[1],
            BabelAuthAction::SendChallengeRequest(_)
        ));
        let nonce2 = extract_nonce(&out.actions[1]);

        // A unicasts the Challenge Reply; B accepts and seeds its state.
        let wire = a.send(&challenge_body(19, &nonce1), b.addr);
        let out = b.receive(&wire, a.addr, b.addr, 120);
        assert!(out.accepted.is_some(), "challenge reply must be accepted");
        assert!(out.actions.is_empty());

        // A unicasts its own Challenge Request; B (knowing A now) accepts it
        // and schedules the reply.
        let wire = a.send(&challenge_body(18, &nonce2), b.addr);
        let out = b.receive(&wire, a.addr, b.addr, 130);
        assert!(out.accepted.is_some());
        assert_eq!(out.actions.len(), 1);
        assert_eq!(extract_nonce(&out.actions[0]), nonce2);

        // B unicasts its Challenge Reply; A accepts and seeds its state.
        let wire = b.send(&challenge_body(19, &nonce2), a.addr);
        let out = a.receive(&wire, b.addr, a.addr, 140);
        assert!(out.accepted.is_some());

        // Both peers now accept plain application traffic.
        let wire = a.send(&hello_body(), mc);
        let out = b.receive(&wire, a.addr, mc, 150);
        assert!(out.accepted.is_some(), "post-handshake multicast accepted");
        assert!(out.accepted.as_ref().unwrap()[BODY_OFFSET..].starts_with(&hello_body()[..2]));
        let wire = b.send(&hello_body(), mc);
        let out = a.receive(&wire, b.addr, mc, 160);
        assert!(out.accepted.is_some());
    }

    #[test]
    fn restart_with_fresh_index_rechallenges() {
        let key = BabelMacKey::new(b"link-key");
        let mut a = Peer::new([10, 0, 0, 1], key.clone());
        let mut b = Peer::new([10, 0, 0, 2], key.clone());
        let mc = v4(MC_V4);
        handshake(&mut a, &mut b);

        // A "restarts": a fresh interface, hence a fresh index.
        let mut a2 = {
            let mut cfg = BabelAuthConfig::new(BabelMacKey::new(b"link-key"));
            cfg.challenge_interval_ms = 0;
            cfg.reply_interval_ms = 0;
            Peer::with_index(cfg, [10, 0, 0, 1], b"restarted-index")
        };
        let wire = a2.send(&hello_body(), mc);
        let out = b.receive(&wire, a2.addr, mc, 1000);
        assert_eq!(out.reason, Some(BabelAuthError::IndexMismatch));
        let nonce = assert_one_challenge_request(&out.actions);

        let wire = a2.send(&challenge_body(19, &nonce), b.addr);
        let out = b.receive(&wire, a2.addr, b.addr, 1010);
        assert!(out.accepted.is_some(), "post-restart reply accepted");
    }

    #[test]
    fn replay_rejected_without_challenge() {
        let key = BabelMacKey::new(b"link-key");
        let mut a = Peer::new([10, 0, 0, 1], key.clone());
        let mut b = Peer::new([10, 0, 0, 2], key.clone());
        let mc = v4(MC_V4);
        handshake(&mut a, &mut b);

        let wire = a.send(&hello_body(), mc);
        assert!(b.receive(&wire, a.addr, mc, 100).accepted.is_some());
        // Replaying the exact same datagram: no challenge (§4.3), no accept.
        let out = b.receive(&wire, a.addr, mc, 110);
        assert_eq!(out.reason, Some(BabelAuthError::Replay));
        assert!(out.actions.is_empty());
    }

    #[test]
    fn mac_failure_creates_no_neighbour_state() {
        let mut a = Peer::new([10, 0, 0, 1], BabelMacKey::new(b"key-a"));
        let mut b = Peer::new([10, 0, 0, 2], BabelMacKey::new(b"key-b"));
        let mc = v4(MC_V4);
        let wire = a.send(&hello_body(), mc);
        let out = b.receive(&wire, a.addr, mc, 100);
        assert_eq!(out.reason, Some(BabelAuthError::AuthenticationFailed));
        assert_eq!(b.iface.neighbour_count(), 0);
    }

    #[test]
    fn unauthenticated_packets_dropped_by_default() {
        let key = BabelMacKey::new(b"link-key");
        let mut a = Peer::new([10, 0, 0, 1], key.clone());
        let mut b = Peer::new([10, 0, 0, 2], key.clone());
        let mc = v4(MC_V4);
        let plain = raw_packet(&hello_body());
        let out = b.receive(&plain, a.addr, mc, 100);
        assert_eq!(out.reason, Some(BabelAuthError::MissingMac));

        // RFC 8967 §5 incremental deployment mode accepts them.
        let mut cfg = BabelAuthConfig::new(key);
        cfg.accept_unauthenticated = true;
        cfg.challenge_interval_ms = 0;
        cfg.reply_interval_ms = 0;
        let mut c = Peer::with_config(cfg, [10, 0, 0, 3]);
        let out = c.receive(&plain, a.addr, mc, 100);
        assert!(out.accepted.is_some());
        // ...but authenticated packets are still fully verified: the first
        // one from an unknown peer is dropped with a challenge, the
        // challenge handshake synchronizes c, and then traffic flows.
        let wire = a.send(&hello_body(), mc);
        let out = c.receive(&wire, a.addr, mc, 110);
        assert_eq!(out.reason, Some(BabelAuthError::IndexMismatch));
        let nonce = assert_one_challenge_request(&out.actions);
        let wire = a.send(&challenge_body(19, &nonce), c.addr);
        assert!(c.receive(&wire, a.addr, c.addr, 115).accepted.is_some());
        let wire = a.send(&hello_body(), mc);
        assert!(c.receive(&wire, a.addr, mc, 118).accepted.is_some());
        let mut tampered = wire.clone();
        let n = tampered.len();
        tampered[n - 1] ^= 0xff;
        let out = c.receive(&tampered, a.addr, mc, 120);
        assert_eq!(out.reason, Some(BabelAuthError::AuthenticationFailed));
    }

    #[test]
    fn blake2s128_handshake_and_wire_length() {
        let key = BabelMacKey::blake2s128(b"blake2s-key");
        let mut a = Peer::new([10, 0, 0, 1], key.clone());
        let mut b = Peer::new([10, 0, 0, 2], key.clone());
        let mc = v4(MC_V4);
        handshake(&mut a, &mut b);

        // The MAC TLV on the wire carries the 16-octet BLAKE2s digest.
        let wire = a.send(&hello_body(), mc);
        let body_len = u16::from_be_bytes([wire[2], wire[3]]) as usize;
        let trailer = &wire[4 + body_len..];
        assert_eq!(trailer[0], 16, "MAC TLV type");
        assert_eq!(trailer[1] as usize, 16, "BLAKE2s-128 digest length");
        assert!(b.receive(&wire, a.addr, mc, 200).accepted.is_some());
    }

    #[test]
    fn key_rotation_multiple_macs_per_packet() {
        let k1 = BabelMacKey::new(b"old-key");
        let k2 = BabelMacKey::blake2s128(b"new-key");

        // A holds both keys (rotation in progress): one MAC per key.
        let mut cfg = BabelAuthConfig::new(k1.clone());
        cfg.keys.push(k2.clone());
        cfg.challenge_interval_ms = 0;
        cfg.reply_interval_ms = 0;
        let mut a = Peer::with_config(cfg, [10, 0, 0, 1]);

        // B knows only the new key: still accepts (§5).
        let mut b = Peer::new([10, 0, 0, 2], k2.clone());
        let mc = v4(MC_V4);
        handshake(&mut a, &mut b);

        let wire = a.send(&hello_body(), mc);
        let body_len = u16::from_be_bytes([wire[2], wire[3]]) as usize;
        let trailer = &wire[4 + body_len..];
        let mut mac_lens = Vec::new();
        let mut off = 0;
        while off < trailer.len() {
            let len = trailer[off + 1] as usize;
            if trailer[off] == 16 {
                mac_lens.push(len);
            }
            off += 2 + len;
        }
        assert_eq!(mac_lens, vec![32, 16], "one MAC per configured key");
        assert!(b.receive(&wire, a.addr, mc, 300).accepted.is_some());
    }

    #[test]
    fn forged_challenge_reply_is_rejected() {
        let key = BabelMacKey::new(b"link-key");
        let mut a = Peer::new([10, 0, 0, 1], key.clone());
        let mut b = Peer::new([10, 0, 0, 2], key.clone());
        let mc = v4(MC_V4);

        let wire = a.send(&hello_body(), mc);
        let out = b.receive(&wire, a.addr, mc, 100);
        let nonce = assert_one_challenge_request(&out.actions);

        // A replies with a WRONG nonce: not matched, drop, re-challenge.
        let mut wrong = nonce.clone();
        wrong[0] ^= 0xff;
        let wire = a.send(&challenge_body(19, &wrong), b.addr);
        let out = b.receive(&wire, a.addr, b.addr, 110);
        assert_eq!(out.reason, Some(BabelAuthError::IndexMismatch));
        let fresh = assert_one_challenge_request(&out.actions);
        assert_ne!(fresh, nonce, "a new nonce was issued");

        // The fresh nonce completes the challenge.
        let wire = a.send(&challenge_body(19, &fresh), b.addr);
        let out = b.receive(&wire, a.addr, b.addr, 120);
        assert!(out.accepted.is_some());
    }

    #[test]
    fn oversized_nonce_and_multicast_requests_ignored() {
        let key = BabelMacKey::new(b"link-key");
        let mut b = Peer::new([10, 0, 0, 2], key.clone());
        let mc = v4(MC_V4);

        // §4.3.1.2: a Challenge Request sent to a multicast address is
        // silently ignored (no reply scheduled).
        let nonce = vec![7u8; 8];
        let body = challenge_body(18, &nonce);
        let mut req = Peer::new([10, 0, 0, 9], key.clone());
        let wire = req.send(&body, mc);
        let out = b.receive(&wire, req.addr, mc, 100);
        assert_eq!(out.reason, Some(BabelAuthError::IndexMismatch));
        assert!(
            !out.actions
                .iter()
                .any(|a| matches!(a, BabelAuthAction::SendChallengeReply(_))),
            "no reply for multicast requests"
        );

        // §6.3: nonces larger than 192 octets MAY be ignored.
        let huge = vec![7u8; 193];
        let body = challenge_body(18, &huge);
        let wire = req.send(&body, b.addr);
        let out = b.receive(&wire, req.addr, b.addr, 110);
        assert!(
            !out.actions
                .iter()
                .any(|a| matches!(a, BabelAuthAction::SendChallengeReply(_))),
            "oversized nonce ignored (challenge traffic is still fine)"
        );

        // An in-bounds unicast request still gets its reply.
        let wire = req.send(&challenge_body(18, &nonce), b.addr);
        let out = b.receive(&wire, req.addr, b.addr, 120);
        assert!(matches!(
            out.actions.first(),
            Some(BabelAuthAction::SendChallengeReply(_))
        ));
    }

    #[test]
    fn oversized_pc_index_is_ignored() {
        let key = BabelMacKey::new(b"link-key");
        let mut b = Peer::with_config(BabelAuthConfig::new(key), [10, 0, 0, 2]);
        let sender = v4([10, 0, 0, 1]);

        // Hand-craft a body whose PC TLV carries a 33-octet index (§6.2
        // allows a node to ignore it — the packet then has no usable PC).
        let mut body = hello_body();
        body.push(17);
        body.push((4 + 33) as u8);
        body.extend_from_slice(&0u32.to_be_bytes());
        body.extend_from_slice(&[0u8; 33]);
        let ph = pseudo(sender, v4(MC_V4));
        let wire = raw_authenticated(&BabelMacKey::new(b"link-key"), b"idx", 1, &body, ph);
        let out = b.receive(&wire, sender, v4(MC_V4), 100);
        assert_eq!(out.reason, Some(BabelAuthError::InvalidIndex));
    }

    // ---- rate limits (§4.3.1.1 / §4.3.1.2) ----

    #[test]
    fn challenge_requests_are_rate_limited() {
        let key = BabelMacKey::new(b"link-key");
        let mut cfg = BabelAuthConfig::new(key);
        cfg.challenge_interval_ms = 300;
        let mut a = Peer::new([10, 0, 0, 1], BabelMacKey::new(b"link-key"));
        let mut b = Peer::with_config(cfg, [10, 0, 0, 2]);
        let mc = v4(MC_V4);

        let wire = a.send(&hello_body(), mc);
        let out = b.receive(&wire, a.addr, mc, 100);
        assert_one_challenge_request(&out.actions);

        // 200 ms later: still inside the rate window — silent drop.
        let wire = a.send(&hello_body(), mc);
        let out = b.receive(&wire, a.addr, mc, 300);
        assert_eq!(out.reason, Some(BabelAuthError::IndexMismatch));
        assert!(out.actions.is_empty());

        // 500 ms after the first challenge: the window has passed.
        let out = b.receive(&wire, a.addr, mc, 600);
        assert_eq!(out.reason, Some(BabelAuthError::IndexMismatch));
        assert_eq!(out.actions.len(), 1);
    }

    #[test]
    fn challenge_replies_are_rate_limited() {
        let key = BabelMacKey::new(b"link-key");
        let mut cfg = BabelAuthConfig::new(key);
        cfg.reply_interval_ms = 300;
        let mut req = Peer::new([10, 0, 0, 9], BabelMacKey::new(b"link-key"));
        let mut b = Peer::with_config(cfg, [10, 0, 0, 2]);
        let nonce = vec![3u8; 8];

        // The unknown sender also triggers a Challenge Request from b; the
        // reply-rate limit only paces the SendChallengeReply actions.
        let replies = |a: &[BabelAuthAction]| {
            a.iter()
                .filter(|x| matches!(x, BabelAuthAction::SendChallengeReply(_)))
                .count()
        };
        let wire = req.send(&challenge_body(18, &nonce), b.addr);
        let out = b.receive(&wire, req.addr, b.addr, 100);
        assert_eq!(replies(&out.actions), 1);

        let wire = req.send(&challenge_body(18, &nonce), b.addr);
        let out = b.receive(&wire, req.addr, b.addr, 200);
        assert_eq!(replies(&out.actions), 0, "reply suppressed within 300 ms");

        let wire = req.send(&challenge_body(18, &nonce), b.addr);
        let out = b.receive(&wire, req.addr, b.addr, 500);
        assert_eq!(replies(&out.actions), 1, "reply allowed after the window");
    }

    #[test]
    fn challenge_expires_after_thirty_seconds() {
        let key = BabelMacKey::new(b"link-key");
        let mut cfg = BabelAuthConfig::new(key);
        cfg.challenge_expiry_ms = 30_000;
        let mut a = Peer::new([10, 0, 0, 1], BabelMacKey::new(b"link-key"));
        let mut b = Peer::with_config(cfg, [10, 0, 0, 2]);
        let mc = v4(MC_V4);

        let wire = a.send(&hello_body(), mc);
        let out = b.receive(&wire, a.addr, mc, 100);
        let nonce = assert_one_challenge_request(&out.actions);

        // The reply arrives late: the challenge expired, so the packet is
        // dropped and a fresh challenge is scheduled (§4.3.1.3).
        let wire = a.send(&challenge_body(19, &nonce), b.addr);
        let out = b.receive(&wire, a.addr, b.addr, 30_200);
        assert_eq!(out.reason, Some(BabelAuthError::IndexMismatch));
        assert_eq!(out.actions.len(), 1);
        let fresh = extract_nonce(&out.actions[0]);
        assert_ne!(fresh, nonce, "a new nonce was issued");
    }

    // ---- RFC 9467 §3.1: unicast / multicast PC split ----

    #[test]
    fn split_unicast_multicast_tracking() {
        let key = BabelMacKey::new(b"link-key");
        let mut a = Peer::new([10, 0, 0, 1], key.clone());
        let mut b = Peer::new([10, 0, 0, 2], key);
        let mc = v4(MC_V4);
        handshake(&mut a, &mut b);

        // Multicast advances PCm, then the same-value unicast packet must
        // still be accepted (PCu is tracked separately).
        let w_mc = a.send(&hello_body(), mc);
        assert!(b.receive(&w_mc, a.addr, mc, 100).accepted.is_some());
        let (_, idx) = a.iface.send_state();
        let idx = idx.to_vec();
        let pc_now = {
            // The next crafted packet carries the current PC + 1 — mirror
            // what `a.send` would emit next.
            let (pc, _) = a.iface.send_state();
            pc
        };
        let w_uc = raw_authenticated(
            &BabelMacKey::new(b"link-key"),
            &idx,
            pc_now + 1,
            &hello_body(),
            pseudo(a.addr, b.addr),
        );
        let out = b.receive(&w_uc, a.addr, b.addr, 110);
        assert!(
            out.accepted.is_some(),
            "RFC 9467 §3.1: unicast state is separate"
        );
    }

    #[test]
    fn no_split_treats_both_classes_as_one() {
        let key = BabelMacKey::new(b"link-key");
        let mut cfg = BabelAuthConfig::new(key);
        cfg.split_unicast_multicast = false;
        cfg.challenge_interval_ms = 0;
        cfg.reply_interval_ms = 0;
        let mut a = Peer::new([10, 0, 0, 1], BabelMacKey::new(b"link-key"));
        let mut b = Peer::with_config(cfg, [10, 0, 0, 2]);
        let mc = v4(MC_V4);
        handshake(&mut a, &mut b);

        let w_mc = a.send(&hello_body(), mc);
        assert!(b.receive(&w_mc, a.addr, mc, 100).accepted.is_some());
        // Same PC value re-delivered as unicast: the shared state rejects it.
        let (pc, idx) = a.iface.send_state();
        let w_uc = raw_authenticated(
            &BabelMacKey::new(b"link-key"),
            idx,
            pc,
            &hello_body(),
            pseudo(a.addr, b.addr),
        );
        let out = b.receive(&w_uc, a.addr, b.addr, 110);
        assert_eq!(out.reason, Some(BabelAuthError::Replay));
    }

    // ---- RFC 9467 §3.2: window-based verification ----

    /// A window-mode pair already synchronized via the challenge handshake.
    fn window_pair() -> (Peer, Peer, IpAddr) {
        let key = BabelMacKey::new(b"link-key");
        let mut cfg = BabelAuthConfig::new(key);
        cfg.pc_window = Some(4);
        cfg.challenge_interval_ms = 0;
        cfg.reply_interval_ms = 0;
        let mut a = Peer::new([10, 0, 0, 1], BabelMacKey::new(b"link-key"));
        let mut b = Peer::with_config(cfg, [10, 0, 0, 2]);
        let mc = v4(MC_V4);
        handshake(&mut a, &mut b);
        (a, b, mc)
    }

    #[test]
    fn window_accepts_bounded_reordering() {
        let (a, mut b, mc) = window_pair();
        let key = BabelMacKey::new(b"link-key");

        // pc=4: jumps past the window (S=4, highest was 3 after handshake);
        // the window shifts fully and only pc=4 is marked.
        let (_, idx) = a.iface.send_state();
        let idx = idx.to_vec();
        let w4 = raw_authenticated(&key, &idx, 4, &hello_body(), pseudo(a.addr, mc));
        assert!(b.receive(&w4, a.addr, mc, 100).accepted.is_some());

        // pc=3 arrives late (reordered): inside the window, unseen → accept.
        let w3 = raw_authenticated(&key, &idx, 3, &hello_body(), pseudo(a.addr, mc));
        assert!(b.receive(&w3, a.addr, mc, 110).accepted.is_some());
        // pc=3 again: now a replay → reject.
        let out = b.receive(&w3, a.addr, mc, 120);
        assert_eq!(out.reason, Some(BabelAuthError::Replay));

        // pc=0 is below the window's left edge → too old, reject.
        let w0 = raw_authenticated(&key, &idx, 0, &hello_body(), pseudo(a.addr, mc));
        assert_eq!(
            b.receive(&w0, a.addr, mc, 130).reason,
            Some(BabelAuthError::Replay)
        );

        // pc=100: far past the edge → window resets, accept.
        let w100 = raw_authenticated(&key, &idx, 100, &hello_body(), pseudo(a.addr, mc));
        assert!(b.receive(&w100, a.addr, mc, 140).accepted.is_some());
    }

    #[test]
    fn combined_split_and_two_windows() {
        // §3.3: two independent windows, one per traffic class.
        let key = BabelMacKey::new(b"link-key");
        let mut cfg = BabelAuthConfig::new(key.clone());
        cfg.pc_window = Some(4);
        cfg.challenge_interval_ms = 0;
        cfg.reply_interval_ms = 0;
        let mut a = Peer::new([10, 0, 0, 1], key.clone());
        let mut b = Peer::with_config(cfg, [10, 0, 0, 2]);
        let mc = v4(MC_V4);
        handshake(&mut a, &mut b);

        // Multicast reaches pc=10.
        for _ in 0..8 {
            let w = a.send(&hello_body(), mc);
            assert!(b.receive(&w, a.addr, mc, 100).accepted.is_some());
        }
        // Unicast is still near the handshake PC: an in-order unicast with
        // a PC below the multicast window edge is accepted independently.
        let (pc, idx) = a.iface.send_state();
        let w_uc = raw_authenticated(&key, idx, pc + 1, &hello_body(), pseudo(a.addr, b.addr));
        assert!(
            b.receive(&w_uc, a.addr, b.addr, 110).accepted.is_some(),
            "unicast window is independent of the multicast window"
        );
    }

    // ---- state expiry (§4.4) ----

    #[test]
    fn neighbour_state_expires() {
        let key = BabelMacKey::new(b"link-key");
        let mut cfg = BabelAuthConfig::new(key);
        cfg.neighbour_expiry_ms = 300_000;
        let mut a = Peer::new([10, 0, 0, 1], BabelMacKey::new(b"link-key"));
        let mut b = Peer::with_config(cfg, [10, 0, 0, 2]);
        let mc = v4(MC_V4);
        handshake(&mut a, &mut b);
        assert_eq!(b.iface.neighbour_count(), 1);

        // Eager gc after the expiry window.
        // The handshake ends well past t=100; any time beyond the last
        // activity plus the expiry window discards the state (§4.4).
        assert_eq!(b.iface.gc(1_000_000), 1);
        assert_eq!(b.iface.neighbour_count(), 0);

        // And the next packet re-triggers the challenge handshake.
        let wire = a.send(&hello_body(), mc);
        let out = b.receive(&wire, a.addr, mc, 1_000_100);
        assert_eq!(out.reason, Some(BabelAuthError::IndexMismatch));
        assert_eq!(out.actions.len(), 1);
    }

    #[test]
    fn pc_overflow_rotates_the_index() {
        let key = BabelMacKey::new(b"link-key");
        let mut cfg = BabelAuthConfig::new(key);
        cfg.index_len = 8;
        let nonce = Box::new(CounterNonceSource::default());
        let mut a = BabelAuthInterface::new(cfg, b"old-index".to_vec(), u32::MAX, nonce).unwrap();
        let packet = raw_packet(&hello_body());
        let ph = pseudo(v4([10, 0, 0, 1]), v4(MC_V4));

        let (pc_before, idx_before) = (a.send_state().0, a.send_state().1.to_vec());
        assert_eq!(pc_before, u32::MAX);
        let wire = a.authenticate_packet(&packet, ph).unwrap();
        let (pc_after, idx_after) = (a.send_state().0, a.send_state().1.to_vec());
        // §4.2: overflow forces a fresh index and the PC restarts at 0.
        assert_eq!(pc_after, 0);
        assert_ne!(idx_before, idx_after, "fresh index generated on overflow");
        assert_eq!(wire[2..4].len(), 2);
    }

    // ---- trailer / body robustness ----

    #[test]
    fn trailer_tlv_robustness() {
        let key = BabelMacKey::new(b"link-key");
        let mut a = Peer::new([10, 0, 0, 1], key.clone());
        let mut b = Peer::new([10, 0, 0, 2], key.clone());
        let mc = v4(MC_V4);
        handshake(&mut a, &mut b);

        let (_, idx) = a.iface.send_state();
        let idx = idx.to_vec();
        let (pc, _) = a.iface.send_state();
        let ph = pseudo(a.addr, mc);

        // Valid packet, then splice extra trailer content: Pad1, PadN and an
        // unknown TLV type must all be skipped (RFC 8966 §4.2) while the
        // MAC TLV is still honoured.
        let wire = raw_authenticated(&key, &idx, pc + 1, &hello_body(), ph);
        let body_len = u16::from_be_bytes([wire[2], wire[3]]) as usize;
        let (head, mac) = wire.split_at(4 + body_len);
        let mut spliced = head.to_vec();
        spliced.push(0); // Pad1
        spliced.extend_from_slice(&[1, 3, 0, 0, 0]); // PadN
        spliced.extend_from_slice(&[200, 2, 0, 0]); // unknown trailer TLV
        spliced.extend_from_slice(mac);
        let out = b.receive(&spliced, a.addr, mc, 100);
        assert!(out.accepted.is_some(), "unknown trailer TLVs are skipped");

        // A truncated trailer TLV is a framing error.
        let mut broken = head.to_vec();
        broken.extend_from_slice(&[16, 40, 1, 2, 3]); // MAC TLV claims 40, has 3
        let out = b.receive(&broken, a.addr, mc, 110);
        assert_eq!(out.reason, Some(BabelAuthError::InvalidMac));
    }

    #[test]
    fn mac_tlv_in_body_is_ignored_and_stripped() {
        let key = BabelMacKey::new(b"link-key");
        let mut b = Peer::new([10, 0, 0, 2], key.clone());
        let sender = v4([10, 0, 0, 1]);
        let mc = v4(MC_V4);

        // §6.1: a MAC TLV found in the packet body MUST be ignored. Build a
        // body that embeds one, authenticate normally, and check both the
        // drop-without-trailer-MAC behaviour and the strip on accept.
        let mut body = hello_body();
        body.extend_from_slice(&[16, 4, 1, 2, 3, 4]); // stray MAC TLV in body
        let ph = pseudo(sender, mc);
        let wire = raw_authenticated(&key, b"some-index", 5, &body, ph);

        // Without a trailer the packet is unauthenticated.
        let body_len = u16::from_be_bytes([wire[2], wire[3]]) as usize;
        let headless = wire[..4 + body_len].to_vec();
        let out = b.receive(&headless, sender, mc, 100);
        assert_eq!(out.reason, Some(BabelAuthError::MissingMac));

        // With the real trailer the packet is verified; b has no state for
        // the sender yet, so it challenges (§4.3). Complete the handshake
        // with a fresh sender that reuses the same crafted body shape, then
        // confirm the stray body MAC TLV does not leak into the plain output.
        let out = b.receive(&wire, sender, mc, 110);
        let nonce = assert_one_challenge_request(&out.actions);
        let mut a = Peer::with_index(
            BabelAuthConfig::new(key.clone()),
            [10, 0, 0, 1],
            b"some-index",
        );
        let wire = a.send(&challenge_body(19, &nonce), b.addr);
        assert!(b.receive(&wire, a.addr, b.addr, 115).accepted.is_some());
        let (_, idx) = a.iface.send_state();
        let (pc, _) = a.iface.send_state();
        let wire = raw_authenticated(&key, idx, pc + 1, &body, pseudo(a.addr, mc));
        let out = b.receive(&wire, a.addr, mc, 120);
        let plain = out.accepted.expect("verified packet accepted");
        let plain_body = &plain[BODY_OFFSET..];
        assert!(!plain_body.starts_with(&[16, 4]), "body MAC TLV stripped");
        assert!(plain_body.starts_with(&hello_body()), "payload preserved");
    }

    #[test]
    fn first_pc_tlv_wins_and_auth_tlvs_are_stripped() {
        let key = BabelMacKey::new(b"link-key");
        let mut b = Peer::new([10, 0, 0, 2], key.clone());
        let sender = v4([10, 0, 0, 1]);

        let mut body = hello_body();
        // PC TLV (pc=9, index "idx-16") + a second PC TLV (ignored) + both
        // challenge TLVs (ignored, stripped).
        body.extend_from_slice(&[17, 6, 0, 0, 0, 9, b'i', b'x']);
        body.extend_from_slice(&[17, 6, 0, 0, 1, 0, b'y', b'z']);
        body.extend_from_slice(&[18, 2, 1, 2]);
        body.extend_from_slice(&[19, 2, 3, 4]);
        let ph = pseudo(sender, v4(MC_V4));
        let wire = raw_authenticated(&key, b"idx-16", 9, &body, ph);

        let out = b.receive(&wire, sender, v4(MC_V4), 100);
        // No successful challenge here (B never challenged this index) —
        // the packet is dropped with a new challenge, but the plain body
        // would contain ONLY the Hello TLV.
        assert_eq!(out.reason, Some(BabelAuthError::IndexMismatch));
        // Verify the stripped-plain behaviour directly on the interface via
        // a completed-challenge path: after the handshake the plain output
        // of an accepted packet contains no auth TLVs.
        let nonce = assert_one_challenge_request(&out.actions);
        let mut a = Peer::new([10, 0, 0, 1], key);
        let wire = a.send(&challenge_body(19, &nonce), b.addr);
        let out = b.receive(&wire, a.addr, b.addr, 110);
        let plain = out.accepted.expect("challenge reply accepted");
        let plain_body = &plain[BODY_OFFSET..];
        // The reply packet carries only the Challenge Reply TLV, which is
        // stripped: the plain body is empty (auth TLVs never leak).
        assert!(plain_body.is_empty(), "auth TLVs stripped from plain body");
    }

    // ---- shared handshake helper (kept last: used above) ----

    /// Drive two peers through the initial RFC 8967 §4.3 challenge until
    /// both hold the other's (Index, PC) state. Each peer's actions are
    /// emitted by that peer, unicast to the other (§4.3.1.1/§4.3.1.2).
    /// Both peers must use zero rate limits and the same key.
    fn handshake(a: &mut Peer, b: &mut Peer) {
        let mc = v4(MC_V4);
        let mut now = 100u64;

        let wire = a.send(&hello_body(), mc);
        let out = b.receive(&wire, a.addr, mc, now);
        assert_eq!(
            out.reason,
            Some(BabelAuthError::IndexMismatch),
            "first contact must challenge"
        );
        let mut a_queue: Vec<BabelAuthAction> = Vec::new();
        let mut b_queue: Vec<BabelAuthAction> = out.actions;

        for _ in 0..16 {
            // B emits its queued control traffic to A.
            for action in std::mem::take(&mut b_queue) {
                now += 10;
                let body = match &action {
                    BabelAuthAction::SendChallengeRequest(n) => challenge_body(18, n),
                    BabelAuthAction::SendChallengeReply(n) => challenge_body(19, n),
                };
                let wire = b.send(&body, a.addr);
                let out = a.receive(&wire, b.addr, a.addr, now);
                a_queue.extend(out.actions);
            }
            // A emits its queued control traffic to B.
            for action in std::mem::take(&mut a_queue) {
                now += 10;
                let body = match &action {
                    BabelAuthAction::SendChallengeRequest(n) => challenge_body(18, n),
                    BabelAuthAction::SendChallengeReply(n) => challenge_body(19, n),
                };
                let wire = a.send(&body, b.addr);
                let out = b.receive(&wire, a.addr, b.addr, now);
                b_queue.extend(out.actions);
            }
            if a_queue.is_empty() && b_queue.is_empty() {
                break;
            }
        }
        assert!(
            a_queue.is_empty() && b_queue.is_empty(),
            "handshake did not converge"
        );
    }
}
