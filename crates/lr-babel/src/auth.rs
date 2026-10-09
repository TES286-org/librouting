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
use hmac::{Hmac, KeyInit, Mac};
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
                let body_len = (plain.len() - BODY_OFFSET) as u16;
                plain[2..4].copy_from_slice(&body_len.to_be_bytes());
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
        // The plain body lost the PC (and any stray challenge) TLVs, so the
        // header's Body Length — which covered the authenticated body — must
        // be repointed at the stripped body the codec is about to parse.
        let body_len = (plain.len() - BODY_OFFSET) as u16;
        plain[2..4].copy_from_slice(&body_len.to_be_bytes());
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
#[path = "auth_tests.rs"]
mod tests;
