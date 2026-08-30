//! RFC 8967 MAC authentication primitives for Babel datagrams.
//!
//! This module implements the mandatory-to-implement HMAC-SHA256 algorithm,
//! including RFC 8967 pseudo-headers, PC TLVs and MAC trailer verification.
//! Transport owners provide the IP addresses and UDP ports for each datagram.

use std::collections::BTreeMap;

use hmac::{Hmac, Mac};
use lr_core::addr::IpAddr;
use sha2::Sha256;

use crate::{BODY_OFFSET, MAGIC, VERSION};

type HmacSha256 = Hmac<Sha256>;

const MAC_TLV: u8 = 16;
const PC_TLV: u8 = 17;
const MAC_LEN: usize = 32;

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

/// One symmetric interface key. RFC 8967 permits multiple active keys to make
/// key rotation non-disruptive.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BabelMacKey(pub Vec<u8>);

impl BabelMacKey {
    pub fn new(bytes: impl Into<Vec<u8>>) -> Self {
        Self(bytes.into())
    }
}

/// Outgoing RFC 8967 packet-counter state for one interface.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BabelPacketCounter {
    index: Vec<u8>,
    next: u32,
}

impl BabelPacketCounter {
    /// `index` is an opaque, fresh value of at most 32 octets.
    pub fn new(index: impl Into<Vec<u8>>, initial: u32) -> Result<Self, BabelAuthError> {
        let index = index.into();
        if index.len() > 32 {
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
}

/// Reception replay state keyed by the sender's RFC 8967 Index.
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
}

/// Authenticate a Babel datagram after it has been encoded without a trailer.
/// The returned datagram contains one PC TLV in the body and one HMAC-SHA256
/// MAC TLV in the trailer, as mandated by RFC 8967 §4.2.
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
    let mut authenticated = Vec::with_capacity(packet.len() + 6 + index.len() + 2 + MAC_LEN);
    authenticated.extend_from_slice(&packet[..BODY_OFFSET + body_len]);
    authenticated.push(PC_TLV);
    authenticated.push((4 + index.len()) as u8);
    authenticated.extend_from_slice(&pc.to_be_bytes());
    authenticated.extend_from_slice(index);
    let new_body_len = body_len + 6 + index.len();
    authenticated[2..4].copy_from_slice(&(new_body_len as u16).to_be_bytes());

    let mac = compute_mac(pseudo_header, &authenticated, key)?;
    authenticated.push(MAC_TLV);
    authenticated.push(MAC_LEN as u8);
    authenticated.extend_from_slice(&mac);
    Ok(authenticated)
}

/// Verify an RFC 8967 datagram against one or more active keys and then apply
/// replay protection. The returned body excludes PC and trailer MAC TLVs.
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
) -> Result<[u8; MAC_LEN], BabelAuthError> {
    let mut mac = HmacSha256::new_from_slice(&key.0).map_err(|_| BabelAuthError::InvalidMac)?;
    mac.update(&pseudo_header.encode());
    mac.update(packet_without_trailer);
    Ok(mac.finalize().into_bytes().into())
}

fn parse_mac_trailer(trailer: &[u8]) -> Result<Vec<&[u8]>, BabelAuthError> {
    let mut macs = Vec::new();
    let mut offset = 0;
    while offset < trailer.len() {
        if offset + 2 > trailer.len() {
            return Err(BabelAuthError::InvalidMac);
        }
        let kind = trailer[offset];
        let len = trailer[offset + 1] as usize;
        offset += 2;
        if offset + len > trailer.len() {
            return Err(BabelAuthError::InvalidMac);
        }
        if kind != MAC_TLV || len != MAC_LEN {
            return Err(BabelAuthError::InvalidMac);
        }
        macs.push(&trailer[offset..offset + len]);
        offset += len;
    }
    if macs.is_empty() {
        Err(BabelAuthError::MissingMac)
    } else {
        Ok(macs)
    }
}

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
            if found.is_none() && (4..=36).contains(&len) {
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
        } else {
            plain.extend_from_slice(&body[offset..end]);
        }
        offset = end;
    }
    found
        .map(|(counter, index)| (counter, index, plain))
        .ok_or(BabelAuthError::MissingPacketCounter)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pseudo() -> BabelPseudoHeader {
        BabelPseudoHeader {
            source: IpAddr::V4([192, 0, 2, 1]),
            source_port: 6696,
            destination: IpAddr::V4([224, 0, 0, 111]),
            destination_port: 6696,
        }
    }

    fn packet() -> Vec<u8> {
        vec![MAGIC, VERSION, 0, 4, 4, 2, 0, 100]
    }

    #[test]
    fn authenticate_verify_and_strip_trailer() {
        let key = BabelMacKey::new(b"correct horse battery staple".to_vec());
        let mut counter = BabelPacketCounter::new(b"fresh-index".to_vec(), 7).unwrap();
        let signed = authenticate_packet(&packet(), pseudo(), &key, &mut counter).unwrap();
        let mut replay = BabelReplayProtection::default();
        assert_eq!(
            verify_packet(&signed, pseudo(), &[key], &mut replay).unwrap(),
            packet()
        );
    }

    #[test]
    fn rejects_tampering_and_replay() {
        let key = BabelMacKey::new(b"a key".to_vec());
        let mut counter = BabelPacketCounter::new(Vec::new(), 0).unwrap();
        let mut signed = authenticate_packet(&packet(), pseudo(), &key, &mut counter).unwrap();
        let mut replay = BabelReplayProtection::default();
        signed[5] ^= 1;
        assert_eq!(
            verify_packet(&signed, pseudo(), std::slice::from_ref(&key), &mut replay),
            Err(BabelAuthError::AuthenticationFailed)
        );
        let signed = authenticate_packet(&packet(), pseudo(), &key, &mut counter).unwrap();
        assert!(verify_packet(&signed, pseudo(), std::slice::from_ref(&key), &mut replay).is_ok());
        assert_eq!(
            verify_packet(&signed, pseudo(), &[key], &mut replay),
            Err(BabelAuthError::Replay)
        );
    }
}
