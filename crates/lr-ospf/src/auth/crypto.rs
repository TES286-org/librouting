//! Cryptographic authentication for OSPFv2 (RFC 2328 §D.3, RFC 5709).
//!
//! OSPFv2 crypto auth ("AuType 2") appends an authentication trailer to
//! every packet. The 64-bit `auth_data` field in the header carries the
//! cryptographic sequence number; the trailer carries the Key ID, the
//! authentication data length and the MAC digest itself.
//!
//! # Wire format
//!
//! ```text
//!  OSPF header (24 bytes)
//!    au_type = 2
//!    auth_data = cryptographic sequence number (u64, big-endian)
//!  OSPF body
//!  Authentication trailer:
//!    +0  Key ID            (u8)
//!    +1  Auth Data Len     (u8)  — total trailer length, including digest
//!    +2  Crypto Sequence   (u32, big-endian)  — redundant with header;
//!                                               included for trailer-only verifiers
//!    +4  Digest            (variable, depends on algorithm)
//! ```
//!
//! RFC 5709 standardises two algorithms:
//! - HMAC-SHA-1 (digest length 20 bytes, trailer length 24)
//! - HMAC-SHA-256 (digest length 32 bytes, trailer length 36)
//!
//! The MAC is computed over the entire packet (header + body) with the
//! `checksum` and `auth_data` fields zeroed for the computation, then
//! appended. The trailer is NOT included in the MAC input.
//!
//! # Pseudo-header
//!
//! RFC 2328 §D.3 specifies an IPv4 pseudo-header (source address,
//! zero, protocol) prepended to the MAC input. This crate is
//! transport-independent — the embedder supplies the source address via
//! [`CryptoAuth::with_source`]; when absent the MAC is computed over the
//! packet alone (sufficient for in-process testing and for the
//! reference daemon which binds a known source).

use core::fmt;

use crate::packet::OspfHeader;

/// HMAC-SHA-1 digest length (RFC 5709 §2.1).
pub const SHA1_DIGEST_LEN: usize = 20;
/// HMAC-SHA-256 digest length (RFC 5709 §2.2).
pub const SHA256_DIGEST_LEN: usize = 32;
/// Trailer overhead beyond the digest: Key ID (1) + Auth Data Len (1) +
/// Crypto Sequence Number (4).
const TRAILER_OVERHEAD: usize = 6;

/// Crypto auth algorithm (RFC 5709 §2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CryptoAlgorithm {
    /// HMAC-SHA-1 (RFC 5709 §2.1). Digest length 20.
    HmacSha1,
    /// HMAC-SHA-256 (RFC 5709 §2.2). Digest length 32.
    HmacSha256,
}

impl CryptoAlgorithm {
    pub fn digest_len(self) -> usize {
        match self {
            Self::HmacSha1 => SHA1_DIGEST_LEN,
            Self::HmacSha256 => SHA256_DIGEST_LEN,
        }
    }

    /// The trailer length this algorithm produces: 6 bytes of overhead
    /// plus the digest.
    pub fn trailer_len(self) -> usize {
        TRAILER_OVERHEAD + self.digest_len()
    }

    /// Compute the HMAC over `data` using `key`.
    pub fn compute_mac(self, data: &[u8], key: &[u8]) -> Vec<u8> {
        match self {
            Self::HmacSha1 => {
                use hmac::{Hmac, Mac};
                let mut mac =
                    <Hmac<sha1::Sha1> as Mac>::new_from_slice(key).expect("HMAC accepts any key");
                mac.update(data);
                mac.finalize().into_bytes().to_vec()
            }
            Self::HmacSha256 => {
                use hmac::{Hmac, Mac};
                let mut mac = <Hmac<sha2::Sha256> as Mac>::new_from_slice(key)
                    .expect("HMAC accepts any key");
                mac.update(data);
                mac.finalize().into_bytes().to_vec()
            }
        }
    }
}

impl fmt::Display for CryptoAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::HmacSha1 => "hmac-sha1",
            Self::HmacSha256 => "hmac-sha256",
        })
    }
}

/// OSPFv2 cryptographic authentication configuration (RFC 2328 §D.3 /
/// RFC 5709).
///
/// One [`CryptoAuth`] carries a single Key ID + secret + algorithm; the
/// embedder rotates keys by swapping the instance on the session. The
/// cryptographic sequence number is monotonic per session and MUST be
/// advanced on every packet (RFC 2328 §D.3.2: "a non-decreasing sequence
/// number").
#[derive(Debug, Clone)]
pub struct CryptoAuth {
    /// Key ID (0..=255). Identifies which key the receiver should use to
    /// verify the digest.
    pub key_id: u8,
    /// Shared secret.
    pub key: Vec<u8>,
    /// MAC algorithm.
    pub algorithm: CryptoAlgorithm,
    /// Monotonic cryptographic sequence number. The embedder advances
    /// this; the library signs with the current value and verifies that
    /// received packets are strictly greater than the last-seen value
    /// (RFC 2328 §D.3.3 anti-replay).
    pub crypto_seq: u32,
    /// Optional IPv4 source address for the pseudo-header (RFC 2328
    /// §D.3). `None` skips the pseudo-header (sufficient for in-process
    /// testing and for the daemon which binds a known source).
    pub source: Option<[u8; 4]>,
    /// Last sequence number seen from the peer (anti-replay). Packets
    /// with a sequence number <= this are rejected.
    last_peer_seq: u32,
}

impl CryptoAuth {
    /// Create a new crypto auth instance with Key ID 1 and HMAC-SHA-256
    /// (the RFC 5709 default recommendation).
    pub fn new(key_id: u8, key: Vec<u8>) -> Self {
        Self {
            key_id,
            key,
            algorithm: CryptoAlgorithm::HmacSha256,
            crypto_seq: 0,
            source: None,
            last_peer_seq: 0,
        }
    }

    /// Use HMAC-SHA-1 instead of the default SHA-256.
    pub fn with_sha1(mut self) -> Self {
        self.algorithm = CryptoAlgorithm::HmacSha1;
        self
    }

    /// Set the IPv4 source address for the pseudo-header.
    pub fn with_source(mut self, source: [u8; 4]) -> Self {
        self.source = Some(source);
        self
    }

    /// Advance the cryptographic sequence number for the next packet.
    pub fn advance_seq(&mut self) {
        self.crypto_seq = self.crypto_seq.wrapping_add(1);
    }

    /// The AuType value this auth strategy reports (always 2 = crypto).
    pub fn au_type_value(&self) -> u16 {
        2
    }

    /// Build the authentication trailer for a packet. The trailer is
    /// appended after the OSPF body; the MAC is computed over the
    /// header + body with `checksum` and `auth_data` zeroed.
    ///
    /// `header_bytes` is the 24-byte OSPF header (already encoded with
    /// `au_type = 2` and `auth_data = crypto_seq`); `body_bytes` is the
    /// packet body. Both are borrowed immutably — the caller patches the
    /// header in place separately if needed.
    pub fn sign_trailer(&self, header_bytes: &[u8], body_bytes: &[u8]) -> Vec<u8> {
        let digest = self.compute_mac(header_bytes, body_bytes);
        let mut trailer = Vec::with_capacity(TRAILER_OVERHEAD + digest.len());
        trailer.push(self.key_id);
        trailer.push((TRAILER_OVERHEAD + digest.len()) as u8);
        trailer.extend_from_slice(&self.crypto_seq.to_be_bytes());
        trailer.extend_from_slice(&digest);
        trailer
    }

    /// Compute the MAC over the header + body, applying the pseudo-header
    /// when configured and zeroing the `checksum` + `auth_data` fields.
    fn compute_mac(&self, header_bytes: &[u8], body_bytes: &[u8]) -> Vec<u8> {
        // Zero checksum (offset 12..14) and auth_data (offset 16..24)
        // for the MAC computation (RFC 2328 §D.3.2).
        let mut buf = Vec::with_capacity(header_bytes.len() + body_bytes.len());
        buf.extend_from_slice(header_bytes);
        if buf.len() >= 24 {
            buf[12] = 0;
            buf[13] = 0;
            // auth_data is 16..24 — zero it.
            for i in 16..24 {
                buf[i] = 0;
            }
        }
        buf.extend_from_slice(body_bytes);

        // Prepend the pseudo-header when configured (RFC 2328 §D.3.2:
        // source IPv4 address + zero + OSPF protocol number 89).
        if let Some(src) = self.source {
            let mut full = Vec::with_capacity(8 + buf.len());
            full.extend_from_slice(&src);
            full.push(0); // zero pad
            full.push(89); // OSPF protocol number
            full.extend_from_slice(&buf);
            return self.algorithm.compute_mac(&full, &self.key);
        }
        self.algorithm.compute_mac(&buf, &self.key)
    }

    /// Verify a received packet's authentication trailer. Returns `true`
    /// when the MAC matches and the sequence number is strictly greater
    /// than the last-seen value (anti-replay, RFC 2328 §D.3.3).
    ///
    /// `packet` is the full OSPF packet (header + body, without the
    /// trailer); `trailer` is the appended authentication trailer.
    pub fn verify(&mut self, packet: &[u8], trailer: &[u8]) -> bool {
        if trailer.len() < TRAILER_OVERHEAD {
            return false;
        }
        let key_id = trailer[0];
        if key_id != self.key_id {
            return false;
        }
        let auth_data_len = trailer[1] as usize;
        if auth_data_len != trailer.len() {
            return false;
        }
        if auth_data_len != self.algorithm.trailer_len() {
            return false;
        }
        let peer_seq = u32::from_be_bytes([trailer[2], trailer[3], trailer[4], trailer[5]]);
        // Anti-replay: the sequence number must be strictly greater than
        // the last-seen value. The first packet (last_peer_seq == 0) is
        // always accepted to bootstrap the session.
        if peer_seq <= self.last_peer_seq && self.last_peer_seq != 0 {
            return false;
        }

        // Split the packet into header (24 bytes) + body.
        if packet.len() < OspfHeader::LEN {
            return false;
        }
        let (header, body) = packet.split_at(OspfHeader::LEN);
        let expected_mac = self.compute_mac(header, body);
        let received_mac = &trailer[TRAILER_OVERHEAD..];
        if received_mac != expected_mac.as_slice() {
            return false;
        }
        self.last_peer_seq = peer_seq;
        true
    }
}

impl PartialEq for CryptoAuth {
    fn eq(&self, other: &Self) -> bool {
        self.key_id == other.key_id
            && self.key == other.key
            && self.algorithm == other.algorithm
            && self.crypto_seq == other.crypto_seq
            && self.source == other.source
    }
}

impl Eq for CryptoAuth {}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_header(au_type: u16, auth_data: u64) -> Vec<u8> {
        let mut h = vec![0u8; 24];
        h[0] = 2; // version
        h[1] = 1; // type = Hello
        h[2..4].copy_from_slice(&24u16.to_be_bytes()); // length (header only)
        h[4..8].copy_from_slice(&1u32.to_be_bytes()); // router id
        h[8..12].copy_from_slice(&0u32.to_be_bytes()); // area id
        h[12..14].copy_from_slice(&0u16.to_be_bytes()); // checksum (zeroed)
        h[14..16].copy_from_slice(&au_type.to_be_bytes());
        h[16..24].copy_from_slice(&auth_data.to_be_bytes());
        h
    }

    #[test]
    fn sha1_digest_length() {
        assert_eq!(CryptoAlgorithm::HmacSha1.digest_len(), 20);
        assert_eq!(CryptoAlgorithm::HmacSha1.trailer_len(), 26);
    }

    #[test]
    fn sha256_digest_length() {
        assert_eq!(CryptoAlgorithm::HmacSha256.digest_len(), 32);
        assert_eq!(CryptoAlgorithm::HmacSha256.trailer_len(), 38);
    }

    #[test]
    fn sign_and_verify_roundtrip_sha256() {
        let auth = CryptoAuth::new(1, b"shared-secret".to_vec());
        let header = make_header(2, 0); // au_type=2, auth_data=0 (crypto_seq)
        let body: Vec<u8> = vec![0xDE, 0xAD, 0xBE, 0xEF];
        let trailer = auth.sign_trailer(&header, &body);
        assert_eq!(trailer.len(), auth.algorithm.trailer_len());

        // Verify: packet = header + body, trailer separate.
        let mut packet = header.clone();
        packet.extend_from_slice(&body);
        let mut verifier = CryptoAuth::new(1, b"shared-secret".to_vec());
        assert!(verifier.verify(&packet, &trailer), "MAC must verify");
    }

    #[test]
    fn sign_and_verify_roundtrip_sha1() {
        let auth = CryptoAuth::new(1, b"key".to_vec()).with_sha1();
        let header = make_header(2, 42);
        let body: Vec<u8> = vec![1, 2, 3];
        let trailer = auth.sign_trailer(&header, &body);
        let mut packet = header.clone();
        packet.extend_from_slice(&body);
        let mut verifier = CryptoAuth::new(1, b"key".to_vec()).with_sha1();
        assert!(verifier.verify(&packet, &trailer));
    }

    #[test]
    fn wrong_key_rejected() {
        let auth = CryptoAuth::new(1, b"correct-key".to_vec());
        let header = make_header(2, 0);
        let body: Vec<u8> = vec![0xAA];
        let trailer = auth.sign_trailer(&header, &body);
        let mut packet = header.clone();
        packet.extend_from_slice(&body);
        let mut verifier = CryptoAuth::new(1, b"wrong-key".to_vec());
        assert!(!verifier.verify(&packet, &trailer), "wrong key must fail");
    }

    #[test]
    fn replay_attack_rejected() {
        let mut auth = CryptoAuth::new(1, b"key".to_vec());
        auth.crypto_seq = 100;
        let header = make_header(2, 100);
        let body: Vec<u8> = vec![0];
        let trailer = auth.sign_trailer(&header, &body);
        let mut packet = header.clone();
        packet.extend_from_slice(&body);

        let mut verifier = CryptoAuth::new(1, b"key".to_vec());
        assert!(verifier.verify(&packet, &trailer), "first packet accepted");
        // Replay the same packet — same sequence number, must be rejected.
        assert!(!verifier.verify(&packet, &trailer), "replay must fail");
    }

    #[test]
    fn wrong_key_id_rejected() {
        let auth = CryptoAuth::new(1, b"key".to_vec());
        let header = make_header(2, 0);
        let body: Vec<u8> = vec![];
        let trailer = auth.sign_trailer(&header, &body);
        let mut packet = header.clone();
        packet.extend_from_slice(&body);
        let mut verifier = CryptoAuth::new(2, b"key".to_vec()); // different key id
        assert!(!verifier.verify(&packet, &trailer));
    }

    #[test]
    fn algorithm_mismatch_rejected() {
        // Sign with SHA-256, verify with SHA-1 → trailer length mismatch.
        let auth = CryptoAuth::new(1, b"key".to_vec()); // SHA-256
        let header = make_header(2, 0);
        let body: Vec<u8> = vec![];
        let trailer = auth.sign_trailer(&header, &body);
        let mut packet = header.clone();
        packet.extend_from_slice(&body);
        let mut verifier = CryptoAuth::new(1, b"key".to_vec()).with_sha1();
        assert!(!verifier.verify(&packet, &trailer));
    }

    #[test]
    fn pseudo_header_source() {
        // Sign with a source address, verify with the same source.
        let auth = CryptoAuth::new(1, b"key".to_vec()).with_source([192, 0, 2, 1]);
        let header = make_header(2, 0);
        let body: Vec<u8> = vec![0xBB];
        let trailer = auth.sign_trailer(&header, &body);
        let mut packet = header.clone();
        packet.extend_from_slice(&body);

        let mut verifier = CryptoAuth::new(1, b"key".to_vec()).with_source([192, 0, 2, 1]);
        assert!(verifier.verify(&packet, &trailer), "same source must verify");

        // Different source → different pseudo-header → MAC mismatch.
        let mut verifier2 = CryptoAuth::new(1, b"key".to_vec()).with_source([10, 0, 0, 1]);
        assert!(!verifier2.verify(&packet, &trailer), "different source must fail");
    }

    #[test]
    fn advance_seq() {
        let mut auth = CryptoAuth::new(1, b"key".to_vec());
        assert_eq!(auth.crypto_seq, 0);
        auth.advance_seq();
        assert_eq!(auth.crypto_seq, 1);
        auth.advance_seq();
        assert_eq!(auth.crypto_seq, 2);
    }

    #[test]
    fn malformed_trailer_rejected() {
        let mut verifier = CryptoAuth::new(1, b"key".to_vec());
        assert!(!verifier.verify(&[0; 24], &[]), "empty trailer");
        assert!(!verifier.verify(&[0; 24], &[1]), "truncated trailer");
    }
}
