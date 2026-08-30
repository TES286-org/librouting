//! Cryptographic authentication for OSPFv2 (RFC 2328 §D.3, RFC 5709).
//!
//! OSPFv2 crypto auth ("AuType 2") appends an authentication trailer to
//! every packet. The 64-bit `auth_data` field in the header carries the
//! Key ID, the Auth Data Len and the cryptographic sequence number
//! (RFC 2328 §D.3.1); the trailer carries the same three fields plus the
//! MAC digest itself (RFC 5709 §3).
//!
//! # Wire format
//!
//! ```text
//!  OSPF header (24 bytes)
//!    au_type = 2
//!    auth_data = key_id(1) | auth_data_len(1) | crypto_seq(4) | 0(2)
//!  OSPF body
//!  Authentication trailer (RFC 5709 §3, not counted in the OSPF length):
//!    +0  Key ID            (u8)
//!    +1  Auth Data Len     (u8)  — the *digest length only* (20/32),
//!                                  never the total trailer size
//!    +2  Crypto Sequence   (u32, big-endian)
//!    +6  Digest            (variable, depends on algorithm)
//! ```
//!
//! RFC 5709 standardises two algorithms:
//! - HMAC-SHA-1 (digest length 20 bytes, trailer length 26)
//! - HMAC-SHA-256 (digest length 32 bytes, trailer length 38)
//!
//! # MAC computation (RFC 5709 §3.3)
//!
//! The MAC is **not** a plain HMAC over the packet:
//!
//! ```text
//! First-Hash  = H(Ko XOR Ipad || (OSPFv2 Packet))
//! Second-Hash = H(Ko XOR Opad || First-Hash)
//! ```
//!
//! where "(OSPFv2 Packet)" is the packet as transmitted **including the
//! Authentication Trailer with its digest field filled with Apad**
//! (`0x878FE1F3` repeated `L/4` times, `L` = digest length), and `Ko`
//! is the secret key padded/truncated to `L` octets (keys longer than
//! `L` are hashed first). This equals standard HMAC with `Ko` as the
//! key, which is how the `hmac` crate is used here.
//!
//! There is no IPv4 pseudo-header in the MAC input: neither RFC 2328
//! §D.3 nor RFC 5709 defines one, and the header is used exactly as
//! transmitted (AuType 2, the RFC 2328 §D.3.1 auth field, and the
//! computed checksum are all covered).

use core::fmt;

use crate::packet::OspfHeader;

/// HMAC-SHA-1 digest length (RFC 5709 §2.1).
pub const SHA1_DIGEST_LEN: usize = 20;
/// HMAC-SHA-256 digest length (RFC 5709 §2.2).
pub const SHA256_DIGEST_LEN: usize = 32;
/// Trailer overhead beyond the digest: Key ID (1) + Auth Data Len (1) +
/// Crypto Sequence Number (4).
const TRAILER_OVERHEAD: usize = 6;

/// The Apad value (RFC 5709 §3.3): `0x878FE1F3` repeated `L/4` times —
/// always the same length as the digest. It fills the digest field of
/// the Authentication Trailer while the MAC is computed.
fn apad(digest_len: usize) -> Vec<u8> {
    let mut v = Vec::with_capacity(digest_len);
    for _ in 0..digest_len / 4 {
        v.extend_from_slice(&0x878f_e1f3u32.to_be_bytes());
    }
    v
}

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

    /// Hash `data` with the algorithm's raw hash (used to fold keys
    /// longer than the digest length into `L` octets, RFC 5709 §3.3 (1)).
    pub(crate) fn hash(self, data: &[u8]) -> Vec<u8> {
        use sha2::Digest;
        match self {
            Self::HmacSha1 => sha1::Sha1::digest(data).to_vec(),
            Self::HmacSha256 => sha2::Sha256::digest(data).to_vec(),
        }
    }

    /// RFC 5709 §3.3: HMAC with a key prepared to `L` octets (Ko). The
    /// `hmac` crate zero-pads `Ko` to the hash block size and XORs with
    /// Ipad/Opad, which is exactly the `Ko XOR Ipad/Opad` construction.
    pub(crate) fn hmac(self, ko: &[u8], data: &[u8]) -> Vec<u8> {
        use hmac::{Hmac, Mac};
        match self {
            Self::HmacSha1 => {
                let mut mac =
                    <Hmac<sha1::Sha1> as Mac>::new_from_slice(ko).expect("HMAC accepts any key");
                mac.update(data);
                mac.finalize().into_bytes().to_vec()
            }
            Self::HmacSha256 => {
                let mut mac =
                    <Hmac<sha2::Sha256> as Mac>::new_from_slice(ko).expect("HMAC accepts any key");
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
    /// Last sequence number seen from the peer (anti-replay). Packets
    /// with a sequence number <= this are rejected; `None` until the
    /// first packet is seen (which is always accepted to bootstrap).
    last_peer_seq: Option<u32>,
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
            last_peer_seq: None,
        }
    }

    /// Use HMAC-SHA-1 instead of the default SHA-256.
    pub fn with_sha1(mut self) -> Self {
        self.algorithm = CryptoAlgorithm::HmacSha1;
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

    /// Build the authentication trailer for a packet.
    ///
    /// `header_bytes` is the 24-byte OSPF header **as it will be
    /// transmitted** — the caller must have set `au_type = 2` and the
    /// RFC 2328 §D.3.1 auth field (`key_id | auth_data_len |
    /// crypto_seq`) so the MAC input matches what a peer sees;
    /// `body_bytes` is the packet body.
    ///
    /// The MAC is computed per RFC 5709 §3.3 over the header + body plus
    /// the trailer with its digest field filled with Apad; the returned
    /// trailer carries the real digest instead.
    pub fn sign_trailer(&self, header_bytes: &[u8], body_bytes: &[u8]) -> Vec<u8> {
        let l = self.algorithm.digest_len();
        let mut mac_input = Vec::with_capacity(header_bytes.len() + body_bytes.len() + 6 + l);
        mac_input.extend_from_slice(header_bytes);
        mac_input.extend_from_slice(body_bytes);
        mac_input.push(self.key_id);
        mac_input.push(l as u8); // Auth Data Len = digest length only
        mac_input.extend_from_slice(&self.crypto_seq.to_be_bytes());
        mac_input.extend_from_slice(&apad(l));
        let digest = self.compute_mac(&mac_input);

        let mut trailer = Vec::with_capacity(TRAILER_OVERHEAD + digest.len());
        trailer.push(self.key_id);
        trailer.push(l as u8);
        trailer.extend_from_slice(&self.crypto_seq.to_be_bytes());
        trailer.extend_from_slice(&digest);
        trailer
    }

    /// Compute the RFC 5709 §3.3 MAC over the full MAC input (packet
    /// including the trailer filled with Apad).
    fn compute_mac(&self, packet_with_trailer: &[u8]) -> Vec<u8> {
        let l = self.algorithm.digest_len();
        // Ko: always L octets. Keys longer than L are folded through the
        // hash (RFC 5709 §3.3 (1)); shorter keys are zero-padded.
        let mut ko = vec![0u8; l];
        if self.key.len() > l {
            let digest = self.algorithm.hash(&self.key);
            ko.copy_from_slice(&digest[..l]);
        } else {
            ko[..self.key.len()].copy_from_slice(&self.key);
        }
        self.algorithm.hmac(&ko, packet_with_trailer)
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
        // RFC 5709 §3.1: the Auth Data Len field is the digest length
        // only — never the total trailer size.
        let auth_data_len = trailer[1] as usize;
        if auth_data_len != self.algorithm.digest_len() {
            return false;
        }
        if trailer.len() != TRAILER_OVERHEAD + auth_data_len {
            return false;
        }
        let peer_seq = u32::from_be_bytes([trailer[2], trailer[3], trailer[4], trailer[5]]);
        // Anti-replay: the sequence number must be strictly greater than
        // any sequence seen so far. The very first packet (nothing seen)
        // is always accepted to bootstrap the session — including a
        // first packet with seq 0, after which further seq-0 packets are
        // rejected (the "has seen any packet" rule, not "last != 0").
        if let Some(last) = self.last_peer_seq {
            if peer_seq <= last {
                return false;
            }
        }

        // Split the packet into header (24 bytes) + body and recompute
        // the MAC over packet + trailer filled with Apad.
        if packet.len() < OspfHeader::LEN {
            return false;
        }
        let l = self.algorithm.digest_len();
        let mut mac_input = packet.to_vec();
        mac_input.push(self.key_id);
        mac_input.push(l as u8);
        mac_input.extend_from_slice(&peer_seq.to_be_bytes());
        mac_input.extend_from_slice(&apad(l));
        let expected_mac = self.compute_mac(&mac_input);
        let received_mac = &trailer[TRAILER_OVERHEAD..];
        if received_mac != expected_mac.as_slice() {
            return false;
        }
        self.last_peer_seq = Some(peer_seq);
        true
    }
}

impl PartialEq for CryptoAuth {
    fn eq(&self, other: &Self) -> bool {
        self.key_id == other.key_id
            && self.key == other.key
            && self.algorithm == other.algorithm
            && self.crypto_seq == other.crypto_seq
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

    /// Build the RFC 2328 §D.3.1 auth field contents (key_id(1) |
    /// auth_data_len(1) | crypto_seq(4)) for a signer.
    fn auth_field(key_id: u8, digest_len: u8, seq: u32) -> u64 {
        let mut v = [0u8; 8];
        v[0] = key_id;
        v[1] = digest_len;
        v[2..6].copy_from_slice(&seq.to_be_bytes());
        u64::from_be_bytes(v)
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
    fn auth_data_len_field_is_digest_length_not_trailer_size() {
        // RFC 5709 §3.1: "with NIST SHA-256, the Authentication Data
        // Length is 32 bytes" — the digest length only.
        let auth = CryptoAuth::new(1, b"shared-secret".to_vec());
        let seq = 7u32;
        let header = make_header(2, auth_field(1, auth.algorithm.digest_len() as u8, seq));
        let body: Vec<u8> = vec![0xDE, 0xAD, 0xBE, 0xEF];
        let trailer = auth.sign_trailer(&header, &body);
        assert_eq!(trailer.len(), auth.algorithm.trailer_len(), "38 for SHA-256");
        assert_eq!(trailer[1], auth.algorithm.digest_len() as u8, "field = 32, not 38");
        // Verify against a trailer whose field were the full size.
        let mut wrong = trailer.clone();
        wrong[1] = wrong.len() as u8;
        let mut verifier = CryptoAuth::new(1, b"shared-secret".to_vec());
        assert!(!verifier.verify(&[&header[..], &body[..]].concat(), &wrong));
    }

    #[test]
    fn sign_and_verify_roundtrip_sha256() {
        let auth = CryptoAuth::new(1, b"shared-secret".to_vec());
        let header = make_header(2, auth_field(1, auth.algorithm.digest_len() as u8, 0));
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
        let header = make_header(2, auth_field(1, auth.algorithm.digest_len() as u8, 42));
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
        let header = make_header(2, auth_field(1, auth.algorithm.digest_len() as u8, 0));
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
        let header = make_header(2, auth_field(1, auth.algorithm.digest_len() as u8, 100));
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
    fn seq_zero_replay_hole_closed() {
        // A first packet with seq 0 is accepted to bootstrap; a second
        // seq-0 packet must be rejected (audit A3).
        let auth = CryptoAuth::new(1, b"key".to_vec());
        let header = make_header(2, auth_field(1, auth.algorithm.digest_len() as u8, 0));
        let body: Vec<u8> = vec![0];
        let trailer = auth.sign_trailer(&header, &body);
        let mut packet = header.clone();
        packet.extend_from_slice(&body);

        let mut verifier = CryptoAuth::new(1, b"key".to_vec());
        assert!(verifier.verify(&packet, &trailer), "first seq-0 packet accepted");
        assert!(
            !verifier.verify(&packet, &trailer),
            "replayed seq-0 packet must be rejected"
        );
    }

    #[test]
    fn wrong_key_id_rejected() {
        let auth = CryptoAuth::new(1, b"key".to_vec());
        let header = make_header(2, auth_field(1, auth.algorithm.digest_len() as u8, 0));
        let body: Vec<u8> = vec![];
        let trailer = auth.sign_trailer(&header, &body);
        let mut packet = header.clone();
        packet.extend_from_slice(&body);
        let mut verifier = CryptoAuth::new(2, b"key".to_vec()); // different key id
        assert!(!verifier.verify(&packet, &trailer));
    }

    #[test]
    fn algorithm_mismatch_rejected() {
        // Sign with SHA-256, verify with SHA-1 → digest-length mismatch.
        let auth = CryptoAuth::new(1, b"key".to_vec()); // SHA-256
        let header = make_header(2, auth_field(1, auth.algorithm.digest_len() as u8, 0));
        let body: Vec<u8> = vec![];
        let trailer = auth.sign_trailer(&header, &body);
        let mut packet = header.clone();
        packet.extend_from_slice(&body);
        let mut verifier = CryptoAuth::new(1, b"key".to_vec()).with_sha1();
        assert!(!verifier.verify(&packet, &trailer));
    }

    #[test]
    fn long_key_is_hashed_to_digest_length() {
        // RFC 5709 §3.3 (1): keys longer than L octets are folded with
        // H(K); both sides must derive the same Ko.
        let long_key = b"this-is-a-very-long-shared-secret-key-that-exceeds-thirty-two-bytes!".to_vec();
        let auth = CryptoAuth::new(1, long_key.clone());
        let header = make_header(2, auth_field(1, auth.algorithm.digest_len() as u8, 0));
        let body: Vec<u8> = vec![9, 9, 9];
        let trailer = auth.sign_trailer(&header, &body);
        let mut packet = header.clone();
        packet.extend_from_slice(&body);
        let mut verifier = CryptoAuth::new(1, long_key);
        assert!(verifier.verify(&packet, &trailer));
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
