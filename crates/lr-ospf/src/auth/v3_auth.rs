//! RFC 7166 authentication trailer for OSPFv3.
//!
//! OSPFv3 removed the authentication fields from the header (they were
//! replaced by the Instance ID). RFC 7166 re-introduces authentication
//! by appending a trailer to every OSPFv3 packet, carried after the
//! body and NOT covered by the OSPF checksum.
//!
//! # Wire format
//!
//! ```text
//!  OSPFv3 header (24 bytes)
//!    au_type_or_instance = Instance ID (no auth field in header)
//!  OSPFv3 body
//!  Authentication trailer (RFC 7166 §2.3):
//!    +0  Security Association ID   (u32, big-endian)
//!    +4  Auth Data Len             (u16, big-endian)  — total trailer length
//!    +6  Cryptographic Sequence    (u64, big-endian)
//!   +14  Digest                    (variable, depends on algorithm)
//! ```
//!
//! The MAC is computed over:
//! 1. The IPv6 pseudo-header (source + dest + length + zero + next-header 89)
//! 2. The OSPFv3 packet (header + body) with the checksum field zeroed
//!
//! The trailer itself is NOT included in the MAC input.
//!
//! # Algorithms
//!
//! RFC 7166 references RFC 5709 for the algorithm set: HMAC-SHA-1
//! (digest 20) and HMAC-SHA-256 (digest 32). The trailer overhead is
//! 14 bytes (SA-ID + len + crypto-seq) plus the digest.

use core::fmt;

use crate::auth::crypto::CryptoAlgorithm;

/// Trailer overhead: SA-ID (4) + Auth Data Len (2) + Crypto Seq (8).
const V3_TRAILER_OVERHEAD: usize = 14;

/// OSPFv3 authentication configuration (RFC 7166).
///
/// Unlike OSPFv2's [`CryptoAuth`](super::CryptoAuth), the v3 trailer
/// uses a 64-bit cryptographic sequence number and a Security
/// Association ID instead of a Key ID. The MAC algorithm set is the
/// same (RFC 5709).
#[derive(Debug, Clone)]
pub struct V3Auth {
    /// Security Association ID (RFC 7166 §2.3). Identifies the key the
    /// receiver should use to verify the digest.
    pub sa_id: u32,
    /// Shared secret.
    pub key: Vec<u8>,
    /// MAC algorithm (HMAC-SHA-1 or HMAC-SHA-256).
    pub algorithm: CryptoAlgorithm,
    /// Monotonic 64-bit cryptographic sequence number.
    pub crypto_seq: u64,
    /// Optional IPv6 source address for the pseudo-header. The embedder
    /// sets this to the source of the OSPFv3 packet.
    pub source_v6: Option<[u8; 16]>,
    /// Optional IPv6 destination address for the pseudo-header.
    pub dest_v6: Option<[u8; 16]>,
    /// Last sequence number seen from the peer (anti-replay).
    last_peer_seq: u64,
}

impl V3Auth {
    /// Create a new v3 auth instance with HMAC-SHA-256 (the recommended
    /// default per RFC 5709 §3).
    pub fn new(sa_id: u32, key: Vec<u8>) -> Self {
        Self {
            sa_id,
            key,
            algorithm: CryptoAlgorithm::HmacSha256,
            crypto_seq: 0,
            source_v6: None,
            dest_v6: None,
            last_peer_seq: 0,
        }
    }

    /// Use HMAC-SHA-1 instead of the default SHA-256.
    pub fn with_sha1(mut self) -> Self {
        self.algorithm = CryptoAlgorithm::HmacSha1;
        self
    }

    /// Set the IPv6 source + destination addresses for the pseudo-header.
    pub fn with_addresses(mut self, source: [u8; 16], dest: [u8; 16]) -> Self {
        self.source_v6 = Some(source);
        self.dest_v6 = Some(dest);
        self
    }

    /// Advance the cryptographic sequence number for the next packet.
    pub fn advance_seq(&mut self) {
        self.crypto_seq = self.crypto_seq.wrapping_add(1);
    }

    /// The trailer length this configuration produces: 14 bytes of
    /// overhead plus the digest.
    pub fn trailer_len(&self) -> usize {
        V3_TRAILER_OVERHEAD + self.algorithm.digest_len()
    }

    /// Build the authentication trailer for an OSPFv3 packet. The trailer
    /// is appended after the OSPF body; the MAC is computed over the
    /// header + body with the checksum zeroed, plus the IPv6 pseudo-header
    /// when configured.
    ///
    /// `packet` is the full OSPFv3 packet (header + body) as it will
    /// appear on the wire (the checksum should already be computed or
    /// will be zeroed for the MAC input).
    pub fn sign_trailer(&self, packet: &[u8]) -> Vec<u8> {
        let digest = self.compute_mac(packet);
        let mut trailer = Vec::with_capacity(V3_TRAILER_OVERHEAD + digest.len());
        trailer.extend_from_slice(&self.sa_id.to_be_bytes());
        trailer.extend_from_slice(&(self.trailer_len() as u16).to_be_bytes());
        trailer.extend_from_slice(&self.crypto_seq.to_be_bytes());
        trailer.extend_from_slice(&digest);
        trailer
    }

    /// Compute the MAC over the packet, applying the IPv6 pseudo-header
    /// when configured and zeroing the checksum field (offset 12..14).
    fn compute_mac(&self, packet: &[u8]) -> Vec<u8> {
        // Zero the checksum (offset 12..14 of the OSPFv3 header).
        let mut buf = packet.to_vec();
        if buf.len() >= 14 {
            buf[12] = 0;
            buf[13] = 0;
        }

        // Prepend the IPv6 pseudo-header when configured (RFC 7166 §2.4:
        // source + dest + OSPF length (u32) + zero + next-header 89).
        if let (Some(src), Some(dst)) = (self.source_v6, self.dest_v6) {
            let ospf_len = buf.len() as u32;
            let mut full = Vec::with_capacity(40 + buf.len());
            full.extend_from_slice(&src);
            full.extend_from_slice(&dst);
            full.extend_from_slice(&ospf_len.to_be_bytes());
            full.push(0); // zero
            full.push(0);
            full.push(0); // zero
            full.push(89); // next header = OSPF
            full.extend_from_slice(&buf);
            return self.algorithm.compute_mac(&full, &self.key);
        }
        self.algorithm.compute_mac(&buf, &self.key)
    }

    /// Verify a received OSPFv3 packet's authentication trailer. Returns
    /// `true` when the MAC matches and the sequence number is strictly
    /// greater than the last-seen value (anti-replay).
    ///
    /// `packet` is the OSPFv3 packet (header + body, without the
    /// trailer); `trailer` is the appended authentication trailer.
    pub fn verify(&mut self, packet: &[u8], trailer: &[u8]) -> bool {
        if trailer.len() < V3_TRAILER_OVERHEAD {
            return false;
        }
        let sa_id = u32::from_be_bytes([trailer[0], trailer[1], trailer[2], trailer[3]]);
        if sa_id != self.sa_id {
            return false;
        }
        let auth_data_len = u16::from_be_bytes([trailer[4], trailer[5]]) as usize;
        if auth_data_len != trailer.len() {
            return false;
        }
        if auth_data_len != self.trailer_len() {
            return false;
        }
        let peer_seq = u64::from_be_bytes([
            trailer[6],
            trailer[7],
            trailer[8],
            trailer[9],
            trailer[10],
            trailer[11],
            trailer[12],
            trailer[13],
        ]);
        // Anti-replay: the sequence number must be strictly greater than
        // the last-seen value. The first packet (last_peer_seq == 0) is
        // always accepted to bootstrap the session.
        if peer_seq <= self.last_peer_seq && self.last_peer_seq != 0 {
            return false;
        }

        let expected_mac = self.compute_mac(packet);
        let received_mac = &trailer[V3_TRAILER_OVERHEAD..];
        if received_mac != expected_mac.as_slice() {
            return false;
        }
        self.last_peer_seq = peer_seq;
        true
    }
}

impl PartialEq for V3Auth {
    fn eq(&self, other: &Self) -> bool {
        self.sa_id == other.sa_id
            && self.key == other.key
            && self.algorithm == other.algorithm
            && self.crypto_seq == other.crypto_seq
            && self.source_v6 == other.source_v6
            && self.dest_v6 == other.dest_v6
    }
}

impl Eq for V3Auth {}

impl fmt::Display for V3Auth {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "ospfv3-auth(sa={}, {}, seq={})",
            self.sa_id, self.algorithm, self.crypto_seq
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_v3_packet() -> Vec<u8> {
        // A minimal 24-byte OSPFv3 header (Hello, no body).
        let mut h = vec![0u8; 24];
        h[0] = 3; // version 3
        h[1] = 1; // type = Hello
        h[2..4].copy_from_slice(&24u16.to_be_bytes()); // length
        h[4..8].copy_from_slice(&1u32.to_be_bytes()); // router id
        h[8..12].copy_from_slice(&0u32.to_be_bytes()); // area id
        h[12..14].copy_from_slice(&0u16.to_be_bytes()); // checksum (zeroed)
        h[14..16].copy_from_slice(&0u16.to_be_bytes()); // instance id
        h
    }

    #[test]
    fn sha256_trailer_length() {
        let auth = V3Auth::new(1, b"key".to_vec());
        // 14 overhead + 32 digest = 46
        assert_eq!(auth.trailer_len(), 46);
    }

    #[test]
    fn sha1_trailer_length() {
        let auth = V3Auth::new(1, b"key".to_vec()).with_sha1();
        // 14 overhead + 20 digest = 34
        assert_eq!(auth.trailer_len(), 34);
    }

    #[test]
    fn sign_and_verify_roundtrip_sha256() {
        let auth = V3Auth::new(1, b"shared-secret".to_vec());
        let packet = make_v3_packet();
        let trailer = auth.sign_trailer(&packet);
        assert_eq!(trailer.len(), 46);

        let mut verifier = V3Auth::new(1, b"shared-secret".to_vec());
        assert!(verifier.verify(&packet, &trailer), "MAC must verify");
    }

    #[test]
    fn sign_and_verify_roundtrip_sha1() {
        let auth = V3Auth::new(1, b"key".to_vec()).with_sha1();
        let packet = make_v3_packet();
        let trailer = auth.sign_trailer(&packet);
        let mut verifier = V3Auth::new(1, b"key".to_vec()).with_sha1();
        assert!(verifier.verify(&packet, &trailer));
    }

    #[test]
    fn wrong_key_rejected() {
        let auth = V3Auth::new(1, b"correct".to_vec());
        let packet = make_v3_packet();
        let trailer = auth.sign_trailer(&packet);
        let mut verifier = V3Auth::new(1, b"wrong".to_vec());
        assert!(!verifier.verify(&packet, &trailer));
    }

    #[test]
    fn replay_attack_rejected() {
        let mut auth = V3Auth::new(1, b"key".to_vec());
        auth.crypto_seq = 1000;
        let packet = make_v3_packet();
        let trailer = auth.sign_trailer(&packet);

        let mut verifier = V3Auth::new(1, b"key".to_vec());
        assert!(verifier.verify(&packet, &trailer), "first packet accepted");
        assert!(!verifier.verify(&packet, &trailer), "replay must fail");
    }

    #[test]
    fn wrong_sa_id_rejected() {
        let auth = V3Auth::new(1, b"key".to_vec());
        let packet = make_v3_packet();
        let trailer = auth.sign_trailer(&packet);
        let mut verifier = V3Auth::new(2, b"key".to_vec());
        assert!(!verifier.verify(&packet, &trailer));
    }

    #[test]
    fn pseudo_header_addresses() {
        let src = [0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let dst = [0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];
        let auth = V3Auth::new(1, b"key".to_vec()).with_addresses(src, dst);
        let packet = make_v3_packet();
        let trailer = auth.sign_trailer(&packet);

        let mut verifier = V3Auth::new(1, b"key".to_vec()).with_addresses(src, dst);
        assert!(verifier.verify(&packet, &trailer), "same addresses must verify");

        let wrong_src = [0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 9];
        let mut verifier2 = V3Auth::new(1, b"key".to_vec()).with_addresses(wrong_src, dst);
        assert!(!verifier2.verify(&packet, &trailer), "different source must fail");
    }

    #[test]
    fn algorithm_mismatch_rejected() {
        let auth = V3Auth::new(1, b"key".to_vec()); // SHA-256
        let packet = make_v3_packet();
        let trailer = auth.sign_trailer(&packet);
        let mut verifier = V3Auth::new(1, b"key".to_vec()).with_sha1();
        assert!(!verifier.verify(&packet, &trailer));
    }

    #[test]
    fn malformed_trailer_rejected() {
        let mut verifier = V3Auth::new(1, b"key".to_vec());
        assert!(!verifier.verify(&[0; 24], &[]));
        assert!(!verifier.verify(&[0; 24], &[0; 5]));
    }

    #[test]
    fn advance_seq() {
        let mut auth = V3Auth::new(1, b"key".to_vec());
        assert_eq!(auth.crypto_seq, 0);
        auth.advance_seq();
        assert_eq!(auth.crypto_seq, 1);
    }
}
