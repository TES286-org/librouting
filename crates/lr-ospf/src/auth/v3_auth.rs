//! RFC 7166 authentication trailer for OSPFv3.
//!
//! OSPFv3 removed the authentication fields from the header (they were
//! replaced by the Instance ID). RFC 7166 re-introduces authentication
//! by appending a trailer to every OSPFv3 packet, carried after the
//! body (and after the optional LLS data block) and NOT covered by the
//! OSPF checksum.
//!
//! # Wire format (RFC 7166 §4.1)
//!
//! ```text
//!  OSPFv3 header (24 bytes)
//!    au_type_or_instance = Instance ID
//!  OSPFv3 body
//!  [optional LLS data block]
//!  Authentication trailer (16-octet fixed header + digest):
//!    +0   Authentication Type   (u16, big-endian)   — 1 = HMAC
//!    +2   Auth Data Len         (u16, big-endian)   — length of the
//!                                                      ENTIRE trailer,
//!                                                      fixed header
//!                                                      included (16 + L)
//!    +4   Reserved              (u16)               — 0
//!    +6   Security Association ID (u16)             — 16-bit SA ID
//!    +8   Cryptographic Sequence Number (u64, big-endian)
//!   +16   Authentication Data   (L octets)
//! ```
//!
//! # MAC computation (RFC 7166 §4.5)
//!
//! ```text
//! Ks = K || OSPFv3 Cryptographic Protocol ID (2 octets, value 1)
//! Ko = Ks padded/truncated to L octets (longer keys are hashed)
//! Apad = IPv6 source address (16 octets) || 0x878FE1F3 repeated
//!        ((L - 16) / 4) times
//! First-Hash  = H(Ko XOR Ipad || (OSPFv3 Packet + LLS data block +
//!                                 Authentication Trailer filled with Apad))
//! Second-Hash = H(Ko XOR Opad || First-Hash)
//! ```
//!
//! The OSPFv3 header checksum is not calculated when the Authentication
//! Trailer is used (RFC 7166 §4.2), so the checksum field is zeroed in
//! the MAC input. The IPv6 source address is embedded in Apad (§2.3) —
//! there is no separate IPv6 pseudo-header.

use core::fmt;

use crate::auth::crypto::CryptoAlgorithm;

/// Fixed Authentication Trailer header: Auth Type(2) + Auth Data Len(2)
/// + Reserved(2) + SA ID(2) + Crypto Seq(8) = 16 octets.
const V3_TRAILER_HEADER: usize = 16;
/// Authentication Type value for HMAC cryptographic authentication
/// (RFC 7166 §4.1).
pub const V3_AUTH_TYPE_HMAC: u16 = 1;
/// OSPFv3 Cryptographic Protocol ID appended to the key (RFC 7166 §4.4).
const OSPFV3_CRYPTO_PROTOCOL_ID: u16 = 1;

/// The Apad value (RFC 7166 §4.5): the IPv6 source address (16 octets)
/// followed by `0x878FE1F3` repeated `(L - 16) / 4` times — always L
/// octets. It fills the Authentication Data field while the MAC is
/// computed.
fn apad(source_v6: [u8; 16], digest_len: usize) -> Vec<u8> {
    let mut v = Vec::with_capacity(digest_len);
    v.extend_from_slice(&source_v6);
    for _ in 0..(digest_len - 16) / 4 {
        v.extend_from_slice(&0x878f_e1f3u32.to_be_bytes());
    }
    v
}

/// OSPFv3 authentication configuration (RFC 7166).
///
/// The trailer uses a 64-bit cryptographic sequence number and a 16-bit
/// Security Association ID; the MAC algorithm set is the same as
/// RFC 5709.
#[derive(Debug, Clone)]
pub struct V3Auth {
    /// Security Association ID (RFC 7166 §4.1, 16 bits). Identifies the
    /// key the receiver should use to verify the digest.
    pub sa_id: u16,
    /// Shared secret.
    pub key: Vec<u8>,
    /// MAC algorithm (HMAC-SHA-1 or HMAC-SHA-256).
    pub algorithm: CryptoAlgorithm,
    /// Monotonic 64-bit cryptographic sequence number.
    pub crypto_seq: u64,
    /// IPv6 source address of the OSPFv3 packets; embedded in Apad so
    /// the source is protected by the digest (RFC 7166 §2.3).
    pub source_v6: [u8; 16],
    /// Last sequence number seen from the peer (anti-replay). `None`
    /// until the first packet is seen (always accepted to bootstrap).
    last_peer_seq: Option<u64>,
}

impl V3Auth {
    /// Create a new v3 auth instance with HMAC-SHA-256 (the recommended
    /// default per RFC 5709 §3).
    pub fn new(sa_id: u16, key: Vec<u8>) -> Self {
        Self {
            sa_id,
            key,
            algorithm: CryptoAlgorithm::HmacSha256,
            crypto_seq: 0,
            source_v6: [0u8; 16],
            last_peer_seq: None,
        }
    }

    /// Use HMAC-SHA-1 instead of the default SHA-256.
    pub fn with_sha1(mut self) -> Self {
        self.algorithm = CryptoAlgorithm::HmacSha1;
        self
    }

    /// Set the IPv6 source address that will be protected via Apad.
    pub fn with_source(mut self, source: [u8; 16]) -> Self {
        self.source_v6 = source;
        self
    }

    /// Advance the cryptographic sequence number for the next packet.
    pub fn advance_seq(&mut self) {
        self.crypto_seq = self.crypto_seq.wrapping_add(1);
    }

    /// The trailer length this configuration produces: the 16-octet
    /// fixed header plus the digest. The Auth Data Len field carries
    /// exactly this value (RFC 7166 §4.1: "the length of the
    /// Authentication Trailer (AT), including both the 16-octet fixed
    /// header and the variable-length message digest").
    pub fn trailer_len(&self) -> usize {
        V3_TRAILER_HEADER + self.algorithm.digest_len()
    }

    /// Build the authentication trailer for an OSPFv3 packet (RFC 7166
    /// §4.3).
    ///
    /// `packet` is the full OSPFv3 packet (header + body) as it will
    /// appear on the wire — the checksum field is zeroed for the MAC
    /// input (RFC 7166 §4.2 omits the header checksum when the AT is
    /// used). `lls` is the optional Link-Local Signaling data block
    /// (RFC 5613), or an empty slice when none is present.
    pub fn sign_trailer(&self, packet: &[u8], lls: &[u8]) -> Vec<u8> {
        let l = self.algorithm.digest_len();
        let mut trailer_with_apad = Vec::with_capacity(self.trailer_len());
        trailer_with_apad.extend_from_slice(&V3_AUTH_TYPE_HMAC.to_be_bytes());
        trailer_with_apad.extend_from_slice(&(self.trailer_len() as u16).to_be_bytes());
        trailer_with_apad.extend_from_slice(&0u16.to_be_bytes()); // Reserved
        trailer_with_apad.extend_from_slice(&self.sa_id.to_be_bytes());
        trailer_with_apad.extend_from_slice(&self.crypto_seq.to_be_bytes());
        trailer_with_apad.extend_from_slice(&apad(self.source_v6, l));

        let digest = self.compute_mac(packet, lls, &trailer_with_apad);

        let mut trailer = trailer_with_apad;
        trailer.truncate(V3_TRAILER_HEADER);
        trailer.extend_from_slice(&digest);
        trailer
    }

    /// Compute the MAC (RFC 7166 §4.5): the First-Hash runs over the
    /// OSPFv3 packet (checksum zeroed) + the LLS data block + the
    /// Authentication Trailer filled with Apad.
    fn compute_mac(&self, packet: &[u8], lls: &[u8], trailer_with_apad: &[u8]) -> Vec<u8> {
        let l = self.algorithm.digest_len();
        // Ks = K || OSPFv3 Cryptographic Protocol ID (§4.4).
        let mut ks = self.key.clone();
        ks.extend_from_slice(&OSPFV3_CRYPTO_PROTOCOL_ID.to_be_bytes());
        // Ko: always L octets (§4.5 (1)). Longer keys are folded through
        // the hash; shorter keys are zero-padded.
        let mut ko = vec![0u8; l];
        if ks.len() > l {
            let digest = self.algorithm.hash(&ks);
            ko.copy_from_slice(&digest[..l]);
        } else {
            ko[..ks.len()].copy_from_slice(&ks);
        }

        // Zero the OSPFv3 header checksum (offset 12..14) — the checksum
        // is omitted when the AT is used (§4.2).
        let mut buf = packet.to_vec();
        if buf.len() >= 14 {
            buf[12] = 0;
            buf[13] = 0;
        }
        buf.extend_from_slice(lls);
        buf.extend_from_slice(trailer_with_apad);

        self.algorithm.hmac(&ko, &buf)
    }

    /// Verify a received OSPFv3 packet's authentication trailer. Returns
    /// `true` when the Authentication Type, SA ID and MAC match and the
    /// sequence number is strictly greater than the last-seen value
    /// (anti-replay, RFC 7166 §4.6).
    ///
    /// `packet` is the OSPFv3 packet (header + body, without the
    /// trailer); `lls` the optional LLS data block; `trailer` the
    /// appended authentication trailer.
    pub fn verify(&mut self, packet: &[u8], lls: &[u8], trailer: &[u8]) -> bool {
        if trailer.len() < V3_TRAILER_HEADER {
            return false;
        }
        let auth_type = u16::from_be_bytes([trailer[0], trailer[1]]);
        if auth_type != V3_AUTH_TYPE_HMAC {
            return false;
        }
        // RFC 7166 §4.1: Auth Data Len = length of the ENTIRE trailer,
        // 16-octet fixed header included.
        let auth_data_len = u16::from_be_bytes([trailer[2], trailer[3]]) as usize;
        if auth_data_len != trailer.len() || auth_data_len != self.trailer_len() {
            return false;
        }
        let sa_id = u16::from_be_bytes([trailer[6], trailer[7]]);
        if sa_id != self.sa_id {
            return false;
        }
        let peer_seq = u64::from_be_bytes([
            trailer[8],
            trailer[9],
            trailer[10],
            trailer[11],
            trailer[12],
            trailer[13],
            trailer[14],
            trailer[15],
        ]);
        // Anti-replay: strictly greater than any sequence seen so far;
        // the first packet (including a seq-0 one) bootstraps the
        // session, after which seq-0 replays are rejected.
        if let Some(last) = self.last_peer_seq {
            if peer_seq <= last {
                return false;
            }
        }

        // Recompute the MAC over packet + LLS + trailer filled with Apad.
        let l = self.algorithm.digest_len();
        let mut trailer_with_apad = trailer.to_vec();
        trailer_with_apad.truncate(V3_TRAILER_HEADER);
        trailer_with_apad.extend_from_slice(&apad(self.source_v6, l));
        let expected_mac = self.compute_mac(packet, lls, &trailer_with_apad);
        let received_mac = &trailer[V3_TRAILER_HEADER..];
        if received_mac != expected_mac.as_slice() {
            return false;
        }
        self.last_peer_seq = Some(peer_seq);
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

    fn src() -> [u8; 16] {
        [0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]
    }

    #[test]
    fn sha256_trailer_length() {
        let auth = V3Auth::new(1, b"key".to_vec());
        // 16 fixed header + 32 digest = 48
        assert_eq!(auth.trailer_len(), 48);
    }

    #[test]
    fn sha1_trailer_length() {
        let auth = V3Auth::new(1, b"key".to_vec()).with_sha1();
        // 16 fixed header + 20 digest = 36
        assert_eq!(auth.trailer_len(), 36);
    }

    #[test]
    fn trailer_layout_matches_rfc7166() {
        // RFC 7166 §4.1 (Figure 3): Authentication Type(2) | Auth Data
        // Len(2) | Reserved(2) | SA ID(2) | Crypto Seq(8) | Auth Data,
        // with Auth Data Len = the ENTIRE trailer length (16 + digest).
        let auth = V3Auth::new(7, b"key".to_vec()).with_source(src());
        let packet = make_v3_packet();
        let trailer = auth.sign_trailer(&packet, &[]);
        assert_eq!(&trailer[0..2], &1u16.to_be_bytes(), "Authentication Type = 1");
        assert_eq!(
            &trailer[2..4],
            &(auth.trailer_len() as u16).to_be_bytes(),
            "Auth Data Len covers the entire trailer"
        );
        assert_eq!(&trailer[4..6], &[0, 0], "Reserved");
        assert_eq!(&trailer[6..8], &7u16.to_be_bytes(), "SA ID (16-bit)");
        assert_eq!(&trailer[8..16], &0u64.to_be_bytes(), "Crypto Seq");
        assert_eq!(trailer.len(), 16 + 32, "SHA-256 digest appended");
    }

    #[test]
    fn sign_and_verify_roundtrip_sha256() {
        let auth = V3Auth::new(1, b"shared-secret".to_vec()).with_source(src());
        let packet = make_v3_packet();
        let trailer = auth.sign_trailer(&packet, &[]);
        assert_eq!(trailer.len(), 48);

        let mut verifier = V3Auth::new(1, b"shared-secret".to_vec()).with_source(src());
        assert!(verifier.verify(&packet, &[], &trailer), "MAC must verify");
    }

    #[test]
    fn sign_and_verify_roundtrip_sha1() {
        let auth = V3Auth::new(1, b"key".to_vec()).with_sha1().with_source(src());
        let packet = make_v3_packet();
        let trailer = auth.sign_trailer(&packet, &[]);
        let mut verifier = V3Auth::new(1, b"key".to_vec()).with_sha1().with_source(src());
        assert!(verifier.verify(&packet, &[], &trailer));
    }

    #[test]
    fn wrong_key_rejected() {
        let auth = V3Auth::new(1, b"correct".to_vec()).with_source(src());
        let packet = make_v3_packet();
        let trailer = auth.sign_trailer(&packet, &[]);
        let mut verifier = V3Auth::new(1, b"wrong".to_vec()).with_source(src());
        assert!(!verifier.verify(&packet, &[], &trailer));
    }

    #[test]
    fn replay_attack_rejected() {
        let mut auth = V3Auth::new(1, b"key".to_vec()).with_source(src());
        auth.crypto_seq = 1000;
        let packet = make_v3_packet();
        let trailer = auth.sign_trailer(&packet, &[]);

        let mut verifier = V3Auth::new(1, b"key".to_vec()).with_source(src());
        assert!(verifier.verify(&packet, &[], &trailer), "first packet accepted");
        assert!(!verifier.verify(&packet, &[], &trailer), "replay must fail");
    }

    #[test]
    fn seq_zero_replay_hole_closed() {
        // A first packet with seq 0 bootstraps; a replayed seq-0 packet
        // must be rejected (audit A3).
        let auth = V3Auth::new(1, b"key".to_vec()).with_source(src());
        let packet = make_v3_packet();
        let trailer = auth.sign_trailer(&packet, &[]);

        let mut verifier = V3Auth::new(1, b"key".to_vec()).with_source(src());
        assert!(verifier.verify(&packet, &[], &trailer), "first seq-0 accepted");
        assert!(
            !verifier.verify(&packet, &[], &trailer),
            "replayed seq-0 must be rejected"
        );
    }

    #[test]
    fn wrong_sa_id_rejected() {
        let auth = V3Auth::new(1, b"key".to_vec()).with_source(src());
        let packet = make_v3_packet();
        let trailer = auth.sign_trailer(&packet, &[]);
        let mut verifier = V3Auth::new(2, b"key".to_vec()).with_source(src());
        assert!(!verifier.verify(&packet, &[], &trailer));
    }

    #[test]
    fn source_address_protected_via_apad() {
        // RFC 7166 §2.3/§4.5: the IPv6 source address is embedded in
        // Apad, so a different source must fail the digest — with no
        // separate pseudo-header involved.
        let src_a = src();
        let mut src_b = src();
        src_b[15] = 9;
        let auth = V3Auth::new(1, b"key".to_vec()).with_source(src_a);
        let packet = make_v3_packet();
        let trailer = auth.sign_trailer(&packet, &[]);

        let mut verifier = V3Auth::new(1, b"key".to_vec()).with_source(src_a);
        assert!(verifier.verify(&packet, &[], &trailer), "same source verifies");

        let mut verifier2 = V3Auth::new(1, b"key".to_vec()).with_source(src_b);
        assert!(
            !verifier2.verify(&packet, &[], &trailer),
            "different source must fail"
        );
    }

    #[test]
    fn lls_data_block_is_covered() {
        // RFC 7166 §4.5: the LLS data block is included in the digest.
        let auth = V3Auth::new(1, b"key".to_vec()).with_source(src());
        let packet = make_v3_packet();
        let lls = vec![0x00, 0x02, 0x00, 0x04, 0xDE, 0xAD, 0xBE, 0xEF];
        let trailer = auth.sign_trailer(&packet, &lls);
        let mut verifier = V3Auth::new(1, b"key".to_vec()).with_source(src());
        assert!(
            verifier.verify(&packet, &lls, &trailer),
            "same LLS block verifies"
        );
        let mut verifier2 = V3Auth::new(1, b"key".to_vec()).with_source(src());
        assert!(
            !verifier2.verify(&packet, &[], &trailer),
            "missing LLS block must fail"
        );
    }

    #[test]
    fn algorithm_mismatch_rejected() {
        let auth = V3Auth::new(1, b"key".to_vec()).with_source(src()); // SHA-256
        let packet = make_v3_packet();
        let trailer = auth.sign_trailer(&packet, &[]);
        let mut verifier = V3Auth::new(1, b"key".to_vec()).with_sha1().with_source(src());
        assert!(!verifier.verify(&packet, &[], &trailer));
    }

    #[test]
    fn malformed_trailer_rejected() {
        let mut verifier = V3Auth::new(1, b"key".to_vec()).with_source(src());
        assert!(!verifier.verify(&[0; 24], &[], &[]));
        assert!(!verifier.verify(&[0; 24], &[], &[0; 5]));
    }

    #[test]
    fn advance_seq() {
        let mut auth = V3Auth::new(1, b"key".to_vec());
        assert_eq!(auth.crypto_seq, 0);
        auth.advance_seq();
        assert_eq!(auth.crypto_seq, 1);
    }
}
