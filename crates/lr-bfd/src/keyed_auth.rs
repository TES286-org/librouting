//! Keyed MD5 and Keyed SHA1 authentication for BFD (RFC 5880 §4.3 / §4.4,
//! §6.7.3 / §6.7.4).
//!
//! The wire framing for the auth section lives in [`crate::auth`]; this
//! module owns the digest computation, the per-session sequence-number
//! state and the anti-replay check the RFC requires on the receive side.
//!
//! # Construction
//!
//! [`BfdKeyedAuth`] carries the static configuration (`key_id`, algorithm,
//! shared secret) plus the per-session dynamic state (transmit sequence
//! counter, last-received sequence, `AuthSeqKnown` flag). Install it on a
//! [`crate::session::BfdSession`] via
//! [`crate::session::BfdSession::set_keyed_auth`]; the session then signs
//! every outbound packet and verifies every inbound packet through it,
//! overriding any Simple Password configured on [`crate::session::BfdConfig`].
//!
//! # Algorithm (RFC 5880 §6.7.3 / §6.7.4)
//!
//! Keyed MD5 and Keyed SHA1 are **not** HMAC constructions: the shared
//! key is placed in the `Auth Key/Digest` field of the auth section
//! (zero-padded to 16 bytes for MD5, 20 for SHA1), and the hash is
//! computed over the **entire** BFD Control packet — including the auth
//! section with the key in the digest field. The hash replaces the key
//! before transmission; the key never rides the wire (RFC 5880 §6.7.3
//! "the secret key, which MUST NOT be carried in the packet").
//!
//! On receive, the receiver replaces the digest field with its own copy
//! of the shared key, recomputes the hash, and compares against the
//! digest carried in the packet. A match authenticates the packet; the
//! key is the only material the hash folds in beyond the packet itself.
//!
//! # Anti-replay (RFC 5880 §6.7.3 / §6.7.4)
//!
//! The session tracks the last sequence number it accepted
//! (`bfd.RcvAuthSeq`) and whether it has seen any packet yet
//! (`bfd.AuthSeqKnown`). On receive:
//!
//! - If `AuthSeqKnown` is 0, accept any sequence number, set
//!   `RcvAuthSeq` to it and `AuthSeqKnown` to 1.
//! - If `AuthSeqKnown` is 1, the sequence number must lie in the
//!   circular range `[RcvAuthSeq, RcvAuthSeq + 3*DetectMult]` for the
//!   non-meticulous types, or `[RcvAuthSeq + 1, RcvAuthSeq + 3*DetectMult]`
//!   for the Meticulous types. Outside the range the packet MUST be
//!   discarded.
//!
//! The 32-bit sequence space is circular (RFC 5880 §6.7.3: "an unsigned
//! 32-bit circular number space"). All arithmetic wraps modulo 2^32.
//!
//! # Sequence-number advancement on transmit
//!
//! The Meticulous types MUST increment on every packet (RFC 5880 §6.7.3
//! "bfd.XmitAuthSeq MUST be incremented in a circular fashion"). The
//! non-Meticulous types MAY increment in a circular fashion and SHOULD
//! increment when the session state changes or the packet contents
//! differ; this implementation increments on every packet for both
//! families, which is the most conservative reading of the RFC and the
//! one BIRD uses.

use crate::auth::{AuthSection, AuthType};

#[cfg(feature = "keyed-auth")]
mod algo {
    // The workspace pulls `md5` and `sha1` as `md5` and `sha1` (workspace
    // deps). We rename the imports inside this module so the per-algo
    // helpers (`algo::md5`, `algo::sha1`) don't shadow the crate names.
    use md5 as md5_;
    use sha1 as sha1_;

    /// Compute MD5 over `data` and write the 16-byte digest into `out`.
    /// The `md5` crate's API is the standalone `compute` function —
    /// there is no `Md5` hasher type exposed.
    pub(crate) fn md5(data: &[u8], out: &mut [u8]) {
        let d = md5_::compute(data);
        out[..16].copy_from_slice(&d.0);
    }

    /// Compute SHA-1 over `data` and write the 20-byte digest into
    /// `out`. Uses the `sha1` crate's `Sha1::digest` associated
    /// function through the `Digest` trait.
    pub(crate) fn sha1(data: &[u8], out: &mut [u8]) {
        use sha1_::Digest;
        let d = sha1_::Sha1::digest(data);
        out[..20].copy_from_slice(&d);
    }
}

/// The four keyed-hash authentication algorithms (RFC 5880 §4.3 / §4.4).
///
/// Each variant carries the expected [`AuthType`] wire code, the digest
/// length in bytes (16 for MD5, 20 for SHA1) and whether the Meticulous
/// anti-replay rules apply (sequence number strictly greater than the
/// last seen, vs. greater-or-equal for the non-Meticulous variants).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum KeyedAuthAlgorithm {
    /// Keyed MD5 (RFC 5880 §4.3, type 2). Digest length 16. The
    /// sequence number MAY advance on every packet; the receiver
    /// accepts a sequence in `[last, last + 3*DetectMult]`.
    KeyedMd5,
    /// Meticulous Keyed MD5 (RFC 5880 §4.3, type 3). Digest length 16.
    /// The sequence number MUST advance on every packet; the receiver
    /// accepts a sequence in `[last + 1, last + 3*DetectMult]`.
    MeticulousKeyedMd5,
    /// Keyed SHA1 (RFC 5880 §4.4, type 4). Digest length 20. The
    /// sequence number MAY advance on every packet; the receiver
    /// accepts a sequence in `[last, last + 3*DetectMult]`.
    KeyedSha1,
    /// Meticulous Keyed SHA1 (RFC 5880 §4.4, type 5). Digest length 20.
    /// The sequence number MUST advance on every packet; the receiver
    /// accepts a sequence in `[last + 1, last + 3*DetectMult]`.
    MeticulousKeyedSha1,
}

impl KeyedAuthAlgorithm {
    /// Wire-level `AuthType` code (RFC 5880 §4.3 / §4.4 / §8).
    pub const fn auth_type(self) -> AuthType {
        match self {
            Self::KeyedMd5 => AuthType::KeyedMd5,
            Self::MeticulousKeyedMd5 => AuthType::MeticulousKeyedMd5,
            Self::KeyedSha1 => AuthType::KeyedSha1,
            Self::MeticulousKeyedSha1 => AuthType::MeticulousKeyedSha1,
        }
    }

    /// Digest length in bytes: 16 for MD5, 20 for SHA1 (RFC 5880 §4.3 / §4.4).
    pub const fn digest_len(self) -> usize {
        match self {
            Self::KeyedMd5 | Self::MeticulousKeyedMd5 => 16,
            Self::KeyedSha1 | Self::MeticulousKeyedSha1 => 20,
        }
    }

    /// True for the Meticulous variants (sequence advances every packet;
    /// the receiver enforces strict `> last` instead of `>= last`).
    pub const fn is_meticulous(self) -> bool {
        matches!(self, Self::MeticulousKeyedMd5 | Self::MeticulousKeyedSha1)
    }

    /// Maximum shared-key length the auth section's digest field can
    /// carry before zero-padding kicks in: 16 for MD5, 20 for SHA1
    /// (RFC 5880 §6.7.3 / §6.7.4 "binary string of up to N bytes").
    pub const fn max_key_len(self) -> usize {
        self.digest_len()
    }

    /// Build the auth section's `data` field for the pre-hash packet:
    /// the shared key zero-padded to the digest length (RFC 5880 §6.7.3
    /// / §6.7.4 "padded with trailing zero bytes as necessary"). Keys
    /// longer than the digest length are folded by truncation to the
    /// digest length; the RFC bars longer keys ("MUST be from 1 to 16
    /// bytes" for MD5, "1 to 20 bytes" for SHA1) — the embedder is
    /// expected to validate length at install time.
    fn key_in_digest_field(self, key: &[u8]) -> Vec<u8> {
        let l = self.digest_len();
        let mut out = vec![0u8; l];
        let n = key.len().min(l);
        out[..n].copy_from_slice(&key[..n]);
        out
    }
}

/// Per-session keyed-hash authentication state (RFC 5880 §6.7.3 / §6.7.4).
///
/// Carries the static configuration (`key_id`, algorithm, shared secret)
/// and the dynamic per-session sequence-number state the RFC tracks as
/// `bfd.XmitAuthSeq`, `bfd.RcvAuthSeq` and `bfd.AuthSeqKnown`.
///
/// Install on a [`crate::session::BfdSession`] via
/// [`crate::session::BfdSession::set_keyed_auth`]. The session then
/// signs every outbound packet and verifies every inbound packet
/// through it; an installed `BfdKeyedAuth` overrides any Simple Password
/// configured on [`crate::session::BfdConfig::auth_key`].
#[derive(Debug, Clone)]
pub struct BfdKeyedAuth {
    /// Auth Key ID (RFC 5880 §4.3 / §4.4). Allows multiple keys to be
    /// active simultaneously; the receiver looks up its key by this ID.
    pub key_id: u8,
    /// The keyed-hash algorithm (MD5 / Meticulous MD5 / SHA1 / Meticulous SHA1).
    pub algorithm: KeyedAuthAlgorithm,
    /// Shared secret. The RFC bars keys longer than the digest length
    /// (16 bytes for MD5, 20 for SHA1); the constructor enforces this
    /// and zero-pads shorter keys at hash time.
    secret: Vec<u8>,
    /// `bfd.XmitAuthSeq` (RFC 5880 §6.7.3 / §6.7.4): the sequence number
    /// stamped on the next outbound packet. Advances circularly modulo
    /// 2^32 on every transmit.
    xmit_seq: u32,
    /// `bfd.AuthSeqKnown` (RFC 5880 §6.7.3 / §6.7.4): 0 until the first
    /// packet from the peer is processed, then 1 for the session's life.
    rcv_auth_seq_known: bool,
    /// `bfd.RcvAuthSeq` (RFC 5880 §6.7.3 / §6.7.4): the last sequence
    /// number accepted from the peer. The anti-replay check requires
    /// the next packet's sequence to lie in `[rcv_auth_seq,
    /// rcv_auth_seq + 3*DetectMult]` for non-Meticulous types, or
    /// `[rcv_auth_seq + 1, rcv_auth_seq + 3*DetectMult]` for Meticulous.
    rcv_auth_seq: u32,
}

impl BfdKeyedAuth {
    /// Construct a new keyed-hash auth state. The secret is checked
    /// against the algorithm's maximum key length (16 for MD5, 20 for
    /// SHA1, RFC 5880 §6.7.3 / §6.7.4) and rejected with a `None` if it
    /// is empty or too long; the embedder is expected to surface this as
    /// a configuration error rather than silently truncating.
    pub fn new(key_id: u8, algorithm: KeyedAuthAlgorithm, secret: Vec<u8>) -> Option<Self> {
        if secret.is_empty() || secret.len() > algorithm.max_key_len() {
            return None;
        }
        Some(Self {
            key_id,
            algorithm,
            secret,
            xmit_seq: 0,
            rcv_auth_seq_known: false,
            rcv_auth_seq: 0,
        })
    }

    /// The configured key ID.
    pub fn key_id(&self) -> u8 {
        self.key_id
    }

    /// The configured algorithm.
    pub fn algorithm(&self) -> KeyedAuthAlgorithm {
        self.algorithm
    }

    /// The next transmit sequence number (`bfd.XmitAuthSeq`).
    pub fn xmit_seq(&self) -> u32 {
        self.xmit_seq
    }

    /// Whether the receiver has seen any authenticated packet yet
    /// (`bfd.AuthSeqKnown`).
    pub fn rcv_auth_seq_known(&self) -> bool {
        self.rcv_auth_seq_known
    }

    /// The last accepted receive sequence number (`bfd.RcvAuthSeq`).
    pub fn rcv_auth_seq(&self) -> u32 {
        self.rcv_auth_seq
    }

    /// Build the wire auth section to ride the next outbound packet:
    /// the auth type, key ID, current transmit sequence and the
    /// **shared key in the digest field** (the placeholder the hash is
    /// computed over, RFC 5880 §6.7.3 / §6.7.4). The codec serialises
    /// the section verbatim; [`sign_packet`] then replaces the key
    /// bytes with the computed digest.
    ///
    /// Exposed publicly so an embedder that owns its own packet
    /// encoder (rather than driving the session's `tick` loop) can
    /// produce the auth section to pass into `BfdPacket::auth`.
    ///
    /// [`sign_packet`]: BfdKeyedAuth::sign_packet
    pub fn auth_section_for_tx(&self) -> AuthSection {
        let key_in_digest = self.algorithm.key_in_digest_field(&self.secret);
        match self.algorithm {
            KeyedAuthAlgorithm::KeyedMd5 => {
                AuthSection::keyed_md5(self.key_id, self.xmit_seq, key_in_digest)
            }
            KeyedAuthAlgorithm::MeticulousKeyedMd5 => {
                AuthSection::meticulous_keyed_md5(self.key_id, self.xmit_seq, key_in_digest)
            }
            KeyedAuthAlgorithm::KeyedSha1 => {
                AuthSection::keyed_sha1(self.key_id, self.xmit_seq, key_in_digest)
            }
            KeyedAuthAlgorithm::MeticulousKeyedSha1 => {
                AuthSection::meticulous_keyed_sha1(self.key_id, self.xmit_seq, key_in_digest)
            }
        }
    }

    /// Advance `bfd.XmitAuthSeq` circularly after a successful
    /// transmit (RFC 5880 §6.7.3 / §6.7.4: MUST increment for Meticulous,
    /// MAY increment for non-Meticulous; this implementation increments
    /// unconditionally to match BIRD and to keep the anti-replay
    /// contract symmetric across the four types).
    pub fn advance_xmit_seq(&mut self) {
        self.xmit_seq = self.xmit_seq.wrapping_add(1);
    }

    /// Sign an encoded outbound BFD Control packet in place. The
    /// `packet` slice MUST be the full encoded packet with the auth
    /// section's digest field carrying the **shared key** (as produced
    /// by [`auth_section_for_tx`] + `BfdCodec::encode`). The last
    /// `digest_len` bytes of the slice are replaced with the computed
    /// digest (RFC 5880 §6.7.3 / §6.7.4).
    ///
    /// Does nothing if the slice is shorter than the digest length
    /// (defensive — the caller has already encoded a valid section).
    ///
    /// Public so an embedder that owns its own packet encoder can sign
    /// the encoded bytes the same way [`BfdSession`] does internally.
    ///
    /// [`BfdSession`]: crate::session::BfdSession
    #[cfg(feature = "keyed-auth")]
    pub fn sign_packet(&self, packet: &mut [u8]) {
        let l = self.algorithm.digest_len();
        if packet.len() < l {
            return;
        }
        let off = packet.len() - l;
        // The hash is computed over the full packet as encoded (key in
        // digest field); the digest is then written over the key
        // bytes before the packet goes on the wire.
        let mut digest = [0u8; 20];
        let d = &mut digest[..l];
        match self.algorithm {
            KeyedAuthAlgorithm::KeyedMd5 | KeyedAuthAlgorithm::MeticulousKeyedMd5 => {
                algo::md5(packet, d);
            }
            KeyedAuthAlgorithm::KeyedSha1 | KeyedAuthAlgorithm::MeticulousKeyedSha1 => {
                algo::sha1(packet, d);
            }
        }
        packet[off..].copy_from_slice(d);
    }

    /// Verify an inbound BFD Control packet against this auth state.
    ///
    /// `received_packet` is the full encoded packet bytes as received
    /// (with the peer's digest in the auth section's digest field).
    /// `section` is the parsed auth section from that packet (carries
    /// the received digest in `section.data`). `detect_mult` is the
    /// session's detect multiplier used to bound the anti-replay window.
    ///
    /// Returns `true` when the packet authenticates and the sequence
    /// number is within the anti-replay window; on success, the receive
    /// sequence state is updated. Returns `false` (and leaves the state
    /// untouched) when the type, key ID or length mismatch, the sequence
    /// number is outside the window, or the digest does not match.
    ///
    /// The verification path rebuilds the pre-hash packet (key in
    /// digest field) by replacing the trailing `digest_len` bytes of
    /// `received_packet` with the shared key, then recomputes the hash
    /// over the full packet and compares against the received digest
    /// (RFC 5880 §6.7.3 / §6.7.4).
    ///
    /// Public so an embedder that owns its own packet decoder can verify
    /// packets the same way [`BfdSession`] does internally.
    ///
    /// [`BfdSession`]: crate::session::BfdSession
    #[cfg(feature = "keyed-auth")]
    pub fn verify_inbound(
        &mut self,
        received_packet: &[u8],
        section: &AuthSection,
        detect_mult: u8,
    ) -> bool {
        // §6.7.3 / §6.7.4: discard when the auth type is not the
        // configured one.
        if section.auth_type != self.algorithm.auth_type() {
            return false;
        }
        // §6.7.3 / §6.7.4: discard when the Auth Key ID does not match.
        if section.key_id != self.key_id {
            return false;
        }
        let l = self.algorithm.digest_len();
        // §6.7.3 / §6.7.4: discard when Auth Len is wrong (the codec
        // already validates this, but a defensive check is cheap).
        if section.data.len() != l {
            return false;
        }
        let Some(seq) = section.sequence else {
            return false;
        };
        let detect_mult = detect_mult.max(1) as u32;
        // Anti-replay window (RFC 5880 §6.7.3 / §6.7.4).
        if self.rcv_auth_seq_known {
            let lo = if self.algorithm.is_meticulous() {
                self.rcv_auth_seq.wrapping_add(1)
            } else {
                self.rcv_auth_seq
            };
            let hi = self.rcv_auth_seq.wrapping_add(3 * detect_mult);
            if !in_circular_range(seq, lo, hi) {
                return false;
            }
        }
        // Rebuild the pre-hash packet: copy the received bytes and
        // overwrite the trailing digest with the shared key padded to
        // the digest length (RFC 5880 §6.7.3 / §6.7.4 "Replace the
        // contents of the Auth Key/Digest field with the authentication
        // key selected by the received Auth Key ID field").
        if received_packet.len() < l {
            return false;
        }
        let mut scratch = received_packet.to_vec();
        let off = scratch.len() - l;
        let key_in_digest = self.algorithm.key_in_digest_field(&self.secret);
        scratch[off..].copy_from_slice(&key_in_digest);
        let mut digest = [0u8; 20];
        let d = &mut digest[..l];
        match self.algorithm {
            KeyedAuthAlgorithm::KeyedMd5 | KeyedAuthAlgorithm::MeticulousKeyedMd5 => {
                algo::md5(&scratch, d);
            }
            KeyedAuthAlgorithm::KeyedSha1 | KeyedAuthAlgorithm::MeticulousKeyedSha1 => {
                algo::sha1(&scratch, d);
            }
        }
        // §6.7.3 / §6.7.4: accept iff the computed hash equals the
        // received Auth Key/Digest field.
        if section.data != d {
            return false;
        }
        // Update the receive sequence state. The RFC sets
        // AuthSeqKnown=1 and RcvAuthSeq=seq on the first packet, then
        // advances RcvAuthSeq on every accepted packet thereafter.
        self.rcv_auth_seq_known = true;
        self.rcv_auth_seq = seq;
        true
    }
}

/// Test whether `seq` lies in the inclusive circular range `[lo, hi]`
/// over the 32-bit unsigned integer space (RFC 5880 §6.7.3 / §6.7.4:
/// "an unsigned 32-bit circular number space"). The range wraps through
/// 0; `lo > hi` (modulo 2^32) denotes a range that crosses the
/// boundary.
fn in_circular_range(seq: u32, lo: u32, hi: u32) -> bool {
    let span = hi.wrapping_sub(lo);
    let off = seq.wrapping_sub(lo);
    off <= span
}

#[cfg(all(test, feature = "keyed-auth"))]
mod tests {
    use super::*;
    use crate::auth::AuthType;
    use crate::packet::{BfdCodec, BfdPacket, PacketFlags};
    use lr_core::buf::{ReadBuf, WriteBuf};
    use lr_core::codec::{Decoder, Encoder};

    fn encode_with_key_in_digest(p: &BfdPacket, ka: &BfdKeyedAuth) -> Vec<u8> {
        // Build a packet carrying the shared key in the digest field,
        // encode it, then sign in place — the result is the on-the-wire
        // packet a peer would receive.
        let mut p = p.clone();
        p.flags |= PacketFlags::AUTH;
        p.auth = Some(ka.auth_section_for_tx());
        let mut buf = [0u8; 96];
        let mut w = WriteBuf::new(&mut buf);
        let codec = BfdCodec::new();
        let n = codec.encode(&p, &mut w).unwrap();
        let mut out = buf[..n].to_vec();
        ka.sign_packet(&mut out);
        out
    }

    #[test]
    fn algorithm_codes_and_lengths() {
        assert_eq!(KeyedAuthAlgorithm::KeyedMd5.auth_type(), AuthType::KeyedMd5);
        assert_eq!(
            KeyedAuthAlgorithm::MeticulousKeyedMd5.auth_type(),
            AuthType::MeticulousKeyedMd5
        );
        assert_eq!(
            KeyedAuthAlgorithm::KeyedSha1.auth_type(),
            AuthType::KeyedSha1
        );
        assert_eq!(
            KeyedAuthAlgorithm::MeticulousKeyedSha1.auth_type(),
            AuthType::MeticulousKeyedSha1
        );
        assert_eq!(KeyedAuthAlgorithm::KeyedMd5.digest_len(), 16);
        assert_eq!(KeyedAuthAlgorithm::MeticulousKeyedMd5.digest_len(), 16);
        assert_eq!(KeyedAuthAlgorithm::KeyedSha1.digest_len(), 20);
        assert_eq!(KeyedAuthAlgorithm::MeticulousKeyedSha1.digest_len(), 20);
        assert!(!KeyedAuthAlgorithm::KeyedMd5.is_meticulous());
        assert!(KeyedAuthAlgorithm::MeticulousKeyedMd5.is_meticulous());
        assert!(!KeyedAuthAlgorithm::KeyedSha1.is_meticulous());
        assert!(KeyedAuthAlgorithm::MeticulousKeyedSha1.is_meticulous());
    }

    #[test]
    fn constructor_rejects_oversized_and_empty_keys() {
        assert!(BfdKeyedAuth::new(1, KeyedAuthAlgorithm::KeyedMd5, Vec::new()).is_none());
        assert!(BfdKeyedAuth::new(1, KeyedAuthAlgorithm::KeyedMd5, vec![0u8; 17]).is_none());
        assert!(BfdKeyedAuth::new(1, KeyedAuthAlgorithm::KeyedSha1, vec![0u8; 21]).is_none());
        assert!(BfdKeyedAuth::new(1, KeyedAuthAlgorithm::KeyedMd5, vec![0u8; 16]).is_some());
        assert!(BfdKeyedAuth::new(1, KeyedAuthAlgorithm::KeyedSha1, vec![0u8; 20]).is_some());
    }

    #[test]
    fn sign_and_verify_round_trip_md5() {
        let mut ka =
            BfdKeyedAuth::new(7, KeyedAuthAlgorithm::KeyedMd5, b"shared-secret".to_vec()).unwrap();
        let p = BfdPacket::heartbeat(0x1111_2222, 0x3333_4444);
        let wire = encode_with_key_in_digest(&p, &ka);

        // Decode the auth section so verify_inbound has the parsed
        // digest to compare against.
        let mut codec = BfdCodec::new();
        let mut r = ReadBuf::new(&wire);
        let decoded = codec.decode(&mut r).unwrap().unwrap();
        let section = decoded.auth.as_ref().unwrap().clone();

        // First packet: AuthSeqKnown=0 → accept any sequence.
        assert!(ka.verify_inbound(&wire, &section, 3));
        assert!(ka.rcv_auth_seq_known());
        assert_eq!(ka.rcv_auth_seq(), 0);

        // Sign a second packet (advances xmit_seq to 1) and verify
        // it is accepted (>= last for non-Meticulous).
        ka.advance_xmit_seq();
        let p2 = BfdPacket::heartbeat(0x1111_2222, 0x3333_4444);
        let wire2 = encode_with_key_in_digest(&p2, &ka);
        let mut r = ReadBuf::new(&wire2);
        let decoded2 = codec.decode(&mut r).unwrap().unwrap();
        let section2 = decoded2.auth.as_ref().unwrap().clone();
        assert!(ka.verify_inbound(&wire2, &section2, 3));
        assert_eq!(ka.rcv_auth_seq(), 1);
    }

    #[test]
    fn sign_and_verify_round_trip_meticulous_sha1() {
        let mut ka = BfdKeyedAuth::new(
            3,
            KeyedAuthAlgorithm::MeticulousKeyedSha1,
            b"another-secret".to_vec(),
        )
        .unwrap();
        let p = BfdPacket::heartbeat(0xaaaa_bbbb, 0xcccc_dddd);
        let wire = encode_with_key_in_digest(&p, &ka);
        let mut codec = BfdCodec::new();
        let mut r = ReadBuf::new(&wire);
        let decoded = codec.decode(&mut r).unwrap().unwrap();
        let section = decoded.auth.as_ref().unwrap().clone();
        assert!(ka.verify_inbound(&wire, &section, 3));
        assert_eq!(ka.rcv_auth_seq(), 0);

        // Meticulous: same sequence number MUST be rejected.
        let wire_dup = encode_with_key_in_digest(&p, &ka);
        let mut r = ReadBuf::new(&wire_dup);
        let decoded_dup = codec.decode(&mut r).unwrap().unwrap();
        let section_dup = decoded_dup.auth.as_ref().unwrap().clone();
        // xmit_seq is still 0 here — verify rejects.
        assert!(!ka.verify_inbound(&wire_dup, &section_dup, 3));
        // After advancing xmit_seq, the new sequence (1) is accepted.
        ka.advance_xmit_seq();
        let p2 = BfdPacket::heartbeat(0xaaaa_bbbb, 0xcccc_dddd);
        let wire2 = encode_with_key_in_digest(&p2, &ka);
        let mut r = ReadBuf::new(&wire2);
        let decoded2 = codec.decode(&mut r).unwrap().unwrap();
        let section2 = decoded2.auth.as_ref().unwrap().clone();
        assert!(ka.verify_inbound(&wire2, &section2, 3));
        assert_eq!(ka.rcv_auth_seq(), 1);
    }

    #[test]
    fn wrong_key_id_rejected() {
        let mut ka =
            BfdKeyedAuth::new(5, KeyedAuthAlgorithm::KeyedMd5, b"shared-secret".to_vec()).unwrap();
        let p = BfdPacket::heartbeat(1, 2);
        let wire = encode_with_key_in_digest(&p, &ka);
        let mut codec = BfdCodec::new();
        let mut r = ReadBuf::new(&wire);
        let decoded = codec.decode(&mut r).unwrap().unwrap();
        // Tamper with the key_id in the section.
        let mut section = decoded.auth.as_ref().unwrap().clone();
        section.key_id = 6;
        assert!(!ka.verify_inbound(&wire, &section, 3));
    }

    #[test]
    fn wrong_secret_rejected() {
        let mut ka =
            BfdKeyedAuth::new(5, KeyedAuthAlgorithm::KeyedMd5, b"shared-secret".to_vec()).unwrap();
        let p = BfdPacket::heartbeat(1, 2);
        let wire = encode_with_key_in_digest(&p, &ka);
        let mut codec = BfdCodec::new();
        let mut r = ReadBuf::new(&wire);
        let decoded = codec.decode(&mut r).unwrap().unwrap();
        let section = decoded.auth.as_ref().unwrap().clone();
        // Switch the configured secret to simulate a peer using a
        // different key. The digest won't match.
        ka.secret = b"another-secret".to_vec();
        assert!(!ka.verify_inbound(&wire, &section, 3));
    }

    #[test]
    fn circular_range_handles_wrap() {
        // Range [u32::MAX - 1, 2] wraps through 0.
        assert!(in_circular_range(u32::MAX - 1, u32::MAX - 1, 2));
        assert!(in_circular_range(u32::MAX, u32::MAX - 1, 2));
        assert!(in_circular_range(0, u32::MAX - 1, 2));
        assert!(in_circular_range(1, u32::MAX - 1, 2));
        assert!(in_circular_range(2, u32::MAX - 1, 2));
        assert!(!in_circular_range(3, u32::MAX - 1, 2));
        // Non-wrapping range.
        assert!(in_circular_range(5, 5, 10));
        assert!(in_circular_range(10, 5, 10));
        assert!(!in_circular_range(4, 5, 10));
        assert!(!in_circular_range(11, 5, 10));
    }

    #[test]
    fn anti_replay_window_bounded_by_detect_mult() {
        // For non-Meticulous, the window is [last, last + 3*DetectMult].
        // Build a base state as if we already accepted seq=100 with
        // detect_mult=3, then probe each sequence against a fresh
        // clone so a successful verify does not roll the state forward
        // and shift the window for the next probe.
        let base = {
            let mut ka =
                BfdKeyedAuth::new(1, KeyedAuthAlgorithm::KeyedMd5, b"key".to_vec()).unwrap();
            ka.rcv_auth_seq_known = true;
            ka.rcv_auth_seq = 100;
            ka
        };
        let detect_mult = 3u8;
        let p = BfdPacket::heartbeat(1, 2);
        // The window for last=100 and detect_mult=3 is [100, 109].
        for seq in [99u32, 100, 105, 109, 110] {
            let mut probe = base.clone();
            probe.xmit_seq = seq;
            let wire = encode_with_key_in_digest(&p, &probe);
            let mut codec = BfdCodec::new();
            let mut r = ReadBuf::new(&wire);
            let decoded = codec.decode(&mut r).unwrap().unwrap();
            let section = decoded.auth.as_ref().unwrap().clone();
            let mut ka = base.clone();
            let accept = ka.verify_inbound(&wire, &section, detect_mult);
            // 99 below, 110 above; the three in between are inside.
            assert_eq!(
                accept,
                (100..=109).contains(&seq),
                "seq={seq} accept={accept}"
            );
        }
        // Meticulous: window is [last+1, last+3*DetectMult].
        let base_m = {
            let mut ka =
                BfdKeyedAuth::new(1, KeyedAuthAlgorithm::MeticulousKeyedMd5, b"key".to_vec())
                    .unwrap();
            ka.rcv_auth_seq_known = true;
            ka.rcv_auth_seq = 100;
            ka
        };
        for seq in [100u32, 101, 105, 109, 110] {
            let mut probe = base_m.clone();
            probe.xmit_seq = seq;
            let wire = encode_with_key_in_digest(&p, &probe);
            let mut codec = BfdCodec::new();
            let mut r = ReadBuf::new(&wire);
            let decoded = codec.decode(&mut r).unwrap().unwrap();
            let section = decoded.auth.as_ref().unwrap().clone();
            let mut ka_m = base_m.clone();
            let accept = ka_m.verify_inbound(&wire, &section, detect_mult);
            // Meticulous window with last=100 and detect_mult=3 is
            // [101, 109]. 100 is the previous seq (rejected as
            // duplicate); 110 is above.
            assert_eq!(
                accept,
                (101..=109).contains(&seq),
                "seq={seq} accept={accept}"
            );
        }
    }

    #[test]
    fn key_in_digest_field_pads_short_key() {
        // A short key is zero-padded to the digest length when placed
        // in the digest field (RFC 5880 §6.7.3 / §6.7.4).
        let ka = BfdKeyedAuth::new(1, KeyedAuthAlgorithm::KeyedMd5, b"abc".to_vec()).unwrap();
        let p = BfdPacket::heartbeat(1, 2);
        let wire = encode_with_key_in_digest(&p, &ka);
        // The packet on the wire has the digest, not the key — verify
        // by checking that the last 16 bytes are NOT the key-padded
        // (they should be the actual MD5 of the pre-hash packet).
        let key_in_digest = ka.algorithm.key_in_digest_field(&b"abc"[..]);
        let digest = &wire[wire.len() - 16..];
        assert_ne!(digest, &key_in_digest[..]);
        // But re-verify to confirm it round-trips.
        let mut ka_v = ka.clone();
        let mut codec = BfdCodec::new();
        let mut r = ReadBuf::new(&wire);
        let decoded = codec.decode(&mut r).unwrap().unwrap();
        let section = decoded.auth.as_ref().unwrap().clone();
        assert!(ka_v.verify_inbound(&wire, &section, 3));
    }
}
