//! BFD authentication (RFC 5880 §4.2 - §4.4).
//!
//! BFD supports three authentication types:
//!
//! - **Keyed MD5** (type 3): a 16-byte MD5 digest over the packet with the
//!   key appended; the digest is recomputed on receive with the same key.
//! - **Meticulous Keyed MD5** (type 5): like type 3 but the sequence number
//!   is monotonically increased for each packet to defeat replay attacks.
//! - **Keyed SHA1** (type 4): 20-byte SHA1 digest.
//! - **Meticulous Keyed SHA1** (type 6): like type 4 with sequence numbers.
//!
//! We don't implement the cryptographic algorithms here (they're widely
//! available in OS crypto libraries; `lr-bfd` is no_std-friendly and avoids
//! pulling in a crypto dependency). Instead, the wire codec handles the auth
//! section framing, and the embedder provides the digest as opaque bytes.

use lr_core::buf::{ReadBuf, WriteBuf};
use lr_core::error::{EncodeError, ParseError};

/// Authentication type code (RFC 5880 §4.2 + IANA registry).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum AuthType {
    /// Reserved — value 0 is unused per IANA.
    Reserved = 0,
    /// Simple password (cleartext, type 1).
    SimplePassword = 1,
    /// Keyed MD5 (type 3).
    KeyedMd5 = 3,
    /// Meticulous Keyed MD5 (type 5).
    MeticulousKeyedMd5 = 5,
    /// Keyed SHA1 (type 4).
    KeyedSha1 = 4,
    /// Meticulous Keyed SHA1 (type 6).
    MeticulousKeyedSha1 = 6,
    /// Unknown auth type — captured as the raw code.
    Unknown(u8),
}

impl AuthType {
    pub fn from_u8(v: u8) -> Self {
        match v {
            0 => Self::Reserved,
            1 => Self::SimplePassword,
            3 => Self::KeyedMd5,
            4 => Self::KeyedSha1,
            5 => Self::MeticulousKeyedMd5,
            6 => Self::MeticulousKeyedSha1,
            _ => Self::Unknown(v),
        }
    }
    pub fn to_u8(self) -> u8 {
        match self {
            Self::Reserved => 0,
            Self::SimplePassword => 1,
            Self::KeyedMd5 => 3,
            Self::KeyedSha1 => 4,
            Self::MeticulousKeyedMd5 => 5,
            Self::MeticulousKeyedSha1 => 6,
            Self::Unknown(v) => v,
        }
    }
    pub fn expected_digest_len(self) -> Option<usize> {
        match self {
            Self::KeyedMd5 | Self::MeticulousKeyedMd5 => Some(16),
            Self::KeyedSha1 | Self::MeticulousKeyedSha1 => Some(20),
            _ => None,
        }
    }
}

/// An authentication key. For MD5/SHA1 this is the shared secret; for simple
/// password it's the password itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthKey {
    pub key_id: u8,
    pub data: Vec<u8>,
}

impl AuthKey {
    pub fn new(key_id: u8, data: Vec<u8>) -> Self {
        Self { key_id, data }
    }
}

/// The wire representation of the auth section (RFC 5880 §4.2):
///
/// Header is 4 bytes; the sequence number is 4 bytes (only present for
/// MD5/SHA1 — see RFC 5880 §4.3); auth data is variable length.
///
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthSection {
    pub auth_type: AuthType,
    pub key_id: u8,
    /// For MD5/SHA1, the 4-byte sequence number.
    pub sequence: Option<u32>,
    /// For simple-password: the password itself. For MD5/SHA1: the digest.
    pub data: Vec<u8>,
}

impl AuthSection {
    pub fn simple_password(password: Vec<u8>, key_id: u8) -> Self {
        Self {
            auth_type: AuthType::SimplePassword,
            key_id,
            sequence: None,
            data: password,
        }
    }
    pub fn keyed_md5(key_id: u8, sequence: u32, digest: Vec<u8>) -> Self {
        Self {
            auth_type: AuthType::KeyedMd5,
            key_id,
            sequence: Some(sequence),
            data: digest,
        }
    }
    pub fn keyed_sha1(key_id: u8, sequence: u32, digest: Vec<u8>) -> Self {
        Self {
            auth_type: AuthType::KeyedSha1,
            key_id,
            sequence: Some(sequence),
            data: digest,
        }
    }

    /// Total wire length: 4-byte header + (4-byte sequence if MD5/SHA1) + data.
    pub fn wire_len(&self) -> usize {
        4 + if self.sequence.is_some() { 4 } else { 0 } + self.data.len()
    }

    /// Encode this section into `out`. Returns the number of bytes written.
    pub fn encode(&self, out: &mut WriteBuf<'_>) -> Result<usize, EncodeError> {
        let needed = self.wire_len();
        if out.remaining_mut() < needed {
            return Err(EncodeError::BufferFull);
        }
        out.put_u8(self.auth_type.to_u8());
        out.put_u8(self.key_id);
        out.put_u8(0); // reserved
        out.put_u8(self.data.len() as u8);
        if let Some(s) = self.sequence {
            out.put_u32_be(s);
        }
        out.put_bytes(&self.data);
        Ok(needed)
    }

    /// Decode a section from `r`. Assumes `r` is positioned at the start of
    /// the auth section.
    pub fn decode(r: &mut ReadBuf<'_>) -> Result<Self, ParseError> {
        let auth_type = r
            .get_u8()
            .ok_or_else(|| ParseError::truncated("bfd.auth.type"))?;
        let key_id = r
            .get_u8()
            .ok_or_else(|| ParseError::truncated("bfd.auth.key_id"))?;
        let _reserved = r
            .get_u8()
            .ok_or_else(|| ParseError::truncated("bfd.auth.reserved"))?;
        let data_len =
            r.get_u8()
                .ok_or_else(|| ParseError::truncated("bfd.auth.data_len"))? as usize;
        let auth_type = AuthType::from_u8(auth_type);
        let sequence = if matches!(
            auth_type,
            AuthType::KeyedMd5
                | AuthType::KeyedSha1
                | AuthType::MeticulousKeyedMd5
                | AuthType::MeticulousKeyedSha1
        ) {
            Some(
                r.get_u32_be()
                    .ok_or_else(|| ParseError::truncated("bfd.auth.sequence"))?,
            )
        } else {
            None
        };
        let data = r
            .get_bytes(data_len)
            .ok_or_else(|| ParseError::truncated("bfd.auth.data"))?
            .to_vec();
        Ok(Self {
            auth_type,
            key_id,
            sequence,
            data,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn simple_password_roundtrip() {
        let s = AuthSection::simple_password(b"hunter2".to_vec(), 7);
        let mut buf = [0u8; 16];
        let mut w = WriteBuf::new(&mut buf);
        let n = s.encode(&mut w).unwrap();
        assert_eq!(n, 4 + 7);
        let mut r = ReadBuf::new(&buf[..n]);
        let decoded = AuthSection::decode(&mut r).unwrap();
        assert_eq!(decoded, s);
    }

    #[test]
    fn keyed_md5_roundtrip() {
        let digest = vec![0u8; 16]; // 16-byte MD5 digest
        let s = AuthSection::keyed_md5(7, 0xdeadbeef, digest.clone());
        let mut buf = [0u8; 32];
        let mut w = WriteBuf::new(&mut buf);
        let n = s.encode(&mut w).unwrap();
        assert_eq!(n, 4 + 4 + 16);
        let mut r = ReadBuf::new(&buf[..n]);
        let decoded = AuthSection::decode(&mut r).unwrap();
        assert_eq!(decoded, s);
    }

    #[test]
    fn keyed_sha1_roundtrip() {
        let digest = vec![0u8; 20]; // 20-byte SHA1 digest
        let s = AuthSection::keyed_sha1(7, 0xdeadbeef, digest.clone());
        let mut buf = [0u8; 32];
        let mut w = WriteBuf::new(&mut buf);
        let n = s.encode(&mut w).unwrap();
        assert_eq!(n, 4 + 4 + 20);
        let mut r = ReadBuf::new(&buf[..n]);
        let decoded = AuthSection::decode(&mut r).unwrap();
        assert_eq!(decoded, s);
    }
}
