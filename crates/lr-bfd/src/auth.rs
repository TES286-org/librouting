//! BFD authentication sections (RFC 5880 §4.2 - §4.4).
//!
//! The Authentication Section (present when the A bit is set in the
//! header) is laid out differently per type:
//!
//! - **Simple Password** (§4.2, type 1): `type | len | key-id | password`
//!   — a 3-byte header plus a 1-16 byte password. `Auth Len` = password
//!   length + 3.
//! - **Keyed MD5 / Meticulous Keyed MD5** (§4.3, types 2-3):
//!   `type | len | key-id | reserved | sequence | 16-byte digest`.
//!   `Auth Len` = 24.
//! - **Keyed SHA1 / Meticulous Keyed SHA1** (§4.4, types 4-5):
//!   `type | len | key-id | reserved | sequence | 20-byte digest`.
//!   `Auth Len` = 28.
//!
//! This crate does not implement the cryptographic algorithms
//! themselves (`lr-bfd` is no_std-friendly and avoids a crypto
//! dependency): the wire codec frames the section and the embedder
//! supplies the digest as opaque bytes. [`BfdSession`]s support the
//! cryptographic-free Simple Password type end-to-end; the digest types
//! are framing-only.

use lr_core::buf::{ReadBuf, WriteBuf};
use lr_core::error::{EncodeError, ParseError};

/// Maximum password length for Simple Password auth (RFC 5880 §4.2).
pub const MAX_PASSWORD_LEN: usize = 16;

/// Authentication type code (RFC 5880 §4.1 + the IANA "BFD
/// Authentication Types" registry, §8: 1 = Simple Password, 2 = Keyed
/// MD5, 3 = Meticulous Keyed MD5, 4 = Keyed SHA1, 5 = Meticulous
/// Keyed SHA1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum AuthType {
    /// Simple Password (type 1, RFC 5880 §4.2).
    SimplePassword = 1,
    /// Keyed MD5 (type 2, RFC 5880 §4.3).
    KeyedMd5 = 2,
    /// Meticulous Keyed MD5 (type 3, RFC 5880 §4.3).
    MeticulousKeyedMd5 = 3,
    /// Keyed SHA1 (type 4, RFC 5880 §4.4).
    KeyedSha1 = 4,
    /// Meticulous Keyed SHA1 (type 5, RFC 5880 §4.4).
    MeticulousKeyedSha1 = 5,
    /// Unknown auth type — captured as the raw code.
    Unknown(u8),
}

impl AuthType {
    pub fn from_u8(v: u8) -> Self {
        match v {
            1 => Self::SimplePassword,
            2 => Self::KeyedMd5,
            3 => Self::MeticulousKeyedMd5,
            4 => Self::KeyedSha1,
            5 => Self::MeticulousKeyedSha1,
            _ => Self::Unknown(v),
        }
    }
    pub fn to_u8(self) -> u8 {
        match self {
            Self::SimplePassword => 1,
            Self::KeyedMd5 => 2,
            Self::MeticulousKeyedMd5 => 3,
            Self::KeyedSha1 => 4,
            Self::MeticulousKeyedSha1 => 5,
            Self::Unknown(v) => v,
        }
    }
    /// Expected digest length for the keyed-hash types; `None` for
    /// Simple Password (variable) and unknown types.
    pub fn expected_digest_len(self) -> Option<usize> {
        match self {
            Self::KeyedMd5 | Self::MeticulousKeyedMd5 => Some(16),
            Self::KeyedSha1 | Self::MeticulousKeyedSha1 => Some(20),
            _ => None,
        }
    }
    /// True for the four keyed-hash types (they share the
    /// §4.3/§4.4 layout: reserved byte + sequence number).
    pub fn is_keyed_hash(self) -> bool {
        matches!(
            self,
            Self::KeyedMd5 | Self::MeticulousKeyedMd5 | Self::KeyedSha1 | Self::MeticulousKeyedSha1
        )
    }
    /// True for the Meticulous variants (sequence number increments
    /// on every packet).
    pub fn is_meticulous(self) -> bool {
        matches!(self, Self::MeticulousKeyedMd5 | Self::MeticulousKeyedSha1)
    }
}

/// An authentication key. For MD5/SHA1 this is the shared secret; for
/// Simple Password it is the password itself.
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

impl AuthKey {
    /// A Simple Password key (RFC 5880 §4.2). Passwords must be 1-16
    /// bytes.
    pub fn simple_password(key_id: u8, password: &[u8]) -> Self {
        Self {
            key_id,
            data: password.to_vec(),
        }
    }
}

/// The wire representation of the auth section (RFC 5880 §4.2-§4.4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthSection {
    pub auth_type: AuthType,
    pub key_id: u8,
    /// For the keyed-hash types: the 4-byte sequence number.
    pub sequence: Option<u32>,
    /// For Simple Password: the password itself. For the keyed-hash
    /// types: the digest / hash.
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
    pub fn meticulous_keyed_md5(key_id: u8, sequence: u32, digest: Vec<u8>) -> Self {
        Self {
            auth_type: AuthType::MeticulousKeyedMd5,
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
    pub fn meticulous_keyed_sha1(key_id: u8, sequence: u32, digest: Vec<u8>) -> Self {
        Self {
            auth_type: AuthType::MeticulousKeyedSha1,
            key_id,
            sequence: Some(sequence),
            data: digest,
        }
    }

    /// Total wire length of the section (the `Auth Len` field value):
    /// Simple Password = 3 + password length; Keyed MD5 = 24;
    /// Keyed SHA1 = 28 (RFC 5880 §4.2-§4.4).
    pub fn wire_len(&self) -> usize {
        match self.auth_type {
            AuthType::SimplePassword => 3 + self.data.len(),
            AuthType::KeyedMd5 | AuthType::MeticulousKeyedMd5 => 24,
            AuthType::KeyedSha1 | AuthType::MeticulousKeyedSha1 => 28,
            AuthType::Unknown(_) => 3 + self.data.len(),
        }
    }

    /// Encode this section into `out`. Returns the number of bytes
    /// written. Validates the type-specific length constraints
    /// (1-16 byte password, 16/20 byte digests, `Auth Len` fixed for
    /// the keyed-hash types).
    pub fn encode(&self, out: &mut WriteBuf<'_>) -> Result<usize, EncodeError> {
        let len = self.wire_len();
        if out.remaining_mut() < len {
            return Err(EncodeError::BufferFull);
        }
        match self.auth_type {
            AuthType::SimplePassword => {
                if self.data.is_empty() || self.data.len() > MAX_PASSWORD_LEN {
                    return Err(EncodeError::InvalidValue("password must be 1-16 bytes"));
                }
                out.put_u8(self.auth_type.to_u8());
                out.put_u8(len as u8);
                out.put_u8(self.key_id);
                out.put_bytes(&self.data);
            }
            AuthType::KeyedMd5 | AuthType::MeticulousKeyedMd5 => {
                if self.data.len() != 16 {
                    return Err(EncodeError::InvalidValue("md5 digest must be 16 bytes"));
                }
                out.put_u8(self.auth_type.to_u8());
                out.put_u8(24);
                out.put_u8(self.key_id);
                out.put_u8(0); // reserved
                out.put_u32_be(self.sequence.unwrap_or(0));
                out.put_bytes(&self.data);
            }
            AuthType::KeyedSha1 | AuthType::MeticulousKeyedSha1 => {
                if self.data.len() != 20 {
                    return Err(EncodeError::InvalidValue("sha1 digest must be 20 bytes"));
                }
                out.put_u8(self.auth_type.to_u8());
                out.put_u8(28);
                out.put_u8(self.key_id);
                out.put_u8(0); // reserved
                out.put_u32_be(self.sequence.unwrap_or(0));
                out.put_bytes(&self.data);
            }
            AuthType::Unknown(_) => {
                return Err(EncodeError::InvalidValue("unknown auth type"));
            }
        }
        Ok(len)
    }

    /// Decode a section from `r`. Assumes `r` is positioned at the
    /// start of the auth section. The section layout and `Auth Len`
    /// value are validated per type (RFC 5880 §4.2-§4.4).
    pub fn decode(r: &mut ReadBuf<'_>) -> Result<Self, ParseError> {
        let auth_type_raw = r
            .get_u8()
            .ok_or_else(|| ParseError::truncated("bfd.auth.type"))?;
        let auth_len = r
            .get_u8()
            .ok_or_else(|| ParseError::truncated("bfd.auth.len"))? as usize;
        let auth_type = AuthType::from_u8(auth_type_raw);
        if auth_len < 3 {
            return Err(ParseError::invalid(1, "bfd.auth.len"));
        }
        let section = match auth_type {
            AuthType::SimplePassword => {
                let key_id = r
                    .get_u8()
                    .ok_or_else(|| ParseError::truncated("bfd.auth.key_id"))?;
                let pw_len = auth_len - 3;
                if pw_len == 0 || pw_len > MAX_PASSWORD_LEN {
                    return Err(ParseError::invalid(1, "bfd.auth.len"));
                }
                let data = r
                    .get_bytes(pw_len)
                    .ok_or_else(|| ParseError::truncated("bfd.auth.password"))?
                    .to_vec();
                Self {
                    auth_type,
                    key_id,
                    sequence: None,
                    data,
                }
            }
            AuthType::KeyedMd5 | AuthType::MeticulousKeyedMd5 => {
                if auth_len != 24 {
                    return Err(ParseError::invalid(1, "bfd.auth.len"));
                }
                Self::decode_keyed_hash(r, auth_type, 16)?
            }
            AuthType::KeyedSha1 | AuthType::MeticulousKeyedSha1 => {
                if auth_len != 28 {
                    return Err(ParseError::invalid(1, "bfd.auth.len"));
                }
                Self::decode_keyed_hash(r, auth_type, 20)?
            }
            AuthType::Unknown(_) => return Err(ParseError::invalid(0, "bfd.auth.type")),
        };
        Ok(section)
    }

    fn decode_keyed_hash(
        r: &mut ReadBuf<'_>,
        auth_type: AuthType,
        digest_len: usize,
    ) -> Result<Self, ParseError> {
        let key_id = r
            .get_u8()
            .ok_or_else(|| ParseError::truncated("bfd.auth.key_id"))?;
        let _reserved = r
            .get_u8()
            .ok_or_else(|| ParseError::truncated("bfd.auth.reserved"))?;
        let sequence = r
            .get_u32_be()
            .ok_or_else(|| ParseError::truncated("bfd.auth.sequence"))?;
        let data = r
            .get_bytes(digest_len)
            .ok_or_else(|| ParseError::truncated("bfd.auth.digest"))?
            .to_vec();
        Ok(Self {
            auth_type,
            key_id,
            sequence: Some(sequence),
            data,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn iana_type_codes() {
        // RFC 5880 §8: 1=Simple Password, 2=Keyed MD5, 3=Meticulous
        // Keyed MD5, 4=Keyed SHA1, 5=Meticulous Keyed SHA1.
        assert_eq!(AuthType::SimplePassword.to_u8(), 1);
        assert_eq!(AuthType::KeyedMd5.to_u8(), 2);
        assert_eq!(AuthType::MeticulousKeyedMd5.to_u8(), 3);
        assert_eq!(AuthType::KeyedSha1.to_u8(), 4);
        assert_eq!(AuthType::MeticulousKeyedSha1.to_u8(), 5);
        assert_eq!(AuthType::from_u8(2), AuthType::KeyedMd5);
        assert_eq!(AuthType::from_u8(5), AuthType::MeticulousKeyedSha1);
        assert_eq!(AuthType::from_u8(99), AuthType::Unknown(99));
    }

    #[test]
    fn simple_password_wire_bytes() {
        // §4.2: type=1, len=3+pwlen, key-id, password — NO reserved,
        // NO length byte, NO sequence.
        let s = AuthSection::simple_password(b"hunter2".to_vec(), 7);
        assert_eq!(s.wire_len(), 3 + 7);
        let mut buf = [0u8; 32];
        let mut w = WriteBuf::new(&mut buf);
        let n = s.encode(&mut w).unwrap();
        assert_eq!(n, 10);
        assert_eq!(
            &buf[..n],
            &[1, 10, 7, b'h', b'u', b'n', b't', b'e', b'r', b'2']
        );
        let mut r = ReadBuf::new(&buf[..n]);
        assert_eq!(AuthSection::decode(&mut r).unwrap(), s);
    }

    #[test]
    fn simple_password_length_bounds() {
        // Passwords must be 1..=16 bytes.
        let too_short = AuthSection::simple_password(Vec::new(), 1);
        let mut buf = [0u8; 32];
        let mut w = WriteBuf::new(&mut buf);
        assert!(too_short.encode(&mut w).is_err());

        let too_long = AuthSection::simple_password(vec![b'x'; 17], 1);
        let mut w = WriteBuf::new(&mut buf);
        assert!(too_long.encode(&mut w).is_err());
    }

    #[test]
    fn keyed_md5_wire_bytes() {
        // §4.3: type=2, len=24, key-id, reserved=0, seq(4), digest(16).
        let digest = vec![0xaau8; 16];
        let s = AuthSection::keyed_md5(7, 0xdead_beef, digest.clone());
        assert_eq!(s.wire_len(), 24);
        let mut buf = [0u8; 64];
        let mut w = WriteBuf::new(&mut buf);
        let n = s.encode(&mut w).unwrap();
        assert_eq!(n, 24);
        assert_eq!(buf[0], 2); // type = Keyed MD5
        assert_eq!(buf[1], 24); // Auth Len
        assert_eq!(buf[2], 7); // key id
        assert_eq!(buf[3], 0); // reserved
        assert_eq!(&buf[4..8], &[0xde, 0xad, 0xbe, 0xef]);
        assert_eq!(&buf[8..24], &digest[..]);
        let mut r = ReadBuf::new(&buf[..n]);
        assert_eq!(AuthSection::decode(&mut r).unwrap(), s);
    }

    #[test]
    fn keyed_sha1_wire_bytes() {
        // §4.4: type=4, len=28, key-id, reserved=0, seq(4), digest(20).
        let digest = vec![0x55u8; 20];
        let s = AuthSection::keyed_sha1(9, 1, digest.clone());
        assert_eq!(s.wire_len(), 28);
        let mut buf = [0u8; 64];
        let mut w = WriteBuf::new(&mut buf);
        let n = s.encode(&mut w).unwrap();
        assert_eq!(n, 28);
        assert_eq!(buf[0], 4);
        assert_eq!(buf[1], 28);
        assert_eq!(&buf[8..28], &digest[..]);
        let mut r = ReadBuf::new(&buf[..n]);
        assert_eq!(AuthSection::decode(&mut r).unwrap(), s);
    }

    #[test]
    fn wrong_auth_len_rejected() {
        // A Keyed MD5 section claiming Auth Len 28 is invalid.
        let digest = vec![0u8; 16];
        let s = AuthSection::keyed_md5(7, 0, digest);
        let mut buf = [0u8; 64];
        let mut w = WriteBuf::new(&mut buf);
        let n = s.encode(&mut w).unwrap();
        buf[1] = 28; // corrupt Auth Len
        let mut r = ReadBuf::new(&buf[..n]);
        assert!(AuthSection::decode(&mut r).is_err());
    }

    #[test]
    fn bad_digest_length_rejected() {
        let s = AuthSection::keyed_md5(7, 0, vec![0u8; 15]);
        let mut buf = [0u8; 64];
        let mut w = WriteBuf::new(&mut buf);
        assert!(s.encode(&mut w).is_err());
    }
}
