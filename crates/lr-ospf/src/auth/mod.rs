//! Authentication strategies for OSPF (RFC 2328 §D, RFC 5709 HMAC-SHA,
//! RFC 4552 IPsec for v3 — out of scope here).

use core::fmt;

/// OSPFv2 AuType (RFC 2328 §D.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum AuType {
    Null = 0,
    SimplePassword = 1,
    /// MD5 crypto (RFC 2328 §D.3).
    Md5 = 2,
}

impl AuType {
    pub fn from_u16(v: u16) -> Self {
        match v {
            1 => Self::SimplePassword,
            2 => Self::Md5,
            _ => Self::Null,
        }
    }
}

/// Auth trait — let the embedder verify/insert auth data per packet.
pub trait Auth: fmt::Debug + Send + Sync {
    /// Verify the auth fields of a received packet header.
    fn verify(&self, header: &[u8], body: &[u8]) -> bool;
    /// Produce the au_type field value.
    fn au_type(&self) -> AuType;
    /// Mutate outgoing header bytes with auth data (MD5 digest, password, etc.).
    fn sign(&self, header: &mut [u8], body: &[u8]);
}

#[derive(Debug, Default)]
pub struct NullAuth;

impl Auth for NullAuth {
    fn verify(&self, _header: &[u8], _body: &[u8]) -> bool {
        true
    }
    fn au_type(&self) -> AuType {
        AuType::Null
    }
    fn sign(&self, _header: &mut [u8], _body: &[u8]) {}
}

#[derive(Debug, Clone)]
pub struct SimplePassword {
    pub password: [u8; 8],
}

impl Auth for SimplePassword {
    fn verify(&self, header: &[u8], _body: &[u8]) -> bool {
        // The 8-byte auth_data field is at offsets 16..24 of the header.
        if header.len() < 24 {
            return false;
        }
        header[16..24] == self.password
    }
    fn au_type(&self) -> AuType {
        AuType::SimplePassword
    }
    fn sign(&self, header: &mut [u8], _body: &[u8]) {
        if header.len() < 24 {
            return;
        }
        header[16..24].copy_from_slice(&self.password);
    }
}
