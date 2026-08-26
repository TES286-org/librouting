//! BGP capabilities (RFC 5492 + RFC 4760 MP-BGP + RFC 4893 4-byte AS +
//! RFC 7911 AddPath + RFC 4724 Graceful Restart + RFC 7313 Enhanced RR).

use core::fmt;

/// Capability codes (subset; see IANA BGP Capability Codes registry).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum CapabilityCode {
    /// RFC 4760: Multiprotocol extensions
    MultiprotocolExtensions = 1,
    /// RFC 2918: Route refresh
    RouteRefresh = 2,
    /// RFC 5492: Extended message support
    ExtendedMessage = 6,
    /// RFC 4724: Graceful restart
    GracefulRestart = 64,
    /// RFC 4893: 4-byte AS number
    FourOctetAs = 65,
    /// RFC 7313: Enhanced route refresh
    EnhancedRouteRefresh = 70,
    /// RFC 7911: AddPath
    AddPath = 69,
    /// RFC 8277 / 8533: Long-Lived Graceful Restart
    LongLivedGracefulRestart = 72,
    /// Unknown
    Other(u8),
}

impl CapabilityCode {
    pub fn from_u8(v: u8) -> Self {
        match v {
            1 => Self::MultiprotocolExtensions,
            2 => Self::RouteRefresh,
            6 => Self::ExtendedMessage,
            64 => Self::GracefulRestart,
            65 => Self::FourOctetAs,
            70 => Self::EnhancedRouteRefresh,
            69 => Self::AddPath,
            72 => Self::LongLivedGracefulRestart,
            _ => Self::Other(v),
        }
    }
}

impl fmt::Display for CapabilityCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "CapabilityCode({})", self.to_u8())
    }
}

impl CapabilityCode {
    pub fn to_u8(self) -> u8 {
        match self {
            Self::MultiprotocolExtensions => 1,
            Self::RouteRefresh => 2,
            Self::ExtendedMessage => 6,
            Self::GracefulRestart => 64,
            Self::FourOctetAs => 65,
            Self::EnhancedRouteRefresh => 70,
            Self::AddPath => 69,
            Self::LongLivedGracefulRestart => 72,
            Self::Other(v) => v,
        }
    }
}

/// A capability as carried in the OPEN optional parameter (RFC 5492).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Capability {
    pub code: CapabilityCode,
    pub value: Vec<u8>,
}

impl Capability {
    pub fn new(code: CapabilityCode, value: Vec<u8>) -> Self {
        Self { code, value }
    }

    /// 4-byte AS capability (RFC 4893). Value = 4-byte ASN.
    pub fn four_octet_as(asn: u32) -> Self {
        Self::new(CapabilityCode::FourOctetAs, asn.to_be_bytes().to_vec())
    }

    pub fn as_four_octet(&self) -> Option<u32> {
        if self.code != CapabilityCode::FourOctetAs || self.value.len() != 4 {
            return None;
        }
        Some(u32::from_be_bytes([
            self.value[0],
            self.value[1],
            self.value[2],
            self.value[3],
        ]))
    }

    /// Multiprotocol capability (RFC 4760). Value = AFI(2) | reserved(1) | SAFI(1).
    pub fn multiprotocol(afi: u16, safi: u8) -> Self {
        let mut v = Vec::with_capacity(4);
        v.extend_from_slice(&afi.to_be_bytes());
        v.push(0);
        v.push(safi);
        Self::new(CapabilityCode::MultiprotocolExtensions, v)
    }

    pub fn as_multiprotocol(&self) -> Option<(u16, u8)> {
        if self.code != CapabilityCode::MultiprotocolExtensions || self.value.len() != 4 {
            return None;
        }
        let afi = u16::from_be_bytes([self.value[0], self.value[1]]);
        let safi = self.value[3];
        Some((afi, safi))
    }

    pub fn route_refresh() -> Self {
        Self::new(CapabilityCode::RouteRefresh, Vec::new())
    }

    /// AddPath capability (RFC 7911 §4.4). Value = repeated (AFI:2, SAFI:1, send:1, recv:1).
    pub fn add_path(families: &[(u16, u8, bool, bool)]) -> Self {
        let mut v = Vec::with_capacity(families.len() * 5);
        for (afi, safi, send, recv) in families {
            v.extend_from_slice(&afi.to_be_bytes());
            v.push(*safi);
            v.push(*send as u8);
            v.push(*recv as u8);
        }
        Self::new(CapabilityCode::AddPath, v)
    }

    /// Enhanced Route Refresh capability (RFC 7313, code 70).
    pub fn enhanced_rr() -> Self {
        Self::new(CapabilityCode::EnhancedRouteRefresh, Vec::new())
    }

    /// Graceful Restart capability (RFC 4724 §3). `restart_time_secs` is a
    /// 12-bit field; the high nibble contains capability flags.
    pub fn graceful_restart(restart_flags: u8, restart_time_secs: u16) -> Self {
        let encoded = (u16::from(restart_flags & 0x0f) << 12) | (restart_time_secs & 0x0fff);
        Self::new(
            CapabilityCode::GracefulRestart,
            encoded.to_be_bytes().to_vec(),
        )
    }

    /// Decode the RFC 4724 restart flags and time from a capability.
    pub fn as_graceful_restart(&self) -> Option<(u8, u16)> {
        if self.code != CapabilityCode::GracefulRestart || self.value.len() < 2 {
            return None;
        }
        let encoded = u16::from_be_bytes([self.value[0], self.value[1]]);
        Some(((encoded >> 12) as u8, encoded & 0x0fff))
    }

    /// Encode all capabilities as the OPEN optional-parameter value
    /// (param_type=2). Each capability is encoded as
    /// `(code:1, len:1, value:0..)` per RFC 5492 §3.
    pub fn encode_set(set: &[Capability]) -> Vec<u8> {
        let mut out = Vec::new();
        for c in set {
            out.push(c.code.to_u8());
            out.push(c.value.len() as u8);
            out.extend_from_slice(&c.value);
        }
        out
    }

    /// Decode the value field of an OPEN optional parameter of type 2.
    pub fn decode_set(value: &[u8]) -> Vec<Capability> {
        let mut out = Vec::new();
        let mut i = 0;
        while i + 1 < value.len() {
            let code = CapabilityCode::from_u8(value[i]);
            let len = value[i + 1] as usize;
            i += 2;
            if i + len > value.len() {
                break;
            }
            out.push(Capability::new(code, value[i..i + len].to_vec()));
            i += len;
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn four_octet_as_roundtrip() {
        let cap = Capability::four_octet_as(70000);
        let v = Capability::encode_set(&[cap]);
        let dec = Capability::decode_set(&v);
        assert_eq!(dec.len(), 1);
        assert_eq!(dec[0].as_four_octet(), Some(70000));
    }

    #[test]
    fn multiprotocol_roundtrip() {
        let cap = Capability::multiprotocol(2, 1);
        let v = Capability::encode_set(&[cap]);
        let dec = Capability::decode_set(&v);
        assert_eq!(dec.len(), 1);
        assert_eq!(dec[0].as_multiprotocol(), Some((2, 1)));
    }
}
