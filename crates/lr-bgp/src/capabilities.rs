//! BGP capabilities (RFC 5492 + RFC 4760 MP-BGP + RFC 4893 4-byte AS +
//! RFC 7911 AddPath + RFC 4724 Graceful Restart + RFC 7313 Enhanced RR +
//! RFC 5549 Extended Next-Hop + RFC 9494 Long-Lived Graceful Restart).

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
    /// RFC 5549: Extended Next-Hop for IPv4 NLRI over IPv6 transport
    ExtendedNextHop = 5,
    /// RFC 4724: Graceful restart
    GracefulRestart = 64,
    /// RFC 4893: 4-byte AS number
    FourOctetAs = 65,
    /// RFC 7313: Enhanced route refresh
    EnhancedRouteRefresh = 70,
    /// RFC 7911: AddPath
    AddPath = 69,
    /// RFC 9494: Long-Lived Graceful Restart
    LongLivedGracefulRestart = 71,
    /// Unknown
    Other(u8),
}

impl CapabilityCode {
    pub fn from_u8(v: u8) -> Self {
        match v {
            1 => Self::MultiprotocolExtensions,
            2 => Self::RouteRefresh,
            5 => Self::ExtendedNextHop,
            6 => Self::ExtendedMessage,
            64 => Self::GracefulRestart,
            65 => Self::FourOctetAs,
            70 => Self::EnhancedRouteRefresh,
            69 => Self::AddPath,
            71 => Self::LongLivedGracefulRestart,
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
            Self::ExtendedNextHop => 5,
            Self::ExtendedMessage => 6,
            Self::GracefulRestart => 64,
            Self::FourOctetAs => 65,
            Self::EnhancedRouteRefresh => 70,
            Self::AddPath => 69,
            Self::LongLivedGracefulRestart => 71,
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

    /// Extended Next-Hop capability (RFC 5549 §2). The value is a
    /// sequence of 5-byte tuples `<NLRI AFI:2, NLRI SAFI:1, Nexthop
    /// AFI:2>`. A tuple `(1, 1, 2)` says "IPv4 unicast NLRI may be
    /// resolved over an IPv6 next-hop."
    pub fn extended_next_hop(tuples: &[(u16, u8, u16)]) -> Self {
        let mut v = Vec::with_capacity(tuples.len() * 5);
        for (nlri_afi, nlri_safi, nh_afi) in tuples {
            v.extend_from_slice(&nlri_afi.to_be_bytes());
            v.push(*nlri_safi);
            v.extend_from_slice(&nh_afi.to_be_bytes());
        }
        Self::new(CapabilityCode::ExtendedNextHop, v)
    }

    /// Decode the RFC 5549 Extended Next-Hop capability value into its
    /// `(NLRI AFI, NLRI SAFI, Nexthop AFI)` tuples. Returns `None` when
    /// the value length is not a multiple of 5.
    pub fn as_extended_next_hop(&self) -> Option<Vec<(u16, u8, u16)>> {
        if self.code != CapabilityCode::ExtendedNextHop
            || !self.value.len().is_multiple_of(5)
        {
            return None;
        }
        let mut out = Vec::with_capacity(self.value.len() / 5);
        for t in self.value.as_chunks::<5>().0 {
            let nlri_afi = u16::from_be_bytes([t[0], t[1]]);
            let nlri_safi = t[2];
            let nh_afi = u16::from_be_bytes([t[3], t[4]]);
            out.push((nlri_afi, nlri_safi, nh_afi));
        }
        Some(out)
    }

    pub fn route_refresh() -> Self {
        Self::new(CapabilityCode::RouteRefresh, Vec::new())
    }

    /// AddPath capability (RFC 7911 §4.4). Value = repeated
    /// `<AFI:2, SAFI:1, Send/Receive:1>` tuples where the Send/Receive
    /// field is 1 = receive (willing to receive multiple paths),
    /// 2 = send, 3 = both.
    pub fn add_path(families: &[(u16, u8, bool, bool)]) -> Self {
        let mut v = Vec::with_capacity(families.len() * 4);
        for (afi, safi, send, recv) in families {
            v.extend_from_slice(&afi.to_be_bytes());
            v.push(*safi);
            v.push((*recv as u8) | ((*send as u8) << 1));
        }
        Self::new(CapabilityCode::AddPath, v)
    }

    /// Enhanced Route Refresh capability (RFC 7313, code 70).
    pub fn enhanced_rr() -> Self {
        Self::new(CapabilityCode::EnhancedRouteRefresh, Vec::new())
    }

    /// Decode the RFC 7911 AddPath capability (code 69): a sequence of
    /// `<AFI:2, SAFI:1, Send/Receive:1>` tuples. The Send/Receive field is
    /// 1 = receive (the sender is willing to receive multiple paths),
    /// 2 = send, 3 = both (RFC 7911 §4.4). Returns `(afi, safi, send,
    /// recv)` per family.
    pub fn as_add_path(&self) -> Option<Vec<(u16, u8, bool, bool)>> {
        if self.code != CapabilityCode::AddPath || self.value.is_empty() {
            return None;
        }
        let mut out = Vec::new();
        for t in self.value.as_chunks::<4>().0 {
            let afi = u16::from_be_bytes([t[0], t[1]]);
            let send = t[3] & 0x02 != 0;
            let recv = t[3] & 0x01 != 0;
            out.push((afi, t[2], send, recv));
        }
        Some(out)
    }

    /// Graceful Restart capability (RFC 4724 §3). `restart_flags` is a
    /// 4-bit field (bit 0x8 = Restart State, R); `restart_time_secs` is a
    /// 12-bit field. `families` lists `(afi, safi, forwarding_state)`
    /// tuples — a family is only listed when the speaker can preserve its
    /// state; per RFC 4724 §4.2 the receiving speaker retains routes
    /// exactly for the listed families.
    pub fn graceful_restart(
        restart_flags: u8,
        restart_time_secs: u16,
        families: &[(u16, u8, bool)],
    ) -> Self {
        let encoded = (u16::from(restart_flags & 0x0f) << 12) | (restart_time_secs & 0x0fff);
        let mut v = encoded.to_be_bytes().to_vec();
        v.reserve(families.len() * 4);
        for (afi, safi, forwarding) in families {
            v.extend_from_slice(&afi.to_be_bytes());
            v.push(*safi);
            v.push(Self::GR_AF_FLAG_F * *forwarding as u8);
        }
        Self::new(CapabilityCode::GracefulRestart, v)
    }

    /// AF flags bit (RFC 4724 §3): forwarding state preserved for the
    /// address family.
    const GR_AF_FLAG_F: u8 = 0x80;

    /// Decode the RFC 4724 restart flags and time from a capability.
    pub fn as_graceful_restart(&self) -> Option<(u8, u16)> {
        if self.code != CapabilityCode::GracefulRestart || self.value.len() < 2 {
            return None;
        }
        let encoded = u16::from_be_bytes([self.value[0], self.value[1]]);
        Some(((encoded >> 12) as u8, encoded & 0x0fff))
    }

    /// Decode the RFC 4724 per-address-family tuples: `(afi, safi,
    /// forwarding_state)`. An empty list means GR was negotiated without
    /// retaining any family (RFC 4724 §4.2: nothing is retained).
    pub fn as_graceful_restart_families(&self) -> Option<Vec<(u16, u8, bool)>> {
        if self.code != CapabilityCode::GracefulRestart || self.value.len() < 2 {
            return None;
        }
        let mut out = Vec::new();
        for t in self.value[2..].as_chunks::<4>().0 {
            let afi = u16::from_be_bytes([t[0], t[1]]);
            out.push((afi, t[2], t[3] & Self::GR_AF_FLAG_F != 0));
        }
        Some(out)
    }

    /// Long-Lived Graceful Restart capability (RFC 9494 §3.1). The value is
    /// a sequence of `<AFI:2, SAFI:1, Flags:1, LLST:3>` tuples, where the
    /// flags field carries the F bit (0x80) and LLST is a 24-bit stale time
    /// in seconds.
    pub fn long_lived_gr(families: &[(u16, u8, bool, u32)]) -> Self {
        let mut v = Vec::with_capacity(families.len() * 7);
        for (afi, safi, forwarding, stale_time) in families {
            v.extend_from_slice(&afi.to_be_bytes());
            v.push(*safi);
            v.push(Self::llgr_flags(*forwarding));
            v.extend_from_slice(&stale_time.to_be_bytes()[1..]); // low 24 bits
        }
        Self::new(CapabilityCode::LongLivedGracefulRestart, v)
    }

    /// F bit (RFC 9494 §3.1): forwarding state preserved during restart.
    const LLGR_FLAG_F: u8 = 0x80;

    fn llgr_flags(forwarding: bool) -> u8 {
        Self::LLGR_FLAG_F * forwarding as u8
    }

    /// Decode the RFC 9494 LLGR tuples: `(afi, safi, forwarding_bit,
    /// stale_time_secs)` per address family.
    pub fn as_long_lived_gr(&self) -> Option<Vec<(u16, u8, bool, u32)>> {
        if self.code != CapabilityCode::LongLivedGracefulRestart
            || !self.value.len().is_multiple_of(7)
        {
            return None;
        }
        let mut out = Vec::with_capacity(self.value.len() / 7);
        for t in self.value.as_chunks::<7>().0 {
            let afi = u16::from_be_bytes([t[0], t[1]]);
            let safi = t[2];
            let forwarding = t[3] & Self::LLGR_FLAG_F != 0;
            let stale_time = u32::from_be_bytes([0, t[4], t[5], t[6]]);
            out.push((afi, safi, forwarding, stale_time));
        }
        Some(out)
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

    /// RFC 5549 §2: capability code 5, value = repeated
    /// `<NLRI AFI:2, NLRI SAFI:1, Nexthop AFI:2>` 5-byte tuples.
    #[test]
    fn extended_next_hop_roundtrip() {
        let cap = Capability::extended_next_hop(&[(1, 1, 2)]);
        assert_eq!(cap.code.to_u8(), 5);
        assert_eq!(CapabilityCode::from_u8(5), CapabilityCode::ExtendedNextHop);
        assert_eq!(cap.value.len(), 5);
        let v = Capability::encode_set(&[cap]);
        let dec = Capability::decode_set(&v);
        assert_eq!(dec.len(), 1);
        assert_eq!(dec[0].as_extended_next_hop(), Some(vec![(1, 1, 2)]));
    }

    #[test]
    fn extended_next_hop_multiple_tuples() {
        let cap = Capability::extended_next_hop(&[(1, 1, 2), (1, 1, 25), (1, 128, 2)]);
        assert_eq!(cap.value.len(), 15);
        let v = Capability::encode_set(&[cap]);
        let dec = Capability::decode_set(&v);
        assert_eq!(
            dec[0].as_extended_next_hop(),
            Some(vec![(1, 1, 2), (1, 1, 25), (1, 128, 2)])
        );
    }

    /// Malformed values (not a multiple of 5) must be rejected.
    #[test]
    fn extended_next_hop_rejects_malformed_value() {
        let cap = Capability::new(CapabilityCode::ExtendedNextHop, vec![1, 2, 3, 4]);
        assert!(cap.as_extended_next_hop().is_none());
    }

    #[test]
    fn long_lived_gr_roundtrip() {
        // RFC 9494 §3.1: capability code 71, 7-byte tuples.
        let cap = Capability::long_lived_gr(&[(1, 1, true, 3600), (2, 1, false, 0xffffff)]);
        let v = Capability::encode_set(&[cap]);
        let dec = Capability::decode_set(&v);
        assert_eq!(dec.len(), 1);
        assert_eq!(dec[0].code, CapabilityCode::LongLivedGracefulRestart);
        assert_eq!(dec[0].value.len(), 14);
        let tuples = dec[0].as_long_lived_gr().unwrap();
        assert_eq!(tuples[0], (1, 1, true, 3600));
        assert_eq!(tuples[1], (2, 1, false, 0xffffff));
    }

    #[test]
    fn long_lived_gr_capability_code_is_71() {
        // RFC 9494 / IANA: 71 = Long-Lived Graceful Restart. (72 is
        // Routing Policy Distribution — a historical mix-up.)
        let cap = Capability::long_lived_gr(&[(1, 1, true, 10)]);
        assert_eq!(cap.code.to_u8(), 71);
        assert_eq!(
            CapabilityCode::from_u8(71),
            CapabilityCode::LongLivedGracefulRestart
        );
    }

    #[test]
    fn long_lived_gr_rejects_malformed_value() {
        let cap = Capability::new(CapabilityCode::LongLivedGracefulRestart, vec![1, 2, 3]);
        assert!(cap.as_long_lived_gr().is_none());
    }

    /// RFC 4724 §3: the GR capability carries per-address-family tuples
    /// with the Forwarding State (F) bit; receivers retain routes exactly
    /// for the listed families (§4.2).
    #[test]
    fn graceful_restart_lists_address_families() {
        let cap = Capability::graceful_restart(0, 120, &[(1, 1, true), (2, 1, false)]);
        let v = Capability::encode_set(&[cap]);
        let dec = Capability::decode_set(&v);
        assert_eq!(dec.len(), 1);
        assert_eq!(dec[0].value.len(), 10); // 2 + 2 * 4
        assert_eq!(dec[0].as_graceful_restart(), Some((0, 120)));
        assert_eq!(
            dec[0].as_graceful_restart_families(),
            Some(vec![(1, 1, true), (2, 1, false)])
        );
    }

    /// A GR capability without family tuples negotiates GR but retains
    /// nothing (the historical encoding this library used to emit).
    #[test]
    fn graceful_restart_empty_family_list_is_empty() {
        let cap = Capability::graceful_restart(0, 90, &[]);
        assert_eq!(cap.value.len(), 2);
        assert_eq!(cap.as_graceful_restart_families(), Some(vec![]));
    }
}
