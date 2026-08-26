//! Well-known path attributes: ORIGIN, NEXT_HOP, MULTI_EXIT_DISC,
//! LOCAL_PREF, ATOMIC_AGGREGATE, AGGREGATOR.

use lr_core::addr::Asn;
use lr_core::addr::IpAddr;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum OriginKind {
    Igp = 0,
    Egp = 1,
    Incomplete = 2,
}

impl OriginKind {
    pub fn from_u8(v: u8) -> Option<Self> {
        Some(match v {
            0 => Self::Igp,
            1 => Self::Egp,
            2 => Self::Incomplete,
            _ => return None,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Origin(pub OriginKind);

impl Origin {
    pub fn new(k: OriginKind) -> Self {
        Self(k)
    }

    pub fn decode(b: &[u8]) -> Option<Self> {
        if b.len() != 1 {
            return None;
        }
        Some(Self(OriginKind::from_u8(b[0])?))
    }

    pub fn encode(&self) -> [u8; 1] {
        [self.0 as u8]
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NextHopKind {
    V4([u8; 4]),
    V6([u8; 16]),
    V4OverV6([u8; 16]),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct NextHop(pub NextHopKind);

impl NextHop {
    pub fn from_v4(b: [u8; 4]) -> Self {
        Self(NextHopKind::V4(b))
    }

    pub fn from_v6(b: [u8; 16]) -> Self {
        Self(NextHopKind::V6(b))
    }

    pub fn from_v4_over_v6(b: [u8; 16]) -> Self {
        Self(NextHopKind::V4OverV6(b))
    }

    pub fn to_ip(&self) -> IpAddr {
        match &self.0 {
            NextHopKind::V4(b) => IpAddr::V4(*b),
            NextHopKind::V6(b) | NextHopKind::V4OverV6(b) => IpAddr::V6(*b),
        }
    }

    pub fn decode(b: &[u8]) -> Option<Self> {
        match b.len() {
            4 => {
                let mut a = [0u8; 4];
                a.copy_from_slice(b);
                Some(Self::from_v4(a))
            }
            16 => {
                let mut a = [0u8; 16];
                a.copy_from_slice(b);
                Some(Self::from_v6(a))
            }
            32 => {
                // 16-byte V6 next-hop + 16-byte V4-over-V6 (RFC 5549 layout).
                let mut a = [0u8; 16];
                a.copy_from_slice(&b[..16]);
                Some(Self::from_v4_over_v6(a))
            }
            _ => None,
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        match &self.0 {
            NextHopKind::V4(b) => b.to_vec(),
            NextHopKind::V6(b) | NextHopKind::V4OverV6(b) => b.to_vec(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct Med(pub u32);

impl Med {
    pub fn decode(b: &[u8]) -> Option<Self> {
        if b.len() != 4 {
            return None;
        }
        Some(Self(u32::from_be_bytes([b[0], b[1], b[2], b[3]])))
    }
    pub fn encode(&self) -> [u8; 4] {
        self.0.to_be_bytes()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct LocalPref(pub u32);

impl LocalPref {
    pub fn decode(b: &[u8]) -> Option<Self> {
        if b.len() != 4 {
            return None;
        }
        Some(Self(u32::from_be_bytes([b[0], b[1], b[2], b[3]])))
    }
    pub fn encode(&self) -> [u8; 4] {
        self.0.to_be_bytes()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct AtomicAggregate;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Aggregator {
    pub asn: Asn,
    pub speaker: [u8; 4],
}

impl Aggregator {
    pub fn decode(b: &[u8]) -> Option<Self> {
        match b.len() {
            6 => Some(Self {
                asn: Asn(u16::from_be_bytes([b[0], b[1]]) as u32),
                speaker: [b[2], b[3], b[4], b[5]],
            }),
            8 => Some(Self {
                asn: Asn(u32::from_be_bytes([b[0], b[1], b[2], b[3]])),
                speaker: [b[4], b[5], b[6], b[7]],
            }),
            _ => None,
        }
    }

    pub fn encode_4(&self) -> [u8; 8] {
        let mut a = [0u8; 8];
        a[..4].copy_from_slice(&self.asn.0.to_be_bytes());
        a[4..].copy_from_slice(&self.speaker);
        a
    }
}
