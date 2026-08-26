//! Standard (RFC 1997), Extended (RFC 4360/6675) and Large (RFC 8097)
//! communities.
//!
//! Standard community: 4 bytes, hi 2 = AS, lo 2 = value.
//! Extended: 8 bytes, type:subtype:global:local.
//! Large: 12 bytes, global_admin:local_part1:local_part2.

use core::fmt;

/// BGP standard community.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Community(pub u32);

impl Community {
    pub const NO_EXPORT: Self = Self(0xffff_ff01);
    pub const NO_ADVERTISE: Self = Self(0xffff_ff02);
    pub const NO_EXPORT_SUBCONFED: Self = Self(0xffff_ff03);
    pub const NOPEER: Self = Self(0xffff_ff04);
    pub const PLANNED_SHUTDOWN: Self = Self(0xffff_0000);

    pub fn new(asn: u16, value: u16) -> Self {
        Self(((asn as u32) << 16) | value as u32)
    }

    pub fn from_u32(v: u32) -> Self {
        Self(v)
    }

    pub fn as_u32(self) -> u32 {
        self.0
    }

    pub fn kind(self) -> CommunityKind {
        if self.0 == Self::NO_EXPORT.0 {
            CommunityKind::NoExport
        } else if self.0 == Self::NO_ADVERTISE.0 {
            CommunityKind::NoAdvertise
        } else if self.0 == Self::NO_EXPORT_SUBCONFED.0 {
            CommunityKind::NoExportSubconfed
        } else if self.0 == Self::NOPEER.0 {
            CommunityKind::NoPeer
        } else {
            CommunityKind::Custom
        }
    }

    pub fn decode_set(b: &[u8]) -> Vec<Self> {
        let mut out = Vec::with_capacity(b.len() / 4);
        for chunk in b.as_chunks::<4>().0 {
            let v = u32::from_be_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
            out.push(Self(v));
        }
        out
    }

    pub fn encode_set(set: &[Self]) -> Vec<u8> {
        let mut out = Vec::with_capacity(set.len() * 4);
        for c in set {
            out.extend_from_slice(&c.0.to_be_bytes());
        }
        out
    }
}

impl fmt::Display for Community {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.kind() {
            CommunityKind::NoExport => f.write_str("no-export"),
            CommunityKind::NoAdvertise => f.write_str("no-advertise"),
            CommunityKind::NoExportSubconfed => f.write_str("no-export-subconfed"),
            CommunityKind::NoPeer => f.write_str("no-peer"),
            CommunityKind::Custom => {
                let asn = (self.0 >> 16) as u16;
                let val = (self.0 & 0xffff) as u16;
                write!(f, "{}:{}", asn, val)
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CommunityKind {
    NoExport,
    NoAdvertise,
    NoExportSubconfed,
    NoPeer,
    Custom,
}

/// BGP extended community. 8 bytes wire-format.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ExtendedCommunity {
    pub kind: u8,
    pub subtype: u8,
    pub global: u32,
    pub local: u16,
}

impl ExtendedCommunity {
    pub fn new(kind: u8, subtype: u8, global: u32, local: u16) -> Self {
        Self {
            kind,
            subtype,
            global,
            local,
        }
    }

    pub fn decode_set(b: &[u8]) -> Vec<Self> {
        let mut out = Vec::with_capacity(b.len() / 8);
        for chunk in b.as_chunks::<8>().0 {
            let kind = chunk[0];
            let subtype = chunk[1];
            let global = u32::from_be_bytes([chunk[2], chunk[3], chunk[4], chunk[5]]);
            let local = u16::from_be_bytes([chunk[6], chunk[7]]);
            out.push(Self {
                kind,
                subtype,
                global,
                local,
            });
        }
        out
    }

    pub fn encode_set(set: &[Self]) -> Vec<u8> {
        let mut out = Vec::with_capacity(set.len() * 8);
        for c in set {
            out.push(c.kind);
            out.push(c.subtype);
            out.extend_from_slice(&c.global.to_be_bytes());
            out.extend_from_slice(&c.local.to_be_bytes());
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn standard_community_roundtrip() {
        let set = vec![Community::NO_EXPORT, Community::new(64512, 100)];
        let enc = Community::encode_set(&set);
        let dec = Community::decode_set(&enc);
        assert_eq!(dec, set);
    }

    #[test]
    fn extended_community_roundtrip() {
        let set = vec![
            ExtendedCommunity::new(0x00, 0x02, 64512, 100),
            ExtendedCommunity::new(0x01, 0x03, 0xdeadbeef, 0xbeef),
        ];
        let enc = ExtendedCommunity::encode_set(&set);
        let dec = ExtendedCommunity::decode_set(&enc);
        assert_eq!(dec, set);
    }
}
