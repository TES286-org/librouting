//! Standard (RFC 1997), Extended (RFC 4360/6675) and Large (RFC 8097)
//! communities.
//!
//! Standard community: 4 bytes, hi 2 = AS, lo 2 = value.
//! Extended: 8 bytes, type:subtype:global:local.
//! Large: 12 bytes, global_admin:local_part1:local_part2.
//!
//! Well-known community aliases (RFC 8326 §4): the
//! `GRACEFUL_SHUTDOWN` community standardised in RFC 8326 has wire
//! value `0xFFFF:0000`. The same wire value was called
//! `PLANNED_SHUTDOWN` in earlier drafts (draft-ietf-idr-shutdown);
//! both names are kept as aliases so config files that use either
//! name work without surprises.

use core::fmt;

/// BGP standard community.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Community(pub u32);

impl Community {
    pub const NO_EXPORT: Self = Self(0xffff_ff01);
    pub const NO_ADVERTISE: Self = Self(0xffff_ff02);
    pub const NO_EXPORT_SUBCONFED: Self = Self(0xffff_ff03);
    pub const NOPEER: Self = Self(0xffff_ff04);
    /// RFC 8326 §4 `GRACEFUL_SHUTDOWN` (`0xFFFF:0000`).
    ///
    /// Carried on a route to signal that the advertising speaker is
    /// in the process of shutting down the session. Receivers SHOULD
    /// treat the route as least-preferred (e.g. set LOCAL_PREF to
    /// zero locally) so transit traffic shifts to alternative paths
    /// before the session actually goes down. Senders SHOULD also set
    /// LOCAL_PREF to zero on the export copy so the signal is visible
    /// to downstream peers. The export hook that does this lives in
    /// `lr_policy::hooks::GracefulShutdownExportHook`.
    pub const GRACEFUL_SHUTDOWN: Self = Self(0xffff_0000);
    /// Legacy alias for [`Self::GRACEFUL_SHUTDOWN`]. Pre-RFC-8326
    /// drafts named this community `PLANNED_SHUTDOWN`; the wire value
    /// is unchanged.
    pub const PLANNED_SHUTDOWN: Self = Self(0xffff_0000);
    /// RFC 9494 §3.2: marks a long-lived stale route (least preferred).
    pub const LLGR_STALE: Self = Self(0xffff_0006);
    /// RFC 9494 §3.3: opts a route out of long-lived graceful restart.
    pub const NO_LLGR: Self = Self(0xffff_0007);

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
        } else if self.0 == Self::GRACEFUL_SHUTDOWN.0 {
            CommunityKind::GracefulShutdown
        } else if self.0 == Self::LLGR_STALE.0 {
            CommunityKind::LlgrStale
        } else if self.0 == Self::NO_LLGR.0 {
            CommunityKind::NoLlgr
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
            CommunityKind::GracefulShutdown => f.write_str("graceful-shutdown"),
            CommunityKind::LlgrStale => f.write_str("llgr-stale"),
            CommunityKind::NoLlgr => f.write_str("no-llgr"),
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
    /// RFC 8326 §4 `GRACEFUL_SHUTDOWN` (`0xFFFF:0000`).
    ///
    /// Honoured by `lr_policy::hooks::GracefulShutdownExportHook` on
    /// the send side (set LOCAL_PREF to zero so receivers prefer
    /// alternatives) and by the import path on the receive side
    /// (treat as least-preferred during best-path selection).
    GracefulShutdown,
    /// RFC 9494 §3.2 `LLGR_STALE` (0xFFFF0006).
    LlgrStale,
    /// RFC 9494 §3.3 `NO_LLGR` (0xFFFF0007).
    NoLlgr,
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

/// BGP Large Community (RFC 8097 §2). 12 bytes wire format:
/// `global_admin:local_data1:local_data2`, each a 4-octet field, so
/// 4-byte ASNs fit without AS_TRANS shenanigans.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct LargeCommunity {
    /// Global administrator — typically the 4-octet AS that defined
    /// the community.
    pub global_admin: u32,
    pub local_data1: u32,
    pub local_data2: u32,
}

impl LargeCommunity {
    pub const fn new(global_admin: u32, local_data1: u32, local_data2: u32) -> Self {
        Self {
            global_admin,
            local_data1,
            local_data2,
        }
    }

    /// Decode a whole LARGE_COMMUNITIES attribute value. Trailing
    /// partial records (len % 12 != 0) are ignored, mirroring the
    /// tolerant decode of the other community attributes.
    pub fn decode_set(b: &[u8]) -> Vec<Self> {
        let mut out = Vec::with_capacity(b.len() / 12);
        for chunk in b.as_chunks::<12>().0 {
            out.push(Self {
                global_admin: u32::from_be_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]),
                local_data1: u32::from_be_bytes([chunk[4], chunk[5], chunk[6], chunk[7]]),
                local_data2: u32::from_be_bytes([chunk[8], chunk[9], chunk[10], chunk[11]]),
            });
        }
        out
    }

    pub fn encode_set(set: &[Self]) -> Vec<u8> {
        let mut out = Vec::with_capacity(set.len() * 12);
        for c in set {
            out.extend_from_slice(&c.global_admin.to_be_bytes());
            out.extend_from_slice(&c.local_data1.to_be_bytes());
            out.extend_from_slice(&c.local_data2.to_be_bytes());
        }
        out
    }
}

impl fmt::Display for LargeCommunity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}:{}:{}",
            self.global_admin, self.local_data1, self.local_data2
        )
    }
}

impl fmt::Display for ExtendedCommunity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}:{}", self.kind, self.global, self.local)
    }
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
    fn large_community_roundtrip_and_wire_form() {
        // RFC 8097 §2: 12-byte records, big-endian per component.
        let set = vec![
            LargeCommunity::new(64512, 100, 200),
            LargeCommunity::new(4200000000, 1, 2),
        ];
        let enc = LargeCommunity::encode_set(&set);
        assert_eq!(enc.len(), 24);
        // First record's wire bytes: 64512:100:200 big-endian.
        assert_eq!(
            &enc[..12],
            &[0x00, 0x00, 0xFC, 0x00, 0x00, 0x00, 0x00, 0x64, 0x00, 0x00, 0x00, 0xC8][..]
        );
        let dec = LargeCommunity::decode_set(&enc);
        assert_eq!(dec, set);
        // Trailing partial record is ignored (tolerant decode).
        assert_eq!(LargeCommunity::decode_set(&enc[..14]).len(), 1);
        assert_eq!(
            LargeCommunity::new(64512, 100, 200).to_string(),
            "64512:100:200"
        );
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

    #[test]
    fn llgr_communities_display_and_classify() {
        // RFC 9494 §3.2/§3.3 wire values.
        assert_eq!(Community::LLGR_STALE.0, 0xffff0006);
        assert_eq!(Community::NO_LLGR.0, 0xffff0007);
        assert_eq!(Community::LLGR_STALE.to_string(), "llgr-stale");
        assert_eq!(Community::NO_LLGR.to_string(), "no-llgr");
        assert_eq!(Community::LLGR_STALE.kind(), CommunityKind::LlgrStale);
        assert_eq!(Community::NO_LLGR.kind(), CommunityKind::NoLlgr);
    }

    #[test]
    fn graceful_shutdown_alias_and_classification() {
        // RFC 8326 §4: GRACEFUL_SHUTDOWN == 0xFFFF:0000. The
        // pre-RFC draft name `PLANNED_SHUTDOWN` is kept as an alias
        // for the same wire value so config files using either
        // name round-trip identically.
        assert_eq!(Community::GRACEFUL_SHUTDOWN.0, 0xffff_0000);
        assert_eq!(Community::PLANNED_SHUTDOWN.0, 0xffff_0000);
        assert_eq!(Community::GRACEFUL_SHUTDOWN, Community::PLANNED_SHUTDOWN);
        assert_eq!(
            Community::GRACEFUL_SHUTDOWN.kind(),
            CommunityKind::GracefulShutdown
        );
        // Display renders the RFC 8326 name, not the legacy alias.
        assert_eq!(
            Community::GRACEFUL_SHUTDOWN.to_string(),
            "graceful-shutdown"
        );
    }
}
