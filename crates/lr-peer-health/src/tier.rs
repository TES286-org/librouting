//! Degradation tier (issue #99 §Layered degradation).
//!
//! `L0` is normal; `L1`–`L3` are progressively more degraded. The
//! tier is stamped onto a route by the import hook as a private
//! `AttrType::LrPeerHealthTier` byte (1 byte, value `0..=3`); the
//! codec strips it at encode so peers never see it.

use core::fmt;

/// Degradation tier. `L0` is normal; higher tiers are worse.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[repr(u8)]
pub enum PeerHealthTier {
    #[default]
    L0 = 0,
    L1 = 1,
    L2 = 2,
    L3 = 3,
}

pub const MAX_TIER: PeerHealthTier = PeerHealthTier::L3;

impl PeerHealthTier {
    pub fn as_u8(self) -> u8 {
        self as u8
    }

    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::L0),
            1 => Some(Self::L1),
            2 => Some(Self::L2),
            3 => Some(Self::L3),
            _ => None,
        }
    }

    pub fn next(self) -> Option<Self> {
        match self {
            Self::L0 => Some(Self::L1),
            Self::L1 => Some(Self::L2),
            Self::L2 => Some(Self::L3),
            Self::L3 => None,
        }
    }

    pub fn prev(self) -> Option<Self> {
        match self {
            Self::L0 => None,
            Self::L1 => Some(Self::L0),
            Self::L2 => Some(Self::L1),
            Self::L3 => Some(Self::L2),
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::L0 => "L0",
            Self::L1 => "L1",
            Self::L2 => "L2",
            Self::L3 => "L3",
        }
    }
}

impl fmt::Display for PeerHealthTier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn next_and_prev() {
        assert_eq!(PeerHealthTier::L0.next(), Some(PeerHealthTier::L1));
        assert_eq!(PeerHealthTier::L1.next(), Some(PeerHealthTier::L2));
        assert_eq!(PeerHealthTier::L2.next(), Some(PeerHealthTier::L3));
        assert_eq!(PeerHealthTier::L3.next(), None);
        assert_eq!(PeerHealthTier::L0.prev(), None);
        assert_eq!(PeerHealthTier::L1.prev(), Some(PeerHealthTier::L0));
        assert_eq!(PeerHealthTier::L3.prev(), Some(PeerHealthTier::L2));
    }

    #[test]
    fn round_trip_u8() {
        for v in 0..=3u8 {
            let t = PeerHealthTier::from_u8(v).unwrap();
            assert_eq!(t.as_u8(), v);
        }
        assert!(PeerHealthTier::from_u8(4).is_none());
    }
}
