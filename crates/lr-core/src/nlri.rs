//! Generic NLRI envelope. Per-protocol crates carry their own typed NLRI
//! structs; this enum lets the RIB hold any of them.

use crate::addr::{IpAddr, Prefix};

/// Address family identifier (AFI) + subsequent AFI (SAFI). RFC 4760.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct NlriFamily {
    pub afi: u16,
    pub safi: u8,
}

impl NlriFamily {
    pub const IPV4_UNICAST: Self = Self { afi: 1, safi: 1 };
    pub const IPV6_UNICAST: Self = Self { afi: 2, safi: 1 };
    pub const IPV4_MULTICAST: Self = Self { afi: 1, safi: 2 };
    pub const IPV4_MPLS_VPN: Self = Self { afi: 1, safi: 128 };
    pub const IPV6_MPLS_VPN: Self = Self { afi: 2, safi: 128 };

    pub fn is_ipv4(&self) -> bool {
        self.afi == 1
    }

    pub fn is_ipv6(&self) -> bool {
        self.afi == 2
    }

    pub fn from_addr(addr: &IpAddr) -> Self {
        match addr {
            IpAddr::V4(_) => Self::IPV4_UNICAST,
            IpAddr::V6(_) => Self::IPV6_UNICAST,
        }
    }
}

/// A generic NLRI entry. The bytes carry the protocol-specific encoding
/// (BGP NLRI is prefix-length-prefixed; OSPF is a prefix + LSA reference; etc.).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Nlri {
    pub family: NlriFamily,
    pub prefix: Prefix,
    /// Optional source-specific prefix (RFC 9079 for Babel; also SADR BGP).
    pub source: Option<Prefix>,
    /// Wire-formatted path-attribute payload (BGP) or metric blob (OSPF/Babel).
    pub payload: Vec<u8>,
}
