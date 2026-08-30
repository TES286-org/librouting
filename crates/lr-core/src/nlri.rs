//! Generic NLRI envelope. Per-protocol crates carry their own typed NLRI
//! structs; this enum lets the RIB hold any of them.

use crate::addr::{IpAddr, Prefix};
#[cfg(not(feature = "std"))]
extern crate alloc;

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

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
    /// RFC 8277 §3: IPv4 labelled unicast (AFI=1, SAFI=4). NLRI carries an
    /// MPLS label stack immediately before the IP prefix.
    pub const IPV4_LABELED_UNICAST: Self = Self { afi: 1, safi: 4 };
    /// RFC 8277 §3: IPv6 labelled unicast (AFI=2, SAFI=4). NLRI carries an
    /// MPLS label stack immediately before the IP prefix.
    pub const IPV6_LABELED_UNICAST: Self = Self { afi: 2, safi: 4 };

    pub fn is_ipv4(&self) -> bool {
        self.afi == 1
    }

    pub fn is_ipv6(&self) -> bool {
        self.afi == 2
    }

    /// True for RFC 8277 labelled-unicast families (SAFI=4). NLRI in these
    /// families carries an MPLS label stack before the IP prefix.
    pub fn is_labeled_unicast(&self) -> bool {
        self.safi == 4 && (self.afi == 1 || self.afi == 2)
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
