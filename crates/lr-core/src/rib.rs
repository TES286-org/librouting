//! RIB trait surface. The implementation lives in `lr-rib`.
//!
//! Definitions follow RFC 4271 §9 (Adj-RIB-In, Adj-RIB-Out, Loc-RIB) and add
//! `RibMux` for cross-protocol merging by admin distance.

use crate::addr::Prefix;
use crate::nlri::NlriFamily;
#[cfg(not(feature = "std"))]
extern crate alloc;

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

/// Where a route came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct RouteOrigin {
    /// Protocol instance identifier (assigned by the router).
    pub proto: u32,
    /// Peer / neighbor identifier (assigned by the protocol instance).
    pub peer: u64,
}

/// Stable identifier for a route. Used as the RIB key.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct RouteKey {
    pub prefix: Prefix,
    pub family: NlriFamily,
    /// Optional source-specific prefix.
    pub source: Option<Prefix>,
}

impl RouteKey {
    pub fn new(prefix: Prefix, family: NlriFamily) -> Self {
        Self {
            prefix,
            family,
            source: None,
        }
    }

    pub fn with_source(prefix: Prefix, family: NlriFamily, source: Prefix) -> Self {
        Self {
            prefix,
            family,
            source: Some(source),
        }
    }
}

/// Which protocol originated this route.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Protocol {
    Bgp,
    Ospfv2,
    Ospfv3,
    Babel,
    Static,
    Connected,
    Other(u16),
}

impl Protocol {
    pub fn default_admin_distance(self) -> u32 {
        // FRR-style default distances.
        match self {
            Self::Connected => 0,
            Self::Static => 1,
            Self::Bgp => 20,
            Self::Ospfv2 | Self::Ospfv3 => 110,
            Self::Babel => 120,
            Self::Other(_) => 200,
        }
    }

    /// BIRD-style lowercase protocol name surfaced through the Filter
    /// DSL `proto` field and any cross-protocol comparison.
    ///
    /// Mirrors the names BIRD 2 uses in `filter` (`bgp`, `ospf`,
    /// `ospf3`, `babel`, `static`, `direct`). Routes from protocols
    /// BIRD does not model collapse to `"unknown"`.
    ///
    /// This is the canonical string form used by the Filter DSL
    /// (`proto == "bgp"`); the Rust `Debug` form is for diagnostics
    /// only and must not leak into the filter string surface.
    pub fn bird_name(self) -> &'static str {
        match self {
            Self::Bgp => "bgp",
            Self::Ospfv2 => "ospf",
            Self::Ospfv3 => "ospf3",
            Self::Babel => "babel",
            Self::Static => "static",
            Self::Connected => "direct",
            Self::Other(_) => "unknown",
        }
    }
}

/// Admin preference (lower wins). Combines admin distance (left) and
/// intra-protocol metric (right).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Preference {
    pub admin_distance: u32,
    pub metric: u32,
}

impl Preference {
    pub const fn new(admin_distance: u32, metric: u32) -> Self {
        Self {
            admin_distance,
            metric,
        }
    }
}

/// A route entry. Concrete attribute payload is stored as bytes; the
/// per-protocol crate knows how to decode it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Route {
    pub key: RouteKey,
    pub origin: RouteOrigin,
    pub protocol: Protocol,
    pub preference: Preference,
    pub next_hop: Option<crate::addr::IpAddr>,
    pub attributes: crate::attr::Attributes,
    pub age_ms: u64,
    /// BGP Add-Path identifier (RFC 7911): distinguishes multiple paths
    /// to the same prefix advertised over one session. `0` means no
    /// add-path discrimination (the single-path default). On routes learned
    /// from a peer it is the peer's path identifier; on routes advertised
    /// by this speaker it is the identifier this speaker assigned for the
    /// egress session.
    pub path_id: u32,
    /// Operator-assigned route tag (RFC 4271 §9.1.2 path attribute space;
    /// OSPF external/NSSA LSAs carry it as the 32-bit External Route Tag
    /// per RFC 2328 §A.4.5 / RFC 3101 §2.3). `None` means no tag is
    /// attached. Set by the `SetTag` policy action and consulted by the
    /// OSPF external-LSA origination path; cross-protocol redistribution
    /// pipes also use this field to carry the source protocol's tag
    /// through.
    pub tag: Option<u32>,
}
