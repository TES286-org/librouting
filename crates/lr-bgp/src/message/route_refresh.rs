//! ROUTE-REFRESH message (RFC 2918 + RFC 7313 enhanced variant).
//!
//! Both variants have a 4-byte body: AFI (2) | subtype/reserved (1) | SAFI
//! (1). RFC 7313 redefines the formerly reserved octet as a demarcation
//! subtype; it does not append a BGP identifier to the message.

use lr_core::nlri::NlriFamily;

/// RFC 7313 route-refresh subtype carried in the third body octet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum RouteRefreshSubtype {
    /// RFC 2918 request, or a normal RFC 7313 route-refresh message.
    Normal = 0,
    /// Beginning-of-RIB marker (BoRR).
    BeginOfRib = 1,
    /// End-of-RIB marker (EoRR).
    EndOfRib = 2,
}

impl RouteRefreshSubtype {
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(Self::Normal),
            1 => Some(Self::BeginOfRib),
            2 => Some(Self::EndOfRib),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RouteRefresh {
    pub family: NlriFamily,
    pub subtype: RouteRefreshSubtype,
}

impl RouteRefresh {
    pub fn new(family: NlriFamily) -> Self {
        Self {
            family,
            subtype: RouteRefreshSubtype::Normal,
        }
    }

    pub fn begin_of_rib(family: NlriFamily) -> Self {
        Self {
            family,
            subtype: RouteRefreshSubtype::BeginOfRib,
        }
    }

    pub fn end_of_rib(family: NlriFamily) -> Self {
        Self {
            family,
            subtype: RouteRefreshSubtype::EndOfRib,
        }
    }
}
