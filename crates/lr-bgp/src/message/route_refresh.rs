//! ROUTE-REFRESH message (RFC 2918 + RFC 7313 enhanced variant).
//!
//! The basic variant is a 4-byte body: AFI (2) | Reserved (1) | SAFI (1).
//! The enhanced variant (RFC 7313) adds a BGP Identifier prefix.

use lr_core::nlri::NlriFamily;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RouteRefresh {
    pub family: NlriFamily,
    /// Optional BGP identifier prefix (RFC 7313). 0 = basic.
    pub bgp_id: u32,
    /// Optional boundary (RFC 7313). None = basic.
    pub boundary: Option<u8>,
}

impl RouteRefresh {
    pub fn new(family: NlriFamily) -> Self {
        Self {
            family,
            bgp_id: 0,
            boundary: None,
        }
    }

    pub fn enhanced(family: NlriFamily, bgp_id: u32, boundary: u8) -> Self {
        Self {
            family,
            bgp_id,
            boundary: Some(boundary),
        }
    }

    pub fn is_enhanced(&self) -> bool {
        self.boundary.is_some()
    }
}
