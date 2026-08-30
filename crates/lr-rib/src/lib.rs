//! Routing information base (RIB).
//!
//! Implements the four-tier RIB model from RFC 4271 §9 (Adj-RIB-In,
//! Adj-RIB-Out, Loc-RIB) plus a cross-protocol mux that selects routes by
//! admin distance. Per-protocol route selection lives in `selection`.

pub mod adj_rib_in;
pub mod adj_rib_out;
pub mod loc_rib;
pub mod merging;
pub mod selection;

pub use adj_rib_in::AdjRibIn;
pub use adj_rib_out::AdjRibOut;
pub use loc_rib::LocRib;
pub use merging::RibMux;
pub use selection::RouteSelector;

/// Absolute minimum [`RouteKey`] under the derived `(prefix, family,
/// source)` ordering: IPv4 `0.0.0.0/0`, the smallest [`NlriFamily`], no
/// source. Together with [`max_route_key`] it brackets the whole key
/// space so `BTreeMap::range` queries can cover every address family.
pub(crate) fn min_route_key() -> lr_core::rib::RouteKey {
    lr_core::rib::RouteKey {
        prefix: lr_core::addr::Prefix::new_v4([0; 4], 0),
        family: lr_core::nlri::NlriFamily { afi: 0, safi: 0 },
        source: None,
    }
}

/// Absolute maximum [`RouteKey`]: IPv6 `ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128`
/// (every IPv6 prefix sorts above every IPv4 one), the largest
/// [`NlriFamily`], the largest possible source prefix.
pub(crate) fn max_route_key() -> lr_core::rib::RouteKey {
    lr_core::rib::RouteKey {
        prefix: lr_core::addr::Prefix::new_v6([0xff; 16], 128),
        family: lr_core::nlri::NlriFamily {
            afi: u16::MAX,
            safi: u8::MAX,
        },
        source: Some(lr_core::addr::Prefix::new_v6([0xff; 16], 128)),
    }
}
