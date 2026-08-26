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
