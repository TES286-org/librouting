//! OSPF v2 (RFC 2328) and v3 (RFC 5340) protocol library.
//!
//! # Wire codec
//!
//! [`codec::OspfCodec`] implements [`lr_core::codec::Codec`] for
//! [`packet::OspfPacket`]. The codec handles both v2 (IPv4, simple IPv4
//! checksum) and v3 (IPv6, pseudo-header checksum).
//!
//! # FSM
//!
//! - [`neighbor::OspfNeighbor`] — per-neighbor FSM (Down → Init → 2-Way →
//!   ExStart → Exchange → Loading → Full).
//! - [`interface::OspfInterface`] — per-interface FSM with DR/BDR election.
//!
//! # LSDB
//!
//! [`lsdb::Lsdb`] is the link-state database for an area. Stores LSAs keyed by
//! `(type, ls_id, adv_router)`.
//!
//! # SPF
//!
//! [`spf::Spf`] runs Dijkstra on the LSDB to produce routes.

#![forbid(unsafe_code)]

pub mod abr;
pub mod auth;
pub mod codec;
pub mod external;
pub mod interface;
pub mod lsa;
pub mod lsdb;
pub mod neighbor;
pub mod nssa;
pub mod packet;
pub mod spf;

pub use codec::OspfCodec;
pub use neighbor::{NeighborEvent, NeighborState, OspfNeighbor};
pub use packet::{OspfHeader, OspfPacket, OspfVersion};
