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
pub mod exchange;
pub mod external;
/// Graceful restart (RFC 3623): helper-neighbour and restarting-router
/// state machines on top of the [`lsa::grace`] Grace-LSA codec.
pub mod gr;
pub mod interface;
pub mod lsa;
pub mod lsdb;
pub mod neighbor;
pub mod nssa;
pub mod origination;
pub mod packet;
pub mod spf;
/// Per-node Segment Routing database (RFC 8665 reception): the SRGBs
/// and Prefix-SID mappings projected from the area LSDB, plus the
/// §5 label resolution the router applies to SPF routes.
pub mod srdb;

/// Per-node SRv6 database (RFC 9513 reception): the SRv6 capabilities,
/// algorithms, MSDs, locators and End SIDs projected from the OSPFv3
/// area LSDB — the receiving half of the OSPFv3 SRv6 control plane.
pub mod srv6db;

pub use codec::OspfCodec;
pub use neighbor::{NeighborEvent, NeighborState, OspfNeighbor};
pub use packet::{OspfHeader, OspfPacket, OspfVersion};
