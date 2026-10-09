//! OSPF protocol runtime types for the router instance.
//!
//! These types live in a sibling module so [`super::DefaultRouter`] stays
//! readable. Every field is `pub(super)` so the parent module (and its
//! test submodules) can access them without qualification. The `impl`
//! blocks stay in `mod.rs` — Rust allows impl blocks for a type in any
//! module within the same crate.

use crate::session::{OspfAreaType, SessionHandle};
use lr_core::addr::IpAddr;
use lr_core::rib::Protocol;
use lr_ospf::external::ExternalMetricType;
use lr_ospf::lsa::{Lsa, LsaTypeV2};
use lr_ospf::lsdb::Lsdb;
use lr_ospf::neighbor::OspfNeighbor;
use lr_ospf::packet::{
    LsUpdateBody, OspfBody, OspfHeader, OspfPacket, OspfPacketType, OspfVersion,
};

/// OSPF protocol runtime for one adjacency: neighbor FSM + per-session
/// decode state.
///
/// The LSDB is *per area* (shared by every session attached to the same
/// area — LSAs flooded within an area belong to the area, not to the
/// adjacency that happened to deliver them). See [`OspfAreaState`].
///
/// This is a simplified but functional driver: Hellos advance the
/// neighbor FSM and LS-Updates are handed to the area LSDB. Full
/// DBD/LSR exchange sequencing is the embedder's job to extend (the FSM
/// states are all exposed).
pub(super) struct OspfRuntime {
    pub(super) router_id: u32,
    pub(super) area_id: u32,
    pub(super) neighbor: OspfNeighbor,
    /// Protocol origin tag used when installing routes.
    pub(super) protocol: Protocol,
    /// Per-session streaming decoder (carryover must never leak between
    /// different peers' transports).
    pub(super) codec: lr_ospf::codec::OspfCodec,
    /// RFC 2328 §7.2 database synchronization driver: DBD negotiation,
    /// header exchange and LS-Request loading up to Full.
    pub(super) exchange: lr_ospf::exchange::DbExchange,
    /// Interface MTU (kept so the exchange can be rebuilt fresh when a
    /// §10.4 demotion resets the adjacency).
    pub(super) iface_mtu: u16,
    /// Interface network type (RFC 2328 §9.4) — drives the §10.4
    /// adjacency decision.
    pub(super) network_type: crate::session::OspfNetworkType,
    /// This router's own segment identity (§10.4): the IPv4 interface
    /// address for v2 sessions (§A.3.2 — the Hello DR/BDR wire form),
    /// the Router ID for v3 sessions (RFC 5340 §4.1.2). `0` = not
    /// supplied — treated as DR-Other.
    pub(super) our_ip: u32,
    /// The neighbor's segment identity (the v2 interface address / the
    /// v3 Router ID).
    pub(super) neighbor_ip: u32,
    /// Elected Designated Router in the segment identity — IP
    /// interface address per §A.3.2 on v2, Router ID on v3 (RFC 5340
    /// §4.1.2). 0 = none / still Waiting. Pushed by the embedder after
    /// every election round via `DefaultRouter::set_ospf_dr_state`.
    pub(super) dr: u32,
    /// Elected Backup Designated Router (segment identity, as above).
    pub(super) bdr: u32,
}

/// One configured virtual link (RFC 2328 §15): a backbone adjacency
/// between two area border routers, riding through `transit_area`.
#[derive(Debug, Clone, Copy)]
pub(super) struct OspfVirtualLink {
    /// The backbone session materialized while the link is up. Its
    /// transport is the embedder's responsibility (tunnel the drained
    /// bytes through the transit area to the peer's virtual session).
    pub(super) session: Option<SessionHandle>,
}

/// Per-area OSPF state shared by every session attached to that area.
pub(super) struct OspfAreaState {
    pub(super) lsdb: Lsdb,
    /// Protocol version the area runs (v2 and v3 cannot mix in one area).
    pub(super) protocol: Protocol,
    /// Area type policy — stub/NSSA gating of LSA flooding and the
    /// border-router default injection (RFC 2328 §3.6, RFC 3101).
    pub(super) kind: OspfAreaType,
    /// Monotonic counter bumped on every *content* change of a
    /// topology LSA (types 1-5, 7 — RFC 3623 §3.2 (3); periodic
    /// refreshes, where only age/sequence move, do not bump). Embedders
    /// poll it via [`DefaultRouter::ospf_area_topology_version`] to
    /// terminate graceful-restart helper mode on topology changes.
    pub(super) topology_version: u64,
}

/// Whether an area of type `kind` accepts `lsa` (RFC 2328 §3.6, RFC 3101):
/// stub and NSSA areas refuse type-5 AS-external and type-4 summary-ASBR
/// LSAs; `no_summary` areas refuse every type-3 summary except the
/// default; type-7 LSAs only exist inside NSSAs. The OSPFv3 shapes of
/// the same classes (0x4005 AS-external, 0x2004 inter-area-router,
/// 0x2003 inter-area-prefix — RFC 5340 §A.4.5/§A.4.6/§A.4.7) are
/// filtered identically, and so are their RFC 8362 Extended forms
/// (0xC025 E-AS-external, 0xA024 E-inter-area-router, 0xA023
/// E-inter-area-prefix, 0xA027 E-Type-7); v2 and v3 types are
/// distinct 16-bit values so one match covers both.
pub(super) fn ospf_area_accepts(kind: &OspfAreaType, lsa: &Lsa) -> bool {
    match lsa.header.ls_type {
        t if t == LsaTypeV2::AsExternalLsa as u16
            || t == LsaTypeV2::SummaryAsbrLsa as u16
            || t == lr_ospf::lsa::v3::LS_TYPE_AS_EXTERNAL
            || t == lr_ospf::lsa::v3::LS_TYPE_INTER_ROUTER
            || t == lr_ospf::lsa::LS_TYPE_E_AS_EXTERNAL
            || t == lr_ospf::lsa::LS_TYPE_E_INTER_ROUTER =>
        {
            !kind.is_stubby()
        }
        t if t == LsaTypeV2::NssaExternalLsa as u16 || t == lr_ospf::lsa::LS_TYPE_E_TYPE_7 => {
            kind.is_nssa()
        }
        t if t == LsaTypeV2::SummaryIpLsa as u16
            || t == lr_ospf::lsa::v3::LS_TYPE_INTER_PREFIX
            || t == lr_ospf::lsa::LS_TYPE_E_INTER_PREFIX =>
        {
            if !kind.no_summary() {
                true
            } else if t == LsaTypeV2::SummaryIpLsa as u16 {
                // v2: the default summary's LS ID is 0.0.0.0.
                lsa.header.link_state_id == 0
            } else if t == lr_ospf::lsa::v3::LS_TYPE_INTER_PREFIX {
                // v3 (RFC 5340 §4.4.3.4): the LS ID has no addressing
                // semantics — the default is a zero-length prefix in
                // the body.
                lr_ospf::lsa::decode_v3_inter_area_prefix_body(&lsa.body)
                    .is_some_and(|b| b.prefix_len == 0)
            } else {
                // The E-Inter-Area-Prefix form (RFC 8362 §4.3): the
                // default is the zero-length prefix in the TLV.
                lr_ospf::lsa::EInterAreaPrefixLsaBody::decode(&lsa.body)
                    .is_some_and(|b| b.0.prefix.prefix_len == 0)
            }
        }
        _ => true,
    }
}

/// Is this LSA a Grace-LSA (RFC 3623 §2.1 / RFC 5187 §2.1)? The OSPFv2
/// form is a type-9 (link-local opaque) LSA with Opaque Type 3 in the
/// LS ID's top octet (RFC 5250 §3.1); the OSPFv3 form is the dedicated
/// link-scoped LS type 0x000b (LSA function code 11 — no opaque-type
/// packing exists in v3).
pub(super) fn is_grace_lsa(lsa: &Lsa) -> bool {
    lsa.header.ls_type == lr_ospf::lsa::grace::LS_TYPE_GRACE_V3
        || (lsa.header.ls_type == lr_ospf::lsa::grace::grace_lsa_type()
            && (lsa.header.link_state_id >> 24) as u8 == lr_ospf::lsa::grace::OPAQUE_TYPE_GRACE)
}

/// Whether an installed LSA instance is a *content* topology change
/// for graceful-restart purposes (RFC 3623 §3.2 (3) — "the contents of
/// the LSA have changed; this includes LSAs with no previous instance
/// and the flushing of LSAs, but excludes periodic LSA refreshes").
/// `outcome` is the install result and `prev` the replaced instance
/// (None on `New`). Only topology LSAs count: v2 types 1-5, 7 and the
/// v3 router/network/inter-area/external/NSSA shapes (0x2001-0x2009).
pub(super) fn lsa_topology_changed(
    prev: Option<&Lsa>,
    new: &Lsa,
    outcome: lr_ospf::lsdb::InstallOutcome,
) -> bool {
    use lr_ospf::lsdb::InstallOutcome;
    let is_topology = matches!(
        new.header.ls_type,
        t if t == LsaTypeV2::RouterLsa as u16
            || t == LsaTypeV2::NetworkLsa as u16
            || t == LsaTypeV2::SummaryIpLsa as u16
            || t == LsaTypeV2::SummaryAsbrLsa as u16
            || t == LsaTypeV2::AsExternalLsa as u16
            || t == LsaTypeV2::NssaExternalLsa as u16
            || t == lr_ospf::lsa::v3::LS_TYPE_ROUTER
            || t == lr_ospf::lsa::v3::LS_TYPE_NETWORK
            || t == lr_ospf::lsa::v3::LS_TYPE_INTER_PREFIX
            || t == lr_ospf::lsa::v3::LS_TYPE_INTER_ROUTER
            || t == lr_ospf::lsa::v3::LS_TYPE_AS_EXTERNAL
            || t == lr_ospf::lsa::v3::LS_TYPE_INTRA_PREFIX
            || t == lr_ospf::lsa::LS_TYPE_E_ROUTER
            || t == lr_ospf::lsa::LS_TYPE_E_NETWORK
            || t == lr_ospf::lsa::LS_TYPE_E_INTER_PREFIX
            || t == lr_ospf::lsa::LS_TYPE_E_INTER_ROUTER
            || t == lr_ospf::lsa::LS_TYPE_E_AS_EXTERNAL
            || t == lr_ospf::lsa::LS_TYPE_E_INTRA_PREFIX
    );
    if !is_topology {
        return false;
    }
    match outcome {
        InstallOutcome::New | InstallOutcome::Purged => true,
        // Replaced: a periodic refresh (RFC 2328 §14.1) bumps the
        // sequence and resets the age with identical body — the
        // contents did not change. Anything else (different body, or
        // an age jump with equal body from a re-originator) did.
        InstallOutcome::Replaced => match prev {
            None => true,
            Some(p) => p.body != new.body || p.header.length != new.header.length,
        },
        InstallOutcome::Ignored => false,
    }
}

/// One entry of an area's computed route table: the metric plus how the
/// route was derived. Inter-area entries remember the advertising border
/// router — ABR summary origination must never re-advertise a route whose
/// only justification is the router's own (possibly stale) summary.
/// External entries (RFC 2328 §16.4) keep the ASBR and metric type so the
/// merged table can apply the §11 preference order.
#[derive(Debug, Clone, Copy)]
pub(super) struct OspfTableEntry {
    pub(super) metric: u64,
    pub(super) kind: OspfKind,
    /// RFC 8665 §5 label the route resolves to (SPF-algorithm Prefix-SID
    /// of its originator), when SR reception is enabled and the mapping
    /// is usable. Intra-area and inter-area routes only — external paths
    /// forward to the ASBR / forwarding address, not the originator.
    pub(super) label: Option<u32>,
    /// The resolved first hop toward the label's originator — the
    /// gateway the RFC 8660 encap route points at. Always `Some` when
    /// `label` is.
    pub(super) label_nh: Option<IpAddr>,
    /// The route's own next hop, where the SPF resolved one (OSPFv3
    /// intra-area routes carry their neighbor's link-local; v2 routes
    /// resolve on-link and publish None).
    pub(super) next_hop: Option<IpAddr>,
}

#[derive(Debug, Clone, Copy)]
pub(super) enum OspfKind {
    Intra,
    Inter {
        /// Advertising border router of the summary-LSA.
        border_router: u32,
    },
    External {
        metric_type: ExternalMetricType,
        /// Advertising ASBR of the type-5 LSA.
        asbr: u32,
        /// Forwarding address from the external LSA: the v2 u32 form
        /// (RFC 2328 §A.4.5, 0 = the ASBR) or the v3 global IPv6 form
        /// (RFC 5340 §A.4.7, F bit) — `None` means the ASBR itself.
        forwarding_addr: Option<IpAddr>,
        /// Internal cost to the ASBR — type-2 tie-breaker (§16.4 (6)).
        internal_cost: u64,
    },
}

/// One OSPF protocol step's output (the router-facing twin of
/// `lr_ospf::exchange::ExchangeStep`).
#[derive(Default)]
pub(super) struct OspfStep {
    pub(super) lsas: Vec<Lsa>,
    pub(super) outbound: Vec<OspfPacket>,
}

/// Build one LS-Update packet for an area.
pub(super) fn ospf_ls_update(
    protocol: Protocol,
    router_id: u32,
    area_id: u32,
    lsas: Vec<Lsa>,
) -> OspfPacket {
    OspfPacket {
        header: OspfHeader {
            version: if protocol == Protocol::Ospfv3 {
                OspfVersion::V3 as u8
            } else {
                OspfVersion::V2 as u8
            },
            kind: OspfPacketType::LinkStateUpdate as u8,
            length: 0,
            router_id,
            area_id,
            checksum: 0,
            au_type_or_instance: 0,
            auth_data: 0,
        },
        body: OspfBody::LsUpdate(LsUpdateBody {
            lsa_count: lsas.len() as u32,
            lsas,
        }),
    }
}
