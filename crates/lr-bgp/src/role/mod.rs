//! BGP role and topology primitives.
//!
//! This module encodes *who* the peer is in the topology, which then drives
//! protocol behavior:
//!
//! - **iBGP vs eBGP** (RFC 4271 §10): drives AS_PATH prepending, NEXT_HOP
//!   rewriting, LOCAL_PREF propagation, route reflection rules.
//! - **Route Reflection** (RFC 4456): cluster-id, ORIGINATOR_ID/CLUSTER_LIST
//!   insertion, reflection between iBGP peers.
//! - **Confederations** (RFC 6793, originally RFC 3065): confederation-internal
//!   vs confederation-external eBGP, AS_CONFED_SEQUENCE / AS_CONFED_SET.
//! - **Route Server / IX** (RFC 7947): "transparent" mode in which the RS
//!   modifies AS_PATH and NEXT_HOP to keep the route acceptable for clients
//!   that don't peer with each other.
//! - **BGP Role** (RFC 9234): OTC (Only To Customer) attribute — enforces
//!   valley-free route propagation in the AS graph.
//!
//! [`PeerRole`] is a property of [`crate::peer::PeerConfig`] and consumed by
//! the import/export pipeline (see [`crate::best_path`]) and the policy hook
//! surface (see `lr-policy::hooks`).

pub mod cluster;
pub mod confederation;
pub mod otc;
pub mod route_server;

pub use cluster::{ClusterId, RouteReflectorConfig};
pub use confederation::ConfederationConfig;
pub use otc::{Otc, OtcRole};
pub use route_server::RouteServerConfig;

use lr_core::addr::Asn;

/// Topological relationship of this peer to the local speaker. The role
/// governs AS_PATH manipulation, NEXT_HOP rewriting, and which routes are
/// eligible for reflection/advertisement.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum PeerRole {
    /// eBGP session — peer is in a different AS. AS_PATH is prepended on
    /// advertisement; NEXT_HOP is rewritten to the local interface address
    /// unless explicitly preserved (e.g. for unnumbered eBGP, RFC 5549).
    #[default]
    Ebgp,
    /// iBGP session — peer is in the same AS. AS_PATH is *not* modified when
    /// advertising; NEXT_HOP is preserved. LOCAL_PREF is propagated. Routes
    /// learned from iBGP are not re-advertised to other iBGP peers unless the
    /// local speaker is a route reflector (RFC 4456 §9).
    Ibgp,
    /// Confederation-external eBGP (RFC 6793). Behaves like eBGP for the
    /// purposes of AS_PATH prepending (using AS_CONFED_SEQUENCE) and NEXT_HOP
    /// rewriting, but the AS_CONFED_SEQUENCE is removed when the route leaves
    /// the confederation.
    ConfederationExternal,
    /// Confederation-internal iBGP (RFC 6793). Behaves like iBGP but confed
    /// peers may exchange routes learned from other confed members.
    ConfederationInternal,
}

impl PeerRole {
    /// True if this peer is in the same AS as the local speaker (iBGP or
    /// confed-internal).
    pub fn is_internal(self) -> bool {
        matches!(self, PeerRole::Ibgp | PeerRole::ConfederationInternal)
    }

    /// True if this peer is outside the local AS (eBGP or
    /// confederation-external). This is the RFC 8212 notion of an
    /// "EBGP session" — §1 explicitly includes confederation
    /// boundaries — and governs the default deny-in/deny-out policy
    /// behaviour for sessions without explicit policy.
    pub fn is_external(self) -> bool {
        matches!(self, PeerRole::Ebgp | PeerRole::ConfederationExternal)
    }

    /// True if AS_PATH is mutated when advertising to this peer.
    pub fn prepends_as_path(self) -> bool {
        matches!(self, PeerRole::Ebgp | PeerRole::ConfederationExternal)
    }

    /// True if NEXT_HOP should be rewritten to the local interface when
    /// advertising to this peer.
    pub fn rewrites_next_hop(self) -> bool {
        matches!(self, PeerRole::Ebgp | PeerRole::ConfederationExternal)
    }

    /// Compute the role from local/peer ASNs and the confederation config.
    /// Returns [`PeerRole::Ebgp`] when peer_as != local_as and no confed
    /// configuration is supplied, [`PeerRole::Ibgp`] when equal, and one of
    /// the confederation variants when the peer AS is in `confed_members`.
    pub fn from_asns(local_as: Asn, peer_as: Asn, confed: Option<&ConfederationConfig>) -> Self {
        if let Some(c) = confed {
            if c.members.contains(&peer_as.0) {
                return if peer_as == local_as {
                    PeerRole::ConfederationInternal
                } else {
                    PeerRole::ConfederationExternal
                };
            }
        }
        if peer_as == local_as {
            PeerRole::Ibgp
        } else {
            PeerRole::Ebgp
        }
    }
}

/// Which role to apply when transmitting routes to this peer. Combines the
/// topological role with optional Route-Reflector client flag and the RFC 9234
/// OTC role.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PeerTopology {
    /// Topological role (eBGP, iBGP, confed-*).
    pub role: PeerRole,
    /// True if this peer is a route-reflector client (RFC 4456).
    pub rr_client: bool,
    /// True if this peer is a route-server client (RFC 7947).
    pub rs_client: bool,
    /// OTC role for this peer (RFC 9234 §3).
    pub otc: OtcRole,
}

impl PeerTopology {
    /// Determine if a route learned from `from` may be advertised to `to`.
    /// This implements the high-level reachability rules (iBGP full-mesh or
    /// RR, route-server transit, OTC valley-free, confederation).
    pub fn can_advertise(&self, from: &PeerTopology, route_otc: Option<Otc>) -> bool {
        // iBGP rule: routes learned from iBGP are only re-advertised to other
        // iBGP peers when this speaker is a route reflector (RFC 4271 §10).
        if from.role.is_internal() && self.role.is_internal() && !self.rr_client && !from.rr_client
        {
            // Unless we are an RR, we don't reflect iBGP-learned routes.
            return false;
        }

        // RFC 9234 §5 egress rule 2: a route that already carries OTC MUST
        // NOT be propagated to Providers, Peers, or RSes — it may go only
        // to Customers and RS-clients.
        if let Some(otc) = route_otc {
            if !crate::role::otc::otc_can_advertise(otc, self.otc) {
                return false;
            }
        }

        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn role_classification() {
        assert_eq!(
            PeerRole::from_asns(Asn(100), Asn(200), None),
            PeerRole::Ebgp
        );
        assert_eq!(
            PeerRole::from_asns(Asn(100), Asn(100), None),
            PeerRole::Ibgp
        );
    }

    #[test]
    fn external_is_the_rfc8212_notion_of_ebgp() {
        // RFC 8212 §1: EBGP sessions include confederation boundaries,
        // so confederation-external counts as external; iBGP and
        // confederation-internal do not.
        assert!(PeerRole::Ebgp.is_external());
        assert!(PeerRole::ConfederationExternal.is_external());
        assert!(!PeerRole::Ibgp.is_external());
        assert!(!PeerRole::ConfederationInternal.is_external());
        // is_external / is_internal partition the role space.
        for role in [
            PeerRole::Ebgp,
            PeerRole::Ibgp,
            PeerRole::ConfederationExternal,
            PeerRole::ConfederationInternal,
        ] {
            assert_eq!(role.is_external(), !role.is_internal());
        }
    }

    #[test]
    fn role_classification_confed() {
        let confed = ConfederationConfig {
            members: vec![64512, 64513, 64514],
        };
        assert_eq!(
            PeerRole::from_asns(Asn(64512), Asn(64513), Some(&confed)),
            PeerRole::ConfederationExternal
        );
        assert_eq!(
            PeerRole::from_asns(Asn(64512), Asn(64512), Some(&confed)),
            PeerRole::ConfederationInternal
        );
        assert_eq!(
            PeerRole::from_asns(Asn(64512), Asn(200), Some(&confed)),
            PeerRole::Ebgp
        );
    }

    #[test]
    fn ibgp_full_mesh_no_reflection() {
        let from = PeerTopology {
            role: PeerRole::Ibgp,
            rr_client: false,
            rs_client: false,
            otc: OtcRole::Unset,
        };
        let to = PeerTopology {
            role: PeerRole::Ibgp,
            rr_client: false,
            rs_client: false,
            otc: OtcRole::Unset,
        };
        assert!(!to.can_advertise(&from, None));
    }

    #[test]
    fn ibgp_rr_client_can_receive() {
        let from = PeerTopology {
            role: PeerRole::Ibgp,
            rr_client: false,
            rs_client: false,
            otc: OtcRole::Unset,
        };
        let to = PeerTopology {
            role: PeerRole::Ibgp,
            rr_client: true,
            rs_client: false,
            otc: OtcRole::Unset,
        };
        assert!(to.can_advertise(&from, None));
    }
}
