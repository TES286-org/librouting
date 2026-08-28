//! RFC 5549 BGP Extended Next-Hop orchestration helpers.
//!
//! The wire-level pieces live elsewhere: capability encoding in
//! [`crate::capabilities`], NEXT_HOP / MP_REACH_NLRI decoding in
//! [`crate::path`]. This module computes what a session should advertise
//! and what it may use after the OPEN exchange.
//!
//! # Capability
//!
//! Capability code 5 (RFC 5549 §2). The value is a sequence of 5-byte
//! tuples `<NLRI AFI:2, NLRI SAFI:1, Nexthop AFI:2>`. A tuple
//! `(1, 1, 2)` therefore says "I can resolve IPv4 unicast NLRI over an
//! IPv6 next-hop".
//!
//! # Negotiation
//!
//! Both speakers must advertise the same tuple for it to take effect
//! (RFC 5549 §3: "a BGP speaker ... SHALL only advertise to a peer ...
//! next-hop addresses whose AFI was advertised by the peer via the
//! capability"). [`negotiated_tuples`] returns the intersection.
//!
//! # Wire impact
//!
//! Once `(1, 1, 2)` is negotiated:
//!
//! - Inbound: a 16-byte NEXT_HOP attribute (well-known, type 3) on an
//!   IPv4 NLRI UPDATE is interpreted as an IPv6 next-hop. A MP_REACH_NLRI
//!   for `(AFI=1, SAFI=1)` with a 16-byte next-hop is also valid.
//! - Outbound: when the local source address is IPv6 and the route is
//!   IPv4 unicast, egress rewrites NEXT_HOP to the 16-byte IPv6 address
//!   instead of skipping the route.

use lr_core::nlri::NlriFamily;

use crate::peer::PeerConfig;

/// A single extended next-hop tuple: IPv4 unicast NLRI can be resolved
/// over an IPv6 next-hop when `(afi=1, safi=1, nh_afi=2)` is negotiated.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ExtNextHopTuple {
    /// NLRI address family (e.g. `1` for IPv4).
    pub nlri_afi: u16,
    /// NLRI subsequent address family (almost always `1` for unicast).
    pub nlri_safi: u8,
    /// Nexthop address family (e.g. `2` for IPv6).
    pub nexthop_afi: u16,
}

impl ExtNextHopTuple {
    /// The canonical "IPv4 over IPv6" tuple `(1, 1, 2)` — the only
    /// combination BIRD, FRR and Cisco commonly negotiate today.
    pub const IPV4_OVER_IPV6: Self = Self {
        nlri_afi: 1,
        nlri_safi: 1,
        nexthop_afi: 2,
    };

    pub fn new(nlri_afi: u16, nlri_safi: u8, nexthop_afi: u16) -> Self {
        Self {
            nlri_afi,
            nlri_safi,
            nexthop_afi,
        }
    }

    pub fn family(&self) -> NlriFamily {
        NlriFamily {
            afi: self.nlri_afi,
            safi: self.nlri_safi,
        }
    }
}

/// Tuples our OPEN advertises for Extended Next-Hop. Returns the
/// intersection of `cfg.extended_next_hop` with the families this session
/// actually speaks (IPv4 unicast is always spoken; MP-BGP families come
/// from `cfg.mp_families`). Tuples for unspoken families are dropped —
/// advertising them would mislead the peer.
pub fn advertised_tuples(cfg: &PeerConfig) -> Vec<ExtNextHopTuple> {
    let mut out = Vec::new();
    for (nlri_afi, nlri_safi, nh_afi) in &cfg.extended_next_hop {
        let tuple = ExtNextHopTuple::new(*nlri_afi, *nlri_safi, *nh_afi);
        let family = tuple.family();
        if family == NlriFamily::IPV4_UNICAST || cfg.mp_families.contains(&family) {
            if !out.contains(&tuple) {
                out.push(tuple);
            }
        }
    }
    out
}

/// Effective tuples after OPEN negotiation: only those the peer also
/// advertised survive (RFC 5549 §3). The peer's tuples are decoded from
/// its OPEN capability value.
pub fn negotiated_tuples(
    cfg: &PeerConfig,
    peer_tuples: &[ExtNextHopTuple],
) -> Vec<ExtNextHopTuple> {
    let ours = advertised_tuples(cfg);
    let mut out = Vec::new();
    for t in &ours {
        if peer_tuples.contains(t) && !out.contains(t) {
            out.push(*t);
        }
    }
    out
}

/// True when `(nlri_afi, nlri_safi, nh_afi)` is in the negotiated set.
pub fn supports(negotiated: &[ExtNextHopTuple], nlri_afi: u16, nlri_safi: u8, nh_afi: u16) -> bool {
    negotiated.iter().any(|t| {
        t.nlri_afi == nlri_afi && t.nlri_safi == nlri_safi && t.nexthop_afi == nh_afi
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::peer::PeerConfig;
    use lr_core::addr::{Asn, RouterId};
    use lr_core::nlri::NlriFamily;

    fn cfg(enh: &[(u16, u8, u16)]) -> PeerConfig {
        let mut c = PeerConfig::new(Asn(64512), Asn(64513), RouterId::from_v4([10, 0, 0, 1]));
        c.extended_next_hop = enh.to_vec();
        c
    }

    #[test]
    fn advertises_only_spoken_families() {
        // IPv4 unicast is always spoken — tuple survives.
        let c = cfg(&[(1, 1, 2)]);
        let t = advertised_tuples(&c);
        assert_eq!(t, vec![ExtNextHopTuple::IPV4_OVER_IPV6]);

        // IPv6 unicast requires the MP-BGP family to be configured.
        let mut c = cfg(&[(1, 1, 2)]);
        c.mp_families = vec![NlriFamily::IPV6_UNICAST];
        // (2, 1, 2) is IPv6-over-IPv6 — unusual but valid on the wire.
        c.extended_next_hop.push((2, 1, 2));
        let t = advertised_tuples(&c);
        assert!(t.contains(&ExtNextHopTuple::IPV4_OVER_IPV6));
        assert!(t.contains(&ExtNextHopTuple::new(2, 1, 2)));

        // A tuple for a family we do not speak is filtered out.
        let mut c = cfg(&[(1, 1, 2)]);
        c.extended_next_hop.push((1, 128, 2)); // MPLS VPN — not configured
        let t = advertised_tuples(&c);
        assert_eq!(t, vec![ExtNextHopTuple::IPV4_OVER_IPV6]);
    }

    /// RFC 5549 §3: both speakers must advertise a tuple for it to be usable.
    #[test]
    fn negotiation_keeps_intersection_only() {
        let c = cfg(&[(1, 1, 2)]);
        // Peer offers the same tuple — survives.
        let n = negotiated_tuples(&c, &[ExtNextHopTuple::IPV4_OVER_IPV6]);
        assert_eq!(n, vec![ExtNextHopTuple::IPV4_OVER_IPV6]);
        // Peer offers nothing — empty intersection.
        let n = negotiated_tuples(&c, &[]);
        assert!(n.is_empty());
        // Peer offers a different tuple — filtered.
        let n = negotiated_tuples(&c, &[ExtNextHopTuple::new(2, 1, 2)]);
        assert!(n.is_empty());
    }

    #[test]
    fn supports_helper() {
        let n = vec![ExtNextHopTuple::IPV4_OVER_IPV6];
        assert!(supports(&n, 1, 1, 2));
        assert!(!supports(&n, 1, 1, 1));
        assert!(!supports(&n, 2, 1, 2));
    }

    #[test]
    fn ipv4_over_ipv6_constant_matches_expected_tuple() {
        assert_eq!(
            ExtNextHopTuple::IPV4_OVER_IPV6,
            ExtNextHopTuple::new(1, 1, 2)
        );
        assert_eq!(ExtNextHopTuple::IPV4_OVER_IPV6.family(), NlriFamily::IPV4_UNICAST);
    }
}
