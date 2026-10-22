//! BGP Role and OTC attribute (RFC 9234).
//!
//! RFC 9234 introduces the `OTC` (Only To Customer) attribute (path attribute
//! type 35) and four topological roles: Provider, RS (Route Server), RS-
//! Client, Customer, and Peer. The roles together enforce a *valley-free*
//! policy: a route learned from a customer must not transit the local AS
//! except to other customers (otherwise the local AS would carry traffic
//! between its providers for free).
//!
//! Behavior matrix:
//!
//! | Direction            | Role of receiving peer | OTC action                |
//! |---------------------|------------------------:|---------------------------|
//! | Customer -> Local   | Customer                | Set OTC=local_as          |
//! | Peer -> Local        | Peer                    | Set OTC=local_as          |
//! | Provider -> Local   | Provider                | OTC already set, else 0  |
//! | Local -> Customer   | Customer                | Forward unchanged         |
//! | Local -> Peer        | Peer                    | Reject if OTC != 0        |
//! | Local -> Provider   | Provider                | Reject if OTC != 0        |
//! | RS -> RS-Client     | RS / RS-Client          | Strip if local sets       |
//!
//! Wire format: 4-byte unsigned integer. `0` means "absent" (treat as unset).

use lr_core::addr::Asn;

/// Path attribute type code for OTC (RFC 9234 §3.1, IANA registry).
pub const OTC_ATTR_TYPE: u8 = 35;

/// Topological role of a peer (RFC 9234 §3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum OtcRole {
    /// No role configured. The OTC attribute is neither honored nor set.
    #[default]
    Unset,
    /// Local AS is a provider of the peer.
    Provider,
    /// Local AS is a customer of the peer.
    Customer,
    /// Local AS is a peer of the peer (peer-peer relationship).
    Peer,
    /// Local AS is a route server and the peer is an RS-client.
    RouteServer,
    /// Peer is a route server and the local AS is an RS-client.
    RsClient,
}

impl OtcRole {
    /// Whether the role is one of the "upstream" types (peer or provider).
    pub fn is_upstream(self) -> bool {
        matches!(self, OtcRole::Peer | OtcRole::Provider)
    }

    /// True if the role is the route-server role.
    pub fn is_route_server(self) -> bool {
        matches!(self, OtcRole::RouteServer | OtcRole::RsClient)
    }

    /// Encode the role as a 1-byte wire value (RFC 9234 §3.1, IANA registry).
    pub fn to_u8(self) -> u8 {
        match self {
            OtcRole::Unset => 0,
            OtcRole::Provider => 1,
            OtcRole::Customer => 2,
            OtcRole::Peer => 3,
            OtcRole::RouteServer => 4,
            OtcRole::RsClient => 5,
        }
    }

    /// Decode a 1-byte role from the wire.
    pub fn from_u8(v: u8) -> Option<Self> {
        Some(match v {
            0 => Self::Unset,
            1 => Self::Provider,
            2 => Self::Customer,
            3 => Self::Peer,
            4 => Self::RouteServer,
            5 => Self::RsClient,
            _ => return None,
        })
    }
}

/// The OTC attribute value. Wraps the 4-byte integer so the policy engine can
/// track presence vs absence (`0` and "not set" are different in practice
/// for filtering but identical on the wire).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, PartialOrd, Ord)]
pub struct Otc(pub u32);

impl Otc {
    pub const fn new(asn: u32) -> Self {
        Self(asn)
    }
    pub fn decode(b: &[u8]) -> Option<Self> {
        if b.len() != 4 {
            return None;
        }
        Some(Self(u32::from_be_bytes([b[0], b[1], b[2], b[3]])))
    }
    pub fn encode(&self) -> [u8; 4] {
        self.0.to_be_bytes()
    }
    pub fn is_set(&self) -> bool {
        self.0 != 0
    }
}

/// Compute the OTC handling when receiving a route from a peer with
/// `local_role` (the local speaker's role relative to that peer), per RFC
/// 9234 §5 ingress rules:
///
/// 1. A route that already carries OTC received from a Customer or an
///    RS-Client is a route leak and MUST be considered ineligible.
/// 2. A route that carries OTC received from a Peer whose value differs
///    from the peer's AS number is a route leak and MUST be considered
///    ineligible.
/// 3. A route received from a Provider, a Peer, or an RS without OTC MUST
///    have OTC added with the remote AS number.
///
/// Returns `Err(OtcLeak)` for cases 1–2; otherwise `Ok(otc)` is the value
/// the route must carry (the existing value, or the newly-added one).
pub fn otc_on_receive(
    existing: Option<Otc>,
    local_role: OtcRole,
    peer_as: Asn,
) -> Result<Otc, OtcLeak> {
    match local_role {
        // Rule 1: the sender is our customer / an RS-client.
        OtcRole::Provider | OtcRole::RouteServer => {
            if existing.map(|o| o.is_set()).unwrap_or(false) {
                Err(OtcLeak)
            } else {
                Ok(Otc(0))
            }
        }
        // Rule 2: a peer must tag with its own AS.
        OtcRole::Peer => match existing {
            Some(o) if o.is_set() && o.0 != peer_as.0 => Err(OtcLeak),
            Some(o) => Ok(o),
            None => Ok(Otc(peer_as.0)),
        },
        // Rule 3: from a provider or an RS without OTC, add the remote AS.
        OtcRole::Customer | OtcRole::RsClient => Ok(existing.unwrap_or(Otc(peer_as.0))),
        OtcRole::Unset => Ok(existing.unwrap_or(Otc(0))),
    }
}

/// A route received in violation of RFC 9234 §5 ingress rules 1–2.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OtcLeak;

/// Whether a route with `route_otc` may be advertised to a peer with
/// `local_role` (the local speaker's role relative to that peer), per RFC
/// 9234 §5 egress rule 2: a route that already contains OTC MUST NOT be
/// propagated to Providers, Peers, or RSes. It may go to Customers and to
/// RS-clients (rule 1).
pub fn otc_can_advertise(route_otc: Otc, local_role: OtcRole) -> bool {
    if !route_otc.is_set() {
        return true;
    }
    match local_role {
        // The target is our customer or an RS-client.
        OtcRole::Provider | OtcRole::RouteServer => true,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn otc_roundtrip() {
        let o = Otc::new(64512);
        let enc = o.encode();
        let dec = Otc::decode(&enc).unwrap();
        assert_eq!(dec, o);
        assert!(o.is_set());
        assert!(!Otc(0).is_set());
    }

    /// RFC 9234 §5 ingress rule 1: OTC from a Customer / RS-Client is a leak.
    #[test]
    fn otc_from_customer_is_a_leak() {
        assert_eq!(
            otc_on_receive(Some(Otc::new(100)), OtcRole::Provider, Asn(200)),
            Err(OtcLeak)
        );
        assert_eq!(
            otc_on_receive(Some(Otc::new(100)), OtcRole::RouteServer, Asn(200)),
            Err(OtcLeak)
        );
        // No OTC from a customer: nothing to set (rule 3 does not apply).
        assert_eq!(
            otc_on_receive(None, OtcRole::Provider, Asn(200)),
            Ok(Otc(0))
        );
    }

    /// RFC 9234 §5 ingress rule 2: a Peer must tag with its own AS.
    #[test]
    fn otc_from_peer_with_wrong_as_is_a_leak() {
        assert_eq!(
            otc_on_receive(Some(Otc::new(999)), OtcRole::Peer, Asn(200)),
            Err(OtcLeak)
        );
        assert_eq!(
            otc_on_receive(Some(Otc::new(200)), OtcRole::Peer, Asn(200)),
            Ok(Otc::new(200))
        );
        // No OTC from a peer: add the remote AS (rule 3).
        assert_eq!(
            otc_on_receive(None, OtcRole::Peer, Asn(200)),
            Ok(Otc::new(200))
        );
    }

    /// RFC 9234 §5 ingress rule 3: from a Provider / RS without OTC, add
    /// the remote AS number.
    #[test]
    fn otc_added_on_provider_and_rs_reception() {
        assert_eq!(
            otc_on_receive(None, OtcRole::Customer, Asn(200)),
            Ok(Otc::new(200))
        );
        assert_eq!(
            otc_on_receive(None, OtcRole::RsClient, Asn(200)),
            Ok(Otc::new(200))
        );
    }

    /// RFC 9234 §5 egress rule 2: OTC routes go only to Customers and
    /// RS-clients.
    #[test]
    fn otc_advertise_only_to_customer_or_rs_client() {
        let otc = Otc::new(100);
        assert!(otc_can_advertise(otc, OtcRole::Provider)); // peer is our customer
        assert!(otc_can_advertise(otc, OtcRole::RouteServer)); // peer is an RS-client
        assert!(!otc_can_advertise(otc, OtcRole::Customer)); // peer is our provider
        assert!(!otc_can_advertise(otc, OtcRole::Peer));
        assert!(!otc_can_advertise(otc, OtcRole::RsClient)); // peer is an RS
        assert!(!otc_can_advertise(otc, OtcRole::Unset));
        // A route without OTC may go anywhere.
        assert!(otc_can_advertise(Otc(0), OtcRole::Peer));
    }

    // CONTRIBUTING.md: a new wire codec needs a fuzz target or
    // proptest strategy. The bgp_decode fuzz target stores raw
    // attribute bytes in PathAttribute::value without consulting the
    // typed accessor, so this strategy is the floor that keeps
    // PathAttributes::otc honest: arbitrary byte slices run through
    // the strict-width decoder, and the round-trip contract holds for
    // every accepted input.
    proptest! {
        #[test]
        fn otc_decode_never_panics(
            bytes in prop::collection::vec(0u8..=255, 0..=64)
        ) {
            // The decoder must either return Some (4-byte input) or
            // None (any other width) — never panic.
            let decoded = Otc::decode(&bytes);
            if let Some(otc) = decoded {
                // Round-trip contract: encode is the inverse of
                // decode for every accepted input.
                prop_assert_eq!(otc.encode(), bytes.as_slice());
                // The 4-byte input invariant.
                prop_assert_eq!(bytes.len(), 4);
                // is_set() is the value != 0 predicate.
                prop_assert_eq!(otc.is_set(), otc.0 != 0);
            } else {
                // Rejected inputs include every non-4-byte width.
                prop_assert_ne!(bytes.len(), 4);
            }
        }
    }

    /// `PathAttributes::otc` reads by tag through the typed accessor
    /// and stays `None` on the absent and malformed cases. The
    /// accessor is the codec half of the `bgp.otc` filter DSL field
    /// (RFC 9234 §3.1).
    #[test]
    fn path_attributes_otc_accessor_round_trips() {
        use crate::path::{AttrType, PathAttrFlags, PathAttribute, PathAttributes};

        let mut attrs = PathAttributes::new();
        // Absent — None on both `otc()` and `has_otc()`.
        assert!(attrs.otc().is_none());
        assert!(!attrs.has_otc());

        // Present, value 64512.
        attrs.insert(PathAttribute::new(
            PathAttrFlags::new().set_optional(true).set_transitive(true),
            AttrType::Otc,
            Otc::new(64512).encode().to_vec(),
        ));
        let o = attrs.otc().expect("present, well-formed");
        assert_eq!(o, Otc::new(64512));
        assert!(o.is_set());
        assert!(attrs.has_otc());

        // Present, value 0 — "set but zero". `otc()` returns
        // `Some(Otc(0))`; `has_otc()` reports presence; `is_set()`
        // reports false. This is the case `defined(bgp.otc)` in the
        // filter DSL must distinguish from "absent".
        let mut attrs_zero = PathAttributes::new();
        attrs_zero.insert(PathAttribute::new(
            PathAttrFlags::new().set_optional(true).set_transitive(true),
            AttrType::Otc,
            Otc(0).encode().to_vec(),
        ));
        assert_eq!(attrs_zero.otc(), Some(Otc(0)));
        assert!(attrs_zero.has_otc());
        assert!(!attrs_zero.otc().unwrap().is_set());

        // Malformed width — None on `otc()`, but `has_otc()` still
        // reports presence (the attribute is on the route; only the
        // value is unreadable). Mirrors the `cluster_list()` accessor's
        // behaviour on a partial tail.
        let mut attrs_bad = PathAttributes::new();
        attrs_bad.insert(PathAttribute::new(
            PathAttrFlags::new().set_optional(true).set_transitive(true),
            AttrType::Otc,
            vec![1, 2, 3],
        ));
        assert!(attrs_bad.otc().is_none());
        assert!(attrs_bad.has_otc());
    }
}
