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

/// Compute the OTC value to set when receiving a route from a peer with
/// `peer_role`.
///
/// Per RFC 9234 §3.2:
/// - On reception from a Customer or Peer: set OTC=local_as if absent.
/// - On reception from a Provider: OTC must be present; if absent, set to
///   peer_as (treat as if the provider already tagged it).
/// - On reception from RS-Client (when local is RS): no change (RS will
///   set it for downstream clients as appropriate).
/// - On reception when local is RS-Client: same as Provider.
pub fn otc_on_receive(
    existing: Option<Otc>,
    local_role: OtcRole,
    local_as: Asn,
    peer_as: Asn,
) -> Otc {
    match local_role {
        OtcRole::Customer => existing.unwrap_or(Otc(local_as.0)),
        OtcRole::Peer => existing.unwrap_or(Otc(local_as.0)),
        OtcRole::Provider => existing.unwrap_or(Otc(peer_as.0)),
        OtcRole::RouteServer => existing.unwrap_or(Otc(0)),
        OtcRole::RsClient => existing.unwrap_or(Otc(peer_as.0)),
        OtcRole::Unset => existing.unwrap_or(Otc(0)),
    }
}

/// Whether a route with `route_otc` may be advertised to a peer with
/// `peer_role`, per RFC 9234 §3.3.
pub fn otc_can_advertise(route_otc: Otc, peer_role: OtcRole) -> bool {
    if !route_otc.is_set() {
        return true;
    }
    match peer_role {
        // A route with OTC may only go to customers or RS-clients of an RS.
        OtcRole::Customer | OtcRole::RsClient => true,
        OtcRole::RouteServer => true,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn otc_roundtrip() {
        let o = Otc::new(64512);
        let enc = o.encode();
        let dec = Otc::decode(&enc).unwrap();
        assert_eq!(dec, o);
        assert!(o.is_set());
        assert!(!Otc(0).is_set());
    }

    #[test]
    fn otc_set_on_customer_reception() {
        let r = otc_on_receive(None, OtcRole::Customer, Asn(100), Asn(200));
        assert_eq!(r.0, 100);
    }

    #[test]
    fn otc_set_on_peer_reception() {
        let r = otc_on_receive(None, OtcRole::Peer, Asn(100), Asn(200));
        assert_eq!(r.0, 100);
    }

    #[test]
    fn otc_set_on_provider_reception() {
        let r = otc_on_receive(None, OtcRole::Provider, Asn(100), Asn(200));
        assert_eq!(r.0, 200);
    }

    #[test]
    fn otc_advertise_only_to_customer() {
        let otc = Otc::new(100);
        assert!(otc_can_advertise(otc, OtcRole::Customer));
        assert!(!otc_can_advertise(otc, OtcRole::Provider));
        assert!(!otc_can_advertise(otc, OtcRole::Peer));
    }
}
