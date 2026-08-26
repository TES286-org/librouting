//! Route Server configuration (RFC 7947) for Internet eXchange (IX) use.
//!
//! At an Internet Exchange (IX), multiple ASes peer with a single route
//! server (RS) over a shared broadcast domain. Each RS-client has its own
//! peering with the RS, but expects the RS to forward routes to its other
//! peers *without* modifying AS_PATH to include the RS's own AS (otherwise
//! each route would appear to transit the RS).
//!
//! Route Server behavior:
//!
//! - On inbound: AS_PATH is stored verbatim. NEXT_HOP is preserved. The route
//!   is associated with the originating AS via the **origin** of the AS_PATH
//!   (or the AS4_PATH for 4-byte ASNs).
//! - On outbound to an RS-client: the local AS is *not* prepended; NEXT_HOP
//!   is preserved; the local speaker's INBOUND community is replaced with
//!   the OUTBOUND community when configured for that pair (per
//!   RFC 7947 §2.3.4 "community rewriting").
//! - The RS may apply client-specific filter chains per RFC 7947 §2.3.4.
//!
//! Note: this implementation does not enforce RFC 8212 ("Default EBGP Route
//! Behaviors toward eBGP Peers"). The embedder's policy chain should set the
//! default behaviors; the route server module only marks the peer as
//! "transit-transparent" for AS_PATH/NEXT_HOP.

/// Per-peer route-server configuration.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RouteServerConfig {
    /// True if this peer is a route-server client (RFC 7947).
    pub client: bool,
    /// Optional: a per-client "process" filter chain name — applied on
    /// inbound before the route is stored in Adj-RIB-In.
    pub inbound_policy: Option<String>,
    /// Optional: a per-client "export" filter chain name — applied on
    /// outbound to this client.
    pub outbound_policy: Option<String>,
    /// Optional: if set, communities in this set are removed when forwarding
    /// to this client (e.g. to strip the IX's internal communities).
    pub strip_communities: Vec<u32>,
    /// Optional: if set, the listed communities are added when exporting to
    /// this client.
    pub add_communities: Vec<u32>,
}

impl RouteServerConfig {
    pub fn new_client() -> Self {
        Self {
            client: true,
            inbound_policy: None,
            outbound_policy: None,
            strip_communities: Vec::new(),
            add_communities: Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_default() {
        let c = RouteServerConfig::new_client();
        assert!(c.client);
        assert!(c.inbound_policy.is_none());
        assert!(c.outbound_policy.is_none());
    }
}
