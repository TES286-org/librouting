//! BGP peer configuration. Transport is abstract — the FSM emits bytes via
//! [`crate::fsm::BgpAction::Send`] and the embedder pumps inbound bytes via
//! [`crate::fsm::BgpPeer::feed_bytes`].

use lr_core::addr::{Asn, RouterId};

/// Per-peer configuration. Used to build a [`crate::fsm::BgpPeer`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerConfig {
    /// Local AS number.
    pub local_as: Asn,
    /// Peer AS number. Determines whether the session is eBGP.
    pub peer_as: Asn,
    /// Local BGP identifier.
    pub local_bgp_id: RouterId,
    /// Proposed hold time (seconds). 0 = use peer's value.
    pub hold_time: u16,
    /// True if this is a route-reflector client (RFC 4456).
    pub route_reflector_client: bool,
    /// True if this is a confederation peer (RFC 3065).
    pub confederation_member: bool,
    /// Optional: override the peer's BGP identifier.
    pub peer_bgp_id: Option<RouterId>,
    /// Optional: enable 4-byte AS capability (RFC 4893).
    pub asn4: bool,
    /// Optional: enable MP-BGP for given families.
    pub mp_families: Vec<lr_core::nlri::NlriFamily>,
    /// Optional: enable AddPath (RFC 7911).
    pub add_path: bool,
    /// Optional: enable graceful restart (RFC 4724).
    pub graceful_restart: bool,
    /// Optional: enable enhanced route refresh (RFC 7313).
    pub enhanced_rr: bool,
    /// Optional: keepalive interval (seconds). 0 = hold_time / 3.
    pub keepalive: u16,
}

impl PeerConfig {
    pub fn new(local_as: Asn, peer_as: Asn, local_bgp_id: RouterId) -> Self {
        Self {
            local_as,
            peer_as,
            local_bgp_id,
            hold_time: 90,
            route_reflector_client: false,
            confederation_member: false,
            peer_bgp_id: None,
            asn4: true,
            mp_families: Vec::new(),
            add_path: false,
            graceful_restart: false,
            enhanced_rr: false,
            keepalive: 0,
        }
    }

    pub fn is_ebgp(&self) -> bool {
        self.local_as != self.peer_as
    }

    pub fn keepalive_interval(&self) -> u16 {
        if self.keepalive != 0 {
            self.keepalive
        } else {
            (self.hold_time / 3).max(1)
        }
    }
}
