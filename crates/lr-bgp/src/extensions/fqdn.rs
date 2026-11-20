//! FQDN/Hostname capability (draft-walton-bgp-hostname-capability-01)
//! orchestration helper.
//!
//! The wire-level capability lives in
//! [`crate::capabilities::Capability::fqdn`] (code 73). The module
//! computes what a session should advertise and what the daemon
//! may surface after the OPEN exchange:
//!
//! - [`advertised`] — whether the local config sets a hostname or
//!   domain for this session.
//! - [`peer_fqdn`] — the `(hostname, domain)` pair the peer
//!   advertised, decoded from its OPEN. The daemon's `lrctl show
//!   sessions` and the metrics endpoint surface this so an operator
//!   can identify a peer by name rather than by transport address.

use crate::capabilities::{Capability, CapabilityCode};
use crate::peer::PeerConfig;

/// Whether the local config sets a hostname or domain for this
/// session. The FSM gates the OPEN advertisement on this.
pub fn advertised(cfg: &PeerConfig) -> bool {
    cfg.fqdn.is_some()
}

/// The `(hostname, domain)` pair the local config established for
/// this session, or `None` when the capability is not advertised.
pub fn local_fqdn(cfg: &PeerConfig) -> Option<&(String, String)> {
    cfg.fqdn.as_ref()
}

/// Whether the peer advertised the FQDN capability in its OPEN.
pub fn peer_offered(peer_caps: &[Capability]) -> bool {
    peer_caps.iter().any(|c| c.code == CapabilityCode::Fqdn)
}

/// The peer's advertised `(hostname, domain)` pair, decoded from
/// its OPEN capability. Returns `None` when the peer did not
/// advertise the capability or its value is malformed (length
/// fields do not add up, or either string is not valid UTF-8).
pub fn peer_fqdn(peer_caps: &[Capability]) -> Option<(String, String)> {
    peer_caps
        .iter()
        .find(|c| c.code == CapabilityCode::Fqdn)
        .and_then(Capability::as_fqdn)
}

/// Build the FQDN capability for a configured peer's OPEN. Returns
/// `None` when the local config has no hostname or domain set.
pub fn open_capability(cfg: &PeerConfig) -> Option<Capability> {
    let (hostname, domain) = cfg.fqdn.as_ref()?;
    Some(Capability::fqdn(hostname, domain))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::peer::PeerConfig;
    use lr_core::addr::{Asn, RouterId};

    fn cfg(fqdn: Option<(&str, &str)>) -> PeerConfig {
        let mut c = PeerConfig::new(Asn(64512), Asn(64513), RouterId::from_v4([10, 0, 0, 1]));
        c.fqdn = fqdn.map(|(h, d)| (h.to_string(), d.to_string()));
        c
    }

    #[test]
    fn advertised_tracks_knob() {
        assert!(!advertised(&cfg(None)));
        assert!(advertised(&cfg(Some(("border-r1", "example.net")))));
    }

    #[test]
    fn open_capability_off_when_knob_off() {
        assert!(open_capability(&cfg(None)).is_none());
    }

    #[test]
    fn open_capability_carries_strings() {
        let cap = open_capability(&cfg(Some(("border-r1", "example.net")))).unwrap();
        assert_eq!(cap.code, CapabilityCode::Fqdn);
        assert_eq!(
            cap.as_fqdn(),
            Some(("border-r1".to_string(), "example.net".to_string()))
        );
    }

    #[test]
    fn peer_fqdn_returns_value_when_present() {
        let cap = open_capability(&cfg(Some(("rr-hk01", "")))).unwrap();
        assert_eq!(
            peer_fqdn(&[cap]),
            Some(("rr-hk01".to_string(), String::new()))
        );
    }

    #[test]
    fn peer_fqdn_returns_none_when_absent() {
        assert!(peer_fqdn(&[]).is_none());
    }

    #[test]
    fn peer_fqdn_returns_none_when_malformed() {
        let malformed = Capability::new(CapabilityCode::Fqdn, vec![]);
        assert!(peer_fqdn(&[malformed]).is_none());
    }
}
