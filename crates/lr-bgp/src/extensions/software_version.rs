//! Software Version capability
//! (draft-abraitis-bgp-version-capability-18) orchestration helper.
//!
//! The wire-level capability lives in
//! [`crate::capabilities::Capability::software_version`] (code 75).
//! This module computes what a session should advertise and what
//! the daemon may surface after the OPEN exchange:
//!
//! - [`advertised`] — whether the local config sets a non-empty
//!   version string for this session.
//! - [`peer_software_version`] — the version string the peer
//!   advertised, decoded from its OPEN. The daemon's `lrctl show
//!   sessions` surfaces this so an operator can audit the software
//!   mix of the peer set.
//!
//! # Draft encoding
//!
//! The latest draft carries the UTF-8 string as the whole capability
//! value. draft-abraitis-bgp-version-capability-11 and earlier
//! prepended a one-octet length. [`crate::peer::PeerConfig`] selects
//! the outgoing encoding with
//! [`SoftwareVersionEncoding`](crate::capabilities_extra::SoftwareVersionEncoding);
//! the decoder always accepts both, so a session between peers on
//! different revisions still exchanges the string.

use crate::capabilities::{Capability, CapabilityCode};
use crate::peer::PeerConfig;

/// Whether the local config sets a non-empty software version string
/// for this session. The FSM gates the OPEN advertisement on this.
///
/// The latest draft defines a zero-length capability value as an
/// encoding error, so an empty configured string is treated as
/// "do not advertise" rather than emitting an invalid capability.
pub fn advertised(cfg: &PeerConfig) -> bool {
    cfg.software_version
        .as_deref()
        .is_some_and(|version| !version.is_empty())
}

/// The version string the local config established for this
/// session, or `None` when the capability is not advertised.
pub fn local_version(cfg: &PeerConfig) -> Option<&str> {
    cfg.software_version
        .as_deref()
        .filter(|version| !version.is_empty())
}

/// Whether the peer advertised the Software Version capability in
/// its OPEN.
pub fn peer_offered(peer_caps: &[Capability]) -> bool {
    peer_caps
        .iter()
        .any(|c| c.code == CapabilityCode::SoftwareVersion)
}

/// The peer's advertised version string, decoded from its OPEN
/// capability. Returns `None` when the peer did not advertise the
/// capability or its value is malformed (empty, or not valid
/// UTF-8 after the detected draft encoding is stripped).
pub fn peer_software_version(peer_caps: &[Capability]) -> Option<String> {
    peer_caps
        .iter()
        .find(|c| c.code == CapabilityCode::SoftwareVersion)
        .and_then(Capability::as_software_version)
}

/// Build the Software Version capability for a configured peer's
/// OPEN. Returns `None` when the local config has no non-empty
/// version set.
pub fn open_capability(cfg: &PeerConfig) -> Option<Capability> {
    let version = local_version(cfg)?;
    Some(Capability::software_version_with(
        version,
        cfg.software_version_encoding,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capabilities_extra::SoftwareVersionEncoding;
    use crate::peer::PeerConfig;
    use lr_core::addr::{Asn, RouterId};

    fn cfg(version: Option<&str>) -> PeerConfig {
        let mut c = PeerConfig::new(Asn(64512), Asn(64513), RouterId::from_v4([10, 0, 0, 1]));
        c.software_version = version.map(String::from);
        c
    }

    #[test]
    fn advertised_tracks_knob() {
        assert!(!advertised(&cfg(None)));
        assert!(advertised(&cfg(Some("lr/2.0"))));
        assert!(!advertised(&cfg(Some(""))));
    }

    #[test]
    fn open_capability_off_when_knob_off() {
        assert!(open_capability(&cfg(None)).is_none());
        assert!(open_capability(&cfg(Some(""))).is_none());
    }

    #[test]
    fn open_capability_defaults_to_latest_encoding() {
        let cap = open_capability(&cfg(Some("lr/2.0"))).unwrap();
        assert_eq!(cap.code, CapabilityCode::SoftwareVersion);
        assert_eq!(cap.value, b"lr/2.0");
        assert_eq!(cap.as_software_version(), Some("lr/2.0".to_string()));
    }

    #[test]
    fn open_capability_honours_draft11_encoding() {
        let mut c = cfg(Some("lr/2.0"));
        c.software_version_encoding = SoftwareVersionEncoding::Draft11;
        let cap = open_capability(&c).unwrap();
        assert_eq!(cap.value, b"\x06lr/2.0");
        assert_eq!(cap.as_software_version(), Some("lr/2.0".to_string()));
    }

    #[test]
    fn peer_software_version_returns_value_when_present() {
        let cap = open_capability(&cfg(Some("frrouting/10.5.1"))).unwrap();
        assert_eq!(
            peer_software_version(&[cap]),
            Some("frrouting/10.5.1".to_string())
        );
    }

    #[test]
    fn peer_software_version_returns_none_when_absent() {
        assert!(peer_software_version(&[]).is_none());
    }

    #[test]
    fn peer_software_version_returns_none_when_malformed() {
        let malformed = Capability::new(CapabilityCode::SoftwareVersion, vec![]);
        assert!(peer_software_version(&[malformed]).is_none());
    }
}
