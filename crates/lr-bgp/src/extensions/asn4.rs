//! RFC 4893 / RFC 6793 4-byte AS number extension.
//!
//! Wire support lives in
//! [`crate::capabilities::Capability::four_octet_as`] (capability 65,
//! 4-byte AS value); the OPEN/KEEPALIVE/NOTIFICATION codec's
//! `with_asn4` toggle (see [`crate::codec::BgpCodec::with_asn4`])
//! selects whether AS_PATH segments are encoded in the 2-byte or
//! 4-byte form. This module computes what a session should advertise
//! and what it may consume after the OPEN exchange, so the FSM does
//! not have to inline the same checks at every call site:
//!
//! - [`advertised`] — whether the local config opts the session into
//!   the 4-byte AS capability. The FSM gates the OPEN advertisement on
//!   this; the helper centralises the check so a caller can test the
//!   posture without constructing a peer (mirrors
//!   [`crate::extensions::enhanced_rr::advertised`]).
//! - [`negotiated`] — whether *both* speakers advertised the
//!   capability, so the 4-byte AS_PATH encoding can be used in both
//!   directions (RFC 6793 §4.2.2).
//! - [`open_capability`] — the capability to put in the OPEN, or
//!   `None` when the knob is off. Mirrors
//!   [`crate::extensions::enhanced_rr::open_capability`] in shape so
//!   the FSM's OPEN builder can call them uniformly.
//! - [`peer_as4`] — extracts the 4-byte AS the peer advertised in its
//!   OPEN. Returns `None` when the peer did not advertise the
//!   capability, when the value is malformed (length != 4) or when
//!   multiple capabilities disagree (RFC 6793 §4 says the receiver
//!   uses the first occurrence; the helper follows that rule and a
//!   later malformed duplicate does not invalidate an earlier
//!   well-formed value).
//!
//! # Negotiation posture
//!
//! RFC 6793 §4.2.2: "If a BGP speaker advertises the capability to
//! its peer, then it MUST be prepared to accept the AS4_PATH and
//! AS4_AGGREGATOR attributes from the peer". The codec is the consumer
//! of these attributes; the FSM's `set_asn4` call gates that
//! consumer. The negotiation is per-session: a later re-establishment
//! re-negotiates fresh (the configured `cfg.asn4` flag is the local
//! policy, the per-session `session_asn4` flag is what the codec
//! actually uses for that session's lifetime).
//!
//! # Backward compatibility
//!
//! A 2-byte-only speaker (one whose `cfg.asn4 = false`) does not
//! advertise the capability and falls back to the 2-byte AS_PATH
//! encoding for the lifetime of every session. A 4-byte speaker
//! paired with a 2-byte-only peer downgrades both directions to the
//! 2-byte width — RFC 6793 §4.2.2 mandates this fallback so the peer
//! can parse the AS_PATH. The [`negotiated`] helper encodes that
//! rule: the session uses 4-byte AS_PATH only when *both* speakers
//! advertised the capability.
//!
//! # Receive-side handling
//!
//! The peer's advertised AS value is the 4-byte AS number the peer
//! puts in the OPEN's `My Autonomous System` field when that value
//! does not fit in 2 bytes (RFC 6793 §4.2.2: the OPEN's 2-byte
//! `My Autonomous System` field is set to `AS_TRANS` = 23456 in that
//! case, and the real value rides the 4-byte AS capability). The FSM
//! reads the peer's 4-byte AS via [`peer_as4`] and falls back to the
//! OPEN's 2-byte field when the capability is absent — see
//! `BgpPeer::handle_open_in_opensent`.
//!
//! Before the issue #92 fix, the FSM inlined the negotiation logic at
//! every call site: the OPEN builder inlined `if self.cfg.asn4 {
//! caps.push(Capability::four_octet_as(...)) }`, the OPEN handler
//! inlined `peer_offered_as4 = caps.iter().any(|c| c.code ==
//! FourOctetAs)` and a separate `caps.iter().find(...).as_four_octet()`
//! chain. The orchestration helpers centralise those call sites so a
//! future change to the negotiation posture lands in one place.

use crate::capabilities::{Capability, CapabilityCode};
use crate::peer::PeerConfig;

/// Whether the local config opts this session into the 4-byte AS
/// capability (RFC 4893 / RFC 6793). The FSM gates the OPEN
/// advertisement on this; the helper centralises the check so a
/// caller can test the posture without constructing a peer.
///
/// This is a thin wrapper around [`PeerConfig::asn4`]; it exists so
/// every extension's `advertised` / `negotiated` / `open_capability`
/// triple has the same shape (compare
/// [`crate::extensions::enhanced_rr::advertised`] /
/// [`crate::extensions::long_lived::open_capability`]).
pub fn advertised(cfg: &PeerConfig) -> bool {
    cfg.asn4
}

/// Whether the peer advertised the 4-byte AS capability in its OPEN,
/// regardless of whether the value is well-formed. The FSM uses this
/// for the per-session AS_PATH width negotiation (RFC 6793 §4.2.2).
///
/// A capability with a malformed value (length != 4) still counts as
/// "offered" for negotiation purposes — the codec turns on the
/// 4-byte AS_PATH encoding, and the peer's advertised AS value is
/// read separately via [`peer_as4`] (which validates the length and
/// falls back to the OPEN's 2-byte field when the value is
/// malformed). This preserves the historical negotiation posture so
/// the helper refactor does not change which OPENs the FSM accepts.
pub fn peer_offered_as4(peer_caps: &[Capability]) -> bool {
    peer_caps
        .iter()
        .any(|c| c.code == CapabilityCode::FourOctetAs)
}

/// Whether *both* speakers advertised the 4-byte AS capability, so
/// the 4-byte AS_PATH encoding can be used in both directions
/// (RFC 6793 §4.2.2).
///
/// `cfg.asn4` is the local policy; `peer_offered_as4(peer_caps)` is
/// the peer's posture read from its OPEN's capabilities. The session
/// uses 4-byte AS_PATH only when both are true — otherwise the codec
/// falls back to the 2-byte width.
///
/// Per-session: the configured `cfg.asn4` flag stays constant across
/// re-establishments, but the negotiated value is recomputed from the
/// peer's OPEN every time, so a session that re-establishes after a
/// peer upgrade re-negotiates fresh (the FSM's `set_asn4` call is the
/// consumer; this helper is the producer).
pub fn negotiated(cfg: &PeerConfig, peer_caps: &[Capability]) -> bool {
    advertised(cfg) && peer_offered_as4(peer_caps)
}

/// Build the 4-byte AS capability for a configured peer's OPEN.
/// Returns `None` when the local config has the knob off — the OPEN
/// does not advertise the capability, and the receiver must not use
/// the 4-byte AS_PATH encoding for the session (RFC 6793 §4.2.2).
///
/// Mirrors
/// [`crate::extensions::enhanced_rr::open_capability`] in shape so
/// the FSM's OPEN builder can call them uniformly.
pub fn open_capability(cfg: &PeerConfig) -> Option<Capability> {
    if advertised(cfg) {
        Some(Capability::four_octet_as(cfg.local_as.as_u32()))
    } else {
        None
    }
}

/// Extract the 4-byte AS the peer advertised in its OPEN. Returns
/// `None` when the peer did not advertise the capability, when the
/// value is malformed (length != 4), or when every advertised
/// capability is malformed.
///
/// RFC 6793 §4: when the peer's AS does not fit in 2 bytes, the OPEN's
/// 2-byte `My Autonomous System` field is set to `AS_TRANS` (23456)
/// and the real value rides the 4-byte AS capability. The FSM reads
/// the peer's AS via this helper and falls back to the OPEN's 2-byte
/// field when the capability is absent — see
/// `BgpPeer::handle_open_in_opensent`.
///
/// When the peer advertised multiple AS4 capabilities (a malformed
/// OPEN), RFC 6793 §4 says the receiver uses the first occurrence; the
/// helper follows that rule — a later malformed duplicate does not
/// invalidate an earlier well-formed value.
pub fn peer_as4(peer_caps: &[Capability]) -> Option<u32> {
    peer_caps
        .iter()
        .find(|c| c.code == CapabilityCode::FourOctetAs)
        .and_then(Capability::as_four_octet)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::peer::PeerConfig;
    use lr_core::addr::{Asn, RouterId};

    fn cfg(asn4: bool) -> PeerConfig {
        let mut c = PeerConfig::new(Asn(64512), Asn(64513), RouterId::from_v4([10, 0, 0, 1]));
        c.asn4 = asn4;
        c
    }

    fn cfg_with_local_as(local_as: u32, asn4: bool) -> PeerConfig {
        let mut c = PeerConfig::new(Asn(local_as), Asn(64513), RouterId::from_v4([10, 0, 0, 1]));
        c.asn4 = asn4;
        c
    }

    #[test]
    fn advertised_tracks_knob() {
        assert!(!advertised(&cfg(false)));
        assert!(advertised(&cfg(true)));
    }

    #[test]
    fn open_capability_off_when_knob_off() {
        assert!(open_capability(&cfg(false)).is_none());
    }

    #[test]
    fn open_capability_on_when_knob_on() {
        let cap = open_capability(&cfg(true)).unwrap();
        assert_eq!(cap.code, CapabilityCode::FourOctetAs);
        assert_eq!(cap.as_four_octet(), Some(64512));
    }

    #[test]
    fn open_capability_carries_local_as_value() {
        // RFC 6793 §4.2.2: a 4-byte AS speaker puts its real AS in the
        // capability value, even when the value fits in 2 bytes (so
        // the peer can use the 4-byte form).
        let cap = open_capability(&cfg_with_local_as(70000, true)).unwrap();
        assert_eq!(cap.as_four_octet(), Some(70000));
    }

    #[test]
    fn peer_offered_when_capability_present() {
        let peer_caps = vec![Capability::four_octet_as(70000)];
        assert!(peer_offered_as4(&peer_caps));
    }

    #[test]
    fn peer_not_offered_when_capability_absent() {
        let peer_caps: Vec<Capability> = vec![];
        assert!(!peer_offered_as4(&peer_caps));
    }

    #[test]
    fn peer_offered_when_capability_value_is_malformed() {
        // The negotiation step does NOT validate the value length;
        // a malformed OPEN still flips the codec to the 4-byte AS_PATH
        // width. The peer's AS value is read separately via
        // `peer_as4`, which validates the length and falls back when
        // malformed. This preserves the historical negotiation
        // posture so the helper refactor does not change which OPENs
        // the FSM accepts.
        let malformed = Capability::new(CapabilityCode::FourOctetAs, vec![0; 2]);
        assert!(peer_offered_as4(&[malformed]));
    }

    #[test]
    fn negotiated_requires_local_knob() {
        // No local knob → not negotiated even if the peer advertised.
        let peer_caps = vec![Capability::four_octet_as(70000)];
        assert!(!negotiated(&cfg(false), &peer_caps));
    }

    #[test]
    fn negotiated_requires_peer_cap() {
        // Local knob on, but peer did not advertise → not negotiated.
        assert!(!negotiated(&cfg(true), &[]));
    }

    #[test]
    fn negotiated_when_both_sides_advertise() {
        let peer_caps = vec![Capability::four_octet_as(70000)];
        assert!(negotiated(&cfg(true), &peer_caps));
    }

    #[test]
    fn negotiated_when_peer_cap_is_malformed() {
        // The negotiation just checks the capability code; a
        // malformed value still flips the codec to 4-byte (the peer
        // advertised the capability, even if its value is broken).
        let malformed = Capability::new(CapabilityCode::FourOctetAs, vec![0; 2]);
        assert!(negotiated(&cfg(true), &[malformed]));
    }

    #[test]
    fn peer_as4_returns_none_when_absent() {
        assert!(peer_as4(&[]).is_none());
    }

    #[test]
    fn peer_as4_returns_value_when_present() {
        let peer_caps = vec![Capability::four_octet_as(70000)];
        assert_eq!(peer_as4(&peer_caps), Some(70000));
    }

    #[test]
    fn peer_as4_returns_none_when_value_is_malformed() {
        let malformed = Capability::new(CapabilityCode::FourOctetAs, vec![0; 2]);
        assert!(peer_as4(&[malformed]).is_none());
    }

    #[test]
    fn peer_as4_uses_first_occurrence_on_duplicate() {
        // RFC 6793 §4: the receiver uses the first occurrence. A
        // later malformed duplicate does not invalidate an earlier
        // well-formed value.
        let first = Capability::four_octet_as(70000);
        let malformed = Capability::new(CapabilityCode::FourOctetAs, vec![0; 2]);
        assert_eq!(peer_as4(&[first, malformed]), Some(70000));
    }

    #[test]
    fn peer_as4_skips_unrelated_capabilities() {
        // A peer's OPEN typically advertises several capabilities;
        // `peer_as4` walks past the unrelated ones.
        let mp = Capability::multiprotocol(1, 1);
        let as4 = Capability::four_octet_as(70000);
        let enh = Capability::enhanced_rr();
        assert_eq!(peer_as4(&[mp, as4, enh]), Some(70000));
    }
}
