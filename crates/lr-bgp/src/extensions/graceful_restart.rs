//! BGP Graceful Restart (RFC 4724) orchestration helpers.
//!
//! Wire support lives in [`crate::capabilities::Capability::graceful_restart`]
//! (capability 64, per-address-family tuples with the Forwarding State bit);
//! the retention procedures run in `lr-router`:
//!
//! | RFC section | Requirement | Implementation |
//! |-------------|-------------|-----------------|
//! | §3 | Capability with restart flags/time + per-family F bits | `Capability::graceful_restart` |
//! | §4.1 | Restarting speaker defers selection until EoR | embedder policy; the FSM emits `EndOfRib` |
//! | §4.1 | EoR marker sent after the initial table dump | `BgpPeer::send_end_of_rib` |
//! | §4.2 | Helper retains routes of the listed families on session loss | `lr-router` retention state |
//! | §4.2 | Routes are deleted when the advertised Restart Time elapses | `DefaultRouter::tick` retention expiry |
//! | §4.2 | Stale routes the peer did not refresh are removed at EoR | `lr-router::on_end_of_rib` |
//!
//! This module computes what a session should advertise and what it may
//! consume after the OPEN exchange, so the FSM does not have to inline
//! the same checks at every call site:
//!
//! - [`advertised`] — whether the local config opts the session into
//!   the RFC 4724 capability. The FSM gates the OPEN advertisement on
//!   this; the helper centralises the check so a caller can test the
//!   posture without constructing a peer (mirrors
//!   [`crate::extensions::enhanced_rr::advertised`] /
//!   [`crate::extensions::asn4::advertised`]).
//! - [`advertised_families`] — the address-family list to put in the
//!   capability. Shared with [`crate::extensions::long_lived`] because
//!   RFC 9494 §3.1 reuses the GR family list shape; LLGR re-exports
//!   this helper so a caller can build either capability from the same
//!   source.
//! - [`peer_offered`] — whether the peer advertised the RFC 4724
//!   capability in its OPEN, regardless of value well-formedness. The
//!   FSM uses this for the per-session retention policy (§4.2).
//! - [`peer_restart_time`] — the peer's advertised Restart Time (§3),
//!   in seconds. Returns `None` when the peer did not advertise the
//!   capability or its value is malformed; the FSM uses this to set the
//!   retention deadline.
//! - [`peer_restart_state`] — whether the peer's R bit (Restart State,
//!   §3) is set, so the local helper-of-record knows the peer is in
//!   the process of restoring its routes. The restarting speaker sets
//!   the R bit in its OPEN; the receiver keys its retention policy on
//!   it (§4.2 step 2).
//! - [`negotiated`] — whether both speakers advertised the
//!   capability, so the helper-of-record retention policy (§4.2)
//!   applies. Mirrors
//!   [`crate::extensions::asn4::negotiated`] /
//!   [`crate::extensions::enhanced_rr::negotiated`] in shape so the
//!   FSM can call them uniformly.
//! - [`open_capability`] — the capability to put in the OPEN, or
//!   `None` when the knob is off. Mirrors
//!   [`crate::extensions::enhanced_rr::open_capability`] /
//!   [`crate::extensions::long_lived::open_capability`] in shape so
//!   the FSM's OPEN builder can call them uniformly.
//!
//! # Negotiation posture
//!
//! RFC 4724 §4.2: "If the peer did not advertise the Graceful Restart
//! capability, the local speaker MUST NOT retain any routes from the
//! peer." The FSM gates retention on [`negotiated`]; the helper
//! centralises the local-knob + peer-capability check so a caller can
//! test the posture without constructing a peer (the same shape
//! [`crate::extensions::asn4`] / [`crate::extensions::enhanced_rr`]
//! already use).
//!
//! # Backward compatibility
//!
//! Before the issue #92 fix, the FSM inlined the OPEN capability
//! construction (`if cfg.graceful_restart { caps.push(... graceful_restart
//! (0, cfg.graceful_restart_time, &families) ...) }`) and the peer-capability
//! walk (`peer_capabilities.iter().find_map(... as_graceful_restart)`).
//! The orchestration helpers centralise those call sites so a future
//! change to the negotiation posture lands in one place.
//!
//! The RFC 9494 Long-Lived Graceful Restart extension (a second, longer
//! retention window with `LLGR_STALE` marking) builds on this module — see
//! [`crate::extensions::long_lived`].

use crate::capabilities::{Capability, CapabilityCode};
use crate::peer::PeerConfig;

use lr_core::nlri::NlriFamily;

/// R bit (RFC 4724 §3): set in the Restart Flags when the speaker has
/// restarted its control plane and is in the process of restoring its
/// routes. Cleared otherwise — the local speaker keeps R=0 in its
/// own OPEN at startup; the receiver keys its retention policy on
/// the *peer's* R bit (see [`peer_restart_state`]).
pub const FLAG_RESTART_STATE: u8 = 0x08;

/// Whether the local config opts this session into the RFC 4724
/// capability. The FSM gates the OPEN advertisement on this; the
/// helper centralises the check so a caller can test the posture
/// without constructing a peer.
///
/// This is a thin wrapper around [`PeerConfig::graceful_restart`]; it
/// exists so every extension's `advertised` / `negotiated` /
/// `open_capability` triple has the same shape (compare
/// [`crate::extensions::enhanced_rr::advertised`] /
/// [`crate::extensions::asn4::advertised`]).
pub fn advertised(cfg: &PeerConfig) -> bool {
    cfg.graceful_restart
}

/// Address families a restart-related capability (RFC 4724 §3 GR,
/// RFC 9494 §3.1 LLGR) should list for a peer: the negotiated
/// MP-BGP families, or implicit `<IPv4, Unicast>` when the session
/// uses RFC 4271 encoding only (RFC 9494 §3.1, applied to GR by §3
/// too — the family list is the same shape).
///
/// FRR `no bgp default ipv4-unicast` (W2.1): when the knob is off and
/// the peer did not explicitly add IPv4 unicast to `mp_families`, the
/// capability does NOT list it — the family is not active, so there
/// is no retention promise to make.
///
/// Re-exported by [`crate::extensions::long_lived`] so the LLGR
/// capability and the GR capability list the same families from one
/// source.
pub fn advertised_families(cfg: &PeerConfig) -> Vec<NlriFamily> {
    if !cfg.default_ipv4_unicast && !cfg.mp_families.contains(&NlriFamily::IPV4_UNICAST) {
        return cfg.mp_families.clone();
    }
    if cfg.mp_families.is_empty() {
        vec![NlriFamily::IPV4_UNICAST]
    } else {
        cfg.mp_families.clone()
    }
}

/// Whether the peer advertised the RFC 4724 capability in its OPEN,
/// regardless of whether the value is well-formed. The FSM uses this
/// for the per-session retention policy (RFC 4724 §4.2: "if the peer
/// did not advertise the Graceful Restart capability, the local
/// speaker MUST NOT retain any routes from the peer").
///
/// A capability with a malformed value (length < 2) still counts as
/// "offered" for negotiation purposes — the receiver treats it as a
/// signal that the peer intends to preserve state for the listed
/// families, and reads the Restart Time / R bit separately via
/// [`peer_restart_time`] / [`peer_restart_state`], both of which
/// validate the value.
pub fn peer_offered(peer_caps: &[Capability]) -> bool {
    peer_caps
        .iter()
        .any(|c| c.code == CapabilityCode::GracefulRestart)
}

/// The peer's advertised Restart Time (RFC 4724 §3), in seconds.
/// Returns `None` when the peer did not advertise the capability or
/// when the value is malformed (length < 2).
///
/// The Restart Time is the maximum number of seconds the helper
/// retains the peer's routes after a session reset (§4.2). The FSM
/// uses this to set the retention deadline in `lr-router`.
pub fn peer_restart_time(peer_caps: &[Capability]) -> Option<u16> {
    peer_caps
        .iter()
        .find_map(Capability::as_graceful_restart)
        .map(|(_, time)| time)
}

/// Whether the peer's R bit (Restart State, RFC 4724 §3) is set, so
/// the local helper-of-record knows the peer has just restarted its
/// control plane and is in the process of restoring its routes.
/// Returns `false` when the peer did not advertise the capability or
/// when the value is malformed.
///
/// §4.2 step 2: when the R bit is set, the helper preserves the
/// peer's routes for the advertised Restart Time; when it is clear,
/// the peer is not restarting and the routes stay because the
/// adjacency was deliberately reset.
pub fn peer_restart_state(peer_caps: &[Capability]) -> bool {
    peer_caps
        .iter()
        .find_map(Capability::as_graceful_restart)
        .is_some_and(|(flags, _)| flags & FLAG_RESTART_STATE != 0)
}

/// Whether *both* speakers advertised the RFC 4724 capability, so
/// the helper-of-record retention policy (§4.2) applies. Mirrors
/// [`crate::extensions::asn4::negotiated`] /
/// [`crate::extensions::enhanced_rr::negotiated`] in shape so the
/// FSM can call them uniformly.
///
/// `cfg.graceful_restart` is the local policy; `peer_offered(peer_caps)`
/// is the peer's posture read from its OPEN's capabilities. The
/// session retains the peer's routes only when both are true —
/// otherwise the FSM does not install the retention deadline in
/// `lr-router`.
pub fn negotiated(cfg: &PeerConfig, peer_caps: &[Capability]) -> bool {
    advertised(cfg) && peer_offered(peer_caps)
}

/// Build the RFC 4724 capability for a configured peer's OPEN.
/// Returns `None` when the local config has the knob off — the OPEN
/// does not advertise the capability, and the receiver must not
/// retain the speaker's routes (§4.2).
///
/// The R bit (Restart State, §3) is left clear: the local speaker is
/// not in the restart state when sending a fresh OPEN. A restarting
/// speaker that needs to set the R bit can do so by post-processing
/// the returned capability (the bit lives in the high nibble of the
/// first value byte). The F bit per family is set: the library keeps
/// Adj-RIB-In across reconnects within the same process (the
/// reference daemon), so the forwarding state is preserved.
///
/// Mirrors
/// [`crate::extensions::enhanced_rr::open_capability`] /
/// [`crate::extensions::long_lived::open_capability`] in shape so
/// the FSM's OPEN builder can call them uniformly.
pub fn open_capability(cfg: &PeerConfig) -> Option<Capability> {
    if !advertised(cfg) {
        return None;
    }
    let families: Vec<(u16, u8, bool)> = advertised_families(cfg)
        .into_iter()
        .map(|f| (f.afi, f.safi, true))
        .collect();
    Some(Capability::graceful_restart(
        0,
        cfg.graceful_restart_time,
        &families,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::peer::PeerConfig;
    use lr_core::addr::{Asn, RouterId};

    fn cfg(graceful_restart: bool) -> PeerConfig {
        let mut c = PeerConfig::new(Asn(64512), Asn(64513), RouterId::from_v4([10, 0, 0, 1]));
        c.graceful_restart = graceful_restart;
        c
    }

    fn cfg_with_time(graceful_restart: bool, time: u16) -> PeerConfig {
        let mut c = cfg(graceful_restart);
        c.graceful_restart_time = time;
        c
    }

    fn cfg_with_families(graceful_restart: bool, families: &[NlriFamily]) -> PeerConfig {
        let mut c = cfg(graceful_restart);
        c.mp_families = families.to_vec();
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
        let cap = open_capability(&cfg_with_time(true, 120)).unwrap();
        assert_eq!(cap.code, CapabilityCode::GracefulRestart);
        let (flags, time) = cap.as_graceful_restart().unwrap();
        // R bit is clear on a fresh OPEN; only the time is set.
        assert_eq!(flags, 0);
        assert_eq!(time, 120);
    }

    #[test]
    fn open_capability_lists_implicit_ipv4_when_no_mp_families() {
        // No mp_families ⇒ implicit IPv4 unicast (RFC 4271 default).
        let cap = open_capability(&cfg(true)).unwrap();
        let families = cap.as_graceful_restart_families().unwrap();
        assert_eq!(families, vec![(1, 1, true)]);
    }

    #[test]
    fn open_capability_lists_mp_families_when_set() {
        let cap = open_capability(&cfg_with_families(
            true,
            &[NlriFamily::IPV4_UNICAST, NlriFamily::IPV6_UNICAST],
        ))
        .unwrap();
        let families = cap.as_graceful_restart_families().unwrap();
        assert_eq!(families.len(), 2);
        assert_eq!(families[0].0, 1); // IPv4
        assert_eq!(families[1].0, 2); // IPv6
    }

    #[test]
    fn open_capability_omits_implicit_ipv4_when_default_off() {
        // FRR `no bgp default ipv4-unicast` (W2.1): IPv4 unicast is not
        // listed unless the operator added it explicitly.
        let mut c = cfg(true);
        c.default_ipv4_unicast = false;
        c.mp_families = vec![NlriFamily::IPV6_UNICAST];
        let cap = open_capability(&c).unwrap();
        let families = cap.as_graceful_restart_families().unwrap();
        assert_eq!(families, vec![(2, 1, true)]);
    }

    #[test]
    fn open_capability_keeps_explicit_ipv4_when_default_off() {
        // Explicit IPv4 unicast in mp_families is kept even when the
        // default is off — the operator opted in for this session.
        let mut c = cfg(true);
        c.default_ipv4_unicast = false;
        c.mp_families = vec![NlriFamily::IPV4_UNICAST, NlriFamily::IPV6_UNICAST];
        let cap = open_capability(&c).unwrap();
        let families = cap.as_graceful_restart_families().unwrap();
        assert_eq!(families.len(), 2);
        assert_eq!(families[0].0, 1);
        assert_eq!(families[1].0, 2);
    }

    #[test]
    fn peer_offered_when_capability_present() {
        let cap = open_capability(&cfg(true)).unwrap();
        assert!(peer_offered(&[cap]));
    }

    #[test]
    fn peer_not_offered_when_capability_absent() {
        let peer_caps: Vec<Capability> = vec![];
        assert!(!peer_offered(&peer_caps));
    }

    #[test]
    fn peer_offered_when_capability_value_is_malformed() {
        // The negotiation step does NOT validate the value length;
        // a malformed OPEN still counts as "offered" for the retention
        // policy. The Restart Time / R bit reads validate the value
        // separately and return None / false when malformed. This
        // preserves the historical negotiation posture so the helper
        // refactor does not change which OPENs the FSM accepts.
        let malformed = Capability::new(CapabilityCode::GracefulRestart, vec![0]);
        assert!(peer_offered(&[malformed]));
    }

    #[test]
    fn peer_restart_time_returns_none_when_absent() {
        assert!(peer_restart_time(&[]).is_none());
    }

    #[test]
    fn peer_restart_time_returns_value_when_present() {
        let cap = open_capability(&cfg_with_time(true, 90)).unwrap();
        assert_eq!(peer_restart_time(&[cap]), Some(90));
    }

    #[test]
    fn peer_restart_time_returns_none_when_value_is_malformed() {
        // A capability with length < 2 cannot decode the (flags, time)
        // pair; `as_graceful_restart` returns None and the helper
        // surfaces it.
        let malformed = Capability::new(CapabilityCode::GracefulRestart, vec![0]);
        assert!(peer_restart_time(&[malformed]).is_none());
    }

    #[test]
    fn peer_restart_time_uses_first_occurrence_on_duplicate() {
        // RFC 4724 does not address duplicate GR capabilities; the
        // helper takes the first well-formed value (matching the
        // asn4 helper's `peer_as4` rule on RFC 6793 §4: "the
        // receiver uses the first occurrence"). A later malformed
        // duplicate does not invalidate an earlier well-formed value.
        let first = open_capability(&cfg_with_time(true, 120)).unwrap();
        let malformed = Capability::new(CapabilityCode::GracefulRestart, vec![0]);
        assert_eq!(peer_restart_time(&[first, malformed]), Some(120));
    }

    #[test]
    fn peer_restart_time_skips_unrelated_capabilities() {
        // A peer's OPEN typically advertises several capabilities;
        // `peer_restart_time` walks past the unrelated ones.
        let mp = Capability::multiprotocol(1, 1);
        let gr = open_capability(&cfg_with_time(true, 120)).unwrap();
        let enh = Capability::enhanced_rr();
        assert_eq!(peer_restart_time(&[mp, gr, enh]), Some(120));
    }

    #[test]
    fn peer_restart_state_clear_on_fresh_open() {
        // The local speaker's fresh OPEN keeps the R bit clear.
        let cap = open_capability(&cfg(true)).unwrap();
        assert!(!peer_restart_state(&[cap]));
    }

    #[test]
    fn peer_restart_state_set_when_peer_signalled_restart() {
        // Restarting speaker sets the R bit (RFC 4724 §3 bit 0x8).
        let cap = Capability::graceful_restart(FLAG_RESTART_STATE, 120, &[(1, 1, true)]);
        assert!(peer_restart_state(&[cap]));
    }

    #[test]
    fn peer_restart_state_false_when_capability_absent() {
        assert!(!peer_restart_state(&[]));
    }

    #[test]
    fn peer_restart_state_false_when_value_is_malformed() {
        let malformed = Capability::new(CapabilityCode::GracefulRestart, vec![0]);
        assert!(!peer_restart_state(&[malformed]));
    }

    #[test]
    fn negotiated_requires_local_knob() {
        // No local knob → not negotiated even if the peer advertised.
        let peer_caps = vec![open_capability(&cfg(true)).unwrap()];
        assert!(!negotiated(&cfg(false), &peer_caps));
    }

    #[test]
    fn negotiated_requires_peer_cap() {
        // Local knob on, but peer did not advertise → not negotiated.
        assert!(!negotiated(&cfg(true), &[]));
    }

    #[test]
    fn negotiated_when_both_sides_advertise() {
        let peer_caps = vec![open_capability(&cfg(true)).unwrap()];
        assert!(negotiated(&cfg(true), &peer_caps));
    }

    #[test]
    fn negotiated_when_peer_cap_is_malformed() {
        // `peer_offered` does not validate the value length; a
        // malformed capability still counts as "the peer intended to
        // preserve state for the listed families." The retention
        // deadline uses `peer_restart_time`, which validates and
        // returns None when malformed (the FSM then keeps retention
        // with a 0-second deadline, the same posture the inline
        // code had).
        let malformed = Capability::new(CapabilityCode::GracefulRestart, vec![0]);
        assert!(negotiated(&cfg(true), &[malformed]));
    }
}
