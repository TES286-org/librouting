//! RFC 7911 Add-Path orchestration helpers.
//!
//! The wire-level pieces live elsewhere: capability encoding in
//! [`crate::capabilities`], NLRI framing in [`crate::codec`] and
//! [`crate::path::mp_nlri`]. This module computes what a session should
//! actually *do* after the OPEN exchange:
//!
//! - [`advertised_families`] — what our OPEN advertises (send + receive
//!   for every family the session speaks).
//! - [`negotiated_directions`] — the effective directions per family once
//!   the peer's AddPath capability is known.
//!
//! Direction semantics (RFC 7911 §4.4): a speaker's *Send* bit offers to
//! transmit multiple paths; its *Receive* bit offers to accept them. So
//! we transmit Add-Path to a peer when the peer offered to receive, and
//! we expect Add-Path from a peer when the peer offered to send.

use lr_core::nlri::NlriFamily;

use crate::peer::PeerConfig;

/// Families our OPEN advertises for Add-Path: IPv4 unicast (always spoken
/// when the FRR `bgp default ipv4-unicast` knob is on, W2.1) plus every
/// configured MP-BGP family, deduplicated. When `default_ipv4_unicast`
/// is `false` and `mp_families` does not explicitly list IPv4 unicast,
/// the capability lists only the MP families.
pub fn advertised_families(cfg: &PeerConfig) -> Vec<NlriFamily> {
    if !cfg.add_path {
        return Vec::new();
    }
    let mut families = if cfg.default_ipv4_unicast {
        vec![NlriFamily::IPV4_UNICAST]
    } else {
        Vec::new()
    };
    for f in &cfg.mp_families {
        if !families.contains(f) {
            families.push(*f);
        }
    }
    families
}

/// Effective Add-Path directions after negotiation. Returns the families
/// for which this speaker may transmit (peer advertised Receive) and
/// receive (peer advertised Send) multiple paths.
///
/// Both sides must have advertised the capability for the family — ours
/// via [`advertised_families`], the peer's via its OPEN — otherwise the
/// family stays single-path (RFC 7911 §4.4: "if a speaker does not
/// advertise the AddPath capability, it must not receive multiple paths").
pub fn negotiated_directions(
    cfg: &PeerConfig,
    peer_caps: &[(u16, u8, bool, bool)],
) -> (Vec<NlriFamily>, Vec<NlriFamily>) {
    let mut tx = Vec::new();
    let mut rx = Vec::new();
    if !cfg.add_path {
        return (tx, rx);
    }
    let ours = advertised_families(cfg);
    for (afi, safi, peer_send, peer_recv) in peer_caps {
        let family = NlriFamily {
            afi: *afi,
            safi: *safi,
        };
        if !ours.contains(&family) {
            continue;
        }
        // The peer is willing to receive → we may transmit.
        if *peer_recv && !tx.contains(&family) {
            tx.push(family);
        }
        // The peer is willing to send → we may receive.
        if *peer_send && !rx.contains(&family) {
            rx.push(family);
        }
    }
    (tx, rx)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::peer::PeerConfig;
    use lr_core::addr::{Asn, RouterId};

    fn cfg(add_path: bool) -> PeerConfig {
        let mut c = PeerConfig::new(Asn(64512), Asn(64513), RouterId::from_v4([10, 0, 0, 1]));
        c.add_path = add_path;
        c.mp_families = vec![NlriFamily::IPV4_UNICAST, NlriFamily::IPV6_UNICAST];
        c
    }

    #[test]
    fn no_capability_when_disabled() {
        assert!(advertised_families(&cfg(false)).is_empty());
        let (tx, rx) = negotiated_directions(&cfg(false), &[(1, 1, true, true)]);
        assert!(tx.is_empty() && rx.is_empty());
    }

    #[test]
    fn advertises_send_and_receive_per_family() {
        let families = advertised_families(&cfg(true));
        assert_eq!(families.len(), 2);
    }

    /// Both directions require both sides to offer them (RFC 7911 §4.4):
    /// peer receive bit enables our transmit, peer send bit our receive.
    #[test]
    fn negotiation_requires_both_sides() {
        // Peer offers both directions for v4, only send for v6.
        let (tx, rx) =
            negotiated_directions(&cfg(true), &[(1, 1, true, true), (2, 1, true, false)]);
        assert!(tx.contains(&NlriFamily::IPV4_UNICAST));
        assert!(rx.contains(&NlriFamily::IPV4_UNICAST));
        assert!(!tx.contains(&NlriFamily::IPV6_UNICAST));
        assert!(rx.contains(&NlriFamily::IPV6_UNICAST));
    }

    /// A family the peer enables but we did not configure stays off.
    #[test]
    fn unconfigured_family_stays_off() {
        let (tx, rx) = negotiated_directions(&cfg(true), &[(1, 128, true, true)]);
        assert!(tx.is_empty() && rx.is_empty());
    }
}
