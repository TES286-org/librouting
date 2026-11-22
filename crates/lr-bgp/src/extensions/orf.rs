//! RFC 5291 Outbound Route Filtering (ORF) capability orchestration
//! helper.
//!
//! The wire-level capability lives in
//! [`crate::capabilities::Capability::orf`] (code 3). The module
//! computes what a session should advertise and what the daemon
//! may consume after the OPEN exchange:
//!
//! - [`advertised_entries`] — the `(afi, safi, [(orf_type, mode)])`
//!   triples to put in the OPEN, filtered to families this session
//!   speaks.
//! - [`peer_offered`] — whether the peer advertised the ORF
//!   capability.
//! - [`peer_entries`] — the peer's advertised ORF entries, decoded
//!   from its OPEN.
//! - [`negotiated_entries`] — the effective per-family mode after
//!   bilateral negotiation: a family appears in the result when
//!   both speakers advertised it, with the modes the peer offered.
//!
//! # Negotiation posture
//!
//! RFC 5291 §3: the capability advertises, per address family, the
//! ORF types the speaker is willing to *send* or *receive* (mode 1
//! = RECEIVE — willing to receive ORF entries from peer; 2 = SEND
//! — wants to send; 3 = BOTH). The bilateral agreement: a speaker
//! may *send* ORF entries to a peer for a family when the peer
//! advertised RECEIVE or BOTH for that family; a speaker may
//! *receive* ORF entries when the peer advertised SEND or BOTH.
//!
//! The wire encoding of ORF entries inside ROUTE_REFRESH messages
//! is handled by `lr-bgp::message::route_refresh`. This module is
//! the OPEN-time negotiation surface.

use crate::capabilities::{Capability, CapabilityCode};
use crate::capabilities_extra::OrfEntry;
use crate::peer::PeerConfig;
use lr_core::nlri::NlriFamily;

/// The ORF entries the OPEN should advertise. Filtered to the
/// families this session speaks — advertising ORF for an unspoken
/// family would mislead the peer. Returns an empty vector when
/// ORF is not configured or no entries survive the filter.
pub fn advertised_entries(cfg: &PeerConfig) -> Vec<OrfEntry> {
    if cfg.orf.is_empty() {
        return Vec::new();
    }
    let spoken: Vec<NlriFamily> = cfg
        .mp_families
        .iter()
        .copied()
        .chain(cfg.default_ipv4_unicast.then_some(NlriFamily::IPV4_UNICAST))
        .collect();
    cfg.orf
        .iter()
        .filter(|(afi, safi, _)| {
            spoken.contains(&NlriFamily {
                afi: *afi,
                safi: *safi,
            })
        })
        .cloned()
        .collect()
}

/// Whether the peer advertised the ORF capability in its OPEN.
pub fn peer_offered(peer_caps: &[Capability]) -> bool {
    peer_caps.iter().any(|c| c.code == CapabilityCode::Orf)
}

/// The peer's advertised ORF entries, decoded from its OPEN
/// capability. Returns `None` when the peer did not advertise the
/// capability or its value is malformed (a num_types field that
/// runs past the entry's bytes, or a trailing partial entry).
pub fn peer_entries(peer_caps: &[Capability]) -> Option<Vec<OrfEntry>> {
    peer_caps
        .iter()
        .find(|c| c.code == CapabilityCode::Orf)
        .and_then(Capability::as_orf)
}

/// The effective per-family ORF modes after bilateral negotiation.
/// A family appears when both speakers advertised it; the modes
/// are the peer's (the daemon consults this to decide whether to
/// send ORF entries to the peer for the family — SEND or BOTH —
/// and whether to honour ORF entries from the peer — RECEIVE or
/// BOTH).
pub fn negotiated_entries(cfg: &PeerConfig, peer_caps: &[Capability]) -> Vec<OrfEntry> {
    let ours = advertised_entries(cfg);
    let Some(peers) = peer_entries(peer_caps) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (afi, safi, types) in peers {
        let family = NlriFamily { afi, safi };
        if !ours
            .iter()
            .any(|(a, s, _)| NlriFamily { afi: *a, safi: *s } == family)
        {
            continue;
        }
        if !out.iter().any(|(a, s, _)| *a == afi && *s == safi) {
            out.push((afi, safi, types));
        }
    }
    out
}

/// Build the ORF capability for a configured peer's OPEN. Returns
/// `None` when the local config has no entries set or no entries
/// survive the spoken-families filter.
pub fn open_capability(cfg: &PeerConfig) -> Option<Capability> {
    let entries = advertised_entries(cfg);
    if entries.is_empty() {
        return None;
    }
    Some(Capability::orf(&entries))
}

/// RFC 5291 §5 Send/Receive values.
pub const ORF_MODE_RECEIVE: u8 = 1;
pub const ORF_MODE_SEND: u8 = 2;
pub const ORF_MODE_BOTH: u8 = 3;

/// The mode this speaker advertised for one `<AFI/SAFI, ORF-Type>`.
/// The first configured tuple for the family wins (matching
/// [`Capability::as_orf`]'s decoder). `None` when the session did not
/// advertise the family at all.
pub fn advertised_mode(cfg: &PeerConfig, family: NlriFamily, orf_type: u8) -> Option<u8> {
    advertised_entries(cfg)
        .into_iter()
        .find(|(afi, safi, _)| {
            NlriFamily {
                afi: *afi,
                safi: *safi,
            } == family
        })
        .and_then(|(_, _, types)| {
            types
                .into_iter()
                .find(|(t, _)| *t == orf_type)
                .map(|(_, mode)| mode)
        })
}

/// The mode the peer advertised for one `<AFI/SAFI, ORF-Type>`, decoded
/// from its OPEN capability. The first tuple wins.
pub fn peer_mode(peer_caps: &[Capability], family: NlriFamily, orf_type: u8) -> Option<u8> {
    peer_entries(peer_caps)?
        .into_iter()
        .find(|(afi, safi, _)| {
            NlriFamily {
                afi: *afi,
                safi: *safi,
            } == family
        })
        .and_then(|(_, _, types)| {
            types
                .into_iter()
                .find(|(t, _)| *t == orf_type)
                .map(|(_, mode)| mode)
        })
}

/// Whether an ORF entry of this type may be received from the peer
/// (RFC 5291 §6): we advertised RECEIVE or BOTH and the peer
/// advertised SEND or BOTH.
pub fn accepts_from_peer(
    cfg: &PeerConfig,
    peer_caps: &[Capability],
    family: NlriFamily,
    orf_type: u8,
) -> bool {
    let ours = advertised_mode(cfg, family, orf_type).unwrap_or(0);
    let theirs = peer_mode(peer_caps, family, orf_type).unwrap_or(0);
    matches!(ours, ORF_MODE_RECEIVE | ORF_MODE_BOTH)
        && matches!(theirs, ORF_MODE_SEND | ORF_MODE_BOTH)
}

/// Whether we may send an ORF entry of this type to the peer
/// (RFC 5291 §6): we advertised SEND or BOTH and the peer advertised
/// RECEIVE or BOTH.
pub fn may_send_to_peer(
    cfg: &PeerConfig,
    peer_caps: &[Capability],
    family: NlriFamily,
    orf_type: u8,
) -> bool {
    let ours = advertised_mode(cfg, family, orf_type).unwrap_or(0);
    let theirs = peer_mode(peer_caps, family, orf_type).unwrap_or(0);
    matches!(ours, ORF_MODE_SEND | ORF_MODE_BOTH)
        && matches!(theirs, ORF_MODE_RECEIVE | ORF_MODE_BOTH)
}

/// Whether both speakers advertised the ORF capability at all. RFC 5291
/// §6 makes ROUTE-REFRESH a precondition, so the FSM checks this before
/// surfacing ORF entries.
pub fn negotiated(cfg: &PeerConfig, peer_caps: &[Capability]) -> bool {
    !advertised_entries(cfg).is_empty() && peer_offered(peer_caps)
}

/// Filter an inbound ORF payload to the lists this speaker is allowed
/// to receive (RFC 5291 §6: entries whose `<AFI/SAFI, ORF-Type>` does
/// not match what we advertised as willing to receive are ignored).
pub fn filter_received(
    cfg: &PeerConfig,
    peer_caps: &[Capability],
    family: NlriFamily,
    orf: &crate::message::OrfRefresh,
) -> Vec<crate::message::OrfList> {
    orf.lists
        .iter()
        .filter(|list| accepts_from_peer(cfg, peer_caps, family, list.orf_type))
        .cloned()
        .collect()
}

/// Whether the peer advertised a willingness to send ORF entries for
/// this family *and* this speaker advertised a willingness to receive
/// at least one of the peer's ORF types. RFC 5291 §6 then says the
/// speaker SHOULD NOT advertise that family until it receives the ORF
/// (or a plain ROUTE-REFRESH) for it.
pub fn peer_will_send_any(cfg: &PeerConfig, peer_caps: &[Capability], family: NlriFamily) -> bool {
    let Some(peers) = peer_entries(peer_caps) else {
        return false;
    };
    let Some((_, _, types)) = peers.iter().find(|(afi, safi, _)| {
        NlriFamily {
            afi: *afi,
            safi: *safi,
        } == family
    }) else {
        return false;
    };
    types
        .iter()
        .any(|(orf_type, _)| accepts_from_peer(cfg, peer_caps, family, *orf_type))
}

/// Filter an outbound ORF payload to the lists the peer is allowed to
/// receive (RFC 5291 §6). Returns `None` when no list survives, so the
/// caller does not put an empty ORF message on the wire.
pub fn filter_outgoing(
    cfg: &PeerConfig,
    peer_caps: &[Capability],
    family: NlriFamily,
    lists: &[crate::message::OrfList],
) -> Option<Vec<crate::message::OrfList>> {
    let kept: Vec<crate::message::OrfList> = lists
        .iter()
        .filter(|list| may_send_to_peer(cfg, peer_caps, family, list.orf_type))
        .cloned()
        .collect();
    (!kept.is_empty()).then_some(kept)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::peer::PeerConfig;
    use lr_core::addr::{Asn, RouterId};
    use lr_core::nlri::NlriFamily;

    fn cfg(orf: &[OrfEntry]) -> PeerConfig {
        let mut c = PeerConfig::new(Asn(64512), Asn(64513), RouterId::from_v4([10, 0, 0, 1]));
        c.default_ipv4_unicast = true;
        c.orf = orf.to_vec();
        c
    }

    #[test]
    fn advertised_entries_empty_when_not_configured() {
        assert!(advertised_entries(&cfg(&[])).is_empty());
        assert!(open_capability(&cfg(&[])).is_none());
    }

    /// IPv4 unicast is spoken by default; ORF for it survives.
    #[test]
    fn advertised_entries_keeps_ipv4_unicast() {
        let c = cfg(&[(1, 1, vec![(64, 3)])]);
        let adv = advertised_entries(&c);
        assert_eq!(adv.len(), 1);
        let cap = open_capability(&c).unwrap();
        assert_eq!(cap.code, CapabilityCode::Orf);
        assert_eq!(cap.as_orf(), Some(vec![(1, 1, vec![(64, 3)])]));
    }

    /// A family the session does not speak is filtered out.
    #[test]
    fn advertised_entries_filters_unspoken_families() {
        let c = cfg(&[(1, 1, vec![(64, 3)]), (2, 1, vec![(64, 3)])]);
        let adv = advertised_entries(&c);
        assert_eq!(adv.len(), 1);
        assert_eq!(adv[0].0, 1); // IPv4 only — IPv6 was filtered.
    }

    /// IPv6 ORF survives when the session speaks IPv6.
    #[test]
    fn advertised_entries_keeps_v6_when_configured() {
        let mut c = cfg(&[(1, 1, vec![(64, 3)]), (2, 1, vec![(64, 3)])]);
        c.mp_families = vec![NlriFamily::IPV6_UNICAST];
        let adv = advertised_entries(&c);
        assert_eq!(adv.len(), 2);
    }

    #[test]
    fn peer_offered_when_capability_present() {
        let cap = Capability::orf(&[(1, 1, vec![(64, 3)])]);
        assert!(peer_offered(&[cap]));
    }

    #[test]
    fn peer_not_offered_when_capability_absent() {
        assert!(!peer_offered(&[]));
    }

    /// A family only the peer advertised is not negotiated.
    #[test]
    fn negotiated_entries_drops_peer_only_families() {
        let c = cfg(&[(1, 1, vec![(64, 3)])]);
        let peer_cap = Capability::orf(&[(1, 1, vec![(64, 3)]), (2, 1, vec![(64, 3)])]);
        let n = negotiated_entries(&c, &[peer_cap]);
        assert_eq!(n.len(), 1);
        assert_eq!(n[0].0, 1); // IPv4 only — IPv6 was peer-only.
    }

    /// When the peer did not advertise ORF, no entries are
    /// negotiated even if the local config has them.
    #[test]
    fn negotiated_entries_empty_when_peer_did_not_advertise() {
        let c = cfg(&[(1, 1, vec![(64, 3)])]);
        assert!(negotiated_entries(&c, &[]).is_empty());
    }

    #[test]
    fn modes_use_the_first_tuple_per_family() {
        let c = cfg(&[(1, 1, vec![(64, ORF_MODE_SEND), (64, ORF_MODE_BOTH)])]);
        assert_eq!(
            advertised_mode(&c, NlriFamily::IPV4_UNICAST, 64),
            Some(ORF_MODE_SEND)
        );
        let peer = Capability::orf(&[(1, 1, vec![(64, ORF_MODE_RECEIVE)])]);
        assert_eq!(
            peer_mode(&[peer], NlriFamily::IPV4_UNICAST, 64),
            Some(ORF_MODE_RECEIVE)
        );
    }

    #[test]
    fn receive_requires_local_receive_and_peer_send() {
        let local = cfg(&[(1, 1, vec![(64, ORF_MODE_RECEIVE)])]);
        let peer_send = Capability::orf(&[(1, 1, vec![(64, ORF_MODE_SEND)])]);
        let peer_receive = Capability::orf(&[(1, 1, vec![(64, ORF_MODE_RECEIVE)])]);
        assert!(accepts_from_peer(
            &local,
            std::slice::from_ref(&peer_send),
            NlriFamily::IPV4_UNICAST,
            64
        ));
        assert!(!accepts_from_peer(
            &local,
            &[peer_receive],
            NlriFamily::IPV4_UNICAST,
            64
        ));
        // A local SEND-only configuration cannot receive.
        let local_send = cfg(&[(1, 1, vec![(64, ORF_MODE_SEND)])]);
        assert!(!accepts_from_peer(
            &local_send,
            &[peer_send],
            NlriFamily::IPV4_UNICAST,
            64
        ));
    }

    #[test]
    fn send_requires_local_send_and_peer_receive() {
        let local = cfg(&[(1, 1, vec![(64, ORF_MODE_SEND)])]);
        let peer_receive = Capability::orf(&[(1, 1, vec![(64, ORF_MODE_RECEIVE)])]);
        let peer_send = Capability::orf(&[(1, 1, vec![(64, ORF_MODE_SEND)])]);
        assert!(may_send_to_peer(
            &local,
            &[peer_receive],
            NlriFamily::IPV4_UNICAST,
            64
        ));
        assert!(!may_send_to_peer(
            &local,
            &[peer_send],
            NlriFamily::IPV4_UNICAST,
            64
        ));
    }

    #[test]
    fn peer_will_send_only_for_a_type_we_accept() {
        let local = cfg(&[(1, 1, vec![(64, ORF_MODE_RECEIVE)])]);
        let peer = Capability::orf(&[(1, 1, vec![(64, ORF_MODE_SEND)])]);
        assert!(peer_will_send_any(
            &local,
            &[peer],
            NlriFamily::IPV4_UNICAST
        ));
        let peer_other_type = Capability::orf(&[(1, 1, vec![(65, ORF_MODE_SEND)])]);
        assert!(!peer_will_send_any(
            &local,
            &[peer_other_type],
            NlriFamily::IPV4_UNICAST
        ));
    }

    #[test]
    fn filter_received_drops_disallowed_types() {
        use crate::message::{OrfEntry, OrfList, OrfRefresh, OrfWhenToRefresh};
        let local = cfg(&[(1, 1, vec![(64, ORF_MODE_RECEIVE)])]);
        let peer = Capability::orf(&[(1, 1, vec![(64, ORF_MODE_SEND), (65, ORF_MODE_SEND)])]);
        let refresh = OrfRefresh {
            when: OrfWhenToRefresh::Immediate,
            lists: vec![
                OrfList {
                    orf_type: 64,
                    entries: vec![OrfEntry::RemoveAll],
                },
                OrfList {
                    orf_type: 65,
                    entries: vec![OrfEntry::Raw(vec![0])],
                },
            ],
        };
        let kept = filter_received(&local, &[peer], NlriFamily::IPV4_UNICAST, &refresh);
        assert_eq!(kept.len(), 1);
        assert_eq!(kept[0].orf_type, 64);
    }
}
