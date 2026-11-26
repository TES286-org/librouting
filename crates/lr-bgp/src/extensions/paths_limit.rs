//! PATHS-LIMIT capability
//! (draft-ietf-idr-addpath-paths-limit-00) orchestration
//! helper.
//!
//! The wire-level capability lives in
//! [`crate::capabilities::Capability::paths_limit`] (code 76). The
//! draft scopes the capability to AddPath-negotiated families — a
//! peer that ships PATHS-LIMIT without AddPath is ignored. This
//! module computes what a session should advertise and what each
//! direction may consume after the OPEN exchange:
//!
//! - [`advertised_families`] — the `(afi, safi, limit)` triples to
//!   put in the OPEN, filtered to the AddPath families this
//!   session speaks.
//! - [`peer_limits`] / [`peer_limit`] — the receive limits the peer
//!   advertised, restricted to AddPath-negotiated families. The
//!   sender caps egress at the peer's limit.
//! - [`local_limit`] — the locally configured receive limit for one
//!   family, which the router enforces on ingress.
//!
//! # Negotiation posture
//!
//! The draft's mandatory gating: PATHS-LIMIT is ignored when
//! AddPath is not negotiated for the family. The helpers take the
//! negotiated family list (or gate on the caller's per-family
//! AddPath direction) so the limit applies only where AddPath is
//! active. A limit of `0` is the draft's "ignore this tuple"
//! sentinel, and the first tuple for an AFI/SAFI wins (§3).
//!
//! The capability is asymmetric: the value a speaker advertises is
//! the number of paths it is willing to *receive*. The peer's value
//! therefore caps our egress, and our own value caps our ingress.
//! The two directions must never be merged.

use crate::capabilities::{Capability, CapabilityCode};
use crate::peer::PeerConfig;
use lr_core::nlri::NlriFamily;

/// The `(afi, safi, limit)` triples the OPEN should advertise.
/// Filtered to the families this session speaks for AddPath (the
/// draft's gating: PATHS-LIMIT is meaningful only for AddPath
/// families). A configured limit of `0` is dropped — the draft's
/// "ignore this family" sentinel — and a repeated AFI/SAFI keeps
/// only its first tuple (§3).
pub fn advertised_families(cfg: &PeerConfig) -> Vec<(u16, u8, u16)> {
    if cfg.paths_limit.is_empty() || !cfg.add_path {
        return Vec::new();
    }
    let spoken: Vec<NlriFamily> = crate::extensions::addpath::advertised_families(cfg);
    let mut out = Vec::new();
    let mut seen: Vec<(u16, u8)> = Vec::new();
    for (afi, safi, limit) in &cfg.paths_limit {
        // §3: the first tuple for an AFI/SAFI wins; later duplicates
        // are ignored even when the first one is the zero sentinel.
        if seen.contains(&(*afi, *safi)) {
            continue;
        }
        seen.push((*afi, *safi));
        if *limit == 0 {
            continue;
        }
        let family = NlriFamily {
            afi: *afi,
            safi: *safi,
        };
        if !spoken.contains(&family) {
            continue;
        }
        out.push((*afi, *safi, *limit));
    }
    out
}

/// Whether the peer advertised the PATHS-LIMIT capability in its
/// OPEN.
pub fn peer_offered(peer_caps: &[Capability]) -> bool {
    peer_caps
        .iter()
        .any(|c| c.code == CapabilityCode::PathsLimit)
}

/// The peer's advertised receive limit for `family`, or `None` when
/// the peer did not advertise a non-zero limit for it.
///
/// Only the first tuple for the AFI/SAFI counts; later duplicates
/// are ignored (draft-ietf-idr-addpath-paths-limit-00 §3). A
/// malformed capability value yields `None`, so the sender falls
/// back to its local egress cap instead of guessing.
pub fn peer_limit(peer_caps: &[Capability], family: NlriFamily) -> Option<u16> {
    let cap = peer_caps
        .iter()
        .find(|c| c.code == CapabilityCode::PathsLimit)?;
    let tuples = cap.as_paths_limit()?;
    let (_, _, limit) = tuples
        .into_iter()
        .find(|(afi, safi, _)| *afi == family.afi && *safi == family.safi)?;
    (limit != 0).then_some(limit)
}

/// The peer's advertised receive limits, filtered to
/// `add_path_families` (the draft's mandatory gating) and with the
/// first tuple per AFI/SAFI winning. Zero limits are dropped. The
/// daemon's AddPath egress path uses this to cap the number of
/// paths it sends per prefix.
pub fn peer_limits(
    peer_caps: &[Capability],
    add_path_families: &[NlriFamily],
) -> Vec<(u16, u8, u16)> {
    let Some(cap) = peer_caps
        .iter()
        .find(|c| c.code == CapabilityCode::PathsLimit)
    else {
        return Vec::new();
    };
    let Some(tuples) = cap.as_paths_limit() else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (afi, safi, limit) in tuples {
        if limit == 0 {
            continue;
        }
        let family = NlriFamily { afi, safi };
        if !add_path_families.contains(&family) {
            continue;
        }
        if out.iter().any(|(a, s, _)| *a == afi && *s == safi) {
            continue;
        }
        out.push((afi, safi, limit));
    }
    out
}

/// The locally configured receive limit for `family`, or `None` when
/// unset or zero. The first tuple for the AFI/SAFI wins (§3).
pub fn local_limit(cfg: &PeerConfig, family: NlriFamily) -> Option<u16> {
    cfg.paths_limit
        .iter()
        .find(|(afi, safi, _)| *afi == family.afi && *safi == family.safi)
        .map(|(_, _, limit)| *limit)
        .filter(|limit| *limit != 0)
}

/// Build the PATHS-LIMIT capability for a configured peer's OPEN.
/// Returns `None` when the local config has no limits set or when
/// AddPath is not enabled (the draft's gating).
pub fn open_capability(cfg: &PeerConfig) -> Option<Capability> {
    let families = advertised_families(cfg);
    if families.is_empty() {
        return None;
    }
    Some(Capability::paths_limit(&families))
}

/// The NOTIFICATION Data field for the "Maximum Number of Paths
/// Reached" Cease (§4 Figure 2): `AFI` (2 octets), `SAFI` (1 octet)
/// and the advertised `Paths Limit` (2 octets) that was exceeded. The
/// sender includes the tuple for any one of the families that tripped
/// — the caller passes the family of the path that crossed the limit.
pub fn cease_data(family: NlriFamily, limit: u16) -> Vec<u8> {
    let mut data = Vec::with_capacity(5);
    data.extend_from_slice(&family.afi.to_be_bytes());
    data.push(family.safi);
    data.extend_from_slice(&limit.to_be_bytes());
    data
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::peer::PeerConfig;
    use lr_core::addr::{Asn, RouterId};
    use lr_core::nlri::NlriFamily;

    fn cfg_with_paths_limit(add_path: bool, limits: &[(u16, u8, u16)]) -> PeerConfig {
        let mut c = PeerConfig::new(Asn(64512), Asn(64513), RouterId::from_v4([10, 0, 0, 1]));
        c.add_path = add_path;
        c.default_ipv4_unicast = true;
        c.paths_limit = limits.to_vec();
        c
    }

    #[test]
    fn advertised_families_empty_when_add_path_off() {
        let c = cfg_with_paths_limit(false, &[(1, 1, 16)]);
        assert!(advertised_families(&c).is_empty());
        assert!(open_capability(&c).is_none());
    }

    #[test]
    fn advertised_families_filtered_to_spoken() {
        // IPv4 unicast is spoken by default; IPv6 unicast is not
        // configured.
        let c = cfg_with_paths_limit(true, &[(1, 1, 16), (2, 1, 32)]);
        let adv = advertised_families(&c);
        assert_eq!(adv, vec![(1, 1, 16)]);
    }

    #[test]
    fn advertised_families_includes_v6_when_configured() {
        let mut c = cfg_with_paths_limit(true, &[(1, 1, 16), (2, 1, 32)]);
        c.mp_families = vec![NlriFamily::IPV6_UNICAST];
        let adv = advertised_families(&c);
        assert_eq!(adv, vec![(1, 1, 16), (2, 1, 32)]);
    }

    /// A limit of 0 is the draft's "ignore this tuple" sentinel; the
    /// first tuple wins, so a later duplicate does not resurrect it.
    #[test]
    fn advertised_families_drops_zero_limits() {
        let c = cfg_with_paths_limit(true, &[(1, 1, 0), (1, 1, 16)]);
        assert!(advertised_families(&c).is_empty());
        let c = cfg_with_paths_limit(true, &[(1, 1, 16), (1, 1, 0)]);
        assert_eq!(advertised_families(&c), vec![(1, 1, 16)]);
    }

    /// §3: only the first tuple for an AFI/SAFI is considered.
    #[test]
    fn advertised_families_keeps_first_tuple_per_family() {
        let c = cfg_with_paths_limit(true, &[(1, 1, 16), (1, 1, 32)]);
        assert_eq!(advertised_families(&c), vec![(1, 1, 16)]);
    }

    #[test]
    fn open_capability_off_when_no_limits() {
        let c = cfg_with_paths_limit(true, &[]);
        assert!(open_capability(&c).is_none());
    }

    #[test]
    fn open_capability_on_when_limits_set() {
        let c = cfg_with_paths_limit(true, &[(1, 1, 16)]);
        let cap = open_capability(&c).unwrap();
        assert_eq!(cap.code, CapabilityCode::PathsLimit);
        assert_eq!(cap.as_paths_limit(), Some(vec![(1, 1, 16)]));
    }

    #[test]
    fn peer_offered_when_capability_present() {
        let cap = Capability::paths_limit(&[(1, 1, 16)]);
        assert!(peer_offered(&[cap]));
    }

    #[test]
    fn peer_not_offered_when_capability_absent() {
        assert!(!peer_offered(&[]));
    }

    #[test]
    fn peer_limit_returns_the_advertised_value() {
        let cap = Capability::paths_limit(&[(1, 1, 32)]);
        assert_eq!(peer_limit(&[cap], NlriFamily::IPV4_UNICAST), Some(32));
    }

    /// §3: a repeated AFI/SAFI uses the first tuple only.
    #[test]
    fn peer_limit_keeps_first_tuple_per_family() {
        let cap = Capability::paths_limit(&[(1, 1, 32), (1, 1, 64)]);
        assert_eq!(peer_limit(&[cap], NlriFamily::IPV4_UNICAST), Some(32));
    }

    #[test]
    fn peer_limit_ignores_zero_and_unknown_families() {
        let cap = Capability::paths_limit(&[(1, 1, 0), (2, 1, 64)]);
        assert_eq!(
            peer_limit(std::slice::from_ref(&cap), NlriFamily::IPV4_UNICAST),
            None
        );
        assert_eq!(peer_limit(&[cap], NlriFamily::IPV6_UNICAST), Some(64));
    }

    #[test]
    fn peer_limit_none_when_capability_malformed() {
        let cap = Capability::new(CapabilityCode::PathsLimit, vec![0, 1, 1, 0]);
        assert_eq!(peer_limit(&[cap], NlriFamily::IPV4_UNICAST), None);
    }

    /// The draft's mandatory gating: PATHS-LIMIT is meaningful only
    /// for AddPath-negotiated families. A peer limit for a family
    /// not in the AddPath set is dropped.
    #[test]
    fn peer_limits_gated_by_add_path() {
        let peer_cap = Capability::paths_limit(&[(1, 1, 32), (2, 1, 64)]);
        let add_path = vec![NlriFamily::IPV4_UNICAST];
        let limits = peer_limits(&[peer_cap], &add_path);
        assert_eq!(limits, vec![(1, 1, 32)]);
    }

    /// A peer limit of 0 is the draft's "ignore this tuple"
    /// sentinel — dropped before returning.
    #[test]
    fn peer_limits_drops_zero_peer_limits() {
        let peer_cap = Capability::paths_limit(&[(1, 1, 0)]);
        let add_path = vec![NlriFamily::IPV4_UNICAST];
        assert!(peer_limits(&[peer_cap], &add_path).is_empty());
    }

    #[test]
    fn peer_limits_keeps_first_tuple_per_family() {
        let peer_cap = Capability::paths_limit(&[(1, 1, 32), (1, 1, 64)]);
        let add_path = vec![NlriFamily::IPV4_UNICAST];
        assert_eq!(peer_limits(&[peer_cap], &add_path), vec![(1, 1, 32)]);
    }

    #[test]
    fn local_limit_reads_the_configured_value() {
        let c = cfg_with_paths_limit(true, &[(1, 1, 16)]);
        assert_eq!(local_limit(&c, NlriFamily::IPV4_UNICAST), Some(16));
        assert_eq!(local_limit(&c, NlriFamily::IPV6_UNICAST), None);
    }

    #[test]
    fn local_limit_ignores_zero_and_keeps_first_tuple() {
        let c = cfg_with_paths_limit(true, &[(1, 1, 0), (1, 1, 16), (1, 1, 32)]);
        assert_eq!(local_limit(&c, NlriFamily::IPV4_UNICAST), None);
        let c = cfg_with_paths_limit(true, &[(1, 1, 16), (1, 1, 32)]);
        assert_eq!(local_limit(&c, NlriFamily::IPV4_UNICAST), Some(16));
    }

    /// §4 Figure 2: the Data field is AFI (2) + SAFI (1) + the
    /// advertised Paths Limit (2), network byte order.
    #[test]
    fn cease_data_is_the_figure_2_layout() {
        assert_eq!(
            cease_data(NlriFamily::IPV4_UNICAST, 16),
            vec![0x00, 0x01, 0x01, 0x00, 0x10]
        );
        assert_eq!(
            cease_data(NlriFamily::IPV6_UNICAST, 4095),
            vec![0x00, 0x02, 0x01, 0x0f, 0xff]
        );
    }
}
