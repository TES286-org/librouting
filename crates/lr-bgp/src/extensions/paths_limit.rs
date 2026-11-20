//! PATHS-LIMIT capability
//! (draft-abraitis-idr-addpath-paths-limit-00) orchestration
//! helper.
//!
//! The wire-level capability lives in
//! [`crate::capabilities::Capability::paths_limit`] (code 76). The
//! draft scopes the capability to AddPath-negotiated families — a
//! peer that ships PATHS-LIMIT without AddPath is ignored. This
//! module computes what a session should advertise and what the
//! daemon may consume after the OPEN exchange:
//!
//! - [`advertised_families`] — the `(afi, safi, limit)` triples to
//!   put in the OPEN, filtered to the AddPath families this
//!   session speaks.
//! - [`negotiated_limits`] — the per-family limits the peer
//!   advertised, restricted to AddPath-negotiated families. The
//!   daemon's AddPath egress path uses this to cap the number of
//!   paths it sends per prefix (the draft's receiver-driven limit).
//!
//! # Negotiation posture
//!
//! The draft's mandatory gating: PATHS-LIMIT is ignored when
//! AddPath is not negotiated for the family. [`negotiated_limits`]
//! takes the AddPath-negotiated family list as an argument so the
//! daemon can apply the limit only where AddPath is active. A
//! limit of `0` is the draft's "ignore this family" sentinel — the
//! helper drops those entries before returning.

use crate::capabilities::{Capability, CapabilityCode};
use crate::peer::PeerConfig;
use lr_core::nlri::NlriFamily;

/// The `(afi, safi, limit)` triples the OPEN should advertise.
/// Filtered to the families this session speaks for AddPath (the
/// draft's gating: PATHS-LIMIT is meaningful only for AddPath
/// families). A configured limit of `0` is dropped — the draft's
/// "ignore this family" sentinel.
pub fn advertised_families(cfg: &PeerConfig) -> Vec<(u16, u8, u16)> {
    if cfg.paths_limit.is_empty() || !cfg.add_path {
        return Vec::new();
    }
    let spoken: Vec<NlriFamily> = crate::extensions::addpath::advertised_families(cfg);
    cfg.paths_limit
        .iter()
        .filter(|(afi, safi, limit)| {
            *limit != 0
                && spoken.contains(&NlriFamily {
                    afi: *afi,
                    safi: *safi,
                })
        })
        .copied()
        .collect()
}

/// Whether the peer advertised the PATHS-LIMIT capability in its
/// OPEN.
pub fn peer_offered(peer_caps: &[Capability]) -> bool {
    peer_caps
        .iter()
        .any(|c| c.code == CapabilityCode::PathsLimit)
}

/// The peer's advertised per-family limits, filtered to the
/// AddPath-negotiated family list (the draft's mandatory gating).
/// Entries with a limit of `0` are dropped (the draft's "ignore"
/// sentinel). The daemon's AddPath egress path uses this to cap
/// the number of paths it sends per prefix.
pub fn negotiated_limits(
    cfg: &PeerConfig,
    peer_caps: &[Capability],
    add_path_families: &[NlriFamily],
) -> Vec<(u16, u8, u16)> {
    let Some(peer_limits) = peer_caps
        .iter()
        .find(|c| c.code == CapabilityCode::PathsLimit)
        .and_then(Capability::as_paths_limit)
    else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (afi, safi, limit) in peer_limits {
        if limit == 0 {
            continue;
        }
        let family = NlriFamily { afi, safi };
        if !add_path_families.contains(&family) {
            continue;
        }
        if !out.contains(&(afi, safi, limit)) {
            out.push((afi, safi, limit));
        }
    }
    // The local config's limits also matter: the daemon caps
    // egress at `min(local, peer)` — the draft's bilateral
    // agreement. Surface the local limit alongside the peer's so
    // the daemon's egress path can take the min.
    let local = advertised_families(cfg);
    for (afi, safi, limit) in local {
        if !out.contains(&(afi, safi, limit)) {
            out.push((afi, safi, limit));
        }
    }
    out
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

    /// A limit of 0 is the draft's "ignore this family" sentinel.
    #[test]
    fn advertised_families_drops_zero_limits() {
        let c = cfg_with_paths_limit(true, &[(1, 1, 0), (1, 1, 16)]);
        let adv = advertised_families(&c);
        assert_eq!(adv, vec![(1, 1, 16)]);
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

    /// The draft's mandatory gating: PATHS-LIMIT is meaningful only
    /// for AddPath-negotiated families. A peer limit for a family
    /// not in the AddPath set is dropped.
    #[test]
    fn negotiated_limits_gated_by_add_path() {
        let c = cfg_with_paths_limit(true, &[(1, 1, 16)]);
        let peer_cap = Capability::paths_limit(&[(1, 1, 32), (2, 1, 64)]);
        let add_path = vec![NlriFamily::IPV4_UNICAST];
        let limits = negotiated_limits(&c, &[peer_cap], &add_path);
        // IPv4 survives (AddPath-negotiated); IPv6 is dropped.
        assert!(limits.contains(&(1, 1, 32)));
        assert!(!limits.iter().any(|&(a, s, _)| a == 2 && s == 1));
    }

    /// A peer limit of 0 is the draft's "ignore this family"
    /// sentinel — dropped before returning.
    #[test]
    fn negotiated_limits_drops_zero_peer_limits() {
        let c = cfg_with_paths_limit(true, &[(1, 1, 16)]);
        let peer_cap = Capability::paths_limit(&[(1, 1, 0)]);
        let add_path = vec![NlriFamily::IPV4_UNICAST];
        let limits = negotiated_limits(&c, &[peer_cap], &add_path);
        assert!(!limits.iter().any(|&(_, _, l)| l == 0));
    }
}
