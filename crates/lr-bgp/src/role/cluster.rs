//! Route Reflector cluster identification (RFC 4456 §9 + §10).
//!
//! A route reflector is identified by a 4-byte cluster identifier. When the
//! local speaker acts as a route reflector, it:
//!
//! 1. Inserts its own [`RouterId`] as [`path::well_known`] ORIGINATOR_ID when
//!    advertising a route to an RR-client (only if ORIGINATOR_ID is absent).
//! 2. Prepends its [`ClusterId`] to the CLUSTER_LIST when reflecting a route.
//! 3. Discards routes whose CLUSTER_LIST contains its own cluster id
//!    (loop detection).
//!
//! These rules together let iBGP topology grow beyond a full mesh without
//! losing loop-freedom (the cluster list tracks the reflection path).

use lr_core::addr::RouterId;

/// 4-byte cluster identifier. Defaults to the local BGP identifier when
/// not explicitly configured.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Default)]
pub struct ClusterId(pub u32);

impl ClusterId {
    pub const fn from_u32(v: u32) -> Self {
        Self(v)
    }
    pub fn from_v4(b: [u8; 4]) -> Self {
        Self(u32::from_be_bytes(b))
    }
    pub fn to_v4_bytes(self) -> [u8; 4] {
        self.0.to_be_bytes()
    }
}

impl core::fmt::Display for ClusterId {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let b = self.to_v4_bytes();
        write!(f, "{}.{}.{}.{}", b[0], b[1], b[2], b[3])
    }
}

impl core::fmt::Debug for ClusterId {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        core::fmt::Display::fmt(self, f)
    }
}

impl core::str::FromStr for ClusterId {
    type Err = lr_core::addr::ParseAddrError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let b: [u8; 4] = s
            .parse::<lr_core::addr::IpAddr>()
            .ok()
            .and_then(|a| match a {
                lr_core::addr::IpAddr::V4(b) => Some(b),
                _ => None,
            })
            .ok_or(lr_core::addr::ParseAddrError)?;
        Ok(Self::from_v4(b))
    }
}

/// Route Reflector configuration for one speaker.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RouteReflectorConfig {
    /// Local cluster id. Defaults to the local BGP identifier when left at 0.
    pub cluster_id: ClusterId,
    /// Whether this speaker is itself a route reflector.
    pub enabled: bool,
}

impl RouteReflectorConfig {
    /// Effective cluster id: configured value, falling back to `bgp_id`.
    pub fn effective_cluster_id(&self, bgp_id: RouterId) -> ClusterId {
        if self.cluster_id.0 != 0 {
            self.cluster_id
        } else {
            ClusterId(bgp_id.0)
        }
    }
}

/// Compute the new ORIGINATOR_ID to insert when reflecting `route` to an
/// RR-client. Returns the ORIGINATOR_ID to insert, if any.
///
/// Per RFC 4456 §9, ORIGINATOR_ID is the BGP identifier of the route
/// reflector that originated the route into the cluster. If the route already
/// has an ORIGINATOR_ID, it is preserved.
pub fn compute_originator_id(
    existing_originator_id: Option<RouterId>,
    local_bgp_id: RouterId,
) -> Option<RouterId> {
    existing_originator_id.or(Some(local_bgp_id))
}

/// Compute the new CLUSTER_LIST to prepend when reflecting `route` to an
/// RR-client. Returns the new cluster list (with local cluster id prepended).
///
/// Per RFC 4456 §10, CLUSTER_LIST is a sequence of cluster ids representing
/// the reflection path. The reflector prepends its own cluster id when
/// reflecting.
pub fn prepend_cluster_id(
    mut existing_cluster_list: Vec<ClusterId>,
    local_cluster: ClusterId,
) -> Vec<ClusterId> {
    // Avoid duplicates: if local cluster already present, this is a loop.
    // Caller is responsible for loop-check via `cluster_list_has_loop` before
    // invoking this function.
    existing_cluster_list.insert(0, local_cluster);
    existing_cluster_list
}

/// True if `cluster_list` contains `local_cluster` (RFC 4456 loop check).
pub fn cluster_list_has_loop(cluster_list: &[ClusterId], local_cluster: ClusterId) -> bool {
    cluster_list.contains(&local_cluster)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cluster_id_parse() {
        let c: ClusterId = "10.0.0.1".parse().unwrap();
        assert_eq!(c.0, 0x0a000001);
        assert_eq!(c.to_string(), "10.0.0.1");
    }

    #[test]
    fn prepend_creates_or_appends() {
        let local = ClusterId(0x0a000001);
        // Empty list -> insert.
        let out = prepend_cluster_id(Vec::new(), local);
        assert_eq!(out, vec![local]);
        // Non-empty -> prepend.
        let out = prepend_cluster_id(vec![ClusterId(0x0a000002)], local);
        assert_eq!(out, vec![local, ClusterId(0x0a000002)]);
    }

    #[test]
    fn loop_detection() {
        let local = ClusterId(0x0a000001);
        assert!(cluster_list_has_loop(&[local], local));
        assert!(!cluster_list_has_loop(&[ClusterId(0x0a000002)], local));
    }

    #[test]
    fn originator_id_falls_back_to_local() {
        let local = RouterId::from_v4([10, 0, 0, 1]);
        // No existing ORIGINATOR_ID -> use local.
        assert_eq!(compute_originator_id(None, local), Some(local));
        // Existing preserved.
        let other = RouterId::from_v4([10, 0, 0, 2]);
        assert_eq!(compute_originator_id(Some(other), local), Some(other));
    }
}
