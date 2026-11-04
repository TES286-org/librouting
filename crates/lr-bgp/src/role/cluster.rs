//! Route Reflector cluster identification (RFC 4456 §8 + §10).
//!
//! A route reflector is identified by a 4-byte cluster identifier. When the
//! local speaker acts as a route reflector, it:
//!
//! 1. Stamps the ORIGINATOR_ID attribute (RFC 4456 §8) when reflecting a
//!    route to an RR-client — *only if* the attribute is not already present
//!    (the RFC says a speaker SHOULD NOT create one when one exists). The
//!    value is the BGP Identifier of the originator of the route in the
//!    local AS — i.e. the source router that originated the route into
//!    iBGP, NOT the route reflector's own identifier. For a locally
//!    originated route the originator is the local speaker, so its own
//!    BGP Identifier is the correct value; for a route learned from an
//!    iBGP peer the originator is that peer.
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

/// Compute the ORIGINATOR_ID to stamp when reflecting a route to an
/// RR-client (RFC 4456 §8).
///
/// `existing_originator_id` is the ORIGINATOR_ID already on the route
/// (preserved verbatim when present — RFC 4456 §8: "A BGP speaker SHOULD
/// NOT create an ORIGINATOR_ID attribute if one already exists").
///
/// `local_bgp_id` is the BGP Identifier to stamp when no existing
/// ORIGINATOR_ID is present. Despite the historical name (preserved for
/// API stability), per RFC 4456 §8 the ORIGINATOR_ID carries "the BGP
/// Identifier of the originator of the route in the local AS" — i.e.
/// the source router that originated the route into iBGP, *not* the
/// route reflector's own identifier. Callers should therefore supply
/// the source peer's BGP Identifier for an iBGP-learned route, or the
/// local speaker's BGP Identifier for a locally originated route (in
/// which case the local speaker is itself the originator and the
/// historical "local_bgp_id" name is accurate).
///
/// Returns the `RouterId` to stamp, or `None` when an existing
/// ORIGINATOR_ID is to be preserved (the caller is responsible for
/// not overwriting in that case — typically by checking
/// `PathAttributes::get(AttrType::OriginatorId).is_none()` first).
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
    fn originator_id_falls_back_to_supplied_value() {
        // The supplied BGP Identifier is what gets stamped when no
        // existing ORIGINATOR_ID is on the route — the caller is
        // responsible for passing the originator's BGP Identifier
        // (the source peer's for iBGP-learned routes, the local
        // speaker's for locally-originated routes).
        let supplied = RouterId::from_v4([10, 0, 0, 1]);
        assert_eq!(compute_originator_id(None, supplied), Some(supplied));
        // Existing ORIGINATOR_ID is preserved (RFC 4456 §8).
        let existing = RouterId::from_v4([10, 0, 0, 2]);
        assert_eq!(compute_originator_id(Some(existing), supplied), Some(existing));
    }
}
