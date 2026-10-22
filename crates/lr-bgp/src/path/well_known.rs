//! Well-known path attributes: ORIGIN, NEXT_HOP, MULTI_EXIT_DISC,
//! LOCAL_PREF, ATOMIC_AGGREGATE, AGGREGATOR, ORIGINATOR_ID, CLUSTER_LIST.

use lr_core::addr::{Asn, IpAddr, RouterId};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum OriginKind {
    Igp = 0,
    Egp = 1,
    Incomplete = 2,
}

impl OriginKind {
    pub fn from_u8(v: u8) -> Option<Self> {
        Some(match v {
            0 => Self::Igp,
            1 => Self::Egp,
            2 => Self::Incomplete,
            _ => return None,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Origin(pub OriginKind);

impl Origin {
    pub fn new(k: OriginKind) -> Self {
        Self(k)
    }

    pub fn decode(b: &[u8]) -> Option<Self> {
        if b.len() != 1 {
            return None;
        }
        Some(Self(OriginKind::from_u8(b[0])?))
    }

    pub fn encode(&self) -> [u8; 1] {
        [self.0 as u8]
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NextHopKind {
    V4([u8; 4]),
    V6([u8; 16]),
    V4OverV6([u8; 16]),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct NextHop(pub NextHopKind);

impl NextHop {
    pub fn from_v4(b: [u8; 4]) -> Self {
        Self(NextHopKind::V4(b))
    }

    pub fn from_v6(b: [u8; 16]) -> Self {
        Self(NextHopKind::V6(b))
    }

    pub fn from_v4_over_v6(b: [u8; 16]) -> Self {
        Self(NextHopKind::V4OverV6(b))
    }

    pub fn to_ip(&self) -> IpAddr {
        match &self.0 {
            NextHopKind::V4(b) => IpAddr::V4(*b),
            NextHopKind::V6(b) | NextHopKind::V4OverV6(b) => IpAddr::V6(*b),
        }
    }

    /// Decode a well-known NEXT_HOP attribute (RFC 4271 §5.1.3).
    ///
    /// Wire widths:
    /// - 4 bytes: IPv4 next-hop (the historical default for IPv4 NLRI).
    /// - 16 bytes: IPv6 next-hop for IPv4 NLRI — only valid when RFC 5549
    ///   Extended Next-Hop was negotiated; decoded as `V4OverV6`. A 16-byte
    ///   NEXT_HOP for IPv6 NLRI never appears on the wire (IPv6 NLRI uses
    ///   MP_REACH_NLRI per RFC 4760), so we never return `V6` here.
    ///
    /// The 32-byte form is not a valid well-known NEXT_HOP encoding — the
    /// MP_REACH_NLRI `V6GlobalLinkLocal` (global + link-local) form lives
    /// behind the MP_REACH attribute, not NEXT_HOP.
    pub fn decode(b: &[u8]) -> Option<Self> {
        match b.len() {
            4 => {
                let mut a = [0u8; 4];
                a.copy_from_slice(b);
                Some(Self::from_v4(a))
            }
            16 => {
                // RFC 5549 §3: IPv6 next-hop for IPv4 NLRI.
                let mut a = [0u8; 16];
                a.copy_from_slice(b);
                Some(Self::from_v4_over_v6(a))
            }
            _ => None,
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        match &self.0 {
            NextHopKind::V4(b) => b.to_vec(),
            NextHopKind::V6(b) | NextHopKind::V4OverV6(b) => b.to_vec(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct Med(pub u32);

impl Med {
    pub fn decode(b: &[u8]) -> Option<Self> {
        if b.len() != 4 {
            return None;
        }
        Some(Self(u32::from_be_bytes([b[0], b[1], b[2], b[3]])))
    }
    pub fn encode(&self) -> [u8; 4] {
        self.0.to_be_bytes()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct LocalPref(pub u32);

impl LocalPref {
    pub fn decode(b: &[u8]) -> Option<Self> {
        if b.len() != 4 {
            return None;
        }
        Some(Self(u32::from_be_bytes([b[0], b[1], b[2], b[3]])))
    }
    pub fn encode(&self) -> [u8; 4] {
        self.0.to_be_bytes()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct AtomicAggregate;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Aggregator {
    pub asn: Asn,
    pub speaker: [u8; 4],
}

impl Aggregator {
    pub fn decode(b: &[u8]) -> Option<Self> {
        match b.len() {
            6 => Some(Self {
                asn: Asn(u16::from_be_bytes([b[0], b[1]]) as u32),
                speaker: [b[2], b[3], b[4], b[5]],
            }),
            8 => Some(Self {
                asn: Asn(u32::from_be_bytes([b[0], b[1], b[2], b[3]])),
                speaker: [b[4], b[5], b[6], b[7]],
            }),
            _ => None,
        }
    }

    pub fn encode_4(&self) -> [u8; 8] {
        let mut a = [0u8; 8];
        a[..4].copy_from_slice(&self.asn.0.to_be_bytes());
        a[4..].copy_from_slice(&self.speaker);
        a
    }
}

/// ORIGINATOR_ID path attribute (RFC 4456 §8).
///
/// A 4-byte BGP Identifier carried by a route-reflected route; the
/// originator is the BGP speaker that first injected the route into
/// the iBGP mesh. A receiver SHOULD ignore any UPDATE whose
/// ORIGINATOR_ID equals its own BGP Identifier (loop detection).
///
/// The attribute is optional non-transitive (flags `0x80`); a
/// route-reflector creates it only when it is absent, and never
/// overwrites an existing value (RFC 4456 §8 p3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct OriginatorId(pub RouterId);

impl OriginatorId {
    /// Construct from a 32-bit BGP Identifier.
    pub const fn from_u32(v: u32) -> Self {
        Self(RouterId::from_u32(v))
    }

    /// Construct from a BGP Identifier in dotted-quad form.
    pub const fn from_v4(b: [u8; 4]) -> Self {
        Self(RouterId::from_v4(b))
    }

    /// Decode the 4-byte wire form. Returns `None` for any other
    /// length — RFC 4456 §8 fixes ORIGINATOR_ID at exactly 4 bytes.
    pub fn decode(b: &[u8]) -> Option<Self> {
        if b.len() != 4 {
            return None;
        }
        Some(Self(RouterId::from_v4([b[0], b[1], b[2], b[3]])))
    }

    pub fn encode(&self) -> [u8; 4] {
        self.0.to_v4_bytes()
    }

    /// The BGP Identifier as an IPv4 `IpAddr` (the canonical filter
    /// representation; BIRD spells ORIGINATOR_ID as an `ip`).
    pub fn to_ip(self) -> IpAddr {
        IpAddr::V4(self.0.to_v4_bytes())
    }
}

/// CLUSTER_LIST path attribute (RFC 4456 §8).
///
/// A sequence of 4-byte CLUSTER_ID values tracing the reflection
/// path the route has taken. A route-reflector prepends its local
/// CLUSTER_ID on every reflection (creating the attribute when
/// absent), and a receiver SHOULD ignore any UPDATE whose
/// CLUSTER_LIST contains its own CLUSTER_ID (loop detection).
///
/// The attribute is optional non-transitive (flags `0x80`); the wire
/// form is a flat concatenation of 4-byte CLUSTER_IDs in reflection
/// order (most-recently-prepended first). An empty list and an
/// absent attribute both decode to `ClusterList::default()`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Default)]
pub struct ClusterList(pub Vec<RouterId>);

impl ClusterList {
    pub fn new() -> Self {
        Self::default()
    }

    /// Push a CLUSTER_ID at the front of the list (RFC 4456 §8
    /// "MUST prepend the local CLUSTER_ID").
    pub fn prepend(&mut self, id: RouterId) {
        self.0.insert(0, id);
    }

    /// True when `id` is anywhere in the list (RFC 4456 §8 loop check).
    pub fn contains(&self, id: RouterId) -> bool {
        self.0.contains(&id)
    }

    /// Decode the wire form. Returns `None` when the length is not
    /// a multiple of 4 (RFC 4456 §8 fixes CLUSTER_ID at 4 bytes).
    pub fn decode(b: &[u8]) -> Option<Self> {
        if !b.len().is_multiple_of(4) {
            return None;
        }
        let mut v = Vec::with_capacity(b.len() / 4);
        for chunk in b.as_chunks::<4>().0 {
            v.push(RouterId::from_v4(*chunk));
        }
        Some(Self(v))
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.0.len() * 4);
        for id in &self.0 {
            out.extend_from_slice(&id.to_v4_bytes());
        }
        out
    }

    /// Iterator over the CLUSTER_IDs as IPv4 `IpAddr`s (the canonical
    /// filter representation; BIRD spells CLUSTER_LIST as a `clist`
    /// of IPv4-typed entries).
    pub fn iter_ips(&self) -> impl Iterator<Item = IpAddr> + '_ {
        self.0.iter().map(|id| IpAddr::V4(id.to_v4_bytes()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn originator_id_roundtrips() {
        let id = OriginatorId::from_v4([10, 0, 0, 1]);
        let wire = id.encode();
        assert_eq!(wire, [10, 0, 0, 1]);
        let back = OriginatorId::decode(&wire).expect("4-byte form decodes");
        assert_eq!(back, id);
        assert_eq!(back.0.as_u32(), 0x0a000001);
        // BIRD spells ORIGINATOR_ID as an IPv4 value in filters.
        assert_eq!(back.to_ip(), IpAddr::V4([10, 0, 0, 1]));
    }

    #[test]
    fn originator_id_rejects_wrong_widths() {
        // RFC 4456 §8 fixes ORIGINATOR_ID at 4 bytes; any other
        // width is malformed.
        assert!(OriginatorId::decode(&[]).is_none());
        assert!(OriginatorId::decode(&[1, 2, 3]).is_none());
        assert!(OriginatorId::decode(&[1, 2, 3, 4, 5]).is_none());
    }

    #[test]
    fn cluster_list_roundtrips_empty() {
        let list = ClusterList::new();
        assert!(list.0.is_empty());
        let wire = list.encode();
        assert!(wire.is_empty());
        let back = ClusterList::decode(&wire).expect("empty decodes");
        assert_eq!(back, list);
    }

    #[test]
    fn cluster_list_roundtrips_three_ids() {
        let mut list = ClusterList::new();
        // RFC 4456 §8: prepend on every reflection, so the most
        // recent cluster ends up first.
        list.prepend(RouterId::from_v4([10, 0, 3, 1]));
        list.prepend(RouterId::from_v4([10, 0, 2, 1]));
        list.prepend(RouterId::from_v4([10, 0, 1, 1]));
        let wire = list.encode();
        assert_eq!(wire.len(), 12);
        let back = ClusterList::decode(&wire).expect("12-byte form decodes");
        assert_eq!(back, list);
        // Loop-detection helper.
        assert!(list.contains(RouterId::from_v4([10, 0, 2, 1])));
        assert!(!list.contains(RouterId::from_v4([192, 0, 2, 1])));
    }

    #[test]
    fn cluster_list_rejects_partial_tail() {
        // RFC 4456 §8 fixes CLUSTER_ID at 4 bytes; a 5-byte body
        // is malformed.
        assert!(ClusterList::decode(&[1, 2, 3, 4, 5]).is_none());
        // A multiple of 4 always decodes (including zero).
        assert!(ClusterList::decode(&[]).is_some());
        assert!(ClusterList::decode(&[1, 2, 3, 4]).is_some());
    }

    #[test]
    fn cluster_list_iter_ips_yields_v4() {
        let mut list = ClusterList::new();
        list.prepend(RouterId::from_v4([10, 0, 0, 1]));
        list.prepend(RouterId::from_v4([10, 0, 0, 2]));
        let ips: Vec<IpAddr> = list.iter_ips().collect();
        assert_eq!(
            ips,
            vec![IpAddr::V4([10, 0, 0, 2]), IpAddr::V4([10, 0, 0, 1])]
        );
    }

    // CONTRIBUTING.md: a new wire codec needs a fuzz target or a
    // proptest strategy. The bgp_decode fuzz target feeds arbitrary
    // bytes to the BGP message codec (which stores raw attribute
    // bytes in PathAttribute::value), but the typed accessors that
    // call OriginatorId::decode / ClusterList::decode are not in its
    // path. The proptest strategy below fills that gap: it generates
    // arbitrary byte slices, runs them through the strict-width
    // decoders, and asserts the round-trip contract holds for any
    // input the decoder accepts.

    proptest! {
        #[test]
        fn originator_id_decode_never_panics(
            bytes in prop::collection::vec(0u8..=255, 0..=64)
        ) {
            // The decoder must either return Some (4-byte input) or
            // None (any other width) — never panic.
            let decoded = OriginatorId::decode(&bytes);
            if let Some(id) = decoded {
                // Round-trip contract: encode is the inverse of decode
                // for every accepted input.
                prop_assert_eq!(id.encode(), bytes.as_slice());
                // The 4-byte input invariant.
                prop_assert_eq!(bytes.len(), 4);
            } else {
                // Rejected inputs include every non-4-byte width.
                prop_assert_ne!(bytes.len(), 4);
            }
        }

        #[test]
        fn cluster_list_decode_never_panics(
            bytes in prop::collection::vec(0u8..=255, 0..=128)
        ) {
            let decoded = ClusterList::decode(&bytes);
            if let Some(list) = decoded {
                // Round-trip contract: encode is the inverse of decode
                // for every accepted input.
                prop_assert_eq!(list.encode(), bytes.as_slice());
                // The multiple-of-4 invariant.
                prop_assert_eq!(bytes.len() % 4, 0);
                // iter_ips yields exactly len/4 addresses, all V4.
                let ips: Vec<IpAddr> = list.iter_ips().collect();
                prop_assert_eq!(ips.len(), bytes.len() / 4);
                for ip in ips {
                    prop_assert!(matches!(ip, IpAddr::V4(_)));
                }
            } else {
                // Rejected inputs include every non-multiple-of-4 width.
                prop_assert_ne!(bytes.len() % 4, 0);
            }
        }
    }
}
