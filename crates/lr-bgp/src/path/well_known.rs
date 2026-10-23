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

/// AIGP path attribute (RFC 7311).
///
/// The Accumulated IGP Metric attribute carries a single
/// administrative domain's end-to-end IGP distance so BGP can
/// select paths by metric across contiguous ASes under one
/// administration. The attribute is optional non-transitive
/// (flags `0x80`); its value field is a TLV stream (RFC 7311 §3):
///
/// - Type 1 — AIGP: an 8-byte big-endian unsigned integer, the
///   accumulated metric.
/// - Other types: preserved verbatim by the codec (RFC 7311 §3 p5:
///   "an AIGP TLV that is not understood MUST be preserved") so the
///   attribute round-trips byte-for-byte.
///
/// The typed view surfaces the *accumulated metric* — the sum of
/// every type-1 TLV's 8-byte value. RFC 7311 §3.4.3 ("Modifications
/// by a Non-Originator") specifies a single type-1 TLV whose value
/// is updated in place; summing is the defensive choice for the
/// "multiple type-1 TLVs" case a malformed peer might emit and
/// matches the attribute's "accumulated" semantics.
///
/// The codec stores the raw attribute bytes verbatim in
/// [`crate::path::PathAttribute::value`]; this type is the typed
/// view the filter DSL's `bgp.aigp` field reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, PartialOrd, Ord)]
pub struct Aigp(pub u64);

/// AIGP TLV type codes (RFC 7311 §3, IANA "BGP AIGP TLV Types"
/// registry).
pub const AIGP_TLV_AIGP: u16 = 1;

impl Aigp {
    /// Construct from an accumulated metric value.
    pub const fn from_metric(m: u64) -> Self {
        Self(m)
    }

    /// The accumulated IGP metric.
    pub const fn metric(self) -> u64 {
        self.0
    }

    /// Decode the AIGP attribute's value field (a TLV stream) and
    /// return the accumulated metric — the sum of every type-1
    /// (AIGP) TLV's 8-byte big-endian value. Returns `None` when the
    /// TLV stream is malformed (a TLV length runs past the end of
    /// the attribute, or a type-1 TLV's value is not exactly 8
    /// bytes). Unknown TLV types are skipped, preserving forward
    /// compatibility (RFC 7311 §3 p5).
    ///
    /// An empty value field decodes to `Aigp(0)` — RFC 7311 does not
    /// forbid an empty AIGP attribute, and a non-originator that
    /// receives one cannot add to a metric that does not exist, so
    /// the attribute is treated as "present, metric zero" rather
    /// than malformed. Callers that need to distinguish "absent"
    /// from "present but zero" consult [`PathAttributes::has_aigp`].
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        let mut acc: u64 = 0;
        let mut i = 0;
        while i < bytes.len() {
            // TLV header: 2-byte type + 2-byte length (RFC 7311 §3).
            if i + 4 > bytes.len() {
                return None;
            }
            let tlv_type = u16::from_be_bytes([bytes[i], bytes[i + 1]]);
            let tlv_len = u16::from_be_bytes([bytes[i + 2], bytes[i + 3]]) as usize;
            // The length field includes the 4-byte header (RFC 7311
            // §3: "the Length field ... includes the Type and Length
            // fields").
            if tlv_len < 4 {
                return None;
            }
            let value_len = tlv_len - 4;
            let value_start = i + 4;
            let value_end = value_start + value_len;
            if value_end > bytes.len() {
                return None;
            }
            if tlv_type == AIGP_TLV_AIGP {
                // RFC 7311 §3: the type-1 TLV value is an 8-byte
                // unsigned integer. A type-1 TLV with any other
                // value width is malformed.
                if value_len != 8 {
                    return None;
                }
                let mut v = [0u8; 8];
                v.copy_from_slice(&bytes[value_start..value_end]);
                acc = acc.wrapping_add(u64::from_be_bytes(v));
            }
            // Unknown TLV types are skipped (preserved by the codec).
            i = value_end;
        }
        Some(Self(acc))
    }

    /// Encode a single type-1 AIGP TLV carrying `self.0` as the
    /// accumulated metric. Originators emit exactly one type-1 TLV
    /// (RFC 7311 §3.4.1); non-originators modify the existing
    /// TLV's value in place (§3.4.3) rather than appending.
    pub fn encode(self) -> Vec<u8> {
        let mut out = Vec::with_capacity(12);
        out.extend_from_slice(&AIGP_TLV_AIGP.to_be_bytes()); // type
        out.extend_from_slice(&12u16.to_be_bytes()); // length: 4 (header) + 8 (value)
        out.extend_from_slice(&self.0.to_be_bytes());
        out
    }
}

/// PMSI Tunnel attribute (RFC 6514 §5).
///
/// The P-Multicast Service Interface Tunnel attribute carries the
/// provider-tunnel binding a BGP UPDATE advertises for an MVPN
/// auto-discovery route (Intra-AS I-PMSI, Inter-As I-PMSI, S-PMSI,
/// Leaf A-D). The attribute is optional transitive (flags `0xC0`);
/// its value field is a fixed 5-byte header followed by a
/// variable-length Tunnel Identifier whose syntax depends on the
/// Tunnel Type:
///
/// ```text
/// +---------------------------------+
/// |  Flags (1 octet)                |
/// +---------------------------------+
/// |  Tunnel Type (1 octet)         |
/// +---------------------------------+
/// |  MPLS Label (3 octets)          |
/// +---------------------------------+
/// |  Tunnel Identifier (variable)   |
/// +---------------------------------+
/// ```
///
/// The Flags byte defines one bit (RFC 6514 §5): bit 0 = Leaf
/// Information Required (`L`). Bits 7..1 are reserved and MUST be
/// zero on originate. The Tunnel Type field selects the
/// provider-tunnel technology; the codec preserves every Tunnel
/// Type value (the BIRD filter surfaces the attribute as a presence
/// probe, not a structured value, so an unknown Tunnel Type still
/// round-trips byte-for-byte). The MPLS Label is the RFC 3032 §2.1
/// 3-octet label encoding — the high-order 20 bits are the label
/// value, the low 3 bits are the EXP, the low 1 bit is the
/// End-of-Stack flag; the codec surfaces the 20-bit label value
/// and re-emits the full 3-byte wire form on encode (an all-zero
/// field means "no MPLS label").
///
/// `PathAttribute::value` stores the raw attribute bytes verbatim,
/// so any well-formed attribute round-trips byte-for-byte —
/// including attributes whose Tunnel Type the codec does not
/// interpret and attributes whose Flags violate the "MUST be zero
/// on originate" constraint. This type is the typed view the filter
/// DSL's `bgp.pmsi_tunnel` field reads.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Default)]
pub struct PmsiTunnel {
    /// The attribute's Flags byte (RFC 6514 §5). Only bit 0 (L =
    /// Leaf Information Required) is defined; the codec preserves
    /// every bit so a Flags value that violates the "MUST be zero
    /// on originate" constraint still round-trips byte-for-byte.
    /// [`Self::leaf_info_required`] is the named accessor for the L
    /// bit.
    pub flags: u8,
    /// The Tunnel Type byte (RFC 6514 §5). The named values live
    /// in the [`TUNNEL_TYPE_*`](self#constants) constants.
    pub tunnel_type: u8,
    /// The 20-bit MPLS label value extracted from the high-order
    /// bits of the 3-octet MPLS Label field. An all-zero field
    /// decodes to `0` ("no MPLS label" per RFC 6514 §5).
    pub mpls_label: u32,
    /// The variable-length Tunnel Identifier (RFC 6514 §5). Its
    /// syntax depends on `tunnel_type`; the codec preserves the
    /// bytes verbatim.
    pub tunnel_id: Vec<u8>,
}

/// Flags bit 0 of the PMSI Tunnel attribute (RFC 6514 §5).
pub const PMSI_FLAG_LEAF_INFO_REQUIRED: u8 = 0b0000_0001;

/// RFC 6514 §5 — Tunnel Type "No tunnel information present".
pub const TUNNEL_TYPE_NO_INFO: u8 = 0;
/// RFC 6514 §5 — Tunnel Type "RSVP-TE P2MP LSP".
pub const TUNNEL_TYPE_RSVP_TE_P2MP: u8 = 1;
/// RFC 6514 §5 — Tunnel Type "mLDP P2MP LSP".
pub const TUNNEL_TYPE_MLDP_P2MP: u8 = 2;
/// RFC 6514 §5 — Tunnel Type "PIM-SSM Tree".
pub const TUNNEL_TYPE_PIM_SSM: u8 = 3;
/// RFC 6514 §5 — Tunnel Type "PIM-SM Tree".
pub const TUNNEL_TYPE_PIM_SM: u8 = 4;
/// RFC 6514 §5 — Tunnel Type "BIDIR-PIM Tree".
pub const TUNNEL_TYPE_BIDIR_PIM: u8 = 5;
/// RFC 6514 §5 — Tunnel Type "Ingress Replication".
pub const TUNNEL_TYPE_INGRESS_REPLICATION: u8 = 6;
/// RFC 6514 §5 — Tunnel Type "mLDP MP2MP LSP".
pub const TUNNEL_TYPE_MLDP_MP2MP: u8 = 7;

impl PmsiTunnel {
    /// Construct a new PMSI Tunnel attribute from its typed fields.
    /// The MPLS label is masked to its low 20 bits and shifted into
    /// the high-order 20 bits of the 3-byte wire field on encode;
    /// the EXP and End-of-Stack bits are zeroed on encode.
    pub const fn new(flags: u8, tunnel_type: u8, mpls_label: u32, tunnel_id: Vec<u8>) -> Self {
        Self {
            flags,
            tunnel_type,
            mpls_label,
            tunnel_id,
        }
    }

    /// True when the Leaf Information Required (L) flag is set
    /// (RFC 6514 §5). A receiver that sees this flag set on an
    /// Inter-As I-PMSI A-D route or an S-PMSI A-D route originates
    /// a Leaf A-D route in response.
    pub const fn leaf_info_required(&self) -> bool {
        (self.flags & PMSI_FLAG_LEAF_INFO_REQUIRED) != 0
    }

    /// Decode the PMSI Tunnel attribute's value field (RFC 6514
    /// §5). Returns `None` when the value is shorter than the
    /// 5-byte header (Flags + Tunnel Type + MPLS Label), or when
    /// the Tunnel Identifier length is inconsistent with the Tunnel
    /// Type's hard rule — Tunnel Type 0 ("No tunnel information
    /// present") MUST carry no Tunnel Identifier, and Tunnel Type
    /// 6 ("Ingress Replication") MUST carry a 4-byte (IPv4) or
    /// 16-byte (IPv6) endpoint address. Every other Tunnel Type
    /// (including unknown types) decodes with the Tunnel Identifier
    /// preserved verbatim, so the attribute round-trips
    /// byte-for-byte (mirrors BIRD's `bgp_decode_pmsi_tunnel`
    /// default arm, which sets the Partial bit but does not
    /// withdraw).
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < 5 {
            return None;
        }
        let flags = bytes[0];
        let tunnel_type = bytes[1];
        // RFC 3032 §2.1: 3-byte label field = 20-bit label +
        // 3-bit EXP + 1-bit S. The high-order 20 bits are the
        // label value; the low 4 bits are encoding overhead the
        // codec surfaces only through the encoded wire form on
        // encode (BIRD's `bgp_pmsi_get_label` makes the same
        // `>> 4` cut).
        let mpls_label = (u32::from_be_bytes([0, bytes[2], bytes[3], bytes[4]])) >> 4;
        let tunnel_id = bytes[5..].to_vec();
        match tunnel_type {
            TUNNEL_TYPE_NO_INFO if !tunnel_id.is_empty() => return None,
            TUNNEL_TYPE_INGRESS_REPLICATION if tunnel_id.len() != 4 && tunnel_id.len() != 16 => {
                return None;
            }
            _ => {}
        }
        Some(Self {
            flags,
            tunnel_type,
            mpls_label,
            tunnel_id,
        })
    }

    /// Encode the typed view back into the wire form. The Flags
    /// byte, Tunnel Type, Tunnel Identifier and the high-order 20
    /// bits of the MPLS Label round-trip byte-for-byte with the
    /// decode contract; the low 4 bits of the MPLS Label field
    /// (EXP + End-of-Stack) are zeroed on encode, matching how
    /// BIRD constructs a fresh attribute (`bgp_pmsi_new_ingress_replication`
    /// writes the label through `put_u24` after the same `<< 4`
    /// shift). The codec preserves the raw bytes verbatim at the
    /// `PathAttribute::value` level so a PMSI Tunnel attribute a
    /// peer sent with non-zero EXP/S bits round-trips byte-exact
    /// through the codec — this encoder is for originating a fresh
    /// attribute, not for round-tripping a received one.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(5 + self.tunnel_id.len());
        out.push(self.flags);
        out.push(self.tunnel_type);
        let label24 = (self.mpls_label & 0x000f_ffff) << 4;
        out.extend_from_slice(&label24.to_be_bytes()[1..4]);
        out.extend_from_slice(&self.tunnel_id);
        out
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

        #[test]
        fn aigp_decode_never_panics(
            bytes in prop::collection::vec(0u8..=255, 0..=256)
        ) {
            // The decoder must return Some or None — never panic —
            // for any byte slice. A None means the TLV stream was
            // malformed (a length runs past the end, or a type-1 TLV
            // value is not 8 bytes).
            let decoded = Aigp::decode(&bytes);
            if let Some(aigp) = decoded {
                // The accumulated metric is a u64 — every accepted
                // input decodes to a finite value.
                let _ = aigp.metric();
            }
        }
    }

    // ---- RFC 7311: AIGP ----

    #[test]
    fn aigp_roundtrips_single_type1_tlv() {
        let a = Aigp::from_metric(0x0123_4567_89ab_cdef);
        let wire = a.encode();
        // type(2) + length(2) + value(8) = 12 bytes
        assert_eq!(wire.len(), 12);
        assert_eq!(&wire[0..2], &1u16.to_be_bytes()); // type 1
        assert_eq!(&wire[2..4], &12u16.to_be_bytes()); // length 12
        let back = Aigp::decode(&wire).expect("single type-1 TLV decodes");
        assert_eq!(back, a);
        assert_eq!(back.metric(), 0x0123_4567_89ab_cdef);
    }

    #[test]
    fn aigp_roundtrips_zero_metric() {
        let a = Aigp::from_metric(0);
        let wire = a.encode();
        let back = Aigp::decode(&wire).expect("zero metric decodes");
        assert_eq!(back, a);
    }

    #[test]
    fn aigp_empty_value_decodes_as_zero() {
        // An empty AIGP attribute value field decodes to Aigp(0)
        // — RFC 7311 does not forbid an empty value, and a
        // non-originator cannot add to a metric that does not exist.
        let back = Aigp::decode(&[]).expect("empty value decodes");
        assert_eq!(back, Aigp::from_metric(0));
    }

    #[test]
    fn aigp_unknown_tlv_skipped_metric_preserved() {
        // RFC 7311 §3 p5: an unknown TLV MUST be preserved. The
        // typed view skips it; the codec preserves the raw bytes.
        // Build: [type-1 TLV metric=100] [unknown type-99 TLV].
        let mut wire = Aigp::from_metric(100).encode();
        // Append an unknown TLV: type=99, length=6 (header + 2 value bytes).
        wire.extend_from_slice(&99u16.to_be_bytes());
        wire.extend_from_slice(&6u16.to_be_bytes());
        wire.extend_from_slice(&[0xaa, 0xbb]);
        let back = Aigp::decode(&wire).expect("unknown TLV is skipped, not rejected");
        assert_eq!(back, Aigp::from_metric(100));
    }

    #[test]
    fn aigp_multiple_type1_tlvs_sum() {
        // RFC 7311 §3.4.3 specifies a single type-1 TLV updated in
        // place; the defensive choice for "multiple type-1 TLVs" is
        // to sum them (the attribute's "accumulated" semantics).
        let mut wire = Aigp::from_metric(100).encode();
        wire.extend_from_slice(&Aigp::from_metric(23).encode());
        let back = Aigp::decode(&wire).expect("multiple type-1 TLVs decode");
        assert_eq!(back, Aigp::from_metric(123));
    }

    #[test]
    fn aigp_rejects_truncated_tlv_header() {
        // 3 bytes — not enough for the 4-byte TLV header.
        assert!(Aigp::decode(&[0, 1, 2]).is_none());
    }

    #[test]
    fn aigp_rejects_length_overrun() {
        // TLV header claims length 20 but only 4 bytes follow.
        let mut wire = vec![0, 1, 0, 20];
        wire.extend_from_slice(&[0; 4]);
        assert!(Aigp::decode(&wire).is_none());
    }

    #[test]
    fn aigp_rejects_length_below_header() {
        // RFC 7311 §3: the length includes the 4-byte header, so a
        // length of 3 is malformed.
        assert!(Aigp::decode(&[0, 1, 0, 3]).is_none());
    }

    #[test]
    fn aigp_rejects_wrong_type1_value_width() {
        // Type-1 TLV with a 7-byte value (must be exactly 8).
        let mut wire = vec![0, 1, 0, 11]; // type 1, length 11 (4 header + 7 value)
        wire.extend_from_slice(&[0; 7]);
        assert!(Aigp::decode(&wire).is_none());
    }

    /// `PathAttributes::aigp` reads by tag through the typed
    /// accessor and stays `None` on the absent and malformed cases.
    /// Mirrors the `path_attributes_otc_accessor_round_trips` test
    /// in `role::otc` — the codec half of the `bgp.aigp` filter DSL
    /// field (RFC 7311).
    #[test]
    fn path_attributes_aigp_accessor_round_trips() {
        use crate::path::{AttrType, PathAttrFlags, PathAttribute, PathAttributes};

        let mut attrs = PathAttributes::new();
        // Absent — None on both `aigp()` and `has_aigp()`.
        assert!(attrs.aigp().is_none());
        assert!(!attrs.has_aigp());

        // Present, metric 64512.
        attrs.insert(PathAttribute::new(
            PathAttrFlags::new()
                .set_optional(true)
                .set_transitive(false),
            AttrType::Aigp,
            Aigp::from_metric(64512).encode(),
        ));
        let a = attrs.aigp().expect("present, well-formed");
        assert_eq!(a, Aigp::from_metric(64512));
        assert_eq!(a.metric(), 64512);
        assert!(attrs.has_aigp());

        // Present, metric 0 — "set but zero". `aigp()` returns
        // `Some(Aigp(0))`; `has_aigp()` reports presence. This is
        // the case `defined(bgp.aigp)` in the filter DSL must
        // distinguish from "absent".
        let mut attrs_zero = PathAttributes::new();
        attrs_zero.insert(PathAttribute::new(
            PathAttrFlags::new()
                .set_optional(true)
                .set_transitive(false),
            AttrType::Aigp,
            Aigp::from_metric(0).encode(),
        ));
        assert_eq!(attrs_zero.aigp(), Some(Aigp::from_metric(0)));
        assert!(attrs_zero.has_aigp());

        // Empty value field — decodes to `Aigp(0)` (RFC 7311 does
        // not forbid an empty value). `has_aigp()` reports presence;
        // `aigp()` reports `Some(Aigp(0))`.
        let mut attrs_empty = PathAttributes::new();
        attrs_empty.insert(PathAttribute::new(
            PathAttrFlags::new()
                .set_optional(true)
                .set_transitive(false),
            AttrType::Aigp,
            vec![],
        ));
        assert_eq!(attrs_empty.aigp(), Some(Aigp::from_metric(0)));
        assert!(attrs_empty.has_aigp());

        // Malformed TLV stream — None on `aigp()`, but `has_aigp()`
        // still reports presence (the attribute is on the route; only
        // the value is unreadable). Mirrors the `otc()` accessor's
        // behaviour on a malformed width.
        let mut attrs_bad = PathAttributes::new();
        attrs_bad.insert(PathAttribute::new(
            PathAttrFlags::new()
                .set_optional(true)
                .set_transitive(false),
            AttrType::Aigp,
            vec![0, 1, 2], // truncated TLV header
        ));
        assert!(attrs_bad.aigp().is_none());
        assert!(attrs_bad.has_aigp());
    }

    // ---- RFC 6514 §5: PMSI Tunnel attribute ----

    #[test]
    fn pmsi_tunnel_roundtrips_no_info() {
        // Tunnel Type 0 ("No tunnel information present") — the
        // attribute carries no Tunnel Identifier; the codec round-
        // trips the 5-byte header verbatim.
        let p = PmsiTunnel::new(0, TUNNEL_TYPE_NO_INFO, 0, Vec::new());
        let wire = p.encode();
        assert_eq!(wire, vec![0, 0, 0, 0, 0]);
        let back = PmsiTunnel::decode(&wire).expect("no-info decodes");
        assert_eq!(back, p);
    }

    #[test]
    fn pmsi_tunnel_roundtrips_ingress_replication_v4() {
        // Tunnel Type 6 (Ingress Replication), IPv4 endpoint,
        // MPLS label 64512, L bit set.
        let p = PmsiTunnel::new(
            PMSI_FLAG_LEAF_INFO_REQUIRED,
            TUNNEL_TYPE_INGRESS_REPLICATION,
            64512,
            vec![10, 0, 0, 1],
        );
        let wire = p.encode();
        // 5-byte header + 4-byte endpoint = 9 bytes.
        assert_eq!(wire.len(), 9);
        assert_eq!(wire[0], 0b0000_0001);
        assert_eq!(wire[1], 6);
        // The 24-bit label field carries the 20-bit label value
        // in its high-order 20 bits (RFC 3032 §2.1). 64512 =
        // 0x0FC00; <<4 = 0x0FC000 → bytes [0x0F, 0xC0, 0x00].
        assert_eq!(&wire[2..5], &[0x0F, 0xC0, 0x00]);
        let back = PmsiTunnel::decode(&wire).expect("ingress replication decodes");
        assert_eq!(back, p);
        assert!(back.leaf_info_required());
    }

    #[test]
    fn pmsi_tunnel_roundtrips_ingress_replication_v6() {
        // Tunnel Type 6 (Ingress Replication), IPv6 endpoint (16
        // bytes).
        let endpoint = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let p = PmsiTunnel::new(0, TUNNEL_TYPE_INGRESS_REPLICATION, 0, endpoint.to_vec());
        let wire = p.encode();
        let back = PmsiTunnel::decode(&wire).expect("v6 ingress replication decodes");
        assert_eq!(back, p);
        assert!(!back.leaf_info_required());
    }

    #[test]
    fn pmsi_tunnel_unknown_type_round_trips_verbatim() {
        // RFC 6514 §5: an undefined Tunnel Type is malformed in
        // the spec sense but BIRD's decoder accepts it and sets
        // the Partial bit. The lr codec preserves the bytes
        // verbatim so the attribute round-trips byte-for-byte —
        // the typed view does not interpret the Tunnel
        // Identifier. This is the byte-exact contract that
        // matches AIGP's "unknown TLV preserved" behaviour.
        let wire: Vec<u8> = vec![0, 200, 0, 0, 0, 0xaa, 0xbb, 0xcc];
        let p = PmsiTunnel::decode(&wire).expect("unknown Tunnel Type decodes");
        assert_eq!(p.tunnel_type, 200);
        assert_eq!(p.tunnel_id, vec![0xaa, 0xbb, 0xcc]);
        assert_eq!(p.encode(), wire);
    }

    #[test]
    fn pmsi_tunnel_preserves_label_low_bits_via_raw_bytes() {
        // The codec stores the raw attribute bytes verbatim at the
        // PathAttribute::value level so a PMSI Tunnel attribute a
        // peer sent with non-zero EXP/S bits round-trips
        // byte-exact. PmsiTunnel::encode re-emits the high-order
        // 20 bits of the label only (EXP/S zeroed); the codec's
        // verbatim value storage carries the rest.
        let mut wire = vec![0, TUNNEL_TYPE_NO_INFO];
        // 3-byte label field with the low 4 bits (EXP+S) set.
        wire.extend_from_slice(&[0x12, 0x34, 0x57]); // label 0x12345, EXP=0b101, S=1
        let p = PmsiTunnel::decode(&wire).expect("low-bit label decodes");
        // The high 20 bits are the label value (0x12345).
        assert_eq!(p.mpls_label, 0x12345);
        // Encode re-emits the 20-bit label only (low 4 bits zeroed).
        let re = p.encode();
        assert_eq!(&re[2..5], &[0x12, 0x34, 0x50]);
    }

    #[test]
    fn pmsi_tunnel_rejects_truncated_header() {
        // 4 bytes — the 5-byte minimum (Flags + Tunnel Type +
        // MPLS Label) is missing.
        assert!(PmsiTunnel::decode(&[0, 0, 0, 0]).is_none());
        assert!(PmsiTunnel::decode(&[]).is_none());
    }

    #[test]
    fn pmsi_tunnel_rejects_no_info_with_tunnel_id() {
        // Tunnel Type 0 MUST carry no Tunnel Identifier
        // (RFC 6514 §5).
        let mut wire = vec![0, TUNNEL_TYPE_NO_INFO, 0, 0, 0];
        wire.push(0xaa);
        assert!(PmsiTunnel::decode(&wire).is_none());
    }

    #[test]
    fn pmsi_tunnel_rejects_ingress_replication_wrong_endpoint_width() {
        // Tunnel Type 6 MUST carry a 4-byte (IPv4) or 16-byte
        // (IPv6) endpoint address (RFC 6514 §5). A 5-byte
        // endpoint is malformed.
        let mut wire = vec![0, TUNNEL_TYPE_INGRESS_REPLICATION, 0, 0, 0];
        wire.extend_from_slice(&[10, 0, 0, 1, 0]);
        assert!(PmsiTunnel::decode(&wire).is_none());
    }

    #[test]
    fn path_attributes_pmsi_tunnel_accessor_round_trips() {
        use crate::path::{AttrType, PathAttrFlags, PathAttribute, PathAttributes};

        let mut attrs = PathAttributes::new();
        // Absent — None on `pmsi_tunnel()`, false on
        // `has_pmsi_tunnel()`.
        assert!(attrs.pmsi_tunnel().is_none());
        assert!(!attrs.has_pmsi_tunnel());

        // Present, Tunnel Type 6 (Ingress Replication), IPv4
        // endpoint, MPLS label 64512, L bit set.
        let p = PmsiTunnel::new(
            PMSI_FLAG_LEAF_INFO_REQUIRED,
            TUNNEL_TYPE_INGRESS_REPLICATION,
            64512,
            vec![10, 0, 0, 1],
        );
        attrs.insert(PathAttribute::new(
            PathAttrFlags::new().set_optional(true).set_transitive(true),
            AttrType::PmsiTunnel,
            p.encode(),
        ));
        let back = attrs.pmsi_tunnel().expect("present, well-formed");
        assert_eq!(back, p);
        assert_eq!(back.tunnel_type, TUNNEL_TYPE_INGRESS_REPLICATION);
        assert_eq!(back.mpls_label, 64512);
        assert!(back.leaf_info_required());
        assert!(attrs.has_pmsi_tunnel());

        // Malformed value (truncated header) — None on
        // `pmsi_tunnel()`, but `has_pmsi_tunnel()` still reports
        // presence (the attribute is on the route; only the value
        // is unreadable). Mirrors the AIGP accessor's behaviour
        // on a malformed TLV stream.
        let mut attrs_bad = PathAttributes::new();
        attrs_bad.insert(PathAttribute::new(
            PathAttrFlags::new().set_optional(true).set_transitive(true),
            AttrType::PmsiTunnel,
            vec![0, 0, 0, 0], // truncated header
        ));
        assert!(attrs_bad.pmsi_tunnel().is_none());
        assert!(attrs_bad.has_pmsi_tunnel());
    }

    proptest! {
        /// CONTRIBUTING.md: a new wire codec needs a fuzz target or
        /// a proptest strategy. The decoder must never panic on
        /// arbitrary byte input — return `Some` (the byte stream
        /// parsed) or `None` (the byte stream was malformed).
        #[test]
        fn pmsi_tunnel_decode_never_panics(
            bytes in prop::collection::vec(0u8..=255, 0..=64)
        ) {
            let decoded = PmsiTunnel::decode(&bytes);
            if let Some(p) = decoded {
                // The Flags byte, Tunnel Type and Tunnel
                // Identifier always round-trip byte-for-byte;
                // the low 4 bits of the MPLS Label field are
                // zeroed on encode (the codec stores the raw
                // bytes verbatim at the PathAttribute::value
                // level so a peer-sent attribute still round-
                // trips byte-exact).
                let re = p.encode();
                assert_eq!(re.len(), bytes.len());
                assert_eq!(re[0], bytes[0]);
                assert_eq!(re[1], bytes[1]);
                assert_eq!(re[5..], bytes[5..]);
                // The high 20 bits of the label field round-trip.
                if bytes.len() >= 5 {
                    let in_label =
                        (u32::from_be_bytes([0, bytes[2], bytes[3], bytes[4]])) >> 4;
                    let out_label = (u32::from_be_bytes([0, re[2], re[3], re[4]])) >> 4;
                    assert_eq!(out_label, in_label);
                }
            } else {
                // Rejected inputs include every byte stream
                // shorter than the 5-byte header, and the two
                // Tunnel-Type-specific malformed shapes (Type 0
                // with a non-empty Tunnel Identifier; Type 6
                // with an endpoint width other than 4 or 16).
                if bytes.len() >= 5 {
                    let tt = bytes[1];
                    let tid_len = bytes.len() - 5;
                    let rejected = match tt {
                        0 => tid_len != 0,
                        6 => tid_len != 4 && tid_len != 16,
                        _ => false,
                    };
                    assert!(rejected, "expected rejection for tt={tt}, tid_len={tid_len}");
                }
            }
        }
    }
}
