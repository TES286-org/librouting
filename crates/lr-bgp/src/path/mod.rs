//! BGP path attributes (RFC 4271 §5 + RFC 4360/7153 communities +
//! RFC 4760 MP-BGP + RFC 7911 AddPath + RFC 4893 AS4_PATH/AS4_AGGREGATOR).
//!
//! Every path attribute has a fixed header:
//! - Flags (1 byte): bit 7 optional, bit 6 transitive, bit 5 partial,
//!   bit 4 extended-length, bits 3-0 unused (RFC 4271 §5.1 + RFC 9072 §2).
//! - Type (1 byte).
//! - Length (1 byte, or 2 bytes if extended-length flag is set).
//! - Value (length bytes).

pub mod as_path;
#[cfg(feature = "bgp_ls")]
pub mod bgp_ls;
#[cfg(feature = "bgp_ls")]
pub mod bgp_ls_attr;
pub mod communities;
#[cfg(feature = "labeled_unicast")]
pub mod labeled_nlri;
pub mod mp_nlri;
pub mod well_known;

pub use as_path::{AsPath, AsPathSegment, AsPathType};
pub use communities::{Community, CommunityKind, ExtendedCommunity, LargeCommunity};
#[cfg(feature = "labeled_unicast")]
pub use labeled_nlri::{
    decode_list as decode_labeled_list, decode_mp_reach as decode_labeled_mp_reach,
    decode_mp_unreach as decode_labeled_mp_unreach, encode_list as encode_labeled_list,
    encode_mp_reach as encode_labeled_mp_reach, encode_mp_unreach as encode_labeled_mp_unreach,
    ipv4_implicit_null, LabeledNlri,
};
pub use mp_nlri::{MpNextHop, MpReach, MpUnreach};
pub use well_known::{
    Aggregator, Aigp, AtomicAggregate, ClusterList, LocalPref, Med, NextHop, NextHopKind, Origin,
    OriginKind, OriginatorId, PmsiTunnel,
};

use lr_core::attr::{AttrTag, Attribute, Attributes};
use lr_core::nlri::NlriFamily;

/// Path attribute flags (RFC 4271 §5.1). Bit positions are documented in
/// RFC 9072 §2 (extended length) and earlier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct PathAttrFlags(pub u8);

impl PathAttrFlags {
    pub const OPTIONAL: u8 = 0x80;
    pub const TRANSITIVE: u8 = 0x40;
    pub const PARTIAL: u8 = 0x20;
    pub const EXTENDED_LENGTH: u8 = 0x10;

    pub const fn new() -> Self {
        Self(0)
    }
    pub const fn optional(self) -> bool {
        (self.0 & Self::OPTIONAL) != 0
    }
    pub const fn transitive(self) -> bool {
        (self.0 & Self::TRANSITIVE) != 0
    }
    pub const fn partial(self) -> bool {
        (self.0 & Self::PARTIAL) != 0
    }
    pub const fn extended_length(self) -> bool {
        (self.0 & Self::EXTENDED_LENGTH) != 0
    }
    pub fn set_optional(mut self, v: bool) -> Self {
        self.0 |= Self::OPTIONAL * v as u8;
        self
    }
    pub fn set_transitive(mut self, v: bool) -> Self {
        self.0 |= Self::TRANSITIVE * v as u8;
        self
    }
    pub fn set_partial(mut self, v: bool) -> Self {
        self.0 |= Self::PARTIAL * v as u8;
        self
    }
    pub fn set_extended(mut self, v: bool) -> Self {
        self.0 |= Self::EXTENDED_LENGTH * v as u8;
        self
    }
}

/// BGP path attribute type code (RFC 4271 §5 + IANA registry).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum AttrType {
    Origin = 1,
    AsPath = 2,
    NextHop = 3,
    MultiExitDisc = 4,
    LocalPref = 5,
    AtomicAggregate = 6,
    Aggregator = 7,
    Communities = 8,
    OriginatorId = 9,
    ClusterList = 10,
    MpReachNlri = 14,
    MpUnreachNlri = 15,
    ExtendedCommunities = 16,
    As4Path = 17,
    As4Aggregator = 18,
    PmsiTunnel = 22,
    TunnelEncap = 23,
    TrafficEngineering = 24,
    LargeCommunities = 32,
    /// RFC 9234: OTC (Only To Customer) — 4-byte unsigned integer.
    Otc = 35,
    /// RFC 7311: AIGP (Accumulated IGP Metric) — an optional
    /// non-transitive attribute whose value is a TLV stream. The
    /// type-1 TLV carries an 8-byte unsigned accumulated metric;
    /// the typed accessor on [`PathAttributes`] surfaces that
    /// metric. The codec stores the raw value bytes verbatim, so
    /// unknown TLVs round-trip byte-for-byte (RFC 7311 §3 p5:
    /// "an AIGP TLV that is not understood MUST be preserved").
    Aigp = 26,
    /// RFC 7752 §3.3 — BGP-LS Attribute. The attribute value is a
    /// TLV stream carrying link-state metadata for an accompanying
    /// BGP-LS NLRI (Node / Link / Prefix / SRv6 SID). Mandatory on
    /// the SRv6 SID NLRI per RFC 9514 §7.1 (the SRv6 Endpoint
    /// Behavior TLV must be present inside it). The TLV codec lives
    /// in [`crate::path::bgp_ls_attr`] (feature `bgp_ls`).
    BgpLsAttribute = 29,
    /// librouting-private MPLS label stack (RFC 8277). This tag is *never*
    /// transmitted on the wire — RFC 8277 carries the label stack inside
    /// the NLRI, not as a path attribute. The value holds the 4-octet-per-
    /// entry wire form (RFC 3032 §2.1, with TTL). The codec filters it out
    /// at encode time so peers never see it. Lives only in the Loc-RIB to
    /// let the router carry the label stack from a received BGP-LU UPDATE
    /// through to a re-advertised one.
    ///
    /// 255 is an internal-only code point: it never appears on the wire
    /// (the codec strips it at encode) and it deliberately avoids the
    /// 244-254 unassigned range that the W6.3 exchange-plane prototype
    /// rides on for its wire attribute (type 251).
    LrMplsLabelStack = 255,
    /// librouting-private exchange-plane record store (W6.3 prototype,
    /// feature `exchange-plane`). Carries the last received exchange-plane
    /// record set for a route through the Loc-RIB so egress can forward
    /// the provenance chain (re-signed) and the router can expose the
    /// scope-1 records to embedders. *Never* transmitted on the wire —
    /// the wire form is the optional-transitive attribute type 251 the
    /// egress path builds fresh from this store; the codec filters this
    /// tag out at encode time. Value layout: kind(1) + payload, kind 0 =
    /// verified record set (`ExchangeRecord::encode()` body), kind 1 =
    /// raw wire body of an attribute that arrived with the Partial bit
    /// set (forwarding material, design §7).
    LrExchangePlaneRecords = 254,
    /// librouting-private OSPF type-2 external metric (RFC 2328 §16.4 /
    /// RFC 5340 §4.8.5). Carries the type-2 external metric — the
    /// 24-bit external-metric value from a type-5 / type-7 LSA's E-bit+
    /// metric field — into the Loc-RIB so the policy DSL's
    /// `ospf.metric2` field can surface it. *Never* transmitted on
    /// the wire: it carries OSPF ingress state inside the Loc-RIB only
    /// (the OSPF LSDB — not BGP — is the source), and the codec strips
    /// it at encode so peers never see it. Only attached to OSPFv2 /
    /// OSPFv3 routes whose `OspfKind::External` entry has `metric_type ==
    /// ExternalMetricType::Type2`; absent for everything else.
    ///
    /// 253 is an internal-only code point: it never appears on the wire
    /// (the codec strips it at encode) and it deliberately avoids the
    /// 244-254 unassigned range that the W6.3 exchange-plane prototype
    /// rides on for its wire attribute (type 251).
    ///
    /// Value layout: a single 4-byte big-endian u32 holding the 24-bit
    /// external metric (zero-extended — RFC 2328 §2.3 caps the metric
    /// at 24 bits, so the high byte is always zero on a well-formed
    /// value).
    LrOspfMetric2 = 253,
    /// librouting-private OSPF advertising-router ID (RFC 2328 §A.4
    /// `Advertising Router` field / RFC 5340 §A.4 the same field on
    /// every v3 LSA). Carries the 32-bit OSPF Router-ID of the router
    /// that originated the LSA the route was computed from — the
    /// Router-LSA's advertising router for intra-area stub routes, the
    /// Network-LSA's advertising router (the DR) for intra-area transit
    /// routes, the summary-LSA's advertising router (the ABR) for
    /// inter-area routes, and the AS-external-LSA's advertising router
    /// (the ASBR) for external routes — into the Loc-RIB so the policy
    /// DSL's `ospf.router_id` field can surface it. *Never*
    /// transmitted on the wire: it carries OSPF ingress state inside
    /// the Loc-RIB only (the OSPF LSDB — not BGP — is the source),
    /// and the codec strips it at encode so peers never see it.
    /// Attached to every OSPFv2 / OSPFv3 route that has a known
    /// originating LSA; absent for non-OSPF routes.
    ///
    /// 252 is an internal-only code point: it never appears on the
    /// wire (the codec strips it at encode) and it deliberately
    /// avoids the 244-254 unassigned range that the W6.3
    /// exchange-plane prototype rides on for its wire attribute
    /// (type 251).
    ///
    /// Value layout: a single 4-byte big-endian u32 holding the OSPF
    /// Router-ID (the LSA `Advertising Router` field is a 32-bit
    /// dotted-quad, RFC 2328 §A.4 — no masking needed; the high byte
    /// is meaningful).
    LrOspfRouterId = 252,
    /// Unknown attribute code. The explicit discriminant keeps the
    /// data-carrying variant out of the unit-like variants' implicit
    /// numbering (the four private tags above sit at 252/253/254/255).
    Other(u8) = 0,
}

impl AttrType {
    pub fn from_u8(v: u8) -> Self {
        match v {
            1 => Self::Origin,
            2 => Self::AsPath,
            3 => Self::NextHop,
            4 => Self::MultiExitDisc,
            5 => Self::LocalPref,
            6 => Self::AtomicAggregate,
            7 => Self::Aggregator,
            8 => Self::Communities,
            9 => Self::OriginatorId,
            10 => Self::ClusterList,
            14 => Self::MpReachNlri,
            15 => Self::MpUnreachNlri,
            16 => Self::ExtendedCommunities,
            17 => Self::As4Path,
            18 => Self::As4Aggregator,
            22 => Self::PmsiTunnel,
            23 => Self::TunnelEncap,
            24 => Self::TrafficEngineering,
            29 => Self::BgpLsAttribute,
            32 => Self::LargeCommunities,
            35 => Self::Otc,
            26 => Self::Aigp,
            254 => Self::LrExchangePlaneRecords,
            253 => Self::LrOspfMetric2,
            252 => Self::LrOspfRouterId,
            255 => Self::LrMplsLabelStack,
            _ => Self::Other(v),
        }
    }

    pub fn to_u8(self) -> u8 {
        match self {
            Self::Origin => 1,
            Self::AsPath => 2,
            Self::NextHop => 3,
            Self::MultiExitDisc => 4,
            Self::LocalPref => 5,
            Self::AtomicAggregate => 6,
            Self::Aggregator => 7,
            Self::Communities => 8,
            Self::OriginatorId => 9,
            Self::ClusterList => 10,
            Self::MpReachNlri => 14,
            Self::MpUnreachNlri => 15,
            Self::ExtendedCommunities => 16,
            Self::As4Path => 17,
            Self::As4Aggregator => 18,
            Self::PmsiTunnel => 22,
            Self::TunnelEncap => 23,
            Self::TrafficEngineering => 24,
            Self::BgpLsAttribute => 29,
            Self::LargeCommunities => 32,
            Self::Otc => 35,
            Self::Aigp => 26,
            Self::LrExchangePlaneRecords => 254,
            Self::LrOspfMetric2 => 253,
            Self::LrOspfRouterId => 252,
            Self::LrMplsLabelStack => 255,
            Self::Other(v) => v,
        }
    }

    /// Whether the attribute is well-known (RFC 4271 §5.2). Well-known
    /// attributes are mandatory unless explicitly flagged optional.
    pub fn is_well_known(self) -> bool {
        matches!(
            self,
            Self::Origin
                | Self::AsPath
                | Self::NextHop
                | Self::MultiExitDisc
                | Self::LocalPref
                | Self::AtomicAggregate
                | Self::Aggregator
        )
    }

    /// Whether the attribute is mandatory (must be present in every UPDATE
    /// carrying NLRI).
    pub fn is_mandatory(self) -> bool {
        matches!(self, Self::Origin | Self::AsPath | Self::NextHop)
    }
}

/// A parsed path attribute with type and flags plus raw value bytes.
/// Decoders for individual attributes live in the `well_known`, `as_path`,
/// `communities`, `mp_nlri` modules and accept the raw value bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathAttribute {
    pub flags: PathAttrFlags,
    pub attr_type: AttrType,
    pub value: Vec<u8>,
}

impl PathAttribute {
    pub fn new(flags: PathAttrFlags, attr_type: AttrType, value: Vec<u8>) -> Self {
        Self {
            flags,
            attr_type,
            value,
        }
    }
}

/// Ordered path-attribute set keyed by attribute type code.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PathAttributes {
    attrs: Vec<PathAttribute>,
}

impl PathAttributes {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&mut self, attr: PathAttribute) {
        // Replace if same type code already present.
        for a in &mut self.attrs {
            if a.attr_type == attr.attr_type {
                *a = attr;
                return;
            }
        }
        self.attrs.push(attr);
    }

    pub fn get(&self, t: AttrType) -> Option<&PathAttribute> {
        self.attrs.iter().find(|a| a.attr_type == t)
    }

    pub fn remove(&mut self, t: AttrType) -> Option<PathAttribute> {
        let idx = self.attrs.iter().position(|a| a.attr_type == t)?;
        Some(self.attrs.remove(idx))
    }

    pub fn get_mut(&mut self, t: AttrType) -> Option<&mut PathAttribute> {
        self.attrs.iter_mut().find(|a| a.attr_type == t)
    }

    pub fn iter(&self) -> impl Iterator<Item = &PathAttribute> {
        self.attrs.iter()
    }

    pub fn iter_mut(&mut self) -> impl Iterator<Item = &mut PathAttribute> {
        self.attrs.iter_mut()
    }

    pub fn is_empty(&self) -> bool {
        self.attrs.is_empty()
    }
    pub fn len(&self) -> usize {
        self.attrs.len()
    }

    // ===== typed accessors for well-known attributes =====

    pub fn origin(&self) -> Option<Origin> {
        let a = self.get(AttrType::Origin)?;
        Origin::decode(&a.value)
    }
    pub fn as_path(&self) -> Option<AsPath> {
        let a = self.get(AttrType::AsPath)?;
        AsPath::decode_4(&a.value)
    }
    /// Decode the AS_PATH attribute at its wire width. Use this on
    /// freshly-decoded wire attributes; [`Self::as_path`] reads the
    /// canonical (4-byte) form stored in route bags.
    pub fn as_path_wire(&self, asn4: bool) -> Option<AsPath> {
        let a = self.get(AttrType::AsPath)?;
        if asn4 {
            AsPath::decode_4(&a.value)
        } else {
            AsPath::decode(&a.value)
        }
    }
    pub fn as4_path(&self) -> Option<AsPath> {
        let a = self.get(AttrType::As4Path)?;
        AsPath::decode_4(&a.value)
    }
    pub fn next_hop(&self) -> Option<NextHop> {
        let a = self.get(AttrType::NextHop)?;
        NextHop::decode(&a.value)
    }
    pub fn med(&self) -> Option<Med> {
        let a = self.get(AttrType::MultiExitDisc)?;
        Med::decode(&a.value)
    }
    pub fn local_pref(&self) -> Option<LocalPref> {
        let a = self.get(AttrType::LocalPref)?;
        LocalPref::decode(&a.value)
    }
    /// Insert or replace the LOCAL_PREF attribute (RFC 4271 §5.1.4).
    ///
    /// LOCAL_PREF is well-known discretionary (flags `0x40` —
    /// transitive, not optional). Used by the RFC 8326 graceful
    /// shutdown export hook to zero out LOCAL_PREF on routes that
    /// carry `GRACEFUL_SHUTDOWN`, so receivers prefer alternatives.
    pub fn set_local_pref(&mut self, value: u32) {
        let lp = LocalPref(value);
        self.insert(PathAttribute::new(
            PathAttrFlags::new().set_transitive(true),
            AttrType::LocalPref,
            lp.encode().to_vec(),
        ));
    }
    pub fn atomic_aggregate(&self) -> Option<AtomicAggregate> {
        self.get(AttrType::AtomicAggregate).map(|_| AtomicAggregate)
    }
    pub fn aggregator(&self) -> Option<Aggregator> {
        let a = self.get(AttrType::Aggregator)?;
        Aggregator::decode(&a.value)
    }
    /// ORIGINATOR_ID (RFC 4456 §8) — the BGP Identifier of the
    /// originator of a route-reflected route. `None` when the
    /// attribute is absent (e.g. a non-reflected route) or when the
    /// wire form is malformed (any length other than 4 bytes).
    pub fn originator_id(&self) -> Option<OriginatorId> {
        let a = self.get(AttrType::OriginatorId)?;
        OriginatorId::decode(&a.value)
    }
    /// CLUSTER_LIST (RFC 4456 §8) — the sequence of CLUSTER_IDs the
    /// route has passed through. Returns an empty `ClusterList` when
    /// the attribute is absent (a non-reflected route); returns
    /// `None` only when the wire form is malformed (length not a
    /// multiple of 4). Callers that distinguish "absent" from "empty"
    /// should consult [`Self::get`] with `AttrType::ClusterList`
    /// first; this accessor collapses the two for convenience.
    pub fn cluster_list(&self) -> Option<ClusterList> {
        match self.get(AttrType::ClusterList) {
            None => Some(ClusterList::default()),
            Some(a) => ClusterList::decode(&a.value),
        }
    }
    /// True when a CLUSTER_LIST attribute is physically present on
    /// the route (RFC 4456 §8). Use this to distinguish "no
    /// attribute" from "present but empty" — `cluster_list()`
    /// collapses both to an empty list.
    pub fn has_cluster_list(&self) -> bool {
        self.get(AttrType::ClusterList).is_some()
    }
    /// OTC (RFC 9234 §3.1) — the 4-byte "Only To Customer" attribute
    /// carrying the AS number that last tagged the route for
    /// customer-only propagation. `None` when the attribute is absent
    /// or the wire form is malformed (any length other than 4 bytes).
    /// A present value of `Otc(0)` is treated as "set but zero" by the
    /// caller — the codec does not collapse it to `None`, so
    /// `defined(bgp.otc)` in the filter DSL distinguishes "absent"
    /// from "set to zero" exactly as BIRD does.
    pub fn otc(&self) -> Option<crate::role::otc::Otc> {
        let a = self.get(AttrType::Otc)?;
        crate::role::otc::Otc::decode(&a.value)
    }
    /// True when an OTC attribute is physically present on the route
    /// (RFC 9234 §3.1). Use this to distinguish "no attribute" from
    /// "present but zero" — `otc()` returns `Some(Otc(0))` for the
    /// latter.
    pub fn has_otc(&self) -> bool {
        self.get(AttrType::Otc).is_some()
    }
    /// AIGP (RFC 7311) — the Accumulated IGP Metric attribute. The
    /// value field is a TLV stream; the typed view surfaces the
    /// accumulated metric (the sum of every type-1 TLV's 8-byte
    /// value). `None` when the attribute is absent or the TLV stream
    /// is malformed (a TLV length runs past the end, or a type-1
    /// TLV's value is not exactly 8 bytes). An empty value field
    /// decodes to `Aigp(0)` — use [`Self::has_aigp`] to distinguish
    /// "absent" from "present but zero".
    ///
    /// The codec stores the raw attribute bytes verbatim, so unknown
    /// TLV types round-trip byte-for-byte (RFC 7311 §3 p5).
    pub fn aigp(&self) -> Option<well_known::Aigp> {
        let a = self.get(AttrType::Aigp)?;
        well_known::Aigp::decode(&a.value)
    }
    /// True when an AIGP attribute is physically present on the route
    /// (RFC 7311). Use this to distinguish "no attribute" from
    /// "present but zero" — `aigp()` returns `Some(Aigp(0))` for the
    /// latter (e.g. an empty value field).
    pub fn has_aigp(&self) -> bool {
        self.get(AttrType::Aigp).is_some()
    }
    /// PMSI Tunnel attribute (RFC 6514 §5) — the
    /// P-Multicast Service Interface Tunnel binding a BGP UPDATE
    /// advertises for an MVPN auto-discovery route. The attribute
    /// is optional transitive (flags `0xC0`); the value field is
    /// a fixed 5-byte header (Flags + Tunnel Type + MPLS Label)
    /// followed by a variable-length Tunnel Identifier. `None`
    /// when the attribute is absent or the value field is
    /// malformed (shorter than 5 bytes; Tunnel Type 0 with a
    /// non-empty Tunnel Identifier; Tunnel Type 6 with an
    /// endpoint width other than 4 or 16 bytes). The codec
    /// stores the raw attribute bytes verbatim so an attribute
    /// with an unknown Tunnel Type or non-zero reserved bits
    /// round-trips byte-for-byte.
    ///
    /// The filter DSL surfaces this attribute as `bgp.pmsi_tunnel`
    /// (read-only `bool` — `true` when the attribute is present,
    /// `false` when absent, mirroring BIRD's `EAF_TYPE_OPAQUE` +
    /// `T_ENUM_EMPTY` exposure so the canonical idiom
    /// `if defined(bgp.pmsi_tunnel) then reject;` translates
    /// faithfully).
    pub fn pmsi_tunnel(&self) -> Option<well_known::PmsiTunnel> {
        let a = self.get(AttrType::PmsiTunnel)?;
        well_known::PmsiTunnel::decode(&a.value)
    }
    /// True when a PMSI Tunnel attribute is physically present on
    /// the route (RFC 6514 §5). Use this to distinguish "no
    /// attribute" from "present but malformed" — `pmsi_tunnel()`
    /// returns `None` for both, but `has_pmsi_tunnel()` reports
    /// the attribute's physical presence so the `defined(bgp.pmsi_tunnel)`
    /// filter DSL predicate can distinguish them exactly as BIRD's
    /// `defined(bgp_pmsi_tunnel)` does.
    pub fn has_pmsi_tunnel(&self) -> bool {
        self.get(AttrType::PmsiTunnel).is_some()
    }
    pub fn communities(&self) -> Vec<Community> {
        self.get(AttrType::Communities)
            .map(|a| Community::decode_set(&a.value))
            .unwrap_or_default()
    }
    /// True when the COMMUNITIES attribute contains `c`.
    pub fn has_community(&self, c: Community) -> bool {
        self.communities().contains(&c)
    }
    /// Attach a community to the COMMUNITIES attribute (idempotent).
    /// COMMUNITIES is optional transitive (RFC 1997 §4).
    pub fn insert_community(&mut self, c: Community) {
        let mut set = self.communities();
        if set.contains(&c) {
            return;
        }
        set.push(c);
        self.insert(PathAttribute::new(
            PathAttrFlags::new().set_optional(true).set_transitive(true),
            AttrType::Communities,
            Community::encode_set(&set),
        ));
    }
    pub fn extended_communities(&self) -> Vec<ExtendedCommunity> {
        self.get(AttrType::ExtendedCommunities)
            .map(|a| ExtendedCommunity::decode_set(&a.value))
            .unwrap_or_default()
    }
    /// The route's LARGE_COMMUNITIES (RFC 8092 §2); empty when absent.
    pub fn large_communities(&self) -> Vec<LargeCommunity> {
        self.get(AttrType::LargeCommunities)
            .map(|a| LargeCommunity::decode_set(&a.value))
            .unwrap_or_default()
    }
    /// Attach a large community (RFC 8092 §2), idempotent.
    /// LARGE_COMMUNITIES is optional transitive.
    pub fn insert_large_community(&mut self, c: LargeCommunity) {
        let mut set = self.large_communities();
        if set.contains(&c) {
            return;
        }
        set.push(c);
        self.insert(PathAttribute::new(
            PathAttrFlags::new().set_optional(true).set_transitive(true),
            AttrType::LargeCommunities,
            LargeCommunity::encode_set(&set),
        ));
    }
    pub fn mp_reach(&self) -> Option<MpReach> {
        let a = self.get(AttrType::MpReachNlri)?;
        MpReach::decode(&a.value)
    }
    pub fn mp_unreach(&self) -> Option<MpUnreach> {
        let a = self.get(AttrType::MpUnreachNlri)?;
        MpUnreach::decode(&a.value)
    }

    /// Attach an MPLS label stack to this attribute set under the private
    /// [`AttrType::LrMplsLabelStack`] tag. The tag is never transmitted on
    /// the wire; it carries the label stack from a received BGP-LU UPDATE
    /// through the Loc-RIB so egress can put it back into the NLRI.
    #[cfg(feature = "labeled_unicast")]
    pub fn set_label_stack(&mut self, stack: &lr_mpls::LabelStack) {
        let value = stack.encode_4octet();
        self.insert(PathAttribute::new(
            PathAttrFlags::new().set_optional(true),
            AttrType::LrMplsLabelStack,
            value,
        ));
    }

    /// Read back the MPLS label stack previously attached with
    /// [`Self::set_label_stack`]. Returns `None` when the route carries no
    /// label stack (i.e. it is not a BGP-LU route).
    #[cfg(feature = "labeled_unicast")]
    pub fn label_stack(&self) -> Option<lr_mpls::LabelStack> {
        let a = self.get(AttrType::LrMplsLabelStack)?;
        lr_mpls::LabelStack::decode_4octet(&a.value).ok()
    }

    /// Attach the OSPF type-2 external metric (RFC 2328 §16.4) to this
    /// attribute set under the private [`AttrType::LrOspfMetric2`] tag.
    /// The tag is never transmitted on the wire; it carries the type-2
    /// external metric the OSPF route computation extracted from a
    /// type-5 / type-7 LSA's E-bit+metric field through the Loc-RIB so
    /// the filter DSL's `ospf.metric2` field can surface it. Only
    /// attached to OSPFv2 / OSPFv3 routes whose `OspfKind::External`
    /// entry has `metric_type == ExternalMetricType::Type2`.
    ///
    /// `metric` is masked to the 24-bit OSPF external-metric width
    /// (RFC 2328 §2.3 caps the metric at 24 bits; values above
    /// `0x00ff_ffff` are clipped, never overflow).
    pub fn set_ospf_metric2(&mut self, metric: u32) {
        let masked = metric & 0x00ff_ffff;
        let value = masked.to_be_bytes();
        self.insert(PathAttribute::new(
            PathAttrFlags::new().set_optional(true),
            AttrType::LrOspfMetric2,
            value.to_vec(),
        ));
    }

    /// Read back the OSPF type-2 external metric previously attached
    /// with [`Self::set_ospf_metric2`]. Returns `None` when the route
    /// carries no OSPF metric-2 attribute — i.e. it is not an OSPF
    /// type-2 external route (the OSPF route computation only attaches
    /// the tag for type-2 externals; intra-area, inter-area and
    /// type-1 external OSPF routes carry no `LrOspfMetric2` tag, as do
    /// all non-OSPF routes).
    ///
    /// A malformed value (not exactly 4 bytes) returns `None` — the
    /// codec rejects partial-width stores at decode. Callers that
    /// need to distinguish "absent" from "present but malformed"
    /// should consult [`Self::has_ospf_metric2`].
    pub fn ospf_metric2(&self) -> Option<u32> {
        let a = self.get(AttrType::LrOspfMetric2)?;
        if a.value.len() != 4 {
            return None;
        }
        Some(u32::from_be_bytes([
            a.value[0], a.value[1], a.value[2], a.value[3],
        ]))
    }

    /// True when an `LrOspfMetric2` attribute is physically present on
    /// the route (RFC 2328 §16.4). Use this to distinguish "no
    /// attribute" from "present but malformed" — [`Self::ospf_metric2`]
    /// returns `None` for both, but `has_ospf_metric2()` reports the
    /// attribute's physical presence so the `defined(ospf.metric2)`
    /// filter DSL predicate can distinguish them exactly as BIRD's
    /// `defined(ospf_metric2)` does.
    pub fn has_ospf_metric2(&self) -> bool {
        self.get(AttrType::LrOspfMetric2).is_some()
    }

    /// Attach the OSPF advertising-router ID (RFC 2328 §A.4 `Advertising
    /// Router` field / RFC 5340 §A.4 the same field on every v3 LSA) to
    /// this attribute set under the private [`AttrType::LrOspfRouterId`]
    /// tag. The tag is never transmitted on the wire; it carries the
    /// 32-bit OSPF Router-ID of the router that originated the LSA the
    /// route was computed from (the Router-LSA's advertising router for
    /// intra-area stub routes; the Network-LSA's advertising router —
    /// the DR — for intra-area transit routes; the summary-LSA's
    /// advertising router — the ABR — for inter-area routes; the
    /// AS-external-LSA's advertising router — the ASBR — for external
    /// routes) through the Loc-RIB so the filter DSL's `ospf.router_id`
    /// field can surface it. Attached to every OSPFv2 / OSPFv3 route
    /// that has a known originating LSA; absent for non-OSPF routes.
    ///
    /// `router_id` is the raw 32-bit OSPF Router-ID (no masking — the
    /// field is 32-bit per RFC 2328 §A.4).
    pub fn set_ospf_router_id(&mut self, router_id: u32) {
        let value = router_id.to_be_bytes();
        self.insert(PathAttribute::new(
            PathAttrFlags::new().set_optional(true),
            AttrType::LrOspfRouterId,
            value.to_vec(),
        ));
    }

    /// Read back the OSPF advertising-router ID previously attached
    /// with [`Self::set_ospf_router_id`]. Returns `None` when the
    /// route carries no OSPF router-id attribute — i.e. it is not an
    /// OSPF route, or the OSPF route computation could not identify
    /// the originating LSA's advertising router.
    ///
    /// A malformed value (not exactly 4 bytes) returns `None` — the
    /// codec rejects partial-width stores at decode. Callers that need
    /// to distinguish "absent" from "present but malformed" should
    /// consult [`Self::has_ospf_router_id`].
    pub fn ospf_router_id(&self) -> Option<u32> {
        let a = self.get(AttrType::LrOspfRouterId)?;
        if a.value.len() != 4 {
            return None;
        }
        Some(u32::from_be_bytes([
            a.value[0], a.value[1], a.value[2], a.value[3],
        ]))
    }

    /// True when an `LrOspfRouterId` attribute is physically present on
    /// the route (RFC 2328 §A.4). Use this to distinguish "no
    /// attribute" from "present but malformed" — [`Self::ospf_router_id`]
    /// returns `None` for both, but `has_ospf_router_id()` reports the
    /// attribute's physical presence so the `defined(ospf.router_id)`
    /// filter DSL predicate can distinguish them exactly as BIRD's
    /// `defined(ospf_router_id)` does.
    pub fn has_ospf_router_id(&self) -> bool {
        self.get(AttrType::LrOspfRouterId).is_some()
    }

    /// Decode MP_REACH_NLRI with RFC 7911 Add-Path awareness: `add_path`
    /// decides, per address family, whether each NLRI entry carries a
    /// 4-octet path identifier (the family is read from the attribute value
    /// itself before decoding the entries).
    pub fn mp_reach_with(&self, add_path: impl Fn(NlriFamily) -> bool) -> Option<MpReach> {
        let a = self.get(AttrType::MpReachNlri)?;
        let family = read_family_prefix(&a.value)?;
        MpReach::decode_ex(&a.value, add_path(family))
    }

    /// Decode MP_UNREACH_NLRI with RFC 7911 Add-Path awareness — see
    /// [`Self::mp_reach_with`].
    pub fn mp_unreach_with(&self, add_path: impl Fn(NlriFamily) -> bool) -> Option<MpUnreach> {
        let a = self.get(AttrType::MpUnreachNlri)?;
        let family = read_family_prefix(&a.value)?;
        MpUnreach::decode_ex(&a.value, add_path(family))
    }
}

/// Read the (AFI, SAFI) prefix of an MP_REACH/MP_UNREACH attribute value.
fn read_family_prefix(value: &[u8]) -> Option<lr_core::nlri::NlriFamily> {
    if value.len() < 3 {
        return None;
    }
    Some(lr_core::nlri::NlriFamily {
        afi: u16::from_be_bytes([value[0], value[1]]),
        safi: value[2],
    })
}

impl From<PathAttributes> for Attributes {
    fn from(p: PathAttributes) -> Self {
        let mut out = Self::new();
        for a in p.attrs {
            out.insert(Attribute {
                tag: AttrTag(a.attr_type.to_u8()),
                flags: a.flags.0,
                value: a.value,
            });
        }
        out
    }
}

impl From<Attributes> for PathAttributes {
    fn from(a: Attributes) -> Self {
        let mut out = Self::new();
        for attr in a.iter().cloned() {
            out.insert(PathAttribute {
                flags: PathAttrFlags(attr.flags),
                attr_type: AttrType::from_u8(attr.tag.0),
                value: attr.value,
            });
        }
        out
    }
}
