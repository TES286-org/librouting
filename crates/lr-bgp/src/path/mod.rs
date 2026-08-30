//! BGP path attributes (RFC 4271 §5 + RFC 4360/6675 communities +
//! RFC 4760 MP-BGP + RFC 7911 AddPath + RFC 4893 AS4_PATH/AS4_AGGREGATOR).
//!
//! Every path attribute has a fixed header:
//! - Flags (1 byte): bit 7 optional, bit 6 transitive, bit 5 partial,
//!   bit 4 extended-length, bits 3-0 unused (RFC 4271 §5.1 + RFC 9072 §2).
//! - Type (1 byte).
//! - Length (1 byte, or 2 bytes if extended-length flag is set).
//! - Value (length bytes).

pub mod as_path;
pub mod communities;
#[cfg(feature = "labeled_unicast")]
pub mod labeled_nlri;
pub mod mp_nlri;
pub mod well_known;

pub use as_path::{AsPath, AsPathSegment, AsPathType};
pub use communities::{Community, CommunityKind, ExtendedCommunity};
#[cfg(feature = "labeled_unicast")]
pub use labeled_nlri::{
    decode_list as decode_labeled_list, decode_mp_reach as decode_labeled_mp_reach,
    decode_mp_unreach as decode_labeled_mp_unreach, encode_list as encode_labeled_list,
    encode_mp_reach as encode_labeled_mp_reach, encode_mp_unreach as encode_labeled_mp_unreach,
    ipv4_implicit_null, LabeledNlri,
};
pub use mp_nlri::{MpNextHop, MpReach, MpUnreach};
pub use well_known::{
    Aggregator, AtomicAggregate, LocalPref, Med, NextHop, NextHopKind, Origin, OriginKind,
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
    /// librouting-private MPLS label stack (RFC 8277). This tag is *never*
    /// transmitted on the wire — RFC 8277 carries the label stack inside
    /// the NLRI, not as a path attribute. The value holds the 4-octet-per-
    /// entry wire form (RFC 3032 §2.1, with TTL). The codec filters it out
    /// at encode time so peers never see it. Lives only in the Loc-RIB to
    /// let the router carry the label stack from a received BGP-LU UPDATE
    /// through to a re-advertised one.
    LrMplsLabelStack = 251,
    /// Unknown attribute code.
    Other(u8),
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
            32 => Self::LargeCommunities,
            35 => Self::Otc,
            251 => Self::LrMplsLabelStack,
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
            Self::LargeCommunities => 32,
            Self::Otc => 35,
            Self::LrMplsLabelStack => 251,
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

    pub fn iter(&self) -> impl Iterator<Item = &PathAttribute> {
        self.attrs.iter()
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
    pub fn atomic_aggregate(&self) -> Option<AtomicAggregate> {
        self.get(AttrType::AtomicAggregate).map(|_| AtomicAggregate)
    }
    pub fn aggregator(&self) -> Option<Aggregator> {
        let a = self.get(AttrType::Aggregator)?;
        Aggregator::decode(&a.value)
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
