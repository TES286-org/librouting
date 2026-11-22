//! ROUTE-REFRESH message (RFC 2918 + RFC 7313 enhanced variant) and
//! the RFC 5291 ORF payload it can carry.
//!
//! A plain ROUTE-REFRESH has a 4-byte body: AFI (2) | subtype/reserved
//! (1) | SAFI (1). RFC 7313 redefines the formerly reserved octet as a
//! demarcation subtype; it does not append a BGP identifier.
//!
//! RFC 5291 §4 reuses the same message for ORF entries: the first four
//! octets keep the AFI/SAFI layout (the third octet is reserved and set
//! to zero), and the body continues with a When-to-refresh octet
//! followed by one or more `(ORF Type, Length, entries)` blocks. The
//! presence of the fifth octet distinguishes an ORF message from a
//! plain refresh (RFC 5291 §4).

use lr_core::addr::Prefix;
use lr_core::nlri::NlriFamily;

/// RFC 7313 route-refresh subtype carried in the third body octet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum RouteRefreshSubtype {
    /// RFC 2918 request, or a normal RFC 7313 route-refresh message.
    Normal = 0,
    /// Beginning-of-RIB marker (BoRR).
    BeginOfRib = 1,
    /// End-of-RIB marker (EoRR).
    EndOfRib = 2,
    /// Unknown subtype — RFC 7313 §3.2 requires the message to be
    /// silently ignored, so the decoder maps unrecognized values here
    /// instead of failing.
    Unknown = 0xff,
}

impl RouteRefreshSubtype {
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(Self::Normal),
            1 => Some(Self::BeginOfRib),
            2 => Some(Self::EndOfRib),
            _ => None,
        }
    }
}

/// RFC 5291 §4 When-to-refresh values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum OrfWhenToRefresh {
    /// Re-advertise the affected routes as soon as the entries are
    /// processed.
    Immediate = 1,
    /// Apply the entries but defer re-advertisement until a plain
    /// ROUTE-REFRESH or an IMMEDIATE ORF arrives for the family.
    Defer = 2,
}

impl OrfWhenToRefresh {
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            1 => Some(Self::Immediate),
            2 => Some(Self::Defer),
            _ => None,
        }
    }

    pub fn as_u8(self) -> u8 {
        self as u8
    }
}

/// RFC 5291 §4 Action field (the two most significant bits of each ORF
/// entry's first octet).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum OrfAction {
    Add = 0,
    Remove = 1,
    RemoveAll = 2,
    /// An unassigned action value. RFC 5291 §6 requires the whole
    /// previously received ORF of that type to be removed when a field
    /// carries an unrecognized value.
    Unknown = 0xff,
}

impl OrfAction {
    pub fn from_u8(value: u8) -> Self {
        match value {
            0 => Self::Add,
            1 => Self::Remove,
            2 => Self::RemoveAll,
            _ => Self::Unknown,
        }
    }
}

/// RFC 5292 §3 Address Prefix ORF entry (ORF type 64).
///
/// The wire fields are `<Sequence, Match, Length, Prefix, Minlen,
/// Maxlen>`; `Match` lives in the common ORF-entry octet and the rest
/// in the type-specific part.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AddressPrefixOrf {
    /// RFC 5292 §2: relative ordering of the entry. The smallest
    /// sequence among the matching entries decides the route
    /// (first-match rule, §4).
    pub sequence: u32,
    /// Action (RFC 5291 §4): Add, Remove, or RemoveAll.
    pub action: OrfAction,
    /// Match bit: `true` = PERMIT, `false` = DENY.
    pub permit: bool,
    /// ORF prefix length in bits.
    pub prefix: Prefix,
    /// Minimum NLRI length required for a match; 0 = unspecified.
    pub min_len: u8,
    /// Maximum NLRI length required for a match; 0 = unspecified.
    pub max_len: u8,
}

impl AddressPrefixOrf {
    /// A PERMIT (or DENY) Add entry.
    pub fn add(sequence: u32, permit: bool, prefix: Prefix, min_len: u8, max_len: u8) -> Self {
        Self {
            sequence,
            action: OrfAction::Add,
            permit,
            prefix,
            min_len,
            max_len,
        }
    }

    /// A Remove entry matching `sequence`.
    pub fn remove(sequence: u32, permit: bool, prefix: Prefix, min_len: u8, max_len: u8) -> Self {
        Self {
            sequence,
            action: OrfAction::Remove,
            permit,
            prefix,
            min_len,
            max_len,
        }
    }

    /// RFC 5292 §4 first-match test: the NLRI must be equal to or more
    /// specific than the ORF prefix, then the Minlen/Maxlen table
    /// decides. An ORF entry never matches a prefix of the other
    /// address family.
    pub fn matches(&self, nlri: &Prefix) -> bool {
        if self.prefix.addr.is_ipv4() != nlri.addr.is_ipv4() {
            return false;
        }
        if nlri.prefix_len < self.prefix.prefix_len || !self.prefix.contains_prefix(nlri) {
            return false;
        }
        let min_ok = self.min_len == 0 || nlri.prefix_len >= self.min_len;
        let max_ok = self.max_len == 0 || nlri.prefix_len <= self.max_len;
        min_ok && max_ok
    }
}

/// One entry of an RFC 5291 ORF block. Unknown ORF types are preserved
/// as raw bytes so a decoder never has to guess their layout.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OrfEntry {
    /// `Action = REMOVE-ALL` (RFC 5291 §4: the entry is only the
    /// common octet).
    RemoveAll,
    /// An Address Prefix ORF entry (type 64, RFC 5292 §3).
    AddressPrefix(AddressPrefixOrf),
    /// An unparsed entry of an ORF type this implementation does not
    /// understand. The whole block's bytes are kept together.
    Raw(Vec<u8>),
}

/// One `<ORF Type, entries>` block of an ORF ROUTE-REFRESH.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OrfList {
    /// RFC 5291 ORF Type; 64 is the Address Prefix ORF (RFC 5292).
    pub orf_type: u8,
    pub entries: Vec<OrfEntry>,
}

impl OrfList {
    /// The Address Prefix ORF type (RFC 5292 §2).
    pub const ADDRESS_PREFIX: u8 = 64;

    pub fn address_prefix(entries: Vec<AddressPrefixOrf>) -> Self {
        Self {
            orf_type: Self::ADDRESS_PREFIX,
            entries: entries.into_iter().map(OrfEntry::AddressPrefix).collect(),
        }
    }

    /// The effective Address Prefix entries, ignoring entries of other
    /// kinds. `None` when this is not an Address Prefix ORF.
    pub fn address_prefix_entries(&self) -> Option<Vec<AddressPrefixOrf>> {
        if self.orf_type != Self::ADDRESS_PREFIX {
            return None;
        }
        Some(
            self.entries
                .iter()
                .filter_map(|e| match e {
                    OrfEntry::AddressPrefix(e) => Some(*e),
                    OrfEntry::RemoveAll => Some(AddressPrefixOrf {
                        sequence: 0,
                        action: OrfAction::RemoveAll,
                        permit: false,
                        prefix: Prefix::new_v4([0, 0, 0, 0], 0),
                        min_len: 0,
                        max_len: 0,
                    }),
                    OrfEntry::Raw(_) => None,
                })
                .collect(),
        )
    }
}

/// The ORF payload of a ROUTE-REFRESH message (RFC 5291 §4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OrfRefresh {
    pub when: OrfWhenToRefresh,
    pub lists: Vec<OrfList>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteRefresh {
    pub family: NlriFamily,
    pub subtype: RouteRefreshSubtype,
    /// RFC 5291 ORF payload. `None` is the plain RFC 2918 / RFC 7313
    /// message; `Some` makes the message an ORF request.
    pub orf: Option<OrfRefresh>,
}

impl RouteRefresh {
    pub fn new(family: NlriFamily) -> Self {
        Self {
            family,
            subtype: RouteRefreshSubtype::Normal,
            orf: None,
        }
    }

    pub fn begin_of_rib(family: NlriFamily) -> Self {
        Self {
            family,
            subtype: RouteRefreshSubtype::BeginOfRib,
            orf: None,
        }
    }

    pub fn end_of_rib(family: NlriFamily) -> Self {
        Self {
            family,
            subtype: RouteRefreshSubtype::EndOfRib,
            orf: None,
        }
    }

    /// Build an ORF ROUTE-REFRESH (RFC 5291 §4). The subtype octet is
    /// reserved in an ORF message and is set to zero on transmit.
    pub fn with_orf(family: NlriFamily, when: OrfWhenToRefresh, lists: Vec<OrfList>) -> Self {
        Self {
            family,
            subtype: RouteRefreshSubtype::Normal,
            orf: Some(OrfRefresh { when, lists }),
        }
    }

    /// True when this is a plain refresh (no ORF payload).
    pub fn is_plain(&self) -> bool {
        self.orf.is_none()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn address_prefix_matches_equal_and_more_specific() {
        let orf = AddressPrefixOrf::add(10, true, Prefix::new_v4([192, 0, 2, 0], 24), 0, 0);
        assert!(orf.matches(&Prefix::new_v4([192, 0, 2, 0], 24)));
        assert!(orf.matches(&Prefix::new_v4([192, 0, 2, 128], 25)));
        // Less specific and outside the covering prefix do not match.
        assert!(!orf.matches(&Prefix::new_v4([192, 0, 0, 0], 16)));
        assert!(!orf.matches(&Prefix::new_v4([198, 51, 100, 0], 24)));
        // Cross-family never matches.
        assert!(!orf.matches(&Prefix::new_v6(
            [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            32
        )));
    }

    #[test]
    fn address_prefix_min_and_max_len_bound_the_match() {
        let orf = AddressPrefixOrf::add(1, true, Prefix::new_v4([10, 0, 0, 0], 8), 16, 24);
        assert!(!orf.matches(&Prefix::new_v4([10, 0, 0, 0], 8)));
        assert!(!orf.matches(&Prefix::new_v4([10, 1, 0, 0], 15)));
        assert!(orf.matches(&Prefix::new_v4([10, 1, 0, 0], 16)));
        assert!(orf.matches(&Prefix::new_v4([10, 1, 2, 0], 24)));
        assert!(!orf.matches(&Prefix::new_v4([10, 1, 2, 0], 25)));
    }
}
