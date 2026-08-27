//! UPDATE message (RFC 4271 §4.3 + RFC 4271 §5 path attributes).

use lr_core::addr::Prefix;
use lr_core::nlri::NlriFamily;

use crate::path::{PathAttribute, PathAttributes};

/// One NLRI entry: an optional RFC 7911 Add-Path identifier plus a prefix.
///
/// When Add-Path is negotiated for the entry's address family, the wire
/// encoding of each NLRI is a 4-octet path identifier followed by the
/// prefix (RFC 7911 §4.3); otherwise only the prefix is encoded and
/// `path_id` is meaningless on the wire. `path_id == 0` is the customary
/// "no add-path discrimination" value for single-path operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Nlri {
    pub path_id: u32,
    pub prefix: Prefix,
}

impl Nlri {
    /// A single-path entry (no Add-Path discrimination).
    pub const fn plain(prefix: Prefix) -> Self {
        Self { path_id: 0, prefix }
    }

    /// An Add-Path-identified entry (RFC 7911 §4.3).
    pub const fn new(path_id: u32, prefix: Prefix) -> Self {
        Self { path_id, prefix }
    }
}

impl From<Prefix> for Nlri {
    fn from(prefix: Prefix) -> Self {
        Self::plain(prefix)
    }
}

/// BGP UPDATE message.
///
/// An UPDATE has three optional sections:
/// - **Withdrawn Routes** (list of prefixes that should be removed)
/// - **Path Attributes** (only if NLRI is present; can be empty for withdraw-only)
/// - **NLRI** (list of prefixes to advertise with the given attributes)
///
/// For MP-BGP (RFC 4760), NLRI is carried inside the `MpReach`/`MpUnreach`
/// path attributes and the IPv4 NLRI section is empty. For Add-Path
/// (RFC 7911), each entry additionally carries a path identifier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Update {
    /// Routes being withdrawn from service (IPv4 only for legacy).
    pub withdrawn: Vec<Nlri>,
    /// Path attributes (origins, AS path, next hop, etc.).
    pub attributes: PathAttributes,
    /// IPv4 NLRI (empty for MP-BGP; for legacy BGP-4).
    pub nlri: Vec<Nlri>,
}

impl Update {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_withdrawn(mut self, prefixes: impl IntoIterator<Item = Prefix>) -> Self {
        self.withdrawn.extend(prefixes.into_iter().map(Nlri::plain));
        self
    }

    pub fn with_attribute(mut self, attr: PathAttribute) -> Self {
        self.attributes.insert(attr);
        self
    }

    pub fn with_nlri(mut self, prefixes: impl IntoIterator<Item = Prefix>) -> Self {
        self.nlri.extend(prefixes.into_iter().map(Nlri::plain));
        self
    }

    /// True if this UPDATE carries only withdrawals (no attributes, no NLRI).
    pub fn is_withdraw_only(&self) -> bool {
        self.attributes.is_empty() && self.nlri.is_empty() && !self.withdrawn.is_empty()
    }

    /// True if this UPDATE is a route refresh marker for a specific AF.
    pub fn family(&self) -> NlriFamily {
        // Default to IPv4 unicast for legacy NLRI. MP-BGP overrides via attributes.
        if let Some(mp) = self.attributes.mp_reach() {
            return mp.family;
        }
        NlriFamily::IPV4_UNICAST
    }
}

impl Default for Update {
    fn default() -> Self {
        Self {
            withdrawn: Vec::new(),
            attributes: PathAttributes::new(),
            nlri: Vec::new(),
        }
    }
}
