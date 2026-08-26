//! UPDATE message (RFC 4271 §4.3 + RFC 4271 §5 path attributes).

use lr_core::addr::Prefix;
use lr_core::nlri::NlriFamily;

use crate::path::{PathAttribute, PathAttributes};

/// BGP UPDATE message.
///
/// An UPDATE has three optional sections:
/// - **Withdrawn Routes** (list of prefixes that should be removed)
/// - **Path Attributes** (only if NLRI is present; can be empty for withdraw-only)
/// - **NLRI** (list of prefixes to advertise with the given attributes)
///
/// For MP-BGP (RFC 4760), NLRI is carried inside the `MpReach`/`MpUnreach`
/// path attributes and the IPv4 NLRI section is empty.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Update {
    /// Routes being withdrawn from service (IPv4 only for legacy).
    pub withdrawn: Vec<Prefix>,
    /// Path attributes (origins, AS path, next hop, etc.).
    pub attributes: PathAttributes,
    /// IPv4 NLRI (empty for MP-BGP; for legacy BGP-4).
    pub nlri: Vec<Prefix>,
}

impl Update {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_withdrawn(mut self, prefixes: impl IntoIterator<Item = Prefix>) -> Self {
        self.withdrawn.extend(prefixes);
        self
    }

    pub fn with_attribute(mut self, attr: PathAttribute) -> Self {
        self.attributes.insert(attr);
        self
    }

    pub fn with_nlri(mut self, prefixes: impl IntoIterator<Item = Prefix>) -> Self {
        self.nlri.extend(prefixes);
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
