//! Confederation configuration (RFC 5065).
//!
//! A confederation is a set of ASNs treated as one AS externally but acting
//! as a sub-AS internally. Routes are exchanged between confederation
//! members using the AS_CONFED_SEQUENCE / AS_CONFED_SET segment types, and
//! the local speaker announces the confederation identifier (not its private
//! Member-AS) to peers outside the confederation (RFC 5065 §4).
//!
//! Wire-level segment types live in [`crate::path::as_path::AsPathType`] as
//! `ConfedSequence` and `ConfedSet`. This module only describes the
//! configuration.

/// Per-speaker confederation configuration.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ConfederationConfig {
    /// AS numbers that participate in this confederation. The local speaker
    /// itself is one of these; its own sub-AS is supplied separately on the
    /// [`crate::peer::PeerConfig`] as `local_as`.
    pub members: Vec<u32>,
    /// The confederation identifier (RFC 5065 §4): the single ASN the
    /// confederation presents to peers that are not members. RFC 5065 §4
    /// requires a member to use this identifier in every transaction with a
    /// non-member peer — including the AS_SEQUENCE prepended on egress. When
    /// `None`, the first member is used as the identifier for backward
    /// compatibility, matching BIRD's `confederation member` default.
    pub confederation_id: Option<u32>,
}

impl ConfederationConfig {
    pub fn new(members: Vec<u32>) -> Self {
        Self {
            members,
            confederation_id: None,
        }
    }

    /// Build a config with an explicit confederation identifier (RFC 5065 §4).
    pub fn with_id(members: Vec<u32>, confederation_id: u32) -> Self {
        Self {
            members,
            confederation_id: Some(confederation_id),
        }
    }

    /// True if `asn` is a confederation member.
    pub fn contains(&self, asn: u32) -> bool {
        self.members.contains(&asn)
    }

    /// The ASN to announce to peers outside the confederation (RFC 5065 §4).
    /// The explicit `confederation_id` wins when set; otherwise the first
    /// member is used (BIRD-compatible default).
    pub fn external_as(&self) -> Option<u32> {
        self.confederation_id
            .or_else(|| self.members.first().copied())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn membership_check() {
        let c = ConfederationConfig::new(vec![64512, 64513, 64514]);
        assert!(c.contains(64513));
        assert!(!c.contains(65500));
        // No explicit identifier: the first member is the external AS.
        assert_eq!(c.external_as(), Some(64512));
    }

    /// RFC 5065 §4: the confederation identifier is the ASN a member
    /// announces to non-members, distinct from any Member-AS.
    #[test]
    fn explicit_confederation_id_wins() {
        let c = ConfederationConfig::with_id(vec![64512, 64513, 64514], 200);
        assert_eq!(c.external_as(), Some(200));
        assert!(c.contains(64513));
    }
}
