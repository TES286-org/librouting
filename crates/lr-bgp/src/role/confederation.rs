//! Confederation configuration (RFC 6793).
//!
//! A confederation is a set of ASNs treated as one AS externally but acting
//! as a sub-AS internally. Routes are exchanged between confederation
//! members using the AS_CONFED_SEQUENCE / AS_CONFED_SET segment types, and
//! the local AS is announced as the confederation's "external" AS to peers
//! outside the confederation.
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
}

impl ConfederationConfig {
    pub fn new(members: Vec<u32>) -> Self {
        Self { members }
    }

    /// True if `asn` is a confederation member.
    pub fn contains(&self, asn: u32) -> bool {
        self.members.contains(&asn)
    }

    /// External AS announced to non-confed peers. Per RFC 3065 §5, this is
    /// the confederation identifier (an ASN reserved at IANA for the
    /// confederation as a whole).
    ///
    /// For simplicity we treat the first member as the external AS; in
    /// practice the confederation identifier is configured explicitly.
    pub fn external_as(&self) -> Option<u32> {
        self.members.first().copied()
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
        assert_eq!(c.external_as(), Some(64512));
    }
}
