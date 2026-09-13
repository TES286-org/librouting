//! Route Origin Authorization (ROA) database and RFC 6811 prefix-origin
//! validation.
//!
//! A ROA is a cryptographically signed statement that "AS X is authorized
//! to originate prefix P, and the longest allowed sub-prefix of P is
//! `max_length` bits long". RFC 6482 §3 defines the structure; RFC 6811
//! §2 defines the validation algorithm applied here.
//!
//! # Validation algorithm (RFC 6811 §2)
//!
//! Given a route `(prefix, origin_as)`:
//!
//! 1. Select every ROA whose `prefix` covers the route's prefix and
//!    whose `max_length >= route.prefix_len`.
//! 2. If no ROA matches, the route is `NotFound` (no PVS data).
//! 3. If at least one matching ROA's `asn == origin_as`, the route is
//!    `Valid`.
//! 4. Otherwise the route is `Invalid` (origin AS not authorized, or
//!    the prefix length exceeds the authorized max length).
//!
//! The database is a flat `Vec<RoaEntry>` — lookup is `O(n)` but the
//! access pattern is cache-friendly and the typical operator-side ROA
//! count is in the low thousands, well under a millisecond per check
//! on commodity hardware. A radix-trie index is future work; the
//! `validate` API stays the same when one is added.
//!
//! # Thread safety
//!
//! `RoaTable` is `Send + Sync` — `RoaEntry` is `Copy` and the
//! backing `Vec` is read-only after construction.

use core::str::FromStr;

use lr_core::addr::{Asn, Prefix};

/// One ROA entry: the authorized prefix, the longest prefix length
/// the origin AS may announce, and the origin AS itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RoaEntry {
    /// Authorized prefix (RFC 6482 §3.1).
    pub prefix: Prefix,
    /// Maximum authorized prefix length. `max_length >= prefix.prefix_len`
    /// and bounded by the address family width (32 for v4, 128 for v6).
    /// When equal to `prefix.prefix_len` only the exact prefix is
    /// authorized.
    pub max_length: u8,
    /// Authorized origin AS (RFC 6482 §3.2). AS 0 marks a ROA for the
    /// "blackhole" range (RFC 6483 §4); it does not match any real AS.
    pub asn: Asn,
}

impl RoaEntry {
    /// Build a ROA entry with `max_length = prefix.prefix_len` (only
    /// the exact prefix is authorized — the common /24 case).
    pub fn exact(prefix: Prefix, asn: Asn) -> Self {
        let max_length = prefix.prefix_len;
        Self {
            prefix,
            max_length,
            asn,
        }
    }

    /// Build a ROA entry with an explicit `max_length`. The constructor
    /// enforces `max_length >= prefix.prefix_len` (RFC 6482 §3.3 — a
    /// ROA with `maxLength < prefix length` is malformed and never
    /// matches; we treat that as a build error here).
    pub fn with_max_length(prefix: Prefix, max_length: u8, asn: Asn) -> Result<Self, RoaError> {
        let family_max = if prefix.is_ipv4() { 32 } else { 128 };
        if max_length < prefix.prefix_len {
            return Err(RoaError::MaxLengthBelowPrefix {
                prefix_len: prefix.prefix_len,
                max_length,
            });
        }
        if max_length > family_max {
            return Err(RoaError::MaxLengthAboveFamily {
                max_length,
                family_max,
            });
        }
        Ok(Self {
            prefix,
            max_length,
            asn,
        })
    }
}

/// Validation outcome per RFC 6811 §2: `Valid`, `NotFound`, `Invalid`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RoaState {
    /// At least one ROA matches `(prefix, origin_as)` and authorizes it.
    Valid,
    /// No ROA covers the prefix — PVS has no opinion.
    NotFound,
    /// Some ROA covers the prefix but none authorizes `(prefix, origin_as)`,
    /// or the route's prefix length exceeds every matching ROA's
    /// `max_length`.
    Invalid,
}

impl RoaState {
    /// Lowercase RFC 6811 name (`valid`, `not-found`, `invalid`) — used by
    /// the filter DSL (`roa.state == "valid"`) and operational output.
    pub fn as_str(self) -> &'static str {
        match self {
            RoaState::Valid => "valid",
            RoaState::NotFound => "not-found",
            RoaState::Invalid => "invalid",
        }
    }

    /// Same as [`as_str`] but with the BIRD `roa_check` casing
    /// (`RTE_VALID`, `RTE_UNKNOWN`, `RTE_INVALID`) — used in interop
    /// diagnostic strings to match BIRD's `show route` output.
    pub fn as_bird_str(self) -> &'static str {
        match self {
            RoaState::Valid => "RTE_VALID",
            RoaState::NotFound => "RTE_UNKNOWN",
            RoaState::Invalid => "RTE_INVALID",
        }
    }
}

/// Error variants for ROA construction. None of these are recoverable —
/// they always mean a malformed configuration that the daemon should
/// reject at startup (`fail closed`).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RoaError {
    #[error("max_length {max_length} < prefix length {prefix_len} (RFC 6482 §3.3)")]
    MaxLengthBelowPrefix {
        prefix_len: u8,
        max_length: u8,
    },
    #[error("max_length {max_length} exceeds the family width {family_max}")]
    MaxLengthAboveFamily {
        max_length: u8,
        family_max: u8,
    },
}

/// ROA database: an immutable vector of [`RoaEntry`].
///
/// Constructed via [`RoaTableBuilder`] (which enforces the RFC 6482
/// invariants per entry) and queried via [`validate`]. Lookups are
/// `O(n)` — a future radix-trie index can drop them to `O(log n)`
/// without touching the public API.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RoaTable {
    entries: Vec<RoaEntry>,
}

impl RoaTable {
    /// Empty table — every validation returns `NotFound`.
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of ROA entries stored.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// True when no ROA entries are stored.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Read-only access to the entries — used by tooling that wants
    /// to dump the table (e.g. `lr roa list`).
    pub fn entries(&self) -> &[RoaEntry] {
        &self.entries
    }

    /// Append one entry. Mutating access is package-private to the
    /// `lr-bgp` crate; embedders go through [`RoaTableBuilder`] which
    /// enforces the RFC 6482 invariants at insert time.
    pub(crate) fn push(&mut self, entry: RoaEntry) {
        self.entries.push(entry);
    }

    /// Validate `(prefix, origin_as)` per RFC 6811 §2. A `None`
    /// `origin_as` (no AS_PATH, e.g. locally originated routes)
    /// returns `NotFound` — a route without an origin AS is not
    /// covered by any ROA.
    pub fn validate(&self, prefix: &Prefix, origin_as: Option<Asn>) -> RoaState {
        let Some(origin_as) = origin_as else {
            return RoaState::NotFound;
        };
        let mut any_covered = false;
        for entry in &self.entries {
            // Same address family and entry.prefix covers the route.
            if entry.prefix.addr.is_ipv4() != prefix.addr.is_ipv4() {
                continue;
            }
            if !entry.prefix.contains_prefix(prefix) {
                continue;
            }
            // The route's prefix length must be ≤ entry.max_length.
            if prefix.prefix_len > entry.max_length {
                // Covered by a more specific ROA but too long — still
                // counts as "covered" for the Invalid/NotFound
                // decision: another ROA might authorize this exact
                // (prefix, asn) pair.
                any_covered = true;
                continue;
            }
            any_covered = true;
            if entry.asn == origin_as {
                return RoaState::Valid;
            }
        }
        if any_covered {
            RoaState::Invalid
        } else {
            RoaState::NotFound
        }
    }
}

/// Builder for [`RoaTable`] that enforces the RFC 6482 invariants at
/// insertion time (max_length ≥ prefix length, max_length ≤ family
/// width, well-formed prefix). Failures are surfaced immediately so
/// the daemon can fail-closed at startup.
#[derive(Debug, Default)]
pub struct RoaTableBuilder {
    table: RoaTable,
}

impl RoaTableBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    /// Add one ROA, parsing the prefix and validating the max_length
    /// invariant. Returns the entry on success for the caller's
    /// convenience (mostly useful for tests).
    pub fn add(
        &mut self,
        prefix: &str,
        max_length: Option<u8>,
        asn: u32,
    ) -> Result<RoaEntry, RoaBuildError> {
        let prefix = Prefix::from_str(prefix)
            .map_err(|e| RoaBuildError::BadPrefix(format!("bad prefix '{prefix}': {e}")))?;
        let asn = Asn(asn);
        let entry = match max_length {
            Some(ml) => RoaEntry::with_max_length(prefix, ml, asn)
                .map_err(RoaBuildError::Invalid)?,
            None => RoaEntry::exact(prefix, asn),
        };
        self.table.push(entry);
        Ok(entry)
    }

    /// Add one already-constructed entry (used by the FFI layer when
    /// the caller passes parsed values).
    pub fn add_entry(&mut self, entry: RoaEntry) {
        self.table.push(entry);
    }

    /// Finalize into an immutable [`RoaTable`].
    pub fn build(self) -> RoaTable {
        self.table
    }
}

/// Build-time error: malformed ROA configuration. Surfaced by the
/// daemon config parser and the FFI layer; always a startup error.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RoaBuildError {
    #[error("bad prefix: {0}")]
    BadPrefix(String),
    #[error("{0}")]
    Invalid(#[from] RoaError),
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p4(octets: [u8; 4], len: u8) -> Prefix {
        Prefix::new_v4(octets, len)
    }

    #[test]
    fn exact_roa_matches_origin() {
        let mut b = RoaTableBuilder::new();
        b.add("203.0.113.0/24", None, 64512).unwrap();
        let t = b.build();
        assert_eq!(
            t.validate(&p4([203, 0, 113, 0], 24), Some(Asn(64512))),
            RoaState::Valid
        );
    }

    #[test]
    fn exact_roa_rejects_wrong_origin() {
        let mut b = RoaTableBuilder::new();
        b.add("203.0.113.0/24", None, 64512).unwrap();
        let t = b.build();
        assert_eq!(
            t.validate(&p4([203, 0, 113, 0], 24), Some(Asn(64513))),
            RoaState::Invalid
        );
    }

    #[test]
    fn max_length_authorizes_more_specific() {
        let mut b = RoaTableBuilder::new();
        b.add("203.0.113.0/24", Some(26), 64512).unwrap();
        let t = b.build();
        // /25 — authorized (≤ max_length 26)
        assert_eq!(
            t.validate(&p4([203, 0, 113, 128], 25), Some(Asn(64512))),
            RoaState::Valid
        );
        // /27 — too specific (> max_length 26)
        assert_eq!(
            t.validate(&p4([203, 0, 113, 0], 27), Some(Asn(64512))),
            RoaState::Invalid
        );
    }

    #[test]
    fn no_roa_returns_not_found() {
        let t = RoaTable::new();
        assert_eq!(
            t.validate(&p4([203, 0, 113, 0], 24), Some(Asn(64512))),
            RoaState::NotFound
        );
    }

    #[test]
    fn local_origin_no_origin_as_returns_not_found() {
        // Routes with no AS_PATH have no origin AS — RFC 6811 §2 says
        // no ROA covers them.
        let mut b = RoaTableBuilder::new();
        b.add("203.0.113.0/24", None, 64512).unwrap();
        let t = b.build();
        assert_eq!(
            t.validate(&p4([203, 0, 113, 0], 24), None),
            RoaState::NotFound
        );
    }

    #[test]
    fn family_mismatch_is_skipped() {
        let mut b = RoaTableBuilder::new();
        b.add("203.0.113.0/24", None, 64512).unwrap();
        let t = b.build();
        let v6 = Prefix::new_v6([0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1], 64);
        assert_eq!(t.validate(&v6, Some(Asn(64512))), RoaState::NotFound);
    }

    #[test]
    fn ipv6_roa_matches() {
        let mut b = RoaTableBuilder::new();
        b.add("2001:db8::/32", Some(48), 64512).unwrap();
        let t = b.build();
        let covered = Prefix::new_v6(
            [0x20, 0x01, 0x0d, 0xb8, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
            40,
        );
        assert_eq!(t.validate(&covered, Some(Asn(64512))), RoaState::Valid);
        // Same prefix, wrong origin → Invalid (covered, not authorized)
        assert_eq!(t.validate(&covered, Some(Asn(64513))), RoaState::Invalid);
    }

    #[test]
    fn max_length_below_prefix_is_rejected() {
        let mut b = RoaTableBuilder::new();
        let err = b.add("203.0.113.0/24", Some(23), 64512).unwrap_err();
        assert!(matches!(
            err,
            RoaBuildError::Invalid(RoaError::MaxLengthBelowPrefix { .. })
        ));
    }

    #[test]
    fn max_length_above_family_is_rejected() {
        let mut b = RoaTableBuilder::new();
        let err = b.add("203.0.113.0/24", Some(33), 64512).unwrap_err();
        assert!(matches!(
            err,
            RoaBuildError::Invalid(RoaError::MaxLengthAboveFamily { .. })
        ));
    }

    #[test]
    fn multiple_roas_match_wins() {
        // Two ROAs cover 203.0.113.0/24: AS 64512 (exact) and
        // AS 64513 (max_length 26). A route from AS 64512 should be
        // Valid — one matches even though the other would reject.
        let mut b = RoaTableBuilder::new();
        b.add("203.0.113.0/24", None, 64512).unwrap();
        b.add("203.0.113.0/24", Some(26), 64513).unwrap();
        let t = b.build();
        assert_eq!(
            t.validate(&p4([203, 0, 113, 0], 24), Some(Asn(64512))),
            RoaState::Valid
        );
        // A third AS not in either ROA — Invalid.
        assert_eq!(
            t.validate(&p4([203, 0, 113, 0], 24), Some(Asn(64514))),
            RoaState::Invalid
        );
    }

    #[test]
    fn state_strings_match_rfc_6811() {
        assert_eq!(RoaState::Valid.as_str(), "valid");
        assert_eq!(RoaState::NotFound.as_str(), "not-found");
        assert_eq!(RoaState::Invalid.as_str(), "invalid");
    }

    #[test]
    fn bird_state_strings() {
        // BIRD's `show route` casing (interop diagnostics).
        assert_eq!(RoaState::Valid.as_bird_str(), "RTE_VALID");
        assert_eq!(RoaState::NotFound.as_bird_str(), "RTE_UNKNOWN");
        assert_eq!(RoaState::Invalid.as_bird_str(), "RTE_INVALID");
    }
}
