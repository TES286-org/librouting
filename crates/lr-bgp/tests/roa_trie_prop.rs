//! Property-based tests for the ROA validation path (ROADMAP-v3
//! D8.4) — differential checks of the Patricia-trie-backed
//! `RoaTable::validate` against a straightforward reference model of
//! RFC 6811 §2.
//!
//! The trie replaced the original `O(n)` linear scan with an
//! `O(prefix_len)` walk over a path-compressed prefix trie. The
//! reference model below *is* the original linear scan: for random
//! entry sets (nested prefixes, duplicate prefixes, malformed
//! `max_length < prefix_len` entries, mixed families) and random
//! query prefixes, both implementations must agree on `Valid` /
//! `NotFound` / `Invalid` for every origin AS. Divergence means the
//! trie walk mis-classifies a covering relationship, which the unit
//! tests can only spot-check.
//!
//! A second property pins determinism: the same entry set presented
//! in a different order must produce an equal table (sorted canonical
//! entry list) with identical validation results.
//!
//! `proptest` shrinks failing cases automatically; the default 256
//! cases per property is enough to surface off-by-one errors in the
//! bit-masking and segment-splitting code paths.

#![cfg(test)]

use lr_bgp::roa::{RoaEntry, RoaState, RoaTable};
use lr_core::addr::{Asn, Prefix};
use proptest::prelude::*;

/// Strategy: an arbitrary IPv4 prefix. Address bytes are random and
/// host bits are NOT pre-zeroed — the trie must normalize them, and
/// the reference model tolerates them by construction.
fn any_v4_prefix() -> impl Strategy<Value = Prefix> {
    (any::<[u8; 4]>(), 0u8..=32).prop_map(|(addr, pl)| Prefix::new_v4(addr, pl))
}

/// Strategy: an arbitrary IPv6 prefix (same shape as v4).
fn any_v6_prefix() -> impl Strategy<Value = Prefix> {
    (any::<[u8; 16]>(), 0u8..=128).prop_map(|(addr, pl)| Prefix::new_v6(addr, pl))
}

/// Strategy: an arbitrary ROA entry. `max_length` is deliberately
/// unbounded (including values below the prefix length) — malformed
/// entries can appear via `RoaEntry`'s public fields and both
/// implementations must treat them identically (covered, never
/// authorizing).
fn any_entry() -> impl Strategy<Value = RoaEntry> {
    prop_oneof![any_v4_prefix(), any_v6_prefix()].prop_flat_map(|prefix| {
        (0u8..=128u8, any::<u32>()).prop_map(move |(max_length, asn)| RoaEntry {
            prefix,
            max_length,
            asn: Asn(asn),
        })
    })
}

/// Strategy: an arbitrary query prefix of either family.
fn any_query() -> impl Strategy<Value = Prefix> {
    prop_oneof![any_v4_prefix(), any_v6_prefix()]
}

/// A small entry set plus a small probe battery, generated together
/// so probes and entries land in the same family mix.
#[derive(Debug, Clone)]
struct Case {
    entries: Vec<RoaEntry>,
    probes: Vec<Prefix>,
    origins: Vec<Option<Asn>>,
}

fn any_case() -> impl Strategy<Value = Case> {
    (
        proptest::collection::vec(any_entry(), 0..=12),
        proptest::collection::vec(any_query(), 1..=8),
        proptest::collection::vec(any::<u32>(), 1..=3),
    )
        .prop_map(|(entries, probes, raw_asns)| {
            let mut origins: Vec<Option<Asn>> = raw_asns.iter().map(|a| Some(Asn(*a))).collect();
            origins.push(None);
            Case {
                entries,
                probes,
                origins,
            }
        })
}

/// The pre-trie linear scan, kept as the reference model of RFC 6811
/// §2 — identical to the implementation this trie replaced.
fn reference_validate(entries: &[RoaEntry], prefix: &Prefix, origin_as: Option<Asn>) -> RoaState {
    let Some(origin_as) = origin_as else {
        return RoaState::NotFound;
    };
    let mut any_covered = false;
    for entry in entries {
        if entry.prefix.addr.is_ipv4() != prefix.addr.is_ipv4() {
            continue;
        }
        if !entry.prefix.contains_prefix(prefix) {
            continue;
        }
        any_covered = true;
        if prefix.prefix_len <= entry.max_length && entry.asn == origin_as {
            return RoaState::Valid;
        }
    }
    if any_covered {
        RoaState::Invalid
    } else {
        RoaState::NotFound
    }
}

proptest! {
    /// The trie-backed `RoaTable::validate` must agree with the
    /// linear-scan reference model on every (probe, origin) pair for
    /// every generated entry set.
    #[test]
    fn trie_validate_matches_reference(case in any_case()) {
        let table = RoaTable::from_entries(case.entries.iter().copied());
        for probe in &case.probes {
            for origin in &case.origins {
                let got = table.validate(probe, *origin);
                let expected = reference_validate(&case.entries, probe, *origin);
                prop_assert_eq!(got, expected);
            }
        }
    }

    /// The same entry set in a different order must produce an equal
    /// table (canonical sorted entry list) with identical validation
    /// results — the RTR snapshot path depends on this.
    #[test]
    fn table_is_order_independent(case in any_case()) {
        let forward = RoaTable::from_entries(case.entries.iter().copied());
        let mut reversed = case.entries.clone();
        reversed.reverse();
        let backward = RoaTable::from_entries(reversed);
        prop_assert_eq!(&forward, &backward);
        for probe in &case.probes {
            for origin in &case.origins {
                prop_assert_eq!(
                    forward.validate(probe, *origin),
                    backward.validate(probe, *origin)
                );
            }
        }
    }

    /// The builder path and `from_entries` must agree on validation
    /// outcomes for the same entry multiset (both deduplicate and
    /// sort at build time).
    #[test]
    fn builder_and_from_entries_agree(case in any_case()) {
        let mut builder = lr_bgp::roa::RoaTableBuilder::new();
        for entry in &case.entries {
            builder.add_entry(*entry);
        }
        let built = builder.build();
        let direct = RoaTable::from_entries(case.entries.iter().copied());
        prop_assert_eq!(&built, &direct);
        for probe in &case.probes {
            for origin in &case.origins {
                prop_assert_eq!(
                    built.validate(probe, *origin),
                    direct.validate(probe, *origin)
                );
            }
        }
    }
}
