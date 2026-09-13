//! Property-based tests for `lr-policy` (ROADMAP-v3 D6).
//!
//! These tests use `proptest` to assert structural invariants that
//! unit tests can only spot-check one value at a time:
//!
//! 1. `Prefix::contains` is reflexive, antisymmetric under prefix
//!    length, and transitive. Random IPv4 / IPv6 prefixes must
//!    honour the containment lattice the rest of the policy engine
//!    relies on (prefix-list matching, AS-path filter `~` operator,
//!    BGP aggregation, ROA coverage).
//! 2. `Prefix::network` is idempotent and prefix-aligned: applying
//!    it twice yields the same address, and the network bits are
//!    preserved exactly while host bits are zeroed.
//! 3. `PrefixList::evaluate` is order-correct: when a permit matches,
//!    every prefix that prefix permits (per `PrefixListEntry::matches`)
//!    also returns `true` from `evaluate`; when a deny matches, every
//!    permitted prefix also returns `false`. Implicit deny holds for
//!    every prefix that no entry covers.
//! 4. The filter DSL parser never panics on arbitrary input — it
//!    must return `Ok(Filter)` or `Err(ParseError)`. The lexer and
//!    parser are hand-rolled and process untrusted config strings,
//!    so a panic is a security defect, not a test failure.
//!
//! `proptest` shrinks failing cases automatically; the default 256
//! cases per property is enough to surface off-by-one errors in
//! the bit-masking code paths.

#![cfg(test)]

use core::str::FromStr;

use lr_core::addr::Prefix;
use lr_policy::filter::compile;
use lr_policy::prefix_list::{PrefixList, PrefixListEntry};
use proptest::prelude::*;

/// Strategy: an arbitrary IPv4 prefix. Address bytes are random;
/// the prefix length is bounded to 0..=32 since the address-family
/// width is the legal maximum.
fn any_v4_prefix() -> impl Strategy<Value = Prefix> {
    (any::<[u8; 4]>(), 0u8..=32).prop_map(|(addr, pl)| Prefix::new_v4(addr, pl))
}

/// Strategy: an arbitrary IPv6 prefix. Same shape as v4 but with
/// 16 address bytes and a 0..=128 length bound.
fn any_v6_prefix() -> impl Strategy<Value = Prefix> {
    (any::<[u8; 16]>(), 0u8..=128).prop_map(|(addr, pl)| Prefix::new_v6(addr, pl))
}

/// Strategy: a prefix of either family — picks v4 half the time
/// so the test exercises the more common path proportionally.
fn any_prefix() -> impl Strategy<Value = Prefix> {
    prop_oneof![any_v4_prefix(), any_v6_prefix()]
}

proptest! {
    /// `Prefix::contains_prefix` is reflexive — every prefix contains
    /// itself. Trivially true by construction but cheap to assert and
    /// catches a future refactor that swaps the comparison direction.
    #[test]
    fn prefix_contains_self(p in any_prefix()) {
        prop_assert!(p.contains_prefix(&p));
    }

    /// Containment is antisymmetric in the prefix-length axis: if
    /// `a` contains `b` and `a != b` (lengths differ), then `b`
    /// cannot contain `a`. The lattice is total within a family.
    #[test]
    fn prefix_contains_antisymmetric(
        a in any_prefix(),
        b in any_prefix(),
    ) {
        // Cross-family containment is impossible — skip those cases.
        prop_assume!(a.is_ipv4() == b.is_ipv4());
        if a.contains_prefix(&b) && a.prefix_len != b.prefix_len {
            prop_assert!(!b.contains_prefix(&a));
        }
    }

    /// Containment is transitive: if `a` ⊇ `b` and `b` ⊇ `c`, then
    /// `a` ⊇ `c`. The SPF tree, ROA coverage and prefix-list
    /// matching all rely on this property.
    #[test]
    fn prefix_contains_transitive(
        a in any_prefix(),
        b in any_prefix(),
        c in any_prefix(),
    ) {
        // All three must be the same family or the relation is
        // trivially false.
        prop_assume!(a.is_ipv4() == b.is_ipv4() && b.is_ipv4() == c.is_ipv4());
        if a.contains_prefix(&b) && b.contains_prefix(&c) {
            prop_assert!(a.contains_prefix(&c));
        }
    }

    /// `Prefix::network` zeroes the host bits without touching the
    /// network bits. Applied twice, it is a no-op (idempotence).
    #[test]
    fn prefix_network_idempotent(p in any_prefix()) {
        let n1 = p.network();
        let n2 = Prefix { addr: n1, prefix_len: p.prefix_len }.network();
        prop_assert_eq!(n1, n2);
    }

    /// The original prefix always contains its own network form —
    /// zeroing host bits cannot change the prefix bits, so the masked
    /// comparison in `contains` succeeds. This is the invariant the
    /// OSPF/BGP originators rely on: when they install
    /// `prefix.network()` into the RIB, the original `prefix` must
    /// still cover it.
    #[test]
    fn prefix_network_is_contained(p in any_prefix()) {
        let n = p.network();
        prop_assert!(p.contains(&n), "prefix {} does not contain its own network {}",
            p, Prefix { addr: n, prefix_len: p.prefix_len });
    }

    /// Prefix-list `evaluate` agrees with the first-matching entry's
    /// `matches`. Generate a small list of permits/denies plus a
    /// probe prefix, then walk the list the same way `evaluate`
    /// does and assert the verdicts agree.
    #[test]
    fn prefix_list_evaluate_matches_first_entry(
        entries in prop::collection::vec(
            (any_v4_prefix(), any::<bool>()),
            0..8,
        ),
        probe in any_v4_prefix(),
    ) {
        let mut list = PrefixList::new();
        for (prefix, permit) in &entries {
            list.push(PrefixListEntry::new(*prefix, *permit));
        }
        // Manual first-match walk — mirrors `PrefixList::evaluate`
        // but lives outside the crate so a bug in `evaluate` cannot
        // also live in the test oracle.
        let mut expected = false; // implicit deny
        for (prefix, permit) in &entries {
            let mut e = PrefixListEntry::new(*prefix, *permit);
            // Match the entry's default ge/le behaviour
            // (ge = prefix_len, le = 255). `PrefixListEntry::new`
            // already sets those, so this is a no-op, kept for
            // clarity when the field defaults ever change.
            e.ge = e.prefix.prefix_len;
            if e.matches(&probe) {
                expected = *permit;
                break;
            }
        }
        prop_assert_eq!(list.evaluate(&probe), expected);
    }

    /// The DSL parser must not panic on arbitrary input. Garbage
    /// bytes, partial tokens, and valid prefixes mixed with junk
    /// must all return `Ok` or `Err(ParseError)` — never `panic!`.
    /// The lexer is the security boundary between operator config
    /// and the evaluator; a panic here is a defect of the same
    /// severity as a `BgpCodec::decode_slice` panic on the wire.
    #[test]
    fn filter_parser_never_panics(src in ".*") {
        let _ = compile("proptest", &src);
        // No assertion on the result — only that we returned at all.
    }

    /// A filter compiled from a syntactically valid body must
    /// round-trip: compiling the same source twice yields filters
    /// whose AST string form is byte-equal. Catches accidental
    /// state leaks between parses (a `static mut` cache, a stale
    /// cursor, etc.).
    #[test]
    fn filter_compile_is_pure(src in ".*") {
        let f1 = compile("proptest-a", &src);
        let f2 = compile("proptest-b", &src);
        prop_assert_eq!(f1.is_ok(), f2.is_ok());
        if let (Ok(a), Ok(b)) = (f1, f2) {
            // The debug form captures the AST shape, so equality
            // here means the AST is the same tree.
            prop_assert_eq!(format!("{a:?}"), format!("{b:?}"));
        }
    }
}

/// `Prefix::from_str` round-trip property: a prefix parsed from its
/// `Display` form yields the same prefix. Catches format regressions
/// in either direction (the parser is the one path operators use to
/// author policy, so a `Display`/`FromStr` mismatch is operationally
/// visible).
#[test]
fn prefix_display_from_str_roundtrip_examples() {
    let cases = [
        "0.0.0.0/0",
        "10.0.0.0/8",
        "192.168.1.0/24",
        "255.255.255.255/32",
        "::/0",
        "2001:db8::/32",
        "fe80::1/128",
    ];
    for s in cases {
        let p = Prefix::from_str(s).unwrap_or_else(|e| panic!("parse {s:?}: {e}"));
        let back = p.to_string();
        assert_eq!(back, s, "round-trip mismatch for {s}");
    }
}
