use super::*;
use crate::roa::RoaState;
use core::str::FromStr;
use lr_core::addr::Asn;

/// The RFC 6811 decision procedure from the pre-trie linear scan,
/// kept here as the reference model for differential testing.
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

/// Build a trie-backed table mirror and compare `validate` with
/// the reference scan over a probe battery.
fn assert_trie_matches(entries: &[RoaEntry], probes: &[Prefix], origin: Option<Asn>) {
    let trie = RoaTrie::build(entries);
    for probe in probes {
        let (any, matched) = trie.walk_covering(entries, probe, &mut |e: &RoaEntry| {
            origin == Some(e.asn) && probe.prefix_len <= e.max_length
        });
        let expected = reference_validate(entries, probe, origin);
        let got = if matched {
            RoaState::Valid
        } else if any {
            RoaState::Invalid
        } else {
            RoaState::NotFound
        };
        assert_eq!(
            got,
            expected,
            "trie mismatch for {probe:?} over {} entries",
            entries.len()
        );
    }
}

fn p4(s: &str) -> Prefix {
    Prefix::from_str(s).unwrap()
}

fn p6(s: &str) -> Prefix {
    Prefix::from_str(s).unwrap()
}

fn entry(prefix: Prefix, max: u8, asn: u32) -> RoaEntry {
    RoaEntry {
        prefix,
        max_length: max,
        asn: Asn(asn),
    }
}

#[test]
fn empty_trie_walks_to_not_covered() {
    let trie = RoaTrie::new();
    let (any, matched) = trie.walk_covering(&[], &p4("203.0.113.0/24"), &mut |_| true);
    assert_eq!((any, matched), (false, false));
}

#[test]
fn single_entry_exact_and_off_path() {
    let entries = [entry(p4("203.0.113.0/24"), 24, 64512)];
    let trie = RoaTrie::build(&entries);
    let probe = p4("203.0.113.0/24");
    let (any, matched) =
        trie.walk_covering(&entries, &probe, &mut |e: &RoaEntry| e.asn == Asn(64512));
    assert_eq!((any, matched), (true, true));
    // Sibling /24 off the trie path: no covering node is reached.
    let probe = p4("203.0.114.0/24");
    let (any, matched) =
        trie.walk_covering(&entries, &probe, &mut |e: &RoaEntry| e.asn == Asn(64512));
    assert_eq!((any, matched), (false, false));
}

#[test]
fn covering_chain_walks_every_ancestor() {
    // A full covering chain: /8 ⊃ /16 ⊃ /24. A /24 query must see
    // all three nodes; each level flips the verdict.
    let entries = [
        entry(p4("10.0.0.0/8"), 24, 64512),
        entry(p4("10.1.0.0/16"), 24, 64513),
        entry(p4("10.1.1.0/24"), 24, 64514),
    ];
    let probes = [
        p4("10.1.1.0/24"),
        p4("10.1.2.0/24"),
        p4("10.2.0.0/16"),
        p4("11.0.0.0/8"),
    ];
    let origins = [Asn(64512), Asn(64513), Asn(64514), Asn(64515)];
    for origin in origins {
        assert_trie_matches(&entries, &probes, Some(origin));
    }
}

#[test]
fn key_exhausted_inside_segment_is_ancestor() {
    // Insert deep first, then walk up: the /16 and /8 must splice
    // in above the /24, and a /20 query must still be covered by
    // the /16 (walk ends mid-segment of nothing — the /16 node is
    // exact) while /12 is covered by the /8 (walk ends inside the
    // /16's segment → break, no false covering from the /16).
    let entries = [
        entry(p4("10.1.1.0/24"), 24, 64512),
        entry(p4("10.1.0.0/16"), 20, 64513),
        entry(p4("10.0.0.0/8"), 12, 64514),
    ];
    let probes = [
        p4("10.1.1.0/24"), // covered by all three
        p4("10.1.2.0/24"), // covered by /16 and /8, not the /24
        p4("10.1.0.0/20"), // exact /16 hit
        p4("10.1.0.0/19"), // wait: /19 is NOT covered by a /16 ROA...
    ];
    // /19 query: covered by /8 (10.0.0.0/8 ⊇ 10.1.0.0/19); the
    // /16 does NOT cover a /19 (16 > 19 is false — actually
    // prefix_len 19 > 16 means the /16 does not contain it at
    // all). Covered only by the /8.
    let origins = [Asn(64512), Asn(64513), Asn(64514), Asn(64599)];
    for origin in origins {
        assert_trie_matches(&entries, &probes, Some(origin));
    }
}

#[test]
fn route_ending_inside_segment_does_not_cover() {
    // Only a /32 exists. A /28 route sharing its first 28 bits
    // must NOT be covered (the ROA is more specific than the
    // route) — the walk must break inside the /32's segment.
    let entries = [entry(p4("10.1.1.16/32"), 32, 64512)];
    let probes = [p4("10.1.1.16/28"), p4("10.1.1.17/32"), p4("10.1.1.16/32")];
    assert_trie_matches(&entries, &probes, Some(Asn(64512)));
}

#[test]
fn same_prefix_multiple_entries_share_node() {
    // Three ROAs on one prefix — a Valid origin among Invalid
    // ones must still win (any-match semantics).
    let entries = [
        entry(p4("203.0.113.0/24"), 24, 64512),
        entry(p4("203.0.113.0/24"), 26, 64513),
        entry(p4("203.0.113.0/24"), 24, 64514),
    ];
    let probes = [p4("203.0.113.0/24"), p4("203.0.113.128/25")];
    for origin in [Asn(64512), Asn(64513), Asn(64514), Asn(64515)] {
        assert_trie_matches(&entries, &probes, Some(origin));
    }
}

#[test]
fn host_bits_are_normalized() {
    // Entries and queries with host bits set must behave exactly
    // like their normalized forms.
    let mut host_bits = p4("203.0.113.5/24");
    host_bits.addr = lr_core::addr::IpAddr::V4([203, 0, 113, 5]);
    let entries = [entry(host_bits, 24, 64512)];
    let probe = p4("203.0.113.0/24");
    assert_trie_matches(&entries, &[probe], Some(Asn(64512)));
    assert_trie_matches(&entries, &[probe], Some(Asn(64599)));
}

#[test]
fn default_route_roa_covers_everything() {
    let entries = [entry(p4("0.0.0.0/0"), 8, 64512)];
    let probes = [
        p4("10.0.0.0/8"),
        p4("10.1.2.0/24"),
        p4("192.0.2.1/32"),
        p4("0.0.0.0/0"),
    ];
    // /8 and shorter are Valid; anything longer than max_length 8
    // is Invalid (covered but too specific).
    assert_trie_matches(&entries, &probes, Some(Asn(64512)));
    assert_trie_matches(&entries, &probes, Some(Asn(64599)));
}

#[test]
fn families_are_isolated() {
    let entries = [
        entry(p4("203.0.113.0/24"), 24, 64512),
        entry(p6("2001:db8::/32"), 48, 64513),
    ];
    let probes = [
        p4("203.0.113.0/24"),
        p4("198.51.100.0/24"),
        p6("2001:db8::/32"),
        p6("2001:db8:1::/48"),
        p6("2001:db9::/32"),
    ];
    for origin in [Asn(64512), Asn(64513), Asn(64599)] {
        assert_trie_matches(&entries, &probes, Some(origin));
    }
}

#[test]
fn deep_unary_chain_path_compression() {
    // Two entries sharing 24 high bits with nothing in between:
    // the intermediate structure must not lose the branch. A
    // probe matching NEITHER must walk out cleanly.
    let entries = [
        entry(p4("10.0.0.0/8"), 8, 64512),
        entry(p4("10.0.0.128/32"), 32, 64513),
    ];
    let probes = [
        p4("10.0.0.64/32"),  // diverges inside the /32's segment
        p4("10.0.0.128/32"), // exact hit
        p4("10.0.0.0/8"),    // exact hit at the shallow node
        p4("10.0.0.0/16"),   // covered by the /8 only
        p4("11.0.0.0/8"),    // unrelated
    ];
    for origin in [Asn(64512), Asn(64513), Asn(64599)] {
        assert_trie_matches(&entries, &probes, Some(origin));
    }
}

#[test]
fn ipv6_full_depth_chain() {
    let entries = [
        entry(p6("2001:db8::/32"), 48, 64512),
        entry(p6("2001:db8:a::/48"), 64, 64513),
        entry(p6("2001:db8:a::/64"), 128, 64514),
    ];
    let probes = [
        p6("2001:db8:a::/64"),
        p6("2001:db8:a:1::/64"),
        p6("2001:db8:b::/48"),
        p6("2001:db8:a::1/128"),
        p6("2001:db9::/32"),
    ];
    for origin in [Asn(64512), Asn(64513), Asn(64514), Asn(64599)] {
        assert_trie_matches(&entries, &probes, Some(origin));
    }
}

#[test]
fn insertion_order_does_not_change_results() {
    // Same entry set, several orders: every probe must get the
    // same verdict from every build.
    let base = [
        entry(p4("10.0.0.0/8"), 16, 64512),
        entry(p4("10.1.0.0/16"), 24, 64513),
        entry(p4("10.1.1.0/24"), 24, 64514),
        entry(p4("10.2.0.0/16"), 20, 64515),
        entry(p6("2001:db8::/32"), 48, 64516),
    ];
    let orders: Vec<Vec<RoaEntry>> = vec![
        base.to_vec(),
        base.iter().rev().copied().collect(),
        [base[2], base[0], base[4], base[1], base[3]].to_vec(),
    ];
    let probes = [
        p4("10.1.1.0/24"),
        p4("10.1.9.0/24"),
        p4("10.2.1.0/20"),
        p4("10.3.0.0/16"),
        p4("10.0.0.0/8"),
        p6("2001:db8:1::/48"),
        p6("2001:db8:1::/64"),
    ];
    for origin in [
        Asn(64512),
        Asn(64513),
        Asn(64514),
        Asn(64515),
        Asn(64516),
        Asn(64599),
    ] {
        for order in &orders {
            assert_trie_matches(order, &probes, Some(origin));
        }
    }
}

#[test]
fn malformed_lengths_are_clamped_for_walk() {
    // A prefix_len above the family width cannot appear in real
    // tables, but `RoaEntry` has public fields — the trie must
    // clamp for its own bookkeeping while `validate` keeps the
    // raw length for the max_length comparison.
    let long = Prefix {
        addr: lr_core::addr::IpAddr::V4([10, 0, 0, 1]),
        prefix_len: 33,
    };
    let entries = [entry(p4("10.0.0.0/8"), 8, 64512)];
    // Walk must not panic; max_length 8 < 33 → Invalid.
    assert_trie_matches(&entries, &[long], Some(Asn(64512)));
}
