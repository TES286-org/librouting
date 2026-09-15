//! Path-compressed (Patricia) prefix trie indexing ROA entries for
//! RFC 6811 validation (ROADMAP-v3 D8.4).
//!
//! [`crate::roa::RoaTable`] keeps its entries in a flat, sorted
//! `Vec<RoaEntry>` (the canonical store used by dumps and equality);
//! this module provides the lookup index that turns the `O(n)`
//! validation scan into an `O(prefix_len)` walk.
//!
//! # Structure
//!
//! Each node owns a *segment*: a run of key bits starting with the
//! branch bit that selected it (the root owns zero bits). The trie is
//! path-compressed — a node's segment spans every bit down to the
//! next branching point, so a chain of `n` ROAs with shared high bits
//! costs `O(n)` nodes, not `O(sum of prefix lengths)`. Nodes live in
//! a flat arena (`Vec<TrieNode>`, `u32` indices) for cache-friendly
//! access and `no_std` compatibility; there are no pointers.
//!
//! A node's *represented prefix* is the bit path from the root to the
//! node: `prefix_len = sum of segment lengths along the path`. Entries
//! whose normalized prefix is exactly that bit path are stored on the
//! node (`entries` holds indices into the table's entry `Vec`), so
//! several ROAs sharing one prefix (e.g. the same /24 with different
//! `max_length`) share a single node.
//!
//! # Covering walk
//!
//! RFC 6811 §2 needs every ROA whose prefix *covers* the route — the
//! ROA prefix must be a bit-prefix of the route prefix. Those are
//! exactly the trie nodes on the root-to-route path, so `validate`
//! walks down following the route's bits and consults each node it
//! fully matches. The walk stops at the first divergence, at the
//! first node longer than the route, or when the route is exhausted:
//! nothing below those points can cover the route. Depth is bounded
//! by the address-family width (32 / 128), giving `O(prefix_len)`
//! lookups versus the previous `O(n)` scan over the whole table.
//!
//! # Key encoding
//!
//! Prefixes are normalized (`host bits zeroed`) and encoded as
//! high-aligned `u128` keys: bit *i* of the key is bit *i* of the
//! address. IPv4 keys are shifted left by 96 bits so both families
//! share one bit-indexing scheme; each family has its own root, so
//! cross-family entries never interact. A malformed prefix length
//! above the family width is clamped for trie purposes (the RFC 6811
//! `max_length` comparison still uses the caller's raw length).

use lr_core::addr::{IpAddr, Prefix};

use crate::roa::RoaEntry;

/// A trie node: one path-compressed segment plus its entries.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct TrieNode {
    /// Segment key bits, high-aligned: bit 0 of the segment is the
    /// MSB of this value, and doubles as the parent's branch selector.
    /// Meaningless when `skip == 0` (kept zeroed for determinism).
    segment: u128,
    /// Segment length in bits (0 for a family root).
    skip: u8,
    /// Indices into the owning [`crate::roa::RoaTable`] entry list for
    /// ROAs whose normalized prefix terminates exactly at this node.
    entries: Vec<u32>,
    /// Children keyed by the next key bit after this node's prefix.
    children: [Option<u32>; 2],
}

/// Prefix trie over ROA entries. See the module documentation for the
/// structure and the covering-walk contract.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct RoaTrie {
    /// Node arena. Node 0 of each family is that family's root.
    nodes: Vec<TrieNode>,
    /// Per-family root node index: `[None; 2]` while empty.
    roots: [Option<u32>; 2],
}

/// Mask with the top `bits` bits set (`bits <= 128`).
fn high_bits_mask(bits: u8) -> u128 {
    if bits == 0 {
        0
    } else {
        u128::MAX << (128 - bits as u32)
    }
}

/// Bit `i` (0-based from the MSB) of a high-aligned key.
fn bit_at(key: u128, i: u8) -> usize {
    ((key << i) >> 127) as usize
}

/// Normalize `prefix` (zero the host bits) and encode it as a
/// high-aligned 128-bit trie key, clamping the length to the family
/// width. Returns `(key, length, family)` where family is 0 for IPv4
/// and 1 for IPv6. Normalization is idempotent, so re-encoding an
/// already-normalized prefix is a no-op.
fn encode_prefix(prefix: &Prefix) -> (u128, u8, usize) {
    match prefix.network() {
        IpAddr::V4(b) => (
            (u32::from_be_bytes(b) as u128) << 96,
            prefix.prefix_len.min(32),
            0,
        ),
        IpAddr::V6(b) => (u128::from_be_bytes(b), prefix.prefix_len.min(128), 1),
    }
}

impl RoaTrie {
    /// Empty trie — no roots, no nodes.
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// Build a trie indexing every entry in `entries` (by position).
    /// Entry prefixes are normalized, so entries that differ only in
    /// host bits share a node. Insertion order does not affect the
    /// walk results.
    pub(crate) fn build(entries: &[RoaEntry]) -> Self {
        let mut trie = Self::new();
        for (idx, entry) in entries.iter().enumerate() {
            let (key, len, family) = encode_prefix(&entry.prefix);
            trie.insert(key, len, family, idx as u32);
        }
        trie
    }

    /// Insert one entry index under the node for `(key, len)`.
    fn insert(&mut self, key: u128, len: u8, family: usize, entry_idx: u32) {
        let Some(root) = self.roots[family] else {
            // First node in this family: it owns the whole key.
            let idx = self.nodes.len() as u32;
            self.nodes.push(TrieNode {
                segment: if len == 0 { 0 } else { key },
                skip: len,
                entries: Vec::from([entry_idx]),
                children: [None, None],
            });
            self.roots[family] = Some(idx);
            return;
        };

        // Where the current node hangs off its parent: either a family
        // root or one child slot of a parent node.
        enum Attach {
            Root(usize),
            Child(u32, usize),
        }

        let mut cur = root;
        let mut pos: u8 = 0;
        let mut attach = Attach::Root(family);
        loop {
            let (seg, skip) = {
                let node = &self.nodes[cur as usize];
                (node.segment, node.skip)
            };
            let remaining = len - pos;
            let cmp = skip.min(remaining);
            let xor = (seg ^ (key << pos)) & high_bits_mask(cmp);
            if xor != 0 {
                // The key and this node diverge `j` bits into the
                // segment: factor the shared prefix into a new branch
                // node and hang both off it. Both operands are
                // high-aligned to the segment start (u128 bit 127 -
                // i is segment index i), and the xor is masked to the
                // compared region — so the first differing index is
                // the leading-zero count of the masked xor.
                let j = xor.leading_zeros() as u8;
                let branch_idx = self.nodes.len() as u32;
                let leaf_idx = branch_idx + 1;
                self.nodes.push(TrieNode {
                    segment: seg & high_bits_mask(j),
                    skip: j,
                    entries: Vec::new(),
                    children: [None, None],
                });
                self.nodes.push(TrieNode {
                    segment: key << (pos + j),
                    skip: remaining - j,
                    entries: Vec::from([entry_idx]),
                    children: [None, None],
                });
                // Shrink the old node's segment: it keeps everything
                // after the divergence point.
                let old_bit = bit_at(seg, j);
                let old = &mut self.nodes[cur as usize];
                old.segment = seg << j;
                old.skip = skip - j;
                self.nodes[branch_idx as usize].children[old_bit] = Some(cur);
                self.nodes[branch_idx as usize].children[1 - old_bit] = Some(leaf_idx);
                match attach {
                    Attach::Root(f) => self.roots[f] = Some(branch_idx),
                    Attach::Child(parent, slot) => {
                        self.nodes[parent as usize].children[slot] = Some(branch_idx)
                    }
                }
                return;
            }
            if remaining < skip {
                // The key is a strict ancestor of this node: splice a
                // new node for it above.
                let new_idx = self.nodes.len() as u32;
                let old_bit = bit_at(seg, remaining);
                self.nodes.push(TrieNode {
                    segment: if remaining == 0 { 0 } else { key << pos },
                    skip: remaining,
                    entries: Vec::from([entry_idx]),
                    children: [None, None],
                });
                let old = &mut self.nodes[cur as usize];
                old.segment = seg << remaining;
                old.skip = skip - remaining;
                self.nodes[new_idx as usize].children[old_bit] = Some(cur);
                match attach {
                    Attach::Root(f) => self.roots[f] = Some(new_idx),
                    Attach::Child(parent, slot) => {
                        self.nodes[parent as usize].children[slot] = Some(new_idx)
                    }
                }
                return;
            }
            if remaining == skip {
                // The key terminates exactly at this node.
                self.nodes[cur as usize].entries.push(entry_idx);
                return;
            }
            // Full segment match with key bits to spare: descend.
            let slot = bit_at(key, pos + skip);
            match self.nodes[cur as usize].children[slot] {
                Some(child) => {
                    pos += skip;
                    attach = Attach::Child(cur, slot);
                    cur = child;
                }
                None => {
                    // The leaf owns the key bits after this node's
                    // segment, starting with the selector bit.
                    let idx = self.nodes.len() as u32;
                    self.nodes.push(TrieNode {
                        segment: key << (pos + skip),
                        skip: remaining - skip,
                        entries: Vec::from([entry_idx]),
                        children: [None, None],
                    });
                    self.nodes[cur as usize].children[slot] = Some(idx);
                    return;
                }
            }
        }
    }

    /// Walk the covering path for `prefix` and invoke `f` on every
    /// covered entry (in root-to-node order), stopping early when `f`
    /// returns `true`. Returns whether any covering entry was seen
    /// and whether `f` matched one — exactly the `any_covered` /
    /// `Valid` pair RFC 6811 §2 needs.
    pub(crate) fn walk_covering<'a, F>(
        &self,
        entries: &'a [RoaEntry],
        prefix: &Prefix,
        f: &mut F,
    ) -> (bool, bool)
    where
        F: FnMut(&'a RoaEntry) -> bool,
    {
        let (key, len, family) = encode_prefix(prefix);
        let Some(mut cur) = self.roots[family] else {
            return (false, false);
        };
        let mut pos: u8 = 0;
        let mut any_covered = false;
        loop {
            let (seg, skip, node_entries) = {
                let node = &self.nodes[cur as usize];
                (node.segment, node.skip, &node.entries)
            };
            let remaining = len - pos;
            let cmp = skip.min(remaining);
            // A divergence inside the segment, or the route ending
            // inside it, means this node and everything below it is
            // longer than (or disjoint from) the route: stop.
            let xor = (seg ^ (key << pos)) & high_bits_mask(cmp);
            if xor != 0 || remaining < skip {
                break;
            }
            // This node's prefix is a bit-prefix of the route: every
            // entry here covers the route (prefix_len <= route len).
            if !node_entries.is_empty() {
                any_covered = true;
                for &idx in node_entries {
                    if f(&entries[idx as usize]) {
                        return (true, true);
                    }
                }
            }
            if remaining == skip {
                // Route exhausted exactly at this node — deeper nodes
                // have longer prefixes and cannot cover it.
                break;
            }
            let slot = bit_at(key, pos + skip);
            match self.nodes[cur as usize].children[slot] {
                Some(child) => {
                    pos += skip;
                    cur = child;
                }
                None => break,
            }
        }
        (any_covered, false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::roa::RoaState;
    use core::str::FromStr;
    use lr_core::addr::Asn;

    /// The RFC 6811 decision procedure from the pre-trie linear scan,
    /// kept here as the reference model for differential testing.
    fn reference_validate(
        entries: &[RoaEntry],
        prefix: &Prefix,
        origin_as: Option<Asn>,
    ) -> RoaState {
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
}
