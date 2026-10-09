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
#[path = "roa_trie_tests.rs"]
mod tests;
