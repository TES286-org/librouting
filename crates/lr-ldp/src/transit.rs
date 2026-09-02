//! Transit-LSR label allocation (RFC 5036 §3.5.7.1.1).
//!
//! A pure label-space bookkeeper: it hands out one locally significant
//! label per transit FEC from a configured platform range, keeps the
//! labels stable for the life of the FEC, and reclaims them when the
//! last downstream binding for the FEC disappears.
//!
//! This module carries no protocol state of its own — the engine feeds
//! it (first binding seen → `allocate`, last binding gone → `release`)
//! and reads back the label to advertise upstream and mirror into the
//! dataplane. Everything here is `no_std` (the crate's embedders run on
//! constrained targets too).

use crate::tlv::GenericLabel;
use alloc::collections::{BTreeMap, BTreeSet};
use alloc::vec::Vec;
use lr_core::addr::Prefix;

/// A downstream peer's binding metadata for one FEC, as received in
/// the peer's Label Mapping: the label plus the §A.1.1.2 Hop Count /
/// §A.2.2 Path Vector attributes (both optional on the wire) needed to
/// propagate correct attributes in the re-advertised mapping, and the
/// engine's receive sequence number for reflection detection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerBinding {
    pub label: GenericLabel,
    /// Hop Count TLV as received (`None` = absent → unknown distance).
    pub hop_count: Option<u8>,
    /// Path Vector TLV as received (empty = absent).
    pub path_vector: Vec<u32>,
    /// Engine-local receive order (see `TransitFec`).
    pub received_seq: u64,
}

impl PeerBinding {
    /// Wire-visible equality: label + hop count + path vector, ignoring
    /// the bookkeeping sequence number.
    pub fn same_wire_attrs(&self, other: &PeerBinding) -> bool {
        self.label == other.label
            && self.hop_count == other.hop_count
            && self.path_vector == other.path_vector
    }
}

/// The platform-wide transit label allocator.
///
/// Labels are handed out from `label_min..=label_max` (RFC 3032 §1.2
/// constrains both bounds to 16..=1048575; the enforced validation
/// lives in the daemon config — the allocator clamps defensively).
/// Labels already promised to embedder-configured bindings arrive as
/// `reserved` and are never re-allocated.
#[derive(Debug, Clone)]
pub struct TransitAllocator {
    label_min: u32,
    label_max: u32,
    /// Allocation cursor: the next candidate to try (wraps at max).
    next: u32,
    /// FEC → allocated in-label. One label per FEC for its full
    /// lifetime (§2.3.3 independent control: the allocation does not
    /// depend on the next hop's label).
    allocated: BTreeMap<Prefix, GenericLabel>,
    /// Label values currently handed out (for O(log n) skip checks).
    used: BTreeSet<u32>,
}

impl TransitAllocator {
    /// Build an allocator over `label_min..=label_max` with `reserved`
    /// label values (explicitly configured bindings) excluded. Values
    /// outside the platform-writable 16..=1048575 window are clamped
    /// into it defensively (the daemon config already rejects them).
    pub fn new(label_min: u32, label_max: u32, reserved: &[u32]) -> Self {
        const PLATFORM_MIN: u32 = 16;
        const PLATFORM_MAX: u32 = 1_048_575;
        let label_min = label_min.clamp(PLATFORM_MIN, PLATFORM_MAX);
        let label_max = label_max.clamp(PLATFORM_MIN, PLATFORM_MAX);
        let (label_min, label_max) = if label_min > label_max {
            (label_max, label_min)
        } else {
            (label_min, label_max)
        };
        let reserved: BTreeSet<u32> = reserved
            .iter()
            .copied()
            .filter(|l| (PLATFORM_MIN..=PLATFORM_MAX).contains(l))
            .collect();
        Self {
            label_min,
            label_max,
            next: label_min,
            allocated: BTreeMap::new(),
            used: reserved,
        }
    }

    /// The label allocated for a FEC, when any.
    pub fn label_of(&self, prefix: &Prefix) -> Option<GenericLabel> {
        self.allocated.get(prefix).copied()
    }

    /// Whether `prefix` already holds a transit allocation.
    pub fn is_allocated(&self, prefix: &Prefix) -> bool {
        self.allocated.contains_key(prefix)
    }

    /// Number of FECs currently holding a transit label.
    pub fn allocated_count(&self) -> usize {
        self.allocated.len()
    }

    /// All currently allocated (FEC, label) pairs.
    pub fn allocated_pairs(&self) -> impl Iterator<Item = (&Prefix, &GenericLabel)> {
        self.allocated.iter()
    }

    /// Allocate a label for `prefix`, idempotently: the first call
    /// picks the lowest free value from the cursor onward (wrapping
    /// once at the top of the range) and returns it; later calls return
    /// the same label. `None` = the range is exhausted (or the FEC
    /// collides with a reserved label — callers treat both as "no
    /// transit LSP for this FEC").
    pub fn allocate(&mut self, prefix: Prefix) -> Option<GenericLabel> {
        if let Some(label) = self.allocated.get(&prefix) {
            return Some(*label);
        }
        let label = self.find_free()?;
        self.allocated.insert(prefix, label);
        self.used.insert(label.0);
        Some(label)
    }

    /// Release the label for `prefix` (last downstream binding gone).
    /// Returns the released label, if any.
    pub fn release(&mut self, prefix: &Prefix) -> Option<GenericLabel> {
        let label = self.allocated.remove(prefix)?;
        self.used.remove(&label.0);
        // Rewind the cursor opportunistically so a released label is
        // the first candidate reused (keeps long-running speakers
        // inside a compact range instead of creeping toward max).
        if label.0 < self.next {
            self.next = label.0;
        }
        Some(label)
    }

    /// Find the lowest free label from the cursor onward, wrapping at
    /// most once. The scan walks the `used` set rather than the range
    /// so a sparse usage pattern does not cost a full-range sweep.
    fn find_free(&mut self) -> Option<GenericLabel> {
        let start = self.next;
        let mut cursor = start;
        let mut wrapped = false;
        loop {
            // Past the top of the range: wrap once (a cursor can sit
            // above max after a sweep that ended on a used value).
            if cursor > self.label_max {
                if wrapped || start == self.label_min {
                    return None;
                }
                wrapped = true;
                cursor = self.label_min;
            }
            match self.used.range(cursor..).next() {
                Some(&used) if used == cursor => {
                    cursor += 1;
                }
                // Free at `cursor`: either nothing used above it, or a
                // hole in the used set. In the wrapped phase, values at
                // or above `start` were already scanned before the
                // wrap — only strictly lower holes remain.
                _ => {
                    if wrapped && cursor >= start {
                        return None;
                    }
                    self.next = cursor + 1;
                    return Some(GenericLabel(cursor));
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(octet: u8) -> Prefix {
        Prefix::new_v4([10, 0, 0, octet], 24)
    }

    #[test]
    fn allocates_lowest_free_and_is_idempotent() {
        let mut a = TransitAllocator::new(16, 1048575, &[]);
        let l1 = a.allocate(p(1)).unwrap();
        assert_eq!(l1, GenericLabel(16));
        // Idempotent: the same FEC gets the same label back.
        assert_eq!(a.allocate(p(1)), Some(l1));
        let l2 = a.allocate(p(2)).unwrap();
        assert_eq!(l2, GenericLabel(17));
        assert_eq!(a.allocated_count(), 2);
    }

    #[test]
    fn reserved_labels_are_skipped() {
        let mut a = TransitAllocator::new(16, 1048575, &[16, 18]);
        assert_eq!(a.allocate(p(1)), Some(GenericLabel(17)));
        assert_eq!(a.allocate(p(2)), Some(GenericLabel(19)));
    }

    #[test]
    fn release_frees_and_cursor_rewinds() {
        let mut a = TransitAllocator::new(16, 1048575, &[]);
        let l1 = a.allocate(p(1)).unwrap();
        let l2 = a.allocate(p(2)).unwrap();
        assert_eq!(a.release(&p(1)), Some(l1));
        assert_eq!(a.label_of(&p(1)), None);
        // The freed label is reused first.
        assert_eq!(a.allocate(p(3)), Some(l1));
        assert_eq!(a.allocate(p(4)), Some(GenericLabel(l2.0 + 1)));
    }

    #[test]
    fn range_bounds_are_clamped_and_swapped() {
        // Inverted bounds are normalized instead of exhausted.
        let mut a = TransitAllocator::new(1048575, 16, &[]);
        assert_eq!(a.allocate(p(1)), Some(GenericLabel(16)));
        // Out-of-platform-window bounds clamp.
        let mut b = TransitAllocator::new(0, 2_000_000, &[]);
        assert_eq!(b.allocate(p(1)), Some(GenericLabel(16)));
    }

    #[test]
    fn exhaustion_returns_none() {
        let mut a = TransitAllocator::new(16, 18, &[]);
        assert_eq!(a.allocate(p(1)), Some(GenericLabel(16)));
        assert_eq!(a.allocate(p(2)), Some(GenericLabel(17)));
        assert_eq!(a.allocate(p(3)), Some(GenericLabel(18)));
        assert_eq!(a.allocate(p(4)), None);
        // But a release makes room again.
        a.release(&p(2));
        assert_eq!(a.allocate(p(4)), Some(GenericLabel(17)));
    }

    #[test]
    fn exhaustion_with_wrapped_scan_finds_holes() {
        let mut a = TransitAllocator::new(16, 18, &[]);
        let _ = a.allocate(p(1)); // 16
        let l2 = a.allocate(p(2)); // 17
        let _ = a.allocate(p(3)); // 18
        let _ = a.release(&p(2));
        // Cursor sits past max (wrapped); the wrap scan must still
        // find the hole at 17.
        assert_eq!(a.allocate(p(4)), l2);
        assert_eq!(a.allocate(p(5)), None);
    }
}
