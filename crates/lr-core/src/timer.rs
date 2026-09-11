//! Logical timer queue.
//!
//! A binary-heap-based wheel that the embedder drives by calling
//! [`TimerQueue::tick`] with the current logical time. Expired timers fire
//! their [`TimerId`] back. The library does not use real time — the embedder
//! pumps the queue at whatever cadence it wants.
//!
//! The queue stores `(fire_at, timer_id, period_ms)`. When a timer with a
//! non-zero `period_ms` fires, it is rescheduled at `fire_at + period_ms`.

use crate::fsm::{TimerId, TimerSpec};
use crate::time::Instant;
use core::cmp::Ordering;

/// An entry in the timer queue.
#[derive(Debug, Clone, Copy)]
struct Entry {
    fire_at: u64,
    period: u64,
    id: TimerId,
}

impl PartialEq for Entry {
    fn eq(&self, other: &Self) -> bool {
        self.fire_at == other.fire_at && self.id == other.id
    }
}

impl Eq for Entry {}

impl PartialOrd for Entry {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Entry {
    fn cmp(&self, other: &Self) -> Ordering {
        // BinaryHeap is a max-heap; we want the earliest fire_at first, so
        // reverse the ordering.
        other.fire_at.cmp(&self.fire_at)
    }
}

#[cfg(not(feature = "std"))]
extern crate alloc;
#[cfg(not(feature = "std"))]
use alloc::collections::BinaryHeap;
#[cfg(not(feature = "std"))]
use alloc::vec::Vec;
#[cfg(feature = "std")]
use std::collections::BinaryHeap;

/// A logical timer queue.
#[derive(Default)]
pub struct TimerQueue {
    heap: BinaryHeap<Entry>,
}

impl TimerQueue {
    pub fn new() -> Self {
        Self {
            heap: BinaryHeap::new(),
        }
    }

    pub fn arm(&mut self, now: Instant, id: TimerId, spec: TimerSpec) {
        let fire_at = now.0.saturating_add(spec.after_ms);
        self.heap.push(Entry {
            fire_at,
            period: spec.periodic_ms,
            id,
        });
    }

    pub fn cancel(&mut self, id: TimerId) {
        // Heap does not support efficient removal; we filter and rebuild.
        let kept: Vec<Entry> = self.heap.drain().filter(|e| e.id != id).collect();
        self.heap = kept.into_iter().collect();
    }

    pub fn cancel_all(&mut self) {
        self.heap.clear();
    }

    /// Advance the clock; returns the list of timers that fired.
    pub fn tick(&mut self, now: Instant) -> Vec<TimerId> {
        let mut fired = Vec::new();
        loop {
            match self.heap.peek() {
                Some(top) if top.fire_at <= now.0 => {
                    // The peek above confirmed the heap is non-empty;
                    // pop() cannot return None here. expect() with a
                    // message documents the invariant for the reader
                    // and surfaces it if the invariant ever breaks.
                    let mut e = self.heap.pop().expect("peek confirmed non-empty");
                    fired.push(e.id);
                    if e.period > 0 {
                        e.fire_at = e.fire_at.saturating_add(e.period);
                        self.heap.push(e);
                    }
                }
                _ => break,
            }
        }
        fired
    }

    pub fn is_empty(&self) -> bool {
        self.heap.is_empty()
    }

    pub fn len(&self) -> usize {
        self.heap.len()
    }

    /// Time of the next fire (or `None` if empty).
    pub fn next_fire(&self) -> Option<Instant> {
        self.heap.peek().map(|e| Instant(e.fire_at))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn arm_and_fire() {
        let mut q = TimerQueue::new();
        let id = TimerId(1);
        q.arm(Instant(0), id, TimerSpec::once(100));
        assert_eq!(q.tick(Instant(50)), Vec::<TimerId>::new());
        assert_eq!(q.tick(Instant(100)), vec![id]);
        assert!(q.is_empty());
    }

    #[test]
    fn periodic_reschedules() {
        let mut q = TimerQueue::new();
        let id = TimerId(7);
        q.arm(Instant(0), id, TimerSpec::periodic(10, 10));
        assert_eq!(q.tick(Instant(10)), vec![id]);
        assert_eq!(q.tick(Instant(20)), vec![id]);
        assert_eq!(q.tick(Instant(25)), Vec::<TimerId>::new());
        assert_eq!(q.tick(Instant(30)), vec![id]);
        q.cancel(id);
        assert_eq!(q.tick(Instant(1000)), Vec::<TimerId>::new());
    }

    #[test]
    fn cancel_removes() {
        let mut q = TimerQueue::new();
        let a = TimerId(1);
        let b = TimerId(2);
        q.arm(Instant(0), a, TimerSpec::once(100));
        q.arm(Instant(0), b, TimerSpec::once(100));
        q.cancel(a);
        assert_eq!(q.len(), 1);
        assert_eq!(q.tick(Instant(100)), vec![b]);
    }
}
