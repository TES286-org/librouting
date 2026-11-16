//! Bounded lock-free MPMC ring — the per-subscriber queue the
//! [`super::EventBus`] pushes to and a subscriber pops from.
//!
//! The previous event bus stored each subscriber's queue behind a
//! `std::sync::mpsc::sync_channel`, whose `try_send` takes a per-send
//! mutex; with N subscribers the publisher took N mutexes per publish.
//! This module replaces that with Dmitry Vyukov's bounded MPMC queue
//! (the algorithm `crossbeam_queue::ArrayQueue` and the Linux kernel's
//! `ptr_ring` both implement): one atomic head and tail, each slot
//! carries its own sequence number, and producers and consumers
//! coordinate through CAS on the head/tail plus an Acquire/Release
//! pair on the slot sequence. There are no locks on the push or pop
//! path; multiple producers and multiple consumers are supported.
//!
//! # Algorithm
//!
//! The buffer is `capacity` slots (rounded up to a power of two so
//! the index is `pos & mask`). Each slot owns:
//!
//! - a `MaybeUninit<T>` cell (the value, or uninitialised memory
//!   between a consumer's pop and the next producer's push at this
//!   slot index);
//! - an `AtomicUsize` sequence number.
//!
//! At init, slot `i` carries `seq = i`. A producer at position `pos`
//! finds `slot.seq == pos` (the slot "is reserved for the producer at
//! position pos"), CASes `tail` forward to claim the slot, writes the
//! value, and publishes `slot.seq = pos + 1`. A consumer at position
//! `pos` finds `slot.seq == pos + 1` (the slot "holds the value
//! pushed at pos"), CASes `head` forward, reads the value, and
//! publishes `slot.seq = pos + capacity` (so the next producer at
//! `pos + capacity` finds `slot.seq == pos + capacity`, which is its
//! own target). The sequence numbers advance monotonically; the head
//! and tail are wrapping `usize` counters, and the arithmetic is
//! `wrapping_add` / `wrapping_sub` so the queue never overflows its
//! 64-bit range in any realistic timeline.
//!
//! # Memory ordering
//!
//! - The producer's `slot.seq.load(Acquire)` pairs with the
//!   consumer's `slot.seq.store(Release)` after the pop, so a
//!   producer never writes into a slot a consumer is still reading.
//! - The consumer's `slot.seq.load(Acquire)` pairs with the
//!   producer's `slot.seq.store(Release)` after the push, so a
//!   consumer never reads a slot a producer has not finished writing.
//! - The `head` / `tail` CAS uses `AcqRel` on the successful store
//!   and `Relaxed` on the failure reload. The slot sequence carries
//!   the value's cross-thread visibility; the `AcqRel` on the head /
//!   tail CAS exists for the fullness / emptiness pre-checks that
//!   read the *other* counter — the producer's `head.load(Acquire)`
//!   pairs with the consumer's `head` CAS (the Release half of
//!   `AcqRel`) so a pop that frees a slot is visible before the
//!   producer declares the queue full, and the consumer's
//!   `tail.load(Acquire)` pairs with the producer's `tail` CAS (the
//!   Release half of `AcqRel`) so a push that claims a slot is
//!   visible before the consumer declares the queue empty. With
//!   `Acquire`-only success the write half would be `Relaxed`, and a
//!   stale read of the other counter could declare full or empty
//!   when the slot's own sequence number says otherwise — a real
//!   loss / latency window on weakly ordered memory (RISC-V RVWMO,
//!   ARM64) that x86_64's TSO hides.
//!
//! # Safety
//!
//! `MaybeUninit<T>` is `Send + Sync` only when `T` is. The cell is
//! accessed by exactly one thread at a time (the producer that won
//! the CAS on `tail`, or the consumer that won the CAS on `head`),
//! so the `UnsafeCell` is sound. `Drop` drains any leftover values
//! so their destructors run before the buffer is freed.

use std::cell::UnsafeCell;
use std::mem::MaybeUninit;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

/// One slot in the ring: a value cell plus its sequence number.
struct Slot<T> {
    data: UnsafeCell<MaybeUninit<T>>,
    seq: AtomicUsize,
}

/// A bounded, lock-free multi-producer multi-consumer queue.
///
/// Created through [`MpmcRing::new`], which returns an `Arc` so the
/// producer side and the consumer side each hold their own reference.
/// `try_push` and `try_pop` are wait-free under contention: a CAS
/// retry loop whose iteration count is bounded by the number of
/// contending threads.
pub(crate) struct MpmcRing<T> {
    buffer: Box<[Slot<T>]>,
    head: AtomicUsize,
    tail: AtomicUsize,
    mask: usize,
    capacity: usize,
}

// SAFETY: the slot's `UnsafeCell<MaybeUninit<T>>` is accessed by
// exactly one thread at a time (the producer that won the CAS on
// `tail`, or the consumer that won the CAS on `head`); the sequence
// numbers enforce the handoff. `T: Send` is the bound the cell needs
// to be shareable across threads.
unsafe impl<T: Send> Send for MpmcRing<T> {}
unsafe impl<T: Send> Sync for MpmcRing<T> {}

impl<T> MpmcRing<T> {
    /// Build a ring with at least `capacity` slots. The actual
    /// capacity is rounded up to the next power of two (the mask
    /// arithmetic requires it) and clamped to a minimum of one.
    pub(crate) fn new(capacity: usize) -> Arc<Self> {
        let cap = capacity.max(1).next_power_of_two();
        let mut buffer: Vec<Slot<T>> = Vec::with_capacity(cap);
        for i in 0..cap {
            buffer.push(Slot {
                data: UnsafeCell::new(MaybeUninit::uninit()),
                seq: AtomicUsize::new(i),
            });
        }
        Arc::new(Self {
            buffer: buffer.into_boxed_slice(),
            head: AtomicUsize::new(0),
            tail: AtomicUsize::new(0),
            mask: cap - 1,
            capacity: cap,
        })
    }

    /// The actual slot count (a power of two ≥ the requested
    /// capacity). Tests read this so the rounding is visible; the
    /// bus does not surface it to its callers (the bus's
    /// `with_capacity` documents the rounding-up behaviour).
    #[cfg(test)]
    pub(crate) fn capacity(&self) -> usize {
        self.capacity
    }

    /// Producer: enqueue `v`. Returns `Ok(())` on success or
    /// `Err(v)` (the value back) when the queue is full — the
    /// non-blocking contract the bus's publish hot path requires.
    ///
    /// The fullness check (`pos - head >= capacity`) runs before the
    /// slot-sequence match so a queue with `capacity == 1` (the
    /// clamped minimum) correctly refuses a second push: after one
    /// push at `pos = 0` the slot's sequence becomes `1`, which
    /// equals the next producer's `pos = 1` — the sequence match
    /// alone would let the producer overwrite an occupied slot.
    pub(crate) fn try_push(&self, v: T) -> Result<(), T> {
        let mut pos = self.tail.load(Ordering::Relaxed);
        loop {
            // Fullness check first: a producer must not advance `tail`
            // past `head + capacity`. Reading `head` with `Acquire`
            // pairs with the consumer's `head` CAS (the Release half
            // of its `AcqRel` success ordering) so a pop that frees a
            // slot is visible before we declare full. An
            // `Acquire`-only success on the consumer's CAS would leave
            // the write half `Relaxed`, and on weakly ordered memory
            // (RISC-V RVWMO, ARM64) this load could observe a stale
            // `head` and falsely declare full — `try_push` returns
            // `Err(v)` and the publisher drops the event even though a
            // slot was free. x86_64's TSO hides the window in
            // practice.
            let head = self.head.load(Ordering::Acquire);
            if pos.wrapping_sub(head) >= self.capacity {
                return Err(v);
            }
            let slot = &self.buffer[pos & self.mask];
            let seq = slot.seq.load(Ordering::Acquire);
            if seq == pos {
                // Slot is empty and reserved for the producer at
                // `pos`. Try to claim it by advancing `tail`; the
                // weak CAS handles contention from other producers
                // loading the same `pos`. Success ordering is
                // `AcqRel`: the `Acquire` half synchronises with any
                // prior consumer's `head` CAS so the fullness check
                // above saw an up-to-date `head` (defensive — the
                // load already established the visibility), and the
                // `Release` half publishes the `tail` advance to a
                // consumer's `tail.load(Acquire)` in the empty check
                // below, so a producer in flight (CAS done, slot.seq
                // not yet published) is not mistaken for an empty
                // queue.
                match self.tail.compare_exchange_weak(
                    pos,
                    pos.wrapping_add(1),
                    Ordering::AcqRel,
                    Ordering::Relaxed,
                ) {
                    Ok(_) => {
                        // SAFETY: the CAS won the slot; no other
                        // producer or consumer touches it until we
                        // publish `seq = pos + 1`.
                        unsafe {
                            (*slot.data.get()) = MaybeUninit::new(v);
                        }
                        slot.seq.store(pos.wrapping_add(1), Ordering::Release);
                        return Ok(());
                    }
                    Err(actual) => {
                        pos = actual;
                    }
                }
            } else {
                // The slot is not reserved for us: either a
                // concurrent producer won it (seq is ahead of pos)
                // or a consumer is mid-pop on a slot we will reach
                // next round. Reload `tail` and retry — the
                // fullness check on the next iteration will catch
                // a queue that filled while we were spinning.
                pos = self.tail.load(Ordering::Relaxed);
            }
        }
    }

    /// Consumer: dequeue the next value. Returns `None` when the
    /// queue is empty. The value is moved out of the slot; the slot
    /// is then re-armed for the producer that will arrive at
    /// `pos + capacity`.
    pub(crate) fn try_pop(&self) -> Option<T> {
        let mut pos = self.head.load(Ordering::Relaxed);
        loop {
            let slot = &self.buffer[pos & self.mask];
            let seq = slot.seq.load(Ordering::Acquire);
            let target = pos.wrapping_add(1);
            if seq == target {
                // Slot holds the value pushed at `pos`. Try to
                // claim it by advancing `head`; the weak CAS
                // handles contention from other consumers. Success
                // ordering is `AcqRel`: the `Acquire` half
                // synchronises with the producer's prior
                // `slot.seq.store(Release)` (already covered by the
                // `slot.seq.load(Acquire)` above), and the `Release`
                // half publishes the `head` advance to a producer's
                // `head.load(Acquire)` in the fullness check above,
                // so a pop that frees a slot is visible before the
                // producer declares full — without it, an
                // `Acquire`-only success leaves the write half
                // `Relaxed`, and on weakly ordered memory a producer
                // could observe a stale `head` and drop an event
                // even though a slot was free.
                match self.head.compare_exchange_weak(
                    pos,
                    pos.wrapping_add(1),
                    Ordering::AcqRel,
                    Ordering::Relaxed,
                ) {
                    Ok(_) => {
                        // SAFETY: the CAS won the slot; the producer
                        // that wrote it published `seq = pos + 1`,
                        // and no other producer will touch it until
                        // we re-arm with `seq = pos + capacity`.
                        let v = unsafe { (*slot.data.get()).assume_init_read() };
                        slot.seq
                            .store(pos.wrapping_add(self.capacity), Ordering::Release);
                        return Some(v);
                    }
                    Err(actual) => {
                        pos = actual;
                    }
                }
            } else if seq == pos {
                // The slot is empty from this consumer's view: no
                // producer has pushed here yet. Verify against the
                // producer's `tail` before declaring empty — a
                // producer may have just CASed `tail` forward but
                // not yet published `seq = pos + 1`.
                let tail = self.tail.load(Ordering::Acquire);
                if pos == tail {
                    return None;
                }
                // Producer advanced but hasn't published; reload.
                pos = self.head.load(Ordering::Relaxed);
            } else {
                // The slot is in a transitional state (a producer
                // is mid-write between the CAS on `tail` and the
                // `seq.store`, or a concurrent consumer is mid-pop).
                // Reload `head` and retry.
                pos = self.head.load(Ordering::Relaxed);
            }
        }
    }

    /// Best-effort emptiness check for diagnostics. A `true` result
    /// is stable (the queue was empty at the load); a `false` result
    /// may already be stale (a producer pushed between the two
    /// loads). The bus does not rely on this for correctness; tests
    /// use it to assert the drained state.
    #[cfg(test)]
    pub(crate) fn is_empty(&self) -> bool {
        let head = self.head.load(Ordering::Acquire);
        let tail = self.tail.load(Ordering::Acquire);
        head == tail
    }
}

impl<T> Drop for MpmcRing<T> {
    fn drop(&mut self) {
        // At drop we have exclusive access (`&mut self`); drain any
        // leftover values so their destructors run. The slot
        // sequence numbers are irrelevant under exclusive access —
        // the producer/consumer coordination is no longer needed.
        // The initialised slots form a contiguous `[head, tail)`
        // range in wrapping arithmetic; walk it in order.
        let head = *self.head.get_mut();
        let tail = *self.tail.get_mut();
        let mut pos = head;
        while pos != tail {
            let slot = &mut self.buffer[pos & self.mask];
            // SAFETY: every slot in `[head, tail)` is initialised
            // because (a) the producer's path between the `tail` CAS
            // and the `slot.seq.store(Release)` is a panic-free
            // `MaybeUninit::new` write plus an atomic store — no
            // user code runs, so no producer can leave a slot
            // half-written; and (b) the bus only drops a ring under
            // the subscriber list's write lock (lazy prune in
            // `publish`, or `close` clearing the list), which
            // excludes concurrent `publish` walks — so no producer
            // is mid-push when `Drop` runs. `assume_init_read` moves
            // the value out so its `Drop` runs when the binding
            // drops at the end of this iteration.
            //
            // The slot's sequence number is `pos + 1` for a slot a
            // producer published and a consumer has not yet popped —
            // verified defensively so a future code path that breaks
            // assumption (a) surfaces as a skipped slot rather than
            // `Drop` on uninitialised memory.
            if *slot.seq.get_mut() == pos.wrapping_add(1) {
                // SAFETY: as above — the slot is initialised.
                unsafe {
                    let _ = (*slot.data.get()).assume_init_read();
                }
            }
            pos = pos.wrapping_add(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::thread;

    /// SPSC: every push then pop preserves value and order.
    #[test]
    fn spsc_push_pop_round_trips() {
        let ring = MpmcRing::<u32>::new(8);
        for i in 0..8 {
            assert!(ring.try_push(i).is_ok());
        }
        // Full at capacity 8.
        assert!(ring.try_push(99).is_err());
        for i in 0..8 {
            assert_eq!(ring.try_pop(), Some(i), "FIFO order preserved");
        }
        assert!(ring.try_pop().is_none(), "empty after drain");
    }

    /// The capacity rounds up to a power of two.
    #[test]
    fn capacity_rounds_up_to_power_of_two() {
        assert_eq!(MpmcRing::<u32>::new(0).capacity(), 1);
        assert_eq!(MpmcRing::<u32>::new(1).capacity(), 1);
        assert_eq!(MpmcRing::<u32>::new(5).capacity(), 8);
        assert_eq!(MpmcRing::<u32>::new(1023).capacity(), 1024);
    }

    /// Wrap-around: pushing and popping past `capacity` cycles the
    /// index through the mask without losing values.
    #[test]
    fn wrap_around_preserves_values() {
        let ring = MpmcRing::<u32>::new(4);
        for round in 0..16u32 {
            // Fill and drain once per round.
            for i in 0..4u32 {
                assert!(ring.try_push(round * 4 + i).is_ok());
            }
            for i in 0..4u32 {
                assert_eq!(ring.try_pop(), Some(round * 4 + i));
            }
        }
        assert!(ring.is_empty());
    }

    /// MPMC stress: 4 producers × 1000 values, 4 consumers, every
    /// value is observed exactly once (sum and count match).
    #[test]
    fn mpmc_stress_no_loss_no_dup() {
        const PRODUCERS: usize = 4;
        const PER_PRODUCER: usize = 1000;
        const CONSUMERS: usize = 4;
        let ring = MpmcRing::<u32>::new(PRODUCERS * PER_PRODUCER + 16);
        let total: u64 = (0..PRODUCERS as u64)
            .map(|p| {
                let base = (p as u32) * (PER_PRODUCER as u32);
                let end = base + PER_PRODUCER as u32;
                (base as u64..end as u64).sum::<u64>()
            })
            .sum();

        let producers: Vec<_> = (0..PRODUCERS)
            .map(|p| {
                let ring = Arc::clone(&ring);
                thread::spawn(move || {
                    let base = (p as u32) * (PER_PRODUCER as u32);
                    for i in 0..PER_PRODUCER as u32 {
                        // Retry-on-full is not appropriate here — the
                        // capacity exceeds the total — but the
                        // contract is `try_push` returns Err on
                        // full, so we retry explicitly.
                        let mut v = base + i;
                        while let Err(e) = ring.try_push(v) {
                            v = e;
                            std::thread::yield_now();
                        }
                    }
                })
            })
            .collect();

        let received = Arc::new(AtomicUsize::new(0));
        let sum = Arc::new(AtomicU64::new(0));
        let consumers: Vec<_> = (0..CONSUMERS)
            .map(|_| {
                let ring = Arc::clone(&ring);
                let received = Arc::clone(&received);
                let sum = Arc::clone(&sum);
                thread::spawn(move || loop {
                    match ring.try_pop() {
                        Some(v) => {
                            received.fetch_add(1, Ordering::Relaxed);
                            sum.fetch_add(v as u64, Ordering::Relaxed);
                        }
                        None => {
                            if received.load(Ordering::Acquire) >= PRODUCERS * PER_PRODUCER {
                                break;
                            }
                            std::thread::yield_now();
                        }
                    }
                })
            })
            .collect();

        for t in producers {
            t.join().unwrap();
        }
        for t in consumers {
            t.join().unwrap();
        }

        assert_eq!(
            received.load(Ordering::Relaxed),
            PRODUCERS * PER_PRODUCER,
            "no loss, no dup"
        );
        assert_eq!(sum.load(Ordering::Relaxed), total, "sum matches");
    }

    /// `Drop` runs the destructors of leftover values.
    #[test]
    fn drop_drains_leftover_values() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc;

        struct DropCounter(Arc<AtomicUsize>);
        impl Drop for DropCounter {
            fn drop(&mut self) {
                self.0.fetch_add(1, Ordering::Relaxed);
            }
        }

        let counter = Arc::new(AtomicUsize::new(0));
        {
            let ring = MpmcRing::<DropCounter>::new(8);
            for _ in 0..5 {
                assert!(ring.try_push(DropCounter(Arc::clone(&counter))).is_ok());
            }
            // Drop the ring with 5 values still queued.
        }
        assert_eq!(counter.load(Ordering::Relaxed), 5, "all 5 dropped");
    }
}
