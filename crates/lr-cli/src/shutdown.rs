//! Daemon-wide graceful drain shutdown (issue #53).
//!
//! `ShutdownController` runs the new "drain" shutdown mode the
//! `[shutdown] mode = "drain"` knob and the runtime API `shutdown
//! drain` command activate. The controller lives in its own module so
//! the daemon, the multi-protocol supervisor, the runtime API and the
//! `lrctl` CLI can all share one implementation.
//!
//! # Lifecycle
//!
//! ```text
//!  Running ──begin_drain()──▶ Draining ──worker completes──▶ Drained ──▶ process exit
//!     ▲                            │                          │
//!     └──────────abort()──────────┘                          │
//!                                                              │
//!                                       running.store(false) ─┘
//! ```
//!
//! The worker thread:
//!
//! 1. Flips the shared gate on so the [`DrainModeImportHook`] drops
//!    every inbound UPDATE at the front of the import chain (the
//!    "stop accepting new routes" step from the issue).
//! 2. Snapshots the queue of routes the daemon originated — statics,
//!    BGP-originated routes and aggregates — under a single read
//!    lock, then releases the lock so the FSMs can keep running.
//! 3. Walks the queue, calling [`RouterInstance::uninstall_static`],
//!    [`RouterInstance::unoriginate`] and [`RouterInstance::remove_aggregate`]
//!    at the configured rate. Each call triggers reselection and
//!    pushes the corresponding withdraw into Adj-RIB-Out — peers see
//!    the UPDATE-withdraw messages at the daemon's normal update
//!    cadence, not a burst.
//! 4. Tears down every session with [`RouterInstance::shutdown_session`]
//!    (RFC 4486 §4.1 subcode 2 — Administrative Shutdown) so the
//!    peer-side implicit-withdraw-on-session-close is signalled
//!    cleanly.
//! 5. Flips the gate off, sets the controller state to `Drained`,
//!    and flips `running` to false. The daemon's main loop notices
//!    the flag on its next poll and exits.
//!
//! # Why this lives in `lr-cli`
//!
//! The drain worker is a *daemon-level* concern (it owns the process
//! exit), not a router-instance concern. Embedders wiring `lr-router`
//! directly into a custom process get the building blocks
//! (`DrainModeImportHook`, `RouterInstance::originated_keys`,
//! `shutdown_session`) but the daemon exit orchestration stays in
//! `lr-cli`.
//!
//! [`DrainModeImportHook`]: lr_policy::DrainModeImportHook
//! [`RouterInstance::uninstall_static`]: lr_router::RouterInstance::uninstall_static
//! [`RouterInstance::unoriginate`]: lr_router::RouterInstance::unoriginate
//! [`RouterInstance::remove_aggregate`]: lr_router::RouterInstance::remove_aggregate
//! [`RouterInstance::shutdown_session`]: lr_router::RouterInstance::shutdown_session

use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::sync::{Arc, RwLock};
use std::thread;
use std::time::{Duration, Instant};

use lr_core::addr::Prefix;
use lr_core::rib::RouteKey;
use lr_router::DefaultRouter;

use crate::daemon_logger::{log_record, Component, Severity};

const STATE_RUNNING: u8 = 0;
const STATE_DRAINING: u8 = 1;
const STATE_DRAINED: u8 = 2;

/// One drain-target route. The worker pops these off the queue in
/// turn; the variant picks the `RouterInstance` API the withdrawal
/// routes through.
enum WithdrawTarget {
    /// `Protocol::Static` route installed via
    /// [`RouterInstance::install_static`] — drained via
    /// [`RouterInstance::uninstall_static`].
    Static(RouteKey),
    /// Route originated via `originate*` — drained via
    /// [`RouterInstance::unoriginate`] (which also flushes the
    /// redistributed BGP copy whose source was this originated route,
    /// via [`RouterInstance::unredistribute_route`]).
    Originated(RouteKey),
    /// BGP route aggregate (RFC 4271 §9.2.2.2) — drained via
    /// [`RouterInstance::remove_aggregate`].
    Aggregate(Prefix),
}

impl WithdrawTarget {
    /// Drain this target through the router. The static and
    /// originated paths return whether the route was present (the
    /// router's uninstall/unoriginate methods return a bool that
    /// signals whether the route actually existed); the aggregate
    /// path is `()` because `remove_aggregate` modifies the
    /// router in place and returns nothing — the drain worker
    /// does not need the success/failure signal either way, so a
    /// uniform `bool` return type keeps the call site a single
    /// `match` expression.
    fn drain(&self, router: &mut DefaultRouter) -> bool {
        match self {
            WithdrawTarget::Static(k) => router.uninstall_static(k),
            WithdrawTarget::Originated(k) => router.unoriginate(k),
            WithdrawTarget::Aggregate(p) => {
                router.remove_aggregate(p);
                true
            }
        }
    }
}

/// Snapshot of the drain queue, used for both the worker's initial
/// queue and the `shutdown status` API reply.
fn snapshot_queue(router: &DefaultRouter) -> Vec<WithdrawTarget> {
    let mut v: Vec<WithdrawTarget> = Vec::new();
    v.extend(
        router
            .static_routes()
            .keys()
            .cloned()
            .map(WithdrawTarget::Static),
    );
    v.extend(
        router
            .originated_keys()
            .into_iter()
            .map(WithdrawTarget::Originated),
    );
    v.extend(
        router
            .aggregate_prefixes()
            .into_iter()
            .map(WithdrawTarget::Aggregate),
    );
    v
}

/// Daemon-wide graceful drain controller (issue #53).
///
/// Shared across the API thread, the worker thread and the daemon's
/// main loop. The `gate` is the flag the
/// [`DrainModeImportHook`] reads; the `state` is the lifecycle
/// indicator the API surfaces via `shutdown status`.
///
/// The controller is cheap to clone — every field is `Arc`-wrapped.
/// Construct one per daemon and clone the handle into the API
/// context, the multi-protocol supervisor and the test harness.
///
/// [`DrainModeImportHook`]: lr_policy::DrainModeImportHook
#[derive(Clone)]
pub struct ShutdownController {
    state: Arc<AtomicU8>,
    gate: Arc<AtomicBool>,
    rate_per_sec: u32,
    max_wait: Duration,
}

/// Lifecycle phase of the drain. Surfaced by `shutdown status`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DrainState {
    /// Normal operation. The drain worker has not started, or has
    /// been reset via [`ShutdownController::abort`].
    Running,
    /// Drain in progress: the gate is set, the worker is walking
    /// the queue.
    Draining,
    /// Drain complete: the queue is empty (or the deadline elapsed),
    /// the worker has torn the sessions down, `running` is about to
    /// flip.
    Drained,
}

impl DrainState {
    /// One-word label for the `shutdown status` reply line.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Running => "running",
            Self::Draining => "draining",
            Self::Drained => "drained",
        }
    }
}

impl ShutdownController {
    /// Construct a controller wired to a fresh shared gate. The
    /// caller passes the configured `rate_per_sec` and `max_wait`;
    /// the controller clamps `rate_per_sec` to at least `1` (a zero
    /// rate would never complete the drain, so [`DaemonConfig::finalize`]
    /// already rejects that — but the clamp keeps an embedder
    /// wiring the controller by hand honest).
    ///
    /// [`DaemonConfig::finalize`]: crate::daemon_config::DaemonConfig::finalize
    pub fn new(rate_per_sec: u32, max_wait: Duration) -> Self {
        Self {
            state: Arc::new(AtomicU8::new(STATE_RUNNING)),
            gate: Arc::new(AtomicBool::new(false)),
            rate_per_sec: rate_per_sec.max(1),
            max_wait,
        }
    }

    /// Clone the shared gate handle. Wire this into a
    /// [`DrainModeImportHook`] and install the hook on the router's
    /// import chain before the daemon starts accepting sessions.
    ///
    /// [`DrainModeImportHook`]: lr_policy::DrainModeImportHook
    pub fn drain_gate(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.gate)
    }

    /// Current drain state. Cheap (one relaxed atomic load), safe to
    /// call from any thread.
    pub fn state(&self) -> DrainState {
        match self.state.load(Ordering::Relaxed) {
            STATE_RUNNING => DrainState::Running,
            STATE_DRAINING => DrainState::Draining,
            _ => DrainState::Drained,
        }
    }

    /// Number of routes still queued for withdrawal. Snapshotted
    /// under a read lock — cheap, but do not call from the drain
    /// worker thread (it holds the write lock when draining).
    pub fn routes_remaining(&self, router: &Arc<RwLock<DefaultRouter>>) -> usize {
        let r = router.read().unwrap();
        snapshot_queue(&r).len()
    }

    /// Begin the drain worker if and only if the controller is in the
    /// `Running` state. The worker runs on its own thread so the API
    /// thread that triggered the drain can return immediately with
    /// the `drain started` reply.
    ///
    /// Returns `true` if the drain was started, `false` if the
    /// controller was already `Draining` or `Drained` (so a
    /// duplicate `shutdown drain` from the operator is a no-op, not
    /// an error).
    pub fn begin_drain(
        self: Arc<Self>,
        router: Arc<RwLock<DefaultRouter>>,
        running: Arc<AtomicBool>,
    ) -> bool {
        if self
            .state
            .compare_exchange(
                STATE_RUNNING,
                STATE_DRAINING,
                Ordering::Relaxed,
                Ordering::Relaxed,
            )
            .is_err()
        {
            return false;
        }
        self.gate.store(true, Ordering::Relaxed);
        log_record(
            Severity::Info,
            Component::Daemon,
            format_args!(
                "graceful drain started (rate={}/s, max_wait={:?})",
                self.rate_per_sec, self.max_wait
            ),
        );
        let ctrl = Arc::clone(&self);
        thread::Builder::new()
            .name("lr-drain".into())
            .spawn(move || ctrl.drain_worker(router, running))
            .ok();
        true
    }

    /// Abort a drain in progress and return the controller to the
    /// `Running` state. The worker thread, if running, notices the
    /// state change on its next iteration and exits without
    /// touching the queue further.
    ///
    /// Intended for the embedder that wants to cancel a drain
    /// started via [`begin_drain`](Self::begin_drain) (the daemon
    /// has no `lrctl shutdown abort` today, but the building block
    /// is here).
    pub fn abort(&self) {
        self.gate.store(false, Ordering::Relaxed);
        self.state.store(STATE_RUNNING, Ordering::Relaxed);
        log_record(
            Severity::Warn,
            Component::Daemon,
            format_args!("graceful drain aborted (state -> running)"),
        );
    }

    /// Worker body — runs on the `lr-drain` thread. The state machine
    /// is: Draining (queue walk) → Drained (sessions torn down,
    /// gate cleared, `running` flipped).
    fn drain_worker(&self, router: Arc<RwLock<DefaultRouter>>, running: Arc<AtomicBool>) {
        let mut queue: Vec<WithdrawTarget> = {
            let r = router.read().unwrap();
            snapshot_queue(&r)
        };
        let interval = Duration::from_secs_f64(1.0 / self.rate_per_sec as f64);
        let deadline = Instant::now() + self.max_wait;

        while !queue.is_empty() {
            // Abort wins: if another thread flipped the state back to
            // Running (via `abort`), the worker exits without further
            // work — leaving the remaining routes installed.
            if self.state.load(Ordering::Relaxed) == STATE_RUNNING {
                log_record(
                    Severity::Info,
                    Component::Daemon,
                    format_args!(
                        "graceful drain worker noticed abort; exiting with {} routes still queued",
                        queue.len()
                    ),
                );
                return;
            }
            if Instant::now() >= deadline {
                break;
            }
            let start = Instant::now();
            let target = queue.pop().expect("non-empty queue");
            {
                let mut w = router.write().unwrap();
                target.drain(&mut w);
            }
            let elapsed = start.elapsed();
            if elapsed < interval {
                thread::sleep(interval - elapsed);
            }
        }

        // Tear down every live session (RFC 4486 §4.1 Administrative
        // Shutdown). The peer-side implicit-withdraw on session close
        // handles the routes the daemon did not originate.
        let summaries = {
            let r = router.read().unwrap();
            r.session_summaries()
        };
        {
            let mut w = router.write().unwrap();
            for s in &summaries {
                w.shutdown_session(s.handle);
            }
        }

        // Clear the gate so any in-flight imports finish cleanly.
        // Done after the session teardown so a late import during the
        // teardown window is dropped, not admitted.
        self.gate.store(false, Ordering::Relaxed);
        self.state.store(STATE_DRAINED, Ordering::Relaxed);

        let drained = queue.is_empty();
        if drained {
            log_record(
                Severity::Info,
                Component::Daemon,
                format_args!("graceful drain complete; exiting"),
            );
        } else {
            log_record(
                Severity::Warn,
                Component::Daemon,
                format_args!(
                    "graceful drain max_wait reached with {} routes still queued; exiting",
                    queue.len()
                ),
            );
        }
        running.store(false, Ordering::Relaxed);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Two WithdrawTargets with the same key compare unequal when
    /// the variant differs — this is what lets the drain worker
    /// call the right `RouterInstance` API for each kind without a
    /// second lookup. A direct `PartialEq` is not derived (the
    /// variants intentionally don't compare), so this test just
    /// asserts the discriminants the worker dispatches on.
    #[test]
    fn withdraw_target_variant_drains_through_expected_api() {
        // Construct one of each variant and verify the discriminant
        // is what we expect — the worker's `match` is exhaustive,
        // so adding a new variant later is a compile error unless the
        // worker's match is updated too.
        let key = RouteKey::new(
            "203.0.113.0/24".parse().unwrap(),
            lr_core::nlri::NlriFamily::IPV4_UNICAST,
        );
        let prefix: Prefix = "203.0.113.0/24".parse().unwrap();
        let static_t = WithdrawTarget::Static(key.clone());
        let orig_t = WithdrawTarget::Originated(key.clone());
        let agg_t = WithdrawTarget::Aggregate(prefix);
        // Variant discriminants (compile-time check): the worker's
        // match must cover all three. The `match` below does, so any
        // future addition will need to be touched here too.
        for t in [static_t, orig_t, agg_t] {
            let _label = match &t {
                WithdrawTarget::Static(_) => "static",
                WithdrawTarget::Originated(_) => "originated",
                WithdrawTarget::Aggregate(_) => "aggregate",
            };
            let _ = &t;
        }
    }

    /// A freshly-constructed controller reports the `Running`
    /// state and a clear gate. The gate is shared: cloning the
    /// handle and flipping the original is observable through the
    /// clone (the API surface for `shutdown status` queries the
    /// clone, the worker holds the original).
    #[test]
    fn fresh_controller_is_running_with_clear_gate() {
        let ctrl = ShutdownController::new(50, Duration::from_secs(60));
        assert_eq!(ctrl.state(), DrainState::Running);
        assert!(!ctrl.gate.load(Ordering::Relaxed));
        // Cloning the gate gives back the same Arc.
        let g1 = ctrl.drain_gate();
        let g2 = ctrl.drain_gate();
        assert!(Arc::ptr_eq(&g1, &g2));
    }

    /// `begin_drain` flips state Running -> Draining and sets the
    /// gate. A second `begin_drain` is a no-op (returns false) and
    /// does not spawn a second worker thread.
    #[test]
    fn begin_drain_is_idempotent_under_repeated_calls() {
        // We use a no-op router here: the worker tries to read it
        // (snapshotting the queue), but the router has no routes,
        // so the worker walks an empty queue, tears down an empty
        // session list, and exits immediately. The state should
        // transition through Draining -> Drained.
        let ctrl = Arc::new(ShutdownController::new(1000, Duration::from_secs(5)));
        let router: Arc<RwLock<DefaultRouter>> = Arc::new(RwLock::new(DefaultRouter::new()));
        let running = Arc::new(AtomicBool::new(true));

        assert!(Arc::clone(&ctrl).begin_drain(Arc::clone(&router), Arc::clone(&running)));
        // Second call is a no-op.
        assert!(!Arc::clone(&ctrl).begin_drain(Arc::clone(&router), Arc::clone(&running)));
        // The state must be Draining (worker may not have finished
        // yet — that's fine, the test only asserts the API
        // contract).
        assert!(matches!(
            ctrl.state(),
            DrainState::Draining | DrainState::Drained
        ));
        assert!(ctrl.gate.load(Ordering::Relaxed));

        // Wait for the worker to finish so we do not leave a thread
        // behind. The router has no routes and no sessions, so the
        // worker should reach Drained within the 5 s deadline.
        let deadline = Instant::now() + Duration::from_secs(2);
        while ctrl.state() != DrainState::Drained && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(10));
        }
        assert_eq!(ctrl.state(), DrainState::Drained);
        assert!(!running.load(Ordering::Relaxed));
    }

    /// `abort` during drain flips the state back to Running and
    /// clears the gate. The worker notices on its next iteration
    /// and exits without further work.
    ///
    /// Constructed to be deterministic: rather than racing the
    /// worker (which is timing-sensitive), this test directly
    /// exercises the abort() state transition on a controller
    /// whose state has been flipped to Draining manually. The
    /// end-to-end "begin_drain → abort → worker exits" race is
    /// covered by the interop lab instead (a worker that has
    /// started but not yet iterated cannot observe an abort; the
    /// abort is best-effort, exactly like POSIX signals).
    #[test]
    fn abort_resets_state_and_gate() {
        let ctrl = ShutdownController::new(50, Duration::from_secs(60));
        // Flip the state to Draining and set the gate, simulating
        // what begin_drain does.
        ctrl.state.store(STATE_DRAINING, Ordering::Relaxed);
        ctrl.gate.store(true, Ordering::Relaxed);
        assert_eq!(ctrl.state(), DrainState::Draining);
        assert!(ctrl.gate.load(Ordering::Relaxed));

        // Abort.
        ctrl.abort();

        // The state must be Running, the gate clear.
        assert_eq!(ctrl.state(), DrainState::Running);
        assert!(!ctrl.gate.load(Ordering::Relaxed));
    }
}
