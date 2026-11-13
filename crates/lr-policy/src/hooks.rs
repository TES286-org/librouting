//! Policy hooks: extension points for route selection, import, and export.
//!
//! The router ships a default policy pipeline:
//!
//! 1. Inbound decode → 2. Safety net (loop check, NEXT_HOP sanity) → 3. Import
//!    filter chain → 4. Adj-RIB-In → 5. Best-path selection → 6. Loc-RIB →
//! 7. Export filter chain → 8. Adj-RIB-Out → 9. Outbound encode.
//!
//! Each of steps 2, 3, 5, 7 is a **hook point** — an embedder can supply a
//! trait object that runs in addition to (or instead of) the default
//! implementation. This lets operators implement non-standard behavior
//! (e.g. prefer routes from a specific peer regardless of attributes) without
//! forking the codebase.
//!
//! Hook contracts:
//!
//! - **[`ImportHook`]** — invoked after decode, before the route enters
//!   Adj-RIB-In. May modify or drop the route.
//! - **[`SelectionHook`]** — invoked during best-path selection; may
//!   override the comparator (returns `Some(Ordering)` instead of `None` to
//!   force a result).
//! - **[`ExportHook`]** — invoked after the route is selected for the
//!   Adj-RIB-Out, before encode. May modify or drop the route.
//!
//! Built-in hooks:
//!
//! - **[`GracefulShutdownExportHook`]** — RFC 8326 §3.1 sender side: when a
//!   route carries the `GRACEFUL_SHUTDOWN` community, zero its LOCAL_PREF
//!   on the export copy so receivers prefer alternatives before the session
//!   actually goes down. The community itself is preserved so downstream
//!   peers see the signal.
//! - **[`GracefulShutdownImportHook`]** — RFC 8326 §4.1 receiver side: an
//!   imported route carrying the `GRACEFUL_SHUTDOWN` community has its
//!   LOCAL_PREF rewritten to a low value (RECOMMENDED 0), which is the
//!   RFC's inbound-policy formulation of the receiver procedure and also
//!   propagates the de-preference to downstream iBGP speakers that do not
//!   implement §4 themselves.
//!
//! All hooks are non-blocking and synchronous. Long-running work should be
//! deferred to a background task and surfaced as a flag attribute on the
//! route itself.

use core::cmp::Ordering;

use lr_core::rib::{Route, RouteKey, RouteOrigin};

#[cfg(feature = "bgp")]
use lr_bgp::path::{Community, PathAttributes};

#[cfg(feature = "damping")]
use lr_damping::DampingTable;
#[cfg(any(feature = "damping", feature = "peer-health"))]
use std::sync::{Arc, Mutex};

/// Verdict returned by a hook. The route is either dropped, kept as-is, or
/// replaced by a modified copy.
#[derive(Debug, Clone)]
pub enum HookVerdict {
    /// Drop the route (do not insert into Adj-RIB-In / Adj-RIB-Out).
    Drop,
    /// Keep the route as-is.
    Keep,
    /// Replace the route with the supplied modified copy.
    Replace(Route),
}

/// Hook invoked on inbound, after decode, before Adj-RIB-In insertion.
pub trait ImportHook: Send + Sync {
    /// Optional human-readable name (for diagnostics).
    fn name(&self) -> &str {
        "import-hook"
    }
    /// Process the inbound route. May mutate or drop it.
    fn on_import(&self, route: &mut Route) -> HookVerdict;
    /// Notification that a route has been withdrawn from a peer.
    ///
    /// Fires inside the router's withdraw path, after the route has
    /// been removed from Adj-RIB-In. The hook is **informational** —
    /// the return value is ignored (a withdraw cannot be "dropped";
    /// the route is already gone). Implementations use this to
    /// update cross-route state such as the RFC 2439 figure-of-merit
    /// table or the per-peer flap-suppression churn counter (issue #99).
    ///
    /// `origin` identifies the protocol instance and peer that
    /// withdrew the route — issue #99's per-peer flap suppression
    /// accounts withdrawals at `(peer, AFI/SAFI)` granularity and
    /// needs the peer id; older per-prefix hooks (RFC 2439 damping)
    /// ignore it.
    ///
    /// `now_s` is wall-clock seconds at the time of the withdraw,
    /// matching the units the damping table expects.
    fn on_withdraw(&self, _origin: RouteOrigin, _key: &RouteKey, _now_s: u64) {
        // default no-op — most hooks do not care about withdrawals
    }
}

/// Hook invoked during best-path selection.
pub trait SelectionHook: Send + Sync {
    fn name(&self) -> &str {
        "selection-hook"
    }
    /// Compare two routes for selection. Return:
    /// - `Some(Less)` if `a` is preferred over `b`.
    /// - `Some(Equal)` if equally preferred.
    /// - `Some(Greater)` if `b` is preferred over `a`.
    /// - `None` to defer to the default comparator.
    fn compare(&self, a: &Route, b: &Route) -> Option<Ordering>;
}

/// Hook invoked on outbound, after Loc-RIB, before Adj-RIB-Out encode.
pub trait ExportHook: Send + Sync {
    fn name(&self) -> &str {
        "export-hook"
    }
    /// Process the outbound route. May mutate or drop it.
    fn on_export(&self, route: &mut Route) -> HookVerdict;
    /// Destination-aware variant: the router calls this with the id of
    /// the session the route is being advertised to, so per-peer
    /// export policy can dispatch on it. The default delegates to
    /// [`ExportHook::on_export`], preserving destination-agnostic
    /// behaviour for existing hooks.
    fn on_export_to(&self, route: &mut Route, destination: u64) -> HookVerdict {
        let _ = destination;
        self.on_export(route)
    }
}

/// RFC 8326 §3.1 sender-side graceful shutdown hook.
///
/// When a route carries the `GRACEFUL_SHUTDOWN` community
/// (`0xFFFF:0000`, [`Community::GRACEFUL_SHUTDOWN`]), the export
/// copy has its `LOCAL_PREF` set to zero so receiving speakers
/// prefer alternative paths. The community itself is preserved so
/// downstream peers see the signal (RFC 8326 §3.1: "the
/// GRACEFUL_SHUTDOWN community ... SHOULD be retained").
///
/// The hook is idempotent: re-running it on a route that already
/// has `LOCAL_PREF == 0` is a no-op.
///
/// By default the hook is destination-agnostic — RFC 8326 makes no
/// exception for the recipient. [`Self::with_exempt_sessions`]
/// scopes the rewrite: routes exported to an exempt session keep
/// their LOCAL_PREF (the daemon fills it from the per-peer
/// `graceful_shutdown = false` override). Embedders that want a
/// different policy can install their own `ExportHook` instead
/// (e.g. to drop the route entirely rather than advertise with
/// `LOCAL_PREF == 0`).
///
/// This is the canonical implementation; the daemon installs it by
/// default on the BGP export chain.
///
/// [`Community::GRACEFUL_SHUTDOWN`]: lr_bgp::path::Community::GRACEFUL_SHUTDOWN
#[cfg(feature = "bgp")]
#[derive(Debug, Default, Clone)]
pub struct GracefulShutdownExportHook {
    /// Session ids exempt from the §3.1 LOCAL_PREF zeroing.
    /// `None` (the [`Default`] / [`Self::new`] shape) means no
    /// exemptions and skips the per-destination lookup entirely —
    /// the rc.3 destination-agnostic behaviour with zero added
    /// cost on the export hot path.
    exempt: Option<std::collections::BTreeSet<u64>>,
}

#[cfg(feature = "bgp")]
impl GracefulShutdownExportHook {
    pub fn new() -> Self {
        Self { exempt: None }
    }

    /// Destination-scoped variant: routes exported to any of
    /// `sessions` are left untouched by the §3.1 rewrite. An empty
    /// set degrades to [`Self::new`].
    pub fn with_exempt_sessions(sessions: std::collections::BTreeSet<u64>) -> Self {
        Self {
            exempt: if sessions.is_empty() {
                None
            } else {
                Some(sessions)
            },
        }
    }

    /// The exempt session ids, if any.
    pub fn exempt_sessions(&self) -> Option<&std::collections::BTreeSet<u64>> {
        self.exempt.as_ref()
    }

    /// The §3.1 rewrite itself, shared by `on_export` and
    /// `on_export_to`.
    fn apply(&self, route: &mut Route) -> HookVerdict {
        // Take ownership of the attribute bag without cloning so we
        // can use the high-level PathAttributes accessors mutably.
        // The conversion is infallible (From<Attributes> for
        // PathAttributes is total) so we always put the bag back,
        // modified or not.
        let mut attrs: PathAttributes = core::mem::take(&mut route.attributes).into();

        if attrs.has_community(Community::GRACEFUL_SHUTDOWN) {
            // RFC 8326 §3.1: "the BGP speaker ... SHOULD set the
            // LOCAL_PREF value to 0 for the routes ... being
            // advertised". We preserve the community so downstream
            // peers can also act on it.
            attrs.set_local_pref(0);
        }

        route.attributes = attrs.into();
        HookVerdict::Keep
    }
}

#[cfg(feature = "bgp")]
impl ExportHook for GracefulShutdownExportHook {
    fn name(&self) -> &str {
        "rfc8326-graceful-shutdown"
    }

    fn on_export(&self, route: &mut Route) -> HookVerdict {
        self.apply(route)
    }

    fn on_export_to(&self, route: &mut Route, destination: u64) -> HookVerdict {
        // Per-destination opt-out: an exempt session receives the
        // route with its LOCAL_PREF intact. The common case (no
        // exemptions configured) is a single `None` check.
        if self
            .exempt
            .as_ref()
            .is_some_and(|s| s.contains(&destination))
        {
            return HookVerdict::Keep;
        }
        self.apply(route)
    }
}

/// RFC 8326 §4.1 receiver-side graceful shutdown hook.
///
/// RFC 8326 §4.1 pre-configures every graceful-shutdown-capable ASBR
/// with an inbound policy that "matches the GRACEFUL_SHUTDOWN
/// community" and "sets the LOCAL_PREF attribute of the paths tagged
/// with the GRACEFUL_SHUTDOWN community to a low value". This hook is
/// that policy as an [`ImportHook`]: any imported route carrying
/// [`Community::GRACEFUL_SHUTDOWN`] has its LOCAL_PREF rewritten to
/// [`Self::low_local_pref`] (the RECOMMENDED value 0, mirroring FRR's
/// `BGP_GSHUT_LOCAL_PREF`), while the community itself is preserved
/// (§3.1: "the GRACEFUL_SHUTDOWN community ... SHOULD be retained") so
/// the best-path comparator's RFC 8326 §4 step
/// (`BestPathConfig::graceful_shutdown_least_preferred`) and
/// downstream peers can still see the signal.
///
/// Routes without the community pass through untouched, which makes
/// the hook free for the common path and idempotent (re-running it on
/// a route whose LOCAL_PREF is already at the low value is a no-op).
/// The rewrite also propagates: when the receiving speaker
/// re-advertises the route over iBGP, downstream speakers that do not
/// implement the §4 de-preference still honour the low LOCAL_PREF
/// through the plain RFC 4271 decision process.
///
/// Install alongside [`GracefulShutdownExportHook`] — the two are the
/// independent halves of the RFC 8326 receiver procedure (§4.1) and
/// sender procedure (§3.1).
///
/// [`Community::GRACEFUL_SHUTDOWN`]: lr_bgp::path::Community::GRACEFUL_SHUTDOWN
#[cfg(feature = "bgp")]
#[derive(Debug, Clone)]
pub struct GracefulShutdownImportHook {
    low_local_pref: u32,
}

#[cfg(feature = "bgp")]
impl GracefulShutdownImportHook {
    /// The RECOMMENDED low LOCAL_PREF (RFC 8326 §4: "The RECOMMENDED
    /// value is 0"; FRR `BGP_GSHUT_LOCAL_PREF`).
    pub fn new() -> Self {
        Self { low_local_pref: 0 }
    }

    /// Use a different low LOCAL_PREF value.
    pub fn with_low_local_pref(value: u32) -> Self {
        Self {
            low_local_pref: value,
        }
    }

    /// The configured low LOCAL_PREF value.
    pub fn low_local_pref(&self) -> u32 {
        self.low_local_pref
    }
}

#[cfg(feature = "bgp")]
impl Default for GracefulShutdownImportHook {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(feature = "bgp")]
impl ImportHook for GracefulShutdownImportHook {
    fn name(&self) -> &str {
        "rfc8326-graceful-shutdown-receive"
    }

    fn on_import(&self, route: &mut Route) -> HookVerdict {
        // Same ownership dance as the export hook: take the attribute
        // bag, consult it through the typed view, put it back either
        // way.
        let mut attrs: PathAttributes = core::mem::take(&mut route.attributes).into();
        if attrs.has_community(Community::GRACEFUL_SHUTDOWN) {
            // RFC 8326 §4.1: "sets the LOCAL_PREF attribute of the
            // paths tagged with the GRACEFUL_SHUTDOWN community to a
            // low value".
            attrs.set_local_pref(self.low_local_pref);
        }
        route.attributes = attrs.into();
        HookVerdict::Keep
    }
}

/// RFC 2439 route flap damping import hook (D4.3).
///
/// Wraps an [`Arc<Mutex<DampingTable>>`] so the same table is shared
/// across all sessions on the router. The hook implements both sides
/// of the damping algorithm:
///
/// * **`on_import`** — first decays the per-prefix figure-of-merit
///   to "now" via [`DampingTable::on_announce`]; then, if the
///   prefix is currently suppressed, returns [`HookVerdict::Drop`]
///   so the route never enters Adj-RIB-In.
/// * **`on_withdraw`** — calls [`DampingTable::on_withdraw`] to
///   increment the figure-of-merit. A withdraw that pushes FoM
///   past the suppress threshold marks the prefix as suppressed;
///   subsequent imports will be dropped until the FoM decays back
///   below the reuse threshold.
///
/// The hook is shared across the import path and the withdraw
/// notification path — both must see the same table for the
/// figure-of-merit to be accurate. The daemon installs one hook
/// instance per router; embedders wiring damping by hand should do
/// the same.
///
/// The decay itself (the exponential FoM reduction over time) is
/// driven by the daemon's periodic ticker thread calling
/// [`DampingTable::decay_all`]; the hook does not run a timer of
/// its own.
///
/// **Note on RFC 7196.** Route flap damping with the RFC 2439
/// defaults is documented as harmful by RFC 7196 — most operators
/// turn RFD off on Internet-facing eBGP. The daemon ships damping
/// disabled by default; the operator opts in via `[damping]
/// enabled = true`.
///
/// **Runtime toggle.** The hook carries a shared `enabled` flag
/// ([`DampingImportHook::enabled_handle`]) so the daemon can flip
/// damping on or off from a SIGHUP / runtime-API reload without
/// removing the hook from the import chain. When the flag is
/// `false`, [`ImportHook::on_import`] returns [`HookVerdict::Keep`]
/// and [`ImportHook::on_withdraw`] is a no-op — every route flows
/// through unchanged, no FoM is recorded, no prefix is suppressed.
/// The daemon pairs the flag flip with starting / stopping the
/// decay ticker thread so a disabled hook does not accumulate
/// figure-of-merit while no decay is running.
#[cfg(feature = "damping")]
#[derive(Debug, Clone)]
pub struct DampingImportHook {
    table: Arc<Mutex<DampingTable>>,
    /// Shared on/off flag. The daemon flips this from another
    /// thread (the SIGHUP reload path); the hook reads it on every
    /// `on_import` / `on_withdraw` invocation with a relaxed
    /// load — the read is essentially free and a torn read is
    /// harmless because the daemon sets the flag once and then
    /// joins the writer side with a release on the router lock.
    enabled: std::sync::Arc<std::sync::atomic::AtomicBool>,
}

#[cfg(feature = "damping")]
impl DampingImportHook {
    /// Wrap a damping table for installation on the import hook chain.
    /// The `Arc<Mutex<_>>` is shared with the daemon's decay ticker
    /// so the same table is mutated from both code paths. The hook
    /// starts **enabled**; use [`Self::with_enabled`] to wire a
    /// shared on/off flag the daemon can flip at runtime.
    pub fn new(table: Arc<Mutex<DampingTable>>) -> Self {
        Self {
            table,
            enabled: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true)),
        }
    }

    /// Like [`Self::new`] but with a caller-supplied `enabled` flag.
    /// The flag is shared with the daemon so a SIGHUP-driven reload
    /// can disable the hook in-place (the hook pass-throughs while
    /// the flag is `false`) and re-enable it later without
    /// reinstalling the hook on the import chain.
    pub fn with_enabled(
        table: Arc<Mutex<DampingTable>>,
        enabled: std::sync::Arc<std::sync::atomic::AtomicBool>,
    ) -> Self {
        Self { table, enabled }
    }

    /// Borrow the underlying shared table handle. Used by the daemon
    /// ticker thread to drive periodic `decay_all` calls without
    /// taking ownership of the table.
    pub fn shared_table(&self) -> Arc<Mutex<DampingTable>> {
        Arc::clone(&self.table)
    }

    /// Borrow the shared on/off flag. Used by the daemon's SIGHUP /
    /// runtime-API reload path to flip damping on or off in-place
    /// without reinstalling the hook on the import chain.
    pub fn enabled_handle(&self) -> std::sync::Arc<std::sync::atomic::AtomicBool> {
        std::sync::Arc::clone(&self.enabled)
    }
}

#[cfg(feature = "damping")]
impl ImportHook for DampingImportHook {
    fn name(&self) -> &str {
        "rfc2439-damping"
    }

    fn on_import(&self, route: &mut Route) -> HookVerdict {
        // The daemon flips this flag from the SIGHUP reload path. A
        // disabled hook pass-throughs so routes flow unchanged — the
        // FoM table is left untouched (no decay, no increments), so
        // re-enabling later resumes from whatever state the table
        // was in when damping was last active. Relaxed load is safe:
        // the daemon's writer side joins via the router write lock
        // before the next import, so every route sees a consistent
        // flag state per import call.
        if !self.enabled.load(std::sync::atomic::Ordering::Relaxed) {
            return HookVerdict::Keep;
        }
        // The router sets `route.age_ms` to `now_ms` immediately
        // before invoking import hooks (instance.rs:2304), so we
        // can read it back to get the current wall-clock. Convert
        // to seconds (the unit DampingTable expects).
        let now_s = route.age_ms / 1000;
        let mut table = match self.table.lock() {
            Ok(g) => g,
            // A poisoned mutex means another thread panicked while
            // holding the lock. Drop the route rather than risk
            // importing an unsuppressed prefix.
            Err(_) => return HookVerdict::Drop,
        };
        // RFC 2439 §4.2: on the reachable transition (re-announce),
        // decay the FoM to now and apply the re-announce increment.
        // Cisco's variant (which we mirror, see lr_damping docs)
        // adds `reuse * (1 - decay_factor_withdrawn)` on each
        // re-announce.
        let _ = table.on_announce(&route.key.prefix, now_s);
        if table.is_suppressed(&route.key.prefix) {
            HookVerdict::Drop
        } else {
            HookVerdict::Keep
        }
    }

    fn on_withdraw(&self, _origin: RouteOrigin, key: &RouteKey, now_s: u64) {
        if !self.enabled.load(std::sync::atomic::Ordering::Relaxed) {
            return;
        }
        let mut table = match self.table.lock() {
            Ok(g) => g,
            Err(_) => return,
        };
        // RFC 2439 §4.2: on the unreachable transition (withdraw),
        // decay the FoM to now and add `additive_incr`. If the new
        // FoM crosses the suppress threshold, mark the prefix as
        // suppressed — future imports will be dropped until FoM
        // decays back below the reuse threshold.
        let _ = table.on_withdraw(&key.prefix, now_s);
    }
}

/// Peer-level flap suppression import hook (issue #99).
///
/// Wraps a shared [`lr_peer_health::PeerHealthTable`] and installs
/// it on the import chain. On every accepted UPDATE the hook
/// accounts the event and, when the rollout mode stamps tiers
/// (`limited` / `full`), stamps the `LrPeerHealthTier` attribute on
/// the route so `BestPath::rank_tiered` can prefer non-degraded
/// paths. Stale markings (`LrPeerHealthStale`) are applied **only
/// when a peer transitions into a degraded tier** — the
/// `PeerHealthTable::escalate_and_mark_stale` path records every
/// prefix the peer advertises as stale so ECMP can exclude it.
///
/// A fresh UPDATE from a degraded peer **re-admits** its prefix
/// (clears the stale marker) per issue #99 §Recovery: "re-admit
/// them on a valid UPDATE or via a rate-limited sweep." The hook
/// therefore calls `readmit` before stamping; it does **not** re-mark
/// stale on a fresh advertisement (a fresh UPDATE is the valid
/// re-admission signal the issue describes).
///
/// Shadow modes (`observe`, `shadow`, `shadow-best-path`) never
/// stamp the attribute, so the speaker's standard `BestPath::rank`
/// is used and routing is unaffected. The `shadow-best-path`
/// comparison (would-be best path under tiering vs. actual best
/// path) is delivered by the separate
/// [`PeerHealthShadowSelectionHook`], which records the divergence
/// without changing the comparator's return value.
///
/// The hook never tears down sessions, never withdraws routes,
/// and never modifies standard BGP path attributes. Fails OPEN on
/// a poisoned mutex (keeping the route) to avoid black-holing
/// prefixes.
#[cfg(feature = "peer-health")]
#[derive(Debug, Clone)]
pub struct PeerHealthImportHook {
    table: Arc<Mutex<lr_peer_health::PeerHealthTable>>,
}

#[cfg(feature = "peer-health")]
impl PeerHealthImportHook {
    pub fn new(table: Arc<Mutex<lr_peer_health::PeerHealthTable>>) -> Self {
        Self { table }
    }

    pub fn shared_table(&self) -> Arc<Mutex<lr_peer_health::PeerHealthTable>> {
        Arc::clone(&self.table)
    }
}

#[cfg(feature = "peer-health")]
impl ImportHook for PeerHealthImportHook {
    fn name(&self) -> &str {
        "peer-health-flap-suppression"
    }

    fn on_import(&self, route: &mut Route) -> HookVerdict {
        if route.protocol != lr_core::rib::Protocol::Bgp {
            return HookVerdict::Keep;
        }
        let peer_id = route.origin.peer;
        let family = route.key.family;
        let now_ms = route.age_ms;
        let prefix = route.key.prefix;

        let mut table = match self.table.lock() {
            Ok(g) => g,
            // Poisoned mutex: keep the route (fail-open) so a
            // peer-health panic does not black-hole prefixes.
            Err(_) => return HookVerdict::Keep,
        };

        // Account the UPDATE; the table runs its state machine and
        // may escalate the peer's tier. If escalation fires, the
        // table marks every prefix previously seen from this peer
        // stale (issue #99 §Recovery: "Mark affected prefixes
        // stale"). The returned tier is the effective tier after
        // any caps (e.g. `limited` mode caps at L1).
        let tier = table.account_update(peer_id, family, now_ms);
        // Record this prefix in the peer's advertisement set so a
        // future escalation marks it stale. This must happen AFTER
        // `account_update` so the current escalation (if any) sees
        // the prefix as already observed — but the escalation path
        // inside `apply_transition` iterates the set as it stood at
        // the moment of escalation, so a prefix that arrives in the
        // same UPDATE that trips escalation is recorded but not
        // marked stale by this escalation (it will be marked stale
        // by the next escalation, if any). The fresh-UPDATE
        // re-admission below clears any stale marker this prefix
        // might have carried from a prior escalation, so the route
        // is fresh.
        table.observe_prefix(peer_id, family, &prefix);
        let applies_stale = table.config().rollout.applies_stale();
        let stamps_tier = table.config().rollout.stamps_tier();

        // A fresh UPDATE is a re-admission signal (issue #99
        // §Recovery: "re-admit them on a valid UPDATE"). Clear the
        // stale marker for this prefix unconditionally — the
        // escalation path above may have re-marked the peer's
        // *other* prefixes stale, but this specific prefix just got
        // a fresh advertisement and is no longer stale.
        if applies_stale {
            table.readmit(peer_id, family, &prefix);
        }

        // Stamp the tier attribute only in modes that affect
        // selection (`limited` / `full`). Shadow modes do not
        // stamp, so `BestPath::rank` (not `rank_tiered`) runs and
        // routing is unaffected.
        if stamps_tier {
            let mut attrs: PathAttributes = core::mem::take(&mut route.attributes).into();
            attrs.set_peer_health_tier(tier.as_u8());
            route.attributes = attrs.into();
        }

        HookVerdict::Keep
    }

    fn on_withdraw(&self, origin: RouteOrigin, key: &RouteKey, now_s: u64) {
        let mut table = match self.table.lock() {
            Ok(g) => g,
            Err(_) => return,
        };
        let now_ms = now_s.saturating_mul(1000);
        // Account the withdraw at the correct (peer, family) — the
        // trait's `origin` parameter carries the peer id (issue #99
        // §Hooks: "per peer + AFI/SAFI update rate and RIB churn
        // rate"). Withdrawals are churn; counting them at peer 0
        // would corrupt every session's baseline.
        let _ = table.account_withdraw(origin.peer, key.family, now_ms);
        // Retire the prefix from the peer's advertisement set so
        // future escalations do not mark stale prefixes that are no
        // longer in the RIB. Also clear any existing stale marker
        // (the prefix is gone from Adj-RIB-In).
        if table.config().rollout.applies_stale() {
            table.forget_prefix(origin.peer, key.family, &key.prefix);
            table.readmit(origin.peer, key.family, &key.prefix);
        }
    }
}

/// Shadow-best-path comparison hook (issue #99 §Rollout phase 3).
///
/// Installed **only** when the rollout mode is `shadow-best-path`.
/// The hook never stamps the `LrPeerHealthTier` attribute, so the
/// speaker's `BestPath::rank` (standard) selects the actual best
/// path. This hook observes the comparison the speaker is about to
/// make, computes the **would-be** ordering under tiering (using
/// the table's current tier for each route's peer), and records a
/// divergence counter when the two orderings disagree. It always
/// returns `None` so the default comparator runs unchanged.
///
/// The counters are read by `lrctl show peer-health` and by the
/// daemon's periodic log line; they are the data the issue's
/// "Shadow comparisons show no fallback black-hole events and
/// limited degraded-to-degraded path switches" acceptance
/// criterion is checked against.
#[cfg(feature = "peer-health")]
#[derive(Debug)]
pub struct PeerHealthShadowSelectionHook {
    table: Arc<Mutex<lr_peer_health::PeerHealthTable>>,
    /// Count of `compare(a, b)` calls where the tiered ordering
    /// disagreed with the standard ordering. Monotonic; read by
    /// `lrctl show peer-health`.
    pub divergences: std::sync::atomic::AtomicU64,
}

#[cfg(feature = "peer-health")]
impl PeerHealthShadowSelectionHook {
    pub fn new(table: Arc<Mutex<lr_peer_health::PeerHealthTable>>) -> Self {
        Self {
            table,
            divergences: std::sync::atomic::AtomicU64::new(0),
        }
    }

    /// Read the divergence counter. Used by `lrctl show peer-health`.
    pub fn divergences(&self) -> u64 {
        self.divergences.load(std::sync::atomic::Ordering::Relaxed)
    }
}

#[cfg(feature = "peer-health")]
impl SelectionHook for PeerHealthShadowSelectionHook {
    fn name(&self) -> &str {
        "peer-health-shadow-best-path"
    }

    fn compare(&self, a: &Route, b: &Route) -> Option<Ordering> {
        // Both routes must be BGP for tiering to apply; otherwise
        // there is nothing to compare (the default comparator
        // handles cross-protocol ordering).
        if a.protocol != lr_core::rib::Protocol::Bgp || b.protocol != lr_core::rib::Protocol::Bgp {
            return None;
        }
        let Ok(table) = self.table.lock() else {
            return None;
        };
        // Use the INTERNAL tier (what the state machine computed,
        // before the rollout-mode mask) — `tier()` returns L0 in
        // shadow modes, which would hide every divergence.
        let tier_a = table.internal_tier(a.origin.peer, a.key.family);
        let tier_b = table.internal_tier(b.origin.peer, b.key.family);
        // If both peers are at L0, the tiered ordering cannot
        // differ from the standard ordering — skip the comparison.
        if tier_a == lr_peer_health::PeerHealthTier::L0
            && tier_b == lr_peer_health::PeerHealthTier::L0
        {
            return None;
        }
        // Compute the would-be ordering under tiering: lower tier
        // wins; if tiers are equal, defer to the standard
        // comparator (no divergence possible).
        let tiered = match tier_a.cmp(&tier_b) {
            Ordering::Equal => return None,
            ord => ord,
        };
        // Compute the standard ordering (without invoking hooks —
        // `BestPath::compare` is a pure function).
        let standard = lr_bgp::best_path::BestPath::compare(
            a,
            b,
            &lr_bgp::best_path::BestPathConfig::default(),
        );
        if tiered != standard {
            self.divergences
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
        // Always defer so the default comparator runs unchanged —
        // shadow-best-path never affects routing.
        None
    }
}

/// Daemon-wide graceful drain (issue #53).
///
/// When the daemon is draining — stopping acceptance of new routes
/// while it gradually withdraws the routes it originated — every
/// inbound UPDATE must be dropped before it reaches Adj-RIB-In. The
/// hook is a thin wrapper around a shared `Arc<AtomicBool>` so the
/// shutdown controller (in `lr-cli`) can flip the gate on entry and
/// flip it back off after the daemon has either completed the drain
/// or aborted it.
///
/// The hook is *informational* in the pipeline sense (it does not
/// inspect or mutate the route) but *blocking* in the verdict sense
/// (`Drop` short-circuits the rest of the import chain — a route
/// dropped here never enters Adj-RIB-In, never reaches the safety
/// net, never participates in selection). This is intentional: the
/// drain posture is "this router is going away, do not let it pick
/// up new state", and the cheapest correct way to express that is
/// to fail-closed at the front of the chain.
///
/// Unlike [`GracefulShutdownImportHook`] (RFC 8326 §4.1), which
/// *de-preferences* tagged routes, this hook *drops all routes*
/// unconditionally while the gate is set. The two are orthogonal:
/// RFC 8326 governs per-peer LOCAL_PREF zeroing for a session in
/// graceful-shutdown maintenance; the drain gate governs the whole
/// router's shutdown posture.
pub struct DrainModeImportHook {
    gate: std::sync::Arc<std::sync::atomic::AtomicBool>,
}

impl DrainModeImportHook {
    /// Construct a hook wired to a shared gate flag. The flag starts
    /// `false` (accepting); the shutdown controller flips it to
    /// `true` while the drain is in progress.
    pub fn new(gate: std::sync::Arc<std::sync::atomic::AtomicBool>) -> Self {
        Self { gate }
    }

    /// Borrow the shared gate so the controller can flip it from
    /// another thread without holding the router lock.
    pub fn gate(&self) -> &std::sync::Arc<std::sync::atomic::AtomicBool> {
        &self.gate
    }
}

impl ImportHook for DrainModeImportHook {
    fn name(&self) -> &str {
        "drain-mode"
    }

    fn on_import(&self, _route: &mut Route) -> HookVerdict {
        if self.gate.load(std::sync::atomic::Ordering::Relaxed) {
            HookVerdict::Drop
        } else {
            HookVerdict::Keep
        }
    }
}

/// RFC 6811 §2 prefix-origin validation hook.
///
/// When installed on the import hook chain, every BGP UPDATE is
/// validated against the supplied [`RoaStore`] *before* it enters
/// Adj-RIB-In. Routes whose origin AS is not authorized by any
/// covering ROA are dropped (`Invalid`); routes that no ROA covers
/// (`NotFound`) and routes that match a covering ROA (`Valid`) pass
/// through unchanged.
///
/// Routes without an origin AS (locally originated, or routes whose
/// AS_PATH is empty / a confed-only sequence) are `NotFound` per
/// RFC 6811 §2 and pass through.
///
/// The hook consults the *current* [`RoaStore`] snapshot per route
/// — the same atomic-swap snapshot the RTR cache refreshes and the
/// `[[roa]]` config reload path replaces. Validation therefore
/// tracks the live cache without recompilation, exactly like the
/// filter DSL's `roa.state` accessor.
///
/// This is the import-pipeline counterpart of the daemon's
/// `DaemonFilterContext::roa_state`: where the daemon runs ROA
/// validation inside a filter DSL evaluation, this hook runs it as
/// a stand-alone import gate for FFI embedders that don't go through
/// the daemon's filter surface. The two paths share the same
/// [`RoaStore`] data.
#[cfg(feature = "bgp")]
#[derive(Debug, Clone)]
pub struct RoaValidationImportHook {
    store: std::sync::Arc<lr_bgp::RoaStore>,
}

#[cfg(feature = "bgp")]
impl RoaValidationImportHook {
    /// Wrap a shared [`RoaStore`] for installation on the import hook
    /// chain. The `Arc` is shared with whatever code path mutates the
    /// store (the FFI's `lr_router_add_roa_entry`, the daemon's RTR
    /// thread, the `[[roa]]` reload path) so the hook always sees the
    /// latest snapshot.
    pub fn new(store: std::sync::Arc<lr_bgp::RoaStore>) -> Self {
        Self { store }
    }

    /// Borrow the underlying shared store handle.
    pub fn shared_store(&self) -> &std::sync::Arc<lr_bgp::RoaStore> {
        &self.store
    }
}

#[cfg(feature = "bgp")]
impl ImportHook for RoaValidationImportHook {
    fn name(&self) -> &str {
        "rfc6811-roa"
    }

    fn on_import(&self, route: &mut Route) -> HookVerdict {
        // RFC 6811 §2: Validity is a function of (prefix, origin AS).
        // A route with no origin AS (empty AS_PATH or a confed-only
        // sequence that did not escape its confederation) is
        // `NotFound` and stays admissible — the daemon's filter
        // surface treats it the same way (see DaemonFilterContext).
        let origin = crate::bgp::as_sequence(route).last().copied();
        let snapshot = self.store.load();
        match snapshot.validate(&route.key.prefix, origin) {
            lr_bgp::RoaState::Invalid => HookVerdict::Drop,
            lr_bgp::RoaState::Valid | lr_bgp::RoaState::NotFound => HookVerdict::Keep,
        }
    }
}

/// A collection of hooks + safety net configuration. Aggregated by the
/// router instance and invoked at the appropriate pipeline stages.
#[derive(Default)]
pub struct HookChain {
    pub import: Vec<Box<dyn ImportHook>>,
    pub selection: Vec<Box<dyn SelectionHook>>,
    pub export: Vec<Box<dyn ExportHook>>,
}

impl HookChain {
    pub fn new() -> Self {
        Self::default()
    }

    /// Run all import hooks on the route. The final verdict is determined by
    /// the *last* hook that returns `Drop`/`Replace`; otherwise `Keep`.
    pub fn run_import(&self, route: &mut Route) -> HookVerdict {
        let mut verdict = HookVerdict::Keep;
        for h in &self.import {
            let v = h.on_import(route);
            match v {
                HookVerdict::Drop => return HookVerdict::Drop,
                HookVerdict::Replace(r) => {
                    *route = r;
                    verdict = HookVerdict::Keep;
                }
                HookVerdict::Keep => verdict = HookVerdict::Keep,
            }
        }
        verdict
    }

    /// Notify all import hooks that a route was withdrawn. The return
    /// value is intentionally `()` — a withdraw cannot be "dropped"
    /// (the route is already gone from Adj-RIB-In). Implementations
    /// use this notification to update cross-route state such as the
    /// RFC 2439 damping figure-of-merit table or the per-peer
    /// flap-suppression churn counter (issue #99).
    ///
    /// `origin` carries the peer id the withdraw came from — issue
    /// #99's per-peer accounting needs it; older per-prefix hooks
    /// ignore it.
    pub fn run_import_withdraw(&self, origin: RouteOrigin, key: &RouteKey, now_s: u64) {
        for h in &self.import {
            h.on_withdraw(origin, key, now_s);
        }
    }

    /// Run all selection hooks; the first that returns `Some(Ordering)`
    /// wins; otherwise `None` (caller falls back to the default comparator).
    pub fn run_selection(&self, a: &Route, b: &Route) -> Option<Ordering> {
        for h in &self.selection {
            if let Some(ord) = h.compare(a, b) {
                return Some(ord);
            }
        }
        None
    }

    /// Run all export hooks on the route.
    pub fn run_export(&self, route: &mut Route) -> HookVerdict {
        self.run_export_to(route, u64::MAX)
    }

    /// Run all export hooks with the destination session id. Hooks
    /// that do not override [`ExportHook::on_export_to`] behave
    /// exactly as under [`HookChain::run_export`].
    pub fn run_export_to(&self, route: &mut Route, destination: u64) -> HookVerdict {
        let mut verdict = HookVerdict::Keep;
        for h in &self.export {
            let v = h.on_export_to(route, destination);
            match v {
                HookVerdict::Drop => return HookVerdict::Drop,
                HookVerdict::Replace(r) => {
                    *route = r;
                    verdict = HookVerdict::Keep;
                }
                HookVerdict::Keep => verdict = HookVerdict::Keep,
            }
        }
        verdict
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lr_core::addr::Prefix;
    use lr_core::nlri::NlriFamily;
    use lr_core::rib::{Preference, Protocol, RouteKey, RouteOrigin};

    fn route(prefix: [u8; 4], plen: u8, peer: u64) -> Route {
        Route {
            key: RouteKey::new(Prefix::new_v4(prefix, plen), NlriFamily::IPV4_UNICAST),
            origin: RouteOrigin { proto: 0, peer },
            protocol: Protocol::Bgp,
            preference: Preference::new(20, 100),
            next_hop: None,
            attributes: lr_core::attr::Attributes::new(),
            age_ms: 0,
            path_id: 0,
            tag: None,
        }
    }

    struct DropPrefixHook;
    impl ImportHook for DropPrefixHook {
        fn on_import(&self, r: &mut Route) -> HookVerdict {
            if r.key
                .prefix
                .contains(&lr_core::addr::IpAddr::V4([10, 0, 0, 1]))
                && r.key.prefix.prefix_len <= 8
            {
                HookVerdict::Drop
            } else {
                HookVerdict::Keep
            }
        }
    }

    struct PreferPeerHook(u64);
    impl SelectionHook for PreferPeerHook {
        fn compare(&self, a: &Route, b: &Route) -> Option<Ordering> {
            if a.origin.peer == self.0 && b.origin.peer != self.0 {
                Some(Ordering::Less)
            } else if a.origin.peer != self.0 && b.origin.peer == self.0 {
                Some(Ordering::Greater)
            } else {
                None
            }
        }
    }

    struct AddTagHook;
    impl ExportHook for AddTagHook {
        fn on_export(&self, r: &mut Route) -> HookVerdict {
            r.preference.metric += 1;
            HookVerdict::Keep
        }
    }

    #[test]
    fn drop_hook_drops_matching_route() {
        let chain = HookChain {
            import: vec![Box::new(DropPrefixHook)],
            selection: vec![],
            export: vec![],
        };
        let mut r = route([10, 0, 0, 0], 8, 1);
        assert!(matches!(chain.run_import(&mut r), HookVerdict::Drop));
    }

    #[test]
    fn drop_hook_passes_through_non_matching() {
        let chain = HookChain {
            import: vec![Box::new(DropPrefixHook)],
            selection: vec![],
            export: vec![],
        };
        let mut r = route([192, 168, 0, 0], 24, 1);
        assert!(matches!(chain.run_import(&mut r), HookVerdict::Keep));
    }

    #[test]
    fn selection_hook_can_force_preference() {
        let chain = HookChain {
            import: vec![],
            selection: vec![Box::new(PreferPeerHook(1))],
            export: vec![],
        };
        let a = route([10, 0, 0, 0], 8, 1);
        let b = route([10, 0, 0, 0], 8, 2);
        // Prefer peer 1 (a) — should return Less.
        assert_eq!(chain.run_selection(&a, &b), Some(Ordering::Less));
    }

    #[test]
    fn export_hook_can_modify_route() {
        let chain = HookChain {
            import: vec![],
            selection: vec![],
            export: vec![Box::new(AddTagHook)],
        };
        let mut r = route([10, 0, 0, 0], 8, 1);
        let initial_metric = r.preference.metric;
        let _ = chain.run_export(&mut r);
        assert_eq!(r.preference.metric, initial_metric + 1);
    }

    /// Helper: build a route whose attribute bag carries a single
    /// LOCAL_PREF attribute at the supplied value. Used by the
    /// RFC 8326 hook tests below.
    #[cfg(feature = "bgp")]
    fn route_with_local_pref(prefix: [u8; 4], plen: u8, peer: u64, lp: u32) -> Route {
        let mut r = route(prefix, plen, peer);
        let mut attrs: PathAttributes = r.attributes.clone().into();
        attrs.set_local_pref(lp);
        r.attributes = attrs.into();
        r
    }

    /// Helper: attach a community to a route's attribute bag.
    #[cfg(feature = "bgp")]
    fn attach_community(r: &mut Route, c: Community) {
        let mut attrs: PathAttributes = r.attributes.clone().into();
        attrs.insert_community(c);
        r.attributes = attrs.into();
    }

    /// Helper: read LOCAL_PREF back from a route (None if absent).
    #[cfg(feature = "bgp")]
    fn local_pref_of(r: &Route) -> Option<u32> {
        let attrs: PathAttributes = r.attributes.clone().into();
        attrs.local_pref().map(|lp| lp.0)
    }

    /// Helper: check whether the route still carries a community.
    #[cfg(feature = "bgp")]
    fn has_community(r: &Route, c: Community) -> bool {
        let attrs: PathAttributes = r.attributes.clone().into();
        attrs.has_community(c)
    }

    #[cfg(feature = "bgp")]
    #[test]
    fn graceful_shutdown_zeroes_local_pref_when_community_present() {
        // RFC 8326 §3.1: a route carrying the GRACEFUL_SHUTDOWN
        // community on export must have LOCAL_PREF set to zero so
        // receivers prefer alternatives.
        let mut r = route_with_local_pref([203, 0, 113, 0], 24, 1, 100);
        attach_community(&mut r, Community::GRACEFUL_SHUTDOWN);
        let hook = GracefulShutdownExportHook::new();
        let verdict = hook.on_export(&mut r);
        assert!(
            matches!(verdict, HookVerdict::Keep),
            "hook must keep, not drop"
        );
        assert_eq!(local_pref_of(&r), Some(0), "LOCAL_PREF must be zeroed");
        assert!(
            has_community(&r, Community::GRACEFUL_SHUTDOWN),
            "GRACEFUL_SHUTDOWN community must be preserved"
        );
    }

    #[cfg(feature = "bgp")]
    #[test]
    fn graceful_shutdown_is_noop_when_community_absent() {
        // Routes without the community pass through unchanged — the
        // hook is opt-in via the community marker, never global.
        let mut r = route_with_local_pref([203, 0, 113, 0], 24, 1, 100);
        let hook = GracefulShutdownExportHook::new();
        let _ = hook.on_export(&mut r);
        assert_eq!(local_pref_of(&r), Some(100), "LOCAL_PREF must be preserved");
        assert!(
            !has_community(&r, Community::GRACEFUL_SHUTDOWN),
            "no community should have been added"
        );
    }

    #[cfg(feature = "bgp")]
    #[test]
    fn graceful_shutdown_inserts_local_pref_when_absent() {
        // RFC 8326 §3.1 does not require LOCAL_PREF to pre-exist on
        // the route. If the attribute is absent (e.g. eBGP-learned
        // route), the hook still injects LOCAL_PREF=0 so the
        // receiver's import path sees the explicit "least preferred"
        // signal rather than a default-100 fallback.
        let mut r = route([203, 0, 113, 0], 24, 1);
        attach_community(&mut r, Community::GRACEFUL_SHUTDOWN);
        assert!(local_pref_of(&r).is_none(), "precondition: no LOCAL_PREF");
        let hook = GracefulShutdownExportHook::new();
        let _ = hook.on_export(&mut r);
        assert_eq!(
            local_pref_of(&r),
            Some(0),
            "LOCAL_PREF must be inserted at zero"
        );
    }

    #[cfg(feature = "bgp")]
    #[test]
    fn graceful_shutdown_is_idempotent() {
        // Running the hook twice must not produce a different
        // result — the second pass finds LOCAL_PREF already at 0
        // and is a no-op.
        let mut r = route_with_local_pref([203, 0, 113, 0], 24, 1, 100);
        attach_community(&mut r, Community::GRACEFUL_SHUTDOWN);
        let hook = GracefulShutdownExportHook::new();
        let _ = hook.on_export(&mut r);
        assert_eq!(local_pref_of(&r), Some(0));
        let _ = hook.on_export(&mut r);
        assert_eq!(local_pref_of(&r), Some(0));
    }

    #[cfg(feature = "bgp")]
    #[test]
    fn graceful_shutdown_legacy_planned_shutdown_alias_triggers_hook() {
        // RFC 8326 renamed PLANNED_SHUTDOWN (draft-ietf-idr-shutdown)
        // to GRACEFUL_SHUTDOWN at the same wire value
        // (0xFFFF:0000). Configs using the legacy alias must still
        // trigger the hook.
        let mut r = route_with_local_pref([203, 0, 113, 0], 24, 1, 100);
        attach_community(&mut r, Community::PLANNED_SHUTDOWN);
        let hook = GracefulShutdownExportHook::new();
        let _ = hook.on_export(&mut r);
        assert_eq!(local_pref_of(&r), Some(0));
    }

    #[cfg(feature = "bgp")]
    #[test]
    fn graceful_shutdown_runs_in_hook_chain() {
        // Verify the hook composes with the HookChain plumbing the
        // router actually uses (HookChain::run_export).
        let chain = HookChain {
            import: vec![],
            selection: vec![],
            export: vec![Box::new(GracefulShutdownExportHook::new())],
        };
        let mut r = route_with_local_pref([203, 0, 113, 0], 24, 1, 100);
        attach_community(&mut r, Community::GRACEFUL_SHUTDOWN);
        let _ = chain.run_export(&mut r);
        assert_eq!(local_pref_of(&r), Some(0));
    }

    // ==== GracefulShutdownImportHook (RFC 8326 §4.1) tests ====

    #[cfg(feature = "bgp")]
    #[test]
    fn gs_receive_hook_lowers_local_pref_when_community_present() {
        // RFC 8326 §4.1: the inbound policy "sets the LOCAL_PREF
        // attribute of the paths tagged with the GRACEFUL_SHUTDOWN
        // community to a low value" — the RECOMMENDED value 0 (FRR
        // BGP_GSHUT_LOCAL_PREF).
        let mut r = route_with_local_pref([203, 0, 113, 0], 24, 1, 100);
        attach_community(&mut r, Community::GRACEFUL_SHUTDOWN);
        let hook = GracefulShutdownImportHook::new();
        let verdict = hook.on_import(&mut r);
        assert!(matches!(verdict, HookVerdict::Keep), "hook must keep");
        assert_eq!(local_pref_of(&r), Some(0), "LOCAL_PREF must drop to 0");
        assert!(
            has_community(&r, Community::GRACEFUL_SHUTDOWN),
            "the community itself must be retained (§3.1)"
        );
    }

    #[cfg(feature = "bgp")]
    #[test]
    fn gs_receive_hook_is_noop_when_community_absent() {
        // Untagged imports pass through byte-identical — the RFC
        // inbound policy matches *on* the community, nothing else.
        let mut r = route_with_local_pref([203, 0, 113, 0], 24, 1, 100);
        let hook = GracefulShutdownImportHook::new();
        let _ = hook.on_import(&mut r);
        assert_eq!(local_pref_of(&r), Some(100), "LOCAL_PREF must be untouched");
    }

    #[cfg(feature = "bgp")]
    #[test]
    fn gs_receive_hook_inserts_low_local_pref_when_attribute_absent() {
        // An eBGP-learned route may arrive without LOCAL_PREF at all;
        // the hook still injects the low value so the attribute is
        // explicit before the decision process and iBGP propagation.
        let mut r = route([203, 0, 113, 0], 24, 1);
        attach_community(&mut r, Community::GRACEFUL_SHUTDOWN);
        assert!(local_pref_of(&r).is_none(), "precondition: no LOCAL_PREF");
        let hook = GracefulShutdownImportHook::new();
        let _ = hook.on_import(&mut r);
        assert_eq!(local_pref_of(&r), Some(0));
    }

    #[cfg(feature = "bgp")]
    #[test]
    fn gs_receive_hook_honours_configured_low_value() {
        // Operators may prefer a small non-zero LOCAL_PREF (e.g. 1)
        // so the path still beats genuinely broken alternatives.
        let mut r = route_with_local_pref([203, 0, 113, 0], 24, 1, 100);
        attach_community(&mut r, Community::GRACEFUL_SHUTDOWN);
        let hook = GracefulShutdownImportHook::with_low_local_pref(1);
        assert_eq!(hook.low_local_pref(), 1);
        let _ = hook.on_import(&mut r);
        assert_eq!(local_pref_of(&r), Some(1));
    }

    #[cfg(feature = "bgp")]
    #[test]
    fn gs_receive_hook_is_idempotent() {
        // Running the hook twice must not change the outcome — the
        // second pass finds LOCAL_PREF already at the low value.
        let mut r = route_with_local_pref([203, 0, 113, 0], 24, 1, 100);
        attach_community(&mut r, Community::GRACEFUL_SHUTDOWN);
        let hook = GracefulShutdownImportHook::new();
        let _ = hook.on_import(&mut r);
        assert_eq!(local_pref_of(&r), Some(0));
        let _ = hook.on_import(&mut r);
        assert_eq!(local_pref_of(&r), Some(0));
    }

    #[cfg(feature = "bgp")]
    #[test]
    fn gs_receive_hook_runs_in_hook_chain() {
        // The daemon installs the hook on the import chain next to
        // the damping hook; the chain must dispatch it correctly.
        let chain = HookChain {
            import: vec![Box::new(GracefulShutdownImportHook::new())],
            selection: vec![],
            export: vec![],
        };
        let mut r = route_with_local_pref([203, 0, 113, 0], 24, 1, 100);
        attach_community(&mut r, Community::GRACEFUL_SHUTDOWN);
        let _ = chain.run_import(&mut r);
        assert_eq!(local_pref_of(&r), Some(0));
    }

    #[cfg(feature = "bgp")]
    #[test]
    fn gs_export_hook_exempt_sessions_skip_the_rewrite() {
        // The per-peer `graceful_shutdown = false` override materialises
        // as an exempt-session set on the export hook: the exempt
        // destination receives the route untouched, every other
        // destination still sees the §3.1 zeroing.
        let hook = GracefulShutdownExportHook::with_exempt_sessions([7].into_iter().collect());
        assert_eq!(
            hook.exempt_sessions().map(|s| s.len()),
            Some(1),
            "the exempt set is retained for introspection"
        );

        let mut exempted = route_with_local_pref([203, 0, 113, 0], 24, 1, 100);
        attach_community(&mut exempted, Community::GRACEFUL_SHUTDOWN);
        let _ = hook.on_export_to(&mut exempted, 7);
        assert_eq!(
            local_pref_of(&exempted),
            Some(100),
            "exempt destination keeps LOCAL_PREF"
        );

        let mut scoped = route_with_local_pref([203, 0, 113, 0], 24, 1, 100);
        attach_community(&mut scoped, Community::GRACEFUL_SHUTDOWN);
        let _ = hook.on_export_to(&mut scoped, 8);
        assert_eq!(
            local_pref_of(&scoped),
            Some(0),
            "non-exempt destination is still zeroed"
        );

        // The destination-agnostic path (`run_export`) is unaffected by
        // an exempt set — it has no destination to check.
        let mut plain = route_with_local_pref([203, 0, 113, 0], 24, 1, 100);
        attach_community(&mut plain, Community::GRACEFUL_SHUTDOWN);
        let _ = hook.on_export(&mut plain);
        assert_eq!(local_pref_of(&plain), Some(0));
    }

    #[cfg(feature = "bgp")]
    #[test]
    fn gs_export_hook_empty_exempt_set_degrades_to_agnostic() {
        let hook = GracefulShutdownExportHook::with_exempt_sessions(Default::default());
        assert!(
            hook.exempt_sessions().is_none(),
            "an empty set must collapse to None so the hot path stays lookup-free"
        );
        let mut r = route_with_local_pref([203, 0, 113, 0], 24, 1, 100);
        attach_community(&mut r, Community::GRACEFUL_SHUTDOWN);
        let _ = hook.on_export_to(&mut r, 42);
        assert_eq!(local_pref_of(&r), Some(0));
    }

    // ==== DampingImportHook (RFC 2439) tests ====

    /// Helper: build a `DampingImportHook` wrapping a fresh
    /// `DampingTable` with the supplied config.
    #[cfg(feature = "damping")]
    fn damping_hook(
        cfg: lr_damping::DampingConfig,
    ) -> (
        DampingImportHook,
        std::sync::Arc<std::sync::Mutex<lr_damping::DampingTable>>,
    ) {
        let table = std::sync::Arc::new(std::sync::Mutex::new(lr_damping::DampingTable::new(cfg)));
        let hook = DampingImportHook::new(std::sync::Arc::clone(&table));
        (hook, table)
    }

    /// Helper: set a route's `age_ms` to a wall-clock-millis value so
    /// the damping hook (and the peer-health hook, which derives
    /// `now_ms` from `route.age_ms`) can read the event timestamp.
    #[cfg(any(feature = "damping", feature = "peer-health"))]
    fn route_at(prefix: [u8; 4], plen: u8, peer: u64, age_ms: u64) -> Route {
        let mut r = route(prefix, plen, peer);
        r.age_ms = age_ms;
        r
    }

    #[cfg(feature = "damping")]
    #[test]
    fn damping_lets_first_route_through() {
        // A prefix with no history should not be suppressed on its
        // first import — the FoM is 0, below the suppress threshold.
        let (hook, _table) = damping_hook(lr_damping::DampingConfig::default());
        let mut r = route_at([203, 0, 113, 0], 24, 1, 1_000);
        assert!(matches!(hook.on_import(&mut r), HookVerdict::Keep));
    }

    #[cfg(feature = "damping")]
    #[test]
    fn damping_drops_route_after_enough_flaps() {
        // Three withdrawals in rapid succession push the FoM to
        // 3000 (>= suppress threshold 2000). The next import must
        // be dropped.
        let (hook, table) = damping_hook(lr_damping::DampingConfig::default());
        let key = lr_core::rib::RouteKey::new(
            "203.0.113.0/24".parse().unwrap(),
            lr_core::nlri::NlriFamily::IPV4_UNICAST,
        );
        // Simulate three withdraws — each adds 1000 to FoM.
        let origin = RouteOrigin { proto: 0, peer: 1 };
        hook.on_withdraw(origin, &key, 0);
        hook.on_withdraw(origin, &key, 0);
        hook.on_withdraw(origin, &key, 0);
        // The third withdraw crosses the threshold — the prefix
        // is now suppressed.
        assert!(table.lock().unwrap().is_suppressed(&key.prefix));
        // The next import must be dropped.
        let mut r = route_at([203, 0, 113, 0], 24, 1, 1_000);
        assert!(
            matches!(hook.on_import(&mut r), HookVerdict::Drop),
            "suppressed prefix must be dropped on import"
        );
    }

    #[cfg(feature = "damping")]
    #[test]
    fn damping_withdraw_notification_runs_through_hook_chain() {
        // Verify the HookChain plumbing also calls on_withdraw.
        let (hook, table) = damping_hook(lr_damping::DampingConfig::default());
        let chain = HookChain {
            import: vec![Box::new(hook)],
            selection: vec![],
            export: vec![],
        };
        let key = lr_core::rib::RouteKey::new(
            "203.0.113.0/24".parse().unwrap(),
            lr_core::nlri::NlriFamily::IPV4_UNICAST,
        );
        // Three withdraws through the chain.
        let origin = RouteOrigin { proto: 0, peer: 1 };
        chain.run_import_withdraw(origin, &key, 0);
        chain.run_import_withdraw(origin, &key, 0);
        chain.run_import_withdraw(origin, &key, 0);
        assert!(table.lock().unwrap().is_suppressed(&key.prefix));
    }

    #[cfg(feature = "damping")]
    #[test]
    fn damping_shared_table_visible_to_hook_and_caller() {
        // The hook's shared_table() returns the same Arc the caller
        // built — used by the daemon decay ticker to drive
        // decay_all on the same table the hook mutates.
        let (hook, table) = damping_hook(lr_damping::DampingConfig::default());
        assert!(
            std::sync::Arc::ptr_eq(&hook.shared_table(), &table),
            "shared_table() must return the same Arc"
        );
        // Mutating via the hook is visible to the caller's handle.
        let key = lr_core::rib::RouteKey::new(
            "203.0.113.0/24".parse().unwrap(),
            lr_core::nlri::NlriFamily::IPV4_UNICAST,
        );
        hook.on_withdraw(RouteOrigin { proto: 0, peer: 1 }, &key, 0);
        assert_eq!(table.lock().unwrap().entries().count(), 1);
    }

    /// The shared `enabled` flag the daemon flips at SIGHUP time must
    /// gate both `on_import` and `on_withdraw` — when the flag is
    /// `false`, the hook is a pass-through (every import keeps; no
    /// withdraw mutates the FoM table). Mirrors the
    /// `drain_mode_hook_reflects_runtime_gate_flips` shape.
    #[cfg(feature = "damping")]
    #[test]
    fn damping_enabled_flag_passes_through_when_disabled() {
        let table = std::sync::Arc::new(std::sync::Mutex::new(lr_damping::DampingTable::new(
            lr_damping::DampingConfig::default(),
        )));
        let enabled = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true));
        let hook = DampingImportHook::with_enabled(
            std::sync::Arc::clone(&table),
            std::sync::Arc::clone(&enabled),
        );
        // enabled_handle() returns the same Arc the caller built —
        // the daemon flips it from the SIGHUP path without holding
        // the router lock.
        assert!(
            std::sync::Arc::ptr_eq(&hook.enabled_handle(), &enabled),
            "enabled_handle() must return the same Arc"
        );

        // Initially enabled: import is gated by the FoM table (empty
        // → first route passes through).
        let mut r = route_at([203, 0, 113, 0], 24, 1, 1_000);
        assert!(matches!(hook.on_import(&mut r), HookVerdict::Keep));

        // Flip the flag off: every import now passes through even if
        // the FoM table would have suppressed the route. First
        // suppress the prefix through three withdraws so the
        // enabled-state would drop the next import, then flip the
        // flag and verify the disabled hook pass-throughs.
        let key = lr_core::rib::RouteKey::new(
            "203.0.113.0/24".parse().unwrap(),
            lr_core::nlri::NlriFamily::IPV4_UNICAST,
        );
        let origin = RouteOrigin { proto: 0, peer: 1 };
        hook.on_withdraw(origin, &key, 0);
        hook.on_withdraw(origin, &key, 0);
        hook.on_withdraw(origin, &key, 0);
        assert!(table.lock().unwrap().is_suppressed(&key.prefix));

        enabled.store(false, std::sync::atomic::Ordering::Relaxed);
        let mut r = route_at([203, 0, 113, 0], 24, 1, 1_000);
        assert!(
            matches!(hook.on_import(&mut r), HookVerdict::Keep),
            "disabled hook must pass suppressed routes through"
        );

        // A withdraw on a disabled hook must not bump the FoM — the
        // table state is frozen until the daemon re-enables. We
        // snapshot the entry count, withdraw, and assert the FoM
        // did not move (the prefix is still suppressed at the same
        // figure-of-merit; `on_withdraw` would otherwise add another
        // `additive_incr`).
        let fom_before = table
            .lock()
            .unwrap()
            .entries()
            .next()
            .map(|e| e.figure_of_merit)
            .unwrap_or(0.0);
        hook.on_withdraw(origin, &key, 0);
        let fom_after = table
            .lock()
            .unwrap()
            .entries()
            .next()
            .map(|e| e.figure_of_merit)
            .unwrap_or(0.0);
        assert_eq!(
            fom_before, fom_after,
            "disabled hook must not mutate the FoM table on withdraw"
        );

        // Re-enable: the hook resumes gating from the existing FoM
        // state, so the suppressed prefix is dropped again.
        enabled.store(true, std::sync::atomic::Ordering::Relaxed);
        let mut r = route_at([203, 0, 113, 0], 24, 1, 1_000);
        assert!(
            matches!(hook.on_import(&mut r), HookVerdict::Drop),
            "re-enabled hook must resume suppression from the existing FoM"
        );
    }

    /// The default-constructed hook (`new`) is enabled — preserves
    /// backward compatibility for embedders that do not wire a
    /// shared flag.
    #[cfg(feature = "damping")]
    #[test]
    fn damping_default_construction_is_enabled() {
        let table = std::sync::Arc::new(std::sync::Mutex::new(lr_damping::DampingTable::new(
            lr_damping::DampingConfig::default(),
        )));
        let hook = DampingImportHook::new(std::sync::Arc::clone(&table));
        assert!(
            hook.enabled_handle()
                .load(std::sync::atomic::Ordering::Relaxed),
            "DampingImportHook::new must start enabled"
        );
        // A first import with an empty table passes through (FoM 0
        // is below the suppress threshold) — the hook behaves the
        // same as before the enabled flag was added.
        let mut r = route_at([203, 0, 113, 0], 24, 1, 1_000);
        assert!(matches!(hook.on_import(&mut r), HookVerdict::Keep));
    }

    #[test]
    fn drain_mode_hook_passes_when_gate_is_clear() {
        // Default state: gate false → accept every import.
        let gate = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let hook = DrainModeImportHook::new(std::sync::Arc::clone(&gate));
        let mut r = route([203, 0, 113, 0], 24, 1);
        assert!(
            matches!(hook.on_import(&mut r), HookVerdict::Keep),
            "clear gate must let routes through"
        );
        assert_eq!(hook.name(), "drain-mode");
    }

    #[test]
    fn drain_mode_hook_drops_when_gate_is_set() {
        // Drain in progress: gate true → drop every import, regardless
        // of the route's attributes. The route is not mutated — there
        // is nothing to mutate, the gate is purely informational on
        // the route itself.
        let gate = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true));
        let hook = DrainModeImportHook::new(std::sync::Arc::clone(&gate));
        let mut r = route([198, 51, 100, 0], 24, 1);
        assert!(
            matches!(hook.on_import(&mut r), HookVerdict::Drop),
            "set gate must drop every import"
        );
        // The hook's gate() accessor returns the same Arc the caller
        // built — used by the shutdown controller to flip the gate
        // from another thread without holding the router lock.
        assert!(
            std::sync::Arc::ptr_eq(hook.gate(), &gate),
            "gate() must return the same Arc"
        );
    }

    #[test]
    fn drain_mode_hook_reflects_runtime_gate_flips() {
        // The gate is shared: flipping it from another thread must
        // change the verdict the hook returns on the next import.
        let gate = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let hook = DrainModeImportHook::new(std::sync::Arc::clone(&gate));
        let mut r = route([203, 0, 113, 0], 24, 1);
        assert!(matches!(hook.on_import(&mut r), HookVerdict::Keep));
        gate.store(true, std::sync::atomic::Ordering::Relaxed);
        assert!(matches!(hook.on_import(&mut r), HookVerdict::Drop));
        gate.store(false, std::sync::atomic::Ordering::Relaxed);
        assert!(matches!(hook.on_import(&mut r), HookVerdict::Keep));
    }

    // ---- PeerHealthImportHook unit tests (issue #99). ----
    //
    // The hook's contract per issue #99 §Rollout + §Recovery:
    //   - off: no accounting, no stamping.
    //   - observe: accounting only; counters recorded; no stamping.
    //   - shadow: state machine runs (tiers computed); no stamping.
    //   - shadow-best-path: like shadow; no stamping (the
    //     PeerHealthShadowSelectionHook observes divergence).
    //   - limited: stamp tier (capped at L1); stale markings applied
    //     on escalation.
    //   - full: stamp tier (L0..=L3); stale markings applied on
    //     escalation.
    //
    // Stale semantics: a peer's prefixes are marked stale ONLY when
    // the peer escalates into a degraded tier. A fresh UPDATE
    // re-admits (clears stale) — the hook does NOT re-mark stale on
    // a fresh advertisement (issue #99 §Recovery: "re-admit them on
    // a valid UPDATE").

    /// Build a PeerHealthConfig tuned for fast, deterministic
    /// escalation in unit tests: tiny windows, low multipliers,
    /// no min-transition/recovery intervals, no dwell.
    ///
    /// The multipliers are high enough (10x enter) that a 1
    /// event/sec training baseline does NOT trip escalation (short
    /// budget = 10 * 0.1 * 5 = 5; 5 events in 5s = 5, not > 5), but
    /// a 200-event burst in 2 seconds does (200 >> 5).
    #[cfg(feature = "peer-health")]
    fn ph_cfg(mode: lr_peer_health::RolloutMode) -> lr_peer_health::PeerHealthConfig {
        let mut c = lr_peer_health::PeerHealthConfig::default();
        c.rollout = mode;
        c.short_window = lr_peer_health::WindowBudget {
            window_s: 5,
            enter_multiplier: 10.0,
            exit_multiplier: 5.0,
            emergency_multiplier: 50.0,
        };
        c.mid_window = lr_peer_health::WindowBudget {
            window_s: 30,
            enter_multiplier: 10.0,
            exit_multiplier: 5.0,
            emergency_multiplier: 50.0,
        };
        c.long_window = lr_peer_health::WindowBudget {
            window_s: 120,
            enter_multiplier: 10.0,
            exit_multiplier: 5.0,
            emergency_multiplier: 50.0,
        };
        c.baseline_window_s = 480;
        c.min_baseline_rate_eps = 0.1;
        c.min_transition_interval_s = 0;
        c.min_recovery_interval_s = 0;
        c.dwell_s = [0, 0, 0, 0];
        c.max_stale_age_s = 60;
        c.tick_interval_s = 1;
        c.global_budgets = lr_peer_health::GlobalBudgets {
            soft_degraded: 100,
            hard_degraded: 0,
        };
        c
    }

    /// Drive a burst of UPDATEs from one peer to force escalation.
    #[cfg(feature = "peer-health")]
    fn ph_burst(
        hook: &PeerHealthImportHook,
        peer: u64,
        prefix: [u8; 4],
        plen: u8,
        burst_start_ms: u64,
        count: u32,
        gap_ms: u64,
    ) {
        // Train the baseline at 1 event/sec for 10 seconds.
        for i in 0..10u64 {
            let mut r = route_at(prefix, plen, peer, i * 1000);
            let _ = hook.on_import(&mut r);
        }
        // Burst `count` events at `gap_ms` apart starting at
        // `burst_start_ms`.
        let mut now = burst_start_ms;
        for _ in 0..count {
            let mut r = route_at(prefix, plen, peer, now);
            let _ = hook.on_import(&mut r);
            now += gap_ms;
        }
    }

    #[cfg(feature = "peer-health")]
    #[test]
    fn peer_health_off_mode_does_not_stamp_or_account() {
        let table = std::sync::Arc::new(std::sync::Mutex::new(
            lr_peer_health::PeerHealthTable::new(ph_cfg(lr_peer_health::RolloutMode::Off)),
        ));
        let hook = PeerHealthImportHook::new(std::sync::Arc::clone(&table));
        let mut r = route_at([203, 0, 113, 0], 24, 1, 1_000);
        assert!(matches!(hook.on_import(&mut r), HookVerdict::Keep));
        let attrs: PathAttributes = r.attributes.clone().into();
        assert!(!attrs.has_peer_health_tier(), "off mode must not stamp");
        assert!(
            table.lock().unwrap().is_empty(),
            "off mode must not create session state"
        );
    }

    #[cfg(feature = "peer-health")]
    #[test]
    fn peer_health_observe_mode_accounts_without_stamping() {
        let table = std::sync::Arc::new(std::sync::Mutex::new(
            lr_peer_health::PeerHealthTable::new(ph_cfg(lr_peer_health::RolloutMode::Observe)),
        ));
        let hook = PeerHealthImportHook::new(std::sync::Arc::clone(&table));
        ph_burst(&hook, 1, [203, 0, 113, 0], 24, 10_000, 200, 10);
        let snap = table
            .lock()
            .unwrap()
            .session_snapshot(1, lr_core::nlri::NlriFamily::IPV4_UNICAST)
            .unwrap();
        assert!(snap.counters.updates >= 200);
        // Observe mode: the PUBLIC tier (what the hook would stamp)
        // is L0 — observe never stamps. The snapshot's internal tier
        // may be escalated (that's the point of observe: you see
        // what the state machine is computing without affecting
        // routing).
        assert_eq!(
            table
                .lock()
                .unwrap()
                .tier(1, lr_core::nlri::NlriFamily::IPV4_UNICAST),
            lr_peer_health::PeerHealthTier::L0,
            "observe mode must expose L0 as the public tier"
        );
    }

    #[cfg(feature = "peer-health")]
    #[test]
    fn peer_health_shadow_mode_does_not_stamp() {
        let table = std::sync::Arc::new(std::sync::Mutex::new(
            lr_peer_health::PeerHealthTable::new(ph_cfg(lr_peer_health::RolloutMode::Shadow)),
        ));
        let hook = PeerHealthImportHook::new(std::sync::Arc::clone(&table));
        ph_burst(&hook, 1, [203, 0, 113, 0], 24, 10_000, 200, 10);
        // Shadow mode: state machine runs (internal tier may be
        // degraded), but no stamping and the public tier is L0.
        assert_eq!(
            table
                .lock()
                .unwrap()
                .tier(1, lr_core::nlri::NlriFamily::IPV4_UNICAST),
            lr_peer_health::PeerHealthTier::L0,
            "shadow mode must not expose a non-L0 tier publicly"
        );
        // A fresh route from the degraded peer has no tier attribute.
        let mut r = route_at([203, 0, 113, 0], 24, 1, 20_000);
        let _ = hook.on_import(&mut r);
        let attrs: PathAttributes = r.attributes.clone().into();
        assert!(!attrs.has_peer_health_tier(), "shadow mode must not stamp");
    }

    #[cfg(feature = "peer-health")]
    #[test]
    fn peer_health_shadow_best_path_mode_does_not_stamp() {
        // Issue #99 §Rollout phase 3: shadow-best-path must NOT
        // affect routing. The previous implementation stamped the
        // tier attribute in this mode, which made rank_tiered run
        // and actually changed selection — contradicting the
        // "shadow" semantics. This test guards against that
        // regression.
        let table =
            std::sync::Arc::new(std::sync::Mutex::new(lr_peer_health::PeerHealthTable::new(
                ph_cfg(lr_peer_health::RolloutMode::ShadowBestPath),
            )));
        let hook = PeerHealthImportHook::new(std::sync::Arc::clone(&table));
        ph_burst(&hook, 1, [203, 0, 113, 0], 24, 10_000, 200, 10);
        // Public tier is L0 (no stamping).
        assert_eq!(
            table
                .lock()
                .unwrap()
                .tier(1, lr_core::nlri::NlriFamily::IPV4_UNICAST),
            lr_peer_health::PeerHealthTier::L0,
            "shadow-best-path must not expose a non-L0 tier publicly"
        );
        let mut r = route_at([203, 0, 113, 0], 24, 1, 20_000);
        let _ = hook.on_import(&mut r);
        let attrs: PathAttributes = r.attributes.clone().into();
        assert!(
            !attrs.has_peer_health_tier(),
            "shadow-best-path must not stamp the tier attribute"
        );
        assert!(
            !attrs.peer_health_stale(),
            "shadow-best-path must not stamp the stale attribute"
        );
    }

    #[cfg(feature = "peer-health")]
    #[test]
    fn peer_health_limited_mode_caps_tier_at_l1() {
        let table = std::sync::Arc::new(std::sync::Mutex::new(
            lr_peer_health::PeerHealthTable::new(ph_cfg(lr_peer_health::RolloutMode::Limited)),
        ));
        let hook = PeerHealthImportHook::new(std::sync::Arc::clone(&table));
        ph_burst(&hook, 1, [203, 0, 113, 0], 24, 10_000, 200, 10);
        // Limited mode: tier is capped at L1.
        assert_eq!(
            table
                .lock()
                .unwrap()
                .tier(1, lr_core::nlri::NlriFamily::IPV4_UNICAST),
            lr_peer_health::PeerHealthTier::L1,
            "limited mode must cap the public tier at L1"
        );
        // A fresh route from the degraded peer carries the tier
        // attribute, but the stale attribute is cleared (fresh
        // UPDATE re-admits).
        let mut r = route_at([203, 0, 113, 0], 24, 1, 20_000);
        let _ = hook.on_import(&mut r);
        let attrs: PathAttributes = r.attributes.clone().into();
        assert!(attrs.has_peer_health_tier(), "limited mode must stamp tier");
        assert_eq!(attrs.peer_health_tier(), Some(1));
        assert!(
            !attrs.peer_health_stale(),
            "fresh UPDATE must clear stale (re-admission)"
        );
    }

    #[cfg(feature = "peer-health")]
    #[test]
    fn peer_health_full_mode_stamps_tier_and_clears_stale_on_fresh_update() {
        let table = std::sync::Arc::new(std::sync::Mutex::new(
            lr_peer_health::PeerHealthTable::new(ph_cfg(lr_peer_health::RolloutMode::Full)),
        ));
        let hook = PeerHealthImportHook::new(std::sync::Arc::clone(&table));
        // Advertise two prefixes from the peer with monotonic
        // timestamps (interleaved) so the event vec stays sorted
        // and window counts are accurate. Each prefix gets 5
        // UPDATEs over 10 seconds.
        for i in 0..5u64 {
            let mut r = route_at([203, 0, 113, 0], 24, 1, i * 2 * 1000);
            let _ = hook.on_import(&mut r);
            let mut r = route_at([198, 51, 100, 0], 24, 1, (i * 2 + 1) * 1000);
            let _ = hook.on_import(&mut r);
        }
        // Burst on the first prefix to trip escalation.
        let mut now = 10_000u64;
        for _ in 0..200 {
            let mut r = route_at([203, 0, 113, 0], 24, 1, now);
            let _ = hook.on_import(&mut r);
            now += 10;
        }
        // After escalation, the prefix the peer advertised that was
        // NOT part of the burst (198.51.100.0/24) should be stale
        // (marked by apply_transition on escalation, never
        // re-admitted). The burst prefix (203.0.113.0/24) was
        // re-admitted by the last burst UPDATE.
        {
            let t = table.lock().unwrap();
            assert!(
                t.is_stale(
                    1,
                    lr_core::nlri::NlriFamily::IPV4_UNICAST,
                    &"198.51.100.0/24".parse().unwrap()
                ),
                "the non-burst advertised prefix should be stale after escalation"
            );
        }
        // A fresh UPDATE for one of the prefixes re-admits it
        // (clears stale) — the hook does NOT re-mark stale.
        let mut r = route_at([203, 0, 113, 0], 24, 1, now);
        let _ = hook.on_import(&mut r);
        let attrs: PathAttributes = r.attributes.clone().into();
        assert!(attrs.has_peer_health_tier(), "full mode must stamp tier");
        assert!(
            !attrs.peer_health_stale(),
            "fresh UPDATE must clear stale (re-admission, not re-mark)"
        );
        assert!(
            !table.lock().unwrap().is_stale(
                1,
                lr_core::nlri::NlriFamily::IPV4_UNICAST,
                &"203.0.113.0/24".parse().unwrap()
            ),
            "table must clear stale for the re-admitted prefix"
        );
        // The other prefix is still stale (no fresh UPDATE for it).
        assert!(
            table.lock().unwrap().is_stale(
                1,
                lr_core::nlri::NlriFamily::IPV4_UNICAST,
                &"198.51.100.0/24".parse().unwrap()
            ),
            "the non-refreshed prefix must remain stale"
        );
    }

    #[cfg(feature = "peer-health")]
    #[test]
    fn peer_health_on_withdraw_accounts_at_correct_peer() {
        // Issue #99 §Hooks: "per peer + AFI/SAFI update rate and
        // RIB churn rate". The previous implementation attributed
        // every withdraw to peer 0 because the ImportHook trait
        // did not carry the peer id. This test guards against that
        // regression: a withdraw from peer 7 must bump peer 7's
        // withdraw counter, not peer 0's.
        let table = std::sync::Arc::new(std::sync::Mutex::new(
            lr_peer_health::PeerHealthTable::new(ph_cfg(lr_peer_health::RolloutMode::Full)),
        ));
        let hook = PeerHealthImportHook::new(std::sync::Arc::clone(&table));
        // Seed the session with one UPDATE so the table has state.
        let mut r = route_at([203, 0, 113, 0], 24, 7, 1_000);
        let _ = hook.on_import(&mut r);
        // Withdraw from peer 7.
        let key = lr_core::rib::RouteKey::new(
            "203.0.113.0/24".parse().unwrap(),
            lr_core::nlri::NlriFamily::IPV4_UNICAST,
        );
        hook.on_withdraw(RouteOrigin { proto: 0, peer: 7 }, &key, 2);
        // Peer 7's withdraw counter must be >= 1; peer 0 must not
        // exist (or have zero withdraws).
        let snap = table
            .lock()
            .unwrap()
            .session_snapshot(7, lr_core::nlri::NlriFamily::IPV4_UNICAST)
            .expect("peer 7 session must exist");
        assert!(
            snap.counters.withdraws >= 1,
            "withdraw must be attributed to peer 7"
        );
        // Peer 0 must not have been created by the withdraw.
        assert!(
            table
                .lock()
                .unwrap()
                .session_snapshot(0, lr_core::nlri::NlriFamily::IPV4_UNICAST)
                .is_none(),
            "withdraw must not create a spurious peer-0 session"
        );
    }

    #[cfg(feature = "peer-health")]
    #[test]
    fn peer_health_shadow_selection_hook_records_divergence() {
        // The PeerHealthShadowSelectionHook computes the would-be
        // ordering under tiering and records a divergence counter
        // when it disagrees with the standard ordering. It always
        // returns None so the default comparator runs unchanged.
        use lr_bgp::best_path::{BestPath, BestPathConfig};
        use lr_core::rib::Preference;
        let table =
            std::sync::Arc::new(std::sync::Mutex::new(lr_peer_health::PeerHealthTable::new(
                ph_cfg(lr_peer_health::RolloutMode::ShadowBestPath),
            )));
        // Manually escalate peer 1 by bursting the table directly
        // (the import hook would not stamp in shadow-best-path, but
        // the table's internal tier still escalates).
        {
            let mut t = table.lock().unwrap();
            for i in 0..10u64 {
                t.account_update(1, lr_core::nlri::NlriFamily::IPV4_UNICAST, i * 1000);
            }
            let mut now = 10_000u64;
            for _ in 0..200 {
                t.account_update(1, lr_core::nlri::NlriFamily::IPV4_UNICAST, now);
                now += 10;
            }
        }
        let hook = PeerHealthShadowSelectionHook::new(std::sync::Arc::clone(&table));
        // Two routes from peer 1 and peer 2: identical attributes,
        // so the standard comparator picks by peer-id (peer 1 wins).
        // Under tiering, peer 1 is degraded and peer 2 is L0, so
        // the tiered ordering would prefer peer 2 — a divergence.
        let a = Route {
            key: lr_core::rib::RouteKey::new(
                "203.0.113.0/24".parse().unwrap(),
                lr_core::nlri::NlriFamily::IPV4_UNICAST,
            ),
            origin: RouteOrigin { proto: 0, peer: 1 },
            protocol: Protocol::Bgp,
            preference: Preference::new(20, 0),
            next_hop: None,
            attributes: lr_core::attr::Attributes::new(),
            age_ms: 1_000,
            path_id: 0,
            tag: None,
        };
        let b = Route {
            key: lr_core::rib::RouteKey::new(
                "203.0.113.0/24".parse().unwrap(),
                lr_core::nlri::NlriFamily::IPV4_UNICAST,
            ),
            origin: RouteOrigin { proto: 0, peer: 2 },
            protocol: Protocol::Bgp,
            preference: Preference::new(20, 0),
            next_hop: None,
            attributes: lr_core::attr::Attributes::new(),
            age_ms: 1_000,
            path_id: 0,
            tag: None,
        };
        let before = hook.divergences();
        let verdict = hook.compare(&a, &b);
        assert!(
            verdict.is_none(),
            "shadow hook must defer to the default comparator"
        );
        let after = hook.divergences();
        assert!(
            after > before,
            "divergence counter must increment when tiered and standard orderings disagree"
        );
        // Sanity: the standard comparator on these two routes does
        // not panic and returns an ordering (peer 1 wins by lower
        // peer-id after the tiebreakers).
        let _ = BestPath::compare(&a, &b, &BestPathConfig::default());
    }
}
