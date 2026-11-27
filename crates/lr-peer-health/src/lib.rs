//! Per-peer BGP flap suppression.
//!
//! A *softer* alternative to RFC 2439 prefix damping: instead of
//! suppressing unstable prefixes (which leaves them unreachable),
//! `lr-peer-health` temporarily lowers a peer's path preference at
//! session + AFI/SAFI granularity. The session stays up, the
//! prefixes stay reachable, and the blast radius is one peer.

#![forbid(unsafe_code)]
#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(not(feature = "std"))]
extern crate alloc;

#[cfg(not(feature = "std"))]
use alloc::collections::{BTreeMap, BTreeSet};
#[cfg(not(feature = "std"))]
use alloc::vec::Vec;
#[cfg(feature = "std")]
use std::collections::{BTreeMap, BTreeSet};

use core::cmp::Ordering;

use lr_core::addr::Prefix;
use lr_core::nlri::NlriFamily;

pub mod config;
pub mod stale;
pub mod tier;

pub use config::{
    ExclusionKind, GlobalBudgets, PeerHealthConfig, RolloutMode, WindowBudget, WindowKind,
    DEFAULT_LONG_WINDOW_S, DEFAULT_MID_WINDOW_S, DEFAULT_SHORT_WINDOW_S,
};
pub use stale::{StaleEntry, StaleSet, StaleSweepReport};
pub use tier::{PeerHealthTier, MAX_TIER};

/// Per-tick budget state for the global recovery rate limit: at or
/// above the `soft_degraded` budget, at most one session recovers per
/// tick (issue #99 §Global protection's "freeze automatic recovery",
/// without the permanent wedge a full freeze produced — recovery is
/// the only thing that lowers the degraded count).
#[derive(Debug, Clone, Copy, Default)]
struct TickBudget {
    recoveries: u32,
}

#[derive(Debug, Clone, PartialEq)]
pub struct SessionState {
    pub baseline_rate: f64,
    pub last_baseline_ms: u64,
    /// Whether the EWMA baseline has taken its first sample. An
    /// explicit flag rather than a `last_baseline_ms == 0` sentinel:
    /// the router clock is milliseconds-since-daemon-start, so a
    /// session created at any `now_ms > 0` would never match the
    /// sentinel and would blend its first sample against an implicit
    /// zero baseline — badly under-estimating a legitimately chatty
    /// peer's budget.
    pub baseline_seeded: bool,
    pub events: Vec<u64>,
    pub tier: PeerHealthTier,
    pub last_transition_ms: u64,
    pub tier_entered_ms: u64,
    pub backoff: u32,
    pub last_recovery_ms: u64,
    pub last_escalation_ms: u64,
    pub exclusions: Vec<ExclusionWindow>,
    pub counters: SessionCounters,
    pub stale: StaleSet,
    pub pending_escalation: Option<PeerHealthTier>,
    /// All prefixes the peer has advertised (issue #99 §Recovery:
    /// "Mark affected prefixes stale"). Populated by
    /// [`PeerHealthTable::observe_prefix`]; retired by
    /// [`PeerHealthTable::forget_prefix`]. On escalation to a
    /// degraded tier, every prefix in this set is marked stale so
    /// ECMP excludes it (`BestPath::multipath_tiered` skips stale
    /// paths). A fresh UPDATE for a prefix re-admits it (clears
    /// the stale marker) — see `PeerHealthImportHook::on_import`.
    pub prefixes: BTreeSet<Prefix>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ExclusionWindow {
    pub kind: ExclusionKind,
    pub start_ms: u64,
    pub end_ms: u64,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SessionCounters {
    pub updates: u64,
    pub withdraws: u64,
    pub escalations: u64,
    pub recoveries: u64,
    pub escalation_suppressed: u64,
    pub recovery_suppressed: u64,
    pub peak_tier: PeerHealthTier,
}

impl Default for SessionState {
    fn default() -> Self {
        Self {
            baseline_rate: 0.0,
            last_baseline_ms: 0,
            baseline_seeded: false,
            events: Vec::new(),
            tier: PeerHealthTier::L0,
            last_transition_ms: 0,
            tier_entered_ms: 0,
            backoff: 1,
            last_recovery_ms: 0,
            last_escalation_ms: 0,
            exclusions: Vec::new(),
            counters: SessionCounters::default(),
            stale: StaleSet::new(),
            pending_escalation: None,
            prefixes: BTreeSet::new(),
        }
    }
}

impl SessionState {
    fn new(now_ms: u64) -> Self {
        SessionState {
            last_baseline_ms: now_ms,
            last_transition_ms: now_ms,
            tier_entered_ms: now_ms,
            ..Default::default()
        }
    }

    fn prune_events(&mut self, cutoff_ms: u64) {
        // Remove events older than `cutoff_ms`. Events are
        // monotonically non-decreasing in practice (the router's
        // `now_ms` clock never goes backwards), but we filter
        // unconditionally rather than relying on sorted order —
        // a test or embedder that feeds events out of order must
        // not corrupt the window counts.
        self.events.retain(|ts| *ts >= cutoff_ms);
    }

    fn count_in_window(&self, window_s: u64, now_ms: u64) -> u64 {
        let cutoff = now_ms.saturating_sub(window_s.saturating_mul(1000));
        // Linear scan: correct regardless of insertion order. The
        // events vec is bounded by `longest_window_s * peak_rate`
        // and pruned on every `account_event`, so the scan is
        // bounded by the longest window's event count.
        self.events.iter().filter(|ts| **ts >= cutoff).count() as u64
    }

    fn is_excluded(&self, now_ms: u64) -> Option<ExclusionKind> {
        for w in &self.exclusions {
            if now_ms >= w.start_ms && now_ms < w.end_ms {
                return Some(w.kind);
            }
        }
        None
    }

    fn record_event(&mut self, now_ms: u64) {
        self.events.push(now_ms);
    }

    fn compute_baseline(&mut self, now_ms: u64, cfg: &PeerHealthConfig) -> f64 {
        // §Detection: "Maintain an EWMA baseline per session; freeze
        // or restrict baseline updates while degraded." The EWMA is
        // updated only while the session is at L0 AND no detection
        // window is currently over budget — a burst's own events sit
        // in the sample window, so blending during the burst would
        // let an escalating flapper raise its own budget (weaker
        // suppression each cycle) before the tier catches up.
        //
        // The sample is the per-second event rate observed over the
        // baseline window (`count_in_window / baseline_window_s`);
        // the EWMA blends this sample with the prior baseline at
        // `ewma_alpha`. A small alpha (default 0.05) makes the
        // baseline slow-tracking, so a short burst does not blow up
        // the budget against which escalation is measured. The
        // windowed-average sample keeps the EWMA grounded in a
        // representative observation rather than the instantaneous
        // rate (which would be noisy on a quiet session).
        let frozen = self.tier != PeerHealthTier::L0 || self.any_window_tripped(cfg, now_ms);
        if !frozen {
            let count = self.count_in_window(cfg.baseline_window_s, now_ms);
            let window_s = cfg.baseline_window_s.max(1) as f64;
            let sample = (count as f64) / window_s;
            let alpha = cfg.ewma_alpha.clamp(0.0, 1.0);
            self.baseline_rate = if !self.baseline_seeded {
                // First sample seeds the EWMA (an explicit flag: the
                // router clock is ms-since-daemon-start, so a
                // `last_baseline_ms == 0` sentinel can never fire for
                // a session created later than the daemon itself).
                self.baseline_seeded = true;
                sample
            } else {
                alpha * sample + (1.0 - alpha) * self.baseline_rate
            };
            self.last_baseline_ms = now_ms;
        }
        self.baseline_rate
    }

    /// Whether any detection window is currently over budget — the
    /// condition under which the baseline update is frozen (a burst
    /// must not raise its own budget).
    fn any_window_tripped(&self, cfg: &PeerHealthConfig, now_ms: u64) -> bool {
        let baseline_eps = self.baseline_rate.max(cfg.min_baseline_rate_eps);
        let short = self.count_in_window(cfg.short_window.window_s, now_ms);
        let mid = self.count_in_window(cfg.mid_window.window_s, now_ms);
        let long = self.count_in_window(cfg.long_window.window_s, now_ms);
        short > cfg.short_window.budget_for(baseline_eps)
            || mid > cfg.mid_window.budget_for(baseline_eps)
            || long > cfg.long_window.budget_for(baseline_eps)
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct SessionSnapshot {
    pub peer_id: u64,
    pub family: NlriFamily,
    pub baseline_rate: f64,
    pub tier: PeerHealthTier,
    pub pending_escalation: Option<PeerHealthTier>,
    pub last_transition_ms: u64,
    pub tier_entered_ms: u64,
    pub backoff: u32,
    pub short_window_count: u64,
    pub mid_window_count: u64,
    pub long_window_count: u64,
    pub stale_count: usize,
    pub counters: SessionCounters,
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct TickReport {
    pub tier_changes: Vec<(u64, NlriFamily, PeerHealthTier, PeerHealthTier)>,
    pub stale_sweep: StaleSweepReport,
}

#[derive(Debug, Clone)]
pub struct PeerHealthTable {
    cfg: PeerHealthConfig,
    sessions: BTreeMap<(u64, NlriFamily), SessionState>,
    degraded_session_count: u32,
    /// Degraded-session count by the state machine's OWN tiers,
    /// independent of the rollout mask. The budget gates read this so
    /// shadow-mode runs simulate the same global-budget behavior Full
    /// mode would produce (the public `degraded_session_count` stays
    /// masked to L0 in shadow modes for operator-facing output).
    internal_degraded_count: u32,
    peak_tier: PeerHealthTier,
}

impl PeerHealthTable {
    pub fn new(cfg: PeerHealthConfig) -> Self {
        Self {
            cfg,
            sessions: BTreeMap::new(),
            degraded_session_count: 0,
            internal_degraded_count: 0,
            peak_tier: PeerHealthTier::L0,
        }
    }

    pub fn config(&self) -> &PeerHealthConfig {
        &self.cfg
    }

    /// Update the rollout mode in-place (issue #99 §Rollout — SIGHUP
    /// live reload). Session state (baselines, counters, tiers, stale
    /// sets) is preserved across the transition so a mode change does
    /// not lose the EWMA history the state machine has accumulated.
    ///
    /// The daemon's reload path calls this when the freshly-reloaded
    /// `[bgp.peer_health]` block carries a different `rollout` value.
    /// Flipping to `Off` makes `tier()` return `L0` for every session
    /// (routing is unaffected); flipping to `Full` re-enables stamping
    /// and stale marking on the next escalation.
    ///
    /// Window lengths, budgets, and other tuning parameters are NOT
    /// changed here — issue #99 §Rollout: "online parameters should
    /// remain stable during comparison windows." A restart is required
    /// to re-tune the windows.
    pub fn set_rollout_mode(&mut self, rollout: RolloutMode) {
        self.cfg.rollout = rollout;
        // Recompute aggregates so `degraded_session_count` and
        // `peak_tier` reflect the new mode's effective tiers (e.g.
        // flipping to Off zeros them; flipping to Limited re-caps
        // at L1).
        self.recompute_aggregates();
    }

    pub fn len(&self) -> usize {
        self.sessions.len()
    }

    pub fn is_empty(&self) -> bool {
        self.sessions.is_empty()
    }

    pub fn degraded_session_count(&self) -> u32 {
        self.degraded_session_count
    }

    pub fn peak_tier(&self) -> PeerHealthTier {
        self.peak_tier
    }

    pub fn account_update(
        &mut self,
        peer_id: u64,
        family: NlriFamily,
        now_ms: u64,
    ) -> PeerHealthTier {
        self.account_event(peer_id, family, now_ms, true)
    }

    pub fn account_withdraw(
        &mut self,
        peer_id: u64,
        family: NlriFamily,
        now_ms: u64,
    ) -> PeerHealthTier {
        self.account_event(peer_id, family, now_ms, false)
    }

    fn account_event(
        &mut self,
        peer_id: u64,
        family: NlriFamily,
        now_ms: u64,
        is_update: bool,
    ) -> PeerHealthTier {
        if self.cfg.rollout == RolloutMode::Off {
            return PeerHealthTier::L0;
        }
        let entry = self
            .sessions
            .entry((peer_id, family))
            .or_insert_with(|| SessionState::new(now_ms));
        if is_update {
            entry.counters.updates = entry.counters.updates.saturating_add(1);
        } else {
            entry.counters.withdraws = entry.counters.withdraws.saturating_add(1);
        }
        entry.record_event(now_ms);
        entry.exclusions.retain(|w| now_ms < w.end_ms);
        let longest_s = self.cfg.longest_window_s();
        entry.prune_events(now_ms.saturating_sub(longest_s.saturating_mul(1000)));
        // An event-driven run has no tick budget of its own to spend;
        // a fresh one means the soft-budget rate limit applies per
        // event rather than per tick — acceptable because event-driven
        // recoveries also require the session's full dwell+cooldown.
        let mut budget = TickBudget::default();
        self.internal_degraded_count = self
            .sessions
            .values()
            .filter(|s| s.tier > PeerHealthTier::L0)
            .count() as u32;
        self.run_state_machine((peer_id, family), now_ms, &mut budget);
        self.recompute_aggregates();
        let session = self
            .sessions
            .get(&(peer_id, family))
            .expect("just inserted");
        self.cfg.effective_tier(session.tier)
    }

    pub fn mark_exclusion(
        &mut self,
        peer_id: u64,
        family: NlriFamily,
        kind: ExclusionKind,
        start_ms: u64,
        end_ms: u64,
    ) {
        if end_ms <= start_ms {
            return;
        }
        let entry = self
            .sessions
            .entry((peer_id, family))
            .or_insert_with(|| SessionState::new(start_ms));
        entry
            .exclusions
            .retain(|w| w.kind != kind || w.end_ms <= start_ms);
        entry.exclusions.push(ExclusionWindow {
            kind,
            start_ms,
            end_ms,
        });
        entry.exclusions.sort_by_key(|w| w.start_ms);
    }

    pub fn clear_exclusion(
        &mut self,
        peer_id: u64,
        family: NlriFamily,
        kind: ExclusionKind,
        now_ms: u64,
    ) {
        if let Some(entry) = self.sessions.get_mut(&(peer_id, family)) {
            entry
                .exclusions
                .retain(|w| w.kind != kind || w.end_ms <= now_ms);
        }
    }

    /// The **public** tier for `(peer, family)`. This is the tier
    /// the import hook stamps on routes and the tier the speaker's
    /// `BestPath::rank_tiered` sees. Shadow modes (`off`, `observe`,
    /// `shadow`, `shadow-best-path`) return `L0` so routing is
    /// unaffected — issue #99 §Rollout: shadow phases must not
    /// change selection. `limited` returns the effective tier
    /// capped at `L1`; `full` returns the effective tier as-is.
    ///
    /// For the **internal** tier (what the state machine actually
    /// computed, before the rollout-mode mask), use
    /// [`Self::session_snapshot`].
    pub fn tier(&self, peer_id: u64, family: NlriFamily) -> PeerHealthTier {
        if matches!(
            self.cfg.rollout,
            RolloutMode::Off
                | RolloutMode::Observe
                | RolloutMode::Shadow
                | RolloutMode::ShadowBestPath
        ) {
            return PeerHealthTier::L0;
        }
        match self.sessions.get(&(peer_id, family)) {
            Some(s) => self.cfg.effective_tier(s.tier),
            None => PeerHealthTier::L0,
        }
    }

    pub fn is_degraded(&self, peer_id: u64, family: NlriFamily) -> bool {
        self.tier(peer_id, family) != PeerHealthTier::L0
    }

    /// The **internal** tier for `(peer, family)` — what the state
    /// machine actually computed, after the `effective_tier` cap
    /// (e.g. `limited` caps at L1) but BEFORE the rollout-mode
    /// mask. Shadow modes return L0 from [`Self::tier`] (the public
    /// tier) but this method returns the actual escalated tier so
    /// the `PeerHealthShadowSelectionHook` can compute the would-be
    /// best path under tiering.
    ///
    /// Prefer [`Self::tier`] everywhere except shadow-mode
    /// comparison / diagnostics.
    pub fn internal_tier(&self, peer_id: u64, family: NlriFamily) -> PeerHealthTier {
        match self.sessions.get(&(peer_id, family)) {
            Some(s) => self.cfg.effective_tier(s.tier),
            None => PeerHealthTier::L0,
        }
    }

    pub fn session_snapshot(&self, peer_id: u64, family: NlriFamily) -> Option<SessionSnapshot> {
        let s = self.sessions.get(&(peer_id, family))?;
        let now_ms = s.events.last().copied().unwrap_or(s.last_baseline_ms);
        Some(SessionSnapshot {
            peer_id,
            family,
            baseline_rate: s.baseline_rate,
            // The INTERNAL tier — what the state machine computed,
            // after the effective_tier cap (e.g. `limited` caps at
            // L1) but BEFORE the rollout-mode mask. Shadow modes
            // return L0 from `tier()` (the public tier) but the
            // snapshot shows the actual escalated tier so operators
            // can see what the state machine is doing.
            tier: self.cfg.effective_tier(s.tier),
            pending_escalation: s.pending_escalation,
            last_transition_ms: s.last_transition_ms,
            tier_entered_ms: s.tier_entered_ms,
            backoff: s.backoff,
            short_window_count: s.count_in_window(self.cfg.short_window.window_s, now_ms),
            mid_window_count: s.count_in_window(self.cfg.mid_window.window_s, now_ms),
            long_window_count: s.count_in_window(self.cfg.long_window.window_s, now_ms),
            stale_count: s.stale.len(),
            counters: s.counters.clone(),
        })
    }

    pub fn snapshots(&self) -> Vec<SessionSnapshot> {
        self.sessions
            .keys()
            .filter_map(|&(p, f)| self.session_snapshot(p, f))
            .collect()
    }

    pub fn mark_stale(&mut self, peer_id: u64, family: NlriFamily, prefix: &Prefix, now_ms: u64) {
        if let Some(s) = self.sessions.get_mut(&(peer_id, family)) {
            s.stale.mark(prefix, now_ms);
        }
    }

    /// Record that the peer advertised `prefix` (issue #99 §Recovery:
    /// "Mark affected prefixes stale"). The import hook calls this on
    /// every accepted UPDATE so the table knows the peer's full
    /// advertisement set; on escalation, `apply_transition` marks
    /// every prefix in this set stale so ECMP excludes it.
    pub fn observe_prefix(&mut self, peer_id: u64, family: NlriFamily, prefix: &Prefix) {
        if let Some(s) = self.sessions.get_mut(&(peer_id, family)) {
            s.prefixes.insert(*prefix);
        }
    }

    /// Retire `prefix` from the peer's advertisement set. The import
    /// hook calls this on withdraw so the set does not accumulate
    /// prefixes the peer no longer advertises (which would make
    /// future escalations mark stale prefixes that are no longer in
    /// the RIB).
    pub fn forget_prefix(&mut self, peer_id: u64, family: NlriFamily, prefix: &Prefix) {
        if let Some(s) = self.sessions.get_mut(&(peer_id, family)) {
            s.prefixes.remove(prefix);
        }
    }

    /// Number of prefixes the peer currently advertises (the size
    /// of the set escalated to stale on a tier transition). Surfaced
    /// by `lrctl show peer-health` for capacity planning.
    pub fn prefix_count(&self, peer_id: u64, family: NlriFamily) -> usize {
        match self.sessions.get(&(peer_id, family)) {
            Some(s) => s.prefixes.len(),
            None => 0,
        }
    }

    pub fn readmit(&mut self, peer_id: u64, family: NlriFamily, prefix: &Prefix) {
        if let Some(s) = self.sessions.get_mut(&(peer_id, family)) {
            s.stale.clear(prefix);
        }
    }

    pub fn is_stale(&self, peer_id: u64, family: NlriFamily, prefix: &Prefix) -> bool {
        match self.sessions.get(&(peer_id, family)) {
            Some(s) => s.stale.is_stale(prefix),
            None => false,
        }
    }

    pub fn tick(&mut self, now_ms: u64) -> TickReport {
        let mut report = TickReport::default();
        if self.cfg.rollout == RolloutMode::Off {
            return report;
        }
        let longest_s = self.cfg.longest_window_s();
        let cutoff = now_ms.saturating_sub(longest_s.saturating_mul(1000));
        let keys: Vec<(u64, NlriFamily)> = self.sessions.keys().copied().collect();
        let mut budget = TickBudget::default();
        for key in keys {
            let before = self
                .sessions
                .get(&key)
                .map(|s| s.tier)
                .unwrap_or(PeerHealthTier::L0);
            if let Some(s) = self.sessions.get_mut(&key) {
                s.prune_events(cutoff);
                s.exclusions.retain(|w| now_ms < w.end_ms);
            }
            // Refresh the internal count from the completed
            // transitions of the sessions already processed this
            // tick, so the budget gates see a monotone view.
            self.internal_degraded_count = self
                .sessions
                .values()
                .filter(|s| s.tier > PeerHealthTier::L0)
                .count() as u32;
            self.run_state_machine(key, now_ms, &mut budget);
            let after = self
                .sessions
                .get(&key)
                .map(|s| s.tier)
                .unwrap_or(PeerHealthTier::L0);
            if before != after {
                report.tier_changes.push((key.0, key.1, before, after));
            }
            if let Some(s) = self.sessions.get_mut(&key) {
                let swept = s.stale.sweep(now_ms, self.cfg.max_stale_age_s);
                report.stale_sweep.readmitted += swept.readmitted;
                report.stale_sweep.expired += swept.expired;
                report.stale_sweep.remaining += swept.remaining;
            }
        }
        self.recompute_aggregates();
        report
    }

    fn run_state_machine(&mut self, key: (u64, NlriFamily), now_ms: u64, budget: &mut TickBudget) {
        let Some(session) = self.sessions.get_mut(&key) else {
            return;
        };
        if session.is_excluded(now_ms).is_some() {
            return;
        }
        let mut s = session.clone();
        let cfg = self.cfg.clone();

        for _ in 0..=(MAX_TIER as u8 as usize) {
            // The state machine gates read the INTERNAL degraded
            // count — the state machine's own tiers, not the
            // rollout-masked public view — so a shadow-mode run
            // computes the same tiers Full mode would (the shadow
            // phases exist to predict Full-mode behavior).
            let degraded_count = self.internal_degraded_count;

            let short = s.count_in_window(cfg.short_window.window_s, now_ms);
            let mid = s.count_in_window(cfg.mid_window.window_s, now_ms);
            let long = s.count_in_window(cfg.long_window.window_s, now_ms);

            let baseline_eps = s
                .compute_baseline(now_ms, &cfg)
                .max(cfg.min_baseline_rate_eps);
            let short_budget = cfg.short_window.budget_for(baseline_eps);
            let mid_budget = cfg.mid_window.budget_for(baseline_eps);
            let long_budget = cfg.long_window.budget_for(baseline_eps);

            let short_tripped = short > short_budget;
            let mid_tripped = mid > mid_budget;
            let long_tripped = long > long_budget;

            let trips = [short_tripped, mid_tripped, long_tripped]
                .iter()
                .filter(|&&b| b)
                .count();
            let confirmed = mid_tripped || long_tripped;

            let escalate = trips >= 2 && confirmed && s.tier < MAX_TIER;
            if escalate {
                let emergency =
                    long_tripped && long > cfg.long_window.emergency_budget(baseline_eps);
                let interval_ok = now_ms.saturating_sub(s.last_escalation_ms)
                    >= cfg.min_transition_interval_s.saturating_mul(1000);
                if emergency || interval_ok {
                    let new_tier = s.tier.next().unwrap_or(MAX_TIER);
                    apply_transition(&mut s, new_tier, now_ms, true, &cfg);
                    continue;
                } else {
                    s.pending_escalation = Some(s.tier.next().unwrap_or(MAX_TIER));
                    s.counters.escalation_suppressed =
                        s.counters.escalation_suppressed.saturating_add(1);
                }
            } else {
                s.pending_escalation = None;
            }

            let short_recovered = short <= cfg.short_window.exit_budget(baseline_eps);
            let mid_recovered = mid <= cfg.mid_window.exit_budget(baseline_eps);
            let long_recovered = long <= cfg.long_window.exit_budget(baseline_eps);
            let all_recovered = short_recovered && mid_recovered && long_recovered;

            if all_recovered && s.tier > PeerHealthTier::L0 {
                let dwell_ok = now_ms.saturating_sub(s.tier_entered_ms)
                    >= cfg
                        .dwell_s(s.tier)
                        .saturating_mul(1000)
                        .saturating_mul(s.backoff as u64);
                let cooldown_ok = now_ms.saturating_sub(s.last_recovery_ms)
                    >= cfg.min_recovery_interval_s.saturating_mul(1000);
                // Global soft budget (issue #99 §Global protection:
                // "freeze automatic recovery"): below it, recovery
                // proceeds freely; at or above it, recovery is
                // RATE-LIMITED to one session per tick — the
                // anti-storm intent, without the wedge a hard freeze
                // produced (recovery is the only thing that lowers
                // the count, so a full freeze at `count >= soft`
                // could never lift once tripped).
                let global_room =
                    degraded_count < cfg.global_budgets.soft_degraded || budget.recoveries == 0;
                if dwell_ok && cooldown_ok && global_room {
                    let new_tier = s.tier.prev().unwrap_or(PeerHealthTier::L0);
                    apply_transition(&mut s, new_tier, now_ms, false, &cfg);
                    budget.recoveries += 1;
                    continue;
                } else {
                    s.counters.recovery_suppressed =
                        s.counters.recovery_suppressed.saturating_add(1);
                }
            }

            if cfg.global_budgets.hard_degraded > 0
                && degraded_count >= cfg.global_budgets.hard_degraded
                && s.tier == PeerHealthTier::L0
            {
                // The hard budget forces a minimum tier (issue #99
                // §Global protection). This is a global-protection
                // posture, NOT evidence against the peer: no stale
                // marking rides with it (marking every healthy
                // peer's prefixes stale during a network-wide event
                // would strip ECMP alternates on top of the event).
                apply_transition_min(&mut s, PeerHealthTier::L1, now_ms, &cfg);
                continue;
            }

            break;
        }

        // One full stable baseline window at L0 clears the recovery
        // backoff — a repeat flapper's dwell stretches within a flap
        // cycle, while a peer that stayed quiet for a whole window
        // starts fresh. (Resetting the backoff at the L0 transition
        // itself defeated the mechanism: the classic L0↔L1 repeat
        // flapper always saw the base dwell.)
        if s.tier == PeerHealthTier::L0
            && s.backoff > 1
            && now_ms.saturating_sub(s.tier_entered_ms)
                >= cfg.baseline_window_s.saturating_mul(1000)
        {
            s.backoff = 1;
        }

        *session = s;
    }

    fn recompute_aggregates(&mut self) {
        // The public tier (what `tier()` returns and what the
        // speaker's `reselect` sees) is L0 for every shadow mode
        // (off / observe / shadow / shadow-best-path). The aggregate
        // counters must match that view so `lrctl show peer-health`
        // and `degraded_session_count()` report 0 degraded sessions
        // when the mechanism is not publicly active — otherwise a
        // flip to Off would leave stale counts that confuse operators
        // and the global-budget logic.
        let publicly_active = matches!(self.cfg.rollout, RolloutMode::Limited | RolloutMode::Full);
        let mut count = 0u32;
        let mut internal = 0u32;
        let mut peak = PeerHealthTier::L0;
        for s in self.sessions.values() {
            if s.tier > PeerHealthTier::L0 {
                internal = internal.saturating_add(1);
            }
            let t = if publicly_active {
                self.cfg.effective_tier(s.tier)
            } else {
                PeerHealthTier::L0
            };
            if t > PeerHealthTier::L0 {
                count = count.saturating_add(1);
            }
            if t > peak {
                peak = t;
            }
        }
        self.degraded_session_count = count;
        self.internal_degraded_count = internal;
        self.peak_tier = peak;
    }

    pub fn forget(&mut self, peer_id: u64, family: NlriFamily) {
        self.sessions.remove(&(peer_id, family));
        self.recompute_aggregates();
    }

    pub fn sessions_iter(&self) -> impl Iterator<Item = ((u64, NlriFamily), &SessionState)> {
        self.sessions.iter().map(|(k, v)| (*k, v))
    }

    pub fn reset(&mut self) {
        self.sessions.clear();
        self.degraded_session_count = 0;
        self.internal_degraded_count = 0;
        self.peak_tier = PeerHealthTier::L0;
    }
}

fn apply_transition(
    s: &mut SessionState,
    new_tier: PeerHealthTier,
    now_ms: u64,
    escalating: bool,
    cfg: &PeerHealthConfig,
) {
    let old_tier = s.tier;
    if new_tier == old_tier {
        return;
    }
    s.tier = new_tier;
    s.last_transition_ms = now_ms;
    s.tier_entered_ms = now_ms;
    if escalating {
        s.last_escalation_ms = now_ms;
        s.counters.escalations = s.counters.escalations.saturating_add(1);
        if new_tier > s.counters.peak_tier {
            s.counters.peak_tier = new_tier;
        }
        // §Recovery: "Mark affected prefixes stale."
        // Every prefix the peer has advertised is now stale so
        // ECMP excludes it (`BestPath::multipath_tiered` skips
        // stale paths). A fresh UPDATE for a prefix re-admits
        // it (clears the stale marker) — see
        // `PeerHealthImportHook::on_import`. Only applied in
        // modes that apply stale markings (`limited` / `full`);
        // shadow modes never mark stale.
        if cfg.rollout.applies_stale() {
            for p in &s.prefixes {
                s.stale.mark(p, now_ms);
            }
        }
    } else {
        s.last_recovery_ms = now_ms;
        s.counters.recoveries = s.counters.recoveries.saturating_add(1);
        // The backoff doubles per recovery step and deliberately
        // survives the L0 return — the classic L0<->L1 repeat flapper
        // must see a stretching dwell, not the base one every cycle.
        // It clears after one full stable baseline window at L0 (see
        // run_state_machine).
        s.backoff = s.backoff.saturating_mul(2).min(cfg.max_backoff);
    }
}

/// A minimum-tier transition forced by the global hard budget: the
/// tier and bookkeeping of [`apply_transition`] without the stale
/// marking — a global-protection posture is not evidence against the
/// peer, and marking every healthy session's prefixes stale during a
/// network-wide event would strip ECMP alternates on top of it.
fn apply_transition_min(
    s: &mut SessionState,
    new_tier: PeerHealthTier,
    now_ms: u64,
    cfg: &PeerHealthConfig,
) {
    let old_tier = s.tier;
    if new_tier == old_tier {
        return;
    }
    s.tier = new_tier;
    s.last_transition_ms = now_ms;
    s.tier_entered_ms = now_ms;
    s.last_escalation_ms = now_ms;
    s.counters.escalations = s.counters.escalations.saturating_add(1);
    if new_tier > s.counters.peak_tier {
        s.counters.peak_tier = new_tier;
    }
    let _ = cfg;
}

impl PartialOrd for PeerHealthTier {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for PeerHealthTier {
    fn cmp(&self, other: &Self) -> Ordering {
        (*self as u8).cmp(&(*other as u8))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use config::*;

    fn cfg_test() -> PeerHealthConfig {
        PeerHealthConfig {
            rollout: RolloutMode::Full,
            short_window: WindowBudget {
                window_s: 5,
                enter_multiplier: 1.5,
                exit_multiplier: 0.75,
                emergency_multiplier: 8.0,
            },
            mid_window: WindowBudget {
                window_s: 30,
                enter_multiplier: 1.5,
                exit_multiplier: 0.75,
                emergency_multiplier: 8.0,
            },
            long_window: WindowBudget {
                window_s: 120,
                enter_multiplier: 1.5,
                exit_multiplier: 0.75,
                emergency_multiplier: 8.0,
            },
            baseline_window_s: 480,
            min_baseline_rate_eps: 0.1,
            ewma_alpha: 0.05,
            min_transition_interval_s: 0,
            min_recovery_interval_s: 0,
            max_backoff: 8,
            dwell_s: [0, 0, 0, 0],
            max_stale_age_s: 60,
            tick_interval_s: 1,
            global_budgets: GlobalBudgets {
                soft_degraded: 100,
                hard_degraded: 0,
            },
        }
    }

    fn train_then_burst(
        t: &mut PeerHealthTable,
        peer: u64,
        family: NlriFamily,
        burst_start_ms: u64,
        burst_count: u32,
        burst_gap_ms: u64,
    ) -> u64 {
        for i in 0..10u64 {
            t.account_update(peer, family, i * 1000);
        }
        let mut now = burst_start_ms;
        for _ in 0..burst_count {
            t.account_update(peer, family, now);
            now += burst_gap_ms;
        }
        now
    }

    #[test]
    fn off_mode_never_degrades() {
        let mut t = PeerHealthTable::new(PeerHealthConfig {
            rollout: RolloutMode::Off,
            ..cfg_test()
        });
        train_then_burst(&mut t, 1, NlriFamily::IPV4_UNICAST, 10_000, 200, 10);
        assert_eq!(t.tier(1, NlriFamily::IPV4_UNICAST), PeerHealthTier::L0);
        assert_eq!(t.degraded_session_count(), 0);
    }

    #[test]
    fn observe_mode_accounts_but_does_not_stamp() {
        let mut t = PeerHealthTable::new(PeerHealthConfig {
            rollout: RolloutMode::Observe,
            ..cfg_test()
        });
        train_then_burst(&mut t, 1, NlriFamily::IPV4_UNICAST, 10_000, 200, 10);
        let snap = t.session_snapshot(1, NlriFamily::IPV4_UNICAST).unwrap();
        assert!(snap.counters.updates >= 200);
        assert_eq!(t.tier(1, NlriFamily::IPV4_UNICAST), PeerHealthTier::L0);
    }

    #[test]
    fn exclusion_window_blocks_escalation() {
        let mut t = PeerHealthTable::new(cfg_test());
        t.mark_exclusion(
            1,
            NlriFamily::IPV4_UNICAST,
            ExclusionKind::Startup,
            0,
            30_000,
        );
        train_then_burst(&mut t, 1, NlriFamily::IPV4_UNICAST, 10_000, 200, 10);
        assert_eq!(t.tier(1, NlriFamily::IPV4_UNICAST), PeerHealthTier::L0);
    }

    #[test]
    fn full_mode_escalates_past_l1() {
        let mut t = PeerHealthTable::new(cfg_test());
        train_then_burst(&mut t, 1, NlriFamily::IPV4_UNICAST, 10_000, 200, 10);
        let tier = t.tier(1, NlriFamily::IPV4_UNICAST);
        assert!(
            tier > PeerHealthTier::L1,
            "expected escalation past L1 in Full mode, got {tier:?}"
        );
    }

    #[test]
    fn limited_mode_caps_at_l1() {
        let mut t = PeerHealthTable::new(PeerHealthConfig {
            rollout: RolloutMode::Limited,
            ..cfg_test()
        });
        train_then_burst(&mut t, 1, NlriFamily::IPV4_UNICAST, 10_000, 200, 10);
        assert_eq!(t.tier(1, NlriFamily::IPV4_UNICAST), PeerHealthTier::L1);
        let snap = t.session_snapshot(1, NlriFamily::IPV4_UNICAST).unwrap();
        assert!(snap.counters.escalations >= 1);
    }

    #[test]
    fn stale_prefix_lifecycle() {
        let mut t = PeerHealthTable::new(cfg_test());
        train_then_burst(&mut t, 1, NlriFamily::IPV4_UNICAST, 10_000, 200, 10);
        let tier = t.tier(1, NlriFamily::IPV4_UNICAST);
        assert!(
            tier > PeerHealthTier::L0,
            "expected escalation, got {tier:?}"
        );
        let prefix: Prefix = "10.0.0.0/8".parse().unwrap();
        t.mark_stale(1, NlriFamily::IPV4_UNICAST, &prefix, 50_000);
        assert!(t.is_stale(1, NlriFamily::IPV4_UNICAST, &prefix));
        t.readmit(1, NlriFamily::IPV4_UNICAST, &prefix);
        assert!(!t.is_stale(1, NlriFamily::IPV4_UNICAST, &prefix));
    }

    #[test]
    fn tick_decays_and_sweeps_stale() {
        let mut t = PeerHealthTable::new(cfg_test());
        let final_ms = train_then_burst(&mut t, 1, NlriFamily::IPV4_UNICAST, 10_000, 200, 10);
        let prefix: Prefix = "10.0.0.0/8".parse().unwrap();
        t.mark_stale(1, NlriFamily::IPV4_UNICAST, &prefix, final_ms);
        let max_age = t.config().max_stale_age_s;
        let report = t.tick(final_ms + (max_age + 1) * 1000);
        assert!(!t.is_stale(1, NlriFamily::IPV4_UNICAST, &prefix));
        let did_recover = report
            .tier_changes
            .iter()
            .any(|(_, _, _, to)| *to == PeerHealthTier::L0);
        let did_sweep = report.stale_sweep.expired + report.stale_sweep.readmitted >= 1;
        assert!(
            did_recover || did_sweep,
            "expected either recovery or a sweep, got {report:?}"
        );
    }

    #[test]
    fn forget_clears_session() {
        let mut t = PeerHealthTable::new(cfg_test());
        t.account_update(1, NlriFamily::IPV4_UNICAST, 0);
        assert_eq!(t.len(), 1);
        t.forget(1, NlriFamily::IPV4_UNICAST);
        assert!(t.is_empty());
    }

    #[test]
    fn snapshots_are_deterministic() {
        let mut t = PeerHealthTable::new(cfg_test());
        t.account_update(2, NlriFamily::IPV6_UNICAST, 0);
        t.account_update(1, NlriFamily::IPV4_UNICAST, 0);
        let snaps = t.snapshots();
        assert_eq!(snaps[0].peer_id, 1);
        assert_eq!(snaps[1].peer_id, 2);
    }

    #[test]
    fn recovery_after_dwell() {
        let mut cfg = cfg_test();
        cfg.dwell_s = [0, 1, 1, 1];
        cfg.min_recovery_interval_s = 0;
        let mut t = PeerHealthTable::new(cfg);
        let final_ms = train_then_burst(&mut t, 1, NlriFamily::IPV4_UNICAST, 10_000, 200, 10);
        let tier_at_peak = t.tier(1, NlriFamily::IPV4_UNICAST);
        assert!(tier_at_peak > PeerHealthTier::L0);
        let mut now = final_ms + 60_000;
        for _ in 0..4 {
            t.tick(now);
            now += 60_000;
        }
        assert_eq!(
            t.tier(1, NlriFamily::IPV4_UNICAST),
            PeerHealthTier::L0,
            "session should recover to L0 after windows drain and dwell elapses"
        );
    }

    #[test]
    fn emergency_escalation_bypasses_min_interval() {
        let mut cfg = cfg_test();
        cfg.min_transition_interval_s = 3600;
        cfg.long_window.emergency_multiplier = 3.0;
        let mut t = PeerHealthTable::new(cfg);
        train_then_burst(&mut t, 1, NlriFamily::IPV4_UNICAST, 10_000, 5000, 1);
        let tier = t.tier(1, NlriFamily::IPV4_UNICAST);
        assert!(
            tier > PeerHealthTier::L0,
            "emergency escalation should bypass min_transition_interval, got {tier:?}"
        );
    }

    #[test]
    fn set_rollout_mode_preserves_state_and_flips_tier() {
        // §Rollout: SIGHUP live reload flips the rollout
        // mode in-place without losing session state.
        let mut t = PeerHealthTable::new(cfg_test());
        train_then_burst(&mut t, 1, NlriFamily::IPV4_UNICAST, 10_000, 200, 10);
        let tier_full = t.tier(1, NlriFamily::IPV4_UNICAST);
        assert!(tier_full > PeerHealthTier::L0, "should be degraded in Full");
        let snap = t.session_snapshot(1, NlriFamily::IPV4_UNICAST).unwrap();
        let updates_before = snap.counters.updates;

        // Flip to Off: tier() returns L0, but state is preserved.
        t.set_rollout_mode(RolloutMode::Off);
        assert_eq!(t.tier(1, NlriFamily::IPV4_UNICAST), PeerHealthTier::L0);
        assert_eq!(t.degraded_session_count(), 0);
        // Session state survived.
        let snap = t.session_snapshot(1, NlriFamily::IPV4_UNICAST).unwrap();
        assert_eq!(snap.counters.updates, updates_before);

        // Flip back to Full: tier() returns the escalated tier again.
        t.set_rollout_mode(RolloutMode::Full);
        assert!(t.tier(1, NlriFamily::IPV4_UNICAST) > PeerHealthTier::L0);
    }

    #[test]
    fn set_rollout_mode_limited_caps_at_l1() {
        let mut t = PeerHealthTable::new(cfg_test());
        train_then_burst(&mut t, 1, NlriFamily::IPV4_UNICAST, 10_000, 200, 10);
        // In Full mode the tier may be L2 or L3.
        let tier_full = t.tier(1, NlriFamily::IPV4_UNICAST);
        assert!(tier_full > PeerHealthTier::L1);

        // Flip to Limited: tier capped at L1.
        t.set_rollout_mode(RolloutMode::Limited);
        assert_eq!(t.tier(1, NlriFamily::IPV4_UNICAST), PeerHealthTier::L1);
    }

    // ---------------------------------------------------------------------------
    // Audit H65 batch: the soft-budget recovery wedge, stale marking on the
    // hard-budget gate, the EWMA first-sample seed, backoff across L0 and
    // window-second overflow.
    // ---------------------------------------------------------------------------

    #[test]
    fn soft_budget_rate_limits_recovery_without_wedging() {
        // With the soft budget at 2, three degraded sessions must still
        // ALL recover — one per tick — instead of being frozen forever
        // (the pre-fix `degraded_count < soft` gate could never lift
        // once tripped, because recovery is the only thing that
        // lowers the count).
        let mut cfg = cfg_test();
        cfg.global_budgets.soft_degraded = 2;
        cfg.global_budgets.hard_degraded = 0;
        let mut t = PeerHealthTable::new(cfg);
        let fam = NlriFamily::IPV4_UNICAST;
        let mut final_ms = 0u64;
        for peer in 1..=3u64 {
            final_ms = train_then_burst(&mut t, peer, fam, 10_000, 200, 10);
        }
        assert_eq!(t.degraded_session_count(), 3);
        // Ticks past every window: at or above the soft budget at most
        // ONE recovery transition fires per tick (the anti-storm
        // rate limit), and the count always reaches 0 — the wedge a
        // full freeze produced (no recovery ever) is gone.
        let mut now = final_ms + 200_000;
        let mut ticks = 0;
        while t.degraded_session_count() > 0 {
            let report = t.tick(now);
            if t.degraded_session_count() >= 2 {
                let recoveries = report
                    .tier_changes
                    .iter()
                    .filter(|(_, _, before, after)| after < before)
                    .count();
                assert!(
                    recoveries <= 1,
                    "at/above the soft budget at most one recovery per tick, got {recoveries}"
                );
            }
            ticks += 1;
            assert!(ticks < 40, "the soft budget must not wedge recovery");
            now += 200_000;
        }
    }

    #[test]
    fn hard_budget_gate_does_not_mark_stale() {
        // The hard budget forces healthy sessions to L1 — a global
        // posture, not evidence against the peer. Their prefixes must
        // NOT be marked stale (that would strip ECMP alternates during
        // a network-wide event). Peers 1-3 degrade for real; peer 4 is
        // healthy and gets the forced floor.
        let mut cfg = cfg_test();
        cfg.global_budgets.soft_degraded = 1;
        cfg.global_budgets.hard_degraded = 2;
        let mut t = PeerHealthTable::new(cfg);
        let fam = NlriFamily::IPV4_UNICAST;
        // The session must exist before the prefix lands in its set.
        let _ = t.account_update(1, fam, 0);
        t.observe_prefix(1, fam, &"198.51.100.0/24".parse().unwrap());
        for peer in 1..=3u64 {
            train_then_burst(&mut t, peer, fam, 10_000, 200, 10);
            assert!(t.tier(peer, fam) > PeerHealthTier::L0);
        }
        assert!(t.is_stale(1, fam, &"198.51.100.0/24".parse().unwrap()));
        // Peer 4 is healthy; the hard gate forces it to L1 but marks
        // nothing stale.
        t.observe_prefix(4, fam, &"203.0.113.0/24".parse().unwrap());
        let _ = t.account_update(4, fam, 20_000);
        let _ = t.tick(20_000);
        assert_eq!(t.tier(4, fam), PeerHealthTier::L1, "hard gate forces L1");
        assert!(
            !t.is_stale(4, fam, &"203.0.113.0/24".parse().unwrap()),
            "hard-budget L1 must not mark the healthy peer's prefixes stale"
        );
    }

    #[test]
    fn ewma_first_sample_seeds_not_blends_with_zero() {
        // A session created at now_ms > 0 (the common case — the router
        // clock is ms-since-daemon-start) must seed the EWMA with its
        // first sample. The pre-fix `last_baseline_ms == 0` sentinel
        // never fired for such a session, so the first sample blended
        // against an implicit zero baseline. The rate stays below every
        // window's floor budget so nothing escalates and the baseline
        // keeps training.
        let cfg = cfg_test();
        let mut t = PeerHealthTable::new(cfg);
        let fam = NlriFamily::IPV4_UNICAST;
        // One update every 30 s for 8 minutes: 16 events, 1 per mid
        // window, well under the mid budget floor of 4.
        let start_ms = 500_000u64;
        for i in 0..16u64 {
            let _ = t.account_update(7, fam, start_ms + i * 30_000);
        }
        let s = t.sessions_iter().find(|(k, _)| k.0 == 7).unwrap().1.clone();
        assert_eq!(t.tier(7, fam), PeerHealthTier::L0);
        assert!(s.baseline_seeded, "the first sample must seed the EWMA");
        assert!(
            s.baseline_rate > 0.01,
            "the seeded EWMA tracks the observed rate, got {} \
             (the zero-blend bug leaves it near 1/480)",
            s.baseline_rate
        );
    }

    #[test]
    fn backoff_survives_l0_within_a_flap_cycle() {
        // The classic L0<->L1 repeat flapper must see a stretching
        // dwell: the backoff doubles per recovery and no longer resets
        // at the L0 transition itself. It clears only after one full
        // stable baseline window at L0.
        let mut cfg = cfg_test();
        cfg.baseline_window_s = 480;
        let mut t = PeerHealthTable::new(cfg);
        let fam = NlriFamily::IPV4_UNICAST;
        let final_ms = train_then_burst(&mut t, 9, fam, 10_000, 200, 10);
        assert!(t.tier(9, fam) > PeerHealthTier::L0);
        // Windows drain; the session recovers to L0 with backoff > 1.
        let mut now = final_ms + 200_000;
        let mut backoff_at_l0 = 0;
        for _ in 0..6 {
            let _ = t.tick(now);
            now += 200_000;
            if t.tier(9, fam) == PeerHealthTier::L0 {
                backoff_at_l0 = t.sessions_iter().find(|(k, _)| k.0 == 9).unwrap().1.backoff;
                break;
            }
        }
        assert_eq!(t.tier(9, fam), PeerHealthTier::L0, "session recovers");
        assert!(
            backoff_at_l0 > 1,
            "the recovery backoff survives the L0 return, got {backoff_at_l0}"
        );
        // One full stable baseline window later, the backoff clears.
        let _ = t.tick(now + 480_000);
        let backoff = t.sessions_iter().find(|(k, _)| k.0 == 9).unwrap().1.backoff;
        assert_eq!(backoff, 1, "a stable baseline window clears the backoff");
    }

    #[test]
    fn window_seconds_overflow_does_not_panic() {
        // A config with u64::MAX window seconds must not overflow the
        // ms conversion (debug builds panic on `window_s * 1000`).
        let mut cfg = cfg_test();
        cfg.short_window.window_s = u64::MAX;
        cfg.mid_window.window_s = u64::MAX;
        cfg.long_window.window_s = u64::MAX;
        cfg.baseline_window_s = u64::MAX;
        let mut t = PeerHealthTable::new(cfg);
        let fam = NlriFamily::IPV4_UNICAST;
        let _ = t.account_update(11, fam, 1_000);
        let _ = t.tick(2_000);
    }
}
