//! OSPF Graceful Restart state machines — RFC 3623 §2/§3 (the wire
//! side, the Grace-LSA codec, lives in [`crate::lsa::grace`]).
//!
//! Two roles, each a small poll-driven machine the embedder drives
//! from its own clock (matching the rest of lr-ospf — no timers of
//! our own):
//!
//! * **Helper neighbour** ([`HelperEntry`]) — RFC 3623 §3. On
//!   receiving a Grace-LSA from a fully adjacent neighbour, enter
//!   helper mode and keep advertising that adjacency (as if Full) for
//!   the requested grace period; exit on grace-LSA flush, grace
//!   expiry, or a link-state-database topology change (§3.2).
//! * **Restarting router** ([`RestartTracker`]) — RFC 3623 §2.
//!   Between the restart and the re-establishment of adjacencies:
//!   originate no topology LSAs, accept self-originated LSAs, and exit
//!   on success (all pre-restart adjacencies back), LSA inconsistency
//!   or grace-period expiry (§2.2).
//!
//! The embedder supplies every input: [`HelperEntry::on_grace_lsa`]
//! evaluates the §3.1 entry checks against the caller's neighbour
//! state and policy, and the §3.1(2) retransmission-list check is
//! trivially satisfied in lr (the OSPF flood path is fire-and-forget
//! — there is no LSA retransmission list that could hold unsent
//! changes; the same simplification BIRD documents in
//! `neighbor.c::changes_in_lsrtl`).
//!
//! The grace clock is the caller's millisecond clock (the daemon's
//! main-loop `now_ms`), consistent with [`crate::lsdb`].
//!
//! Defaults match BIRD 2 (`OSPF_DEFAULT_GR_TIME` = 120 s, valid range
//! 1..=1800 s — RFC 3623 §2.1 caps the period at LSRefreshTime) and
//! FRR 10 (`supported_grace_time` = 120 s helper ceiling).

use crate::lsa::grace::GraceLsaBody;

/// Default grace period in seconds (BIRD `OSPF_DEFAULT_GR_TIME`,
/// FRR `supported_grace_time` default: 120).
pub const DEFAULT_GRACE_PERIOD_SECS: u32 = 120;

/// RFC 3623 §2.1: the grace period must not exceed LSRefreshTime
/// (1800 s), or the restarting router's LSAs age out before it can
/// re-originate them.
pub const MAX_GRACE_PERIOD_SECS: u32 = 1_800;

/// Clamp a configured grace period into the RFC 3623 §2.1 window.
pub fn clamp_grace_period(secs: u32) -> u32 {
    secs.clamp(1, MAX_GRACE_PERIOD_SECS)
}

/// Why a helper refused (or stopped) helping — surfaces in logs and
/// embedder events. Mirrors the check numbering of RFC 3623 §3.1/§3.2.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HelperExit {
    /// §3.1 (1): the neighbour was not fully adjacent.
    NotFull,
    /// §3.1 (3): the grace-LSA's age already exceeded its grace period.
    GraceExpired,
    /// §3.1 (4): local policy disabled the helper role (or the
    /// supported grace period was exceeded and clamping is refused).
    PolicyDisabled,
    /// §3.1 (5): the local router is itself gracefully restarting.
    SelfRestarting,
    /// §3.2 (1): the grace-LSA was flushed — restart succeeded.
    GraceLsaFlushed,
    /// §3.2 (2): the grace period elapsed.
    GraceTimeout,
    /// §3.2 (3): a topology change in the link-state database.
    TopologyChange,
}

impl HelperExit {
    /// One-line human rendering (daemon logs, runbook greps).
    pub fn reason(self) -> &'static str {
        match self {
            Self::NotFull => "neighbor not Full (RFC 3623 3.1 (1))",
            Self::GraceExpired => "grace-LSA age >= grace period (RFC 3623 3.1 (3))",
            Self::PolicyDisabled => "helper policy disabled (RFC 3623 3.1 (4))",
            Self::SelfRestarting => "local graceful restart in progress (RFC 3623 3.1 (5))",
            Self::GraceLsaFlushed => "grace-LSA flushed, restart complete (RFC 3623 3.2 (1))",
            Self::GraceTimeout => "grace period expired (RFC 3623 3.2 (2))",
            Self::TopologyChange => "topology change (RFC 3623 3.2 (3))",
        }
    }
}

/// The §3.1 evaluation inputs, supplied by the embedder per received
/// Grace-LSA.
#[derive(Debug, Clone, Copy)]
pub struct HelperCheck<'a> {
    /// §3.1 (1): is the neighbour fully adjacent right now?
    pub neighbor_full: bool,
    /// §3.1 (4): does local policy allow helping?
    pub helper_enabled: bool,
    /// §3.1 (4, FRR `supported_grace_time`): cap on the accepted grace
    /// period — a longer requested period is clamped (FRR behaviour)
    /// rather than refused.
    pub supported_grace_cap_secs: u32,
    /// §3.1 (5): is the local router itself restarting?
    pub self_restarting: bool,
    /// The grace-LSA body (period, reason) plus its LS age.
    pub lsa: &'a GraceLsaBody,
    pub lsa_age_secs: u16,
    /// §3.2 helper clock: now, in the caller's milliseconds.
    pub now_ms: u64,
}

/// Result of feeding one Grace-LSA into a [`HelperEntry`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HelperTransition {
    /// §3.1 checks failed — not (or no longer) helping; carry the
    /// reason for the log.
    Refused(HelperExit),
    /// Helper mode entered: retain the adjacency for
    /// `grace_deadline_ms` (caller clock). First entry into helper
    /// mode.
    Entered { grace_deadline_ms: u64 },
    /// §3.1 exception: already helping, the grace period was extended
    /// to the new deadline.
    Refreshed { grace_deadline_ms: u64 },
}

impl HelperTransition {
    /// The helper deadline this transition established (None when the
    /// LSA was refused).
    pub fn deadline(self) -> Option<u64> {
        match self {
            Self::Refused(_) => None,
            Self::Entered { grace_deadline_ms } | Self::Refreshed { grace_deadline_ms } => {
                Some(grace_deadline_ms)
            }
        }
    }
}

/// Per-neighbour helper state for one network segment (RFC 3623 §3).
/// The embedder keys one entry per (area, neighbour router-id) — the
/// segment the Grace-LSA arrived on — and drives it with:
///
/// * [`HelperEntry::on_grace_lsa`] when a (non-MaxAge) Grace-LSA from
///   that neighbour installs,
/// * [`HelperEntry::on_flush`] when a MaxAge (flushed) Grace-LSA
///   arrives,
/// * [`HelperEntry::on_topology_change`] when the area's LSDB contents
///   change (§3.2 (3)),
/// * [`HelperEntry::poll`] from the main loop for the §3.2 (2)
///   timeout.
#[derive(Debug, Default, Clone)]
pub struct HelperEntry {
    active: bool,
    grace_deadline_ms: u64,
    /// Remaining seconds as last advertised (for status output).
    last_period_secs: u32,
}

impl HelperEntry {
    /// Is helper mode currently active for this neighbour?
    pub fn is_active(&self) -> bool {
        self.active
    }

    /// The grace deadline on the caller's clock (0 when inactive).
    pub fn grace_deadline_ms(&self) -> u64 {
        self.grace_deadline_ms
    }

    /// The grace period last advertised by the restarting neighbour.
    pub fn last_period_secs(&self) -> u32 {
        self.last_period_secs
    }

    /// Feed one received (non-MaxAge) Grace-LSA through the §3.1
    /// checks. `check.lsa_age_secs` is the LS age carried by the
    /// received instance; the helper honours
    /// `remaining = period - age` per §3.1 (3).
    pub fn on_grace_lsa(&mut self, check: HelperCheck<'_>) -> HelperTransition {
        // §3.1 exception comes first: a router already helping just
        // updates its grace period, no re-evaluation.
        if self.active {
            let deadline = Self::deadline_for(
                check.now_ms,
                check.lsa,
                check.lsa_age_secs,
                check.supported_grace_cap_secs,
            );
            self.grace_deadline_ms = deadline;
            self.last_period_secs = check.lsa.grace_period;
            return HelperTransition::Refreshed {
                grace_deadline_ms: deadline,
            };
        }
        // §3.1 (1)
        if !check.neighbor_full {
            return HelperTransition::Refused(HelperExit::NotFull);
        }
        // §3.1 (3): age must be less than the requested period.
        if u32::from(check.lsa_age_secs) >= check.lsa.grace_period {
            return HelperTransition::Refused(HelperExit::GraceExpired);
        }
        // §3.1 (4): policy. (The FRR supported_grace_time clamp is
        // applied below, after the entry checks, mirroring
        // ospf_gr_helper.c — a longer request is helped for the
        // shorter supported time, not refused.)
        if !check.helper_enabled {
            return HelperTransition::Refused(HelperExit::PolicyDisabled);
        }
        // §3.1 (5)
        if check.self_restarting {
            return HelperTransition::Refused(HelperExit::SelfRestarting);
        }
        let deadline = Self::deadline_for(
            check.now_ms,
            check.lsa,
            check.lsa_age_secs,
            check.supported_grace_cap_secs,
        );
        self.active = true;
        self.grace_deadline_ms = deadline;
        self.last_period_secs = check.lsa.grace_period;
        HelperTransition::Entered {
            grace_deadline_ms: deadline,
        }
    }

    /// Deadline computation shared by enter and refresh: the remaining
    /// grace (`period - age`, §3.1 (3)) clamped to the supported helper
    /// ceiling (FRR `supported_grace_time` — a longer request is
    /// helped for the shorter supported time, not refused; see
    /// ospf_gr_helper.c).
    fn deadline_for(now_ms: u64, lsa: &GraceLsaBody, age_secs: u16, cap_secs: u32) -> u64 {
        let remaining = lsa
            .grace_period
            .saturating_sub(u32::from(age_secs))
            .clamp(1, MAX_GRACE_PERIOD_SECS)
            .min(cap_secs.max(1));
        now_ms + u64::from(remaining) * 1_000
    }

    /// §3.2 (1): the neighbour flushed its Grace-LSA (a MaxAge
    /// instance arrived) — successful restart termination.
    /// Returns whether helper mode was actually exited.
    pub fn on_flush(&mut self) -> Option<HelperExit> {
        if self.active {
            self.deactivate();
            Some(HelperExit::GraceLsaFlushed)
        } else {
            None
        }
    }

    /// §3.2 (3): the LSDB's topology changed — stop helping so the
    /// network can re-route around the restarting router.
    pub fn on_topology_change(&mut self) -> Option<HelperExit> {
        if self.active {
            self.deactivate();
            Some(HelperExit::TopologyChange)
        } else {
            None
        }
    }

    /// §3.2 (2): grace-period expiry from the poll loop.
    pub fn poll(&mut self, now_ms: u64) -> Option<HelperExit> {
        if self.active && now_ms >= self.grace_deadline_ms {
            self.deactivate();
            Some(HelperExit::GraceTimeout)
        } else {
            None
        }
    }

    fn deactivate(&mut self) {
        self.active = false;
        self.grace_deadline_ms = 0;
    }
}

/// The restarting side of graceful restart (RFC 3623 §2), driven by
/// the embedder after the process restarts. The embedder:
///
/// 1. skips topology-LSA (types 1-5, 7) origination while
///    [`RestartTracker::recovering`] — §2 (1),
/// 2. accepts received self-originated LSAs — §2 (1),
/// 3. keeps installing computed routes — §2 (2) (lr-daemon relies on
///    the kernel FIB surviving the restart instead of suppressing
///    installs; recomputed routes refresh, not churn),
/// 4. feeds each Full adjacency + back-link verdict into
///    [`RestartTracker::observe_adjacency`],
/// 5. polls [`RestartTracker::poll`] for the §2.2 exit decision.
#[derive(Debug, Clone)]
pub struct RestartTracker {
    started_ms: u64,
    grace_deadline_ms: u64,
    /// Router-ids the pre-restart router-LSA lists as adjacent
    /// (type-1 p2p links / transit neighbours) and their current
    /// Full + back-link state. `None` = adjacency not yet re-established.
    adjacencies: Vec<(u32, Option<bool>)>,
    /// Set by the embedder when an LSA inconsistent with the
    /// pre-restart state arrives (§2.2 (2)) — e.g. a neighbour's
    /// router-LSA no longer links back to us.
    inconsistent: bool,
    done: Option<RestartOutcome>,
}

/// Why the restarting router left graceful restart (§2.2/§2.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RestartOutcome {
    /// §2.2 (1): every pre-restart adjacency is Full again.
    AdjacenciesRestablished,
    /// §2.2 (2): an inconsistent LSA arrived.
    InconsistentLsa,
    /// §2.2 (3): the grace period expired.
    GraceTimeout,
}

impl RestartOutcome {
    pub fn reason(self) -> &'static str {
        match self {
            Self::AdjacenciesRestablished => "all adjacencies re-established (RFC 3623 2.2 (1))",
            Self::InconsistentLsa => "inconsistent LSA received (RFC 3623 2.2 (2))",
            Self::GraceTimeout => "grace period expired (RFC 3623 2.2 (3))",
        }
    }
}

impl RestartTracker {
    /// Start recovery: `grace_period_secs` is the period the
    /// pre-restart process put into its Grace-LSAs (the embedder
    /// should persist it across the restart — or re-derive it from
    /// the same config, as lr-daemon does).
    pub fn new(grace_period_secs: u32, now_ms: u64) -> Self {
        let period = clamp_grace_period(grace_period_secs);
        Self {
            started_ms: now_ms,
            grace_deadline_ms: now_ms + u64::from(period) * 1_000,
            adjacencies: Vec::new(),
            inconsistent: false,
            done: None,
        }
    }

    /// Is graceful-restart recovery still in progress?
    pub fn recovering(&self) -> bool {
        self.done.is_none()
    }

    /// The grace deadline on the caller's clock.
    pub fn grace_deadline_ms(&self) -> u64 {
        self.grace_deadline_ms
    }

    /// The configured grace period (seconds) this tracker runs with
    /// — the restarting router's shutdown flood re-advertises it.
    pub fn grace_period_secs(&self) -> u32 {
        ((self.grace_deadline_ms - self.started_ms) / 1_000).clamp(1, u32::MAX as u64) as u32
    }

    /// The pre-restart adjacency router-ids this tracker watches
    /// (empty until the pre-restart router-LSA was seen).
    pub fn adjacency_ids(&self) -> impl Iterator<Item = u32> + '_ {
        self.adjacencies.iter().map(|(rid, _)| *rid)
    }

    /// Record the set of router-ids the pre-restart router-LSA
    /// (re-received from helpers through database exchange) lists as
    /// adjacent — §2.2 (1)'s yardstick. Call once the pre-restart
    /// router-LSA becomes available; call again if the set changes.
    pub fn set_pre_restart_adjacencies(&mut self, router_ids: Vec<u32>) {
        self.adjacencies = router_ids.into_iter().map(|rid| (rid, None)).collect();
    }

    /// Report the current state of one adjacency: `Some(full)` —
    /// Full and (when the embedder checked) the neighbour's back-link
    /// present; `None` — not Full yet. Unknown router-ids are ignored
    /// (they were not in the pre-restart LSA); missing ones stay
    /// unestablished. Passing `Some(false)` (Full but the neighbour's
    /// LSA no longer links back) trips §2.2 (2).
    pub fn observe_adjacency(&mut self, rid: u32, full: Option<bool>) {
        if full == Some(false) {
            self.inconsistent = true;
        }
        for (want, state) in self.adjacencies.iter_mut() {
            if *want == rid {
                *state = full;
            }
        }
    }

    /// §2.2 (2) short-circuit: an LSA inconsistent with the
    /// pre-restart state (the embedder's own detection, e.g. a
    /// neighbour router-LSA dropping our link).
    pub fn mark_inconsistent(&mut self) {
        self.inconsistent = true;
    }

    /// Evaluate the §2.2 exit conditions. Cheap; call from the poll
    /// loop. Once an outcome is returned it is latched — §2.3 runs
    /// exactly once.
    pub fn poll(&mut self, now_ms: u64) -> Option<RestartOutcome> {
        if let Some(done) = self.done {
            return Some(done);
        }
        let outcome = if self.inconsistent {
            RestartOutcome::InconsistentLsa
        } else if now_ms >= self.grace_deadline_ms {
            RestartOutcome::GraceTimeout
        } else if !self.adjacencies.is_empty()
            && self.adjacencies.iter().all(|(_, s)| *s == Some(true))
        {
            RestartOutcome::AdjacenciesRestablished
        } else {
            return None;
        };
        self.done = Some(outcome);
        Some(outcome)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lsa::grace::GraceReason;

    fn lsa_body(period: u32) -> GraceLsaBody {
        GraceLsaBody {
            grace_period: period,
            reason: GraceReason::SoftwareRestart,
            ipv4_address: Some([192, 0, 2, 1]),
            ipv6_address: None,
        }
    }

    fn check<'a>(lsa: &'a GraceLsaBody, age: u16, now_ms: u64) -> HelperCheck<'a> {
        HelperCheck {
            neighbor_full: true,
            helper_enabled: true,
            supported_grace_cap_secs: DEFAULT_GRACE_PERIOD_SECS,
            self_restarting: false,
            lsa,
            lsa_age_secs: age,
            now_ms,
        }
    }

    #[test]
    fn clamp_grace_period_matches_rfc3623() {
        assert_eq!(clamp_grace_period(0), 1);
        assert_eq!(clamp_grace_period(60), 60);
        assert_eq!(clamp_grace_period(1_800), 1_800);
        // §2.1: never longer than LSRefreshTime.
        assert_eq!(clamp_grace_period(3_600), MAX_GRACE_PERIOD_SECS);
        assert_eq!(clamp_grace_period(u32::MAX), MAX_GRACE_PERIOD_SECS);
    }

    #[test]
    fn helper_enters_on_full_adjacency() {
        let body = lsa_body(120);
        let mut h = HelperEntry::default();
        let t = h.on_grace_lsa(check(&body, 0, 1_000));
        assert!(matches!(t, HelperTransition::Entered { .. }));
        assert!(h.is_active());
        // Full period honoured: 120 s from the caller clock.
        assert_eq!(h.grace_deadline_ms(), 1_000 + 120_000);
    }

    #[test]
    fn helper_refuses_not_full() {
        // §3.1 (1)
        let body = lsa_body(120);
        let mut h = HelperEntry::default();
        let mut c = check(&body, 0, 1_000);
        c.neighbor_full = false;
        assert_eq!(
            h.on_grace_lsa(c),
            HelperTransition::Refused(HelperExit::NotFull)
        );
        assert!(!h.is_active());
    }

    #[test]
    fn helper_refuses_expired_age() {
        // §3.1 (3): LS age must be < the grace period.
        let body = lsa_body(30);
        let mut h = HelperEntry::default();
        assert_eq!(
            h.on_grace_lsa(check(&body, 30, 0)),
            HelperTransition::Refused(HelperExit::GraceExpired)
        );
        assert!(!h.is_active());
        // age 29 is still inside.
        let t = h.on_grace_lsa(check(&body, 29, 0));
        assert!(matches!(t, HelperTransition::Entered { .. }));
    }

    #[test]
    fn helper_refuses_policy_disabled() {
        // §3.1 (4)
        let body = lsa_body(120);
        let mut h = HelperEntry::default();
        let mut c = check(&body, 0, 0);
        c.helper_enabled = false;
        assert_eq!(
            h.on_grace_lsa(c),
            HelperTransition::Refused(HelperExit::PolicyDisabled)
        );
    }

    #[test]
    fn helper_refuses_while_self_restarting() {
        // §3.1 (5)
        let body = lsa_body(120);
        let mut h = HelperEntry::default();
        let mut c = check(&body, 0, 0);
        c.self_restarting = true;
        assert_eq!(
            h.on_grace_lsa(c),
            HelperTransition::Refused(HelperExit::SelfRestarting)
        );
    }

    #[test]
    fn helper_remaining_grace_subtracts_age() {
        // §3.1 (3): a period of 120 s at age 20 leaves 100 s.
        let body = lsa_body(120);
        let mut h = HelperEntry::default();
        let t = h.on_grace_lsa(check(&body, 20, 5_000));
        assert_eq!(t.deadline(), Some(5_000 + 100_000));
    }

    #[test]
    fn helper_refresh_extends_period() {
        // §3.1 exception: an already-helping router updates its timer.
        let body = lsa_body(60);
        let mut h = HelperEntry::default();
        let t1 = h.on_grace_lsa(check(&body, 0, 1_000));
        assert_eq!(t1.deadline(), Some(61_000));
        let t2 = h.on_grace_lsa(check(&body, 0, 30_000));
        assert_eq!(
            t2,
            HelperTransition::Refreshed {
                grace_deadline_ms: 90_000
            }
        );
        assert_eq!(h.grace_deadline_ms(), 90_000);
    }

    #[test]
    fn helper_timeout_fires_on_deadline() {
        // §3.2 (2)
        let body = lsa_body(5);
        let mut h = HelperEntry::default();
        h.on_grace_lsa(check(&body, 0, 0));
        assert_eq!(h.poll(4_999), None);
        assert_eq!(h.poll(5_000), Some(HelperExit::GraceTimeout));
        assert!(!h.is_active());
        // Idempotent after exit.
        assert_eq!(h.poll(10_000), None);
    }

    #[test]
    fn helper_flush_exits() {
        // §3.2 (1)
        let body = lsa_body(60);
        let mut h = HelperEntry::default();
        h.on_grace_lsa(check(&body, 0, 0));
        assert_eq!(h.on_flush(), Some(HelperExit::GraceLsaFlushed));
        assert!(!h.is_active());
        assert_eq!(h.on_flush(), None);
    }

    #[test]
    fn helper_topology_change_exits() {
        // §3.2 (3)
        let body = lsa_body(60);
        let mut h = HelperEntry::default();
        h.on_grace_lsa(check(&body, 0, 0));
        assert_eq!(h.on_topology_change(), Some(HelperExit::TopologyChange));
        assert!(!h.is_active());
    }

    #[test]
    fn helper_records_last_period() {
        let body = lsa_body(45);
        let mut h = HelperEntry::default();
        h.on_grace_lsa(check(&body, 0, 0));
        assert_eq!(h.last_period_secs(), 45);
    }

    #[test]
    fn restart_tracker_success_when_all_adjacencies_back() {
        // §2.2 (1)
        let mut t = RestartTracker::new(60, 0);
        assert!(t.recovering());
        t.set_pre_restart_adjacencies(vec![0x0a00_0001, 0x0a00_0002]);
        assert_eq!(t.poll(1_000), None);
        t.observe_adjacency(0x0a00_0001, Some(true));
        assert_eq!(t.poll(2_000), None);
        t.observe_adjacency(0x0a00_0002, Some(true));
        assert_eq!(t.poll(3_000), Some(RestartOutcome::AdjacenciesRestablished));
        assert!(!t.recovering());
        // Latched: §2.3 runs once.
        assert_eq!(t.poll(4_000), Some(RestartOutcome::AdjacenciesRestablished));
    }

    #[test]
    fn restart_tracker_inconsistent_lsa_exits() {
        // §2.2 (2)
        let mut t = RestartTracker::new(60, 0);
        t.set_pre_restart_adjacencies(vec![1]);
        t.observe_adjacency(1, Some(false)); // Full but no back-link
        assert_eq!(t.poll(1_000), Some(RestartOutcome::InconsistentLsa));
    }

    #[test]
    fn restart_tracker_timeout_exits() {
        // §2.2 (3)
        let mut t = RestartTracker::new(5, 0);
        t.set_pre_restart_adjacencies(vec![1]);
        assert_eq!(t.poll(4_999), None);
        assert_eq!(t.poll(5_000), Some(RestartOutcome::GraceTimeout));
    }

    #[test]
    fn restart_tracker_no_adjacencies_never_succeeds_early() {
        // Without a pre-restart LSA (nothing synced yet) only the
        // timeout / inconsistency exits fire.
        let mut t = RestartTracker::new(5, 0);
        assert_eq!(t.poll(4_000), None);
        assert_eq!(t.poll(5_000), Some(RestartOutcome::GraceTimeout));
    }

    #[test]
    fn restart_tracker_ignores_unknown_adjacency_reports() {
        let mut t = RestartTracker::new(60, 0);
        t.set_pre_restart_adjacencies(vec![7]);
        t.observe_adjacency(99, Some(true));
        assert_eq!(t.poll(1_000), None);
        t.observe_adjacency(7, Some(true));
        assert_eq!(t.poll(2_000), Some(RestartOutcome::AdjacenciesRestablished));
    }

    #[test]
    fn restart_tracker_clamps_period() {
        let t = RestartTracker::new(u32::MAX, 1_000);
        assert_eq!(
            t.grace_deadline_ms(),
            1_000 + u64::from(MAX_GRACE_PERIOD_SECS) * 1_000
        );
    }
}
