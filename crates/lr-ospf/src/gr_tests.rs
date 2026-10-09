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
