use super::*;

fn el(router_id: u32, ip: u32, priority: u8, stated_dr: u32, stated_bdr: u32) -> Elector {
    Elector {
        router_id,
        ip,
        priority,
        stated_dr,
        stated_bdr,
    }
}

/// §9.4 step 2: routers that declared themselves BDR (but not DR)
/// win BDR election; step 3: self-declared DR wins DR election.
#[test]
fn elect_basic() {
    let electors = vec![
        el(1, 0x0a00_0001, 1, 0x0a00_0001, 0),
        el(2, 0x0a00_0002, 1, 0, 0x0a00_0002),
        el(3, 0x0a00_0003, 200, 0, 0),
    ];
    let (dr, bdr) = elect(&electors, 0x0a00_0063);
    assert_eq!(dr, 0x0a00_0001);
    // bdr: 2 declared itself BDR; per §9.4 step 2, only routers that
    // declared themselves BDR (and not DR) are eligible — so 2 wins
    // over the higher-priority 3.
    assert_eq!(bdr, 0x0a00_0002);
}

/// §9.4 step 2 fallback: nobody declares BDR → highest priority
/// among the non-DR-declarers, router-id breaking ties.
#[test]
fn elect_bdr_fallback_priority() {
    let electors = vec![
        el(1, 0x0a00_0001, 1, 0, 0),
        el(3, 0x0a00_0003, 200, 0, 0),
        el(2, 0x0a00_0002, 200, 0, 0),
    ];
    let (_dr, bdr) = elect(&electors, 0x0a00_0063);
    // 3 and 2 tie on priority → highest router-id wins.
    assert_eq!(bdr, 0x0a00_0003);
}

/// §9.4 step 3 fallback: nobody declares DR → DR = newly elected
/// BDR (the same neighbor identity, not 0).
#[test]
fn elect_dr_falls_back_to_bdr() {
    let electors = vec![el(1, 0x0a00_0001, 1, 0, 0), el(2, 0x0a00_0002, 100, 0, 0)];
    let (dr, bdr) = elect(&electors, 0x0a00_0001);
    assert_eq!(bdr, 0x0a00_0002);
    assert_eq!(dr, 0x0a00_0002, "DR must fall back to the elected BDR");
}

/// §9.4 step 4: a router that ends up claiming both DR and BDR in
/// round 1 must re-run the election claiming itself DR — the BDR
/// then moves to another router (BIRD's second round in
/// ospf_dr_election).
#[test]
fn elect_step4_repeat_resolves_double_claim() {
    // Two fresh routers (no claims yet): the higher router-id wins
    // round 1 (as BDR and by DR fallback), i.e. router 2. Router 2
    // (self here) must then re-run claiming itself DR so router 1
    // becomes BDR instead of the double claim (DR=2, BDR=2).
    let electors = vec![el(1, 0x0a00_0001, 1, 0, 0), el(2, 0x0a00_0002, 1, 0, 0)];
    let (dr, bdr) = elect(&electors, 0x0a00_0002);
    assert_eq!(dr, 0x0a00_0002);
    assert_eq!(
        bdr, 0x0a00_0001,
        "step-4 repeat must promote the other router to BDR"
    );
}

/// §9.4 step 4 must NOT fire when our status is unchanged: a DR
/// already claiming itself stays, and the BDR is picked normally.
#[test]
fn elect_step4_stable_when_unchanged() {
    let electors = vec![
        el(1, 0x0a00_0001, 1, 0x0a00_0001, 0),
        el(2, 0x0a00_0002, 1, 0, 0x0a00_0002),
        el(9, 0x0a00_0009, 5, 0, 0),
    ];
    // Self = router 9 (no claims): round 1 yields DR=1, BDR=2; we
    // are neither → no repeat.
    let (dr, bdr) = elect(&electors, 0x0a00_0009);
    assert_eq!(dr, 0x0a00_0001);
    assert_eq!(bdr, 0x0a00_0002);
}

/// §9.4 step 1: routers with priority 0 never take part — not as
/// DR, not as BDR, and they are excluded from the fallback pools.
#[test]
fn elect_excludes_priority_zero() {
    let electors = vec![
        el(1, 0x0a00_0001, 0, 0x0a00_0001, 0x0a00_0001),
        el(2, 0x0a00_0002, 1, 0, 0),
    ];
    let (dr, bdr) = elect(&electors, 0x0a00_0063);
    assert_eq!(dr, 0x0a00_0002, "priority-0 router must not become DR");
    assert_eq!(bdr, 0x0a00_0002);
}

/// A lone eligible router elects itself DR. The BDR is none
/// (0.0.0.0): after the step-4 repeat the router claims itself DR,
/// leaving nobody eligible for BDR — same outcome as BIRD's second
/// election round (nbdr = NULL) and RFC 2328 §9.4 step 2 (the
/// fallback pool excludes DR-declarers).
#[test]
fn elect_lone_router_is_dr() {
    let electors = vec![el(9, 0x0a00_0009, 1, 0, 0)];
    let (dr, bdr) = elect(&electors, 0x0a00_0009);
    assert_eq!(dr, 0x0a00_0009);
    assert_eq!(bdr, 0);
}

/// DR death transition: the old DR stops claiming; the BDR takes
/// over (step 3) and a new BDR is picked (step 4 repeat when we
/// were the old BDR and now become DR).
#[test]
fn elect_dr_death_promotes_bdr() {
    // Self = router 2, currently BDR (claiming itself BDR). Router 1
    // (DR) died: its elector is gone. We should become DR (we claim
    // BDR... no router claims DR) and the repeat fixes our double
    // claim, promoting router 3 to BDR.
    let electors = vec![
        el(2, 0x0a00_0002, 1, 0, 0x0a00_0002),
        el(3, 0x0a00_0003, 1, 0, 0),
    ];
    let (dr, bdr) = elect(&electors, 0x0a00_0002);
    assert_eq!(
        dr, 0x0a00_0002,
        "the old BDR becomes DR via step 3 fallback"
    );
    assert_eq!(
        bdr, 0x0a00_0003,
        "step-4 repeat must promote router 3 to BDR"
    );
}

/// Priority beats router-id: a lower-id router with higher priority
/// wins the election.
#[test]
fn elect_priority_beats_router_id() {
    let electors = vec![
        el(1, 0x0a00_0001, 1, 0x0a00_0001, 0),
        el(2, 0x0a00_0002, 255, 0x0a00_0002, 0),
    ];
    let (dr, _) = elect(&electors, 0x0a00_0063);
    assert_eq!(dr, 0x0a00_0002);
}

/// The FSM must reach DR/Backup when we win the election.
#[test]
fn fsm_enters_dr_and_backup() {
    let mut iface = OspfInterface::new(0);
    iface.router_id = 9;
    iface.ip = 0x0a00_0009;
    iface.priority = 100;
    iface.step(IfEvent::InterfaceUp);
    assert_eq!(iface.state, IfState::Waiting);

    // Only we are present and eligible → we become DR.
    iface.step(IfEvent::NeighborChange { elector: vec![] });
    assert_eq!(iface.state, IfState::Dr);
    assert_eq!(iface.dr, 0x0a00_0009);

    // A higher-priority router appears → it becomes DR; we drop to
    // Backup (we claim DR from the previous round, so the step-4
    // repeat reclassifies us as its BDR).
    iface.step(IfEvent::NeighborChange {
        elector: vec![el(5, 0x0a00_0005, 200, 0x0a00_0005, 0)],
    });
    assert_eq!(iface.dr, 0x0a00_0005);
    assert_eq!(iface.bdr, 0x0a00_0009);
    assert_eq!(iface.state, IfState::Backup);
}

// ---- OSPFv3 election (RFC 5340 §4.1.2 — identity = Router ID) ----

fn el3(router_id: u32, priority: u8, stated_dr: u32, stated_bdr: u32) -> V3Elector {
    V3Elector {
        router_id,
        priority,
        stated_dr,
        stated_bdr,
    }
}

/// §9.4 steps 2/3 on Router-ID identity over a fresh two-router
/// segment — and the convergence across rounds the claims exchange
/// produces. Round 1 at the *lower* Router ID elects router 2 into
/// both roles (no step-4 repeat fires for a DR-Other router); the
/// next election, run once the Hellos carry router 2's own repeat
/// result (it claims DR, router 1 is its BDR), converges both
/// routers on (DR=2, BDR=1) — the same two-round convergence FRR's
/// `dr_election` produces.
#[test]
fn elect_v3_fresh_segment() {
    let electors = vec![el3(1, 1, 0, 0), el3(2, 1, 0, 0)];
    // Router 1, first election: router 2 wins BDR by Router ID and
    // DR via the step-3 fallback; router 1 is DR-Other, so its own
    // step 4 does not repeat.
    let (dr, bdr) = elect_v3(&electors, 1);
    assert_eq!(dr, 2);
    assert_eq!(bdr, 2);
    // Router 2's first election: it is newly DR *and* newly BDR, so
    // its own step 4 repeats the round claiming itself DR.
    let (dr2, bdr2) = elect_v3(&electors, 2);
    assert_eq!(dr2, 2);
    assert_eq!(bdr2, 1);
    // Router 1's next election, with the claims now on the wire
    // (router 2 claims DR; router 1 still advertises the round-1
    // view where neither is a self-claim):
    let converged = vec![el3(1, 1, 2, 2), el3(2, 1, 2, 1)];
    let (dr3, bdr3) = elect_v3(&converged, 1);
    assert_eq!(dr3, 2);
    assert_eq!(bdr3, 1);
}

/// Priority beats Router ID on the v3 identity too, and a router
/// claiming DR keeps the role (step 2 excludes DR-declarers from
/// the BDR pool).
#[test]
fn elect_v3_priority_and_claims() {
    let electors = vec![el3(1, 1, 1, 0), el3(2, 200, 0, 2), el3(3, 255, 0, 0)];
    let (dr, bdr) = elect_v3(&electors, 3);
    assert_eq!(dr, 1, "the DR claimant keeps the role");
    assert_eq!(bdr, 2, "the BDR claimant beats higher-priority router 3");
}

/// §9.4 step 4 v3 form: the router that ends up claiming both roles
/// re-runs the election so the BDR moves to the other router.
#[test]
fn elect_v3_step4_resolves_double_claim() {
    let electors = vec![el3(9, 100, 0, 0), el3(3, 1, 0, 0)];
    let (dr, bdr) = elect_v3(&electors, 9);
    assert_eq!(dr, 9);
    assert_eq!(bdr, 3);
}

/// Priority-0 routers are ineligible (§9.4 step 1) and a lone
/// eligible router elects itself DR with no BDR.
#[test]
fn elect_v3_excludes_priority_zero_and_lone_router() {
    let electors = vec![el3(1, 0, 1, 1), el3(2, 1, 0, 0)];
    let (dr, bdr) = elect_v3(&electors, 2);
    assert_eq!(dr, 2);
    assert_eq!(bdr, 0);

    let (lone_dr, lone_bdr) = elect_v3(&[el3(7, 1, 0, 0)], 7);
    assert_eq!(lone_dr, 7);
    assert_eq!(lone_bdr, 0);
}

/// DR death: the old DR's elector disappears; the BDR claimant
/// promotes to DR and the step-4 repeat promotes the remaining
/// router to BDR.
#[test]
fn elect_v3_dr_death_promotes() {
    // Self = router 2 (was BDR), router 1 (DR) died.
    let electors = vec![el3(2, 1, 0, 2), el3(3, 1, 0, 0)];
    let (dr, bdr) = elect_v3(&electors, 2);
    assert_eq!(dr, 2);
    assert_eq!(bdr, 3);
}
