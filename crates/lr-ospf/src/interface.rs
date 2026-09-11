//! OSPF interface FSM (RFC 2328 §9) — DR/BDR election happens here.

use core::fmt;

use lr_core::fsm::{Action, StateId, StateMachine};

/// Interface states (RFC 2328 §9.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum IfState {
    Down = 1,
    Loopback = 2,
    Waiting = 3,
    PointToPoint = 4,
    DrOther = 5,
    Backup = 6, // Backup Designated Router
    Dr = 7,
}

impl IfState {
    pub fn name(self) -> &'static str {
        match self {
            Self::Down => "Down",
            Self::Loopback => "Loopback",
            Self::Waiting => "Waiting",
            Self::PointToPoint => "Point-to-Point",
            Self::DrOther => "DR-Other",
            Self::Backup => "Backup",
            Self::Dr => "DR",
        }
    }

    pub fn state_id(self) -> StateId {
        self as u8 as u32
    }
}

impl fmt::Display for IfState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

#[derive(Debug, Clone)]
pub enum IfEvent {
    InterfaceUp,
    InterfaceDown,
    WaitTimer,
    BackupSeen,
    NeighborChange { elector: Vec<Elector> },
}

/// One entry in DR/BDR election input (RFC 2328 §9.4.1).
///
/// On broadcast and NBMA networks a router is identified on the
/// segment by its **IP interface address** (RFC 2328 §A.3.2 — the
/// Hello's DR/BDR fields carry addresses, not router-ids), so `ip` is
/// the election identity while `router_id` only breaks priority ties
/// (BIRD `elect_bdr`/`elect_dr` and FRR's `ospf_dr_election_sub` both
/// fall back to the router-id). `stated_dr`/`stated_bdr` carry the
/// addresses the elector currently claims in its own Hellos.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Elector {
    pub router_id: u32,
    /// This elector's IP interface address on the segment (identity).
    pub ip: u32,
    pub priority: u8,
    pub stated_dr: u32,
    pub stated_bdr: u32,
}

/// Pick the highest-priority elector, ties broken by the highest
/// router-id (RFC 2328 §9.4 steps 2/3; BIRD `max` in `elect_bdr` and
/// `elect_dr`, FRR `ospf_dr_election_sub`).
fn pick(candidates: &[&Elector]) -> Option<u32> {
    candidates
        .iter()
        .copied()
        .max_by(|a, b| {
            a.priority
                .cmp(&b.priority)
                .then(a.router_id.cmp(&b.router_id))
        })
        .map(|e| e.ip)
}

/// Run the DR/BDR election algorithm (RFC 2328 §9.4). Returns
/// `(dr_ip, bdr_ip)` — the IP interface addresses of the elected
/// Designated Router and Backup Designated Router (0.0.0.0 when no
/// router is elected).
///
/// `electors` must contain every bidirectional neighbor (state ≥
/// 2-Way) plus this router itself; routers with priority 0 are
/// ineligible (§9.4 step 1: "Discard all routers from the list that
/// are ineligible"). `self_ip` is this router's own identity on the
/// segment and drives the §9.4 step-4 re-election: when the result
/// newly makes (or un-makes) this router DR or BDR, the algorithm
/// repeats with the router claiming the round-1 result — this
/// guarantees no router ends up declaring itself both DR and BDR.
pub fn elect(electors: &[Elector], self_ip: u32) -> (u32, u32) {
    // §9.4 step 1: drop ineligible (priority 0) routers. The caller
    // supplies only bidirectional neighbors; bidirectionality itself is
    // not re-checked here.
    let eligible: Vec<Elector> = electors
        .iter()
        .filter(|e| e.priority > 0)
        .cloned()
        .collect();

    // One election round (§9.4 steps 2-3): BDR first, then DR. Split
    // out so the step-4 repeat can re-run it with updated claims.
    fn round(eligible: &[Elector]) -> (u32, u32) {
        // Step 2: BDR. "Only those routers on the list that have not
        // declared themselves to be Designated Router are eligible."
        let not_dr: Vec<&Elector> = eligible.iter().filter(|e| e.stated_dr != e.ip).collect();
        let bdr = {
            let declared: Vec<&Elector> = not_dr
                .iter()
                .copied()
                .filter(|e| e.stated_bdr == e.ip)
                .collect();
            pick(&declared).unwrap_or_else(|| {
                // "If no routers have declared themselves Backup
                // Designated Router, choose the router having highest
                // Router Priority (again excluding those routers who
                // have declared themselves Designated Router)."
                pick(&not_dr).unwrap_or(0)
            })
        };
        // Step 3: DR. Routers that declared themselves DR; if none,
        // "assign the Designated Router to be the same as the newly
        // elected Backup Designated Router".
        let dr = {
            let declared: Vec<&Elector> = eligible.iter().filter(|e| e.stated_dr == e.ip).collect();
            pick(&declared).unwrap_or(bdr)
        };
        (dr, bdr)
    }

    let self_entry = eligible.iter().find(|e| e.ip == self_ip);
    let (mut dr, mut bdr) = round(&eligible);

    // Step 4: "If Router X is now newly the Designated Router or newly
    // the Backup Designated Router, or is now no longer the Designated
    // Router or no longer the Backup Designated Router, repeat steps 2
    // and 3" — with X claiming the round-1 result (BIRD updates the
    // `me` entry's dr/bdr before re-running the election).
    let newly = |cur: u32, got: u32| (cur == self_ip) != (got == self_ip);
    if self_ip != 0 {
        if let Some(me) = self_entry {
            if newly(me.stated_dr, dr) || newly(me.stated_bdr, bdr) {
                let updated: Vec<Elector> = eligible
                    .iter()
                    .map(|e| {
                        if e.ip == self_ip {
                            Elector {
                                stated_dr: dr,
                                stated_bdr: bdr,
                                ..*e
                            }
                        } else {
                            *e
                        }
                    })
                    .collect();
                let (dr2, bdr2) = round(&updated);
                dr = if dr2 == 0 { bdr2 } else { dr2 };
                bdr = bdr2;
            }
        }
    }

    (dr, bdr)
}

/// One entry in the OSPFv3 DR/BDR election input (RFC 5340 §4.1.2).
///
/// The v3 interface state machine and the §9.4 election algorithm are
/// the IPv4 ones "remain unchanged" — but the segment identity is the
/// **Router ID**: an OSPFv3 Hello carries Router IDs in its DR/BDR
/// fields (§A.3.2), unlike the v2 wire form's IP interface addresses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct V3Elector {
    /// The elector's Router ID — the OSPFv3 segment identity.
    pub router_id: u32,
    pub priority: u8,
    /// The Router ID the elector currently claims as DR in its Hellos.
    pub stated_dr: u32,
    /// The Router ID the elector currently claims as BDR.
    pub stated_bdr: u32,
}

/// Run the DR/BDR election algorithm on an OSPFv3 broadcast segment —
/// the RFC 2328 §9.4 algorithm of [`elect`], keyed by Router IDs
/// (RFC 5340 §4.1.2, §A.3.2; FRR ospf6d `dr_election` parity).
/// Returns `(dr_rid, bdr_rid)` — the elected Designated Router and
/// Backup Designated Router as Router IDs (0 = none elected).
///
/// `electors` must contain every bidirectional neighbor (state ≥
/// 2-Way) plus this router itself; routers with priority 0 are
/// ineligible (§9.4 step 1). `self_router_id` drives the §9.4 step-4
/// re-election exactly like the v2 form.
pub fn elect_v3(electors: &[V3Elector], self_router_id: u32) -> (u32, u32) {
    // The §9.4 core is identity-agnostic: present the v3 electors in
    // the shared shape with the Router ID as the identity.
    let inner: Vec<Elector> = electors
        .iter()
        .map(|e| Elector {
            router_id: e.router_id,
            ip: e.router_id,
            priority: e.priority,
            stated_dr: e.stated_dr,
            stated_bdr: e.stated_bdr,
        })
        .collect();
    elect(&inner, self_router_id)
}

/// Per-interface FSM. Stays minimal — full interface FSM lives in `lr-router`.
pub struct OspfInterface {
    pub state: IfState,
    pub priority: u8,
    pub hello_interval: u16,
    pub dead_interval: u32,
    /// Elected Designated Router — its IP interface address on the
    /// segment (§9.1 identity; 0.0.0.0 = none elected yet).
    pub dr: u32,
    /// Elected Backup Designated Router (IP interface address).
    pub bdr: u32,
    pub area_id: u32,
    /// This router's own identifier (tie-break input; election identity
    /// is the interface's IP, kept by the caller in `Elector::ip`).
    pub router_id: u32,
    /// This router's own IP interface address on the segment.
    pub ip: u32,
}

impl OspfInterface {
    pub fn new(area_id: u32) -> Self {
        Self {
            state: IfState::Down,
            priority: 1,
            hello_interval: 10,
            dead_interval: 40,
            dr: 0,
            bdr: 0,
            area_id,
            router_id: 0,
            ip: 0,
        }
    }
}

impl StateMachine for OspfInterface {
    type State = IfState;
    type Event = IfEvent;
    fn state(&self) -> Self::State {
        self.state
    }
    fn step(&mut self, ev: Self::Event) -> Vec<Action> {
        let mut actions = Vec::new();
        let next = match (self.state, &ev) {
            (IfState::Down, IfEvent::InterfaceUp) => IfState::Waiting,
            (IfState::Waiting, IfEvent::WaitTimer) | (IfState::Waiting, IfEvent::BackupSeen) => {
                IfState::DrOther
            }
            (_s, IfEvent::InterfaceDown) => IfState::Down,
            (_s, IfEvent::NeighborChange { elector }) => {
                // Elect including ourselves (the router is eligible while
                // priority > 0; the RFC's step-4 self-exclusion is handled
                // inside `elect`).
                let mut all = elector.clone();
                all.push(Elector {
                    router_id: self.router_id,
                    ip: self.ip,
                    priority: self.priority,
                    stated_dr: self.dr,
                    stated_bdr: self.bdr,
                });
                let (dr, bdr) = elect(&all, self.ip);
                self.dr = dr;
                self.bdr = bdr;
                // Role follows the IP identity (§9.1: on broadcast
                // networks the DR is identified by its interface
                // address, not the router-id).
                if self.ip != 0 && self.ip == dr {
                    IfState::Dr
                } else if self.ip != 0 && self.ip == bdr {
                    IfState::Backup
                } else {
                    IfState::DrOther
                }
            }
            (s, _) => s,
        };
        if next != self.state {
            actions.push(Action::EmitEvent(lr_core::event::Event::PeerStateChange {
                session: 0,
                peer_state: next.name(),
            }));
        }
        self.state = next;
        actions
    }
    fn reset(&mut self) {
        self.state = IfState::Down;
    }
}

#[cfg(test)]
mod tests {
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
}
