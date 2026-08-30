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
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Elector {
    pub router_id: u32,
    pub priority: u8,
    pub stated_dr: u32,
    pub stated_bdr: u32,
}

/// Run the DR/BDR election algorithm (RFC 2328 §9.4.1). Returns (dr, bdr).
///
/// `our_id` is this router's own BGP/OSPF identifier; the caller includes
/// itself in `electors` (with `stated_dr`/`stated_bdr` as this router
/// claims) if it is eligible — routers with priority 0 never participate
/// (§9.4.1 step 1).
pub fn elect(electors: &[Elector], our_id: u32) -> (u32, u32) {
    let eligible: Vec<&Elector> = electors
        .iter()
        .filter(|e| e.priority > 0)
        .collect();

    // Step 1: BDR — pick the router that declared itself BDR (and is in our
    // list), with highest priority, then highest router-id. If none declared
    // themselves BDR, pick the highest-priority among the rest.
    let mut bdr_candidates: Vec<&Elector> = eligible
        .iter()
        .copied()
        .filter(|e| e.stated_bdr == e.router_id)
        .collect();
    bdr_candidates.sort_by(|a, b| {
        b.priority
            .cmp(&a.priority)
            .then(b.router_id.cmp(&a.router_id))
    });
    let bdr = bdr_candidates.first().map(|e| e.router_id).unwrap_or(0);

    // Step 2: DR — pick the router that declared itself DR (and is in our
    // list). Fall back to the elected BDR.
    let mut dr_candidates: Vec<&Elector> = eligible
        .iter()
        .copied()
        .filter(|e| e.stated_dr == e.router_id)
        .collect();
    dr_candidates.sort_by(|a, b| {
        b.priority
            .cmp(&a.priority)
            .then(b.router_id.cmp(&a.router_id))
    });
    let dr = dr_candidates.first().map(|e| e.router_id).unwrap_or(bdr);

    // Step 3: recompute BDR — pick the highest priority that is not the
    // elected DR, excluding routers with priority 0.
    let mut bdr2_candidates: Vec<&Elector> = eligible
        .iter()
        .copied()
        .filter(|e| e.router_id != dr)
        .collect();
    bdr2_candidates.sort_by(|a, b| {
        b.priority
            .cmp(&a.priority)
            .then(b.router_id.cmp(&a.router_id))
    });
    // If the recomputation selected us, the RFC repeats with ourselves
    // excluded (§9.4.1 step 3) — but only when there is another eligible
    // router; a lone router still becomes DR.
    let bdr_final = bdr2_candidates
        .first()
        .map(|e| e.router_id)
        .unwrap_or(our_id);
    let bdr_final = if bdr_final == our_id && bdr2_candidates.len() > 1 {
        bdr2_candidates
            .iter()
            .find(|e| e.router_id != our_id)
            .map(|e| e.router_id)
            .unwrap_or(our_id)
    } else {
        bdr_final
    };

    // A lone router on the segment (no other elector) is both DR and BDR.
    let dr = if dr == 0 && bdr == 0 && !eligible.is_empty() {
        // Electors exist but none declared themselves DR/BDR: we become DR.
        our_id
    } else {
        dr
    };

    (dr, if bdr == 0 { bdr_final } else { bdr })
}

/// Per-interface FSM. Stays minimal — full interface FSM lives in `lr-router`.
pub struct OspfInterface {
    pub state: IfState,
    pub priority: u8,
    pub hello_interval: u16,
    pub dead_interval: u32,
    pub dr: u32,
    pub bdr: u32,
    pub area_id: u32,
    /// This router's own identifier (used as the self candidate in
    /// DR/BDR election).
    pub router_id: u32,
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
                // priority > 0; the RFC's step 3 self-exclusion is handled
                // inside `elect`).
                let mut all = elector.clone();
                all.push(Elector {
                    router_id: self.router_id,
                    priority: self.priority,
                    stated_dr: self.dr,
                    stated_bdr: self.bdr,
                });
                let (dr, bdr) = elect(&all, self.router_id);
                self.dr = dr;
                self.bdr = bdr;
                if self.router_id == dr {
                    IfState::Dr
                } else if self.router_id == bdr {
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

    #[test]
    fn elect_basic() {
        let electors = vec![
            Elector {
                router_id: 1,
                priority: 1,
                stated_dr: 1,
                stated_bdr: 0,
            },
            Elector {
                router_id: 2,
                priority: 1,
                stated_dr: 0,
                stated_bdr: 2,
            },
            Elector {
                router_id: 3,
                priority: 200,
                stated_dr: 0,
                stated_bdr: 0,
            },
        ];
        let (dr, bdr) = elect(&electors, 99);
        assert_eq!(dr, 1);
        // bdr: 2 declared itself BDR; we should prefer 2 over fallback 3 even
        // though 3 has higher priority? Per RFC §9.4.1 step 1, only routers
        // that declared themselves BDR are eligible. So 2 wins.
        assert_eq!(bdr, 2);
    }

    #[test]
    fn elect_with_higher_priority_no_declared() {
        // None declares; should elect by priority then router-id.
        let electors = vec![
            Elector {
                router_id: 1,
                priority: 1,
                stated_dr: 0,
                stated_bdr: 0,
            },
            Elector {
                router_id: 3,
                priority: 200,
                stated_dr: 0,
                stated_bdr: 0,
            },
        ];
        let (_dr, bdr) = elect(&electors, 99);
        // _dr would be our_id (no candidate declared). We test BDR.
        assert_eq!(bdr, 3);
    }

    /// RFC 2328 §9.4.1: routers with priority 0 never take part.
    #[test]
    fn elect_excludes_priority_zero() {
        let electors = vec![
            Elector {
                router_id: 1,
                priority: 0,
                stated_dr: 1,
                stated_bdr: 1,
            },
            Elector {
                router_id: 2,
                priority: 1,
                stated_dr: 0,
                stated_bdr: 2,
            },
        ];
        let (dr, bdr) = elect(&electors, 99);
        assert_eq!(dr, 2, "priority-0 router must not become DR");
        assert_eq!(bdr, 2);
    }

    /// The FSM must reach DR/Backup when we win the election.
    #[test]
    fn fsm_enters_dr_and_backup() {
        let mut iface = OspfInterface::new(0);
        iface.router_id = 9;
        iface.priority = 100;
        iface.step(IfEvent::InterfaceUp);
        assert_eq!(iface.state, IfState::Waiting);

        // Only we are present and eligible → we become DR.
        iface.step(IfEvent::NeighborChange { elector: vec![] });
        assert_eq!(iface.state, IfState::Dr);
        assert_eq!(iface.dr, 9);

        // A higher-priority router appears → we drop to DR-Other and it
        // becomes DR; we are Backup.
        iface.step(IfEvent::NeighborChange {
            elector: vec![Elector {
                router_id: 5,
                priority: 200,
                stated_dr: 5,
                stated_bdr: 0,
            }],
        });
        assert_eq!(iface.dr, 5);
        assert_eq!(iface.bdr, 9);
        assert_eq!(iface.state, IfState::Backup);
    }
}
