//! OSPF neighbor FSM (RFC 2328 §10).

use core::fmt;

use lr_core::addr::RouterId;
use lr_core::fsm::{Action, StateId, StateMachine};

/// Neighbor FSM states (RFC 2328 §10.1). The declaration order is the
/// RFC's progress order (BIRD/FRR compare neighbor states with `>=`,
/// e.g. `state >= 2-Way` in the DR election input).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum NeighborState {
    Down = 1,
    Attempt = 2,
    Init = 3,
    TwoWay = 4,
    ExStart = 5,
    Exchange = 6,
    Loading = 7,
    Full = 8,
}

impl NeighborState {
    pub fn name(self) -> &'static str {
        match self {
            Self::Down => "Down",
            Self::Attempt => "Attempt",
            Self::Init => "Init",
            Self::TwoWay => "2-Way",
            Self::ExStart => "ExStart",
            Self::Exchange => "Exchange",
            Self::Loading => "Loading",
            Self::Full => "Full",
        }
    }

    pub fn state_id(self) -> StateId {
        self as u8 as u32
    }
}

impl fmt::Display for NeighborState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// Neighbor FSM event.
#[derive(Debug, Clone)]
pub enum NeighborEvent {
    /// Received a Hello that lists us as seen.
    HelloSeen { dr: u32, bdr: u32, priority: u8 },
    /// Adjacency should start (decided we are DR/BDR or we're on a P2P link).
    AdjOk { proceed: bool },
    /// DD exchange negotiation done.
    NegotiationDone,
    /// Exchange done; ready to load missing LSAs.
    ExchangeDone,
    /// Bad LS-Request or LS-Update.
    SeqMismatch,
    /// One of the LSA entries is malformed.
    BadLsa,
    /// LS-Update or LS-Request arrived in Loading.
    LsaUpdateArrived,
    /// Neighbor had to be torn down.
    Kill,
}

/// Per-neighbor state.
pub struct OspfNeighbor {
    pub router_id: RouterId,
    pub state: NeighborState,
    pub priority: u8,
    pub dr: u32,
    pub bdr: u32,
    /// DD sequence number we use.
    pub dd_seq: u32,
    /// True if we are the master in DD exchange.
    pub master: bool,
}

impl OspfNeighbor {
    pub fn new(router_id: RouterId) -> Self {
        Self {
            router_id,
            state: NeighborState::Down,
            priority: 1,
            dr: 0,
            bdr: 0,
            dd_seq: 0,
            master: false,
        }
    }
}

impl StateMachine for OspfNeighbor {
    type State = NeighborState;
    type Event = NeighborEvent;
    fn state(&self) -> Self::State {
        self.state
    }
    fn step(&mut self, ev: Self::Event) -> Vec<Action> {
        let mut actions: Vec<Action> = Vec::new();
        let next = match (self.state, ev) {
            (NeighborState::Down, NeighborEvent::HelloSeen { dr, bdr, priority }) => {
                self.dr = dr;
                self.bdr = bdr;
                self.priority = priority;
                NeighborState::Init
            }
            (NeighborState::Init, NeighborEvent::HelloSeen { dr, bdr, priority }) => {
                self.dr = dr;
                self.bdr = bdr;
                self.priority = priority;
                // Peer has seen us; transition to 2-Way.
                NeighborState::TwoWay
            }
            (NeighborState::TwoWay, NeighborEvent::AdjOk { proceed: true }) => {
                NeighborState::ExStart
            }
            (NeighborState::TwoWay, NeighborEvent::AdjOk { proceed: false }) => {
                NeighborState::TwoWay
            }
            // RFC 2328 §9.4 step 7 / §10.3: an AdjOK? with a negative
            // decision (the DR/BDR relationship changed) breaks an
            // existing adjacency back down to 2-Way — the exchange and
            // loading states all demote (BIRD's INM_ADJOK does
            // `reset_lists` + NEIGHBOR_2WAY).
            (
                NeighborState::ExStart
                | NeighborState::Exchange
                | NeighborState::Loading
                | NeighborState::Full,
                NeighborEvent::AdjOk { proceed: false },
            ) => {
                actions.push(Action::EmitEvent(lr_core::event::Event::Log(format!(
                    "OSPF neighbor {} adjacency broken (no longer DR/BDR related)",
                    self.router_id
                ))));
                NeighborState::TwoWay
            }
            (NeighborState::ExStart, NeighborEvent::NegotiationDone) => NeighborState::Exchange,
            (NeighborState::Exchange, NeighborEvent::ExchangeDone) => NeighborState::Loading,
            (NeighborState::Loading, NeighborEvent::LsaUpdateArrived)
            | (NeighborState::Loading, NeighborEvent::ExchangeDone) => NeighborState::Full,
            (NeighborState::Full, NeighborEvent::LsaUpdateArrived) => NeighborState::Full,
            (_, NeighborEvent::Kill) => {
                // RFC 2328 §10.6 / §10.1 — adjacency killed (inactivity
                // timer expiry, Hello parameter mismatch, manual reset).
                // Surface a structured `Event::OspfNeighborReset` so the
                // router can record the cause into the session's
                // `SessionStats::last_error` via the dedicated
                // `SessionErrorKind::OspfKill` variant — the previous
                // shape was a free-form `Event::Log` line that the router
                // collapsed into the generic `SessionErrorKind::Other`,
                // losing the RFC 2328 reason on the operator-visible
                // `show sessions` surface.
                actions.push(Action::EmitEvent(
                    lr_core::event::Event::OspfNeighborReset {
                        router_id: self.router_id.as_u32(),
                        kind: lr_core::event::OspfNeighborResetKind::Kill,
                    },
                ));
                NeighborState::Down
            }
            // RFC 2328 §10.9 / Fig. 12: a sequence mismatch or a bad
            // LSA in the exchange states restarts the *adjacency
            // negotiation* (back to ExStart), not the neighbor. The two
            // FSM events share the next-state transition but carry
            // distinct RFC causes — surface them as separate
            // `OspfNeighborResetKind` variants so the router can record
            // the right `SessionErrorKind` per cause.
            (_, NeighborEvent::SeqMismatch) => {
                actions.push(Action::EmitEvent(
                    lr_core::event::Event::OspfNeighborReset {
                        router_id: self.router_id.as_u32(),
                        kind: lr_core::event::OspfNeighborResetKind::SeqMismatch,
                    },
                ));
                NeighborState::ExStart
            }
            (_, NeighborEvent::BadLsa) => {
                actions.push(Action::EmitEvent(
                    lr_core::event::Event::OspfNeighborReset {
                        router_id: self.router_id.as_u32(),
                        kind: lr_core::event::OspfNeighborResetKind::BadLsa,
                    },
                ));
                NeighborState::ExStart
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
        self.state = NeighborState::Down;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lr_core::addr::RouterId;

    #[test]
    fn transitions_to_full() {
        let mut n = OspfNeighbor::new(RouterId::from_u32(0x01020304));
        n.step(NeighborEvent::HelloSeen {
            dr: 0,
            bdr: 0,
            priority: 1,
        });
        assert_eq!(n.state, NeighborState::Init);
        n.step(NeighborEvent::HelloSeen {
            dr: 0,
            bdr: 0,
            priority: 1,
        });
        assert_eq!(n.state, NeighborState::TwoWay);
        n.step(NeighborEvent::AdjOk { proceed: true });
        assert_eq!(n.state, NeighborState::ExStart);
        n.step(NeighborEvent::NegotiationDone);
        assert_eq!(n.state, NeighborState::Exchange);
        n.step(NeighborEvent::ExchangeDone);
        assert_eq!(n.state, NeighborState::Loading);
        n.step(NeighborEvent::LsaUpdateArrived);
        assert_eq!(n.state, NeighborState::Full);
    }

    /// `NeighborEvent::Kill` is the "hard reset" trigger (RFC 2328
    /// §10.6 / §10.1) — inactivity timer expiry, Hello parameter
    /// mismatch, manual reset. The FSM must surface the cause as a
    /// structured `Event::OspfNeighborReset { kind: Kill }` so the
    /// router can record `SessionErrorKind::OspfKill` rather than the
    /// generic `Other` the previous free-form `Event::Log` shape
    /// collapsed into.
    #[test]
    fn kill_emits_structured_ospf_neighbor_reset_event() {
        use lr_core::event::{Event, OspfNeighborResetKind};
        use lr_core::fsm::Action;
        let mut n = OspfNeighbor::new(RouterId::from_u32(0x0A000001));
        // Bring the neighbour up to Full so Kill's Down transition is
        // observable in the action stream.
        n.step(NeighborEvent::HelloSeen {
            dr: 0,
            bdr: 0,
            priority: 1,
        });
        n.step(NeighborEvent::HelloSeen {
            dr: 0,
            bdr: 0,
            priority: 1,
        });
        n.step(NeighborEvent::AdjOk { proceed: true });
        n.step(NeighborEvent::NegotiationDone);
        n.step(NeighborEvent::ExchangeDone);
        n.step(NeighborEvent::LsaUpdateArrived);
        assert_eq!(n.state, NeighborState::Full);
        let actions = n.step(NeighborEvent::Kill);
        assert_eq!(n.state, NeighborState::Down);
        let reset = actions.iter().find_map(|a| match a {
            Action::EmitEvent(Event::OspfNeighborReset { router_id, kind }) => {
                Some((*router_id, *kind))
            }
            _ => None,
        });
        let (router_id, kind) = reset.expect("Kill emits an OspfNeighborReset event");
        assert_eq!(
            router_id, 0x0A000001,
            "the reset carries the neighbour's router-id"
        );
        assert_eq!(
            kind,
            OspfNeighborResetKind::Kill,
            "Kill maps to the Kill variant"
        );
    }

    /// `NeighborEvent::SeqMismatch` (RFC 2328 §10.9 / Fig. 12) restarts
    /// the adjacency negotiation back to ExStart — the neighbour stays
    /// alive. The FSM must surface `OspfNeighborResetKind::SeqMismatch`
    /// so the router records `SessionErrorKind::OspfSeqMismatch`.
    #[test]
    fn seq_mismatch_emits_structured_ospf_neighbor_reset_event() {
        use lr_core::event::{Event, OspfNeighborResetKind};
        use lr_core::fsm::Action;
        let mut n = OspfNeighbor::new(RouterId::from_u32(0x0A000002));
        // Bring the neighbour up to Exchange so the mismatch's
        // transition back to ExStart is observable.
        n.step(NeighborEvent::HelloSeen {
            dr: 0,
            bdr: 0,
            priority: 1,
        });
        n.step(NeighborEvent::HelloSeen {
            dr: 0,
            bdr: 0,
            priority: 1,
        });
        n.step(NeighborEvent::AdjOk { proceed: true });
        n.step(NeighborEvent::NegotiationDone);
        assert_eq!(n.state, NeighborState::Exchange);
        let actions = n.step(NeighborEvent::SeqMismatch);
        assert_eq!(n.state, NeighborState::ExStart);
        let reset = actions.iter().find_map(|a| match a {
            Action::EmitEvent(Event::OspfNeighborReset { router_id, kind }) => {
                Some((*router_id, *kind))
            }
            _ => None,
        });
        let (router_id, kind) = reset.expect("SeqMismatch emits an OspfNeighborReset event");
        assert_eq!(router_id, 0x0A000002);
        assert_eq!(
            kind,
            OspfNeighborResetKind::SeqMismatch,
            "SeqMismatch maps to the SeqMismatch variant (not Kill or BadLsa)"
        );
    }

    /// `NeighborEvent::BadLsa` (RFC 2328 §13.7 / §A.3 — a malformed or
    /// inconsistent LSA in an LS-Update or LS-Request) is distinct from
    /// SeqMismatch even though both restart the adjacency from ExStart.
    /// The FSM must surface `OspfNeighborResetKind::BadLsa` so the
    /// router records `SessionErrorKind::OspfBadLsa` rather than
    /// collapsing the two causes into the same `OspfSeqMismatch`.
    #[test]
    fn bad_lsa_emits_structured_ospf_neighbor_reset_event() {
        use lr_core::event::{Event, OspfNeighborResetKind};
        use lr_core::fsm::Action;
        let mut n = OspfNeighbor::new(RouterId::from_u32(0x0A000003));
        n.step(NeighborEvent::HelloSeen {
            dr: 0,
            bdr: 0,
            priority: 1,
        });
        n.step(NeighborEvent::HelloSeen {
            dr: 0,
            bdr: 0,
            priority: 1,
        });
        n.step(NeighborEvent::AdjOk { proceed: true });
        n.step(NeighborEvent::NegotiationDone);
        assert_eq!(n.state, NeighborState::Exchange);
        let actions = n.step(NeighborEvent::BadLsa);
        assert_eq!(n.state, NeighborState::ExStart);
        let reset = actions.iter().find_map(|a| match a {
            Action::EmitEvent(Event::OspfNeighborReset { router_id, kind }) => {
                Some((*router_id, *kind))
            }
            _ => None,
        });
        let (router_id, kind) = reset.expect("BadLsa emits an OspfNeighborReset event");
        assert_eq!(router_id, 0x0A000003);
        assert_eq!(
            kind,
            OspfNeighborResetKind::BadLsa,
            "BadLsa maps to the BadLsa variant (distinct from SeqMismatch)"
        );
    }

    /// The previous FSM shape emitted `Event::Log("OSPF neighbor X reset")`
    /// for Kill and `Event::Log("OSPF neighbor X exchange restart (sequence
    /// mismatch)")` for SeqMismatch/BadLsa — both free-form strings that
    /// the router collapsed into the generic `SessionErrorKind::Other`.
    /// The structured `Event::OspfNeighborReset` replaces both, but
    /// neither the old `Event::Log` shape nor any other `Event::Log`
    /// should leak through for these three events (the router
    /// synthesises the operator-visible log line itself from the
    /// structured event).
    #[test]
    fn reset_events_do_not_also_emit_log() {
        use lr_core::event::Event;
        use lr_core::fsm::Action;
        let mut n = OspfNeighbor::new(RouterId::from_u32(0x0A000004));
        n.step(NeighborEvent::HelloSeen {
            dr: 0,
            bdr: 0,
            priority: 1,
        });
        n.step(NeighborEvent::HelloSeen {
            dr: 0,
            bdr: 0,
            priority: 1,
        });
        n.step(NeighborEvent::AdjOk { proceed: true });
        n.step(NeighborEvent::NegotiationDone);
        for ev in [
            NeighborEvent::Kill,
            NeighborEvent::SeqMismatch,
            NeighborEvent::BadLsa,
        ] {
            let label = format!("{ev:?}");
            let actions = n.step(ev);
            let has_log = actions
                .iter()
                .any(|a| matches!(a, Action::EmitEvent(Event::Log(_))));
            assert!(
                !has_log,
                "the {label} event must not also emit an Event::Log; the router synthesises the log line"
            );
            // Re-establish the neighbour between iterations so the
            // next event has somewhere to transition from.
            n.step(NeighborEvent::HelloSeen {
                dr: 0,
                bdr: 0,
                priority: 1,
            });
            n.step(NeighborEvent::HelloSeen {
                dr: 0,
                bdr: 0,
                priority: 1,
            });
            n.step(NeighborEvent::AdjOk { proceed: true });
            n.step(NeighborEvent::NegotiationDone);
        }
    }
}
