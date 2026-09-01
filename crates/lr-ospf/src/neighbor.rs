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
                actions.push(Action::EmitEvent(lr_core::event::Event::Log(format!(
                    "OSPF neighbor {} reset",
                    self.router_id
                ))));
                NeighborState::Down
            }
            // RFC 2328 §10.9 / Fig. 12: a sequence mismatch or a bad
            // LSA in the exchange states restarts the *adjacency
            // negotiation* (back to ExStart), not the neighbor.
            (_, NeighborEvent::SeqMismatch) | (_, NeighborEvent::BadLsa) => {
                actions.push(Action::EmitEvent(lr_core::event::Event::Log(format!(
                    "OSPF neighbor {} exchange restart (sequence mismatch)",
                    self.router_id
                ))));
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
}
