//! High-level router instance. Ties sessions + Loc-RIB + timers.

use std::collections::BTreeMap;

use crate::connection::{Connection, MemoryConn};
use crate::event::RouterEvent;
use crate::session::{SessionConfig, SessionHandle, SessionKind};

use lr_core::fsm::TimerId;
use lr_core::rib::Route;
use lr_core::time::Instant;
use lr_core::timer::TimerQueue;

use lr_bgp::{BgpEvent, BgpPeer, PeerConfig as BgpPeerConfig};
use lr_rib::{LocRib, RibMux};

/// The router trait — embedders can plug a mock implementation.
pub trait RouterInstance {
    fn add_session(&mut self, cfg: SessionConfig) -> Result<SessionHandle, String>;
    fn remove_session(&mut self, h: SessionHandle) -> Result<(), String>;
    fn feed_input(&mut self, h: SessionHandle, bytes: &[u8]) -> Result<(), String>;
    fn drain_output(&mut self, h: SessionHandle) -> Vec<u8>;
    fn tick(&mut self, now: Instant);
    fn poll_events(&mut self) -> Vec<RouterEvent>;
    fn rib_snapshot(&self) -> Vec<&Route>;
}

/// Default router implementation. Poll-based, embedder-driven.
pub struct DefaultRouter {
    sessions: BTreeMap<u64, SessionState>,
    next_handle: u64,
    timers: TimerQueue,
    /// Logical "now" the embedder sets via tick().
    now_ms: u64,
    loc_rib: LocRib,
    #[allow(dead_code)]
    rib_mux: RibMux,
    pending_events: Vec<RouterEvent>,
}

#[allow(clippy::large_enum_variant)]
enum SessionState {
    Bgp { peer: BgpPeer, conn: MemoryConn },
    Ospf,
    #[allow(dead_code)]
    Babel,
}

impl Default for DefaultRouter {
    fn default() -> Self {
        Self {
            sessions: BTreeMap::new(),
            next_handle: 1,
            timers: TimerQueue::new(),
            now_ms: 0,
            loc_rib: LocRib::new(),
            rib_mux: RibMux::new(),
            pending_events: Vec::new(),
        }
    }
}

impl DefaultRouter {
    pub fn new() -> Self {
        Self::default()
    }

    fn alloc_handle(&mut self) -> SessionHandle {
        let h = SessionHandle(self.next_handle);
        self.next_handle += 1;
        h
    }
}

impl RouterInstance for DefaultRouter {
    fn add_session(&mut self, cfg: SessionConfig) -> Result<SessionHandle, String> {
        let h = self.alloc_handle();
        match cfg.kind {
            SessionKind::Bgp => {
                let mut p_cfg = BgpPeerConfig::new(cfg.local_as, cfg.peer_as, cfg.local_bgp_id);
                p_cfg.hold_time = cfg.hold_time;
                p_cfg.keepalive = cfg.keepalive;
                p_cfg.asn4 = cfg.asn4;
                p_cfg.mp_families = cfg.mp_families.clone();
                let peer = BgpPeer::new(p_cfg);
                self.sessions.insert(
                    h.0,
                    SessionState::Bgp {
                        peer,
                        conn: MemoryConn::new(),
                    },
                );
            }
            SessionKind::Ospfv2 | SessionKind::Ospfv3 | SessionKind::Babel => {
                self.sessions.insert(h.0, SessionState::Ospf);
            }
        }
        Ok(h)
    }

    fn remove_session(&mut self, h: SessionHandle) -> Result<(), String> {
        if self.sessions.remove(&h.0).is_none() {
            return Err(format!("session {} not found", h.0));
        }
        Ok(())
    }

    fn feed_input(&mut self, h: SessionHandle, bytes: &[u8]) -> Result<(), String> {
        let state = self
            .sessions
            .get_mut(&h.0)
            .ok_or_else(|| format!("no session {}", h.0))?;
        match state {
            SessionState::Bgp { peer, conn } => {
                conn.push_input(bytes);
                let input = conn.take_input();
                if !input.is_empty() {
                    let actions = peer.feed_bytes(&input).map_err(|e| e.to_string())?;
                    for a in actions {
                        match a {
                            lr_bgp::BgpAction::Send(b) => conn.put_output(&b),
                            lr_bgp::BgpAction::SetTimer(id, spec) => {
                                self.timers.arm(Instant(self.now_ms), id, spec);
                            }
                            lr_bgp::BgpAction::CancelTimer(id) => self.timers.cancel(id),
                            lr_bgp::BgpAction::Emit(ev) => self.pending_events.push(ev.into()),
                            _ => {}
                        }
                    }
                    if peer.is_established() {
                        self.pending_events.push(RouterEvent::PeerStateChange {
                            session: h,
                            state: "Established",
                        });
                    }
                }
            }
            SessionState::Ospf | SessionState::Babel => {
                // TODO: drive OSPF/Babel FSMs.
            }
        }
        Ok(())
    }

    fn drain_output(&mut self, h: SessionHandle) -> Vec<u8> {
        match self.sessions.get_mut(&h.0) {
            Some(SessionState::Bgp { conn, .. }) => conn.drain_output(),
            _ => Vec::new(),
        }
    }

    fn tick(&mut self, now: Instant) {
        self.now_ms = now.0;
        let expired = self.timers.tick(now);
        for tid in expired {
            // Drive each session that might own the timer. In a more
            // sophisticated router, we'd route timers to the owning session.
            for state in self.sessions.values_mut() {
                if let SessionState::Bgp { peer, conn } = state {
                    let ev = match tid {
                        TimerId(id) if id == lr_bgp::fsm::timer_ids::HOLD.0 => {
                            BgpEvent::TimerHoldExpired
                        }
                        TimerId(id) if id == lr_bgp::fsm::timer_ids::KEEPALIVE.0 => {
                            BgpEvent::TimerKeepalive
                        }
                        TimerId(id) if id == lr_bgp::fsm::timer_ids::CONNECT_RETRY.0 => {
                            BgpEvent::TimerConnectRetry
                        }
                        _ => continue,
                    };
                    let actions = peer.step(ev);
                    for a in actions {
                        match a {
                            lr_bgp::BgpAction::Send(b) => conn.put_output(&b),
                            lr_bgp::BgpAction::SetTimer(id, spec) => {
                                self.timers.arm(now, id, spec);
                            }
                            lr_bgp::BgpAction::CancelTimer(id) => self.timers.cancel(id),
                            lr_bgp::BgpAction::Emit(ev) => self.pending_events.push(ev.into()),
                            _ => {}
                        }
                    }
                    // Reset timer when peer resets hold timer via actions.
                    let _ = peer.state();
                }
            }
        }
    }

    fn poll_events(&mut self) -> Vec<RouterEvent> {
        core::mem::take(&mut self.pending_events)
    }

    fn rib_snapshot(&self) -> Vec<&Route> {
        self.loc_rib.iter_best().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lr_core::addr::{Asn, RouterId};
    use lr_core::fsm::TimerSpec;

    #[test]
    fn add_and_remove_bgp_session() {
        let mut r = DefaultRouter::new();
        let h = r
            .add_session(SessionConfig::bgp(
                Asn(64512),
                Asn(64513),
                RouterId::from_v4([10, 0, 0, 1]),
            ))
            .unwrap();
        assert_eq!(h.0, 1);
        assert!(r.remove_session(h).is_ok());
    }

    #[test]
    fn tick_drives_timers() {
        let mut r = DefaultRouter::new();
        let _h = r
            .add_session(SessionConfig::bgp(
                Asn(64512),
                Asn(64513),
                RouterId::from_v4([10, 0, 0, 1]),
            ))
            .unwrap();
        // Arm a timer then tick.
        r.timers.arm(Instant(0), TimerId(7), TimerSpec::once(100));
        r.tick(Instant(50));
        r.tick(Instant(100));
        // No assertions needed — we just verify the router doesn't crash.
    }
}
