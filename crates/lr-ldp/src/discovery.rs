//! LDP discovery: Hello adjacencies (RFC 5036 §1.5.2, §3.5.2.1).
//!
//! Hellos create and refresh Hello adjacencies. Each adjacency binds a
//! peer label space to a transport address, negotiates the hold time
//! (the minimum of the two proposals, where 0 selects the 15 s link /
//! 45 s targeted defaults and 0xffff proposes effectively infinite)
//! and expires when no Hello arrives within the negotiated hold time.
//! When an R=1 targeted Hello is received and the local speaker is
//! configured to accept targeted Hellos, periodic targeted Hellos are
//! sent back to the source (§3.5.2.1, extended discovery).
//!
//! No I/O happens here: the embedder feeds received Hellos in via
//! [`LdpDiscovery::feed_hello`], drains outbound Hellos via
//! [`LdpDiscovery::drain_outgoing`] and drives
//! [`LdpDiscovery::tick`] with the current time.

use crate::message::{HelloMsg, LdpMessage};
use crate::pdu::{LdpId, DEFAULT_LINK_HELLO_HOLD, DEFAULT_TARGETED_HELLO_HOLD};
use crate::tlv::{HelloParams, TransportAddress};
use alloc::vec::Vec;
use lr_core::addr::IpAddr;
use lr_core::time::{Duration, Instant};

/// Whether an adjacency was created by Link Hellos (basic discovery,
/// multicast on a shared segment) or Targeted Hellos (extended
/// discovery, unicast).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DiscoveryKind {
    Link,
    Targeted,
}

/// A Hello adjacency (§1.5.2): one per (peer label space, discovery
/// kind, source pair).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HelloAdjacency {
    /// The peer's label space (from the Hello PDU header).
    pub peer_id: LdpId,
    pub kind: DiscoveryKind,
    /// The UDP source address of the Hellos.
    pub source: IpAddr,
    /// The transport address the peer advertises for its TCP endpoint
    /// (Transport Address TLV, falling back to the Hello source).
    pub transport_addr: IpAddr,
    /// The negotiated hold time.
    pub hold_time: Duration,
    /// Time of the most recent matching Hello.
    pub last_seen: Instant,
    /// The peer's Configuration Sequence Number, when sent.
    pub config_seq: Option<u32>,
}

/// Events from the discovery machinery.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DiscoveryEvent {
    /// A new Hello adjacency was created.
    AdjacencyUp(HelloAdjacency),
    /// A Hello adjacency expired (hold timer, §3.5.2.1).
    AdjacencyDown {
        peer_id: LdpId,
        kind: DiscoveryKind,
        source: IpAddr,
    },
    /// A targeted Hello requested that we send targeted Hellos back
    /// (R=1) and we accepted: respond in kind.
    TargetedHelloRequested { source: IpAddr, peer_id: LdpId },
}

/// An outbound Hello the embedder should transmit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutgoingHello {
    /// Destination address (unicast for targeted; the multicast group
    /// for link discovery is the embedder's choice — 224.0.0.2 /
    /// ff02::2 with TTL 1 per §3.5.2 — fed back through
    /// [`LdpDiscovery::feed_hello`] on receipt).
    pub dest: IpAddr,
    pub message: LdpMessage,
}

/// Discovery configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LdpDiscoveryConfig {
    /// The local label space advertised in Hello PDU headers.
    pub local_id: LdpId,
    /// The transport address advertised in Hellos (the TCP endpoint).
    pub transport_addr: IpAddr,
    /// Proposed Link Hello hold time (0 → 15 s default).
    pub link_hello_hold: u16,
    /// Proposed Targeted Hello hold time (0 → 45 s default).
    pub targeted_hello_hold: u16,
    /// Peers to which periodic targeted Hellos are sent.
    pub targeted_peers: Vec<IpAddr>,
    /// Whether targeted Hellos from others are accepted (and answered
    /// when they carry R=1).
    pub accept_targeted: bool,
}

impl Default for LdpDiscoveryConfig {
    fn default() -> Self {
        Self {
            local_id: LdpId::default(),
            transport_addr: IpAddr::V4([0, 0, 0, 0]),
            link_hello_hold: DEFAULT_LINK_HELLO_HOLD,
            targeted_hello_hold: DEFAULT_TARGETED_HELLO_HOLD,
            targeted_peers: Vec::new(),
            accept_targeted: true,
        }
    }
}

/// The discovery machinery: adjacency bookkeeping plus outbound hello
/// scheduling.
pub struct LdpDiscovery {
    cfg: LdpDiscoveryConfig,
    adjacencies: Vec<HelloAdjacency>,
    /// Targets we owe periodic targeted Hellos, with the time of the
    /// most recent Hello sent (`None` = not sent yet, due now).
    targeted_targets: Vec<(IpAddr, Option<Instant>)>,
    outgoing: Vec<OutgoingHello>,
    next_message_id: u32,
}

impl LdpDiscovery {
    pub fn new(cfg: LdpDiscoveryConfig) -> Self {
        let targeted_targets = cfg.targeted_peers.iter().map(|p| (*p, None)).collect();
        Self {
            cfg,
            adjacencies: Vec::new(),
            targeted_targets,
            outgoing: Vec::new(),
            next_message_id: 1,
        }
    }

    pub fn config(&self) -> &LdpDiscoveryConfig {
        &self.cfg
    }

    /// The live adjacencies.
    pub fn adjacencies(&self) -> &[HelloAdjacency] {
        &self.adjacencies
    }

    /// Find the adjacency binding a peer label space to a transport
    /// address (the §2.5.3 passive-role adjacency match).
    pub fn adjacency_for_peer(&self, peer_id: LdpId) -> Option<&HelloAdjacency> {
        self.adjacencies.iter().find(|a| a.peer_id == peer_id)
    }

    /// Forget every adjacency bound to a peer label space (session
    /// teardown companion). Configured targeted peers keep receiving
    /// Hellos.
    pub fn remove_adjacencies_for_peer(&mut self, peer_id: LdpId) {
        let sources: Vec<IpAddr> = self
            .adjacencies
            .iter()
            .filter(|a| a.peer_id == peer_id)
            .map(|a| a.source)
            .collect();
        self.adjacencies.retain(|a| a.peer_id != peer_id);
        self.targeted_targets.retain(|(t, _)| {
            self.cfg.targeted_peers.contains(t)
                || self
                    .adjacencies
                    .iter()
                    .any(|a| a.kind == DiscoveryKind::Targeted && a.source == *t)
        });
        let _ = sources;
    }

    /// Process a received Hello. `source` is the UDP source address.
    pub fn feed_hello(
        &mut self,
        now: Instant,
        pdu: &crate::message::LdpPdu,
        hello: &HelloMsg,
        source: IpAddr,
    ) -> Vec<DiscoveryEvent> {
        let mut events = Vec::new();
        // Acceptability (§3.5.2.1): targeted Hellos are only accepted
        // when configured; link Hellos are acceptable on label-switching
        // interfaces, which the embedder filters before feeding us.
        if hello.params.targeted && !self.cfg.accept_targeted {
            return events;
        }
        let kind = if hello.params.targeted {
            DiscoveryKind::Targeted
        } else {
            DiscoveryKind::Link
        };
        let transport_addr = hello.transport_addr.map(|t| t.0).unwrap_or(source);
        let hold = Self::effective_hold(
            hello.params.hold_time,
            match kind {
                DiscoveryKind::Link => self.cfg.link_hello_hold,
                DiscoveryKind::Targeted => self.cfg.targeted_hello_hold,
            },
        );
        if let Some(adj) = self
            .adjacencies
            .iter_mut()
            .find(|a| a.peer_id == pdu.sender && a.kind == kind && a.source == source)
        {
            // Restart the hold timer (§3.5.2.1 step 3).
            adj.last_seen = now;
            adj.transport_addr = transport_addr;
            adj.hold_time = hold;
            adj.config_seq = hello.config_seq.map(|c| c.0);
        } else {
            let adjacency = HelloAdjacency {
                peer_id: pdu.sender,
                kind,
                source,
                transport_addr,
                hold_time: hold,
                last_seen: now,
                config_seq: hello.config_seq.map(|c| c.0),
            };
            self.adjacencies.push(adjacency.clone());
            events.push(DiscoveryEvent::AdjacencyUp(adjacency));
        }
        // R=1: request to receive targeted Hellos back (§3.5.2.1).
        if hello.params.request_targeted
            && kind == DiscoveryKind::Targeted
            && !self.targeted_targets.iter().any(|(t, _)| *t == source)
        {
            self.targeted_targets.push((source, None));
            events.push(DiscoveryEvent::TargetedHelloRequested {
                source,
                peer_id: pdu.sender,
            });
        }
        events
    }

    /// Advance timers: expire adjacencies and schedule due Hellos.
    pub fn tick(&mut self, now: Instant) -> Vec<DiscoveryEvent> {
        let mut events = Vec::new();
        // Expiry (§3.5.2.1): discard adjacencies whose hold timer ran
        // out.
        let expired: Vec<HelloAdjacency> = self
            .adjacencies
            .iter()
            .filter(|a| now.saturating_sub(a.last_seen).as_millis() >= a.hold_time.as_millis())
            .cloned()
            .collect();
        for adj in expired {
            events.push(DiscoveryEvent::AdjacencyDown {
                peer_id: adj.peer_id,
                kind: adj.kind,
                source: adj.source,
            });
            self.adjacencies.retain(|a| {
                !(a.peer_id == adj.peer_id && a.kind == adj.kind && a.source == adj.source)
            });
            if adj.kind == DiscoveryKind::Targeted && !self.cfg.targeted_peers.contains(&adj.source)
            {
                self.targeted_targets.retain(|(t, _)| *t != adj.source);
            }
        }
        // Outbound targeted Hellos: every hold/3 (§3.5.2.1 recommends
        // at most one third of the hold time between Hellos).
        let interval = (self.cfg.targeted_hello_hold as u64).max(1) * 1000 / 3;
        let due: Vec<IpAddr> = self
            .targeted_targets
            .iter()
            .filter(|(_, last)| {
                last.map(|l| now.saturating_sub(l).as_millis() >= interval)
                    .unwrap_or(true)
            })
            .map(|(t, _)| *t)
            .collect();
        for target in due {
            if let Some(entry) = self.targeted_targets.iter_mut().find(|(t, _)| *t == target) {
                entry.1 = Some(now);
            }
            let message_id = self.alloc_message_id();
            self.outgoing.push(OutgoingHello {
                dest: target,
                message: LdpMessage::Hello(HelloMsg {
                    message_id,
                    params: HelloParams {
                        hold_time: self.cfg.targeted_hello_hold,
                        targeted: true,
                        request_targeted: false,
                    },
                    transport_addr: Some(TransportAddress(self.cfg.transport_addr)),
                    config_seq: None,
                    unknown_tlvs: Vec::new(),
                }),
            });
        }
        events
    }

    /// Drain outbound Hellos.
    pub fn drain_outgoing(&mut self) -> Vec<OutgoingHello> {
        core::mem::take(&mut self.outgoing)
    }

    fn alloc_message_id(&mut self) -> u32 {
        let id = self.next_message_id;
        self.next_message_id = self.next_message_id.wrapping_add(1);
        id
    }

    /// Map a peer's proposed hold time through the §3.5.2 rules
    /// (0 → default; 0xffff = effectively infinite) and take the
    /// minimum against our proposal.
    fn effective_hold(peer_proposed: u16, local_proposed: u16) -> Duration {
        let peer = if peer_proposed == 0 {
            local_proposed
        } else {
            peer_proposed
        };
        let local = if local_proposed == 0 {
            DEFAULT_LINK_HELLO_HOLD
        } else {
            local_proposed
        };
        Duration::from_secs(peer.min(local).max(1) as u64)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::message::LdpPdu;
    use crate::tlv::{ConfigSequenceNumber, HelloParams};

    fn id(v: u8) -> LdpId {
        LdpId::new([v, 0, 0, 1], 0)
    }

    fn hello_pdu(
        sender: LdpId,
        targeted: bool,
        hold: u16,
        transport: Option<IpAddr>,
    ) -> (LdpPdu, HelloMsg) {
        let msg = HelloMsg {
            message_id: 1,
            params: HelloParams {
                hold_time: hold,
                targeted,
                request_targeted: false,
            },
            transport_addr: transport.map(TransportAddress),
            config_seq: None,
            unknown_tlvs: Vec::new(),
        };
        let pdu = LdpPdu {
            version: 1,
            sender,
            messages: vec![LdpMessage::Hello(msg.clone())],
        };
        (pdu, msg)
    }

    fn cfg() -> LdpDiscoveryConfig {
        LdpDiscoveryConfig {
            local_id: id(1),
            transport_addr: IpAddr::V4([192, 0, 2, 1]),
            ..LdpDiscoveryConfig::default()
        }
    }

    #[test]
    fn adjacency_created_and_refreshed() {
        let now = Instant::from_secs(0);
        let mut d = LdpDiscovery::new(cfg());
        let (pdu, msg) = hello_pdu(id(2), true, 45, Some(IpAddr::V4([192, 0, 2, 2])));
        let events = d.feed_hello(now, &pdu, &msg, IpAddr::V4([192, 0, 2, 2]));
        assert_eq!(events.len(), 1);
        match &events[0] {
            DiscoveryEvent::AdjacencyUp(a) => {
                assert_eq!(a.peer_id, id(2));
                assert_eq!(a.kind, DiscoveryKind::Targeted);
                assert_eq!(a.transport_addr, IpAddr::V4([192, 0, 2, 2]));
                // min(45, 45) seconds.
                assert_eq!(a.hold_time.as_secs(), 45);
            }
            other => panic!("wrong event {other:?}"),
        }
        // A second hello refreshes instead of re-creating.
        let events = d.feed_hello(
            Instant::from_secs(5),
            &pdu,
            &msg,
            IpAddr::V4([192, 0, 2, 2]),
        );
        assert!(events.is_empty());
        assert_eq!(d.adjacencies().len(), 1);
        assert_eq!(d.adjacencies()[0].last_seen, Instant::from_secs(5));
    }

    #[test]
    fn hold_time_negotiated_to_minimum() {
        let now = Instant::from_secs(0);
        let mut d = LdpDiscovery::new(cfg());
        // Peer proposes 0 → default 45 (targeted); we propose 45 → 45.
        let (pdu, msg) = hello_pdu(id(2), true, 0, None);
        let _ = d.feed_hello(now, &pdu, &msg, IpAddr::V4([192, 0, 2, 2]));
        assert_eq!(d.adjacencies()[0].hold_time.as_secs(), 45);
        // Peer proposes 10 → min(10, 45) = 10.
        let (pdu, msg) = hello_pdu(id(3), true, 10, None);
        let _ = d.feed_hello(now, &pdu, &msg, IpAddr::V4([192, 0, 2, 3]));
        assert_eq!(d.adjacencies()[1].hold_time.as_secs(), 10);
        // Link hello default: peer 0 → we propose 15 → 15.
        let (pdu, msg) = hello_pdu(id(4), false, 0, None);
        let _ = d.feed_hello(now, &pdu, &msg, IpAddr::V4([192, 0, 2, 4]));
        assert_eq!(d.adjacencies()[2].hold_time.as_secs(), 15);
    }

    #[test]
    fn adjacency_expiry() {
        let now = Instant::from_secs(0);
        let mut d = LdpDiscovery::new(cfg());
        let (pdu, msg) = hello_pdu(id(2), true, 9, None);
        let _ = d.feed_hello(now, &pdu, &msg, IpAddr::V4([192, 0, 2, 2]));
        // 8s: still alive (9s hold).
        let events = d.tick(Instant::from_secs(8));
        assert!(events.is_empty());
        assert_eq!(d.adjacencies().len(), 1);
        // 9s: expired.
        let events = d.tick(Instant::from_secs(9));
        match &events[0] {
            DiscoveryEvent::AdjacencyDown { peer_id, kind, .. } => {
                assert_eq!(*peer_id, id(2));
                assert_eq!(*kind, DiscoveryKind::Targeted);
            }
            other => panic!("wrong event {other:?}"),
        }
        assert!(d.adjacencies().is_empty());
    }

    #[test]
    fn targeted_accept_policy() {
        let now = Instant::from_secs(0);
        let cfg = LdpDiscoveryConfig {
            accept_targeted: false,
            ..cfg()
        };
        let mut d = LdpDiscovery::new(cfg);
        let (pdu, msg) = hello_pdu(id(2), true, 45, None);
        let events = d.feed_hello(now, &pdu, &msg, IpAddr::V4([192, 0, 2, 2]));
        assert!(events.is_empty());
        assert!(d.adjacencies().is_empty());
    }

    #[test]
    fn targeted_peers_get_periodic_hellos() {
        let cfg = LdpDiscoveryConfig {
            targeted_peers: Vec::from([IpAddr::V4([192, 0, 2, 9])]),
            ..cfg()
        };
        let mut d = LdpDiscovery::new(cfg);
        let _ = d.tick(Instant::from_secs(0));
        let out = d.drain_outgoing();
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].dest, IpAddr::V4([192, 0, 2, 9]));
        match &out[0].message {
            LdpMessage::Hello(h) => {
                assert!(h.params.targeted);
                assert_eq!(h.params.hold_time, DEFAULT_TARGETED_HELLO_HOLD);
                assert_eq!(
                    h.transport_addr,
                    Some(TransportAddress(IpAddr::V4([192, 0, 2, 1])))
                );
            }
            other => panic!("wrong message {other:?}"),
        }
        // The interval is hold/3 = 15s; a tick at 10s sends nothing.
        let _ = d.drain_outgoing();
        let _ = d.tick(Instant::from_secs(10));
        assert!(d.drain_outgoing().is_empty());
        // At 15s the next Hello is due.
        let _ = d.tick(Instant::from_secs(15));
        assert_eq!(d.drain_outgoing().len(), 1);
        let _ = d.drain_outgoing();
    }

    #[test]
    fn r1_request_creates_response_target() {
        let now = Instant::from_secs(0);
        let mut d = LdpDiscovery::new(cfg());
        let msg = HelloMsg {
            message_id: 1,
            params: HelloParams {
                hold_time: 45,
                targeted: true,
                request_targeted: true,
            },
            transport_addr: None,
            config_seq: None,
            unknown_tlvs: Vec::new(),
        };
        let pdu = LdpPdu {
            version: 1,
            sender: id(2),
            messages: vec![LdpMessage::Hello(msg.clone())],
        };
        let events = d.feed_hello(now, &pdu, &msg, IpAddr::V4([192, 0, 2, 7]));
        match &events[1] {
            DiscoveryEvent::TargetedHelloRequested { source, .. } => {
                assert_eq!(*source, IpAddr::V4([192, 0, 2, 7]));
            }
            other => panic!("wrong event {other:?}"),
        }
        // The responder now emits periodic targeted Hellos to the source.
        let _ = d.tick(Instant::from_secs(1));
        let out = d.drain_outgoing();
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].dest, IpAddr::V4([192, 0, 2, 7]));
    }

    #[test]
    fn config_sequence_number_tracked() {
        let now = Instant::from_secs(0);
        let mut d = LdpDiscovery::new(cfg());
        let msg = HelloMsg {
            message_id: 1,
            params: HelloParams {
                hold_time: 45,
                targeted: true,
                request_targeted: false,
            },
            transport_addr: None,
            config_seq: Some(ConfigSequenceNumber(7)),
            unknown_tlvs: Vec::new(),
        };
        let pdu = LdpPdu {
            version: 1,
            sender: id(2),
            messages: vec![LdpMessage::Hello(msg.clone())],
        };
        let _ = d.feed_hello(now, &pdu, &msg, IpAddr::V4([192, 0, 2, 7]));
        assert_eq!(d.adjacencies()[0].config_seq, Some(7));
    }

    #[test]
    fn transport_address_falls_back_to_source() {
        let now = Instant::from_secs(0);
        let mut d = LdpDiscovery::new(cfg());
        let (pdu, msg) = hello_pdu(id(2), true, 45, None);
        let _ = d.feed_hello(now, &pdu, &msg, IpAddr::V4([192, 0, 2, 8]));
        assert_eq!(
            d.adjacencies()[0].transport_addr,
            IpAddr::V4([192, 0, 2, 8])
        );
    }
}
