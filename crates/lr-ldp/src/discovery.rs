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
use crate::tlv::{DualStackCapability, HelloParams, TransportAddress, TransportPreference};
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
    /// (Transport Address TLV of the Hello's own address family per
    /// RFC 7552 §6.1, falling back to the Hello source).
    pub transport_addr: IpAddr,
    /// The negotiated hold time.
    pub hold_time: Duration,
    /// Time of the most recent matching Hello.
    pub last_seen: Instant,
    /// The peer's Configuration Sequence Number, when sent.
    pub config_seq: Option<u32>,
    /// The RFC 7552 §6.1.1 Dual-Stack capability the peer advertises
    /// in these Hellos, when present. `None` on none: a peer heard in
    /// both address families without this capability is a
    /// noncompliant dual-stack neighbor (§6.1.1 rule 3c) and must not
    /// get a session.
    pub dual_stack: Option<TransportPreference>,
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
    /// A Hello was discarded: the embedder should log it. Reasons are
    /// the RFC 7552 §6.1.1 checks (preference mismatch, capability
    /// inconsistency).
    HelloDiscarded {
        peer_id: LdpId,
        source: IpAddr,
        reason: &'static str,
    },
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
    /// The IPv4 transport address advertised in IPv4 Hellos (the TCP
    /// endpoint).
    pub transport_addr: IpAddr,
    /// The IPv6 transport address advertised in IPv6 Hellos (RFC
    /// 7552 §6.1 rule 5: a global unicast address, preferred over
    /// unique-local or link-local). `None` = single-stack IPv4
    /// speaker.
    pub transport_addr_v6: Option<IpAddr>,
    /// The §6.1.1 transport-connection preference sent in the
    /// Dual-Stack capability (only carried by dual-stack speakers).
    /// The RFC default is LDPoIPv6.
    pub prefer_ipv6: bool,
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
            transport_addr_v6: None,
            prefer_ipv6: true,
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
        // RFC 7552 §6.1.1: a dual-stack LSR MUST check the Dual-Stack
        // capability in received Hellos. When the local speaker is
        // dual-stack for this peer, a capability whose preference does
        // not match (or is not recognized) means the Hello MUST be
        // discarded. An unrecognized TR value already fails the TLV
        // parse, so a parsed capability always has a known preference.
        if let Some(cap) = hello.dual_stack {
            if self.is_dual_stack() && cap.preference != self.local_preference() {
                events.push(DiscoveryEvent::HelloDiscarded {
                    peer_id: pdu.sender,
                    source,
                    reason: "dual-stack transport preference mismatch",
                });
                return events;
            }
        }
        // Transport address (§3.5.2.1 + RFC 7552 §6.1): only the TLV
        // of the carrying packet's family counts; fall back to the UDP
        // source when none was carried.
        let transport_addr = hello
            .transport_addr_for(&source)
            .map(|t| t.0)
            .unwrap_or(source);
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
            adj.dual_stack = hello.dual_stack.map(|c| c.preference);
        } else {
            let adjacency = HelloAdjacency {
                peer_id: pdu.sender,
                kind,
                source,
                transport_addr,
                hold_time: hold,
                last_seen: now,
                config_seq: hello.config_seq.map(|c| c.0),
                dual_stack: hello.dual_stack.map(|c| c.preference),
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
            // Per-family transport TLV + the dual-stack capability;
            // None = no local address in the target's family (skip —
            // the embedder should not have us targeted over an AF it
            // did not configure).
            if let Some(message) = self.build_hello(&target, true) {
                self.outgoing.push(OutgoingHello {
                    dest: target,
                    message: LdpMessage::Hello(message),
                });
            }
        }
        events
    }

    /// Drain outbound Hellos.
    pub fn drain_outgoing(&mut self) -> Vec<OutgoingHello> {
        core::mem::take(&mut self.outgoing)
    }

    /// Whether the local speaker runs dual-stack LDP (both transport
    /// addresses configured). Dual-stack LSRs carry the RFC 7552
    /// §6.1.1 Dual-Stack capability in every Hello.
    fn is_dual_stack(&self) -> bool {
        self.cfg.transport_addr_v6.is_some()
    }

    /// The local §6.1.1 transport-connection preference.
    fn local_preference(&self) -> TransportPreference {
        if self.cfg.prefer_ipv6 {
            TransportPreference::Ipv6
        } else {
            TransportPreference::Ipv4
        }
    }

    /// The transport address of `dest`'s address family (RFC 7552
    /// §6.1 rule 1: a Hello carries only the transport address of its
    /// own family). The primary `transport_addr` serves its own
    /// family — a speaker may legitimately be IPv6-only with only
    /// that field set. `None` = the speaker has no address in that
    /// family and must not originate the Hello.
    fn transport_for_af(&self, dest: &IpAddr) -> Option<TransportAddress> {
        self.local_transport(matches!(dest, IpAddr::V6(_)))
            .map(TransportAddress)
    }

    /// The local transport address of one address family.
    fn local_transport(&self, af_v6: bool) -> Option<IpAddr> {
        if af_v6 {
            match self.cfg.transport_addr_v6 {
                Some(v6) => Some(v6),
                None => match self.cfg.transport_addr {
                    IpAddr::V6(_) => Some(self.cfg.transport_addr),
                    IpAddr::V4(_) => None,
                },
            }
        } else {
            match self.cfg.transport_addr {
                IpAddr::V4(_) => Some(self.cfg.transport_addr),
                IpAddr::V6(_) => None,
            }
        }
    }

    /// Build one Hello message for `dest`, with the family-correct
    /// transport address TLV and — on dual-stack speakers — the RFC
    /// 7552 §6.1.1 Dual-Stack capability.
    pub(crate) fn build_hello(&mut self, dest: &IpAddr, targeted: bool) -> Option<HelloMsg> {
        let transport_addr = self.transport_for_af(dest)?;
        let message_id = self.alloc_message_id();
        let dual_stack = if self.is_dual_stack() {
            Some(DualStackCapability {
                preference: self.local_preference(),
            })
        } else {
            None
        };
        Some(HelloMsg {
            message_id,
            params: HelloParams {
                hold_time: if targeted {
                    self.cfg.targeted_hello_hold
                } else {
                    self.cfg.link_hello_hold
                },
                targeted,
                request_targeted: false,
            },
            transport_addr: match transport_addr {
                TransportAddress(IpAddr::V4(_)) => Some(transport_addr),
                _ => None,
            },
            transport_addr_v6: match transport_addr {
                TransportAddress(IpAddr::V6(_)) => Some(transport_addr),
                _ => None,
            },
            config_seq: None,
            dual_stack,
            unknown_tlvs: Vec::new(),
        })
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
            transport_addr_v6: None,
            config_seq: None,
            dual_stack: None,
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
            transport_addr_v6: None,
            config_seq: None,
            dual_stack: None,
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
            transport_addr_v6: None,
            config_seq: Some(ConfigSequenceNumber(7)),
            dual_stack: None,
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

    // ---- RFC 7552 §6.1: per-family transport-address handling ----

    fn hello_pdu_full(
        sender: LdpId,
        targeted: bool,
        hold: u16,
        transport_v4: Option<IpAddr>,
        transport_v6: Option<IpAddr>,
        dual_stack: Option<TransportPreference>,
    ) -> (LdpPdu, HelloMsg) {
        let msg = HelloMsg {
            message_id: 1,
            params: HelloParams {
                hold_time: hold,
                targeted,
                request_targeted: false,
            },
            transport_addr: transport_v4.map(TransportAddress),
            transport_addr_v6: transport_v6.map(TransportAddress),
            config_seq: None,
            dual_stack: dual_stack.map(|preference| DualStackCapability { preference }),
            unknown_tlvs: Vec::new(),
        };
        let pdu = LdpPdu {
            version: 1,
            sender,
            messages: vec![LdpMessage::Hello(msg.clone())],
        };
        (pdu, msg)
    }

    fn dual_cfg() -> LdpDiscoveryConfig {
        LdpDiscoveryConfig {
            local_id: id(1),
            transport_addr: IpAddr::V4([192, 0, 2, 1]),
            transport_addr_v6: Some(IpAddr::V6([
                0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
            ])),
            ..LdpDiscoveryConfig::default()
        }
    }

    #[test]
    fn rfc7552_same_af_transport_tlv_wins() {
        // A (noncompliant) Hello carrying both families inside an IPv6
        // datagram: only the v6 transport address may be used (§6.1
        // rule 2).
        let now = Instant::from_secs(0);
        let mut d = LdpDiscovery::new(dual_cfg());
        let (pdu, msg) = hello_pdu_full(
            id(2),
            true,
            45,
            Some(IpAddr::V4([192, 0, 2, 2])),
            Some(IpAddr::V6([
                0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2,
            ])),
            Some(TransportPreference::Ipv6),
        );
        let _ = d.feed_hello(
            now,
            &pdu,
            &msg,
            IpAddr::V6([0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]),
        );
        let adj = &d.adjacencies()[0];
        assert_eq!(
            adj.transport_addr,
            IpAddr::V6([0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2])
        );
        assert_eq!(adj.dual_stack, Some(TransportPreference::Ipv6));
    }

    #[test]
    fn rfc7552_dual_stack_v6_hello_without_v6_tlv_uses_source() {
        // A v6 Hello with no v6 transport TLV: the source-address
        // fallback of §3.5.2.1 applies (not the v4 TLV!).
        let now = Instant::from_secs(0);
        let mut d = LdpDiscovery::new(dual_cfg());
        let (pdu, msg) = hello_pdu_full(
            id(2),
            true,
            45,
            Some(IpAddr::V4([192, 0, 2, 2])),
            None,
            None,
        );
        let _ = d.feed_hello(
            now,
            &pdu,
            &msg,
            IpAddr::V6([0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 9]),
        );
        assert_eq!(
            d.adjacencies()[0].transport_addr,
            IpAddr::V6([0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 9])
        );
    }

    #[test]
    fn rfc7552_preference_mismatch_discards_hello() {
        // §6.1.1 rule 1: local prefers IPv6, the peer advertises
        // TR=LDPoIPv4 — the Hello MUST be discarded and an error
        // logged.
        let now = Instant::from_secs(0);
        let mut d = LdpDiscovery::new(dual_cfg()); // prefer_ipv6 default true
        let (pdu, msg) = hello_pdu_full(
            id(2),
            true,
            45,
            Some(IpAddr::V4([192, 0, 2, 2])),
            None,
            Some(TransportPreference::Ipv4),
        );
        let events = d.feed_hello(now, &pdu, &msg, IpAddr::V4([192, 0, 2, 2]));
        assert!(
            matches!(events[0], DiscoveryEvent::HelloDiscarded { .. }),
            "mismatched preference must surface HelloDiscarded"
        );
        assert!(d.adjacencies().is_empty());
    }

    #[test]
    fn rfc7552_matching_preference_creates_adjacency() {
        let now = Instant::from_secs(0);
        let mut d = LdpDiscovery::new(dual_cfg());
        let (pdu, msg) = hello_pdu_full(
            id(2),
            true,
            45,
            Some(IpAddr::V4([192, 0, 2, 2])),
            None,
            Some(TransportPreference::Ipv6),
        );
        let events = d.feed_hello(now, &pdu, &msg, IpAddr::V4([192, 0, 2, 2]));
        assert!(matches!(events[0], DiscoveryEvent::AdjacencyUp(_)));
        assert_eq!(
            d.adjacencies()[0].dual_stack,
            Some(TransportPreference::Ipv6)
        );
    }

    #[test]
    fn rfc7552_single_stack_speaker_ignores_capability() {
        // §6.1.1: "A Single-stack LSR ... SHOULD ignore this
        // capability if received" — no preference enforcement.
        let now = Instant::from_secs(0);
        let mut d = LdpDiscovery::new(cfg()); // v4-only speaker
        let (pdu, msg) = hello_pdu_full(
            id(2),
            true,
            45,
            Some(IpAddr::V4([192, 0, 2, 2])),
            None,
            Some(TransportPreference::Ipv6),
        );
        let events = d.feed_hello(now, &pdu, &msg, IpAddr::V4([192, 0, 2, 2]));
        assert!(matches!(events[0], DiscoveryEvent::AdjacencyUp(_)));
    }

    #[test]
    fn rfc7552_targeted_hello_per_family_transport() {
        // Targeted Hellos to a v6 destination carry the v6 transport
        // address; a v4-only speaker emits none for a v6 target.
        let now = Instant::from_secs(0);
        let mut dual = dual_cfg();
        dual.targeted_peers = vec![IpAddr::V6([
            0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 99,
        ])];
        let mut d = LdpDiscovery::new(dual);
        let _ = d.tick(now);
        let out = d.drain_outgoing();
        assert_eq!(out.len(), 1);
        let LdpMessage::Hello(hello) = &out[0].message else {
            panic!("expected a Hello");
        };
        match hello.transport_addr_v6 {
            Some(TransportAddress(IpAddr::V6(b))) => assert_eq!(b[1], 1),
            other => panic!("expected a v6 transport TLV, got {other:?}"),
        }
        assert!(hello.transport_addr.is_none());
        // The dual-stack capability rides along (§6.1.1: "in all of
        // its LDP Hellos").
        assert_eq!(
            hello.dual_stack.map(|c| c.preference),
            Some(TransportPreference::Ipv6)
        );

        // A v4-only speaker must not emit a Hello it cannot sign with
        // a v6 transport address.
        let now = Instant::from_secs(0);
        let mut single = cfg();
        single.targeted_peers = vec![IpAddr::V6([
            0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 99,
        ])];
        let mut d = LdpDiscovery::new(single);
        let _ = d.tick(now);
        assert!(d.drain_outgoing().is_empty());
    }
}
