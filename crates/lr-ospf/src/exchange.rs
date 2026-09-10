//! Database Description / LS-Request exchange (RFC 2328 §7.2, §10.3–§10.8).
//!
//! The neighbor FSM reaches 2-Way, decides to adjoint (`AdjOk`), and
//! enters ExStart — from there the two routers must synchronize their
//! LSDBs before the adjacency counts as Full:
//!
//! 1. **Master election** (§10.3): both sides emit an *initial* DBD
//!    (`I|M|MS`, empty, sequence picked by the sender). The router with
//!    the higher router-id becomes master; the slave adopts the
//!    master's sequence number and answers with `I=0, MS=0`.
//! 2. **Exchange**: DBD packets now carry pages of LSA headers. The
//!    master increments the sequence each round, the slave echoes it.
//!    Each side compares received headers against its LSDB and queues
//!    the LSAs it is missing (or that are newer) for the next phase.
//!    When both sides clear their More bits the exchange is done.
//! 3. **Loading**: LS-Request packets ask for the queued LSAs; the
//!    neighbor answers with LS-Updates. When the queue drains, the
//!    adjacency is Full.
//!
//! [`DbExchange`] is the embedder-side driver for one neighbor: it
//! consumes decoded packets plus a read-only LSDB view and produces
//! the packets to transmit. It carries no timers of its own — the
//! embedder's clock drives [`DbExchange::poll`] for retransmissions
//! (RxmtInterval), matching the poll-driven router design.
//!
//! MTU handling follows §10.6: a DBD advertising an interface MTU
//! larger than ours is dropped. The interface MTU must be the *real*
//! one (BIRD enforces equality), which is why the daemon reads it off
//! the socket.

use crate::lsa::{Lsa, LsaHeader};
use crate::lsdb::Lsdb;
use lr_core::fsm::StateMachine;

use crate::neighbor::{NeighborEvent, OspfNeighbor};
use crate::packet::{
    DbDescBody, LsAckBody, LsRequestBody, LsRequestEntry, LsUpdateBody, OspfBody, OspfHeader,
    OspfPacket, OspfPacketType, OspfVersion, OSPF_V3_OPTIONS_DEFAULT,
};

/// DBD flag bits (RFC 2328 §A.3.3): the Imms byte carries I at bit 2,
/// M at bit 1, MS at bit 0.
pub const DD_I: u8 = 0x04; // Initial
pub const DD_M: u8 = 0x02; // More
pub const DD_MS: u8 = 0x01; // Master/Slave

/// Fixed overhead of one LSA header.
const LSA_HEADER_LEN: usize = 20;
/// IP(20) + OSPF(24) + DBD fixed body(8): the header room of a DBD.
const DD_OVERHEAD: usize = 52;

/// Retransmit interval for the pending DBD / LS-Request (BIRD/FRR
/// default RxmtInterval).
pub const RXMT_INTERVAL_MS: u64 = 5_000;

/// Exchange phase — mirrors the neighbor FSM states ExStart..Full.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    /// Master/slave not yet negotiated.
    ExStart,
    /// Trading LSA headers in DBD pages.
    Exchange,
    /// Requesting the LSAs discovered during Exchange.
    Loading,
    /// Fully adjacent.
    Full,
}

impl Phase {
    pub fn name(self) -> &'static str {
        match self {
            Self::ExStart => "ExStart",
            Self::Exchange => "Exchange",
            Self::Loading => "Loading",
            Self::Full => "Full",
        }
    }
}

/// One exchange step's output: packets to transmit plus the LSAs that
/// arrived (the caller installs them into the LSDB and floods).
#[derive(Debug, Default)]
pub struct ExchangeStep {
    /// Complete packets ready for the wire.
    pub outbound: Vec<OspfPacket>,
    /// LSAs received in an LS-Update (caller: install + flood).
    pub lsas: Vec<Lsa>,
    /// True on the transition into Full.
    pub newly_full: bool,
}

/// The DBD/LSR exchange driver for one neighbor (RFC 2328 §10.3–§10.8).
pub struct DbExchange {
    router_id: u32,
    area_id: u32,
    iface_mtu: u16,
    phase: Phase,
    /// Set at negotiation: true when we won the router-id comparison.
    master_role: bool,
    /// Master side: our current sequence. Slave side: the master's
    /// sequence we must echo.
    seq: u32,
    /// Whether the initial DBD has been sent for this negotiation
    /// round (restarts on sequence mismatch reset it).
    started: bool,
    /// Paging cursor over our LSDB headers.
    our_cursor: usize,
    /// True while we still have headers to send.
    our_more: bool,
    /// True while the peer signaled More on its last DBD.
    their_more: bool,
    /// LSAs to request in Loading (§10.7 request list).
    lsr_queue: Vec<LsRequestEntry>,
    /// Last LS-Request we sent (for retransmission).
    last_lsr: Option<LsRequestBody>,
    /// Last DBD sent, as (flags, sequence, headers) — the master
    /// retransmits until the slave echoes the sequence; the slave
    /// retransmits on duplicate master DBDs.
    last_dd: Option<(u8, u32, Vec<LsaHeader>)>,
    last_dd_sent_ms: u64,
    last_lsr_sent_ms: u64,
    /// Protocol version the session speaks — v3 packets carry the
    /// 16-byte header (RFC 5340 §A.3.1) and 24-bit options.
    version: OspfVersion,
    /// The Options word DD packets advertise (v2: E|O; v3: V6|R|E).
    options: u32,
}

impl DbExchange {
    /// Create the driver. `iface_mtu` is clamped to at least
    /// [`DD_OVERHEAD`] so the DBD/LSU paging arithmetic
    /// (`iface_mtu - DD_OVERHEAD`) can never underflow for tiny MTUs
    /// (audit E1).
    pub fn new(router_id: u32, area_id: u32, iface_mtu: u16) -> Self {
        Self::with_version(router_id, area_id, iface_mtu, OspfVersion::V2)
    }

    /// Create the driver for a specific protocol version. The v3 driver
    /// emits 16-byte-header packets and advertises the RFC 5340 §A.2
    /// V6|R|E option set; the v2 driver keeps the E|O (RFC 5250 §3)
    /// set.
    pub fn with_version(
        router_id: u32,
        area_id: u32,
        iface_mtu: u16,
        version: OspfVersion,
    ) -> Self {
        let iface_mtu = iface_mtu.max(DD_OVERHEAD as u16);
        Self {
            router_id,
            area_id,
            iface_mtu,
            phase: Phase::ExStart,
            master_role: false,
            seq: 0,
            started: false,
            our_cursor: 0,
            our_more: true,
            their_more: true,
            lsr_queue: Vec::new(),
            last_lsr: None,
            last_dd: None,
            last_dd_sent_ms: 0,
            last_lsr_sent_ms: 0,
            version,
            options: if version == OspfVersion::V3 {
                // RFC 5340 §A.2: V6 (0x01) | E (0x02) | R (0x10).
                OSPF_V3_OPTIONS_DEFAULT
            } else {
                0x02 | u32::from(crate::lsa::grace::OPTIONS_O_BIT)
            },
        }
    }

    /// Current phase.
    pub fn phase(&self) -> Phase {
        self.phase
    }

    /// True once the adjacency reached Full.
    pub fn is_full(&self) -> bool {
        self.phase == Phase::Full
    }

    /// True once the initial DBD was sent for this round (restarted
    /// by a sequence mismatch).
    pub fn started(&self) -> bool {
        self.started
    }

    /// Reset for a fresh negotiation round (ExStart re-entry — §10.9
    /// sequence-mismatch handling).
    pub fn restart(&mut self, seq: u32) {
        self.phase = Phase::ExStart;
        self.master_role = false;
        self.seq = seq;
        self.started = false;
        self.our_cursor = 0;
        self.our_more = true;
        self.their_more = true;
        self.lsr_queue.clear();
        self.last_lsr = None;
        self.last_dd = None;
    }

    /// The initial DBD: I|M|MS set, empty, sequence chosen by us
    /// (§10.3). Idempotent per negotiation round.
    pub fn initial_db_desc(&mut self, seq: u32, now_ms: u64) -> OspfPacket {
        if !self.started {
            self.seq = seq;
            self.started = true;
        }
        let pkt = self.db_desc_packet(DD_I | DD_M | DD_MS, self.seq, Vec::new());
        self.last_dd = Some((DD_I | DD_M | DD_MS, self.seq, Vec::new()));
        self.last_dd_sent_ms = now_ms;
        pkt
    }

    /// Process one received DBD (§10.6). `peer_rid` is the sender's
    /// router-id (from the OSPF header); `lsdb` is our area database
    /// for header comparison. Steps the neighbor FSM on the
    /// negotiation transitions.
    pub fn on_db_desc(
        &mut self,
        d: &DbDescBody,
        peer_rid: u32,
        lsdb: &Lsdb,
        neighbor: &mut OspfNeighbor,
        now_ms: u64,
    ) -> ExchangeStep {
        let mut step = ExchangeStep::default();
        // §10.6: the MTU in a received DBD must not exceed ours (BIRD
        // enforces equality; we accept anything not larger).
        if d.mtu > self.iface_mtu {
            return step;
        }
        let is_initial = d.flags & (DD_I | DD_M | DD_MS) == (DD_I | DD_M | DD_MS);
        match self.phase {
            Phase::ExStart => {
                if is_initial && d.lsa_headers.is_empty() && peer_rid > self.router_id {
                    // We are the slave (§10.3): adopt the master's
                    // sequence and answer with our first data DBD.
                    // Negotiation counts as "started" — a Hello driving
                    // the FSM to ExStart later must not emit a stale
                    // initial DBD into an established conversation.
                    self.started = true;
                    self.master_role = false;
                    self.seq = d.dd_seq;
                    self.phase = Phase::Exchange;
                    let _ = neighbor.step(NeighborEvent::NegotiationDone);
                    let (headers, more) = self.next_our_chunk(lsdb);
                    let flags = DD_M * u8::from(more);
                    let pkt = self.db_desc_packet(flags, self.seq, headers.clone());
                    self.remember_dd(flags, self.seq, headers, now_ms);
                    step.outbound.push(pkt);
                } else if !is_initial
                    && d.flags & DD_I == 0
                    && d.flags & DD_MS == 0
                    && peer_rid < self.router_id
                    && d.dd_seq == self.seq
                {
                    // We are the master: the slave echoed our initial
                    // sequence. Process its headers, bump the sequence
                    // and send our first data DBD.
                    self.started = true;
                    self.master_role = true;
                    self.phase = Phase::Exchange;
                    let _ = neighbor.step(NeighborEvent::NegotiationDone);
                    self.process_their_headers(&d.lsa_headers, lsdb, &mut step);
                    self.seq = self.seq.wrapping_add(1);
                    self.send_master_db_desc(lsdb, &mut step, now_ms);
                }
                // Anything else in ExStart is the peer's initial from a
                // lower id (ignored — we wait for its echo) or noise.
            }
            Phase::Exchange => {
                let imms_ok = d.flags & DD_MS == if self.is_master() { 0 } else { DD_MS };
                if d.flags & DD_I != 0 || !imms_ok {
                    // Restart the adjacency (§10.9): I-bit or MS-bit
                    // mismatch is a sequence-number-mismatch event.
                    self.sequence_mismatch(neighbor, now_ms, &mut step);
                    return step;
                }
                if self.is_master() {
                    // The slave's echo must carry our sequence.
                    if d.dd_seq != self.seq {
                        self.sequence_mismatch(neighbor, now_ms, &mut step);
                        return step;
                    }
                    self.their_more = d.flags & DD_M != 0;
                    self.process_their_headers(&d.lsa_headers, lsdb, &mut step);
                    if !self.our_more && !self.their_more {
                        self.finish_exchange(neighbor, &mut step, now_ms);
                        return step;
                    }
                    self.seq = self.seq.wrapping_add(1);
                    self.send_master_db_desc(lsdb, &mut step, now_ms);
                } else {
                    // Slave: the master's packet must advance the
                    // sequence by exactly one.
                    if d.dd_seq != self.seq.wrapping_add(1) {
                        self.sequence_mismatch(neighbor, now_ms, &mut step);
                        return step;
                    }
                    self.seq = d.dd_seq;
                    self.their_more = d.flags & DD_M != 0;
                    self.process_their_headers(&d.lsa_headers, lsdb, &mut step);
                    let (headers, more) = self.next_our_chunk(lsdb);
                    let flags = DD_M * u8::from(more);
                    let pkt = self.db_desc_packet(flags, self.seq, headers.clone());
                    self.remember_dd(flags, self.seq, headers, now_ms);
                    step.outbound.push(pkt);
                    if !more && !self.their_more {
                        self.finish_exchange(neighbor, &mut step, now_ms);
                    }
                }
            }
            Phase::Loading | Phase::Full => {
                // §10.6: duplicates (same imms/options/sequence) are
                // acked by a slave retransmission; anything else is a
                // mismatch.
                if let Some((flags, seq, _)) = &self.last_dd {
                    if d.flags == *flags && d.dd_seq == *seq {
                        if !self.is_master() {
                            let (flags, seq, headers) = self.last_dd.clone().unwrap();
                            step.outbound.push(self.db_desc_packet(flags, seq, headers));
                        }
                        return step;
                    }
                }
                self.sequence_mismatch(neighbor, now_ms, &mut step);
            }
        }
        step
    }

    /// Process one received LS-Request (§10.7): answer with an LSU
    /// carrying the requested LSAs. Unknown LSAs are a BadLsa event
    /// (the adjacency restarts).
    pub fn on_ls_request(
        &mut self,
        body: &LsRequestBody,
        lsdb: &Lsdb,
        neighbor: &mut OspfNeighbor,
        now_ms: u64,
    ) -> ExchangeStep {
        let mut step = ExchangeStep::default();
        if self.phase == Phase::ExStart {
            return step; // §10.7: ignore below Exchange
        }
        let mut lsas: Vec<Lsa> = Vec::new();
        for entry in &body.entries {
            let key = crate::lsa::LsaKey {
                ls_type: entry.ls_type,
                link_state_id: entry.ls_id,
                advertising_router: entry.adv_router,
            };
            match lsdb.get(&key) {
                Some(entry) => lsas.push(entry.lsa.clone()),
                None => {
                    // §10.7: an LSA we cannot supply restarts the
                    // adjacency.
                    self.sequence_mismatch(neighbor, now_ms, &mut step);
                    return step;
                }
            }
        }
        // Page the answer: one LSU per MTU-sized batch. The MTU is
        // clamped at construction, so this cannot underflow.
        let max_bytes = self.iface_mtu as usize - DD_OVERHEAD;
        let mut batch: Vec<Lsa> = Vec::new();
        let mut batch_bytes = 0usize;
        for lsa in lsas {
            let len = lsa.header.length as usize;
            if !batch.is_empty() && batch_bytes + len > max_bytes {
                step.outbound
                    .push(self.ls_update_packet(std::mem::take(&mut batch)));
                batch_bytes = 0;
            }
            batch_bytes += len;
            batch.push(lsa);
        }
        if !batch.is_empty() {
            step.outbound.push(self.ls_update_packet(batch));
        }
        step
    }

    /// Process one received LS-Update: the LSAs go to the caller for
    /// LSDB install/flooding, the request queue drops satisfied
    /// entries, and a direct LSAck acknowledges the receipt (§13.7 —
    /// always acking is valid and keeps retransmitters quiet).
    pub fn on_ls_update(&mut self, lsas: &[Lsa], neighbor: &mut OspfNeighbor) -> ExchangeStep {
        let mut step = ExchangeStep {
            lsas: lsas.to_vec(),
            ..ExchangeStep::default()
        };
        if self.phase == Phase::ExStart {
            // Not yet exchanging: still ack (harmless) and hand the
            // LSAs over — early flooding data is legal to process.
            let ack = self.ls_ack_packet(lsas.iter().map(|l| l.header).collect());
            step.outbound.push(ack);
            return step;
        }
        let mut satisfied = false;
        for lsa in lsas {
            let before = self.lsr_queue.len();
            self.lsr_queue.retain(|e| {
                !(e.ls_type == lsa.header.ls_type
                    && e.ls_id == lsa.header.link_state_id
                    && e.adv_router == lsa.header.advertising_router)
            });
            satisfied |= self.lsr_queue.len() != before;
        }
        let ack = self.ls_ack_packet(lsas.iter().map(|l| l.header).collect());
        step.outbound.push(ack);
        if satisfied && self.lsr_queue.is_empty() && self.phase == Phase::Loading {
            self.phase = Phase::Full;
            let _ = neighbor.step(NeighborEvent::ExchangeDone); // Loading → Full
            step.newly_full = true;
        }
        step
    }

    /// Periodic retransmission (RxmtInterval): the master repeats its
    /// pending DBD, both sides repeat a pending LS-Request until the
    /// answer arrives.
    pub fn poll(&mut self, now_ms: u64) -> Vec<OspfPacket> {
        let mut out = Vec::new();
        if now_ms.saturating_sub(self.last_dd_sent_ms) >= RXMT_INTERVAL_MS {
            if let Some((flags, seq, headers)) = &self.last_dd {
                // Master DBDs repeat until the slave echoes the
                // sequence; slave DBDs repeat on duplicate master
                // packets (sent from on_db_desc) but a stuck master
                // benefits from the slave repeating too (BIRD accepts
                // duplicates in Exchange/Loading).
                if self.phase == Phase::Exchange {
                    let pkt = self.db_desc_packet(*flags, *seq, headers.clone());
                    out.push(pkt);
                    self.last_dd_sent_ms = now_ms;
                }
            }
        }
        if self.phase == Phase::Loading
            && !self.lsr_queue.is_empty()
            && now_ms.saturating_sub(self.last_lsr_sent_ms) >= RXMT_INTERVAL_MS
        {
            let body = self
                .last_lsr
                .clone()
                .unwrap_or_else(|| self.lsr_body_from_queue());
            self.last_lsr_sent_ms = now_ms;
            out.push(self.ls_request_packet(body));
        }
        out
    }

    /// Build the LS-Request packet for the current queue (Loading).
    pub fn take_ls_request(&mut self, now_ms: u64) -> Option<OspfPacket> {
        if self.lsr_queue.is_empty() {
            return None;
        }
        let body = self.lsr_body_from_queue();
        self.last_lsr = Some(body.clone());
        self.last_lsr_sent_ms = now_ms;
        Some(self.ls_request_packet(body))
    }

    /// True while LSAs are still queued for the Loading phase.
    pub fn pending_requests(&self) -> usize {
        self.lsr_queue.len()
    }

    // ----- internals -----

    /// The negotiated role (valid from Exchange onward).
    fn is_master(&self) -> bool {
        self.master_role
    }

    fn process_their_headers(
        &mut self,
        headers: &[LsaHeader],
        lsdb: &Lsdb,
        step: &mut ExchangeStep,
    ) {
        for h in headers {
            let key = crate::lsa::LsaKey {
                ls_type: h.ls_type,
                link_state_id: h.link_state_id,
                advertising_router: h.advertising_router,
            };
            let have = lsdb.get(&key);
            let need = match &have {
                // §10.5: request when we have no copy or ours is older
                // (signed sequence space, §12.1.1).
                None => true,
                Some(ours) => {
                    (h.ls_sequence_number as i32) > (ours.lsa.header.ls_sequence_number as i32)
                }
            };
            if need {
                let entry = LsRequestEntry {
                    ls_type: h.ls_type,
                    ls_id: h.link_state_id,
                    adv_router: h.advertising_router,
                };
                if !self.lsr_queue.contains(&entry) {
                    self.lsr_queue.push(entry);
                }
            } else if let Some(ours) = have {
                // We have an equal or newer instance: flood our copy
                // back when strictly newer so the neighbor converges
                // (§10.5 step 4); an equal instance needs nothing.
                if (h.ls_sequence_number as i32) < (ours.lsa.header.ls_sequence_number as i32) {
                    step.outbound
                        .push(self.ls_update_packet(vec![ours.lsa.clone()]));
                }
            }
        }
    }

    /// The next page of our LSA headers (`our_cursor` walks the LSDB).
    fn next_our_chunk(&mut self, lsdb: &Lsdb) -> (Vec<LsaHeader>, bool) {
        // Saturating so a degenerate MTU can never underflow (the MTU is
        // also clamped at construction).
        let per_page =
            ((self.iface_mtu as usize).saturating_sub(DD_OVERHEAD) / LSA_HEADER_LEN).max(1);
        let mut headers = Vec::with_capacity(per_page);
        let mut iter = lsdb.headers().into_iter().skip(self.our_cursor);
        for h in iter.by_ref().take(per_page) {
            headers.push(h);
        }
        let consumed = headers.len();
        self.our_cursor += consumed;
        self.our_more = self.our_cursor < lsdb.len();
        (headers, self.our_more)
    }

    fn finish_exchange(
        &mut self,
        neighbor: &mut OspfNeighbor,
        step: &mut ExchangeStep,
        now_ms: u64,
    ) {
        let _ = neighbor.step(NeighborEvent::ExchangeDone); // Exchange → Loading
        if self.lsr_queue.is_empty() {
            self.phase = Phase::Full;
            let _ = neighbor.step(NeighborEvent::ExchangeDone); // Loading → Full
            step.newly_full = true;
        } else {
            self.phase = Phase::Loading;
            if let Some(pkt) = self.take_ls_request(now_ms) {
                step.outbound.push(pkt);
            }
        }
    }

    fn sequence_mismatch(
        &mut self,
        neighbor: &mut OspfNeighbor,
        now_ms: u64,
        step: &mut ExchangeStep,
    ) {
        let _ = neighbor.step(NeighborEvent::SeqMismatch); // ≥ExStart → ExStart
        self.restart(self.seq.wrapping_add(1));
        step.outbound.push(self.initial_db_desc(self.seq, now_ms));
    }

    fn remember_dd(&mut self, flags: u8, seq: u32, headers: Vec<LsaHeader>, now_ms: u64) {
        self.last_dd = Some((flags, seq, headers));
        self.last_dd_sent_ms = now_ms;
    }

    fn send_master_db_desc(&mut self, lsdb: &Lsdb, step: &mut ExchangeStep, now_ms: u64) {
        let (headers, more) = self.next_our_chunk(lsdb);
        let flags = DD_MS | (DD_M * u8::from(more));
        let pkt = self.db_desc_packet(flags, self.seq, headers.clone());
        self.remember_dd(flags, self.seq, headers, now_ms);
        step.outbound.push(pkt);
    }

    fn lsr_body_from_queue(&self) -> LsRequestBody {
        LsRequestBody {
            entries: self.lsr_queue.clone(),
        }
    }

    // ----- packet constructors -----

    fn base_header(&self, kind: OspfPacketType) -> OspfHeader {
        OspfHeader {
            version: self.version as u8,
            kind: kind as u8,
            length: 0,
            router_id: self.router_id,
            area_id: self.area_id,
            checksum: 0,
            au_type_or_instance: 0,
            auth_data: 0,
        }
    }

    fn db_desc_packet(&self, flags: u8, seq: u32, headers: Vec<LsaHeader>) -> OspfPacket {
        OspfPacket {
            header: self.base_header(OspfPacketType::DatabaseDescription),
            body: OspfBody::DbDesc(DbDescBody {
                mtu: self.iface_mtu,
                // v2: E-bit (normal area) plus the RFC 5250 §3 O-bit —
                // this router originates and floods Opaque-LSAs (the
                // RFC 3623/5187 Grace-LSA), so DD packets must announce
                // opaque capability. Peers gate opaque flooding on this
                // bit — BIRD captures it from DD packets only
                // (proto/ospf/dbdes.c: n->options = rcv_options) and
                // skips neighbours without it when retransmitting
                // opaque LSAs (lsa_is_acceptable, lsupd.c); FRR's
                // ospf_gr.c likewise refuses to originate a Grace-LSA
                // without OSPF_OPAQUE_CAPABLE. RFC 5250 §3: the bit is
                // meaningful in DD packets only — Hellos keep the
                // plain E-bit. v3: the V6|R|E set (see `with_version`).
                options: self.options,
                flags,
                dd_seq: seq,
                lsa_headers: headers,
            }),
        }
    }

    fn ls_request_packet(&self, body: LsRequestBody) -> OspfPacket {
        OspfPacket {
            header: self.base_header(OspfPacketType::LinkStateRequest),
            body: OspfBody::LsRequest(body),
        }
    }

    fn ls_update_packet(&self, lsas: Vec<Lsa>) -> OspfPacket {
        OspfPacket {
            header: self.base_header(OspfPacketType::LinkStateUpdate),
            body: OspfBody::LsUpdate(LsUpdateBody {
                lsa_count: lsas.len() as u32,
                lsas,
            }),
        }
    }

    fn ls_ack_packet(&self, headers: Vec<LsaHeader>) -> OspfPacket {
        OspfPacket {
            header: self.base_header(OspfPacketType::LinkStateAck),
            body: OspfBody::LsAck(LsAckBody {
                lsa_headers: headers,
            }),
        }
    }
}

#[cfg(test)]
#[path = "exchange_tests.rs"]
mod exchange_tests;
