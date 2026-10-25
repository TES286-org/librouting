//! Unit tests for the DBD/LSR exchange driver (RFC 2328 §10.3–§10.8).
//!
//! The scenarios drive two `DbExchange` instances against each other
//! through a scripted packet pump — the same conversation BIRD runs,
//! with both role assignments exercised.

use super::*;
use crate::lsa::v3::{
    originate_v3_router_lsa, V3RouterLink, LINK_TYPE_POINTTOPOINT, LS_TYPE_ROUTER, ROUTER_BIT_V6,
};
use crate::lsdb::Lsdb;
use crate::neighbor::{NeighborState, OspfNeighbor};
use crate::origination::{originate_router_lsa, RouterLsaFlags, RouterLsaLink};
use crate::packet::OSPF_V3_OPTIONS_DEFAULT;

const US: u32 = 0x0a00_0001; // 10.0.0.1
const THEM: u32 = 0x0a00_0002; // 10.0.0.2 (higher — master by §10.3)
const AREA: u32 = 0;
const MTU: u16 = 1500;
const NOW: u64 = 1_000;

fn neighbor(rid: u32) -> OspfNeighbor {
    OspfNeighbor::new(lr_core::addr::RouterId::from_u32(rid))
}

/// A neighbor already at ExStart — the state the runtime has reached
/// via Hellos when the DBD exchange begins (§9.5.4 → §10.2 AdjOk).
fn neighbor_at_exstart(rid: u32) -> OspfNeighbor {
    let mut n = neighbor(rid);
    let hello = NeighborEvent::HelloSeen {
        dr: 0,
        bdr: 0,
        priority: 1,
    };
    n.step(hello.clone()); // Down → Init
    n.step(hello); // Init → 2-Way (we are listed)
    n.step(NeighborEvent::AdjOk { proceed: true }); // 2-Way → ExStart
    assert_eq!(n.state, NeighborState::ExStart);
    n
}

fn exchange(rid: u32, lsdb: &Lsdb) -> DbExchange {
    let _ = lsdb;
    DbExchange::new(rid, AREA, MTU)
}

fn lsdb_with(router_id: u32, links: &[RouterLsaLink]) -> Lsdb {
    let mut lsdb = Lsdb::new();
    if let Some(lsa) = originate_router_lsa(router_id, RouterLsaFlags::default(), links, None) {
        lsdb.install(lsa, 0);
    }
    lsdb
}

#[test]
fn slave_negotiation_and_full_exchange_with_master() {
    // Two routers: THEM (higher id, master) with a Router-LSA, US
    // (slave) with a different Router-LSA. The scripted conversation:
    //   1. both send initial DBDs
    //   2. US (slave) adopts THEM's seq, answers with its headers
    //   3. THEM (master) bumps seq, sends its headers
    //   4. US echoes; both M=0 → Loading
    //   5. US requests THEM's LSA (LSR); THEM answers LSU; US acks
    //   6. US reaches Full; THEM's queue (our LSA) is served back
    let our_lsdb = lsdb_with(
        US,
        &[RouterLsaLink::Stub {
            network: 0x0a0a_0a00,
            mask: 0xffff_ff00,
            metric: 10,
        }],
    );
    let their_lsdb = lsdb_with(
        THEM,
        &[RouterLsaLink::Stub {
            network: 0x0a0b_0b00,
            mask: 0xffff_ff00,
            metric: 20,
        }],
    );

    let mut us = exchange(US, &our_lsdb);
    let mut us_nbr = neighbor_at_exstart(US);
    let mut them = exchange(THEM, &their_lsdb);
    let mut them_nbr = neighbor_at_exstart(THEM);

    // 1. Initial DBDs cross.
    let us_init = us.initial_db_desc(US + 1, NOW);
    let them_init = them.initial_db_desc(THEM + 1, NOW);
    assert_eq!(
        body_db_desc(&us_init).flags,
        DD_I | DD_M | DD_MS,
        "initial DBD carries I|M|MS"
    );

    // 2. US receives THEM's initial → slave, answers with headers.
    let step_us = us.on_db_desc(body_db_desc(&them_init), THEM, &our_lsdb, &mut us_nbr, NOW);
    assert_eq!(step_us.outbound.len(), 1, "slave answers immediately");

    let answer = &step_us.outbound[0];
    let answer_dd = body_db_desc(answer);
    assert_eq!(answer_dd.flags & DD_MS, 0, "slave clears MS");
    assert_eq!(answer_dd.flags & DD_I, 0, "slave clears I");
    assert_eq!(
        answer_dd.dd_seq,
        body_db_desc(&them_init).dd_seq,
        "slave echoes master seq"
    );
    assert_eq!(
        answer_dd.lsa_headers.len(),
        1,
        "slave's first page carries its LSA header"
    );
    assert_eq!(us.phase(), Phase::Exchange);
    assert_eq!(us_nbr.state, NeighborState::Exchange);

    // 3. THEM receives US's initial (lower id) — ignored — then US's
    //    answer: master is negotiated, sends its own headers, seq+1.
    let step_noise = them.on_db_desc(body_db_desc(&us_init), US, &their_lsdb, &mut them_nbr, NOW);
    assert!(
        step_noise.outbound.is_empty(),
        "master ignores the slave's initial"
    );
    let step_them = them.on_db_desc(answer_dd, US, &their_lsdb, &mut them_nbr, NOW);
    assert_eq!(step_them.outbound.len(), 1);
    let master_dd = body_db_desc(&step_them.outbound[0]);
    assert_eq!(master_dd.flags & DD_MS, DD_MS, "master keeps MS");
    assert_eq!(
        master_dd.dd_seq,
        body_db_desc(&them_init).dd_seq + 1,
        "master bumps seq"
    );
    assert_eq!(master_dd.lsa_headers.len(), 1);
    assert_eq!(them.phase(), Phase::Exchange);
    assert_eq!(them_nbr.state, NeighborState::Exchange);

    // 4. US processes the master's page: queues THEIR LSA (missing),
    //    answers M=0 (no more of ours) and — the exchange now being
    //    complete on both sides — emits its LS-Request in the same step.
    let step_us = us.on_db_desc(master_dd, THEM, &our_lsdb, &mut us_nbr, NOW + 10);
    let slave_final = step_us
        .outbound
        .iter()
        .map(body_db_desc)
        .find(|d| d.flags & DD_MS == 0)
        .expect("slave echo DBD");
    assert_eq!(slave_final.flags & DD_M, 0, "slave done after one page");
    assert_eq!(
        slave_final.dd_seq, master_dd.dd_seq,
        "slave echoes the new seq"
    );
    assert_eq!(us.pending_requests(), 1, "their LSA is queued for Loading");
    assert_eq!(master_dd.flags & DD_M, 0, "master had exactly one page");
    assert_eq!(us.phase(), Phase::Loading, "slave enters Loading");
    assert_eq!(us_nbr.state, NeighborState::Loading);
    let us_lsr = step_us
        .outbound
        .iter()
        .find(|p| p.header.kind == OspfPacketType::LinkStateRequest as u8)
        .expect("slave emits its LSR at exchange completion");

    // 5. THEM receives the slave's final echo (M=0, same seq) → both
    //    done → THEM enters Loading and requests OUR LSA.
    let step_them = them.on_db_desc(slave_final, US, &their_lsdb, &mut them_nbr, NOW + 20);
    assert_eq!(them.phase(), Phase::Loading);
    assert_eq!(them_nbr.state, NeighborState::Loading);
    assert_eq!(step_them.outbound.len(), 1, "the LSR for our LSA");
    assert_eq!(
        step_them.outbound[0].header.kind,
        OspfPacketType::LinkStateRequest as u8
    );
    assert_eq!(them.pending_requests(), 1);

    // 6. THEM's own LSR (requesting OUR LSA) and OUR LSR (requesting
    //    THEIR LSA) cross; each side answers the other's request from
    //    its own LSDB.
    let them_lsreq = step_them.outbound[0].clone();
    assert_eq!(
        them_lsreq.header.kind,
        OspfPacketType::LinkStateRequest as u8
    );
    // THEM answers OUR lsr with its Router-LSA.
    let them_answer = them.on_ls_request(
        body_ls_request(us_lsr),
        &their_lsdb,
        &mut them_nbr,
        NOW + 30,
    );
    assert_eq!(them_answer.outbound.len(), 1);
    assert_eq!(
        them_answer.outbound[0].header.kind,
        OspfPacketType::LinkStateUpdate as u8
    );
    // US answers THEIR lsr with its Router-LSA.
    let us_answer = us.on_ls_request(
        body_ls_request(&them_lsreq),
        &our_lsdb,
        &mut us_nbr,
        NOW + 30,
    );
    assert_eq!(us_answer.outbound.len(), 1);
    assert_eq!(
        us_answer.outbound[0].header.kind,
        OspfPacketType::LinkStateUpdate as u8
    );

    // 7. US receives THEM's LS-Update: installs, acks, goes Full.
    let step_us = us.on_ls_update(body_ls_update(&them_answer.outbound[0]), &mut us_nbr);
    assert_eq!(step_us.lsas.len(), 1);
    assert!(step_us
        .outbound
        .iter()
        .any(|p| p.header.kind == OspfPacketType::LinkStateAck as u8));
    assert_eq!(us.phase(), Phase::Full);
    assert_eq!(us_nbr.state, NeighborState::Full);
    assert!(step_us.newly_full);

    // 8. THEM receives OUR LS-Update: installs, acks, goes Full.
    let step_them = them.on_ls_update(body_ls_update(&us_answer.outbound[0]), &mut them_nbr);
    assert_eq!(them.phase(), Phase::Full);
    assert_eq!(them_nbr.state, NeighborState::Full);
    assert!(step_them.newly_full);
}

#[test]
fn master_role_when_peer_router_id_is_lower() {
    // Mirror of the main scenario from THEM's perspective: feed US's
    // initial into THEM after THEM sent its own — but here we test the
    // router whose id is HIGHER and receives a slave's initial first.
    let our_lsdb = lsdb_with(THEM, &[]);
    let their_lsdb = lsdb_with(US, &[]);
    let mut us = exchange(THEM, &our_lsdb); // "us" = higher id
    let mut us_nbr = neighbor(THEM);
    let mut them = exchange(US, &their_lsdb); // "them" = lower id
    let mut them_nbr = neighbor(US);

    let us_init = us.initial_db_desc(7, NOW);
    let them_init = them.initial_db_desc(9, NOW);

    // The lower-id router receives the higher-id router's initial and
    // becomes slave.
    let step = them.on_db_desc(
        body_db_desc(&us_init),
        THEM,
        &their_lsdb,
        &mut them_nbr,
        NOW,
    );
    let slave_answer = body_db_desc(&step.outbound[0]);
    assert_eq!(slave_answer.dd_seq, 7, "slave adopts master's seq");

    // The higher-id router ignores the slave's initial...
    let step = us.on_db_desc(body_db_desc(&them_init), US, &our_lsdb, &mut us_nbr, NOW);
    assert!(step.outbound.is_empty());
    // ...and negotiates on the echo.
    let step = us.on_db_desc(slave_answer, US, &our_lsdb, &mut us_nbr, NOW + 5);
    assert_eq!(us.phase(), Phase::Exchange);
    assert!(us.is_master());
    let master_dd = body_db_desc(&step.outbound[0]);
    assert_eq!(master_dd.dd_seq, 8, "master sequence advanced");
    assert_eq!(master_dd.flags & DD_MS, DD_MS);
}

#[test]
fn sequence_mismatch_restarts_negotiation() {
    let our_lsdb = lsdb_with(US, &[]);
    let their_lsdb = lsdb_with(THEM, &[]);
    let mut us = exchange(US, &their_lsdb);
    let mut us_nbr = neighbor_at_exstart(US);
    let mut them = exchange(THEM, &our_lsdb);

    // Negotiate to Exchange (slave).
    let them_init = them.initial_db_desc(5, NOW);
    let step = us.on_db_desc(body_db_desc(&them_init), THEM, &our_lsdb, &mut us_nbr, NOW);
    assert_eq!(us.phase(), Phase::Exchange);

    // A master DBD with a WRONG sequence → mismatch → ExStart + a
    // fresh initial DBD.
    let mut bad = body_db_desc(&step.outbound[0]).clone();
    bad.dd_seq = 99;
    let step = us.on_db_desc(&bad, THEM, &our_lsdb, &mut us_nbr, NOW + 10);
    assert_eq!(us.phase(), Phase::ExStart);
    assert_eq!(us_nbr.state, NeighborState::ExStart);
    assert_eq!(step.outbound.len(), 1);
    assert_eq!(body_db_desc(&step.outbound[0]).flags, DD_I | DD_M | DD_MS);
}

#[test]
fn duplicate_master_db_desc_makes_slave_repeat_answer() {
    let our_lsdb = lsdb_with(US, &[]);
    let their_lsdb = lsdb_with(THEM, &[]);
    let mut us = exchange(US, &their_lsdb);
    let mut us_nbr = neighbor_at_exstart(US);
    let mut them = exchange(THEM, &our_lsdb);

    let them_init = them.initial_db_desc(5, NOW);
    let step = us.on_db_desc(body_db_desc(&them_init), THEM, &our_lsdb, &mut us_nbr, NOW);
    let first = body_db_desc(&step.outbound[0]);
    // The master re-delivers the same initial (duplicate): the slave
    // repeats its answer (§10.6 duplicate handling).
    let step = us.on_db_desc(
        body_db_desc(&them_init),
        THEM,
        &our_lsdb,
        &mut us_nbr,
        NOW + 10,
    );
    let _ = first;
    // THEM's initial in ExStart (already negotiated) is a duplicate by
    // flags+seq → slave retransmits.
    assert_eq!(
        step.outbound.len(),
        1,
        "slave repeats its answer on duplicates"
    );
}

#[test]
fn ls_request_for_unknown_lsa_restarts_adjacency() {
    let our_lsdb = lsdb_with(US, &[]);
    let mut us = exchange(US, &our_lsdb);
    let mut us_nbr = neighbor_at_exstart(US);
    // Force into Exchange.
    us.restart(1);
    let _ = us.initial_db_desc(1, NOW);
    let mut them = exchange(THEM, &our_lsdb);
    let them_init = them.initial_db_desc(3, NOW);
    us.on_db_desc(body_db_desc(&them_init), THEM, &our_lsdb, &mut us_nbr, NOW);

    let req = LsRequestBody {
        entries: vec![LsRequestEntry {
            ls_type: 1,
            ls_id: 0xdead_beef,
            adv_router: 0x0a00_0042,
        }],
    };
    let step = us.on_ls_request(&req, &our_lsdb, &mut us_nbr, NOW + 10);
    assert_eq!(us.phase(), Phase::ExStart, "bad LSR restarts the exchange");
    assert_eq!(step.outbound.len(), 1, "a fresh initial DBD goes out");
}

#[test]
fn poll_retransmits_pending_master_db_desc() {
    let our_lsdb = lsdb_with(THEM, &[]);
    let their_lsdb = lsdb_with(US, &[]);
    let mut us = exchange(THEM, &our_lsdb);
    let mut us_nbr = neighbor(THEM);
    let mut them = exchange(US, &their_lsdb);
    let mut them_nbr = neighbor(US);

    let us_init = us.initial_db_desc(7, NOW);
    let step = them.on_db_desc(
        body_db_desc(&us_init),
        THEM,
        &their_lsdb,
        &mut them_nbr,
        NOW,
    );
    let answer = body_db_desc(&step.outbound[0]);
    let step = us.on_db_desc(answer, US, &our_lsdb, &mut us_nbr, NOW);
    let master_dd = body_db_desc(&step.outbound[0]);

    // Before RxmtInterval: nothing.
    assert!(us.poll(NOW + 1_000).is_empty());
    // After: the master repeats its pending DBD verbatim.
    let retrans = us.poll(NOW + RXMT_INTERVAL_MS + 1);
    assert_eq!(retrans.len(), 1);
    assert_eq!(body_db_desc(&retrans[0]), master_dd);
}

#[test]
fn with_rxmt_interval_overrides_poll_wait() {
    // RFC 2328 Appendix B `RxmtInterval` is per-neighbor: BIRD exposes
    // it as `rxmtint`, FRR as `retransmit-interval`. The constant
    // `RXMT_INTERVAL_MS` (5 s) is the BIRD/FRR default; a daemon that
    // surfaces a per-interface knob must be able to drive the wait
    // below the default without touching the codec.
    let our_lsdb = lsdb_with(THEM, &[]);
    let their_lsdb = lsdb_with(US, &[]);
    let mut us = DbExchange::with_version(THEM, AREA, MTU, OspfVersion::V2).with_rxmt_interval(500);
    let mut us_nbr = neighbor(THEM);
    let mut them = exchange(US, &their_lsdb);
    let mut them_nbr = neighbor(US);

    assert_eq!(us.rxmt_interval_ms(), 500);

    let us_init = us.initial_db_desc(7, NOW);
    let step = them.on_db_desc(
        body_db_desc(&us_init),
        THEM,
        &their_lsdb,
        &mut them_nbr,
        NOW,
    );
    let answer = body_db_desc(&step.outbound[0]);
    let step = us.on_db_desc(answer, US, &our_lsdb, &mut us_nbr, NOW);
    let master_dd = body_db_desc(&step.outbound[0]);

    // Below the 500 ms override: nothing.
    assert!(us.poll(NOW + 499).is_empty());
    // At 500 ms + 1: the master repeats its pending DBD. (With the
    // default 5 s `RXMT_INTERVAL_MS` this `NOW + 501` would be far
    // below the wait and the poll would return nothing — pinning the
    // override is what makes the test meaningful.)
    let retrans = us.poll(NOW + 501);
    assert_eq!(retrans.len(), 1);
    assert_eq!(body_db_desc(&retrans[0]), master_dd);
}

#[test]
fn with_rxmt_interval_clamps_zero_to_one_ms() {
    // A 0 ms override would otherwise let `saturating_sub(last, now)`
    // be 0 every tick, busy-spinning the poll loop on every pump.
    // The builder clamps to 1 ms so the wait is at least one tick.
    let ex = DbExchange::with_version(US, AREA, MTU, OspfVersion::V2).with_rxmt_interval(0);
    assert_eq!(ex.rxmt_interval_ms(), 1);
}

#[test]
fn poll_retransmits_initial_db_desc_in_exstart() {
    // The broadcast-segment deadlock (interop `ospf_broadcast.sh`
    // hangs): the master's initial DBD is lost — or dropped by a peer
    // whose §10.4 DR/BDR gate has not opened yet — while the peer
    // later enters ExStart and sends its own initial, which the master
    // ignores by design (§10.3: only the slave reacts to the master's
    // initial). Without an ExStart retransmission both sides wait
    // forever while Hellos keep the neighbor alive. BIRD's
    // `dbdes_timer_hook` resends in NEIGHBOR_EXSTART; so must `poll`.
    let our_lsdb = lsdb_with(THEM, &[]);
    let their_lsdb = lsdb_with(US, &[]);
    let mut master = exchange(THEM, &our_lsdb);
    let mut master_nbr = neighbor_at_exstart(US);
    let mut slave = exchange(US, &their_lsdb);
    let mut slave_nbr = neighbor_at_exstart(THEM);

    // 1. The master (higher router-id) sends its initial DBD …
    let master_init = master.initial_db_desc(9, NOW);
    // … and it is LOST on the wire (never fed to the slave).

    // 2. The slave enters ExStart later and sends its own initial …
    let slave_init = slave.initial_db_desc(21, NOW + 500);
    // … which the master correctly ignores (§10.3: a master waits for
    // the slave's echo, not its initial).
    let step = master.on_db_desc(
        body_db_desc(&slave_init),
        US,
        &our_lsdb,
        &mut master_nbr,
        NOW + 500,
    );
    assert!(step.outbound.is_empty());
    assert_eq!(master.phase(), Phase::ExStart);

    // 3. Before RxmtInterval elapses: nothing repeats.
    assert!(master.poll(NOW + 500).is_empty());
    assert!(slave.poll(NOW + 500).is_empty());

    // 4. After RxmtInterval: the master repeats its initial DBD
    // verbatim (this is the fix — previously ExStart never repeated).
    let retrans = master.poll(NOW + RXMT_INTERVAL_MS + 501);
    assert_eq!(retrans.len(), 1);
    assert_eq!(body_db_desc(&retrans[0]), body_db_desc(&master_init));

    // 5. The retransmitted initial reaches the slave: negotiation
    // proceeds, and the adjacency converges to Full.
    let step = slave.on_db_desc(
        body_db_desc(&retrans[0]),
        THEM,
        &their_lsdb,
        &mut slave_nbr,
        NOW + RXMT_INTERVAL_MS + 501,
    );
    assert!(!step.outbound.is_empty());
    let answer = body_db_desc(&step.outbound[0]);
    let step = master.on_db_desc(
        answer,
        US,
        &our_lsdb,
        &mut master_nbr,
        NOW + RXMT_INTERVAL_MS + 600,
    );
    assert!(!step.outbound.is_empty());
    assert_eq!(master.phase(), Phase::Exchange);
    assert_eq!(slave.phase(), Phase::Exchange);
    assert_eq!(master_nbr.state, NeighborState::Exchange);
    assert_eq!(slave_nbr.state, NeighborState::Exchange);
}

#[test]
fn slave_repeats_its_initial_db_desc_in_exstart() {
    // The slave's initial is also repeated in ExStart (BIRD resends
    // for both roles): a duplicate at the master is ignored, so the
    // repetition is safe — and it keeps the conversation alive when
    // the master has not yet consumed the slave's first answer.
    let our_lsdb = lsdb_with(US, &[]);
    let mut slave = exchange(US, &our_lsdb);

    let slave_init = slave.initial_db_desc(31, NOW);
    // Before RxmtInterval: nothing.
    assert!(slave.poll(NOW + 1_000).is_empty());
    // After: the slave repeats its pending initial verbatim.
    let retrans = slave.poll(NOW + RXMT_INTERVAL_MS + 1);
    assert_eq!(retrans.len(), 1);
    assert_eq!(body_db_desc(&retrans[0]), body_db_desc(&slave_init));
}

#[test]
fn header_paging_respects_mtu() {
    // A tiny MTU forces one LSA header per DBD page; an LSDB with
    // three LSAs therefore takes three slave pages.
    let mut lsdb = Lsdb::new();
    for i in 0..3u32 {
        let lsa = originate_router_lsa(
            0x0a00_0001 + i,
            RouterLsaFlags::default(),
            &[RouterLsaLink::Stub {
                network: i,
                mask: 0xffff_ff00,
                metric: 1,
            }],
            None,
        )
        .unwrap();
        lsdb.install(lsa, 0);
    }
    let mut ex = DbExchange::new(US, AREA, (DD_OVERHEAD_V2 + LSA_HEADER_LEN + 4) as u16);
    let mut nbr = neighbor_at_exstart(US);
    let mut them = DbExchange::new(THEM, AREA, (DD_OVERHEAD_V2 + LSA_HEADER_LEN + 4) as u16);

    // Negotiate: THEM (higher id) is master.
    let them_init = them.initial_db_desc(5, NOW);
    let step = ex.on_db_desc(body_db_desc(&them_init), THEM, &lsdb, &mut nbr, NOW);
    let mut pages: Vec<DbDescBody> = vec![body_db_desc(&step.outbound[0]).clone()];
    assert_eq!(pages[0].lsa_headers.len(), 1, "one header per page");
    assert_eq!(pages[0].flags & DD_M, DD_M, "more pages follow");

    // The master keeps advancing the sequence; every slave answer
    // carries the next single header.
    let mut seq = body_db_desc(&them_init).dd_seq;
    for round in 0..4 {
        // Hand-built master DBD: MS=1, M=1 (the master still has more
        // of its own), sequence advanced.
        seq = seq.wrapping_add(1);
        let master_dd = DbDescBody {
            mtu: (DD_OVERHEAD_V2 + LSA_HEADER_LEN + 4) as u16,
            options: 0x02,
            flags: DD_MS | DD_M,
            dd_seq: seq,
            lsa_headers: vec![],
        };
        let step = ex.on_db_desc(&master_dd, THEM, &lsdb, &mut nbr, NOW + round as u64 * 10);
        let answer = step
            .outbound
            .iter()
            .map(body_db_desc)
            .find(|d| d.flags & DD_MS == 0)
            .expect("slave answer");
        pages.push(answer.clone());
        if answer.flags & DD_M == 0 {
            break;
        }
    }

    // Three headers total, one per page, M clear on the last.
    assert_eq!(pages.len(), 3, "three pages at one header each");
    let headers: usize = pages.iter().map(|p| p.lsa_headers.len()).sum();
    assert_eq!(headers, 3, "every LSA header paged exactly once");
    assert_eq!(
        pages.last().unwrap().flags & DD_M,
        0,
        "final page clears More"
    );
    // The sequences echo the master each round.
    assert_eq!(pages[2].dd_seq, seq);
}

// ===== OSPFv3 (RFC 5340) coverage =====
//
// `DbExchange::with_version(.., OspfVersion::V3)` was previously
// uncovered by `exchange_tests.rs` (defects.txt TEST-GAP entry on
// `crates/lr-ospf/src/exchange.rs`). The v3 wire shapes are
// exercised in `codec.rs` (`v3_dbdesc_uses_24bit_options_and_flags_at_offset_5`,
// `v3_ls_request_reserved_word_leads_16bit_type`,
// `v3_lsu_carries_full_16bit_lsa_type_on_the_wire`); these tests pin
// the *exchange driver's* v3-specific behaviour — the default
// Options set on the initial DBD, the version-aware paging overhead
// (v2: 52 bytes; v3: 68 bytes — IPv6 + OSPFv3 header + v3 DBD body),
// and a full master/slave negotiation that drives a v3 Router-LSA
// (LS type 0x2001) through the LSR/LSU/LSAck conversation to Full.

fn v3_exchange(rid: u32, lsdb: &Lsdb) -> DbExchange {
    let _ = lsdb;
    DbExchange::with_version(rid, AREA, MTU, OspfVersion::V3)
}

/// Originate a v3 Router-LSA (RFC 5340 §A.4.3, LS type 0x2001) for one
/// point-to-point link. The v3 Router-LSA body shape is `bits(1) |
/// options(3) | links` (no link-count field; descriptors run to the
/// end of the LSA), and a regular IPv6 router sets
/// [`ROUTER_BIT_V6`] plus [`ROUTER_BIT_E`] if it originates
/// AS-external LSAs.
fn v3_lsdb_with(router_id: u32, links: &[V3RouterLink]) -> Lsdb {
    let mut lsdb = Lsdb::new();
    let bits = ROUTER_BIT_V6;
    let options = OSPF_V3_OPTIONS_DEFAULT;
    if let Some(lsa) = originate_v3_router_lsa(router_id, bits, options, links, None) {
        lsdb.install(lsa, 0);
    }
    lsdb
}

fn v3_p2p_link(metric: u16, neighbor_iface: u32, neighbor_rid: u32) -> V3RouterLink {
    V3RouterLink {
        link_type: LINK_TYPE_POINTTOPOINT,
        metric,
        interface_id: 1,
        neighbor_interface_id: neighbor_iface,
        neighbor_router_id: neighbor_rid,
    }
}

/// The v3 driver's initial DBD carries the RFC 5340 §A.2 default
/// Options set (V6 | E | R = 0x13), not the v2 E | O set. Without
/// this pin, a future regression that flipped the version check in
/// `with_version` would silently advertise v2 options on a v3 DBD,
/// which §A.4.1 forbids (the V6 bit is mandatory for IPv6 routing
/// participation; the R bit signals a router that contributes to
/// forwarding).
#[test]
fn v3_initial_db_desc_carries_v3_default_options() {
    let lsdb = Lsdb::new();
    let mut ex = v3_exchange(US, &lsdb);
    let init = ex.initial_db_desc(7, NOW);
    let dd = body_db_desc(&init);
    assert_eq!(
        dd.options, OSPF_V3_OPTIONS_DEFAULT,
        "v3 DBD advertises V6|R|E (RFC 5340 §A.2)"
    );
    assert_eq!(dd.options, 0x13, "V6(0x01) | E(0x02) | R(0x10) = 0x13");
    assert_eq!(
        dd.flags,
        DD_I | DD_M | DD_MS,
        "v3 initial DBD still carries I|M|MS (RFC 2328 §10.3 unchanged by 5340)"
    );
}

/// The version-aware MTU clamp. v3's overhead is 68 bytes (IPv6 40 +
/// OSPFv3 header 16 + DBD body 12); the constructor's clamp must use
/// 68, not v2's 52. Without this pin a v3 driver constructed with
/// `iface_mtu = 60` would leave `mtu - overhead = 60 - 52 = 8` bytes
/// of headroom that does not actually exist on the wire (the real
/// headroom is `60 - 68 = -8`, i.e. the DBD body alone does not fit),
/// and `next_our_chunk` would return `1` header per page anyway
/// (the `.max(1)` floor) — silently emitting oversized DBDs.
#[test]
fn v3_with_version_clamps_iface_mtu_to_v3_overhead() {
    let ex = DbExchange::with_version(US, AREA, 60, OspfVersion::V3);
    assert_eq!(
        ex.iface_mtu, DD_OVERHEAD_V3 as u16,
        "v3 iface_mtu clamped to DD_OVERHEAD_V3 (68), not DD_OVERHEAD_V2 (52)"
    );
    // v2 keeps its 52-byte clamp.
    let ex_v2 = DbExchange::new(US, AREA, 50);
    assert_eq!(ex_v2.iface_mtu, DD_OVERHEAD_V2 as u16);
}

/// The v3 paging arithmetic uses the v3 overhead (68). The
/// `header_paging_respects_mtu` test pins the v2 case at
/// `DD_OVERHEAD_V2 + LSA_HEADER_LEN + 4` (one header per page); this
/// is the v3 mirror — `DD_OVERHEAD_V3 + LSA_HEADER_LEN + 4` (still
/// one header per page, but the arithmetic would yield TWO without
/// the version-aware overhead, since `92 - 52 = 40 = 2 * 20`).
///
/// Three v3 Router-LSAs (each 0x2001 with one point-to-point link)
/// drive three pages — one LSA header per page, M clear on the last.
#[test]
fn v3_header_paging_uses_v3_aware_overhead() {
    let mut lsdb = Lsdb::new();
    for i in 0..3u32 {
        let lsa = originate_v3_router_lsa(
            0x0a00_0001 + i,
            ROUTER_BIT_V6,
            OSPF_V3_OPTIONS_DEFAULT,
            &[v3_p2p_link(1, 100 + i, 0x0a00_0001 + ((i + 1) % 3))],
            None,
        )
        .unwrap();
        lsdb.install(lsa, 0);
    }
    // MTU chosen so exactly one v3 LSA header fits: 68 (v3 overhead)
    // + 20 (one header) + 4 (spare) = 92. The paging arithmetic with
    // the correct overhead yields 1 header per page; with v2's 52 it
    // would yield 2 headers per page (40 bytes / 20 bytes).
    let mtu = (DD_OVERHEAD_V3 + LSA_HEADER_LEN + 4) as u16;
    let mut ex = DbExchange::with_version(US, AREA, mtu, OspfVersion::V3);
    let mut nbr = neighbor_at_exstart(US);
    let mut them = DbExchange::with_version(THEM, AREA, mtu, OspfVersion::V3);

    let them_init = them.initial_db_desc(5, NOW);
    let step = ex.on_db_desc(body_db_desc(&them_init), THEM, &lsdb, &mut nbr, NOW);
    let mut pages: Vec<DbDescBody> = vec![body_db_desc(&step.outbound[0]).clone()];
    assert_eq!(
        pages[0].lsa_headers.len(),
        1,
        "v3 paging yields one header per page (correct v3 overhead 68)"
    );
    assert_eq!(pages[0].flags & DD_M, DD_M, "more pages follow");

    // Master rounds: each advances the sequence and consumes one more
    // header from our LSDB.
    let mut seq = body_db_desc(&them_init).dd_seq;
    for round in 0..4 {
        seq = seq.wrapping_add(1);
        let master_dd = DbDescBody {
            mtu,
            // v3 default options on the master side too.
            options: OSPF_V3_OPTIONS_DEFAULT,
            flags: DD_MS | DD_M,
            dd_seq: seq,
            lsa_headers: vec![],
        };
        let step = ex.on_db_desc(&master_dd, THEM, &lsdb, &mut nbr, NOW + round as u64 * 10);
        let answer = step
            .outbound
            .iter()
            .map(body_db_desc)
            .find(|d| d.flags & DD_MS == 0)
            .expect("slave answer");
        pages.push(answer.clone());
        if answer.flags & DD_M == 0 {
            break;
        }
    }

    // Three headers total, one per page, M clear on the last — same
    // invariant as `header_paging_respects_mtu`, just with the v3
    // overhead.
    assert_eq!(pages.len(), 3, "three pages at one header each");
    let headers: usize = pages.iter().map(|p| p.lsa_headers.len()).sum();
    assert_eq!(headers, 3, "every v3 LSA header paged exactly once");
    assert_eq!(
        pages.last().unwrap().flags & DD_M,
        0,
        "final v3 page clears More"
    );
    // Each paged LSA header is a v3 Router-LSA (LS type 0x2001) —
    // pins that the v3 LSDB walk produces 16-bit ls_type values and
    // not v2's 8-bit `1`.
    for page in &pages {
        for h in &page.lsa_headers {
            assert_eq!(
                h.ls_type, LS_TYPE_ROUTER,
                "v3 LSA header carries 0x2001 (16-bit ls_type)"
            );
        }
    }
    assert_eq!(pages[2].dd_seq, seq);
}

/// Full v3 master/slave exchange — the v3 mirror of
/// `slave_negotiation_and_full_exchange_with_master`. Each side has
/// one v3 Router-LSA (LS type 0x2001) describing a point-to-point
/// link; the scripted conversation is identical to the v2 case
/// (initials cross → slave answers → master bumps seq and pages →
/// both M=0 → Loading → LSR/LSU cross → both Full). The v3-specific
/// assertions pin: (a) the DD Options word is V6|R|E on every DD we
/// send; (b) the LSR entry carries the 16-bit v3 LS type; (c) the
/// LSU round-trips the original v3 Router-LSA unchanged.
#[test]
fn v3_slave_negotiation_and_full_exchange_with_master() {
    let our_lsdb = v3_lsdb_with(US, &[v3_p2p_link(10, 0x0000_0001, THEM)]);
    let their_lsdb = v3_lsdb_with(THEM, &[v3_p2p_link(20, 0x0000_0002, US)]);

    let mut us = v3_exchange(US, &our_lsdb);
    let mut us_nbr = neighbor_at_exstart(US);
    let mut them = v3_exchange(THEM, &their_lsdb);
    let mut them_nbr = neighbor_at_exstart(THEM);

    // 1. Initial DBDs cross. Both advertise V6|R|E (RFC 5340 §A.2).
    let us_init = us.initial_db_desc(US + 1, NOW);
    let them_init = them.initial_db_desc(THEM + 1, NOW);
    assert_eq!(
        body_db_desc(&us_init).options,
        OSPF_V3_OPTIONS_DEFAULT,
        "US initial DBD carries V6|R|E"
    );
    assert_eq!(
        body_db_desc(&them_init).options,
        OSPF_V3_OPTIONS_DEFAULT,
        "THEM initial DBD carries V6|R|E"
    );
    assert_eq!(
        body_db_desc(&us_init).flags,
        DD_I | DD_M | DD_MS,
        "v3 initial DBD carries I|M|MS"
    );

    // 2. US receives THEM's initial (higher id) → slave, answers with
    //    its own v3 Router-LSA header.
    let step_us = us.on_db_desc(body_db_desc(&them_init), THEM, &our_lsdb, &mut us_nbr, NOW);
    assert_eq!(step_us.outbound.len(), 1);
    let answer = &step_us.outbound[0];
    let answer_dd = body_db_desc(answer);
    assert_eq!(answer_dd.flags & DD_MS, 0, "slave clears MS");
    assert_eq!(answer_dd.flags & DD_I, 0, "slave clears I");
    assert_eq!(answer_dd.dd_seq, body_db_desc(&them_init).dd_seq);
    assert_eq!(answer_dd.lsa_headers.len(), 1);
    assert_eq!(
        answer_dd.lsa_headers[0].ls_type, LS_TYPE_ROUTER,
        "v3 LSA header on the slave's answer carries LS type 0x2001"
    );
    assert_eq!(answer_dd.options, OSPF_V3_OPTIONS_DEFAULT);
    assert_eq!(us.phase(), Phase::Exchange);
    assert_eq!(us_nbr.state, NeighborState::Exchange);

    // 3. THEM receives US's initial (lower id, ignored) then US's
    //    answer → master is negotiated, sends its own v3 headers,
    //    seq+1.
    let step_noise = them.on_db_desc(body_db_desc(&us_init), US, &their_lsdb, &mut them_nbr, NOW);
    assert!(step_noise.outbound.is_empty());
    let step_them = them.on_db_desc(answer_dd, US, &their_lsdb, &mut them_nbr, NOW);
    assert_eq!(step_them.outbound.len(), 1);
    let master_dd = body_db_desc(&step_them.outbound[0]);
    assert_eq!(master_dd.flags & DD_MS, DD_MS);
    assert_eq!(master_dd.dd_seq, body_db_desc(&them_init).dd_seq + 1);
    assert_eq!(master_dd.lsa_headers.len(), 1);
    assert_eq!(master_dd.options, OSPF_V3_OPTIONS_DEFAULT);
    assert_eq!(them.phase(), Phase::Exchange);
    assert_eq!(them_nbr.state, NeighborState::Exchange);

    // 4. US processes the master's page: queues THEIR LSA (missing),
    //    answers M=0 and emits its LSR (16-bit ls_type in the entry).
    let step_us = us.on_db_desc(master_dd, THEM, &our_lsdb, &mut us_nbr, NOW + 10);
    let slave_final = step_us
        .outbound
        .iter()
        .map(body_db_desc)
        .find(|d| d.flags & DD_MS == 0)
        .expect("slave echo DBD");
    assert_eq!(slave_final.flags & DD_M, 0);
    assert_eq!(slave_final.dd_seq, master_dd.dd_seq);
    assert_eq!(us.pending_requests(), 1);
    assert_eq!(us.phase(), Phase::Loading);
    assert_eq!(us_nbr.state, NeighborState::Loading);
    let us_lsr_pkt = step_us
        .outbound
        .iter()
        .find(|p| p.header.kind == OspfPacketType::LinkStateRequest as u8)
        .expect("slave emits its LSR at exchange completion");
    let us_lsr = body_ls_request(us_lsr_pkt);
    assert_eq!(us_lsr.entries.len(), 1);
    assert_eq!(
        us_lsr.entries[0].ls_type, LS_TYPE_ROUTER,
        "v3 LSR entry carries the 16-bit LS type 0x2001"
    );

    // 5. THEM receives the slave's final echo → enters Loading, LSRs
    //    OUR LSA.
    let step_them = them.on_db_desc(slave_final, US, &their_lsdb, &mut them_nbr, NOW + 20);
    assert_eq!(them.phase(), Phase::Loading);
    assert_eq!(them_nbr.state, NeighborState::Loading);
    assert_eq!(step_them.outbound.len(), 1);
    assert_eq!(
        step_them.outbound[0].header.kind,
        OspfPacketType::LinkStateRequest as u8
    );
    assert_eq!(them.pending_requests(), 1);

    // 6. Cross-LRS round-trip: each side answers the other's request
    //    with its own v3 Router-LSA.
    let them_lsreq = step_them.outbound[0].clone();
    let them_answer = them.on_ls_request(
        body_ls_request(us_lsr_pkt),
        &their_lsdb,
        &mut them_nbr,
        NOW + 30,
    );
    assert_eq!(them_answer.outbound.len(), 1);
    assert_eq!(
        them_answer.outbound[0].header.kind,
        OspfPacketType::LinkStateUpdate as u8
    );
    let us_answer = us.on_ls_request(
        body_ls_request(&them_lsreq),
        &our_lsdb,
        &mut us_nbr,
        NOW + 30,
    );
    assert_eq!(us_answer.outbound.len(), 1);
    assert_eq!(
        us_answer.outbound[0].header.kind,
        OspfPacketType::LinkStateUpdate as u8
    );

    // 7. US receives THEM's LS-Update (their v3 Router-LSA), acks, Full.
    let step_us = us.on_ls_update(body_ls_update(&them_answer.outbound[0]), &mut us_nbr);
    assert_eq!(step_us.lsas.len(), 1);
    assert_eq!(
        step_us.lsas[0].header.ls_type, LS_TYPE_ROUTER,
        "v3 LS-Update carries a 0x2001 Router-LSA"
    );
    assert!(step_us
        .outbound
        .iter()
        .any(|p| p.header.kind == OspfPacketType::LinkStateAck as u8));
    assert_eq!(us.phase(), Phase::Full);
    assert_eq!(us_nbr.state, NeighborState::Full);
    assert!(step_us.newly_full);

    // 8. THEM receives OUR LS-Update, acks, Full.
    let step_them = them.on_ls_update(body_ls_update(&us_answer.outbound[0]), &mut them_nbr);
    assert_eq!(them.phase(), Phase::Full);
    assert_eq!(them_nbr.state, NeighborState::Full);
    assert!(step_them.newly_full);
}

// ----- helpers -----

fn body_db_desc(p: &OspfPacket) -> &DbDescBody {
    match &p.body {
        OspfBody::DbDesc(d) => d,
        other => panic!("expected DBD, got {other:?}"),
    }
}

fn body_ls_request(p: &OspfPacket) -> &LsRequestBody {
    match &p.body {
        OspfBody::LsRequest(r) => r,
        other => panic!("expected LS-Request, got {other:?}"),
    }
}

fn body_ls_update(p: &OspfPacket) -> &Vec<Lsa> {
    match &p.body {
        OspfBody::LsUpdate(u) => &u.lsas,
        other => panic!("expected LS-Update, got {other:?}"),
    }
}
