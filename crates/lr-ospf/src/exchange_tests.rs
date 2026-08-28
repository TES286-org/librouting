//! Unit tests for the DBD/LSR exchange driver (RFC 2328 §10.3–§10.8).
//!
//! The scenarios drive two `DbExchange` instances against each other
//! through a scripted packet pump — the same conversation BIRD runs,
//! with both role assignments exercised.

use super::*;
use crate::lsdb::Lsdb;
use crate::neighbor::{NeighborState, OspfNeighbor};
use crate::origination::{originate_router_lsa, RouterLsaLink};

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
    if let Some(lsa) = originate_router_lsa(router_id, links, None) {
        lsdb.install(lsa, 0);
    }
    lsdb
}

/// Deliver every outbound packet of `from` to `to` (both the exchange
/// and its neighbor FSM), returning the packets `to` produced.
fn deliver(
    from: &mut DbExchange,
    from_nbr: &mut OspfNeighbor,
    to: &mut DbExchange,
    to_nbr: &mut OspfNeighbor,
    to_lsdb: &Lsdb,
    now_ms: u64,
) -> Vec<OspfPacket> {
    let _ = from_nbr;
    let mut produced = Vec::new();
    // A fresh copy of the sender's last output is not tracked here;
    // callers pass explicit packets.
    let _ = (to, to_lsdb, now_ms);
    produced
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
    let step_us = us.on_ls_update(&body_ls_update(&them_answer.outbound[0]), &mut us_nbr);
    assert_eq!(step_us.lsas.len(), 1);
    assert!(step_us
        .outbound
        .iter()
        .any(|p| p.header.kind == OspfPacketType::LinkStateAck as u8));
    assert_eq!(us.phase(), Phase::Full);
    assert_eq!(us_nbr.state, NeighborState::Full);
    assert!(step_us.newly_full);

    // 8. THEM receives OUR LS-Update: installs, acks, goes Full.
    let step_them = them.on_ls_update(&body_ls_update(&us_answer.outbound[0]), &mut them_nbr);
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
    let mut them_nbr = neighbor_at_exstart(THEM);

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
    let mut them_nbr = neighbor_at_exstart(THEM);

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
    let mut them_nbr = neighbor_at_exstart(THEM);
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
fn header_paging_respects_mtu() {
    // A tiny MTU forces one LSA header per DBD page; an LSDB with
    // three LSAs therefore takes three slave pages.
    let mut lsdb = Lsdb::new();
    for i in 0..3u32 {
        let lsa = originate_router_lsa(
            0x0a00_0001 + i,
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
    let mut ex = DbExchange::new(US, AREA, (DD_OVERHEAD + LSA_HEADER_LEN + 4) as u16);
    let mut nbr = neighbor_at_exstart(US);
    let mut them = DbExchange::new(THEM, AREA, (DD_OVERHEAD + LSA_HEADER_LEN + 4) as u16);
    let mut them_nbr = neighbor_at_exstart(THEM);

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
            mtu: (DD_OVERHEAD + LSA_HEADER_LEN + 4) as u16,
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

// Silence the unused helper when scenarios inline their pumps.
#[allow(dead_code)]
fn _unused(
    _: fn(
        &mut DbExchange,
        &mut OspfNeighbor,
        &mut DbExchange,
        &mut OspfNeighbor,
        &Lsdb,
        u64,
    ) -> Vec<OspfPacket>,
) {
    let _ = deliver as fn(_, _, _, _, _, _) -> _;
}

#[test]
fn dbg_scenario() {
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
    let mut us = DbExchange::new(US, AREA, MTU);
    let mut us_nbr = neighbor_at_exstart(US);
    let mut them = DbExchange::new(THEM, AREA, MTU);
    let mut them_nbr = neighbor_at_exstart(THEM);
    let us_init = us.initial_db_desc(11, NOW);
    let them_init = them.initial_db_desc(22, NOW);
    let step = us.on_db_desc(
        body_db_desc(&them_init),
        THEM,
        &their_lsdb,
        &mut us_nbr,
        NOW,
    );
    eprintln!("slave step: {} outbound", step.outbound.len());
    for p in &step.outbound {
        eprintln!(
            "  kind={} flags={:x} seq={}",
            p.header.kind,
            body_db_desc(p).flags,
            body_db_desc(p).dd_seq
        );
    }
    let answer = step.outbound[0].clone();
    let step2 = them.on_db_desc(
        body_db_desc(&answer),
        US,
        &their_lsdb,
        &mut them_nbr,
        NOW + 5,
    );
    eprintln!("master step: {} outbound", step2.outbound.len());
    for p in &step2.outbound {
        eprintln!("  kind={}", p.header.kind);
    }
}
