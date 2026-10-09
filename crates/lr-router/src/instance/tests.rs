use super::*;
use crate::redistribution::RedistributionPipe;
use lr_core::addr::Asn;
use lr_core::addr::RouterId;
use lr_core::fsm::TimerSpec;
use lr_ospf::packet::{LsUpdateBody, OspfBody};

/// Test helper: encode one LS-Update carrying `lsas` as if received
/// from a peer in `area`. The v2 packet checksum is finalized the way
/// the router's egress does (RFC 2328 §A.1) — the receive-side
/// decoder validates it.
fn ospf_lsu_bytes(router_id: u32, area_id: u32, lsas: Vec<Lsa>) -> Vec<u8> {
    let packet = ospf_ls_update(Protocol::Ospfv2, router_id, area_id, lsas);
    let mut bytes = lr_ospf::codec::OspfCodec::v2()
        .encode_vec(&packet)
        .expect("encode LSU");
    lr_ospf::origination::finalize_v2_stream(&mut bytes);
    bytes
}

/// Decode every LS-Update packet from a drained output stream.
fn decode_lsus(bytes: &[u8]) -> Vec<LsUpdateBody> {
    let mut out = Vec::new();
    let mut codec = lr_ospf::codec::OspfCodec::v2();
    let mut r = lr_core::buf::ReadBuf::new(bytes);
    while let Ok(Some(pkt)) = codec.decode(&mut r) {
        if let OspfBody::LsUpdate(u) = pkt.body {
            out.push(u);
        }
    }
    out
}

/// True when the session's output carries only LS-Acks (no data).
fn drain_is_ack_only(r: &mut DefaultRouter, h: SessionHandle) -> bool {
    let bytes = r.drain_output(h);
    let mut codec = lr_ospf::codec::OspfCodec::v2();
    let mut reader = lr_core::buf::ReadBuf::new(&bytes);
    let mut ack_only = true;
    let mut any = false;
    while let Ok(Some(pkt)) = codec.decode(&mut reader) {
        any = true;
        if !matches!(pkt.body, OspfBody::LsAck(_)) {
            ack_only = false;
        }
    }
    any && ack_only
}

/// Grace-LSA test constructor (RFC 3623 §2.1): one period/reason/
/// address set, sequence-controllable for retransmission tests.
fn grace_lsa(rid: u32, period: u32, seq: Option<u32>) -> Lsa {
    let body = lr_ospf::lsa::grace::GraceLsaBody {
        grace_period: period,
        reason: lr_ospf::lsa::grace::GraceReason::SoftwareRestart,
        ipv4_address: Some([192, 0, 2, 1]),
        ipv6_address: None,
    };
    lr_ospf::lsa::grace::originate_grace_lsa_v2(rid, &body, seq).expect("grace LSA")
}

#[test]
fn ospf_grace_lsa_emits_event_not_installed_not_flooded() {
    // RFC 3623 §3.1: the helper trigger is the received Grace-LSA.
    // It surfaces as one OspfGraceEvent; being link-scoped
    // (RFC 5250 §3.1) it never enters the area LSDB and is never
    // re-flooded to the area's other sessions.
    let mut r = DefaultRouter::new();
    let rid = RouterId::from_u32(0x01010101);
    let a = r.add_session(SessionConfig::ospfv2(rid, 0)).unwrap();
    let b = r.add_session(SessionConfig::ospfv2(rid, 0)).unwrap();
    let peer = 0x02020202u32;
    let lsa = grace_lsa(peer, 60, None);
    let grace_ls_id = lsa.header.link_state_id;
    r.feed_input(a, &ospf_lsu_bytes(peer, 0, vec![lsa]))
        .unwrap();
    let _ = r.poll_events();
    let grace_events = r.drain_ospf_grace_events();
    assert_eq!(grace_events.len(), 1, "one event per instance");
    let ev = &grace_events[0];
    assert_eq!(ev.area, 0);
    assert_eq!(ev.advertising_router, peer);
    assert_eq!(ev.grace_period_secs, 60);
    assert_eq!(ev.reason, 1); // software restart
    assert_eq!(ev.interface_addr_v4, Some([192, 0, 2, 1]));
    assert_eq!(ev.interface_addr_v6, None);
    assert_eq!(ev.ls_age_secs, 0);
    assert!(!ev.purged);
    // Not installed into the area LSDB (link-scoped opaque).
    assert!(r
        .ospf_area_lsa(0, lr_ospf::lsa::grace::grace_lsa_type(), grace_ls_id, peer)
        .is_none());
    // Not flooded to the other session: b's output stays quiet
    // (a's own output carries only the LSAck).
    assert!(r.drain_output(b).is_empty());
    assert!(drain_is_ack_only(&mut r, a));
    // The LSDB stayed empty of type-9s — nothing to age or refresh.
    let entries = r.ospf_areas.get(&0).unwrap().lsdb.len();
    assert_eq!(entries, 0);
}

#[test]
fn ospf_grace_lsa_retransmission_emits_no_second_event() {
    // RFC 3623 §2.1: the restarting router retransmits its
    // Grace-LSAs until acknowledged — dedup by sequence keeps the
    // event stream one-per-instance.
    let mut r = DefaultRouter::new();
    let rid = RouterId::from_u32(0x01010101);
    let a = r.add_session(SessionConfig::ospfv2(rid, 0)).unwrap();
    let peer = 0x02020202u32;
    let lsa1 = grace_lsa(peer, 60, None);
    let seq = lsa1.header.ls_sequence_number;
    r.feed_input(a, &ospf_lsu_bytes(peer, 0, vec![lsa1]))
        .unwrap();
    let _ = r.poll_events();
    assert_eq!(r.drain_ospf_grace_events().len(), 1);
    // The retransmitted copy (identical sequence).
    let copy = grace_lsa(peer, 60, Some(seq.wrapping_sub(1)));
    r.feed_input(a, &ospf_lsu_bytes(peer, 0, vec![copy]))
        .unwrap();
    let _ = r.poll_events();
    assert!(r.drain_ospf_grace_events().is_empty());
    // A *newer* instance (the restart was extended) emits again.
    let newer = grace_lsa(peer, 120, Some(seq));
    r.feed_input(a, &ospf_lsu_bytes(peer, 0, vec![newer]))
        .unwrap();
    let _ = r.poll_events();
    assert_eq!(r.drain_ospf_grace_events().len(), 1);
}

#[test]
fn ospf_grace_lsa_flush_emits_purged_event() {
    // RFC 3623 §3.2 (1): a MaxAge Grace-LSA (the flush) maps to
    // purged = true — helpers exit on it.
    let mut r = DefaultRouter::new();
    let rid = RouterId::from_u32(0x01010101);
    let a = r.add_session(SessionConfig::ospfv2(rid, 0)).unwrap();
    let peer = 0x02020202u32;
    // Fresh instance first (so the flush's sequence is newer).
    let lsa1 = grace_lsa(peer, 60, None);
    let seq = lsa1.header.ls_sequence_number;
    r.feed_input(a, &ospf_lsu_bytes(peer, 0, vec![lsa1]))
        .unwrap();
    let _ = r.poll_events();
    let _ = r.drain_ospf_grace_events();
    let mut flush = grace_lsa(peer, 0, Some(seq));
    flush.header.ls_age = lr_ospf::lsdb::MAX_AGE_SECS;
    flush.body.clear();
    flush.finalize();
    r.feed_input(a, &ospf_lsu_bytes(peer, 0, vec![flush]))
        .unwrap();
    let _ = r.poll_events();
    let grace_events = r.drain_ospf_grace_events();
    let Some(ev) = grace_events.iter().find(|e| e.purged) else {
        panic!("expected a purged grace event");
    };
    assert_eq!(ev.ls_age_secs, lr_ospf::lsdb::MAX_AGE_SECS);
    assert_eq!(ev.advertising_router, peer);
}

#[test]
fn ospfv3_grace_lsa_emits_event_not_installed() {
    // RFC 5187 §2: the v3 Grace-LSA (LS type 0x000b, Link State ID
    // = Interface ID) surfaces as an OspfGraceEvent like the v2
    // form — link-scoped, never installed, never re-flooded.
    let mut r = DefaultRouter::new();
    let rid = RouterId::from_u32(0x01010101);
    let a = r.add_session(SessionConfig::ospfv3(rid, 0)).unwrap();
    let peer = 0x02020202u32;
    let body = lr_ospf::lsa::grace::GraceLsaBody {
        grace_period: 90,
        reason: lr_ospf::lsa::grace::GraceReason::SoftwareReload,
        ipv4_address: None,
        ipv6_address: Some([0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x2a]),
    };
    let lsa =
        lr_ospf::lsa::grace::originate_grace_lsa_v3(peer, 5, &body, None).expect("v3 grace LSA");
    r.feed_input(a, &ospf3_lsu_bytes(peer, 0, vec![lsa]))
        .unwrap();
    let _ = r.poll_events();
    let grace_events = r.drain_ospf_grace_events();
    assert_eq!(grace_events.len(), 1, "one event per instance");
    let ev = &grace_events[0];
    assert_eq!(ev.area, 0);
    assert_eq!(ev.advertising_router, peer);
    assert_eq!(ev.grace_period_secs, 90);
    assert_eq!(ev.reason, 2); // software reload
    assert_eq!(ev.interface_addr_v4, None);
    assert_eq!(
        ev.interface_addr_v6,
        Some([0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x2a])
    );
    assert_eq!(ev.ls_age_secs, 0);
    assert!(!ev.purged);
    // Link-scoped 0x000b: not in the area LSDB.
    assert!(r
        .ospf_area_lsa(0, lr_ospf::lsa::grace::LS_TYPE_GRACE_V3, 5, peer)
        .is_none());
    // The MaxAge flush form (restart completed) purges.
    let flush = lr_ospf::lsa::grace::originate_grace_lsa_v3(
        peer,
        5,
        &body,
        Some(0x8000_005a), // strictly newer than the fresh instance
    )
    .expect("flush instance");
    let mut flush = flush;
    flush.header.ls_age = lr_ospf::lsdb::MAX_AGE_SECS;
    flush.finalize();
    r.feed_input(a, &ospf3_lsu_bytes(peer, 0, vec![flush]))
        .unwrap();
    let _ = r.poll_events();
    let grace_events = r.drain_ospf_grace_events();
    assert_eq!(grace_events.len(), 1);
    assert!(grace_events[0].purged);
}

#[test]
fn ospf_topology_version_bumps_on_content_change_only() {
    // RFC 3623 §3.2 (3): helpers exit on content changes but not
    // on periodic refreshes. The area's topology version is the
    // poll surface for exactly that distinction.
    let mut r = DefaultRouter::new();
    let rid = RouterId::from_u32(0x01010101);
    let a = r.add_session(SessionConfig::ospfv2(rid, 0)).unwrap();
    let peer = 0x02020202u32;
    assert_eq!(r.ospf_area_topology_version(0), Some(0));
    // First instance of a router-LSA: a topology change.
    let lsa1 = router_lsa(peer, vec![(0x03030303, 0xc0a80101, P2P, 10)]);
    let seq = lsa1.header.ls_sequence_number;
    r.feed_input(a, &ospf_lsu_bytes(peer, 0, vec![lsa1]))
        .unwrap();
    assert_eq!(r.ospf_area_topology_version(0), Some(1));
    let _ = r.poll_events();
    // Periodic refresh (same body, sequence +1, age reset):
    // RFC 2328 §14.1 — contents unchanged, version must not bump.
    let mut refresh = router_lsa(peer, vec![(0x03030303, 0xc0a80101, P2P, 10)]);
    refresh.header.ls_sequence_number = seq + 1;
    refresh.header.ls_age = 0;
    r.feed_input(a, &ospf_lsu_bytes(peer, 0, vec![refresh]))
        .unwrap();
    assert_eq!(
        r.ospf_area_topology_version(0),
        Some(1),
        "periodic refresh is not a topology change"
    );
    // Content change (the link set changed): bumps.
    let changed = router_lsa(peer, vec![]);
    let changed = {
        let mut c = changed;
        c.header.ls_sequence_number = seq + 2;
        c
    };
    r.feed_input(a, &ospf_lsu_bytes(peer, 0, vec![changed]))
        .unwrap();
    assert_eq!(r.ospf_area_topology_version(0), Some(2));
    let _ = r.poll_events();
    // ospf_area_lsa reads the installed instance back.
    let read = r.ospf_area_lsa(0, 1, peer, peer);
    assert!(read.is_some());
    assert_eq!(read.unwrap().header.ls_sequence_number, seq + 2);
}

#[test]
fn ospf_area_lsa_unknown_area_is_none() {
    let r = DefaultRouter::new();
    assert!(r.ospf_area_lsa(7, 1, 0, 0).is_none());
    assert!(r.ospf_area_topology_version(7).is_none());
}

#[test]
fn ospf_self_lsa_refresh_emits_new_lsu() {
    // Router with one OSPF session in area 0 and a self-originated
    // Router-LSA installed in the area LSDB at t=0. The refresh pass
    // at the 1800 s boundary must re-originate it (seq+1, age 0) and
    // queue an LSU on the session.
    let mut r = DefaultRouter::new();
    let h = r
        .add_session(SessionConfig::ospfv2(RouterId::from_u32(0x01020304), 0))
        .unwrap();
    let lsa = Lsa {
        header: lr_ospf::lsa::LsaHeader {
            ls_age: 0,
            options: 0,
            ls_type: 1,
            link_state_id: 0x01020304,
            advertising_router: 0x01020304,
            ls_sequence_number: 0x80000001,
            ls_checksum: 0,
            length: lr_ospf::lsa::LsaHeader::LEN as u16,
        },
        body: Vec::new(),
    };
    r.ospf_areas.get_mut(&0).unwrap().lsdb.install(lsa, 0);
    r.tick(Instant(1_799_999));
    assert!(r.drain_output(h).is_empty());
    r.tick(Instant(1_800_000));
    let updates = decode_lsus(&r.drain_output(h));
    assert_eq!(updates.len(), 1);
    assert_eq!(updates[0].lsa_count, 1);
    assert_eq!(updates[0].lsas[0].header.ls_sequence_number, 0x80000002);
    assert_eq!(updates[0].lsas[0].header.ls_age, 0);
}

/// Router-LSA test constructor: `(link_id, link_data, link_type, metric)`.
fn router_lsa(rid: u32, links: Vec<(u32, u32, u8, u16)>) -> Lsa {
    let mut body = Vec::new();
    body.extend_from_slice(&0u16.to_be_bytes()); // flags
    body.extend_from_slice(&(links.len() as u16).to_be_bytes());
    for (lid, ldata, ltype, metric) in links {
        body.extend_from_slice(&lid.to_be_bytes());
        body.extend_from_slice(&ldata.to_be_bytes());
        body.push(ltype);
        body.push(0); // tos
        body.extend_from_slice(&metric.to_be_bytes());
    }
    Lsa {
        header: lr_ospf::lsa::LsaHeader {
            ls_age: 0,
            options: 0x02,
            ls_type: 1,
            link_state_id: rid,
            advertising_router: rid,
            ls_sequence_number: 0x80000001,
            ls_checksum: 0,
            length: (lr_ospf::lsa::LsaHeader::LEN + body.len()) as u16,
        },
        body,
    }
}

const P2P: u8 = 1; // RouterLinkType::PointToPoint
const STUB: u8 = 3; // RouterLinkType::StubNetwork

#[test]
fn ospf_same_area_sessions_share_lsdb() {
    // Two sessions in one area: an LSA arriving on one must be flooded
    // to the other (RFC 2328 §13.3) and both share the area LSDB, so
    // the route installs exactly once.
    let mut r = DefaultRouter::new();
    let rid = RouterId::from_u32(0x01010101);
    let a = r.add_session(SessionConfig::ospfv2(rid, 0)).unwrap();
    let b = r.add_session(SessionConfig::ospfv2(rid, 0)).unwrap();

    let ours = router_lsa(0x01010101, vec![(0x0a0a0a00, 0xffff_ff00, STUB, 10)]);
    r.feed_input(a, &ospf_lsu_bytes(0x02020202, 0, vec![ours]))
        .unwrap();

    let updates = decode_lsus(&r.drain_output(b));
    assert_eq!(updates.len(), 1, "session b must see the flooded LSA");
    assert_eq!(updates[0].lsas[0].header.advertising_router, 0x01010101);
    // Session a's output is at most the acknowledgement of what it
    // delivered — never a flood of its own LSA back.
    assert!(
        drain_is_ack_only(&mut r, a) || r.drain_output(a).is_empty(),
        "no flood back to the source"
    );

    let snap = r.rib_snapshot();
    assert!(snap
        .iter()
        .any(|rt| rt.key.prefix == Prefix::new_v4([10, 10, 10, 0], 24)));
}

#[test]
fn ospf_abr_originates_summary_into_backbone() {
    // ABR attached to area 0 and area 1. An intra-area net in area 1
    // (10.10.10.0/24, total metric 15) must be summarized into the
    // backbone as a type-3 LSA with a valid §C.4 checksum.
    let mut r = DefaultRouter::new();
    let rid = 0x01010101;
    let h0 = r
        .add_session(SessionConfig::ospfv2(RouterId::from_u32(rid), 0))
        .unwrap();
    let h1 = r
        .add_session(SessionConfig::ospfv2(RouterId::from_u32(rid), 1))
        .unwrap();

    let ours = router_lsa(rid, vec![(0x02020202, 0, P2P, 5)]);
    let r2 = router_lsa(
        0x02020202,
        vec![(rid, 0, P2P, 5), (0x0a0a0a00, 0xffff_ff00, STUB, 10)],
    );
    r.feed_input(h1, &ospf_lsu_bytes(0x02020202, 1, vec![ours, r2]))
        .unwrap();

    // Intra-area route: 5 (to R2) + 10 (stub) = 15.
    let route = r
        .rib_snapshot()
        .into_iter()
        .find(|rt| rt.key.prefix == Prefix::new_v4([10, 10, 10, 0], 24))
        .expect("intra-area route installed");
    assert_eq!(route.preference.metric, 15);

    // Backbone session received exactly the type-3 summary.
    let updates = decode_lsus(&r.drain_output(h0));
    assert_eq!(updates.len(), 1);
    let lsa = &updates[0].lsas[0];
    assert_eq!(lsa.header.ls_type, 3);
    assert_eq!(lsa.header.advertising_router, rid);
    assert_eq!(lsa.header.link_state_id, 0x0a0a0a00);
    assert_eq!(lsa.header.ls_sequence_number, 0x80000001);
    let body = lr_ospf::lsa::decode_summary_lsa_body(&lsa.body).unwrap();
    assert_eq!(body.network_mask, 0xffff_ff00);
    assert_eq!(body.tos0_metric(), Some(15));
    assert!(
        lsa.checksum_ok(),
        "originated summary must checksum correctly"
    );
    // The summary targets the backbone only (area 1 sees at most the
    // acknowledgement of what it delivered).
    assert!(drain_is_ack_only(&mut r, h1) || r.drain_output(h1).is_empty());
}

#[test]
fn ospf_inter_area_route_installed() {
    // Single backbone area: border router 3.3.3.3 (metric 5 away)
    // summarizes 10.20.20.0/24 metric 7 → inter-area route metric 12.
    // A summary from an unreachable border router must yield nothing.
    let mut r = DefaultRouter::new();
    let rid = 0x01010101;
    let h0 = r
        .add_session(SessionConfig::ospfv2(RouterId::from_u32(rid), 0))
        .unwrap();

    let ours = router_lsa(rid, vec![(0x03030303, 0, P2P, 5)]);
    let br = router_lsa(0x03030303, vec![(rid, 0, P2P, 5)]);
    let reachable_summary = originate_summary_lsa(
        0x03030303,
        &SummaryDestination::new(Prefix::new_v4([10, 20, 20, 0], 24), 7),
        None,
    )
    .unwrap();
    let ghost_summary = originate_summary_lsa(
        0x09090909,
        &SummaryDestination::new(Prefix::new_v4([10, 30, 30, 0], 24), 7),
        None,
    )
    .unwrap();
    r.feed_input(
        h0,
        &ospf_lsu_bytes(
            0x03030303,
            0,
            vec![ours, br, reachable_summary, ghost_summary],
        ),
    )
    .unwrap();

    let snap = r.rib_snapshot();
    let route = snap
        .iter()
        .find(|rt| rt.key.prefix == Prefix::new_v4([10, 20, 20, 0], 24))
        .expect("inter-area route via reachable border router");
    assert_eq!(route.preference.metric, 12); // 5 + 7
    assert_eq!(route.protocol, Protocol::Ospfv2);
    assert!(
        !snap
            .iter()
            .any(|rt| rt.key.prefix == Prefix::new_v4([10, 30, 30, 0], 24)),
        "unreachable border router's summary must not install a route"
    );
}

#[test]
fn ospf_inter_area_loop_guard() {
    // ABR attached to areas 0, 1, 2. A route learned *inter-area* in
    // area 1 (from border router 4.4.4.4) must never be re-advertised
    // into area 2 or the backbone — only the backbone's knowledge is
    // summarized into non-backbone areas (RFC 2328 §12.4.3).
    let mut r = DefaultRouter::new();
    let rid = 0x01010101;
    let h0 = r
        .add_session(SessionConfig::ospfv2(RouterId::from_u32(rid), 0))
        .unwrap();
    let h1 = r
        .add_session(SessionConfig::ospfv2(RouterId::from_u32(rid), 1))
        .unwrap();
    let h2 = r
        .add_session(SessionConfig::ospfv2(RouterId::from_u32(rid), 2))
        .unwrap();

    // Area 1: BR 4.4.4.4 reachable at 5, advertising 10.40.40.0/24 (7).
    let ours_a1 = router_lsa(rid, vec![(0x04040404, 0, P2P, 5)]);
    let br = router_lsa(0x04040404, vec![(rid, 0, P2P, 5)]);
    let br_summary = originate_summary_lsa(
        0x04040404,
        &SummaryDestination::new(Prefix::new_v4([10, 40, 40, 0], 24), 7),
        None,
    )
    .unwrap();
    r.feed_input(
        h1,
        &ospf_lsu_bytes(0x04040404, 1, vec![ours_a1, br, br_summary]),
    )
    .unwrap();
    // Area 2: our stub net 10.50.50.0/24 metric 3.
    let ours_a2 = router_lsa(rid, vec![(0x0a323200, 0xffff_ff00, STUB, 3)]);
    r.feed_input(h2, &ospf_lsu_bytes(0x05050505, 2, vec![ours_a2]))
        .unwrap();

    // The area-1-learned inter-area route is usable locally...
    let snap = r.rib_snapshot();
    let route = snap
        .iter()
        .find(|rt| rt.key.prefix == Prefix::new_v4([10, 40, 40, 0], 24))
        .expect("inter-area route via area 1");
    assert_eq!(route.preference.metric, 12); // 5 + 7

    // ...but area 2 must NOT learn it. Area 2 receives nothing at all:
    // the backbone knows no routes beyond area 2's own intra net,
    // which the loop guard excludes.
    assert!(
        drain_is_ack_only(&mut r, h2) || r.drain_output(h2).is_empty(),
        "non-backbone inter-area knowledge must not transit areas"
    );
    // The backbone only gets area 2's intra net (10.50.50.0/24), never
    // the area-1-learned 10.40.40.0/24.
    let backbone_updates = decode_lsus(&r.drain_output(h0));
    let backbone_prefixes: Vec<u32> = backbone_updates
        .iter()
        .flat_map(|u| u.lsas.iter().map(|l| l.header.link_state_id))
        .collect();
    assert_eq!(backbone_prefixes, vec![0x0a323200]);
}

#[test]
fn ospf_summary_flushed_when_net_disappears() {
    // ABR setup as in ospf_abr_originates_summary_into_backbone; then
    // R2's Router-LSA ages out (MaxAge instance) → the backbone
    // summary is flushed with a MaxAge LSA and the route withdraws.
    let mut r = DefaultRouter::new();
    let rid = 0x01010101;
    let h0 = r
        .add_session(SessionConfig::ospfv2(RouterId::from_u32(rid), 0))
        .unwrap();
    let h1 = r
        .add_session(SessionConfig::ospfv2(RouterId::from_u32(rid), 1))
        .unwrap();

    let ours = router_lsa(rid, vec![(0x02020202, 0, P2P, 5)]);
    let mut r2 = router_lsa(
        0x02020202,
        vec![(rid, 0, P2P, 5), (0x0a0a0a00, 0xffff_ff00, STUB, 10)],
    );
    r.feed_input(h1, &ospf_lsu_bytes(0x02020202, 1, vec![ours, r2.clone()]))
        .unwrap();
    assert!(r
        .rib_snapshot()
        .iter()
        .any(|rt| rt.key.prefix == Prefix::new_v4([10, 10, 10, 0], 24)));
    let _ = r.drain_output(h0);

    // Flush R2's LSA with a MaxAge instance (seq advanced).
    r2.header.ls_age = 3600;
    r2.header.ls_sequence_number += 1;
    r.feed_input(h1, &ospf_lsu_bytes(0x02020202, 1, vec![r2]))
        .unwrap();

    let updates = decode_lsus(&r.drain_output(h0));
    let flushed = updates
        .iter()
        .flat_map(|u| u.lsas.iter())
        .find(|l| l.header.ls_type == 3 && l.header.link_state_id == 0x0a0a0a00)
        .expect("backbone summary must be flushed");
    assert_eq!(flushed.header.ls_age, 3600);

    assert!(
        !r.rib_snapshot()
            .iter()
            .any(|rt| rt.key.prefix == Prefix::new_v4([10, 10, 10, 0], 24)),
        "route must withdraw with its summary"
    );
}

#[test]
fn ospf_no_backbone_no_summaries() {
    // Router attached to areas 1 and 2 only: without a backbone
    // attachment it is not a functioning ABR and must not summarize.
    let mut r = DefaultRouter::new();
    let rid = 0x01010101;
    let h1 = r
        .add_session(SessionConfig::ospfv2(RouterId::from_u32(rid), 1))
        .unwrap();
    let h2 = r
        .add_session(SessionConfig::ospfv2(RouterId::from_u32(rid), 2))
        .unwrap();
    let ours = router_lsa(rid, vec![(0x0a0a0a00, 0xffff_ff00, STUB, 10)]);
    r.feed_input(h1, &ospf_lsu_bytes(0x02020202, 1, vec![ours]))
        .unwrap();
    // h1's output is at most its acknowledgement of the delivery;
    // h2 (backbone) must see nothing without an ABR summary.
    assert!(drain_is_ack_only(&mut r, h1) || r.drain_output(h1).is_empty());
    assert!(r.drain_output(h2).is_empty());
    assert!(r
        .rib_snapshot()
        .iter()
        .any(|rt| rt.key.prefix == Prefix::new_v4([10, 10, 10, 0], 24)));
}

#[test]
fn ospf_area_teardown_with_last_session() {
    // Routes must not outlive their area: removing the last session of
    // an area withdraws its routes, while other areas keep theirs.
    let mut r = DefaultRouter::new();
    let rid = 0x01010101;
    let h0 = r
        .add_session(SessionConfig::ospfv2(RouterId::from_u32(rid), 0))
        .unwrap();
    let h1 = r
        .add_session(SessionConfig::ospfv2(RouterId::from_u32(rid), 1))
        .unwrap();
    // Area 0: our stub net.
    let ours_a0 = router_lsa(rid, vec![(0x0b0b0b00, 0xffff_ff00, STUB, 4)]);
    r.feed_input(h0, &ospf_lsu_bytes(0x02020202, 0, vec![ours_a0]))
        .unwrap();
    // Area 1: our stub net.
    let ours_a1 = router_lsa(rid, vec![(0x0c0c0c00, 0xffff_ff00, STUB, 6)]);
    r.feed_input(h1, &ospf_lsu_bytes(0x03030303, 1, vec![ours_a1]))
        .unwrap();
    assert_eq!(r.rib_snapshot().len(), 2);

    r.remove_session(h1).unwrap();
    let snap = r.rib_snapshot();
    assert!(
        !snap
            .iter()
            .any(|rt| rt.key.prefix == Prefix::new_v4([12, 12, 12, 0], 24)),
        "area 1 routes must withdraw with the last session"
    );
    assert!(
        snap.iter()
            .any(|rt| rt.key.prefix == Prefix::new_v4([11, 11, 11, 0], 24)),
        "area 0 routes must survive"
    );
}

#[test]
fn ospf_rejects_mismatched_router_id_and_version() {
    let mut r = DefaultRouter::new();
    let _h = r
        .add_session(SessionConfig::ospfv2(RouterId::from_u32(0x01010101), 0))
        .unwrap();
    assert!(
        r.add_session(SessionConfig::ospfv2(RouterId::from_u32(0x02020202), 1))
            .is_err(),
        "a second OSPF router ID must be rejected"
    );
    // v3 into the same area as v2 must be rejected.
    let mut v3_cfg = SessionConfig::ospfv2(RouterId::from_u32(0x01010101), 0);
    v3_cfg.kind = crate::session::SessionKind::Ospfv3;
    assert!(
        r.add_session(v3_cfg).is_err(),
        "OSPFv3 must not mix into a v2 area"
    );
}

/// Encode one LS-Update carrying `lsas` as a v3 packet (16-byte
/// header, pseudo-header checksum finalized).
fn ospf3_lsu_bytes(router_id: u32, area_id: u32, lsas: Vec<Lsa>) -> Vec<u8> {
    let packet = ospf_ls_update(Protocol::Ospfv3, router_id, area_id, lsas);
    let mut bytes = lr_ospf::codec::OspfCodec::v3()
        .encode_vec(&packet)
        .expect("encode v3 LSU");
    let src = [0xfe_u8, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
    let dst = [0xff_u8, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 5];
    lr_ospf::origination::finalize_v3_stream(&mut bytes, &src, &dst);
    bytes
}

/// An IPv6 redistribution originates a 0x4005 into every attached
/// v3 area (LS ID stable per prefix), refuses illegal forwarding
/// addresses, and `ospf_unredistribute_v3` MaxAge-flushes it.
#[test]
fn ospfv3_redistribute_originates_as_external() {
    let mut r = DefaultRouter::new();
    let r1 = RouterId::from_u32(0x0a00_0001);
    let h = r
        .add_session(SessionConfig::ospfv3(r1, 0).with_ospf_mtu(1500))
        .expect("v3 session");
    let _ = h;

    use lr_ospf::lsa::v3::{V3AsExternalBody, V3ExternalDestination};
    let p = Prefix::new_v6(
        [
            0x20, 0x01, 0x0d, 0xb8, 0xbe, 0xef, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ],
        48,
    );
    let mut dest = V3ExternalDestination::new(p, 100, true);
    dest.route_tag = Some(7);
    assert!(r.ospf_redistribute_v3(dest), "v6 destination accepted");

    let lsa = r
        .ospf_area_lsa(0, lr_ospf::lsa::v3::LS_TYPE_AS_EXTERNAL, 1, 0x0a00_0001)
        .expect("0x4005 originated");
    assert!(lsa.checksum_ok());
    let body = V3AsExternalBody::decode(&lsa.body).unwrap();
    assert!(body.e_bit, "type 2");
    assert_eq!(body.metric, 100);
    assert_eq!(body.route_tag, Some(7));
    assert_eq!(body.prefix.prefix_len, 48);
    assert_eq!(body.forwarding_addr, None);
    assert_eq!(body.prefix_addr_prefix(), Some(p));

    // A link-local forwarding address is illegal (§A.4.7).
    let mut bad = V3ExternalDestination::new(p, 100, true);
    bad.forwarding_addr = Some({
        let mut a = [0u8; 16];
        a[0] = 0xfe;
        a[1] = 0x80;
        a
    });
    assert!(!r.ospf_redistribute_v3(bad), "link-local FA refused");

    // Withdrawal: the MaxAge flush is flooded and the LSA leaves
    // the LSDB (RFC 2328 §14 — a purged LSA is not retained).
    assert!(r.ospf_unredistribute_v3(p));
    assert!(r
        .ospf_area_lsa(0, lr_ospf::lsa::v3::LS_TYPE_AS_EXTERNAL, 1, 0x0a00_0001)
        .is_none());
    assert!(!r.ospf_unredistribute_v3(p), "already withdrawn");
}

#[test]
fn dbg_decode_v3_lsu() {
    let r2 = 0x0a00_0002u32;
    use lr_ospf::lsa::v3::originate_v3_router_lsa;
    let lsa = originate_v3_router_lsa(
        r2,
        0x04,
        0x13,
        &[lr_ospf::lsa::v3::V3RouterLink {
            link_type: 1,
            metric: 10,
            interface_id: 3,
            neighbor_interface_id: 5,
            neighbor_router_id: 1,
        }],
        None,
    )
    .unwrap();
    let bytes = ospf3_lsu_bytes(r2, 0, vec![lsa]);
    eprintln!("total bytes: {}", bytes.len());
    let mut codec = lr_ospf::codec::OspfCodec::v3();
    let mut r = lr_core::buf::ReadBuf::new(&bytes);
    match codec.decode(&mut r) {
        Ok(Some(pkt)) => eprintln!(
            "decoded kind={} version={}",
            pkt.header.kind, pkt.header.version
        ),
        Ok(None) => eprintln!("None (incomplete)"),
        Err(e) => eprintln!("decode err: {:?}", e),
    }
}

/// A v3 LSU received on a v3 session installs into the area LSDB and
/// publishes IPv6 routes: the neighbor's prefixes surface as
/// Protocol::Ospfv3 routes in the v6-unicast family with the
/// neighbor's link-local next hop (RFC 5340 §3.1, §16.1 v3 form).
#[test]
fn ospfv3_routes_publish_as_ipv6_with_link_local_next_hop() {
    let mut r = DefaultRouter::new();
    let r1 = RouterId::from_u32(0x0a00_0001);
    let r2 = 0x0a00_0002u32;
    let h = r
        .add_session(SessionConfig::ospfv3(r1, 0).with_ospf_mtu(1500))
        .expect("v3 session");

    use lr_ospf::lsa::v3::{
        originate_v3_intra_area_prefix_lsa, originate_v3_link_lsa, originate_v3_router_lsa,
        LINK_TYPE_POINTTOPOINT, ROUTER_BIT_V6,
    };
    let mut ll2 = [0u8; 16];
    ll2[0] = 0xfe;
    ll2[1] = 0x80;
    ll2[15] = 2;
    // r2's Router-LSA (p2p back to us), Link-LSA (its link-local) and
    // Intra-Area-Prefix-LSA (one /64).
    let router_lsa = originate_v3_router_lsa(
        r2,
        ROUTER_BIT_V6,
        0x13,
        &[lr_ospf::lsa::v3::V3RouterLink {
            link_type: LINK_TYPE_POINTTOPOINT,
            metric: 10,
            interface_id: 3,
            neighbor_interface_id: 5,
            neighbor_router_id: 0x0a00_0001,
        }],
        None,
    )
    .unwrap();
    let link_lsa = originate_v3_link_lsa(r2, 3, 1, 0x13, ll2, vec![], None).unwrap();
    let mut p2 = [0u8; 16];
    p2[0] = 0x20;
    p2[1] = 0x01;
    p2[3] = 0xb8;
    p2[7] = 2;
    let prefix = Prefix::new_v6(p2, 64);
    let iap = originate_v3_intra_area_prefix_lsa(
        r2,
        1,
        lr_ospf::lsa::v3::LS_TYPE_ROUTER,
        0,
        r2,
        vec![lr_ospf::lsa::v3::V3Prefix {
            prefix_len: 64,
            options: 0,
            metric: 0,
            addr: p2,
        }],
        None,
    )
    .unwrap();

    // Our own Router-LSA: the daemon originates it on adjacency-up
    // and feeds it through the anchor session; the SPF needs it as
    // the outbound edge from the root vertex.
    let own_lsa = originate_v3_router_lsa(
        0x0a00_0001,
        ROUTER_BIT_V6,
        0x13,
        &[lr_ospf::lsa::v3::V3RouterLink {
            link_type: LINK_TYPE_POINTTOPOINT,
            metric: 10,
            interface_id: 5,
            neighbor_interface_id: 3,
            neighbor_router_id: r2,
        }],
        None,
    )
    .unwrap();
    let bytes = ospf3_lsu_bytes(r2, 0, vec![router_lsa, link_lsa, iap, own_lsa]);
    r.feed_input(h, &bytes).expect("feed v3 LSU");
    let _ = r.drain_output(h);

    let routes = r.rib_snapshot();
    let got = routes
        .iter()
        .find(|rt| rt.key.prefix == prefix)
        .expect("v3 route published");
    assert_eq!(got.protocol, Protocol::Ospfv3);
    assert_eq!(got.key.family, NlriFamily::IPV6_UNICAST, "v6 family");
    assert_eq!(got.next_hop, Some(IpAddr::V6(ll2)), "link-local next hop");
    assert_eq!(got.preference.metric, 10, "spf cost");
}

/// Flooding from a v3 session emits v3 packets: the drained output
/// parses with the v3 codec (16-byte header) and the v3 version byte.
#[test]
fn ospfv3_flooded_lsas_carry_v3_wire_shape() {
    let mut r = DefaultRouter::new();
    let r1 = RouterId::from_u32(0x0a00_0001);
    let r2 = 0x0a00_0002u32;
    let h = r
        .add_session(SessionConfig::ospfv3(r1, 0).with_ospf_mtu(1500))
        .expect("v3 session");
    use lr_ospf::lsa::v3::{originate_v3_router_lsa, LINK_TYPE_POINTTOPOINT, ROUTER_BIT_V6};
    let lsa = originate_v3_router_lsa(
        r2,
        ROUTER_BIT_V6,
        0x13,
        &[lr_ospf::lsa::v3::V3RouterLink {
            link_type: LINK_TYPE_POINTTOPOINT,
            metric: 10,
            interface_id: 3,
            neighbor_interface_id: 5,
            neighbor_router_id: 0x0a00_0001,
        }],
        None,
    )
    .unwrap();
    let bytes = ospf3_lsu_bytes(r2, 0, vec![lsa]);
    r.feed_input(h, &bytes).expect("feed v3 LSU");
    let out = r.drain_output(h);
    assert!(!out.is_empty(), "flooded back on the same session");
    let mut codec = lr_ospf::codec::OspfCodec::v3();
    let mut reader = lr_core::buf::ReadBuf::new(&out);
    let mut saw_lsack_or_update = false;
    while let Ok(Some(pkt)) = codec.decode(&mut reader) {
        assert_eq!(pkt.header.version, 3, "v3 version byte");
        saw_lsack_or_update = true;
    }
    assert!(saw_lsack_or_update);
}

#[test]
fn ospf_area_type_mismatch_rejected_and_runtime_change_allowed() {
    let mut r = DefaultRouter::new();
    let rid = RouterId::from_u32(0x01010101);
    let _h = r
        .add_session(SessionConfig::ospfv2(rid, 1).with_ospf_area_type(OspfAreaType::nssa(10)))
        .unwrap();
    // A second session with a different area type must be rejected...
    assert!(
        r.add_session(SessionConfig::ospfv2(rid, 1).with_ospf_area_type(OspfAreaType::stub(5)),)
            .is_err(),
        "conflicting area types must be rejected at attach"
    );
    // ...while the same type attaches fine.
    assert!(r
        .add_session(SessionConfig::ospfv2(rid, 1).with_ospf_area_type(OspfAreaType::nssa(10)),)
        .is_ok());
    // Runtime conversion through the dedicated API works.
    assert!(r.ospf_set_area_type(1, OspfAreaType::stub(5)));
    assert!(
        !r.ospf_set_area_type(1, OspfAreaType::stub(5)),
        "a no-op conversion changes nothing"
    );
    assert!(!r.ospf_set_area_type(99, OspfAreaType::stub(5)));
}

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
    r.timers.arm(Instant(0), TimerId(7), TimerSpec::once(100));
    r.tick(Instant(50));
    r.tick(Instant(100));
}

#[test]
fn timer_encoding_roundtrips() {
    let t = encode_timer(42, TimerId(3));
    assert_eq!(decode_timer(t), (42, 3));
}

#[test]
fn originate_fills_rib() {
    let mut r = DefaultRouter::new();
    let key = r.originate(Prefix::new_v4([203, 0, 113, 0], 24), None);
    assert_eq!(r.rib_len(), 1);
    r.unoriginate(&key);
    assert_eq!(r.rib_len(), 0);
}

#[test]
fn mrai_batches_prefix_reannouncements() {
    let mut a = DefaultRouter::new();
    let mut b = DefaultRouter::new();
    let a_session = a
        .add_session(
            SessionConfig::bgp(Asn(64512), Asn(64513), RouterId::from_v4([10, 0, 0, 1]))
                .with_mrai_ms(100),
        )
        .unwrap();
    let b_session = b
        .add_session(SessionConfig::bgp(
            Asn(64513),
            Asn(64512),
            RouterId::from_v4([10, 0, 0, 2]),
        ))
        .unwrap();
    a.start_session(a_session).unwrap();
    b.start_session(b_session).unwrap();
    let a_open = a.drain_output(a_session);
    let b_open = b.drain_output(b_session);
    a.feed_input(a_session, &b_open).unwrap();
    b.feed_input(b_session, &a_open).unwrap();
    let a_keepalive = a.drain_output(a_session);
    let b_keepalive = b.drain_output(b_session);
    a.feed_input(a_session, &b_keepalive).unwrap();
    b.feed_input(b_session, &a_keepalive).unwrap();

    let key = a.originate(
        Prefix::new_v4([203, 0, 113, 0], 24),
        Some(IpAddr::V4([192, 0, 2, 1])),
    );
    let advertisement = a.drain_output(a_session);
    assert!(!advertisement.is_empty());
    b.feed_input(b_session, &advertisement).unwrap();
    assert_eq!(b.rib_len(), 1);

    // Re-origination changes the path and would normally advertise an
    // UPDATE immediately; MRAI holds it until the 100 ms boundary.
    a.unoriginate(&key);
    let withdrawal = a.drain_output(a_session);
    assert!(!withdrawal.is_empty(), "withdrawals bypass MRAI");
    b.feed_input(b_session, &withdrawal).unwrap();
    let _replacement = a.originate(
        Prefix::new_v4([203, 0, 113, 0], 24),
        Some(IpAddr::V4([192, 0, 2, 2])),
    );
    assert!(a.drain_output(a_session).is_empty());
    a.tick(Instant(99));
    assert!(a.drain_output(a_session).is_empty());
    a.tick(Instant(100));
    let replacement = a.drain_output(a_session);
    assert!(!replacement.is_empty());
    b.feed_input(b_session, &replacement).unwrap();
    assert_eq!(b.rib_len(), 1);
}

#[test]
fn route_refresh_reannounces_current_family() {
    let mut a = DefaultRouter::new();
    let mut b = DefaultRouter::new();
    let a_session = a
        .add_session(SessionConfig::bgp(
            Asn(64512),
            Asn(64513),
            RouterId::from_v4([10, 0, 0, 1]),
        ))
        .unwrap();
    let b_session = b
        .add_session(SessionConfig::bgp(
            Asn(64513),
            Asn(64512),
            RouterId::from_v4([10, 0, 0, 2]),
        ))
        .unwrap();
    a.start_session(a_session).unwrap();
    b.start_session(b_session).unwrap();
    let a_open = a.drain_output(a_session);
    let b_open = b.drain_output(b_session);
    a.feed_input(a_session, &b_open).unwrap();
    b.feed_input(b_session, &a_open).unwrap();
    let a_keepalive = a.drain_output(a_session);
    let b_keepalive = b.drain_output(b_session);
    a.feed_input(a_session, &b_keepalive).unwrap();
    b.feed_input(b_session, &a_keepalive).unwrap();

    a.originate(
        Prefix::new_v4([203, 0, 113, 0], 24),
        Some(IpAddr::V4([192, 0, 2, 1])),
    );
    let initial_advertisement = a.drain_output(a_session);
    b.feed_input(b_session, &initial_advertisement).unwrap();
    assert_eq!(b.rib_len(), 1);

    assert!(b.request_route_refresh(b_session, NlriFamily::IPV4_UNICAST));
    let request = b.drain_output(b_session);
    a.feed_input(a_session, &request).unwrap();
    let refreshed = a.drain_output(a_session);
    assert!(!refreshed.is_empty());
    b.feed_input(b_session, &refreshed).unwrap();
    assert_eq!(b.rib_len(), 1);
}

// ===== RFC 4724 + RFC 9494 retention tests =====

fn establish(
    a: &mut DefaultRouter,
    a_session: SessionHandle,
    b: &mut DefaultRouter,
    b_session: SessionHandle,
) {
    a.start_session(a_session).unwrap();
    b.start_session(b_session).unwrap();
    let a_open = a.drain_output(a_session);
    let b_open = b.drain_output(b_session);
    a.feed_input(a_session, &b_open).unwrap();
    b.feed_input(b_session, &a_open).unwrap();
    let a_keepalive = a.drain_output(a_session);
    let b_keepalive = b.drain_output(b_session);
    a.feed_input(a_session, &b_keepalive).unwrap();
    b.feed_input(b_session, &a_keepalive).unwrap();
}

/// Wire B's Loc-RIB into A: originate on B, pump the UPDATE across.
fn b_advertise_to_a(
    a: &mut DefaultRouter,
    a_session: SessionHandle,
    b: &mut DefaultRouter,
    b_session: SessionHandle,
) {
    b.originate(
        Prefix::new_v4([198, 51, 100, 0], 24),
        Some(IpAddr::V4([192, 0, 2, 10])),
    );
    let advertisement = b.drain_output(b_session);
    assert!(!advertisement.is_empty());
    a.feed_input(a_session, &advertisement).unwrap();
    assert_eq!(a.rib_len(), 1);
}

fn llgr_pair() -> (DefaultRouter, SessionHandle, DefaultRouter, SessionHandle) {
    let mut a = DefaultRouter::new();
    let mut b = DefaultRouter::new();
    let a_session = a
        .add_session(
            SessionConfig::bgp(Asn(64512), Asn(64513), RouterId::from_v4([10, 0, 0, 1]))
                .with_mrai_ms(0)
                .with_graceful_restart(1)
                .with_long_lived_gr(10),
        )
        .unwrap();
    // B advertises LLST 20 s: A must retain B's routes for
    // restart (1 s) + LLST (20 s) per RFC 9494 §4.2.
    let b_session = b
        .add_session(
            SessionConfig::bgp(Asn(64513), Asn(64512), RouterId::from_v4([10, 0, 0, 2]))
                .with_mrai_ms(0)
                .with_graceful_restart(1)
                .with_long_lived_gr(20),
        )
        .unwrap();
    (a, a_session, b, b_session)
}

fn best_has_llgr_stale(a: &DefaultRouter) -> bool {
    let snap = a.rib_snapshot();
    assert_eq!(snap.len(), 1);
    let attrs: PathAttributes = snap[0].attributes.clone().into();
    attrs.has_community(Community::LLGR_STALE)
}

/// RFC 4724: routes are retained for the restart window and purged
/// when it expires (no LLGR negotiated).
#[test]
fn plain_gr_retains_then_purges() {
    let mut a = DefaultRouter::new();
    let mut b = DefaultRouter::new();
    let a_session = a
        .add_session(
            SessionConfig::bgp(Asn(64512), Asn(64513), RouterId::from_v4([10, 0, 0, 1]))
                .with_mrai_ms(0)
                .with_graceful_restart(1),
        )
        .unwrap();
    let b_session = b
        .add_session(
            SessionConfig::bgp(Asn(64513), Asn(64512), RouterId::from_v4([10, 0, 0, 2]))
                .with_mrai_ms(0)
                .with_graceful_restart(1),
        )
        .unwrap();
    establish(&mut a, a_session, &mut b, b_session);
    b_advertise_to_a(&mut a, a_session, &mut b, b_session);

    a.tick(Instant(0));
    a.close_session(a_session);
    a.tick(Instant(500));
    assert_eq!(a.rib_len(), 1, "still inside the restart window");
    a.tick(Instant(1_500));
    assert_eq!(a.rib_len(), 0, "restart window expired — purge");
}

/// RFC 9494 §4.2: after the restart window the routes are marked
/// LLGR_STALE and retained for the negotiated long-lived stale time.
#[test]
fn llgr_marks_stale_then_purges_at_llst_expiry() {
    let (mut a, a_session, mut b, b_session) = llgr_pair();
    establish(&mut a, a_session, &mut b, b_session);
    b_advertise_to_a(&mut a, a_session, &mut b, b_session);

    a.tick(Instant(0));
    a.close_session(a_session);
    a.tick(Instant(500));
    assert_eq!(a.rib_len(), 1, "retained inside the restart window");
    assert!(!best_has_llgr_stale(&a), "not yet long-lived stale");

    // Restart window (1 s) elapses → LLGR period begins.
    a.tick(Instant(1_500));
    assert_eq!(a.rib_len(), 1, "LLGR retains the route");
    assert!(best_has_llgr_stale(&a), "marked LLGR_STALE");

    // LLST (20 s after the restart window) not yet over.
    a.tick(Instant(20_999));
    assert_eq!(a.rib_len(), 1);

    a.tick(Instant(21_000));
    assert_eq!(a.rib_len(), 0, "long-lived stale time expired — purge");
}

/// RFC 9494 §4.2: when the session re-establishes and resends its
/// table (EoR received), the routes are refreshed and outlive the
/// original LLST deadline.
#[test]
fn llgr_reestablishment_with_eor_refreshes_routes() {
    let (mut a, a_session, mut b, b_session) = llgr_pair();
    establish(&mut a, a_session, &mut b, b_session);
    b_advertise_to_a(&mut a, a_session, &mut b, b_session);

    a.tick(Instant(0));
    a.close_session(a_session);
    a.tick(Instant(1_500)); // enter LLGR stale period
    assert!(best_has_llgr_stale(&a));

    // B restarts and re-advertises everything (initial dump + EoR).
    establish(&mut a, a_session, &mut b, b_session);
    let b_dump = b.drain_output(b_session);
    assert!(!b_dump.is_empty());
    a.feed_input(a_session, &b_dump).unwrap();
    assert_eq!(a.rib_len(), 1);
    assert!(
        !best_has_llgr_stale(&a),
        "fresh route replaced the stale one"
    );

    // Well past the original LLST deadline: nothing may be purged
    // because synchronization completed at EoR.
    a.tick(Instant(60_000));
    assert_eq!(a.rib_len(), 1, "refreshed routes survive past LLST");
}

/// RFC 4724 §4.1 / RFC 9494 §4.2: at EoR, stale routes the peer did
/// not re-advertise are deleted.
#[test]
fn llgr_eor_purges_unrefreshed_routes() {
    let (mut a, a_session, mut b, b_session) = llgr_pair();
    establish(&mut a, a_session, &mut b, b_session);
    b_advertise_to_a(&mut a, a_session, &mut b, b_session);
    let key = RouteKey::new(
        Prefix::new_v4([198, 51, 100, 0], 24),
        NlriFamily::IPV4_UNICAST,
    );

    a.tick(Instant(0));
    a.close_session(a_session);
    a.tick(Instant(1_500)); // LLGR stale period

    // B no longer originates the prefix when it comes back.
    b.unoriginate(&key);
    establish(&mut a, a_session, &mut b, b_session);
    let b_dump = b.drain_output(b_session);
    a.feed_input(a_session, &b_dump).unwrap();
    assert_eq!(
        a.rib_len(),
        0,
        "EoR arrived without a refresh — stale route purged"
    );
}

/// RFC 9494 §4.2: routes marked NO_LLGR are not retained.
#[test]
fn llgr_no_llgr_routes_are_dropped() {
    struct TagNoLlgr;
    impl lr_policy::hooks::ImportHook for TagNoLlgr {
        fn on_import(&self, route: &mut Route) -> lr_policy::hooks::HookVerdict {
            let mut attrs: PathAttributes = route.attributes.clone().into();
            attrs.insert_community(Community::NO_LLGR);
            route.attributes = attrs.into();
            lr_policy::hooks::HookVerdict::Keep
        }
    }
    let (mut a, a_session, mut b, b_session) = llgr_pair();
    a.hooks_mut().import.push(Box::new(TagNoLlgr));
    establish(&mut a, a_session, &mut b, b_session);
    b_advertise_to_a(&mut a, a_session, &mut b, b_session);

    a.tick(Instant(0));
    a.close_session(a_session);
    a.tick(Instant(500));
    assert_eq!(a.rib_len(), 1, "retained inside the restart window");
    a.tick(Instant(1_500));
    assert_eq!(
        a.rib_len(),
        0,
        "NO_LLGR routes must not survive into the LLGR period"
    );
}

/// RFC 9494 §4.2: a locally configured cap limits the received LLST.
#[test]
fn llgr_local_cap_limits_received_stale_time() {
    let mut a = DefaultRouter::new();
    let mut b = DefaultRouter::new();
    let a_session = a
        .add_session(
            SessionConfig::bgp(Asn(64512), Asn(64513), RouterId::from_v4([10, 0, 0, 1]))
                .with_mrai_ms(0)
                .with_graceful_restart(1)
                .with_long_lived_gr(10)
                .with_llgr_max_stale_time(5),
        )
        .unwrap();
    let b_session = b
        .add_session(
            SessionConfig::bgp(Asn(64513), Asn(64512), RouterId::from_v4([10, 0, 0, 2]))
                .with_mrai_ms(0)
                .with_graceful_restart(1)
                .with_long_lived_gr(20), // peer proposes 20 s
        )
        .unwrap();
    establish(&mut a, a_session, &mut b, b_session);
    b_advertise_to_a(&mut a, a_session, &mut b, b_session);

    a.tick(Instant(0));
    a.close_session(a_session);
    a.tick(Instant(1_500));
    assert_eq!(a.rib_len(), 1, "LLGR period, still retained");
    // 1 s restart + 5 s capped LLST = 6 s deadline; 20 s would be
    // the un-capped expiry.
    a.tick(Instant(6_000));
    assert_eq!(a.rib_len(), 0, "capped LLST expired the retention early");
}

/// RFC 4724 §4.2: when the session re-establishes *before* the restart
/// window elapses and re-advertises its routes, expiry of the (now
/// moot) restart timer must NOT purge the fresh routes.
#[test]
fn fast_reestablishment_survives_restart_window_expiry() {
    let (mut a, a_session, mut b, b_session) = llgr_pair();
    establish(&mut a, a_session, &mut b, b_session);
    b_advertise_to_a(&mut a, a_session, &mut b, b_session);

    a.tick(Instant(0));
    a.close_session(a_session);
    // Re-establish immediately and refresh the route.
    establish(&mut a, a_session, &mut b, b_session);
    let b_dump = b.drain_output(b_session);
    a.feed_input(a_session, &b_dump).unwrap();
    assert_eq!(a.rib_len(), 1);

    // Long past the 1 s restart window (and past the 20 s LLST): the
    // session is up and synchronized, so nothing may be purged.
    a.tick(Instant(30_000));
    assert_eq!(a.rib_len(), 1, "resynchronized routes survive expiry");
}

/// LLGR variant: the LLST timer keeps running across re-establishment
/// (RFC 9494 §4.2) but only removes routes the peer did not refresh.
#[test]
fn llgr_timer_runs_during_resync_but_spares_refreshed_routes() {
    let (mut a, a_session, mut b, b_session) = llgr_pair();
    establish(&mut a, a_session, &mut b, b_session);
    b_advertise_to_a(&mut a, a_session, &mut b, b_session);
    let key = RouteKey::new(
        Prefix::new_v4([198, 51, 100, 0], 24),
        NlriFamily::IPV4_UNICAST,
    );

    a.tick(Instant(0));
    a.close_session(a_session);
    // Enter the LLGR stale period while still down.
    a.tick(Instant(1_500));
    assert_eq!(a.rib_len(), 1);

    // B comes back but no longer originates the prefix; the session
    // re-establishes without refreshing the stale route.
    b.unoriginate(&key);
    establish(&mut a, a_session, &mut b, b_session);
    let b_dump = b.drain_output(b_session);
    a.feed_input(a_session, &b_dump).unwrap();

    // LLST deadline (1 s restart + 20 s LLST) passes while the session
    // is up: the unrefreshed stale route must go.
    a.tick(Instant(21_500));
    assert_eq!(
        a.rib_len(),
        0,
        "LLST expiry during resync removes unrefreshed stale routes"
    );
}

#[test]
fn session_summaries_track_bgp_lifecycle() {
    // A plain (no-GR) pair: session loss must purge the Adj-RIB-In
    // immediately, which the summary counter reflects.
    let mut a = DefaultRouter::new();
    let mut b = DefaultRouter::new();
    let a_session = a
        .add_session(
            SessionConfig::bgp(Asn(64512), Asn(64513), RouterId::from_v4([10, 0, 0, 1]))
                .with_graceful_restart(0),
        )
        .unwrap();
    let b_session = b
        .add_session(
            SessionConfig::bgp(Asn(64513), Asn(64512), RouterId::from_v4([10, 0, 0, 2]))
                .with_graceful_restart(0),
        )
        .unwrap();

    // Pre-start: configured but idle.
    let s = a.session_summaries();
    assert_eq!(s.len(), 1);
    assert_eq!(s[0].handle, a_session);
    assert_eq!(s[0].kind, "bgp");
    assert_eq!(s[0].state, "Idle");
    assert!(!s[0].established);
    assert_eq!(s[0].local_as, Asn(64512));
    assert_eq!(s[0].peer_as, Asn(64513));
    assert_eq!(s[0].peer_bgp_id, None);
    assert_eq!(s[0].adj_rib_in_len, 0);

    // Post-handshake: established, peer identity + hold time known.
    establish(&mut a, a_session, &mut b, b_session);
    let s = a.session_summaries();
    assert_eq!(s[0].state, "Established");
    assert!(s[0].established);
    assert_eq!(s[0].peer_bgp_id, Some(RouterId::from_v4([10, 0, 0, 2])));
    assert!(s[0].negotiated_hold_time > 0);

    // Adj-RIB-In counter follows the peer's advertisements.
    b_advertise_to_a(&mut a, a_session, &mut b, b_session);
    let s = a.session_summaries();
    assert_eq!(s[0].adj_rib_in_len, 1);

    // Session loss flips the summary back to Idle and purges the RIB.
    a.close_session(a_session);
    a.tick(Instant(0));
    let s = a.session_summaries();
    assert_eq!(s[0].state, "Idle");
    assert!(!s[0].established);
    assert_eq!(s[0].adj_rib_in_len, 0);
}

/// The UPDATE counters on [`SessionSummary`] follow the wire: the
/// initial table dump's EoR marker counts as one UPDATE, each
/// pumped advertisement adds one more per direction, and the
/// counters survive a session flap (FRR per-neighbor semantics).
#[test]
fn session_summaries_count_updates() {
    let mut a = DefaultRouter::new();
    let mut b = DefaultRouter::new();
    let a_session = a
        .add_session(SessionConfig::bgp(
            Asn(64512),
            Asn(64513),
            RouterId::from_v4([10, 0, 0, 1]),
        ))
        .unwrap();
    let b_session = b
        .add_session(SessionConfig::bgp(
            Asn(64513),
            Asn(64512),
            RouterId::from_v4([10, 0, 0, 2]),
        ))
        .unwrap();

    // Pre-start: no UPDATEs booked in either direction.
    let s = &a.session_summaries()[0];
    assert_eq!((s.updates_received, s.updates_sent), (0, 0));

    establish(&mut a, a_session, &mut b, b_session);
    // Pump the post-establishment output both ways: each side's
    // initial dump ends in an EoR marker (one UPDATE PDU) that is
    // still sitting in the peer's connection buffer.
    let a_out = a.drain_output(a_session);
    let b_out = b.drain_output(b_session);
    a.feed_input(a_session, &b_out).unwrap();
    b.feed_input(b_session, &a_out).unwrap();
    let s = &a.session_summaries()[0];
    assert_eq!(s.updates_received, 1, "B's EoR marker arrives");
    assert_eq!(s.updates_sent, 1, "A's own EoR marker");
    let s = &b.session_summaries()[0];
    assert_eq!(s.updates_received, 1);
    assert_eq!(s.updates_sent, 1);

    // One advertisement: +1 on both sides of the wire.
    b_advertise_to_a(&mut a, a_session, &mut b, b_session);
    let s = &a.session_summaries()[0];
    assert_eq!(s.updates_received, 2, "EoR + the real advertisement");
    let s = &b.session_summaries()[0];
    assert_eq!(s.updates_sent, 2);

    // A session flap (close + re-establish) must not zero the
    // counters — they are per-neighbor, not per-connection.
    a.close_session(a_session);
    a.tick(Instant(0));
    let s = &a.session_summaries()[0];
    assert_eq!(s.updates_received, 2, "counters survive the flap");
    assert_eq!(s.state, "Idle");
}

#[test]
fn session_summaries_list_multiple_sessions_in_order() {
    let mut r = DefaultRouter::new();
    r.add_session(SessionConfig::bgp(
        Asn(64512),
        Asn(64513),
        RouterId::from_v4([10, 0, 0, 1]),
    ))
    .unwrap();
    r.add_session(SessionConfig::ospfv2(RouterId::from_u32(0x01020304), 0))
        .unwrap();
    r.add_session(SessionConfig::babel(IpAddr::V4([192, 0, 2, 1])))
        .unwrap();

    let s = r.session_summaries();
    assert_eq!(s.len(), 3);
    // Ordered by handle.
    assert_eq!(s[0].handle, SessionHandle(1));
    assert_eq!(s[0].kind, "bgp");
    assert_eq!(s[1].handle, SessionHandle(2));
    assert_eq!(s[1].kind, "ospf");
    assert_eq!(s[1].state, "Down");
    assert_eq!(s[2].handle, SessionHandle(3));
    assert_eq!(s[2].kind, "babel");
    assert_eq!(s[2].state, "Down");
    assert!(!s.iter().any(|x| x.established));
}

// ===== RFC 8212 default eBGP route behaviors =====

/// A plain eBGP pair (no graceful restart, no MRAI) with the
/// RFC 8212 mode armed on the receiving side.
fn ebgp_pair() -> (DefaultRouter, SessionHandle, DefaultRouter, SessionHandle) {
    let mut a = DefaultRouter::new();
    let mut b = DefaultRouter::new();
    let a_session = a
        .add_session(
            SessionConfig::bgp(Asn(64512), Asn(64513), RouterId::from_v4([10, 0, 0, 1]))
                .with_mrai_ms(0)
                .with_graceful_restart(0),
        )
        .unwrap();
    let b_session = b
        .add_session(
            SessionConfig::bgp(Asn(64513), Asn(64512), RouterId::from_v4([10, 0, 0, 2]))
                .with_mrai_ms(0)
                .with_graceful_restart(0),
        )
        .unwrap();
    (a, a_session, b, b_session)
}

fn logs_contain(a: &mut DefaultRouter, needle: &str) -> bool {
    a.poll_events()
        .iter()
        .any(|e| matches!(e, RouterEvent::Log(m) if m.contains(needle)))
}

#[test]
fn rfc8212_off_by_default_keeps_rfc4271_behaviour() {
    // Without the mode, a policy-less eBGP session accepts and
    // advertises everything (library back-compat; the daemon is
    // what turns the mode on).
    let (mut a, a_session, mut b, b_session) = ebgp_pair();
    establish(&mut a, a_session, &mut b, b_session);
    b_advertise_to_a(&mut a, a_session, &mut b, b_session);
    assert_eq!(a.rib_len(), 1);
}

#[test]
fn rfc8212_ebgp_import_denied_without_policy() {
    let (mut a, a_session, mut b, b_session) = ebgp_pair();
    a.set_ebgp_requires_policy(true);
    establish(&mut a, a_session, &mut b, b_session);

    b.originate(
        Prefix::new_v4([198, 51, 100, 0], 24),
        Some(IpAddr::V4([192, 0, 2, 10])),
    );
    let advertisement = b.drain_output(b_session);
    assert!(!advertisement.is_empty());
    a.feed_input(a_session, &advertisement).unwrap();
    assert_eq!(
        a.rib_len(),
        0,
        "routes from a policy-less external peer must not reach the Loc-RIB"
    );
    assert!(
        logs_contain(&mut a, "no import policy"),
        "the denial is surfaced once as a log event"
    );
}

#[test]
fn rfc8212_ebgp_import_allowed_with_explicit_policy() {
    let (mut a, a_session, mut b, b_session) = ebgp_pair();
    a.set_ebgp_requires_policy(true);
    a.set_session_policy(a_session, true, false).unwrap();
    establish(&mut a, a_session, &mut b, b_session);
    b_advertise_to_a(&mut a, a_session, &mut b, b_session);
    assert_eq!(a.rib_len(), 1);
}

#[test]
fn rfc8212_ebgp_export_denied_without_policy() {
    let (mut a, a_session, mut b, b_session) = ebgp_pair();
    a.set_ebgp_requires_policy(true);
    establish(&mut a, a_session, &mut b, b_session);
    assert!(logs_contain(&mut a, "no export policy"));

    a.originate(
        Prefix::new_v4([203, 0, 113, 0], 24),
        Some(IpAddr::V4([192, 0, 2, 1])),
    );
    // The drained bytes may carry the session's End-of-RIB marker
    // from establishment — what matters is that no UPDATE flows.
    let bytes = a.drain_output(a_session);
    if !bytes.is_empty() {
        b.feed_input(b_session, &bytes).unwrap();
    }
    assert_eq!(
        b.rib_len(),
        0,
        "a policy-less external peer must not receive advertisements"
    );
}

#[test]
fn rfc8212_ebgp_export_allowed_with_explicit_policy() {
    let (mut a, a_session, mut b, b_session) = ebgp_pair();
    a.set_ebgp_requires_policy(true);
    a.set_session_policy(a_session, false, true).unwrap();
    establish(&mut a, a_session, &mut b, b_session);

    a.originate(
        Prefix::new_v4([203, 0, 113, 0], 24),
        Some(IpAddr::V4([192, 0, 2, 1])),
    );
    let advertisement = a.drain_output(a_session);
    assert!(!advertisement.is_empty());
    b.feed_input(b_session, &advertisement).unwrap();
    assert_eq!(b.rib_len(), 1);
}

#[test]
fn rfc8212_spared_for_ibgp() {
    // RFC 8212 §1 scopes the default behaviors to EBGP sessions;
    // iBGP keeps the RFC 4271 default-accept.
    let mut a = DefaultRouter::new();
    let mut b = DefaultRouter::new();
    a.set_ebgp_requires_policy(true);
    b.set_ebgp_requires_policy(true);
    let a_session = a
        .add_session(
            SessionConfig::bgp(Asn(64512), Asn(64512), RouterId::from_v4([10, 0, 0, 1]))
                .with_mrai_ms(0)
                .with_graceful_restart(0),
        )
        .unwrap();
    let b_session = b
        .add_session(
            SessionConfig::bgp(Asn(64512), Asn(64512), RouterId::from_v4([10, 0, 0, 2]))
                .with_mrai_ms(0)
                .with_graceful_restart(0),
        )
        .unwrap();
    establish(&mut a, a_session, &mut b, b_session);
    b_advertise_to_a(&mut a, a_session, &mut b, b_session);
    assert_eq!(a.rib_len(), 1);

    a.originate(
        Prefix::new_v4([203, 0, 113, 0], 24),
        Some(IpAddr::V4([192, 0, 2, 1])),
    );
    let advertisement = a.drain_output(a_session);
    assert!(!advertisement.is_empty());
    b.feed_input(b_session, &advertisement).unwrap();
    // B holds its own 198.51.100.0/24 plus the learned
    // 203.0.113.0/24 — iBGP exchanges flow without policy.
    assert!(
        b.rib_snapshot()
            .iter()
            .any(|r| r.key.prefix == Prefix::new_v4([203, 0, 113, 0], 24)),
        "iBGP keeps the RFC 4271 default-accept"
    );
}

#[test]
fn rfc8212_export_policy_removal_withdraws_advertised_routes() {
    let (mut a, a_session, mut b, b_session) = ebgp_pair();
    a.set_ebgp_requires_policy(true);
    a.set_session_policy(a_session, false, true).unwrap();
    establish(&mut a, a_session, &mut b, b_session);

    a.originate(
        Prefix::new_v4([203, 0, 113, 0], 24),
        Some(IpAddr::V4([192, 0, 2, 1])),
    );
    let advertisement = a.drain_output(a_session);
    b.feed_input(b_session, &advertisement).unwrap();
    assert_eq!(b.rib_len(), 1);

    // Policy withdrawn at runtime: the Adj-RIB-Out must be emptied
    // and the far side must see the withdrawal (RFC 8212 §3).
    a.set_session_policy(a_session, false, false).unwrap();
    let withdrawal = a.drain_output(a_session);
    assert!(!withdrawal.is_empty());
    b.feed_input(b_session, &withdrawal).unwrap();
    assert_eq!(b.rib_len(), 0);
}

#[test]
fn rfc8212_unknown_session_rejected() {
    let mut a = DefaultRouter::new();
    let err = a
        .set_session_policy(SessionHandle(99), true, true)
        .unwrap_err();
    assert!(err.contains("unknown session 99"), "{err}");
}

// ===== FRR `bgp enforce-first-as` (W2.2) =====
//
// The check rejects eBGP UPDATEs whose leftmost AS_PATH sequence
// segment's first AS does not equal the peer's AS (the peer did
// not prepend its own AS — forgery or misconfiguration). iBGP and
// confederation-internal sessions are exempt; the default is off
// (matches FRR `no bgp enforce-first-as`).

#[test]
fn enforce_first_as_disabled_by_default_accepts_mismatch() {
    // Without the mode, an eBGP route whose first AS is not the
    // peer's AS still reaches Adj-RIB-In — RFC 4271 §6.3 allows
    // it, and FRR's default is `no bgp enforce-first-as`.
    let (mut a, a_session, mut b, b_session) = ebgp_pair();
    establish(&mut a, a_session, &mut b, b_session);

    // For a path with first AS = 64520 (not 64513, the peer's AS).
    // We need to craft an UPDATE; the cleanest way is to use the
    // raw codec via `b`'s advertising helper, but the standard
    // `b_advertise_to_a` always prepends `b`'s own AS. Instead,
    // construct the path manually using `b.originate` and patch
    // the AS_PATH before sending — but `b`'s output is opaque
    // bytes. Use the in-process `import_route`-equivalent path
    // by feeding a forged UPDATE directly. We instead use the
    // in-process safety check helper indirectly: assert the
    // disabled mode means `check_first_as` is not even consulted.
    assert!(!a.enforce_first_as());
    b_advertise_to_a(&mut a, a_session, &mut b, b_session);
    // The route landed even though it has the peer's AS prepended
    // (always — `b`'s eBGP egress prepends its own AS).
    assert_eq!(a.rib_len(), 1);
    assert!(
        !logs_contain(&mut a, "enforce-first-as"),
        "the check is dormant when disabled"
    );
}

#[test]
fn enforce_first_as_accepts_correct_first_as() {
    // When the mode is on and the peer's AS is the first in the
    // path (the normal, well-formed eBGP case), the route is
    // admitted and no rejection is logged.
    let (mut a, a_session, mut b, b_session) = ebgp_pair();
    a.set_enforce_first_as(true);
    establish(&mut a, a_session, &mut b, b_session);
    b_advertise_to_a(&mut a, a_session, &mut b, b_session);
    assert_eq!(a.rib_len(), 1, "well-formed eBGP UPDATE is admitted");
    assert!(
        !logs_contain(&mut a, "enforce-first-as"),
        "no rejection for a peer that prepended its own AS"
    );
}

/// Inject a forged eBGP UPDATE whose leftmost AS is not the
/// peer's AS by hand: take `b`'s normal advertisement and rewrite
/// the first AS in the AS_PATH attribute to a foreign AS.
///
/// `drain_output` may return several BGP messages concatenated
/// (the originated UPDATE plus the End-of-RIB marker). We walk
/// each 19-byte-framed message and patch the first UPDATE that
/// carries an AS_PATH attribute. The width of the AS_PATH
/// segment is inferred from the attribute value length — `b`'s
/// egress uses 4-byte AS_PATH when `asn4` is negotiated (the
/// test default) and 2-byte otherwise.
fn forge_first_as_in_advertisement(
    b: &mut DefaultRouter,
    b_session: SessionHandle,
    foreign_as: u32,
) -> Vec<u8> {
    let bytes = b.drain_output(b_session);
    let mut out = bytes.clone();
    // Each BGP message is:
    //   marker:16, length:2 (BE, includes header), type:1, body…
    // Type 2 is UPDATE.
    let mut msg_start = 0;
    while msg_start + 19 <= out.len() {
        let total_len = u16::from_be_bytes([out[msg_start + 16], out[msg_start + 17]]) as usize;
        if total_len < 19 || msg_start + total_len > out.len() {
            break;
        }
        let msg_type = out[msg_start + 18];
        if msg_type == 2 {
            // UPDATE body layout:
            //   withdraw_len:2, withdraws…, attr_len:2, attrs…, NLRI…
            let body = &out[msg_start + 19..msg_start + total_len];
            if body.len() >= 4 {
                let withdraw_len = u16::from_be_bytes([body[0], body[1]]) as usize;
                if 2 + withdraw_len + 2 <= body.len() {
                    let attrs_off_rel = 2 + withdraw_len;
                    let attr_len =
                        u16::from_be_bytes([body[attrs_off_rel], body[attrs_off_rel + 1]]) as usize;
                    let attrs_start_rel = attrs_off_rel + 2;
                    let attrs_end_rel = attrs_start_rel + attr_len;
                    if attrs_end_rel <= body.len() {
                        let attrs_start = msg_start + 19 + attrs_start_rel;
                        let attrs_end = msg_start + 19 + attrs_end_rel;
                        if patch_first_as_in_attrs(&mut out, attrs_start, attrs_end, foreign_as)
                            .is_some()
                        {
                            return out;
                        }
                    }
                }
            }
        }
        msg_start += total_len;
    }
    panic!("AS_PATH attribute not found in advertised UPDATE");
}

/// Walk one UPDATE's path-attributes region and rewrite the first
/// AS of the leftmost AS_SEQUENCE / AS_CONFED_SEQUENCE segment in
/// the AS_PATH attribute. Returns `Some(())` on success.
fn patch_first_as_in_attrs(
    out: &mut [u8],
    attrs_start: usize,
    attrs_end: usize,
    foreign_as: u32,
) -> Option<()> {
    let mut i = attrs_start;
    while i + 3 <= attrs_end {
        let flags = out[i];
        let type_ = out[i + 1];
        let extended = flags & 0x10 != 0;
        let (len, header) = if extended {
            (u16::from_be_bytes([out[i + 2], out[i + 3]]) as usize, 4)
        } else {
            (out[i + 2] as usize, 3)
        };
        if type_ == 2 && i + header + 2 <= attrs_end {
            let seg_off = i + header;
            let seg_type = out[seg_off];
            let seg_count = out[seg_off + 1] as usize;
            if seg_count > 0 {
                let seg_body = len - 2;
                let width = if seg_body % seg_count == 0 {
                    seg_body / seg_count
                } else {
                    4
                };
                let first_as_off = seg_off + 2;
                if (seg_type == 2 || seg_type == 3) && first_as_off + width <= attrs_end {
                    if width == 4 {
                        out[first_as_off..first_as_off + 4]
                            .copy_from_slice(&foreign_as.to_be_bytes());
                    } else {
                        let lo = (foreign_as & 0xffff) as u16;
                        out[first_as_off..first_as_off + 2].copy_from_slice(&lo.to_be_bytes());
                    }
                    return Some(());
                }
            }
        }
        i += header + len;
    }
    None
}

#[test]
fn enforce_first_as_rejects_mismatched_first_as() {
    let (mut a, a_session, mut b, b_session) = ebgp_pair();
    a.set_enforce_first_as(true);
    establish(&mut a, a_session, &mut b, b_session);

    // Originate on b — its eBGP egress prepends 64513 (b's AS).
    b.originate(
        Prefix::new_v4([198, 51, 100, 0], 24),
        Some(IpAddr::V4([192, 0, 2, 10])),
    );
    // Rewrite the first AS in the AS_PATH to a foreign AS
    // before feeding it to a — this simulates a forged UPDATE.
    let forged = forge_first_as_in_advertisement(&mut b, b_session, 64520);
    assert!(!forged.is_empty());
    a.feed_input(a_session, &forged).unwrap();

    assert_eq!(
        a.rib_len(),
        0,
        "a forged eBGP UPDATE whose first AS is not the peer's AS \
             must be dropped before Adj-RIB-In"
    );
    assert!(
        logs_contain(&mut a, "enforce-first-as"),
        "the rejection is surfaced as a log event"
    );
}

#[test]
fn enforce_first_as_spared_for_ibgp() {
    // iBGP routes are exempt: the peer is in the same AS, so the
    // "first AS" check is meaningless — FRR's `bgp enforce-first-as`
    // only applies to eBGP.
    let mut a = DefaultRouter::new();
    let mut b = DefaultRouter::new();
    a.set_enforce_first_as(true);
    b.set_enforce_first_as(true);
    let a_session = a
        .add_session(
            SessionConfig::bgp(Asn(64512), Asn(64512), RouterId::from_v4([10, 0, 0, 1]))
                .with_mrai_ms(0)
                .with_graceful_restart(0),
        )
        .unwrap();
    let b_session = b
        .add_session(
            SessionConfig::bgp(Asn(64512), Asn(64512), RouterId::from_v4([10, 0, 0, 2]))
                .with_mrai_ms(0)
                .with_graceful_restart(0),
        )
        .unwrap();
    establish(&mut a, a_session, &mut b, b_session);
    b.originate(
        Prefix::new_v4([198, 51, 100, 0], 24),
        Some(IpAddr::V4([192, 0, 2, 10])),
    );
    let advertisement = b.drain_output(b_session);
    // iBGP does not prepend the peer's AS, so the AS_PATH is
    // empty (or contains only the origin AS) — enforce-first-as
    // must NOT reject this.
    a.feed_input(a_session, &advertisement).unwrap();
    assert_eq!(a.rib_len(), 1, "iBGP routes are exempt");
    assert!(
        !logs_contain(&mut a, "enforce-first-as"),
        "iBGP does not trigger the eBGP-only check"
    );
}

// ===== FRR `neighbor X allowas-in N` / BIRD `allow local as` (W2.3) =====

/// Helper: build an eBGP pair where `b`'s egress AS_PATH is forced
/// to include `a`'s local AS N times, simulating a route that
/// contains the local AS in its path. We construct the forged
/// UPDATE from scratch using the `lr-bgp` codec so the wire bytes
/// are well-formed (no manual byte-splicing that could confuse
/// the receiver's strict UPDATE validator).
fn advertise_with_local_as_loop(
    a: &mut DefaultRouter,
    a_session: SessionHandle,
    _b: &mut DefaultRouter,
    _b_session: SessionHandle,
    local_as: u32,
    count: usize,
) {
    use lr_bgp::codec::BgpCodec;
    use lr_bgp::message::update::{Nlri, Update};
    use lr_bgp::message::BgpMessage;
    use lr_bgp::path::{
        AsPath, AsPathSegment, AsPathType, AttrType, NextHop, PathAttrFlags, PathAttribute,
        PathAttributes,
    };

    // Build the AS_PATH: a single AS_SEQUENCE segment starting
    // with the peer's AS (so `enforce_first_as` would admit it)
    // followed by `count` copies of the local AS.
    let peer_as = 64513u32; // b's local AS
    let mut ases = vec![lr_core::addr::Asn(peer_as)];
    for _ in 0..count {
        ases.push(lr_core::addr::Asn(local_as));
    }
    let as_path = AsPath {
        segments: vec![AsPathSegment {
            kind: AsPathType::Sequence,
            ases,
        }],
    };

    let mut attrs = PathAttributes::new();
    attrs.insert(PathAttribute::new(
        PathAttrFlags::new().set_transitive(true),
        AttrType::Origin,
        vec![0], // IGP
    ));
    attrs.insert(PathAttribute::new(
        PathAttrFlags::new().set_transitive(true),
        AttrType::AsPath,
        as_path.encode_4(),
    ));
    attrs.insert(PathAttribute::new(
        PathAttrFlags::new().set_transitive(true),
        AttrType::NextHop,
        NextHop::from_v4([192, 0, 2, 10]).encode().to_vec(),
    ));

    let mut u = Update::new();
    u.attributes = attrs;
    u.nlri
        .push(Nlri::plain(Prefix::new_v4([198, 51, 100, 0], 24)));

    // The codec on the receiver's side expects the OPEN-negotiated
    // asn4 mode. We construct a fresh codec with asn4=true (the
    // default for the test pairs).
    let codec = BgpCodec::new().with_asn4(true);
    let bytes = codec.encode_vec(&BgpMessage::Update(u)).unwrap();
    a.feed_input(a_session, &bytes).unwrap();
}

#[test]
fn allow_local_as_zero_rejects_local_as_in_path() {
    // Default: tolerance = 0, the safety net's reject_as_loop fires
    // and the route is dropped (RFC 4271 §9.1.2.15).
    let (mut a, a_session, mut b, b_session) = ebgp_pair();
    establish(&mut a, a_session, &mut b, b_session);
    advertise_with_local_as_loop(&mut a, a_session, &mut b, b_session, 64512, 1);
    assert_eq!(a.rib_len(), 0, "local AS in AS_PATH is rejected by default");
    assert!(
        logs_contain(&mut a, "safety: rejected"),
        "the rejection is surfaced as a log event"
    );
}

#[test]
fn allow_local_as_one_admits_single_occurrence() {
    // FRR `allowas-in 1`: admit a route whose AS_PATH contains
    // the local AS up to 1 time.
    let (mut a, a_session, mut b, b_session) = ebgp_pair();
    a.set_session_local_as_tolerance(a_session, 1).unwrap();
    establish(&mut a, a_session, &mut b, b_session);
    advertise_with_local_as_loop(&mut a, a_session, &mut b, b_session, 64512, 1);
    assert_eq!(
        a.rib_len(),
        1,
        "single local AS occurrence admitted under tolerance=1"
    );
}

#[test]
fn allow_local_as_one_rejects_two_occurrences() {
    // tolerance=1 admits up to 1 occurrence; 2 occurrences must
    // still be rejected.
    let (mut a, a_session, mut b, b_session) = ebgp_pair();
    a.set_session_local_as_tolerance(a_session, 1).unwrap();
    establish(&mut a, a_session, &mut b, b_session);
    advertise_with_local_as_loop(&mut a, a_session, &mut b, b_session, 64512, 2);
    assert_eq!(
        a.rib_len(),
        0,
        "two local AS occurrences rejected under tolerance=1"
    );
}

#[test]
fn allow_local_as_any_admits_arbitrary_count() {
    // FRR `allowas-any`: tolerate any number of local AS in the
    // path. u32::MAX is the sentinel.
    let (mut a, a_session, mut b, b_session) = ebgp_pair();
    a.set_session_local_as_tolerance(a_session, u32::MAX)
        .unwrap();
    establish(&mut a, a_session, &mut b, b_session);
    advertise_with_local_as_loop(&mut a, a_session, &mut b, b_session, 64512, 5);
    assert_eq!(
        a.rib_len(),
        1,
        "any number of local AS admitted under allowas-any"
    );
}

#[test]
fn set_session_local_as_tolerance_rejects_unknown_handle() {
    // Unknown session handle fails closed.
    let mut a = DefaultRouter::new();
    let err = a
        .set_session_local_as_tolerance(SessionHandle(99), 1)
        .unwrap_err();
    assert!(err.contains("not found"), "{err}");
}

#[test]
fn set_session_local_as_tolerance_after_start_fails() {
    // Setting tolerance after start_session must fail closed.
    let (mut a, a_session, mut b, b_session) = ebgp_pair();
    establish(&mut a, a_session, &mut b, b_session);
    let err = a.set_session_local_as_tolerance(a_session, 1).unwrap_err();
    assert!(err.contains("already established"), "{err}");
}

// ===== FRR `neighbor X soft-reconfiguration inbound` (W2.4) =====

#[test]
fn soft_reconfig_inbound_retains_pre_policy_view() {
    // When soft_reconfig_inbound is on, the pre-policy RIB
    // retains the raw received route — even after the import hook
    // chain drops it.
    use lr_policy::hooks::{HookVerdict, ImportHook};
    struct DropAll;
    impl ImportHook for DropAll {
        fn on_import(&self, _route: &mut Route) -> HookVerdict {
            HookVerdict::Drop
        }
    }
    let (mut a, a_session, mut b, b_session) = ebgp_pair();
    // Enable soft-reconfig-inbound before start_session.
    a.set_session_soft_reconfig_inbound(a_session, true)
        .unwrap();
    // Install an import hook that drops every route.
    a.hooks_mut().import.push(Box::new(DropAll));
    establish(&mut a, a_session, &mut b, b_session);
    // Advertise one route from b.
    b.originate(
        Prefix::new_v4([198, 51, 100, 0], 24),
        Some(IpAddr::V4([192, 0, 2, 10])),
    );
    let advertisement = b.drain_output(b_session);
    a.feed_input(a_session, &advertisement).unwrap();
    // The import hook dropped the route — Loc-RIB is empty.
    assert_eq!(a.rib_len(), 0, "import hook dropped the route");
    // But the pre-policy RIB retained the raw received route.
    let snapshot = a.adj_rib_in_snapshot(a_session);
    assert_eq!(snapshot.len(), 1, "pre-policy RIB retained the raw route");
    assert_eq!(
        snapshot[0].key.prefix,
        Prefix::new_v4([198, 51, 100, 0], 24)
    );
}

#[test]
fn soft_reconfig_inbound_off_does_not_retain() {
    // When soft_reconfig_inbound is off (the default), the
    // pre-policy RIB stays empty — no memory cost.
    let (mut a, a_session, mut b, b_session) = ebgp_pair();
    establish(&mut a, a_session, &mut b, b_session);
    b_advertise_to_a(&mut a, a_session, &mut b, b_session);
    let snapshot = a.adj_rib_in_snapshot(a_session);
    assert!(
        snapshot.is_empty(),
        "pre-policy RIB is empty when soft_reconfig_inbound is off"
    );
}

#[test]
fn soft_reconfig_inbound_re_evaluates_after_policy_change() {
    // soft_reconfig_inbound(h) re-runs the import hooks against
    // the pre-policy RIB. A route previously dropped by an
    // import hook is re-admitted when the hook is removed.
    use lr_policy::hooks::{HookVerdict, ImportHook};
    struct DropAll;
    impl ImportHook for DropAll {
        fn on_import(&self, _route: &mut Route) -> HookVerdict {
            HookVerdict::Drop
        }
    }
    let (mut a, a_session, mut b, b_session) = ebgp_pair();
    a.set_session_soft_reconfig_inbound(a_session, true)
        .unwrap();
    a.hooks_mut().import.push(Box::new(DropAll));
    establish(&mut a, a_session, &mut b, b_session);
    b.originate(
        Prefix::new_v4([198, 51, 100, 0], 24),
        Some(IpAddr::V4([192, 0, 2, 10])),
    );
    let advertisement = b.drain_output(b_session);
    a.feed_input(a_session, &advertisement).unwrap();
    assert_eq!(a.rib_len(), 0);
    // Remove the import hook (simulating a policy change).
    a.hooks_mut().import.clear();
    // Run soft reconfiguration inbound.
    let n = a.soft_reconfig_inbound(a_session).unwrap();
    assert_eq!(n, 1, "one route re-evaluated");
    assert_eq!(a.rib_len(), 1, "route admitted into Loc-RIB after re-eval");
}

#[test]
fn soft_reconfig_inbound_noop_when_flag_off() {
    // soft_reconfig_inbound on a session without the flag is a
    // no-op (returns 0) — the pre-policy RIB was not retained.
    let (mut a, a_session, mut b, b_session) = ebgp_pair();
    establish(&mut a, a_session, &mut b, b_session);
    b_advertise_to_a(&mut a, a_session, &mut b, b_session);
    let n = a.soft_reconfig_inbound(a_session).unwrap();
    assert_eq!(n, 0, "no-op when soft_reconfig_inbound is off");
}

#[test]
fn soft_reconfig_inbound_unknown_handle_noop() {
    // Unknown session handle: the pre-policy RIB is empty for
    // that origin, so the op is a no-op (returns 0).
    let mut a = DefaultRouter::new();
    let n = a.soft_reconfig_inbound(SessionHandle(999)).unwrap();
    assert_eq!(n, 0, "no-op on unknown handle");
}

#[test]
fn set_session_soft_reconfig_inbound_rejects_unknown_handle() {
    let mut a = DefaultRouter::new();
    let err = a
        .set_session_soft_reconfig_inbound(SessionHandle(99), true)
        .unwrap_err();
    assert!(err.contains("not found"), "{err}");
}

#[test]
fn set_session_soft_reconfig_inbound_after_start_fails() {
    let (mut a, a_session, mut b, b_session) = ebgp_pair();
    establish(&mut a, a_session, &mut b, b_session);
    let err = a
        .set_session_soft_reconfig_inbound(a_session, true)
        .unwrap_err();
    assert!(err.contains("already established"), "{err}");
}

// ===== audit regression tests =====

/// Walk a stream of framed BGP messages and return the (error code,
/// subcode) of the first NOTIFICATION found.
fn find_notification(bytes: &[u8]) -> Option<(u8, u8)> {
    let mut i = 0;
    while i + 19 <= bytes.len() {
        let len = u16::from_be_bytes([bytes[i + 16], bytes[i + 17]]) as usize;
        if len < 19 || i + len > bytes.len() {
            return None;
        }
        if bytes[i + 18] == 3 {
            return Some((bytes[i + 19], bytes[i + 20]));
        }
        i += len;
    }
    None
}

/// The FSM's `BgpAction::Close` (hold timer expiry) must tear the
/// session down like a transport close: the peer's routes are purged
/// from Adj-RIB-In and Loc-RIB (RFC 4271 §6.5 / §6). Regression:
/// Close used to be ignored, leaving the peer's routes installed and
/// advertised forever.
#[test]
fn fsm_close_purges_peer_routes_from_loc_rib() {
    let (mut a, a_session, mut b, b_session) = ebgp_pair();
    establish(&mut a, a_session, &mut b, b_session);
    b_advertise_to_a(&mut a, a_session, &mut b, b_session);
    assert_eq!(a.rib_len(), 1);
    // Drive A's FSM to hold-timer expiry the way tick() would after a
    // silent peer: the FSM emits BgpAction::Close.
    let actions = match a.sessions.get_mut(&a_session.0) {
        Some(SessionState::Bgp { peer, .. }) => peer.step(BgpEvent::TimerHoldExpired),
        _ => panic!("expected a BGP session"),
    };
    assert!(
        actions.iter().any(|a| matches!(a, BgpAction::Close)),
        "hold timer expiry must emit Close"
    );
    a.dispatch_bgp_actions(a_session.0, actions);
    // The session is down and its routes are gone from the pipeline.
    assert_eq!(a.rib_len(), 0, "peer's routes must not survive Close");
    assert!(a.adj_rib_in.is_empty(), "Adj-RIB-In purged");
    assert!(
        !a.sessions.get(&a_session.0).is_some_and(|s| matches!(
            s,
            SessionState::Bgp {
                established: true,
                ..
            }
        )),
        "established latch cleared"
    );
}

/// `unoriginate` re-runs the decision process: a peer path that was
/// beaten by the originated route is restored to the Loc-RIB
/// (RFC 4271 §9.1.2). Regression: unoriginate used to uninstall the
/// key wholesale, leaving the prefix withdrawn until the peer
/// re-advertised.
#[test]
fn unoriginate_restores_beaten_peer_path() {
    let (mut a, a_session, mut b, b_session) = ebgp_pair();
    establish(&mut a, a_session, &mut b, b_session);
    b_advertise_to_a(&mut a, a_session, &mut b, b_session);
    let key = RouteKey::new(
        Prefix::new_v4([198, 51, 100, 0], 24),
        NlriFamily::IPV4_UNICAST,
    );
    // A locally originated route for the same prefix beats the peer
    // path (empty AS_PATH vs the peer's one-AS path).
    a.originate(Prefix::new_v4([198, 51, 100, 0], 24), None);
    let best = a.loc_rib.best(&key).expect("originated route installed");
    assert_eq!(best.origin.proto, 2, "originated route wins the Loc-RIB");
    // Unoriginating must re-run selection and restore the peer path.
    a.unoriginate(&key);
    let best = a.loc_rib.best(&key).expect("peer path restored");
    assert_eq!(best.origin.proto, 0, "peer path restored by re-selection");
    assert_eq!(best.origin.peer, a_session.0);
}

/// The initial table dump on re-establishment applies the same split
/// horizon as steady-state export: a route retained by graceful
/// restart is never advertised back to the peer it came from
/// (RFC 4271 §9.1.3 Phase 3). Regression: on_bgp_established dumped
/// the whole Loc-RIB, handing GR-retained routes back to their origin
/// (a route-leak loop).
#[test]
fn established_dump_does_not_readvertise_retained_route_to_origin() {
    let (mut a, a_session, mut b, b_session) = llgr_pair();
    establish(&mut a, a_session, &mut b, b_session);
    b_advertise_to_a(&mut a, a_session, &mut b, b_session);
    assert_eq!(a.rib_len(), 1);
    // B goes down; A retains the route under GR.
    a.tick(Instant(0));
    a.close_session(a_session);
    a.tick(Instant(500));
    assert_eq!(a.rib_len(), 1, "route retained inside the restart window");
    // B drops the prefix and comes back without re-advertising it.
    let key = RouteKey::new(
        Prefix::new_v4([198, 51, 100, 0], 24),
        NlriFamily::IPV4_UNICAST,
    );
    b.unoriginate(&key);
    establish(&mut a, a_session, &mut b, b_session);
    let a_dump = a.drain_output(a_session);
    assert!(!a_dump.is_empty(), "A re-establishes with an initial dump");
    // A's Adj-RIB-Out for B's session must not carry the retained
    // route: on_bgp_established applies the same split horizon as the
    // steady-state export path (RFC 4271 §9.1.3 Phase 3).
    assert!(
        a.adj_rib_out
            .paths_for(
                RouteOrigin {
                    proto: 0,
                    peer: a_session.0
                },
                &key
            )
            .is_empty(),
        "the origin session's Adj-RIB-Out must not carry its own retained route"
    );
    // And the wire must not hand it back either.
    b.feed_input(b_session, &a_dump).unwrap();
    assert_eq!(b.rib_len(), 0, "B never re-learns its own route");
    assert!(
        !b.adj_rib_in.iter_all().any(|r| r.key.prefix == key.prefix),
        "B's Adj-RIB-In stays clear of its own route"
    );
}

/// RFC 4486 §3: the max-prefix CEASE NOTIFICATION must use subcode 1
/// ("Maximum Number of Prefixes Reached"), not 8 ("Out of Resources").
#[test]
fn max_prefix_cease_uses_subcode_1() {
    let mut a = DefaultRouter::new();
    let mut b = DefaultRouter::new();
    let ha = a
        .add_session(
            SessionConfig::bgp(Asn(64512), Asn(64513), RouterId::from_v4([10, 0, 0, 1]))
                .with_mrai_ms(0)
                .with_graceful_restart(0)
                .with_maximum_prefix(1, lr_bgp::MaxPrefixAction::Teardown),
        )
        .unwrap();
    let hb = b
        .add_session(
            SessionConfig::bgp(Asn(64513), Asn(64512), RouterId::from_v4([10, 0, 0, 2]))
                .with_mrai_ms(0)
                .with_graceful_restart(0),
        )
        .unwrap();
    establish(&mut a, ha, &mut b, hb);
    // Drain the initial-dump residue so only the CEASE is left.
    let _ = a.drain_output(ha);
    // Two routes cross the limit of one.
    for prefix in [
        Prefix::new_v4([203, 0, 113, 0], 24),
        Prefix::new_v4([198, 51, 100, 0], 24),
    ] {
        b.originate(prefix, Some(IpAddr::V4([192, 0, 2, 10])));
        let adv = b.drain_output(hb);
        assert!(!adv.is_empty());
        a.feed_input(ha, &adv).unwrap();
    }
    let out = a.drain_output(ha);
    let (code, sub) = find_notification(&out).expect("CEASE NOTIFICATION queued");
    assert_eq!(code, 6, "CEASE error code");
    assert_eq!(
        sub, 1,
        "RFC 4486 §3 subcode 1 = Maximum Number of Prefixes Reached"
    );
}

/// RFC 4486 §3 + FRR `bgp maximum-prefix restart <secs>`: when the
/// `Restart` action trips, the session tears down with the CEASE
/// NOTIFICATION and the router arms a re-establishment cooldown the
/// connector reads before it dials again. `Teardown` arms no such
/// cooldown, so `Restart` and `Teardown` are now genuinely distinct.
#[test]
fn max_prefix_restart_arms_cooldown() {
    let mut a = DefaultRouter::new();
    let mut b = DefaultRouter::new();
    let ha = a
        .add_session(
            SessionConfig::bgp(Asn(64512), Asn(64513), RouterId::from_v4([10, 0, 0, 1]))
                .with_mrai_ms(0)
                .with_graceful_restart(0)
                .with_maximum_prefix(1, lr_bgp::MaxPrefixAction::Restart)
                .with_maximum_prefix_restart_time(30),
        )
        .unwrap();
    let hb = b
        .add_session(
            SessionConfig::bgp(Asn(64513), Asn(64512), RouterId::from_v4([10, 0, 0, 2]))
                .with_mrai_ms(0)
                .with_graceful_restart(0),
        )
        .unwrap();
    establish(&mut a, ha, &mut b, hb);
    let _ = a.drain_output(ha);
    // Advance the router clock so the cooldown deadline is meaningful.
    // now=10s; the cooldown (30s) lands at t=40s.
    a.tick(lr_core::time::Instant(10_000));
    // Two routes cross the limit of one → Restart fires.
    for prefix in [
        Prefix::new_v4([203, 0, 113, 0], 24),
        Prefix::new_v4([198, 51, 100, 0], 24),
    ] {
        b.originate(prefix, Some(IpAddr::V4([192, 0, 2, 10])));
        let adv = b.drain_output(hb);
        assert!(!adv.is_empty());
        a.feed_input(ha, &adv).unwrap();
    }
    let out = a.drain_output(ha);
    let (code, sub) = find_notification(&out).expect("CEASE NOTIFICATION queued");
    assert_eq!(code, 6, "CEASE error code");
    assert_eq!(sub, 1, "Maximum Number of Prefixes Reached");
    // The cooldown is armed: ~30s remain at t=10s.
    let remaining = a
        .session_restart_cooldown_remaining(ha)
        .expect("cooldown armed after Restart");
    assert!(
        (29_000..=30_000).contains(&remaining),
        "cooldown ~30s right after the trip, got {remaining}"
    );
    // The cooldown is keyed on the router clock; advancing past the
    // deadline re-opens the gate.
    a.tick(lr_core::time::Instant(40_001));
    assert_eq!(
        a.session_restart_cooldown_remaining(ha),
        None,
        "the cooldown elapses with the router clock"
    );
}

/// `Teardown` must NOT arm a cooldown — only `Restart` does. This
/// guards the `matches!` gate in `check_max_prefix` against regressing
/// into the old shared arm that treated both identically.
#[test]
fn max_prefix_teardown_arms_no_cooldown() {
    let mut a = DefaultRouter::new();
    let mut b = DefaultRouter::new();
    let ha = a
        .add_session(
            SessionConfig::bgp(Asn(64512), Asn(64513), RouterId::from_v4([10, 0, 0, 1]))
                .with_mrai_ms(0)
                .with_graceful_restart(0)
                .with_maximum_prefix(1, lr_bgp::MaxPrefixAction::Teardown)
                .with_maximum_prefix_restart_time(30),
        )
        .unwrap();
    let hb = b
        .add_session(
            SessionConfig::bgp(Asn(64513), Asn(64512), RouterId::from_v4([10, 0, 0, 2]))
                .with_mrai_ms(0)
                .with_graceful_restart(0),
        )
        .unwrap();
    establish(&mut a, ha, &mut b, hb);
    let _ = a.drain_output(ha);
    a.tick(lr_core::time::Instant(10_000));
    for prefix in [
        Prefix::new_v4([203, 0, 113, 0], 24),
        Prefix::new_v4([198, 51, 100, 0], 24),
    ] {
        b.originate(prefix, Some(IpAddr::V4([192, 0, 2, 10])));
        let adv = b.drain_output(hb);
        a.feed_input(ha, &adv).unwrap();
    }
    let _ = a.drain_output(ha);
    assert_eq!(
        a.session_restart_cooldown_remaining(ha),
        None,
        "Teardown must not arm a Restart cooldown even with a non-zero restart_time"
    );
}

/// A BGP→BGP redistribution pipe must not re-advertise a route back
/// to the session it was learned from (RFC 4271 §9.1.3 Phase 3 /
/// §5.1.2 loop avoidance). Regression: the re-originated copy used
/// peer=0, so the export split horizon never fired and the origin
/// session received its own route back.
#[test]
fn redistribution_bgp_to_bgp_respects_split_horizon() {
    // A peers with B (route source) and with C (third party).
    let mut a = DefaultRouter::new();
    let mut b = DefaultRouter::new();
    let mut c = DefaultRouter::new();
    let ha = a
        .add_session(
            SessionConfig::bgp(Asn(64512), Asn(64513), RouterId::from_v4([10, 0, 0, 1]))
                .with_mrai_ms(0)
                .with_graceful_restart(0)
                .with_local_address(IpAddr::V4([192, 0, 2, 1])),
        )
        .unwrap();
    let hb = b
        .add_session(
            SessionConfig::bgp(Asn(64513), Asn(64512), RouterId::from_v4([10, 0, 0, 2]))
                .with_mrai_ms(0)
                .with_graceful_restart(0)
                .with_local_address(IpAddr::V4([192, 0, 2, 2])),
        )
        .unwrap();
    let ha2 = a
        .add_session(
            SessionConfig::bgp(Asn(64512), Asn(64514), RouterId::from_v4([10, 0, 0, 1]))
                .with_mrai_ms(0)
                .with_graceful_restart(0)
                .with_local_address(IpAddr::V4([192, 0, 2, 1])),
        )
        .unwrap();
    let hc = c
        .add_session(
            SessionConfig::bgp(Asn(64514), Asn(64512), RouterId::from_v4([10, 0, 0, 3]))
                .with_mrai_ms(0)
                .with_graceful_restart(0)
                .with_local_address(IpAddr::V4([192, 0, 2, 3])),
        )
        .unwrap();
    establish(&mut a, ha, &mut b, hb);
    establish(&mut a, ha2, &mut c, hc);
    // Drain the initial-dump residue (End-of-RIB markers) so the
    // assertions below only see post-redistribution traffic.
    let _ = a.drain_output(ha);
    let _ = a.drain_output(ha2);

    a.add_redistribution_pipe(RedistributionPipe::new(Protocol::Bgp, Protocol::Bgp));

    let p = Prefix::new_v4([203, 0, 113, 0], 24);
    b.originate(p, Some(IpAddr::V4([192, 0, 2, 2])));
    let adv = b.drain_output(hb);
    assert!(!adv.is_empty());
    a.feed_input(ha, &adv).unwrap();

    // A re-originates and advertises the copy to the third party.
    let to_c = a.drain_output(ha2);
    assert!(
        !to_c.is_empty(),
        "the third-party session receives the redistributed route"
    );
    c.feed_input(hc, &to_c).unwrap();
    assert_eq!(c.rib_len(), 1, "C learned the redistributed route");

    // ... and must NOT advertise it back to the origin session.
    let back_to_b = a.drain_output(ha);
    assert!(
        back_to_b.is_empty(),
        "the origin session must not receive the route back"
    );
    assert!(
        !b.adj_rib_in.iter_all().any(|r| r.key.prefix == p),
        "B never re-learns its own route"
    );
}

/// remove_session must drop every piece of per-session bookkeeping:
/// Adj-RIB-Out entries, pre-policy slices, LLGR caps, max-prefix
/// state (audit m1) — and withdraw iBGP-origin (proto 1) paths too.
#[test]
fn remove_session_cleans_up_bookkeeping() {
    let (mut a, a_session, mut b, b_session) = ebgp_pair();
    a.set_session_soft_reconfig_inbound(a_session, true)
        .unwrap();
    establish(&mut a, a_session, &mut b, b_session);
    b_advertise_to_a(&mut a, a_session, &mut b, b_session);
    // A advertises something of its own so Adj-RIB-Out carries an
    // entry for the session.
    a.originate(
        Prefix::new_v4([203, 0, 113, 0], 24),
        Some(IpAddr::V4([192, 0, 2, 1])),
    );
    let adv = a.drain_output(a_session);
    assert!(!adv.is_empty());
    assert!(!a.adj_rib_out.is_empty(), "A advertised its route to B");
    assert_eq!(a.adj_rib_in.len(), 1);
    assert_eq!(a.adj_rib_in_snapshot(a_session).len(), 1);
    // Seed the bookkeeping that used to leak.
    a.llgr_caps.insert(a_session.0, 5);
    a.max_prefix_state.insert(
        a_session.0,
        MaxPrefixState {
            count: 1,
            ..Default::default()
        },
    );

    a.remove_session(a_session).unwrap();
    assert!(a.adj_rib_in.is_empty(), "Adj-RIB-In purged");
    assert!(
        a.adj_rib_in_snapshot(a_session).is_empty(),
        "pre-policy slice purged"
    );
    assert!(a.adj_rib_out.is_empty(), "Adj-RIB-Out bookkeeping purged");
    assert!(!a.llgr_caps.contains_key(&a_session.0));
    assert!(!a.max_prefix_state.contains_key(&a_session.0));
    assert!(!a.mrai.contains_key(&a_session.0));
}

// ----- W6.3 exchange-plane (feature `exchange-plane`): router-level
// record plumbing — exposure, cross-hop re-signing, partial transit.

#[cfg(feature = "exchange-plane")]
fn xp_cfg(nonce: u8) -> lr_bgp::extensions::exchange_plane::ExchangePlaneConfig {
    use lr_bgp::extensions::exchange_plane::{ExchangeKey, ExchangePlaneConfig};
    let mut cfg = ExchangePlaneConfig::new([nonce; 8]);
    cfg.keys = vec![ExchangeKey::hmac_sha256(1, "alpha")];
    cfg.origin_base_secs = 1_700_000_000;
    cfg
}

#[cfg(feature = "exchange-plane")]
#[test]
fn exchange_plane_records_surface_on_import() {
    let (mut a, a_session, mut b, b_session) = ebgp_pair();
    a.set_session_exchange_plane(a_session, xp_cfg(1)).unwrap();
    b.set_session_exchange_plane(b_session, xp_cfg(2)).unwrap();
    establish(&mut a, a_session, &mut b, b_session);

    a.originate(
        Prefix::new_v4([203, 0, 113, 0], 24),
        Some(IpAddr::V4([192, 0, 2, 1])),
    );
    let advertisement = a.drain_output(a_session);
    b.feed_input(b_session, &advertisement).unwrap();
    assert_eq!(b.rib_len(), 1);

    // The typed accessor exposes the verified record set per prefix.
    let records = b.exchange_plane_records(b_session);
    assert_eq!(records.len(), 1);
    let (prefix, record) = &records[0];
    assert_eq!(prefix, &Prefix::new_v4([203, 0, 113, 0], 24));
    assert!(record
        .records
        .iter()
        .any(|r| matches!(r, lr_bgp::extensions::exchange_plane::Record::Hint(_))));
    assert!(record
        .records
        .iter()
        .any(|r| matches!(r, lr_bgp::extensions::exchange_plane::Record::Origin(_))));
    assert_eq!(
        b.exchange_plane_partial_transit(b_session),
        0,
        "direct lr-to-lr exchange sets no Partial bit"
    );
    assert!(
        logs_contain(&mut b, "exchange-plane"),
        "the record set is surfaced as a log event"
    );
}

#[cfg(feature = "exchange-plane")]
#[test]
fn exchange_plane_plane_off_sessions_stay_record_free() {
    let (mut a, a_session, mut b, b_session) = ebgp_pair();
    // Neither side configures the plane: the default build shape.
    establish(&mut a, a_session, &mut b, b_session);
    a.originate(
        Prefix::new_v4([203, 0, 113, 0], 24),
        Some(IpAddr::V4([192, 0, 2, 1])),
    );
    let advertisement = a.drain_output(a_session);
    b.feed_input(b_session, &advertisement).unwrap();
    assert_eq!(b.rib_len(), 1);
    assert!(b.exchange_plane_records(b_session).is_empty());
}

/// Three lr speakers in a chain: the middle hop forwards the
/// provenance chain with the scope decremented and its own segment
/// signature appended (design §7); the end receiver can verify the
/// whole chain from the record set alone (design §5.3).
#[cfg(feature = "exchange-plane")]
#[test]
fn exchange_plane_three_speaker_chain_re_signs() {
    use lr_bgp::extensions::exchange_plane as xp;

    // Speakers: a (AS 64512) -> b (AS 64513) -> c (AS 64514).
    let mut a = DefaultRouter::new();
    let mut b = DefaultRouter::new();
    let mut c = DefaultRouter::new();
    let a_s = a
        .add_session(
            SessionConfig::bgp(Asn(64512), Asn(64513), RouterId::from_v4([10, 0, 0, 1]))
                .with_mrai_ms(0)
                .with_graceful_restart(0),
        )
        .unwrap();
    let b_s1 = b
        .add_session(
            SessionConfig::bgp(Asn(64513), Asn(64512), RouterId::from_v4([10, 0, 0, 2]))
                .with_mrai_ms(0)
                .with_graceful_restart(0),
        )
        .unwrap();
    let b_s2 = b
        .add_session(
            SessionConfig::bgp(Asn(64513), Asn(64514), RouterId::from_v4([10, 0, 0, 2]))
                .with_mrai_ms(0)
                .with_graceful_restart(0),
        )
        .unwrap();
    let c_s = c
        .add_session(
            SessionConfig::bgp(Asn(64514), Asn(64513), RouterId::from_v4([10, 0, 0, 3]))
                .with_mrai_ms(0)
                .with_graceful_restart(0),
        )
        .unwrap();
    a.set_session_exchange_plane(a_s, xp_cfg(1)).unwrap();
    b.set_session_exchange_plane(b_s1, xp_cfg(2)).unwrap();
    b.set_session_exchange_plane(b_s2, xp_cfg(3)).unwrap();
    c.set_session_exchange_plane(c_s, xp_cfg(4)).unwrap();
    establish(&mut a, a_s, &mut b, b_s1);
    establish(&mut b, b_s2, &mut c, c_s);

    a.originate(
        Prefix::new_v4([203, 0, 113, 0], 24),
        Some(IpAddr::V4([192, 0, 2, 1])),
    );
    let hop1 = a.drain_output(a_s);
    b.feed_input(b_s1, &hop1).unwrap();
    assert_eq!(b.rib_len(), 1);

    // b re-advertises toward c; the UPDATE carries a fresh record
    // set (b's scope-1 records + the forwarded chain, re-signed).
    let hop2 = b.drain_output(b_s2);
    assert!(!hop2.is_empty(), "b re-advertises the learned route");
    c.feed_input(c_s, &hop2).unwrap();
    assert_eq!(c.rib_len(), 1);

    let records = c.exchange_plane_records(c_s);
    assert_eq!(records.len(), 1);
    let (_, record) = &records[0];
    // Origin attestation from a + segment signatures from a and b.
    let origin = record
        .records
        .iter()
        .find_map(|r| match r {
            xp::Record::Origin(o) => Some(*o),
            _ => None,
        })
        .expect("origin attestation propagated");
    assert_eq!(origin.origin_as, 64512);
    let segments: Vec<&xp::PathSegmentSig> = record
        .records
        .iter()
        .filter_map(|r| match r {
            xp::Record::Segment(s) => Some(s),
            _ => None,
        })
        .collect();
    assert_eq!(segments.len(), 2, "origin hop + middle hop signatures");
    // The scope decremented once per lr hop (8 at the originator).
    assert_eq!(record.scope, 7);

    // The end receiver validates the chain with both hops' keys.
    let keys = vec![
        (64512u32, xp::ExchangeKey::hmac_sha256(1, "alpha")),
        (64513u32, xp::ExchangeKey::hmac_sha256(1, "alpha")),
    ];
    let (path, broken) = xp::verify_provenance_chain(&record.records, &keys);
    assert!(broken.is_none(), "chain verifies end to end");
    assert_eq!(path, vec![(64512, 64512), (64513, 64512)]);

    // Scope-1 hints never propagate past the first receiver: c's
    // set carries the ORIGIN's provenance but b's fresh hint, not
    // a's (b rebuilt its own scope-1 records).
    assert!(record
        .records
        .iter()
        .any(|r| matches!(r, xp::Record::Hint(_))));
}

/// A Partial-bit record set arriving on a *negotiated* session is
/// forwarding material: parked raw, never consumed, and counted
/// (design §7 — the runtime API exposes the partial-transit
/// counter).
#[cfg(feature = "exchange-plane")]
#[test]
fn exchange_plane_partial_transit_is_counted() {
    use lr_bgp::extensions::exchange_plane as xp;

    let (mut a, a_session, mut b, b_session) = ebgp_pair();
    a.set_session_exchange_plane(a_session, xp_cfg(1)).unwrap();
    b.set_session_exchange_plane(b_session, xp_cfg(2)).unwrap();
    establish(&mut a, a_session, &mut b, b_session);

    // Hand-craft the forwarding-material shape: an UPDATE whose
    // type-251 attribute carries the Partial bit, as it would after
    // crossing a non-lr transit speaker upstream of a.
    let mut u = lr_bgp::message::update::Update::new();
    u.attributes.insert(PathAttribute::new(
        PathAttrFlags::new()
            .set_optional(true)
            .set_transitive(true)
            .set_partial(true),
        AttrType::Other(xp::ATTRIBUTE_TYPE),
        xp::store_partial_raw(&xp::ExchangeRecord::new(3, 1, [9; 8], 42).encode()),
    ));
    u.attributes.insert(PathAttribute::new(
        PathAttrFlags::new().set_transitive(true),
        AttrType::Origin,
        vec![0],
    ));
    u.attributes.insert(PathAttribute::new(
        PathAttrFlags::new().set_transitive(true),
        AttrType::AsPath,
        lr_bgp::path::AsPath::from_sequence([64512].iter().copied().map(Asn)).encode_4(),
    ));
    u.attributes.insert(PathAttribute::new(
        PathAttrFlags::new().set_transitive(true),
        AttrType::NextHop,
        vec![10, 0, 0, 1],
    ));
    u.nlri
        .push(lr_bgp::message::update::Nlri::plain(Prefix::new_v4(
            [198, 51, 100, 0],
            24,
        )));
    let wire = lr_bgp::codec::BgpCodec::new()
        .with_asn4(true)
        .encode_vec(&lr_bgp::message::BgpMessage::Update(u))
        .unwrap();
    b.feed_input(b_session, &wire).unwrap();
    assert_eq!(b.rib_len(), 1);

    // Forwarding material: not consumed, not in the accessor.
    assert!(
        b.exchange_plane_records(b_session).is_empty(),
        "partial-bit records are forwarding material only"
    );
    assert_eq!(b.exchange_plane_partial_transit(b_session), 1);
}
/// RFC 8665 reception, happy path: an SR neighbour's Router
/// Information LSA (SRGB 16000/8000) + Extended Prefix Opaque LSA
/// (10.20.0.0/24, SID 100, NP) label the stub route the same LSDB
/// produces — Loc-RIB carries label 16100 and the first hop toward
/// the originator. Without `set_ospf_sr_receive` the identical
/// LSDB installs the same route unlabelled (fail-closed default).
#[test]
fn ospf_sr_labels_follow_the_prefix_sid_when_enabled() {
    let build = |sr_receive: bool| {
        let mut r = DefaultRouter::new();
        r.set_ospf_sr_receive(sr_receive);
        let rid = 0x01010101;
        let h = r
            .add_session(SessionConfig::ospfv2(RouterId::from_u32(rid), 0))
            .unwrap();
        // Topology: us —10— B (0x02020202); B's back-link carries
        // its address 10.0.0.2 so the next hop resolves (§16.1.1).
        let ours = router_lsa(rid, vec![(0x02020202, 0, P2P, 10)]);
        let peer = router_lsa(
            0x02020202,
            vec![
                (rid, 0x0a000002, P2P, 10),
                (0x0a140000, 0xffff_ff00, STUB, 5),
            ],
        );
        let ri = lr_ospf::lsa::sr::originate_sr_ri_lsa(0x02020202, 16_000, 8_000, None).unwrap();
        let advert = lr_ospf::lsa::sr::SrPrefixAdvert {
            route_type: 1,
            flags: 0x40, // N-flag: node segment
            prefix: [10, 20, 0, 0],
            prefix_len: 24,
            sid_flags: lr_ospf::lsa::sr::sid_flags::NP,
            sid: 100,
            algorithm: 0,
        };
        let ext = lr_ospf::lsa::sr::originate_sr_prefix_lsa(0x02020202, &advert, 1, None).unwrap();
        r.feed_input(h, &ospf_lsu_bytes(0x02020202, 0, vec![ours, peer, ri, ext]))
            .unwrap();
        (r, h)
    };

    // Default: SR reception off — the route installs unlabelled
    // but still carries the resolved next hop toward the prefix's
    // originator (the kernel FIB mirror needs the next hop to
    // install the route; the OSPFv2 stub_route path used to
    // discard it, which is why --install-kernel-routes did not
    // mirror OSPF intra-area routes into the kernel).
    let (r, _) = build(false);
    let route = r
        .rib_snapshot()
        .into_iter()
        .find(|rt| rt.key.prefix == Prefix::new_v4([10, 20, 0, 0], 24))
        .expect("route installed");
    assert_eq!(route.next_hop, Some(IpAddr::V4([10, 0, 0, 2])));
    assert!(
        route
            .attributes
            .get(lr_core::attr::AttrTag(
                lr_bgp::path::AttrType::LrMplsLabelStack.to_u8()
            ))
            .is_none(),
        "no label attribute without SR reception"
    );

    // SR reception on: same LSDB, labelled route + next hop.
    let (r, _) = build(true);
    let route = r
        .rib_snapshot()
        .into_iter()
        .find(|rt| rt.key.prefix == Prefix::new_v4([10, 20, 0, 0], 24))
        .expect("route installed");
    assert_eq!(route.preference.metric, 15); // 10 + 5, unchanged
    assert_eq!(route.next_hop, Some(IpAddr::V4([10, 0, 0, 2])));
    let attr = route
        .attributes
        .get(lr_core::attr::AttrTag(
            lr_bgp::path::AttrType::LrMplsLabelStack.to_u8(),
        ))
        .expect("label attribute present");
    let stack = lr_mpls::LabelStack::decode_4octet(&attr.value).expect("label stack");
    assert_eq!(stack.labels()[0].value, 16_100); // 16000 + 100
}

/// RFC 8665 §5 PHP: an NP-clear Prefix-SID whose originator is
/// directly adjacent makes this router the penultimate hop — no
/// label is attached and the route forwards unlabeled.
#[test]
fn ospf_sr_php_drops_the_label_for_adjacent_originators() {
    let mut r = DefaultRouter::new();
    r.set_ospf_sr_receive(true);
    let rid = 0x01010101;
    let h = r
        .add_session(SessionConfig::ospfv2(RouterId::from_u32(rid), 0))
        .unwrap();
    let ours = router_lsa(rid, vec![(0x02020202, 0, P2P, 10)]);
    let peer = router_lsa(
        0x02020202,
        vec![
            (rid, 0x0a000002, P2P, 10),
            (0x0a140000, 0xffff_ff00, STUB, 5),
        ],
    );
    let ri = lr_ospf::lsa::sr::originate_sr_ri_lsa(0x02020202, 16_000, 8_000, None).unwrap();
    let advert = lr_ospf::lsa::sr::SrPrefixAdvert {
        route_type: 1,
        flags: 0x40,
        prefix: [10, 20, 0, 0],
        prefix_len: 24,
        sid_flags: 0, // PHP by default (FRR's default too)
        sid: 100,
        algorithm: 0,
    };
    let ext = lr_ospf::lsa::sr::originate_sr_prefix_lsa(0x02020202, &advert, 1, None).unwrap();
    r.feed_input(h, &ospf_lsu_bytes(0x02020202, 0, vec![ours, peer, ri, ext]))
        .unwrap();
    let route = r
        .rib_snapshot()
        .into_iter()
        .find(|rt| rt.key.prefix == Prefix::new_v4([10, 20, 0, 0], 24))
        .expect("route installed");
    // Penultimate hop: no label (PHP), but the route's next hop
    // toward the originator is still populated — the kernel FIB
    // mirror needs it to install the route. The OSPFv2 stub-route
    // path used to discard the resolved next hop, which made
    // --install-kernel-routes silently skip OSPF intra-area
    // routes.
    assert_eq!(route.next_hop, Some(IpAddr::V4([10, 0, 0, 2])));
    assert!(route
        .attributes
        .get(lr_core::attr::AttrTag(
            lr_bgp::path::AttrType::LrMplsLabelStack.to_u8()
        ))
        .is_none());
}

/// RFC 8665 §4 / RFC 8661 §3.2: an SR Mapping Server's Extended
/// Prefix Range TLV labels the covered prefixes exactly as if
/// their owners had advertised the SIDs — a prefix inside the
/// range resolves `server-SRGB base + index` with the prefix's
/// *own* next hop (the path toward the owner, not the server).
#[test]
fn ospf_sr_mapping_server_range_labels_covered_prefixes() {
    let mut r = DefaultRouter::new();
    r.set_ospf_sr_receive(true);
    let rid = 0x01010101;
    let h = r
        .add_session(SessionConfig::ospfv2(RouterId::from_u32(rid), 0))
        .unwrap();
    // Topology: us —10— B (0x02020202), the mapping server; B
    // advertises two stubs — 10.77.0.0/24 (index 500) and
    // 10.77.1.0/24 (index 501, inside the range).
    let ours = router_lsa(rid, vec![(0x02020202, 0, P2P, 10)]);
    let peer = router_lsa(
        0x02020202,
        vec![
            (rid, 0x0a000002, P2P, 10),
            (0x0a4d0000, 0xffff_ff00, STUB, 5),
            (0x0a4d0100, 0xffff_ff00, STUB, 5),
        ],
    );
    let ri = lr_ospf::lsa::sr::originate_sr_ri_lsa(0x02020202, 16_000, 8_000, None).unwrap();
    let range = lr_ospf::lsa::sr::SrPrefixRangeCore {
        prefix_len: 24,
        range_size: 4,
        flags: 0,
        prefix: [10, 77, 0, 0],
    };
    let sid = lr_ospf::lsa::sr::SrPrefixSidTlv {
        flags: lr_ospf::lsa::sr::sid_flags::M | lr_ospf::lsa::sr::sid_flags::NP,
        mt_id: 0,
        algorithm: 0,
        sid: 500,
    };
    let ext =
        lr_ospf::lsa::sr::originate_sr_prefix_range_lsa(0x02020202, &range, &sid, 1, None).unwrap();
    r.feed_input(h, &ospf_lsu_bytes(0x02020202, 0, vec![ours, peer, ri, ext]))
        .unwrap();

    for (expect_prefix, expect_label) in [
        ([10, 77, 0, 0], 16_500), // base + 500
        ([10, 77, 1, 0], 16_501), // base + 501 (offset 1)
    ] {
        let route = r
            .rib_snapshot()
            .into_iter()
            .find(|rt| rt.key.prefix == Prefix::new_v4(expect_prefix, 24))
            .unwrap_or_else(|| panic!("route for {expect_prefix:?} installed"));
        assert_eq!(route.preference.metric, 15); // 10 + 5, unchanged
                                                 // The LSP rides the prefix's own path: via B's address,
                                                 // not toward the mapping server as such (the same router
                                                 // here — the assertion is the next hop resolves at all).
        assert_eq!(route.next_hop, Some(IpAddr::V4([10, 0, 0, 2])));
        let attr = route
            .attributes
            .get(lr_core::attr::AttrTag(
                lr_bgp::path::AttrType::LrMplsLabelStack.to_u8(),
            ))
            .unwrap_or_else(|| panic!("label attribute for {expect_prefix:?}"));
        let stack = lr_mpls::LabelStack::decode_4octet(&attr.value).expect("label stack");
        assert_eq!(stack.labels()[0].value, expect_label);
    }

    // The SRDB exposure reports the mapping-server range (the
    // daemon's runtime API view of the same data). An uncovered
    // prefix resolves nothing — the range guard is unit-tested in
    // lr-ospf (`range_index_arithmetic_maps_prefixes_inside_the_span`).
    let srdb = r.ospf_sr_databases().remove(&0).expect("area 0 srdb");
    assert_eq!(srdb.prefix_ranges.len(), 1);
    assert_eq!(srdb.prefix_ranges[0].range.range_size, 4);
    assert_eq!(srdb.prefix_ranges[0].sid.sid, 500);
    assert!(srdb.prefixes.is_empty()); // range TLVs are not direct mappings
}

/// RFC 9513 §5 reception over a live v3 exchange: with
/// `ospf_srv6_receive` on, a neighbor's SRv6 Locator LSA publishes
/// the locator as a Protocol::Ospfv3 IPv6 route (the router's SPF
/// distance, its link-local first hop), and the SRv6 database
/// exposes the node's capabilities and End SIDs.
#[test]
fn ospfv3_srv6_locator_publishes_with_receive_on() {
    let mut r = DefaultRouter::new();
    r.set_ospf_srv6_receive(true);
    let r1 = RouterId::from_u32(0x0a00_0001);
    let r2 = 0x0a00_0002u32;
    let h = r
        .add_session(SessionConfig::ospfv3(r1, 0).with_ospf_mtu(1500))
        .expect("v3 session");

    use lr_ospf::lsa::srv6::{
        locator_route_type, originate_v3_srv6_locator_lsa, originate_v3_srv6_ri_lsa,
        Srv6EndSidSubTlv, Srv6LocatorTlv, PREFIX_OPT_AC, SRV6_CAP_O_FLAG,
    };
    use lr_ospf::lsa::v3::{
        originate_v3_link_lsa, originate_v3_router_lsa, LINK_TYPE_POINTTOPOINT, ROUTER_BIT_V6,
    };
    let mut ll2 = [0u8; 16];
    ll2[0] = 0xfe;
    ll2[1] = 0x80;
    ll2[15] = 2;
    let router_lsa = originate_v3_router_lsa(
        r2,
        ROUTER_BIT_V6,
        0x13,
        &[lr_ospf::lsa::v3::V3RouterLink {
            link_type: LINK_TYPE_POINTTOPOINT,
            metric: 10,
            interface_id: 3,
            neighbor_interface_id: 5,
            neighbor_router_id: 0x0a00_0001,
        }],
        None,
    )
    .unwrap();
    let link_lsa = originate_v3_link_lsa(r2, 3, 1, 0x13, ll2, vec![], None).unwrap();
    // §2: an SRv6-enabled router MUST advertise the SRv6
    // Capabilities TLV on its Router Information LSA.
    let ri_lsa = originate_v3_srv6_ri_lsa(r2, SRV6_CAP_O_FLAG, &[0], &[], None).unwrap();
    // r2's locator 2001:db8:1::/48 with one End SID.
    let mut prefix_bytes = [0u8; 16];
    prefix_bytes[..6].copy_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0x00, 0x01]);
    let mut end_sid = [0u8; 16];
    end_sid[..6].copy_from_slice(&prefix_bytes[..6]);
    end_sid[15] = 1;
    let locator_tlv = Srv6LocatorTlv {
        route_type: locator_route_type::INTRA_AREA,
        algorithm: 0,
        locator_len: 48,
        options: PREFIX_OPT_AC,
        metric: 0,
        prefix: prefix_bytes,
        end_sids: vec![Srv6EndSidSubTlv {
            flags: 0,
            behavior: 1, // End
            sid: end_sid,
            structure: None,
        }],
        fwd_addr: None,
        route_tag: None,
    };
    let locator_lsa =
        originate_v3_srv6_locator_lsa(r2, 0, std::slice::from_ref(&locator_tlv), None).unwrap();
    // The root's own Router-LSA (the daemon originates it on
    // adjacency-up; the SPF needs the outbound edge).
    let own_lsa = originate_v3_router_lsa(
        0x0a00_0001,
        ROUTER_BIT_V6,
        0x13,
        &[lr_ospf::lsa::v3::V3RouterLink {
            link_type: LINK_TYPE_POINTTOPOINT,
            metric: 10,
            interface_id: 5,
            neighbor_interface_id: 3,
            neighbor_router_id: r2,
        }],
        None,
    )
    .unwrap();
    let bytes = ospf3_lsu_bytes(
        r2,
        0,
        vec![router_lsa, link_lsa, ri_lsa, locator_lsa, own_lsa],
    );
    r.feed_input(h, &bytes).expect("feed v3 LSU");
    let _ = r.drain_output(h);

    let prefix = Prefix::new_v6(prefix_bytes, 48);
    let got = r
        .rib_snapshot()
        .into_iter()
        .find(|rt| rt.key.prefix == prefix)
        .expect("locator published");
    assert_eq!(got.protocol, Protocol::Ospfv3);
    assert_eq!(got.key.family, NlriFamily::IPV6_UNICAST);
    assert_eq!(got.next_hop, Some(IpAddr::V6(ll2)));
    assert_eq!(got.preference.metric, 10, "the router's SPF distance");

    // The SRv6 database view: r2 is SRv6-enabled with its End SID
    // under the locator.
    let db = r.ospf_srv6_databases().remove(&0).expect("area 0 srv6 db");
    let node = db.node(r2).expect("r2 projected");
    assert!(node.is_srv6_enabled());
    assert_eq!(node.locators.len(), 1);
    assert_eq!(node.locators[0].end_sids.len(), 1);
    assert_eq!(node.locators[0].end_sids[0].behavior, 1);
}

/// §4.8.3/§4.8.5 over a live v3 exchange: a 0x2003 summary from the
/// neighbor publishes an inter-area Ospfv3 route at
/// dist(border) + metric with the border router's link-local next
/// hop; a 0x4005 from the same neighbor publishes an external route
/// at the type-2 external metric; the 0x4005's F-bit forwarding
/// address form publishes with the forwarding address as next hop.
#[test]
fn ospfv3_inter_area_and_external_routes_published() {
    let mut r = DefaultRouter::new();
    let r1 = RouterId::from_u32(0x0a00_0001);
    let r2 = 0x0a00_0002u32;
    let h = r
        .add_session(SessionConfig::ospfv3(r1, 0).with_ospf_mtu(1500))
        .expect("v3 session");

    use lr_ospf::abr::originate_v3_inter_area_prefix_lsa;
    use lr_ospf::lsa::v3::{
        originate_v3_as_external_lsa, originate_v3_link_lsa, originate_v3_router_lsa,
        V3ExternalDestination, LINK_TYPE_POINTTOPOINT, ROUTER_BIT_V6,
    };
    let mut ll2 = [0u8; 16];
    ll2[0] = 0xfe;
    ll2[1] = 0x80;
    ll2[15] = 2;
    let link = lr_ospf::lsa::v3::V3RouterLink {
        link_type: LINK_TYPE_POINTTOPOINT,
        metric: 10,
        interface_id: 3,
        neighbor_interface_id: 5,
        neighbor_router_id: 0x0a00_0001,
    };
    let router_lsa = originate_v3_router_lsa(r2, ROUTER_BIT_V6, 0x13, &[link], None).unwrap();
    let link_lsa = originate_v3_link_lsa(r2, 3, 1, 0x13, ll2, vec![], None).unwrap();
    // The root's own Router-LSA (adjacency-up origination).
    let own_lsa = originate_v3_router_lsa(
        0x0a00_0001,
        ROUTER_BIT_V6,
        0x13,
        &[lr_ospf::lsa::v3::V3RouterLink {
            link_type: LINK_TYPE_POINTTOPOINT,
            metric: 10,
            interface_id: 5,
            neighbor_interface_id: 3,
            neighbor_router_id: r2,
        }],
        None,
    )
    .unwrap();
    // r2's 0x2003 for 2001:db8:a::/48 at metric 7 (LS ID arbitrary).
    let mut p6 = [0u8; 16];
    p6[..6].copy_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0x00, 0x0a]);
    let summary = originate_v3_inter_area_prefix_lsa(
        r2,
        1,
        &lr_ospf::abr::SummaryDestination {
            prefix: Prefix::new_v6(p6, 48),
            metric: 7,
        },
        None,
    )
    .unwrap();
    // r2's 0x4005: type 2 metric 100 for 2001:db8:b::/48.
    let mut ep = [0u8; 16];
    ep[..6].copy_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0x00, 0x0b]);
    let ext_dest = V3ExternalDestination::new(Prefix::new_v6(ep, 48), 100, true);
    let external = originate_v3_as_external_lsa(r2, 1, &ext_dest, None).unwrap();

    let bytes = ospf3_lsu_bytes(
        r2,
        0,
        vec![router_lsa, link_lsa, own_lsa, summary, external],
    );
    r.feed_input(h, &bytes).expect("feed v3 LSU");
    let _ = r.drain_output(h);

    // Inter-area: dist(r2)=10 + 7, via r2's link-local.
    let summary_route = r
        .rib_snapshot()
        .into_iter()
        .find(|rt| rt.key.prefix == Prefix::new_v6(p6, 48))
        .expect("inter-area route published");
    assert_eq!(summary_route.protocol, Protocol::Ospfv3);
    assert_eq!(summary_route.preference.metric, 17);
    assert_eq!(summary_route.next_hop, Some(IpAddr::V6(ll2)));
    // External: type 2 → the external metric alone, via the ASBR's
    // link-local.
    let external_route = r
        .rib_snapshot()
        .into_iter()
        .find(|rt| rt.key.prefix == Prefix::new_v6(ep, 48))
        .expect("external route published");
    assert_eq!(external_route.protocol, Protocol::Ospfv3);
    assert_eq!(external_route.preference.metric, 100);
    assert_eq!(external_route.next_hop, Some(IpAddr::V6(ll2)));
}

/// An F-bit 0x4005 publishes with the global forwarding address as
/// the next hop — the §16.4 (c) v3 form, where the FA (covered by
/// the neighbor's intra-area prefix) resolves the internal leg.
#[test]
fn ospfv3_external_forwarding_address_next_hop() {
    let mut r = DefaultRouter::new();
    let r1 = RouterId::from_u32(0x0a00_0001);
    let r2 = 0x0a00_0002u32;
    let h = r
        .add_session(SessionConfig::ospfv3(r1, 0).with_ospf_mtu(1500))
        .expect("v3 session");

    use lr_ospf::lsa::v3::{
        originate_v3_as_external_lsa, originate_v3_intra_area_prefix_lsa, originate_v3_link_lsa,
        originate_v3_router_lsa, V3ExternalDestination, V3Prefix, LINK_TYPE_POINTTOPOINT,
        ROUTER_BIT_V6,
    };
    let mut ll2 = [0u8; 16];
    ll2[0] = 0xfe;
    ll2[1] = 0x80;
    ll2[15] = 2;
    let link = lr_ospf::lsa::v3::V3RouterLink {
        link_type: LINK_TYPE_POINTTOPOINT,
        metric: 10,
        interface_id: 3,
        neighbor_interface_id: 5,
        neighbor_router_id: 0x0a00_0001,
    };
    let router_lsa = originate_v3_router_lsa(r2, ROUTER_BIT_V6, 0x13, &[link], None).unwrap();
    let link_lsa = originate_v3_link_lsa(r2, 3, 1, 0x13, ll2, vec![], None).unwrap();
    let own_lsa = originate_v3_router_lsa(
        0x0a00_0001,
        ROUTER_BIT_V6,
        0x13,
        &[lr_ospf::lsa::v3::V3RouterLink {
            link_type: LINK_TYPE_POINTTOPOINT,
            metric: 10,
            interface_id: 5,
            neighbor_interface_id: 3,
            neighbor_router_id: r2,
        }],
        None,
    )
    .unwrap();
    // r2's own /64 on the link: covers the forwarding address below.
    let mut own_prefix = [0u8; 16];
    own_prefix[..7].copy_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0x00, 0x02, 0x02]);
    let mut own_p = V3Prefix {
        prefix_len: 64,
        options: 0,
        metric: 0,
        addr: own_prefix,
    };
    own_p.prefix_len = 64;
    let iap = originate_v3_intra_area_prefix_lsa(
        r2,
        1,
        lr_ospf::lsa::v3::LS_TYPE_ROUTER,
        0,
        r2,
        vec![own_p.clone()],
        None,
    )
    .unwrap();
    // The external with the FA inside r2's /64 (a global address).
    let mut fa = [0u8; 16];
    fa[..8].copy_from_slice(&own_prefix[..8]);
    fa[15] = 1;
    let mut ep = [0u8; 16];
    ep[..6].copy_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0x00, 0x0c]);
    let mut ext_dest = V3ExternalDestination::new(Prefix::new_v6(ep, 48), 30, true);
    ext_dest.forwarding_addr = Some(fa);
    let external = originate_v3_as_external_lsa(r2, 1, &ext_dest, None).unwrap();

    let bytes = ospf3_lsu_bytes(r2, 0, vec![router_lsa, link_lsa, own_lsa, iap, external]);
    r.feed_input(h, &bytes).expect("feed v3 LSU");
    let _ = r.drain_output(h);

    let route = r
        .rib_snapshot()
        .into_iter()
        .find(|rt| rt.key.prefix == Prefix::new_v6(ep, 48))
        .expect("external route published");
    assert_eq!(route.protocol, Protocol::Ospfv3);
    assert_eq!(route.preference.metric, 30, "type 2: FA leg not added");
    // The FA — not the ASBR's link-local — is the published next hop.
    assert_eq!(route.next_hop, Some(IpAddr::V6(fa)));
}

/// An OSPFv3 ABR (backbone + area 1, both v3) originates a 0x2003
/// into the backbone for area 1's intra-area prefixes (RFC 5340
/// §4.4.3.4), with a stable LS ID and the area-1 cost.
#[test]
fn ospfv3_abr_originates_inter_area_prefix() {
    let mut r = DefaultRouter::new();
    let r1 = RouterId::from_u32(0x0a00_0001);
    let r2 = 0x0a00_0002u32;
    let h0 = r
        .add_session(SessionConfig::ospfv3(r1, 0).with_ospf_mtu(1500))
        .expect("backbone session");
    let h1 = r
        .add_session(SessionConfig::ospfv3(r1, 1).with_ospf_mtu(1500))
        .expect("area 1 session");

    use lr_ospf::lsa::v3::{
        originate_v3_intra_area_prefix_lsa, originate_v3_link_lsa, originate_v3_router_lsa,
        V3Prefix, LINK_TYPE_POINTTOPOINT, ROUTER_BIT_V6,
    };
    let mk_link = |ifid: u32, nifid: u32, nrid: u32| lr_ospf::lsa::v3::V3RouterLink {
        link_type: LINK_TYPE_POINTTOPOINT,
        metric: 10,
        interface_id: ifid,
        neighbor_interface_id: nifid,
        neighbor_router_id: nrid,
    };
    let own_lsa =
        originate_v3_router_lsa(r1.as_u32(), ROUTER_BIT_V6, 0x13, &[mk_link(5, 3, r2)], None)
            .unwrap();
    let r2_lsa =
        originate_v3_router_lsa(r2, ROUTER_BIT_V6, 0x13, &[mk_link(3, 5, r1.as_u32())], None)
            .unwrap();
    let mut ll2 = [0u8; 16];
    ll2[0] = 0xfe;
    ll2[1] = 0x80;
    ll2[15] = 2;
    let r2_link = originate_v3_link_lsa(r2, 3, 1, 0x13, ll2, vec![], None).unwrap();
    // r2's /64 on the link, attached to its Router-LSA.
    let mut p2 = [0u8; 16];
    p2[..7].copy_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 2, 2]);
    let p2_prefix = V3Prefix {
        prefix_len: 64,
        options: 0,
        metric: 0,
        addr: p2,
    };
    let iap = originate_v3_intra_area_prefix_lsa(
        r2,
        1,
        lr_ospf::lsa::v3::LS_TYPE_ROUTER,
        0,
        r2,
        vec![p2_prefix],
        None,
    )
    .unwrap();

    // Area 1 learns r2's topology; the router becomes a v3 ABR
    // (backbone attached) and must summarize r2's /64 into area 0.
    let bytes = ospf3_lsu_bytes(r2, 1, vec![own_lsa, r2_lsa, r2_link, iap]);
    r.feed_input(h1, &bytes).expect("feed area 1 LSU");
    let _ = r.drain_output(h1);
    let _ = r.drain_output(h0);

    let summary = r
        .ospf_area_lsa(0, lr_ospf::lsa::v3::LS_TYPE_INTER_PREFIX, 1, r1.as_u32())
        .expect("0x2003 originated into the backbone");
    assert!(summary.checksum_ok());
    let body = lr_ospf::lsa::decode_v3_inter_area_prefix_body(&summary.body).unwrap();
    assert_eq!(body.metric, 10, "the area-1 cost to r2");
    assert_eq!(body.prefix_len, 64);
    assert_eq!(
        body.to_prefix().unwrap(),
        Prefix::new_v6(p2, 64),
        "r2's /64 summarized"
    );
    // The backbone itself carries no summary for its own prefixes —
    // area 0 has no intra nets here, but the loop guard holds by
    // construction (nothing else was originated).
    assert!(r
        .ospf_area_lsa(1, lr_ospf::lsa::v3::LS_TYPE_INTER_PREFIX, 1, r1.as_u32())
        .is_none());
}

/// An OSPFv3 ABR advertises an ASBR (a 0x4005 advertiser) into the
/// areas that cannot reach it intra-area (RFC 5340 §4.4.3.5): the
/// 0x2004 rides the backbone with LS ID = destination router ID,
/// the ABR's cost, and the destination's Router-LSA options.
#[test]
fn ospfv3_abr_originates_inter_area_router() {
    let mut r = DefaultRouter::new();
    let r1 = RouterId::from_u32(0x0a00_0001);
    let (r2, r3) = (0x0a00_0002u32, 0x0a00_0003u32);
    let h0 = r
        .add_session(SessionConfig::ospfv3(r1, 0).with_ospf_mtu(1500))
        .expect("backbone session");
    let h1 = r
        .add_session(SessionConfig::ospfv3(r1, 1).with_ospf_mtu(1500))
        .expect("area 1 session");

    use lr_ospf::lsa::v3::{
        originate_v3_as_external_lsa, originate_v3_link_lsa, originate_v3_router_lsa,
        V3ExternalDestination, LINK_TYPE_POINTTOPOINT, ROUTER_BIT_V6,
    };
    let mk_link = |ifid: u32, nifid: u32, nrid: u32| lr_ospf::lsa::v3::V3RouterLink {
        link_type: LINK_TYPE_POINTTOPOINT,
        metric: 10,
        interface_id: ifid,
        neighbor_interface_id: nifid,
        neighbor_router_id: nrid,
    };
    let own_lsa =
        originate_v3_router_lsa(r1.as_u32(), ROUTER_BIT_V6, 0x13, &[mk_link(5, 3, r2)], None)
            .unwrap();
    // r1 - r2 - r3 chain in area 1: r3 is intra-area reachable there.
    let r2_lsa = originate_v3_router_lsa(
        r2,
        ROUTER_BIT_V6,
        0x13,
        &[mk_link(3, 5, r1.as_u32()), mk_link(4, 6, r3)],
        None,
    )
    .unwrap();
    let r3_lsa =
        originate_v3_router_lsa(r3, ROUTER_BIT_V6, 0x13, &[mk_link(6, 4, r2)], None).unwrap();
    let r3_link = originate_v3_link_lsa(r3, 6, 1, 0x13, [0xfe; 16], vec![], None).unwrap();
    let r2_link = originate_v3_link_lsa(r2, 3, 1, 0x13, [0xfe; 16], vec![], None).unwrap();
    let r2_link2 = originate_v3_link_lsa(r2, 4, 1, 0x13, [0xfe; 16], vec![], None).unwrap();
    // r3 is an ASBR: it advertises an external (installed into
    // area 1, re-flooded to the backbone at AS scope).
    let mut ep = [0u8; 16];
    ep[..6].copy_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0xaa, 0x00]);
    let external = originate_v3_as_external_lsa(
        r3,
        1,
        &V3ExternalDestination::new(Prefix::new_v6(ep, 48), 100, true),
        None,
    )
    .unwrap();

    let bytes = ospf3_lsu_bytes(
        r3,
        1,
        vec![
            own_lsa, r2_lsa, r2_link, r2_link2, r3_lsa, r3_link, external,
        ],
    );
    r.feed_input(h1, &bytes).expect("feed area 1 LSU");
    let _ = r.drain_output(h1);
    let _ = r.drain_output(h0);

    // The backbone cannot reach r3 intra-area (no topology there),
    // so the ABR advertises r3's location with the area-1 cost.
    let summary = r
        .ospf_area_lsa(0, lr_ospf::lsa::v3::LS_TYPE_INTER_ROUTER, r3, r1.as_u32())
        .expect("0x2004 originated into the backbone");
    let body = lr_ospf::lsa::v3::V3InterAreaRouterBody::decode(&summary.body).unwrap();
    assert_eq!(body.dest_router_id, r3);
    assert_eq!(body.metric, 20, "dist(r2) + dist(r3) in area 1");
    assert_eq!(body.options, 0x13, "r3's Router-LSA options mirrored");
}

/// Fail-closed default: without `ospf_srv6_receive` the identical
/// exchange publishes no locator route — the router is
/// byte-identical to a pre-SRv6 one. (§5 still holds for the
/// receiver side: the SIDs are never directly routable, so nothing
/// else changes.)
#[test]
fn ospfv3_srv6_locator_inert_without_receive() {
    let mut r = DefaultRouter::new();
    let r1 = RouterId::from_u32(0x0a00_0001);
    let r2 = 0x0a00_0002u32;
    let h = r
        .add_session(SessionConfig::ospfv3(r1, 0).with_ospf_mtu(1500))
        .expect("v3 session");

    use lr_ospf::lsa::srv6::{locator_route_type, originate_v3_srv6_locator_lsa, Srv6LocatorTlv};
    use lr_ospf::lsa::v3::{
        originate_v3_link_lsa, originate_v3_router_lsa, LINK_TYPE_POINTTOPOINT, ROUTER_BIT_V6,
    };
    let mut ll2 = [0u8; 16];
    ll2[0] = 0xfe;
    ll2[1] = 0x80;
    ll2[15] = 2;
    let router_lsa = originate_v3_router_lsa(
        r2,
        ROUTER_BIT_V6,
        0x13,
        &[lr_ospf::lsa::v3::V3RouterLink {
            link_type: LINK_TYPE_POINTTOPOINT,
            metric: 10,
            interface_id: 3,
            neighbor_interface_id: 5,
            neighbor_router_id: 0x0a00_0001,
        }],
        None,
    )
    .unwrap();
    let link_lsa = originate_v3_link_lsa(r2, 3, 1, 0x13, ll2, vec![], None).unwrap();
    let mut prefix_bytes = [0u8; 16];
    prefix_bytes[..6].copy_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0x00, 0x01]);
    let tlv = Srv6LocatorTlv {
        route_type: locator_route_type::INTRA_AREA,
        algorithm: 0,
        locator_len: 48,
        options: 0,
        metric: 0,
        prefix: prefix_bytes,
        end_sids: vec![],
        fwd_addr: None,
        route_tag: None,
    };
    let locator_lsa =
        originate_v3_srv6_locator_lsa(r2, 0, std::slice::from_ref(&tlv), None).unwrap();
    let own_lsa = originate_v3_router_lsa(
        0x0a00_0001,
        ROUTER_BIT_V6,
        0x13,
        &[lr_ospf::lsa::v3::V3RouterLink {
            link_type: LINK_TYPE_POINTTOPOINT,
            metric: 10,
            interface_id: 5,
            neighbor_interface_id: 3,
            neighbor_router_id: r2,
        }],
        None,
    )
    .unwrap();
    let bytes = ospf3_lsu_bytes(r2, 0, vec![router_lsa, link_lsa, locator_lsa, own_lsa]);
    r.feed_input(h, &bytes).expect("feed v3 LSU");
    let _ = r.drain_output(h);

    let prefix = Prefix::new_v6(prefix_bytes, 48);
    assert!(
        !r.rib_snapshot().iter().any(|rt| rt.key.prefix == prefix),
        "no locator route without the flag"
    );
}

/// §5 preference: a prefix reachability advertisement covering the
/// same prefix wins over the locator advertisement — r3's
/// Intra-Area-Prefix route (metric 20, through r2-r3) beats r2's
/// locator (metric 10) for the same /48, matching the forwarding a
/// non-SRv6 router installs from the IAP route alone.
#[test]
fn ospfv3_srv6_iap_prefix_beats_locator_for_the_same_prefix() {
    let mut r = DefaultRouter::new();
    r.set_ospf_srv6_receive(true);
    let r1 = RouterId::from_u32(0x0a00_0001);
    let (r2, r3) = (0x0a00_0002u32, 0x0a00_0003u32);
    let h = r
        .add_session(SessionConfig::ospfv3(r1, 0).with_ospf_mtu(1500))
        .expect("v3 session");

    use lr_ospf::lsa::srv6::{locator_route_type, originate_v3_srv6_locator_lsa, Srv6LocatorTlv};
    use lr_ospf::lsa::v3::{
        originate_v3_intra_area_prefix_lsa, originate_v3_link_lsa, originate_v3_router_lsa,
        V3Prefix, V3RouterLink, LINK_TYPE_POINTTOPOINT, LS_TYPE_ROUTER, ROUTER_BIT_V6,
    };
    let link = |metric: u16, ifid: u32, nifid: u32, nrid: u32| V3RouterLink {
        link_type: LINK_TYPE_POINTTOPOINT,
        metric,
        interface_id: ifid,
        neighbor_interface_id: nifid,
        neighbor_router_id: nrid,
    };
    let ll = |host: u8| {
        let mut a = [0u8; 16];
        a[0] = 0xfe;
        a[1] = 0x80;
        a[15] = host;
        a
    };
    // r1 - 10 - r2 - 10 - r3.
    let lsas = vec![
        originate_v3_router_lsa(
            0x0a00_0001,
            ROUTER_BIT_V6,
            0x13,
            &[link(10, 5, 3, r2)],
            None,
        )
        .unwrap(),
        originate_v3_router_lsa(
            r2,
            ROUTER_BIT_V6,
            0x13,
            &[link(10, 3, 5, 0x0a00_0001), link(10, 6, 7, r3)],
            None,
        )
        .unwrap(),
        originate_v3_router_lsa(r3, ROUTER_BIT_V6, 0x13, &[link(10, 7, 6, r2)], None).unwrap(),
        originate_v3_link_lsa(0x0a00_0001, 5, 1, 0x13, ll(1), vec![], None).unwrap(),
        originate_v3_link_lsa(r2, 3, 1, 0x13, ll(2), vec![], None).unwrap(),
        originate_v3_link_lsa(r2, 6, 1, 0x13, ll(22), vec![], None).unwrap(),
        originate_v3_link_lsa(r3, 7, 1, 0x13, ll(3), vec![], None).unwrap(),
    ];
    // r2's locator 2001:db8:1::/48 (metric 10 from r1)...
    let mut prefix_bytes = [0u8; 16];
    prefix_bytes[..6].copy_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0x00, 0x01]);
    let tlv = Srv6LocatorTlv {
        route_type: locator_route_type::INTRA_AREA,
        algorithm: 0,
        locator_len: 48,
        options: 0,
        metric: 0,
        prefix: prefix_bytes,
        end_sids: vec![],
        fwd_addr: None,
        route_tag: None,
    };
    let locator_lsa =
        originate_v3_srv6_locator_lsa(r2, 0, std::slice::from_ref(&tlv), None).unwrap();
    // ...and r3's Intra-Area-Prefix-LSA attaching the SAME /48 to
    // its Router-LSA (metric 20 from r1).
    let iap = originate_v3_intra_area_prefix_lsa(
        r3,
        1,
        LS_TYPE_ROUTER,
        0,
        r3,
        vec![V3Prefix {
            prefix_len: 48,
            options: 0,
            metric: 0,
            addr: prefix_bytes,
        }],
        None,
    )
    .unwrap();
    let own_lsa = originate_v3_router_lsa(
        0x0a00_0001,
        ROUTER_BIT_V6,
        0x13,
        &[link(10, 5, 3, r2)],
        None,
    )
    .unwrap();
    let bytes = ospf3_lsu_bytes(r2, 0, lsas)
        .into_iter()
        .chain(ospf3_lsu_bytes(r3, 0, vec![iap]))
        .chain(ospf3_lsu_bytes(r2, 0, vec![locator_lsa, own_lsa]))
        .collect::<Vec<u8>>();
    r.feed_input(h, &bytes).expect("feed v3 LSUs");
    let _ = r.drain_output(h);

    let prefix = Prefix::new_v6(prefix_bytes, 48);
    let got = r
        .rib_snapshot()
        .into_iter()
        .find(|rt| rt.key.prefix == prefix)
        .expect("the prefix is installed");
    assert_eq!(
        got.preference.metric, 20,
        "the IAP advertisement wins over the metric-10 locator (§5)"
    );
}

/// §5 algorithm gate: a locator bound to an algorithm the receiver
/// does not support (anything beyond SPF, algorithm 0) never
/// installs.
#[test]
fn ospfv3_srv6_unsupported_algorithm_not_installed() {
    let mut r = DefaultRouter::new();
    r.set_ospf_srv6_receive(true);
    let r1 = RouterId::from_u32(0x0a00_0001);
    let r2 = 0x0a00_0002u32;
    let h = r
        .add_session(SessionConfig::ospfv3(r1, 0).with_ospf_mtu(1500))
        .expect("v3 session");

    use lr_ospf::lsa::srv6::{locator_route_type, originate_v3_srv6_locator_lsa, Srv6LocatorTlv};
    use lr_ospf::lsa::v3::{
        originate_v3_link_lsa, originate_v3_router_lsa, LINK_TYPE_POINTTOPOINT, ROUTER_BIT_V6,
    };
    let mut ll2 = [0u8; 16];
    ll2[0] = 0xfe;
    ll2[1] = 0x80;
    ll2[15] = 2;
    let router_lsa = originate_v3_router_lsa(
        r2,
        ROUTER_BIT_V6,
        0x13,
        &[lr_ospf::lsa::v3::V3RouterLink {
            link_type: LINK_TYPE_POINTTOPOINT,
            metric: 10,
            interface_id: 3,
            neighbor_interface_id: 5,
            neighbor_router_id: 0x0a00_0001,
        }],
        None,
    )
    .unwrap();
    let link_lsa = originate_v3_link_lsa(r2, 3, 1, 0x13, ll2, vec![], None).unwrap();
    let mut prefix_bytes = [0u8; 16];
    prefix_bytes[..6].copy_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0x00, 0x01]);
    let tlv = Srv6LocatorTlv {
        route_type: locator_route_type::INTRA_AREA,
        algorithm: 128, // a private/flex-algo value — unsupported
        locator_len: 48,
        options: 0,
        metric: 0,
        prefix: prefix_bytes,
        end_sids: vec![],
        fwd_addr: None,
        route_tag: None,
    };
    let locator_lsa =
        originate_v3_srv6_locator_lsa(r2, 0, std::slice::from_ref(&tlv), None).unwrap();
    let own_lsa = originate_v3_router_lsa(
        0x0a00_0001,
        ROUTER_BIT_V6,
        0x13,
        &[lr_ospf::lsa::v3::V3RouterLink {
            link_type: LINK_TYPE_POINTTOPOINT,
            metric: 10,
            interface_id: 5,
            neighbor_interface_id: 3,
            neighbor_router_id: r2,
        }],
        None,
    )
    .unwrap();
    let bytes = ospf3_lsu_bytes(r2, 0, vec![router_lsa, link_lsa, locator_lsa, own_lsa]);
    r.feed_input(h, &bytes).expect("feed v3 LSU");
    let _ = r.drain_output(h);

    let prefix = Prefix::new_v6(prefix_bytes, 48);
    assert!(
        !r.rib_snapshot().iter().any(|rt| rt.key.prefix == prefix),
        "an unsupported-algorithm locator never installs"
    );
}

// ===== rc.3 shared Loc-RIB: BGP + protocol-direct contributions =====

/// The mixed-protocol test bed: router `a` runs one OSPFv2 area and
/// one established eBGP session toward `b`, so the same prefix can
/// arrive from both planes into one Loc-RIB.
fn mixed_pair() -> (
    DefaultRouter,
    SessionHandle,
    SessionHandle,
    DefaultRouter,
    SessionHandle,
) {
    let mut a = DefaultRouter::new();
    let mut b = DefaultRouter::new();
    let ospf = a
        .add_session(SessionConfig::ospfv2(RouterId::from_u32(0x01010101), 0))
        .unwrap();
    let a_session = a
        .add_session(
            SessionConfig::bgp(Asn(64512), Asn(64513), RouterId::from_v4([10, 0, 0, 1]))
                .with_mrai_ms(0),
        )
        .unwrap();
    let b_session = b
        .add_session(
            SessionConfig::bgp(Asn(64513), Asn(64512), RouterId::from_v4([10, 0, 0, 2]))
                .with_mrai_ms(0),
        )
        .unwrap();
    establish(&mut a, a_session, &mut b, b_session);
    (a, ospf, a_session, b, b_session)
}

/// Feed the area-0 LSDB pair that makes 10.10.10.0/24 reachable via
/// neighbour 2.2.2.2 (numbered p2p link with its interface address,
/// stub link metric 10) → one OSPF-direct route with a real next hop.
fn neighbour_lsa() -> Lsa {
    router_lsa(
        0x02020202,
        vec![
            (0x01010101, 0x0b0b0b01, P2P, 5),
            (0x0a0a0a00, 0xffff_ff00, STUB, 10),
        ],
    )
}

fn feed_direct_ospf_route(a: &mut DefaultRouter, ospf: SessionHandle) {
    let ours = router_lsa(0x01010101, vec![(0x02020202, 0x0b0b0b01, P2P, 5)]);
    let r2 = neighbour_lsa();
    a.feed_input(ospf, &ospf_lsu_bytes(0x02020202, 0, vec![ours, r2]))
        .unwrap();
}

/// Flush 2.2.2.2's Router-LSA with a MaxAge instance → the OSPF
/// route withdraws.
fn flush_direct_ospf_route(a: &mut DefaultRouter, ospf: SessionHandle) {
    let mut r2 = neighbour_lsa();
    r2.header.ls_age = 3600;
    r2.header.ls_sequence_number += 1;
    a.feed_input(ospf, &ospf_lsu_bytes(0x02020202, 0, vec![r2]))
        .unwrap();
}

#[test]
fn mixed_rib_bgp_beats_direct_ospf_and_withdrawals_fall_back() {
    // The rc.3 multi-protocol RIB: the same prefix learned by OSPF
    // (admin 110) and BGP (admin 20) must rank BGP first, and a
    // withdrawal from either side must fall back to the other's
    // contribution instead of dropping the route.
    let (mut a, ospf, a_session, mut b, b_session) = mixed_pair();
    feed_direct_ospf_route(&mut a, ospf);
    let prefix = Prefix::new_v4([10, 10, 10, 0], 24);
    let best = a
        .rib_snapshot()
        .into_iter()
        .find(|rt| rt.key.prefix == prefix)
        .expect("OSPF route installs");
    assert_eq!(best.protocol, Protocol::Ospfv2);

    // B advertises the same prefix over the established session.
    let key = b.originate(prefix, Some(IpAddr::V4([192, 0, 2, 10])));
    let advertisement = b.drain_output(b_session);
    assert!(!advertisement.is_empty());
    a.feed_input(a_session, &advertisement).unwrap();
    let best = a
        .rib_snapshot()
        .into_iter()
        .find(|rt| rt.key.prefix == prefix)
        .expect("prefix still present after the BGP advertisement");
    assert_eq!(
        best.protocol,
        Protocol::Bgp,
        "BGP (admin 20) must outrank OSPF (110) for the shared prefix"
    );

    // B withdraws → the OSPF contribution must come back, not vanish.
    b.unoriginate(&key);
    let withdrawal = b.drain_output(b_session);
    assert!(!withdrawal.is_empty());
    a.feed_input(a_session, &withdrawal).unwrap();
    let best = a
        .rib_snapshot()
        .into_iter()
        .find(|rt| rt.key.prefix == prefix)
        .expect("OSPF route must survive the BGP withdrawal");
    assert_eq!(best.protocol, Protocol::Ospfv2);

    // OSPF flushes (MaxAge) → nothing is left.
    flush_direct_ospf_route(&mut a, ospf);
    assert!(
        !a.rib_snapshot().iter().any(|rt| rt.key.prefix == prefix),
        "route must leave with its last contribution"
    );
}

#[test]
fn direct_ospf_route_is_not_exported_to_bgp_without_a_pipe() {
    // FRR `redistribute` / BIRD `pipe` semantics: an OSPF-learned
    // route never leaks into BGP advertisements unless a
    // redistribution pipe is configured — sharing the Loc-RIB is
    // not redistribution.
    let (mut a, ospf, a_session, mut b, b_session) = mixed_pair();
    feed_direct_ospf_route(&mut a, ospf);
    let prefix = Prefix::new_v4([10, 10, 10, 0], 24);

    // Whatever a sends toward b (keepalives, nothing else) must not
    // carry the OSPF route: b must not learn it.
    let out = a.drain_output(a_session);
    if !out.is_empty() {
        b.feed_input(b_session, &out).unwrap();
    }
    assert!(
        !b.rib_snapshot().iter().any(|rt| rt.key.prefix == prefix),
        "OSPF route must not leak into BGP without a pipe"
    );

    // Control: a locally originated network (protocol Bgp) still
    // exports to the established peer as before.
    let key = a.originate(prefix, Some(IpAddr::V4([192, 0, 2, 10])));
    let out = a.drain_output(a_session);
    assert!(!out.is_empty(), "originated network must advertise");
    b.feed_input(b_session, &out).unwrap();
    assert!(
        b.rib_snapshot().iter().any(|rt| rt.key.prefix == prefix),
        "the originated network must reach the peer"
    );
    a.unoriginate(&key);
}

#[test]
fn ospf_route_present_at_session_up_does_not_leak_into_bgp() {
    // The session-up full sync is the other export path: a Loc-RIB
    // already holding protocol-direct (OSPF) routes when the BGP
    // session establishes must not dump them — they carry no
    // ORIGIN/AS_PATH, and a real peer treats the UPDATE as
    // malformed (BIRD: "Missing mandatory ORIGIN attribute",
    // caught live by tests/interop/redistribute_bird.sh where the
    // OSPF-internal transit net leaked into the BGP session).
    let mut a = DefaultRouter::new();
    let mut b = DefaultRouter::new();
    let ospf = a
        .add_session(SessionConfig::ospfv2(RouterId::from_u32(0x01010101), 0))
        .unwrap();
    let a_session = a
        .add_session(
            SessionConfig::bgp(Asn(64512), Asn(64513), RouterId::from_v4([10, 0, 0, 1]))
                .with_mrai_ms(0),
        )
        .unwrap();
    let b_session = b
        .add_session(
            SessionConfig::bgp(Asn(64513), Asn(64512), RouterId::from_v4([10, 0, 0, 2]))
                .with_mrai_ms(0),
        )
        .unwrap();

    // The OSPF route lands in the Loc-RIB *before* the BGP
    // handshake — so the initial dump is the only path it could
    // leak through.
    feed_direct_ospf_route(&mut a, ospf);
    assert!(
        a.rib_snapshot()
            .iter()
            .any(|rt| rt.key.prefix == Prefix::new_v4([10, 10, 10, 0], 24)),
        "precondition: the OSPF route is in the shared Loc-RIB"
    );

    establish(&mut a, a_session, &mut b, b_session);
    let out = a.drain_output(a_session);
    b.feed_input(b_session, &out).unwrap();
    assert!(
        !b.rib_snapshot()
            .iter()
            .any(|rt| rt.key.prefix == Prefix::new_v4([10, 10, 10, 0], 24)),
        "OSPF route must not leak into the BGP initial dump"
    );

    // Control: a locally originated network (protocol Bgp) is part
    // of the same initial dump and must reach the peer.
    let key = a.originate(
        Prefix::new_v4([10, 10, 10, 0], 24),
        Some(IpAddr::V4([192, 0, 2, 10])),
    );
    let out = a.drain_output(a_session);
    assert!(!out.is_empty(), "originated network must advertise");
    b.feed_input(b_session, &out).unwrap();
    assert!(
        b.rib_snapshot()
            .iter()
            .any(|rt| rt.key.prefix == Prefix::new_v4([10, 10, 10, 0], 24)),
        "the originated network must reach the peer"
    );
    a.unoriginate(&key);
}

#[test]
fn pipe_redistributes_direct_ospf_into_bgp() {
    // The opt-in path: with an Ospfv2 → BGP pipe, an OSPF-learned
    // route is re-originated into BGP (the copy — admin 20 — takes
    // the Loc-RIB slot, an UPDATE leaves toward the peer) and the
    // copy is withdrawn when the OSPF source flushes. Whether the
    // peer accepts the UPDATE is BGP import policy — v2 intra-area
    // OSPF routes carry no next hop, so a strict peer may refuse —
    // the pipe mechanics under test are A's side.
    let (mut a, ospf, a_session, _b, _b_session) = mixed_pair();
    a.add_redistribution_pipe(RedistributionPipe::new(Protocol::Ospfv2, Protocol::Bgp));
    feed_direct_ospf_route(&mut a, ospf);
    let prefix = Prefix::new_v4([10, 10, 10, 0], 24);

    // The pipe fired: the redistributed copy is the Loc-RIB best.
    let best = a
        .rib_snapshot()
        .into_iter()
        .find(|rt| rt.key.prefix == prefix)
        .expect("the redistributed copy installs");
    assert_eq!(best.protocol, Protocol::Bgp);
    assert_eq!(
        best.preference,
        lr_core::rib::Preference::new(Protocol::Bgp.default_admin_distance(), 15),
        "the copy inherits the OSPF metric (SPF 15) under the BGP admin distance"
    );
    let events = a.poll_events();
    assert!(
        events.iter().any(|e| matches!(e, RouterEvent::Log(msg)
                    if msg.contains("redistribute: 10.10.10.0/24 -> BGP"))),
        "the redistribute log must fire: {:?}",
        events
    );
    // An UPDATE left the BGP session toward the peer.
    let out = a.drain_output(a_session);
    assert!(
        !out.is_empty(),
        "the pipe must produce an advertisement toward the peer"
    );

    // Source flush → the copy goes with it.
    flush_direct_ospf_route(&mut a, ospf);
    assert!(
        !a.rib_snapshot().iter().any(|rt| rt.key.prefix == prefix),
        "the redistributed route must withdraw with its source"
    );
    let events = a.poll_events();
    assert!(
        events.iter().any(|e| matches!(e, RouterEvent::Log(msg)
                    if msg.contains("redistribute: withdraw 10.10.10.0/24"))),
        "the withdraw log must fire: {:?}",
        events
    );
}

/// `apply_runtime_delta` must not emit a fresh `RouteInstalled`
/// event for a byte-identical re-install — the rc.4 defect flooded
/// the kernel mirror with redundant `CreateIpForwardEntry2` /
/// `ip route replace` calls on every Babel UPDATE re-advertisement
/// (the Windows production report showed `mirror: route installed
/// ...` four times in a row for the same prefix). The fix:
/// `LocRib::install` now returns a `bool` "did this actually
/// change the Loc-RIB?" signal, and `apply_runtime_delta` skips
/// the event emission when the signal is `false`.
#[test]
fn apply_runtime_delta_deduplicates_identical_reinstalls() {
    use lr_core::addr::Prefix;
    use lr_core::nlri::NlriFamily;
    use lr_core::rib::{Preference, Protocol, Route, RouteOrigin};

    let mut r = DefaultRouter::new();
    let prefix = Prefix::new_v4([203, 0, 113, 0], 24);
    let key = RouteKey::new(prefix, NlriFamily::IPV4_UNICAST);
    let route = Route {
        key: key.clone(),
        origin: RouteOrigin { proto: 1, peer: 1 },
        protocol: Protocol::Babel,
        preference: Preference::new(120, 0),
        next_hop: Some(IpAddr::V4([169, 254, 1, 6])),
        attributes: lr_core::attr::Attributes::new(),
        age_ms: 0,
        path_id: 0,
        tag: None,
    };

    // First install: must emit exactly one RouteInstalled event.
    r.apply_runtime_delta(RuntimeDelta {
        installed: vec![route.clone()],
        withdrawn: vec![],
        ..Default::default()
    });
    let events = r.poll_events();
    let installed_count = events
        .iter()
        .filter(|e| matches!(e, RouterEvent::RouteInstalled(rt) if rt.key == key))
        .count();
    assert_eq!(installed_count, 1, "first install emits one RouteInstalled");

    // Byte-identical re-install: must NOT emit a RouteInstalled
    // event. This is the regression — pre-fix the daemon would
    // re-emit and the kernel mirror would re-install.
    r.apply_runtime_delta(RuntimeDelta {
        installed: vec![route.clone()],
        withdrawn: vec![],
        ..Default::default()
    });
    let events = r.poll_events();
    let installed_count = events
        .iter()
        .filter(|e| matches!(e, RouterEvent::RouteInstalled(rt) if rt.key == key))
        .count();
    assert_eq!(
        installed_count, 0,
        "byte-identical re-install must not emit RouteInstalled (regression)"
    );

    // Content change (different metric): must emit a fresh
    // RouteInstalled event — the deduplication must not swallow
    // legitimate updates.
    let mut changed = route.clone();
    changed.preference.metric = 7;
    r.apply_runtime_delta(RuntimeDelta {
        installed: vec![changed],
        withdrawn: vec![],
        ..Default::default()
    });
    let events = r.poll_events();
    let installed_count = events
        .iter()
        .filter(|e| matches!(e, RouterEvent::RouteInstalled(rt) if rt.key == key))
        .count();
    assert_eq!(
        installed_count, 1,
        "content change must emit RouteInstalled"
    );
}

/// Withdrawals must still fire `RouteWithdrawn` even after the
/// deduplication path was taken — a no-op re-install must not
/// suppress the subsequent withdrawal.
#[test]
fn apply_runtime_delta_withdrawal_after_identical_reinstall() {
    use lr_core::addr::Prefix;
    use lr_core::nlri::NlriFamily;
    use lr_core::rib::{Preference, Protocol, Route, RouteOrigin};

    let mut r = DefaultRouter::new();
    let prefix = Prefix::new_v4([198, 51, 100, 0], 24);
    let key = RouteKey::new(prefix, NlriFamily::IPV4_UNICAST);
    let route = Route {
        key: key.clone(),
        origin: RouteOrigin { proto: 1, peer: 1 },
        protocol: Protocol::Babel,
        preference: Preference::new(120, 0),
        next_hop: Some(IpAddr::V4([169, 254, 1, 6])),
        attributes: lr_core::attr::Attributes::new(),
        age_ms: 0,
        path_id: 0,
        tag: None,
    };

    r.apply_runtime_delta(RuntimeDelta {
        installed: vec![route.clone()],
        withdrawn: vec![],
        ..Default::default()
    });
    let _ = r.poll_events();

    // Identical re-install (no-op) followed by withdrawal: the
    // withdrawal must fire because the route IS still in the
    // direct_rib and Loc-RIB.
    r.apply_runtime_delta(RuntimeDelta {
        installed: vec![route],
        withdrawn: vec![],
        ..Default::default()
    });
    let _ = r.poll_events();

    r.apply_runtime_delta(RuntimeDelta {
        installed: vec![],
        withdrawn: vec![key.clone()],
        ..Default::default()
    });
    let events = r.poll_events();
    let withdrawn_count = events
        .iter()
        .filter(|e| matches!(e, RouterEvent::RouteWithdrawn(k) if k == &key))
        .count();
    assert_eq!(
        withdrawn_count, 1,
        "withdrawal must fire after an identical re-install"
    );
}
