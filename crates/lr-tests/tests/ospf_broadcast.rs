//! RFC 2328 §10.4 adjacency gating on broadcast segments.
//!
//! The daemon runs the §9.4 DR/BDR election and pushes the elected
//! pair into each session via `set_ospf_dr_state`; these tests drive
//! the router side directly: a bidirectional neighbor must stay at
//! 2-Way until the elected DR/BDR relationship makes the adjacency
//! viable, must advance to ExStart (queuing the initial DBD) when it
//! does, and must demote back to 2-Way when the DR/BDR relationship
//! goes away (§9.4 step 7).

use lr_core::addr::{Prefix, RouterId};
use lr_router::{DefaultRouter, OspfNetworkType, RouterInstance, SessionConfig, SessionHandle};

fn broadcast_config(our_rid: [u8; 4], our_ip: u32, peer_ip: u32) -> SessionConfig {
    SessionConfig::ospfv2(RouterId::from_v4(our_rid), 0)
        .with_ospf_network_type(OspfNetworkType::Broadcast)
        .with_ospf_interface_ip(our_ip)
        .with_ospf_neighbor_ip(peer_ip)
}

/// A Hello from `peer_rid` (at `peer_ip` claims) listing us — §9.5.4.
fn hello_bytes(peer_rid: [u8; 4], lists_us: bool) -> Vec<u8> {
    let pkt = lr_ospf::packet::OspfPacket {
        header: lr_ospf::packet::OspfHeader {
            version: 2,
            kind: lr_ospf::packet::OspfPacketType::Hello as u8,
            length: 0,
            router_id: u32::from_be_bytes(peer_rid),
            area_id: 0,
            checksum: 0,
            au_type_or_instance: 0,
            auth_data: 0,
        },
        body: lr_ospf::packet::OspfBody::Hello(lr_ospf::packet::HelloBody {
            network_mask: 0xffff_ff00,
            hello_interval: 10,
            options: 0x02,
            priority: 1,
            dead_interval: 40,
            dr: 0,
            bdr: 0,
            neighbors: if lists_us {
                vec![u32::from_be_bytes([1, 1, 1, 1])]
            } else {
                vec![]
            },
        }),
    };
    let mut bytes = lr_ospf::codec::OspfCodec::v2().encode_vec(&pkt).unwrap();
    assert!(lr_ospf::origination::finalize_v2_packet(&mut bytes));
    bytes
}

fn ospf_session_state(r: &DefaultRouter, h: SessionHandle) -> String {
    r.session_summaries()
        .into_iter()
        .find(|s| s.handle == h)
        .expect("session exists")
        .state
        .to_string()
}

/// §10.4 + §9.4: without an elected DR (the interface is Waiting), a
/// bidirectional neighbor on a broadcast segment must stay at 2-Way —
/// no DBD is emitted.
#[test]
fn broadcast_stays_two_way_before_election() {
    let mut r = DefaultRouter::new();
    // our interface IP 10.99.1.1, neighbor at 10.99.1.2.
    let h = r
        .add_session(broadcast_config([1, 1, 1, 1], 0x0a63_0101, 0x0a63_0102))
        .unwrap();
    // Two Hellos: the second one (listing us again) completes 2-Way.
    r.feed_input(h, &hello_bytes([2, 2, 2, 2], true)).unwrap();
    r.feed_input(h, &hello_bytes([2, 2, 2, 2], true)).unwrap();
    assert_eq!(ospf_session_state(&r, h), "2-Way");
    assert!(r.drain_output(h).is_empty(), "no DBD without a DR");
}

/// When the neighbor is the elected DR, the §10.4 gate opens: the
/// session advances to ExStart and the initial DBD is queued.
#[test]
fn broadcast_adjacent_when_neighbor_is_dr() {
    let mut r = DefaultRouter::new();
    let h = r
        .add_session(broadcast_config([1, 1, 1, 1], 0x0a63_0101, 0x0a63_0102))
        .unwrap();
    r.feed_input(h, &hello_bytes([2, 2, 2, 2], true)).unwrap();
    r.feed_input(h, &hello_bytes([2, 2, 2, 2], true)).unwrap();
    assert_eq!(ospf_session_state(&r, h), "2-Way");

    // The daemon's election reports the neighbor (10.99.1.2) as DR.
    r.set_ospf_dr_state(h, 0x0a63_0102, 0).unwrap();
    assert_eq!(ospf_session_state(&r, h), "ExStart");
    assert!(
        !r.drain_output(h).is_empty(),
        "entering ExStart queues the initial DBD (§10.3)"
    );
}

/// When we ourselves are the elected DR, every bidirectional neighbor
/// is adjacent (§10.4: "the router itself is the Designated Router").
#[test]
fn broadcast_adjacent_when_we_are_dr() {
    let mut r = DefaultRouter::new();
    let h = r
        .add_session(broadcast_config([1, 1, 1, 1], 0x0a63_0101, 0x0a63_0102))
        .unwrap();
    r.feed_input(h, &hello_bytes([2, 2, 2, 2], true)).unwrap();
    r.feed_input(h, &hello_bytes([2, 2, 2, 2], true)).unwrap();
    r.set_ospf_dr_state(h, 0x0a63_0101, 0x0a63_0102).unwrap();
    assert_eq!(ospf_session_state(&r, h), "ExStart");
}

/// §9.4 step 7 / §10.3: a DR/BDR relationship change re-runs the §10.4
/// decision — a neighbor that no longer qualifies demotes back to
/// 2-Way (BIRD's INM_ADJOK demotion).
#[test]
fn broadcast_demotes_when_dr_relationship_dies() {
    let mut r = DefaultRouter::new();
    let h = r
        .add_session(broadcast_config([1, 1, 1, 1], 0x0a63_0101, 0x0a63_0102))
        .unwrap();
    r.feed_input(h, &hello_bytes([2, 2, 2, 2], true)).unwrap();
    r.feed_input(h, &hello_bytes([2, 2, 2, 2], true)).unwrap();
    r.set_ospf_dr_state(h, 0x0a63_0102, 0).unwrap();
    assert_eq!(ospf_session_state(&r, h), "ExStart");

    // The DR dies; a new election nobody wins (neither identity elected).
    r.set_ospf_dr_state(h, 0x0a63_0199, 0x0a63_0198).unwrap();
    assert_eq!(ospf_session_state(&r, h), "2-Way");
}

/// set_ospf_dr_state is fail-closed: unknown handles and non-OSPF
/// sessions are rejected.
#[test]
fn set_ospf_dr_state_fail_closed() {
    let mut r = DefaultRouter::new();
    let h = r
        .add_session(broadcast_config([1, 1, 1, 1], 0x0a63_0101, 0x0a63_0102))
        .unwrap();
    assert!(r.set_ospf_dr_state(SessionHandle(9999), 0, 0).is_err());
    // A BGP session is not an OSPF session.
    let bgp = r
        .add_session(SessionConfig::bgp(
            lr_core::addr::Asn(1),
            lr_core::addr::Asn(2),
            RouterId::from_v4([9, 9, 9, 9]),
        ))
        .unwrap();
    assert!(r.set_ospf_dr_state(bgp, 0, 0).is_err());
    let _ = h;
}

/// Point-to-point behavior is unchanged: bidirectional neighbors
/// always adjoint (§10.4), with no DR knowledge needed.
#[test]
fn point_to_point_adjacent_without_dr() {
    let mut r = DefaultRouter::new();
    let h = r
        .add_session(SessionConfig::ospfv2(RouterId::from_v4([1, 1, 1, 1]), 0))
        .unwrap();
    r.feed_input(h, &hello_bytes([2, 2, 2, 2], true)).unwrap();
    r.feed_input(h, &hello_bytes([2, 2, 2, 2], true)).unwrap();
    assert_eq!(ospf_session_state(&r, h), "ExStart");
}

/// A DBD arriving while we are a DR-Other at 2-Way with another
/// DR-Other must not open the exchange (§10.6 via BIRD's INM_2WAYREC —
/// the DBD fires 2-Way Received, and the §10.4 decision then refuses).
#[test]
fn broadcast_dbd_does_not_bypass_the_gate() {
    let mut r = DefaultRouter::new();
    let h = r
        .add_session(broadcast_config([1, 1, 1, 1], 0x0a63_0101, 0x0a63_0102))
        .unwrap();
    r.feed_input(h, &hello_bytes([2, 2, 2, 2], true)).unwrap();
    r.feed_input(h, &hello_bytes([2, 2, 2, 2], true)).unwrap();
    assert_eq!(ospf_session_state(&r, h), "2-Way");

    // A DBD from the DR-Other neighbor while the gate is closed.
    let dbd = lr_ospf::packet::OspfPacket {
        header: lr_ospf::packet::OspfHeader {
            version: 2,
            kind: lr_ospf::packet::OspfPacketType::DatabaseDescription as u8,
            length: 0,
            router_id: u32::from_be_bytes([2, 2, 2, 2]),
            area_id: 0,
            checksum: 0,
            au_type_or_instance: 0,
            auth_data: 0,
        },
        body: lr_ospf::packet::OspfBody::DbDesc(lr_ospf::packet::DbDescBody {
            mtu: 1500,
            options: 0x02,
            flags: 0x07, // I|M|MS — the master's initial DBD
            dd_seq: 0x1234_5678,
            lsa_headers: vec![],
        }),
    };
    let mut bytes = lr_ospf::codec::OspfCodec::v2().encode_vec(&dbd).unwrap();
    assert!(lr_ospf::origination::finalize_v2_packet(&mut bytes));
    r.feed_input(h, &bytes).unwrap();
    assert_eq!(
        ospf_session_state(&r, h),
        "2-Way",
        "the §10.4 gate must hold even against DBDs"
    );
}

/// The SPF consumes Network-LSAs (§12.4.2) and derives the transit
/// network's own prefix (LS ID masked by the network mask) — the
/// broadcast counterpart of a stub link.
#[test]
fn network_lsa_derives_transit_prefix_route() {
    use lr_ospf::lsa::{Lsa, LsaHeader, LsaTypeV2};
    use lr_ospf::packet::{LsUpdateBody, OspfHeader, OspfPacket};

    let mut r = DefaultRouter::new();
    let h = r
        .add_session(SessionConfig::ospfv2(RouterId::from_v4([1, 1, 1, 1]), 0))
        .unwrap();

    // The DR (2.2.2.2, interface address 10.99.1.2) originates the
    // Network-LSA for 10.99.1.0/24 with both routers attached.
    let mut body: Vec<u8> = Vec::new();
    body.extend_from_slice(&0xffff_ff00u32.to_be_bytes()); // mask
    body.extend_from_slice(&u32::from_be_bytes([2, 2, 2, 2]).to_be_bytes());
    body.extend_from_slice(&u32::from_be_bytes([1, 1, 1, 1]).to_be_bytes());
    let lsa = Lsa {
        header: LsaHeader {
            ls_age: 1,
            options: 0x02,
            ls_type: LsaTypeV2::NetworkLsa as u16,
            link_state_id: 0x0a63_0102, // the DR's interface address
            advertising_router: u32::from_be_bytes([2, 2, 2, 2]),
            ls_sequence_number: 0x8000_0001,
            ls_checksum: 0,
            length: (body.len() as u16) + 20,
        },
        body,
    };
    // A transit link from our own (stub-described) router-LSA into the
    // segment so the Network vertex is reachable in SPF.
    let rlsa = lr_ospf::origination::originate_router_lsa(
        u32::from_be_bytes([1, 1, 1, 1]),
        &[lr_ospf::origination::RouterLsaLink::Transit {
            dr_addr: 0x0a63_0102,
            local_addr: 0x0a63_0101,
            metric: 10,
        }],
        None,
    )
    .unwrap();
    let pkt = OspfPacket {
        header: OspfHeader {
            version: 2,
            kind: 4, // LS-Update
            length: 0,
            router_id: u32::from_be_bytes([2, 2, 2, 2]),
            area_id: 0,
            checksum: 0,
            au_type_or_instance: 0,
            auth_data: 0,
        },
        body: lr_ospf::packet::OspfBody::LsUpdate(LsUpdateBody {
            lsa_count: 2,
            lsas: vec![rlsa, lsa],
        }),
    };
    let mut bytes = lr_ospf::codec::OspfCodec::v2().encode_vec(&pkt).unwrap();
    assert!(lr_ospf::origination::finalize_v2_packet(&mut bytes));
    r.feed_input(h, &bytes).unwrap();

    let snap = r.rib_snapshot();
    assert!(
        snap.iter()
            .any(|rt| rt.key.prefix == Prefix::new_v4([10, 99, 1, 0], 24)),
        "the transit network's own prefix must be installed, got {:?}",
        snap.iter().map(|rt| rt.key.prefix).collect::<Vec<_>>()
    );
}
