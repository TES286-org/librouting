//! End-to-end OSPF virtual-link tests (RFC 2328 §15): backbone repair
//! for an ABR without a physical backbone attachment, inter-area
//! summaries flowing over the virtual adjacency, and the link lifecycle
//! (up via transit-area reachability, down when the transit area is
//! lost, refused through stub areas).
//!
//! Topology: R1 (areas 1+2, no backbone) --transit area 1-- R2
//! (areas 0+1) --backbone-- R3 (area 0). The virtual link R1 <--> R2
//! rides through area 1.

use lr_core::addr::{Prefix, RouterId};
use lr_ospf::lsa::{Lsa, LsaHeader, LsaTypeV2};
use lr_ospf::packet::{LsUpdateBody, OspfBody, OspfHeader, OspfPacket, OspfPacketType};
use lr_router::{DefaultRouter, OspfAreaType, RouterInstance, SessionConfig, SessionHandle};

const R1: u32 = 0x0101_0101; // ABR without a physical backbone attachment
const R2: u32 = 0x0202_0202; // ABR with the real backbone
const R3: u32 = 0x0303_0303; // backbone router (stub net 10.30.30.0/24)
const P2P: u8 = 1;
const STUB_NET: u8 = 3;
const VIRTUAL: u8 = 4;

const TRANSIT_COST: u16 = 4; // R1 -- R2 through area 1
const BACKBONE_COST: u16 = 3; // R2 -- R3 in area 0

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
        header: LsaHeader {
            ls_age: 0,
            options: 0x02,
            ls_type: LsaTypeV2::RouterLsa as u8,
            link_state_id: rid,
            advertising_router: rid,
            ls_sequence_number: 0x8000_0001,
            ls_checksum: 0,
            length: (LsaHeader::LEN + body.len()) as u16,
        },
        body,
    }
}

fn lsu(sender: u32, area: u32, lsas: Vec<Lsa>) -> Vec<u8> {
    let packet = OspfPacket {
        header: OspfHeader {
            version: 2,
            kind: OspfPacketType::LinkStateUpdate as u8,
            length: 0,
            router_id: sender,
            area_id: area,
            checksum: 0,
            au_type_or_instance: 0,
            auth_data: 0,
        },
        body: OspfBody::LsUpdate(LsUpdateBody {
            lsa_count: lsas.len() as u32,
            lsas,
        }),
    };
    lr_ospf::codec::OspfCodec::v2()
        .encode_vec(&packet)
        .expect("encode LS-Update")
}

/// Router-LSAs of the topology. The transit-area LSAs carry the V-bit
/// (flags 0x04, RFC 2328 §12.4.1); the backbone LSAs describe the
/// virtual link as a type-4 link whose metric is the transit-area path
/// cost (§15).
fn transit_lsa_r1() -> Lsa {
    // V-bit set: active virtual-link endpoint.
    let mut body = Vec::new();
    body.extend_from_slice(&(0x04u16 << 8).to_be_bytes());
    body.extend_from_slice(&1u16.to_be_bytes());
    body.extend_from_slice(&R2.to_be_bytes());
    body.extend_from_slice(&0u32.to_be_bytes());
    body.push(P2P);
    body.push(0);
    body.extend_from_slice(&TRANSIT_COST.to_be_bytes());
    Lsa {
        header: LsaHeader {
            ls_age: 0,
            options: 0x02,
            ls_type: LsaTypeV2::RouterLsa as u8,
            link_state_id: R1,
            advertising_router: R1,
            ls_sequence_number: 0x8000_0001,
            ls_checksum: 0,
            length: (LsaHeader::LEN + body.len()) as u16,
        },
        body,
    }
}

fn transit_lsa_r2() -> Lsa {
    let mut body = Vec::new();
    body.extend_from_slice(&(0x04u16 << 8).to_be_bytes());
    body.extend_from_slice(&1u16.to_be_bytes());
    body.extend_from_slice(&R1.to_be_bytes());
    body.extend_from_slice(&0u32.to_be_bytes());
    body.push(P2P);
    body.push(0);
    body.extend_from_slice(&TRANSIT_COST.to_be_bytes());
    Lsa {
        header: LsaHeader {
            ls_age: 0,
            options: 0x02,
            ls_type: LsaTypeV2::RouterLsa as u8,
            link_state_id: R2,
            advertising_router: R2,
            ls_sequence_number: 0x8000_0001,
            ls_checksum: 0,
            length: (LsaHeader::LEN + body.len()) as u16,
        },
        body,
    }
}

/// R1's backbone router-LSA: only the virtual link to R2.
fn backbone_lsa_r1() -> Lsa {
    router_lsa(R1, vec![(R2, 0, VIRTUAL, TRANSIT_COST)])
}

/// R2's backbone router-LSA: physical link to R3 plus the virtual link.
fn backbone_lsa_r2() -> Lsa {
    router_lsa(
        R2,
        vec![(R3, 0, P2P, BACKBONE_COST), (R1, 0, VIRTUAL, TRANSIT_COST)],
    )
}

fn backbone_lsa_r3() -> Lsa {
    router_lsa(
        R3,
        vec![
            (R2, 0, P2P, BACKBONE_COST),
            (0x0a1e_1e00, 0xffff_ff00, STUB_NET, 2),
        ],
    )
}

/// R1's area-2 router-LSA: a lone stub network 10.50.50.0/24.
fn area2_lsa_r1() -> Lsa {
    router_lsa(R1, vec![(0x0a32_3200, 0xffff_ff00, STUB_NET, 2)])
}

fn r3_stub_net() -> Prefix {
    Prefix::new_v4([10, 30, 30, 0], 24)
}

fn r1_area2_net() -> Prefix {
    Prefix::new_v4([10, 50, 50, 0], 24)
}

fn rib_metric(r: &DefaultRouter, p: Prefix) -> Option<u32> {
    r.rib_snapshot()
        .iter()
        .find(|rt| rt.key.prefix == p)
        .map(|rt| rt.preference.metric)
}

fn rib_has(r: &DefaultRouter, p: Prefix) -> bool {
    r.rib_snapshot().iter().any(|rt| rt.key.prefix == p)
}

struct Topology {
    r1: DefaultRouter,
    r1_transit: SessionHandle,
    r2: DefaultRouter,
    r2_bb: SessionHandle,
    r2_transit: SessionHandle,
    r3: DefaultRouter,
    r3_bb: SessionHandle,
    /// The two virtual-link sessions (R1's and R2's), wired by `pump`.
    vlink_r1: Option<SessionHandle>,
    vlink_r2: Option<SessionHandle>,
}

impl Topology {
    fn new() -> Self {
        let mut r1 = DefaultRouter::new();
        let r1_transit = r1
            .add_session(SessionConfig::ospfv2(RouterId::from_u32(R1), 1))
            .unwrap();
        let r1_area2 = r1
            .add_session(SessionConfig::ospfv2(RouterId::from_u32(R1), 2))
            .unwrap();
        let mut r2 = DefaultRouter::new();
        let r2_bb = r2
            .add_session(SessionConfig::ospfv2(RouterId::from_u32(R2), 0))
            .unwrap();
        let r2_transit = r2
            .add_session(SessionConfig::ospfv2(RouterId::from_u32(R2), 1))
            .unwrap();
        let mut r3 = DefaultRouter::new();
        let r3_bb = r3
            .add_session(SessionConfig::ospfv2(RouterId::from_u32(R3), 0))
            .unwrap();

        // Sync the transit area and the physical backbone first: the
        // virtual link can only come up once R2 is reachable through
        // area 1.
        r1.feed_input(r1_transit, &lsu(R1, 1, vec![transit_lsa_r1()]))
            .unwrap();
        r2.feed_input(r2_transit, &lsu(R2, 1, vec![transit_lsa_r2()]))
            .unwrap();
        r1.feed_input(r1_transit, &lsu(R2, 1, vec![transit_lsa_r2()]))
            .unwrap();
        r2.feed_input(r2_transit, &lsu(R1, 1, vec![transit_lsa_r1()]))
            .unwrap();
        r2.feed_input(r2_bb, &lsu(R2, 0, vec![backbone_lsa_r2()]))
            .unwrap();
        r3.feed_input(r3_bb, &lsu(R3, 0, vec![backbone_lsa_r3()]))
            .unwrap();
        r2.feed_input(r2_bb, &lsu(R3, 0, vec![backbone_lsa_r3()]))
            .unwrap();
        r3.feed_input(r3_bb, &lsu(R2, 0, vec![backbone_lsa_r2()]))
            .unwrap();
        r1.feed_input(r1_area2, &lsu(R1, 2, vec![area2_lsa_r1()]))
            .unwrap();

        let mut t = Self {
            r1,
            r1_transit,
            r2,
            r2_bb,
            r2_transit,
            r3,
            r3_bb,
            vlink_r1: None,
            vlink_r2: None,
        };
        t.pump();
        t
    }

    /// Bring the virtual link up on both endpoints.
    fn add_virtual_links(&mut self) {
        assert!(
            self.r1.ospf_add_virtual_link(1, R2),
            "virtual link R1 -> R2 must configure"
        );
        assert!(
            self.r2.ospf_add_virtual_link(1, R1),
            "virtual link R2 -> R1 must configure"
        );
        assert!(self.r1.ospf_virtual_link_up(1, R2));
        assert!(self.r2.ospf_virtual_link_up(1, R1));
        self.vlink_r1 = self.r1.ospf_virtual_link_session(1, R2);
        self.vlink_r2 = self.r2.ospf_virtual_link_session(1, R1);
        assert!(self.vlink_r1.is_some() && self.vlink_r2.is_some());
        // R1's backbone router-LSA enters its (virtual) backbone LSDB
        // and floods to R2; R2 re-floods it to R3.
        let v = self.vlink_r1.unwrap();
        self.r1
            .feed_input(v, &lsu(R1, 0, vec![backbone_lsa_r1()]))
            .unwrap();
        self.pump();
    }

    /// Pump every wired link to quiescence (bounded), including the
    /// virtual-link tunnels. The virtual sessions are re-looked-up
    /// every round — they appear and disappear with the link state
    /// (asymmetrically on the two endpoints while LSAs age out).
    fn pump(&mut self) {
        for _ in 0..24 {
            let r1_to_r2 = self.r1.drain_output(self.r1_transit);
            let r2_to_r1 = self.r2.drain_output(self.r2_transit);
            let r2_to_r3 = self.r2.drain_output(self.r2_bb);
            let r3_to_r2 = self.r3.drain_output(self.r3_bb);
            let v1 = self.r1.ospf_virtual_link_session(1, R2);
            let v2 = self.r2.ospf_virtual_link_session(1, R1);
            let v1_out = v1.map(|h| self.r1.drain_output(h)).unwrap_or_default();
            let v2_out = v2.map(|h| self.r2.drain_output(h)).unwrap_or_default();
            let quiet = r1_to_r2.is_empty()
                && r2_to_r1.is_empty()
                && r2_to_r3.is_empty()
                && r3_to_r2.is_empty()
                && v1_out.is_empty()
                && v2_out.is_empty();
            if !r1_to_r2.is_empty() {
                // Tolerant feeds: sessions removed mid-test (torn-down
                // links) must not abort the pump — the peer's output is
                // simply dropped, like a dead wire.
                let _ = self.r2.feed_input(self.r2_transit, &r1_to_r2);
            }
            if !r2_to_r1.is_empty() {
                let _ = self.r1.feed_input(self.r1_transit, &r2_to_r1);
            }
            if !r2_to_r3.is_empty() {
                self.r3.feed_input(self.r3_bb, &r2_to_r3).unwrap();
            }
            if !r3_to_r2.is_empty() {
                self.r2.feed_input(self.r2_bb, &r3_to_r2).unwrap();
            }
            // The virtual link: R1's backbone output tunnels to R2 and
            // vice versa (RFC 2328 §15 — the transport rides through the
            // transit area; in-process the direct wiring is equivalent).
            if !v1_out.is_empty() {
                if let Some(h) = v2 {
                    self.r2.feed_input(h, &v1_out).unwrap();
                }
            }
            if !v2_out.is_empty() {
                if let Some(h) = v1 {
                    self.r1.feed_input(h, &v2_out).unwrap();
                }
            }
            if quiet {
                break;
            }
        }
    }
}

#[test]
fn virtual_link_repairs_the_backbone_partition() {
    let mut t = Topology::new();

    // Before the virtual link: R1 has no backbone attachment, is not an
    // ABR and area 2 stays invisible to the backbone (R1 already sees
    // the backbone's networks through R2's area-1 summaries — that is
    // plain multi-area behaviour, not virtual-link dependent).
    assert!(!rib_has(&t.r3, r1_area2_net()));

    t.add_virtual_links();

    // R1's area-2 network reaches R3 through the virtual backbone:
    // summary metric 2 (R1's intra cost) + R3's cost to R1
    // (3 to R2 + 4 over the virtual link) = 9.
    assert_eq!(rib_metric(&t.r3, r1_area2_net()), Some(9));

    // R3's backbone stub reaches R1 through R2's summary into area 1:
    // 5 (R2's intra cost) + 4 (R1 to R2 through the transit area) = 9.
    assert_eq!(rib_metric(&t.r1, r3_stub_net()), Some(9));

    // Both endpoints report the link up and route each other's transit.
    assert!(t.r1.ospf_virtual_link_up(1, R2));
    assert!(t.r2.ospf_virtual_link_up(1, R1));
    assert!(rib_has(&t.r1, r3_stub_net()));

    // R2 also routes the area-2 network (its own virtual adjacency).
    assert_eq!(rib_metric(&t.r2, r1_area2_net()), Some(6));
}

#[test]
fn virtual_link_down_when_transit_area_is_lost() {
    let mut t = Topology::new();
    t.add_virtual_links();
    assert_eq!(rib_metric(&t.r3, r1_area2_net()), Some(9));

    // Losing the transit area tears the virtual link down: R1 stops
    // being an ABR and its own view of the backbone goes with it.
    assert!(t.r1.remove_session(t.r1_transit).is_ok());
    t.pump();

    assert!(
        !t.r1.ospf_virtual_link_up(1, R2),
        "the virtual link must fall with its transit area"
    );
    assert!(!rib_has(&t.r1, r3_stub_net()));
    // A disconnected originator cannot flush its LSAs (RFC 2328 §14):
    // R3 keeps the stale summary until it ages out at MaxAge.
    assert_eq!(rib_metric(&t.r3, r1_area2_net()), Some(9));
    for r in [&mut t.r1, &mut t.r2, &mut t.r3] {
        r.tick(lr_core::time::Instant(3_700_000));
    }
    t.pump();
    assert!(
        !rib_has(&t.r3, r1_area2_net()),
        "the aged-out summary must leave R3's table"
    );
    // R2 keeps its physical backbone view.
    assert!(rib_has(&t.r3, r3_stub_net()));
}

#[test]
fn virtual_link_refused_through_stub_area_and_bad_endpoints() {
    let mut r = DefaultRouter::new();
    let rid = RouterId::from_u32(R1);
    let _stub_area = r
        .add_session(SessionConfig::ospfv2(rid, 7).with_ospf_area_type(OspfAreaType::stub(10)))
        .unwrap();
    let _normal_area = r.add_session(SessionConfig::ospfv2(rid, 8)).unwrap();
    // RFC 2328 §15: virtual links cannot cross stub areas.
    assert!(!r.ospf_add_virtual_link(7, R2));
    // Unknown transit areas and self-endpoints are refused too.
    assert!(!r.ospf_add_virtual_link(9, R2));
    assert!(!r.ospf_add_virtual_link(8, R1));
    // A regular transit area configures fine (but stays down: the
    // endpoint is not reachable in the empty area).
    assert!(r.ospf_add_virtual_link(8, R2));
    assert!(!r.ospf_virtual_link_up(8, R2));
    assert!(r.ospf_virtual_link_session(8, R2).is_none());
    // Removal of a non-existent link reports false.
    assert!(!r.ospf_remove_virtual_link(7, R2));
}

#[test]
fn backbone_cannot_be_configured_stub() {
    let mut r = DefaultRouter::new();
    let rid = RouterId::from_u32(R1);
    assert!(
        r.add_session(SessionConfig::ospfv2(rid, 0).with_ospf_area_type(OspfAreaType::stub(10)),)
            .is_err(),
        "the backbone must never become a stub area (RFC 2328 §3.6)"
    );
    // Runtime conversion is refused as well.
    let mut r2 = DefaultRouter::new();
    let h = r2.add_session(SessionConfig::ospfv2(rid, 0)).unwrap();
    let _ = h;
    assert!(!r2.ospf_set_area_type(0, OspfAreaType::nssa(10)));
    // Normal area-0 conversions of the same type are no-ops.
    assert!(!r2.ospf_set_area_type(0, OspfAreaType::Normal));
}
