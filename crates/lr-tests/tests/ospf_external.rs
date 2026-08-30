//! End-to-end OSPF external-route tests (RFC 2328 §12.4.3 / §16.4):
//! type-5 AS-external-LSA origination, AS-scope flooding across an ABR,
//! type-4 summary-ASBR origination, the external route calculation at a
//! remote router, the forwarding-address next hop and the un-redistribute
//! (MaxAge flush) lifecycle.
//!
//! Topology: ASBR-Z (area 1) -- ABR-X (areas 0+1) -- BR-Y (area 0).

use lr_core::addr::{Prefix, RouterId};
use lr_core::rib::Protocol;
use lr_ospf::external::{ExternalDestination, ExternalMetricType};
use lr_ospf::lsa::{Lsa, LsaHeader, LsaTypeV2};
use lr_ospf::packet::{LsUpdateBody, OspfBody, OspfHeader, OspfPacket, OspfPacketType};
use lr_router::{DefaultRouter, RouterInstance, SessionConfig, SessionHandle};

const X: u32 = 0x0101_0101; // ABR
const Y: u32 = 0x0303_0303; // backbone router
const Z: u32 = 0x0202_0202; // ASBR in area 1
const P2P: u8 = 1;
const STUB: u8 = 3;

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
            ls_type: LsaTypeV2::RouterLsa as u16,
            link_state_id: rid,
            advertising_router: rid,
            ls_sequence_number: 0x8000_0001,
            ls_checksum: 0,
            length: (LsaHeader::LEN + body.len()) as u16,
        },
        body,
    }
}

/// Encode one LS-Update carrying `lsas` as if sent by `sender` in `area`.
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
    let mut bytes = lr_ospf::codec::OspfCodec::v2()
        .encode_vec(&packet)
        .expect("encode LS-Update");
    // The codec zeroes the packet checksum; the router validates it on
    // receive (RFC 2328 §8.2), so finalize before feeding.
    assert!(lr_ospf::origination::finalize_v2_packet(&mut bytes));
    bytes
}

/// The three-router topology with LSDBs primed to convergence before any
/// external is redistributed.
struct Topology {
    abr: DefaultRouter,
    abr_bb: SessionHandle,
    abr_a1: SessionHandle,
    br_y: DefaultRouter,
    y_bb: SessionHandle,
    asbr: DefaultRouter,
    z_a1: SessionHandle,
}

impl Topology {
    fn new() -> Self {
        let mut abr = DefaultRouter::new();
        let abr_bb = abr
            .add_session(SessionConfig::ospfv2(RouterId::from_u32(X), 0))
            .unwrap();
        let abr_a1 = abr
            .add_session(SessionConfig::ospfv2(RouterId::from_u32(X), 1))
            .unwrap();
        let mut br_y = DefaultRouter::new();
        let y_bb = br_y
            .add_session(SessionConfig::ospfv2(RouterId::from_u32(Y), 0))
            .unwrap();
        let mut asbr = DefaultRouter::new();
        let z_a1 = asbr
            .add_session(SessionConfig::ospfv2(RouterId::from_u32(Z), 1))
            .unwrap();

        // Self-origination of router-LSAs (the poll-driven model leaves
        // origination to the embedder), then cross-feeding so every LSDB
        // sees every LSA of its area.
        let x_bb = router_lsa(X, vec![(Y, 0, P2P, 3)]);
        let x_a1 = router_lsa(X, vec![(Z, 0, P2P, 5)]);
        let y_lsa = router_lsa(Y, vec![(X, 0, P2P, 3), (0x0a1e_1e00, 0xffff_ff00, STUB, 2)]);
        let z_lsa = router_lsa(Z, vec![(X, 0, P2P, 5)]);

        br_y.feed_input(y_bb, &lsu(Y, 0, vec![y_lsa.clone()]))
            .unwrap();
        abr.feed_input(abr_bb, &lsu(X, 0, vec![x_bb.clone()]))
            .unwrap();
        abr.feed_input(abr_a1, &lsu(X, 1, vec![x_a1.clone()]))
            .unwrap();
        asbr.feed_input(z_a1, &lsu(Z, 1, vec![z_lsa.clone()]))
            .unwrap();
        // Cross-feed: X<->Y in area 0, X<->Z in area 1.
        br_y.feed_input(y_bb, &lsu(X, 0, vec![x_bb.clone()]))
            .unwrap();
        abr.feed_input(abr_bb, &lsu(Y, 0, vec![y_lsa.clone()]))
            .unwrap();
        asbr.feed_input(z_a1, &lsu(X, 1, vec![x_a1.clone()]))
            .unwrap();
        abr.feed_input(abr_a1, &lsu(Z, 1, vec![z_lsa.clone()]))
            .unwrap();

        let mut t = Self {
            abr,
            abr_bb,
            abr_a1,
            br_y,
            y_bb,
            asbr,
            z_a1,
        };
        t.pump();
        t
    }

    /// Pump every wired link to quiescence (bounded).
    fn pump(&mut self) {
        for _ in 0..16 {
            let x_to_y = self.abr.drain_output(self.abr_bb);
            let y_to_x = self.br_y.drain_output(self.y_bb);
            let x_to_z = self.abr.drain_output(self.abr_a1);
            let z_to_x = self.asbr.drain_output(self.z_a1);
            let quiet =
                x_to_y.is_empty() && y_to_x.is_empty() && x_to_z.is_empty() && z_to_x.is_empty();
            if !x_to_y.is_empty() {
                self.br_y.feed_input(self.y_bb, &x_to_y).unwrap();
            }
            if !y_to_x.is_empty() {
                self.abr.feed_input(self.abr_bb, &y_to_x).unwrap();
            }
            if !x_to_z.is_empty() {
                self.asbr.feed_input(self.z_a1, &x_to_z).unwrap();
            }
            if !z_to_x.is_empty() {
                self.abr.feed_input(self.abr_a1, &z_to_x).unwrap();
            }
            if quiet {
                break;
            }
        }
    }
}

fn external_net() -> Prefix {
    Prefix::new_v4([198, 51, 100, 0], 24)
}

#[test]
fn ospf_external_propagates_as_scope_with_type4_asbr_leg() {
    let mut t = Topology::new();

    // ASBR-Z redistributes a type-2 external (metric 40).
    assert!(t.asbr.ospf_redistribute(ExternalDestination::new(
        external_net(),
        40,
        ExternalMetricType::Type2,
    )));
    t.pump();

    // BR-Y resolves the external through: type-5 (re-flooded by the ABR
    // at AS scope) + type-4 summary-ASBR (Z via X at metric 5; Y's cost
    // to X is 3 → internal cost 8). Type-2 metric is the external one.
    let snap = t.br_y.rib_snapshot();
    let ext = snap
        .iter()
        .find(|rt| rt.key.prefix == external_net())
        .expect("external route reached BR-Y through the ABR");
    assert_eq!(ext.preference.metric, 40, "type-2 metric is external-only");
    assert_eq!(ext.protocol, Protocol::Ospfv2);
    assert_eq!(
        ext.next_hop, None,
        "no forwarding address: next hop is the ASBR"
    );

    // The ABR itself also routes the external (Z intra-reachable in
    // area 1 at metric 5).
    let snap_x = t.abr.rib_snapshot();
    let ext_x = snap_x
        .iter()
        .find(|rt| rt.key.prefix == external_net())
        .expect("external route on the ABR");
    assert_eq!(ext_x.preference.metric, 40);

    // The ASBR keeps its own redistribution in the table.
    let snap_z = t.asbr.rib_snapshot();
    assert!(snap_z.iter().any(|rt| rt.key.prefix == external_net()));
}

#[test]
fn ospf_external_type1_sums_internal_and_external_cost() {
    let mut t = Topology::new();
    assert!(t.asbr.ospf_redistribute(ExternalDestination::new(
        external_net(),
        40,
        ExternalMetricType::Type1,
    )));
    t.pump();

    // Type-1 at BR-Y: cost to ASBR (3 to X + 5 via type-4) + 40 = 48.
    let snap = t.br_y.rib_snapshot();
    let ext = snap
        .iter()
        .find(|rt| rt.key.prefix == external_net())
        .expect("type-1 external reached BR-Y");
    assert_eq!(ext.preference.metric, 48);
}

#[test]
fn ospf_external_forwarding_address_sets_next_hop() {
    let mut t = Topology::new();

    // Forwarding address inside BR-Y's intra-area stub 10.30.30.0/24 —
    // reachable at every computing router, so the external is usable and
    // the next hop becomes the forwarding address (§16.4 (c)).
    let mut dest = ExternalDestination::new(external_net(), 40, ExternalMetricType::Type2);
    dest.forwarding_addr = 0x0a1e_1e01; // 10.30.30.1
    assert!(t.asbr.ospf_redistribute(dest));
    t.pump();

    let snap = t.br_y.rib_snapshot();
    let ext = snap
        .iter()
        .find(|rt| rt.key.prefix == external_net())
        .expect("external with reachable forwarding address");
    assert_eq!(
        ext.next_hop,
        Some(lr_core::addr::IpAddr::V4([10, 30, 30, 1])),
        "forwarding address is the next hop"
    );
}

#[test]
fn ospf_unredistribute_flushes_across_the_as() {
    let mut t = Topology::new();
    assert!(t.asbr.ospf_redistribute(ExternalDestination::new(
        external_net(),
        40,
        ExternalMetricType::Type2,
    )));
    t.pump();
    assert!(t
        .br_y
        .rib_snapshot()
        .iter()
        .any(|rt| rt.key.prefix == external_net()));

    // Withdraw: the ASBR MaxAge-flushes its type-5; the flush must
    // propagate through the ABR to BR-Y and the route must leave every
    // Loc-RIB.
    assert!(t.asbr.ospf_unredistribute(external_net()));
    t.pump();

    for (name, snap) in [
        ("BR-Y", t.br_y.rib_snapshot()),
        ("ABR-X", t.abr.rib_snapshot()),
        ("ASBR-Z", t.asbr.rib_snapshot()),
    ] {
        assert!(
            !snap.iter().any(|rt| rt.key.prefix == external_net()),
            "{name} still holds the flushed external"
        );
    }
}

#[test]
fn ospf_external_type1_preferred_over_type2() {
    let mut t = Topology::new();
    // Type-2 with a tiny metric from the ASBR...
    assert!(t.asbr.ospf_redistribute(ExternalDestination::new(
        external_net(),
        1,
        ExternalMetricType::Type2,
    )));
    // ...must lose to a type-1 from the same prefix advertised by the
    // ABR itself (§16.4 (6)). ABR-X is an ASBR of its own now.
    assert!(t.abr.ospf_redistribute(ExternalDestination::new(
        external_net(),
        60,
        ExternalMetricType::Type1,
    )));
    t.pump();

    // At BR-Y both type-5s are present; the type-1 wins despite its
    // larger metric: 3 (to X) + 60 = 63 < type-2's 1.
    let snap = t.br_y.rib_snapshot();
    let ext = snap
        .iter()
        .find(|rt| rt.key.prefix == external_net())
        .expect("external route present");
    assert_eq!(ext.preference.metric, 63, "type-1 must beat type-2");
}
