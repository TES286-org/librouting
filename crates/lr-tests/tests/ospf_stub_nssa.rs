//! End-to-end OSPF stub/NSSA area tests (RFC 2328 §3.6, RFC 3101):
//! stub-area LSA gating + summary-default injection, totally-stubby and
//! totally-NSSA (`no_summary`) variants, NSSA type-7 origination with
//! forwarding-address validation, type-7 → type-5 translation at the
//! elected border router, the type-7 default, the un-redistribute
//! lifecycle and translator election between two border routers.
//!
//! Topology: BR-Y (area 0) -- ABR-X (areas 0+1) -- Z (area 1, stub
//! network 10.40.40.0/24 whose .1 hosts the NSSA forwarding addresses).

use lr_core::addr::{Prefix, RouterId};
use lr_core::rib::Protocol;
use lr_ospf::external::{ExternalDestination, ExternalMetricType};
use lr_ospf::lsa::{Lsa, LsaHeader, LsaTypeV2};
use lr_ospf::packet::{LsUpdateBody, OspfBody, OspfHeader, OspfPacket, OspfPacketType};
use lr_router::{DefaultRouter, OspfAreaType, RouterInstance, SessionConfig, SessionHandle};

const X: u32 = 0x0101_0101; // ABR
const Y: u32 = 0x0303_0303; // backbone router (stub net 10.30.30.0/24)
const Z: u32 = 0x0202_0202; // area-1 router (stub net 10.40.40.0/24, NSSA ASBR)
const P2P: u8 = 1;
const STUB_NET: u8 = 3;

/// Router-LSA test constructor: `(link_id, link_data, link_type, metric)`
/// plus a raw flags byte (B-bit = 0x01 marks border routers, RFC 2328
/// §A.4.2 — used by the translator-election test).
fn router_lsa(rid: u32, flags: u8, links: Vec<(u32, u32, u8, u16)>) -> Lsa {
    let mut body = Vec::new();
    body.extend_from_slice(&(u16::from(flags) << 8).to_be_bytes());
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
    // receive (RFC 2328 §8.2).
    assert!(lr_ospf::origination::finalize_v2_packet(&mut bytes));
    bytes
}

/// Count LSUs in `bytes` carrying a type-5 LSA advertised by `adv`
/// (translator-election observability).
fn count_type5_adv(bytes: &[u8], adv: u32) -> usize {
    use lr_core::codec::Decoder;
    let mut r = lr_core::buf::ReadBuf::new(bytes);
    let mut codec = lr_ospf::codec::OspfCodec::v2();
    let mut n = 0;
    while let Ok(Some(pkt)) = codec.decode(&mut r) {
        if let OspfBody::LsUpdate(u) = &pkt.body {
            n += u
                .lsas
                .iter()
                .filter(|lsa| {
                    lsa.header.ls_type == LsaTypeV2::AsExternalLsa as u16
                        && lsa.header.advertising_router == adv
                })
                .count();
        }
    }
    n
}

/// The three-router topology; area 1 runs the requested `kind`.
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
    fn new(kind: OspfAreaType) -> Self {
        let mut abr = DefaultRouter::new();
        let abr_bb = abr
            .add_session(SessionConfig::ospfv2(RouterId::from_u32(X), 0))
            .unwrap();
        let abr_a1 = abr
            .add_session(SessionConfig::ospfv2(RouterId::from_u32(X), 1).with_ospf_area_type(kind))
            .unwrap();
        let mut br_y = DefaultRouter::new();
        let y_bb = br_y
            .add_session(SessionConfig::ospfv2(RouterId::from_u32(Y), 0))
            .unwrap();
        let mut asbr = DefaultRouter::new();
        let z_a1 = asbr
            .add_session(SessionConfig::ospfv2(RouterId::from_u32(Z), 1).with_ospf_area_type(kind))
            .unwrap();

        // Self-origination of router-LSAs, then cross-feeding so every
        // LSDB sees every LSA of its area.
        let x_bb = router_lsa(X, 0, vec![(Y, 0, P2P, 3)]);
        let x_a1 = router_lsa(X, 0, vec![(Z, 0, P2P, 5)]);
        let y_lsa = router_lsa(
            Y,
            0,
            vec![(X, 0, P2P, 3), (0x0a1e_1e00, 0xffff_ff00, STUB_NET, 2)],
        );
        let z_lsa = router_lsa(
            Z,
            0,
            vec![(X, 0, P2P, 5), (0x0a28_2800, 0xffff_ff00, STUB_NET, 2)],
        );

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

fn default_route() -> Prefix {
    Prefix::new_v4([0, 0, 0, 0], 0)
}

fn y_stub_net() -> Prefix {
    Prefix::new_v4([10, 30, 30, 0], 24)
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

/// Z redistributes a type-2 external (metric 40) with the forwarding
/// address on its own NSSA-internal stub network — translatable
/// (P-bit + non-zero FA, RFC 3101 §2.3/§2.4).
fn redistribute_from_z(t: &mut Topology, p_bit: bool) {
    let mut dest = ExternalDestination::new(external_net(), 40, ExternalMetricType::Type2);
    dest.p_bit = p_bit;
    dest.forwarding_addr = 0x0a28_2801; // 10.40.40.1 (inside Z's stub net)
    assert!(t.asbr.ospf_redistribute(dest));
    t.pump();
}

#[test]
fn stub_area_blocks_type5_and_injects_summary_default() {
    let mut t = Topology::new(OspfAreaType::stub(10));

    // BR-Y redistributes an external: the type-5 floods area 0 but must
    // not enter the stub area.
    assert!(t.br_y.ospf_redistribute(ExternalDestination::new(
        external_net(),
        40,
        ExternalMetricType::Type2,
    )));
    t.pump();

    assert!(
        !rib_has(&t.asbr, external_net()),
        "stub area must not carry the type-5 external"
    );
    assert!(
        rib_has(&t.abr, external_net()),
        "the ABR sees the external through the backbone"
    );
    // ABR-injected summary default: Z's cost to the ABR (5) + metric 10.
    assert_eq!(
        rib_metric(&t.asbr, default_route()),
        Some(15),
        "stub default = cost to ABR + default metric"
    );
    // Plain stub areas still import type-3 summaries (only totally-stubby
    // ones do not): Y's 10.30.30.0/24 at Z = 5 (to X) + 5 (summary).
    assert_eq!(rib_metric(&t.asbr, y_stub_net()), Some(10));
}

#[test]
fn totally_stubby_area_gets_only_the_default() {
    let mut t = Topology::new(OspfAreaType::stub_no_summary(10));

    assert!(t.br_y.ospf_redistribute(ExternalDestination::new(
        external_net(),
        40,
        ExternalMetricType::Type2,
    )));
    t.pump();

    assert_eq!(rib_metric(&t.asbr, default_route()), Some(15));
    assert!(
        !rib_has(&t.asbr, y_stub_net()),
        "no-summary stub areas carry no inter-area summaries"
    );
    assert!(!rib_has(&t.asbr, external_net()));
    // The ABR keeps the full view.
    assert_eq!(rib_metric(&t.abr, y_stub_net()), Some(5));
    assert!(rib_has(&t.abr, external_net()));
}

#[test]
fn nssa_external_translated_to_type5_via_abr() {
    let mut t = Topology::new(OspfAreaType::nssa(10));
    redistribute_from_z(&mut t, true);

    // Z routes its own type-7 (type-2 metric 40, forwarding address).
    let z_snap = t.asbr.rib_snapshot();
    let z_ext = z_snap
        .iter()
        .find(|rt| rt.key.prefix == external_net())
        .expect("type-7 external at the NSSA ASBR");
    assert_eq!(z_ext.preference.metric, 40);
    assert_eq!(
        z_ext.next_hop,
        Some(lr_core::addr::IpAddr::V4([10, 40, 40, 1])),
        "forwarding address is the next hop"
    );

    // BR-Y resolves the same external through the ABR's translated
    // type-5: same metric, same forwarding address (RFC 3101 §3.2).
    let y_snap = t.br_y.rib_snapshot();
    let y_ext = y_snap
        .iter()
        .find(|rt| rt.key.prefix == external_net())
        .expect("translated type-5 reached the backbone");
    assert_eq!(y_ext.preference.metric, 40, "translation copies the metric");
    assert_eq!(y_ext.protocol, Protocol::Ospfv2);
    assert_eq!(
        y_ext.next_hop,
        Some(lr_core::addr::IpAddr::V4([10, 40, 40, 1])),
        "translation copies the forwarding address"
    );

    // The ABR itself routes the external too.
    assert_eq!(rib_metric(&t.abr, external_net()), Some(40));
}

#[test]
fn nssa_p_bit_clear_stays_inside_the_nssa() {
    let mut t = Topology::new(OspfAreaType::nssa(10));
    redistribute_from_z(&mut t, false);

    assert!(
        rib_has(&t.asbr, external_net()),
        "the type-7 still routes inside the NSSA"
    );
    assert!(
        !rib_has(&t.br_y, external_net()),
        "P-bit-clear type-7s are never translated (RFC 3101 §3.2 step 1)"
    );
}

#[test]
fn nssa_blocks_type5_and_injects_type7_default() {
    let mut t = Topology::new(OspfAreaType::nssa(10));

    // An external redistributed by the backbone router must not reach the
    // NSSA as a type-5 (RFC 3101 §2.1).
    assert!(t.br_y.ospf_redistribute(ExternalDestination::new(
        external_net(),
        40,
        ExternalMetricType::Type2,
    )));
    t.pump();
    assert!(!rib_has(&t.asbr, external_net()));

    // The border router's type-7 default (metric 10, type-2, FA = the
    // ABR itself) installs at Z with the external metric only.
    assert_eq!(
        rib_metric(&t.asbr, default_route()),
        Some(10),
        "type-7 default metric is external-only (type 2)"
    );
    // Plain NSSAs import summaries: Y's stub net at Z = 5 + 5.
    assert_eq!(rib_metric(&t.asbr, y_stub_net()), Some(10));
}

#[test]
fn totally_nssa_area_gets_type3_default_only() {
    let mut t = Topology::new(OspfAreaType::nssa_no_summary(10));

    // Type-7 externals still flow and translate in a totally-NSSA
    // (summary suppression does not affect type-7s).
    redistribute_from_z(&mut t, true);
    assert!(rib_has(&t.br_y, external_net()));

    // With summaries suppressed the border router's default is a type-3
    // summary (RFC 3101 §2.7): Z's metric = 5 (to the ABR) + 10.
    assert_eq!(
        rib_metric(&t.asbr, default_route()),
        Some(15),
        "type-3 default in no-summary NSSAs"
    );
    assert!(
        !rib_has(&t.asbr, y_stub_net()),
        "no-summary NSSAs carry no inter-area summaries"
    );
}

#[test]
fn nssa_unredistribute_flushes_type7_and_translation() {
    let mut t = Topology::new(OspfAreaType::nssa(10));
    redistribute_from_z(&mut t, true);
    assert!(rib_has(&t.br_y, external_net()));

    assert!(t.asbr.ospf_unredistribute(external_net()));
    t.pump();

    for (name, r) in [("BR-Y", &t.br_y), ("ABR-X", &t.abr), ("ASBR-Z", &t.asbr)] {
        assert!(
            !rib_has(r, external_net()),
            "{name} still holds the flushed NSSA external"
        );
    }
}

#[test]
fn nssa_translator_election_prevents_duplicate_translation() {
    // Two border routers attached to the NSSA (both with the B-bit set
    // in their router-LSAs, RFC 2328 §A.4.2); only the one with the
    // higher router ID translates (RFC 3101 §3.1).
    const X2: u32 = 0x0404_0404;

    let mut abr1 = DefaultRouter::new();
    let x1_bb = abr1
        .add_session(SessionConfig::ospfv2(RouterId::from_u32(X), 0))
        .unwrap();
    let x1_a1 = abr1
        .add_session(
            SessionConfig::ospfv2(RouterId::from_u32(X), 1)
                .with_ospf_area_type(OspfAreaType::nssa(10)),
        )
        .unwrap();
    let mut abr2 = DefaultRouter::new();
    let x2_bb = abr2
        .add_session(SessionConfig::ospfv2(RouterId::from_u32(X2), 0))
        .unwrap();
    let x2_a1 = abr2
        .add_session(
            SessionConfig::ospfv2(RouterId::from_u32(X2), 1)
                .with_ospf_area_type(OspfAreaType::nssa(10)),
        )
        .unwrap();
    let mut br_y = DefaultRouter::new();
    let y_bb = br_y
        .add_session(SessionConfig::ospfv2(RouterId::from_u32(Y), 0))
        .unwrap();
    let y_bb2 = br_y
        .add_session(SessionConfig::ospfv2(RouterId::from_u32(Y), 0))
        .unwrap();
    let mut asbr = DefaultRouter::new();
    let z_a1 = asbr
        .add_session(
            SessionConfig::ospfv2(RouterId::from_u32(Z), 1)
                .with_ospf_area_type(OspfAreaType::nssa(10)),
        )
        .unwrap();
    let z_a2 = asbr
        .add_session(
            SessionConfig::ospfv2(RouterId::from_u32(Z), 1)
                .with_ospf_area_type(OspfAreaType::nssa(10)),
        )
        .unwrap();

    // Area 0: X1—Y (3), X2—Y (4). Area 1 (NSSA): X1—Z (5), X2—Z (6);
    // Z carries the stub network hosting the type-7 forwarding address.
    // Border routers advertise the B-bit in the NSSA.
    let x1_bb_lsa = router_lsa(X, 0, vec![(Y, 0, P2P, 3)]);
    let x1_a1_lsa = router_lsa(X, 0x01, vec![(Z, 0, P2P, 5)]);
    let x2_bb_lsa = router_lsa(X2, 0, vec![(Y, 0, P2P, 4)]);
    let x2_a1_lsa = router_lsa(X2, 0x01, vec![(Z, 0, P2P, 6)]);
    let y_lsa = router_lsa(Y, 0, vec![(X, 0, P2P, 3), (X2, 0, P2P, 4)]);
    let z_lsa = router_lsa(
        Z,
        0,
        vec![
            (X, 0, P2P, 5),
            (X2, 0, P2P, 6),
            (0x0a28_2800, 0xffff_ff00, STUB_NET, 2),
        ],
    );

    // Cross-feed so every LSDB sees every router-LSA of its area
    // (area 0: X1, X2, Y; area 1: X1, X2, Z).
    br_y.feed_input(
        y_bb,
        &lsu(
            Y,
            0,
            vec![y_lsa.clone(), x1_bb_lsa.clone(), x2_bb_lsa.clone()],
        ),
    )
    .unwrap();
    br_y.feed_input(
        y_bb2,
        &lsu(
            Y,
            0,
            vec![y_lsa.clone(), x2_bb_lsa.clone(), x1_bb_lsa.clone()],
        ),
    )
    .unwrap();
    abr1.feed_input(
        x1_bb,
        &lsu(
            X,
            0,
            vec![x1_bb_lsa.clone(), y_lsa.clone(), x2_bb_lsa.clone()],
        ),
    )
    .unwrap();
    abr2.feed_input(
        x2_bb,
        &lsu(
            X2,
            0,
            vec![x2_bb_lsa.clone(), y_lsa.clone(), x1_bb_lsa.clone()],
        ),
    )
    .unwrap();
    abr1.feed_input(
        x1_a1,
        &lsu(
            X,
            1,
            vec![x1_a1_lsa.clone(), z_lsa.clone(), x2_a1_lsa.clone()],
        ),
    )
    .unwrap();
    abr2.feed_input(
        x2_a1,
        &lsu(
            X2,
            1,
            vec![x2_a1_lsa.clone(), z_lsa.clone(), x1_a1_lsa.clone()],
        ),
    )
    .unwrap();
    asbr.feed_input(
        z_a1,
        &lsu(
            Z,
            1,
            vec![z_lsa.clone(), x1_a1_lsa.clone(), x2_a1_lsa.clone()],
        ),
    )
    .unwrap();
    asbr.feed_input(
        z_a2,
        &lsu(
            Z,
            1,
            vec![z_lsa.clone(), x2_a1_lsa.clone(), x1_a1_lsa.clone()],
        ),
    )
    .unwrap();

    // Pump to quiescence, capturing every byte the two border routers
    // emit into the backbone.
    let mut x1_bb_out = Vec::new();
    let mut x2_bb_out = Vec::new();
    for _ in 0..16 {
        let x1_to_y = abr1.drain_output(x1_bb);
        let x1_to_z = abr1.drain_output(x1_a1);
        let x2_to_y = abr2.drain_output(x2_bb);
        let x2_to_z = abr2.drain_output(x2_a1);
        let y_out = br_y.drain_output(y_bb);
        let y_out2 = br_y.drain_output(y_bb2);
        let z_out = asbr.drain_output(z_a1);
        let z_out2 = asbr.drain_output(z_a2);
        if x1_to_y.is_empty()
            && x1_to_z.is_empty()
            && x2_to_y.is_empty()
            && x2_to_z.is_empty()
            && y_out.is_empty()
            && y_out2.is_empty()
            && z_out.is_empty()
            && z_out2.is_empty()
        {
            break;
        }
        x1_bb_out.extend_from_slice(&x1_to_y);
        x2_bb_out.extend_from_slice(&x2_to_y);
        if !x1_to_y.is_empty() {
            br_y.feed_input(y_bb, &x1_to_y).unwrap();
        }
        if !x2_to_y.is_empty() {
            br_y.feed_input(y_bb2, &x2_to_y).unwrap();
        }
        if !y_out.is_empty() {
            abr1.feed_input(x1_bb, &y_out).unwrap();
            abr2.feed_input(x2_bb, &y_out).unwrap();
        }
        if !y_out2.is_empty() {
            abr1.feed_input(x1_bb, &y_out2).unwrap();
            abr2.feed_input(x2_bb, &y_out2).unwrap();
        }
        if !x1_to_z.is_empty() {
            asbr.feed_input(z_a1, &x1_to_z).unwrap();
        }
        if !x2_to_z.is_empty() {
            asbr.feed_input(z_a2, &x2_to_z).unwrap();
        }
        if !z_out.is_empty() {
            abr1.feed_input(x1_a1, &z_out).unwrap();
            abr2.feed_input(x2_a1, &z_out).unwrap();
        }
        if !z_out2.is_empty() {
            abr1.feed_input(x1_a1, &z_out2).unwrap();
            abr2.feed_input(x2_a1, &z_out2).unwrap();
        }
    }

    // Z redistributes a translatable type-7.
    let mut dest = ExternalDestination::new(external_net(), 40, ExternalMetricType::Type2);
    dest.p_bit = true;
    dest.forwarding_addr = 0x0a28_2801;
    assert!(asbr.ospf_redistribute(dest));

    // Pump to quiescence, still capturing the ABRs' backbone output.
    for _ in 0..16 {
        let x1_to_y = abr1.drain_output(x1_bb);
        let x1_to_z = abr1.drain_output(x1_a1);
        let x2_to_y = abr2.drain_output(x2_bb);
        let x2_to_z = abr2.drain_output(x2_a1);
        let y_out = br_y.drain_output(y_bb);
        let y_out2 = br_y.drain_output(y_bb2);
        let z_out = asbr.drain_output(z_a1);
        let z_out2 = asbr.drain_output(z_a2);
        if x1_to_y.is_empty()
            && x1_to_z.is_empty()
            && x2_to_y.is_empty()
            && x2_to_z.is_empty()
            && y_out.is_empty()
            && y_out2.is_empty()
            && z_out.is_empty()
            && z_out2.is_empty()
        {
            break;
        }
        x1_bb_out.extend_from_slice(&x1_to_y);
        x2_bb_out.extend_from_slice(&x2_to_y);
        if !x1_to_y.is_empty() {
            br_y.feed_input(y_bb, &x1_to_y).unwrap();
        }
        if !x2_to_y.is_empty() {
            br_y.feed_input(y_bb2, &x2_to_y).unwrap();
        }
        if !y_out.is_empty() {
            abr1.feed_input(x1_bb, &y_out).unwrap();
            abr2.feed_input(x2_bb, &y_out).unwrap();
        }
        if !y_out2.is_empty() {
            abr1.feed_input(x1_bb, &y_out2).unwrap();
            abr2.feed_input(x2_bb, &y_out2).unwrap();
        }
        if !x1_to_z.is_empty() {
            asbr.feed_input(z_a1, &x1_to_z).unwrap();
        }
        if !x2_to_z.is_empty() {
            asbr.feed_input(z_a2, &x2_to_z).unwrap();
        }
        if !z_out.is_empty() {
            abr1.feed_input(x1_a1, &z_out).unwrap();
            abr2.feed_input(x2_a1, &z_out).unwrap();
        }
        if !z_out2.is_empty() {
            abr1.feed_input(x1_a1, &z_out2).unwrap();
            abr2.feed_input(x2_a1, &z_out2).unwrap();
        }
    }

    // Y routes the external through exactly one translation.
    assert!(rib_has(&br_y, external_net()));
    // The elected translator (higher router ID X2) originated the type-5;
    // X1 never did (RFC 3101 §3.1).
    assert_eq!(
        count_type5_adv(&x1_bb_out, X),
        0,
        "the lower-ID border router must not translate"
    );
    assert!(
        count_type5_adv(&x2_bb_out, X2) >= 1,
        "the higher-ID border router translates"
    );
}
