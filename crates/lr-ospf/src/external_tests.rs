use super::*;
use crate::lsdb::InstallOutcome;
use crate::spf::run_spf;

fn net(a: u32, len: u8) -> Prefix {
    Prefix::new_v4(a.to_be_bytes(), len)
}

#[test]
fn originate_external_type2_sets_e_bit() {
    let dest = ExternalDestination::new(net(0xc000_0200, 24), 100, ExternalMetricType::Type2);
    let lsa = originate_external_lsa(0x01020304, &dest, None).unwrap();
    assert_eq!(lsa.header.ls_type, LsaTypeV2::AsExternalLsa as u16);
    assert_eq!(lsa.header.link_state_id, 0xc000_0200);
    assert_eq!(lsa.header.advertising_router, 0x01020304);
    assert_eq!(lsa.header.ls_sequence_number, INITIAL_SEQUENCE_NUMBER);
    assert_eq!(lsa.header.length, 36); // 20 header + 16 body
    assert!(lsa.checksum_ok());
    let body = decode_as_external_body(&lsa.body).unwrap();
    assert!(body.external_type2());
    assert_eq!(body.metric_value(), 100);
    assert_eq!(body.network_mask, 0xffff_ff00);
    assert_eq!(body.forwarding_addr, 0);
    assert_eq!(body.route_tag, 0);
}

#[test]
fn originate_external_type1_and_forwarding_address() {
    let mut dest = ExternalDestination::new(net(0x0a000000, 8), 50, ExternalMetricType::Type1);
    dest.forwarding_addr = 0x0a0a0a01;
    dest.route_tag = 7;
    let lsa = originate_external_lsa(1, &dest, Some(0x80000005)).unwrap();
    assert_eq!(lsa.header.ls_sequence_number, 0x80000006);
    let body = decode_as_external_body(&lsa.body).unwrap();
    assert!(!body.external_type2());
    assert_eq!(body.metric_value(), 50);
    assert_eq!(body.forwarding_addr, 0x0a0a0a01);
    assert_eq!(body.route_tag, 7);
}

#[test]
fn originate_external_rejects_v6_and_sequence_exhaustion() {
    let v6 = Prefix::new_v6([0x20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1], 64);
    assert!(originate_external_lsa(
        1,
        &ExternalDestination::new(v6, 5, ExternalMetricType::Type1),
        None
    )
    .is_none());
    let dest = ExternalDestination::new(net(1, 32), 5, ExternalMetricType::Type1);
    assert!(originate_external_lsa(1, &dest, Some(MAX_SEQUENCE_NUMBER)).is_none());
}

#[test]
fn flush_external_ages_to_maxage() {
    let dest = ExternalDestination::new(net(0xc000_0200, 24), 10, ExternalMetricType::Type1);
    let lsa = originate_external_lsa(1, &dest, None).unwrap();
    let flush = flush_external_lsa(&lsa).unwrap();
    assert_eq!(flush.header.ls_age, crate::lsdb::MAX_AGE_SECS);
    assert_eq!(flush.header.ls_sequence_number, INITIAL_SEQUENCE_NUMBER + 1);
    assert!(flush.checksum_ok());
}

#[test]
fn originate_summary_asbr_uses_router_id_as_ls_id() {
    let dest = AsbrDestination::new(0x09090909, 30);
    let lsa = originate_summary_asbr_lsa(0x01020304, &dest, None).unwrap();
    assert_eq!(lsa.header.ls_type, LsaTypeV2::SummaryAsbrLsa as u16);
    assert_eq!(lsa.header.link_state_id, 0x09090909);
    assert_eq!(lsa.header.length, 28); // 20 header + 8 body
    assert!(lsa.checksum_ok());
    let body = decode_summary_lsa_body(&lsa.body).unwrap();
    assert_eq!(body.network_mask, 0);
    assert_eq!(body.tos0_metric(), Some(30));
}

/// Topology: root R1 (router-id 1) — R2 (ASBR, router-id 2) with a
/// p2p link of metric 10, and R2 redistributes 198.51.100.0/24 as a
/// type-1 external with metric 5.
fn externals_with_asbr_reachable() -> Vec<ExternalRoute> {
    let mut lsdb = Lsdb::new();
    // R1's router-LSA: p2p link to R2, metric 10 + stub net.
    let mut r1 = Lsa {
        header: LsaHeader {
            ls_age: 0,
            options: 0x02,
            ls_type: LsaTypeV2::RouterLsa as u16,
            link_state_id: 1,
            advertising_router: 1,
            ls_sequence_number: INITIAL_SEQUENCE_NUMBER,
            ls_checksum: 0,
            length: 0,
        },
        body: crate::spf::encode_router_lsa_body(
            0,
            vec![crate::lsa::RouterLink {
                link_id: 2,
                link_data: 0,
                link_type: 1,
                tos: 0,
                metric: 10,
            }],
        ),
    };
    r1.finalize();
    assert_eq!(lsdb.install(r1, 0), InstallOutcome::New);
    // R2's router-LSA: link back to R1.
    let mut r2 = Lsa {
        header: LsaHeader {
            ls_age: 0,
            options: 0x02,
            ls_type: LsaTypeV2::RouterLsa as u16,
            link_state_id: 2,
            advertising_router: 2,
            ls_sequence_number: INITIAL_SEQUENCE_NUMBER,
            ls_checksum: 0,
            length: 0,
        },
        body: crate::spf::encode_router_lsa_body(
            0,
            vec![crate::lsa::RouterLink {
                link_id: 1,
                link_data: 0,
                link_type: 1,
                tos: 0,
                metric: 10,
            }],
        ),
    };
    r2.finalize();
    assert_eq!(lsdb.install(r2, 0), InstallOutcome::New);
    // R2's external: 198.51.100.0/24 type-1 metric 5.
    let dest = ExternalDestination::new(net(0xc6336400, 24), 5, ExternalMetricType::Type1);
    let ext = originate_external_lsa(2, &dest, None).unwrap();
    assert_eq!(lsdb.install(ext, 0), InstallOutcome::New);
    let result = run_spf(&lsdb, 1);
    external_routes(&lsdb, &result)
}

#[test]
fn type1_external_adds_asbr_cost() {
    let routes = externals_with_asbr_reachable();
    assert_eq!(routes.len(), 1);
    let r = &routes[0];
    assert_eq!(r.prefix, net(0xc6336400, 24));
    assert_eq!(r.metric_type, ExternalMetricType::Type1);
    assert_eq!(r.metric, 15); // 10 to ASBR + 5 external
    assert_eq!(r.internal_cost, 10);
    assert_eq!(r.asbr, 2);
    assert_eq!(r.border_router, None);
}

#[test]
fn type2_external_keeps_external_metric_only() {
    let mut lsdb = Lsdb::new();
    let mut r1 = Lsa {
        header: LsaHeader {
            ls_age: 0,
            options: 0x02,
            ls_type: LsaTypeV2::RouterLsa as u16,
            link_state_id: 1,
            advertising_router: 1,
            ls_sequence_number: INITIAL_SEQUENCE_NUMBER,
            ls_checksum: 0,
            length: 0,
        },
        body: crate::spf::encode_router_lsa_body(
            0,
            vec![crate::lsa::RouterLink {
                link_id: 2,
                link_data: 0,
                link_type: 1,
                tos: 0,
                metric: 10,
            }],
        ),
    };
    r1.finalize();
    lsdb.install(r1, 0);
    let mut r2 = Lsa {
        header: LsaHeader {
            ls_age: 0,
            options: 0x02,
            ls_type: LsaTypeV2::RouterLsa as u16,
            link_state_id: 2,
            advertising_router: 2,
            ls_sequence_number: INITIAL_SEQUENCE_NUMBER,
            ls_checksum: 0,
            length: 0,
        },
        body: crate::spf::encode_router_lsa_body(
            0,
            vec![crate::lsa::RouterLink {
                link_id: 1,
                link_data: 0,
                link_type: 1,
                tos: 0,
                metric: 10,
            }],
        ),
    };
    r2.finalize();
    lsdb.install(r2, 0);
    let dest = ExternalDestination::new(net(0xc6336400, 24), 7, ExternalMetricType::Type2);
    lsdb.install(originate_external_lsa(2, &dest, None).unwrap(), 0);
    let result = run_spf(&lsdb, 1);
    let routes = external_routes(&lsdb, &result);
    assert_eq!(routes.len(), 1);
    assert_eq!(routes[0].metric, 7);
    assert_eq!(routes[0].internal_cost, 10);
}

#[test]
fn unreachable_asbr_is_skipped() {
    let mut lsdb = Lsdb::new();
    // Only the external LSA — its ASBR (router 9) has no router-LSA
    // here, so §16.4 cannot locate it.
    let dest = ExternalDestination::new(net(0xc6336400, 24), 5, ExternalMetricType::Type1);
    lsdb.install(originate_external_lsa(9, &dest, None).unwrap(), 0);
    let result = run_spf(&lsdb, 1);
    assert!(external_routes(&lsdb, &result).is_empty());
}

#[test]
fn ls_infinity_external_is_skipped() {
    let mut lsdb = Lsdb::new();
    let dest =
        ExternalDestination::new(net(0xc6336400, 24), LS_INFINITY, ExternalMetricType::Type1);
    lsdb.install(originate_external_lsa(2, &dest, None).unwrap(), 0);
    let result = run_spf(&lsdb, 1);
    assert!(external_routes(&lsdb, &result).is_empty());
}

#[test]
fn type1_preferred_over_type2_and_asbr_leg_via_type4() {
    // R1 — (metric 4) — ABR(3) — type-4 says ASBR 9 reachable at 20.
    // Two externals for 203.0.113.0/24: type-2 metric 1 from ASBR 9
    // and type-1 metric 50 from ASBR 3 (reachable intra-area).
    let mut lsdb = Lsdb::new();
    let link = |adv: u32, to: u32, metric: u16| {
        let mut lsa = Lsa {
            header: LsaHeader {
                ls_age: 0,
                options: 0x02,
                ls_type: LsaTypeV2::RouterLsa as u16,
                link_state_id: adv,
                advertising_router: adv,
                ls_sequence_number: INITIAL_SEQUENCE_NUMBER,
                ls_checksum: 0,
                length: 0,
            },
            body: crate::spf::encode_router_lsa_body(
                0,
                vec![crate::lsa::RouterLink {
                    link_id: to,
                    link_data: 0,
                    link_type: 1,
                    tos: 0,
                    metric,
                }],
            ),
        };
        lsa.finalize();
        lsa
    };
    lsdb.install(link(1, 3, 4), 0);
    lsdb.install(link(3, 1, 4), 0);
    // ABR 3's type-4: ASBR 9 at metric 20.
    lsdb.install(
        originate_summary_asbr_lsa(3, &AsbrDestination::new(9, 20), None).unwrap(),
        0,
    );
    // ASBR 9's type-2 external (metric 1) and ASBR 3's type-1 (metric 50).
    lsdb.install(
        originate_external_lsa(
            9,
            &ExternalDestination::new(net(0xcb007100, 24), 1, ExternalMetricType::Type2),
            None,
        )
        .unwrap(),
        0,
    );
    lsdb.install(
        originate_external_lsa(
            3,
            &ExternalDestination::new(net(0xcb007100, 24), 50, ExternalMetricType::Type1),
            None,
        )
        .unwrap(),
        0,
    );
    let result = run_spf(&lsdb, 1);
    let routes = external_routes(&lsdb, &result);
    assert_eq!(routes.len(), 1);
    // Type 1 always beats type 2 (§16.4 (6)): 4 + 50 = 54 < type-2's 1.
    assert_eq!(routes[0].metric_type, ExternalMetricType::Type1);
    assert_eq!(routes[0].metric, 54);
    assert_eq!(routes[0].asbr, 3);
}

#[test]
fn type2_ties_broken_by_internal_cost() {
    // ASBR 8 and ASBR 9 both advertise 198.51.100.0/24 type-2 metric
    // 5; ASBR 8 is nearer. The nearer one must win.
    let mut lsdb = Lsdb::new();
    let link = |adv: u32, to: u32, metric: u16| {
        let mut lsa = Lsa {
            header: LsaHeader {
                ls_age: 0,
                options: 0x02,
                ls_type: LsaTypeV2::RouterLsa as u16,
                link_state_id: adv,
                advertising_router: adv,
                ls_sequence_number: INITIAL_SEQUENCE_NUMBER,
                ls_checksum: 0,
                length: 0,
            },
            body: crate::spf::encode_router_lsa_body(
                0,
                vec![crate::lsa::RouterLink {
                    link_id: to,
                    link_data: 0,
                    link_type: 1,
                    tos: 0,
                    metric,
                }],
            ),
        };
        lsa.finalize();
        lsa
    };
    lsdb.install(link(1, 8, 3), 0);
    lsdb.install(link(8, 1, 3), 0);
    lsdb.install(link(1, 9, 9), 0);
    lsdb.install(link(9, 1, 9), 0);
    for asbr in [8u32, 9u32] {
        lsdb.install(
            originate_external_lsa(
                asbr,
                &ExternalDestination::new(net(0xc6336400, 24), 5, ExternalMetricType::Type2),
                None,
            )
            .unwrap(),
            0,
        );
    }
    let result = run_spf(&lsdb, 1);
    let routes = external_routes(&lsdb, &result);
    assert_eq!(routes.len(), 1);
    assert_eq!(routes[0].asbr, 8);
    assert_eq!(routes[0].internal_cost, 3);
}

#[test]
fn forwarding_address_must_be_covered() {
    // R1's stub network 10.1.0.0/16 (metric 2) covers the forwarding
    // address 10.1.7.7; an external via that FA is usable, one via an
    // uncovered FA is not.
    let mut lsdb = Lsdb::new();
    let mut r1 = Lsa {
        header: LsaHeader {
            ls_age: 0,
            options: 0x02,
            ls_type: LsaTypeV2::RouterLsa as u16,
            link_state_id: 1,
            advertising_router: 1,
            ls_sequence_number: INITIAL_SEQUENCE_NUMBER,
            ls_checksum: 0,
            length: 0,
        },
        body: crate::spf::encode_router_lsa_body(
            0,
            vec![crate::lsa::RouterLink {
                link_id: 0x0a010000,
                link_data: 0xffff0000,
                link_type: 3,
                tos: 0,
                metric: 2,
            }],
        ),
    };
    r1.finalize();
    lsdb.install(r1, 0);
    // ASBR 2 is a direct neighbor.
    let mut r2 = Lsa {
        header: LsaHeader {
            ls_age: 0,
            options: 0x02,
            ls_type: LsaTypeV2::RouterLsa as u16,
            link_state_id: 2,
            advertising_router: 2,
            ls_sequence_number: INITIAL_SEQUENCE_NUMBER,
            ls_checksum: 0,
            length: 0,
        },
        body: crate::spf::encode_router_lsa_body(
            0,
            vec![crate::lsa::RouterLink {
                link_id: 1,
                link_data: 0,
                link_type: 1,
                tos: 0,
                metric: 6,
            }],
        ),
    };
    r2.finalize();
    lsdb.install(r2, 0);
    // Covering FA: 10.1.7.7 inside 10.1.0.0/16.
    let mut covered = ExternalDestination::new(net(0xc6336400, 24), 9, ExternalMetricType::Type2);
    covered.forwarding_addr = 0x0a010707;
    lsdb.install(originate_external_lsa(2, &covered, None).unwrap(), 0);
    // Uncovering FA: 10.99.0.1 outside every known prefix.
    let mut uncovered = ExternalDestination::new(net(0xc6336500, 24), 9, ExternalMetricType::Type2);
    uncovered.forwarding_addr = 0x0a630001;
    lsdb.install(originate_external_lsa(2, &uncovered, None).unwrap(), 0);
    let result = run_spf(&lsdb, 1);
    let routes = external_routes(&lsdb, &result);
    assert_eq!(routes.len(), 1);
    assert_eq!(routes[0].prefix, net(0xc6336400, 24));
    assert_eq!(routes[0].forwarding_addr, 0x0a010707);
}
