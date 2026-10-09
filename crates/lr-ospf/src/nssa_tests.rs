use super::*;
use crate::external::ExternalMetricType;
use crate::lsa::{decode_as_external_body, LsaHeader, LsaTypeV2};
use crate::lsdb::MAX_AGE_SECS;
use crate::spf::{run_spf, SpfRoute};

fn net(a: u32, len: u8) -> Prefix {
    Prefix::new_v4(a.to_be_bytes(), len)
}

/// A minimal router-LSA: `flags` byte + one p2p link to `neighbor`
/// at `metric` (enough for both SPF and the election scan). The
/// V/E/B/Nt bits live in the *high* byte of the 16-bit flags word
/// (RFC 2328 §A.4.2 diagram).
fn router_lsa(rid: u32, flags: u8, neighbor: u32, metric: u16) -> Lsa {
    let mut body = Vec::new();
    body.extend_from_slice(&(u16::from(flags) << 8).to_be_bytes());
    body.extend_from_slice(&1u16.to_be_bytes());
    body.extend_from_slice(&neighbor.to_be_bytes());
    body.extend_from_slice(&0u32.to_be_bytes());
    body.push(1); // p2p
    body.push(0); // tos
    body.extend_from_slice(&metric.to_be_bytes());
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

#[test]
fn originate_nssa_sets_type_p_bit_and_forwarding_address() {
    let mut dest = ExternalDestination::new(net(0xc000_0200, 24), 40, ExternalMetricType::Type2);
    dest.forwarding_addr = 0x0a40_4001; // required with the P-bit set
    let lsa = originate_nssa_lsa(0x0202_0202, &dest, None).unwrap();
    assert_eq!(lsa.header.ls_type, LsaTypeV2::NssaExternalLsa as u16);
    assert_eq!(lsa.header.link_state_id, 0xc000_0200);
    assert_eq!(lsa.header.advertising_router, 0x0202_0202);
    assert_eq!(lsa.header.ls_sequence_number, INITIAL_SEQUENCE_NUMBER);
    assert_eq!(lsa.header.length, 36); // 20 header + 16 body
    assert!(p_bit_set(&lsa), "P-bit from the destination config");
    assert!(lsa.checksum_ok());
    let body = decode_as_external_body(&lsa.body).unwrap();
    assert!(body.external_type2());
    assert_eq!(body.metric_value(), 40);
    assert_eq!(body.forwarding_addr, 0x0a40_4001);
}

#[test]
fn originate_nssa_clear_bit_omits_p() {
    let mut dest = ExternalDestination::new(net(0x0a000000, 8), 50, ExternalMetricType::Type1);
    dest.p_bit = false;
    let lsa = originate_nssa_lsa(1, &dest, Some(0x80000005)).unwrap();
    assert!(!p_bit_set(&lsa));
    assert_eq!(lsa.header.ls_sequence_number, 0x80000006);
    let body = decode_as_external_body(&lsa.body).unwrap();
    assert!(!body.external_type2());
    assert_eq!(body.metric_value(), 50);
}

#[test]
fn originate_nssa_rejects_p_bit_with_zero_forwarding_address() {
    // §2.3: a P-bit-set type-7 must carry a non-zero forwarding
    // address; without one the LSA is not originated.
    let dest = ExternalDestination::new(net(0x0a000000, 8), 50, ExternalMetricType::Type2);
    assert!(dest.p_bit);
    assert!(originate_nssa_lsa(1, &dest, None).is_none());
}

#[test]
fn originate_nssa_rejects_v6_and_sequence_exhaustion() {
    let v6 = Prefix::new_v6([0x20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1], 64);
    let mut dest = ExternalDestination::new(v6, 5, ExternalMetricType::Type2);
    dest.forwarding_addr = 1;
    assert!(originate_nssa_lsa(1, &dest, None).is_none());
    let mut dest = ExternalDestination::new(net(1, 32), 5, ExternalMetricType::Type2);
    dest.forwarding_addr = 1;
    assert!(originate_nssa_lsa(1, &dest, Some(MAX_SEQUENCE_NUMBER)).is_none());
}

#[test]
fn nssa_default_lsa_has_clear_p_and_zero_forwarding() {
    let lsa = originate_nssa_default_lsa(0x0101_0101, &NssaDefault::new(10), None).unwrap();
    assert_eq!(lsa.header.ls_type, LsaTypeV2::NssaExternalLsa as u16);
    assert_eq!(lsa.header.link_state_id, 0);
    assert!(
        !p_bit_set(&lsa),
        "border-router defaults are never translated (§2.4)"
    );
    let body = decode_as_external_body(&lsa.body).unwrap();
    assert_eq!(body.network_mask, 0);
    assert_eq!(body.metric_value(), 10);
    assert!(body.external_type2());
    assert_eq!(body.forwarding_addr, 0);
    // A generic (internal-ASBR) default obeys the same §2.3 rule as
    // every P-bit-set type-7: non-zero forwarding address required.
    let mut dest = ExternalDestination::new(net(0, 0), 10, ExternalMetricType::Type2);
    dest.p_bit = true;
    assert!(originate_nssa_lsa(1, &dest, None).is_none());
    dest.forwarding_addr = 1;
    let lsa = originate_nssa_lsa(1, &dest, None).unwrap();
    assert!(
        p_bit_set(&lsa),
        "internal ASBRs may set P on a default (§2.4)"
    );
}

#[test]
fn flush_ages_to_max() {
    let mut dest = ExternalDestination::new(net(0x0a000000, 8), 50, ExternalMetricType::Type2);
    dest.p_bit = false;
    let lsa = originate_nssa_lsa(1, &dest, None).unwrap();
    let flush = flush_nssa_lsa(&lsa).unwrap();
    assert_eq!(flush.header.ls_age, MAX_AGE_SECS);
    assert_eq!(flush.header.ls_sequence_number, INITIAL_SEQUENCE_NUMBER + 1);
    assert!(flush.checksum_ok());
}

#[test]
fn nssa_routes_type2_with_forwarding_address_intra_cover() {
    // Root 1 -- ASBR 5 (stub net 10.64.64.0/24 metric 2); ASBR 5
    // redistributes a type-7 with the forwarding address inside that
    // stub network.
    let mut lsdb = Lsdb::new();
    lsdb.install(router_lsa(1, 0, 5, 7), 0);
    let mut body = Vec::new();
    body.extend_from_slice(&0u16.to_be_bytes());
    body.extend_from_slice(&1u16.to_be_bytes());
    body.extend_from_slice(&0x0a40_4000u32.to_be_bytes()); // stub network
    body.extend_from_slice(&0x0000_ff00u32.to_be_bytes()); // stub mask
    body.push(3); // stub network
    body.push(0);
    body.extend_from_slice(&2u16.to_be_bytes());
    let asbr_lsa = Lsa {
        header: LsaHeader {
            ls_age: 0,
            options: 0x02,
            ls_type: LsaTypeV2::RouterLsa as u16,
            link_state_id: 5,
            advertising_router: 5,
            ls_sequence_number: 0x8000_0001,
            ls_checksum: 0,
            length: (LsaHeader::LEN + body.len()) as u16,
        },
        body,
    };
    lsdb.install(asbr_lsa, 0);

    let mut dest = ExternalDestination::new(net(0xc000_0200, 24), 40, ExternalMetricType::Type2);
    dest.forwarding_addr = 0x0a40_4001;
    let t7 = originate_nssa_lsa(5, &dest, None).unwrap();
    lsdb.install(t7, 0);

    let spf = run_spf(&lsdb, 1);
    let routes = nssa_routes(&lsdb, &spf, NssaCalcOpts::default());
    assert_eq!(routes.len(), 1);
    assert_eq!(routes[0].prefix, net(0xc000_0200, 24));
    assert_eq!(routes[0].metric, 40, "type-2 metric is external-only");
    assert_eq!(
        routes[0].internal_cost, 9,
        "7 to the ASBR + 2 across its stub"
    );
    assert_eq!(routes[0].forwarding_addr, 0x0a40_4001);
    assert_eq!(routes[0].asbr, 5);
}

#[test]
fn nssa_routes_forwarding_address_needs_intra_cover() {
    // The forwarding address is only covered by a type-3 summary —
    // §2.5 step (3) requires an intra-area path, so the type-7 is
    // skipped even though the summary exists.
    let mut lsdb = Lsdb::new();
    let mut dest = ExternalDestination::new(net(0xc000_0200, 24), 40, ExternalMetricType::Type2);
    dest.forwarding_addr = 0x0a40_4001;
    let t7 = originate_nssa_lsa(5, &dest, None).unwrap();
    lsdb.install(t7, 0);
    // Summary-LSA covering 10.64.64.0/24 (but no intra-area route).
    let summary = crate::abr::originate_summary_lsa(
        9,
        &crate::abr::SummaryDestination::new(net(0x0a40_4000, 24), 3),
        None,
    )
    .unwrap();
    lsdb.install(summary, 0);

    let spf = run_spf(&lsdb, 1);
    assert!(nssa_routes(&lsdb, &spf, NssaCalcOpts::default()).is_empty());
}

#[test]
fn nssa_routes_type1_sums_internal_cost() {
    // FA = 0: the ASBR itself is the internal leg (intra-area via a
    // p2p link from the calculating root 1 to ASBR 5 at metric 7).
    let mut lsdb = Lsdb::new();
    lsdb.install(router_lsa(1, 0, 5, 7), 0);
    lsdb.install(router_lsa(5, 0, 1, 7), 0);
    let mut dest = ExternalDestination::new(net(0xc000_0200, 24), 40, ExternalMetricType::Type1);
    dest.p_bit = false; // FA stays 0
    let t7 = originate_nssa_lsa(5, &dest, None).unwrap();
    lsdb.install(t7, 0);

    let spf = run_spf(&lsdb, 1);
    let routes = nssa_routes(&lsdb, &spf, NssaCalcOpts::default());
    assert_eq!(routes.len(), 1);
    assert_eq!(routes[0].metric, 47, "type-1: internal 7 + external 40");
    assert_eq!(routes[0].internal_cost, 7);
}

#[test]
fn nssa_routes_skips_unreachable_asbr_and_ls_infinity() {
    let mut lsdb = Lsdb::new();
    // No router-LSA for the ASBR at all → unreachable → skipped.
    let mut dest = ExternalDestination::new(net(0xc000_0200, 24), 40, ExternalMetricType::Type2);
    dest.p_bit = false;
    lsdb.install(originate_nssa_lsa(5, &dest, None).unwrap(), 0);
    // LSInfinity external → skipped.
    let mut inf =
        ExternalDestination::new(net(0xc000_0300, 24), LS_INFINITY, ExternalMetricType::Type2);
    inf.p_bit = false;
    lsdb.install(originate_nssa_lsa(5, &inf, None).unwrap(), 0);

    let spf = run_spf(&lsdb, 1);
    assert!(nssa_routes(&lsdb, &spf, NssaCalcOpts::default()).is_empty());
}

#[test]
fn nssa_routes_default_install_rules_for_border_routers() {
    // Root 1 -- ASBR 5 (stub 10.64.64.0/24); ASBR 5 originates the
    // type-7 default. P-bit-set defaults carry FA 10.64.64.1 (inside
    // the stub network, so it is intra-area covered).
    fn area_with_default(p_bit: bool) -> Lsdb {
        let mut lsdb = Lsdb::new();
        lsdb.install(router_lsa(1, 0, 5, 7), 0);
        let mut body = Vec::new();
        body.extend_from_slice(&0u16.to_be_bytes());
        body.extend_from_slice(&2u16.to_be_bytes());
        body.extend_from_slice(&1u32.to_be_bytes()); // p2p to root
        body.extend_from_slice(&0u32.to_be_bytes());
        body.push(1);
        body.push(0);
        body.extend_from_slice(&7u16.to_be_bytes());
        body.extend_from_slice(&0x0a40_4000u32.to_be_bytes()); // stub net
        body.extend_from_slice(&0x0000_ff00u32.to_be_bytes()); // mask
        body.push(3);
        body.push(0);
        body.extend_from_slice(&2u16.to_be_bytes());
        lsdb.install(
            Lsa {
                header: LsaHeader {
                    ls_age: 0,
                    options: 0x02,
                    ls_type: LsaTypeV2::RouterLsa as u16,
                    link_state_id: 5,
                    advertising_router: 5,
                    ls_sequence_number: 0x8000_0001,
                    ls_checksum: 0,
                    length: (LsaHeader::LEN + body.len()) as u16,
                },
                body,
            },
            0,
        );
        let mut dest = ExternalDestination::new(net(0, 0), 10, ExternalMetricType::Type2);
        dest.p_bit = p_bit;
        dest.forwarding_addr = if p_bit { 0x0a40_4001 } else { 0 };
        lsdb.install(originate_nssa_lsa(5, &dest, None).unwrap(), 0);
        lsdb
    }
    let spf_of = |lsdb: &Lsdb| run_spf(lsdb, 1);

    // Internal router installs any type-7 default.
    let lsdb = area_with_default(false);
    assert_eq!(
        nssa_routes(&lsdb, &spf_of(&lsdb), NssaCalcOpts::default()).len(),
        1
    );

    // Border router: P-bit clear default skipped (§2.5 step (3))...
    assert_eq!(
        nssa_routes(
            &lsdb,
            &spf_of(&lsdb),
            NssaCalcOpts {
                border_router: true,
                summaries_suppressed: false,
            }
        )
        .len(),
        0
    );

    // ...P-bit set default installed...
    let lsdb = area_with_default(true);
    assert_eq!(
        nssa_routes(
            &lsdb,
            &spf_of(&lsdb),
            NssaCalcOpts {
                border_router: true,
                summaries_suppressed: false,
            }
        )
        .len(),
        1
    );

    // ...but with suppressed summaries all type-7 defaults are
    // skipped at border routers (§2.7 — the type-3 default wins).
    assert_eq!(
        nssa_routes(
            &lsdb,
            &spf_of(&lsdb),
            NssaCalcOpts {
                border_router: true,
                summaries_suppressed: true,
            }
        )
        .len(),
        0
    );
}

#[test]
fn nssa_routes_empty_area_fast_path() {
    let lsdb = Lsdb::new();
    assert!(nssa_routes(&lsdb, &SpfResult::default(), NssaCalcOpts::default()).is_empty());
}

#[test]
fn translator_election_by_b_bit_and_router_id() {
    // Only our own (implicit) candidacy: elected.
    let mut lsdb = Lsdb::new();
    lsdb.install(router_lsa(9, 0, 1, 1), 0); // plain internal router
    assert!(is_elected_translator(&lsdb, 3));

    // A higher-ID border router beats us.
    let mut lsdb = Lsdb::new();
    lsdb.install(router_lsa(9, router_lsa_flags::B, 1, 1), 0);
    assert!(!is_elected_translator(&lsdb, 3), "higher B-bit router wins");

    // A lower-ID border router does not.
    let mut lsdb = Lsdb::new();
    lsdb.install(router_lsa(2, router_lsa_flags::B, 1, 1), 0);
    assert!(is_elected_translator(&lsdb, 3));

    // Nt-bit (unconditional translator) wins regardless of router ID.
    let mut lsdb = Lsdb::new();
    lsdb.install(
        router_lsa(2, router_lsa_flags::B | router_lsa_flags::NT, 1, 1),
        0,
    );
    assert!(!is_elected_translator(&lsdb, 3), "Nt-bit beats higher ID");
}

#[test]
fn n_p_bit_position() {
    // RFC 3101 Appendix A: options bit 3.
    assert_eq!(N_P_BIT, 0x08);
    assert_eq!(router_lsa_flags::B, 0x01);
    assert_eq!(router_lsa_flags::E, 0x02);
    assert_eq!(router_lsa_flags::V, 0x04);
    assert_eq!(router_lsa_flags::NT, 0x10);
}

#[test]
fn spf_route_struct_field_coverage() {
    // Keeps the SpfRoute import honest for future next-hop wiring.
    let r = SpfRoute {
        prefix: net(1, 24),
        metric: 5,
        next_hop: None,
        border_router: None,
    };
    assert_eq!(r.metric, 5);
}
