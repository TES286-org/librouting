use super::*;
use crate::lsa::v3::{
    originate_v3_as_external_lsa, originate_v3_inter_area_router_lsa, V3ExternalDestination,
    V3Prefix,
};
use crate::lsa::v3::{
    originate_v3_intra_area_prefix_lsa, originate_v3_link_lsa, originate_v3_router_lsa,
    LINK_TYPE_POINTTOPOINT, ROUTER_BIT_V6,
};
use crate::spf::run_spf_v3;

fn fe80(host: u8) -> [u8; 16] {
    let mut a = [0u8; 16];
    a[0] = 0xfe;
    a[1] = 0x80;
    a[15] = host;
    a
}

/// 2001:db8:0:hn::/64 — a /64 whose significant bits fit the wire.
fn net64(host: u8) -> V3Prefix {
    let mut a = [0u8; 16];
    a[0] = 0x20;
    a[1] = 0x01;
    a[2] = 0x0d;
    a[3] = 0xb8;
    a[7] = host;
    V3Prefix {
        prefix_len: 64,
        options: 0,
        metric: 0,
        addr: a,
    }
}

fn ext_prefix(bytes6: [u8; 6], len: u8) -> Prefix {
    let mut a = [0u8; 16];
    a[..6].copy_from_slice(&bytes6);
    Prefix::new_v6(a, len)
}

/// r1 - r2 p2p LSDB (Router-LSAs + Link-LSAs), metric 10.
fn v3_p2p_lsdb(r1: u32, r2: u32) -> Lsdb {
    let mut db = Lsdb::new();
    let mk = |from_if: u32, to_if: u32, to: u32| crate::lsa::v3::V3RouterLink {
        link_type: LINK_TYPE_POINTTOPOINT,
        metric: 10,
        interface_id: from_if,
        neighbor_interface_id: to_if,
        neighbor_router_id: to,
    };
    db.install(
        originate_v3_router_lsa(r1, ROUTER_BIT_V6, 0x13, &[mk(5, 3, r2)], None).unwrap(),
        0,
    );
    db.install(
        originate_v3_router_lsa(r2, ROUTER_BIT_V6, 0x13, &[mk(3, 5, r1)], None).unwrap(),
        0,
    );
    db.install(
        originate_v3_link_lsa(r1, 5, 1, 0x13, fe80(1), vec![], None).unwrap(),
        0,
    );
    db.install(
        originate_v3_link_lsa(r2, 3, 1, 0x13, fe80(2), vec![], None).unwrap(),
        0,
    );
    db
}

/// An intra-area ASBR: r2's 0x4005 (type 2, metric 100) installs at
/// the external metric with the SPF distance as the internal leg;
/// the type 1 form adds it.
#[test]
fn v3_external_intra_area_asbr() {
    let (r1, r2) = (0x0a00_0001, 0x0a00_0002);
    let mut db = v3_p2p_lsdb(r1, r2);
    let p = ext_prefix([0x20, 0x01, 0x0d, 0xb8, 0xbe, 0xef], 48);
    let dest = V3ExternalDestination::new(p, 100, true);
    db.install(originate_v3_as_external_lsa(r2, 1, &dest, None).unwrap(), 0);

    let spf = run_spf_v3(&db, r1);
    let routes = external_routes_v3(&db, &spf);
    assert_eq!(routes.len(), 1);
    let r = &routes[0];
    assert_eq!(r.prefix, p);
    assert_eq!(r.metric, 100, "type 2: external metric only");
    assert_eq!(r.metric_type, ExternalMetricType::Type2);
    assert_eq!(r.internal_cost, 10, "the SPF distance to the ASBR");
    assert_eq!(r.asbr, r2);
    assert_eq!(r.border_router, None);
    assert_eq!(r.forwarding_addr, None);

    // The type 1 form: cost-to-ASBR + external metric.
    let dest1 = V3ExternalDestination::new(p, 100, false);
    let mut db1 = v3_p2p_lsdb(r1, r2);
    db1.install(
        originate_v3_as_external_lsa(r2, 1, &dest1, None).unwrap(),
        0,
    );
    let spf1 = run_spf_v3(&db1, r1);
    let routes1 = external_routes_v3(&db1, &spf1);
    assert_eq!(routes1[0].metric, 110, "type 1: internal + external");
    assert_eq!(routes1[0].metric_type, ExternalMetricType::Type1);
}

/// §16.4 (b) v3 form: the ASBR sits in another area — a 0x2004 from
/// the reachable border router r2 resolves r3's leg
/// (dist(r2) + 0x2004 metric); the 0x4005's LS ID is irrelevant.
#[test]
fn v3_external_inter_area_asbr_via_2004() {
    let (r1, r2, r3) = (0x0a00_0001, 0x0a00_0002, 0x0a00_0003);
    let mut db = v3_p2p_lsdb(r1, r2);
    // r2's inter-area-router-LSA: destination ASBR r3, metric 5.
    db.install(
        originate_v3_inter_area_router_lsa(r2, r3, 0x13, r3, 5, None).unwrap(),
        0,
    );
    // r3's external: type 2 metric 100. LS ID arbitrary (99).
    let p = ext_prefix([0x20, 0x01, 0x0d, 0xb8, 0xca, 0xfe], 48);
    let dest = V3ExternalDestination::new(p, 100, true);
    db.install(
        originate_v3_as_external_lsa(r3, 99, &dest, None).unwrap(),
        0,
    );

    let spf = run_spf_v3(&db, r1);
    let routes = external_routes_v3(&db, &spf);
    assert_eq!(routes.len(), 1);
    let r = &routes[0];
    assert_eq!(r.prefix, p);
    assert_eq!(r.metric, 100);
    assert_eq!(r.internal_cost, 15, "dist(r2)=10 + 0x2004 metric 5");
    assert_eq!(r.border_router, Some(r2), "the ASBR leg came via r2");
    assert_eq!(r.asbr, r3);
}

/// §16.4 (c) v3 form: an F-bit forwarding address must be covered by
/// an intra-area or summary route; the covering route's metric is
/// the internal leg. Link-local and uncovered FAs yield nothing.
#[test]
fn v3_external_forwarding_address_validation() {
    let (r1, r2) = (0x0a00_0001, 0x0a00_0002);
    let mut db = v3_p2p_lsdb(r1, r2);
    // r2's own /64 — covers a FA inside it at metric 10.
    let p2 = net64(2);
    db.install(
        originate_v3_intra_area_prefix_lsa(
            r2,
            1,
            crate::lsa::v3::LS_TYPE_ROUTER,
            0,
            r2,
            vec![p2.clone()],
            None,
        )
        .unwrap(),
        0,
    );
    let fa_in: [u8; 16] = p2.addr; // inside 2001:db8:0:2::/64
                                   // (a) FA covered by the intra-area route.
    let p_a = ext_prefix([0x20, 0x01, 0x0d, 0xb8, 0xaa, 0x00], 48);
    let mut dest_a = V3ExternalDestination::new(p_a, 30, true);
    dest_a.forwarding_addr = Some(fa_in);
    db.install(
        originate_v3_as_external_lsa(r2, 1, &dest_a, None).unwrap(),
        0,
    );
    // (b) FA outside every known prefix.
    let p_b = ext_prefix([0x20, 0x01, 0x0d, 0xb8, 0xbb, 0x00], 48);
    let mut dest_b = V3ExternalDestination::new(p_b, 30, true);
    dest_b.forwarding_addr = Some([0x20, 0x01, 0x0d, 0xb9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
    db.install(
        originate_v3_as_external_lsa(r2, 2, &dest_b, None).unwrap(),
        0,
    );
    // (c) Link-local FA — illegal per §A.4.7, dropped.
    let p_c = ext_prefix([0x20, 0x01, 0x0d, 0xb8, 0xcc, 0x00], 48);
    let mut dest_c = V3ExternalDestination::new(p_c, 30, true);
    dest_c.forwarding_addr = Some(fe80(9));
    db.install(
        originate_v3_as_external_lsa(r2, 3, &dest_c, None).unwrap(),
        0,
    );

    let spf = run_spf_v3(&db, r1);
    let routes = external_routes_v3(&db, &spf);
    assert_eq!(routes.len(), 1, "only the covered FA survives");
    assert_eq!(routes[0].prefix, p_a);
    assert_eq!(routes[0].internal_cost, 10, "the covering /64's metric");
    assert_eq!(routes[0].forwarding_addr, Some(IpAddr::V6(fa_in)));
    assert_eq!(routes[0].asbr, r2, "the LSA's advertising router");
}

/// §16.4 (1)/(6) filters: LSInfinity and NU-marked externals are
/// skipped; for identical prefixes type 1 beats type 2 and the
/// lower external metric wins within a type.
#[test]
fn v3_external_filters_and_preference() {
    let (r1, r2) = (0x0a00_0001, 0x0a00_0002);
    let mut db = v3_p2p_lsdb(r1, r2);
    let p = ext_prefix([0x20, 0x01, 0x0d, 0xb8, 0x0d, 0x00], 48);
    // Type 1 metric 10 → 20; type 2 metric 300 (loses); type 2
    // metric 50 (wins among type 2 but still loses to type 1).
    let t1 = V3ExternalDestination::new(p, 10, false);
    let t2_big = V3ExternalDestination::new(p, 300, true);
    let t2_small = V3ExternalDestination::new(p, 50, true);
    db.install(originate_v3_as_external_lsa(r2, 1, &t1, None).unwrap(), 0);
    db.install(
        originate_v3_as_external_lsa(r2, 2, &t2_big, None).unwrap(),
        0,
    );
    db.install(
        originate_v3_as_external_lsa(r2, 3, &t2_small, None).unwrap(),
        0,
    );
    // LSInfinity and NU-marked destinations are skipped.
    let p_inf = ext_prefix([0x20, 0x01, 0x0d, 0xb8, 0x0e, 0x00], 48);
    let mut inf = V3ExternalDestination::new(p_inf, 0x00ff_ffff, true);
    inf.metric = 0x00ff_ffff;
    db.install(originate_v3_as_external_lsa(r2, 4, &inf, None).unwrap(), 0);
    let p_nu = ext_prefix([0x20, 0x01, 0x0d, 0xb8, 0x0f, 0x00], 48);
    let mut nu = V3ExternalDestination::new(p_nu, 10, true);
    nu.prefix = Prefix::new_v6(
        {
            let mut a = [0u8; 16];
            a[..6].copy_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0x0f, 0x00]);
            a
        },
        48,
    );
    db.install(originate_v3_as_external_lsa(r2, 5, &nu, None).unwrap(), 0);
    // Manually set the NU bit on the LSA's prefix (the originator
    // always clears it — §4.4.3.6). A fresh instance with a higher
    // sequence replaces the clean one.
    let key = crate::lsa::LsaKey {
        ls_type: crate::lsa::v3::LS_TYPE_AS_EXTERNAL,
        link_state_id: 5,
        advertising_router: r2,
    };
    if let Some(entry) = db.get(&key) {
        let mut lsa = entry.lsa.clone();
        lsa.body[5] = crate::lsa::v3::PREFIX_OPT_NU;
        lsa.header.ls_sequence_number = entry.lsa.header.ls_sequence_number + 1;
        lsa.finalize();
        db.install(lsa, 0);
    }

    let spf = run_spf_v3(&db, r1);
    let routes = external_routes_v3(&db, &spf);
    assert_eq!(routes.len(), 1, "type 1 wins over both type 2s");
    assert_eq!(routes[0].prefix, p);
    assert_eq!(routes[0].metric, 20);
    assert_eq!(routes[0].metric_type, ExternalMetricType::Type1);
    assert_eq!(routes[0].internal_cost, 10);
}

/// RFC 8362 §4.5: an E-AS-External-LSA (0xC025) installs the
/// external route in extended mode (with the forwarding address as
/// a sub-TLV); legacy mode ignores it.
#[test]
fn v3_e_as_external_installs_in_extended_mode() {
    let (r1, r2) = (0x0a00_0001, 0x0a00_0002);
    let mut db = v3_p2p_lsdb(r1, r2);
    let p = ext_prefix([0x20, 0x01, 0x0d, 0xb8, 0xca, 0xfe], 48);
    let dest = V3ExternalDestination::new(p, 100, true);
    db.install(
        crate::lsa::originate_v3_e_as_external_lsa(
            crate::lsa::LS_TYPE_E_AS_EXTERNAL,
            r2,
            7,
            &dest,
            None,
        )
        .unwrap(),
        0,
    );

    // Legacy mode: the 0xC025 is invisible.
    let spf = run_spf_v3(&db, r1);
    assert!(external_routes_v3(&db, &spf).is_empty());

    // Extended mode: type 2, metric 100, internal leg = SPF
    // distance 10, next hop = r2's link-local.
    let spf = crate::spf::run_spf_v3_extended(&db, r1);
    let routes = external_routes_v3_extended(&db, &spf);
    assert_eq!(routes.len(), 1);
    let r = &routes[0];
    assert_eq!(r.prefix, p);
    assert_eq!(r.metric, 100);
    assert_eq!(r.metric_type, ExternalMetricType::Type2);
    assert_eq!(r.internal_cost, 10);
    assert_eq!(r.asbr, r2);
    assert_eq!(r.next_hop, Some(lr_core::addr::IpAddr::V6(fe80(2))));
}
