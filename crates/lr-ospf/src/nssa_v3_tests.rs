//! OSPFv3 NSSA route computation tests (RFC 5340 §4.4.3.6 / RFC 3101 §2.5).
//!
//! Mirrors the v3 external-LSA tests (`external_v3_tests.rs`) — the
//! body shape is shared — but pins the NSSA-specific selection rules:
//!
//! - **Intra-area-only FA cover**: the forwarding address must be
//!   covered by an *intra-area* path of the NSSA itself, never by a
//!   type-3 summary. The type-5 path admits summaries; the type-7 path
//!   must not.
//! - **Intra-area-only ASBR reachability**: the ASBR must be reachable
//!   within the NSSA itself. There is no `0x2004` inter-area-router
//!   fallback (type-4 LSAs never flood into NSSAs).
//! - **Default-route install rules** (RFC 3101 §2.5 step (3) [NSSA]):
//!   border routers skip type-7 defaults whose P-bit is clear, and
//!   skip all type-7 defaults when summary import is suppressed. The
//!   v3 P-bit travels in the prefix-options byte
//!   ([`PREFIX_OPT_P`], RFC 5340 §A.4.1.1), since v3 LSA headers carry
//!   no options byte.

use super::*;
use crate::external::ExternalMetricType;
use crate::lsa::v3::{
    originate_v3_as_external_lsa, originate_v3_intra_area_prefix_lsa, originate_v3_link_lsa,
    originate_v3_nssa_lsa, originate_v3_router_lsa, V3ExternalDestination, V3Prefix,
    LINK_TYPE_POINTTOPOINT, LS_TYPE_ROUTER, ROUTER_BIT_V6,
};
use crate::lsa::{LsaKey, LS_TYPE_E_TYPE_7, PREFIX_OPT_P};
use crate::spf::run_spf_v3;
use lr_core::addr::{IpAddr, Prefix};

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

/// r1 - r2 p2p LSDB (Router-LSAs + Link-LSAs), metric 10. Mirrors the
/// `external_v3_tests::v3_p2p_lsdb` helper so the v3 NSSA tests
/// exercise the same intra-area topology.
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

/// An intra-area ASBR: r2's 0x2007 (type 2, metric 100) installs at the
/// external metric with the SPF distance as the internal leg; the
/// type 1 form adds it. Mirrors the v3 type-5
/// `v3_external_intra_area_asbr` test for the type-7 path.
#[test]
fn v3_nssa_intra_area_asbr() {
    let (r1, r2) = (0x0a00_0001, 0x0a00_0002);
    let mut db = v3_p2p_lsdb(r1, r2);
    let p = ext_prefix([0x20, 0x01, 0x0d, 0xb8, 0xbe, 0xef], 48);
    // Type 2 metric 100, P-bit clear (FA = None is fine — the ASBR
    // itself is the next hop, §2.5 step (3)).
    let dest = V3ExternalDestination::new(p, 100, true);
    db.install(originate_v3_nssa_lsa(r2, 1, &dest, false, None).unwrap(), 0);

    let spf = run_spf_v3(&db, r1);
    let routes = nssa_routes_v3(&db, &spf, NssaCalcOpts::default());
    assert_eq!(routes.len(), 1);
    let r = &routes[0];
    assert_eq!(r.prefix, p);
    assert_eq!(r.metric, 100, "type 2: external metric only");
    assert_eq!(r.metric_type, ExternalMetricType::Type2);
    assert_eq!(r.internal_cost, 10, "the SPF distance to the ASBR");
    assert_eq!(r.asbr, r2);
    assert_eq!(r.border_router, None);
    assert_eq!(r.forwarding_addr, None);
    // `V3ExternalDestination::new` defaults `route_tag` to `None`,
    // so the v3 LSA carries no T-bit-set tag field — the route
    // computation surfaces `None` (the v3 T bit distinguishes "no
    // tag" from "tag of zero").
    assert_eq!(r.route_tag, None);

    // The type 1 form: cost-to-ASBR + external metric.
    let dest1 = V3ExternalDestination::new(p, 100, false);
    let mut db1 = v3_p2p_lsdb(r1, r2);
    db1.install(
        originate_v3_nssa_lsa(r2, 1, &dest1, false, None).unwrap(),
        0,
    );
    let spf1 = run_spf_v3(&db1, r1);
    let routes1 = nssa_routes_v3(&db1, &spf1, NssaCalcOpts::default());
    assert_eq!(routes1[0].metric, 110, "type 1: internal + external");
    assert_eq!(routes1[0].metric_type, ExternalMetricType::Type1);
}

/// A v3 0x2007 LSA with the T-bit-set external route tag (RFC 5340
/// §A.4.7) — the OSPF route computation surfaces the tag through
/// `ExternalRouteV3::route_tag` so the resulting RIB `Route::tag`
/// carries it and the policy DSL's `ospf.tag` accessor reads the
/// value. Mirrors the v3 type-5 tag test for the type-7 path.
#[test]
fn v3_nssa_carries_route_tag() {
    let (r1, r2) = (0x0a00_0001, 0x0a00_0002);
    let mut db = v3_p2p_lsdb(r1, r2);
    let p = ext_prefix([0x20, 0x01, 0x0d, 0xb8, 0xbe, 0xef], 48);
    let mut dest = V3ExternalDestination::new(p, 100, true);
    dest.route_tag = Some(0xdead_beef);
    db.install(originate_v3_nssa_lsa(r2, 1, &dest, false, None).unwrap(), 0);

    let spf = run_spf_v3(&db, r1);
    let routes = nssa_routes_v3(&db, &spf, NssaCalcOpts::default());
    assert_eq!(routes.len(), 1);
    assert_eq!(routes[0].route_tag, Some(0xdead_beef));
}

/// §2.5 step (3) [NSSA] — the forwarding address must be covered by
/// an *intra-area* path of the NSSA itself. Unlike the type-5 path,
/// summary routes (0x2003 / 0xA023) do NOT qualify. A FA covered by
/// a summary alone yields nothing; a FA covered by an intra-area
/// route yields the route.
#[test]
fn v3_nssa_forwarding_address_needs_intra_area_cover() {
    let (r1, r2) = (0x0a00_0001, 0x0a00_0002);
    let mut db = v3_p2p_lsdb(r1, r2);
    // r2's own /64 — covers a FA inside it at metric 10 (an
    // intra-area route, the only kind §2.5 step (3) admits for
    // type-7 FAs).
    let p2 = net64(2);
    db.install(
        originate_v3_intra_area_prefix_lsa(r2, 1, LS_TYPE_ROUTER, 0, r2, vec![p2.clone()], None)
            .unwrap(),
        0,
    );
    let fa_in: [u8; 16] = p2.addr; // inside 2001:db8:0:2::/64
    let p_a = ext_prefix([0x20, 0x01, 0x0d, 0xb8, 0xaa, 0x00], 48);
    let mut dest_a = V3ExternalDestination::new(p_a, 30, true);
    dest_a.forwarding_addr = Some(fa_in);
    db.install(
        originate_v3_nssa_lsa(r2, 1, &dest_a, false, None).unwrap(),
        0,
    );

    let spf = run_spf_v3(&db, r1);
    let routes = nssa_routes_v3(&db, &spf, NssaCalcOpts::default());
    assert_eq!(routes.len(), 1, "intra-area cover installs");
    assert_eq!(routes[0].prefix, p_a);
    assert_eq!(routes[0].internal_cost, 10, "the covering /64's metric");
    assert_eq!(routes[0].forwarding_addr, Some(IpAddr::V6(fa_in)));
    assert_eq!(routes[0].asbr, r2, "the LSA's advertising router");
}

/// §2.5 step (3) [NSSA] — when the FA is uncovered by any intra-area
/// route, the type-7 candidate is dropped (mirrors the v2 path's
/// `nssa_routes_forwarding_address_needs_intra_cover` test). The
/// FA below sits outside every known intra-area prefix.
#[test]
fn v3_nssa_forwarding_address_uncovered_drops_route() {
    let (r1, r2) = (0x0a00_0001, 0x0a00_0002);
    let mut db = v3_p2p_lsdb(r1, r2);
    let p = ext_prefix([0x20, 0x01, 0x0d, 0xb8, 0xaa, 0x00], 48);
    let mut dest = V3ExternalDestination::new(p, 30, true);
    // FA outside every known prefix.
    dest.forwarding_addr = Some([0x20, 0x01, 0x0d, 0xb9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
    db.install(originate_v3_nssa_lsa(r2, 1, &dest, false, None).unwrap(), 0);

    let spf = run_spf_v3(&db, r1);
    let routes = nssa_routes_v3(&db, &spf, NssaCalcOpts::default());
    assert!(routes.is_empty(), "an uncovered FA drops the route");
}

/// §2.5 step (3) [NSSA] — the v3 type-7 path does NOT honour
/// inter-area summary routes as forwarding-address cover (the type-5
/// v3 path does). A summary-LSA covering the FA must NOT make a
/// type-7 candidate install — type-7 LSAs do not leave the NSSA, so
/// a summary's reachability crosses the area boundary the type-7 was
/// confined to.
#[test]
fn v3_nssa_forwarding_address_rejects_inter_area_summary_cover() {
    let (r1, r2) = (0x0a00_0001, 0x0a00_0002);
    let mut db = v3_p2p_lsdb(r1, r2);
    // r2 originates a 0x2003 summary-LSA covering 2001:db8:0:99::/64
    // at metric 5. This is a *summary*, not an intra-area route.
    let summary_prefix = ext_prefix([0x20, 0x01, 0x0d, 0xb8, 0x00, 0x99], 64);
    let summary_dest = crate::abr::SummaryDestination::new(summary_prefix, 5);
    db.install(
        crate::abr::originate_v3_inter_area_prefix_lsa(r2, 7, &summary_dest, None).unwrap(),
        0,
    );
    // The FA sits inside the summary-LSA's prefix.
    let mut fa = [0u8; 16];
    fa[..6].copy_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0x00, 0x99]);
    let p = ext_prefix([0x20, 0x01, 0x0d, 0xb8, 0xaa, 0x00], 48);
    let mut dest = V3ExternalDestination::new(p, 30, true);
    dest.forwarding_addr = Some(fa);
    db.install(originate_v3_nssa_lsa(r2, 1, &dest, false, None).unwrap(), 0);

    let spf = run_spf_v3(&db, r1);
    let routes = nssa_routes_v3(&db, &spf, NssaCalcOpts::default());
    assert!(
        routes.is_empty(),
        "summary cover must not satisfy the §2.5 step (3) intra-area rule"
    );
}

/// §2.5 step (3) [NSSA] — link-local and unspecified forwarding
/// addresses are illegal per RFC 5340 §A.4.7; the type-7 path drops
/// them just like the type-5 path does.
#[test]
fn v3_nssa_forwarding_address_link_local_is_dropped() {
    let (r1, r2) = (0x0a00_0001, 0x0a00_0002);
    let mut db = v3_p2p_lsdb(r1, r2);
    let p = ext_prefix([0x20, 0x01, 0x0d, 0xb8, 0xcc, 0x00], 48);
    let mut dest = V3ExternalDestination::new(p, 30, true);
    dest.forwarding_addr = Some(fe80(9)); // link-local
    db.install(originate_v3_nssa_lsa(r2, 1, &dest, false, None).unwrap(), 0);

    let spf = run_spf_v3(&db, r1);
    let routes = nssa_routes_v3(&db, &spf, NssaCalcOpts::default());
    assert!(routes.is_empty(), "link-local FA is illegal");
}

/// §2.5 step (3) [NSSA] — there is no inter-area-router-LSA leg for
/// type-7 routes (type-4 LSAs do not flood into NSSAs). An ASBR
/// reachable only through an inter-area-router-LSA must NOT
/// contribute a type-7 route, even though the same setup would
/// contribute a type-5 route through the §16.4 (b) v3 path.
#[test]
fn v3_nssa_no_inter_area_router_leg() {
    let (r1, r2, r3) = (0x0a00_0001, 0x0a00_0002, 0x0a00_0003);
    let mut db = v3_p2p_lsdb(r1, r2);
    // r2's inter-area-router-LSA: destination ASBR r3, metric 5.
    // r3 sits in another area; only r2's 0x2004 advertises it.
    db.install(
        crate::lsa::v3::originate_v3_inter_area_router_lsa(r2, r3, 0x13, r3, 5, None).unwrap(),
        0,
    );
    // r3's type-7 LSA (NSSA-LSA, type 0x2007) — the v3 type-7 path
    // must NOT honour the inter-area-router leg.
    let p = ext_prefix([0x20, 0x01, 0x0d, 0xb8, 0xca, 0xfe], 48);
    let dest = V3ExternalDestination::new(p, 100, true);
    db.install(
        originate_v3_nssa_lsa(r3, 99, &dest, false, None).unwrap(),
        0,
    );

    let spf = run_spf_v3(&db, r1);
    let routes = nssa_routes_v3(&db, &spf, NssaCalcOpts::default());
    assert!(
        routes.is_empty(),
        "the v3 type-7 path must not honour an inter-area-router leg"
    );

    // Sanity check: the same setup with a type-5 LSA (0x4005) WOULD
    // honour the leg (verifies the asymmetry the v3 NSSA defect
    // describes — the type-5 path's `asbr_legs` table is the gap).
    let mut db5 = v3_p2p_lsdb(r1, r2);
    db5.install(
        crate::lsa::v3::originate_v3_inter_area_router_lsa(r2, r3, 0x13, r3, 5, None).unwrap(),
        0,
    );
    db5.install(
        originate_v3_as_external_lsa(r3, 99, &dest, None).unwrap(),
        0,
    );
    let spf5 = run_spf_v3(&db5, r1);
    let ext_routes = crate::external::external_routes_v3(&db5, &spf5);
    assert_eq!(ext_routes.len(), 1, "type-5 still uses the 0x2004 leg");
    assert_eq!(
        ext_routes[0].internal_cost, 15,
        "dist(r2)=10 + 0x2004 metric 5"
    );
}

/// §16.4 (1)/(6) filters: LSInfinity and NU-marked type-7 LSAs are
/// skipped; for identical prefixes type 1 beats type 2 and the
/// lower external metric wins within a type. Mirrors the v3 type-5
/// `v3_external_filters_and_preference` test for the type-7 path.
#[test]
fn v3_nssa_filters_and_preference() {
    let (r1, r2) = (0x0a00_0001, 0x0a00_0002);
    let mut db = v3_p2p_lsdb(r1, r2);
    let p = ext_prefix([0x20, 0x01, 0x0d, 0xb8, 0x0d, 0x00], 48);
    // Type 1 metric 10 → 20; type 2 metric 300 (loses); type 2
    // metric 50 (wins among type 2 but still loses to type 1).
    let t1 = V3ExternalDestination::new(p, 10, false);
    let t2_big = V3ExternalDestination::new(p, 300, true);
    let t2_small = V3ExternalDestination::new(p, 50, true);
    db.install(originate_v3_nssa_lsa(r2, 1, &t1, false, None).unwrap(), 0);
    db.install(
        originate_v3_nssa_lsa(r2, 2, &t2_big, false, None).unwrap(),
        0,
    );
    db.install(
        originate_v3_nssa_lsa(r2, 3, &t2_small, false, None).unwrap(),
        0,
    );
    // LSInfinity external → skipped. `V3ExternalDestination::new`
    // caps the metric at 0x00ff_fffe, so override after `new` to
    // actually write LSInfinity onto the wire (mirrors the v3 type-5
    // path's `v3_external_filters_and_preference` setup).
    let mut inf = V3ExternalDestination::new(
        ext_prefix([0x20, 0x01, 0x0d, 0xb8, 0x0e, 0x00], 48),
        0x00ff_ffff,
        true,
    );
    inf.metric = 0x00ff_ffff;
    db.install(originate_v3_nssa_lsa(r2, 4, &inf, false, None).unwrap(), 0);

    let spf = run_spf_v3(&db, r1);
    let routes = nssa_routes_v3(&db, &spf, NssaCalcOpts::default());
    assert_eq!(
        routes.len(),
        1,
        "type 1 wins over both type 2s; LSInfinity skipped"
    );
    assert_eq!(routes[0].prefix, p);
    assert_eq!(routes[0].metric, 20);
    assert_eq!(routes[0].metric_type, ExternalMetricType::Type1);
    assert_eq!(routes[0].internal_cost, 10);
}

/// §2.5 step (3) [NSSA] default-route install rules for border
/// routers: a border router skips a type-7 default whose P-bit is
/// clear, and skips ALL type-7 defaults when summary import is
/// suppressed (its own type-3 default wins). A non-border router
/// installs every type-7 default regardless of the P-bit. The v3
/// P-bit travels in the prefix-options byte.
#[test]
fn v3_nssa_default_install_rules_for_border_routers() {
    // The default route's FA must be a *global* IPv6 address inside
    // an intra-area prefix — link-local FAs are illegal per RFC 5340
    // §A.4.7 and dropped by the type-7 path. We originate r2's own
    // /64 intra-area prefix and use a global FA inside it so the
    // install rules (not FA validity) drive the assertion.
    fn area_with_default(p_bit: bool) -> (u32, u32, Lsdb) {
        let (r1, r2) = (0x0a00_0001, 0x0a00_0002);
        let mut db = v3_p2p_lsdb(r1, r2);
        let p2 = net64(2);
        db.install(
            originate_v3_intra_area_prefix_lsa(
                r2,
                1,
                LS_TYPE_ROUTER,
                0,
                r2,
                vec![p2.clone()],
                None,
            )
            .unwrap(),
            0,
        );
        let p = Prefix::new_v6([0u8; 16], 0);
        let mut dest = V3ExternalDestination::new(p, 40, true);
        // §2.3: a P-bit-set type-7 must carry a non-zero FA — use a
        // global IPv6 address inside r2's intra-area prefix.
        let mut fa = p2.addr;
        fa[15] = 1; // 2001:db8:0:2::1
        dest.forwarding_addr = Some(fa);
        db.install(originate_v3_nssa_lsa(r2, 1, &dest, p_bit, None).unwrap(), 0);
        (r1, r2, db)
    }

    // (1) Non-border router: install every type-7 default,
    // regardless of the P-bit.
    let (r1, _r2, db) = area_with_default(false);
    let spf = run_spf_v3(&db, r1);
    let routes = nssa_routes_v3(
        &db,
        &spf,
        NssaCalcOpts {
            border_router: false,
            summaries_suppressed: false,
        },
    );
    assert_eq!(routes.len(), 1, "non-border router installs the default");

    // (2) Border router, summaries imported, P-bit CLEAR: skip.
    let (r1, _r2, db) = area_with_default(false);
    let spf = run_spf_v3(&db, r1);
    let routes = nssa_routes_v3(
        &db,
        &spf,
        NssaCalcOpts {
            border_router: true,
            summaries_suppressed: false,
        },
    );
    assert!(
        routes.is_empty(),
        "border router skips a P-bit-clear default"
    );

    // (3) Border router, summaries imported, P-bit SET: install.
    let (r1, _r2, db) = area_with_default(true);
    let spf = run_spf_v3(&db, r1);
    let routes = nssa_routes_v3(
        &db,
        &spf,
        NssaCalcOpts {
            border_router: true,
            summaries_suppressed: false,
        },
    );
    assert_eq!(
        routes.len(),
        1,
        "border router installs a P-bit-set default"
    );

    // (4) Border router, summaries suppressed, P-bit SET: skip
    // (the border router's own type-3 default wins).
    let (r1, _r2, db) = area_with_default(true);
    let spf = run_spf_v3(&db, r1);
    let routes = nssa_routes_v3(
        &db,
        &spf,
        NssaCalcOpts {
            border_router: true,
            summaries_suppressed: true,
        },
    );
    assert!(
        routes.is_empty(),
        "border router skips ALL type-7 defaults when summaries are suppressed"
    );
}

/// RFC 8362 §4.6: an E-Type-7-LSA (0xA027) installs the type-7 route
/// in extended mode (with the forwarding address as a sub-TLV);
/// legacy mode ignores it. Mirrors the v3 type-5
/// `v3_e_as_external_installs_in_extended_mode` test for the type-7
/// path.
#[test]
fn v3_e_type_7_installs_in_extended_mode() {
    let (r1, r2) = (0x0a00_0001, 0x0a00_0002);
    let mut db = v3_p2p_lsdb(r1, r2);
    let p = ext_prefix([0x20, 0x01, 0x0d, 0xb8, 0xca, 0xfe], 48);
    let dest = V3ExternalDestination::new(p, 100, true);
    db.install(
        crate::lsa::originate_v3_e_as_external_lsa(LS_TYPE_E_TYPE_7, r2, 7, &dest, None).unwrap(),
        0,
    );

    // Legacy mode: the 0xA027 is invisible to nssa_routes_v3.
    let spf = run_spf_v3(&db, r1);
    assert!(nssa_routes_v3(&db, &spf, NssaCalcOpts::default()).is_empty());

    // Extended mode: type 2, metric 100, internal leg = SPF
    // distance 10, next hop = r2's link-local.
    let spf = crate::spf::run_spf_v3_extended(&db, r1);
    let routes = nssa_routes_v3_extended(&db, &spf, NssaCalcOpts::default());
    assert_eq!(routes.len(), 1);
    let r = &routes[0];
    assert_eq!(r.prefix, p);
    assert_eq!(r.metric, 100);
    assert_eq!(r.metric_type, ExternalMetricType::Type2);
    assert_eq!(r.internal_cost, 10);
    assert_eq!(r.asbr, r2);
    assert_eq!(r.next_hop, Some(IpAddr::V6(fe80(2))));
}

/// Origination helper sanity-check: a P-bit-set type-7 MUST carry a
/// non-zero forwarding address (RFC 3101 §2.3); `originate_v3_nssa_lsa`
/// returns `None` when the P-bit is set but no FA is supplied.
#[test]
fn v3_originate_nssa_lsa_requires_fa_with_p_bit() {
    let r2 = 0x0a00_0002;
    let p = ext_prefix([0x20, 0x01, 0x0d, 0xb8, 0xca, 0xfe], 48);
    let dest_no_fa = V3ExternalDestination::new(p, 100, true);
    assert!(
        originate_v3_nssa_lsa(r2, 1, &dest_no_fa, true, None).is_none(),
        "P-bit set without a FA refuses to originate"
    );
    // Same destination with a FA — originates cleanly, and the
    // prefix-options byte carries the P-bit.
    let mut dest_fa = dest_no_fa;
    dest_fa.forwarding_addr = Some(fe80(2));
    let lsa =
        originate_v3_nssa_lsa(r2, 1, &dest_fa, true, None).expect("P-bit set with a FA originates");
    // Decode the body and verify the prefix-options P-bit is set.
    let decoded = crate::lsa::v3::V3AsExternalBody::decode(&lsa.body).unwrap();
    assert!(
        decoded.prefix.options & PREFIX_OPT_P != 0,
        "the P-bit travels in the prefix-options byte for v3"
    );
    // LSA type is 0x2007 (LS_TYPE_NSSA).
    assert_eq!(lsa.header.ls_type, crate::lsa::LS_TYPE_NSSA);
}

/// The v3 type-7 path ignores AS-external-LSAs (0x4005) — only
/// NSSA-LSAs (0x2007) contribute type-7 routes. A 0x4005 LSA in the
/// same LSDB must NOT show up in `nssa_routes_v3`'s output (the
/// type-5 path handles those).
#[test]
fn v3_nssa_ignores_type_5_lsas() {
    let (r1, r2) = (0x0a00_0001, 0x0a00_0002);
    let mut db = v3_p2p_lsdb(r1, r2);
    let p = ext_prefix([0x20, 0x01, 0x0d, 0xb8, 0xca, 0xfe], 48);
    let dest = V3ExternalDestination::new(p, 100, true);
    // A type-5 LSA (0x4005) — invisible to nssa_routes_v3.
    db.install(originate_v3_as_external_lsa(r2, 1, &dest, None).unwrap(), 0);

    let spf = run_spf_v3(&db, r1);
    let routes = nssa_routes_v3(&db, &spf, NssaCalcOpts::default());
    assert!(routes.is_empty(), "type-5 LSAs are not type-7 candidates");
}

/// Fast-path: an LSDB with no type-7 LSAs yields nothing and skips
/// the covering-table construction (verified by the empty result on
/// a pure-intra-area LSDB).
#[test]
fn v3_nssa_fast_path_no_type_7_lsas() {
    let (r1, r2) = (0x0a00_0001, 0x0a00_0002);
    let db = v3_p2p_lsdb(r1, r2);
    let spf = run_spf_v3(&db, r1);
    let routes = nssa_routes_v3(&db, &spf, NssaCalcOpts::default());
    assert!(routes.is_empty());
}

/// An unreachable ASBR (no router-LSA at all) is dropped — the
/// intra-area ASBR reachability check excludes it.
#[test]
fn v3_nssa_skips_unreachable_asbr() {
    let (r1, _r2) = (0x0a00_0001, 0x0a00_0002);
    let mut db = Lsdb::new();
    // r1's router-LSA only — no path to ASBR 5.
    db.install(
        originate_v3_router_lsa(r1, ROUTER_BIT_V6, 0x13, &[], None).unwrap(),
        0,
    );
    db.install(
        originate_v3_link_lsa(r1, 5, 1, 0x13, fe80(1), vec![], None).unwrap(),
        0,
    );
    let p = ext_prefix([0x20, 0x01, 0x0d, 0xb8, 0xca, 0xfe], 48);
    let dest = V3ExternalDestination::new(p, 100, true);
    db.install(originate_v3_nssa_lsa(5, 99, &dest, false, None).unwrap(), 0);

    let spf = run_spf_v3(&db, r1);
    let routes = nssa_routes_v3(&db, &spf, NssaCalcOpts::default());
    assert!(routes.is_empty(), "an unreachable ASBR contributes nothing");
}

/// Manual mutation of the prefix-options byte (mirrors the v3
/// external NU-bit test): set PREFIX_OPT_P manually on an existing
/// type-7 LSA's prefix to flip the P-bit. Verifies the v3 NSSA path
/// reads the P-bit from the wire-form prefix-options byte.
#[test]
fn v3_nssa_p_bit_read_from_prefix_options_byte() {
    let (r1, r2) = (0x0a00_0001, 0x0a00_0002);
    let mut db = v3_p2p_lsdb(r1, r2);
    // Originate a default type-7 with P-bit CLEAR (FA stays None —
    // §2.3 only constrains P-bit-set LSAs).
    let p = Prefix::new_v6([0u8; 16], 0);
    let dest = V3ExternalDestination::new(p, 40, true);
    db.install(originate_v3_nssa_lsa(r2, 1, &dest, false, None).unwrap(), 0);

    // Manually set the P-bit on the LSA's prefix-options byte
    // (position 5 in the body — the second byte after the
    // 4-byte metric word and the 1-byte prefix length).
    let key = LsaKey {
        ls_type: crate::lsa::LS_TYPE_NSSA,
        link_state_id: 1,
        advertising_router: r2,
    };
    if let Some(entry) = db.get(&key) {
        let mut lsa = entry.lsa.clone();
        lsa.body[5] |= PREFIX_OPT_P;
        lsa.header.ls_sequence_number = entry.lsa.header.ls_sequence_number + 1;
        lsa.finalize();
        db.install(lsa, 0);
    }

    let spf = run_spf_v3(&db, r1);
    // Border router with summaries imported: the P-bit-set default
    // installs (the FA is None, but the border-router install rule
    // checks the P-bit before §2.3's FA-nonzero rule for
    // origination — at the receive side we already have the LSA,
    // so the FA check is moot).
    let routes = nssa_routes_v3(
        &db,
        &spf,
        NssaCalcOpts {
            border_router: true,
            summaries_suppressed: false,
        },
    );
    assert_eq!(
        routes.len(),
        1,
        "border router installs a P-bit-set default"
    );
}
