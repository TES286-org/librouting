//! `cargo bench -p lr-policy --bench import_pipeline` — measure the
//! per-route cost of the BGP import pipeline the daemon runs (ROADMAP-v3
//! D6.2, GitHub issue #19 P0).
//!
//! The DSL-level bench (`filter_eval.rs`) measures the evaluator in
//! isolation; this bench measures the *pipeline* the daemon runs per
//! UPDATE: bytecode eval → Adj-RIB-In install → Loc-RIB install +
//! best-path select. That is the surface any future DSL optimisation
//! has to actually move — a win that does not show up here is a win
//! the daemon does not feel.
//!
//! Three scales:
//! * 100 routes  — small enterprise / lab router.
//! * 1 000 routes — medium edge router.
//! * 10 000 routes — large enterprise / IXP edge.
//!
//! Two filter shapes are exercised at every scale:
//! * `trivial` — `accept;`. Measures the fixed pipeline overhead
//!   (DSL setup + Adj-RIB-In insert + Loc-RIB install + select) —
//!   the cost every route pays regardless of policy complexity.
//! * `realistic` — `if bgp.local_pref > 100 && bgp.med < 50 then
//!   accept; if net ~ [ 10.0.0.0/8{16,24} ] then accept; reject;`.
//!   Measures the canonical import-policy shape (attribute read +
//!   branch + prefix-set membership) end-to-end through the
//!   pipeline. This is the shape the issue comment's "daemon-level
//!   import-pipeline bench" calls out: route in → verdict + mutated
//!   route out.
//!
//! Each iteration:
//! 1. Resets the Adj-RIB-In and Loc-RIB to empty.
//! 2. Compiles the filter once (outside the timed loop, mirroring
//!    `daemon_policy::build_filters` which precompiles every
//!    `[[filter]]` at startup).
//! 3. For each route: bytecode eval → if accepted, feed into
//!    Adj-RIB-In and install into Loc-RIB (selecting the best).
//!
//! The bench is the basis for the #19 P0 perf baseline. The issue
//! calls for it to outlive the #18 config-format migration (route in
//! → verdict + mutated route out, regardless of how the filter was
//! configured) — so the filter body is a string literal, not a
//! config fragment, and the bench can be reused unchanged after
//! the TOML→DSL migration lands.

use criterion::{criterion_group, criterion_main, Criterion, Throughput};
use lr_core::addr::{Asn, Prefix};
use lr_core::attr::{AttrTag, Attribute, Attributes};
use lr_core::nlri::NlriFamily;
use lr_core::rib::{Preference, Protocol, Route, RouteKey, RouteOrigin};
use lr_policy::filter::bytecode::{self, CompiledFilter};
use lr_policy::filter::{compile, FilterContext, RoaStateLit};
use lr_rib::{AdjRibIn, LocRib};
use std::hint::black_box;

/// Test context — mirrors the StubCtx in `filter/eval.rs`; kept
/// local so the bench is independent of the crate's test surface.
struct BenchCtx;

const TAG_AS_PATH: u8 = 2;
const TAG_MED: u8 = 4;
const TAG_LOCAL_PREF: u8 = 5;
const TAG_COMMUNITIES: u8 = 8;

fn attr(route: &Route, tag: u8) -> Option<Vec<u8>> {
    route
        .attributes
        .get(AttrTag::raw(tag))
        .map(|a| a.value.clone())
}

impl FilterContext for BenchCtx {
    fn bgp_local_pref(&self, route: &Route) -> Option<u32> {
        attr(route, TAG_LOCAL_PREF).and_then(|b| b.try_into().ok().map(u32::from_be_bytes))
    }
    fn bgp_med(&self, route: &Route) -> Option<u32> {
        attr(route, TAG_MED).and_then(|b| b.try_into().ok().map(u32::from_be_bytes))
    }
    fn bgp_next_hop(&self, _route: &Route) -> Option<lr_core::addr::IpAddr> {
        None
    }
    fn bgp_as_path(&self, route: &Route) -> Vec<Asn> {
        let Some(b) = attr(route, TAG_AS_PATH) else {
            return Vec::new();
        };
        let mut out = Vec::new();
        let mut i = 0;
        while i + 2 <= b.len() {
            let count = b[i + 1] as usize;
            i += 2;
            for _ in 0..count {
                if i + 4 > b.len() {
                    break;
                }
                out.push(Asn(u32::from_be_bytes(b[i..i + 4].try_into().unwrap())));
                i += 4;
            }
        }
        out
    }
    fn bgp_communities(&self, route: &Route) -> Vec<(Asn, u16)> {
        let Some(b) = attr(route, TAG_COMMUNITIES) else {
            return Vec::new();
        };
        let mut out = Vec::new();
        #[allow(clippy::chunks_exact_to_as_chunks)]
        for chunk in b.chunks_exact(4) {
            out.push((
                Asn(u16::from_be_bytes([chunk[0], chunk[1]]) as u32),
                u16::from_be_bytes([chunk[2], chunk[3]]),
            ));
        }
        out
    }
    fn bgp_origin(&self, _route: &Route) -> Option<u8> {
        Some(0)
    }
    fn roa_state(&self, _route: &Route) -> RoaStateLit {
        RoaStateLit::NotFound
    }
    fn set_bgp_local_pref(&self, route: &mut Route, value: u32) {
        route.attributes.insert(Attribute {
            tag: AttrTag::raw(TAG_LOCAL_PREF),
            flags: 0x40,
            value: value.to_be_bytes().to_vec(),
        });
    }
    fn set_bgp_med(&self, route: &mut Route, value: u32) {
        route.attributes.insert(Attribute {
            tag: AttrTag::raw(TAG_MED),
            flags: 0x80,
            value: value.to_be_bytes().to_vec(),
        });
    }
    fn set_bgp_next_hop(&self, _route: &mut Route, _value: lr_core::addr::IpAddr) {}
    fn bgp_as_path_prepend(&self, route: &mut Route, asn: Asn) {
        let mut path = self.bgp_as_path(route);
        path.insert(0, asn);
        let mut v = vec![2u8, path.len() as u8];
        for a in &path {
            v.extend_from_slice(&a.0.to_be_bytes());
        }
        route.attributes.insert(Attribute {
            tag: AttrTag::raw(TAG_AS_PATH),
            flags: 0x40,
            value: v,
        });
    }
    fn bgp_communities_add(&self, _route: &mut Route, _asn: Asn, _val: u16) {}
    fn set_bgp_communities(&self, _route: &mut Route, _set: Vec<(Asn, u16)>) {}
    fn set_bgp_as_path(&self, _route: &mut Route, _seq: Vec<Asn>) {}
    fn bgp_large_communities(&self, _route: &Route) -> Vec<(u32, u32, u32)> {
        Vec::new()
    }
    fn bgp_ext_communities(&self, _route: &Route) -> Vec<(u8, u8, u32, u16)> {
        Vec::new()
    }
    fn set_bgp_large_communities(&self, _route: &mut Route, _set: Vec<(u32, u32, u32)>) {}
    fn set_bgp_ext_communities(&self, _route: &mut Route, _set: Vec<(u8, u8, u32, u16)>) {}
}

/// Build a route for index `i` — distinct /24 in the 10/8 space,
/// with LOCAL_PREF=150 (matches `realistic`) and MED=30 (below the
/// 50 threshold), so the realistic filter accepts on the first
/// branch. This is the common-case accept path every production
/// import filter takes for the bulk of received routes.
fn make_route(i: u32) -> Route {
    let a = (i >> 8) as u8;
    let b = (i & 0xff) as u8;
    let prefix = Prefix::new_v4([10, a, b, 0], 24);
    let mut attrs = Attributes::new();
    attrs.insert(Attribute {
        tag: AttrTag::raw(TAG_LOCAL_PREF),
        flags: 0x40,
        value: 150u32.to_be_bytes().to_vec(),
    });
    attrs.insert(Attribute {
        tag: AttrTag::raw(TAG_MED),
        flags: 0x80,
        value: 30u32.to_be_bytes().to_vec(),
    });
    Route {
        key: RouteKey::new(prefix, NlriFamily::IPV4_UNICAST),
        origin: RouteOrigin { proto: 0, peer: 1 },
        protocol: Protocol::Bgp,
        preference: Preference::new(20, 100 + i),
        next_hop: None,
        attributes: attrs,
        age_ms: 0,
        path_id: 0,
        tag: None,
    }
}

/// The pipeline a single UPDATE goes through in the daemon, minus
/// the policy gates (RFC 8212 / safety net / enforce-first-as) that
/// are invariant across routes and would just add constant overhead
/// the DSL bench should not absorb. The closure is the surface the
/// daemon's `import_route` (see `lr-router/src/instance.rs`) walks
/// after those gates pass — keeping it as a free function means the
/// bench measures the same hot path the daemon runs, without
/// depending on `lr-router` (which would create a dev-dep cycle).
fn import_pipeline(
    route: Route,
    cf: &CompiledFilter,
    ctx: &dyn FilterContext,
    adj_in: &mut AdjRibIn,
    loc_rib: &mut LocRib,
) {
    let mut route = route;
    let verdict = bytecode::execute(cf, &mut route, ctx);
    if matches!(verdict, lr_policy::filter::EvalResult::Accept) {
        let origin = route.origin;
        adj_in.feed_pre_policy(origin, route.clone());
        // Loc-RIB install mirrors `instance::reselect` for the
        // single-path case (no Add-Path): install the route and let
        // the selector pick the best across the existing candidates
        // for the same key. Since the bench uses unique /24s, every
        // install is a fresh key — but `install` is the path the
        // daemon takes when the new route wins.
        loc_rib.install(route);
    }
}

fn bench_import_pipeline(c: &mut Criterion) {
    // Compile both filter shapes once — mirroring
    // `daemon_policy::build_filters` which precompiles every
    // `[[filter]]` at startup and reuses the compiled `Filter`
    // across every per-route eval.
    let trivial = compile("bench-pipeline-trivial", "accept;").unwrap();
    let trivial_vm = bytecode::compile(&trivial);
    let realistic_src = "if bgp.local_pref > 100 && bgp.med < 50 then accept; \
         if net ~ [ 10.0.0.0/8{16,24} ] then accept; reject;";
    let realistic = compile("bench-pipeline-realistic", realistic_src).unwrap();
    let realistic_vm = bytecode::compile(&realistic);

    let mut group = c.benchmark_group("import_pipeline");

    for size in [100u32, 1_000u32, 10_000u32] {
        let routes: Vec<Route> = (0..size).map(make_route).collect();
        group.throughput(Throughput::Elements(size as u64));

        group.bench_function(format!("trivial/{size}"), |b| {
            b.iter_with_setup(
                || routes.clone(),
                |routes| {
                    let mut adj_in = AdjRibIn::new();
                    let mut loc_rib = LocRib::new();
                    for r in routes {
                        import_pipeline(
                            black_box(r),
                            black_box(&trivial_vm),
                            black_box(&BenchCtx),
                            black_box(&mut adj_in),
                            black_box(&mut loc_rib),
                        );
                    }
                    let n = black_box(loc_rib.iter_best().count());
                    assert_eq!(n, size as usize, "trivial filter accepts every route");
                },
            );
        });

        group.bench_function(format!("realistic/{size}"), |b| {
            b.iter_with_setup(
                || routes.clone(),
                |routes| {
                    let mut adj_in = AdjRibIn::new();
                    let mut loc_rib = LocRib::new();
                    for r in routes {
                        import_pipeline(
                            black_box(r),
                            black_box(&realistic_vm),
                            black_box(&BenchCtx),
                            black_box(&mut adj_in),
                            black_box(&mut loc_rib),
                        );
                    }
                    // Every route has local_pref=150 > 100 and med=30
                    // < 50, so the realistic filter accepts on the
                    // first branch — the common-case accept path.
                    let n = black_box(loc_rib.iter_best().count());
                    assert_eq!(n, size as usize, "realistic filter accepts every route");
                },
            );
        });
    }

    group.finish();
}

criterion_group!(benches, bench_import_pipeline);
criterion_main!(benches);
