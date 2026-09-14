//! `cargo bench -p lr-policy --bench filter_eval` — measure the
//! filter DSL evaluator throughput (ROADMAP-v3 D6.2, D3.7).
//!
//! Three filters cover the policy complexity spectrum:
//!
//! * `simple_accept` — `accept;` — minimum overhead, measures the
//!   fixed cost of the evaluator setup + first-statement dispatch.
//! * `if_local_pref` — `if bgp.local_pref > 100 then accept; reject;`
//!   — the canonical import policy shape. The bench measures the
//!   cost of one attribute read + one comparison + one branch.
//! * `complex_chain` — multi-branch if/else + arithmetic + prefix-set
//!   membership. The bench measures the worst-case per-route cost
//!   of a policy that exercises every evaluator subsystem (scope,
//!   attribute lookup, arithmetic, prefix-set, branch).
//!
//! The bench is the basis for the D3.7 bytecode-VM refactor: the
//! current tree-walking interpreter has a ~2–5× regression risk vs
//! BIRD's `f_line`. When the VM lands, this bench should show a
//! commensurate speedup.

use criterion::{criterion_group, criterion_main, Criterion, Throughput};
use lr_core::addr::{Asn, Prefix};
use lr_core::attr::{AttrTag, Attribute, Attributes};
use lr_core::nlri::NlriFamily;
use lr_core::rib::{Preference, Protocol, Route, RouteKey, RouteOrigin};
use lr_policy::filter::{compile, evaluate, FilterContext, RoaStateLit};
use std::hint::black_box;

/// Test context — mirrors the in-crate StubCtx, lives outside the
/// crate so a bug in the in-crate impl cannot also live in the bench
/// oracle.
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
}

fn route_with(prefix: &str, local_pref: u32, med: u32) -> Route {
    let prefix: Prefix = prefix.parse().unwrap();
    let mut attrs = Attributes::new();
    attrs.insert(Attribute {
        tag: AttrTag::raw(TAG_LOCAL_PREF),
        flags: 0x40,
        value: local_pref.to_be_bytes().to_vec(),
    });
    attrs.insert(Attribute {
        tag: AttrTag::raw(TAG_MED),
        flags: 0x80,
        value: med.to_be_bytes().to_vec(),
    });
    Route {
        key: RouteKey::new(prefix, NlriFamily::IPV4_UNICAST),
        origin: RouteOrigin { proto: 1, peer: 0 },
        protocol: Protocol::Bgp,
        preference: Preference::new(20, 100),
        next_hop: None,
        attributes: attrs,
        age_ms: 0,
        path_id: 0,
        tag: None,
    }
}

fn bench_eval(c: &mut Criterion) {
    let simple = compile("bench-simple", "accept;").unwrap();
    let if_lp = compile(
        "bench-if-lp",
        "if bgp.local_pref > 100 then accept; reject;",
    )
    .unwrap();
    let complex = compile(
        "bench-complex",
        "let pfx = 100; \
         if bgp.local_pref > 100 && bgp.med < 50 then { \
             bgp.local_pref = 200; accept; \
         } else { \
             if net ~ [ 10.0.0.0/8{8,24} ] then accept; reject; \
         }",
    )
    .unwrap();

    let mut route = route_with("203.0.113.0/24", 150, 30);

    let mut group = c.benchmark_group("filter_eval");
    group.throughput(Throughput::Elements(1));

    group.bench_function("simple_accept", |b| {
        b.iter(|| {
            let r = evaluate(
                black_box(&simple),
                black_box(&mut route),
                black_box(&BenchCtx),
            );
            let _ = black_box(r);
        });
    });

    group.bench_function("if_local_pref", |b| {
        b.iter(|| {
            let r = evaluate(
                black_box(&if_lp),
                black_box(&mut route),
                black_box(&BenchCtx),
            );
            let _ = black_box(r);
        });
    });

    group.bench_function("complex_chain", |b| {
        b.iter(|| {
            let r = evaluate(
                black_box(&complex),
                black_box(&mut route),
                black_box(&BenchCtx),
            );
            let _ = black_box(r);
        });
    });

    group.finish();
}

criterion_group!(benches, bench_eval);
criterion_main!(benches);
