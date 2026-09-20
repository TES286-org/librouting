//! `cargo bench -p lr-policy --bench filter_eval` — measure the
//! filter DSL evaluator throughput (ROADMAP-v3 D6.2, D3.7, #19 P0, #19 P5).
//!
//! Seven filter families cover the policy complexity spectrum, sized
//! to expose the costs that real-world policies actually pay:
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
//! * `large_prefix_set` — `if net ~ [ 100 prefixes ] then accept;
//!   reject;`. The bench measures the linear `MatchRhs::Set` scan
//!   that the bytecode VM currently inherits from the tree-walker
//!   — the realistic-load lever for the P4 prefix-trie work. Two
//!   positions are measured: `hit_last` (route matches the last
//!   entry, full scan on the accept path) and `miss` (route matches
//!   no entry, full scan on the reject path). The set is sized to
//!   100 entries — the lower bound of a real ISP import policy.
//! * `large_community_set` — `if bgp.communities ~ [ 10 entries ]
//!   then accept; reject;`. The bench measures the community
//!   membership scan (10 entries — the upper bound of a typical
//!   tagging taxonomy) for both `hit_last` and `miss` positions.
//! * `user_functions` — a filter that calls two user functions
//!   (one recursive call, one route-mutating helper). The bench
//!   measures the call-dispatch overhead the VM pays per call —
//!   the P2 slot-resolution lever.
//!
//! Each shape runs under both engines:
//! * tree walk (`evaluate`) — the semantic oracle.
//! * bytecode VM (`bytecode::execute`) — the hot path the daemon
//!   runs per route after `daemon_policy::build_filters` precompiles
//!   every `[[filter]]`.
//!
//! The bench is the basis for the #19 P0 perf baseline: the current
//! three shapes are too small to justify the P4 prefix-trie work, so
//! the larger shapes here are the precondition for any further DSL
//! optimisation. Each new shape must keep VM == interpreter verdict
//! and route state — pinned in `vm_matches_interpreter_on_policy_table`
//! in `crates/lr-policy/src/filter/eval.rs`.

use criterion::{criterion_group, criterion_main, Criterion, Throughput};
use lr_core::addr::{Asn, Prefix};
use lr_core::attr::{AttrTag, Attribute, Attributes};
use lr_core::nlri::NlriFamily;
use lr_core::rib::{Preference, Protocol, Route, RouteKey, RouteOrigin};
use lr_policy::filter::bytecode;
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
        // GitHub #19 P3: read the 4-byte LOCAL_PREF in place via
        // `Attributes::get_u32_be` — no `Vec<u8>` clone. The previous
        // path (`attr(TAG_LOCAL_PREF).and_then(...)`) cloned the
        // `Vec<u8>` for every attribute read, which was a bench
        // artifact, not a production cost (the production
        // `DaemonFilterContext` uses `lr_policy::bgp::local_pref`
        // which already read off `&[u8]`). The bench now matches the
        // production fast path so the `vm_if_local_pref` number
        // reflects what the daemon actually pays.
        route.attributes.get_u32_be(AttrTag::raw(TAG_LOCAL_PREF))
    }
    fn bgp_med(&self, route: &Route) -> Option<u32> {
        route.attributes.get_u32_be(AttrTag::raw(TAG_MED))
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

/// Stamp a COMMUNITIES attribute onto a route (mirrors `with_communities`
/// in the in-crate test helpers — kept local so the bench is independent
/// of the crate's test surface).
fn with_communities(mut r: Route, set: &[(u32, u16)]) -> Route {
    let mut v = Vec::with_capacity(set.len() * 4);
    for (asn, val) in set {
        v.extend_from_slice(&(*asn as u16).to_be_bytes());
        v.extend_from_slice(&val.to_be_bytes());
    }
    r.attributes.insert(Attribute {
        tag: AttrTag::raw(TAG_COMMUNITIES),
        flags: 0xC0,
        value: v,
    });
    r
}

// ----- #19 P0: large-set bench shapes --------------------------------------

/// Number of prefix entries in the `large_prefix_set` filter. 100 is
/// the lower bound of a real ISP import list — BIRD configs in the
/// wild routinely carry 200–2000 entries, but 100 already moves the
/// linear scan past the L1 cache-line boundary that the trivial
/// 1–3-entry sets in `complex_chain` never cross.
const PREFIX_SET_SIZE: usize = 100;

/// Number of community entries in the `large_community_set` filter.
/// 10 is the upper bound of a typical tagging taxonomy (transit,
/// peer, customer, downstream, blackhole, no-export, ...); a
/// larger set is a configuration smell, not a hot path.
const COMMUNITY_SET_SIZE: usize = 10;

/// Build a prefix-set literal body: `[ 10.0.0.1/32, 10.0.0.2/32, ... ]`.
/// Each entry is a host route so the `~` scan cannot short-circuit on
/// a longest-prefix-match optimization the tree-walker performs for
/// overlapping ranges — every entry is a distinct comparison.
fn prefix_set_literal(n: usize) -> String {
    let mut s = String::from("net ~ [ ");
    for i in 0..n {
        if i > 0 {
            s.push_str(", ");
        }
        // 10.{i/256}.{i%256}.1/32 — host routes inside 10/8.
        let a = (i / 256) as u8;
        let b = (i % 256) as u8;
        s.push_str(&format!("10.{a}.{b}.1/32"));
    }
    s.push_str(" ]");
    s
}

/// Build a community-set literal body: `[ 64512:1, 64512:2, ... ]`.
/// Uses a single ASN so the linear scan cannot short-circuit on the
/// ASN-side hash bucket — every entry is a distinct (asn, value) pair.
fn community_set_literal(n: usize) -> String {
    let mut s = String::from("bgp.communities ~ [ ");
    for i in 0..n {
        if i > 0 {
            s.push_str(", ");
        }
        s.push_str(&format!("64512:{}", i + 1));
    }
    s.push_str(" ]");
    s
}

/// A filter that exercises two user functions (one pure, one
/// route-mutating), so the bench measures the call-dispatch overhead
/// the VM pays per call. The function bodies are intentionally small
/// — the call overhead, not the body, is what we want to measure.
fn user_function_filter() -> String {
    "function tag_customer(lp) { bgp.local_pref = lp; return true; } \
     function classify(lp) { if lp >= 200 then return 300; return 100; } \
     let lp = classify(bgp.local_pref); \
     if tag_customer(lp) && bgp.local_pref == 300 then accept; reject;"
        .to_string()
}

/// A filter that exercises the peephole constant-propagation +
/// literal-folding pass (GitHub #19 P5). `let a = 6; let b = 7; if
/// a * b == 42 then accept; reject;` compiles to 12 instructions
/// unoptimised (`Push; StoreVar` × 2, `LoadVar; LoadVar; Bin(Mul);
/// Push; Bin(Eq); JumpIfFalse; Accept; Reject`). The peephole pass
/// propagates `a` and `b` through the `let` bindings, folds
/// `Push(6); Push(7); Bin(Mul)` → `Push(42)`, then folds
/// `Push(42); Push(42); Bin(Eq)` → `Push(Bool(true))`, and the
/// dead-branch pass drops the `Push(Bool(true)); JumpIfFalse`,
/// leaving the `Accept` to fall through. The dead `Push; StoreVar`
/// pairs remain (dead-store elimination is a later phase); the VM
/// executes them but they have no route side effects. The bench
/// measures the cost the peephole pass saves — the unoptimised
/// 12-instruction stream vs the optimised 6-instruction stream.
fn const_fold_filter() -> &'static str {
    "let a = 6; let b = 7; if a * b == 42 then accept; reject;"
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

    // #19 P0 — large-set shapes. Compiled once per bench; the
    // compiled `Filter` / `CompiledFilter` are reused across
    // iterations exactly the way the daemon reuses them.
    let large_prefix_src = format!(
        "if {} then accept; reject;",
        prefix_set_literal(PREFIX_SET_SIZE)
    );
    let large_prefix = compile("bench-large-prefix-set", &large_prefix_src)
        .expect("large prefix set filter must compile");
    let large_comm_src = format!(
        "if {} then accept; reject;",
        community_set_literal(COMMUNITY_SET_SIZE)
    );
    let large_comm = compile("bench-large-community-set", &large_comm_src)
        .expect("large community set filter must compile");
    let user_fn = compile("bench-user-functions", &user_function_filter())
        .expect("user-function filter must compile");
    // #19 P5 — const-fold shape: 12 unoptimised instrs collapse to
    // 6 after the peephole pass. Compiled once; the route is
    // irrelevant (the verdict is constant) — the bench measures
    // the per-eval cost the pass saves.
    let const_fold =
        compile("bench-const-fold", const_fold_filter()).expect("const-fold filter must compile");

    // Route inputs.
    let mut route_plain = route_with("203.0.113.0/24", 150, 30);
    // `large_prefix_set` hit_last: the route matches the last entry
    // in the set — the worst-case accept path (full scan).
    let route_pfx_hit = route_with(
        &format!(
            "10.{}.{}.1/32",
            (PREFIX_SET_SIZE - 1) / 256,
            (PREFIX_SET_SIZE - 1) % 256
        ),
        150,
        30,
    );
    // `large_prefix_set` miss: the route matches no entry — the
    // worst-case reject path (full scan, no early exit).
    let route_pfx_miss = route_with("203.0.113.0/24", 150, 30);
    // `large_community_set` hit_last: the route carries the last
    // community in the set.
    let route_comm_hit = with_communities(
        route_with("203.0.113.0/24", 150, 30),
        &[(64512, COMMUNITY_SET_SIZE as u16)],
    );
    // `large_community_set` miss: the route carries a community
    // that is not in the set.
    let route_comm_miss = with_communities(route_with("203.0.113.0/24", 150, 30), &[(64512, 9999)]);
    // `user_functions`: the route has local_pref=200 so the
    // classifier returns 300, the tag function sets local_pref=300,
    // and the if-condition matches.
    let route_user_fn = route_with("203.0.113.0/24", 200, 30);

    let mut group = c.benchmark_group("filter_eval");
    group.throughput(Throughput::Elements(1));

    // Original three shapes — preserved verbatim so historical
    // regression baselines keep working.
    group.bench_function("simple_accept", |b| {
        b.iter(|| {
            let r = evaluate(
                black_box(&simple),
                black_box(&mut route_plain),
                black_box(&BenchCtx),
            );
            let _ = black_box(r);
        });
    });

    group.bench_function("if_local_pref", |b| {
        b.iter(|| {
            let r = evaluate(
                black_box(&if_lp),
                black_box(&mut route_plain),
                black_box(&BenchCtx),
            );
            let _ = black_box(r);
        });
    });

    group.bench_function("complex_chain", |b| {
        b.iter(|| {
            let r = evaluate(
                black_box(&complex),
                black_box(&mut route_plain),
                black_box(&BenchCtx),
            );
            let _ = black_box(r);
        });
    });

    // #19 P0 — large prefix set (linear scan, 100 entries).
    group.bench_function("large_prefix_set/hit_last", |b| {
        let mut r = route_pfx_hit.clone();
        b.iter(|| {
            let v = evaluate(
                black_box(&large_prefix),
                black_box(&mut r),
                black_box(&BenchCtx),
            );
            let _ = black_box(v);
        });
    });
    group.bench_function("large_prefix_set/miss", |b| {
        let mut r = route_pfx_miss.clone();
        b.iter(|| {
            let v = evaluate(
                black_box(&large_prefix),
                black_box(&mut r),
                black_box(&BenchCtx),
            );
            let _ = black_box(v);
        });
    });

    // #19 P0 — large community set (linear scan, 10 entries).
    group.bench_function("large_community_set/hit_last", |b| {
        let mut r = route_comm_hit.clone();
        b.iter(|| {
            let v = evaluate(
                black_box(&large_comm),
                black_box(&mut r),
                black_box(&BenchCtx),
            );
            let _ = black_box(v);
        });
    });
    group.bench_function("large_community_set/miss", |b| {
        let mut r = route_comm_miss.clone();
        b.iter(|| {
            let v = evaluate(
                black_box(&large_comm),
                black_box(&mut r),
                black_box(&BenchCtx),
            );
            let _ = black_box(v);
        });
    });

    // #19 P0 — user functions (call dispatch overhead).
    group.bench_function("user_functions", |b| {
        let mut r = route_user_fn.clone();
        b.iter(|| {
            let v = evaluate(black_box(&user_fn), black_box(&mut r), black_box(&BenchCtx));
            let _ = black_box(v);
        });
    });

    // #19 P5 — const-fold shape (tree-walk interpreter). The
    // interpreter does not run the peephole pass, so this bench
    // measures the unoptimised 12-instruction cost. The VM bench
    // below (`vm_const_fold`) measures the optimised 6-instruction
    // cost — the delta is the P5 win.
    group.bench_function("const_fold", |b| {
        b.iter(|| {
            let v = evaluate(
                black_box(&const_fold),
                black_box(&mut route_plain),
                black_box(&BenchCtx),
            );
            let _ = black_box(v);
        });
    });

    // D3.7 bytecode VM on the same inputs — quantifies the hot-path
    // win the compiler + stack VM buys over the tree walk.
    let simple_vm = bytecode::compile(&simple);
    let if_lp_vm = bytecode::compile(&if_lp);
    let complex_vm = bytecode::compile(&complex);
    let large_prefix_vm = bytecode::compile(&large_prefix);
    let large_comm_vm = bytecode::compile(&large_comm);
    let user_fn_vm = bytecode::compile(&user_fn);
    let const_fold_vm = bytecode::compile(&const_fold);

    group.bench_function("vm_simple_accept", |b| {
        b.iter(|| {
            let r = bytecode::execute(
                black_box(&simple_vm),
                black_box(&mut route_plain),
                black_box(&BenchCtx),
            );
            let _ = black_box(r);
        });
    });

    group.bench_function("vm_if_local_pref", |b| {
        b.iter(|| {
            let r = bytecode::execute(
                black_box(&if_lp_vm),
                black_box(&mut route_plain),
                black_box(&BenchCtx),
            );
            let _ = black_box(r);
        });
    });

    group.bench_function("vm_complex_chain", |b| {
        b.iter(|| {
            let r = bytecode::execute(
                black_box(&complex_vm),
                black_box(&mut route_plain),
                black_box(&BenchCtx),
            );
            let _ = black_box(r);
        });
    });

    group.bench_function("vm_large_prefix_set/hit_last", |b| {
        let mut r = route_pfx_hit.clone();
        b.iter(|| {
            let v = bytecode::execute(
                black_box(&large_prefix_vm),
                black_box(&mut r),
                black_box(&BenchCtx),
            );
            let _ = black_box(v);
        });
    });
    group.bench_function("vm_large_prefix_set/miss", |b| {
        let mut r = route_pfx_miss.clone();
        b.iter(|| {
            let v = bytecode::execute(
                black_box(&large_prefix_vm),
                black_box(&mut r),
                black_box(&BenchCtx),
            );
            let _ = black_box(v);
        });
    });

    group.bench_function("vm_large_community_set/hit_last", |b| {
        let mut r = route_comm_hit.clone();
        b.iter(|| {
            let v = bytecode::execute(
                black_box(&large_comm_vm),
                black_box(&mut r),
                black_box(&BenchCtx),
            );
            let _ = black_box(v);
        });
    });
    group.bench_function("vm_large_community_set/miss", |b| {
        let mut r = route_comm_miss.clone();
        b.iter(|| {
            let v = bytecode::execute(
                black_box(&large_comm_vm),
                black_box(&mut r),
                black_box(&BenchCtx),
            );
            let _ = black_box(v);
        });
    });

    group.bench_function("vm_user_functions", |b| {
        let mut r = route_user_fn.clone();
        b.iter(|| {
            let v = bytecode::execute(
                black_box(&user_fn_vm),
                black_box(&mut r),
                black_box(&BenchCtx),
            );
            let _ = black_box(v);
        });
    });

    // #19 P5 — const-fold shape (bytecode VM). The peephole pass
    // runs inside `bytecode::compile`, so this bench measures the
    // optimised 6-instruction cost. Compare against `const_fold`
    // (tree walk, 12 instructions unoptimised) for the P5 delta.
    group.bench_function("vm_const_fold", |b| {
        b.iter(|| {
            let v = bytecode::execute(
                black_box(&const_fold_vm),
                black_box(&mut route_plain),
                black_box(&BenchCtx),
            );
            let _ = black_box(v);
        });
    });

    group.finish();
}

criterion_group!(benches, bench_eval);
criterion_main!(benches);
