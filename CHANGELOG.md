# Changelog

All notable changes to librouting are documented here. The format is
based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Pre-1.0 release candidates (`1.0.0-rc.N`) freeze the public API;
breaking changes after a `-rc` lands are recorded under the next
`-rc` heading with a `BREAKING CHANGE:` marker.

The complete narrative for each landed workstream lives in
[`docs/ROADMAP.md`](docs/ROADMAP.md) (the v2 landing log) and
[`docs/ROADMAP-v3.md`](docs/ROADMAP-v3.md) (forward directions).
This file is the consumer-facing summary — protocol features that
ship, breaking changes that affect embedders, dependency bumps.

## [Unreleased]

### Added

- User-function call index resolution for the filter DSL bytecode
  (GitHub #19 P2): `Expr::Call { name, .. }` resolves to a new
  `Instr::CallFn { idx, argc }` instruction at compile time when
  `name` is a user-defined function, eliminating the `BTreeMap`
  lookup per call that `Instr::Call { name, .. }` previously paid.
  Built-in calls (`len`, `count`, `delete`, `filter`, `empty`,
  `first`, `last`) keep `Instr::Call { name, argc }` — the parser's
  `validate_calls` pass already guarantees every call name is a user
  function or a built-in, so the resolution is total.
  - **`CompiledFilter`** — `functions` changed from
    `BTreeMap<String, CompiledFunction>` to `Vec<CompiledFunction>`
    (indexed by `CallFn`), plus a new `function_index:
    BTreeMap<String, usize>` map (name → index). The VM's `CallFn`
    handler does `cf.functions[idx]` — a direct `Vec` index, no
    hash + string comparison. **BREAKING CHANGE** for embedders that
    access `CompiledFilter.functions` directly (the field type
    changed from a map to a vec); use `function_index` for name-based
    lookup. No FFI/binding updates needed — `CompiledFilter` is
    opaque across the FFI boundary.
  - **Bench delta** (criterion, `--baseline p5`, `--quick`):
    `vm_user_functions` improved **−1.25 %** (437 → 430 ns,
    p = 0.05). The `user_functions` bench calls 2 user functions
    per eval; the win is the 2 BTreeMap lookups eliminated. No
    other bench regresses — all existing shapes are within ±1 % of
    P5 (noise). The `import_pipeline` bench is also unchanged.
  - **Equivalence preserved** — the 27×4 policy table, the
    bench-shapes table, and the prefix-trie differential table in
    `crates/lr-policy/src/filter/eval.rs` all pass unchanged. 2 new
    tests pin the P2 contract: `p2_user_function_calls_resolve_to_callfn`
    (verifies `CallFn` is emitted for user functions, `Call` for
    built-ins) and `p2_callfn_matches_interpreter_on_user_functions`
    (verifies `CallFn` produces identical verdicts + route state
    vs the tree-walking interpreter across 4 filter sources × 3
    routes).
  - **What is NOT in P2.** Variable slot resolution (`LoadSlot`/
    `StoreSlot`/`AssignSlot` + frame-based scope management) was
    prototyped and benchmarked but not landed — the frame/scope
    double-write and the `Evaluator` allocation overhead regressed
    `vm_simple_accept` by +10 % and `vm_const_fold` by +29 %. The
    slot-resolution work is deferred until a bench with a hot
    variable-intensive filter (100+ `let`/`LoadVar` per eval) exists
    to amortise the fixed overhead, or until P3 (attribute fast
    paths) makes the frame pay for itself by eliminating the
    `Value` clone on attribute reads. P3 remains the highest-
    leverage remaining lever — it would eliminate the `Value` clone
    the `if_local_pref` bench (81.5 ns) pays on every attribute
    read.
- Peephole optimisation pass for the filter DSL bytecode (GitHub
  #19 P5): a new `crates/lr-policy/src/filter/peephole.rs` module
  runs three passes inside `bytecode::compile` after the
  AST-to-bytecode compiler emits the instruction stream.
  - **Constant propagation + literal folding** — a forward pass
    tracks `let`-bound constants in a `HashMap<String, Value>` and
    rewrites `LoadVar(name)` to `Push(v)` when `name` is a known
    constant. `Push(L1); Push(L2); Bin(Op)` triples fold to a
    single `Push(folded)` when both are literals and the fold
    cannot error (the pass refuses to fold division by zero,
    arithmetic overflow, and bad shift amounts — those errors must
    surface at runtime exactly as the unoptimised code surfaces
    them). `Push(Bool(b)); Not` and `Push(Int(n)); Neg` fold the
    same way. The constant map is invalidated at every control-flow
    join (`Jump`, `JumpIfFalse`, `JumpIfTrue`, `PushScope`,
    `PopScope`) and every side-effecting instruction (`Call`,
    `Method`, `EvalTree`, `AssignField`, `AppendField`, `Defined`,
    `AssignVar`) so the analysis is a single forward walk, not a
    full data-flow fixpoint.
  - **Dead-branch elimination** — after folding produces
    `Push(Bool(c)); JumpIfFalse(X)` or `Push(Bool(c));
    JumpIfTrue(X)`, the branch direction is known at compile time.
    `Push(Bool(true)); JumpIfFalse(X)` always falls through (drop
    both); `Push(Bool(false)); JumpIfFalse(X)` always jumps
    (replace with `Jump(X)`). The pass is only applied when the
    `JumpIfFalse`/`JumpIfTrue` is NOT a jump target from elsewhere
    — the `&&`/`||` short-circuit compilation emits `Jump(Le)`
    that targets the `JumpIfFalse` directly, so eliminating the
    branch in that case would change the stack state seen by the
    jump.
  - **Jump threading** — `Jump(X)` where `code[X]` is `Jump(Y)`
    is rewritten to `Jump(Y)`; same for `JumpIfFalse(X)` and
    `JumpIfTrue(X)` when `code[X]` is an unconditional `Jump`.
    Conditional-jump-to-conditional-jump is NOT threaded (the
    target conditional pops a stack value). Threads through chains
    of unconditional jumps until a fixed point per instruction.
  - **Jump-target safety** — both the fold and dead-branch passes
    compute the set of jump targets upfront and skip any
    optimisation that would consume an instruction that is a jump
    target. This is the key correctness invariant: collapsing a
    jump target would change the stack state seen by the jump
    source.
  - The passes iterate to a fixed point (constant propagation can
    expose new fold patterns), then run dead-branch elimination
    once, then jump threading once. The order is intentional:
    folding exposes dead branches, dead-branch elimination exposes
    new jump chains (a `Jump(X)` replacing a `JumpIfFalse(X)` may
    now target another `Jump`).
  - **Bench delta** (criterion, `--quick`): the new `const_fold`
    bench shape (`let a = 6; let b = 7; if a * b == 42 then accept;
    reject;`) measures the win — the tree-walk interpreter runs
    the unoptimised 12-instruction stream at 160 ns, the bytecode
    VM runs the peephole-optimised 6-instruction stream at
    119.5 ns, a **-25 % (1.34×)** speedup. The existing six bench
    shapes are all within ±2 % of P4 (noise) — the pass is a
    no-op on filters without foldable constants.
  - **Equivalence preserved** — the 27×4 policy table, the
    bench-shapes table, and the prefix-trie differential table in
    `crates/lr-policy/src/filter/eval.rs` all pass unchanged. 14
    new unit tests in `peephole.rs` pin the pass's golden output
    (folds, no-fold error cases, jump threading, self-loop safety,
    jump-target invalidation, no-op on dynamic filters).
  - **API additions** — `Instr`, `MatchItem`, `MatchRhs`,
    `DefinedTarget`, `Expr` derive `PartialEq, Eq` (the fold tests
    compare instruction streams for equality; the derives are
    additive and do not affect existing code). `Value` gains `Eq`
    (it was already `PartialEq`; all variants are integer/bool
    based). No public function signatures change; no FFI/binding
    updates needed.
- Prefix-trie set matching for the filter DSL (GitHub #19 P4):
  `PrefixSetTrie` in `crates/lr-policy/src/filter/bytecode.rs`
  replaces the O(n) linear scan over `MatchRhs::Set` prefix items
  with an O(prefix_len) covering walk. The trie is a
  path-compressed Patricia trie that borrows its structure from
  `lr-bgp::roa_trie` (ROADMAP-v3 D8.4) — the same flat-arena node
  layout, the same high-aligned `u128` key encoding, the same
  two-family root layout, the same covering-walk divergence
  rule — but stores `(ge, le)` range constraints instead of ROA
  entry indices. A new `MatchRhs::PrefixSet { trie, others }`
  variant is emitted by the compiler when the set contains at
  least one `MatchItem::PrefixSet`; non-prefix items (values,
  dynamic exprs) stay in `others` for a linear scan. Pure value
  sets keep `MatchRhs::Set` — no regression for sets the trie
  cannot help. Single-prefix patterns (`net ~ 10.0.0.0/8`) now
  also go through the trie (a one-node trie is cheaper than the
  one-element `Vec`).
  - Bench delta (criterion, `--baseline p0`): `vm_large_prefix_set`
    goes from 291 ns to 87.6 ns on `hit_last` (−70 %, 3.3× faster)
    and from 191 ns to 58.3 ns on `miss` (−69 %, 3.3× faster) —
    the biggest actionable win the P0 baseline surfaced. The
    import-pipeline bench shows the win compounding at scale:
    `realistic/10000` −8.8 %, `trivial/10000` −10.4 %,
    `realistic/1000` −5.3 %, `trivial/1000` −5.9 %. No shape
    regresses; the other VM shapes (`simple_accept`,
    `if_local_pref`, `complex_chain`, `large_community_set`,
    `user_functions`) are all within ±1 % of P0 (noise).
  - Engine equivalence: a new test
    `prefix_trie_matches_linear_scan_across_set_shapes` in
    `crates/lr-policy/src/filter/eval.rs` pins the trie ==
    linear-scan contract across five set shapes (plain /32s,
    `ge`/`le` ranges, IPv6, mixed prefix + value, overlapping
    ranges) and a hit/miss/longer/shorter/wrong-family query
    matrix. The existing 27×4 equivalence table and the
    bench-shapes table run verbatim against both `MatchRhs::Set`
    and `MatchRhs::PrefixSet`.
  - P1 (compact instruction encoding, `Instr { op, a: u32, b: u32 }`
    = 12 bytes) was attempted and reverted. The A/B bench showed
    a 2–10 % regression across every VM shape: the side-table
    indirection (one `Vec` lookup per dispatch) exceeded the
    cache-density win on the bench sizes (the existing benches
    exercise filters with ≤ 10 instructions, where the whole
    instruction stream fits in 1–2 cache lines either way). The
    process guardrail ("every optimisation lands with a bench
    delta attached, not an argument") was honoured — the P1
    regression was measured, not argued, and the change was not
    landed. The instruction-encoding work is deferred until a
    bench with a 1000+ instruction filter exists, or until P2/P5
    work makes the compact encoding pay for itself.
- DSL performance baseline benches (GitHub #19 P0): two new
  criterion benches in `crates/lr-policy/benches/` give the filter
  DSL and the daemon import pipeline a measurable perf baseline
  before the P1–P5 optimisation work begins.
  - `filter_eval.rs` grows from three shapes to six: the original
    `simple_accept` / `if_local_pref` / `complex_chain` are
    preserved verbatim (historical regression baselines keep
    working), and three new shapes exercise the realistic-load
    surface the issue comment calls out — `large_prefix_set`
    (100-entry `net ~ [...]`, measured on `hit_last` and `miss`
    positions), `large_community_set` (10-entry
    `bgp.communities ~ [...]`, same two positions) and
    `user_functions` (a two-call chain — classify + tag — that
    exercises the VM's call-dispatch overhead). Every shape runs
    under both engines: the tree-walking interpreter (`evaluate`)
    stays the semantic oracle; the bytecode VM
    (`bytecode::execute`) is the hot path the daemon runs per
    route after `daemon_policy::build_filters` precompiles every
    `[[filter]]` at startup.
  - `import_pipeline.rs` is the new daemon-level bench. For each
    route it runs the import path the daemon actually runs —
    bytecode eval → Adj-RIB-In install → Loc-RIB install — at
    three scales (100 / 1 000 / 10 000 routes) and under two
    filter shapes (`trivial` and `realistic`). The bench lives in
    `lr-policy` (DSL eval is the dominant component) and pulls
    `lr-rib` as a dev-dependency (no cycle — `lr-rib` does not
    depend on `lr-policy`). The bench is shaped to outlive the
    #18 config-format migration: the filter body is a string
    literal, not a config fragment, so the bench can be reused
    unchanged after the TOML→DSL migration lands.
  - Baseline numbers (criterion, `--quick`): the VM is at parity
    with the interpreter on the original three shapes — `if_local_pref`
    is where the VM still loses (+19 %), confirming the P1
    instruction-encoding hypothesis. The new shapes expose where
    the VM wins and loses today: `large_prefix_set` VM is 22–35 %
    *slower* than the tree walk (the linear `MatchRhs::Set` scan
    that P4 prefix-trie targets), `large_community_set` VM is
    43–45 % faster, `user_functions` VM is 64 % faster (the P2
    slot-resolution lever — call dispatch is the tree walker's
    worst case). The import-pipeline bench shows the per-route
    cost the daemon pays: ~570 ns / route at 100 routes,
    ~1.18 µs / route at 10 000 routes (BTreeMap log factor). These
    numbers are the P1–P5 deltas will be measured against.
  - Engine equivalence is load-bearing: a new test
    `vm_matches_interpreter_on_bench_shapes` in
    `crates/lr-policy/src/filter/eval.rs` pins the VM ==
    interpreter contract on the bench-sized shapes (100-entry
    prefix set, 10-entry community set, two-call user-function
    chain) across a six-route matrix. The 27×4 equivalence
    table is preserved unchanged; the new test is additive.
- RFC 8212 interop tests (ROADMAP-v3 D10.6): two end-to-end
  interop scripts verify lr-daemon's default RFC 8212 eBGP policy
  against real BIRD 2 and FRR bgpd. `tests/interop/rfc8212_bird.sh`
  and `tests/interop/rfc8212_frr.sh` each run two phases: Phase 1
  (default mode, no explicit policy) asserts the session reaches
  Established but BIRD/FRR does NOT learn lr-daemon's route and
  lr-daemon does NOT install BIRD/FRR's route — the RFC 8212
  import-deny and export-deny are both exercised; Phase 2 (explicit
  permit-all route-maps) asserts the route flows both directions,
  confirming the RFC-intended escape hatch. The startup warnings
  (`no export route-map; announcing nothing (RFC 8212)` and `no
  import route-map; discarding received routes (RFC 8212)`) are
  pinned as Phase 1 assertions. Both scripts are wired into the CI
  interop job. The scripts gracefully SKIP when `bird`/`birdc` or
  `bgpd` are not on `$PATH` (same pattern as every other interop
  script). The in-process `daemon_rfc8212.rs` tests remain — the
  interop scripts are additive, not replacement.
- FFI design document (ROADMAP-v3 D9.6): `docs/ffi_design.md` is
  the canonical reference for the librouting C ABI design — the
  panic-barrier contract, the `lr_bytes_t` ownership model, the
  cbindgen pipeline, the opaque-handle pattern, the non-reentrant
  lock hazard, what is NOT exposed and why (OSPF/Babel engines are
  daemon-driven, LDP has no router session model, BMP/MRT/BFD are
  codec-only), the error model, and the three-level testing
  strategy. Cross-references every section to the source file that
  implements it.
- Container image (ROADMAP-v3 D12.3): a multi-stage `Dockerfile` at
  the repo root builds the whole workspace in release mode with all
  features and ships the three CLI binaries (`lr`, `lr-daemon`,
  `lrctl`), `liblr_ffi.so` and the C / C++ headers into a
  `debian:bookworm-slim` runtime image. The builder stage pins
  `rust:1.88-slim-bookworm` (the workspace MSRV) and uses BuildKit
  mount caches on the cargo registry + target dir so a no-op rebuild
  is seconds. The runtime stage creates a non-root `lr` user,
  `EXPOSE`s `179/tcp` (BGP) + `9119/tcp` (metrics), declares
  `VOLUME /etc/lr-daemon` + `VOLUME /run/lr-daemon` (for config
  mount + `lrctl` sidecar pattern), and uses
  `ENTRYPOINT ["lr-daemon"]` with `CMD ["--help"]`. The image does
  NOT ship a default config and does NOT push to a registry from CI.
  The `.dockerignore` keeps the build context lean. The
  `docker/README.md` deployment guide covers quick start, production
  config-file mount, sidecar `lrctl`, image layout, exposed ports,
  volumes, the ~100 MB size target, and what the image does NOT
  include. The `.github/workflows/docker.yml` CI workflow builds the
  image on every push / PR / nightly, runs the three CLI binaries,
  verifies `liblr_ffi.so` is loadable via `ldconfig -p`, and reports
  the image size. Helm chart deferred — a Helm chart conventionally
  lives in its own repository so it can version independently of the
  image; the Dockerfile here is the foundation a chart would
  reference.
- Prometheus `/metrics` HTTP endpoint (ROADMAP-v3 D12.2): the daemon
  gains an opt-in HTTP endpoint that serves the Prometheus text
  exposition format on `GET /metrics` (`crates/lr-cli/src/metrics.rs`).
  Hand-rolled HTTP/1.0 responder — no `hyper` / `tokio` dependency,
  matching the project's stance on `api.rs`. Configuration:
  `--metrics-addr ADDR` CLI flag / `[bgp] metrics_addr = "…"` TOML
  key (default off, like `api_socket`); a bind failure is fatal
  (same stance as `spawn_api`). The exposition covers `lr_info`
  (gauge=1 with `version` / `local_as` / `router_id` labels, for join
  queries), `lr_uptime_seconds`, `lr_sessions_total{kind,state}`,
  `lr_established_sessions{kind}` (with explicit-zero for kinds that
  have sessions but none established), `lr_adj_rib_in_entries{kind}`,
  `lr_rib_entries`, and `lr_roa_entries` (omitted entirely when no
  ROA store is configured). `GET /` returns a one-line pointer to
  `/metrics`, `GET /nonexistent` returns `404`, non-GET methods
  return `404`. The `Runtime` struct gained an optional
  `roa_len: Option<Arc<dyn Fn() -> usize + Send + Sync>>` field so
  the BGP daemon can expose the live ROA count without holding a
  lock; OSPF/Babel/LDP/BMP/multi pass `None`. Wired into every
  daemon entry point via `spawn_metrics()`. 7 e2e tests in
  `crates/lr-cli/tests/daemon_metrics.rs`. Documented in
  `docs/RUNBOOK.md`, `docs/lr-cli.md` and `templates/daemon.toml`.
  Filter-eval latency histograms and UPDATE tx/rx counters remain
  open — they require per-session counters the daemon does not track
  today.
- `lrctl` operational CLI (ROADMAP-v3 D12.1): a third `lr-cli` binary
  alongside `lr` and `lr-daemon`. Connects to a running `lr-daemon`
  over its Unix API socket and proxies the line-oriented command
  protocol: `lrctl status`, `lrctl sessions [list]`,
  `lrctl routes show [prefix]` (client-side prefix filter),
  `lrctl routes dump <path>` (MRT export via the daemon's `mrt PATH`
  command), `lrctl reload`, `lrctl shutdown`. Adds a client-side
  `lrctl filter compile <body>` that reuses
  `lr-policy::filter::compile` directly so operators can validate a
  filter body before deploying — the same parser path the daemon
  runs at startup. Default socket path `/run/lr-daemon.api` (matches
  `templates/daemon.toml`); `--socket PATH` overrides on any
  subcommand. Non-Unix targets refuse with a clear error. The
  release workflow stages `lrctl` in every platform archive. 10 e2e
  tests in `crates/lr-cli/tests/lrctl.rs`. Documented in
  `docs/lr-cli.md` (new `lrctl` section) and `docs/RUNBOOK.md`.
  `roa list` is deferred — exposing it requires threading the
  `RoaStore` through the daemon's `Runtime` struct (a follow-up
  commit).
- Filter DSL formal grammar reference (ROADMAP-v3 D9.2): the new
  `docs/filter_dsl_grammar.md` is the canonical EBNF reference for
  the BIRD-like filter DSL, derived directly from the lexer + Pratt
  parser source in `crates/lr-policy/src/filter/`. Covers the
  lexical structure, the full statement + expression grammar, the
  operator precedence table (mirroring `BinaryOp::precedence`), the
  route field reference, the `MAX_EXPR_DEPTH` / `MAX_CALL_DEPTH`
  limits, a worked-examples section and a BIRD-comparison table.
  The companion `crates/lr-policy/tests/grammar_corpus.rs` pins
  every example through `lr_policy::filter::compile` — 30 tests
  across positive, negative and boundary cases. The grammar
  captured two real divergences from the older in-tree BIRD
  example doc: the function return-type annotation uses `=>`
  (the same `TokenKind::Arrow` as `case` arms), not BIRD's `->`;
  and AS-path `~` is currently flat set-membership, not BIRD regex
  (the `_` wildcard token is parsed but does not yet carry
  meaning inside `~` patterns). Both are now documented as
  current behaviour with a follow-up pointer.
- BIRD `!~` (not-match) operator in the filter DSL (ROADMAP-v3 D14.5):
  the lr DSL AST has carried `BinaryOp::NotMatch` since the parser was
  first written — the evaluator and bytecode VM already lowered it to
  `Match { negated: true }` — but the lexer never produced a `!~`
  token, so no source program could exercise the path. The fix adds
  `TokenKind::BangTilde` to the lexer's multi-char set (alongside
  `!=` / `==` / …) and maps it to `BinaryOp::NotMatch` in the parser.
  The BIRD filter compat translator (D14.1) now passes `!~` through
  verbatim instead of fail-closing on it; BIRD and lr spell the
  operator identically.
- BIRD `case` statement translation (ROADMAP-v3 D14.6): a new
  structural pre-pass `rewrite_cases` in the BIRD filter compat
  translator walks the token stream and rewrites every BIRD
  `case … { … }` block into lr DSL syntax. The mapping was verified
  against BIRD's `filter/config.Y` §`switch_body` and `conf/cf-lex.l`
  (the `else:` ELSECOL token): arm separator `:` (at depth 1) → `=>`;
  `else :` → `default =>`; non-block arm bodies are wrapped in
  `{ … }` (lr DSL case arm bodies parse a single statement, which
  may be a `Block`); block arm bodies are left as-is; nested cases
  are handled recursively. Range arms (`a .. b:`) remain
  unfaithful — lr case arms match exact values only. `case` is
  removed from the translator's `UNMAPPABLE_WORDS` list.
- FFI expansion, third wave — D5 direction complete (ROADMAP-v3
  D5.1–D5.3): OSPFv2/OSPFv3/Babel session management
  (`lr_router_add_ospf_session` / `lr_router_add_ospfv3_session` /
  `lr_router_add_ospf_session_ext` with stub/NSSA area kinds, network
  type and the RFC 2328 §10.4 segment identities;
  `lr_router_add_babel_session` per RFC 8966 §4.2.1 — LDP sessions
  stay daemon-side by design); policy objects (`lr_route_new_v4/_v6`
  boxing a real `Route` with typed attribute setters/getters,
  `lr_prefix_list_*` with FRR ge/le semantics, `lr_route_map_*` +
  `lr_resolver_*` running the FRR route-map flow with fail-closed
  NULL-resolver semantics); and the Filter DSL over the C ABI
  (`lr_filter_compile` to the D3.7 stack VM, `lr_filter_evaluate`,
  `lr_filter_context_t` — the C callback variant of `FilterContext`
  where every NULL field keeps the built-in route-backed behaviour).
  C/C++/Go/Python bindings synced with tests; the C++ wrapper gains
  RAII `Route` / `PrefixListHandle` / `RouteMapHandle` /
  `ResolverHandle` / `Filter` types.
- FFI expansion, second wave (ROADMAP-v3 D5.4–D5.7): BGP message
  encoders (`lr_bgp_encode_open` with the RFC 6793 four-octet-AS
  capability, `lr_bgp_encode_notification`,
  `lr_bgp_encode_update_withdraw_v4` / `..._announce_v4`), event
  polling (`lr_router_poll_events` serializing `lr_event_t` batches
  with lossless requeue of the overflow), and the local route
  lifecycle (`lr_router_originate_v6`, `lr_router_withdraw_v4` /
  `_v6` — FRR `no network` semantics, idempotent on absent
  statements). `RouterInstance::unoriginate` now reports whether a
  route was actually removed (bool, non-breaking). The C/C++/Go/
  Python surfaces are all synced with tests.
- Cross-protocol interop labs (ROADMAP-v3 D4.5) closing the D4
  direction: `tests/interop/redistribute_bird.sh` (BIRD 2 speaks both
  ends of a BGP↔OSPF pipe over a veth pair — flushed out the
  Router-LSA V/E/B body-bits bug and the protocol-direct export
  missing ORIGIN/AS_PATH), `tests/interop/aggregate_bird.sh` (BIRD
  originates covering specifics, lr aggregates, BIRD verifies
  ATOMIC_AGGREGATE + AGGREGATOR + AS_PATH on the wire and the
  retraction after a SIGHUP route swap) and
  `tests/interop/damping_frr.sh` (FRR bgpd drives withdraw flaps
  into the `[damping]` table — three flaps suppress, the decay ticker
  reactivates below reuse, a post-reuse flap re-installs). All three
  wired into the CI interop job.
- FFI surface for the cross-protocol daemon features (ROADMAP-v3
  D4.4): `lr_router_add_redistribution_pipe` (BIRD `pipe` / FRR
  `redistribute` with metric policy, tag and allow-list),
  `lr_router_add_aggregate` / `lr_router_remove_aggregate` (RFC 4271
  section 9.2.2.2), and `lr_router_set_damping` + `lr_damping_decay` /
  `lr_damping_destroy` (RFC 2439 with an embedder-driven decay
  handle). C constants (`LR_PROTO_*`, `LR_METRIC_*`) ship in the
  generated header; the C++ RAII wrapper, Go and Python bindings all
  expose the new surface with tests, and the C/C++ harnesses exercise
  it in CI.
- Filter DSL bytecode VM (ROADMAP-v3 D3.7): the filter AST compiles
  to a flat instruction stream (jumps for short-circuits and
  branches, lifted constant patterns for `~`, presence instructions
  for `defined()`) executed by a stack VM sharing the interpreter's
  scope/function state, so the two engines are equivalent by
  construction (a 27-source equivalence table pins verdict + route
  state). The daemon's import/export filter hooks compile once at
  start-up and execute bytecode per route. Measured: 23.8 ns vs
  27.9 ns on bare accept, ~2% on complex chains.
- Filter DSL user-defined functions (ROADMAP-v3 D3.1): BIRD-style
  `function name(a, b) -> ret { ... }` declarations ahead of the
  filter body. Bodies run against the caller's route (mutations
  stick), arguments bind positionally in a fresh scope, `return` /
  bare-return / fall-off-the-end yield the call value (default
  `false`), and `accept` / `reject` inside a function terminate the
  whole filter. Runaway recursion is bounded (`MAX_CALL_DEPTH = 64`)
  and compile-time validation rejects undeclared calls, duplicates
  and built-in shadowing — typos fail at startup, not at route time.
- Filter DSL large communities (ROADMAP-v3 D3.2, RFC 8097):
  `LargeCommunity` struct + 12-byte codec in `lr-bgp` (byte-exact
  wire test), typed `PathAttributes` accessors, `lr_policy::bgp`
  helpers and the `bgp.large_communities` filter surface — `+=`, `=`,
  `.add/.delete/.filter`, `~` membership; 4-octet ASNs work natively
  (`4200000000:7:9`).
- Filter DSL extended communities (ROADMAP-v3 D3.3, RFC 4360): BIRD
  tuple literals `(rt, <asn|ip>, <local>)` / `(ro, ...)` / `(soo,
  ...)` mapped to the canonical transitive types (0x42 / 0x41),
  exposed as `bgp.ext_communities` with the same read/write/method
  surface. Note: the pre-existing `ExtendedCommunity` struct cannot
  represent the 2-octet-AS administrator form (type 0x00); the DSL
  steers literals to the canonical 4-octet form and wire bytes from
  peers still pass through opaquely.
- Filter DSL set operations (ROADMAP-v3 D3.4): BIRD `delete` /
  `filter` / `empty` / `count`, with wildcard community patterns
  (`asn:val`, `asn:*`, `*:val`, `*:*`) in set literals. Works
  value-level (`delete(cs, [64512:*])` on a local) and directly on
  route attributes (`bgp.communities.delete([...])`,
  `bgp.as_path.delete([...])`, `bgp.communities.filter([...])`).
  Assignment accepts the canonical BIRD idiom
  `bgp.communities = delete(bgp.communities, [64512:*]);` and
  `bgp.as_path = <sequence>`; `~` matches wildcard patterns. Two new
  `FilterContext` mutators (`set_bgp_communities`, `set_bgp_as_path`)
  — empty results drop the attribute.
- Filter DSL `defined()` / `exists()` (ROADMAP-v3 D3.5): presence
  checks for route attributes and scope variables, parsed structurally
  (`Expr::Defined`) so the argument is never evaluated and an absent
  attribute stays distinguishable from "set to the default". Optional
  attributes (`bgp.local_pref`, `bgp.med`, `bgp.next_hop`,
  `bgp.origin`) report presence from the typed accessors; list-valued
  attributes (`bgp.as_path`, `bgp.communities`) report presence as
  non-empty; `net` / `proto` / `source` / `roa.state` and literals are
  always defined. Any other expression probes against a route copy, so
  `defined()` can never write through. Seven regression tests cover
  the absent-vs-zero-MED distinction, the `exists` alias, list fields,
  variables and the one-argument arity error.
- ROADMAP-v3 D4.1 / D4.2 — daemon surfaces for the cross-protocol
  engines (`[[redistribute]]` and `[[aggregate]]` TOML tables):
  - `[[redistribute]]` (BIRD `pipe` / FRR `redistribute`): routes from
    `source` (`bgp` | `ospf` | `ospf3` | `babel`) are re-originated
    into `target` (`bgp` | `ospf` | `ospf3`) with an optional fixed
    `metric`, OSPF route `tag`, and prefix `allow` list. Fail-closed
    validation: unknown keys, unknown protocol names, unsupported
    targets, sources without a daemon injection surface, pipes into a
    non-running engine (protocol set + `[ospf] version` cross-check)
    and duplicate `(source, target)` pairs are all start-up errors.
    Installed once per process (supervisor or standalone BGP engine);
    the banner lists every pipe and the router logs each
    re-origination as `daemon: redistribute: <prefix> -> <TARGET>`.
  - `[[aggregate]]` (RFC 4271 §9.2.2.2): registers a BGP aggregate
    (zeroed AS_PATH + ATOMIC_AGGREGATE + AGGREGATOR) that is
    originated while a more-specific exists and withdrawn when the
    last one disappears. `summary_only` is refused on purpose — the
    router has no specific-suppression knob yet.
  - Router fix surfaced by the aggregate e2e: `recompute_aggregates`
    now flushes `export_selection` at origination, so an aggregate
    born after the session-up full sync reaches Adj-RIB-Out (with a
    `lr-tests` regression test).
  - E2E: `crates/lr-cli/tests/daemon_redistribute.rs` — the pipe's
    allow-list gates exactly the covered prefix (asserted through the
    router's own log events) and the aggregate traverses an A–B–C
    daemon chain end to end.
- Filter parser recursion limit (nightly fuzz fix): the recursive-
  descent parser now bails out with
  `ParseErrorKind::RecursionLimitExceeded` at `MAX_EXPR_DEPTH = 128`
  nesting levels instead of overflowing the stack on inputs like
  thousands of nested `[` set opens or `!` chains — the nightly
  `filter_parser` cargo-fuzz target found the crash (AddressSanitizer
  stack-overflow, 3 911-byte input). The limit also bounds the AST
  height, keeping recursive `Drop` glue and the tree-walking
  evaluator safe. The crashing input ships as a fuzz seed and a
  corpus-driven regression test
  (`crates/lr-policy/tests/filter_corpus.rs`) runs the whole committed
  seed corpus through `filter::compile`.


- BIRD 2 filter translation into the lr filter DSL (ROADMAP-v3 D14.1):
  `filter`/`function`/`define`/`roa table` blocks become `[[filter]]`
  bodies; `import|export filter NAME` and `import where EXPR` wire the
  filters to peers. Fail-closed per filter — constructs without a
  faithful lr mapping (BIRD-only route attributes, `case`, `print`,
  `!~`, `proto` comparisons, multi-table `roa_check`, …) leave the
  filter unemitted and reported. Operator mapping verified against
  BIRD's grammar and lexer: no `and`/`or`/`not` keywords exist in
  BIRD 2; BIRD equality `=` becomes `==` and assignment `:=` becomes
  `=`. Every emitted body must compile and reference only introduced
  variables. Inline channel bodies (`ipv4 { import all; };`) now
  split into statements instead of one UNMAPPED line, and `roa table`
  entries carry over as `[[roa]]` rows.
- BIRD `protocol babel` translation (ROADMAP-v3 D14.2): interface
  blocks map the RFC 8966 §A.2 parameters onto `[[babel.interface]]`
  tables (type/kind, rxcost, rtt cost/min/max with BIRD's time
  grammar, check link, extended next hop, port); protocol-level
  `next hop` statements backfill interfaces that lack their own.

### Changed

- **BREAKING** `lr-policy::hooks`: `ImportHook`, `SelectionHook` and
  `ExportHook` now require `Send + Sync` (previously `Send` only).
  Hooks are invoked on whichever thread owns the router guard, so
  shared-reference access is the real contract; the `Sync` bound lets
  read guards share `DefaultRouter` across threads (ROADMAP-v3 D8.1).
  Embedders with non-`Sync` hook state must wrap it in `Arc`/`Mutex` —
  a compile-time change, not a behavioural one.
- **BREAKING** `lr-cli` daemon surface: the shared router handle is
  `Arc<RwLock<DefaultRouter>>` (was `Arc<Mutex<...>>`). Read-only
  paths (API `routes`/`status`/`sessions` dumps, session summaries,
  Babel RTT probes, OSPF/LSDB status views) take the read lock and run
  concurrently with each other; mutating paths (session setup,
  `feed_input`, event polling, reselection, redistribution, Babel GC,
  config reload) take the write lock. All 81 call sites are classified
  and the classification is enforced by the borrow checker
  (`DefaultRouter` has no interior mutability) (ROADMAP-v3 D8.1).
- `lr-bgp::roa`: `RoaTable::validate` now walks a path-compressed
  (Patricia) prefix trie — `O(prefix_len)` per query instead of the
  `O(n)` entry scan. Entries keep their canonical sorted `Vec`
  (dumps, equality, snapshot determinism unchanged); the trie is a
  pure lookup index built once at construction.
  `RoaTableBuilder::build` now sorts and deduplicates like
  `from_entries`, so every construction path is byte-deterministic
  (ROADMAP-v3 D8.4). Criterion: ~5 ns uncovered / 75-182 ns covered
  across 1k/10k/100k tables.
- Performance documented in the new "Performance characteristics"
  section of `docs/ARCHITECTURE.md` — ROA lookup costs, the filter
  bytecode hot path, the daemon thread model, the RwLock read/write
  split and the scalability ceiling (ROADMAP-v3 D8.6).

### Fixed

- Route flap damping decay used the UNIX epoch as its time base while
  the import hook derives `now` from the router's monotonic
  milliseconds-since-daemon-start — every decay tick saw an
  astronomically large elapsed time, zeroed the figure-of-merit and
  instantly "reactivated" every suppressed prefix, so damping could
  never hold. The `lr-damping-decay` thread now ticks on the same
  monotonic base the router stamps `route.age_ms` with (caught live by
  the new `tests/interop/damping_frr.sh` FRR lab).
- `cargo bench --workspace -- <criterion args>` no longer dies on the
  first libtest target ("Unrecognized option: 'sample-size'"): every
  `[lib]` target and the `lr-cli` binaries now carry `bench = false`,
  so the bench-smoke nightly job exercises exactly the four criterion
  harnesses.
- ROADMAP-v3 D1 — Babel multi-session concurrency + per-interface
  parameters (RFC 8966 §3.3/§3.7.5/§A.2):
  - `[[babel.interface]]` glob patterns now resolve to one Babel
    session per matching system interface (first matching pattern wins,
    BIRD semantics), each with its own router-id, socket pair and
    per-interface `hello_interval_ms` / `update_interval_ms` /
    `rxcost` / `rtt_cost` / `rtt_min_us` / `rtt_max_us` /
    `next_hop_ipv4` / `next_hop_ipv6` / `extended_next_hop` / `port` /
    `group` / `check_link`. Dual-stack interfaces announce on both
    the IPv6 and IPv4 transports (§4.1).
  - Route re-advertisement between interfaces (§3.7.5): the origin's
    (router-id, seqno) is preserved with the interface cost added to
    the metric, split-horizoned per session; a claim that vanishes is
    retracted with an infinity-metric Update under the origin's
    Router-Id (§3.5.5). `check link` (BIRD `check link yes`, default
    on) withdraws a dead segment's routes within one second and
    resumes when it returns.
  - RFC 8966 §A.2.4 BABEL-RTT delay metric: Timestamp sub-TLV on
    Hellos, Timestamp Echo sub-TLV on IHUs, EWMA-smoothed RTT
    (babeld's decay 42/256, 1 s echo freshness, 600 s sanity, 180 s
    validity) and the linear `rtt_penalty` added to every advertised
    metric when `rtt_cost > 0`.
  - RFC 8966 §3.2.5 route expiry: every Update refreshes its claim's
    hold deadline (babeld's `hold_time = MAX(4·I/100 + I/50, 15)` s);
    `RouterInstance::babel_gc` (new) sweeps expiry once a second and
    retracts everything a dead neighbour taught us.
  - `RouterInstance::babel_rtt_echo` (new) exposes the IHU echo pair;
    `feed_input_at` now takes the transport's wall-clock milliseconds
    beside the 32-bit BABEL-RTT microsecond clock (the method ships
    for the first time in this release, so the signature is final
    rather than broken).
  - `[[babel.key]]` gained the `interface` pattern: keys apply only to
    matching interfaces (unscoped keys apply everywhere); each
    interface authenticates with its own RFC 8967 state.
  - E2E: `tests/interop/babel_multihop.sh` — three speakers in three
    namespaces chained over veth pairs (transit both ways through the
    multi-session middle box, `check link` withdrawal end-to-end,
    reconvergence), wired into CI.
- ROADMAP-v3 D2.3 — `lr_bgp::roa_store::RoaStore`, a thread-safe
  two-layer ROA database with atomic snapshot swaps:
  - **Static + RTR provenance layers.** Static entries
    (`[[roa]]` config, FFI) survive cache expiry and are replaced only
    by `replace_static` (config reload); RTR entries follow the RFC
    8210 lifecycle (`apply_rtr_deltas` per sync, `clear_rtr` on §6
    data expiry or cache change).
  - **Atomic whole-table swaps.** Every mutation rebuilds the merged
    entry set and swaps one `Arc<RoaTable>` under a `RwLock`; readers
    clone the Arc under a read lock and validate lock-free — a reader
    never sees a half-applied sync (arc-swap semantics without the new
    dependency). Sort + dedup keeps the table deterministic; §5.6
    duplicates coalesce and §12 code-6 withdrawals no-op naturally.
  - `RoaTable::from_entries` and the `RoaEntry` `Ord` derive are new
    (non-breaking); 11 unit tests including a concurrent-reader
    smoke test.
- ROADMAP-v3 D2.4 — `[bgp.rpki]` configuration + daemon RTR thread:
  - `[bgp.rpki] cache / refresh_interval / retry_interval /
    expire_interval` (fail-closed parsing, syntax-checked cache
    address, non-zero intervals) plus `--rpki-cache`, `--rpki-refresh`,
    `--rpki-retry`, `--rpki-expire` flags. The configured intervals
    are the *initial* §6 timers — a v1+ cache overrides them from
    every End-of-Data PDU. `RtrClient::set_intervals` (new,
    non-breaking) injects them.
  - `lr-cli::daemon_rpki`: one thread per configured cache —
    connect/reconnect with the §6 retry backoff, framing-aware decode
    + `on_pdu`, `poll` driving refresh and expiry, atomic delta
    application into the shared `RoaStore`, §6 expiry withdrawing the
    cache-sourced records. The filter DSL's `roa.state` and the
    `roa_validate` import hook read the live store (cache updates
    apply without recompilation). A grep-friendly `rpki:` line
    (cache/state/version/phase/session/serial/roas/intervals/
    last-sync) joins the runtime API `status` output.
  - Daemon e2e against the mock cache:
    `tests/interop/rtr_lr.sh` (API-verified sync + reconnect) and 3
    cargo e2e tests (`crates/lr-cli/tests/daemon_rpki.rs`).
- ROADMAP-v3 D2.5 — SIGHUP / API `reload` hot reload for RPKI:
  - The fresh config's `[[roa]]` tables replace the store's static
    layer wholesale (malformed reload-time ROAs keep the current
    entries — reload never half-applies); an rpki cache address change
    drops the transport, resets the session memory (§8.2) and
    withdraws the old cache's records; a same-address reload forces a
    fresh incremental query. E2E: SIGHUP re-points a running daemon
    from cache A to cache B (API-verified `roas=4 (static=2 rtr=2)`).
- FFI — `lr_roa_store_*` for C/C++/Go/Python embedders:
  `lr_roa_store_new/free/replace_static/apply_deltas/clear_rtr/len/
  validate` with the `LR_ROA_VALID/_NOT_FOUND/_INVALID` outcomes.
  cbindgen header regenerated; C harness + C++ `librouting.hpp`
  RAII (`make_roa_store`, `roa_store_replace_static/apply_deltas/
  validate`) covered by `tests/ffi/harness.{c,cpp}`; Go `RoaStore`
  type (`bindings/lr-go`) and Python `RoaStore` (`bindings/lr-python`,
  new `roa.py` module) with tests.

- ROADMAP-v3 D2.2 — RTR client state machine,
  `lr_bgp::rtr::client::RtrClient` (RFC 8210 §6-§8):
  - **Transport-agnostic client.** The embedder owns the socket, the
    clock and the live `RoaTable`; `RtrClient` owns the protocol.
    `on_connect()` emits the §8.1 query (Serial Query with the
    remembered `(session_id, serial)`, else Reset Query), `on_pdu()`
    consumes one decoded PDU (now carrying its wire version for §7
    negotiation) and returns the next step, `poll()` applies the §6
    refresh/retry/expire timing rules.
  - **Atomic ROA deltas per sync.** Prefix PDUs accumulate in a
    per-sync batch; the End-of-Data step carries the diff of the
    authoritative record sets — one sync = one atomic delta batch
    (or a `snapshot()` swap), never a half-applied database.
    Duplicates (§5.6) coalesce and unknown withdrawals (§12 code 6)
    no-op, both logged — BIRD's lenient channel semantics.
  - **Full client rule coverage:** §7 version downgrade on the first
    lower-version PDU (Serial Notifies ignored during startup),
    §5.2 immediate Serial Query on notify, session-ID change
    re-issuing a Reset Query, §8.3 Cache-Reset re-query, §12
    No-Data-Available vs. fatal error reports, v0 End-of-Data
    default intervals, and expire-window reporting.
  - 19 unit tests, one per protocol rule. The codec module moved to
    `rtr/pdu.rs` with `rtr/client.rs` alongside; `rtr::decode` now
    returns the PDU's wire version (needed by the negotiation).
- ROADMAP-v3 D2.1 — RPKI-Router (RTR) protocol PDU codec,
  `lr_bgp::rtr` (RFC 8210 versions 0-2):
  - **11-variant PDU enum + framing codec.** Serial Notify, Serial
    Query, Reset Query, Cache Response, IPv4/IPv6 Prefix,
    End-of-Data (v0 12-byte and v1 24-byte forms), Cache Reset,
    Router Key, Error Report, and the ASPA PDU (type 11, version 2 —
    SIDROPS ASPA profile, the shape BIRD's `proto/rpki` implements;
    the roadmap previously mis-cited RFC 8281, which is PCEP).
    `rtr::decode` is framing-aware (`Ok(None)` while a PDU is
    partially buffered) and `rtr::encode` writes exact wire lengths.
  - **BIRD-parity validation on decode.** Version-gated PDU types
    (Router Key ≥ 1, ASPA ≥ 2), the 64 KiB PDU ceiling, per-type
    minimum/exact lengths, prefix invariants (`prefix_len ≤ family
    width`, `max_len ≥ prefix_len`, `max_len ≤ family width`), host
    bit masking, reserved flag-bit normalization, and internal
    length consistency for Error Report and ASPA bodies. The nine
    RFC 8210 §12 error codes are a closed enum with the
    fatal/no-data distinction.
  - **29 unit tests** pin byte-exact wire forms from the RFC 8210 §5
    figures, framing behavior, and the malformed-input paths.
  - **Live interop with BIRD 2.** The new `rtr_cache_mock` example
    (`cargo build -p lr-bgp --example rtr_cache_mock`) serves a
    fixed two-ROA dataset through the codec, and
    `tests/interop/rtr_bird.sh` runs BIRD's RPKI client against it:
    BIRD's Reset Query decodes through `lr_bgp::rtr`, the §7
    version downgrade to v1 works, and our Cache Response + Prefix
    + End-of-Data encodings install `192.0.2.0/24-24 AS64512` and
    `2001:db8::/48-64 AS64512` into BIRD's roa4/roa6 tables
    (birdc-verified). Wired into the CI interop job.
- ROADMAP-v3 D6 — fuzzing, property tests, performance benchmarks
  and RFC wire conformance vectors:
  - **`Prefix::network` IPv6 bug fix.** The previous
    implementation zeroed byte `full_bytes` *before* applying
    the partial-byte mask when `rem_bits > 0`, so the mask
    operated on `0x00` and the partial-byte network bits were
    dropped. For a `/31` prefix, byte 3 holds 7 network bits +
    1 host bit; the old code zeroed all of byte 3 and only then
    AND-ed with `0xfe`, leaving byte 3 at `0x00` regardless of
    the original. OSPFv3 LSA origination, BGP-LS export and
    LDP transit-prefix installation all call `.network()` and
    would silently install wrong addresses for any non-byte-aligned
    IPv6 prefix. Fix: skip byte `full_bytes` in the zeroing loop
    when `rem_bits > 0`, then mask in place — symmetric to the
    v4 path. Two regression tests pin the fix.
  - **proptest suite.** `crates/lr-policy/tests/proptest.rs`
    adds 9 property tests covering prefix-lattice invariants
    (reflexivity, antisymmetry, transitivity), `Prefix::network`
    idempotence and containment, `PrefixList::evaluate`
    first-match semantics, and filter-DSL parser robustness
    (never panics, pure compilation).
  - **RFC conformance vectors.** `crates/lr-bgp/tests/rfc_vectors.rs`
    pins 15 byte-exact wire forms from RFC 4271 (header / OPEN /
    UPDATE / KEEPALIVE / NOTIFICATION), RFC 4486 (Cease /
    Administrative Shutdown), RFC 5492 (capability TLV) and
    RFC 6793 (4-byte AS capability via AS_TRANS).
  - **Criterion benchmarks.** Four bench harnesses under
    `crates/{lr-bgp,lr-policy,lr-rib}/benches/` pin the codec /
    ROA / filter / RIB hot paths. The numbers are the immutable
    baseline the future optimisation work (D8.4 radix trie,
    D3.7 bytecode VM, D15 sharded RIB) will be measured against.
  - **cargo-fuzz targets.** Standalone `fuzz/` workspace with
    three targets — `bgp_decode`, `filter_parser`, `roa_validate`
    — asserting the security contract: never panic / abort / UB
    on arbitrary input. Each ships with a hand-picked seed
    corpus under `fuzz/seeds/<target>/`.
  - **Nightly CI** gained a `fuzz` job (5 min per target,
    non-blocking, uploads crash artifacts) and a `bench-smoke`
    job (workspace criterion run, reduced sample size, uploads
    reports as artifacts).
- ROADMAP-v3 D7 — nightly `cargo deny check` CI step fixed. The
  job had been failing on every run since cargo-deny 0.20 because
  it invoked `cargo deny check --all-features`, but cargo-deny
  0.20+ rejects `--all-features` (it operates on `Cargo.lock`,
  not on the build manifest). Separately, `cbindgen v0.27.0`
  ships under MPL-2.0 which was not on the license allow-list —
  MPL-2.0 is OSI-approved, FSF-libre, file-level copyleft that
  only affects `cbindgen` (a build-time-only dependency of
  `lr-ffi`'s `build.rs`). Added to `deny.toml` with rationale.
- `Protocol::bird_name()` returns the canonical BIRD-style
  lowercase protocol name used by the Filter DSL `proto` field.
  `Bgp -> "bgp"`, `Ospfv2 -> "ospf"`, `Ospfv3 -> "ospf3"`,
  `Babel -> "babel"`, `Static -> "static"`, `Connected -> "direct"`,
  `Other(_) -> "unknown"`. `lr-core::rib::Protocol` gained the new
  method; `lr-policy::filter::eval` uses it instead of the Rust
  `Debug` form, so `proto == "bgp"` now matches a BGP route.
- RFC 8326 Graceful BGP Session Shutdown (sender side):
  `Community::GRACEFUL_SHUTDOWN` (`0xFFFF:0000`) is now the
  canonical alias for the legacy `PLANNED_SHUTDOWN` constant at
  the same wire value; `CommunityKind::GracefulShutdown` is added
  to the classification enum; the export hook
  `lr_policy::hooks::GracefulShutdownExportHook` zeroes
  `LOCAL_PREF` on any route carrying the community while preserving
  the community itself so downstream peers see the signal. The
  daemon installs the hook always-on for BGP. `PathAttributes`
  gained a `set_local_pref(u32)` helper. Six regression tests
  cover the new behaviour.
- RFC 2439 route flap damping wired into the daemon (D4.3). The
  `lr-damping` crate shipped in rc.3 as dead code; the daemon now
  exposes it via a `[damping]` TOML table with eight tunables
  (`additive_incr`, `suppress_threshold`, `reuse_threshold`,
  `upper_limit`, `decay_interval_s`, `decay_factor_active`,
  `decay_factor_withdrawn`, plus `enabled`). When `enabled = true`,
  the daemon installs `lr_policy::hooks::DampingImportHook` on the
  import chain and spawns a `lr-damping-decay` thread that drives
  `DampingTable::decay_all` every `decay_interval_s`. The
  `ImportHook` trait gained an `on_withdraw` default no-op
  notification so the damping hook can also track the
  unreachable-transition FoM increment (router's
  `withdraw_from_session` now notifies the chain). Off by default
  (RFC 7196 §3: RFC 2439 defaults are harmful on Internet-facing
  eBGP). Four unit tests + five TOML parsing tests cover the new
  behaviour.
- `docs/ROADMAP-v3.md` captures the 15 post-rc.3 maturity
  directions, grouped into four priority tiers (T1 immediate value,
  T2 high practical value, T3 engineering maturity, T4 long-term
  protocol breadth).
- Supply-chain hardening:
  - `deny.toml` for `cargo-deny` (advisories, licenses, bans,
    sources).
  - `.github/dependabot.yml` for weekly Cargo + GitHub Actions
    dependency bumps.
  - New `supply-chain` job in `.github/workflows/nightly.yml`
    running `cargo audit` and `cargo deny check`.
- Governance documents at the repo root: `CONTRIBUTING.md`
  (PR checklist, commit message format, test layers, RFC pinning
  procedure), `SECURITY.md` (vulnerability reporting, 90-day
  embargo, threat model), `CODE_OF_CONDUCT.md` (Contributor
  Covenant 2.0).

### Changed

- The Filter DSL `proto` field no longer returns the Rust `Debug`
  string form (`"Bgp"`, `"Ospfv2"`, …). Existing filter bodies that
  matched against the Rust `Debug` form will no longer match — the
  BIRD-style lowercase form documented in the `RouteFieldKind::Proto`
  docstring has always been the intended surface, and is now what
  the evaluator produces.
- RustCrypto family bumped to the 2025 releases (issue #12):
  `hmac` 0.12 → 0.13, `sha1`/`sha2`/`blake2` 0.10 → 0.11, all on
  `digest` 0.11 / `crypto-common` 0.2. The four crates move as one
  atomic change — bumping any of them alone splits the tree across
  two incompatible `digest` versions and cannot compile
  (`Hmac<Sha256>` would implement traits from both). Call-site
  migration: MAC key setup resolves through `KeyInit` now (it moved
  off `Mac`), so `<Hmac<Sha1> as Mac>::new_from_slice` UFCS became
  `Hmac::<Sha1>::new_from_slice` with `KeyInit` in scope. Behavior
  is unchanged: the RFC 5709 HMAC-SHA-1/SHA-256 vectors, the RFC
  8967 Babel MAC vectors (HMAC-SHA256 + keyed BLAKE2s-128) and the
  exchange-plane tag tests all pass byte-identically, and the
  `babel_auth.sh` interop lab (challenge resync, wrong-key fail
  closed, incremental deployment) passes against BIRD. All new
  transitive dependencies (`hybrid-array`, `ctutils`, `cmov`,
  `const-oid`, `cpufeatures` 0.3) are `MIT OR Apache-2.0` and
  require Rust ≥ 1.85 — below the workspace MSRV 1.88.
- Dependabot now groups the RustCrypto family (`hmac`, `sha1`,
  `sha2`, `blake2`) into one PR covering major/minor/patch updates.
  Dependabot reads 0.x minor-position bumps as major, which the
  production-dependencies group (minor+patch only) excluded, so the
  0.10 → 0.11 generation landed as four independent PRs (#7-#10)
  that each broke the dependency tree on their own. The dedicated
  group keeps the family on a single `digest` version per PR.

### Deprecated

Nothing yet.

### Removed

Nothing yet.

### Fixed

- `lr-ospf::exchange::DbExchange::poll` retransmits the pending
  initial DBD in ExStart (issue #11). The periodic retransmission
  only fired in Phase::Exchange, so the initial Database Description
  (I|M|MS) sent on entering ExStart was never repeated: one lost
  initial DBD — or one dropped by a peer whose §10.4 DR/BDR gate had
  not opened yet (the runtime drops DBDs below ExStart until the
  election makes `adjacency_viable()` true) — deadlocked the
  adjacency with both sides waiting in ExStart for the other's
  initial while Hellos kept the neighbor alive, and the
  `ospf_broadcast.sh` interop lab hung until its 60 s timeout
  (~10 % of CI runs). RFC 2328 §10.3/§10.8 have the master repeat
  Database Descriptions at RxmtInterval, and BIRD's
  `dbdes_timer_hook` resends in NEIGHBOR_EXSTART for both roles; the
  fix mirrors that. Verified: 20/20 consecutive lab runs green after
  the fix (1 failure in 10 before), two regression tests model the
  deadlock conversation.
- `lr-policy::filter::eval::read_route_field` no longer leaks the
  Rust `Debug` form of `Protocol` into the string surface of the
  Filter DSL `proto` field.

### Security

Nothing yet. Vulnerability disclosures follow the embargo in
[`SECURITY.md`](SECURITY.md); security-relevant fixes land here under
a dedicated `### Security` subsection when they ship.

## [1.0.0-rc.3] — multi-protocol daemon

### Added

- Multi-protocol supervisor — `lr-daemon` can run BGP, OSPF and
  Babel sessions in one process, with cross-protocol Loc-RIB
  merging for shared routers.
- `[[babel.interface]]` TOML table with full RFC 8966 §A.2
  parameter parsing.
- `[[roa]]` TOML table for static ROA loading.
- `[[filter]]` TOML table for BIRD-like filter DSL.

See [`docs/ROADMAP.md`](docs/ROADMAP.md) for the full v2 workstream
narrative that landed in this release candidate.

## [1.0.0-rc.2] — CLI binaries in the release

### Added

- `lr` and `lr-daemon` CLI binaries included in per-OS release
  archives.

## [1.0.0-rc.1] — the API-freeze pre-release

### Added

- Public API freeze. Every crate ships under the dual `MIT OR
  Apache-2.0` license. See [`docs/RELEASE-PLAN.md`](docs/RELEASE-PLAN.md)
  for the freeze criteria that gate 1.0.
