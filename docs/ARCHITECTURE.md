# librouting Architecture

This document describes the layering, data flow, and extension points of
`librouting`. It is the canonical reference for new contributors and
embedders.

## High-level layout

```
+----------------+    +----------------+    +----------------+    +---------+
|   lr-bgp       |    |   lr-ospf      |    |   lr-babel     |    | lr-ldp  |
| (RFC 4271 +    |    | (RFC 2328 /    |    | (RFC 8966 +    |    | (RFC    |
|  extensions)   |    |  RFC 5340)     |    |  RFC 9079)     |    |  5036)  |
+-------+--------+    +-------+--------+    +-------+--------+    +----+----+
        |                     |                     |                  |
        +---------------------+---------------------+------------------+
                              |
                              v
                    +---------------------+
                    |   lr-router         |    <- orchestrator
                    |   (DefaultRouter)   |
                    +----------+----------+
                               |
            +------------------+------------------+----------------+
            |                  |                  |                |
            v                  v                  v                v
    +---------------+  +---------------+  +----------------+  +---------+
    |   lr-rib      |  |   lr-policy   |  |   lr-bfd       |  | lr-bmp  |
    | (Adj-RIB-In,  |  | (route-maps,  |  | (peer failure  |  | (RFC    |
    |  Loc-RIB,     |  |  prefix lists,|  |  detection)    |  |  7854   |
    |  Adj-RIB-Out) |  |  AS filters,  |  +----------------+  |  sink)  |
    +-------+-------+  |  safety net)  |                      +---------+
            |          +-------+-------+
            |                  |
            v                  v
            +------------------+
            |   lr-osroute     |  <- optional OS kernel interface
            | (Linux rtnetlink,|
            |  BSD route(4),   |
            |  Windows IPHelper|
            |  + MPLS dataplane)|
            +------------------+
```

All crates depend on `lr-core` for shared primitives (`IpAddr`, `Prefix`,
`Asn`, `RouterId`, `Route`, `Attributes`, codec traits, FSM/timer traits).
`lr-mpls` provides the RFC 3032 label + label-stack codec shared by
`lr-ldp` and `lr-bgp` (BGP-LU, RFC 8277). `lr-mrt` (RFC 6396) and `lr-bmp`
(RFC 7854) feed monitoring / dump tooling. `lr-damping` (RFC 2439 flap
damping) plugs into the selection stage via `lr-policy` hooks. `lr-ffi`
exposes a C ABI; Go/Python/C/C++ bindings sit on top.

## Three-layer API

Every protocol crate is structured so embedders can stop at the right level
of abstraction:

| Layer | Description                                  | Example API            |
| ----- | -------------------------------------------- | ---------------------- |
| 1     | Pure codec — encode/decode wire bytes        | `BgpCodec`, `BfdCodec` |
| 2     | Protocol FSM — state machine driving actions | `BgpPeer::step`        |
| 3     | Orchestrator — wires sessions + RIB + timers | `DefaultRouter`        |

Layer 1 is for analyzers (pcap processors, route collectors).
Layer 2 is for embedders that own their event loop but want protocol logic.
Layer 3 is for embedders that just want "run BGP for me" and get Loc-RIB
deltas back.

## RIB pipeline

Fully implemented in `lr-router::DefaultRouter` (see
`crates/lr-router/src/instance.rs`):

```
inbound bytes  →  BgpPeer::feed_bytes  →  InstallRoute/WithdrawRoute actions
                                                                ↓
              SafetyNet.check  (AS-loop, martian, next-hop sanity)
                                                                ↓
              ImportHooks  →  AdjRibIn  →  reselect (BestPath for BGP,
                                              RouteSelector for mixed)
                                                                ↓
                                              LocRib  →  RouterEvent::RouteInstalled
                                                                ↓
              ExportHooks  →  egress rules (AS prepend, next-hop-self,
              iBGP split-horizon, RR reflection, OTC valley-free)
                                                                ↓
                      AdjRibOut  →  BgpPeer::advertise  →  outbound bytes
                                                                ↓
                            OsRouteTable.add_route  (optional, lr-daemon)
```

Withdrawals run the same pipeline in reverse: the session reports
`WithdrawRoute`, the Adj-RIB-In entry is removed, the decision process
re-runs, and peers that previously received the route get a wire
withdrawal.

Each stage is replaceable via traits:

- `ImportHook` / `ExportHook` — arbitrary Rust code that may drop or mutate
  routes (`DefaultRouter::hooks_mut()`).
- `SelectionHook` — override the comparator (e.g. prefer routes from a
  specific peer).
- `OsRouteTable` — platform abstraction for the kernel FIB.

### Timer routing

Timer IDs are encoded as `(session << 8) | timer_code` inside
`DefaultRouter`, so every FSM timer expiry is routed back to the session
that armed it — a prerequisite for multi-session deployments where hold
timers must not cross-fire between peers.

### OSPF / Babel runtimes

OSPF sessions decode Hellos into the neighbor FSM, install received LSAs
into the per-session LSDB and re-run SPF on every LSDB change; the
resulting intra-area routes (stub + transit networks) land in Loc-RIB with
delta bookkeeping (stale routes are withdrawn). Babel sessions track
Hello/IHU/Router-Id/NextHop/Update TLVs into the neighbor + route tables,
apply the feasibility rules of RFC 8966 §3.5, and publish feasible best
routes to Loc-RIB — including metric-infinity retractions and RFC 9079
source-specific destinations.

### Canonical AS_PATH

Route attribute bags store AS_PATH in canonical 4-byte encoding regardless
of the session's negotiated width (ingress normalizes, egress re-encodes).
This means best-path, the safety net and the egress rules never have to
guess the wire format of a route's provenance.

## Extension points

| Hook trait      | Stage          | Crate      |
| --------------- | -------------- | ---------- |
| `ImportHook`    | post-decode    | lr-policy  |
| `SelectionHook` | best-path      | lr-policy  |
| `ExportHook`    | pre-encode     | lr-policy  |
| `SafetyNet`     | post-decode    | lr-policy  |
| `OsRouteTable`  | kernel install | lr-osroute |

## BGP topology

A `PeerTopology` carries the relationship of the local speaker to the peer:

- `role`: `Ebgp` / `Ibgp` / `ConfederationExternal` / `ConfederationInternal`
- `rr_client`: true if this peer is a route-reflector client (RFC 4456)
- `rs_client`: true if this peer is a route-server client (RFC 7947)
- `otc`: RFC 9234 role (`Provider` / `Customer` / `Peer` / `RouteServer` /
  `RsClient`)

The topology drives AS_PATH mutation, NEXT_HOP rewriting, and reachability
checks (`can_advertise()` enforces iBGP full-mesh + RR rules + OTC
valley-free: a route carrying OTC may only be advertised to Customers and
RS-clients, per RFC 9234 §5 egress rule 2).

## Best-path comparator

`lr-bgp::best_path::BestPath` implements RFC 4271 §9.1.2 with extensions:

1. Weight (vendor-specific; set via policy).
2. LOCAL_PREF (iBGP only; eBGP approximated as 100).
3. AS_PATH length (AS_SET counts as 1, RFC 4271 §9.1.2.2(a); confederation segments not counted — RFC 5065 §5.3(3) — unless `count_confed_in_path_len`).
4. ORIGIN (IGP < EGP < INCOMPLETE).
5. MED (only when same neighboring AS, unless `always_compare_med`).
6. eBGP over iBGP (unless `prefer_externals=false`).
7. Lowest IGP metric to NEXT_HOP (caller-supplied).
8. NEXT_HOP equal to peer address.
9. Oldest route (only when `deterministic_router_id=false`).
10. Lowest ORIGINATOR_ID (RFC 5004 deterministic).
11. Shortest CLUSTER_LIST (RFC 4456).
12. Lowest peer IP / peer-id (last resort).

Multipath (`multipath()`) collects all routes that tie on steps 1–11 (the
final peer-id tiebreaker is by definition different for different peers).
`multipath_relax=true` allows mixing neighbors.

## Filter DSL

`lr-policy::filter` is a self-contained BIRD-style filter language.
The daemon references a filter by name from a peer's
`import_filter` / `export_filter` table, the FFI exposes
`lr_filter_compile` / `lr_filter_evaluate`, and embedders can call
`lr_policy::filter::compile` directly. The subsystem is split into six
files in `crates/lr-policy/src/filter/`, with a typed AST as the
contract between the parser and the evaluators:

```
   source text
        │
        ▼
   lexer.rs        hand-rolled scanner: 1-char/2-char/keyword tokens,
   (Token, Span)    each token carries its byte Span (issue #18 P0)
        │
        ▼
   parser.rs      Pratt parser for expressions (parse_binary with
   (Filter)        operator-precedence + right-assoc fixpoint) +
        │         recursive descent for statements; validates call
        │         targets (user fn vs built-in) up front
        │
        ├──────────────────────┐
        ▼                      ▼
   eval.rs                 bytecode.rs + peephole.rs
   tree-walking             flat Instr stream + peephole passes
   interpreter              (constant propagation + literal folding +
   (semantic oracle)         dead-branch elimination + jump threading
                            + BranchFieldIntCmp fusion)
        │                      │
        └──────┬───────────────┘
               ▼
         EvalResult (Accept / Reject(reason) / Fallthrough)
```

### AST

The AST is `Filter { name, body: FilterBody, functions: Vec<FunctionDecl>, line_index }`
where `FilterBody { stmts: Vec<Stmt> }`. `Stmt` carries the imperative
side (`If` / `Case` / `Let` / `Assign` / `AssignRouteField` /
`AppendRouteField` / `Expr` / `Block` / `Return` / `Accept` / `Reject`);
`Expr` carries the functional side (`Lit` / `Var` / `RouteField` /
`Call` / `Defined` / `Method` / `Binary` / `Unary` / `Set` /
`PrefixSet`). Every node owns its byte `Span`; structural equality is
span-blind (hand-written `PartialEq` ignores spans) so peephole golden
tables and proptest oracles don't shift when the source is reformatted.
`RouteFieldKind` enumerates the settable (`bgp.local_pref` / `med` /
`next_hop` / `communities` / `ext_communities` / `large_communities`)
and read-only (`net` / `proto` / `source` / `bgp.as_path` /
`bgp.origin` / `roa.state`) attributes; the parser rejects assignment
to a non-settable field at compile time.

### Pratt parser

`parse_binary(min_prec)` is the precedence-climbing loop: it peeks
the next operator (`TokenKind::Plus` → `BinaryOp::Add`, …, including
`Tilde`/`BangTilde` for `~`/`!~` membership), checks the operator's
`precedence()` against `min_prec`, advances, recurses with the
right-associative fixpoint (`prec` for right-assoc, `prec + 1`
otherwise), then folds the result into an `Expr::Binary` node. Unary
(`!x`, `-x`) and postfix (`.method(...)`) sit above the binary loop;
primaries (`Lit`, `Var`, `RouteField`, `(` expr `)`, set literals,
prefix-set literals) sit at the bottom. The parser runs a `validate_calls`
pass after the body so every `Expr::Call` name resolves to either a
user-declared function or a known built-in (`len`, `bgp.first_as`,
`bgp.contains`, …) — the bytecode compiler relies on this totality
to resolve user calls to indices (GitHub #19 P2).

### Tree-walking evaluator (the oracle)

`eval::Evaluator<'a, C: FilterContext + ?Sized>` holds the scope
stack (`Vec<Scope>` of `BTreeMap<String, Value>`), the user functions,
and a call-depth counter (capped at `MAX_CALL_DEPTH = 64` so runaway
recursion surfaces as `CallDepthExceeded` instead of a thread-stack
overflow). The evaluator walks the AST statement-by-statement; the
first `accept` / `reject` short-circuits the whole filter
(`ControlFlow::Accept` / `Reject(reason)`), and `return` exits the
enclosing user function (the DSL's `accept` inside a function
terminates the *whole filter*, BIRD parity). `EvalResult::Fallthrough`
is the no-terminal-hit case the daemon falls back to (the
`[[peer]] import_filter` with no `accept`/`reject` matching a route
leaves it for the next route-map entry).

### FilterContext trait

The evaluator never touches a `Route` directly — it goes through the
`FilterContext` trait, an interface of typed accessors
(`bgp_local_pref(&Route) -> Option<u32>`,
`bgp_communities(&Route) -> Vec<(Asn, u16)>`, `roa_state(&Route) -> RoaStateLit`,
…) plus mutators (`set_bgp_local_pref(&mut Route, u32)`,
`bgp_as_path_prepend(&mut Route, Asn)`, …). This has three payoffs:

1. The DSL never collapses an absent attribute to its default
   (`Option<u32>` preserves "unset" vs "set to zero" — BIRD's
   `defined()` semantics depend on it; the `Defined` AST node is
   specifically an unevaluated probe that goes through the typed
   presence check, not a value read).
2. The daemon's `DaemonFilterContext` and the FFI's C-callback
   context (`lr_filter_context_t`, 19 optional function pointers,
   NULL = the built-in route-backed default) share the same evaluator,
   so a C embedder's `bgp.local_pref` reads the same path the daemon
   does.
3. The in-place integer fast paths (`Attributes::get_u32_be` /
   `get_u8`, GitHub #19 P3) live behind the trait, so the evaluator
   reads LOCAL_PREF / MED / ORIGIN without cloning the `Vec<u8>`
   attribute payload.

### Bytecode VM

`bytecode::compile` lowers the whole AST to a flat `Vec<Instr>` plus
a per-function `Vec<Instr>` for each user function; the daemon's
`daemon_policy::build_filters` precompiles every `[[filter]]` at
startup so import/export hot loops run the VM. The instruction set
is small and flat (`Push` / `LoadVar` / `LoadField` / `StoreVar` /
`AssignVar` / `StoreTmp` / `LoadTmp` / `Bin` / `Not` / `Neg` /
`JumpIfFalse` / `JumpIfTrue` / `Jump` / `Truthy` / `Match` /
`BranchFieldIntCmp` / `Defined` / `Call` / `CallFn` / `Method` /
`AssignField` / `AppendField` / `Pop` / `PushScope` / `PopScope` /
`Accept` / `Reject` / `Return` / `EvalTree`) — `EvalTree(Expr)` is
the tree-walking fallback for dynamic subtrees (e.g. `defined()` on
an arbitrary expression), so the VM and the interpreter cannot diverge
semantically. A 27-source × 4-route equivalence table pins verdict
+ attribute-state equality across both engines (`vm_matches_interpreter_on_policy_table`
plus the bench-shaped `vm_matches_interpreter_on_bench_shapes`).

`peephole::optimize_with_spans` runs three passes inside `compile`:
constant propagation + literal folding (tracks `let` constants,
folds `Push; Push; Bin` triples and `Push; Not/Neg` pairs, refuses
div-by-zero / overflow / bad-shift), dead-branch elimination
(`Push(Bool(c)); JumpIfFalse/JumpIfTrue` → drop or `Jump`, only when
the conditional is not a jump target — preserves `&&`/`||`
short-circuit semantics), and jump threading (`Jump(X) → Jump(Y)`
chains). GitHub #19 P6 adds a fourth fused pass that collapses the
canonical `LoadField(int); Push(Int(c)); Bin(op); JumpIf*(t)` pattern
into one `BranchFieldIntCmp` instruction (zero stack traffic) for the
four int-typed fields and six comparison ops.

### Comparison to BIRD `f_line`

BIRD compiles its filter AST to an `f_line` (a flat instruction
array with embedded constant pools) and runs it through `f_run`. lr's
design is structurally similar — flat `Vec<Instr>`, per-function
instruction arrays, a small constant pool embedded in the `Push` /
`Match` operands, the same `accept` / `reject` short-circuit
semantics — with two deliberate differences:

- lr keeps the tree-walking interpreter as the semantic oracle and
  uses `EvalTree` as the dynamic-subtree fallback. BIRD removed its
  tree-walker when `f_line` landed; lr keeps it so the bytecode VM
  has a differential oracle for the equivalence table.
- lr does not intern strings or attributes inside the VM. Names
  (`LoadVar` / `AssignVar` / `Call` / `Method`) are still `String`
  clones. The P1 attempt at side-table interning (compact
  `Instr { op, a: u32, b: u32 }` + `consts` / `matches` / `trees`
  side tables) measured a 2–10 % regression from the indirection
  and was reverted; the current `Instr` is a fat enum (64 B) but the
  fetch loop is branch-predicted and cache-line-aligned, which is
  where the hot loop wins.

## Performance characteristics

### ROA validation (RFC 6811)

`lr-bgp::roa::RoaTable::validate` walks a path-compressed (Patricia)
prefix trie (ROADMAP-v3 D8.4). The covering ROAs of a route are exactly
the trie nodes on the root-to-route bit path, so a query costs
`O(prefix_len)` (bounded by 32 / 128 bit visits) whatever the table
size. Entries stay in a canonical sorted `Vec<RoaEntry>` (dumps,
equality, snapshot determinism) with the trie as a pure lookup index
built once at construction.

Criterion (`crates/lr-bgp/benches/roa_validate.rs`, sample-size 20,
x86_64 Linux):

| Probe                  | 1k entries | 10k entries | 100k entries |
| ---------------------- | ---------- | ----------- | ------------ |
| uncovered (`NotFound`) | ~5.1 ns    | ~5.1 ns     | ~5.8 ns      |
| covered (`Valid`)      | ~75 ns     | ~119 ns     | ~182 ns      |

Both shapes are flat across the sizes operators actually deploy (1k
single-AS, 10k IXP route-server, 100k regional cache). The replaced
linear scan visited every entry per query and grew linearly with the
table — the trie removes that ceiling entirely.

### Filter DSL evaluation

Policy filters run the D3.7 stack-machine bytecode (see the
[Filter DSL](#filter-dsl) chapter for the AST, parser, evaluator and
peephole design). Filters compile once at startup and each route
evaluation is a flat opcode loop with no AST re-walking and no
per-route allocation on the match path
(`crates/lr-policy/src/filter/bytecode.rs`). Criterion harnesses:
`crates/lr-policy/benches/filter_eval.rs` (seven shapes under both
engines) and `crates/lr-policy/benches/import_pipeline.rs` (the
daemon per-UPDATE cost at 100 / 1k / 10k routes).

### Daemon thread model and lock strategy

The `lr` daemon runs one thread per BGP peer session, one API-socket
thread, BFD / BMP / RTR threads, per-protocol OSPF/Babel loops and a
periodic ticker. All of them share the routing state through
`Arc<RwLock<DefaultRouter>>` (ROADMAP-v3 D8.1):

* **Read lock** — API dumps and status (`rib_paths_snapshot`,
  `session_summaries`, `rib_len`), Babel RTT probes, OSPF/LSDB status
  views. Readers run concurrently: a `show routes` no longer blocks
  behind (or blocks) a peer import.
* **Write lock** — session setup, `feed_input`, event polling,
  best-path reselection, redistribution, Babel GC, config reload.

`DefaultRouter` contains no interior mutability, so `&self` methods
are genuinely read-only and the borrow checker polices the
read/write classification of every call site. Hook traits carry
`Send + Sync` for the same reason (`lr-policy::hooks`).

The daemon event plane is still thread-per-socket with non-blocking
poll loops — see ROADMAP-v3 D8.3 for the planned `mio` event-loop
migration.

### Scalability ceiling and next steps

With one `RwLock` there is still at most one writer at a time; a full
BGP table (800k+ routes) arriving over several peers serializes on
import. The planned next stages (ROADMAP-v3 D8.2 / D15) are per-AFI
Loc-RIB sharding (independent `RwLock<LocRib>` per family so v4 and
v6 imports run in parallel), a lock-free event bus, sharded
Adj-RIB-In, and import-throughput benchmarks at 100k / 500k / 1M
routes.

## OS routing table reference

`lr-osroute` provides:

- **Trait**: `OsRouteTable` — `add_route()`, `delete_route()`, `list_routes()`.
- **Reference impl**: `linux::RtNetlink` — speaks raw rtnetlink over
  `AF_NETLINK` sockets. Builds `RTM_NEWROUTE` / `RTM_DELROUTE` messages with
  `RTA_DST` / `RTA_GATEWAY` / `RTA_OIF` / `RTA_PRIORITY` attributes.
- **Stub**: `StubRouteTable` — for platforms without rtnetlink or for tests.

The crate is **opt-in** because it performs FFI and requires privileges.
Embedders running inside a sandbox can omit it entirely.

## BFD integration

`lr-bfd` is fully independent — it doesn't depend on `lr-bgp` or any other
protocol crate. It implements the RFC 5880 §6.8 state machine and timing
exactly (peer-multiplier detection time, negotiated transmit interval with
jitter, Poll/Final parameter confirmation). The sockets live in
`lr-osroute::bfd_transport` — one shared receive socket per (address,
mode) on the well-known port (3784 single-hop per RFC 5881, 4784 multihop
per RFC 5883) with the single-hop TTL 255 filter, plus one transmit
socket per session with an RFC 5881 §4 ephemeral source port.

The daemon wires the two (`daemon_bfd.rs`): one BFD session per
`bfd = true` peer; a BFD Up→Down transition tears the BGP session down
(CEASE NOTIFICATION + route purge) without waiting for the hold timer
(typical sub-second detection vs. 90s for BGP-only keepalives), and the
connector holds off reconnecting while BFD is down.

## Damping integration

`lr-damping` implements RFC 2439 route flap damping. It is _opt-in_ and
off by default: **RFC 7196 documents that RFD with the RFC 2439 default
parameters penalizes well-connected networks** (each alternate path
explored during convergence re-triggers the penalty), which is why most
operators disable it on Internet-facing eBGP. The `lr-damping`
configuration knobs cover the RFC 7196 conservative settings. Use it
for OSPF / Babel where there is no AS_PATH loop detection to absorb
transient flaps, or as a defensive-safety mechanism during incidents.

## FFI and bindings

- `lr-ffi` exposes a C ABI. `cbindgen` generates `include/lr_ffi.h`.
- `bindings/lr-go` — cgo wrapper with `runtime.SetFinalizer` cleanup.
- `bindings/lr-python` — cffi loader with `Router` context manager.
- `include/librouting.hpp` — header-only C++ wrapper (RAII, throwing
  wrappers).

The C ABI surface is intentionally minimal: opaque handle (`lr_router_t`),
`lr_router_*` lifecycle functions, `lr_bytes_t` for byte buffers,
thread-local `lr_last_error()` for error strings.

## Feature flags

Each crate exposes `default` features that are sensible for typical
embedders. Notable toggles:

- `lr-core` — `std` (default) / `no_std` (for embedded analyzers).
- `lr-bgp` — `asn4` / `mp_bgp` / `addpath` / `graceful_restart` /
  `enhanced_rr` / `extended_communities` / `long_lived` / `labeled_unicast` /
  `exchange-plane` (off by default; the LRXP private capability prototype).
- `lr-ospf` — `v2` / `v3` / `nssa` / `te` / `hmac_sha` / `graceful_restart`.
- `lr-bfd` — `std` / `no_std`.
- `lr-ldp` — `std` / `no_std`.

## Testing

- Unit tests live alongside the source (`#[cfg(test)]` modules).
- End-to-end tests live in `crates/lr-tests/tests/` — 16 files:
  - `tcp_smoke.rs` — two librouting BGP peers exchange OPEN+KEEPALIVE over
    real TCP.
  - `route_propagation.rs` — originate → Adj-RIB-In → Loc-RIB →
    Adj-RIB-Out → withdrawal reversal, over the full pipeline.
  - `protocol_runtimes.rs` — OSPF and Babel delta integration into Loc-RIB.
  - `add_path.rs` — RFC 7911 multi-path propagation.
  - `bgp_session_modes.rs` — the 8 dual-stack / MP-BGP / ENH session modes.
  - `bgp_labeled_unicast.rs` — RFC 8277 labelled unicast (BGP-LU).
  - `gtsm_max_prefix.rs` — RFC 5082 GTSM + per-peer maximum-prefix.
  - `redistribution.rs` — cross-protocol pipes.
  - `route_aggregation.rs` — RFC 4271 §9.2.2.2 aggregate lifecycle.
  - `bmp_monitoring.rs` — RFC 7854 Peer Up/Down + Route Monitoring.
  - `ospf_broadcast.rs` — RFC 2328 §10.4 adjacency gating on broadcast segments.
  - `ospf_multi_area.rs`, `ospf_external.rs`, `ospf_stub_nssa.rs`,
    `ospf_virtual_link.rs` — OSPF area/ABR/NSSA/§15 coverage.
  - `tutorial_snippets.rs` — compile-and-run anchors for `docs/tutorial.md`.
- Daemon-level integration tests in `crates/lr-cli/tests/` (20 files)
  spawn the real `lr-daemon` binary (runtime API, signals, reload,
  privilege drop, multi-peer fan-out, RFC 8212 policy, FRR parity knobs,
  exchange-plane prototype, BFD fast-fail, filter diagnostics,
  graceful-shutdown receive, metrics endpoint, config `check` /
  `to-dsl`, `lrctl` proxy surface).
- Per-crate integration suites: `crates/lr-bgp/tests/` (5 files,
  incl. RFC 4271 Appendix A vectors and the codec-reset regression),
  `crates/lr-ldp/tests/` (2 files, the LDP session-FSM and
  transit-LSR e2e suites, ~5 KLOC), `crates/lr-router/tests/`
  (2 files, Babel announcement + multihop), `crates/lr-policy/tests/`
  (3 files: filter corpus + proptest + grammar corpus),
  `crates/lr-osroute/tests/` (2 files, the OSPFv3-transport + SRv6
  kernel-gated suites).
- Interop scripts against the BIRD and FRR reference routers live in
  `tests/interop/` — 54 scripts covering BGP / OSPF / Babel / LDP /
  BFD / BMP / RPKI-RTR / TCP-AO / Add-Path / route-server / E-LSA /
  End.X / SRv6 / graceful-shutdown / RFC 8212 / filter DSL / damping /
  aggregation / multi-protocol / redistribute / MPLS-LSP / MRT /
  labelled-unicast. They run in CI on ubuntu runners with the
  reference daemons installed via apt; they skip gracefully when
  absent.
- Total: ~1,900 nextest cases run on every push across 50
  integration test files in `crates/*/tests/` plus per-crate unit
  tests, doc-tests across every public API, and 54 interop scripts.
  Run `cargo nextest list --workspace --all-features` for the live
  count.

## CI/CD

`.github/workflows/`:

- `ci.yml` — fmt + clippy + nextest + doc-tests + C/C++ harness +
  Python bindings + Go bindings + 5 in-process interop labs
  (`two_daemon.sh`, `addpath.sh`, `filter_dsl_bird.sh`,
  `babel_multi_nic.sh`, `babel_multihop.sh`) + MSRV 1.88 + cross
  builds (`aarch64-unknown-linux-gnu`,
  `x86_64-pc-windows-gnu`, `x86_64-apple-darwin`) + native macOS /
  Windows runners + coverage (`cargo-tarpaulin`).
- `nightly.yml` — `miri` (UB audit on the FFI unsafe surface),
  `supply-chain` (`cargo audit` + `cargo deny`), `vm-kernel-gated`
  (QEMU VM with `CAP_NET_ADMIN` for TCP-AO / MPLS / SRv6), `fuzz`
  (the three `cargo-fuzz` targets: `bgp_decode`, `filter_parser`,
  `roa_validate`), `bench-smoke` (criterion smoke run).
- `docker.yml` — multi-stage Dockerfile build verification
  (ROADMAP-v3 D12.3) on push / PR / nightly.
- `release.yml` — tag-driven cross-compiled binaries + `cargo publish`
  + GitHub Release archives.

## License

`MIT OR Apache-2.0` per crate. No GPL/AGPL components.
