# Roadmap v3 — toward a mature routing stack

Forward-looking plan that picks up where [`ROADMAP.md`](ROADMAP.md) (the v2
landing log) leaves off. Each item below is a self-contained direction:
the current gap, the proposed work, the reference implementation to
mirror, and an estimated size. Items get checked off (`~~struck
through~~`) as they land; the strike-through stays as the audit trail
exactly like the v2 log.

The *current* implemented-vs-missing snapshot still lives in
[`STATUS.md`](STATUS.md) and is the source of truth for "what can it do
today". This file answers "what is the next block of work and why".

## Prioritisation

The 15 directions are grouped by impact and risk so reviewers can
sequence the work:

* **T1 — immediate value, low risk** (do first):
  D3.6, D7, D6, D4.3, D10.1
* **T2 — high practical value, medium risk**:
  D1, D2, D3 (rest), D4 (rest), D5
* **T3 — engineering maturity, larger surface**:
  D8, D15, D9, D14
* **T4 — long-term protocol breadth (post-1.0)**:
  D10 (rest), D11, D13, D12

Cross-direction ordering is a judgement call, but protocol-correctness
items (D1, D2) always beat convenience items when in doubt, and small
verifiable commits always beat big-bang ones.

---

## D1 — Babel multi-session concurrency + per-interface parameters

**Status:** landed — ~~D1.1 (RTT measurement codec)~~, ~~D1.2 (interface
state)~~, ~~D1.3 (key scoping)~~, ~~D1.4 (router re-advertisement +
flush)~~, ~~D1.5 (daemon multi-session rewrite)~~ and ~~D1.6 (e2e)~~
are all in. Tracks `lr-babel` + `lr-router` + `lr-cli::daemon`.

**What landed.**

1. ~~**Per-interface socket pair.**~~ `run_babel_daemon` resolves every
   `[[babel.interface]]` glob against the system's interfaces (first
   matching pattern wins, BIRD semantics) and gives each match its own
   `BabelIface` — one or two `BabelTransport`s (the v6 link-local and
   the v4 address, RFC 8966 §4.1), each a unicast socket bound to the
   interface address (TTL 255, SO_BINDTODEVICE, IP_MULTICAST_IF) plus a
   wildcard-bound multicast socket that joins the group on its own
   interface. The wildcard listener is isolated two ways —
   `IP_MULTICAST_ALL` is switched off (the Linux default would deliver
   every locally-joined group's traffic to every wildcard socket) and
   `SO_BINDTODEVICE` pins it to the segment — verified against the
   kernel's delivery model before the rewrite landed.
2. ~~**Per-interface session.**~~ One `SessionConfig::babel` session per
   interface, each with its own RFC 8966 §3.3 router-id (address +
   per-boot random) and its own announcement seqno. Routes learned on
   one interface are re-advertised on the others with the *origin's*
   (router-id, seqno) preserved and the interface cost added
   (§3.7.5), split-horizoned per session through
   `RouterInstance::babel_reachable(exclude)`; a claim that vanishes is
   retracted on the next announcement with an infinity-metric Update
   under the origin's Router-Id (§3.5.5) instead of leaving peers to
   time it out. The daemon polls every socket non-blocking, as before,
   one loop for all interfaces.
3. ~~**Per-interface authentication.**~~ `[[babel.key]]` gained the
   `interface` pattern (D1.3): keys without one apply everywhere, keys
   with one only to matching interfaces; each interface builds its own
   `BabelAuthInterface` (fresh Index, own nonce source) and its
   challenge traffic stays unicast to the peer.
4. ~~**Per-interface parameters.**~~ Every `[[babel.interface]]` field
   drives its interface: `hello_interval_ms` (Hello cadence + the
   advertised interval), `update_interval_ms` (the Update TLV's
   interval + the re-announcement hold), `rxcost` (the IHU and the
   base of every advertised metric), `next_hop_ipv4` /
   `next_hop_ipv6` / `extended_next_hop` (§3.5.3, per-transport gating:
   the v4 transport carries IPv4 destinations only), `port`, `group`.
   The Hello seqno advances by one per Hello (§3.4.1) while the Update
   seqno only moves when the advertised set changes (§3.7.1).
5. ~~**RTT measurement.**~~ RFC 8966 §A.2.4 end to end: timestamped
   Hellos, IHU echoes of the peer's `(send, receive)` pair (babeld's
   1 s freshness window), EWMA smoothing (decay 42/256), the sanity
   window, and the linear `rtt_penalty` between `rtt_min_us` /
   `rtt_max_us` added to every advertised metric; `rtt_cost` gates it
   all (tunnels default to 96, babeld parity).
6. ~~**Per-interface `check_link`.**~~ One-second `getifaddrs` polling
   (RFC 8966 §A.2 / BIRD `check link yes`, default on): a segment that
   went down loses its routes — `babel_flush_session` withdraws them
   from the Loc-RIB and the other interfaces' re-advertisements — and
   stops announcing until the link returns.
7. ~~**Route expiry (§3.2.5).**~~ Landed alongside the rewrite because a
   transit speaker without it is not protocol-correct: every Update
   refreshes its claim's hold deadline (babeld's `hold_time =
   MAX(4·I/100 + I/50, 15)` s), `RouterInstance::babel_gc` sweeps once
   a second, and a neighbour whose Hellos stopped loses everything it
   taught us without waiting out each hold (babeld's
   `retract_neighbour_routes`). `feed_input_at` now carries the
   transport's wall-clock milliseconds beside the 32-bit BABEL-RTT
   microsecond clock so the bookkeeping is real-time-true.

**Verification.** `tests/interop/babel_multihop.sh` — three speakers in
three namespaces chained over veth pairs: bidirectional transit through
the multi-session middle box, `check link` withdrawal end-to-end within
the convergence window, and reconvergence when the link returns; in CI
beside `babel_multi_nic.sh` (per-interface sessions + parameters).
Router-level semantics (split horizon, dedup by claim, flush, expiry,
neighbour-death retraction, the RTT round trip) are pinned in
`crates/lr-router/tests/babel_multihop.rs`; the timestamp sub-TLVs and
the RTT state machine in `lr-babel` unit tests.

**Reference implementations.** BIRD `proto/babel/babel.c`
(`babel_if_start()` / `babel_if_stop()` per interface) and babeld
(`interface.c`, `neighbour.c`, `message.c`, `route.c`) were read
first-hand for the Hello/IHU cadences, the hold-time formula, the
retraction behaviour and the RTT constants quoted above.

---

## D2 — RPKI-RTR client (RFC 8210)

**Status:** landed — ~~D2.1 (PDU codec)~~, ~~D2.2 (client state
machine)~~, ~~D2.3 (incremental ROA table)~~, ~~D2.4 (configuration
surface + daemon RTR thread)~~ and ~~D2.5 (hot reload)~~ are all in.
Tracks `lr-bgp` + `lr-cli::daemon`. Note: the ASPA PDU reference in
this file originally cited RFC 8281, which is PCEP — the ASPA PDU
(type 11, version 2) comes from the SIDROPS ASPA profile, which BIRD
implements (`proto/rpki/packets.c` `struct pdu_aspa`). The codec
follows the BIRD shape.

**Current gap.** `crates/lr-bgp/src/roa.rs` implements the RFC 6811 §2
validation algorithm, but ROA data can only be loaded through a static
`[[roa]]` TOML table or the `lr_router_add_roa_entry` FFI. There is no
RPKI cache-server connection (TCP 8282), no Serial/Reset Query PDU, no
Cache Response / End-of-Data PDU, no incremental updates. Operators
must maintain ROA data by hand — unacceptable in production.

**Proposed work.**

1. ~~**RTR PDU codec.**~~ **Landed.** `crates/lr-bgp/src/rtr.rs`
   implements the ten PDU types RFC 8210 §5 defines plus the ASPA PDU
   v2, SIDROPS ASPA profile — the reference the item below
   originally mislabeled as RFC 8281, which is PCEP): Serial Notify,
   Serial Query, Reset Query, Cache Response, IPv4/IPv6 Prefix,
   End-of-Data (both the v0 12-byte and v1 24-byte forms), Cache
   Reset, Router Key, Error Report, ASPA. Framing-aware
   `rtr::decode` / `rtr::encode` + the 11-variant enum, with
   BIRD-parity validation (version gates, PDU length bounds,
   prefix invariants, host-bit masking, reserved-flag
   normalization). 29 unit tests pin the byte-exact RFC wire forms;
   the `rtr_cache_mock` example plus `tests/interop/rtr_bird.sh`
   run BIRD 2's real RPKI client against the codec — its Reset
   Query decodes through us, our Cache Response + Prefix + EoD
   encodings install ROAs into BIRD's roa4/roa6 tables.
2. ~~**RTR client state machine.**~~ **Landed** as
   `lr_bgp::rtr::client::RtrClient` — transport-agnostic, embedding
   the §6 client logic the item describes: on connect a Serial Query
   carrying the remembered `(session_id, serial)` or a Reset Query
   (§8.1); Cache Response + Prefix PDUs + End-of-Data sequencing with
   the new serial and session ID; a session-ID change re-issues the
   Reset Query; `session_id`/`serial` persist across reconnects. Also
   the §7 version negotiation (downgrade to the first lower-version
   PDU before the first sync; Serial Notifies ignored during
   startup), §5.2 immediate Serial Queries on notify, §8.3
   Cache-Reset re-query, §12 error-report handling (No Data Available
   vs. fatal), and the §6 refresh/retry/expire timers. ROA deltas are
   *atomic per sync*: the step at End of Data carries the diff of the
   authoritative record sets, so the embedder never sees a
   half-applied database and duplicates (§5.6) / unknown withdrawals
   (§12 code 6) coalesce or no-op with a log. 19 unit tests cover
   each protocol rule.
3. ~~**Incremental ROA table.**~~ **Landed** as `lr_bgp::roa_store::RoaStore`
   — `RoaTable` stays immutable (rc API freeze) and `RoaStore` wraps
   it with two provenance layers: static (`[[roa]]` config, FFI
   entries) survives cache expiry and is replaced only by an explicit
   `replace_static` (config reload); rtr entries follow the RFC 8210
   lifecycle (`apply_rtr_deltas` per sync, `clear_rtr` on §6 data
   expiry or cache change). Every mutation rebuilds the merged entry
   set and swaps one `Arc<RoaTable>` under a `RwLock` — readers clone
   the Arc under a read lock and validate lock-free, so a reader never
   sees a half-applied sync: arc-swap semantics without the new
   dependency. Sort + dedup keeps the table deterministic. 11 unit
   tests including a concurrent-reader smoke test asserting snapshots
   are never partial.
4. ~~**Configuration surface.**~~ **Landed.** The `[bgp.rpki]` TOML
   table parses with the fail-closed posture (unknown keys are hard
   errors; `finalize_rpki` syntax-checks the cache address — port
   required, bracketed v6 literals accepted, intervals non-zero) and
   `--rpki-cache / --rpki-refresh / --rpki-retry / --rpki-expire` flag
   the quick labs. The configured intervals are the *initial* §6
   timers — a v1+ cache overrides them from every End-of-Data PDU.
   The daemon spawns one RTR thread per configured cache
   (`lr-cli::daemon_rpki`): connect/reconnect with the §6 retry
   backoff, framing-aware decode + `on_pdu`, `poll` driving refresh
   and expiry, atomic delta application into the shared `RoaStore`, §6
   expiry withdrawing the cache-sourced records, and a grep-friendly
   `rpki:` status line on the runtime API `status` command. Daemon e2e
   against the mock cache: `tests/interop/rtr_lr.sh` + 3 cargo tests
   (`crates/lr-cli/tests/daemon_rpki.rs`). Scope note: the thread is
   spawned by the BGP engine's `run_daemon` path — a
   multi-protocol-supervisor deployment carries `[bgp.rpki]` through
   the same engine config, but its shared runtime's `status` /
   `reload` surfaces do not render the rpki line yet (the standalone
   daemon is the reference deployment).
5. ~~**Hot reload.**~~ **Landed.** SIGHUP / API `reload` re-applies the
   fresh config's `[[roa]]` tables through `RoaStore::replace_static`
   (malformed reload-time ROAs keep the current entries — reload
   never half-applies) and re-points the RTR thread: an address change
   drops the transport, resets the session memory (the old cache's
   serial is meaningless, §8.2) and withdraws the old cache's records;
   a same-address reload forces a fresh incremental query. E2E:
   SIGHUP re-points a running daemon from cache A to cache B and grows
   the static table (API-verified `roas=4 (static=2 rtr=2)`).

**Reference implementations.** BIRD `proto/rpki/` (`rpki.c`,
`transport.c`, `packets.c`) is a complete RTR client; FRR
`bgpd/bgp_rpki.c` mirrors it; `rtrtr` is a pure-Rust RTR relay whose
PDU parser is a useful cross-check.

**Estimated size.** ~2000–3000 new lines (codec ~800, state machine
~600, config + integration ~400, tests ~400).

---

## D3 — Filter DSL feature expansion toward BIRD syntax parity

**Status:** ~~landed~~ — ~~D3.6~~, ~~D3.5~~, ~~D3.4~~, ~~D3.2~~,
~~D3.3~~, ~~D3.1~~ and ~~D3.7~~ are all in. Tracks `lr-policy`.

**Current gap.** `crates/lr-policy/src/filter/` implements a subset of
the BIRD filter syntax (if/then/else, let, arithmetic, comparison,
boolean, bitwise, prefix-set membership, route-attribute read/write,
accept/reject, case). Compared to BIRD `filter/config.Y`, the following
are missing:

### D3.1 — User-defined functions — ~~landed~~

AST node `FunctionDecl { name, params, return_type, body: Vec<Stmt> }`;
new `function` keyword; evaluator creates a new scope frame, binds
arguments to formal parameters, executes the body until `return`.
~400 LoC (AST + parser + evaluator + tests).

~~Landed: `function name(a, b) -> ret { ... }` declarations ahead of
the filter body (the optional `-> type` annotation is documentation
only — the DSL is dynamically typed). The evaluator binds arguments
positionally in a fresh scope frame and executes the body against the
caller's route (BIRD parity: functions are the primary mutation
tool). `return expr;` / bare `return;` produce the call value
(default `false` when the body falls off the end); `accept` /
`reject` inside a function terminate the whole filter (BIRD
`f_cmd` semantics) via a latched pending verdict. Runaway recursion
is bounded by `MAX_CALL_DEPTH = 64` (`CallDepthExceeded`), and
compile-time call validation rejects calls that name neither a
built-in nor a declared function (`UnknownFunctionCall`) plus
duplicate/shadowing declarations — a typo fails at startup instead of
silently falling through at route time. Top-level `return` in the
filter body is Fallthrough. Ten tests.~~

### D3.2 — Large Communities (RFC 8097) — ~~landed~~

`AttrType::LargeCommunities = 32` is a tag enum value only — no
`LargeCommunity` struct, codec, accessor, setter. Need to add
`LargeCommunity { global_admin: u32, local_data1: u32, local_data2: u32 }`
(12 bytes) + codec to `lr-bgp/src/path/communities.rs`;
`RouteFieldKind::BgpLargeCommunities` to `ast.rs`;
`FilterContext::bgp_large_communities()` /
`set_bgp_large_communities()` to the trait; DSL syntax
`bgp.large_communities += [ 64512:100:200 ]`. ~500 LoC.

~~Landed: `LargeCommunity` struct + 12-byte codec (byte-exact wire
test) in `lr-bgp`; `PathAttributes::large_communities()` /
`insert_large_community()` typed accessors; `lr_policy::bgp`
read/add/set helpers; DSL field `bgp.large_communities` with `+=`,
`=`, `.add/.delete/.filter` (exact matches) and `~` membership.
4-octet ASNs work natively (`4200000000:7:9`).~~

### D3.3 — Extended Communities (RFC 4360) — ~~landed~~

`ExtendedCommunity` already lives in `communities.rs:104-150` but is
not exposed to the DSL. Add `RouteFieldKind::BgpExtCommunities` and
`FilterContext::bgp_ext_communities()`; support Route Target (`rt`),
Site of Origin (`soo`) and friends. ~400 LoC.

~~Landed: BIRD tuple syntax in set literals — `(rt, <asn|ip>,
<local>)` / `(ro, ...)` / `(soo, ...)` — mapped to the canonical
transitive types (0x42 4-octet-AS specific, 0x41 IPv4 specific;
subtype 0x02 rt / 0x03 ro). DSL field `bgp.ext_communities` with
`+=`, `=`, `.add/.delete/.filter` (exact) and `~` membership.
Known limitation (pre-existing struct shape): the 2-octet-AS
administrator form (type 0x00, admin 2 bytes + assigned 4 bytes)
cannot round-trip through the `global: u32, local: u16` struct — the
DSL steers literals to the canonical 4-octet form instead; raw
attribute bytes from the wire still pass through the codec
opaquely.~~

### D3.4 — Set operations (`add`/`delete`/`filter`/`empty`/`count`) — ~~landed~~

BIRD's `delete(community_set, [asn:val])`,
`filter(community_set, [asn:val])`, `empty(community_set)`,
`count(community_set)`. Wire them into `eval_call`. AS_PATH needs
`delete` and `filter` too. ~300 LoC.

~~Landed with BIRD wildcard patterns on top: set literals accept
`asn:val`, `asn:*`, `*:val` and `*:*` community patterns (new
`Value::CommPattern`, the lexer breaks the number scan before `:*`);
`delete` / `filter` / `empty` / `count` work value-level (locals) via
`eval_call`, and `bgp.communities.delete/filter`,
`bgp.as_path.delete/filter` mutate the route through two new
`FilterContext` mutators (`set_bgp_communities`, `set_bgp_as_path` —
empty results drop the attribute, BIRD semantics). Assignment now
accepts `bgp.communities = delete(bgp.communities, [64512:*])` (the
canonical BIRD idiom) and `bgp.as_path = <sequence>`;
`bgp.communities += [asn:val]` keeps working (wildcards rejected) and
`~` matches wildcard patterns. Ten tests cover exact/wildcard delete,
filter, attribute drop, the assignment idiom, AS-path ops,
value-level ops and append rejections.~~

### D3.5 — `defined()` / `exists()` checks

BIRD's `defined(bgp.large_community)` checks whether an attribute is
present. The current DSL returns a default (0/false) for missing
attributes and cannot distinguish "absent" from "value 0". Add
`Expr::Defined(Box<Expr>)`. ~150 LoC.

### D3.6 — `proto` field string format — ~~landed~~

`eval.rs:492` returned `Value::Str(format!("{:?}", route.protocol))`,
producing the Rust Debug string (e.g. `"Bgp"`). BIRD uses lower-case
`"bgp"`. ~~Map to BIRD-style protocol names: `Bgp -> "bgp"`,
`Ospfv2 -> "ospf"`, `Ospfv3 -> "ospf3"`, `Babel -> "babel"`.
~20 LoC.~~ Landed in commit `ca8fe42` — new `Protocol::bird_name()`
method on `lr-core::rib::Protocol` plus four regression tests
covering the lowercase match, the negative Rust-Debug form, an
exhaustive loop over every `Protocol` variant, and a case statement
that routes on the OSPFv2 BIRD name.

### D3.7 — Bytecode compilation — ~~landed~~

The current DSL is a tree-walking interpreter. BIRD compiles to
`f_line` bytecode. For hot paths (every import/export) bytecode can
be 2–5× faster. Compile the AST to `Vec<Instruction>` (stack VM):
`Instruction` is `enum { Push(Value), LoadVar, LoadField, BinOp(
BinaryOp), Jump, Accept, Reject, … }`. ~800–1200 LoC (compiler + VM
+ tests).

~~Landed: `filter::bytecode` — a total AST→`Vec<Instr>` compiler
(short-circuit `&&`/`||` compile to jumps, `case` to a scrutinee temp
slot + chained pattern compares, `~` patterns lift their constant
items, `defined()` compiles to presence instructions) plus a stack VM
sharing the interpreter's scope stack, user-function machinery and
matching helpers, so semantics are identical by construction. Dynamic
shapes without a bytecode representation fall back to the tree walker
on that subtree, so the engines can never diverge. `CompiledFilter`
is built once at daemon start-up and the daemon's import/export
filter hooks now execute bytecode per route. The D3.7 bench gained
`vm_*` counterparts — measured parity on simple filters (23.8 ns vs
27.9 ns bare accept) and a small win on complex chains (222 ns vs
227 ns); the projected 2–5× needs typed stack slots and constant
folding, recorded as future work. An equivalence test pins 27 filter
sources × 4 routes for verdict + attribute-state equality.~~

**Total estimated size.** ~2500–3000 new lines; land in small commits.

---

## D4 — Daemon surface for library-level cross-protocol features

**Status:** landed — ~~D4.1 (`[[redistribute]]`)~~, ~~D4.2
(`[[aggregate]]`)~~, ~~D4.3 (`[damping]`)~~, ~~D4.4 (FFI)~~ and
~~D4.5 (interop scripts)~~ are all in. Tracks `lr-cli::daemon_config` +
`lr-cli::daemon` + `lr-ffi`.

**Current gap.** None — direction closed. ~~The FFI surface for the three
daemon-wired features~~ (D4.4) ~~and the interop scripts against
BIRD/FRR~~ (D4.5) ~~remain~~ both landed.

1. **Redistribution.** `RedistributionPipe` in
   `lr-router/src/redistribution.rs` (227 LoC) supports BGP↔OSPF,
   BGP↔Babel, Static→BGP, Connected→BGP, with 7 in-process tests.
   ~~But the daemon has no `[[redistribute]]` TOML table, no
   `--redistribute` CLI flag, no FFI entry.~~ The TOML table
   landed (D4.1); the CLI flag and FFI entry remain open.
2. **Aggregation.** `RouterInstance::add_aggregate(prefix)`
   implements RFC 4271 §9.2.2.2 (zero AS_PATH + ATOMIC_AGGREGATE +
   AGGREGATOR; withdraw when all specifics disappear). 5 in-process
   tests pass. ~~But the daemon has no `[[aggregate]]` table, no CLI
   flag, no FFI.~~ The TOML table landed (D4.2); the CLI flag and
   FFI entry remain open.
3. **Damping.** `lr-damping` (283 LoC) implements the RFC 2439
   figure-of-merit algorithm with full config + RFC 7196 warning.
   But `grep` shows no crate depends on `lr-damping` — it is dead
   code. `STATUS.md` incorrectly marks it ✅.

**Proposed work.**

1. **`[[redistribute]]` TOML table.** ~~Proposed.~~ Landed:
   ```toml
   [[redistribute]]
   source = "ospf"
   target = "bgp"
   metric = 100
   tag = 65000
   allow = ["10.0.0.0/8"]
   ```
   `RedistributeSpec` in `daemon_config.rs` with the same fail-closed
   posture as every other protocol table (unknown keys are hard
   errors). `finalize_redistribution` validates the protocol
   vocabulary, rejects targets the router does not implement (`bgp` |
   `ospf` | `ospf3` only), rejects sources with no daemon injection
   surface (`static` / `connected` — an inert pipe would silently
   advertise capability the daemon lacks) and cross-checks both ends
   against the configured protocol set **and** `[ospf] version`, so a
   pipe into a non-running engine fails at start-up instead of
   sitting dormant. Duplicate `(source, target)` pairs are rejected;
   same-protocol pipes stay allowed where the router supports them
   (BGP→BGP re-origination, OSPF→OSPF via `ospf_redistribute`).
   `apply_cross_protocol_config` installs the pipes once per process
   (supervisor after router creation, or the standalone BGP engine;
   embedded engines skip so pipes are never double-installed) and the
   start-up banner lists every pipe. Metric maps to
   `MetricPolicy::Fixed`, `allow` maps to the pipe's prefix
   allow-list. 12 config unit tests plus a daemon e2e
   (`tests/daemon_redistribute.rs`) asserting through the router's
   own `redistribute: <prefix> -> BGP` log events that an allow-list
   gates exactly the covered prefix.
2. **`[[aggregate]]` TOML table.** ~~Proposed.~~ Landed:
   ```toml
   [[aggregate]]
   prefix = "203.0.113.0/24"
   ```
   `AggregateSpec` + `finalize_aggregates` (prefix required, parse
   checked, no duplicates). `summary_only` is deliberately **not**
   accepted — the router does not implement specific suppression yet,
   and an ignored key would lie to the operator; it becomes available
   the moment the library grows the knob. Wiring shares the D4.1
   install path and the banner. The e2e chain (A–B–C daemons) proves
   the aggregate reaches a downstream peer — which exposed a real
   router bug: `recompute_aggregates` bypassed `export_selection`, so
   an aggregate originating after the session-up full sync never
   reached Adj-RIB-Out. Fixed with a regression test
   (`aggregate_originated_after_session_up_reaches_the_peer`).
3. **`[damping]` TOML table + import-hook wiring.** ~~Landed (commit
   pending).~~
   ```toml
   [damping]
   enabled = true
   half_life = 15
   reuse = 750
   suppress = 2000
   max_suppress = 4
   ```
   ~~Build a `DampingTable` at start-up and install it as an `ImportHook`
   so every route is checked against figure-of-merit before entering
   Adj-RIB-In. **D4.3 should land first** — wiring up existing dead
   code is the highest-leverage piece in this direction.~~ Landed:
   `[damping] enabled = true` installs a
   `lr_policy::hooks::DampingImportHook` on the import chain; the
   hook drops routes whose prefix has crossed the suppress threshold
   and tracks re-announcements via `DampingTable::on_announce`. A
   separate daemon thread (`lr-damping-decay`) calls
   `DampingTable::decay_all` every `decay_interval_s` so suppressed
   prefixes re-emerge as FoM decays below the reuse threshold. The
   `ImportHook` trait gained an `on_withdraw` default no-op method
   so the damping hook can also track withdrawals (router
   `withdraw_from_session` notifies the chain). The TOML table
   surfaces all eight `DampingConfig` tunables verbatim — operators
   familiar with RFC 2439 §4.7's parameter names can dial them
   directly. Off by default (RFC 7196 §3).
4. **FFI surface.** ~~`lr_router_add_redistribution_pipe()`,
   `lr_router_add_aggregate()`, `lr_router_set_damping_config()`, etc.
   Sync Go / Python / C++ bindings.~~ Landed as `crates/lr-ffi/src/policy.rs`:
   `lr_router_add_redistribution_pipe` (source/target as `LR_PROTO_*`
   ids, metric policy as `LR_METRIC_*`, optional tag + allow-list),
   `lr_router_add_aggregate` / `lr_router_remove_aggregate`,
   `lr_router_set_damping` (installs the RFC 2439 import hook and
   returns a shared `lr_damping_t` handle) plus `lr_damping_decay` /
   `lr_damping_destroy`. C constants ship in the cbindgen header
   (`after_includes` preamble); the C++ RAII wrapper gains
   `add_redistribution_pipe` / `add_aggregate` / `remove_aggregate` /
   `set_damping` + a `Damping` unique_ptr; Go gains `AddRedistributionPipe`
   / `AddAggregate` / `RemoveAggregate` / `SetDamping` / `(*Damping).Decay`
   with finalizers; Python gains the same surface with protocol/metric
   constants re-exported. The C, C++, Go and Python harnesses/test
   suites exercise the new entries in CI. FFI tests (5) pin round
   trips + the argument-validation matrix.
5. **Interop tests.** Landed: `redistribute_bird.sh` (BIRD 2 speaks
   both ends of a BGP↔OSPF pipe over a veth pair — the lab that
   flushed out the Router-LSA V/E/B bit and the protocol-direct
   ORIGIN/AS_PATH export bugs), `aggregate_bird.sh` (BIRD originates
   two covering specifics, lr aggregates, BIRD verifies
   ATOMIC_AGGREGATE + AGGREGATOR + AS_PATH on the wire and the
   retraction after a SIGHUP route swap — the lab that caught the
   AGGREGATOR flags bug) and `damping_frr.sh` (FRR bgpd drives
   withdraw flaps into lr's `[damping]` table — three flaps
   suppress, the decay ticker reactivates below reuse, a post-reuse
   flap re-installs — the lab that caught the epoch-vs-monotonic
   decay time base). All three run in the CI interop job.

**Estimated size.** ~800–1200 new lines (TOML ~300, daemon wiring
~200, FFI ~200, tests ~300).

---

## D5 — FFI expansion across protocols and policy

**Status:** partial — ~~D5.4 (BGP message encoders)~~, ~~D5.5
(event polling)~~, ~~D5.6 (route withdraw)~~ and ~~D5.7 (IPv6
origination)~~ are in; D5.1 (OSPF/Babel/LDP session management), D5.2
(Filter DSL via FFI) and D5.3 (policy objects via FFI) remain. Tracks
`lr-ffi` + bindings.

**Current gap.** `crates/lr-ffi/` exposes 60+ `extern "C"` functions
covering BGP session lifecycle + Layer-1 codecs + Layer-3 router
lifecycle + the D5.4–D5.7 slices. Still unreachable: OSPF, Babel,
LDP, BMP, MRT, BFD session management; Filter DSL and policy engine.
BGP UPDATE/OPEN/NOTIFICATION encoders, event polling, route
withdraw and IPv6 origination ~~are~~ are in.

**Proposed work.**

1. **OSPF / Babel / LDP session management.**
   `lr_router_add_ospf_session()`, `lr_router_add_ospfv3_session()`,
   `lr_router_add_babel_session()`, `lr_router_add_ldp_session()`.
2. **Filter DSL via FFI.** `lr_filter_compile(name, body) ->
   lr_filter_t`, `lr_filter_evaluate(filter, route) ->
   lr_filter_result_t`, `lr_filter_free(filter)`. Requires a C-callback
   variant of the `FilterContext` trait (`lr_filter_context_t` + a
   function-pointer table).
3. **Policy objects via FFI.** `lr_route_map_new() ->
   lr_route_map_t`, `lr_route_map_add_entry(map, matches, sets,
   verdict)`, `lr_prefix_list_new() -> lr_prefix_list_t`,
   `lr_prefix_list_add(list, prefix, ge, le, permit)`.
4. **BGP message encoding.** ~~`lr_bgp_encode_open()`,
   `lr_bgp_encode_update()`, `lr_bgp_encode_notification()`.~~
   Landed as `lr_bgp_encode_open` (version 4 + the RFC 6793
   four-octet-AS capability, AS_TRANS above 16 bits; rejects illegal
   hold times and unrepresentable AS/wire-width combinations),
   `lr_bgp_encode_notification` (code + subcode + optional data) and
   `lr_bgp_encode_update_withdraw_v4` /
   `lr_bgp_encode_update_announce_v4` (ORIGIN + AS_PATH + NEXT_HOP
   + the legacy IPv4 NLRI; AS_SEQUENCE in wire order, 2- or 4-octet
   path encoding). 8 Rust tests pin the wire forms and the
   rejection matrix; the C/C++/Go/Python harnesses exercise the
   same surface.
5. **Event polling.** ~~`lr_router_poll_events(router, out_events) ->
   i32` — polls `RouterEvent::RouteInstalled` / `PeerUp` / `PeerDown`
   and serializes them to a C struct array.~~ Landed: `lr_event_t`
   (kind/session/prefix/path-id/count/limit/pct/action + 128-byte
   NUL-terminated text) with `lr_router_poll_events`; the
   `RouterInstance::requeue_events` trait hook pushes events back to
   the front of the queue so a bounded poll never loses an event;
   `SendBytes` (drain-output data plane) and `TimerFired` (internal)
   are consumed silently.
6. **Route withdraw.** ~~`lr_router_withdraw_v4(router, prefix,
   prefix_len)`, `lr_router_withdraw_v6(router, prefix_v6, prefix_len)`.~~
   Landed — both, backed by the `unoriginate` return-value widening
   (bool: was a locally originated route removed). 0 = withdrawn,
   1 = not locally originated (idempotent no-op, FRR/BIRD `no
   network` semantics), negative = error.
7. **IPv6 origination.** ~~`lr_router_originate_v6(router, prefix_v6,
   prefix_len)` (currently only `lr_router_originate_v4` and a
   labeled variant exist).~~ Landed.
8. **cbindgen header + Go / Python / C++ binding sync.**

**Estimated size.** ~1500–2000 new lines (FFI ~800, Go ~400, Python
~300, C++ ~200, tests ~300).

---

## D6 — Fuzzing + property tests + performance benchmarks

**Status:** ~~landed~~ (commit pending). Tracks workspace + CI.

**Current gap.** The project has no fuzz targets (no `fuzz/` directory,
no `cargo-fuzz` dependency), no property tests (no `proptest` /
`quickcheck`), no benchmarks (no `benches/`, no `criterion`). Every
wire codec (`BgpCodec`, `OspfCodec`, `BabelCodec`, `LdpCodec`,
`BfdPacket`, `BmpMessage`, `MrtRecord`) parses untrusted network
bytes and is a natural fuzz target.

**Landed.**

* **Property tests** — `crates/lr-policy/tests/proptest.rs` (9
  properties, ~250 LoC) covering prefix-lattice invariants
  (reflexivity / antisymmetry / transitivity of
  `Prefix::contains_prefix`), `Prefix::network` idempotence and
  containment, `PrefixList::evaluate` first-match semantics, and
  two filter-DSL parser robustness properties (never panics on
  arbitrary input, pure / reproducible compilation). The
  property tests discovered and fixed a real bug in
  `Prefix::network` IPv6 partial-byte handling — see the
  `network_v6_preserves_partial_byte_bits` regression test in
  `crates/lr-core/src/addr.rs`.
* **RFC conformance vectors** — `crates/lr-bgp/tests/rfc_vectors.rs`
  (15 vectors, ~440 LoC) pinning byte-exact wire forms from
  RFC 4271 (header / OPEN / UPDATE / KEEPALIVE / NOTIFICATION),
  RFC 4486 (Cease / Administrative Shutdown), RFC 5492
  (capability TLV encoding) and RFC 6793 (4-byte AS capability
  via AS_TRANS).
* **Criterion benchmarks** — four bench harnesses pinning the
  hot paths ROADMAP-v3 D8.4 / D3.7 / D15 will later optimise:
  `crates/lr-bgp/benches/bgp_decode.rs` (OPEN / KEEPALIVE /
  UPDATE decode throughput), `crates/lr-bgp/benches/roa_validate.rs`
  (1k / 10k / 100k entries, the linear-scan target for the
  future Patricia trie), `crates/lr-policy/benches/filter_eval.rs`
  (simple / if-local-pref / complex chain, the target for the
  future bytecode VM), `crates/lr-rib/benches/rib_select.rs`
  (100 / 1k / 10k routes, the target for sharded RIB).
* **cargo-fuzz targets** — `fuzz/` standalone workspace with
  three targets covering the highest-risk input surfaces:
  `bgp_decode` (BgpCodec wire path), `filter_parser` (filter DSL
  config string), `roa_validate` (RPKI-RTR future input path).
  Each is ~20 LoC, asserts the security contract (never panic /
  abort / UB on arbitrary input), and ships with a hand-picked
  seed corpus under `fuzz/seeds/<target>/` that bootstraps
  coverage from a fresh checkout.
* **CI integration** — the nightly workflow gained a `fuzz` job
  (5 min per target, non-blocking, uploads crash artifacts) and
  a `bench-smoke` job (workspace criterion run with reduced
  sample size, uploads reports as artifacts). Property tests
  and RFC vectors run inside the existing `cargo test` step on
  every PR — no separate CI surface needed.

**Original gap (kept as audit trail).**

1. **cargo-fuzz targets.**
   ```
   fuzz/fuzz_targets/
   ├── bgp_decode.rs      # fuzz BgpCodec::decode_slice
   ├── ospf_decode.rs     # fuzz OspfCodec::decode_slice
   ├── babel_decode.rs    # fuzz BabelCodec::decode_slice
   ├── ldp_decode.rs      # fuzz LdpCodec::decode
   ├── bfd_decode.rs      # fuzz BfdPacket::decode
   ├── bmp_decode.rs      # fuzz BmpMessage::decode
   ├── mrt_decode.rs      # fuzz MrtRecord::decode
   ├── filter_parser.rs   # fuzz lr_policy::filter::compile
   └── roa_validate.rs    # fuzz RoaTable::validate
   ```
   Each target is ~20–30 LoC. Add a `cargo fuzz run` step (5 min /
   target) to `nightly.yml`.
2. **proptest strategies.** Prefix-set matching (random prefix +
   prefix-set, check `prefix_set_matches` correctness), AS-path
   filter patterns, glob patterns, TOML config fragments (parser must
   never panic). `crates/lr-policy/tests/proptest.rs` ~200 LoC +
   `proptest = "1"` dev-dependency.
3. **criterion benchmarks.**
   ```
   benches/
   ├── bgp_decode.rs   # BgpCodec::decode_slice throughput (MB/s)
   ├── ospf_decode.rs  # OspfCodec::decode_slice
   ├── roa_validate.rs # RoaTable::validate (10k / 100k / 1M entries)
   ├── filter_eval.rs  # filter::evaluate (simple vs complex body)
   └── rib_select.rs   # Loc-RIB best-path selection (100 / 1k / 10k routes)
   ```
   ~50–80 LoC per bench. Add a `cargo bench` CI step; alert on >10 %
   regression.
4. **RFC test-vector conformance tests.** Extract example packets from
   RFCs (RFC 4271 Appendix A BGP messages, RFC 8966 §4.4 Babel
   packets) and assert the decoded structure matches the RFC text.

**Estimated size.** ~1000–1500 new lines (fuzz ~250, proptest ~200,
benches ~350, RFC vectors ~200, CI ~100).

---

## D7 — CI/CD supply-chain hardening

**Status:** ~~landed~~ (commit pending). Tracks `.github/` + repo root.
The supply-chain `cargo audit` + `cargo deny` job runs nightly in
`.github/workflows/nightly.yml`; `deny.toml` is the source of truth
for advisories / licenses / bans / sources; `.github/dependabot.yml`
opens weekly Cargo + GitHub Actions bumps. Contributor governance
files (`CONTRIBUTING.md`, `SECURITY.md`, `CODE_OF_CONDUCT.md`,
`CHANGELOG.md`) live at the repo root.

**Landed.** SBOM generation (cyclonedx), artifact signing (cosign)
and CodeQL/Semgrep SAST are not yet wired — these touch
`release.yml` more invasively and will land in a follow-up.

**Original gap (kept as audit trail).** CI has 11 jobs covering fmt,
clippy, test, interop, cross-build, MSRV, coverage, Miri — the happy
path is well covered. But supply-chain security is empty: no
`cargo-audit`, no `cargo-deny`, no Dependabot, no SBOM, no artifact
signing, no SAST (CodeQL/Semgrep).

**Proposed work.**

1. **`cargo-audit` job.** Install `cargo-audit`; run `cargo audit`
   against the RustSec advisory database.
2. **`cargo-deny` config + job.** Add `deny.toml` with advisory,
   license, ban, source sections. Add a CI job that runs
   `cargo deny check`.
3. **Dependabot config.** `.github/dependabot.yml` for weekly Cargo
   updates.
4. **SBOM generation.** Add a CI step that runs `cyclonedx` to emit a
   CycloneDX SBOM and uploads it as a release artifact.
5. **Artifact signing.** Wire `sigstore/cosign-installer@v3` to sign
   release archives.
6. **CodeQL / Semgrep SAST.** `github/codeql-action/init@v3` with
   `languages: rust`.
7. **Contributor governance files.** `CONTRIBUTING.md` (PR checklist,
   commit message format, code style), `SECURITY.md` (vulnerability
   reporting, 90-day embargo policy), `CHANGELOG.md` (version history
   from git log), `CODE_OF_CONDUCT.md`.

**Estimated size.** ~300–500 lines of config + docs.

---

## D8 — Performance: RIB sharding + async I/O

**Status:** not started. Tracks `lr-router` + `lr-cli::daemon`.

**Current gap.** `DefaultRouter` is wrapped in
`Arc<Mutex<DefaultRouter>>` (`daemon.rs:2332, 2380, 3204`). Every BGP
peer thread, API socket thread, BFD thread, BMP thread and ticker
thread contends on the same lock. No `RwLock` to separate read and
write paths, no per-AFI RIB sharding, no async I/O (no tokio/mio) —
the daemon uses `set_nonblocking(true) + thread::sleep(10ms)`
polling.

**Proposed work.**

1. **`RwLock` instead of `Mutex`.** Loc-RIB access moves to `RwLock`:
   reads (RIB dump, peer export) take the read lock; writes (import,
   reselect) take the write lock. Concurrency goes from 1 to N.
2. **Per-AFI RIB sharding.** Split Loc-RIB by AFI (IPv4 / IPv6 /
   labeled) into independent `RwLock<LocRib>`s. Further sharding by
   prefix first byte (16 buckets) is optional.
3. **`mio` or `tokio` async I/O.** Replace the
   thread-per-socket + `set_nonblocking + sleep` model with a single
   `mio` event loop. BGP TCP, Babel UDP, OSPF raw, API socket share
   the loop. Eliminates the 10 ms latency.
4. **`RoaTable` radix-tree index.** `RoaTable::validate` is currently
   O(n) linear scan (`roa.rs:21-25`). Convert to a Patricia trie for
   O(prefix_len) lookup.
5. **Filter DSL bytecode.** Already covered by D3.7.
6. **Performance documentation.** Add a "Performance
   characteristics" section to `ARCHITECTURE.md` covering the thread
   model, lock strategy, expected throughput, scalability ceiling.

**Estimated size.** Large refactor: RwLock + sharding ~1000, async
I/O migration ~2000, radix tree ~500, benchmarks ~350. Stage it:
radix tree + RwLock first (low risk), async I/O last (high risk).

---

## D9 — Documentation: architecture deep-dive + contributor guide

**Status:** not started. Tracks `docs/`.

**Current gap.** Existing docs target operators and embedders
(`README.md`, `tutorial.md`, `API.md`, `lr-cli.md`, `RUNBOOK.md`,
`PARITY.md`, `INTEROP.md`, 13 example files). Contributor-facing
docs are thin: no `CONTRIBUTING.md`, no Filter DSL architecture
write-up, no internal structure document for
`lr-router/src/instance.rs` (a 11 158-LoC single file), no thread
model document, no formal EBNF for the Filter DSL.

**Proposed work.**

1. **`docs/ARCHITECTURE.md` expansion.** Filter DSL chapter (AST
   structure, Pratt parser flow, tree-walking evaluator design,
   `FilterContext` trait intent, comparison to BIRD `f_line`).
   `instance.rs` internal structure chapter (Loc-RIB data
   structures, reselect path, export hook ordering, redistribution
   tracking, `redistributed_bgp` BTreeMap design). Thread model
   chapter (global Mutex design, thread-per-peer, lock contention
   analysis, scalability ceiling). Performance chapter (expected
   throughput, bottleneck analysis, optimisation directions).
2. **`docs/filter_dsl_grammar.md`.** Formal EBNF for the Filter DSL.
3. **`CONTRIBUTING.md`.** PR checklist (fmt / clippy / test green,
   `-D warnings` clean, every new feature has tests + docs), commit
   message format (`type(scope): summary`), Rust style guide,
   testing strategy (unit + interop + RFC test vectors).
4. **`SECURITY.md`.** Vulnerability reporting flow (email to
   security@tes286.top), coordinated disclosure (90-day embargo),
   affected version range, PGP public key.
5. **`CHANGELOG.md`.** Version history from `git log`, organised by
   version, marking breaking changes and new features.
6. **`docs/ffi_design.md`.** FFI design: panic barrier contract
   (`catch_unwind` so panics never cross the C ABI), `lr_bytes_t`
   ownership model (caller frees), cbindgen pipeline (`build.rs` →
   `include/lr_ffi.h`), why OSPF/Babel/LDP are not yet exposed.

**Estimated size.** ~1500–2000 lines of docs.

---

## D10 — BGP extension protocol backfill

**Status:** partial. Tracks `lr-bgp`.

**Current gap.** BGP core coverage is strong (25 extensions), but the
following RFCs are unimplemented:

### D10.1 — RFC 8326 (Graceful Session Shutdown) — ~~landed~~

The `GRACEFUL_SHUTDOWN` community constant was previously named
`PLANNED_SHUTDOWN` (the pre-RFC-8326 draft name) and the export
direction did not honour it. Landed: `Community::GRACEFUL_SHUTDOWN`
is added as the canonical alias at the same wire value
(`0xFFFF:0000`); `CommunityKind::GracefulShutdown` is added to the
classification enum; the export hook
`lr_policy::hooks::GracefulShutdownExportHook` zeroes LOCAL_PREF on
any route carrying the community while preserving the community
itself (RFC 8326 §3.1: "the GRACEFUL_SHUTDOWN community ... SHOULD
be retained"). The hook is destination-agnostic and idempotent; the
daemon installs it always-on for BGP sessions. Six regression tests
in `lr-policy/src/hooks.rs` plus the community classification test
in `lr-bgp/src/path/communities.rs` cover the new behaviour.

A future follow-up will add the receive-side hook (treat routes
carrying `GRACEFUL_SHUTDOWN` as least-preferred during best-path
selection) and a per-peer `[bgp] graceful_shutdown = false` knob
for embedders that want to disable the sender side. Tracked under
D10 follow-up.

### D10.2 — RFC 5666 (Egress Peer Engineering)

Marked `partial (TBD)`. BGP-LU variant that uses BGP next-hop to
steer traffic to a specific egress peer.

### D10.3 — RFC 7752 + RFC 9552 (BGP-LS)

ROADMAP Phase 3 item 3, post-1.0. BGP Link-State — SDN controllers use
it to collect topology. New MP-BGP SAFI (BGP-LS = 71). TLV codecs for
Node Descriptor, Link Descriptor, Prefix Descriptor + SRv6
extensions. Tracked separately as D11.

### D10.4 — RFC 9256 + RFC 9430 (SR Policy)

ROADMAP Phase 3 item 4, post-1.0. BGP SR Policy for SR-TE. New BGP
NLRI type and path attribute.

### D10.5 — RFC 8097 (Large Communities)

Already covered by D3.2.

### D10.6 — RFC 8212 interop tests

Currently only tested in-process (`daemon_rfc8212.rs`). Needs
end-to-end interop scripts against BIRD / FRR.

**Estimated size.** Varies: D10.1 ~200, D10.5 ~500, D10.3 ~2000,
D10.4 ~1500. Land by priority.

---

## D11 — BGP-LS (RFC 7752) + SRv6 BGP-LS extensions (RFC 9552)

**Status:** not started. Tracks `lr-bgp` + `lr-ospf` + `lr-router`.
Post-1.0 per ROADMAP Phase 3.

**Current gap.** ROADMAP Phase 3 item 3 explicitly post-1.0. BGP-LS
is the standard protocol for SDN controllers to obtain IGP
topology. lr already has an OSPF LSDB (Router-LSA / Network-LSA /
Extended-Prefix-LSA / Extended-Link-LSA) and an SRv6 data plane
(`lr-srv6`), but no BGP-LS export path.

**Proposed work.**

1. **BGP-LS NLRI codec.** Add `BgpLsNlri` to `lr-bgp/src/nlri.rs`:
   Node NLRI, Link NLRI, Prefix NLRI. Each carries Node Descriptor
   TLVs + Link/Prefix Descriptor TLVs.
2. **BGP-LS Attribute codec.** Add `BgpLsAttribute` to
   `lr-bgp/src/path/`: IGP Metric TLV, TE Metric TLV, Admin Group
   TLV, SR Adj-SID TLV, SRv6 End.X SID TLV, etc.
3. **OSPF → BGP-LS export.** New `lr-ospf/src/ls_to_bgp_ls.rs`:
   convert OSPF LSDB Router-LSA / Network-LSA / Extended-Link-LSA
   into BGP-LS Link NLRI; convert Extended-Prefix-LSA (with SR
   Prefix-SID) into BGP-LS Prefix NLRI.
4. **BGP-LS publication.** Add a `redistribute_ls` pipe to
   `lr-router` that incrementally publishes OSPF LSDB changes to
   BGP-LS peers.
5. **Interop tests.** GoBGP or FRR (both support BGP-LS).

**Estimated size.** ~2000–3000 new lines (NLRI ~600, attribute ~500,
OSPF→BGP-LS ~500, daemon wiring ~300, tests ~400).

---

## D12 — Container deployment + operational tooling

**Status:** not started. Tracks repo root + `lr-cli`.

**Current gap.** No Dockerfile, no published container image, no Helm
chart, no operational CLI tool (e.g. `lrctl`). Operators must build
from source or download binaries from GitHub Releases.

**Proposed work.**

1. **`lrctl` operational CLI.** Standalone CLI that connects to a
   running `lr-daemon` over the API socket and provides:
   `lrctl status`, `lrctl sessions list`,
   `lrctl routes show <prefix>`, `lrctl routes dump` (MRT export),
   `lrctl reload`, `lrctl shutdown`, `lrctl roa list`,
   `lrctl filter compile <body>`.
2. **Prometheus metrics exporter.** Add a `/metrics` HTTP endpoint
   to the daemon exposing session count, route count, UPDATE tx/rx
   counters, filter-eval latency histograms.

**Estimated size.** ~1000–1500 new lines (`lrctl` ~500, metrics ~400,
Dockerfile + Helm ~100).

---

## D13 — OSPF backfill: E-LSA (RFC 8362) + SRv6 End.X SIDs

**Status:** not started. Tracks `lr-ospf`.

**Current gap.** `docs/research/E-LSA-DESIGN.md` is a design document
only — no implementation yet. RFC 8362 is the OSPFv3 Extended LSA
that turns fixed-length LSA types into variable TLV structures,
allowing larger Router-ID / Link-ID spaces. SRv6 End.X SIDs
(RFC 9513 §8) need E-LSA to carry SIDs long enough.

**Proposed work.**

1. **E-LSA codec.** Add to `lr-ospf/src/lsa/v3.rs`:
   E-Router-LSA (0xC0), E-Network-LSA (0xC1),
   E-Inter-Area-Prefix-LSA (0xC2), E-Inter-Area-Router-LSA (0xC3),
   E-AS-External-LSA (0xC4), E-Type-7-LSA (0xC5).
2. **E-LSA LSDB.** Extend the existing LSDB to hold both legacy and
   Extended LSAs; SPF prefers E-LSA when the `E-bit` is set in
   Options.
3. **SRv6 End.X SID carriage.** Add an SRv6 End.X SID sub-TLV to
   E-Link-LSA: 16-byte IPv6 SID + behavior + 4-byte SID Structure
   (`block_len`/`node_len`/`function_len`/`argument_len`).
4. **Interop tests.** FRR `ospf6d` supports E-LSA + SRv6.

**Estimated size.** ~1500–2000 new lines (E-LSA codec ~600, LSDB
changes ~300, SPF adaptation ~200, End.X SID ~200, tests ~300).

---

## D14 — Config compatibility: native BIRD / FRR config loading

**Status:** partial. Tracks `lr-cli::compat`.

**Current gap.** `crates/lr-cli/src/compat.rs` already detects and
translates BIRD/FRR configs (`detect_dialect` + `load_config_text`),
but coverage is limited. BIRD `filter` / `function` / `define` /
`protocol` syntax is incomplete; FRR `route-map` / `access-list` /
`prefix-list` syntax is incomplete.

**Proposed work.**

1. **BIRD filter → lr filter DSL.** Translate BIRD `filter { ... }`
   blocks to lr `[[filter]]` body strings. BIRD and lr DSL are close
   (both C-like), but BIRD uses `and/or/not` while lr uses
   `&&/||/!`; `~` is identical.
2. **BIRD `protocol babel` → `[[babel.interface]]`.**
3. **FRR `route-map` → `[[route-map]]`.**
   `match ip address prefix-list NAME` → `match_prefix = "NAME"`;
   `set local-preference N` → `set_local_pref = N`.
4. **FRR `bgp neighbor` → `[[peer]]`.**
5. **Conversion test suite.** Maintain a set of BIRD/FRR configs +
   expected lr TOML outputs as regression tests.

**Estimated size.** ~1000–1500 new lines (translator ~600, tests
~400, docs ~200).

---

## D15 — Multi-threaded RIB + lock-free event bus

**Status:** not started. Tracks `lr-router` + `lr-cli::daemon`.

**Current gap.** All routing operations serialise through a single
`Arc<Mutex<DefaultRouter>>`. For a full BGP table (800k+ routes), lock
contention is the bottleneck.

**Proposed work.**

1. **Per-AFI RIB sharding.** `LocRib` internally splits by AFI into
   `IPv4Rib`, `IPv6Rib`, `LabeledV4Rib`, `LabeledV6Rib`, each holding
   its own `RwLock`. Different AFI import / export run in parallel.
2. **Lock-free event bus.** Replace
   `Arc<Mutex<Vec<RouterEvent>>>` polling with a `crossbeam` channel.
   Each session thread pushes events non-blockingly; the API socket
   thread reads from the channel.
3. **Sharded Adj-RIB-In.** Per-peer Adj-RIB-In uses `DashMap` instead
   of `BTreeMap` for concurrent read/write.
4. **Benchmarks.** At 100k / 500k / 1M routes, compare single-lock vs
   sharded import throughput.

**Estimated size.** ~2000–3000 new lines (RIB refactor ~800, event
bus ~400, sharded RIB ~500, benchmarks ~350, tests ~300). High-risk
refactor — needs extensive regression tests.

---

## Tracking

| Direction | Status                | Owner | Notes                                    |
| --------- | --------------------- | ----- | ---------------------------------------- |
| D1        | not started           | —     | Babel multi-session + per-iface params   |
| D2        | landed                | —     | RPKI-RTR client: codec + state machine + RoaStore + `[bgp.rpki]` daemon thread + hot reload |
| D3        | partial (D3.6 landed) | —     | Filter DSL parity — proto fix landed; rest pending |
| D4        | landed                | —     | Daemon surface — damping + redistribution + aggregate wired; FFI + interop scripts landed (D4.1–D4.5) |
| D5        | partial (D5.4–D5.7 landed) | —     | FFI expansion — encoders + event polling + withdraw + v6 originate in; OSPF/Babel/LDP sessions, filter DSL, policy objects pending |
| D6        | landed                | —     | proptest + RFC vectors + criterion benches + cargo-fuzz targets; nightly `fuzz` and `bench-smoke` jobs wired |
| D7        | landed                | —     | Supply-chain: cargo-audit + cargo-deny + Dependabot + governance docs |
| D8        | not started           | —     | RwLock + per-AFI sharding + async I/O    |
| D9        | not started           | —     | Architecture + contributor docs         |
| D10       | partial (D10.1 landed) | —     | RFC 8326 sender-side hook landed; BGP-LS / SR Policy post-1.0 |
| D11       | not started (post-1.0)| —     | BGP-LS                                   |
| D12       | not started           | —     | `lrctl` + Prometheus exporter            |
| D13       | not started           | —     | OSPF E-LSA + SRv6 End.X                  |
| D14       | partial               | —     | BIRD / FRR config loader                 |
| D15       | not started           | —     | Multi-threaded RIB + lock-free event bus  |

Items flip to `~~struck through~~` here as they land, with a pointer
to the landing commit. `STATUS.md` remains the live capability
snapshot; this file is the forward plan.
