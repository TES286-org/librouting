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

### D3.5 — `defined()` / `exists()` checks — ~~landed~~

BIRD's `defined(bgp.large_community)` checks whether an attribute is
present. The current DSL returns a default (0/false) for missing
attributes and cannot distinguish "absent" from "value 0". Add
`Expr::Defined(Box<Expr>)`. ~150 LoC. Landed in commit `f0fb91b`.

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

**Status:** landed — ~~D5.4 (BGP message encoders)~~, ~~D5.5
(event polling)~~, ~~D5.6 (route withdraw)~~, ~~D5.7 (IPv6
origination)~~, ~~D5.1 (OSPF/OSPFv3/Babel session management)~~,
~~D5.3 (policy objects via FFI)~~ and ~~D5.2 (Filter DSL via FFI)~~
are all in. Tracks `lr-ffi` + bindings.

**Current gap.** None — direction closed. The FFI surface now spans
router + session lifecycle (BGP, OSPFv2, OSPFv3, Babel), Layer-1
codecs, policy objects (route handles, prefix-lists, route-maps,
resolver), the compiled Filter DSL with a C-callback context, ROA
stores, damping and redistribution. LDP session management stays
daemon-side (see the D5.1 audit trail); BMP/MRT/BFD remain
codec/polling level by design.

**Proposed work.**

1. ~~**OSPF / Babel / LDP session management.**~~
   `lr_router_add_ospf_session()`, `lr_router_add_ospfv3_session()`,
   `lr_router_add_babel_session()`, `lr_router_add_ldp_session()`.
   Landed (commit `5500ae7`): `lr_router_add_ospf_session` /
   `lr_router_add_ospfv3_session` (BIRD/FRR `type ptp` defaults: MTU
   1500, point-to-point, Normal area), `lr_router_add_ospf_session_ext`
   (area kind incl. RFC 2328 §3.6 stub / RFC 3101 NSSA and their
   totally- variants with the injected-default metric, MTU §10.6,
   network type §9.1, the §10.4 segment identities) and
   `lr_router_add_babel_session` (one interface session keyed by the
   local address, RFC 8966 §4.2.1; v4 in the first four bytes).
   Unknown version/area-kind/network-type ids fail closed; the
   router's own rejections (router-id mismatch, area kind conflict,
   backbone stub) surface through last-error with rc -3. 6 Rust
   tests + the C/C++/Go/Python harness sections. **LDP deliberately
   absent:** `lr-router` has no LDP session kind — the `LdpEngine`
   is daemon-driven (UDP/TCP 646 discovery + transport), so an
   `lr_router_add_ldp_session` would advertise a capability the
   library does not have. If the engine ever grows a router-level
   LDP session model, the entry lands then.
2. ~~**Filter DSL via FFI.**~~ `lr_filter_compile(name, body) ->
   lr_filter_t`, `lr_filter_evaluate(filter, route) ->
   lr_filter_result_t`, `lr_filter_free(filter)`. Requires a C-callback
   variant of the `FilterContext` trait (`lr_filter_context_t` + a
   function-pointer table).
   Landed (commit `3929549`): `lr_filter_compile` parses a BIRD-like
   body and compiles it to the D3.7 stack VM (the daemon's hot path;
   parse errors carry the 1-indexed line/column diagnostic through
   last-error), `lr_filter_evaluate` runs it against an `lr_route_t`
   (D5.3) reporting ACCEPT / REJECT / FALLTHROUGH with the optional
   `reject with` reason as an owned NUL-terminated `lr_bytes_t`, and
   runtime evaluation errors surface as Fallthrough exactly like the
   daemon. `lr_filter_context_t` is the C callback variant of
   `FilterContext`: 19 optional function pointers + `user_data`
   where every NULL field keeps the built-in route-backed context
   (the same `lr_policy::bgp` accessors the daemon uses — mutations
   land in the route handle's real path attributes) and a non-NULL
   field overrides exactly that aspect (canonical example:
   `roa.state` from a live RFC 6811 store, the built-in default being
   not-found). 7 Rust tests; the C harness exercises the C callback
   override, the C++ RAII `Filter` throws on parse errors with the
   filter name, and Go/Python get Compile/evaluate with the built-in
   context.
3. ~~**Policy objects via FFI.**~~ `lr_route_map_new() ->
   lr_route_map_t`, `lr_route_map_add_entry(map, matches, sets,
   verdict)`, `lr_prefix_list_new() -> lr_prefix_list_t`,
   `lr_prefix_list_add(list, prefix, ge, le, permit)`.
   Landed (commit `78c227c`): `lr_route_new_v4`/`_v6` + `lr_route_free`
   box a real `lr_core::rib::Route`; `lr_route_set/get` cover next
   hop, LOCAL_PREF, MED, ORIGIN, the canonical 4-byte AS_PATH,
   standard/large/extended communities, metric and tag (probe-then-
   read array getters, a short buffer is -3). `lr_prefix_list_*`
   mirror FRR ge/le first-match semantics. `lr_route_map_*` run the
   FRR flow over tagged `lr_match_t`/`lr_set_t` arrays with
   CONTINUE/PERMIT/DENY verdicts; matches resolve through
   `lr_resolver_*` — a `PolicySet`-backed registry of prefix-lists,
   FRR-dialect AS-path access-lists and RFC 1997 community lists
   (each with its own id namespace). A NULL resolver fails every
   list-backed match (fail-closed). `lr-policy::PrefixList` gained
   `Clone` (non-breaking) for registration. 6 Rust tests + harness
   sections in all four binding languages.
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

### D6 follow-up — DSL performance baseline (GitHub #19 P0) — ~~landed~~

The DSL perf optimisation plan in GitHub #19 phasing has its P0
landed. The original three bench shapes (`simple_accept`,
`if_local_pref`, `complex_chain`) were too small to justify the
later P4 prefix-trie work, so P0 grows the bench set first — the
precondition every later phase measures its win against.

**What landed.**

* **`crates/lr-policy/benches/filter_eval.rs` grew from three
  shapes to six.** The original three are preserved verbatim so
  historical regression baselines keep working; three new shapes
  exercise the realistic-load surface the #19 process guardrails
  call out:
  * `large_prefix_set` — `if net ~ [ 100 entries ] then accept;
    reject;`. 100 host routes (`10.x.y.1/32`) so the linear
    `MatchRhs::Set` scan cannot short-circuit on a longest-prefix
    optimisation; measured on `hit_last` (route matches the last
    entry — full scan accept) and `miss` (route matches no entry —
    full scan reject).
  * `large_community_set` — `if bgp.communities ~ [ 10 entries ]
    then accept; reject;`. 10 entries is the upper bound of a
    typical tagging taxonomy; same `hit_last` / `miss` positions.
  * `user_functions` — a two-call chain (`classify` + `tag_customer`)
    that exercises the VM's call-dispatch overhead, the #19 P2
    slot-resolution lever.
  Every shape runs under both engines (tree-walk interpreter
  stays the semantic oracle; bytecode VM is the hot path the
  daemon runs per route after `daemon_policy::build_filters`
  precompiles every `[[filter]]` at startup).
* **`crates/lr-policy/benches/import_pipeline.rs` is the new
  daemon-level bench.** For each route it runs the import path
  the daemon actually runs — bytecode eval → Adj-RIB-In install
  → Loc-RIB install — at three scales (100 / 1 000 / 10 000
  routes) under two filter shapes (`trivial` and `realistic`).
  Lives in `lr-policy` (DSL eval is the dominant component) and
  pulls `lr-rib` as a dev-dependency (no cycle — `lr-rib` does
  not depend on `lr-policy`). The bench is shaped to outlive the
  #18 config-format migration: the filter body is a string
  literal, not a config fragment, so the bench can be reused
  unchanged after the TOML→DSL migration lands.
* **Baseline numbers** (criterion, `--quick`, this machine):
  * The VM is at parity with the interpreter on the original
    three shapes — `if_local_pref` is where the VM still loses
    (+19 %), confirming the P1 instruction-encoding hypothesis.
  * `large_prefix_set` VM is 22–35 % *slower* than the tree walk
    — the linear `MatchRhs::Set` scan that P4 prefix-trie targets.
  * `large_community_set` VM is 43–45 % faster than the tree walk.
  * `user_functions` VM is 64 % faster than the tree walk — the
    P2 slot-resolution lever; call dispatch is the tree walker's
    worst case.
  * Import-pipeline: ~570 ns / route at 100 routes, ~1.18 µs /
    route at 10 000 routes (BTreeMap log factor) under the
    realistic filter.
  These numbers are the P1–P5 deltas will be measured against.
* **Engine equivalence is load-bearing.** A new test
  `vm_matches_interpreter_on_bench_shapes` in
  `crates/lr-policy/src/filter/eval.rs` pins the VM ==
  interpreter contract on the bench-sized shapes (100-entry
  prefix set, 10-entry community set, two-call user-function
  chain) across a six-route matrix. The 27×4 equivalence table
  is preserved unchanged; the new test is additive.

**What is NOT in P0.** Every later phase of #19 — P1
(instruction encoding), P2 (slot resolution), P3 (attribute
fast paths), P4 (prefix trie), P5 (folding/peephole) — is
explicitly out of scope for this PR; each will land as its own
PR with a bench delta attached, per the #19 process
guardrails ("Profile before each step. Every optimization
lands with a bench delta attached, not an argument").

### D6 follow-up — P4 prefix trie (GitHub #19 P4) — ~~landed~~

The `MatchRhs::Set` linear scan was the biggest actionable win
the P0 baseline surfaced: `vm_large_prefix_set` was 22–35 %
slower than the tree-walk interpreter because every route paid
an O(n) scan over every `MatchItem::PrefixSet` entry. P4
replaces that scan with a path-compressed Patricia trie — the
same structure `lr-bgp::roa_trie` (D8.4) uses for RFC 6811 ROA
validation — turning the per-route cost into an O(prefix_len)
covering walk.

**What landed.**

* **`PrefixSetTrie`** in `crates/lr-policy/src/filter/bytecode.rs`:
  a flat-arena Patricia trie with two family roots (IPv4 / IPv6),
  high-aligned `u128` key encoding, and a covering walk that
  stops at the first divergence. Each trie node holds the
  `(ge, le)` constraints of every pattern whose prefix
  terminates at that node; the walk checks each covering node's
  patterns in turn. The structure mirrors `RoaTrie` — the same
  `encode_prefix` / `high_bits_mask` / `bit_at` helpers, the same
  `insert` branch/factor/ancestor/descend cases — but stores
  `(ge, le)` pairs instead of `RoaEntry` indices. The trie is
  `#[derive(Debug, Clone, Default, PartialEq, Eq)]` so it fits
  the existing `MatchRhs` derive chain.
* **`MatchRhs::PrefixSet { trie, others }`** — a new variant
  alongside the existing `MatchRhs::Set(Vec<MatchItem>)`. The
  compiler (`compile_match_rhs`) builds the trie when the set
  contains at least one `MatchItem::PrefixSet`, filters the
  non-prefix items (values, dynamic exprs) into `others`, and
  emits `MatchRhs::PrefixSet`. Pure value / dynamic sets keep
  `MatchRhs::Set` — no regression for sets the trie cannot help.
  Single-prefix patterns (`net ~ 10.0.0.0/8`) now also go
  through the trie (a one-node trie is cheaper than the
  `MatchRhs::Set` one-element `Vec`).
* **`run_match`** in `crates/lr-policy/src/filter/eval.rs`
  handles the new variant: if the LHS is a `Value::Prefix`, it
  tries the trie first (O(prefix_len) walk); then linear-scans
  `others` for non-prefix items. The `MatchRhs::Set` path is
  unchanged — the existing 27×4 equivalence table plus the
  bench-shapes table run verbatim against both variants.
* **`prefix_trie_matches_linear_scan_across_set_shapes`** — a
  new differential test in `crates/lr-policy/src/filter/eval.rs`
  pins the trie == linear-scan contract across five set shapes
  (plain /32s, `ge`/`le` ranges, IPv6, mixed prefix + value,
  overlapping ranges) and a hit/miss/longer/shorter/wrong-family
  query matrix. The test is additive to the existing 27×4 and
  bench-shapes equivalence tables.

**Bench delta (criterion, `--baseline p0`).** The win is exactly
where the #19 comment predicted:

| shape | P0 | P4 | delta |
|---|---|---|---|
| `vm_large_prefix_set/hit_last` | 291 ns | 87.6 ns | **−70 % (3.3×)** |
| `vm_large_prefix_set/miss` | 191 ns | 58.3 ns | **−69 % (3.3×)** |
| `import_pipeline/trivial/10000` | 11.86 ms | 10.63 ms | **−10.4 %** |
| `import_pipeline/realistic/10000` | 12.93 ms | 11.79 ms | **−8.8 %** |
| `import_pipeline/trivial/1000` | 807 µs | 759 µs | **−5.9 %** |
| `import_pipeline/realistic/1000` | 919 µs | 871 µs | **−5.3 %** |

The import-pipeline `realistic` filter exercises the trie on
every route (`net ~ [ 10.0.0.0/8{16,24} ]`), so the per-route
saving compounds at scale. The `trivial` filter (`accept;`) does
not use the trie, but the 10 000-route case still improves by
−10.4 % — a code-layout effect from the new `PrefixSetTrie`
module that shifts the hot loop into a better-aligned cache
line. No shape regresses; the other VM shapes (`simple_accept`,
`if_local_pref`, `complex_chain`, `large_community_set`,
`user_functions`) are all within ±1 % of P0 (noise).

**What is NOT in P4.** P1 (instruction encoding), P2 (slot
resolution), P3 (attribute fast paths), P5
(folding/peephole). P1 was attempted and reverted — see the
note below.

**P1 finding (reverted).** The compact instruction encoding
(`Instr { op, a: u32, b: u32 }` = 12 bytes, down from the 64-byte
fat enum) was implemented and A/B-benched against the P0
baseline. The result: a 2–10 % regression across every VM
shape, with `vm_simple_accept` worst at +9.8 %. The side-table
indirection (one `Vec` lookup per dispatch for `Op::Push` /
`Op::LoadVar` / `Op::LoadField` / `Op::Match` / ...) exceeded the
cache-density win on the bench sizes — the existing benches
exercise filters with ≤ 10 instructions, where the whole
instruction stream fits in 1–2 cache lines either way. The
issue comment's prediction ("5–8× denser fetch, biggest effect
on branchy shapes") did not materialise because the indirection
cost dominates at these sizes. P1 was reverted; the
instruction-encoding work is deferred until a bench with a
1000+ instruction filter exists to exercise the cache-density
win, or until P2/P5 work makes the compact encoding pay for
itself (slot resolution eliminates the `LoadVar`/`StoreVar`
string lookups; constant folding eliminates redundant `Push`/
`Bin` chains). The process guardrail ("every optimisation lands
with a bench delta attached, not an argument") was honoured:
the P1 regression was measured, not argued, and the change was
not landed.

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

**Status:** partial — ~~D8.1 (RwLock read/write split)~~,
~~D8.4 (RoaTable Patricia trie)~~, ~~D8.6 (performance docs)~~.
Tracks `lr-router` + `lr-cli::daemon`.

**Current gap.** ~~`DefaultRouter` is wrapped in
`Arc<Mutex<DefaultRouter>>` (`daemon.rs:2332, 2380, 3204`). Every BGP
peer thread, API socket thread, BFD thread, BMP thread and ticker
thread contends on the same lock.~~ D8.1 landed: the shared handle is
`Arc<RwLock<DefaultRouter>>` — read-only call sites (API dumps,
status, session summaries, Babel RTT probes) take the read lock and
run concurrently while writes (import, reselect, reload) take the
write lock; the borrow checker polices the split because
`DefaultRouter` has no interior mutability (commit `e5102d5`, plus
`f236b1c` which adds the `Sync` supertraits the read path requires on
`lr-policy` hooks). Still open: per-AFI RIB sharding and async I/O —
the daemon remains `set_nonblocking(true) + thread::sleep(10ms)`
polling (D8.3).

**Proposed work.**

1. **`RwLock` instead of `Mutex`.** Loc-RIB access moves to `RwLock`:
   reads (RIB dump, peer export) take the read lock; writes (import,
   reselect) take the write lock. Concurrency goes from 1 to N.
   ~~Landed in commit `e5102d5` — `Arc<RwLock<DefaultRouter>>` with
   81 call sites classified (16 read / 65 write), the borrow checker
   enforcing the read-only set; hooks gained `Sync` supertraits in
   `f236b1c`.~~
2. **Per-AFI RIB sharding.** Split Loc-RIB by AFI (IPv4 / IPv6 /
   labeled) into independent `RwLock<LocRib>`s. Further sharding by
   prefix first byte (16 buckets) is optional.
3. **`mio` or `tokio` async I/O.** Replace the
   thread-per-socket + `set_nonblocking + sleep` model with a single
   `mio` event loop. BGP TCP, Babel UDP, OSPF raw, API socket share
   the loop. Eliminates the 10 ms latency.
4. **`RoaTable` radix-tree index.** ~~`RoaTable::validate` is
   currently O(n) linear scan (`roa.rs:21-25`). Convert to a Patricia
   trie for O(prefix_len) lookup.~~ Landed in commit `296fb38` —
   path-compressed trie over high-aligned u128 keys, one root per
   family; entries keep their canonical sorted Vec and equality;
   criterion shows the query cost flat across 1k/10k/100k tables
   (~5 ns uncovered, 75–182 ns covered) with differential proptests
   against the reference scan.
5. **Filter DSL bytecode.** Already covered by D3.7.
6. **Performance documentation.** Add a "Performance
   characteristics" section to `ARCHITECTURE.md` covering the thread
   model, lock strategy, expected throughput, scalability ceiling.
   ~~Landed: `docs/ARCHITECTURE.md` documents ROA lookup costs, the
   filter bytecode hot path, the daemon thread model, the RwLock
   read/write split and the scalability ceiling.~~

**Estimated size.** Large refactor: RwLock + sharding ~1000, async
I/O migration ~2000, radix tree ~500, benchmarks ~350. Stage it:
radix tree + RwLock first (low risk), async I/O last (high risk).

---

## D9 — Documentation: architecture deep-dive + contributor guide

**Status:** partial — ~~D9.2 (filter DSL EBNF grammar)~~ and
~~D9.6 (`docs/ffi_design.md`)~~ landed; D9.1, D9.3–D9.5 still open.
Tracks `docs/`.

**Current gap.** Existing docs target operators and embedders
(`README.md`, `tutorial.md`, `API.md`, `lr-cli.md`, `RUNBOOK.md`,
`PARITY.md`, `INTEROP.md`, 13 example files). Contributor-facing
docs are thin: no Filter DSL architecture write-up, no internal
structure document for `lr-router/src/instance.rs` (a 11 158-LoC
single file), no thread model document. ~~No formal EBNF for the
Filter DSL.~~ D9.2 closed that gap. ~~No FFI design document.~~
D9.6 closed that gap.

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
2. ~~**`docs/filter_dsl_grammar.md`.** Formal EBNF for the Filter DSL.~~
   Landed. ISO/IEC 14977 EBNF derived directly from the lexer +
   Pratt parser source: lexical structure (identifiers, keywords,
   literals, operators), the full statement + expression grammar
   (every production traced to its parser function), the operator
   precedence table (mirrors `BinaryOp::precedence`), the route
   field reference (settable vs `+=`-only vs read-only), the
   `MAX_EXPR_DEPTH` / `MAX_CALL_DEPTH` limits, a worked-examples
   section, and a BIRD-comparison table. The companion
   `crates/lr-policy/tests/grammar_corpus.rs` pins every example
   (positive + negative) — a doc/source drift fails CI rather than
   shipping. The grammar captured two real divergences from the
  in-tree BIRD example doc (`docs/examples/filter_dsl_roa.md`):
   the function return-type annotation uses `=>` (not BIRD's `->`),
   and AS-path `~` is flat set-membership, not BIRD regex (the `_`
   wildcard token is parsed but does not yet carry meaning inside
   `~` patterns). Both are now documented as current behaviour
   with a follow-up pointer.
3. **`CONTRIBUTING.md`.** PR checklist (fmt / clippy / test green,
   `-D warnings` clean, every new feature has tests + docs), commit
   message format (`type(scope): summary`), Rust style guide,
   testing strategy (unit + interop + RFC test vectors).
4. **`SECURITY.md`.** Vulnerability reporting flow (email to
   security@tes286.top), coordinated disclosure (90-day embargo),
   affected version range, PGP public key.
5. **`CHANGELOG.md`.** Version history from `git log`, organised by
   version, marking breaking changes and new features.
6. ~~**`docs/ffi_design.md`.** FFI design: panic barrier contract
   (`catch_unwind` so panics never cross the C ABI), `lr_bytes_t`
   ownership model (caller frees), cbindgen pipeline (`build.rs` →
   `include/lr_ffi.h`), why OSPF/Babel/LDP are not yet exposed.~~
   Landed. The document covers: the panic-barrier contract (every
   `extern "C"` entry point wrapped in `guarded` / `catch_unwind`;
   the release-profile `panic = "abort"` caveat that makes the
   barrier a dev-build-only safety net); the `lr_bytes_t` ownership
   model (`from_vec` / `reclaim_into_vec` / `lr_bytes_free`; the
   four embedder rules); the cbindgen pipeline (`build.rs` config,
   the `LrError` exclusion for pre-C23 portability, the `#define`
   constants in `after_includes`); the opaque-handle pattern
   (`#[repr(C)]` + `_private: [u8; 0]`; the handle zoo table; the
   destroy contract); the non-reentrant lock hazard (every
   `lr_router_*` holds the `Mutex` for the whole call; hooks must
   not re-enter); what is NOT exposed and why (OSPF/Babel engines
   are daemon-driven, LDP has no router session model, BMP/MRT/BFD
   are codec-only, the exchange-plane prototype is daemon-only);
   the error model (the `LR_ERR_*` code table, the thread-local
   last-error string, the `lr_abi_version()` check); and the
   three-level testing strategy (Rust unit tests, C / C++ harness,
   Go / Python bindings). Cross-references every section to the
   source file that implements it.

**Estimated size.** ~1500–2000 lines of docs (D9.2 lands ~680 of
those; D9.6 lands ~310; the rest is split across D9.1 + D9.3–D9.5).

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

### D10.6 — RFC 8212 interop tests — ~~landed~~

~~Currently only tested in-process (`daemon_rfc8212.rs`). Needs
end-to-end interop scripts against BIRD / FRR.~~ Landed:
`tests/interop/rfc8212_bird.sh` and `tests/interop/rfc8212_frr.sh`
verify lr-daemon's default RFC 8212 eBGP policy against real BIRD 2
and FRR bgpd. Each script runs two phases: Phase 1 (default mode,
no explicit policy) asserts the session reaches Established but
BIRD/FRR does NOT learn lr-daemon's route and lr-daemon does NOT
install BIRD/FRR's route — the RFC 8212 import-deny and export-deny
are both exercised; Phase 2 (explicit permit-all route-maps)
asserts the route flows both directions, confirming the
RFC-intended escape hatch. The startup warnings (`no export
route-map; announcing nothing (RFC 8212)` and `no import
route-map; discarding received routes (RFC 8212)`) are pinned as
Phase 1 assertions. Both scripts are wired into the CI interop job.
The scripts gracefully SKIP when `bird`/`birdc` or `bgpd` are not
on `$PATH` (same pattern as every other interop script), so they
run in CI (where `bird2` + `frr` are installed) and skip locally
without a reference daemon.

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

**Status:** partial — ~~D12.1 (`lrctl` operational CLI)~~,
~~D12.2 (Prometheus `/metrics` endpoint)~~ and
~~D12.3 (container deployment)~~ landed; per-session UPDATE
counters / filter-eval latency histograms still open. Tracks repo
root + `lr-cli`.

**Current gap.** ~~No Dockerfile, no published container image, no
Helm chart, no operational CLI tool (e.g. `lrctl`).~~ D12.1 closed
the operational CLI gap. ~~No metrics endpoint.~~ D12.2 closed
the Prometheus gap. ~~No container image.~~ D12.3 closed the
container gap (a Helm chart remains open — it conventionally lives
in its own repository so it can version independently of the image).
Per-session UPDATE tx/rx counters and filter-eval latency
histograms remain open — they require per-session counters the
daemon does not track today (a follow-up commit under D12).

**Proposed work.**

1. ~~**`lrctl` operational CLI.** Standalone CLI that connects to a
   running `lr-daemon` over the API socket and provides:
   `lrctl status`, `lrctl sessions list`,
   `lrctl routes show <prefix>`, `lrctl routes dump` (MRT export),
   `lrctl reload`, `lrctl shutdown`, `lrctl roa list`,
   `lrctl filter compile <body>`.~~
   Landed as `crates/lr-cli/src/lrctl.rs` — a third `lr-cli` binary
   alongside `lr` and `lr-daemon`. Mirrors their hand-rolled
   `env::args()` style (no clap dependency). The daemon-proxy surface
   (`status` / `sessions [list]` / `routes show [prefix]` /
   `routes dump <path>` / `reload` / `shutdown`) covers the runtime
   API verbatim; `routes show <prefix>` does client-side prefix
   filtering (exact match on the leading token) since the daemon API
   has no parameterised `routes <prefix>` command today. The
   client-side surface (`filter compile <body>`) reuses
   `lr-policy::filter::compile` directly so operators can validate a
   filter body before deploying — the same parser path the daemon
   runs at startup. The default socket path matches
   `templates/daemon.toml` (`/run/lr-daemon.api`); `--socket PATH`
   overrides on any subcommand. Non-Unix targets refuse with a clear
   error (the runtime API requires Unix domain sockets). The release
   workflow stages `lrctl` alongside `lr` and `lr-daemon` in every
   platform archive. 10 e2e tests in `crates/lr-cli/tests/lrctl.rs`
   pin every subcommand including transport-failure and
   argument-error paths. `roa list` deferred — the daemon's
   `Runtime` struct does not carry a `RoaStore` reference today, so
   exposing it requires threading the store through `spawn_api` (a
   follow-up commit).
2. ~~**Prometheus metrics exporter.** Add a `/metrics` HTTP endpoint
   to the daemon exposing session count, route count, UPDATE tx/rx
   counters, filter-eval latency histograms.~~
   Landed as `crates/lr-cli/src/metrics.rs` — a hand-rolled HTTP/1.0
   responder (no `hyper` / `tokio` dependency) bound to a TCP
   address. Opt-in via `--metrics-addr ADDR` /
   `[bgp] metrics_addr = "…"` (default off, like `api_socket`); a
   bind failure is fatal (same stance as `spawn_api`). The thread
   model mirrors `api.rs`: one thread polls a
   `set_nonblocking(true)` `TcpListener` with a 100 ms sleep, each
   accepted connection served on its own short-lived thread so a
   slow client cannot hold the endpoint hostage. The router lock is
   held only for the duration of a single `session_summaries()` +
   `rib_len()` read, never for the network write. The exposition
   covers `lr_info` (gauge=1 with `version`/`local_as`/`router_id`
   labels, for join queries), `lr_uptime_seconds`,
   `lr_sessions_total{kind,state}`, `lr_established_sessions{kind}`
   (with explicit-zero for kinds that have sessions but none
   established, so an alert joining on `kind` does not see a missing
   series), `lr_adj_rib_in_entries{kind}`, `lr_rib_entries`, and
   `lr_roa_entries` (omitted entirely when no ROA store is
   configured — a missing metric is more honest than a misleading
   zero). `GET /` returns a one-line pointer to `/metrics`,
   `GET /nonexistent` returns `404`, non-GET methods return `404`.
   The `Runtime` struct gained an optional
   `roa_len: Option<Arc<dyn Fn() -> usize + Send + Sync>>` field so
   the BGP daemon (which always builds a `RoaStore`) can expose the
   live count without holding a lock; OSPF/Babel/LDP/BMP/multi pass
   `None`. 7 e2e tests in `crates/lr-cli/tests/daemon_metrics.rs`
   pin the exposition shape, the opt-in default, the 404 paths,
   non-GET rejection, scrape stability and bind-failure fatality.
   Filter-eval latency histograms and UPDATE tx/rx counters remain
   open — they require per-session counters the daemon does not
   track today (a follow-up commit under D12).
3. ~~**Container deployment.** Dockerfile + published container image
   + Helm chart.~~
   Landed as `Dockerfile` (multi-stage: `rust:1.88-slim-bookworm`
   builder + `debian:bookworm-slim` runtime) + `.dockerignore` +
   `docker/README.md` (deployment guide: quick start, production
   config-file mount, sidecar `lrctl`, image layout table, exposed
   ports, volumes, size target ~100 MB, what the image does NOT
   include) + `.github/workflows/docker.yml` (CI verification that
   builds the image on every push / PR / nightly, runs the three
   CLI binaries with `--help` / `version`, verifies
   `liblr_ffi.so` is loadable via `ldconfig -p`, reports image size).
   BuildKit mount caches (`--mount=type=cache`) on the cargo
   registry + target dir keep no-op rebuilds fast. The runtime
   stage ships the three CLI binaries (`lr`, `lr-daemon`, `lrctl`),
   `liblr_ffi.so`, the C / C++ headers, a non-root `lr` user,
   `EXPOSE 179/tcp` (BGP) + `9119/tcp` (metrics — matches the
   example address in `docs/RUNBOOK.md` and `templates/daemon.toml`),
   `VOLUME /etc/lr-daemon` (config mount) + `/run/lr-daemon` (API
   socket mount for the `lrctl` sidecar pattern), `ENTRYPOINT
   ["lr-daemon"]` with `CMD ["--help"]`. The image does NOT ship a
   default config (operators mount one or pass CLI flags) and does
   NOT push to a registry from CI (that is a release-event concern
   — the existing `release.yml` handles `v*` tag pushes and produces
   the GitHub Release archives; a future container-registry push
   would ride the same tag event). Helm chart deferred — a Helm
   chart conventionally lives in its own repository so it can
   version independently of the image; the Dockerfile here is the
   foundation a chart would reference.

**Estimated size.** ~1000–1500 new lines (`lrctl` ~500, metrics ~400,
Dockerfile + Helm ~100). D12.1 landed ~870 lines; D12.2 landed ~880
lines (metrics.rs ~340, daemon_metrics.rs tests ~470, daemon +
daemon_config + templates + docs ~70); D12.3 landed ~390 lines
(Dockerfile ~180, .dockerignore ~70, docker/README.md ~140,
.github/workflows/docker.yml ~110 — the workflow counts against
the D12.3 total even though it is CI not image).

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

**Status:** partial — ~~D14.1 (BIRD filters)~~, ~~D14.2 (BIRD
babel)~~, ~~D14.3 (FRR route-maps)~~, ~~D14.4 (FRR neighbors)~~,
~~D14.5 (`!~` operator)~~, ~~D14.6 (`case` statements)~~.
Tracks `lr-cli::compat`.

**Current gap.** ~~`crates/lr-cli/src/compat.rs` already detects and
translates BIRD/FRR configs (`detect_dialect` + `load_config_text`),
but coverage is limited. BIRD `filter` / `function` / `define` /
`protocol` syntax is incomplete; FRR `route-map` / `access-list` /
`prefix-list` syntax is incomplete.~~ D14.1 landed: BIRD 2
`filter`/`function`/`define`/`roa table` blocks translate into the
lr filter DSL (fail-closed per filter — constructs without a
faithful mapping leave the filter unemitted and reported; the
operator mapping was verified against BIRD's own grammar/lexer,
correcting the assumption below: BIRD 2 has no `and/or/not` keywords,
and BIRD writes equality `=` / assignment `:=` where lr writes `==`
/ `=`); `import|export filter NAME` / `where EXPR` wire the filters
to peers, inline channel bodies now split into statements, and `roa
table` entries carry over as `[[roa]]` (commits `f1fc747` and
`2456f45`, including `protocol babel` → `[[babel.interface]]` with
the RFC 8966 §A.2 parameter mapping). ~~D14.5 + D14.6 landed: BIRD
`!~` (not-match) and `case` statements now translate faithfully
(commits `1b09aa7` + `6f39f15`). The `!~` operator gained a
`TokenKind::BangTilde` in the lr DSL lexer and a `BinaryOp::NotMatch`
mapping in the parser — the AST, evaluator and bytecode VM already
lowered it to `Match { negated: true }`, so the language-level
addition was the missing piece. The `case` translation is a
structural pre-pass (`rewrite_cases`) that walks the token stream
before the regular token-rewriting pass and converts BIRD's `:`
arm separator to lr's `=>`, `else:` to `default =>`, and wraps
non-block arm bodies in `{ … }` (lr DSL case arm bodies parse a
single statement). Range arms (`a .. b:`) remain unfaithful — lr
case arms match exact values only.~~ Still open: per-protocol route
attributes, and a maintained external conversion corpus (the in-tree
regression suite covers the mapping table).

**Proposed work.**

1. **BIRD filter → lr filter DSL.** Translate BIRD `filter { ... }`
   blocks to lr `[[filter]]` body strings. ~~BIRD and lr DSL are
   close (both C-like), but BIRD uses `and/or/not` while lr uses
   `&&/||/!`; `~` is identical.~~ Landed in commit `f1fc747` — the
   corrected mapping (verified against BIRD's `filter/config.Y` +
   `conf/cf-lex.l`): booleans are symbolic in both dialects; BIRD `=`
   becomes `==` and BIRD `:=` becomes `=`; attribute renames
   (`bgp_path` → `bgp.as_path`, …); `define` constants substitute
   textually; user functions embed with parameter types stripped;
   `roa_check` on a single table becomes `roa.state` comparisons;
   every emitted body must compile and reference only introduced
   variables (compile + AST-walk backstops).
2. **BIRD `protocol babel` → `[[babel.interface]]`.** Landed in
   commit `2456f45` — interface blocks and bare interface lines map
   the RFC 8966 §A.2 parameters (type/kind, rxcost, rtt
   cost/min/max with BIRD's time grammar, check link, extended next
   hop, port); protocol-level next hops backfill; the rest stays
   visible per statement.
3. **FRR `route-map` → `[[route-map]]`.**
   `match ip address prefix-list NAME` → `match_prefix = "NAME"`;
   `set local-preference N` → `set_local_pref = N`. (Pre-existing
   converter surface, W5.1.)
4. **FRR `bgp neighbor` → `[[peer]]`.** (Pre-existing converter
   surface, W5.1.)
5. **BIRD `!~` (not-match) → lr `!~`.** Landed in commits `1b09aa7`
   (lexer + parser) + `6f39f15` (translator). The lr DSL AST has
   carried `BinaryOp::NotMatch` since the parser was first written —
   the evaluator and bytecode VM already lowered it to
   `Match { negated: true }` — but the lexer never produced a `!~`
   token, so no source program could exercise the path. The fix adds
   `TokenKind::BangTilde` to the lexer's multi-char set (alongside
   `!=` / `==` / …) and maps it to `BinaryOp::NotMatch` in the
   parser. The translator's `!~` branch — which pushed an
   unfaithful note — is removed; the operator now passes through
   verbatim because BIRD and lr spell it identically.
6. **BIRD `case` → lr `case`.** Landed in commit `6f39f15`. A new
   structural pre-pass `rewrite_cases` walks the token stream before
   the regular token-rewriting pass and rewrites every BIRD
   `case … { … }` block into lr DSL syntax. The mapping was verified
   against BIRD's `filter/config.Y` §`switch_body` and `conf/cf-lex.l`
   (the `else:` ELSECOL token): arm separator `:` (at depth 1) →
   `=>`; `else :` → `default =>`; non-block arm bodies are wrapped
   in `{ … }` (lr DSL case arm bodies parse a single statement,
   which may be a `Block`); block arm bodies are left as-is; range
   arms (`a .. b:`) remain unfaithful. Nested cases are handled
   recursively. `case` is removed from `UNMAPPABLE_WORDS`.
7. **Conversion test suite.** Maintain a set of BIRD/FRR configs +
   expected lr TOML outputs as regression tests. Partially covered:
   the D14.1/D14.2/D14.5/D14.6 round-trip tests load every generated
   TOML through the real daemon config parser and finalize (compiling
   the filters); a larger external corpus remains open.

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
| D5        | landed                | —     | FFI expansion — encoders, event polling, withdraw, v6 originate, OSPFv2/v3/Babel sessions, policy objects (route handle + prefix-list + route-map + resolver) and the Filter DSL with a C-callback context all in; LDP sessions stay daemon-side (documented in the D5 audit trail) |
| D6        | landed                | —     | proptest + RFC vectors + criterion benches + cargo-fuzz targets; nightly `fuzz` and `bench-smoke` jobs wired; **GitHub #19 P0 landed** — `filter_eval` grows to 6 shapes (large prefix set / large community set / user functions) + new `import_pipeline` bench (DSL eval → Adj-RIB-In → Loc-RIB at 100/1k/10k scales) + equivalence test on the bench-sized shapes; **GitHub #19 P4 landed** — `PrefixSetTrie` (Patricia trie borrowing from `lr-bgp::roa_trie`) replaces the O(n) `MatchRhs::Set` prefix scan with O(prefix_len) covering walk; `vm_large_prefix_set` 3.3× faster (−70 %), import-pipeline −8.8 % to −10.4 % at 10 k routes; P1 (compact instruction encoding) attempted and reverted (2–10 % regression from side-table indirection, documented in the D6 follow-up) |
| D7        | landed                | —     | Supply-chain: cargo-audit + cargo-deny + Dependabot + governance docs |
| D8        | partial (D8.1 + D8.4 + D8.6 landed) | —     | RwLock read/write split + ROA Patricia trie + perf docs; per-AFI sharding (D8.2) and async I/O (D8.3) open |
| D9        | partial (D9.2 + D9.6 landed) | —     | Filter DSL formal EBNF grammar + corpus test + `docs/ffi_design.md` landed; ARCHITECTURE expansion, CONTRIBUTING/SECURITY/CHANGELOG refresh still open |
| D10       | partial (D10.1 + D10.6 landed) | —     | RFC 8326 sender-side hook + RFC 8212 BIRD/FRR interop scripts landed; BGP-LS / SR Policy post-1.0 |
| D11       | not started (post-1.0)| —     | BGP-LS                                   |
| D12       | partial (D12.1 + D12.2 + D12.3 landed) | —     | `lrctl` operational CLI + Prometheus `/metrics` endpoint + multi-stage Dockerfile + `.dockerignore` + `docker/README.md` + `.github/workflows/docker.yml` CI verification landed; Helm chart (separate repo) and per-session UPDATE counters / filter-eval histograms open |
| D13       | not started           | —     | OSPF E-LSA + SRv6 End.X                  |
| D14       | partial (D14.1–D14.6 landed) | —     | BIRD filters → lr DSL (fail-closed, verified against BIRD grammar) + babel interfaces + `!~` + `case`; FRR route-map/neighbor pre-existing; per-protocol attrs + external corpus open |
| D15       | not started           | —     | Multi-threaded RIB + lock-free event bus  |

Items flip to `~~struck through~~` here as they land, with a pointer
to the landing commit. `STATUS.md` remains the live capability
snapshot; this file is the forward plan.
