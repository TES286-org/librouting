# Project Status — Implemented vs. Missing

Honest gap analysis of librouting as of this revision. "Implemented"
means: code exists, is unit-tested, and (where marked) is exercised by
end-to-end or interop tests. "Partial" means the mechanism exists but a
documented subset is missing. "Missing" means not implemented.

Legend: ✅ implemented · 🟡 partial · ❌ missing · 🧪 E2E-verified
(in `cargo test`, the interop suite or the C/Go/Python harnesses)

## Layer 1 — core (`lr-core`)

| Capability | Status | Notes |
|-----------|:------:|-------|
| Prefix / IpAddr / Asn / RouterId types | ✅ | v4+v6, no-std compatible |
| Streaming codec primitives (ReadBuf/WriteBuf) | ✅ | |
| Generic FSM + timer framework | ✅ | |
| RIB data model (Route, RouteKey, Preference) | ✅ | administrative distances per protocol |
| Event model | ✅ | |

## Layer 2 — protocol crates

### BGP (`lr-bgp`)

| Capability | Status | Notes |
|-----------|:------:|-------|
| RFC 4271 FSM (6 states, timers, events) | ✅ 🧪 | incl. NOTIFICATION-as-fatal, session reset semantics |
| OPEN / KEEPALIVE / UPDATE / NOTIFICATION codec | ✅ 🧪 | interop-verified against BIRD 2 + FRR 10 |
| RFC 5492 capabilities | ✅ | |
| RFC 4760 MP-BGP (IPv4/IPv6 unicast NLRI) | ✅ | BIRD requires it — now advertised by default; FRR `bgp default ipv4-unicast` (W2.1) gates implicit IPv4 unicast |
| RFC 4893/6793 4-octet AS + dynamic negotiation | ✅ | downgrade to 2-byte when peer lacks the capability |
| RFC 4456 route reflection (ORIGINATOR_ID, CLUSTER_LIST) | ✅ | correct optional non-transitive flags |
| RFC 5065 confederations | ✅ | |
| RFC 7947 route server mode | ✅ | |
| RFC 9234 OTC / roles | ✅ | |
| RFC 4271 §6.8 connection collision detection | ✅ 🧪 | router-level resolver over sessions sharing a `SessionConfig::collision_group` (the group is the §6.8 "BGP Identifier known by means outside of the protocol"); sibling roles from `locally_initiated`; retains the connection initiated by the higher-BGP-Identifier speaker (FRR `bgp_collision_detect` parity, incl. examining OpenSent siblings), Established siblings always win, loser gets Cease / Connection Collision Resolution (RFC 4486 subcode 7) + teardown; equal BGP Identifiers are rejected by OPEN validation (FRR `BGP_NOTIFY_OPEN_BAD_BGP_ID` parity); daemon: bidirectional peers (`remote` + `address`) run both transports and converge to exactly one Established session; 5 router unit tests + 1 daemon e2e (`crates/lr-cli/tests/daemon_collision.rs`) |
| RFC 7911 Add-Path | ✅ 🧪 | capability negotiation (per-family send/receive), path-id NLRI framing (plain + MP), Adj-RIB-In keyed by path id, ranked N-path selection (`add_path_max_paths`), per-path export/withdrawal with rank-slot transmit ids, MRAI path sets, GR/LLGR per-path retention; two-daemon + full-stack e2e |
| RFC 5549 Extended Next-Hop | ✅ 🧪 | capability code 5 with `(NLRI AFI, NLRI SAFI, Nexthop AFI)` tuples in the RFC 5549 §4 / RFC 8950 §4 6-byte wire form (AFI:2, SAFI:2, NH-AFI:2 — byte-identical to BIRD 2.x and FRR, both of which OPEN-error non-multiples of 6); OPEN negotiation as the intersection of local + peer tuples (§4); 16-byte NEXT_HOP for IPv4 NLRI decoded as `V4OverV6`, MP_REACH `(AFI=1, 16B)` accepted; eBGP egress rewrites IPv4 NEXT_HOP to IPv6 when `(1,1,2)` is negotiated and `local_address` is IPv6; daemon `--extended-next-hop` / `--local-address-v6` / `--mp-family ipv6-unicast`; e2e coverage of all 8 dual-stack / MP-BGP / ENH / pure-v6 session modes + real BIRD interop (`tests/interop/bird_enh.sh`, unskipped) |
| RFC 2918 route refresh | ✅ | negotiated capability, outbound API, inbound re-advertisement through current export policy |
| RFC 7313 enhanced route refresh | ✅ | negotiated capability plus BoRR/EoRR demarcation around refreshed tables |
| RFC 4724 graceful restart | ✅ 🧪 | capability lists address families with F bits; stale-route retention, negotiated expiry purge, EoR-based resynchronization (BIRD-verified) |
| RFC 9494 LLGR | ✅ 🧪 | capability 71, per-family LLST, LLGR_STALE/NO_LLGR communities, least-preferred selection, egress gating, full retention lifecycle (BIRD-verified) |
| RFC 8326 Graceful Shutdown (sender) | ✅ 🧪 | `GRACEFUL_SHUTDOWN` community `0xFFFF:0000` honoured on export — LOCAL_PREF zeroed, community preserved; legacy `PLANNED_SHUTDOWN` alias at the same wire value; per-peer `[[peer]] graceful_shutdown = false` exempts a neighbor (e2e-verified) via `lr_policy::hooks::GracefulShutdownExportHook::with_exempt_sessions` |
| RFC 8326 Graceful Shutdown (receiver) | ✅ 🧪 | §4 best-path step — a tagged route is the least preferred for its prefix (`BestPathConfig::graceful_shutdown_least_preferred`, ahead of LOCAL_PREF so the eBGP pinning cannot mask it); §4.1 import hook lowers LOCAL_PREF to the RECOMMENDED 0 on tagged imports (`GracefulShutdownImportHook`); `[bgp] graceful_shutdown = false` opts out of all surfaces; e2e-verified |
| MRAI (Min. Route Advertisement Interval) | ✅ | configurable per-prefix batching (withdrawals immediate); defaults to 30 s eBGP / 5 s iBGP |
| MD5 / TCP-AO session authentication | ✅ 🧪 | RFC 2385 MD5 + RFC 5925 TCP-AO (hmac(sha1)/cmac(aes), ao_required) via `lr-osroute::tcp_auth`; kernel-signed SYNs, fail-closed arming; BIRD/FRR interop-verified |
| BGPsec | ❌ | out of scope for now |
| RFC 8277 BGP labelled unicast (BGP-LU) | ✅ 🧪 | `lr-mpls` (RFC 3032 label + label-stack codec, 4- and 3-octet wire forms) + `lr-bgp::path::labeled_nlri` (RFC 8277 §3 NLRI codec, MP_REACH/MP_UNREACH helpers); `lr-router::originate_labeled`; daemon `--labeled-network` / `labeled_networks` TOML + `--mp-family ipv4-labeled-unicast` / `ipv6-labeled-unicast`; daemon LSP mirror (W3-extra.3): Loc-RIB best routes program the kernel — tail pop for originated labels, head encap for received stacks; FFI + Go/Python bindings; 4 e2e tests + `tests/interop/labeled_unicast.sh` (two-daemon TCP, label=100 round-trip) + `tests/interop/mpls_lsp.sh` (kernel dataplane, ping through the LSP) |
| Best-path selection (RFC 4271 §9) | ✅ | incl. LOCAL_PREF, AS_PATH length, origin, MED, eBGP<iBGP, router-id tiebreak; LLGR_STALE routes least-preferred (RFC 9494 §4.4); `BestPathConfig::deterministic_router_id` exposed to daemon as FRR `bgp bestpath compare-routerid` (W2.2) |
| Route damping (`lr-damping`) | ✅ 🧪 | RFC 2439-style figure-of-merit; wired into the daemon as `DampingImportHook` (opt-in via `[damping] enabled = true`); `ImportHook::on_withdraw` notification feeds the unreachable-transition FoM increment; `lr-damping-decay` thread drives periodic `decay_all` (same monotonic-since-start time base as the router's `now_ms`) so suppressed prefixes re-emerge below the reuse threshold; FRR-verified (`tests/interop/damping_frr.sh`, ROADMAP-v3 D4.5: bgpd-driven flaps suppress at the threshold, decay reactivates, post-reuse flap re-installs) |
| BFD interaction (`lr-bfd`) | ✅ 🧪 | RFC 5880 §6.8 state machine + timing (peer detect-multiplier detection time, negotiated tx interval with jitter + 1s idle floor, Poll/Final parameter changes), §6.8.6 MUST-discard rules, Simple Password auth; `lr-osroute::bfd_transport` sockets (3784/4784, TTL 255, ephemeral source ports); daemon `--bfd` fast-fails BGP on BFD Down (BIRD-verified) |
| Policy: prefix-lists, community-lists, AS-path filters, route-maps | ✅ | `lr-policy` — all matchers evaluate real BGP path attributes (feature `bgp`, default): community lists (RFC 1997 first-match/implicit-deny), FRR-style AS-path patterns (`^ $ _`, substring parity incl. the bare-literal footgun), MED/prepend/add-community/set-tag set actions (`SetTag` writes the `Route.tag` field) |
| Filter DSL: `defined()` / `exists()` presence checks | ✅ | `lr-policy::filter` (ROADMAP-v3 D3.5) — parsed structurally so the argument stays unevaluated; distinguishes absent attributes from default values (BIRD `defined()` semantics); scope variables checked without `UndefinedVar`; the fallback probe evaluates on a route copy so presence checks never write through |
| Filter DSL: bytecode VM (compiled filters) | ✅ | `lr-policy::filter::bytecode` (ROADMAP-v3 D3.7) — total AST→instruction compiler + stack VM sharing the interpreter's scope/function state; equivalence table (27 sources × 4 routes) pins verdict + attribute-state equality; dynamic subtrees fall back to the tree walk so engines never diverge; daemon filter hooks precompile at start-up and execute bytecode per route; `vm_*` criterion benches track the hot path |
| Filter DSL: perf baseline + import-pipeline bench | ✅ | `crates/lr-policy/benches/` (GitHub #19 P0) — `filter_eval` covers seven shapes (3 original + `large_prefix_set` 100-entry / `large_community_set` 10-entry / `user_functions` two-call chain / `const_fold` peephole-exerciser) under both engines; `import_pipeline` measures the daemon per-UPDATE cost (bytecode eval → Adj-RIB-In install → Loc-RIB install) at 100 / 1 000 / 10 000 routes under `trivial` and `realistic` filters; equivalence pinned on the bench-sized shapes by `vm_matches_interpreter_on_bench_shapes` (additive to the 27×4 table) |
| Filter DSL: peephole optimisation pass | ✅ | `crates/lr-policy/src/filter/peephole.rs` (GitHub #19 P5) — three passes run inside `bytecode::compile`: constant propagation + literal folding (tracks `let` constants, folds `Push; Push; Bin` triples, `Push; Not/Neg` pairs, refuses to fold div-by-zero / overflow / bad-shift), dead-branch elimination (`Push(Bool(c)); JumpIfFalse/JumpIfTrue` → drop or `Jump`, only when the conditional is not a jump target — preserves `&&`/`||` short-circuit semantics), jump threading (`Jump(X)→Jump(Y)` chains). New `const_fold` bench shape: −25 % (1.34×) on the VM; existing shapes within ±2 % of P4 (noise). 14 unit tests pin golden output; 27×4 + bench-shapes + prefix-trie equivalence tables pass unchanged |
| Filter DSL: user-function call index resolution | ✅ | `crates/lr-policy/src/filter/bytecode.rs` (GitHub #19 P2) — `Instr::CallFn { idx, argc }` resolves user-function calls at compile time; `CompiledFilter.functions` is `Vec<CompiledFunction>` (indexed by `CallFn`) + `function_index: BTreeMap<String, usize>` (name → index); VM `CallFn` does direct Vec index, no BTreeMap lookup per call; `Call` now only handles built-ins; `vm_user_functions` −1.25 % (437 → 430 ns, p=0.05); variable slot resolution prototyped and reverted (frame/scope double-write regressed trivial benches); 2 new tests pin `CallFn` emission + interpreter equivalence |
| Filter DSL: attribute fast paths | ✅ | `crates/lr-core/src/attr.rs` + `crates/lr-policy/src/bgp.rs` (GitHub #19 P3) — `Attributes::get_u32_be`/`get_u8` read fixed-width integer attributes in place (no `Vec<u8>` clone); `lr_policy::bgp::local_pref`/`med`/new `origin` use the new methods; `DaemonFilterContext::bgp_origin` now reads ORIGIN from the route (previously hardcoded `Some(0)`); bench `BenchCtx` updated to match production; `vm_if_local_pref` −21 % (83.5 → 66.4 ns), `vm_complex_chain` −8 %, `vm_user_functions` −8 %, `import_pipeline/realistic/1000` −5.4 %; no API break, 2 new tests |
| Filter DSL: prefix-trie set matching | ✅ | `lr-policy::filter::bytecode::PrefixSetTrie` (GitHub #19 P4) — path-compressed Patricia trie (borrowing structure from `lr-bgp::roa_trie` D8.4) replaces the O(n) linear scan over `MatchRhs::Set` prefix items with an O(prefix_len) covering walk; `MatchRhs::PrefixSet { trie, others }` emitted when the set contains any `MatchItem::PrefixSet`; non-prefix items stay in `others` for linear scan; single-prefix patterns also go through the trie; `vm_large_prefix_set` 3.3× faster (291 → 87.6 ns hit_last, 191 → 58.3 ns miss); import-pipeline bench −8.8 % to −10.4 % at 10 k routes; `prefix_trie_matches_linear_scan_across_set_shapes` differential test pins trie == linear-scan across 5 set shapes and a hit/miss/longer/shorter/wrong-family query matrix |
| Filter DSL: user-defined functions | ✅ | `lr-policy::filter` (ROADMAP-v3 D3.1) — BIRD-style `function` declarations; positional binding in fresh scope frames; bodies mutate the caller's route (BIRD parity); `accept`/`reject` in a function terminate the whole filter; `MAX_CALL_DEPTH = 64` recursion bound; compile-time call validation (undeclared calls / duplicates / built-in shadowing fail at startup) |
| Filter DSL: large + extended communities | ✅ | `lr-policy::filter` + `lr-bgp` (ROADMAP-v3 D3.2/D3.3) — RFC 8097 12-byte codec with byte-exact wire test; `bgp.large_communities` (4-octet ASNs native) and `bgp.ext_communities` (BIRD `(rt, asn|ip, local)` tuples → canonical transitive 0x42/0x41) with `+=`, `=`, `.add/.delete/.filter`, `~` membership; pre-existing limitation: 2-octet-AS ext-community admin form not representable in the `ExtendedCommunity` struct |
| Filter DSL: BIRD set operations (`delete`/`filter`/`empty`/`count`) | ✅ | `lr-policy::filter` (ROADMAP-v3 D3.4) — wildcard community patterns (`asn:*`, `*:val`, `*:*`) in set literals; value-level ops on locals and route-level `bgp.communities.delete/filter` / `bgp.as_path.delete/filter` via new `FilterContext` mutators (empty results drop the attribute); `bgp.communities = delete(...)` assignment idiom; `~` matches wildcard patterns |
| Filter DSL: `!~` (not-match) operator | ✅ | `lr-policy::filter` (ROADMAP-v3 D14.5) — `TokenKind::BangTilde` in the lexer (2-char op alongside `!=`/`==`/…); `BinaryOp::NotMatch` in the parser sharing Match precedence (4); the AST, evaluator and bytecode VM already lowered it to `Match { negated: true }`; BIRD `!~` passes through the compat translator verbatim |
| Filter DSL: `case` statement | ✅ | `lr-policy::filter` — `case expr { pat => stmt; default => stmt; }` with comma-separated patterns, parenthesised expressions, `default` arm, single-stmt or `{ … }` block arm bodies; BIRD `case` (D14.6) translates via `rewrite_cases` structural pre-pass (`:`→`=>`, `else:`→`default =>`, non-block arm bodies wrapped in `{ … }`); range arms (`a .. b:`) fail-closed |
| Import/export/safety hooks (violations configurable) | ✅ | safety net rejects AS loops / martians; can be disabled; FRR `bgp enforce-first-as` (W2.2) — router-level flag rejects eBGP UPDATEs whose leftmost AS_PATH AS != peer AS; FRR `allowas-in N` / BIRD `allow local as` (W2.3) — per-peer AS-loop tolerance; `local_as_count` fixed to use the FSM-normalized 4-byte AS_PATH |
| RFC 8212 default eBGP route behaviors | ✅ 🧪 | `lr-router` `set_ebgp_requires_policy` + per-session `set_session_policy`: external sessions (eBGP *and* confederation boundaries, §1) without explicit import policy discard received routes before Adj-RIB-In; without export policy advertise nothing — enforced at all three egress paths (per-prefix export, RFC 2918/7313 reannounce, initial dump; EoR still flows) with stale Adj-RIB-Out entries withdrawn; iBGP exempt; daemon default-on via `[bgp] ebgp_policy` with `accept-all` as the §3/Appendix-A deviation; FFI + Go/Python bindings |
| iBGP split-horizon, next-hop-self, LOCAL_PREF injection | ✅ 🧪 | |
| GTSM / TTL security (RFC 5082) | ✅ 🧪 | `lr-osroute::gtsm` (IP_TTL + IP_MINTTL / IPV6_MINHOPCOUNT on the listener, outbound TTL on the connector); daemon `--gtsm` / `--gtsm N`; live socket tests verify both happy-path and low-TTL rejection |
| Per-peer maximum-prefix | ✅ 🧪 | `with_maximum_prefix(N, action)` + `with_maximum_prefix_threshold(pct)`; warn / teardown / restart actions; CEASE NOTIFICATION subcode 1 (RFC 4486 §3); threshold + exceeded events latched per session; daemon `--max-prefixes` / `--max-prefix-action` / `--max-prefix-threshold` |
| Route aggregation | ✅ 🧪 | `add_aggregate(prefix)` / `remove_aggregate(prefix)` (RFC 4271 §9.2.2.2): originates aggregate with zeroed AS_PATH + ATOMIC_AGGREGATE + AGGREGATOR when specifics exist; withdraws when all specifics disappear; the origination flushes the export pipeline (`export_selection`) so a downstream peer learns aggregates originating after the session-up full sync; 6 e2e tests + daemon `[[aggregate]]` TOML surface (ROADMAP-v3 D4.2) with its own e2e (`tests/daemon_redistribute.rs`) |
| FFI: BGP message encoders + event polling + route lifecycle | ✅ 🧪 | `lr-ffi` (ROADMAP-v3 D5.4–D5.7) — `lr_bgp_encode_open` (RFC 6793 ASN4 capability, AS_TRANS, hold-time validation), `lr_bgp_encode_notification`, `lr_bgp_encode_update_withdraw_v4`/`announce_v4` (ORIGIN/AS_PATH/NEXT_HOP, 2- and 4-octet paths); `lr_router_poll_events` → `lr_event_t` batches (peer state, installs, withdrawals, advertisements, logs, protocol errors, max-prefix signals; overflow requeued losslessly); `lr_router_originate_v6` + `lr_router_withdraw_v4`/`_v6` (0 = withdrawn, 1 = not originated no-op); C/C++/Go/Python bindings synced with tests |
| FFI: policy objects + Filter DSL + OSPF/Babel sessions | ✅ 🧪 | `lr-ffi` (ROADMAP-v3 D5.1–D5.3) — `lr_route_new_v4/_v6` boxing a real `Route` with `lr_route_set/get` for next hop, LOCAL_PREF, MED, ORIGIN, canonical AS_PATH, standard/large/extended communities, metric, tag (probe-then-read getters); `lr_prefix_list_*` (FRR ge/le, first-match, implicit deny); `lr_route_map_*` running the FRR flow (all matches hold → sets apply → first matching entry decides; PERMIT/DENY/FALLTHROUGH) with `lr_resolver_*` — a `PolicySet`-backed registry of prefix-lists, FRR-dialect AS-path access-lists and RFC 1997 community lists, NULL resolver fail-closed; `lr_filter_compile/_evaluate/_free` compiling to the D3.7 stack VM with `lr_filter_context_t`, the C callback variant of `FilterContext` (19 optional pointers; NULL = built-in route-backed context, override e.g. `roa.state`); `lr_router_add_ospf_session`/`_ospfv3_session`/`_ext` (area kinds incl. stub/NSSA + totally- variants, §10.4 identities) and `lr_router_add_babel_session` (RFC 8966 §4.2.1); LDP sessions deliberately absent (daemon-side engine, no router session kind); C/C++/Go/Python bindings synced with tests |
| FFI: redistribution / aggregation / damping | ✅ 🧪 | `lr-ffi::policy` (ROADMAP-v3 D4.4) — `lr_router_add_redistribution_pipe` (LR_PROTO_*/LR_METRIC_* ids, tag, allow-list), `lr_router_add_aggregate`/`remove_aggregate`, `lr_router_set_damping` + `lr_damping_decay`/`destroy` (embedder-driven decay, the hook keeps its own Arc); C/C++/Go/Python bindings synced and exercised by the language harnesses in CI; 5 FFI tests |
| BMP monitoring (RFC 7854) | ✅ 🧪 | `lr-bmp` crate (7 message types, streaming codec with split feed/next_message, IPv4/IPv6 peer headers); `DefaultRouter::set_bmp_sink` mirrors Peer Up/Down + Route Monitoring — Route Monitoring carries the full UPDATE (real path attributes, MP_REACH for IPv6), Peer Up precedes it per §4.6 ordering; daemon egress `--bmp-target` + collector mode `--protocol bmp --listen`; 10 unit + 3 e2e tests |
| MRT dump import/export (RFC 6396) | ✅ 🧪 | `lr-mrt` crate: streaming TABLE_DUMP_V2 reader/writer (peer index tables, RIB_IPV4/IPv6_UNICAST + ADDPATH) + BGP4MP decode; `lr mrt parse/rib` CLI; daemon runtime API `mrt <path>` dumps the Loc-RIB (BIRD-shape output, byte-verified against BIRD 2.17.5 `protocol mrt`); typed attribute interpretation behind the `bgp` feature |
| RPKI-RTR cache client (RFC 8210) | ✅ 🧪 | `lr-bgp::rtr` — the 11-variant PDU codec (v0/v1/v2 + the SIDROPS ASPA PDU, BIRD-parity decode validation, 29 wire-form unit tests) and the transport-agnostic `RtrClient` state machine (§6 refresh/retry/expire timers, §7 version negotiation, §8.1 Serial/Reset Query memory, atomic per-sync ROA deltas, §12 error handling; 19+20 unit tests). Daemon side (`lr-cli::daemon_rpki`): one thread per `[bgp.rpki] cache` doing connect/reconnect with the §6 retry backoff, delta application into the live `RoaStore`, §6 data-expiry withdrawal, SIGHUP re-pointing; grep-friendly `rpki:` line on the runtime API `status`. Codec interop: BIRD 2's RPKI client syncs through our encoder (`tests/interop/rtr_bird.sh`, birdc-verified ROAs); daemon e2e against the mock cache (`tests/interop/rtr_lr.sh`) + 3 cargo e2e tests (`crates/lr-cli/tests/daemon_rpki.rs`) |
| ROA store + RFC 6811 origin validation | ✅ 🧪 | `lr-bgp::roa` (RoaTable, RFC 6811 §2 validate: Valid/NotFound/Invalid) + `lr-bgp::roa_store::RoaStore` (D2.3): two provenance layers — static `[[roa]]` config / FFI entries and RTR cache deltas — merged into an atomically swapped `Arc<RoaTable>` snapshot; readers clone the Arc under a read lock and validate lock-free; §5.6 duplicates coalesce, §12 code-6 withdrawals no-op, sort+dedup keeps the table deterministic. The filter DSL's `roa.state` and the built-in `roa_validate` import hook read the live store (cache updates apply without recompilation). FFI `lr_roa_store_*` + C/C++/Go/Python bindings; SIGHUP reload re-applies the static layer (D2.5). Validation lookups run a path-compressed Patricia trie over the entries (ROADMAP-v3 D8.4) — O(prefix_len) per query instead of the former O(n) scan; criterion keeps the cost flat across 1k/10k/100k tables (~5 ns uncovered, 75–182 ns covered) with differential proptests against the reference scan |

### OSPF (`lr-ospf`)

| Capability | Status | Notes |
|-----------|:------:|-------|
| Packet codec v2 (RFC 2328) / v3 (RFC 5340) | ✅ 🧪 | hello, DBD, LSR, LSU, LSAck, version-dispatched. v3: 16-byte packet header (§A.3.1, Instance ID at byte 14 — FRR `ospf6_packet_examin` parity), Hello body with FRR `ospf6_make_hello` layout (Interface ID | priority | options(3) | hello | **16-bit dead interval** | DR | BDR), DBD body 12 bytes (§A.3.3: 0\|options(3)\|MTU\|0\|flags\|seq — FRR `ospf6_make_dbdesc` parity), LSR entries 0(2)\|type(2)\|ID\|Adv (§A.3.4), IPv6 pseudo-header checksum finalization (§A.3.1); all v3 shapes FRR 10.3 interop-verified (`tests/interop/ospf6_frr.sh`). A wire audit found the earlier v3 codec self-consistent but wrong on four counts (24-byte header, Hello field order + 32-bit dead, 10-byte DBD, swapped LSR reserved word) — each was invisible to self-tests and caught only against the reference implementation |
| Neighbor FSM | ✅ | incl. §10.9 restart-to-ExStart on sequence mismatch (Fig. 12) |
| DBD/LSR exchange (§7.2, §10.3–§10.8) | ✅ 🧪 | `lr-ospf::exchange::DbExchange` + router wiring: master/slave election, header paging by MTU, LSR loading to Full, duplicate handling, RxmtInterval retransmit; BIRD 2 and FRR 10 interop-verified (Full adjacency + bidirectional routes + dead-timer teardown) |
| LSDB + LSA flooding | ✅ | per-area shared LSDB; same-area sessions flood to each other (§13.3 simplified) |
| SPF (Dijkstra) route computation | ✅ 🧪 | E2E test computes routes over a synthetic topology |
| Inter-area routes from summary-LSAs (§16.2) | ✅ 🧪 | reachable-border check, dist-to-border + summary metric, LSInfinity skip |
| ABR summary-LSA origination/flush (§12.4.3) | ✅ 🧪 | type-3 lifecycle with backbone-only loop guard, checksummed LSAs, MaxAge flush |
| AS-external routes (type-5 LSAs, §16.4) | ✅ 🧪 | origination via `ospf_redistribute`, AS-scope flooding across ABRs, §16.4 calculation (type-1/2 metrics, forwarding-address reachability + next hop), MaxAge flush lifecycle |
| Summary-ASBR LSAs (type-4, §12.4.3) | ✅ 🧪 | ABR origination for inter-area-only ASBRs, ASBR leg resolution in §16.4 (b) |
| External route redistribution API | ✅ 🧪 | `DefaultRouter::ospf_redistribute`/`ospf_unredistribute` |
| Cross-protocol redistribution engine | ✅ 🧪 | `RedistributionPipe` (BIRD `pipe` / FRR `redistribute`); BGP↔BGP, BGP→OSPF, OSPF→BGP; metric policy (Inherit/Fixed/Add); prefix-list filter; withdrawal propagation; 7 e2e tests; daemon `[[redistribute]]` TOML surface (ROADMAP-v3 D4.1) — source/target/metric/tag/allow, fail-closed validation against the running protocol set (sources with no daemon injection surface rejected), start-up banner + router log events `redistribute: <prefix> -> BGP`; daemon e2e in `tests/daemon_redistribute.rs` |
| Designated-router election | ✅ 🧪 | `lr-ospf::interface::elect` implements §9.4 step-by-step (IP-identity electors per §A.3.2, BDR candidates exclude DR-declarers, DR falls back to the elected BDR, step-4 re-election so no router claims both DR and BDR) — cross-checked against BIRD 2 `ospf_dr_election` and FRR 10 `ospf_dr_election`; §10.4 adjacency gate in the router (`adjacency_viable`, Waiting blocks adjacency like BIRD `can_do_adj`), AdjOK? re-evaluation via `DefaultRouter::set_ospf_dr_state` (§9.4 step 7: promotion to ExStart with the initial DBD, demotion to 2-Way with the exchange reset); daemon broadcast mode end-to-end (`tests/interop/ospf_broadcast.sh`); the OSPFv3 form is `lr-ospf::interface::elect_v3` — the same §9.4 algorithm on Router-ID identity per RFC 5340 §4.1.2 (the v3 Hello's DR/BDR fields carry Router IDs, §A.3.2) — with the daemon election driven from received Hellos (§9.3 BackupSeen/NeighborChange dirtying, §9.3 WaitTimer) and pushed into sessions via `set_ospf_dr_state`; FRR ospf6d `dr_election` parity verified live (`tests/interop/ospf6_frr_broadcast.sh`) |
| Network-LSA (§12.4.2) + transit links (§12.4.1.2) | ✅ 🧪 | `originate_network_lsa` (LS ID = the DR's IP interface address, Advertising Router = its router-id — they differ in general), `RouterLsaLink::Transit`; the DR originates the Network-LSA only when fully adjacent to ≥ 1 other router and flushes it (MaxAge) when that stops; the SPF derives the transit network's own prefix (LS ID masked by the network mask — BIRD `spfa_process_net` parity) and secondary addresses on the interface stay stub links |
| Area support | ✅ | multi-area v2 with ABR summaries (backbone-attached); OSPFv3 multi-area with ABR 0x2003 summaries and 0x2004 ASBR summaries (backbone-attached, all-v3 areas — `ospf_summarize_areas_v3`) |
| LSA refresh / aging / MaxAge flush | ✅ | periodic self-LSA re-origination at 1800 s, MaxAge expiry at 3600 s, MaxAge purge on receipt (§13) |
| Daemon transport (`--protocol ospf`) | ✅ 🧪 | `lr-osroute::ospf_transport`: raw `IPPROTO_OSPF` socket per interface (v2: IPv4, `ip_mreqn` membership 224.0.0.5/6, TTL 1; v3: IPv6, ff02::5/6 membership, hop limit 1, header-less receive, kernel-gated test `tests/ospf6_kernel.rs`); `lr-ospf::origination`: Router-LSA builder + §A.1 packet checksum; two-daemon e2e over a veth pair (user namespaces, rootless); per-interface `network_type = "broadcast"` (TOML) runs the §9.4 election — Hello DR/BDR fields, §10.4 adjacency, transit links and Network-LSA end-to-end, with BIRD 2 on its default broadcast type (`tests/interop/ospf_broadcast.sh`) |
| Stub/NSSA areas | ✅ 🧪 | `OspfAreaType` (stub / no-summary / NSSA / totally-NSSA): type-5/type-4 refusal at install & AS-scope re-flood, ABR summary-default (type-3) and type-7 default injection, area-scoped type-7 origination, §3.2 translation to type-5 by the elected (highest-ID/Nt) border router; OSPFv2 only |
| Virtual links | ✅ 🧪 | `ospf_add_virtual_link` (§15): up while the transit-area SPF reaches the endpoint; materializes a backbone adjacency restoring ABR status; embedder-routed transport; stub/NSSA transit refused |
| Auth (cryptographic) | ✅ 🧪 | RFC 5709 HMAC-SHA-1/SHA-256 (v2 AuType 2 trailer; Ko/Apad MAC per §3.3, Auth Data Len = digest), RFC 7166 v3 auth trailer (RFC 7166 layout with 16-bit SA ID + 64-bit crypto-seq; §4.5 Apad MAC embedding the IPv6 source), anti-replay; unit tests |
| OSPFv3 inter-area-prefix-LSA (0x2003) | ✅ 🧪 | body encode/decode (§A.4.5: 0\|metric(3)\|§A.4.1 prefix); `originate_v3_inter_area_prefix_lsa` (LS ID caller-assigned — §4.4.3.4 strips its addressing semantics); router-side ABR origination with stable per-(area, prefix) LS IDs, previous-instance reuse and lowest-free-ID allocation (FRR `ospf6_new_ls_id` parity); flush lifecycle on ABR-status loss |
| OSPFv3 LSA bodies (RFC 5340 §A.4) | ✅ 🧪 | `lr-ospf::lsa::v3`: Router-LSA (0x2001, bits\|options\|16-byte descriptors, no count field), Network-LSA (0x2002, LS ID = DR Interface ID), Inter-Area-Router-LSA (0x2004, 12-byte body with the destination Router ID — §A.4.6), Link-LSA (0x0008, priority\|options\|link-local\|prefixes, §4.4.3.4 MUST), Intra-Area-Prefix-LSA (0x2009, referenced-LSA triple + prefixes), AS-External-LSA (0x4005, E/F/T flag layout per FRR `ospf6_asbr.h`, §A.4.1 prefix with the Referenced LS Type riding the trailing word, optional global forwarding address/tag/referenced LS ID) and the §A.4.1 prefix encoding (address rounded to 32-bit words); origination helpers with §12.1.2 sequence floors; FRR `ospf6_lsa.h` struct parity |
| OSPFv3 intra-area SPF (§4.8) | ✅ 🧪 | `run_spf_v3`: Network vertices keyed (DR Router ID, DR Interface ID); next hops are (link-local, outgoing Interface ID) pairs — a direct p2p neighbor's link-local resolves from its Link-LSA (LS ID = the Neighbor Interface ID of our link), routers on a directly attached transit network resolve through the back-link transit entry, deeper vertices inherit; FRR `ospf6_lsdesc_backlink` bidirectional check; prefixes arrive via Intra-Area-Prefix-LSAs (NU/LA excluded, §A.4.1); the Router-LSA options of every router are exposed for 0x2004 origination (§4.4.3.5); routes publish as `Protocol::Ospfv3` in the v6-unicast family |
| OSPFv3 inter-area + AS-external routing (§4.8.3 / §4.8.5) | ✅ 🧪 | `summary_routes_v3` — 0x2003 candidates from intra-area-reachable border routers at dist(border)+metric, LSInfinity skipped, NU-marked prefixes ignored (§4.8.3), best candidate per prefix (metric, then border router ID), each carrying the border router's resolved link-local. `external_routes_v3` — the §16.4 v3 form over 0x4005 LSAs: ASBR legs resolve intra-area from the tree or inter-area via 0x2004 bodies (LS ID is meaningless per §4.4.3.5), F-bit forwarding addresses must be a legal global address covered by an intra-area or 0x2003 route (§16.4 (c)), type-1/2 metric semantics and the §16.4 (6) preference (type 1 > type 2 > lower metric > lower internal cost > lower ASBR ID). Router install: the v3 recompute merges intra > inter > external per prefix (§11), external entries generalize the v2 `OspfKind::External` forwarding address to `Option<IpAddr>` so a v6 FA publishes as the next hop, 0x4005s re-flood across attached v3 areas like v2 type-5s, and the `no_summary` acceptance check for 0x2003 decodes the zero-length default from the body. Origination: `ospf_redistribute_v3`/`ospf_unredistribute_v3` (§4.4.3.6, stable per-prefix LS ID, illegal FAs refused, MaxAge withdrawal), ABR 0x2003/0x2004 summaries (`ospf_summarize_areas_v3`), redistribution pipes targeting Ospfv3 bridge v6 routes; 12 unit tests + 5 FSM-level router tests |
| OSPFv3 daemon mode (`[ospf] version = "v3"`) | ✅ 🧪 | `daemon_ospf3`: one IPv6 raw socket per interface (no address needed — link-local sources), Interface ID = kernel ifindex (FRR convention), neighbor's Interface ID learned from Hellos; self-origination = Router-LSA (p2p links per Full adjacency, §14.1 refresh) + Link-LSA per interface (the §4.4.3.4 MUST) + Intra-Area-Prefix-LSA attaching global prefixes; pseudo-header checksum on every egress datagram; the link-local → interface mapping learned from Hello sources feeds the kernel mirror's RTA_OIF resolution; inter-area summaries, AS-external redistribution and the v3 route calculation are live (the rows above); broadcast segments run the RFC 5340 §4.1.2 interface FSM over the §9.4 election on Router-ID identity (`lr-ospf::interface::elect_v3`): Waiting/DR/BDR/DR-Other, Hello DR/BDR fields (§A.3.2), the §10.4 gate pushed via `set_ospf_dr_state`, Router-LSA transit links (§A.4.3 type 2, the DR self-referential — FRR `ospf6_router_lsa_originate` parity), the DR's Network-LSA (§4.4.3.3, options OR'd from fully adjacent neighbors' Link-LSAs) with MaxAge flush on role loss, and the §4.4.3.5 prefix split (transit-reported interfaces drop their prefixes from the router-referenced IAP; the DR originates the network-referenced IAP — the Link-LSA prefix union, NU/LA and link-locals excluded, duplicates merged OR'ing options); graceful restart (RFC 5187) runs the same machinery as v2 — helper retention, shutdown Grace-LSA flood (LS type 0x000b, LS ID = the Interface ID), state-file recovery, §2.3 flush — through `tests/interop/ospf6_gr.sh` and `tests/interop/ospf6_gr_frr.sh` (see the GR rows below); SRv6 = the RFC 9513 row above. Interop: two lr daemons (`tests/interop/ospf6.sh`, adjacency + routes + kernel install + withdrawal; `tests/interop/ospf6_broadcast.sh`, election convergence + Network-LSA-vertex routing + the DR's network IAP), FRR 10.3 ospf6d (`tests/interop/ospf6_frr.sh`, Full adjacency both ways, lr learns FRR's prefix via a link-local, FRR learns lr's prefixes, dead-timer teardown) and FRR ospf6d on its default broadcast type (`tests/interop/ospf6_frr_broadcast.sh`, both sides run the §9.4 election independently and agree on the same DR/BDR pair, FRR parses lr's transit links + Network-LSA + network IAP, lr resolves FRR's loopback through the network vertex onto a link-local) |
| Grace-LSA codec (RFC 3623 / RFC 5187) | ✅ 🧪 | `lr-ospf::lsa::grace` — v2: link-local opaque type 9 with Opaque Type 3 / ID packing (RFC 5250 §3.1); v3: the dedicated link-scoped LS type 0x000b with the Interface ID as the Link State ID (RFC 5187 §2.1/§2.2, FRR `ospf6_gr_lsa_originate` parity); TLV numbers 1=Grace Period / 2=Reason / 3=IP interface address (4-octet v4 or 16-octet v6 value), 4-octet TLV padding, `originate_grace_lsa_v2` + `originate_grace_lsa_v3`; O-bit = RFC 5250 Opaque-LSA capability (DBD scope, v2 only), NOT a GR signal — RFC 5187 defines no capability bit at all; DD packets carry it (see the RFC 5250 row in `RFC_MAP.md`) |
| RFC 5250 Opaque-LSA capability signalling | ✅ 🧪 | the O-bit rides the DD options byte (`lr-ospf::exchange::db_desc_packet`) — lr both originates and floods opaque LSAs, so peers learn it can receive them; BIRD 2.0.8 captures a neighbour's options from DD packets only and skips opaque flooding to non-O-bit neighbours (`lsa_is_acceptable`), FRR's `ospf_gr.c` refuses Grace-LSA origination without `OSPF_OPAQUE_CAPABLE`; Hellos stay O-bit-free per RFC 5250 §3 (audit fix: the bit previously existed only in LSA headers, so BIRD never flooded opaque LSAs toward lr) |
| GR helper mode (RFC 3623 §3) | ✅ 🧪 | `lr-ospf::gr::HelperEntry` + daemon wiring — §3.1 checks, dead-timer retention, adjacency kept in the Router-LSA, §3.2 exits (flush/timeout/topology change via per-area topology versions), FRR `supported_grace_time` cap; default on (`--ospf-no-gr-helper`); both daemon versions carry it: v2 BIRD-verified (`tests/interop/ospf_gr_bird.sh`), v3 verified against FRR 10.3 ospf6d with `graceful-restart helper enable` (`tests/interop/ospf6_gr_frr.sh` — helper entry on the 0x000b Grace-LSA, retention across the dead interval, `lastExitReason: Successful graceful restart` on the flush); received Grace-LSAs surface through the dedicated `drain_ospf_grace_events()` channel so the daemon's ticker/mirror thread can never swallow one |
| GR restarting router (RFC 3623 §2) | ✅ 🧪 | state-file-persisted grace deadline, shutdown Grace-LSA flood, recovery with origination suppression + §2.2 adjacency/back-link verification, §2.3 flush + re-origination above the retained sequence floor; the flood window keeps servicing the protocol (inbound ACKs + Hellos + outbound — no re-origination/election) so a peer's post-Full LSA refresh gets ACKed and its §3.1 (2) helper check passes on a later flood round (this was the CI-red race in `ospf_gr_bird.sh`: 7 consecutive failures because the un-ACKed Router-LSA pinned the peer's LS retransmission list); `tests/interop/ospf_gr.sh`. RFC 5187 wires the identical flow for v3 (`daemon_ospf3`: v3 Grace-LSAs, Router-ID neighbour identity, the pre-restart adjacency set seeded from the retained v3 Router-LSA p2p descriptors, Interface IDs = kernel ifindexes preserved across the restart per §3.2) — `tests/interop/ospf6_gr.sh` (planned restart + grace timeout, both roles) and `tests/interop/ospf6_gr_frr.sh` (recovery from a live FRR ospf6d helper) |
| Prefix Link-Local LSA (RFC 7684) | ✅ | `LsaTypeV3::PrefixLinkLocalAsLsa = 0x4004` + `v3_prefix_options` bits (Af, R) + `V3PrefixLinkLocalEntry` codec with optional Address Family ID; 8 unit tests |
| Extended LSAs (RFC 8362) | ✅ 🧪 | `lr-ospf::lsa::e_v3` — the eight TLV-bodied E-LSA codecs (E-Router 0xA021/fc 33, E-Network 0xA022/34, E-Inter-Area-Prefix 0xA023/35, E-Inter-Area-Router 0xA024/36, E-AS-External 0xC025/37, E-Type-7 0xA027/39, E-Link 0x8028/40, E-Intra-Area-Prefix 0xA029/41; fc 38 stays unallocated) with the RFC 3630 TLV framing (Type/Length/Value, 4-octet padded, padding not in Length) and the §3 top-level TLV set (Router-Link 1, Attached-Routers 2, Inter-Area-Prefix 3, Inter-Area-Router 4, External-Prefix 5 with E-bit 0x04000000 + fwd-addr/route-tag sub-TLVs 1/2/3, Intra-Area-Prefix 6, IPv6/IPv4 Link-Local Address 7/8); §5 malformed rules decode to `None` (truncated, below-minimum, missing required TLV — refused install/ack/flood), unknown TLVs skipped, duplicate single-instance TLVs keep the first; origination helpers for all eight shapes. Reception (the receiver decides — §6.1/§6.2, no wire capability negotiation exists): `run_spf_v3_extended` / `summary_routes_v3_extended` / `external_routes_v3_extended` prefer a speaker's E-Router/E-Network/E-Link/E-IAP LSAs over its legacy shapes (first E-instance per router wins; fragmented E-Router-LSAs concatenate) and admit the E inter-area/external forms, while the legacy `run_spf_v3` path stays byte-identical (E-LSAs stored + re-flooded, never used for the calc); the router's `set_ospf_v3_extended_lsas` knob (daemon `[ospf] extended_lsas`, `--ospf-extended-lsas`, OSPFv3-only fail-closed) drives both sides; E-IAP ref types 0xA021/0xA022 map onto the Router/Network vertices; `ospf_area_accepts` classifies the E forms (0xC025/0xA024 stub-refused, 0xA023 no-summary default via the TLV, 0xA027 NSSA-only), 0xC025 re-floods at AS scope, and the RFC 3623 topology-version bookkeeping counts the E types. Daemon origination: E-Router/E-Network/E-Link/both E-IAP forms replace the legacy shapes under `extended_lsas` (same sequence floors per (area, LS ID), MaxAge flush paths switched symmetrically); ABR/ASBR origination stays legacy (interoperable with every receiver — §6.1 migrates areas individually). No reference implementation originates E-LSAs (verified: FRR 10.3+ and BIRD 2.17 have none), so acceptance is RFC-figure-pinned unit tests + the two-daemon lab `tests/interop/ospf6_e_lsa.sh` where `extended_lsas = true` makes legacy origination impossible — adjacency + route convergence + link-local next hops + MaxAge withdrawal prove the E-LSA path end to end; `ospf6.sh` / `ospf6_broadcast.sh` regressions pin the byte-identical legacy default |
| Segment Routing control plane (RFC 8665) | ✅ 🧪 | control plane (slice 1) + reception (slice 2) + adjacency/mapping-server (slice 3). Slice 1: `lr-ospf::lsa::sr` — RI LSA SR-Algorithm + SID/Label Range TLVs (RFC 8665 §3), Extended Prefix Opaque LSA (Opaque Type 7) + Prefix-SID sub-TLV codec (RFC 7684 §2.1 descriptor order, RFC 8665 §5 Flags/Reserved/MT-ID/Algorithm/SID-Index, RFC 7684 §2.3 4-octet alignment), remote-label mapping (SRGB base + index); daemon originates RI + one Ext-Prefix LSA per `[[ospf.prefix_sid]]` (LSDB sequence floor, adjacency-driven re-origination, `no_php` = §5 NP flag / FRR `no-php-flag`); FRR 10.3 stores both LSAs (`tests/interop/ospf_sr_frr.sh`). Slice 2: `lr-ospf::srdb` — per-node SRDB projected from the area LSDB (SRGBs from RI LSAs, Prefix-SID mappings from Ext-Prefix LSAs); the router attaches resolved labels (closest reachable originator, §5 PHP rule for NP-clear adjacent originators, V/L + range guards) to intra/inter-area routes behind `[ospf] sr_receive`, and the shared kernel mirror installs the RFC 8660 encap routes; own SIDs get AF_MPLS pop routes with `install_kernel`; two-daemon lab `tests/interop/ospf_sr.sh` (API-verified labels both directions), FRR phase 2 kernel-gated. A wire audit against RFC 7684/8665 corrected the descriptor field order (Prefix Length before Flags) and the Prefix-SID sub-TLV shape (Reserved byte + 4-octet index) — the old encoding aborted FRR 8.1's ospfd (assert in `masklen2ip` once `segment-routing on` activates its SRDB parse). Slice 3: Adj-SID + LAN Adj-SID sub-TLVs (§6.1/§6.2, B/V/L/G/P flags, length-7/8 + length-11/12 shapes) riding the RFC 7684 §3 Extended Link Opaque LSA (Opaque Type 8), `[ospf.interface] adj_sid` origination on Full adjacency (p2p Adj-SID; broadcast §7.4.2 DR/LAN shapes) with §7.4.1 MaxAge withdrawal + kernel tail pops, `install_kernel`-gated; the mapping-server shapes — Extended Prefix Range TLV (§4) with the M-flagged Prefix-SID, `[[ospf.mapping_server]]` origination, range→prefix index arithmetic and `SrDatabase::mapping_label_for` resolution (direct advertisements win per RFC 8661 §3.2.3, the LSP rides the prefix's own path — SPF stub/transit routes now carry the RFC 2328 §16.1.1 owner next hop); learned adjacency segments + ranges surface through `DefaultRouter::ospf_sr_databases` and the daemon's `ospf-sr adj` / `ospf-sr ms` status lines; two-daemon lab `tests/interop/ospf_sr_adj.sh`, FRR 10.3 decodes lr's Extended Link LSA (label 24000, length-7 Adj-SID) in `tests/interop/ospf_sr_frr.sh` phase 3. Slice 4 (SRv6) in progress — see the new `lr-srv6` row below |
| SRv6 data plane (RFC 8754 / RFC 8402 / RFC 8986) — slice 1 | 🟡 🧪 | `lr-srv6` crate: 128-bit [`Sid`] (RFC 8754 §3, structured LOC:FUNCT:ARGS), [`Locator`] (RFC 8754 §3.1, IPv6 prefix + block bits), [`Srh`] codec (RFC 8754 §2 — Next Header / Hdr Ext Len / Routing Type 43 / Segments Left / Last Entry / Flags / Tag / Segment List / TLVs, full encode/decode with mid-stack-bottom-bit and reserved-flag-bit checks, max-segments bound of 127 from the `Hdr Ext Len` octet), and the RFC 8986 §4 [`Behavior`] registry (all 32 IANA-assigned opcodes End / End.X / End.DX6 / End.DT46 / End.B6.Encaps.Red / End.Un etc. with PSP/USP/USD flavor classification). `no_std`-compatible (mirrors `lr-mpls`). `lr-osroute::seg6_route` Linux netlink mirror: `Seg6Netlink` installs/deletes `seg6` encap routes (`LWTUNNEL_ENCAP_SEG6` + `SEG6_IPTUNNEL_SRH`, inline/encap modes) and `seg6local` endpoint routes (`LWTUNNEL_ENCAP_SEG6_LOCAL` + `SEG6_LOCAL_ACTION` with the per-behavior parameter set NH4/NH6/IIF/OIF/TABLE); capability detection via `/proc/sys/net/ipv6/conf/all/seg6_enabled`. 52 `lr-srv6` unit tests + 17 `lr-osroute::seg6_route` wire-shape tests + 2 kernel-gated interop tests (`crates/lr-osroute/tests/srv6_kernel.rs`, gated on `seg6_enabled=1` + `CAP_NET_ADMIN`). FFI: `lr_srv6_encode_srh` / `lr_srv6_decode_srh` exposed via C ABI, Python (`encode_srv6_srh`/`decode_srv6_srh`) and Go (`EncodeSRv6SRH`/`DecodeSRv6SRH`) bindings. Missing: BGP SR Policy (RFC 9256/9430, future slice) |
| OSPFv3 SRv6 control plane (RFC 9513) — slices 2-3 | 🟡 🧪 | `lr-ospf::lsa::srv6`: the SRv6 Capabilities TLV (type 20, O-flag bit 1) on the OSPFv3 Router Information LSA (RFC 7770 §2.2 function code 12, 0xA00C area-scoped) with the SR-Algorithm TLV (type 8) and the Node MSD TLV (RFC 8476 type 12; SRv6 MSD types 41/42/44/45 from the shared IGP MSD-Types registry); the SRv6 Locator LSA (function code 42, 0xA02A area-scoped, U-bit set) with the Locator TLV (route types 1-6 gated, locator length 1-128, §A.4.1 prefix words, metric 0xFFFFFFFF = unreachable) in RFC 3630 TLV format with 4-octet padding; the End SID sub-TLV (type 1, §8) with the RFC 8986 behavior and the SID Structure sub-TLV (§10: length MUST be 4, four lengths ≤ 128 bits, at most once per parent); the §6 AC prefix option (0x80); origination helpers (`originate_v3_srv6_ri_lsa`, `originate_v3_srv6_locator_lsa`). `lr-ospf::srv6db`: the per-node LSDB projection — capabilities/algorithms/MSDs per node, locators deduplicated per prefix under the §7.1 preference (area scope beats link/AS, then smallest LS ID, then first occurrence), End SIDs gated on §8 containment (masked prefix) and the §11 Table 1 behavior set, duplicate SIDs keep the first. `run_spf_v3` attaches locator routes (§5: metric = the advertising router's SPF distance, link-local first hop; the root's own locator is connected; unreachable/non-intra-area locators never route). `DefaultRouter::set_ospf_srv6_receive` (fail-closed, off by default) installs supported-algorithm (0/SPF) locators as IPv6 forwarding entries with §5's IAP-beats-locator preference; `ospf_srv6_databases()` exposes the read-only view. 13 codec tests pin every shape byte-for-byte against the RFC figures, 9 projection tests, 3 SPF tests, 4 router e2e tests over live v3 exchanges. NOTE: the repo previously cited RFC 9352 for OSPFv3 SRv6 — 9352 is the IS-IS SRv6 sibling; the OSPFv3 extensions are RFC 9513. Slice 3 (daemon): `[[ospf.srv6_locator]]` tables (prefix/algorithm/metric/anycast/`sid`/`behavior` + the all-or-none §10 SID Structure lengths) and the `[ospf]` globals `srv6_receive` / `srv6_o_flag` / `srv6_max_sl` / `srv6_max_end_pop` / `srv6_max_h_encaps` / `srv6_max_end_d` (CLI: `--ospf-srv6-locator`, `--ospf-srv6-receive`, `--ospf-srv6-o-flag`), all OSPFv3-only and fail-closed (rejected under v2; duplicate prefixes, non-IPv6, §10 violations and End-SID-invalid behaviors rejected at finalize). With locators configured the v3 daemon originates, per area and into the same LSU as the topology LSAs: the RI LSA (Capabilities + SR-Algorithm derived from the locators + Node MSD from the configured limits) and the Locator LSA (§7.1 TLVs with §8 End SIDs — default SID = the locator prefix, default behavior End) on the normal re-origination + §14.1 refresh cadences; without locator configuration the daemon stays byte-identical to a pre-SRv6 one. Interop: `tests/interop/ospf6_frr_srv6.sh` — a 3-node lab (lr1 originator ↔ FRR 10.3 ospf6d ↔ lr2 receiver) where ospf6d (no SRv6 support) stores and re-floods the U-bit-set unknown LSAs (all 5 of lr1's LSAs in its LSDB) and lr2 installs lr1's locator through the FRR relay as an Ospfv3 route with a link-local next hop. Slice 4 (RFC 9513 §9 over RFC 8362): the End.X (§9.1, registry type 31) and LAN End.X (§9.2, type 32) sub-TLV codecs ride the E-Router-Link TLV's sub-TLV region — Behavior(2)|Flags(1,B/S/P)|Reserved1|Algorithm|Weight|Reserved2|SID(16)[+Neighbor Router-ID(4) for the LAN form] with the §10 SID Structure as registry type 30 (at most once, sum ≤ 128); `srv6db` projects `Srv6EndXSid`s (parent link's neighbor ids + the LAN neighbor field) gated on §9 locator containment + algorithm match of the same router, multiple instances preserved (load-balancing / shared SIDs); the daemon originates the p2p form per `[[ospf.interface]] srv6_end_x` (IPv6, fail-closed inside a configured locator; on broadcast segments the same knob covers the §9.1 DR adjacency) plus the LAN form per `[[ospf.interface]] srv6_end_x_lan` (an at-most-/96 IPv6 base inside a locator, broadcast-only, fail-closed: each Full BDR/DR-Other neighbor `R` derives the per-neighbor §9.2 SID `base | R` — the Router-ID fills the low 32 bits, so every derived SID provably stays inside the locator): under `extended_lsas` the End.X sub-TLVs ride the topology E-Router-LSA, under legacy mode a complete sparse-mode companion E-Router-LSA (RFC 8362 §6.2) carries them alongside the legacy Router-LSA; both sides surface the projections on the runtime API `status` as `srv6-endx` lines (`tests/interop/ospf6_e_lsa_endx.sh`: adjacency + legacy routes unaffected + r2 projects r1's SID + self-projection; `tests/interop/ospf6_e_lsa_endx_lan.sh`: a three-router bridge broadcast segment in extended mode — the DR projects the plain §9.1 SID, the BDR the derived §9.2 LAN SID, the originator self-projects both — which also pinned and fixed the multicast-DD deadlock: RFC 2328 §8.1's per-adjacency DD/LSR are now unicast at the peer's link-local in both the v2 and v3 daemons, and Full→2-Way demotions re-originate the Router-LSA immediately). Missing: BGP SR Policy (RFC 9256/9430) | `lr-ospf::lsa::srv6`, `lr-ospf::srv6db`, `lr-ospf::spf` (`run_spf_v3` locators), `lr-router` (`ospf_srv6_receive`), `lr-cli` (v3 daemon origination) |

### Babel (`lr-babel`)

| Capability | Status | Notes |
|-----------|:------:|-------|
| RFC 8966 codec (all core TLVs) | ✅ | magic 42 (0x2A) + version 2 header validated; §4.6 TLV bodies byte-exact (flags/reserved fields, Update Seqno/Metric order) |
| Neighbor / route table + feasibility (RFC 8966 §3.5.2) | ✅ | |
| Route expiry + neighbour-death retraction (RFC 8966 §3.2.5) | ✅ 🧪 | every Update refreshes its claim's hold deadline (babeld's `hold_time = MAX(4·I/100 + I/50, 15)` s, I = the announced interval in centiseconds — six times the update interval, 15 s floor); `BabelRouteTable::expire` drops lapsed claims and a neighbour whose Hellos stopped (4× its advertised Hello interval) loses everything it taught us without waiting out each hold (babeld's `retract_neighbour_routes`); `RouterInstance::babel_gc` sweeps both once a second |
| BABEL-RTT delay metric (RFC 8966 §A.2.4) | ✅ 🧪 | Timestamp sub-TLV on Hello (1), Timestamp Echo sub-TLV on IHU (2); neighbour state records the peer's `(send, receive)` pair and echoes it while fresh (1 s window), the originator computes `rtt = max(0, local_wait − remote_wait)` from its own records — single-clock differences, no synchronisation; EWMA smoothing (babeld's decay 42/256, first sample doubled), 600 s sanity window, 180 s validity, linear `rtt_penalty` between `rtt_min_us`/`rtt_max_us` |
| Metric computation, seqno handling | ✅ 🧪 | E2E install/withdraw tests |
| RFC 9079 source-specific routing | ✅ 🧪 | Source Prefix **sub-TLV** (type 128) inside Update / Route Request / Seqno Request per §7.1; IPv4 + IPv6 source prefixes; route table keyed by (destination, source) tuple |
| RFC 8967 MAC authentication | ✅ 🧪 | stateful `BabelAuthInterface`: full §4.3 reception (MAC test once per key, preparse, PC verification), §4.3.1 Challenge Request/Reply resynchronization (30 s expiry, 300 ms request/reply rate limits), §4.4 neighbour-state expiry (lazy + gc), §5 incremental-deployment mode, keyed BLAKE2s-128 (§4.1 SHOULD) beside the mandatory HMAC-SHA256, §4.2 PC-overflow index rotation, variable-length MAC TLVs (unknown trailer TLVs skipped, body MAC TLVs ignored); two-daemon e2e (`tests/interop/babel_auth.sh`) |
| RFC 9467 relaxed PC verification | ✅ 🧪 | §3.1 unicast/multicast PC split (PCm/PCu, RECOMMENDED, default on), §3.2 window verification (OPTIONAL, configurable S), §3.3 combined mode with two windows; successful Challenge Replies seed both fields; covered by unit tests and the two-daemon e2e |
| Babel daemon transport (IPv6 link-local + IPv4 local networks) | ✅ 🧪 | daemon `--protocol babel` mode: UDP 6696, TTL=255 (RFC 8966 §2.1/§4), `%iface` scope carried into bind/join/send; two-socket transport per family (unicast on the local address + multicast on the group address — ff02::1:6 v6 / 224.0.0.111 v4 — with SO_REUSEADDR) so the destination class is exact; periodic Hello + IHU + Router-Id + Next-Hop + Update announcements (Loc-RIB minus babel-learned routes, split horizon, boot-unique router-id); `--network` origination; source-port/self-datagram filtering (§4.1); RFC 8967 auth wired in with per-neighbour state and challenge traffic unicast to the peer; `tests/interop/babel_auth.sh` (four phases) |
| Multi-interface sessions + per-interface parameters (ROADMAP-v3 D1) | ✅ 🧪 | `[[babel.interface]]` glob patterns resolve against the system's interfaces (first match wins, BIRD semantics); each match gets its own session, router-id, socket pair (unicast address-bound with SO_BINDTODEVICE + wildcard multicast listener isolated via `IP_MULTICAST_ALL=0` and the per-interface membership), `hello_interval_ms` / `update_interval_ms` / `rxcost` / `rtt_cost`+`rtt_min_us`+`rtt_max_us` / `next_hop_ipv4` / `next_hop_ipv6` / `extended_next_hop` / `port` / `group` / `check_link` (1 s poll, withdraw-on-down, announce-on-return); dual-stack interfaces announce on both transports (§4.1; the v4 transport carries IPv4 destinations only); routes learned on one interface are re-advertised on the others with the origin's (router-id, seqno) and the interface cost added (§3.7.5), per-session split horizon, and vanished claims retracted with infinity-metric Updates (§3.5.5); Hello seqno advances per Hello (§3.4.1) while the Update seqno tracks content changes (§3.7.1); `[[babel.key]] interface` scopes RFC 8967 keys per interface; `tests/interop/babel_multihop.sh` (three speakers, three namespaces: transit both ways, check-link withdrawal end-to-end, reconvergence) + `babel_multi_nic.sh` |

### LDP (`lr-ldp`)

| Capability | Status | Notes |
|-----------|:------:|-------|
| RFC 5036 codec (PDU / TLV / all 11 message types) | ✅ 🧪 | streaming `LdpCodec` (split feed/next-PDU), U/F-bit passthrough, FEC element set (prefix, wildcard, RD-free §3.4.1 subset), generic label, Status TLVs with the §3.9 status-code registry; no-std |
| §2.5.4 session FSM + §3.5.3 parameter negotiation | ✅ 🧪 | active/passive roles, Init validation (version, keepalive, advertisement discipline resolution, receiver label-space match), min-of-proposals negotiation, KeepAlive send/hold timers with expiry teardown |
| §3.5.2 discovery (link + targeted) | ✅ 🧪 | UDP Hellos with hold/refresh timers, adjacency creation + expiry, extended (targeted) discovery with accept policy, §2.5.2 active-role decision by transport-address comparison, session teardown when the last adjacency for a label space drops |
| Label bookkeeping (downstream unsolicited) | ✅ 🧪 | per-peer LIB (learn/advertise/withdraw), §3.5.8.1 request→mapping/No-Route answers, §3.5.10.1 withdraw→release, wildcard withdraw handling, Address message exchange before mappings (§3.5.5.1), address-based session matching |
| §3.5.3 Max PDU Length enforcement | ✅ 🧪 | TX: session messages batch into PDUs capped at the negotiated Max PDU Length; RX: an over-long PDU is answered with a fatal Bad PDU Length Notification before the session drops (FRR `S_BAD_PDU_LEN` parity) |
| §3.5.4 / §3.4.4.1 loop detection (Hop Count + Path Vector) | ✅ 🧪 | configurable per engine (`loop_detection`, default off per RFC 2.8); the Init proposes the D bit with PVLim; with it on, received Label Mappings and Label Requests are checked per A.2.6 (local config governs — the D bit is not negotiated): a Hop Count over the limit (0 = unknown, exempt), a Path Vector containing our LSR Id, or a Path Vector over the limit rejects the message — a looping Mapping is dropped and rejected with a Label Release carrying the Loop Detected Status TLV (E=0, non-fatal), a looping Request is answered with a Loop Detected Notification; `EngineEvent::LoopDetected` surfaces both; e2e over real sockets + unit tests |
| Engine glue (`LdpEngine`) | ✅ 🧪 | embedder moves bytes; TCP connection lifecycle (EstablishTransport/on_connected/on_accepted), session collision + No-Hello (§2.5.3) rejection, events for adjacency/session/address/label churn; two-speaker loopback e2e covers the full lifecycle plus keepalive expiry and both shutdown paths |
| Daemon transport (`--protocol ldp`, TCP/UDP 646) + FRR ldpd interop | ✅ 🧪 | wildcard UDP socket joins 224.0.0.2 per interface, link Hellos every hold-time third with TTL 1 and per-interface egress (`send_link_hello`), targeted Hellos unicast; TCP listener + active connects driven by `EstablishTransport` (connect failures return the peer to the engine for a retry on the next Hello); `[[ldp.bind]]` FEC-label pairs advertised downstream-unsolicited and re-advertised on every fresh SessionUp; self-Hello protection (PDUs carrying our own LDP Identifier are dropped); runtime API status counters; verified two-daemon over a veth pair (`tests/interop/ldp.sh`) and against FRR 10 ldpd (`tests/interop/ldp_frr.sh` — lr learns FRR's imp-null connected-FEC binding, FRR learns lr's explicit binding) |
| RFC 7552 IPv6 dual-stack procedures | ✅ 🧪 | §5.1 IPv6 basic discovery (ff02::2 link Hellos, hop-limit-255 GTSM check, link-local sources), §5.2 targeted over global unicast only (link-local rejected at config parse), §6.1 Dual-Stack capability TLV (0x0701) with the TR transport-connection preference (LDPoIPv6 default per §6.1.1), per-family Transport Address TLV handling (same-AF only, first-per-family accepted from noncompliant senders), one session per LDP Identifier, §6.1.1 dual-stack role decision (noncompliant both-AF/no-capability neighbours never get a session, preference mismatch resets with the fatal 0x32 notification), §7.1 per-family Address-message scoping, §7 IPv6 FEC bindings never advertised to legacy v4-only peers; single-stack IPv6 speakers supported; daemon: dual-stack UDP/TCP transports with a V6ONLY=0 listener; 13 unit tests + 3 loopback v6 e2e; FRR 10 ldpd dual-stack interop (`tests/interop/ldp_frr_v6.sh`) — session over the IPv6 transport (TR=6 both sides), IPv4 bindings exchanged both ways, IPv6 FEC (fd00:99::/64) learned from FRR's ipv6 address-family. LDPoIPv6 session TCPs send with hop limit 255 (RFC 7552 §9 / RFC 6720 — FRR enforces GTSM on AF_INET6 sessions by default and dropped the pre-fix 64-hops SYN-ACKs with TcpExtTCPMinTTLDrop); listener, accepted sockets and active connects all set it |
| Kernel MPLS mirror + label range allocation | ✅ 🧪 | `[ldp] install_kernel` mirrors the LIB into the Linux AF_MPLS dataplane — pop route per local binding (tail, local delivery via `lo`) and encap route per learned binding (head, pushing the peer's label toward its transport address); MappingWithdrawn and session teardown reverse both halves, graceful shutdown cleans up. `[ldp] label_min/label_max` (16..=1048575, fail-closed validation) drive automatic allocation for label-0 binds — the first free value inside the range, exhaustion is a startup error; `tests/interop/ldp.sh` phase 3 asserts kernel LSP state on both LSRs, an end-to-end ICMP echo through the LSP, and teardown reverting the encap route (gated on `mpls_router`) |
| §3.5.7.1.1 transit-LSR label allocation (independent control) | ✅ 🧪 | the engine allocates one local label per FEC learned from peers (platform range 16..=1048575, explicitly configured bind labels reserved), re-advertises it upstream to every operational peer with the §3.4.4.1 incremented hop count (unknown stays unknown; 255 stops propagation) and the §A.2.6.4 Path Vector + own LSR Id when loop detection is on, answers Label Requests with it, and re-pushes the full transit LIB on every fresh SessionUp; egress FECs (locally bound) are excluded, a FEC whose last non-reflected downstream binding disappears is withdrawn upstream and its label recycled. Next-hop selection without an IGP view: the first peer that advertised the FEC wins (bindings propagate outward from the egress, so the first mapping is causally the closest to it); on its loss the fallback picks the lowest LDP Id among *non-reflected* bindings only (arrived before the local allocation — a post-allocation mapping is the upstream echo of our own advertisement, and using it would loop the exchange); if none remains the LSP is torn down and reflected bindings are released. FEC keys are normalized to the §3.4.1.1 wire form (host bits never fit the encoding). Engine state surfaces as `TransitSwapChanged` / `TransitSwapRemoved` / `TransitLabelExhausted`; the daemon mirrors the swap into the kernel (`MplsRoute::swap` via a cached FIB lookup for the output interface, routed peers refused with a note) and exposes `ldp-transit-labels` in the runtime API; `[ldp] transit_allocation` (default on) / `--ldp-no-transit` disable it. Verified by a three-speaker loopback e2e (allocation, hop-count propagation, withdrawal cascade + label reuse, bind exclusion, transport-close teardown) and `tests/interop/ldp.sh` phase 3c: r2 — the middle LSR of a three-LSR chain — transit-allocates for r3's FEC and re-advertises to r1, r3's death tears the LSP down, and with kernel MPLS an ICMP echo crosses the full r1→r2(swap)→r3 LSP (gated on `mpls_router`) |
| RFC 3478 graceful restart (LDP GR) | ✅ 🧪 | FT Session TLV (RFC 3479 §8.2: type 0x0503, L flag, Reconnect Timeout + Recovery Time in ms) carried in the Initialization when `[ldp] graceful_restart` / `--ldp-graceful-restart` is on (off by default — FRR parity); as the SURVIVING peer (§3.3): an unexpected session failure (transport closed / keepalive expiry — a deliberate Shutdown never retains) keeps the failed peer's bindings and the kernel LSPs programmed, marked stale for min(peer's Reconnect Timeout, local Neighbor Liveness); on reconnection the peer's fresh Recovery Time decides — zero deletes the stale bindings immediately (MappingWithdrawn reverts the dataplane, the peer's re-advertisements relearn) while non-zero moves them into a recovery window (min(peer Recovery Time, local Maximum Recovery Time)) where re-arriving mappings refresh them and the leftovers are deleted at expiry. As the RESTARTING speaker the daemon honestly advertises Recovery Time 0 (its kernel mirror is deleted on shutdown); `[ldp] gr_reconnect_ms` (default 15000) and `gr_recovery_ms` (default 0) shape the advertisement. Verified by loopback e2e: retention on transport close (no withdrawal, label kept), zero-recovery purge + relearn with label reuse, recovery window without withdrawal, reconnect-window expiry purging the stale LSP |

## Layer 3 — router pipeline (`lr-router`)

| Capability | Status | Notes |
|-----------|:------:|-------|
| Adj-RIB-In → safety → import hooks → best-path → Loc-RIB → export hooks → Adj-RIB-Out | ✅ 🧪 | full pipeline, per-session attribution |
| Initial table dump on session establishment + End-of-RIB | ✅ 🧪 | BIRD/FRR see convergence markers; inbound EoR drives restart resynchronization |
| Session-down Adj-RIB-In purge (RFC 4271 §8.2.2 semantics) | ✅ | routes do not outlive their session — except negotiated RFC 4724/9494 retention |
| Reconnect-safe session restart | ✅ | FSM reset + established-latch clear |
| OSPF/Babel delta integration into Loc-RIB | ✅ | |
| Cross-protocol administrative distance merge | ✅ 🧪 | |
| Route reflection fan-out, originate/unoriginate APIs | ✅ | |
| Concurrent daemon access — RwLock read/write split (ROADMAP-v3 D8.1) | ✅ 🧪 | the shared daemon handle is `Arc<RwLock<DefaultRouter>>`: read-only call sites (API `routes`/`status`/`sessions` dumps, session summaries, Babel RTT probes, OSPF/LSDB status views) take the read lock and run concurrently with each other; mutating call sites (session setup, `feed_input`, event polling, best-path reselection, redistribution, Babel GC, config reload) take the write lock; all 81 call sites classified (16 read / 65 write) and policed by the borrow checker — `DefaultRouter` has no interior mutability, so `&self` is genuinely read-only; `lr-policy` hook traits gained `Sync` supertraits so read guards can share the router across threads; per-AFI Loc-RIB sharding (D8.2) and the async event loop (D8.3) remain queued |

## Layer 4 — system integration (`lr-osroute`)

| Capability | Status | Notes |
|-----------|:------:|-------|
| Linux rtnetlink add/delete/list | ✅ 🧪 | used by `lr-daemon --install-kernel-routes` |
| Linux AF_MPLS netlink LSP install/delete | ✅ 🧪 | `lr-osroute::mpls_route` — Pop (label→IP), pop-local (label→`lo`, the kernel's own explicit-null shape for local delivery) and Swap (label→label) via `RTM_NEWROUTE`/`RTM_DELROUTE` with `RTA_DST`/`RTA_VIA`/`RTA_NEWDST`/`RTA_OIF`; LSP head-end encap routes (`RTA_ENCAP_TYPE = LWTUNNEL_ENCAP_MPLS` + nested `MPLS_IPTUNNEL_DST`, the `ip route add … encap mpls` form); netlink label attributes encode control-plane style (TTL/TC clear, BOS on the last entry, implicit-null refused — `nla_get_labels` rules); `RTA_VIA` family in host byte order (kernel `nla_put_via`/`nla_get_via`); `/proc/sys/net/mpls/platform_labels` capability detection; per-`MplsNetlink` socket, error decoding (EPERM/ENOENT/EEXIST/EOPNOTSUPP) |
| TCP MD5 / TCP-AO socket auth | ✅ 🧪 | `lr-osroute::tcp_auth` — arm_listener (wildcard keys) + connect_auth (keys before connect, signed SYN); Linux both, other platforms Unsupported |
| BSD route(4) socket (FreeBSD/NetBSD/OpenBSD/macOS) | ✅ | layouts pinned per-OS; cross-compile checked |
| Windows IP Helper API | ✅ | full link verified (x86_64-pc-windows-gnu) |
| Interface auto-resolution when `if_index == 0` | ✅ | gateway-based (Linux), longest-prefix (Windows) |
| Other systems | ✅ | documented extension path — see `docs/OS-INTEGRATION.md` |

## Layer 5 — embedder surface

| Capability | Status | Notes |
|-----------|:------:|-------|
| `lr-daemon` reference daemon (TCP I/O loop, reconnect, TOML incl. policy tables) | ✅ 🧪 | multi-peer (`[[peer]]` TOML tables / repeatable `--peer`): per-peer AS/hold-time/GR/auth/GTSM/max-prefix/Add-Path/families with `[bgp]` inheritance, one connector thread per outbound peer, listener matches inbound connections to peers by source address (fail-closed), centralized event consumption preserving Loc-RIB ordering; signals (SIGTERM/SIGINT graceful, SIGHUP reload), privilege drop, runtime API; `--protocol ospf` mode: `[[ospf.interface]]`/`[[ospf.area]]` config (stub/NSSA, no-summary, dotted-quad area IDs), dynamic per-`(area, router-id)` neighbor sessions, Hello origination, dead timer, per-area Router-LSA self-origination, raw-socket transport (above); `--protocol ldp` mode: `[[ldp.interface]]`/`[[ldp.targeted]]`/`[[ldp.bind]]` config, UDP 646 multicast discovery + TCP 646 sessions around `LdpEngine`, per-interface Hello egress, self-Hello protection, LDP counters in the API status; `--install-kernel-routes` mirrors best routes into the kernel: plain IP FIB plus, for BGP-LU routes, the RFC 8277 LSP endpoints (tail pop for originated labels, head encap for received stacks, implicit-null left to PHP) |
| Native BIRD/FRR config run (compat surface) | ✅ 🧪 | `lr-daemon --config bird.conf\|frr.conf`: dialect auto-detection (BIRD 2 / FRR / lr TOML, `--config-dialect` override, fail-closed on unknown content), the W5.1 converter pipeline feeds the regular TOML loader (one mapping, no drift), dialect-correct defaults (accept-all eBGP policy both, FRR `enforce-first-as` on), lr-specific `lr:` comment-directive extensions (globals + per-peer, invisible to real BIRD/FRR), unmapped constructs and non-BGP stanzas surface as startup warnings, SIGHUP/API reload re-parses through the same dialect path; **BIRD filters** (ROADMAP-v3 D14.1): `filter`/`function`/`define`/`roa table` blocks translate into `[[filter]]` bodies with the operator mapping verified against BIRD's own grammar (`=`→`==`, `:=`→`=`, attribute renames, ROA literals, typed decls→`let`), fail-closed per filter (unfaithful constructs leave the filter unemitted and reported; compile + AST variable backstops), `import|export filter NAME`/`where EXPR` wire to peers, inline channel bodies split into statements; **BIRD babel** (D14.2): `protocol babel` interface blocks map the RFC 8966 §A.2 parameters onto `[[babel.interface]]` (type/kind, rxcost, rtt cost/min/max with BIRD's time grammar, check link, extended next hop, port, protocol-level next-hop backfill); **BIRD `!~`** (D14.5): the not-match operator passes through verbatim — the lr DSL lexer gained `TokenKind::BangTilde` mapped to `BinaryOp::NotMatch` (the AST/evaluator/bytecode VM already lowered it to `Match { negated: true }`); **BIRD `case`** (D14.6): `case expr { pat: body; else: body; }` translates via a structural pre-pass (`rewrite_cases`) that converts `:`→`=>`, `else:`→`default =>`, wraps non-block arm bodies in `{ … }` (lr DSL case arm bodies parse a single statement), leaves block arm bodies as-is, handles nested cases recursively, and fail-closes on range arms (`a .. b:`) which have no lr equivalent; `daemon_compat.rs` E2E + `tests/interop/compat_{bird,frr}.sh` against real BIRD 2 / bgpd (see `docs/COMPAT.md`) |
| C ABI FFI (`lr-ffi`) + cbindgen header | ✅ 🧪 | C harness in CI |
| Go bindings | ✅ 🧪 | `bindings/lr-go` |
| Python bindings | ✅ 🧪 | `bindings/lr-python` (cffi) |
| C++ bindings | ✅ | header-only RAII wrapper over the C ABI (`include/librouting.hpp`) |
| Signal handling / privilege drop / config reload / runtime API in daemon | ✅ 🧪 | SIGTERM/SIGINT close sessions with a NOTIFICATION (RFC 4271 §6.4) then exit 0; SIGHUP + API `reload` re-apply `networks` (bad config keeps running); `--user`/`--group` setuid/setgid after bind; `--api-socket` Unix-socket management plane (status/sessions/routes/reload/shutdown); `daemon_runtime.rs` E2E |

## Testing & CI

| Item | Status |
|------|:------:|
| Unit tests (workspace) | ✅ 42 binaries / 900+ tests |
| Two-daemon TCP E2E | ✅ 🧪 | `lr-tests/tests/tcp_smoke.rs` |
| Route-propagation E2E (originate → Adj-RIB-In → Loc-RIB → Adj-RIB-Out, withdrawal reversal) | ✅ 🧪 | `lr-tests/tests/route_propagation.rs` |
| Protocol-runtime E2E (OSPF + Babel delta integration into Loc-RIB) | ✅ 🧪 | `lr-tests/tests/protocol_runtimes.rs` |
| Add-Path E2E (two-daemon + full-stack multi-path propagation) | ✅ 🧪 |
| BGP session-mode E2E (8 modes: standard dual-stack, LL dual-stack, MP-BGP, MP-BGP+LL, ENH, ENH+LL, pure IPv6, pure IPv6+LL) | ✅ 🧪 | `lr-tests/tests/bgp_session_modes.rs` |
| RFC 8277 BGP-LU E2E (single-label, multi-label, implicit-null, withdrawal) | ✅ 🧪 | `lr-tests/tests/bgp_labeled_unicast.rs` |
| RFC 8277 two-daemon interop (TCP, label=100 for 198.51.100.0/24) | ✅ 🧪 | `tests/interop/labeled_unicast.sh` |
| BGP-LU → MPLS dataplane interop (two netns: tail pop + head encap mirrored into the kernel, ICMP echo through the LSP; kernel-gated) | ✅ 🧪 | `tests/interop/mpls_lsp.sh` |
| GTSM + maximum-prefix E2E (TTL security + per-peer prefix limit) | ✅ 🧪 | `lr-tests/tests/gtsm_max_prefix.rs` |
| Redistribution E2E (BGP↔BGP, BGP→OSPF, metric policy, prefix filter, withdrawal) | ✅ 🧪 | `lr-tests/tests/redistribution.rs` |
| Route-aggregation E2E (aggregate origination/withdrawal lifecycle) | ✅ 🧪 | `lr-tests/tests/route_aggregation.rs` |
| BMP monitoring E2E (Peer Up/Down + Route Monitoring end-to-end) | ✅ 🧪 | `lr-tests/tests/bmp_monitoring.rs` |
| Daemon hardening E2E (signals, reload, runtime API, privilege drop) | ✅ 🧪 | `lr-cli` integration tests |
| Cross-protocol daemon E2E (`[[redistribute]]` allow-list through the pipe, `[[aggregate]]` reaching a downstream peer) | ✅ 🧪 | `crates/lr-cli/tests/daemon_redistribute.rs` |
| OSPF two-daemon E2E (raw-socket multicast adjacency, stub-net propagation both ways, dead-timer teardown) | ✅ 🧪 | `tests/interop/ospf.sh` — veth pair, one network namespace per daemon, rootless via `unshare -Urn` |
| OSPF broadcast-segment E2E (§9.4 DR/BDR election, §10.4 adjacency, Network-LSA + transit links, BIRD default-broadcast interop) | ✅ 🧪 | `tests/interop/ospf_broadcast.sh` — phase 1: two lr-daemons; phase 2: lr ↔ BIRD 2 on BIRD's default (broadcast) type |
| OSPF x BIRD E2E (real DBD/LSR exchange to Full adjacency, stub nets propagated in BOTH directions via birdc) | ✅ 🧪 | `tests/interop/ospf_bird.sh` — lr-daemon ↔ BIRD 2 over a veth pair |
| Babel MAC auth E2E (two-daemon: propagation, restart challenge resync, wrong-key fail-closed, RFC 8967 §5 incremental deployment) | ✅ 🧪 | `tests/interop/babel_auth.sh` — IPv4 multicast over loopback, rootless netns |
| LDP two-daemon E2E (multicast link-Hello discovery over a veth pair, TCP 646 session, bindings both directions, hold-time teardown) | ✅ 🧪 | `tests/interop/ldp.sh` — rootless netns, one LSR per namespace |
| LDP transit-LSR E2E (three-LSR chain: middle LSR transit-allocates and re-advertises upstream, peer death tears the LSP down and withdraws it; kernel-gated ICMP echo across the full r1→r2(swap)→r3 LSP) | ✅ 🧪 | `tests/interop/ldp.sh` phase 3c |
| MRT interop (BIRD 2 `protocol mrt` dump decoded by `lr mrt rib`; daemon Loc-RIB export round-trip with AS path + next hop) | ✅ 🧪 | `tests/interop/mrt.sh` |
| BMP collector E2E (daemon `--bmp-target` mirroring Peer Up + Route Monitoring to a daemon collector; routes + MRT dump via API) | ✅ 🧪 | `tests/interop/bmp.sh` |
| Multi-peer daemon E2E (two-outbound-peer fan-out + transit, inbound source-address matching, fail-closed rejection of unmatched peers, per-peer hold-time inheritance) | ✅ 🧪 | `crates/lr-cli/tests/daemon_multi_peer.rs` |
| Policy-in-config E2E (export filter, import filter, set-actions keep-route, unknown-reference fail-closed startup) | ✅ 🧪 | `crates/lr-cli/tests/daemon_policy.rs` |
| RFC 8212 E2E (default deny-in/deny-out, permit-all route-maps restoring flow, accept-all deviation, iBGP exemption, unknown mode fails closed) | ✅ 🧪 | `crates/lr-cli/tests/daemon_rfc8212.rs` (in-process) + `tests/interop/rfc8212_bird.sh` + `tests/interop/rfc8212_frr.sh` (D10.6 — real BIRD 2 + FRR bgpd, two-phase: default deny + explicit policy restores flow) |
| MD5 auth interop (two-daemon positive/negative + BIRD `password` + FRR `neighbor password`) | ✅ 🧪 |
| TCP-AO interop (two-daemon positive/negative; kernel >= 6.7, else SKIP) | ✅ 🧪 |
| Kernel-gated tests in a QEMU VM (tests/vm: tcp_ao + MPLS dataplane phases without host kernel/root support) | ✅ 🧪 |
| OSPF multi-area + ABR inter-area E2E (incl. two-router propagation) | ✅ 🧪 |
| OSPF external-route E2E (type-5 AS-scope propagation, type-4 ASBR legs, §16.4 type-1/2 + forwarding address, flush lifecycle) | ✅ 🧪 |
| OSPF stub/NSSA E2E (stub/totally-stubby gating + default injection, NSSA type-7 + P-bit translation with forwarding address, type-7/type-3 defaults, no-summary, translator election, flush lifecycle) | ✅ 🧪 |
| OSPF virtual-link E2E (§15 backbone partition repair, summaries over the virtual adjacency, teardown + stale-LSA MaxAge age-out, stub-transit refusal) | ✅ 🧪 |
| OSPFv3 two-daemon E2E (RFC 5340: v3 Hello/DBD/LSR to Full, Router/Link/Intra-Area-Prefix LSAs, IPv6 propagation both directions, dead-timer withdrawal) | ✅ 🧪 | `tests/interop/ospf6.sh` |
| OSPFv3 x FRR ospf6d E2E (RFC 5340 wire shapes to Full both ways, link-local next hops, dead-timer teardown) | ✅ 🧪 | `tests/interop/ospf6_frr.sh` |
| OSPFv3 broadcast E2E (RFC 5340 §4.1.2 election on Router-ID identity, Network-LSA vertex routing, the DR's network-referenced IAP, dead-timer retraction) | ✅ 🧪 | `tests/interop/ospf6_broadcast.sh` — two lr-daemons on `network_type = "broadcast"`; r2 (higher Router ID) wins DR, routes resolve through the network vertex both directions, the non-DR carries the shared-segment prefix only via the DR's network IAP |
| OSPFv3 broadcast x FRR ospf6d E2E (independent §9.4 elections converge; transit links + Network-LSA + network IAP parsed by both) | ✅ 🧪 | `tests/interop/ospf6_frr_broadcast.sh` — lr ↔ FRR 10.3 ospf6d on FRR's default broadcast type; FRR's vty and lr's log agree on DR 2.2.2.2 / BDR 1.1.1.1; lr resolves FRR's loopback through the network vertex onto a link-local; SIGKILL teardown |
| OSPFv3 SRv6 E2E (RFC 9513 slice 3: ospf6d stores + re-floods lr's RI/Locator LSAs, lr2 installs the locator through the FRR relay as an Ospfv3 route) | ✅ 🧪 | `tests/interop/ospf6_frr_srv6.sh` |
| BIRD 2 interop (bidirectional) | ✅ 🧪 |
| BIRD 2 LLGR interop (RFC 9494 full lifecycle, both helper roles) | ✅ 🧪 |
| BFD monitoring fast-fail E2E (two-daemon SIGSTOP freeze: BFD tears BGP down in ~0.5s at 100ms×3 vs 60s hold) | ✅ 🧪 | `crates/lr-cli/tests/daemon_bfd.rs` |
| BFD x BIRD interop (single-hop + multihop sessions, `protocol bfd` + `bfd on`, SIGSTOP fast-fail) | ✅ 🧪 | `tests/interop/bfd_bird.sh` |
| FRR bgpd interop (bidirectional) | ✅ 🧪 |
| FRR ldpd interop (RFC 5036: adjacency, session to Operational, imp-null learned from FRR, lr's explicit binding in FRR's LIB) | ✅ 🧪 | `tests/interop/ldp_frr.sh` — zebra + ldpd in a rootless netns |
| C / Go / Python binding harnesses | ✅ 🧪 |
| fmt + clippy (-D warnings) | ✅ |
| Cross builds: aarch64-linux-gnu, x86_64-windows-gnu (full link), freebsd/netbsd (check) | ✅ |
| Coverage (tarpaulin) | ✅ |
| MSRV 1.88 build | ✅ |
| `cargo audit` (RustSec advisories, nightly) | ✅ | `.github/workflows/nightly.yml` `supply-chain` job |
| `cargo deny` (advisories + licenses + bans + sources, nightly) | ✅ | `deny.toml` at repo root |
| Dependabot (cargo + github-actions, weekly grouped PRs) | ✅ | `.github/dependabot.yml` |

## Roadmap v1 — complete

The original 15-item production roadmap is finished. In order:
graceful restart (RFC 4724) + LLGR (RFC 9494); OSPF LSA refresh/ABR
summaries (§12.4.3, §16.2); Babel HMAC (RFC 8967); BGP MD5/TCP-AO
(RFC 2385/5925); daemon hardening (signals, privilege drop, runtime
API); RFC 7911 Add-Path end-to-end; OSPF type-5/type-4 external routes
(§16.4); OSPF stub/NSSA areas (RFC 3101); OSPF virtual links (§15);
BGP dual-stack/MP-BGP/ENH session modes (RFC 5549, 8 modes e2e); OSPF
authentication (RFC 5709/7166) + OSPFv3 inter-area; BGP GTSM (RFC 5082)
+ maximum-prefix; cross-protocol redistribution; Babel daemon parity
(IPv6 link-local + RFC 9079 completion); BMP monitoring (RFC 7854).
BGP route aggregation (RFC 4271 §9.2.2.2) landed as a bonus item.
Per-item details live in the git history; the capability tables above
reflect the current state.

## Roadmap v2 — toward a complete routing stack

Six workstreams. Every item except the SR-MPLS placeholder has
landed; the per-item narratives (design decisions, evidence, the bugs
flushed out) live in [`ROADMAP.md`](ROADMAP.md) — this section tracks
the state, that file tracks the how and why.

| Workstream | Scope | State |
|------------|-------|-------|
| W1 — a complete daemon | multi-peer BGP daemon, config, runtime API, privilege drop, MRT/BMP, LDP/OSPF/Babel daemon modes | complete — see [`ROADMAP.md` §W1](ROADMAP.md#w1--a-complete-daemon-lr-daemon) |
| W2 — BIRD/FRR non-standard compatibility | RFC 8212 default-policy parity, FRR `default ipv4-unicast`, GTSM knobs, ENH defaults, `supported_grace_time`, MRT/BMP shape parity | complete — see [`ROADMAP.md` §W2](ROADMAP.md#w2--bird--frr-non-standard-compatibility-selective) |
| W3 — RFC coverage gaps | §6.8 collision, RFC 8212, OSPF DBD/LSR exchange, OSPF graceful restart (3623), RFC 7684, Babel MAC (8967/9467), BGP-LU (8277), MPLS dataplane, YANG models (9647/8177) | complete — see [`ROADMAP.md` §W3](ROADMAP.md#w3--rfc-coverage-gaps-from-rfc_mapmd) |
| W3-extra — comprehensive MPLS | label codec (3032), BGP-LU dataplane mirror, LDP (5036) + dual-stack (7552) + transit allocation + loop detection + GR (3478), kernel mirror, SR-MPLS slices 1–3 (RFC 8665/8660/8661) | SR-MPLS complete; SRv6 slices 1-3 (data plane + OSPFv3 SRv6 control plane + daemon origination, RFC 9513) landed — see [`ROADMAP.md` §W3-extra](ROADMAP.md#w3-extra--comprehensive-mpls-support-new) |
| W4 — documentation | tutorial, per-protocol deep dives, binding guides, runbook | complete — see [`ROADMAP.md` §W4](ROADMAP.md#w4--documentation-guides-tutorials) |
| W5 — compatibility layer | `translate bird\|frr`, native BIRD/FRR config run (compat surface), capture/replay parity harness, VM test harness | complete — see [`ROADMAP.md` §W5](ROADMAP.md#w5--compatibility-layer) |
| W6 — research: BGP defects + exchange plane | BGP-DEFECTS + EXCHANGE-PLANE research docs, exchange-plane prototype (feature-gated, IANA experimental range) | prototype landed behind `exchange-plane` (off by default) — see [`ROADMAP.md` §W6](ROADMAP.md#w6--research-bgp-defects-and-a-private-exchange-plane) |

**Remaining open items** (nothing else is queued):

1. **SRv6 (RFC 8754 / RFC 8402 / RFC 8986)** — slices 1-3 have
   landed: slice 1, the data-plane codec + kernel mirror (`lr-srv6`
   provides the SID/Locator/SRH codec + the RFC 8986 behavior
   registry; `lr-osroute::seg6_route` installs `seg6`/`seg6local`
   routes via Linux netlink). Slice 2, the control-plane extensions:
   the OSPFv3 SRv6 extensions of RFC 9513 (the repo previously cited
   RFC 9352, which is the IS-IS SRv6 sibling — corrected) — the
   codec, the per-node SRv6 database, locator routes in the v3 SPF
   and the fail-closed `ospf_srv6_receive` router gate. Slice 3, the
   daemon surface: `[[ospf.srv6_locator]]` config + per-area
   origination of the RFC 9513 Router Information LSA (Capabilities /
   SR-Algorithm / Node MSD) and the Locator LSA (End SIDs + optional
   §10 SID Structure), plus the `[ospf] srv6_receive` reception gate
   on the daemon path; FRR 10.3 ospf6d (no SRv6 support) stores and
   re-floods the LSAs and a third lr installs the locator through
   that relay (`tests/interop/ospf6_frr_srv6.sh`). Slice 4, the
   adjacency SIDs: End.X (RFC 9513 §9.1) and LAN End.X (§9.2) codecs
   ride the RFC 8362 E-Router-Link TLV's sub-TLV region (registry
   types 31/32, SID Structure as 30), the srv6db projects them gated
   on §9 locator containment + algorithm match, and the daemon
   originates the p2p form per `[[ospf.interface]] srv6_end_x` plus
   the broadcast forms — the §9.1 sub-TLV for the DR adjacency and
   one §9.2 LAN End.X per Full BDR/DR-Other neighbor derived from
   `[[ospf.interface]] srv6_end_x_lan` as `base | Router-ID` —
   sparse-mode companion E-Router-LSA under legacy mode, in-LSA under
   `extended_lsas` (`tests/interop/ospf6_e_lsa_endx.sh`,
   `tests/interop/ospf6_e_lsa_endx_lan.sh`). Still open:
   BGP-LS / BGP SR Policy (RFC 9256 / 9430).
   (`ROADMAP.md` W3-extra — "Slice 5 — OSPFv3 SRv6 control plane".)
2. **OSPFv3 daemon depth** — slices 1-2 landed: the daemon runs v3 end
   to end (adjacency, v3 LSDB exchange, v3 SPF, IPv6 route
   publication, kernel mirror), interoperates with FRR 10.3
   ospf6d, and the route calculation now covers inter-area summaries
   (0x2003), inter-area ASBRs (0x2004) and AS externals (0x4005) with
   ABR summary origination and v6 external redistribution (see the
   RFC 5340 rows above). Slice 3 landed: broadcast segments — the
   RFC 5340 §4.1.2 interface FSM over the §9.4 DR/BDR election on
   Router-ID identity, Hello DR/BDR fields, Router-LSA transit links,
   the DR's Network-LSA and the network-referenced
   Intra-Area-Prefix-LSA, interoperating live with FRR ospf6d's
   default broadcast type (`tests/interop/ospf6_broadcast.sh`,
   `tests/interop/ospf6_frr_broadcast.sh`). Slice 4 landed: OSPFv3
   graceful restart (RFC 5187) — helper + restarting router, verified
   against FRR ospf6d (`tests/interop/ospf6_gr.sh`,
   `tests/interop/ospf6_gr_frr.sh`). No v2-only daemon feature
   remains; the v3 codec + LSA + SPF surfaces are in the capability
   tables above.
3. **Phase 4 — pre-1.0 hardening** — landed: cross-platform CI
   matrix (Ubuntu, macOS Intel, macOS Apple Silicon, Windows
   x86_64-MSVC) running `cargo fmt`, `cargo clippy -D warnings`,
   `cargo build --workspace --all-features`, and
   `cargo test --workspace --all-features` on each runner in
   `.github/workflows/ci.yml` (the Linux-only interop suite stays
   on its existing `interop` job; the Windows/macOS runners skip
   the Linux-only kernel-gated tests at the file level via
   `#![cfg(target_os = "linux")]`). `docs/lr-cli.md` and
   `docs/lr-cli-internals.md` document every CLI subcommand and
   the daemon's module layout + extension patterns.
   `docs/RELEASE-PLAN.md` defines the semver policy, the
   three-tier API stability contract, the 1.0 freeze criteria,
   the release flow, and the post-1.0 governance rules.
   `.github/workflows/release.yml` builds `lr-ffi` on the four
   native targets and assembles them into a single draft GitHub
   Release with auto-generated commit-diff notes. The 1.0 cut PR
   is the next release-event after one clean week of CI on all
   three platforms.
4. **Phase 5 — CI matrix hardening + documentation expansion** —
   landed: dropped `macos-13` (Intel) from the cross-platform
   matrix (GitHub Actions retired the Intel runner pool; the
   runner was queued-for-hours every CI run since Phase 4 landed
   while the same code paths ran green on `macos-14`). Added a
   new `cross-macos-intel` job that cross-compiles
   `x86_64-apple-darwin` from a `macos-14` runner (the universal
   Apple clang targets both arches natively), so Intel macOS
   compilation is still covered. Filled the example-doc gaps with
   three new walkthroughs: `docs/examples/ldp_basic.md` (RFC 5036
   LDP label distribution + the kernel MPLS dataplane mirror),
   `docs/examples/bgp_labeled_unicast.md` (RFC 8277 BGP-LU → MPLS
   dataplane, the LSP tail/head classification), and
   `docs/examples/ospfv3_srv6.md` (RFC 9513 OSPFv3 SRv6 — the
   RI LSA + Locator LSA origination signatures and the
   `srv6db` reception path). Indexed all three in
   `docs/README.md`.
5. **Phase 6 — E-LSA design doc + RUNBOOK expansion + code
   audit** — landed: `docs/research/E-LSA-DESIGN.md` is the
   implementation plan for the RFC 8362 Extended-LSA machinery
   (Phase 3 item 2's prerequisite), laying out the function
   codes (0xA020–0xA026), the TLV framing, the seven E-LSA body
   codecs, the U-bit-2 flooding rules, the SPF integration plan,
   the End.X SID sub-TLV design (RFC 9513 §9), the interop
   verification plan, and the three-slice breakdown (codecs →
   SPF → End.X origination). Expanded `docs/RUNBOOK.md` with a
   "Deeper troubleshooting" section covering BGP session flapping,
   OSPF adjacency stuck in ExStart/Exchange, LDP label binding
   not propagating, route flap damping tuning, memory growth on
   full-table peers, CPU spikes during reconvergence, and MRT
   dump disk growth. Code audit: replaced two `unwrap()` calls in
   `lr-core` (the IPv6-address dotted-quad parser and the timer
   heap's `pop()`) with explicit `match` / `expect()` patterns
   that document the safety invariant for the reader.
6. **Phase 7 — v1.0.0-rc.1 pre-release** — landed: bumped the
   workspace version from `0.1.0` to `1.0.0-rc.1`, tagged
   `v1.0.0-rc.1`, and triggered the `release.yml` workflow which
   built per-OS artifacts (Linux x86_64, macOS Intel + Apple
   Silicon, Windows x86_64-MSVC) and published them as a GitHub
   pre-release with 6 assets (4 tarballs/zip + 2 standalone
   headers). All §2 freeze criteria verified on the cut commit;
   CI 11/11 green, nightly 2/2 green. The 1-week clean-CI wait
   (RELEASE-PLAN.md §2.8) was skipped per the user's instruction:
   functionality is complete and no large code changes are
   expected before 1.0.0 (recent history is docs + CI + small
   fixes). Released as `rc.1` rather than the final `1.0.0` to
   test the never-exercised release workflow end-to-end and
   signal API freeze to the community. The final `1.0.0` follows
   after rc.1 artifacts are validated. Also fixed the `release.yml`
   matrix to use `macos-14` (Apple Silicon) for the Intel macOS
   cross-compile (the `macos-13` Intel runner was retired by
   GitHub Actions and was stuck queued on the first release run).
7. **Phase 8 — v1.0.0-rc.3 multi-protocol daemon** — landed: one
   `lr-daemon` process now runs a combination of BGP, OSPF (v2/v3)
   and Babel through a shared-router supervisor (`daemon_multi.rs`).
   `--protocol` became a set (repeatable + comma-separated; TOML
   `protocol = "a,b"` / `protocols = ["a","b"]`). The engines take an
   `Option<EngineHost>`: standalone keeps the classic path bit-for-bit
   (own router, ticker, API socket, privilege drop), embedded shares
   the supervisor's plumbing (one `DefaultRouter` = one shared
   Loc-RIB, one running flag, one ticker, one API socket, one thread
   per engine, per-engine startup gates between the socket binds and
   the privilege drop). Signal dispatch became supervised: the
   supervisor is the sole signal consumer, so connector threads and
   session pumps cannot steal SIGTERM from it. `lr-router` gained the
   cross-protocol Loc-RIB merge the shared router exposed as missing:
   protocol-direct contributions (OSPF/Babel runtime deltas) are
   tracked in a `direct_rib` map, chained into `reselect` (a BGP
   re-ranking can no longer evict them; a withdrawal falls back to
   the surviving protocol's contribution), keys with BGP-side
   candidates rank through the full preference order (BGP 20 < OSPF
   110 < Babel 120), and the BGP export path filters non-BGP routes so
   cross-protocol advertisement stays opt-in through redistribution
   pipes (FRR `redistribute` / BIRD `pipe` semantics). Direct installs
   also feed `redistribute_route` now, so Ospf/Babel to BGP pipes see
   protocol-direct sources. bmp/ldp combinations fail closed; a
   startup failure aborts the whole combination. The Babel main loop's
   busy-spin (a full core at idle) was fixed with a 10 ms idle sleep.
   Coverage: 5 new daemon-config unit tests, 3 new lr-router
   merge/pipe unit tests, 4 new lr-cli e2e tests, and the
   `tests/interop/multi_protocol.sh` lab (lr `--protocol bgp,ospf`
   versus one BIRD 2 process running ospf + bgp: Full adjacency +
   established BGP in both processes, the shared prefix prefers the
   BGP path in lr's merged RIB, no OSPF route leaks into lr's BGP
   advertisements, graceful whole-combination shutdown). Verified
   against BIRD 2.17.5 locally.
8. **Phase 9 — D9.2 Filter DSL formal grammar** — landed: the
   `docs/filter_dsl_grammar.md` reference document derives an
   ISO/IEC 14977 EBNF grammar directly from the lexer + Pratt
   parser source (`crates/lr-policy/src/filter/`). It covers the
   lexical structure (identifiers, reserved words, integer /
   string / IP / prefix literals, the full operator table with
   longest-match rules), the full statement + expression grammar
   (every production traced to its parser function), the operator
   precedence table mirroring `BinaryOp::precedence`, the route
   field reference (settable vs `+=`-only vs read-only), the
   `MAX_EXPR_DEPTH = 108` / `MAX_CALL_DEPTH = 64` limits, a
   worked-examples section covering accept-on-prefix, prefix-range
   membership, ROA gating, `case`, user-defined functions,
   community-set mutation, AS-path membership, extended- and
   large-community tuples, and a BIRD-comparison table. The
   companion `crates/lr-policy/tests/grammar_corpus.rs` test
   suite pins every example — positive cases compile through
   `lr_policy::filter::compile`, negative cases fail with the
   documented `ParseErrorKind` — so a doc/source drift fails CI
   rather than shipping. 30 tests across positive, negative and
   boundary cases. The grammar captured two real divergences
   from the older in-tree BIRD example doc
   (`docs/examples/filter_dsl_roa.md`): the function return-type
   annotation uses `=>` (the same `TokenKind::Arrow` as `case`
   arms), not BIRD's `->`; and AS-path `~` is currently flat
   set-membership, not BIRD regex (the `_` wildcard token is
   parsed by the lexer but does not yet carry meaning inside `~`
   patterns). Both are documented as current behaviour with
   follow-up pointers in ROADMAP-v3 D9.
9. **Phase 10 — D12.1 `lrctl` operational CLI** — landed: a third
   `lr-cli` binary (`crates/lr-cli/src/lrctl.rs`) connects to a
   running `lr-daemon` over its Unix API socket and proxies the
   line-oriented command protocol. Mirrors the existing `lr` /
   `lr-daemon` style (hand-rolled `env::args()` parsing, no clap
   dependency, `ExitCode` returns). Daemon-proxy surface:
   `lrctl status`, `lrctl sessions [list]`,
   `lrctl routes show [prefix]` (client-side prefix filter — exact
   match on the leading token so `203.0.113.0/24` does not also
   match `203.0.113.0/25`), `lrctl routes dump <path>` (writes an
   MRT dump via the daemon's `mrt PATH` command),
   `lrctl reload`, `lrctl shutdown`. Client-side surface:
   `lrctl filter compile <body>` reuses `lr-policy::filter::compile`
   directly so operators can validate a filter body before deploying
   — the same parser path the daemon runs at startup. Default
   socket path `/run/lr-daemon.api` matches `templates/daemon.toml`;
   `--socket PATH` overrides on any subcommand. Non-Unix targets
   refuse with a clear error (the runtime API requires Unix domain
   sockets). Exit codes: 0 success (or a `routes show <prefix>` with
   no match — FRR parity), 1 transport failure / daemon `error:`
   reply / filter parse error, 2 argument error. The release
   workflow stages `lrctl` alongside `lr` and `lr-daemon` in every
   platform archive (Linux x86_64, macOS Intel + Apple Silicon,
   Windows x86_64-MSVC). 10 e2e tests in
   `crates/lr-cli/tests/lrctl.rs` pin every subcommand including
   transport-failure and argument-error paths. `lrctl` is documented
   in `docs/lr-cli.md` (new `lrctl` section) and `docs/RUNBOOK.md`
   (cross-reference from the Runtime API section). `roa list` deferred
   — the daemon's `Runtime` struct does not carry a `RoaStore`
   reference today, so exposing it requires threading the store
   through `spawn_api` (a follow-up commit).
10. **Phase 11 — D12.2 Prometheus `/metrics` endpoint** — landed:
    the daemon gained an opt-in HTTP endpoint that serves the
    Prometheus text exposition format on `GET /metrics`
    (`crates/lr-cli/src/metrics.rs`). Hand-rolled HTTP/1.0
    responder — no `hyper` / `tokio` dependency, matching the
    project's stance on `api.rs`. Configuration: `--metrics-addr ADDR`
    CLI flag / `[bgp] metrics_addr = "…"` TOML key (default off,
    like `api_socket`); a bind failure is fatal (same stance as
    `spawn_api`). The thread model mirrors `api.rs`: one thread
    polls a `set_nonblocking(true)` `TcpListener` with a 100 ms
    sleep, each accepted connection served on its own short-lived
    thread so a slow client cannot hold the endpoint hostage. The
    router lock is held only for the duration of a single
    `session_summaries()` + `rib_len()` read, never for the
    network write. The exposition covers: `lr_info` (gauge=1 with
    `version` / `local_as` / `router_id` labels, for join
    queries); `lr_uptime_seconds`; `lr_sessions_total{kind,state}`;
    `lr_established_sessions{kind}` (with explicit-zero for kinds
    that have sessions but none established, so an alert joining
    on `kind` does not see a missing series);
    `lr_adj_rib_in_entries{kind}`; `lr_rib_entries`; and
    `lr_roa_entries` (omitted entirely when no ROA store is
    configured — a missing metric is more honest than a misleading
    zero). `GET /` returns a one-line pointer to `/metrics`,
    `GET /nonexistent` returns `404`, non-GET methods return
    `404`. The `Runtime` struct gained an optional
    `roa_len: Option<Arc<dyn Fn() -> usize + Send + Sync>>` field
    so the BGP daemon (which always builds a `RoaStore`) can
    expose the live count without holding a lock; OSPF/Babel/LDP/
    BMP/multi pass `None`. Wired into every daemon entry point
    (BGP, OSPFv2, OSPFv3, Babel, LDP, BMP, multi-protocol
    supervisor) via `spawn_metrics()`, paralleling `spawn_api()`.
    7 e2e tests in `crates/lr-cli/tests/daemon_metrics.rs` pin
    the exposition shape, the opt-in default, the 404 paths,
    non-GET rejection, scrape stability across two scrapes, and
    bind-failure fatality. Documented in `docs/RUNBOOK.md` (new
    "Prometheus `/metrics` endpoint" section with the metric
    table and a live scrape example), `docs/lr-cli.md`
    (`--metrics-addr` row in the daemon flag reference) and
    `templates/daemon.toml` (commented-out `metrics_addr` with
    the metric list). ~~Filter-eval latency histograms and UPDATE
    tx/rx counters remain open — they require per-session
    counters the daemon does not track today (a follow-up
    commit under D12).~~ Closed by Phase 14 (D12.4) below.
11. **Phase 12 — D12.3 container deployment** — landed: a
    multi-stage `Dockerfile` at the repo root builds the whole
    workspace in release mode with all features and ships the
    three CLI binaries (`lr`, `lr-daemon`, `lrctl`), `liblr_ffi.so`
    and the C / C++ headers into a `debian:bookworm-slim` runtime
    image. The builder stage pins `rust:1.88-slim-bookworm` (the
    workspace MSRV) and uses BuildKit mount caches on the cargo
    registry + target dir so a no-op rebuild is seconds, not
    minutes. The runtime stage is `debian:bookworm-slim` — the
    glibc baseline matches the builder so the dynamically linked
    `liblr_ffi.so` and CLI binaries load without a compatibility
    shim. The image creates a non-root `lr` user, `EXPOSE`s
    `179/tcp` (BGP) and `9119/tcp` (Prometheus metrics — matches
    the example address in `docs/RUNBOOK.md` and
    `templates/daemon.toml`), declares `VOLUME /etc/lr-daemon`
    (config mount) and `VOLUME /run/lr-daemon` (API socket mount
    for the `lrctl` sidecar pattern), and uses
    `ENTRYPOINT ["lr-daemon"]` with `CMD ["--help"]` so a bare
    `docker run` prints the usage banner instead of crashing. The
    image does NOT ship a default config (operators mount one or
    pass CLI flags) and does NOT push to a registry from CI (that
    is a release-event concern). The `.dockerignore` keeps the
    build context lean (excludes `target/`, editor state, Python /
    Go binding build artifacts, fuzz corpus, `.git/`, etc.). The
    `docker/README.md` deployment guide covers quick start,
    production config-file mount, sidecar `lrctl`, image layout,
    exposed ports, volumes, the ~100 MB size target, and what the
    image does NOT include (no default config, no Helm chart, no
    BIRD/FRR, no process supervisor). The
    `.github/workflows/docker.yml` CI workflow builds the image on
    every push / PR / nightly, runs the three CLI binaries with
    `--help` / `version`, verifies `liblr_ffi.so` is loadable via
    `ldconfig -p`, and reports the image size. Helm chart deferred
    — a Helm chart conventionally lives in its own repository so
    it can version independently of the image; the Dockerfile here
    is the foundation a chart would reference.
12. **Phase 13 — D10.6 RFC 8212 interop + D9.6 FFI design doc**
    — landed: two interop scripts verify lr-daemon's default
    RFC 8212 eBGP policy against real BIRD 2 and FRR bgpd.
    `tests/interop/rfc8212_bird.sh` and
    `tests/interop/rfc8212_frr.sh` each run two phases: Phase 1
    (default mode, no explicit policy) asserts the session reaches
    Established but BIRD/FRR does NOT learn lr-daemon's route and
    lr-daemon does NOT install BIRD/FRR's route — the RFC 8212
    import-deny and export-deny are both exercised; Phase 2
    (explicit permit-all route-maps) asserts the route flows both
    directions, confirming the RFC-intended escape hatch. The
    startup warnings (`no export route-map; announcing nothing
    (RFC 8212)` and `no import route-map; discarding received
    routes (RFC 8212)`) are pinned as Phase 1 assertions. Both
    scripts are wired into the CI interop job. The scripts
    gracefully SKIP when `bird`/`birdc` or `bgpd` are not on
    `$PATH` (same pattern as every other interop script). The
    in-process `daemon_rfc8212.rs` tests (the original D10.6
    coverage) remain — the interop scripts are additive, not
    replacement.
    `docs/ffi_design.md` (~310 lines) is the canonical FFI design
    reference: the panic-barrier contract (every `extern "C"`
    entry point wrapped in `guarded` / `catch_unwind`; the
    release-profile `panic = "abort"` caveat); the `lr_bytes_t`
    ownership model (`from_vec` / `reclaim_into_vec` /
    `lr_bytes_free`; the four embedder rules); the cbindgen
    pipeline (`build.rs` config, the `LrError` exclusion for
    pre-C23 portability, the `#define` constants in
    `after_includes`); the opaque-handle pattern (`#[repr(C)]` +
    `_private: [u8; 0]`; the handle zoo table; the destroy
    contract); the non-reentrant lock hazard (every `lr_router_*`
    holds the `Mutex` for the whole call; hooks must not
    re-enter); what is NOT exposed and why (OSPF/Babel engines
    are daemon-driven, LDP has no router session model, BMP/MRT/BFD
    are codec-only, the exchange-plane prototype is daemon-only);
    the error model (the `LR_ERR_*` code table, the thread-local
    last-error string, the `lr_abi_version()` check); and the
    three-level testing strategy (Rust unit tests, C / C++ harness,
    Go / Python bindings). Cross-references every section to the
    source file that implements it. The doc is indexed in
    `docs/README.md` under "Embedding the library".

13. **Phase 14 — D12.4 per-session UPDATE counters + filter-eval
    latency histograms** — landed: two new metric families on the
    Prometheus endpoint, backed by counters that live where the
    traffic flows. `lr-bgp::PeerMessageStats` (FRR `show bgp
    neighbor` "Message statistics" parity) counts OPEN / UPDATE /
    NOTIFICATION / KEEPALIVE / ROUTE-REFRESH per direction at the
    wire boundary — the ten inline encode sites in
    `fsm.rs`/`advertise.rs` folded into one `send_msg()` choke
    point, `feed_bytes` counts every decoded message, and the
    counters are monotonic across session re-establishment
    (`reset()` leaves them untouched; structurally invalid PDUs
    never decode and do not count). `SessionSummary` grew
    `updates_received`/`updates_sent` (0 for OSPF/Babel), surfaced
    on the runtime API `sessions` command (`updates-rx=`/
    `updates-tx=`) and the FFI `lr_router_sessions_dump` text —
    additive key=value fields. The metrics endpoint renders
    `lr_bgp_updates_total{session,peer,direction}` (the `peer`
    label carries the configured name/address; bidirectional peers
    get an `(inbound)` suffix on the RFC 4271 §6.8 challenger) and
    `lr_filter_eval_duration_seconds{direction,filter}` histograms
    — fixed 16-bucket atomic `DurationHistogram`s (100 ns … 10 ms,
    bounds around the GitHub #19 measured VM hot path of
    60–430 ns) recorded by the import/export filter hooks with
    relaxed atomics, no locks on the per-route path. Recording is
    opt-in: hooks carry `Option<Arc<DurationHistogram>>` that is
    `Some` only when `--metrics-addr` is configured, so the hot
    path pays the two `Instant::now()` calls only while metrics
    are enabled; the internal `__roa_validate` filter registers
    like any user filter so ROA-validation cost is separable from
    user policy. Daemon wiring covers the standalone BGP daemon
    and the multi-protocol supervisor (the embedded engine pushes
    its registry + session labels into the supervisor's `Runtime`
    before reporting Started). Along the way a real RFC 8212 bug
    was fixed: `set_session_policy` only counted route-map
    bindings, so a peer configured with `import_filter`/
    `export_filter` but no route-map was treated as policy-less
    and its imports silently discarded under the default
    `rfc8212` enforcement — DSL filter bindings now count as
    explicit policy. Coverage: 4 `lr-bgp` unit tests, 1
    `lr-router` test (EoR + advertisement + flap survival), 6
    `lr-cli` unit tests (bucket cumulativity, exact seconds
    formatting, registry rendering, empty omission, concurrent
    recording, hook latency) and the two-daemon e2e
    `metrics_updates_and_filter_histograms` (the first cargo e2e
    exercising `import_filter`/`export_filter` bindings).
