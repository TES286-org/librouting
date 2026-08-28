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
| RFC 4760 MP-BGP (IPv4/IPv6 unicast NLRI) | ✅ | BIRD requires it — now advertised by default |
| RFC 4893/6793 4-octet AS + dynamic negotiation | ✅ | downgrade to 2-byte when peer lacks the capability |
| RFC 4456 route reflection (ORIGINATOR_ID, CLUSTER_LIST) | ✅ | correct optional non-transitive flags |
| RFC 5065 confederations | ✅ | |
| RFC 7947 route server mode | ✅ | |
| RFC 9234 OTC / roles | ✅ | |
| RFC 7911 Add-Path | ✅ 🧪 | capability negotiation (per-family send/receive), path-id NLRI framing (plain + MP), Adj-RIB-In keyed by path id, ranked N-path selection (`add_path_max_paths`), per-path export/withdrawal with rank-slot transmit ids, MRAI path sets, GR/LLGR per-path retention; two-daemon + full-stack e2e |
| RFC 5549 Extended Next-Hop | ✅ 🧪 | capability code 5 with `(NLRI AFI, NLRI SAFI, Nexthop AFI)` tuples; OPEN negotiation as the intersection of local + peer tuples (§3); 16-byte NEXT_HOP for IPv4 NLRI decoded as `V4OverV6`, MP_REACH `(AFI=1, 16B)` accepted; eBGP egress rewrites IPv4 NEXT_HOP to IPv6 when `(1,1,2)` is negotiated and `local_address` is IPv6; daemon `--extended-next-hop` / `--local-address-v6` / `--mp-family ipv6-unicast`; e2e coverage of all 8 dual-stack / MP-BGP / ENH / pure-v6 session modes |
| RFC 2918 route refresh | ✅ | negotiated capability, outbound API, inbound re-advertisement through current export policy |
| RFC 7313 enhanced route refresh | ✅ | negotiated capability plus BoRR/EoRR demarcation around refreshed tables |
| RFC 4724 graceful restart | ✅ 🧪 | capability lists address families with F bits; stale-route retention, negotiated expiry purge, EoR-based resynchronization (BIRD-verified) |
| RFC 9494 LLGR | ✅ 🧪 | capability 71, per-family LLST, LLGR_STALE/NO_LLGR communities, least-preferred selection, egress gating, full retention lifecycle (BIRD-verified) |
| MRAI (Min. Route Advertisement Interval) | ✅ | configurable per-prefix batching (withdrawals immediate); defaults to 30 s eBGP / 5 s iBGP |
| MD5 / TCP-AO session authentication | ✅ 🧪 | RFC 2385 MD5 + RFC 5925 TCP-AO (hmac(sha1)/cmac(aes), ao_required) via `lr-osroute::tcp_auth`; kernel-signed SYNs, fail-closed arming; BIRD/FRR interop-verified |
| BGPsec | ❌ | out of scope for now |
| Best-path selection (RFC 4271 §9) | ✅ | incl. LOCAL_PREF, AS_PATH length, origin, MED, eBGP<iBGP, router-id tiebreak; LLGR_STALE routes least-preferred (RFC 9494 §4.4) |
| Route damping (`lr-damping`) | ✅ | RFC 2439-style figure-of-merit |
| BFD interaction (`lr-bfd`) | ✅ | session liveness events feed the FSM |
| Policy: prefix-lists, community-lists, AS-path filters, route-maps | ✅ | `lr-policy` |
| Import/export/safety hooks (violations configurable) | ✅ | safety net rejects AS loops / martians; can be disabled |
| iBGP split-horizon, next-hop-self, LOCAL_PREF injection | ✅ 🧪 | |
| GTSM / TTL security (RFC 5082) | ✅ 🧪 | `lr-osroute::gtsm` (IP_TTL + IP_MINTTL on listener, outbound TTL on connector); daemon `--gtsm` / `--gtsm N`; live socket tests verify both happy-path and low-TTL rejection |
| Per-peer maximum-prefix | ✅ 🧪 | `with_maximum_prefix(N, action)` + `with_maximum_prefix_threshold(pct)`; warn / teardown / restart actions; CEASE NOTIFICATION subcode 8 (RFC 4486 §2.1); threshold + exceeded events latched per session; daemon `--max-prefixes` / `--max-prefix-action` / `--max-prefix-threshold` |
| Route aggregation | ❌ | aggregate NLRI generation + AS_PATH zeroing |
| BMP monitoring (RFC 7854) | ❌ | session mirroring to a collector |

### OSPF (`lr-ospf`)

| Capability | Status | Notes |
|-----------|:------:|-------|
| Packet codec v2 (RFC 2328) / v3 (RFC 5340) | ✅ | hello, DBD, LSR, LSU, LSAck |
| Neighbor FSM | ✅ | |
| LSDB + LSA flooding | ✅ | per-area shared LSDB; same-area sessions flood to each other (§13.3 simplified) |
| SPF (Dijkstra) route computation | ✅ 🧪 | E2E test computes routes over a synthetic topology |
| Inter-area routes from summary-LSAs (§16.2) | ✅ 🧪 | reachable-border check, dist-to-border + summary metric, LSInfinity skip |
| ABR summary-LSA origination/flush (§12.4.3) | ✅ 🧪 | type-3 lifecycle with backbone-only loop guard, checksummed LSAs, MaxAge flush |
| AS-external routes (type-5 LSAs, §16.4) | ✅ 🧪 | origination via `ospf_redistribute`, AS-scope flooding across ABRs, §16.4 calculation (type-1/2 metrics, forwarding-address reachability + next hop), MaxAge flush lifecycle |
| Summary-ASBR LSAs (type-4, §12.4.3) | ✅ 🧪 | ABR origination for inter-area-only ASBRs, ASBR leg resolution in §16.4 (b) |
| External route redistribution API | ✅ 🧪 | `DefaultRouter::ospf_redistribute`/`ospf_unredistribute` |
| Cross-protocol redistribution engine | ✅ 🧪 | `RedistributionPipe` (BIRD `pipe` / FRR `redistribute`); BGP↔BGP, BGP→OSPF, OSPF→BGP; metric policy (Inherit/Fixed/Add); prefix-list filter; withdrawal propagation; 7 e2e tests |
| Designated-router election | ✅ | |
| Area support | ✅ | multi-area v2 with ABR summaries (backbone-attached); OSPFv3 inter-area LSA bodies not originated yet |
| LSA refresh / aging / MaxAge flush | ✅ | periodic self-LSA re-origination at 1800 s, MaxAge expiry at 3600 s, MaxAge purge on receipt (§13) |
| Stub/NSSA areas | ✅ 🧪 | `OspfAreaType` (stub / no-summary / NSSA / totally-NSSA): type-5/type-4 refusal at install & AS-scope re-flood, ABR summary-default (type-3) and type-7 default injection, area-scoped type-7 origination, §3.2 translation to type-5 by the elected (highest-ID/Nt) border router; OSPFv2 only |
| Virtual links | ✅ 🧪 | `ospf_add_virtual_link` (§15): up while the transit-area SPF reaches the endpoint; materializes a backbone adjacency restoring ABR status; embedder-routed transport; stub/NSSA transit refused |
| Auth (cryptographic) | ✅ 🧪 | RFC 5709 HMAC-SHA-1/SHA-256 (v2 AuType 2 trailer), RFC 7166 v3 auth trailer (SA-ID + 64-bit crypto-seq + MAC), anti-replay; 22 unit tests |
| OSPFv3 inter-area-prefix-LSA (0x2003) | ✅ 🧪 | `originate_v3_inter_area_prefix_lsa` ABR origination; v3 LSA type enum; body encode/decode with IPv6 prefix support |

### Babel (`lr-babel`)

| Capability | Status | Notes |
|-----------|:------:|-------|
| RFC 8966 codec (all core TLVs) | ✅ | |
| Neighbor / route table + feasibility (RFC 8966 §3.5.2) | ✅ | |
| Metric computation, seqno handling | ✅ 🧪 | E2E install/withdraw tests |
| RFC 9079 source-specific routing | ✅ 🧪 | TLV model (SsHello/SsIhu/SsUpdate/SsRouteRequest/SsSeqnoRequest); IPv4 + IPv6 source prefixes; route table keyed by (destination, source) tuple; 4 new encode/decode tests |
| RFC 8967 HMAC authentication | ✅ | HMAC-SHA256, IPv4/IPv6 pseudo-headers, multi-key receive validation, packet counters, replay rejection |
| Babel over IPv6 link-local transport | ✅ 🧪 | daemon `--protocol babel` mode; UDP on port 6696, ff02::1:6 multicast, TTL=255 (RFC 8966 §2.1); AE=2 (IPv6) destination + source prefix handling |

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

## Layer 4 — system integration (`lr-osroute`)

| Capability | Status | Notes |
|-----------|:------:|-------|
| Linux rtnetlink add/delete/list | ✅ 🧪 | used by `lr-daemon --install-kernel-routes` |
| TCP MD5 / TCP-AO socket auth | ✅ 🧪 | `lr-osroute::tcp_auth` — arm_listener (wildcard keys) + connect_auth (keys before connect, signed SYN); Linux both, other platforms Unsupported |
| BSD route(4) socket (FreeBSD/NetBSD/OpenBSD/macOS) | ✅ | layouts pinned per-OS; cross-compile checked |
| Windows IP Helper API | ✅ | full link verified (x86_64-pc-windows-gnu) |
| Interface auto-resolution when `if_index == 0` | ✅ | gateway-based (Linux), longest-prefix (Windows) |
| Other systems | ✅ | documented extension path — see `docs/OS-INTEGRATION.md` |

## Layer 5 — embedder surface

| Capability | Status | Notes |
|-----------|:------:|-------|
| `lr-daemon` reference daemon (TCP I/O loop, reconnect, TOML subset) | ✅ 🧪 | signals (SIGTERM/SIGINT graceful, SIGHUP reload), privilege drop, runtime API |
| C ABI FFI (`lr-ffi`) + cbindgen header | ✅ 🧪 | C harness in CI |
| Go bindings | ✅ 🧪 | `bindings/lr-go` |
| Python bindings | ✅ 🧪 | `bindings/lr-python` (cffi) |
| C++ bindings | ✅ | header-only RAII wrapper over the C ABI (`include/librouting.hpp`) |
| Signal handling / privilege drop / config reload / runtime API in daemon | ✅ 🧪 | SIGTERM/SIGINT close sessions with a NOTIFICATION (RFC 4271 §6.4) then exit 0; SIGHUP + API `reload` re-apply `networks` (bad config keeps running); `--user`/`--group` setuid/setgid after bind; `--api-socket` Unix-socket management plane (status/sessions/routes/reload/shutdown); `daemon_runtime.rs` E2E |

## Testing & CI

| Item | Status |
|------|:------:|
| Unit tests (workspace) | ✅ 30 binaries / 260+ tests |
| Two-daemon TCP E2E | ✅ 🧪 |
| Add-Path E2E (two-daemon + full-stack multi-path propagation) | ✅ 🧪 |
| BGP session-mode E2E (8 modes: standard dual-stack, LL dual-stack, MP-BGP, MP-BGP+LL, ENH, ENH+LL, pure IPv6, pure IPv6+LL) | ✅ 🧪 | `lr-tests/tests/bgp_session_modes.rs` |
| GTSM + maximum-prefix E2E (TTL security + per-peer prefix limit) | ✅ 🧪 | `lr-tests/tests/gtsm_max_prefix.rs` |
| Redistribution E2E (BGP↔BGP, BGP→OSPF, metric policy, prefix filter, withdrawal) | ✅ 🧪 | `lr-tests/tests/redistribution.rs` |
| Daemon hardening E2E (signals, reload, runtime API, privilege drop) | ✅ 🧪 | `lr-cli` integration tests |
| MD5 auth interop (two-daemon positive/negative + BIRD `password` + FRR `neighbor password`) | ✅ 🧪 |
| TCP-AO interop (two-daemon positive/negative; kernel >= 6.7, else SKIP) | ✅ 🧪 |
| OSPF multi-area + ABR inter-area E2E (incl. two-router propagation) | ✅ 🧪 |
| OSPF external-route E2E (type-5 AS-scope propagation, type-4 ASBR legs, §16.4 type-1/2 + forwarding address, flush lifecycle) | ✅ 🧪 |
| OSPF stub/NSSA E2E (stub/totally-stubby gating + default injection, NSSA type-7 + P-bit translation with forwarding address, type-7/type-3 defaults, no-summary, translator election, flush lifecycle) | ✅ 🧪 |
| OSPF virtual-link E2E (§15 backbone partition repair, summaries over the virtual adjacency, teardown + stale-LSA MaxAge age-out, stub-transit refusal) | ✅ 🧪 |
| BIRD 2 interop (bidirectional) | ✅ 🧪 |
| BIRD 2 LLGR interop (RFC 9494 full lifecycle, both helper roles) | ✅ 🧪 |
| FRR bgpd interop (bidirectional) | ✅ 🧪 |
| C / Go / Python binding harnesses | ✅ 🧪 |
| fmt + clippy (-D warnings) | ✅ |
| Cross builds: aarch64-linux-gnu, x86_64-windows-gnu (full link), freebsd/netbsd (check) | ✅ |
| Coverage (tarpaulin) | ✅ |
| MSRV 1.88 build | ✅ |

## Roadmap to production (recommended order)

1. ~~**Graceful restart restart-state**~~ — done, including RFC 9494
   long-lived graceful restart.
2. ~~**OSPF LSA refresh scheduling + ABR summary LSAs**~~ — done: shared
   per-area LSDBs, §16.2 inter-area calculation, §12.4.3 summary
   origination/flush with loop guards (OSPFv2; v3 inter-area-prefix-LSA
   origination remains future work).
3. ~~**Babel HMAC (RFC 8967)**~~ — done.
4. ~~**BGP MD5/TCP-AO**~~ — done: `lr-osroute::tcp_auth` (RFC 2385 +
   RFC 5925, Linux kernel-signed segments), daemon flags `--md5-key` /
   `--tcp-ao-key`, interop-verified against BIRD and FRR.
5. ~~**Daemon hardening**~~ — done: signal handling (SIGTERM/SIGINT
   graceful shutdown with NOTIFICATION-first close, SIGHUP config
   reload), privilege drop (`--user`/`--group`), and a Unix-socket
   runtime API (`--api-socket`: status/sessions/routes/reload/shutdown)
   backed by the new `DefaultRouter::session_summaries()` introspection
   (also exposed through the FFI and the Go/Python bindings).
6. ~~**Add-Path best-path wiring**~~ — done: RFC 7911 negotiation,
   wire framing and the N-path decision/export pipeline
   (`BestPath::rank` → Loc-RIB path sets → per-path Adj-RIB-Out diffs);
   the daemon exposes `--add-path` / `--add-path-max` and the runtime API
   dumps paths with their identifiers.
7. ~~**OSPF external routes (type-5 AS-external-LSAs)**~~ — done:
   `lr_ospf::external` (type-5/type-4 origination + flush, §16.4
   calculation) and the `DefaultRouter::ospf_redistribute` /
   `ospf_unredistribute` API with AS-scope flooding, type-4 ABR
   origination and per-area external route merging into Loc-RIB;
   verified by 9 unit + 5 three-router E2E tests.
8. ~~**OSPF stub/NSSA areas**~~ — done: stub areas (type-5/type-4
   refusal, ABR summary-default, `no_summary` totally-stubby) and NSSA
   (RFC 3101: area-scoped type-7 LSAs with P-bit + forwarding-address
   rules, §3.1 translator election, §3.2 translation to type-5, §2.5
   route calculation, type-7 default with the `no_summary` type-3
   fallback); area types configured per session
   (`with_ospf_area_type`) or at runtime (`ospf_set_area_type`);
   verified by 13 unit + 8 three-/four-router E2E tests. OSPFv2 only —
   v3 stub/NSSA follows the v3 inter-area work in item 11.
9. ~~**OSPF virtual links**~~ — done: §15 lifecycle (`ospf_add_virtual_link`/
   `ospf_remove_virtual_link`, up while the transit-area SPF reaches the
   endpoint, stub/NSSA transit areas refused), type-4 link SPF
   traversal, and the materialized backbone adjacency that restores
   border-router status for partitioned / backbone-disconnected ABRs —
   summaries, defaults and type-4s flow across the virtual backbone
   through an embedder-routed transport session. Router-LSA
   origination (type-4 link descriptions, V-bit) stays with the
   embedder, as with all router-LSAs in this model; verified by 4 E2E
   tests incl. MaxAge age-out of stale LSAs after a partition.
10. ~~**BGP dual-stack / MP-BGP / Extended Next-Hop session modes**~~ —
    done: RFC 5549 capability (code 5) negotiated as the intersection
    of local and peer `(NLRI AFI, NLRI SAFI, Nexthop AFI)` tuples;
    16-byte well-known NEXT_HOP for IPv4 NLRI decoded as `V4OverV6`
    (the spurious 32-byte form is rejected); MP_REACH `(AFI=1, 16B)`
    accepted; eBGP egress rewrites IPv4 NEXT_HOP to IPv6 when
    `(1,1,2)` is negotiated and `local_address` is IPv6. Daemon gains
    `--extended-next-hop`, `--mp-family` (repeatable) and
    `--local-address-v6`, plus proper IPv6 / `[fe80::1%eth0]:port`
    address resolution (replacing the `split(':')` shortcut that broke
    for IPv6). All eight BGP session establishment modes — standard
    dual-stack, link-local dual-stack, MP-BGP, MP-BGP+link-local,
    ENH, ENH+link-local, pure IPv6, pure IPv6+link-local — verified by
    `lr-tests/tests/bgp_session_modes.rs` (10 tests, in-process byte
    pump). FFI + Go/Python/C++ bindings expose
    `set_extended_next_hop` / `set_mp_families` / `set_local_address`.
11. ~~**OSPF authentication + OSPFv3 inter-area**~~ — done: RFC 5709
    HMAC-SHA-1/SHA-256 crypto auth for OSPFv2 (`CryptoAuth` with Key ID,
    shared secret, algorithm, anti-replay via monotonic crypto-seq, IPv4
    pseudo-header), RFC 7166 auth trailer for OSPFv3 (`V3Auth` with
    SA-ID, 64-bit crypto-seq, IPv6 pseudo-header), and OSPFv3
    inter-area-prefix-LSA (0x2003) ABR origination
    (`originate_v3_inter_area_prefix_lsa` + `LsaTypeV3` enum + body
    encode/decode with IPv6 prefix support). 22 auth unit tests + 5 v3
    ABR origination tests.
12. ~~**BGP GTSM + maximum-prefix**~~ — done: RFC 5082 TTL security
    (`lr-osroute::gtsm` — listener-side `IP_MINTTL`/`IPV6_MINHOPLIMIT`
    filter + outbound TTL on connector; daemon `--gtsm` / `--gtsm N`;
    live socket tests verify both happy-path and low-TTL rejection) and
    per-peer `maximum-prefix` with warn/teardown/restart actions
    (`with_maximum_prefix(N, action)` + `with_maximum_prefix_threshold`;
    CEASE NOTIFICATION subcode 8 per RFC 4486 §2.1; threshold +
    exceeded events latched per session; daemon `--max-prefixes` /
    `--max-prefix-action` / `--max-prefix-threshold`). Verified by 10
    e2e tests in `lr-tests/tests/gtsm_max_prefix.rs`.
13. ~~**Cross-protocol redistribution engine**~~ — done:
    `RedistributionPipe` (BIRD `pipe` / FRR `redistribute`) bridges
    routes from a source protocol to a target protocol with a
    configurable metric policy (`Inherit` / `Fixed(N)` / `Add(N)`) and
    an optional prefix-list filter. Supported pipes: BGP→BGP
    (re-originate as locally originated), BGP→OSPF (type-5 external),
    OSPF→BGP. Withdrawals propagate automatically. 7 e2e tests cover
    basic re-origination, fixed/add metric, prefix-list filter,
    withdrawal propagation, pipe removal, and IPv6 support.
14. ~~**Babel daemon parity**~~ — done: IPv6 link-local transport in
    the daemon via `--protocol babel` (UDP on port 6696, ff02::1:6
    multicast, TTL=255 per RFC 8966 §2.1); RFC 9079 source-specific
    table completion (IPv6 source prefixes in `apply_update`, IPv6
    Loc-RIB family selection in `best_routes`, `SsRouteRequest` and
    `SsSeqnoRequest` TLV encode/decode with 4 roundtrip tests).
15. **BMP monitoring (RFC 7854)** — session mirroring to an external
    collector for operational parity with BIRD/FRR.
