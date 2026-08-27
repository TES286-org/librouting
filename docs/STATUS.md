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
| GTSM / TTL security (RFC 5082) | ❌ | BIRD `ttl security` / FRR `ttl-security` parity |
| Per-peer maximum-prefix | ❌ | limit + warn / tear-down semantics |
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
| AS-external routes (type-5 LSAs, §16.4) | ❌ | LSA body modelled only — no origination, flooding or external route calculation |
| Summary-ASBR LSAs (type-4, §12.4.3) | ❌ | enum value only — no ABR origination / ASBR reachability use |
| External route redistribution API | ❌ | BIRD/FRR `redistribute` equivalent |
| Cross-protocol redistribution engine | ❌ | BGP/OSPF/Babel ↔ Loc-RIB import/export pipes |
| Designated-router election | ✅ | |
| Area support | ✅ | multi-area v2 with ABR summaries (backbone-attached); OSPFv3 inter-area LSA bodies not originated yet |
| LSA refresh / aging / MaxAge flush | ✅ | periodic self-LSA re-origination at 1800 s, MaxAge expiry at 3600 s, MaxAge purge on receipt (§13) |
| Stub/NSSA areas | ❌ | stub needs type-5 awareness (block + default-route injection); NSSA adds type-7 LSAs |
| Virtual links | ❌ | non-backbone-only attachment does not summarize (needs backbone) |
| Auth (cryptographic) | 🟡 | `Auth` trait + AuType model exist; only NullAuth implemented — RFC 2328 §C.3 MD5, RFC 5709 HMAC-SHA, RFC 7166 v3 trailer missing |

### Babel (`lr-babel`)

| Capability | Status | Notes |
|-----------|:------:|-------|
| RFC 8966 codec (all core TLVs) | ✅ | |
| Neighbor / route table + feasibility (RFC 8966 §3.5.2) | ✅ | |
| Metric computation, seqno handling | ✅ 🧪 | E2E install/withdraw tests |
| RFC 9079 source-specific routing | 🟡 | TLVs modelled; source-table integration partial |
| RFC 8967 HMAC authentication | ✅ | HMAC-SHA256, IPv4/IPv6 pseudo-headers, multi-key receive validation, packet counters, replay rejection |
| Babel over IPv6 link-local transport | 🟡 | model supported; daemon transport is IPv4 today |

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
| Daemon hardening E2E (signals, reload, runtime API, privilege drop) | ✅ 🧪 | `lr-cli` integration tests |
| MD5 auth interop (two-daemon positive/negative + BIRD `password` + FRR `neighbor password`) | ✅ 🧪 |
| TCP-AO interop (two-daemon positive/negative; kernel >= 6.7, else SKIP) | ✅ 🧪 |
| OSPF multi-area + ABR inter-area E2E (incl. two-router propagation) | ✅ 🧪 |
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
7. **OSPF external routes (type-5 AS-external-LSAs)** — the largest OSPF
   parity gap with BIRD/FRR (`redistribute` support): type-5
   origination/flush API, AS-scope flooding into every attached area,
   type-4 summary-ASBR origination by ABRs, and the §16.4 external route
   calculation (type-1/type-2 metrics, forwarding-address reachability).
8. **OSPF stub/NSSA areas** — stub areas (block type-5 flooding, ABR
   summary-default injection, RFC 2328 §3.6 / §12.4.3) and NSSA (RFC 3101
   + RFC 3509 type-7 LSAs, P-bit translation to type-5 at the ABR,
   no-summary option). Depends on 7.
9. **OSPF virtual links** — §15 transit through non-backbone areas,
   §16.3 virtual-link next-hop resolution, allowing partitioned
   backbone repair.
10. **OSPF authentication + OSPFv3 inter-area** — RFC 5709 HMAC-SHA auth
    (v2 AuType 2 trailer), RFC 7166 v3 auth trailer, and OSPFv3
    inter-area-prefix-LSA (0x2003) ABR origination.
11. **BGP GTSM + maximum-prefix** — RFC 5082 TTL security (peer
    `min-ttl` enforcement) and per-peer `maximum-prefix` with warn /
    restart / teardown actions. Quick BIRD/FRR parity wins.
12. **Cross-protocol redistribution engine** — explicit import/export
    pipes between BGP, OSPF, Babel and Loc-RIB (BIRD pipe / FRR
    `redistribute` equivalent), with protocol-tag and metric policy.
13. **Babel daemon parity** — IPv6 link-local transport in the daemon
    (today IPv4-only) and RFC 9079 source-specific table completion.
14. **BMP monitoring (RFC 7854)** — session mirroring to an external
    collector for operational parity with BIRD/FRR.
