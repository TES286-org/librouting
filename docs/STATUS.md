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
| RFC 7911 Add-Path | 🟡 | capability + encoding; full N-path handling in best-path not wired |
| RFC 2918 route refresh | 🟡 | codec + capability; request generation not wired into router |
| RFC 7313 enhanced route refresh | 🟡 | codec only |
| RFC 4724 graceful restart | 🟡 | capability + EoR marker sent; restart-state retention not implemented |
| RFC 8277/8533 LLGR | ❌ | |
| MRAI (Min. Route Advertisement Interval) | ❌ | updates sent immediately; safe but chatty |
| MD5 / TCP-AO session authentication | ❌ | |
| BGPsec | ❌ | out of scope for now |
| Best-path selection (RFC 4271 §9) | ✅ | incl. LOCAL_PREF, AS_PATH length, origin, MED, eBGP<iBGP, router-id tiebreak |
| Route damping (`lr-damping`) | ✅ | RFC 2439-style figure-of-merit |
| BFD interaction (`lr-bfd`) | ✅ | session liveness events feed the FSM |
| Policy: prefix-lists, community-lists, AS-path filters, route-maps | ✅ | `lr-policy` |
| Import/export/safety hooks (violations configurable) | ✅ | safety net rejects AS loops / martians; can be disabled |
| iBGP split-horizon, next-hop-self, LOCAL_PREF injection | ✅ 🧪 | |

### OSPF (`lr-ospf`)

| Capability | Status | Notes |
|-----------|:------:|-------|
| Packet codec v2 (RFC 2328) / v3 (RFC 5340) | ✅ | hello, DBD, LSR, LSU, LSAck |
| Neighbor FSM | ✅ | |
| LSDB + LSA flooding | ✅ | |
| SPF (Dijkstra) route computation | ✅ 🧪 | E2E test computes routes over a synthetic topology |
| Designated-router election | ✅ | |
| Area support | 🟡 | single area (backbone) focus; inter-area/ABR summary-LSA handling is minimal |
| LSA refresh / aging / MaxAge flush | 🟡 | basic aging; periodic re-origination not scheduled |
| Stub/NSSA areas | ❌ | |
| Auth (cryptographic) | ❌ | |

### Babel (`lr-babel`)

| Capability | Status | Notes |
|-----------|:------:|-------|
| RFC 8966 codec (all core TLVs) | ✅ | |
| Neighbor / route table + feasibility (RFC 8966 §3.5.2) | ✅ | |
| Metric computation, seqno handling | ✅ 🧪 | E2E install/withdraw tests |
| RFC 9079 source-specific routing | 🟡 | TLVs modelled; source-table integration partial |
| RFC 8967 HMAC authentication | ❌ | |
| Babel over IPv6 link-local transport | 🟡 | model supported; daemon transport is IPv4 today |

## Layer 3 — router pipeline (`lr-router`)

| Capability | Status | Notes |
|-----------|:------:|-------|
| Adj-RIB-In → safety → import hooks → best-path → Loc-RIB → export hooks → Adj-RIB-Out | ✅ 🧪 | full pipeline, per-session attribution |
| Initial table dump on session establishment + End-of-RIB | ✅ 🧪 | BIRD/FRR see convergence markers |
| Session-down Adj-RIB-In purge (RFC 4271 §8.2.2 semantics) | ✅ | routes do not outlive their session |
| Reconnect-safe session restart | ✅ | FSM reset + established-latch clear |
| OSPF/Babel delta integration into Loc-RIB | ✅ | |
| Cross-protocol administrative distance merge | ✅ 🧪 | |
| Route reflection fan-out, originate/unoriginate APIs | ✅ | |

## Layer 4 — system integration (`lr-osroute`)

| Capability | Status | Notes |
|-----------|:------:|-------|
| Linux rtnetlink add/delete/list | ✅ 🧪 | used by `lr-daemon --install-kernel-routes` |
| BSD route(4) socket (FreeBSD/NetBSD/OpenBSD/macOS) | ✅ | layouts pinned per-OS; cross-compile checked |
| Windows IP Helper API | ✅ | full link verified (x86_64-pc-windows-gnu) |
| Interface auto-resolution when `if_index == 0` | ✅ | gateway-based (Linux), longest-prefix (Windows) |
| Other systems | ✅ | documented extension path — see `docs/OS-INTEGRATION.md` |

## Layer 5 — embedder surface

| Capability | Status | Notes |
|-----------|:------:|-------|
| `lr-daemon` reference daemon (TCP I/O loop, reconnect, TOML subset) | ✅ 🧪 | |
| C ABI FFI (`lr-ffi`) + cbindgen header | ✅ 🧪 | C harness in CI |
| Go bindings | ✅ 🧪 | `bindings/lr-go` |
| Python bindings | ✅ 🧪 | `bindings/lr-python` (cffi) |
| C++ bindings | ✅ | header-compatible with the C ABI (`bindings/lr-cpp`) |
| Signal handling / privilege drop in daemon | ❌ | documented as embedder responsibility |

## Testing & CI

| Item | Status |
|------|:------:|
| Unit tests (workspace) | ✅ 29 binaries / 170+ tests |
| Two-daemon TCP E2E | ✅ 🧪 |
| BIRD 2 interop (bidirectional) | ✅ 🧪 |
| FRR bgpd interop (bidirectional) | ✅ 🧪 |
| C / Go / Python binding harnesses | ✅ 🧪 |
| fmt + clippy (-D warnings) | ✅ |
| Cross builds: aarch64-linux-gnu, x86_64-windows-gnu (full link), freebsd/netbsd (check) | ✅ |
| Coverage (tarpaulin) | ✅ |
| MSRV 1.74 build | ✅ |

## Roadmap to production (recommended order)

1. **MRAI** — batch UPDATEs per prefix (default 30 s eBGP / 5 s iBGP,
   configurable) to be a polite peer at scale.
2. **Route refresh wiring** — emit ROUTE-REFRESH on policy change so
   Adj-RIB-In can be re-evaluated without a session bounce.
3. **Graceful restart restart-state** — retain routes during restart
   window (capability already negotiated).
4. **OSPF LSA refresh scheduling + ABR summary LSAs** — multi-area
   correctness.
5. **Babel HMAC (RFC 8967)** — authentication for untrusted links.
6. **BGP MD5/TCP-AO** — where operators require it.
7. **Daemon hardening** — signal handling, privilege drop, config reload,
   runtime API (gRPC/UNIX socket) for operational visibility.
