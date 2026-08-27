# librouting

Platform-independent routing protocol library implemented in Rust. Provides
BGP (RFC 4271 and extensions), OSPFv2/v3 (RFC 2328/5340 and extensions) and
Babel (RFC 8966 and extensions) parsing, finite-state machine interaction and
route calculation. BFD (RFC 5880) for fast peer failure detection, route flap
damping (RFC 2439), and an OS route table reference implementation (Linux
rtnetlink) are provided as opt-in crates.

## Design

Three-layer API:

| Layer | Crate | Purpose |
|-------|-------|---------|
| 1 | `lr-core::codec` + per-protocol codec modules | Stateless wire codec |
| 2 | `lr-bgp::fsm`, `lr-ospf::neighbor`, `lr-babel::fsm`, `lr-bfd::session` | Peer FSM + transport abstraction |
| 3 | `lr-router::instance` | High-level router instance tying sessions, RIB and policies |

The four-tier RIB model (Adj-RIB-In, Adj-RIB-Out, Loc-RIB, with cross-protocol
merging via admin distance) is captured in `lr-rib`. Policy framework (route
maps, prefix lists, AS-path filters, community lists, hooks + safety net)
lives in `lr-policy`.

The full data plane is wired end-to-end: UPDATEs received by a BGP session
are extracted into routes, pass the safety net and import hooks, enter
Adj-RIB-In, win (or lose) the decision process, land in Loc-RIB, and are
re-advertised to other peers with the correct egress rules (AS prepend,
next-hop-self, LOCAL_PREF stripping/injection, iBGP split-horizon, RR
reflection with ORIGINATOR_ID/CLUSTER_LIST, OTC valley-free enforcement).
Withdrawals propagate back through the same pipeline. See
`docs/ARCHITECTURE.md` for the pipeline diagram.

C ABI bindings (`lr-ffi`) let Go, Python, C and C++ embedders call into the
library without depending on the Rust toolchain at runtime.

## Crates

| Crate | Path | Purpose |
|-------|------|---------|
| `lr-core` | `crates/lr-core` | Shared foundation: types, codec traits, generic FSM, RIB traits, timers, wire utilities |
| `lr-bgp` | `crates/lr-bgp` | BGP-4 codec, path attributes, peer FSM, capabilities, MP-BGP, AddPath, 4-byte ASN, iBGP/eBGP roles, Route Reflector (RFC 4456), Confederations (RFC 6793), Route Server (RFC 7947), OTC (RFC 9234), best-path with multipath (RFC 4271 §9.1.2 / RFC 4784) |
| `lr-ospf` | `crates/lr-ospf` | OSPFv2/v3 codec, LSAs, link-state DB, neighbor FSM, SPF, areas, auth |
| `lr-babel` | `crates/lr-babel` | Babel codec, TLVs, neighbor FSM, route table, source-specific routing |
| `lr-rib` | `crates/lr-rib` | Adj-RIB-In, Adj-RIB-Out, Loc-RIB, route selection, cross-protocol merging |
| `lr-policy` | `crates/lr-policy` | Route maps, prefix lists, AS-path filters, community lists, import/export/selection hooks, safety net |
| `lr-router` | `crates/lr-router` | Layer-3 router instance, sessions, scheduler, event dispatch |
| `lr-bfd` | `crates/lr-bfd` | BFD Control packet codec (RFC 5880), session FSM (Down→Init→Up), auth |
| `lr-damping` | `crates/lr-damping` | Route flap damping (RFC 2439) |
| `lr-osroute` | `crates/lr-osroute` | OS routing table reference (Linux rtnetlink) + Stub for non-Linux |
| `lr-cli` | `crates/lr-cli` | `lr` CLI tool (decode/routes) + `lr-daemon` reference wiring |
| `lr-ffi` | `crates/lr-ffi` | C ABI bindings (cbindgen-generated header) |
| `lr-tests` | `crates/lr-tests` | Cross-crate integration tests |

## The daemon

`lr-daemon` is a complete reference embedder: TCP transport (connect or
listen), poll-driven router, ticker thread, reconnect with backoff, RFC
4724 graceful restart and RFC 9494 long-lived graceful restart
(`--graceful-restart SECS`, `--llgr SECS`), RFC 2385 MD5 / RFC 5925
TCP-AO session authentication (`--md5-key SECRET`, `--tcp-ao-key
ID:SECRET`), and optional kernel route installation via rtnetlink.

```bash
# Terminal 1 — speaker A (listens, originates a prefix)
lr-daemon --local-as 64512 --peer-as 64513 --router-id 10.0.0.1 \
          --listen 127.0.0.1:1179 --local-address 192.0.2.1 \
          --network 203.0.113.0/24

# Terminal 2 — speaker B (connects, receives the route)
lr-daemon --local-as 64513 --peer-as 64512 --router-id 10.0.0.2 \
          --peer 127.0.0.1:1179 --local-address 192.0.2.2
# → daemon: session #1 → Established
# → daemon: route installed 203.0.113.0/24 via 192.0.2.1
```

A TOML config (`templates/daemon.toml`) is supported via `--config`.

## Workspace Layout

```
librouting/
├── Cargo.toml
├── crates/{lr-core, lr-bgp, lr-ospf, lr-babel, lr-rib, lr-policy,
│           lr-router, lr-bfd, lr-damping, lr-osroute, lr-cli,
│           lr-ffi, lr-tests}/
├── bindings/{lr-go, lr-python}/
├── docs/
│   ├── ARCHITECTURE.md
│   ├── RFC_MAP.md
│   ├── API.md
│   ├── examples/
│   └── scaffolding/
├── examples/                    # standalone example binaries
├── templates/                  # scaffolding templates
├── include/{lr_ffi.h, librouting.hpp}
└── .github/workflows/
```

## Documentation

| Document | Path |
|----------|------|
| Architecture | `docs/ARCHITECTURE.md` |
| RFC reference map | `docs/RFC_MAP.md` |
| Public API tour | `docs/API.md` |
| Implemented-vs-missing gap analysis | `docs/STATUS.md` |
| OS route-table integration guide (Linux/BSD/Windows + porting) | `docs/OS-INTEGRATION.md` |
| Interop testing guide (BIRD / FRR) | `docs/INTEROP.md` |
| Scaffolding guide | `docs/scaffolding/README.md` |
| Examples | `docs/examples/*.md` |
| Templates | `templates/*/` |

## BGP topology support

`librouting` ships full support for the most common BGP deployments:

- **iBGP vs eBGP** (RFC 4271 §10): automatic role detection from local/peer
  AS + confederation configuration. Drives AS_PATH prepending, NEXT_HOP
  rewriting, LOCAL_PREF propagation, and reflection rules.
- **Route Reflector** (RFC 4456): `ClusterId`, `ORIGINATOR_ID` insertion,
  `CLUSTER_LIST` prepend + loop detection.
- **Confederations** (RFC 6793): sub-AS membership, `AS_CONFED_SEQUENCE` /
  `AS_CONFED_SET` segment types, external AS announcement.
- **Route Server / IX** (RFC 7947): transparent mode (no AS_PATH prepend,
  NEXT_HOP preserved) + per-client filter chains.
- **BGP Role / OTC** (RFC 9234): `OtcRole` (Provider/Customer/Peer/RS/RsClient)
  + valley-free advertisement enforcement.
- **Graceful Restart** (RFC 4724): per-family capability advertisement,
  stale-route retention for the negotiated restart window and End-of-RIB
  driven resynchronization.
- **Long-Lived Graceful Restart** (RFC 9494): capability 71 negotiation,
  `LLGR_STALE`/`NO_LLGR` communities, least-preferred stale-route
  selection, egress gating to non-LLGR neighbors and per-family stale-time
  retention with a locally configurable cap.

## Best-path selection

Full RFC 4271 §9.1.2 decision process (12 steps) + RFC 5004 deterministic
router-id tiebreak + RFC 4784 multipath. Tunable via `BestPathConfig`:

- `always_compare_med`
- `missing_med_as_infinity`
- `deterministic_router_id`
- `prefer_externals`
- `count_confed_in_path_len`
- `multipath` (N-way equal-cost)
- `multipath_relax` (cross-neighbor multipath)

## Policy hooks

The router ships three trait-based hook points:

- `ImportHook` — invoked after decode, before Adj-RIB-In insertion.
- `SelectionHook` — overrides the comparator during best-path selection.
- `ExportHook` — invoked after Loc-RIB selection, before Adj-RIB-Out encode.

All hooks may drop, keep, or replace routes. They are pure Rust code, so
any operator policy (e.g. "prefer routes from peer X over Y regardless of
attributes") can be implemented without forking.

## Safety net

Protocol-level invariants (RFC compliance requirements) are enforced by
`lr-policy::SafetyNet`:

- AS path loop rejection (RFC 4271 §9.1.2.15)
- NEXT_HOP sanity (unspecified, loopback, or self)
- Martian prefix rejection (RFC 1918 + link-local + loopback + multicast)
- Empty AS_PATH on eBGP (RFC 8212)
- Excessive AS loops (> N appearances of own AS)
- Oversized AS_PATH (> N segments)
- Oversized LOCAL_PREF

Each check can be **individually disabled** via `SafetyConfig`. The
defaults match common operator expectations (strict, but not overly
restrictive).

## Status

Implemented and missing features are tracked in detail in
[`docs/STATUS.md`](docs/STATUS.md). Highlights:

- BGP data plane verified bidirectionally against **BIRD 2** and **FRR
  bgpd** over real TCP sessions (`tests/interop/{bird,frr}.sh`, wired into
  CI), including an **RFC 9494 LLGR** lifecycle test
  (`tests/interop/bird_llgr.sh`): both sides negotiate the Long-Lived
  Graceful Restart capability, retain routes across a restart, mark them
  `LLGR_STALE` and purge at the negotiated stale-time expiry.
- OS route-table integration for **Linux (rtnetlink)**, the **BSD family
  (route(4) socket)** and **Windows (IP Helper API)**, plus a porting guide
  for other systems (`docs/OS-INTEGRATION.md`).
- Not yet production-ready: see the roadmap at the end of `STATUS.md`
  (daemon hardening, Add-Path best-path wiring and OSPF depth are the
  main gaps). The C ABI is **unstable** until v0.5.

## CI/CD

GitHub Actions workflows live in `.github/workflows/` and run on push to
`main` and on PRs: fmt + clippy + workspace tests + C harness + Go bindings +
Python bindings + MSRV + cross-build (aarch64 Linux, Windows) + **interop
jobs against BIRD and FRR**. Nightly runs `miri` for the unsafe audit on
`lr-osroute` FFI.

## License

Dual-licensed under MIT OR Apache-2.0.
