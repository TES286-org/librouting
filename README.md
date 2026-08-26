# librouting

Platform-independent routing protocol library implemented in Rust. Provides
BGP (RFC 4271 and extensions), OSPFv2/v3 (RFC 2328/5340 and extensions) and
Babel (RFC 8966 and extensions) parsing, finite-state machine interaction and
route calculation. **No system-level or platform-specific code** — no sockets,
no netlink, no system routing tables. The embedder (a daemon, an analyzer, a
simulator) drives I/O and time.

## Design

Three-layer API:

| Layer | Crate | Purpose |
|-------|-------|---------|
| 1 | `lr-core::codec` + per-protocol codec modules | Stateless wire codec |
| 2 | `lr-bgp::fsm`, `lr-ospf::neighbor`, `lr-babel::fsm` | Peer FSM + transport abstraction |
| 3 | `lr-router::instance` | High-level router instance tying sessions, RIB and policies |

The four-tier RIB model (Adj-RIB-In, Adj-RIB-Out, Loc-RIB, with cross-protocol
merging via admin distance) is captured in `lr-rib`. Policy framework (route
maps, prefix lists, AS-path filters, community lists) is in `lr-policy`.

C ABI bindings (`lr-ffi`) let Go, Python, C and C++ embedders call into the
library without depending on the Rust toolchain at runtime.

## Crates

| Crate | Path | Purpose |
|-------|------|---------|
| `lr-core` | `crates/lr-core` | Shared foundation: types, codec traits, generic FSM, RIB traits, timers, wire utilities |
| `lr-bgp` | `crates/lr-bgp` | BGP-4 codec, path attributes, peer FSM, capabilities, MP-BGP, AddPath, 4-byte ASN |
| `lr-ospf` | `crates/lr-ospf` | OSPFv2/v3 codec, LSAs, link-state DB, neighbor FSM, SPF, areas, auth |
| `lr-babel` | `crates/lr-babel` | Babel codec, TLVs, neighbor FSM, route table, source-specific routing |
| `lr-rib` | `crates/lr-rib` | Adj-RIB-In, Adj-RIB-Out, Loc-RIB, route selection, cross-protocol merging |
| `lr-policy` | `crates/lr-policy` | Route maps, prefix lists, AS-path filters, community lists |
| `lr-router` | `crates/lr-router` | Layer-3 router instance, sessions, scheduler, event dispatch |
| `lr-ffi` | `crates/lr-ffi` | C ABI bindings (cbindgen-generated header) |
| `lr-tests` | `crates/lr-tests` | Cross-crate integration tests |

## Workspace Layout

```
librouting/
├── Cargo.toml
├── crates/{lr-core, lr-bgp, lr-ospf, lr-babel, lr-rib, lr-policy, lr-router, lr-ffi, lr-tests}/
├── bindings/{lr-go, lr-python}/
├── include/{lr_ffi.h, librouting.hpp}
└── .github/workflows/
```

## Status

Early implementation. The library is **not** production-ready and the C ABI is
**unstable** until v0.5.

## CI/CD

GitHub Actions workflows live in `.github/workflows/` on disk (see the local
checkout). They run on push to `main` and on PRs: fmt + clippy + workspace
tests + C harness + Go bindings + Python bindings + MSRV + cross-build.

**Note**: pushing the workflow files via the bot's PAT requires the `workflow`
scope. The PAT used to push the main code lacks that scope, so the workflow
files are tracked on disk locally but were not pushed to the remote. To
activate CI, either:

1. Grant the bot PAT the `workflow` scope and run `git add .github/workflows && git commit -m "ci: workflows" && git push origin main`, or
2. Open `.github/workflows/*.yml` on the GitHub web UI and create them by hand
   (copy-paste from the local repo).

## License

Dual-licensed under MIT OR Apache-2.0.
