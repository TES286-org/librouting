# librouting

A platform-independent routing protocol library in Rust. The library
parses, speaks, and computes routes for BGP (RFC 4271 and extensions),
OSPFv2/v3 (RFC 2328 / RFC 5340 and extensions), Babel (RFC 8966 and
extensions), LDP (RFC 5036), and the MPLS label codec (RFC 3032). BFD
(RFC 5880) provides fast peer failure detection; route flap damping
(RFC 2439) is available; an OS route-table reference implementation
(Linux rtnetlink, BSD route(4), Windows IP Helper) and a Linux MPLS
dataplane mirror are opt-in crates. The library is verified
bidirectionally against BIRD 2 and FRR 10 in CI on Linux, macOS and
Windows.

The library is transport-free: nothing in `lr-*` opens a socket or
touches an OS routing table. The embedder owns bytes and time; `lr`
owns protocol state. The shipped `lr-daemon` binary is the reference
embedder — every pattern in the library ends up on the daemon's flag
surface so it can be tested end-to-end.

## Quick start

```sh
git clone https://github.com/TES286-org/librouting.git
cd librouting
cargo build --release -p lr-cli
# → target/release/lr          (inspection CLI)
# → target/release/lr-daemon   (reference daemon)
# → target/release/lrctl       (operational CLI)
```

Run a two-speaker BGP lab on loopback:

```sh
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

The daemon also reads BIRD 2 and FRR 10 configs directly
(`lr-daemon --config bird.conf`), runs OSPF, Babel, LDP and BMP, and
multiplexes protocols in one process (`--protocol bgp,ospf`). The
native `.lr` DSL carries configuration and policy in one file — see
`templates/daemon.lr` for the fully-commented reference. See
[`docs/lr-cli.md`](docs/lr-cli.md) for the full CLI guide and
[`docs/RUNBOOK.md`](docs/RUNBOOK.md) for day-2 operations.

## Crates

| Crate        | Purpose                                                                  |
| ------------ | ------------------------------------------------------------------------ |
| `lr-core`    | Shared types, codec traits, generic FSM, RIB traits, timers              |
| `lr-bgp`     | BGP-4 codec, peer FSM, capabilities, best-path, roles, extensions       |
| `lr-ospf`    | OSPFv2/v3 codec, LSAs, LSDB, neighbor FSM, SPF, areas, auth              |
| `lr-babel`   | Babel codec, TLVs, neighbor FSM, route table, MAC auth                    |
| `lr-rib`     | Adj-RIB-In, Adj-RIB-Out, Loc-RIB, selection, cross-protocol merging       |
| `lr-policy`  | Route maps, prefix/AS-path/community lists, hooks, safety net, filter DSL |
| `lr-router`  | Layer-3 router instance, sessions, scheduler, event dispatch             |
| `lr-bfd`     | BFD codec (RFC 5880) + session FSM                                        |
| `lr-mpls`    | MPLS label + label-stack codec (RFC 3032)                                |
| `lr-ldp`     | LDP codec + state machines (RFC 5036)                                    |
| `lr-osroute` | OS route integration + protocol transports (Linux / BSD / Windows)       |
| `lr-mrt`     | MRT dump format (RFC 6396)                                               |
| `lr-bmp`     | BGP Monitoring Protocol (RFC 7854)                                       |
| `lr-damping` | Route flap damping (RFC 2439)                                            |
| `lr-srv6`    | SRv6 SID, locator, behavior                                             |
| `lr-ffi`     | C ABI bindings (cbindgen-generated header)                               |
| `lr-cli`     | `lr` + `lr-daemon` + `lrctl` binaries                                    |
| `lr-tests`   | Cross-crate integration tests                                            |

Every protocol crate follows the same three-layer shape:

| Layer | What                             | Example                |
| ----- | -------------------------------- | ---------------------- |
| 1     | Stateless wire codec             | `BgpCodec`, `BfdCodec` |
| 2     | Peer FSM + transport abstraction | `BgpPeer::step`        |
| 3     | Orchestrator (sessions + RIB)     | `DefaultRouter`        |

See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for the layering,
the RIB pipeline, and the extension points.

## Bindings

The C ABI (`lr-ffi`, header in `include/lr_ffi.h`) lets Go, Python, C
and C++ embedders call into the library without a Rust toolchain at
runtime. The C++ RAII wrapper lives in `include/librouting.hpp`.

- **Go** — [`docs/bindings/go.md`](docs/bindings/go.md), `bindings/lr-go/`
- **Python** — [`docs/bindings/python.md`](docs/bindings/python.md), `bindings/lr-python/`
- **C** — [`docs/bindings/c.md`](docs/bindings/c.md)
- **C++** — [`docs/bindings/cpp.md`](docs/bindings/cpp.md)
- **FFI design** — [`docs/ffi_design.md`](docs/ffi_design.md)

## Documentation

The full documentation set lives under [`docs/`](docs/). Start at
[`docs/README.md`](docs/README.md) for the per-audience index:

- **Getting started** — [`docs/tutorial.md`](docs/tutorial.md) (book-style walk)
- **Embedding (Rust)** — [`docs/API.md`](docs/API.md), [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md)
- **Running the daemon** — [`docs/lr-cli.md`](docs/lr-cli.md), [`docs/RUNBOOK.md`](docs/RUNBOOK.md), `templates/daemon.lr`
- **Configuration** — [`docs/config_dsl_grammar.md`](docs/config_dsl_grammar.md), [`docs/filter_dsl_grammar.md`](docs/filter_dsl_grammar.md)
- **Protocol coverage** — [`docs/STATUS.md`](docs/STATUS.md), [`docs/RFC_MAP.md`](docs/RFC_MAP.md), [`docs/PARITY.md`](docs/PARITY.md), [`docs/INTEROP.md`](docs/INTEROP.md)
- **Interop with BIRD/FRR** — [`docs/COMPAT.md`](docs/COMPAT.md) (running their configs natively)
- **Platform porting** — [`docs/OS-INTEGRATION.md`](docs/OS-INTEGRATION.md)
- **Internals** — [`docs/lr-cli-internals.md`](docs/lr-cli-internals.md), [`docs/ffi_design.md`](docs/ffi_design.md)
- **Releases** — [`docs/RELEASE-PLAN.md`](docs/RELEASE-PLAN.md), [`docs/ROADMAP.md`](docs/ROADMAP.md)
- **Research** — [`docs/research/`](docs/research)
- **Contributing** — [`CONTRIBUTING.md`](CONTRIBUTING.md), [`AGENTS.md`](AGENTS.md)

## Status

The public Rust API and the C ABI are frozen for the 1.0 cut. See
[`docs/STATUS.md`](docs/STATUS.md) for the implemented-vs-missing gap
analysis and [`docs/RELEASE-PLAN.md`](docs/RELEASE-PLAN.md) for the
remaining 1.0.0 freeze criteria. The current workspace version is in
`Cargo.toml` (`[workspace.package] version`).

## License

Dual-licensed under MIT OR Apache-2.0.
