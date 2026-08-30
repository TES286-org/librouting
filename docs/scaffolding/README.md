# Scaffolding guide

This document describes how to scaffold a new librouting-based project,
either as an analyzer (read-only pcap processor), a partial daemon (only
some protocols), or a full daemon (BGP + OSPF + Babel).

## Option A — Quick start (clone the template)

Use `cargo new` to start a binary crate, then add `librouting` as a
dependency:

```bash
cargo new --bin my-router
cd my-router
cat >> Cargo.toml <<EOF
[dependencies]
lr-core   = { path = "../librouting/crates/lr-core" }
lr-bgp    = { path = "../librouting/crates/lr-bgp" }
lr-router = { path = "../librouting/crates/lr-router" }
EOF
```

For an *external* project, use the published crate:

```toml
[dependencies]
lr-bgp    = "0.1"
lr-router = "0.1"
```

## Option B — Workspace structure for forks

A production router built on top of `librouting` typically looks like:

```
my-router/
├── Cargo.toml          # workspace root
├── crates/
│   ├── my-router-daemon/      # the binary
│   ├── my-router-config/      # config parsing (TOML/JSON/YANG)
│   └── my-router-extensions/  # vendor-specific policy hooks
├── docs/
└── tests/
```

`crates/my-router-daemon/src/main.rs`:

```rust
use std::process::ExitCode;
use lr_router::{DefaultRouter, RouterInstance, SessionConfig};
use lr_core::addr::{Asn, RouterId};

fn main() -> ExitCode {
    let mut r = DefaultRouter::new();
    let _h = r.add_session(SessionConfig::bgp(
        Asn(64512), Asn(64513), RouterId::from_v4([10,0,0,1]),
    )).expect("add_session");
    // ... open TCP, wire bytes into r.feed_input, drain_output
    ExitCode::SUCCESS
}
```

## Templates

The `templates/` directory contains scaffolding for common use cases:

| Template            | Description                                          |
|---------------------|------------------------------------------------------|
| `analyzer/`         | Pcap-reading tool that decodes BGP/OSPF/Babel traffic. |
| `bgp-rr/`           | iBGP route reflector cluster with multiple clients.   |
| `os-integration/`   | librouting + Linux rtnetlink (install routes to FIB). |
| `bfd-integration/`  | BGP peer with BFD for sub-second failure detection.   |

Each template is a self-contained Cargo workspace that can be cloned and
extended.

## Choosing the right layer

| Use case                                              | Layer | Crates                 |
|-------------------------------------------------------|-------|------------------------|
| Build a pcap analyzer                                 |   1   | lr-core + lr-bgp/ospf/babel |
| Build a custom protocol FSM driver                    |   2   | + lr-bgp/ospf/babel FSM     |
| Build a router daemon                                 |   3   | + lr-router, lr-rib, lr-policy |
| Add BFD fast detection                                |   3   | + lr-bfd                   |
| Install routes into the kernel                        |   3   | + lr-osroute               |
| Suppress route flaps                                  |   3   | + lr-damping               |
| Embed in a non-Rust application (Go/Python/C/C++)    |   —   | lr-ffi + bindings           |

## Extension points

After scaffolding, the following customization points are available without
forking:

1. **Policy hooks** — implement `ImportHook` / `ExportHook` /
   `SelectionHook` to override route handling.
2. **Safety net** — toggle individual checks via `SafetyConfig`.
3. **OS integration** — implement `OsRouteTable` for non-Linux platforms.
4. **BGP roles** — set `PeerConfig::role_override` / `otc_role` /
   `confederation` for non-standard topology.
5. **Best-path tuning** — use `BestPathConfig` to enable
   `always_compare_med`, `multipath`, `deterministic_router_id`, etc.

## Deployment tips

- Run with `PANIC=abort` to ensure panics don't poison mutexes; the
  release profile already sets `panic = "abort"`.
- Build with `--release` for production; `lto = "thin"` + `codegen-units = 1`
  is already in the workspace profile.
- For running in a sandboxed environment, exclude `lr-osroute` to avoid
  FFI side effects.
- For deterministic path selection in a multi-speaker setup, keep
  `deterministic_router_id = true` (the default).
