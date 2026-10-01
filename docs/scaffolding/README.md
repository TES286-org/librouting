# Scaffolding guide

How to start a project on the librouting crates: a decoder that stops at the
wire codec, a partial daemon that runs some protocols, or a full daemon. Each
protocol crate exposes three layers — stateless codec, peer FSM, orchestrator
— described in [`ARCHITECTURE.md`](../ARCHITECTURE.md).

[`templates/`](../../templates/README.md) holds working starting points
(analyzer, route reflector, OS integration, BFD); copy one rather than
starting from an empty crate.

## Dependencies

Nothing is published to crates.io; depend on a checkout by `path` or `git`:

```toml
[dependencies]
lr-core   = { path = "../librouting/crates/lr-core" }
lr-bgp    = { path = "../librouting/crates/lr-bgp" }
lr-router = { path = "../librouting/crates/lr-router" }
# or, without a local checkout:
# lr-bgp = { git = "https://github.com/TES286-org/librouting.git" }
```

## Workspace structure

A production router looks like:

```text
my-router/
├── Cargo.toml                  # workspace root
└── crates/
    ├── my-router-daemon/       # the binary
    ├── my-router-config/       # config parsing (TOML/JSON/YANG)
    └── my-router-extensions/   # vendor-specific policy hooks
```

`crates/my-router-daemon/src/main.rs` drives the router through the
`RouterInstance` trait in `crates/lr-router/src/instance.rs`:

```rust
use lr_core::addr::{Asn, RouterId};
use lr_router::{DefaultRouter, RouterInstance, SessionConfig};

fn main() {
    let mut r = DefaultRouter::new();
    let cfg = SessionConfig::bgp(
        Asn(64512), Asn(64513), RouterId::from_v4([10, 0, 0, 1]),
    );
    let h = r.add_session(cfg).expect("add_session");
    // Illustrative: `bytes` is what the transport read.
    r.feed_input(h, &bytes).expect("feed_input");
    let out = r.drain_output(h);
}
```

## Choosing the layer

| Use case | Layer | Crates |
| --- | --- | --- |
| Decode wire traffic | 1 | lr-core + lr-bgp/ospf/babel |
| Drive a protocol FSM yourself | 2 | + the protocol FSM |
| Run a router daemon | 3 | + lr-router, lr-rib, lr-policy |
| Add BFD, kernel routes or damping | 3 | + lr-bfd, lr-osroute, lr-damping |
| Embed from C, C++, Go or Python | — | lr-ffi and [`bindings/`](../bindings/) |

## Extension points

These need no fork:

1. **Hooks** — implement `ImportHook` / `SelectionHook` / `ExportHook`
   (`crates/lr-policy/src/hooks.rs`).
2. **Safety net** — toggle individual checks via `SafetyConfig`.
3. **OS integration** — implement `OsRouteTable` for a non-Linux platform.
4. **BGP roles** — `PeerConfig::role_override`, `otc_role`, `confederation`.
5. **Best-path tuning** — `BestPathConfig`: `always_compare_med`,
   `multipath`, `deterministic_router_id`.

The workspace `[profile.release]` in `Cargo.toml` already sets
`panic = "abort"`, `lto = "thin"` and `codegen-units = 1`.
