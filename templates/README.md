# librouting scaffolding templates

Each subdirectory of `templates/` is a self-contained Cargo workspace that
scaffolds one common librouting use case. Copy it as the starting point
for a new project:

```
cp -r templates/analyzer ~/projects/my-analyzer
cd ~/projects/my-analyzer
cargo run --release -- --pcap capture.pcap
```

## Available templates

| Template           | Description                                            |
| ------------------ | ------------------------------------------------------ |
| `daemon.lr`        | lr-daemon configuration, native `.lr` DSL (preferred). |
| `daemon.toml`      | The same configuration in the TOML subset (compat).    |
| `analyzer/`        | Pcap-reading tool that decodes BGP/OSPF/Babel traffic. |
| `bgp-rr/`          | iBGP route reflector cluster with multiple clients.    |
| `os-integration/`  | librouting + Linux rtnetlink (install routes to FIB).  |
| `bfd-integration/` | BGP peer with BFD for sub-second failure detection.    |

## Daemon configuration

`daemon.lr` and `daemon.toml` are two spellings of one configuration:
both parse to the same IR (pinned by tests) and both document every
daemon key as commented examples. Start from the `.lr` file — the
native dialect is DSL-first since ROADMAP-v3 D16 Phase 3 (issue #18):

```
lr-daemon --config templates/daemon.lr
lr-daemon config check templates/daemon.lr   # validate without starting
lr-daemon config to-dsl templates/daemon.toml > converted.lr
```

The TOML subset stays fully supported through 1.x (deprecated) and is
planned for removal in 2.x; `config to-dsl` is the migration bridge.
The DSL grammar is specified in `docs/config_dsl_grammar.md`.

## Customizing

Each template is a minimal Cargo project; edit `Cargo.toml` and `src/main.rs`
as needed. The templates don't try to be production-grade — they show the
minimal wiring for the use case.
