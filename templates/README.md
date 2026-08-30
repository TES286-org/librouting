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

| Template            | Description                                          |
|---------------------|------------------------------------------------------|
| `analyzer/`         | Pcap-reading tool that decodes BGP/OSPF/Babel traffic. |
| `bgp-rr/`           | iBGP route reflector cluster with multiple clients.   |
| `os-integration/`   | librouting + Linux rtnetlink (install routes to FIB). |
| `bfd-integration/`  | BGP peer with BFD for sub-second failure detection.   |

## Customizing

Each template is a minimal Cargo project; edit `Cargo.toml` and `src/main.rs`
as needed. The templates don't try to be production-grade — they show the
minimal wiring for the use case.
