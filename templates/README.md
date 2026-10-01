# librouting templates

`templates/` holds the reference daemon configuration and the scaffolding
projects. Copy a project directory as the starting point for a new tool:

```sh
cp -r templates/analyzer ~/projects/my-analyzer
cd ~/projects/my-analyzer
# Decode a hex blob on stdin as a BGP message (argv[1] picks the kind).
echo 'ffffffffffffffffffffffffffffffff001304' | cargo run -- bgp
```

Each project directory is a self-contained Cargo workspace with its own
`[workspace]` table, so it builds outside the librouting workspace.

## Available templates

| Template | Description |
| --- | --- |
| `analyzer/` | Decodes a hex BGP message read from stdin. |
| `bgp-rr/` | iBGP route reflector cluster (RFC 4456). |
| `os-integration/` | `lr-osroute` over Linux rtnetlink; installs routes. |
| `bfd-integration/` | BGP peer with BFD fast failure detection. |

`daemon.lr` and `daemon.toml` are files, not projects: two spellings of one
daemon configuration that parse to the same IR, pinned by
`shipped_templates_match_across_frontends` in
`crates/lr-cli/src/daemon_config.rs`.

## Daemon configuration

Start from `daemon.lr`; both files comment every daemon key.

```sh
lr-daemon --config templates/daemon.lr
lr-daemon config check templates/daemon.lr   # validate, do not start
lr-daemon config to-dsl templates/daemon.toml > converted.lr
```

The TOML subset stays supported and is deprecated. The notice in
`crates/lr-cli/src/daemon_config.rs` promises removal in 2.0, and
`config to-dsl` is the migration path. The grammar is specified in
[`docs/config_dsl_grammar.md`](../docs/config_dsl_grammar.md).
