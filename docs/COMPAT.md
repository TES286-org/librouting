# Running BIRD and FRR configurations natively

`lr-daemon` loads a **BIRD 2** or **FRR (bgpd)** configuration file
directly and runs it: no conversion step, no lr configuration to write.
Read this page when you are migrating from one of those daemons and want
to know what carries over, what lr adds, and what it refuses.

```sh
lr-daemon --config bird.conf          # BIRD 2 config, runs directly
lr-daemon --config frr.conf           # FRR config, runs directly
lr-daemon --config daemon.toml        # the native lr TOML
lr-daemon --config daemon.lr          # the native lr DSL
```

The dialect is recognised from the file's content.
`--config-dialect lr|toml|bird|frr` forces one when a file mixes shapes,
for example a BIRD file whose `# lr:` directives contain TOML-looking
text. An unrecognised file fails closed instead of guessing.

This is the *compatible form* of the daemon: the source
implementation's semantics apply, so a configuration that ran on BIRD or
FRR behaves the same way under lr. Everything `lr-daemon translate
bird|frr <file>` converts is covered, because compat mode and the
converter share one parse and render pipeline — the rendered TOML goes
through the daemon's regular loader, so the two surfaces cannot drift
apart. Run `lr-daemon translate bird bird.conf` when you want to read the
TOML the daemon will run, review it, and edit from there.

## What is covered

The compat surface covers the **BGP control plane**. Nothing else in the
file changes how lr routes.

| Source shape | lr behaviour |
| --- | --- |
| `router id` (BIRD) / `bgp router-id` (FRR) | `[bgp] router_id` |
| `local as` (BIRD) / `router bgp <as>` (FRR) | `[bgp] local_as` |
| `protocol bgp <name> { … }` (BIRD) | one `[[peer]]` per stanza |
| `neighbor … as` (BIRD) / `neighbor … remote-as` (FRR) | `[[peer]]` with `remote` and `peer_as` |
| `neighbor … port N` (both) | the connect port, merged into `remote` |
| `password` / `neighbor … password 0` | `md5_key`; FRR type-7 passwords are noted, not mapped |
| `local address` / `update-source` | `local_address`, the next-hop-self source |
| `hold time` (BIRD) | per-peer `hold_time` |
| `bfd on` / `off` (BIRD), `neighbor … bfd` (FRR) | per-peer `bfd` |
| `import none` / `export none` | a generated deny-all route-map |
| `import all` / `export all` | the accept-all eBGP policy |
| Prefix lists, as-path access lists, community lists, route-maps | the matching lr policy tables |
| `network PREFIX` (FRR), BIRD static `route` | `networks`, locally originated |
| BIRD `ipv4`/`ipv6` channels, FRR `address-family` plus `activate` | `mp_families` |

Anything the source file contains that has no lr equivalent is never
dropped silently. It becomes a `config warning: unmapped: …` line at
startup, or a `# UNMAPPED:` comment when you run the converter.

A non-BGP routing protocol in the file — BIRD `protocol ospf …`, FRR
`router ospf …`, and friends — is reported and ignored: `config warning:
<stanza>: ignored — the compat surface runs the BGP control plane only`.
The BGP part still runs. BIRD's `protocol device` is housekeeping with no
routing meaning and is skipped without a note.

Combining BGP and OSPF *from one BIRD or FRR file* is not supported: the
compat surface loads the BGP control plane, and the non-BGP stanzas are
reported as ignored. Running several protocols in one process is
supported through lr's own configuration — the `--protocol bgp,ospf`
CLI form and the `protocol = "bgp,ospf"` key — which is a different
surface from loading someone else's file.

## Dialect defaults

BIRD and FRR differ from lr's own defaults in ways that would change a
configuration's behaviour if they were not applied. The compat surface
restores the source implementation's semantics:

| Knob | BIRD file | FRR file | lr TOML default |
| --- | --- | --- | --- |
| eBGP route policy (RFC 8212) | accept-all | accept-all | rfc8212, deny by default |
| `bgp enforce-first-as` | off, no such check | on, FRR's default | off |
| IPv4 unicast activation | implicit, channels refine | implicit on | implicit on |

Accept-all is what both reference implementations do for a peer without
filters: every route is admitted and exported unless an explicit filter
— converted to a route-map — says otherwise. An `lr:` directive can
override it back to RFC 8212 strictness.

The startup lines `bird dialect defaults applied: accept-all eBGP
policy` and `frr dialect defaults applied: enforce-first-as on,
accept-all eBGP policy` state which set was applied.
[`PARITY.md`](PARITY.md) §1 explains why the two dialects need the
opposite default from lr's own.

## lr-specific extensions: `lr:` comment directives

The dialects have no syntax for the parts of lr that the reference
implementations do not have. Extensions ride in as **comment
directives**, which keeps them invisible to real BIRD and FRR: the same
file still loads there.

```
# lr: <key> [value...]            (BIRD: anywhere; FRR: '#' or '!' comment)
! lr: <key> [value...]            (FRR: '!' comment form)
# lr: neighbor ADDR <key> [value] (FRR per-peer form)
```

In BIRD the scope follows the stanza: a directive inside
`protocol bgp <name> { … }` applies to that peer, a directive at the top
of the file is global. In FRR everything is line-based, so the
`neighbor ADDR` form scopes to a peer and the plain form is global.

Keys are matched with `-` and `_` treated as equal (`install-kernel` is
`install_kernel`), and both `key value` and `key = value` are accepted.
An unknown key or a malformed value becomes a warning; neither is
applied silently.

### Global directives

| Directive | Maps to | Example |
| --- | --- | --- |
| `listen ADDR:PORT` | `[bgp] listen_addr` | `# lr: listen 0.0.0.0:1179` |
| `install-kernel [true/false]` | `install_kernel` | `# lr: install-kernel` |
| `api-socket PATH` | `api_socket` | `! lr: api-socket /run/lr/api.sock` |
| `user NAME` / `group NAME` | privilege drop | `# lr: user lr-daemon` |
| `bmp-target ADDR:PORT` | BMP mirroring | `# lr: bmp-target 10.0.0.9:5000` |
| `graceful-restart SEC` | `[bgp] graceful_restart_time` | `# lr: graceful-restart 300` |
| `llgr SEC` / `llgr-max-stale SEC` | RFC 9494 stale timers | `# lr: llgr 3600` |
| `add-path [true/false]` / `add-path-max N` | RFC 7911 | `# lr: add-path` |
| `max-prefixes N` | per-peer prefix limit | `# lr: max-prefixes 1000` |
| `max-prefix-action A` | `warn` / `teardown` / `restart` | `# lr: max-prefix-action teardown` |
| `max-prefix-threshold P` | early-warning percentage | `# lr: max-prefix-threshold 80` |
| `gtsm [N]` | RFC 5082 | `# lr: gtsm 2` |
| `ebgp-policy rfc8212\|accept-all` | overrides the dialect default | `# lr: ebgp-policy rfc8212` |
| `soft-reconfig-inbound [true/false]` | pre-policy retention | `# lr: soft-reconfig-inbound` |

### Per-peer directives

`add-path`, `add-path-max`, `max-prefixes`, `max-prefix-action`,
`max-prefix-threshold`, `gtsm`, `mp-family` (repeatable:
`ipv4-unicast` / `ipv6-unicast`), `tcp-ao-key` (repeatable
`ID:SECRET`, RFC 5925), `extended-next-hop` (RFC 5549),
`allow-local-as [N|any]`, `local-address`, `soft-reconfig-inbound`.

BIRD example:

```
protocol bgp upstream {
    local as 64512;
    neighbor 192.0.2.9 as 64513;
    ipv4 { import filter in; export filter out; };
    # lr: gtsm 2
    # lr: max-prefixes 5000
    # lr: mp-family ipv6-unicast
}
```

FRR example, using the per-peer form:

```
router bgp 64512
 neighbor 192.0.2.9 remote-as 64513
 !
 # lr: neighbor 192.0.2.9 add-path
 # lr: neighbor 192.0.2.9 tcp-ao-key 1:s3cret
 # lr: api-socket /run/lr/api.sock
```

## Reload, signals and the runtime API

A compat-loaded configuration remembers its dialect, so `SIGHUP` and the
runtime API `reload` command re-parse the file through the same dialect
path. The networks diff applies live; peer, auth and router-id changes
still need a restart, exactly as with the native configuration. The
`status` command and every other runtime API command work unchanged. See
[`RUNBOOK.md`](RUNBOOK.md) for the lifecycle and the command reference.

## Testing

- Unit tests: dialect detection, directive resolution and the dialect
  defaults live next to the code, in `crates/lr-cli/src/compat.rs` and
  `crates/lr-cli/src/translate.rs`.
- End to end: `crates/lr-cli/tests/daemon_compat.rs` spawns the real
  binary from BIRD and FRR configurations and asserts session
  establishment, bidirectional route flow and the directive side effects.
- Interop: `tests/interop/compat_bird.sh` and `tests/interop/compat_frr.sh`
  run a compat-mode daemon against real BIRD 2 and FRR bgpd; see
  [`INTEROP.md`](INTEROP.md).

## Limitations

- BGP control plane only. OSPF, Babel and BFD stanzas in the source file
  are reported as ignored; BFD *settings on a BGP peer* do map.
- A BIRD or FRR `include` is not expanded: the compat loader takes the
  file it was given, so an include-heavy configuration needs its pieces
  inlined first. The native `.lr` dialect is different — it resolves
  `include "path";`, including globs, with cycle and depth guards.
- FRR type-7 encrypted passwords and VRFs have no lr equivalent and are
  noted rather than mapped.
- One dialect per file. An FRR file containing BIRD stanzas, or the
  reverse, fails to parse; split it.
- The native TOML schema has no `include` equivalent either, so a split
  TOML configuration has to be passed as one file.
