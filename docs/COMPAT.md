# Running BIRD and FRR configurations natively (compat surface)

`lr-daemon` can load a **BIRD 2** or **FRR (bgpd)** configuration file
directly and run it — no conversion step, no lr TOML to write:

```bash
lr-daemon --config bird.conf          # BIRD 2 config, runs directly
lr-daemon --config frr.conf           # FRR config, runs directly
lr-daemon --config daemon.toml        # the native lr TOML (as before)
```

The dialect is recognised from the file's content; `--config-dialect
bird|frr|toml` forces one when a file mixes shapes (for example a BIRD
file whose `# lr:` extension comments contain TOML-looking text). An
unrecognised file fails closed instead of guessing.

This is the *compatible form* of the daemon: the source
implementation's semantics apply, so a config that ran on BIRD or FRR
behaves the same way under lr. Everything `lr-daemon translate
bird|frr <file>` converts is covered — compat mode and the converter
share exactly one parse/render pipeline (the rendered TOML is loaded
by the daemon's regular parser), so the two surfaces cannot drift
apart. Run `lr-daemon translate bird bird.conf` when you want to see
the TOML the daemon will run, review it, and edit it from there.

## What is covered

The compat surface covers the **BGP control plane** — the same scope
as the W5.1 converter:

| Source shape | lr behaviour |
| ------------ | ------------- |
| `router id` (BIRD) / `bgp router-id` (FRR) | `[bgp] router_id` |
| `local as` (BIRD) / `router bgp <as>` (FRR) | `[bgp] local_as` |
| `protocol bgp <name> { … }` (BIRD) | one `[[peer]]` per stanza |
| `neighbor … as` (BIRD) / `neighbor … remote-as` (FRR) | `[[peer]]` with `remote` + `peer_as` |
| `neighbor … port N` (both) | connect port merged into `remote` |
| `password` / `neighbor … password 0` | `md5_key` (type 7 is noted, not mapped) |
| `local address` / `update-source` | `local_address` (next-hop-self source) |
| `hold time` (BIRD) | per-peer `hold_time` |
| `bfd on/off` / `neighbor … bfd` | per-peer `bfd` |
| `import none` / `export none` | generated deny-all route-map |
| `import all` / `export all` | the accept-all eBGP policy (see defaults) |
| prefix-lists, as-path access-lists, community-lists, route-maps | the matching lr policy tables |
| `network PREFIX` (FRR), BIRD static `route` | `networks` (locally originated) |
| BIRD `ipv4`/`ipv6` channels, FRR `address-family` + `activate` | `mp_families` |

Anything the source config contains that has no lr equivalent is
never dropped silently: it becomes a `config warning: unmapped: …`
line at startup (and a `# UNMAPPED:` comment when you run the
converter). Non-BGP routing protocols in the file — BIRD
`protocol ospf …`, FRR `router ospf …`, and friends — are reported as
ignored (`config warning: <stanza>: ignored — the compat surface runs
the BGP control plane only`) and the BGP part still runs. BIRD's
`protocol device` is housekeeping with no routing meaning and is
skipped without a note. Multi-protocol operation (BGP and OSPF from
one file in one process) is future work — see the roadmap.

## Dialect defaults

BIRD and FRR differ from lr's own defaults in ways that would change
a config's behaviour if they were not applied. The compat surface
restores the source implementation's semantics:

| Knob | BIRD file | FRR file | lr TOML default |
| ---- | --------- | -------- | --------------- |
| eBGP route policy (RFC 8212) | accept-all | accept-all | rfc8212 (deny by default) |
| `bgp enforce-first-as` | off (no such check) | **on** (FRR default) | off |
| IPv4-unicast activation | implicit, channels refine | implicit on | implicit on |

The accept-all policy is what both reference implementations do for a
peer without filters: every route is admitted and exported unless an
explicit filter (converted to a route-map) says otherwise. An `lr:`
directive can override it back to the RFC 8212 strictness (below).

## lr-specific extensions: `lr:` comment directives

The dialects have no syntax for the parts of lr the reference
implementations do not have. Extensions ride in as **comment
directives**, which keeps them invisible to real BIRD and FRR — the
same file still loads in the reference implementations:

```
# lr: <key> [value...]            (BIRD: anywhere; FRR: '#' or '!' comment)
! lr: <key> [value...]            (FRR: '!' comment form)
# lr: neighbor ADDR <key> [value] (FRR per-peer form)
```

In BIRD the scope follows the stanza: a directive inside
`protocol bgp <name> { … }` applies to that peer, a directive at the
top of the file is global. In FRR everything is line-based, so the
`neighbor ADDR` form scopes to a peer and the plain form is global.

Keys are matched with `-` and `_` treated as equal
(`install-kernel` = `install_kernel`). Unknown keys and malformed
values are reported as warnings; they never silently disappear.

### Global directives

| Directive | Maps to | Example |
| --------- | ------- | ------- |
| `listen ADDR:PORT` | `[bgp] listen_addr` | `# lr: listen 0.0.0.0:1179` |
| `install-kernel [true/false]` | `install_kernel` | `# lr: install-kernel` |
| `api-socket PATH` | `api_socket` | `! lr: api-socket /run/lr/api.sock` |
| `user NAME` / `group NAME` | privilege drop | `# lr: user lr-daemon` |
| `bmp-target ADDR:PORT` | BMP mirroring | `# lr: bmp-target 10.0.0.9:5000` |
| `graceful-restart SEC` | `[bgp] graceful_restart_time` | `# lr: graceful-restart 300` |
| `llgr SEC` / `llgr-max-stale SEC` | RFC 9494 stale timers | `# lr: llgr 3600` |
| `add-path [true/false]` / `add-path-max N` | RFC 7911 | `# lr: add-path` |
| `max-prefixes N` / `max-prefix-action A` | peer limits | `# lr: max-prefixes 1000` |
| `gtsm [N]` | RFC 5082 | `# lr: gtsm 2` |
| `ebgp-policy rfc8212\|accept-all` | override the dialect default | `# lr: ebgp-policy rfc8212` |
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

FRR example (the per-peer form):

```
router bgp 64512
 neighbor 192.0.2.9 remote-as 64513
 !
 # lr: neighbor 192.0.2.9 add-path
 # lr: neighbor 192.0.2.9 tcp-ao-key 1:s3cret
 # lr: api-socket /run/lr/api.sock
```

## Reload, signals, runtime API

A compat-loaded config remembers its dialect, so `SIGHUP` and the
runtime API `reload` re-parse the file through the same dialect path
(the networks diff applies live; peer/auth/router-id changes still
need a restart, exactly as with TOML). The `status` command and all
other runtime API commands work unchanged.

## Testing

- Unit tests: dialect detection, directive resolution and the
  dialect defaults live next to the code
  (`crates/lr-cli/src/compat.rs`, `crates/lr-cli/src/translate.rs`).
- End-to-end: `crates/lr-cli/tests/daemon_compat.rs` spawns the real
  binary from BIRD and FRR configs and asserts session establishment,
  bidirectional route flow and the directive side effects.
- Interop: `tests/interop/compat_bird.sh` and
  `tests/interop/compat_frr.sh` run a compat-mode lr-daemon against
  real BIRD 2 / FRR bgpd (see `INTEROP.md`).

## Limitations

- BGP control plane only; OSPF/Babel/BFD stanzas in the source file
  are reported as ignored (BFD *settings on a BGP peer* do map).
- BIRD `include` is not expanded; an include-heavy file needs its
  pieces inlined first.
- FRR type-7 encrypted passwords and VRFs have no lr equivalent and
  are noted.
- One dialect per file: an FRR file with BIRD stanzas (or vice versa)
  fails to parse — split it.
