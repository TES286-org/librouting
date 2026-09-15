# lr-cli — User Guide

`lr-cli` is the librouting command-line package. It ships **three
binaries**, all built from the same crate (`crates/lr-cli`):

| Binary        | Purpose                                                       |
| ------------- | ------------------------------------------------------------- |
| `lr`          | The protocol-inspection CLI — decode wire bytes, parse MRT dumps, replay captured streams. |
| `lr-daemon`   | The reference daemon — runs a real BGP / OSPF / Babel / LDP / BMP router with a config file or CLI flags. |
| `lrctl`       | The operational CLI — connects to a running `lr-daemon` over its Unix API socket (status / sessions / routes / reload / shutdown) and validates filter DSL bodies client-side. |

```sh
cargo build --release -p lr-cli
# → target/release/lr
# → target/release/lr-daemon
# → target/release/lrctl
```

All three binaries are intentionally dependency-light: `lr` has no
argument-parsing library at all, `lr-daemon` parses its own argv in
`daemon_config::parse_args` so a stripped container can still run the
daemon, and `lrctl` mirrors the same hand-rolled style. Operators
looking for a full production BGP daemon should use BIRD / FRR /
OpenBGPD; `lr-cli` is the librouting reference implementation — every
feature in the library ends up on the daemon's flag surface so it can
be tested end-to-end.

This guide is the user-facing reference. For the architecture, module
layout and extension points see
[`lr-cli-internals.md`](lr-cli-internals.md). For the runtime API
exposed on the management socket, see
[`RUNBOOK.md`](RUNBOOK.md). For every config key (with line-by-line
explanation), see `templates/daemon.toml`.

---

## `lr` — the inspection CLI

```text
USAGE:
    lr <command> [args]

COMMANDS:
    version            Print library version + crate list
    decode <kind> <hex> Decode a wire message
                       kind: bgp-open|bgp-keepalive|bfd
    routes list         Dump kernel routing table
    routes add <prefix> <gw> <if_index>
                       Add a route to the kernel
    routes del <prefix> Delete a route from the kernel
    mrt parse <file>    Decode an MRT dump record by record
    mrt rib <file>      Print the RIB an MRT dump carries
    mrt diff <a> <b>    Content-diff two MRT RIB dumps
    parity-replay       Replay a captured BGP stream into an
                       offline router, dump the Loc-RIB as MRT
    help                Show this message
```

Exit codes: `0` success, `1` runtime failure (decode error, file
I/O, kernel error), `2` usage error (bad subcommand or wrong
argument count).

### `lr version`

```sh
$ lr version
librouting 0.1.0
crates: lr-core, lr-bgp, lr-ospf, lr-babel, lr-ldp, lr-bfd, lr-rib, lr-policy, lr-router, lr-damping, lr-mpls, lr-mrt, lr-bmp, lr-osroute, lr-ffi
```

Prints the library version (from `Cargo.toml`) and the list of
workspace crates the binary was built against. Useful for confirming
which feature set a binary carries before debugging a wire issue.

### `lr decode <kind> <hex>`

Decodes a single wire message and pretty-prints its fields. `<hex>`
is the raw bytes — including any framing marker / header (BGP's
16-octet marker + 2-byte length + 1-byte type, BFD's fixed 24/26-byte
header). A `0x` prefix is accepted but optional; odd-length hex is an
error.

| `<kind>`       | Codec used                | Wire shape                                                                                   |
| -------------- | ------------------------- | -------------------------------------------------------------------------------------------- |
| `bgp-open`     | `lr_bgp::BgpCodec`        | 16-byte marker + 2-byte length + 1-byte type (1=OPEN) + body                                  |
| `bgp-keepalive`| `lr_bgp::BgpCodec`        | 16-byte marker + 2-byte length + 1-byte type (4=KEEPALIVE), no body                          |
| `bfd`          | `lr_bfd::BfdCodec`        | RFC 5880 fixed 24-byte header (or 26 with authentication)                                     |

```sh
# A BGP KEEPALIVE is just the marker + length 19 + type 4.
$ lr decode bgp-keepalive \
    ffffffffffffffffffffffffffffffff001304
BgpMessage::Keepalive(...)
```

```sh
# A BFD control packet (version 1, diagnostic 0, state Down).
$ lr decode bfd \
    4090000020c0000000000f424000000753000000000000000
BfdPacket { version: 1, diagnostic: 0, state: Down, ... }
```

### `lr routes <list|add|del>`

Direct kernel routing-table manipulation through `lr-osroute`. The
backend is picked automatically: Linux `rtnetlink`, BSD/macOS
`route(4)` socket, Windows `IP Helper`. On platforms without a
native backend (`stub`), the commands return an error.

```sh
# Show the kernel FIB.
$ lr routes list
prefix                            next_hop             if   metric proto
203.0.113.0/24                    192.0.2.1            2    0      Bgp
198.51.100.0/24                   (none)               1    0      Kernel
```

```sh
# Add a route — needs CAP_NET_ADMIN on Linux / Administrator on Windows.
$ lr routes add 198.51.100.0/24 192.0.2.1 2
added: 198.51.100.0/24 via 192.0.2.1 dev 2
```

```sh
$ lr routes del 198.51.100.0/24
deleted: 198.51.100.0/24
```

### `lr mrt parse <file>` / `lr mrt rib <file>` / `lr mrt diff <a> <b>`

MRT (RFC 6396) dump tooling on top of `lr-mrt`.

- `lr mrt parse <file.mrt>` — one summary line per record (peer
  tables, RIB sequence + prefix, BGP4MP state changes and messages).
- `lr mrt rib <file.mrt>` — the RIB view: the peer index table
  followed by one line per (prefix, entry) with AS path, next hop,
  peer, and the RFC 7911 Add-Path `PATH-ID`.
- `lr mrt diff <a.mrt> <b.mrt>` — content-diff two RIB dumps: per
  prefix, compares AS path, next hop, local-pref, MED and
  communities; ignores dump-specific noise (timestamps, peer
  indexes, view names). Exit `1` when they differ, `0` when they
  match — usable as an interop assertion.

```sh
# Inspect a BIRD MRT dump.
$ lr mrt rib /tmp/bird.rib.mrt
view "bird" collector=10.0.0.1
  peer[0] 10.0.0.2 asn=64513 ip=192.0.2.2
PREFIX              PEER           AS-PATH                     NEXT-HOP        PATH-ID
203.0.113.0/24      10.0.0.2       64513                       192.0.2.2      -
198.51.100.0/24     10.0.0.2       64513 64514                 192.0.2.2      -
2 rib record(s)
```

### `lr parity-replay`

The wire-level parity harness (ROADMAP.md W5.3): replay a captured
BGP message stream into an offline `lr-router` pipeline and dump the
resulting Loc-RIB as an MRT `TABLE_DUMP_V2` file. Combined with
`lr mrt diff`, this answers "does librouting produce the same RIB
as the reference implementation given the same wire stream?".

The capture file is line-oriented JSON
(`{"dir":"down","hex":"…"}`, one BGP message per line). The interop
proxy `tests/parity/capture_proxy.py` produces them off the wire;
in-process tests can also write them via `lr_cli::parity::write_capture`.

```sh
# Replay a captured exchange and diff against BIRD's dump.
$ lr parity-replay \
    --in captured.json \
    --local-as 64512 --peer-as 64513 --router-id 10.0.0.1 \
    --out lr-loc-rib.mrt
$ lr mrt diff lr-loc-rib.mrt bird-loc-rib.mrt && echo parity
```

Run `lr parity-replay --help` for the full flag set. The parity
harness is what the CI interop matrix uses to assert wire-level
equivalence with BIRD 2 and FRR 10 — see
[`INTEROP.md`](INTEROP.md) for the lab.

---

## `lr-daemon` — the reference daemon

```text
USAGE:
  lr-daemon --local-as AS --peer-as AS --router-id A.B.C.D \
            [--peer ADDR:PORT]... [--listen ADDR:PORT] \
            [--network PREFIX]... [--hold-time SEC]
  lr-daemon --config daemon.toml [--install-kernel-routes]
  lr-daemon --config bird.conf|frr.conf   (the dialect is auto-detected)
  lr-daemon translate <bird|frr> <config-file>
  lr-daemon yang render <config-file> [--model babel|keychain|all]

SUBCOMMANDS:
  translate bird|frr FILE  Best-effort conversion of a BIRD 2 / FRR BGP
                           config into lr daemon TOML.
  yang render FILE         Render the Babel subset of a daemon TOML as
                           RFC 9647 / RFC 8177 XML instance data.
```

### Quick start — single-peer BGP

```sh
# Build once.
cargo build --release -p lr-cli
# Local router 64512 (router-id 10.0.0.1) peers with 64513 at 192.0.2.2:179.
# Originate 203.0.113.0/24 and install best routes into the kernel FIB.
./target/release/lr-daemon \
    --local-as 64512 --peer-as 64513 --router-id 10.0.0.1 \
    --peer 192.0.2.2:179 --local-address 192.0.2.1 \
    --network 203.0.113.0/24 \
    --install-kernel-routes
```

The same shape as a TOML file:

```toml
[bgp]
local_as     = 64512
peer_as      = 64513
router_id    = "10.0.0.1"
peer_addr    = "192.0.2.2:179"
local_address = "192.0.2.1"
hold_time    = 90
install_kernel = true

[[networks]]
prefix = "203.0.113.0/24"
```

```sh
./target/release/lr-daemon --config daemon.toml
```

### Multi-peer — `[[peer]]` tables

Add one `[[peer]]` table per remote. Every key inherits the `[bgp]`
globals when omitted, so a peer can be as short as the address:

```toml
[bgp]
local_as  = 64512
router_id = "10.0.0.1"

[[peer]]
remote   = "192.0.2.2:179"
peer_as  = 64513
import   = "from-upstream"
export   = "to-upstream"

[[peer]]
address  = "192.0.2.3"        # listen-only, expected source IP
peer_as  = 64514
bfd      = true
```

The same shape on the command line: `--peer ADDR:PORT` is
repeatable; all `--peer` instances share `--peer-as`. Per-peer
settings require TOML.

A `[[peer]]` that combines `remote` and `address` is bidirectional:
the daemon connects out **and** accepts inbound connections for it,
running the two transports on separate sessions and resolving the
collision per RFC 4271 §6.8 — the connection initiated by the
speaker with the higher BGP Identifier survives; the loser receives a
`Cease / Connection Collision Resolution` NOTIFICATION.

### Running BIRD / FRR configs directly

```sh
# The daemon recognises the dialect from the file's content;
# --config-dialect forces one when auto-detection is ambiguous.
./target/release/lr-daemon --config /etc/bird/bird.conf
./target/release/lr-daemon --config /etc/frr/frr.conf
./target/release/lr-daemon --config bird.conf --config-dialect bird
```

The dialect persists across `SIGHUP` reloads. Unmapped constructs and
non-BGP stanzas in a BIRD/FRR file become startup warnings — see
[`COMPAT.md`](COMPAT.md) for the full mapping surface, the `lr:`
extension directives, and the documented deviations.

### `lr-daemon translate` — best-effort config conversion

```sh
$ lr-daemon translate bird /etc/bird/bird.conf > daemon.toml
$ lr-daemon translate frr  /etc/frr/frr.conf    > daemon.toml
```

Best-effort, line-based conversion of BIRD 2 / FRR BGP configs into
lr daemon TOML. Mapped shapes: `router id` / `router-id`, local AS,
peers (`neighbor … as` / `remote-as`, non-default ports →
`remote` ADDR:PORT), MD5 auth, `local address` / `update-source`,
hold time, BFD, `import|export none|all` idioms, prefix-lists,
as-path access-lists, community-lists, route-map `match`/`set`
clauses, FRR `network` and BIRD `route` static prefixes. Anything
unmappable is kept as an explicit `# UNMAPPED:` comment instead of
being dropped silently; FRR peers without a `remote-as` and dangling
policy references are dropped with notes — the daemon would refuse
to start them (fail-closed policy resolution).

### `lr-daemon yang render` — RFC 9647 / RFC 8177 XML instance data

```sh
$ lr-daemon yang render daemon.toml > babel.xml
$ lr-daemon yang render daemon.toml --model babel   > babel-only.xml
$ lr-daemon yang render daemon.toml --model keychain > keychain.xml
```

Renders the Babel subset of a daemon TOML as NETCONF-style XML
instance data for the standards-track YANG models shipped in
`yang/`:

- `ietf-babel` (RFC 9647) — the Babel protocol configuration.
- `ietf-key-chain` (RFC 8177) — the same symmetric keys expressed in
  the generic key-chain model. BLAKE2s keys are a hard error here
  (RFC 8177 has no `crypto-algorithm` identity for BLAKE2s); render
  `--model babel` instead.

`--model all` (the default) wraps both top-level elements in a
NETCONF `<config>` element. The mapping is config → instance data
only — `lr` does not implement a YANG validator, and `config false`
nodes are not rendered. See [`INTEROP.md`](INTEROP.md) for the
`yang.sh` lab that exercises this surface against `libyang`.

### Lifecycle

| Signal (Unix) / Event (Windows) | Effect |
| ------------------------------ | ------ |
| `SIGTERM`, `SIGINT` | Graceful: every BGP session receives a NOTIFICATION CEASE (RFC 4271 §6.4), the Loc-RIB is torn down cleanly, exit code 0. |
| `SIGHUP` | Reload: re-applies `networks` (new prefixes originated, removed ones withdrawn). Bad config keeps the current one running — never crashes or half-applies. AS, router-id, peer, auth changes always require a restart; the reload output says so explicitly. On non-Unix platforms `SIGHUP` does not exist — reload is via the runtime API `reload` command instead. |
| Ctrl-C (Windows console) | Same as `SIGINT` on Unix — graceful shutdown. |

`--user NAME` / `--group NAME` drop privileges after the listening
sockets are bound (port 179 needs root; the daemon can hold it and
then run unprivileged). `--api-socket PATH` exposes the management
plane (see [`RUNBOOK.md`](RUNBOOK.md) for the command protocol).

### Daemon flag reference (BGP)

Every flag below has a TOML counterpart documented in
`templates/daemon.toml`. "Global" keys live under `[bgp]`; per-peer
overrides live under `[[peer]]` and inherit the global when omitted.

| Flag | TOML | Default | Notes |
| --- | --- | --- | --- |
| `--local-as AS` | `local_as` | (required) | Local autonomous system. |
| `--peer-as AS` | `peer_as` | (required for legacy single-peer) | Remote AS for `--peer`. Per-peer `peer_as` overrides. |
| `--router-id A.B.C.D` | `router_id` | (required for BGP) | BGP Identifier. |
| `--config PATH` | (config file) | — | The dialect (lr TOML, BIRD 2, FRR) is auto-detected. |
| `--config-dialect D` | — | auto | `bird` / `frr` / `toml` forces one. |
| `--peer ADDR:PORT` | `[[peer]] remote` | (repeatable) | Outbound peer; per-peer `--peer-as` shared. |
| `--listen ADDR:PORT` | `listen_addr` | — | Accept inbound BGP connections. |
| `--network PREFIX` | `[[networks]] prefix` | (repeatable) | Locally originate prefix. |
| `--hold-time SEC` | `hold_time` | 90 | BGP hold time; 0 disables keepalives. |
| `--graceful-restart SEC` | `gr_restart_time` | 120 | RFC 4724; 0 disables. |
| `--llgr SEC` | `llgr_stale_time` | 0 | RFC 9494 long-lived GR; 0 disables. |
| `--llgr-max-stale SEC` | `llgr_max_stale_time` | — | Cap on the peer-advertised stale time. |
| `--md5-key SECRET` | `md5_key` | — | RFC 2385 TCP MD5 auth. |
| `--tcp-ao-key ID:SECRET` | `tcp_ao_keys` | (repeatable) | RFC 5925 TCP-AO. |
| `--tcp-ao-alg ALG` | `tcp_ao_algorithm` | `hmac-sha1` | `hmac-sha1` or `cmac-aes`. |
| `--tcp-ao-maclen BYTES` | `tcp_ao_maclen` | 0 (default) | MAC length; 0 = RFC 5925 default. |
| `--add-path` | `add_path` | off | Advertise RFC 7911 Add-Path. |
| `--add-path-max N` | `add_path_max_paths` | 6 | Paths per prefix kept. |
| `--mp-family NAME` | `mp_families` | — | Extra MP-BGP family (repeatable; `ipv4-unicast` / `ipv6-unicast`). |
| `--extended-next-hop` | `extended_next_hop` | off | RFC 5549 IPv4-over-IPv6 next-hops. |
| `--local-address ADDR` | `local_address` | — | Source address for next-hop-self egress. |
| `--local-address-v6 ADDR` | `local_address_v6` | — | IPv6 source for v6 NLRI / ENH egress. |
| `--gtsm [N]` | `gtsm_hops` | off | RFC 5082 TTL security; bare = 1 hop. |
| `--max-prefixes N` | `max_prefixes` | — | Per-peer maximum-prefix limit. |
| `--max-prefix-action A` | `max_prefix_action` | `warn` | `warn` / `teardown` / `restart`. |
| `--max-prefix-threshold P` | `max_prefix_threshold` | 75 | Early-warning percentage. |
| `--ebgp-policy MODE` | `ebgp_policy` | `rfc8212` | `rfc8212` (deny-in/deny-out) or `accept-all` (legacy default-accept deviation). |
| `--enforce-first-as` / `--no-enforce-first-as` | `enforce_first_as` | off | FRR `bgp enforce-first-as` parity. |
| `--bestpath-compare-routerid` / `--no-bestpath-compare-routerid` | `bestpath_compare_routerid` | on | RFC 5004 deterministic vs oldest-route tie-break. |
| `--default-ipv4-unicast` / `--no-default-ipv4-unicast` | `default_ipv4_unicast` | on | FRR `bgp default ipv4-unicast` parity. |
| `--allow-local-as [N]` / `--allowas-any` | `allow_local_as` | 0 (reject any) | FRR `allowas-in N` / `allowas-any`. |
| `--soft-reconfig-inbound` / `--no-soft-reconfig-inbound` | `soft_reconfig_inbound` | off | FRR `soft-reconfiguration inbound`. |
| `--bfd` | `bfd` | off | BFD fast-fail (RFC 5880/5881). |
| `--bfd-multihop` | `bfd_multihop` | off | RFC 5883 multihop BFD (UDP 4784). |
| `--bfd-min-tx-ms MS` | `bfd_min_tx_ms` | 100 | BFD transmit interval. |
| `--bfd-min-rx-ms MS` | `bfd_min_rx_ms` | 100 | BFD receive interval. |
| `--bfd-multiplier N` | `bfd_multiplier` | 3 | BFD detection multiplier. |
| `--install-kernel-routes` | `install_kernel` | off | Install best routes into the kernel FIB. |
| `--user NAME` | `user` | — | Drop privileges after binding sockets. |
| `--group NAME` | `group` | — | Privilege-drop group. |
| `--api-socket PATH` | `api_socket` | — | Unix-socket runtime API (see RUNBOOK.md). |
| `--metrics-addr ADDR` | `metrics_addr` | — | Prometheus `/metrics` HTTP endpoint (ROADMAP-v3 D12.2). Bind to a loopback address; basic-auth/mTLS is out of scope. |

### Multi-protocol combinations (rc.3)

`--protocol` takes a *set*: `bgp`, `ospf` and `babel` combine in one
process through the shared-router supervisor. The flag is repeatable
and each value may carry a comma-separated list
(`--protocol bgp --protocol ospf` ≡ `--protocol bgp,ospf`); the TOML
equivalents are the top-level `protocol = "bgp,ospf"` string and the
`protocols = ["bgp", "ospf"]` array. A single name keeps the classic
dedicated-daemon path unchanged.

One process then runs one engine thread per protocol against **one
`DefaultRouter`**: the engines share the Loc-RIB (routes learned by
any engine are visible to all, per the FRR admin-distance order BGP
20 < OSPF 110 < Babel 120, with withdrawal fallback between
contributions), one running flag (SIGTERM stops everything), one
ticker and one runtime API socket (`status`, `sessions`, `routes`,
`reload` cover all engines; OSPF registers its status view into the
shared registry). Cross-protocol advertisement into BGP is opt-in
only — OSPF/Babel routes never leak into BGP advertisements without a
redistribution pipe (see `lr-router`'s `RedistributionPipe`).
`bmp` and `ldp` stay standalone-only: combining them fails closed at
startup.

### Cross-protocol policy — `[[redistribute]]` and `[[aggregate]]`

Two TOML tables attach the router-level cross-protocol engines to the
daemon (ROADMAP-v3 D4.1 / D4.2). Both validate fail closed: unknown
keys, unknown protocol names, a pipe into a protocol the daemon does
not run, and duplicate declarations are start-up errors, not
warnings.

`[[redistribute]]` installs a redistribution pipe (BIRD `pipe` / FRR
`redistribute`): routes from `source` that enter the Loc-RIB are
re-originated into `target`:

```toml
[[redistribute]]
source = "ospf"                  # bgp | ospf | ospf3 | babel
target = "bgp"                   # bgp | ospf | ospf3
metric = 100                     # optional fixed metric override
tag    = 65000                   # optional OSPF external route tag
allow  = ["10.0.0.0/8"]          # optional prefix allow-list
```

Without `metric` the re-originated route inherits the source metric.
Without `allow` every source route crosses the pipe. Sources the
daemon cannot actually learn routes with (`static`, `connected`) are
rejected — the daemon has no injection surface for them yet, and a
permanently inert pipe would silently promise redistribution the
process can never perform.

`[[aggregate]]` registers a BGP route aggregate (RFC 4271 §9.2.2.2):
while at least one more-specific route exists in the Loc-RIB, the
aggregate is originated with a zeroed AS_PATH, ATOMIC_AGGREGATE and
AGGREGATOR; when the last specific disappears the aggregate is
withdrawn. This is the BIRD `aggregate` / FRR `aggregate-address`
equivalent:

```toml
[[aggregate]]
prefix = "203.0.113.0/24"
```

Both surfaces print one start-up banner line each
(`redistribute: ospf -> bgp`, `aggregate: 203.0.113.0/24`) and the
router logs every re-origination as
`daemon: redistribute: <prefix> -> BGP (metric=N)`. Aggregation has
no `summary_only` knob yet (the router does not implement specific
suppression); the daemon refuses the key rather than ignoring it.

Startup is gated: each engine binds its sockets (OSPF raw sockets, the
BGP :179 listener, the Babel UDP pair) and reports readiness; the
supervisor then drops privileges (`--user`), creates the API socket as
the reduced user and releases the engines. A startup failure in any
engine aborts the whole combination with that engine's exit code, and
an engine dying at runtime stops the remaining engines gracefully.

### Daemon flag reference (other protocols)

`--protocol PROTO` selects the protocol (`bgp` default, or a
combination like `bgp,ospf` — see above). Each protocol has its own
sub-flags:

| Protocol | Flag | TOML | Default | Notes |
| --- | --- | --- | --- | --- |
| `babel` | `--babel-group ADDR` | `babel_group` | `ff02::1:6` v6, `224.0.0.111` v4 | Babel multicast group. |
| `babel` | `--babel-port PORT` | `babel_port` | 6696 | Babel UDP port. |
| `babel` | `--babel-key SECRET` | `[[babel.key]] secret` | (repeatable) | RFC 8967 MAC key. One MAC per key per datagram, key-rotation safe. |
| `babel` | `--babel-accept-unauthenticated` | `babel_accept_unauthenticated` | off | RFC 8967 §5 incremental deployment. |
| `babel` | `--babel-no-pc-split` | `babel_no_pc_split` | off | RFC 9467 §3.1 single PC field. |
| `babel` | `--babel-pc-window N` | `babel_pc_window` | 0 | RFC 9467 §3.2 PC window verification. |
| `ospf` | `--ospf-interface NAME` | `[[ospf.interface]] name` | (repeatable) | Needs root or a user/network namespace. |
| `ospf` | `--ospf-area ID` | `[[ospf.interface]] area` | 0 | Integer or dotted quad. |
| `ospf` | `--ospf-hello-interval S` | `[[ospf.interface]] hello_interval` | 10 | OSPF hello interval. |
| `ospf` | `--ospf-dead-interval S` | `[[ospf.interface]] dead_interval` | 40 | OSPF dead interval. |
| `ldp` | `--ldp-transport ADDR` | `ldp_transport` | first interface addr | LDP transport address advertised in Hellos. |
| `ldp` | `--ldp-port PORT` | `ldp_port` | 646 | LDP UDP/TCP port. |
| `ldp` | `--ldp-keepalive SEC` | `ldp_keepalive` | 15 | Session KeepAlive Time. |
| `ldp` | `--ldp-link-hold SEC` | `ldp_link_hold` | 15 | Link Hello hold time. |
| `ldp` | `--ldp-targeted-hold SEC` | `ldp_targeted_hold` | 45 | Targeted Hello hold time. |
| `ldp` | `--ldp-interface NAME` | `[[ldp.interface]] name` | (repeatable) | LDP link-discovery interface. |
| `ldp` | `--ldp-targeted ADDR` | `[[ldp.targeted]] addr` | (repeatable) | Extended-discovery peer. |
| `ldp` | `--ldp-bind PFX[=LABEL]` | `[[ldp.binding]] prefix/label` | (repeatable) | Advertise FEC binding; LABEL auto-allocates from 16. |
| `bmp` | `--bmp-target ADDR:PORT` | `bmp_target` | (repeatable) | Mirror Peer Up/Down + Route Monitoring to a BMP station (RFC 7854). |
| `ospf` (v3) | `--ospf-version v3` | `ospf_version` | `v2` | Run OSPFv3 (RFC 5340). |
| `ospf` | `--ospf-srv6-locator PREFIX` | `[[ospf.srv6_locator]]` | — | RFC 9513 SRv6 locator (v3 only). |
| `ospf` | `--ospf-srv6-receive` | `ospf_srv6_receive` | off | Install supported-algorithm locators (RFC 9513 §5). |
| `ospf` | `--ospf-srv6-o-flag` | `ospf_srv6_o_flag` | off | Advertise the SRv6 O-flag in the RI LSA. |
| `ospf` | `--ospf-srv6-max-sl N` | `ospf_srv6_max_sl` | — | Max Segments Left MSD (Node MSD TLV). |
| `ospf` | `--ospf-srv6-max-end-pop N` | `ospf_srv6_max_end_pop` | — | Max End.Pop MSD. |
| `ospf` | `--ospf-srv6-max-h-encaps N` | `ospf_srv6_max_h_encaps` | — | Max H.Encaps MSD. |
| `ospf` | `--ospf-srv6-max-end-d N` | `ospf_srv6_max_end_d` | — | Max End.D MSD. |

### Exchange-plane feature (W6.3 prototype)

The exchange-plane prototype (`--features exchange-plane` build) is
opt-in: the wire format rides IANA experimental code points
(capability + path-attribute 251) pending an RFC 7120 early
allocation, and the plane only activates between two lr speakers
that both opt in with a shared key id. Non-lr peers (BIRD, FRR) are
unaffected (RFC 5492 §3 inert capability). The default release
build carries none of the exchange-plane code. See
[`research/EXCHANGE-PLANE.md`](research/EXCHANGE-PLANE.md).

### Common recipes

**iBGP route reflector**

```toml
[bgp]
local_as  = 65000
router_id = "10.0.0.1"

[[peer]]
remote = "10.0.0.2:179"
peer_as = 65000
route_reflector_client = true
```

**eBGP with BFD fast-fail and RFC 8212 deny-by-default**

```toml
[bgp]
local_as   = 64512
router_id  = "10.0.0.1"
ebgp_policy = "rfc8212"   # default; explicit for documentation

[[peer]]
remote = "192.0.2.2:179"
peer_as = 64513
bfd = true
bfd_min_tx_ms = 100
bfd_min_rx_ms = 100
bfd_multiplier = 3
import = "from-upstream"
export = "to-upstream"
```

**OSPFv3 with SRv6 (RFC 9513)**

```toml
[ospf]
version = "v3"
srv6_receive = true
srv6_o_flag = true
srv6_max_sl = 16

[[ospf.interface]]
name = "eth0"
area = 0

[[ospf.srv6_locator]]
prefix = "fc00:dead:beef::/48"
algorithm = 0
behavior = "end"
sid = "fc00:dead:beef::"
```

For the full set of worked examples — route reflector, confederation,
route server, BFD integration, OS integration, Babel source-specific,
OSPF ABR/NSSA — see the [`examples/`](examples/) directory.

---

## `lrctl` — the operational CLI (ROADMAP-v3 D12)

`lrctl` is the operator-facing companion to `lr-daemon`. It connects to
a running daemon over its Unix API socket (the same line-oriented
protocol `socat - UNIX-CONNECT:…` speaks) and proxies the command,
returning the daemon's reply verbatim to stdout. A small set of
subcommands (`filter compile`) run client-side and never touch the
daemon — they reuse the `lr-policy` library directly so the operator
can validate a filter body before deploying it.

### Quick start

```sh
# Start a daemon with the API socket enabled.
./target/release/lr-daemon \
    --local-as 64512 --peer-as 64513 --router-id 10.0.0.1 \
    --listen 127.0.0.1:1179 --network 203.0.113.0/24 \
    --api-socket /run/lr-daemon.api &

# Query it.
./target/release/lrctl status
./target/release/lrctl sessions
./target/release/lrctl routes show
./target/release/lrctl routes show 203.0.113.0/24

# Validate a filter body client-side (no daemon needed).
./target/release/lrctl filter compile 'if net ~ 10.0.0.0/8 then accept; reject;'

# Reload or shut the daemon down.
./target/release/lrctl reload
./target/release/lrctl shutdown
```

The default socket path is `/run/lr-daemon.api` (matches
`templates/daemon.toml`); override with `--socket PATH` on any
subcommand. On non-Unix targets `lrctl` refuses with a clear error —
the runtime API requires Unix domain sockets.

### Daemon commands (proxy the runtime API)

| Command                         | Daemon API  | Effect                                                |
| ------------------------------- | ----------- | ----------------------------------------------------- |
| `lrctl status`                  | `status`    | Daemon summary (version, identity, uptime, counters)  |
| `lrctl sessions [list]`         | `sessions`  | One line per configured session                       |
| `lrctl routes show [prefix]`    | `routes`    | Loc-RIB dump, optionally filtered to one prefix        |
| `lrctl routes dump <path>`      | `mrt PATH`  | Write the Loc-RIB as an MRT dump (RFC 6396)           |
| `lrctl reload`                  | `reload`    | Re-apply configuration (SIGHUP equivalent)           |
| `lrctl shutdown`                | `shutdown`  | Graceful shutdown                                      |

`routes show <prefix>` is the operator-facing verb for the FRR
`show ip route <prefix>` lineage; the daemon API has no
parameterised `routes <prefix>` command today, so `lrctl` does the
filtering client-side (exact match on the leading token so
`203.0.113.0/24` does not also match `203.0.113.0/25`). A non-zero
exit code signals a transport failure or a daemon `error:` reply; a
missing prefix on `routes show <prefix>` is exit 0 with an empty
stdout and a `no route for …` note on stderr (FRR parity).

### Client-side commands (no daemon required)

| Command                         | Effect                                                |
| ------------------------------- | ----------------------------------------------------- |
| `lrctl filter compile <body>`   | Validate a filter DSL body via `lr-policy::filter::compile` |

`filter compile` runs the same parser path the daemon runs at startup,
so an `ok` here means the body will compile when the daemon reloads.
The body is a single shell-quoted argument; multiple args after
`compile` are joined with spaces so `lrctl filter compile if net ~
10/8 then accept; reject;` works without extra quoting. On success the
exit code is 0 and the body is `ok (<n> statement(s)…)`; on a parse
error the exit code is 1 and the stderr carries the 1-indexed
line/column diagnostic.

### Other commands

| Command        | Effect                              |
| -------------- | ----------------------------------- |
| `lrctl version` | Print `lrctl <version>`             |
| `lrctl help`    | Show the usage banner               |

### Exit codes

| Code | Meaning                                                        |
| ---- | -------------------------------------------------------------- |
| 0    | Success (or a `routes show <prefix>` with no match)            |
| 1    | Transport failure, daemon `error:` reply, or filter parse error |
| 2    | `lrctl` argument error (unknown subcommand, missing arg)       |
