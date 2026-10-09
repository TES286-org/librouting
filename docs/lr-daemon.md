# Running the `lr-daemon` reference daemon

`lr-daemon` is the reference daemon built from `crates/lr-cli`. It runs
real BGP, OSPFv2/v3, Babel, LDP and BMP engines over the `lr-router`
pipeline. This page is the narrative guide: getting one peer up,
scaling to many, importing a BIRD or FRR file, combining protocols,
redistributing and aggregating, lifecycle, privilege drop, and the
runtime API socket.

Every flag and every configuration key, with defaults, is in
[lr-daemon-reference.md](lr-daemon-reference.md). Day-2 operations —
the API reply strings, the metrics endpoint, containers — are in
[RUNBOOK.md](RUNBOOK.md). The inspection and operational CLIs are in
[lr-cli.md](lr-cli.md).

`lr-daemon` hand-parses its own `argv` in
`daemon_config::parse_args`, so a stripped container needs no argument
library. It is not a production NOS: BIRD, FRR and OpenBGPD are. Every
library feature reaches the daemon's surface so it can be exercised
end to end.

## Quick start — one BGP peer

```sh
cargo build --release -p lr-cli

# Local AS 64512 (router-id 10.0.0.1) peers with AS 64513 at
# 192.0.2.2:179, originates 203.0.113.0/24, and installs the best
# routes into the kernel FIB.
./target/release/lr-daemon \
    --local-as 64512 --peer-as 64513 --router-id 10.0.0.1 \
    --peer 192.0.2.2:179 --local-address 192.0.2.1 \
    --network 203.0.113.0/24 \
    --install-kernel-routes
```

`--local-as` and `--router-id` are required; without them the daemon
prints `error: --local-as is required` or `error: --router-id is
required`, prints the usage banner and exits 2.

The same shape as a native `.lr` file:

```lr
bgp {
    local_as       64512;
    peer_as        64513;
    router_id      10.0.0.1;
    peer_addr      192.0.2.2:179;
    local_address  192.0.2.1;
    hold_time      90s;
    install_kernel true;
    networks       [203.0.113.0/24];
}
```

```sh
./target/release/lr-daemon --config daemon.lr
```

[`templates/daemon.lr`](../templates/daemon.lr) is the fully commented
reference config; `templates/daemon.toml` is its deprecated TOML twin.
The `.lr` grammar is specified in
[config_dsl_grammar.md](config_dsl_grammar.md). There is no
`--config-dump`: `lr-daemon config check <file>` prints a summary of
what a config resolves to without starting the daemon, and
`lr-daemon config to-dsl <file>` prints the equivalent `.lr` program.

The default eBGP posture is RFC 8212: an external peer with no import or
export policy exchanges nothing, and the daemon says so at startup:

```text
daemon: peer upstream: warning: no import route-map or filter; discarding received routes (RFC 8212)
daemon: peer upstream: warning: no export route-map or filter; announcing nothing (RFC 8212)
```

Attach `import` / `export` route-maps, `import_filter` /
`export_filter`, or run the explicit deviation `--ebgp-policy
accept-all`.

## Multi-peer configuration

Command-line peers are uniform: `--peer ADDR:PORT` is repeatable and
every other per-peer knob comes from `--peer-as` / the `[bgp]` globals.
Per-peer settings need a config file. One `peer` block per remote; every
key inherits the `bgp` block when omitted.

```lr
bgp {
    local_as  64512;
    router_id 10.0.0.1;
}

peer "upstream" {
    remote 192.0.2.2:179;        # outbound: dial this peer
    peer_as 64513;
    import "from-upstream";
    export "to-upstream";
}

peer "customer" {
    address 192.0.2.3;           # listen-only, expected source IP
    peer_as 64514;
    bfd true;
}
```

Things worth knowing before you write one:

- An **inbound** peer (`address`, or an inbound connection matched to an
  outbound peer) needs `--listen ADDR:PORT`; without it startup fails
  with `daemon: peer <name>: inbound peers require --listen` and exit 2.
- A peer with neither `remote` nor `address` is an error:
  `daemon: peer <name>: 'remote' or 'address' is required`.
- `peer_as` of 0 inherits the global. If neither is set:
  `daemon: peer <name>: no peer AS configured (set peer_as or the
  global --peer-as)`.
- For an eBGP outbound peer with no source address the daemon warns that
  egress will keep the received NEXT_HOP, which peers usually reject.
- A peer template (`[peer-template.<name>]` in TOML, `peer-template
  "<name>" { … }` in the DSL) holds reusable defaults; a peer extends
  one with `extends = "<name>"` / `extends <name>;`. Templates chain,
  per-peer keys win, and an unknown name or a cycle is a startup error.

A peer that can end up with two parallel transports to the same
neighbour — its own dial plus an inbound connection — gets two sessions
sharing one collision group. The router resolves the collision per RFC
4271 §6.8: the speaker with the higher BGP Identifier keeps its
connection and the loser receives a Cease / Connection Collision
Resolution NOTIFICATION. The daemon announces this at startup:

```text
daemon: peer upstream: bidirectional (remote + listener); collision resolution per RFC 4271 §6.8 on sessions #1 / #2
```

Any outbound peer counts as bidirectional while a listener is up, not
only a peer that also sets `address`.

## Running BIRD or FRR configuration files

The dialect is recognised from the file's content, so these run
directly:

```sh
./target/release/lr-daemon --config /etc/bird/bird.conf
./target/release/lr-daemon --config /etc/frr/frr.conf

# Force one when auto-detection is ambiguous.
./target/release/lr-daemon --config bird.conf --config-dialect bird
```

`--config-dialect` accepts `bird`, `frr`, `toml` and `lr`. The resolved
dialect is remembered and reused on `SIGHUP` and on the API `reload`
command, so a compat-mode daemon does not break on reload. Unmapped
constructs and non-BGP stanzas become startup warnings, in the
`config warning: …` voice; see [COMPAT.md](COMPAT.md) for the mapping
surface, the `lr:` comment directives and the documented deviations.

`lr-daemon translate bird|frr FILE` performs a best-effort conversion of
such a file into an lr daemon config instead of loading it. Anything it
cannot map stays behind as an explicit `# UNMAPPED:` comment rather than
being dropped silently.

## Running several protocols in one process

`--protocol PROTO` selects the protocol set. It is repeatable and each
value may carry a comma-separated list, so `--protocol bgp --protocol
ospf` and `--protocol bgp,ospf` are the same request. The accepted names
are `bgp` (the default), `ospf`, `babel`, `bmp` and `ldp`. The config
equivalents are the top-level `protocol = "bgp,ospf"` string and the
`protocols = ["bgp", "ospf"]` array.

- A single name takes the classic dedicated-daemon path.
- `bgp`, `ospf` and `babel` combine in one process. The others do not:
  a combination containing `bmp` or `ldp` fails closed with
  `error: --protocol <name> cannot run in a combination (only bgp,
  ospf and babel combine)`, exit 2.
- One process runs one engine thread per protocol against **one**
  `DefaultRouter`, so they share the Loc-RIB. A route learned by any
  engine is visible to all, ordered by administrative distance — BGP
  20, OSPF 110, Babel 120 — with withdrawal falling back to the next
  contribution.
- There is one running flag, one ticker and one runtime API socket. The
  API's `status`, `sessions` and `routes` cover every engine.
- Cross-protocol advertisement into BGP is opt-in only. OSPF and Babel
  routes never leak into BGP advertisements without a redistribution
  pipe.
- OSPFv2 and OSPFv3 are separate protocols with separate LSDBs; one
  process runs one of them, chosen by `[ospf] version`.

Startup is gated. Each engine binds its sockets — OSPF raw sockets, the
BGP listener, the Babel UDP pair — and reports readiness. The supervisor
then drops privileges, creates the API socket as the reduced user,
starts the metrics endpoint, and only then releases the engines. If any
engine fails to start, the whole combination aborts with that engine's
exit code and the daemon prints `daemon: multi-protocol startup
aborted`. An engine dying at runtime stops the others gracefully.

The banner names the set:

```text
librouting daemon (lr-daemon)
  protocols:   bgp,ospf (one shared Loc-RIB)
  router-id:   10.0.0.1
  install:     false
  platform:    linux
```

## Redistribution and aggregation

Two cross-protocol tables attach the router-level engines. Both validate
fail closed at startup.

A `redistribute` block installs a redistribution pipe — the BIRD `pipe`
/ FRR `redistribute` equivalent. Routes from `source` that enter the
Loc-RIB are re-originated into `target`:

```lr
redistribute {
    source "ospf";                       # bgp | ospf | ospf3 | babel
    target "bgp";                        # bgp | ospf | ospf3
    metric 100;                          # fixed metric override
    tag    65000;                        # OSPF external route tag
    allow  ["10.0.0.0/8"];               # prefix allow-list
}
```

Without `metric` the re-originated route keeps the source metric.
Without `allow` every source route crosses the pipe. `static` and
`connected` are rejected as sources: the daemon has no injection surface
for them yet, and an inert pipe would promise redistribution the process
can never perform. A pipe whose source or target engine is not in the
protocol set is a startup error naming the missing engine.

An `aggregate` block registers a BGP route aggregate (RFC 4271
§9.2.2.2). While at least one more-specific route is in the Loc-RIB the
aggregate is originated with a zeroed AS_PATH, ATOMIC_AGGREGATE and
AGGREGATOR; when the last specific disappears it is withdrawn. This is
the BIRD `aggregate` / FRR `aggregate-address` equivalent:

```lr
aggregate {
    prefix "203.0.113.0/24";
}
```

Aggregation has no specific-suppression knob. The `[[aggregate]]` schema
accepts only `prefix`, so any other key is a hard error rather than a
silently ignored one. Both surfaces print one startup line each:

```text
  redistribute: ospf -> bgp metric=100
  aggregate:    203.0.113.0/24 (rfc4271 §9.2.2.2)
```

Static routes (`[[static.route]]`, or `static { route "…" { … } }` in
the DSL) are installed into the Loc-RIB at startup with admin distance
1, winning over every dynamic protocol except connected, and print
`  static:      <prefix> via <next-hop> metric=<n>` — without the `via`
part for a blackhole.

## Lifecycle and signals

| Event (Unix) | Windows equivalent | Effect |
| --- | --- | --- |
| `SIGTERM`, `SIGINT` | Ctrl-C / console close, logoff, shutdown | Graceful stop; exit 0 |
| `SIGHUP` | none | Reload the config file |

A graceful stop closes every session with a Cease NOTIFICATION (RFC 4271
§6.4), gives live session threads a bounded window to flush it, prints
`daemon: shutdown complete` and returns 0. On Unix the daemon logs the
signal number: `daemon: signal 15 received — shutting down`.

`SIGHUP` prints `daemon: SIGHUP received — reloading configuration` and
then each reload line with a `daemon: ` prefix. A parse or validation
error keeps the running configuration and reports it:
`reload: <error> (keeping current config)`. Reload never crashes and
never half-applies.

What reload actually re-applies:

| Config | Reload behaviour |
| --- | --- |
| `networks` | Added prefixes are originated, removed ones unoriginated |
| `[[static.route]]` | Added and changed routes installed, removed ones withdrawn |
| `[[roa]]` | The static ROA layer is replaced wholesale |
| `[bgp.rpki]` | Cache address change re-points the RTR client; same address re-syncs |
| everything else | Reported as needing a restart |

If nothing changed, reload prints `reload: no network changes`. It
always ends with `reload: note: AS, router-id, peer and auth changes
require a restart`. Damping is installed for the process lifetime and
cannot be unset by a reload.

Windows has no `SIGHUP`. Use the runtime API `reload` command, or
`lrctl reload`, which sends the same thing.

## Dropping privileges

`--user NAME` and `--group NAME` (names or numeric ids) drop privileges
after the privileged work is done: bind the listener, arm TCP-MD5,
TCP-AO and GTSM, bind OSPF raw sockets. The daemon then clears
supplementary groups, calls `setgid` and calls `setuid`, and logs
`daemon: privileges dropped (uid=… gid=…)`. A failed drop is fatal — the
process never keeps running as root by accident. This is why port 179
can be held and then released.

`--user` with `--install-kernel-routes` warns at startup that kernel
installs may be denied after the drop. Either grant the reduced user the
route capability or drop `--install-kernel-routes`.

The API socket and the metrics listener are created after the drop, so
their files belong to the reduced user.

## The runtime API socket

`--api-socket PATH` starts a line-oriented management server. On Unix
that is a stream socket at `PATH`; the daemon logs `daemon: runtime API
on <path>` and the file is chmod 0600, so access is limited to the
owning user and to whoever can reach the directory. On Windows `PATH` is
the full pipe name (`\\.\pipe\<name>`) and the pipe's security
descriptor scopes access instead. Creation failure is fatal either way:
an operator who asked for a management socket must not get a daemon
running silently without one.

Connect with `socat - UNIX-CONNECT:/run/lr-daemon.api` or use
[`lrctl`](lr-cli.md), and send one command per line. On Unix the socket
file is unlinked before binding, so a stale file from an unclean
shutdown never blocks startup, and it is unlinked again on `shutdown`
and on thread exit. `lrctl` itself is Unix-only: its transport refuses
on Windows with `runtime API requires Unix domain sockets (not supported
here)`, so a Windows daemon is driven directly over the pipe.

The command surface is small: `status`, `sessions`, `routes`,
`mrt PATH`, `reload`, `shutdown`, `help` and `quit`. The `show …` family
mirrors the BIRD console: `show status` (extended summary with per-protocol
session counts and memory), `show sessions [detail]` (per-session stats —
transitions, uptime, last error), `show session <handle>` (deep dive for
one session), `show routes count` (Loc-RIB grouped by protocol) and
`show memory` (process RSS and virtual size). [RUNBOOK.md](RUNBOOK.md)
documents each command's exact reply string.

`--metrics-addr ADDR` starts the Prometheus endpoint, which has its own
exposure story; see [RUNBOOK.md](RUNBOOK.md#prometheus-metrics-endpoint).

## Where to go next

| Goal | Start here |
| --- | --- |
| Every flag and config key | [lr-daemon-reference.md](lr-daemon-reference.md) |
| The API, metrics, containers, failures | [RUNBOOK.md](RUNBOOK.md) |
| BIRD / FRR config mapping | [COMPAT.md](COMPAT.md) |
| `.lr` and filter syntax | [config_dsl_grammar.md](config_dsl_grammar.md) |
| Worked configurations | [examples/](examples/) |
| Verifying against BIRD and FRR | [INTEROP.md](INTEROP.md) |
| Module layout | [lr-cli-internals.md](lr-cli-internals.md) |
| The exchange-plane prototype | [research/EXCHANGE-PLANE.md](research/EXCHANGE-PLANE.md) |
