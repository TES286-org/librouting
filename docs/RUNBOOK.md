# Operations runbook

Day-2 operations for `lr-daemon`: lifecycle, the runtime API and its
exact replies, the Prometheus endpoint, containers, and the failures
operators actually hit. Read it when a session will not come up, when a
script needs to branch on a daemon reply, or when a route is in the RIB
but not in the kernel.

| Task | Authoritative source |
| --- | --- |
| Every flag and config key | [lr-daemon-reference.md](lr-daemon-reference.md) |
| Getting a daemon running | [lr-daemon.md](lr-daemon.md) |
| BIRD / FRR config mapping | [COMPAT.md](COMPAT.md) |
| Interop lab | [INTEROP.md](INTEROP.md) |
| Embedding the library | [tutorial.md](tutorial.md), [ARCHITECTURE.md](ARCHITECTURE.md) |

## Lifecycle

```sh
cargo build --release -p lr-cli
./target/release/lr-daemon --protocol bgp --config /etc/lr/daemon.lr

# Migrating from BIRD 2 or FRR: the daemon reads those files too.
./target/release/lr-daemon --config /etc/bird/bird.conf
./target/release/lr-daemon --config /etc/frr/frr.conf
```

There is no `-c`; the flag is `--config PATH`.

The dialect is recognised from the content, and a compat-loaded config
keeps its dialect across reloads. Unmapped constructs and non-BGP
stanzas become `config warning: …` lines at startup; [COMPAT.md](COMPAT.md)
has the surface and the `lr:` comment directives. A TOML config adds
`config deprecation: …` on every load and every reload.

| Signal (Unix) / event (Windows) | Effect |
| --- | --- |
| `SIGTERM`, `SIGINT` | Graceful: Cease NOTIFICATION per session, RIB torn down, exit 0 |
| `SIGHUP` | Reload: `networks`, static routes, `[[roa]]`, `[bgp.rpki]` |
| Ctrl-C, console close/logoff/shutdown (Windows) | Graceful shutdown |

The daemon logs `daemon: signal 15 received — shutting down` (the number
is the signal), gives session threads a bounded window to flush their
close NOTIFICATIONs, and ends with `daemon: shutdown complete`.

`SIGHUP` prints `daemon: SIGHUP received — reloading configuration`
followed by every reload line prefixed with `daemon: `. Reload re-applies
more than the network list:

```text
reload: originating 203.0.113.0/24
reload: unoriginating 198.51.100.0/24
reload: static 10.0.0.0/8 installed
reload: roa table: 2 -> 3 static entries
reload: rpki re-sync requested from rpki.example.net:8282
reload: config warning: line 12: unknown key 'bgp.typo' (ignored)
reload: no network changes
reload: note: AS, router-id, peer and auth changes require a restart
```

The last two lines: `reload: no network changes` appears only when
nothing else changed, and the note is always printed. A parse or
validation failure keeps the running configuration and reports
`reload: <error> (keeping current config)`. Damping, once installed,
stays installed for the process lifetime.

`--user` / `--group` drop privileges after the listening sockets are
bound and the auth is armed. A failed drop is fatal. `--api-socket PATH`
creation failure is fatal too: an operator who asked for a management
socket must not get a daemon running silently without one.

## The runtime API

`--api-socket PATH` serves a line-oriented protocol. On Unix that is a
stream socket at `PATH`, chmod 0600 — connect with
`socat - UNIX-CONNECT:/run/lr-daemon.api` or `nc -U`, send one command
per line, and read the reply. On Windows `PATH` is the full pipe name
(`\\.\pipe\<name>`) and the same protocol runs over it; `lrctl` is
Unix-only and does not connect there. On Unix the socket file is
unlinked before binding and again on `shutdown`, so a stale file from an
unclean stop never blocks startup.

The default socket path used by `lrctl` is `/run/lr-daemon.api`. The
daemon announces its own path at startup:

```text
daemon: runtime API on /run/lr-daemon.api
```

### Commands and replies

| Command | Reply |
| --- | --- |
| `status` | Key/value lines (below) |
| `sessions` | One line per session |
| `routes` | One line per Loc-RIB path |
| `mrt PATH` | `mrt-dump <path> records=<n>` |
| `show status` | Extended summary (per-protocol session counts, memory) |
| `show sessions [detail]` | Per-session stats (transitions, uptime, last error) |
| `show session <handle>` | Deep dive for one session |
| `show routes count` | Loc-RIB grouped by protocol |
| `show memory` | Process RSS and virtual size |
| `show roa` | ROA table dump (BIRD `show roa` parity) |
| `reload` | The reload lines above |
| `shutdown` | `shutting down` |
| `help` | The command list |
| `quit` | Closes the connection, no reply |

A real transcript:

```text
> status
version <version>
local-as 64512
peer-as 64513
router-id 10.0.0.1
config /etc/lr/daemon.lr
uptime-secs 42
sessions 1
rib-entries 1
> sessions
#1 kind=bgp local-as=64512 peer-as=64513 state=Established established=true peer-id=10.0.0.2 hold-time=90 adj-rib-in=1 updates-rx=2 updates-tx=2
> routes
203.0.113.0/24 via 192.0.2.1 proto=Bgp metric=0 path-id=0
> mrt /tmp/rib.mrt
mrt-dump /tmp/rib.mrt records=1
> reload
reload: no network changes
reload: note: AS, router-id, peer and auth changes require a restart
> shutdown
shutting down
```

`status` always prints `version`, `local-as`, `peer-as`, `router-id`,
`config` (`(none)` when no file was loaded), `uptime-secs`, `sessions`
and `rib-entries`, then any protocol-specific lines the running engines
registered.

`sessions` uses one fixed shape per session:
`#<handle> kind=<kind> local-as=<as> peer-as=<as> state=<state>
established=<bool> peer-id=<id> hold-time=<n> adj-rib-in=<n>
updates-rx=<n> updates-tx=<n>`. A session without a peer identifier
prints `peer-id=-`. With the `exchange-plane` feature enabled, a session
carrying records gets one extra indented line.

`routes` prints `<prefix> via <next-hop> proto=<Protocol> metric=<n>
path-id=<n>`, using `(none)` when the route has no next hop. A labelled
route — RFC 8277 BGP-LU, RFC 8665 OSPF prefix-SID — appends
`label=<top>`: the MPLS label the kernel mirror installs. `path-id` is
the RFC 7911 Add-Path identifier and is 0 without Add-Path.

`mrt PATH` writes the current Loc-RIB as an RFC 6396 `TABLE_DUMP_V2`
file and answers `mrt-dump <path> records=<n>`; a write failure answers
`mrt-dump failed: <error>`. `mrt` with no path answers
`usage: mrt <path>`.

The `show …` family is the BIRD-style operational surface (issue #52):
`show status` extends the legacy `status` reply with per-protocol
session breakdown (`kind=<proto> total=<n> established=<n>`) and a
`memory rss-bytes=… vsize-bytes=…` line; `show sessions [detail]`
extends each session line with `transitions=`, `uptime-ms=`,
`last-error=` and `last-error-at-ms=` (the optional `detail` keyword
appends a multi-line block per session, mirroring BIRD `show protocols
all`); `show session <handle>` is the single-session deep dive;
`show routes count` groups the Loc-RIB by `Route::protocol` (BIRD
`show route count` / FRR `show ip route summary` parity); `show memory`
prints `uptime-secs`, `rss-bytes` and `vsize-bytes`. `lrctl` proxies
each sub-command verbatim — `lrctl show` (no sub) maps to `show status`,
matching BIRD's shortcut.

An unknown command answers
`error: unknown command '<x>' (try 'help')`, and a command line longer
than 4096 bytes answers `error: command too long`. A connection that
sends nothing is closed after roughly ten seconds of idleness.

### Clients

[`lrctl`](lr-cli.md) is the supported client. It proxies the same
commands — `lrctl status`, `lrctl sessions`, `lrctl routes show
[prefix]`, `lrctl routes dump <path>`, `lrctl show status`, `lrctl show
sessions [detail]`, `lrctl show session <handle>`, `lrctl show routes
count`, `lrctl show memory`, `lrctl roa list`, `lrctl roa count`,
`lrctl reload`, `lrctl shutdown` — and adds the client-side
`lrctl filter compile <body>`, which needs no daemon. `lrctl` exits 1
when the reply carries an `error:` line, so a script can branch on the
daemon's own verdict.

`lrctl roa list` dumps the merged ROA table (the static `[[roa]]` layer
plus the live RTR cache, deduplicated) with one line per entry:

```text
roa-total 2 static 2 rtr 0
198.51.100.0/24 max-length 26 as 64513 source static
203.0.113.0/24 max-length 24 as 64512 source static
```

The summary line (`roa-total N static S rtr R`) is always present, even
when the daemon has no ROA store (OSPF/Babel/BMP report
`roa-total 0 static 0 rtr 0`). `lrctl roa count` prints just the
summary line — convenient for scripted polling.

### Who can connect

On Unix the socket file is created mode 0600 (`chmod_0600` in
`crates/lr-cli/src/api.rs`), so only its owner can connect. On Windows
the named pipe carries a security descriptor instead. Either way there
is no authentication beyond that and no per-command authorization:
anyone who can open the channel can read the Loc-RIB, write an MRT dump
anywhere the daemon user can write, trigger a reload and stop the
daemon. When `--user` is set, the daemon drops privileges *before*
creating the socket, so the file is owned by the reduced user. Protect
the containing directory accordingly — a world-writable `/run`
subdirectory would let anyone replace the socket before the daemon binds
it.

## Prometheus `/metrics` endpoint

`--metrics-addr ADDR` (or a top-level `metrics_addr`) starts an opt-in
HTTP endpoint serving the Prometheus text exposition format. It is a
hand-rolled HTTP/1.0 responder with no `hyper` or `tokio` dependency.
Bind it to a loopback address: there is no basic-auth and no mTLS, so
scrape security is a reverse proxy's job. Creation failure is fatal.

```sh
./target/release/lr-daemon \
    --local-as 64512 --peer-as 64513 --router-id 10.0.0.1 \
    --listen 127.0.0.1:1179 --network 203.0.113.0/24 \
    --metrics-addr 127.0.0.1:9119
```

```sh
$ curl -s http://127.0.0.1:9119/metrics
# HELP lr_info librouting daemon identity (always 1).
# TYPE lr_info gauge
lr_info{version="<version>",local_as="64512",router_id="10.0.0.1"} 1
# HELP lr_uptime_seconds Daemon uptime in seconds.
# TYPE lr_uptime_seconds gauge
lr_uptime_seconds 42
# HELP lr_sessions_total Number of configured sessions, by protocol kind and state.
# TYPE lr_sessions_total gauge
lr_sessions_total{kind="bgp",state="Idle"} 1
# HELP lr_established_sessions Number of sessions in the established / Full / Up state, by protocol kind.
# TYPE lr_established_sessions gauge
lr_established_sessions{kind="bgp"} 0
# HELP lr_adj_rib_in_entries Total routes held in Adj-RIB-In across all sessions of each protocol kind.
# TYPE lr_adj_rib_in_entries gauge
lr_adj_rib_in_entries{kind="bgp"} 0
# HELP lr_bgp_updates_total BGP UPDATE messages exchanged per session, by direction. Monotonic across session re-establishment.
# TYPE lr_bgp_updates_total counter
lr_bgp_updates_total{session="1",peer="192.0.2.2",direction="received"} 7
lr_bgp_updates_total{session="1",peer="192.0.2.2",direction="sent"} 5
# HELP lr_rib_entries Number of routes in the Loc-RIB (best-path selection output).
# TYPE lr_rib_entries gauge
lr_rib_entries 1
# HELP lr_roa_entries Number of ROA entries in the live ROA store (static + RTR cache).
# TYPE lr_roa_entries gauge
lr_roa_entries 0
# HELP lr_filter_eval_duration_seconds Filter DSL evaluation latency, by direction and filter name.
# TYPE lr_filter_eval_duration_seconds histogram
lr_filter_eval_duration_seconds_bucket{direction="import",filter="in",le="0.000000100"} 2
…
lr_filter_eval_duration_seconds_sum{direction="import",filter="in"} 0.000003540
lr_filter_eval_duration_seconds_count{direction="import",filter="in"} 7
```

| Metric | Type | Labels |
| --- | --- | --- |
| `lr_info` | gauge, always 1 | `version`, `local_as`, `router_id` |
| `lr_uptime_seconds` | gauge | — |
| `lr_sessions_total` | gauge | `kind`, `state` |
| `lr_established_sessions` | gauge | `kind` |
| `lr_adj_rib_in_entries` | gauge | `kind` |
| `lr_bgp_updates_total` | counter | `session`, `peer`, `direction` |
| `lr_rib_entries` | gauge | — |
| `lr_roa_entries` | gauge | — |
| `lr_filter_eval_duration_seconds` | histogram | `direction`, `filter` |

Three blocks are conditional, and a missing series is deliberate:

- `lr_roa_entries` is omitted when the daemon has no ROA store — an
  OSPF-only or Babel-only daemon, or a BGP daemon without
  `roa_validate` and without `[[roa]]` tables.
- `lr_filter_eval_duration_seconds` is omitted when no filter hooks were
  registered, which is also what happens without `--metrics-addr`.
- `lr_bgp_updates_total` is emitted only when at least one BGP session
  exists. Its `peer` label is the configured peer name, remote or
  address, with an `(inbound)` suffix on the RFC 4271 §6.8 challenger
  session; the `session` label keeps the series unique.

`lr_established_sessions` does emit an explicit `0` for every kind that
has sessions but none established, so an alert joining on `kind` does
not see a missing series.

The histogram counts filter DSL evaluation latency as nanoseconds across
fixed buckets from 100 ns to 10 ms plus `+Inf`, recorded per (direction,
filter) only while the endpoint is configured. The internal
`__roa_validate` filter registers like any user filter.

Everything except `/metrics` is minimal: `GET /` and `GET /metrics/`
return a two-line pointer to `/metrics`, and every other request gets
`404 Not Found`.

## Container deployment

A multi-stage `Dockerfile` at the repo root builds `lr-daemon`, `lr`,
`lrctl` and `liblr_ffi.so` into a `debian:bookworm-slim` runtime image
running as a non-root `lr` user. [docker/README.md](../docker/README.md)
is the deployment guide: image layout, exposed ports, volumes, the size
target, and what the image deliberately omits. Two things it will tell
you that bite in `docker run` lines:

- The image `ENTRYPOINT` is `lr-daemon`, so a sidecar needs
  `--entrypoint lrctl` before the command.
- The daemon's socket lives in a volume so a sidecar can reach it:
  `/run/lr-daemon/api.sock`.

```sh
docker build -t librouting:latest .

# Quick start — single-peer BGP on loopback.
docker run --rm --network host \
    librouting:latest \
    --local-as 64512 --peer-as 64513 --router-id 10.0.0.1 \
    --listen 127.0.0.1:1179 --network 203.0.113.0/24 \
    --api-socket /run/lr-daemon/api.sock \
    --metrics-addr 127.0.0.1:9119

# Production — config file mount (native .lr DSL; TOML works the same).
docker run --rm -d \
    --name lr-daemon \
    -p 179:179 -p 9119:9119 \
    -v /etc/lr-daemon/daemon.lr:/etc/lr-daemon/daemon.lr:ro \
    -v lr-daemon-run:/run/lr-daemon \
    librouting:latest \
    --config /etc/lr-daemon/daemon.lr

# Sidecar lrctl — same image, entrypoint overridden.
docker run --rm --volumes-from lr-daemon \
    --entrypoint lrctl \
    librouting:latest \
    --socket /run/lr-daemon/api.sock status
```

## Troubleshooting

**A session establishes but no routes flow in either direction.**
The default eBGP posture is RFC 8212: an external peer with no explicit
import or export policy exchanges nothing. The daemon warns per peer at
startup with `daemon: peer <name>: warning: no import route-map or
filter; discarding received routes (RFC 8212)` and the matching
`announcing nothing` line. Attach route-maps or DSL filters, or run the
explicit `--ebgp-policy accept-all` deviation. iBGP and
confederation-internal sessions are exempt.

**`config warning: line N: unknown key '…' (ignored)` at startup.**
Only the root and `[bgp]` schemas, plus `[[peer]]`, tolerate unknown
keys — and they surface each one as a line-numbered warning so a newer
config does not brick an older daemon. Inside `[ospf]`, `[ldp]`,
`[babel]`, `[damping]`, `[bgp.rpki]` and every policy table an unknown
key is a hard error and the daemon exits 2. See
[lr-daemon-reference.md](lr-daemon-reference.md#unknown-keys-warnings-versus-errors).
If the warning names a key you meant to use, it is misspelled.

**`config deprecation: the TOML configuration dialect is deprecated …`.**
The config loaded fine; the TOML spelling is inside its deprecation
window. Migrate with
`lr-daemon config to-dsl daemon.toml > daemon.lr` and switch `--config`
to the `.lr` file. `config to-dsl` refuses a config that produced parse
warnings, because the emitted file would mean less than the input —
fix the warnings first.

**A session is stuck in Connect or Active.**
For outbound peers the daemon retries with backoff. Check the peer
address and port first, then GTSM (`--gtsm` needs the peer to send TTL
255; one extra hop silently kills it), then auth: an MD5 or TCP-AO
mismatch logs `daemon: session auth arming failed: …` before the TCP
handshake completes. The daemon also diagnoses a configured
`local_address` that is not on the kernel's chosen egress interface —
the Windows Strong Host Model symptom, where the session bounces with
Cease / Connection Collision Resolution forever.

**A BGP session flaps between Established and Idle.**
Almost always a hold-timer mismatch or an auth failure. The daemon logs
every session state transition as `daemon: session #<n> → <state>`
(`RouterEvent::PeerStateChange`, printed in `crates/lr-cli/src/daemon.rs`),
and every router-level message passes through as `daemon: <message>`. A
peer that keeps sending NOTIFICATIONs shows
`daemon: peer sent NOTIFICATION code=<c> sub=<s> — closing session`
(emitted by `crates/lr-bgp/src/fsm.rs`); compare the subcode against
RFC 4486. An auth failure instead shows
`daemon: session auth arming failed: <error>` before any session
exists. Check the peer's KEEPALIVE cadence against the negotiated hold
time, and remember that `--gtsm` needs TTL 255 from the peer.

**`Protocol not available` when arming TCP-AO.**
The kernel lacks TCP-AO support. There is no workaround on an old
kernel; use MD5 (RFC 2385) or plain TCP with BFD. Inbound connections
with a mismatched auth configuration are rejected fail-closed.

**OSPF or Babel fails to bind raw or multicast sockets.**
OSPF needs raw `IPPROTO_OSPF` sockets (`CAP_NET_RAW`). In CI and in
containers the pattern is a rootless network namespace: `unshare -Urn`
grants the capability inside the new namespace without host root. A
failed multicast join logs `daemon: ldp multicast join <group> on
<iface>: … (link discovery may not receive Hellos on this interface)`.

**LDP interop scripts print `SKIP: phase 3 (dataplane)`.**
Kernel MPLS is not loaded. `modprobe mpls_router mpls_iptunnel` as host
root, then let the scripts set the per-namespace `platform_labels` and
the per-interface `input` switches.

**Routes are learned but absent from the kernel FIB.**
Kernel installation is opt-in: `--install-kernel-routes` or
`install_kernel = true`. For BGP-LU routes and OSPF prefix-SIDs the
mirror needs the `AF_MPLS` stack; without it only the plain IP routes
install. Linux and BSD need root or the route capability, Windows needs
an elevated console. Grep the log for `mirror: route installed` or
`mirror: route install failed`, then verify independently with
`lr routes list`. `--user` together with `--install-kernel-routes` warns
`daemon: warning: --user with --install-kernel-routes: kernel installs
may be denied after the privilege drop` — that warning is usually the
answer.

**Reload ignored a peer edit.**
Reload re-applies `networks`, `[[static.route]]`, `[[roa]]` and
`[bgp.rpki]`. AS, router-id, peer and auth changes are restart-only by
design, and the reload output ends with
`reload: note: AS, router-id, peer and auth changes require a restart`.
Adding or removing a peer block also needs a restart.

**`daemon: peer <name>: bidirectional (remote + listener); collision
resolution per RFC 4271 §6.8 on sessions #1 / #2`.**
This is normal, not an error: the listener matched an inbound connection
to a peer the daemon also dials, so the router runs two sessions in one
collision group and lets the higher BGP Identifier win. It appears once
per startup. If the peer keeps flapping instead of converging, check the
underlying TCP reachability — a session that keeps losing the collision
has a transport that keeps coming back.

**Route flap damping is suppressing legitimate routes.**
RFC 2439's defaults over-damp (RFC 7196 documents the harm), which is
why damping is off by default. The keys are `[damping]
suppress_threshold` (a figure of merit, not a second count),
`reuse_threshold` and `decay_interval_s`; `additive_incr`,
`upper_limit` and the two decay factors tune the curve. The daemon logs
reactivation as `damping: prefix <prefix> reactivated (FoM decayed below
reuse threshold)` once the figure of merit falls back under the reuse
threshold. Damping is installed for the process lifetime — a reload
cannot turn it off.

**Memory grows without bound on a full-table peer.**
Adj-RIB-In dominates for a peer carrying a full table. Turn off
`--soft-reconfig-inbound` if it is on: it retains the pre-policy
Adj-RIB-In per peer, doubling the per-peer cost, and a soft reconfig
then costs a route-refresh instead of a local re-evaluation. Add an
import route-map that rejects unwanted prefixes early — the safety net
and import hooks run before the RIB entry exists — or cap the peer with
`--max-prefixes N`.

**The CPU spikes during a full-table reconvergence.**
A session reset without GR drops every learned prefix at once.
`--graceful-restart SEC` (RFC 4724) keeps the peer's forwarding state
across the restart, `--llgr SEC` (RFC 9494) adds the long-lived stale
variant, and `--bfd` detects the failure before the hold timer lets the
peer start retaining.

**`--max-prefixes` did not tear the session down.**
The default action is `warn`, which only logs. Use
`--max-prefix-action teardown` (or `restart`). Any other value silently
falls back to `warn`, because the daemon does not validate the string
before mapping it.

**The MRT dump grows the disk.**
The runtime API `mrt PATH` writes a `TABLE_DUMP_V2` file of the whole
Loc-RIB, so its size tracks the RIB. Rotate it with `logrotate`, write
it to a tmpfs, or dump on demand rather than on a timer.

## Where the verification lives

Session lifecycle and hardening are pinned by
`crates/lr-cli/tests/daemon_*.rs`; the API protocol, the metrics
exposition and the config frontends have unit tests beside their
modules. Cross-vendor behaviour lives in `tests/interop/*.sh` — see
[INTEROP.md](INTEROP.md) for the matrix. When this page and a test
disagree, the test wins and this page gets fixed.
