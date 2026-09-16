# Operations runbook

Day-2 operations for `lr-daemon`: lifecycle, the runtime API, and the
failure modes operators actually hit. Point references go to the
authoritative documents; this page adds only what those do not cover.

| Task                        | Authoritative source            |
| --------------------------- | ------------------------------- |
| Every config key explained  | `templates/daemon.toml`         |
| Running BIRD/FRR configs    | `docs/COMPAT.md`                |
| Behaviour knobs vs BIRD/FRR | `docs/PARITY.md`                |
| Interop lab (BIRD + FRR)    | `docs/INTEROP.md`               |
| Embedded (library) use      | `docs/API.md`, `docs/tutorial.md` |

## Lifecycle

```sh
# Build once; the binary is crates/lr-cli's.
cargo build --release -p lr-cli
./target/release/lr-daemon --protocol bgp -c /etc/lr/daemon.toml
# Migrating from BIRD 2 or FRR: the daemon reads those configs too.
./target/release/lr-daemon --config /etc/bird/bird.conf
./target/release/lr-daemon --config /etc/frr/frr.conf
```

The dialect (lr TOML, BIRD 2, FRR) is recognised from the file's
content; a compat-loaded config keeps its dialect for `SIGHUP`
reloads. Unmapped constructs and non-BGP stanzas in a BIRD/FRR file
become startup warnings — see `docs/COMPAT.md` for the full surface
and the `lr:` extension directives.

* `SIGTERM` / `SIGINT` — graceful: every session receives a
  NOTIFICATION CEASE (RFC 4271 §6.4), the Loc-RIB is torn down
  cleanly, exit code 0.
* `SIGHUP` — reload: re-applies `networks` (new prefixes are
  originated, removed prefixes withdrawn). A bad config file keeps
  the current configuration running — reload never crashes or
  half-applies. AS, router-id, peer, and auth changes always require
  a restart; the reload output says so explicitly.
* `--user` / `--group` — privilege drop after the listening sockets
  are bound, so the daemon can hold port 179 and still run unprivileged.
* `--api-socket PATH` — the management plane below. Creation failure
  is fatal on purpose: an operator who asked for a management socket
  must not get a daemon silently running without it.

## Runtime API

`--api-socket` exposes a line-based command protocol on a Unix
socket. Connect with `socat - UNIX-CONNECT:/run/lr.sock` (or
`nc -U`):

```
> status
version 0.1.0
local-as 64512
...
> sessions
#1 64513 Established (hold 90s)
> routes
203.0.113.0/24 via 192.0.2.1 proto=Bgp metric=0 path-id=0
> mrt /tmp/rib.mrt
wrote 1 record(s)
> reload
reload: no network changes
reload: note: AS, router-id, peer and auth changes require a restart
> shutdown
shutting down
```

The `lrctl` binary (ROADMAP-v3 D12) is the supported client: it
proxies the same commands with `lrctl status`, `lrctl sessions`,
`lrctl routes show [prefix]`, `lrctl routes dump <path>`,
`lrctl reload`, `lrctl shutdown` and adds a client-side
`lrctl filter compile <body>` that validates a filter DSL body
without touching the daemon. See
[`lr-cli.md`](lr-cli.md#lrctl--the-operational-cli-roadmap-v3-d12)
for the full `lrctl` reference.

Command reference:

| Command    | Effect                                                          |
| ---------- | --------------------------------------------------------------- |
| `status`   | version, identity, uptime, session/RIB counters, extras        |
| `sessions` | one line per configured session (state, hold time)              |
| `routes`   | Loc-RIB dump, one line per path (`path-id` = RFC 7911 Add-Path; labelled routes — BGP-LU, OSPF prefix-SIDs — append `label=<top>`) |
| `mrt PATH` | write the Loc-RIB as RFC 6396 TABLE_DUMP_V2 (BIRD mrt shape)    |
| `reload`   | re-apply the config file (SIGHUP equivalent)                    |
| `shutdown` | graceful shutdown                                               |
| `help`     | command list                                                    |
| `quit`     | close this connection                                           |

## Prometheus `/metrics` endpoint

`--metrics-addr ADDR` (or `[bgp] metrics_addr = "…"`) starts an
opt-in HTTP endpoint that serves the Prometheus text exposition
format on `GET /metrics` (ROADMAP-v3 D12.2). The endpoint is a
hand-rolled HTTP/1.0 responder (no `hyper` / `tokio` dependency)
bound to a TCP address; bind it to a loopback address for scrape
security — Prometheus basic-auth / mTLS is out of scope (use a
reverse proxy for that).

```sh
./target/release/lr-daemon \
    --local-as 64512 --peer-as 64513 --router-id 10.0.0.1 \
    --listen 127.0.0.1:1179 --network 203.0.113.0/24 \
    --metrics-addr 127.0.0.1:9119
```

Scrape with any HTTP client:

```sh
$ curl -s http://127.0.0.1:9119/metrics
# HELP lr_info librouting daemon identity (always 1).
# TYPE lr_info gauge
lr_info{version="1.0.0-rc.3",local_as="64512",router_id="10.0.0.1"} 1
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
# HELP lr_rib_entries Number of routes in the Loc-RIB (best-path selection output).
# TYPE lr_rib_entries gauge
lr_rib_entries 1
# HELP lr_roa_entries Number of ROA entries in the live ROA store (static + RTR cache).
# TYPE lr_roa_entries gauge
lr_roa_entries 0
```

The exposed metrics:

| Metric                       | Type    | Labels                          | Source                                   |
| ---------------------------- | ------- | ------------------------------- | ---------------------------------------- |
| `lr_info`                    | gauge=1 | `version`, `local_as`, `router_id` | daemon identity (for join queries)  |
| `lr_uptime_seconds`          | gauge   | —                               | `Instant::elapsed()` since metrics spawn |
| `lr_sessions_total`          | gauge   | `kind`, `state`                 | `session_summaries()` count per (kind, state) |
| `lr_established_sessions`    | gauge   | `kind`                          | `session_summaries().established` count |
| `lr_rib_entries`             | gauge   | —                               | `rib_len()`                              |
| `lr_adj_rib_in_entries`      | gauge   | `kind`                          | sum of `adj_rib_in_len` per kind         |
| `lr_roa_entries`             | gauge   | —                               | `RoaStore::len()` (omitted when no store) |

The `lr_roa_entries` metric is omitted entirely when the daemon does
not carry a ROA store (e.g. OSPF-only, Babel-only, or a BGP daemon
without `roa_validate` and no static `[[roa]]` table) — a missing
metric is more honest than a misleading zero. The endpoint also
serves `GET /` (a one-line pointer to `/metrics`) and `404 Not Found`
for every other path.

## Container deployment

A multi-stage `Dockerfile` at the repo root builds the daemon, the
inspection CLI (`lr`), the operational CLI (`lrctl`), and the C ABI
shared library (`liblr_ffi.so`) into a `debian:bookworm-slim` runtime
image (ROADMAP-v3 D12.3). See [`docker/README.md`](docker/README.md)
for the full deployment guide — quick start, production config-file
mount, sidecar `lrctl`, image layout, exposed ports, volumes, the
~100 MB size target, and what the image does NOT include.

```sh
# Build.
docker build -t librouting:rc.3 .

# Quick start — single-peer BGP on loopback.
docker run --rm --network host \
    librouting:rc.3 \
    --local-as 64512 --peer-as 64513 --router-id 10.0.0.1 \
    --listen 127.0.0.1:1179 --network 203.0.113.0/24 \
    --api-socket /run/lr-daemon/api.sock \
    --metrics-addr 127.0.0.1:9119

# Production — config file mount.
docker run --rm -d \
    --name lr-daemon \
    -p 179:179 -p 9119:9119 \
    -v /etc/lr-daemon/daemon.toml:/etc/lr-daemon/daemon.toml:ro \
    -v lr-daemon-run:/run/lr-daemon \
    librouting:rc.3 \
    --config /etc/lr-daemon/daemon.toml

# Sidecar lrctl — same image, override the entrypoint.
docker run --rm --volumes-from lr-daemon \
    librouting:rc.3 \
    lrctl --socket /run/lr-daemon/api.sock status
```

The image does NOT ship a default config (operators mount one or pass
CLI flags) and does NOT push to a registry from CI (that is a
release-event concern). A Helm chart is deferred — it conventionally
lives in its own repository so it can version independently of the
image; the Dockerfile here is the foundation a chart would reference.

## Troubleshooting FAQ

**Session establishes but no routes flow in either direction.**
The daemon's default eBGP posture is RFC 8212: external peers
without an explicit import/export policy exchange nothing. The
startup log says so per peer. Either attach route-maps
(`[[route-map]]` + per-peer `import`/`export`) or run the explicit
insecure deviation `--ebgp-policy accept-all`. iBGP and
confederation-internal sessions are exempt.

**`config warning: unknown key ...` at startup.**
The parser is fail-closed on structure, forward-compatible on keys:
unknown keys are surfaced as line-numbered warnings, not errors, so
a newer config does not brick an older daemon. If the warning names
a key you meant to use, it is misspelled — everything else is a
warning only.

**Session stuck in Connect/Active.**
For outbound peers the daemon retries with backoff; check the peer
address/port, then GTSM (`--gtsm` requires the peer to send TTL 255
— an extra hop silently kills it), then auth: an MD5/TCP-AO mismatch
logs `session auth arming failed` before the TCP handshake completes.

**`Protocol not available` when arming TCP-AO.**
The kernel lacks TCP-AO support (needs Linux >= 6.7,
`CONFIG_TCP_AO`). There is no workaround on older kernels; use MD5
(RFC 2385) or plain TCP with BFD. Inbound connections with a
mismatched auth configuration are rejected fail-closed.

**OSPF or Babel daemons fail to bind raw/multicast sockets.**
OSPF mode needs raw `IPPROTO_OSPF` sockets (`CAP_NET_RAW`). In CI
and containers the established pattern is a rootless network
namespace: `unshare -Urn` grants the capability inside the new
namespace without host root.

**LDP/MPLS interop scripts print `SKIP: phase 3 (dataplane)`.**
Kernel MPLS is not loaded on the host: `modprobe mpls_router
mpls_iptunnel` (host root — the sysctls are host-level), then the
per-namespace `platform_labels` and per-interface `input` switches
are set by the scripts themselves.

**Routes learned but not in the kernel FIB.**
Kernel installation is opt-in: `--install-kernel-routes` (or
`install_kernel = true`). For BGP-LU routes and OSPF Segment Routing
prefix-SIDs (`[ospf] sr_receive`) the mirror needs the `AF_MPLS` stack
(see above); without it only the plain IP routes install and the LSP
halves log a note.

**Reload ignored my peer edits.**
Reload re-applies `networks` only. Peer, AS, router-id, and auth
changes are restart-only by design; the reload output lists what
was applied and reminds about the rest.

## Deeper troubleshooting

**BGP session flapping (Established → Idle → Established every
~90 s).**
This is almost always a hold-timer mismatch or an auth failure. Check
the daemon log for:
- `session N: hold time expired` — the peer's KEEPALIVE cadence is
  slower than the negotiated hold time / 3. Lower `--hold-time` or
  fix the peer's KEEPALIVE interval.
- `session auth arming failed` — MD5 or TCP-AO key mismatch. The
  TCP handshake never completes; the BGP FSM sits in Active and
  retries with backoff. Verify the shared secret with the peer
  operator; for TCP-AO also verify the key ID and the algorithm
  (`hmac-sha1` default, `cmac-aes` optional).
- `session N: NOTIFICATION received (Cease/ConnectionCollision)` —
  both sides are dialing each other simultaneously and the
  lower-BGP-Identifier speaker loses per RFC 4271 §6.8. This is
  expected once per startup; if it repeats, the losing side's
  outbound transport is flapping (check the underlying TCP
  reachability).

**OSPF adjacency stuck in ExStart.**
The DBD exchange (RFC 2328 §7.2 / RFC 5340 §A.5) never advances past
ExStart when:
- The **MTU** disagrees between the two sides (the DBD packet is
  larger than the peer's interface MTU; the large-DBD never lands).
  Check `ip link show <if>` (Linux) — both sides must agree.
- The **Router ID** is duplicated (the §10.6 election cannot pick a
  master). Check the daemon log: `ospf: neighbor <ip> router-id
  <id>` — the IDs must differ.
- The **interface type** disagrees (one side is broadcast, the other
  point-to-point). The §9.4 DR election only runs on broadcast;
  a p2p side does not send the DR/BDR fields and the broadcast side
  waits forever. Check `network_type` per interface in the TOML.

**OSPF adjacency stuck in Exchange (DBD exchange never completes).**
Usually a **dead interval mismatch**: the neighbor's Hello dead
timer does not match ours, so the kernel drops the adjacency before
the DBD sequence finishes. Verify `dead_interval` per interface
(default 40 s) matches the peer. Also check the **area ID** — a
mismatched area ID (e.g. `0.0.0.0` vs `0.0.0.1`) puts the neighbor
in a different area and the DBD exchange is rejected.

**LDP label binding not propagating.**
The DU mode (RFC 5036 §3.5.7.1.1) requires both sides to advertise
the binding independently. Check:
- `ldp: peer <ip> -> Operational` in the daemon log — the TCP
  session must be up first. If not, check the UDP Hello exchange
  (`ldp: hello <ip> hold=N`); a missing Hello is usually a
  multicast-routing or firewall issue (LDP uses 224.0.0.106 v4 /
  ff02::1:6 v6).
- `ldp: mapping <prefix> label=N -> <peer>` — the local binding
  was advertised. If the peer's LIB does not show the binding, the
  peer's `advertise_mapping` was not called or the FEC was
  withdrawn.
- On Linux, `mpls -l` (iproute2) shows the installed LSP. If the
  binding is in the LIB but not in the kernel, the `AF_MPLS` stack
  is missing (see above) or `--install-kernel-routes` was not set.

**Route flap damping too aggressive (legitimate routes suppressed).**
RFC 2439's defaults are known to over-damp (RFC 7196 documents the
harm). The daemon ships with damping **off** by default; enabling it
requires explicit configuration. If you enabled it and routes are
suppressed:
- Lower `max-suppress` (the ceiling in seconds) — 30 s is the
  modern recommendation, not RFC 2439's 60 s.
- Raise `reuse-limit` above the route's flap history (the default
  is 750; a prefix that flaps 4×/hour can exceed it).
- Check `daemon: route <prefix> suppressed (decay=N)` in the log —
  the figure of merit is printed at suppression time.

**Memory growth over time (Adj-RIB-In unbounded).**
For a full-table peer (800k+ prefixes), the Adj-RIB-In is the
dominant memory consumer. Mitigations:
- Disable `--soft-reconfig-inbound` if enabled (it retains the
  pre-policy Adj-RIB-In per peer, doubling the memory cost). The
  trade-off is that a soft reconfig requires a route-refresh from
  the peer instead of a local re-evaluation.
- Add an import route-map that rejects unwanted prefixes early
  (before Adj-RIB-In). The safety net + import hooks run before
  the RIB entry is created.
- Use `--max-prefixes N` to cap the per-peer prefix count and
  tear down the session when exceeded (FRR `maximum-prefix`).

**Daemon CPU spike during full-table reconvergence.**
A session reset without GR (RFC 4724) drops every learned prefix at
once and the decision process runs flat-out. Mitigations:
- Enable `--graceful-restart SEC` (RFC 4724, default 120 s) so the
  peer retains the forwarding state across the restart.
- Enable `--llgr SEC` (RFC 9494) for the long-lived stale variant
  on address families that need it (VPN, EVPN).
- Add BFD (`--bfd`) so the failure is detected before the hold
  timer expires and the peer has time to retain the state.

**MRT dump grows the disk.**
The runtime API `mrt PATH` writes a TABLE_DUMP_V2 file (RFC 6396)
of the current Loc-RIB. The file grows with the RIB size; a full
table is ~200 MB. Rotate with `logrotate` or write to a tmpfs.

## Where the verification lives

Every behavior above is pinned by a test: session lifecycle and
hardening in `crates/lr-cli/tests/daemon_*.rs`, cross-vendor
behavior in `tests/interop/*.sh` (see `docs/INTEROP.md` for the
matrix and the local reproduction steps), and the unit layer under
each crate. When a runbook entry and a test disagree, the test wins
and this document gets fixed.
