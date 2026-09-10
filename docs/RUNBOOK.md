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

## Where the verification lives

Every behavior above is pinned by a test: session lifecycle and
hardening in `crates/lr-cli/tests/daemon_*.rs`, cross-vendor
behavior in `tests/interop/*.sh` (see `docs/INTEROP.md` for the
matrix and the local reproduction steps), and the unit layer under
each crate. When a runbook entry and a test disagree, the test wins
and this document gets fixed.
