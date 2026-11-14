# First deployment: from zero to a running BGP router

This page walks an operator from a fresh checkout to a working
two-router BGP deployment in one sitting: build the daemon, write a
`.lr` config, bring up a peer, watch a route propagate, apply basic
import and export policy, validate origins against ROA, install best
routes into the kernel FIB, and reload with `SIGHUP`. Every command
below is the exact command the page runs; copy them in order.

If you would rather embed the library in your own event loop than run
a daemon, read [`../tutorial.md`](../tutorial.md) instead. The
narrative guide in [`../lr-daemon.md`](../lr-daemon.md) covers the
same surface with more context and less step-by-step hand-holding;
this page is the "I just want it running" path.

The daemon is not a production NOS — BIRD, FRR and OpenBGPD are. It
exists to exercise every library feature end to end, so the same
configuration surface that runs in production-grade NOSes runs here.

## Prerequisites

A Rust toolchain (`rustup`, stable) and a Linux, macOS or Windows
host. The kernel-route-install step at the end is Linux-only; on
macOS and Windows the daemon still runs, but `--install-kernel-routes`
is a no-op or skipped. The peer used here is a second `lr-daemon`
process — the same approach `tests/interop/two_daemon.sh` takes — so
no BIRD or FRR install is needed. The page names where BIRD or FRR
drop in instead.

## Step 1 — build the daemon and the client

```sh
git clone https://github.com/TES286-org/librouting.git
cd librouting
cargo build --release -p lr-cli
```

The two binaries that matter are `target/release/lr-daemon` (the
router) and `target/release/lrctl` (the operational CLI). The daemon
hand-parses its own `argv`, so a stripped container needs no argument
library. The build has no system dependencies beyond the toolchain.

## Step 2 — write the smallest useful config

Pick two loopback ports nothing else is using. The page uses
`127.0.0.1:11791` for router A and a second `lr-daemon` (router B)
that connects into it. Put both configs in `/tmp/lr-first/` so the
page's paths are stable:

```sh
mkdir -p /tmp/lr-first
```

Router A — AS 64512, listens on `127.0.0.1:11791`, originates
`203.0.113.0/24`. The `local_address` is the NEXT_HOP the daemon
advertises; it must not be loopback (BGP safety rejects
`127.0.0.1` as a NEXT_HOP, so use a TEST-NET address from RFC 5737
or a real interface address):

```sh
cat > /tmp/lr-first/a.lr <<'EOF'
bgp {
    local_as       64512;
    peer_as        64513;
    router_id      10.0.0.1;
    listen_addr    127.0.0.1:11791;
    local_address  192.0.2.1;
    hold_time      9s;
    ebgp_policy    "accept-all";
    networks       [203.0.113.0/24];
}
EOF
```

Router B — AS 64513, connects to A, accepts everything A advertises.
A peer with `remote` dials out; one with `address` listens for a
specific source IP. Router B does the dialling:

```sh
cat > /tmp/lr-first/b.lr <<'EOF'
bgp {
    local_as       64513;
    peer_as        64512;
    router_id      10.0.0.2;
    local_address  192.0.2.2;
    hold_time      9s;
    ebgp_policy    "accept-all";
}

peer "upstream" {
    remote         127.0.0.1:11791;
    peer_as        64512;
}
EOF
```

`hold_time 9s;` keeps the test cycle short — production peers use the
RFC 4271 default of 90 s. `ebgp_policy "accept-all";` is the RFC 8212
Appendix A "insecure-mode" deviation that lets the session exchange
routes without explicit import/export route-maps; the default is
`rfc8212` (deny-in/deny-out for external peers without policy). Use
`accept-all` only for a lab.

The `.lr` grammar reference is
[`../config_dsl_grammar.md`](../config_dsl_grammar.md); the commented
reference config is [`../../templates/daemon.lr`](../../templates/daemon.lr).

## Step 3 — start the daemon and watch it come up

Start A first (it listens), then B (it dials). The `--api-socket`
flag opens the runtime API so `lrctl` can inspect the daemon without
sending signals.

```sh
target/release/lr-daemon --config /tmp/lr-first/a.lr \
    --api-socket /tmp/lr-first/a.sock > /tmp/lr-first/a.out 2>&1 &

target/release/lr-daemon --config /tmp/lr-first/b.lr \
    --api-socket /tmp/lr-first/b.sock > /tmp/lr-first/b.out 2>&1 &
```

Give the daemons two seconds to negotiate, then ask B for its Loc-RIB.
The originated route should have propagated from A to B:

```sh
target/release/lrctl --socket /tmp/lr-first/b.sock routes count
target/release/lrctl --socket /tmp/lr-first/b.sock routes show 203.0.113.0/24
```

```text
total 2
  proto=bgp routes=1
  proto=direct routes=1
203.0.113.0/24 via 192.0.2.1 proto=Bgp metric=1 path-id=0
```

The `proto=direct` line is the daemon's connected-route enumeration
(`getifaddrs`) — BIRD `protocol direct` / FRR `redistribute connected`
parity. `routes show <prefix>` prints one line per path; with
Add-Path (RFC 7911) a prefix can hold several ranked paths
distinguished by `path-id`.

Confirm the session is Established:

```sh
target/release/lrctl --socket /tmp/lr-first/b.sock show sessions
```

```text
#1 kind=bgp local-as=64513 peer-as=64512 state=Established established=true peer-id=10.0.0.1 hold-time=9 adj-rib-in=1 ...
```

`peer-id` is the peer's BGP Identifier; `hold-time` is the negotiated
value (the lower of the two OPENs); `adj-rib-in` is the count of
routes held in Adj-RIB-In. The full per-session field reference is in
[`../RUNBOOK.md`](../RUNBOOK.md).

## Step 4 — inspect the daemon's identity and config dialect

The `status` and `show status` commands print the daemon's identity
block. The page uses it to verify the dialect the daemon resolved:

```sh
target/release/lrctl --socket /tmp/lr-first/b.sock status
```

```text
version <version>
local-as 64513
peer-as 64512
router-id 10.0.0.2
config b.lr
config-dialect lr
uptime-secs 4
sessions 1
rib-entries 2
```

`config-dialect lr` is the native `.lr` DSL — the primary authoring
dialect. A daemon started on a TOML config stamps `config-dialect
toml` and an extra `config-deprecation` line pointing at the
migration tool, because the TOML subset is in its deprecation window
(fully supported through the 1.x series, planned for removal in 2.x).
The same notice rides the startup stderr, the structured `log_warn!`
record, every reload, and the `lr_config_dialect_deprecated` metrics
gauge.

## Step 5 — add import policy with the filter DSL

`ebgp_policy "accept-all"` lets everything through. Real deployments
attach a filter to the peer so the Loc-RIB only sees routes the
operator vetted. The filter DSL is a BIRD-style `if/then` language
over the route's attributes; the grammar is in
[`../filter_dsl_grammar.md`](../filter_dsl_grammar.md).

Replace B's config with one that:

- accepts `203.0.113.0/24` from A and sets `local_pref = 200` on it,
- rejects anything else from 203.0.113.0/24 with a different next-hop,
- accepts everything else (so the lab does not lose other routes).

```sh
cat > /tmp/lr-first/b.lr <<'EOF'
bgp {
    local_as       64513;
    peer_as        64512;
    router_id      10.0.0.2;
    local_address  192.0.2.2;
    hold_time      9s;
    ebgp_policy    "accept-all";
}

peer "upstream" {
    remote         127.0.0.1:11791;
    peer_as        64512;
    import_filter  "customer-in";
}

filter "customer-in" {
    if net ~ 203.0.113.0/24 then {
        bgp.local_pref = 200;
        accept;
    }
    accept;
}
EOF
```

Reload B. The daemon re-reads its config on `SIGHUP` and prints what
changed; filter changes apply on the next UPDATE, not retroactively,
so the already-installed `203.0.113.0/24` keeps its old `local_pref`
until A re-advertises it (send `lrctl session 1 soft-in` to force a
re-evaluation against the new filter):

```sh
kill -HUP $(pgrep -f 'lr-daemon --config /tmp/lr-first/b.lr')
sleep 1
tail -5 /tmp/lr-first/b.out
target/release/lrctl --socket /tmp/lr-first/b.sock session 1 soft-in
```

The reload log names what was applied; an unchanged filter set prints
`reload: no network changes`. Reload never crashes and never
half-applies — a parse error keeps the running config and prints
`reload: <error> (keeping current config)`.

## Step 6 — add ROA validation

RFC 6811 prefix-origin validation rejects a route whose origin AS is
not authorized by a Route Origin Authorization. The daemon's ROA
table is fed by `roa` blocks in the config (a static layer) and/or an
RPKI-RTR cache (RFC 8210); the two merge into one table.

Add a ROA that authorizes `203.0.113.0/24` for AS 64512 (the peer
that advertises it), and a second that authorizes
`198.51.100.0/24` for AS 65000 only — so a route for it from AS 64512
would validate as `invalid`. Turn validation on in the `bgp` block:

```sh
cat >> /tmp/lr-first/b.lr <<'EOF'

bgp {
    roa_validate    true;
    roa_invalid_action "reject";
}

roa {
    prefix "203.0.113.0/24";
    asn    64512;
}

roa {
    prefix "198.51.100.0/24";
    asn    65000;
    max_length 24;
}
EOF
```

The two `bgp { … }` blocks merge — the DSL is a stream of statements
and the applier folds them into one typed IR. `roa_invalid_action
"reject"` drops invalid routes at import; the alternatives are
`"warn"` (log and accept) and `"accept"` (no-op). Reload B and watch
the startup banner name the ROA table:

```sh
kill -HUP $(pgrep -f 'lr-daemon --config /tmp/lr-first/b.lr')
sleep 1
grep "roa:" /tmp/lr-first/b.out | tail -1
```

```text
  roa:         2 inline entries, validate=true (action: reject)
```

`lrctl show roa` dumps the merged table; the BGP daemon populates it
from `roa` blocks and the live RTR cache. See
[`filter_dsl_roa.md`](filter_dsl_roa.md) for the full ROA + filter
DSL walkthrough.

## Step 7 — install best routes into the kernel FIB

`--install-kernel-routes` (or `install_kernel true;` in the config)
writes the Loc-RIB's best path per prefix into the kernel FIB via the
platform's routing-table API (`rtnetlink` on Linux, `PF_ROUTE` on
BSD, `CreateIpForwardEntry2` on Windows). The daemon needs the
privilege the kernel requires (root on Linux/BSD; admin on Windows).

Add the flag to A (so it installs the route it originates):

```sh
kill $(pgrep -f 'lr-daemon --config /tmp/lr-first/a.lr')
target/release/lr-daemon --config /tmp/lr-first/a.lr \
    --api-socket /tmp/lr-first/a.sock \
    --install-kernel-routes > /tmp/lr-first/a.out 2>&1 &
```

On Linux, verify the route landed:

```sh
ip route show 203.0.113.0/24
```

A production daemon drops privileges with `--user` / `--group` after
binding the listener and arming TCP-MD5 / TCP-AO; if the reduced user
cannot install routes, the daemon warns at startup. See
[`../lr-daemon.md`](../lr-daemon.md) §"Dropping privileges".

## Step 8 — use a real BIRD or FRR peer instead

The peer in this page is a second `lr-daemon` because the page cannot
assume BIRD or FRR is installed. To use a real reference
implementation, point A at BIRD's config and B at FRR's:

```sh
# BIRD 2 as router A
cat > /tmp/lr-first/a.bird <<'EOF'
router id 10.0.0.1;
protocol bgp upstream {
    local as 64512;
    neighbor 127.0.0.1 as 64513;
    source address 127.0.0.1;
    hold time 9;
    ipv4 { import all; export all; };
}
protocol static { route 203.0.113.0/24 unreachable; }
protocol device {}
EOF
bird -c /tmp/lr-first/a.bird

# FRR (bgpd) as router B
target/release/lr-daemon --config /tmp/lr-first/b.lr
```

`lr-daemon translate bird|frr FILE` converts a BIRD or FRR file into
an equivalent `.lr` program; `lr-daemon config check FILE` validates
any dialect without starting the daemon. The compat mapping is in
[`../COMPAT.md`](../COMPAT.md); the interop labs in
`tests/interop/` run the same scenarios against real BIRD and FRR
peers in CI.

## Troubleshooting

The session never reaches `Established`. Check `b.out` for
`outbound TCP established` — if the dial failed, A is not listening
(check `a.out` for `listening on`). If the TCP is up but the FSM
stops at `OpenSent` / `OpenConfirm`, the AS numbers or router-ids
mismatched; the OPEN NOTIFICATION names the error.

A route A originates does not appear in B's Loc-RIB. The safety net
may have rejected it. Look for `safety: rejected <prefix>` in
`b.out` — the most common cause is a NEXT_HOP the receiver cannot
use (loopback, or an address not on any of the receiver's
interfaces). Set `local_address` on A to an address B's kernel would
route to (TEST-NET addresses are fine for a lab; the daemon does not
require the address to be assigned to a real interface, but BGP's
NEXT_HOP validity check rejects loopback).

`SIGHUP` did not apply the new filter. Reload only re-applies a
subset of the config — networks, static routes, ROAs, RPKI cache
address, logging. Filter bodies are compiled at startup and bound to
peers; a new filter body or a new peer-→-filter binding needs a
restart. The reload log says `reload: note: AS, router-id, peer and
auth changes require a restart`.

`lrctl` says `Connection refused`. The daemon either never started
(check `*.out`) or has already exited. The API socket file is
unlinked on `shutdown` and on thread exit, so a stale file from an
unclean shutdown never blocks startup.

The daemon exits with `error: --local-as is required` or `error:
--router-id is required`. The two fields are mandatory; the daemon
prints the usage banner and exits 2. `--router-id` accepts an IPv4
dotted-quad; ASNs are unsigned 32-bit.

## Where to go next

- Every flag and every configuration key, with defaults:
  [`../lr-daemon-reference.md`](../lr-daemon-reference.md).
- The `.lr` grammar and the filter DSL grammar:
  [`../config_dsl_grammar.md`](../config_dsl_grammar.md),
  [`../filter_dsl_grammar.md`](../filter_dsl_grammar.md).
- Multi-peer deployments, redistribution, aggregation, privilege
  drop, signals, the runtime API socket:
  [`../lr-daemon.md`](../lr-daemon.md).
- The API reply strings, the metrics endpoint, containers, failures:
  [`../RUNBOOK.md`](../RUNBOOK.md).
- Worked scenario walkthroughs (route reflection, route servers,
  BGP-LU, BFD, ROA, OSPF ABR/NSSA, SRv6, Babel, LDP, OS integration):
  [`./`](./).
- Verifying against BIRD or FRR with the interop labs:
  [`../INTEROP.md`](../INTEROP.md), `tests/interop/`.
