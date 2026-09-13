# Babel multi-NIC with glob patterns

This example demonstrates the `[[babel.interface]]` configuration for
per-interface Babel parameters (RFC 8966 §A.2) with shell-like glob
pattern matching. The daemon enumerates the system interfaces via
`getifaddrs(3)`, matches each name against the patterns in file order,
and uses the first match's parameters for the single Babel session.

## Configuration

```toml
# Top-level protocol selection.
protocol = "babel"

[babel]
port = 6696

# Wired interfaces: low rxcost, fast hello interval.
[[babel.interface]]
name = "eth*"
type = "wired"
rxcost = 96
hello_interval_ms = 4000

# Wireless interface: high rxcost, slow hello interval.
[[babel.interface]]
name = "wlan0"
type = "wireless"
rxcost = 256

# Tunnel interface: RTT-based cost for latency-sensitive routes.
[[babel.interface]]
name = "tun0"
type = "tunnel"
rxcost = 192
rtt_cost = 100
rtt_min_us = 10000       # 10 ms
rtt_max_us = 120000      # 120 ms

# Loopback: inert, high cost (never used for Babel adjacency).
[[babel.interface]]
name = "lo"
type = "wired"
rxcost = 65535
```

## How it works

1. At startup, `run_babel_daemon()` calls
   `lr_osroute::ospf_transport::list_interfaces()` to enumerate every
   system interface with its IPv4 and IPv6 addresses.
2. For each `[[babel.interface]]` block, the daemon matches the `name`
   glob pattern against the enumerated interfaces using
   `daemon_config::glob_match()` (BIRD's `lib/patmatch.c` semantics:
   `*` matches any sequence, `?` any single character, `\` escapes).
3. The first matching pattern wins — its parameters apply to the
   single Babel session.
4. When `--local-address` is unset, the daemon picks the first
   matched interface's primary IPv4 (or IPv6 if no IPv4) as the bind
   source.

## Glob pattern syntax

| Pattern | Matches                                     |
|---------|---------------------------------------------|
| `eth*`  | `eth0`, `eth1`, `ethernet-extra-long`       |
| `eth?`  | `eth0`, `eth1` (not `eth` or `eth01`)       |
| `*0`    | `eth0`, `wlan0` (any name ending in `0`)    |
| `eth\*` | `eth*` literally (the `*` is escaped)       |
| `lo`    | `lo` exactly                                |

## Available keys

| Key                  | Type   | Default          | Description                          |
|----------------------|--------|------------------|--------------------------------------|
| `name`               | string | (required)       | Interface name or glob pattern       |
| `type` / `kind`      | string | `"wired"`        | `wired` \| `wireless` \| `tunnel`   |
| `hello_interval_ms`  | int    | 4000 (wired)     | Hello interval in ms (RFC 8966 §3.1)|
| `update_interval_ms` | int    | 4× hello         | Multicast update interval            |
| `rxcost`             | int    | 96 (wired)       | Receive cost (§3.5.2)               |
| `rtt_cost`           | int    | 0                | RTT-based cost (§A.2.4, off when 0) |
| `rtt_min_us`         | int    | 10000            | Lower RTT bound in microseconds      |
| `rtt_max_us`         | int    | 120000           | Upper RTT bound in microseconds      |
| `next_hop_ipv4`      | string | (auto)           | Per-interface IPv4 next-hop          |
| `next_hop_ipv6`      | string | (auto)           | Per-interface IPv6 next-hop          |
| `extended_next_hop`  | bool   | false            | RFC 5549 extended next-hop           |
| `check_link`         | bool   | true             | Withdraw on interface down           |
| `port`               | int    | `[babel] port`   | Override the global Babel port       |
| `group`              | string | `[babel] group`  | Override the global multicast group  |

## Interop

The `tests/interop/babel_multi_nic.sh` test runs in a user+network
namespace (`unshare -Urn`), creates a veth pair (`veth0`/`veth1`),
configures two `[[babel.interface]]` patterns (`veth*` and `lo`), and
verifies the daemon:

1. Logs `babel N interface pattern(s) configured; enumerating M
   system interface(s)`.
2. Matches `veth*` against `veth0` and `veth1`.
3. Matches `lo` against the loopback.
4. Picks the first matched interface's address as the bind source.

## References

- RFC 8966 — The Babel Routing Protocol (§A.2 link cost models)
- RFC 8967 — Babel MAC authentication (per-interface keys)
- BIRD `proto/babel/config.Y` — interface directive grammar
- BIRD `lib/patmatch.c` — shell-like pattern matching
