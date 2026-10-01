# Babel per-interface parameters

Babel computes link cost per interface, so the same daemon can treat a
wired port, a wireless port and a tunnel differently. This page
configures that with glob patterns and shows how to confirm which
interface got which parameters.

## Configuration

```lr
protocol babel;

babel {
    port 6696;

    # Every eth* interface: wired cost model, fast Hellos.
    interface "eth*" {
        type "wired";
        rxcost 96;
        hello_interval_ms 4s;
    }

    # The wireless port is expensive and quiet.
    interface "wlan0" {
        type "wireless";
        rxcost 256;
    }

    # A tunnel adds an RTT-based penalty on top of rxcost.
    interface "tun0" {
        type "tunnel";
        rxcost 192;
        rtt_cost 100;
        rtt_min 10ms;      # 10000 us
        rtt_max 120ms;     # 120000 us
    }
}
```

Each glob is matched in file order and the **first match wins per
interface**. The daemon enumerates the system interfaces, resolves one
Babel session for each matched interface, and skips the ones whose
sockets cannot bind.

## Glob syntax

The matcher follows BIRD's `lib/patmatch.c`: `*` is any sequence, `?` is
any single character, `\` escapes the next character.

| Pattern | Matches |
| ------- | ------- |
| `eth*` | `eth0`, `eth1`, `ethernet-extra-long` |
| `eth?` | `eth0`, `eth1` (not `eth` or `eth01`) |
| `*0` | `eth0`, `wlan0` |
| `eth\*` | the literal name `eth*` |

## Keys

| Key | Type | Default | Meaning |
| --- | ---- | ------- | ------- |
| `name` | string | required | Interface name or glob, the block identity |
| `type` / `kind` | string | `"wired"` | `wired`, `wireless` or `tunnel` |
| `hello_interval_ms` | duration | 1000 ms | Hello interval (RFC 8966 §3.1) |
| `update_interval_ms` | duration | 3× hello | Multicast update interval |
| `rxcost` | int | 96 | Receive cost advertised (§3.5.2) |
| `rtt_cost` | int | 96 on `tunnel`, else 0 | RTT penalty (§A.2.4) |
| `rtt_min` | duration | 10 ms | Lower RTT bound |
| `rtt_max` | duration | 120 ms | Upper RTT bound |
| `next_hop_ipv4` | string | interface address | Advertised IPv4 next hop |
| `next_hop_ipv6` | string | link-local | Advertised IPv6 next hop |
| `extended_next_hop` | bool | false | RFC 5549 next hop |
| `check_link` | bool | true | Withdraw on interface down |
| `port` | int | global `port` | Override the Babel port |
| `group` | string | global group | Override the multicast group |

`rtt_min` and `rtt_max` take a duration suffix and are stored in
microseconds; a bare number is microseconds. The older spellings
`rtt_min_us` and `rtt_max_us` are accepted for the same keys. A
`rtt_min` that is not below `rtt_max` is a startup error.

## Verify

Startup logs every pattern and every session:

```text
daemon: babel 3 interface pattern(s) configured; enumerating 6 system interface(s)
daemon: babel interface pattern 'eth*' matched 2 interface(s): eth0, eth1
daemon: babel interface eth0 session 1 — v6 hello 4000ms update 12000ms rxcost 96 router-id 10.0.0.1 check-link
```

A pattern that matches nothing logs
`daemon: babel interface pattern '...' matched 0 interfaces`. If no
pattern matches any interface at all, the daemon exits with
`no system interface matched any [[babel.interface]] pattern`.

To watch reachability per session:

```sh
lrctl --socket /run/lr-daemon.api routes show 2001:db8::/32
```

## Reference

- RFC 8966 — The Babel Routing Protocol (§A.2 link cost models)
- RFC 8967 — MAC authentication for Babel (per-interface keys)
- [`babel_source_specific.md`](babel_source_specific.md) — RFC 9079
  routes over the same sessions
