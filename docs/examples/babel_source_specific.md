# Babel source-specific routing

RFC 9079 adds an optional source prefix to a Babel route, so the same
destination can carry one path for traffic from one source prefix and a
different path for the rest. This page keys a route table on
`(destination, source)` and shows what the daemon does with those routes.

## The problem it solves

```text
                        +---------+
   src 2001:db8:1::/48  | uplink  |  default route
        ~~~~~~~~~~~~~~> +---------+
                        |  host   |
   src 10.0.0.0/8       +---------+
        ~~~~~~~~~~~~~~> |   vpn   |  10.0.0.0/8 internal path
                        +---------+
```

Both routes point at the same destination prefix; only the source
prefix separates them.

## The data model

`RouteKey` carries `destination`, an optional `source`, and the
`router_id` that originated the route. An ordinary RFC 8966 route is the
`source: None` case, so the two classes never collide:

```rust
// Cargo.toml:
// [dependencies]
// lr-babel = "<version>"
// lr-core = "<version>"

use lr_babel::{BabelRoute, BabelRouteTable, RouteKey, SourcePrefix};
use lr_core::addr::{IpAddr, Prefix};

fn main() {
    let mut table = BabelRouteTable::new();
    let dst = Prefix::new_v4([10, 0, 0, 0], 8);

    // Plain RFC 8966 route: source = None, metric 200.
    table.insert(BabelRoute {
        key: RouteKey {
            destination: dst,
            source: None,
            router_id: [1; 8],
        },
        seqno: 1,
        metric: 200,
        next_hop: IpAddr::V4([192, 0, 2, 1]),
        feasible: true,
        installed: false,
    });

    // RFC 9079 variant: same destination, internal source prefix,
    // better metric.
    table.insert(BabelRoute {
        key: RouteKey {
            destination: dst,
            source: Some(SourcePrefix::new(Prefix::new_v4([10, 8, 0, 0], 14))),
            router_id: [2; 8],
        },
        seqno: 1,
        metric: 100,
        next_hop: IpAddr::V4([198, 51, 100, 1]),
        feasible: true,
        installed: false,
    });

    // Feasibility and best-path selection are per (destination, source)
    // pair, so the VPN path serves VPN-sourced traffic and the uplink
    // path serves everything else.
    assert_eq!(table.len(), 2);
}
```

## On the wire and in the daemon

The source prefix travels as the Source Prefix sub-TLV
(`lr_babel::TlvType::SourcePrefixSubTlv`, type 128, RFC 9079 §4) inside
an Update TLV. `lr-babel`'s codec parses and emits it; the daemon
re-advertises the sub-TLV on every session and keeps both classes of
route in the Loc-RIB, so they show up in the runtime API:

```sh
lrctl --socket /run/lr-daemon.api routes show 10.0.0.0/8
```

## Kernel caveat

The Linux FIB needs a source-qualified route — `ip route add <dst> from
<source> ...` — and `lr_osroute` installs plain `RTM_NEWROUTE` entries
only. Source-specific routes therefore take part in the Loc-RIB and in
best-path selection, but the kernel mirror does not program them. An
embedder that needs them programs those entries through its own FIB
layer; see [`os_integration.md`](os_integration.md) for the trait to
implement.

## Reference

- RFC 9079 — Source-Specific Routing in Babel
- RFC 8966 §3.2.5 — route expiry
- [`babel_multi_nic.md`](babel_multi_nic.md) — the per-interface
  parameters these routes are learned over
