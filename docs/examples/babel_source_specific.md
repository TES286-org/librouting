# Example: Babel source-specific routing (RFC 9079)

Babel's route table keys on more than the destination: RFC 9079 adds
an optional *source* prefix, so the same destination can carry
different routes for different traffic sources. The classic use is a
dual-connected edge network that must pin intra-company traffic to
the internal path while everything else follows the default:

```
                      +---------+
   src 2001:db8:1::/48 |  uplink |  default route
        ~~~~~~~~~~~~~> +---------+
                      |  host   |
   src 10.0.0.0/8     +---------+
        ~~~~~~~~~~~~~> |  vpn    |  10.0.0.0/8 internal path
                       +---------+
```

Both routes point at the same destination prefix; the source prefix
is what separates them.

## The data model

`lr-babel` keys every route on `(destination, source, router-id)` —
the source is optional, so ordinary RFC 8966 routes are the
`None`-source special case and the two classes never collide:

```rust
// Cargo.toml:
// [dependencies]
// lr-babel = "1.0.0-rc.4"

use lr_babel::route::{BabelRoute, BabelRouteTable, RouteKey};
use lr_babel::source::SourcePrefix;
use lr_core::addr::{IpAddr, Prefix};

fn main() {
    let mut table = BabelRouteTable::new();
    let dst = Prefix::new_v4([10, 0, 0, 0], 8);

    // The plain (RFC 8966) route: source = None.
    let plain_key = RouteKey {
        destination: dst,
        source: None,
        router_id: [1; 8],
    };

    // The source-specific variant (RFC 9079): same destination,
    // different traffic class. The wire carries the source prefix as
    // the Source Prefix sub-TLV (type 128) on the Update.
    let vpn_key = RouteKey {
        destination: dst,
        source: Some(SourcePrefix::new(Prefix::new_v4([10, 8, 0, 0], 14))),
        router_id: [2; 8],
    };

    table.insert(BabelRoute {
        key: plain_key,
        seqno: 1,
        metric: 200,
        next_hop: IpAddr::V4([192, 0, 2, 1]),
        feasible: true,
        installed: false,
    });
    table.insert(BabelRoute {
        key: vpn_key,
        seqno: 1,
        metric: 100,
        next_hop: IpAddr::V4([198, 51, 100, 1]),
        feasible: true,
        installed: false,
    });

    // Feasibility and best-route selection treat the two entries as
    // distinct routes: each (destination, source) pair picks its own
    // winner, so the VPN path serves VPN-sourced traffic at metric 100
    // while everything else rides the uplink.
    assert_eq!(table.len(), 2);
}
```

## Wire form and daemon support

On the wire the source prefix rides as the Source Prefix sub-TLV
(type 128, RFC 9079 §4) inside Babel Update TLVs — the codec in
`lr-babel::tlv` parses and emits it, and `lr-babel::route` tracks
feasibility per `(destination, source)` tuple exactly as above. The
daemon's Babel transport carries the same table: source-specific
entries land in the Loc-RIB alongside plain routes and are visible in
the runtime API (`routes`) with their prefix.

## Kernel caveat

Installing a source-specific route into the Linux FIB means
`ip route add <dst> from <source> ...` — a policy-route shape the
plain `RTM_NEWROUTE` mirror does not emit today. Source-specific
routes therefore participate in the Loc-RIB and best-path selection,
while the kernel mirror is the same future-work item noted in
`STATUS.md` for the Babel daemon row; embedders with policy-routing
needs program those entries through their own FIB layer (the OS
integration point in `docs/OS-INTEGRATION.md` is the seam).
