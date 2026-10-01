# IX route server

An Internet exchange route server peers with many clients over one
shared segment and re-advertises their routes without changing
`AS_PATH` or `NEXT_HOP`, so each client forwards straight to the
originator. This page shows the per-client configuration and the
community rewriting an IX usually wants. Read it if you are embedding a
route server.

## Topology

```text
   client A AS64512 ---+
                       |
   client B AS64513 ---+--- route server AS64500
                       |
   client C AS64514 ---+
```

## Wiring

```rust
// Cargo.toml:
// [dependencies]
// lr-bgp = "<version>"
// lr-core = "<version>"

use lr_bgp::role::RouteServerConfig;
use lr_bgp::{BgpPeer, PeerConfig};
use lr_core::addr::{Asn, RouterId};

/// One RS client. Every client gets its own session.
fn rs_client(peer_as: u32) -> BgpPeer {
    let mut cfg = PeerConfig::new(
        Asn(64500),
        Asn(peer_as),
        RouterId::from_v4([10, 0, 0, 1]),
    );
    cfg.route_server = RouteServerConfig::new_client();
    BgpPeer::new(cfg)
}

fn main() {
    let _a = rs_client(64512);
    let _b = rs_client(64513);
    let _c = rs_client(64514);
}
```

`RouteServerConfig::new_client` sets `client = true`. With `client` set,
`BgpPeer::advertise` skips the AS_PATH prepend and the NEXT_HOP rewrite
for that session (RFC 7947 §2.3.4), so a client sees the originator's own
path and next hop rather than one through the route server.

`client` is the only field with an effect. The optional
`inbound_policy`, `outbound_policy`, `strip_communities` and
`add_communities` fields are carried in the struct but no code path reads
them.

## Per-client community rewriting

IXes usually tag inbound routes with the source peer, then filter
outbound on those tags. Do that with an export hook, which sees the route
body:

```rust
use lr_core::rib::Route;
use lr_policy::{ExportHook, HookChain, HookVerdict};

/// Strip IX-internal communities before the route leaves to a client.
struct StripIxCommunities;

impl ExportHook for StripIxCommunities {
    fn on_export(&self, _route: &mut Route) -> HookVerdict {
        // Remove the IX's own community values here.
        HookVerdict::Keep
    }
}

fn install(chain: &mut HookChain) {
    chain.export.push(Box::new(StripIxCommunities));
}
```

Return `HookVerdict::Drop` to withhold the route from that client, or
`HookVerdict::Replace(route)` to send a modified copy. Per-client
dispatch uses `on_export_to(&mut route, destination)`, where
`destination` is the session handle.

## Check

After the sessions come up, the server's Loc-RIB holds every client's
routes and each client's Adj-RIB-Out holds the routes that survived its
policy:

```sh
lrctl --socket /run/lr-daemon.api sessions
lrctl --socket /run/lr-daemon.api routes show 203.0.113.0/24
```

`lrctl sessions` prints one line per client with `state=` and
`adj-rib-in=`; a client at `state=Established` with a non-zero
`adj-rib-in` has delivered routes.

## Reference

- RFC 7947 — Internet Exchange BGP Route Server
- RFC 1997 — BGP Communities Attribute
- [`bgp_route_reflector.md`](bgp_route_reflector.md) — iBGP instead of a
  shared segment
