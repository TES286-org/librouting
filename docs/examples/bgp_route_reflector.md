# iBGP route reflection in one cluster

A route reflector is an iBGP speaker that re-advertises routes learned
from one client to its other clients, so the cluster does not need a
full iBGP mesh. librouting has no daemon knob for it; this page shows the
`PeerConfig` fields an embedder sets. Read it if you are wiring iBGP
into your own event loop.

## Topology

```text
              RR1 (reflector, cluster 10.0.0.1)
             /                              \
      RR2 (client)                      PE1 (client)
```

`RR1` reflects; `RR2` and `PE1` only peer with `RR1`.

## Wiring

```rust
// Cargo.toml:
// [dependencies]
// lr-bgp = "<version>"
// lr-core = "<version>"

use lr_bgp::role::{ClusterId, RouteReflectorConfig};
use lr_bgp::{BgpPeer, BgpEvent, PeerConfig};
use lr_core::addr::{Asn, RouterId};

/// One session. `client` marks the peer as an RFC 4456 client of ours.
fn peer(peer_id: [u8; 4], client: bool) -> BgpPeer {
    let mut cfg =
        PeerConfig::new(Asn(64512), Asn(64512), RouterId::from_v4(peer_id));
    cfg.route_reflector_client = client;
    cfg.route_reflector = RouteReflectorConfig {
        cluster_id: ClusterId::from_v4([10, 0, 0, 1]),
        enabled: true,
    };
    BgpPeer::new(cfg)
}

fn main() {
    // The reflector itself is not its own client.
    let mut rr = peer([10, 0, 0, 1], false);
    let _client_a = peer([10, 0, 0, 2], true);
    let _client_b = peer([10, 0, 0, 3], true);

    rr.step(BgpEvent::ManualStart);
    rr.step(BgpEvent::TransportOpen);
    let open = rr.drain_outgoing();
    assert!(!open.is_empty(), "the OPEN is queued in OpenSent");
}
```

`cluster_id` is left at 0 to fall back to the local BGP identifier;
`RouteReflectorConfig::effective_cluster_id` does that fallback. Set
`route_reflector_client` only on the sessions where the peer is your
client: the reflection attributes are keyed off it. The
`RouteReflectorConfig::enabled` field is not read by any code path.

## What the reflector adds

`BgpPeer::advertise` (in `lr-bgp::advertise`) stamps two optional
non-transitive attributes on every route it sends to an
`route_reflector_client` peer, per RFC 4456 §3:

1. `ORIGINATOR_ID` — the local BGP identifier, added only when the route
   does not carry one already.
2. `CLUSTER_LIST` — the effective cluster id prepended to the existing
   list.

`lr_bgp::role::cluster::cluster_list_has_loop` returns true when a
received `CLUSTER_LIST` already contains the local cluster id, which is
the RFC 4456 §10 loop condition; drop the route when it does.

## Check

Take a capture of the reflected UPDATE and confirm both attributes are
present; they are optional and non-transitive, so they appear only on
routes that came through the reflector:

```sh
sudo tcpdump -i eth0 -w rr.pcap 'tcp port 179'
```

The behaviour is pinned by the route-reflector tests in
`crates/lr-bgp/src/advertise.rs`.

## Reference

- RFC 4456 — BGP Route Reflection
- [`bgp_roles_otc.md`](bgp_roles_otc.md) — the OTC attribute on the same
  egress path
