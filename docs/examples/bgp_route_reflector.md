# Example: iBGP route reflector cluster (RFC 4456)

This example wires three BGP speakers in a route-reflection topology:

```
            +-----------+
            |  RR1      |
            |  (client) |
            +-----+-----+
                  |
       +----------+----------+
       |                     |
       v                     v
   +-------+               +-------+
   |  RR2  |               |  PE1  |
   |client |               |client |
   +-------+               +-------+
```

```rust
// Cargo.toml:
// [dependencies]
// lr-bgp = "1.0.0-rc.4"
// lr-router = "1.0.0-rc.4"

use lr_bgp::{BgpPeer, BgpEvent, PeerConfig, fsm::BgpState};
use lr_bgp::role::{ClusterId, RouteReflectorConfig};
use lr_core::addr::{Asn, RouterId};

fn make_rr_client() -> BgpPeer {
    let mut cfg = PeerConfig::new(Asn(64512), Asn(64512), RouterId::from_v4([10,0,0,1]));
    cfg.route_reflector_client = true;
    cfg.route_reflector = RouteReflectorConfig {
        cluster_id: ClusterId::from_v4([10, 0, 0, 1]),
        enabled: true,
    };
    BgpPeer::new(cfg)
}

fn make_rr_server() -> BgpPeer {
    let mut cfg = PeerConfig::new(Asn(64512), Asn(64512), RouterId::from_v4([10,0,0,2]));
    cfg.route_reflector = RouteReflectorConfig {
        cluster_id: ClusterId::from_v4([10, 0, 0, 2]),
        enabled: true,
    };
    BgpPeer::new(cfg)
}

fn main() {
    let mut rr = make_rr_server();
    let _client = make_rr_client();
    // Establish: rr.step(ManualStart) → rr.step(TransportOpen) → exchange
    // OPEN+KEEPALIVE → rr goes Established.
    rr.step(BgpEvent::ManualStart);
    rr.step(BgpEvent::TransportOpen);
    let open_bytes = rr.drain_outgoing();
    println!("RR sent {} bytes (OPEN)", open_bytes.len());
}
```

## Verification

When a route arrives from `client`, `rr` advertises it to other RR clients
by:

1. Setting ORIGINATOR_ID = `rr.bgp_id` (if not already set).
2. Prepending `rr.cluster_id` to CLUSTER_LIST.
3. Re-exporting to all other RR clients.

The receiving client must reject the route if its own cluster_id is in
CLUSTER_LIST (RFC 4456 §10 loop detection). See
`lr-bgp::role::cluster::cluster_list_has_loop`.
