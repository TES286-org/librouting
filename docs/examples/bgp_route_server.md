# Example: IX Route Server (RFC 7947)

At an Internet Exchange (IX), participants peer with a single route server
over a shared broadcast domain. The RS is *transparent*: it forwards routes
between clients without modifying AS_PATH or NEXT_HOP (so each client can
route directly to the original originator without transiting the RS).

```
                  +-------------+
        +--------->| RS          |<---------+
        |          | (route srv) |          |
        |          +-------------+          |
        |                  ^                |
        |                  |                |
   +----+-----+      +----+-----+      +----+-----+
   | client A |      | client B |      | client C |
   | AS 64512 |      | AS 64513 |      | AS 64514 |
   +----------+      +----------+      +----------+
```

```rust
// Cargo.toml:
// [dependencies]
// lr-bgp = "0.1"
// lr-policy = "0.1"

use lr_bgp::{BgpPeer, PeerConfig};
use lr_bgp::role::RouteServerConfig;
use lr_core::addr::{Asn, RouterId};

fn make_rs_client(peer_as: u32) -> BgpPeer {
    let mut cfg = PeerConfig::new(Asn(64512), Asn(peer_as), RouterId::from_v4([10,0,0,1]));
    cfg.route_server = RouteServerConfig::new_client();
    BgpPeer::new(cfg)
}

fn main() {
    let _peer_a = make_rs_client(64512);
    let _peer_b = make_rs_client(64513);
    let _peer_c = make_rs_client(64514);
    // Each peer has its own per-client policy chain; the RS re-exports
    // routes between them without modifying AS_PATH/NEXT_HOP.
}
```

## Community rewriting

IXes typically attach "inbound" communities to identify the source peer:

- Route from client A → community `64512:1`
- Route from client B → community `64512:2`

Then per-client "outbound" filters say "only export `64512:1` to client B
unless B explicitly opts in". This is implemented via:

```rust
use lr_policy::{HookChain, ExportHook, HookVerdict};
use lr_core::rib::Route;

struct IxCommunityRewriter;
impl ExportHook for IxCommunityRewriter {
    fn on_export(&self, r: &mut Route) -> HookVerdict {
        // Strip IX-internal communities, replace with per-client OUT
        // communities.
        HookVerdict::Keep
    }
}

let mut chain = HookChain::new();
chain.export.push(Box::new(IxCommunityRewriter));
```
