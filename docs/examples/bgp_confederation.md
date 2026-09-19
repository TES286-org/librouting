# Example: BGP Confederation (RFC 6793, originally RFC 3065)

A confederation is a group of sub-ASes that internally behave like eBGP
but externally appear as one AS. The local AS is announced as the
confederation's "external" AS.

```
  +------+       +------+       +------+
  | AS   |       | AS   |       | AS   |
  | 64512|<----->|64513 |<----->|64514 |  (confederation members)
  +------+  eBGP +------+  eBGP +------+
                                |
                                | eBGP to AS 100
                                v
                          +-----------+
                          |    AS100  |
                          +-----------+
```

```rust
// Cargo.toml:
// [dependencies]
// lr-bgp = "1.0.0-rc.4"

use lr_bgp::{BgpPeer, PeerConfig};
use lr_bgp::role::{ConfederationConfig, PeerRole};
use lr_core::addr::{Asn, RouterId};

fn make_confed_peer(peer_as: u32) -> BgpPeer {
    let mut cfg = PeerConfig::new(Asn(64512), Asn(peer_as), RouterId::from_v4([10,0,0,1]));
    cfg.confederation = Some(ConfederationConfig::new(vec![64512, 64513, 64514, 64515]));
    BgpPeer::new(cfg)
}

fn main() {
    // Peer is in the same confederation but a different sub-AS.
    let peer = make_confed_peer(64513);
    assert_eq!(peer.peer_role(), PeerRole::ConfederationExternal);

    // Peer outside the confederation.
    let mut cfg = PeerConfig::new(Asn(64512), Asn(100), RouterId::from_v4([10,0,0,1]));
    cfg.confederation = Some(ConfederationConfig::new(vec![64512, 64513, 64514, 64515]));
    let external_peer = BgpPeer::new(cfg);
    assert_eq!(external_peer.peer_role(), PeerRole::Ebgp);
}
```

## AS_PATH handling

Inside the confederation, AS_CONFED_SEQUENCE / AS_CONFED_SET segments are
used (see `lr-bgp::path::AsPathType::ConfedSequence` and `ConfedSet`).
When a route leaves the confederation (via an eBGP peer), all
AS_CONFED_* segments are removed from the AS_PATH.

The best-path comparator by default counts AS_CONFED_SEQUENCE in path
length (RFC 6793 §7); this is controlled by
`BestPathConfig::count_confed_in_path_len`.
