# Example: BFD integration for sub-second BGP failure detection

Without BFD, BGP peers take `hold_time` (default 90s) to detect a forwarding
failure. BFD brings detection down to milliseconds — useful at IXes or for
high-availability CE/PE links.

```rust
// Cargo.toml:
// [dependencies]
// lr-bgp = "0.1"
// lr-bfd = "0.1"

use lr_bgp::{BgpPeer, BgpEvent, PeerConfig};
use lr_bfd::{BfdConfig, BfdSession, SessionRole};
use lr_core::addr::{Asn, RouterId};
use lr_core::time::Instant;

fn main() {
    // 1. Start a BGP session.
    let mut bgp = BgpPeer::new(PeerConfig::new(
        Asn(64512), Asn(64513), RouterId::from_v4([10,0,0,1]),
    ));
    bgp.step(BgpEvent::ManualStart);
    bgp.step(BgpEvent::TransportOpen);

    // 2. Start a BFD session with aggressive timing.
    let cfg = BfdConfig {
        detect_mult: 3,
        desired_min_tx_interval: 50_000,  // 50ms
        required_min_rx_interval: 50_000, // 50ms
        role: SessionRole::Active,
        ..Default::default()
    };
    let mut bfd = BfdSession::new(cfg, 0x11111111);
    let _evs = bfd.start(Instant(0));

    // 3. Pump both: BGP keepalives go over TCP; BFD control packets go
    // over UDP/3784. If BFD signals Down, the embedder tears down the
    // TCP connection, which triggers BGP's TransportClose event.
    //
    // The wiring is left to the embedder; here we just show the data flow.
    let _bgp_bytes = bgp.drain_outgoing();
    let _bfd_bytes = bfd.drain_outgoing();

    // 4. Periodically call `bfd.tick(now)` and dispatch events. If
    // `BfdSessionEvent::Timeout` fires, tear down TCP.
}
```

## Detection time

Detection time = `detect_mult * max(required_min_rx_interval,
peer's desired_min_tx_interval)`. With `detect_mult=3` and 50ms
intervals, detection time is 150ms — three orders of magnitude faster
than BGP-only keepalives.
