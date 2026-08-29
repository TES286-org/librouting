# Example: BFD integration for sub-second BGP failure detection

Without BFD, BGP peers take `hold_time` (default 90s) to detect a forwarding
failure. BFD brings detection down to milliseconds — useful at IXes or for
high-availability CE/PE links.

The reference daemon already wires this end-to-end: `lr-daemon --bfd`
(one BFD session per peer, UDP 3784 per RFC 5881 / 4784 per RFC 5883,
tearing the BGP session down the moment BFD goes Down). This example
shows the library-level pieces an embedder composes.

```rust
// Cargo.toml:
// [dependencies]
// lr-bgp = "0.1"
// lr-bfd = "0.1"
// lr-core = "0.1"

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

    // 2. Start a BFD session with aggressive timing. The role is
    // Active: single-hop BFD (RFC 5881 §3) requires both sides to
    // initiate with Your Discriminator 0.
    let cfg = BfdConfig {
        detect_mult: 3,
        desired_min_tx_interval: 50_000,  // 50ms
        required_min_rx_interval: 50_000, // 50ms
        role: SessionRole::Active,
        ..Default::default()
    };
    let mut bfd = BfdSession::new(cfg, 0x11111111);
    let _evs = bfd.start(Instant(0));

    // 3. Pump both. BGP keepalives go over TCP; BFD Control packets
    // go over UDP 3784 (single-hop; 4784 for multihop per RFC 5883).
    // lr_osroute::bfd_transport provides the socket model: one
    // shared receive socket on the well-known port plus one transmit
    // socket per session with an RFC 5881 §4 ephemeral source port.
    // Received datagrams are fed with the current time so the
    // detection timer anchors to packet arrival:
    //
    //   let evs = bfd.feed_bytes(now, &datagram);
    //   let out = bfd.drain_outgoing(); // -> tx socket, peer:3784
    //
    // The wiring is left to the embedder; here we just show the data flow.
    let _bgp_bytes = bgp.drain_outgoing();
    let _bfd_bytes = bfd.drain_outgoing();

    // 4. Periodically call `bfd.tick(now)` and dispatch events. When
    // `BfdSessionEvent::Timeout` fires (the detection time expired)
    // the session is already Down — tear down TCP, which triggers
    // BGP's TransportClose event. That is the whole fast-fail trick.
}
```

## Detection time

Detection time = the *peer's* `detect_mult` × `max(required_min_rx_interval,
peer's desired_min_tx_interval)` (RFC 5880 §6.8.4 — the multiplier is the
remote system's, not a negotiated minimum). With `detect_mult=3` and 50ms
intervals, detection time is 150ms — three orders of magnitude faster than
BGP-only keepalives.

While the session is not Up, the transmit interval is floored at one
second (RFC 5880 §6.8.3); interval changes while Up are confirmed with
a Poll/Final sequence (§6.5).

## What the daemon does

`lr-daemon --bfd --bfd-min-tx-ms 100 --bfd-min-rx-ms 100 --bfd-multiplier 3`
(or per-peer `bfd = true` in the TOML config, with `bfd_multihop = true`
for RFC 5883 sessions) runs one BFD session per peer and:

- tears the BGP session down (CEASE NOTIFICATION, route purge per
  RFC 4271 §8.2.2) the moment BFD goes Down;
- holds off reconnecting while BFD is down (after it has been up at
  least once), so a dead path is not connect-stormed.

`tests/interop/bfd_bird.sh` verifies both the single-hop and multihop
modes against BIRD 2 (`protocol bfd` + `bfd on`), including the
fast-fail: with the BIRD side frozen mid-session (TCP still open), the
BGP session comes down within ~0.5s at 100ms × 3 timing while the hold
timer would have waited 60s.
