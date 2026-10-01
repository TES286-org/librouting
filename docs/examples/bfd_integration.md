# BFD-driven fast failure detection

BGP notices a dead peer only when the hold timer expires — 90 s at the
default `hold_time 90s` — and it never notices a broken forwarding path
while the TCP session stays alive. BFD closes both gaps. This page
configures the daemon's BFD fast-fail and shows the library session an
embedder drives directly.

## Timing

Detection time is the peer's detection multiplier times
`max(required_min_rx_interval, the peer's desired_min_tx_interval)`
(RFC 5880 §6.8.4). With `detect_mult 3` and 50 ms intervals that is
150 ms, roughly 600× faster than a 90 s BGP hold timer. The daemon's
defaults are `bfd_min_tx_ms 100`, `bfd_min_rx_ms 100` and
`bfd_multiplier 3`, so detection is about 300 ms out of the box.

While the session is not Up the transmit interval is floored at one
second (RFC 5880 §6.8.3). Interval changes while Up are confirmed with a
Poll/Final sequence (§6.5).

## Configuration

```lr
protocol bgp;

bgp {
    local_as 64512;
    peer_as 64513;
    router_id "10.0.0.1";
    peer_addr "192.0.2.2:179";
    local_address "192.0.2.1";

    bfd true;                # one BFD session per peer that enables it
    bfd_multihop false;      # RFC 5883 multihop: UDP 4784, no TTL check
    bfd_min_tx_ms 100ms;     # DesiredMinTxInterval
    bfd_min_rx_ms 100ms;     # RequiredMinRxInterval
    bfd_multiplier 3;        # missed packets before Down
}
```

A peer block can override any of these:

```lr
peer "core-1" {
    remote "192.0.2.2:179";
    peer_as 64513;
    bfd true;
    bfd_multihop true;
}
```

The same knobs on the command line, for the legacy single-peer form:

```sh
lr-daemon --local-as 64512 --peer-as 64513 --router-id 10.0.0.1 \
    --peer 192.0.2.2:179 --local-address 192.0.2.1 \
    --bfd --bfd-min-tx-ms 100 --bfd-min-rx-ms 100 --bfd-multiplier 3
```

BFD needs a `local_address`: the session sockets bind it. Single-hop BFD
uses UDP 3784 (RFC 5881); multihop uses 4784 (RFC 5883).

## What the daemon does

1. Logs `daemon: bfd: listening on <addr> (single-hop)` once per address
   family and mode, then one session per peer.
2. Logs every state change as
   `daemon: bfd: peer <label>: Down -> Up (<diag>)`.
3. On `BfdSessionEvent::Timeout` logs
   `daemon: bfd: peer <label>: detection time expired`, closes the
   transport, and purges the routes that session contributed
   (RFC 4271 §8.2.2), instead of waiting out the hold timer.
4. Holds off reconnecting while BFD is down (after it has been up at
   least once), so a dead path is not connect-stormed.

## Verify

Startup confirms the timing that was actually configured:

```text
daemon: bfd: 1 session(s), min tx 100 ms, min rx 100 ms, multiplier 3
daemon: bfd: listening on 192.0.2.1:3784 (single-hop)
```

Then watch a live session:

```sh
lrctl --socket /run/lr-daemon.api sessions
sudo tcpdump -i eth0 -n 'udp port 3784'
```

`lrctl sessions` shows `state=Established`. Break the path under the
session — drop the peer's traffic at the firewall, or freeze the daemon
with `SIGSTOP` and keep its TCP socket open — and the session drops
within about `detect_mult × interval`, not 90 s. BFD Control packets at
the negotiated interval confirm the session is live in the capture.

## Driving the session yourself

`BfdSession` is I/O free, like the protocol engines:

```rust
// Cargo.toml:
// [dependencies]
// lr-bfd = "<version>"
// lr-core = "<version>"

use lr_bfd::{BfdConfig, BfdSession, BfdSessionEvent, SessionRole};
use lr_core::time::Instant;

fn main() {
    let cfg = BfdConfig {
        detect_mult: 3,
        desired_min_tx_interval: 50_000,  // 50 ms
        required_min_rx_interval: 50_000, // 50 ms
        // Single-hop BFD (RFC 5881 §3) requires both sides to be Active.
        role: SessionRole::Active,
        ..Default::default()
    };
    let mut bfd = BfdSession::new(cfg, 0x11111111);
    let _ = bfd.start(Instant::from_millis(0));

    // Per pump round: tick, send drain_outgoing(), and feed every
    // received datagram with the arrival time so the detection timer
    // anchors to packet arrival.
    let now = Instant::from_millis(10);
    let events = bfd.tick(now);
    let _out = bfd.drain_outgoing();
    // let events = bfd.feed_bytes(now, &datagram);

    if events.iter().any(|e| matches!(e, BfdSessionEvent::Timeout)) {
        // Detection time expired: the session is already Down.
    }
}
```

`BfdSessionEvent::Timeout` means the detection time expired and the
session is already Down. Tear down the transport that rides on it; for
BGP that is the TCP connection, which raises `BgpEvent::TransportClose`.
`lr_osroute::bfd_transport` provides the socket model: one shared receive
socket on the well-known port plus one transmit socket per session with
an ephemeral source port (RFC 5881 §4).

## Reference

- RFC 5880 — Bidirectional Forwarding Detection
- RFC 5881 §3, §4 — single-hop BFD
- RFC 5883 — BFD for multihop paths
- [`../INTEROP.md`](../INTEROP.md) — the BIRD BFD lab
