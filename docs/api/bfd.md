# BFD API (`lr-bfd`, `lr-osroute`)

Read this page if you are running BFD sessions: the codec and session
FSM live in `lr-bfd`, and the sockets that carry the datagrams live in
`lr-osroute::bfd_transport`.

No extra feature is needed. The socket helpers need `std` and a real
UDP stack, so they are not usable under `no_std`.

## Example

`BfdSession` owns its codec, state, timers and outbound buffer. The
embedder supplies the clock: pass the current `Instant` to every call,
including `feed_bytes`, so the detection timer anchors to packet
arrival rather than to a polling interval.

```rust
use lr_bfd::{BfdConfig, BfdSession, SessionRole};
use lr_core::time::Instant;

let cfg = BfdConfig {
    detect_mult: 3,
    desired_min_tx_interval: 100_000,   // microseconds
    required_min_rx_interval: 100_000,
    role: SessionRole::Active,          // RFC 5881 §3: both sides Active
    ..Default::default()
};
let mut session = BfdSession::new(cfg, 0x1111_1111); // our discriminator
let _ = session.start(Instant(0));

// Inbound datagram: the codec applies the §6.8.6 MUST-discard rules and
// drives the §6.8.6 state machine (Down+Init -> Up, Init+Init -> Up).
let events = session.feed_bytes(Instant::from_millis(120), &datagram);
let outbound = session.drain_outgoing();

// Every tick: periodic transmit plus detection expiry.
let events = session.tick(Instant::from_millis(200));

// Change the intervals while Up: Poll/Final confirmation (§6.5).
let events = session.update_timers(Instant::from_millis(200), 200_000, 200_000);
```

`feed_bytes` and `tick` return `Vec<BfdSessionEvent>`:
`StateChanged { from, to, diag }`, `PeerDiagnostic`, `Timeout`,
`AuthFailed` and `OutboundQueued`. `drain_outgoing` returns the bytes
that are ready; after `OutboundQueued` there is always something to
drain.

The intervals follow RFC 5880: the detection time is the peer's detect
multiplier times `max(required rx, peer desired tx)` (§6.8.4); the
transmit interval is `max(desired tx, peer required rx)` (§6.8.7)
jittered down by 0-25% and floored at one second while the session is
not Up (§6.8.3). `tx_interval_us()` exposes the current value for
diagnostics. An interval change while Up goes through Poll/Final
confirmation via `update_timers(now, desired_tx_us, required_rx_us)`.

The sockets. One shared receive socket demultiplexes every session by
the Your Discriminator in the packet; each session transmits from its
own ephemeral port:

```rust
use lr_core::addr::IpAddr;
use lr_osroute::bfd_transport::{BfdMode, BfdRxSocket, BfdTxSocket};

let rx = BfdRxSocket::bind(Some(local), BfdMode::SingleHop)?;
let tx = BfdTxSocket::bind_session(Some(local), BfdMode::SingleHop)?;
let datagram = rx.recv_from(&mut buf)?; // None when nothing is pending
```

`BfdMode::SingleHop` is port 3784 with TTL 255 on transmit and a
receive-side TTL filter (RFC 5881 §4/§5). `BfdMode::Multihop` is port
4784 with the default TTL and no receive-side check (RFC 5883 §3). The
receive socket discards a single-hop datagram whose received TTL is
below 255 before it reaches the session FSM, and returns the TTL
alongside the packet for diagnostics. `BfdTxSocket` picks a source port
from the RFC 5881 §4 range.

## Configuration

| Knob | Default | Effect |
| --- | --- | --- |
| `detect_mult` | 3 | Missed packets tolerated before the session is Down (§6.8.4) |
| `desired_min_tx_interval` | 1 000 000 µs | What we ask to transmit at |
| `required_min_rx_interval` | 1 000 000 µs | What we can receive at |
| `required_min_echo_interval` | 0 | 0 disables the echo function |
| `role` | `SessionRole::Active` | Passive waits for the peer's first packet (§6.1) |
| `auth_key` | none | RFC 5880 §4.2 authentication section |

`SessionRole::Active` sends with `your_disc = 0` until a packet carrying
our discriminator arrives. Single-hop BFD requires both sides to be
Active.

## RFCs

- RFC 5880 — the base protocol: session states (§6.1), Poll/Final (§6.5),
  timer negotiation and the transmit floor (§6.8.3), detection time
  (§6.8.4), the state machine and its MUST-discard rules (§6.8.6),
  jitter (§6.8.7), authentication (§4.2).
- RFC 5881 — single-hop BFD: the port and the requirement that both
  sides be Active (§3), the source-port range and TTL 255 (§4), the
  receive-side TTL check (§5).
- RFC 5883 — multihop BFD: port 4784, no TTL check, no echo (§3).

## See also

- [`router.md`](router.md) — event delivery and session introspection.
- [`ldp-mpls.md`](ldp-mpls.md) — the other `lr-osroute` transport in
  this documentation set.
- [`../examples/`](../examples/) — a BFD integration walkthrough.
