# Router API (`lr-router`)

Read this page if you are embedding the whole pipeline: sessions, the
event loop, cross-protocol redistribution, the OS route table and
runtime introspection.

No extra feature is needed; `labeled_unicast` is on by default and
`exchange-plane` is opt-in. The OS route-table backends need `std` and
the platform's routing API at run time.

## Example

`DefaultRouter` is poll-based: the embedder drives time with `tick`,
pushes inbound bytes with `feed_input`, pulls outbound bytes with
`drain_output` and drains events with `poll_events`.

```rust
use lr_core::addr::{Asn, RouterId};
use lr_core::time::Instant;
use lr_router::{DefaultRouter, RouterInstance, SessionConfig};

let mut r = DefaultRouter::new();
let h = r.add_session(SessionConfig::bgp(
    Asn(64512),
    Asn(64513),
    RouterId::from_v4([10, 0, 0, 1]),
))?;

// RFC 4271 MRAI defaults: 30 s for eBGP, 5 s for iBGP. Zero sends at once.
r.set_mrai(h, 10_000)?;
r.start_session(h)?;

r.feed_input(h, &inbound)?;
let out = r.drain_output(h);          // hand this to the socket
let events = r.poll_events();         // RouteInstalled, PeerStateChange, ...
r.tick(Instant::from_millis(1_000));  // timers, MRAI flush, LSA ageing
```

Every mutating call takes `&mut self`, so one thread drives the router.
`tick` is not optional: MRAI flush, graceful-restart expiry, OSPF LSA
refresh and MaxAge removal, and Babel garbage collection all happen
there. `close_session` and `shutdown_session` end a session gracefully;
`remove_session` drops it. `requeue_events` puts events back if a consumer
must stop early — the daemon uses it when a downstream channel is full.

Cross-protocol redistribution (BIRD `pipe`, FRR `redistribute`) bridges
routes from a source protocol into a target one:

```rust
use lr_core::addr::Prefix;
use lr_core::rib::Protocol;
use lr_router::{DefaultRouter, MetricPolicy, RedistributionPipe};

let mut r = DefaultRouter::new();

// BGP -> OSPFv2 with a fixed metric.
r.add_redistribution_pipe(
    RedistributionPipe::new(Protocol::Bgp, Protocol::Ospfv2)
        .with_metric(MetricPolicy::Fixed(100)),
);

// OSPFv2 -> BGP, inheriting the source metric.
r.add_redistribution_pipe(RedistributionPipe::new(Protocol::Ospfv2, Protocol::Bgp));

// BGP -> BGP, restricted to specific prefixes.
r.add_redistribution_pipe(
    RedistributionPipe::new(Protocol::Bgp, Protocol::Bgp)
        .with_allow_prefixes(vec![Prefix::new_v4([203, 0, 113, 0], 24)]),
);

// Removes every pipe with that source/target pair; returns how many.
let removed = r.remove_redistribution_pipe(Protocol::Ospfv2, Protocol::Bgp);
```

A pipe re-originates a route into the target when the route enters the
Loc-RIB from the source, and propagates withdrawals automatically.

The OS route table is behind one trait, with a per-platform
implementation:

```rust
use lr_core::addr::{IpAddr, Prefix};
use lr_osroute::{OsRouteTable, RtNetlink};

let mut rt = RtNetlink::connect()?; // the platform's backend
let prefix: Prefix = "203.0.113.0/24".parse().unwrap();
let gw: IpAddr = "198.51.100.1".parse().unwrap();
rt.add_route(prefix, gw, 2)?; // prefix, next hop, interface index
rt.delete_route(prefix)?;
let present = rt.has_route(prefix)?;
```

`RtNetlink` is an alias for the platform backend: the rtnetlink socket
on Linux, the routing socket on BSD, the IP Helper API on Windows and a
stub elsewhere. `add_route_tagged` carries the originating protocol's
tag where the kernel supports one, and `add_blackhole_route` installs a
discard route (BIRD `blackhole`, FRR `Null0`).

Runtime introspection:

```rust
for s in r.session_summaries() {
    // handle, kind, local_as/peer_as, state, established, peer_bgp_id,
    // negotiated_hold_time, adj_rib_in_len, updates_received/sent
    println!("#{} {} state={} established={}", s.handle.0, s.kind, s.state, s.established);
}

let loc_rib: Vec<lr_core::rib::Route> = r.rib_snapshot();
let paths: Vec<lr_core::rib::Route> = r.rib_paths_snapshot(); // Add-Path
```

`session_summaries` is the data plane behind the daemon's `sessions`
command and the FFI's `lr_router_sessions_dump`; `rib_snapshot` backs
the route dumps. Both are read-only views — the snapshots are owned
copies cloned out of the Loc-RIB's per-family shard locks, so a caller
never holds a borrow of router internals. For the same reason the
router hands out the RIB itself:

```rust
let rib: std::sync::Arc<lr_rib::LocRib> = r.rib_handle();
// Reads take the per-family shard locks, never the router's RwLock.
for route in rib.iter_best() {
    // …
}
```

Embedders running the RIB next to a busy writer share the handle the
same way the daemon's runtime API and metrics endpoint do — an IPv6
walk never waits for an IPv4 writer.

## Event bus

Read this section if you drain `poll_events` on one thread and apply
the events somewhere slower — the kernel FIB, a BMP collector, a
scraper. `lr_router::EventBus` is a bounded broadcast channel for
`RouterEvent`: the draining thread publishes, every consumer that
subscribed before the publish receives its own copy on its own
thread.

```rust
use lr_router::{EventBus, RouterEvent};
use std::time::Duration;

let bus = EventBus::new();          // 1024 events per subscriber
let rx = bus.subscribe();           // one handle per consumer thread

// Publisher side (the thread that owns the router):
let accepted = bus.publish(RouterEvent::RouteInstalled(route));
// `accepted` counts the subscribers whose queue had room; a full
// subscriber drops the event rather than blocking the publisher.

// Consumer side:
match rx.recv_timeout(Duration::from_millis(50)) {
    Ok(ev) => apply(ev),            // events arrive in publish order
    Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
    Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => return,
}
```

The contract:

- `EventSubscriber::try_recv` and `recv_timeout` mirror
  `std::sync::mpsc::Receiver`'s API (the same `TryRecvError` /
  `RecvTimeoutError` types).
- `close` is the shutdown handshake: after the last publish, `close`
  refuses further publishes and every subscriber drains its queue,
  then observes `Disconnected` — joining the subscriber threads
  guarantees every accepted event was applied.
- `dropped_total` counts publishes that dropped on at least one
  subscriber; a non-zero rate means a consumer is stuck.
  `published_total` counts every publish call.

Each subscriber's queue is a lock-free MPMC ring
(`lr_router::event_bus::ring`): the publisher walks the subscriber
list under a shared read lock and pushes through a CAS retry loop,
so publishing never blocks on a consumer. The daemon's own wiring —
the ticker that publishes and the kernel-mirror thread that
subscribes — is described in
[`../ARCHITECTURE.md`](../ARCHITECTURE.md).

## Configuration

| Item | Default | Effect |
| --- | --- | --- |
| `SessionConfig` | required | Kind plus the per-protocol knobs (see [`bgp.md`](bgp.md)) |
| `set_mrai(h, ms)` | 30 s eBGP / 5 s iBGP | Per-session advertisement batching |
| `MetricPolicy::Inherit` | yes | Keep the source metric |
| `MetricPolicy::Fixed(n)` | — | Advertise exactly `n` |
| `MetricPolicy::Add(n)` | — | Add `n`, saturating at `u32::MAX` |
| `RedistributionPipe::with_tag(n)` | 0 | Protocol tag carried through |
| `RedistributionPipe::with_allow_prefixes(v)` | all | `Prefix` allow list |
| `add_blackhole_route(prefix)` | — | Kernel discard route |
| `RouterEvent::Log(String)` | — | Diagnostics surface, including policy rejections |

`RouterEvent` also carries `PeerStateChange`, `RouteInstalled`,
`RouteWithdrawn`, `SendBytes`, `TimerFired`, `ProtocolError`,
`PrefixAdvertised`, `PrefixRetracted`, `MaxPrefixThreshold` and
`MaxPrefixExceeded`.

## RFCs

- RFC 4271 §9.2.1.1 — MRAI, the reason `set_mrai` exists.
- RFC 2328 §14 — OSPF LSA refresh and MaxAge, driven from `tick`.
- RFC 4724 — graceful-restart expiry, also on the `tick` path.
- RFC 2439 §4.2 — the damping decay a ticker must drive (see
  [`policy.md`](policy.md)).
- Redistribution itself is a BIRD/FRR concept rather than a wire
  protocol; there is no RFC for the pipe.

## See also

- [`README.md`](README.md) — `RouterInstance` versus `DefaultRouter`,
  error and thread-safety rules.
- [`bgp.md`](bgp.md), [`ospf.md`](ospf.md), [`babel.md`](babel.md) —
  the per-protocol knobs `SessionConfig` carries.
- [`policy.md`](policy.md) — `hooks_mut` and `set_safety_net`.
- [`../lr-cli.md`](../lr-cli.md) — the daemon built on this API.
