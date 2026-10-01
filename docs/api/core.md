# Core primitives (`lr-core`)

Read this page if you are writing a codec, an FSM host or a RIB consumer
against `lr-core`; it is the layer every protocol crate in the workspace
shares.

## Example

Addresses, the `Prefix` / `Asn` / `RouterId` primitives:

```rust
use lr_core::addr::{Asn, IpAddr, IpNet, Prefix, RouterId};

let prefix: Prefix = "203.0.113.0/24".parse().unwrap();
let asn: Asn = "AS64512".parse().unwrap();          // "AS" prefix optional
let rid = RouterId::from_v4([10, 0, 0, 1]);
let host = IpAddr::V4([192, 0, 2, 1]);
let net = IpNet::new(prefix);

assert_eq!(asn.as_u32(), 64512);
assert!(prefix.contains(&host));
assert_eq!(Prefix::new_v4([203, 0, 113, 0], 24), prefix);
assert_eq!(net.prefix(), prefix);
```

`lr_core::prelude` re-exports the common set (`Asn`, `IpAddr`, `IpNet`,
`Prefix`, `RouterId`, `ReadBuf`, `WriteBuf`, `Codec`, `Decoder`,
`Encoder`, `ParseError`, `EncodeError`, `Route`, `RouteKey`,
`RouteOrigin`, `Clock`, `Duration`, `Instant`, `TimerQueue`).

The codec traits. The encoder is stateless; the decoder is stateful and
owns its partial-frame carryover (see
[`README.md`](README.md#one-codec-per-session)):

```rust
use lr_core::buf::{ReadBuf, WriteBuf};
use lr_core::codec::{Codec, Decoder, Encoder};
use lr_core::error::{EncodeError, ParseError};

pub trait Encoder<M> {
    fn encode(&self, msg: &M, out: &mut WriteBuf<'_>) -> Result<usize, EncodeError>;
}
pub trait Decoder<M> {
    fn decode(&mut self, src: &mut ReadBuf<'_>) -> Result<Option<M>, ParseError>;
}
pub trait Codec<M>: Encoder<M> + Decoder<M> {}
```

`WriteBuf::new(&mut [u8])` and `ReadBuf::new(&[u8])` are slice-backed, so
the codecs never touch `std::io` and never allocate on the decode path.

The generic FSM. `BgpPeer` and `OspfNeighbor` implement it; a host may
also drive a custom machine through the same dispatch loop:

```rust
use lr_core::fsm::{Action, StateMachine};

pub trait StateMachine {
    type State: Copy + Eq + core::fmt::Debug;
    type Event;
    fn state(&self) -> Self::State;
    fn step(&mut self, event: Self::Event) -> Vec<Action>;
    fn reset(&mut self);
}
```

The embedder arms what the FSM asked for:

```rust
use lr_core::fsm::{Action, TimerId, TimerSpec};
use lr_core::time::Instant;
use lr_core::timer::TimerQueue;

let now = Instant::from_millis(0);
let mut timers = TimerQueue::new();
let actions: Vec<Action> = vec![Action::SetTimer(TimerId(1), TimerSpec::once(5_000))];
for action in actions {
    if let Action::SetTimer(id, spec) = action {
        timers.arm(now, id, spec);
    }
}
```

The timer queue is a logical wheel — no wall clock, no threads:

```rust
use lr_core::fsm::{TimerId, TimerSpec};
use lr_core::time::Instant;
use lr_core::timer::TimerQueue;

let mut q = TimerQueue::new();
q.arm(
    Instant::from_millis(1_000),
    TimerId(1),
    TimerSpec::periodic(1_000, 1_000),
);
let fired: Vec<TimerId> = q.tick(Instant::from_millis(1_000));
assert_eq!(fired, vec![TimerId(1)]);
```

A route, and the minimal fields a protocol runtime must fill in:

```rust
use lr_core::addr::{IpAddr, Prefix};
use lr_core::attr::Attributes;
use lr_core::nlri::NlriFamily;
use lr_core::rib::{Preference, Protocol, Route, RouteKey, RouteOrigin};

let key = RouteKey::new(
    Prefix::new_v4([203, 0, 113, 0], 24),
    NlriFamily::IPV4_UNICAST,
);
let route = Route {
    key,
    origin: RouteOrigin { proto: 0, peer: 0 },
    protocol: Protocol::Bgp,
    preference: Preference { admin_distance: 20, metric: 0 },
    next_hop: Some(IpAddr::V4([192, 0, 2, 1])),
    attributes: Attributes::new(),
    age_ms: 0,
    path_id: 0, // RFC 7911 path identifier; 0 = none
    tag: None,
};
```

## Configuration surface

`lr-core` has no configuration of its own. What it does have is the
feature that decides whether `std` is linked, and the type vocabulary
that the other crates configure:

| Item | Notes |
| --- | --- |
| `std` feature | On by default; off gives `no_std` plus `alloc` |
| `Prefix` | `addr` (an `IpAddr`) + `prefix_len`; host bits are not normalized |
| `Asn` | Always 4-byte in memory; `as_u16()` is `None` above `0xffff` |
| `RouteKey` | `prefix` + `family` + optional source-specific `source` |
| `RouteOrigin` | `proto` (numeric) + `peer` (the session it came from) |
| `Preference` | `admin_distance` + `metric`; the RIB compares these first |
| `ErrorKind` | `Truncated` is the "need more bytes" signal, not a failure |
| `TimerQueue` | Logical; the embedder supplies `Instant` to `arm`/`tick` |

`Protocol::default_admin_distance()` and `Protocol::bird_name()` give the
per-protocol defaults that `lr-rib` and the daemon both read.

## RFCs

- `Asn` — RFC 4893 two-octet AS space on the wire, RFC 6793 4-byte AS,
  RFC 6996 private-ASN ranges.
- `RouterId` — RFC 4271 §4.2, the BGP Identifier.
- `NlriFamily { afi, safi }` — RFC 4760.
- `Route::path_id` — RFC 7911 Add-Path.
- `Route::tag` — RFC 4271 §9.1.2 attribute space, RFC 2328 §A.4.5 and
  RFC 3101 §2.3 for the OSPF external route tag.
- `Action`/`StateMachine` are a host vocabulary with no RFC behind them;
  each protocol crate maps its own FSM onto them.

## See also

- [`README.md`](README.md) — error, thread-safety and `no_std` rules.
- [`bgp.md`](bgp.md) — `BgpPeer`, the largest `StateMachine`.
- [`router.md`](router.md) — how the RIB types are wired together.
- [`../ARCHITECTURE.md`](../ARCHITECTURE.md) — the pipeline in pictures.
