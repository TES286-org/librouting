# Tutorial: from bytes to a working router

This tutorial builds a working BGP speaker in four steps, using only the
public library API. Every snippet is the same code
`crates/lr-tests/tests/tutorial_snippets.rs` runs, so the tutorial cannot
drift from the API without breaking CI.

It is aimed at a Rust developer embedding librouting in their own event
loop. If you would rather run a router than build one, read
[`lr-daemon.md`](lr-daemon.md) instead.

## Before you start

The crates are not published to a registry yet, so depend on the
repository and pin a tag or revision you have tested:

```toml
[dependencies]
lr-core = { git = "https://github.com/TES286-org/librouting.git" }
lr-bgp = { git = "https://github.com/TES286-org/librouting.git" }
lr-router = { git = "https://github.com/TES286-org/librouting.git" }
```

The library never opens a socket and never touches a routing table. You
own the bytes, the clock and the kernel; the library owns protocol
state. That split is what makes the same code run in a unit test, in a
daemon and behind a C ABI.

## Chapter 1 — the wire

`BgpCodec` turns a byte stream into `BgpMessage`s and back. Decoding is
incremental: hand it whatever the transport produced and it returns the
messages that are complete, keeping the partial tail for next time.

```rust
use lr_bgp::message::keepalive::Keepalive;
use lr_bgp::{BgpCodec, BgpMessage};

let codec = BgpCodec::new();
let bytes = codec.encode_vec(&BgpMessage::Keepalive(Keepalive)).unwrap();

// The RFC 4271 framing: a 16-byte marker of 0xFF, a 2-byte length, then
// a 1-byte type at offset 18. Type 4 is KEEPALIVE.
assert_eq!(bytes[18], 4);
```

An UPDATE carries withdrawn prefixes, path attributes and NLRI. The
attribute set is an ordered list of `(flags, type, value)` triples;
typed accessors decode one on demand, so an attribute you do not
understand costs nothing:

```rust
use lr_bgp::message::{BgpMessage, Update};
use lr_bgp::path::{AsPath, AttrType, PathAttrFlags, PathAttribute};
use lr_core::addr::{Asn, Prefix};

let update = Update::new()
    .with_nlri([Prefix::new_v4([203, 0, 113, 0], 24)])
    .with_attribute(PathAttribute::new(
        PathAttrFlags(PathAttrFlags::TRANSITIVE),
        AttrType::AsPath,
        AsPath::from_sequence([Asn(64512)]).encode_4(),
    ));

let codec = BgpCodec::new();
let bytes = codec.encode_vec(&BgpMessage::Update(update)).unwrap();

// The peer decodes the same bytes back.
let mut peer_codec = BgpCodec::new();
let msg = peer_codec.decode_slice(&bytes).unwrap().unwrap();
match msg {
    BgpMessage::Update(u) => {
        assert_eq!(u.nlri.len(), 1);
        assert_eq!(u.nlri[0].prefix, Prefix::new_v4([203, 0, 113, 0], 24));
        // The AS path comes back in canonical 4-byte form: the codec
        // merges AS4_PATH into AS_PATH when both are present.
        let path = u.attributes.as_path().unwrap();
        assert_eq!(path.as_sequence(), vec![Asn(64512)]);
    }
    _ => panic!("expected an UPDATE"),
}
```

The same round trip covers every family. MP-BGP NLRI rides in the
`MpReachNlri` and `MpUnreachNlri` attributes (RFC 4760), labelled
prefixes use the RFC 8277 encoding (`lr_bgp::path::labeled_nlri`), and
Add-Path (RFC 7911) prefixes a path identifier onto each NLRI entry.

One thing is yours to configure rather than the codec's: Add-Path
framing is not inferred. After OPEN negotiates it, call
`BgpCodec::set_add_path(tx, rx)` on the session's codec. Four-byte ASNs
are the opposite case — the `asn4` feature is on by default and the
codec handles the encoding.

Errors are typed: `EncodeError` and `ParseError` tell you whether the
frame was malformed or merely incomplete.

## Chapter 2 — two peers

`BgpPeer` is one session's RFC 4271 state machine, its timers and its
output buffer. You drive it with events and drain the bytes it wants
sent:

```rust
use lr_bgp::{BgpEvent, BgpPeer, PeerConfig};
use lr_core::addr::{Asn, RouterId};

let mut peer = BgpPeer::new(PeerConfig::new(
    Asn(64512),                       // local AS
    Asn(64513),                       // peer AS
    RouterId::from_v4([10, 0, 0, 1]), // local BGP identifier
));
peer.step(BgpEvent::ManualStart);
peer.step(BgpEvent::TransportOpen); // the TCP connection came up
let open = peer.drain_outgoing();   // send these bytes to the peer
```

Two peers reach Established by exchanging each other's bytes. This is
the whole establishment sequence, with the sockets replaced by two
variables — `crates/lr-tests/tests/tcp_smoke.rs` runs the same loop over
a real socket pair:

```rust
use lr_bgp::{BgpEvent, BgpPeer, PeerConfig};
use lr_core::addr::{Asn, RouterId};

let mut a = BgpPeer::new(PeerConfig::new(
    Asn(64512),
    Asn(64513),
    RouterId::from_v4([10, 0, 0, 1]),
));
let mut b = BgpPeer::new(PeerConfig::new(
    Asn(64513),
    Asn(64512),
    RouterId::from_v4([10, 0, 0, 2]),
));

// Both sides start, and both transports open.
for peer in [&mut a, &mut b] {
    peer.step(BgpEvent::ManualStart);
    peer.step(BgpEvent::TransportOpen);
}

// Exchange output until the buffers run dry. The FSM answers OPEN with
// KEEPALIVE, so the default configuration settles in two rounds.
let a_out = a.drain_outgoing();
let b_out = b.drain_outgoing();
a.feed_bytes(&b_out).unwrap();
b.feed_bytes(&a_out).unwrap();
let a_ka = a.drain_outgoing();
let b_ka = b.drain_outgoing();
a.feed_bytes(&b_ka).unwrap();
b.feed_bytes(&a_ka).unwrap();

assert!(a.is_established() && b.is_established());
```

Capabilities are negotiated in the OPEN exchange. Most are `PeerConfig`
fields — MP-BGP families, graceful restart, Add-Path, and so on — and
the FSM advertises a capability only when the corresponding field is
set. Four-byte ASN support is a crate feature rather than a field. A
peer that does not understand a capability ignores it (RFC 5492 §3),
which is why any RFC 4271 speaker can peer with you.

Once Established, inbound UPDATEs go in through `feed_bytes` and come
back out of `step` as `BgpAction`s: `InstallRoute`, `WithdrawRoute`,
`RouteRefreshRequested`, `EndOfRib`. Dispatching those actions is what
the next chapter automates.

KEEPALIVE and hold timers do not fire on their own. The FSM asks you to
schedule them by returning `BgpAction::SetTimer` and `CancelTimer`, and
expects them back as events: `BgpEvent::TimerHoldExpired`,
`TimerKeepalive`, `TimerConnectRetry` or `TimerIdleHold`. A peer with no
clock never notices a dead session. At Layer 3 the router does this for
you — see [Driving time](#driving-time) below.

## Chapter 3 — the router pipeline

`DefaultRouter` is the Layer 3 orchestrator. It owns the sessions, the
Adj-RIB-In and Adj-RIB-Out, the Loc-RIB, best-path selection and the
export hooks. You add a session, start it, and pump bytes; the router
produces the UPDATEs.

`add_session` needs a `SessionConfig`. Building one for BGP takes the
local AS, the peer AS and the local BGP identifier:

```rust
use lr_core::addr::{Asn, IpAddr, RouterId};
use lr_router::{DefaultRouter, RouterInstance, SessionConfig};

let mut a = DefaultRouter::new();
let ha = a
    .add_session(
        SessionConfig::bgp(Asn(64512), Asn(64513), RouterId::from_v4([10, 0, 0, 1]))
            .with_local_address(IpAddr::V4([192, 0, 2, 1])),
    )
    .unwrap();
a.start_session(ha).unwrap();
```

`SessionHandle`s address a session for byte I/O and events. Here is the
complete two-router harness — both routers, both sessions, and the pump
that moves bytes between them:

```rust
use lr_core::addr::{Asn, IpAddr, RouterId};
use lr_router::{DefaultRouter, RouterInstance, SessionConfig, SessionHandle};

fn pump(a: &mut DefaultRouter, ha: SessionHandle, b: &mut DefaultRouter, hb: SessionHandle) {
    for _ in 0..16 {
        let out_a = a.drain_output(ha);
        if !out_a.is_empty() {
            b.feed_input(hb, &out_a).unwrap();
        }
        let out_b = b.drain_output(hb);
        if !out_b.is_empty() {
            a.feed_input(ha, &out_b).unwrap();
        }
        if out_a.is_empty() && out_b.is_empty() {
            return;
        }
    }
    panic!("byte pump did not converge");
}

let mut a = DefaultRouter::new();
let mut b = DefaultRouter::new();

let ha = a
    .add_session(
        SessionConfig::bgp(Asn(64512), Asn(64513), RouterId::from_v4([10, 0, 0, 1]))
            .with_local_address(IpAddr::V4([192, 0, 2, 1])),
    )
    .unwrap();
let hb = b
    .add_session(
        SessionConfig::bgp(Asn(64513), Asn(64512), RouterId::from_v4([10, 0, 0, 2]))
            .with_local_address(IpAddr::V4([192, 0, 2, 2])),
    )
    .unwrap();

a.start_session(ha).unwrap();
b.start_session(hb).unwrap();
pump(&mut a, ha, &mut b, hb);
let _ = b.poll_events(); // discard the session-state events
```

Against real peers the same `drain_output` / `feed_input` pair wraps a
`TcpStream`; the contract is raw bytes in, raw bytes out.

With the session Established, originate a prefix. The router builds the
UPDATE — AS_PATH, a NEXT_HOP taken from the configured local address,
and the other attributes — and returns a `RouteKey` you use to withdraw
it later:

```rust
use lr_core::addr::{IpAddr, Prefix};

let key = a.originate(
    Prefix::new_v4([203, 0, 113, 0], 24),
    Some(IpAddr::V4([192, 0, 2, 1])), // NEXT_HOP for the eBGP advertisement
);
pump(&mut a, ha, &mut b, hb);
```

On `b`, the route travels the full inbound pipeline: Adj-RIB-In, the
safety net (AS-loop rejection, RFC 4271 §9.1.2.15), the import hooks,
best-path selection, then the Loc-RIB. Two mirrors let you watch it:
the RIB snapshot and the event stream.

```rust
let snapshot = b.rib_snapshot();
assert_eq!(snapshot.len(), 1);
let route = &snapshot[0];
assert_eq!(route.key.prefix, Prefix::new_v4([203, 0, 113, 0], 24));
assert_eq!(route.next_hop, Some(IpAddr::V4([192, 0, 2, 1])));

// The AS path survived the wire.
let attrs: lr_bgp::path::PathAttributes = route.attributes.clone().into();
assert_eq!(attrs.as_path().unwrap().as_sequence(), vec![Asn(64512)]);

// b emitted RouteInstalled for it.
assert!(b
    .poll_events()
    .into_iter()
    .any(|e| matches!(e, lr_router::RouterEvent::RouteInstalled(_))));
```

Withdrawing runs the same path backwards. `unoriginate` removes the
route from the originating Loc-RIB, the egress path emits a withdrawal,
and the peer's entry disappears with a `RouteWithdrawn` event:

```rust
a.unoriginate(&key);
pump(&mut a, ha, &mut b, hb);
assert!(b.rib_snapshot().is_empty());
```

That is the whole pipeline: originate, propagate, install, withdraw.

### Driving time

Nothing above advances a clock, which is fine for a test and wrong for a
daemon. Timers — hold time, keepalive, MRAI, OSPF hello and dead
intervals, Babel hello and IHU — fire from `RouterInstance::tick`:

```rust
use std::time::Instant;

// Call this from your event loop, at least as often as your shortest
// protocol timer.
router.tick(Instant::now());
```

For protocols with sub-millisecond timestamps (Babel RTT, RFC 8966
§A.2.4), use `feed_input_at(handle, bytes, now_ms, now_us)` so the
datagram arrives with the same clock the outgoing hellos were stamped
from.

### Errors

Every fallible call returns `Result<_, String>` with a human-readable
reason: `add_session` rejects an invalid configuration, `feed_input`
rejects bytes that are not a valid frame for that session, and
`set_session_*` calls reject a handle that is not the protocol you think
it is. Treat a `feed_input` error as a transport fault and close the
session; do not retry the same bytes.

## Chapter 4 — policy

Policy is expressed as hooks. `HookChain` holds three lists — import,
selection and export — and the router runs them at the matching stage of
the pipeline.

An import hook sees the decoded route before it reaches Adj-RIB-In, and
can keep it, drop it or replace it:

```rust
use lr_core::rib::Route;
use lr_policy::{HookChain, HookVerdict, ImportHook};

struct RejectTooSpecific;

impl ImportHook for RejectTooSpecific {
    fn name(&self) -> &str {
        "reject-too-specific"
    }

    fn on_import(&self, route: &mut Route) -> HookVerdict {
        if route.key.prefix.prefix_len > 24 {
            HookVerdict::Drop
        } else {
            HookVerdict::Keep
        }
    }
}

let mut router = lr_router::DefaultRouter::new();
router.hooks_mut().import.push(Box::new(RejectTooSpecific));
```

The same shape works for `SelectionHook` (return `None` to fall back to
the built-in comparator) and `ExportHook` (fire once per destination
session with `on_export_to`).

For anything you would write in BIRD — prefix sets, community lists,
arithmetic, `case` — use the filter DSL instead of a Rust hook. It
compiles to bytecode and runs in the router's import and export stages:

```rust
use lr_policy::filter;

let f = filter::compile(
    "reject-too-specific",
    "if bgp.as_path.len > 10 then reject; \
     if net ~ [ 203.0.113.0/24{24,24} ] then accept; \
     reject",
)
.unwrap();
```

The full grammar, the built-in functions and the route fields are in
[`filter_dsl_grammar.md`](filter_dsl_grammar.md).

Two safety features are on by default and worth knowing about:

- **The safety net** rejects AS-loop routes and other RFC 4271 §9.1.2
  violations before your hooks ever see them.
- **RFC 8212** means an eBGP session imports and exports nothing until
  you attach policy. `DefaultRouter::set_ebgp_requires_policy(false)`
  turns that off, and `docs/PARITY.md` records what BIRD and FRR do
  differently.

## Where to go next

| Topic | Read |
| --- | --- |
| Every public type, by crate | [`api/`](api/) |
| How the pieces fit together | [`ARCHITECTURE.md`](ARCHITECTURE.md) |
| Running the reference daemon | [`lr-daemon.md`](lr-daemon.md), [`lr-daemon-reference.md`](lr-daemon-reference.md) |
| Filter and configuration syntax | [`filter_dsl_grammar.md`](filter_dsl_grammar.md), [`config_dsl_grammar.md`](config_dsl_grammar.md) |
| Embedding from C, C++, Go or Python | [`bindings/`](bindings/) |
| Verifying against BIRD and FRR | [`INTEROP.md`](INTEROP.md) |
