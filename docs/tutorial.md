# The librouting tutorial

A book-style walk from raw bytes to a working routing pipeline. The
tutorial is three chapters, each building on the previous one, and
every code block mirrors code that compiles and runs in this
repository (the snippets are adapted from `crates/lr-tests`):

1. **The wire** — encode and decode BGP messages with the `lr-bgp`
   codec, and read a hand-built UPDATE's attributes back.
2. **Two peers** — run two `BgpPeer` state machines against each other
   in memory and drive a session to Established.
3. **The router pipeline** — wire the sessions into `DefaultRouter`,
   originate a prefix, watch it cross the wire, install in the peer's
   Loc-RIB, and withdraw it again.

The library is transport-free by design: nothing in lr opens a socket
or touches an OS routing table. The embedder owns bytes and time —
lr owns protocol state. The daemon in `crates/lr-cli` is itself just
the most complete embedder; every pattern below is what it does
internally.

Add the crates to your `Cargo.toml` (path or git, matching how you
vendor lr):

```toml
[dependencies]
lr-bgp = "0.1"
lr-core = "0.1"
lr-router = "0.1"
```

## Chapter 1 — the wire

`lr-bgp`'s codec turns a byte stream into `BgpMessage`s and back. It
is incremental: feed it whatever the TCP socket produced, and it
returns the messages that completed (`decode_slice` returns
`Ok(None)` when it needs more bytes — TCP coalescing and short reads
are handled by the codec, not by you).

Encoding is the mirror image. Build an `Open`, an `Update`, or a
`Keepalive` and hand it to `encode_vec`:

```rust
use lr_bgp::message::keepalive::Keepalive;
use lr_bgp::{BgpCodec, BgpMessage};

let codec = BgpCodec::new();
let bytes = codec.encode_vec(&BgpMessage::Keepalive(Keepalive)).unwrap();

// `bytes` is the full RFC 4271 message: marker (16 x 0xFF), 2-byte
// length, then the type octet (18) — 4 = KEEPALIVE.
assert_eq!(bytes[18], 4);
```

An UPDATE carries withdrawn prefixes, path attributes, and NLRI. The
attribute set (`PathAttributes`) is an ordered bag keyed by attribute
type; individual attributes are raw `(flags, type, value)` triples
that the `well_known`/`as_path`/`communities`/`mp_nlri` modules
decode on demand:

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

// The peer receives bytes and decodes them back.
let mut peer_codec = BgpCodec::new();
let msg = peer_codec.decode_slice(&bytes).unwrap().unwrap();
match msg {
    BgpMessage::Update(u) => {
        assert_eq!(u.nlri.len(), 1);
        assert_eq!(u.nlri[0].prefix, Prefix::new_v4([203, 0, 113, 0], 24));
        // Read the AS path back from the attribute bag (canonical
        // 4-byte form — the codec merges AS4_PATH when present).
        let path = u.attributes.as_path().unwrap();
        assert_eq!(path.as_sequence(), vec![Asn(64512)]);
    }
    _ => panic!("expected an UPDATE"),
}
```

The same round-trip works for every family: MP-BGP NLRI rides in
`MpReachNlri`/`MpUnreachNlri` attributes (RFC 4760), labelled prefixes
in the RFC 8277 encoding (see `lr-bgp::path::labeled_nlri`), and
Add-Path (RFC 7911) adds a path identifier per NLRI entry — all
negotiated at OPEN and switched per session by the codec, not by the
embedder.

## Chapter 2 — two peers

A `BgpPeer` is one side of one BGP session: the RFC 4271 state
machine, its timers, and its output buffer. The embedder drives it
with events and drains the bytes it wants sent:

```rust
use lr_bgp::{BgpEvent, BgpPeer, PeerConfig};
use lr_core::addr::{Asn, RouterId};

let mut peer = BgpPeer::new(PeerConfig::new(
    Asn(64512),                       // local AS
    Asn(64513),                       // peer AS
    RouterId::from_v4([10, 0, 0, 1]), // local BGP identifier
));
peer.step(BgpEvent::ManualStart);
peer.step(BgpEvent::TransportOpen);   // the TCP connection is up
let open = peer.drain_outgoing();     // send these bytes to the peer
```

Two peers reach Established by exchanging each other's bytes. This is
the whole session-establishment dance — the same loop `tcp_smoke.rs`
runs over a real socket pair, with the sockets replaced by two
variables:

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

// Both sides start and their transports open.
for peer in [&mut a, &mut b] {
    peer.step(BgpEvent::ManualStart);
    peer.step(BgpEvent::TransportOpen);
}

// Exchange each side's output with the other until the buffers run
// dry. The FSM answers OPEN with KEEPALIVE; one exchange round is
// enough for the default configuration.
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

Capabilities are negotiated here, in the OPEN exchange: Add-Path,
MP-BGP families, graceful restart, 4-byte AS — each is a `PeerConfig`
field, and the FSM advertises the capability only when the field is
set (see `docs/API.md` for the full list). A peer that does not
understand a capability ignores it (RFC 5492 §3), which is why lr can
speak to any RFC 4271 speaker.

Once Established, UPDATEs flow through `feed_bytes` and come back out
as `BgpAction`s from `step` — `BgpAction::InstallRoute`,
`WithdrawRoute`, `RouteRefreshRequested`, `EndOfRib`. That dispatch
is exactly what the next chapter's router automates.

## Chapter 3 — the router pipeline

`DefaultRouter` (crate `lr-router`) is the Layer-3 orchestrator: it
owns the sessions, the Adj-RIB-In/Out, the Loc-RIB, the best-path
decision process, and the export hooks. You add a session, start it,
and pump bytes; the router produces the UPDATEs for you:

```rust
use lr_core::addr::{Asn, IpAddr, RouterId};
use lr_router::{DefaultRouter, SessionConfig};

let mut a = DefaultRouter::new();
let ha = a
    .add_session(
        SessionConfig::bgp(Asn(64512), Asn(64513), RouterId::from_v4([10, 0, 0, 1]))
            .with_local_address(IpAddr::V4([192, 0, 2, 1])),
    )
    .unwrap();
a.start_session(ha).unwrap();
```

`SessionHandle`s are how you address a session for byte I/O and
events. Wiring two routers together is the same pump as Chapter 2,
one layer up — feed each side's output into the other until both go
quiet (this is verbatim `route_propagation.rs`'s harness):

```rust
use lr_router::{DefaultRouter, RouterInstance, SessionHandle};

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
```

Against real peers the same `drain_output`/`feed_input` pair wraps a
tcpstream — the contract is raw bytes in, raw bytes out (see
`tcp_smoke.rs` for the socket variant and `docs/INTEROP.md` for the
BIRD/FRR labs).

With the session Established, originate a prefix. The router builds
the UPDATE — AS_PATH, NEXT_HOP (the `local_address` you configured,
i.e. next-hop-self), and any attributes — and hands you a `RouteKey`
for the withdrawal later:

```rust
use lr_core::addr::{IpAddr, Prefix};

let _key = a.originate(
    Prefix::new_v4([203, 0, 113, 0], 24),
    Some(IpAddr::V4([192, 0, 2, 1])), // NEXT_HOP for the eBGP advertisement
);
// pump() moves the UPDATE from a to b...
```

On `b`, the route lands through the full inbound pipeline —
Adj-RIB-In, the safety net (AS-loop rejection, RFC 4271 §9.1.2), the
import policy hooks, best-path selection, then the Loc-RIB — and the
embedder observes it through two mirrors: the RIB snapshot and the
event stream:

```rust
let snapshot = b.rib_snapshot();
assert_eq!(snapshot.len(), 1);
let route = &snapshot[0];
assert_eq!(route.key.prefix, Prefix::new_v4([203, 0, 113, 0], 24));
assert_eq!(route.next_hop, Some(IpAddr::V4([192, 0, 2, 1])));

// The AS path survived the wire: canonical 4-byte decode from the
// route's attribute bag.
let attrs: lr_bgp::path::PathAttributes = route.attributes.clone().into();
assert_eq!(
    attrs.as_path().unwrap().as_sequence(),
    vec![Asn(64512)]
);

// b emitted RouteInstalled for it.
assert!(b
    .poll_events()
    .into_iter()
    .any(|e| matches!(e, lr_router::RouterEvent::RouteInstalled(_))));
```

Withdrawing reverses everything: `unoriginate` removes the route from
the Loc-RIB, the egress path emits a withdrawal, and the peer's
Loc-RIB entry disappears with a `RouteWithdrawn` event:

```rust
a.unoriginate(&key);
// pump() moves the withdrawal from a to b...
assert!(b.rib_snapshot().is_empty());
```

That is the complete pipeline — originate, propagate, install,
withdraw — the same cycle the daemon runs against BIRD and FRR in the
interop suite.

## Where to go next

* **Policy**: import/export hooks, prefix-lists, route-maps —
  `docs/API.md` §Policy and `crates/lr-policy`.
* **The daemon**: the native `.lr` config, runtime API, kernel FIB
  mirroring —
  `README.md`'s quick start and `templates/daemon.lr`.
* **Interop**: how lr is verified against BIRD 2 and FRR 10 —
  `docs/INTEROP.md`.
* **Architecture**: the layering and extension points behind the
  three chapters — `docs/ARCHITECTURE.md`.
* **Status**: what exists and what does not, honestly —
  `docs/STATUS.md`.
