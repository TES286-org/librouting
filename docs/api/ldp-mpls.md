# LDP and MPLS API (`lr-ldp`, `lr-mpls`, `lr-osroute`)

Read this page if you distribute MPLS labels with LDP, or if you install
label-switched paths into a Linux kernel.

No extra feature is needed. `lr-ldp` and `lr-mpls` are the two crates
here that also build `no_std`; the kernel install path needs Linux and
`CAP_NET_ADMIN` at run time.

## Example

The label codec first. `Label::new` sets TTL 64; `Label::new_value` sets
TTL 0, which is what the TTL-less 3-octet NLRI form needs:

```rust
use lr_mpls::{Label, LabelStack};

// Top of stack first; encoding sets the S bit on the last entry.
let stack = LabelStack::from_labels([Label::new(100), Label::new(200)]);
let wire = stack.encode_4octet(); // RFC 3032 §2.1, 8 bytes
let nlri = stack.encode_3octet(); // RFC 8277 §2.2/§2.3, 6 bytes

assert_eq!(LabelStack::decode_4octet(&wire).unwrap(), stack);
// The 3-octet form carries no TTL and no TC, so it decodes to TTL 0.
let dec = LabelStack::decode_3octet(&nlri).unwrap();
assert_eq!(
    dec.labels().iter().map(|l| l.value).collect::<Vec<_>>(),
    vec![100, 200],
);
```

Decoding a 4-octet stack rejects a mid-stack S bit with
`LabelStackError::MidStackBottom` instead of silently truncating the
stack. `decode_3octet_count(bytes, count)` parses the stack out of a
longer NLRI buffer.

The LDP engine. It is protocol-only: it never opens a socket. The
embedder owns UDP 646 for Hellos and TCP 646 for the sessions, feeds
bytes in and drains bytes out:

```rust
use lr_core::addr::Prefix;
use lr_ldp::{GenericLabel, IpAddr, LdpEngine, LdpEngineConfig, LdpId};
use lr_ldp::mapping::FecKey;

let mut cfg = LdpEngineConfig::new(
    LdpId::new([10, 0, 0, 1], 0),
    IpAddr::V4([10, 0, 0, 1]), // transport address
);
cfg.targeted_peers = vec![IpAddr::V4([10, 0, 0, 2])]; // extended discovery
cfg.interface_addresses = vec![IpAddr::V4([10, 0, 0, 1])];
cfg.transit_allocation = true; // off in the library by default
let mut engine = LdpEngine::new(cfg);

engine.tick(now); // advance the timers for this pump round
for (_dest, _datagram) in engine.drain_udp() {
    // transmit the Hellos
}
// engine.feed_udp(now, source, &datagram);  // received Hellos
// engine.on_connected(now, conn, peer_id);  // the active TCP connect is done
// engine.on_accepted(conn, local_addr);     // the passive accept is done
// engine.feed_tcp(now, conn, &bytes);       // received stream bytes
for event in engine.take_events() {
    // AdjacencyUp, SessionUp(negotiated), AddressReceived,
    // MappingLearned, MappingWithdrawn, MappingReleased, ...
}

let prefix = Prefix::new_v4([198, 51, 100, 0], 24);
engine.advertise_mapping(prefix, GenericLabel(100));
engine.withdraw_mapping(prefix); // peers answer with Label Release §3.5.10.1

let peer = LdpId::new([10, 0, 0, 2], 0);
let state = engine.session_state(peer);
let label = engine.lib().label_from(peer, &FecKey::new(prefix));
let swap = engine.transit_next_hop(&prefix);
```

`LdpEngineConfig::new` takes the local LDP Identifier and the transport
address; link discovery needs nothing else, and both it and targeted
discovery ride the same UDP socket. The engine batches queued session
messages into PDUs that respect the negotiated Max PDU Length, and
answers a longer received PDU with a fatal Bad PDU Length Notification
(§3.5.3).

Installing LSPs in a Linux kernel:

```rust
use lr_core::addr::{IpAddr, Prefix};
use lr_mpls::{Label, LabelStack};
use lr_osroute::mpls_route::{MplsNetlink, MplsRoute, mpls_enabled};

// The kernel needs the mpls_router module and a non-zero
// net.mpls.platform_labels; check before connecting.
assert!(mpls_enabled());
let mut mpls = MplsNetlink::connect()?;

// Pop: in-label 100 -> forward the inner packet to 192.0.2.1 on if 2.
mpls.add_route(&MplsRoute::pop(Label::new_value(100), IpAddr::V4([192, 0, 2, 1]), 2))?;

// Pop-local: in-label 100 -> decapsulate and deliver locally.
mpls.add_route(&MplsRoute::pop_local(Label::new_value(100), 1))?; // 1 = lo

// Swap: in-label 200 -> push [300, 400], forward to 198.51.100.1.
let new_stack = LabelStack::from_labels([Label::new_value(300), Label::new_value(400)]);
mpls.add_route(&MplsRoute::swap(
    Label::new_value(200),
    new_stack,
    IpAddr::V4([198, 51, 100, 1]),
    2,
))?;

// LSP head end: reach 198.51.100.0/24 via 192.0.2.1 pushing label 100.
let prefix: Prefix = "198.51.100.0/24".parse().unwrap();
let head = LabelStack::from_labels([Label::new_value(100)]);
mpls.add_encap_route(&prefix, &head, IpAddr::V4([192, 0, 2, 1]), 0)?;
mpls.delete_encap_route(&prefix)?;
mpls.delete_route(Label::new_value(100))?;
```

The netlink label attributes follow the kernel's `nla_get_labels()`
rules: four bytes per entry, bottom-of-stack on the last entry, TTL and
TC cleared because the kernel owns the data-plane TTL, and label 3
(implicit null) refused — `add_encap_route` and `swap` return
`MplsRouteError::ImplicitNullLabel` without making the syscall.

## Configuration

| Knob | Default | Effect |
| --- | --- | --- |
| `LdpEngineConfig::local_id` | required | LSR ID + label space; `LdpId::new([u8; 4], u16)` |
| `transport_addr` | required | Address advertised in the Transport Address TLV |
| `targeted_peers` | empty | Extended (targeted) discovery targets |
| `accept_targeted` | true | Accept inbound targeted Hellos |
| `interface_addresses` | empty | Addresses advertised in Address messages |
| `link_hello_hold`, `targeted_hello_hold` | RFC defaults | Hello hold times |
| `keepalive_time`, `max_pdu_len` | RFC defaults | Session timers and PDU bound |
| `advertisement` | `DownstreamUnsolicited` | `AdvertisementMode` |
| `loop_detection`, `hop_count_limit`, `path_vector_limit` | off, 32, 32 | §2.8 loop detection |
| `transit_allocation` | false | Allocate a local label per learned FEC |
| `label_min`..=`label_max`, `reserved_labels` | 16..=1 048 575, empty | The range to allocate from |
| `graceful_restart`, `gr_reconnect_ms`, `gr_recovery_ms` | off, 15 s, 0 | RFC 3478 |
| `transport_addr_v6`, `prefer_ipv6` | `None`, true | RFC 7552 dual-stack |

Transit-LSR allocation (RFC 5036 §3.5.7.1.1, independent control) is off
in the library and on in the daemon. When it is on, every FEC learned
from a peer gets one locally allocated label that is re-advertised
upstream with the §3.4.4.1 incremented Hop Count and, when loop
detection is configured, the §A.2.6.4 Path Vector extended with the
local LSR ID. The resulting LSP state arrives as
`EngineEvent::TransitSwapChanged { prefix, in_label, next_hop, out_label }`
and `EngineEvent::TransitSwapRemoved { prefix, in_label }`, with
`EngineEvent::TransitLabelExhausted { prefix }` when the range runs out;
`transit_label_of` and `transit_next_hop` introspect it. FEC keys are
normalized to the §3.4.1.1 wire form, so an advertised `10.0.0.1/24` and
a peer's `10.0.0.0/24` are the same FEC.

RFC 3478 graceful restart rides on top of `graceful_restart`: the Init
carries the FT Session TLV, and when a capable peer's session fails
unexpectedly (`EngineEvent::SessionDown { graceful: true, .. }`) its
bindings are retained so the dataplane keeps forwarding. They are
refreshed if the session re-establishes inside the reconnect window and
the peer kept its forwarding state, and withdrawn through the ordinary
events when it did not.

RFC 7552 (LDP over IPv6) is built in: setting `transport_addr_v6` makes
the engine carry the §6.1.1 Dual-Stack capability in every Hello, apply
the per-family Transport-Address-TLV rules, scope Address messages and
IPv6 bindings per peer, and enforce the TR transport preference — a
mismatch resets the session with the fatal Transport Connection
Mismatch notification. Constructing the engine with an IPv6
`transport_addr` instead gives a single-stack IPv6 speaker.

## RFCs

- RFC 3032 §2.1 — the 4-octet label stack entry (label, TC, S, TTL).
- RFC 5462 — TC, the renamed EXP field.
- RFC 8277 §2.2/§2.3 — the 3-octet NLRI label entry used by BGP
  labelled unicast.
- RFC 5036 — LDP: session establishment and roles (§2.5.2), loop
  detection (§2.8), the transport preference and Dual-Stack capability,
  label distribution and advertisement modes (§3.4), FEC normalization
  (§3.4.1.1), hop count (§3.4.4.1), independent control and label
  allocation (§3.5.7.1.1), label release (§3.5.10.1), the Max PDU
  Length check (§3.5.3), the Path Vector TLV (§A.2.6.4).
- RFC 3478 — LDP graceful restart.
- RFC 7552 §6.1.1 — LDP over IPv6.
- RFC 8402 §3.5 and RFC 8665 — the segment-routing use of labels; see
  [`ospf.md`](ospf.md) for the SR surface.

## See also

- [`ospf.md`](ospf.md) — segment routing and the SRGB.
- [`bgp.md`](bgp.md) — RFC 8277 labelled unicast origination.
- [`router.md`](router.md) — the redistribution and OS-table surface.
