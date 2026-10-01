# BGP API (`lr-bgp`, `lr-router`)

Read this page if you are embedding a BGP speaker: it covers the wire
codec, the peer FSM, topology roles, best-path selection and the BGP
knobs on `DefaultRouter`.

The snippets need no extra features except where noted: LLGR needs
`long_lived` on `lr-bgp`, and the exchange plane needs `exchange-plane`
on `lr-bgp` and on `lr-router`. Labelled unicast is on by default.

## Example

Layer 1, the codec. `lr_bgp::BgpCodec` is a re-export of
`lr_bgp::codec::BgpCodec`, and `encode` comes from
`lr_core::codec::Encoder` — not from `lr_bgp::codec`:

```rust
use lr_bgp::codec::BgpCodec;
use lr_bgp::message::{keepalive::Keepalive, BgpMessage};
use lr_core::buf::{ReadBuf, WriteBuf};
use lr_core::codec::{Decoder, Encoder};

let codec = BgpCodec::new();
let wire = codec.encode_vec(&BgpMessage::Keepalive(Keepalive))?;

// `encode` itself comes from the Encoder trait:
let mut out = [0u8; 19];
let mut w = WriteBuf::new(&mut out);
let n: usize = codec.encode(&BgpMessage::Keepalive(Keepalive), &mut w)?;

// Decoding is stateful, so keep one codec per session.
let mut rx = BgpCodec::new();
let msg: Option<BgpMessage> = rx.decode_bgp(&mut ReadBuf::new(&bytes))?;
```

`encode_vec(&self, msg) -> Result<Vec<u8>, EncodeError>` is the
convenience encoder, bounded by the 4096-byte BGP PDU maximum.
`decode_slice` and `decode_bgp` both buffer partial frames, and
`decode_bgp` keeps the `BgpError` payload so the FSM can raise the exact
NOTIFICATION RFC 4271 requires.

Layer 2, the peer FSM. `BgpPeer::new` takes a `PeerConfig`:

```rust
use lr_bgp::{BgpEvent, BgpPeer, PeerConfig};
use lr_core::addr::{Asn, RouterId};

let cfg = PeerConfig::new(Asn(64512), Asn(64513), RouterId::from_v4([10, 0, 0, 1]));
let mut peer = BgpPeer::new(cfg);
peer.step(BgpEvent::ManualStart);
peer.step(BgpEvent::TransportOpen);
let out: Vec<u8> = peer.drain_outgoing();  // give this to the socket
let actions = peer.feed_bytes(&inbound)?;  // Vec<BgpAction>
```

`step` and `feed_bytes` return the `BgpAction`s to dispatch (send,
arm/cancel a timer, install or withdraw a route, close); `feed_bytes`
takes `&[u8]` and returns `Result<Vec<BgpAction>, ParseError>`.
`peer.state()`, `peer.is_established()` and `peer.message_stats()` are
the observable state.

Topology roles come from `PeerConfig`:

```rust
use lr_bgp::PeerConfig;
use lr_bgp::role::{OtcRole, PeerRole};
use lr_core::addr::{Asn, RouterId};

let mut cfg = PeerConfig::new(Asn(100), Asn(100), RouterId::from_v4([10, 0, 0, 1]));
cfg.route_reflector_client = true; // RFC 4456
cfg.otc_role = OtcRole::Customer;  // RFC 9234
let topo = cfg.compute_topology();
assert!(topo.rr_client);
assert_eq!(topo.role, PeerRole::Ibgp);
```

`compute_topology()` folds the role, the route-reflector and
route-server flags and the OTC role into a `PeerTopology`, which the
import and export pipeline reads. `role_override` and `confederation`
(RFC 5065/6793) are the other inputs.

Best-path selection is a pure function over a route slice; `multipath`
returns `Option<Vec<&Route>>` — `None` only for an empty input,
otherwise the best path and its equal-cost peers, capped at
`cfg.multipath`. `rank` is the full best-first ordering, which is what
Add-Path advertises from:

```rust
use lr_bgp::best_path::{BestPath, BestPathConfig};

let cfg = BestPathConfig { multipath: 8, ..Default::default() };
let best: Option<&Route> = BestPath::select(&routes, &cfg);
let paths: Option<Vec<&Route>> = BestPath::multipath(&routes, &cfg);
let ranked: Vec<&Route> = BestPath::rank(&routes, &cfg);
```

## Session knobs

| Knob | Default | Effect |
| --- | --- | --- |
| `hold_time`, `keepalive` | 90 s, 0 = hold/3 | RFC 4271 §4.2 |
| `mrai_ms` | 30 s eBGP, 5 s iBGP | Minimum interval between UPDATEs per prefix, RFC 4271 §9.2.1.1 |
| `mp_families` | IPv4 unicast | Families advertised in OPEN, RFC 4760 |
| `add_path` | false | RFC 7911 send + receive |
| `extended_next_hop` | empty | RFC 5549 tuples `(AFI, SAFI, NH-AFI)` |
| `graceful_restart[_time]` | on, 120 s | RFC 4724 |
| `long_lived_gr`, `long_lived_stale_time` | off | RFC 9494; needs `long_lived` |
| `maximum_prefix`, `_action`, `_threshold` | none, `Warn`, 75 | Per-peer prefix ceiling |
| `default_ipv4_unicast` | true | FRR `bgp default ipv4-unicast` posture |
| `local_as_tolerance` | 0 | AS-loop tolerance, FRR `allowas-in`, RFC 4271 §9.1.2.15 |
| `soft_reconfig_inbound` | false | Retain the pre-policy Adj-RIB-In |
| `collision_group`, `locally_initiated` | `None`, false | RFC 4271 §6.8 collision resolution |

`PeerConfig` and `SessionConfig` carry these under the same names, and
`SessionConfig` (the type `add_session` accepts) adds `area_id`, the
OSPF knobs and the session kind. Build it with
`SessionConfig::bgp(local_as, peer_as, local_bgp_id)`, `::ospfv2(rid,
area)`, `::ospfv3(rid, area)` or `::babel(local_addr)`, then chain
`with_mp_families`, `with_add_path`, `with_extended_next_hop[_tuple]`,
`with_local_address`, `with_graceful_restart(secs)`,
`with_long_lived_gr(secs)`, `with_llgr_max_stale_time(cap)`,
`with_mrai_ms(ms)`, `with_maximum_prefix(limit, action)`,
`with_maximum_prefix_threshold(pct)`, `with_ospf_mtu(mtu)` and
`with_ospf_area_type(kind)`.

## Router-level API

All of these live on `DefaultRouter` and return `Result<_, String>`
unless noted. The session mutators must be called after `add_session`
and before `start_session`; they reject an already-established session
and an unknown handle.

| Method | Notes |
| --- | --- |
| `add_session(cfg)` | Returns the `SessionHandle` |
| `start_session(h)`, `feed_input(h, bytes)`, `drain_output(h)` | Transport-facing |
| `tick(now: Instant)`, `poll_events()` | Embedder-driven clock, event drain |
| `set_mrai(h, ms)` | Override `mrai_ms` for one session |
| `set_session_mp_families(h, &[NlriFamily])` | MP-BGP families |
| `set_session_extended_next_hop(h, &[(u16, u8, u16)])` | RFC 5549 |
| `set_session_local_address(h, ip)` | Next-hop-self source |
| `set_session_add_path(h, bool)` | RFC 7911 for one session |
| `set_session_local_as_tolerance(h, u32)` | `u32::MAX` = allow any |
| `set_session_default_ipv4_unicast(h, bool)`, `..._soft_reconfig_inbound(h, bool)` | FRR parity postures |
| `soft_reconfig_inbound(h) -> Result<usize, String>` | Re-runs the import hooks |
| `adj_rib_in_snapshot(h) -> Vec<Route>` | The retained pre-policy view |
| `best_path_config_mut() -> &mut BestPathConfig` | Decision-process knobs |
| `set_enforce_first_as(bool)` | Reject a foreign leftmost AS |
| `originate_with_attributes(prefix, family, next_hop, attributes)` | Returns `RouteKey` |
| `set_bmp_sink(impl Fn(&[u8]) + Send + Sync + 'static)` | RFC 7854 |
| `session_summaries() -> Vec<SessionSummary>` | Introspection |

The per-knob CLI flags, TOML keys and binding names are one table in
[`compat-matrix.md`](compat-matrix.md); this list is the Rust surface.
The remaining router methods — `set_add_path_max_paths(n)`,
`set_ebgp_requires_policy(on)`, `set_session_policy(h, import, export)`,
`add_aggregate(prefix)`, `remove_aggregate(&prefix)`,
`originate_labeled(prefix, family, stack, next_hop)` — are described by
the bullets below. Two of them deserve their semantics spelled out:

- **RFC 8212.** With `set_ebgp_requires_policy(true)`, an *external*
  session — eBGP or a confederation boundary, RFC 8212 §1 — with no
  declared import policy discards every received route, and one with no
  declared export policy advertises nothing. `set_session_policy`
  declares presence per direction; the library default is off.
- **enforce-first-as.** With `set_enforce_first_as(true)`, an external
  session's UPDATE whose leftmost AS_PATH sequence is not the peer's
  negotiated AS is dropped before Adj-RIB-In and logged once per session
  as `RouterEvent::Log`. iBGP and confederation-internal sessions are
  exempt. Off by default.

Worked examples of both, plus Add-Path, extended next-hop and
max-prefix, are in [`../examples/`](../examples/).

## Egress, aggregation, monitoring

- **Add-Path** (RFC 7911). `with_add_path()` advertises send + receive
  for the session's families; it takes effect only if the peer offers it
  too. Peers that negotiated it receive every ranked path under its own
  wire path identifier (rank slot + 1); other peers see the best path.
- **Extended next-hop / MP-BGP** (RFC 5549, RFC 8950). The 6-byte tuple
  form `<AFI:2, SAFI:2, NH-AFI:2>` is what BIRD 2 and FRR send and
  accept; the builders above cover the dual-stack session modes.
- **Labelled unicast** (RFC 8277, feature `labeled_unicast`, on by
  default). Add `NlriFamily::IPV4_LABELED_UNICAST` to `mp_families` and
  originate with `originate_labeled`.
- **Graceful restart** (RFC 4724). Sessions advertise it by default;
  `with_graceful_restart(secs)` sets the window. When an established
  peer's transport closes, its imported routes stay selectable until the
  peer reconnects or the window expires, so keep calling
  `DefaultRouter::tick`, which enforces expiry. `long_lived` adds
  RFC 9494 on top.
- **Aggregation** (RFC 4271 §9.2.2.2). `add_aggregate(prefix)`
  originates the aggregate while a more specific is in the Loc-RIB, with
  an empty AS_PATH, ATOMIC_AGGREGATE and AGGREGATOR, and withdraws it
  when the last specific goes away.
- **BMP** (RFC 7854). `set_bmp_sink` receives an encoded message when a
  session reaches Established, when it goes down, and when a route
  enters the Loc-RIB; `lr_bmp::BmpCodec` (`feed` plus `next_message`)
  decodes the collector side and drains several messages per read.
- **MRT** (RFC 6396). `lr_mrt::parse_file` returns `Vec<MrtRecord>` and
  `MrtRecord::Rib(RibTable)` carries `prefix` and `entries`; with the
  default `bgp` feature `lr_mrt::walk_attributes(&entry)` decodes the
  path attributes into an `AttrSummary`, and `MrtRibDump::encode` writes
  BIRD's `protocol mrt` shape. Replay a dump — or a BMP-monitored prefix
  — with `originate_with_attributes`.

### GTSM (RFC 5082)

GTSM is a transport concern: the kernel writes the outbound TTL and
drops inbound segments below the minimum, and the library never inspects
a TTL on the wire. `Gtsm::single_hop()` arms TTL 255 in both directions
via `arm_listener_gtsm(&listener, &gtsm)` and
`connect_gtsm(addr, &gtsm, Duration::from_secs(5))`.

`Gtsm::multihop(hops)` sets the outbound TTL to `hops` and the minimum
inbound TTL to `255 - hops + 1`. Arm the connector with the outbound TTL
only — a minimum-TTL filter on the connector drops the SYN-ACK.

### FRR and BIRD parity

- `default_ipv4_unicast` (default true) keeps IPv4 unicast implicitly
  active; `PeerConfig::ipv4_unicast_active()` reports
  `default_ipv4_unicast || mp_families.contains(IPV4_UNICAST)`.
- `local_as_tolerance` is FRR `allowas-in N` / BIRD `allow local as`,
  and `u32::MAX` is FRR `allowas-any`; iBGP is exempt.
- `BestPathConfig::deterministic_router_id` (default true) is the
  inverse of FRR's `bgp bestpath compare-routerid`: true means lowest
  router ID wins (RFC 5004), false means oldest route wins.
- A maximum-prefix breach fires `RouterEvent::MaxPrefixThreshold` at the
  percentage and `RouterEvent::MaxPrefixExceeded` at the limit; the
  `Teardown` and `Restart` actions send a CEASE NOTIFICATION.

## Exchange plane (experimental)

Behind the `exchange-plane` feature of `lr-bgp` (forwarded by
`lr-router`), off by default and using IANA code point 251 pending an
early allocation. The codec is `lr_bgp::extensions::exchange_plane`:
`ExchangePlaneConfig::capability()` advertises it, `parse_capability`
parses the peer's OPEN, `ExchangePlaneSession::negotiate` applies the
activation rule, `ExchangeRecord::{encode, decode}` carry the
`Record::{Hint, Policy, Origin, Segment}` TLVs, `sign` and `verify`
handle the HMAC-SHA256 tag, and `ReplayTracker` enforces the OPEN-nonce
binding and the monotonic per-key sequence.

`BgpPeer::set_exchange_plane(cfg)` advertises the capability for one
session and `BgpPeer::exchange_plane_session()` is the result after OPEN
(`None` when the peer did not join; the session is unaffected either
way, RFC 5492 §3). `DefaultRouter::set_session_exchange_plane(h, cfg)`
attaches it before `start_session`, `exchange_plane_records(h)` returns
the verified records per prefix, and the daemon wires the same surface
from `[bgp] exchange_plane` plus `exchange_plane_keys` with a per-peer
override.

## RFCs

- RFC 4271 — message format, FSM, decision process, MRAI, aggregation.
- RFC 4456 route reflection, RFC 5065 confederations, RFC 7947 route
  servers, RFC 9234 OTC, RFC 4271 §6.8 collision resolution.
- RFC 4760 MP-BGP, RFC 5549 and RFC 8950 extended next-hop, RFC 7911
  Add-Path, RFC 2918 and RFC 7313 route refresh.
- RFC 4724 graceful restart, RFC 9494 LLGR, RFC 8326 graceful shutdown.
- RFC 8212 default eBGP policy, RFC 5004 deterministic tie-breaking,
  RFC 4784 multipath.
- RFC 8277 labelled unicast, RFC 7854 BMP, RFC 6396 MRT, RFC 5082 GTSM,
  RFC 5881 §5 for the single-hop TTL filter.
- RFC 5492 — the capability-negotiation rule the exchange plane follows.

## See also

- [`compat-matrix.md`](compat-matrix.md) — daemon knob names.
- [`router.md`](router.md) — sessions, events and redistribution.
- [`policy.md`](policy.md) — import/export hooks a BGP session runs.
- [`../RFC_MAP.md`](../RFC_MAP.md) — the full coverage table.
