# librouting Public API

This is a curated tour of the most useful types and functions. For full
details, see `cargo doc --workspace --open`.

## Core primitives (`lr-core`)

```rust
use lr_core::addr::{IpAddr, Prefix, Asn, RouterId, IpNet};

let prefix: Prefix = "203.0.113.0/24".parse().unwrap();
let as_: Asn = "AS64512".parse().unwrap();
let rid: RouterId = "10.0.0.1".parse().unwrap();
```

## BGP — Layer 1 (codec)

```rust
use lr_bgp::BgpCodec;
use lr_bgp::message::{BgpMessage, BgpMessageType};
use lr_bgp::codec::BgpCodec; // trait import

let mut codec = BgpCodec::new().with_asn4(true);
let mut buf = [0u8; 64];
let mut w = lr_core::buf::WriteBuf::new(&mut buf);
codec.encode(&BgpMessage::Keepalive(lr_bgp::message::keepalive::Keepalive), &mut w);
```

## BGP — Layer 2 (FSM)

```rust
use lr_bgp::{BgpPeer, BgpEvent, PeerConfig, fsm::BgpState};
use lr_core::addr::{Asn, RouterId};

let cfg = PeerConfig::new(Asn(64512), Asn(64513), RouterId::from_v4([10,0,0,1]));
let mut peer = BgpPeer::new(cfg);
peer.step(BgpEvent::ManualStart);
peer.step(BgpEvent::TransportOpen);
let bytes = peer.drain_outgoing();
// send bytes over TCP; push peer replies via peer.feed_bytes(bytes).
```

## BGP — topology (iBGP vs eBGP vs RR vs RS)

```rust
use lr_bgp::role::{PeerRole, PeerTopology, OtcRole};
use lr_bgp::peer::PeerConfig;
use lr_core::addr::{Asn, RouterId};

let mut cfg = PeerConfig::new(Asn(100), Asn(100), RouterId::from_v4([10,0,0,1]));
cfg.route_reflector_client = true; // RFC 4456
cfg.otc_role = OtcRole::Customer;  // RFC 9234
let topo = cfg.compute_topology();
assert!(topo.rr_client);
assert_eq!(topo.role, PeerRole::Ibgp);
```

## BGP — best-path

```rust
use lr_bgp::best_path::{BestPath, BestPathConfig};

let cfg = BestPathConfig { multipath: 8, ..Default::default() };
let best = BestPath::select(&routes, &cfg);
let mp = BestPath::multipath(&routes, &cfg); // Vec of equal-cost paths
```

## Policy — hooks + safety net

```rust
use lr_policy::{HookChain, ImportHook, HookVerdict, SafetyNet, SafetyConfig};
use lr_core::rib::Route;

struct FilterOnAsPath { my_as: u32 }
impl ImportHook for FilterOnAsPath {
    fn on_import(&self, r: &mut Route) -> HookVerdict {
        // ... custom AS path filter logic
        HookVerdict::Keep
    }
}

let mut chain = HookChain::new();
chain.import.push(Box::new(FilterOnAsPath { my_as: 64512 }));

let mut safety = SafetyNet::new(lr_core::addr::Asn(64512));
safety.cfg = SafetyConfig { reject_as_loop: true, ..Default::default() };
safety.check(&route, true).unwrap(); // Err on violation
```

## BFD

```rust
use lr_bfd::{BfdConfig, BfdSession, SessionRole};

let cfg = BfdConfig {
    detect_mult: 3,
    desired_min_tx_interval: 100_000, // 100ms
    required_min_rx_interval: 100_000,
    role: SessionRole::Active,
    ..Default::default()
};
let mut session = BfdSession::new(cfg, 0x11111111);
let _ = session.start(lr_core::time::Instant(0));
// push bytes via feed_bytes, drain via drain_outgoing
```

## BGP graceful restart

BGP sessions advertise RFC 4724 graceful restart by default through
`SessionConfig::bgp`. Configure the negotiated restart window with
`with_graceful_restart(seconds)`. When an established peer's transport closes,
its imported routes remain selectable until the peer reconnects or the
negotiated restart window expires; expiry purges both eBGP and iBGP route
origins. A successful reconnect cancels retention. The embedder must continue
calling `DefaultRouter::tick` so expiry is enforced.

## OSPF LSA lifecycle

`DefaultRouter::tick` applies RFC 2328 LSA lifecycle processing to OSPF
sessions: locally originated LSAs are refreshed and flooded as LSUs after
1800 seconds, while LSAs that reach MaxAge (3600 seconds) are removed and SPF
is rerun. The router clock is embedder-driven, so call `tick` with a monotonic
millisecond timestamp.

## OSPF external routes (RFC 2328 §12.4.3 / §16.4)

`DefaultRouter::ospf_redistribute` injects an external destination into
OSPF as a type-5 AS-external-LSA, originated into every attached *regular*
OSPFv2 area (AS flooding scope) with the requested metric type
(`ExternalMetricType::Type1`/`Type2`), forwarding address and route tag.
In NSSA areas the destination is originated as an area-scoped type-7 LSA
instead (RFC 3101 §2.4): with the P-bit set (`ExternalDestination::p_bit`,
the default) and a non-zero forwarding address it is translated back into
a type-5 by the elected border router; a border router that also sources
the type-5 into its regular areas forces the P-bit clear (§2.4). Stub
areas receive nothing. `ospf_unredistribute` MaxAge-flushes the type-5 and
type-7 LSAs across the areas carrying them. The router re-floods received
type-5s into every other attached regular area, originates type-4
summary-ASBR-LSAs for ASBRs that are only reachable inter-area, and merges
the §16.4 external calculation into Loc-RIB — forwarding addresses become
the route's next hop.

```rust
use lr_ospf::external::{ExternalDestination, ExternalMetricType};
use lr_core::addr::Prefix;

let dest = ExternalDestination::new(
    Prefix::new_v4([198, 51, 100, 0], 24),
    40,
    ExternalMetricType::Type2,
);
router.ospf_redistribute(dest);
```

The C ABI does not expose an OSPF session surface yet; redistribution is
Rust-level until the daemon gains OSPF support (roadmap item 12).

## OSPF stub/NSSA areas (RFC 2328 §3.6, RFC 3101)

Area types are policy attached to an OSPF area, fixed by the first session
that connects to it and changeable later via
`DefaultRouter::ospf_set_area_type`:

```rust
use lr_router::{OspfAreaType, RouterInstance, SessionConfig};

// Stub area (summary default injected at metric 10, summaries imported):
let cfg = SessionConfig::ospfv2(rid, 1)
    .with_ospf_area_type(OspfAreaType::stub(10));
// Totally-stubby (default only), NSSA and totally-NSSA:
OspfAreaType::stub_no_summary(10);
OspfAreaType::nssa(10);          // type-7 default, summaries imported
OspfAreaType::nssa_no_summary(10); // type-3 default, summaries suppressed

// Runtime conversion (flushes/drops the LSAs the new type refuses):
router.ospf_set_area_type(1, OspfAreaType::nssa(10));
```

Behaviour per type: stub/NSSA areas refuse type-5 and type-4 LSAs (both at
install time and in the AS-scope re-flood path); `no_summary` areas
additionally refuse every type-3 summary except the default. Border
routers inject the default route with the configured metric — a type-3
summary-LSA for stub and `no_summary` areas, a type-7 LSA (P-bit clear)
for summary-importing NSSAs (RFC 3101 §2.4/§2.7). Type-7 LSAs inside an
NSSA are calculated by the §2.5 rules (non-zero forwarding addresses must
be intra-area reachable within the NSSA; border routers only install
type-7 defaults with the P-bit set) and the elected border router —
highest router ID among the area's B-bit routers, Nt-bit (RFC 3101
Appendix B) wins — translates P-bit, non-zero-forwarding-address type-7s
into AS-scoped type-5s. Stub/NSSA semantics are OSPFv2-only.

## OSPF virtual links (RFC 2328 §15)

A virtual link is a backbone adjacency between two border routers that
rides through a non-backbone transit area, repairing a partitioned or
physically disconnected backbone:

```rust
use lr_router::RouterInstance;

// On both endpoints (transit area 1, far endpoint's router ID):
assert!(router.ospf_add_virtual_link(1, 0x0202_0202));
assert!(router.ospf_virtual_link_up(1, 0x0202_0202));

// While up, the transport is the embedder's job: tunnel the backbone
// session's bytes through the transit area to the peer.
let h = router.ospf_virtual_link_session(1, 0x0202_0202).unwrap();
let out = router.drain_output(h);
// ... deliver `out` to the peer's virtual session; feed what returns.

router.ospf_remove_virtual_link(1, 0x0202_0202);
```

The link is up while the router's transit-area SPF reaches the endpoint;
coming up materializes an area-0 session — restoring border-router
status (summaries, defaults, type-4s) for a router without a physical
backbone attachment — and losing the transit area tears it down again.
Stub/NSSA transit areas are refused (§15, RFC 3101 §2.1), as is
configuring the backbone itself as stub. Router-LSA origination stays
with the embedder, as everywhere in this model: endpoints advertise the
link as a type-4 link in their backbone router-LSAs (metric = the
transit-area path cost) and set the V-bit in their transit-area
router-LSAs.

## Babel RFC 8967 authentication

```rust
use lr_babel::{
    BabelCodec, BabelFrame, BabelMacKey, BabelPacketCounter, BabelPseudoHeader,
    BabelReplayProtection,
};
use lr_core::addr::IpAddr;

let pseudo_header = BabelPseudoHeader {
    source: IpAddr::V4([192, 0, 2, 1]),
    source_port: 6696,
    destination: IpAddr::V4([224, 0, 0, 111]),
    destination_port: 6696,
};
let key = BabelMacKey::new(b"32-byte-interface-secret".to_vec());
let mut sender = BabelPacketCounter::new(b"fresh-interface-index".to_vec(), 0)?;
let packet = BabelCodec::new().encode_authenticated(
    &BabelFrame::empty(), pseudo_header, &key, &mut sender,
)?;
let mut replay = BabelReplayProtection::default();
let frame = BabelCodec::new().decode_authenticated_slice(
    &packet, pseudo_header, &[key], &mut replay,
)?;
```

## OS routing table

```rust
use lr_osroute::{OsRouteTable, RtNetlink};
use lr_core::addr::{Prefix, IpAddr};

let mut rt = RtNetlink::connect()?;
let prefix: Prefix = "203.0.113.0/24".parse().unwrap();
let gw: IpAddr = "198.51.100.1".parse().unwrap();
rt.add_route(prefix, gw, 2)?;
```

## Damping (RFC 2439)

```rust
use lr_damping::{DampingTable, DampingConfig};

let mut t = DampingTable::new(DampingConfig::default());
let now_s = 0;
t.on_withdraw(&"10.0.0.0/8".parse().unwrap(), now_s);
let suppressed = t.is_suppressed(&"10.0.0.0/8".parse().unwrap());
```

## Router (Layer 3 orchestrator)

```rust
use lr_router::{DefaultRouter, RouterInstance, SessionConfig, SessionKind};
use lr_core::addr::{Asn, RouterId};

let mut r = DefaultRouter::new();
let h = r.add_session(SessionConfig::bgp(Asn(64512), Asn(64513), RouterId::from_v4([10,0,0,1])))?;
// RFC 4271 MRAI uses 30 s for eBGP and 5 s for iBGP by default.
// Override it per session; zero sends updates immediately.
r.set_mrai(h, 10_000)?;
let events = r.poll_events();
```

### RFC 7911 Add-Path

`SessionConfig::with_add_path()` advertises the Add-Path capability
(send + receive) for the session's families; it only takes effect when
the peer offers it too. `set_add_path_max_paths(n)` caps how many paths
per prefix the decision process keeps in the Loc-RIB (default 1 =
single-path). Add-Path peers then receive every ranked path, each under
its own wire path identifier (rank slot + 1), while plain peers continue
to see only the best path.

```rust
let h = r.add_session(
    SessionConfig::bgp(Asn(64512), Asn(64513), RouterId::from_v4([10,0,0,1]))
        .with_add_path(),
)?;
r.set_add_path_max_paths(4);
```

### RFC 5549 Extended Next-Hop + MP-BGP family / address selection

`SessionConfig` exposes three builders for the dual-stack / MP-BGP / ENH
session modes:

* `with_mp_families(families)` — override the MP-BGP family list
  advertised in OPEN (default: IPv4 unicast only).
* `with_extended_next_hop()` — advertise the canonical RFC 5549
  `(1, 1, 2)` tuple (IPv4 unicast over an IPv6 next-hop). Use
  `with_extended_next_hop_tuple(afi, safi, nh_afi)` for non-canonical
  tuples.
* `with_local_address(ip)` — local source for next-hop-self egress.
  For ENH over IPv6 pass an IPv6 literal; the eBGP egress path then
  rewrites IPv4 NLRI's NEXT_HOP to a 16-byte IPv6 address.

The same options are exposed post-creation via mutators:
`set_session_mp_families`, `set_session_extended_next_hop`, and
`set_session_local_address`. They must be called before
`start_session` (OPEN negotiation).

```rust
let h = r.add_session(
    SessionConfig::bgp(Asn(64512), Asn(64513), RouterId::from_v4([10,0,0,1]))
        .with_mp_families(vec![NlriFamily::IPV4_UNICAST, NlriFamily::IPV6_UNICAST])
        .with_extended_next_hop()
        .with_local_address(IpAddr::V6([0x20,0x01,0x0d,0xb8, 0,0,0,0, 0,0,0,0, 0,0,0,1])),
)?;
// Equivalent: post-creation mutators (same effect, FFI-friendly).
r.set_session_mp_families(h, &[NlriFamily::IPV4_UNICAST, NlriFamily::IPV6_UNICAST])?;
r.set_session_extended_next_hop(h, &[(1, 1, 2)])?;
r.set_session_local_address(h, IpAddr::V6([0x20,0x01,0x0d,0xb8, 0,0,0,0, 0,0,0,0, 0,0,0,1]))?;
```

The eight BGP session establishment modes (standard dual-stack,
link-local dual-stack, MP-BGP, MP-BGP+link-local, ENH, ENH+link-local,
pure IPv6, pure IPv6+link-local) are exercised end-to-end by
`crates/lr-tests/tests/bgp_session_modes.rs`.

### Operational introspection

`session_summaries()` renders one [`SessionSummary`] per session (kind,
ASNs, FSM state, establishment, peer BGP id, negotiated hold time,
Adj-RIB-In size) — the data plane behind `lr-daemon --api-socket`
(`sessions` command), `lr_router_sessions_dump` in the FFI and the
Go/Python bindings. `rib_snapshot()` (via `RouterInstance`) yields the
Loc-RIB for `routes`/dumps.

```rust
for s in r.session_summaries() {
    println!("#{} {} state={} established={}", s.handle.0, s.kind, s.state, s.established);
}
```
