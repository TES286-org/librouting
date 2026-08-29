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

## Policy — named sets + per-peer dispatch (PolicySet)

`PolicySet` binds user-facing names to prefix-lists / AS-path filters
/ community lists / route-maps and implements `MatchResolver`, so a
route-map's `match` clauses resolve through the same set. `PolicyHooks`
is the import/export dispatch pair: routes whose session has a bound
route-map are evaluated (FRR semantics: first matching entry wins, no
match = deny); sessions without a binding pass through.

```rust
use lr_policy::{ListKind, PolicySet, SetAction};
use lr_policy::prefix_list::{PrefixList, PrefixListEntry};
use lr_policy::route_map::RouteMapEntry;
use lr_core::addr::Prefix;

let mut set = PolicySet::new();
let mut space = PrefixList::new();
space.push(PrefixListEntry {
    prefix: Prefix::new_v4([203, 0, 113, 0], 24),
    ge: 24, le: 32, permit: true,
});
set.add_prefix_list("customer-space", space);

set.push_route_map_entry("to-customer", RouteMapEntry {
    matches: vec![set.match_condition(ListKind::Prefix, "customer-space").unwrap()],
    sets: vec![SetAction::SetLocalPref(200)],
    verdict: Some(true),
});

// Attach to session 3 and register on the router.
set.bind_export(3, "to-customer");
let hooks = set.hooks();
router.hooks_mut().import.push(Box::new(hooks.clone()));
router.hooks_mut().export.push(Box::new(hooks));
```

`ExportHook::on_export_to(route, destination)` receives the egress
session id (default method delegates to `on_export`, so existing hooks
are unaffected). The daemon exposes all of this as TOML tables — see
`templates/daemon.toml`.

## BFD

```rust
use lr_bfd::{BfdConfig, BfdSession, SessionRole};
use lr_core::time::Instant;

let cfg = BfdConfig {
    detect_mult: 3,
    desired_min_tx_interval: 100_000, // 100ms
    required_min_rx_interval: 100_000,
    role: SessionRole::Active, // RFC 5881 §3: both sides Active
    ..Default::default()
};
let mut session = BfdSession::new(cfg, 0x11111111);
let _ = session.start(Instant(0));
// feed a received datagram (pass the current time so the detection
// timer anchors to arrival); drain the reply onto the wire
let events = session.feed_bytes(Instant(120), &datagram);
let out = session.drain_outgoing();
// every tick: advance timers (periodic transmit + detection expiry)
let events = session.tick(Instant(200));
```

`feed_bytes` applies the RFC 5880 §6.8.6 MUST-discard rules and drives
the exact §6.8.6 state machine (Down+Init→Up, Init+Init→Up). The
detection time is the *peer's* detect multiplier ×
`max(required rx, peer desired tx)` (§6.8.4); the transmit interval is
`max(desired tx, peer required rx)` with 0-25% jitter (§6.8.7) and a
one-second floor while not Up (§6.8.3). Interval changes while Up go
through Poll/Final confirmation (§6.5) via
`update_timers(now, desired_tx_us, required_rx_us)`.

The sockets live in `lr_osroute::bfd_transport`: `BfdRxSocket` (shared
receive socket on 3784 single-hop / 4784 multihop, single-hop TTL 255
filter per RFC 5881 §5) and `BfdTxSocket` (per-session ephemeral
source port in 49152-65535, TTL 255 on transmit). The daemon wires it
all with `--bfd` / per-peer `bfd = true` — see
`docs/examples/bfd_integration.md`.

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

## OSPF DBD/LSR exchange (RFC 2328 §7.2)

OSPF sessions run the full database synchronization: after 2-Way the
runtime negotiates master/slave (§10.3, higher router-id wins), pages
LSA headers through Database Description packets bounded by the
interface MTU, queues missing/newer LSAs and requests them in the
Loading phase until the adjacency reaches Full. Sequence mismatches
restart the negotiation (§10.9); duplicates are answered per §10.6;
pending DBDs and LS-Requests retransmit on RxmtInterval from `tick()`.

```rust
use lr_router::{DefaultRouter, RouterInstance, SessionConfig};
use lr_core::addr::RouterId;

let mut r = DefaultRouter::new();
// The interface MTU must be the real one: peers reject DBDs that
// advertise a larger MTU (§10.6).
let h = r.add_session(
    SessionConfig::ospfv2(RouterId::from_v4([10, 0, 0, 1]), 0)
        .with_ospf_mtu(1500),
)?;
```

The exchange driver itself (`lr_ospf::exchange::DbExchange`) is
public for embedders that wire their own OSPF transport — it consumes
decoded packets plus an `&Lsdb` view and produces the packets to
transmit, unit-tested through both role assignments.

## OSPF origination + raw transport (speaker building blocks)

The router pipeline is receive-driven; a real OSPF *speaker* additionally
produces its own artifacts. `lr-ospf::origination` and
`lr-osroute::ospf_transport` are the two halves `lr-daemon --protocol ospf`
is built from — and embedders can reuse them directly:

```rust
use lr_ospf::origination::{originate_router_lsa, RouterLsaLink,
    finalize_v2_packet, finalize_v2_stream, v2_packet_checksum_ok};
use lr_osroute::ospf_transport::{OspfV2Transport, interface_v4_addrs};

// 1. Transport: one raw socket per interface (SO_BINDTODEVICE, both
//    multicast groups joined, TTL 1). Needs root or a user/net namespace.
let addrs = interface_v4_addrs("eth0")?;      // for stub links + masks
let sock = OspfV2Transport::bind("eth0", false)?;
sock.set_nonblocking(true)?;

// 2. Router-LSA (RFC 2328 12.4.1): stub links per interface address,
//    p2p links per Full adjacency; prev_seq continues the sequence space.
let lsa = originate_router_lsa(router_id, &[
    RouterLsaLink::Stub { network: 0x0a0a_0a00, mask: 0xffff_ff00, metric: 10 },
    RouterLsaLink::PointToPoint { neighbor: 0x0b00_0002, local_addr: 0x0a0a_0a01, metric: 10 },
], None)?;

// 3. Egress checksums: the codec emits the A.1 checksum field zeroed;
//    checksum-validating peers (BIRD, FRR) require it. Finalize whole
//    packets (Hellos) or drain_output-shaped streams (LSU bursts).
let mut bytes = codec.encode_vec(&hello_packet)?;
finalize_v2_packet(&mut bytes);          // single packet
finalize_v2_stream(&mut drained);        // back-to-back packets
assert!(v2_packet_checksum_ok(&received[..len]));  // ingress gate
```

`v2_packet_checksum_ok` excludes the 64-bit authentication field exactly
as RFC 2328 §A.1 prescribes. On non-Linux platforms the transport returns
`OspfTransportError::Unsupported`; `is_permission_denied()` detects a
missing `CAP_NET_RAW` so callers can degrade gracefully.

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

## OSPF authentication (RFC 5709 / RFC 7166)

OSPFv2 crypto auth (`CryptoAuth`, AuType 2) and OSPFv3 auth trailer
(`V3Auth`, RFC 7166) both use HMAC-SHA-1 or HMAC-SHA-256. The MAC is
computed over the packet (with checksum/auth fields zeroed) plus an
optional IP pseudo-header. Anti-replay is enforced via a monotonic
cryptographic sequence number.

```rust
use lr_ospf::auth::{CryptoAuth, V3Auth};

// OSPFv2: Key ID + HMAC-SHA-256, 32-bit crypto-seq.
let mut v2 = CryptoAuth::new(1, b"shared-secret".to_vec());
v2.advance_seq();
let trailer = v2.sign_trailer(&header_bytes, &body_bytes);
// ... append `trailer` after the OSPF body on the wire ...

// OSPFv3: SA-ID + HMAC-SHA-256, 64-bit crypto-seq.
let mut v3 = V3Auth::new(1, b"shared-secret".to_vec())
    .with_addresses(src_v6, dst_v6);
v3.advance_seq();
let trailer = v3.sign_trailer(&packet); // header + body
```

## OSPFv3 inter-area-prefix-LSA (RFC 5340 §A.4.5)

An OSPFv3 ABR re-advertises reachability between areas using
inter-area-prefix-LSAs (type 0x2003). The body carries a 3-byte metric,
the prefix length, prefix options, and the truncated address prefix.

```rust
use lr_ospf::abr::{originate_v3_inter_area_prefix_lsa, SummaryDestination};
use lr_ospf::lsa::LsaTypeV3;
use lr_core::addr::Prefix;

let prefix = Prefix::new_v6([0x20,0x01,0x0d,0xb8, 0,0,0,0, 0,0,0,0, 0,0,0,1], 64);
let dest = SummaryDestination::new(prefix, 10);
let lsa = originate_v3_inter_area_prefix_lsa(router_id, ls_id, &dest, None)?;
assert_eq!(lsa.header.ls_type, LsaTypeV3::InterAreaPrefixLsa.function_code());
assert!(lsa.checksum_ok());
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

## MPLS — label stack codec (`lr-mpls`)

```rust
use lr_mpls::{Label, LabelStack};

// Build a stack: top = 100, bottom = 200 (S bit set on encode).
let stack = LabelStack::from_labels([Label::new(100), Label::new(200)]);
let wire = stack.encode_4octet();          // RFC 3032 §2.1 (8 bytes)
let nlri = stack.encode_3octet();          // RFC 8277 §3.2 (6 bytes, no TTL)

// Round-trip both forms.
assert_eq!(LabelStack::decode_4octet(&wire).unwrap(), stack);
// The 3-octet form does not carry TTL — decode produces TTL=0.
let dec = LabelStack::decode_3octet(&nlri).unwrap();
assert_eq!(dec.labels().iter().map(|l| l.value).collect::<Vec<_>>(),
           vec![100, 200]);
```

## MPLS — Linux kernel LSP installation (`lr-osroute::mpls_route`)

```rust
use lr_osroute::mpls_route::{MplsNetlink, MplsRoute, mpls_enabled};
use lr_mpls::{Label, LabelStack};
use lr_core::addr::IpAddr;

if !mpls_enabled() {
    eprintln!("load mpls_router; echo 16 > /proc/sys/net/mpls/platform_labels");
    return;
}
let mut mpls = MplsNetlink::connect()?;

// Pop: incoming label 100 → forward IP to 192.0.2.1 on if 2.
mpls.add_route(&MplsRoute::pop(Label::new(100), IpAddr::V4([192, 0, 2, 1]), 2))?;

// Swap: incoming label 200 → push [300, 400], forward to 198.51.100.1.
let new_stack = LabelStack::from_labels([Label::new(300), Label::new(400)]);
mpls.add_route(&MplsRoute::swap(Label::new(200), new_stack,
                                IpAddr::V4([198, 51, 100, 1]), 2))?;

// Remove by in-label.
mpls.delete_route(Label::new(100))?;
```

## BGP labelled unicast (RFC 8277)

```rust
use lr_core::addr::Prefix;
use lr_core::nlri::NlriFamily;
use lr_mpls::{Label, LabelStack};
use lr_router::{DefaultRouter, RouterInstance, SessionConfig};

let mut r = DefaultRouter::new();
let h = r.add_session(
    SessionConfig::bgp(Asn(64512), Asn(64513), RouterId::from_v4([10, 0, 0, 1]))
        .with_mp_families(vec![NlriFamily::IPV4_UNICAST,
                                NlriFamily::IPV4_LABELED_UNICAST]),
).unwrap();
r.start_session(h).unwrap();

// Originate a labelled IPv4 route: 198.51.100.0/24 with label 100.
let stack = LabelStack::from_labels([Label::new(100)]);
r.originate_labeled(
    Prefix::new_v4([198, 51, 100, 0], 24),
    NlriFamily::IPV4_LABELED_UNICAST,
    stack,
    Some(IpAddr::V4([192, 0, 2, 1])),
);
```

Daemon-side, the same route is originated with `--labeled-network
"198.51.100.0/24 100"` (or the `labeled_networks` TOML key) plus
`--mp-family ipv4-labeled-unicast` on the peer. The interop script
`tests/interop/labeled_unicast.sh` runs the full two-daemon lifecycle
over a real TCP socket.

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

### RFC 5549 / RFC 8950 Extended Next-Hop + MP-BGP family / address selection

`SessionConfig` exposes three builders for the dual-stack / MP-BGP / ENH
session modes:

* `with_mp_families(families)` — override the MP-BGP family list
  advertised in OPEN (default: IPv4 unicast only).
* `with_extended_next_hop()` — advertise the canonical RFC 5549
  `(1, 1, 2)` tuple (IPv4 unicast over an IPv6 next-hop). Use
  `with_extended_next_hop_tuple(afi, safi, nh_afi)` for non-canonical
  tuples. On the wire the tuples use the RFC 5549 §4 / RFC 8950 §4
  6-byte form `<AFI:2, SAFI:2, NH-AFI:2>` — byte-identical to what
  BIRD 2.x and FRR send and the only form both accept.
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
`crates/lr-tests/tests/bgp_session_modes.rs`, and the ENH mode is
additionally verified against real BIRD by
`tests/interop/bird_enh.sh`.

### RFC 5082 GTSM (TTL security)

GTSM is a transport-layer concern: the kernel sets the outbound TTL and
drops inbound segments whose TTL is below the configured minimum. The
library never inspects TTL on the wire — it only arms the socket.

`lr_osroute::gtsm::Gtsm::single_hop()` produces TTL=255 both directions
(the standard for directly connected eBGP). `Gtsm::multihop(hops)`
produces outbound TTL = `hops`, minimum inbound TTL = `255 - hops + 1`.
`arm_listener_gtsm` arms the listener (the min-TTL filter is inherited
by accepted sockets); `connect_gtsm` arms the connector (outbound TTL
only — setting min-TTL on the connector would drop the SYN-ACK).

```rust
use lr_osroute::gtsm::{Gtsm, arm_listener_gtsm, connect_gtsm};
let gtsm = Gtsm::single_hop();
arm_listener_gtsm(&listener, &gtsm)?;
let stream = connect_gtsm(addr, &gtsm, Duration::from_secs(5))?;
```

The daemon exposes `--gtsm` (bare = single-hop) and `--gtsm N` (multihop)
plus the TOML key `bgp.gtsm`. When combined with `--md5-key` /
`--tcp-ao-key` the connector uses `connect_auth` then sets TTL on the
stream via `set_ttl`.

### Per-peer maximum-prefix

`SessionConfig::with_maximum_prefix(limit, action)` configures a
per-peer prefix ceiling. When the peer's Adj-RIB-In exceeds `limit` the
router fires `RouterEvent::MaxPrefixExceeded` (once, latched) and, for
`Teardown`/`Restart`, sends a CEASE NOTIFICATION (subcode 8,
RFC 4486 §2.1). `with_maximum_prefix_threshold(pct)` sets the
early-warning percentage (default 75); `RouterEvent::MaxPrefixThreshold`
fires once when the count crosses it.

```rust
use lr_bgp::MaxPrefixAction;
let h = r.add_session(
    SessionConfig::bgp(Asn(64512), Asn(64513), RouterId::from_v4([10,0,0,1]))
        .with_maximum_prefix(1000, MaxPrefixAction::Teardown)
        .with_maximum_prefix_threshold(75),
)?;
// The router emits MaxPrefixThreshold at 750/1000 and MaxPrefixExceeded
// at 1001/1000; the latter tears the session down with CEASE subcode 8.
```

The daemon exposes `--max-prefixes N`, `--max-prefix-action warn|
teardown|restart`, `--max-prefix-threshold P` (TOML:
`bgp.max_prefixes` / `max_prefix_action` / `max_prefix_threshold`).

### RFC 8212 default eBGP route behaviors

`DefaultRouter::set_ebgp_requires_policy(true)` arms the RFC 8212 §3
defaults (updating RFC 4271 §9.1/§9.1.3): an *external* BGP session —
eBGP **or** a confederation boundary, per §1 — whose embedder declared
no explicit import policy discards every received route before
Adj-RIB-In, and one without an explicit export policy advertises
nothing (stale Adj-RIB-Out entries are withdrawn at the next export
evaluation). Policy presence is declared per session with
`set_session_policy(handle, import, export)`; iBGP and
confederation-internal sessions are exempt. The library default is off
(RFC 4271 accept-all) — embedder pipelines are untouched until they opt
in.

```rust
r.set_ebgp_requires_policy(true);
let h = r.add_session(SessionConfig::bgp(Asn(64512), Asn(64513), RouterId::from_v4([10,0,0,1])))?;
// This peer runs without import/export route-maps, so both directions
// are denied; declare presence to open a direction:
r.set_session_policy(h, true, false)?; // import policy attached
```

The shipped daemon enables the mode by default — `[bgp]
ebgp_policy = "rfc8212"` with per-peer `import`/`export` route-maps as
the explicit policy; `ebgp_policy = "accept-all"` (CLI
`--ebgp-policy accept-all`) is the §3/Appendix-A "insecure-mode"
deviation, and unknown values fail closed at parse time. The FFI
mirrors the two calls (`lr_router_set_ebgp_requires_policy`,
`lr_router_set_session_policy`), as do the Go
(`SetEbgpRequiresPolicy` / `SetSessionPolicy`) and Python
(`set_ebgp_requires_policy` / `set_session_policy`) bindings.

### Cross-protocol redistribution (BIRD `pipe` / FRR `redistribute`)

`RedistributionPipe` bridges routes from a source protocol to a target
protocol. When a route enters the Loc-RIB from the source protocol, the
pipe re-originates it into the target with the configured metric policy.
Withdrawals propagate automatically.

```rust
use lr_router::{RedistributionPipe, MetricPolicy};
use lr_core::rib::Protocol;

// Redistribute BGP routes into OSPF with a fixed metric.
r.add_redistribution_pipe(
    RedistributionPipe::new(Protocol::Bgp, Protocol::Ospfv2)
        .with_metric(MetricPolicy::Fixed(100))
);

// Redistribute OSPF routes into BGP, inheriting the metric.
r.add_redistribution_pipe(
    RedistributionPipe::new(Protocol::Ospfv2, Protocol::Bgp)
);

// Restrict to specific prefixes.
r.add_redistribution_pipe(
    RedistributionPipe::new(Protocol::Bgp, Protocol::Bgp)
        .with_allow_prefixes(vec![(IpAddr::V4([203, 0, 113, 0]), 24)])
);
```

`MetricPolicy::Inherit` (default) uses the source metric unchanged;
`Fixed(N)` always advertises N; `Add(N)` adds N to the source metric.
`remove_redistribution_pipe(source, target)` removes matching pipes.

### Route aggregation (RFC 4271 §9.2.2.2)

`add_aggregate(prefix)` registers a BGP route aggregate. When the
Loc-RIB contains at least one route more specific than the aggregate,
the router originates the aggregate with:
- AS_PATH zeroed (empty AS_SEQUENCE)
- ATOMIC_AGGREGATE attribute
- AGGREGATOR attribute (local AS + router ID)

When all specifics disappear, the aggregate is withdrawn automatically.

```rust
use lr_core::addr::Prefix;
// Aggregate 203.0.113.0/24 from any /25..-/32 specifics.
r.add_aggregate(Prefix::new_v4([203, 0, 113, 0], 24));
// ... when a /32 arrives via BGP, the /24 aggregate appears in Loc-RIB.
// ... when the /32 is withdrawn, the /24 aggregate disappears.
r.remove_aggregate(&Prefix::new_v4([203, 0, 113, 0], 24));
```

### BMP monitoring (RFC 7854)

`DefaultRouter::set_bmp_sink` installs a closure that receives encoded
BMP messages whenever a BGP session transitions to Established (Peer
Up), goes down (Peer Down), or a route enters the Loc-RIB (Route
Monitoring). The closure is called from within `feed_input`/`tick`, so
it must be non-blocking.

```rust
use lr_bmp::BmpCodec;
use std::sync::{Arc, Mutex};

let received: Arc<Mutex<Vec<Vec<u8>>>> = Arc::new(Mutex::new(Vec::new()));
let received_clone = Arc::clone(&received);
r.set_bmp_sink(move |bytes| {
    received_clone.lock().unwrap().push(bytes.to_vec());
});
// Every BGP session establishment, teardown, and route install now
// fires a BMP message into the closure.
```

The `lr-bmp` crate provides the full BMP message codec (`BmpCodec`,
`BmpMessage`, `BmpMsgType`, `PeerHeader`) for embedders that need to
decode the messages on the collector side. `BmpCodec` splits buffering
from decoding (`feed` + `next_message`) so one `read(2)` carrying
several messages drains fully. The daemon wires both directions:
`--bmp-target host:port` mirrors to a monitoring station, and
`--protocol bmp --listen` runs the collector (decoding Peer Up/Down +
Route Monitoring, installing monitored prefixes through
[`originate_with_attributes`]).

### MRT dumps (RFC 6396)

The `lr-mrt` crate reads and writes the MRT interchange format:
`MrtReader` (streaming, carryover-safe) decodes TABLE_DUMP_V2 peer
index tables, RIB_IPV4/IPv6_UNICAST records (including the RFC 7911
add-path variants) and BGP4MP state changes/messages;
`MrtRibDump::encode` produces the same shape BIRD's `protocol mrt`
emits (byte-verified in the interop suite). RIB entries keep path
attributes as raw TLVs; with the default `bgp` feature,
`walk_attributes` interprets them (AS path, next hop, communities,
LOCAL_PREF, MED) through the `lr-bgp` decoders.

```rust
use lr_mrt::{parse_file, MrtRecord};

for record in parse_file("rib.mrt")? {
    if let MrtRecord::Rib(table) = record {
        for entry in &table.entries {
            let summary = lr_mrt::walk_attributes(entry);
            println!("{} via {:?}", table.prefix, summary.next_hop);
        }
    }
}
```

Restoring a RIB (offline replay / observation feed) goes through
`DefaultRouter::originate_with_attributes(prefix, family, next_hop,
attributes)` — the same entry point the BMP collector uses.

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
