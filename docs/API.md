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
