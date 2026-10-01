# OSPF API (`lr-ospf`, `lr-router`)

Read this page if you are embedding an OSPFv2 or OSPFv3 speaker, or
building your own OSPF transport on the `lr-ospf` primitives.

No extra feature is needed: `lr-ospf` enables `v2`, `v3`, `nssa`, `te`,
`hmac_sha` and `graceful_restart` by default. The raw socket transport
needs `root` or a network namespace at run time, not a feature. The
snippets below share one narrative: `router` is the `DefaultRouter`,
`router_id` identifies this speaker, and `lsas` / `neighbor` are the
decoded packet's contents.

## Example

A session and the database exchange it runs. The MTU you configure must
be the real interface MTU, because a peer rejects a DBD that advertises
a larger one (RFC 2328 §10.6):

```rust
use lr_core::addr::RouterId;
use lr_router::{DefaultRouter, RouterInstance, SessionConfig};

let mut r = DefaultRouter::new();
let h = r.add_session(SessionConfig::ospfv2(RouterId::from_v4([10, 0, 0, 1]), 0)
    .with_ospf_mtu(1500))?;
r.start_session(h)?;
```

After 2-Way the runtime negotiates master/slave (the higher Router ID
wins, §10.3), pages LSA headers through DBD packets bounded by that MTU,
queues missing and newer LSAs, and requests them in Loading until the
adjacency reaches Full. Sequence mismatches restart the negotiation
(§10.9); duplicates are answered per §10.6; pending DBDs and LS-Requests
retransmit on RxmtInterval from `tick()`. LSA refresh at 1800 s and
MaxAge removal at 3600 s are also `tick()` work (§14), so an embedder
that stops ticking stops aging.

The exchange driver is public for embedders that own their transport:
`DbExchange::new(router_id, area_id, iface_mtu)`, then
`on_ls_update(&lsas, &mut neighbor) -> ExchangeStep` with `poll(now_ms)`
returning the packets to transmit. An `ExchangeStep` carries `outbound`
packets, the arrived `lsas` to install and flood, and `newly_full`;
`phase()` and `is_full()` report the negotiation state.

Originating a Router-LSA, and getting its checksum right. The codec
leaves the §A.1 packet checksum zeroed, so finalize before sending or a
checksum-validating peer (BIRD, FRR) drops the packet:

```rust
use lr_ospf::codec::OspfCodec;
use lr_ospf::origination::{
    finalize_v2_packet, originate_router_lsa, v2_packet_checksum_ok,
    RouterLsaFlags, RouterLsaLink,
};
use lr_ospf::packet::OspfVersion;

let flags = RouterLsaFlags { asbr: false, border: false, virtual_link: false };
let lsa = originate_router_lsa(
    router_id,
    flags,
    &[RouterLsaLink::Stub { network: 0x0a0a_0a00, mask: 0xffff_ff00, metric: 10 }],
    None, // previous sequence number, when re-originating
); // Option<Lsa>: None means the sequence space is exhausted

// The codec leaves the §A.1 packet checksum zeroed; finalize it now, or
// a checksum-validating peer (BIRD, FRR) drops the packet.
let mut packet = OspfCodec::new(OspfVersion::V2).encode_vec(&hello)?;
finalize_v2_packet(&mut packet);
assert!(v2_packet_checksum_ok(&received));
```

`PointToPoint`, `Transit` and `Raw` are the other `RouterLsaLink`
variants, `finalize_v2_stream` patches a burst of back-to-back packets,
and `v2_packet_checksum_ok` excludes the 64-bit authentication field as
§A.1 prescribes. `originate_network_lsa` and `originate_summary_lsa`
(in `lr_ospf::abr`) have the same `Option<Lsa>` shape.

The raw transport is one socket per interface:
`OspfV2Transport::bind("eth0", multicast_loop)` joins both multicast
groups, binds to the device and sets TTL 1, and
`interface_v4_addrs("eth0")` returns the addresses a stub link or mask
needs. Without the platform backend every method returns
`OspfTransportError::Unsupported`, and `is_permission_denied()`
separates a missing `CAP_NET_RAW` from other failures.

Broadcast segments elect a DR/BDR. The election is a pure function; the
router holds the session state:

```rust
use lr_ospf::interface::{elect, Elector};
use lr_router::{OspfNetworkType, SessionConfig};

let h = router.add_session(SessionConfig::ospfv2(router_id, 0)
    .with_ospf_network_type(OspfNetworkType::Broadcast)
    .with_ospf_interface_ip(0x0a63_0101)  // 10.99.1.1, this router
    .with_ospf_neighbor_ip(0x0a63_0102))?; // 10.99.1.2, the neighbor

let electors = vec![
    Elector { router_id: 0x0101_0101, ip: 0x0a63_0101, priority: 1, stated_dr: 0, stated_bdr: 0 },
    Elector { router_id: 0x0202_0202, ip: 0x0a63_0102, priority: 1, stated_dr: 0, stated_bdr: 0 },
];
let (dr, bdr) = elect(&electors, 0x0a63_0101);
let changed = router.set_ospf_dr_state(h, dr, bdr)?; // Ok(false) = no change
```

The list must hold every bidirectional neighbor plus this router;
priority 0 routers are dropped by §9.4. `set_ospf_dr_state` re-runs the
§10.4 decision: a 2-Way neighbor that now qualifies advances to ExStart,
one that no longer qualifies demotes to 2-Way with the DBD state reset
(the AdjOK? event of §9.4 step 7), and the DR originates the Network-LSA
with a `RouterLsaLink::Transit`.

## Redistribution, areas and virtual links

```rust
use lr_core::addr::Prefix;
use lr_ospf::external::{ExternalDestination, ExternalMetricType};
use lr_router::OspfAreaType;

let dest = ExternalDestination::new(
    Prefix::new_v4([198, 51, 100, 0], 24), 40, ExternalMetricType::Type2);
let _ = router.ospf_redistribute(dest); // bool: originated or not
router.ospf_unredistribute(Prefix::new_v4([198, 51, 100, 0], 24));

// Areas: stub, totally-stubby, NSSA, totally-NSSA.
let converted = router.ospf_set_area_type(1, OspfAreaType::nssa(10));

// Virtual links (RFC 2328 §15), endpoint identified by Router ID.
router.ospf_add_virtual_link(1, 0x0202_0202);
let h = router.ospf_virtual_link_session(1, 0x0202_0202).unwrap();
let out = router.drain_output(h);
let up = router.ospf_virtual_link_up(1, 0x0202_0202);
router.ospf_remove_virtual_link(1, 0x0202_0202);
```

| Item | Notes |
| --- | --- |
| `ExternalDestination::p_bit` | Set by default; clear forbids translation |
| `ospf_redistribute_v3` / `ospf_unredistribute_v3` | RFC 5340 AS-external-LSA |
| `OspfAreaType::{stub, stub_no_summary, nssa, nssa_no_summary}(metric)` | Area policy |
| `ospf_router_lsa_flags(area)` | The V/E/B bits this router claims |

`ospf_redistribute` originates a type-5 into every attached regular
OSPFv2 area and a type-7 into each NSSA; `ospf_unredistribute` flushes
both. `ospf_set_area_type` converts an area at run time, flushing the
LSAs the new type refuses, and `ospf_virtual_link_up` is true while
transit-area SPF reaches the endpoint.

Stub and NSSA areas refuse type-5 and type-4 LSAs at install time and in
the AS-scope re-flood path; `no_summary` areas additionally refuse every
type-3 summary except the default. Border routers inject the default
with the configured metric: a type-3 summary for stub and `no_summary`
areas, a type-7 LSA with the P-bit clear for summary-importing NSSAs
(RFC 3101 §2.4/§2.7). The elected translator — highest Router ID among
the area's B-bit routers, the Nt-bit (RFC 3101 Appendix B) winning —
turns P-bit, non-zero-forwarding-address type-7s into AS-scoped type-5s,
and the semantics are OSPFv2-only. A virtual link comes up when the
router's SPF over the transit area reaches the endpoint, materializing
an area-0 session that restores border-router status; stub and NSSA
transit areas are refused, as is a stub backbone.

## Authentication

`lr_ospf::auth::CryptoAuth::new(key_id: u8, key: Vec<u8>)` signs OSPFv2
AuType 2 and `V3Auth::new(sa_id: u16, key: Vec<u8>)` the OSPFv3 auth
trailer; both default to HMAC-SHA-256, need `advance_seq()` before
signing, and expose `sign_trailer(...) -> Vec<u8>`.
`V3Auth::with_source([u8; 16])` supplies the IPv6 source the RFC 7166
§4.5 Apad construction needs. The digest follows RFC 5709 §3.3 — packet
checksum and authentication fields zeroed, trailer filled with Apad —
and anti-replay rides the monotonic crypto sequence number, 32-bit on v2
and 64-bit on v3.

## OSPFv3 inter-area LSA and segment routing

`lr_ospf::abr::originate_v3_inter_area_prefix_lsa(router_id, ls_id,
&SummaryDestination, prev_seq)` returns `Option<Lsa>`, the same
sequence-exhaustion contract as the v2 originators. Compare
`lsa.header.ls_type` against `LsaTypeV3::InterAreaPrefixLsa as u16`
(`0x2003`): `function_code()` is the low byte only. The body is a
reserved octet, a 24-bit metric, the prefix length, the prefix options,
two reserved octets, and the prefix padded to a 32-bit boundary.

Beyond the Prefix-SID shapes (RFC 7684 §2, RFC 8665 §5),
`lr_ospf::lsa::sr` covers adjacency segments and the mapping server:

```rust
use lr_ospf::lsa::sr::{
    adj_flags, link_type, originate_sr_link_lsa, SrAdjSidTlv, SrLinkAdvert,
};

let link = SrLinkAdvert { link_type: link_type::POINT_TO_POINT, link_id: [2, 2, 2, 2], link_data: [10, 0, 0, 1] };
let adj = SrAdjSidTlv { flags: adj_flags::V | adj_flags::L | adj_flags::P, mt_id: 0, weight: 0, sid: 24_000, neighbor_id: None };
let lsa = originate_sr_link_lsa(0x0101_0101, &[(link, vec![adj])], 3, None);
assert!(lsa.is_some()); // `neighbor_id: Some(rid)` selects the LAN shape
```

The Extended Link Opaque LSA (RFC 7684 §3, Opaque Type 8) carries one
Extended Link TLV per link with `SrAdjSidTlv` sub-TLVs: V and L set mean
an absolute local label, V and L clear mean an index into the
originator's SRGB. The Extended Prefix Range TLV (RFC 8665 §4) is the
mapping-server carrier, a contiguous range whose M-flagged Prefix-SID
applies to the range's first prefix.

`SrDatabase::from_lsdb(&lsdb)` exposes `links`, `prefixes`,
`prefix_ranges` and `srgbs`; `label_for(&prefix, &spf)` resolves a direct
prefix-SID to `(label, next_hop)`, `SrRangeMapping::index_for` resolves a
prefix inside a range, and `mapping_label_for(&prefix, &spf)` is the
mapping-server fallback — a direct advertisement wins (RFC 8661 §3.2.3).
`DefaultRouter::ospf_sr_databases()` projects every area, and
`set_ospf_sr_receive(true)` attaches the labels to Loc-RIB routes. The
OSPFv3 SRv6 counterpart is `set_ospf_srv6_receive`,
`set_ospf_v3_extended_lsas` and `ospf_srv6_databases()`.

## Graceful restart

The state machines in `lr_ospf::gr` are embedder-driven and have no
internal timers. `HelperEntry` is per `(area, neighbor Router ID)`:
`on_grace_lsa(HelperCheck)` runs the §3.1 checks, `poll(now_ms)` the
§3.2 (2) timeout, and `on_flush` / `on_topology_change` the other §3.2
exits. `RestartTracker::new(grace_period_secs, now_ms)` suppresses
topology-LSA origination while `recovering()`, takes adjacency state
through `observe_adjacency(rid, full)`, and reports the §2.2 result from
`poll`. `clamp_grace_period` bounds the period.

Received Grace-LSAs (v2's type-9 opaque, v3's LS type `0x000b`) never
enter the area LSDB, and each changed instance arrives on its own
channel, so a consumer that delegates `poll_events` to a ticker thread
still sees every one:

```rust
for ev in router.drain_ospf_grace_events() {
    // ev.area, ev.advertising_router, ev.grace_period_secs, ev.reason,
    // ev.interface_addr_v4 / ev.interface_addr_v6, ev.ls_age_secs,
    // ev.purged (true = the MaxAge flush: restart done, §3.2 (1))
    let _ = ev;
}
```

## C ABI and daemon surface

OSPF is reachable without Rust: the C ABI has
`lr_router_add_ospf_session`, `lr_router_add_ospfv3_session` and
`lr_router_add_ospf_session_ext` (version, area kind, MTU, network type,
interface and neighbor identity), and the daemon runs `--protocol ospf`
with `[ospf]` plus `[[ospf.area]]`, `[[ospf.interface]]`,
`[[ospf.prefix_sid]]`, `[[ospf.mapping_server]]` and
`[[ospf.srv6_locator]]`. See [`compat-matrix.md`](compat-matrix.md) and
[`../lr-cli.md`](../lr-cli.md).

## RFCs

- RFC 2328 — LSA formats (§A.4), checksum (§A.1), Hello fields (§A.3.2),
  DR election (§9.4), adjacency decision (§10.4), DBD exchange (§7.2,
  §10.3, §10.6, §10.9), LSA refresh and MaxAge (§14), Router-LSA
  (§12.4.1), Network-LSA (§12.4.2), externals (§12.4.3, §16.4),
  virtual links (§15).
- RFC 5340 — OSPFv3, including the inter-area-prefix-LSA (§A.4.5);
  RFC 9513 — SRv6 in OSPFv3.
- RFC 3101 — NSSA: type-7 processing (§2.5), translation (§2.4, §3.2),
  the Nt-bit (Appendix B), the default route (§2.7).
- RFC 5709 and RFC 7166 — OSPFv2 HMAC-SHA and the OSPFv3 auth trailer.
- RFC 3623 and RFC 5187 — graceful restart for v2 and v3.
- RFC 8665, RFC 7684 and RFC 8661 — segment routing, extended LSAs and
  the mapping-server resolution order.

## See also

- [`compat-matrix.md`](compat-matrix.md) — daemon knob names.
- [`router.md`](router.md) — sessions, events, redistribution pipes.
- [`core.md`](core.md) — the codec and FSM traits the OSPF types use.
