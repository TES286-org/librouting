# Project Status — Implemented vs. Missing

Honest gap analysis of librouting as of this revision. "Implemented"
means: code exists, is unit-tested, and (where marked) is exercised by
end-to-end or interop tests. "Partial" means the mechanism exists but a
documented subset is missing. "Missing" means not implemented.

Legend: ✅ implemented · 🟡 partial · ❌ missing · 🧪 E2E-verified
(in `cargo test`, the interop suite or the C/Go/Python harnesses)

## Layer 1 — core (`lr-core`)

| Capability | Status | Notes |
|-----------|:------:|-------|
| Prefix / IpAddr / Asn / RouterId types | ✅ | v4+v6, no-std compatible |
| Streaming codec primitives (ReadBuf/WriteBuf) | ✅ | |
| Generic FSM + timer framework | ✅ | |
| RIB data model (Route, RouteKey, Preference) | ✅ | administrative distances per protocol |
| Event model | ✅ | |

## Layer 2 — protocol crates

### BGP (`lr-bgp`)

| Capability | Status | Notes |
|-----------|:------:|-------|
| RFC 4271 FSM (6 states, timers, events) | ✅ 🧪 | incl. NOTIFICATION-as-fatal, session reset semantics |
| OPEN / KEEPALIVE / UPDATE / NOTIFICATION codec | ✅ 🧪 | interop-verified against BIRD 2 + FRR 10 |
| RFC 5492 capabilities | ✅ | |
| RFC 4760 MP-BGP (IPv4/IPv6 unicast NLRI) | ✅ | BIRD requires it — now advertised by default; FRR `bgp default ipv4-unicast` (W2.1) gates implicit IPv4 unicast |
| RFC 4893/6793 4-octet AS + dynamic negotiation | ✅ | downgrade to 2-byte when peer lacks the capability |
| RFC 4456 route reflection (ORIGINATOR_ID, CLUSTER_LIST) | ✅ | correct optional non-transitive flags |
| RFC 5065 confederations | ✅ | |
| RFC 7947 route server mode | ✅ | |
| RFC 9234 OTC / roles | ✅ | |
| RFC 4271 §6.8 connection collision detection | ✅ 🧪 | router-level resolver over sessions sharing a `SessionConfig::collision_group` (the group is the §6.8 "BGP Identifier known by means outside of the protocol"); sibling roles from `locally_initiated`; retains the connection initiated by the higher-BGP-Identifier speaker (FRR `bgp_collision_detect` parity, incl. examining OpenSent siblings), Established siblings always win, loser gets Cease / Connection Collision Resolution (RFC 4486 subcode 7) + teardown; equal BGP Identifiers are rejected by OPEN validation (FRR `BGP_NOTIFY_OPEN_BAD_BGP_ID` parity); daemon: bidirectional peers (`remote` + `address`) run both transports and converge to exactly one Established session; 5 router unit tests + 1 daemon e2e (`crates/lr-cli/tests/daemon_collision.rs`) |
| RFC 7911 Add-Path | ✅ 🧪 | capability negotiation (per-family send/receive), path-id NLRI framing (plain + MP), Adj-RIB-In keyed by path id, ranked N-path selection (`add_path_max_paths`), per-path export/withdrawal with rank-slot transmit ids, MRAI path sets, GR/LLGR per-path retention; two-daemon + full-stack e2e |
| RFC 5549 Extended Next-Hop | ✅ 🧪 | capability code 5 with `(NLRI AFI, NLRI SAFI, Nexthop AFI)` tuples in the RFC 5549 §4 / RFC 8950 §4 6-byte wire form (AFI:2, SAFI:2, NH-AFI:2 — byte-identical to BIRD 2.x and FRR, both of which OPEN-error non-multiples of 6); OPEN negotiation as the intersection of local + peer tuples (§4); 16-byte NEXT_HOP for IPv4 NLRI decoded as `V4OverV6`, MP_REACH `(AFI=1, 16B)` accepted; eBGP egress rewrites IPv4 NEXT_HOP to IPv6 when `(1,1,2)` is negotiated and `local_address` is IPv6; daemon `--extended-next-hop` / `--local-address-v6` / `--mp-family ipv6-unicast`; e2e coverage of all 8 dual-stack / MP-BGP / ENH / pure-v6 session modes + real BIRD interop (`tests/interop/bird_enh.sh`, unskipped) |
| RFC 2918 route refresh | ✅ | negotiated capability, outbound API, inbound re-advertisement through current export policy |
| RFC 7313 enhanced route refresh | ✅ | negotiated capability plus BoRR/EoRR demarcation around refreshed tables |
| RFC 4724 graceful restart | ✅ 🧪 | capability lists address families with F bits; stale-route retention, negotiated expiry purge, EoR-based resynchronization (BIRD-verified) |
| RFC 9494 LLGR | ✅ 🧪 | capability 71, per-family LLST, LLGR_STALE/NO_LLGR communities, least-preferred selection, egress gating, full retention lifecycle (BIRD-verified) |
| MRAI (Min. Route Advertisement Interval) | ✅ | configurable per-prefix batching (withdrawals immediate); defaults to 30 s eBGP / 5 s iBGP |
| MD5 / TCP-AO session authentication | ✅ 🧪 | RFC 2385 MD5 + RFC 5925 TCP-AO (hmac(sha1)/cmac(aes), ao_required) via `lr-osroute::tcp_auth`; kernel-signed SYNs, fail-closed arming; BIRD/FRR interop-verified |
| BGPsec | ❌ | out of scope for now |
| RFC 8277 BGP labelled unicast (BGP-LU) | ✅ 🧪 | `lr-mpls` (RFC 3032 label + label-stack codec, 4- and 3-octet wire forms) + `lr-bgp::path::labeled_nlri` (RFC 8277 §3 NLRI codec, MP_REACH/MP_UNREACH helpers); `lr-router::originate_labeled`; daemon `--labeled-network` / `labeled_networks` TOML + `--mp-family ipv4-labeled-unicast` / `ipv6-labeled-unicast`; daemon LSP mirror (W3-extra.3): Loc-RIB best routes program the kernel — tail pop for originated labels, head encap for received stacks; FFI + Go/Python bindings; 4 e2e tests + `tests/interop/labeled_unicast.sh` (two-daemon TCP, label=100 round-trip) + `tests/interop/mpls_lsp.sh` (kernel dataplane, ping through the LSP) |
| Best-path selection (RFC 4271 §9) | ✅ | incl. LOCAL_PREF, AS_PATH length, origin, MED, eBGP<iBGP, router-id tiebreak; LLGR_STALE routes least-preferred (RFC 9494 §4.4); `BestPathConfig::deterministic_router_id` exposed to daemon as FRR `bgp bestpath compare-routerid` (W2.2) |
| Route damping (`lr-damping`) | ✅ | RFC 2439-style figure-of-merit |
| BFD interaction (`lr-bfd`) | ✅ 🧪 | RFC 5880 §6.8 state machine + timing (peer detect-multiplier detection time, negotiated tx interval with jitter + 1s idle floor, Poll/Final parameter changes), §6.8.6 MUST-discard rules, Simple Password auth; `lr-osroute::bfd_transport` sockets (3784/4784, TTL 255, ephemeral source ports); daemon `--bfd` fast-fails BGP on BFD Down (BIRD-verified) |
| Policy: prefix-lists, community-lists, AS-path filters, route-maps | ✅ | `lr-policy` — all matchers evaluate real BGP path attributes (feature `bgp`, default): community lists (RFC 1997 first-match/implicit-deny), FRR-style AS-path patterns (`^ $ _`, substring parity incl. the bare-literal footgun), MED/prepend/add-community/set-tag set actions (`SetTag` writes the `Route.tag` field) |
| Import/export/safety hooks (violations configurable) | ✅ | safety net rejects AS loops / martians; can be disabled; FRR `bgp enforce-first-as` (W2.2) — router-level flag rejects eBGP UPDATEs whose leftmost AS_PATH AS != peer AS; FRR `allowas-in N` / BIRD `allow local as` (W2.3) — per-peer AS-loop tolerance; `local_as_count` fixed to use the FSM-normalized 4-byte AS_PATH |
| RFC 8212 default eBGP route behaviors | ✅ 🧪 | `lr-router` `set_ebgp_requires_policy` + per-session `set_session_policy`: external sessions (eBGP *and* confederation boundaries, §1) without explicit import policy discard received routes before Adj-RIB-In; without export policy advertise nothing — enforced at all three egress paths (per-prefix export, RFC 2918/7313 reannounce, initial dump; EoR still flows) with stale Adj-RIB-Out entries withdrawn; iBGP exempt; daemon default-on via `[bgp] ebgp_policy` with `accept-all` as the §3/Appendix-A deviation; FFI + Go/Python bindings |
| iBGP split-horizon, next-hop-self, LOCAL_PREF injection | ✅ 🧪 | |
| GTSM / TTL security (RFC 5082) | ✅ 🧪 | `lr-osroute::gtsm` (IP_TTL + IP_MINTTL / IPV6_MINHOPCOUNT on the listener, outbound TTL on the connector); daemon `--gtsm` / `--gtsm N`; live socket tests verify both happy-path and low-TTL rejection |
| Per-peer maximum-prefix | ✅ 🧪 | `with_maximum_prefix(N, action)` + `with_maximum_prefix_threshold(pct)`; warn / teardown / restart actions; CEASE NOTIFICATION subcode 1 (RFC 4486 §3); threshold + exceeded events latched per session; daemon `--max-prefixes` / `--max-prefix-action` / `--max-prefix-threshold` |
| Route aggregation | ✅ 🧪 | `add_aggregate(prefix)` / `remove_aggregate(prefix)` (RFC 4271 §9.2.2.2): originates aggregate with zeroed AS_PATH + ATOMIC_AGGREGATE + AGGREGATOR when specifics exist; withdraws when all specifics disappear; 5 e2e tests |
| BMP monitoring (RFC 7854) | ✅ 🧪 | `lr-bmp` crate (7 message types, streaming codec with split feed/next_message, IPv4/IPv6 peer headers); `DefaultRouter::set_bmp_sink` mirrors Peer Up/Down + Route Monitoring — Route Monitoring carries the full UPDATE (real path attributes, MP_REACH for IPv6), Peer Up precedes it per §4.6 ordering; daemon egress `--bmp-target` + collector mode `--protocol bmp --listen`; 10 unit + 3 e2e tests |
| MRT dump import/export (RFC 6396) | ✅ 🧪 | `lr-mrt` crate: streaming TABLE_DUMP_V2 reader/writer (peer index tables, RIB_IPV4/IPv6_UNICAST + ADDPATH) + BGP4MP decode; `lr mrt parse/rib` CLI; daemon runtime API `mrt <path>` dumps the Loc-RIB (BIRD-shape output, byte-verified against BIRD 2.17.5 `protocol mrt`); typed attribute interpretation behind the `bgp` feature |

### OSPF (`lr-ospf`)

| Capability | Status | Notes |
|-----------|:------:|-------|
| Packet codec v2 (RFC 2328) / v3 (RFC 5340) | ✅ 🧪 | hello, DBD, LSR, LSU, LSAck; version-dispatched DBD (v3 24-bit options, 10-byte body) and LSR (v3 16-bit LS type) layouts; v2 receive checksum validation (§8.2); LSR wire format (12-byte entries, §A.3.4) interop-verified |
| Neighbor FSM | ✅ | incl. §10.9 restart-to-ExStart on sequence mismatch (Fig. 12) |
| DBD/LSR exchange (§7.2, §10.3–§10.8) | ✅ 🧪 | `lr-ospf::exchange::DbExchange` + router wiring: master/slave election, header paging by MTU, LSR loading to Full, duplicate handling, RxmtInterval retransmit; BIRD 2 and FRR 10 interop-verified (Full adjacency + bidirectional routes + dead-timer teardown) |
| LSDB + LSA flooding | ✅ | per-area shared LSDB; same-area sessions flood to each other (§13.3 simplified) |
| SPF (Dijkstra) route computation | ✅ 🧪 | E2E test computes routes over a synthetic topology |
| Inter-area routes from summary-LSAs (§16.2) | ✅ 🧪 | reachable-border check, dist-to-border + summary metric, LSInfinity skip |
| ABR summary-LSA origination/flush (§12.4.3) | ✅ 🧪 | type-3 lifecycle with backbone-only loop guard, checksummed LSAs, MaxAge flush |
| AS-external routes (type-5 LSAs, §16.4) | ✅ 🧪 | origination via `ospf_redistribute`, AS-scope flooding across ABRs, §16.4 calculation (type-1/2 metrics, forwarding-address reachability + next hop), MaxAge flush lifecycle |
| Summary-ASBR LSAs (type-4, §12.4.3) | ✅ 🧪 | ABR origination for inter-area-only ASBRs, ASBR leg resolution in §16.4 (b) |
| External route redistribution API | ✅ 🧪 | `DefaultRouter::ospf_redistribute`/`ospf_unredistribute` |
| Cross-protocol redistribution engine | ✅ 🧪 | `RedistributionPipe` (BIRD `pipe` / FRR `redistribute`); BGP↔BGP, BGP→OSPF, OSPF→BGP; metric policy (Inherit/Fixed/Add); prefix-list filter; withdrawal propagation; 7 e2e tests |
| Designated-router election | ✅ 🧪 | `lr-ospf::interface::elect` implements §9.4 step-by-step (IP-identity electors per §A.3.2, BDR candidates exclude DR-declarers, DR falls back to the elected BDR, step-4 re-election so no router claims both DR and BDR) — cross-checked against BIRD 2 `ospf_dr_election` and FRR 10 `ospf_dr_election`; §10.4 adjacency gate in the router (`adjacency_viable`, Waiting blocks adjacency like BIRD `can_do_adj`), AdjOK? re-evaluation via `DefaultRouter::set_ospf_dr_state` (§9.4 step 7: promotion to ExStart with the initial DBD, demotion to 2-Way with the exchange reset); daemon broadcast mode end-to-end (`tests/interop/ospf_broadcast.sh`) |
| Network-LSA (§12.4.2) + transit links (§12.4.1.2) | ✅ 🧪 | `originate_network_lsa` (LS ID = the DR's IP interface address, Advertising Router = its router-id — they differ in general), `RouterLsaLink::Transit`; the DR originates the Network-LSA only when fully adjacent to ≥ 1 other router and flushes it (MaxAge) when that stops; the SPF derives the transit network's own prefix (LS ID masked by the network mask — BIRD `spfa_process_net` parity) and secondary addresses on the interface stay stub links |
| Area support | ✅ | multi-area v2 with ABR summaries (backbone-attached); OSPFv3 inter-area-prefix-LSA (0x2003) origination via `originate_v3_inter_area_prefix_lsa` |
| LSA refresh / aging / MaxAge flush | ✅ | periodic self-LSA re-origination at 1800 s, MaxAge expiry at 3600 s, MaxAge purge on receipt (§13) |
| Daemon transport (`--protocol ospf`) | ✅ 🧪 | `lr-osroute::ospf_transport`: raw `IPPROTO_OSPF` socket per interface, `SO_BINDTODEVICE` + `ip_mreqn` membership (224.0.0.5/6), TTL 1; `lr-ospf::origination`: Router-LSA builder + §A.1 packet checksum; two-daemon e2e over a veth pair (user namespaces, rootless); per-interface `network_type = "broadcast"` (TOML) runs the §9.4 election — Hello DR/BDR fields, §10.4 adjacency, transit links and Network-LSA end-to-end, with BIRD 2 on its default broadcast type (`tests/interop/ospf_broadcast.sh`) |
| Stub/NSSA areas | ✅ 🧪 | `OspfAreaType` (stub / no-summary / NSSA / totally-NSSA): type-5/type-4 refusal at install & AS-scope re-flood, ABR summary-default (type-3) and type-7 default injection, area-scoped type-7 origination, §3.2 translation to type-5 by the elected (highest-ID/Nt) border router; OSPFv2 only |
| Virtual links | ✅ 🧪 | `ospf_add_virtual_link` (§15): up while the transit-area SPF reaches the endpoint; materializes a backbone adjacency restoring ABR status; embedder-routed transport; stub/NSSA transit refused |
| Auth (cryptographic) | ✅ 🧪 | RFC 5709 HMAC-SHA-1/SHA-256 (v2 AuType 2 trailer; Ko/Apad MAC per §3.3, Auth Data Len = digest), RFC 7166 v3 auth trailer (RFC 7166 layout with 16-bit SA ID + 64-bit crypto-seq; §4.5 Apad MAC embedding the IPv6 source), anti-replay; unit tests |
| OSPFv3 inter-area-prefix-LSA (0x2003) | ✅ 🧪 | `originate_v3_inter_area_prefix_lsa` ABR origination; v3 LSA type enum; body encode/decode with IPv6 prefix support |
| Grace-LSA codec (RFC 3623 / RFC 5187) | ✅ 🧪 | `lr-ospf::lsa::grace` — link-local opaque type 9 with Opaque Type 3 / ID packing (RFC 5250 §3.1), TLV numbers 1=Grace Period / 2=Reason / 3=IP interface address, 4-octet TLV padding, `originate_grace_lsa_v2`; O-bit = RFC 5250 Opaque-LSA capability (DBD scope), NOT a GR signal; DD packets carry it (see the RFC 5250 row in `RFC_MAP.md`) |
| RFC 5250 Opaque-LSA capability signalling | ✅ 🧪 | the O-bit rides the DD options byte (`lr-ospf::exchange::db_desc_packet`) — lr both originates and floods opaque LSAs, so peers learn it can receive them; BIRD 2.0.8 captures a neighbour's options from DD packets only and skips opaque flooding to non-O-bit neighbours (`lsa_is_acceptable`), FRR's `ospf_gr.c` refuses Grace-LSA origination without `OSPF_OPAQUE_CAPABLE`; Hellos stay O-bit-free per RFC 5250 §3 (audit fix: the bit previously existed only in LSA headers, so BIRD never flooded opaque LSAs toward lr) |
| GR helper mode (RFC 3623 §3) | ✅ 🧪 | `lr-ospf::gr::HelperEntry` + daemon wiring — §3.1 checks, dead-timer retention, adjacency kept in the Router-LSA, §3.2 exits (flush/timeout/topology change via per-area topology versions), FRR `supported_grace_time` cap; default on (`--ospf-no-gr-helper`); BIRD-verified (`tests/interop/ospf_gr_bird.sh`) |
| GR restarting router (RFC 3623 §2) | ✅ 🧪 | state-file-persisted grace deadline, shutdown Grace-LSA flood, recovery with origination suppression + §2.2 adjacency/back-link verification, §2.3 flush + re-origination above the retained sequence floor; the flood window keeps servicing the protocol (inbound ACKs + Hellos + outbound — no re-origination/election) so a peer's post-Full LSA refresh gets ACKed and its §3.1 (2) helper check passes on a later flood round (this was the CI-red race in `ospf_gr_bird.sh`: 7 consecutive failures because the un-ACKed Router-LSA pinned the peer's LS retransmission list); `tests/interop/ospf_gr.sh` |
| Prefix Link-Local LSA (RFC 7684) | ✅ | `LsaTypeV3::PrefixLinkLocalAsLsa = 0x4004` + `v3_prefix_options` bits (Af, R) + `V3PrefixLinkLocalEntry` codec with optional Address Family ID; 8 unit tests |
| Segment Routing control plane (RFC 8665) | ✅ 🧪 | control plane (slice 1) + reception (slice 2). Slice 1: `lr-ospf::lsa::sr` — RI LSA SR-Algorithm + SID/Label Range TLVs (RFC 8665 §3), Extended Prefix Opaque LSA (Opaque Type 7) + Prefix-SID sub-TLV codec (RFC 7684 §2.1 descriptor order, RFC 8665 §5 Flags/Reserved/MT-ID/Algorithm/SID-Index, RFC 7684 §2.3 4-octet alignment), remote-label mapping (SRGB base + index); daemon originates RI + one Ext-Prefix LSA per `[[ospf.prefix_sid]]` (LSDB sequence floor, adjacency-driven re-origination, `no_php` = §5 NP flag / FRR `no-php-flag`); FRR 10.3 stores both LSAs (`tests/interop/ospf_sr_frr.sh`). Slice 2: `lr-ospf::srdb` — per-node SRDB projected from the area LSDB (SRGBs from RI LSAs, Prefix-SID mappings from Ext-Prefix LSAs); the router attaches resolved labels (closest reachable originator, §5 PHP rule for NP-clear adjacent originators, V/L + range guards) to intra/inter-area routes behind `[ospf] sr_receive`, and the shared kernel mirror installs the RFC 8660 encap routes; own SIDs get AF_MPLS pop routes with `install_kernel`; two-daemon lab `tests/interop/ospf_sr.sh` (API-verified labels both directions), FRR phase 2 kernel-gated. A wire audit against RFC 7684/8665 corrected the descriptor field order (Prefix Length before Flags) and the Prefix-SID sub-TLV shape (Reserved byte + 4-octet index) — the old encoding aborted FRR 8.1's ospfd (assert in `masklen2ip` once `segment-routing on` activates its SRDB parse). Missing: Adj-SIDs (§6), mapping server (M-flag), SRv6 |

### Babel (`lr-babel`)

| Capability | Status | Notes |
|-----------|:------:|-------|
| RFC 8966 codec (all core TLVs) | ✅ | magic 42 (0x2A) + version 2 header validated; §4.6 TLV bodies byte-exact (flags/reserved fields, Update Seqno/Metric order) |
| Neighbor / route table + feasibility (RFC 8966 §3.5.2) | ✅ | |
| Metric computation, seqno handling | ✅ 🧪 | E2E install/withdraw tests |
| RFC 9079 source-specific routing | ✅ 🧪 | Source Prefix **sub-TLV** (type 128) inside Update / Route Request / Seqno Request per §7.1; IPv4 + IPv6 source prefixes; route table keyed by (destination, source) tuple |
| RFC 8967 MAC authentication | ✅ 🧪 | stateful `BabelAuthInterface`: full §4.3 reception (MAC test once per key, preparse, PC verification), §4.3.1 Challenge Request/Reply resynchronization (30 s expiry, 300 ms request/reply rate limits), §4.4 neighbour-state expiry (lazy + gc), §5 incremental-deployment mode, keyed BLAKE2s-128 (§4.1 SHOULD) beside the mandatory HMAC-SHA256, §4.2 PC-overflow index rotation, variable-length MAC TLVs (unknown trailer TLVs skipped, body MAC TLVs ignored); two-daemon e2e (`tests/interop/babel_auth.sh`) |
| RFC 9467 relaxed PC verification | ✅ 🧪 | §3.1 unicast/multicast PC split (PCm/PCu, RECOMMENDED, default on), §3.2 window verification (OPTIONAL, configurable S), §3.3 combined mode with two windows; successful Challenge Replies seed both fields; covered by unit tests and the two-daemon e2e |
| Babel daemon transport (IPv6 link-local + IPv4 local networks) | ✅ 🧪 | daemon `--protocol babel` mode: UDP 6696, TTL=255 (RFC 8966 §2.1/§4), `%iface` scope carried into bind/join/send; two-socket transport (unicast on the local address + multicast on the group address — ff02::1:6 v6 / 224.0.0.111 v4 — with SO_REUSEADDR) so the destination class is exact; periodic Hello + Router-Id + Next-Hop + Update announcements (Loc-RIB minus babel-learned routes, split horizon, boot-unique router-id); `--network` origination; source-port/self-datagram filtering (§4.1); RFC 8967 auth wired in with per-neighbour state and challenge traffic unicast to the peer; `tests/interop/babel_auth.sh` (four phases) |

### LDP (`lr-ldp`)

| Capability | Status | Notes |
|-----------|:------:|-------|
| RFC 5036 codec (PDU / TLV / all 11 message types) | ✅ 🧪 | streaming `LdpCodec` (split feed/next-PDU), U/F-bit passthrough, FEC element set (prefix, wildcard, RD-free §3.4.1 subset), generic label, Status TLVs with the §3.9 status-code registry; no-std |
| §2.5.4 session FSM + §3.5.3 parameter negotiation | ✅ 🧪 | active/passive roles, Init validation (version, keepalive, advertisement discipline resolution, receiver label-space match), min-of-proposals negotiation, KeepAlive send/hold timers with expiry teardown |
| §3.5.2 discovery (link + targeted) | ✅ 🧪 | UDP Hellos with hold/refresh timers, adjacency creation + expiry, extended (targeted) discovery with accept policy, §2.5.2 active-role decision by transport-address comparison, session teardown when the last adjacency for a label space drops |
| Label bookkeeping (downstream unsolicited) | ✅ 🧪 | per-peer LIB (learn/advertise/withdraw), §3.5.8.1 request→mapping/No-Route answers, §3.5.10.1 withdraw→release, wildcard withdraw handling, Address message exchange before mappings (§3.5.5.1), address-based session matching |
| §3.5.3 Max PDU Length enforcement | ✅ 🧪 | TX: session messages batch into PDUs capped at the negotiated Max PDU Length; RX: an over-long PDU is answered with a fatal Bad PDU Length Notification before the session drops (FRR `S_BAD_PDU_LEN` parity) |
| §3.5.4 / §3.4.4.1 loop detection (Hop Count + Path Vector) | ✅ 🧪 | configurable per engine (`loop_detection`, default off per RFC 2.8); the Init proposes the D bit with PVLim; with it on, received Label Mappings and Label Requests are checked per A.2.6 (local config governs — the D bit is not negotiated): a Hop Count over the limit (0 = unknown, exempt), a Path Vector containing our LSR Id, or a Path Vector over the limit rejects the message — a looping Mapping is dropped and rejected with a Label Release carrying the Loop Detected Status TLV (E=0, non-fatal), a looping Request is answered with a Loop Detected Notification; `EngineEvent::LoopDetected` surfaces both; e2e over real sockets + unit tests |
| Engine glue (`LdpEngine`) | ✅ 🧪 | embedder moves bytes; TCP connection lifecycle (EstablishTransport/on_connected/on_accepted), session collision + No-Hello (§2.5.3) rejection, events for adjacency/session/address/label churn; two-speaker loopback e2e covers the full lifecycle plus keepalive expiry and both shutdown paths |
| Daemon transport (`--protocol ldp`, TCP/UDP 646) + FRR ldpd interop | ✅ 🧪 | wildcard UDP socket joins 224.0.0.2 per interface, link Hellos every hold-time third with TTL 1 and per-interface egress (`send_link_hello`), targeted Hellos unicast; TCP listener + active connects driven by `EstablishTransport` (connect failures return the peer to the engine for a retry on the next Hello); `[[ldp.bind]]` FEC-label pairs advertised downstream-unsolicited and re-advertised on every fresh SessionUp; self-Hello protection (PDUs carrying our own LDP Identifier are dropped); runtime API status counters; verified two-daemon over a veth pair (`tests/interop/ldp.sh`) and against FRR 10 ldpd (`tests/interop/ldp_frr.sh` — lr learns FRR's imp-null connected-FEC binding, FRR learns lr's explicit binding) |
| RFC 7552 IPv6 dual-stack procedures | ✅ 🧪 | §5.1 IPv6 basic discovery (ff02::2 link Hellos, hop-limit-255 GTSM check, link-local sources), §5.2 targeted over global unicast only (link-local rejected at config parse), §6.1 Dual-Stack capability TLV (0x0701) with the TR transport-connection preference (LDPoIPv6 default per §6.1.1), per-family Transport Address TLV handling (same-AF only, first-per-family accepted from noncompliant senders), one session per LDP Identifier, §6.1.1 dual-stack role decision (noncompliant both-AF/no-capability neighbours never get a session, preference mismatch resets with the fatal 0x32 notification), §7.1 per-family Address-message scoping, §7 IPv6 FEC bindings never advertised to legacy v4-only peers; single-stack IPv6 speakers supported; daemon: dual-stack UDP/TCP transports with a V6ONLY=0 listener; 13 unit tests + 3 loopback v6 e2e; FRR 10 ldpd dual-stack interop (`tests/interop/ldp_frr_v6.sh`) — session over the IPv6 transport (TR=6 both sides), IPv4 bindings exchanged both ways, IPv6 FEC (fd00:99::/64) learned from FRR's ipv6 address-family. LDPoIPv6 session TCPs send with hop limit 255 (RFC 7552 §9 / RFC 6720 — FRR enforces GTSM on AF_INET6 sessions by default and dropped the pre-fix 64-hops SYN-ACKs with TcpExtTCPMinTTLDrop); listener, accepted sockets and active connects all set it |
| Kernel MPLS mirror + label range allocation | ✅ 🧪 | `[ldp] install_kernel` mirrors the LIB into the Linux AF_MPLS dataplane — pop route per local binding (tail, local delivery via `lo`) and encap route per learned binding (head, pushing the peer's label toward its transport address); MappingWithdrawn and session teardown reverse both halves, graceful shutdown cleans up. `[ldp] label_min/label_max` (16..=1048575, fail-closed validation) drive automatic allocation for label-0 binds — the first free value inside the range, exhaustion is a startup error; `tests/interop/ldp.sh` phase 3 asserts kernel LSP state on both LSRs, an end-to-end ICMP echo through the LSP, and teardown reverting the encap route (gated on `mpls_router`) |
| §3.5.7.1.1 transit-LSR label allocation (independent control) | ✅ 🧪 | the engine allocates one local label per FEC learned from peers (platform range 16..=1048575, explicitly configured bind labels reserved), re-advertises it upstream to every operational peer with the §3.4.4.1 incremented hop count (unknown stays unknown; 255 stops propagation) and the §A.2.6.4 Path Vector + own LSR Id when loop detection is on, answers Label Requests with it, and re-pushes the full transit LIB on every fresh SessionUp; egress FECs (locally bound) are excluded, a FEC whose last non-reflected downstream binding disappears is withdrawn upstream and its label recycled. Next-hop selection without an IGP view: the first peer that advertised the FEC wins (bindings propagate outward from the egress, so the first mapping is causally the closest to it); on its loss the fallback picks the lowest LDP Id among *non-reflected* bindings only (arrived before the local allocation — a post-allocation mapping is the upstream echo of our own advertisement, and using it would loop the exchange); if none remains the LSP is torn down and reflected bindings are released. FEC keys are normalized to the §3.4.1.1 wire form (host bits never fit the encoding). Engine state surfaces as `TransitSwapChanged` / `TransitSwapRemoved` / `TransitLabelExhausted`; the daemon mirrors the swap into the kernel (`MplsRoute::swap` via a cached FIB lookup for the output interface, routed peers refused with a note) and exposes `ldp-transit-labels` in the runtime API; `[ldp] transit_allocation` (default on) / `--ldp-no-transit` disable it. Verified by a three-speaker loopback e2e (allocation, hop-count propagation, withdrawal cascade + label reuse, bind exclusion, transport-close teardown) and `tests/interop/ldp.sh` phase 3c: r2 — the middle LSR of a three-LSR chain — transit-allocates for r3's FEC and re-advertises to r1, r3's death tears the LSP down, and with kernel MPLS an ICMP echo crosses the full r1→r2(swap)→r3 LSP (gated on `mpls_router`) |
| RFC 3478 graceful restart (LDP GR) | ✅ 🧪 | FT Session TLV (RFC 3479 §8.2: type 0x0503, L flag, Reconnect Timeout + Recovery Time in ms) carried in the Initialization when `[ldp] graceful_restart` / `--ldp-graceful-restart` is on (off by default — FRR parity); as the SURVIVING peer (§3.3): an unexpected session failure (transport closed / keepalive expiry — a deliberate Shutdown never retains) keeps the failed peer's bindings and the kernel LSPs programmed, marked stale for min(peer's Reconnect Timeout, local Neighbor Liveness); on reconnection the peer's fresh Recovery Time decides — zero deletes the stale bindings immediately (MappingWithdrawn reverts the dataplane, the peer's re-advertisements relearn) while non-zero moves them into a recovery window (min(peer Recovery Time, local Maximum Recovery Time)) where re-arriving mappings refresh them and the leftovers are deleted at expiry. As the RESTARTING speaker the daemon honestly advertises Recovery Time 0 (its kernel mirror is deleted on shutdown); `[ldp] gr_reconnect_ms` (default 15000) and `gr_recovery_ms` (default 0) shape the advertisement. Verified by loopback e2e: retention on transport close (no withdrawal, label kept), zero-recovery purge + relearn with label reuse, recovery window without withdrawal, reconnect-window expiry purging the stale LSP |

## Layer 3 — router pipeline (`lr-router`)

| Capability | Status | Notes |
|-----------|:------:|-------|
| Adj-RIB-In → safety → import hooks → best-path → Loc-RIB → export hooks → Adj-RIB-Out | ✅ 🧪 | full pipeline, per-session attribution |
| Initial table dump on session establishment + End-of-RIB | ✅ 🧪 | BIRD/FRR see convergence markers; inbound EoR drives restart resynchronization |
| Session-down Adj-RIB-In purge (RFC 4271 §8.2.2 semantics) | ✅ | routes do not outlive their session — except negotiated RFC 4724/9494 retention |
| Reconnect-safe session restart | ✅ | FSM reset + established-latch clear |
| OSPF/Babel delta integration into Loc-RIB | ✅ | |
| Cross-protocol administrative distance merge | ✅ 🧪 | |
| Route reflection fan-out, originate/unoriginate APIs | ✅ | |

## Layer 4 — system integration (`lr-osroute`)

| Capability | Status | Notes |
|-----------|:------:|-------|
| Linux rtnetlink add/delete/list | ✅ 🧪 | used by `lr-daemon --install-kernel-routes` |
| Linux AF_MPLS netlink LSP install/delete | ✅ 🧪 | `lr-osroute::mpls_route` — Pop (label→IP), pop-local (label→`lo`, the kernel's own explicit-null shape for local delivery) and Swap (label→label) via `RTM_NEWROUTE`/`RTM_DELROUTE` with `RTA_DST`/`RTA_VIA`/`RTA_NEWDST`/`RTA_OIF`; LSP head-end encap routes (`RTA_ENCAP_TYPE = LWTUNNEL_ENCAP_MPLS` + nested `MPLS_IPTUNNEL_DST`, the `ip route add … encap mpls` form); netlink label attributes encode control-plane style (TTL/TC clear, BOS on the last entry, implicit-null refused — `nla_get_labels` rules); `RTA_VIA` family in host byte order (kernel `nla_put_via`/`nla_get_via`); `/proc/sys/net/mpls/platform_labels` capability detection; per-`MplsNetlink` socket, error decoding (EPERM/ENOENT/EEXIST/EOPNOTSUPP) |
| TCP MD5 / TCP-AO socket auth | ✅ 🧪 | `lr-osroute::tcp_auth` — arm_listener (wildcard keys) + connect_auth (keys before connect, signed SYN); Linux both, other platforms Unsupported |
| BSD route(4) socket (FreeBSD/NetBSD/OpenBSD/macOS) | ✅ | layouts pinned per-OS; cross-compile checked |
| Windows IP Helper API | ✅ | full link verified (x86_64-pc-windows-gnu) |
| Interface auto-resolution when `if_index == 0` | ✅ | gateway-based (Linux), longest-prefix (Windows) |
| Other systems | ✅ | documented extension path — see `docs/OS-INTEGRATION.md` |

## Layer 5 — embedder surface

| Capability | Status | Notes |
|-----------|:------:|-------|
| `lr-daemon` reference daemon (TCP I/O loop, reconnect, TOML incl. policy tables) | ✅ 🧪 | multi-peer (`[[peer]]` TOML tables / repeatable `--peer`): per-peer AS/hold-time/GR/auth/GTSM/max-prefix/Add-Path/families with `[bgp]` inheritance, one connector thread per outbound peer, listener matches inbound connections to peers by source address (fail-closed), centralized event consumption preserving Loc-RIB ordering; signals (SIGTERM/SIGINT graceful, SIGHUP reload), privilege drop, runtime API; `--protocol ospf` mode: `[[ospf.interface]]`/`[[ospf.area]]` config (stub/NSSA, no-summary, dotted-quad area IDs), dynamic per-`(area, router-id)` neighbor sessions, Hello origination, dead timer, per-area Router-LSA self-origination, raw-socket transport (above); `--protocol ldp` mode: `[[ldp.interface]]`/`[[ldp.targeted]]`/`[[ldp.bind]]` config, UDP 646 multicast discovery + TCP 646 sessions around `LdpEngine`, per-interface Hello egress, self-Hello protection, LDP counters in the API status; `--install-kernel-routes` mirrors best routes into the kernel: plain IP FIB plus, for BGP-LU routes, the RFC 8277 LSP endpoints (tail pop for originated labels, head encap for received stacks, implicit-null left to PHP) |
| Native BIRD/FRR config run (compat surface) | ✅ 🧪 | `lr-daemon --config bird.conf\|frr.conf`: dialect auto-detection (BIRD 2 / FRR / lr TOML, `--config-dialect` override, fail-closed on unknown content), the W5.1 converter pipeline feeds the regular TOML loader (one mapping, no drift), dialect-correct defaults (accept-all eBGP policy both, FRR `enforce-first-as` on), lr-specific `lr:` comment-directive extensions (globals + per-peer, invisible to real BIRD/FRR), unmapped constructs and non-BGP stanzas surface as startup warnings, SIGHUP/API reload re-parses through the same dialect path; `daemon_compat.rs` E2E + `tests/interop/compat_{bird,frr}.sh` against real BIRD 2 / bgpd (see `docs/COMPAT.md`) |
| C ABI FFI (`lr-ffi`) + cbindgen header | ✅ 🧪 | C harness in CI |
| Go bindings | ✅ 🧪 | `bindings/lr-go` |
| Python bindings | ✅ 🧪 | `bindings/lr-python` (cffi) |
| C++ bindings | ✅ | header-only RAII wrapper over the C ABI (`include/librouting.hpp`) |
| Signal handling / privilege drop / config reload / runtime API in daemon | ✅ 🧪 | SIGTERM/SIGINT close sessions with a NOTIFICATION (RFC 4271 §6.4) then exit 0; SIGHUP + API `reload` re-apply `networks` (bad config keeps running); `--user`/`--group` setuid/setgid after bind; `--api-socket` Unix-socket management plane (status/sessions/routes/reload/shutdown); `daemon_runtime.rs` E2E |

## Testing & CI

| Item | Status |
|------|:------:|
| Unit tests (workspace) | ✅ 42 binaries / 900+ tests |
| Two-daemon TCP E2E | ✅ 🧪 | `lr-tests/tests/tcp_smoke.rs` |
| Route-propagation E2E (originate → Adj-RIB-In → Loc-RIB → Adj-RIB-Out, withdrawal reversal) | ✅ 🧪 | `lr-tests/tests/route_propagation.rs` |
| Protocol-runtime E2E (OSPF + Babel delta integration into Loc-RIB) | ✅ 🧪 | `lr-tests/tests/protocol_runtimes.rs` |
| Add-Path E2E (two-daemon + full-stack multi-path propagation) | ✅ 🧪 |
| BGP session-mode E2E (8 modes: standard dual-stack, LL dual-stack, MP-BGP, MP-BGP+LL, ENH, ENH+LL, pure IPv6, pure IPv6+LL) | ✅ 🧪 | `lr-tests/tests/bgp_session_modes.rs` |
| RFC 8277 BGP-LU E2E (single-label, multi-label, implicit-null, withdrawal) | ✅ 🧪 | `lr-tests/tests/bgp_labeled_unicast.rs` |
| RFC 8277 two-daemon interop (TCP, label=100 for 198.51.100.0/24) | ✅ 🧪 | `tests/interop/labeled_unicast.sh` |
| BGP-LU → MPLS dataplane interop (two netns: tail pop + head encap mirrored into the kernel, ICMP echo through the LSP; kernel-gated) | ✅ 🧪 | `tests/interop/mpls_lsp.sh` |
| GTSM + maximum-prefix E2E (TTL security + per-peer prefix limit) | ✅ 🧪 | `lr-tests/tests/gtsm_max_prefix.rs` |
| Redistribution E2E (BGP↔BGP, BGP→OSPF, metric policy, prefix filter, withdrawal) | ✅ 🧪 | `lr-tests/tests/redistribution.rs` |
| Route-aggregation E2E (aggregate origination/withdrawal lifecycle) | ✅ 🧪 | `lr-tests/tests/route_aggregation.rs` |
| BMP monitoring E2E (Peer Up/Down + Route Monitoring end-to-end) | ✅ 🧪 | `lr-tests/tests/bmp_monitoring.rs` |
| Daemon hardening E2E (signals, reload, runtime API, privilege drop) | ✅ 🧪 | `lr-cli` integration tests |
| OSPF two-daemon E2E (raw-socket multicast adjacency, stub-net propagation both ways, dead-timer teardown) | ✅ 🧪 | `tests/interop/ospf.sh` — veth pair, one network namespace per daemon, rootless via `unshare -Urn` |
| OSPF broadcast-segment E2E (§9.4 DR/BDR election, §10.4 adjacency, Network-LSA + transit links, BIRD default-broadcast interop) | ✅ 🧪 | `tests/interop/ospf_broadcast.sh` — phase 1: two lr-daemons; phase 2: lr ↔ BIRD 2 on BIRD's default (broadcast) type |
| OSPF x BIRD E2E (real DBD/LSR exchange to Full adjacency, stub nets propagated in BOTH directions via birdc) | ✅ 🧪 | `tests/interop/ospf_bird.sh` — lr-daemon ↔ BIRD 2 over a veth pair |
| Babel MAC auth E2E (two-daemon: propagation, restart challenge resync, wrong-key fail-closed, RFC 8967 §5 incremental deployment) | ✅ 🧪 | `tests/interop/babel_auth.sh` — IPv4 multicast over loopback, rootless netns |
| LDP two-daemon E2E (multicast link-Hello discovery over a veth pair, TCP 646 session, bindings both directions, hold-time teardown) | ✅ 🧪 | `tests/interop/ldp.sh` — rootless netns, one LSR per namespace |
| LDP transit-LSR E2E (three-LSR chain: middle LSR transit-allocates and re-advertises upstream, peer death tears the LSP down and withdraws it; kernel-gated ICMP echo across the full r1→r2(swap)→r3 LSP) | ✅ 🧪 | `tests/interop/ldp.sh` phase 3c |
| MRT interop (BIRD 2 `protocol mrt` dump decoded by `lr mrt rib`; daemon Loc-RIB export round-trip with AS path + next hop) | ✅ 🧪 | `tests/interop/mrt.sh` |
| BMP collector E2E (daemon `--bmp-target` mirroring Peer Up + Route Monitoring to a daemon collector; routes + MRT dump via API) | ✅ 🧪 | `tests/interop/bmp.sh` |
| Multi-peer daemon E2E (two-outbound-peer fan-out + transit, inbound source-address matching, fail-closed rejection of unmatched peers, per-peer hold-time inheritance) | ✅ 🧪 | `crates/lr-cli/tests/daemon_multi_peer.rs` |
| Policy-in-config E2E (export filter, import filter, set-actions keep-route, unknown-reference fail-closed startup) | ✅ 🧪 | `crates/lr-cli/tests/daemon_policy.rs` |
| RFC 8212 E2E (default deny-in/deny-out, permit-all route-maps restoring flow, accept-all deviation, iBGP exemption, unknown mode fails closed) | ✅ 🧪 | `crates/lr-cli/tests/daemon_rfc8212.rs` |
| MD5 auth interop (two-daemon positive/negative + BIRD `password` + FRR `neighbor password`) | ✅ 🧪 |
| TCP-AO interop (two-daemon positive/negative; kernel >= 6.7, else SKIP) | ✅ 🧪 |
| Kernel-gated tests in a QEMU VM (tests/vm: tcp_ao + MPLS dataplane phases without host kernel/root support) | ✅ 🧪 |
| OSPF multi-area + ABR inter-area E2E (incl. two-router propagation) | ✅ 🧪 |
| OSPF external-route E2E (type-5 AS-scope propagation, type-4 ASBR legs, §16.4 type-1/2 + forwarding address, flush lifecycle) | ✅ 🧪 |
| OSPF stub/NSSA E2E (stub/totally-stubby gating + default injection, NSSA type-7 + P-bit translation with forwarding address, type-7/type-3 defaults, no-summary, translator election, flush lifecycle) | ✅ 🧪 |
| OSPF virtual-link E2E (§15 backbone partition repair, summaries over the virtual adjacency, teardown + stale-LSA MaxAge age-out, stub-transit refusal) | ✅ 🧪 |
| BIRD 2 interop (bidirectional) | ✅ 🧪 |
| BIRD 2 LLGR interop (RFC 9494 full lifecycle, both helper roles) | ✅ 🧪 |
| BFD monitoring fast-fail E2E (two-daemon SIGSTOP freeze: BFD tears BGP down in ~0.5s at 100ms×3 vs 60s hold) | ✅ 🧪 | `crates/lr-cli/tests/daemon_bfd.rs` |
| BFD x BIRD interop (single-hop + multihop sessions, `protocol bfd` + `bfd on`, SIGSTOP fast-fail) | ✅ 🧪 | `tests/interop/bfd_bird.sh` |
| FRR bgpd interop (bidirectional) | ✅ 🧪 |
| FRR ldpd interop (RFC 5036: adjacency, session to Operational, imp-null learned from FRR, lr's explicit binding in FRR's LIB) | ✅ 🧪 | `tests/interop/ldp_frr.sh` — zebra + ldpd in a rootless netns |
| C / Go / Python binding harnesses | ✅ 🧪 |
| fmt + clippy (-D warnings) | ✅ |
| Cross builds: aarch64-linux-gnu, x86_64-windows-gnu (full link), freebsd/netbsd (check) | ✅ |
| Coverage (tarpaulin) | ✅ |
| MSRV 1.88 build | ✅ |

## Roadmap v1 — complete

The original 15-item production roadmap is finished. In order:
graceful restart (RFC 4724) + LLGR (RFC 9494); OSPF LSA refresh/ABR
summaries (§12.4.3, §16.2); Babel HMAC (RFC 8967); BGP MD5/TCP-AO
(RFC 2385/5925); daemon hardening (signals, privilege drop, runtime
API); RFC 7911 Add-Path end-to-end; OSPF type-5/type-4 external routes
(§16.4); OSPF stub/NSSA areas (RFC 3101); OSPF virtual links (§15);
BGP dual-stack/MP-BGP/ENH session modes (RFC 5549, 8 modes e2e); OSPF
authentication (RFC 5709/7166) + OSPFv3 inter-area; BGP GTSM (RFC 5082)
+ maximum-prefix; cross-protocol redistribution; Babel daemon parity
(IPv6 link-local + RFC 9079 completion); BMP monitoring (RFC 7854).
BGP route aggregation (RFC 4271 §9.2.2.2) landed as a bonus item.
Per-item details live in the git history; the capability tables above
reflect the current state.

## Roadmap v2 — toward a complete routing stack

Six workstreams. Every item except the SR-MPLS placeholder has
landed; the per-item narratives (design decisions, evidence, the bugs
flushed out) live in [`ROADMAP.md`](ROADMAP.md) — this section tracks
the state, that file tracks the how and why.

| Workstream | Scope | State |
|------------|-------|-------|
| W1 — a complete daemon | multi-peer BGP daemon, config, runtime API, privilege drop, MRT/BMP, LDP/OSPF/Babel daemon modes | complete — see [`ROADMAP.md` §W1](ROADMAP.md#w1--a-complete-daemon-lr-daemon) |
| W2 — BIRD/FRR non-standard compatibility | RFC 8212 default-policy parity, FRR `default ipv4-unicast`, GTSM knobs, ENH defaults, `supported_grace_time`, MRT/BMP shape parity | complete — see [`ROADMAP.md` §W2](ROADMAP.md#w2--bird--frr-non-standard-compatibility-selective) |
| W3 — RFC coverage gaps | §6.8 collision, RFC 8212, OSPF DBD/LSR exchange, OSPF graceful restart (3623), RFC 7684, Babel MAC (8967/9467), BGP-LU (8277), MPLS dataplane, YANG models (9647/8177) | complete — see [`ROADMAP.md` §W3](ROADMAP.md#w3--rfc-coverage-gaps-from-rfc_mapmd) |
| W3-extra — comprehensive MPLS | label codec (3032), BGP-LU dataplane mirror, LDP (5036) + dual-stack (7552) + transit allocation + loop detection + GR (3478), kernel mirror | complete except SR-MPLS — see [`ROADMAP.md` §W3-extra](ROADMAP.md#w3-extra--comprehensive-mpls-support-new) |
| W4 — documentation | tutorial, per-protocol deep dives, binding guides, runbook | complete — see [`ROADMAP.md` §W4](ROADMAP.md#w4--documentation-guides-tutorials) |
| W5 — compatibility layer | `translate bird\|frr`, native BIRD/FRR config run (compat surface), capture/replay parity harness, VM test harness | complete — see [`ROADMAP.md` §W5](ROADMAP.md#w5--compatibility-layer) |
| W6 — research: BGP defects + exchange plane | BGP-DEFECTS + EXCHANGE-PLANE research docs, exchange-plane prototype (feature-gated, IANA experimental range) | prototype landed behind `exchange-plane` (off by default) — see [`ROADMAP.md` §W6](ROADMAP.md#w6--research-bgp-defects-and-a-private-exchange-plane) |

**Remaining open items** (nothing else is queued):

1. **SR-MPLS (RFC 8660/8667)** — the wire codecs, SRGB/prefix-SID
   configuration and origination have landed (W3-extra.5 slice 1,
   FRR-verified); the remaining SR-MPLS work is the receive path
   (Extended Prefix LSA parsing → SPF label attach → kernel AF_MPLS
   mirror), Adj-SIDs and the mapping-server shapes. RFC 9256 (Segment
   Routing Policy) builds on that data plane. (`ROADMAP.md`
   W3-extra item 5.)
2. **OSPFv3 daemon depth** — the OSPFv3 exchange/daemon mode shares
   v2's machinery but is not yet exercised by the daemon; the v3
   codec and LSA surfaces exist. (Tracked by the capability tables
   above and the RFC 5187 row in `RFC_MAP.md`.)

