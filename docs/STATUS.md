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
| Policy: prefix-lists, community-lists, AS-path filters, route-maps | ✅ | `lr-policy` — all matchers evaluate real BGP path attributes (feature `bgp`, default): community lists (RFC 1997 first-match/implicit-deny), FRR-style AS-path patterns (`^ $ _`, substring parity incl. the bare-literal footgun), MED/prepend/add-community set actions; route tags (`set tag`) still open
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
| DBD/LSR exchange (§7.2, §10.3–§10.8) | ✅ 🧪 | `lr-ospf::exchange::DbExchange` + router wiring: master/slave election, header paging by MTU, LSR loading to Full, duplicate handling, RxmtInterval retransmit; BIRD 2 interop-verified (Full adjacency + bidirectional routes) |
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
| Grace-LSA codec (RFC 3623 / RFC 5187) | ✅ | `lr-ospf::lsa::grace` — link-local opaque type 9 with Opaque Type 3 / ID packing (RFC 5250 §3.1), TLV numbers 1=Grace Period / 2=Reason / 3=IP interface address, 4-octet TLV padding, O-bit options helpers, `originate_grace_lsa_v2`; full GR future work |
| Prefix Link-Local LSA (RFC 7684) | ✅ | `LsaTypeV3::PrefixLinkLocalAsLsa = 0x4004` + `v3_prefix_options` bits (Af, R) + `V3PrefixLinkLocalEntry` codec with optional Address Family ID; 8 unit tests |

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
| RFC 7552 IPv6 dual-stack procedures | ✅ 🧪 | §5.1 IPv6 basic discovery (ff02::2 link Hellos, hop-limit-255 GTSM check, link-local sources), §5.2 targeted over global unicast only (link-local rejected at config parse), §6.1 Dual-Stack capability TLV (0x0701) with the TR transport-connection preference (LDPoIPv6 default per §6.1.1), per-family Transport Address TLV handling (same-AF only, first-per-family accepted from noncompliant senders), one session per LDP Identifier, §6.1.1 dual-stack role decision (noncompliant both-AF/no-capability neighbours never get a session, preference mismatch resets with the fatal 0x32 notification), §7.1 per-family Address-message scoping, §7 IPv6 FEC bindings never advertised to legacy v4-only peers; single-stack IPv6 speakers supported; daemon: dual-stack UDP/TCP transports with a V6ONLY=0 listener; 13 unit tests + 3 loopback v6 e2e (not yet verified against an external dual-stack LDP implementation) |
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

Six workstreams, ordered by expected user value. Work top-down inside
each workstream; cross-workstream ordering is a judgement call, but
protocol-correctness items (W3) always beat convenience items when in
doubt. Items get checked off here as they land.

### W1 — A complete daemon (`lr-daemon`)

The reference daemon must be able to run a real router on its own,
BIRD/FRR-style, without an embedder writing code.

1. ~~**Multi-peer daemon**~~ — done: `[[peer]]` array-of-tables in the
   TOML config with per-peer settings (AS, transport, auth, GTSM,
   maximum-prefix, Add-Path, MP families) inherited from the `[bgp]`
   globals when omitted; repeatable `--peer` CLI flag; one connector
   thread per outbound peer (independent reconnect/backoff); the
   listener accepts concurrent sessions and matches inbound
   connections to configured peers by source address (fail-closed);
   centralized event consumption so Loc-RIB ordering is preserved;
   the previously-ignored TOML keys (`graceful_restart_time`,
   `llgr_stale_time`, `llgr_max_stale_time`, `install_kernel`) now
   parse. Verified by 6 parser unit tests + 4 daemon E2E tests
   (fan-out/transit, inbound matching, unmatched rejection, per-peer
   hold time). Bidirectional peers (`remote` + `address` on one peer)
   wait for RFC 4271 §6.8 collision detection; heterogeneous listener
   auth keys are still future work.
2. ~~**Config completeness**~~ — done: the previously-ignored documented
   keys (`graceful_restart_time`, `llgr_stale_time`,
   `llgr_max_stale_time`, `install_kernel`) parse, and unknown keys /
   sections / tables now produce line-numbered warnings (kept
   non-fatal for forward compatibility) surfaced at startup
   (`config warning: …`) and on reload.
3. ~~**BFD in the daemon**~~ — done: `--bfd` (or per-peer `bfd =
   true`) starts one BFD session per peer via
   `lr-osroute::bfd_transport` (shared rx socket on 3784 single-hop /
   4784 multihop with the RFC 5881 §5 TTL filter, per-session
   ephemeral source ports) and fast-fails BGP: a BFD Up→Down
   transition tears the session down with a CEASE NOTIFICATION and a
   route purge instead of waiting out the hold timer; the connector
   holds off reconnecting while BFD is down (after first Up — BIRD
   `bgp_bfd_notify` parity). Timing: `[bgp] bfd_min_tx_ms /
   bfd_min_rx_ms / bfd_multiplier` globals with per-peer overrides
   and CLI flags; `bfd_multihop = true` switches to RFC 5883. Verified
   by `crates/lr-cli/tests/daemon_bfd.rs` (SIGSTOP freeze: BGP down
   in ~0.5s at 100ms×3 vs a 60s hold time) and
   `tests/interop/bfd_bird.sh` (BIRD `protocol bfd` + `bfd on`, both
   single-hop and multihop). Landing this drove an lr-bfd
   wire-correctness overhaul: RFC 5880 §4.1 flag bits (the old code
   had a phantom ECHO flag on the Final bit and no Poll/Final), the
   IANA auth type codes, §4.2-§4.4 auth section layouts, and the
   §6.8.6 state machine (Down+Init→Up / Init+Init→Up — the old
   mapping deadlocked two conforming peers in Init forever).
4. **Policy in config + reuse** (external request) — three slices,
   in order:
   a. ~~**Policy engine completion**~~ — done: new `lr-policy::bgp`
      module decodes/encodes AS_PATH, COMMUNITIES and MED straight
      on the raw attribute bag (no whole-bag conversion); community
      lists do first-match/implicit-deny against real communities;
      AS-path filters get an FRR-parity pattern matcher (`^ $ _`,
      documented substring semantics); `set med`, `as-path prepend`
      and `add community` now write real attributes. Feature-gated
      `lr-policy → lr-bgp` (default on, no cycle). 14 new unit tests
      against real attribute bytes.
   b. ~~**Policy objects in TOML**~~ — done: `[[prefix-list]]`,
      `[[as-path-list]]`, `[[community-list]]`, `[[route-map]]`
      tables with per-peer `import`/`export` attachment; entries in
      ascending `entry` order; unknown keys inside policy tables and
      unknown references are startup errors (fail closed). Router
      export hooks gained a destination-aware variant
      (`ExportHook::on_export_to`) so per-peer export policy
      dispatches on the egress session — backward compatible via a
      default method. `lr_policy::PolicySet` + `PolicyHooks` are the
      reusable bridge; the daemon wires them in one block. E2E:
      export filter, import filter, set-actions keep-route,
      unknown-reference startup failure (4 tests).
   c. ~~**Peer templates**~~ — done: `[peer-template.<name>]` tables
      holding any `[[peer]]` key (incl. policy attachments); peers
      pull them in via `extends = "<name>"`, per-peer keys override,
      template chains resolve least-specific-first, cycles and
      unknown names are startup errors. Resolves the copy-paste
      burden of multi-peer configs without inventing a new language
      (TOML has no anchors). 3 parser unit tests + template e2e.
5. ~~**OSPF daemon mode**~~ — done: `--protocol ospf` with
   area/interface configuration (`[[ospf.area]]` +
   `[[ospf.interface]]` TOML tables, `--ospf-interface` /
   `--ospf-area` / `--ospf-hello-interval` / `--ospf-dead-interval`
   CLI flags, fail-closed key schemas). Transport: one raw
   `IPPROTO_OSPF` socket per interface (`lr-osroute::ospf_transport`,
   Linux) with `SO_BINDTODEVICE` + `ip_mreqn` multicast scoping; the
   daemon originates Hellos (with the heard-router list), discovers
   neighbors dynamically — one session per `(area, router-id)`, one
   anchor session per area registering the area type — originates
   and re-originates the Router-LSA per area (stub links from
   interface addresses, p2p links per Full adjacency), verifies
   inbound packet checksums and finalizes them on egress. Verified by
   `tests/interop/ospf.sh`: two daemons over a veth pair (one network
   namespace each, rootless via `unshare -Urn`) reach Full adjacency,
   exchange stub nets both directions (10.99.2.0/24 ↔ 10.99.3.0/24)
   and tear the session down on the dead timer. Broadcast segments
   (`network_type = "broadcast"`) run the RFC 2328 §9.4 DR/BDR
   election end-to-end — see the OSPF capability table. Scope notes:
   OSPFv2 only (v3 needs Link-LSAs); auth and reload are not wired
   into the daemon yet.
6. ~~**Operational tooling**~~ — done: the `lr-mrt` crate (RFC 6396)
   reads and writes TABLE_DUMP_V2 dumps (peer index tables,
   RIB_IPV4/IPv6_UNICAST incl. the ADDPATH variants; BGP4MP decode for
   stream tools) and `lr mrt parse|rib` inspects them; the daemon's
   runtime API `mrt <path>` dumps the Loc-RIB in the exact shape
   BIRD's `protocol mrt` produces (byte-verified in the interop suite,
   BIRD dump -> lr parse and back). BMP grew both directions: egress
   `--bmp-target` (channel + reconnecting sender thread wiring the
   router sink) and collector mode `--protocol bmp --listen` (accepts
   stations, decodes Peer Up/Down + Route Monitoring with the split
   feed/next_message codec API, mirrors monitored prefixes into the
   Loc-RIB via `originate_with_attributes` so routes/status/mrt serve
   them). Route Monitoring now carries the full UPDATE (real path
   attributes, MP_REACH for IPv6) and Peer Up mirrors before it even
   under TCP coalescing. RIB *restore* is `originate_with_attributes`
   + `parse_file` — an offline router fed from a dump (the MRT
   round-trip e2e covers the encode side; a full restore CLI remains
   future work). Known limitation: Debian's bird2 package ships
   without the BMP protocol, so the BMP e2e uses two lr-daemons; a
   BIRD-side BMP test waits on a BMP-enabled build.

### W2 — BIRD / FRR non-standard compatibility (selective)

Where BIRD or FRR deviate from (or extend) the RFCs in ways that
matter for interoperation, support the behaviour behind explicit
flags; never break standards compliance by default.

1. ~~**FRR `bgp default ipv4-unicast`**~~ — done: `PeerConfig`
   gained a `default_ipv4_unicast: bool` field (default `true` —
   matches FRR's default and the RFC 4271 implicit IPv4 unicast
   family) plus a helper `ipv4_unicast_active()` returning
   `default_ipv4_unicast || mp_families.contains(IPV4_UNICAST)`. The
   FSM gates legacy-section IPv4 NLRI (withdrawals, NLRI, EoR) on it
   in `lr-bgp::fsm::handle_update_in_established`; `advertise.rs`
   gates `advertise()`, `withdraw_paths()` and `send_end_of_rib()`;
   Add-Path / LLGR `advertised_families()` drop the implicit IPv4
   unicast when the flag is off. The router gained
   `set_session_default_ipv4_unicast(h, on)`; `SessionConfig`
   carries the field through `add_session` to PeerConfig. The daemon
   wires the router-level `[bgp] default_ipv4_unicast = bool` (default
   `true`) + CLI `--default-ipv4-unicast` / `--no-default-ipv4-unicast`
   + per-peer override `[peer] default_ipv4_unicast = bool`. The
   daemon's mp_families builder now always overrides the
   `SessionConfig::bgp()` default (which keeps IPv4 unicast for BIRD
   capability interop): when `default_ipv4_unicast=true` it ensures
   `IPV4_UNICAST` is in the family list (BIRD requires the
   capability to match one of their channels), when `false` it leaves
   the list as configured so the user's explicit `mp_families`
   determines what's active. FFI:
   `lr_router_set_default_ipv4_unicast(r, session, enabled)`, with
   Go (`Router.SetDefaultIPv4Unicast`) and Python
   (`Router.set_default_ipv4_unicast`) mirrors; the C harness
   smoke-tests the on/off round-trip + unknown-handle fail-closed.
   Verified by 4 PeerConfig unit tests, 3 FSM tests (EoR, NLRI,
   withdrawals all suppressed when the flag is off), 1 daemon_config
   unit test, 3 daemon e2e tests (default-on propagates routes,
   `--no-default-ipv4-unicast` suppresses them, explicit
   `--mp-family ipv4-unicast` reactivates), and the C/Go/Python
   binding smoke tests.
2. ~~**FRR `bgp enforce-first-as` + `bgp bestpath compare-routerid`**~~
   — done: the router gained `set_enforce_first_as(bool)` (default
   off — matches FRR `no bgp enforce-first-as` and the RFC 4271 §6.3
   "MAY reject" latitude). With it on, an UPDATE from an external
   peer (eBGP or a confederation boundary, mirroring the W2.1
   scope) whose leftmost AS_PATH sequence segment's first AS is not
   the peer's negotiated AS is dropped before Adj-RIB-In and the
   rejection is surfaced once per session as a `RouterEvent::Log`;
   iBGP and confederation-internal sessions are exempt. The decoder
   uses the FSM-normalized canonical AS_PATH (always 4-byte after the
   `lr-bgp` codec's AS4_PATH merge) — no wire-width guessing. FRR
   `bgp bestpath compare-routerid` is exposed through the existing
   `BestPathConfig::deterministic_router_id` knob: the daemon wires
   it via `[bgp] bestpath_compare_routerid = bool` (default true —
   RFC 5004 deterministic, the inverse of FRR's default). Daemon
   surfaces both as `--enforce-first-as` / `--no-enforce-first-as`
   and `--bestpath-compare-routerid` / `--no-bestpath-compare-routerid`
   CLI flags plus the `[bgp] enforce_first_as` /
   `[bgp] bestpath_compare_routerid` TOML keys; the startup status
   printout names both. FFI: `lr_router_set_enforce_first_as` mirrors
   the C ABI; Go (`Router.SetEnforceFirstAs`) and Python
   (`Router.set_enforce_first_as`) bindings round-trip; the C harness
   smoke-tests the new entry point. Verified by 4 router unit tests
   (default-off accepts, accepts the well-formed case, rejects a
   forged AS_PATH via a hand-rewritten wire UPDATE, iBGP exemption)
   and 2 daemon e2e tests (the flag parses, legit traffic still
   flows, the status printout names the new knobs).
3. ~~**BIRD `bgp allow local as`**~~ — done: `PeerConfig` gained a
   `local_as_tolerance: u32` field (default `0` = reject any
   occurrence of the local AS in a received AS_PATH — RFC 4271
   §9.1.2.15). The router's `import_route` now consults the per-peer
   tolerance when the safety net's `reject_as_loop` fires: on an
   eBGP peer with `tolerance > 0`, the route is admitted when the
   local AS count is ≤ tolerance (FRR `allowas-in N`); `u32::MAX` is
   the `allowas-any` sentinel. iBGP is exempt (FRR/BIRD scope the
   relaxation to eBGP). The new `count_local_as` helper reads the
   FSM-normalized canonical AS_PATH via `PathAttributes::as_path()`,
   fixing a latent width-guessing bug in the safety net's
   `local_as_count` that silently broke `reject_as_loop` for routes
   from any modern peer sending 4-byte AS_PATH (the FSM rewrites
   tag-2 AS_PATH to 4-byte, but the old counter treated tag-2 as
   2-byte when AS4_PATH was absent — undercounting local AS
   occurrences). The router gained
   `set_session_local_as_tolerance(h, N)`; `SessionConfig` carries
   the field through `add_session`. The daemon wires the router-wide
   `[bgp] allow_local_as = N|any|true|false` (default `0`) + CLI
   `--allow-local-as [N]` / `--allowas-any` + per-peer override
   `[peer] allow_local_as`. FFI:
   `lr_router_set_local_as_tolerance`, with Go
   (`Router.SetLocalAsTolerance`) and Python
   (`Router.set_local_as_tolerance`) mirrors. Verified by 6 router
   unit tests (default-0 rejects, tolerance=1 admits 1 / rejects 2,
   allowas-any admits arbitrary, unknown-handle fail-closed,
   post-start fail-closed), the C/Go/Python binding smoke tests,
   and the safety-net fix is exercised by the existing
   `rejects_as_loop` test (2-byte path) plus the new router tests
   (4-byte path). The extended-community syntax sugar
   (`rt:`/`ro:` literals) already parses; no further action needed.
4. ~~**Soft reconfiguration inbound**~~ — done: the router gained a
   `pre_policy_adj_rib_in` storage (a second `AdjRibIn` instance)
   that retains the **raw** received routes before the safety net
   or import hook chain runs, for peers with `soft_reconfig_inbound`
   enabled. `PeerConfig` gained `soft_reconfig_inbound: bool` (default
   off — FRR's default; the cost is duplicate RIB memory per peer);
   `SessionConfig` carries the field through `add_session`;
   `DefaultRouter::set_session_soft_reconfig_inbound(h, on)` is the
   post-`add_session` mutator. `import_route` populates the pre-policy
   RIB before any safety net or import hook runs; `withdraw_from_session`
   and `session_down_cleanup` purge it in lockstep with the post-policy
   RIB. `DefaultRouter::soft_reconfig_inbound(h)` is the FRR `clear ip
   bgp * soft in` op: it re-runs the import hooks against the stored
   pre-policy routes, replaces the session's entries in the post-policy
   `adj_rib_in`, and re-selects every affected prefix — without
   re-fetching from the peer. `DefaultRouter::adj_rib_in_snapshot(h)`
   exposes the pre-policy view to embedders / the runtime API. The
   daemon wires the router-wide `[bgp] soft_reconfig_inbound = bool`
   (default off) + CLI `--soft-reconfig-inbound` /
   `--no-soft-reconfig-inbound` + per-peer override
   `[peer] soft_reconfig_inbound`. FFI:
   `lr_router_set_soft_reconfig_inbound` +
   `lr_router_soft_reconfig_inbound`, with Go
   (`Router.SetSoftReconfigInbound` / `Router.SoftReconfigInbound`) and
   Python (`Router.set_soft_reconfig_inbound` /
   `Router.soft_reconfig_inbound`) mirrors. Verified by 7 router unit
   tests (retains-pre-policy-view, off-does-not-retain,
   re-evaluates-after-policy-change, noop-when-flag-off,
   unknown-handle-noop, mutator-unknown-handle-fail-closed,
   mutator-post-start-fail-closed) and the C/Go/Python binding smokes.
5. Maintain the interop scripts (`tests/interop/*`) as the acceptance
   gate for every compatibility item.


### W3 — RFC coverage gaps (from `RFC_MAP.md`)

Highest-value missing/partial standards, in rough order:

1. ~~**BFD multihop**~~ — done, as RFC 5883 (the roadmap previously
   mis-cited this as "RFC 8562/5881": 8562 is *Multipoint* BFD, and
   5881 is *single-hop*). Multihop sessions ride UDP 4784 with no
   TTL 255 requirement (RFC 5883 §5/§3), demultiplexed by Your
   Discriminator with the source-address fallback for discovery
   packets (§4.1). The daemon exposes it as `--bfd-multihop` /
   `bfd_multihop = true`. BIRD-verified end-to-end
   (`tests/interop/bfd_bird.sh` phase 2: multihop BFD + multihop eBGP
   against `neighbor ... multihop` + `bfd on`). Landing this also
   fixed lr-bfd's core RFC 5880 wire bugs (see W1.3) — without them
   no BFD interop worked at all. Keyed-hash auth over multihop
   (RFC 5883 §6 SHOULD) remains future work (Simple Password is
   supported).
2. ~~**RFC 8212** default eBGP route behaviors~~ — done: the router
   gained `set_ebgp_requires_policy` + per-session
   `set_session_policy(import, export)`; with the mode on, an external
   session (eBGP or a confederation boundary — §1 counts both) without
   an explicit import policy drops received routes before Adj-RIB-In,
   and without an export policy advertises nothing at any of the three
   egress paths (per-prefix export, RFC 2918/7313 reannounce, initial
   dump — EoR still flows so peer GR logic converges). Removing an
   export policy re-evaluates every prefix and withdraws what the
   session carried; iBGP and confederation-internal sessions are
   exempt. The daemon enables the mode by default
   (`[bgp] ebgp_policy = "rfc8212"`; `accept-all` is the §3/Appendix-A
   "insecure-mode" deviation), warns per policy-less external peer at
   startup, and unknown modes fail closed. Verified by 8 router unit
   tests + 5 daemon e2e tests (deny both directions, permit-all
   route-maps restoring flow, accept-all deviation, iBGP exemption,
   unknown mode rejected); the protocol-subject interop scripts pin
   `--ebgp-policy accept-all` on their lr sides. Landing this also
   fixed daemon-level iBGP propagation: locally originated routes
   carried no NEXT_HOP and iBGP egress preserved the gap, so peers
   discarded the UPDATEs (RFC 4271 §6.3) — egress now synthesizes the
   local address (§5.1.3) and the daemon originates `network`s with
   their local address, which also un-breaks kernel FIB installs.
3. ~~**OSPF DBD/LSR exchange**~~ — done: the router runs the full
   RFC 2328 §7.2 synchronization per session (`lr-ospf::exchange`):
   master/slave election per §10.3, MTU-bounded LSA-header paging,
   request-list loading to Full, duplicate DBD handling and
   RxmtInterval retransmissions from tick(). The neighbor FSM now
   restarts to ExStart on sequence mismatch (§10.9/Fig. 12) instead
   of tearing the neighbor down. Landing this against BIRD 2.17.5
   flushed out four latent wire bugs (10-byte LS-Request encoding,
   wrong DBD I-bit value, big-endian MTU ioctl parse, multi-packet
   IP datagrams) and required MinLSArrival-paced Router-LSA
   re-origination (§14). Verified by `tests/interop/ospf_bird.sh`:
   Full adjacency with BIRD over a veth pair and stub nets
   propagated in both directions — OSPF interop is unlocked. FRR
   interop and OSPFv3 exchange remain open. Broadcast-segment DR
   election landed on top (see the OSPF capability table and
   `tests/interop/ospf_broadcast.sh` — BIRD's default broadcast type
   included).
4. ~~**RFC 5187 / RFC 3623** OSPF graceful restart — Grace-LSA codec~~
   — foundation slice done: new `lr-ospf::lsa::grace` module
   implements the Grace-LSA body codec (TLV encode/decode for Grace
   Period, Reason, IPv4/IPv6 Interface Address, Address Family), the
   Opaque LSA ID packing (RFC 5250 §3.1 — 8-bit Opaque Type `3` +
   24-bit Opaque ID), the O-bit helpers for the OSPF options field
   (RFC 3623 §1 / RFC 5187 §1), and `originate_grace_lsa_v2()`
   (builds a finalized Opaque-AS-LSA with the right LS type, LS ID
   packing, and §C.4 checksum). 15 unit tests: TLV roundtrips
   (minimal, full v2 with IPv4 + AF, v3 with IPv6), missing-mandatory
   failure, unknown-TLV skip, truncated-TLV failure, Opaque ID
   packing, O-bit helpers, sequence advance, LSA checksum
   validation, interface-address TLV helper, GraceReason
   roundtrips. The full graceful restart (neighbour LSA retention,
   Hello O-bit advertisement, daemon integration) remains future
   work — this slice is the wire-level foundation both BIRD and FRR
   require for interop.
5. ~~**RFC 7684** OSPFv3 prefix link-local attribute LSA types~~
   — done: `LsaTypeV3` gained `PrefixLinkLocalAsLsa = 0x4004`
   (AS-scope, function 4 — RFC 7684 §2.1) with `from_u16`,
   `function_code`, and `Display` support. The `v3_prefix_options`
   module documents all RFC 5340 §A.4.1.1 bits (P, MC, LA, NU) and
   the two RFC 7684 §3 additions (Af-bit `0x80`, R-bit `0x10`). New
   `V3PrefixLinkLocalEntry` struct + `encode_v3_prefix_link_local_entry`
   / `decode_v3_prefix_link_local_entry` / `encode_v3_prefix_link_local_body`
   / `decode_v3_prefix_link_local_body` codec handles the
   variable-length prefix body with the optional one-byte Address
   Family ID (present only when the Af-bit is set). 8 unit tests:
   prefix-options bit values, single-entry roundtrip (basic + with
   Af-bit + without Af-bit), multi-entry body roundtrip, truncated
   body failure (prefix-options byte, prefix bytes, Af-bit af_id),
   empty body, new LSA type parse + display.
6. ~~**Babel-MAC completion**~~ — done (the item previously cited
   "RFC 9289", which is an ONC-RPC/TLS document — a wrong citation;
   the DTLS-less MAC variant is RFC 8967, and RFC 9467 updates it).
   New `BabelAuthInterface` in `lr-babel::auth` implements the full
   RFC 8967 §4.3 reception algorithm: per-neighbour (Index, PC) state
   keyed by source address (created only after the MAC test passes),
   §4.3.1 Challenge Request/Reply resynchronization with a 30 s
   challenge expiry and 300 ms request/reply rate limits, §4.4
   neighbour-state expiry (lazy + explicit gc), and §5 incremental
   deployment (send authenticated, accept unauthenticated). MAC
   algorithms: the mandatory HMAC-SHA256 plus keyed BLAKE2s-128
   (§4.1 SHOULD). §4.2 PC overflow now rotates to a fresh index.
   RFC 9467 landed on top: §3.1 unicast/multicast PC split
   (RECOMMENDED, default on), §3.2 window verification (OPTIONAL,
   configurable size), §3.3 combined mode. The daemon transport signs
   and verifies every datagram (`--babel-key`/`[[babel.key]]`,
   `--babel-accept-unauthenticated`, `--babel-no-pc-split`,
   `--babel-pc-window`), and gained the two-socket unicast/multicast
   transport, periodic Hello/Router-Id/Next-Hop/Update announcements
   with boot-unique router-ids, and `--network` origination.
   Verified by 27 new unit tests plus the two-daemon e2e
   (`tests/interop/babel_auth.sh`: propagation, restart challenge
   resynchronization, wrong-key fail-closed, incremental deployment).
7. ~~**RFC 8277** BGP labeled prefixes (BGP-LU)~~ — done: new `lr-mpls`
   crate (RFC 3032 label + label-stack codec, 4- and 3-octet wire
   forms); `lr-bgp::path::labeled_nlri` (RFC 8277 §3 NLRI codec with
   MP_REACH/MP_UNREACH helpers); `lr-router::originate_labeled`
   injects labelled routes into Loc-RIB; egress encodes the stack into
   labelled MP_REACH (BGP peer FSM dispatches on family for both
   directions); `lr-osroute::mpls_route` (Linux `AF_MPLS` netlink
   route push/swap/pop with `RTA_DST`/`RTA_VIA`/`RTA_NEWDST` and
   `/proc/sys/net/mpls/platform_labels` capability detection);
   `lr-ffi` + Go/Python bindings (`lr_router_originate_labeled_v4/v6`,
   `lr_mpls_platform_labels`); daemon `--labeled-network` /
   `labeled_networks` TOML + `--mp-family ipv4-labeled-unicast` /
   `ipv6-labeled-unicast`; 4 e2e tests + a two-daemon interop script
   (`tests/interop/labeled_unicast.sh`). RFC 5666 EPE remains future
   work.
8. YANG models (RFC 9647 Babel, key chains RFC 8177) — low priority
   unless an embedder asks.

### W3-extra — Comprehensive MPLS support (new)

Standalone workstream tracking the comprehensive MPLS goal. Builds on
the RFC 8277 BGP-LU foundation above; each item ships independently.

1. ~~**RFC 3032 label + label-stack codec**~~ — done (lr-mpls crate).
2. ~~**RFC 8277 BGP-LU end-to-end**~~ — done (codec → router → daemon →
   FFI + bindings → interop).
3. ~~**Linux `AF_MPLS` LSP installation**~~ — done
   (`lr-osroute::mpls_route`, push/swap/pop via netlink), including the
   router-level integration: when a BGP-LU route lands in the Loc-RIB
   the daemon mirrors it into the kernel dataplane — an `AF_MPLS` pop
   route for locally originated labels (in-label → `lo`, local
   delivery, the kernel's own explicit-null shape) and an encap route
   (`ip route add … encap mpls <stack>`) for peer-advertised stacks,
   with implicit-null left to PHP and withdrawals reversing both
   halves. Landing this against the v5.10 netlink sources flushed out
   two latent wire bugs the unit tests could never catch: `RTA_VIA`'s
   family field is host byte order (the old big-endian encoding was
   rejected by `nla_get_via` on little-endian kernels), and netlink
   label attributes must carry TTL/TC zeroed (`nla_get_labels`
   rejects data-plane TTL 64). Verified by `tests/interop/mpls_lsp.sh`:
   two rootless netns over a veth pair, kernel-state assertions on
   both sides, and an ICMP echo pushed through the LSP (kernel-gated,
   the tcp_ao.sh skip pattern). Router-level LSP *withdrawal*
   bookkeeping lives in the daemon's mirror (prefix → in-label side
   table); per-prefix label *allocation* for transit LSR roles (swap
   toward a labelled next hop) remains future work.
4. **LDP (RFC 5036)** — label distribution protocol for non-BGP MPLS
   LSPs. Foundation slice landed in the new `lr-ldp` crate: the
   RFC 5036 codec (PDU/TLV/message), the §2.5.4 session FSM with
   §3.5.3 negotiation, §3.5.2 discovery (link + targeted) with the
   §2.5.2 role decision, a per-peer label information base with DU
   bookkeeping (§3.5.8.1 / §3.5.10.1), §3.5.3 Max PDU Length
   enforcement in both directions, and the `LdpEngine` glue — all
   no-std and covered by a two-speaker loopback e2e. Daemon
   transport done: `--protocol ldp` runs the reference daemon as an
   LSR — a wildcard UDP socket on port 646 joined to 224.0.0.2 per
   configured `[[ldp.interface]]`, link Hellos originated every
   hold-time third with TTL 1 and per-interface egress, targeted
   Hellos (`[[ldp.targeted]]`, `ADDR` or `ADDR:PORT`) as unicast,
   TCP 646 sessions (listener + `EstablishTransport`-driven active
   connects with retry-on-Hello after a failed connect), and
   `[[ldp.bind]]` FEC-label pairs (16..=1048575, 0 = auto-allocate)
   advertised downstream-unsolicited and re-advertised to every
   freshly operational session. Interop verified both ways against
   FRR 10 ldpd (`tests/interop/ldp_frr.sh`: lr learns FRR's
   implicit-null connected-FEC binding, FRR's LIB carries lr's
   explicit 24000 binding) and two-daemon over a veth pair
   (`tests/interop/ldp.sh`). Four follow-up slices landed: RFC 7552
   IPv6 dual-stack procedures (library + daemon transport, see the
   LDP capability table), the `[ldp] install_kernel` AF_MPLS mirror
   of learned bindings, automatic label allocation from the
   `[ldp] label_min/label_max` range, and §3.5.7.1.1 transit-LSR
   label allocation (one local label per learned FEC,
   re-advertised upstream with propagated Hop Count / Path Vector,
   reflected-binding-safe next-hop fallback, kernel swap mirror —
   see the LDP capability table). RFC 5036 §3.5.4 loop detection
   landed on top: `[ldp] loop_detection` (+ `loop_hop_count_limit` /
   `loop_path_vector_limit`, CLI `--ldp-loop-detection`) proposes the
   D bit with PVLim and enforces the §3.4.4.1/A.2.6 checks — a looping
   Mapping is rejected with a Label Release carrying the Loop Detected
   Status TLV, a looping Request
   answered with the non-fatal Loop Detected Notification. RFC 3478
   graceful restart landed on top of that (FT Session TLV + §3.3
   binding retention — see the LDP capability table). Still open:
   external dual-stack interop verification.
5. **SR-MPLS (RFC 8660 / 8667)** — Segment Routing MPLS data plane.
   Future work; depends on RFC 9256 (Segment Routing Policy) once an
   embedder asks.

### W4 — Documentation, guides, tutorials

1. ~~**A book-style tutorial (`docs/tutorial.md`)**~~ — done: three
   chapters from raw bytes to the router pipeline — wire decode (the
   codec, a hand-built UPDATE read back through the attribute bag),
   two peer FSMs (in-memory session establishment to Established),
   and the router pipeline (sessions, originate → propagate →
   install → withdraw with RIB snapshots and events). Every snippet
   is pinned by `crates/lr-tests/tests/tutorial_snippets.rs`, which
   runs the tutorial's code verbatim — the tutorial cannot drift
   from the API without breaking a test. Indexed at the top of
   `docs/README.md`.
2. Per-protocol deep dives extending `docs/examples/` (BGP roles,
   OSPF ABR/NSSA scenarios, Babel source-specific routing).
3. ~~**Binding guides per language (Go / Python / C / C++)**~~ — done:
   `docs/bindings/{go,python,c,cpp}.md`, one page each with a
   complete program (router + eBGP session + originate + wire-byte
   dump) and its exact build/run commands. All four programs were
   compiled and executed against the real `lr-ffi` release build
   during the docs work — each prints the same OPEN wire bytes and
   the guides match the shipped binding APIs (Go's
   finalizer-based cleanup, Python's context-manager Router, C's
   owned `lr_bytes_t` discipline and link-order caveat, C++'s RAII
   wrapper with the raw-ABI escape hatch). Indexed under
   `docs/README.md` §Embedding the library.
4. ~~**Operations runbook**~~ — done: `docs/RUNBOOK.md` — daemon
   lifecycle (signals, privilege drop, the fatal-by-design API
   socket), the runtime API command reference (`status`/`sessions`/
   `routes`/`mrt`/`reload`/`shutdown`, verified against `api.rs`'s
   dispatch), and a troubleshooting FAQ covering the failure modes
   operators hit first: RFC 8212's deny-by-default eBGP, unknown-key
   config warnings, Connect/Active hangs (GTSM TTL, auth arming),
   TCP-AO kernel requirements, rootless-netns raw sockets, the
   host-level `mpls_router` load, kernel-FIB installation being
   opt-in, and reload's networks-only scope. Config reference stays
   in `templates/daemon.toml`, interop lab in `docs/INTEROP.md` —
   the runbook links instead of duplicating. Indexed under
   `docs/README.md` §Running the daemon.
5. Keep `STATUS.md` / `RFC_MAP.md` / `API.md` synchronized with
   every landed feature (standing rule, enforced at review).

### W5 — Compatibility layer

1. **`lr-daemon translate bird|frr <config>`** — best-effort
   conversion of BIRD 2 / FRR BGP configs into lr daemon TOML, riding
   the daemon binary so the output is round-trip-tested against the
   real config parser in every test run. Mapped: router id / local AS,
   peers (`neighbor … as`, `remote-as`, non-default ports →
   `remote` ADDR:PORT), MD5 auth (FRR type-0 passwords; type-7 is
   noted), local address / update-source, hold time, BFD, the
   `import|export none|all` idioms (`none` → generated deny-all
   route-map, `all` → nothing because the emitted
   `ebgp_policy = "accept-all"` already means exactly that — the
   daemon's rfc8212 default would otherwise silently drop routes the
   source config accepted), prefix-lists, as-path access-lists,
   standard community-lists, route-map `match`/`set` clauses
   (prefix-list / as-path / community matches; next-hop,
   local-pref, MED, as-path prepend, add-community), FRR `network`
   and BIRD static-protocol `route` prefixes → `networks`, BIRD
   `ipv4`/`ipv6` channels → `mp_families` (an ipv6-only channel also
   sets `default_ipv4_unicast = false`), and FRR
   `address-family ipv6 unicast` activation. Anything unmappable is
   kept as an explicit `# UNMAPPED:` comment (per-line, per-entry, or
   global) instead of being dropped silently; FRR peers without a
   `remote-as` and dangling policy references are dropped with notes
   because the daemon would refuse to start them (fail-closed policy
   resolution). Remaining in W5: item 3 below.
2. ~~**Behaviour parity flags documented side-by-side**~~ — done:
   `docs/PARITY.md` catalogs every behaviour-compatibility knob
   (RFC 8212 mode, enforce-first-as, deterministic router-ID
   tie-break, implicit IPv4 unicast, local-AS tolerance, soft
   reconfiguration, Babel §5 incremental deployment) against the
   BIRD 2.17.5 and FRR 10.3 documented semantics — including the
   default differences (FRR defaults enforce-first-as on, BIRD/lr
   off; FRR defaults the RFC 5004 older-route tie-break, BIRD/lr the
   deterministic router-ID) and the transport-knob mapping (GTSM,
   MD5, TCP-AO, BFD, maximum-prefix). Sources are the upstream docs
   themselves, not folklore.
3. ~~**Wire-level parity harness**~~ — done: `lr parity-replay`
   replays a captured BGP message stream (JSONL, one hex message per
   line) into an offline `DefaultRouter` and dumps the resulting
   Loc-RIB as MRT TABLE_DUMP_V2; `lr mrt diff A B` content-compares
   two dumps (per prefix: AS path, next hop, MED, communities —
   LOCAL_PREF excluded: it is iBGP-only on the wire and dump-side
   values are the viewer's internal default, not the sender's).
   `tests/parity/capture_proxy.py` records per-direction BGP messages
   off a live TCP session (RFC 4271 reassembly, TCP-coalescing safe)
   and `tests/interop/parity.sh` runs the full loop against BIRD 2:
   lr-daemon originates two prefixes through the proxy, BIRD's own
   `protocol mrt` view (filtered to the lr protocol) is the ground
   truth, and the replay must come out IDENTICAL. In-process parity
   (capture → replay → diff against the original receiver) is covered
   by unit tests in `crates/lr-cli/src/parity.rs`.

### W6 — Research: BGP defects and a private exchange plane

1. ~~**`docs/research/BGP-DEFECTS.md`**~~ — done: catalogues BGP's
   inherent weaknesses with verified references (RFC sections checked
   against the published text; the paper citations taken from the RFCs'
   own reference lists): slow convergence/path-vector latency
   (Labovitz 2000, Griffin 1999/2002, Gao-Rexford), withdrawal
   propagation storms, route leaks (RFC 7908 taxonomy, RFC 9234 role
   gap), origin/path forgery (RFC 6811/8205/7132), full-mesh/RR
   scaling limits (RFC 4456, RFC 3345), MRAI vs churn trade-offs
   (RFC 4271 §9.2.1.1, RFC 7196 — not RFC 8326, which is Graceful BGP
   Session Shutdown and unimplemented), MED oscillation (RFC 3345
   Type I/II, RFC 5004). Each entry maps the defect to the standard
   mitigation and to lr's current coverage; the summary table flags
   the three unmitigated-in-practice defects the EXCHANGE-PLANE design
   targets. Writing it flushed out four wrong RFC 8326 citations
   (lr-damping doc comment, `lr-bgp::best_path` module doc,
   ARCHITECTURE.md, RFC_MAP.md's 8326 row claimed implemented) — all
   fixed in the same series.
2. ~~**`docs/research/EXCHANGE-PLANE.md`**~~ — done: the design review
   document for a capability-negotiated private exchange plane
   (LRXP). Grounded in verified first-hand facts — RFC 5492 §3
   (unknown capabilities are inert, the transparent-fallback hook),
   RFC 4271 §5 (unknown optional-transitive attributes forward with
   the Partial bit, so records survive non-lr transit), the IANA
   "Capability Codes" registry (239-254 reserved for experimental
   use; the prototype claims 251) and the unassigned path-attribute
   range (prototype type 251, both with an RFC 7120 early-allocation
   path to production). Three record classes: scope-1 feasibility
   hints (best-path rank, damping FoM, IGP cost), scope-1 policy
   intent (RFC 9234 role claim + import/export filter digests), and
   propagated, per-hop re-signed provenance proofs (origin
   attestation + a BGPsec-shaped digest chain over lr hops only).
   Session binding via OPEN nonces, monotonic sequences and HMAC-SHA256
   tags (the primitive lr-babel's RFC 8967 code already ships);
   fail-open for route data, fail-closed for trust assertions;
   aggregation strips provenance. Includes the W6.3 prototype plan
   (module layout, feature flag, config keys, five-phase test plan)
   and the open questions for the design review.
3. ~~**Prototype the plane inside `lr-bgp::extensions`**~~ — done as
   the first slice, behind the `exchange-plane` feature flag (off by
   default; the wire format uses the IANA experimental capability
   range 239-254 — the prototype claims 251 — and path-attribute type
   251, both pending an RFC 7120 early allocation):
   `lr-bgp::extensions::exchange_plane` implements the full codec —
   capability value (version/flags/nonce/key block), the
   optional-transitive attribute body (header + record TLVs), all
   three record classes (scope-1 hints, scope-1 policy intent,
   scope-N provenance with origin attestations and per-hop segment
   signatures), HMAC-SHA256 signing/verification with constant-time
   comparison (the same primitive lr-babel's RFC 8967 code uses), the
   OPEN-nonce replay tracker with per-key monotonic sequences, and
   the §3 activation rule (same version + non-empty key
   intersection). FSM wiring: `BgpPeer::set_exchange_plane`
   advertises the capability in OPEN, `exchange_plane_session()`
   exposes the negotiation result — RFC 5492 §3 keeps a one-sided
   advertisement inert, so sessions with non-participating peers
   (BIRD, FRR) are byte-identical to before. 20 new unit tests
   (codec roundtrips, unknown-TLV skip, truncation/version/duplicate-
   tag errors, sign/verify tamper detection, replay decisions,
   activation rules) plus 2 FSM tests (both-sides activation,
   one-sided fallback) — all behind the feature, 147 lr-bgp tests
   with it on and the default build unchanged. The decision process
   is untouched; the follow-up slice wires daemon config
   (`[peer] exchange_plane` + key block) and the UPDATE
   attach/detach hooks, then the design's interop gate (flag off =
   byte-identical UPDATE streams via the W5.3 parity harness).
