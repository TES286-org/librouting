# Capability status

What `librouting` implements today, one row per capability, with the
module that carries it. Read this before assuming a mechanism exists,
then read the module's doc comment: a cell holds a few words, and the
detail belongs next to the code. Planned work is in
[`ROADMAP.md`](ROADMAP.md), release history in
[`../CHANGELOG.md`](../CHANGELOG.md), the RFC-to-module mapping in
[`RFC_MAP.md`](RFC_MAP.md), and the deliberately out-of-scope protocols
in [`RELEASE-PLAN.md`](RELEASE-PLAN.md) §4.4.

Status values: `yes` means the mechanism exists and a test exercises it;
`partial` means it exists with a documented subset missing. Every row
names a path that exists in the workspace — modules under `crates/`, or
files of the `lr-cli` binary crate, which is not a library.

## Shared primitives — `lr-core`

| Capability | Status | Module |
| --- | --- | --- |
| Address, prefix, ASN and router-ID types, v4 and v6 | yes | `lr-core::addr` |
| Path-attribute store with fixed-width read paths | yes | `lr-core::attr` |
| Streaming read and write buffers | yes | `lr-core::buf` |
| `Codec`, `Encoder` and `Decoder` traits | yes | `lr-core::codec` |
| Generic finite-state-machine engine | yes | `lr-core::fsm` |
| Timer queue over an injected clock | yes | `lr-core::timer`, `lr-core::time` |
| Event sink model | yes | `lr-core::event` |
| RIB data model (`Route`, `RouteKey`, `Protocol`) | yes | `lr-core::rib` |
| NLRI family keys | yes | `lr-core::nlri` |
| Checksums and bit-flag helpers | yes | `lr-core::util` |

## BGP — `lr-bgp`

| Capability | Status | Module |
| --- | --- | --- |
| FSM, hold and keepalive timers (RFC 4271) | yes | `lr-bgp::fsm` |
| OPEN, UPDATE, KEEPALIVE, NOTIFICATION codec | yes | `lr-bgp::message`, `lr-bgp::codec` |
| Capability advertisement (RFC 5492) | yes | `lr-bgp::capabilities` |
| Four-octet AS and AS4_PATH reconstruction (RFC 6793) | yes | `lr-bgp::extensions::asn4`, `lr-bgp::path::as_path` |
| MP-BGP NLRI, IPv4 and IPv6 unicast (RFC 4760) | yes | `lr-bgp::path::mp_nlri` |
| Extended next hop (RFC 8950) | yes | `lr-bgp::extensions::extended_next_hop` |
| Add-Path send, receive and path-id framing (RFC 7911) | yes | `lr-bgp::extensions::addpath` |
| Route refresh (RFC 2918) and BoRR/EoRR (RFC 7313) | yes | `lr-bgp::message::route_refresh`, `lr-bgp::extensions::enhanced_rr` |
| Graceful restart and End-of-RIB (RFC 4724) | yes | `lr-bgp::extensions::graceful_restart` |
| Long-lived graceful restart (RFC 9494) | yes | `lr-bgp::extensions::long_lived` |
| Route reflection, ORIGINATOR_ID and CLUSTER_LIST (RFC 4456) | yes | `lr-bgp::role::cluster` |
| Confederation segments (RFC 5065) | yes | `lr-bgp::role::confederation` |
| Route server egress (RFC 7947) | yes | `lr-bgp::role::route_server` |
| OTC attribute and role negotiation (RFC 9234) | yes | `lr-bgp::role::otc` |
| Best-path selection and the router-id tiebreak | yes | `lr-bgp::best_path` |
| Standard, extended and large communities | yes | `lr-bgp::path::communities` |
| Well-known communities and attribute flags | yes | `lr-bgp::path::well_known`, `lr-bgp::path` |
| Labelled-unicast NLRI and MP helpers (RFC 8277) | yes | `lr-bgp::path::labeled_nlri` |
| NLRI types and prefix encoding | yes | `lr-bgp::nlri` |
| Egress rewrite rules, iBGP split horizon, next-hop-self | yes | `lr-bgp::advertise` |
| Per-peer configuration: hold time, families, max-prefix, GTSM | yes | `lr-bgp::peer` |
| RPKI-RTR PDU codec and client (RFC 8210) | yes | `lr-bgp::rtr::pdu`, `lr-bgp::rtr::client` |
| ROA table and origin validation (RFC 6811) | yes | `lr-bgp::roa`, `lr-bgp::roa_store` |

## OSPF — `lr-ospf`

| Capability | Status | Module |
| --- | --- | --- |
| v2 and v3 packet codec, including the v3 pseudo-header checksum | yes | `lr-ospf::packet`, `lr-ospf::codec` |
| Neighbor FSM, Down through Full | yes | `lr-ospf::neighbor` |
| Interface FSM, DR and BDR election, v2 and v3 | yes | `lr-ospf::interface` |
| DBD, LSR, LSU and LSAck exchange | yes | `lr-ospf::exchange` |
| Per-area LSDB and flooding | yes | `lr-ospf::lsdb` |
| Dijkstra SPF for v2 and v3 | yes | `lr-ospf::spf` |
| Self-LSA origination: Router-LSA, Network-LSA, refresh | yes | `lr-ospf::origination` |
| ABR summary-LSAs and ASBR summaries (§12.4.3, §16.2) | yes | `lr-ospf::abr` |
| AS-external routes and type-5 calculation (§16.4) | yes | `lr-ospf::external` |
| Stub, totally-stubby and NSSA areas with type-7 translation | yes | `lr-ospf::nssa` |
| Graceful restart, helper and restarting roles (RFC 3623) | yes | `lr-ospf::gr` |
| Grace-LSA codec, v2 opaque and v3 link-scoped | yes | `lr-ospf::lsa::grace` |
| HMAC-SHA authentication (RFC 5709) | yes | `lr-ospf::auth::crypto` |
| v3 authentication trailer (RFC 7166) | yes | `lr-ospf::auth::v3_auth` |
| Opaque LSA type space and the O-bit (RFC 5250) | yes | `lr-ospf::lsa`, `lr-ospf::exchange` |
| OSPFv3 fixed-format LSA bodies (RFC 5340 §A.4) | yes | `lr-ospf::lsa::v3` |
| Prefix-link-local LSA and its option bits | yes | `lr-ospf::lsa::v3_prefix_options` |
| Extended LSAs and their TLV framing (RFC 8362) | yes | `lr-ospf::lsa::e_v3` |
| Router Information LSA and capability TLVs (RFC 7770) | yes | `lr-ospf::lsa::srv6` |
| OSPFv2 extended prefix and link opaque LSAs (RFC 7684) | yes | `lr-ospf::lsa::sr` |
| OSPFv2 Segment Routing control plane (RFC 8665) | yes | `lr-ospf::lsa::sr`, `lr-ospf::srdb` |
| OSPFv3 SRv6 control plane and reception (RFC 9513) | yes | `lr-ospf::lsa::srv6`, `lr-ospf::srv6db` |

## Babel — `lr-babel`

| Capability | Status | Module |
| --- | --- | --- |
| Datagram codec and TLV framing (RFC 8966) | yes | `lr-babel::message`, `lr-babel::tlv` |
| Streaming codec over the TLV set | yes | `lr-babel::codec` |
| Neighbor state and route table with feasibility | yes | `lr-babel::neighbor`, `lr-babel::route` |
| Metric computation and sequence-number handling | yes | `lr-babel::metric` |
| Source-specific routing (RFC 9079) | yes | `lr-babel::source` |
| MAC authentication and relaxed counter checks | yes | `lr-babel::auth` |

## LDP — `lr-ldp`

| Capability | Status | Module |
| --- | --- | --- |
| PDU, TLV and message codec (RFC 5036) | yes | `lr-ldp::pdu`, `lr-ldp::tlv`, `lr-ldp::message` |
| Session FSM and parameter negotiation (§2.5.4, §3.5.3) | yes | `lr-ldp::session` |
| Link and targeted discovery (§3.5.2, RFC 7552) | yes | `lr-ldp::discovery` |
| Label bookkeeping: learn, advertise, withdraw | yes | `lr-ldp::mapping` |
| Transit-LSR label allocation | yes | `lr-ldp::transit` |
| Engine glue and session events | yes | `lr-ldp::engine` |

## Monitoring, detection and damping

| Capability | Status | Module |
| --- | --- | --- |
| BFD packet codec and session FSM (RFC 5880) | yes | `lr-bfd::packet`, `lr-bfd::session` |
| BFD authentication sections | partial | `lr-bfd::auth` |
| BMP codec, split feed, peer headers (RFC 7854) | yes | `lr-bmp` |
| MRT TABLE_DUMP_V2 read and write, BGP4MP (RFC 6396) | yes | `lr-mrt` |
| Route flap damping figure of merit (RFC 2439) | yes | `lr-damping` |

## RIB and router — `lr-rib`, `lr-router`

| Capability | Status | Module |
| --- | --- | --- |
| Adj-RIB-In, Adj-RIB-Out and Loc-RIB | yes | `lr-rib::adj_rib_in`, `lr-rib::adj_rib_out`, `lr-rib::loc_rib` |
| Per-protocol route selection | yes | `lr-rib::selection` |
| Cross-protocol merge by administrative distance | yes | `lr-rib::merging` |
| Router instance: sessions, Loc-RIB, policy, scheduler | yes | `lr-router::instance` |
| Session configuration, handles and summaries | yes | `lr-router::session` |
| Embedder-supplied connection abstraction | yes | `lr-router::connection` |
| Router events, including OSPF grace events | yes | `lr-router::event` |
| Cross-protocol redistribution pipes | yes | `lr-router::redistribution` |

## Policy — `lr-policy`

| Capability | Status | Module |
| --- | --- | --- |
| Route maps, prefix lists, AS-path filters, community lists | yes | `lr-policy::route_map`, `lr-policy::prefix_list`, `lr-policy::as_path_filter`, `lr-policy::community_list` |
| Import, selection and export hooks | yes | `lr-policy::hooks` |
| Safety net: AS loops, next-hop sanity, martians | yes | `lr-policy::safety` |
| Safety net granular overrides: global kill switch, per-AFI martian, per-rule exceptions | yes | `lr-policy::safety::SafetyConfig` |
| Policy chains and verdicts | yes | `lr-policy::policy` |
| Named policy sets and per-route actions | yes | `lr-policy::set`, `lr-policy::action` |
| BGP attribute access from policy | yes | `lr-policy::bgp` |
| Filter DSL: lexer, parser, AST, interpreter | yes | `lr-policy::filter`, `lr-policy::filter::{lexer, parser, ast, eval}` |
| Filter DSL bytecode compiler and stack VM | yes | `lr-policy::filter::bytecode` |
| Filter DSL peephole optimisation | yes | `lr-policy::filter::peephole` |
| Source spans and positioned diagnostics | yes | `lr-policy::filter::span` |
| Cross-filter reusable function definitions | yes | `lr-cli::daemon_policy::build_filters` |

## OS integration and data plane — `lr-osroute`, `lr-mpls`, `lr-srv6`

| Capability | Status | Module |
| --- | --- | --- |
| Linux rtnetlink route table | yes | `lr-osroute::linux` |
| BSD and macOS `route(4)` socket route table | yes | `lr-osroute::bsd` |
| Windows IP Helper route table | yes | `lr-osroute::windows` |
| Compile-only stub for other systems | yes | `lr-osroute::stub` |
| TCP MD5 and TCP-AO socket keys (RFC 2385, RFC 5925) | yes | `lr-osroute::tcp_auth` |
| GTSM TTL arming and receive filter (RFC 5082) | yes | `lr-osroute::gtsm` |
| OSPF raw-socket transport | yes | `lr-osroute::ospf_transport` |
| BFD UDP transport, single-hop and multihop | yes | `lr-osroute::bfd_transport` |
| Source-bound TCP connect and source-address diagnostic | yes | `lr-osroute::tcp_bind`, `lr-osroute::source_check` |
| Linux `AF_MPLS` LSP install and delete | yes | `lr-osroute::mpls_route` |
| Linux `seg6` and `seg6local` route install | yes | `lr-osroute::seg6_route` |
| MPLS label and label-stack codec (RFC 3032) | yes | `lr-mpls` |
| SRv6 SID, locator, SRH and behavior registry | yes | `lr-srv6::sid`, `lr-srv6::locator`, `lr-srv6::srh`, `lr-srv6::behavior` |

## Embedder surface — `lr-ffi`, `lr-cli`, bindings

| Capability | Status | Module |
| --- | --- | --- |
| C ABI entry points and cbindgen header | yes | `lr-ffi` |
| FFI router, sessions, policy objects and route objects | yes | `lr-ffi::router`, `lr-ffi::sessions`, `lr-ffi::policy_objects`, `lr-ffi::policy` |
| FFI BGP message encoders and event polling | yes | `lr-ffi::codec`, `lr-ffi::events` |
| FFI ROA store and origin validation | yes | `lr-ffi::roa_store`, `lr-ffi::filters` |
| C++ header-only RAII wrapper | yes | `include/librouting.hpp` |
| Go and Python bindings | yes | `bindings/lr-go`, `bindings/lr-python` |
| Daemon for BGP, OSPFv2, OSPFv3, Babel, LDP, BMP and combinations | yes | `crates/lr-cli/src/daemon.rs`, `daemon_multi.rs` |
| Categorised logging: severity, components, per-component levels, plain/JSON format, file mirror | yes | `crates/lr-cli/src/daemon_logger.rs` |
| Runtime API socket and `lrctl` client | yes | `crates/lr-cli/src/api.rs`, `crates/lr-cli/src/lrctl.rs` |
| Prometheus exposition on `/metrics` | yes | `crates/lr-cli/src/metrics.rs` |
| Config: native `.lr` DSL, TOML, BIRD and FRR dialects | yes | `crates/lr-cli/src/daemon_config.rs`, `crates/lr-cli/src/compat.rs`, `crates/lr-cli/src/translate.rs` |
| Config validation without starting the daemon | yes | `crates/lr-cli/src/config_check.rs` |
| RPKI-RTR cache client in the daemon | yes | `crates/lr-cli/src/daemon_rpki.rs` |
| YANG instance data for Babel and key chains | yes | `crates/lr-cli/src/yang.rs`, `yang/ietf-babel@2024-10-10.yang` |
| Privilege drop, signal handling and reload | yes | `crates/lr-cli/src/privdrop.rs`, `crates/lr-cli/src/signal.rs` |
| Cross-crate integration tests | yes | `crates/lr-tests/tests/` |
