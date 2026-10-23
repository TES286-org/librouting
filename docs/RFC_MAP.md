# RFC reference map

Which RFCs `librouting` implements, and the module that implements each
one. Every crate path here exists in the workspace; a capability with no
module is not listed. See [`STATUS.md`](STATUS.md) for the capability
view and [`RELEASE-PLAN.md`](RELEASE-PLAN.md) §4.4 for what is out of
scope.

## BGP

| RFC | crate::module | what it implements |
| --- | --- | --- |
| 1997 | `lr-bgp::path::communities` | COMMUNITIES attribute |
| 2385 | `lr-osroute::tcp_auth` | TCP MD5 socket authentication |
| 2439 | `lr-damping` | route flap damping figure of merit |
| 2545 | `lr-bgp::path::mp_nlri` | IPv6 NLRI over MP-BGP |
| 2918 | `lr-bgp::message::route_refresh` | ROUTE-REFRESH message |
| 4271 | `lr-bgp::fsm`, `lr-bgp::message`, `lr-bgp::path::well_known`, `lr-policy::bgp`, `lr-policy::filter::ast::RouteFieldKind` | FSM, message codec, §9.1.2 selection, §5.1.6 ATOMIC_AGGREGATE typed accessor and filter-DSL exposure (`bgp.atomic_aggregate`), §5.1.7 AGGREGATOR typed accessor and filter-DSL exposure (`bgp.aggregator.asn` / `bgp.aggregator.speaker`, `defined(bgp.aggregator.asn)` distinguishes "absent" from "set to zero") |
| 4360 | `lr-bgp::path::communities` | EXTENDED_COMMUNITIES attribute |
| 4456 | `lr-bgp::role::cluster`, `lr-bgp::path::well_known`, `lr-policy::bgp`, `lr-policy::filter::ast` | route reflection, ORIGINATOR_ID, CLUSTER_LIST — wire codec accessors on `PathAttributes`, `OriginatorId`/`ClusterList` types, filter-DSL exposure as `bgp.originator_id` and `bgp.cluster_list` |
| 4486 | `lr-bgp::message::notification` | CEASE subcodes, subcode 1 for max-prefix |
| 4724 | `lr-bgp::extensions::graceful_restart` | restart capability and End-of-RIB |
| 4760 | `lr-bgp::path::mp_nlri` | MP_REACH_NLRI and MP_UNREACH_NLRI |
| 5004 | `lr-bgp::best_path` | deterministic router-id tiebreak |
| 5065 | `lr-bgp::role::confederation`, `lr-bgp::path::as_path` | confederation segments |
| 5082 | `lr-osroute::gtsm` | outbound TTL and minimum-TTL receive filter |
| 5492 | `lr-bgp::capabilities` | capability optional parameter |
| 5925 | `lr-osroute::tcp_auth` | TCP-AO key installation |
| 6396 | `lr-mrt` | TABLE_DUMP_V2 read and write, BGP4MP decode |
| 6514 | `lr-bgp::path::PathAttributes`, `lr-bgp::path::well_known::PmsiTunnel`, `lr-policy::bgp`, `lr-policy::filter::ast::RouteFieldKind` | PMSI Tunnel attribute (type 22, optional transitive) for MVPN auto-discovery; `PmsiTunnel` codec (Flags + Tunnel Type + 3-octet MPLS Label + variable Tunnel Identifier; Tunnel Type 0 / 6 hard rules enforced, unknown types preserved verbatim); `PathAttributes::pmsi_tunnel`/`has_pmsi_tunnel` typed accessors; `bgp.pmsi_tunnel` filter DSL field (read-only `bool`, `defined(bgp.pmsi_tunnel)` distinguishes "absent" from "present but malformed") |
| 6793 | `lr-bgp::extensions::asn4`, `lr-bgp::path::as_path` | four-octet AS, AS4_PATH reconstruction |
| 6811 | `lr-bgp::roa`, `lr-bgp::roa_store` | prefix-origin validation |
| 7311 | `lr-bgp::path::PathAttributes`, `lr-bgp::path::well_known::Aigp`, `lr-policy::bgp`, `lr-policy::filter::ast::RouteFieldKind` | AIGP ("Accumulated IGP Metric") attribute (type 26, optional non-transitive); `Aigp` TLV-stream codec (type-1 TLV = 8-byte accumulated metric, unknown TLVs preserved); `PathAttributes::aigp`/`has_aigp` typed accessors; `bgp.aigp` filter DSL field (read-only `int`, `defined(bgp.aigp)` distinguishes "absent" from "set to zero") |
| 7313 | `lr-bgp::extensions::enhanced_rr` | BoRR and EoRR demarcation |
| 7752 | `lr-bgp::path::bgp_ls`, `lr-bgp::path::bgp_ls_attr`, `lr-bgp::advertise`, `lr-core::nlri`, `lr-router::instance::lsdb_to_bgpls`, `lr-router::instance::DefaultRouter::bgpls_republish`, `lr-cli::daemon::BgplsDriver`, `lr-cli::daemon_config::BgpLsSpec` | BGP-LS Link-State AFI/SAFI, Node/Link/Prefix NLRI codec, descriptor TLVs, BGP-LS Attribute (§3.3) TLV codec including the Node/Link/Prefix Attribute TLVs (§3.3.1-§3.3.3), SRv6 SID NLRI (RFC 9514 §6 with TLV 518), OSPF LSDB → BGP-LS projection (RFC 7752 §3, incl. RFC 9514 §6 SRv6 SID NLRI for OSPFv3), opaque BGP-LS NLRI egress on `BgpPeer`, BGP-LS Attribute egress (`BgpPeer::advertise_bgpls_with_attr`), incremental republish driver, daemon `--bgp-ls` flag and `[bgp_ls]` config block |
| 7854 | `lr-bmp` | BMP message codec and sink |
| 7911 | `lr-bgp::extensions::addpath` | path-identifier framing and negotiation |
| 7947 | `lr-bgp::role::route_server` | transparent route-server egress |
| 8092 | `lr-bgp::path::communities` | LARGE_COMMUNITIES attribute |
| 8210 | `lr-bgp::rtr` | RTR PDU codec and client state machine |
| 8212 | `lr-router::instance` | default external route propagation |
| 8277 | `lr-bgp::path::labeled_nlri`, `lr-osroute::mpls_route` | labelled NLRI, LSP install |
| 8326 | `lr-bgp::path::communities`, `lr-policy::hooks` | GRACEFUL_SHUTDOWN community |
| 8950 | `lr-bgp::extensions::extended_next_hop` | IPv4 NLRI with an IPv6 next hop |
| 9072 | `lr-bgp::path` | extended-length path-attribute flag |
| 9234 | `lr-bgp::role::otc`, `lr-bgp::path::PathAttributes`, `lr-policy::bgp`, `lr-policy::filter::ast::RouteFieldKind` | OTC attribute and role negotiation; `PathAttributes::otc`/`has_otc` typed accessors; `bgp.otc` filter DSL field (read-only `int`, `defined(bgp.otc)` distinguishes "absent" from "set to zero") |
| 9494 | `lr-bgp::extensions::long_lived` | LLGR capability, LLGR_STALE, NO_LLGR |
| 9514 | `lr-bgp::path::bgp_ls`, `lr-bgp::path::bgp_ls_attr`, `lr-router::instance::lsdb_to_bgpls` | SRv6 SID NLRI Type 6 (§6) with the SRv6 SID Information TLV (§6.1, type 518); OSPFv3 SRv6 database (`lr-ospf::srv6db`, RFC 9513 reception) projected onto SRv6 SID NLRIs (one End SID per NLRI); BGP-LS Attribute TLVs (§7 SRv6 Endpoint Behavior type 1250, §7.2 SRv6 BGP PeerNode SID type 1251, §8 SRv6 SID Structure type 1252) codec in `path::bgp_ls_attr`; §3.1 SRv6 Capabilities (type 1038), §4.1 SRv6 End.X SID (type 1106), §4.2 IS-IS/OSPFv3 SRv6 LAN End.X SID (types 1107/1108), §5.1 SRv6 Locator (type 1162) modelled. End.X / LAN End.X SID *projection* (attaching the §7 attribute to a projected End.X NLRI) out of scope — the codec is the foundation, the projection update is a follow-up. |
| 9086 | `lr-bgp::path::bgp_ls`, `lr-bgp::path::bgp_ls_attr`, `lr-router::instance::epe`, `lr-router::instance::DefaultRouter::bgpls_republish_epe`, `lr-cli::daemon::BgplsDriver` | BGP-LS extensions for Segment Routing BGP Egress Peer Engineering. Node Descriptor sub-TLVs (§3.1 BGP Router-ID type 516, §3.2 Member-AS Number type 517) modelled in `path::bgp_ls::NodeDescriptorSubTlv` for BGP-LS Link NLRIs whose Protocol-ID is `Bgp`. SR-MPLS BGP Peering SID TLVs (§5 PeerNode SID type 1101, §5 PeerAdj SID type 1102, §5 PeerSet SID type 1103) modelled in `path::bgp_ls_attr::BgpLsAttrTlv::PeerNodeSid` / `PeerAdjSid` / `PeerSetSid`, sharing the `BgpPeeringSid` shape with the V/L/B/P flag bits, weight, reserved and variable SID/Index/Label (3-byte label or 4-byte SRGB index). Daemon-side EPE projection (walking the daemon's BGP peer sessions and emitting one BGP-LS Link NLRI per Established session, paired with a BGP-LS Attribute carrying the PeerNode SID and any optional PeerAdj / PeerSet SIDs) lands in `lr-router::instance::epe::project_epe_peer_sessions`; `DefaultRouter::bgpls_republish_epe` drives the incremental republish; `BgplsDriver` ticker polls `bgp_session_identity_hash` and re-projects on change. Operator-configurable SID values are a follow-up — the daemon emits a deterministic per-session placeholder (V flag clear, SRGB index = session handle). |

## OSPF

| RFC | crate::module | what it implements |
| --- | --- | --- |
| 2328 | `lr-ospf::packet`, `lr-ospf::lsdb`, `lr-ospf::spf`, `lr-ospf::external`, `lr-bgp::path::AttrType::LrOspfMetric2`, `lr-policy::ospf`, `lr-policy::filter::ast::RouteFieldKind`, `lr-router::instance::ospf_ops` | OSPFv2 codec, LSDB and SPF; §16 route preference order and metric semantics surfaced in the filter DSL as `ospf.metric1` (read-only `int`, `0` for non-OSPF routes — mirrors BIRD's eattr default for an unattached `ospf_metric1` reference; `defined(ospf.metric1)` distinguishes "non-OSPF route" from "OSPF route with metric 0" via `lr-policy::ospf::has_metric1`) and §16.4 type-2 external metric surfaced as `ospf.metric2` (read-only `int`, `0` for non-type-2-external routes — mirrors BIRD's eattr default for an unattached `ospf_metric2` reference; `defined(ospf.metric2)` distinguishes "not a type-2 external" from "type-2 external with metric 0" via `lr-policy::ospf::has_metric2`; the type-2 external metric rides the private `LrOspfMetric2` path-attribute tag — code point 253, stripped at BGP encode — that `lr-router::instance::ospf_ops::ospf_recompute` attaches for type-2 externals); §A.4.5 bullet h external route tag surfaced in the filter DSL as `ospf.tag` (read-only `int`, `0` for routes without a tag — non-OSPF routes, intra-area / inter-area OSPF routes, or v3 externals without the T bit set — mirrors BIRD's eattr default for an unattached `ospf_tag` reference; `defined(ospf.tag)` distinguishes "no tag" from "tag of zero" via `lr-policy::ospf::has_tag` — the v2 LSA body always carries a 4-byte tag, zero being well-formed, so a v2 external surfaces `Some(t)` even when the tag is zero; the route tag rides the existing `Route::tag` field, populated by `lr-router::instance::ospf_ops::ospf_recompute` for type-5 / type-7 externals) |
| 3101 | `lr-ospf::nssa`, `lr-policy::ospf`, `lr-policy::filter::ast::RouteFieldKind`, `lr-router::instance::ospf_ops` | type-7 origination, P-bit and translation; §2.3 / Appendix A type-7 LSA body is byte-identical to the type-5 body so the same 32-bit external route tag surfaces in the filter DSL as `ospf.tag` for NSSA externals |
| 3623 | `lr-ospf::gr`, `lr-ospf::lsa::grace` | graceful restart and the Grace-LSA |
| 5187 | `lr-ospf::lsa::grace`, `lr-ospf::gr` | v3 Grace-LSA, LS type 0x000b |
| 5250 | `lr-ospf::lsa`, `lr-ospf::exchange` | opaque LSA types and the DD O-bit |
| 5340 | `lr-ospf::packet`, `lr-ospf::lsa::v3`, `lr-ospf::spf`, `lr-ospf::external`, `lr-bgp::path::AttrType::LrOspfMetric2`, `lr-policy::ospf`, `lr-policy::filter::ast::RouteFieldKind`, `lr-router::instance::ospf_ops` | OSPFv3 codec, LSA bodies, SPF; §4.1 route preference (mirrors OSPFv2 §16) surfaced in the filter DSL as `ospf.metric1`; §4.8.5 external route calculation (mirrors OSPFv2 §16.4) surfaced as `ospf.metric2` (the type-2 external metric — the §16.4 (6) preference's primary sort key — carried through the Loc-RIB on the private `LrOspfMetric2` path-attribute tag `lr-router::instance::ospf_ops::ospf_recompute` attaches for type-2 externals); §A.4.7 T bit external route tag (mirrors OSPFv2 §A.4.5) surfaced in the filter DSL as `ospf.tag` (the v3 form requires the T bit to surface a tag, so a missing v3 tag stays `None` — unlike the v2 form which always carries a 4-byte tag) |
| 5709 | `lr-ospf::auth::crypto` | HMAC-SHA-1 and HMAC-SHA-256 trailer |
| 7166 | `lr-ospf::auth::v3_auth` | v3 authentication trailer |
| 7684 | `lr-ospf::lsa::sr` | extended prefix and link opaque LSAs |
| 7770 | `lr-ospf::lsa::srv6`, `lr-ospf::srv6db` | Router Information LSA and capability TLVs |
| 8362 | `lr-ospf::lsa::e_v3`, `lr-ospf::external`, `lr-policy::ospf`, `lr-policy::filter::ast::RouteFieldKind`, `lr-router::instance::ospf_ops` | Extended LSAs and their TLV framing; §3.6 External-Prefix sub-TLV 3 carries the v3 external route tag for the Extended-LSA form, surfaced in the filter DSL as `ospf.tag` |
| 8665 | `lr-ospf::lsa::sr`, `lr-ospf::srdb` | OSPFv2 Segment Routing control plane |
| 9513 | `lr-ospf::lsa::srv6`, `lr-ospf::srv6db` | OSPFv3 SRv6 control plane and reception |

## Babel

| RFC | crate::module | what it implements |
| --- | --- | --- |
| 8966 | `lr-babel::message`, `lr-babel::tlv` | datagram codec and the core TLV set |
| 8967 | `lr-babel::auth` | MAC authentication and the challenge handshake |
| 9079 | `lr-babel::source` | source-prefix sub-TLV and the (dest, source) route key |
| 9229 | `lr-babel::message` | address encoder 4, IPv4 routes over an IPv6 next hop |
| 9467 | `lr-babel::auth` | relaxed packet-counter verification |
| 9647 | `yang/ietf-babel@2024-10-10.yang`, `crates/lr-cli/src/yang.rs` | Babel YANG model and rendered instance data |

## BFD

| RFC | crate::module | what it implements |
| --- | --- | --- |
| 5880 | `lr-bfd::packet`, `lr-bfd::session`, `lr-bfd::auth`, `lr-bfd::keyed_auth` | packet codec, session FSM, Simple Password auth (§4.2 / §6.7.2), Keyed MD5 / Keyed SHA1 / Meticulous Keyed MD5 / Meticulous Keyed SHA1 auth (§4.3 / §4.4 / §6.7.3 / §6.7.4) with anti-replay |
| 5881 | `lr-osroute::bfd_transport` | single-hop sockets and the TTL receive check |
| 5883 | `lr-osroute::bfd_transport` | multihop sessions on UDP 4784 |

## MPLS and Segment Routing

| RFC | crate::module | what it implements |
| --- | --- | --- |
| 3032 | `lr-mpls` | label and label-stack codec |
| 5036 | `lr-ldp` | LDP codec, session FSM and label bookkeeping |
| 5462 | `lr-mpls` | traffic-class field on a label |
| 5586 | `lr-mpls` | generic associated channel label |
| 6790 | `lr-mpls` | entropy label indicator |
| 7552 | `lr-ldp` | IPv6 discovery and targeted sessions |
| 8660 | `lr-ospf::srdb`, `lr-osroute::mpls_route` | SR-MPLS label resolution and install |
| 8754 | `lr-srv6::srh`, `lr-srv6::sid`, `lr-srv6::locator` | SRH, segment identifier and locator |
| 8986 | `lr-srv6::behavior`, `lr-osroute::seg6_route` | endpoint behaviors and seg6local install |

## OS interface

| RFC | crate::module | what it implements |
| --- | --- | --- |
| 3549 | `lr-osroute::linux` | the rtnetlink message set the Linux backend speaks |

## Policy and models

| RFC | crate::module | what it implements |
| --- | --- | --- |
| 8177 | `yang/ietf-key-chain@2017-06-15.yang`, `crates/lr-cli/src/yang.rs` | key-chain instance data for Babel MAC keys |
