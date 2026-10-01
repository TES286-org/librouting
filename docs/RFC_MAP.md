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
| 4271 | `lr-bgp::fsm`, `lr-bgp::message` | FSM, message codec, §9.1.2 selection |
| 4360 | `lr-bgp::path::communities` | EXTENDED_COMMUNITIES attribute |
| 4456 | `lr-bgp::role::cluster` | route reflection, ORIGINATOR_ID, CLUSTER_LIST |
| 4486 | `lr-bgp::message::notification` | CEASE subcodes, subcode 1 for max-prefix |
| 4724 | `lr-bgp::extensions::graceful_restart` | restart capability and End-of-RIB |
| 4760 | `lr-bgp::path::mp_nlri` | MP_REACH_NLRI and MP_UNREACH_NLRI |
| 5004 | `lr-bgp::best_path` | deterministic router-id tiebreak |
| 5065 | `lr-bgp::role::confederation`, `lr-bgp::path::as_path` | confederation segments |
| 5082 | `lr-osroute::gtsm` | outbound TTL and minimum-TTL receive filter |
| 5492 | `lr-bgp::capabilities` | capability optional parameter |
| 5925 | `lr-osroute::tcp_auth` | TCP-AO key installation |
| 6396 | `lr-mrt` | TABLE_DUMP_V2 read and write, BGP4MP decode |
| 6793 | `lr-bgp::extensions::asn4`, `lr-bgp::path::as_path` | four-octet AS, AS4_PATH reconstruction |
| 6811 | `lr-bgp::roa`, `lr-bgp::roa_store` | prefix-origin validation |
| 7313 | `lr-bgp::extensions::enhanced_rr` | BoRR and EoRR demarcation |
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
| 9234 | `lr-bgp::role::otc` | OTC attribute and role negotiation |
| 9494 | `lr-bgp::extensions::long_lived` | LLGR capability, LLGR_STALE, NO_LLGR |

## OSPF

| RFC | crate::module | what it implements |
| --- | --- | --- |
| 2328 | `lr-ospf::packet`, `lr-ospf::lsdb`, `lr-ospf::spf` | OSPFv2 codec, LSDB and SPF |
| 3101 | `lr-ospf::nssa` | type-7 origination, P-bit and translation |
| 3623 | `lr-ospf::gr`, `lr-ospf::lsa::grace` | graceful restart and the Grace-LSA |
| 5187 | `lr-ospf::lsa::grace`, `lr-ospf::gr` | v3 Grace-LSA, LS type 0x000b |
| 5250 | `lr-ospf::lsa`, `lr-ospf::exchange` | opaque LSA types and the DD O-bit |
| 5340 | `lr-ospf::packet`, `lr-ospf::lsa::v3`, `lr-ospf::spf` | OSPFv3 codec, LSA bodies, SPF |
| 5709 | `lr-ospf::auth::crypto` | HMAC-SHA-1 and HMAC-SHA-256 trailer |
| 7166 | `lr-ospf::auth::v3_auth` | v3 authentication trailer |
| 7684 | `lr-ospf::lsa::sr` | extended prefix and link opaque LSAs |
| 7770 | `lr-ospf::lsa::srv6`, `lr-ospf::srv6db` | Router Information LSA and capability TLVs |
| 8362 | `lr-ospf::lsa::e_v3` | Extended LSAs and their TLV framing |
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
| 5880 | `lr-bfd::packet`, `lr-bfd::session` | packet codec and session FSM |
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
