# RFC reference map

This document lists the RFCs that `librouting` implements, partially
implements, or references. It is grouped by protocol family.

## BGP — RFC 4271 (BGP-4) + extensions

| RFC    | Title                                                | Status                  | Crate path                          |
|--------|------------------------------------------------------|--------------------------|--------------------------------------|
| 4271   | BGP-4                                                | ✓ core                  | `lr-bgp::fsm`, `lr-bgp::message`    |
| 1997  | BGP Communities Attribute                            | ✓                       | `lr-bgp::path::communities`         |
| 2385  | Protection of BGP Sessions via a TCP MD5 Signature (TCP MD5) | ✓                       | `lr-osroute::tcp_auth` (TCP_MD5SIG/_EXT) |
| 2439  | BGP Route Flap Damping                               | ✓ (deprecated by 8326) | `lr-damping`                          |
| 2545  | BGP-4 Multiprotocol Extensions for IPv6              | ✓ (under mp_bgp)        | `lr-bgp::path::mp_nlri`              |
| 2796  | BGP Route Reflection                                 | ✓ (superseded by 4456) | `lr-bgp::role::cluster`              |
| 2918  | BGP Route Refresh                                    | ✓                       | `lr-bgp::message::route_refresh`    |
| 3065  | BGP Confederations                                   | ✓ (superseded by 6793) | `lr-bgp::role::confederation`        |
| 4360  | BGP Extended Communities                             | ✓                       | `lr-bgp::path::communities`         |
| 4456  | BGP Route Reflection (revised)                       | ✓                       | `lr-bgp::role::cluster`              |
| 4724  | BGP Graceful Restart                                 | ✓ (per-family F bits)  | `lr-bgp::extensions::graceful_restart`, `lr-router` |
| 4760  | Multiprotocol BGP                                    | ✓                       | `lr-bgp::path::mp_nlri`              |
| 4784  | BGP Cumulative Bestpath                              | ✓ (multipath)           | `lr-bgp::best_path`                  |
| 4893  | BGP Support for 4-byte AS                            | ✓                       | `lr-bgp::extensions::asn4`           |
| 5004  | BGP Deterministic Path Selection                     | ✓ (default on)          | `lr-bgp::best_path`                  |
| 5082  | The Generalized TTL Security Mechanism (GTSM)        | planned (roadmap 11)    | —                                    |
| 5492  | BGP Capabilities                                     | ✓                       | `lr-bgp::capabilities`              |
| 5666  | BGP Egress Peer Engineering                          | partial (TBD)           | —                                    |
| 5925  | The TCP Authentication Option (TCP-AO)               | ✓ (Linux >= 6.7; RFC 5926 KDFs via kernel) | `lr-osroute::tcp_auth` (TCP_AO_ADD_KEY/INFO) |
| 6793  | BGP Support for 4-byte AS (revised)                  | ✓ (superseded 4893)     | `lr-bgp::role::confederation`         |
| 7313  | Enhanced Route Refresh                               | ✓                       | `lr-bgp::extensions::enhanced_rr`    |
| 7854  | BGP Monitoring Protocol (BMP)                        | planned (roadmap 14)    | —                                    |
| 7911  | BGP Add-Path                                         | ✓ (negotiation, wire framing, N-path selection/export) | `lr-bgp::extensions::addpath`, `lr-bgp::codec`, `lr-bgp::best_path`, `lr-router` |
| 7947  | Internet Exchange BGP Route Server                   | ✓                       | `lr-bgp::role::route_server`         |
| 8212  | Default EBGP Route Behaviors                         | partial (policy)        | `lr-policy`                          |
| 8277  | BGP and Labeled Address Prefixes (MPLS)              | not implemented         | —                                    |
| 8326  | Graceful BGP Session Restart + damp deprecation       | ✓                       | `lr-bgp::best_path`, `lr-damping`    |
| 9072  | Extended Message Support for BGP                      | ✓ (extended length)     | `lr-bgp::path::PathAttrFlags`        |
| 9234  | BGP Role (OTC)                                       | ✓                       | `lr-bgp::role::otc`                  |
| 9494  | Long-Lived Graceful Restart                          | ✓                       | `lr-bgp::extensions::long_lived`, `lr-router` |
| 9647  | Babel YANG model                                     | partial                 | `lr-babel`                            |
| 1105  | BGP-1 (historic)                                     | not implemented (legacy)| —                                   |
| 1163  | BGP-3 (historic)                                     | not implemented (legacy)| —                                   |
| 1267  | BGP-3 → BGP-4 transition (historic)                  | not implemented         | —                                    |

## OSPF — RFC 2328 (OSPFv2) + RFC 5340 (OSPFv3) + extensions

| RFC    | Title                                                | Status       | Crate path                          |
|--------|------------------------------------------------------|--------------|--------------------------------------|
| 2328   | OSPF Version 2                                       | ✓ core + inter-area | `lr-ospf::packet`, `lr-ospf::lsdb`, `lr-ospf::spf`, `lr-ospf::abr`, `lr-router` |
| 3101   | OSPF Not-So-Stubby Areas (NSSA)                      | partial      | `lr-ospf::lsa`                       |
| 3623   | Graceful OSPF Restart                                | partial      | TBD                                 |
| 4577   | OSPF as the Provider Edge-to-CE                      | partial      | —                                    |
| 5340   | OSPF for IPv6                                         | ✓ core       | `lr-ospf::packet` (inter-area-prefix-LSA origination not implemented) |
| 5643   | Management Information Base for OSPFv3                | partial      | —                                    |
| 6850   | OSPFv3 MIB                                            | partial      | —                                    |
| 7166   | Support for the Auth Trailer in OSPFv3               | partial      | `lr-ospf::auth`                      |
| 7471   | OSPF TE MIB                                           | partial      | —                                    |
| 7506   | OSPFv3 Auto-Configuration                             | partial      | —                                    |
| 7684   | OSPFv3 Prefix Link-Local Attributes                  | partial      | —                                    |
| 7770   | OSPF Node Admin Tags                                 | partial      | —                                    |
| 8036   | Multi-Area OSPF                                       | partial      | —                                    |
| 8362   | OSPFv3 over IPv6 (revised)                            | ✓            | `lr-ospf::packet`                   |
| 9825   | OSPFv3 Segment Routing                                | partial      | —                                    |

## Babel — RFC 8966 + extensions

| RFC    | Title                                                | Status       | Crate path                          |
|--------|------------------------------------------------------|--------------|--------------------------------------|
| 7557   | Babel Source-Specific Extensions (precursor to 9079) | ✓            | `lr-babel::source`                  |
| 8966   | Babel                                                | ✓ core       | `lr-babel::tlv`, `lr-babel::message` |
| 8967   | Babel HMAC Cryptographic Auth                        | ✓            | `lr-babel::tlv`, `lr-babel::hmac`   |
| 9079   | Babel Source-Specific Routing                        | ✓            | `lr-babel::source`                  |
| 9289   | Babel-MAC Algorithm                                  | partial      | `lr-babel::codec`                    |
| 9647   | Babel YANG Data Model                                | partial      | TBD                                 |

## BFD — RFC 5880 + extensions

| RFC    | Title                                                | Status       | Crate path                          |
|--------|------------------------------------------------------|--------------|--------------------------------------|
| 5880   | BFD for IPv4/IPv6                                     | ✓ core       | `lr-bfd::packet`, `lr-bfd::session` |
| 5881   | BFD for IPv4/IPv6 on Multihop                          | partial      | TBD                                 |
| 7130   | BFD for MPLS PW                                       | not impl     | —                                   |
| 8562   | BFD for Multi-Hop (revised)                           | partial      | TBD                                 |

## OS interface — RFC 3549 + Linux

| RFC / spec | Title                                          | Status       | Crate path                          |
|------------|------------------------------------------------|--------------|--------------------------------------|
| 3549       | Linux Netlink as an IP Services Protocol       | ✓            | `lr-osroute::linux::RtNetlink`      |
| Linux      | `uapi/linux/rtnetlink.h`                       | ✓ reference  | `lr-osroute::linux`                  |
| FreeBSD    | `route(4)` socket                              | partial      | TBD                                 |
| Windows    | `IPHelper` (`IP_INTERFACE_INFO`)              | partial      | TBD                                 |

## Policy

| RFC    | Title                                                | Status       | Crate path                          |
|--------|------------------------------------------------------|--------------|--------------------------------------|
| 2622   | Routing Policy Specification Language (RPSL)         | not impl     | —                                   |
| 8195  | Identifiers for BGP-4                                | partial      | `lr-bgp::path`                       |
| 8177  | YANG Data Model for Key Chains                       | partial      | TBD                                 |
