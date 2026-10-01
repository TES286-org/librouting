# RFC reference map

This document lists the RFCs that `librouting` implements, partially implements, or references. It is grouped by protocol family.

## BGP — RFC 4271 (BGP-4) + extensions

| RFC | Title | Status | Crate path |
| --- | --- | --- | --- |
| 4271 | BGP-4 | ✓ core; §6.8 connection collision detection over `SessionConfig::{collision_group, locally_initiated}` — retains the connection initiated by the higher-BGP-Identifier speaker, Established siblings … | `lr-bgp::fsm`, `lr-bgp::message`, `lr-bgp::peer::{ipv4_unicast_active, local_as_tolerance, soft_reconfig_inbound}`, `lr-router::import_route`, `lr-router::resolve_connection_collision`, … |
| 1997 | BGP Communities Attribute | ✓ | `lr-bgp::path::communities` |
| 2385 | Protection of BGP Sessions via a TCP MD5 Signature (TCP MD5) | ✓ | `lr-osroute::tcp_auth` (TCP_MD5SIG/\_EXT) |
| 2439 | BGP Route Flap Damping | ✓ (opt-in; RFC 7196 documents the harm of the defaults) | `lr-damping` |
| 2545 | BGP-4 Multiprotocol Extensions for IPv6 | ✓ (under mp_bgp) | `lr-bgp::path::mp_nlri` |
| 2796 | BGP Route Reflection | ✓ (superseded by 4456) | `lr-bgp::role::cluster` |
| 2918 | BGP Route Refresh | ✓ | `lr-bgp::message::route_refresh` |
| 3065 | BGP Confederations | ✓ (superseded by 6793) | `lr-bgp::role::confederation` |
| 4360 | BGP Extended Communities | ✓ | `lr-bgp::path::communities` |
| 4456 | BGP Route Reflection (revised) | ✓ | `lr-bgp::role::cluster` |
| 4486 | Subcodes for BGP CEASE NOTIFICATION | ✓ (subcode 1 = max-prefix reached) | `lr-bgp::fsm`, `lr-router` |
| 4724 | BGP Graceful Restart | ✓ (per-family F bits) | `lr-bgp::extensions::graceful_restart`, `lr-router` |
| 4760 | Multiprotocol BGP | ✓ | `lr-bgp::path::mp_nlri` |
| 4784 | BGP Cumulative Bestpath | ✓ (multipath) | `lr-bgp::best_path` |
| 4893 | BGP Support for 4-byte AS | ✓ | `lr-bgp::extensions::asn4` |
| 5004 | BGP Deterministic Path Selection | ✓ (default on; exposed as FRR `bgp bestpath compare-routerid` on the daemon, W2.2) | `lr-bgp::best_path` |
| 5082 | The Generalized TTL Security Mechanism (GTSM) | ✓ (IP_MINTTL / IPV6_MINHOPCOUNT listener filter + outbound TTL; `--gtsm` daemon flag) | `lr-osroute::gtsm` |
| 5492 | BGP Capabilities | ✓ | `lr-bgp::capabilities` |
| 5549 | BGP Extended Next-Hop | ✓ (capability 5 in the §4 6-byte tuple form, (1,1,2) negotiation + 16B NEXT_HOP decode + eBGP egress rewrite + e2e 8 modes + BIRD interop) | `lr-bgp::extensions::extended_next_hop`, `lr-bgp::capabilities`, `lr-bgp::advertise` |
| 5666 | BGP Egress Peer Engineering | partial (TBD) | — |
| 5925 | The TCP Authentication Option (TCP-AO) | ✓ (Linux >= 6.7; RFC 5926 KDFs via kernel) | `lr-osroute::tcp_auth` (TCP_AO_ADD_KEY/INFO) |
| 6396 | MRT Routing Information Export Format | ✓ TABLE_DUMP_V2 read/write (peer index tables, RIB v4/v6 unicast + add-path), BGP4MP decode | `lr-mrt` |
| 6793 | BGP Support for 4-byte AS (revised) | ✓ (supersedes 4893; §4.2.3 AS4_PATH reconstruction) | `lr-bgp::path::as_path`, `lr-bgp::extensions::asn4` |
| 7313 | Enhanced Route Refresh | ✓ | `lr-bgp::extensions::enhanced_rr` |
| 7854 | BGP Monitoring Protocol (BMP) | ✓ (lr-bmp crate: 7 message types, streaming codec, IPv4/IPv6 peer headers; set_bmp_sink router integration) | `lr-bmp`, `lr-router` |
| 7911 | BGP Add-Path | ✓ (negotiation, wire framing, N-path selection/export) | `lr-bgp::extensions::addpath`, `lr-bgp::codec`, `lr-bgp::best_path`, `lr-router` |
| 7947 | Internet Exchange BGP Route Server | ✓ | `lr-bgp::role::route_server` |
| 8212 | Default EBGP Route Behaviors | ✓ (deny-in/deny-out for external sessions without explicit policy; daemon default-on, `accept-all` deviation) | `lr-router` (`set_ebgp_requires_policy` / `set_session_policy`), `lr-cli` daemon (`ebgp_policy`) |
| 8277 | BGP and Labeled Address Prefixes (MPLS) | ✓ (lr-mpls: RFC 3032 label + label-stack codec, 4- and 3-octet wire forms; lr-bgp::path::labeled_nlri: RFC 8277 §3 NLRI codec + MP_REACH/MP_UNREACH helpers; lr-router::originate_labeled; … | `lr-mpls`, `lr-bgp::path::labeled_nlri`, `lr-router`, `lr-osroute::mpls_route`, `lr-ffi`, `lr-cli` |
| 8326 | Graceful BGP Session Shutdown | ✓ (sender side: `GRACEFUL_SHUTDOWN` community `0xFFFF:0000` honoured on export — LOCAL_PREF zeroed, community preserved, per-peer `graceful_shutdown = false` exemption; … | `lr-bgp::path::communities`, `lr-bgp::best_path`, `lr-policy::hooks::{GracefulShutdownExportHook, GracefulShutdownImportHook}`, `lr-cli::daemon` |
| 8950 | Advertising IPv4 NLRI with an IPv6 Next Hop | ✓ (obsoletes 5549's NLRI encoding; capability encoding identical) | `lr-bgp::extensions::extended_next_hop`, `lr-bgp::path` |
| 9072 | Extended Message Support for BGP | ✓ (extended length) | `lr-bgp::path::PathAttrFlags` |
| 9234 | BGP Role (OTC) | ✓ (§5 ingress leak rejection + egress customer/RS-client-only rule) | `lr-bgp::role::otc` |
| 9494 | Long-Lived Graceful Restart | ✓ | `lr-bgp::extensions::long_lived`, `lr-router` |
| 1105 | BGP-1 (historic) | not implemented (legacy) | — |
| 1163 | BGP-3 (historic) | not implemented (legacy) | — |
| 1267 | BGP-3 → BGP-4 transition (historic) | not implemented | — |

## OSPF — RFC 2328 (OSPFv2) + RFC 5340 (OSPFv3) + extensions

| RFC | Title | Status | Crate path |
| --- | --- | --- | --- |
| 2328 | OSPF Version 2 | ✓ core + inter-area + external + stub areas + virtual links + daemon transport (raw sockets, Hello/Router-LSA origination, §A.1 packet checksum) + full DBD/LSR exchange (§7.2/§10.3–§10.8, … | `lr-ospf::packet`, `lr-ospf::lsdb`, `lr-ospf::spf`, `lr-ospf::abr`, `lr-ospf::external`, `lr-ospf::origination`, `lr-ospf::interface`, `lr-ospf::exchange`, `lr-router`, `lr-osroute::ospf_transport` |
| 3101 | OSPF Not-So-Stubby Areas (NSSA) | ✓ type-7 origination (P-bit + forwarding-address rules), §2.5 calculation, §3.1 translator election, §3.2 type-5 translation, type-7/type-3 defaults, `no_summary` | `lr-ospf::nssa`, `lr-router` |
| 3623 | Graceful OSPF Restart | ✓ complete — Grace-LSA codec (`lr-ospf::lsa::grace`), helper + restarting state machines (`lr-ospf::gr`: §3.1 checks, §3.2 exits, §2.2 outcomes), router event surface (`drain_ospf_grace_events()`, … | `lr-ospf::lsa::grace`, `lr-ospf::gr`, `lr-router`, `crates/lr-cli/src/daemon_ospf.rs` |
| 4577 | OSPF as the Provider Edge-to-CE | partial | — |
| 5340 | OSPF for IPv6 | ✓ daemon mode (slice 1): v3 wire formats fixed against a reference implementation — 16-byte packet header (§A.3.1, Instance ID), FRR-parity Hello (§A.3.2, 16-bit dead interval), 12-byte DBD (§A.3.3: … | options(3)\\|MTU\\|0\\|flags\\|seq), LSR entries with the leading reserved word (§A.3.4), IPv6 pseudo-header checksum; v3 LSA bodies (§A.4: Router 0x2001, Network 0x2002, Link 0x0008, Intra-Area-Prefix … |
| 5187 | OSPFv3 Graceful Restart | ✓ complete — the v3 Grace-LSA is the dedicated link-scoped LS type 0x000b with the Interface ID as the Link State ID (§2.1/§2.2, `originate_grace_lsa_v3`, FRR `ospf6_gr_lsa_originate` parity; … | `lr-ospf::lsa::grace`, `lr-ospf::gr`, `lr-router` (`drain_ospf_grace_events`), `lr-cli/src/daemon_ospf3.rs` |
| 5250 | Opaque LSA Option | ✓ opaque-LSA type space (v2 types 9/10/11 in `LsaTypeV2`), Opaque Type/ID packing for the Link State ID (`opaque_lsa_id`), the O-bit in DD packet options announcing opaque capability — BIRD/FRR gate … | `lr-ospf::lsa`, `lr-ospf::exchange` |
| 5709 | OSPFv2 HMAC-SHA Cryptographic Auth | ✓ (HMAC-SHA-1 + HMAC-SHA-256 with the §3.3 Ko/Apad construction, Auth Data Len = digest, anti-replay) | `lr-ospf::auth::crypto` |
| 5643 | Management Information Base for OSPFv3 | partial | — |
| 6850 | OSPFv3 MIB | partial | — |
| 7166 | Support for the Auth Trailer in OSPFv3 | ✓ (RFC 7166 trailer: AuthType/SA-ID(16-bit)/crypto-seq + §4.5 Apad MAC embedding the IPv6 source, anti-replay) | `lr-ospf::auth::v3_auth` |
| 7471 | OSPF TE MIB | partial | — |
| 7506 | OSPFv3 Auto-Configuration | partial | — |
| 7684 | OSPFv3 Prefix Link-Local Attributes; OSPFv2 Extended Prefix/Link Opaque LSA | ✓ v3: LSA type 0x4004 (AS-scope, function 4) + `v3_prefix_options` bits (Af, R) + `V3PrefixLinkLocalEntry` codec (W3.5). v2: Extended Prefix Opaque LSA (area-scoped, Opaque Type 7) + Extended Prefix … | `lr-ospf::lsa::{LsaTypeV3::PrefixLinkLocalAsLsa, v3_prefix_options}`, `lr-ospf::lsa::sr::{SrPrefixAdvert, encode_ext_prefix_lsa_body, decode_ext_prefix_lsa_body, SrLinkAdvert, SrAdjSidTlv, … |
| 7770 | OSPF Node Admin Tags | partial | — |
| 8036 | Multi-Area OSPF | partial | — |
| 8362 | OSPFv3 over IPv6 (revised) | ✓ | `lr-ospf::packet` |
| 8665 | OSPF Extensions for Segment Routing | ✓ control plane + reception (W3-extra.5 slices 1+2): wire codecs (RI LSA SR-Algorithm type 8 + SID/Label Range TLV type 9 per §3, Extended Prefix Opaque LSA + Prefix-SID sub-TLV with … | `lr-ospf::lsa::sr`, `lr-ospf::srdb`, `lr-cli/src/daemon_ospf.rs` (`reoriginate_sr`, `reoriginate_sr_links`), `[ospf] srgb_base/srgb_range/sr_receive` + `[[ospf.prefix_sid]]` + `[[ospf.interface]] … |
| 9825 | OSPFv3 Segment Routing | partial | — |

## Babel — RFC 8966 + extensions

| RFC | Title | Status | Crate path |
| --- | --- | --- | --- |
| 7557 | Babel Source-Specific Extensions (precursor to 9079) | ✓ | `lr-babel::source` |
| 8966 | Babel | ✓ core | `lr-babel::tlv`, `lr-babel::message` |
| 8967 | Babel MAC Cryptographic Auth | ✓ (stateful §4.3 interface, §4.3.1 challenge handshake, §4.4 expiry, §5 incremental deployment, HMAC-SHA256 + keyed BLAKE2s-128) | `lr-babel::auth` |
| 9079 | Babel Source-Specific Routing | ✓ (Source Prefix sub-TLV 128 inside Update / Route Request / Seqno Request, IPv6 source prefixes, route table keyed by (dest, source)) | `lr-babel::source`, `lr-babel::message` |
| 9229 | Babel RPM (route propagation) — registers AE 4 | ✓ (§2.4 AE 4 "IPv4 via IPv6": announced for v4 destinations over a v6-only next hop when `extended_next_hop` is on, decoded symmetrically — the encoding BIRD 3 and babeld accept on v6-only links) | `lr-babel::message`, `lr-router::instance`, `lr-cli` daemon |
| 9467 | Relaxed Packet Counter Verification for Babel MAC | ✓ (§3.1 unicast/multicast split, §3.2 window, §3.3 combined) | `lr-babel::auth` |
| 9647 | Babel YANG Data Model | ✓ (verbatim `ietf-babel@2024-10-10.yang` in `yang/`; `lr-daemon yang render` emits libyang-validated XML instance data for the babel container — NMDA envelope, constants, mac-key-set) | `lr-cli` (`yang` module), `yang/`, `tests/interop/yang.sh` |

## BFD — RFC 5880 + extensions

| RFC | Title | Status | Crate path |
| --- | --- | --- | --- |
| 5880 | Bidirectional Forwarding Detection | ✓ core | `lr-bfd::packet`, `lr-bfd::session` |
| 5881 | BFD for IPv4 and IPv6 (Single Hop) | ✓ (Linux; TTL check Linux-only) | `lr-osroute::bfd_transport` |
| 5883 | BFD for Multihop Paths | ✓ (UDP 4784, no TTL filter) | `lr-osroute::bfd_transport`, daemon `--bfd-multihop` |
| 7130 | BFD for LAG | not impl | — |
| 8562 | BFD for Multipoint Networks | not impl | — |

Notes: the §6.8.6 state machine, §6.8.4 detection time (peer's detect multiplier), §6.8.7 negotiated transmit interval with jitter and the §6.5 Poll/Final sequences are implemented and BIRD-verified (`tests/interop/bfd_bird.sh`). Simple Password auth (§4.2) works end-to-end in sessions; the keyed-hash sections (§4.3/§4.4) are framing-only — digests are embedder-supplied (no crypto dependency in `lr-bfd`). The Echo function (§6.4) is not implemented (single-hop-only and optional; multihop MUST NOT use it, RFC 5883 §3).

## MPLS — RFC 3032 + extensions

| RFC | Title | Status | Crate path |
| --- | --- | --- | --- |
| 3032 | MPLS Label Stack Encoding | ✓ (Label + LabelStack types, 4-octet-per-entry wire form §2.1 + 3-octet-per-entry NLRI form for RFC 8277; bottom-of-stack bit handling; named constants for all reserved labels — IPv4/IPv6 … | `lr-mpls` |
| 5462 | MPLS Label Stack Entry — TC field | ✓ (3-bit TC field on Label) | `lr-mpls` |
| 6790 | Entropy LSE Indicator | ✓ (Label::ELI constant) | `lr-mpls` |
| 5586 | GAL (Generic Associated Channel Label) | ✓ (Label::GAL constant) | `lr-mpls` |
| 8277 | BGP and Labeled Address Prefixes (BGP-LU) | ✓ (NLRI codec, MP_REACH/MP_UNREACH helpers, router originate/withdraw, kernel dataplane mirror — tail pop + head encap LSPs —, FFI + bindings, daemon config, two-daemon interop + kernel dataplane … | `lr-bgp::path::labeled_nlri`, `lr-router`, `lr-osroute::mpls_route`, `lr-ffi`, `lr-cli` |
| 5036 | LDP (Label Distribution Protocol) | ✓ complete IPv4/IPv6 LSR (PDU/TLV/message codec for all 11 message types with U/F-bit passthrough, §2.5.4 session FSM with §3.5.3 parameter negotiation, §3.5.2 discovery (link + targeted) with the … | `lr-ldp` |
| 7552 | LDP IPv6 | ✓ (§5.1 IPv6 basic discovery: ff02::2 link Hellos with hop-limit-255 GTSM check and link-local sources; §5.2 targeted over global unicast only, link-local rejected at config parse; … | `lr-ldp` |
| 8660 | SR-MPLS Data Plane | ✓ head end + tail (the OSPFv2 slice; IS-IS rides no plane here): the Prefix-SID label resolved from the SRDB becomes a Loc-RIB `LrMplsLabelStack` attribute and the shared kernel mirror installs the … | `lr-ospf::srdb`, `lr-router` (SR attach), `lr-osroute::mpls_route`, `lr-cli` |
| 8667 | IS-IS Extensions for Segment Routing | not impl (IS-IS; the OSPF counterpart is RFC 8665 — see the OSPF table) | — |
| 8754 | IPv6 Segment Routing Header (SRH) | ✓ (lr-srv6: 128-bit `Sid` (RFC 8754 §3, LOC:FUNCT:ARGS structured), `Locator` (RFC 8754 §3.1, IPv6 prefix + block bits, host-bits masking, from_str/Display with the RFC 5952 canonical form), `Srh` … | `lr-srv6::srh`, `lr-srv6::sid`, `lr-srv6::locator` |
| 8986 | SRv6 Segment Routing with the IPv6 Data Plane | ✓ (lr-srv6: `Behavior` enum — the 38 RFC 8986 IANA assignments exactly (1-24, 26-39; 25 Reserved): End / End.X / End.T / End.B6.Insert / End.B6.Encaps / End.BM / End.DX6 / End.DX4 / End.DT6 / End.DT4 … | `lr-srv6::behavior`, `lr-osroute::seg6_route` (`Seg6LocalRoute::new` + builder) |
| 9256 | Segment Routing Policy | not impl (SR Policy; future slice — the slice-1 SRv6 data plane is the foundation, RFC 9256 §2 builds the policy model on top) | — |
| 9513 | OSPFv3 Extensions for SRv6 | ✓ slice 2 (control plane, library level): the SRv6 Capabilities / SR-Algorithm / Node MSD TLVs on the OSPFv3 Router Information LSA (RFC 7770 §2.2, 0xA00C area-scoped), the SRv6 Locator LSA (function … | `lr-ospf::lsa::srv6`, `lr-ospf::srv6db`, `lr-ospf::spf`, `lr-router` |

## OS interface — RFC 3549 + Linux

| RFC / spec | Title | Status | Crate path |
| --- | --- | --- | --- |
| 3549 | Linux Netlink as an IP Services Protocol | ✓ | `lr-osroute::linux::RtNetlink` |
| Linux | `uapi/linux/rtnetlink.h` | ✓ reference | `lr-osroute::linux` |
| FreeBSD, OpenBSD, NetBSD, macOS | `route(4)` socket | ✓ (per-OS layout tables pinned; cross-compile checked) | `lr-osroute::bsd::RouteSocket` |
| Windows | IP Helper API (`CreateIpForwardEntry2` / `GetIpForwardTable2`) | ✓ (full link verified, x86_64-windows-gnu) | `lr-osroute::windows::IpHelper` |

## Policy

| RFC | Title | Status | Crate path |
| --- | --- | --- | --- |
| 2622 | Routing Policy Specification Language (RPSL) | not impl | — |
| 8195 | Identifiers for BGP-4 | partial | `lr-bgp::path` |
| 8177 | YANG Data Model for Key Chains | ✓ (verbatim `ietf-key-chain@2017-06-15.yang` in `yang/`; babel MAC keys render as a key chain via `lr-daemon yang render --model keychain`; BLAKE2s fails closed — no RFC 8177 identity) | `lr-cli` (`yang` module), `yang/`, `tests/interop/yang.sh` |
