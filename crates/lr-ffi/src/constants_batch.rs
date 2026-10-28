//! Constants FFI batch — mirrors `pub const` items across lr-babel,
//! lr-bgp (BGP-LS descriptor TLV type ids + RTR PDU/version/flag
//! constants), lr-bfd (packet version, MIN_LEN, MAX_PASSWORD_LEN),
//! lr-bmp (BmpHeader::LEN, MAX_MESSAGE), lr-osroute (OSPF multicast
//! addresses + IPPROTO_OSPF + BFD transport port numbers).
//!
//! Each constant is exported as a `pub const LR_*` so cbindgen emits
//! a matching `#define` in `include/lr_ffi.h`. C consumers can then
//! write `if (type == LR_BGP_LS_TLV_LOCAL_NODE_DESCRIPTOR)` instead
//! of hard-coding `0x0100`.
//!
//! Issue #92 — gap closure: the Rust pub API exposed these constants
//! but no C ABI mirror existed.

#![allow(dead_code)]

// =========================================================================
// lr-babel — RFC 8966 magic / version / body offset + neighbour RTT
// =========================================================================

/// Babel packet magic byte (RFC 8966 §4.1).
pub const LR_BABEL_MAGIC: u8 = 0x2A;
/// Babel protocol version (RFC 8966 §4.1).
pub const LR_BABEL_VERSION: u8 = 2;
/// Body offset inside a Babel frame — magic + version + body length (2).
pub const LR_BABEL_BODY_OFFSET: usize = 4;

/// RTT EWMA decay constant (RFC 8966 §3.4.2 — IRTT calc).
pub const LR_BABEL_RTT_DECAY: u32 = 42;
/// RTT validity window (RFC 8966 §3.4.2) — 180 s in ms.
pub const LR_BABEL_RTT_VALIDITY_MS: u64 = 180_000;
/// Hello timestamp freshness window — 1 s in ms (RFC 8966 §3.4.3).
pub const LR_BABEL_RTT_ECHO_FRESHNESS_MS: u64 = 1_000;
/// Sanity upper bound on RTT — 600 s in microseconds (RFC 8966 §A.2.2).
pub const LR_BABEL_RTT_SANITY_US: u32 = 600_000_000;

// Sub-TLV codes (RFC 8966 §4.4 + draft-ietf-babel-rtt-extension).
pub const LR_BABEL_SUBTLV_SOURCE_PREFIX: u8 = 128;
pub const LR_BABEL_SUBTLV_TIMESTAMP: u8 = 3;

// Hello flag bit (RFC 8966 §4.4.6).
pub const LR_BABEL_HELLO_FLAG_UNICAST: u16 = 0x8000;

// Update flag bits (RFC 8966 §4.4.9 — ae=0 default prefix / router-id).
pub const LR_BABEL_UPDATE_FLAG_PREFIX: u8 = 0x80;
pub const LR_BABEL_UPDATE_FLAG_ROUTER_ID: u8 = 0x40;

// =========================================================================
// lr-bfd — RFC 5880 packet version + minimum length + auth
// =========================================================================

/// BFD packet version (RFC 5880 §4.1).
pub const LR_BFD_VERSION: u8 = 1;
/// Minimum BFD control packet length (RFC 5880 §4.1 — 24 bytes).
pub const LR_BFD_PACKET_MIN_LEN: usize = 24;
/// Maximum Simple Password auth data length (RFC 5880 §4.2).
pub const LR_BFD_MAX_PASSWORD_LEN: usize = 16;

// =========================================================================
// lr-bmp — RFC 7854 header length + maximum message size
// =========================================================================

/// BMP header length (RFC 7854 §4.1 — 6 bytes).
pub const LR_BMP_HEADER_LEN: usize = 6;
/// Maximum BMP message size (RFC 7854 §4.1 — 65535 bytes).
pub const LR_BMP_MAX_MESSAGE: usize = 65535;

// =========================================================================
// lr-bgp — BGP-LS TLV type ids (RFC 7752 §3.3 / §3.4 + RFC 9552 §4)
//
// Exposed as named constants so a C embedder walking the TLV stream
// from `lr_bgp_ls_decode_tlv_stream` can `switch (tlv_type)` on names
// rather than the raw u16 code points.
// =========================================================================

/// Node Descriptor TLV (RFC 7752 §3.3.1) — appears under a Node NLRI.
pub const LR_BGP_LS_TLV_LOCAL_NODE_DESCRIPTOR: u16 = 256;
/// Remote Node Descriptor TLV (RFC 7752 §3.3.2) — appears under a Link NLRI.
pub const LR_BGP_LS_TLV_REMOTE_NODE_DESCRIPTOR: u16 = 257;
/// Link Local/Remote Identifier TLV (RFC 7752 §3.3.2).
pub const LR_BGP_LS_TLV_LINK_LOCAL_REMOTE_ID: u16 = 258;
/// IPv4 Interface Address TLV (RFC 7752 §3.3.2).
pub const LR_BGP_LS_TLV_IPV4_INTERFACE_ADDRESS: u16 = 259;
/// IPv4 Neighbor Address TLV (RFC 7752 §3.3.2).
pub const LR_BGP_LS_TLV_IPV4_NEIGHBOR_ADDRESS: u16 = 260;
/// IPv6 Interface Address TLV (RFC 7752 §3.3.2).
pub const LR_BGP_LS_TLV_IPV6_INTERFACE_ADDRESS: u16 = 261;
/// IPv6 Neighbor Address TLV (RFC 7752 §3.3.2).
pub const LR_BGP_LS_TLV_IPV6_NEIGHBOR_ADDRESS: u16 = 262;
/// Multi-Topology ID TLV (RFC 7752 §3.3.2 + RFC 4915).
pub const LR_BGP_LS_TLV_MULTI_TOPOLOGY_ID: u16 = 263;
/// OSPF Route Type TLV (RFC 7752 §3.3.3).
pub const LR_BGP_LS_TLV_OSPF_ROUTE_TYPE: u16 = 264;
/// IP Reachability Information TLV (RFC 7752 §3.3.3).
pub const LR_BGP_LS_TLV_IP_REACHABILITY_INFO: u16 = 265;
/// Autonomous System TLV (RFC 7752 §3.3.1).
pub const LR_BGP_LS_TLV_AUTONOMOUS_SYSTEM: u16 = 512;
/// BGP-LS Identifier TLV (RFC 7752 §3.3.1).
pub const LR_BGP_LS_TLV_BGP_LS_IDENTIFIER: u16 = 513;
/// OSPF Area ID TLV (RFC 7752 §3.3.1).
pub const LR_BGP_LS_TLV_OSPF_AREA_ID: u16 = 514;
/// IGP Router Identifier TLV (RFC 7752 §3.3.1).
pub const LR_BGP_LS_TLV_IGP_ROUTER_ID: u16 = 515;
/// BGP Router Identifier TLV (RFC 7752 §3.3.1 — BGP-LS extension).
pub const LR_BGP_LS_TLV_BGP_ROUTER_ID: u16 = 516;
/// BGP Confederation Member TLV (RFC 7752 §3.3.1 — BGP-LS extension).
pub const LR_BGP_LS_TLV_BGP_CONFEDERATION_MEMBER: u16 = 517;
/// SRv6 SID Information TLV (RFC 9552 §4 — SRv6 SID extension).
pub const LR_BGP_LS_TLV_SRV6_SID_INFORMATION: u16 = 518;

// =========================================================================
// lr-bgp — RTR (RFC 8210) PDU version + length constants
// =========================================================================

/// RTR protocol version 0 (RFC 6810).
pub const LR_RTR_VERSION_0: u8 = 0;
/// RTR protocol version 1 (RFC 8210).
pub const LR_RTR_VERSION_1: u8 = 1;
/// RTR protocol version 2 (RFC 8210 §6 — future use).
pub const LR_RTR_VERSION_2: u8 = 2;
/// Highest RTR protocol version supported.
pub const LR_RTR_VERSION_MAX: u8 = 2;
/// RTR PDU fixed header length (RFC 8210 §5).
pub const LR_RTR_HEADER_LEN: usize = 8;
/// Maximum RTR PDU length (RFC 8210 §5).
pub const LR_RTR_PDU_MAX_LEN: usize = 65_536;
/// RTR IPv4/IPv6 Prefix PDU Announce flag bit (RFC 8210 §5.5/§5.6).
pub const LR_RTR_FLAG_ANNOUNCE: u8 = 0x01;

/// Default RTR refresh interval (RFC 8210 §6 — 1 hour, seconds).
pub const LR_RTR_DEFAULT_REFRESH_INTERVAL: u32 = 3600;
/// Default RTR retry interval (RFC 8210 §6 — 10 minutes, seconds).
pub const LR_RTR_DEFAULT_RETRY_INTERVAL: u32 = 600;
/// Default RTR expire interval (RFC 8210 §6 — 2 hours, seconds).
pub const LR_RTR_DEFAULT_EXPIRE_INTERVAL: u32 = 7200;

// =========================================================================
// lr-osroute — OSPF multicast addresses + IPPROTO_OSPF + BFD ports
// =========================================================================

/// OSPF AllSPFRouters IPv4 multicast (RFC 2328 §A.1 — 224.0.0.5).
pub const LR_OSPF_ALL_SPF_ROUTERS_V4_OCTET_0: u8 = 224;
pub const LR_OSPF_ALL_SPF_ROUTERS_V4_OCTET_1: u8 = 0;
pub const LR_OSPF_ALL_SPF_ROUTERS_V4_OCTET_2: u8 = 0;
pub const LR_OSPF_ALL_SPF_ROUTERS_V4_OCTET_3: u8 = 5;

/// OSPF AllDRouters IPv4 multicast (RFC 2328 §A.1 — 224.0.0.6).
pub const LR_OSPF_ALL_D_ROUTERS_V4_OCTET_3: u8 = 6;

/// IPv6 hop limit for OSPFv3 multicast (RFC 5340 §A.1 — 1, link-local).
pub const LR_OSPF_V3_MULTICAST_HOP_LIMIT: u8 = 1;

/// IP protocol number for OSPF (RFC 2328 §A.1 — 89).
pub const LR_IPPROTO_OSPF: i32 = 89;

/// BFD Control port (RFC 5881 §4 — single-hop, 3784).
pub const LR_BFD_CONTROL_PORT: u16 = 3784;
/// BFD Multihop Control port (RFC 5881 §4 — multihop, 4784).
pub const LR_BFD_MULTIHOP_PORT: u16 = 4784;
/// BFD source port range minimum (RFC 5881 §4 — 49152).
pub const LR_BFD_SOURCE_PORT_MIN: u16 = 49_152;
/// BFD source port range maximum (RFC 5881 §4 — 65535).
pub const LR_BFD_SOURCE_PORT_MAX: u16 = 65_535;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn babel_constants_match_rust() {
        assert_eq!(LR_BABEL_MAGIC, lr_babel::MAGIC);
        assert_eq!(LR_BABEL_VERSION, lr_babel::VERSION);
        assert_eq!(LR_BABEL_BODY_OFFSET, lr_babel::BODY_OFFSET);
        assert_eq!(LR_BABEL_RTT_DECAY, lr_babel::neighbor::RTT_DECAY);
        assert_eq!(
            LR_BABEL_RTT_VALIDITY_MS,
            lr_babel::neighbor::RTT_VALIDITY_MS
        );
        assert_eq!(
            LR_BABEL_RTT_ECHO_FRESHNESS_MS,
            lr_babel::neighbor::RTT_ECHO_FRESHNESS_MS
        );
        assert_eq!(LR_BABEL_RTT_SANITY_US, lr_babel::neighbor::RTT_SANITY_US);
        assert_eq!(
            LR_BABEL_SUBTLV_SOURCE_PREFIX,
            lr_babel::message::SOURCE_PREFIX_SUBTLV
        );
        assert_eq!(
            LR_BABEL_SUBTLV_TIMESTAMP,
            lr_babel::message::TIMESTAMP_SUBTLV
        );
        assert_eq!(
            LR_BABEL_HELLO_FLAG_UNICAST,
            lr_babel::message::Hello::UNICAST
        );
        assert_eq!(
            LR_BABEL_UPDATE_FLAG_PREFIX,
            lr_babel::message::Update::FLAG_PREFIX
        );
        assert_eq!(
            LR_BABEL_UPDATE_FLAG_ROUTER_ID,
            lr_babel::message::Update::FLAG_ROUTER_ID
        );
    }

    #[test]
    fn bfd_constants_match_rust() {
        assert_eq!(LR_BFD_VERSION, lr_bfd::packet::BFD_VERSION);
        assert_eq!(LR_BFD_PACKET_MIN_LEN, lr_bfd::packet::BfdPacket::MIN_LEN);
        assert_eq!(LR_BFD_MAX_PASSWORD_LEN, lr_bfd::auth::MAX_PASSWORD_LEN);
    }

    #[test]
    fn bmp_constants_match_rust() {
        assert_eq!(LR_BMP_HEADER_LEN, lr_bmp::BmpHeader::LEN);
        assert_eq!(LR_BMP_MAX_MESSAGE, lr_bmp::BmpHeader::MAX_MESSAGE);
    }

    #[test]
    fn bgp_ls_tlv_constants_match_rust() {
        use lr_bgp::path::bgp_ls::tlv_type::*;
        assert_eq!(LR_BGP_LS_TLV_LOCAL_NODE_DESCRIPTOR, LOCAL_NODE_DESCRIPTOR);
        assert_eq!(LR_BGP_LS_TLV_REMOTE_NODE_DESCRIPTOR, REMOTE_NODE_DESCRIPTOR);
        assert_eq!(LR_BGP_LS_TLV_LINK_LOCAL_REMOTE_ID, LINK_LOCAL_REMOTE_ID);
        assert_eq!(LR_BGP_LS_TLV_IPV4_INTERFACE_ADDRESS, IPV4_INTERFACE_ADDRESS);
        assert_eq!(LR_BGP_LS_TLV_IPV4_NEIGHBOR_ADDRESS, IPV4_NEIGHBOR_ADDRESS);
        assert_eq!(LR_BGP_LS_TLV_IPV6_INTERFACE_ADDRESS, IPV6_INTERFACE_ADDRESS);
        assert_eq!(LR_BGP_LS_TLV_IPV6_NEIGHBOR_ADDRESS, IPV6_NEIGHBOR_ADDRESS);
        assert_eq!(LR_BGP_LS_TLV_MULTI_TOPOLOGY_ID, MULTI_TOPOLOGY_ID);
        assert_eq!(LR_BGP_LS_TLV_OSPF_ROUTE_TYPE, OSPF_ROUTE_TYPE);
        assert_eq!(LR_BGP_LS_TLV_IP_REACHABILITY_INFO, IP_REACHABILITY_INFO);
        assert_eq!(LR_BGP_LS_TLV_AUTONOMOUS_SYSTEM, AUTONOMOUS_SYSTEM);
        assert_eq!(LR_BGP_LS_TLV_BGP_LS_IDENTIFIER, BGP_LS_IDENTIFIER);
        assert_eq!(LR_BGP_LS_TLV_OSPF_AREA_ID, OSPF_AREA_ID);
        assert_eq!(LR_BGP_LS_TLV_IGP_ROUTER_ID, IGP_ROUTER_ID);
        assert_eq!(LR_BGP_LS_TLV_BGP_ROUTER_ID, BGP_ROUTER_ID);
        assert_eq!(
            LR_BGP_LS_TLV_BGP_CONFEDERATION_MEMBER,
            BGP_CONFEDERATION_MEMBER
        );
        assert_eq!(LR_BGP_LS_TLV_SRV6_SID_INFORMATION, SRV6_SID_INFORMATION);
    }

    #[test]
    fn rtr_constants_match_rust() {
        use lr_bgp::rtr::client::{
            DEFAULT_EXPIRE_INTERVAL, DEFAULT_REFRESH_INTERVAL, DEFAULT_RETRY_INTERVAL,
        };
        use lr_bgp::rtr::pdu::{
            RTR_FLAG_ANNOUNCE, RTR_HEADER_LEN, RTR_PDU_MAX_LEN, RTR_VERSION_0, RTR_VERSION_1,
            RTR_VERSION_2, RTR_VERSION_MAX,
        };
        assert_eq!(LR_RTR_VERSION_0, RTR_VERSION_0);
        assert_eq!(LR_RTR_VERSION_1, RTR_VERSION_1);
        assert_eq!(LR_RTR_VERSION_2, RTR_VERSION_2);
        assert_eq!(LR_RTR_VERSION_MAX, RTR_VERSION_MAX);
        assert_eq!(LR_RTR_HEADER_LEN, RTR_HEADER_LEN);
        assert_eq!(LR_RTR_PDU_MAX_LEN, RTR_PDU_MAX_LEN);
        assert_eq!(LR_RTR_FLAG_ANNOUNCE, RTR_FLAG_ANNOUNCE);
        assert_eq!(LR_RTR_DEFAULT_REFRESH_INTERVAL, DEFAULT_REFRESH_INTERVAL);
        assert_eq!(LR_RTR_DEFAULT_RETRY_INTERVAL, DEFAULT_RETRY_INTERVAL);
        assert_eq!(LR_RTR_DEFAULT_EXPIRE_INTERVAL, DEFAULT_EXPIRE_INTERVAL);
    }

    #[test]
    fn ospf_transport_constants_match_rust() {
        // The v4 multicast constants live as `[u8; 4]` in Rust; we
        // mirror them as named bytes so a C embedder building an IPv4
        // socket struct can `addr[3] = LR_OSPF_ALL_D_ROUTERS_V4_OCTET_3`.
        let all_spf_v4 = lr_osroute::ospf_transport::ALL_SPF_ROUTERS;
        assert_eq!(all_spf_v4[0], LR_OSPF_ALL_SPF_ROUTERS_V4_OCTET_0);
        assert_eq!(all_spf_v4[3], LR_OSPF_ALL_SPF_ROUTERS_V4_OCTET_3);
        let all_d_v4 = lr_osroute::ospf_transport::ALL_D_ROUTERS;
        assert_eq!(all_d_v4[3], LR_OSPF_ALL_D_ROUTERS_V4_OCTET_3);
        assert_eq!(LR_IPPROTO_OSPF, lr_osroute::ospf_transport::IPPROTO_OSPF);
    }

    #[test]
    fn bfd_port_constants_match_rust() {
        use lr_osroute::bfd_transport::{
            BFD_CONTROL_PORT, BFD_MULTIHOP_PORT, BFD_SOURCE_PORT_MAX, BFD_SOURCE_PORT_MIN,
        };
        assert_eq!(LR_BFD_CONTROL_PORT, BFD_CONTROL_PORT);
        assert_eq!(LR_BFD_MULTIHOP_PORT, BFD_MULTIHOP_PORT);
        assert_eq!(LR_BFD_SOURCE_PORT_MIN, BFD_SOURCE_PORT_MIN);
        assert_eq!(LR_BFD_SOURCE_PORT_MAX, BFD_SOURCE_PORT_MAX);
    }
}
