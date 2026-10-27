//! OSPF protocol constant surface — mirrors the `pub const` items
//! across the OSPFv2 (RFC 2328) and OSPFv3 (RFC 5340) LSA submodules
//! of `lr_ospf`.
//!
//! This module exposes the well-known OSPF code points as C-side
//! `#define`s so a C embedder can switch on them when decoding LSA
//! bodies, originating type-5 / type-7 / summary LSAs, or interpreting
//! SRv6 sub-TLVs. Each `LR_OSPF_*` constant below mirrors the
//! corresponding Rust `pub const` in `lr_ospf::lsa::*`.

#![allow(unused_unsafe)]

// ---- LSA type constants (RFC 2328 §A.4, RFC 5340 §A.4.2 / RFC 8362) ----

/// OSPFv2 Router-LSA (RFC 2328 §A.4.2).
pub const LR_OSPF_LSA_TYPE_V2_ROUTER: u8 = 1;
/// OSPFv2 Network-LSA (RFC 2328 §A.4.3).
pub const LR_OSPF_LSA_TYPE_V2_NETWORK: u8 = 2;
/// OSPFv2 Summary-IP LSA (RFC 2328 §A.4.4 — type-3 summary).
pub const LR_OSPF_LSA_TYPE_V2_SUMMARY_IP: u8 = 3;
/// OSPFv2 Summary-ASBR LSA (RFC 2328 §A.4.5 — type-4 summary).
pub const LR_OSPF_LSA_TYPE_V2_SUMMARY_ASBR: u8 = 4;
/// OSPFv2 AS-External LSA (RFC 2328 §A.4.5 — type-5).
pub const LR_OSPF_LSA_TYPE_V2_AS_EXTERNAL: u8 = 5;
/// OSPFv2 NSSA-External LSA (RFC 3101 §2.3 — type-7).
pub const LR_OSPF_LSA_TYPE_V2_NSSA_EXTERNAL: u8 = 7;
/// OSPFv2 Opaque-Link LSA (RFC 5250 §3 — type 9).
pub const LR_OSPF_LSA_TYPE_V2_OPAQUE_LINK: u8 = 9;
/// OSPFv2 Opaque-Area LSA (RFC 5250 §3 — type 10).
pub const LR_OSPF_LSA_TYPE_V2_OPAQUE_AREA: u8 = 10;
/// OSPFv2 Opaque-AS LSA (RFC 5250 §3 — type 11).
pub const LR_OSPF_LSA_TYPE_V2_OPAQUE_AS: u8 = 11;

/// OSPFv3 Router-LSA (RFC 5340 §A.4.2 — 0x2001).
pub const LR_OSPF_LSA_TYPE_V3_ROUTER: u16 = 0x2001;
/// OSPFv3 Network-LSA (RFC 5340 §A.4.3 — 0x2002).
pub const LR_OSPF_LSA_TYPE_V3_NETWORK: u16 = 0x2002;
/// OSPFv3 Inter-Area-Prefix LSA (RFC 5340 §A.4.4 — 0x2003).
pub const LR_OSPF_LSA_TYPE_V3_INTER_PREFIX: u16 = 0x2003;
/// OSPFv3 Inter-Area-Router LSA (RFC 5340 §A.4.5 — 0x2004).
pub const LR_OSPF_LSA_TYPE_V3_INTER_ROUTER: u16 = 0x2004;
/// OSPFv3 AS-External LSA (RFC 5340 §A.4.7 — 0x4005).
pub const LR_OSPF_LSA_TYPE_V3_AS_EXTERNAL: u16 = 0x4005;
/// OSPFv3 NSSA-External LSA (RFC 5340 §A.4.7 / RFC 3101 — 0x2007).
pub const LR_OSPF_LSA_TYPE_V3_NSSA: u16 = 0x2007;
/// OSPFv3 Link LSA (RFC 5340 §A.4.6 — 0x0008).
pub const LR_OSPF_LSA_TYPE_V3_LINK: u16 = 0x0008;
/// OSPFv3 Intra-Area-Prefix LSA (RFC 5340 §A.4.10 — 0x2009).
pub const LR_OSPF_LSA_TYPE_V3_INTRA_PREFIX: u16 = 0x2009;

// ---- OSPFv3 Extended-LSA types (RFC 8362 §3) ----

pub const LR_OSPF_LSA_TYPE_E_ROUTER: u16 = 0xA021;
pub const LR_OSPF_LSA_TYPE_E_NETWORK: u16 = 0xA022;
pub const LR_OSPF_LSA_TYPE_E_INTER_PREFIX: u16 = 0xA023;
pub const LR_OSPF_LSA_TYPE_E_INTER_ROUTER: u16 = 0xA024;
pub const LR_OSPF_LSA_TYPE_E_AS_EXTERNAL: u16 = 0xC025;
pub const LR_OSPF_LSA_TYPE_E_TYPE_7: u16 = 0xA027;
pub const LR_OSPF_LSA_TYPE_E_LINK: u16 = 0x8028;
pub const LR_OSPF_LSA_TYPE_E_INTRA_PREFIX: u16 = 0xA029;

// ---- Router-LSA body bits (RFC 2328 §A.4.2 / RFC 5340 §A.4.2) ----

/// V bit — endpoint of an active virtual link.
pub const LR_OSPF_ROUTER_LSA_FLAG_V: u8 = 0x04;
/// E bit — AS boundary router (originates type-5 LSAs).
pub const LR_OSPF_ROUTER_LSA_FLAG_E: u8 = 0x02;
/// B bit — area border router.
pub const LR_OSPF_ROUTER_LSA_FLAG_B: u8 = 0x01;

/// v3 Router-LSA B bit (border router, RFC 5340 §A.4.2).
pub const LR_OSPF_V3_ROUTER_BIT_B: u8 = 0x01;
/// v3 Router-LSA E bit (ASBR).
pub const LR_OSPF_V3_ROUTER_BIT_E: u8 = 0x02;
/// v3 Router-LSA V6 bit (router is IPv6-capable).
pub const LR_OSPF_V3_ROUTER_BIT_V6: u8 = 0x04;

// ---- Router-LSA link types (RFC 2328 §A.4.2) ----

pub const LR_OSPF_LINK_TYPE_POINT_TO_POINT: u8 = 1;
pub const LR_OSPF_LINK_TYPE_TRANSIT_NETWORK: u8 = 2;
pub const LR_OSPF_LINK_TYPE_STUB_NETWORK: u8 = 3;
pub const LR_OSPF_LINK_TYPE_VIRTUAL_LINK: u8 = 4;

/// v3 Router-LSA link type: point-to-point (RFC 5340 §A.4.2).
pub const LR_OSPF_V3_LINK_TYPE_POINTTOPOINT: u8 = 1;
/// v3 Router-LSA link type: transit network.
pub const LR_OSPF_V3_LINK_TYPE_TRANSIT: u8 = 2;
/// v3 Router-LSA link type: virtual.
pub const LR_OSPF_V3_LINK_TYPE_VIRTUAL: u8 = 4;

// ---- OSPFv3 prefix-option bits (RFC 5340 §A.4.1.1) ----

pub const LR_OSPF_PREFIX_OPT_NU: u8 = 0x01;
pub const LR_OSPF_PREFIX_OPT_LA: u8 = 0x02;
pub const LR_OSPF_PREFIX_OPT_MC: u8 = 0x04;
pub const LR_OSPF_PREFIX_OPT_P: u8 = 0x08;

// ---- OSPFv3 AS-External flags (RFC 5340 §A.4.7) ----

pub const LR_OSPF_AS_EXT_BIT_E: u32 = 0x0400_0000;
pub const LR_OSPF_AS_EXT_BIT_F: u32 = 0x0200_0000;
pub const LR_OSPF_AS_EXT_BIT_T: u32 = 0x0100_0000;
pub const LR_OSPF_AS_EXT_METRIC_MASK: u32 = 0x00ff_ffff;

// ---- LSA sequence-number range (RFC 2328 §12.1.2) ----

/// First sequence number of a newly-originated LSA.
pub const LR_OSPF_INITIAL_SEQUENCE_NUMBER: u32 = 0x8000_0001;
/// Largest sequence number an LSA may carry (the next is MaxSequenceNumber + 1 = 0x80000000, the flush).
pub const LR_OSPF_MAX_SEQUENCE_NUMBER: u32 = 0x7fff_ffff;

// ---- LS age limits (RFC 2328 §14) ----

/// LSInfinity — the largest age (RFC 2328 §14.1).
pub const LR_OSPF_MAX_AGE_SECS: u16 = 3_600;
/// LSRefreshTime — refresh interval (RFC 2328 §14.1).
pub const LR_OSPF_LS_REFRESH_TIME_SECS: u16 = 1_800;

// ---- NSSA P-bit (RFC 3101 §2.4) ----

pub const LR_OSPF_NSSA_N_P_BIT: u8 = 0x08;

// ---- Grace-LSA (RFC 3623 §2.1 / RFC 5187 §2.1) ----

pub const LR_OSPF_OPAQUE_TYPE_GRACE: u8 = 3;
pub const LR_OSPF_LS_TYPE_GRACE_V3: u16 = 0x000b;
pub const LR_OSPF_OPTIONS_O_BIT: u8 = 0x40;

// ---- SR (Segment Routing) opaque types (RFC 8665) ----

pub const LR_OSPF_OPAQUE_TYPE_EXT_PREFIX: u8 = 7;
pub const LR_OSPF_OPAQUE_TYPE_RI: u8 = 4;
pub const LR_OSPF_OPAQUE_TYPE_EXT_LINK: u8 = 8;

pub const LR_OSPF_TLV_EXT_PREFIX: u16 = 1;
pub const LR_OSPF_TLV_EXT_PREFIX_RANGE: u16 = 2;
pub const LR_OSPF_TLV_EXT_LINK: u16 = 1;
pub const LR_OSPF_SUBTLV_PREFIX_SID: u16 = 2;
pub const LR_OSPF_TLV_SR_ALGORITHM: u16 = 8;
pub const LR_OSPF_TLV_SRGB: u16 = 9;
pub const LR_OSPF_SUBTLV_SID_LABEL: u16 = 1;
pub const LR_OSPF_SUBTLV_ADJ_SID: u16 = 2;
pub const LR_OSPF_SUBTLV_LAN_ADJ_SID: u16 = 3;

// ---- SRv6 LSA types (RFC 9513) ----

pub const LR_OSPF_LS_TYPE_V3_ROUTER_INFORMATION: u16 = 0xA00C;
pub const LR_OSPF_LS_TYPE_SRV6_LOCATOR: u16 = 0xA02A;

pub const LR_OSPF_RI_TLV_SRV6_CAPABILITIES: u16 = 20;
pub const LR_OSPF_RI_TLV_NODE_MSD: u16 = 12;
pub const LR_OSPF_RI_TLV_SR_ALGORITHM: u16 = 8;

pub const LR_OSPF_SRV6_CAP_O_FLAG: u16 = 0x0002;
pub const LR_OSPF_LOCATOR_TLV_SRV6_LOCATOR: u16 = 1;
pub const LR_OSPF_LOCATOR_SUBTLV_END_SID: u16 = 1;
pub const LR_OSPF_LOCATOR_SUBTLV_IPV6_FWD_ADDR: u16 = 2;
pub const LR_OSPF_LOCATOR_SUBTLV_ROUTE_TAG: u16 = 3;
pub const LR_OSPF_LOCATOR_SUBTLV_PREFIX_SRC_ROUTER_ID: u16 = 4;
pub const LR_OSPF_LOCATOR_SUBTLV_PREFIX_SRC_ROUTER_ADDR: u16 = 5;
pub const LR_OSPF_LOCATOR_SUBTLV_SID_STRUCTURE: u16 = 10;

pub const LR_OSPF_EXT_SUBTLV_SID_STRUCTURE: u16 = 30;
pub const LR_OSPF_PREFIX_OPT_AC: u8 = 0x80;

pub const LR_OSPF_END_X_FLAG_B: u8 = 0x80;
pub const LR_OSPF_END_X_FLAG_S: u8 = 0x40;
pub const LR_OSPF_END_X_FLAG_P: u8 = 0x20;

pub const LR_OSPF_EXT_SUBTLV_END_X_SID: u16 = 31;
pub const LR_OSPF_EXT_SUBTLV_LAN_END_X_SID: u16 = 32;

// ---- Extended-LSA TLVs (RFC 8362 §3) ----

pub const LR_OSPF_TLV_ROUTER_LINK: u16 = 1;
pub const LR_OSPF_TLV_ATTACHED_ROUTERS: u16 = 2;
pub const LR_OSPF_TLV_INTER_AREA_PREFIX: u16 = 3;
pub const LR_OSPF_TLV_INTER_AREA_ROUTER: u16 = 4;
pub const LR_OSPF_TLV_EXTERNAL_PREFIX: u16 = 5;
pub const LR_OSPF_TLV_INTRA_AREA_PREFIX: u16 = 6;
pub const LR_OSPF_TLV_IPV6_LINK_LOCAL: u16 = 7;
pub const LR_OSPF_TLV_IPV4_LINK_LOCAL: u16 = 8;

pub const LR_OSPF_SUBTLV_IPV6_FWD_ADDR: u16 = 1;
pub const LR_OSPF_SUBTLV_IPV4_FWD_ADDR: u16 = 2;
pub const LR_OSPF_SUBTLV_ROUTE_TAG: u16 = 3;

pub const LR_OSPF_EXT_PREFIX_BIT_E: u32 = 0x0400_0000;
pub const LR_OSPF_EXT_PREFIX_METRIC_MASK: u32 = 0x00ff_ffff;

#[cfg(test)]
mod tests {
    use super::*;

    /// The constants are pure C-side `#define`s — the only Rust
    /// invariant we need to assert is that they mirror the upstream
    /// Rust crate's values. One assertion per pair keeps drift
    /// noisy.
    #[test]
    fn ffi_ospf_constants_match_rust() {
        assert_eq!(
            LR_OSPF_LSA_TYPE_V2_ROUTER as u16,
            lr_ospf::lsa::LsaTypeV2::RouterLsa as u16
        );
        assert_eq!(
            LR_OSPF_LSA_TYPE_V2_NETWORK as u16,
            lr_ospf::lsa::LsaTypeV2::NetworkLsa as u16
        );
        assert_eq!(
            LR_OSPF_LSA_TYPE_V2_SUMMARY_IP as u16,
            lr_ospf::lsa::LsaTypeV2::SummaryIpLsa as u16
        );
        assert_eq!(
            LR_OSPF_LSA_TYPE_V2_SUMMARY_ASBR as u16,
            lr_ospf::lsa::LsaTypeV2::SummaryAsbrLsa as u16
        );
        assert_eq!(
            LR_OSPF_LSA_TYPE_V2_AS_EXTERNAL as u16,
            lr_ospf::lsa::LsaTypeV2::AsExternalLsa as u16
        );
        assert_eq!(
            LR_OSPF_LSA_TYPE_V2_NSSA_EXTERNAL as u16,
            lr_ospf::lsa::LsaTypeV2::NssaExternalLsa as u16
        );
        assert_eq!(
            LR_OSPF_LSA_TYPE_V2_OPAQUE_LINK as u16,
            lr_ospf::lsa::LsaTypeV2::OpaqueLinkLsa as u16
        );
        assert_eq!(
            LR_OSPF_LSA_TYPE_V2_OPAQUE_AREA as u16,
            lr_ospf::lsa::LsaTypeV2::OpaqueAreaLsa as u16
        );
        assert_eq!(
            LR_OSPF_LSA_TYPE_V2_OPAQUE_AS as u16,
            lr_ospf::lsa::LsaTypeV2::OpaqueAsLsa as u16
        );

        assert_eq!(LR_OSPF_LSA_TYPE_V3_ROUTER, lr_ospf::lsa::v3::LS_TYPE_ROUTER);
        assert_eq!(
            LR_OSPF_LSA_TYPE_V3_NETWORK,
            lr_ospf::lsa::v3::LS_TYPE_NETWORK
        );
        assert_eq!(
            LR_OSPF_LSA_TYPE_V3_INTER_PREFIX,
            lr_ospf::lsa::v3::LS_TYPE_INTER_PREFIX
        );
        assert_eq!(
            LR_OSPF_LSA_TYPE_V3_INTER_ROUTER,
            lr_ospf::lsa::v3::LS_TYPE_INTER_ROUTER
        );
        assert_eq!(
            LR_OSPF_LSA_TYPE_V3_AS_EXTERNAL,
            lr_ospf::lsa::v3::LS_TYPE_AS_EXTERNAL
        );
        assert_eq!(LR_OSPF_LSA_TYPE_V3_NSSA, lr_ospf::lsa::v3::LS_TYPE_NSSA);
        assert_eq!(LR_OSPF_LSA_TYPE_V3_LINK, lr_ospf::lsa::v3::LS_TYPE_LINK);
        assert_eq!(
            LR_OSPF_LSA_TYPE_V3_INTRA_PREFIX,
            lr_ospf::lsa::v3::LS_TYPE_INTRA_PREFIX
        );

        assert_eq!(
            LR_OSPF_INITIAL_SEQUENCE_NUMBER,
            lr_ospf::abr::INITIAL_SEQUENCE_NUMBER
        );
        assert_eq!(
            LR_OSPF_MAX_SEQUENCE_NUMBER,
            lr_ospf::abr::MAX_SEQUENCE_NUMBER
        );
        assert_eq!(LR_OSPF_MAX_AGE_SECS, lr_ospf::lsdb::MAX_AGE_SECS);
        assert_eq!(
            LR_OSPF_LS_REFRESH_TIME_SECS,
            lr_ospf::lsdb::LS_REFRESH_TIME_SECS
        );

        assert_eq!(LR_OSPF_NSSA_N_P_BIT, lr_ospf::nssa::N_P_BIT);
    }
}
