//! MRT constants FFI — `msg_type`, `tdv2_subtype`, `bgp4mp_subtype`
//! (RFC 6396 §4.3 / §4.4 / §8050 §4).
//!
//! Mirrors `lr_mrt::{msg_type, tdv2_subtype, bgp4mp_subtype}` so a C
//! embedder can compare the values returned by `lr_mrt_record_type`
//! and `lr_mrt_record_subtype` without re-deriving them from the RFC.

#![allow(dead_code)]

// ---- MRT record types (RFC 6396 §4 — u16 wire values) ----

/// Legacy TABLE_DUMP (v1) — superseded by `TABLE_DUMP_V2`. Decodes as
/// `MrtRecord::Unknown`.
pub const LR_MRT_MSG_TYPE_TABLE_DUMP: u16 = 12;
/// TABLE_DUMP_V2 — peer index tables and per-prefix RIB records.
pub const LR_MRT_MSG_TYPE_TABLE_DUMP_V2: u16 = 13;
/// BGP4MP — BGP message and state-change log (2-byte AS).
pub const LR_MRT_MSG_TYPE_BGP4MP: u16 = 16;
/// BGP4MP with microsecond timestamps.
pub const LR_MRT_MSG_TYPE_BGP4MP_ET: u16 = 17;

// ---- TABLE_DUMP_V2 subtypes (RFC 6396 §4.3) ----

pub const LR_MRT_TDV2_PEER_INDEX_TABLE: u16 = 1;
pub const LR_MRT_TDV2_RIB_IPV4_UNICAST: u16 = 2;
pub const LR_MRT_TDV2_RIB_IPV4_MULTICAST: u16 = 3;
pub const LR_MRT_TDV2_RIB_IPV6_UNICAST: u16 = 4;
pub const LR_MRT_TDV2_RIB_IPV6_MULTICAST: u16 = 5;
pub const LR_MRT_TDV2_RIB_GENERIC: u16 = 6;
pub const LR_MRT_TDV2_RIB_IPV4_UNICAST_ADDPATH: u16 = 7;
pub const LR_MRT_TDV2_RIB_IPV4_MULTICAST_ADDPATH: u16 = 8;
pub const LR_MRT_TDV2_RIB_IPV6_UNICAST_ADDPATH: u16 = 9;
pub const LR_MRT_TDV2_RIB_IPV6_MULTICAST_ADDPATH: u16 = 10;
pub const LR_MRT_TDV2_RIB_GENERIC_ADDPATH: u16 = 11;

// ---- BGP4MP subtypes (RFC 6396 §4.4) ----

pub const LR_MRT_BGP4MP_STATE_CHANGE: u16 = 0;
pub const LR_MRT_BGP4MP_MESSAGE: u16 = 1;
/// Deprecated pre-publication layout (Zebra `BGP4MP_ENTRY`) — decodes
/// as `MrtRecord::Unknown`.
pub const LR_MRT_BGP4MP_ENTRY: u16 = 2;
/// Deprecated pre-publication layout (Zebra `BGP4MP_SNAPSHOT`) —
/// decodes as `MrtRecord::Unknown`.
pub const LR_MRT_BGP4MP_SNAPSHOT: u16 = 3;
pub const LR_MRT_BGP4MP_MESSAGE_AS4: u16 = 4;
pub const LR_MRT_BGP4MP_STATE_CHANGE_AS4: u16 = 5;
/// Deprecated — decodes as `MrtRecord::Unknown`.
pub const LR_MRT_BGP4MP_MESSAGE_LOCAL: u16 = 6;
/// Deprecated — decodes as `MrtRecord::Unknown`.
pub const LR_MRT_BGP4MP_MESSAGE_AS4_LOCAL: u16 = 7;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ffi_msg_types_match_rfc() {
        assert_eq!(LR_MRT_MSG_TYPE_TABLE_DUMP, 12);
        assert_eq!(LR_MRT_MSG_TYPE_TABLE_DUMP_V2, 13);
        assert_eq!(LR_MRT_MSG_TYPE_BGP4MP, 16);
        assert_eq!(LR_MRT_MSG_TYPE_BGP4MP_ET, 17);
    }

    #[test]
    fn ffi_tdv2_subtypes_match_rfc() {
        assert_eq!(LR_MRT_TDV2_PEER_INDEX_TABLE, 1);
        assert_eq!(LR_MRT_TDV2_RIB_IPV4_UNICAST, 2);
        assert_eq!(LR_MRT_TDV2_RIB_IPV6_UNICAST, 4);
        assert_eq!(LR_MRT_TDV2_RIB_GENERIC, 6);
        assert_eq!(LR_MRT_TDV2_RIB_IPV4_UNICAST_ADDPATH, 7);
        assert_eq!(LR_MRT_TDV2_RIB_GENERIC_ADDPATH, 11);
    }

    #[test]
    fn ffi_bgp4mp_subtypes_match_rfc() {
        assert_eq!(LR_MRT_BGP4MP_STATE_CHANGE, 0);
        assert_eq!(LR_MRT_BGP4MP_MESSAGE, 1);
        assert_eq!(LR_MRT_BGP4MP_MESSAGE_AS4, 4);
        assert_eq!(LR_MRT_BGP4MP_STATE_CHANGE_AS4, 5);
    }
}
