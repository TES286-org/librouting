//! BGP error code constants FFI — exposes the wire constants from
//! lr_bgp::error::{BgpErrorCode, BgpOpenErrorSubcode,
//! BgpUpdateErrorSubcode, BgpHeaderErrorSubcode, BgpCeaseSubcode}
//! as C `#define`-equivalent `pub const` values.
//!
//! These were previously returned as raw u8 values by
//! `lr_bgp_message_notification_code` / `_subcode` but embedders
//! had no named constants to switch on — they had to use magic
//! numbers. This module gives them the names.

#![allow(dead_code)]

// ---- BgpErrorCode (RFC 4271 §6) ----

pub const LR_BGP_ERR_HEADER: u8 = 1;
pub const LR_BGP_ERR_OPEN: u8 = 2;
pub const LR_BGP_ERR_UPDATE: u8 = 3;
pub const LR_BGP_ERR_HOLD_TIMER_EXPIRED: u8 = 4;
pub const LR_BGP_ERR_FSM_ERROR: u8 = 5;
pub const LR_BGP_ERR_CEASE: u8 = 6;
pub const LR_BGP_ERR_ROUTE_REFRESH: u8 = 7;

// ---- BgpOpenErrorSubcode (RFC 4271 §6.2) ----

pub const LR_BGP_OPEN_UNSUPPORTED_VERSION: u8 = 1;
pub const LR_BGP_OPEN_BAD_PEER_AS: u8 = 2;
pub const LR_BGP_OPEN_BAD_BGP_IDENTIFIER: u8 = 3;
pub const LR_BGP_OPEN_UNSUPPORTED_OPTIONAL_PARAM: u8 = 4;
pub const LR_BGP_OPEN_AUTHENTICATION_FAILURE: u8 = 5;
pub const LR_BGP_OPEN_UNACCEPTABLE_HOLD_TIME: u8 = 6;
pub const LR_BGP_OPEN_UNSUPPORTED_CAPABILITY: u8 = 7;
pub const LR_BGP_OPEN_BAD_OPEN_LENGTH: u8 = 8;

// ---- BgpUpdateErrorSubcode (RFC 4271 §6.3) ----

pub const LR_BGP_UPDATE_MALFORMED_ATTRIBUTE_LIST: u8 = 1;
pub const LR_BGP_UPDATE_UNRECOGNIZED_WELL_KNOWN_ATTR: u8 = 2;
pub const LR_BGP_UPDATE_MISSING_WELL_KNOWN_ATTR: u8 = 3;
pub const LR_BGP_UPDATE_ATTRIBUTE_FLAGS_ERROR: u8 = 4;
pub const LR_BGP_UPDATE_ATTRIBUTE_LENGTH_ERROR: u8 = 5;
pub const LR_BGP_UPDATE_INVALID_ORIGIN_ATTR: u8 = 6;
pub const LR_BGP_UPDATE_ATTR_DISCONTINUED_DEPRECATED: u8 = 7;
pub const LR_BGP_UPDATE_INVALID_AS_PATH: u8 = 8;
pub const LR_BGP_UPDATE_INVALID_NEXT_HOP: u8 = 9;
pub const LR_BGP_UPDATE_OPTIONAL_ATTRIBUTE_ERROR: u8 = 10;
pub const LR_BGP_UPDATE_INVALID_NETWORK_FIELD: u8 = 11;
pub const LR_BGP_UPDATE_MALFORMED_AS_PATH: u8 = 12;

// ---- BgpHeaderErrorSubcode (RFC 4271 §6.1) ----

pub const LR_BGP_HDR_CONNECTION_NOT_SYNCHRONIZED: u8 = 1;
pub const LR_BGP_HDR_BAD_MESSAGE_LENGTH: u8 = 2;
pub const LR_BGP_HDR_BAD_MESSAGE_TYPE: u8 = 3;

// ---- BgpCeaseSubcode (RFC 4486 + RFC 9494) ----

pub const LR_BGP_CEASE_MAXIMUM_PREFIXES: u8 = 1;
pub const LR_BGP_CEASE_ADMINISTRATIVE_SHUTDOWN: u8 = 2;
pub const LR_BGP_CEASE_PEER_DECONFIGURED: u8 = 3;
pub const LR_BGP_CEASE_ADMINISTRATIVE_RESET: u8 = 4;
pub const LR_BGP_CEASE_CONNECTION_REJECTED: u8 = 5;
pub const LR_BGP_CEASE_OTHER_CONFIG_CHANGE: u8 = 6;
pub const LR_BGP_CEASE_CONNECTION_COLLISION: u8 = 7;
pub const LR_BGP_CEASE_OUT_OF_RESOURCES: u8 = 8;
pub const LR_BGP_CEASE_HARD_RESET: u8 = 9;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ffi_error_codes_match_rfc() {
        // Verify the constants match the RFC values.
        assert_eq!(LR_BGP_ERR_HEADER, 1);
        assert_eq!(LR_BGP_ERR_OPEN, 2);
        assert_eq!(LR_BGP_ERR_UPDATE, 3);
        assert_eq!(LR_BGP_ERR_HOLD_TIMER_EXPIRED, 4);
        assert_eq!(LR_BGP_ERR_FSM_ERROR, 5);
        assert_eq!(LR_BGP_ERR_CEASE, 6);
        assert_eq!(LR_BGP_ERR_ROUTE_REFRESH, 7);
    }

    #[test]
    fn ffi_open_subcodes_match_rfc() {
        assert_eq!(LR_BGP_OPEN_UNSUPPORTED_VERSION, 1);
        assert_eq!(LR_BGP_OPEN_BAD_PEER_AS, 2);
        assert_eq!(LR_BGP_OPEN_BAD_BGP_IDENTIFIER, 3);
        assert_eq!(LR_BGP_OPEN_UNSUPPORTED_CAPABILITY, 7);
    }

    #[test]
    fn ffi_update_subcodes_match_rfc() {
        assert_eq!(LR_BGP_UPDATE_MALFORMED_ATTRIBUTE_LIST, 1);
        assert_eq!(LR_BGP_UPDATE_INVALID_AS_PATH, 8);
        assert_eq!(LR_BGP_UPDATE_MALFORMED_AS_PATH, 12);
    }

    #[test]
    fn ffi_cease_subcodes_match_rfc() {
        assert_eq!(LR_BGP_CEASE_MAXIMUM_PREFIXES, 1);
        assert_eq!(LR_BGP_CEASE_ADMINISTRATIVE_SHUTDOWN, 2);
        assert_eq!(LR_BGP_CEASE_HARD_RESET, 9);
    }
}
