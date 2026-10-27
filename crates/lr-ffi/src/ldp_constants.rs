//! LDP message-type and TLV-type constants (RFC 5036 §3).
//! Exposes lr_ldp::pdu::{MessageType, TlvType} as C constants.

#![allow(dead_code)]

// ---- MessageType (RFC 5036 §3.4 — u16 wire values) ----

pub const LR_LDP_MSG_NOTIFICATION: u16 = 0x0001;
pub const LR_LDP_MSG_HELLO: u16 = 0x0100;
pub const LR_LDP_MSG_INITIALIZATION: u16 = 0x0200;
pub const LR_LDP_MSG_KEEPALIVE: u16 = 0x0201;
pub const LR_LDP_MSG_CAPABILITY: u16 = 0x0202;
pub const LR_LDP_MSG_ADDRESS: u16 = 0x0300;
pub const LR_LDP_MSG_ADDRESS_WITHDRAW: u16 = 0x0301;
pub const LR_LDP_MSG_LABEL_MAPPING: u16 = 0x0400;
pub const LR_LDP_MSG_LABEL_REQUEST: u16 = 0x0401;
pub const LR_LDP_MSG_LABEL_WITHDRAW: u16 = 0x0402;
pub const LR_LDP_MSG_LABEL_RELEASE: u16 = 0x0403;
pub const LR_LDP_MSG_LABEL_ABORT_REQUEST: u16 = 0x0404;

// ---- TlvType (RFC 5036 §3.4.1 — u16 wire values) ----

pub const LR_LDP_TLV_FEC: u16 = 0x0100;
pub const LR_LDP_TLV_ADDRESS_LIST: u16 = 0x0101;
pub const LR_LDP_TLV_HOP_COUNT: u16 = 0x0103;
pub const LR_LDP_TLV_PATH_VECTOR: u16 = 0x0104;
pub const LR_LDP_TLV_GENERIC_LABEL: u16 = 0x0200;
pub const LR_LDP_TLV_ATM_LABEL: u16 = 0x0201;
pub const LR_LDP_TLV_FRAME_RELAY_LABEL: u16 = 0x0202;
pub const LR_LDP_TLV_STATUS: u16 = 0x0300;
pub const LR_LDP_TLV_EXTENDED_STATUS: u16 = 0x0301;
pub const LR_LDP_TLV_RETURNED_PDU: u16 = 0x0302;
pub const LR_LDP_TLV_RETURNED_MESSAGE: u16 = 0x0303;
pub const LR_LDP_TLV_COMMON_HELLO_PARAMETERS: u16 = 0x0400;
pub const LR_LDP_TLV_CONFIG_SEQUENCE_NUMBER: u16 = 0x0402;
pub const LR_LDP_TLV_COMMON_SESSION_PARAMETERS: u16 = 0x0500;
pub const LR_LDP_TLV_ATM_SESSION_PARAMETERS: u16 = 0x0501;
pub const LR_LDP_TLV_FRAME_RELAY_SESSION_PARAMETERS: u16 = 0x0502;
pub const LR_LDP_TLV_LABEL_REQUEST_MESSAGE_ID: u16 = 0x0600;
pub const LR_LDP_TLV_LDP_CAPABILITY: u16 = 0x0601;

// ---- LDP status codes (RFC 5036 §3.5.7 — u32) ----

pub const LR_LDP_STATUS_SUCCESS: u32 = 0x0000_0000;
pub const LR_LDP_STATUS_BAD_LDP_IDENTIFIER: u32 = 0x0000_0001;
pub const LR_LDP_STATUS_BAD_PROTOCOL_VERSION: u32 = 0x0000_0002;
pub const LR_LDP_STATUS_BAD_PDU_LENGTH: u32 = 0x0000_0003;
pub const LR_LDP_STATUS_UNKNOWN_MESSAGE_TYPE: u32 = 0x0000_0004;
pub const LR_LDP_STATUS_BAD_MESSAGE_LENGTH: u32 = 0x0000_0005;
pub const LR_LDP_STATUS_UNKNOWN_TLV: u32 = 0x0000_0006;
pub const LR_LDP_STATUS_BAD_TLV_LENGTH: u32 = 0x0000_0007;
pub const LR_LDP_STATUS_MALFORMED_TLV_VALUE: u32 = 0x0000_0008;
pub const LR_LDP_STATUS_HOLD_TIMER_EXPIRED: u32 = 0x0000_0009;
pub const LR_LDP_STATUS_KEEPALIVE_TIMER_EXPIRED: u32 = 0x0000_000A;
pub const LR_LDP_STATUS_SHUTDOWN: u32 = 0x0000_000B;
pub const LR_LDP_STATUS_LOOP_DETECTED: u32 = 0x0000_000C;
pub const LR_LDP_STATUS_TRANSPORT_CONNECTION_MISMATCH: u32 = 0x0000_000D;
pub const LR_LDP_STATUS_DUAL_STACK_NONCOMPLIANCE: u32 = 0x0000_000E;
pub const LR_LDP_STATUS_KEEP_ALIVE_MISSED: u32 = 0x0000_000F;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ffi_msg_types_match_rfc() {
        assert_eq!(LR_LDP_MSG_NOTIFICATION, 0x0001);
        assert_eq!(LR_LDP_MSG_HELLO, 0x0100);
        assert_eq!(LR_LDP_MSG_INITIALIZATION, 0x0200);
        assert_eq!(LR_LDP_MSG_LABEL_MAPPING, 0x0400);
        assert_eq!(LR_LDP_MSG_LABEL_ABORT_REQUEST, 0x0404);
    }

    #[test]
    fn ffi_tlv_types_match_rfc() {
        assert_eq!(LR_LDP_TLV_FEC, 0x0100);
        assert_eq!(LR_LDP_TLV_GENERIC_LABEL, 0x0200);
        assert_eq!(LR_LDP_TLV_STATUS, 0x0300);
    }

    #[test]
    fn ffi_status_codes_match_rfc() {
        assert_eq!(LR_LDP_STATUS_SUCCESS, 0);
        assert_eq!(LR_LDP_STATUS_SHUTDOWN, 0x0B);
        assert_eq!(LR_LDP_STATUS_LOOP_DETECTED, 0x0C);
    }
}
