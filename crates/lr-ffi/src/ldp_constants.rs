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

// ---- LDP status codes (RFC 5036 §3.5.7 — u32 wire values) ----
//
// NOT defined here. The wire-value set lives in
// [`crate::ldp_tlv`] (`LR_LDP_STATUS_SHUTDOWN = 0x8000_000A` etc.) —
// those are the exact codes `lr_ldp::tlv::Status` carries on the wire
// and the engine writes into `lr_ldp_engine_event_t::status_code`.
// This module previously re-declared the same names with small
// sequential values (SHUTDOWN = 11), which cbindgen picked for the
// header, so a consumer matching events against the constants got
// the wrong answer for every code. The single definition is
// re-exported below so historical `crate::ldp_constants::` paths keep
// resolving.
pub use crate::ldp_tlv::{
    LR_LDP_STATUS_BAD_LDP_IDENTIFIER, LR_LDP_STATUS_BAD_MESSAGE_LENGTH,
    LR_LDP_STATUS_BAD_PDU_LENGTH, LR_LDP_STATUS_BAD_PROTOCOL_VERSION, LR_LDP_STATUS_BAD_TLV_LENGTH,
    LR_LDP_STATUS_DUAL_STACK_NONCOMPLIANCE, LR_LDP_STATUS_HOLD_TIMER_EXPIRED,
    LR_LDP_STATUS_KEEPALIVE_TIMER_EXPIRED, LR_LDP_STATUS_LABEL_RESOURCE_AVAILABLE,
    LR_LDP_STATUS_LABEL_WITHDRAW, LR_LDP_STATUS_LOOP_DETECTED, LR_LDP_STATUS_MALFORMED_TLV_VALUE,
    LR_LDP_STATUS_NO_LABEL_RESOURCE, LR_LDP_STATUS_NO_ROUTE, LR_LDP_STATUS_SESSION_REJECTED,
    LR_LDP_STATUS_SHUTDOWN, LR_LDP_STATUS_SUCCESS, LR_LDP_STATUS_TRANSPORT_CONNECTION_MISMATCH,
    LR_LDP_STATUS_UNKNOWN_FEC, LR_LDP_STATUS_UNKNOWN_MESSAGE_TYPE, LR_LDP_STATUS_UNKNOWN_TLV,
};

#[cfg(test)]
mod tests {
    use super::*;
    use lr_ldp::pdu::{MessageType, TlvType};

    #[test]
    fn msg_type_constants_match_rust_enum() {
        assert_eq!(LR_LDP_MSG_NOTIFICATION, MessageType::Notification as u16);
        assert_eq!(LR_LDP_MSG_HELLO, MessageType::Hello as u16);
        assert_eq!(
            LR_LDP_MSG_INITIALIZATION,
            MessageType::Initialization as u16
        );
        assert_eq!(LR_LDP_MSG_KEEPALIVE, MessageType::KeepAlive as u16);
        assert_eq!(LR_LDP_MSG_CAPABILITY, MessageType::Capability as u16);
        assert_eq!(LR_LDP_MSG_ADDRESS, MessageType::Address as u16);
        assert_eq!(
            LR_LDP_MSG_ADDRESS_WITHDRAW,
            MessageType::AddressWithdraw as u16
        );
        assert_eq!(LR_LDP_MSG_LABEL_MAPPING, MessageType::LabelMapping as u16);
        assert_eq!(LR_LDP_MSG_LABEL_REQUEST, MessageType::LabelRequest as u16);
        assert_eq!(LR_LDP_MSG_LABEL_WITHDRAW, MessageType::LabelWithdraw as u16);
        assert_eq!(LR_LDP_MSG_LABEL_RELEASE, MessageType::LabelRelease as u16);
        assert_eq!(
            LR_LDP_MSG_LABEL_ABORT_REQUEST,
            MessageType::LabelAbortRequest as u16
        );
    }

    #[test]
    fn tlv_type_constants_match_rust_enum() {
        assert_eq!(LR_LDP_TLV_FEC, TlvType::Fec as u16);
        assert_eq!(LR_LDP_TLV_ADDRESS_LIST, TlvType::AddressList as u16);
        assert_eq!(LR_LDP_TLV_HOP_COUNT, TlvType::HopCount as u16);
        assert_eq!(LR_LDP_TLV_PATH_VECTOR, TlvType::PathVector as u16);
        assert_eq!(LR_LDP_TLV_GENERIC_LABEL, TlvType::GenericLabel as u16);
        assert_eq!(LR_LDP_TLV_ATM_LABEL, TlvType::AtmLabel as u16);
        assert_eq!(
            LR_LDP_TLV_FRAME_RELAY_LABEL,
            TlvType::FrameRelayLabel as u16
        );
        assert_eq!(LR_LDP_TLV_STATUS, TlvType::Status as u16);
        assert_eq!(LR_LDP_TLV_EXTENDED_STATUS, TlvType::ExtendedStatus as u16);
        assert_eq!(LR_LDP_TLV_RETURNED_PDU, TlvType::ReturnedPdu as u16);
        assert_eq!(LR_LDP_TLV_RETURNED_MESSAGE, TlvType::ReturnedMessage as u16);
        assert_eq!(
            LR_LDP_TLV_COMMON_HELLO_PARAMETERS,
            TlvType::CommonHelloParameters as u16
        );
        assert_eq!(
            LR_LDP_TLV_CONFIG_SEQUENCE_NUMBER,
            TlvType::ConfigSequenceNumber as u16
        );
        assert_eq!(
            LR_LDP_TLV_COMMON_SESSION_PARAMETERS,
            TlvType::CommonSessionParameters as u16
        );
        assert_eq!(
            LR_LDP_TLV_ATM_SESSION_PARAMETERS,
            TlvType::AtmSessionParameters as u16
        );
        assert_eq!(
            LR_LDP_TLV_FRAME_RELAY_SESSION_PARAMETERS,
            TlvType::FrameRelaySessionParameters as u16
        );
        assert_eq!(
            LR_LDP_TLV_LABEL_REQUEST_MESSAGE_ID,
            TlvType::LabelRequestMessageId as u16
        );
        assert_eq!(LR_LDP_TLV_LDP_CAPABILITY, TlvType::LdpCapability as u16);
    }

    #[test]
    fn status_constants_carry_the_wire_values() {
        // RFC 5036 §3.5.7: the F-bit-encodes-fatal wire codes, not
        // sequential small numbers.
        assert_eq!(LR_LDP_STATUS_SHUTDOWN, 0x8000_000A);
        assert_eq!(LR_LDP_STATUS_KEEPALIVE_TIMER_EXPIRED, 0x8000_0012);
        assert_eq!(LR_LDP_STATUS_LOOP_DETECTED, 0x8000_000B);
    }
}
