//! BMP constants FFI — PeerType + PeerDownReason (RFC 7854 §4).

#![allow(dead_code)]

// ---- PeerType (RFC 7854 §4.2) ----

pub const LR_BMP_PEER_TYPE_GLOBAL: u8 = 0;
pub const LR_BMP_PEER_TYPE_RD: u8 = 1;
pub const LR_BMP_PEER_TYPE_LOCAL: u8 = 2;

// ---- PeerDownReason (RFC 7854 §4.9) ----

pub const LR_BMP_PEER_DOWN_LOCAL_CLOSE: u8 = 1;
pub const LR_BMP_PEER_DOWN_REMOTE_CLOSE: u8 = 2;
pub const LR_BMP_PEER_DOWN_REMOTE_NOTIFICATION: u8 = 3;
pub const LR_BMP_PEER_DOWN_DEPLETED_RESOURCE: u8 = 4;
pub const LR_BMP_PEER_DOWN_ADMIN_RESET: u8 = 5;

// ---- BmpMsgType (RFC 7854 §4) ----

pub const LR_BMP_MSG_ROUTE_MONITORING: u8 = 0;
pub const LR_BMP_MSG_STATISTICS_REPORT: u8 = 1;
pub const LR_BMP_MSG_PEER_DOWN: u8 = 2;
pub const LR_BMP_MSG_PEER_UP: u8 = 3;
pub const LR_BMP_MSG_INITIATION: u8 = 4;
pub const LR_BMP_MSG_TERMINATION: u8 = 5;
pub const LR_BMP_MSG_ROUTE_MIRRORING: u8 = 6;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ffi_peer_types_match_rfc() {
        assert_eq!(LR_BMP_PEER_TYPE_GLOBAL, 0);
        assert_eq!(LR_BMP_PEER_TYPE_RD, 1);
        assert_eq!(LR_BMP_PEER_TYPE_LOCAL, 2);
    }

    #[test]
    fn ffi_peer_down_reasons_match_rfc() {
        assert_eq!(LR_BMP_PEER_DOWN_LOCAL_CLOSE, 1);
        assert_eq!(LR_BMP_PEER_DOWN_REMOTE_NOTIFICATION, 3);
        assert_eq!(LR_BMP_PEER_DOWN_ADMIN_RESET, 5);
    }

    #[test]
    fn ffi_msg_types_match_rfc() {
        assert_eq!(LR_BMP_MSG_ROUTE_MONITORING, 0);
        assert_eq!(LR_BMP_MSG_PEER_UP, 3);
        assert_eq!(LR_BMP_MSG_ROUTE_MIRRORING, 6);
    }
}
