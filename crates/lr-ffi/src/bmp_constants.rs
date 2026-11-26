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

// ---- BMP protocol version (RFC 7854 §3.1 — version 3) ----
//
// Literal 3, not a re-export of `lr_bmp::VERSION`: a cross-crate path
// is a value cbindgen cannot evaluate, and it previously reached the
// header as the undefined bare identifier `#define LR_BMP_VERSION
// VERSION`. A pinned test below fails if lr_bmp ever moves off
// version 3, so the literal cannot drift silently.
pub const LR_BMP_VERSION: u8 = 3;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_literal_matches_lr_bmp() {
        assert_eq!(LR_BMP_VERSION, lr_bmp::VERSION);
    }

    #[test]
    fn msg_types_match_lr_bmp_enum() {
        use lr_bmp::BmpMsgType;
        assert_eq!(
            LR_BMP_MSG_ROUTE_MONITORING,
            BmpMsgType::RouteMonitoring as u8
        );
        assert_eq!(
            LR_BMP_MSG_STATISTICS_REPORT,
            BmpMsgType::StatisticsReport as u8
        );
        assert_eq!(LR_BMP_MSG_PEER_DOWN, BmpMsgType::PeerDown as u8);
        assert_eq!(LR_BMP_MSG_PEER_UP, BmpMsgType::PeerUp as u8);
        assert_eq!(LR_BMP_MSG_INITIATION, BmpMsgType::Initiation as u8);
        assert_eq!(LR_BMP_MSG_TERMINATION, BmpMsgType::Termination as u8);
        assert_eq!(LR_BMP_MSG_ROUTE_MIRRORING, BmpMsgType::RouteMirroring as u8);
    }

    #[test]
    fn peer_types_match_lr_bmp_enum() {
        use lr_bmp::PeerType;
        assert_eq!(LR_BMP_PEER_TYPE_GLOBAL, PeerType::Global as u8);
        assert_eq!(LR_BMP_PEER_TYPE_RD, PeerType::Rd as u8);
        assert_eq!(LR_BMP_PEER_TYPE_LOCAL, PeerType::Local as u8);
    }

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
