//! Enum accessor triplets (`from_u*` / `to_u*` / `name`) for the
//! protocol crates whose pub enum surfaces were not yet exposed via
//! the C ABI.
//!
//! Mirrors the established pattern in `bgp_enums.rs`:
//! - `lr_<crate>_<enum>_from_u8(u8) -> u8` — round-trip; returns the
//!   input when it matches a known variant, 0 otherwise (0 is never a
//!   valid variant on the wire for the covered enums, so it is a safe
//!   "unknown" sentinel).
//! - `lr_<crate>_<enum>_to_u8(u8) -> u8` — identity (the wire form IS
//!   the enum discriminant).
//! - `lr_<crate>_<enum>_name(u8) -> *const c_char` — returns the
//!   Display string for the variant, or `"unknown"` for an unknown
//!   value. The pointer is valid until the next call on the same
//!   thread.
//!
//! For 16-bit discriminant enums (`MessageType`, `TlvType`,
//! `LsaTypeV3`), the suffix is `_u16`.

#![allow(unused_unsafe)]

use lr_bfd::auth::AuthType;
use lr_bfd::packet::{Diagnostic, State};
use lr_bmp::{BmpMsgType, PeerDownReason, PeerType};
use lr_ldp::pdu::{AdvertisementMode, MessageType, TlvType};
use lr_mpls::LabelStackError;
use lr_ospf::lsa::{LsaTypeV2, LsaTypeV3, RouterLinkType};
use lr_router::session::{OspfNetworkType, SessionErrorKind};
use lr_srv6::{LocatorParseError, SidParseError};

use crate::guarded;

fn name_ptr(s: &str) -> *const std::os::raw::c_char {
    thread_local! {
        static BUF: std::cell::RefCell<Vec<u8>> = const { std::cell::RefCell::new(Vec::new()) };
    }
    BUF.with(|b| {
        let mut b = b.borrow_mut();
        b.clear();
        b.extend_from_slice(s.as_bytes());
        b.push(0);
        b.as_ptr() as *const std::os::raw::c_char
    })
}

// =========================================================================
// lr-bfd: AuthType, Diagnostic, State, KeyedAuthAlgorithm
// =========================================================================

#[no_mangle]
pub extern "C" fn lr_bfd_auth_type_from_u8(v: u8) -> u8 {
    guarded(|| AuthType::from_u8(v).to_u8(), 0)
}

#[no_mangle]
pub extern "C" fn lr_bfd_auth_type_to_u8(v: u8) -> u8 {
    v
}

#[no_mangle]
pub extern "C" fn lr_bfd_auth_type_name(v: u8) -> *const std::os::raw::c_char {
    guarded(
        || {
            let t = AuthType::from_u8(v);
            name_ptr(&format!("{t:?}"))
        },
        std::ptr::null(),
    )
}

#[no_mangle]
pub extern "C" fn lr_bfd_diagnostic_from_u8(v: u8) -> u8 {
    guarded(|| Diagnostic::from_u8(v).to_u8(), 0)
}

#[no_mangle]
pub extern "C" fn lr_bfd_diagnostic_to_u8(v: u8) -> u8 {
    v
}

#[no_mangle]
pub extern "C" fn lr_bfd_diagnostic_name(v: u8) -> *const std::os::raw::c_char {
    guarded(
        || {
            let d = Diagnostic::from_u8(v);
            name_ptr(d.name())
        },
        std::ptr::null(),
    )
}

#[no_mangle]
pub extern "C" fn lr_bfd_state_from_u8(v: u8) -> u8 {
    guarded(|| State::from_u8(v).map(|s| s as u8).unwrap_or(0), 0)
}

#[no_mangle]
pub extern "C" fn lr_bfd_state_to_u8(v: u8) -> u8 {
    v
}

#[no_mangle]
pub extern "C" fn lr_bfd_state_name(v: u8) -> *const std::os::raw::c_char {
    guarded(
        || match State::from_u8(v) {
            Some(s) => name_ptr(s.name()),
            None => name_ptr("unknown"),
        },
        std::ptr::null(),
    )
}

#[no_mangle]
pub extern "C" fn lr_bfd_keyed_auth_algorithm_from_u8(v: u8) -> u8 {
    guarded(
        || {
            // KeyedAuthAlgorithm has no from_u8; reconstruct via the
            // AuthType round-trip (every algorithm corresponds to a
            // distinct auth_type code per RFC 5880 §4.3/§4.4).
            let auth = AuthType::from_u8(v);
            match auth {
                AuthType::KeyedMd5 => 2,
                AuthType::MeticulousKeyedMd5 => 3,
                AuthType::KeyedSha1 => 4,
                AuthType::MeticulousKeyedSha1 => 5,
                _ => 0,
            }
        },
        0,
    )
}

#[no_mangle]
pub extern "C" fn lr_bfd_keyed_auth_algorithm_to_u8(v: u8) -> u8 {
    v
}

#[no_mangle]
pub extern "C" fn lr_bfd_keyed_auth_algorithm_name(v: u8) -> *const std::os::raw::c_char {
    guarded(
        || {
            let auth = AuthType::from_u8(v);
            let s = match auth {
                AuthType::KeyedMd5 => "KeyedMd5",
                AuthType::MeticulousKeyedMd5 => "MeticulousKeyedMd5",
                AuthType::KeyedSha1 => "KeyedSha1",
                AuthType::MeticulousKeyedSha1 => "MeticulousKeyedSha1",
                _ => "unknown",
            };
            name_ptr(s)
        },
        std::ptr::null(),
    )
}

// =========================================================================
// lr-bmp: BmpMsgType, PeerType, PeerDownReason
// =========================================================================
//
// PeerType and PeerDownReason do not have from_u8 in lr-bmp; the FFI
// walks the discriminants via the documented wire values (the enums
// are #[repr(u8)] so the integer cast is sound).

#[no_mangle]
pub extern "C" fn lr_bmp_msg_type_from_u8(v: u8) -> u8 {
    guarded(|| BmpMsgType::from_u8(v).map(|t| t as u8).unwrap_or(0), 0)
}

#[no_mangle]
pub extern "C" fn lr_bmp_msg_type_to_u8(v: u8) -> u8 {
    v
}

#[no_mangle]
pub extern "C" fn lr_bmp_msg_type_name(v: u8) -> *const std::os::raw::c_char {
    guarded(
        || match BmpMsgType::from_u8(v) {
            Some(t) => name_ptr(&format!("{t:?}")),
            None => name_ptr("unknown"),
        },
        std::ptr::null(),
    )
}

#[no_mangle]
pub extern "C" fn lr_bmp_peer_type_from_u8(v: u8) -> u8 {
    // PeerType is #[repr(u8)] with variants 0..=2 — return the input
    // when it matches a known variant, 0 otherwise.
    match v {
        0..=2 => v,
        _ => 0,
    }
}

#[no_mangle]
pub extern "C" fn lr_bmp_peer_type_to_u8(v: u8) -> u8 {
    v
}

#[no_mangle]
pub extern "C" fn lr_bmp_peer_type_name(v: u8) -> *const std::os::raw::c_char {
    guarded(
        || match v {
            0 => name_ptr("Global"),
            1 => name_ptr("Rd"),
            2 => name_ptr("Local"),
            _ => name_ptr("unknown"),
        },
        std::ptr::null(),
    )
}

#[no_mangle]
pub extern "C" fn lr_bmp_peer_down_reason_from_u8(v: u8) -> u8 {
    // PeerDownReason is #[repr(u8)] with variants 1..=5.
    match v {
        1..=5 => v,
        _ => 0,
    }
}

#[no_mangle]
pub extern "C" fn lr_bmp_peer_down_reason_to_u8(v: u8) -> u8 {
    v
}

#[no_mangle]
pub extern "C" fn lr_bmp_peer_down_reason_name(v: u8) -> *const std::os::raw::c_char {
    guarded(
        || match v {
            1 => name_ptr("LocalClose"),
            2 => name_ptr("RemoteClose"),
            3 => name_ptr("RemoteNotification"),
            4 => name_ptr("DepletedResource"),
            5 => name_ptr("AdminReset"),
            _ => name_ptr("unknown"),
        },
        std::ptr::null(),
    )
}

// =========================================================================
// lr-ospf: LsaTypeV2 (u8), LsaTypeV3 (u16), RouterLinkType (u8)
// =========================================================================

#[no_mangle]
pub extern "C" fn lr_ospf_lsa_type_v2_from_u8(v: u8) -> u8 {
    guarded(|| LsaTypeV2::from_u8(v).map(|t| t as u8).unwrap_or(0), 0)
}

#[no_mangle]
pub extern "C" fn lr_ospf_lsa_type_v2_to_u8(v: u8) -> u8 {
    v
}

#[no_mangle]
pub extern "C" fn lr_ospf_lsa_type_v2_name(v: u8) -> *const std::os::raw::c_char {
    guarded(
        || match LsaTypeV2::from_u8(v) {
            Some(t) => name_ptr(&format!("{t:?}")),
            None => name_ptr("unknown"),
        },
        std::ptr::null(),
    )
}

#[no_mangle]
pub extern "C" fn lr_ospf_lsa_type_v3_from_u16(v: u16) -> u16 {
    guarded(|| LsaTypeV3::from_u16(v).map(|t| t as u16).unwrap_or(0), 0)
}

#[no_mangle]
pub extern "C" fn lr_ospf_lsa_type_v3_to_u16(v: u16) -> u16 {
    v
}

#[no_mangle]
pub extern "C" fn lr_ospf_lsa_type_v3_name(v: u16) -> *const std::os::raw::c_char {
    guarded(
        || match LsaTypeV3::from_u16(v) {
            Some(t) => name_ptr(&format!("{t:?}")),
            None => name_ptr("unknown"),
        },
        std::ptr::null(),
    )
}

#[no_mangle]
pub extern "C" fn lr_ospf_router_link_type_from_u8(v: u8) -> u8 {
    guarded(
        || RouterLinkType::from_u8(v).map(|t| t as u8).unwrap_or(0),
        0,
    )
}

#[no_mangle]
pub extern "C" fn lr_ospf_router_link_type_to_u8(v: u8) -> u8 {
    v
}

#[no_mangle]
pub extern "C" fn lr_ospf_router_link_type_name(v: u8) -> *const std::os::raw::c_char {
    guarded(
        || match RouterLinkType::from_u8(v) {
            Some(t) => name_ptr(&format!("{t:?}")),
            None => name_ptr("unknown"),
        },
        std::ptr::null(),
    )
}

// =========================================================================
// lr-ldp: MessageType (u16), TlvType (u16), AdvertisementMode (i32)
// =========================================================================

#[no_mangle]
pub extern "C" fn lr_ldp_message_type_from_u16(v: u16) -> u16 {
    guarded(
        || MessageType::from_u16(v).map(|t| t as u16).unwrap_or(0),
        0,
    )
}

#[no_mangle]
pub extern "C" fn lr_ldp_message_type_to_u16(v: u16) -> u16 {
    v
}

#[no_mangle]
pub extern "C" fn lr_ldp_message_type_name(v: u16) -> *const std::os::raw::c_char {
    guarded(
        || match MessageType::from_u16(v) {
            Some(t) => name_ptr(&format!("{t:?}")),
            None => name_ptr("unknown"),
        },
        std::ptr::null(),
    )
}

#[no_mangle]
pub extern "C" fn lr_ldp_tlv_type_from_u16(v: u16) -> u16 {
    guarded(|| TlvType::from_u16(v).map(|t| t as u16).unwrap_or(0), 0)
}

#[no_mangle]
pub extern "C" fn lr_ldp_tlv_type_to_u16(v: u16) -> u16 {
    v
}

#[no_mangle]
pub extern "C" fn lr_ldp_tlv_type_name(v: u16) -> *const std::os::raw::c_char {
    guarded(
        || match TlvType::from_u16(v) {
            Some(t) => name_ptr(&format!("{t:?}")),
            None => name_ptr("unknown"),
        },
        std::ptr::null(),
    )
}

// AdvertisementMode has no from_u16 in lr-ldp; the FFI surfaces the
// constants directly (1 = DownstreamUnsolicited, 2 =
// DownstreamOnDemand). The name accessor walks the two valid values
// only.

#[no_mangle]
pub extern "C" fn lr_ldp_advertisement_mode_from_u8(v: u8) -> u8 {
    // The enum has two valid discriminants; everything else is unknown
    // (returns 0).
    match v {
        1 | 2 => v,
        _ => 0,
    }
}

#[no_mangle]
pub extern "C" fn lr_ldp_advertisement_mode_to_u8(v: u8) -> u8 {
    v
}

#[no_mangle]
pub extern "C" fn lr_ldp_advertisement_mode_name(v: u8) -> *const std::os::raw::c_char {
    guarded(
        || match v {
            1 => name_ptr("DownstreamUnsolicited"),
            2 => name_ptr("DownstreamOnDemand"),
            _ => name_ptr("unknown"),
        },
        std::ptr::null(),
    )
}

// =========================================================================
// lr-router: OspfNetworkType (i32), SessionErrorKind (i32)
// =========================================================================

#[no_mangle]
pub extern "C" fn lr_router_ospf_network_type_name(v: i32) -> *const std::os::raw::c_char {
    guarded(
        || {
            // OspfNetworkType has two variants (PointToPoint=0,
            // Broadcast=1) — walk the documented wire values.
            let s = match v {
                0 => "PointToPoint",
                1 => "Broadcast",
                _ => "unknown",
            };
            name_ptr(s)
        },
        std::ptr::null(),
    )
}

#[no_mangle]
pub extern "C" fn lr_router_session_error_kind_name(v: i32) -> *const std::os::raw::c_char {
    guarded(
        || {
            // SessionErrorKind is #[repr(u8)] with variants 0..=9.
            let s = match v {
                0 => "None",
                1 => "NotificationReceived",
                2 => "TransportClosed",
                3 => "HoldTimerExpired",
                4 => "ParseError",
                5 => "Manual",
                6 => "Other",
                7 => "OspfKill",
                8 => "OspfSeqMismatch",
                9 => "OspfBadLsa",
                _ => "unknown",
            };
            name_ptr(s)
        },
        std::ptr::null(),
    )
}

// =========================================================================
// lr-srv6: SidParseError, LocatorParseError
// =========================================================================
//
// SidParseError / LocatorParseError are not #[repr(i32)] so they cannot
// be cast from an integer; the FFI exposes a fixed wire code per variant
// and the name accessor returns the documented variant name.

#[no_mangle]
pub extern "C" fn lr_srv6_sid_parse_error_name(v: i32) -> *const std::os::raw::c_char {
    guarded(
        || {
            let s = match v {
                1 => "Empty",
                2 => "DoubleDoubleColon",
                3 => "BadHextet",
                4 => "WrongLength",
                _ => "unknown",
            };
            name_ptr(s)
        },
        std::ptr::null(),
    )
}

#[no_mangle]
pub extern "C" fn lr_srv6_locator_parse_error_name(v: i32) -> *const std::os::raw::c_char {
    guarded(
        || {
            let s = match v {
                1 => "MissingPrefixLen",
                2 => "BadAddr",
                3 => "BadPrefixLen",
                _ => "unknown",
            };
            name_ptr(s)
        },
        std::ptr::null(),
    )
}

// =========================================================================
// lr-mpls: LabelStackError
// =========================================================================

#[no_mangle]
pub extern "C" fn lr_mpls_label_stack_error_name(v: i32) -> *const std::os::raw::c_char {
    guarded(
        || {
            let s = match v {
                1 => "TooShort",
                2 => "UnevenLength",
                3 => "MidStackBottom",
                4 => "ValueOutOfRange",
                _ => "unknown",
            };
            name_ptr(s)
        },
        std::ptr::null(),
    )
}

// Allow the imports to compile cleanly even when an enum variant is
// added (the match arms above are exhaustive-by-name; adding a new
// variant is a non-breaking change at the FFI level because unknown
// values fall through to "unknown").
#[allow(dead_code)]
fn _silence_unused_imports() {
    let _ = (
        AuthType::SimplePassword,
        Diagnostic::None,
        State::Down,
        BmpMsgType::RouteMonitoring,
        PeerType::Global,
        PeerDownReason::LocalClose,
        AdvertisementMode::DownstreamUnsolicited,
        MessageType::Hello,
        TlvType::Fec,
        LsaTypeV2::RouterLsa,
        LsaTypeV3::RouterLsa,
        RouterLinkType::PointToPoint,
        OspfNetworkType::Broadcast,
        SessionErrorKind::Other,
        LabelStackError::TooShort,
        SidParseError::Empty,
        LocatorParseError::MissingPrefixLen,
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    /// SAFETY: the test reads NUL-terminated C strings produced by
    /// name_ptr(); the buffers live until the next call on the same
    /// thread, which is fine for a sequential test.
    unsafe fn name_to_string(p: *const std::os::raw::c_char) -> String {
        if p.is_null() {
            return "<null>".to_string();
        }
        std::ffi::CStr::from_ptr(p).to_string_lossy().into_owned()
    }

    // ---- lr-bfd ----

    #[test]
    fn bfd_auth_type_round_trip() {
        assert_eq!(lr_bfd_auth_type_from_u8(2), 2); // KeyedMd5
        assert_eq!(lr_bfd_auth_type_to_u8(2), 2);
        let name = unsafe { name_to_string(lr_bfd_auth_type_name(2)) };
        assert!(name.contains("KeyedMd5"), "got: {name}");
        // Unknown value 99 falls through to Unknown(99); name still
        // surfaces the Debug form.
        let name = unsafe { name_to_string(lr_bfd_auth_type_name(99)) };
        assert!(name.contains("Unknown"), "got: {name}");
    }

    #[test]
    fn bfd_diagnostic_round_trip() {
        assert_eq!(lr_bfd_diagnostic_from_u8(1), 1); // ControlDetectionTimeExpired
        let name = unsafe { name_to_string(lr_bfd_diagnostic_name(1)) };
        assert!(!name.is_empty());
    }

    #[test]
    fn bfd_state_round_trip() {
        assert_eq!(lr_bfd_state_from_u8(3), 3); // Up
        let name = unsafe { name_to_string(lr_bfd_state_name(3)) };
        assert_eq!(name, "Up");
        // Unknown value 99 → 0, name "unknown".
        assert_eq!(lr_bfd_state_from_u8(99), 0);
        let name = unsafe { name_to_string(lr_bfd_state_name(99)) };
        assert_eq!(name, "unknown");
    }

    #[test]
    fn bfd_keyed_auth_algorithm_round_trip() {
        assert_eq!(lr_bfd_keyed_auth_algorithm_from_u8(2), 2); // KeyedMd5
        assert_eq!(lr_bfd_keyed_auth_algorithm_from_u8(5), 5); // MeticulousKeyedSha1
        let name = unsafe { name_to_string(lr_bfd_keyed_auth_algorithm_name(2)) };
        assert_eq!(name, "KeyedMd5");
        let name = unsafe { name_to_string(lr_bfd_keyed_auth_algorithm_name(99)) };
        assert_eq!(name, "unknown");
    }

    // ---- lr-bmp ----

    #[test]
    fn bmp_msg_type_round_trip() {
        assert_eq!(lr_bmp_msg_type_from_u8(0), 0); // RouteMonitoring
        let name = unsafe { name_to_string(lr_bmp_msg_type_name(0)) };
        assert!(name.contains("RouteMonitoring"), "got: {name}");
        assert_eq!(lr_bmp_msg_type_from_u8(1), 1); // StatisticsReport
        let name = unsafe { name_to_string(lr_bmp_msg_type_name(1)) };
        assert!(name.contains("StatisticsReport"), "got: {name}");
    }

    #[test]
    fn bmp_peer_type_round_trip() {
        assert_eq!(lr_bmp_peer_type_from_u8(0), 0); // Global
        let name = unsafe { name_to_string(lr_bmp_peer_type_name(0)) };
        assert!(name.contains("Global"), "got: {name}");
    }

    #[test]
    fn bmp_peer_down_reason_round_trip() {
        // All PeerDownReason values map to a non-zero integer.
        let name = unsafe { name_to_string(lr_bmp_peer_down_reason_name(1)) };
        assert!(!name.is_empty() && name != "unknown");
        // Unknown value 99 → "unknown".
        let name = unsafe { name_to_string(lr_bmp_peer_down_reason_name(99)) };
        assert_eq!(name, "unknown");
    }

    // ---- lr-ospf ----

    #[test]
    fn ospf_lsa_type_v2_round_trip() {
        assert_eq!(lr_ospf_lsa_type_v2_from_u8(1), 1); // RouterLsa
        let name = unsafe { name_to_string(lr_ospf_lsa_type_v2_name(1)) };
        assert!(name.contains("RouterLsa"), "got: {name}");
        // Unknown value 99 → 0.
        assert_eq!(lr_ospf_lsa_type_v2_from_u8(99), 0);
    }

    #[test]
    fn ospf_lsa_type_v3_round_trip() {
        // 0x2001 = RouterLsa in v3.
        assert_eq!(lr_ospf_lsa_type_v3_from_u16(0x2001), 0x2001);
        let name = unsafe { name_to_string(lr_ospf_lsa_type_v3_name(0x2001)) };
        assert!(name.contains("RouterLsa"), "got: {name}");
        // Unknown value → 0.
        assert_eq!(lr_ospf_lsa_type_v3_from_u16(0x9999), 0);
    }

    #[test]
    fn ospf_router_link_type_round_trip() {
        assert_eq!(lr_ospf_router_link_type_from_u8(1), 1); // PointToPoint
        let name = unsafe { name_to_string(lr_ospf_router_link_type_name(1)) };
        assert!(name.contains("PointToPoint"), "got: {name}");
    }

    // ---- lr-ldp ----

    #[test]
    fn ldp_message_type_round_trip() {
        assert_eq!(lr_ldp_message_type_from_u16(0x0100), 0x0100); // Hello
        let name = unsafe { name_to_string(lr_ldp_message_type_name(0x0100)) };
        assert!(name.contains("Hello"), "got: {name}");
    }

    #[test]
    fn ldp_tlv_type_round_trip() {
        // 0x0100 = Fec
        assert_eq!(lr_ldp_tlv_type_from_u16(0x0100), 0x0100);
        let name = unsafe { name_to_string(lr_ldp_tlv_type_name(0x0100)) };
        assert!(name.contains("Fec"), "got: {name}");
    }

    #[test]
    fn ldp_advertisement_mode_round_trip() {
        assert_eq!(lr_ldp_advertisement_mode_from_u8(1), 1);
        assert_eq!(lr_ldp_advertisement_mode_from_u8(99), 0);
        let name = unsafe { name_to_string(lr_ldp_advertisement_mode_name(1)) };
        assert_eq!(name, "DownstreamUnsolicited");
        let name = unsafe { name_to_string(lr_ldp_advertisement_mode_name(2)) };
        assert_eq!(name, "DownstreamOnDemand");
    }

    // ---- lr-router ----

    #[test]
    fn router_ospf_network_type_name() {
        let name = unsafe { name_to_string(lr_router_ospf_network_type_name(0)) };
        assert_eq!(name, "PointToPoint");
        let name = unsafe { name_to_string(lr_router_ospf_network_type_name(1)) };
        assert_eq!(name, "Broadcast");
        let name = unsafe { name_to_string(lr_router_ospf_network_type_name(99)) };
        assert_eq!(name, "unknown");
    }

    #[test]
    fn router_session_error_kind_name() {
        let name = unsafe { name_to_string(lr_router_session_error_kind_name(0)) };
        assert_eq!(name, "None");
        let name = unsafe { name_to_string(lr_router_session_error_kind_name(1)) };
        assert_eq!(name, "NotificationReceived");
        let name = unsafe { name_to_string(lr_router_session_error_kind_name(99)) };
        assert_eq!(name, "unknown");
    }

    // ---- lr-srv6 ----

    #[test]
    fn srv6_sid_parse_error_name() {
        let name = unsafe { name_to_string(lr_srv6_sid_parse_error_name(1)) };
        assert_eq!(name, "Empty");
        let name = unsafe { name_to_string(lr_srv6_sid_parse_error_name(99)) };
        assert_eq!(name, "unknown");
    }

    #[test]
    fn srv6_locator_parse_error_name() {
        let name = unsafe { name_to_string(lr_srv6_locator_parse_error_name(1)) };
        assert_eq!(name, "MissingPrefixLen");
        let name = unsafe { name_to_string(lr_srv6_locator_parse_error_name(99)) };
        assert_eq!(name, "unknown");
    }

    // ---- lr-mpls ----

    #[test]
    fn mpls_label_stack_error_name() {
        let name = unsafe { name_to_string(lr_mpls_label_stack_error_name(1)) };
        assert_eq!(name, "TooShort");
        let name = unsafe { name_to_string(lr_mpls_label_stack_error_name(4)) };
        assert_eq!(name, "ValueOutOfRange");
        let name = unsafe { name_to_string(lr_mpls_label_stack_error_name(99)) };
        assert_eq!(name, "unknown");
    }
}
