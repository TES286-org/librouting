//! BGP enum conversion FFI — exposes `from_u8` / `to_u8` / `name`
//! for the wire-form enums in `lr_bgp::error`, `lr_bgp::message`,
//! `lr_bgp::capabilities`, `lr_bgp::path::bgp_ls`, and
//! `lr_bgp::path::as_path`.
//!
//! - `lr_bgp_<enum>_from_u8(u8) -> u8` — round-trip; returns the input
//!   when it matches a known variant, 0 otherwise (0 is never a valid
//!   variant on the wire per RFC 4271 §6 / RFC 7752 §3.3, so it is a
//!   safe "unknown" sentinel).
//! - `lr_bgp_<enum>_to_u8(u8) -> u8` — identity (the wire form IS the
//!   enum discriminant).
//! - `lr_bgp_<enum>_name(u8) -> *const c_char` — returns the Display
//!   string for the variant, or `"unknown"` for an unknown value.

use lr_bgp::capabilities::CapabilityCode;
use lr_bgp::message::BgpMessageType;
use lr_bgp::path::as_path::AsPathType;
use lr_bgp::path::bgp_ls::BgpLsNlriType;
use lr_bgp::{
    BgpCeaseSubcode, BgpErrorCode, BgpHeaderErrorSubcode, BgpOpenErrorSubcode,
    BgpUpdateErrorSubcode,
};

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

// ---- BgpErrorCode (RFC 4271 §6) ----

#[no_mangle]
pub extern "C" fn lr_bgp_error_code_from_u8(v: u8) -> u8 {
    guarded(|| BgpErrorCode::from_u8(v).map(|c| c as u8).unwrap_or(0), 0)
}

#[no_mangle]
pub extern "C" fn lr_bgp_error_code_to_u8(v: u8) -> u8 {
    v
}

#[no_mangle]
pub extern "C" fn lr_bgp_error_code_name(v: u8) -> *const std::os::raw::c_char {
    guarded(
        || match BgpErrorCode::from_u8(v) {
            Some(c) => name_ptr(&c.to_string()),
            None => name_ptr("unknown"),
        },
        std::ptr::null(),
    )
}

// ---- BgpOpenErrorSubcode (RFC 4271 §6.2) ----

#[no_mangle]
pub extern "C" fn lr_bgp_open_error_subcode_from_u8(v: u8) -> u8 {
    guarded(
        || {
            BgpOpenErrorSubcode::from_u8(v)
                .map(|c| c as u8)
                .unwrap_or(0)
        },
        0,
    )
}

#[no_mangle]
pub extern "C" fn lr_bgp_open_error_subcode_to_u8(v: u8) -> u8 {
    v
}

#[no_mangle]
pub extern "C" fn lr_bgp_open_error_subcode_name(v: u8) -> *const std::os::raw::c_char {
    guarded(
        || match BgpOpenErrorSubcode::from_u8(v) {
            Some(_) => name_ptr(&format!("open-subcode-{v}")),
            None => name_ptr("unknown"),
        },
        std::ptr::null(),
    )
}

// ---- BgpUpdateErrorSubcode (RFC 4271 §6.3) ----

#[no_mangle]
pub extern "C" fn lr_bgp_update_error_subcode_from_u8(v: u8) -> u8 {
    guarded(
        || {
            BgpUpdateErrorSubcode::from_u8(v)
                .map(|c| c as u8)
                .unwrap_or(0)
        },
        0,
    )
}

#[no_mangle]
pub extern "C" fn lr_bgp_update_error_subcode_to_u8(v: u8) -> u8 {
    v
}

#[no_mangle]
pub extern "C" fn lr_bgp_update_error_subcode_name(v: u8) -> *const std::os::raw::c_char {
    guarded(
        || match BgpUpdateErrorSubcode::from_u8(v) {
            Some(_) => name_ptr(&format!("update-subcode-{v}")),
            None => name_ptr("unknown"),
        },
        std::ptr::null(),
    )
}

// ---- BgpHeaderErrorSubcode (RFC 4271 §6.1) ----

#[no_mangle]
pub extern "C" fn lr_bgp_header_error_subcode_from_u8(v: u8) -> u8 {
    guarded(
        || {
            BgpHeaderErrorSubcode::from_u8(v)
                .map(|c| c as u8)
                .unwrap_or(0)
        },
        0,
    )
}

#[no_mangle]
pub extern "C" fn lr_bgp_header_error_subcode_to_u8(v: u8) -> u8 {
    v
}

#[no_mangle]
pub extern "C" fn lr_bgp_header_error_subcode_name(v: u8) -> *const std::os::raw::c_char {
    guarded(
        || match BgpHeaderErrorSubcode::from_u8(v) {
            Some(_) => name_ptr(&format!("header-subcode-{v}")),
            None => name_ptr("unknown"),
        },
        std::ptr::null(),
    )
}

// ---- BgpCeaseSubcode (RFC 4486 + RFC 9494) ----

#[no_mangle]
pub extern "C" fn lr_bgp_cease_subcode_from_u8(v: u8) -> u8 {
    guarded(
        || BgpCeaseSubcode::from_u8(v).map(|c| c as u8).unwrap_or(0),
        0,
    )
}

#[no_mangle]
pub extern "C" fn lr_bgp_cease_subcode_to_u8(v: u8) -> u8 {
    v
}

#[no_mangle]
pub extern "C" fn lr_bgp_cease_subcode_name(v: u8) -> *const std::os::raw::c_char {
    guarded(
        || match BgpCeaseSubcode::from_u8(v) {
            Some(c) => name_ptr(&format!("{c:?}")),
            None => name_ptr("unknown"),
        },
        std::ptr::null(),
    )
}

// ---- BgpMessageType (RFC 4271 §4.1) ----

#[no_mangle]
pub extern "C" fn lr_bgp_message_type_from_u8(v: u8) -> u8 {
    guarded(
        || BgpMessageType::from_u8(v).map(|c| c as u8).unwrap_or(0),
        0,
    )
}

#[no_mangle]
pub extern "C" fn lr_bgp_message_type_to_u8(v: u8) -> u8 {
    v
}

#[no_mangle]
pub extern "C" fn lr_bgp_message_type_name(v: u8) -> *const std::os::raw::c_char {
    guarded(
        || match BgpMessageType::from_u8(v) {
            Some(c) => name_ptr(&format!("{c:?}")),
            None => name_ptr("unknown"),
        },
        std::ptr::null(),
    )
}

// ---- CapabilityCode (RFC 5492 / IANA registry) ----

#[no_mangle]
pub extern "C" fn lr_bgp_capability_code_from_u8(v: u8) -> u8 {
    guarded(|| CapabilityCode::from_u8(v).to_u8(), 0)
}

#[no_mangle]
pub extern "C" fn lr_bgp_capability_code_to_u8(v: u8) -> u8 {
    v
}

#[no_mangle]
pub extern "C" fn lr_bgp_capability_code_name(v: u8) -> *const std::os::raw::c_char {
    guarded(
        || {
            let c = CapabilityCode::from_u8(v);
            name_ptr(&c.to_string())
        },
        std::ptr::null(),
    )
}

// ---- BgpLsNlriType (RFC 7752 §3.3) ----

#[no_mangle]
pub extern "C" fn lr_bgp_ls_nlri_type_from_u16(v: u16) -> u16 {
    guarded(
        || {
            let t = BgpLsNlriType::from_u16(v);
            t.to_u16()
        },
        0,
    )
}

#[no_mangle]
pub extern "C" fn lr_bgp_ls_nlri_type_to_u16(v: u16) -> u16 {
    v
}

#[no_mangle]
pub extern "C" fn lr_bgp_ls_nlri_type_name(v: u16) -> *const std::os::raw::c_char {
    guarded(
        || {
            let t = BgpLsNlriType::from_u16(v);
            name_ptr(&format!("{t:?}"))
        },
        std::ptr::null(),
    )
}

// ---- AsPathType (RFC 4271 §5.1.2) ----

#[no_mangle]
pub extern "C" fn lr_bgp_as_path_type_from_u8(v: u8) -> u8 {
    guarded(|| AsPathType::from_u8(v).map(|c| c as u8).unwrap_or(0), 0)
}

#[no_mangle]
pub extern "C" fn lr_bgp_as_path_type_to_u8(v: u8) -> u8 {
    v
}

#[no_mangle]
pub extern "C" fn lr_bgp_as_path_type_name(v: u8) -> *const std::os::raw::c_char {
    guarded(
        || match AsPathType::from_u8(v) {
            Some(c) => name_ptr(&format!("{c:?}")),
            None => name_ptr("unknown"),
        },
        std::ptr::null(),
    )
}

// ---- OriginKind (RFC 4271 §5.1.2) ----

/// Origin kind constants (RFC 4271 §5.1.2 — ORIGIN attribute):
/// - 0 = Igp
/// - 1 = Egp
/// - 2 = Incomplete
///
/// Unknown values round-trip as 0xff (the Rust enum is non-exhaustive).
#[no_mangle]
pub extern "C" fn lr_bgp_origin_kind_from_u8(v: u8) -> u8 {
    use lr_bgp::path::well_known::OriginKind;
    guarded(
        || match v {
            0 => OriginKind::Igp as u8,
            1 => OriginKind::Egp as u8,
            2 => OriginKind::Incomplete as u8,
            _ => 0xff,
        },
        0xff,
    )
}

#[no_mangle]
pub extern "C" fn lr_bgp_origin_kind_to_u8(v: u8) -> u8 {
    v
}

#[no_mangle]
pub extern "C" fn lr_bgp_origin_kind_name(v: u8) -> *const std::os::raw::c_char {
    use lr_bgp::path::well_known::OriginKind;
    guarded(
        || match v {
            0 => name_ptr(&format!("{:?}", OriginKind::Igp)),
            1 => name_ptr(&format!("{:?}", OriginKind::Egp)),
            2 => name_ptr(&format!("{:?}", OriginKind::Incomplete)),
            _ => name_ptr("unknown"),
        },
        std::ptr::null(),
    )
}

// ---- CommunityKind (RFC 1997 §4 + RFC 8326 §4 + RFC 9494 §3.2/§3.3) ----

/// Community kind constants (RFC 1997 §4 well-known communities +
/// RFC 8326 §4 GRACEFUL_SHUTDOWN + RFC 9494 §3.2/§3.3 LLGR_STALE /
/// NO_LLGR):
/// - 0 = NoExport
/// - 1 = NoAdvertise
/// - 2 = NoExportSubconfed
/// - 3 = NoPeer
/// - 4 = GracefulShutdown
/// - 5 = LlgrStale
/// - 6 = NoLlgr
/// - 7 = Custom
#[no_mangle]
pub extern "C" fn lr_bgp_community_kind_from_u8(v: u8) -> u8 {
    use lr_bgp::path::communities::CommunityKind;
    guarded(
        || match v {
            0 => CommunityKind::NoExport as u8,
            1 => CommunityKind::NoAdvertise as u8,
            2 => CommunityKind::NoExportSubconfed as u8,
            3 => CommunityKind::NoPeer as u8,
            4 => CommunityKind::GracefulShutdown as u8,
            5 => CommunityKind::LlgrStale as u8,
            6 => CommunityKind::NoLlgr as u8,
            7 => CommunityKind::Custom as u8,
            _ => 0xff,
        },
        0xff,
    )
}

#[no_mangle]
pub extern "C" fn lr_bgp_community_kind_to_u8(v: u8) -> u8 {
    v
}

#[no_mangle]
pub extern "C" fn lr_bgp_community_kind_name(v: u8) -> *const std::os::raw::c_char {
    use lr_bgp::path::communities::CommunityKind;
    guarded(
        || match v {
            0 => name_ptr(&format!("{:?}", CommunityKind::NoExport)),
            1 => name_ptr(&format!("{:?}", CommunityKind::NoAdvertise)),
            2 => name_ptr(&format!("{:?}", CommunityKind::NoExportSubconfed)),
            3 => name_ptr(&format!("{:?}", CommunityKind::NoPeer)),
            4 => name_ptr(&format!("{:?}", CommunityKind::GracefulShutdown)),
            5 => name_ptr(&format!("{:?}", CommunityKind::LlgrStale)),
            6 => name_ptr(&format!("{:?}", CommunityKind::NoLlgr)),
            7 => name_ptr(&format!("{:?}", CommunityKind::Custom)),
            _ => name_ptr("unknown"),
        },
        std::ptr::null(),
    )
}

// ---- RouteRefreshSubtype (RFC 2918 + RFC 7313) ----

/// Route-refresh subtype constants (RFC 2918 + RFC 7313 §3):
/// - 0 = Normal
/// - 1 = BeginOfRib (BoRR)
/// - 2 = EndOfRib (EoRR)
/// - 0xff = Unknown — RFC 7313 §3.2 mandates silent ignore.
#[no_mangle]
pub extern "C" fn lr_bgp_route_refresh_subtype_from_u8(v: u8) -> u8 {
    use lr_bgp::message::RouteRefreshSubtype;
    guarded(
        || match v {
            0 => RouteRefreshSubtype::Normal as u8,
            1 => RouteRefreshSubtype::BeginOfRib as u8,
            2 => RouteRefreshSubtype::EndOfRib as u8,
            _ => 0xff,
        },
        0xff,
    )
}

#[no_mangle]
pub extern "C" fn lr_bgp_route_refresh_subtype_to_u8(v: u8) -> u8 {
    v
}

#[no_mangle]
pub extern "C" fn lr_bgp_route_refresh_subtype_name(v: u8) -> *const std::os::raw::c_char {
    use lr_bgp::message::RouteRefreshSubtype;
    guarded(
        || match v {
            0 => name_ptr(&format!("{:?}", RouteRefreshSubtype::Normal)),
            1 => name_ptr(&format!("{:?}", RouteRefreshSubtype::BeginOfRib)),
            2 => name_ptr(&format!("{:?}", RouteRefreshSubtype::EndOfRib)),
            0xff => name_ptr(&format!("{:?}", RouteRefreshSubtype::Unknown)),
            _ => name_ptr("unknown"),
        },
        std::ptr::null(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CStr;

    fn name(v: u8, f: extern "C" fn(u8) -> *const std::os::raw::c_char) -> String {
        let p = f(v);
        assert!(!p.is_null());
        unsafe { CStr::from_ptr(p) }.to_string_lossy().into_owned()
    }

    #[test]
    fn ffi_error_code_round_trip() {
        assert_eq!(lr_bgp_error_code_from_u8(1), 1); // Header
        assert_eq!(lr_bgp_error_code_from_u8(6), 6); // Cease
        assert_eq!(lr_bgp_error_code_from_u8(99), 0); // Unknown
    }

    #[test]
    fn ffi_error_code_name_known() {
        let n = name(1, lr_bgp_error_code_name);
        assert!(n.contains("Header") || n.contains("header"), "got: {n}");
        let n = name(6, lr_bgp_error_code_name);
        assert!(n.contains("Cease"), "got: {n}");
    }

    #[test]
    fn ffi_error_code_name_unknown() {
        let n = name(99, lr_bgp_error_code_name);
        assert_eq!(n, "unknown");
    }

    #[test]
    fn ffi_open_subcode_round_trip() {
        assert_eq!(lr_bgp_open_error_subcode_from_u8(1), 1); // UnsupportedVersion
        assert_eq!(lr_bgp_open_error_subcode_from_u8(8), 8); // BadOpenLength
        assert_eq!(lr_bgp_open_error_subcode_from_u8(99), 0);
    }

    #[test]
    fn ffi_update_subcode_round_trip() {
        assert_eq!(lr_bgp_update_error_subcode_from_u8(8), 8); // InvalidAsPath
        assert_eq!(lr_bgp_update_error_subcode_from_u8(99), 0);
    }

    #[test]
    fn ffi_cease_subcode_round_trip() {
        assert_eq!(lr_bgp_cease_subcode_from_u8(9), 9); // HardReset
        assert_eq!(lr_bgp_cease_subcode_from_u8(99), 0);
    }

    #[test]
    fn ffi_cease_subcode_name() {
        let n = name(9, lr_bgp_cease_subcode_name);
        assert!(n.contains("HardReset"), "got: {n}");
    }

    #[test]
    fn ffi_message_type_round_trip() {
        assert_eq!(lr_bgp_message_type_from_u8(1), 1); // Open
        assert_eq!(lr_bgp_message_type_from_u8(4), 4); // Keepalive
        assert_eq!(lr_bgp_message_type_from_u8(99), 0);
    }

    #[test]
    fn ffi_message_type_name() {
        let n = name(4, lr_bgp_message_type_name);
        assert!(n.contains("Keepalive"), "got: {n}");
    }

    #[test]
    fn ffi_capability_code_round_trip() {
        assert_eq!(lr_bgp_capability_code_from_u8(1), 1); // MultiprotocolExtensions
        assert_eq!(lr_bgp_capability_code_from_u8(65), 65); // FourOctetAs
                                                            // Unknown codes round-trip (the Rust enum has Other(u8)).
        assert_eq!(lr_bgp_capability_code_from_u8(200), 200);
    }

    #[test]
    fn ffi_ls_nlri_type_round_trip() {
        assert_eq!(lr_bgp_ls_nlri_type_from_u16(1), 1); // Node
        assert_eq!(lr_bgp_ls_nlri_type_from_u16(6), 6); // Srv6Sid
                                                        // Unknown values round-trip verbatim (the enum has Unknown(u16)).
        assert_eq!(lr_bgp_ls_nlri_type_from_u16(9999), 9999);
    }

    #[test]
    fn ffi_as_path_type_round_trip() {
        assert_eq!(lr_bgp_as_path_type_from_u8(1), 1); // Set
        assert_eq!(lr_bgp_as_path_type_from_u8(2), 2); // Sequence
        assert_eq!(lr_bgp_as_path_type_from_u8(99), 0);
    }

    #[test]
    fn ffi_as_path_type_name() {
        let n = name(2, lr_bgp_as_path_type_name);
        // The Debug string contains "Sequence" (AsPathType::Sequence = 2).
        assert!(n.contains("Sequence"), "got: {n}");
    }

    #[test]
    fn ffi_origin_kind_round_trip() {
        assert_eq!(lr_bgp_origin_kind_from_u8(0), 0); // Igp
        assert_eq!(lr_bgp_origin_kind_from_u8(1), 1); // Egp
        assert_eq!(lr_bgp_origin_kind_from_u8(2), 2); // Incomplete
        assert_eq!(lr_bgp_origin_kind_from_u8(99), 0xff);
    }

    #[test]
    fn ffi_origin_kind_name() {
        let n = name(0, lr_bgp_origin_kind_name);
        assert!(n.contains("Igp"), "got: {n}");
    }

    #[test]
    fn ffi_community_kind_name() {
        // GracefulShutdown (RFC 8326) — community 0xFFFF:0000.
        let n = name(4, lr_bgp_community_kind_name);
        assert!(n.contains("GracefulShutdown"), "got: {n}");
    }

    #[test]
    fn ffi_route_refresh_subtype_round_trip() {
        assert_eq!(lr_bgp_route_refresh_subtype_from_u8(0), 0); // Normal
        assert_eq!(lr_bgp_route_refresh_subtype_from_u8(1), 1); // BeginOfRib
        assert_eq!(lr_bgp_route_refresh_subtype_from_u8(2), 2); // EndOfRib
        assert_eq!(lr_bgp_route_refresh_subtype_from_u8(99), 0xff); // Unknown
    }
}
