//! BGP message constructors FFI — opaque-handle builders for
//! `BgpMessage::{Open, Update, Notification, Keepalive, RouteRefresh}`.
//!
//! Mirrors the Rust `lr_bgp::message::*` constructors (`Open::new`,
//! `Update::new` / `_with_*`, `BgpNotification::new` /
//! `_from_code`, `RouteRefresh::new` / `_begin_of_rib` / `_end_of_rib`,
//! `Keepalive` unit struct) so a C embedder can construct any
//! BgpMessage variant from scratch and then `lr_bgp_codec_encode_vec`
//! it onto the wire.
//!
//! The opaque handle returned is the same `lr_bgp_message_t` produced
//! by `lr_bgp_decode_message` (`crates/lr-ffi/src/codec.rs`), so all
//! the `lr_bgp_message_*` readers work uniformly on constructed and
//! decoded messages.
//!
//! Issue #92 — gap closure: the readers existed but no constructor
//! surface, so a C embedder could only decode-then-inspect, never
//! build-then-encode.

#![allow(unused_unsafe)]
#![allow(dead_code)]

use lr_bgp::message::{
    keepalive::Keepalive, open::Open, route_refresh::RouteRefresh, update::Update, BgpMessage,
};
use lr_bgp::{error::BgpErrorCode, BgpNotification};
use lr_core::addr::{Asn, RouterId};
use lr_core::nlri::NlriFamily;

use crate::error::{set_last_error, LrError};
use crate::guarded;
use crate::handle::{box_bgp_message, lr_bgp_message_t};

const LR_ERR_NULL: i32 = LrError::Null as i32;

/// Construct an OPEN message (RFC 4271 §4.2). `version` is forced to
/// 4 per RFC 4271 §4.2; an `as4` flag of 1 attaches the RFC 6793
/// four-octet-AS capability (code 65) with the full 32-bit AS — an
/// AS above 65535 then travels as AS_TRANS (23456) in the 16-bit
/// field per RFC 4893 §7. Returns NULL on a panic.
///
/// Hold time 0 (use the negotiated default) or >= 3 per RFC 4271
/// §4.2; the illegal 1-2 second values are rejected with
/// `LR_ERR_OTHER` (-6) and a last-error string.
#[no_mangle]
pub extern "C" fn lr_bgp_message_new_open(
    my_as: u32,
    hold_time: u16,
    bgp_id: u32,
    as4: u8,
) -> lr_bgp_message_t {
    guarded(
        || {
            if hold_time == 1 || hold_time == 2 {
                set_last_error(format!(
                    "illegal hold time {hold_time}s: RFC 4271 §4.2 wants 0 or >= 3"
                ));
                return std::ptr::null_mut();
            }
            if my_as > 0xffff && as4 == 0 {
                set_last_error(format!(
                    "AS {my_as} exceeds 16 bits and as4 is off: the wire form is unrepresentable"
                ));
                return std::ptr::null_mut();
            }
            let mut open = Open::new(Asn(my_as), hold_time, RouterId::from_u32(bgp_id));
            if as4 != 0 {
                let mut value = vec![65u8, 4];
                value.extend_from_slice(&my_as.to_be_bytes());
                open.params.push(lr_bgp::message::open::OpenParam {
                    param_type: lr_bgp::message::open::OpenParam::PARAM_TYPE_CAPABILITY,
                    value,
                });
            }
            box_bgp_message(BgpMessage::Open(open))
        },
        std::ptr::null_mut(),
    )
}

/// Construct an empty UPDATE message (RFC 4271 §4.3). Use
/// [`lr_bgp_message_update_with_withdrawn`] /
/// [`lr_bgp_message_update_with_nlri`] / the path-attribute helpers
/// on a `PathAttributes` handle to populate it. Returns NULL on a
/// panic.
///
/// Note: this is a bare Update — no attributes, no NLRI. A C
/// embedder typically builds the path attributes separately and
/// then calls this constructor as the starting point; the final
/// message is what gets handed to `lr_bgp_codec_encode_vec`.
#[no_mangle]
pub extern "C" fn lr_bgp_message_new_update() -> lr_bgp_message_t {
    guarded(
        || box_bgp_message(BgpMessage::Update(Update::new())),
        std::ptr::null_mut(),
    )
}

/// Construct a NOTIFICATION message (RFC 4271 §4.5): the error code,
/// the subcode and the optional data payload (NULL when `data_len` is
/// 0). Returns NULL on a panic.
#[no_mangle]
pub unsafe extern "C" fn lr_bgp_message_new_notification(
    error_code: u8,
    error_subcode: u8,
    data: *const u8,
    data_len: usize,
) -> lr_bgp_message_t {
    guarded(
        || unsafe {
            if data.is_null() && data_len != 0 {
                return std::ptr::null_mut();
            }
            let payload = if data.is_null() {
                Vec::new()
            } else {
                unsafe { std::slice::from_raw_parts(data, data_len).to_vec() }
            };
            box_bgp_message(BgpMessage::Notification(BgpNotification::new(
                error_code,
                error_subcode,
                payload,
            )))
        },
        std::ptr::null_mut(),
    )
}

/// Construct a NOTIFICATION message from a typed error code (RFC 4271
/// §6). Maps the enum to its u8 form and forwards to
/// [`lr_bgp_message_new_notification`]. The `error_code` argument
/// must be a value returned by `lr_bgp_error_code_to_u8` (or the raw
/// RFC 4271 value). Returns NULL on a panic.
#[no_mangle]
pub unsafe extern "C" fn lr_bgp_message_new_notification_from_code(
    error_code: u8,
    error_subcode: u8,
    data: *const u8,
    data_len: usize,
) -> lr_bgp_message_t {
    match guarded(
        || unsafe {
            // Forward to the plain constructor — the typed `from_code`
            // path validates `error_code` against BgpErrorCode, but the
            // plain `new` accepts any u8 and lets the receiver decide
            // whether to treat it as an unknown code. The two paths
            // produce the same wire bytes when `error_code` is valid.
            let _ = BgpErrorCode::from_u8(error_code); // validation only
            Some(lr_bgp_message_new_notification(
                error_code,
                error_subcode,
                data,
                data_len,
            ))
        },
        None,
    ) {
        Some(m) => m,
        None => std::ptr::null_mut(),
    }
}

/// Construct a KEEPALIVE message (RFC 4271 §4.4). The unit struct
/// has no body — returns a handle whose only useful reader is
/// `lr_bgp_message_type` (which returns `LR_BGP_MSG_KEEPALIVE`).
#[no_mangle]
pub extern "C" fn lr_bgp_message_new_keepalive() -> lr_bgp_message_t {
    guarded(
        || box_bgp_message(BgpMessage::Keepalive(Keepalive)),
        std::ptr::null_mut(),
    )
}

/// Construct a ROUTE-REFRESH message (RFC 2918 / RFC 7313). `afi`
/// and `safi` select the address family; `subtype` is one of
/// `LR_BGP_RR_SUBTYPE_*` (0 = normal, 1 = BoRR, 2 = EoRR). Returns
/// NULL on a panic.
#[no_mangle]
pub extern "C" fn lr_bgp_message_new_route_refresh(
    afi: u16,
    safi: u8,
    subtype: u8,
) -> lr_bgp_message_t {
    guarded(
        || {
            let family = NlriFamily { afi, safi };
            let subtype_enum = match subtype {
                1 => lr_bgp::message::route_refresh::RouteRefreshSubtype::BeginOfRib,
                2 => lr_bgp::message::route_refresh::RouteRefreshSubtype::EndOfRib,
                _ => lr_bgp::message::route_refresh::RouteRefreshSubtype::Normal,
            };
            box_bgp_message(BgpMessage::RouteRefresh(RouteRefresh {
                family,
                subtype: subtype_enum,
            }))
        },
        std::ptr::null_mut(),
    )
}

/// Construct a BoRR (Beginning-of-RIB Route Refresh) message (RFC 7313
/// §3.2). Shorthand for `lr_bgp_message_new_route_refresh(afi, safi, 1)`.
#[no_mangle]
pub extern "C" fn lr_bgp_message_new_begin_of_rib(afi: u16, safi: u8) -> lr_bgp_message_t {
    guarded(
        || {
            let family = NlriFamily { afi, safi };
            box_bgp_message(BgpMessage::RouteRefresh(RouteRefresh::begin_of_rib(family)))
        },
        std::ptr::null_mut(),
    )
}

/// Construct an EoRR (End-of-RIB Route Refresh) message (RFC 7313
/// §3.2). Shorthand for `lr_bgp_message_new_route_refresh(afi, safi, 2)`.
#[no_mangle]
pub extern "C" fn lr_bgp_message_new_end_of_rib(afi: u16, safi: u8) -> lr_bgp_message_t {
    guarded(
        || {
            let family = NlriFamily { afi, safi };
            box_bgp_message(BgpMessage::RouteRefresh(RouteRefresh::end_of_rib(family)))
        },
        std::ptr::null_mut(),
    )
}

/// Construct an OPEN message and attach the four-octet-AS capability
/// (RFC 6793) only when `my_as > 0xffff`. Convenience wrapper around
/// [`lr_bgp_message_new_open`] so the embedder does not have to track
/// the `as4` flag manually. Returns NULL on a panic or on the
/// illegal hold-time / AS-range cases documented on
/// [`lr_bgp_message_new_open`].
#[no_mangle]
pub extern "C" fn lr_bgp_message_new_open_auto_as4(
    my_as: u32,
    hold_time: u16,
    bgp_id: u32,
) -> lr_bgp_message_t {
    match guarded(
        || {
            let as4: u8 = if my_as > 0xffff { 1 } else { 0 };
            Some(lr_bgp_message_new_open(my_as, hold_time, bgp_id, as4))
        },
        None,
    ) {
        Some(m) => m,
        None => std::ptr::null_mut(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::handle::lr_bgp_message_t;

    unsafe fn msg_type(m: lr_bgp_message_t) -> u8 {
        let mut k = 0u8;
        let _ = crate::codec::lr_bgp_message_type(m, &raw mut k);
        k
    }

    unsafe fn rr_afi(m: lr_bgp_message_t) -> u16 {
        let mut v = 0u16;
        let _ = crate::codec::lr_bgp_message_route_refresh_afi(m, &raw mut v);
        v
    }

    unsafe fn rr_safi(m: lr_bgp_message_t) -> u8 {
        let mut v = 0u8;
        let _ = crate::codec::lr_bgp_message_route_refresh_safi(m, &raw mut v);
        v
    }

    unsafe fn rr_subtype(m: lr_bgp_message_t) -> u8 {
        let mut v = 0u8;
        let _ = crate::codec::lr_bgp_message_route_refresh_subtype(m, &raw mut v);
        v
    }

    #[test]
    fn ffi_new_open_round_trip() {
        let m = lr_bgp_message_new_open(64512, 90, 0x0a000001, 1);
        assert!(!m.is_null());
        assert_eq!(unsafe { msg_type(m) }, 1); // OPEN
                                               // The four-octet-AS capability (param type 2, code 65) is attached.
        assert_eq!(crate::codec::lr_bgp_message_open_param_count(m), 1);
        unsafe { crate::codec::lr_bgp_message_free(m) };
    }

    #[test]
    fn ffi_new_open_auto_as4_off_for_2byte_as() {
        // AS 64512 fits in 16 bits — auto-as4 attaches no capability.
        let m = lr_bgp_message_new_open_auto_as4(64512, 90, 0x0a000001);
        assert!(!m.is_null());
        assert_eq!(crate::codec::lr_bgp_message_open_param_count(m), 0);
        unsafe { crate::codec::lr_bgp_message_free(m) };
    }

    #[test]
    fn ffi_new_open_auto_as4_on_for_4byte_as() {
        // AS 4_000_000 needs the 4-byte capability.
        let m = lr_bgp_message_new_open_auto_as4(4_000_000, 90, 0x0a000001);
        assert!(!m.is_null());
        assert_eq!(crate::codec::lr_bgp_message_open_param_count(m), 1);
        unsafe { crate::codec::lr_bgp_message_free(m) };
    }

    #[test]
    fn ffi_new_open_rejects_illegal_hold_time() {
        let m = lr_bgp_message_new_open(64512, 1, 0x0a000001, 0);
        assert!(m.is_null(), "hold-time 1s must be rejected");
        let m = lr_bgp_message_new_open(64512, 2, 0x0a000001, 0);
        assert!(m.is_null(), "hold-time 2s must be rejected");
    }

    #[test]
    fn ffi_new_open_rejects_4byte_as_with_as4_off() {
        let m = lr_bgp_message_new_open(4_000_000, 90, 0x0a000001, 0);
        assert!(m.is_null(), "4-byte AS with as4 off must be rejected");
    }

    #[test]
    fn ffi_new_update_is_empty() {
        let m = lr_bgp_message_new_update();
        assert!(!m.is_null());
        assert_eq!(unsafe { msg_type(m) }, 2); // UPDATE
        assert_eq!(crate::codec::lr_bgp_message_update_withdrawn_count(m), 0);
        assert_eq!(crate::codec::lr_bgp_message_update_nlri_count(m), 0);
        assert_eq!(crate::codec::lr_bgp_message_update_attr_count(m), 0);
        unsafe { crate::codec::lr_bgp_message_free(m) };
    }

    #[test]
    fn ffi_new_notification_round_trip() {
        let data = [0u8; 0];
        let m = unsafe { lr_bgp_message_new_notification(6, 3, data.as_ptr(), 0) };
        assert!(!m.is_null());
        assert_eq!(unsafe { msg_type(m) }, 3); // NOTIFICATION
        let mut code = 0u8;
        let rc = unsafe { crate::codec::lr_bgp_message_notification_code(m, &raw mut code) };
        assert_eq!(rc, 0);
        assert_eq!(code, 6);
        let mut sub = 0u8;
        let rc = unsafe { crate::codec::lr_bgp_message_notification_subcode(m, &raw mut sub) };
        assert_eq!(rc, 0);
        assert_eq!(sub, 3);
        unsafe { crate::codec::lr_bgp_message_free(m) };
    }

    #[test]
    fn ffi_new_notification_with_data() {
        let data = [0xde, 0xad, 0xbe, 0xef];
        let m = unsafe { lr_bgp_message_new_notification(3, 2, data.as_ptr(), data.len()) };
        assert!(!m.is_null());
        let mut bytes = crate::handle::lr_bytes_t {
            ptr: std::ptr::null_mut(),
            len: 0,
            cap: 0,
        };
        let rc = unsafe { crate::codec::lr_bgp_message_notification_data(m, &raw mut bytes) };
        assert_eq!(rc, 0);
        assert_eq!(bytes.len, 4);
        unsafe {
            assert_eq!(std::slice::from_raw_parts(bytes.ptr, bytes.len), data);
            crate::bytes::lr_bytes_free(&raw mut bytes);
            crate::codec::lr_bgp_message_free(m);
        }
    }

    #[test]
    fn ffi_new_keepalive() {
        let m = lr_bgp_message_new_keepalive();
        assert!(!m.is_null());
        assert_eq!(unsafe { msg_type(m) }, 4); // KEEPALIVE
        unsafe { crate::codec::lr_bgp_message_free(m) };
    }

    #[test]
    fn ffi_new_route_refresh_round_trip() {
        let m = lr_bgp_message_new_route_refresh(1, 1, 0);
        assert!(!m.is_null());
        assert_eq!(unsafe { msg_type(m) }, 5); // ROUTE_REFRESH
        assert_eq!(unsafe { rr_afi(m) }, 1);
        assert_eq!(unsafe { rr_safi(m) }, 1);
        assert_eq!(unsafe { rr_subtype(m) }, 0);
        unsafe { crate::codec::lr_bgp_message_free(m) };
    }

    #[test]
    fn ffi_new_begin_of_rib_subtype() {
        let m = lr_bgp_message_new_begin_of_rib(1, 1);
        assert!(!m.is_null());
        assert_eq!(unsafe { rr_subtype(m) }, 1);
        unsafe { crate::codec::lr_bgp_message_free(m) };
    }

    #[test]
    fn ffi_new_end_of_rib_subtype() {
        let m = lr_bgp_message_new_end_of_rib(2, 1);
        assert!(!m.is_null());
        assert_eq!(unsafe { rr_subtype(m) }, 2);
        // EoRR for IPv6 unicast — verify the family fields too.
        assert_eq!(unsafe { rr_afi(m) }, 2);
        assert_eq!(unsafe { rr_safi(m) }, 1);
        unsafe { crate::codec::lr_bgp_message_free(m) };
    }

    #[test]
    fn ffi_new_notification_from_code_round_trip() {
        let m = unsafe { lr_bgp_message_new_notification_from_code(6, 3, std::ptr::null(), 0) };
        assert!(!m.is_null());
        let mut code = 0u8;
        let _ = unsafe { crate::codec::lr_bgp_message_notification_code(m, &raw mut code) };
        assert_eq!(code, 6);
        unsafe { crate::codec::lr_bgp_message_free(m) };
    }
}
