//! Layer-1 codec FFI: `lr_bgp_decode`, `lr_bgp_encode`, `lr_ospf_decode`,
//! `lr_babel_decode`.
//!
//! Stateless. Accepts raw byte slices; returns `lr_bytes_t` of the
//! re-encoded canonical bytes for the parsed message:
//!
//! - `lr_bgp_decode` round-trips the parsed message through
//!   `BgpCodec::encode_vec`, producing a canonical byte form whose
//!   first byte is the type code (RFC 4271 §4.1 message type). Useful
//!   for codec-level fuzzing / differential checks against a peer's
//!   raw bytes.
//! - `lr_ospf_decode_v2` and `lr_babel_decode` round-trip the parsed
//!   message through `OspfCodec::encode_vec` / `BabelCodec::encode_vec`
//!   the same way the BGP path does. The parse is checked (decode
//!   errors return `LR_ERR_CODEC` = `-5`); a successful re-encode
//!   returns the canonical byte form so FFI consumers see a stable
//!   shape regardless of which optional fields the peer set.
//!
//! Every entry point runs inside the crate's `catch_unwind` barrier
//! ([`crate::guarded`]): a panic returns `LR_ERR_PANIC` and sets the
//! thread-local last-error string.

// The closure body passed to `guarded` is wrapped in a single
// `unsafe` block to mirror the `pub unsafe extern "C" fn` shape —
// the inner `unsafe { ... }` blocks would otherwise trip
// `unused_unsafe` under the crate's `-D warnings` clippy gate.
#![allow(unused_unsafe)]

use lr_babel::BabelCodec as BabelC;
use lr_bgp::{BgpCodec as BgpC, BgpMessage};
use lr_ospf::OspfCodec as OspfC;

use crate::error::{set_last_error, LrError, LR_ERR_PANIC};
use crate::guarded;
use crate::handle::lr_bytes_t;
use crate::policy::lr_prefix_t;

/// `LR_ERR_NULL` (-1) — null pointer or null handle.
const LR_ERR_NULL: i32 = LrError::Null as i32;
/// `LR_ERR_INVALID_HANDLE` (-2) — wrong message variant for this reader.
const LR_ERR_INVALID_HANDLE: i32 = LrError::InvalidHandle as i32;
/// `LR_ERR_OTHER` (-6) — index out of range or other documented failure.
const LR_ERR_OTHER: i32 = LrError::Other as i32;

/// Decode one BGP message from `data`. Returns 0 on success (and writes a
/// `lr_bytes_t` containing the message type byte at offset 0 + body to
/// `out`). Negative on error.
#[no_mangle]
pub extern "C" fn lr_bgp_decode(data: *const u8, len: usize, out: *mut lr_bytes_t) -> i32 {
    guarded(
        || {
            if data.is_null() || out.is_null() {
                return -1;
            }
            let slice = unsafe { std::slice::from_raw_parts(data, len) };
            let mut codec = BgpC::new();
            match codec.decode_slice(slice) {
                Ok(Some(m)) => {
                    // Encode the message back into bytes (round-trip) — this gives
                    // callers a canonical bytes form. The first byte is the type.
                    let bytes = match codec.encode_vec(&m) {
                        Ok(b) => b,
                        Err(e) => {
                            set_last_error(e.to_string());
                            return -4;
                        }
                    };
                    unsafe { *out = lr_bytes_t::from_vec(bytes) }
                    0
                }
                Ok(None) => {
                    set_last_error("truncated".into());
                    -3
                }
                Err(e) => {
                    set_last_error(format!("{:?}", e));
                    -5
                }
            }
        },
        LR_ERR_PANIC,
    )
}

/// Encode a KEEPALIVE message (RFC 4271 §4.4). Part of the D5.4
/// encoder surface: see also [`lr_bgp_encode_open`],
/// [`lr_bgp_encode_notification`], [`lr_bgp_encode_update_withdraw_v4`]
/// and [`lr_bgp_encode_update_announce_v4`].
#[no_mangle]
pub extern "C" fn lr_bgp_encode_keepalive(out: *mut lr_bytes_t) -> i32 {
    guarded(
        || {
            if out.is_null() {
                return -1;
            }
            let codec = BgpC::new();
            match codec.encode_vec(&BgpMessage::Keepalive(
                lr_bgp::message::keepalive::Keepalive,
            )) {
                Ok(b) => {
                    unsafe { *out = lr_bytes_t::from_vec(b) }
                    0
                }
                Err(e) => {
                    set_last_error(e.to_string());
                    -2
                }
            }
        },
        LR_ERR_PANIC,
    )
}

/// Encode an OPEN message (RFC 4271 §4.2, ROADMAP-v3 D5.4): version 4,
/// the given AS, hold time and BGP identifier. When `as4` is non-zero
/// the RFC 6793 four-octet-AS capability (code 65) is appended with the
/// full 32-bit AS — an AS above 65535 then travels as AS_TRANS (23456)
/// in the 16-bit field per RFC 4893 §7. An AS above 65535 with `as4`
/// unset is rejected (it cannot be represented on the wire).
///
/// Hold time 0 (use the negotiated default) or >= 3 per RFC 4271 §4.2;
/// the illegal 1-2 second values are rejected up front.
///
/// Returns 0 on success, negative on error.
///
/// # Safety
/// `bgp_id` must point to 4 readable bytes.
#[no_mangle]
pub unsafe extern "C" fn lr_bgp_encode_open(
    my_as: u32,
    hold_time: u16,
    bgp_id: *const u8,
    as4: u8,
    out: *mut lr_bytes_t,
) -> i32 {
    guarded(
        || {
            if bgp_id.is_null() || out.is_null() {
                return -1;
            }
            if hold_time == 1 || hold_time == 2 {
                set_last_error(format!(
                    "illegal hold time {hold_time}s: RFC 4271 §4.2 wants 0 or >= 3"
                ));
                return -3;
            }
            if my_as > 0xffff && as4 == 0 {
                set_last_error(format!(
                    "AS {my_as} exceeds 16 bits and as4 is off: the wire form is unrepresentable"
                ));
                return -3;
            }
            let mut id = [0u8; 4];
            unsafe { id.copy_from_slice(std::slice::from_raw_parts(bgp_id, 4)) };
            let mut open = lr_bgp::message::Open::new(
                lr_core::addr::Asn(my_as),
                hold_time,
                lr_core::addr::RouterId::from_v4(id),
            );
            if as4 != 0 {
                // RFC 6793: the four-octet AS capability carries the
                // real AS; the 16-bit field reads AS_TRANS when needed.
                let mut value = vec![65u8, 4];
                value.extend_from_slice(&my_as.to_be_bytes());
                open.params.push(lr_bgp::message::OpenParam {
                    param_type: lr_bgp::message::OpenParam::PARAM_TYPE_CAPABILITY,
                    value,
                });
            }
            let codec = BgpC::new();
            match codec.encode_vec(&BgpMessage::Open(open)) {
                Ok(b) => {
                    unsafe { *out = lr_bytes_t::from_vec(b) }
                    0
                }
                Err(e) => {
                    set_last_error(e.to_string());
                    -2
                }
            }
        },
        LR_ERR_PANIC,
    )
}

/// Encode a NOTIFICATION message (RFC 4271 §4.5): the error code, the
/// subcode and the optional data payload (NULL when `data_len` is 0).
/// Returns 0 on success, negative on error.
///
/// # Safety
/// `data` must point to `data_len` readable bytes (NULL only when
/// `data_len` is 0).
#[no_mangle]
pub unsafe extern "C" fn lr_bgp_encode_notification(
    error_code: u8,
    error_subcode: u8,
    data: *const u8,
    data_len: usize,
    out: *mut lr_bytes_t,
) -> i32 {
    guarded(
        || {
            if out.is_null() || (data.is_null() && data_len != 0) {
                return -1;
            }
            let payload = if data.is_null() {
                Vec::new()
            } else {
                unsafe { std::slice::from_raw_parts(data, data_len).to_vec() }
            };
            let codec = BgpC::new();
            let msg = BgpMessage::Notification(lr_bgp::error::BgpNotification::new(
                error_code,
                error_subcode,
                payload,
            ));
            match codec.encode_vec(&msg) {
                Ok(b) => {
                    unsafe { *out = lr_bytes_t::from_vec(b) }
                    0
                }
                Err(e) => {
                    set_last_error(e.to_string());
                    -2
                }
            }
        },
        LR_ERR_PANIC,
    )
}

/// Collect and validate an IPv4 prefix array from C. Returns `None`
/// after recording the error when any entry is IPv6 (the legacy NLRI
/// sections are IPv4-only; MP-BGP UPDATEs are a router-level concern)
/// or malformed.
unsafe fn collect_v4_prefixes(
    prefixes: *const lr_prefix_t,
    n: usize,
) -> Option<Vec<lr_core::addr::Prefix>> {
    if n == 0 {
        return Some(Vec::new());
    }
    if prefixes.is_null() {
        set_last_error("prefix array is NULL".to_string());
        return None;
    }
    let slice = unsafe { std::slice::from_raw_parts(prefixes, n) };
    let mut out = Vec::with_capacity(n);
    for (i, p) in slice.iter().enumerate() {
        if p.is_ipv6 != 0 {
            set_last_error(format!(
                "prefix {i} is IPv6: the legacy NLRI section carries IPv4 only"
            ));
            return None;
        }
        if p.prefix_len > 32 {
            set_last_error(format!(
                "prefix {i}: invalid IPv4 prefix length {} (must be <= 32)",
                p.prefix_len
            ));
            return None;
        }
        out.push(lr_core::addr::Prefix::new_v4(
            [p.addr[0], p.addr[1], p.addr[2], p.addr[3]],
            p.prefix_len,
        ));
    }
    Some(out)
}

/// Encode a withdraw-only UPDATE (RFC 4271 §4.3): every listed IPv4
/// prefix goes into the withdrawn-routes section; no path attributes,
/// no NLRI. Returns 0 on success, negative on error.
///
/// # Safety
/// `prefixes` must point to `n_prefixes` readable `lr_prefix_t` values.
#[no_mangle]
pub unsafe extern "C" fn lr_bgp_encode_update_withdraw_v4(
    prefixes: *const lr_prefix_t,
    n_prefixes: usize,
    out: *mut lr_bytes_t,
) -> i32 {
    guarded(
        || {
            if out.is_null() {
                return -1;
            }
            let list = match unsafe { collect_v4_prefixes(prefixes, n_prefixes) } {
                Some(l) => l,
                None => return -3,
            };
            let update = lr_bgp::message::update::Update::new().with_withdrawn(list);
            let codec = BgpC::new();
            match codec.encode_vec(&BgpMessage::Update(update)) {
                Ok(b) => {
                    unsafe { *out = lr_bytes_t::from_vec(b) }
                    0
                }
                Err(e) => {
                    set_last_error(e.to_string());
                    -2
                }
            }
        },
        LR_ERR_PANIC,
    )
}

/// Encode an announcement UPDATE (RFC 4271 §4.3): ORIGIN + AS_PATH +
/// NEXT_HOP attributes and the IPv4 prefixes in the NLRI section.
///
/// `origin` selects the ORIGIN value (0 = IGP, 1 = EGP, 2 = INCOMPLETE;
/// anything else is rejected). `as_path` is an AS_SEQUENCE in wire order
/// (the origin AS first); with `as4` set the segments use the RFC 6793
/// four-octet encoding. An empty AS_PATH (locally originated) is legal.
///
/// Returns 0 on success, negative on error.
///
/// # Safety
/// `prefixes` must point to `n_prefixes` readable `lr_prefix_t` values,
/// `next_hop` to 4 readable bytes and `as_path` to `as_path_len` readable
/// `uint32_t` values.
#[no_mangle]
pub unsafe extern "C" fn lr_bgp_encode_update_announce_v4(
    prefixes: *const lr_prefix_t,
    n_prefixes: usize,
    next_hop: *const u8,
    as_path: *const u32,
    as_path_len: usize,
    origin: u8,
    as4: u8,
    out: *mut lr_bytes_t,
) -> i32 {
    guarded(
        || {
            if out.is_null() || next_hop.is_null() || (as_path_len > 0 && as_path.is_null()) {
                return -1;
            }
            if origin > 2 {
                set_last_error(format!(
                    "invalid ORIGIN {origin}: RFC 4271 §5.1.1 defines 0 (IGP), 1 (EGP), 2 (INCOMPLETE)"
                ));
                return -3;
            }
            let list = match unsafe { collect_v4_prefixes(prefixes, n_prefixes) } {
                Some(l) => l,
                None => return -3,
            };
            let ases: Vec<lr_core::addr::Asn> = if as_path.is_null() {
                Vec::new()
            } else {
                unsafe { std::slice::from_raw_parts(as_path, as_path_len) }
                    .iter()
                    .map(|&a| lr_core::addr::Asn(a))
                    .collect()
            };
            for asn in &ases {
                if asn.0 > 0xffff && as4 == 0 {
                    set_last_error(format!(
                        "AS {} in the path exceeds 16 bits and as4 is off",
                        asn.0
                    ));
                    return -3;
                }
            }
            let mut nh = [0u8; 4];
            unsafe { nh.copy_from_slice(std::slice::from_raw_parts(next_hop, 4)) };
            let path = lr_bgp::path::AsPath::from_sequence(ases);
            let path_value = if as4 != 0 {
                path.encode_4()
            } else {
                path.encode_2()
            };
            let update = lr_bgp::message::update::Update::new()
                .with_attribute(lr_bgp::path::PathAttribute::new(
                    lr_bgp::path::PathAttrFlags::new().set_transitive(true),
                    lr_bgp::path::AttrType::Origin,
                    vec![origin],
                ))
                .with_attribute(lr_bgp::path::PathAttribute::new(
                    lr_bgp::path::PathAttrFlags::new().set_transitive(true),
                    lr_bgp::path::AttrType::AsPath,
                    path_value,
                ))
                .with_attribute(lr_bgp::path::PathAttribute::new(
                    lr_bgp::path::PathAttrFlags::new().set_transitive(true),
                    lr_bgp::path::AttrType::NextHop,
                    nh.to_vec(),
                ))
                .with_nlri(list);
            let codec = BgpC::new();
            match codec.encode_vec(&BgpMessage::Update(update)) {
                Ok(b) => {
                    unsafe { *out = lr_bytes_t::from_vec(b) }
                    0
                }
                Err(e) => {
                    set_last_error(e.to_string());
                    -2
                }
            }
        },
        LR_ERR_PANIC,
    )
}

#[no_mangle]
pub extern "C" fn lr_ospf_decode_v2(data: *const u8, len: usize, out: *mut lr_bytes_t) -> i32 {
    guarded(
        || {
            if data.is_null() || out.is_null() {
                return -1;
            }
            let slice = unsafe { std::slice::from_raw_parts(data, len) };
            let mut codec = OspfC::v2();
            match codec.decode_slice(slice) {
                Ok(Some(p)) => {
                    // Round-trip through the encoder so callers get the
                    // canonical byte form, same as `lr_bgp_decode`. The
                    // raw input bytes were a placeholder; the parsed
                    // structure is now projected through `encode_vec`.
                    let bytes = match codec.encode_vec(&p) {
                        Ok(b) => b,
                        Err(e) => {
                            set_last_error(e.to_string());
                            return -4;
                        }
                    };
                    unsafe { *out = lr_bytes_t::from_vec(bytes) }
                    0
                }
                Ok(None) => {
                    set_last_error("truncated".into());
                    -3
                }
                Err(e) => {
                    set_last_error(e.to_string());
                    -5
                }
            }
        },
        LR_ERR_PANIC,
    )
}

#[no_mangle]
pub extern "C" fn lr_babel_decode(data: *const u8, len: usize, out: *mut lr_bytes_t) -> i32 {
    guarded(
        || {
            if data.is_null() || out.is_null() {
                return -1;
            }
            let slice = unsafe { std::slice::from_raw_parts(data, len) };
            let mut codec = BabelC::new();
            match codec.decode_slice(slice) {
                Ok(Some(f)) => {
                    // Round-trip through the encoder so callers get the
                    // canonical byte form, same as `lr_bgp_decode`. The
                    // raw input bytes were a placeholder; the parsed
                    // structure is now projected through `encode_vec`.
                    let bytes = match codec.encode_vec(&f) {
                        Ok(b) => b,
                        Err(e) => {
                            set_last_error(e.to_string());
                            return -4;
                        }
                    };
                    unsafe { *out = lr_bytes_t::from_vec(bytes) }
                    0
                }
                Ok(None) => {
                    set_last_error("truncated".into());
                    -3
                }
                Err(e) => {
                    set_last_error(e.to_string());
                    -5
                }
            }
        },
        LR_ERR_PANIC,
    )
}

// ============================================================================
// Structured BGP message inspection
// ----------------------------------------------------------------------------
// The `lr_bgp_decode` round-trip surface above is useful for differential
// checks but useless for an embedder that needs to read the parsed fields:
// the C side cannot crack open a Rust enum, so OPEN's AS, NOTIFICATION's
// code/subcode, ROUTE-REFRESH's AFI/SAFI, UPDATE's NLRI list, etc. were all
// invisible across the ABI. The handles + readers below mirror the
// `BgpMessage` enum and its variants so an embedder can decode a message
// once and walk its structured form field-by-field — the same shape a Rust
// embedder gets from `match msg { ... }`.
//
// The design follows the existing handle convention (see `handle.rs`):
// `lr_bgp_decode_message` returns a heap-allocated `lr_bgp_message_t` owned
// by the caller; every reader takes a non-null handle and returns the
// documented error code on mismatch (`LR_ERR_INVALID_HANDLE` when the
// message is not the variant the reader expects, `LR_ERR_NULL` on a null
// handle). The handle is freed with `lr_bgp_message_free`.
//
// Future OSPF/Babel message inspection surfaces (`lr_ospf_message_t`,
// `lr_babel_message_t`) will follow the same pattern.
// ============================================================================

/// BGP message type codes (RFC 4271 §4.1 + RFC 2918). Mirrors
/// [`lr_bgp::BgpMessageType`] but exposed as plain `u8` constants so C
/// consumers can `switch` on the value returned by
/// [`lr_bgp_message_type`] without depending on a generated enum.
pub const LR_BGP_MSG_OPEN: u8 = 1;
pub const LR_BGP_MSG_UPDATE: u8 = 2;
pub const LR_BGP_MSG_NOTIFICATION: u8 = 3;
pub const LR_BGP_MSG_KEEPALIVE: u8 = 4;
pub const LR_BGP_MSG_ROUTE_REFRESH: u8 = 5;

/// Route-Refresh subtype (RFC 7313 §3.2). The third body octet of a
/// ROUTE-REFRESH message; ROUTE-REFRESH readers surface this via
/// [`lr_bgp_message_route_refresh_subtype`].
pub const LR_BGP_RR_SUBTYPE_NORMAL: u8 = 0;
pub const LR_BGP_RR_SUBTYPE_BORR: u8 = 1;
pub const LR_BGP_RR_SUBTYPE_EORR: u8 = 2;

/// Decode one BGP message and return an opaque handle to the parsed
/// form. The caller owns the handle and must release it with
/// [`lr_bgp_message_free`]. Returns NULL on failure (the thread-local
/// last-error string is set).
///
/// Unlike [`lr_bgp_decode`] (which round-trips the parsed message
/// through `encode_vec` and hands back canonical bytes), this entry
/// point keeps the structured `BgpMessage` alive so its variant fields
/// can be read by the matching `lr_bgp_message_*` readers.
///
/// # Safety
/// `data` must point to `len` readable bytes.
#[no_mangle]
pub extern "C" fn lr_bgp_decode_message(
    data: *const u8,
    len: usize,
) -> crate::handle::lr_bgp_message_t {
    guarded(
        || {
            if data.is_null() {
                set_last_error("null data pointer".into());
                return std::ptr::null_mut();
            }
            let slice = unsafe { std::slice::from_raw_parts(data, len) };
            let mut codec = BgpC::new();
            match codec.decode_slice(slice) {
                Ok(Some(m)) => crate::handle::box_bgp_message(m),
                Ok(None) => {
                    set_last_error("truncated".into());
                    std::ptr::null_mut()
                }
                Err(e) => {
                    set_last_error(format!("{e:?}"));
                    std::ptr::null_mut()
                }
            }
        },
        std::ptr::null_mut(),
    )
}

/// Free a BGP-message handle produced by [`lr_bgp_decode_message`]. Safe
/// to call with NULL.
///
/// # Safety
/// `m` must have been produced by [`lr_bgp_decode_message`] and must not
/// be destroyed while another thread is inside a call on the same handle.
#[no_mangle]
pub unsafe extern "C" fn lr_bgp_message_free(m: crate::handle::lr_bgp_message_t) {
    guarded(
        || {
            let _ = unsafe { crate::handle::unbox_bgp_message(m) };
        },
        (),
    )
}

/// Write the BGP message type code (1..5, see `LR_BGP_MSG_*`) to `out`.
/// Returns 0 on success, `LR_ERR_NULL` on a null handle.
///
/// # Safety
/// `out` must point to a writable `uint8_t`.
#[no_mangle]
pub unsafe extern "C" fn lr_bgp_message_type(
    m: crate::handle::lr_bgp_message_t,
    out: *mut u8,
) -> i32 {
    guarded(
        || {
            if out.is_null() {
                return LR_ERR_NULL;
            }
            let Some(msg) = (unsafe { crate::handle::borrow_bgp_message(m) }) else {
                return LR_ERR_NULL;
            };
            let kind = match msg {
                BgpMessage::Open(_) => LR_BGP_MSG_OPEN,
                BgpMessage::Update(_) => LR_BGP_MSG_UPDATE,
                BgpMessage::Notification(_) => LR_BGP_MSG_NOTIFICATION,
                BgpMessage::Keepalive(_) => LR_BGP_MSG_KEEPALIVE,
                BgpMessage::RouteRefresh(_) => LR_BGP_MSG_ROUTE_REFRESH,
            };
            unsafe { *out = kind };
            0
        },
        LR_ERR_PANIC,
    )
}

// ---------- OPEN readers (RFC 4271 §4.2) ----------

/// Write the OPEN version (always 4 on a well-formed message) to `out`.
/// Returns 0 on success, `LR_ERR_NULL` on a null handle, and
/// `LR_ERR_INVALID_HANDLE` when the message is not an OPEN.
///
/// # Safety
/// `out` must point to a writable `uint8_t`.
#[no_mangle]
pub unsafe extern "C" fn lr_bgp_message_open_version(
    m: crate::handle::lr_bgp_message_t,
    out: *mut u8,
) -> i32 {
    guarded(
        || {
            if out.is_null() {
                return LR_ERR_NULL;
            }
            let Some(msg) = (unsafe { crate::handle::borrow_bgp_message(m) }) else {
                return LR_ERR_NULL;
            };
            let BgpMessage::Open(o) = msg else {
                set_last_error("message is not OPEN".into());
                return LR_ERR_INVALID_HANDLE;
            };
            unsafe { *out = o.version };
            0
        },
        LR_ERR_PANIC,
    )
}

/// Write the sender AS to `out`. When the OPEN carries the RFC 6793
/// four-octet-AS capability (param type 2, capability code 65), the
/// real 32-bit AS is read from the capability; otherwise the 16-bit
/// `my_as` field is returned. Returns 0 on success, `LR_ERR_NULL`
/// on a null handle, `LR_ERR_INVALID_HANDLE` when not OPEN.
///
/// # Safety
/// `out` must point to a writable `uint32_t`.
#[no_mangle]
pub unsafe extern "C" fn lr_bgp_message_open_my_as(
    m: crate::handle::lr_bgp_message_t,
    out: *mut u32,
) -> i32 {
    guarded(
        || {
            if out.is_null() {
                return LR_ERR_NULL;
            }
            let Some(msg) = (unsafe { crate::handle::borrow_bgp_message(m) }) else {
                return LR_ERR_NULL;
            };
            let BgpMessage::Open(o) = msg else {
                set_last_error("message is not OPEN".into());
                return LR_ERR_INVALID_HANDLE;
            };
            // RFC 6793 §7: when AS_TRANS (23456) is announced in the
            // 16-bit field, the real 4-byte AS lives in the
            // Four-Octet-AS capability (param type 2, cap code 65).
            // `decode_set` parses the capability value as 4 BE bytes.
            let mut asn = o.my_as.as_u32();
            if o.uses_as_trans() {
                for p in &o.params {
                    if p.param_type != lr_bgp::message::OpenParam::PARAM_TYPE_CAPABILITY {
                        continue;
                    }
                    for cap in lr_bgp::capabilities::Capability::decode_set(&p.value) {
                        if let Some(real) = cap.as_four_octet() {
                            asn = real;
                        }
                    }
                }
            }
            unsafe { *out = asn };
            0
        },
        LR_ERR_PANIC,
    )
}

/// Write the OPEN hold time (seconds) to `out`. Returns 0 on success,
/// `LR_ERR_NULL` on a null handle, `LR_ERR_INVALID_HANDLE` when not OPEN.
///
/// # Safety
/// `out` must point to a writable `uint16_t`.
#[no_mangle]
pub unsafe extern "C" fn lr_bgp_message_open_hold_time(
    m: crate::handle::lr_bgp_message_t,
    out: *mut u16,
) -> i32 {
    guarded(
        || {
            if out.is_null() {
                return LR_ERR_NULL;
            }
            let Some(msg) = (unsafe { crate::handle::borrow_bgp_message(m) }) else {
                return LR_ERR_NULL;
            };
            let BgpMessage::Open(o) = msg else {
                set_last_error("message is not OPEN".into());
                return LR_ERR_INVALID_HANDLE;
            };
            unsafe { *out = o.hold_time };
            0
        },
        LR_ERR_PANIC,
    )
}

/// Write the OPEN BGP identifier (4 bytes, network order) to `out`.
/// Returns 0 on success, `LR_ERR_NULL` on a null handle or null `out`,
/// `LR_ERR_INVALID_HANDLE` when not OPEN.
///
/// # Safety
/// `out` must point to 4 writable bytes.
#[no_mangle]
pub unsafe extern "C" fn lr_bgp_message_open_bgp_id(
    m: crate::handle::lr_bgp_message_t,
    out: *mut u8,
) -> i32 {
    guarded(
        || {
            if out.is_null() {
                return LR_ERR_NULL;
            }
            let Some(msg) = (unsafe { crate::handle::borrow_bgp_message(m) }) else {
                return LR_ERR_NULL;
            };
            let BgpMessage::Open(o) = msg else {
                set_last_error("message is not OPEN".into());
                return LR_ERR_INVALID_HANDLE;
            };
            let id_bytes = o.bgp_id.as_u32().to_be_bytes();
            unsafe {
                std::ptr::copy_nonoverlapping(id_bytes.as_ptr(), out, 4);
            }
            0
        },
        LR_ERR_PANIC,
    )
}

/// Number of optional parameters in the OPEN. Returns the count
/// directly (0 on a null handle or non-OPEN message — the last-error
/// string is set on the latter so the caller can distinguish).
#[no_mangle]
pub extern "C" fn lr_bgp_message_open_param_count(m: crate::handle::lr_bgp_message_t) -> usize {
    guarded(
        || {
            let Some(msg) = (unsafe { crate::handle::borrow_bgp_message(m) }) else {
                return 0;
            };
            let BgpMessage::Open(o) = msg else {
                set_last_error("message is not OPEN".into());
                return 0;
            };
            o.params.len()
        },
        0,
    )
}

/// Write the optional parameter at `idx` to `out_type` and `out_value`.
/// Returns 0 on success, `LR_ERR_NULL` on a null handle or null outputs,
/// `LR_ERR_INVALID_HANDLE` when the message is not OPEN, and
/// `LR_ERR_OTHER` when `idx` is out of range.
///
/// `out_value` is a freshly allocated `lr_bytes_t` the caller must free
/// with [`crate::bytes::lr_bytes_free`]. The param `value` is the raw
/// capability payload (RFC 5492 §3): a sequence of `(code:1, length:1,
/// value:length)` capability triples that an embedder can crack open
/// with [`lr_bgp::Capability::decode_set`] on the Rust side or by hand
/// from C — see `tests/ffi/harness.c` for the wire layout.
///
/// # Safety
/// `out_type` must point to a writable `uint8_t`, `out_value` to a
/// writable `lr_bytes_t`.
#[no_mangle]
pub unsafe extern "C" fn lr_bgp_message_open_param_at(
    m: crate::handle::lr_bgp_message_t,
    idx: usize,
    out_type: *mut u8,
    out_value: *mut lr_bytes_t,
) -> i32 {
    guarded(
        || {
            if out_type.is_null() || out_value.is_null() {
                return LR_ERR_NULL;
            }
            let Some(msg) = (unsafe { crate::handle::borrow_bgp_message(m) }) else {
                return LR_ERR_NULL;
            };
            let BgpMessage::Open(o) = msg else {
                set_last_error("message is not OPEN".into());
                return LR_ERR_INVALID_HANDLE;
            };
            let Some(p) = o.params.get(idx) else {
                set_last_error(format!(
                    "param index {idx} out of range ({})",
                    o.params.len()
                ));
                return LR_ERR_OTHER;
            };
            unsafe {
                *out_type = p.param_type;
                *out_value = lr_bytes_t::from_vec(p.value.clone());
            }
            0
        },
        LR_ERR_PANIC,
    )
}

// ---------- NOTIFICATION readers (RFC 4271 §4.5) ----------

/// Write the NOTIFICATION error code to `out`. Returns 0 on success,
/// `LR_ERR_NULL` on a null handle or null `out`, `LR_ERR_INVALID_HANDLE`
/// when the message is not a NOTIFICATION.
///
/// # Safety
/// `out` must point to a writable `uint8_t`.
#[no_mangle]
pub unsafe extern "C" fn lr_bgp_message_notification_code(
    m: crate::handle::lr_bgp_message_t,
    out: *mut u8,
) -> i32 {
    guarded(
        || {
            if out.is_null() {
                return LR_ERR_NULL;
            }
            let Some(msg) = (unsafe { crate::handle::borrow_bgp_message(m) }) else {
                return LR_ERR_NULL;
            };
            let BgpMessage::Notification(n) = msg else {
                set_last_error("message is not NOTIFICATION".into());
                return LR_ERR_INVALID_HANDLE;
            };
            unsafe { *out = n.error_code };
            0
        },
        LR_ERR_PANIC,
    )
}

/// Write the NOTIFICATION error subcode to `out`. See
/// [`lr_bgp_message_notification_code`].
///
/// # Safety
/// `out` must point to a writable `uint8_t`.
#[no_mangle]
pub unsafe extern "C" fn lr_bgp_message_notification_subcode(
    m: crate::handle::lr_bgp_message_t,
    out: *mut u8,
) -> i32 {
    guarded(
        || {
            if out.is_null() {
                return LR_ERR_NULL;
            }
            let Some(msg) = (unsafe { crate::handle::borrow_bgp_message(m) }) else {
                return LR_ERR_NULL;
            };
            let BgpMessage::Notification(n) = msg else {
                set_last_error("message is not NOTIFICATION".into());
                return LR_ERR_INVALID_HANDLE;
            };
            unsafe { *out = n.error_subcode };
            0
        },
        LR_ERR_PANIC,
    )
}

/// Write the NOTIFICATION data payload (variable-length, often empty)
/// to `out`. Returns 0 on success, `LR_ERR_NULL` on a null handle or
/// null `out`, `LR_ERR_INVALID_HANDLE` when not a NOTIFICATION.
///
/// `out` is a freshly allocated `lr_bytes_t` the caller must free with
/// [`crate::bytes::lr_bytes_free`]. The payload is empty for the
/// compact NOTIFICATIONs BIRD/FRR emit on Cease/Administrative Reset,
/// and carries diagnostic text (RFC 4271 §4.5) for Header/OPEN/UPDATE
/// errors.
///
/// # Safety
/// `out` must point to a writable `lr_bytes_t`.
#[no_mangle]
pub unsafe extern "C" fn lr_bgp_message_notification_data(
    m: crate::handle::lr_bgp_message_t,
    out: *mut lr_bytes_t,
) -> i32 {
    guarded(
        || {
            if out.is_null() {
                return LR_ERR_NULL;
            }
            let Some(msg) = (unsafe { crate::handle::borrow_bgp_message(m) }) else {
                return LR_ERR_NULL;
            };
            let BgpMessage::Notification(n) = msg else {
                set_last_error("message is not NOTIFICATION".into());
                return LR_ERR_INVALID_HANDLE;
            };
            unsafe { *out = lr_bytes_t::from_vec(n.data.clone()) };
            0
        },
        LR_ERR_PANIC,
    )
}

// ---------- ROUTE-REFRESH readers (RFC 2918 + RFC 7313) ----------

/// Write the ROUTE-REFRESH AFI (RFC 4271 address-family identifier) to
/// `out`. Returns 0 on success, `LR_ERR_NULL` on a null handle or null
/// `out`, `LR_ERR_INVALID_HANDLE` when the message is not a
/// ROUTE-REFRESH.
///
/// # Safety
/// `out` must point to a writable `uint16_t`.
#[no_mangle]
pub unsafe extern "C" fn lr_bgp_message_route_refresh_afi(
    m: crate::handle::lr_bgp_message_t,
    out: *mut u16,
) -> i32 {
    guarded(
        || {
            if out.is_null() {
                return LR_ERR_NULL;
            }
            let Some(msg) = (unsafe { crate::handle::borrow_bgp_message(m) }) else {
                return LR_ERR_NULL;
            };
            let BgpMessage::RouteRefresh(r) = msg else {
                set_last_error("message is not ROUTE-REFRESH".into());
                return LR_ERR_INVALID_HANDLE;
            };
            unsafe { *out = r.family.afi };
            0
        },
        LR_ERR_PANIC,
    )
}

/// Write the ROUTE-REFRESH SAFI (RFC 4271 sub-address-family
/// identifier) to `out`. See [`lr_bgp_message_route_refresh_afi`].
///
/// # Safety
/// `out` must point to a writable `uint8_t`.
#[no_mangle]
pub unsafe extern "C" fn lr_bgp_message_route_refresh_safi(
    m: crate::handle::lr_bgp_message_t,
    out: *mut u8,
) -> i32 {
    guarded(
        || {
            if out.is_null() {
                return LR_ERR_NULL;
            }
            let Some(msg) = (unsafe { crate::handle::borrow_bgp_message(m) }) else {
                return LR_ERR_NULL;
            };
            let BgpMessage::RouteRefresh(r) = msg else {
                set_last_error("message is not ROUTE-REFRESH".into());
                return LR_ERR_INVALID_HANDLE;
            };
            unsafe { *out = r.family.safi };
            0
        },
        LR_ERR_PANIC,
    )
}

/// Write the ROUTE-REFRESH subtype (RFC 7313 §3.2) to `out`: 0 = Normal,
/// 1 = BoRR, 2 = EoRR, 0xff = unknown (RFC 7313 §3.2 requires the
/// message be silently ignored, so the decoder maps unrecognized values
/// here). See [`LR_BGP_RR_SUBTYPE_*`] for the named constants.
///
/// # Safety
/// `out` must point to a writable `uint8_t`.
#[no_mangle]
pub unsafe extern "C" fn lr_bgp_message_route_refresh_subtype(
    m: crate::handle::lr_bgp_message_t,
    out: *mut u8,
) -> i32 {
    guarded(
        || {
            if out.is_null() {
                return LR_ERR_NULL;
            }
            let Some(msg) = (unsafe { crate::handle::borrow_bgp_message(m) }) else {
                return LR_ERR_NULL;
            };
            let BgpMessage::RouteRefresh(r) = msg else {
                set_last_error("message is not ROUTE-REFRESH".into());
                return LR_ERR_INVALID_HANDLE;
            };
            unsafe { *out = r.subtype as u8 };
            0
        },
        LR_ERR_PANIC,
    )
}

// ---------- UPDATE readers (RFC 4271 §4.3) ----------
//
// The UPDATE surface here covers the IPv4 withdrawn-routes + NLRI
// sections and the path-attribute list. MP-BGP NLRI (RFC 4760) carried
// inside MpReach/MpUnreach is reachable through the attribute reader at
// index 14/15 — a follow-up slice will add typed readers for those.

/// Number of withdrawn routes in the UPDATE. Returns the count
/// directly (0 on a null handle or non-UPDATE message — the last-error
/// string is set on the latter).
#[no_mangle]
pub extern "C" fn lr_bgp_message_update_withdrawn_count(
    m: crate::handle::lr_bgp_message_t,
) -> usize {
    guarded(
        || {
            let Some(msg) = (unsafe { crate::handle::borrow_bgp_message(m) }) else {
                return 0;
            };
            let BgpMessage::Update(u) = msg else {
                set_last_error("message is not UPDATE".into());
                return 0;
            };
            u.withdrawn.len()
        },
        0,
    )
}

/// Number of NLRI entries in the UPDATE (IPv4 unicast legacy NLRI only;
/// MP-BGP NLRI lives inside the MpReach/MpUnreach path attributes). See
/// [`lr_bgp_message_update_withdrawn_count`] for return semantics.
#[no_mangle]
pub extern "C" fn lr_bgp_message_update_nlri_count(m: crate::handle::lr_bgp_message_t) -> usize {
    guarded(
        || {
            let Some(msg) = (unsafe { crate::handle::borrow_bgp_message(m) }) else {
                return 0;
            };
            let BgpMessage::Update(u) = msg else {
                set_last_error("message is not UPDATE".into());
                return 0;
            };
            u.nlri.len()
        },
        0,
    )
}

/// Number of path attributes in the UPDATE. The attribute at index `i`
/// is read with [`lr_bgp_message_update_attr_at`].
#[no_mangle]
pub extern "C" fn lr_bgp_message_update_attr_count(m: crate::handle::lr_bgp_message_t) -> usize {
    guarded(
        || {
            let Some(msg) = (unsafe { crate::handle::borrow_bgp_message(m) }) else {
                return 0;
            };
            let BgpMessage::Update(u) = msg else {
                set_last_error("message is not UPDATE".into());
                return 0;
            };
            u.attributes.iter().count()
        },
        0,
    )
}

/// Write the withdrawn route at `idx` to `out`. Returns 0 on success,
/// `LR_ERR_NULL` on a null handle or null `out`, `LR_ERR_INVALID_HANDLE`
/// when the message is not an UPDATE, and `LR_ERR_OTHER` when `idx` is
/// out of range. The prefix's `addr` is zero-padded to 16 bytes (the
/// first 4 carry the IPv4 octets); `is_ipv6` is 0; `prefix_len` carries
/// the prefix length.
///
/// # Safety
/// `out` must point to a writable `lr_prefix_t`.
#[no_mangle]
pub unsafe extern "C" fn lr_bgp_message_update_withdrawn_at(
    m: crate::handle::lr_bgp_message_t,
    idx: usize,
    out: *mut crate::policy::lr_prefix_t,
) -> i32 {
    guarded(
        || {
            if out.is_null() {
                return LR_ERR_NULL;
            }
            let Some(msg) = (unsafe { crate::handle::borrow_bgp_message(m) }) else {
                return LR_ERR_NULL;
            };
            let BgpMessage::Update(u) = msg else {
                set_last_error("message is not UPDATE".into());
                return LR_ERR_INVALID_HANDLE;
            };
            let Some(nlri) = u.withdrawn.get(idx) else {
                set_last_error(format!(
                    "withdrawn index {idx} out of range ({})",
                    u.withdrawn.len()
                ));
                return LR_ERR_OTHER;
            };
            unsafe { *out = prefix_to_lr_prefix(&nlri.prefix) };
            0
        },
        LR_ERR_PANIC,
    )
}

/// Write the NLRI entry at `idx` to `out`. Same contract as
/// [`lr_bgp_message_update_withdrawn_at`] but for the announce section.
///
/// # Safety
/// `out` must point to a writable `lr_prefix_t`.
#[no_mangle]
pub unsafe extern "C" fn lr_bgp_message_update_nlri_at(
    m: crate::handle::lr_bgp_message_t,
    idx: usize,
    out: *mut crate::policy::lr_prefix_t,
) -> i32 {
    guarded(
        || {
            if out.is_null() {
                return LR_ERR_NULL;
            }
            let Some(msg) = (unsafe { crate::handle::borrow_bgp_message(m) }) else {
                return LR_ERR_NULL;
            };
            let BgpMessage::Update(u) = msg else {
                set_last_error("message is not UPDATE".into());
                return LR_ERR_INVALID_HANDLE;
            };
            let Some(nlri) = u.nlri.get(idx) else {
                set_last_error(format!("nlri index {idx} out of range ({})", u.nlri.len()));
                return LR_ERR_OTHER;
            };
            unsafe { *out = prefix_to_lr_prefix(&nlri.prefix) };
            0
        },
        LR_ERR_PANIC,
    )
}

/// Write the path attribute at `idx` to `out_type`, `out_flags` and
/// `out_value`. Returns 0 on success, `LR_ERR_NULL` on a null handle or
/// null outputs, `LR_ERR_INVALID_HANDLE` when not an UPDATE, and
/// `LR_ERR_OTHER` when `idx` is out of range.
///
/// `out_value` is a freshly allocated `lr_bytes_t` the caller must free
/// with [`crate::bytes::lr_bytes_free`]. The flags byte layout is
/// RFC 4271 §5.1 + RFC 9072 §2: bit 7 optional, bit 6 transitive, bit 5
/// partial, bit 4 extended-length.
///
/// # Safety
/// `out_type` and `out_flags` must point to writable `uint8_t` values,
/// `out_value` to a writable `lr_bytes_t`.
#[no_mangle]
pub unsafe extern "C" fn lr_bgp_message_update_attr_at(
    m: crate::handle::lr_bgp_message_t,
    idx: usize,
    out_type: *mut u8,
    out_flags: *mut u8,
    out_value: *mut lr_bytes_t,
) -> i32 {
    guarded(
        || {
            if out_type.is_null() || out_flags.is_null() || out_value.is_null() {
                return LR_ERR_NULL;
            }
            let Some(msg) = (unsafe { crate::handle::borrow_bgp_message(m) }) else {
                return LR_ERR_NULL;
            };
            let BgpMessage::Update(u) = msg else {
                set_last_error("message is not UPDATE".into());
                return LR_ERR_INVALID_HANDLE;
            };
            let Some(attr) = u.attributes.iter().nth(idx) else {
                set_last_error(format!("attr index {idx} out of range"));
                return LR_ERR_OTHER;
            };
            unsafe {
                *out_type = attr.attr_type.to_u8();
                *out_flags = attr.flags.0;
                *out_value = lr_bytes_t::from_vec(attr.value.clone());
            }
            0
        },
        LR_ERR_PANIC,
    )
}

/// Project a `lr_core::addr::Prefix` into the C-ABI `lr_prefix_t` shape
/// (16-byte zero-padded `addr`, `is_ipv6` discriminator, `prefix_len`).
/// Used by the UPDATE readers above.
fn prefix_to_lr_prefix(p: &lr_core::addr::Prefix) -> crate::policy::lr_prefix_t {
    use lr_core::addr::IpAddr;
    let mut out = crate::policy::lr_prefix_t {
        addr: [0u8; 16],
        is_ipv6: 0,
        prefix_len: p.prefix_len,
    };
    match p.addr {
        IpAddr::V4(b) => {
            out.addr[..4].copy_from_slice(&b);
        }
        IpAddr::V6(b) => {
            out.addr = b;
            out.is_ipv6 = 1;
        }
    }
    out
}

// ---- IPv4 NLRI codec (RFC 4271 §4.3) ----
//
// The legacy IPv4 NLRI codec lives in `lr_bgp::nlri` and is the form
// UPDATE messages carry outside of MP_REACH_NLRI / MP_UNREACH_NLRI.
// `lr_bgp_encode_update_announce_v4` already wraps it inside a full
// UPDATE; the helpers below expose the raw NLRI byte form so an
// embedder can build / parse NLRI lists directly (e.g. for a BGP-LS
// projection or a custom UPDATE encoder).

/// Encode a list of IPv4 prefixes as RFC 4271 §4.3 NLRI bytes
/// (variable-length prefix-length + minimal address bytes). Each
/// prefix must be IPv4 (the `is_ipv6` flag of every `lr_prefix_t`
/// must be 0); a non-IPv4 prefix sets the last-error string and
/// returns `LR_ERR_OTHER` (-6).
///
/// `prefixes` points to `count` `lr_prefix_t` entries. The encoded
/// bytes are written to `*out` as a freshly-allocated `lr_bytes_t`
/// (caller frees via `lr_bytes_free`).
///
/// # Safety
/// `prefixes` (when `count > 0`) must point to `count` readable
/// `lr_prefix_t` entries. `out` must point to a writable
/// `lr_bytes_t`.
#[no_mangle]
pub unsafe extern "C" fn lr_bgp_encode_ipv4_nlri(
    prefixes: *const crate::policy::lr_prefix_t,
    count: usize,
    out: *mut lr_bytes_t,
) -> i32 {
    guarded(
        || unsafe {
            if out.is_null() {
                return LR_ERR_NULL;
            }
            if count == 0 {
                unsafe { *out = lr_bytes_t::from_vec(Vec::new()) }
                return 0;
            }
            if prefixes.is_null() {
                return LR_ERR_NULL;
            }
            let slice = unsafe { core::slice::from_raw_parts(prefixes, count) };
            let mut prefixes_vec: Vec<lr_core::addr::Prefix> = Vec::with_capacity(count);
            for spec in slice {
                let Some(p) = spec.to_prefix() else {
                    set_last_error(format!("invalid prefix length {}", spec.prefix_len));
                    return LR_ERR_OTHER;
                };
                if p.is_ipv6() {
                    set_last_error("ipv4 NLRI must contain IPv4 prefixes".to_string());
                    return LR_ERR_OTHER;
                }
                prefixes_vec.push(p);
            }
            let bytes = lr_bgp::nlri::encode_ipv4_nlri(&prefixes_vec);
            unsafe { *out = lr_bytes_t::from_vec(bytes) }
            0
        },
        LR_ERR_PANIC,
    )
}

/// Decode RFC 4271 §4.3 NLRI bytes into a list of IPv4 prefixes.
/// On success writes a freshly-allocated `lr_bytes_t` to `*out`
/// carrying `n * 17` bytes (each prefix occupies 16 bytes of address
/// octets + 1 byte of prefix length — the address octets are
/// zero-padded to 16 bytes so the caller can re-use `lr_prefix_t`
/// regardless of family). Returns 0 on success, `LR_ERR_NULL` on
/// NULL pointers, `LR_ERR_OTHER` (-6) on a malformed NLRI stream
/// (prefix length > 32, or trailing bytes shorter than the prefix
/// length demands).
///
/// # Safety
/// `data` must point to `len` readable bytes. `out` must point to a
/// writable `lr_bytes_t`.
#[no_mangle]
pub unsafe extern "C" fn lr_bgp_decode_ipv4_nlri(
    data: *const u8,
    len: usize,
    out: *mut lr_bytes_t,
) -> i32 {
    guarded(
        || unsafe {
            if data.is_null() || out.is_null() {
                return LR_ERR_NULL;
            }
            let slice = unsafe { core::slice::from_raw_parts(data, len) };
            match lr_bgp::nlri::decode_ipv4_nlri(slice) {
                Some(prefixes) => {
                    // Each prefix: 16 bytes (IPv4 zero-padded to 16) +
                    // 1 byte prefix_len + 1 byte is_ipv6 (always 0).
                    let mut bytes = Vec::with_capacity(prefixes.len() * 18);
                    for p in &prefixes {
                        let mut addr16 = [0u8; 16];
                        if let lr_core::addr::IpAddr::V4(b) = &p.addr {
                            addr16[..4].copy_from_slice(b);
                        }
                        bytes.extend_from_slice(&addr16);
                        bytes.push(p.prefix_len);
                        bytes.push(0); // is_ipv6 = 0
                    }
                    unsafe { *out = lr_bytes_t::from_vec(bytes) }
                    0
                }
                None => {
                    set_last_error("malformed IPv4 NLRI stream".to_string());
                    LR_ERR_OTHER
                }
            }
        },
        LR_ERR_PANIC,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn take(b: &lr_bytes_t) -> Vec<u8> {
        unsafe { std::slice::from_raw_parts(b.ptr, b.len) }.to_vec()
    }

    fn drop_bytes(mut b: lr_bytes_t) {
        unsafe { crate::bytes::lr_bytes_free(&raw mut b) };
    }

    #[test]
    fn encode_open_round_trip() {
        let mut out = lr_bytes_t {
            ptr: std::ptr::null_mut(),
            len: 0,
            cap: 0,
        };
        let id = [10u8, 0, 0, 1];
        assert_eq!(
            unsafe { lr_bgp_encode_open(64512, 90, id.as_ptr(), 1, &raw mut out) },
            0
        );
        let bytes = take(&out);
        // Header: marker (16) + length (2) + type 1 (OPEN).
        assert_eq!(bytes[18], 1, "message type is OPEN");
        // Body: version 4, AS 64512, hold 90, id, opt-params len > 0
        // (the RFC 6793 capability), capability code 65 + 4-octet AS.
        assert_eq!(bytes[19], 4);
        assert_eq!(&bytes[20..22], &64512u16.to_be_bytes());
        assert_eq!(&bytes[22..24], &90u16.to_be_bytes());
        assert_eq!(&bytes[24..28], &id);
        let plen = bytes[28] as usize;
        assert!(plen > 0, "optional parameters present (ASN4 capability)");
        assert_eq!(bytes[29], 2, "param type 2 (capabilities, RFC 5492)");
        assert!(bytes.contains(&65), "capability code 65 present");
        // Decode with the library codec and verify the AS + capability.
        let mut codec = BgpC::new().with_asn4(true);
        let msg = codec.decode_slice(&bytes).unwrap().expect("full message");
        match msg {
            BgpMessage::Open(o) => {
                assert_eq!(o.my_as, lr_core::addr::Asn(64512));
                assert!(o
                    .params
                    .iter()
                    .any(|p| p.param_type == 2 && p.value.starts_with(&[65, 4])));
            }
            other => panic!("wrong message type: {other:?}"),
        }
        drop_bytes(out);
    }

    #[test]
    fn encode_open_rejects_bad_values() {
        let id = [10u8, 0, 0, 1];
        let mut out = lr_bytes_t {
            ptr: std::ptr::null_mut(),
            len: 0,
            cap: 0,
        };
        // Hold time 1 is illegal (RFC 4271 §4.2).
        assert_eq!(
            unsafe { lr_bgp_encode_open(64512, 1, id.as_ptr(), 0, &raw mut out) },
            -3
        );
        // A 4-byte AS without as4 cannot be represented.
        assert_eq!(
            unsafe { lr_bgp_encode_open(4200000000, 90, id.as_ptr(), 0, &raw mut out) },
            -3
        );
        // NULL BGP identifier.
        assert_eq!(
            unsafe { lr_bgp_encode_open(64512, 90, std::ptr::null(), 0, &raw mut out) },
            -1
        );
    }

    #[test]
    fn encode_open_as_trans_for_4byte_as() {
        let mut out = lr_bytes_t {
            ptr: std::ptr::null_mut(),
            len: 0,
            cap: 0,
        };
        let id = [10u8, 0, 0, 1];
        assert_eq!(
            unsafe { lr_bgp_encode_open(4200000000, 90, id.as_ptr(), 1, &raw mut out) },
            0
        );
        let bytes = take(&out);
        // The 16-bit field reads AS_TRANS (23456) per RFC 4893 §7...
        assert_eq!(&bytes[20..22], &23456u16.to_be_bytes());
        // ...and the RFC 6793 capability carries the real 4-octet AS.
        let needle: Vec<u8> = {
            let mut v = vec![65u8, 4];
            v.extend_from_slice(&4200000000u32.to_be_bytes());
            v
        };
        assert!(
            bytes.windows(needle.len()).any(|w| w == needle),
            "four-octet AS capability present"
        );
        drop_bytes(out);
    }

    #[test]
    fn encode_notification_round_trip() {
        let mut out = lr_bytes_t {
            ptr: std::ptr::null_mut(),
            len: 0,
            cap: 0,
        };
        assert_eq!(
            unsafe { lr_bgp_encode_notification(6, 3, std::ptr::null(), 0, &raw mut out) },
            0
        );
        let bytes = take(&out);
        assert_eq!(bytes[18], 3, "message type is NOTIFICATION");
        assert_eq!(&bytes[19..], &[6u8, 3], "code 6 (CEASE), subcode 3");
        assert_eq!(bytes.len(), 21, "no data payload");
        drop_bytes(out);
        out = lr_bytes_t {
            ptr: std::ptr::null_mut(),
            len: 0,
            cap: 0,
        };

        // With a data payload.
        let data = [1u8, 2, 3, 4];
        assert_eq!(
            unsafe { lr_bgp_encode_notification(3, 2, data.as_ptr(), data.len(), &raw mut out) },
            0
        );
        let bytes = take(&out);
        assert_eq!(&bytes[19..], &[3u8, 2, 1, 2, 3, 4]);
        drop_bytes(out);
    }

    #[test]
    fn encode_update_withdraw_v4_wire_form() {
        let mut out = lr_bytes_t {
            ptr: std::ptr::null_mut(),
            len: 0,
            cap: 0,
        };
        let prefixes = [
            lr_prefix_t {
                addr: [203, 0, 113, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                is_ipv6: 0,
                prefix_len: 24,
            },
            lr_prefix_t {
                addr: [198, 51, 100, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                is_ipv6: 0,
                prefix_len: 24,
            },
        ];
        assert_eq!(
            unsafe { lr_bgp_encode_update_withdraw_v4(prefixes.as_ptr(), 2, &raw mut out) },
            0
        );
        let bytes = take(&out);
        assert_eq!(bytes[18], 2, "message type is UPDATE");
        // Withdrawn length = 2 * (1 + 3) = 8, then zero attribute
        // length, then the two NLRI entries.
        assert_eq!(&bytes[19..21], &8u16.to_be_bytes(), "withdrawn length");
        assert_eq!(&bytes[21..29], &[24, 203, 0, 113, 24, 198, 51, 100]);
        assert_eq!(&bytes[29..31], &0u16.to_be_bytes(), "empty attributes");
        assert_eq!(bytes.len(), 31, "nothing follows the attribute section");
        drop_bytes(out);
        out = lr_bytes_t {
            ptr: std::ptr::null_mut(),
            len: 0,
            cap: 0,
        };

        // Zero prefixes is a legal (if useless) empty withdrawal.
        assert_eq!(
            unsafe { lr_bgp_encode_update_withdraw_v4(std::ptr::null(), 0, &raw mut out) },
            0
        );
        let bytes = take(&out);
        assert_eq!(&bytes[19..23], &[0, 0, 0, 0]);
        drop_bytes(out);
    }

    #[test]
    fn encode_update_announce_v4_wire_form() {
        let mut out = lr_bytes_t {
            ptr: std::ptr::null_mut(),
            len: 0,
            cap: 0,
        };
        let prefixes = [lr_prefix_t {
            addr: [203, 0, 113, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            is_ipv6: 0,
            prefix_len: 24,
        }];
        let nh = [192u8, 0, 2, 1];
        let ases = [64513u32, 64512];
        assert_eq!(
            unsafe {
                lr_bgp_encode_update_announce_v4(
                    prefixes.as_ptr(),
                    1,
                    nh.as_ptr(),
                    ases.as_ptr(),
                    2,
                    0,
                    0,
                    &raw mut out,
                )
            },
            0
        );
        let bytes = take(&out);
        assert_eq!(&bytes[19..21], &0u16.to_be_bytes(), "nothing withdrawn");
        // Decode back and verify the attributes semantically.
        let mut codec = BgpC::new().with_asn4(false);
        let msg = codec.decode_slice(&bytes).unwrap().expect("full message");
        match msg {
            BgpMessage::Update(u) => {
                assert!(u.withdrawn.is_empty());
                assert_eq!(u.nlri.len(), 1);
                let attrs: lr_bgp::path::PathAttributes = u.attributes.clone();
                assert_eq!(
                    attrs.origin().map(|o| o.0),
                    Some(lr_bgp::path::OriginKind::Igp),
                    "ORIGIN = IGP"
                );
                let path = attrs.as_path_wire(false).expect("AS_PATH present");
                assert_eq!(
                    path.as_sequence(),
                    vec![lr_core::addr::Asn(64513), lr_core::addr::Asn(64512)]
                );
                assert_eq!(
                    attrs.next_hop().map(|n| n.0),
                    Some(lr_bgp::path::NextHopKind::V4([192, 0, 2, 1]))
                );
            }
            other => panic!("wrong message type: {other:?}"),
        }
        drop_bytes(out);
    }

    #[test]
    fn encode_update_announce_v4_as4_path() {
        let mut out = lr_bytes_t {
            ptr: std::ptr::null_mut(),
            len: 0,
            cap: 0,
        };
        let prefixes = [lr_prefix_t {
            addr: [10, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            is_ipv6: 0,
            prefix_len: 8,
        }];
        let nh = [192u8, 0, 2, 1];
        let ases = [4200000000u32];
        assert_eq!(
            unsafe {
                lr_bgp_encode_update_announce_v4(
                    prefixes.as_ptr(),
                    1,
                    nh.as_ptr(),
                    ases.as_ptr(),
                    1,
                    0,
                    1,
                    &raw mut out,
                )
            },
            0
        );
        let bytes = take(&out);
        let mut codec = BgpC::new().with_asn4(true);
        let msg = codec.decode_slice(&bytes).unwrap().expect("full message");
        match msg {
            BgpMessage::Update(u) => {
                let attrs: lr_bgp::path::PathAttributes = u.attributes.clone();
                assert_eq!(
                    attrs.as_path().expect("AS_PATH").as_sequence(),
                    vec![lr_core::addr::Asn(4200000000)]
                );
            }
            other => panic!("wrong message type: {other:?}"),
        }
        // A 4-byte AS with as4 off is rejected.
        assert_eq!(
            unsafe {
                lr_bgp_encode_update_announce_v4(
                    prefixes.as_ptr(),
                    1,
                    nh.as_ptr(),
                    ases.as_ptr(),
                    1,
                    0,
                    0,
                    &raw mut out,
                )
            },
            -3
        );
        drop_bytes(out);
    }

    #[test]
    fn encode_update_announce_v4_rejects_bad_values() {
        let mut out = lr_bytes_t {
            ptr: std::ptr::null_mut(),
            len: 0,
            cap: 0,
        };
        let prefixes = [lr_prefix_t {
            addr: [203, 0, 113, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            is_ipv6: 0,
            prefix_len: 24,
        }];
        let nh = [192u8, 0, 2, 1];
        // ORIGIN 3 is not defined by RFC 4271 §5.1.1.
        assert_eq!(
            unsafe {
                lr_bgp_encode_update_announce_v4(
                    prefixes.as_ptr(),
                    1,
                    nh.as_ptr(),
                    std::ptr::null(),
                    0,
                    3,
                    0,
                    &raw mut out,
                )
            },
            -3
        );
        // IPv6 prefixes do not fit the legacy NLRI section.
        let v6 = [lr_prefix_t {
            addr: [0x20, 1, 0xd, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            is_ipv6: 1,
            prefix_len: 32,
        }];
        assert_eq!(
            unsafe { lr_bgp_encode_update_withdraw_v4(v6.as_ptr(), 1, &raw mut out) },
            -3
        );
        // Prefix length 33 is invalid for IPv4.
        let bad = [lr_prefix_t {
            addr: [203, 0, 113, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            is_ipv6: 0,
            prefix_len: 33,
        }];
        assert_eq!(
            unsafe { lr_bgp_encode_update_withdraw_v4(bad.as_ptr(), 1, &raw mut out) },
            -3
        );
        // NULL next-hop.
        assert_eq!(
            unsafe {
                lr_bgp_encode_update_announce_v4(
                    prefixes.as_ptr(),
                    1,
                    std::ptr::null(),
                    std::ptr::null(),
                    0,
                    0,
                    0,
                    &raw mut out,
                )
            },
            -1
        );
    }

    fn new_out() -> lr_bytes_t {
        lr_bytes_t {
            ptr: std::ptr::null_mut(),
            len: 0,
            cap: 0,
        }
    }

    #[test]
    fn ospf_decode_v2_round_trips_through_encoder() {
        // Build a minimal OSPFv2 Hello (RFC 2328 §A.3.1) via the
        // library codec so the FFI surface gets valid bytes to chew on.
        let codec = OspfC::v2();
        let pkt = lr_ospf::OspfPacket {
            header: lr_ospf::OspfHeader {
                version: 2,
                kind: 1, // Hello.
                length: 0,
                router_id: 0x01020304,
                area_id: 0,
                checksum: 0,
                au_type_or_instance: 0,
                auth_data: 0,
            },
            body: lr_ospf::packet::OspfBody::Hello(lr_ospf::packet::HelloBody {
                network_mask: 0xffffff00,
                hello_interval: 10,
                options: 0x02,
                priority: 1,
                dead_interval: 40,
                dr: 0,
                bdr: 0,
                neighbors: vec![0x01020304, 0x05060708],
            }),
        };
        let mut bytes = codec.encode_vec(&pkt).unwrap();
        lr_ospf::origination::finalize_v2_packet(&mut bytes);

        let mut out = new_out();
        let rc = lr_ospf_decode_v2(bytes.as_ptr(), bytes.len(), &raw mut out);
        assert_eq!(rc, 0, "decode must succeed on a valid Hello");
        let got = take(&out);
        // The output is the re-encoded canonical form, not the raw
        // input bytes. The fixed header layout: version (1) + kind (1)
        // + length (2) + router-id (4) + area-id (4) + checksum (2)
        // + au_type (2) + auth_data (8) = 24 bytes.
        assert_eq!(got[0], 2, "OSPF version 2");
        assert_eq!(got[1], 1, "Hello kind");
        assert_eq!(&got[4..8], &0x01020304u32.to_be_bytes(), "router-id");
        // Length covers header (24) + Hello body (network_mask 4 +
        // hello_interval 2 + options 1 + priority 1 + dead_interval 4
        // + dr 4 + bdr 4 + neighbors 8 = 28) = 52.
        assert_eq!(&got[2..4], &52u16.to_be_bytes(), "packet length");
        drop_bytes(out);
    }

    #[test]
    fn ospf_decode_v2_rejects_null_pointers() {
        let mut out = new_out();
        assert_eq!(lr_ospf_decode_v2(std::ptr::null(), 0, &raw mut out), -1);
        let bytes = [0u8; 24];
        assert_eq!(
            lr_ospf_decode_v2(bytes.as_ptr(), bytes.len(), std::ptr::null_mut()),
            -1
        );
    }

    #[test]
    fn ospf_decode_v2_rejects_truncated_input() {
        // Three bytes cannot fit the OSPF fixed header (24 bytes).
        let bytes = [0u8, 2, 1];
        let mut out = new_out();
        let rc = lr_ospf_decode_v2(bytes.as_ptr(), bytes.len(), &raw mut out);
        assert!(
            rc == -3 || rc == -5,
            "truncated/malformed input returns -3/-5, got {rc}"
        );
    }

    #[test]
    fn babel_decode_round_trips_through_encoder() {
        // A minimal Babel frame: one Hello TLV (RFC 8966 §A.2) plus a
        // single Pad1 to round the body up to a non-trivial length.
        let h = lr_babel::message::Hello::new(1, 200);
        let mut frame = lr_babel::BabelFrame::empty();
        frame.body.push(lr_babel::tlv::Tlv::new(
            lr_babel::tlv::TlvType::Hello,
            h.encode().to_vec(),
        ));
        frame.body.push(lr_babel::tlv::Tlv::pad1());
        let codec = BabelC::new();
        let bytes = codec.encode_vec(&frame).unwrap();

        let mut out = new_out();
        let rc = lr_babel_decode(bytes.as_ptr(), bytes.len(), &raw mut out);
        assert_eq!(rc, 0, "decode must succeed on a valid Babel frame");
        let got = take(&out);
        // Wire layout (RFC 8966 §4.1): magic (1) + version (1) +
        // body_length (2 BE) + body. The body begins at offset 4 with
        // the Hello TLV: type (1) + length (1) + value (6 for the
        // encoded Hello — `Hello::new(1, 200)` packs seqno + interval
        // into 6 bytes).
        assert_eq!(got[0], 0x2a, "Babel magic");
        assert_eq!(got[1], 2, "Babel version 2");
        // Hello TLV type lives at offset 4, after the fixed header.
        assert_eq!(
            got[4],
            lr_babel::tlv::TlvType::Hello.to_u8(),
            "first TLV is Hello"
        );
        // The Hello TLV value is 6 bytes (RFC 8966 §A.2: 2-byte
        // seqno + 2-byte interval + 2 reserved bits).
        assert_eq!(got[5], 6, "Hello TLV value length is 6");
        drop_bytes(out);
    }

    #[test]
    fn babel_decode_rejects_null_pointers() {
        let mut out = new_out();
        assert_eq!(lr_babel_decode(std::ptr::null(), 0, &raw mut out), -1);
        let bytes = [0u8; 4];
        assert_eq!(
            lr_babel_decode(bytes.as_ptr(), bytes.len(), std::ptr::null_mut()),
            -1
        );
    }

    #[test]
    fn babel_decode_rejects_truncated_input() {
        // Two bytes cannot fit the magic + body.
        let bytes = [0x2a, 0x00];
        let mut out = new_out();
        let rc = lr_babel_decode(bytes.as_ptr(), bytes.len(), &raw mut out);
        assert!(
            rc == -3 || rc == -5,
            "truncated/malformed input returns -3/-5, got {rc}"
        );
    }

    // ---------- structured BGP message inspection ----------

    use crate::handle::{box_bgp_message, lr_bgp_message_t};
    use lr_bgp::message::{Keepalive, Open, OpenParam, RouteRefresh, RouteRefreshSubtype};

    fn last_error() -> String {
        use std::ffi::CStr;
        unsafe {
            CStr::from_ptr(crate::error::lr_last_error())
                .to_string_lossy()
                .into_owned()
        }
    }

    /// Build a BGP-4 OPEN with the 4-byte AS capability so the AS_TRANS
    /// unwrap path is exercised end-to-end through the FFI.
    fn build_open_with_as4(asn: u32, hold: u16, id: [u8; 4]) -> Vec<u8> {
        let mut out = new_out();
        assert_eq!(
            unsafe { lr_bgp_encode_open(asn, hold, id.as_ptr(), 1, &raw mut out) },
            0,
            "encode_open must succeed"
        );
        take(&out)
    }

    fn build_keepalive() -> Vec<u8> {
        let mut out = new_out();
        assert_eq!(lr_bgp_encode_keepalive(&raw mut out), 0);
        take(&out)
    }

    fn build_notification(code: u8, subcode: u8, data: &[u8]) -> Vec<u8> {
        let mut out = new_out();
        assert_eq!(
            unsafe {
                lr_bgp_encode_notification(
                    code,
                    subcode,
                    if data.is_empty() {
                        std::ptr::null()
                    } else {
                        data.as_ptr()
                    },
                    data.len(),
                    &raw mut out,
                )
            },
            0
        );
        take(&out)
    }

    fn build_update_withdraw(prefixes: &[([u8; 4], u8)]) -> Vec<u8> {
        let mut out = new_out();
        let arr: Vec<lr_prefix_t> = prefixes
            .iter()
            .map(|(addr, len)| lr_prefix_t {
                addr: {
                    let mut a = [0u8; 16];
                    a[..4].copy_from_slice(addr);
                    a
                },
                is_ipv6: 0,
                prefix_len: *len,
            })
            .collect();
        assert_eq!(
            unsafe { lr_bgp_encode_update_withdraw_v4(arr.as_ptr(), arr.len(), &raw mut out,) },
            0
        );
        take(&out)
    }

    fn build_update_announce(
        prefixes: &[([u8; 4], u8)],
        next_hop: [u8; 4],
        as_path: &[u32],
        origin: u8,
    ) -> Vec<u8> {
        let mut out = new_out();
        let arr: Vec<lr_prefix_t> = prefixes
            .iter()
            .map(|(addr, len)| lr_prefix_t {
                addr: {
                    let mut a = [0u8; 16];
                    a[..4].copy_from_slice(addr);
                    a
                },
                is_ipv6: 0,
                prefix_len: *len,
            })
            .collect();
        assert_eq!(
            unsafe {
                lr_bgp_encode_update_announce_v4(
                    arr.as_ptr(),
                    arr.len(),
                    next_hop.as_ptr(),
                    as_path.as_ptr(),
                    as_path.len(),
                    origin,
                    1,
                    &raw mut out,
                )
            },
            0
        );
        take(&out)
    }

    #[test]
    fn decode_message_returns_null_on_null_data() {
        let m = lr_bgp_decode_message(std::ptr::null(), 0);
        assert!(m.is_null(), "null data must return NULL handle");
        let err = last_error();
        assert!(err.contains("null"), "expected null error, got: {err}");
    }

    #[test]
    fn decode_message_returns_null_on_truncated() {
        // 4 bytes cannot fit a 19-byte BGP header.
        let bytes = [0xffu8; 4];
        let m = lr_bgp_decode_message(bytes.as_ptr(), bytes.len());
        assert!(m.is_null(), "truncated input must return NULL");
        unsafe { lr_bgp_message_free(m) };
    }

    #[test]
    fn message_type_round_trip() {
        for (label, bytes, want) in [
            (
                1u8,
                build_open_with_as4(64512, 90, [10, 0, 0, 1]),
                LR_BGP_MSG_OPEN,
            ),
            (2, build_keepalive(), LR_BGP_MSG_KEEPALIVE),
            (3, build_notification(6, 4, &[]), LR_BGP_MSG_NOTIFICATION),
            (
                4,
                build_update_withdraw(&[([203, 0, 113, 0], 24)]),
                LR_BGP_MSG_UPDATE,
            ),
        ] {
            let m = lr_bgp_decode_message(bytes.as_ptr(), bytes.len());
            assert!(!m.is_null(), "case {label}: decode must succeed");
            let mut kind = 0u8;
            assert_eq!(
                unsafe { lr_bgp_message_type(m, &raw mut kind) },
                0,
                "case {label}: type read must succeed"
            );
            assert_eq!(kind, want, "case {label}: type code mismatch");
            unsafe { lr_bgp_message_free(m) };
        }
    }

    #[test]
    fn message_type_null_handle_returns_null_err() {
        let mut kind = 0u8;
        assert_eq!(
            unsafe { lr_bgp_message_type(std::ptr::null_mut(), &raw mut kind) },
            LR_ERR_NULL
        );
    }

    #[test]
    fn open_readers_round_trip_as4() {
        // 4_200_000_000 cannot fit in 16 bits, so the OPEN must
        // announce AS_TRANS (23456) on the wire and carry the real
        // AS inside the RFC 6793 capability. The reader is
        // expected to unwrap and surface the 32-bit value.
        let bytes = build_open_with_as4(4_200_000_000, 180, [10, 0, 0, 1]);
        let m = lr_bgp_decode_message(bytes.as_ptr(), bytes.len());
        assert!(!m.is_null());

        let mut version = 0u8;
        assert_eq!(
            unsafe { lr_bgp_message_open_version(m, &raw mut version) },
            0
        );
        assert_eq!(version, 4, "BGP-4 only");

        let mut asn = 0u32;
        assert_eq!(unsafe { lr_bgp_message_open_my_as(m, &raw mut asn) }, 0);
        assert_eq!(asn, 4_200_000_000, "must unwrap AS_TRANS → real AS");

        let mut hold = 0u16;
        assert_eq!(
            unsafe { lr_bgp_message_open_hold_time(m, &raw mut hold) },
            0
        );
        assert_eq!(hold, 180);

        let mut id = [0u8; 4];
        assert_eq!(unsafe { lr_bgp_message_open_bgp_id(m, id.as_mut_ptr()) }, 0);
        assert_eq!(id, [10, 0, 0, 1]);

        // The encoder appends exactly one optional parameter (the
        // capabilities TLV) holding the 4-byte-AS capability.
        let param_count = lr_bgp_message_open_param_count(m);
        assert_eq!(param_count, 1, "exactly one capabilities param");
        let mut ptype = 0u8;
        let mut pvalue = lr_bytes_t {
            ptr: std::ptr::null_mut(),
            len: 0,
            cap: 0,
        };
        assert_eq!(
            unsafe { lr_bgp_message_open_param_at(m, 0, &raw mut ptype, &raw mut pvalue) },
            0
        );
        assert_eq!(ptype, 2, "param type 2 = capabilities (RFC 5492)");
        // The capabilities payload begins with (code=65, length=4, as_be).
        let value_bytes = take(&pvalue);
        drop_bytes(pvalue);
        assert_eq!(value_bytes[0], 65, "capability code 65 = Four-Octet-AS");
        assert_eq!(value_bytes[1], 4, "capability length 4");
        assert_eq!(
            &value_bytes[2..6],
            &4_200_000_000u32.to_be_bytes(),
            "real 4-byte AS in the capability value"
        );

        // Out-of-range index returns LR_ERR_OTHER. Use a fresh
        // `lr_bytes_t` since `drop_bytes(pvalue)` already consumed it.
        let mut ptype2 = 0u8;
        let mut pvalue2 = lr_bytes_t {
            ptr: std::ptr::null_mut(),
            len: 0,
            cap: 0,
        };
        let rc = unsafe { lr_bgp_message_open_param_at(m, 1, &raw mut ptype2, &raw mut pvalue2) };
        assert_eq!(rc, LR_ERR_OTHER);

        unsafe { lr_bgp_message_free(m) };
    }

    #[test]
    fn open_readers_reject_wrong_variant() {
        // A KEEPALIVE decoded through the OPEN readers must return
        // LR_ERR_INVALID_HANDLE and set the last-error string.
        let bytes = build_keepalive();
        let m = lr_bgp_decode_message(bytes.as_ptr(), bytes.len());
        assert!(!m.is_null());
        let mut version = 0u8;
        assert_eq!(
            unsafe { lr_bgp_message_open_version(m, &raw mut version) },
            LR_ERR_INVALID_HANDLE
        );
        assert!(last_error().contains("not OPEN"), "{}", last_error());
        unsafe { lr_bgp_message_free(m) };
    }

    #[test]
    fn open_readers_reject_null_handle_and_null_outputs() {
        let mut v = 0u8;
        assert_eq!(
            unsafe { lr_bgp_message_open_version(std::ptr::null_mut(), &raw mut v) },
            LR_ERR_NULL
        );
        // Build a real OPEN so we can verify null-output rejection too.
        let bytes = build_open_with_as4(64512, 90, [10, 0, 0, 1]);
        let m = lr_bgp_decode_message(bytes.as_ptr(), bytes.len());
        assert!(!m.is_null());
        assert_eq!(
            unsafe { lr_bgp_message_open_version(m, std::ptr::null_mut()) },
            LR_ERR_NULL
        );
        assert_eq!(
            unsafe { lr_bgp_message_open_my_as(m, std::ptr::null_mut()) },
            LR_ERR_NULL
        );
        assert_eq!(
            unsafe { lr_bgp_message_open_hold_time(m, std::ptr::null_mut()) },
            LR_ERR_NULL
        );
        assert_eq!(
            unsafe { lr_bgp_message_open_bgp_id(m, std::ptr::null_mut()) },
            LR_ERR_NULL
        );
        assert_eq!(
            unsafe {
                lr_bgp_message_open_param_at(m, 0, std::ptr::null_mut(), std::ptr::null_mut())
            },
            LR_ERR_NULL
        );
        unsafe { lr_bgp_message_free(m) };
    }

    #[test]
    fn notification_readers_round_trip() {
        // Cease / Administrative Reset, no data (the compact form BIRD/FRR emit).
        let bytes = build_notification(6, 4, &[]);
        let m = lr_bgp_decode_message(bytes.as_ptr(), bytes.len());
        assert!(!m.is_null());

        let mut code = 0u8;
        let mut subcode = 0u8;
        let mut data = lr_bytes_t {
            ptr: std::ptr::null_mut(),
            len: 0,
            cap: 0,
        };
        assert_eq!(
            unsafe { lr_bgp_message_notification_code(m, &raw mut code) },
            0
        );
        assert_eq!(
            unsafe { lr_bgp_message_notification_subcode(m, &raw mut subcode) },
            0
        );
        assert_eq!(
            unsafe { lr_bgp_message_notification_data(m, &raw mut data) },
            0
        );
        assert_eq!(code, 6, "Cease");
        assert_eq!(subcode, 4, "Administrative Reset");
        assert_eq!(data.len, 0, "no diagnostic data");
        drop_bytes(data);
        unsafe { lr_bgp_message_free(m) };

        // NOTIFICATION with diagnostic data (Header/Conn-Not-Sync).
        let payload = [0xde, 0xad, 0xbe, 0xef];
        let bytes = build_notification(1, 2, &payload);
        let m = lr_bgp_decode_message(bytes.as_ptr(), bytes.len());
        assert!(!m.is_null());
        let mut data = lr_bytes_t {
            ptr: std::ptr::null_mut(),
            len: 0,
            cap: 0,
        };
        assert_eq!(
            unsafe { lr_bgp_message_notification_data(m, &raw mut data) },
            0
        );
        assert_eq!(take(&data), payload);
        drop_bytes(data);
        unsafe { lr_bgp_message_free(m) };
    }

    #[test]
    fn notification_readers_reject_wrong_variant() {
        let bytes = build_keepalive();
        let m = lr_bgp_decode_message(bytes.as_ptr(), bytes.len());
        assert!(!m.is_null());
        let mut code = 0u8;
        assert_eq!(
            unsafe { lr_bgp_message_notification_code(m, &raw mut code) },
            LR_ERR_INVALID_HANDLE
        );
        assert!(last_error().contains("not NOTIFICATION"));
        unsafe { lr_bgp_message_free(m) };
    }

    #[test]
    fn route_refresh_readers_round_trip() {
        use lr_core::nlri::NlriFamily;
        // Construct a ROUTE-REFRESH for IPv6 unicast (AFI=2, SAFI=1)
        // with the BoRR subtype. Build the message via the Rust API
        // and encode it through BgpCodec so the decoder sees real
        // wire bytes.
        let rr = RouteRefresh {
            family: NlriFamily { afi: 2, safi: 1 },
            subtype: RouteRefreshSubtype::BeginOfRib,
        };
        let codec = BgpC::new();
        let bytes = codec.encode_vec(&BgpMessage::RouteRefresh(rr)).unwrap();
        let m = lr_bgp_decode_message(bytes.as_ptr(), bytes.len());
        assert!(!m.is_null());

        let mut afi = 0u16;
        let mut safi = 0u8;
        let mut subtype = 0u8;
        assert_eq!(
            unsafe { lr_bgp_message_route_refresh_afi(m, &raw mut afi) },
            0
        );
        assert_eq!(
            unsafe { lr_bgp_message_route_refresh_safi(m, &raw mut safi) },
            0
        );
        assert_eq!(
            unsafe { lr_bgp_message_route_refresh_subtype(m, &raw mut subtype) },
            0
        );
        assert_eq!(afi, 2, "IPv6");
        assert_eq!(safi, 1, "unicast");
        assert_eq!(subtype, LR_BGP_RR_SUBTYPE_BORR, "BoRR");
        unsafe { lr_bgp_message_free(m) };
    }

    #[test]
    fn route_refresh_readers_reject_wrong_variant() {
        let bytes = build_keepalive();
        let m = lr_bgp_decode_message(bytes.as_ptr(), bytes.len());
        assert!(!m.is_null());
        let mut afi = 0u16;
        assert_eq!(
            unsafe { lr_bgp_message_route_refresh_afi(m, &raw mut afi) },
            LR_ERR_INVALID_HANDLE
        );
        assert!(last_error().contains("not ROUTE-REFRESH"));
        unsafe { lr_bgp_message_free(m) };
    }

    #[test]
    fn update_readers_round_trip_withdraw_only() {
        // Withdraw-only UPDATE: two prefixes, no attributes, no NLRI.
        let bytes = build_update_withdraw(&[([203, 0, 113, 0], 24), ([198, 51, 100, 0], 25)]);
        let m = lr_bgp_decode_message(bytes.as_ptr(), bytes.len());
        assert!(!m.is_null());

        assert_eq!(lr_bgp_message_update_withdrawn_count(m), 2);
        assert_eq!(
            lr_bgp_message_update_nlri_count(m),
            0,
            "no NLRI in withdraw-only"
        );

        let mut prefix = lr_prefix_t {
            addr: [0u8; 16],
            is_ipv6: 0,
            prefix_len: 0,
        };
        assert_eq!(
            unsafe { lr_bgp_message_update_withdrawn_at(m, 0, &raw mut prefix) },
            0
        );
        assert_eq!(&prefix.addr[..4], &[203, 0, 113, 0]);
        assert_eq!(prefix.prefix_len, 24);
        assert_eq!(prefix.is_ipv6, 0);

        assert_eq!(
            unsafe { lr_bgp_message_update_withdrawn_at(m, 1, &raw mut prefix) },
            0
        );
        assert_eq!(&prefix.addr[..4], &[198, 51, 100, 0]);
        assert_eq!(prefix.prefix_len, 25);

        // Out-of-range returns LR_ERR_OTHER.
        assert_eq!(
            unsafe { lr_bgp_message_update_withdrawn_at(m, 2, &raw mut prefix) },
            LR_ERR_OTHER
        );

        // No NLRI to read; the nlri_at reader must also reject the
        // out-of-range index.
        assert_eq!(
            unsafe { lr_bgp_message_update_nlri_at(m, 0, &raw mut prefix) },
            LR_ERR_OTHER
        );

        // Path attributes: the encoder writes ORIGIN + AS_PATH +
        // NEXT_HOP for an announce UPDATE; for a withdraw-only
        // UPDATE there are zero attributes.
        assert_eq!(lr_bgp_message_update_attr_count(m), 0);

        unsafe { lr_bgp_message_free(m) };
    }

    #[test]
    fn update_readers_round_trip_announce() {
        let bytes = build_update_announce(
            &[([203, 0, 113, 0], 24)],
            [192, 0, 2, 1],
            &[64512, 64513, 64514],
            0, // IGP
        );
        let m = lr_bgp_decode_message(bytes.as_ptr(), bytes.len());
        assert!(!m.is_null());

        assert_eq!(lr_bgp_message_update_nlri_count(m), 1);
        assert_eq!(lr_bgp_message_update_withdrawn_count(m), 0);

        let mut prefix = lr_prefix_t {
            addr: [0u8; 16],
            is_ipv6: 0,
            prefix_len: 0,
        };
        assert_eq!(
            unsafe { lr_bgp_message_update_nlri_at(m, 0, &raw mut prefix) },
            0
        );
        assert_eq!(&prefix.addr[..4], &[203, 0, 113, 0]);
        assert_eq!(prefix.prefix_len, 24);

        // The encoder writes ORIGIN (1) + AS_PATH (2) + NEXT_HOP (3).
        assert!(lr_bgp_message_update_attr_count(m) >= 3);
        let mut found_origin = false;
        let mut found_next_hop = false;
        for i in 0..lr_bgp_message_update_attr_count(m) {
            let mut atype = 0u8;
            let mut aflags = 0u8;
            let mut avalue = lr_bytes_t {
                ptr: std::ptr::null_mut(),
                len: 0,
                cap: 0,
            };
            assert_eq!(
                unsafe {
                    lr_bgp_message_update_attr_at(
                        m,
                        i,
                        &raw mut atype,
                        &raw mut aflags,
                        &raw mut avalue,
                    )
                },
                0
            );
            if atype == 1 {
                found_origin = true;
                assert_eq!(avalue.len, 1, "ORIGIN value is 1 byte");
                assert_eq!(take(&avalue)[0], 0, "ORIGIN=IGP");
            }
            if atype == 3 {
                found_next_hop = true;
                assert_eq!(avalue.len, 4, "NEXT_HOP value is 4 bytes");
                assert_eq!(&take(&avalue)[..], &[192, 0, 2, 1]);
            }
            drop_bytes(avalue);
        }
        assert!(found_origin, "ORIGIN attribute present");
        assert!(found_next_hop, "NEXT_HOP attribute present");

        unsafe { lr_bgp_message_free(m) };
    }

    #[test]
    fn update_readers_reject_wrong_variant() {
        let bytes = build_keepalive();
        let m = lr_bgp_decode_message(bytes.as_ptr(), bytes.len());
        assert!(!m.is_null());
        assert_eq!(lr_bgp_message_update_withdrawn_count(m), 0);
        assert!(last_error().contains("not UPDATE"));
        unsafe { lr_bgp_message_free(m) };
    }

    #[test]
    fn update_attr_at_rejects_null_outputs() {
        let bytes = build_update_announce(&[([203, 0, 113, 0], 24)], [192, 0, 2, 1], &[64512], 0);
        let m = lr_bgp_decode_message(bytes.as_ptr(), bytes.len());
        assert!(!m.is_null());
        assert_eq!(
            unsafe {
                lr_bgp_message_update_attr_at(
                    m,
                    0,
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                )
            },
            LR_ERR_NULL
        );
        unsafe { lr_bgp_message_free(m) };
    }

    #[test]
    fn free_handles_null_safely() {
        // SAFE no-op on a NULL handle — no UB, no panic, no allocation.
        unsafe { lr_bgp_message_free(std::ptr::null_mut()) };
    }

    #[test]
    fn decode_then_free_does_not_leak() {
        // Sanity check the box/unbox lifecycle on a real message.
        // Repeated decode + free in a loop should not OOM in practice
        // (the test does not assert memory, only that the cycle
        // completes without panicking or returning NULL).
        let bytes = build_open_with_as4(64512, 90, [10, 0, 0, 1]);
        for _ in 0..100 {
            let m = lr_bgp_decode_message(bytes.as_ptr(), bytes.len());
            assert!(!m.is_null());
            unsafe { lr_bgp_message_free(m) };
        }
    }

    #[test]
    fn open_my_as_unwraps_as_trans_for_2_byte_as_with_capability() {
        // A 16-bit AS that ALSO carries the 4-byte-AS capability
        // (e.g. an AS_TRANS upgrade probe from BIRD) must surface
        // the capability's value, not the 16-bit field.
        let open = Open::new(
            lr_core::addr::Asn::new(23456),
            90,
            lr_core::addr::RouterId::from_u32(0x0a000001),
        );
        // Manually attach a Four-Octet-AS capability with AS 4_000_000.
        let mut cap_bytes = vec![65u8, 4];
        cap_bytes.extend_from_slice(&4_000_000u32.to_be_bytes());
        let param = OpenParam {
            param_type: OpenParam::PARAM_TYPE_CAPABILITY,
            value: cap_bytes,
        };
        let mut open = open;
        open.params.push(param);
        let codec = BgpC::new();
        let bytes = codec.encode_vec(&BgpMessage::Open(open)).unwrap();
        let m = lr_bgp_decode_message(bytes.as_ptr(), bytes.len());
        assert!(!m.is_null());
        let mut asn = 0u32;
        assert_eq!(unsafe { lr_bgp_message_open_my_as(m, &raw mut asn) }, 0);
        assert_eq!(
            asn, 4_000_000,
            "AS_TRANS must be unwrapped to the cap value"
        );
        unsafe { lr_bgp_message_free(m) };
    }

    #[test]
    fn open_my_as_returns_16bit_when_no_capability() {
        // A plain 2-byte AS without the 4-byte-AS capability returns
        // the raw 16-bit field value (no unwrap).
        let mut out = new_out();
        // as4=0 to suppress the capability; 64512 fits in 16 bits.
        assert_eq!(
            unsafe { lr_bgp_encode_open(64512, 90, [10, 0, 0, 1].as_ptr(), 0, &raw mut out) },
            0
        );
        let bytes = take(&out);
        let m = lr_bgp_decode_message(bytes.as_ptr(), bytes.len());
        assert!(!m.is_null());
        let mut asn = 0u32;
        assert_eq!(unsafe { lr_bgp_message_open_my_as(m, &raw mut asn) }, 0);
        assert_eq!(asn, 64512, "no capability → raw 16-bit field");
        unsafe { lr_bgp_message_free(m) };
    }

    /// Box a hand-built message directly, exercising the box/unbox
    /// path that does not go through `lr_bgp_decode_message`.
    #[test]
    fn box_bgp_message_then_borrow_round_trip() {
        let msg = BgpMessage::Keepalive(Keepalive);
        let m: lr_bgp_message_t = box_bgp_message(msg);
        let mut kind = 0u8;
        assert_eq!(unsafe { lr_bgp_message_type(m, &raw mut kind) }, 0);
        assert_eq!(kind, LR_BGP_MSG_KEEPALIVE);
        unsafe { lr_bgp_message_free(m) };
    }

    // ---- IPv4 NLRI codec (RFC 4271 §4.3) ----

    #[test]
    fn ffi_encode_ipv4_nlri_round_trip() {
        let prefixes = [
            crate::policy::lr_prefix_t {
                addr: [203, 0, 113, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                is_ipv6: 0,
                prefix_len: 24,
            },
            crate::policy::lr_prefix_t {
                addr: [198, 51, 100, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                is_ipv6: 0,
                prefix_len: 16,
            },
        ];
        let mut out = new_out();
        let rc =
            unsafe { lr_bgp_encode_ipv4_nlri(prefixes.as_ptr(), prefixes.len(), &raw mut out) };
        assert_eq!(rc, 0);
        let bytes = take(&out);
        drop_bytes(out);
        // First prefix 203.0.113.0/24 → 0x18 (24) + 3 bytes.
        // Second prefix 198.51.100.0/16 → 0x10 (16) + 2 bytes.
        // Total = 4 + 3 = 7 bytes.
        assert_eq!(bytes.len(), 7);
        assert_eq!(bytes[0], 24); // prefix length
        assert_eq!(bytes[1..4], [203, 0, 113]); // 3 octets of /24
        assert_eq!(bytes[4], 16); // prefix length
        assert_eq!(bytes[5..7], [198, 51]); // 2 octets of /16
    }

    #[test]
    fn ffi_decode_ipv4_nlri_round_trip() {
        // Same wire form the encode test produces.
        let wire: [u8; 7] = [24, 203, 0, 113, 16, 198, 51];
        let mut out = new_out();
        let rc = unsafe { lr_bgp_decode_ipv4_nlri(wire.as_ptr(), wire.len(), &raw mut out) };
        assert_eq!(rc, 0);
        let bytes = take(&out);
        drop_bytes(out);
        // Two prefixes × 18 bytes (16 addr + 1 prefix_len + 1 is_ipv6).
        assert_eq!(bytes.len(), 36);
        // First prefix: 203.0.113.0/24, is_ipv6=0.
        assert_eq!(bytes[0..4], [203, 0, 113, 0]); // addr padded to 16
        assert_eq!(bytes[16], 24); // prefix_len
        assert_eq!(bytes[17], 0); // is_ipv6
                                  // Second prefix: 198.51.100.0/16, is_ipv6=0.
        assert_eq!(bytes[18..20], [198, 51]); // first 2 octets
        assert_eq!(bytes[18 + 16], 16); // prefix_len
        assert_eq!(bytes[18 + 17], 0); // is_ipv6
    }

    #[test]
    fn ffi_encode_ipv4_nlri_rejects_ipv6_prefix() {
        let prefixes = [crate::policy::lr_prefix_t {
            addr: [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            is_ipv6: 1,
            prefix_len: 32,
        }];
        let mut out = new_out();
        let rc =
            unsafe { lr_bgp_encode_ipv4_nlri(prefixes.as_ptr(), prefixes.len(), &raw mut out) };
        assert_eq!(rc, LR_ERR_OTHER);
    }

    #[test]
    fn ffi_encode_ipv4_nlri_handles_empty_input() {
        let mut out = new_out();
        let rc = unsafe { lr_bgp_encode_ipv4_nlri(std::ptr::null(), 0, &raw mut out) };
        assert_eq!(rc, 0);
        let bytes = take(&out);
        drop_bytes(out);
        assert!(bytes.is_empty());
    }

    #[test]
    fn ffi_decode_ipv4_nlri_rejects_malformed_stream() {
        // Prefix length 40 (> 32) → invalid for IPv4.
        let bad: [u8; 2] = [40, 0];
        let mut out = new_out();
        let rc = unsafe { lr_bgp_decode_ipv4_nlri(bad.as_ptr(), bad.len(), &raw mut out) };
        assert_eq!(rc, LR_ERR_OTHER);
    }

    #[test]
    fn ffi_encode_ipv4_nlri_handles_null_safely() {
        let mut out = new_out();
        // NULL out → LR_ERR_NULL.
        let rc = unsafe { lr_bgp_encode_ipv4_nlri(std::ptr::null(), 0, std::ptr::null_mut()) };
        assert_eq!(rc, LR_ERR_NULL);
        // Non-zero count + NULL prefixes → LR_ERR_NULL.
        let rc = unsafe { lr_bgp_encode_ipv4_nlri(std::ptr::null(), 1, &raw mut out) };
        assert_eq!(rc, LR_ERR_NULL);
    }

    #[test]
    fn ffi_decode_ipv4_nlri_handles_null_safely() {
        let rc = unsafe { lr_bgp_decode_ipv4_nlri(std::ptr::null(), 0, std::ptr::null_mut()) };
        assert_eq!(rc, LR_ERR_NULL);
    }
}
