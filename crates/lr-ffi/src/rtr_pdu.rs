//! RTR PDU codec FFI — `lr_rtr_pdu_*`.
//!
//! Mirrors the public Rust API of `lr_bgp::rtr::pdu::{RtrPdu, RtrPduType,
//! RtrErrorCode, encode, decode, encode_vec}` so an embedder can build,
//! inspect and round-trip RPKI-Router protocol PDUs (RFC 8210 §5)
//! without going through the `RtrClient` state machine.
//!
//! # Surface
//!
//! - `lr_rtr_pdu_encode` / `lr_rtr_pdu_encode_vec` — RFC 8210 §5 PDU
//!   encoder (one PDU per call, appends to caller-supplied bytes).
//! - `lr_rtr_pdu_decode` — framing-aware decode (returns the parsed
//!   PDU + version + bytes consumed, or `NULL` when the buffer is
//!   incomplete).
//! - `lr_rtr_pdu_free` — drop a boxed `RtrPdu`.
//! - `lr_rtr_pdu_type` / `lr_rtr_pdu_min_version` — variant introspection.
//! - `lr_rtr_pdu_serial_notify` / `_serial_query` / `_reset_query` /
//!   `_cache_response` / `_cache_reset` — fixed-size PDU constructors.
//! - `lr_rtr_pdu_ipv4_prefix` / `_ipv6_prefix` — ROA PDU constructors.
//! - `lr_rtr_pdu_end_of_data` — End-of-Data constructor (timing
//!   intervals are optional per §5.8 — pass 0 to omit on v0).
//! - `lr_rtr_pdu_router_key` — Router Key PDU constructor.
//! - `lr_rtr_pdu_error_report` — Error Report PDU constructor.
//! - `lr_rtr_pdu_aspa` — ASPA PDU constructor (v2+).
//! - `lr_rtr_pdu_*_session_id` / `_serial` / `_announce` / `_prefix`
//!   / `_max_length` / `_asn` / `_refresh_interval` / `_retry_interval`
//!   / `_expire_interval` / `_ski` / `_subject_public_key_info` /
//!   `_error_code` / `_erroneous_pdu` / `_error_text` /
//!   `_customer_asn` / `_providers` — per-variant accessors.
//! - `lr_rtr_pdu_type_name` / `lr_rtr_pdu_type_min_len` /
//!   `lr_rtr_pdu_type_from_u8` — type-code introspection.
//! - `lr_rtr_error_code_name` / `lr_rtr_error_code_is_fatal` /
//!   `lr_rtr_error_code_from_u16` — error-code introspection.
//!
//! Constants: `LR_RTR_VERSION_0/1/2/MAX`, `LR_RTR_HEADER_LEN`,
//! `LR_RTR_PDU_MAX_LEN`, `LR_RTR_FLAG_ANNOUNCE` are emitted as
//! `pub const` in `lib.rs` so the cbindgen header publishes them as
//! `#define`s.
//!
//! Every entry point runs inside the crate's `catch_unwind` barrier
//! ([`crate::guarded`]): a panic returns `LR_ERR_PANIC` and sets the
//! thread-local last-error string.

#![allow(unused_unsafe)]

use lr_bgp::rtr::pdu::{
    decode as decode_pdu, encode as encode_pdu, RtrErrorCode, RtrPdu, RtrPduType,
    RTR_FLAG_ANNOUNCE, RTR_HEADER_LEN, RTR_PDU_MAX_LEN, RTR_VERSION_0, RTR_VERSION_1,
    RTR_VERSION_2, RTR_VERSION_MAX,
};

use crate::error::{set_last_error, LrError, LR_ERR_PANIC};
use crate::guarded;
use crate::handle::lr_bytes_t;

const LR_ERR_NULL: i32 = LrError::Null as i32;
const LR_ERR_INVALID_HANDLE: i32 = LrError::InvalidHandle as i32;
const LR_ERR_OTHER: i32 = LrError::Other as i32;

// Re-export as pub consts so cbindgen picks them up.
pub const LR_RTR_VERSION_0: u8 = RTR_VERSION_0;
pub const LR_RTR_VERSION_1: u8 = RTR_VERSION_1;
pub const LR_RTR_VERSION_2: u8 = RTR_VERSION_2;
pub const LR_RTR_VERSION_MAX: u8 = RTR_VERSION_MAX;
pub const LR_RTR_HEADER_LEN: usize = RTR_HEADER_LEN;
pub const LR_RTR_PDU_MAX_LEN: usize = RTR_PDU_MAX_LEN;
pub const LR_RTR_FLAG_ANNOUNCE: u8 = RTR_FLAG_ANNOUNCE;

/// Opaque `RtrPdu` handle. C side never touches internals.
#[repr(C)]
pub struct OpaqueRtrPdu {
    _private: [u8; 0],
}
pub type lr_rtr_pdu_t = *mut OpaqueRtrPdu;

/// Box a `RtrPdu` into an opaque handle.
fn box_pdu(p: RtrPdu) -> lr_rtr_pdu_t {
    Box::into_raw(Box::new(p)) as lr_rtr_pdu_t
}
unsafe fn unbox_pdu(p: lr_rtr_pdu_t) -> Option<Box<RtrPdu>> {
    if p.is_null() {
        return None;
    }
    Some(unsafe { Box::from_raw(p as *mut RtrPdu) })
}
unsafe fn borrow_pdu(p: lr_rtr_pdu_t) -> Option<&'static RtrPdu> {
    if p.is_null() {
        return None;
    }
    Some(unsafe { &*(p as *const RtrPdu) })
}

/// Encode `pdu` at protocol `version` and write the wire bytes to
/// `*out`. The version must satisfy `RtrPdu::min_version` — otherwise
/// the wire form would be a cache-side protocol violation and the
/// function returns `LR_ERR_OTHER`.
///
/// # Safety
/// `pdu` must be a valid handle. `out` must point to a writable
/// `lr_bytes_t`.
#[no_mangle]
pub unsafe extern "C" fn lr_rtr_pdu_encode(
    pdu: lr_rtr_pdu_t,
    version: u8,
    out: *mut lr_bytes_t,
) -> i32 {
    guarded(
        || unsafe {
            let Some(p) = borrow_pdu(pdu) else {
                return LR_ERR_NULL;
            };
            if out.is_null() {
                return LR_ERR_NULL;
            }
            if version < p.min_version() {
                set_last_error(format!(
                    "PDU {:?} requires version >= {} (got {version})",
                    p.pdu_type(),
                    p.min_version()
                ));
                return LR_ERR_OTHER;
            }
            let mut bytes = Vec::new();
            encode_pdu(p, version, &mut bytes);
            unsafe { *out = lr_bytes_t::from_vec(bytes) }
            0
        },
        LR_ERR_PANIC,
    )
}

/// Convenience encoder returning a fresh `lr_bytes_t`. Same contract
/// as [`lr_rtr_pdu_encode`].
///
/// # Safety
/// `pdu` must be a valid handle. `out` must point to a writable
/// `lr_bytes_t`.
#[no_mangle]
pub unsafe extern "C" fn lr_rtr_pdu_encode_vec(
    pdu: lr_rtr_pdu_t,
    version: u8,
    out: *mut lr_bytes_t,
) -> i32 {
    // Same body as lr_rtr_pdu_encode — kept as a separate symbol so the
    // C header documents both shapes (the `_vec` form mirrors the Rust
    // `encode_vec` standalone).
    unsafe { lr_rtr_pdu_encode(pdu, version, out) }
}

/// Decode one PDU from `data`. On success writes a freshly-allocated
/// `lr_rtr_pdu_t` to `*out_pdu`, the protocol version to `*out_version`
/// and the bytes consumed to `*out_consumed`. Returns 0 on success,
/// `LR_ERR_NULL` on a NULL pointer, `LR_ERR_OTHER` on a decode error
/// (the last-error string is set), and 1 when the buffer is
/// incomplete (more bytes needed — the caller should read more and
/// retry).
///
/// # Safety
/// `data` must point to `len` readable bytes. The three out-pointers
/// must point to writable memory of the right type.
#[no_mangle]
pub unsafe extern "C" fn lr_rtr_pdu_decode(
    data: *const u8,
    len: usize,
    out_pdu: *mut lr_rtr_pdu_t,
    out_version: *mut u8,
    out_consumed: *mut usize,
) -> i32 {
    guarded(
        || unsafe {
            if data.is_null()
                || out_pdu.is_null()
                || out_version.is_null()
                || out_consumed.is_null()
            {
                return LR_ERR_NULL;
            }
            let slice = unsafe { std::slice::from_raw_parts(data, len) };
            match decode_pdu(slice) {
                Ok(Some((version, pdu, consumed))) => {
                    unsafe {
                        *out_pdu = box_pdu(pdu);
                        *out_version = version;
                        *out_consumed = consumed;
                    }
                    0
                }
                Ok(None) => {
                    // Incomplete — caller should read more.
                    1
                }
                Err(e) => {
                    set_last_error(e.to_string());
                    LR_ERR_OTHER
                }
            }
        },
        LR_ERR_PANIC,
    )
}

/// Drop a boxed `RtrPdu`. Safe to call with NULL.
///
/// # Safety
/// `pdu` must have been produced by a `lr_rtr_pdu_*` constructor and
/// must not be used after this call.
#[no_mangle]
pub unsafe extern "C" fn lr_rtr_pdu_free(pdu: lr_rtr_pdu_t) {
    guarded(
        || unsafe {
            drop(unbox_pdu(pdu));
        },
        (),
    )
}

// ---- Variant introspection ----

/// Write the PDU's RFC §5.1.2 type code to `*out`. Returns 0 on
/// success, `LR_ERR_NULL` on a NULL handle.
///
/// # Safety
/// `pdu` must be a valid handle. `out` must point to writable `uint8_t`.
#[no_mangle]
pub unsafe extern "C" fn lr_rtr_pdu_type(pdu: lr_rtr_pdu_t, out: *mut u8) -> i32 {
    guarded(
        || unsafe {
            let Some(p) = borrow_pdu(pdu) else {
                return LR_ERR_NULL;
            };
            if out.is_null() {
                return LR_ERR_NULL;
            }
            unsafe { *out = p.pdu_type() as u8 }
            0
        },
        LR_ERR_PANIC,
    )
}

/// Write the PDU's minimum required protocol version to `*out`.
///
/// # Safety
/// See [`lr_rtr_pdu_type`].
#[no_mangle]
pub unsafe extern "C" fn lr_rtr_pdu_min_version(pdu: lr_rtr_pdu_t, out: *mut u8) -> i32 {
    guarded(
        || unsafe {
            let Some(p) = borrow_pdu(pdu) else {
                return LR_ERR_NULL;
            };
            if out.is_null() {
                return LR_ERR_NULL;
            }
            unsafe { *out = p.min_version() }
            0
        },
        LR_ERR_PANIC,
    )
}

// ---- Constructors ----

/// Build a Serial Notify PDU (RFC 8210 §5.2).
#[no_mangle]
pub extern "C" fn lr_rtr_pdu_serial_notify(session_id: u16, serial: u32) -> lr_rtr_pdu_t {
    guarded(
        || box_pdu(RtrPdu::SerialNotify { session_id, serial }),
        std::ptr::null_mut(),
    )
}

/// Build a Serial Query PDU (RFC 8210 §5.3).
#[no_mangle]
pub extern "C" fn lr_rtr_pdu_serial_query(session_id: u16, serial: u32) -> lr_rtr_pdu_t {
    guarded(
        || box_pdu(RtrPdu::SerialQuery { session_id, serial }),
        std::ptr::null_mut(),
    )
}

/// Build a Reset Query PDU (RFC 8210 §5.4).
#[no_mangle]
pub extern "C" fn lr_rtr_pdu_reset_query() -> lr_rtr_pdu_t {
    guarded(|| box_pdu(RtrPdu::ResetQuery), std::ptr::null_mut())
}

/// Build a Cache Response PDU (RFC 8210 §5.5).
#[no_mangle]
pub extern "C" fn lr_rtr_pdu_cache_response(session_id: u16) -> lr_rtr_pdu_t {
    guarded(
        || box_pdu(RtrPdu::CacheResponse { session_id }),
        std::ptr::null_mut(),
    )
}

/// Build a Cache Reset PDU (RFC 8210 §5.9).
#[no_mangle]
pub extern "C" fn lr_rtr_pdu_cache_reset() -> lr_rtr_pdu_t {
    guarded(|| box_pdu(RtrPdu::CacheReset), std::ptr::null_mut())
}

/// Build an IPv4 Prefix PDU (RFC 8210 §5.6). `prefix_v4` points to 4
/// readable bytes; `prefix_len` and `max_length` are the prefix and
/// ROA max lengths. Pass `announce = 1` for an announcement, `0` for
/// a withdrawal.
///
/// # Safety
/// `prefix_v4` must point to 4 readable bytes (NULL only when
/// `prefix_len == 0` is desired — but the codec requires a real
/// prefix, so NULL is rejected).
#[no_mangle]
pub unsafe extern "C" fn lr_rtr_pdu_ipv4_prefix(
    announce: u8,
    prefix_v4: *const u8,
    prefix_len: u8,
    max_length: u8,
    asn: u32,
) -> lr_rtr_pdu_t {
    guarded(
        || unsafe {
            if prefix_v4.is_null() {
                set_last_error("IPv4 Prefix PDU: prefix_v4 is NULL".into());
                return std::ptr::null_mut();
            }
            let mut octets = [0u8; 4];
            unsafe {
                octets.copy_from_slice(std::slice::from_raw_parts(prefix_v4, 4));
            }
            let prefix = lr_core::addr::Prefix::new_v4(octets, prefix_len);
            box_pdu(RtrPdu::Ipv4Prefix {
                announce: announce != 0,
                prefix,
                max_length,
                asn,
            })
        },
        std::ptr::null_mut(),
    )
}

/// Build an IPv6 Prefix PDU (RFC 8210 §5.7). `prefix_v6` points to 16
/// readable bytes.
///
/// # Safety
/// `prefix_v6` must point to 16 readable bytes.
#[no_mangle]
pub unsafe extern "C" fn lr_rtr_pdu_ipv6_prefix(
    announce: u8,
    prefix_v6: *const u8,
    prefix_len: u8,
    max_length: u8,
    asn: u32,
) -> lr_rtr_pdu_t {
    guarded(
        || unsafe {
            if prefix_v6.is_null() {
                set_last_error("IPv6 Prefix PDU: prefix_v6 is NULL".into());
                return std::ptr::null_mut();
            }
            let mut octets = [0u8; 16];
            unsafe {
                octets.copy_from_slice(std::slice::from_raw_parts(prefix_v6, 16));
            }
            let prefix = lr_core::addr::Prefix::new_v6(octets, prefix_len);
            box_pdu(RtrPdu::Ipv6Prefix {
                announce: announce != 0,
                prefix,
                max_length,
                asn,
            })
        },
        std::ptr::null_mut(),
    )
}

/// Build an End-of-Data PDU (RFC 8210 §5.8). The timing intervals are
/// optional per §5.8 — pass 0 to omit (the v0 wire form omits them;
/// v1+ always carries them and 0 means "use the configured default").
#[no_mangle]
pub extern "C" fn lr_rtr_pdu_end_of_data(
    session_id: u16,
    serial: u32,
    refresh_interval: u32,
    retry_interval: u32,
    expire_interval: u32,
) -> lr_rtr_pdu_t {
    guarded(
        || {
            let (r, rt, e) = if refresh_interval == 0 && retry_interval == 0 && expire_interval == 0
            {
                (None, None, None)
            } else {
                (
                    Some(refresh_interval),
                    Some(retry_interval),
                    Some(expire_interval),
                )
            };
            box_pdu(RtrPdu::EndOfData {
                session_id,
                serial,
                refresh_interval: r,
                retry_interval: rt,
                expire_interval: e,
            })
        },
        std::ptr::null_mut(),
    )
}

/// Build a Router Key PDU (RFC 8210 §5.10, v1+). `ski` points to 20
/// readable bytes; `spki` points to `spki_len` readable bytes (the
/// full DER subjectPublicKeyInfo).
///
/// # Safety
/// `ski` must point to 20 readable bytes; `spki` must point to
/// `spki_len` readable bytes (NULL only when `spki_len == 0`).
#[no_mangle]
pub unsafe extern "C" fn lr_rtr_pdu_router_key(
    announce: u8,
    ski: *const u8,
    asn: u32,
    spki: *const u8,
    spki_len: usize,
) -> lr_rtr_pdu_t {
    guarded(
        || unsafe {
            if ski.is_null() {
                set_last_error("Router Key PDU: ski is NULL".into());
                return std::ptr::null_mut();
            }
            let mut ski_arr = [0u8; 20];
            unsafe {
                ski_arr.copy_from_slice(std::slice::from_raw_parts(ski, 20));
            }
            let spki_vec = if spki.is_null() || spki_len == 0 {
                Vec::new()
            } else {
                unsafe { std::slice::from_raw_parts(spki, spki_len).to_vec() }
            };
            box_pdu(RtrPdu::RouterKey {
                announce: announce != 0,
                ski: ski_arr,
                asn,
                subject_public_key_info: spki_vec,
            })
        },
        std::ptr::null_mut(),
    )
}

/// Build an Error Report PDU (RFC 8210 §5.11). `erroneous_pdu` points
/// to `erroneous_pdu_len` readable bytes (NULL when `len == 0`);
/// `error_text` is a NUL-terminated UTF-8 string (NULL when absent).
///
/// # Safety
/// `erroneous_pdu` must point to `erroneous_pdu_len` readable bytes
/// (NULL only when `erroneous_pdu_len == 0`). `error_text` must be a
/// NUL-terminated UTF-8 string or NULL.
#[no_mangle]
pub unsafe extern "C" fn lr_rtr_pdu_error_report(
    error_code: u16,
    erroneous_pdu: *const u8,
    erroneous_pdu_len: usize,
    error_text: *const std::os::raw::c_char,
) -> lr_rtr_pdu_t {
    guarded(
        || unsafe {
            let Some(code) = RtrErrorCode::from_u16(error_code) else {
                set_last_error(format!("unknown RTR error code {error_code}"));
                return std::ptr::null_mut();
            };
            let pdu_bytes = if erroneous_pdu.is_null() || erroneous_pdu_len == 0 {
                Vec::new()
            } else {
                unsafe { std::slice::from_raw_parts(erroneous_pdu, erroneous_pdu_len).to_vec() }
            };
            let text = if error_text.is_null() {
                None
            } else {
                match unsafe { std::ffi::CStr::from_ptr(error_text) }.to_str() {
                    Ok(s) => Some(s.to_string()),
                    Err(_) => {
                        set_last_error("Error Report PDU: error_text is not valid UTF-8".into());
                        return std::ptr::null_mut();
                    }
                }
            };
            box_pdu(RtrPdu::ErrorReport {
                error_code: code,
                erroneous_pdu: pdu_bytes,
                error_text: text,
            })
        },
        std::ptr::null_mut(),
    )
}

/// Build an ASPA PDU (v2+, SIDROPS ASPA profile). `providers` points
/// to `providers_count` readable `uint32_t` values.
///
/// # Safety
/// `providers` must point to `providers_count` readable `uint32_t`
/// values (NULL only when `providers_count == 0`).
#[no_mangle]
pub unsafe extern "C" fn lr_rtr_pdu_aspa(
    announce: u8,
    customer_asn: u32,
    providers: *const u32,
    providers_count: usize,
) -> lr_rtr_pdu_t {
    guarded(
        || unsafe {
            let providers_vec = if providers.is_null() || providers_count == 0 {
                Vec::new()
            } else {
                unsafe { std::slice::from_raw_parts(providers, providers_count).to_vec() }
            };
            box_pdu(RtrPdu::Aspa {
                announce: announce != 0,
                customer_asn,
                providers: providers_vec,
            })
        },
        std::ptr::null_mut(),
    )
}

// ---- Per-variant accessors ----

/// Read the session_id of a Serial Notify / Serial Query / Cache
/// Response / End-of-Data PDU. Returns 0 on a NULL handle or a
/// non-matching variant (the caller can check the type first via
/// [`lr_rtr_pdu_type`]).
///
/// # Safety
/// `pdu` must be a valid handle. `out` must point to writable `uint16_t`.
#[no_mangle]
pub unsafe extern "C" fn lr_rtr_pdu_session_id(pdu: lr_rtr_pdu_t, out: *mut u16) -> i32 {
    guarded(
        || unsafe {
            let Some(p) = borrow_pdu(pdu) else {
                return LR_ERR_NULL;
            };
            if out.is_null() {
                return LR_ERR_NULL;
            }
            let sid = match p {
                RtrPdu::SerialNotify { session_id, .. }
                | RtrPdu::SerialQuery { session_id, .. }
                | RtrPdu::CacheResponse { session_id }
                | RtrPdu::EndOfData { session_id, .. } => *session_id,
                _ => {
                    set_last_error(format!(
                        "session_id not applicable to PDU type {:?}",
                        p.pdu_type()
                    ));
                    return LR_ERR_INVALID_HANDLE;
                }
            };
            unsafe { *out = sid }
            0
        },
        LR_ERR_PANIC,
    )
}

/// Read the serial number of a Serial Notify / Serial Query / End-of-
/// Data PDU.
///
/// # Safety
/// See [`lr_rtr_pdu_session_id`].
#[no_mangle]
pub unsafe extern "C" fn lr_rtr_pdu_serial(pdu: lr_rtr_pdu_t, out: *mut u32) -> i32 {
    guarded(
        || unsafe {
            let Some(p) = borrow_pdu(pdu) else {
                return LR_ERR_NULL;
            };
            if out.is_null() {
                return LR_ERR_NULL;
            }
            let serial = match p {
                RtrPdu::SerialNotify { serial, .. }
                | RtrPdu::SerialQuery { serial, .. }
                | RtrPdu::EndOfData { serial, .. } => *serial,
                _ => {
                    set_last_error(format!(
                        "serial not applicable to PDU type {:?}",
                        p.pdu_type()
                    ));
                    return LR_ERR_INVALID_HANDLE;
                }
            };
            unsafe { *out = serial }
            0
        },
        LR_ERR_PANIC,
    )
}

/// Read the announce flag of an IPv4 Prefix / IPv6 Prefix / Router
/// Key / ASPA PDU. Writes 1 for announcement, 0 for withdrawal.
///
/// # Safety
/// See [`lr_rtr_pdu_session_id`].
#[no_mangle]
pub unsafe extern "C" fn lr_rtr_pdu_announce(pdu: lr_rtr_pdu_t, out: *mut u8) -> i32 {
    guarded(
        || unsafe {
            let Some(p) = borrow_pdu(pdu) else {
                return LR_ERR_NULL;
            };
            if out.is_null() {
                return LR_ERR_NULL;
            }
            let announce = match p {
                RtrPdu::Ipv4Prefix { announce, .. }
                | RtrPdu::Ipv6Prefix { announce, .. }
                | RtrPdu::RouterKey { announce, .. }
                | RtrPdu::Aspa { announce, .. } => *announce,
                _ => {
                    set_last_error(format!(
                        "announce not applicable to PDU type {:?}",
                        p.pdu_type()
                    ));
                    return LR_ERR_INVALID_HANDLE;
                }
            };
            unsafe { *out = announce as u8 }
            0
        },
        LR_ERR_PANIC,
    )
}

/// Read the prefix of an IPv4 Prefix PDU. Writes 4 bytes of prefix
/// address to `out_prefix_v4` and the prefix length to
/// `*out_prefix_len`.
///
/// # Safety
/// `out_prefix_v4` must point to 4 writable bytes; `out_prefix_len`
/// must point to a writable `uint8_t`.
#[no_mangle]
pub unsafe extern "C" fn lr_rtr_pdu_ipv4_prefix_fields(
    pdu: lr_rtr_pdu_t,
    out_prefix_v4: *mut u8,
    out_prefix_len: *mut u8,
    out_max_length: *mut u8,
    out_asn: *mut u32,
) -> i32 {
    guarded(
        || unsafe {
            let Some(p) = borrow_pdu(pdu) else {
                return LR_ERR_NULL;
            };
            if out_prefix_v4.is_null()
                || out_prefix_len.is_null()
                || out_max_length.is_null()
                || out_asn.is_null()
            {
                return LR_ERR_NULL;
            }
            match p {
                RtrPdu::Ipv4Prefix {
                    prefix,
                    max_length,
                    asn,
                    ..
                } => {
                    let lr_core::addr::IpAddr::V4(octets) = prefix.addr else {
                        set_last_error("IPv4 Prefix PDU carries a non-v4 prefix".into());
                        return LR_ERR_INVALID_HANDLE;
                    };
                    unsafe {
                        std::ptr::copy_nonoverlapping(octets.as_ptr(), out_prefix_v4, 4);
                        *out_prefix_len = prefix.prefix_len;
                        *out_max_length = *max_length;
                        *out_asn = *asn;
                    }
                    0
                }
                _ => {
                    set_last_error(format!(
                        "ipv4_prefix_fields not applicable to PDU type {:?}",
                        p.pdu_type()
                    ));
                    LR_ERR_INVALID_HANDLE
                }
            }
        },
        LR_ERR_PANIC,
    )
}

/// Read the prefix of an IPv6 Prefix PDU. Writes 16 bytes of prefix
/// address to `out_prefix_v6`.
///
/// # Safety
/// `out_prefix_v6` must point to 16 writable bytes; the other three
/// out-pointers must point to writable memory of the right type.
#[no_mangle]
pub unsafe extern "C" fn lr_rtr_pdu_ipv6_prefix_fields(
    pdu: lr_rtr_pdu_t,
    out_prefix_v6: *mut u8,
    out_prefix_len: *mut u8,
    out_max_length: *mut u8,
    out_asn: *mut u32,
) -> i32 {
    guarded(
        || unsafe {
            let Some(p) = borrow_pdu(pdu) else {
                return LR_ERR_NULL;
            };
            if out_prefix_v6.is_null()
                || out_prefix_len.is_null()
                || out_max_length.is_null()
                || out_asn.is_null()
            {
                return LR_ERR_NULL;
            }
            match p {
                RtrPdu::Ipv6Prefix {
                    prefix,
                    max_length,
                    asn,
                    ..
                } => {
                    let lr_core::addr::IpAddr::V6(octets) = prefix.addr else {
                        set_last_error("IPv6 Prefix PDU carries a non-v6 prefix".into());
                        return LR_ERR_INVALID_HANDLE;
                    };
                    unsafe {
                        std::ptr::copy_nonoverlapping(octets.as_ptr(), out_prefix_v6, 16);
                        *out_prefix_len = prefix.prefix_len;
                        *out_max_length = *max_length;
                        *out_asn = *asn;
                    }
                    0
                }
                _ => {
                    set_last_error(format!(
                        "ipv6_prefix_fields not applicable to PDU type {:?}",
                        p.pdu_type()
                    ));
                    LR_ERR_INVALID_HANDLE
                }
            }
        },
        LR_ERR_PANIC,
    )
}

/// Read the End-of-Data timing intervals. Writes 1 to
/// `*out_present` when the intervals are present (v1+), 0 when
/// absent (v0). When present, the three interval values are written
/// to the matching out-pointers; when absent the out-pointers are
/// left untouched.
///
/// # Safety
/// All four out-pointers must point to writable memory of the right
/// type.
#[no_mangle]
pub unsafe extern "C" fn lr_rtr_pdu_end_of_data_intervals(
    pdu: lr_rtr_pdu_t,
    out_present: *mut u8,
    out_refresh: *mut u32,
    out_retry: *mut u32,
    out_expire: *mut u32,
) -> i32 {
    guarded(
        || unsafe {
            let Some(p) = borrow_pdu(pdu) else {
                return LR_ERR_NULL;
            };
            if out_present.is_null()
                || out_refresh.is_null()
                || out_retry.is_null()
                || out_expire.is_null()
            {
                return LR_ERR_NULL;
            }
            match p {
                RtrPdu::EndOfData {
                    refresh_interval,
                    retry_interval,
                    expire_interval,
                    ..
                } => {
                    let (present, r, rt, e) =
                        match (refresh_interval, retry_interval, expire_interval) {
                            (Some(r), Some(rt), Some(e)) => (1u8, *r, *rt, *e),
                            (None, None, None) => (0u8, 0, 0, 0),
                            _ => {
                                set_last_error(
                                    "End-of-Data PDU: partial intervals are invalid".into(),
                                );
                                return LR_ERR_INVALID_HANDLE;
                            }
                        };
                    unsafe {
                        *out_present = present;
                        if present != 0 {
                            *out_refresh = r;
                            *out_retry = rt;
                            *out_expire = e;
                        }
                    }
                    0
                }
                _ => {
                    set_last_error(format!(
                        "end_of_data_intervals not applicable to PDU type {:?}",
                        p.pdu_type()
                    ));
                    LR_ERR_INVALID_HANDLE
                }
            }
        },
        LR_ERR_PANIC,
    )
}

/// Read the Router Key PDU's SKI (20 bytes) and ASN. `out_ski` must
/// point to 20 writable bytes.
///
/// # Safety
/// `out_ski` must point to 20 writable bytes; `out_asn` must point
/// to a writable `uint32_t`. The SPKI bytes are returned via
/// `out_spki` as a `lr_bytes_t` (caller frees with `lr_bytes_free`).
#[no_mangle]
pub unsafe extern "C" fn lr_rtr_pdu_router_key_fields(
    pdu: lr_rtr_pdu_t,
    out_ski: *mut u8,
    out_asn: *mut u32,
    out_spki: *mut lr_bytes_t,
) -> i32 {
    guarded(
        || unsafe {
            let Some(p) = borrow_pdu(pdu) else {
                return LR_ERR_NULL;
            };
            if out_ski.is_null() || out_asn.is_null() || out_spki.is_null() {
                return LR_ERR_NULL;
            }
            match p {
                RtrPdu::RouterKey {
                    ski,
                    asn,
                    subject_public_key_info,
                    ..
                } => {
                    unsafe {
                        std::ptr::copy_nonoverlapping(ski.as_ptr(), out_ski, 20);
                        *out_asn = *asn;
                        *out_spki = lr_bytes_t::from_vec(subject_public_key_info.clone());
                    }
                    0
                }
                _ => {
                    set_last_error(format!(
                        "router_key_fields not applicable to PDU type {:?}",
                        p.pdu_type()
                    ));
                    LR_ERR_INVALID_HANDLE
                }
            }
        },
        LR_ERR_PANIC,
    )
}

/// Read the Error Report PDU's error code (RFC 8210 §12).
///
/// # Safety
/// `out` must point to a writable `uint16_t`.
#[no_mangle]
pub unsafe extern "C" fn lr_rtr_pdu_error_code(pdu: lr_rtr_pdu_t, out: *mut u16) -> i32 {
    guarded(
        || unsafe {
            let Some(p) = borrow_pdu(pdu) else {
                return LR_ERR_NULL;
            };
            if out.is_null() {
                return LR_ERR_NULL;
            }
            match p {
                RtrPdu::ErrorReport { error_code, .. } => {
                    unsafe { *out = *error_code as u16 }
                    0
                }
                _ => {
                    set_last_error(format!(
                        "error_code not applicable to PDU type {:?}",
                        p.pdu_type()
                    ));
                    LR_ERR_INVALID_HANDLE
                }
            }
        },
        LR_ERR_PANIC,
    )
}

/// Read the Error Report PDU's erroneous-PDU bytes (caller frees with
/// `lr_bytes_free`).
///
/// # Safety
/// `out` must point to a writable `lr_bytes_t`.
#[no_mangle]
pub unsafe extern "C" fn lr_rtr_pdu_erroneous_pdu(pdu: lr_rtr_pdu_t, out: *mut lr_bytes_t) -> i32 {
    guarded(
        || unsafe {
            let Some(p) = borrow_pdu(pdu) else {
                return LR_ERR_NULL;
            };
            if out.is_null() {
                return LR_ERR_NULL;
            }
            match p {
                RtrPdu::ErrorReport { erroneous_pdu, .. } => {
                    unsafe { *out = lr_bytes_t::from_vec(erroneous_pdu.clone()) }
                    0
                }
                _ => {
                    set_last_error(format!(
                        "erroneous_pdu not applicable to PDU type {:?}",
                        p.pdu_type()
                    ));
                    LR_ERR_INVALID_HANDLE
                }
            }
        },
        LR_ERR_PANIC,
    )
}

/// Read the Error Report PDU's error text. Writes a freshly-allocated
/// `lr_bytes_t` to `*out` carrying the UTF-8 text (without trailing
/// NUL) when present, or sets `out->ptr = NULL` when absent.
///
/// # Safety
/// `out` must point to a writable `lr_bytes_t`.
#[no_mangle]
pub unsafe extern "C" fn lr_rtr_pdu_error_text(pdu: lr_rtr_pdu_t, out: *mut lr_bytes_t) -> i32 {
    guarded(
        || unsafe {
            let Some(p) = borrow_pdu(pdu) else {
                return LR_ERR_NULL;
            };
            if out.is_null() {
                return LR_ERR_NULL;
            }
            match p {
                RtrPdu::ErrorReport { error_text, .. } => {
                    let bytes = match error_text {
                        Some(s) => s.clone().into_bytes(),
                        None => Vec::new(),
                    };
                    unsafe { *out = lr_bytes_t::from_vec(bytes) }
                    0
                }
                _ => {
                    set_last_error(format!(
                        "error_text not applicable to PDU type {:?}",
                        p.pdu_type()
                    ));
                    LR_ERR_INVALID_HANDLE
                }
            }
        },
        LR_ERR_PANIC,
    )
}

/// Read the ASPA PDU's customer ASN.
///
/// # Safety
/// `out` must point to a writable `uint32_t`.
#[no_mangle]
pub unsafe extern "C" fn lr_rtr_pdu_customer_asn(pdu: lr_rtr_pdu_t, out: *mut u32) -> i32 {
    guarded(
        || unsafe {
            let Some(p) = borrow_pdu(pdu) else {
                return LR_ERR_NULL;
            };
            if out.is_null() {
                return LR_ERR_NULL;
            }
            match p {
                RtrPdu::Aspa { customer_asn, .. } => {
                    unsafe { *out = *customer_asn }
                    0
                }
                _ => {
                    set_last_error(format!(
                        "customer_asn not applicable to PDU type {:?}",
                        p.pdu_type()
                    ));
                    LR_ERR_INVALID_HANDLE
                }
            }
        },
        LR_ERR_PANIC,
    )
}

/// Read the ASPA PDU's provider ASNs as a flat `uint32_t` array
/// (caller-supplied buffer). Writes the count to `*out_count` and
/// returns 0 on success. If the buffer is too small, writes the
/// required count to `*out_count` and returns `LR_ERR_OTHER` (the
/// last-error string is set).
///
/// # Safety
/// `out_providers` must point to `cap` writable `uint32_t` values
/// (NULL is allowed only when `cap == 0`, in which case the function
/// only reports the count). `out_count` must point to a writable
/// `uintptr_t`.
#[no_mangle]
pub unsafe extern "C" fn lr_rtr_pdu_providers(
    pdu: lr_rtr_pdu_t,
    out_providers: *mut u32,
    cap: usize,
    out_count: *mut usize,
) -> i32 {
    guarded(
        || unsafe {
            let Some(p) = borrow_pdu(pdu) else {
                return LR_ERR_NULL;
            };
            if out_count.is_null() {
                return LR_ERR_NULL;
            }
            match p {
                RtrPdu::Aspa { providers, .. } => {
                    let n = providers.len();
                    unsafe { *out_count = n }
                    if n > cap {
                        set_last_error(format!("providers buffer too small: need {n}, have {cap}"));
                        return LR_ERR_OTHER;
                    }
                    if !out_providers.is_null() && n > 0 {
                        unsafe {
                            std::ptr::copy_nonoverlapping(providers.as_ptr(), out_providers, n);
                        }
                    }
                    0
                }
                _ => {
                    set_last_error(format!(
                        "providers not applicable to PDU type {:?}",
                        p.pdu_type()
                    ));
                    LR_ERR_INVALID_HANDLE
                }
            }
        },
        LR_ERR_PANIC,
    )
}

// ---- RtrPduType + RtrErrorCode introspection ----

/// Write the BIRD-style display name for PDU type `ty` to
/// `*out_name`. The pointer is valid until the next FFI call on this
/// thread. Returns 0 on success, `LR_ERR_NULL` on a NULL out-pointer,
/// `LR_ERR_INVALID_HANDLE` when `ty` is not a known type code.
///
/// # Safety
/// `out_name` must point to a writable `const char*`.
#[no_mangle]
pub unsafe extern "C" fn lr_rtr_pdu_type_name(
    ty: u8,
    out_name: *mut *const std::os::raw::c_char,
) -> i32 {
    guarded(
        || unsafe {
            if out_name.is_null() {
                return LR_ERR_NULL;
            }
            let Some(t) = RtrPduType::from_u8(ty) else {
                set_last_error(format!("unknown RTR PDU type {ty}"));
                return LR_ERR_INVALID_HANDLE;
            };
            // Copy the &'static str into a NUL-terminated thread-local
            // buffer so the returned pointer is C-string compatible.
            thread_local! {
                static BUF: std::cell::RefCell<Vec<u8>> = const { std::cell::RefCell::new(Vec::new()) };
            }
            BUF.with(|b| {
                let mut b = b.borrow_mut();
                b.clear();
                b.extend_from_slice(t.name().as_bytes());
                b.push(0);
                unsafe {
                    *out_name = b.as_ptr() as *const std::os::raw::c_char;
                }
            });
            0
        },
        LR_ERR_PANIC,
    )
}

/// Write the minimum PDU length for type `ty` to `*out`. Returns 0 on
/// success, `LR_ERR_INVALID_HANDLE` when `ty` is unknown.
///
/// # Safety
/// `out` must point to a writable `uintptr_t`.
#[no_mangle]
pub unsafe extern "C" fn lr_rtr_pdu_type_min_len(ty: u8, out: *mut usize) -> i32 {
    guarded(
        || unsafe {
            if out.is_null() {
                return LR_ERR_NULL;
            }
            let Some(t) = RtrPduType::from_u8(ty) else {
                set_last_error(format!("unknown RTR PDU type {ty}"));
                return LR_ERR_INVALID_HANDLE;
            };
            unsafe { *out = t.min_len() }
            0
        },
        LR_ERR_PANIC,
    )
}

/// Convert a wire type byte to the canonical RtrPduType tag, or
/// return `LR_ERR_INVALID_HANDLE` when the type is unknown. Writes
/// the type code back to `*out` (so a caller passing a reserved type
/// like 5 still gets the same byte back, but the call errors).
///
/// Useful for a C consumer that wants to validate the type before
/// dispatching on it.
///
/// # Safety
/// `out` must point to a writable `uint8_t`.
#[no_mangle]
pub unsafe extern "C" fn lr_rtr_pdu_type_from_u8(ty: u8, out: *mut u8) -> i32 {
    guarded(
        || unsafe {
            if out.is_null() {
                return LR_ERR_NULL;
            }
            if RtrPduType::from_u8(ty).is_some() {
                unsafe { *out = ty }
                0
            } else {
                set_last_error(format!("unknown RTR PDU type {ty}"));
                LR_ERR_INVALID_HANDLE
            }
        },
        LR_ERR_PANIC,
    )
}

/// Write the BIRD-style diagnostic name for error code `code` to
/// `*out_name`. The pointer is valid until the next FFI call on this
/// thread. Returns 0 on success, `LR_ERR_INVALID_HANDLE` when `code`
/// is unknown.
///
/// # Safety
/// `out_name` must point to a writable `const char*`.
#[no_mangle]
pub unsafe extern "C" fn lr_rtr_error_code_name(
    code: u16,
    out_name: *mut *const std::os::raw::c_char,
) -> i32 {
    guarded(
        || unsafe {
            if out_name.is_null() {
                return LR_ERR_NULL;
            }
            let Some(c) = RtrErrorCode::from_u16(code) else {
                set_last_error(format!("unknown RTR error code {code}"));
                return LR_ERR_INVALID_HANDLE;
            };
            thread_local! {
                static BUF: std::cell::RefCell<Vec<u8>> = const { std::cell::RefCell::new(Vec::new()) };
            }
            BUF.with(|b| {
                let mut b = b.borrow_mut();
                b.clear();
                b.extend_from_slice(c.name().as_bytes());
                b.push(0);
                unsafe {
                    *out_name = b.as_ptr() as *const std::os::raw::c_char;
                }
            });
            0
        },
        LR_ERR_PANIC,
    )
}

/// Write 1 to `*out` when `code` is a fatal error (everything except
/// No Data Available per RFC §12), 0 otherwise.
///
/// # Safety
/// `out` must point to a writable `uint8_t`.
#[no_mangle]
pub unsafe extern "C" fn lr_rtr_error_code_is_fatal(code: u16, out: *mut u8) -> i32 {
    guarded(
        || unsafe {
            if out.is_null() {
                return LR_ERR_NULL;
            }
            let Some(c) = RtrErrorCode::from_u16(code) else {
                set_last_error(format!("unknown RTR error code {code}"));
                return LR_ERR_INVALID_HANDLE;
            };
            unsafe { *out = c.is_fatal() as u8 }
            0
        },
        LR_ERR_PANIC,
    )
}

/// Validate that `code` is a known RTR error code. Returns 0 on
/// success, `LR_ERR_INVALID_HANDLE` when unknown.
#[no_mangle]
pub extern "C" fn lr_rtr_error_code_from_u16(code: u16) -> i32 {
    guarded(
        || {
            if RtrErrorCode::from_u16(code).is_some() {
                0
            } else {
                set_last_error(format!("unknown RTR error code {code}"));
                LR_ERR_INVALID_HANDLE
            }
        },
        LR_ERR_PANIC,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    unsafe fn bytes_to_vec(b: &mut lr_bytes_t) -> Vec<u8> {
        if b.ptr.is_null() {
            return Vec::new();
        }
        let v = unsafe { Vec::from_raw_parts(b.ptr, b.len, b.cap) };
        b.ptr = std::ptr::null_mut();
        b.len = 0;
        b.cap = 0;
        v
    }

    #[test]
    fn ffi_rtr_pdu_serial_notify_roundtrip() {
        let pdu = lr_rtr_pdu_serial_notify(0x1234, 42);
        assert!(!pdu.is_null());

        let mut out = lr_bytes_t {
            ptr: std::ptr::null_mut(),
            len: 0,
            cap: 0,
        };
        let rc = unsafe { lr_rtr_pdu_encode(pdu, LR_RTR_VERSION_0, &raw mut out) };
        assert_eq!(rc, 0);
        let bytes = unsafe { bytes_to_vec(&mut out) };
        // Serial Notify PDU is 12 bytes: header(8) + session_id(2) + serial(4)
        // minus 2 because session_id is in the header's flags_or_session_id field.
        // Actually total length is 12 = 8 (header) + 4 (serial).
        assert_eq!(bytes.len(), 12);
        assert_eq!(bytes[0], LR_RTR_VERSION_0); // version
        assert_eq!(bytes[1], 0); // type = Serial Notify

        // Decode it back.
        let mut decoded: lr_rtr_pdu_t = std::ptr::null_mut();
        let mut version = 0u8;
        let mut consumed = 0usize;
        let rc = unsafe {
            lr_rtr_pdu_decode(
                bytes.as_ptr(),
                bytes.len(),
                &raw mut decoded,
                &raw mut version,
                &raw mut consumed,
            )
        };
        assert_eq!(rc, 0);
        assert!(!decoded.is_null());
        assert_eq!(version, LR_RTR_VERSION_0);
        assert_eq!(consumed, 12);

        // Verify the type.
        let mut ty = 0u8;
        let rc = unsafe { lr_rtr_pdu_type(decoded, &raw mut ty) };
        assert_eq!(rc, 0);
        assert_eq!(ty, 0); // Serial Notify

        // Verify the session_id.
        let mut sid = 0u16;
        let rc = unsafe { lr_rtr_pdu_session_id(decoded, &raw mut sid) };
        assert_eq!(rc, 0);
        assert_eq!(sid, 0x1234);

        // Verify the serial.
        let mut serial = 0u32;
        let rc = unsafe { lr_rtr_pdu_serial(decoded, &raw mut serial) };
        assert_eq!(rc, 0);
        assert_eq!(serial, 42);

        unsafe { lr_rtr_pdu_free(pdu) };
        unsafe { lr_rtr_pdu_free(decoded) };
    }

    #[test]
    fn ffi_rtr_pdu_ipv4_prefix_roundtrip() {
        let prefix_bytes: [u8; 4] = [203, 0, 113, 0];
        let pdu = unsafe { lr_rtr_pdu_ipv4_prefix(1, prefix_bytes.as_ptr(), 24, 24, 65001) };
        assert!(!pdu.is_null());

        let mut out = lr_bytes_t {
            ptr: std::ptr::null_mut(),
            len: 0,
            cap: 0,
        };
        let rc = unsafe { lr_rtr_pdu_encode(pdu, LR_RTR_VERSION_0, &raw mut out) };
        assert_eq!(rc, 0);
        let bytes = unsafe { bytes_to_vec(&mut out) };
        // IPv4 Prefix PDU is 20 bytes.
        assert_eq!(bytes.len(), 20);

        let mut decoded: lr_rtr_pdu_t = std::ptr::null_mut();
        let mut version = 0u8;
        let mut consumed = 0usize;
        let rc = unsafe {
            lr_rtr_pdu_decode(
                bytes.as_ptr(),
                bytes.len(),
                &raw mut decoded,
                &raw mut version,
                &raw mut consumed,
            )
        };
        assert_eq!(rc, 0);
        assert_eq!(consumed, 20);

        // Read back the announce flag.
        let mut announce = 0u8;
        let rc = unsafe { lr_rtr_pdu_announce(decoded, &raw mut announce) };
        assert_eq!(rc, 0);
        assert_eq!(announce, 1);

        // Read back the prefix fields.
        let mut prefix = [0u8; 4];
        let mut plen = 0u8;
        let mut maxlen = 0u8;
        let mut asn = 0u32;
        let rc = unsafe {
            lr_rtr_pdu_ipv4_prefix_fields(
                decoded,
                prefix.as_mut_ptr(),
                &raw mut plen,
                &raw mut maxlen,
                &raw mut asn,
            )
        };
        assert_eq!(rc, 0);
        assert_eq!(prefix, prefix_bytes);
        assert_eq!(plen, 24);
        assert_eq!(maxlen, 24);
        assert_eq!(asn, 65001);

        unsafe { lr_rtr_pdu_free(pdu) };
        unsafe { lr_rtr_pdu_free(decoded) };
    }

    #[test]
    fn ffi_rtr_pdu_end_of_data_with_intervals() {
        let pdu = lr_rtr_pdu_end_of_data(0xabcd, 99, 3600, 600, 7200);
        let mut out = lr_bytes_t {
            ptr: std::ptr::null_mut(),
            len: 0,
            cap: 0,
        };
        let rc = unsafe { lr_rtr_pdu_encode(pdu, LR_RTR_VERSION_1, &raw mut out) };
        assert_eq!(rc, 0);
        let bytes = unsafe { bytes_to_vec(&mut out) };
        // v1+ End-of-Data is 24 bytes (header + serial + 3 intervals).
        assert_eq!(bytes.len(), 24);

        // Decode and verify intervals.
        let mut decoded: lr_rtr_pdu_t = std::ptr::null_mut();
        let mut version = 0u8;
        let mut consumed = 0usize;
        let rc = unsafe {
            lr_rtr_pdu_decode(
                bytes.as_ptr(),
                bytes.len(),
                &raw mut decoded,
                &raw mut version,
                &raw mut consumed,
            )
        };
        assert_eq!(rc, 0);
        assert_eq!(version, LR_RTR_VERSION_1);

        let mut present = 0u8;
        let mut refresh = 0u32;
        let mut retry = 0u32;
        let mut expire = 0u32;
        let rc = unsafe {
            lr_rtr_pdu_end_of_data_intervals(
                decoded,
                &raw mut present,
                &raw mut refresh,
                &raw mut retry,
                &raw mut expire,
            )
        };
        assert_eq!(rc, 0);
        assert_eq!(present, 1);
        assert_eq!(refresh, 3600);
        assert_eq!(retry, 600);
        assert_eq!(expire, 7200);

        unsafe { lr_rtr_pdu_free(pdu) };
        unsafe { lr_rtr_pdu_free(decoded) };
    }

    #[test]
    fn ffi_rtr_pdu_aspa_roundtrip() {
        let providers: [u32; 3] = [64512, 64513, 64514];
        let pdu = unsafe { lr_rtr_pdu_aspa(1, 64500, providers.as_ptr(), providers.len()) };
        assert!(!pdu.is_null());

        let mut out = lr_bytes_t {
            ptr: std::ptr::null_mut(),
            len: 0,
            cap: 0,
        };
        let rc = unsafe { lr_rtr_pdu_encode(pdu, LR_RTR_VERSION_2, &raw mut out) };
        assert_eq!(rc, 0);
        let bytes = unsafe { bytes_to_vec(&mut out) };
        // ASPA PDU: 8 (header) + 4 (customer ASN) + 3*4 (providers) = 24 bytes.
        assert_eq!(bytes.len(), 24);

        let mut decoded: lr_rtr_pdu_t = std::ptr::null_mut();
        let mut version = 0u8;
        let mut consumed = 0usize;
        let rc = unsafe {
            lr_rtr_pdu_decode(
                bytes.as_ptr(),
                bytes.len(),
                &raw mut decoded,
                &raw mut version,
                &raw mut consumed,
            )
        };
        assert_eq!(rc, 0);
        assert_eq!(version, LR_RTR_VERSION_2);

        let mut customer = 0u32;
        let rc = unsafe { lr_rtr_pdu_customer_asn(decoded, &raw mut customer) };
        assert_eq!(rc, 0);
        assert_eq!(customer, 64500);

        let mut count = 0usize;
        let rc = unsafe { lr_rtr_pdu_providers(decoded, std::ptr::null_mut(), 0, &raw mut count) };
        assert_eq!(rc, LR_ERR_OTHER); // buffer too small
        assert_eq!(count, 3);

        let mut buf = [0u32; 3];
        let rc = unsafe { lr_rtr_pdu_providers(decoded, buf.as_mut_ptr(), 3, &raw mut count) };
        assert_eq!(rc, 0);
        assert_eq!(buf, providers);

        unsafe { lr_rtr_pdu_free(pdu) };
        unsafe { lr_rtr_pdu_free(decoded) };
    }

    #[test]
    fn ffi_rtr_pdu_type_name_and_min_len() {
        let mut name_ptr: *const std::os::raw::c_char = std::ptr::null();
        let rc = unsafe { lr_rtr_pdu_type_name(0, &raw mut name_ptr) };
        assert_eq!(rc, 0);
        let name = unsafe { std::ffi::CStr::from_ptr(name_ptr) }
            .to_str()
            .unwrap();
        assert_eq!(name, "Serial Notify");

        let mut min_len = 0usize;
        let rc = unsafe { lr_rtr_pdu_type_min_len(0, &raw mut min_len) };
        assert_eq!(rc, 0);
        assert_eq!(min_len, 12);

        // Unknown type code returns InvalidHandle.
        let rc = unsafe { lr_rtr_pdu_type_name(99, &raw mut name_ptr) };
        assert_eq!(rc, LR_ERR_INVALID_HANDLE);
    }

    #[test]
    fn ffi_rtr_error_code_name_and_is_fatal() {
        let mut name_ptr: *const std::os::raw::c_char = std::ptr::null();
        let rc = unsafe { lr_rtr_error_code_name(0, &raw mut name_ptr) };
        assert_eq!(rc, 0);
        let name = unsafe { std::ffi::CStr::from_ptr(name_ptr) }
            .to_str()
            .unwrap();
        assert_eq!(name, "Corrupt Data");

        let mut fatal = 0u8;
        let rc = unsafe { lr_rtr_error_code_is_fatal(0, &raw mut fatal) };
        assert_eq!(rc, 0);
        assert_eq!(fatal, 1); // Corrupt Data is fatal.

        // No Data Available is the documented non-fatal exception.
        let rc = unsafe { lr_rtr_error_code_is_fatal(2, &raw mut fatal) };
        assert_eq!(rc, 0);
        assert_eq!(fatal, 0);

        // Unknown code returns InvalidHandle.
        let rc = unsafe { lr_rtr_error_code_name(999, &raw mut name_ptr) };
        assert_eq!(rc, LR_ERR_INVALID_HANDLE);
    }

    #[test]
    fn ffi_rtr_pdu_encode_rejects_version_below_min() {
        // ASPA requires v2; encoding at v0 must fail.
        let pdu = unsafe { lr_rtr_pdu_aspa(1, 64500, std::ptr::null(), 0) };
        let mut out = lr_bytes_t {
            ptr: std::ptr::null_mut(),
            len: 0,
            cap: 0,
        };
        let rc = unsafe { lr_rtr_pdu_encode(pdu, LR_RTR_VERSION_0, &raw mut out) };
        assert_eq!(rc, LR_ERR_OTHER);
        unsafe { lr_rtr_pdu_free(pdu) };
    }

    #[test]
    fn ffi_rtr_pdu_free_handles_null() {
        unsafe { lr_rtr_pdu_free(std::ptr::null_mut()) };
    }

    #[test]
    fn ffi_rtr_pdu_decode_incomplete_returns_one() {
        // 4 bytes is below the 8-byte header → incomplete.
        let bytes = [0u8; 4];
        let mut pdu: lr_rtr_pdu_t = std::ptr::null_mut();
        let mut version = 0u8;
        let mut consumed = 0usize;
        let rc = unsafe {
            lr_rtr_pdu_decode(
                bytes.as_ptr(),
                bytes.len(),
                &raw mut pdu,
                &raw mut version,
                &raw mut consumed,
            )
        };
        assert_eq!(rc, 1); // incomplete — caller should read more.
        assert!(pdu.is_null());
    }
}
