//! LDP TLV value types — Generic Label, FEC, Status (RFC 5036 §3.4).
//!
//! Mirrors the public Rust API of `lr_ldp::tlv::{GenericLabel, Fec,
//! FecElement, StatusCode, Status}`. The PDU framing / message-level
//! codec already has FFI in `ldp.rs` (lr_ldp_decode /
//! lr_ldp_encode_hello_pdu); this module adds the structured TLV value
//! types so a C embedder can build / inspect individual TLVs.

#![allow(unused_unsafe)]
#![allow(unused_imports)]
#![allow(dead_code)]

use lr_core::addr::{IpAddr, Prefix};
use lr_ldp::tlv::{
    AddressList, ConfigSequenceNumber, DualStackCapability, Fec, FecElement, GenericLabel,
    HopCount, LabelRequestMessageId, PathVector, RawTlv, SessionParams, Status, StatusCode,
    TransportAddress,
};

use crate::error::{set_last_error, LrError, LR_ERR_PANIC};
use crate::guarded;
use crate::handle::lr_bytes_t;

const LR_ERR_NULL: i32 = LrError::Null as i32;
const LR_ERR_OTHER: i32 = LrError::Other as i32;

// ---- GenericLabel ----

/// Opaque `GenericLabel` handle.
#[repr(C)]
pub struct OpaqueLdpGenericLabel {
    _private: [u8; 0],
}
pub type lr_ldp_label_t = *mut OpaqueLdpGenericLabel;

fn box_label(l: GenericLabel) -> lr_ldp_label_t {
    Box::into_raw(Box::new(l)) as lr_ldp_label_t
}
unsafe fn borrow_label(l: lr_ldp_label_t) -> Option<&'static GenericLabel> {
    if l.is_null() {
        return None;
    }
    Some(unsafe { &*(l as *const GenericLabel) })
}

/// Construct a `GenericLabel` (RFC 5036 §3.4.2.1) from the 20-bit
/// label value.
#[no_mangle]
pub extern "C" fn lr_ldp_label_new(value: u32) -> lr_ldp_label_t {
    guarded(|| box_label(GenericLabel(value)), std::ptr::null_mut())
}

/// Read the 20-bit label value.
///
/// # Safety
/// `l` must be a valid handle.
#[no_mangle]
pub unsafe extern "C" fn lr_ldp_label_value(l: lr_ldp_label_t) -> u32 {
    guarded(|| unsafe { borrow_label(l).map(|x| x.0).unwrap_or(0) }, 0)
}

/// True when the value fits the 20-bit label field.
///
/// # Safety
/// `l` must be a valid handle.
#[no_mangle]
pub unsafe extern "C" fn lr_ldp_label_is_valid(l: lr_ldp_label_t) -> u8 {
    guarded(
        || unsafe { borrow_label(l).map(|x| x.is_valid() as u8).unwrap_or(0) },
        0,
    )
}

/// Drop a boxed `GenericLabel`. Safe to call with `NULL`.
///
/// # Safety
/// `l` must have been produced by [`lr_ldp_label_new`] and not already
/// freed.
#[no_mangle]
pub unsafe extern "C" fn lr_ldp_label_free(l: lr_ldp_label_t) {
    guarded(
        || unsafe {
            if l.is_null() {
                return;
            }
            drop(unsafe { Box::from_raw(l as *mut GenericLabel) });
        },
        (),
    )
}

/// Well-known Generic Label constants — mirror
/// `GenericLabel::*` (RFC 3032 §2.1 reserved labels).
pub const LR_LDP_LABEL_IPV4_EXPLICIT_NULL: u32 = 0;
pub const LR_LDP_LABEL_ROUTER_ALERT: u32 = 1;
pub const LR_LDP_LABEL_IPV6_EXPLICIT_NULL: u32 = 2;
pub const LR_LDP_LABEL_IMPLICIT_NULL: u32 = 3;

// ---- FEC ----

/// Opaque `Fec` handle.
#[repr(C)]
pub struct OpaqueLdpFec {
    _private: [u8; 0],
}
pub type lr_ldp_fec_t = *mut OpaqueLdpFec;

/// Construct a wildcard `Fec` (RFC 5036 §3.4.1).
#[no_mangle]
pub extern "C" fn lr_ldp_fec_new_wildcard() -> lr_ldp_fec_t {
    guarded(
        || Box::into_raw(Box::new(Fec::wildcard())) as lr_ldp_fec_t,
        std::ptr::null_mut(),
    )
}

/// Construct a single-prefix `Fec` (RFC 5036 §3.4.1).
///
/// # Safety
/// `prefix_v4` must point to 4 readable bytes when v4; `prefix_v6`
/// must point to 16 readable bytes when v6.
#[no_mangle]
pub unsafe extern "C" fn lr_ldp_fec_new_prefix(
    prefix_v4: *const u8,
    prefix_v6: *const u8,
    prefix_len: u8,
) -> lr_ldp_fec_t {
    guarded(
        || unsafe {
            let addr = if !prefix_v4.is_null() {
                let b = unsafe { std::slice::from_raw_parts(prefix_v4, 4) };
                IpAddr::V4([b[0], b[1], b[2], b[3]])
            } else if !prefix_v6.is_null() {
                let b = unsafe { std::slice::from_raw_parts(prefix_v6, 16) };
                let mut octets = [0u8; 16];
                octets.copy_from_slice(b);
                IpAddr::V6(octets)
            } else {
                set_last_error("lr_ldp_fec_new_prefix: both prefix pointers NULL".into());
                return std::ptr::null_mut();
            };
            Box::into_raw(Box::new(Fec::prefix(Prefix { addr, prefix_len }))) as lr_ldp_fec_t
        },
        std::ptr::null_mut(),
    )
}

/// True when the FEC is the wildcard element.
///
/// # Safety
/// `f` must be a valid handle.
#[no_mangle]
pub unsafe extern "C" fn lr_ldp_fec_is_wildcard(f: lr_ldp_fec_t) -> u8 {
    guarded(
        || unsafe {
            if f.is_null() {
                return 0;
            }
            let fec: &Fec = unsafe { &*(f as *const Fec) };
            fec.is_wildcard() as u8
        },
        0,
    )
}

/// Read the single prefix as `(is_ipv6, octets_out[16], prefix_len_out,
/// present_out)`. Writes 1 to `*present` when the FEC carries a single
/// prefix, 0 otherwise (wildcard or multi-element).
///
/// # Safety
/// `f` must be a valid handle; `octets_out`, `prefix_len_out` and
/// `present_out` must point to writable memory.
#[no_mangle]
pub unsafe extern "C" fn lr_ldp_fec_single_prefix(
    f: lr_ldp_fec_t,
    octets_out: *mut u8,
    prefix_len_out: *mut u8,
    present_out: *mut u8,
) -> i32 {
    guarded(
        || unsafe {
            if f.is_null()
                || octets_out.is_null()
                || prefix_len_out.is_null()
                || present_out.is_null()
            {
                return LR_ERR_NULL;
            }
            let fec: &Fec = unsafe { &*(f as *const Fec) };
            match fec.single_prefix() {
                Some(p) => {
                    let octets = match p.addr {
                        IpAddr::V4(b) => {
                            let mut buf = [0u8; 16];
                            buf[..4].copy_from_slice(&b);
                            buf
                        }
                        IpAddr::V6(b) => b,
                    };
                    unsafe {
                        std::ptr::copy_nonoverlapping(octets.as_ptr(), octets_out, 16);
                        *prefix_len_out = p.prefix_len;
                        *present_out = 1;
                    }
                }
                None => unsafe {
                    std::ptr::write_bytes(octets_out, 0, 16);
                    *prefix_len_out = 0;
                    *present_out = 0;
                },
            }
            0
        },
        LR_ERR_PANIC,
    )
}

/// Drop a boxed `Fec`. Safe to call with `NULL`.
///
/// # Safety
/// `f` must have been produced by [`lr_ldp_fec_new_wildcard`] or
/// [`lr_ldp_fec_new_prefix`] and not already freed.
#[no_mangle]
pub unsafe extern "C" fn lr_ldp_fec_free(f: lr_ldp_fec_t) {
    guarded(
        || unsafe {
            if f.is_null() {
                return;
            }
            drop(unsafe { Box::from_raw(f as *mut Fec) });
        },
        (),
    )
}

// ---- StatusCode ----

/// Construct a `StatusCode` from a raw 32-bit status code (RFC 5036
/// §3.4.6.1 — high 31 bits carry the status, low bit is unused).
#[no_mangle]
pub extern "C" fn lr_ldp_status_code_new(code: u32) -> u32 {
    guarded(|| StatusCode(code).0, 0)
}

/// True when the status code is fatal (RFC 5036 §3.4.6.1 — bit 31).
#[no_mangle]
pub extern "C" fn lr_ldp_status_code_is_fatal(code: u32) -> u8 {
    guarded(|| StatusCode(code).is_fatal() as u8, 0)
}

/// True when the status code carries the Forward bit (RFC 5036 §3.4.6.1
/// — bit 30).
#[no_mangle]
pub extern "C" fn lr_ldp_status_code_is_forward(code: u32) -> u8 {
    guarded(|| StatusCode(code).is_forward() as u8, 0)
}

/// Well-known LDP status codes — mirror the `StatusCode::*` constants
/// in `lr_ldp::tlv`. Each is a raw 32-bit value the embedder passes to
/// [`lr_ldp_status_code_new`] / `_is_fatal` / `_is_forward`.
pub const LR_LDP_STATUS_SUCCESS: u32 = 0x0000_0000;
pub const LR_LDP_STATUS_BAD_LDP_IDENTIFIER: u32 = 0x8000_0001;
pub const LR_LDP_STATUS_BAD_PROTOCOL_VERSION: u32 = 0x8000_0002;
pub const LR_LDP_STATUS_BAD_PDU_LENGTH: u32 = 0x8000_0003;
pub const LR_LDP_STATUS_UNKNOWN_MESSAGE_TYPE: u32 = 0x8000_0004;
pub const LR_LDP_STATUS_BAD_MESSAGE_LENGTH: u32 = 0x8000_0005;
pub const LR_LDP_STATUS_UNKNOWN_TLV: u32 = 0x8000_0006;
pub const LR_LDP_STATUS_BAD_TLV_LENGTH: u32 = 0x8000_0007;
pub const LR_LDP_STATUS_MALFORMED_TLV_VALUE: u32 = 0x8000_0008;
pub const LR_LDP_STATUS_HOLD_TIMER_EXPIRED: u32 = 0x8000_0009;
pub const LR_LDP_STATUS_SHUTDOWN: u32 = 0x8000_000A;
pub const LR_LDP_STATUS_LOOP_DETECTED: u32 = 0x8000_000B;
pub const LR_LDP_STATUS_UNKNOWN_FEC: u32 = 0x8000_000C;
pub const LR_LDP_STATUS_NO_ROUTE: u32 = 0x8000_000D;
pub const LR_LDP_STATUS_NO_LABEL_RESOURCE: u32 = 0x8000_000E;
pub const LR_LDP_STATUS_LABEL_RESOURCE_AVAILABLE: u32 = 0x8000_000F;
pub const LR_LDP_STATUS_SESSION_REJECTED: u32 = 0x8000_0010;
pub const LR_LDP_STATUS_TRANSPORT_CONNECTION_MISMATCH: u32 = 0x8000_0011;
pub const LR_LDP_STATUS_KEEPALIVE_TIMER_EXPIRED: u32 = 0x8000_0012;
pub const LR_LDP_STATUS_DUAL_STACK_NONCOMPLIANCE: u32 = 0x8000_0013;
pub const LR_LDP_STATUS_LABEL_WITHDRAW: u32 = 0x0000_0028;

// ---- LDP message-type constants (RFC 5036 §3.5) ----

pub const LR_LDP_MSG_NOTIFICATION: u16 = 0x0001;
pub const LR_LDP_MSG_HELLO: u16 = 0x0100;
pub const LR_LDP_MSG_INITIALIZATION: u16 = 0x0200;
pub const LR_LDP_MSG_KEEP_ALIVE: u16 = 0x0201;
pub const LR_LDP_MSG_CAPABILITY: u16 = 0x0202;
pub const LR_LDP_MSG_ADDRESS_MESSAGE: u16 = 0x0300;
pub const LR_LDP_MSG_ADDRESS_WITHDRAW: u16 = 0x0301;
pub const LR_LDP_MSG_LABEL_MAPPING: u16 = 0x0400;
pub const LR_LDP_MSG_LABEL_REQUEST: u16 = 0x0401;
pub const LR_LDP_MSG_LABEL_WITHDRAW: u16 = 0x0402;
pub const LR_LDP_MSG_LABEL_RELEASE: u16 = 0x0403;
pub const LR_LDP_MSG_LABEL_ABORT_REQUEST: u16 = 0x0404;

// ---- LDP TLV-type constants (RFC 5036 §3.4) ----

pub const LR_LDP_TLV_FEC: u16 = 0x0100;
pub const LR_LDP_TLV_ADDRESS_LIST: u16 = 0x0101;
pub const LR_LDP_TLV_HOP_COUNT: u16 = 0x0103;
pub const LR_LDP_TLV_PATH_VECTOR: u16 = 0x0104;
pub const LR_LDP_TLV_GENERIC_LABEL: u16 = 0x0200;
pub const LR_LDP_TLV_STATUS: u16 = 0x0300;
pub const LR_LDP_TLV_EXTENDED_STATUS: u16 = 0x0301;
pub const LR_LDP_TLV_RETURNED_PDU: u16 = 0x0302;
pub const LR_LDP_TLV_RETURNED_MESSAGE: u16 = 0x0303;
pub const LR_LDP_TLV_COMMON_HELLO_PARAMS: u16 = 0x0400;
pub const LR_LDP_TLV_IPV4_TRANSPORT_ADDR: u16 = 0x0401;
pub const LR_LDP_TLV_CONFIG_SEQ_NUMBER: u16 = 0x0402;
pub const LR_LDP_TLV_IPV6_TRANSPORT_ADDR: u16 = 0x0403;
pub const LR_LDP_TLV_DUAL_STACK_CAPABILITY: u16 = 0x0404;
pub const LR_LDP_TLV_COMMON_SESSION_PARAMS: u16 = 0x0500;
pub const LR_LDP_TLV_LABEL_REQUEST_MESSAGE_ID: u16 = 0x0600;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ffi_label_new_and_readers() {
        let l = lr_ldp_label_new(100);
        assert!(!l.is_null());
        assert_eq!(unsafe { lr_ldp_label_value(l) }, 100);
        assert_eq!(unsafe { lr_ldp_label_is_valid(l) }, 1);
        unsafe { lr_ldp_label_free(l) };
    }

    #[test]
    fn ffi_label_implicit_null_constant() {
        let l = lr_ldp_label_new(LR_LDP_LABEL_IMPLICIT_NULL);
        assert_eq!(unsafe { lr_ldp_label_value(l) }, 3);
        unsafe { lr_ldp_label_free(l) };
    }

    #[test]
    fn ffi_label_invalid_value_rejected() {
        // 0x100000 = 1 << 20 = MAX + 1.
        let l = lr_ldp_label_new(0x100000);
        assert_eq!(unsafe { lr_ldp_label_is_valid(l) }, 0);
        unsafe { lr_ldp_label_free(l) };
    }

    #[test]
    fn ffi_fec_new_wildcard() {
        let f = lr_ldp_fec_new_wildcard();
        assert!(!f.is_null());
        assert_eq!(unsafe { lr_ldp_fec_is_wildcard(f) }, 1);
        let mut octets = [0u8; 16];
        let mut plen = 0u8;
        let mut present = 0u8;
        let rc = unsafe {
            lr_ldp_fec_single_prefix(f, octets.as_mut_ptr(), &raw mut plen, &raw mut present)
        };
        assert_eq!(rc, 0);
        assert_eq!(present, 0);
        unsafe { lr_ldp_fec_free(f) };
    }

    #[test]
    fn ffi_fec_new_prefix_v4() {
        let prefix = [10u8, 0, 0, 0];
        let f = unsafe { lr_ldp_fec_new_prefix(prefix.as_ptr(), std::ptr::null(), 24) };
        assert!(!f.is_null());
        assert_eq!(unsafe { lr_ldp_fec_is_wildcard(f) }, 0);
        let mut octets = [0u8; 16];
        let mut plen = 0u8;
        let mut present = 0u8;
        let rc = unsafe {
            lr_ldp_fec_single_prefix(f, octets.as_mut_ptr(), &raw mut plen, &raw mut present)
        };
        assert_eq!(rc, 0);
        assert_eq!(present, 1);
        assert_eq!(plen, 24);
        assert_eq!(&octets[..4], &[10, 0, 0, 0]);
        unsafe { lr_ldp_fec_free(f) };
    }

    #[test]
    fn ffi_fec_new_prefix_null_returns_null() {
        let f = unsafe { lr_ldp_fec_new_prefix(std::ptr::null(), std::ptr::null(), 24) };
        assert!(f.is_null());
    }

    #[test]
    fn ffi_status_code_is_fatal() {
        // 0x80000001 = Bad LDP Identifier (fatal).
        assert_eq!(lr_ldp_status_code_is_fatal(0x8000_0001), 1);
        assert_eq!(lr_ldp_status_code_is_fatal(0x0000_0000), 0);
        assert_eq!(lr_ldp_status_code_is_fatal(LR_LDP_STATUS_SHUTDOWN), 1);
    }

    #[test]
    fn ffi_status_code_is_forward() {
        // Status code with bit 30 set (forward bit).
        assert_eq!(lr_ldp_status_code_is_forward(0x4000_0000), 1);
        assert_eq!(lr_ldp_status_code_is_forward(0x0000_0000), 0);
    }

    #[test]
    fn ffi_free_handles_null_safely() {
        unsafe {
            lr_ldp_label_free(std::ptr::null_mut());
            lr_ldp_fec_free(std::ptr::null_mut());
        }
    }
}
