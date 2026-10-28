//! MPLS constants FFI — Label constants and `LabelStackError`
//! discriminants (RFC 3032 §2.1).
//!
//! Mirrors `lr_mpls::{Label::FIRST_NORMAL, Label::MAX_VALUE,
//! LabelStackError}` so a C embedder can build / interpret MPLS
//! label values without re-deriving them from the RFC.

#![allow(dead_code)]

// ---- Label value range (RFC 3032 §2.1) ----

/// Maximum legal label value (20-bit range, RFC 3032 §2.1).
pub const LR_MPLS_LABEL_MAX_VALUE: u32 = (1 << 20) - 1; // 0xFFFFF
/// First label value outside the reserved range 0–15 (RFC 3032 §2.1).
pub const LR_MPLS_LABEL_FIRST_NORMAL: u32 = 16;

// ---- Reserved label values (RFC 3032 §2.1) ----

/// IPv4 Explicit NULL (label 0, RFC 3032 §2.1).
pub const LR_MPLS_LABEL_IPV4_EXPLICIT_NULL: u32 = 0;
/// Router Alert Label (label 1, RFC 3032 §2.1).
pub const LR_MPLS_LABEL_ROUTER_ALERT: u32 = 1;
/// IPv6 Explicit NULL (label 2, RFC 3032 §2.1).
pub const LR_MPLS_LABEL_IPV6_EXPLICIT_NULL: u32 = 2;
/// Implicit NULL (label 3, RFC 3032 §2.1). Never appears on the wire —
/// only in label-distribution signaling (LDP, RSVP-TE, BGP-LU).
pub const LR_MPLS_LABEL_IMPLICIT_NULL: u32 = 3;
/// Entropy LSE Indicator (label 7, RFC 6790).
pub const LR_MPLS_LABEL_ELI: u32 = 7;
/// Generic Associated Channel Label (label 13, RFC 5586).
pub const LR_MPLS_LABEL_GAL: u32 = 13;
/// OAM Alert Label (label 14, RFC 3429).
pub const LR_MPLS_LABEL_OAM_ALERT: u32 = 14;
/// Extension Label (label 15, RFC 7274).
pub const LR_MPLS_LABEL_EXTENSION: u32 = 15;

// ---- LabelStackError discriminant (mirrors `lr_mpls::LabelStackError`) ----

/// `LabelStackError::TooShort`.
pub const LR_MPLS_STACK_ERR_TOO_SHORT: i32 = 0;
/// `LabelStackError::UnevenLength`.
pub const LR_MPLS_STACK_ERR_UNEVEN_LENGTH: i32 = 1;
/// `LabelStackError::MidStackBottom`.
pub const LR_MPLS_STACK_ERR_MID_STACK_BOTTOM: i32 = 2;
/// `LabelStackError::ValueOutOfRange`.
pub const LR_MPLS_STACK_ERR_VALUE_OUT_OF_RANGE: i32 = 3;
/// Unknown `LabelStackError` variant (forward-compat sentinel).
pub const LR_MPLS_STACK_ERR_UNKNOWN: i32 = -1;

/// Translate a `LabelStackError` to its discriminant code.
pub fn stack_err_code(e: &lr_mpls::LabelStackError) -> i32 {
    use lr_mpls::LabelStackError;
    match e {
        LabelStackError::TooShort => LR_MPLS_STACK_ERR_TOO_SHORT,
        LabelStackError::UnevenLength => LR_MPLS_STACK_ERR_UNEVEN_LENGTH,
        LabelStackError::MidStackBottom => LR_MPLS_STACK_ERR_MID_STACK_BOTTOM,
        LabelStackError::ValueOutOfRange(_) => LR_MPLS_STACK_ERR_VALUE_OUT_OF_RANGE,
    }
}

/// `lr_mpls_stack_last_err_code` — return the discriminant of the
/// last label-stack decode error stored in the thread-local
/// last-error string. Returns `LR_MPLS_STACK_ERR_UNKNOWN` (-1) when
/// no stack error is recorded.
#[no_mangle]
pub extern "C" fn lr_mpls_stack_last_err_code() -> i32 {
    let s = crate::error::last_error_string();
    if s.is_empty() {
        return LR_MPLS_STACK_ERR_UNKNOWN;
    }
    if s.contains("label stack input is empty") {
        LR_MPLS_STACK_ERR_TOO_SHORT
    } else if s.contains("not a multiple of entry width") {
        LR_MPLS_STACK_ERR_UNEVEN_LENGTH
    } else if s.contains("bottom-of-stack bit set on a non-bottom") {
        LR_MPLS_STACK_ERR_MID_STACK_BOTTOM
    } else if s.contains("exceeds the 20-bit range") {
        LR_MPLS_STACK_ERR_VALUE_OUT_OF_RANGE
    } else {
        LR_MPLS_STACK_ERR_UNKNOWN
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ffi_label_constants_match_rfc() {
        assert_eq!(LR_MPLS_LABEL_MAX_VALUE, 0xFFFFF);
        assert_eq!(LR_MPLS_LABEL_FIRST_NORMAL, 16);
        assert_eq!(LR_MPLS_LABEL_IPV4_EXPLICIT_NULL, 0);
        assert_eq!(LR_MPLS_LABEL_ROUTER_ALERT, 1);
        assert_eq!(LR_MPLS_LABEL_IPV6_EXPLICIT_NULL, 2);
        assert_eq!(LR_MPLS_LABEL_IMPLICIT_NULL, 3);
        assert_eq!(LR_MPLS_LABEL_ELI, 7);
        assert_eq!(LR_MPLS_LABEL_GAL, 13);
        assert_eq!(LR_MPLS_LABEL_OAM_ALERT, 14);
        assert_eq!(LR_MPLS_LABEL_EXTENSION, 15);
    }

    #[test]
    fn ffi_stack_err_codes_distinct() {
        let codes = [
            LR_MPLS_STACK_ERR_TOO_SHORT,
            LR_MPLS_STACK_ERR_UNEVEN_LENGTH,
            LR_MPLS_STACK_ERR_MID_STACK_BOTTOM,
            LR_MPLS_STACK_ERR_VALUE_OUT_OF_RANGE,
        ];
        let mut sorted: Vec<i32> = codes.to_vec();
        sorted.sort();
        sorted.dedup();
        assert_eq!(sorted.len(), codes.len());
    }
}
