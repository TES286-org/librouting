//! SRv6 constants FFI — SRH wire constants (RFC 8754 §2).
//!
//! Mirrors `lr_srv6::srh` constants so a C embedder can interpret the
//! flags / TLV bytes returned by `lr_srv6_decode_srh` without
//! re-deriving them from the RFC.

#![allow(dead_code)]

// ---- SRH routing type / next header (RFC 8754 §2) ----

/// Routing Type field value for the SRH in the IPv6 Routing header
/// (RFC 8754 §2).
pub const LR_SRV6_ROUTING_TYPE_SRH: u8 = 4;

// ---- SRH flag bits (RFC 8754 §2.1 / Linux uapi) ----

/// OAM flag (RFC 8754 §2.1 — deployed in the Linux uapi).
pub const LR_SRV6_FLAG_OAM: u8 = 0x20;
/// HMAC flag (RFC 8754 §2.1 — deployed in the Linux uapi).
pub const LR_SRV6_FLAG_HMAC: u8 = 0x08;
/// Alert flag (RFC 8754 §2.1 — deployed in the Linux uapi).
pub const LR_SRV6_FLAG_ALERT: u8 = 0x10;
/// Protected flag (RFC 8754 §2.1 — deployed in the Linux uapi).
pub const LR_SRV6_FLAG_PROTECTED: u8 = 0x40;

// ---- SRH layout constants (RFC 8754 §2) ----

/// Fixed-header length of an SRH (8 octets: next-header / hdr-ext-len
/// / routing-type / segments-left / last-entry / flags / tag /
/// 2 reserved octets — the segment list follows).
pub const LR_SRV6_SRH_FIXED_LEN: usize = 8;
/// Per-segment length of an SRH (16 octets — one IPv6 SID).
pub const LR_SRV6_SRH_SEGMENT_LEN: usize = 16;

// ---- SRH TLV types (RFC 8754 §2.3) ----

/// Pad1 TLV (RFC 8754 §2.3 — 1 octet, value 0; inserted for alignment).
pub const LR_SRV6_TLV_PAD1: u8 = 0;
/// PadN TLV (RFC 8754 §2.3 — 1 type octet + 1 length octet + N
/// zero octets; inserted for alignment).
pub const LR_SRV6_TLV_PADN: u8 = 1;

/// Maximum number of segments an SRH can carry (RFC 8754 §2 — `Hdr
/// Ext Len` is a single octet, so the segment list cannot exceed 127
/// entries, fitting in `(255 - 1) / 2 = 127` 16-octet segments).
pub const LR_SRV6_MAX_SEGMENTS: usize = 127;

// ---- Locator (RFC 8754 §3) ----

/// Maximum block-bit width supported by `Locator::new` (RFC 8754 §3.1
/// — the locator block is the leading portion of an SRv6 SID; librouting
/// supports up to 128 bits).
pub const LR_SRV6_MAX_BLOCK_BITS: u8 = 128;

// ---- SrhError discriminant (mirrors `lr_srv6::SrhError`) ----

/// `SrhError::TooShort`.
pub const LR_SRV6_SRH_ERR_TOO_SHORT: i32 = 0;
/// `SrhError::LengthMismatch`.
pub const LR_SRV6_SRH_ERR_LENGTH_MISMATCH: i32 = 1;
/// `SrhError::EmptySegmentList`.
pub const LR_SRV6_SRH_ERR_EMPTY_SEGMENT_LIST: i32 = 2;
/// `SrhError::TooManySegments`.
pub const LR_SRV6_SRH_ERR_TOO_MANY_SEGMENTS: i32 = 3;
/// `SrhError::LastEntryOutOfRange`.
pub const LR_SRV6_SRH_ERR_LAST_ENTRY_OUT_OF_RANGE: i32 = 4;
/// `SrhError::SegmentsLeftOutOfRange`.
pub const LR_SRV6_SRH_ERR_SEGMENTS_LEFT_OUT_OF_RANGE: i32 = 5;
/// `SrhError::WrongRoutingType`.
pub const LR_SRV6_SRH_ERR_WRONG_ROUTING_TYPE: i32 = 6;
/// `SrhError::ReservedFlagBits`.
pub const LR_SRV6_SRH_ERR_RESERVED_FLAG_BITS: i32 = 7;
/// Unknown SrhError variant (forward-compat sentinel).
pub const LR_SRV6_SRH_ERR_UNKNOWN: i32 = -1;

/// Translate a `SrhError` to its discriminant code. Public via the
/// `lr_srv6_srh_err_code` entry point so a C embedder can switch on
/// the code without parsing the last-error string. Kept `pub` so the
/// Rust-side `srv6.rs` codec can call it when surfacing the code on a
/// decode failure (the FFI module's own decode path delegates here).
#[allow(dead_code)]
pub fn srh_err_code(e: &lr_srv6::SrhError) -> i32 {
    use lr_srv6::SrhError;
    match e {
        SrhError::TooShort => LR_SRV6_SRH_ERR_TOO_SHORT,
        SrhError::LengthMismatch => LR_SRV6_SRH_ERR_LENGTH_MISMATCH,
        SrhError::EmptySegmentList => LR_SRV6_SRH_ERR_EMPTY_SEGMENT_LIST,
        SrhError::TooManySegments => LR_SRV6_SRH_ERR_TOO_MANY_SEGMENTS,
        SrhError::LastEntryOutOfRange => LR_SRV6_SRH_ERR_LAST_ENTRY_OUT_OF_RANGE,
        SrhError::SegmentsLeftOutOfRange => LR_SRV6_SRH_ERR_SEGMENTS_LEFT_OUT_OF_RANGE,
        SrhError::WrongRoutingType(_) => LR_SRV6_SRH_ERR_WRONG_ROUTING_TYPE,
        SrhError::ReservedFlagBits(_) => LR_SRV6_SRH_ERR_RESERVED_FLAG_BITS,
    }
}

/// `lr_srv6_srh_err_code` — return the discriminant of the most recent
/// `SrhError` produced by `lr_srv6_encode_srh` / `lr_srv6_decode_srh`.
/// Mirrors the substring-match logic of `lr_srv6_srh_last_err_code`,
/// kept as a separate entry point so a future typed-error-pointer
/// surface can call into `srh_err_code` directly without going through
/// the thread-local string. Returns `LR_SRV6_SRH_ERR_UNKNOWN` (-1)
/// when no SRH error is recorded.
#[no_mangle]
pub extern "C" fn lr_srv6_srh_err_code() -> i32 {
    lr_srv6_srh_last_err_code()
}

/// `lr_srv6_srh_last_err_code` — return the discriminant of the last
/// SRH encode/decode error stored in the thread-local last-error
/// string. Returns `LR_SRV6_SRH_ERR_UNKNOWN` (-1) when no SRH error
/// is recorded (e.g. the last FFI call succeeded or stored a non-SRH
/// error).
///
/// This is a peek-only helper: it does not clear the last-error
/// string. Callers that need the human-readable message should still
/// call `lr_last_error`.
#[no_mangle]
pub extern "C" fn lr_srv6_srh_last_err_code() -> i32 {
    // The last-error string carries the Display form of the SrhError.
    // We re-parse it back into a discriminant by substring match. This
    // keeps the C ABI self-contained without exposing the Rust enum
    // shape across the FFI.
    let s = crate::error::last_error_string();
    if s.is_empty() {
        return LR_SRV6_SRH_ERR_UNKNOWN;
    }
    // Match the Display form's stable prefixes (see SrhError::fmt).
    if s.contains("shorter than the 8-octet fixed header") {
        LR_SRV6_SRH_ERR_TOO_SHORT
    } else if s.contains("Hdr Ext Len does not match") {
        LR_SRV6_SRH_ERR_LENGTH_MISMATCH
    } else if s.contains("segment list is empty") {
        LR_SRV6_SRH_ERR_EMPTY_SEGMENT_LIST
    } else if s.contains("segment maximum") {
        LR_SRV6_SRH_ERR_TOO_MANY_SEGMENTS
    } else if s.contains("Last Entry is greater") {
        LR_SRV6_SRH_ERR_LAST_ENTRY_OUT_OF_RANGE
    } else if s.contains("Segments Left is greater") {
        LR_SRV6_SRH_ERR_SEGMENTS_LEFT_OUT_OF_RANGE
    } else if s.contains("Routing Type is not 4") {
        LR_SRV6_SRH_ERR_WRONG_ROUTING_TYPE
    } else if s.contains("Reserved flag bits") {
        LR_SRV6_SRH_ERR_RESERVED_FLAG_BITS
    } else {
        // Not an SRH error — surface as the unknown sentinel.
        LR_SRV6_SRH_ERR_UNKNOWN
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ffi_srh_constants_match_rfc() {
        assert_eq!(LR_SRV6_ROUTING_TYPE_SRH, 4);
        assert_eq!(LR_SRV6_FLAG_OAM, 0x20);
        assert_eq!(LR_SRV6_FLAG_HMAC, 0x08);
        assert_eq!(LR_SRV6_FLAG_ALERT, 0x10);
        assert_eq!(LR_SRV6_FLAG_PROTECTED, 0x40);
    }

    #[test]
    fn ffi_srh_layout_constants_match_rfc() {
        assert_eq!(LR_SRV6_SRH_FIXED_LEN, 8);
        assert_eq!(LR_SRV6_SRH_SEGMENT_LEN, 16);
        assert_eq!(LR_SRV6_MAX_SEGMENTS, 127);
        assert_eq!(LR_SRV6_TLV_PAD1, 0);
        assert_eq!(LR_SRV6_TLV_PADN, 1);
    }

    #[test]
    fn ffi_locator_constants() {
        assert_eq!(LR_SRV6_MAX_BLOCK_BITS, 128);
    }

    #[test]
    fn ffi_srh_err_codes_distinct() {
        let codes = [
            LR_SRV6_SRH_ERR_TOO_SHORT,
            LR_SRV6_SRH_ERR_LENGTH_MISMATCH,
            LR_SRV6_SRH_ERR_EMPTY_SEGMENT_LIST,
            LR_SRV6_SRH_ERR_TOO_MANY_SEGMENTS,
            LR_SRV6_SRH_ERR_LAST_ENTRY_OUT_OF_RANGE,
            LR_SRV6_SRH_ERR_SEGMENTS_LEFT_OUT_OF_RANGE,
            LR_SRV6_SRH_ERR_WRONG_ROUTING_TYPE,
            LR_SRV6_SRH_ERR_RESERVED_FLAG_BITS,
        ];
        // All discriminants distinct.
        let mut sorted: Vec<i32> = codes.to_vec();
        sorted.sort();
        sorted.dedup();
        assert_eq!(sorted.len(), codes.len());
    }
}
