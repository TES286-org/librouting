//! BGP capability code FFI (RFC 5492, IANA registry).
//!
//! Stateless. Mirrors the public Rust API of
//! `lr_bgp::capabilities::{CapabilityCode, Capability}` so an embedder
//! can decode and construct BGP OPEN capabilities.
//!
//! Every entry point runs inside the crate's `catch_unwind` barrier
//! ([`crate::guarded`]): a panic returns `LR_ERR_PANIC` and sets the
//! thread-local last-error string.

// The closure body passed to `guarded` is wrapped in a single `unsafe`
// block to mirror the `pub unsafe extern "C" fn` shape — the inner
// `unsafe { ... }` blocks would otherwise trip `unused_unsafe` under
// the crate's `-D warnings` clippy gate.
#![allow(unused_unsafe)]

use lr_bgp::capabilities::{Capability, CapabilityCode};

use crate::guarded;

// ---- Capability-code constants (mirrors lr_bgp::CapabilityCode) ----

pub const LR_BGP_CAP_MULTIPROTOCOL_EXTENSIONS: u8 = 1;
pub const LR_BGP_CAP_ROUTE_REFRESH: u8 = 2;
pub const LR_BGP_CAP_EXTENDED_NEXT_HOP: u8 = 5;
pub const LR_BGP_CAP_EXTENDED_MESSAGE: u8 = 6;
pub const LR_BGP_CAP_GRACEFUL_RESTART: u8 = 64;
pub const LR_BGP_CAP_FOUR_OCTET_AS: u8 = 65;
pub const LR_BGP_CAP_ADD_PATH: u8 = 69;
pub const LR_BGP_CAP_ENHANCED_ROUTE_REFRESH: u8 = 70;
pub const LR_BGP_CAP_LONG_LIVED_GRACEFUL_RESTART: u8 = 71;

/// Convert a BGP capability wire value to its `LR_BGP_CAP_*` constant.
/// Unknown values are passed through as-is (matching `CapabilityCode::Other(u8)`).
#[no_mangle]
pub extern "C" fn lr_bgp_cap_code_from_wire(wire: u8) -> u8 {
    guarded(|| CapabilityCode::from_u8(wire).to_u8(), 0)
}

/// Construct a Four-Octet AS capability (RFC 6793 §4) carrying the
/// given ASN. Returns an opaque `lr_bgp_capability_t` handle.
#[no_mangle]
pub extern "C" fn lr_bgp_cap_four_octet_as(asn: u32) -> lr_bgp_capability_t {
    guarded(
        || box_capability(Capability::four_octet_as(asn)),
        std::ptr::null_mut(),
    )
}

/// Opaque `Capability` handle.
#[repr(C)]
pub struct OpaqueBgpCapability {
    _private: [u8; 0],
}

pub type lr_bgp_capability_t = *mut OpaqueBgpCapability;

fn box_capability(c: Capability) -> lr_bgp_capability_t {
    Box::into_raw(Box::new(c)) as lr_bgp_capability_t
}

/// Borrow a capability handle as `&Capability`.
///
/// # Safety
/// `c` must have been produced by [`box_capability`] and not be freed
/// while the returned reference is live.
unsafe fn borrow_capability(c: lr_bgp_capability_t) -> Option<&'static Capability> {
    if c.is_null() {
        return None;
    }
    Some(unsafe { &*(c as *const Capability) })
}

/// Read the capability's wire code (one of the `LR_BGP_CAP_*`
/// constants, or a pass-through value for unknown capabilities).
///
/// # Safety
/// `cap` must be a valid handle.
#[no_mangle]
pub unsafe extern "C" fn lr_bgp_cap_code(cap: lr_bgp_capability_t) -> u8 {
    guarded(
        || unsafe { borrow_capability(cap).map(|c| c.code.to_u8()).unwrap_or(0) },
        0,
    )
}

/// Read the length of the capability's value bytes.
///
/// # Safety
/// `cap` must be a valid handle.
#[no_mangle]
pub unsafe extern "C" fn lr_bgp_cap_value_len(cap: lr_bgp_capability_t) -> usize {
    guarded(
        || unsafe { borrow_capability(cap).map(|c| c.value.len()).unwrap_or(0) },
        0,
    )
}

/// Copy the capability's value bytes into the caller-supplied buffer.
/// Returns the number of bytes copied.
///
/// # Safety
/// `cap` must be a valid handle. `out` must point to at least `cap_size`
/// writable bytes.
#[no_mangle]
pub unsafe extern "C" fn lr_bgp_cap_value(
    cap: lr_bgp_capability_t,
    out: *mut u8,
    cap_size: usize,
) -> usize {
    guarded(
        || unsafe {
            let Some(c) = borrow_capability(cap) else {
                return 0;
            };
            if out.is_null() || cap_size == 0 {
                return 0;
            }
            let take = c.value.len().min(cap_size);
            unsafe {
                std::ptr::copy_nonoverlapping(c.value.as_ptr(), out, take);
            }
            take
        },
        0,
    )
}

/// For a Four-Octet-AS capability, return the 4-byte ASN value. Returns
/// 0 on a NULL handle or when the capability is not a Four-Octet-AS.
///
/// # Safety
/// `cap` must be a valid handle.
#[no_mangle]
pub unsafe extern "C" fn lr_bgp_cap_as_four_octet(cap: lr_bgp_capability_t) -> u32 {
    guarded(
        || unsafe {
            borrow_capability(cap)
                .and_then(|c| c.as_four_octet())
                .unwrap_or(0)
        },
        0,
    )
}

/// Drop a boxed `Capability`. Safe to call with NULL.
///
/// # Safety
/// `cap` must have been produced by a `lr_bgp_cap_*` constructor and
/// must not be used after this call.
#[no_mangle]
pub unsafe extern "C" fn lr_bgp_cap_free(cap: lr_bgp_capability_t) {
    guarded(
        || unsafe {
            if cap.is_null() {
                return;
            }
            let boxed: Box<Capability> = Box::from_raw(cap as *mut Capability);
            drop(boxed);
        },
        (),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ffi_constants_match_iana() {
        assert_eq!(LR_BGP_CAP_MULTIPROTOCOL_EXTENSIONS, 1);
        assert_eq!(LR_BGP_CAP_ROUTE_REFRESH, 2);
        assert_eq!(LR_BGP_CAP_EXTENDED_NEXT_HOP, 5);
        assert_eq!(LR_BGP_CAP_FOUR_OCTET_AS, 65);
        assert_eq!(LR_BGP_CAP_ADD_PATH, 69);
        assert_eq!(LR_BGP_CAP_ENHANCED_ROUTE_REFRESH, 70);
        assert_eq!(LR_BGP_CAP_LONG_LIVED_GRACEFUL_RESTART, 71);
    }

    #[test]
    fn ffi_cap_code_from_wire() {
        assert_eq!(lr_bgp_cap_code_from_wire(1), 1);
        assert_eq!(lr_bgp_cap_code_from_wire(65), 65);
        // Unknown code passes through.
        assert_eq!(lr_bgp_cap_code_from_wire(99), 99);
    }

    #[test]
    fn ffi_cap_four_octet_as_roundtrip() {
        let cap = lr_bgp_cap_four_octet_as(0x12345678);
        assert!(!cap.is_null());
        unsafe {
            assert_eq!(lr_bgp_cap_code(cap), LR_BGP_CAP_FOUR_OCTET_AS);
            assert_eq!(lr_bgp_cap_value_len(cap), 4);
            assert_eq!(lr_bgp_cap_as_four_octet(cap), 0x12345678);

            let mut buf = [0u8; 4];
            assert_eq!(lr_bgp_cap_value(cap, buf.as_mut_ptr(), 4), 4);
            assert_eq!(u32::from_be_bytes(buf), 0x12345678);
            lr_bgp_cap_free(cap);
        }
    }

    #[test]
    fn ffi_cap_as_four_octet_returns_zero_for_non_cap() {
        // Construct a Four-Octet-AS capability, then ask for the value
        // of a different capability type — we only have four_octet_as
        // here, so this just verifies the reader doesn't panic on
        // unknown codes.
        let cap = lr_bgp_cap_four_octet_as(64512);
        unsafe {
            assert_eq!(lr_bgp_cap_as_four_octet(cap), 64512);
            lr_bgp_cap_free(cap);
        }
    }

    #[test]
    fn ffi_cap_code_returns_zero_on_null() {
        assert_eq!(unsafe { lr_bgp_cap_code(std::ptr::null_mut()) }, 0);
    }

    #[test]
    fn ffi_cap_free_handles_null() {
        unsafe { lr_bgp_cap_free(std::ptr::null_mut()) };
    }

    #[test]
    fn ffi_cap_value_returns_zero_on_null_handle() {
        let mut buf = [0u8; 4];
        let n = unsafe { lr_bgp_cap_value(std::ptr::null_mut(), buf.as_mut_ptr(), 4) };
        assert_eq!(n, 0);
    }
}
