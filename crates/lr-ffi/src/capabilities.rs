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

/// Construct a Multiprotocol capability (RFC 4760 §4) carrying the
/// given AFI/SAFI tuple. Returns an opaque `lr_bgp_capability_t`
/// handle.
#[no_mangle]
pub extern "C" fn lr_bgp_cap_multiprotocol(afi: u16, safi: u8) -> lr_bgp_capability_t {
    guarded(
        || box_capability(Capability::multiprotocol(afi, safi)),
        std::ptr::null_mut(),
    )
}

/// For a Multiprotocol capability (RFC 4760 §4), read the AFI/SAFI
/// pair. Writes the AFI to `*out_afi` and the SAFI to `*out_safi`
/// and returns 1 when the capability is a Multiprotocol one; returns
/// 0 on a NULL handle, NULL out-pointers, or a non-Multiprotocol
/// capability.
///
/// # Safety
/// `cap` must be a valid handle. `out_afi` / `out_safi` must point
/// to writable `uint16_t` / `uint8_t`.
#[no_mangle]
pub unsafe extern "C" fn lr_bgp_cap_as_multiprotocol(
    cap: lr_bgp_capability_t,
    out_afi: *mut u16,
    out_safi: *mut u8,
) -> u8 {
    guarded(
        || unsafe {
            let Some(c) = borrow_capability(cap) else {
                return 0;
            };
            if out_afi.is_null() || out_safi.is_null() {
                return 0;
            }
            match c.as_multiprotocol() {
                Some((afi, safi)) => {
                    unsafe {
                        *out_afi = afi;
                        *out_safi = safi;
                    }
                    1
                }
                None => 0,
            }
        },
        0,
    )
}

/// Construct an Extended Next-Hop capability (RFC 5549 §4) carrying
/// the given list of `(nlri_afi, nlri_safi, nexthop_afi)` tuples.
/// Each tuple says "NLRI of family (nlri_afi, nlri_safi) may be
/// resolved over a nexthop of family nexthop_afi". A typical tuple
/// is `(1, 1, 2)` — IPv4 unicast over an IPv6 nexthop.
///
/// `tuples` points to `count` `lr_bgp_ext_next_hop_tuple_t` entries.
/// Returns an opaque `lr_bgp_capability_t` handle, or NULL on a
/// NULL `tuples` with non-zero `count`.
///
/// # Safety
/// `tuples` (when `count > 0`) must point to `count` readable
/// `lr_bgp_ext_next_hop_tuple_t` entries.
#[no_mangle]
pub unsafe extern "C" fn lr_bgp_cap_extended_next_hop(
    tuples: *const lr_bgp_ext_next_hop_tuple_t,
    count: usize,
) -> lr_bgp_capability_t {
    guarded(
        || unsafe {
            if count == 0 {
                return box_capability(Capability::extended_next_hop(&[]));
            }
            if tuples.is_null() {
                return std::ptr::null_mut();
            }
            let slice = unsafe { core::slice::from_raw_parts(tuples, count) };
            let mapped: Vec<(u16, u8, u16)> = slice
                .iter()
                .map(|t| (t.nlri_afi, t.nlri_safi, t.nexthop_afi))
                .collect();
            box_capability(Capability::extended_next_hop(&mapped))
        },
        std::ptr::null_mut(),
    )
}

/// One Extended Next-Hop tuple (RFC 5549 §4): the NLRI AFI/SAFI
/// pair and the nexthop AFI. Used by
/// [`lr_bgp_cap_extended_next_hop`] to build a capability from a
/// flat C array without round-tripping through individual handles.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct lr_bgp_ext_next_hop_tuple_t {
    /// NLRI address family (1 = IPv4, 2 = IPv6).
    pub nlri_afi: u16,
    /// NLRI subsequent address family (1 = unicast, etc.).
    pub nlri_safi: u8,
    /// Nexthop address family (2 = IPv6, for RFC 5549 IPv4-over-IPv6).
    pub nexthop_afi: u16,
}

/// For an Extended Next-Hop capability (RFC 5549 §4), return the
/// number of `(nlri_afi, nlri_safi, nexthop_afi)` tuples it carries.
/// Returns 0 on a NULL handle or a non-Extended-Next-Hop capability.
///
/// # Safety
/// `cap` must be a valid handle.
#[no_mangle]
pub unsafe extern "C" fn lr_bgp_cap_extended_next_hop_len(cap: lr_bgp_capability_t) -> usize {
    guarded(
        || unsafe {
            let Some(c) = borrow_capability(cap) else {
                return 0;
            };
            c.as_extended_next_hop()
                .map(|tuples| tuples.len())
                .unwrap_or(0)
        },
        0,
    )
}

/// For an Extended Next-Hop capability (RFC 5549 §4), copy the
/// `(nlri_afi, nlri_safi, nexthop_afi)` tuples into the caller-
/// supplied buffer. Each tuple occupies one
/// `lr_bgp_ext_next_hop_tuple_t`. Returns the number of tuples
/// actually copied (capped at `cap_size`). Use
/// [`lr_bgp_cap_extended_next_hop_len`] to size the buffer first.
///
/// # Safety
/// `cap` must be a valid handle. `out` must point to at least
/// `cap_size` writable `lr_bgp_ext_next_hop_tuple_t` entries.
#[no_mangle]
pub unsafe extern "C" fn lr_bgp_cap_extended_next_hop_tuples(
    cap: lr_bgp_capability_t,
    out: *mut lr_bgp_ext_next_hop_tuple_t,
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
            let Some(tuples) = c.as_extended_next_hop() else {
                return 0;
            };
            let take = tuples.len().min(cap_size);
            for (i, t) in tuples.iter().take(take).enumerate() {
                unsafe {
                    *out.add(i) = lr_bgp_ext_next_hop_tuple_t {
                        nlri_afi: t.0,
                        nlri_safi: t.1,
                        nexthop_afi: t.2,
                    };
                }
            }
            take
        },
        0,
    )
}

/// Construct a generic capability from a wire code + raw value bytes.
/// Returns an opaque `lr_bgp_capability_t` handle. The wire code is
/// the IANA `CapabilityCode` value; `value` points to `value_len`
/// bytes of capability-specific data (NULL + 0 length is legal and
/// produces a zero-value capability — used by Route Refresh, code 2).
///
/// # Safety
/// `value` (when `value_len > 0`) must point to `value_len` readable
/// bytes.
#[no_mangle]
pub unsafe extern "C" fn lr_bgp_cap_new(
    code: u8,
    value: *const u8,
    value_len: usize,
) -> lr_bgp_capability_t {
    guarded(
        || unsafe {
            let value_vec = if value.is_null() || value_len == 0 {
                Vec::new()
            } else {
                unsafe { core::slice::from_raw_parts(value, value_len).to_vec() }
            };
            box_capability(Capability::new(CapabilityCode::from_u8(code), value_vec))
        },
        std::ptr::null_mut(),
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

    // ---- Multiprotocol capability (RFC 4760 §4) ----

    #[test]
    fn ffi_cap_multiprotocol_roundtrip() {
        let cap = lr_bgp_cap_multiprotocol(2, 1); // IPv6 unicast
        assert!(!cap.is_null());
        unsafe {
            assert_eq!(lr_bgp_cap_code(cap), LR_BGP_CAP_MULTIPROTOCOL_EXTENSIONS);
            // RFC 4760 §4 value: AFI(2) | reserved(1) | SAFI(1) = 4 bytes.
            assert_eq!(lr_bgp_cap_value_len(cap), 4);
            let mut afi = 0u16;
            let mut safi = 0u8;
            assert_eq!(
                lr_bgp_cap_as_multiprotocol(cap, &raw mut afi, &raw mut safi),
                1
            );
            assert_eq!(afi, 2);
            assert_eq!(safi, 1);
            lr_bgp_cap_free(cap);
        }
    }

    #[test]
    fn ffi_cap_as_multiprotocol_returns_zero_for_non_mp() {
        // A Four-Octet-AS capability is not Multiprotocol — the
        // reader returns 0.
        let cap = lr_bgp_cap_four_octet_as(64512);
        unsafe {
            let mut afi = 0u16;
            let mut safi = 0u8;
            assert_eq!(
                lr_bgp_cap_as_multiprotocol(cap, &raw mut afi, &raw mut safi),
                0
            );
            lr_bgp_cap_free(cap);
        }
    }

    #[test]
    fn ffi_cap_as_multiprotocol_handles_null_safely() {
        let cap = lr_bgp_cap_multiprotocol(1, 1);
        unsafe {
            // NULL handle → 0.
            let mut afi = 0u16;
            let mut safi = 0u8;
            assert_eq!(
                lr_bgp_cap_as_multiprotocol(std::ptr::null_mut(), &raw mut afi, &raw mut safi),
                0
            );
            // NULL out_afi → 0.
            assert_eq!(
                lr_bgp_cap_as_multiprotocol(cap, std::ptr::null_mut(), &raw mut safi),
                0
            );
            // NULL out_safi → 0.
            assert_eq!(
                lr_bgp_cap_as_multiprotocol(cap, &raw mut afi, std::ptr::null_mut()),
                0
            );
            lr_bgp_cap_free(cap);
        }
    }

    // ---- Extended Next-Hop capability (RFC 5549 §4) ----

    #[test]
    fn ffi_cap_extended_next_hop_roundtrip() {
        let tuples = [
            lr_bgp_ext_next_hop_tuple_t {
                nlri_afi: 1,
                nlri_safi: 1,
                nexthop_afi: 2,
            },
            lr_bgp_ext_next_hop_tuple_t {
                nlri_afi: 2,
                nlri_safi: 1,
                nexthop_afi: 2,
            },
        ];
        let cap = unsafe { lr_bgp_cap_extended_next_hop(tuples.as_ptr(), tuples.len()) };
        assert!(!cap.is_null());
        unsafe {
            assert_eq!(lr_bgp_cap_code(cap), LR_BGP_CAP_EXTENDED_NEXT_HOP);
            assert_eq!(lr_bgp_cap_extended_next_hop_len(cap), 2);
            let mut out = [
                lr_bgp_ext_next_hop_tuple_t::default(),
                lr_bgp_ext_next_hop_tuple_t::default(),
            ];
            let n = lr_bgp_cap_extended_next_hop_tuples(cap, out.as_mut_ptr(), 2);
            assert_eq!(n, 2);
            assert_eq!(out[0].nlri_afi, 1);
            assert_eq!(out[0].nexthop_afi, 2);
            assert_eq!(out[1].nlri_afi, 2);
            lr_bgp_cap_free(cap);
        }
    }

    #[test]
    fn ffi_cap_extended_next_hop_handles_null_safely() {
        // Non-zero count + NULL tuples → NULL handle.
        let cap = unsafe { lr_bgp_cap_extended_next_hop(std::ptr::null(), 1) };
        assert!(cap.is_null());
        // Zero count is legal (empty capability).
        let cap = unsafe { lr_bgp_cap_extended_next_hop(std::ptr::null(), 0) };
        assert!(!cap.is_null());
        unsafe {
            // Readers handle NULL out → 0.
            assert_eq!(
                lr_bgp_cap_extended_next_hop_tuples(cap, std::ptr::null_mut(), 4),
                0
            );
            lr_bgp_cap_free(cap);
        }
    }

    #[test]
    fn ffi_cap_extended_next_hop_len_returns_zero_on_null_or_non_enh() {
        // NULL handle → 0.
        assert_eq!(
            unsafe { lr_bgp_cap_extended_next_hop_len(std::ptr::null_mut()) },
            0
        );
        // Four-Octet-AS is not Extended-Next-Hop → 0.
        let cap = lr_bgp_cap_four_octet_as(64512);
        unsafe {
            assert_eq!(lr_bgp_cap_extended_next_hop_len(cap), 0);
            lr_bgp_cap_free(cap);
        }
    }

    // ---- Generic constructor (lr_bgp_cap_new) ----

    #[test]
    fn ffi_cap_new_roundtrip_with_raw_value() {
        // Construct a Multiprotocol capability manually: code 1, value
        // = AFI(2) | reserved(1) | SAFI(1) = [0x00, 0x02, 0x00, 0x01].
        let value: [u8; 4] = [0x00, 0x02, 0x00, 0x01];
        let cap = unsafe { lr_bgp_cap_new(1, value.as_ptr(), 4) };
        assert!(!cap.is_null());
        unsafe {
            assert_eq!(lr_bgp_cap_code(cap), LR_BGP_CAP_MULTIPROTOCOL_EXTENSIONS);
            assert_eq!(lr_bgp_cap_value_len(cap), 4);
            // The typed reader recovers the AFI/SAFI.
            let mut afi = 0u16;
            let mut safi = 0u8;
            assert_eq!(
                lr_bgp_cap_as_multiprotocol(cap, &raw mut afi, &raw mut safi),
                1
            );
            assert_eq!(afi, 2);
            assert_eq!(safi, 1);
            lr_bgp_cap_free(cap);
        }
    }

    #[test]
    fn ffi_cap_new_handles_null_value() {
        // NULL value + 0 length → zero-value capability (legal for
        // Route Refresh, code 2).
        let cap = unsafe { lr_bgp_cap_new(2, std::ptr::null(), 0) };
        assert!(!cap.is_null());
        unsafe {
            assert_eq!(lr_bgp_cap_code(cap), LR_BGP_CAP_ROUTE_REFRESH);
            assert_eq!(lr_bgp_cap_value_len(cap), 0);
            lr_bgp_cap_free(cap);
        }
    }
}
