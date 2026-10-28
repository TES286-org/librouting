//! OSPF enum-introspection FFI — `from_u8` / `from_u16` / `name` /
//! `e_bit` / `from_e_bit` / `to_word` / `from_word` helpers for the
//! Rust `pub enum`s in `lr_ospf::{packet, lsa, neighbor, interface,
//! external, exchange, lsa::grace, origination::RouterLsaFlags}`.
//!
//! Mirrors the Rust pub API so a C embedder can map a wire byte back
//! to a named constant (or render a numeric value to a human-readable
//! name for `show` output) without re-implementing the enum tables.
//!
//! Every entry point runs inside the crate's `catch_unwind` barrier
//! (`guarded`): a panic returns the documented sentinel value
//! (`LR_OSPF_ENUM_UNKNOWN` for the `from_*` mappings, `NULL` for the
//! `name` helpers).

#![allow(unused_unsafe)]

use lr_ospf::external::ExternalMetricType;
use lr_ospf::interface::IfState;
use lr_ospf::neighbor::NeighborState;
use lr_ospf::packet::{OspfPacketType, OspfVersion};
use lr_ospf::{exchange::Phase, lsa::grace::GraceReason, lsa::grace::GraceTlvType};

use crate::guarded;

/// Sentinel returned by `lr_ospf_*_from_u8` / `_from_u16` when the
/// wire value does not map to a known enum variant. Negative so a C
/// embedder can switch on it without colliding with the (always
/// non-negative) valid variant values.
pub const LR_OSPF_ENUM_UNKNOWN: i32 = -1;

// ---- OspfPacketType (RFC 2328 §A.3) ----

/// `OspfPacketType::from_u8` — returns one of the `LR_OSPF_PACKET_*`
/// constants, or `LR_OSPF_ENUM_UNKNOWN` when `v` is not a known packet
/// type.
#[no_mangle]
pub extern "C" fn lr_ospf_packet_type_from_u8(v: u8) -> i32 {
    guarded(
        || match OspfPacketType::from_u8(v) {
            Some(t) => t as i32,
            None => LR_OSPF_ENUM_UNKNOWN,
        },
        LR_OSPF_ENUM_UNKNOWN,
    )
}

/// `OspfPacketType::name` — returns a NUL-terminated ASCII name
/// (`"Hello"` / `"DBDesc"` / `"LS-Request"` / `"LS-Update"` /
/// `"LS-Ack"`) or `NULL` when `v` is not a known packet type.
///
/// The name is borrowed from a per-call `CString` allocated in a
/// thread-local buffer — the pointer is valid only until the next
/// `lr_ospf_packet_type_name` call on this thread.
#[no_mangle]
pub extern "C" fn lr_ospf_packet_type_name(v: u8) -> *const std::os::raw::c_char {
    thread_local! {
        static BUF: std::cell::RefCell<Option<std::ffi::CString>> = const { std::cell::RefCell::new(None) };
    }
    guarded(
        || match OspfPacketType::from_u8(v) {
            Some(t) => {
                let s = t.to_string();
                let c = std::ffi::CString::new(s).unwrap_or_default();
                BUF.with(|b| *b.borrow_mut() = Some(c));
                BUF.with(|b| {
                    b.borrow()
                        .as_ref()
                        .map(|c| c.as_ptr())
                        .unwrap_or(std::ptr::null())
                })
            }
            None => std::ptr::null(),
        },
        std::ptr::null(),
    )
}

// ---- OspfVersion (RFC 2328 / RFC 5340) ----

/// `OspfVersion::from_u8` — returns 2 (OSPFv2) or 3 (OSPFv3), or
/// `LR_OSPF_ENUM_UNKNOWN` when `v` is not a supported version.
#[no_mangle]
pub extern "C" fn lr_ospf_version_from_u8(v: u8) -> i32 {
    guarded(
        || match OspfVersion::from_u8(v) {
            Some(t) => t as i32,
            None => LR_OSPF_ENUM_UNKNOWN,
        },
        LR_OSPF_ENUM_UNKNOWN,
    )
}

// ---- NeighborState (RFC 2328 §10.1) ----

/// `NeighborState::name` — returns a NUL-terminated ASCII name
/// (`"Down"` / `"Attempt"` / `"Init"` / `"2-Way"` / `"ExStart"` /
/// `"Exchange"` / `"Loading"` / `"Full"`). Returns `NULL` when `state`
/// is outside the 1..=8 variant range.
///
/// The name is borrowed from a per-call `CString` allocated in a
/// thread-local buffer — the pointer is valid only until the next
/// `lr_ospf_neighbor_state_name` call on this thread.
#[no_mangle]
pub extern "C" fn lr_ospf_neighbor_state_name(state: u8) -> *const std::os::raw::c_char {
    thread_local! {
        static BUF: std::cell::RefCell<Option<std::ffi::CString>> = const { std::cell::RefCell::new(None) };
    }
    guarded(
        || {
            if !(1..=8).contains(&state) {
                return std::ptr::null();
            }
            // SAFETY: NeighborState is `repr(u8)` and we have just
            // validated the value is in the variant range, so the
            // transmute is sound.
            let s = unsafe { std::mem::transmute::<u8, NeighborState>(state) };
            let c = std::ffi::CString::new(s.name()).unwrap_or_default();
            BUF.with(|b| *b.borrow_mut() = Some(c));
            BUF.with(|b| {
                b.borrow()
                    .as_ref()
                    .map(|c| c.as_ptr())
                    .unwrap_or(std::ptr::null())
            })
        },
        std::ptr::null(),
    )
}

// ---- IfState (RFC 2328 §9.4 — DR election interface state) ----

/// `IfState::name` — returns a NUL-terminated ASCII name
/// (`"Down"` / `"Loopback"` / `"Waiting"` / `"Point-to-Point"` /
/// `"DR-Other"` / `"Backup"` / `"DR"`). Returns `NULL` when `state`
/// is outside the 1..=7 variant range.
///
/// The name is borrowed from a per-call `CString` allocated in a
/// thread-local buffer — the pointer is valid only until the next
/// `lr_ospf_if_state_name` call on this thread.
#[no_mangle]
pub extern "C" fn lr_ospf_if_state_name(state: u8) -> *const std::os::raw::c_char {
    thread_local! {
        static BUF: std::cell::RefCell<Option<std::ffi::CString>> = const { std::cell::RefCell::new(None) };
    }
    guarded(
        || {
            // IfState is `repr(u8)` with variants 1..=7 — transmute
            // via the wire byte. We map explicitly to avoid relying on
            // a TryFrom impl (the Rust enum does not provide one).
            let s = match state {
                1 => IfState::Down,
                2 => IfState::Loopback,
                3 => IfState::Waiting,
                4 => IfState::PointToPoint,
                5 => IfState::DrOther,
                6 => IfState::Backup,
                7 => IfState::Dr,
                _ => return std::ptr::null(),
            };
            let c = std::ffi::CString::new(s.name()).unwrap_or_default();
            BUF.with(|b| *b.borrow_mut() = Some(c));
            BUF.with(|b| {
                b.borrow()
                    .as_ref()
                    .map(|c| c.as_ptr())
                    .unwrap_or(std::ptr::null())
            })
        },
        std::ptr::null(),
    )
}

// ---- Phase (RFC 2328 §10.3–§10.8 — DBD exchange phase) ----

/// `Phase::name` — returns a NUL-terminated ASCII name
/// (`"ExStart"` / `"Exchange"` / `"Loading"` / `"Full"`). The Phase
/// enum is internal-only (not `repr(u8)`), so `phase` here is the
/// 0..=3 index used by the FFI to identify the variant.
///
/// The name is borrowed from a per-call `CString` allocated in a
/// thread-local buffer — the pointer is valid only until the next
/// `lr_ospf_db_exchange_phase_name` call on this thread.
#[no_mangle]
pub extern "C" fn lr_ospf_db_exchange_phase_name(phase: u8) -> *const std::os::raw::c_char {
    thread_local! {
        static BUF: std::cell::RefCell<Option<std::ffi::CString>> = const { std::cell::RefCell::new(None) };
    }
    guarded(
        || {
            let p = match phase {
                0 => Phase::ExStart,
                1 => Phase::Exchange,
                2 => Phase::Loading,
                3 => Phase::Full,
                _ => return std::ptr::null(),
            };
            let c = std::ffi::CString::new(p.name()).unwrap_or_default();
            BUF.with(|b| *b.borrow_mut() = Some(c));
            BUF.with(|b| {
                b.borrow()
                    .as_ref()
                    .map(|c| c.as_ptr())
                    .unwrap_or(std::ptr::null())
            })
        },
        std::ptr::null(),
    )
}

// ---- ExternalMetricType (RFC 2328 §2.3 / §A.4.5) ----

/// `ExternalMetricType::e_bit` — returns 1 when `t == Type2` (the
/// E-bit must be set in the AS-External LSA body), 0 otherwise.
/// `t` is the numeric variant: 0 = Type1, 1 = Type2 (matching the
/// `#[repr(u8)]` order in `lr_ospf::external::ExternalMetricType`).
#[no_mangle]
pub extern "C" fn lr_ospf_external_metric_type_e_bit(t: u8) -> u8 {
    guarded(
        || {
            let m = match t {
                0 => ExternalMetricType::Type1,
                1 => ExternalMetricType::Type2,
                _ => return 0,
            };
            m.e_bit() as u8
        },
        0,
    )
}

/// `ExternalMetricType::from_e_bit` — returns 0 (Type1) when `e_bit`
/// is 0, 1 (Type2) when `e_bit` is non-zero. The numeric encoding
/// matches the `#[repr(u8)]` order so C consumers can switch on the
/// integer directly.
#[no_mangle]
pub extern "C" fn lr_ospf_external_metric_type_from_e_bit(e_bit: u8) -> u8 {
    guarded(
        || match ExternalMetricType::from_e_bit(e_bit != 0) {
            ExternalMetricType::Type1 => 0,
            ExternalMetricType::Type2 => 1,
        },
        0,
    )
}

// ---- GraceTlvType (RFC 3623 §2.1 / RFC 5187 §2.1) ----

/// `GraceTlvType::from_u16` — returns one of the
/// `LR_OSPF_GRACE_TLV_*` constants (1 = grace period, 2 = reason,
/// 3 = IPv4 address, 4 = IPv6 address), or `LR_OSPF_ENUM_UNKNOWN` for
/// an unknown TLV type.
#[no_mangle]
pub extern "C" fn lr_ospf_grace_tlv_type_from_u16(v: u16) -> i32 {
    guarded(
        || match GraceTlvType::from_u16(v) {
            Some(t) => t as i32,
            None => LR_OSPF_ENUM_UNKNOWN,
        },
        LR_OSPF_ENUM_UNKNOWN,
    )
}

// ---- GraceReason (RFC 3623 §2.1 / RFC 5187 §2.1) ----

/// `GraceReason::from_u8` — returns one of the
/// `LR_OSPF_GRACE_REASON_*` constants (0 = unspecified, 1 = software
/// restart, 2 = software reload/upgrade, 3 = control-plane switchover).
#[no_mangle]
pub extern "C" fn lr_ospf_grace_reason_from_u8(v: u8) -> i32 {
    guarded(|| GraceReason::from_u8(v) as i32, LR_OSPF_ENUM_UNKNOWN)
}

// ---- AuType (RFC 2328 §A.1 — OSPFv2 authentication type) ----
//
// Already exposed as `lr_ospf_au_type_from_u16` in `ospf_auth.rs` —
// that variant returns the `LR_OSPF_AU_TYPE_*` u16 directly. No
// additional surface here.

// ---- RouterLsaFlags (RFC 2328 §A.4.2 — V/E/B bits) ----

/// `RouterLsaFlags::V_BIT` (RFC 2328 §A.4.2 — virtual-link bit).
pub const LR_OSPF_ROUTER_LSA_FLAG_V_BIT: u8 = lr_ospf::origination::RouterLsaFlags::V_BIT;
/// `RouterLsaFlags::E_BIT` (RFC 2328 §A.4.2 — AS-border-router bit).
pub const LR_OSPF_ROUTER_LSA_FLAG_E_BIT: u8 = lr_ospf::origination::RouterLsaFlags::E_BIT;
/// `RouterLsaFlags::B_BIT` (RFC 2328 §A.4.2 — area-border-router bit).
pub const LR_OSPF_ROUTER_LSA_FLAG_B_BIT: u8 = lr_ospf::origination::RouterLsaFlags::B_BIT;

/// `RouterLsaFlags::to_word` — pack the V/E/B bits into the 2-byte
/// flags word that opens the Router-LSA body (the bits live in the
/// FIRST byte; the second byte is always zero on transmit).
#[no_mangle]
pub extern "C" fn lr_ospf_router_lsa_flags_to_word(virtual_link: u8, asbr: u8, border: u8) -> u16 {
    guarded(
        || {
            lr_ospf::origination::RouterLsaFlags {
                virtual_link: virtual_link != 0,
                asbr: asbr != 0,
                border: border != 0,
            }
            .to_word()
        },
        0,
    )
}

/// `RouterLsaFlags::from_word` — decode the 2-byte flags word into
/// its three component bits. Writes 1 to `*out_v` when the V bit is
/// set, 0 otherwise; same for `*out_e` and `*out_b`.
///
/// Returns `LR_ERR_NULL` (-1) when any of the out-pointers is NULL.
#[no_mangle]
pub unsafe extern "C" fn lr_ospf_router_lsa_flags_from_word(
    word: u16,
    out_v: *mut u8,
    out_e: *mut u8,
    out_b: *mut u8,
) -> i32 {
    guarded(
        || unsafe {
            if out_v.is_null() || out_e.is_null() || out_b.is_null() {
                return -1;
            }
            let f = lr_ospf::origination::RouterLsaFlags::from_word(word);
            unsafe {
                *out_v = f.virtual_link as u8;
                *out_e = f.asbr as u8;
                *out_b = f.border as u8;
            }
            0
        },
        -1,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ffi_packet_type_round_trip() {
        assert_eq!(lr_ospf_packet_type_from_u8(1), 1);
        assert_eq!(lr_ospf_packet_type_from_u8(2), 2);
        assert_eq!(lr_ospf_packet_type_from_u8(5), 5);
        assert_eq!(lr_ospf_packet_type_from_u8(99), LR_OSPF_ENUM_UNKNOWN);
    }

    #[test]
    fn ffi_packet_type_name_returns_static_cstr() {
        let p = lr_ospf_packet_type_name(1);
        assert!(!p.is_null());
        let s = unsafe { std::ffi::CStr::from_ptr(p) }.to_str().unwrap();
        assert_eq!(s, "Hello");
        let p = lr_ospf_packet_type_name(99);
        assert!(p.is_null());
    }

    #[test]
    fn ffi_version_from_u8() {
        assert_eq!(lr_ospf_version_from_u8(2), 2);
        assert_eq!(lr_ospf_version_from_u8(3), 3);
        assert_eq!(lr_ospf_version_from_u8(1), LR_OSPF_ENUM_UNKNOWN);
    }

    #[test]
    fn ffi_neighbor_state_name() {
        let p = lr_ospf_neighbor_state_name(8);
        assert!(!p.is_null());
        let s = unsafe { std::ffi::CStr::from_ptr(p) }.to_str().unwrap();
        assert_eq!(s, "Full");
        let p = lr_ospf_neighbor_state_name(99);
        assert!(p.is_null());
    }

    #[test]
    fn ffi_external_metric_type_e_bit() {
        assert_eq!(lr_ospf_external_metric_type_e_bit(0), 0); // Type1
        assert_eq!(lr_ospf_external_metric_type_e_bit(1), 1); // Type2
        assert_eq!(lr_ospf_external_metric_type_e_bit(99), 0); // unknown → 0
    }

    #[test]
    fn ffi_external_metric_type_from_e_bit() {
        assert_eq!(lr_ospf_external_metric_type_from_e_bit(0), 0); // Type1
        assert_eq!(lr_ospf_external_metric_type_from_e_bit(1), 1); // Type2
    }

    #[test]
    fn ffi_router_lsa_flags_to_from_word_round_trip() {
        let word = lr_ospf_router_lsa_flags_to_word(1, 0, 1); // V + B
        let mut v = 0u8;
        let mut e = 0u8;
        let mut b = 0u8;
        let rc =
            unsafe { lr_ospf_router_lsa_flags_from_word(word, &raw mut v, &raw mut e, &raw mut b) };
        assert_eq!(rc, 0);
        assert_eq!(v, 1);
        assert_eq!(e, 0);
        assert_eq!(b, 1);
    }

    #[test]
    fn ffi_router_lsa_flag_bits_match_rfc() {
        assert_eq!(LR_OSPF_ROUTER_LSA_FLAG_V_BIT, 0x04);
        assert_eq!(LR_OSPF_ROUTER_LSA_FLAG_E_BIT, 0x02);
        assert_eq!(LR_OSPF_ROUTER_LSA_FLAG_B_BIT, 0x01);
    }

    #[test]
    fn ffi_grace_reason_from_u8() {
        // GraceReason::from_u8 has no unknown sentinel — it falls back
        // to Unspecified (0) for any value not in the table.
        assert_eq!(lr_ospf_grace_reason_from_u8(0), 0);
        assert_eq!(lr_ospf_grace_reason_from_u8(1), 1); // SoftwareRestart
        assert_eq!(lr_ospf_grace_reason_from_u8(2), 2); // SoftwareReload
        assert_eq!(lr_ospf_grace_reason_from_u8(3), 3); // ControlPlaneSwitchover
        assert_eq!(lr_ospf_grace_reason_from_u8(99), 0); // unknown → Unspecified
    }

    #[test]
    fn ffi_grace_tlv_type_from_u16() {
        // GraceTlvType::from_u16 returns Some for known types, None for
        // unknown — surfaced as LR_OSPF_ENUM_UNKNOWN.
        assert_eq!(lr_ospf_grace_tlv_type_from_u16(1), 1); // Period
        assert_eq!(lr_ospf_grace_tlv_type_from_u16(2), 2); // Reason
        assert_eq!(lr_ospf_grace_tlv_type_from_u16(99), LR_OSPF_ENUM_UNKNOWN);
    }
}
