//! BGP-LS TLV envelope codec (RFC 7752 §3.1) and BGP-LS Attribute
//! TLV stream codec (RFC 7752 §3.3).
//!
//! Mirrors the public Rust API of `lr_bgp::path::bgp_ls::{Tlv,
//! decode_tlv_stream, encode_tlv_stream}` and `lr_bgp::path::bgp_ls_attr`
//! constants. This is the Layer-1 wire codec — a higher-level typed
//! view (`BgpLsAttr` / `BgpLsAttrTlv`) stays on the Rust side for now;
//! this FFI exposes the raw TLV-tuple surface so a C embedder can
//! decode / inspect / re-encode BGP-LS Attribute bytes without going
//! through the daemon.

#![allow(unused_unsafe)]
#![allow(unused_imports)]
#![allow(dead_code)]

use lr_bgp::path::bgp_ls::{decode_tlv_stream, encode_tlv_stream, Tlv};

use crate::error::{set_last_error, LrError, LR_ERR_PANIC};
use crate::guarded;
use crate::handle::lr_bytes_t;

const LR_ERR_NULL: i32 = LrError::Null as i32;
const LR_ERR_OTHER: i32 = LrError::Other as i32;

/// Opaque `Tlv` handle.
#[repr(C)]
pub struct OpaqueBgpLsTlv {
    _private: [u8; 0],
}
pub type lr_bgp_ls_tlv_t = *mut OpaqueBgpLsTlv;

/// Opaque `Vec<Tlv>` handle (the decoded TLV stream).
#[repr(C)]
pub struct OpaqueBgpLsTlvVec {
    _private: [u8; 0],
}
pub type lr_bgp_ls_tlv_vec_t = *mut OpaqueBgpLsTlvVec;

fn box_tlv(t: Tlv) -> lr_bgp_ls_tlv_t {
    Box::into_raw(Box::new(t)) as lr_bgp_ls_tlv_t
}
unsafe fn borrow_tlv(t: lr_bgp_ls_tlv_t) -> Option<&'static Tlv> {
    if t.is_null() {
        return None;
    }
    Some(unsafe { &*(t as *const Tlv) })
}
unsafe fn unbox_tlv(t: lr_bgp_ls_tlv_t) -> Option<Box<Tlv>> {
    if t.is_null() {
        return None;
    }
    Some(unsafe { Box::from_raw(t as *mut Tlv) })
}

/// Construct a TLV from `(type, value_bytes)`.
///
/// # Safety
/// `value` must point to `value_len` readable bytes.
#[no_mangle]
pub unsafe extern "C" fn lr_bgp_ls_tlv_new(
    tlv_type: u16,
    value: *const u8,
    value_len: usize,
) -> lr_bgp_ls_tlv_t {
    guarded(
        || unsafe {
            let v: Vec<u8> = if value.is_null() || value_len == 0 {
                Vec::new()
            } else {
                unsafe { std::slice::from_raw_parts(value, value_len) }.to_vec()
            };
            box_tlv(Tlv {
                ty: tlv_type,
                value: v,
            })
        },
        std::ptr::null_mut(),
    )
}

/// Read the 16-bit TLV type.
///
/// # Safety
/// `t` must be a valid handle.
#[no_mangle]
pub unsafe extern "C" fn lr_bgp_ls_tlv_type(t: lr_bgp_ls_tlv_t) -> u16 {
    guarded(|| unsafe { borrow_tlv(t).map(|x| x.ty).unwrap_or(0) }, 0)
}

/// Read the value length.
///
/// # Safety
/// `t` must be a valid handle.
#[no_mangle]
pub unsafe extern "C" fn lr_bgp_ls_tlv_value_len(t: lr_bgp_ls_tlv_t) -> usize {
    guarded(
        || unsafe { borrow_tlv(t).map(|x| x.value.len()).unwrap_or(0) },
        0,
    )
}

/// Copy the TLV value bytes into `out` (caller-allocated buffer of
/// at least `lr_bgp_ls_tlv_value_len` bytes). Returns the number of
/// bytes copied (clamped to `cap`).
///
/// # Safety
/// `t` must be a valid handle; `out` must point to writable memory of
/// at least `cap` bytes.
#[no_mangle]
pub unsafe extern "C" fn lr_bgp_ls_tlv_value(t: lr_bgp_ls_tlv_t, out: *mut u8, cap: usize) -> i32 {
    guarded(
        || unsafe {
            let Some(tlv) = borrow_tlv(t) else {
                return LR_ERR_NULL;
            };
            if out.is_null() {
                return LR_ERR_NULL;
            }
            let n = tlv.value.len().min(cap);
            unsafe {
                std::ptr::copy_nonoverlapping(tlv.value.as_ptr(), out, n);
            }
            n as i32
        },
        LR_ERR_PANIC,
    )
}

/// Drop a boxed `Tlv`. Safe to call with `NULL`.
///
/// # Safety
/// `t` must have been produced by [`lr_bgp_ls_tlv_new`] and not
/// already freed.
#[no_mangle]
pub unsafe extern "C" fn lr_bgp_ls_tlv_free(t: lr_bgp_ls_tlv_t) {
    guarded(
        || unsafe {
            drop(unbox_tlv(t));
        },
        (),
    )
}

/// Decode a TLV stream (RFC 7752 §3.1 — concatenation of 4-byte-header
/// TLVs). Returns a freshly-allocated `lr_bgp_ls_tlv_vec_t`.
///
/// # Safety
/// `data` must point to `len` readable bytes; `out` must point to
/// writable `lr_bgp_ls_tlv_vec_t`.
#[no_mangle]
pub unsafe extern "C" fn lr_bgp_ls_decode_tlv_stream(
    data: *const u8,
    len: usize,
    out: *mut lr_bgp_ls_tlv_vec_t,
) -> i32 {
    guarded(
        || unsafe {
            if data.is_null() || out.is_null() {
                return LR_ERR_NULL;
            }
            let slice = unsafe { std::slice::from_raw_parts(data, len) };
            match decode_tlv_stream(slice) {
                Ok(tlvs) => {
                    unsafe {
                        *out = Box::into_raw(Box::new(tlvs)) as lr_bgp_ls_tlv_vec_t;
                    }
                    0
                }
                Err(e) => {
                    set_last_error(format!("{:?}", e));
                    LR_ERR_OTHER
                }
            }
        },
        LR_ERR_PANIC,
    )
}

/// Encode a TLV stream back to wire bytes (RFC 7752 §3.1). The
/// caller frees `*out` with [`crate::bytes::lr_bytes_free`].
///
/// # Safety
/// `vec` must be a valid handle; `out` must point to writable
/// `lr_bytes_t`.
#[no_mangle]
pub unsafe extern "C" fn lr_bgp_ls_encode_tlv_stream(
    vec: lr_bgp_ls_tlv_vec_t,
    out: *mut lr_bytes_t,
) -> i32 {
    guarded(
        || unsafe {
            if vec.is_null() || out.is_null() {
                return LR_ERR_NULL;
            }
            let tlvs: &Vec<Tlv> = unsafe { &*(vec as *const Vec<Tlv>) };
            // Inline encode: 4-byte TLV header (type + length) per
            // entry, big-endian. We avoid the lr-bgp
            // `encode_tlv_stream` helper because it constructs a
            // `WriteBuf::new(&mut Vec::with_capacity(n))` which
            // requires an initialised backing buffer — instead we
            // build the wire bytes directly, which is what the
            // underlying `Tlv::encode` would do anyway.
            let total: usize = tlvs.iter().map(Tlv::wire_len).sum();
            let mut bytes = Vec::with_capacity(total);
            for t in tlvs {
                bytes.extend_from_slice(&t.ty.to_be_bytes());
                let len = t.value.len();
                if len > u16::MAX as usize {
                    set_last_error(format!(
                        "lr_bgp_ls_encode_tlv_stream: TLV value length {len} exceeds u16::MAX"
                    ));
                    return LR_ERR_OTHER;
                }
                bytes.extend_from_slice(&(len as u16).to_be_bytes());
                bytes.extend_from_slice(&t.value);
            }
            unsafe { *out = lr_bytes_t::from_vec(bytes) }
            0
        },
        LR_ERR_PANIC,
    )
}

/// Number of TLVs in a decoded stream.
///
/// # Safety
/// `vec` must be a valid handle.
#[no_mangle]
pub unsafe extern "C" fn lr_bgp_ls_tlv_vec_len(vec: lr_bgp_ls_tlv_vec_t) -> usize {
    guarded(
        || unsafe {
            if vec.is_null() {
                return 0;
            }
            let tlvs: &Vec<Tlv> = unsafe { &*(vec as *const Vec<Tlv>) };
            tlvs.len()
        },
        0,
    )
}

/// Borrow one TLV by index. The returned handle is borrowed (do NOT
/// free it); it is invalid after `lr_bgp_ls_tlv_vec_free` runs.
///
/// # Safety
/// `vec` must be a valid handle; `index` must be in range.
#[no_mangle]
pub unsafe extern "C" fn lr_bgp_ls_tlv_vec_at(
    vec: lr_bgp_ls_tlv_vec_t,
    index: usize,
) -> lr_bgp_ls_tlv_t {
    guarded(
        || unsafe {
            if vec.is_null() {
                return std::ptr::null_mut();
            }
            let tlvs: &Vec<Tlv> = unsafe { &*(vec as *const Vec<Tlv>) };
            match tlvs.get(index) {
                Some(t) => t as *const Tlv as lr_bgp_ls_tlv_t,
                None => std::ptr::null_mut(),
            }
        },
        std::ptr::null_mut(),
    )
}

/// Drop a boxed `Vec<Tlv>`. Safe to call with `NULL`.
///
/// # Safety
/// `vec` must have been produced by [`lr_bgp_ls_decode_tlv_stream`]
/// and not already freed.
#[no_mangle]
pub unsafe extern "C" fn lr_bgp_ls_tlv_vec_free(vec: lr_bgp_ls_tlv_vec_t) {
    guarded(
        || unsafe {
            if vec.is_null() {
                return;
            }
            drop(unsafe { Box::from_raw(vec as *mut Vec<Tlv>) });
        },
        (),
    )
}

// ---- BGP-LS Attribute TLV type constants ----
//
// Re-export the well-known code points from
// `lr_bgp::path::bgp_ls_attr::tlv_type` so a C embedder can switch on
// them when reading a decoded TLV stream. Each `#define` below
// mirrors the corresponding Rust constant.

/// Node Flag Bits (RFC 7752 §3.3.1.1). 1-byte value.
pub const LR_BGP_LS_TLV_NODE_FLAG_BITS: u16 = 1024;
/// Opaque Node Attribute (RFC 7752 §3.3.1.5). Variable-length.
pub const LR_BGP_LS_TLV_OPAQUE_NODE_ATTRIBUTE: u16 = 1025;
/// Node Name (RFC 7752 §3.3.1.3). Variable-length UTF-8.
pub const LR_BGP_LS_TLV_NODE_NAME: u16 = 1026;
/// IS-IS Area Identifier (RFC 7752 §3.3.1.2). Variable-length.
pub const LR_BGP_LS_TLV_ISIS_AREA_IDENTIFIER: u16 = 1027;
/// IPv4 Router-ID of Local Node (RFC 5305 §4.3). 4-byte value.
pub const LR_BGP_LS_TLV_IPV4_ROUTER_ID_LOCAL: u16 = 1028;
/// IPv6 Router-ID of Local Node (RFC 6119 §4.1). 16-byte value.
pub const LR_BGP_LS_TLV_IPV6_ROUTER_ID_LOCAL: u16 = 1029;
/// SRv6 Capabilities (RFC 9514 §3.1). 4-byte value.
pub const LR_BGP_LS_TLV_SRV6_CAPABILITIES: u16 = 1038;

/// Admin Group / Color (RFC 7752 §3.3.2.1). 4-byte value.
pub const LR_BGP_LS_TLV_ADMIN_GROUP: u16 = 1088;
/// Maximum Link Bandwidth (RFC 7752 §3.3.2.2). 4-byte IEEE float.
pub const LR_BGP_LS_TLV_MAX_LINK_BANDWIDTH: u16 = 1089;
/// Max Reservable Link Bandwidth (RFC 7752 §3.3.2.2). 4-byte IEEE float.
pub const LR_BGP_LS_TLV_MAX_RESERVABLE_LINK_BANDWIDTH: u16 = 1090;
/// Unreserved Link Bandwidth (RFC 7752 §3.3.2.2). 8 × 4-byte IEEE floats.
pub const LR_BGP_LS_TLV_UNRESERVED_LINK_BANDWIDTH: u16 = 1091;
/// TED Metric (RFC 7752 §3.3.2.3 / RFC 3630 §2.5.5). 4-byte value.
pub const LR_BGP_LS_TLV_TE_DEFAULT_METRIC: u16 = 1092;
/// Link Protection Type (RFC 7752 §3.3.2.4). 2-byte value.
pub const LR_BGP_LS_TLV_LINK_PROTECTION_TYPE: u16 = 1093;
/// MPLS Mask (RFC 7752 §3.3.2.5). 1-byte value.
pub const LR_BGP_LS_TLV_MPLS_MASK: u16 = 1094;
/// IGP Metric (RFC 7752 §3.3.2.6). Variable-length.
pub const LR_BGP_LS_TLV_IGP_METRIC: u16 = 1095;
/// IPv4 Router-ID of Remote Node (RFC 5305 §4.3). 4-byte value.
pub const LR_BGP_LS_TLV_IPV4_ROUTER_ID_REMOTE: u16 = 1030;
/// IPv6 Router-ID of Remote Node (RFC 6119 §4.1). 16-byte value.
pub const LR_BGP_LS_TLV_IPV6_ROUTER_ID_REMOTE: u16 = 1031;

/// Prefix Metric (RFC 7752 §3.3.3.1). 4-byte value.
pub const LR_BGP_LS_TLV_PREFIX_METRIC: u16 = 1155;
/// Prefix Flag Bits (RFC 7752 §3.3.3.2). 1-byte value.
pub const LR_BGP_LS_TLV_PREFIX_FLAG_BITS: u16 = 1156;
/// Source Router-ID (RFC 7752 §3.3.3.4). 4-byte or 8-byte value.
pub const LR_BGP_LS_TLV_SOURCE_ROUTER_ID: u16 = 1170;

/// SRv6 Endpoint Behavior (RFC 9514 §7.1). 4-byte value.
pub const LR_BGP_LS_TLV_SRV6_ENDPOINT_BEHAVIOR: u16 = 1250;
/// SRv6 BGP Peering SID (RFC 9514 §7.2). Variable-length.
pub const LR_BGP_LS_TLV_SRV6_BGP_PEERING_SID: u16 = 1251;
/// SRv6 SID Structure (RFC 9514 §7.3). 4-byte value.
pub const LR_BGP_LS_TLV_SRV6_SID_STRUCTURE: u16 = 1252;

/// BGP-LS path attribute type code (RFC 7752 §13 — value 29 in the
/// BGP Path Attributes sub-registry).
pub const LR_BGP_ATTR_TYPE_BGP_LS: u8 = 29;

/// AFI / SAFI for BGP-LS (RFC 7752 §13).
pub const LR_BGP_LS_AFI: u16 = 16388;
pub const LR_BGP_LS_SAFI: u8 = 71;
pub const LR_BGP_LS_SAFI_VPN: u8 = 72;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ffi_tlv_new_and_readers() {
        let value = [0xdeu8, 0xad, 0xbe, 0xef];
        let t = unsafe { lr_bgp_ls_tlv_new(1024, value.as_ptr(), 4) };
        assert!(!t.is_null());
        assert_eq!(unsafe { lr_bgp_ls_tlv_type(t) }, 1024);
        assert_eq!(unsafe { lr_bgp_ls_tlv_value_len(t) }, 4);
        let mut buf = [0u8; 4];
        let n = unsafe { lr_bgp_ls_tlv_value(t, buf.as_mut_ptr(), 4) };
        assert_eq!(n, 4);
        assert_eq!(buf, value);
        unsafe { lr_bgp_ls_tlv_free(t) };
    }

    #[test]
    fn ffi_decode_encode_roundtrip() {
        // Build two TLVs as wire bytes: type 1024 (Node Flag Bits)
        // value 0x01, and type 1095 (IGP Metric) value 0x0000000A.
        let wire: Vec<u8> = vec![
            0x04, 0x00, 0x00, 0x01, 0x01, // TLV 1024, len 1, value 0x01
            0x04, 0x47, 0x00, 0x04, 0x00, 0x00, 0x00, 0x0A, // TLV 1095, len 4, value 0x0A
        ];

        let mut vec: lr_bgp_ls_tlv_vec_t = std::ptr::null_mut();
        let rc = unsafe { lr_bgp_ls_decode_tlv_stream(wire.as_ptr(), wire.len(), &raw mut vec) };
        assert_eq!(rc, 0);
        assert!(!vec.is_null());
        assert_eq!(unsafe { lr_bgp_ls_tlv_vec_len(vec) }, 2);

        let t0 = unsafe { lr_bgp_ls_tlv_vec_at(vec, 0) };
        assert!(!t0.is_null());
        assert_eq!(unsafe { lr_bgp_ls_tlv_type(t0) }, 1024);
        assert_eq!(unsafe { lr_bgp_ls_tlv_value_len(t0) }, 1);

        let t1 = unsafe { lr_bgp_ls_tlv_vec_at(vec, 1) };
        assert!(!t1.is_null());
        assert_eq!(unsafe { lr_bgp_ls_tlv_type(t1) }, 1095);
        assert_eq!(unsafe { lr_bgp_ls_tlv_value_len(t1) }, 4);

        // Re-encode and compare with the input.
        let mut out = lr_bytes_t {
            ptr: std::ptr::null_mut(),
            len: 0,
            cap: 0,
        };
        let rc = unsafe { lr_bgp_ls_encode_tlv_stream(vec, &raw mut out) };
        assert_eq!(rc, 0);
        assert_eq!(out.len, wire.len());
        unsafe {
            let v = Vec::from_raw_parts(out.ptr, out.len, out.cap);
            assert_eq!(v, wire);
            lr_bgp_ls_tlv_vec_free(vec);
        }
    }

    #[test]
    fn ffi_free_handles_null_safely() {
        unsafe {
            lr_bgp_ls_tlv_free(std::ptr::null_mut());
            lr_bgp_ls_tlv_vec_free(std::ptr::null_mut());
        }
    }
}
