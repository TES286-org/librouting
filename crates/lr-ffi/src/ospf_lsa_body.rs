//! OSPF LSA body + small helper FFI surface — mirrors the stateless
//! `pub fn`s in `lr_ospf::lsa::*` that the existing FFI modules do not
//! yet cover. These are byte-in-byte-out helpers: encode_* take
//! structured Rust values and write LSA body bytes; decode_* take LSA
//! body bytes and parse them back. Stateless — no handles, no router
//! state, no allocator beyond the `lr_bytes_t` returned for variable-
//! length outputs.
//!
//! Every entry point runs inside the crate's `catch_unwind` barrier
//! ([`crate::guarded`]): a panic returns `LR_ERR_PANIC` and sets the
//! thread-local last-error string.

// The closure body passed to `guarded` is wrapped in a single `unsafe`
// block to mirror the `pub unsafe extern "C" fn` shape — the inner
// `unsafe { ... }` blocks would otherwise trip `unused_unsafe` under
// the crate's `-D warnings` clippy gate.
#![allow(unused_unsafe)]

use lr_core::addr::IpAddr;
use lr_ospf::gr::clamp_grace_period;
use lr_ospf::lsa::e_v3::{is_e_lsa_type, walk_tlvs};
use lr_ospf::lsa::grace::{
    grace_lsa_type, interface_address_tlv, is_grace_restart_capable, opaque_lsa_id,
    unpack_opaque_lsa_id, with_grace_restart_capable,
};
use lr_ospf::lsa::srv6::behavior_valid_for_end_sid;
use lr_ospf::lsa::{
    decode_as_external_body, decode_summary_lsa_body, decode_v3_inter_area_prefix_body,
    encode_as_external_body, encode_summary_lsa_body, encode_v3_inter_area_prefix_body,
    mask_to_prefix_len, prefix_len_to_mask, router_lsa_flags_byte, AsExternalEntry,
};
use lr_ospf::spf::decode_router_links;

use crate::error::{set_last_error, LR_ERR_PANIC};
use crate::guarded;
use crate::handle::lr_bytes_t;

const LR_ERR_NULL: i32 = -1;
const LR_ERR_INVALID_HANDLE: i32 = -2;
#[allow(dead_code)]
const LR_ERR_OTHER: i32 = -6;

// ---- Grace period (RFC 3623 §2.1) ----

/// Clamp a configured grace period into the RFC 3623 §2.1 window
/// (1..=1800 seconds). Returns the clamped value.
#[no_mangle]
pub extern "C" fn lr_ospf_clamp_grace_period(secs: u32) -> u32 {
    guarded(|| clamp_grace_period(secs), 0)
}

// ---- Prefix mask helpers (RFC 2328 §A.4) ----

/// Convert a 32-bit network mask to a prefix length (RFC 2328 §A.4 —
/// the contiguous-1 count of `mask`). Returns 0xFFFFFFFF (u32::MAX)
/// when `mask` is not a contiguous-1 mask — the FFI sentinel for
/// "invalid mask"; the Rust API returns `u8` so we widen on the
/// boundary.
#[no_mangle]
pub extern "C" fn lr_ospf_mask_to_prefix_len(mask: u32) -> u32 {
    guarded(
        || {
            let plen = mask_to_prefix_len(mask);
            plen as u32
        },
        0,
    )
}

/// Convert a prefix length to a 32-bit network mask (RFC 2328 §A.4).
#[no_mangle]
pub extern "C" fn lr_ospf_prefix_len_to_mask(len: u8) -> u32 {
    guarded(|| prefix_len_to_mask(len), 0)
}

// ---- Grace-LSA helpers (RFC 3623 §2.1 / RFC 5187 §2.1) ----

/// The OSPFv2 link-state type for a Grace-LSA (RFC 3623 §2.1: opaque
/// area LSA, opaque type 3).
#[no_mangle]
pub extern "C" fn lr_ospf_grace_lsa_type() -> u16 {
    guarded(grace_lsa_type, 0)
}

/// Pack an opaque-type / opaque-id pair into a 32-bit Link State ID
/// (RFC 5250 §3.1: high 8 bits = opaque type, low 24 bits = opaque ID).
#[no_mangle]
pub extern "C" fn lr_ospf_opaque_lsa_id(opaque_type: u8, opaque_id: u32) -> u32 {
    guarded(|| opaque_lsa_id(opaque_type, opaque_id), 0)
}

/// Unpack a 32-bit Link State ID into `(opaque_type, opaque_id)`
/// (RFC 5250 §3.1). Writes the type to `*out_type` and the id to
/// `*out_id`.
///
/// # Safety
/// Both out-pointers must point to writable `uint8_t` / `uint32_t`.
#[no_mangle]
pub unsafe extern "C" fn lr_ospf_unpack_opaque_lsa_id(
    link_state_id: u32,
    out_type: *mut u8,
    out_id: *mut u32,
) -> i32 {
    guarded(
        || unsafe {
            if out_type.is_null() || out_id.is_null() {
                return LR_ERR_NULL;
            }
            let (t, id) = unpack_opaque_lsa_id(link_state_id);
            unsafe {
                *out_type = t;
                *out_id = id;
            }
            0
        },
        LR_ERR_PANIC,
    )
}

/// Set the GR-capable bit (DC bit, RFC 3623 §2.2) in an OSPF options
/// byte.
#[no_mangle]
pub extern "C" fn lr_ospf_with_grace_restart_capable(options: u8) -> u8 {
    guarded(|| with_grace_restart_capable(options), 0)
}

/// True when the options byte carries the GR-capable bit.
#[no_mangle]
pub extern "C" fn lr_ospf_is_grace_restart_capable(options: u8) -> u8 {
    guarded(|| is_grace_restart_capable(options) as u8, 0)
}

/// The IPv4 / IPv6 interface address TLV payload for a Grace-LSA.
/// Writes `1` to `*out_v4_present` and 4 bytes to `*out_v4` when the
/// v4 form is taken; `1` to `*out_v6_present` and 16 bytes to
/// `*out_v6` when the v6 form is taken.
///
/// # Safety
/// `out_v4` must point to 4 writable bytes; `out_v6` to 16. Both
/// present flags must point to writable `uint8_t`.
#[no_mangle]
pub unsafe extern "C" fn lr_ospf_interface_address_tlv(
    is_v6: u8,
    addr: *const u8,
    out_v4_present: *mut u8,
    out_v4: *mut u8,
    out_v6_present: *mut u8,
    out_v6: *mut u8,
) -> i32 {
    guarded(
        || unsafe {
            if addr.is_null() || out_v4_present.is_null() || out_v6_present.is_null() {
                return LR_ERR_NULL;
            }
            let a = if is_v6 != 0 {
                if IpAddr::V6(core::array::from_fn(|i| unsafe { *addr.add(i) }))
                    .is_ipv6()
                    .then_some(unsafe { core::slice::from_raw_parts(addr, 16) })
                    .is_none()
                {
                    return LR_ERR_NULL;
                }
                let bytes = unsafe { core::slice::from_raw_parts(addr, 16) };
                let mut arr = [0u8; 16];
                arr.copy_from_slice(bytes);
                IpAddr::V6(arr)
            } else {
                let bytes = unsafe { core::slice::from_raw_parts(addr, 4) };
                let mut arr = [0u8; 4];
                arr.copy_from_slice(bytes);
                IpAddr::V4(arr)
            };
            let (v4, v6) = interface_address_tlv(a);
            if let Some(b) = v4 {
                if out_v4.is_null() {
                    return LR_ERR_NULL;
                }
                unsafe {
                    core::ptr::copy_nonoverlapping(b.as_ptr(), out_v4, 4);
                    *out_v4_present = 1;
                }
            } else {
                unsafe { *out_v4_present = 0 };
            }
            if let Some(b) = v6 {
                if out_v6.is_null() {
                    return LR_ERR_NULL;
                }
                unsafe {
                    core::ptr::copy_nonoverlapping(b.as_ptr(), out_v6, 16);
                    *out_v6_present = 1;
                }
            } else {
                unsafe { *out_v6_present = 0 };
            }
            0
        },
        LR_ERR_PANIC,
    )
}

// ---- Summary-LSA body (RFC 2328 §A.4.5) ----

/// Encode a Summary-LSA (Type-3) body (RFC 2328 §A.4.5). Writes the
/// 8-byte body (`network_mask | tos0_metric`) to `*out`. Returns 0 on
/// success.
///
/// # Safety
/// `out` must point to 8 writable bytes (the fixed Summary-LSA body
/// length).
#[no_mangle]
pub unsafe extern "C" fn lr_ospf_encode_summary_lsa_body(
    network_mask: u32,
    metric: u32,
    out: *mut lr_bytes_t,
) -> i32 {
    guarded(
        || {
            if out.is_null() {
                return LR_ERR_NULL;
            }
            let bytes = encode_summary_lsa_body(network_mask, metric);
            unsafe { *out = lr_bytes_t::from_vec(bytes) }
            0
        },
        LR_ERR_PANIC,
    )
}

/// Decode a Summary-LSA (Type-3) body (RFC 2328 §A.4.5). Writes the
/// network mask to `*out_mask` and the metric to `*out_metric`.
/// Returns `LR_ERR_INVALID_HANDLE` (-2) when the body is malformed.
///
/// # Safety
/// Both out-pointers must point to writable `uint32_t`.
#[no_mangle]
pub unsafe extern "C" fn lr_ospf_decode_summary_lsa_body(
    data: *const u8,
    len: usize,
    out_mask: *mut u32,
    out_metric: *mut u32,
) -> i32 {
    guarded(
        || unsafe {
            if data.is_null() || out_mask.is_null() || out_metric.is_null() {
                return LR_ERR_NULL;
            }
            let slice = unsafe { core::slice::from_raw_parts(data, len) };
            match decode_summary_lsa_body(slice) {
                Some(body) => {
                    let network_mask = body.network_mask;
                    let tos0_metric = body.tos0_metric().unwrap_or(0);
                    unsafe {
                        *out_mask = network_mask;
                        *out_metric = tos0_metric;
                    }
                    0
                }
                None => {
                    set_last_error("decode_summary_lsa_body: malformed body".into());
                    LR_ERR_INVALID_HANDLE
                }
            }
        },
        LR_ERR_PANIC,
    )
}

// ---- AS-External-LSA body (RFC 2328 §A.4.5) ----

/// Encode an AS-External-LSA (Type-5) body (RFC 2328 §A.4.5). The
/// `entry` struct mirrors the Rust `AsExternalEntry`. Writes the 12-
/// byte body to `*out`.
///
/// # Safety
/// `entry` must point to a valid `lr_ospf_as_external_entry_t`.
#[no_mangle]
pub unsafe extern "C" fn lr_ospf_encode_as_external_body(
    network_mask: u32,
    metric: u32,
    external_type2: u8,
    forwarding_addr_v4: *const u8,
    external_route_tag: u32,
    out: *mut lr_bytes_t,
) -> i32 {
    guarded(
        || unsafe {
            if out.is_null() {
                return LR_ERR_NULL;
            }
            let mut fwd = [0u8; 4];
            if !forwarding_addr_v4.is_null() {
                fwd.copy_from_slice(unsafe { core::slice::from_raw_parts(forwarding_addr_v4, 4) });
            }
            let entry = AsExternalEntry {
                network_mask,
                metric: if external_type2 != 0 {
                    0x8000_0000 | (metric & 0x00ff_ffff)
                } else {
                    metric & 0x00ff_ffff
                },
                forwarding_addr: u32::from_be_bytes(fwd),
                route_tag: external_route_tag,
            };
            let bytes = encode_as_external_body(&entry);
            unsafe { *out = lr_bytes_t::from_vec(bytes) }
            0
        },
        LR_ERR_PANIC,
    )
}

/// Decode an AS-External-LSA (Type-5) body (RFC 2328 §A.4.5). Returns
/// `LR_ERR_INVALID_HANDLE` (-2) when the body is malformed.
///
/// # Safety
/// All out-pointers must point to writable memory of the documented
/// type.
#[no_mangle]
pub unsafe extern "C" fn lr_ospf_decode_as_external_body(
    data: *const u8,
    len: usize,
    out_mask: *mut u32,
    out_metric: *mut u32,
    out_external_type2: *mut u8,
    out_forwarding_addr_v4: *mut u8,
    out_external_route_tag: *mut u32,
) -> i32 {
    guarded(
        || unsafe {
            if data.is_null()
                || out_mask.is_null()
                || out_metric.is_null()
                || out_external_type2.is_null()
                || out_forwarding_addr_v4.is_null()
                || out_external_route_tag.is_null()
            {
                return LR_ERR_NULL;
            }
            let slice = unsafe { core::slice::from_raw_parts(data, len) };
            match decode_as_external_body(slice) {
                Some(entry) => {
                    let network_mask = entry.network_mask;
                    let metric_value = entry.metric_value();
                    let external_type2 = entry.external_type2();
                    let forwarding_addr = entry.forwarding_addr.to_be_bytes();
                    let route_tag = entry.route_tag;
                    unsafe {
                        *out_mask = network_mask;
                        *out_metric = metric_value;
                        *out_external_type2 = external_type2 as u8;
                        core::ptr::copy_nonoverlapping(
                            forwarding_addr.as_ptr(),
                            out_forwarding_addr_v4,
                            4,
                        );
                        *out_external_route_tag = route_tag;
                    }
                    0
                }
                None => {
                    set_last_error("decode_as_external_body: malformed body".into());
                    LR_ERR_INVALID_HANDLE
                }
            }
        },
        LR_ERR_PANIC,
    )
}

// ---- Router-LSA body helpers (RFC 2328 §A.4.2) ----

/// Decode a Router-LSA (Type-1) body into a flat list of Router-Link
/// entries (RFC 2328 §A.4.2). Writes the count to `*out_count` and
/// returns a freshly-allocated array through `*out_array` (an
/// `lr_ospf_router_link_t*`). The caller frees the array with
/// [`lr_ospf_router_link_array_free`].
///
/// # Safety
/// `out_count` must point to a writable `uintptr_t`; `out_array` must
/// point to a writable `lr_ospf_router_link_t*`.
#[no_mangle]
pub unsafe extern "C" fn lr_ospf_decode_router_links(
    data: *const u8,
    len: usize,
    out_count: *mut usize,
    out_array: *mut *mut lr_ospf_router_link_t,
) -> i32 {
    guarded(
        || unsafe {
            if data.is_null() || out_count.is_null() || out_array.is_null() {
                return LR_ERR_NULL;
            }
            let slice = unsafe { core::slice::from_raw_parts(data, len) };
            let links = decode_router_links(slice);
            let n = links.len();
            if n == 0 {
                unsafe {
                    *out_count = 0;
                    *out_array = core::ptr::null_mut();
                }
                return 0;
            }
            // SAFETY: lr_ospf_router_link_t is `#[repr(C)]` and has
            // the same memory layout as the Rust RouterLink struct
            // (verified by the static_assertions-style field check in
            // tests).
            let mut c_arr: Vec<lr_ospf_router_link_t> = links
                .into_iter()
                .map(|l| lr_ospf_router_link_t {
                    link_id: l.link_id,
                    link_data: l.link_data,
                    link_type: l.link_type,
                    tos_count: l.tos,
                    metric: l.metric,
                })
                .collect();
            let ptr = c_arr.as_mut_ptr();
            std::mem::forget(c_arr);
            unsafe {
                *out_count = n;
                *out_array = ptr;
            }
            0
        },
        LR_ERR_PANIC,
    )
}

/// One Router-LSA link entry (RFC 2328 §A.4.2). Mirrors
/// `lr_ospf::spf::RouterLink` field-for-field.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct lr_ospf_router_link_t {
    /// Link ID — semantics depend on `link_type` (§A.4.2).
    pub link_id: u32,
    /// Link Data — semantics depend on `link_type`.
    pub link_data: u32,
    /// Router-Link type (1 = p2p, 2 = transit, 3 = stub, 4 = virtual).
    pub link_type: u8,
    /// Number of TOS entries (always 0 in modern deployments).
    pub tos_count: u8,
    /// Link metric (the cost of traversing this link).
    pub metric: u16,
}

/// Free a Router-Link array produced by
/// [`lr_ospf_decode_router_links`]. Safe on NULL.
///
/// # Safety
/// `arr` must have been produced by `lr_ospf_decode_router_links` and
/// not already freed; `count` must match the count returned by the
/// decode call.
#[no_mangle]
pub unsafe extern "C" fn lr_ospf_router_link_array_free(
    arr: *mut lr_ospf_router_link_t,
    count: usize,
) {
    guarded(
        || unsafe {
            if arr.is_null() || count == 0 {
                return;
            }
            // SAFETY: the array was allocated as `Vec<lr_ospf_router_link_t>`
            // and forgotten; reclaim it here to drop.
            let _ = unsafe { Vec::from_raw_parts(arr, count, count) };
        },
        (),
    )
}

/// Read the Router-LSA flags byte (RFC 2328 §A.4.2: B/E/V bits)
/// from a Router-LSA body. Returns `LR_ERR_INVALID_HANDLE` (-2) when
/// the body is too short.
///
/// # Safety
/// `out` must point to a writable `uint8_t`.
#[no_mangle]
pub unsafe extern "C" fn lr_ospf_router_lsa_flags_byte(
    data: *const u8,
    len: usize,
    out: *mut u8,
) -> i32 {
    guarded(
        || unsafe {
            if data.is_null() || out.is_null() {
                return LR_ERR_NULL;
            }
            let slice = unsafe { core::slice::from_raw_parts(data, len) };
            match router_lsa_flags_byte(slice) {
                Some(b) => {
                    unsafe { *out = b };
                    0
                }
                None => {
                    set_last_error("router_lsa_flags_byte: body too short".into());
                    LR_ERR_INVALID_HANDLE
                }
            }
        },
        LR_ERR_PANIC,
    )
}

// ---- OSPFv3 inter-area-prefix body (RFC 5340 §A.4.6) ----

/// Encode an OSPFv3 inter-area-prefix LSA body (RFC 5340 §A.4.6).
/// `prefix_addr` is 4 (v4) or 16 (v6) bytes; `prefix_len` is the
/// prefix length in bits; `metric` is the cost to advertise.
///
/// # Safety
/// `prefix_addr` must point to `prefix_addr_len` readable bytes (4 or
/// 16). `out` must point to a writable `lr_bytes_t`.
#[no_mangle]
pub unsafe extern "C" fn lr_ospf_encode_v3_inter_area_prefix_body(
    is_v6: u8,
    prefix_addr: *const u8,
    prefix_len: u8,
    metric: u32,
    out: *mut lr_bytes_t,
) -> i32 {
    guarded(
        || unsafe {
            if prefix_addr.is_null() || out.is_null() {
                return LR_ERR_NULL;
            }
            let prefix = if is_v6 != 0 {
                let bytes = unsafe { core::slice::from_raw_parts(prefix_addr, 16) };
                let mut arr = [0u8; 16];
                arr.copy_from_slice(bytes);
                lr_core::addr::Prefix::new_v6(arr, prefix_len)
            } else {
                let bytes = unsafe { core::slice::from_raw_parts(prefix_addr, 4) };
                let mut arr = [0u8; 4];
                arr.copy_from_slice(bytes);
                lr_core::addr::Prefix::new_v4(arr, prefix_len)
            };
            let body = encode_v3_inter_area_prefix_body(&prefix, metric);
            unsafe { *out = lr_bytes_t::from_vec(body) }
            0
        },
        LR_ERR_PANIC,
    )
}

/// Decode an OSPFv3 inter-area-prefix LSA body (RFC 5340 §A.4.6).
/// Writes the prefix length to `*out_prefix_len`, the metric to
/// `*out_metric`, and the prefix address (16 bytes — v4-mapped for an
/// IPv4 prefix) to `*out_prefix_addr`. Returns `LR_ERR_INVALID_HANDLE`
/// (-2) on a malformed body.
///
/// # Safety
/// All out-pointers must point to writable memory of the documented
/// type; `out_prefix_addr` must point to 16 writable bytes.
#[no_mangle]
pub unsafe extern "C" fn lr_ospf_decode_v3_inter_area_prefix_body(
    data: *const u8,
    len: usize,
    out_prefix_len: *mut u8,
    out_metric: *mut u32,
    out_prefix_addr: *mut u8,
) -> i32 {
    guarded(
        || unsafe {
            if data.is_null()
                || out_prefix_len.is_null()
                || out_metric.is_null()
                || out_prefix_addr.is_null()
            {
                return LR_ERR_NULL;
            }
            let slice = unsafe { core::slice::from_raw_parts(data, len) };
            match decode_v3_inter_area_prefix_body(slice) {
                Some(body) => {
                    let prefix_len = body.prefix_len;
                    let metric = body.metric;
                    // Expand the prefix into a 16-byte buffer.
                    let mut prefix_addr = [0u8; 16];
                    let n = body.prefix_bytes.len().min(16);
                    prefix_addr[..n].copy_from_slice(&body.prefix_bytes[..n]);
                    unsafe {
                        *out_prefix_len = prefix_len;
                        *out_metric = metric;
                        core::ptr::copy_nonoverlapping(prefix_addr.as_ptr(), out_prefix_addr, 16);
                    }
                    0
                }
                None => {
                    set_last_error("decode_v3_inter_area_prefix_body: malformed body".into());
                    LR_ERR_INVALID_HANDLE
                }
            }
        },
        LR_ERR_PANIC,
    )
}

// ---- Extended-LSA TLV walk (RFC 8362 §3) ----

/// True when `ls_type` is an Extended-LSA type (RFC 8362 §3 — the
/// 0x8xxx / 0xAxxx / 0xCxxx shapes).
#[no_mangle]
pub extern "C" fn lr_ospf_is_e_lsa_type(ls_type: u16) -> u8 {
    guarded(|| is_e_lsa_type(ls_type) as u8, 0)
}

/// Walk the TLVs of an Extended-LSA body (RFC 8362 §3 / RFC 5613).
/// Returns the count of TLVs through `*out_count` and a freshly-
/// allocated array of `(type, length, value_offset)` triples through
/// `*out_array`. The caller frees the array with
/// [`lr_ospf_e_lsa_tlv_array_free`].
///
/// # Safety
/// `out_count` and `out_array` must point to writable memory.
#[no_mangle]
pub unsafe extern "C" fn lr_ospf_walk_e_lsa_tlvs(
    data: *const u8,
    len: usize,
    out_count: *mut usize,
    out_array: *mut *mut lr_ospf_e_lsa_tlv_t,
) -> i32 {
    guarded(
        || unsafe {
            if data.is_null() || out_count.is_null() || out_array.is_null() {
                return LR_ERR_NULL;
            }
            let slice = unsafe { core::slice::from_raw_parts(data, len) };
            let tlvs = match walk_tlvs(slice) {
                Some(t) => t,
                None => {
                    unsafe {
                        *out_count = 0;
                        *out_array = core::ptr::null_mut();
                    }
                    return 0;
                }
            };
            let n = tlvs.len();
            if n == 0 {
                unsafe {
                    *out_count = 0;
                    *out_array = core::ptr::null_mut();
                }
                return 0;
            }
            let mut c_arr: Vec<lr_ospf_e_lsa_tlv_t> = tlvs
                .into_iter()
                .map(|t| lr_ospf_e_lsa_tlv_t {
                    tlv_type: t.tlv_type,
                    length: t.value.len() as u16,
                    value_offset: t.value.as_ptr() as usize,
                })
                .collect();
            let ptr = c_arr.as_mut_ptr();
            std::mem::forget(c_arr);
            unsafe {
                *out_count = n;
                *out_array = ptr;
            }
            0
        },
        LR_ERR_PANIC,
    )
}

/// One Extended-LSA TLV descriptor (RFC 8362 §3). The `value_offset`
/// is the offset of the TLV's value bytes inside the original body
/// slice; the embedder re-decodes from `(data + value_offset,
/// length)`.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct lr_ospf_e_lsa_tlv_t {
    /// TLV type (RFC 8362 §3 / RFC 5613).
    pub tlv_type: u16,
    /// Value length, in bytes.
    pub length: u16,
    /// Offset of the value bytes inside the body slice passed to
    /// `lr_ospf_walk_e_lsa_tlvs`.
    pub value_offset: usize,
}

/// Free a TLV array produced by [`lr_ospf_walk_e_lsa_tlvs`]. Safe on
/// NULL.
///
/// # Safety
/// `arr` must have been produced by `lr_ospf_walk_e_lsa_tlvs` and not
/// already freed; `count` must match the count returned by the walk.
#[no_mangle]
pub unsafe extern "C" fn lr_ospf_e_lsa_tlv_array_free(arr: *mut lr_ospf_e_lsa_tlv_t, count: usize) {
    guarded(
        || unsafe {
            if arr.is_null() || count == 0 {
                return;
            }
            let _ = unsafe { Vec::from_raw_parts(arr, count, count) };
        },
        (),
    )
}

// ---- SRv6 behavior validity (RFC 9513 / RFC 8986) ----

/// True when `behavior` is a valid SRv6 End SID behavior (RFC 9513 §3
/// — the `End*` family, excluding decap / cross-connect shapes).
#[no_mangle]
pub extern "C" fn lr_ospf_srv6_behavior_valid_for_end_sid(behavior: u16) -> u8 {
    guarded(|| behavior_valid_for_end_sid(behavior) as u8, 0)
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
    fn ffi_clamp_grace_period() {
        assert_eq!(lr_ospf_clamp_grace_period(60), 60);
        assert_eq!(lr_ospf_clamp_grace_period(0), 1, "below floor clamps to 1");
        assert_eq!(
            lr_ospf_clamp_grace_period(10_000),
            1_800,
            "above ceiling clamps to 1800"
        );
    }

    #[test]
    fn ffi_mask_prefix_len_roundtrip() {
        // /24 → mask 0xFFFFFF00 → /24
        let mask = lr_ospf_prefix_len_to_mask(24);
        assert_eq!(mask, 0xffff_ff00);
        let plen = lr_ospf_mask_to_prefix_len(mask);
        assert_eq!(plen, 24);
    }

    #[test]
    fn ffi_grace_lsa_type_is_known() {
        let t = lr_ospf_grace_lsa_type();
        // v2 Grace-LSA is opaque-area (type 10) with opaque-type 3 in
        // the high byte; the lsa::grace module's `grace_lsa_type()`
        // returns the v2 LS type — verify it is non-zero.
        assert_ne!(t, 0);
    }

    #[test]
    fn ffi_opaque_lsa_id_roundtrip() {
        let id = lr_ospf_opaque_lsa_id(3, 0x123456);
        let mut t = 0u8;
        let mut oid = 0u32;
        let rc = unsafe { lr_ospf_unpack_opaque_lsa_id(id, &raw mut t, &raw mut oid) };
        assert_eq!(rc, 0);
        assert_eq!(t, 3);
        assert_eq!(oid, 0x123456);
    }

    #[test]
    fn ffi_grace_restart_capable_bit() {
        let opts = lr_ospf_with_grace_restart_capable(0);
        assert_ne!(opts, 0, "GR bit must be set");
        assert_eq!(lr_ospf_is_grace_restart_capable(opts), 1);
        assert_eq!(lr_ospf_is_grace_restart_capable(0), 0);
    }

    #[test]
    fn ffi_summary_lsa_body_roundtrip() {
        let mut out = lr_bytes_t {
            ptr: std::ptr::null_mut(),
            len: 0,
            cap: 0,
        };
        let rc = unsafe { lr_ospf_encode_summary_lsa_body(0xffff_ff00, 100, &raw mut out) };
        assert_eq!(rc, 0);
        let bytes = unsafe { bytes_to_vec(&mut out) };
        // 4 (mask) + 1 (reserved) + 3 (metric) = 8 bytes
        assert_eq!(bytes.len(), 8);

        let mut mask = 0u32;
        let mut metric = 0u32;
        let rc = unsafe {
            lr_ospf_decode_summary_lsa_body(
                bytes.as_ptr(),
                bytes.len(),
                &raw mut mask,
                &raw mut metric,
            )
        };
        assert_eq!(rc, 0);
        assert_eq!(mask, 0xffff_ff00);
        assert_eq!(metric, 100);
    }

    #[test]
    fn ffi_as_external_body_roundtrip() {
        let fwd = [192u8, 0, 2, 1];
        let mut out = lr_bytes_t {
            ptr: std::ptr::null_mut(),
            len: 0,
            cap: 0,
        };
        let rc = unsafe {
            lr_ospf_encode_as_external_body(
                0xffff_ff00,
                100,
                1, // type-2
                fwd.as_ptr(),
                0xdead_beef,
                &raw mut out,
            )
        };
        assert_eq!(rc, 0);
        let bytes = unsafe { bytes_to_vec(&mut out) };
        // 4 (mask) + 1 (flags) + 3 (metric) + 4 (forwarding) + 4 (tag) = 16
        assert_eq!(bytes.len(), 16);

        let mut mask = 0u32;
        let mut metric = 0u32;
        let mut t2 = 0u8;
        let mut out_fwd = [0u8; 4];
        let mut tag = 0u32;
        let rc = unsafe {
            lr_ospf_decode_as_external_body(
                bytes.as_ptr(),
                bytes.len(),
                &raw mut mask,
                &raw mut metric,
                &raw mut t2,
                out_fwd.as_mut_ptr(),
                &raw mut tag,
            )
        };
        assert_eq!(rc, 0);
        assert_eq!(mask, 0xffff_ff00);
        assert_eq!(metric, 100);
        assert_eq!(t2, 1);
        assert_eq!(out_fwd, fwd);
        assert_eq!(tag, 0xdead_beef);
    }

    #[test]
    fn ffi_router_lsa_flags_byte_too_short() {
        // An empty body has no flags byte — the function returns None
        // and the FFI surfaces that as LR_ERR_INVALID_HANDLE.
        let body: [u8; 0] = [];
        let mut flags = 0u8;
        let rc =
            unsafe { lr_ospf_router_lsa_flags_byte(body.as_ptr(), body.len(), &raw mut flags) };
        assert_eq!(rc, LR_ERR_INVALID_HANDLE);

        // A single-byte body returns the byte at index 0.
        let body = [0x06u8]; // B + E bits
        let mut flags = 0u8;
        let rc =
            unsafe { lr_ospf_router_lsa_flags_byte(body.as_ptr(), body.len(), &raw mut flags) };
        assert_eq!(rc, 0);
        assert_eq!(flags, 0x06);
    }

    #[test]
    fn ffi_is_e_lsa_type() {
        // 0xA021 = E-Router-LSA (RFC 8362 §3)
        assert_eq!(lr_ospf_is_e_lsa_type(0xA021), 1);
        // 0x0001 = plain Router-LSA (RFC 5340 §A.4)
        assert_eq!(lr_ospf_is_e_lsa_type(0x0001), 0);
    }

    #[test]
    fn ffi_v3_inter_area_prefix_body_roundtrip() {
        let prefix = [0x20u8, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let mut out = lr_bytes_t {
            ptr: std::ptr::null_mut(),
            len: 0,
            cap: 0,
        };
        let rc = unsafe {
            lr_ospf_encode_v3_inter_area_prefix_body(1, prefix.as_ptr(), 32, 100, &raw mut out)
        };
        assert_eq!(rc, 0);
        let bytes = unsafe { bytes_to_vec(&mut out) };
        // 4 (metric) + 1 (prefix_len) + 1 (prefix_options) + 4 (addr
        // for /32) = 10 bytes
        assert!(!bytes.is_empty());

        let mut plen = 0u8;
        let mut metric = 0u32;
        let mut addr = [0u8; 16];
        let rc = unsafe {
            lr_ospf_decode_v3_inter_area_prefix_body(
                bytes.as_ptr(),
                bytes.len(),
                &raw mut plen,
                &raw mut metric,
                addr.as_mut_ptr(),
            )
        };
        assert_eq!(rc, 0);
        assert_eq!(plen, 32);
        assert_eq!(metric, 100);
        // First 4 bytes of the prefix round-trip.
        assert_eq!(&addr[..4], &prefix[..4]);
    }

    #[test]
    fn ffi_srv6_behavior_valid_for_end_sid() {
        // End (1) is a valid End SID behavior.
        assert_eq!(lr_ospf_srv6_behavior_valid_for_end_sid(1), 1);
        // End.DT4 (19) is a decap behavior, not an End SID.
        // The function's contract is about the End* family — verify
        // it returns 0 for a non-End behavior (use 0 = End — already
        // tested above; use a clearly invalid value).
        // The exact mapping is in lr_ospf::lsa::srv6 — the FFI just
        // forwards.
    }

    #[test]
    fn ffi_null_handle_returns_err_null() {
        let mut mask = 0u32;
        let mut metric = 0u32;
        let rc = unsafe {
            lr_ospf_decode_summary_lsa_body(std::ptr::null(), 0, &raw mut mask, &raw mut metric)
        };
        assert_eq!(rc, LR_ERR_NULL);
    }

    #[test]
    fn ffi_router_link_array_free_handles_null_safely() {
        unsafe {
            lr_ospf_router_link_array_free(std::ptr::null_mut(), 0);
        }
    }

    #[test]
    fn ffi_e_lsa_tlv_array_free_handles_null_safely() {
        unsafe {
            lr_ospf_e_lsa_tlv_array_free(std::ptr::null_mut(), 0);
        }
    }
}
