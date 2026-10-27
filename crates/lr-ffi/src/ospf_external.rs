//! OSPF AS-external-LSA origination + external route calculation
//! (RFC 2328 §12.4.3, §16.4, §16.5; RFC 5340 §4.8.5; RFC 8362 §6.1).
//!
//! Mirrors the public Rust API of `lr_ospf::external`:
//! - `ExternalMetricType` (Type1 / Type2)
//! - `ExternalDestination` (type-5 origination input)
//! - `AsbrDestination` (type-4 summary-ASBR-LSA origination input)
//! - `ExternalRoute` / `ExternalRouteV3` (the §16.4 calculation
//!   output)
//! - `originate_external_lsa` / `flush_external_lsa` /
//!   `originate_summary_asbr_lsa`
//! - `external_routes` / `external_routes_v3` /
//!   `external_routes_v3_extended`
//!
//! All opaque handles are `lr_*_t` typedefs to boxed Rust values; the
//! embedder releases them via the matching `lr_*_free`.

#![allow(unused_unsafe)]
#![allow(unused_imports)]
#![allow(dead_code)]

use lr_core::addr::{IpAddr, Prefix};
use lr_ospf::external::{
    originate_external_lsa, originate_summary_asbr_lsa, AsbrDestination, ExternalDestination,
    ExternalMetricType, ExternalRoute, ExternalRouteV3,
};

use crate::error::{set_last_error, LrError, LR_ERR_PANIC};
use crate::guarded;

const LR_ERR_NULL: i32 = LrError::Null as i32;
const LR_ERR_OTHER: i32 = LrError::Other as i32;

/// Metric type constants — mirror `ExternalMetricType::*`.
pub const LR_OSPF_METRIC_TYPE_1: i32 = 0;
pub const LR_OSPF_METRIC_TYPE_2: i32 = 1;

fn metric_type_from_c(v: i32) -> Option<ExternalMetricType> {
    match v {
        LR_OSPF_METRIC_TYPE_1 => Some(ExternalMetricType::Type1),
        LR_OSPF_METRIC_TYPE_2 => Some(ExternalMetricType::Type2),
        _ => None,
    }
}

fn metric_type_to_c(t: ExternalMetricType) -> i32 {
    match t {
        ExternalMetricType::Type1 => LR_OSPF_METRIC_TYPE_1,
        ExternalMetricType::Type2 => LR_OSPF_METRIC_TYPE_2,
    }
}

// ---- Opaque handles ----

/// Opaque OSPF LSDB handle (read-only borrow). The embedder obtains
/// one from `lr_ospf_lsdb_*` and passes it to
/// `lr_ospf_external_routes`.
#[repr(C)]
pub struct OpaqueOspfExternalLsdb {
    _private: [u8; 0],
}
pub type lr_ospf_lsdb_borrow_t = *const OpaqueOspfExternalLsdb;

/// Opaque `ExternalDestination` handle (origination input).
#[repr(C)]
pub struct OpaqueOspfExternalDest {
    _private: [u8; 0],
}
pub type lr_ospf_external_dest_t = *mut OpaqueOspfExternalDest;

/// Opaque `AsbrDestination` handle (type-4 origination input).
#[repr(C)]
pub struct OpaqueOspfAsbrDest {
    _private: [u8; 0],
}
pub type lr_ospf_asbr_dest_t = *mut OpaqueOspfAsbrDest;

/// Opaque `ExternalRoute` handle (one §16.4 candidate).
#[repr(C)]
pub struct OpaqueOspfExternalRoute {
    _private: [u8; 0],
}
pub type lr_ospf_external_route_t = *mut OpaqueOspfExternalRoute;

/// Opaque `ExternalRouteV3` handle (one v3 §4.8.5 candidate).
#[repr(C)]
pub struct OpaqueOspfExternalRouteV3 {
    _private: [u8; 0],
}
pub type lr_ospf_external_route_v3_t = *mut OpaqueOspfExternalRouteV3;

/// Opaque `Vec<ExternalRoute>` handle (the §16.4 calculation output).
#[repr(C)]
pub struct OpaqueOspfExternalRouteVec {
    _private: [u8; 0],
}
pub type lr_ospf_external_route_vec_t = *mut OpaqueOspfExternalRouteVec;

/// Opaque `Vec<ExternalRouteV3>` handle.
#[repr(C)]
pub struct OpaqueOspfExternalRouteV3Vec {
    _private: [u8; 0],
}
pub type lr_ospf_external_route_v3_vec_t = *mut OpaqueOspfExternalRouteV3Vec;

// Already-defined FFI types we need to bridge to. The ospf_lsdb FFI
// module owns the LSDB handle type `lr_ospf_lsdb_t`; we borrow it as
// a raw pointer (read-only). The ospf_spf FFI module owns
// `lr_ospf_spf_result_t` / `lr_ospf_spf_v3_result_t`. We do not
// re-declare them here — the borrow is via `as *const Lsdb` /
// `as *const SpfResult`.

fn box_dest(d: ExternalDestination) -> lr_ospf_external_dest_t {
    Box::into_raw(Box::new(d)) as lr_ospf_external_dest_t
}
unsafe fn borrow_dest(d: lr_ospf_external_dest_t) -> Option<&'static ExternalDestination> {
    if d.is_null() {
        return None;
    }
    Some(unsafe { &*(d as *const ExternalDestination) })
}
unsafe fn unbox_dest(d: lr_ospf_external_dest_t) -> Option<Box<ExternalDestination>> {
    if d.is_null() {
        return None;
    }
    Some(unsafe { Box::from_raw(d as *mut ExternalDestination) })
}

fn box_asbr(d: AsbrDestination) -> lr_ospf_asbr_dest_t {
    Box::into_raw(Box::new(d)) as lr_ospf_asbr_dest_t
}
unsafe fn borrow_asbr(d: lr_ospf_asbr_dest_t) -> Option<&'static AsbrDestination> {
    if d.is_null() {
        return None;
    }
    Some(unsafe { &*(d as *const AsbrDestination) })
}

fn box_route(r: ExternalRoute) -> lr_ospf_external_route_t {
    Box::into_raw(Box::new(r)) as lr_ospf_external_route_t
}
unsafe fn borrow_route(r: lr_ospf_external_route_t) -> Option<&'static ExternalRoute> {
    if r.is_null() {
        return None;
    }
    Some(unsafe { &*(r as *const ExternalRoute) })
}

fn box_route_v3(r: ExternalRouteV3) -> lr_ospf_external_route_v3_t {
    Box::into_raw(Box::new(r)) as lr_ospf_external_route_v3_t
}
unsafe fn borrow_route_v3(r: lr_ospf_external_route_v3_t) -> Option<&'static ExternalRouteV3> {
    if r.is_null() {
        return None;
    }
    Some(unsafe { &*(r as *const ExternalRouteV3) })
}

// ---- ExternalDestination ----

/// Construct an `ExternalDestination` for type-5 / type-7 origination
/// (RFC 2328 §12.4.3). The `prefix_v4` / `prefix_v6` slots follow the
/// same convention as the rest of the FFI: pass exactly one of them,
/// the other NULL.
///
/// # Safety
/// `prefix_v4` must point to 4 readable bytes when `is_ipv6 == 0`;
/// `prefix_v6` must point to 16 readable bytes when `is_ipv6 == 1`.
#[no_mangle]
pub unsafe extern "C" fn lr_ospf_external_dest_new(
    prefix_v4: *const u8,
    prefix_v6: *const u8,
    prefix_len: u8,
    metric: u32,
    metric_type: i32,
) -> lr_ospf_external_dest_t {
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
                set_last_error(
                    "lr_ospf_external_dest_new: both prefix_v4 and prefix_v6 NULL".into(),
                );
                return std::ptr::null_mut();
            };
            let mt = match metric_type_from_c(metric_type) {
                Some(m) => m,
                None => {
                    set_last_error(format!(
                        "lr_ospf_external_dest_new: unknown metric_type {metric_type}"
                    ));
                    return std::ptr::null_mut();
                }
            };
            box_dest(ExternalDestination::new(
                Prefix { addr, prefix_len },
                metric,
                mt,
            ))
        },
        std::ptr::null_mut(),
    )
}

/// Set the forwarding address (RFC 2328 §A.4.5 bullet f). `0` means
/// "forward to the ASBR" (the default).
///
/// # Safety
/// `d` must be a valid handle.
#[no_mangle]
pub unsafe extern "C" fn lr_ospf_external_dest_set_forwarding_addr(
    d: lr_ospf_external_dest_t,
    forwarding_addr: u32,
) -> i32 {
    guarded(
        || unsafe {
            if d.is_null() {
                return LR_ERR_NULL;
            }
            // SAFETY: the caller guarantees no concurrent access —
            // same no-race contract as the rest of the FFI.
            (*(d as *mut ExternalDestination)).forwarding_addr = forwarding_addr;
            0
        },
        LR_ERR_PANIC,
    )
}

/// Set the external route tag (RFC 2328 §A.4.5 bullet h). `0` is
/// well-formed.
///
/// # Safety
/// See [`lr_ospf_external_dest_set_forwarding_addr`].
#[no_mangle]
pub unsafe extern "C" fn lr_ospf_external_dest_set_route_tag(
    d: lr_ospf_external_dest_t,
    route_tag: u32,
) -> i32 {
    guarded(
        || unsafe {
            if d.is_null() {
                return LR_ERR_NULL;
            }
            (*(d as *mut ExternalDestination)).route_tag = route_tag;
            0
        },
        LR_ERR_PANIC,
    )
}

/// Set the P-bit (RFC 3101 §2.4): ask NSSA border routers to translate
/// the type-7 into a type-5. Default is true.
///
/// # Safety
/// See [`lr_ospf_external_dest_set_forwarding_addr`].
#[no_mangle]
pub unsafe extern "C" fn lr_ospf_external_dest_set_p_bit(
    d: lr_ospf_external_dest_t,
    p_bit: u8,
) -> i32 {
    guarded(
        || unsafe {
            if d.is_null() {
                return LR_ERR_NULL;
            }
            (*(d as *mut ExternalDestination)).p_bit = p_bit != 0;
            0
        },
        LR_ERR_PANIC,
    )
}

/// Read the prefix as `(is_ipv6, octets_out[16], prefix_len_out)`.
/// Writes 16 bytes to `octets_out` (first 4 valid for v4, all 16 for
/// v6). `prefix_len_out` receives the prefix length.
///
/// # Safety
/// `d` must be a valid handle. `octets_out` must point to 16 writable
/// bytes; `prefix_len_out` must point to a writable `uint8_t`.
#[no_mangle]
pub unsafe extern "C" fn lr_ospf_external_dest_prefix(
    d: lr_ospf_external_dest_t,
    octets_out: *mut u8,
    prefix_len_out: *mut u8,
) -> i32 {
    guarded(
        || unsafe {
            let Some(dest) = borrow_dest(d) else {
                return LR_ERR_NULL;
            };
            if octets_out.is_null() || prefix_len_out.is_null() {
                return LR_ERR_NULL;
            }
            let octets = match dest.prefix.addr {
                IpAddr::V4(b) => {
                    let mut buf = [0u8; 16];
                    buf[..4].copy_from_slice(&b);
                    buf
                }
                IpAddr::V6(b) => b,
            };
            unsafe {
                std::ptr::copy_nonoverlapping(octets.as_ptr(), octets_out, 16);
                *prefix_len_out = dest.prefix.prefix_len;
            }
            0
        },
        LR_ERR_PANIC,
    )
}

/// Read the metric (capped at LSInfinity - 1).
///
/// # Safety
/// `d` must be a valid handle.
#[no_mangle]
pub unsafe extern "C" fn lr_ospf_external_dest_metric(d: lr_ospf_external_dest_t) -> u32 {
    guarded(
        || unsafe { borrow_dest(d).map(|x| x.metric).unwrap_or(0) },
        0,
    )
}

/// Read the metric type (`LR_OSPF_METRIC_TYPE_*`).
///
/// # Safety
/// `d` must be a valid handle.
#[no_mangle]
pub unsafe extern "C" fn lr_ospf_external_dest_metric_type(d: lr_ospf_external_dest_t) -> i32 {
    guarded(
        || unsafe {
            borrow_dest(d)
                .map(|x| metric_type_to_c(x.metric_type))
                .unwrap_or(LR_OSPF_METRIC_TYPE_1)
        },
        LR_OSPF_METRIC_TYPE_1,
    )
}

/// Read the forwarding address (`0` = ASBR itself).
///
/// # Safety
/// `d` must be a valid handle.
#[no_mangle]
pub unsafe extern "C" fn lr_ospf_external_dest_forwarding_addr(d: lr_ospf_external_dest_t) -> u32 {
    guarded(
        || unsafe { borrow_dest(d).map(|x| x.forwarding_addr).unwrap_or(0) },
        0,
    )
}

/// Read the external route tag.
///
/// # Safety
/// `d` must be a valid handle.
#[no_mangle]
pub unsafe extern "C" fn lr_ospf_external_dest_route_tag(d: lr_ospf_external_dest_t) -> u32 {
    guarded(
        || unsafe { borrow_dest(d).map(|x| x.route_tag).unwrap_or(0) },
        0,
    )
}

/// Read the P-bit (RFC 3101 §2.4). Returns 1 when set, 0 otherwise.
///
/// # Safety
/// `d` must be a valid handle.
#[no_mangle]
pub unsafe extern "C" fn lr_ospf_external_dest_p_bit(d: lr_ospf_external_dest_t) -> u8 {
    guarded(
        || unsafe { borrow_dest(d).map(|x| x.p_bit as u8).unwrap_or(0) },
        0,
    )
}

/// Drop a boxed `ExternalDestination`. Safe to call with `NULL`.
///
/// # Safety
/// `d` must have been produced by [`lr_ospf_external_dest_new`] and not
/// already freed.
#[no_mangle]
pub unsafe extern "C" fn lr_ospf_external_dest_free(d: lr_ospf_external_dest_t) {
    guarded(
        || unsafe {
            drop(unbox_dest(d));
        },
        (),
    )
}

// ---- AsbrDestination ----

/// Construct an `AsbrDestination` for type-4 summary-ASBR-LSA
/// origination (RFC 2328 §12.4.3). `asbr` is the ASBR's router ID;
/// `metric` is the cost to reach it.
#[no_mangle]
pub extern "C" fn lr_ospf_asbr_dest_new(asbr: u32, metric: u32) -> lr_ospf_asbr_dest_t {
    guarded(
        || box_asbr(AsbrDestination::new(asbr, metric)),
        std::ptr::null_mut(),
    )
}

/// Read the ASBR router ID.
///
/// # Safety
/// `d` must be a valid handle.
#[no_mangle]
pub unsafe extern "C" fn lr_ospf_asbr_dest_asbr(d: lr_ospf_asbr_dest_t) -> u32 {
    guarded(|| unsafe { borrow_asbr(d).map(|x| x.asbr).unwrap_or(0) }, 0)
}

/// Read the metric (capped at LSInfinity - 1).
///
/// # Safety
/// `d` must be a valid handle.
#[no_mangle]
pub unsafe extern "C" fn lr_ospf_asbr_dest_metric(d: lr_ospf_asbr_dest_t) -> u32 {
    guarded(
        || unsafe { borrow_asbr(d).map(|x| x.metric).unwrap_or(0) },
        0,
    )
}

/// Drop a boxed `AsbrDestination`. Safe to call with `NULL`.
///
/// # Safety
/// `d` must have been produced by [`lr_ospf_asbr_dest_new`] and not
/// already freed.
#[no_mangle]
pub unsafe extern "C" fn lr_ospf_asbr_dest_free(d: lr_ospf_asbr_dest_t) {
    guarded(
        || unsafe {
            if d.is_null() {
                return;
            }
            drop(unsafe { Box::from_raw(d as *mut AsbrDestination) });
        },
        (),
    )
}

// ---- LSA origination ----

/// Originate a type-5 AS-external-LSA for `dest` (RFC 2328 §12.4.3).
/// `prev_seq` carries the previous instance's sequence number (`NULL`
/// to start fresh); the new LSA continues the sequence space.
///
/// Writes a freshly-allocated `lr_ospf_lsa_box_t` to `*out` on success.
/// Returns 0 on success, negative on error:
/// - `LR_ERR_NULL` (-1): NULL pointer.
/// - `LR_ERR_OTHER` (-6): non-IPv4 prefix or sequence-space exhausted.
///
/// # Safety
/// `dest` must be a valid `ExternalDestination` handle; `out` must
/// point to writable `lr_ospf_lsa_box_t`.
#[no_mangle]
pub unsafe extern "C" fn lr_ospf_originate_external_lsa(
    router_id: u32,
    dest: lr_ospf_external_dest_t,
    prev_seq: *const u32,
    out: *mut crate::ospf_lsdb::lr_ospf_lsa_box_t,
) -> i32 {
    guarded(
        || unsafe {
            let Some(dest_val) = borrow_dest(dest) else {
                return LR_ERR_NULL;
            };
            if out.is_null() {
                return LR_ERR_NULL;
            }
            let prev = if prev_seq.is_null() {
                None
            } else {
                Some(unsafe { *prev_seq })
            };
            match originate_external_lsa(router_id, dest_val, prev) {
                Some(lsa) => {
                    // Reuse the ospf_lsdb box helper.
                    unsafe {
                        *out = crate::ospf_lsdb::box_lsa(lsa);
                    }
                    0
                }
                None => {
                    set_last_error(
                        "lr_ospf_originate_external_lsa: non-IPv4 prefix or sequence exhausted"
                            .into(),
                    );
                    LR_ERR_OTHER
                }
            }
        },
        LR_ERR_PANIC,
    )
}

/// Flush (MaxAge) an existing type-5 / type-7 LSA instance (RFC 2328
/// §14.1). `prev_seq` is the previous instance's sequence number
/// (`NULL` to start fresh).
///
/// # Safety
/// `existing` must be a valid `lr_ospf_lsa_box_t` handle (it is borrowed,
/// not consumed); `out` must point to writable `lr_ospf_lsa_box_t`.
#[no_mangle]
pub unsafe extern "C" fn lr_ospf_flush_external_lsa(
    existing: crate::ospf_lsdb::lr_ospf_lsa_box_t,
    out: *mut crate::ospf_lsdb::lr_ospf_lsa_box_t,
) -> i32 {
    guarded(
        || unsafe {
            let Some(existing_lsa) = crate::ospf_lsdb::borrow_lsa(existing) else {
                return LR_ERR_NULL;
            };
            if out.is_null() {
                return LR_ERR_NULL;
            }
            match lr_ospf::external::flush_external_lsa(existing_lsa) {
                Some(flushed) => {
                    unsafe {
                        *out = crate::ospf_lsdb::box_lsa(flushed);
                    }
                    0
                }
                None => {
                    set_last_error("lr_ospf_flush_external_lsa: cannot flush".into());
                    LR_ERR_OTHER
                }
            }
        },
        LR_ERR_PANIC,
    )
}

/// Originate a type-4 summary-ASBR-LSA (RFC 2328 §12.4.3) for the
/// given `asbr_dest`.
///
/// # Safety
/// `asbr_dest` must be a valid `AsbrDestination` handle; `out` must
/// point to writable `lr_ospf_lsa_box_t`.
#[no_mangle]
pub unsafe extern "C" fn lr_ospf_originate_summary_asbr_lsa(
    router_id: u32,
    asbr_dest: lr_ospf_asbr_dest_t,
    prev_seq: *const u32,
    out: *mut crate::ospf_lsdb::lr_ospf_lsa_box_t,
) -> i32 {
    guarded(
        || unsafe {
            let Some(dest) = borrow_asbr(asbr_dest) else {
                return LR_ERR_NULL;
            };
            if out.is_null() {
                return LR_ERR_NULL;
            }
            let prev = if prev_seq.is_null() {
                None
            } else {
                Some(unsafe { *prev_seq })
            };
            match originate_summary_asbr_lsa(router_id, dest, prev) {
                Some(lsa) => {
                    unsafe {
                        *out = crate::ospf_lsdb::box_lsa(lsa);
                    }
                    0
                }
                None => {
                    set_last_error("lr_ospf_originate_summary_asbr_lsa: sequence exhausted".into());
                    LR_ERR_OTHER
                }
            }
        },
        LR_ERR_PANIC,
    )
}

// ---- external_routes (§16.4) ----

/// Compute the §16.4 external route candidates for one area (RFC 2328
/// §16.4). The LSDB and SPF result are borrowed (read-only) — the
/// caller retains ownership. Returns a freshly-allocated
/// `lr_ospf_external_route_vec_t` on success, NULL on a NULL input.
///
/// # Safety
/// `lsdb` and `spf_result` must be valid handles produced by
/// `lr_ospf_lsdb_*` / `lr_ospf_spf_*`.
#[no_mangle]
pub unsafe extern "C" fn lr_ospf_external_routes(
    lsdb: crate::ospf_lsdb::lr_ospf_lsdb_t,
    spf_result: crate::ospf_spf::lr_ospf_spf_result_t,
) -> lr_ospf_external_route_vec_t {
    guarded(
        || unsafe {
            let Some(lsdb_ref) = crate::ospf_lsdb::borrow_lsdb(lsdb) else {
                return std::ptr::null_mut();
            };
            let Some(spf_ref) = crate::ospf_spf::borrow_result(spf_result) else {
                return std::ptr::null_mut();
            };
            let routes = lr_ospf::external::external_routes(lsdb_ref, spf_ref);
            Box::into_raw(Box::new(routes)) as lr_ospf_external_route_vec_t
        },
        std::ptr::null_mut(),
    )
}

/// Number of `ExternalRoute` candidates in a `route_vec`.
///
/// # Safety
/// `v` must be a valid handle.
#[no_mangle]
pub unsafe extern "C" fn lr_ospf_external_route_vec_len(v: lr_ospf_external_route_vec_t) -> usize {
    guarded(
        || unsafe {
            if v.is_null() {
                return 0;
            }
            let vec: &Vec<ExternalRoute> = unsafe { &*(v as *const Vec<ExternalRoute>) };
            vec.len()
        },
        0,
    )
}

/// Borrow one `ExternalRoute` from a `route_vec` by index. The
/// returned handle is borrowed (do NOT free it); it is invalid after
/// `lr_ospf_external_route_vec_free` runs.
///
/// # Safety
/// `v` must be a valid handle; `index` must be in range.
#[no_mangle]
pub unsafe extern "C" fn lr_ospf_external_route_vec_at(
    v: lr_ospf_external_route_vec_t,
    index: usize,
) -> lr_ospf_external_route_t {
    guarded(
        || unsafe {
            if v.is_null() {
                return std::ptr::null_mut();
            }
            let vec: &Vec<ExternalRoute> = unsafe { &*(v as *const Vec<ExternalRoute>) };
            match vec.get(index) {
                Some(r) => r as *const ExternalRoute as lr_ospf_external_route_t,
                None => std::ptr::null_mut(),
            }
        },
        std::ptr::null_mut(),
    )
}

/// Drop a boxed `Vec<ExternalRoute>`. Safe to call with `NULL`.
///
/// # Safety
/// `v` must have been produced by [`lr_ospf_external_routes`] and not
/// already freed.
#[no_mangle]
pub unsafe extern "C" fn lr_ospf_external_route_vec_free(v: lr_ospf_external_route_vec_t) {
    guarded(
        || unsafe {
            if v.is_null() {
                return;
            }
            drop(unsafe { Box::from_raw(v as *mut Vec<ExternalRoute>) });
        },
        (),
    )
}

// ---- ExternalRoute readers ----

/// Read the prefix as `(is_ipv6, octets_out[16], prefix_len_out)`.
///
/// # Safety
/// `r` must be a valid handle (borrowed from a route_vec).
#[no_mangle]
pub unsafe extern "C" fn lr_ospf_external_route_prefix(
    r: lr_ospf_external_route_t,
    octets_out: *mut u8,
    prefix_len_out: *mut u8,
) -> i32 {
    guarded(
        || unsafe {
            let Some(route) = borrow_route(r) else {
                return LR_ERR_NULL;
            };
            if octets_out.is_null() || prefix_len_out.is_null() {
                return LR_ERR_NULL;
            }
            let octets = match route.prefix.addr {
                IpAddr::V4(b) => {
                    let mut buf = [0u8; 16];
                    buf[..4].copy_from_slice(&b);
                    buf
                }
                IpAddr::V6(b) => b,
            };
            unsafe {
                std::ptr::copy_nonoverlapping(octets.as_ptr(), octets_out, 16);
                *prefix_len_out = route.prefix.prefix_len;
            }
            0
        },
        LR_ERR_PANIC,
    )
}

/// Read the metric (type 1: cost-to-ASBR + external; type 2: external
/// only).
///
/// # Safety
/// `r` must be a valid handle.
#[no_mangle]
pub unsafe extern "C" fn lr_ospf_external_route_metric(r: lr_ospf_external_route_t) -> u64 {
    guarded(
        || unsafe { borrow_route(r).map(|x| x.metric).unwrap_or(0) },
        0,
    )
}

/// Read the metric type (`LR_OSPF_METRIC_TYPE_*`).
///
/// # Safety
/// `r` must be a valid handle.
#[no_mangle]
pub unsafe extern "C" fn lr_ospf_external_route_metric_type(r: lr_ospf_external_route_t) -> i32 {
    guarded(
        || unsafe {
            borrow_route(r)
                .map(|x| metric_type_to_c(x.metric_type))
                .unwrap_or(LR_OSPF_METRIC_TYPE_1)
        },
        LR_OSPF_METRIC_TYPE_1,
    )
}

/// Read the cost of the internal path to the ASBR (or forwarding
/// address). Used as the type-2 tie-breaker (§16.4 (6)).
///
/// # Safety
/// `r` must be a valid handle.
#[no_mangle]
pub unsafe extern "C" fn lr_ospf_external_route_internal_cost(r: lr_ospf_external_route_t) -> u64 {
    guarded(
        || unsafe { borrow_route(r).map(|x| x.internal_cost).unwrap_or(0) },
        0,
    )
}

/// Read the advertising ASBR router ID.
///
/// # Safety
/// `r` must be a valid handle.
#[no_mangle]
pub unsafe extern "C" fn lr_ospf_external_route_asbr(r: lr_ospf_external_route_t) -> u32 {
    guarded(
        || unsafe { borrow_route(r).map(|x| x.asbr).unwrap_or(0) },
        0,
    )
}

/// Read the border router when the ASBR was reached inter-area
/// (§16.4 (b)); writes 1 to `*present` and the router ID to
/// `*border_router`, or 0 to `*present` when the path is intra-area.
///
/// # Safety
/// `r` must be a valid handle; `present` and `border_router` must
/// point to writable memory.
#[no_mangle]
pub unsafe extern "C" fn lr_ospf_external_route_border_router(
    r: lr_ospf_external_route_t,
    present: *mut u8,
    border_router: *mut u32,
) -> i32 {
    guarded(
        || unsafe {
            let Some(route) = borrow_route(r) else {
                return LR_ERR_NULL;
            };
            if present.is_null() || border_router.is_null() {
                return LR_ERR_NULL;
            }
            match route.border_router {
                Some(br) => unsafe {
                    *present = 1;
                    *border_router = br;
                },
                None => unsafe {
                    *present = 0;
                    *border_router = 0;
                },
            }
            0
        },
        LR_ERR_PANIC,
    )
}

/// Read the forwarding address (`0` = ASBR itself).
///
/// # Safety
/// `r` must be a valid handle.
#[no_mangle]
pub unsafe extern "C" fn lr_ospf_external_route_forwarding_addr(
    r: lr_ospf_external_route_t,
) -> u32 {
    guarded(
        || unsafe { borrow_route(r).map(|x| x.forwarding_addr).unwrap_or(0) },
        0,
    )
}

/// Read the external route tag.
///
/// # Safety
/// `r` must be a valid handle.
#[no_mangle]
pub unsafe extern "C" fn lr_ospf_external_route_tag(r: lr_ospf_external_route_t) -> u32 {
    guarded(
        || unsafe { borrow_route(r).map(|x| x.route_tag).unwrap_or(0) },
        0,
    )
}

// ---- external_routes_v3 (§4.8.5) ----

/// Compute the v3 §4.8.5 external route candidates (RFC 5340 §4.8.5).
///
/// # Safety
/// `lsdb` and `spf_result` must be valid handles.
#[no_mangle]
pub unsafe extern "C" fn lr_ospf_external_routes_v3(
    lsdb: crate::ospf_lsdb::lr_ospf_lsdb_t,
    spf_result: crate::ospf_spf::lr_ospf_spf_v3_result_t,
) -> lr_ospf_external_route_v3_vec_t {
    guarded(
        || unsafe {
            let Some(lsdb_ref) = crate::ospf_lsdb::borrow_lsdb(lsdb) else {
                return std::ptr::null_mut();
            };
            let Some(spf_ref) = crate::ospf_spf::borrow_v3_result(spf_result) else {
                return std::ptr::null_mut();
            };
            let routes = lr_ospf::external::external_routes_v3(lsdb_ref, spf_ref);
            Box::into_raw(Box::new(routes)) as lr_ospf_external_route_v3_vec_t
        },
        std::ptr::null_mut(),
    )
}

/// Compute the v3 §4.8.5 external route candidates in Extended-LSA
/// mode (RFC 8362 §6.1): E-AS-External-LSAs (0xC025) contribute
/// alongside the legacy 0x4005s.
///
/// # Safety
/// `lsdb` and `spf_result` must be valid handles.
#[no_mangle]
pub unsafe extern "C" fn lr_ospf_external_routes_v3_extended(
    lsdb: crate::ospf_lsdb::lr_ospf_lsdb_t,
    spf_result: crate::ospf_spf::lr_ospf_spf_v3_result_t,
) -> lr_ospf_external_route_v3_vec_t {
    guarded(
        || unsafe {
            let Some(lsdb_ref) = crate::ospf_lsdb::borrow_lsdb(lsdb) else {
                return std::ptr::null_mut();
            };
            let Some(spf_ref) = crate::ospf_spf::borrow_v3_result(spf_result) else {
                return std::ptr::null_mut();
            };
            let routes = lr_ospf::external::external_routes_v3_extended(lsdb_ref, spf_ref);
            Box::into_raw(Box::new(routes)) as lr_ospf_external_route_v3_vec_t
        },
        std::ptr::null_mut(),
    )
}

/// Number of `ExternalRouteV3` candidates in a v3 route_vec.
///
/// # Safety
/// `v` must be a valid handle.
#[no_mangle]
pub unsafe extern "C" fn lr_ospf_external_route_v3_vec_len(
    v: lr_ospf_external_route_v3_vec_t,
) -> usize {
    guarded(
        || unsafe {
            if v.is_null() {
                return 0;
            }
            let vec: &Vec<ExternalRouteV3> = unsafe { &*(v as *const Vec<ExternalRouteV3>) };
            vec.len()
        },
        0,
    )
}

/// Borrow one `ExternalRouteV3` by index. The returned handle is
/// borrowed (do NOT free it).
///
/// # Safety
/// `v` must be a valid handle; `index` must be in range.
#[no_mangle]
pub unsafe extern "C" fn lr_ospf_external_route_v3_vec_at(
    v: lr_ospf_external_route_v3_vec_t,
    index: usize,
) -> lr_ospf_external_route_v3_t {
    guarded(
        || unsafe {
            if v.is_null() {
                return std::ptr::null_mut();
            }
            let vec: &Vec<ExternalRouteV3> = unsafe { &*(v as *const Vec<ExternalRouteV3>) };
            match vec.get(index) {
                Some(r) => r as *const ExternalRouteV3 as lr_ospf_external_route_v3_t,
                None => std::ptr::null_mut(),
            }
        },
        std::ptr::null_mut(),
    )
}

/// Drop a boxed `Vec<ExternalRouteV3>`. Safe to call with `NULL`.
///
/// # Safety
/// `v` must have been produced by `lr_ospf_external_routes_v3` (or
/// `_extended`) and not already freed.
#[no_mangle]
pub unsafe extern "C" fn lr_ospf_external_route_v3_vec_free(v: lr_ospf_external_route_v3_vec_t) {
    guarded(
        || unsafe {
            if v.is_null() {
                return;
            }
            drop(unsafe { Box::from_raw(v as *mut Vec<ExternalRouteV3>) });
        },
        (),
    )
}

// ---- ExternalRouteV3 readers ----

/// Read the prefix as `(is_ipv6, octets_out[16], prefix_len_out)`.
///
/// # Safety
/// `r` must be a valid handle (borrowed from a v3 route_vec).
#[no_mangle]
pub unsafe extern "C" fn lr_ospf_external_route_v3_prefix(
    r: lr_ospf_external_route_v3_t,
    octets_out: *mut u8,
    prefix_len_out: *mut u8,
) -> i32 {
    guarded(
        || unsafe {
            let Some(route) = borrow_route_v3(r) else {
                return LR_ERR_NULL;
            };
            if octets_out.is_null() || prefix_len_out.is_null() {
                return LR_ERR_NULL;
            }
            let octets = match route.prefix.addr {
                IpAddr::V4(b) => {
                    let mut buf = [0u8; 16];
                    buf[..4].copy_from_slice(&b);
                    buf
                }
                IpAddr::V6(b) => b,
            };
            unsafe {
                std::ptr::copy_nonoverlapping(octets.as_ptr(), octets_out, 16);
                *prefix_len_out = route.prefix.prefix_len;
            }
            0
        },
        LR_ERR_PANIC,
    )
}

/// Read the metric.
///
/// # Safety
/// `r` must be a valid handle.
#[no_mangle]
pub unsafe extern "C" fn lr_ospf_external_route_v3_metric(r: lr_ospf_external_route_v3_t) -> u64 {
    guarded(
        || unsafe { borrow_route_v3(r).map(|x| x.metric).unwrap_or(0) },
        0,
    )
}

/// Read the metric type (`LR_OSPF_METRIC_TYPE_*`).
///
/// # Safety
/// `r` must be a valid handle.
#[no_mangle]
pub unsafe extern "C" fn lr_ospf_external_route_v3_metric_type(
    r: lr_ospf_external_route_v3_t,
) -> i32 {
    guarded(
        || unsafe {
            borrow_route_v3(r)
                .map(|x| metric_type_to_c(x.metric_type))
                .unwrap_or(LR_OSPF_METRIC_TYPE_1)
        },
        LR_OSPF_METRIC_TYPE_1,
    )
}

/// Read the internal cost to the ASBR (type-2 tie-breaker).
///
/// # Safety
/// `r` must be a valid handle.
#[no_mangle]
pub unsafe extern "C" fn lr_ospf_external_route_v3_internal_cost(
    r: lr_ospf_external_route_v3_t,
) -> u64 {
    guarded(
        || unsafe { borrow_route_v3(r).map(|x| x.internal_cost).unwrap_or(0) },
        0,
    )
}

/// Read the advertising ASBR router ID.
///
/// # Safety
/// `r` must be a valid handle.
#[no_mangle]
pub unsafe extern "C" fn lr_ospf_external_route_v3_asbr(r: lr_ospf_external_route_v3_t) -> u32 {
    guarded(
        || unsafe { borrow_route_v3(r).map(|x| x.asbr).unwrap_or(0) },
        0,
    )
}

/// Read the border router when the ASBR was reached inter-area.
/// Writes 1 to `*present` and the router ID to `*border_router`, or 0
/// to `*present` when the path is intra-area.
///
/// # Safety
/// `r` must be a valid handle; `present` and `border_router` must
/// point to writable memory.
#[no_mangle]
pub unsafe extern "C" fn lr_ospf_external_route_v3_border_router(
    r: lr_ospf_external_route_v3_t,
    present: *mut u8,
    border_router: *mut u32,
) -> i32 {
    guarded(
        || unsafe {
            let Some(route) = borrow_route_v3(r) else {
                return LR_ERR_NULL;
            };
            if present.is_null() || border_router.is_null() {
                return LR_ERR_NULL;
            }
            match route.border_router {
                Some(br) => unsafe {
                    *present = 1;
                    *border_router = br;
                },
                None => unsafe {
                    *present = 0;
                    *border_router = 0;
                },
            }
            0
        },
        LR_ERR_PANIC,
    )
}

/// Read the next-hop address as `(is_ipv6, octets_out[16],
/// present_out)`. Writes 1 to `*present` when the route carries a
/// next hop, 0 otherwise (16 zero bytes in that case).
///
/// # Safety
/// `r` must be a valid handle; `octets_out` and `present_out` must
/// point to writable memory.
#[no_mangle]
pub unsafe extern "C" fn lr_ospf_external_route_v3_next_hop(
    r: lr_ospf_external_route_v3_t,
    octets_out: *mut u8,
    present_out: *mut u8,
) -> i32 {
    guarded(
        || unsafe {
            let Some(route) = borrow_route_v3(r) else {
                return LR_ERR_NULL;
            };
            if octets_out.is_null() || present_out.is_null() {
                return LR_ERR_NULL;
            }
            match route.next_hop {
                Some(IpAddr::V4(b)) => {
                    let mut buf = [0u8; 16];
                    buf[..4].copy_from_slice(&b);
                    unsafe {
                        std::ptr::copy_nonoverlapping(buf.as_ptr(), octets_out, 16);
                        *present_out = 1;
                    }
                }
                Some(IpAddr::V6(b)) => unsafe {
                    std::ptr::copy_nonoverlapping(b.as_ptr(), octets_out, 16);
                    *present_out = 1;
                },
                None => unsafe {
                    std::ptr::write_bytes(octets_out, 0, 16);
                    *present_out = 0;
                },
            }
            0
        },
        LR_ERR_PANIC,
    )
}

/// Read the external route tag. Writes 1 to `*present` and the tag
/// to `*tag`, or 0 to `*present` when the LSA carries no tag (RFC 5340
/// §A.4.7 T bit clear / RFC 8362 §3.6 External-Prefix sub-TLV 3
/// absent).
///
/// # Safety
/// `r` must be a valid handle; `present` and `tag` must point to
/// writable memory.
#[no_mangle]
pub unsafe extern "C" fn lr_ospf_external_route_v3_route_tag(
    r: lr_ospf_external_route_v3_t,
    present: *mut u8,
    tag: *mut u32,
) -> i32 {
    guarded(
        || unsafe {
            let Some(route) = borrow_route_v3(r) else {
                return LR_ERR_NULL;
            };
            if present.is_null() || tag.is_null() {
                return LR_ERR_NULL;
            }
            match route.route_tag {
                Some(t) => unsafe {
                    *present = 1;
                    *tag = t;
                },
                None => unsafe {
                    *present = 0;
                    *tag = 0;
                },
            }
            0
        },
        LR_ERR_PANIC,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ffi_external_dest_new_and_readers() {
        let prefix_v4 = [10u8, 0, 0, 0];
        let d = unsafe {
            lr_ospf_external_dest_new(
                prefix_v4.as_ptr(),
                std::ptr::null(),
                24,
                100,
                LR_OSPF_METRIC_TYPE_2,
            )
        };
        assert!(!d.is_null());
        assert_eq!(unsafe { lr_ospf_external_dest_metric(d) }, 100);
        assert_eq!(
            unsafe { lr_ospf_external_dest_metric_type(d) },
            LR_OSPF_METRIC_TYPE_2
        );
        // Default p_bit is true.
        assert_eq!(unsafe { lr_ospf_external_dest_p_bit(d) }, 1);

        let mut octets = [0u8; 16];
        let mut plen = 0u8;
        let rc = unsafe { lr_ospf_external_dest_prefix(d, octets.as_mut_ptr(), &raw mut plen) };
        assert_eq!(rc, 0);
        assert_eq!(plen, 24);
        assert_eq!(&octets[..4], &[10, 0, 0, 0]);

        unsafe { lr_ospf_external_dest_free(d) };
    }

    #[test]
    fn ffi_external_dest_setters() {
        let prefix_v4 = [10u8, 0, 0, 0];
        let d = unsafe {
            lr_ospf_external_dest_new(
                prefix_v4.as_ptr(),
                std::ptr::null(),
                24,
                100,
                LR_OSPF_METRIC_TYPE_2,
            )
        };
        assert_eq!(
            unsafe { lr_ospf_external_dest_set_forwarding_addr(d, 0xC0A80101) },
            0
        );
        assert_eq!(unsafe { lr_ospf_external_dest_set_route_tag(d, 42) }, 0);
        assert_eq!(unsafe { lr_ospf_external_dest_set_p_bit(d, 0) }, 0);
        assert_eq!(
            unsafe { lr_ospf_external_dest_forwarding_addr(d) },
            0xC0A80101
        );
        assert_eq!(unsafe { lr_ospf_external_dest_route_tag(d) }, 42);
        assert_eq!(unsafe { lr_ospf_external_dest_p_bit(d) }, 0);
        unsafe { lr_ospf_external_dest_free(d) };
    }

    #[test]
    fn ffi_external_dest_metric_type_1() {
        let prefix_v4 = [10u8, 0, 0, 0];
        let d = unsafe {
            lr_ospf_external_dest_new(
                prefix_v4.as_ptr(),
                std::ptr::null(),
                24,
                100,
                LR_OSPF_METRIC_TYPE_1,
            )
        };
        assert_eq!(
            unsafe { lr_ospf_external_dest_metric_type(d) },
            LR_OSPF_METRIC_TYPE_1
        );
        unsafe { lr_ospf_external_dest_free(d) };
    }

    #[test]
    fn ffi_asbr_dest_new_and_readers() {
        let d = lr_ospf_asbr_dest_new(0x01020304, 50);
        assert!(!d.is_null());
        assert_eq!(unsafe { lr_ospf_asbr_dest_asbr(d) }, 0x01020304);
        assert_eq!(unsafe { lr_ospf_asbr_dest_metric(d) }, 50);
        unsafe { lr_ospf_asbr_dest_free(d) };
    }

    #[test]
    fn ffi_originate_external_lsa_v4() {
        let prefix_v4 = [10u8, 0, 0, 0];
        let d = unsafe {
            lr_ospf_external_dest_new(
                prefix_v4.as_ptr(),
                std::ptr::null(),
                24,
                100,
                LR_OSPF_METRIC_TYPE_2,
            )
        };
        let mut lsa: crate::ospf_lsdb::lr_ospf_lsa_box_t = std::ptr::null_mut();
        let rc = unsafe {
            lr_ospf_originate_external_lsa(0x01020304, d, std::ptr::null(), &raw mut lsa)
        };
        assert_eq!(rc, 0);
        assert!(!lsa.is_null());
        unsafe {
            crate::ospf_lsdb::lr_ospf_lsa_free(lsa);
            lr_ospf_external_dest_free(d);
        }
    }

    #[test]
    fn ffi_originate_summary_asbr_lsa() {
        let d = lr_ospf_asbr_dest_new(0x01020304, 50);
        let mut lsa: crate::ospf_lsdb::lr_ospf_lsa_box_t = std::ptr::null_mut();
        let rc = unsafe {
            lr_ospf_originate_summary_asbr_lsa(0x01020304, d, std::ptr::null(), &raw mut lsa)
        };
        assert_eq!(rc, 0);
        assert!(!lsa.is_null());
        unsafe {
            crate::ospf_lsdb::lr_ospf_lsa_free(lsa);
            lr_ospf_asbr_dest_free(d);
        }
    }

    #[test]
    fn ffi_external_dest_null_inputs() {
        // Both prefix pointers NULL → error.
        let d = unsafe {
            lr_ospf_external_dest_new(
                std::ptr::null(),
                std::ptr::null(),
                24,
                100,
                LR_OSPF_METRIC_TYPE_1,
            )
        };
        assert!(d.is_null());

        // Unknown metric_type → error.
        let prefix_v4 = [10u8, 0, 0, 0];
        let d =
            unsafe { lr_ospf_external_dest_new(prefix_v4.as_ptr(), std::ptr::null(), 24, 100, 99) };
        assert!(d.is_null());
    }

    #[test]
    fn ffi_free_handles_null_safely() {
        unsafe {
            lr_ospf_external_dest_free(std::ptr::null_mut());
            lr_ospf_asbr_dest_free(std::ptr::null_mut());
            lr_ospf_external_route_vec_free(std::ptr::null_mut());
            lr_ospf_external_route_v3_vec_free(std::ptr::null_mut());
        }
    }
}
