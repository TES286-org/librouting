//! OSPF ABR summary-LSA + NSSA-LSA origination (RFC 2328 §12.4.3,
//! RFC 3101 §2.4) and the §16.4 NSSA route projection.
//!
//! Mirrors the public Rust API of `lr_ospf::abr` and `lr_ospf::nssa`:
//! - `SummaryDestination` / `originate_summary_lsa` / `flush_summary_lsa`
//!   / `originate_v3_inter_area_prefix_lsa` / `summary_lsa_id_for`
//! - `NssaDefault` / `originate_nssa_lsa` / `flush_nssa_lsa` /
//!   `originate_nssa_default_lsa`
//! - `NssaCalcOpts` / `nssa_routes` / `nssa_routes_v3` /
//!   `nssa_routes_v3_extended` / `is_elected_translator`
//! - `p_bit_set` / `N_P_BIT`

#![allow(unused_unsafe)]
#![allow(unused_imports)]
#![allow(dead_code)]

use lr_core::addr::{IpAddr, Prefix};
use lr_ospf::abr::{
    flush_summary_lsa, originate_summary_lsa, originate_v3_inter_area_prefix_lsa,
    summary_lsa_id_for, SummaryDestination,
};
use lr_ospf::lsa::Lsa;
use lr_ospf::nssa::{
    flush_nssa_lsa, is_elected_translator, nssa_routes, nssa_routes_v3, nssa_routes_v3_extended,
    originate_nssa_default_lsa, originate_nssa_lsa, NssaCalcOpts, NssaDefault,
};

use crate::error::{set_last_error, LrError, LR_ERR_PANIC};
use crate::guarded;

const LR_ERR_NULL: i32 = LrError::Null as i32;
const LR_ERR_OTHER: i32 = LrError::Other as i32;

/// NSSA P-bit (RFC 3101 §2.4) — set on type-7 LSAs that ask border
/// routers to translate them into type-5s.
pub const LR_OSPF_NSSA_N_P_BIT: u8 = 0x08;

/// NSSA translator-mode calculation options — mirrors
/// `NssaCalcOpts`.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct lr_ospf_nssa_calc_opts_t {
    /// 1 = the calculating router is a border router of the NSSA
    /// (§2.5 step (3): skip type-7 defaults the border router would
    /// not install).
    pub border_router: u8,
    /// 1 = the NSSA suppresses type-3 summary import ("no-summary"
    /// mode). Border routers then ignore type-7 defaults entirely.
    pub summaries_suppressed: u8,
}

fn nssa_opts_from_c(c: lr_ospf_nssa_calc_opts_t) -> NssaCalcOpts {
    NssaCalcOpts {
        border_router: c.border_router != 0,
        summaries_suppressed: c.summaries_suppressed != 0,
    }
}

// ---- SummaryDestination ----

/// Opaque `SummaryDestination` handle.
#[repr(C)]
pub struct OpaqueOspfSummaryDest {
    _private: [u8; 0],
}
pub type lr_ospf_summary_dest_t = *mut OpaqueOspfSummaryDest;

fn box_summary(d: SummaryDestination) -> lr_ospf_summary_dest_t {
    Box::into_raw(Box::new(d)) as lr_ospf_summary_dest_t
}
unsafe fn borrow_summary(d: lr_ospf_summary_dest_t) -> Option<&'static SummaryDestination> {
    if d.is_null() {
        return None;
    }
    Some(unsafe { &*(d as *const SummaryDestination) })
}

/// Construct a `SummaryDestination` (RFC 2328 §12.4.3) for type-3
/// summary-LSA origination. The `prefix_v4` / `prefix_v6` slots follow
/// the same convention as the rest of the FFI: pass exactly one.
///
/// # Safety
/// `prefix_v4` must point to 4 readable bytes when v4; `prefix_v6`
/// must point to 16 readable bytes when v6.
#[no_mangle]
pub unsafe extern "C" fn lr_ospf_summary_dest_new(
    prefix_v4: *const u8,
    prefix_v6: *const u8,
    prefix_len: u8,
    metric: u32,
) -> lr_ospf_summary_dest_t {
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
                set_last_error("lr_ospf_summary_dest_new: both prefix pointers NULL".into());
                return std::ptr::null_mut();
            };
            box_summary(SummaryDestination::new(Prefix { addr, prefix_len }, metric))
        },
        std::ptr::null_mut(),
    )
}

/// Read the metric (capped at LSInfinity - 1).
///
/// # Safety
/// `d` must be a valid handle.
#[no_mangle]
pub unsafe extern "C" fn lr_ospf_summary_dest_metric(d: lr_ospf_summary_dest_t) -> u32 {
    guarded(
        || unsafe { borrow_summary(d).map(|x| x.metric).unwrap_or(0) },
        0,
    )
}

/// Read the prefix as `(is_ipv6, octets_out[16], prefix_len_out)`.
///
/// # Safety
/// `d` must be a valid handle; `octets_out` must point to 16 writable
/// bytes; `prefix_len_out` must point to a writable `uint8_t`.
#[no_mangle]
pub unsafe extern "C" fn lr_ospf_summary_dest_prefix(
    d: lr_ospf_summary_dest_t,
    octets_out: *mut u8,
    prefix_len_out: *mut u8,
) -> i32 {
    guarded(
        || unsafe {
            let Some(dest) = borrow_summary(d) else {
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

/// Drop a boxed `SummaryDestination`. Safe to call with `NULL`.
///
/// # Safety
/// `d` must have been produced by [`lr_ospf_summary_dest_new`] and not
/// already freed.
#[no_mangle]
pub unsafe extern "C" fn lr_ospf_summary_dest_free(d: lr_ospf_summary_dest_t) {
    guarded(
        || unsafe {
            if d.is_null() {
                return;
            }
            drop(unsafe { Box::from_raw(d as *mut SummaryDestination) });
        },
        (),
    )
}

// ---- summary-LSA origination ----

/// Compute the 32-bit Link State ID for a summary-LSA summarizing
/// `prefix`, applying the RFC 2328 Appendix E collision-remapping
/// algorithm. `existing_ls_ids` is a flat array of `(ls_id, prefix_len)`
/// pairs packed as `ls_id_lo | (ls_id_hi << 8) | (prefix_len << 16)`
/// (use the helper inline; each pair occupies one `u32`). Returns 1 +
/// the LS-ID written to `*out` on success (1 so 0 can be a NULL
/// indicator), 0 when the collision is unsolvable.
///
/// Actually, simpler shape: write the LS-ID to `*out` and return 1
/// on success, 0 on unsolvable / non-IPv4 prefix.
///
/// # Safety
/// `existing` must point to `count` readable `uint32_t` values; `out`
/// must point to writable `uint32_t`.
#[no_mangle]
pub unsafe extern "C" fn lr_ospf_summary_lsa_id_for(
    prefix_v4: *const u8,
    prefix_v6: *const u8,
    prefix_len: u8,
    existing: *const u32,
    count: usize,
    out: *mut u32,
) -> i32 {
    guarded(
        || unsafe {
            if out.is_null() {
                return LR_ERR_NULL;
            }
            let addr = if !prefix_v4.is_null() {
                let b = unsafe { std::slice::from_raw_parts(prefix_v4, 4) };
                IpAddr::V4([b[0], b[1], b[2], b[3]])
            } else if !prefix_v6.is_null() {
                let b = unsafe { std::slice::from_raw_parts(prefix_v6, 16) };
                let mut octets = [0u8; 16];
                octets.copy_from_slice(b);
                IpAddr::V6(octets)
            } else {
                set_last_error("lr_ospf_summary_lsa_id_for: both prefix pointers NULL".into());
                return LR_ERR_NULL;
            };
            let prefix = Prefix { addr, prefix_len };
            let existing_slice: &[u32] = if count == 0 || existing.is_null() {
                &[]
            } else {
                unsafe { std::slice::from_raw_parts(existing, count) }
            };
            // Unpack each u32 as (ls_id_low_24, prefix_len_high_8) —
            // for v4 LS-IDs only the low 24 bits matter (top 8 are
            // the prefix length).
            let existing_pairs: Vec<(u32, u8)> = existing_slice
                .iter()
                .map(|v| (*v & 0x00ff_ffff, (*v >> 24) as u8))
                .collect();
            match summary_lsa_id_for(&prefix, &existing_pairs) {
                Some(lsid) => {
                    unsafe { *out = lsid };
                    1
                }
                None => 0,
            }
        },
        LR_ERR_PANIC,
    )
}

/// Originate a type-3 summary-LSA (RFC 2328 §12.4.3). The `dest`
/// carries the prefix and metric; `prev_seq` is the previous
/// instance's sequence number (`NULL` to start fresh).
///
/// # Safety
/// `dest` must be a valid handle; `out` must point to writable
/// `lr_ospf_lsa_box_t`.
#[no_mangle]
pub unsafe extern "C" fn lr_ospf_originate_summary_lsa(
    router_id: u32,
    dest: lr_ospf_summary_dest_t,
    prev_seq: *const u32,
    out: *mut crate::ospf_lsdb::lr_ospf_lsa_box_t,
) -> i32 {
    guarded(
        || unsafe {
            let Some(dest_val) = borrow_summary(dest) else {
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
            match originate_summary_lsa(router_id, dest_val, prev) {
                Some(lsa) => {
                    unsafe {
                        *out = crate::ospf_lsdb::box_lsa(lsa);
                    }
                    0
                }
                None => {
                    set_last_error("lr_ospf_originate_summary_lsa: sequence exhausted".into());
                    LR_ERR_OTHER
                }
            }
        },
        LR_ERR_PANIC,
    )
}

/// MaxAge-flush an existing summary-LSA (RFC 2328 §14.1).
///
/// # Safety
/// `existing` must be a valid `lr_ospf_lsa_box_t` handle (borrowed);
/// `out` must point to writable `lr_ospf_lsa_box_t`.
#[no_mangle]
pub unsafe extern "C" fn lr_ospf_flush_summary_lsa(
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
            match flush_summary_lsa(existing_lsa) {
                Some(flushed) => {
                    unsafe {
                        *out = crate::ospf_lsdb::box_lsa(flushed);
                    }
                    0
                }
                None => {
                    set_last_error("lr_ospf_flush_summary_lsa: cannot flush".into());
                    LR_ERR_OTHER
                }
            }
        },
        LR_ERR_PANIC,
    )
}

/// Originate an OSPFv3 inter-area-prefix-LSA (RFC 5340 §4.4.3).
///
/// # Safety
/// `dest` must be a valid `SummaryDestination` handle; `out` must
/// point to writable `lr_ospf_lsa_box_t`.
#[no_mangle]
pub unsafe extern "C" fn lr_ospf_originate_v3_inter_area_prefix_lsa(
    router_id: u32,
    ls_id: u32,
    dest: lr_ospf_summary_dest_t,
    prev_seq: *const u32,
    out: *mut crate::ospf_lsdb::lr_ospf_lsa_box_t,
) -> i32 {
    guarded(
        || unsafe {
            let Some(dest_val) = borrow_summary(dest) else {
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
            match originate_v3_inter_area_prefix_lsa(router_id, ls_id, dest_val, prev) {
                Some(lsa) => {
                    unsafe {
                        *out = crate::ospf_lsdb::box_lsa(lsa);
                    }
                    0
                }
                None => {
                    set_last_error(
                        "lr_ospf_originate_v3_inter_area_prefix_lsa: sequence exhausted".into(),
                    );
                    LR_ERR_OTHER
                }
            }
        },
        LR_ERR_PANIC,
    )
}

// ---- NSSA origination ----

/// Opaque `NssaDefault` handle.
#[repr(C)]
pub struct OpaqueOspfNssaDefault {
    _private: [u8; 0],
}
pub type lr_ospf_nssa_default_t = *mut OpaqueOspfNssaDefault;

/// Construct a `NssaDefault` (RFC 3101 §2.4 default summary) for
/// `originate_nssa_default_lsa`. The `metric` is the only field —
/// the type-7 default always carries the E-bit (RFC 3101 §2.4).
///
/// # Safety
/// None — the inputs are by value.
#[no_mangle]
pub extern "C" fn lr_ospf_nssa_default_new(metric: u32) -> lr_ospf_nssa_default_t {
    guarded(
        || Box::into_raw(Box::new(NssaDefault::new(metric))) as lr_ospf_nssa_default_t,
        std::ptr::null_mut(),
    )
}

/// Drop a boxed `NssaDefault`. Safe to call with `NULL`.
///
/// # Safety
/// `d` must have been produced by [`lr_ospf_nssa_default_new`] and
/// not already freed.
#[no_mangle]
pub unsafe extern "C" fn lr_ospf_nssa_default_free(d: lr_ospf_nssa_default_t) {
    guarded(
        || unsafe {
            if d.is_null() {
                return;
            }
            drop(unsafe { Box::from_raw(d as *mut NssaDefault) });
        },
        (),
    )
}

/// Originate a type-7 NSSA-LSA (RFC 3101 §2.4) for the given
/// `ExternalDestination`. The `p_bit` is taken from the dest (set
/// with `lr_ospf_external_dest_set_p_bit`).
///
/// # Safety
/// `dest` must be a valid `ExternalDestination` handle; `out` must
/// point to writable `lr_ospf_lsa_box_t`.
#[no_mangle]
pub unsafe extern "C" fn lr_ospf_originate_nssa_lsa(
    router_id: u32,
    dest: crate::ospf_external::lr_ospf_external_dest_t,
    prev_seq: *const u32,
    out: *mut crate::ospf_lsdb::lr_ospf_lsa_box_t,
) -> i32 {
    guarded(
        || unsafe {
            let Some(dest_val) = crate::ospf_external::borrow_dest_pub(dest) else {
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
            match originate_nssa_lsa(router_id, dest_val, prev) {
                Some(lsa) => {
                    unsafe {
                        *out = crate::ospf_lsdb::box_lsa(lsa);
                    }
                    0
                }
                None => {
                    set_last_error("lr_ospf_originate_nssa_lsa: sequence exhausted".into());
                    LR_ERR_OTHER
                }
            }
        },
        LR_ERR_PANIC,
    )
}

/// MaxAge-flush an existing type-7 NSSA-LSA.
///
/// # Safety
/// `existing` must be a valid `lr_ospf_lsa_box_t` handle (borrowed);
/// `out` must point to writable `lr_ospf_lsa_box_t`.
#[no_mangle]
pub unsafe extern "C" fn lr_ospf_flush_nssa_lsa(
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
            match flush_nssa_lsa(existing_lsa) {
                Some(flushed) => {
                    unsafe {
                        *out = crate::ospf_lsdb::box_lsa(flushed);
                    }
                    0
                }
                None => {
                    set_last_error("lr_ospf_flush_nssa_lsa: cannot flush".into());
                    LR_ERR_OTHER
                }
            }
        },
        LR_ERR_PANIC,
    )
}

/// Originate a type-7 default NSSA-LSA (RFC 3101 §2.4 default
/// summary).
///
/// # Safety
/// `default_dest` must be a valid `NssaDefault` handle; `out` must
/// point to writable `lr_ospf_lsa_box_t`.
#[no_mangle]
pub unsafe extern "C" fn lr_ospf_originate_nssa_default_lsa(
    router_id: u32,
    default_dest: lr_ospf_nssa_default_t,
    prev_seq: *const u32,
    out: *mut crate::ospf_lsdb::lr_ospf_lsa_box_t,
) -> i32 {
    guarded(
        || unsafe {
            if default_dest.is_null() || out.is_null() {
                return LR_ERR_NULL;
            }
            let dest: &NssaDefault = unsafe { &*(default_dest as *const NssaDefault) };
            let prev = if prev_seq.is_null() {
                None
            } else {
                Some(unsafe { *prev_seq })
            };
            match originate_nssa_default_lsa(router_id, dest, prev) {
                Some(lsa) => {
                    unsafe {
                        *out = crate::ospf_lsdb::box_lsa(lsa);
                    }
                    0
                }
                None => {
                    set_last_error("lr_ospf_originate_nssa_default_lsa: sequence exhausted".into());
                    LR_ERR_OTHER
                }
            }
        },
        LR_ERR_PANIC,
    )
}

/// True when the local `router_id` is elected as the type-7→type-5
/// translator for the area whose LSDB is `lsdb` (RFC 3101 §2.5 step
/// (2)). Returns 0 (false) on a NULL handle.
///
/// # Safety
/// `lsdb` must be a valid handle.
#[no_mangle]
pub unsafe extern "C" fn lr_ospf_is_elected_translator(
    lsdb: crate::ospf_lsdb::lr_ospf_lsdb_t,
    router_id: u32,
) -> u8 {
    guarded(
        || unsafe {
            let Some(lsdb_ref) = crate::ospf_lsdb::borrow_lsdb(lsdb) else {
                return 0;
            };
            is_elected_translator(lsdb_ref, router_id) as u8
        },
        0,
    )
}

/// True when the LSA's P-bit (RFC 3101 §2.4) is set. Returns 0 on a
/// NULL handle.
///
/// # Safety
/// `lsa` must be a valid handle.
#[no_mangle]
pub unsafe extern "C" fn lr_ospf_nssa_p_bit_set(lsa: crate::ospf_lsdb::lr_ospf_lsa_box_t) -> u8 {
    guarded(
        || unsafe {
            let Some(lsa_ref) = crate::ospf_lsdb::borrow_lsa(lsa) else {
                return 0;
            };
            lr_ospf::nssa::p_bit_set(lsa_ref) as u8
        },
        0,
    )
}

// ---- NSSA route projection (§16.4) ----

/// Opaque `Vec<ExternalRoute>` handle (the §16.4 NSSA calculation
/// output). Reuses the v2 external-route vec type — NSSA routes are
/// ExternalRoute values, just computed from type-7 LSAs instead of
/// type-5s.
pub type lr_ospf_nssa_route_vec_t = crate::ospf_external::lr_ospf_external_route_vec_t;

/// Compute the §16.4 NSSA route candidates for one area (RFC 3101
/// §2.4 + RFC 2328 §16.4). Returns a freshly-allocated vec handle.
///
/// # Safety
/// `lsdb` and `spf_result` must be valid handles.
#[no_mangle]
pub unsafe extern "C" fn lr_ospf_nssa_routes(
    lsdb: crate::ospf_lsdb::lr_ospf_lsdb_t,
    spf_result: crate::ospf_spf::lr_ospf_spf_result_t,
    opts: lr_ospf_nssa_calc_opts_t,
) -> lr_ospf_nssa_route_vec_t {
    guarded(
        || unsafe {
            let Some(lsdb_ref) = crate::ospf_lsdb::borrow_lsdb(lsdb) else {
                return std::ptr::null_mut();
            };
            let Some(spf_ref) = crate::ospf_spf::borrow_result(spf_result) else {
                return std::ptr::null_mut();
            };
            let routes = nssa_routes(lsdb_ref, spf_ref, nssa_opts_from_c(opts));
            Box::into_raw(Box::new(routes)) as lr_ospf_nssa_route_vec_t
        },
        std::ptr::null_mut(),
    )
}

/// v3 form of [`lr_ospf_nssa_routes`] (RFC 5340 §4.4.3.6).
///
/// # Safety
/// `lsdb` and `spf_result` must be valid handles.
#[no_mangle]
pub unsafe extern "C" fn lr_ospf_nssa_routes_v3(
    lsdb: crate::ospf_lsdb::lr_ospf_lsdb_t,
    spf_result: crate::ospf_spf::lr_ospf_spf_v3_result_t,
    opts: lr_ospf_nssa_calc_opts_t,
) -> crate::ospf_external::lr_ospf_external_route_v3_vec_t {
    guarded(
        || unsafe {
            let Some(lsdb_ref) = crate::ospf_lsdb::borrow_lsdb(lsdb) else {
                return std::ptr::null_mut();
            };
            let Some(spf_ref) = crate::ospf_spf::borrow_v3_result(spf_result) else {
                return std::ptr::null_mut();
            };
            let routes = nssa_routes_v3(lsdb_ref, spf_ref, nssa_opts_from_c(opts));
            Box::into_raw(Box::new(routes)) as crate::ospf_external::lr_ospf_external_route_v3_vec_t
        },
        std::ptr::null_mut(),
    )
}

/// Extended-LSA mode of [`lr_ospf_nssa_routes_v3`] (RFC 8362 §6.1).
///
/// # Safety
/// `lsdb` and `spf_result` must be valid handles.
#[no_mangle]
pub unsafe extern "C" fn lr_ospf_nssa_routes_v3_extended(
    lsdb: crate::ospf_lsdb::lr_ospf_lsdb_t,
    spf_result: crate::ospf_spf::lr_ospf_spf_v3_result_t,
    opts: lr_ospf_nssa_calc_opts_t,
) -> crate::ospf_external::lr_ospf_external_route_v3_vec_t {
    guarded(
        || unsafe {
            let Some(lsdb_ref) = crate::ospf_lsdb::borrow_lsdb(lsdb) else {
                return std::ptr::null_mut();
            };
            let Some(spf_ref) = crate::ospf_spf::borrow_v3_result(spf_result) else {
                return std::ptr::null_mut();
            };
            let routes = nssa_routes_v3_extended(lsdb_ref, spf_ref, nssa_opts_from_c(opts));
            Box::into_raw(Box::new(routes)) as crate::ospf_external::lr_ospf_external_route_v3_vec_t
        },
        std::ptr::null_mut(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ffi_summary_dest_new_and_readers() {
        let prefix_v4 = [10u8, 0, 0, 0];
        let d = unsafe { lr_ospf_summary_dest_new(prefix_v4.as_ptr(), std::ptr::null(), 24, 100) };
        assert!(!d.is_null());
        assert_eq!(unsafe { lr_ospf_summary_dest_metric(d) }, 100);

        let mut octets = [0u8; 16];
        let mut plen = 0u8;
        let rc = unsafe { lr_ospf_summary_dest_prefix(d, octets.as_mut_ptr(), &raw mut plen) };
        assert_eq!(rc, 0);
        assert_eq!(plen, 24);
        assert_eq!(&octets[..4], &[10, 0, 0, 0]);
        unsafe { lr_ospf_summary_dest_free(d) };
    }

    #[test]
    fn ffi_summary_lsa_id_for_no_collision() {
        let prefix_v4 = [10u8, 0, 0, 0];
        let mut out = 0u32;
        let rc = unsafe {
            lr_ospf_summary_lsa_id_for(
                prefix_v4.as_ptr(),
                std::ptr::null(),
                24,
                std::ptr::null(),
                0,
                &raw mut out,
            )
        };
        assert_eq!(rc, 1);
        // 10.0.0.0/24 → network = 0x0A000000.
        assert_eq!(out, 0x0A000000);
    }

    #[test]
    fn ffi_originate_summary_lsa() {
        let prefix_v4 = [10u8, 0, 0, 0];
        let d = unsafe { lr_ospf_summary_dest_new(prefix_v4.as_ptr(), std::ptr::null(), 24, 100) };
        let mut lsa: crate::ospf_lsdb::lr_ospf_lsa_box_t = std::ptr::null_mut();
        let rc =
            unsafe { lr_ospf_originate_summary_lsa(0x01020304, d, std::ptr::null(), &raw mut lsa) };
        assert_eq!(rc, 0);
        assert!(!lsa.is_null());
        unsafe {
            crate::ospf_lsdb::lr_ospf_lsa_free(lsa);
            lr_ospf_summary_dest_free(d);
        }
    }

    #[test]
    fn ffi_originate_v3_inter_area_prefix_lsa() {
        let prefix_v4 = [10u8, 0, 0, 0];
        let d = unsafe { lr_ospf_summary_dest_new(prefix_v4.as_ptr(), std::ptr::null(), 24, 100) };
        let mut lsa: crate::ospf_lsdb::lr_ospf_lsa_box_t = std::ptr::null_mut();
        let rc = unsafe {
            lr_ospf_originate_v3_inter_area_prefix_lsa(
                0x01020304,
                0,
                d,
                std::ptr::null(),
                &raw mut lsa,
            )
        };
        assert_eq!(rc, 0);
        assert!(!lsa.is_null());
        unsafe {
            crate::ospf_lsdb::lr_ospf_lsa_free(lsa);
            lr_ospf_summary_dest_free(d);
        }
    }

    #[test]
    fn ffi_nssa_default_new_and_free() {
        let d = lr_ospf_nssa_default_new(100);
        assert!(!d.is_null());
        unsafe { lr_ospf_nssa_default_free(d) };
    }

    #[test]
    fn ffi_free_handles_null_safely() {
        unsafe {
            lr_ospf_summary_dest_free(std::ptr::null_mut());
            lr_ospf_nssa_default_free(std::ptr::null_mut());
        }
    }
}
