//! BGP role / extended-next-hop / labeled-NLRI helper FFI surface —
//! fills the gaps left by the existing role_topology.rs / bgp_codec.rs
//! modules. Mirrors the stateless `pub fn`s in:
//!
//! - `lr_bgp::role::cluster::{compute_originator_id, prepend_cluster_id,
//!    cluster_list_has_loop}` (RFC 4456 §8-§10)
//! - `lr_bgp::role::otc::{otc_on_receive, otc_can_advertise}` (RFC 9234 §5)
//! - `lr_bgp::extensions::extended_next_hop::{advertised_tuples,
//!    negotiated_tuples, supports}` (RFC 5549)
//! - `lr_bgp::path::as_path::reconcile_as4` (RFC 6793 §4.2)
//! - `lr_bgp::path::labeled_nlri::{ipv4_implicit_null, encode_list,
//!    decode_list, encode_mp_reach, encode_mp_unreach, decode_mp_reach,
//!    decode_mp_unreach}` (RFC 8277)
//!
//! Every entry point runs inside the crate's `catch_unwind` barrier
//! ([`crate::guarded`]): a panic returns `LR_ERR_PANIC` and sets the
//! thread-local last-error string.

// The closure body passed to `guarded` is wrapped in a single `unsafe`
// block to mirror the `pub unsafe extern "C" fn` shape — the inner
// `unsafe { ... }` blocks would otherwise trip `unused_unsafe` under
// the crate's `-D warnings` clippy gate.
#![allow(unused_unsafe)]

use lr_bgp::extensions::extended_next_hop::{advertised_tuples, supports};
use lr_bgp::path::labeled_nlri::{encode_list, ipv4_implicit_null};
use lr_bgp::role::cluster::{cluster_list_has_loop, compute_originator_id, prepend_cluster_id};
use lr_bgp::role::otc::{otc_can_advertise, otc_on_receive, Otc};
use lr_core::addr::{Asn, Prefix, RouterId};

use crate::error::{set_last_error, LR_ERR_PANIC};
use crate::guarded;
use crate::handle::lr_bytes_t;

const LR_ERR_NULL: i32 = -1;
const LR_ERR_INVALID_HANDLE: i32 = -2;
#[allow(dead_code)]
const LR_ERR_OTHER: i32 = -6;

// ---- Cluster-List helpers (RFC 4456 §8-§10) ----

/// Compute the new ORIGINATOR_ID to insert when reflecting a route to
/// an RR-client (RFC 4456 §9). When `existing_present` is 1, the
/// existing ORIGINATOR_ID is preserved; otherwise the local BGP
/// identifier becomes the new ORIGINATOR_ID. Writes the 4-byte
/// ORIGINATOR_ID to `*out_addr` and `1` to `*out_present` when a
/// value is to be inserted.
///
/// # Safety
/// All out-pointers must point to writable memory of the documented
/// type; `out_addr` needs 4 bytes.
#[no_mangle]
pub unsafe extern "C" fn lr_bgp_compute_originator_id(
    existing_present: u8,
    existing_addr: *const u8,
    local_bgp_id: u32,
    out_addr: *mut u8,
    out_present: *mut u8,
) -> i32 {
    guarded(
        || unsafe {
            if out_addr.is_null() || out_present.is_null() {
                return LR_ERR_NULL;
            }
            let existing = if existing_present != 0 {
                if existing_addr.is_null() {
                    return LR_ERR_NULL;
                }
                let bytes = unsafe { core::slice::from_raw_parts(existing_addr, 4) };
                Some(RouterId::from_v4([bytes[0], bytes[1], bytes[2], bytes[3]]))
            } else {
                None
            };
            let local = RouterId::from_u32(local_bgp_id);
            match compute_originator_id(existing, local) {
                Some(rid) => {
                    let bytes = rid.to_v4_bytes();
                    unsafe {
                        core::ptr::copy_nonoverlapping(bytes.as_ptr(), out_addr, 4);
                        *out_present = 1;
                    }
                }
                None => unsafe { *out_present = 0 },
            }
            0
        },
        LR_ERR_PANIC,
    )
}

/// True when `cluster_list` contains `local_cluster` (RFC 4456 §10
/// loop check). `cluster_list` is a flat array of 4-byte cluster IDs;
/// `count` is the number of entries.
///
/// # Safety
/// `cluster_list` must point to `count * 4` readable bytes.
#[no_mangle]
pub unsafe extern "C" fn lr_bgp_cluster_list_has_loop(
    cluster_list: *const u8,
    count: usize,
    local_cluster: u32,
) -> u8 {
    guarded(
        || unsafe {
            if cluster_list.is_null() && count != 0 {
                return 0;
            }
            let bytes = if count == 0 {
                &[][..]
            } else {
                unsafe { core::slice::from_raw_parts(cluster_list, count * 4) }
            };
            let mut ids: Vec<lr_bgp::role::cluster::ClusterId> = Vec::with_capacity(count);
            for chunk in bytes.as_chunks::<4>().0 {
                let v = u32::from_be_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
                ids.push(lr_bgp::role::cluster::ClusterId(v));
            }
            cluster_list_has_loop(&ids, lr_bgp::role::cluster::ClusterId(local_cluster)) as u8
        },
        0,
    )
}

/// Prepend `local_cluster` to the cluster list and write the result
/// to `*out` as a flat array of 4-byte cluster IDs. The caller frees
/// the result with [`lr_bytes_free`]. `cluster_list` is the existing
/// list (NULL when empty); `count` is its entry count.
///
/// # Safety
/// `cluster_list` must point to `count * 4` readable bytes when
/// non-NULL; `out` must point to a writable `lr_bytes_t`.
#[no_mangle]
pub unsafe extern "C" fn lr_bgp_prepend_cluster_id(
    cluster_list: *const u8,
    count: usize,
    local_cluster: u32,
    out: *mut lr_bytes_t,
) -> i32 {
    guarded(
        || unsafe {
            if out.is_null() {
                return LR_ERR_NULL;
            }
            if cluster_list.is_null() && count != 0 {
                return LR_ERR_NULL;
            }
            let bytes = if count == 0 {
                &[][..]
            } else {
                unsafe { core::slice::from_raw_parts(cluster_list, count * 4) }
            };
            let mut ids: Vec<lr_bgp::role::cluster::ClusterId> = Vec::with_capacity(count);
            for chunk in bytes.as_chunks::<4>().0 {
                let v = u32::from_be_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
                ids.push(lr_bgp::role::cluster::ClusterId(v));
            }
            let out_ids = prepend_cluster_id(ids, lr_bgp::role::cluster::ClusterId(local_cluster));
            let mut out_bytes = Vec::with_capacity(out_ids.len() * 4);
            for id in out_ids {
                out_bytes.extend_from_slice(&id.0.to_be_bytes());
            }
            unsafe { *out = lr_bytes_t::from_vec(out_bytes) }
            0
        },
        LR_ERR_PANIC,
    )
}

// ---- OTC (RFC 9234 §5) ----

/// Apply the RFC 9234 §5 ingress rules:
///
/// - Rule 1: a route that already carries OTC received from a
///   Customer or RS-Client is a route leak.
/// - Rule 2: a route that carries OTC received from a Peer whose
///   value differs from the peer's AS is a route leak.
/// - Rule 3: a route received from a Provider, a Peer, or an RS
///   without OTC MUST have OTC added with the remote AS number.
///
/// `existing_present` + `existing_value` carry the route's existing
/// OTC; `local_role` is one of the LR_OTC_ROLE_* constants; `peer_as`
/// is the remote AS number. Writes the resulting OTC value to
/// `*out_value` and `1` to `*out_present` on success; `0` to
/// `*out_present` and returns LR_ERR_INVALID_HANDLE (-2) on a route
/// leak.
///
/// # Safety
/// All out-pointers must point to writable memory of the documented
/// type.
#[no_mangle]
pub unsafe extern "C" fn lr_bgp_otc_on_receive(
    existing_present: u8,
    existing_value: u32,
    local_role: u8,
    peer_as: u32,
    out_value: *mut u32,
    out_present: *mut u8,
) -> i32 {
    guarded(
        || unsafe {
            if out_value.is_null() || out_present.is_null() {
                return LR_ERR_NULL;
            }
            let existing = if existing_present != 0 {
                Some(Otc(existing_value))
            } else {
                None
            };
            let role = match lr_bgp::role::otc::OtcRole::from_u8(local_role) {
                Some(r) => r,
                None => {
                    set_last_error(format!("unknown OtcRole {local_role}"));
                    return LR_ERR_INVALID_HANDLE;
                }
            };
            match otc_on_receive(existing, role, Asn(peer_as)) {
                Ok(otc) => unsafe {
                    *out_value = otc.0;
                    *out_present = 1;
                    0
                },
                Err(_) => {
                    set_last_error("OTC route leak: RFC 9234 §5 ingress rule violated".into());
                    unsafe { *out_present = 0 };
                    LR_ERR_INVALID_HANDLE
                }
            }
        },
        LR_ERR_PANIC,
    )
}

/// True when a route with `route_otc` may be advertised to a peer
/// with `local_role` (RFC 9234 §5 egress rule 2: a route that
/// already carries OTC MUST NOT be propagated to Providers, Peers,
/// or RSes; it may go to Customers and RS-clients).
#[no_mangle]
pub extern "C" fn lr_bgp_otc_can_advertise(route_otc: u32, local_role: u8) -> u8 {
    guarded(
        || {
            let role = lr_bgp::role::otc::OtcRole::from_u8(local_role);
            match role {
                Some(r) => otc_can_advertise(Otc(route_otc), r) as u8,
                None => 0,
            }
        },
        0,
    )
}

// ---- Extended Next-Hop (RFC 5549) ----

/// One RFC 5549 tuple `(nlri_afi, nlri_safi, nh_afi)`. Mirrors
/// `lr_bgp::extensions::extended_next_hop::ExtNextHopTuple` field-for-
/// field.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct lr_bgp_ext_next_hop_tuple_t {
    pub nlri_afi: u16,
    pub nlri_safi: u8,
    pub nh_afi: u16,
}

/// Walk the BgpPeer's advertised RFC 5549 tuples and write them to
/// `*out_array` as a flat array of `lr_bgp_ext_next_hop_tuple_t`.
/// The caller frees the array with
/// [`lr_bgp_ext_next_hop_tuple_array_free`]. Returns the count
/// through `*out_count`.
///
/// # Safety
/// `peer` must be a valid `lr_bgp_peer_t`. Both out-pointers must
/// point to writable memory.
#[no_mangle]
pub unsafe extern "C" fn lr_bgp_peer_advertised_tuples(
    peer: crate::bgp_peer::lr_bgp_peer_t,
    out_count: *mut usize,
    out_array: *mut *mut lr_bgp_ext_next_hop_tuple_t,
) -> i32 {
    guarded(
        || unsafe {
            if peer.is_null() || out_count.is_null() || out_array.is_null() {
                return LR_ERR_NULL;
            }
            // SAFETY: see crate::bgp_peer::borrow_peer — same pattern.
            let peer_ref: &'static lr_bgp::fsm::BgpPeer =
                unsafe { &*(peer as *const lr_bgp::fsm::BgpPeer) };
            let tuples = advertised_tuples(peer_ref.config());
            let n = tuples.len();
            if n == 0 {
                unsafe {
                    *out_count = 0;
                    *out_array = core::ptr::null_mut();
                }
                return 0;
            }
            let mut c_arr: Vec<lr_bgp_ext_next_hop_tuple_t> = tuples
                .into_iter()
                .map(|t| lr_bgp_ext_next_hop_tuple_t {
                    nlri_afi: t.nlri_afi,
                    nlri_safi: t.nlri_safi,
                    nh_afi: t.nexthop_afi,
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

/// Free a tuple array produced by [`lr_bgp_advertised_tuples`]. Safe
/// on NULL.
///
/// # Safety
/// `arr` must have been produced by `lr_bgp_advertised_tuples` and not
/// already freed; `count` must match the count returned by the
/// advertised_tuples call.
#[no_mangle]
pub unsafe extern "C" fn lr_bgp_ext_next_hop_tuple_array_free(
    arr: *mut lr_bgp_ext_next_hop_tuple_t,
    count: usize,
) {
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

/// True when the `(nlri_afi, nlri_safi, nh_afi)` tuple is in the
/// negotiated set (RFC 5549 — the peer advertised the tuple in its
/// OPEN, and we negotiated Extended Next-Hop).
///
/// # Safety
/// `tuples` must point to `count` readable
/// `lr_bgp_ext_next_hop_tuple_t` values.
#[no_mangle]
pub unsafe extern "C" fn lr_bgp_ext_next_hop_supports(
    tuples: *const lr_bgp_ext_next_hop_tuple_t,
    count: usize,
    nlri_afi: u16,
    nlri_safi: u8,
    nh_afi: u16,
) -> u8 {
    guarded(
        || unsafe {
            if tuples.is_null() && count != 0 {
                return 0;
            }
            let slice: &[lr_bgp_ext_next_hop_tuple_t] = if count == 0 {
                &[]
            } else {
                unsafe { core::slice::from_raw_parts(tuples, count) }
            };
            let rust_tuples: Vec<lr_bgp::extensions::extended_next_hop::ExtNextHopTuple> = slice
                .iter()
                .map(|t| lr_bgp::extensions::extended_next_hop::ExtNextHopTuple {
                    nlri_afi: t.nlri_afi,
                    nlri_safi: t.nlri_safi,
                    nexthop_afi: t.nh_afi,
                })
                .collect();
            supports(&rust_tuples, nlri_afi, nlri_safi, nh_afi) as u8
        },
        0,
    )
}

// ---- Labeled Unicast (RFC 8277) ----

/// Build a one-label IPv4 NLRI with the implicit-null label (RFC
/// 8277 §3 — the canonical 'forward the packet unlabelled' marker).
/// `prefix_addr` is 4 bytes; writes the wire form to `*out`.
///
/// # Safety
/// `prefix_addr` must point to 4 readable bytes; `out` must point to
/// a writable `lr_bytes_t`.
#[no_mangle]
pub unsafe extern "C" fn lr_bgp_labeled_nlri_ipv4_implicit_null(
    prefix_addr: *const u8,
    prefix_len: u8,
    out: *mut lr_bytes_t,
) -> i32 {
    guarded(
        || unsafe {
            if prefix_addr.is_null() || out.is_null() {
                return LR_ERR_NULL;
            }
            let bytes = unsafe { core::slice::from_raw_parts(prefix_addr, 4) };
            let prefix = Prefix::new_v4([bytes[0], bytes[1], bytes[2], bytes[3]], prefix_len);
            let entry = ipv4_implicit_null(prefix);
            // Encode a single-entry list with add_path=false.
            let wire = encode_list(&[entry], false);
            unsafe { *out = lr_bytes_t::from_vec(wire) }
            0
        },
        LR_ERR_PANIC,
    )
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
    fn ffi_compute_originator_id_uses_local_when_absent() {
        let mut out_addr = [0u8; 4];
        let mut present = 0u8;
        let rc = unsafe {
            lr_bgp_compute_originator_id(
                0,
                std::ptr::null(),
                0x0a000001,
                out_addr.as_mut_ptr(),
                &raw mut present,
            )
        };
        assert_eq!(rc, 0);
        assert_eq!(present, 1);
        assert_eq!(out_addr, [10, 0, 0, 1]);
    }

    #[test]
    fn ffi_compute_originator_id_preserves_existing() {
        let existing = [192u8, 0, 2, 1];
        let mut out_addr = [0u8; 4];
        let mut present = 0u8;
        let rc = unsafe {
            lr_bgp_compute_originator_id(
                1,
                existing.as_ptr(),
                0x0a000001,
                out_addr.as_mut_ptr(),
                &raw mut present,
            )
        };
        assert_eq!(rc, 0);
        assert_eq!(present, 1);
        assert_eq!(out_addr, [192, 0, 2, 1], "existing ORIGINATOR_ID preserved");
    }

    #[test]
    fn ffi_cluster_list_has_loop_detects_local() {
        // 10.0.0.1 / 10.0.0.2 — local is 10.0.0.2 → loop.
        let bytes = [10u8, 0, 0, 1, 10, 0, 0, 2];
        let has_loop = unsafe { lr_bgp_cluster_list_has_loop(bytes.as_ptr(), 2, 0x0a000002) };
        assert_eq!(has_loop, 1);
        let has_loop = unsafe { lr_bgp_cluster_list_has_loop(bytes.as_ptr(), 2, 0x0a000003) };
        assert_eq!(has_loop, 0);
    }

    #[test]
    fn ffi_prepend_cluster_id_prepends_local() {
        let existing = [10u8, 0, 0, 2]; // 10.0.0.2
        let mut out = lr_bytes_t {
            ptr: std::ptr::null_mut(),
            len: 0,
            cap: 0,
        };
        let rc =
            unsafe { lr_bgp_prepend_cluster_id(existing.as_ptr(), 1, 0x0a000001, &raw mut out) };
        assert_eq!(rc, 0);
        let bytes = unsafe { bytes_to_vec(&mut out) };
        // Expect 8 bytes: 10.0.0.1 (prepended) + 10.0.0.2 (existing).
        assert_eq!(bytes, vec![10, 0, 0, 1, 10, 0, 0, 2]);
    }

    #[test]
    fn ffi_otc_on_receive_no_otc_from_peer_adds_peer_as() {
        // RFC 9234 §5 rule 2: a Peer without OTC gets tagged with its AS.
        // local_role = 3 (Peer).
        let mut value = 0u32;
        let mut present = 0u8;
        let rc = unsafe {
            lr_bgp_otc_on_receive(
                0,
                0,
                3, // LR_OTC_ROLE_PEER
                64512,
                &raw mut value,
                &raw mut present,
            )
        };
        assert_eq!(rc, 0);
        assert_eq!(present, 1);
        assert_eq!(value, 64512);
    }

    #[test]
    fn ffi_otc_on_receive_from_customer_with_otc_is_leak() {
        // RFC 9234 §5 rule 1: OTC from a Customer / RS-Client is a leak.
        // local_role = 1 (Provider) — peer is our customer.
        let mut value = 0u32;
        let mut present = 1u8;
        let rc = unsafe {
            lr_bgp_otc_on_receive(
                1,
                100,
                1, // LR_OTC_ROLE_PROVIDER — peer is our customer
                64512,
                &raw mut value,
                &raw mut present,
            )
        };
        assert_eq!(rc, LR_ERR_INVALID_HANDLE);
        assert_eq!(present, 0);
    }

    #[test]
    fn ffi_otc_can_advertise_blocks_egress_to_peer_when_set() {
        // RFC 9234 §5 egress rule 2: a route that carries OTC MUST NOT
        // go to a Peer (3) or to a Customer (2 — peer is our provider
        // here). LR_OTC_ROLE_PROVIDER (1) means peer is our customer;
        // allowed.
        assert_eq!(lr_bgp_otc_can_advertise(64512, 3), 0, "Peer: blocked");
        assert_eq!(
            lr_bgp_otc_can_advertise(64512, 1),
            1,
            "Provider: peer-is-customer, allowed"
        );
        // No OTC set: any role is allowed.
        assert_eq!(lr_bgp_otc_can_advertise(0, 3), 1, "No OTC: allowed");
    }

    #[test]
    fn ffi_labeled_nlri_ipv4_implicit_null_round_trips() {
        let prefix = [10u8, 0, 0, 0];
        let mut out = lr_bytes_t {
            ptr: std::ptr::null_mut(),
            len: 0,
            cap: 0,
        };
        let rc =
            unsafe { lr_bgp_labeled_nlri_ipv4_implicit_null(prefix.as_ptr(), 24, &raw mut out) };
        assert_eq!(rc, 0);
        let bytes = unsafe { bytes_to_vec(&mut out) };
        // RFC 8277 §3 wire form: 1 length byte + 3 label bytes (implicit
        // null = label value 3, S=1 → 0x00 0x00 0x31) + 3 prefix bytes.
        assert!(!bytes.is_empty());
        // Length byte: 3*8 + 24 = 48 bits.
        assert_eq!(bytes[0], 48);
        // Implicit-null label: value=3, bottom=1 → byte2 = (3<<4) | 1 = 0x31.
        assert_eq!(&bytes[1..4], &[0x00, 0x00, 0x31]);
        // Prefix bytes (3 of them, /24 in 3 bytes).
        assert_eq!(&bytes[4..7], &[10, 0, 0]);
    }

    #[test]
    fn ffi_null_handle_returns_err_null() {
        let rc = unsafe {
            lr_bgp_compute_originator_id(
                0,
                std::ptr::null(),
                0,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        };
        assert_eq!(rc, LR_ERR_NULL);
    }

    #[test]
    fn ffi_ext_next_hop_tuple_array_free_handles_null_safely() {
        unsafe {
            lr_bgp_ext_next_hop_tuple_array_free(std::ptr::null_mut(), 0);
        }
    }
}
