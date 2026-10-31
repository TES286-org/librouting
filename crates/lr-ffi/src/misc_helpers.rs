//! Stateless helper FFI surface — fills the remaining gaps in
//! lr_babel::metric, lr_ldp::session and lr_ospf::lsa::sr.
//!
//! These are pure functions (no handles, no allocator) that take
//! primitive arguments and return primitive results. Every entry point
//! runs inside the crate's `catch_unwind` barrier.

#![allow(unused_unsafe)]

use lr_babel::metric::{feasible, link_cost, route_metric, rtt_penalty};
use lr_core::addr::IpAddr;
use lr_ldp::session::{compare_transport_addrs, role_for};

use crate::error::{set_last_error, LR_ERR_PANIC};
use crate::guarded;
use crate::handle::lr_bytes_t;

const LR_ERR_NULL: i32 = -1;
const LR_ERR_INVALID_HANDLE: i32 = -2;
const LR_ERR_OTHER: i32 = -6;

// ---- Babel metric helpers (RFC 8966 §3.1) ----

/// Compute the link cost from a peer's RX cost (RFC 8966 §3.4.2).
#[no_mangle]
pub extern "C" fn lr_babel_link_cost(rxcost: u16) -> u32 {
    guarded(|| link_cost(rxcost), 0)
}

/// The RTT-based extra link cost (RFC 8966 §A.2.4, BABEL-RTT): a
/// linear ramp from 0 at `rtt_min_us` to `max_penalty` at
/// `rtt_max_us`, clamped at `max_penalty` above it.
/// `max_penalty == 0` disables the feature.
#[no_mangle]
pub extern "C" fn lr_babel_rtt_penalty(
    rtt_us: u32,
    rtt_min_us: u32,
    rtt_max_us: u32,
    max_penalty: u16,
) -> u16 {
    guarded(
        || rtt_penalty(rtt_us, rtt_min_us, rtt_max_us, max_penalty),
        0,
    )
}

/// Compute the total route metric: sum of link costs (RFC 8966 §3.1).
///
/// Renamed from `lr_babel_route_metric` so the unqualified name is
/// free for the per-route field reader on `lr_babel_route_t` (the
/// `BabelRoute::metric` field). The two functions are semantically
/// distinct: this one computes a metric from a list of link costs;
/// the field reader reads the stored metric from a route handle.
///
/// # Safety
/// `link_metrics` must point to `count` readable `uint32_t` values.
#[no_mangle]
pub unsafe extern "C" fn lr_babel_route_metric_sum(
    link_metrics: *const u32,
    count: usize,
) -> u32 {
    guarded(
        || unsafe {
            if link_metrics.is_null() && count != 0 {
                return 0;
            }
            let slice: &[u32] = if count == 0 {
                &[]
            } else {
                unsafe { core::slice::from_raw_parts(link_metrics, count) }
            };
            route_metric(slice)
        },
        0,
    )
}

/// Feasibility condition (RFC 8966 §3.2.2): a route is feasible iff
/// its (seqno, metric) pair is strictly better than the current
/// best-known feasible metric for the same source. Returns 1 when
/// feasible, 0 when not.
#[no_mangle]
pub extern "C" fn lr_babel_feasible(
    route_seqno: u16,
    route_metric: u32,
    feasible_seqno: u16,
    feasible_metric: u32,
) -> u8 {
    guarded(
        || feasible(route_seqno, route_metric, feasible_seqno, feasible_metric) as u8,
        0,
    )
}

// ---- LDP transport-address comparison (RFC 5036 §2.5.2) ----

/// Compare two transport addresses per RFC 5036 §2.5.2. Returns:
/// - `-1` when `a < b`
/// - `0` when `a == b`
/// - `1` when `a > b`
/// - `-2` (`LR_ERR_OTHER`) when the addresses are in different
///   families (incomparable — no session can be established).
///
/// # Safety
/// `a` must point to 4 (v4) or 16 (v6) readable bytes; `b` likewise.
#[no_mangle]
pub unsafe extern "C" fn lr_ldp_compare_transport_addrs(
    a_is_v6: u8,
    a: *const u8,
    b_is_v6: u8,
    b: *const u8,
) -> i32 {
    guarded(
        || unsafe {
            if a.is_null() || b.is_null() {
                return LR_ERR_NULL;
            }
            let addr_a = if a_is_v6 != 0 {
                let bytes = unsafe { core::slice::from_raw_parts(a, 16) };
                let mut arr = [0u8; 16];
                arr.copy_from_slice(bytes);
                IpAddr::V6(arr)
            } else {
                let bytes = unsafe { core::slice::from_raw_parts(a, 4) };
                let mut arr = [0u8; 4];
                arr.copy_from_slice(bytes);
                IpAddr::V4(arr)
            };
            let addr_b = if b_is_v6 != 0 {
                let bytes = unsafe { core::slice::from_raw_parts(b, 16) };
                let mut arr = [0u8; 16];
                arr.copy_from_slice(bytes);
                IpAddr::V6(arr)
            } else {
                let bytes = unsafe { core::slice::from_raw_parts(b, 4) };
                let mut arr = [0u8; 4];
                arr.copy_from_slice(bytes);
                IpAddr::V4(arr)
            };
            match compare_transport_addrs(&addr_a, &addr_b) {
                Some(core::cmp::Ordering::Less) => -1,
                Some(core::cmp::Ordering::Equal) => 0,
                Some(core::cmp::Ordering::Greater) => 1,
                None => LR_ERR_OTHER,
            }
        },
        LR_ERR_PANIC,
    )
}

/// The §2.5.2 role decision: the LSR with the higher transport
/// address plays the active role (RFC 5036 §2.5.2). Returns:
/// - `0` = Active (local > remote)
/// - `1` = Passive (local <= remote)
/// - `-1` = None (different families — no session)
///
/// # Safety
/// See [`lr_ldp_compare_transport_addrs`].
#[no_mangle]
pub unsafe extern "C" fn lr_ldp_role_for(
    local_is_v6: u8,
    local: *const u8,
    remote_is_v6: u8,
    remote: *const u8,
) -> i32 {
    guarded(
        || unsafe {
            if local.is_null() || remote.is_null() {
                return LR_ERR_NULL;
            }
            let addr_local = if local_is_v6 != 0 {
                let bytes = unsafe { core::slice::from_raw_parts(local, 16) };
                let mut arr = [0u8; 16];
                arr.copy_from_slice(bytes);
                IpAddr::V6(arr)
            } else {
                let bytes = unsafe { core::slice::from_raw_parts(local, 4) };
                let mut arr = [0u8; 4];
                arr.copy_from_slice(bytes);
                IpAddr::V4(arr)
            };
            let addr_remote = if remote_is_v6 != 0 {
                let bytes = unsafe { core::slice::from_raw_parts(remote, 16) };
                let mut arr = [0u8; 16];
                arr.copy_from_slice(bytes);
                IpAddr::V6(arr)
            } else {
                let bytes = unsafe { core::slice::from_raw_parts(remote, 4) };
                let mut arr = [0u8; 4];
                arr.copy_from_slice(bytes);
                IpAddr::V4(arr)
            };
            match role_for(&addr_local, &addr_remote) {
                Some(lr_ldp::session::SessionRole::Active) => 0,
                Some(lr_ldp::session::SessionRole::Passive) => 1,
                None => -1,
            }
        },
        LR_ERR_PANIC,
    )
}

// ---- OSPF SR label + opaque-type helpers (RFC 8665 §3/§5) ----

/// Compute the MPLS label a remote node's SRGB maps a SID index to
/// (RFC 8665 §5 / RFC 8402 §3.1.1). Returns the label, or 0 with
/// `*out_present = 0` when the index falls outside the originator's
/// advertised range or the SID carries the V/L flags (absolute/local
/// — the global mapping does not apply).
///
/// `srgb_base` and `srgb_range` are the originator's SRGB; `sid` is
/// the SID index; `flags` are the Prefix-SID flags (bit 0 = V, bit 1
/// = L, per RFC 8665 §5).
///
/// # Safety
/// `out` and `out_present` must point to writable `uint32_t` / `uint8_t`.
#[no_mangle]
pub unsafe extern "C" fn lr_ospf_sr_remote_label(
    srgb_base: u32,
    srgb_range: u32,
    sid: u32,
    flags: u8,
    out: *mut u32,
    out_present: *mut u8,
) -> i32 {
    guarded(
        || unsafe {
            if out.is_null() || out_present.is_null() {
                return LR_ERR_NULL;
            }
            // Reconstruct the Rust types so we can call the real
            // remote_label function — it validates the V/L flags and
            // the index-range check in one place.
            let srgb = lr_ospf::lsa::sr::RiSrBlock {
                srgb_base,
                srgb_range,
            };
            let sid_tlv = lr_ospf::lsa::sr::SrPrefixSidTlv {
                flags,
                mt_id: 0,
                algorithm: 0,
                sid,
            };
            match lr_ospf::lsa::sr::remote_label(&srgb, &sid_tlv) {
                Some(label) => unsafe {
                    *out = label;
                    *out_present = 1;
                },
                None => unsafe { *out_present = 0 },
            }
            0
        },
        LR_ERR_PANIC,
    )
}

/// Encode an RI-SR LSA body (RFC 8665 §3: the SRGB descriptor TLV).
/// Returns the wire bytes through `*out`. Returns `LR_ERR_OTHER`
/// when the SRGB range is zero (no SRGB to advertise).
///
/// # Safety
/// `out` must point to a writable `lr_bytes_t`.
#[no_mangle]
pub unsafe extern "C" fn lr_ospf_sr_encode_ri_lsa_body(
    srgb_base: u32,
    srgb_range: u32,
    out: *mut lr_bytes_t,
) -> i32 {
    guarded(
        || unsafe {
            if out.is_null() {
                return LR_ERR_NULL;
            }
            match lr_ospf::lsa::sr::encode_ri_sr_lsa_body(srgb_base, srgb_range) {
                Some(bytes) => {
                    unsafe { *out = lr_bytes_t::from_vec(bytes) }
                    0
                }
                None => {
                    set_last_error("encode_ri_sr_lsa_body: SRGB range is zero".into());
                    LR_ERR_OTHER
                }
            }
        },
        LR_ERR_PANIC,
    )
}

/// Decode an RI-SR LSA body (RFC 8665 §3). Writes the SRGB base to
/// `*out_srgb_base`, the SRGB range to `*out_srgb_range`, and `1`
/// to `*out_present` when the body carries a valid SRGB; `0` to
/// `*out_present` when the body is well-formed but carries no SRGB
/// block. Returns `LR_ERR_INVALID_HANDLE` (-2) on a malformed body.
///
/// # Safety
/// `data` must point to `len` readable bytes; all out-pointers must
/// point to writable memory of the documented type.
#[no_mangle]
pub unsafe extern "C" fn lr_ospf_sr_decode_ri_lsa_body(
    data: *const u8,
    len: usize,
    out_srgb_base: *mut u32,
    out_srgb_range: *mut u32,
    out_present: *mut u8,
) -> i32 {
    guarded(
        || unsafe {
            if data.is_null()
                || out_srgb_base.is_null()
                || out_srgb_range.is_null()
                || out_present.is_null()
            {
                return LR_ERR_NULL;
            }
            let slice = unsafe { core::slice::from_raw_parts(data, len) };
            match lr_ospf::lsa::sr::decode_ri_sr_lsa_body(slice) {
                Some(Some(block)) => unsafe {
                    *out_srgb_base = block.srgb_base;
                    *out_srgb_range = block.srgb_range;
                    *out_present = 1;
                },
                Some(None) => unsafe { *out_present = 0 },
                None => {
                    set_last_error("decode_ri_sr_lsa_body: malformed body".into());
                    return LR_ERR_INVALID_HANDLE;
                }
            }
            0
        },
        LR_ERR_PANIC,
    )
}

/// Extract the Opaque Type from an Opaque LSA's Link State ID (RFC
/// 5250 §3.1: the high 8 bits of the LS-ID). Takes the raw 32-bit
/// `link_state_id` field (not a full LSA handle).
#[no_mangle]
pub extern "C" fn lr_ospf_sr_opaque_type_from_lsid(link_state_id: u32) -> u8 {
    guarded(|| (link_state_id >> 24) as u8, 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ffi_babel_link_cost() {
        assert_eq!(lr_babel_link_cost(100), 100);
        assert_eq!(lr_babel_link_cost(0), 0);
        assert_eq!(lr_babel_link_cost(0xffff), 0xffff);
    }

    #[test]
    fn ffi_babel_rtt_penalty_ramp() {
        assert_eq!(lr_babel_rtt_penalty(0, 10_000, 120_000, 96), 0);
        assert_eq!(lr_babel_rtt_penalty(10_000, 10_000, 120_000, 96), 0);
        assert_eq!(lr_babel_rtt_penalty(65_000, 10_000, 120_000, 96), 48);
        assert_eq!(lr_babel_rtt_penalty(120_000, 10_000, 120_000, 96), 96);
        assert_eq!(lr_babel_rtt_penalty(500_000, 10_000, 120_000, 96), 96);
        assert_eq!(lr_babel_rtt_penalty(500_000, 10_000, 120_000, 0), 0);
    }

    #[test]
    fn ffi_babel_route_metric_sum() {
        let metrics = [100u32, 200, 300];
        let total = unsafe { lr_babel_route_metric_sum(metrics.as_ptr(), 3) };
        assert_eq!(total, 600);
        let total = unsafe { lr_babel_route_metric_sum(std::ptr::null(), 0) };
        assert_eq!(total, 0);
    }

    #[test]
    fn ffi_babel_feasible() {
        // Newer seqno → feasible.
        assert_eq!(lr_babel_feasible(10, 1000, 9, 100), 1);
        // Same seqno, lower metric → feasible.
        assert_eq!(lr_babel_feasible(10, 50, 10, 100), 1);
        // Same seqno, equal metric → not feasible.
        assert_eq!(lr_babel_feasible(10, 100, 10, 100), 0);
        // Older seqno → not feasible.
        assert_eq!(lr_babel_feasible(9, 50, 10, 100), 0);
    }

    #[test]
    fn ffi_ldp_compare_transport_addrs_v4() {
        let a = [10u8, 0, 0, 1];
        let b = [10u8, 0, 0, 2];
        assert_eq!(
            unsafe { lr_ldp_compare_transport_addrs(0, a.as_ptr(), 0, b.as_ptr()) },
            -1,
            "10.0.0.1 < 10.0.0.2"
        );
        assert_eq!(
            unsafe { lr_ldp_compare_transport_addrs(0, b.as_ptr(), 0, a.as_ptr()) },
            1,
            "10.0.0.2 > 10.0.0.1"
        );
        assert_eq!(
            unsafe { lr_ldp_compare_transport_addrs(0, a.as_ptr(), 0, a.as_ptr()) },
            0,
            "10.0.0.1 == 10.0.0.1"
        );
    }

    #[test]
    fn ffi_ldp_compare_transport_addrs_mismatched_families() {
        let a = [10u8, 0, 0, 1];
        let b = [0u8; 16];
        assert_eq!(
            unsafe { lr_ldp_compare_transport_addrs(0, a.as_ptr(), 1, b.as_ptr()) },
            LR_ERR_OTHER,
            "v4 vs v6 is incomparable"
        );
    }

    #[test]
    fn ffi_ldp_role_for() {
        let lower = [10u8, 0, 0, 1];
        let higher = [10u8, 0, 0, 2];
        // local=10.0.0.1, remote=10.0.0.2 → local < remote → Passive (1).
        assert_eq!(
            unsafe { lr_ldp_role_for(0, lower.as_ptr(), 0, higher.as_ptr()) },
            1,
            "lower local → Passive"
        );
        // local=10.0.0.2, remote=10.0.0.1 → local > remote → Active (0).
        assert_eq!(
            unsafe { lr_ldp_role_for(0, higher.as_ptr(), 0, lower.as_ptr()) },
            0,
            "higher local → Active"
        );
    }

    #[test]
    fn ffi_ldp_role_for_mismatched_families() {
        let v4 = [10u8, 0, 0, 1];
        let v6 = [0u8; 16];
        assert_eq!(
            unsafe { lr_ldp_role_for(0, v4.as_ptr(), 1, v6.as_ptr()) },
            -1,
            "mismatched families → None (-1)"
        );
    }

    #[test]
    fn ffi_ospf_sr_remote_label_in_range() {
        let mut label = 0u32;
        let mut present = 0u8;
        let rc = unsafe {
            lr_ospf_sr_remote_label(
                16000,
                9000,
                100,
                0, // no V/L flags
                &raw mut label,
                &raw mut present,
            )
        };
        assert_eq!(rc, 0);
        assert_eq!(present, 1);
        assert_eq!(label, 16100, "SRGB base 16000 + index 100 = 16100");
    }

    #[test]
    fn ffi_ospf_sr_remote_label_out_of_range() {
        let mut label = 0u32;
        let mut present = 0u8;
        let rc = unsafe {
            lr_ospf_sr_remote_label(
                16000,
                9000,
                99999, // way outside the range
                0,
                &raw mut label,
                &raw mut present,
            )
        };
        assert_eq!(rc, 0);
        assert_eq!(present, 0, "index outside range → None");
    }

    #[test]
    fn ffi_ospf_sr_remote_label_v_flag_rejects() {
        let mut label = 0u32;
        let mut present = 0u8;
        // V flag (0x08) set → absolute label, not a global mapping.
        let rc = unsafe {
            lr_ospf_sr_remote_label(
                16000,
                9000,
                100,
                0x08, // V flag
                &raw mut label,
                &raw mut present,
            )
        };
        assert_eq!(rc, 0);
        assert_eq!(present, 0, "V flag set → None");
    }

    #[test]
    fn ffi_ospf_sr_opaque_type_from_lsid() {
        // Opaque type 3 (Grace-LSA) in the high byte, opaque ID 0x123456.
        let lsid = lr_ospf::lsa::grace::opaque_lsa_id(3, 0x123456);
        assert_eq!(lr_ospf_sr_opaque_type_from_lsid(lsid), 3);
    }

    #[test]
    fn ffi_ospf_sr_ri_lsa_body_roundtrip() {
        let mut out = lr_bytes_t {
            ptr: std::ptr::null_mut(),
            len: 0,
            cap: 0,
        };
        let rc = unsafe { lr_ospf_sr_encode_ri_lsa_body(16000, 9000, &raw mut out) };
        assert_eq!(rc, 0);
        assert!(!out.ptr.is_null());

        // Reclaim the bytes for decoding.
        let bytes = if out.ptr.is_null() {
            Vec::new()
        } else {
            unsafe { Vec::from_raw_parts(out.ptr, out.len, out.cap) }
        };

        let mut base = 0u32;
        let mut range = 0u32;
        let mut present = 0u8;
        let rc = unsafe {
            lr_ospf_sr_decode_ri_lsa_body(
                bytes.as_ptr(),
                bytes.len(),
                &raw mut base,
                &raw mut range,
                &raw mut present,
            )
        };
        assert_eq!(rc, 0);
        assert_eq!(present, 1);
        assert_eq!(base, 16000);
        assert_eq!(range, 9000);
    }

    #[test]
    fn ffi_ospf_sr_encode_ri_lsa_body_rejects_zero_range() {
        let mut out = lr_bytes_t {
            ptr: std::ptr::null_mut(),
            len: 0,
            cap: 0,
        };
        let rc = unsafe { lr_ospf_sr_encode_ri_lsa_body(16000, 0, &raw mut out) };
        assert_eq!(rc, LR_ERR_OTHER, "zero SRGB range → LR_ERR_OTHER");
    }

    #[test]
    fn ffi_null_handle_returns_err_null() {
        let rc =
            unsafe { lr_ldp_compare_transport_addrs(0, std::ptr::null(), 0, std::ptr::null()) };
        assert_eq!(rc, LR_ERR_NULL);
    }
}
