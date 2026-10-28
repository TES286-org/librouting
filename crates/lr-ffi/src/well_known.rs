//! BGP well-known path attribute codec FFI — `lr_bgp_well_known_*`.
//!
//! Mirrors the public Rust API of `lr_bgp::path::well_known::{Origin,
//! NextHop, Med, LocalPref, AtomicAggregate, Aggregator,
//! OriginatorId, ClusterList, Aigp, PmsiTunnel}` so an embedder can
//! build, inspect and round-trip the RFC 4271 §5.1 well-known path
//! attributes without going through the higher-level
//! `lr_bgp_path_attrs_*` collection API.
//!
//! The well-known attributes are stateless codecs: each takes raw
//! bytes (or a small set of fields) and produces raw bytes. They are
//! not opaque handles — every entry point is a free function that
//! writes the encoded form into a caller-supplied `lr_bytes_t` (or
//! reads it from a caller-supplied byte slice). This matches the
//! Rust inherent-impl API where `decode(b: &[u8]) -> Option<Self>`
//! and `encode(&self) -> Vec<u8>` are the only shapes.
//!
//! # Surface
//!
//! - `lr_bgp_well_known_origin_decode` / `_encode` — ORIGIN (RFC 4271 §5.1.2).
//! - `lr_bgp_well_known_next_hop_decode` / `_encode` — NEXT_HOP (RFC 4271 §5.1.3).
//! - `lr_bgp_well_known_med_decode` / `_encode` — MULTI_EXIT_DISC (RFC 4271 §5.1.4).
//! - `lr_bgp_well_known_local_pref_decode` / `_encode` — LOCAL_PREF (RFC 4271 §5.1.5).
//! - `lr_bgp_well_known_aggregator_decode` / `_encode_4` — AGGREGATOR (RFC 4271 §5.1.7 / RFC 6793).
//! - `lr_bgp_well_known_originator_id_decode` / `_encode` — ORIGINATOR_ID (RFC 4456 §8).
//! - `lr_bgp_well_known_cluster_list_decode` / `_encode` — CLUSTER_LIST (RFC 4456 §8).
//! - `lr_bgp_well_known_aigp_decode` / `_encode` — AIGP (RFC 7311).
//! - `lr_bgp_well_known_pmsi_tunnel_decode` / `_encode` — PMSI Tunnel (RFC 6514 §5).
//!
//! Every entry point runs inside the crate's `catch_unwind` barrier
//! ([`crate::guarded`]): a panic returns `LR_ERR_PANIC` and sets the
//! thread-local last-error string.

#![allow(unused_unsafe)]

use lr_bgp::path::well_known::{
    Aggregator, Aigp, ClusterList, LocalPref, Med, NextHop, Origin, OriginatorId, PmsiTunnel,
};

use crate::error::{set_last_error, LrError, LR_ERR_PANIC};
use crate::guarded;
use crate::handle::lr_bytes_t;

const LR_ERR_NULL: i32 = LrError::Null as i32;
const LR_ERR_OTHER: i32 = LrError::Other as i32;

// ---- ORIGIN (RFC 4271 §5.1.2) ----

/// Decode an ORIGIN attribute (RFC 4271 §5.1.2). `data` is the
/// attribute value (1 byte: 0=IGP, 1=EGP, 2=INCOMPLETE). Writes the
/// origin kind (0/1/2) to `*out`. Returns 0 on success, `LR_ERR_NULL`
/// on a NULL pointer, `LR_ERR_OTHER` on a decode failure.
///
/// # Safety
/// `data` must point to `len` readable bytes. `out` must point to a
/// writable `uint8_t`.
#[no_mangle]
pub unsafe extern "C" fn lr_bgp_well_known_origin_decode(
    data: *const u8,
    len: usize,
    out: *mut u8,
) -> i32 {
    guarded(
        || unsafe {
            if data.is_null() || out.is_null() {
                return LR_ERR_NULL;
            }
            let slice = unsafe { std::slice::from_raw_parts(data, len) };
            match Origin::decode(slice) {
                Some(o) => {
                    unsafe { *out = o.0 as u8 }
                    0
                }
                None => {
                    set_last_error("ORIGIN decode: invalid length or value".into());
                    LR_ERR_OTHER
                }
            }
        },
        LR_ERR_PANIC,
    )
}

/// Encode an ORIGIN attribute. `kind` is 0 (IGP), 1 (EGP) or 2
/// (INCOMPLETE). Writes 1 byte to `*out`.
///
/// # Safety
/// `out` must point to a writable `lr_bytes_t`.
#[no_mangle]
pub extern "C" fn lr_bgp_well_known_origin_encode(kind: u8, out: *mut lr_bytes_t) -> i32 {
    guarded(
        || {
            if out.is_null() {
                return LR_ERR_NULL;
            }
            // The Rust side masks nothing — but the wire form is a single
            // byte 0/1/2, so we validate here.
            if kind > 2 {
                set_last_error(format!("ORIGIN encode: invalid kind {kind}"));
                return LR_ERR_OTHER;
            }
            let o = Origin::new(match kind {
                0 => lr_bgp::path::well_known::OriginKind::Igp,
                1 => lr_bgp::path::well_known::OriginKind::Egp,
                _ => lr_bgp::path::well_known::OriginKind::Incomplete,
            });
            let bytes = o.encode().to_vec();
            unsafe { *out = lr_bytes_t::from_vec(bytes) }
            0
        },
        LR_ERR_PANIC,
    )
}

// ---- NEXT_HOP (RFC 4271 §5.1.3) ----

/// Decode a NEXT_HOP attribute (RFC 4271 §5.1.3). `data` is the
/// attribute value: 4 bytes (IPv4) or 16 bytes (IPv6 for IPv4 NLRI
/// under RFC 5549). Writes 1 to `*out_is_ipv6` when the next-hop is
/// IPv6 (or IPv4-over-IPv6), 0 when it is IPv4. The address bytes
/// are written to `*out_addr` (4 bytes for v4, 16 for v6).
///
/// # Safety
/// `data` must point to `len` readable bytes. `out_is_ipv6` must
/// point to a writable `uint8_t`. `out_addr` must point to 16
/// writable bytes (the function always writes 16, with the trailing
/// 12 bytes zeroed for a v4 next-hop).
#[no_mangle]
pub unsafe extern "C" fn lr_bgp_well_known_next_hop_decode(
    data: *const u8,
    len: usize,
    out_is_ipv6: *mut u8,
    out_addr: *mut u8,
) -> i32 {
    guarded(
        || unsafe {
            if data.is_null() || out_is_ipv6.is_null() || out_addr.is_null() {
                return LR_ERR_NULL;
            }
            let slice = unsafe { std::slice::from_raw_parts(data, len) };
            match NextHop::decode(slice) {
                Some(nh) => {
                    let (is_v6, addr) = match nh.0 {
                        lr_bgp::path::well_known::NextHopKind::V4(b) => (0u8, b.to_vec()),
                        lr_bgp::path::well_known::NextHopKind::V6(b)
                        | lr_bgp::path::well_known::NextHopKind::V4OverV6(b) => (1u8, b.to_vec()),
                    };
                    unsafe {
                        *out_is_ipv6 = is_v6;
                        // Zero-fill 16 bytes then write the address
                        // bytes at the start.
                        std::ptr::write_bytes(out_addr, 0, 16);
                        std::ptr::copy_nonoverlapping(addr.as_ptr(), out_addr, addr.len());
                    }
                    0
                }
                None => {
                    set_last_error("NEXT_HOP decode: invalid length".into());
                    LR_ERR_OTHER
                }
            }
        },
        LR_ERR_PANIC,
    )
}

/// Encode a NEXT_HOP attribute. `is_ipv6 = 0` writes 4 bytes (IPv4),
/// `is_ipv6 = 1` writes 16 bytes (IPv6). `addr` must point to 4 or
/// 16 readable bytes accordingly.
///
/// # Safety
/// `addr` must point to 4 readable bytes when `is_ipv6 == 0`, or 16
/// readable bytes when `is_ipv6 == 1`. `out` must point to a writable
/// `lr_bytes_t`.
#[no_mangle]
pub unsafe extern "C" fn lr_bgp_well_known_next_hop_encode(
    is_ipv6: u8,
    addr: *const u8,
    out: *mut lr_bytes_t,
) -> i32 {
    guarded(
        || unsafe {
            if addr.is_null() || out.is_null() {
                return LR_ERR_NULL;
            }
            let nh = if is_ipv6 == 0 {
                let mut a = [0u8; 4];
                a.copy_from_slice(unsafe { std::slice::from_raw_parts(addr, 4) });
                NextHop::from_v4(a)
            } else {
                let mut a = [0u8; 16];
                a.copy_from_slice(unsafe { std::slice::from_raw_parts(addr, 16) });
                NextHop::from_v6(a)
            };
            let bytes = nh.encode();
            unsafe { *out = lr_bytes_t::from_vec(bytes) }
            0
        },
        LR_ERR_PANIC,
    )
}

// ---- MULTI_EXIT_DISC (RFC 4271 §5.1.4) ----

/// Decode a MULTI_EXIT_DISC attribute (RFC 4271 §5.1.4). `data` is
/// 4 bytes (big-endian u32). Writes the metric to `*out`.
///
/// # Safety
/// `data` must point to `len` readable bytes. `out` must point to a
/// writable `uint32_t`.
#[no_mangle]
pub unsafe extern "C" fn lr_bgp_well_known_med_decode(
    data: *const u8,
    len: usize,
    out: *mut u32,
) -> i32 {
    guarded(
        || unsafe {
            if data.is_null() || out.is_null() {
                return LR_ERR_NULL;
            }
            let slice = unsafe { std::slice::from_raw_parts(data, len) };
            match Med::decode(slice) {
                Some(m) => {
                    unsafe { *out = m.0 }
                    0
                }
                None => {
                    set_last_error("MED decode: invalid length".into());
                    LR_ERR_OTHER
                }
            }
        },
        LR_ERR_PANIC,
    )
}

/// Encode a MULTI_EXIT_DISC attribute. Writes 4 bytes (big-endian u32).
///
/// # Safety
/// `out` must point to a writable `lr_bytes_t`.
#[no_mangle]
pub extern "C" fn lr_bgp_well_known_med_encode(value: u32, out: *mut lr_bytes_t) -> i32 {
    guarded(
        || {
            if out.is_null() {
                return LR_ERR_NULL;
            }
            let bytes = Med(value).encode().to_vec();
            unsafe { *out = lr_bytes_t::from_vec(bytes) }
            0
        },
        LR_ERR_PANIC,
    )
}

// ---- LOCAL_PREF (RFC 4271 §5.1.5) ----

/// Decode a LOCAL_PREF attribute (RFC 4271 §5.1.5). `data` is 4 bytes.
///
/// # Safety
/// See [`lr_bgp_well_known_med_decode`].
#[no_mangle]
pub unsafe extern "C" fn lr_bgp_well_known_local_pref_decode(
    data: *const u8,
    len: usize,
    out: *mut u32,
) -> i32 {
    guarded(
        || unsafe {
            if data.is_null() || out.is_null() {
                return LR_ERR_NULL;
            }
            let slice = unsafe { std::slice::from_raw_parts(data, len) };
            match LocalPref::decode(slice) {
                Some(lp) => {
                    unsafe { *out = lp.0 }
                    0
                }
                None => {
                    set_last_error("LOCAL_PREF decode: invalid length".into());
                    LR_ERR_OTHER
                }
            }
        },
        LR_ERR_PANIC,
    )
}

/// Encode a LOCAL_PREF attribute. Writes 4 bytes.
///
/// # Safety
/// See [`lr_bgp_well_known_med_encode`].
#[no_mangle]
pub extern "C" fn lr_bgp_well_known_local_pref_encode(value: u32, out: *mut lr_bytes_t) -> i32 {
    guarded(
        || {
            if out.is_null() {
                return LR_ERR_NULL;
            }
            let bytes = LocalPref(value).encode().to_vec();
            unsafe { *out = lr_bytes_t::from_vec(bytes) }
            0
        },
        LR_ERR_PANIC,
    )
}

// ---- AGGREGATOR (RFC 4271 §5.1.7 / RFC 6793) ----

/// Decode an AGGREGATOR attribute (RFC 4271 §5.1.7 / RFC 6793). The
/// `data` argument is 6 bytes (2-octet AS + 4-octet speaker) or 8
/// bytes (4-octet AS + 4-octet speaker). Writes the ASN to `*out_asn`
/// and the 4-byte speaker BGP identifier to `out_speaker`.
///
/// # Safety
///
/// `data` must point to `len` readable bytes. `out_asn` must point
/// to a writable `uint32_t`. `out_speaker` must point to 4 writable
/// bytes.
#[no_mangle]
pub unsafe extern "C" fn lr_bgp_well_known_aggregator_decode(
    data: *const u8,
    len: usize,
    out_asn: *mut u32,
    out_speaker: *mut u8,
) -> i32 {
    guarded(
        || unsafe {
            if data.is_null() || out_asn.is_null() || out_speaker.is_null() {
                return LR_ERR_NULL;
            }
            let slice = unsafe { std::slice::from_raw_parts(data, len) };
            match Aggregator::decode(slice) {
                Some(a) => {
                    unsafe {
                        *out_asn = a.asn.0;
                        std::ptr::copy_nonoverlapping(a.speaker.as_ptr(), out_speaker, 4);
                    }
                    0
                }
                None => {
                    set_last_error("AGGREGATOR decode: invalid length".into());
                    LR_ERR_OTHER
                }
            }
        },
        LR_ERR_PANIC,
    )
}

/// Encode an AGGREGATOR attribute in the 4-octet-AS form (RFC 6793).
/// Writes 8 bytes.
///
/// # Safety
/// `speaker` must point to 4 readable bytes. `out` must point to a
/// writable `lr_bytes_t`.
#[no_mangle]
pub unsafe extern "C" fn lr_bgp_well_known_aggregator_encode_4(
    asn: u32,
    speaker: *const u8,
    out: *mut lr_bytes_t,
) -> i32 {
    guarded(
        || unsafe {
            if speaker.is_null() || out.is_null() {
                return LR_ERR_NULL;
            }
            let mut sp = [0u8; 4];
            sp.copy_from_slice(unsafe { std::slice::from_raw_parts(speaker, 4) });
            let a = Aggregator {
                asn: lr_core::addr::Asn(asn),
                speaker: sp,
            };
            let bytes = a.encode_4().to_vec();
            unsafe { *out = lr_bytes_t::from_vec(bytes) }
            0
        },
        LR_ERR_PANIC,
    )
}

// ---- ORIGINATOR_ID (RFC 4456 §8) ----

/// Decode an ORIGINATOR_ID attribute (RFC 4456 §8). `data` is 4 bytes
/// (BGP Identifier). Writes the identifier to `*out_bgp_id`.
///
/// # Safety
/// `data` must point to `len` readable bytes. `out_bgp_id` must
/// point to a writable `uint32_t`.
#[no_mangle]
pub unsafe extern "C" fn lr_bgp_well_known_originator_id_decode(
    data: *const u8,
    len: usize,
    out_bgp_id: *mut u32,
) -> i32 {
    guarded(
        || unsafe {
            if data.is_null() || out_bgp_id.is_null() {
                return LR_ERR_NULL;
            }
            let slice = unsafe { std::slice::from_raw_parts(data, len) };
            match OriginatorId::decode(slice) {
                Some(oid) => {
                    unsafe { *out_bgp_id = oid.0.as_u32() }
                    0
                }
                None => {
                    set_last_error("ORIGINATOR_ID decode: invalid length".into());
                    LR_ERR_OTHER
                }
            }
        },
        LR_ERR_PANIC,
    )
}

/// Encode an ORIGINATOR_ID attribute. Writes 4 bytes.
///
/// # Safety
/// `out` must point to a writable `lr_bytes_t`.
#[no_mangle]
pub extern "C" fn lr_bgp_well_known_originator_id_encode(bgp_id: u32, out: *mut lr_bytes_t) -> i32 {
    guarded(
        || {
            if out.is_null() {
                return LR_ERR_NULL;
            }
            let bytes = OriginatorId::from_u32(bgp_id).encode().to_vec();
            unsafe { *out = lr_bytes_t::from_vec(bytes) }
            0
        },
        LR_ERR_PANIC,
    )
}

// ---- CLUSTER_LIST (RFC 4456 §8) ----

/// Decode a CLUSTER_LIST attribute (RFC 4456 §8). `data` is a
/// sequence of 4-byte cluster IDs. Writes the cluster IDs as a flat
/// `uint32_t` array into a caller-supplied buffer; writes the count
/// to `*out_count`. If the buffer is too small, writes the required
/// count and returns `LR_ERR_OTHER`.
///
/// # Safety
/// `data` must point to `len` readable bytes. `out_clusters` must
/// point to `cap` writable `uint32_t` values (NULL is allowed only
/// when `cap == 0`, in which case the function only reports the
/// count). `out_count` must point to a writable `uintptr_t`.
#[no_mangle]
pub unsafe extern "C" fn lr_bgp_well_known_cluster_list_decode(
    data: *const u8,
    len: usize,
    out_clusters: *mut u32,
    cap: usize,
    out_count: *mut usize,
) -> i32 {
    guarded(
        || unsafe {
            if data.is_null() || out_count.is_null() {
                return LR_ERR_NULL;
            }
            let slice = unsafe { std::slice::from_raw_parts(data, len) };
            match ClusterList::decode(slice) {
                Some(cl) => {
                    let n = cl.0.len();
                    unsafe { *out_count = n }
                    if n > cap {
                        set_last_error(format!(
                            "CLUSTER_LIST buffer too small: need {n}, have {cap}"
                        ));
                        return LR_ERR_OTHER;
                    }
                    if !out_clusters.is_null() && n > 0 {
                        let ids: Vec<u32> = cl.0.iter().map(|r| r.as_u32()).collect();
                        unsafe {
                            std::ptr::copy_nonoverlapping(ids.as_ptr(), out_clusters, n);
                        }
                    }
                    0
                }
                None => {
                    set_last_error("CLUSTER_LIST decode: invalid length".into());
                    LR_ERR_OTHER
                }
            }
        },
        LR_ERR_PANIC,
    )
}

/// Encode a CLUSTER_LIST attribute from a flat `uint32_t` array of
/// cluster IDs. Writes `count * 4` bytes.
///
/// # Safety
/// `clusters` must point to `count` readable `uint32_t` values (NULL
/// is allowed only when `count == 0`). `out` must point to a writable
/// `lr_bytes_t`.
#[no_mangle]
pub unsafe extern "C" fn lr_bgp_well_known_cluster_list_encode(
    clusters: *const u32,
    count: usize,
    out: *mut lr_bytes_t,
) -> i32 {
    guarded(
        || unsafe {
            if out.is_null() {
                return LR_ERR_NULL;
            }
            if clusters.is_null() && count != 0 {
                return LR_ERR_NULL;
            }
            let ids: Vec<lr_core::addr::RouterId> = if count == 0 {
                Vec::new()
            } else {
                unsafe { std::slice::from_raw_parts(clusters, count) }
                    .iter()
                    .map(|v| lr_core::addr::RouterId::from_u32(*v))
                    .collect()
            };
            let cl = ClusterList(ids);
            let bytes = cl.encode();
            unsafe { *out = lr_bytes_t::from_vec(bytes) }
            0
        },
        LR_ERR_PANIC,
    )
}

// ---- AIGP (RFC 7311) ----

/// Decode an AIGP attribute (RFC 7311). `data` is the TLV form: a
/// single TLV with type 1 (AIGP) and a 64-bit accumulated metric.
/// Writes the metric to `*out_metric`.
///
/// # Safety
/// `data` must point to `len` readable bytes. `out_metric` must
/// point to a writable `uint64_t`.
#[no_mangle]
pub unsafe extern "C" fn lr_bgp_well_known_aigp_decode(
    data: *const u8,
    len: usize,
    out_metric: *mut u64,
) -> i32 {
    guarded(
        || unsafe {
            if data.is_null() || out_metric.is_null() {
                return LR_ERR_NULL;
            }
            let slice = unsafe { std::slice::from_raw_parts(data, len) };
            match Aigp::decode(slice) {
                Some(a) => {
                    unsafe { *out_metric = a.0 }
                    0
                }
                None => {
                    set_last_error("AIGP decode: invalid TLV".into());
                    LR_ERR_OTHER
                }
            }
        },
        LR_ERR_PANIC,
    )
}

/// Encode an AIGP attribute. Writes the TLV form (12 bytes: 2-byte
/// type + 2-byte length + 8-byte metric).
///
/// # Safety
/// `out` must point to a writable `lr_bytes_t`.
#[no_mangle]
pub extern "C" fn lr_bgp_well_known_aigp_encode(metric: u64, out: *mut lr_bytes_t) -> i32 {
    guarded(
        || {
            if out.is_null() {
                return LR_ERR_NULL;
            }
            let bytes = Aigp(metric).encode();
            unsafe { *out = lr_bytes_t::from_vec(bytes) }
            0
        },
        LR_ERR_PANIC,
    )
}

// ---- PMSI Tunnel (RFC 6514 §5) ----

/// Decode a PMSI Tunnel attribute (RFC 6514 §5). `data` is the
/// attribute value: 1 byte flags + 1 byte tunnel type + 1 byte
/// label length (always 3) + 3-byte label + tunnel-id bytes. Writes
/// the flags, tunnel type, label, and tunnel-id length to the
/// out-pointers; the tunnel-id bytes are returned via `out_tunnel_id`
/// as a `lr_bytes_t` (caller frees with `lr_bytes_free`).
///
/// # Safety
/// `data` must point to `len` readable bytes. The four scalar
/// out-pointers must point to writable memory of the right type.
/// `out_tunnel_id` must point to a writable `lr_bytes_t`.
#[no_mangle]
pub unsafe extern "C" fn lr_bgp_well_known_pmsi_tunnel_decode(
    data: *const u8,
    len: usize,
    out_flags: *mut u8,
    out_tunnel_type: *mut u8,
    out_label: *mut u32,
    out_tunnel_id: *mut lr_bytes_t,
) -> i32 {
    guarded(
        || unsafe {
            if data.is_null()
                || out_flags.is_null()
                || out_tunnel_type.is_null()
                || out_label.is_null()
                || out_tunnel_id.is_null()
            {
                return LR_ERR_NULL;
            }
            let slice = unsafe { std::slice::from_raw_parts(data, len) };
            match PmsiTunnel::decode(slice) {
                Some(p) => {
                    unsafe {
                        *out_flags = p.flags;
                        *out_tunnel_type = p.tunnel_type;
                        *out_label = p.mpls_label;
                        *out_tunnel_id = lr_bytes_t::from_vec(p.tunnel_id.clone());
                    }
                    0
                }
                None => {
                    set_last_error("PMSI Tunnel decode: invalid length".into());
                    LR_ERR_OTHER
                }
            }
        },
        LR_ERR_PANIC,
    )
}

/// Encode a PMSI Tunnel attribute. `label` is a 20-bit MPLS label
/// packed into the low 20 bits of a `uint32_t`. `tunnel_id` is the
/// tunnel-id bytes (NULL only when `tunnel_id_len == 0`).
///
/// # Safety
/// `tunnel_id` must point to `tunnel_id_len` readable bytes (NULL
/// only when `tunnel_id_len == 0`). `out` must point to a writable
/// `lr_bytes_t`.
#[no_mangle]
pub unsafe extern "C" fn lr_bgp_well_known_pmsi_tunnel_encode(
    flags: u8,
    tunnel_type: u8,
    label: u32,
    tunnel_id: *const u8,
    tunnel_id_len: usize,
    out: *mut lr_bytes_t,
) -> i32 {
    guarded(
        || unsafe {
            if out.is_null() {
                return LR_ERR_NULL;
            }
            if tunnel_id.is_null() && tunnel_id_len != 0 {
                return LR_ERR_NULL;
            }
            let p = PmsiTunnel::new(
                flags,
                tunnel_type,
                label,
                if tunnel_id.is_null() || tunnel_id_len == 0 {
                    Vec::new()
                } else {
                    unsafe { std::slice::from_raw_parts(tunnel_id, tunnel_id_len).to_vec() }
                },
            );
            let bytes = p.encode();
            unsafe { *out = lr_bytes_t::from_vec(bytes) }
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
    fn ffi_well_known_origin_roundtrip() {
        // Encode IGP (kind=0).
        let mut out = lr_bytes_t {
            ptr: std::ptr::null_mut(),
            len: 0,
            cap: 0,
        };
        let rc = lr_bgp_well_known_origin_encode(0, &raw mut out);
        assert_eq!(rc, 0);
        let bytes = unsafe { bytes_to_vec(&mut out) };
        assert_eq!(bytes, vec![0]);

        // Decode it back.
        let mut kind = 0u8;
        let rc =
            unsafe { lr_bgp_well_known_origin_decode(bytes.as_ptr(), bytes.len(), &raw mut kind) };
        assert_eq!(rc, 0);
        assert_eq!(kind, 0);

        // Invalid kind.
        let rc = lr_bgp_well_known_origin_encode(3, &raw mut out);
        assert_eq!(rc, LR_ERR_OTHER);
    }

    #[test]
    fn ffi_well_known_med_roundtrip() {
        let mut out = lr_bytes_t {
            ptr: std::ptr::null_mut(),
            len: 0,
            cap: 0,
        };
        let rc = lr_bgp_well_known_med_encode(100, &raw mut out);
        assert_eq!(rc, 0);
        let bytes = unsafe { bytes_to_vec(&mut out) };
        assert_eq!(bytes, vec![0, 0, 0, 100]);

        let mut value = 0u32;
        let rc =
            unsafe { lr_bgp_well_known_med_decode(bytes.as_ptr(), bytes.len(), &raw mut value) };
        assert_eq!(rc, 0);
        assert_eq!(value, 100);
    }

    #[test]
    fn ffi_well_known_local_pref_roundtrip() {
        let mut out = lr_bytes_t {
            ptr: std::ptr::null_mut(),
            len: 0,
            cap: 0,
        };
        let rc = lr_bgp_well_known_local_pref_encode(200, &raw mut out);
        assert_eq!(rc, 0);
        let bytes = unsafe { bytes_to_vec(&mut out) };
        assert_eq!(bytes, vec![0, 0, 0, 200]);

        let mut value = 0u32;
        let rc = unsafe {
            lr_bgp_well_known_local_pref_decode(bytes.as_ptr(), bytes.len(), &raw mut value)
        };
        assert_eq!(rc, 0);
        assert_eq!(value, 200);
    }

    #[test]
    fn ffi_well_known_aggregator_roundtrip() {
        let speaker = [10u8, 0, 0, 1];
        let mut out = lr_bytes_t {
            ptr: std::ptr::null_mut(),
            len: 0,
            cap: 0,
        };
        let rc =
            unsafe { lr_bgp_well_known_aggregator_encode_4(65001, speaker.as_ptr(), &raw mut out) };
        assert_eq!(rc, 0);
        let bytes = unsafe { bytes_to_vec(&mut out) };
        // 8 bytes: 4-byte ASN + 4-byte speaker.
        assert_eq!(bytes.len(), 8);
        assert_eq!(&bytes[0..4], &[0, 0, 0xfd, 0xe9]); // 65001 BE
        assert_eq!(&bytes[4..8], &speaker);

        let mut asn = 0u32;
        let mut sp = [0u8; 4];
        let rc = unsafe {
            lr_bgp_well_known_aggregator_decode(
                bytes.as_ptr(),
                bytes.len(),
                &raw mut asn,
                sp.as_mut_ptr(),
            )
        };
        assert_eq!(rc, 0);
        assert_eq!(asn, 65001);
        assert_eq!(sp, speaker);
    }

    #[test]
    fn ffi_well_known_originator_id_roundtrip() {
        let mut out = lr_bytes_t {
            ptr: std::ptr::null_mut(),
            len: 0,
            cap: 0,
        };
        let rc = lr_bgp_well_known_originator_id_encode(0x0a000001, &raw mut out);
        assert_eq!(rc, 0);
        let bytes = unsafe { bytes_to_vec(&mut out) };
        assert_eq!(bytes, vec![10, 0, 0, 1]);

        let mut bgp_id = 0u32;
        let rc = unsafe {
            lr_bgp_well_known_originator_id_decode(bytes.as_ptr(), bytes.len(), &raw mut bgp_id)
        };
        assert_eq!(rc, 0);
        assert_eq!(bgp_id, 0x0a000001);
    }

    #[test]
    fn ffi_well_known_cluster_list_roundtrip() {
        let clusters: [u32; 3] = [0x0a000001, 0x0a000002, 0x0a000003];
        let mut out = lr_bytes_t {
            ptr: std::ptr::null_mut(),
            len: 0,
            cap: 0,
        };
        let rc =
            unsafe { lr_bgp_well_known_cluster_list_encode(clusters.as_ptr(), 3, &raw mut out) };
        assert_eq!(rc, 0);
        let bytes = unsafe { bytes_to_vec(&mut out) };
        assert_eq!(bytes.len(), 12);

        let mut decoded = [0u32; 3];
        let mut count = 0usize;
        let rc = unsafe {
            lr_bgp_well_known_cluster_list_decode(
                bytes.as_ptr(),
                bytes.len(),
                decoded.as_mut_ptr(),
                3,
                &raw mut count,
            )
        };
        assert_eq!(rc, 0);
        assert_eq!(count, 3);
        assert_eq!(decoded, clusters);
    }

    #[test]
    fn ffi_well_known_aigp_roundtrip() {
        let mut out = lr_bytes_t {
            ptr: std::ptr::null_mut(),
            len: 0,
            cap: 0,
        };
        let rc = lr_bgp_well_known_aigp_encode(12345, &raw mut out);
        assert_eq!(rc, 0);
        let bytes = unsafe { bytes_to_vec(&mut out) };
        // AIGP TLV: type(2) + length(2) + metric(8) = 12 bytes.
        assert_eq!(bytes.len(), 12);

        let mut metric = 0u64;
        let rc =
            unsafe { lr_bgp_well_known_aigp_decode(bytes.as_ptr(), bytes.len(), &raw mut metric) };
        assert_eq!(rc, 0);
        assert_eq!(metric, 12345);
    }

    #[test]
    fn ffi_well_known_pmsi_tunnel_roundtrip() {
        let tunnel_id = [0xde, 0xad, 0xbe, 0xef];
        let mut out = lr_bytes_t {
            ptr: std::ptr::null_mut(),
            len: 0,
            cap: 0,
        };
        // flags=1 (leaf info required), tunnel_type=6 (IR), label=16 (low 24 bits).
        let rc = unsafe {
            lr_bgp_well_known_pmsi_tunnel_encode(
                1,
                6,
                16,
                tunnel_id.as_ptr(),
                tunnel_id.len(),
                &raw mut out,
            )
        };
        assert_eq!(rc, 0);
        let bytes = unsafe { bytes_to_vec(&mut out) };
        // flags(1) + tunnel_type(1) + label(3) + tunnel_id(4) = 9 bytes.
        assert_eq!(bytes.len(), 9);

        let mut flags = 0u8;
        let mut tunnel_type = 0u8;
        let mut label = 0u32;
        let mut tid = lr_bytes_t {
            ptr: std::ptr::null_mut(),
            len: 0,
            cap: 0,
        };
        let rc = unsafe {
            lr_bgp_well_known_pmsi_tunnel_decode(
                bytes.as_ptr(),
                bytes.len(),
                &raw mut flags,
                &raw mut tunnel_type,
                &raw mut label,
                &raw mut tid,
            )
        };
        assert_eq!(rc, 0);
        assert_eq!(flags, 1);
        assert_eq!(tunnel_type, 6);
        assert_eq!(label, 16);
        let tid_bytes = unsafe { bytes_to_vec(&mut tid) };
        assert_eq!(tid_bytes, tunnel_id);
    }

    #[test]
    fn ffi_well_known_next_hop_v4_roundtrip() {
        let addr = [10u8, 0, 0, 1];
        let mut out = lr_bytes_t {
            ptr: std::ptr::null_mut(),
            len: 0,
            cap: 0,
        };
        let rc = unsafe { lr_bgp_well_known_next_hop_encode(0, addr.as_ptr(), &raw mut out) };
        assert_eq!(rc, 0);
        let bytes = unsafe { bytes_to_vec(&mut out) };
        assert_eq!(bytes, vec![10, 0, 0, 1]);

        let mut is_ipv6 = 0u8;
        let mut out_addr = [0u8; 16];
        let rc = unsafe {
            lr_bgp_well_known_next_hop_decode(
                bytes.as_ptr(),
                bytes.len(),
                &raw mut is_ipv6,
                out_addr.as_mut_ptr(),
            )
        };
        assert_eq!(rc, 0);
        assert_eq!(is_ipv6, 0);
        assert_eq!(&out_addr[0..4], &addr);
    }

    #[test]
    fn ffi_well_known_decode_rejects_invalid_length() {
        let mut value = 0u32;
        // MED requires exactly 4 bytes; 3 is invalid.
        let rc = unsafe { lr_bgp_well_known_med_decode([0, 0, 0].as_ptr(), 3, &raw mut value) };
        assert_eq!(rc, LR_ERR_OTHER);
    }
}
