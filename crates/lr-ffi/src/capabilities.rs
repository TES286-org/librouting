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
// The opaque-bytes and opaque-array helpers box `Vec<u8>` /
// `Vec<lr_bgp_capability_t>` behind `Box::into_raw` so the FFI can
// hand a pointer to C; clippy considers `Box<Vec<_>>` redundant with
// `Vec<_>` but here we need the Box to match the `Box::into_raw`
// reclaim path.
#![allow(clippy::box_collection)]

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
// ---- Capability-set wire helpers (RFC 5492 §3) ----

/// Opaque handle to a heap-allocated byte buffer returned by
/// `lr_bgp_cap_encode_set`. Owns a `Vec<u8>` so the C side can pass
/// the bytes back to the caller without copying. Free with
/// [`lr_bgp_cap_bytes_free`].
#[repr(C)]
pub struct OpaqueBgpCapBytes {
    _private: [u8; 0],
}
pub type lr_bytes_t_handle = *mut OpaqueBgpCapBytes;

/// Opaque handle to a heap-allocated array of `lr_bgp_capability_t`
/// entries returned by `lr_bgp_cap_decode_set`. Free with
/// [`lr_bgp_cap_array_free`].
#[repr(C)]
pub struct OpaqueBgpCapArray {
    _private: [u8; 0],
}
pub type lr_bgp_capability_array_t = *mut OpaqueBgpCapArray;

/// One AddPath family tuple (RFC 7911 §4.4): `(afi, safi, send, recv)`.
/// `send` and `recv` are `u8` (1/0) for ABI stability — the Rust
/// side maps them to bools.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct lr_bgp_cap_add_path_family_t {
    pub afi: u16,
    pub safi: u8,
    pub send: u8,
    pub recv: u8,
}

/// One Graceful-Restart family tuple (RFC 4724 §3):
/// `(afi, safi, forwarding)`. `forwarding` is `u8` (1/0).
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct lr_bgp_cap_gr_family_t {
    pub afi: u16,
    pub safi: u8,
    pub forwarding: u8,
}

/// One Long-Lived-GR family tuple (RFC 9494 §3.1):
/// `(afi, safi, forwarding, stale_time_secs)`.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct lr_bgp_cap_llgr_family_t {
    pub afi: u16,
    pub safi: u8,
    pub forwarding: u8,
    pub stale_time_secs: u32,
}

/// Box a `Vec<u8>` into the opaque bytes handle.
fn box_cap_bytes(v: Vec<u8>) -> lr_bytes_t_handle {
    Box::into_raw(Box::new(v)) as lr_bytes_t_handle
}

/// Box a `Vec<lr_bgp_capability_t>` into the opaque array handle.
fn box_cap_array(v: Vec<lr_bgp_capability_t>) -> lr_bgp_capability_array_t {
    Box::into_raw(Box::new(v)) as lr_bgp_capability_array_t
}

/// Reclaim a bytes handle back into its `Vec<u8>`.
///
/// # Safety
/// `b` must have been produced by [`box_cap_bytes`] and not freed.
unsafe fn unbox_cap_bytes(b: lr_bytes_t_handle) -> Option<Box<Vec<u8>>> {
    if b.is_null() {
        return None;
    }
    Some(unsafe { Box::from_raw(b as *mut Vec<u8>) })
}

/// Reclaim a capability-array handle back into its `Vec<lr_bgp_capability_t>`.
///
/// # Safety
/// `a` must have been produced by [`box_cap_array`] and not freed.
unsafe fn unbox_cap_array(a: lr_bgp_capability_array_t) -> Option<Box<Vec<lr_bgp_capability_t>>> {
    if a.is_null() {
        return None;
    }
    Some(unsafe { Box::from_raw(a as *mut Vec<lr_bgp_capability_t>) })
}

/// Construct a Route Refresh capability (RFC 2918 §3, code 2). The
/// capability carries no value.
#[no_mangle]
pub extern "C" fn lr_bgp_cap_route_refresh() -> lr_bgp_capability_t {
    guarded(
        || box_capability(Capability::route_refresh()),
        std::ptr::null_mut(),
    )
}

/// Construct an AddPath capability (RFC 7911 §4.4). Each family tuple
/// is one `lr_bgp_cap_add_path_family_t`. `send` / `recv` are 1/0
/// (the C-side caller does not need Rust's `bool`).
///
/// # Safety
/// `families` (when `count > 0`) must point to `count` readable
/// `lr_bgp_cap_add_path_family_t` entries.
#[no_mangle]
pub unsafe extern "C" fn lr_bgp_cap_add_path(
    families: *const lr_bgp_cap_add_path_family_t,
    count: usize,
) -> lr_bgp_capability_t {
    guarded(
        || unsafe {
            if count == 0 {
                return box_capability(Capability::add_path(&[]));
            }
            if families.is_null() {
                return std::ptr::null_mut();
            }
            let slice = unsafe { core::slice::from_raw_parts(families, count) };
            let mapped: Vec<(u16, u8, bool, bool)> = slice
                .iter()
                .map(|f| (f.afi, f.safi, f.send != 0, f.recv != 0))
                .collect();
            box_capability(Capability::add_path(&mapped))
        },
        std::ptr::null_mut(),
    )
}

/// For an AddPath capability, return the number of family tuples it
/// carries. Returns 0 on a NULL handle or a non-AddPath capability.
#[no_mangle]
pub unsafe extern "C" fn lr_bgp_cap_as_add_path_len(cap: lr_bgp_capability_t) -> usize {
    guarded(
        || unsafe {
            borrow_capability(cap)
                .and_then(|c| c.as_add_path())
                .map(|v| v.len())
                .unwrap_or(0)
        },
        0,
    )
}

/// For an AddPath capability, copy its family tuples into the caller-
/// supplied buffer. Each tuple occupies one `lr_bgp_cap_add_path_family_t`.
/// Returns the number of tuples copied (capped at `cap_size`).
///
/// # Safety
/// `cap` must be a valid handle. `out` must point to at least
/// `cap_size` writable `lr_bgp_cap_add_path_family_t` entries.
#[no_mangle]
pub unsafe extern "C" fn lr_bgp_cap_as_add_path(
    cap: lr_bgp_capability_t,
    out: *mut lr_bgp_cap_add_path_family_t,
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
            let Some(fams) = c.as_add_path() else {
                return 0;
            };
            let take = fams.len().min(cap_size);
            for (i, f) in fams.iter().take(take).enumerate() {
                unsafe {
                    *out.add(i) = lr_bgp_cap_add_path_family_t {
                        afi: f.0,
                        safi: f.1,
                        send: f.2 as u8,
                        recv: f.3 as u8,
                    };
                }
            }
            take
        },
        0,
    )
}

/// Construct an Enhanced Route Refresh capability (RFC 7313, code 70).
/// Carries no value.
#[no_mangle]
pub extern "C" fn lr_bgp_cap_enhanced_rr() -> lr_bgp_capability_t {
    guarded(
        || box_capability(Capability::enhanced_rr()),
        std::ptr::null_mut(),
    )
}

/// Construct a Graceful Restart capability (RFC 4724 §3).
/// `restart_flags` is a 4-bit field (bit 0x8 = Restart State, R);
/// `restart_time_secs` is a 12-bit field (clamped on encode).
/// `families` lists `(afi, safi, forwarding)` tuples — a family is
/// only listed when the speaker can preserve its state.
///
/// # Safety
/// `families` (when `count > 0`) must point to `count` readable
/// `lr_bgp_cap_gr_family_t` entries.
#[no_mangle]
pub unsafe extern "C" fn lr_bgp_cap_graceful_restart(
    restart_flags: u8,
    restart_time_secs: u16,
    families: *const lr_bgp_cap_gr_family_t,
    count: usize,
) -> lr_bgp_capability_t {
    guarded(
        || unsafe {
            let mapped: Vec<(u16, u8, bool)> = if count == 0 {
                Vec::new()
            } else {
                if families.is_null() {
                    return std::ptr::null_mut();
                }
                let slice = unsafe { core::slice::from_raw_parts(families, count) };
                slice
                    .iter()
                    .map(|f| (f.afi, f.safi, f.forwarding != 0))
                    .collect()
            };
            box_capability(Capability::graceful_restart(
                restart_flags,
                restart_time_secs,
                &mapped,
            ))
        },
        std::ptr::null_mut(),
    )
}

/// For a Graceful Restart capability, write the restart flags (4 bits,
/// bit 0x8 = R) to `*out_flags` and the restart time in seconds (12
/// bits) to `*out_time`. Returns 1 on success, 0 on a NULL handle, NULL
/// out-pointers, or a non-Graceful-Restart capability.
#[no_mangle]
pub unsafe extern "C" fn lr_bgp_cap_as_graceful_restart(
    cap: lr_bgp_capability_t,
    out_flags: *mut u8,
    out_time: *mut u16,
) -> u8 {
    guarded(
        || unsafe {
            let Some(c) = borrow_capability(cap) else {
                return 0;
            };
            if out_flags.is_null() || out_time.is_null() {
                return 0;
            }
            match c.as_graceful_restart() {
                Some((flags, time)) => {
                    unsafe {
                        *out_flags = flags;
                        *out_time = time;
                    }
                    1
                }
                None => 0,
            }
        },
        0,
    )
}

/// For a Graceful Restart capability, return the number of
/// `(afi, safi, forwarding)` family tuples.
#[no_mangle]
pub unsafe extern "C" fn lr_bgp_cap_as_graceful_restart_families_len(
    cap: lr_bgp_capability_t,
) -> usize {
    guarded(
        || unsafe {
            borrow_capability(cap)
                .and_then(|c| c.as_graceful_restart_families())
                .map(|v| v.len())
                .unwrap_or(0)
        },
        0,
    )
}

/// For a Graceful Restart capability, copy its family tuples into the
/// caller-supplied buffer. Each tuple occupies one
/// `lr_bgp_cap_gr_family_t`.
///
/// # Safety
/// `cap` must be a valid handle. `out` must point to at least
/// `cap_size` writable `lr_bgp_cap_gr_family_t` entries.
#[no_mangle]
pub unsafe extern "C" fn lr_bgp_cap_as_graceful_restart_families(
    cap: lr_bgp_capability_t,
    out: *mut lr_bgp_cap_gr_family_t,
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
            let Some(fams) = c.as_graceful_restart_families() else {
                return 0;
            };
            let take = fams.len().min(cap_size);
            for (i, f) in fams.iter().take(take).enumerate() {
                unsafe {
                    *out.add(i) = lr_bgp_cap_gr_family_t {
                        afi: f.0,
                        safi: f.1,
                        forwarding: f.2 as u8,
                    };
                }
            }
            take
        },
        0,
    )
}

/// Construct a Long-Lived Graceful Restart capability (RFC 9494 §3.1).
/// Each family tuple is one `lr_bgp_cap_llgr_family_t` with the
/// `(afi, safi, forwarding, stale_time_secs)` shape.
///
/// # Safety
/// `families` (when `count > 0`) must point to `count` readable
/// `lr_bgp_cap_llgr_family_t` entries.
#[no_mangle]
pub unsafe extern "C" fn lr_bgp_cap_long_lived_gr(
    families: *const lr_bgp_cap_llgr_family_t,
    count: usize,
) -> lr_bgp_capability_t {
    guarded(
        || unsafe {
            let mapped: Vec<(u16, u8, bool, u32)> = if count == 0 {
                Vec::new()
            } else {
                if families.is_null() {
                    return std::ptr::null_mut();
                }
                let slice = unsafe { core::slice::from_raw_parts(families, count) };
                slice
                    .iter()
                    .map(|f| (f.afi, f.safi, f.forwarding != 0, f.stale_time_secs))
                    .collect()
            };
            box_capability(Capability::long_lived_gr(&mapped))
        },
        std::ptr::null_mut(),
    )
}

/// For a Long-Lived-GR capability, return the number of family tuples.
#[no_mangle]
pub unsafe extern "C" fn lr_bgp_cap_as_long_lived_gr_len(cap: lr_bgp_capability_t) -> usize {
    guarded(
        || unsafe {
            borrow_capability(cap)
                .and_then(|c| c.as_long_lived_gr())
                .map(|v| v.len())
                .unwrap_or(0)
        },
        0,
    )
}

/// For a Long-Lived-GR capability, copy its family tuples into the
/// caller-supplied buffer. Each tuple occupies one
/// `lr_bgp_cap_llgr_family_t`.
///
/// # Safety
/// `cap` must be a valid handle. `out` must point to at least
/// `cap_size` writable `lr_bgp_cap_llgr_family_t` entries.
#[no_mangle]
pub unsafe extern "C" fn lr_bgp_cap_as_long_lived_gr(
    cap: lr_bgp_capability_t,
    out: *mut lr_bgp_cap_llgr_family_t,
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
            let Some(fams) = c.as_long_lived_gr() else {
                return 0;
            };
            let take = fams.len().min(cap_size);
            for (i, f) in fams.iter().take(take).enumerate() {
                unsafe {
                    *out.add(i) = lr_bgp_cap_llgr_family_t {
                        afi: f.0,
                        safi: f.1,
                        forwarding: f.2 as u8,
                        stale_time_secs: f.3,
                    };
                }
            }
            take
        },
        0,
    )
}

/// Encode a slice of capabilities as the OPEN optional-parameter
/// value (RFC 5492 §3). Each capability is encoded as
/// `(code:1, len:1, value:0..)`. The returned `lr_bytes_t_handle`
/// owns a `Vec<u8>`; free it with [`lr_bgp_cap_bytes_free`].
///
/// Returns 0 on success; `LR_ERR_NULL` (-1) on a null `out` or when
/// `caps` is NULL with a non-zero `count`.
///
/// # Safety
/// `caps` (when `count > 0`) must point to `count` readable
/// `lr_bgp_capability_t` entries. The handles are borrowed, not
/// consumed — the caller still owns them and must free each
/// individually with [`lr_bgp_cap_free`].
#[no_mangle]
pub unsafe extern "C" fn lr_bgp_cap_encode_set(
    caps: *const lr_bgp_capability_t,
    count: usize,
    out: *mut lr_bytes_t_handle,
) -> i32 {
    use crate::error::{set_last_error, LrError, LR_ERR_PANIC as PANIC};
    guarded(
        || unsafe {
            if out.is_null() {
                return LrError::Null as i32;
            }
            if count == 0 {
                unsafe { *out = box_cap_bytes(Vec::new()) }
                return 0;
            }
            if caps.is_null() {
                return LrError::Null as i32;
            }
            let slice = unsafe { core::slice::from_raw_parts(caps, count) };
            // Borrow each capability handle (do NOT consume) and clone
            // the underlying Rust Capability so encode_set can borrow
            // them immutably.
            let mut borrowed: Vec<Capability> = Vec::with_capacity(count);
            for (i, &h) in slice.iter().enumerate() {
                match borrow_capability(h) {
                    Some(c) => borrowed.push(c.clone()),
                    None => {
                        set_last_error(format!(
                            "lr_bgp_cap_encode_set: capability at index {i} is null"
                        ));
                        return LrError::Null as i32;
                    }
                }
            }
            let bytes = Capability::encode_set(&borrowed);
            unsafe { *out = box_cap_bytes(bytes) }
            0
        },
        PANIC,
    )
}

/// Decode an OPEN optional-parameter value (RFC 5492 §3) into a
/// freshly-allocated array of `lr_bgp_capability_t` handles. Writes
/// the array handle to `*out_caps` and the count to `*out_count`.
/// Free the array with [`lr_bgp_cap_array_free`] (which frees each
/// capability handle inside, then the array itself).
///
/// Returns 0 on success, `LR_ERR_NULL` (-1) on null pointers, or
/// `LR_ERR_PANIC` (-4) on a panic. A truncated trailing capability is
/// silently dropped (matching the Rust `decode_set` behavior).
///
/// # Safety
/// `data` must point to `len` readable bytes. `out_caps` and
/// `out_count` must point to writable `lr_bgp_capability_array_t` /
/// `uintptr_t`.
#[no_mangle]
pub unsafe extern "C" fn lr_bgp_cap_decode_set(
    data: *const u8,
    len: usize,
    out_caps: *mut lr_bgp_capability_array_t,
    out_count: *mut usize,
) -> i32 {
    use crate::error::{set_last_error, LrError, LR_ERR_PANIC as PANIC};
    guarded(
        || unsafe {
            if data.is_null() || out_caps.is_null() || out_count.is_null() {
                return LrError::Null as i32;
            }
            let slice = unsafe { core::slice::from_raw_parts(data, len) };
            let decoded = Capability::decode_set(slice);
            let count = decoded.len();
            let handles: Vec<lr_bgp_capability_t> =
                decoded.into_iter().map(box_capability).collect();
            unsafe {
                *out_caps = box_cap_array(handles);
                *out_count = count;
            }
            // Silence unused-set_last_error import warning if the path
            // above never errored.
            let _ = set_last_error;
            0
        },
        PANIC,
    )
}

/// Free a `lr_bytes_t_handle` returned by [`lr_bgp_cap_encode_set`].
/// Safe to call with NULL.
#[no_mangle]
pub unsafe extern "C" fn lr_bgp_cap_bytes_free(b: lr_bytes_t_handle) {
    guarded(
        || unsafe {
            drop(unbox_cap_bytes(b));
        },
        (),
    )
}

/// Read the length of a `lr_bytes_t_handle` buffer. Returns 0 on NULL.
#[no_mangle]
pub unsafe extern "C" fn lr_bgp_cap_bytes_len(b: lr_bytes_t_handle) -> usize {
    guarded(
        || unsafe {
            if b.is_null() {
                return 0;
            }
            let v: &Vec<u8> = &*(b as *const Vec<u8>);
            v.len()
        },
        0,
    )
}

/// Read a pointer to the underlying bytes of a `lr_bytes_t_handle`.
/// Returns NULL on a NULL handle. The pointer is valid until the
/// handle is freed.
#[no_mangle]
pub unsafe extern "C" fn lr_bgp_cap_bytes_ptr(b: lr_bytes_t_handle) -> *const u8 {
    guarded(
        || unsafe {
            if b.is_null() {
                return std::ptr::null();
            }
            let v: &Vec<u8> = &*(b as *const Vec<u8>);
            v.as_ptr()
        },
        std::ptr::null(),
    )
}

/// Free a `lr_bgp_capability_array_t` returned by
/// [`lr_bgp_cap_decode_set`]. Frees each capability handle inside
/// first, then the array itself. Safe to call with NULL.
///
/// # Safety
/// `arr` must have been produced by [`box_cap_array`] and not freed.
/// `count` must be the count returned alongside the array; passing a
/// smaller count leaks the trailing capabilities.
#[no_mangle]
pub unsafe extern "C" fn lr_bgp_cap_array_free(arr: lr_bgp_capability_array_t, count: usize) {
    guarded(
        || unsafe {
            let Some(boxed) = unbox_cap_array(arr) else {
                return;
            };
            // Free each capability handle individually before dropping
            // the vector.
            for h in boxed.iter().take(count) {
                if !h.is_null() {
                    let inner: Box<Capability> = Box::from_raw(*h as *mut Capability);
                    drop(inner);
                }
            }
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

    // ---- Route Refresh capability (RFC 2918 §3) ----

    #[test]
    fn ffi_cap_route_refresh() {
        let cap = lr_bgp_cap_route_refresh();
        assert!(!cap.is_null());
        unsafe {
            assert_eq!(lr_bgp_cap_code(cap), LR_BGP_CAP_ROUTE_REFRESH);
            assert_eq!(lr_bgp_cap_value_len(cap), 0);
            lr_bgp_cap_free(cap);
        }
    }

    // ---- AddPath capability (RFC 7911 §4.4) ----

    #[test]
    fn ffi_cap_add_path_roundtrip() {
        let families = [
            lr_bgp_cap_add_path_family_t {
                afi: 1,
                safi: 1,
                send: 1,
                recv: 1,
            },
            lr_bgp_cap_add_path_family_t {
                afi: 2,
                safi: 1,
                send: 0,
                recv: 1,
            },
        ];
        let cap = unsafe { lr_bgp_cap_add_path(families.as_ptr(), families.len()) };
        assert!(!cap.is_null());
        unsafe {
            assert_eq!(lr_bgp_cap_code(cap), LR_BGP_CAP_ADD_PATH);
            assert_eq!(lr_bgp_cap_value_len(cap), 8); // 2 × 4 bytes
            assert_eq!(lr_bgp_cap_as_add_path_len(cap), 2);
            let mut out = [
                lr_bgp_cap_add_path_family_t::default(),
                lr_bgp_cap_add_path_family_t::default(),
            ];
            let n = lr_bgp_cap_as_add_path(cap, out.as_mut_ptr(), 2);
            assert_eq!(n, 2);
            assert_eq!(out[0].afi, 1);
            assert_eq!(out[0].recv, 1);
            assert_eq!(out[1].afi, 2);
            assert_eq!(out[1].send, 0);
            lr_bgp_cap_free(cap);
        }
    }

    #[test]
    fn ffi_cap_add_path_handles_null_safely() {
        // Non-zero count + NULL → NULL.
        let cap = unsafe { lr_bgp_cap_add_path(std::ptr::null(), 1) };
        assert!(cap.is_null());
        // Zero count is legal (empty capability).
        let cap = unsafe { lr_bgp_cap_add_path(std::ptr::null(), 0) };
        assert!(!cap.is_null());
        unsafe {
            assert_eq!(lr_bgp_cap_as_add_path_len(cap), 0);
            lr_bgp_cap_free(cap);
        }
    }

    #[test]
    fn ffi_cap_as_add_path_len_returns_zero_on_null_or_non_addpath() {
        assert_eq!(
            unsafe { lr_bgp_cap_as_add_path_len(std::ptr::null_mut()) },
            0
        );
        let cap = lr_bgp_cap_four_octet_as(64512);
        unsafe {
            assert_eq!(lr_bgp_cap_as_add_path_len(cap), 0);
            lr_bgp_cap_free(cap);
        }
    }

    // ---- Enhanced Route Refresh capability (RFC 7313) ----

    #[test]
    fn ffi_cap_enhanced_rr() {
        let cap = lr_bgp_cap_enhanced_rr();
        assert!(!cap.is_null());
        unsafe {
            assert_eq!(lr_bgp_cap_code(cap), LR_BGP_CAP_ENHANCED_ROUTE_REFRESH);
            assert_eq!(lr_bgp_cap_value_len(cap), 0);
            lr_bgp_cap_free(cap);
        }
    }

    // ---- Graceful Restart capability (RFC 4724 §3) ----

    #[test]
    fn ffi_cap_graceful_restart_roundtrip() {
        let families = [
            lr_bgp_cap_gr_family_t {
                afi: 1,
                safi: 1,
                forwarding: 1,
            },
            lr_bgp_cap_gr_family_t {
                afi: 2,
                safi: 1,
                forwarding: 0,
            },
        ];
        let cap = unsafe {
            lr_bgp_cap_graceful_restart(
                0x08, // Restart State (R) bit set
                120,  // 120 s restart time
                families.as_ptr(),
                families.len(),
            )
        };
        assert!(!cap.is_null());
        unsafe {
            assert_eq!(lr_bgp_cap_code(cap), LR_BGP_CAP_GRACEFUL_RESTART);
            assert_eq!(lr_bgp_cap_value_len(cap), 2 + 8); // 2-byte hdr + 2 × 4-byte family
            let mut flags = 0u8;
            let mut time = 0u16;
            assert_eq!(
                lr_bgp_cap_as_graceful_restart(cap, &raw mut flags, &raw mut time),
                1
            );
            assert_eq!(flags, 0x08);
            assert_eq!(time, 120);
            assert_eq!(lr_bgp_cap_as_graceful_restart_families_len(cap), 2);
            let mut out = [
                lr_bgp_cap_gr_family_t::default(),
                lr_bgp_cap_gr_family_t::default(),
            ];
            let n = lr_bgp_cap_as_graceful_restart_families(cap, out.as_mut_ptr(), 2);
            assert_eq!(n, 2);
            assert_eq!(out[0].afi, 1);
            assert_eq!(out[0].forwarding, 1);
            assert_eq!(out[1].afi, 2);
            assert_eq!(out[1].forwarding, 0);
            lr_bgp_cap_free(cap);
        }
    }

    #[test]
    fn ffi_cap_graceful_restart_handles_null_safely() {
        let cap = unsafe { lr_bgp_cap_graceful_restart(0, 120, std::ptr::null(), 1) };
        assert!(cap.is_null());
        // Zero families is legal (no AF retained).
        let cap = unsafe { lr_bgp_cap_graceful_restart(0, 120, std::ptr::null(), 0) };
        assert!(!cap.is_null());
        unsafe {
            let mut flags = 0u8;
            let mut time = 0u16;
            assert_eq!(
                lr_bgp_cap_as_graceful_restart(cap, &raw mut flags, &raw mut time),
                1
            );
            assert_eq!(lr_bgp_cap_as_graceful_restart_families_len(cap), 0);
            lr_bgp_cap_free(cap);
        }
    }

    #[test]
    fn ffi_cap_as_graceful_restart_returns_zero_on_non_gr() {
        let cap = lr_bgp_cap_four_octet_as(64512);
        unsafe {
            let mut flags = 0u8;
            let mut time = 0u16;
            assert_eq!(
                lr_bgp_cap_as_graceful_restart(cap, &raw mut flags, &raw mut time),
                0
            );
            assert_eq!(lr_bgp_cap_as_graceful_restart_families_len(cap), 0);
            lr_bgp_cap_free(cap);
        }
    }

    // ---- Long-Lived Graceful Restart capability (RFC 9494 §3.1) ----

    #[test]
    fn ffi_cap_long_lived_gr_roundtrip() {
        let families = [lr_bgp_cap_llgr_family_t {
            afi: 1,
            safi: 1,
            forwarding: 1,
            stale_time_secs: 65535,
        }];
        let cap = unsafe { lr_bgp_cap_long_lived_gr(families.as_ptr(), families.len()) };
        assert!(!cap.is_null());
        unsafe {
            assert_eq!(lr_bgp_cap_code(cap), LR_BGP_CAP_LONG_LIVED_GRACEFUL_RESTART);
            assert_eq!(lr_bgp_cap_value_len(cap), 7); // 1 × 7-byte tuple
            assert_eq!(lr_bgp_cap_as_long_lived_gr_len(cap), 1);
            let mut out = [lr_bgp_cap_llgr_family_t::default()];
            let n = lr_bgp_cap_as_long_lived_gr(cap, out.as_mut_ptr(), 1);
            assert_eq!(n, 1);
            assert_eq!(out[0].afi, 1);
            assert_eq!(out[0].stale_time_secs, 65535);
            lr_bgp_cap_free(cap);
        }
    }

    #[test]
    fn ffi_cap_long_lived_gr_handles_null_safely() {
        let cap = unsafe { lr_bgp_cap_long_lived_gr(std::ptr::null(), 1) };
        assert!(cap.is_null());
        // Zero families is legal.
        let cap = unsafe { lr_bgp_cap_long_lived_gr(std::ptr::null(), 0) };
        assert!(!cap.is_null());
        unsafe {
            assert_eq!(lr_bgp_cap_as_long_lived_gr_len(cap), 0);
            lr_bgp_cap_free(cap);
        }
    }

    // ---- encode_set / decode_set round-trip ----

    #[test]
    fn ffi_cap_encode_decode_set_roundtrip() {
        let caps = [
            lr_bgp_cap_four_octet_as(64512),
            lr_bgp_cap_multiprotocol(1, 1),
            lr_bgp_cap_route_refresh(),
        ];
        let mut out: lr_bytes_t_handle = std::ptr::null_mut();
        let rc = unsafe { lr_bgp_cap_encode_set(caps.as_ptr(), caps.len(), &raw mut out) };
        assert_eq!(rc, 0);
        assert!(!out.is_null());
        // Read the bytes back.
        let len = unsafe { lr_bgp_cap_bytes_len(out) };
        // four_octet_as: code(1)+len(1)+value(4) = 6
        // multiprotocol: code(1)+len(1)+value(4) = 6
        // route_refresh: code(1)+len(1) = 2
        assert_eq!(len, 6 + 6 + 2);

        // Decode.
        let mut out_caps: lr_bgp_capability_array_t = std::ptr::null_mut();
        let mut out_count: usize = 0;
        let rc = unsafe {
            lr_bgp_cap_decode_set(
                unsafe { lr_bgp_cap_bytes_ptr(out) },
                len,
                &raw mut out_caps,
                &raw mut out_count,
            )
        };
        assert_eq!(rc, 0);
        assert_eq!(out_count, 3);
        assert!(!out_caps.is_null());
        // Free the array (frees each capability + the array itself).
        unsafe { lr_bgp_cap_array_free(out_caps, out_count) };
        unsafe { lr_bgp_cap_bytes_free(out) };
        // Free the input capabilities.
        for c in caps {
            unsafe { lr_bgp_cap_free(c) };
        }
    }

    #[test]
    fn ffi_cap_encode_set_handles_null_safely() {
        // NULL caps + non-zero count → NULL out.
        let mut out: lr_bytes_t_handle = std::ptr::null_mut();
        let rc = unsafe { lr_bgp_cap_encode_set(std::ptr::null(), 1, &raw mut out) };
        assert_eq!(rc, crate::error::LrError::Null as i32);
        // Zero count is legal but produces empty output.
        let rc = unsafe { lr_bgp_cap_encode_set(std::ptr::null(), 0, &raw mut out) };
        assert_eq!(rc, 0);
        unsafe {
            assert_eq!(lr_bgp_cap_bytes_len(out), 0);
            lr_bgp_cap_bytes_free(out);
        }
    }
}
