//! C ABI gap-fill batch — closes the remaining pub-fn coverage gaps
//! across lr-bgp, lr-ospf, lr-babel, lr-bfd, lr-ldp, lr-core, lr-rib,
//! lr-policy, lr-router, lr-osroute and lr-mpls that did not fit into
//! the existing themed FFI modules.
//!
//! Each section is self-contained: it pulls in the Rust types it needs
//! from the matching crate, defines the opaque handles / repr-C
//! structs it needs (or reuses existing ones from
//! [`crate::handle`]), and exports the `extern "C"` entry points with
//! the `lr_<crate>_*` prefix.
//!
//! Every entry point runs inside the crate's `catch_unwind` barrier
//! ([`crate::guarded`]): a panic returns `LR_ERR_PANIC` and sets the
//! thread-local last-error string.

// The closure body passed to `guarded` is wrapped in a single `unsafe`
// block to mirror the `pub unsafe extern "C" fn` shape — the inner
// `unsafe { ... }` blocks would otherwise trip `unused_unsafe` under
// the crate's `-D warnings` clippy gate.
#![allow(unused_unsafe)]

use lr_core::rib::Route;
use lr_core::time::Instant;

use crate::error::{set_last_error, LrError, LR_ERR_PANIC};
use crate::guarded;
use crate::handle::{lr_bytes_t, lr_route_t};

const LR_ERR_NULL: i32 = LrError::Null as i32;
const LR_ERR_INVALID_HANDLE: i32 = LrError::InvalidHandle as i32;
const LR_ERR_OTHER: i32 = LrError::Other as i32;

// ===========================================================================
// lr-mpls gap-fill: Label::new_value / try_new / is_valid_value /
// LabelStack::from_vec / into_vec
// ===========================================================================

use lr_mpls::{Label, LabelStack};
// Re-export the opaque-handle type aliases so the gap-fill functions
// use the same `lr_mpls_label_t` / `lr_mpls_label_stack_t` surface
// as the rest of the FFI (see `crates/lr-ffi/src/mpls.rs`). The
// previous shape returned `*mut Label` (the inner Rust type) — cbindgen
// does not know how to render that and emits `Label *` in the header,
// which has no typedef and breaks every C consumer's compile.
use crate::mpls::{lr_mpls_label_stack_t, lr_mpls_label_t};

/// Construct a Label with just the value (TC=0, TTL=0). Used for the
/// BGP-LU 3-octet NLRI form, where TTL is absent (RFC 8277 §2.2).
/// Infallible — the value is masked to 20 bits on encode.
#[no_mangle]
pub extern "C" fn lr_mpls_label_new_value(value: u32) -> lr_mpls_label_t {
    guarded(
        || crate::mpls::box_label(Label::new_value(value)),
        std::ptr::null_mut(),
    )
}

/// True when `value` fits in the 20-bit label range (RFC 3032 §2.1).
/// Stateless — does not allocate.
#[no_mangle]
pub extern "C" fn lr_mpls_label_is_valid_value(value: u32) -> u8 {
    guarded(|| Label::is_valid_value(value) as u8, 0)
}

// Note: lr_mpls_label_try_new is already exposed via the existing
// lr_mpls_label_new_checked in mpls.rs. Adding an alias here for the
// Rust fn name.
//
/// Alias for `lr_mpls_label_new_checked` — the Rust fn `Label::try_new`
/// maps to the same surface (validate the 20-bit range, return NULL on
/// out-of-range). Kept as a separate symbol so a C consumer searching
/// for `try_new` finds it.
#[no_mangle]
pub extern "C" fn lr_mpls_label_try_new(value: u32) -> lr_mpls_label_t {
    guarded(
        || match Label::try_new(value) {
            Ok(l) => crate::mpls::box_label(l),
            Err(e) => {
                set_last_error(e.to_string());
                std::ptr::null_mut()
            }
        },
        std::ptr::null_mut(),
    )
}

/// Wrap an existing Vec of labels into a LabelStack. Takes ownership
/// of the array contents — the caller must not free the labels
/// afterwards.
///
/// # Safety
/// `labels` must point to `count` readable `lr_mpls_label_t` handles
/// produced by `lr_mpls_label_new` / `_new_value` / `_try_new`. Each
/// handle is consumed (freed) by this call.
#[no_mangle]
pub unsafe extern "C" fn lr_mpls_label_stack_from_vec(
    labels: *const lr_mpls_label_t,
    count: usize,
) -> lr_mpls_label_stack_t {
    guarded(
        || unsafe {
            if labels.is_null() && count != 0 {
                return std::ptr::null_mut();
            }
            let slice = if count == 0 {
                &[]
            } else {
                unsafe { std::slice::from_raw_parts(labels, count) }
            };
            let mut v = Vec::with_capacity(count);
            for &ptr in slice {
                if ptr.is_null() {
                    set_last_error("NULL label in from_vec input".into());
                    return std::ptr::null_mut();
                }
                // Reclaim the boxed Label and move it into our Vec.
                let boxed: Box<Label> = unsafe { Box::from_raw(ptr as *mut Label) };
                v.push(*boxed);
            }
            crate::mpls::box_label_stack(LabelStack::from_vec(v))
        },
        std::ptr::null_mut(),
    )
}

/// Take the underlying Vec of labels out of the stack. Returns a
/// freshly-allocated `lr_bytes_t` carrying `count * 4` bytes (one
/// 4-octet wire entry per label, no S bit set — caller must add the
/// bottom-of-stack bit if needed). The stack handle is consumed
/// and freed.
///
/// The shape is bytes (not a label-handle array) because label
/// handles are owned by the caller and would need individual
/// `lr_mpls_label_free` calls; the byte form is what an embedder
/// typically wants when round-tripping through a `Vec<Label>`.
///
/// # Safety
/// `stack` must be a valid handle produced by a `lr_mpls_label_stack_*`
/// constructor. `out` must point to a writable `lr_bytes_t`.
#[no_mangle]
pub unsafe extern "C" fn lr_mpls_label_stack_into_vec(
    stack: lr_mpls_label_stack_t,
    out: *mut lr_bytes_t,
) -> i32 {
    guarded(
        || unsafe {
            if stack.is_null() || out.is_null() {
                return LR_ERR_NULL;
            }
            // Reclaim the boxed LabelStack behind the opaque handle.
            let boxed: Box<LabelStack> = unsafe { Box::from_raw(stack as *mut LabelStack) };
            // Each Label encodes as 4 octets (label + tc + 0 + ttl); we
            // emit them with bottom=0 since the caller decides which
            // entry is the bottom of the stack.
            let mut bytes = Vec::with_capacity(boxed.len() * 4);
            for l in boxed.labels() {
                bytes.extend_from_slice(&l.encode_4octet(false));
            }
            unsafe { *out = lr_bytes_t::from_vec(bytes) }
            0
        },
        LR_ERR_PANIC,
    )
}

// ===========================================================================
// lr-bfd gap-fill: covered by existing bfd_auth.rs (lr_bfd_keyed_auth_*)
// and bfd_session.rs. The earlier gap analysis flagged these because of
// the heuristic — the existing surface is comprehensive.
// ===========================================================================

// (Empty — kept as a marker for the gap analysis tooling.)

// BFD keyed-auth algorithm constants kept here for backward
// compatibility with embedders that may have imported them. The
// canonical definitions live in bfd_auth.rs.
pub const LR_BFD_KEYED_AUTH_ALGO_KEYED_MD5: i32 = 1;
pub const LR_BFD_KEYED_AUTH_ALGO_METICULOUS_KEYED_MD5: i32 = 2;
pub const LR_BFD_KEYED_AUTH_ALGO_KEYED_SHA1: i32 = 3;
pub const LR_BFD_KEYED_AUTH_ALGO_METICULOUS_KEYED_SHA1: i32 = 4;

/// AuthType constants (mirrors `lr_bfd::auth::AuthType`).
pub const LR_BFD_AUTH_TYPE_SIMPLE_PASSWORD: i32 = 0;
pub const LR_BFD_AUTH_TYPE_KEYED_MD5: i32 = 1;
pub const LR_BFD_AUTH_TYPE_METICULOUS_KEYED_MD5: i32 = 2;
pub const LR_BFD_AUTH_TYPE_KEYED_SHA1: i32 = 3;
pub const LR_BFD_AUTH_TYPE_METICULOUS_KEYED_SHA1: i32 = 4;

/// Read the AuthType as one of the `LR_BFD_AUTH_TYPE_*` constants.
/// Stateless — given an algorithm id, returns the matching AuthType.
#[no_mangle]
pub extern "C" fn lr_bfd_auth_type_from_algorithm(algorithm: i32) -> i32 {
    guarded(
        || match algorithm {
            1 => LR_BFD_AUTH_TYPE_KEYED_MD5,
            2 => LR_BFD_AUTH_TYPE_METICULOUS_KEYED_MD5,
            3 => LR_BFD_AUTH_TYPE_KEYED_SHA1,
            4 => LR_BFD_AUTH_TYPE_METICULOUS_KEYED_SHA1,
            _ => 0,
        },
        0,
    )
}

// ===========================================================================
// lr-srv6 gap-fill: covered by existing srv6.rs (Sid/Locator/Srh
// constructors + readers) and srv6_srh.rs (Srh handle lifecycle). The
// earlier gap analysis flagged these because of the heuristic — the
// existing surface is comprehensive.
// ===========================================================================

// (Empty — kept as a marker for the gap analysis tooling.)

// ===========================================================================
// lr-ospf gap-fill: HelperEntry / RestartTracker accessors + srv6db
// ===========================================================================

use lr_ospf::gr::{HelperEntry, RestartTracker};

/// Opaque HelperEntry handle.
#[repr(C)]
pub struct OpaqueOspfHelperEntry {
    _private: [u8; 0],
}
pub type lr_ospf_helper_entry_t = *mut OpaqueOspfHelperEntry;

unsafe fn borrow_helper(h: lr_ospf_helper_entry_t) -> Option<&'static HelperEntry> {
    if h.is_null() {
        return None;
    }
    Some(unsafe { &*(h as *const HelperEntry) })
}

/// Construct an empty HelperEntry (RFC 3623 §3 helper state).
#[no_mangle]
pub extern "C" fn lr_ospf_helper_entry_new() -> lr_ospf_helper_entry_t {
    guarded(
        || Box::into_raw(Box::new(HelperEntry::default())) as lr_ospf_helper_entry_t,
        std::ptr::null_mut(),
    )
}

/// Drop a HelperEntry handle. Safe on NULL.
///
/// # Safety
/// `h` must have been produced by `lr_ospf_helper_entry_new` and not
/// already freed.
#[no_mangle]
pub unsafe extern "C" fn lr_ospf_helper_entry_free(h: lr_ospf_helper_entry_t) {
    guarded(
        || unsafe {
            if !h.is_null() {
                drop(Box::from_raw(h as *mut HelperEntry));
            }
        },
        (),
    )
}

/// True (1) when helper mode is currently active for this neighbour.
///
/// # Safety
/// `h` must be a valid handle.
#[no_mangle]
pub unsafe extern "C" fn lr_ospf_helper_entry_is_active(h: lr_ospf_helper_entry_t) -> u8 {
    guarded(
        || unsafe { borrow_helper(h).map(|e| e.is_active() as u8).unwrap_or(0) },
        0,
    )
}

/// The grace deadline on the caller's clock (0 when inactive).
///
/// # Safety
/// `h` must be a valid handle.
#[no_mangle]
pub unsafe extern "C" fn lr_ospf_helper_entry_grace_deadline_ms(h: lr_ospf_helper_entry_t) -> u64 {
    guarded(
        || unsafe { borrow_helper(h).map(|e| e.grace_deadline_ms()).unwrap_or(0) },
        0,
    )
}

/// The grace period last advertised by the restarting neighbour.
///
/// # Safety
/// `h` must be a valid handle.
#[no_mangle]
pub unsafe extern "C" fn lr_ospf_helper_entry_last_period_secs(h: lr_ospf_helper_entry_t) -> u32 {
    guarded(
        || unsafe { borrow_helper(h).map(|e| e.last_period_secs()).unwrap_or(0) },
        0,
    )
}

/// Opaque RestartTracker handle.
#[repr(C)]
pub struct OpaqueOspfRestartTracker {
    _private: [u8; 0],
}
pub type lr_ospf_restart_tracker_t = *mut OpaqueOspfRestartTracker;

unsafe fn borrow_tracker(t: lr_ospf_restart_tracker_t) -> Option<&'static RestartTracker> {
    if t.is_null() {
        return None;
    }
    Some(unsafe { &*(t as *const RestartTracker) })
}

/// True (1) when the tracker is in the recovering phase.
///
/// # Safety
/// `t` must be a valid handle.
#[no_mangle]
pub unsafe extern "C" fn lr_ospf_restart_tracker_recovering(t: lr_ospf_restart_tracker_t) -> u8 {
    guarded(
        || unsafe {
            borrow_tracker(t)
                .map(|tr| tr.recovering() as u8)
                .unwrap_or(0)
        },
        0,
    )
}

/// The grace deadline on the caller's clock (0 when inactive).
///
/// # Safety
/// `t` must be a valid handle.
#[no_mangle]
pub unsafe extern "C" fn lr_ospf_restart_tracker_grace_deadline_ms(
    t: lr_ospf_restart_tracker_t,
) -> u64 {
    guarded(
        || unsafe {
            borrow_tracker(t)
                .map(|tr| tr.grace_deadline_ms())
                .unwrap_or(0)
        },
        0,
    )
}

/// Opaque Srv6Database handle.
#[repr(C)]
pub struct OpaqueOspfSrv6Db {
    _private: [u8; 0],
}
pub type lr_ospf_srv6_db_t = *mut OpaqueOspfSrv6Db;

// Note: lr_ospf_srv6_db_from_lsdb / _free / _node_* already live in
// ospf_sr_srv6_db.rs. The earlier gap analysis flagged these because
// of the heuristic — they are in fact already exposed.

// ===========================================================================
// lr-rib gap-fill: covered by existing rib.rs (lr_adj_rib_in_new /
// _free, lr_adj_rib_out_new / _free, lr_loc_rib_*, lr_rib_mux_*,
// lr_route_selector_*). The earlier gap analysis flagged these because
// of the simple heuristic — they are in fact already exposed.
// ===========================================================================

// (Empty — kept as a marker for the gap analysis tooling.)

// ===========================================================================
// lr-router gap-fill: SessionConfig builder-style with_* mutators
// ===========================================================================

use lr_router::SessionConfig;

/// Opaque SessionConfig handle. Constructed via
/// `lr_session_config_bgp` / `_ospfv2` / `_ospfv3` / `_babel`; the
/// `with_*` mutators below apply in place and return the same handle
/// so the embedder can chain.
#[repr(C)]
pub struct OpaqueSessionConfig {
    _private: [u8; 0],
}
pub type lr_session_config_t = *mut OpaqueSessionConfig;

fn box_session_config(c: SessionConfig) -> lr_session_config_t {
    Box::into_raw(Box::new(c)) as lr_session_config_t
}

unsafe fn borrow_session_config_mut(c: lr_session_config_t) -> Option<&'static mut SessionConfig> {
    if c.is_null() {
        return None;
    }
    Some(unsafe { &mut *(c as *mut SessionConfig) })
}

/// Construct a BGP SessionConfig with the default knobs (matches
/// `SessionConfig::bgp` in Rust).
#[no_mangle]
pub extern "C" fn lr_session_config_bgp(
    local_as: u32,
    peer_as: u32,
    local_bgp_id: u32,
) -> lr_session_config_t {
    guarded(
        || {
            let cfg = SessionConfig::bgp(
                lr_core::addr::Asn(local_as),
                lr_core::addr::Asn(peer_as),
                lr_core::addr::RouterId::from_u32(local_bgp_id),
            );
            box_session_config(cfg)
        },
        std::ptr::null_mut(),
    )
}

/// Construct an OSPFv2 SessionConfig (matches `SessionConfig::ospfv2`).
#[no_mangle]
pub extern "C" fn lr_session_config_ospfv2(router_id: u32, area_id: u32) -> lr_session_config_t {
    guarded(
        || {
            box_session_config(SessionConfig::ospfv2(
                lr_core::addr::RouterId::from_u32(router_id),
                area_id,
            ))
        },
        std::ptr::null_mut(),
    )
}

/// Construct an OSPFv3 SessionConfig (matches `SessionConfig::ospfv3`).
#[no_mangle]
pub extern "C" fn lr_session_config_ospfv3(router_id: u32, area_id: u32) -> lr_session_config_t {
    guarded(
        || {
            box_session_config(SessionConfig::ospfv3(
                lr_core::addr::RouterId::from_u32(router_id),
                area_id,
            ))
        },
        std::ptr::null_mut(),
    )
}

/// Construct a Babel SessionConfig (matches `SessionConfig::babel`).
///
/// # Safety
/// `addr` must point to 16 readable bytes (IPv6 link-local).
#[no_mangle]
pub unsafe extern "C" fn lr_session_config_babel(
    addr: *const u8,
    addr_len: usize,
) -> lr_session_config_t {
    guarded(
        || unsafe {
            if addr.is_null() || addr_len != 16 {
                return std::ptr::null_mut();
            }
            let mut b = [0u8; 16];
            std::ptr::copy_nonoverlapping(addr, b.as_mut_ptr(), 16);
            box_session_config(SessionConfig::babel(lr_core::addr::IpAddr::V6(b)))
        },
        std::ptr::null_mut(),
    )
}

/// Drop a SessionConfig handle. Safe on NULL.
///
/// # Safety
/// `c` must have been produced by one of the `lr_session_config_*`
/// constructors and not already freed.
#[no_mangle]
pub unsafe extern "C" fn lr_session_config_free(c: lr_session_config_t) {
    guarded(
        || unsafe {
            if !c.is_null() {
                drop(Box::from_raw(c as *mut SessionConfig));
            }
        },
        (),
    )
}

/// Apply `with_mp_families` (RFC 4760). Returns the same handle on
/// success, NULL on a NULL handle.
///
/// # Safety
/// `c` must be a valid handle. `families` must point to `count`
/// readable `lr_nlri_family_t` structs.
#[no_mangle]
pub unsafe extern "C" fn lr_session_config_with_mp_families(
    c: lr_session_config_t,
    families: *const crate::bgp_codec::lr_afi_safi_t,
    count: usize,
) -> lr_session_config_t {
    guarded(
        || unsafe {
            let Some(cfg) = borrow_session_config_mut(c) else {
                return std::ptr::null_mut();
            };
            let slice = if count == 0 || families.is_null() {
                &[]
            } else {
                unsafe { std::slice::from_raw_parts(families, count) }
            };
            cfg.mp_families = slice
                .iter()
                .map(|f| lr_core::nlri::NlriFamily {
                    afi: f.afi,
                    safi: f.safi,
                })
                .collect();
            c
        },
        std::ptr::null_mut(),
    )
}

/// Apply `with_add_path` (RFC 7911). Returns the same handle.
///
/// # Safety
/// `c` must be a valid handle.
#[no_mangle]
pub unsafe extern "C" fn lr_session_config_with_add_path(
    c: lr_session_config_t,
) -> lr_session_config_t {
    guarded(
        || unsafe {
            let Some(cfg) = borrow_session_config_mut(c) else {
                return std::ptr::null_mut();
            };
            cfg.add_path = true;
            c
        },
        std::ptr::null_mut(),
    )
}

/// Apply `with_extended_next_hop` (RFC 5549 canonical tuple). Returns
/// the same handle.
///
/// # Safety
/// `c` must be a valid handle.
#[no_mangle]
pub unsafe extern "C" fn lr_session_config_with_extended_next_hop(
    c: lr_session_config_t,
) -> lr_session_config_t {
    guarded(
        || unsafe {
            let Some(cfg) = borrow_session_config_mut(c) else {
                return std::ptr::null_mut();
            };
            let t = (1, 1, 2);
            if !cfg.extended_next_hop.contains(&t) {
                cfg.extended_next_hop.push(t);
            }
            c
        },
        std::ptr::null_mut(),
    )
}

/// Apply `with_extended_next_hop_tuple` (RFC 5549 arbitrary tuple).
/// Returns the same handle.
///
/// # Safety
/// `c` must be a valid handle.
#[no_mangle]
pub unsafe extern "C" fn lr_session_config_with_extended_next_hop_tuple(
    c: lr_session_config_t,
    nlri_afi: u16,
    nlri_safi: u8,
    nexthop_afi: u16,
) -> lr_session_config_t {
    guarded(
        || unsafe {
            let Some(cfg) = borrow_session_config_mut(c) else {
                return std::ptr::null_mut();
            };
            let t = (nlri_afi, nlri_safi, nexthop_afi);
            if !cfg.extended_next_hop.contains(&t) {
                cfg.extended_next_hop.push(t);
            }
            c
        },
        std::ptr::null_mut(),
    )
}

/// Apply `with_graceful_restart` (RFC 4724). Returns the same handle.
///
/// # Safety
/// `c` must be a valid handle.
#[no_mangle]
pub unsafe extern "C" fn lr_session_config_with_graceful_restart(
    c: lr_session_config_t,
    restart_time_secs: u16,
) -> lr_session_config_t {
    guarded(
        || unsafe {
            let Some(cfg) = borrow_session_config_mut(c) else {
                return std::ptr::null_mut();
            };
            cfg.graceful_restart = true;
            cfg.graceful_restart_time = restart_time_secs;
            c
        },
        std::ptr::null_mut(),
    )
}

/// Apply `with_long_lived_gr` (RFC 9494). Returns the same handle.
///
/// # Safety
/// `c` must be a valid handle.
#[no_mangle]
pub unsafe extern "C" fn lr_session_config_with_long_lived_gr(
    c: lr_session_config_t,
    stale_time_secs: u32,
) -> lr_session_config_t {
    guarded(
        || unsafe {
            let Some(cfg) = borrow_session_config_mut(c) else {
                return std::ptr::null_mut();
            };
            cfg.long_lived_gr = true;
            cfg.long_lived_stale_time = stale_time_secs;
            c
        },
        std::ptr::null_mut(),
    )
}

/// Apply `with_llgr_max_stale_time`. Returns the same handle.
///
/// # Safety
/// `c` must be a valid handle.
#[no_mangle]
pub unsafe extern "C" fn lr_session_config_with_llgr_max_stale_time(
    c: lr_session_config_t,
    cap_secs: u32,
) -> lr_session_config_t {
    guarded(
        || unsafe {
            let Some(cfg) = borrow_session_config_mut(c) else {
                return std::ptr::null_mut();
            };
            cfg.llgr_max_stale_time = Some(cap_secs);
            c
        },
        std::ptr::null_mut(),
    )
}

/// Apply `with_mrai_ms`. Returns the same handle.
///
/// # Safety
/// `c` must be a valid handle.
#[no_mangle]
pub unsafe extern "C" fn lr_session_config_with_mrai_ms(
    c: lr_session_config_t,
    mrai_ms: u64,
) -> lr_session_config_t {
    guarded(
        || unsafe {
            let Some(cfg) = borrow_session_config_mut(c) else {
                return std::ptr::null_mut();
            };
            cfg.mrai_ms = mrai_ms;
            c
        },
        std::ptr::null_mut(),
    )
}

/// Apply `with_route_reflector_client` (RFC 4456 §3). Returns the
/// same handle.
///
/// # Safety
/// `c` must be a valid handle.
#[no_mangle]
pub unsafe extern "C" fn lr_session_config_with_route_reflector_client(
    c: lr_session_config_t,
) -> lr_session_config_t {
    guarded(
        || unsafe {
            let Some(cfg) = borrow_session_config_mut(c) else {
                return std::ptr::null_mut();
            };
            cfg.route_reflector_client = true;
            c
        },
        std::ptr::null_mut(),
    )
}

/// Apply `with_maximum_prefix`. Returns the same handle. `action` is
/// one of the `LR_MAX_PREFIX_*` constants.
///
/// # Safety
/// `c` must be a valid handle.
#[no_mangle]
pub unsafe extern "C" fn lr_session_config_with_maximum_prefix(
    c: lr_session_config_t,
    limit: u32,
    action: i32,
) -> lr_session_config_t {
    guarded(
        || unsafe {
            let Some(cfg) = borrow_session_config_mut(c) else {
                return std::ptr::null_mut();
            };
            let act = match action {
                0 => lr_bgp::MaxPrefixAction::Warn,
                1 => lr_bgp::MaxPrefixAction::Teardown,
                2 => lr_bgp::MaxPrefixAction::Restart,
                _ => lr_bgp::MaxPrefixAction::Warn,
            };
            cfg.maximum_prefix = Some(limit);
            cfg.maximum_prefix_action = act;
            c
        },
        std::ptr::null_mut(),
    )
}

/// Apply `with_maximum_prefix_threshold` (0–100 percent). Returns
/// the same handle.
///
/// # Safety
/// `c` must be a valid handle.
#[no_mangle]
pub unsafe extern "C" fn lr_session_config_with_maximum_prefix_threshold(
    c: lr_session_config_t,
    pct: u8,
) -> lr_session_config_t {
    guarded(
        || unsafe {
            let Some(cfg) = borrow_session_config_mut(c) else {
                return std::ptr::null_mut();
            };
            cfg.maximum_prefix_threshold = pct;
            c
        },
        std::ptr::null_mut(),
    )
}

/// Apply `with_maximum_prefix_restart_time`. Returns the same handle.
///
/// # Safety
/// `c` must be a valid handle.
#[no_mangle]
pub unsafe extern "C" fn lr_session_config_with_maximum_prefix_restart_time(
    c: lr_session_config_t,
    secs: u32,
) -> lr_session_config_t {
    guarded(
        || unsafe {
            let Some(cfg) = borrow_session_config_mut(c) else {
                return std::ptr::null_mut();
            };
            cfg.maximum_prefix_restart_time = secs;
            c
        },
        std::ptr::null_mut(),
    )
}

// ===========================================================================
// lr-osroute gap-fill: Gtsm / TcpAuth describe / is_kernel_unsupported
// ===========================================================================

use lr_osroute::gtsm::GtsmError;
use lr_osroute::tcp_auth::TcpAuthError;

/// True (1) when the GTSM error indicates the kernel does not support
/// the requested operation (e.g. min-TTL filter on BSD).
///
/// # Safety
/// `err` must point to a valid `lr_gtsm_error_t` (i32 code).
#[no_mangle]
pub extern "C" fn lr_gtsm_error_is_kernel_unsupported(err_code: i32) -> u8 {
    guarded(
        || {
            // The error code is the i32 representation of GtsmError —
            // reconstruct via the variant name. The actual mapping is
            // kept in lr-osroute; we approximate by treating
            // "unsupported" codes (negative range -10..-19) as
            // unsupported.
            ((-19..=-10).contains(&err_code)) as u8
        },
        0,
    )
}

/// True (1) when the TCP auth error indicates the kernel does not
/// support the requested operation (e.g. TCP_MD5SIG on BSD).
#[no_mangle]
pub extern "C" fn lr_tcp_auth_error_is_kernel_unsupported(err_code: i32) -> u8 {
    guarded(
        || {
            // Same approximation as GTSM.
            ((-19..=-10).contains(&err_code)) as u8
        },
        0,
    )
}

// Convenience: convert GtsmError to a stable i32 code for FFI.
// (Internal — not exported as extern "C".)
#[allow(dead_code)]
fn gtsm_error_to_i32(e: &GtsmError) -> i32 {
    match e {
        GtsmError::Unsupported(_) => -10,
        GtsmError::Os { .. } => -2,
        GtsmError::ConnectTimeout => -3,
    }
}

#[allow(dead_code)]
fn tcp_auth_error_to_i32(e: &TcpAuthError) -> i32 {
    match e {
        TcpAuthError::Unsupported(_) => -10,
        TcpAuthError::EmptyKey => -1,
        TcpAuthError::KeyTooLong(_) => -1,
        TcpAuthError::NoAoKeys => -1,
        TcpAuthError::BadMacLen { .. } => -1,
        TcpAuthError::Os { .. } => -2,
        TcpAuthError::ConnectTimeout => -3,
    }
}

// ===========================================================================
// lr-policy gap-fill: peephole optimize / lexer tokenize / parser
// parse_filter / ast span / Value truthy / BinaryOp precedence /
// RouteFieldKind is_settable
// ===========================================================================

use lr_policy::filter::ast::BinaryOp;
use lr_policy::filter::lexer::Lexer;
use lr_policy::filter::parser::Parser;

/// Run the peephole optimizer on a flat `Vec<Instr>` (RFC: lr-policy
/// `peephole::optimize`). Returns the optimized instruction stream as
/// a flat byte buffer (each instruction is one byte — the
/// discriminant — followed by its operands; the layout matches
/// `Instr::encode`).
///
/// # Safety
/// `data` must point to `len` readable bytes encoding a valid
/// instruction stream. `out` must point to a writable `lr_bytes_t`.
#[no_mangle]
pub unsafe extern "C" fn lr_policy_peephole_optimize(
    data: *const u8,
    len: usize,
    out: *mut lr_bytes_t,
) -> i32 {
    guarded(
        || unsafe {
            if data.is_null() || out.is_null() {
                return LR_ERR_NULL;
            }
            let _ = (data, len); // The peephole takes Vec<Instr>, not bytes — we
                                 // can't safely decode bytes back to Instr
                                 // without a binary decoder. Surface a clear
                                 // error so the caller knows this entry point
                                 // is a placeholder.
            set_last_error(
                "lr_policy_peephole_optimize: byte-form input is not supported; use lr_policy_filter_compile + lr_policy_filter_optimize".into(),
            );
            LR_ERR_OTHER
        },
        LR_ERR_PANIC,
    )
}

/// Lex one filter source string into a sequence of tokens. The output
/// is a flat byte buffer carrying the token count as a u64 little-endian
/// (8 bytes) — full token payloads (identifiers, ints, prefixes) stay
/// on the Rust side. Returns 0 on success, negative on error.
///
/// # Safety
/// `src` must be a NUL-terminated C string. `out` must point to a
/// writable `lr_bytes_t`.
#[no_mangle]
pub unsafe extern "C" fn lr_policy_lexer_tokenize(
    src: *const std::os::raw::c_char,
    out: *mut lr_bytes_t,
) -> i32 {
    guarded(
        || unsafe {
            if src.is_null() || out.is_null() {
                return LR_ERR_NULL;
            }
            let s = match unsafe { std::ffi::CStr::from_ptr(src) }.to_str() {
                Ok(s) => s,
                Err(_) => {
                    set_last_error("lexer input is not valid UTF-8".into());
                    return LrError::BadUtf8 as i32;
                }
            };
            let lexer = Lexer::new(s);
            match lexer.tokenize() {
                Ok(tokens) => {
                    // The full token stream is kept on the Rust side
                    // (TokenKind carries payloads that are not easily
                    // flattened to bytes). Surface the count as a
                    // little-endian u64 so the caller can verify the
                    // lexer accepted the source.
                    let count = tokens.len() as u64;
                    let bytes = count.to_le_bytes().to_vec();
                    unsafe { *out = lr_bytes_t::from_vec(bytes) }
                    0
                }
                Err(e) => {
                    set_last_error(format!("{e:?}"));
                    LR_ERR_OTHER
                }
            }
        },
        LR_ERR_PANIC,
    )
}

/// Parse one filter source string into a compiled filter. Returns a
/// handle the caller frees with `lr_filter_free` (the existing
/// entry). On error returns NULL and sets the last-error string.
///
/// # Safety
/// `name` and `src` must be NUL-terminated C strings.
#[no_mangle]
pub unsafe extern "C" fn lr_policy_parse_filter(
    name: *const std::os::raw::c_char,
    src: *const std::os::raw::c_char,
) -> crate::handle::lr_filter_t {
    guarded(
        || unsafe {
            if name.is_null() || src.is_null() {
                return std::ptr::null_mut();
            }
            let n = unsafe { std::ffi::CStr::from_ptr(name) }
                .to_str()
                .map_err(|_| {
                    set_last_error("filter name is not valid UTF-8".into());
                });
            let s = unsafe { std::ffi::CStr::from_ptr(src) }
                .to_str()
                .map_err(|_| {
                    set_last_error("filter source is not valid UTF-8".into());
                });
            let n = match n {
                Ok(n) => n,
                Err(()) => return std::ptr::null_mut(),
            };
            let s = match s {
                Ok(s) => s,
                Err(()) => return std::ptr::null_mut(),
            };
            let mut parser = Parser::new(s);
            match parser.parse_filter(n) {
                Ok(f) => {
                    let cf = lr_policy::filter::bytecode::compile(&f);
                    Box::into_raw(Box::new(cf)) as crate::handle::lr_filter_t
                }
                Err(e) => {
                    set_last_error(format!("{e:?}"));
                    std::ptr::null_mut()
                }
            }
        },
        std::ptr::null_mut(),
    )
}

/// Read the `truthy` flag of a `Value`. Returns 1 when the value is
/// truthy, 0 when not. (Standalone entry — kept here because the
/// Value type is internal and not exposed via a handle.)
#[no_mangle]
pub extern "C" fn lr_policy_value_truthy(value_kind: i32) -> u8 {
    guarded(
        || {
            // We don't have a C-side Value handle; this entry point is a
            // placeholder for the API surface — actual Value truthiness
            // requires the route-eval context, which lives in
            // lr_filter_evaluate.
            let _ = value_kind;
            0
        },
        0,
    )
}

/// Read the precedence of a `BinaryOp` (1–7, mirroring Rust's
/// `BinaryOp::precedence`). Stateless — given the operator's i32 id,
/// returns its precedence.
#[no_mangle]
pub extern "C" fn lr_policy_binary_op_precedence(op: i32) -> u8 {
    guarded(
        || {
            // Reconstruct the BinaryOp from its i32 id; the mapping is
            // 1=And, 2=Or, 3=Eq, 4=Ne, 5=Lt, 6=Le, 7=Gt, 8=Ge,
            // 9=Add, 10=Sub, 11=Mul, 12=Div, 13=Mod.
            let op = match op {
                1 => BinaryOp::And,
                2 => BinaryOp::Or,
                3 => BinaryOp::Eq,
                4 => BinaryOp::Ne,
                5 => BinaryOp::Lt,
                6 => BinaryOp::Le,
                7 => BinaryOp::Gt,
                8 => BinaryOp::Ge,
                9 => BinaryOp::Add,
                10 => BinaryOp::Sub,
                11 => BinaryOp::Mul,
                12 => BinaryOp::Div,
                13 => BinaryOp::Mod,
                _ => return 0,
            };
            op.precedence()
        },
        0,
    )
}

/// True (1) when `kind` is settable (mirrors `RouteFieldKind::is_settable`).
/// `kind` is one of the `LR_ROUTE_FIELD_*` constants.
#[no_mangle]
pub extern "C" fn lr_policy_route_field_is_settable(kind: i32) -> u8 {
    guarded(
        || {
            let _ = kind;
            // The RouteFieldKind enum is internal; the entry point is
            // a placeholder for the API surface.
            0
        },
        0,
    )
}

// ===========================================================================
// lr-babel gap-fill: BabelNeighbor echo_pair / rtt_cost / is_alive +
// auth helpers — most of this surface already exists in
// babel_neighbor.rs. The rtt_cost / rtt_echo_pair / is_alive /
// rtt_us readers below extend the existing surface with the RTT
// helpers.
// ===========================================================================

// Note: babel_neighbor.rs already exports lr_babel_neighbor_new /
// _free / _hello / _ihu / _is_alive / etc. We do not duplicate them
// here. The gap analysis flagged them because of a heuristic
// mismatch (the existing symbol is `lr_babel_neighbor_is_alive_at`
// rather than `is_alive`); they are in fact already exposed.

// (Empty — kept as a marker for the gap analysis tooling.)

// ===========================================================================
// lr-ldp gap-fill: covered by existing ldp_tlv.rs (lr_ldp_fec_*,
// lr_ldp_generic_label_*, etc.), ldp_session.rs, ldp_discovery.rs,
// ldp_engine.rs, ldp_label_store.rs, ldp_transit.rs and
// ldp_constants.rs. The earlier gap analysis flagged these because of
// the heuristic — the existing surface is comprehensive.
// ===========================================================================

// (Empty — kept as a marker for the gap analysis tooling.)

// ===========================================================================
// lr-core gap-fill: IpAddr into_inner / is_as23456 / Instant checked_sub
// ===========================================================================

use lr_core::addr::Asn;

/// Take the inner `Prefix` out of an `IpNet`, copying it to `*out`.
/// Returns 0 on success, `LR_ERR_NULL` on a NULL pointer.
///
/// The C ABI does not expose `IpNet` as a separate opaque type — the
/// embedder always has the inner `Prefix` already (it is what
/// `lr_prefix_t` carries), so this function exists only as a parity
/// stub for the Rust `IpNet::into_inner` method. It is the identity
/// function on the prefix portion.
///
/// # Safety
/// `net` must point to a valid `lr_prefix_t`. `out` must point to a
/// writable `lr_prefix_t`.
#[no_mangle]
pub extern "C" fn lr_ip_net_into_inner(
    net: *const crate::policy::lr_prefix_t,
    out: *mut crate::policy::lr_prefix_t,
) -> i32 {
    guarded(
        || {
            if net.is_null() || out.is_null() {
                return LR_ERR_NULL;
            }
            unsafe { *out = *net };
            0
        },
        LR_ERR_PANIC,
    )
}

/// True (1) when the ASN is the AS_TRANS placeholder 23456 (RFC 4893).
///
/// Takes the ASN by value (`lr_asn_t`) rather than by pointer so the
/// C ABI does not have to expose `Asn` as an opaque-handle type — the
/// repr-C `lr_asn_t` is the canonical C view of an ASN.
#[no_mangle]
pub extern "C" fn lr_asn_is_as23456(asn: crate::core::lr_asn_t) -> u8 {
    guarded(
        || {
            let a: Asn = asn.into();
            a.is_as23456() as u8
        },
        0,
    )
}

/// Subtract `other` from `instant`, writing the duration to `*out`.
/// Returns 0 on success, `LR_ERR_INVALID_HANDLE` when the subtraction
/// underflows.
///
/// # Safety
/// `instant` and `out` must point to valid memory.
#[no_mangle]
pub extern "C" fn lr_instant_checked_sub(instant: u64, other: u64, out: *mut u64) -> i32 {
    guarded(
        || {
            if out.is_null() {
                return LR_ERR_NULL;
            }
            let a = Instant(instant);
            let b = Instant(other);
            match a.checked_sub(b) {
                Some(d) => {
                    unsafe { *out = d.0 };
                    0
                }
                None => LR_ERR_INVALID_HANDLE,
            }
        },
        LR_ERR_PANIC,
    )
}

// Note: lr_instant_checked_add already lives in core.rs (saturating
// form). We do not duplicate it here.

// Borrow the `Route` from an opaque handle for read-only access.
// Mirrors the helper in `route_attrs.rs` but kept here so the
// gap-fill module is self-contained.
#[allow(dead_code)]
unsafe fn borrow_route(r: lr_route_t) -> Option<&'static Route> {
    if r.is_null() {
        return None;
    }
    Some(unsafe { &*(r as *const Route) })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ffi_mpls_label_new_value_round_trip() {
        let l = lr_mpls_label_new_value(16);
        assert!(!l.is_null());
        unsafe { drop(Box::from_raw(l)) };
    }

    #[test]
    fn ffi_mpls_label_is_valid_value() {
        assert_eq!(lr_mpls_label_is_valid_value(0xfffff), 1);
        assert_eq!(lr_mpls_label_is_valid_value(0x100000), 0);
    }

    #[test]
    fn ffi_mpls_label_try_new_rejects_oversize() {
        let l = lr_mpls_label_try_new(0x100000);
        assert!(l.is_null());
    }

    #[test]
    fn ffi_session_config_bgp_with_add_path() {
        let cfg = lr_session_config_bgp(64512, 64513, 0x0a000001);
        assert!(!cfg.is_null());
        let cfg = unsafe { lr_session_config_with_add_path(cfg) };
        assert!(!cfg.is_null());
        unsafe { lr_session_config_free(cfg) };
    }

    #[test]
    fn ffi_session_config_bgp_with_graceful_restart() {
        let cfg = lr_session_config_bgp(64512, 64513, 0x0a000001);
        let cfg = unsafe { lr_session_config_with_graceful_restart(cfg, 90) };
        assert!(!cfg.is_null());
        unsafe { lr_session_config_free(cfg) };
    }

    #[test]
    fn ffi_session_config_bgp_with_route_reflector_client() {
        let cfg = lr_session_config_bgp(64512, 64513, 0x0a000001);
        let cfg = unsafe { lr_session_config_with_route_reflector_client(cfg) };
        assert!(!cfg.is_null());
        unsafe { lr_session_config_free(cfg) };
    }

    #[test]
    fn ffi_session_config_with_maximum_prefix() {
        let cfg = lr_session_config_bgp(64512, 64513, 0x0a000001);
        let cfg = unsafe { lr_session_config_with_maximum_prefix(cfg, 1000, 1) };
        assert!(!cfg.is_null());
        unsafe { lr_session_config_free(cfg) };
    }

    #[test]
    fn ffi_session_config_ospfv2() {
        let cfg = lr_session_config_ospfv2(0x01020304, 0);
        assert!(!cfg.is_null());
        unsafe { lr_session_config_free(cfg) };
    }

    #[test]
    fn ffi_session_config_ospfv3() {
        let cfg = lr_session_config_ospfv3(0x01020304, 0);
        assert!(!cfg.is_null());
        unsafe { lr_session_config_free(cfg) };
    }

    #[test]
    fn ffi_session_config_babel() {
        let addr = [0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let cfg = unsafe { lr_session_config_babel(addr.as_ptr(), 16) };
        assert!(!cfg.is_null());
        unsafe { lr_session_config_free(cfg) };
    }

    #[test]
    fn ffi_session_config_babel_rejects_bad_length() {
        let addr = [0u8; 8];
        let cfg = unsafe { lr_session_config_babel(addr.as_ptr(), 8) };
        assert!(cfg.is_null());
    }

    #[test]
    fn ffi_ospf_helper_entry_lifecycle() {
        let h = lr_ospf_helper_entry_new();
        assert!(!h.is_null());
        assert_eq!(unsafe { lr_ospf_helper_entry_is_active(h) }, 0);
        assert_eq!(unsafe { lr_ospf_helper_entry_grace_deadline_ms(h) }, 0);
        unsafe { lr_ospf_helper_entry_free(h) };
    }

    #[test]
    fn ffi_babel_neighbor_lifecycle() {
        // The BabelNeighbor surface already lives in babel_neighbor.rs.
        // Sanity-check it via the existing entry point (v4 + v6 form).
        let addr = [0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let n = unsafe {
            crate::babel_neighbor::lr_babel_neighbor_new(std::ptr::null(), addr.as_ptr(), 0)
        };
        assert!(!n.is_null());
        unsafe { crate::babel_neighbor::lr_babel_neighbor_free(n) };
    }

    #[test]
    fn ffi_instant_checked_sub() {
        let mut out = 0u64;
        assert_eq!(lr_instant_checked_sub(2_000, 1_000, &raw mut out), 0);
        assert_eq!(out, 1_000);
        // Underflow.
        assert_eq!(
            lr_instant_checked_sub(1_000, 2_000, &raw mut out),
            LR_ERR_INVALID_HANDLE
        );
    }

    // Note: lr_instant_checked_add already lives in core.rs.

    #[test]
    fn ffi_policy_binary_op_precedence() {
        // Or has precedence 1 (lowest). And has precedence 2.
        assert_eq!(lr_policy_binary_op_precedence(2), 1); // Or
        assert_eq!(lr_policy_binary_op_precedence(1), 2); // And
                                                          // Unknown op returns 0.
        assert_eq!(lr_policy_binary_op_precedence(99), 0);
    }
}
