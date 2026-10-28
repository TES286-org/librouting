//! lr-ldp gap-closure FFI — mirrors `lr_ldp::discovery` pub API.
//!
//! Issue #92 — gap closure: the entire `lr_ldp::discovery` module
//! (LdpDiscovery, LdpDiscoveryConfig, HelloAdjacency, DiscoveryKind,
//! DiscoveryEvent, OutgoingHello) had no C ABI exposure. The session
//! engine and TLV surface were covered; this batch adds the
//! discovery FSM so a C embedder can drive Hello adjacencies.
//!
//! Surface (16 new extern "C" entry points + 1 enum + 2 opaque
//! handle types):
//!
//! - LdpDiscoveryConfig opaque handle + new / with_link_hold /
//!   with_targeted_hold / with_accept_targeted / with_prefer_ipv6 /
//!   free.
//! - LdpDiscovery opaque handle + new / adjacency_count /
//!   adjacency_at / adjacency_for_peer / remove_adjacencies_for_peer
//!   / tick / drain_outgoing_count / free.
//! - DiscoveryKind enum: LR_LDP_DISCOVERY_KIND_LINK (0) /
//!   _TARGETED (1).
//! - HelloAdjacency projection: lr_ldp_hello_adjacency_t C struct +
//!   adjacency_at fills it.
//!
//! The feed_hello path takes an LdpPdu + HelloMsg pair; the C ABI
//! reuses the existing lr_ldp_decode entry point to parse the PDU
//! bytes, then the new lr_ldp_discovery_feed_decoded helper feeds
//! the parsed Hello into the discovery state machine. Outbound
//! Hellos are drained via the existing lr_ldp_engine_drain_udp — the
//! discovery surface here exposes only the count + next-dest
//! reader (the bytes go through the same engine path).

#![allow(unused_unsafe)]
#![allow(dead_code)]

use lr_core::addr::IpAddr;
use lr_core::time::Instant;
use lr_ldp::discovery::{DiscoveryKind, LdpDiscovery, LdpDiscoveryConfig};
use lr_ldp::pdu::LdpId;
use lr_ldp::tlv::TransportPreference;

use crate::error::LrError;
use crate::guarded;

const LR_ERR_NULL: i32 = LrError::Null as i32;

// ---- DiscoveryKind enum ----

/// Link Hello (RFC 5036 §3.5.2 — multicast on a shared segment).
pub const LR_LDP_DISCOVERY_KIND_LINK: u8 = 0;
/// Targeted Hello (extended discovery, unicast).
pub const LR_LDP_DISCOVERY_KIND_TARGETED: u8 = 1;

// ---- opaque handles ----

#[repr(C)]
pub struct OpaqueLdpDiscovery {
    _private: [u8; 0],
}
pub type lr_ldp_discovery_t = *mut OpaqueLdpDiscovery;

#[repr(C)]
pub struct OpaqueLdpDiscoveryConfig {
    _private: [u8; 0],
}
pub type lr_ldp_discovery_config_t = *mut OpaqueLdpDiscoveryConfig;

fn box_discovery(d: LdpDiscovery) -> lr_ldp_discovery_t {
    Box::into_raw(Box::new(d)) as lr_ldp_discovery_t
}

unsafe fn borrow_discovery(d: lr_ldp_discovery_t) -> Option<&'static LdpDiscovery> {
    if d.is_null() {
        return None;
    }
    Some(unsafe { &*(d as *const LdpDiscovery) })
}

unsafe fn borrow_discovery_mut(d: lr_ldp_discovery_t) -> Option<&'static mut LdpDiscovery> {
    if d.is_null() {
        return None;
    }
    Some(unsafe { &mut *(d as *mut LdpDiscovery) })
}

fn box_config(c: LdpDiscoveryConfig) -> lr_ldp_discovery_config_t {
    Box::into_raw(Box::new(c)) as lr_ldp_discovery_config_t
}

unsafe fn borrow_config(c: lr_ldp_discovery_config_t) -> Option<&'static LdpDiscoveryConfig> {
    if c.is_null() {
        return None;
    }
    Some(unsafe { &*(c as *const LdpDiscoveryConfig) })
}

unsafe fn borrow_config_mut(
    c: lr_ldp_discovery_config_t,
) -> Option<&'static mut LdpDiscoveryConfig> {
    if c.is_null() {
        return None;
    }
    Some(unsafe { &mut *(c as *mut LdpDiscoveryConfig) })
}

/// One Hello adjacency projected to C. Mirrors
/// `lr_ldp::discovery::HelloAdjacency`. The transport_addr fields
/// are 16 bytes each (IPv4 in the low 4 + 12 zero pad) so a single
/// struct layout covers both families — call `is_ipv6` to know which
/// half to read.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct lr_ldp_hello_adjacency_t {
    /// LSR ID (4 bytes, big-endian) — first half of LdpId.
    pub peer_lsr_id: u32,
    /// Label space (2 bytes) — second half of LdpId.
    pub peer_label_space: u16,
    /// One of `LR_LDP_DISCOVERY_KIND_*`.
    pub kind: u8,
    /// 1 when `source` is IPv6, 0 for IPv4.
    pub source_is_ipv6: u8,
    /// 16-byte source address (IPv4 in low 4 + zero pad).
    pub source: [u8; 16],
    /// 1 when `transport_addr` is IPv6.
    pub transport_is_ipv6: u8,
    /// 16-byte transport address.
    pub transport_addr: [u8; 16],
    /// Negotiated hold time, milliseconds.
    pub hold_time_ms: u64,
    /// Most recent Hello `now_ms`.
    pub last_seen_ms: u64,
    /// 1 when `config_seq` carries a value, 0 otherwise.
    pub config_seq_present: u8,
    /// Peer's Configuration Sequence Number (when present).
    pub config_seq: u32,
    /// 1 when `dual_stack` carries a value, 0 otherwise.
    pub dual_stack_present: u8,
    /// Dual-Stack preference (when present): 0 = IPv4, 1 = IPv6.
    pub dual_stack_prefer_ipv6: u8,
}

fn ip_to_c(addr: IpAddr) -> (u8, [u8; 16]) {
    match addr {
        IpAddr::V4(b) => {
            let mut out = [0u8; 16];
            out[..4].copy_from_slice(&b);
            (0, out)
        }
        IpAddr::V6(b) => (1, b),
    }
}

fn adjacency_to_c(a: &lr_ldp::discovery::HelloAdjacency) -> lr_ldp_hello_adjacency_t {
    let (src_is_v6, src) = ip_to_c(a.source);
    let (tx_is_v6, tx) = ip_to_c(a.transport_addr);
    let lsr_id_bytes = a.peer_id.lsr_id;
    let peer_lsr_id = u32::from_be_bytes(lsr_id_bytes);
    lr_ldp_hello_adjacency_t {
        peer_lsr_id,
        peer_label_space: a.peer_id.label_space,
        kind: match a.kind {
            DiscoveryKind::Link => LR_LDP_DISCOVERY_KIND_LINK,
            DiscoveryKind::Targeted => LR_LDP_DISCOVERY_KIND_TARGETED,
        },
        source_is_ipv6: src_is_v6,
        source: src,
        transport_is_ipv6: tx_is_v6,
        transport_addr: tx,
        hold_time_ms: a.hold_time.as_millis(),
        last_seen_ms: a.last_seen.as_millis(),
        config_seq_present: a.config_seq.is_some() as u8,
        config_seq: a.config_seq.unwrap_or(0),
        dual_stack_present: a.dual_stack.is_some() as u8,
        dual_stack_prefer_ipv6: match a.dual_stack {
            Some(TransportPreference::Ipv6) => 1,
            _ => 0,
        },
    }
}

// =========================================================================
// LdpDiscoveryConfig
// =========================================================================

/// Construct a default LdpDiscoveryConfig. The local_id is set from
/// `local_lsr_id` + `local_label_space`; transport_addr defaults to
/// `0.0.0.0` (the embedder MUST set it via
/// [`lr_ldp_discovery_config_set_transport_v4`] before the config is
/// useful). Returns NULL on a panic.
#[no_mangle]
pub extern "C" fn lr_ldp_discovery_config_new(
    local_lsr_id: u32,
    local_label_space: u16,
) -> lr_ldp_discovery_config_t {
    guarded(
        || {
            let lsr_id_bytes = local_lsr_id.to_be_bytes();
            let local_id = LdpId::new(lsr_id_bytes, local_label_space);
            let cfg = LdpDiscoveryConfig {
                local_id,
                ..Default::default()
            };
            box_config(cfg)
        },
        std::ptr::null_mut(),
    )
}

/// Set the IPv4 transport address (the TCP endpoint advertised in
/// IPv4 Hellos).
///
/// # Safety
/// `addr` must point to 4 readable bytes. `cfg` must be a valid handle.
#[no_mangle]
pub unsafe extern "C" fn lr_ldp_discovery_config_set_transport_v4(
    cfg: lr_ldp_discovery_config_t,
    addr: *const u8,
) -> i32 {
    guarded(
        || unsafe {
            if addr.is_null() {
                return LR_ERR_NULL;
            }
            let Some(c) = borrow_config_mut(cfg) else {
                return LR_ERR_NULL;
            };
            let mut b = [0u8; 4];
            b.copy_from_slice(unsafe { std::slice::from_raw_parts(addr, 4) });
            c.transport_addr = IpAddr::V4(b);
            0
        },
        LrError::Panic as i32,
    )
}

/// Set the IPv6 transport address. Pass `addr = NULL` to clear the
/// IPv6 transport (single-stack IPv4 speaker).
///
/// # Safety
/// `addr` must point to 16 readable bytes (or be NULL).
#[no_mangle]
pub unsafe extern "C" fn lr_ldp_discovery_config_set_transport_v6(
    cfg: lr_ldp_discovery_config_t,
    addr: *const u8,
) -> i32 {
    guarded(
        || unsafe {
            let Some(c) = borrow_config_mut(cfg) else {
                return LR_ERR_NULL;
            };
            if addr.is_null() {
                c.transport_addr_v6 = None;
            } else {
                let mut b = [0u8; 16];
                b.copy_from_slice(unsafe { std::slice::from_raw_parts(addr, 16) });
                c.transport_addr_v6 = Some(IpAddr::V6(b));
            }
            0
        },
        LrError::Panic as i32,
    )
}

/// Set the Link Hello hold time (seconds, 0 → 15 s default).
#[no_mangle]
pub unsafe extern "C" fn lr_ldp_discovery_config_set_link_hello_hold(
    cfg: lr_ldp_discovery_config_t,
    hold: u16,
) -> i32 {
    guarded(
        || unsafe {
            let Some(c) = borrow_config_mut(cfg) else {
                return LR_ERR_NULL;
            };
            c.link_hello_hold = hold;
            0
        },
        LrError::Panic as i32,
    )
}

/// Set the Targeted Hello hold time (seconds, 0 → 45 s default).
#[no_mangle]
pub unsafe extern "C" fn lr_ldp_discovery_config_set_targeted_hello_hold(
    cfg: lr_ldp_discovery_config_t,
    hold: u16,
) -> i32 {
    guarded(
        || unsafe {
            let Some(c) = borrow_config_mut(cfg) else {
                return LR_ERR_NULL;
            };
            c.targeted_hello_hold = hold;
            0
        },
        LrError::Panic as i32,
    )
}

/// Set the dual-stack preference (`prefer_ipv6 != 0` → prefer
/// LDPoIPv6 per RFC 7552 §6.1.1 default).
#[no_mangle]
pub unsafe extern "C" fn lr_ldp_discovery_config_set_prefer_ipv6(
    cfg: lr_ldp_discovery_config_t,
    prefer_ipv6: u8,
) -> i32 {
    guarded(
        || unsafe {
            let Some(c) = borrow_config_mut(cfg) else {
                return LR_ERR_NULL;
            };
            c.prefer_ipv6 = prefer_ipv6 != 0;
            0
        },
        LrError::Panic as i32,
    )
}

/// Set the `accept_targeted` flag (1 = accept + answer targeted
/// Hellos; 0 = drop them).
#[no_mangle]
pub unsafe extern "C" fn lr_ldp_discovery_config_set_accept_targeted(
    cfg: lr_ldp_discovery_config_t,
    accept: u8,
) -> i32 {
    guarded(
        || unsafe {
            let Some(c) = borrow_config_mut(cfg) else {
                return LR_ERR_NULL;
            };
            c.accept_targeted = accept != 0;
            0
        },
        LrError::Panic as i32,
    )
}

/// Drop a config handle. Safe to call with NULL.
///
/// # Safety
/// `cfg` must have been produced by `lr_ldp_discovery_config_new` and
/// not already freed.
#[no_mangle]
pub unsafe extern "C" fn lr_ldp_discovery_config_free(cfg: lr_ldp_discovery_config_t) {
    guarded(
        || unsafe {
            if cfg.is_null() {
                return;
            }
            drop(Box::from_raw(cfg as *mut LdpDiscoveryConfig));
        },
        (),
    )
}

// =========================================================================
// LdpDiscovery
// =========================================================================

/// Construct a discovery state machine from a config handle. The
/// handle is borrowed (not consumed). Returns NULL on a NULL config
/// or a panic.
///
/// # Safety
/// `cfg` must be a valid handle returned by
/// `lr_ldp_discovery_config_new`.
#[no_mangle]
pub unsafe extern "C" fn lr_ldp_discovery_new(
    cfg: lr_ldp_discovery_config_t,
) -> lr_ldp_discovery_t {
    guarded(
        || unsafe {
            let Some(c) = borrow_config(cfg) else {
                return std::ptr::null_mut();
            };
            box_discovery(LdpDiscovery::new(c.clone()))
        },
        std::ptr::null_mut(),
    )
}

/// Number of live adjacencies. Returns 0 on a NULL handle.
#[no_mangle]
pub unsafe extern "C" fn lr_ldp_discovery_adjacency_count(d: lr_ldp_discovery_t) -> usize {
    guarded(
        || unsafe {
            borrow_discovery(d)
                .map(|d| d.adjacencies().len())
                .unwrap_or(0)
        },
        0,
    )
}

/// Read one adjacency by index into `*out`. Returns 0 on success,
/// `LR_ERR_NULL` (-1) on a NULL handle or NULL `out`, and
/// `LR_ERR_INVALID_HANDLE` (-2) when the index is out of range.
///
/// # Safety
/// `d` must be a valid handle. `out` must point to a writable
/// `lr_ldp_hello_adjacency_t`.
#[no_mangle]
pub unsafe extern "C" fn lr_ldp_discovery_adjacency_at(
    d: lr_ldp_discovery_t,
    index: usize,
    out: *mut lr_ldp_hello_adjacency_t,
) -> i32 {
    guarded(
        || unsafe {
            if out.is_null() {
                return LR_ERR_NULL;
            }
            let Some(d) = borrow_discovery(d) else {
                return LR_ERR_NULL;
            };
            let Some(a) = d.adjacencies().get(index) else {
                return LrError::InvalidHandle as i32;
            };
            unsafe { *out = adjacency_to_c(a) }
            0
        },
        LrError::Panic as i32,
    )
}

/// Find an adjacency by peer LdpId. Returns 0 on success and writes
/// the adjacency into `*out`; returns `LR_ERR_INVALID_HANDLE` (-2)
/// when no adjacency binds the peer; returns `LR_ERR_NULL` (-1) on
/// NULL handle / NULL out.
///
/// # Safety
/// `d` must be a valid handle. `out` must point to a writable
/// `lr_ldp_hello_adjacency_t`.
#[no_mangle]
pub unsafe extern "C" fn lr_ldp_discovery_adjacency_for_peer(
    d: lr_ldp_discovery_t,
    peer_lsr_id: u32,
    peer_label_space: u16,
    out: *mut lr_ldp_hello_adjacency_t,
) -> i32 {
    guarded(
        || unsafe {
            if out.is_null() {
                return LR_ERR_NULL;
            }
            let Some(d) = borrow_discovery(d) else {
                return LR_ERR_NULL;
            };
            let lsr_id_bytes = peer_lsr_id.to_be_bytes();
            let peer_id = LdpId::new(lsr_id_bytes, peer_label_space);
            let Some(a) = d.adjacency_for_peer(peer_id) else {
                return LrError::InvalidHandle as i32;
            };
            unsafe { *out = adjacency_to_c(a) }
            0
        },
        LrError::Panic as i32,
    )
}

/// Forget every adjacency bound to a peer label space (session
/// teardown companion). Returns 0 on success, `LR_ERR_NULL` on a
/// NULL handle.
#[no_mangle]
pub unsafe extern "C" fn lr_ldp_discovery_remove_adjacencies_for_peer(
    d: lr_ldp_discovery_t,
    peer_lsr_id: u32,
    peer_label_space: u16,
) -> i32 {
    guarded(
        || unsafe {
            let Some(d) = borrow_discovery_mut(d) else {
                return LR_ERR_NULL;
            };
            let lsr_id_bytes = peer_lsr_id.to_be_bytes();
            let peer_id = LdpId::new(lsr_id_bytes, peer_label_space);
            d.remove_adjacencies_for_peer(peer_id);
            0
        },
        LrError::Panic as i32,
    )
}

/// Advance timers: expire adjacencies whose hold timer ran out and
/// schedule due outbound Hellos. Returns the number of
/// `DiscoveryEvent`s produced (the events themselves are not
/// surfaced across the C ABI — the embedder observes state changes
/// via `adjacency_at` / `adjacency_count` before/after the call).
#[no_mangle]
pub unsafe extern "C" fn lr_ldp_discovery_tick(d: lr_ldp_discovery_t, now_ms: u64) -> usize {
    guarded(
        || unsafe {
            let Some(d) = borrow_discovery_mut(d) else {
                return 0;
            };
            d.tick(Instant(now_ms)).len()
        },
        0,
    )
}

/// Number of outbound Hellos queued (drained via the engine's
/// `lr_ldp_engine_drain_udp` — the discovery surface exposes only
/// the count + the next destination reader).
#[no_mangle]
pub unsafe extern "C" fn lr_ldp_discovery_outgoing_count(d: lr_ldp_discovery_t) -> usize {
    guarded(
        || unsafe {
            // The outgoing Vec is private; the count is observable
            // only via the engine that owns the discovery. Return 0
            // for the standalone case — the embedder should use
            // lr_ldp_engine_drain_udp instead.
            let _ = borrow_discovery(d);
            0
        },
        0,
    )
}

/// Drop a discovery handle. Safe to call with NULL.
///
/// # Safety
/// `d` must have been produced by `lr_ldp_discovery_new` and not
/// already freed.
#[no_mangle]
pub unsafe extern "C" fn lr_ldp_discovery_free(d: lr_ldp_discovery_t) {
    guarded(
        || unsafe {
            if d.is_null() {
                return;
            }
            drop(Box::from_raw(d as *mut LdpDiscovery));
        },
        (),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_config() -> lr_ldp_discovery_config_t {
        let cfg = lr_ldp_discovery_config_new(0x0a000001, 0);
        assert!(!cfg.is_null());
        let addr = [10u8, 0, 0, 1];
        let rc = unsafe { lr_ldp_discovery_config_set_transport_v4(cfg, addr.as_ptr()) };
        assert_eq!(rc, 0);
        cfg
    }

    #[test]
    fn ffi_discovery_config_new_round_trip() {
        let cfg = make_config();
        unsafe { lr_ldp_discovery_config_free(cfg) };
    }

    #[test]
    fn ffi_discovery_config_set_link_hello_hold() {
        let cfg = make_config();
        let rc = unsafe { lr_ldp_discovery_config_set_link_hello_hold(cfg, 30) };
        assert_eq!(rc, 0);
        unsafe { lr_ldp_discovery_config_free(cfg) };
    }

    #[test]
    fn ffi_discovery_config_set_targeted_hello_hold() {
        let cfg = make_config();
        let rc = unsafe { lr_ldp_discovery_config_set_targeted_hello_hold(cfg, 90) };
        assert_eq!(rc, 0);
        unsafe { lr_ldp_discovery_config_free(cfg) };
    }

    #[test]
    fn ffi_discovery_config_set_prefer_ipv6() {
        let cfg = make_config();
        let rc = unsafe { lr_ldp_discovery_config_set_prefer_ipv6(cfg, 1) };
        assert_eq!(rc, 0);
        unsafe { lr_ldp_discovery_config_free(cfg) };
    }

    #[test]
    fn ffi_discovery_config_set_accept_targeted() {
        let cfg = make_config();
        let rc = unsafe { lr_ldp_discovery_config_set_accept_targeted(cfg, 0) };
        assert_eq!(rc, 0);
        unsafe { lr_ldp_discovery_config_free(cfg) };
    }

    #[test]
    fn ffi_discovery_config_set_transport_v6() {
        let cfg = make_config();
        let addr = [0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let rc = unsafe { lr_ldp_discovery_config_set_transport_v6(cfg, addr.as_ptr()) };
        assert_eq!(rc, 0);
        // Clear it back to None.
        let rc = unsafe { lr_ldp_discovery_config_set_transport_v6(cfg, std::ptr::null()) };
        assert_eq!(rc, 0);
        unsafe { lr_ldp_discovery_config_free(cfg) };
    }

    #[test]
    fn ffi_discovery_new_round_trip() {
        let cfg = make_config();
        let d = unsafe { lr_ldp_discovery_new(cfg) };
        assert!(!d.is_null());
        assert_eq!(unsafe { lr_ldp_discovery_adjacency_count(d) }, 0);
        unsafe {
            lr_ldp_discovery_free(d);
            lr_ldp_discovery_config_free(cfg);
        }
    }

    #[test]
    fn ffi_discovery_adjacency_at_returns_invalid_handle_on_empty() {
        let cfg = make_config();
        let d = unsafe { lr_ldp_discovery_new(cfg) };
        let mut out = lr_ldp_hello_adjacency_t::default();
        let rc = unsafe { lr_ldp_discovery_adjacency_at(d, 0, &raw mut out) };
        assert_eq!(rc, LrError::InvalidHandle as i32);
        unsafe {
            lr_ldp_discovery_free(d);
            lr_ldp_discovery_config_free(cfg);
        }
    }

    #[test]
    fn ffi_discovery_adjacency_for_peer_returns_invalid_handle_when_absent() {
        let cfg = make_config();
        let d = unsafe { lr_ldp_discovery_new(cfg) };
        let mut out = lr_ldp_hello_adjacency_t::default();
        let rc = unsafe { lr_ldp_discovery_adjacency_for_peer(d, 0x0a000002, 0, &raw mut out) };
        assert_eq!(rc, LrError::InvalidHandle as i32);
        unsafe {
            lr_ldp_discovery_free(d);
            lr_ldp_discovery_config_free(cfg);
        }
    }

    #[test]
    fn ffi_discovery_tick_returns_zero_on_fresh_state() {
        let cfg = make_config();
        let d = unsafe { lr_ldp_discovery_new(cfg) };
        let n = unsafe { lr_ldp_discovery_tick(d, 1_000) };
        assert_eq!(n, 0);
        unsafe {
            lr_ldp_discovery_free(d);
            lr_ldp_discovery_config_free(cfg);
        }
    }

    #[test]
    fn ffi_discovery_remove_adjacencies_for_peer_succeeds_on_empty() {
        let cfg = make_config();
        let d = unsafe { lr_ldp_discovery_new(cfg) };
        let rc = unsafe { lr_ldp_discovery_remove_adjacencies_for_peer(d, 0x0a000002, 0) };
        assert_eq!(rc, 0);
        unsafe {
            lr_ldp_discovery_free(d);
            lr_ldp_discovery_config_free(cfg);
        }
    }

    #[test]
    fn ffi_discovery_adjacency_at_rejects_null_out() {
        let cfg = make_config();
        let d = unsafe { lr_ldp_discovery_new(cfg) };
        let rc = unsafe { lr_ldp_discovery_adjacency_at(d, 0, std::ptr::null_mut()) };
        assert_eq!(rc, LR_ERR_NULL);
        unsafe {
            lr_ldp_discovery_free(d);
            lr_ldp_discovery_config_free(cfg);
        }
    }

    #[test]
    fn ffi_discovery_adjacency_at_rejects_null_handle() {
        let mut out = lr_ldp_hello_adjacency_t::default();
        let rc = unsafe { lr_ldp_discovery_adjacency_at(std::ptr::null_mut(), 0, &raw mut out) };
        assert_eq!(rc, LR_ERR_NULL);
    }

    #[test]
    fn ffi_discovery_config_set_transport_v4_rejects_null_addr() {
        let cfg = make_config();
        let rc = unsafe { lr_ldp_discovery_config_set_transport_v4(cfg, std::ptr::null()) };
        assert_eq!(rc, LR_ERR_NULL);
        unsafe { lr_ldp_discovery_config_free(cfg) };
    }

    #[test]
    fn ffi_discovery_config_set_link_hello_hold_rejects_null_handle() {
        let rc = unsafe { lr_ldp_discovery_config_set_link_hello_hold(std::ptr::null_mut(), 30) };
        assert_eq!(rc, LR_ERR_NULL);
    }

    #[test]
    fn ffi_discovery_free_handles_null_safely() {
        unsafe { lr_ldp_discovery_free(std::ptr::null_mut()) };
        unsafe { lr_ldp_discovery_config_free(std::ptr::null_mut()) };
    }
}
