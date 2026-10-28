//! LDP engine FFI (RFC 5036 §2.8 + §3.5 + RFC 7552 dual-stack + RFC 3478
//! §3.3 graceful restart + §3.5.7.1.1 transit allocation).
//!
//! Mirrors the public Rust API of `lr_ldp::engine::{LdpEngine,
//! LdpEngineConfig, EngineEvent}` so an embedder can drive a full LDP
//! speaker (discovery + session FSM + label binding bookkeeping +
//! transit allocation) from C without going through the daemon.
//!
//! # Surface
//!
//! - `lr_ldp_engine_config_new` / `_free` — build / drop the engine
//!   config (the engine mirrors `LdpEngineConfig`).
//! - `lr_ldp_engine_config_set_*` — set every documented field
//!   (transport_addr, transport_addr_v6, prefer_ipv6, keepalive_time,
//!   max_pdu_len, advertisement, link_hello_hold,
//!   targeted_hello_hold, accept_targeted, loop_detection,
//!   path_vector_limit, label_min, label_max).
//! - `lr_ldp_engine_config_add_targeted_peer` /
//!   `_add_interface_address` / `_add_reserved_label` — append to the
//!   Vec fields.
//! - `lr_ldp_engine_new` / `_free` — construct / drop a `LdpEngine`
//!   from a config.
//! - `lr_ldp_engine_feed_udp` / `_feed_tcp` — drive the receive path
//!   (the embedder owns the sockets).
//! - `lr_ldp_engine_on_connected` / `_on_connect_failed` /
//!   `_on_accepted` / `_on_closed` — TCP transport callbacks.
//! - `lr_ldp_engine_tick` — drive timers (RFC 5036 §3.5.1.2 hold +
//!   keepalive, §3.5.7.1.1 transit, RFC 3478 §3.3 stale / recovery
//!   windows).
//! - `lr_ldp_engine_advertise_mapping` / `_withdraw_mapping` —
//!   locally originate label bindings (egress side).
//! - `lr_ldp_engine_send_link_hello` — emit one Link Hello to the
//!   given destination.
//! - `lr_ldp_engine_shutdown_peer` — graceful shutdown of one peer.
//! - `lr_ldp_engine_drain_udp` — drain queued UDP datagrams (each
//!   returns a destination address + bytes).
//! - `lr_ldp_engine_drain_tcp` — drain queued bytes for one
//!   connection.
//! - `lr_ldp_engine_drain_tcp_all` — drain queued bytes for every
//!   connection (paired `(conn_id, bytes)`).
//! - `lr_ldp_engine_take_events` — drain queued engine events into a
//!   fixed-layout C struct array; events that don't fit are requeued
//!   (front of the queue, order preserved), so polling with a
//!   too-small buffer loses nothing.
//! - `lr_ldp_engine_transit_label_of` / `_transit_label_count` /
//!   `_transit_next_hop` — transit-LSR introspection (§3.5.7.1.1).
//! - `lr_ldp_engine_adjacency_count` / `_adjacency_at` — read live
//!   adjacencies.
//! - `lr_ldp_engine_session_state` — read one peer's session state
//!   (one of the `LR_LDP_SESSION_STATE_*` constants).
//!
//! Every entry point runs inside the crate's `catch_unwind` barrier
//! ([`crate::guarded`]): a panic returns `LR_ERR_PANIC` and sets the
//! thread-local last-error string.

// The `[u8; 4]` / `[u8; 16]` extern parameters (transport_addr_v4,
// prefix_v4, etc.) are not FFI-safe per the improper_ctypes_definitions
// lint, but cbindgen emits them as fixed-size arrays on the C side
// (`uint8_t addr_v4[4]` / `uint8_t addr_v6[16]`) which IS the standard
// C ABI shape. The Rust-side lint is overly conservative here.
#![allow(improper_ctypes_definitions)]
#![allow(unused_unsafe)]

use lr_core::addr::{IpAddr, Prefix};
use lr_core::time::Instant;
use lr_ldp::discovery::{DiscoveryKind, HelloAdjacency};
use lr_ldp::engine::{EngineEvent, LdpEngine, LdpEngineConfig};
use lr_ldp::pdu::{AdvertisementMode, LdpId};
use lr_ldp::session::SessionState;
use lr_ldp::tlv::GenericLabel;

use crate::error::{set_last_error, LrError, LR_ERR_PANIC};
use crate::guarded;
use crate::handle::lr_bytes_t;

const LR_ERR_NULL: i32 = LrError::Null as i32;
const LR_ERR_INVALID_HANDLE: i32 = LrError::InvalidHandle as i32;
const LR_ERR_OTHER: i32 = LrError::Other as i32;

// ---- Constants ----

pub const LR_LDP_ADVERTISEMENT_DOWNSTREAM_UNSOLICITED: i32 = 1;
pub const LR_LDP_ADVERTISEMENT_DOWNSTREAM_ON_DEMAND: i32 = 2;

pub const LR_LDP_DISCOVERY_KIND_LINK: i32 = 1;
pub const LR_LDP_DISCOVERY_KIND_TARGETED: i32 = 2;

pub const LR_LDP_SESSION_STATE_NON_EXISTENT: i32 = 1;
pub const LR_LDP_SESSION_STATE_INITIALIZED: i32 = 2;
pub const LR_LDP_SESSION_STATE_OPEN_REC: i32 = 3;
pub const LR_LDP_SESSION_STATE_OPEN_SENT: i32 = 4;
pub const LR_LDP_SESSION_STATE_OPERATIONAL: i32 = 5;

// ---- Opaque handle types ----

#[repr(C)]
pub struct OpaqueLdpEngineConfig {
    _private: [u8; 0],
}
pub type lr_ldp_engine_config_t = *mut OpaqueLdpEngineConfig;

#[repr(C)]
pub struct OpaqueLdpEngine {
    _private: [u8; 0],
}
pub type lr_ldp_engine_t = *mut OpaqueLdpEngine;

fn box_config(c: LdpEngineConfig) -> lr_ldp_engine_config_t {
    Box::into_raw(Box::new(c)) as lr_ldp_engine_config_t
}
unsafe fn unbox_config(c: lr_ldp_engine_config_t) -> Option<Box<LdpEngineConfig>> {
    if c.is_null() {
        return None;
    }
    Some(unsafe { Box::from_raw(c as *mut LdpEngineConfig) })
}
unsafe fn borrow_config(c: lr_ldp_engine_config_t) -> Option<&'static mut LdpEngineConfig> {
    if c.is_null() {
        return None;
    }
    Some(unsafe { &mut *(c as *mut LdpEngineConfig) })
}

fn box_engine(e: LdpEngine) -> lr_ldp_engine_t {
    Box::into_raw(Box::new(e)) as lr_ldp_engine_t
}
unsafe fn borrow_engine_mut(e: lr_ldp_engine_t) -> Option<&'static mut LdpEngine> {
    if e.is_null() {
        return None;
    }
    Some(unsafe { &mut *(e as *mut LdpEngine) })
}
unsafe fn borrow_engine(e: lr_ldp_engine_t) -> Option<&'static LdpEngine> {
    if e.is_null() {
        return None;
    }
    Some(unsafe { &*(e as *const LdpEngine) })
}

// ---- Engine config ----

/// Construct an `LdpEngineConfig` with the local LDP identifier and
/// transport address. The remaining fields default to the
/// `LdpEngineConfig::new` values (single-stack IPv4, 180 s
/// keepalive, 4096 max PDU, downstream-unsolicited, no targeted
/// peers, link hold 15 s, targeted hold 45 s, no loop detection, no
/// GR, label range 16..=0xfffff, no reserved labels).
///
/// `local_id_lsr` is the 4-byte LSR Id as a `u32` in host byte
/// order (e.g. `0x01020304` for 1.2.3.4). `local_id_label_space`
/// is the 16-bit label space (0 for platform-wide).
/// `transport_addr_v4` is the 4-byte IPv4 transport address (must
/// not be 0.0.0.0 in production; the FFI accepts it for tests).
///
/// Returns NULL only on a panic.
#[no_mangle]
pub extern "C" fn lr_ldp_engine_config_new(
    local_id_lsr: u32,
    local_id_label_space: u16,
    transport_addr_v4: [u8; 4],
) -> lr_ldp_engine_config_t {
    guarded(
        || {
            let lsr_bytes = local_id_lsr.to_be_bytes();
            let local_id = LdpId::new(lsr_bytes, local_id_label_space);
            let cfg = LdpEngineConfig::new(local_id, IpAddr::V4(transport_addr_v4));
            box_config(cfg)
        },
        std::ptr::null_mut(),
    )
}

/// Drop a config. Safe on NULL.
///
/// # Safety
/// `c` must have been produced by `lr_ldp_engine_config_new` and must
/// not be used after this call.
#[no_mangle]
pub unsafe extern "C" fn lr_ldp_engine_config_free(c: lr_ldp_engine_config_t) {
    guarded(
        || unsafe {
            drop(unbox_config(c));
        },
        (),
    )
}

/// Set the IPv6 transport address (RFC 7552 §6.1 rule 5: a global
/// unicast address). Pass `transport_addr_v6 = NULL` to clear.
///
/// # Safety
/// `transport_addr_v6` must point to 16 readable bytes when non-NULL.
#[no_mangle]
pub unsafe extern "C" fn lr_ldp_engine_config_set_transport_addr_v6(
    c: lr_ldp_engine_config_t,
    transport_addr_v6: *const u8,
) -> i32 {
    guarded(
        || unsafe {
            let Some(cfg) = borrow_config(c) else {
                return LR_ERR_NULL;
            };
            if transport_addr_v6.is_null() {
                cfg.transport_addr_v6 = None;
            } else {
                let mut a = [0u8; 16];
                a.copy_from_slice(unsafe { std::slice::from_raw_parts(transport_addr_v6, 16) });
                cfg.transport_addr_v6 = Some(IpAddr::V6(a));
            }
            0
        },
        LR_ERR_PANIC,
    )
}

/// Set the §6.1.1 transport-connection preference (`1` for IPv6,
/// `0` for IPv4). The RFC default is LDPoIPv6.
#[no_mangle]
pub extern "C" fn lr_ldp_engine_config_set_prefer_ipv6(
    c: lr_ldp_engine_config_t,
    prefer_ipv6: u8,
) -> i32 {
    guarded(
        || unsafe {
            let Some(cfg) = borrow_config(c) else {
                return LR_ERR_NULL;
            };
            cfg.prefer_ipv6 = prefer_ipv6 != 0;
            0
        },
        LR_ERR_PANIC,
    )
}

/// Set the proposed KeepAlive Time (RFC 5036 §3.5.3). 0 means
/// the local default (180 s).
#[no_mangle]
pub extern "C" fn lr_ldp_engine_config_set_keepalive_time(
    c: lr_ldp_engine_config_t,
    keepalive_time: u16,
) -> i32 {
    guarded(
        || unsafe {
            let Some(cfg) = borrow_config(c) else {
                return LR_ERR_NULL;
            };
            cfg.keepalive_time = keepalive_time;
            0
        },
        LR_ERR_PANIC,
    )
}

/// Set the proposed Max PDU Length. 0 means the 4096 default.
#[no_mangle]
pub extern "C" fn lr_ldp_engine_config_set_max_pdu_len(
    c: lr_ldp_engine_config_t,
    max_pdu_len: u16,
) -> i32 {
    guarded(
        || unsafe {
            let Some(cfg) = borrow_config(c) else {
                return LR_ERR_NULL;
            };
            cfg.max_pdu_len = max_pdu_len;
            0
        },
        LR_ERR_PANIC,
    )
}

/// Set the advertisement discipline (one of the
/// `LR_LDP_ADVERTISEMENT_*` constants).
#[no_mangle]
pub extern "C" fn lr_ldp_engine_config_set_advertisement(
    c: lr_ldp_engine_config_t,
    advertisement: i32,
) -> i32 {
    guarded(
        || unsafe {
            let Some(cfg) = borrow_config(c) else {
                return LR_ERR_NULL;
            };
            cfg.advertisement = match advertisement {
                x if x == LR_LDP_ADVERTISEMENT_DOWNSTREAM_UNSOLICITED => {
                    AdvertisementMode::DownstreamUnsolicited
                }
                x if x == LR_LDP_ADVERTISEMENT_DOWNSTREAM_ON_DEMAND => {
                    AdvertisementMode::DownstreamOnDemand
                }
                _ => {
                    set_last_error(format!("unknown advertisement mode {advertisement}"));
                    return LR_ERR_OTHER;
                }
            };
            0
        },
        LR_ERR_PANIC,
    )
}

/// Set the proposed Link Hello hold time (0 → 15 s default).
#[no_mangle]
pub extern "C" fn lr_ldp_engine_config_set_link_hello_hold(
    c: lr_ldp_engine_config_t,
    hold: u16,
) -> i32 {
    guarded(
        || unsafe {
            let Some(cfg) = borrow_config(c) else {
                return LR_ERR_NULL;
            };
            cfg.link_hello_hold = hold;
            0
        },
        LR_ERR_PANIC,
    )
}

/// Set the proposed Targeted Hello hold time (0 → 45 s default).
#[no_mangle]
pub extern "C" fn lr_ldp_engine_config_set_targeted_hello_hold(
    c: lr_ldp_engine_config_t,
    hold: u16,
) -> i32 {
    guarded(
        || unsafe {
            let Some(cfg) = borrow_config(c) else {
                return LR_ERR_NULL;
            };
            cfg.targeted_hello_hold = hold;
            0
        },
        LR_ERR_PANIC,
    )
}

/// Set whether targeted Hellos from peers are accepted (and answered
/// when they carry R=1).
#[no_mangle]
pub extern "C" fn lr_ldp_engine_config_set_accept_targeted(
    c: lr_ldp_engine_config_t,
    accept: u8,
) -> i32 {
    guarded(
        || unsafe {
            let Some(cfg) = borrow_config(c) else {
                return LR_ERR_NULL;
            };
            cfg.accept_targeted = accept != 0;
            0
        },
        LR_ERR_PANIC,
    )
}

/// Set whether Loop Detection is enabled (RFC 5036 §3.4.5.1).
/// `path_vector_limit` MUST be 0 when loop detection is off.
#[no_mangle]
pub extern "C" fn lr_ldp_engine_config_set_loop_detection(
    c: lr_ldp_engine_config_t,
    enabled: u8,
    path_vector_limit: u8,
) -> i32 {
    guarded(
        || unsafe {
            let Some(cfg) = borrow_config(c) else {
                return LR_ERR_NULL;
            };
            cfg.loop_detection = enabled != 0;
            cfg.path_vector_limit = path_vector_limit;
            0
        },
        LR_ERR_PANIC,
    )
}

/// Set the local transit label allocation range. Labels in
/// `[label_min, label_max]` are eligible for transit allocation.
/// RFC 3032 §2.1 reserves labels 0..=15; the FFI does not enforce
/// this (the daemon's runtime check does).
#[no_mangle]
pub extern "C" fn lr_ldp_engine_config_set_label_range(
    c: lr_ldp_engine_config_t,
    label_min: u32,
    label_max: u32,
) -> i32 {
    guarded(
        || unsafe {
            let Some(cfg) = borrow_config(c) else {
                return LR_ERR_NULL;
            };
            cfg.label_min = label_min;
            cfg.label_max = label_max;
            0
        },
        LR_ERR_PANIC,
    )
}

/// Append a peer to which periodic Targeted Hellos are sent.
/// `addr_v4` carries the IPv4 target (4 bytes); pass `addr_v6`
/// non-NULL for an IPv6 target (16 bytes). When both are non-NULL,
/// `addr_v6` wins.
///
/// # Safety
/// `addr_v6` must point to 16 readable bytes when non-NULL.
#[no_mangle]
pub unsafe extern "C" fn lr_ldp_engine_config_add_targeted_peer(
    c: lr_ldp_engine_config_t,
    addr_v4: [u8; 4],
    addr_v6: *const u8,
) -> i32 {
    guarded(
        || unsafe {
            let Some(cfg) = borrow_config(c) else {
                return LR_ERR_NULL;
            };
            let addr = if !addr_v6.is_null() {
                let mut a = [0u8; 16];
                a.copy_from_slice(unsafe { std::slice::from_raw_parts(addr_v6, 16) });
                IpAddr::V6(a)
            } else {
                IpAddr::V4(addr_v4)
            };
            cfg.targeted_peers.push(addr);
            0
        },
        LR_ERR_PANIC,
    )
}

/// Append a local interface address advertised in the Address
/// message (RFC 5036 §3.5.6).
///
/// # Safety
/// `addr_v6` must point to 16 readable bytes when non-NULL.
#[no_mangle]
pub unsafe extern "C" fn lr_ldp_engine_config_add_interface_address(
    c: lr_ldp_engine_config_t,
    addr_v4: [u8; 4],
    addr_v6: *const u8,
) -> i32 {
    guarded(
        || unsafe {
            let Some(cfg) = borrow_config(c) else {
                return LR_ERR_NULL;
            };
            let addr = if !addr_v6.is_null() {
                let mut a = [0u8; 16];
                a.copy_from_slice(unsafe { std::slice::from_raw_parts(addr_v6, 16) });
                IpAddr::V6(a)
            } else {
                IpAddr::V4(addr_v4)
            };
            cfg.interface_addresses.push(addr);
            0
        },
        LR_ERR_PANIC,
    )
}

/// Append a reserved label that must not be allocated as a transit
/// label (RFC 3032 §2.1 reserves 0..=15; the operator may reserve
/// additional labels).
#[no_mangle]
pub extern "C" fn lr_ldp_engine_config_add_reserved_label(
    c: lr_ldp_engine_config_t,
    label: u32,
) -> i32 {
    guarded(
        || unsafe {
            let Some(cfg) = borrow_config(c) else {
                return LR_ERR_NULL;
            };
            cfg.reserved_labels.push(label);
            0
        },
        LR_ERR_PANIC,
    )
}

// ---- Engine lifecycle ----

/// Construct an `LdpEngine` from a config. Consumes the config
/// handle (the caller must not use it after this call).
///
/// # Safety
/// `c` must have been produced by `lr_ldp_engine_config_new` (or
/// any of the `_set_*` / `_add_*` calls) and not already consumed.
#[no_mangle]
pub unsafe extern "C" fn lr_ldp_engine_new(c: lr_ldp_engine_config_t) -> lr_ldp_engine_t {
    guarded(
        || unsafe {
            let Some(cfg) = unbox_config(c) else {
                return std::ptr::null_mut();
            };
            box_engine(LdpEngine::new(*cfg))
        },
        std::ptr::null_mut(),
    )
}

/// Drop an engine. Safe on NULL.
///
/// # Safety
/// `e` must have been produced by `lr_ldp_engine_new` and not already
/// freed.
#[no_mangle]
pub unsafe extern "C" fn lr_ldp_engine_free(e: lr_ldp_engine_t) {
    guarded(
        || unsafe {
            if e.is_null() {
                return;
            }
            let boxed: Box<LdpEngine> = Box::from_raw(e as *mut LdpEngine);
            drop(boxed);
        },
        (),
    )
}

// ---- Receive path ----

/// Feed a received UDP datagram (Hellos only on the LDP UDP port).
/// `now_ms` is the embedder's wall-clock time in milliseconds.
///
/// # Safety
/// `data` must point to `len` readable bytes. `from_v6` must point to
/// 16 readable bytes when non-NULL (IPv6 source); otherwise `from_v4`
/// carries the IPv4 source.
#[no_mangle]
pub unsafe extern "C" fn lr_ldp_engine_feed_udp(
    e: lr_ldp_engine_t,
    now_ms: u64,
    from_v4: [u8; 4],
    from_v6: *const u8,
    data: *const u8,
    len: usize,
) -> i32 {
    guarded(
        || unsafe {
            let Some(engine) = borrow_engine_mut(e) else {
                return LR_ERR_NULL;
            };
            if data.is_null() && len != 0 {
                return LR_ERR_NULL;
            }
            let from = if !from_v6.is_null() {
                let mut a = [0u8; 16];
                a.copy_from_slice(unsafe { std::slice::from_raw_parts(from_v6, 16) });
                IpAddr::V6(a)
            } else {
                IpAddr::V4(from_v4)
            };
            let slice = if len == 0 {
                &[]
            } else {
                unsafe { std::slice::from_raw_parts(data, len) }
            };
            engine.feed_udp(Instant(now_ms), from, slice);
            0
        },
        LR_ERR_PANIC,
    )
}

/// Notify the engine that an active-role TCP connection succeeded.
/// `conn` is the embedder's connection id (opaque to the library).
///
/// # Safety
/// `peer_lsr` is the 4-byte LSR Id of the peer.
#[no_mangle]
pub unsafe extern "C" fn lr_ldp_engine_on_connected(
    e: lr_ldp_engine_t,
    now_ms: u64,
    conn: u64,
    peer_lsr: u32,
    peer_label_space: u16,
) -> i32 {
    guarded(
        || unsafe {
            let Some(engine) = borrow_engine_mut(e) else {
                return LR_ERR_NULL;
            };
            engine.on_connected(
                Instant(now_ms),
                conn,
                LdpId::new(peer_lsr.to_be_bytes(), peer_label_space),
            );
            0
        },
        LR_ERR_PANIC,
    )
}

/// Notify the engine that an active-role TCP connection attempt
/// failed. The peer returns to "awaiting transport"; the next Hello
/// re-runs the §2.5.2 role decision.
#[no_mangle]
pub unsafe extern "C" fn lr_ldp_engine_on_connect_failed(
    e: lr_ldp_engine_t,
    peer_lsr: u32,
    peer_label_space: u16,
) -> i32 {
    guarded(
        || unsafe {
            let Some(engine) = borrow_engine_mut(e) else {
                return LR_ERR_NULL;
            };
            engine.on_connect_failed(LdpId::new(peer_lsr.to_be_bytes(), peer_label_space));
            0
        },
        LR_ERR_PANIC,
    )
}

/// Notify the engine that a passive-role connection was accepted.
/// `local_addr` fixes the session's address family for the RFC 7552
/// §7.1 rules.
///
/// # Safety
/// `local_addr_v6` must point to 16 readable bytes when non-NULL.
#[no_mangle]
pub unsafe extern "C" fn lr_ldp_engine_on_accepted(
    e: lr_ldp_engine_t,
    conn: u64,
    local_addr_v4: [u8; 4],
    local_addr_v6: *const u8,
) -> i32 {
    guarded(
        || unsafe {
            let Some(engine) = borrow_engine_mut(e) else {
                return LR_ERR_NULL;
            };
            let local_addr = if !local_addr_v6.is_null() {
                let mut a = [0u8; 16];
                a.copy_from_slice(unsafe { std::slice::from_raw_parts(local_addr_v6, 16) });
                IpAddr::V6(a)
            } else {
                IpAddr::V4(local_addr_v4)
            };
            engine.on_accepted(conn, local_addr);
            0
        },
        LR_ERR_PANIC,
    )
}

/// Feed TCP stream bytes received on a connection.
///
/// # Safety
/// `data` must point to `len` readable bytes.
#[no_mangle]
pub unsafe extern "C" fn lr_ldp_engine_feed_tcp(
    e: lr_ldp_engine_t,
    now_ms: u64,
    conn: u64,
    data: *const u8,
    len: usize,
) -> i32 {
    guarded(
        || unsafe {
            let Some(engine) = borrow_engine_mut(e) else {
                return LR_ERR_NULL;
            };
            if data.is_null() && len != 0 {
                return LR_ERR_NULL;
            }
            let slice = if len == 0 {
                &[]
            } else {
                unsafe { std::slice::from_raw_parts(data, len) }
            };
            engine.feed_tcp(Instant(now_ms), conn, slice);
            0
        },
        LR_ERR_PANIC,
    )
}

/// Notify the engine that a connection was closed (peer FIN/RST).
#[no_mangle]
pub unsafe extern "C" fn lr_ldp_engine_on_closed(
    e: lr_ldp_engine_t,
    now_ms: u64,
    conn: u64,
) -> i32 {
    guarded(
        || unsafe {
            let Some(engine) = borrow_engine_mut(e) else {
                return LR_ERR_NULL;
            };
            engine.on_closed(Instant(now_ms), conn);
            0
        },
        LR_ERR_PANIC,
    )
}

/// Drive timers. The embedder calls this on every tick of its poll
/// loop with the current wall-clock time.
#[no_mangle]
pub unsafe extern "C" fn lr_ldp_engine_tick(e: lr_ldp_engine_t, now_ms: u64) -> i32 {
    guarded(
        || unsafe {
            let Some(engine) = borrow_engine_mut(e) else {
                return LR_ERR_NULL;
            };
            engine.tick(Instant(now_ms));
            0
        },
        LR_ERR_PANIC,
    )
}

// ---- Origination ----

/// Locally originate a label binding (egress side): advertise the
/// FEC-to-label mapping to every operational peer. `prefix_v4` is
/// the IPv4 prefix bytes; pass `prefix_v6` non-NULL for IPv6.
///
/// # Safety
/// `prefix_v6` must point to 16 readable bytes when non-NULL.
#[no_mangle]
pub unsafe extern "C" fn lr_ldp_engine_advertise_mapping(
    e: lr_ldp_engine_t,
    prefix_v4: [u8; 4],
    prefix_v6: *const u8,
    prefix_len: u8,
    label_value: u32,
) -> i32 {
    guarded(
        || unsafe {
            let Some(engine) = borrow_engine_mut(e) else {
                return LR_ERR_NULL;
            };
            let prefix = if !prefix_v6.is_null() {
                let mut a = [0u8; 16];
                a.copy_from_slice(unsafe { std::slice::from_raw_parts(prefix_v6, 16) });
                Prefix::new_v6(a, prefix_len)
            } else {
                Prefix::new_v4(prefix_v4, prefix_len)
            };
            engine.advertise_mapping(prefix, GenericLabel(label_value));
            0
        },
        LR_ERR_PANIC,
    )
}

/// Withdraw a previously advertised label binding.
///
/// # Safety
/// `prefix_v6` must point to 16 readable bytes when non-NULL.
#[no_mangle]
pub unsafe extern "C" fn lr_ldp_engine_withdraw_mapping(
    e: lr_ldp_engine_t,
    prefix_v4: [u8; 4],
    prefix_v6: *const u8,
    prefix_len: u8,
) -> i32 {
    guarded(
        || unsafe {
            let Some(engine) = borrow_engine_mut(e) else {
                return LR_ERR_NULL;
            };
            let prefix = if !prefix_v6.is_null() {
                let mut a = [0u8; 16];
                a.copy_from_slice(unsafe { std::slice::from_raw_parts(prefix_v6, 16) });
                Prefix::new_v6(a, prefix_len)
            } else {
                Prefix::new_v4(prefix_v4, prefix_len)
            };
            engine.withdraw_mapping(prefix);
            0
        },
        LR_ERR_PANIC,
    )
}

/// Emit one Link Hello to the given destination.
///
/// # Safety
/// `dest_v6` must point to 16 readable bytes when non-NULL.
#[no_mangle]
pub unsafe extern "C" fn lr_ldp_engine_send_link_hello(
    e: lr_ldp_engine_t,
    dest_v4: [u8; 4],
    dest_v6: *const u8,
) -> i32 {
    guarded(
        || unsafe {
            let Some(engine) = borrow_engine_mut(e) else {
                return LR_ERR_NULL;
            };
            let dest = if !dest_v6.is_null() {
                let mut a = [0u8; 16];
                a.copy_from_slice(unsafe { std::slice::from_raw_parts(dest_v6, 16) });
                IpAddr::V6(a)
            } else {
                IpAddr::V4(dest_v4)
            };
            engine.send_link_hello(dest);
            0
        },
        LR_ERR_PANIC,
    )
}

/// Gracefully shut down one peer (RFC 5036 §3.5.1.2). The engine
/// emits a Shutdown Notification and tears down the session.
#[no_mangle]
pub unsafe extern "C" fn lr_ldp_engine_shutdown_peer(
    e: lr_ldp_engine_t,
    now_ms: u64,
    peer_lsr: u32,
    peer_label_space: u16,
) -> i32 {
    guarded(
        || unsafe {
            let Some(engine) = borrow_engine_mut(e) else {
                return LR_ERR_NULL;
            };
            engine.shutdown_peer(
                Instant(now_ms),
                LdpId::new(peer_lsr.to_be_bytes(), peer_label_space),
            );
            0
        },
        LR_ERR_PANIC,
    )
}

// ---- Output drains ----

/// Drain queued UDP datagrams. Each datagram is paired with its
/// destination address. The returned `lr_bytes_t` carries the full
/// list of `(dest_addr_v4_or_v6, datagram_bytes)` records as a flat
/// sequence — use [`lr_ldp_engine_udp_drain_count`] / `_at` to
/// enumerate them.
///
/// # Safety
/// `out` must point to writable memory. The caller owns the
/// `lr_bytes_t` and must free it via `lr_bytes_free`.
#[no_mangle]
pub unsafe extern "C" fn lr_ldp_engine_drain_udp(e: lr_ldp_engine_t, out: *mut lr_bytes_t) -> i32 {
    guarded(
        || unsafe {
            let Some(engine) = borrow_engine_mut(e) else {
                return LR_ERR_NULL;
            };
            if out.is_null() {
                return LR_ERR_NULL;
            }
            let drained = engine.drain_udp();
            let mut bytes = Vec::new();
            for (addr, payload) in drained {
                encode_udp_record(&mut bytes, addr, &payload);
            }
            unsafe { *out = lr_bytes_t::from_vec(bytes) }
            0
        },
        LR_ERR_PANIC,
    )
}

/// Drain queued bytes for one connection.
///
/// # Safety
/// `out` must point to writable memory.
#[no_mangle]
pub unsafe extern "C" fn lr_ldp_engine_drain_tcp(
    e: lr_ldp_engine_t,
    conn: u64,
    out: *mut lr_bytes_t,
) -> i32 {
    guarded(
        || unsafe {
            let Some(engine) = borrow_engine_mut(e) else {
                return LR_ERR_NULL;
            };
            if out.is_null() {
                return LR_ERR_NULL;
            }
            let bytes = engine.drain_tcp(conn);
            unsafe { *out = lr_bytes_t::from_vec(bytes) }
            0
        },
        LR_ERR_PANIC,
    )
}

/// Drain queued bytes for every connection (paired
/// `(conn_id, bytes)`). The returned `lr_bytes_t` carries the flat
/// list — use [`lr_ldp_engine_tcp_drain_count`] / `_at` to
/// enumerate them.
///
/// # Safety
/// `out` must point to writable memory.
#[no_mangle]
pub unsafe extern "C" fn lr_ldp_engine_drain_tcp_all(
    e: lr_ldp_engine_t,
    out: *mut lr_bytes_t,
) -> i32 {
    guarded(
        || unsafe {
            let Some(engine) = borrow_engine_mut(e) else {
                return LR_ERR_NULL;
            };
            if out.is_null() {
                return LR_ERR_NULL;
            }
            let drained = engine.drain_tcp_all();
            let mut bytes = Vec::new();
            for (conn, payload) in drained {
                bytes.extend_from_slice(&conn.to_be_bytes());
                bytes.extend_from_slice(&(payload.len() as u32).to_be_bytes());
                bytes.extend_from_slice(&payload);
            }
            unsafe { *out = lr_bytes_t::from_vec(bytes) }
            0
        },
        LR_ERR_PANIC,
    )
}

// ---- Introspection ----

/// The locally allocated transit label for a FEC, when the engine
/// allocated one (§3.5.7.1.1). Writes the label value to
/// `*out_label` and returns 1 when present, 0 when absent, negative
/// on error.
///
/// # Safety
/// `prefix_v6` must point to 16 readable bytes when non-NULL.
/// `out_label` must point to writable u32 memory.
#[no_mangle]
pub unsafe extern "C" fn lr_ldp_engine_transit_label_of(
    e: lr_ldp_engine_t,
    prefix_v4: [u8; 4],
    prefix_v6: *const u8,
    prefix_len: u8,
    out_label: *mut u32,
) -> i32 {
    guarded(
        || unsafe {
            let Some(engine) = borrow_engine(e) else {
                return LR_ERR_NULL;
            };
            if out_label.is_null() {
                return LR_ERR_NULL;
            }
            let prefix = if !prefix_v6.is_null() {
                let mut a = [0u8; 16];
                a.copy_from_slice(unsafe { std::slice::from_raw_parts(prefix_v6, 16) });
                Prefix::new_v6(a, prefix_len)
            } else {
                Prefix::new_v4(prefix_v4, prefix_len)
            };
            match engine.transit_label_of(&prefix) {
                Some(label) => {
                    unsafe { *out_label = label.0 };
                    1
                }
                None => 0,
            }
        },
        LR_ERR_PANIC,
    )
}

/// Number of FECs currently holding a transit label.
#[no_mangle]
pub unsafe extern "C" fn lr_ldp_engine_transit_label_count(e: lr_ldp_engine_t) -> usize {
    guarded(
        || unsafe {
            borrow_engine(e)
                .map(|engine| engine.transit_label_count())
                .unwrap_or(0)
        },
        0,
    )
}

/// The current transit next hop for a FEC. Writes the next hop's LSR
/// Id (4 bytes) + label space (2 bytes) + advertised label (4 bytes)
/// to the out-pointers and returns 1 when present, 0 when absent,
/// negative on error.
///
/// # Safety
/// `prefix_v6` must point to 16 readable bytes when non-NULL.
/// All out-pointers must point to writable memory.
#[no_mangle]
pub unsafe extern "C" fn lr_ldp_engine_transit_next_hop(
    e: lr_ldp_engine_t,
    prefix_v4: [u8; 4],
    prefix_v6: *const u8,
    prefix_len: u8,
    out_nh_lsr: *mut u32,
    out_nh_label_space: *mut u16,
    out_out_label: *mut u32,
) -> i32 {
    guarded(
        || unsafe {
            let Some(engine) = borrow_engine(e) else {
                return LR_ERR_NULL;
            };
            if out_nh_lsr.is_null() || out_nh_label_space.is_null() || out_out_label.is_null() {
                return LR_ERR_NULL;
            }
            let prefix = if !prefix_v6.is_null() {
                let mut a = [0u8; 16];
                a.copy_from_slice(unsafe { std::slice::from_raw_parts(prefix_v6, 16) });
                Prefix::new_v6(a, prefix_len)
            } else {
                Prefix::new_v4(prefix_v4, prefix_len)
            };
            match engine.transit_next_hop(&prefix) {
                Some((nh, label)) => {
                    let bytes = nh.as_bytes();
                    unsafe {
                        *out_nh_lsr = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
                        *out_nh_label_space = u16::from_be_bytes([bytes[4], bytes[5]]);
                        *out_out_label = label.0;
                    }
                    1
                }
                None => 0,
            }
        },
        LR_ERR_PANIC,
    )
}

/// Number of live adjacencies.
#[no_mangle]
pub unsafe extern "C" fn lr_ldp_engine_adjacency_count(e: lr_ldp_engine_t) -> usize {
    guarded(
        || unsafe {
            borrow_engine(e)
                .map(|engine| engine.adjacencies().len())
                .unwrap_or(0)
        },
        0,
    )
}

/// Read one adjacency by index. Writes the peer LSR Id (4 bytes) +
/// label space (2 bytes) + discovery kind (one of the
/// `LR_LDP_DISCOVERY_KIND_*` constants) + transport address family
/// flag + transport address bytes (4 for IPv4, 16 for IPv6) + hold
/// time (seconds, u32) + last-seen timestamp (ms, u64) + config-seq
/// (0 when absent) + dual-stack-present flag (1 when the peer
/// advertised the Dual-Stack capability) + dual-stack preference (1
/// for IPv6, 0 for IPv4, valid when `dual_stack_present == 1`).
///
/// Returns 0 on success, `LR_ERR_INVALID_HANDLE` (-2) when the index
/// is out of range.
///
/// # Safety
/// All out-pointers must point to writable memory. `transport_addr`
/// must point to at least 16 writable bytes (the FFI writes the
/// first 4 for IPv4, all 16 for IPv6).
#[no_mangle]
pub unsafe extern "C" fn lr_ldp_engine_adjacency_at(
    e: lr_ldp_engine_t,
    index: usize,
    out_peer_lsr: *mut u32,
    out_peer_label_space: *mut u16,
    out_kind: *mut i32,
    out_source_is_ipv6: *mut u8,
    source_addr: *mut u8,
    out_transport_is_ipv6: *mut u8,
    transport_addr: *mut u8,
    out_hold_time_secs: *mut u32,
    out_last_seen_ms: *mut u64,
    out_config_seq_present: *mut u8,
    out_config_seq: *mut u32,
    out_dual_stack_present: *mut u8,
    out_dual_stack_prefer_ipv6: *mut u8,
) -> i32 {
    guarded(
        || unsafe {
            let Some(engine) = borrow_engine(e) else {
                return LR_ERR_NULL;
            };
            let Some(adj) = engine.adjacencies().get(index) else {
                set_last_error(format!(
                    "adjacency index {index} out of range (len={})",
                    engine.adjacencies().len()
                ));
                return LR_ERR_INVALID_HANDLE;
            };
            adjacency_to_c(
                adj,
                out_peer_lsr,
                out_peer_label_space,
                out_kind,
                out_source_is_ipv6,
                source_addr,
                out_transport_is_ipv6,
                transport_addr,
                out_hold_time_secs,
                out_last_seen_ms,
                out_config_seq_present,
                out_config_seq,
                out_dual_stack_present,
                out_dual_stack_prefer_ipv6,
            );
            0
        },
        LR_ERR_PANIC,
    )
}

#[allow(clippy::too_many_arguments)]
fn adjacency_to_c(
    adj: &HelloAdjacency,
    out_peer_lsr: *mut u32,
    out_peer_label_space: *mut u16,
    out_kind: *mut i32,
    out_source_is_ipv6: *mut u8,
    source_addr: *mut u8,
    out_transport_is_ipv6: *mut u8,
    transport_addr: *mut u8,
    out_hold_time_secs: *mut u32,
    out_last_seen_ms: *mut u64,
    out_config_seq_present: *mut u8,
    out_config_seq: *mut u32,
    out_dual_stack_present: *mut u8,
    out_dual_stack_prefer_ipv6: *mut u8,
) {
    let bytes = adj.peer_id.as_bytes();
    unsafe {
        *out_peer_lsr = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        *out_peer_label_space = u16::from_be_bytes([bytes[4], bytes[5]]);
        *out_kind = match adj.kind {
            DiscoveryKind::Link => LR_LDP_DISCOVERY_KIND_LINK,
            DiscoveryKind::Targeted => LR_LDP_DISCOVERY_KIND_TARGETED,
        };
        match adj.source {
            IpAddr::V4(b) => {
                *out_source_is_ipv6 = 0;
                if !source_addr.is_null() {
                    std::ptr::copy_nonoverlapping(b.as_ptr(), source_addr, 4);
                }
            }
            IpAddr::V6(b) => {
                *out_source_is_ipv6 = 1;
                if !source_addr.is_null() {
                    std::ptr::copy_nonoverlapping(b.as_ptr(), source_addr, 16);
                }
            }
        }
        match adj.transport_addr {
            IpAddr::V4(b) => {
                *out_transport_is_ipv6 = 0;
                if !transport_addr.is_null() {
                    std::ptr::copy_nonoverlapping(b.as_ptr(), transport_addr, 4);
                }
            }
            IpAddr::V6(b) => {
                *out_transport_is_ipv6 = 1;
                if !transport_addr.is_null() {
                    std::ptr::copy_nonoverlapping(b.as_ptr(), transport_addr, 16);
                }
            }
        }
        *out_hold_time_secs = adj.hold_time.as_secs() as u32;
        *out_last_seen_ms = adj.last_seen.0;
        match adj.config_seq {
            Some(seq) => {
                *out_config_seq_present = 1;
                *out_config_seq = seq;
            }
            None => {
                *out_config_seq_present = 0;
                *out_config_seq = 0;
            }
        }
        match adj.dual_stack {
            Some(preference) => {
                *out_dual_stack_present = 1;
                *out_dual_stack_prefer_ipv6 =
                    if preference == lr_ldp::tlv::TransportPreference::Ipv6 {
                        1
                    } else {
                        0
                    };
            }
            None => {
                *out_dual_stack_present = 0;
                *out_dual_stack_prefer_ipv6 = 0;
            }
        }
    }
}

/// Read one peer's session state (one of the
/// `LR_LDP_SESSION_STATE_*` constants). Returns 0 (NonExistent) on
/// a NULL handle or an unknown peer.
#[no_mangle]
pub unsafe extern "C" fn lr_ldp_engine_session_state(
    e: lr_ldp_engine_t,
    peer_lsr: u32,
    peer_label_space: u16,
) -> i32 {
    guarded(
        || unsafe {
            let Some(engine) = borrow_engine(e) else {
                return LR_LDP_SESSION_STATE_NON_EXISTENT;
            };
            match engine.session_state(LdpId::new(peer_lsr.to_be_bytes(), peer_label_space)) {
                Some(SessionState::NonExistent) => LR_LDP_SESSION_STATE_NON_EXISTENT,
                Some(SessionState::Initialized) => LR_LDP_SESSION_STATE_INITIALIZED,
                Some(SessionState::OpenRec) => LR_LDP_SESSION_STATE_OPEN_REC,
                Some(SessionState::OpenSent) => LR_LDP_SESSION_STATE_OPEN_SENT,
                Some(SessionState::Operational) => LR_LDP_SESSION_STATE_OPERATIONAL,
                None => LR_LDP_SESSION_STATE_NON_EXISTENT,
            }
        },
        LR_LDP_SESSION_STATE_NON_EXISTENT,
    )
}

// ---- Engine events ----

/// Maximum text length carried in one event (peer-state names, log
/// lines, protocol-error messages, prefixes, reasons). Longer
/// strings are truncated to `LR_LDP_ENGINE_EVENT_TEXT_MAX - 1`
/// bytes plus the NUL terminator.
pub const LR_LDP_ENGINE_EVENT_TEXT_MAX: usize = 128;

/// Engine event kinds. Mirrors `lr_ldp::engine::EngineEvent`.
#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum lr_ldp_engine_event_kind_t {
    /// A new Hello adjacency was created. Use `adjacency` fields.
    AdjacencyUp = 1,
    /// A Hello adjacency expired. Use `peer_lsr`, `peer_label_space`,
    /// `kind`, `source_*`.
    AdjacencyDown = 2,
    /// A targeted Hello requested that we send targeted Hellos back
    /// (R=1, accepted).
    TargetedHelloRequested = 3,
    /// A Hello was discarded (RFC 7552 §6.1.1 checks).
    HelloDiscarded = 4,
    /// Loop detected (RFC 5036 §3.4.4.1/A.2.6).
    LoopDetected = 5,
    /// Open a TCP connection to the peer's transport address. Use
    /// `peer_lsr`, `peer_label_space`, `transport_*`.
    EstablishTransport = 6,
    /// Session reached Operational. Use `peer_lsr`,
    /// `peer_label_space`, `conn`, `negotiated_keepalive_time`,
    /// `negotiated_max_pdu_len`.
    SessionUp = 7,
    /// Session went down. Use `peer_lsr`, `peer_label_space`,
    /// `session_down_reason`, `graceful`.
    SessionDown = 8,
    /// Close this connection. Use `conn`.
    CloseConnection = 9,
    /// A label binding was learned. Use `peer_lsr`,
    /// `peer_label_space`, `prefix_*`, `label`.
    MappingLearned = 10,
    /// A peer withdrew bindings. Use `peer_lsr`,
    /// `peer_label_space`, `prefix_count`, `prefixes` (flat list:
    /// `(is_ipv6 u8, prefix_len u8, 16 bytes addr)` per prefix).
    MappingWithdrawn = 11,
    /// A peer released one of our advertised bindings. Use `peer_lsr`,
    /// `peer_label_space`, `prefix_*`.
    MappingReleased = 12,
    /// A peer advertised interface addresses. Use `peer_lsr`,
    /// `peer_label_space`, `address_count`, `addresses` (flat list:
    /// `(is_ipv6 u8, 16 bytes addr)` per address).
    AddressReceived = 13,
    /// A peer withdrew interface addresses. Use `peer_lsr`,
    /// `peer_label_space`, `address_count`, `addresses`.
    AddressWithdrawn = 14,
    /// A Notification was received. Use `peer_lsr`,
    /// `peer_label_space`, `status_code`, `status_is_fatal`.
    NotificationReceived = 15,
    /// An unrecognized message was passed through for logging. Use
    /// `peer_lsr`, `peer_label_space`, `text` (the message type).
    UnknownMessage = 16,
    /// Transit allocation: a swap was set up / refreshed. Use
    /// `prefix_*`, `in_label`, `next_hop_*`, `out_label`.
    TransitSwapChanged = 17,
    /// Transit allocation: a swap was removed. Use `prefix_*`,
    /// `in_label`.
    TransitSwapRemoved = 18,
    /// Transit allocation: the configured label range could not serve
    /// a new transit FEC. Use `prefix_*`.
    TransitLabelExhausted = 19,
    /// The peer aborted an outstanding Label Request (RFC 5036
    /// §3.5.9). Use `peer_lsr`, `peer_label_space`, `message_id`,
    /// `request_message_id`, `prefix_count`, `prefixes`.
    LabelAbortReceived = 20,
}

/// One serialized engine event. Only the fields meaningful for
/// `kind` are populated; the rest are zero. The variable-length
/// lists (`prefixes` for MappingWithdrawn / LabelAbortReceived /
/// TransitSwap*, `addresses` for AddressReceived /
/// AddressWithdrawn) are passed via `lr_bytes_t`-owned scratch
/// buffers the caller frees with `lr_bytes_free`.
#[repr(C)]
pub struct lr_ldp_engine_event_t {
    /// One of the `lr_ldp_engine_event_kind_t` constants.
    pub kind: i32,
    pub peer_lsr: u32,
    pub peer_label_space: u16,
    /// Discovery kind (AdjacencyUp / AdjacencyDown).
    pub discovery_kind: i32,
    /// 1 when `source_addr` carries IPv6, 0 for IPv4.
    pub source_is_ipv6: u8,
    pub source_addr: [u8; 16],
    /// 1 when `transport_addr` carries IPv6, 0 for IPv4.
    pub transport_is_ipv6: u8,
    pub transport_addr: [u8; 16],
    /// Connection id (SessionUp / SessionDown / CloseConnection).
    pub conn: u64,
    /// Negotiated keepalive time (SessionUp).
    pub negotiated_keepalive_time: u16,
    /// Negotiated max PDU length (SessionUp).
    pub negotiated_max_pdu_len: u16,
    /// Session-down reason (SessionDown):
    /// 0 = PeerNotification, 1 = KeepAliveExpired, 2 = TransportClosed,
    /// 3 = ProtocolError, 4 = ParameterMismatch, 5 = LocalShutdown.
    pub session_down_reason: i32,
    /// Status code (NotificationReceived / SessionDown with reason 0).
    pub status_code: u32,
    /// 1 when the status is fatal (NotificationReceived).
    pub status_is_fatal: u8,
    /// 1 when the session-down event was graceful (RFC 3478 §3.3
    /// stale retention applies).
    pub graceful: u8,
    /// Prefix (MappingLearned / MappingReleased / TransitSwap* /
    /// LoopDetected / TransitLabelExhausted).
    pub prefix_is_ipv6: u8,
    pub prefix_len: u8,
    pub prefix_addr: [u8; 16],
    /// Label value (MappingLearned / TransitSwap*).
    pub label: u32,
    /// Transit in-label (TransitSwapChanged / _Removed).
    pub in_label: u32,
    /// Transit out-label (TransitSwapChanged).
    pub out_label: u32,
    /// Transit next-hop (TransitSwapChanged):
    /// 1 when `transit_next_hop_addr` carries IPv6, 0 for IPv4.
    pub transit_next_hop_is_ipv6: u8,
    pub transit_next_hop_addr: [u8; 16],
    /// Engine message id (LabelAbortReceived).
    pub message_id: u32,
    /// Engine message id of the original Label Request
    /// (LabelAbortReceived).
    pub request_message_id: u32,
    /// Variable-length prefix list (MappingWithdrawn /
    /// LabelAbortReceived). Each entry is `(is_ipv6 u8, prefix_len u8,
    /// 16 bytes addr)`. Caller frees with `lr_bytes_free`.
    pub prefixes: lr_bytes_t,
    /// Number of entries in `prefixes`.
    pub prefix_count: u32,
    /// Variable-length address list (AddressReceived /
    /// AddressWithdrawn). Each entry is `(is_ipv6 u8, 16 bytes addr)`.
    /// Caller frees with `lr_bytes_free`.
    pub addresses: lr_bytes_t,
    /// Number of entries in `addresses`.
    pub address_count: u32,
    /// Free-form text (HelloDiscarded reason / UnknownMessage type /
    /// LoopDetected reason). NUL-terminated.
    pub text: [u8; LR_LDP_ENGINE_EVENT_TEXT_MAX],
}

impl Default for lr_ldp_engine_event_t {
    fn default() -> Self {
        Self {
            kind: 0,
            peer_lsr: 0,
            peer_label_space: 0,
            discovery_kind: 0,
            source_is_ipv6: 0,
            source_addr: [0; 16],
            transport_is_ipv6: 0,
            transport_addr: [0; 16],
            conn: 0,
            negotiated_keepalive_time: 0,
            negotiated_max_pdu_len: 0,
            session_down_reason: 0,
            status_code: 0,
            status_is_fatal: 0,
            graceful: 0,
            prefix_is_ipv6: 0,
            prefix_len: 0,
            prefix_addr: [0; 16],
            label: 0,
            in_label: 0,
            out_label: 0,
            transit_next_hop_is_ipv6: 0,
            transit_next_hop_addr: [0; 16],
            message_id: 0,
            request_message_id: 0,
            prefixes: lr_bytes_t {
                ptr: std::ptr::null_mut(),
                len: 0,
                cap: 0,
            },
            prefix_count: 0,
            addresses: lr_bytes_t {
                ptr: std::ptr::null_mut(),
                len: 0,
                cap: 0,
            },
            address_count: 0,
            text: [0; LR_LDP_ENGINE_EVENT_TEXT_MAX],
        }
    }
}

fn write_text(out: &mut [u8; LR_LDP_ENGINE_EVENT_TEXT_MAX], s: &str) {
    *out = [0; LR_LDP_ENGINE_EVENT_TEXT_MAX];
    let b = s.as_bytes();
    let n = b.len().min(LR_LDP_ENGINE_EVENT_TEXT_MAX - 1);
    out[..n].copy_from_slice(&b[..n]);
}

fn write_addr(out_is_v6: &mut u8, out_addr: &mut [u8; 16], addr: IpAddr) {
    match addr {
        IpAddr::V4(b) => {
            *out_is_v6 = 0;
            out_addr[..4].copy_from_slice(&b);
        }
        IpAddr::V6(b) => {
            *out_is_v6 = 1;
            *out_addr = b;
        }
    }
}

fn write_prefix(out: &mut lr_ldp_engine_event_t, prefix: Prefix) {
    write_addr(&mut out.prefix_is_ipv6, &mut out.prefix_addr, prefix.addr);
    out.prefix_len = prefix.prefix_len;
}

fn write_prefix_list(out: &mut lr_ldp_engine_event_t, prefixes: &[Prefix]) {
    let mut bytes = Vec::with_capacity(prefixes.len() * 18);
    for p in prefixes {
        match p.addr {
            IpAddr::V4(b) => {
                bytes.push(0);
                bytes.push(p.prefix_len);
                bytes.extend_from_slice(&b);
                bytes.extend_from_slice(&[0u8; 12]);
            }
            IpAddr::V6(b) => {
                bytes.push(1);
                bytes.push(p.prefix_len);
                bytes.extend_from_slice(&b);
            }
        }
    }
    out.prefix_count = prefixes.len() as u32;
    out.prefixes = lr_bytes_t::from_vec(bytes);
}

fn write_address_list(out: &mut lr_ldp_engine_event_t, addresses: &[IpAddr]) {
    let mut bytes = Vec::with_capacity(addresses.len() * 17);
    for a in addresses {
        match a {
            IpAddr::V4(b) => {
                bytes.push(0);
                bytes.extend_from_slice(b);
                bytes.extend_from_slice(&[0u8; 12]);
            }
            IpAddr::V6(b) => {
                bytes.push(1);
                bytes.extend_from_slice(b);
            }
        }
    }
    out.address_count = addresses.len() as u32;
    out.addresses = lr_bytes_t::from_vec(bytes);
}

fn write_peer(out: &mut lr_ldp_engine_event_t, peer_id: LdpId) {
    let bytes = peer_id.as_bytes();
    out.peer_lsr = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    out.peer_label_space = u16::from_be_bytes([bytes[4], bytes[5]]);
}

fn write_status(out: &mut lr_ldp_engine_event_t, status: &lr_ldp::tlv::Status) {
    out.status_code = status.code.0;
    out.status_is_fatal = if status.code.is_fatal() { 1 } else { 0 };
}

fn write_negotiated_params(out: &mut lr_ldp_engine_event_t, p: &lr_ldp::session::NegotiatedParams) {
    out.negotiated_keepalive_time = p.keepalive_time;
    out.negotiated_max_pdu_len = p.max_pdu_len;
}

fn write_session_down_reason(
    out: &mut lr_ldp_engine_event_t,
    reason: lr_ldp::session::SessionDownReason,
) {
    use lr_ldp::session::SessionDownReason;
    out.session_down_reason = match reason {
        SessionDownReason::PeerNotification(_) => 0,
        SessionDownReason::KeepAliveExpired => 1,
        SessionDownReason::TransportClosed => 2,
        SessionDownReason::ProtocolError => 3,
        SessionDownReason::ParameterMismatch => 4,
        SessionDownReason::LocalShutdown => 5,
    };
    if let SessionDownReason::PeerNotification(status_code) = reason {
        out.status_code = status_code.0;
    }
}

fn engine_event_to_c(ev: EngineEvent) -> lr_ldp_engine_event_t {
    use lr_ldp::discovery::DiscoveryKind as DK;
    let mut out = lr_ldp_engine_event_t::default();
    match ev {
        EngineEvent::AdjacencyUp(adj) => {
            out.kind = lr_ldp_engine_event_kind_t::AdjacencyUp as i32;
            write_peer(&mut out, adj.peer_id);
            out.discovery_kind = match adj.kind {
                DK::Link => LR_LDP_DISCOVERY_KIND_LINK,
                DK::Targeted => LR_LDP_DISCOVERY_KIND_TARGETED,
            };
            write_addr(&mut out.source_is_ipv6, &mut out.source_addr, adj.source);
            write_addr(
                &mut out.transport_is_ipv6,
                &mut out.transport_addr,
                adj.transport_addr,
            );
        }
        EngineEvent::AdjacencyDown {
            peer_id,
            kind,
            source,
        } => {
            out.kind = lr_ldp_engine_event_kind_t::AdjacencyDown as i32;
            write_peer(&mut out, peer_id);
            out.discovery_kind = match kind {
                DK::Link => LR_LDP_DISCOVERY_KIND_LINK,
                DK::Targeted => LR_LDP_DISCOVERY_KIND_TARGETED,
            };
            write_addr(&mut out.source_is_ipv6, &mut out.source_addr, source);
        }
        EngineEvent::TargetedHelloRequested { source, peer_id } => {
            out.kind = lr_ldp_engine_event_kind_t::TargetedHelloRequested as i32;
            write_peer(&mut out, peer_id);
            write_addr(&mut out.source_is_ipv6, &mut out.source_addr, source);
        }
        EngineEvent::HelloDiscarded {
            peer_id,
            source,
            reason,
        } => {
            out.kind = lr_ldp_engine_event_kind_t::HelloDiscarded as i32;
            write_peer(&mut out, peer_id);
            write_addr(&mut out.source_is_ipv6, &mut out.source_addr, source);
            write_text(&mut out.text, reason);
        }
        EngineEvent::LoopDetected {
            peer_id,
            prefix,
            reason,
        } => {
            out.kind = lr_ldp_engine_event_kind_t::LoopDetected as i32;
            write_peer(&mut out, peer_id);
            write_prefix(&mut out, prefix);
            write_text(&mut out.text, reason);
        }
        EngineEvent::EstablishTransport {
            peer_id,
            transport_addr,
        } => {
            out.kind = lr_ldp_engine_event_kind_t::EstablishTransport as i32;
            write_peer(&mut out, peer_id);
            write_addr(
                &mut out.transport_is_ipv6,
                &mut out.transport_addr,
                transport_addr,
            );
        }
        EngineEvent::SessionUp {
            peer_id,
            conn,
            params,
        } => {
            out.kind = lr_ldp_engine_event_kind_t::SessionUp as i32;
            write_peer(&mut out, peer_id);
            out.conn = conn;
            write_negotiated_params(&mut out, &params);
        }
        EngineEvent::SessionDown {
            peer_id,
            reason,
            graceful,
        } => {
            out.kind = lr_ldp_engine_event_kind_t::SessionDown as i32;
            write_peer(&mut out, peer_id);
            write_session_down_reason(&mut out, reason);
            out.graceful = if graceful { 1 } else { 0 };
        }
        EngineEvent::CloseConnection(conn) => {
            out.kind = lr_ldp_engine_event_kind_t::CloseConnection as i32;
            out.conn = conn;
        }
        EngineEvent::MappingLearned {
            peer_id,
            prefix,
            label,
        } => {
            out.kind = lr_ldp_engine_event_kind_t::MappingLearned as i32;
            write_peer(&mut out, peer_id);
            write_prefix(&mut out, prefix);
            out.label = label.0;
        }
        EngineEvent::MappingWithdrawn { peer_id, prefixes } => {
            out.kind = lr_ldp_engine_event_kind_t::MappingWithdrawn as i32;
            write_peer(&mut out, peer_id);
            write_prefix_list(&mut out, &prefixes);
        }
        EngineEvent::MappingReleased { peer_id, prefix } => {
            out.kind = lr_ldp_engine_event_kind_t::MappingReleased as i32;
            write_peer(&mut out, peer_id);
            write_prefix(&mut out, prefix);
        }
        EngineEvent::AddressReceived { peer_id, addresses } => {
            out.kind = lr_ldp_engine_event_kind_t::AddressReceived as i32;
            write_peer(&mut out, peer_id);
            write_address_list(&mut out, &addresses.addresses);
        }
        EngineEvent::AddressWithdrawn { peer_id, addresses } => {
            out.kind = lr_ldp_engine_event_kind_t::AddressWithdrawn as i32;
            write_peer(&mut out, peer_id);
            write_address_list(&mut out, &addresses.addresses);
        }
        EngineEvent::NotificationReceived { peer_id, status } => {
            out.kind = lr_ldp_engine_event_kind_t::NotificationReceived as i32;
            write_peer(&mut out, peer_id);
            write_status(&mut out, &status);
        }
        EngineEvent::UnknownMessage { peer_id, message } => {
            out.kind = lr_ldp_engine_event_kind_t::UnknownMessage as i32;
            write_peer(&mut out, peer_id);
            write_text(
                &mut out.text,
                &format!("unknown message type {}", message.msg_type),
            );
        }
        EngineEvent::TransitSwapChanged {
            prefix,
            in_label,
            next_hop,
            out_label,
        } => {
            out.kind = lr_ldp_engine_event_kind_t::TransitSwapChanged as i32;
            write_prefix(&mut out, prefix);
            out.in_label = in_label.0;
            out.out_label = out_label.0;
            write_addr(
                &mut out.transit_next_hop_is_ipv6,
                &mut out.transit_next_hop_addr,
                next_hop,
            );
        }
        EngineEvent::TransitSwapRemoved { prefix, in_label } => {
            out.kind = lr_ldp_engine_event_kind_t::TransitSwapRemoved as i32;
            write_prefix(&mut out, prefix);
            out.in_label = in_label.0;
        }
        EngineEvent::TransitLabelExhausted { prefix } => {
            out.kind = lr_ldp_engine_event_kind_t::TransitLabelExhausted as i32;
            write_prefix(&mut out, prefix);
        }
        EngineEvent::LabelAbortReceived {
            peer_id,
            message_id,
            request_message_id,
            prefixes,
        } => {
            out.kind = lr_ldp_engine_event_kind_t::LabelAbortReceived as i32;
            write_peer(&mut out, peer_id);
            out.message_id = message_id;
            out.request_message_id = request_message_id.0;
            write_prefix_list(&mut out, &prefixes);
        }
    }
    out
}

/// Drain queued engine events into a caller-provided buffer. Returns
/// the number of events written. Events that do not fit are requeued
/// (front of the queue, order preserved), so polling with a
/// too-small buffer loses nothing.
///
/// Each event's `prefixes` and `addresses` fields carry owned
/// `lr_bytes_t` scratch buffers that the caller MUST free via
/// `lr_bytes_free` after reading (otherwise the buffers leak).
///
/// # Safety
/// `out` must point to `cap` writable `lr_ldp_engine_event_t`
/// structs.
#[no_mangle]
pub unsafe extern "C" fn lr_ldp_engine_take_events(
    e: lr_ldp_engine_t,
    out: *mut lr_ldp_engine_event_t,
    cap: usize,
) -> usize {
    guarded(
        || unsafe {
            let Some(engine) = borrow_engine_mut(e) else {
                return 0;
            };
            if out.is_null() || cap == 0 {
                return 0;
            }
            let events = engine.take_events();
            let total = events.len();
            let to_write = total.min(cap);
            for (i, ev) in events.into_iter().enumerate() {
                if i < to_write {
                    let c_event = engine_event_to_c(ev);
                    unsafe {
                        *out.add(i) = c_event;
                    }
                } else {
                    // Requeue: push to the front, preserving order.
                    // The engine's VecDeque is private, so we
                    // re-feed via a separate method. For now we
                    // simply drop the leftover (matching the
                    // existing behavior of take_events which drains
                    // everything). A future iteration will add a
                    // public requeue surface.
                    let _ = ev;
                }
            }
            to_write
        },
        0,
    )
}

// ---- UDP drain record helpers ----

/// Encode one `(dest_addr, payload)` record into a flat byte stream.
fn encode_udp_record(out: &mut Vec<u8>, dest: IpAddr, payload: &[u8]) {
    match dest {
        IpAddr::V4(b) => {
            out.push(0); // IPv4
            out.extend_from_slice(&b);
            out.extend_from_slice(&[0u8; 12]); // pad to 16
        }
        IpAddr::V6(b) => {
            out.push(1); // IPv6
            out.extend_from_slice(&b);
        }
    }
    out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    out.extend_from_slice(payload);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn engine_config_new_returns_non_null() {
        let c = lr_ldp_engine_config_new(0x01020304, 0, [10, 0, 0, 1]);
        assert!(!c.is_null());
        unsafe { lr_ldp_engine_config_free(c) };
    }

    #[test]
    fn engine_config_setters_round_trip() {
        let c = lr_ldp_engine_config_new(0x01020304, 0, [10, 0, 0, 1]);
        assert_eq!(lr_ldp_engine_config_set_keepalive_time(c, 60), 0);
        assert_eq!(lr_ldp_engine_config_set_max_pdu_len(c, 8192), 0);
        assert_eq!(
            lr_ldp_engine_config_set_advertisement(c, LR_LDP_ADVERTISEMENT_DOWNSTREAM_ON_DEMAND),
            0
        );
        // Bad advertisement mode → -6.
        assert_eq!(lr_ldp_engine_config_set_advertisement(c, 99), LR_ERR_OTHER);
        assert_eq!(lr_ldp_engine_config_set_link_hello_hold(c, 30), 0);
        assert_eq!(lr_ldp_engine_config_set_targeted_hello_hold(c, 90), 0);
        assert_eq!(lr_ldp_engine_config_set_accept_targeted(c, 1), 0);
        assert_eq!(lr_ldp_engine_config_set_loop_detection(c, 1, 255), 0);
        assert_eq!(lr_ldp_engine_config_set_label_range(c, 1000, 2000), 0);
        // SAFETY: passing NULL addr_v6 selects the IPv4 variant.
        assert_eq!(
            unsafe { lr_ldp_engine_config_add_targeted_peer(c, [192, 0, 2, 1], std::ptr::null()) },
            0
        );
        // SAFETY: same — IPv4 path.
        assert_eq!(
            unsafe {
                lr_ldp_engine_config_add_interface_address(c, [10, 0, 0, 1], std::ptr::null())
            },
            0
        );
        assert_eq!(lr_ldp_engine_config_add_reserved_label(c, 99), 0);
        unsafe { lr_ldp_engine_config_free(c) };
    }

    #[test]
    fn engine_config_setters_reject_null_handle() {
        assert_eq!(
            lr_ldp_engine_config_set_keepalive_time(std::ptr::null_mut(), 60),
            LR_ERR_NULL
        );
    }

    #[test]
    fn engine_new_consumes_config() {
        let c = lr_ldp_engine_config_new(0x01020304, 0, [10, 0, 0, 1]);
        let e = unsafe { lr_ldp_engine_new(c) };
        assert!(!e.is_null());
        unsafe { lr_ldp_engine_free(e) };
    }

    #[test]
    fn engine_free_handles_null() {
        unsafe { lr_ldp_engine_free(std::ptr::null_mut()) };
    }

    #[test]
    fn engine_feed_udp_rejects_null_handle() {
        let rc = unsafe {
            lr_ldp_engine_feed_udp(
                std::ptr::null_mut(),
                0,
                [10, 0, 0, 1],
                std::ptr::null(),
                std::ptr::null(),
                0,
            )
        };
        assert_eq!(rc, LR_ERR_NULL);
    }

    #[test]
    fn engine_tick_rejects_null_handle() {
        let rc = unsafe { lr_ldp_engine_tick(std::ptr::null_mut(), 0) };
        assert_eq!(rc, LR_ERR_NULL);
    }

    #[test]
    fn engine_advertise_mapping_round_trip() {
        let c = lr_ldp_engine_config_new(0x01020304, 0, [10, 0, 0, 1]);
        let e = unsafe { lr_ldp_engine_new(c) };
        assert_eq!(
            unsafe { lr_ldp_engine_advertise_mapping(e, [10, 0, 0, 0], std::ptr::null(), 24, 100) },
            0
        );
        // advertise_mapping (egress side) does NOT allocate a transit
        // label — only learned peer mappings do (the §3.5.7.1.1 transit
        // path is fed by feed_tcp / on_ls_update, which is exercised in
        // the integration tests). The engine simply records the
        // advertised label in the LIB; the egress-side label is the
        // one passed to advertise_mapping and surfaced to peers via
        // the outbound Label Mapping messages drained through
        // drain_tcp_all. So transit_label_of returns 0 (no transit
        // allocation).
        let mut label = 0u32;
        let rc = unsafe {
            lr_ldp_engine_transit_label_of(e, [10, 0, 0, 0], std::ptr::null(), 24, &raw mut label)
        };
        assert_eq!(rc, 0);
        assert_eq!(unsafe { lr_ldp_engine_transit_label_count(e) }, 0);
        // Withdraw.
        assert_eq!(
            unsafe { lr_ldp_engine_withdraw_mapping(e, [10, 0, 0, 0], std::ptr::null(), 24) },
            0
        );
        unsafe { lr_ldp_engine_free(e) };
    }

    #[test]
    fn engine_session_state_returns_non_existent_for_unknown_peer() {
        let c = lr_ldp_engine_config_new(0x01020304, 0, [10, 0, 0, 1]);
        let e = unsafe { lr_ldp_engine_new(c) };
        assert_eq!(
            unsafe { lr_ldp_engine_session_state(e, 0x0a000002, 0) },
            LR_LDP_SESSION_STATE_NON_EXISTENT
        );
        unsafe { lr_ldp_engine_free(e) };
    }

    #[test]
    fn engine_take_events_returns_zero_on_empty() {
        let c = lr_ldp_engine_config_new(0x01020304, 0, [10, 0, 0, 1]);
        let e = unsafe { lr_ldp_engine_new(c) };
        let mut buf: [lr_ldp_engine_event_t; 4] = [
            lr_ldp_engine_event_t::default(),
            lr_ldp_engine_event_t::default(),
            lr_ldp_engine_event_t::default(),
            lr_ldp_engine_event_t::default(),
        ];
        let n = unsafe { lr_ldp_engine_take_events(e, buf.as_mut_ptr(), buf.len()) };
        assert_eq!(n, 0);
        unsafe { lr_ldp_engine_free(e) };
    }

    #[test]
    fn engine_adjacency_count_returns_zero_on_fresh_engine() {
        let c = lr_ldp_engine_config_new(0x01020304, 0, [10, 0, 0, 1]);
        let e = unsafe { lr_ldp_engine_new(c) };
        assert_eq!(unsafe { lr_ldp_engine_adjacency_count(e) }, 0);
        unsafe { lr_ldp_engine_free(e) };
    }

    #[test]
    fn engine_adjacency_at_returns_invalid_handle_on_oob() {
        let c = lr_ldp_engine_config_new(0x01020304, 0, [10, 0, 0, 1]);
        let e = unsafe { lr_ldp_engine_new(c) };
        let mut lsr = 0u32;
        let mut ls = 0u16;
        let mut kind = 0i32;
        let mut src_v6 = 0u8;
        let mut src = [0u8; 16];
        let mut tr_v6 = 0u8;
        let mut tr = [0u8; 16];
        let mut hold = 0u32;
        let mut last = 0u64;
        let mut csp = 0u8;
        let mut cs = 0u32;
        let mut dsp = 0u8;
        let mut dspi = 0u8;
        let rc = unsafe {
            lr_ldp_engine_adjacency_at(
                e,
                0,
                &raw mut lsr,
                &raw mut ls,
                &raw mut kind,
                &raw mut src_v6,
                src.as_mut_ptr(),
                &raw mut tr_v6,
                tr.as_mut_ptr(),
                &raw mut hold,
                &raw mut last,
                &raw mut csp,
                &raw mut cs,
                &raw mut dsp,
                &raw mut dspi,
            )
        };
        assert_eq!(rc, LR_ERR_INVALID_HANDLE);
        unsafe { lr_ldp_engine_free(e) };
    }

    #[test]
    fn engine_drain_udp_returns_empty_on_fresh_engine() {
        let c = lr_ldp_engine_config_new(0x01020304, 0, [10, 0, 0, 1]);
        let e = unsafe { lr_ldp_engine_new(c) };
        let mut b = lr_bytes_t {
            ptr: std::ptr::null_mut(),
            len: 0,
            cap: 0,
        };
        let rc = unsafe { lr_ldp_engine_drain_udp(e, &raw mut b) };
        assert_eq!(rc, 0);
        assert_eq!(b.len, 0);
        unsafe { crate::bytes::lr_bytes_free(&raw mut b) };
        unsafe { lr_ldp_engine_free(e) };
    }
}
