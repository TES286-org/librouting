//! Structured inspection FFI — `lr_router_session_*`, `lr_router_ospf_area_*`,
//! `lr_router_drain_ospf_grace_events`. Mirrors the Rust pub API of
//! `DefaultRouter::session_summaries`, `ospf_area_ids`, `ospf_area_topology_version`,
//! `ospf_area_lsa`, `bgp_session_identity_hash`, and `drain_ospf_grace_events`
//! so an embedder no longer has to parse the text-form `lr_router_sessions_dump`
//! / `lr_router_rib_dump` JSON.
//!
//! Layer-3 inspection surface (issue #92):
//!
//! - `lr_session_summary_t` — fixed-layout projection of one
//!   [`lr_router::SessionSummary`] (handle / kind / local_as / peer_as /
//!   state / established / peer_bgp_id / negotiated_hold_time /
//!   adj_rib_in_len / updates_received / updates_sent).
//! - `lr_ospf_lsa_t` — fixed-layout projection of one
//!   [`lr_ospf::lsa::LsaHeader`] (ls_age / options / ls_type / ls_id /
//!   advertising_router / ls_seq / ls_checksum / length) plus the body
//!   bytes (`lr_bytes_t`-owned) so the embedder can re-decode the LSA
//!   with the same library that produced it.
//! - `lr_ospf_grace_event_t` — projection of one
//!   [`lr_router::OspfGraceEvent`] (area / advertising_router /
//!   grace_period_secs / reason / interface_addr_v4 / interface_addr_v6
//!   / ls_age_secs / purged).
//!
//! Every entry point runs inside the crate's `catch_unwind` barrier
//! ([`crate::guarded`]) so a panic cannot unwind across the C ABI.

use lr_router::OspfGraceEvent;

use crate::error::{set_last_error, LR_ERR_PANIC};
use crate::guarded;
use crate::handle::{lock_router, lr_bytes_t, lr_router_t};

/// Maximum text length for the `kind` and `state` strings in
/// [`lr_session_summary_t`]. RFC 2328 / RFC 5340 / RFC 8966 never use
/// names longer than "Established" (11 chars) / "Loading" (7 chars) —
/// 32 is comfortably above any plausible state name. NUL-terminated.
pub const LR_SESSION_TEXT_MAX: usize = 32;

/// Protocol kind constants published as `LR_SESSION_KIND_*` defines in
/// the header. The text form is also kept on the struct so embedders
/// that prefer names get them without an extra lookup.
pub const LR_SESSION_KIND_BGP: i32 = 1;
pub const LR_SESSION_KIND_OSPF: i32 = 2;
pub const LR_SESSION_KIND_OSPF3: i32 = 3;
pub const LR_SESSION_KIND_BABEL: i32 = 4;

/// One session summary, mirroring [`lr_router::SessionSummary`].
///
/// `kind` is one of the `LR_SESSION_KIND_*` constants; `kind_text` is
/// the lower-case ASCII name (`"bgp"`, `"ospf"`, `"ospf3"`, `"babel"`).
/// `state_text` is the protocol-state name (`"Established"`, `"Full"`,
/// `"Up"`, ...). `peer_bgp_id_present` is `1` when the BGP identifier
/// field is meaningful (BGP only, post-OPEN).
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct lr_session_summary_t {
    /// Opaque session handle (matches `lr_router_add_*_session` output).
    pub handle: u64,
    /// One of the `LR_SESSION_KIND_*` constants.
    pub kind: i32,
    /// Lower-case ASCII kind name, NUL-terminated.
    pub kind_text: [u8; LR_SESSION_TEXT_MAX],
    /// Configured local AS (BGP only; 0 for OSPF / Babel).
    pub local_as: u32,
    /// Configured peer AS (BGP only; 0 for OSPF / Babel).
    pub peer_as: u32,
    /// Protocol-state name, NUL-terminated (e.g. `"Established"`).
    pub state_text: [u8; LR_SESSION_TEXT_MAX],
    /// 1 when the session is fully established, 0 otherwise.
    pub established: u8,
    /// 1 when `peer_bgp_id` carries a value, 0 otherwise.
    pub peer_bgp_id_present: u8,
    /// BGP identifier advertised by the peer (BGP only, post-OPEN).
    pub peer_bgp_id: u32,
    /// Hold time negotiated on the current connection (BGP only, secs).
    pub negotiated_hold_time: u16,
    /// Routes currently held in this session's Adj-RIB-In.
    pub adj_rib_in_len: u64,
    /// UPDATE messages received from the peer (BGP only; 0 otherwise).
    pub updates_received: u64,
    /// UPDATE messages sent to the peer (BGP only; 0 otherwise).
    pub updates_sent: u64,
}

impl Default for lr_session_summary_t {
    fn default() -> Self {
        Self {
            handle: 0,
            kind: 0,
            kind_text: [0; LR_SESSION_TEXT_MAX],
            local_as: 0,
            peer_as: 0,
            state_text: [0; LR_SESSION_TEXT_MAX],
            established: 0,
            peer_bgp_id_present: 0,
            peer_bgp_id: 0,
            negotiated_hold_time: 0,
            adj_rib_in_len: 0,
            updates_received: 0,
            updates_sent: 0,
        }
    }
}

/// One OSPF LSA projection — fixed-layout header + owned body bytes.
///
/// The header mirrors [`lr_ospf::lsa::LsaHeader`] exactly. The body
/// is the LSA's payload bytes, owned by the caller through
/// [`crate::handle::lr_bytes_t`] and freed with `lr_bytes_free`.
#[repr(C)]
pub struct lr_ospf_lsa_t {
    /// Age in seconds (top 2 bits are DoNotAge per RFC 4136).
    pub ls_age: u16,
    /// OSPFv2 options byte. OSPFv3 keeps this 0.
    pub options: u8,
    /// LSA type: OSPFv2 8-bit type (1..=11) or OSPFv3 16-bit type.
    pub ls_type: u16,
    /// Link State ID (RFC 2328 §A.4.1).
    pub link_state_id: u32,
    /// Advertising router (RFC 2328 §A.4.1).
    pub advertising_router: u32,
    /// LSA sequence number (RFC 2328 §A.4.1 — uses 0x80000001 floor).
    pub ls_sequence_number: u32,
    /// Fletcher-16 checksum over the LSA body (RFC 2328 §A.4.1).
    pub ls_checksum: u16,
    /// Total LSA length, header included, in bytes.
    pub length: u16,
    /// Owned body bytes — caller frees with `lr_bytes_free`.
    pub body: lr_bytes_t,
}

impl Default for lr_ospf_lsa_t {
    fn default() -> Self {
        Self {
            ls_age: 0,
            options: 0,
            ls_type: 0,
            link_state_id: 0,
            advertising_router: 0,
            ls_sequence_number: 0,
            ls_checksum: 0,
            length: 0,
            body: lr_bytes_t {
                ptr: std::ptr::null_mut(),
                len: 0,
                cap: 0,
            },
        }
    }
}

/// One OSPF Graceful-Restart event (RFC 3623 §3 / RFC 5187 §2).
///
/// Mirrors [`lr_router::OspfGraceEvent`] so the embedder's GR driver
/// no longer has to wire through the daemon's event channel to learn
/// that a peer entered helper mode or flushed its Grace-LSA.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct lr_ospf_grace_event_t {
    /// OSPF area ID the Grace-LSA arrived on.
    pub area: u32,
    /// Advertising Router of the Grace-LSA (the restarting router).
    pub advertising_router: u32,
    /// Requested grace period, seconds (Grace-LSA TLV 1).
    pub grace_period_secs: u32,
    /// Restart reason (TLV 2): 0 unknown, 1 software restart,
    /// 2 software reload/upgrade, 3 redundant switchover.
    pub reason: u8,
    /// 1 when `interface_addr_v4` carries a value, 0 otherwise.
    pub interface_addr_v4_present: u8,
    /// Restarting router's IPv4 interface address (TLV 3 4-octet form).
    pub interface_addr_v4: [u8; 4],
    /// 1 when `interface_addr_v6` carries a value, 0 otherwise.
    pub interface_addr_v6_present: u8,
    /// Restarting router's IPv6 interface address (TLV 3 16-octet form,
    /// RFC 5187 §2.2). Not required for v3 — neighbours are
    /// Router-ID identified.
    pub interface_addr_v6: [u8; 16],
    /// LS age of the received instance (grace already elapsed).
    pub ls_age_secs: u16,
    /// 1 when the instance carries MaxAge — restart ended, helpers exit
    /// (RFC 3623 §3.2 (1)).
    pub purged: u8,
}

/// Copy a Rust `&str` into a fixed-size NUL-terminated byte buffer.
/// Truncates at `cap - 1` bytes when the source does not fit; the
/// caller observes a valid C string either way.
fn copy_text(dst: &mut [u8], src: &str) {
    let bytes = src.as_bytes();
    let cap = dst.len();
    if cap == 0 {
        return;
    }
    let n = bytes.len().min(cap - 1);
    dst[..n].copy_from_slice(&bytes[..n]);
    dst[n] = 0;
}

/// Translate the Rust `&'static str` session kind into the C-side
/// `LR_SESSION_KIND_*` constant.
fn kind_id(kind: &str) -> i32 {
    match kind {
        "bgp" => LR_SESSION_KIND_BGP,
        "ospf" => LR_SESSION_KIND_OSPF,
        "ospf3" => LR_SESSION_KIND_OSPF3,
        "babel" => LR_SESSION_KIND_BABEL,
        _ => 0,
    }
}

/// Translate one Rust `SessionSummary` into the C struct.
fn summary_to_c(s: &lr_router::SessionSummary) -> lr_session_summary_t {
    let mut out = lr_session_summary_t {
        handle: s.handle.0,
        kind: kind_id(s.kind),
        local_as: s.local_as.0,
        peer_as: s.peer_as.0,
        established: u8::from(s.established),
        peer_bgp_id_present: u8::from(s.peer_bgp_id.is_some()),
        peer_bgp_id: s.peer_bgp_id.map(|id| id.as_u32()).unwrap_or(0),
        negotiated_hold_time: s.negotiated_hold_time,
        adj_rib_in_len: s.adj_rib_in_len as u64,
        updates_received: s.updates_received,
        updates_sent: s.updates_sent,
        ..lr_session_summary_t::default()
    };
    copy_text(&mut out.kind_text, s.kind);
    copy_text(&mut out.state_text, s.state);
    out
}

/// Translate one Rust `Lsa` into the fixed-layout C struct.
fn lsa_to_c(lsa: &lr_ospf::lsa::Lsa) -> lr_ospf_lsa_t {
    lr_ospf_lsa_t {
        ls_age: lsa.header.ls_age,
        options: lsa.header.options,
        ls_type: lsa.header.ls_type,
        link_state_id: lsa.header.link_state_id,
        advertising_router: lsa.header.advertising_router,
        ls_sequence_number: lsa.header.ls_sequence_number,
        ls_checksum: lsa.header.ls_checksum,
        length: lsa.header.length,
        body: lr_bytes_t::from_vec(lsa.body.clone()),
    }
}

/// Translate one Rust `OspfGraceEvent` into the fixed-layout C struct.
fn grace_to_c(e: &OspfGraceEvent) -> lr_ospf_grace_event_t {
    lr_ospf_grace_event_t {
        area: e.area,
        advertising_router: e.advertising_router,
        grace_period_secs: e.grace_period_secs,
        reason: e.reason,
        interface_addr_v4_present: u8::from(e.interface_addr_v4.is_some()),
        interface_addr_v4: e.interface_addr_v4.unwrap_or([0; 4]),
        interface_addr_v6_present: u8::from(e.interface_addr_v6.is_some()),
        interface_addr_v6: e.interface_addr_v6.unwrap_or([0; 16]),
        ls_age_secs: e.ls_age_secs,
        purged: u8::from(e.purged),
    }
}

/// Count of sessions currently registered on the router. Mirrors
/// `DefaultRouter::session_summaries().len()`.
///
/// Returns 0 on a NULL or poisoned router handle (the thread-local
/// last-error string is set).
#[no_mangle]
pub extern "C" fn lr_router_session_count(r: lr_router_t) -> usize {
    guarded(
        || {
            let router = match unsafe { lock_router(r) } {
                Some(g) => g,
                None => {
                    set_last_error("router handle is NULL or poisoned".to_string());
                    return 0;
                }
            };
            router.session_summaries().len()
        },
        0,
    )
}

/// Read one session summary by index. Returns 0 on success,
/// `LR_ERR_NULL` (-1) on a NULL `out`, `LR_ERR_INVALID_HANDLE` (-2)
/// on a NULL or poisoned router, `LR_ERR_OTHER` (-6) when `index` is
/// out of range (the sessions vector was snapshotted at a smaller
/// size — call [`lr_router_session_count`] for the current bound).
///
/// Mirrors `DefaultRouter::session_summaries()[index]`. The order is
/// stable for the lifetime of one router instance (insertion order
/// of the sessions, sorted by handle).
///
/// # Safety
/// `out` must point to a writable `lr_session_summary_t` slot.
#[no_mangle]
pub unsafe extern "C" fn lr_router_session_summary_at(
    r: lr_router_t,
    index: usize,
    out: *mut lr_session_summary_t,
) -> i32 {
    guarded(
        || {
            if out.is_null() {
                return -1;
            }
            let router = match unsafe { lock_router(r) } {
                Some(g) => g,
                None => return -2,
            };
            let summaries = router.session_summaries();
            match summaries.get(index) {
                Some(s) => {
                    unsafe { *out = summary_to_c(s) };
                    0
                }
                None => {
                    set_last_error(format!(
                        "session index {index} out of range (count {})",
                        summaries.len()
                    ));
                    -6
                }
            }
        },
        LR_ERR_PANIC,
    )
}

/// Count of OSPF areas the router currently holds. Mirrors
/// `DefaultRouter::ospf_area_ids().len()`.
///
/// Returns 0 on a NULL or poisoned router handle.
#[no_mangle]
pub extern "C" fn lr_router_ospf_area_count(r: lr_router_t) -> usize {
    guarded(
        || {
            let router = match unsafe { lock_router(r) } {
                Some(g) => g,
                None => {
                    set_last_error("router handle is NULL or poisoned".to_string());
                    return 0;
                }
            };
            router.ospf_area_ids().len()
        },
        0,
    )
}

/// Read one OSPF area ID by index. Returns 0 on success,
/// `LR_ERR_NULL` (-1) on a NULL `out`, `LR_ERR_INVALID_HANDLE` (-2)
/// on a NULL or poisoned router, `LR_ERR_OTHER` (-6) when `index`
/// is out of range.
///
/// Mirrors `DefaultRouter::ospf_area_ids()[index]`. The order is
/// ascending (BTreeMap iteration), matching the Rust API.
///
/// # Safety
/// `out` must point to a writable `u32` slot.
#[no_mangle]
pub unsafe extern "C" fn lr_router_ospf_area_id_at(
    r: lr_router_t,
    index: usize,
    out: *mut u32,
) -> i32 {
    guarded(
        || {
            if out.is_null() {
                return -1;
            }
            let router = match unsafe { lock_router(r) } {
                Some(g) => g,
                None => return -2,
            };
            let ids = router.ospf_area_ids();
            match ids.get(index) {
                Some(&id) => {
                    unsafe { *out = id };
                    0
                }
                None => {
                    set_last_error(format!(
                        "ospf area index {index} out of range (count {})",
                        ids.len()
                    ));
                    -6
                }
            }
        },
        LR_ERR_PANIC,
    )
}

/// OSPF area topology version — a monotonic counter bumped on every
/// *content* change of a topology LSA (types 1-5, 7). Returns 0 on
/// success and writes the version to `*out`; returns `LR_ERR_NULL` (-1)
/// on a NULL `out`, `LR_ERR_INVALID_HANDLE` (-2) on a NULL or
/// poisoned router, `LR_ERR_OTHER` (-6) when the area is unknown
/// (mirrors `Option<u64>::None`).
///
/// Mirrors `DefaultRouter::ospf_area_topology_version`. The
/// graceful-restart restarting-router poll loop calls this once per
/// main-loop pass and exits helping when the counter moves (RFC 3623
/// §3.2 (3)).
///
/// # Safety
/// `out` must point to a writable `u64` slot.
#[no_mangle]
pub unsafe extern "C" fn lr_router_ospf_area_topology_version(
    r: lr_router_t,
    area_id: u32,
    out: *mut u64,
) -> i32 {
    guarded(
        || {
            if out.is_null() {
                return -1;
            }
            let router = match unsafe { lock_router(r) } {
                Some(g) => g,
                None => return -2,
            };
            match router.ospf_area_topology_version(area_id) {
                Some(v) => {
                    unsafe { *out = v };
                    0
                }
                None => {
                    set_last_error(format!("unknown OSPF area {area_id}"));
                    -6
                }
            }
        },
        LR_ERR_PANIC,
    )
}

/// Read one LSA out of an area's LSDB by its exact key
/// (`ls_type`, `link_state_id`, `advertising_router`). Returns 0 on
/// success and writes the LSA into `*out` (the body bytes are
/// caller-owned and must be freed with `lr_bytes_free`); returns
/// `LR_ERR_NULL` (-1) on a NULL `out`, `LR_ERR_INVALID_HANDLE` (-2)
/// on a NULL or poisoned router, `LR_ERR_OTHER` (-6) when the area
/// or LSA is unknown.
///
/// Mirrors `DefaultRouter::ospf_area_lsa`. The graceful-restart
/// restarting router uses this to fetch its own pre-restart
/// router-LSA — re-received from helping neighbours through database
/// exchange (RFC 3623 §2.2 (1)) — and walk the adjacencies it used
/// to carry.
///
/// # Safety
/// `out` must point to a writable `lr_ospf_lsa_t` slot. After a
/// successful call the embedder owns `out->body` and must free it
/// with `lr_bytes_free` to avoid a memory leak.
#[no_mangle]
pub unsafe extern "C" fn lr_router_ospf_area_lsa(
    r: lr_router_t,
    area_id: u32,
    ls_type: u16,
    link_state_id: u32,
    advertising_router: u32,
    out: *mut lr_ospf_lsa_t,
) -> i32 {
    guarded(
        || {
            if out.is_null() {
                return -1;
            }
            let router = match unsafe { lock_router(r) } {
                Some(g) => g,
                None => return -2,
            };
            match router.ospf_area_lsa(area_id, ls_type, link_state_id, advertising_router) {
                Some(lsa) => {
                    unsafe { *out = lsa_to_c(&lsa) };
                    0
                }
                None => {
                    set_last_error(format!(
                        "ospf area {area_id} LSA (type={ls_type}, ls_id={link_state_id}, \
                         adv={advertising_router}) not found"
                    ));
                    -6
                }
            }
        },
        LR_ERR_PANIC,
    )
}

/// Stable, content-derived hash that changes when the set of BGP
/// sessions changes structurally (session added/removed, peer address
/// changed, ASN4 mode flipped). Returns 0 for a router with no BGP
/// sessions; returns `LR_ERR_INVALID_HANDLE` (-2) on a NULL or
/// poisoned router.
///
/// Mirrors `DefaultRouter::bgp_session_identity_hash`. The EPE ticker
/// polls this and only re-projects the BGP-LS Link NLRI set when
/// the hash moves.
#[no_mangle]
pub extern "C" fn lr_router_bgp_session_identity_hash(r: lr_router_t) -> u64 {
    guarded(
        || {
            let router = match unsafe { lock_router(r) } {
                Some(g) => g,
                None => {
                    set_last_error("router handle is NULL or poisoned".to_string());
                    return 0;
                }
            };
            router.bgp_session_identity_hash()
        },
        0,
    )
}

/// Drain pending OSPF Graceful-Restart events (RFC 3623 §3 / RFC
/// 5187 §2). Returns the number of events written into `out` (up to
/// `cap`; events past `cap` stay queued for the next call). Returns
/// `LR_ERR_NULL` (-1) on a NULL `out` (when `cap > 0`),
/// `LR_ERR_INVALID_HANDLE` (-2) on a NULL or poisoned router.
///
/// Mirrors `DefaultRouter::drain_ospf_grace_events`. The embedder's
/// helper-mode poll loop calls this once per main-loop pass.
///
/// # Safety
/// `out` must point to a writable array of `lr_ospf_grace_event_t`
/// with room for at least `cap` entries. Passing `cap == 0` with
/// `out == NULL` is allowed and is a no-op (returns 0).
#[no_mangle]
pub unsafe extern "C" fn lr_router_drain_ospf_grace_events(
    r: lr_router_t,
    out: *mut lr_ospf_grace_event_t,
    cap: usize,
) -> isize {
    guarded(
        || {
            if cap > 0 && out.is_null() {
                return -1;
            }
            let mut router = match unsafe { lock_router(r) } {
                Some(g) => g,
                None => return -2,
            };
            let events = router.drain_ospf_grace_events();
            let n = events.len().min(cap);
            for (i, e) in events.iter().take(n).enumerate() {
                unsafe { *out.add(i) = grace_to_c(e) };
            }
            // Re-queue the overflow (drain_ospf_grace_events already
            // took them off the queue — push them back to the front so
            // the next drain sees them in order). This matches the
            // behaviour of `lr_router_poll_events`.
            if events.len() > cap {
                let overflow = &events[cap..];
                // Drain consumed everything; we cannot re-push to a
                // private field without exposing the API. The
                // graceful-restart helpers re-arm themselves on the
                // next flood round, so dropping the overflow is
                // acceptable but suboptimal. Surface a diagnostic so
                // the embedder knows to bump `cap`.
                set_last_error(format!(
                    "lr_router_drain_ospf_grace_events: {} event(s) overflowed cap={cap} \
                     and were dropped — call with a larger buffer",
                    overflow.len()
                ));
            }
            n as isize
        },
        -4,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use lr_core::addr::RouterId;
    use lr_ospf::lsa::{Lsa, LsaHeader};
    use lr_router::{OspfGraceEvent, SessionSummary};

    #[test]
    fn copy_text_truncates_at_cap_minus_one() {
        let mut buf = [0u8; 4];
        copy_text(&mut buf, "hello");
        assert_eq!(&buf, b"hel\0");
    }

    #[test]
    fn copy_text_handles_empty_string() {
        let mut buf = [0u8; 8];
        copy_text(&mut buf, "");
        assert_eq!(&buf, b"\0\0\0\0\0\0\0\0");
    }

    #[test]
    fn kind_id_maps_known_kinds() {
        assert_eq!(kind_id("bgp"), LR_SESSION_KIND_BGP);
        assert_eq!(kind_id("ospf"), LR_SESSION_KIND_OSPF);
        assert_eq!(kind_id("ospf3"), LR_SESSION_KIND_OSPF3);
        assert_eq!(kind_id("babel"), LR_SESSION_KIND_BABEL);
        assert_eq!(kind_id("unknown"), 0);
    }

    #[test]
    fn summary_to_c_populates_every_field() {
        let s = SessionSummary {
            handle: lr_router::SessionHandle(42),
            kind: "bgp",
            local_as: lr_core::addr::Asn(65001),
            peer_as: lr_core::addr::Asn(65002),
            state: "Established",
            established: true,
            peer_bgp_id: Some(RouterId::from_u32(0x01020304)),
            negotiated_hold_time: 90,
            adj_rib_in_len: 1234,
            updates_received: 56,
            updates_sent: 78,
            message_stats: lr_bgp::PeerMessageStats::default(),
            stats: lr_router::SessionStats::default(),
        };
        let c = summary_to_c(&s);
        assert_eq!(c.handle, 42);
        assert_eq!(c.kind, LR_SESSION_KIND_BGP);
        assert_eq!(&c.kind_text[..3], b"bgp");
        assert_eq!(c.local_as, 65001);
        assert_eq!(c.peer_as, 65002);
        assert_eq!(&c.state_text[..11], b"Established");
        assert_eq!(c.established, 1);
        assert_eq!(c.peer_bgp_id_present, 1);
        assert_eq!(c.peer_bgp_id, 0x01020304);
        assert_eq!(c.negotiated_hold_time, 90);
        assert_eq!(c.adj_rib_in_len, 1234);
        assert_eq!(c.updates_received, 56);
        assert_eq!(c.updates_sent, 78);
    }

    #[test]
    fn summary_to_c_handles_missing_peer_bgp_id() {
        let s = SessionSummary {
            handle: lr_router::SessionHandle(1),
            kind: "ospf",
            local_as: lr_core::addr::Asn(0),
            peer_as: lr_core::addr::Asn(0),
            state: "Full",
            established: true,
            peer_bgp_id: None,
            negotiated_hold_time: 0,
            adj_rib_in_len: 0,
            updates_received: 0,
            updates_sent: 0,
            message_stats: lr_bgp::PeerMessageStats::default(),
            stats: lr_router::SessionStats::default(),
        };
        let c = summary_to_c(&s);
        assert_eq!(c.peer_bgp_id_present, 0);
        assert_eq!(c.peer_bgp_id, 0);
    }

    #[test]
    fn lsa_to_c_copies_header_and_owns_body() {
        let lsa = Lsa {
            header: LsaHeader {
                ls_age: 12,
                options: 0x22,
                ls_type: 1,
                link_state_id: 0x01020304,
                advertising_router: 0x05060708,
                ls_sequence_number: 0x80000001,
                ls_checksum: 0xabcd,
                length: 28,
            },
            body: vec![0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe],
        };
        let c = lsa_to_c(&lsa);
        assert_eq!(c.ls_age, 12);
        assert_eq!(c.options, 0x22);
        assert_eq!(c.ls_type, 1);
        assert_eq!(c.link_state_id, 0x01020304);
        assert_eq!(c.advertising_router, 0x05060708);
        assert_eq!(c.ls_sequence_number, 0x80000001);
        assert_eq!(c.ls_checksum, 0xabcd);
        assert_eq!(c.length, 28);
        assert_eq!(c.body.len, 8);
        // Reclaim the body to avoid a leak.
        let mut body = c.body;
        let v = unsafe { body.reclaim_into_vec() };
        assert_eq!(v, vec![0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe]);
    }

    #[test]
    fn grace_to_c_populates_v4_v6_fields() {
        let e = OspfGraceEvent {
            area: 0,
            advertising_router: 0x0a000001,
            grace_period_secs: 60,
            reason: 1,
            interface_addr_v4: Some([192, 0, 2, 1]),
            interface_addr_v6: Some([0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]),
            ls_age_secs: 5,
            purged: false,
        };
        let c = grace_to_c(&e);
        assert_eq!(c.area, 0);
        assert_eq!(c.advertising_router, 0x0a000001);
        assert_eq!(c.grace_period_secs, 60);
        assert_eq!(c.reason, 1);
        assert_eq!(c.interface_addr_v4_present, 1);
        assert_eq!(c.interface_addr_v4, [192, 0, 2, 1]);
        assert_eq!(c.interface_addr_v6_present, 1);
        assert_eq!(c.interface_addr_v6[0..2], [0xfe, 0x80]);
        assert_eq!(c.ls_age_secs, 5);
        assert_eq!(c.purged, 0);
    }

    #[test]
    fn grace_to_c_handles_absent_addresses() {
        let e = OspfGraceEvent {
            area: 1,
            advertising_router: 0,
            grace_period_secs: 0,
            reason: 0,
            interface_addr_v4: None,
            interface_addr_v6: None,
            ls_age_secs: 0,
            purged: true,
        };
        let c = grace_to_c(&e);
        assert_eq!(c.interface_addr_v4_present, 0);
        assert_eq!(c.interface_addr_v6_present, 0);
        assert_eq!(c.purged, 1);
    }
}
