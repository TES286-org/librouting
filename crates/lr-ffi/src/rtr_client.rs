//! BGP RTR client FFI — `lr_rtr_client_*`.
//!
//! Mirrors the public Rust API of `lr_bgp::rtr::client::{RtrClient,
//! ClientStep, RoaDelta}` so an embedder can drive the RPKI-Router
//! protocol state machine (RFC 8210 §6-§8) without going through
//! the daemon's `DefaultRouter`. The state machine owns the
//! protocol: `on_connect` returns the initial query, `on_pdu`
//! advances per received PDU, `poll` advances per the §6 timing.
//!
//! `on_pdu` requires a decoded `RtrPdu`; the PDU codec is currently
//! only exposed via the codec module's `lr_bgp_decode` /
//! `lr_bgp_encode_*` surface. Until the RTR PDU codec is exposed
//! as a separate `lr_rtr_pdu_*` surface, `on_pdu` is reachable
//! through `lr_rtr_client_on_pdu_raw` (decode + on_pdu in one
//! call, returning the `ClientStep` projection).
//!
//! `lr_rtr_client_step_t` carries the step's `send_bytes`,
//! `roa_deltas` array, `router_key_deltas` array, `aspa_deltas`
//! array and `logs` array inline; the embedder frees all five with
//! a single [`lr_rtr_client_step_free`] call (or by freeing
//! `send_bytes` with [`crate::bytes::lr_bytes_free`] and leaving the
//! deltas/logs arrays to be reclaimed at process exit, but the
//! helper is the canonical path).
//!
//! # RFC 8210 §5.10 / §5.11 attestation surfaces
//!
//! The Rust `ClientStep` carries `router_key_deltas` (BGPsec Router
//! Key attestation, RFC 8210 §5.10) and `aspa_deltas` (ASPA
//! provider-set attestation, §5.11) alongside the ROA deltas. The
//! C `lr_rtr_client_step_t` mirrors both: each delta array is a flat
//! `lr_router_key_delta_t` / `lr_aspa_delta_t` array the embedder
//! walks with [`lr_rtr_client_step_router_key_delta_at`] /
//! [`lr_rtr_client_step_aspa_delta_at`]. The two new types are
//! additive growth on the existing struct (the new fields land at
//! the tail, the existing fields' offsets are unchanged); the
//! freeze gate (`scripts/abi_freeze_check.py`) treats new fields and
//! new symbols as silent, so no `ABI_VERSION` bump is required.
//!
//! The variable-length payloads inside each entry (the Router Key
//! `subject_public_key_info` byte string and the ASPA `providers`
//! ASN array) are heap-allocated by the FFI and owned by the step:
//! the pointers stay valid until [`lr_rtr_client_step_free`] runs.
//! The embedder reads them through the in-struct pointers; no
//! per-delta free is required.
//!
//! Every entry point runs inside the crate's `catch_unwind` barrier
//! ([`crate::guarded`]): a panic returns `LR_ERR_PANIC` and sets the
//! thread-local last-error string.

#![allow(unsafe_code)]
#![allow(unused_unsafe)]

use std::ffi::CString;
use std::os::raw::c_char;

use lr_bgp::rtr::client::{
    AspaDelta, AspaEntry, ClientStep, RouterKeyDelta, RouterKeyEntry, RtrClient,
};
use lr_bgp::rtr::pdu::decode as decode_pdu;

use crate::error::{set_last_error, LrError, LR_ERR_PANIC};
use crate::guarded;
use crate::handle::lr_bytes_t;
use crate::roa_store::{lr_roa_delta_t, lr_roa_entry_t};

const LR_ERR_NULL: i32 = LrError::Null as i32;

/// Opaque `RtrClient` handle.
#[repr(C)]
pub struct OpaqueRtrClient {
    _private: [u8; 0],
}
pub type lr_rtr_client_t = *mut OpaqueRtrClient;

fn box_client(c: RtrClient) -> lr_rtr_client_t {
    Box::into_raw(Box::new(c)) as lr_rtr_client_t
}
unsafe fn borrow_client(c: lr_rtr_client_t) -> Option<&'static RtrClient> {
    if c.is_null() {
        return None;
    }
    Some(unsafe { &*(c as *const RtrClient) })
}
unsafe fn borrow_client_mut(c: lr_rtr_client_t) -> Option<&'static mut RtrClient> {
    if c.is_null() {
        return None;
    }
    Some(unsafe { &mut *(c as *mut RtrClient) })
}

// ============================================================================
// RFC 8210 §5.10 / §5.11 typed delta surfaces
// ----------------------------------------------------------------------------
// The Rust `ClientStep` carries `router_key_deltas` (BGPsec Router Key
// attestation, §5.10) and `aspa_deltas` (ASPA provider-set attestation,
// §5.11) alongside the ROA deltas. The C ABI mirrors both as flat arrays
// of [`lr_router_key_delta_t`] / [`lr_aspa_delta_t`] the embedder walks
// with [`lr_rtr_client_step_router_key_delta_at`] /
// [`lr_rtr_client_step_aspa_delta_at`]. The variable-length payloads
// (the Router Key `subject_public_key_info` byte string and the ASPA
// `providers` ASN array) are heap-allocated by the FFI and owned by the
// step — the pointers stay valid until [`lr_rtr_client_step_free`] runs.
// ============================================================================

/// One BGPsec Router Key entry (RFC 8210 §5.10) — the cache's
/// attestation for one `(ski, asn)` pair.
///
/// The wire identity is `(ski, asn)` (RFC 8210 §5.10 scopes a key by
/// that pair); the `subject_public_key_info` is the full DER
/// `subjectPublicKeyInfo` blob the cache vouches for. The SPKI is
/// variable-length; the FFI heap-allocates one buffer per delta and
/// carries the pointer + length inline. The pointer is owned by the
/// step that produced the delta — the embedder must NOT free it; the
/// step's [`lr_rtr_client_step_free`] call reclaims every SPKI buffer
/// in one pass.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct lr_router_key_entry_t {
    /// RFC 8210 §5.10: the 20-byte SHA-1 hash of the SPKI. The cache
    /// identifies the key by this hash; the client treats it as the
    /// primary identity inside one ASN.
    pub ski: [u8; 20],
    /// The AS number the router key is valid for. §5.10 scopes a key
    /// by `(ski, asn)`; two keys with the same SKI for different ASNs
    /// are distinct records.
    pub asn: u32,
    /// Heap-allocated, NUL-free `subjectPublicKeyInfo` blob the cache
    /// attests (DER tag + length + value). Owned by the step that
    /// produced the delta; valid until [`lr_rtr_client_step_free`]
    /// runs. NULL when `subject_public_key_info_len == 0` (an empty
    /// SPKI is wire-valid as a withdrawal target).
    pub subject_public_key_info: *mut u8,
    /// Length of `subject_public_key_info` in bytes. Zero when the
    /// entry carries no SPKI (a withdrawal or a malformed PDU the
    /// client still surfaced for symmetry with the Rust API).
    pub subject_public_key_info_len: usize,
}

/// One Router Key delta at a completed sync (RFC 8210 §5.10):
/// `announce != 0` adds the entry to the authoritative set,
/// `announce == 0` removes it. Mirrors [`lr_roa_delta_t`] for the
/// §5.10 Router Key PDU.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct lr_router_key_delta_t {
    /// `0` = withdraw, anything else = announce.
    pub announce: u8,
    /// The record the delta applies to.
    pub entry: lr_router_key_entry_t,
}

/// One ASPA record (RFC 8210 §5.11, SIDROPS ASPA profile) — the
/// cache's attestation for one customer ASN's provider set.
///
/// The wire identity is `customer_asn` (§5.11: "A withdrawal deletes
/// the entire ASPA object for the customer ASN"); the `providers`
/// array carries the provider ASNs the cache attests, in ascending
/// order (the Rust side canonicalises to a `BTreeSet<u32>` so two
/// announcements with the same providers in different wire order
/// compare equal). The providers array is heap-allocated and owned
/// by the step that produced the delta — the embedder must NOT free
/// it; the step's [`lr_rtr_client_step_free`] call reclaims every
/// providers buffer in one pass.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct lr_aspa_entry_t {
    /// The customer AS the providers are attested for. The wire
    /// identity of an ASPA record.
    pub customer_asn: u32,
    /// Heap-allocated, ascending-order provider ASN array. Owned by
    /// the step that produced the delta; valid until
    /// [`lr_rtr_client_step_free`] runs. NULL when
    /// `provider_count == 0` (an empty provider set is wire-valid as
    /// "the customer is not a provider of any AS" per §5.11).
    pub providers: *mut u32,
    /// Number of providers in the `providers` array.
    pub provider_count: usize,
}

/// One ASPA delta at a completed sync (RFC 8210 §5.11):
/// `announce != 0` adds the entry to the authoritative set,
/// `announce == 0` removes it. Mirrors [`lr_roa_delta_t`] for the
/// §5.11 ASPA PDU.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct lr_aspa_delta_t {
    /// `0` = withdraw, anything else = announce.
    pub announce: u8,
    /// The record the delta applies to.
    pub entry: lr_aspa_entry_t,
}

unsafe fn unbox_client(c: lr_rtr_client_t) -> Option<Box<RtrClient>> {
    if c.is_null() {
        return None;
    }
    Some(unsafe { Box::from_raw(c as *mut RtrClient) })
}

/// One `ClientStep` projection — what the embedder should do after
/// one protocol step. The `send_bytes` field carries the wire bytes
/// to transmit (NULL `lr_bytes_t` when empty); `roa_deltas` carries
/// the atomic ROA deltas at End of Data; `router_key_deltas` carries
/// the RFC 8210 §5.10 BGPsec Router Key attestation; `aspa_deltas`
/// carries the §5.11 ASPA provider-set attestation; `logs` carries
/// the diagnostic log lines the state machine produced; the boolean
/// flags surface `synced` / `drop` / `expired`.
///
/// # Ownership
///
/// `send_bytes`, `roa_deltas`, `router_key_deltas`, `aspa_deltas` and
/// `logs` are caller-owned. Free them all with a single
/// [`lr_rtr_client_step_free`] call. The accessors
/// [`lr_rtr_client_step_roa_delta_at`],
/// [`lr_rtr_client_step_router_key_delta_at`],
/// [`lr_rtr_client_step_aspa_delta_at`] and
/// [`lr_rtr_client_step_log_at`] borrow the arrays in place — they
/// do not allocate, and the arrays they read from stay owned by the
/// step until [`lr_rtr_client_step_free`] runs.
#[repr(C)]
pub struct lr_rtr_client_step_t {
    /// Wire bytes to transmit (zero or more complete PDUs). NULL
    /// `ptr` means empty — caller must call [`crate::bytes::lr_bytes_free`]
    /// (or [`lr_rtr_client_step_free`]) to release.
    pub send_bytes: lr_bytes_t,
    /// 1 when this step completed a sync (End of Data processed).
    pub synced: u8,
    /// 1 when the transport connection should be closed.
    pub drop: u8,
    /// 1 when the last synced data exceeded its expire interval
    /// without a successful poll (§6) — validation on it must stop.
    pub expired: u8,
    /// Number of ROA deltas in this step (zero unless `synced`).
    pub roa_delta_count: usize,
    /// Number of diagnostic log lines in this step.
    pub log_count: usize,
    /// Owned flat array of `roa_delta_count` [`lr_roa_delta_t`]
    /// values. NULL when `roa_delta_count == 0`. Freed by
    /// [`lr_rtr_client_step_free`].
    pub roa_deltas: *mut lr_roa_delta_t,
    /// Owned array of `log_count` NUL-terminated C strings. NULL
    /// when `log_count == 0`. Each entry is a heap `CString`; the
    /// array and every entry are freed by
    /// [`lr_rtr_client_step_free`].
    pub logs: *mut *mut c_char,
    /// Number of BGPsec Router Key deltas in this step (RFC 8210
    /// §5.10 — zero unless `synced`, always zero for v0 caches).
    pub router_key_delta_count: usize,
    /// Number of ASPA deltas in this step (RFC 8210 §5.11 — zero
    /// unless `synced`, always zero for v0/v1 caches).
    pub aspa_delta_count: usize,
    /// Owned flat array of `router_key_delta_count`
    /// [`lr_router_key_delta_t`] values. NULL when
    /// `router_key_delta_count == 0`. Each entry's SPKI buffer and
    /// the array itself are freed by [`lr_rtr_client_step_free`].
    pub router_key_deltas: *mut lr_router_key_delta_t,
    /// Owned flat array of `aspa_delta_count` [`lr_aspa_delta_t`]
    /// values. NULL when `aspa_delta_count == 0`. Each entry's
    /// providers array and the array itself are freed by
    /// [`lr_rtr_client_step_free`].
    pub aspa_deltas: *mut lr_aspa_delta_t,
}

impl Default for lr_rtr_client_step_t {
    fn default() -> Self {
        Self {
            send_bytes: lr_bytes_t {
                ptr: std::ptr::null_mut(),
                len: 0,
                cap: 0,
            },
            synced: 0,
            drop: 0,
            expired: 0,
            roa_delta_count: 0,
            log_count: 0,
            roa_deltas: std::ptr::null_mut(),
            logs: std::ptr::null_mut(),
            router_key_delta_count: 0,
            aspa_delta_count: 0,
            router_key_deltas: std::ptr::null_mut(),
            aspa_deltas: std::ptr::null_mut(),
        }
    }
}

/// Construct a fresh `RtrClient` (RFC 8210 §8.1 cold start — no
/// session memory, protocol version starts at RTR_VERSION_MAX).
#[no_mangle]
pub extern "C" fn lr_rtr_client_new() -> lr_rtr_client_t {
    guarded(|| box_client(RtrClient::new()), std::ptr::null_mut())
}

/// Drop a boxed `RtrClient`. Safe to call with NULL.
///
/// # Safety
/// `c` must have been produced by `lr_rtr_client_new` and not already
/// freed.
#[no_mangle]
pub unsafe extern "C" fn lr_rtr_client_free(c: lr_rtr_client_t) {
    guarded(
        || unsafe {
            drop(unbox_client(c));
        },
        (),
    )
}

/// The protocol version currently spoken (post-§7 downgrade).
/// Returns 0 on a NULL handle.
///
/// # Safety
/// `c` must be a valid RtrClient handle.
#[no_mangle]
pub unsafe extern "C" fn lr_rtr_client_version(c: lr_rtr_client_t) -> u8 {
    guarded(
        || unsafe { borrow_client(c).map(|x| x.version()).unwrap_or(0) },
        0,
    )
}

/// The remembered session ID (None until the first Cache Response).
/// Writes the session ID to `*out_session` and returns 1 if present,
/// 0 if absent (or NULL handle).
///
/// # Safety
/// `c` must be a valid RtrClient handle. `out_session` must point to
/// a writable `uint16_t`.
#[no_mangle]
pub unsafe extern "C" fn lr_rtr_client_session_id(c: lr_rtr_client_t, out_session: *mut u16) -> u8 {
    guarded(
        || unsafe {
            let Some(client) = borrow_client(c) else {
                return 0;
            };
            if out_session.is_null() {
                return 0;
            }
            match client.session_id() {
                Some(s) => {
                    unsafe { *out_session = s };
                    1
                }
                None => 0,
            }
        },
        0,
    )
}

/// The serial of the last completed sync. Writes to `*out_serial`
/// and returns 1 if present, 0 if absent (or NULL handle).
///
/// # Safety
/// See [`lr_rtr_client_session_id`].
#[no_mangle]
pub unsafe extern "C" fn lr_rtr_client_serial(c: lr_rtr_client_t, out_serial: *mut u32) -> u8 {
    guarded(
        || unsafe {
            let Some(client) = borrow_client(c) else {
                return 0;
            };
            if out_serial.is_null() {
                return 0;
            }
            match client.serial() {
                Some(s) => {
                    unsafe { *out_serial = s };
                    1
                }
                None => 0,
            }
        },
        0,
    )
}

/// The current phase name (diagnostics: "awaiting-reset",
/// "awaiting-serial", "receiving", "synced"). Writes a NUL-terminated
/// string to `out_buf` (capacity `cap`); returns the length needed
/// (excluding NUL) — call with `cap=0` to size.
///
/// # Safety
/// `c` must be a valid RtrClient handle. `out_buf` must point to
/// writable bytes (NULL only when `cap == 0`).
#[no_mangle]
pub unsafe extern "C" fn lr_rtr_client_phase_name(
    c: lr_rtr_client_t,
    out_buf: *mut u8,
    cap: usize,
) -> usize {
    guarded(
        || unsafe {
            let Some(client) = borrow_client(c) else {
                return 0;
            };
            let name = client.phase_name();
            let n = name.len();
            if out_buf.is_null() || cap == 0 {
                return n;
            }
            let to_copy = n.min(cap - 1); // leave room for NUL
            unsafe {
                std::ptr::copy_nonoverlapping(name.as_ptr(), out_buf, to_copy);
                *out_buf.add(to_copy) = 0; // NUL-terminate
            }
            n
        },
        0,
    )
}

/// The §6 timing intervals in effect (refresh, retry, expire —
/// seconds). Writes to the three out-pointers. Returns 0 on success,
/// `LR_ERR_NULL` on a NULL client or NULL out-pointers.
///
/// # Safety
/// `c` must be a valid RtrClient handle. The out-pointers must point
/// to writable `uint32_t` values.
#[no_mangle]
pub unsafe extern "C" fn lr_rtr_client_intervals(
    c: lr_rtr_client_t,
    out_refresh: *mut u32,
    out_retry: *mut u32,
    out_expire: *mut u32,
) -> i32 {
    guarded(
        || unsafe {
            let Some(client) = borrow_client(c) else {
                return LR_ERR_NULL;
            };
            if out_refresh.is_null() || out_retry.is_null() || out_expire.is_null() {
                return LR_ERR_NULL;
            }
            let (r, re, e) = client.intervals();
            unsafe {
                *out_refresh = r;
                *out_retry = re;
                *out_expire = e;
            }
            0
        },
        LR_ERR_PANIC,
    )
}

/// Override the initial §6 intervals (refresh, retry, expire —
/// seconds). The embedder calls this once at construction from its
/// configuration; a v1+ cache replaces all three from every
/// End-of-Data PDU (§6), so this only shapes the behaviour before
/// the first End of Data and for v0 caches.
///
/// # Safety
/// `c` must be a valid RtrClient handle.
#[no_mangle]
pub unsafe extern "C" fn lr_rtr_client_set_intervals(
    c: lr_rtr_client_t,
    refresh: u32,
    retry: u32,
    expire: u32,
) -> i32 {
    guarded(
        || unsafe {
            let Some(client) = borrow_client_mut(c) else {
                return LR_ERR_NULL;
            };
            client.set_intervals(refresh, retry, expire);
            0
        },
        LR_ERR_PANIC,
    )
}

/// Bytes to transmit when the transport comes up (§8.1): a Serial
/// Query when the client remembers an unexpired session, a Reset
/// Query otherwise. Writes the wire bytes to `*out`.
///
/// # Safety
/// `c` must be a valid RtrClient handle. `out` must point to a
/// writable `lr_bytes_t`.
#[no_mangle]
pub unsafe extern "C" fn lr_rtr_client_on_connect(c: lr_rtr_client_t, out: *mut lr_bytes_t) -> i32 {
    guarded(
        || unsafe {
            let Some(client) = borrow_client_mut(c) else {
                return LR_ERR_NULL;
            };
            if out.is_null() {
                return LR_ERR_NULL;
            }
            let bytes = client.on_connect();
            unsafe { *out = lr_bytes_t::from_vec(bytes) }
            0
        },
        LR_ERR_PANIC,
    )
}

/// Run the §6 timing rules at `now_ms`. Returns the `ClientStep`
/// projection: refresh polls while synced, data-expiry reporting
/// once the expire interval passes without a successful sync.
///
/// Writes the step's `synced` / `drop` / `expired` flags to the
/// out-struct; the wire bytes are written to `out_step.send_bytes`
/// (caller frees with `lr_bytes_free`).
///
/// # Safety
/// `c` must be a valid RtrClient handle. `out_step` must point to a
/// writable `lr_rtr_client_step_t`.
#[no_mangle]
pub unsafe extern "C" fn lr_rtr_client_poll(
    c: lr_rtr_client_t,
    now_ms: u64,
    out_step: *mut lr_rtr_client_step_t,
) -> i32 {
    guarded(
        || unsafe {
            let Some(client) = borrow_client_mut(c) else {
                return LR_ERR_NULL;
            };
            if out_step.is_null() {
                return LR_ERR_NULL;
            }
            let step = client.poll(now_ms);
            unsafe { *out_step = step_to_c(step) };
            0
        },
        LR_ERR_PANIC,
    )
}

/// Decode one RTR PDU from `data` and feed it to the client.
/// Returns the `ClientStep` projection. This is the receive-side
/// entry point for the RTR protocol (RFC 8210 §5/§8.2).
///
/// # Safety
/// `c` must be a valid RtrClient handle. `data` must point to `len`
/// readable bytes. `out_step` must point to a writable
/// `lr_rtr_client_step_t`.
#[no_mangle]
pub unsafe extern "C" fn lr_rtr_client_on_pdu_raw(
    c: lr_rtr_client_t,
    data: *const u8,
    len: usize,
    now_ms: u64,
    out_step: *mut lr_rtr_client_step_t,
) -> i32 {
    guarded(
        || unsafe {
            let Some(client) = borrow_client_mut(c) else {
                return LR_ERR_NULL;
            };
            if data.is_null() || out_step.is_null() {
                return LR_ERR_NULL;
            }
            let slice = unsafe { std::slice::from_raw_parts(data, len) };
            let (version, pdu, consumed) = match decode_pdu(slice) {
                Ok(Some((v, p, n))) => (v, p, n),
                Ok(None) => {
                    set_last_error("rtr: PDU truncated".into());
                    return LrError::Other as i32;
                }
                Err(e) => {
                    set_last_error(e.to_string());
                    return LrError::Other as i32;
                }
            };
            let _ = consumed; // consumed bytes (informational)
            let step = client.on_pdu(version, &pdu, now_ms);
            unsafe { *out_step = step_to_c(step) };
            0
        },
        LR_ERR_PANIC,
    )
}

/// Read the authoritative ROA record set after the last completed
/// sync, sorted for deterministic snapshots. Writes the entries to
/// `out_entries` (a flat `lr_roa_entry_t` array of capacity `cap`).
/// Returns the number of entries (caller-allocates pattern: call
/// with `cap=0` to size, then again to fill).
///
/// # Safety
/// `c` must be a valid RtrClient handle. `out_entries` must point
/// to writable `lr_roa_entry_t` values (NULL only when `cap == 0`).
#[no_mangle]
pub unsafe extern "C" fn lr_rtr_client_snapshot(
    c: lr_rtr_client_t,
    out_entries: *mut lr_roa_entry_t,
    cap: usize,
) -> usize {
    guarded(
        || unsafe {
            let Some(client) = borrow_client(c) else {
                return 0;
            };
            let snap = client.snapshot();
            let n = snap.len();
            if out_entries.is_null() || cap == 0 {
                return n;
            }
            let to_copy = n.min(cap);
            for (i, entry) in snap.iter().take(to_copy).enumerate() {
                let c_entry = roa_entry_to_c(entry);
                unsafe {
                    *out_entries.add(i) = c_entry;
                }
            }
            n
        },
        0,
    )
}

// ---- helpers ----

fn roa_entry_to_c(e: &lr_bgp::roa::RoaEntry) -> lr_roa_entry_t {
    let mut out = lr_roa_entry_t {
        addr: [0u8; 16],
        is_ipv6: 0,
        prefix_len: e.prefix.prefix_len,
        max_length: e.max_length,
        asn: e.asn.as_u32(),
    };
    match e.prefix.addr {
        lr_core::addr::IpAddr::V4(b) => {
            out.addr[..4].copy_from_slice(&b);
        }
        lr_core::addr::IpAddr::V6(b) => {
            out.addr = b;
            out.is_ipv6 = 1;
        }
    }
    out
}

fn step_to_c(step: ClientStep) -> lr_rtr_client_step_t {
    // Project the Rust `Vec<RoaDelta>` into a flat C array. The
    // array is owned by the step and freed by
    // `lr_rtr_client_step_free`. Using `into_boxed_slice` shrinks
    // the allocation to the exact count, so the free path can
    // reconstruct it via `slice_from_raw_parts_mut(ptr, count)`.
    let roa_delta_count = step.roa_deltas.len();
    let roa_deltas_ptr = if roa_delta_count == 0 {
        std::ptr::null_mut()
    } else {
        let c_deltas: Vec<lr_roa_delta_t> = step
            .roa_deltas
            .iter()
            .map(|d| lr_roa_delta_t {
                announce: u8::from(d.announce),
                entry: roa_entry_to_c(&d.entry),
            })
            .collect();
        let boxed: Box<[lr_roa_delta_t]> = c_deltas.into_boxed_slice();
        Box::into_raw(boxed) as *mut lr_roa_delta_t
    };

    // Project the Rust `Vec<String>` into a C array of NUL-terminated
    // strings. Interior NUL bytes are replaced with U+FFFD so
    // `CString::new` cannot fail (the replacement keeps the log
    // readable from C; the original Rust `String` is preserved on
    // the Rust side and round-trips through tracing unchanged).
    let log_count = step.logs.len();
    let logs_ptr = if log_count == 0 {
        std::ptr::null_mut()
    } else {
        let c_logs: Vec<*mut c_char> = step
            .logs
            .iter()
            .map(|s| {
                let cleaned: String = s
                    .chars()
                    .map(|c| if c == '\0' { '\u{FFFD}' } else { c })
                    .collect();
                CString::new(cleaned)
                    .unwrap_or_else(|_| CString::new("").unwrap())
                    .into_raw()
            })
            .collect();
        let boxed: Box<[*mut c_char]> = c_logs.into_boxed_slice();
        Box::into_raw(boxed) as *mut *mut c_char
    };

    // Project the Rust `Vec<RouterKeyDelta>` into a flat C array
    // of `lr_router_key_delta_t`. Each delta's SPKI blob is
    // heap-allocated as a separate buffer (the Rust `Vec<u8>` is
    // `clone`'d into a heap allocation the C struct owns); the
    // `lr_rtr_client_step_free` path reclaims every SPKI buffer
    // before dropping the delta array itself.
    let router_key_delta_count = step.router_key_deltas.len();
    let router_key_deltas_ptr = if router_key_delta_count == 0 {
        std::ptr::null_mut()
    } else {
        let c_deltas: Vec<lr_router_key_delta_t> = step
            .router_key_deltas
            .iter()
            .map(router_key_delta_to_c)
            .collect();
        let boxed: Box<[lr_router_key_delta_t]> = c_deltas.into_boxed_slice();
        Box::into_raw(boxed) as *mut lr_router_key_delta_t
    };

    // Project the Rust `Vec<AspaDelta>` into a flat C array of
    // `lr_aspa_delta_t`. Each delta's providers ASN array is
    // heap-allocated as a separate `u32` buffer (the Rust
    // `BTreeSet<u32>` is collected into ascending order, which is
    // the BTreeSet's natural iteration order, and copied into a
    // heap allocation the C struct owns); the
    // `lr_rtr_client_step_free` path reclaims every providers
    // buffer before dropping the delta array itself.
    let aspa_delta_count = step.aspa_deltas.len();
    let aspa_deltas_ptr = if aspa_delta_count == 0 {
        std::ptr::null_mut()
    } else {
        let c_deltas: Vec<lr_aspa_delta_t> = step.aspa_deltas.iter().map(aspa_delta_to_c).collect();
        let boxed: Box<[lr_aspa_delta_t]> = c_deltas.into_boxed_slice();
        Box::into_raw(boxed) as *mut lr_aspa_delta_t
    };

    lr_rtr_client_step_t {
        send_bytes: lr_bytes_t::from_vec(step.send),
        synced: step.synced as u8,
        drop: step.drop as u8,
        expired: step.expired as u8,
        roa_delta_count,
        log_count,
        roa_deltas: roa_deltas_ptr,
        logs: logs_ptr,
        router_key_delta_count,
        aspa_delta_count,
        router_key_deltas: router_key_deltas_ptr,
        aspa_deltas: aspa_deltas_ptr,
    }
}

/// Project one Rust `RouterKeyEntry` into the C ABI shape. The
/// SPKI bytes are heap-allocated (cloned into a `Box<[u8]>` the C
/// struct owns through a raw pointer); the caller — the step's
/// free path — reclaims them by reconstructing the `Box<[u8]>` from
/// `slice_from_raw_parts_mut(ptr, len)` and dropping it.
fn router_key_entry_to_c(e: &RouterKeyEntry) -> lr_router_key_entry_t {
    let spki_len = e.subject_public_key_info.len();
    let spki_ptr = if spki_len == 0 {
        std::ptr::null_mut()
    } else {
        let buf: Box<[u8]> = e.subject_public_key_info.clone().into_boxed_slice();
        Box::into_raw(buf) as *mut u8
    };
    lr_router_key_entry_t {
        ski: e.ski,
        asn: e.asn,
        subject_public_key_info: spki_ptr,
        subject_public_key_info_len: spki_len,
    }
}

/// Project one Rust `RouterKeyDelta` into the C ABI shape — a thin
/// wrapper around [`router_key_entry_to_c`] that copies the
/// `announce` flag.
fn router_key_delta_to_c(d: &RouterKeyDelta) -> lr_router_key_delta_t {
    lr_router_key_delta_t {
        announce: u8::from(d.announce),
        entry: router_key_entry_to_c(&d.entry),
    }
}

/// Project one Rust `AspaEntry` into the C ABI shape. The provider
/// ASNs are heap-allocated as a `Box<[u32]>` in ascending order
/// (the `BTreeSet<u32>`'s natural iteration order, so two PDUs that
/// list the same providers in different wire order project to the
/// same C array — matching the Rust `PartialEq` shape that
/// collapses onto `customer_asn`).
fn aspa_entry_to_c(e: &AspaEntry) -> lr_aspa_entry_t {
    let provider_count = e.providers.len();
    let providers_ptr = if provider_count == 0 {
        std::ptr::null_mut()
    } else {
        let buf: Box<[u32]> = e
            .providers
            .iter()
            .copied()
            .collect::<Vec<u32>>()
            .into_boxed_slice();
        Box::into_raw(buf) as *mut u32
    };
    lr_aspa_entry_t {
        customer_asn: e.customer_asn,
        providers: providers_ptr,
        provider_count,
    }
}

/// Project one Rust `AspaDelta` into the C ABI shape — a thin
/// wrapper around [`aspa_entry_to_c`] that copies the `announce`
/// flag.
fn aspa_delta_to_c(d: &AspaDelta) -> lr_aspa_delta_t {
    lr_aspa_delta_t {
        announce: u8::from(d.announce),
        entry: aspa_entry_to_c(&d.entry),
    }
}

/// Reclaim one delta entry by index. Copies the value into `*out`.
/// Returns `0` on success, `LR_ERR_NULL` (-1) on a NULL `step` or
/// `out`, `LR_ERR_INVALID_HANDLE` (-2) on an out-of-bounds index.
///
/// # Safety
/// `step` must point to a `lr_rtr_client_step_t` returned by
/// [`lr_rtr_client_poll`] or [`lr_rtr_client_on_pdu_raw`] and not
/// yet freed. `out` must point to a writable `lr_roa_delta_t`.
#[no_mangle]
pub unsafe extern "C" fn lr_rtr_client_step_roa_delta_at(
    step: *const lr_rtr_client_step_t,
    index: usize,
    out: *mut lr_roa_delta_t,
) -> i32 {
    guarded(
        || unsafe {
            if step.is_null() || out.is_null() {
                return LR_ERR_NULL;
            }
            let s = &*step;
            if index >= s.roa_delta_count || s.roa_deltas.is_null() {
                return LrError::InvalidHandle as i32;
            }
            *out = *s.roa_deltas.add(index);
            0
        },
        LR_ERR_PANIC,
    )
}

/// Reclaim one BGPsec Router Key delta by index (RFC 8210 §5.10).
/// Copies the value into `*out`. The SPKI bytes stay owned by the
/// step — `out->entry.subject_public_key_info` points into the
/// step's heap allocation and stays valid until
/// [`lr_rtr_client_step_free`] runs; the caller must NOT free the
/// pointer.
///
/// Returns `0` on success, `LR_ERR_NULL` (-1) on a NULL `step` or
/// `out`, `LR_ERR_INVALID_HANDLE` (-2) on an out-of-bounds index.
///
/// # Safety
/// `step` must point to a `lr_rtr_client_step_t` returned by
/// [`lr_rtr_client_poll`] or [`lr_rtr_client_on_pdu_raw`] and not
/// yet freed. `out` must point to a writable
/// `lr_router_key_delta_t`. The `subject_public_key_info` pointer
/// inside `*out` borrows from the step and is invalidated by
/// [`lr_rtr_client_step_free`].
#[no_mangle]
pub unsafe extern "C" fn lr_rtr_client_step_router_key_delta_at(
    step: *const lr_rtr_client_step_t,
    index: usize,
    out: *mut lr_router_key_delta_t,
) -> i32 {
    guarded(
        || unsafe {
            if step.is_null() || out.is_null() {
                return LR_ERR_NULL;
            }
            let s = &*step;
            if index >= s.router_key_delta_count || s.router_key_deltas.is_null() {
                return LrError::InvalidHandle as i32;
            }
            *out = *s.router_key_deltas.add(index);
            0
        },
        LR_ERR_PANIC,
    )
}

/// Reclaim one ASPA delta by index (RFC 8210 §5.11). Copies the
/// value into `*out`. The provider ASN array stays owned by the
/// step — `out->entry.providers` points into the step's heap
/// allocation and stays valid until [`lr_rtr_client_step_free`]
/// runs; the caller must NOT free the pointer.
///
/// Returns `0` on success, `LR_ERR_NULL` (-1) on a NULL `step` or
/// `out`, `LR_ERR_INVALID_HANDLE` (-2) on an out-of-bounds index.
///
/// # Safety
/// `step` must point to a `lr_rtr_client_step_t` returned by
/// [`lr_rtr_client_poll`] or [`lr_rtr_client_on_pdu_raw`] and not
/// yet freed. `out` must point to a writable `lr_aspa_delta_t`. The
/// `providers` pointer inside `*out` borrows from the step and is
/// invalidated by [`lr_rtr_client_step_free`].
#[no_mangle]
pub unsafe extern "C" fn lr_rtr_client_step_aspa_delta_at(
    step: *const lr_rtr_client_step_t,
    index: usize,
    out: *mut lr_aspa_delta_t,
) -> i32 {
    guarded(
        || unsafe {
            if step.is_null() || out.is_null() {
                return LR_ERR_NULL;
            }
            let s = &*step;
            if index >= s.aspa_delta_count || s.aspa_deltas.is_null() {
                return LrError::InvalidHandle as i32;
            }
            *out = *s.aspa_deltas.add(index);
            0
        },
        LR_ERR_PANIC,
    )
}

/// Read one log line by index into `out_buf` (NUL-terminated).
/// Returns the length needed (excluding the NUL) — call with
/// `cap=0` to size. `0` is also returned on a NULL `step` or
/// out-of-bounds index (callers must check `log_count` first
/// when they need to disambiguate).
///
/// # Safety
/// `step` must point to a `lr_rtr_client_step_t` returned by
/// [`lr_rtr_client_poll`] or [`lr_rtr_client_on_pdu_raw`] and not
/// yet freed. `out_buf` must point to writable bytes (NULL only
/// when `cap == 0`).
#[no_mangle]
pub unsafe extern "C" fn lr_rtr_client_step_log_at(
    step: *const lr_rtr_client_step_t,
    index: usize,
    out_buf: *mut u8,
    cap: usize,
) -> usize {
    guarded(
        || unsafe {
            if step.is_null() {
                return 0;
            }
            let s = &*step;
            if index >= s.log_count || s.logs.is_null() {
                return 0;
            }
            let p = *s.logs.add(index);
            if p.is_null() {
                return 0;
            }
            // CStr::from_ptr is safe here because we allocated with
            // CString::into_raw, which guarantees a NUL terminator.
            let bytes = std::ffi::CStr::from_ptr(p).to_bytes();
            let n = bytes.len();
            if out_buf.is_null() || cap == 0 {
                return n;
            }
            let to_copy = n.min(cap - 1);
            std::ptr::copy_nonoverlapping(bytes.as_ptr(), out_buf, to_copy);
            *out_buf.add(to_copy) = 0; // NUL-terminate
            n
        },
        0,
    )
}

/// Free every owned field of a `lr_rtr_client_step_t`: the
/// `send_bytes`, the `roa_deltas` array, the `router_key_deltas`
/// array (including every SPKI buffer inside each entry), the
/// `aspa_deltas` array (including every providers buffer inside
/// each entry), and the `logs` array (including every C string
/// inside it). Safe to call with NULL. After this returns, the
/// step's pointer fields are NULL and the counts are zero — the
/// embedder may let the step go out of scope without further
/// cleanup.
///
/// # Safety
/// `step` must point to a `lr_rtr_client_step_t` returned by
/// [`lr_rtr_client_poll`] or [`lr_rtr_client_on_pdu_raw`] and not
/// already freed. Calling this twice on the same step is a
/// use-after-free.
#[no_mangle]
pub unsafe extern "C" fn lr_rtr_client_step_free(step: *mut lr_rtr_client_step_t) {
    guarded(
        || unsafe {
            if step.is_null() {
                return;
            }
            let s = &mut *step;
            // send_bytes — always reclaim through the bytes surface.
            crate::bytes::lr_bytes_free(&raw mut s.send_bytes);
            // roa_deltas — reconstruct the boxed slice from the
            // thin pointer + count, then drop it.
            if !s.roa_deltas.is_null() && s.roa_delta_count > 0 {
                let slice_ptr = std::ptr::slice_from_raw_parts_mut(s.roa_deltas, s.roa_delta_count);
                let boxed: Box<[lr_roa_delta_t]> = Box::from_raw(slice_ptr);
                drop(boxed);
            }
            s.roa_deltas = std::ptr::null_mut();
            s.roa_delta_count = 0;
            // router_key_deltas — drop every entry's SPKI buffer
            // first, then drop the array. The SPKI buffer is a
            // `Box<[u8]>` reconstructed from `(ptr, len)`; a NULL
            // pointer with `len == 0` was never allocated and is
            // skipped.
            if !s.router_key_deltas.is_null() && s.router_key_delta_count > 0 {
                let slice_ptr = std::ptr::slice_from_raw_parts_mut(
                    s.router_key_deltas,
                    s.router_key_delta_count,
                );
                let boxed: Box<[lr_router_key_delta_t]> = Box::from_raw(slice_ptr);
                for d in boxed.iter() {
                    if !d.entry.subject_public_key_info.is_null()
                        && d.entry.subject_public_key_info_len > 0
                    {
                        let spki_ptr = std::ptr::slice_from_raw_parts_mut(
                            d.entry.subject_public_key_info,
                            d.entry.subject_public_key_info_len,
                        );
                        let spki_boxed: Box<[u8]> = Box::from_raw(spki_ptr);
                        drop(spki_boxed);
                    }
                }
                drop(boxed);
            }
            s.router_key_deltas = std::ptr::null_mut();
            s.router_key_delta_count = 0;
            // aspa_deltas — drop every entry's providers buffer
            // first, then drop the array. The providers buffer is a
            // `Box<[u32]>` reconstructed from `(ptr, count)`; a NULL
            // pointer with `count == 0` was never allocated and is
            // skipped.
            if !s.aspa_deltas.is_null() && s.aspa_delta_count > 0 {
                let slice_ptr =
                    std::ptr::slice_from_raw_parts_mut(s.aspa_deltas, s.aspa_delta_count);
                let boxed: Box<[lr_aspa_delta_t]> = Box::from_raw(slice_ptr);
                for d in boxed.iter() {
                    if !d.entry.providers.is_null() && d.entry.provider_count > 0 {
                        let providers_ptr = std::ptr::slice_from_raw_parts_mut(
                            d.entry.providers,
                            d.entry.provider_count,
                        );
                        let providers_boxed: Box<[u32]> = Box::from_raw(providers_ptr);
                        drop(providers_boxed);
                    }
                }
                drop(boxed);
            }
            s.aspa_deltas = std::ptr::null_mut();
            s.aspa_delta_count = 0;
            // logs — drop every CString, then drop the array.
            if !s.logs.is_null() && s.log_count > 0 {
                let slice_ptr = std::ptr::slice_from_raw_parts_mut(s.logs, s.log_count);
                let boxed: Box<[*mut c_char]> = Box::from_raw(slice_ptr);
                for p in boxed.iter() {
                    if !p.is_null() {
                        // CString::from_raw reclaims the allocation.
                        drop(CString::from_raw(*p));
                    }
                }
                drop(boxed);
            }
            s.logs = std::ptr::null_mut();
            s.log_count = 0;
        },
        (),
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
    fn ffi_rtr_client_new_and_readers() {
        let c = lr_rtr_client_new();
        assert!(!c.is_null());
        assert_eq!(
            unsafe { lr_rtr_client_version(c) },
            lr_bgp::rtr::pdu::RTR_VERSION_MAX
        );

        let mut session = 0u16;
        assert_eq!(unsafe { lr_rtr_client_session_id(c, &raw mut session) }, 0);

        let mut serial = 0u32;
        assert_eq!(unsafe { lr_rtr_client_serial(c, &raw mut serial) }, 0);

        // Phase name on a fresh client is "awaiting-reset".
        let mut buf = [0u8; 32];
        let n = unsafe { lr_rtr_client_phase_name(c, buf.as_mut_ptr(), buf.len()) };
        assert_eq!(n, "awaiting-reset".len());
        assert_eq!(&buf[..n], b"awaiting-reset");

        unsafe { lr_rtr_client_free(c) };
    }

    #[test]
    fn ffi_rtr_client_intervals_default() {
        let c = lr_rtr_client_new();
        let mut refresh = 0u32;
        let mut retry = 0u32;
        let mut expire = 0u32;
        let rc = unsafe {
            lr_rtr_client_intervals(c, &raw mut refresh, &raw mut retry, &raw mut expire)
        };
        assert_eq!(rc, 0);
        assert_eq!(refresh, lr_bgp::rtr::client::DEFAULT_REFRESH_INTERVAL);
        assert_eq!(retry, lr_bgp::rtr::client::DEFAULT_RETRY_INTERVAL);
        assert_eq!(expire, lr_bgp::rtr::client::DEFAULT_EXPIRE_INTERVAL);
        unsafe { lr_rtr_client_free(c) };
    }

    #[test]
    fn ffi_rtr_client_set_intervals() {
        let c = lr_rtr_client_new();
        let rc = unsafe { lr_rtr_client_set_intervals(c, 100, 60, 600) };
        assert_eq!(rc, 0);
        let mut r = 0u32;
        let mut re = 0u32;
        let mut e = 0u32;
        let _ = unsafe { lr_rtr_client_intervals(c, &raw mut r, &raw mut re, &raw mut e) };
        assert_eq!(r, 100);
        assert_eq!(re, 60);
        assert_eq!(e, 600);
        unsafe { lr_rtr_client_free(c) };
    }

    #[test]
    fn ffi_rtr_client_on_connect_emits_reset_query() {
        // A fresh client (no session) emits a Reset Query on connect.
        // The Reset Query is a 8-byte PDU (RFC 8210 §5.3).
        let c = lr_rtr_client_new();
        let mut out = lr_bytes_t {
            ptr: std::ptr::null_mut(),
            len: 0,
            cap: 0,
        };
        let rc = unsafe { lr_rtr_client_on_connect(c, &raw mut out) };
        assert_eq!(rc, 0);
        let bytes = unsafe { bytes_to_vec(&mut out) };
        assert_eq!(bytes.len(), 8);
        // Reset Query PDU: version(1) + type(1) + zero(2) + length(4).
        // Type byte is at offset 1 — value 2 (RtrPduType::ResetQuery).
        assert_eq!(bytes[1], 2);
        unsafe { lr_rtr_client_free(c) };
    }

    #[test]
    fn ffi_rtr_client_snapshot_empty_on_fresh_client() {
        let c = lr_rtr_client_new();
        let n = unsafe { lr_rtr_client_snapshot(c, std::ptr::null_mut(), 0) };
        assert_eq!(n, 0);
        unsafe { lr_rtr_client_free(c) };
    }

    #[test]
    fn ffi_rtr_client_handles_null_safely() {
        assert_eq!(unsafe { lr_rtr_client_version(std::ptr::null_mut()) }, 0);
        unsafe { lr_rtr_client_free(std::ptr::null_mut()) };
    }

    #[test]
    fn ffi_rtr_client_poll_no_op_on_fresh_client() {
        // A fresh client has no last_sync_ms, so poll returns an empty step.
        let c = lr_rtr_client_new();
        let mut step = lr_rtr_client_step_t::default();
        let rc = unsafe { lr_rtr_client_poll(c, 0, &raw mut step) };
        assert_eq!(rc, 0);
        assert_eq!(step.synced, 0);
        assert_eq!(step.expired, 0);
        assert_eq!(step.roa_delta_count, 0);
        assert_eq!(step.log_count, 0);
        assert!(step.roa_deltas.is_null());
        assert!(step.logs.is_null());
        // send_bytes is empty (length 0; the ptr may be the Vec's
        // dangling pointer for an empty Vec, so check len not ptr).
        assert_eq!(step.send_bytes.len, 0);
        // The caller is responsible for freeing — even an empty
        // bytes handle must go through lr_bytes_free. The helper
        // also clears the deltas/logs arrays.
        unsafe { lr_rtr_client_step_free(&raw mut step) };
        assert!(step.roa_deltas.is_null());
        assert!(step.logs.is_null());
        assert_eq!(step.send_bytes.len, 0);
        unsafe { lr_rtr_client_free(c) };
    }

    /// Drive one full sync via `lr_rtr_client_on_pdu_raw` and confirm
    /// the step's `roa_deltas` array surfaces every record the cache
    /// announced. End-of-Data with session 0x00ff / serial 5 carries
    /// two announced IPv4 Prefix PDUs (RFC 8210 §5.6 / §5.7).
    #[test]
    fn ffi_rtr_client_step_roa_deltas_after_full_sync() {
        use lr_bgp::rtr::pdu::{encode_vec, RtrPdu, RTR_VERSION_1};
        let c = lr_rtr_client_new();
        // 1) Feed a Cache Response.
        let cr = RtrPdu::CacheResponse { session_id: 0x00ff };
        let wire_cr = encode_vec(&cr, RTR_VERSION_1);
        let mut step = lr_rtr_client_step_t::default();
        let rc = unsafe {
            lr_rtr_client_on_pdu_raw(c, wire_cr.as_ptr(), wire_cr.len(), 1_000, &raw mut step)
        };
        assert_eq!(rc, 0);
        assert_eq!(step.roa_delta_count, 0);
        unsafe { lr_rtr_client_step_free(&raw mut step) };

        // 2) Feed two IPv4 Prefix PDUs (announced).
        let a = RtrPdu::Ipv4Prefix {
            announce: true,
            prefix: lr_core::addr::Prefix::new_v4([192, 0, 2, 0], 24),
            max_length: 24,
            asn: 64512,
        };
        let b = RtrPdu::Ipv4Prefix {
            announce: true,
            prefix: lr_core::addr::Prefix::new_v4([198, 51, 100, 0], 24),
            max_length: 24,
            asn: 64513,
        };
        for pdu in [&a, &b] {
            let wire = encode_vec(pdu, RTR_VERSION_1);
            let rc = unsafe {
                lr_rtr_client_on_pdu_raw(c, wire.as_ptr(), wire.len(), 1_000, &raw mut step)
            };
            assert_eq!(rc, 0);
            assert_eq!(step.roa_delta_count, 0);
            unsafe { lr_rtr_client_step_free(&raw mut step) };
        }

        // 3) Feed End-of-Data — the step the FFI surface returns now
        // carries the two ROA deltas. `diff_records` iterates a
        // HashSet, so the order is not guaranteed — collect both
        // and check the entries are the two we announced (in any
        // order).
        let eod = RtrPdu::EndOfData {
            session_id: 0x00ff,
            serial: 5,
            refresh_interval: Some(60),
            retry_interval: Some(30),
            expire_interval: Some(600),
        };
        let wire_eod = encode_vec(&eod, RTR_VERSION_1);
        let rc = unsafe {
            lr_rtr_client_on_pdu_raw(c, wire_eod.as_ptr(), wire_eod.len(), 1_000, &raw mut step)
        };
        assert_eq!(rc, 0);
        assert_eq!(step.synced, 1);
        assert_eq!(step.roa_delta_count, 2);

        let mut seen_a = false;
        let mut seen_b = false;
        for i in 0..step.roa_delta_count {
            let mut d = lr_roa_delta_t {
                announce: 0,
                entry: lr_roa_entry_t {
                    addr: [0u8; 16],
                    is_ipv6: 0,
                    prefix_len: 0,
                    max_length: 0,
                    asn: 0,
                },
            };
            let rc = unsafe { lr_rtr_client_step_roa_delta_at(&raw const step, i, &raw mut d) };
            assert_eq!(rc, 0);
            assert_eq!(d.announce, 1);
            assert_eq!(d.entry.prefix_len, 24);
            assert_eq!(d.entry.max_length, 24);
            match &d.entry.addr[..4] {
                [192, 0, 2, 0] => {
                    assert_eq!(d.entry.asn, 64512);
                    seen_a = true;
                }
                [198, 51, 100, 0] => {
                    assert_eq!(d.entry.asn, 64513);
                    seen_b = true;
                }
                other => panic!("unexpected delta entry addr: {other:?}"),
            }
        }
        assert!(seen_a, "delta for 192.0.2.0/24 missing from step");
        assert!(seen_b, "delta for 198.51.100.0/24 missing from step");

        // Out-of-bounds returns -2 (LR_ERR_INVALID_HANDLE).
        let mut d0 = lr_roa_delta_t {
            announce: 0,
            entry: lr_roa_entry_t {
                addr: [0u8; 16],
                is_ipv6: 0,
                prefix_len: 0,
                max_length: 0,
                asn: 0,
            },
        };
        let rc = unsafe { lr_rtr_client_step_roa_delta_at(&raw const step, 2, &raw mut d0) };
        assert_eq!(rc, LrError::InvalidHandle as i32);

        // NULL step or out returns -1 (LR_ERR_NULL).
        let rc = unsafe { lr_rtr_client_step_roa_delta_at(std::ptr::null(), 0, &raw mut d0) };
        assert_eq!(rc, LR_ERR_NULL);
        let rc =
            unsafe { lr_rtr_client_step_roa_delta_at(&raw const step, 0, std::ptr::null_mut()) };
        assert_eq!(rc, LR_ERR_NULL);

        unsafe { lr_rtr_client_step_free(&raw mut step) };
        // After free, the arrays are NULL and the counts are zero.
        assert!(step.roa_deltas.is_null());
        assert!(step.logs.is_null());
        assert_eq!(step.roa_delta_count, 0);
        assert_eq!(step.log_count, 0);
        unsafe { lr_rtr_client_free(c) };
    }

    /// `lr_rtr_client_step_log_at` mirrors the count -> sized-buffer
    /// pattern that the rest of the C ABI uses for strings. A step
    /// whose `log_count` is zero has a NULL `logs` pointer and the
    /// accessor returns 0.
    #[test]
    fn ffi_rtr_client_step_log_at_on_empty_step() {
        let c = lr_rtr_client_new();
        let mut step = lr_rtr_client_step_t::default();
        let rc = unsafe { lr_rtr_client_poll(c, 0, &raw mut step) };
        assert_eq!(rc, 0);
        assert_eq!(step.log_count, 0);
        // Calling the accessor with an out-of-bounds index returns 0.
        let n = unsafe { lr_rtr_client_step_log_at(&raw const step, 0, std::ptr::null_mut(), 0) };
        assert_eq!(n, 0);
        // NULL step returns 0.
        let n = unsafe { lr_rtr_client_step_log_at(std::ptr::null(), 0, std::ptr::null_mut(), 0) };
        assert_eq!(n, 0);
        unsafe { lr_rtr_client_step_free(&raw mut step) };
        unsafe { lr_rtr_client_free(c) };
    }

    /// `lr_rtr_client_step_free` is safe to call with NULL.
    #[test]
    fn ffi_rtr_client_step_free_null_safely() {
        unsafe { lr_rtr_client_step_free(std::ptr::null_mut()) };
    }

    /// End-of-Data after a v2 sync that announced one BGPsec Router
    /// Key (RFC 8210 §5.10) and one ASPA record (§5.11) surfaces
    /// those two attestation classes through the new FFI arrays
    /// `router_key_deltas` and `aspa_deltas`. The test pins the
    /// end-to-end shape: the step's counts, the accessor round-trip
    /// for the SPKI blob and the providers ASN array, the
    /// out-of-bounds / NULL-pointer rc, and the post-`free` zero
    /// state.
    ///
    /// The test uses the Rust PDU encoder (`encode_vec`) to produce
    /// the wire bytes — the C ABI does not yet expose a per-PDU
    /// encoder, so the C harness can only exercise the empty-step
    /// path; this is the full-wire gate.
    #[test]
    fn ffi_rtr_client_step_router_key_and_aspa_deltas_after_v2_sync() {
        use lr_bgp::rtr::pdu::{encode_vec, RtrPdu, RTR_VERSION_2};
        let c = lr_rtr_client_new();

        // 1) Cache Response (v2 — both Router Key and ASPA are v2+).
        let cr = RtrPdu::CacheResponse { session_id: 0x0102 };
        let wire_cr = encode_vec(&cr, RTR_VERSION_2);
        let mut step = lr_rtr_client_step_t::default();
        let rc = unsafe {
            lr_rtr_client_on_pdu_raw(c, wire_cr.as_ptr(), wire_cr.len(), 1_000, &raw mut step)
        };
        assert_eq!(rc, 0);
        assert_eq!(step.router_key_delta_count, 0);
        assert_eq!(step.aspa_delta_count, 0);
        unsafe { lr_rtr_client_step_free(&raw mut step) };

        // 2) One Router Key PDU (RFC 8210 §5.10). The SPKI is a
        // hand-rolled DER-ish blob — the FFI does not parse it, so
        // any non-empty byte string round-trips.
        let ski = [
            0x01u8, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab,
            0xcd, 0xef, 0x01, 0x23, 0x45, 0x67,
        ];
        let spki = vec![
            0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06,
            0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04, 0x6f,
            0xad, 0x12, 0x34,
        ];
        let rk = RtrPdu::RouterKey {
            announce: true,
            ski,
            asn: 64512,
            subject_public_key_info: spki.clone(),
        };
        let wire_rk = encode_vec(&rk, RTR_VERSION_2);
        let rc = unsafe {
            lr_rtr_client_on_pdu_raw(c, wire_rk.as_ptr(), wire_rk.len(), 1_000, &raw mut step)
        };
        assert_eq!(rc, 0);
        assert_eq!(
            step.router_key_delta_count, 0,
            "Router Key PDU does not sync alone"
        );
        unsafe { lr_rtr_client_step_free(&raw mut step) };

        // 3) One ASPA PDU (RFC 8210 §5.11). The provider set is
        // canonicalised by the client — feed them out of order so
        // the test pins the ascending-order projection.
        let aspa = RtrPdu::Aspa {
            announce: true,
            customer_asn: 65000,
            providers: vec![65003, 65001, 65002],
        };
        let wire_aspa = encode_vec(&aspa, RTR_VERSION_2);
        let rc = unsafe {
            lr_rtr_client_on_pdu_raw(c, wire_aspa.as_ptr(), wire_aspa.len(), 1_000, &raw mut step)
        };
        assert_eq!(rc, 0);
        assert_eq!(step.aspa_delta_count, 0, "ASPA PDU does not sync alone");
        unsafe { lr_rtr_client_step_free(&raw mut step) };

        // 4) End-of-Data — the step the FFI surface returns now
        // carries the Router Key delta and the ASPA delta.
        let eod = RtrPdu::EndOfData {
            session_id: 0x0102,
            serial: 5,
            refresh_interval: Some(60),
            retry_interval: Some(30),
            expire_interval: Some(600),
        };
        let wire_eod = encode_vec(&eod, RTR_VERSION_2);
        let rc = unsafe {
            lr_rtr_client_on_pdu_raw(c, wire_eod.as_ptr(), wire_eod.len(), 1_000, &raw mut step)
        };
        assert_eq!(rc, 0);
        assert_eq!(step.synced, 1);
        assert_eq!(
            step.router_key_delta_count, 1,
            "one Router Key delta after EoD"
        );
        assert_eq!(step.aspa_delta_count, 1, "one ASPA delta after EoD");

        // Router Key delta: SPKI bytes round-trip verbatim; the
        // pointer borrows from the step's heap allocation and is
        // valid until `lr_rtr_client_step_free` runs.
        let mut rk_d = lr_router_key_delta_t {
            announce: 0,
            entry: lr_router_key_entry_t {
                ski: [0u8; 20],
                asn: 0,
                subject_public_key_info: std::ptr::null_mut(),
                subject_public_key_info_len: 0,
            },
        };
        let rc =
            unsafe { lr_rtr_client_step_router_key_delta_at(&raw const step, 0, &raw mut rk_d) };
        assert_eq!(rc, 0);
        assert_eq!(rk_d.announce, 1);
        assert_eq!(rk_d.entry.ski, ski);
        assert_eq!(rk_d.entry.asn, 64512);
        assert_eq!(rk_d.entry.subject_public_key_info_len, spki.len());
        assert!(!rk_d.entry.subject_public_key_info.is_null());
        // Read the SPKI bytes through the pointer; they must match
        // the bytes we fed in.
        let spki_got: Vec<u8> = unsafe {
            std::slice::from_raw_parts(
                rk_d.entry.subject_public_key_info,
                rk_d.entry.subject_public_key_info_len,
            )
            .to_vec()
        };
        assert_eq!(
            spki_got, spki,
            "SPKI bytes round-trip verbatim through the FFI pointer"
        );

        // ASPA delta: provider ASNs round-trip in ascending order;
        // the pointer borrows from the step's heap allocation and is
        // valid until `lr_rtr_client_step_free` runs.
        let mut aspa_d = lr_aspa_delta_t {
            announce: 0,
            entry: lr_aspa_entry_t {
                customer_asn: 0,
                providers: std::ptr::null_mut(),
                provider_count: 0,
            },
        };
        let rc = unsafe { lr_rtr_client_step_aspa_delta_at(&raw const step, 0, &raw mut aspa_d) };
        assert_eq!(rc, 0);
        assert_eq!(aspa_d.announce, 1);
        assert_eq!(aspa_d.entry.customer_asn, 65000);
        assert_eq!(aspa_d.entry.provider_count, 3);
        assert!(!aspa_d.entry.providers.is_null());
        // Read the provider ASNs through the pointer; they must be
        // in ascending order (65001, 65002, 65003) regardless of the
        // wire order we fed (65003, 65001, 65002).
        let providers_got: Vec<u32> = unsafe {
            std::slice::from_raw_parts(aspa_d.entry.providers, aspa_d.entry.provider_count).to_vec()
        };
        assert_eq!(
            providers_got,
            vec![65001, 65002, 65003],
            "provider ASNs are ascending"
        );

        // Out-of-bounds returns -2 (LR_ERR_INVALID_HANDLE).
        let rc =
            unsafe { lr_rtr_client_step_router_key_delta_at(&raw const step, 1, &raw mut rk_d) };
        assert_eq!(rc, LrError::InvalidHandle as i32);
        let rc = unsafe { lr_rtr_client_step_aspa_delta_at(&raw const step, 1, &raw mut aspa_d) };
        assert_eq!(rc, LrError::InvalidHandle as i32);

        // NULL step or out returns -1 (LR_ERR_NULL).
        let rc =
            unsafe { lr_rtr_client_step_router_key_delta_at(std::ptr::null(), 0, &raw mut rk_d) };
        assert_eq!(rc, LR_ERR_NULL);
        let rc = unsafe {
            lr_rtr_client_step_router_key_delta_at(&raw const step, 0, std::ptr::null_mut())
        };
        assert_eq!(rc, LR_ERR_NULL);
        let rc = unsafe { lr_rtr_client_step_aspa_delta_at(std::ptr::null(), 0, &raw mut aspa_d) };
        assert_eq!(rc, LR_ERR_NULL);
        let rc =
            unsafe { lr_rtr_client_step_aspa_delta_at(&raw const step, 0, std::ptr::null_mut()) };
        assert_eq!(rc, LR_ERR_NULL);

        unsafe { lr_rtr_client_step_free(&raw mut step) };
        // After free, all four new fields are NULL/zero.
        assert!(step.router_key_deltas.is_null());
        assert!(step.aspa_deltas.is_null());
        assert_eq!(step.router_key_delta_count, 0);
        assert_eq!(step.aspa_delta_count, 0);
        unsafe { lr_rtr_client_free(c) };
    }

    /// An ASPA announcement with an empty provider set (RFC 8210 §5.11
    /// permits it: "the customer is not a provider of any AS") and a
    /// Router Key announcement with an empty SPKI both round-trip with
    /// NULL pointers and zero counts on the entry — the FFI must not
    /// crash dereferencing a NULL `subject_public_key_info` or
    /// `providers` pointer.
    #[test]
    fn ffi_rtr_client_step_router_key_and_aspa_with_empty_payloads() {
        use lr_bgp::rtr::pdu::{encode_vec, RtrPdu, RTR_VERSION_2};
        let c = lr_rtr_client_new();
        // Cache Response.
        let cr = RtrPdu::CacheResponse { session_id: 0x0304 };
        let wire_cr = encode_vec(&cr, RTR_VERSION_2);
        let mut step = lr_rtr_client_step_t::default();
        let rc = unsafe {
            lr_rtr_client_on_pdu_raw(c, wire_cr.as_ptr(), wire_cr.len(), 1_000, &raw mut step)
        };
        assert_eq!(rc, 0);
        unsafe { lr_rtr_client_step_free(&raw mut step) };

        // Router Key with empty SPKI.
        let rk = RtrPdu::RouterKey {
            announce: true,
            ski: [0u8; 20],
            asn: 64513,
            subject_public_key_info: Vec::new(),
        };
        let wire_rk = encode_vec(&rk, RTR_VERSION_2);
        let rc = unsafe {
            lr_rtr_client_on_pdu_raw(c, wire_rk.as_ptr(), wire_rk.len(), 1_000, &raw mut step)
        };
        assert_eq!(rc, 0);
        unsafe { lr_rtr_client_step_free(&raw mut step) };

        // ASPA with empty provider set.
        let aspa = RtrPdu::Aspa {
            announce: true,
            customer_asn: 65010,
            providers: Vec::new(),
        };
        let wire_aspa = encode_vec(&aspa, RTR_VERSION_2);
        let rc = unsafe {
            lr_rtr_client_on_pdu_raw(c, wire_aspa.as_ptr(), wire_aspa.len(), 1_000, &raw mut step)
        };
        assert_eq!(rc, 0);
        unsafe { lr_rtr_client_step_free(&raw mut step) };

        // End-of-Data — the step's arrays carry both deltas; the
        // FFI must surface NULL pointers + zero lengths for the
        // empty payloads without crashing.
        let eod = RtrPdu::EndOfData {
            session_id: 0x0304,
            serial: 1,
            refresh_interval: Some(60),
            retry_interval: Some(30),
            expire_interval: Some(600),
        };
        let wire_eod = encode_vec(&eod, RTR_VERSION_2);
        let rc = unsafe {
            lr_rtr_client_on_pdu_raw(c, wire_eod.as_ptr(), wire_eod.len(), 1_000, &raw mut step)
        };
        assert_eq!(rc, 0);
        assert_eq!(step.synced, 1);
        assert_eq!(step.router_key_delta_count, 1);
        assert_eq!(step.aspa_delta_count, 1);

        let mut rk_d = lr_router_key_delta_t {
            announce: 0,
            entry: lr_router_key_entry_t {
                ski: [0u8; 20],
                asn: 0,
                subject_public_key_info: std::ptr::null_mut(),
                subject_public_key_info_len: 0,
            },
        };
        let rc =
            unsafe { lr_rtr_client_step_router_key_delta_at(&raw const step, 0, &raw mut rk_d) };
        assert_eq!(rc, 0);
        assert_eq!(rk_d.entry.subject_public_key_info_len, 0);
        assert!(rk_d.entry.subject_public_key_info.is_null());
        assert_eq!(rk_d.entry.asn, 64513);

        let mut aspa_d = lr_aspa_delta_t {
            announce: 0,
            entry: lr_aspa_entry_t {
                customer_asn: 0,
                providers: std::ptr::null_mut(),
                provider_count: 0,
            },
        };
        let rc = unsafe { lr_rtr_client_step_aspa_delta_at(&raw const step, 0, &raw mut aspa_d) };
        assert_eq!(rc, 0);
        assert_eq!(aspa_d.entry.provider_count, 0);
        assert!(aspa_d.entry.providers.is_null());
        assert_eq!(aspa_d.entry.customer_asn, 65010);

        unsafe { lr_rtr_client_step_free(&raw mut step) };
        unsafe { lr_rtr_client_free(c) };
    }

    // The unused-import suppressor: keep a no-op so the test module
    // does not get flagged for not testing anything.
    #[allow(dead_code)]
    fn _link_test() {}
}
