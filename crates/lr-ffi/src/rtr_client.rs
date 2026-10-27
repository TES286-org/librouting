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
//! Every entry point runs inside the crate's `catch_unwind` barrier
//! ([`crate::guarded`]): a panic returns `LR_ERR_PANIC` and sets the
//! thread-local last-error string.

#![allow(unused_unsafe)]

use lr_bgp::rtr::client::{ClientStep, RtrClient};
use lr_bgp::rtr::pdu::decode as decode_pdu;

use crate::error::{set_last_error, LrError, LR_ERR_PANIC};
use crate::guarded;
use crate::handle::lr_bytes_t;
use crate::roa_store::lr_roa_entry_t;

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
unsafe fn unbox_client(c: lr_rtr_client_t) -> Option<Box<RtrClient>> {
    if c.is_null() {
        return None;
    }
    Some(unsafe { Box::from_raw(c as *mut RtrClient) })
}

/// One `ClientStep` projection — what the embedder should do after
/// one protocol step. The `send_bytes` field carries the wire bytes
/// to transmit (NULL `lr_bytes_t` when empty); `roa_deltas` carries
/// the atomic ROA deltas at End of Data; the boolean flags surface
/// `synced` / `drop` / `expired`.
#[repr(C)]
pub struct lr_rtr_client_step_t {
    /// Wire bytes to transmit (zero or more complete PDUs). NULL when
    /// empty — caller must call `lr_bytes_free` to release.
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
    lr_rtr_client_step_t {
        send_bytes: lr_bytes_t::from_vec(step.send),
        synced: step.synced as u8,
        drop: step.drop as u8,
        expired: step.expired as u8,
        roa_delta_count: step.roa_deltas.len(),
        log_count: step.logs.len(),
    }
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
        // send_bytes is empty (length 0; the ptr may be the Vec's
        // dangling pointer for an empty Vec, so check len not ptr).
        assert_eq!(step.send_bytes.len, 0);
        // The caller is responsible for freeing — even an empty
        // bytes handle must go through lr_bytes_free.
        unsafe { crate::bytes::lr_bytes_free(&raw mut step.send_bytes) };
        unsafe { lr_rtr_client_free(c) };
    }

    // The unused-import suppressor: keep a no-op so the test module
    // does not get flagged for not testing anything.
    #[allow(dead_code)]
    fn _link_test() {}
}
