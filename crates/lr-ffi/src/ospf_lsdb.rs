//! OSPF LSDB + LSA FFI (RFC 2328 §12, RFC 5340 §A.4).
//!
//! Mirrors the public Rust API of `lr_ospf::lsdb::{Lsdb, LsaEntry,
//! InstallOutcome}` and `lr_ospf::lsa::{Lsa, LsaHeader, LsaKey}` so
//! an embedder can build, populate and inspect a link-state database
//! without going through the daemon's `DefaultRouter`. The lsdb
//! crate was previously invisible across the C ABI — embedders that
//! wanted to bring their own OSPF plumbing had to re-implement the
//! LSDB in C.
//!
//! # Naming note
//!
//! `inspection.rs` already exposes `lr_ospf_lsa_t` as a struct
//! projection (header fields + body bytes) for the
//! `lr_router_ospf_area_lsa` reader. This module uses the distinct
//! `lr_ospf_lsdb_*` and `lr_ospf_lsa_box_*` / `lr_ospf_lsa_hdr_*`
//! prefixes so the two surfaces do not collide — the C-side LSA
//! projection in this module is `lr_ospf_lsa_hdr_t`, the opaque
//! boxed-LSA handle is `lr_ospf_lsa_box_t`, and the opaque
//! boxed-LSA-header handle is `lr_ospf_lsa_hdr_box_t`.

#![allow(unused_unsafe)]

use lr_ospf::lsa::{Lsa, LsaHeader, LsaKey};
use lr_ospf::lsdb::{InstallOutcome, Lsdb};

use crate::error::{LrError, LR_ERR_PANIC};
use crate::guarded;
use crate::handle::lr_bytes_t;

const LR_ERR_NULL: i32 = LrError::Null as i32;
#[allow(dead_code)]
const LR_ERR_OTHER: i32 = LrError::Other as i32;

// ---- Opaque handle types ----

#[repr(C)]
pub struct OpaqueOspfLsdb {
    _private: [u8; 0],
}
pub type lr_ospf_lsdb_t = *mut OpaqueOspfLsdb;

#[repr(C)]
pub struct OpaqueOspfLsaBox {
    _private: [u8; 0],
}
/// Opaque boxed-LSA handle. The C-side LSA *projection* is
/// `lr_ospf_lsa_hdr_t` (a struct the caller can read fields from);
/// this is the boxed owned-LSA handle the embedder passes back to
/// `lr_ospf_lsa_*` functions.
pub type lr_ospf_lsa_box_t = *mut OpaqueOspfLsaBox;

#[repr(C)]
pub struct OpaqueOspfLsaHdrBox {
    _private: [u8; 0],
}
/// Opaque boxed-LSA-header handle (for the
/// `lr_ospf_lsa_header_new` / `_free` constructor / destructor pair).
pub type lr_ospf_lsa_hdr_box_t = *mut OpaqueOspfLsaHdrBox;

// ---- LSA header C-side projection ----

/// Fixed-layout projection of one LSA header (RFC 2328 §A.4.1).
/// Mirrors the header fields of `lr_ospf::lsa::LsaHeader` without
/// the body bytes (use `lr_ospf_lsa_body` to read the body).
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct lr_ospf_lsa_hdr_t {
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
}

impl From<&LsaHeader> for lr_ospf_lsa_hdr_t {
    fn from(h: &LsaHeader) -> Self {
        Self {
            ls_age: h.ls_age,
            options: h.options,
            ls_type: h.ls_type,
            link_state_id: h.link_state_id,
            advertising_router: h.advertising_router,
            ls_sequence_number: h.ls_sequence_number,
            ls_checksum: h.ls_checksum,
            length: h.length,
        }
    }
}

// ---- Lsdb box / unbox helpers ----

fn box_lsdb(d: Lsdb) -> lr_ospf_lsdb_t {
    Box::into_raw(Box::new(d)) as lr_ospf_lsdb_t
}
pub(crate) unsafe fn borrow_lsdb(r: lr_ospf_lsdb_t) -> Option<&'static Lsdb> {
    if r.is_null() {
        return None;
    }
    Some(unsafe { &*(r as *const Lsdb) })
}
pub(crate) unsafe fn borrow_lsdb_mut(r: lr_ospf_lsdb_t) -> Option<&'static mut Lsdb> {
    if r.is_null() {
        return None;
    }
    Some(unsafe { &mut *(r as *mut Lsdb) })
}
unsafe fn unbox_lsdb(r: lr_ospf_lsdb_t) -> Option<Box<Lsdb>> {
    if r.is_null() {
        return None;
    }
    Some(unsafe { Box::from_raw(r as *mut Lsdb) })
}

// ---- LSA box / unbox helpers ----

pub(crate) fn box_lsa(l: Lsa) -> lr_ospf_lsa_box_t {
    Box::into_raw(Box::new(l)) as lr_ospf_lsa_box_t
}
pub(crate) unsafe fn borrow_lsa(r: lr_ospf_lsa_box_t) -> Option<&'static Lsa> {
    if r.is_null() {
        return None;
    }
    Some(unsafe { &*(r as *const Lsa) })
}
pub(crate) unsafe fn borrow_lsa_mut(r: lr_ospf_lsa_box_t) -> Option<&'static mut Lsa> {
    if r.is_null() {
        return None;
    }
    Some(unsafe { &mut *(r as *mut Lsa) })
}
unsafe fn unbox_lsa(r: lr_ospf_lsa_box_t) -> Option<Box<Lsa>> {
    if r.is_null() {
        return None;
    }
    Some(unsafe { Box::from_raw(r as *mut Lsa) })
}

fn box_lsa_header(h: LsaHeader) -> lr_ospf_lsa_hdr_box_t {
    Box::into_raw(Box::new(h)) as lr_ospf_lsa_hdr_box_t
}
unsafe fn unbox_lsa_header(r: lr_ospf_lsa_hdr_box_t) -> Option<Box<LsaHeader>> {
    if r.is_null() {
        return None;
    }
    Some(unsafe { Box::from_raw(r as *mut LsaHeader) })
}

/// Translate an `InstallOutcome` to a C-side return code.
fn install_outcome_rc(o: InstallOutcome) -> i32 {
    match o {
        InstallOutcome::New => 1,
        InstallOutcome::Replaced => 2,
        InstallOutcome::Ignored => 0,
        InstallOutcome::Purged => 3,
    }
}

// ---- Lsdb surface ----

/// Construct an empty LSDB (RFC 2328 §12).
#[no_mangle]
pub extern "C" fn lr_ospf_lsdb_new() -> lr_ospf_lsdb_t {
    guarded(|| box_lsdb(Lsdb::new()), std::ptr::null_mut())
}

/// Drop a boxed LSDB. Safe to call with NULL.
///
/// # Safety
/// `r` must have been produced by `lr_ospf_lsdb_new` and not already freed.
#[no_mangle]
pub unsafe extern "C" fn lr_ospf_lsdb_free(r: lr_ospf_lsdb_t) {
    guarded(
        || unsafe {
            drop(unbox_lsdb(r));
        },
        (),
    )
}

/// Install one LSA into the LSDB (RFC 2328 §13). The `lsa` handle is
/// *consumed* — the caller must not use it after this call.
///
/// Returns:
/// - 0 = NoChange (byte-identical reinstall, no generation bump).
/// - 1 = NewEntry (a new LSA was added).
/// - 2 = Refreshed (an existing LSA was replaced with newer content).
/// - 3 = Duplicate (an older-instance duplicate was dropped).
/// - Negative on error.
///
/// # Safety
/// `r` must be a valid LSDB handle. `lsa` must be a valid LSA handle.
#[no_mangle]
pub unsafe extern "C" fn lr_ospf_lsdb_install(
    r: lr_ospf_lsdb_t,
    lsa: lr_ospf_lsa_box_t,
    now_ms: u64,
) -> i32 {
    guarded(
        || unsafe {
            let Some(lsdb) = borrow_lsdb_mut(r) else {
                return LR_ERR_NULL;
            };
            let Some(l) = unbox_lsa(lsa) else {
                return LR_ERR_NULL;
            };
            let outcome = lsdb.install(*l, now_ms);
            install_outcome_rc(outcome)
        },
        LR_ERR_PANIC,
    )
}

/// Remove one LSA by (ls_type, link_state_id, advertising_router).
/// Returns 1 when an LSA was removed, 0 when the key was absent.
///
/// # Safety
/// `r` must be a valid LSDB handle.
#[no_mangle]
pub unsafe extern "C" fn lr_ospf_lsdb_remove(
    r: lr_ospf_lsdb_t,
    ls_type: u16,
    link_state_id: u32,
    advertising_router: u32,
) -> i32 {
    guarded(
        || unsafe {
            let Some(lsdb) = borrow_lsdb_mut(r) else {
                return LR_ERR_NULL;
            };
            let key = LsaKey {
                ls_type,
                link_state_id,
                advertising_router,
            };
            if lsdb.remove(&key).is_some() {
                1
            } else {
                0
            }
        },
        LR_ERR_PANIC,
    )
}

/// Read one LSA by key. Returns 0 on success and writes a NEW
/// `lr_ospf_lsa_box_t` handle (a *copy* the caller frees via
/// `lr_ospf_lsa_free`) to `*out`. Returns 0 with `*out = NULL` when
/// the key is absent.
///
/// # Safety
/// `r` must be a valid LSDB handle. `out` must point to writable memory.
#[no_mangle]
pub unsafe extern "C" fn lr_ospf_lsdb_get(
    r: lr_ospf_lsdb_t,
    ls_type: u16,
    link_state_id: u32,
    advertising_router: u32,
    out: *mut lr_ospf_lsa_box_t,
) -> i32 {
    guarded(
        || unsafe {
            if out.is_null() {
                return LR_ERR_NULL;
            }
            let Some(lsdb) = borrow_lsdb(r) else {
                return LR_ERR_NULL;
            };
            let key = LsaKey {
                ls_type,
                link_state_id,
                advertising_router,
            };
            match lsdb.get(&key) {
                None => {
                    unsafe { *out = std::ptr::null_mut() }
                    0
                }
                Some(entry) => {
                    unsafe { *out = box_lsa(entry.lsa.clone()) }
                    0
                }
            }
        },
        LR_ERR_PANIC,
    )
}

/// Number of LSAs in the LSDB. Returns 0 on a NULL handle.
///
/// # Safety
/// `r` must be a valid LSDB handle.
#[no_mangle]
pub unsafe extern "C" fn lr_ospf_lsdb_len(r: lr_ospf_lsdb_t) -> usize {
    guarded(
        || unsafe { borrow_lsdb(r).map(|d| d.len()).unwrap_or(0) },
        0,
    )
}

/// True when the LSDB holds no LSAs. Returns 1 on a NULL handle.
///
/// # Safety
/// See [`lr_ospf_lsdb_len`].
#[no_mangle]
pub unsafe extern "C" fn lr_ospf_lsdb_is_empty(r: lr_ospf_lsdb_t) -> u8 {
    guarded(
        || unsafe { borrow_lsdb(r).map(|d| d.is_empty() as u8).unwrap_or(1) },
        1,
    )
}

/// Read every LSA header as a flat array (RFC 2328 §A.4.1). On success
/// writes a freshly-allocated `lr_ospf_lsa_hdr_t*` to `*out` and the
/// count to `*out_count`. The caller owns the array and must free it
/// via `lr_ospf_lsa_hdr_array_free`.
///
/// # Safety
/// `r` must be a valid LSDB handle. `out` and `out_count` must point
/// to writable memory.
#[no_mangle]
pub unsafe extern "C" fn lr_ospf_lsdb_headers(
    r: lr_ospf_lsdb_t,
    out: *mut *mut lr_ospf_lsa_hdr_t,
    out_count: *mut usize,
) -> i32 {
    guarded(
        || unsafe {
            if out.is_null() || out_count.is_null() {
                return LR_ERR_NULL;
            }
            let Some(lsdb) = borrow_lsdb(r) else {
                return LR_ERR_NULL;
            };
            let headers: Vec<lr_ospf_lsa_hdr_t> =
                lsdb.headers().iter().map(lr_ospf_lsa_hdr_t::from).collect();
            let count = headers.len();
            let mut boxed = headers.into_boxed_slice();
            let ptr = boxed.as_mut_ptr();
            std::mem::forget(boxed);
            unsafe {
                *out = ptr;
                *out_count = count;
            }
            0
        },
        LR_ERR_PANIC,
    )
}

/// Free an LSA header array returned by `lr_ospf_lsdb_headers`. Safe
/// to call with NULL.
///
/// # Safety
/// `ptr` must have been produced by `lr_ospf_lsdb_headers` and `count`
/// must be the value written to `*out_count` by that call.
#[no_mangle]
pub unsafe extern "C" fn lr_ospf_lsa_hdr_array_free(ptr: *mut lr_ospf_lsa_hdr_t, count: usize) {
    guarded(
        || unsafe {
            if ptr.is_null() || count == 0 {
                return;
            }
            let slice = unsafe { std::slice::from_raw_parts_mut(ptr, count) };
            let _ = unsafe { Box::from_raw(slice as *mut [lr_ospf_lsa_hdr_t]) };
        },
        (),
    )
}

// ---- LSA surface ----

/// Construct an LSA from a header handle + body bytes. The header
/// handle is *consumed*. Returns NULL on a NULL header.
///
/// # Safety
/// `header` must be a valid LSA header handle. `body` must point to
/// `body_len` readable bytes (NULL only when `body_len == 0`).
#[no_mangle]
pub unsafe extern "C" fn lr_ospf_lsa_new(
    header: lr_ospf_lsa_hdr_box_t,
    body: *const u8,
    body_len: usize,
) -> lr_ospf_lsa_box_t {
    guarded(
        || unsafe {
            let Some(h) = unbox_lsa_header(header) else {
                return std::ptr::null_mut();
            };
            let body_vec = if body.is_null() || body_len == 0 {
                Vec::new()
            } else {
                unsafe { std::slice::from_raw_parts(body, body_len) }.to_vec()
            };
            box_lsa(Lsa {
                header: *h,
                body: body_vec,
            })
        },
        std::ptr::null_mut(),
    )
}

/// Read the header fields of an LSA into `*out`. Returns 0 on success.
///
/// # Safety
/// `lsa` must be a valid LSA handle. `out` must point to writable
/// memory of size `lr_ospf_lsa_hdr_t`.
#[no_mangle]
pub unsafe extern "C" fn lr_ospf_lsa_header_get(
    lsa: lr_ospf_lsa_box_t,
    out: *mut lr_ospf_lsa_hdr_t,
) -> i32 {
    guarded(
        || unsafe {
            if out.is_null() {
                return LR_ERR_NULL;
            }
            let Some(l) = borrow_lsa(lsa) else {
                return LR_ERR_NULL;
            };
            unsafe { *out = lr_ospf_lsa_hdr_t::from(&l.header) }
            0
        },
        LR_ERR_PANIC,
    )
}

/// Read the body bytes of an LSA. Returns 0 on success and writes a
/// freshly-allocated `lr_bytes_t` to `*out` (the caller frees via
/// `lr_bytes_free`).
///
/// # Safety
/// `lsa` must be a valid LSA handle. `out` must point to writable memory.
#[no_mangle]
pub unsafe extern "C" fn lr_ospf_lsa_body(lsa: lr_ospf_lsa_box_t, out: *mut lr_bytes_t) -> i32 {
    guarded(
        || unsafe {
            if out.is_null() {
                return LR_ERR_NULL;
            }
            let Some(l) = borrow_lsa(lsa) else {
                return LR_ERR_NULL;
            };
            unsafe { *out = lr_bytes_t::from_vec(l.body.clone()) }
            0
        },
        LR_ERR_PANIC,
    )
}

/// Encode the LSA as the 20-byte header + body (RFC 2328 §A.4 wire
/// form). Returns 0 on success and writes a freshly-allocated
/// `lr_bytes_t` to `*out`.
///
/// # Safety
/// `lsa` must be a valid LSA handle. `out` must point to writable memory.
#[no_mangle]
pub unsafe extern "C" fn lr_ospf_lsa_to_wire(lsa: lr_ospf_lsa_box_t, out: *mut lr_bytes_t) -> i32 {
    guarded(
        || unsafe {
            if out.is_null() {
                return LR_ERR_NULL;
            }
            let Some(l) = borrow_lsa(lsa) else {
                return LR_ERR_NULL;
            };
            unsafe { *out = lr_bytes_t::from_vec(l.to_wire()) }
            0
        },
        LR_ERR_PANIC,
    )
}

/// Drop a boxed LSA. Safe to call with NULL.
///
/// # Safety
/// `lsa` must have been produced by `lr_ospf_lsa_new` /
/// `lr_ospf_lsdb_get` and not already freed.
#[no_mangle]
pub unsafe extern "C" fn lr_ospf_lsa_free(lsa: lr_ospf_lsa_box_t) {
    guarded(
        || unsafe {
            drop(unbox_lsa(lsa));
        },
        (),
    )
}

/// Compute and store the LSA's Fletcher-16 checksum (RFC 2328 §C.4)
/// and the length field, in place. Subsequent `lr_ospf_lsa_to_wire`
/// calls produce a wire form that round-trips through
/// `lr_ospf_lsa_checksum_ok`. Returns 0 on success, `LR_ERR_NULL`
/// on a NULL handle.
///
/// # Safety
/// `lsa` must be a valid LSA handle.
#[no_mangle]
pub unsafe extern "C" fn lr_ospf_lsa_finalize(lsa: lr_ospf_lsa_box_t) -> i32 {
    guarded(
        || unsafe {
            let Some(l) = borrow_lsa_mut(lsa) else {
                return LR_ERR_NULL;
            };
            l.finalize();
            0
        },
        LR_ERR_PANIC,
    )
}

/// Verify the LSA's Fletcher-16 checksum (RFC 2328 §C.4). Returns 1
/// when the checksum is valid, 0 otherwise (including on a NULL
/// handle).
///
/// This is the LSA-handle variant; the raw-bytes variant
/// `lr_ospf_lsa_checksum_ok` in `core_extras.rs` operates on a flat
/// byte buffer without going through an LSA handle.
///
/// # Safety
/// `lsa` must be a valid LSA handle.
#[no_mangle]
pub unsafe extern "C" fn lr_ospf_lsa_handle_checksum_ok(lsa: lr_ospf_lsa_box_t) -> u8 {
    guarded(
        || unsafe { borrow_lsa(lsa).map(|l| l.checksum_ok() as u8).unwrap_or(0) },
        0,
    )
}

/// Build a MaxAge-flush copy of the LSA (RFC 2328 §14: ls_age =
/// MaxAge, sequence number bumped). Writes a new LSA handle to
/// `*out` (caller frees with `lr_ospf_lsa_free`). Returns 1 when a
/// flush was produced, 0 when the LSA cannot be flushed (e.g. it is
/// already MaxAge) or the input handle is NULL.
///
/// # Safety
/// `lsa` must be a valid LSA handle. `out` must point to a writable
/// `lr_ospf_lsa_box_t`.
#[no_mangle]
pub unsafe extern "C" fn lr_ospf_lsa_maxage_flush(
    lsa: lr_ospf_lsa_box_t,
    out: *mut lr_ospf_lsa_box_t,
) -> u8 {
    guarded(
        || unsafe {
            if out.is_null() {
                return 0;
            }
            let Some(l) = borrow_lsa(lsa) else {
                return 0;
            };
            match l.maxage_flush() {
                Some(flushed) => {
                    unsafe { *out = box_lsa(flushed) }
                    1
                }
                None => 0,
            }
        },
        0,
    )
}

/// Compute the LSA's key (RFC 2328 §12.1 — `(ls_type, link_state_id,
/// advertising_router)`). Writes the three fields to the out-pointers.
/// Returns 0 on success, `LR_ERR_NULL` on a NULL handle.
///
/// # Safety
/// `lsa` must be a valid LSA handle. `out_ls_type`, `out_link_state_id`
/// and `out_advertising_router` must point to writable `uint16_t` /
/// `uint32_t` / `uint32_t`.
#[no_mangle]
pub unsafe extern "C" fn lr_ospf_lsa_key(
    lsa: lr_ospf_lsa_box_t,
    out_ls_type: *mut u16,
    out_link_state_id: *mut u32,
    out_advertising_router: *mut u32,
) -> i32 {
    guarded(
        || unsafe {
            let Some(l) = borrow_lsa(lsa) else {
                return LR_ERR_NULL;
            };
            if out_ls_type.is_null()
                || out_link_state_id.is_null()
                || out_advertising_router.is_null()
            {
                return LR_ERR_NULL;
            }
            let key = l.key();
            unsafe {
                *out_ls_type = key.ls_type;
                *out_link_state_id = key.link_state_id;
                *out_advertising_router = key.advertising_router;
            }
            0
        },
        LR_ERR_PANIC,
    )
}

// ---- LSA header surface ----

/// Construct an LSA header from the 8 fields (RFC 2328 §A.4.1).
#[no_mangle]
pub extern "C" fn lr_ospf_lsa_header_new(
    ls_age: u16,
    options: u8,
    ls_type: u16,
    link_state_id: u32,
    advertising_router: u32,
    ls_sequence_number: u32,
    ls_checksum: u16,
    length: u16,
) -> lr_ospf_lsa_hdr_box_t {
    guarded(
        || {
            box_lsa_header(LsaHeader {
                ls_age,
                options,
                ls_type,
                link_state_id,
                advertising_router,
                ls_sequence_number,
                ls_checksum,
                length,
            })
        },
        std::ptr::null_mut(),
    )
}

/// Drop a boxed LSA header. Safe to call with NULL.
///
/// # Safety
/// `h` must have been produced by `lr_ospf_lsa_header_new` and not
/// already freed.
#[no_mangle]
pub unsafe extern "C" fn lr_ospf_lsa_header_free(h: lr_ospf_lsa_hdr_box_t) {
    guarded(
        || unsafe {
            drop(unbox_lsa_header(h));
        },
        (),
    )
}

// ---- LSA-array surface (refresh_due / age_out) ----
//
// `Lsdb::refresh_due` and `Lsdb::age_out` return `Vec<Lsa>` — the
// embedder owns the LSAs and must re-flood them. The FFI returns a
// heap-allocated array of `lr_ospf_lsa_box_t` handles (one per LSA),
// plus a matching free function.

/// Returns the LSAs whose `ls_sequence_number` is due for refresh
/// (RFC 2328 §14.1 — `LSRefreshTime`, 30 minutes by default). The
/// embedder re-originates each LSA (bumping the sequence, zeroing
/// the age) and re-installs it via [`lr_ospf_lsdb_install`].
///
/// `advertising_router` is the router-id whose self-originated LSAs
/// to refresh (RFC 2328 §14.1 only refreshes LSAs originated by
/// this router). Pass 0 to match all LSAs (useful for tests).
///
/// Writes a freshly-allocated `lr_ospf_lsa_box_t*` array to `*out`
/// and the count to `*out_count`. The caller owns the array and each
/// LSA handle inside it; free the array via
/// [`lr_ospf_lsa_array_free`] (which also frees each LSA handle).
///
/// Returns 0 on success, `LR_ERR_NULL` (-1) on a null handle / null
/// out pointer, `LR_ERR_PANIC` (-4) on a panic.
///
/// # Safety
/// `r` must be a valid LSDB handle. `out` and `out_count` must point
/// to writable memory.
#[no_mangle]
pub unsafe extern "C" fn lr_ospf_lsdb_refresh_due(
    r: lr_ospf_lsdb_t,
    advertising_router: u32,
    now_ms: u64,
    out: *mut *mut lr_ospf_lsa_box_t,
    out_count: *mut usize,
) -> i32 {
    guarded(
        || unsafe {
            if out.is_null() || out_count.is_null() {
                return LR_ERR_NULL;
            }
            let Some(lsdb) = borrow_lsdb_mut(r) else {
                return LR_ERR_NULL;
            };
            let lsas: Vec<Lsa> = lsdb.refresh_due(advertising_router, now_ms);
            let handles: Vec<lr_ospf_lsa_box_t> = lsas.into_iter().map(box_lsa).collect();
            let count = handles.len();
            let mut boxed = handles.into_boxed_slice();
            let ptr = boxed.as_mut_ptr();
            std::mem::forget(boxed);
            unsafe {
                *out = ptr;
                *out_count = count;
            }
            0
        },
        LR_ERR_PANIC,
    )
}

/// Ages out LSAs that have reached `MaxAge` (RFC 2328 §14 — MaxAge
/// is 3600 seconds). Returns the LSAs that were purged from the
/// LSDB; the embedder re-floods them as MaxAge LSAs to flush them
/// from neighbors' LSDBs.
///
/// Writes a freshly-allocated `lr_ospf_lsa_box_t*` array to `*out`
/// and the count to `*out_count`. The caller owns the array and each
/// LSA handle inside it; free via [`lr_ospf_lsa_array_free`].
///
/// # Safety
/// `r` must be a valid LSDB handle. `out` and `out_count` must point
/// to writable memory.
#[no_mangle]
pub unsafe extern "C" fn lr_ospf_lsdb_age_out(
    r: lr_ospf_lsdb_t,
    now_ms: u64,
    out: *mut *mut lr_ospf_lsa_box_t,
    out_count: *mut usize,
) -> i32 {
    guarded(
        || unsafe {
            if out.is_null() || out_count.is_null() {
                return LR_ERR_NULL;
            }
            let Some(lsdb) = borrow_lsdb_mut(r) else {
                return LR_ERR_NULL;
            };
            let lsas: Vec<Lsa> = lsdb.age_out(now_ms);
            let handles: Vec<lr_ospf_lsa_box_t> = lsas.into_iter().map(box_lsa).collect();
            let count = handles.len();
            let mut boxed = handles.into_boxed_slice();
            let ptr = boxed.as_mut_ptr();
            std::mem::forget(boxed);
            unsafe {
                *out = ptr;
                *out_count = count;
            }
            0
        },
        LR_ERR_PANIC,
    )
}

/// Free an LSA handle array returned by [`lr_ospf_lsdb_refresh_due`]
/// or [`lr_ospf_lsdb_age_out`]. Also frees each LSA handle inside the
/// array. Safe to call with NULL / count=0.
///
/// # Safety
/// `ptr` must have been produced by `lr_ospf_lsdb_refresh_due` or
/// `lr_ospf_lsdb_age_out`, and `count` must be the value written to
/// `*out_count` by that call. Double-free is undefined behaviour.
#[no_mangle]
pub unsafe extern "C" fn lr_ospf_lsa_array_free(ptr: *mut lr_ospf_lsa_box_t, count: usize) {
    guarded(
        || unsafe {
            if ptr.is_null() || count == 0 {
                return;
            }
            let slice = unsafe { std::slice::from_raw_parts_mut(ptr, count) };
            // Free each LSA handle inside the array.
            for handle in slice.iter() {
                if !handle.is_null() {
                    drop(unbox_lsa(*handle));
                }
            }
            // Free the array itself.
            let _ = unsafe { Box::from_raw(slice as *mut [lr_ospf_lsa_box_t]) };
        },
        (),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_lsa(seq: u32) -> Lsa {
        Lsa {
            header: LsaHeader {
                ls_age: 1,
                options: 0,
                ls_type: 1,
                link_state_id: 0x01020304,
                advertising_router: 0x01020304,
                ls_sequence_number: seq,
                ls_checksum: 0xabcd,
                length: 20,
            },
            body: vec![0xde, 0xad, 0xbe, 0xef],
        }
    }

    fn box_lsa_for_test(l: Lsa) -> lr_ospf_lsa_box_t {
        box_lsa(l)
    }

    #[test]
    fn ffi_ospf_lsdb_install_and_get() {
        let lsdb = lr_ospf_lsdb_new();
        assert!(!lsdb.is_null());
        assert_eq!(unsafe { lr_ospf_lsdb_is_empty(lsdb) }, 1);

        let lsa = box_lsa_for_test(sample_lsa(0x80000001));
        let rc = unsafe { lr_ospf_lsdb_install(lsdb, lsa, 0) };
        assert_eq!(rc, 1, "first install is New");
        assert_eq!(unsafe { lr_ospf_lsdb_len(lsdb) }, 1);
        assert_eq!(unsafe { lr_ospf_lsdb_is_empty(lsdb) }, 0);

        // Get it back.
        let mut out: lr_ospf_lsa_box_t = std::ptr::null_mut();
        let rc = unsafe { lr_ospf_lsdb_get(lsdb, 1, 0x01020304, 0x01020304, &raw mut out) };
        assert_eq!(rc, 0);
        assert!(!out.is_null());

        // Read the header back.
        let mut hdr = lr_ospf_lsa_hdr_t::default();
        let rc = unsafe { lr_ospf_lsa_header_get(out, &raw mut hdr) };
        assert_eq!(rc, 0);
        assert_eq!(hdr.ls_type, 1);
        assert_eq!(hdr.link_state_id, 0x01020304);
        assert_eq!(hdr.ls_sequence_number, 0x80000001);

        // Read the body back.
        let mut body = lr_bytes_t {
            ptr: std::ptr::null_mut(),
            len: 0,
            cap: 0,
        };
        let rc = unsafe { lr_ospf_lsa_body(out, &raw mut body) };
        assert_eq!(rc, 0);
        assert_eq!(body.len, 4);
        unsafe { crate::bytes::lr_bytes_free(&raw mut body) };

        unsafe { lr_ospf_lsa_free(out) };

        // Reinstall the same LSA (same sequence) — should be Ignored.
        let lsa2 = box_lsa_for_test(sample_lsa(0x80000001));
        let rc = unsafe { lr_ospf_lsdb_install(lsdb, lsa2, 0) };
        assert_eq!(rc, 0, "duplicate-instance reinstall is Ignored");

        // Install a newer instance — should be Replaced.
        let lsa3 = box_lsa_for_test(sample_lsa(0x80000002));
        let rc = unsafe { lr_ospf_lsdb_install(lsdb, lsa3, 0) };
        assert_eq!(rc, 2, "newer instance is Replaced");

        // Remove.
        let rc = unsafe { lr_ospf_lsdb_remove(lsdb, 1, 0x01020304, 0x01020304) };
        assert_eq!(rc, 1);
        assert_eq!(unsafe { lr_ospf_lsdb_is_empty(lsdb) }, 1);

        unsafe { lr_ospf_lsdb_free(lsdb) };
    }

    #[test]
    fn ffi_ospf_lsdb_headers_array() {
        let lsdb = lr_ospf_lsdb_new();
        let lsa1 = box_lsa_for_test(sample_lsa(0x80000001));
        let _ = unsafe { lr_ospf_lsdb_install(lsdb, lsa1, 0) };
        let lsa2 = box_lsa_for_test(Lsa {
            header: LsaHeader {
                ls_type: 1,
                link_state_id: 0x05060708,
                advertising_router: 0x01020304,
                ls_sequence_number: 0x80000001,
                ..sample_lsa(0).header
            },
            body: vec![],
        });
        let _ = unsafe { lr_ospf_lsdb_install(lsdb, lsa2, 0) };

        let mut ptr: *mut lr_ospf_lsa_hdr_t = std::ptr::null_mut();
        let mut count: usize = 0;
        let rc = unsafe { lr_ospf_lsdb_headers(lsdb, &raw mut ptr, &raw mut count) };
        assert_eq!(rc, 0);
        assert_eq!(count, 2);

        unsafe { lr_ospf_lsa_hdr_array_free(ptr, count) };
        unsafe { lr_ospf_lsdb_free(lsdb) };
    }

    #[test]
    fn ffi_ospf_lsa_new_and_to_wire() {
        let hdr = lr_ospf_lsa_header_new(1, 0, 1, 0x01020304, 0x01020304, 0x80000001, 0xabcd, 24);
        let body = [0xde, 0xad, 0xbe, 0xef];
        let lsa = unsafe { lr_ospf_lsa_new(hdr, body.as_ptr(), body.len()) };
        assert!(!lsa.is_null());

        let mut wire = lr_bytes_t {
            ptr: std::ptr::null_mut(),
            len: 0,
            cap: 0,
        };
        let rc = unsafe { lr_ospf_lsa_to_wire(lsa, &raw mut wire) };
        assert_eq!(rc, 0);
        // 20-byte header + 4-byte body = 24 bytes.
        assert_eq!(wire.len, 24);
        unsafe { crate::bytes::lr_bytes_free(&raw mut wire) };

        unsafe { lr_ospf_lsa_free(lsa) };
    }

    #[test]
    fn ffi_ospf_lsdb_handles_null_safely() {
        assert_eq!(unsafe { lr_ospf_lsdb_len(std::ptr::null_mut()) }, 0);
        assert_eq!(unsafe { lr_ospf_lsdb_is_empty(std::ptr::null_mut()) }, 1);
        unsafe { lr_ospf_lsdb_free(std::ptr::null_mut()) };
        unsafe { lr_ospf_lsa_free(std::ptr::null_mut()) };
        unsafe { lr_ospf_lsa_header_free(std::ptr::null_mut()) };
    }

    #[test]
    fn ffi_ospf_lsa_finalize_and_checksum_ok_round_trip() {
        // `lr_ospf_lsa_new` consumes the header handle (unbox_lsa_header
        // takes ownership), so we do NOT free it separately.
        let hdr = lr_ospf_lsa_header_new(1, 0, 1, 0x01020304, 0x01020304, 0x80000001, 0, 0);
        let body = [0u8; 4]; // 4 bytes body.
        let lsa = unsafe { lr_ospf_lsa_new(hdr, body.as_ptr(), body.len()) };
        assert!(!lsa.is_null());
        // Before finalize, checksum is zero → checksum_ok returns false.
        assert_eq!(unsafe { lr_ospf_lsa_handle_checksum_ok(lsa) }, 0);
        // Finalize computes the checksum and length in place.
        assert_eq!(unsafe { lr_ospf_lsa_finalize(lsa) }, 0);
        // After finalize, checksum_ok returns true.
        assert_eq!(unsafe { lr_ospf_lsa_handle_checksum_ok(lsa) }, 1);
        unsafe { lr_ospf_lsa_free(lsa) };
    }

    #[test]
    fn ffi_ospf_lsa_key_round_trip() {
        let hdr = lr_ospf_lsa_header_new(
            1, 0, 0x2003, // OSPFv3 Inter-Area-Prefix.
            0x0a0b0c0d, 0x01020304, 0x80000001, 0, 0,
        );
        let body = [0u8; 4];
        let lsa = unsafe { lr_ospf_lsa_new(hdr, body.as_ptr(), body.len()) };
        let mut ls_type = 0u16;
        let mut ls_id = 0u32;
        let mut adv = 0u32;
        assert_eq!(
            unsafe { lr_ospf_lsa_key(lsa, &raw mut ls_type, &raw mut ls_id, &raw mut adv) },
            0
        );
        assert_eq!(ls_type, 0x2003);
        assert_eq!(ls_id, 0x0a0b0c0d);
        assert_eq!(adv, 0x01020304);
        unsafe { lr_ospf_lsa_free(lsa) };
    }

    #[test]
    fn ffi_ospf_lsdb_refresh_due_returns_empty_on_fresh_lsdb() {
        let lsdb = lr_ospf_lsdb_new();
        let mut ptr: *mut lr_ospf_lsa_box_t = std::ptr::null_mut();
        let mut count: usize = 0;
        let rc =
            unsafe { lr_ospf_lsdb_refresh_due(lsdb, 0x01020304, 0, &raw mut ptr, &raw mut count) };
        assert_eq!(rc, 0);
        assert_eq!(count, 0, "fresh LSDB has no LSAs due for refresh");
        // Free the (empty) array — safe even when count == 0.
        unsafe { lr_ospf_lsa_array_free(ptr, count) };
        unsafe { lr_ospf_lsdb_free(lsdb) };
    }

    #[test]
    fn ffi_ospf_lsdb_refresh_due_returns_lsas_past_ls_refresh_time() {
        let lsdb = lr_ospf_lsdb_new();
        // Install one LSA with ls_age=0 at now_ms=0. The refresh_due
        // gate is `now_ms - installed_ms + ls_age*1000 >= 1800*1000`.
        // With now_ms=0, installed_ms=0, ls_age=0 → 0 < 1800000 → not due.
        let lsa = box_lsa_for_test(sample_lsa(0x80000001));
        let rc = unsafe { lr_ospf_lsdb_install(lsdb, lsa, 0) };
        assert_eq!(rc, 1);

        // refresh_due at now_ms=0 → not due.
        let mut ptr: *mut lr_ospf_lsa_box_t = std::ptr::null_mut();
        let mut count: usize = 0;
        let rc =
            unsafe { lr_ospf_lsdb_refresh_due(lsdb, 0x01020304, 0, &raw mut ptr, &raw mut count) };
        assert_eq!(rc, 0);
        assert_eq!(count, 0, "LSA installed at t=0 is not due at t=0");
        unsafe { lr_ospf_lsa_array_free(ptr, count) };

        // refresh_due at now_ms=1_800_000 (30 min) → due.
        let rc = unsafe {
            lr_ospf_lsdb_refresh_due(lsdb, 0x01020304, 1_800_000, &raw mut ptr, &raw mut count)
        };
        assert_eq!(rc, 0);
        assert_eq!(count, 1, "LSA is due at LSRefreshTime");
        assert!(!ptr.is_null());
        // Free the array + each LSA handle inside it.
        unsafe { lr_ospf_lsa_array_free(ptr, count) };
        unsafe { lr_ospf_lsdb_free(lsdb) };
    }

    #[test]
    fn ffi_ospf_lsdb_refresh_due_filters_by_advertising_router() {
        let lsdb = lr_ospf_lsdb_new();
        // Install an LSA with advertising_router = 0x01020304.
        let lsa = box_lsa_for_test(sample_lsa(0x80000001));
        unsafe { lr_ospf_lsdb_install(lsdb, lsa, 0) };

        // refresh_due for a different advertising_router → no LSAs.
        let mut ptr: *mut lr_ospf_lsa_box_t = std::ptr::null_mut();
        let mut count: usize = 0;
        let rc = unsafe {
            lr_ospf_lsdb_refresh_due(
                lsdb,
                0x99999999, // different router-id
                1_800_000,
                &raw mut ptr,
                &raw mut count,
            )
        };
        assert_eq!(rc, 0);
        assert_eq!(count, 0, "different advertising_router → no LSAs");
        unsafe { lr_ospf_lsa_array_free(ptr, count) };
        unsafe { lr_ospf_lsdb_free(lsdb) };
    }

    #[test]
    fn ffi_ospf_lsdb_age_out_returns_empty_on_fresh_lsdb() {
        let lsdb = lr_ospf_lsdb_new();
        let mut ptr: *mut lr_ospf_lsa_box_t = std::ptr::null_mut();
        let mut count: usize = 0;
        let rc = unsafe { lr_ospf_lsdb_age_out(lsdb, 0, &raw mut ptr, &raw mut count) };
        assert_eq!(rc, 0);
        assert_eq!(count, 0, "fresh LSDB has no LSAs to age out");
        unsafe { lr_ospf_lsa_array_free(ptr, count) };
        unsafe { lr_ospf_lsdb_free(lsdb) };
    }

    #[test]
    fn ffi_ospf_lsdb_age_out_returns_lsas_at_max_age() {
        let lsdb = lr_ospf_lsdb_new();
        // Install one LSA with ls_age=1 at now_ms=0.
        let lsa = box_lsa_for_test(sample_lsa(0x80000001));
        unsafe { lr_ospf_lsdb_install(lsdb, lsa, 0) };
        assert_eq!(unsafe { lr_ospf_lsdb_len(lsdb) }, 1);

        // age_out at now_ms=0 → nothing aged out (ls_age=1, installed at 0,
        // effective age = 1s << MaxAge 3600s).
        let mut ptr: *mut lr_ospf_lsa_box_t = std::ptr::null_mut();
        let mut count: usize = 0;
        let rc = unsafe { lr_ospf_lsdb_age_out(lsdb, 0, &raw mut ptr, &raw mut count) };
        assert_eq!(rc, 0);
        assert_eq!(count, 0, "LSA at age 1s is not at MaxAge");
        assert_eq!(unsafe { lr_ospf_lsdb_len(lsdb) }, 1, "LSA still in LSDB");
        unsafe { lr_ospf_lsa_array_free(ptr, count) };

        // age_out at now_ms = 3_600_000 (1 hour) → LSA reaches MaxAge.
        let rc = unsafe { lr_ospf_lsdb_age_out(lsdb, 3_600_000, &raw mut ptr, &raw mut count) };
        assert_eq!(rc, 0);
        assert_eq!(count, 1, "LSA reached MaxAge");
        assert_eq!(
            unsafe { lr_ospf_lsdb_len(lsdb) },
            0,
            "aged-out LSA removed from LSDB"
        );
        unsafe { lr_ospf_lsa_array_free(ptr, count) };
        unsafe { lr_ospf_lsdb_free(lsdb) };
    }

    #[test]
    fn ffi_ospf_lsa_array_free_handles_null_safely() {
        unsafe { lr_ospf_lsa_array_free(std::ptr::null_mut(), 0) };
    }

    #[test]
    fn ffi_ospf_lsdb_refresh_due_null_handle_returns_lr_err_null() {
        let mut ptr: *mut lr_ospf_lsa_box_t = std::ptr::null_mut();
        let mut count: usize = 0;
        let rc = unsafe {
            lr_ospf_lsdb_refresh_due(std::ptr::null_mut(), 0, 0, &raw mut ptr, &raw mut count)
        };
        assert_eq!(rc, LR_ERR_NULL);
    }

    #[test]
    fn ffi_ospf_lsdb_age_out_null_handle_returns_lr_err_null() {
        let mut ptr: *mut lr_ospf_lsa_box_t = std::ptr::null_mut();
        let mut count: usize = 0;
        let rc =
            unsafe { lr_ospf_lsdb_age_out(std::ptr::null_mut(), 0, &raw mut ptr, &raw mut count) };
        assert_eq!(rc, LR_ERR_NULL);
    }
}
