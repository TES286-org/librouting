//! OSPF authentication C ABI (RFC 2328 §D, RFC 5709, RFC 7166).
//!
//! Mirrors the public Rust API of `lr_ospf::auth::{AuType, SimplePassword,
//! CryptoAuth, CryptoAlgorithm, V3Auth}` so an embedder can construct
//! and inspect OSPF authentication objects without going through the
//! Rust compiler.
//!
//! # Surface
//!
//! - `lr_ospf_au_type_*` — `AuType` enum conversions + constants.
//! - `lr_ospf_simple_password_new` / `_free` / `_password_at` /
//!   `_password_len` — RFC 2328 §D.2 simple password.
//! - `lr_ospf_crypto_algorithm_*` — `CryptoAlgorithm` enum conversions.
//! - `lr_ospf_crypto_auth_new` / `_with_sha1` / `_free` / `_key_id` /
//!   `_algorithm` / `_crypto_seq` / `_advance_seq` — RFC 5709 + RFC 2328
//!   §D.3 crypto auth (HMAC-SHA-1 / HMAC-SHA-256).
//! - `lr_ospf_v3_auth_new` / `_with_sha1` / `_with_source` / `_free` /
//!   `_sa_id` / `_trailer_len` — RFC 7166 OSPFv3 authentication
//!   trailer.
//!
//! Every entry point runs inside the crate's `catch_unwind` barrier
//! (`crate::guarded`); a panic returns `LR_ERR_PANIC` and sets the
//! thread-local last-error string.

#![allow(unused_unsafe)]

use lr_ospf::auth::v3_auth::V3_AUTH_TYPE_HMAC;
use lr_ospf::auth::{AuType, CryptoAlgorithm, CryptoAuth, SimplePassword, V3Auth};

use crate::error::{set_last_error, LrError, LR_ERR_PANIC};
use crate::guarded;

const LR_ERR_NULL: i32 = LrError::Null as i32;
#[allow(dead_code)]
const LR_ERR_OTHER: i32 = LrError::Other as i32;

// ---- AuType enum constants (RFC 2328 §D.1) ----

pub const LR_OSPF_AU_TYPE_NULL: u16 = AuType::Null as u16;
pub const LR_OSPF_AU_TYPE_SIMPLE_PASSWORD: u16 = AuType::SimplePassword as u16;
pub const LR_OSPF_AU_TYPE_MD5: u16 = AuType::Md5 as u16;

/// Convert a wire `AuType` value (RFC 2328 §D.1) to its
/// `LR_OSPF_AU_TYPE_*` constant. Unknown values map to NULL (0) —
/// matching the Rust `AuType::from_u16` behavior.
#[no_mangle]
pub extern "C" fn lr_ospf_au_type_from_u16(wire: u16) -> u16 {
    guarded(|| AuType::from_u16(wire) as u16, 0)
}

/// Convert a `LR_OSPF_AU_TYPE_*` constant back to its wire value.
/// (Identity — kept for ABI symmetry with `from_u16`.)
#[no_mangle]
pub extern "C" fn lr_ospf_au_type_to_u16(value: u16) -> u16 {
    guarded(|| value, 0)
}

/// Return the name of an `AuType` value ("null", "simple-password",
/// "md5") as a NUL-terminated C string. The returned pointer is valid
/// until the next call to any `lr_ospf_*` function on this thread.
#[no_mangle]
pub extern "C" fn lr_ospf_au_type_name(value: u16) -> *const std::os::raw::c_char {
    use std::cell::RefCell;
    thread_local! {
        static BUF: RefCell<std::ffi::CString> = RefCell::new(std::ffi::CString::new("").unwrap());
    }
    guarded(
        || {
            let name: &'static str = match value {
                x if x == LR_OSPF_AU_TYPE_NULL => "null",
                x if x == LR_OSPF_AU_TYPE_SIMPLE_PASSWORD => "simple-password",
                x if x == LR_OSPF_AU_TYPE_MD5 => "md5",
                _ => "unknown",
            };
            BUF.with(|b| {
                *b.borrow_mut() = std::ffi::CString::new(name).unwrap();
                b.borrow().as_ptr()
            })
        },
        std::ptr::null(),
    )
}

// ---- SimplePassword (RFC 2328 §D.2) ----

/// Opaque `SimplePassword` handle.
#[repr(C)]
pub struct OpaqueOspfSimplePassword {
    _private: [u8; 0],
}

pub type lr_ospf_simple_password_t = *mut OpaqueOspfSimplePassword;

fn box_simple(p: SimplePassword) -> lr_ospf_simple_password_t {
    Box::into_raw(Box::new(p)) as lr_ospf_simple_password_t
}

/// Reclaim a `SimplePassword` handle.
///
/// # Safety
/// `p` must have been produced by [`box_simple`] and not freed.
unsafe fn unbox_simple(p: lr_ospf_simple_password_t) -> Option<Box<SimplePassword>> {
    if p.is_null() {
        return None;
    }
    Some(unsafe { Box::from_raw(p as *mut SimplePassword) })
}

/// Borrow a `SimplePassword` handle for read-only access.
///
/// # Safety
/// `p` must be a valid handle and not freed while the reference is live.
unsafe fn borrow_simple(p: lr_ospf_simple_password_t) -> Option<&'static SimplePassword> {
    if p.is_null() {
        return None;
    }
    Some(unsafe { &*(p as *const SimplePassword) })
}

/// Construct a Simple Password auth config (RFC 2328 §D.2). `password`
/// points to up to 8 bytes; bytes beyond `password_len` are zero-padded
/// to fill the 8-byte auth_data field. Passing `password_len == 0`
/// produces an all-zero password.
///
/// # Safety
/// `password` (when `password_len > 0`) must point to `password_len`
/// readable bytes. `password_len` must be <= 8.
#[no_mangle]
pub unsafe extern "C" fn lr_ospf_simple_password_new(
    password: *const u8,
    password_len: usize,
) -> lr_ospf_simple_password_t {
    guarded(
        || unsafe {
            if password_len > 8 {
                set_last_error(format!(
                    "SimplePassword length {password_len} exceeds the 8-byte RFC 2328 §D.2 maximum"
                ));
                return std::ptr::null_mut();
            }
            let mut buf = [0u8; 8];
            if password_len > 0 {
                if password.is_null() {
                    return std::ptr::null_mut();
                }
                let src = unsafe { std::slice::from_raw_parts(password, password_len) };
                buf[..password_len].copy_from_slice(src);
            }
            box_simple(SimplePassword { password: buf })
        },
        std::ptr::null_mut(),
    )
}

/// Read the password bytes (always 8 bytes per RFC 2328 §D.2).
/// Returns 0 on a NULL handle and writes nothing to `out`.
///
/// # Safety
/// `p` must be a valid handle. `out` must point to at least 8 writable
/// bytes.
#[no_mangle]
pub unsafe extern "C" fn lr_ospf_simple_password_password(
    p: lr_ospf_simple_password_t,
    out: *mut u8,
) -> usize {
    guarded(
        || unsafe {
            let Some(sp) = borrow_simple(p) else {
                return 0;
            };
            if out.is_null() {
                return 0;
            }
            unsafe {
                std::ptr::copy_nonoverlapping(sp.password.as_ptr(), out, 8);
            }
            8
        },
        0,
    )
}

/// Drop a boxed `SimplePassword`. Safe to call with NULL.
#[no_mangle]
pub unsafe extern "C" fn lr_ospf_simple_password_free(p: lr_ospf_simple_password_t) {
    guarded(
        || unsafe {
            drop(unbox_simple(p));
        },
        (),
    )
}

// ---- CryptoAlgorithm enum (RFC 5709 §2) ----

pub const LR_OSPF_CRYPTO_ALG_HMAC_SHA1: u8 = 1;
pub const LR_OSPF_CRYPTO_ALG_HMAC_SHA256: u8 = 2;

/// Convert a `LR_OSPF_CRYPTO_ALG_*` constant to its wire value.
#[no_mangle]
pub extern "C" fn lr_ospf_crypto_algorithm_to_u8(value: u8) -> u8 {
    guarded(|| value, 0)
}

/// Convert a wire algorithm value to its `LR_OSPF_CRYPTO_ALG_*`
/// constant. Unknown values map to 0 (NULL) — the Rust enum has only
/// two variants.
#[no_mangle]
pub extern "C" fn lr_ospf_crypto_algorithm_from_u8(value: u8) -> u8 {
    guarded(
        || match value {
            LR_OSPF_CRYPTO_ALG_HMAC_SHA1 | LR_OSPF_CRYPTO_ALG_HMAC_SHA256 => value,
            _ => 0,
        },
        0,
    )
}

/// Return the name of a `CryptoAlgorithm` value ("hmac-sha1",
/// "hmac-sha256") as a NUL-terminated C string. The returned pointer is
/// valid until the next call to any `lr_ospf_*` function on this
/// thread.
#[no_mangle]
pub extern "C" fn lr_ospf_crypto_algorithm_name(value: u8) -> *const std::os::raw::c_char {
    use std::cell::RefCell;
    thread_local! {
        static BUF: RefCell<std::ffi::CString> = RefCell::new(std::ffi::CString::new("").unwrap());
    }
    guarded(
        || {
            let name: &'static str = match value {
                x if x == LR_OSPF_CRYPTO_ALG_HMAC_SHA1 => "hmac-sha1",
                x if x == LR_OSPF_CRYPTO_ALG_HMAC_SHA256 => "hmac-sha256",
                _ => "unknown",
            };
            BUF.with(|b| {
                *b.borrow_mut() = std::ffi::CString::new(name).unwrap();
                b.borrow().as_ptr()
            })
        },
        std::ptr::null(),
    )
}

/// Return the digest length of a `CryptoAlgorithm` (RFC 5709 §2):
/// 20 for HMAC-SHA-1, 32 for HMAC-SHA-256.
#[no_mangle]
pub extern "C" fn lr_ospf_crypto_algorithm_digest_len(value: u8) -> usize {
    guarded(
        || match value {
            x if x == LR_OSPF_CRYPTO_ALG_HMAC_SHA1 => CryptoAlgorithm::HmacSha1.digest_len(),
            x if x == LR_OSPF_CRYPTO_ALG_HMAC_SHA256 => CryptoAlgorithm::HmacSha256.digest_len(),
            _ => 0,
        },
        0,
    )
}

/// Return the trailer length a `CryptoAlgorithm` produces (RFC 5709):
/// 6 bytes of overhead (Key ID + Auth Data Len + Crypto Seq Number) +
/// the digest.
#[no_mangle]
pub extern "C" fn lr_ospf_crypto_algorithm_trailer_len(value: u8) -> usize {
    guarded(
        || match value {
            x if x == LR_OSPF_CRYPTO_ALG_HMAC_SHA1 => CryptoAlgorithm::HmacSha1.trailer_len(),
            x if x == LR_OSPF_CRYPTO_ALG_HMAC_SHA256 => CryptoAlgorithm::HmacSha256.trailer_len(),
            _ => 0,
        },
        0,
    )
}

// ---- CryptoAuth (RFC 2328 §D.3 + RFC 5709) ----

/// Opaque `CryptoAuth` handle.
#[repr(C)]
pub struct OpaqueOspfCryptoAuth {
    _private: [u8; 0],
}

pub type lr_ospf_crypto_auth_t = *mut OpaqueOspfCryptoAuth;

fn box_crypto(c: CryptoAuth) -> lr_ospf_crypto_auth_t {
    Box::into_raw(Box::new(c)) as lr_ospf_crypto_auth_t
}

/// Reclaim a `CryptoAuth` handle.
///
/// # Safety
/// `c` must have been produced by [`box_crypto`] and not freed.
unsafe fn unbox_crypto(c: lr_ospf_crypto_auth_t) -> Option<Box<CryptoAuth>> {
    if c.is_null() {
        return None;
    }
    Some(unsafe { Box::from_raw(c as *mut CryptoAuth) })
}

/// Borrow a `CryptoAuth` handle for read-only access.
///
/// # Safety
/// `c` must be a valid handle and not freed while the reference is live.
unsafe fn borrow_crypto(c: lr_ospf_crypto_auth_t) -> Option<&'static CryptoAuth> {
    if c.is_null() {
        return None;
    }
    Some(unsafe { &*(c as *const CryptoAuth) })
}

/// Borrow a `CryptoAuth` handle mutably for in-place field updates.
///
/// # Safety
/// `c` must be a valid handle; the caller must not race the mutation.
unsafe fn borrow_crypto_mut(c: lr_ospf_crypto_auth_t) -> Option<&'static mut CryptoAuth> {
    if c.is_null() {
        return None;
    }
    Some(unsafe { &mut *(c as *mut CryptoAuth) })
}

/// Construct a `CryptoAuth` with HMAC-SHA-256 (the RFC 5709 default).
/// `key_id` is the 0..=255 Key ID; `key` points to `key_len` bytes of
/// shared secret (RFC 5709 §3.3).
///
/// # Safety
/// `key` (when `key_len > 0`) must point to `key_len` readable bytes.
#[no_mangle]
pub unsafe extern "C" fn lr_ospf_crypto_auth_new(
    key_id: u8,
    key: *const u8,
    key_len: usize,
) -> lr_ospf_crypto_auth_t {
    guarded(
        || unsafe {
            if key.is_null() && key_len != 0 {
                return std::ptr::null_mut();
            }
            let key_vec = if key_len == 0 {
                Vec::new()
            } else {
                unsafe { std::slice::from_raw_parts(key, key_len).to_vec() }
            };
            box_crypto(CryptoAuth::new(key_id, key_vec))
        },
        std::ptr::null_mut(),
    )
}

/// Switch a `CryptoAuth` to HMAC-SHA-1 (RFC 5709 §2.1). Returns 0 on
/// success, `LR_ERR_NULL` on a NULL handle.
#[no_mangle]
pub unsafe extern "C" fn lr_ospf_crypto_auth_with_sha1(c: lr_ospf_crypto_auth_t) -> i32 {
    guarded(
        || unsafe {
            let Some(auth) = borrow_crypto_mut(c) else {
                return LR_ERR_NULL;
            };
            // Rebuild via with_sha1 to mirror the Rust builder API.
            let rebuilt = CryptoAuth::new(auth.key_id, auth.key.clone()).with_sha1();
            *auth = rebuilt;
            0
        },
        LR_ERR_PANIC,
    )
}

/// Read the Key ID (0..=255, RFC 2328 §D.3).
#[no_mangle]
pub unsafe extern "C" fn lr_ospf_crypto_auth_key_id(c: lr_ospf_crypto_auth_t) -> u8 {
    guarded(
        || unsafe { borrow_crypto(c).map(|a| a.key_id).unwrap_or(0) },
        0,
    )
}

/// Read the algorithm constant (`LR_OSPF_CRYPTO_ALG_*`).
#[no_mangle]
pub unsafe extern "C" fn lr_ospf_crypto_auth_algorithm(c: lr_ospf_crypto_auth_t) -> u8 {
    guarded(
        || unsafe {
            borrow_crypto(c)
                .map(|a| match a.algorithm {
                    CryptoAlgorithm::HmacSha1 => LR_OSPF_CRYPTO_ALG_HMAC_SHA1,
                    CryptoAlgorithm::HmacSha256 => LR_OSPF_CRYPTO_ALG_HMAC_SHA256,
                })
                .unwrap_or(0)
        },
        0,
    )
}

/// Read the monotonic cryptographic sequence number (RFC 2328 §D.3.2).
#[no_mangle]
pub unsafe extern "C" fn lr_ospf_crypto_auth_crypto_seq(c: lr_ospf_crypto_auth_t) -> u32 {
    guarded(
        || unsafe { borrow_crypto(c).map(|a| a.crypto_seq).unwrap_or(0) },
        0,
    )
}

/// Advance the crypto sequence number by 1. Returns 0 on success,
/// `LR_ERR_NULL` on a NULL handle. Per RFC 2328 §D.3.2, the embedder
/// MUST call this on every outbound packet.
#[no_mangle]
pub unsafe extern "C" fn lr_ospf_crypto_auth_advance_seq(c: lr_ospf_crypto_auth_t) -> i32 {
    guarded(
        || unsafe {
            let Some(auth) = borrow_crypto_mut(c) else {
                return LR_ERR_NULL;
            };
            auth.advance_seq();
            0
        },
        LR_ERR_PANIC,
    )
}

/// Copy the shared secret bytes into the caller-supplied buffer.
/// Returns the number of bytes copied (capped at `out_len`). Use a
/// first call with `out == NULL` to size the buffer.
///
/// # Safety
/// `c` must be a valid handle. `out` (when non-NULL) must point to at
/// least `out_len` writable bytes.
#[no_mangle]
pub unsafe extern "C" fn lr_ospf_crypto_auth_key(
    c: lr_ospf_crypto_auth_t,
    out: *mut u8,
    out_len: usize,
) -> usize {
    guarded(
        || unsafe {
            let Some(auth) = borrow_crypto(c) else {
                return 0;
            };
            if out.is_null() || out_len == 0 {
                return auth.key.len();
            }
            let take = auth.key.len().min(out_len);
            unsafe {
                std::ptr::copy_nonoverlapping(auth.key.as_ptr(), out, take);
            }
            take
        },
        0,
    )
}

/// Length of the shared secret in bytes. Returns 0 on a NULL handle.
#[no_mangle]
pub unsafe extern "C" fn lr_ospf_crypto_auth_key_len(c: lr_ospf_crypto_auth_t) -> usize {
    guarded(
        || unsafe { borrow_crypto(c).map(|a| a.key.len()).unwrap_or(0) },
        0,
    )
}

/// Drop a boxed `CryptoAuth`. Safe to call with NULL.
#[no_mangle]
pub unsafe extern "C" fn lr_ospf_crypto_auth_free(c: lr_ospf_crypto_auth_t) {
    guarded(
        || unsafe {
            drop(unbox_crypto(c));
        },
        (),
    )
}

// ---- V3Auth (RFC 7166 OSPFv3 auth trailer) ----

/// Opaque `V3Auth` handle.
#[repr(C)]
pub struct OpaqueOspfV3Auth {
    _private: [u8; 0],
}

pub type lr_ospf_v3_auth_t = *mut OpaqueOspfV3Auth;

fn box_v3(v: V3Auth) -> lr_ospf_v3_auth_t {
    Box::into_raw(Box::new(v)) as lr_ospf_v3_auth_t
}

/// Reclaim a `V3Auth` handle.
///
/// # Safety
/// `v` must have been produced by [`box_v3`] and not freed.
unsafe fn unbox_v3(v: lr_ospf_v3_auth_t) -> Option<Box<V3Auth>> {
    if v.is_null() {
        return None;
    }
    Some(unsafe { Box::from_raw(v as *mut V3Auth) })
}

/// Borrow a `V3Auth` handle for read-only access.
///
/// # Safety
/// `v` must be a valid handle and not freed while the reference is live.
unsafe fn borrow_v3(v: lr_ospf_v3_auth_t) -> Option<&'static V3Auth> {
    if v.is_null() {
        return None;
    }
    Some(unsafe { &*(v as *const V3Auth) })
}

/// Borrow a `V3Auth` handle mutably for in-place field updates.
///
/// # Safety
/// `v` must be a valid handle; the caller must not race the mutation.
unsafe fn borrow_v3_mut(v: lr_ospf_v3_auth_t) -> Option<&'static mut V3Auth> {
    if v.is_null() {
        return None;
    }
    Some(unsafe { &mut *(v as *mut V3Auth) })
}

/// The OSPFv3 authentication type for HMAC trailers (RFC 7166).
pub const LR_OSPF_V3_AUTH_TYPE_HMAC: u16 = V3_AUTH_TYPE_HMAC;

/// Construct a `V3Auth` with HMAC-SHA-256 (the RFC 7166 default) and
/// the given Security Association ID + shared secret.
///
/// # Safety
/// `key` (when `key_len > 0`) must point to `key_len` readable bytes.
#[no_mangle]
pub unsafe extern "C" fn lr_ospf_v3_auth_new(
    sa_id: u16,
    key: *const u8,
    key_len: usize,
) -> lr_ospf_v3_auth_t {
    guarded(
        || unsafe {
            if key.is_null() && key_len != 0 {
                return std::ptr::null_mut();
            }
            let key_vec = if key_len == 0 {
                Vec::new()
            } else {
                unsafe { std::slice::from_raw_parts(key, key_len).to_vec() }
            };
            box_v3(V3Auth::new(sa_id, key_vec))
        },
        std::ptr::null_mut(),
    )
}

/// Switch a `V3Auth` to HMAC-SHA-1 (RFC 5709 §2.1). Returns 0 on
/// success, `LR_ERR_NULL` on a NULL handle.
#[no_mangle]
pub unsafe extern "C" fn lr_ospf_v3_auth_with_sha1(v: lr_ospf_v3_auth_t) -> i32 {
    guarded(
        || unsafe {
            let Some(auth) = borrow_v3_mut(v) else {
                return LR_ERR_NULL;
            };
            // Rebuild via with_sha1 to mirror the Rust builder API.
            // The original key is preserved.
            let key = auth.key.clone();
            let sa_id = auth.sa_id;
            *auth = V3Auth::new(sa_id, key).with_sha1();
            0
        },
        LR_ERR_PANIC,
    )
}

/// Set the source IPv6 address (the LLS data block source). The
/// caller passes 16 bytes. Returns 0 on success, `LR_ERR_NULL` on a
/// NULL handle or NULL `source`.
///
/// # Safety
/// `v` must be a valid handle. `source` must point to 16 readable bytes.
#[no_mangle]
pub unsafe extern "C" fn lr_ospf_v3_auth_with_source(
    v: lr_ospf_v3_auth_t,
    source: *const u8,
) -> i32 {
    guarded(
        || unsafe {
            let Some(auth) = borrow_v3_mut(v) else {
                return LR_ERR_NULL;
            };
            if source.is_null() {
                return LR_ERR_NULL;
            }
            let mut buf = [0u8; 16];
            unsafe {
                std::ptr::copy_nonoverlapping(source, buf.as_mut_ptr(), 16);
            }
            *auth = auth.clone().with_source(buf);
            0
        },
        LR_ERR_PANIC,
    )
}

/// Read the Security Association ID (RFC 7166).
#[no_mangle]
pub unsafe extern "C" fn lr_ospf_v3_auth_sa_id(v: lr_ospf_v3_auth_t) -> u16 {
    guarded(|| unsafe { borrow_v3(v).map(|a| a.sa_id).unwrap_or(0) }, 0)
}

/// Read the algorithm constant (`LR_OSPF_CRYPTO_ALG_*`).
#[no_mangle]
pub unsafe extern "C" fn lr_ospf_v3_auth_algorithm(v: lr_ospf_v3_auth_t) -> u8 {
    guarded(
        || unsafe {
            borrow_v3(v)
                .map(|a| match a.algorithm {
                    CryptoAlgorithm::HmacSha1 => LR_OSPF_CRYPTO_ALG_HMAC_SHA1,
                    CryptoAlgorithm::HmacSha256 => LR_OSPF_CRYPTO_ALG_HMAC_SHA256,
                })
                .unwrap_or(0)
        },
        0,
    )
}

/// Read the length of the auth trailer this `V3Auth` produces.
#[no_mangle]
pub unsafe extern "C" fn lr_ospf_v3_auth_trailer_len(v: lr_ospf_v3_auth_t) -> usize {
    guarded(
        || unsafe { borrow_v3(v).map(|a| a.trailer_len()).unwrap_or(0) },
        0,
    )
}

/// Copy the shared secret bytes into the caller-supplied buffer.
/// Returns the number of bytes copied (capped at `out_len`). Use a
/// first call with `out == NULL` to size the buffer.
///
/// # Safety
/// `v` must be a valid handle. `out` (when non-NULL) must point to at
/// least `out_len` writable bytes.
#[no_mangle]
pub unsafe extern "C" fn lr_ospf_v3_auth_key(
    v: lr_ospf_v3_auth_t,
    out: *mut u8,
    out_len: usize,
) -> usize {
    guarded(
        || unsafe {
            let Some(auth) = borrow_v3(v) else {
                return 0;
            };
            if out.is_null() || out_len == 0 {
                return auth.key.len();
            }
            let take = auth.key.len().min(out_len);
            unsafe {
                std::ptr::copy_nonoverlapping(auth.key.as_ptr(), out, take);
            }
            take
        },
        0,
    )
}

/// Length of the shared secret in bytes. Returns 0 on a NULL handle.
#[no_mangle]
pub unsafe extern "C" fn lr_ospf_v3_auth_key_len(v: lr_ospf_v3_auth_t) -> usize {
    guarded(
        || unsafe { borrow_v3(v).map(|a| a.key.len()).unwrap_or(0) },
        0,
    )
}

/// Drop a boxed `V3Auth`. Safe to call with NULL.
#[no_mangle]
pub unsafe extern "C" fn lr_ospf_v3_auth_free(v: lr_ospf_v3_auth_t) {
    guarded(
        || unsafe {
            drop(unbox_v3(v));
        },
        (),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ffi_au_type_roundtrip() {
        assert_eq!(lr_ospf_au_type_from_u16(0), LR_OSPF_AU_TYPE_NULL);
        assert_eq!(lr_ospf_au_type_from_u16(1), LR_OSPF_AU_TYPE_SIMPLE_PASSWORD);
        assert_eq!(lr_ospf_au_type_from_u16(2), LR_OSPF_AU_TYPE_MD5);
        // Unknown → NULL.
        assert_eq!(lr_ospf_au_type_from_u16(99), LR_OSPF_AU_TYPE_NULL);
        assert_eq!(
            lr_ospf_au_type_to_u16(LR_OSPF_AU_TYPE_MD5),
            LR_OSPF_AU_TYPE_MD5
        );
    }

    #[test]
    fn ffi_au_type_name() {
        let name_ptr = lr_ospf_au_type_name(LR_OSPF_AU_TYPE_NULL);
        let name = unsafe { std::ffi::CStr::from_ptr(name_ptr) }
            .to_str()
            .unwrap();
        assert_eq!(name, "null");
        let name_ptr = lr_ospf_au_type_name(LR_OSPF_AU_TYPE_MD5);
        let name = unsafe { std::ffi::CStr::from_ptr(name_ptr) }
            .to_str()
            .unwrap();
        assert_eq!(name, "md5");
    }

    #[test]
    fn ffi_simple_password_roundtrip() {
        let pwd = [1u8, 2, 3, 4, 5];
        let sp = unsafe { lr_ospf_simple_password_new(pwd.as_ptr(), pwd.len()) };
        assert!(!sp.is_null());
        let mut out = [0u8; 8];
        let n = unsafe { lr_ospf_simple_password_password(sp, out.as_mut_ptr()) };
        assert_eq!(n, 8);
        assert_eq!(&out[..5], &pwd);
        assert_eq!(&out[5..], &[0, 0, 0]); // zero-padded
        unsafe { lr_ospf_simple_password_free(sp) };
    }

    #[test]
    fn ffi_simple_password_rejects_oversize() {
        let pwd = [0u8; 9];
        let sp = unsafe { lr_ospf_simple_password_new(pwd.as_ptr(), 9) };
        assert!(sp.is_null());
        let err = unsafe { std::ffi::CStr::from_ptr(crate::error::lr_last_error()) }
            .to_string_lossy()
            .into_owned();
        assert!(err.contains("8-byte"));
    }

    #[test]
    fn ffi_simple_password_free_null_safe() {
        unsafe { lr_ospf_simple_password_free(std::ptr::null_mut()) };
    }

    #[test]
    fn ffi_crypto_algorithm_roundtrip() {
        assert_eq!(
            lr_ospf_crypto_algorithm_from_u8(LR_OSPF_CRYPTO_ALG_HMAC_SHA1),
            LR_OSPF_CRYPTO_ALG_HMAC_SHA1
        );
        assert_eq!(
            lr_ospf_crypto_algorithm_from_u8(99),
            0 // unknown → 0
        );
        assert_eq!(lr_ospf_crypto_algorithm_to_u8(2), 2);
        assert_eq!(
            lr_ospf_crypto_algorithm_digest_len(LR_OSPF_CRYPTO_ALG_HMAC_SHA1),
            20
        );
        assert_eq!(
            lr_ospf_crypto_algorithm_digest_len(LR_OSPF_CRYPTO_ALG_HMAC_SHA256),
            32
        );
        assert_eq!(
            lr_ospf_crypto_algorithm_trailer_len(LR_OSPF_CRYPTO_ALG_HMAC_SHA1),
            20 + 6
        );
        assert_eq!(
            lr_ospf_crypto_algorithm_trailer_len(LR_OSPF_CRYPTO_ALG_HMAC_SHA256),
            32 + 6
        );
    }

    #[test]
    fn ffi_crypto_algorithm_name() {
        let name_ptr = lr_ospf_crypto_algorithm_name(LR_OSPF_CRYPTO_ALG_HMAC_SHA1);
        let name = unsafe { std::ffi::CStr::from_ptr(name_ptr) }
            .to_str()
            .unwrap();
        assert_eq!(name, "hmac-sha1");
        let name_ptr = lr_ospf_crypto_algorithm_name(LR_OSPF_CRYPTO_ALG_HMAC_SHA256);
        let name = unsafe { std::ffi::CStr::from_ptr(name_ptr) }
            .to_str()
            .unwrap();
        assert_eq!(name, "hmac-sha256");
        let name_ptr = lr_ospf_crypto_algorithm_name(99);
        let name = unsafe { std::ffi::CStr::from_ptr(name_ptr) }
            .to_str()
            .unwrap();
        assert_eq!(name, "unknown");
    }

    #[test]
    fn ffi_crypto_auth_roundtrip() {
        let key = [0u8; 32];
        let c = unsafe { lr_ospf_crypto_auth_new(7, key.as_ptr(), key.len()) };
        assert!(!c.is_null());
        unsafe {
            assert_eq!(lr_ospf_crypto_auth_key_id(c), 7);
            assert_eq!(
                lr_ospf_crypto_auth_algorithm(c),
                LR_OSPF_CRYPTO_ALG_HMAC_SHA256
            );
            assert_eq!(lr_ospf_crypto_auth_key_len(c), 32);
            // Default crypto_seq is 0; advance_seq bumps it.
            assert_eq!(lr_ospf_crypto_auth_crypto_seq(c), 0);
            assert_eq!(lr_ospf_crypto_auth_advance_seq(c), 0);
            assert_eq!(lr_ospf_crypto_auth_crypto_seq(c), 1);
            // Switch to SHA-1.
            assert_eq!(lr_ospf_crypto_auth_with_sha1(c), 0);
            assert_eq!(
                lr_ospf_crypto_auth_algorithm(c),
                LR_OSPF_CRYPTO_ALG_HMAC_SHA1
            );
            // Read the key bytes back.
            let mut out = [0u8; 32];
            let n = lr_ospf_crypto_auth_key(c, out.as_mut_ptr(), 32);
            assert_eq!(n, 32);
            lr_ospf_crypto_auth_free(c);
        }
    }

    #[test]
    fn ffi_crypto_auth_free_null_safe() {
        unsafe { lr_ospf_crypto_auth_free(std::ptr::null_mut()) };
    }

    #[test]
    fn ffi_crypto_auth_advance_seq_null_returns_error() {
        let rc = unsafe { lr_ospf_crypto_auth_advance_seq(std::ptr::null_mut()) };
        assert_eq!(rc, LR_ERR_NULL);
    }

    #[test]
    fn ffi_v3_auth_roundtrip() {
        let key = [0u8; 32];
        let v = unsafe { lr_ospf_v3_auth_new(7, key.as_ptr(), key.len()) };
        assert!(!v.is_null());
        unsafe {
            assert_eq!(lr_ospf_v3_auth_sa_id(v), 7);
            assert_eq!(lr_ospf_v3_auth_algorithm(v), LR_OSPF_CRYPTO_ALG_HMAC_SHA256);
            assert_eq!(lr_ospf_v3_auth_key_len(v), 32);
            // Trailer length: 16-byte RFC 7166 trailer header + 32-byte
            // SHA-256 digest = 48.
            assert_eq!(lr_ospf_v3_auth_trailer_len(v), 48);
            // Switch to SHA-1: trailer length drops to 16 + 20 = 36.
            assert_eq!(lr_ospf_v3_auth_with_sha1(v), 0);
            assert_eq!(lr_ospf_v3_auth_algorithm(v), LR_OSPF_CRYPTO_ALG_HMAC_SHA1);
            assert_eq!(lr_ospf_v3_auth_trailer_len(v), 36);
            lr_ospf_v3_auth_free(v);
        }
    }

    #[test]
    fn ffi_v3_auth_with_source() {
        let key = [0u8; 32];
        let v = unsafe { lr_ospf_v3_auth_new(1, key.as_ptr(), key.len()) };
        let src = [0xfe_u8, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let rc = unsafe { lr_ospf_v3_auth_with_source(v, src.as_ptr()) };
        assert_eq!(rc, 0);
        unsafe { lr_ospf_v3_auth_free(v) };
    }

    #[test]
    fn ffi_v3_auth_with_source_null_returns_error() {
        let rc = unsafe { lr_ospf_v3_auth_with_source(std::ptr::null_mut(), [0u8; 16].as_ptr()) };
        assert_eq!(rc, LR_ERR_NULL);
    }

    #[test]
    fn ffi_v3_auth_free_null_safe() {
        unsafe { lr_ospf_v3_auth_free(std::ptr::null_mut()) };
    }
}
