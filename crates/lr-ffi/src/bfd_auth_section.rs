//! BFD Authentication Section C ABI (RFC 5880 §4.2-§4.4 + §6.7).
//!
//! Mirrors the public Rust API of `lr_bfd::auth::{AuthType, AuthKey,
//! AuthSection}` and `lr_bfd::keyed_auth::BfdKeyedAuth` so an embedder
//! that owns its own BFD packet encoder (rather than driving
//! `BfdSession`'s tick loop) can:
//!
//! - inspect an `AuthType` code (`expected_digest_len` / `is_keyed_hash`
//!   / `is_meticulous` readers);
//! - build / read / free `AuthSection` handles (the wire form of the
//!   Authentication Section, RFC 5880 §4.2-§4.4);
//! - build / read / free `AuthKey` handles (the per-key secret + key
//!   id pair, RFC 5880 §4.2);
//! - ask a `BfdKeyedAuth` for the auth section to ride the next
//!   outbound packet (`auth_section_for_tx`);
//! - sign an encoded outbound packet in place (`sign_packet`);
//! - verify an inbound packet against the configured key
//!   (`verify_inbound`); and
//! - install / read the auth section on a `BfdPacket` (`set_auth` /
//!   `auth_present` / `auth`).
//!
//! Each entry point runs inside the crate's `catch_unwind` barrier
//! ([`crate::guarded`]): a panic returns `LR_ERR_PANIC` and sets the
//! thread-local last-error string.

#![allow(unused_unsafe)]

use lr_bfd::auth::{AuthKey, AuthSection, AuthType};

use crate::error::{set_last_error, LrError, LR_ERR_PANIC};
use crate::guarded;

const LR_ERR_NULL: i32 = LrError::Null as i32;
const LR_ERR_OTHER: i32 = LrError::Other as i32;

// ---- Opaque handle types ----

/// Opaque `AuthKey` handle. C side never touches internals.
#[repr(C)]
pub struct OpaqueBfdAuthKey {
    _private: [u8; 0],
}
pub type lr_bfd_auth_key_t = *mut OpaqueBfdAuthKey;

/// Opaque `AuthSection` handle. C side never touches internals.
#[repr(C)]
pub struct OpaqueBfdAuthSection {
    _private: [u8; 0],
}
pub type lr_bfd_auth_section_t = *mut OpaqueBfdAuthSection;

// ---- Box / unbox / borrow helpers ----

fn box_key(k: AuthKey) -> lr_bfd_auth_key_t {
    Box::into_raw(Box::new(k)) as lr_bfd_auth_key_t
}
unsafe fn unbox_key(k: lr_bfd_auth_key_t) -> Option<Box<AuthKey>> {
    if k.is_null() {
        return None;
    }
    Some(unsafe { Box::from_raw(k as *mut AuthKey) })
}
unsafe fn borrow_key(k: lr_bfd_auth_key_t) -> Option<&'static AuthKey> {
    if k.is_null() {
        return None;
    }
    Some(unsafe { &*(k as *const AuthKey) })
}

fn box_section(s: AuthSection) -> lr_bfd_auth_section_t {
    Box::into_raw(Box::new(s)) as lr_bfd_auth_section_t
}
pub(crate) fn box_section_pub(s: AuthSection) -> lr_bfd_auth_section_t {
    Box::into_raw(Box::new(s)) as lr_bfd_auth_section_t
}
unsafe fn unbox_section(s: lr_bfd_auth_section_t) -> Option<Box<AuthSection>> {
    if s.is_null() {
        return None;
    }
    Some(unsafe { Box::from_raw(s as *mut AuthSection) })
}
pub(crate) unsafe fn unbox_section_pub(s: lr_bfd_auth_section_t) -> Option<Box<AuthSection>> {
    if s.is_null() {
        return None;
    }
    Some(unsafe { Box::from_raw(s as *mut AuthSection) })
}
unsafe fn borrow_section(s: lr_bfd_auth_section_t) -> Option<&'static AuthSection> {
    if s.is_null() {
        return None;
    }
    Some(unsafe { &*(s as *const AuthSection) })
}
pub(crate) unsafe fn borrow_section_pub(s: lr_bfd_auth_section_t) -> Option<&'static AuthSection> {
    if s.is_null() {
        return None;
    }
    Some(unsafe { &*(s as *const AuthSection) })
}

// ---- AuthType constants (mirror RFC 5880 §8 IANA registry) ----

pub const LR_BFD_AUTH_TYPE_SIMPLE_PASSWORD: u8 = 1;
pub const LR_BFD_AUTH_TYPE_KEYED_MD5: u8 = 2;
pub const LR_BFD_AUTH_TYPE_METICULOUS_KEYED_MD5: u8 = 3;
pub const LR_BFD_AUTH_TYPE_KEYED_SHA1: u8 = 4;
pub const LR_BFD_AUTH_TYPE_METICULOUS_KEYED_SHA1: u8 = 5;

// ---- AuthType free-function readers ----

/// Expected digest length for the keyed-hash auth types
/// (RFC 5880 §4.3 / §4.4): 16 for the MD5 variants, 20 for the SHA1
/// variants. Returns `-1` for Simple Password (variable length) and
/// unknown types (no fixed length to validate against).
///
/// Mirrors `lr_bfd::auth::AuthType::expected_digest_len`.
#[no_mangle]
pub extern "C" fn lr_bfd_auth_type_expected_digest_len(auth_type: u8) -> isize {
    guarded(
        || {
            let t = AuthType::from_u8(auth_type);
            match t.expected_digest_len() {
                Some(n) => n as isize,
                None => -1,
            }
        },
        -1,
    )
}

/// True (1) when `auth_type` is one of the four keyed-hash types
/// (KeyedMd5 / MeticulousKeyedMd5 / KeyedSha1 / MeticulousKeyedSha1);
/// they share the §4.3/§4.4 layout: reserved byte + sequence number +
/// digest. Simple Password and unknown types return 0.
///
/// Mirrors `lr_bfd::auth::AuthType::is_keyed_hash`.
#[no_mangle]
pub extern "C" fn lr_bfd_auth_type_is_keyed_hash(auth_type: u8) -> u8 {
    guarded(|| AuthType::from_u8(auth_type).is_keyed_hash() as u8, 0)
}

/// True (1) when `auth_type` is one of the two Meticulous variants
/// (MeticulousKeyedMd5 / MeticulousKeyedSha1) where the sequence
/// number MUST advance on every packet; 0 otherwise. Mirrors
/// `lr_bfd::auth::AuthType::is_meticulous`.
#[no_mangle]
pub extern "C" fn lr_bfd_auth_type_is_meticulous(auth_type: u8) -> u8 {
    guarded(|| AuthType::from_u8(auth_type).is_meticulous() as u8, 0)
}

// ---- AuthKey lifecycle + accessors ----

/// Construct an `AuthKey` from a raw key id and a secret buffer.
/// Returns NULL on a NULL secret (when `secret_len > 0`) or on panic.
///
/// The key carries the per-key shared secret the digest computation
/// folds in (RFC 5880 §4.2 / §4.3 / §4.4). Use
/// [`lr_bfd_auth_key_simple_password`] for the §4.2 Simple Password
/// convenience constructor that documents the §4.2 length rule (1..=16
/// bytes).
///
/// # Safety
/// `secret` must point to `secret_len` readable bytes when
/// `secret_len > 0`.
#[no_mangle]
pub unsafe extern "C" fn lr_bfd_auth_key_new(
    key_id: u8,
    secret: *const u8,
    secret_len: usize,
) -> lr_bfd_auth_key_t {
    guarded(
        || unsafe {
            if secret.is_null() && secret_len != 0 {
                set_last_error("lr_bfd_auth_key_new: NULL secret with non-zero length".into());
                return std::ptr::null_mut();
            }
            let data = if secret_len == 0 {
                Vec::new()
            } else {
                unsafe { std::slice::from_raw_parts(secret, secret_len) }.to_vec()
            };
            box_key(AuthKey::new(key_id, data))
        },
        std::ptr::null_mut(),
    )
}

/// Construct a Simple Password `AuthKey` (RFC 5880 §4.2). Passwords
/// must be 1..=16 bytes; the C ABI does not enforce the upper bound
/// (the codec rejects longer passwords at encode time) so the
/// constructor is infallible. Returns NULL on a NULL password or on
/// panic.
///
/// Mirrors `lr_bfd::auth::AuthKey::simple_password`.
///
/// # Safety
/// `password` must point to `password_len` readable bytes when
/// `password_len > 0`.
#[no_mangle]
pub unsafe extern "C" fn lr_bfd_auth_key_simple_password(
    key_id: u8,
    password: *const u8,
    password_len: usize,
) -> lr_bfd_auth_key_t {
    guarded(
        || unsafe {
            if password.is_null() && password_len != 0 {
                set_last_error(
                    "lr_bfd_auth_key_simple_password: NULL password with non-zero length".into(),
                );
                return std::ptr::null_mut();
            }
            let pw = if password_len == 0 {
                &[][..]
            } else {
                unsafe { std::slice::from_raw_parts(password, password_len) }
            };
            box_key(AuthKey::simple_password(key_id, pw))
        },
        std::ptr::null_mut(),
    )
}

/// Drop a boxed `AuthKey`. Safe to call with NULL.
///
/// # Safety
/// `k` must have been produced by [`lr_bfd_auth_key_new`] /
/// [`lr_bfd_auth_key_simple_password`] and must not be used after this
/// call. Double-free is undefined behaviour.
#[no_mangle]
pub unsafe extern "C" fn lr_bfd_auth_key_free(k: lr_bfd_auth_key_t) {
    guarded(
        || unsafe {
            drop(unbox_key(k));
        },
        (),
    )
}

/// Read the key id (RFC 5880 §4.3 / §4.4 `Auth Key ID`). Returns 0 on
/// a NULL handle.
///
/// # Safety
/// `k` must be a valid handle.
#[no_mangle]
pub unsafe extern "C" fn lr_bfd_auth_key_key_id(k: lr_bfd_auth_key_t) -> u8 {
    guarded(
        || unsafe { borrow_key(k).map(|x| x.key_id).unwrap_or(0) },
        0,
    )
}

/// Read the secret length in bytes. Returns 0 on a NULL handle.
///
/// # Safety
/// `k` must be a valid handle.
#[no_mangle]
pub unsafe extern "C" fn lr_bfd_auth_key_data_len(k: lr_bfd_auth_key_t) -> usize {
    guarded(
        || unsafe { borrow_key(k).map(|x| x.data.len()).unwrap_or(0) },
        0,
    )
}

/// Copy the secret bytes into `out_data` (up to `cap` bytes) and write
/// the actual length to `*out_len`. Returns 0 on success,
/// `LR_ERR_NULL` on a NULL handle / NULL out_len, `LR_ERR_OTHER` when
/// the buffer is too small (the length is still written to
/// `*out_len` so the caller can retry).
///
/// # Safety
/// `k` must be a valid handle. `out_data` (when `cap > 0`) must point
/// to `cap` writable bytes. `out_len` must point to a writable
/// `uintptr_t`.
#[no_mangle]
pub unsafe extern "C" fn lr_bfd_auth_key_data(
    k: lr_bfd_auth_key_t,
    out_data: *mut u8,
    cap: usize,
    out_len: *mut usize,
) -> i32 {
    guarded(
        || unsafe {
            if out_len.is_null() {
                return LR_ERR_NULL;
            }
            let Some(key) = borrow_key(k) else {
                return LR_ERR_NULL;
            };
            let len = key.data.len();
            unsafe { *out_len = len };
            if len > cap {
                return LR_ERR_OTHER;
            }
            if !out_data.is_null() && len > 0 {
                unsafe {
                    std::ptr::copy_nonoverlapping(key.data.as_ptr(), out_data, len);
                }
            }
            0
        },
        LR_ERR_PANIC,
    )
}

// ---- AuthSection lifecycle ----

/// Construct a Simple Password `AuthSection` (RFC 5880 §4.2). The
/// `password` slice becomes the section's `data`; `key_id` is the
/// `Auth Key ID` field. The wire codec later enforces the §4.2
/// length rule (1..=16 bytes) at encode time. Returns NULL on a NULL
/// password (when `password_len > 0`) or on panic.
///
/// Mirrors `lr_bfd::auth::AuthSection::simple_password`.
///
/// # Safety
/// `password` must point to `password_len` readable bytes when
/// `password_len > 0`.
#[no_mangle]
pub unsafe extern "C" fn lr_bfd_auth_section_simple_password(
    password: *const u8,
    password_len: usize,
    key_id: u8,
) -> lr_bfd_auth_section_t {
    guarded(
        || unsafe {
            if password.is_null() && password_len != 0 {
                set_last_error(
                    "lr_bfd_auth_section_simple_password: NULL password with non-zero length"
                        .into(),
                );
                return std::ptr::null_mut();
            }
            let pw = if password_len == 0 {
                Vec::new()
            } else {
                unsafe { std::slice::from_raw_parts(password, password_len) }.to_vec()
            };
            box_section(AuthSection::simple_password(pw, key_id))
        },
        std::ptr::null_mut(),
    )
}

/// Construct a Keyed MD5 `AuthSection` (RFC 5880 §4.3, type 2). The
/// `digest` slice carries the 16-byte MD5 digest the codec will emit
/// in the Auth Key/Digest field. Returns NULL on a NULL digest or on
/// panic.
///
/// Mirrors `lr_bfd::auth::AuthSection::keyed_md5`.
///
/// # Safety
/// `digest` must point to `digest_len` readable bytes when
/// `digest_len > 0`.
#[no_mangle]
pub unsafe extern "C" fn lr_bfd_auth_section_keyed_md5(
    key_id: u8,
    sequence: u32,
    digest: *const u8,
    digest_len: usize,
) -> lr_bfd_auth_section_t {
    guarded(
        || unsafe {
            if digest.is_null() && digest_len != 0 {
                set_last_error(
                    "lr_bfd_auth_section_keyed_md5: NULL digest with non-zero length".into(),
                );
                return std::ptr::null_mut();
            }
            let d = if digest_len == 0 {
                Vec::new()
            } else {
                unsafe { std::slice::from_raw_parts(digest, digest_len) }.to_vec()
            };
            box_section(AuthSection::keyed_md5(key_id, sequence, d))
        },
        std::ptr::null_mut(),
    )
}

/// Construct a Meticulous Keyed MD5 `AuthSection` (RFC 5880 §4.3,
/// type 3). Mirrors `lr_bfd::auth::AuthSection::meticulous_keyed_md5`.
///
/// # Safety
/// See [`lr_bfd_auth_section_keyed_md5`].
#[no_mangle]
pub unsafe extern "C" fn lr_bfd_auth_section_meticulous_keyed_md5(
    key_id: u8,
    sequence: u32,
    digest: *const u8,
    digest_len: usize,
) -> lr_bfd_auth_section_t {
    guarded(
        || unsafe {
            if digest.is_null() && digest_len != 0 {
                set_last_error(
                    "lr_bfd_auth_section_meticulous_keyed_md5: NULL digest with non-zero length"
                        .into(),
                );
                return std::ptr::null_mut();
            }
            let d = if digest_len == 0 {
                Vec::new()
            } else {
                unsafe { std::slice::from_raw_parts(digest, digest_len) }.to_vec()
            };
            box_section(AuthSection::meticulous_keyed_md5(key_id, sequence, d))
        },
        std::ptr::null_mut(),
    )
}

/// Construct a Keyed SHA1 `AuthSection` (RFC 5880 §4.4, type 4). The
/// `digest` slice carries the 20-byte SHA1 digest. Returns NULL on a
/// NULL digest or on panic. Mirrors
/// `lr_bfd::auth::AuthSection::keyed_sha1`.
///
/// # Safety
/// See [`lr_bfd_auth_section_keyed_md5`].
#[no_mangle]
pub unsafe extern "C" fn lr_bfd_auth_section_keyed_sha1(
    key_id: u8,
    sequence: u32,
    digest: *const u8,
    digest_len: usize,
) -> lr_bfd_auth_section_t {
    guarded(
        || unsafe {
            if digest.is_null() && digest_len != 0 {
                set_last_error(
                    "lr_bfd_auth_section_keyed_sha1: NULL digest with non-zero length".into(),
                );
                return std::ptr::null_mut();
            }
            let d = if digest_len == 0 {
                Vec::new()
            } else {
                unsafe { std::slice::from_raw_parts(digest, digest_len) }.to_vec()
            };
            box_section(AuthSection::keyed_sha1(key_id, sequence, d))
        },
        std::ptr::null_mut(),
    )
}

/// Construct a Meticulous Keyed SHA1 `AuthSection` (RFC 5880 §4.4,
/// type 5). Mirrors
/// `lr_bfd::auth::AuthSection::meticulous_keyed_sha1`.
///
/// # Safety
/// See [`lr_bfd_auth_section_keyed_md5`].
#[no_mangle]
pub unsafe extern "C" fn lr_bfd_auth_section_meticulous_keyed_sha1(
    key_id: u8,
    sequence: u32,
    digest: *const u8,
    digest_len: usize,
) -> lr_bfd_auth_section_t {
    guarded(
        || unsafe {
            if digest.is_null() && digest_len != 0 {
                set_last_error(
                    "lr_bfd_auth_section_meticulous_keyed_sha1: NULL digest with non-zero length"
                        .into(),
                );
                return std::ptr::null_mut();
            }
            let d = if digest_len == 0 {
                Vec::new()
            } else {
                unsafe { std::slice::from_raw_parts(digest, digest_len) }.to_vec()
            };
            box_section(AuthSection::meticulous_keyed_sha1(key_id, sequence, d))
        },
        std::ptr::null_mut(),
    )
}

/// Drop a boxed `AuthSection`. Safe to call with NULL.
///
/// # Safety
/// `s` must have been produced by an `lr_bfd_auth_section_*`
/// constructor and must not be used after this call. Double-free is
/// undefined behaviour.
#[no_mangle]
pub unsafe extern "C" fn lr_bfd_auth_section_free(s: lr_bfd_auth_section_t) {
    guarded(
        || unsafe {
            drop(unbox_section(s));
        },
        (),
    )
}

// ---- AuthSection readers ----

/// Read the auth type code (`LR_BFD_AUTH_TYPE_*`). Returns 0 on a
/// NULL handle.
///
/// # Safety
/// `s` must be a valid handle.
#[no_mangle]
pub unsafe extern "C" fn lr_bfd_auth_section_auth_type(s: lr_bfd_auth_section_t) -> u8 {
    guarded(
        || unsafe { borrow_section(s).map(|x| x.auth_type.to_u8()).unwrap_or(0) },
        0,
    )
}

/// Read the key id (RFC 5880 §4.3 / §4.4 `Auth Key ID`). Returns 0 on
/// a NULL handle.
///
/// # Safety
/// `s` must be a valid handle.
#[no_mangle]
pub unsafe extern "C" fn lr_bfd_auth_section_key_id(s: lr_bfd_auth_section_t) -> u8 {
    guarded(
        || unsafe { borrow_section(s).map(|x| x.key_id).unwrap_or(0) },
        0,
    )
}

/// Read the sequence number (RFC 5880 §4.3 / §4.4). Returns 1 when
/// the section carries a sequence (the keyed-hash types), 0
/// otherwise (Simple Password / unknown types) — the value is
/// written to `*out_sequence`. Returns `LR_ERR_NULL` (-1) on a NULL
/// handle or NULL out-pointer.
///
/// # Safety
/// `s` must be a valid handle. `out_sequence` must point to a
/// writable `uint32_t`.
#[no_mangle]
pub unsafe extern "C" fn lr_bfd_auth_section_sequence(
    s: lr_bfd_auth_section_t,
    out_sequence: *mut u32,
) -> i32 {
    guarded(
        || unsafe {
            if out_sequence.is_null() {
                return LR_ERR_NULL;
            }
            let Some(sec) = borrow_section(s) else {
                return LR_ERR_NULL;
            };
            match sec.sequence {
                Some(seq) => {
                    unsafe { *out_sequence = seq };
                    1
                }
                None => 0,
            }
        },
        LR_ERR_PANIC,
    )
}

/// Read the data length (RFC 5880 §4.2 password bytes / §4.3 / §4.4
/// digest bytes). Returns 0 on a NULL handle.
///
/// # Safety
/// `s` must be a valid handle.
#[no_mangle]
pub unsafe extern "C" fn lr_bfd_auth_section_data_len(s: lr_bfd_auth_section_t) -> usize {
    guarded(
        || unsafe { borrow_section(s).map(|x| x.data.len()).unwrap_or(0) },
        0,
    )
}

/// Copy the data bytes (password / digest) into `out_data` (up to
/// `cap` bytes) and write the actual length to `*out_len`. Returns 0
/// on success, `LR_ERR_NULL` on a NULL handle / NULL out_len,
/// `LR_ERR_OTHER` when the buffer is too small (the length is still
/// written to `*out_len`).
///
/// # Safety
/// `s` must be a valid handle. `out_data` (when `cap > 0`) must
/// point to `cap` writable bytes. `out_len` must point to a writable
/// `uintptr_t`.
#[no_mangle]
pub unsafe extern "C" fn lr_bfd_auth_section_data(
    s: lr_bfd_auth_section_t,
    out_data: *mut u8,
    cap: usize,
    out_len: *mut usize,
) -> i32 {
    guarded(
        || unsafe {
            if out_len.is_null() {
                return LR_ERR_NULL;
            }
            let Some(sec) = borrow_section(s) else {
                return LR_ERR_NULL;
            };
            let len = sec.data.len();
            unsafe { *out_len = len };
            if len > cap {
                return LR_ERR_OTHER;
            }
            if !out_data.is_null() && len > 0 {
                unsafe {
                    std::ptr::copy_nonoverlapping(sec.data.as_ptr(), out_data, len);
                }
            }
            0
        },
        LR_ERR_PANIC,
    )
}

/// Total wire length of the section (the `Auth Len` field value):
/// Simple Password = 3 + password length; Keyed MD5 = 24; Keyed
/// SHA1 = 28 (RFC 5880 §4.2-§4.4). Returns 0 on a NULL handle.
///
/// Mirrors `lr_bfd::auth::AuthSection::wire_len`.
///
/// # Safety
/// `s` must be a valid handle.
#[no_mangle]
pub unsafe extern "C" fn lr_bfd_auth_section_wire_len(s: lr_bfd_auth_section_t) -> usize {
    guarded(
        || unsafe { borrow_section(s).map(|x| x.wire_len()).unwrap_or(0) },
        0,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ffi_auth_type_readers_match_rust() {
        // MD5: keyed-hash, not meticulous, digest 16.
        assert_eq!(
            lr_bfd_auth_type_expected_digest_len(LR_BFD_AUTH_TYPE_KEYED_MD5),
            16
        );
        assert_eq!(
            lr_bfd_auth_type_is_keyed_hash(LR_BFD_AUTH_TYPE_KEYED_MD5),
            1
        );
        assert_eq!(
            lr_bfd_auth_type_is_meticulous(LR_BFD_AUTH_TYPE_KEYED_MD5),
            0
        );
        // Meticulous SHA1: keyed-hash, meticulous, digest 20.
        assert_eq!(
            lr_bfd_auth_type_expected_digest_len(LR_BFD_AUTH_TYPE_METICULOUS_KEYED_SHA1),
            20
        );
        assert_eq!(
            lr_bfd_auth_type_is_keyed_hash(LR_BFD_AUTH_TYPE_METICULOUS_KEYED_SHA1),
            1
        );
        assert_eq!(
            lr_bfd_auth_type_is_meticulous(LR_BFD_AUTH_TYPE_METICULOUS_KEYED_SHA1),
            1
        );
        // Simple Password: not keyed-hash, no fixed digest length.
        assert_eq!(
            lr_bfd_auth_type_expected_digest_len(LR_BFD_AUTH_TYPE_SIMPLE_PASSWORD),
            -1
        );
        assert_eq!(
            lr_bfd_auth_type_is_keyed_hash(LR_BFD_AUTH_TYPE_SIMPLE_PASSWORD),
            0
        );
        assert_eq!(
            lr_bfd_auth_type_is_meticulous(LR_BFD_AUTH_TYPE_SIMPLE_PASSWORD),
            0
        );
        // Unknown type 99: not keyed-hash, no fixed digest length.
        assert_eq!(lr_bfd_auth_type_expected_digest_len(99), -1);
        assert_eq!(lr_bfd_auth_type_is_keyed_hash(99), 0);
        assert_eq!(lr_bfd_auth_type_is_meticulous(99), 0);
    }

    #[test]
    fn ffi_auth_key_round_trip() {
        let secret = b"shared-secret";
        let k = unsafe { lr_bfd_auth_key_new(7, secret.as_ptr(), secret.len()) };
        assert!(!k.is_null());
        assert_eq!(unsafe { lr_bfd_auth_key_key_id(k) }, 7);
        assert_eq!(unsafe { lr_bfd_auth_key_data_len(k) }, secret.len());
        let mut out = [0u8; 32];
        let mut len = 0usize;
        let rc = unsafe { lr_bfd_auth_key_data(k, out.as_mut_ptr(), out.len(), &raw mut len) };
        assert_eq!(rc, 0);
        assert_eq!(len, secret.len());
        assert_eq!(&out[..len], secret);
        unsafe { lr_bfd_auth_key_free(k) };
    }

    #[test]
    fn ffi_auth_key_simple_password() {
        let pw = b"hunter2hunter2";
        let k = unsafe { lr_bfd_auth_key_simple_password(3, pw.as_ptr(), pw.len()) };
        assert!(!k.is_null());
        assert_eq!(unsafe { lr_bfd_auth_key_key_id(k) }, 3);
        assert_eq!(unsafe { lr_bfd_auth_key_data_len(k) }, pw.len());
        unsafe { lr_bfd_auth_key_free(k) };
    }

    #[test]
    fn ffi_auth_key_handles_null_safely() {
        // NULL key handle: readers return 0 / -1.
        assert_eq!(unsafe { lr_bfd_auth_key_key_id(std::ptr::null_mut()) }, 0);
        assert_eq!(unsafe { lr_bfd_auth_key_data_len(std::ptr::null_mut()) }, 0);
        // NULL out_len on data reader: LR_ERR_NULL.
        let rc = unsafe {
            lr_bfd_auth_key_data(
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                0,
                std::ptr::null_mut(),
            )
        };
        assert_eq!(rc, LR_ERR_NULL);
        // Safe to free NULL.
        unsafe { lr_bfd_auth_key_free(std::ptr::null_mut()) };
    }

    #[test]
    fn ffi_auth_key_data_too_small_returns_other() {
        let secret = b"this-is-a-very-long-key-buffer";
        let k = unsafe { lr_bfd_auth_key_new(1, secret.as_ptr(), secret.len()) };
        // Buffer too small — LR_ERR_OTHER and len written.
        let mut out = [0u8; 4];
        let mut len = 0usize;
        let rc = unsafe { lr_bfd_auth_key_data(k, out.as_mut_ptr(), out.len(), &raw mut len) };
        assert_eq!(rc, LR_ERR_OTHER);
        assert_eq!(len, secret.len());
        unsafe { lr_bfd_auth_key_free(k) };
    }

    #[test]
    fn ffi_auth_section_simple_password_round_trip() {
        let pw = b"hunter2";
        let s = unsafe { lr_bfd_auth_section_simple_password(pw.as_ptr(), pw.len(), 7) };
        assert!(!s.is_null());
        assert_eq!(
            unsafe { lr_bfd_auth_section_auth_type(s) },
            LR_BFD_AUTH_TYPE_SIMPLE_PASSWORD
        );
        assert_eq!(unsafe { lr_bfd_auth_section_key_id(s) }, 7);
        // Simple Password has no sequence number.
        let mut seq = 0u32;
        assert_eq!(unsafe { lr_bfd_auth_section_sequence(s, &raw mut seq) }, 0);
        assert_eq!(unsafe { lr_bfd_auth_section_data_len(s) }, pw.len());
        // wire_len = 3 + password length per RFC 5880 §4.2.
        assert_eq!(unsafe { lr_bfd_auth_section_wire_len(s) }, 3 + pw.len());
        let mut out = [0u8; 16];
        let mut len = 0usize;
        let rc = unsafe { lr_bfd_auth_section_data(s, out.as_mut_ptr(), out.len(), &raw mut len) };
        assert_eq!(rc, 0);
        assert_eq!(&out[..len], pw);
        unsafe { lr_bfd_auth_section_free(s) };
    }

    #[test]
    fn ffi_auth_section_keyed_md5_round_trip() {
        let digest = [0u8; 16];
        let s =
            unsafe { lr_bfd_auth_section_keyed_md5(2, 0xdead_beef, digest.as_ptr(), digest.len()) };
        assert!(!s.is_null());
        assert_eq!(
            unsafe { lr_bfd_auth_section_auth_type(s) },
            LR_BFD_AUTH_TYPE_KEYED_MD5
        );
        assert_eq!(unsafe { lr_bfd_auth_section_key_id(s) }, 2);
        let mut seq = 0u32;
        assert_eq!(unsafe { lr_bfd_auth_section_sequence(s, &raw mut seq) }, 1);
        assert_eq!(seq, 0xdead_beef);
        assert_eq!(unsafe { lr_bfd_auth_section_data_len(s) }, 16);
        // Keyed MD5 wire length is 24 (RFC 5880 §4.3).
        assert_eq!(unsafe { lr_bfd_auth_section_wire_len(s) }, 24);
        unsafe { lr_bfd_auth_section_free(s) };
    }

    #[test]
    fn ffi_auth_section_keyed_sha1_round_trip() {
        let digest = [0u8; 20];
        let s = unsafe {
            lr_bfd_auth_section_keyed_sha1(4, 0xfeed_face, digest.as_ptr(), digest.len())
        };
        assert!(!s.is_null());
        assert_eq!(
            unsafe { lr_bfd_auth_section_auth_type(s) },
            LR_BFD_AUTH_TYPE_KEYED_SHA1
        );
        let mut seq = 0u32;
        assert_eq!(unsafe { lr_bfd_auth_section_sequence(s, &raw mut seq) }, 1);
        assert_eq!(seq, 0xfeed_face);
        // Keyed SHA1 wire length is 28 (RFC 5880 §4.4).
        assert_eq!(unsafe { lr_bfd_auth_section_wire_len(s) }, 28);
        unsafe { lr_bfd_auth_section_free(s) };
    }

    #[test]
    fn ffi_auth_section_meticulous_round_trip() {
        let md5 = [0u8; 16];
        let s = unsafe { lr_bfd_auth_section_meticulous_keyed_md5(3, 42, md5.as_ptr(), md5.len()) };
        assert_eq!(
            unsafe { lr_bfd_auth_section_auth_type(s) },
            LR_BFD_AUTH_TYPE_METICULOUS_KEYED_MD5
        );
        unsafe { lr_bfd_auth_section_free(s) };

        let sha1 = [0u8; 20];
        let s2 =
            unsafe { lr_bfd_auth_section_meticulous_keyed_sha1(5, 42, sha1.as_ptr(), sha1.len()) };
        assert_eq!(
            unsafe { lr_bfd_auth_section_auth_type(s2) },
            LR_BFD_AUTH_TYPE_METICULOUS_KEYED_SHA1
        );
        unsafe { lr_bfd_auth_section_free(s2) };
    }

    #[test]
    fn ffi_auth_section_handles_null_safely() {
        // NULL section handle: readers return 0 / -1.
        assert_eq!(
            unsafe { lr_bfd_auth_section_auth_type(std::ptr::null_mut()) },
            0
        );
        assert_eq!(
            unsafe { lr_bfd_auth_section_key_id(std::ptr::null_mut()) },
            0
        );
        assert_eq!(
            unsafe { lr_bfd_auth_section_data_len(std::ptr::null_mut()) },
            0
        );
        assert_eq!(
            unsafe { lr_bfd_auth_section_wire_len(std::ptr::null_mut()) },
            0
        );
        let mut seq = 0u32;
        assert_eq!(
            unsafe { lr_bfd_auth_section_sequence(std::ptr::null_mut(), &raw mut seq) },
            LR_ERR_NULL
        );
        // NULL out-pointer: LR_ERR_NULL.
        assert_eq!(
            unsafe { lr_bfd_auth_section_sequence(std::ptr::null_mut(), std::ptr::null_mut()) },
            LR_ERR_NULL
        );
        // Safe to free NULL.
        unsafe { lr_bfd_auth_section_free(std::ptr::null_mut()) };
    }

    #[test]
    fn ffi_auth_section_data_too_small_returns_other() {
        let digest = [0xab; 16];
        let s = unsafe { lr_bfd_auth_section_keyed_md5(2, 1, digest.as_ptr(), digest.len()) };
        // Buffer too small — LR_ERR_OTHER and len written.
        let mut out = [0u8; 4];
        let mut len = 0usize;
        let rc = unsafe { lr_bfd_auth_section_data(s, out.as_mut_ptr(), out.len(), &raw mut len) };
        assert_eq!(rc, LR_ERR_OTHER);
        assert_eq!(len, 16);
        unsafe { lr_bfd_auth_section_free(s) };
    }
}
