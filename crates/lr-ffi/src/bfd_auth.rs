//! BFD keyed authentication FFI (RFC 5880 §6.7 / §6.8.5).
#![allow(unused_unsafe)]

use lr_bfd::keyed_auth::{BfdKeyedAuth, KeyedAuthAlgorithm};
use lr_core::time::Instant;

use crate::error::{set_last_error, LrError, LR_ERR_PANIC};
use crate::guarded;

const LR_ERR_NULL: i32 = LrError::Null as i32;

pub const LR_BFD_AUTH_ALGO_KEYED_MD5: i32 = 1;
pub const LR_BFD_AUTH_ALGO_METICULOUS_KEYED_MD5: i32 = 2;
pub const LR_BFD_AUTH_ALGO_KEYED_SHA1: i32 = 3;
pub const LR_BFD_AUTH_ALGO_METICULOUS_KEYED_SHA1: i32 = 4;

fn algo_to_i32(a: KeyedAuthAlgorithm) -> i32 {
    match a {
        KeyedAuthAlgorithm::KeyedMd5 => LR_BFD_AUTH_ALGO_KEYED_MD5,
        KeyedAuthAlgorithm::MeticulousKeyedMd5 => LR_BFD_AUTH_ALGO_METICULOUS_KEYED_MD5,
        KeyedAuthAlgorithm::KeyedSha1 => LR_BFD_AUTH_ALGO_KEYED_SHA1,
        KeyedAuthAlgorithm::MeticulousKeyedSha1 => LR_BFD_AUTH_ALGO_METICULOUS_KEYED_SHA1,
    }
}
fn i32_to_algo(v: i32) -> Option<KeyedAuthAlgorithm> {
    match v {
        LR_BFD_AUTH_ALGO_KEYED_MD5 => Some(KeyedAuthAlgorithm::KeyedMd5),
        LR_BFD_AUTH_ALGO_METICULOUS_KEYED_MD5 => Some(KeyedAuthAlgorithm::MeticulousKeyedMd5),
        LR_BFD_AUTH_ALGO_KEYED_SHA1 => Some(KeyedAuthAlgorithm::KeyedSha1),
        LR_BFD_AUTH_ALGO_METICULOUS_KEYED_SHA1 => Some(KeyedAuthAlgorithm::MeticulousKeyedSha1),
        _ => None,
    }
}

#[repr(C)]
pub struct OpaqueBfdKeyedAuth {
    _private: [u8; 0],
}
pub type lr_bfd_keyed_auth_t = *mut OpaqueBfdKeyedAuth;
fn box_auth(a: BfdKeyedAuth) -> lr_bfd_keyed_auth_t {
    Box::into_raw(Box::new(a)) as lr_bfd_keyed_auth_t
}
unsafe fn borrow_auth(a: lr_bfd_keyed_auth_t) -> Option<&'static BfdKeyedAuth> {
    if a.is_null() {
        None
    } else {
        Some(unsafe { &*(a as *const BfdKeyedAuth) })
    }
}
unsafe fn borrow_auth_mut(a: lr_bfd_keyed_auth_t) -> Option<&'static mut BfdKeyedAuth> {
    if a.is_null() {
        None
    } else {
        Some(unsafe { &mut *(a as *mut BfdKeyedAuth) })
    }
}
unsafe fn unbox_auth(a: lr_bfd_keyed_auth_t) -> Option<Box<BfdKeyedAuth>> {
    if a.is_null() {
        None
    } else {
        Some(unsafe { Box::from_raw(a as *mut BfdKeyedAuth) })
    }
}

#[no_mangle]
pub unsafe extern "C" fn lr_bfd_keyed_auth_new(
    algorithm: i32,
    key_id: u8,
    secret: *const u8,
    secret_len: usize,
) -> lr_bfd_keyed_auth_t {
    guarded(
        || unsafe {
            let Some(algo) = i32_to_algo(algorithm) else {
                set_last_error(format!("unknown BFD auth algorithm id {algorithm}"));
                return std::ptr::null_mut();
            };
            if secret.is_null() && secret_len != 0 {
                return std::ptr::null_mut();
            }
            let s = if secret_len == 0 {
                &[][..]
            } else {
                unsafe { std::slice::from_raw_parts(secret, secret_len) }
            };
            match BfdKeyedAuth::new(key_id, algo, s.to_vec()) {
                Some(a) => box_auth(a),
                None => {
                    set_last_error("BfdKeyedAuth::new rejected".into());
                    std::ptr::null_mut()
                }
            }
        },
        std::ptr::null_mut(),
    )
}

#[no_mangle]
pub unsafe extern "C" fn lr_bfd_keyed_auth_key_id(a: lr_bfd_keyed_auth_t) -> u8 {
    guarded(
        || unsafe { borrow_auth(a).map(|x| x.key_id()).unwrap_or(0) },
        0,
    )
}
#[no_mangle]
pub unsafe extern "C" fn lr_bfd_keyed_auth_algorithm(a: lr_bfd_keyed_auth_t) -> i32 {
    guarded(
        || unsafe {
            borrow_auth(a)
                .map(|x| algo_to_i32(x.algorithm()))
                .unwrap_or(0)
        },
        0,
    )
}
#[no_mangle]
pub unsafe extern "C" fn lr_bfd_keyed_auth_auth_type_value(a: lr_bfd_keyed_auth_t) -> u8 {
    guarded(
        || unsafe {
            borrow_auth(a)
                .map(|x| match x.algorithm().auth_type() {
                    lr_bfd::auth::AuthType::SimplePassword => 1,
                    lr_bfd::auth::AuthType::KeyedMd5 => 2,
                    lr_bfd::auth::AuthType::MeticulousKeyedMd5 => 3,
                    lr_bfd::auth::AuthType::KeyedSha1 => 4,
                    lr_bfd::auth::AuthType::MeticulousKeyedSha1 => 5,
                    lr_bfd::auth::AuthType::Unknown(v) => v,
                })
                .unwrap_or(0)
        },
        0,
    )
}
#[no_mangle]
pub unsafe extern "C" fn lr_bfd_keyed_auth_digest_len(a: lr_bfd_keyed_auth_t) -> usize {
    guarded(
        || unsafe {
            borrow_auth(a)
                .map(|x| x.algorithm().digest_len())
                .unwrap_or(0)
        },
        0,
    )
}
#[no_mangle]
pub unsafe extern "C" fn lr_bfd_keyed_auth_is_meticulous(a: lr_bfd_keyed_auth_t) -> u8 {
    guarded(
        || unsafe {
            borrow_auth(a)
                .map(|x| x.algorithm().is_meticulous() as u8)
                .unwrap_or(0)
        },
        0,
    )
}
#[no_mangle]
pub unsafe extern "C" fn lr_bfd_keyed_auth_xmit_seq(a: lr_bfd_keyed_auth_t) -> u32 {
    guarded(
        || unsafe { borrow_auth(a).map(|x| x.xmit_seq()).unwrap_or(0) },
        0,
    )
}
#[no_mangle]
pub unsafe extern "C" fn lr_bfd_keyed_auth_rcv_auth_seq_known(a: lr_bfd_keyed_auth_t) -> u8 {
    guarded(
        || unsafe {
            borrow_auth(a)
                .map(|x| x.rcv_auth_seq_known() as u8)
                .unwrap_or(0)
        },
        0,
    )
}
#[no_mangle]
pub unsafe extern "C" fn lr_bfd_keyed_auth_rcv_auth_seq(a: lr_bfd_keyed_auth_t) -> u32 {
    guarded(
        || unsafe { borrow_auth(a).map(|x| x.rcv_auth_seq()).unwrap_or(0) },
        0,
    )
}

#[no_mangle]
pub unsafe extern "C" fn lr_bfd_keyed_auth_advance_xmit_seq(a: lr_bfd_keyed_auth_t) -> i32 {
    guarded(
        || unsafe {
            let Some(auth) = borrow_auth_mut(a) else {
                return LR_ERR_NULL;
            };
            auth.advance_xmit_seq();
            0
        },
        LR_ERR_PANIC,
    )
}
#[no_mangle]
pub unsafe extern "C" fn lr_bfd_keyed_auth_free(a: lr_bfd_keyed_auth_t) {
    guarded(
        || unsafe {
            drop(unbox_auth(a));
        },
        (),
    )
}

// ---- BfdSession auth integration ----

#[no_mangle]
pub unsafe extern "C" fn lr_bfd_session_set_keyed_auth(
    s: crate::bfd_session::lr_bfd_session_t,
    auth: lr_bfd_keyed_auth_t,
) -> i32 {
    guarded(
        || unsafe {
            let Some(sess) = crate::bfd_session::borrow_session_mut(s) else {
                return LR_ERR_NULL;
            };
            let auth_opt = if auth.is_null() {
                None
            } else {
                let Some(a) = unbox_auth(auth) else {
                    return LR_ERR_NULL;
                };
                Some(*a)
            };
            sess.set_keyed_auth(auth_opt);
            0
        },
        LR_ERR_PANIC,
    )
}

#[no_mangle]
pub unsafe extern "C" fn lr_bfd_session_keyed_auth_present(
    s: crate::bfd_session::lr_bfd_session_t,
) -> u8 {
    guarded(
        || unsafe {
            let Some(sess) = crate::bfd_session::borrow_session(s) else {
                return 0;
            };
            sess.keyed_auth().is_some() as u8
        },
        0,
    )
}

#[no_mangle]
pub unsafe extern "C" fn lr_bfd_session_update_timers(
    s: crate::bfd_session::lr_bfd_session_t,
    now_ms: u64,
    desired_min_tx: u32,
    required_min_rx: u32,
    out_array: *mut *mut crate::bfd_session::lr_bfd_session_event_t,
    out_count: *mut usize,
) -> i32 {
    guarded(
        || unsafe {
            let Some(sess) = crate::bfd_session::borrow_session_mut(s) else {
                return LR_ERR_NULL;
            };
            if out_array.is_null() || out_count.is_null() {
                return LR_ERR_NULL;
            }
            let events = sess.update_timers(Instant(now_ms), desired_min_tx, required_min_rx);
            crate::bfd_session::write_event_array(events, out_array, out_count)
        },
        LR_ERR_PANIC,
    )
}

#[no_mangle]
pub unsafe extern "C" fn lr_bfd_session_remote_detect_mult(
    s: crate::bfd_session::lr_bfd_session_t,
) -> u8 {
    guarded(
        || unsafe {
            crate::bfd_session::borrow_session(s)
                .map(|x| x.remote_detect_mult())
                .unwrap_or(0)
        },
        0,
    )
}
#[no_mangle]
pub unsafe extern "C" fn lr_bfd_session_poll_active(s: crate::bfd_session::lr_bfd_session_t) -> u8 {
    guarded(
        || unsafe {
            crate::bfd_session::borrow_session(s)
                .map(|x| x.poll_active() as u8)
                .unwrap_or(0)
        },
        0,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn ffi_keyed_auth_new() {
        let secret = b"0123456789abcdef";
        let a = unsafe {
            lr_bfd_keyed_auth_new(LR_BFD_AUTH_ALGO_KEYED_MD5, 1, secret.as_ptr(), secret.len())
        };
        assert!(!a.is_null());
        assert_eq!(unsafe { lr_bfd_keyed_auth_key_id(a) }, 1);
        assert_eq!(unsafe { lr_bfd_keyed_auth_digest_len(a) }, 16);
        unsafe { lr_bfd_keyed_auth_free(a) };
    }
    #[test]
    fn ffi_keyed_auth_sha1() {
        let secret = b"0123456789abcdef0123";
        let a = unsafe {
            lr_bfd_keyed_auth_new(
                LR_BFD_AUTH_ALGO_METICULOUS_KEYED_SHA1,
                2,
                secret.as_ptr(),
                secret.len(),
            )
        };
        assert!(!a.is_null());
        assert_eq!(unsafe { lr_bfd_keyed_auth_digest_len(a) }, 20);
        assert_eq!(unsafe { lr_bfd_keyed_auth_is_meticulous(a) }, 1);
        unsafe { lr_bfd_keyed_auth_free(a) };
    }
    #[test]
    fn ffi_keyed_auth_advance() {
        let secret = b"0123456789abcdef";
        let a = unsafe {
            lr_bfd_keyed_auth_new(LR_BFD_AUTH_ALGO_KEYED_MD5, 1, secret.as_ptr(), secret.len())
        };
        assert_eq!(unsafe { lr_bfd_keyed_auth_xmit_seq(a) }, 0);
        assert_eq!(unsafe { lr_bfd_keyed_auth_advance_xmit_seq(a) }, 0);
        assert_eq!(unsafe { lr_bfd_keyed_auth_xmit_seq(a) }, 1);
        unsafe { lr_bfd_keyed_auth_free(a) };
    }
    #[test]
    fn ffi_session_set_keyed_auth() {
        let cfg = crate::bfd_session::lr_bfd_config_new(3, 1_000_000, 1_000_000, 0, 1);
        let s = unsafe { crate::bfd_session::lr_bfd_session_new(cfg, 1) };
        assert_eq!(unsafe { lr_bfd_session_keyed_auth_present(s) }, 0);
        let secret = b"0123456789abcdef";
        let a = unsafe {
            lr_bfd_keyed_auth_new(LR_BFD_AUTH_ALGO_KEYED_MD5, 1, secret.as_ptr(), secret.len())
        };
        assert_eq!(unsafe { lr_bfd_session_set_keyed_auth(s, a) }, 0);
        assert_eq!(unsafe { lr_bfd_session_keyed_auth_present(s) }, 1);
        assert_eq!(
            unsafe { lr_bfd_session_set_keyed_auth(s, std::ptr::null_mut()) },
            0
        );
        assert_eq!(unsafe { lr_bfd_session_keyed_auth_present(s) }, 0);
        unsafe { crate::bfd_session::lr_bfd_session_free(s) };
    }
    #[test]
    fn ffi_session_remote_detect_mult_fresh() {
        let cfg = crate::bfd_session::lr_bfd_config_new(3, 1_000_000, 1_000_000, 0, 1);
        let s = unsafe { crate::bfd_session::lr_bfd_session_new(cfg, 1) };
        assert_eq!(unsafe { lr_bfd_session_remote_detect_mult(s) }, 0);
        assert_eq!(unsafe { lr_bfd_session_poll_active(s) }, 0);
        unsafe { crate::bfd_session::lr_bfd_session_free(s) };
    }
}
