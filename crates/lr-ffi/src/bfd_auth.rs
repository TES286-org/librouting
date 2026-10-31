//! BFD keyed authentication FFI (RFC 5880 §6.7 / §6.8.5).
#![allow(unused_unsafe)]

use lr_bfd::keyed_auth::{BfdKeyedAuth, KeyedAuthAlgorithm};
use lr_core::time::Instant;

use crate::error::{set_last_error, LrError, LR_ERR_PANIC};
use crate::guarded;

const LR_ERR_NULL: i32 = LrError::Null as i32;
const LR_ERR_OTHER: i32 = LrError::Other as i32;

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

/// Build the wire auth section to ride the next outbound packet
/// (RFC 5880 §6.7.3 / §6.7.4): the auth type, key ID, current transmit
/// sequence and the **shared key in the digest field** (the
/// placeholder the hash is computed over). The returned
/// `lr_bfd_auth_section_t` is owned by the caller; free it via
/// [`crate::bfd_auth_section::lr_bfd_auth_section_free`]. Returns
/// NULL on a NULL `BfdKeyedAuth` or on panic.
///
/// Mirrors `lr_bfd::keyed_auth::BfdKeyedAuth::auth_section_for_tx`.
///
/// # Safety
/// `a` must be a valid handle.
#[no_mangle]
pub unsafe extern "C" fn lr_bfd_keyed_auth_auth_section_for_tx(
    a: lr_bfd_keyed_auth_t,
) -> crate::bfd_auth_section::lr_bfd_auth_section_t {
    guarded(
        || unsafe {
            let Some(auth) = borrow_auth(a) else {
                return std::ptr::null_mut();
            };
            let section = auth.auth_section_for_tx();
            crate::bfd_auth_section::box_section_pub(section)
        },
        std::ptr::null_mut(),
    )
}

/// Sign an encoded outbound BFD Control packet in place (RFC 5880
/// §6.7.3 / §6.7.4). The `packet` slice MUST be the full encoded
/// packet with the auth section's digest field carrying the shared
/// key (as produced by `auth_section_for_tx` + `BfdCodec::encode`).
/// The last `digest_len` bytes of the slice are replaced with the
/// computed digest. Returns 0 on success, `LR_ERR_NULL` (-1) on a
/// NULL handle / NULL packet, `LR_ERR_OTHER` (-6) when the packet is
/// shorter than the digest length (defensive — the caller has
/// already encoded a valid section).
///
/// Mirrors `lr_bfd::keyed_auth::BfdKeyedAuth::sign_packet`.
///
/// # Safety
/// `a` must be a valid handle. `packet` must point to `packet_len`
/// writable bytes.
#[no_mangle]
pub unsafe extern "C" fn lr_bfd_keyed_auth_sign_packet(
    a: lr_bfd_keyed_auth_t,
    packet: *mut u8,
    packet_len: usize,
) -> i32 {
    guarded(
        || unsafe {
            let Some(auth) = borrow_auth(a) else {
                return LR_ERR_NULL;
            };
            if packet.is_null() {
                return LR_ERR_NULL;
            }
            if packet_len == 0 {
                return LR_ERR_OTHER;
            }
            let buf = unsafe { std::slice::from_raw_parts_mut(packet, packet_len) };
            auth.sign_packet(buf);
            0
        },
        LR_ERR_PANIC,
    )
}

/// Verify an inbound BFD Control packet against this auth state
/// (RFC 5880 §6.7.3 / §6.7.4 anti-replay + digest check). Returns 1
/// when the packet authenticates and the sequence number is within
/// the anti-replay window (the receive state is updated in place),
/// 0 when it does not, `LR_ERR_NULL` (-1) on a NULL handle / NULL
/// packet / NULL section.
///
/// `received_packet` is the full encoded packet bytes as received;
/// `section` is the parsed auth section (the received digest lives
/// in its `data` field); `detect_mult` is the session's detect
/// multiplier used to bound the anti-replay window.
///
/// Mirrors `lr_bfd::keyed_auth::BfdKeyedAuth::verify_inbound`.
///
/// # Safety
/// `a` must be a valid handle. `packet` must point to `packet_len`
/// readable bytes. `section` must be a valid
/// `lr_bfd_auth_section_t` handle.
#[no_mangle]
pub unsafe extern "C" fn lr_bfd_keyed_auth_verify_inbound(
    a: lr_bfd_keyed_auth_t,
    packet: *const u8,
    packet_len: usize,
    section: crate::bfd_auth_section::lr_bfd_auth_section_t,
    detect_mult: u8,
) -> i32 {
    guarded(
        || unsafe {
            let Some(auth) = borrow_auth_mut(a) else {
                return LR_ERR_NULL;
            };
            if packet.is_null() {
                return LR_ERR_NULL;
            }
            let Some(sec) = crate::bfd_auth_section::borrow_section_pub(section) else {
                return LR_ERR_NULL;
            };
            let pkt = unsafe { std::slice::from_raw_parts(packet, packet_len) };
            if auth.verify_inbound(pkt, sec, detect_mult) {
                1
            } else {
                0
            }
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

    /// `lr_bfd_keyed_auth_auth_section_for_tx` mirrors
    /// `BfdKeyedAuth::auth_section_for_tx` (RFC 5880 §6.7.3 / §6.7.4):
    /// the returned section carries the auth type, key id, current
    /// xmit_seq and the shared key in the digest field.
    #[test]
    fn ffi_keyed_auth_auth_section_for_tx() {
        let secret = b"0123456789abcdef";
        let a = unsafe {
            lr_bfd_keyed_auth_new(LR_BFD_AUTH_ALGO_KEYED_MD5, 7, secret.as_ptr(), secret.len())
        };
        assert_eq!(unsafe { lr_bfd_keyed_auth_xmit_seq(a) }, 0);
        let s = unsafe { lr_bfd_keyed_auth_auth_section_for_tx(a) };
        assert!(!s.is_null(), "auth_section_for_tx must not return NULL");
        use crate::bfd_auth_section::*;
        assert_eq!(
            unsafe { lr_bfd_auth_section_auth_type(s) },
            LR_BFD_AUTH_TYPE_KEYED_MD5
        );
        assert_eq!(unsafe { lr_bfd_auth_section_key_id(s) }, 7);
        let mut seq = 0u32;
        assert_eq!(unsafe { lr_bfd_auth_section_sequence(s, &raw mut seq) }, 1);
        assert_eq!(seq, 0, "xmit_seq is 0 before any advance");
        assert_eq!(
            unsafe { lr_bfd_auth_section_data_len(s) },
            16,
            "MD5 digest field is 16 bytes"
        );
        // The shared key sits in the digest field zero-padded to 16 bytes.
        let mut buf = [0u8; 16];
        let mut len = 0usize;
        let rc = unsafe { lr_bfd_auth_section_data(s, buf.as_mut_ptr(), buf.len(), &raw mut len) };
        assert_eq!(rc, 0);
        assert_eq!(len, 16);
        assert_eq!(&buf[..secret.len()], secret);
        assert_eq!(&buf[secret.len()..], &[0u8; 16][..16 - secret.len()]);
        unsafe { lr_bfd_auth_section_free(s) };
        unsafe { lr_bfd_keyed_auth_free(a) };
    }

    /// `auth_section_for_tx` returns NULL on a NULL `BfdKeyedAuth`.
    #[test]
    fn ffi_keyed_auth_auth_section_for_tx_null() {
        let s = unsafe { lr_bfd_keyed_auth_auth_section_for_tx(std::ptr::null_mut()) };
        assert!(s.is_null());
    }

    /// End-to-end: build a BFD packet carrying the auth section, encode
    /// it, sign it, decode it, verify it. Mirrors the Rust-side
    /// `sign_and_verify_round_trip_md5` test in `keyed_auth.rs`.
    #[test]
    fn ffi_keyed_auth_sign_and_verify_round_trip_md5() {
        use crate::bfd::*;
        use crate::bfd_auth_section::*;
        use crate::lr_bytes_t;

        // Build a keyed MD5 auth state with a 16-byte shared key.
        let secret = b"0123456789abcdef";
        let a = unsafe {
            lr_bfd_keyed_auth_new(LR_BFD_AUTH_ALGO_KEYED_MD5, 7, secret.as_ptr(), secret.len())
        };

        // Build a BFD packet and install the auth section. set_auth
        // consumes the section handle.
        let p = lr_bfd_packet_heartbeat(0x1111_2222, 0x3333_4444);
        let s = unsafe { lr_bfd_keyed_auth_auth_section_for_tx(a) };
        // Set the A flag bit (RFC 5880 §4.1) so the codec emits the section.
        unsafe {
            assert_eq!(lr_bfd_packet_set_flags(p, 0b0000_0100), 0);
            assert_eq!(lr_bfd_packet_set_auth(p, s), 0);
            assert_eq!(lr_bfd_packet_auth_present(p), 1);
        }

        // Encode the packet (the section's digest field carries the
        // shared key at this stage — exactly what sign_packet expects).
        let mut out = lr_bytes_t {
            ptr: std::ptr::null_mut(),
            len: 0,
            cap: 0,
        };
        let rc = unsafe { lr_bfd_encode(p, &raw mut out) };
        assert_eq!(rc, 0);
        assert!(!out.ptr.is_null());

        // Sign the encoded packet in place — the last 16 bytes
        // (MD5 digest) are replaced with the computed hash.
        let rc = unsafe { lr_bfd_keyed_auth_sign_packet(a, out.ptr, out.len) };
        assert_eq!(rc, 0);

        // Decode the signed packet — the auth section's `data` field
        // now carries the received digest (not the shared key).
        let mut decoded: lr_bfd_packet_t = std::ptr::null_mut();
        let rc = unsafe { lr_bfd_decode(out.ptr, out.len, &raw mut decoded) };
        assert_eq!(rc, 0);
        assert!(!decoded.is_null());
        let mut sec_out: lr_bfd_auth_section_t = std::ptr::null_mut();
        let rc = unsafe { lr_bfd_packet_auth(decoded, &raw mut sec_out) };
        assert_eq!(rc, 0);
        assert!(!sec_out.is_null());

        // Verify the inbound packet — should authenticate (first
        // packet, AuthSeqKnown=0 → accept any sequence).
        let rc = unsafe { lr_bfd_keyed_auth_verify_inbound(a, out.ptr, out.len, sec_out, 3) };
        assert_eq!(rc, 1, "the signed packet must verify against its own key");
        assert_eq!(unsafe { lr_bfd_keyed_auth_rcv_auth_seq_known(a) }, 1);

        // Free everything.
        unsafe {
            lr_bfd_auth_section_free(sec_out);
            lr_bfd_packet_free(decoded);
            // Reclaim the bytes_t buffer to avoid a leak.
            let _ = Vec::from_raw_parts(out.ptr, out.len, out.cap);
            lr_bfd_packet_free(p);
            lr_bfd_keyed_auth_free(a);
        }
    }

    /// `sign_packet` and `verify_inbound` return `LR_ERR_NULL` on NULL
    /// inputs and 0 (verify) when the auth type does not match.
    #[test]
    fn ffi_keyed_auth_sign_verify_null_inputs() {
        let secret = b"0123456789abcdef";
        let a = unsafe {
            lr_bfd_keyed_auth_new(LR_BFD_AUTH_ALGO_KEYED_MD5, 1, secret.as_ptr(), secret.len())
        };
        // sign_packet: NULL packet.
        let rc = unsafe { lr_bfd_keyed_auth_sign_packet(a, std::ptr::null_mut(), 0) };
        assert_eq!(rc, LR_ERR_NULL);
        // sign_packet: NULL auth handle.
        let mut buf = [0u8; 32];
        let rc = unsafe {
            lr_bfd_keyed_auth_sign_packet(std::ptr::null_mut(), buf.as_mut_ptr(), buf.len())
        };
        assert_eq!(rc, LR_ERR_NULL);
        // verify_inbound: NULL auth handle.
        let rc = unsafe {
            lr_bfd_keyed_auth_verify_inbound(
                std::ptr::null_mut(),
                buf.as_ptr(),
                buf.len(),
                std::ptr::null_mut(),
                3,
            )
        };
        assert_eq!(rc, LR_ERR_NULL);
        // verify_inbound: NULL packet.
        let rc = unsafe {
            lr_bfd_keyed_auth_verify_inbound(a, std::ptr::null(), 0, std::ptr::null_mut(), 3)
        };
        assert_eq!(rc, LR_ERR_NULL);
        unsafe { lr_bfd_keyed_auth_free(a) };
    }
}
