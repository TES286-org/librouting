//! BGP-4 message codec FFI — `lr_bgp_codec_*` exposes the standalone
//! `lr_bgp::BgpCodec` (RFC 4271) so an embedder can drive encode/decode
//! without going through the daemon's `DefaultRouter` lifecycle.

// The closure body passed to `guarded` is wrapped in a single `unsafe`
// block to mirror the `pub unsafe extern "C" fn` shape.
#![allow(unused_unsafe)]

use lr_bgp::{BgpCodec, BgpMessage};

use crate::error::{set_last_error, LrError, LR_ERR_PANIC};
use crate::guarded;
use crate::handle::{box_bgp_message, lr_bgp_message_t, lr_bytes_t};

const LR_ERR_NULL: i32 = LrError::Null as i32;
const LR_ERR_CODEC: i32 = LrError::Codec as i32;

#[repr(C)]
pub struct OpaqueBgpCodec {
    _private: [u8; 0],
}

pub type lr_bgp_codec_t = *mut OpaqueBgpCodec;

fn box_codec(c: BgpCodec) -> lr_bgp_codec_t {
    Box::into_raw(Box::new(c)) as lr_bgp_codec_t
}

unsafe fn borrow_codec(c: lr_bgp_codec_t) -> Option<&'static BgpCodec> {
    if c.is_null() {
        return None;
    }
    Some(unsafe { &*(c as *const BgpCodec) })
}

unsafe fn borrow_codec_mut(c: lr_bgp_codec_t) -> Option<&'static mut BgpCodec> {
    if c.is_null() {
        return None;
    }
    Some(unsafe { &mut *(c as *mut BgpCodec) })
}

/// One AFI/SAFI pair — the FFI view of `lr_core::nlri::NlriFamily`.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct lr_afi_safi_t {
    pub afi: u16,
    pub safi: u8,
}

/// Construct a BGP-4 message codec (RFC 4271). Defaults to `asn4 = false`
/// and `add_path = (empty, empty)`.
#[no_mangle]
pub extern "C" fn lr_bgp_codec_new() -> lr_bgp_codec_t {
    guarded(|| box_codec(BgpCodec::new()), std::ptr::null_mut())
}

/// Construct a BGP-4 codec with explicit `asn4` (RFC 6793) flag.
#[no_mangle]
pub extern "C" fn lr_bgp_codec_with_asn4(asn4: u8) -> lr_bgp_codec_t {
    guarded(
        || box_codec(BgpCodec::new().with_asn4(asn4 != 0)),
        std::ptr::null_mut(),
    )
}

/// Set the codec's `asn4` flag in place (RFC 6793). Returns
/// `LR_ERR_NULL` (-1) on a NULL codec.
///
/// # Safety
/// `c` must have been produced by [`lr_bgp_codec_new`] and not freed.
#[no_mangle]
pub unsafe extern "C" fn lr_bgp_codec_set_asn4(c: lr_bgp_codec_t, asn4: u8) -> i32 {
    guarded(
        || unsafe {
            let Some(codec) = borrow_codec_mut(c) else {
                return LR_ERR_NULL;
            };
            codec.set_asn4(asn4 != 0);
            0
        },
        LR_ERR_PANIC,
    )
}

/// Read the codec's `asn4` flag. Returns 1 when 4-byte AS is in use,
/// 0 otherwise (and 0 on a NULL codec).
///
/// # Safety
/// `c` must be a valid handle.
#[no_mangle]
pub unsafe extern "C" fn lr_bgp_codec_asn4_active(c: lr_bgp_codec_t) -> u8 {
    guarded(
        || unsafe { borrow_codec(c).map(|c| c.asn4_active() as u8).unwrap_or(0) },
        0,
    )
}

/// Configure Add-Path (RFC 7911) TX/RX families in place.
///
/// # Safety
/// `c` must be a valid handle. `tx`/`rx` must each point to `tx_count`
/// / `rx_count` readable `lr_afi_safi_t` records (NULL only when the
/// corresponding count is 0).
#[no_mangle]
pub unsafe extern "C" fn lr_bgp_codec_set_add_path(
    c: lr_bgp_codec_t,
    tx: *const lr_afi_safi_t,
    tx_count: usize,
    rx: *const lr_afi_safi_t,
    rx_count: usize,
) -> i32 {
    guarded(
        || unsafe {
            let Some(codec) = borrow_codec_mut(c) else {
                return LR_ERR_NULL;
            };
            // XOR check: (NULL pointer + non-zero count) is illegal, as is
            // (non-NULL pointer + zero count). Both signal a confused
            // caller — error rather than silently treating as "no
            // families" so a mis-formed call does not accidentally clear
            // an existing Add-Path configuration.
            if tx.is_null() != (tx_count == 0) {
                return LR_ERR_NULL;
            }
            if rx.is_null() != (rx_count == 0) {
                return LR_ERR_NULL;
            }
            let tx_fams: Vec<lr_core::nlri::NlriFamily> = if tx.is_null() {
                Vec::new()
            } else {
                let slice = unsafe { std::slice::from_raw_parts(tx, tx_count) };
                slice
                    .iter()
                    .map(|s| lr_core::nlri::NlriFamily {
                        afi: s.afi,
                        safi: s.safi,
                    })
                    .collect()
            };
            let rx_fams: Vec<lr_core::nlri::NlriFamily> = if rx.is_null() {
                Vec::new()
            } else {
                let slice = unsafe { std::slice::from_raw_parts(rx, rx_count) };
                slice
                    .iter()
                    .map(|s| lr_core::nlri::NlriFamily {
                        afi: s.afi,
                        safi: s.safi,
                    })
                    .collect()
            };
            codec.set_add_path(tx_fams, rx_fams);
            0
        },
        LR_ERR_PANIC,
    )
}

/// Decode one BGP message from `data`. Returns 0 on success and writes
/// a freshly-allocated `lr_bgp_message_t` to `*out`. `Ok(None)` from the
/// Rust codec (incomplete frame) returns `LR_ERR_NULL` (-1) with the
/// last-error string set to "truncated". Decode errors return
/// `LR_ERR_CODEC` (-5).
///
/// # Safety
/// `data` must point to `len` readable bytes. `out` must point to a
/// writable `lr_bgp_message_t`.
#[no_mangle]
pub unsafe extern "C" fn lr_bgp_codec_decode_slice(
    c: lr_bgp_codec_t,
    data: *const u8,
    len: usize,
    out: *mut lr_bgp_message_t,
) -> i32 {
    guarded(
        || unsafe {
            let Some(codec) = borrow_codec_mut(c) else {
                return LR_ERR_NULL;
            };
            if data.is_null() || out.is_null() {
                return LR_ERR_NULL;
            }
            let slice = unsafe { std::slice::from_raw_parts(data, len) };
            match codec.decode_slice(slice) {
                Ok(Some(m)) => {
                    unsafe { *out = box_bgp_message(m) }
                    0
                }
                Ok(None) => {
                    set_last_error("truncated".into());
                    LR_ERR_NULL
                }
                Err(e) => {
                    set_last_error(format!("{e:?}"));
                    LR_ERR_CODEC
                }
            }
        },
        LR_ERR_PANIC,
    )
}

/// Encode one BGP message to wire bytes. Returns 0 on success and
/// writes a freshly-allocated `lr_bytes_t` to `*out`.
///
/// # Safety
/// `c` must be a valid codec handle. `msg` must be a valid
/// `lr_bgp_message_t`. `out` must point to a writable `lr_bytes_t`.
#[no_mangle]
pub unsafe extern "C" fn lr_bgp_codec_encode_vec(
    c: lr_bgp_codec_t,
    msg: lr_bgp_message_t,
    out: *mut lr_bytes_t,
) -> i32 {
    guarded(
        || unsafe {
            let Some(codec) = borrow_codec(c) else {
                return LR_ERR_NULL;
            };
            if msg.is_null() || out.is_null() {
                return LR_ERR_NULL;
            }
            let m: &BgpMessage = &*(msg as *const BgpMessage);
            match codec.encode_vec(m) {
                Ok(b) => {
                    unsafe { *out = lr_bytes_t::from_vec(b) }
                    0
                }
                Err(e) => {
                    set_last_error(e.to_string());
                    LR_ERR_CODEC
                }
            }
        },
        LR_ERR_PANIC,
    )
}

/// Drop a boxed `BgpCodec`. Safe to call with NULL.
///
/// # Safety
/// `c` must have been produced by [`lr_bgp_codec_new`] and not freed.
#[no_mangle]
pub unsafe extern "C" fn lr_bgp_codec_free(c: lr_bgp_codec_t) {
    guarded(
        || unsafe {
            if c.is_null() {
                return;
            }
            drop(Box::from_raw(c as *mut BgpCodec));
        },
        (),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use lr_bgp::message::keepalive::Keepalive;
    use lr_bgp::BgpCodec as BgpC;

    #[test]
    fn ffi_codec_new_default() {
        let c = lr_bgp_codec_new();
        assert!(!c.is_null());
        assert_eq!(unsafe { lr_bgp_codec_asn4_active(c) }, 0);
        unsafe { lr_bgp_codec_free(c) };
    }

    #[test]
    fn ffi_codec_with_asn4() {
        let c = lr_bgp_codec_with_asn4(1);
        assert_eq!(unsafe { lr_bgp_codec_asn4_active(c) }, 1);
        unsafe { lr_bgp_codec_free(c) };
    }

    #[test]
    fn ffi_codec_set_asn4_in_place() {
        let c = lr_bgp_codec_new();
        assert_eq!(unsafe { lr_bgp_codec_asn4_active(c) }, 0);
        assert_eq!(unsafe { lr_bgp_codec_set_asn4(c, 1) }, 0);
        assert_eq!(unsafe { lr_bgp_codec_asn4_active(c) }, 1);
        unsafe { lr_bgp_codec_free(c) };
    }

    #[test]
    fn ffi_codec_set_asn4_null_returns_err() {
        assert_eq!(
            unsafe { lr_bgp_codec_set_asn4(std::ptr::null_mut(), 1) },
            LR_ERR_NULL
        );
    }

    #[test]
    fn ffi_codec_decode_slice_keepalive() {
        let rust_codec = BgpC::new();
        let bytes = rust_codec
            .encode_vec(&BgpMessage::Keepalive(Keepalive))
            .unwrap();
        let c = lr_bgp_codec_new();
        let mut out: lr_bgp_message_t = std::ptr::null_mut();
        let rc = unsafe { lr_bgp_codec_decode_slice(c, bytes.as_ptr(), bytes.len(), &mut out) };
        assert_eq!(rc, 0);
        assert!(!out.is_null());
        unsafe {
            crate::handle::unbox_bgp_message(out).unwrap();
            lr_bgp_codec_free(c);
        };
    }

    #[test]
    fn ffi_codec_decode_slice_truncated_returns_null() {
        let bytes = [0xffu8; 5];
        let c = lr_bgp_codec_new();
        let mut out: lr_bgp_message_t = std::ptr::null_mut();
        let rc = unsafe { lr_bgp_codec_decode_slice(c, bytes.as_ptr(), bytes.len(), &mut out) };
        assert_eq!(rc, LR_ERR_NULL);
        assert!(out.is_null());
        unsafe { lr_bgp_codec_free(c) };
    }

    #[test]
    fn ffi_codec_decode_slice_null_returns_err() {
        let bytes = [0xffu8; 19];
        let c = lr_bgp_codec_new();
        let mut out: lr_bgp_message_t = std::ptr::null_mut();
        assert_eq!(
            unsafe {
                lr_bgp_codec_decode_slice(
                    std::ptr::null_mut(),
                    bytes.as_ptr(),
                    bytes.len(),
                    &mut out,
                )
            },
            LR_ERR_NULL
        );
        assert_eq!(
            unsafe { lr_bgp_codec_decode_slice(c, std::ptr::null(), 0, &mut out) },
            LR_ERR_NULL
        );
        assert_eq!(
            unsafe {
                lr_bgp_codec_decode_slice(c, bytes.as_ptr(), bytes.len(), std::ptr::null_mut())
            },
            LR_ERR_NULL
        );
        unsafe { lr_bgp_codec_free(c) };
    }

    #[test]
    fn ffi_codec_encode_vec_keepalive() {
        let rust_codec = BgpC::new();
        let bytes = rust_codec
            .encode_vec(&BgpMessage::Keepalive(Keepalive))
            .unwrap();
        let mut rust_codec = rust_codec;
        let m = crate::handle::box_bgp_message(rust_codec.decode_slice(&bytes).unwrap().unwrap());
        let c = lr_bgp_codec_new();
        let mut out = lr_bytes_t {
            ptr: std::ptr::null_mut(),
            len: 0,
            cap: 0,
        };
        let rc = unsafe { lr_bgp_codec_encode_vec(c, m, &mut out) };
        assert_eq!(rc, 0);
        assert_eq!(out.len, 19); // KEEPALIVE is 19 bytes (header only).
        let _ = unsafe { Vec::from_raw_parts(out.ptr, out.len, out.cap) };
        unsafe {
            crate::handle::unbox_bgp_message(m).unwrap();
            lr_bgp_codec_free(c);
        };
    }

    #[test]
    fn ffi_codec_set_add_path_basic() {
        let c = lr_bgp_codec_new();
        let tx = [lr_afi_safi_t { afi: 1, safi: 1 }];
        let rx = [lr_afi_safi_t { afi: 1, safi: 1 }];
        let rc = unsafe { lr_bgp_codec_set_add_path(c, tx.as_ptr(), 1, rx.as_ptr(), 1) };
        assert_eq!(rc, 0);
        unsafe { lr_bgp_codec_free(c) };
    }

    #[test]
    fn ffi_codec_set_add_path_null_clears() {
        let c = lr_bgp_codec_new();
        let rc = unsafe { lr_bgp_codec_set_add_path(c, std::ptr::null(), 0, std::ptr::null(), 0) };
        assert_eq!(rc, 0);
        unsafe { lr_bgp_codec_free(c) };
    }

    #[test]
    fn ffi_codec_set_add_path_null_with_count_returns_err() {
        let c = lr_bgp_codec_new();
        let rc = unsafe { lr_bgp_codec_set_add_path(c, std::ptr::null(), 1, std::ptr::null(), 0) };
        assert_eq!(rc, LR_ERR_NULL);
        unsafe { lr_bgp_codec_free(c) };
    }

    #[test]
    fn ffi_codec_free_null_safe() {
        unsafe { lr_bgp_codec_free(std::ptr::null_mut()) };
    }
}
