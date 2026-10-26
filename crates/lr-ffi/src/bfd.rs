//! BFD Control packet wire codec FFI (RFC 5880 §4.1).
//!
//! Stateless. Mirrors the public Rust API of `lr_bfd::{BfdCodec,
//! BfdPacket, State, Diagnostic, PacketFlags}` so an embedder can build,
//! inspect and round-trip BFD Control packets without going through the
//! Rust compiler.
//!
//! # Surface
//!
//! - `lr_bfd_decode` — decode one BFD Control packet from raw bytes,
//!   returns an opaque `lr_bfd_packet_t` handle.
//! - `lr_bfd_encode` — encode a `lr_bfd_packet_t` to its wire form.
//! - `lr_bfd_packet_new` / `lr_bfd_packet_heartbeat` — constructors.
//! - `lr_bfd_packet_*` readers for every field (version, diag, state,
//!   flags, detect_mult, my/your discriminator, tx/rx/echo intervals).
//! - `lr_bfd_packet_set_*` mutators for every settable field.
//! - `lr_bfd_packet_free` — drop the boxed packet.
//!
//! Every entry point runs inside the crate's `catch_unwind` barrier
//! ([`crate::guarded`]): a panic returns `LR_ERR_PANIC` and sets the
//! thread-local last-error string.

// The closure body passed to `guarded` is wrapped in a single `unsafe`
// block to mirror the `pub unsafe extern "C" fn` shape — the inner
// `unsafe { ... }` blocks would otherwise trip `unused_unsafe` under
// the crate's `-D warnings` clippy gate.
#![allow(unused_unsafe)]

use lr_bfd::packet::{BfdCodec, BfdPacket, Diagnostic, PacketFlags, State, BFD_VERSION};
use lr_core::buf::{ReadBuf, WriteBuf};
use lr_core::codec::{Decoder, Encoder};

use crate::error::{set_last_error, LrError, LR_ERR_PANIC};
use crate::guarded;
use crate::handle::lr_bytes_t;

const LR_ERR_NULL: i32 = LrError::Null as i32;
const LR_ERR_OTHER: i32 = LrError::Other as i32;

/// Opaque `BfdPacket` handle.
#[repr(C)]
pub struct OpaqueBfdPacket {
    _private: [u8; 0],
}

pub type lr_bfd_packet_t = *mut OpaqueBfdPacket;

fn box_packet(p: BfdPacket) -> lr_bfd_packet_t {
    Box::into_raw(Box::new(p)) as lr_bfd_packet_t
}

/// Reclaim a packet handle.
///
/// # Safety
/// `p` must have been produced by [`box_packet`] and not freed.
unsafe fn unbox_packet(p: lr_bfd_packet_t) -> Option<Box<BfdPacket>> {
    if p.is_null() {
        return None;
    }
    Some(unsafe { Box::from_raw(p as *mut BfdPacket) })
}

/// Borrow a packet handle as `&BfdPacket` for read-only access.
///
/// # Safety
/// `p` must have been produced by [`box_packet`] and not be freed while
/// the returned reference is live.
unsafe fn borrow_packet(p: lr_bfd_packet_t) -> Option<&'static BfdPacket> {
    if p.is_null() {
        return None;
    }
    Some(unsafe { &*(p as *const BfdPacket) })
}

/// Borrow a packet handle as `&mut BfdPacket` for mutation.
///
/// # Safety
/// See [`borrow_packet`]; the caller must not race the mutation with
/// another `lr_bfd_packet_*` call on the same handle.
unsafe fn borrow_packet_mut(p: lr_bfd_packet_t) -> Option<&'static mut BfdPacket> {
    if p.is_null() {
        return None;
    }
    Some(unsafe { &mut *(p as *mut BfdPacket) })
}

// ---- State / Diagnostic constants (mirrors lr_bfd pub consts) ----

/// State: AdminDown (RFC 5880 §6.1).
pub const LR_BFD_STATE_ADMIN_DOWN: u8 = 0;
/// State: Down.
pub const LR_BFD_STATE_DOWN: u8 = 1;
/// State: Init.
pub const LR_BFD_STATE_INIT: u8 = 2;
/// State: Up.
pub const LR_BFD_STATE_UP: u8 = 3;

/// Diagnostic: No Diagnostic.
pub const LR_BFD_DIAG_NONE: u8 = 0;
/// Diagnostic: Control Detection Time Expired.
pub const LR_BFD_DIAG_CTRL_EXPIRED: u8 = 1;
/// Diagnostic: Echo Function Failed.
pub const LR_BFD_DIAG_ECHO_FAILED: u8 = 2;
/// Diagnostic: Neighbor Signaled Session Down.
pub const LR_BFD_DIAG_NEIGHBOR_SIGNALLED: u8 = 3;
/// Diagnostic: Forwarding Plane Reset.
pub const LR_BFD_DIAG_FWD_RESET: u8 = 4;
/// Diagnostic: Path Down.
pub const LR_BFD_DIAG_PATH_DOWN: u8 = 5;
/// Diagnostic: Concatenated Path Down.
pub const LR_BFD_DIAG_CONCAT_PATH_DOWN: u8 = 6;
/// Diagnostic: Administratively Down.
pub const LR_BFD_DIAG_ADMIN_DOWN: u8 = 7;
/// Diagnostic: Reverse Concatenated Path Down.
pub const LR_BFD_DIAG_REV_PATH_DOWN: u8 = 8;
/// Diagnostic: Mis-Connectivity Defect.
pub const LR_BFD_DIAG_MISCONN_DEFECT: u8 = 9;

// ---- Packet surface ----

/// Decode one BFD Control packet from `data`. On success, writes a
/// freshly-allocated `lr_bfd_packet_t` to `*out`. Returns 0 on success,
/// negative on error.
///
/// # Safety
/// `data` must point to `len` readable bytes. `out` must point to a
/// writable `lr_bfd_packet_t`.
#[no_mangle]
pub unsafe extern "C" fn lr_bfd_decode(
    data: *const u8,
    len: usize,
    out: *mut lr_bfd_packet_t,
) -> i32 {
    guarded(
        || unsafe {
            if data.is_null() || out.is_null() {
                return LR_ERR_NULL;
            }
            let slice = unsafe { std::slice::from_raw_parts(data, len) };
            let mut codec = BfdCodec::new();
            let mut r = ReadBuf::new(slice);
            match codec.decode(&mut r) {
                Ok(Some(p)) => {
                    unsafe { *out = box_packet(p) }
                    0
                }
                Ok(None) => {
                    set_last_error("truncated".into());
                    LR_ERR_OTHER
                }
                Err(e) => {
                    set_last_error(format!("{e:?}"));
                    LrError::Codec as i32
                }
            }
        },
        LR_ERR_PANIC,
    )
}

/// Encode a `lr_bfd_packet_t` to its wire form. On success, writes a
/// freshly-allocated `lr_bytes_t` to `*out`.
///
/// # Safety
/// `packet` must be a valid handle. `out` must point to a writable
/// `lr_bytes_t`.
#[no_mangle]
pub unsafe extern "C" fn lr_bfd_encode(packet: lr_bfd_packet_t, out: *mut lr_bytes_t) -> i32 {
    guarded(
        || unsafe {
            let Some(p) = borrow_packet(packet) else {
                return LR_ERR_NULL;
            };
            if out.is_null() {
                return LR_ERR_NULL;
            }
            let codec = BfdCodec::new();
            // 24 bytes + auth trailer (max ~80 for keyed SHA1) → 128
            // is generous.
            let mut buf = vec![0u8; 128];
            let mut wb = WriteBuf::new(&mut buf);
            match codec.encode(p, &mut wb) {
                Ok(n) => {
                    let bytes: Vec<u8> = buf[..n].to_vec();
                    unsafe { *out = lr_bytes_t::from_vec(bytes) }
                    0
                }
                Err(e) => {
                    set_last_error(e.to_string());
                    LrError::Codec as i32
                }
            }
        },
        LR_ERR_PANIC,
    )
}

/// Construct an empty `BfdPacket` with sensible defaults (state=Down,
/// diag=None, detect_mult=3, all intervals 1s). Returns NULL on panic.
#[no_mangle]
pub extern "C" fn lr_bfd_packet_new() -> lr_bfd_packet_t {
    guarded(
        || {
            box_packet(BfdPacket {
                diag: Diagnostic::None,
                state: State::Down,
                flags: PacketFlags::empty(),
                detect_mult: 3,
                my_discriminator: 0,
                your_discriminator: 0,
                desired_min_tx_interval: 1_000_000,
                required_min_rx_interval: 1_000_000,
                required_min_echo_interval: 0,
                auth: None,
            })
        },
        std::ptr::null_mut(),
    )
}

/// Construct an "Up" heartbeat packet (state=Up, diag=None,
/// detect_mult=3, intervals=1s, no auth). Convenience for the most
/// common on-wire shape.
#[no_mangle]
pub extern "C" fn lr_bfd_packet_heartbeat(my_disc: u32, your_disc: u32) -> lr_bfd_packet_t {
    guarded(
        || box_packet(BfdPacket::heartbeat(my_disc, your_disc)),
        std::ptr::null_mut(),
    )
}

/// Read the BFD version field (RFC 5880 §4.1: always 1).
///
/// # Safety
/// `packet` must be a valid handle.
#[no_mangle]
pub unsafe extern "C" fn lr_bfd_packet_version(packet: lr_bfd_packet_t) -> u8 {
    guarded(
        || {
            let _ = unsafe { borrow_packet(packet) };
            BFD_VERSION
        },
        0,
    )
}

/// Read the diagnostic code (`LR_BFD_DIAG_*`).
///
/// # Safety
/// `packet` must be a valid handle.
#[no_mangle]
pub unsafe extern "C" fn lr_bfd_packet_diag(packet: lr_bfd_packet_t) -> u8 {
    guarded(
        || unsafe { borrow_packet(packet).map(|p| p.diag.to_u8()).unwrap_or(0) },
        0,
    )
}

/// Read the state (`LR_BFD_STATE_*`).
///
/// # Safety
/// `packet` must be a valid handle.
#[no_mangle]
pub unsafe extern "C" fn lr_bfd_packet_state(packet: lr_bfd_packet_t) -> u8 {
    guarded(
        || unsafe { borrow_packet(packet).map(|p| p.state as u8).unwrap_or(0) },
        0,
    )
}

/// Read the flags bitmask (M | D | A | C | F | P — see RFC 5880 §4.1).
/// Bit layout: bit 0 = M (Multipoint), bit 1 = D (Demand), bit 2 = A
/// (Auth), bit 3 = C (CPI), bit 4 = F (Final), bit 5 = P (Poll).
///
/// # Safety
/// `packet` must be a valid handle.
#[no_mangle]
pub unsafe extern "C" fn lr_bfd_packet_flags(packet: lr_bfd_packet_t) -> u8 {
    guarded(
        || unsafe { borrow_packet(packet).map(|p| p.flags.bits()).unwrap_or(0) },
        0,
    )
}

/// Read the detect multiplier.
///
/// # Safety
/// `packet` must be a valid handle.
#[no_mangle]
pub unsafe extern "C" fn lr_bfd_packet_detect_mult(packet: lr_bfd_packet_t) -> u8 {
    guarded(
        || unsafe { borrow_packet(packet).map(|p| p.detect_mult).unwrap_or(0) },
        0,
    )
}

/// Read the My Discriminator field.
///
/// # Safety
/// `packet` must be a valid handle.
#[no_mangle]
pub unsafe extern "C" fn lr_bfd_packet_my_discriminator(packet: lr_bfd_packet_t) -> u32 {
    guarded(
        || unsafe {
            borrow_packet(packet)
                .map(|p| p.my_discriminator)
                .unwrap_or(0)
        },
        0,
    )
}

/// Read the Your Discriminator field.
///
/// # Safety
/// `packet` must be a valid handle.
#[no_mangle]
pub unsafe extern "C" fn lr_bfd_packet_your_discriminator(packet: lr_bfd_packet_t) -> u32 {
    guarded(
        || unsafe {
            borrow_packet(packet)
                .map(|p| p.your_discriminator)
                .unwrap_or(0)
        },
        0,
    )
}

/// Read the Desired Min TX Interval (microseconds).
///
/// # Safety
/// `packet` must be a valid handle.
#[no_mangle]
pub unsafe extern "C" fn lr_bfd_packet_desired_min_tx_interval(packet: lr_bfd_packet_t) -> u32 {
    guarded(
        || unsafe {
            borrow_packet(packet)
                .map(|p| p.desired_min_tx_interval)
                .unwrap_or(0)
        },
        0,
    )
}

/// Read the Required Min RX Interval (microseconds).
///
/// # Safety
/// `packet` must be a valid handle.
#[no_mangle]
pub unsafe extern "C" fn lr_bfd_packet_required_min_rx_interval(packet: lr_bfd_packet_t) -> u32 {
    guarded(
        || unsafe {
            borrow_packet(packet)
                .map(|p| p.required_min_rx_interval)
                .unwrap_or(0)
        },
        0,
    )
}

/// Read the Required Min Echo Interval (microseconds).
///
/// # Safety
/// `packet` must be a valid handle.
#[no_mangle]
pub unsafe extern "C" fn lr_bfd_packet_required_min_echo_interval(packet: lr_bfd_packet_t) -> u32 {
    guarded(
        || unsafe {
            borrow_packet(packet)
                .map(|p| p.required_min_echo_interval)
                .unwrap_or(0)
        },
        0,
    )
}

/// Read the wire length (24 + auth section).
///
/// # Safety
/// `packet` must be a valid handle.
#[no_mangle]
pub unsafe extern "C" fn lr_bfd_packet_length(packet: lr_bfd_packet_t) -> u8 {
    guarded(
        || unsafe { borrow_packet(packet).map(|p| p.length()).unwrap_or(0) },
        0,
    )
}

/// Set the diagnostic code (`LR_BFD_DIAG_*`).
///
/// # Safety
/// `packet` must be a valid handle.
#[no_mangle]
pub unsafe extern "C" fn lr_bfd_packet_set_diag(packet: lr_bfd_packet_t, diag: u8) -> i32 {
    guarded(
        || unsafe {
            let Some(p) = borrow_packet_mut(packet) else {
                return LR_ERR_NULL;
            };
            p.diag = Diagnostic::from_u8(diag);
            0
        },
        LR_ERR_PANIC,
    )
}

/// Set the state (`LR_BFD_STATE_*`). Out-of-range values are clamped
/// to AdminDown (0).
///
/// # Safety
/// `packet` must be a valid handle.
#[no_mangle]
pub unsafe extern "C" fn lr_bfd_packet_set_state(packet: lr_bfd_packet_t, state: u8) -> i32 {
    guarded(
        || unsafe {
            let Some(p) = borrow_packet_mut(packet) else {
                return LR_ERR_NULL;
            };
            p.state = State::from_u8(state).unwrap_or(State::AdminDown);
            0
        },
        LR_ERR_PANIC,
    )
}

/// Set the flags bitmask (M | D | A | C | F | P). Reserved bits are
/// masked off.
///
/// # Safety
/// `packet` must be a valid handle.
#[no_mangle]
pub unsafe extern "C" fn lr_bfd_packet_set_flags(packet: lr_bfd_packet_t, flags: u8) -> i32 {
    guarded(
        || unsafe {
            let Some(p) = borrow_packet_mut(packet) else {
                return LR_ERR_NULL;
            };
            // PacketFlags::from_bits_truncate keeps only valid bits.
            p.flags = PacketFlags::from_bits_truncate(flags);
            0
        },
        LR_ERR_PANIC,
    )
}

/// Set the detect multiplier.
///
/// # Safety
/// `packet` must be a valid handle.
#[no_mangle]
pub unsafe extern "C" fn lr_bfd_packet_set_detect_mult(
    packet: lr_bfd_packet_t,
    detect_mult: u8,
) -> i32 {
    guarded(
        || unsafe {
            let Some(p) = borrow_packet_mut(packet) else {
                return LR_ERR_NULL;
            };
            p.detect_mult = detect_mult;
            0
        },
        LR_ERR_PANIC,
    )
}

/// Set the My Discriminator field.
///
/// # Safety
/// `packet` must be a valid handle.
#[no_mangle]
pub unsafe extern "C" fn lr_bfd_packet_set_my_discriminator(
    packet: lr_bfd_packet_t,
    disc: u32,
) -> i32 {
    guarded(
        || unsafe {
            let Some(p) = borrow_packet_mut(packet) else {
                return LR_ERR_NULL;
            };
            p.my_discriminator = disc;
            0
        },
        LR_ERR_PANIC,
    )
}

/// Set the Your Discriminator field.
///
/// # Safety
/// `packet` must be a valid handle.
#[no_mangle]
pub unsafe extern "C" fn lr_bfd_packet_set_your_discriminator(
    packet: lr_bfd_packet_t,
    disc: u32,
) -> i32 {
    guarded(
        || unsafe {
            let Some(p) = borrow_packet_mut(packet) else {
                return LR_ERR_NULL;
            };
            p.your_discriminator = disc;
            0
        },
        LR_ERR_PANIC,
    )
}

/// Set the Desired Min TX Interval (microseconds).
///
/// # Safety
/// `packet` must be a valid handle.
#[no_mangle]
pub unsafe extern "C" fn lr_bfd_packet_set_desired_min_tx_interval(
    packet: lr_bfd_packet_t,
    interval: u32,
) -> i32 {
    guarded(
        || unsafe {
            let Some(p) = borrow_packet_mut(packet) else {
                return LR_ERR_NULL;
            };
            p.desired_min_tx_interval = interval;
            0
        },
        LR_ERR_PANIC,
    )
}

/// Set the Required Min RX Interval (microseconds).
///
/// # Safety
/// `packet` must be a valid handle.
#[no_mangle]
pub unsafe extern "C" fn lr_bfd_packet_set_required_min_rx_interval(
    packet: lr_bfd_packet_t,
    interval: u32,
) -> i32 {
    guarded(
        || unsafe {
            let Some(p) = borrow_packet_mut(packet) else {
                return LR_ERR_NULL;
            };
            p.required_min_rx_interval = interval;
            0
        },
        LR_ERR_PANIC,
    )
}

/// Set the Required Min Echo Interval (microseconds).
///
/// # Safety
/// `packet` must be a valid handle.
#[no_mangle]
pub unsafe extern "C" fn lr_bfd_packet_set_required_min_echo_interval(
    packet: lr_bfd_packet_t,
    interval: u32,
) -> i32 {
    guarded(
        || unsafe {
            let Some(p) = borrow_packet_mut(packet) else {
                return LR_ERR_NULL;
            };
            p.required_min_echo_interval = interval;
            0
        },
        LR_ERR_PANIC,
    )
}

/// Drop a boxed `BfdPacket`. Safe to call with NULL.
///
/// # Safety
/// `packet` must have been produced by a `lr_bfd_packet_*` constructor
/// and must not be used after this call.
#[no_mangle]
pub unsafe extern "C" fn lr_bfd_packet_free(packet: lr_bfd_packet_t) {
    guarded(
        || unsafe {
            drop(unbox_packet(packet));
        },
        (),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Reclaim a `lr_bytes_t` into a Rust `Vec<u8>`.
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
    fn ffi_packet_new_defaults() {
        let p = lr_bfd_packet_new();
        assert!(!p.is_null());
        assert_eq!(unsafe { lr_bfd_packet_diag(p) }, 0);
        assert_eq!(unsafe { lr_bfd_packet_state(p) }, LR_BFD_STATE_DOWN);
        assert_eq!(unsafe { lr_bfd_packet_flags(p) }, 0);
        assert_eq!(unsafe { lr_bfd_packet_detect_mult(p) }, 3);
        assert_eq!(unsafe { lr_bfd_packet_my_discriminator(p) }, 0);
        assert_eq!(unsafe { lr_bfd_packet_your_discriminator(p) }, 0);
        assert_eq!(
            unsafe { lr_bfd_packet_desired_min_tx_interval(p) },
            1_000_000
        );
        assert_eq!(
            unsafe { lr_bfd_packet_required_min_rx_interval(p) },
            1_000_000
        );
        assert_eq!(unsafe { lr_bfd_packet_required_min_echo_interval(p) }, 0);
        assert_eq!(unsafe { lr_bfd_packet_length(p) }, 24);
        unsafe { lr_bfd_packet_free(p) };
    }

    #[test]
    fn ffi_packet_heartbeat() {
        let p = lr_bfd_packet_heartbeat(0x1234, 0x5678);
        assert!(!p.is_null());
        assert_eq!(unsafe { lr_bfd_packet_state(p) }, LR_BFD_STATE_UP);
        assert_eq!(unsafe { lr_bfd_packet_my_discriminator(p) }, 0x1234);
        assert_eq!(unsafe { lr_bfd_packet_your_discriminator(p) }, 0x5678);
        unsafe { lr_bfd_packet_free(p) };
    }

    #[test]
    fn ffi_packet_setters_mutate_in_place() {
        let p = lr_bfd_packet_new();
        unsafe {
            assert_eq!(lr_bfd_packet_set_diag(p, LR_BFD_DIAG_CTRL_EXPIRED), 0);
            assert_eq!(lr_bfd_packet_set_state(p, LR_BFD_STATE_UP), 0);
            assert_eq!(lr_bfd_packet_set_flags(p, 0b0010_0000), 0); // Poll bit
            assert_eq!(lr_bfd_packet_set_detect_mult(p, 5), 0);
            assert_eq!(lr_bfd_packet_set_my_discriminator(p, 0xaabbccdd), 0);
            assert_eq!(lr_bfd_packet_set_your_discriminator(p, 0x11223344), 0);
            assert_eq!(lr_bfd_packet_set_desired_min_tx_interval(p, 500_000), 0);
            assert_eq!(lr_bfd_packet_set_required_min_rx_interval(p, 750_000), 0);
            assert_eq!(lr_bfd_packet_set_required_min_echo_interval(p, 100_000), 0);

            assert_eq!(lr_bfd_packet_diag(p), LR_BFD_DIAG_CTRL_EXPIRED);
            assert_eq!(lr_bfd_packet_state(p), LR_BFD_STATE_UP);
            assert_eq!(lr_bfd_packet_flags(p), 0b0010_0000);
            assert_eq!(lr_bfd_packet_detect_mult(p), 5);
            assert_eq!(lr_bfd_packet_my_discriminator(p), 0xaabbccdd);
            assert_eq!(lr_bfd_packet_your_discriminator(p), 0x11223344);
            assert_eq!(lr_bfd_packet_desired_min_tx_interval(p), 500_000);
            assert_eq!(lr_bfd_packet_required_min_rx_interval(p), 750_000);
            assert_eq!(lr_bfd_packet_required_min_echo_interval(p), 100_000);
        }
        unsafe { lr_bfd_packet_free(p) };
    }

    #[test]
    fn ffi_set_state_clamps_invalid_to_admin_down() {
        let p = lr_bfd_packet_new();
        unsafe {
            assert_eq!(lr_bfd_packet_set_state(p, 99), 0);
            assert_eq!(lr_bfd_packet_state(p), LR_BFD_STATE_ADMIN_DOWN);
        }
        unsafe { lr_bfd_packet_free(p) };
    }

    #[test]
    fn ffi_set_flags_masks_reserved_bits() {
        let p = lr_bfd_packet_new();
        unsafe {
            // All 8 bits set; only M|D|A|C|F|P (bits 0..5) are valid.
            assert_eq!(lr_bfd_packet_set_flags(p, 0xff), 0);
            assert_eq!(lr_bfd_packet_flags(p), 0b0011_1111);
        }
        unsafe { lr_bfd_packet_free(p) };
    }

    #[test]
    fn ffi_encode_decode_roundtrip() {
        let p = lr_bfd_packet_heartbeat(0xdeadbeef, 0xcafebabe);
        unsafe {
            let mut out = lr_bytes_t {
                ptr: std::ptr::null_mut(),
                len: 0,
                cap: 0,
            };
            assert_eq!(lr_bfd_encode(p, &raw mut out), 0);
            let bytes = bytes_to_vec(&mut out);
            assert_eq!(bytes.len(), 24);

            // Decode back.
            let mut dec: lr_bfd_packet_t = std::ptr::null_mut();
            assert_eq!(lr_bfd_decode(bytes.as_ptr(), bytes.len(), &raw mut dec), 0);
            assert!(!dec.is_null());
            assert_eq!(lr_bfd_packet_state(dec), LR_BFD_STATE_UP);
            assert_eq!(lr_bfd_packet_my_discriminator(dec), 0xdeadbeef);
            assert_eq!(lr_bfd_packet_your_discriminator(dec), 0xcafebabe);
            assert_eq!(lr_bfd_packet_desired_min_tx_interval(dec), 1_000_000);
            lr_bfd_packet_free(dec);
        }
        unsafe { lr_bfd_packet_free(p) };
    }

    #[test]
    fn ffi_decode_rejects_too_short() {
        let bytes = [0u8; 10];
        let mut dec: lr_bfd_packet_t = std::ptr::null_mut();
        let rc = unsafe { lr_bfd_decode(bytes.as_ptr(), bytes.len(), &raw mut dec) };
        assert!(rc < 0);
        assert!(dec.is_null());
    }

    #[test]
    fn ffi_decode_rejects_null_input() {
        let mut dec: lr_bfd_packet_t = std::ptr::null_mut();
        let rc = unsafe { lr_bfd_decode(std::ptr::null(), 0, &raw mut dec) };
        assert_eq!(rc, LR_ERR_NULL);
    }

    #[test]
    fn ffi_encode_returns_null_on_null_handle() {
        let mut out = lr_bytes_t {
            ptr: std::ptr::null_mut(),
            len: 0,
            cap: 0,
        };
        let rc = unsafe { lr_bfd_encode(std::ptr::null_mut(), &raw mut out) };
        assert_eq!(rc, LR_ERR_NULL);
    }

    #[test]
    fn ffi_free_handles_null_safely() {
        unsafe { lr_bfd_packet_free(std::ptr::null_mut()) };
    }

    #[test]
    fn ffi_packet_version_always_one() {
        let p = lr_bfd_packet_new();
        assert_eq!(unsafe { lr_bfd_packet_version(p) }, 1);
        unsafe { lr_bfd_packet_free(p) };
    }
}
