//! OSPF v2/v3 wire codec FFI (RFC 2328, RFC 5340).
//!
//! Stateless. Mirrors the public Rust API of `lr_ospf::{OspfCodec,
//! OspfPacket, OspfHeader, OspfPacketType, OspfVersion, OspfBody}` so
//! an embedder can build, inspect and round-trip OSPF packets without
//! going through the Rust compiler.
//!
//! Every entry point runs inside the crate's `catch_unwind` barrier
//! ([`crate::guarded`]): a panic returns `LR_ERR_PANIC` and sets the
//! thread-local last-error string.

// The closure body passed to `guarded` is wrapped in a single `unsafe`
// block to mirror the `pub unsafe extern "C" fn` shape — the inner
// `unsafe { ... }` blocks would otherwise trip `unused_unsafe` under
// the crate's `-D warnings` clippy gate.
#![allow(unused_unsafe)]

use lr_ospf::packet::{OspfBody, OspfPacket, OspfPacketType, OspfVersion};
use lr_ospf::OspfCodec;

use crate::error::{set_last_error, LrError, LR_ERR_PANIC};
use crate::guarded;
use crate::handle::lr_bytes_t;

const LR_ERR_NULL: i32 = LrError::Null as i32;
const LR_ERR_OTHER: i32 = LrError::Other as i32;

/// Opaque `OspfPacket` handle.
#[repr(C)]
pub struct OpaqueOspfPacket {
    _private: [u8; 0],
}

pub type lr_ospf_packet_t = *mut OpaqueOspfPacket;

fn box_packet(p: OspfPacket) -> lr_ospf_packet_t {
    Box::into_raw(Box::new(p)) as lr_ospf_packet_t
}

/// Reclaim a packet handle.
///
/// # Safety
/// `p` must have been produced by [`box_packet`] and not freed.
unsafe fn unbox_packet(p: lr_ospf_packet_t) -> Option<Box<OspfPacket>> {
    if p.is_null() {
        return None;
    }
    Some(unsafe { Box::from_raw(p as *mut OspfPacket) })
}

/// Borrow a packet handle as `&OspfPacket`.
///
/// # Safety
/// `p` must have been produced by [`box_packet`] and not be freed while
/// the returned reference is live.
unsafe fn borrow_packet(p: lr_ospf_packet_t) -> Option<&'static OspfPacket> {
    if p.is_null() {
        return None;
    }
    Some(unsafe { &*(p as *const OspfPacket) })
}

// ---- Version / packet-type constants ----

pub const LR_OSPF_VERSION_V2: u8 = OspfVersion::V2 as u8;
pub const LR_OSPF_VERSION_V3: u8 = OspfVersion::V3 as u8;

pub const LR_OSPF_PACKET_HELLO: u8 = OspfPacketType::Hello as u8;
pub const LR_OSPF_PACKET_DB_DESC: u8 = OspfPacketType::DatabaseDescription as u8;
pub const LR_OSPF_PACKET_LS_REQUEST: u8 = OspfPacketType::LinkStateRequest as u8;
pub const LR_OSPF_PACKET_LS_UPDATE: u8 = OspfPacketType::LinkStateUpdate as u8;
pub const LR_OSPF_PACKET_LS_ACK: u8 = OspfPacketType::LinkStateAck as u8;

// ---- Decode / encode ----

/// Decode one OSPFv2 packet from `data`. On success, writes a freshly-
/// allocated `lr_ospf_packet_t` to `*out`.
///
/// # Safety
/// `data` must point to `len` readable bytes. `out` must point to a
/// writable `lr_ospf_packet_t`.
#[no_mangle]
pub unsafe extern "C" fn lr_ospf_decode_v2_packet(
    data: *const u8,
    len: usize,
    out: *mut lr_ospf_packet_t,
) -> i32 {
    guarded(
        || unsafe {
            if data.is_null() || out.is_null() {
                return LR_ERR_NULL;
            }
            let slice = unsafe { std::slice::from_raw_parts(data, len) };
            let mut codec = OspfCodec::v2();
            match codec.decode_slice(slice) {
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

/// Decode one OSPFv3 packet from `data`.
///
/// # Safety
/// See [`lr_ospf_decode_v2_packet`].
#[no_mangle]
pub unsafe extern "C" fn lr_ospf_decode_v3_packet(
    data: *const u8,
    len: usize,
    out: *mut lr_ospf_packet_t,
) -> i32 {
    guarded(
        || unsafe {
            if data.is_null() || out.is_null() {
                return LR_ERR_NULL;
            }
            let slice = unsafe { std::slice::from_raw_parts(data, len) };
            let mut codec = OspfCodec::v3();
            match codec.decode_slice(slice) {
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

/// Encode an OSPF packet to its wire form. The version field on the
/// header selects v2 vs v3.
///
/// # Safety
/// `packet` must be a valid handle. `out` must point to a writable
/// `lr_bytes_t`.
#[no_mangle]
pub unsafe extern "C" fn lr_ospf_encode_packet(
    packet: lr_ospf_packet_t,
    out: *mut lr_bytes_t,
) -> i32 {
    guarded(
        || unsafe {
            let Some(p) = borrow_packet(packet) else {
                return LR_ERR_NULL;
            };
            if out.is_null() {
                return LR_ERR_NULL;
            }
            let version = if p.header.version == OspfVersion::V3 as u8 {
                OspfVersion::V3
            } else {
                OspfVersion::V2
            };
            let codec = OspfCodec::new(version);
            match codec.encode_vec(p) {
                Ok(bytes) => {
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

// ---- Readers ----

/// Read the OSPF version field (2 for v2, 3 for v3).
///
/// # Safety
/// `packet` must be a valid handle.
#[no_mangle]
pub unsafe extern "C" fn lr_ospf_packet_version(packet: lr_ospf_packet_t) -> u8 {
    guarded(
        || unsafe { borrow_packet(packet).map(|p| p.header.version).unwrap_or(0) },
        0,
    )
}

/// Read the packet-type code (`LR_OSPF_PACKET_*`).
///
/// # Safety
/// `packet` must be a valid handle.
#[no_mangle]
pub unsafe extern "C" fn lr_ospf_packet_type(packet: lr_ospf_packet_t) -> u8 {
    guarded(
        || unsafe { borrow_packet(packet).map(|p| p.header.kind).unwrap_or(0) },
        0,
    )
}

/// Read the OSPF Router ID (big-endian, 4 bytes).
///
/// # Safety
/// `packet` must be a valid handle.
#[no_mangle]
pub unsafe extern "C" fn lr_ospf_packet_router_id(packet: lr_ospf_packet_t) -> u32 {
    guarded(
        || unsafe {
            borrow_packet(packet)
                .map(|p| p.header.router_id)
                .unwrap_or(0)
        },
        0,
    )
}

/// Read the OSPF Area ID (big-endian, 4 bytes).
///
/// # Safety
/// `packet` must be a valid handle.
#[no_mangle]
pub unsafe extern "C" fn lr_ospf_packet_area_id(packet: lr_ospf_packet_t) -> u32 {
    guarded(
        || unsafe { borrow_packet(packet).map(|p| p.header.area_id).unwrap_or(0) },
        0,
    )
}

/// Read the body variant tag — one of the `LR_OSPF_BODY_*` constants.
/// Returns 0 on a NULL handle.
///
/// # Safety
/// `packet` must be a valid handle.
#[no_mangle]
pub unsafe extern "C" fn lr_ospf_packet_body_kind(packet: lr_ospf_packet_t) -> u8 {
    guarded(
        || unsafe {
            let Some(p) = borrow_packet(packet) else {
                return 0;
            };
            match &p.body {
                OspfBody::Hello(_) => LR_OSPF_BODY_HELLO,
                OspfBody::DbDesc(_) => LR_OSPF_BODY_DB_DESC,
                OspfBody::LsRequest(_) => LR_OSPF_BODY_LS_REQUEST,
                OspfBody::LsUpdate(_) => LR_OSPF_BODY_LS_UPDATE,
                OspfBody::LsAck(_) => LR_OSPF_BODY_LS_ACK,
                OspfBody::Raw(_) => LR_OSPF_BODY_RAW,
            }
        },
        0,
    )
}

pub const LR_OSPF_BODY_HELLO: u8 = 1;
pub const LR_OSPF_BODY_DB_DESC: u8 = 2;
pub const LR_OSPF_BODY_LS_REQUEST: u8 = 3;
pub const LR_OSPF_BODY_LS_UPDATE: u8 = 4;
pub const LR_OSPF_BODY_LS_ACK: u8 = 5;
pub const LR_OSPF_BODY_RAW: u8 = 6;

/// Drop a boxed `OspfPacket`. Safe to call with NULL.
///
/// # Safety
/// `packet` must have been produced by a `lr_ospf_*_packet` constructor
/// and must not be used after this call.
#[no_mangle]
pub unsafe extern "C" fn lr_ospf_packet_free(packet: lr_ospf_packet_t) {
    guarded(
        || unsafe {
            drop(unbox_packet(packet));
        },
        (),
    )
}

// ---- OSPF packet finalize / checksum (RFC 2328 §A.1, RFC 5340 §A.1) ----
//
// `lr_ospf::origination` exposes the v2 / v3 packet-finalize helpers
// (compute + write the OSPF checksum into a pre-encoded packet) and
// the v2 checksum verifier. These are essential for an embedder that
// builds OSPF packets by hand — without them the packet the codec
// produces is checksum-zero, and a conformant peer rejects it.

/// Finalize an OSPFv2 packet's checksum in place (RFC 2328 §A.1).
/// Writes the 16-bit checksum into the OSPF header (offset 12) of
/// `bytes` and returns 1 on success, 0 on a too-short buffer (the
/// OSPFv2 header is 24 bytes; `bytes.len()` must be at least that).
///
/// # Safety
/// `bytes` must point to `len` writable bytes.
#[no_mangle]
pub unsafe extern "C" fn lr_ospf_finalize_v2_packet(bytes: *mut u8, len: usize) -> u8 {
    guarded(
        || unsafe {
            if bytes.is_null() || len < 24 {
                return 0;
            }
            let slice = unsafe { core::slice::from_raw_parts_mut(bytes, len) };
            lr_ospf::origination::finalize_v2_packet(slice) as u8
        },
        0,
    )
}

/// Finalize an OSPFv2 stream (a sequence of back-to-back OSPF packets
/// in one buffer, e.g. a multicast frame carrying multiple packets).
/// Writes the checksum into each packet header and returns the number
/// of bytes consumed (the position where the next packet would start).
/// Returns 0 on a too-short buffer or NULL pointer.
///
/// # Safety
/// `bytes` must point to `len` writable bytes.
#[no_mangle]
pub unsafe extern "C" fn lr_ospf_finalize_v2_stream(bytes: *mut u8, len: usize) -> usize {
    guarded(
        || unsafe {
            if bytes.is_null() || len == 0 {
                return 0;
            }
            let slice = unsafe { core::slice::from_raw_parts_mut(bytes, len) };
            lr_ospf::origination::finalize_v2_stream(slice)
        },
        0,
    )
}

/// Verify an OSPFv2 packet's checksum (RFC 2328 §A.1). Returns 1 when
/// the checksum is correct, 0 on a bad checksum or a too-short buffer.
///
/// # Safety
/// `bytes` must point to `len` readable bytes.
#[no_mangle]
pub unsafe extern "C" fn lr_ospf_v2_packet_checksum_ok(bytes: *const u8, len: usize) -> u8 {
    guarded(
        || unsafe {
            if bytes.is_null() || len < 24 {
                return 0;
            }
            let slice = unsafe { core::slice::from_raw_parts(bytes, len) };
            lr_ospf::origination::v2_packet_checksum_ok(slice) as u8
        },
        0,
    )
}

/// Finalize an OSPFv3 packet's checksum in place (RFC 5340 §A.1 —
/// uses the IPv6 pseudo-header carrying `src` + `dst`). Writes the
/// 16-bit checksum into the OSPFv3 header (offset 12) and returns 1
/// on success, 0 on a too-short buffer (OSPFv3 header is 16 bytes).
///
/// # Safety
/// `bytes` must point to `len` writable bytes. `src` / `dst` must
/// each point to 16 readable bytes (IPv6 source / destination
/// address).
#[no_mangle]
pub unsafe extern "C" fn lr_ospf_finalize_v3_packet(
    bytes: *mut u8,
    len: usize,
    src: *const u8,
    dst: *const u8,
) -> u8 {
    guarded(
        || unsafe {
            if bytes.is_null() || len < 16 || src.is_null() || dst.is_null() {
                return 0;
            }
            let slice = unsafe { core::slice::from_raw_parts_mut(bytes, len) };
            let mut src_arr = [0u8; 16];
            let mut dst_arr = [0u8; 16];
            unsafe {
                src_arr.copy_from_slice(core::slice::from_raw_parts(src, 16));
                dst_arr.copy_from_slice(core::slice::from_raw_parts(dst, 16));
            }
            lr_ospf::origination::finalize_v3_packet(slice, &src_arr, &dst_arr) as u8
        },
        0,
    )
}

/// Finalize an OSPFv3 stream (a sequence of back-to-back OSPFv3
/// packets in one buffer). Returns the number of bytes consumed.
///
/// # Safety
/// See [`lr_ospf_finalize_v3_packet`].
#[no_mangle]
pub unsafe extern "C" fn lr_ospf_finalize_v3_stream(
    bytes: *mut u8,
    len: usize,
    src: *const u8,
    dst: *const u8,
) -> usize {
    guarded(
        || unsafe {
            if bytes.is_null() || len == 0 || src.is_null() || dst.is_null() {
                return 0;
            }
            let slice = unsafe { core::slice::from_raw_parts_mut(bytes, len) };
            let mut src_arr = [0u8; 16];
            let mut dst_arr = [0u8; 16];
            unsafe {
                src_arr.copy_from_slice(core::slice::from_raw_parts(src, 16));
                dst_arr.copy_from_slice(core::slice::from_raw_parts(dst, 16));
            }
            lr_ospf::origination::finalize_v3_stream(slice, &src_arr, &dst_arr)
        },
        0,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use lr_ospf::packet::{HelloBody, OspfHeader};

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

    fn build_v2_hello() -> Vec<u8> {
        let pkt = OspfPacket {
            header: OspfHeader {
                version: 2,
                kind: OspfPacketType::Hello as u8,
                length: 0,
                router_id: 0x0a000001,
                area_id: 0,
                checksum: 0,
                au_type_or_instance: 0,
                auth_data: 0,
            },
            body: OspfBody::Hello(HelloBody {
                network_mask: 0xffff_ff00,
                hello_interval: 10,
                options: 0,
                priority: 1,
                dead_interval: 40,
                dr: 0,
                bdr: 0,
                neighbors: Vec::new(),
            }),
        };
        let codec = OspfCodec::v2();
        let bytes = codec.encode_vec(&pkt).expect("encode");
        let mut bytes = bytes;
        lr_ospf::origination::finalize_v2_packet(&mut bytes);
        bytes
    }

    #[test]
    fn ffi_decode_v2_packet_roundtrip() {
        let bytes = build_v2_hello();
        let mut p: lr_ospf_packet_t = std::ptr::null_mut();
        let rc = unsafe { lr_ospf_decode_v2_packet(bytes.as_ptr(), bytes.len(), &raw mut p) };
        assert_eq!(rc, 0);
        assert!(!p.is_null());
        unsafe {
            assert_eq!(lr_ospf_packet_version(p), 2);
            assert_eq!(lr_ospf_packet_type(p), LR_OSPF_PACKET_HELLO);
            assert_eq!(lr_ospf_packet_router_id(p), 0x0a000001);
            assert_eq!(lr_ospf_packet_area_id(p), 0);
            assert_eq!(lr_ospf_packet_body_kind(p), LR_OSPF_BODY_HELLO);

            // Encode it back.
            let mut out = lr_bytes_t {
                ptr: std::ptr::null_mut(),
                len: 0,
                cap: 0,
            };
            assert_eq!(lr_ospf_encode_packet(p, &raw mut out), 0);
            let bytes2 = bytes_to_vec(&mut out);
            assert_eq!(bytes2.len(), bytes.len());

            lr_ospf_packet_free(p);
        }
    }

    #[test]
    fn ffi_decode_v2_rejects_null_input() {
        let mut p: lr_ospf_packet_t = std::ptr::null_mut();
        let rc = unsafe { lr_ospf_decode_v2_packet(std::ptr::null(), 0, &raw mut p) };
        assert_eq!(rc, LR_ERR_NULL);
    }

    #[test]
    fn ffi_decode_v2_rejects_too_short() {
        let bytes = [0u8; 5];
        let mut p: lr_ospf_packet_t = std::ptr::null_mut();
        let rc = unsafe { lr_ospf_decode_v2_packet(bytes.as_ptr(), bytes.len(), &raw mut p) };
        assert!(rc < 0);
        assert!(p.is_null());
    }

    #[test]
    fn ffi_decode_v3_rejects_null_input() {
        let mut p: lr_ospf_packet_t = std::ptr::null_mut();
        let rc = unsafe { lr_ospf_decode_v3_packet(std::ptr::null(), 0, &raw mut p) };
        assert_eq!(rc, LR_ERR_NULL);
    }

    #[test]
    fn ffi_free_handles_null() {
        unsafe { lr_ospf_packet_free(std::ptr::null_mut()) };
    }

    #[test]
    fn ffi_packet_version_returns_zero_on_null() {
        assert_eq!(unsafe { lr_ospf_packet_version(std::ptr::null_mut()) }, 0);
    }

    #[test]
    fn ffi_constants_match_rfc() {
        assert_eq!(LR_OSPF_VERSION_V2, 2);
        assert_eq!(LR_OSPF_VERSION_V3, 3);
        assert_eq!(LR_OSPF_PACKET_HELLO, 1);
        assert_eq!(LR_OSPF_PACKET_DB_DESC, 2);
        assert_eq!(LR_OSPF_PACKET_LS_REQUEST, 3);
        assert_eq!(LR_OSPF_PACKET_LS_UPDATE, 4);
        assert_eq!(LR_OSPF_PACKET_LS_ACK, 5);
    }

    // ---- OSPF packet finalize / checksum (RFC 2328 §A.1, RFC 5340 §A.1) ----

    #[test]
    fn ffi_finalize_v2_packet_writes_checksum() {
        // Build a minimal OSPFv2 Hello via the codec, finalize it,
        // then verify the checksum is non-zero and validates.
        use lr_ospf::codec::OspfCodec;
        use lr_ospf::packet::{HelloBody, OspfHeader, OspfPacket, OspfPacketType};
        let pkt = OspfPacket {
            header: OspfHeader {
                version: 2,
                kind: OspfPacketType::Hello as u8,
                length: 0,
                router_id: 0x01020304,
                area_id: 0,
                checksum: 0,
                au_type_or_instance: 0,
                auth_data: 0,
            },
            body: OspfBody::Hello(HelloBody {
                network_mask: 0xffff_ff00,
                hello_interval: 10,
                options: 0x02,
                priority: 1,
                dead_interval: 40,
                dr: 0,
                bdr: 0,
                neighbors: Vec::new(),
            }),
        };
        let mut bytes = OspfCodec::v2().encode_vec(&pkt).expect("encode");
        // The header.length field is set during encode — patch it
        // first if needed (the codec sets it for us).
        let len = bytes.len() as u16;
        bytes[2..4].copy_from_slice(&len.to_be_bytes());
        // Finalize the checksum in place.
        let rc = unsafe { lr_ospf_finalize_v2_packet(bytes.as_mut_ptr(), bytes.len()) };
        assert_eq!(rc, 1);
        // The checksum at offset 12-13 should now be non-zero.
        let checksum = u16::from_be_bytes([bytes[12], bytes[13]]);
        assert_ne!(checksum, 0);
        // Verify the checksum is valid.
        let rc = unsafe { lr_ospf_v2_packet_checksum_ok(bytes.as_ptr(), bytes.len()) };
        assert_eq!(rc, 1, "finalized checksum must validate");
    }

    #[test]
    fn ffi_finalize_v2_packet_rejects_too_short() {
        // 23 bytes < 24-byte header → returns 0.
        let mut bytes = [0u8; 23];
        let rc = unsafe { lr_ospf_finalize_v2_packet(bytes.as_mut_ptr(), 23) };
        assert_eq!(rc, 0);
        // NULL pointer → 0.
        let rc = unsafe { lr_ospf_finalize_v2_packet(std::ptr::null_mut(), 24) };
        assert_eq!(rc, 0);
    }

    #[test]
    fn ffi_v2_packet_checksum_ok_returns_zero_on_bad_input() {
        // A too-short buffer returns 0.
        let bytes = [0u8; 23];
        let rc = unsafe { lr_ospf_v2_packet_checksum_ok(bytes.as_ptr(), 23) };
        assert_eq!(rc, 0);
        // NULL pointer → 0.
        let rc = unsafe { lr_ospf_v2_packet_checksum_ok(std::ptr::null(), 24) };
        assert_eq!(rc, 0);
    }

    #[test]
    fn ffi_finalize_v2_stream_returns_packets_consumed() {
        // Build a minimal OSPFv2 Hello via the codec.
        use lr_ospf::codec::OspfCodec;
        use lr_ospf::packet::{HelloBody, OspfBody, OspfHeader, OspfPacket, OspfPacketType};
        let pkt = OspfPacket {
            header: OspfHeader {
                version: 2,
                kind: OspfPacketType::Hello as u8,
                length: 0,
                router_id: 0x01020304,
                area_id: 0,
                checksum: 0,
                au_type_or_instance: 0,
                auth_data: 0,
            },
            body: OspfBody::Hello(HelloBody {
                network_mask: 0xffff_ff00,
                hello_interval: 10,
                options: 0x02,
                priority: 1,
                dead_interval: 40,
                dr: 0,
                bdr: 0,
                neighbors: Vec::new(),
            }),
        };
        let mut bytes = OspfCodec::v2().encode_vec(&pkt).expect("encode");
        let len = bytes.len() as u16;
        bytes[2..4].copy_from_slice(&len.to_be_bytes());
        // finalize_v2_stream returns the number of finalized packets
        // (one per OSPF packet in the stream). For a single-packet
        // stream that is 1.
        let consumed = unsafe { lr_ospf_finalize_v2_stream(bytes.as_mut_ptr(), bytes.len()) };
        assert_eq!(consumed, 1);
        // NULL pointer → 0.
        let consumed = unsafe { lr_ospf_finalize_v2_stream(std::ptr::null_mut(), 24) };
        assert_eq!(consumed, 0);
    }

    #[test]
    fn ffi_finalize_v3_packet_rejects_null_or_short() {
        let mut bytes = [0u8; 16];
        let src = [0xfe_u8, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let dst = [0xff_u8, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 5];
        // NULL bytes → 0.
        let rc = unsafe {
            lr_ospf_finalize_v3_packet(std::ptr::null_mut(), 16, src.as_ptr(), dst.as_ptr())
        };
        assert_eq!(rc, 0);
        // Too-short buffer (15 < 16) → 0.
        let mut short = [0u8; 15];
        let rc = unsafe {
            lr_ospf_finalize_v3_packet(short.as_mut_ptr(), 15, src.as_ptr(), dst.as_ptr())
        };
        assert_eq!(rc, 0);
        // NULL src → 0.
        let rc = unsafe {
            lr_ospf_finalize_v3_packet(bytes.as_mut_ptr(), 16, std::ptr::null(), dst.as_ptr())
        };
        assert_eq!(rc, 0);
        // NULL dst → 0.
        let rc = unsafe {
            lr_ospf_finalize_v3_packet(bytes.as_mut_ptr(), 16, src.as_ptr(), std::ptr::null())
        };
        assert_eq!(rc, 0);
    }

    #[test]
    fn ffi_finalize_v3_stream_handles_null_safely() {
        let src = [0xfe_u8, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let dst = [0xff_u8, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 5];
        // NULL bytes → 0.
        let consumed = unsafe {
            lr_ospf_finalize_v3_stream(std::ptr::null_mut(), 16, src.as_ptr(), dst.as_ptr())
        };
        assert_eq!(consumed, 0);
        // NULL src → 0.
        let mut bytes = [0u8; 16];
        let consumed = unsafe {
            lr_ospf_finalize_v3_stream(bytes.as_mut_ptr(), 16, std::ptr::null(), dst.as_ptr())
        };
        assert_eq!(consumed, 0);
    }
}
