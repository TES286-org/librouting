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
}
