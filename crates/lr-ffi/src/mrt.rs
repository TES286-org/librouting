//! MRT (RFC 6396 / RFC 8050) wire codec FFI.
//!
//! Stateless. Mirrors the public Rust API of `lr_mrt::{MrtReader,
//! MrtRecord, PeerIndexTable, RibTable, RibEntry, PeerEntry, Bgp4MpCommon,
//! Bgp4MpStateChange, Bgp4MpMessage, MrtRibDump, encode_peer_index_table,
//! encode_rib_table}` so an embedder can parse and emit MRT dumps without
//! going through the Rust compiler.
//!
//! # Surface
//!
//! - `lr_mrt_decode` — decode one MRT record, return an opaque handle.
//! - `lr_mrt_encode_peer_index_table` / `lr_mrt_encode_rib_table` —
//!   encode a complete record to wire bytes.
//! - `lr_mrt_record_*` readers: type, subtype, is_rib.
//! - `lr_mrt_record_peer_index_table_*` / `lr_mrt_record_rib_*` / etc.
//! - `lr_mrt_record_free` — drop the boxed record.
//!
//! Every entry point runs inside the crate's `catch_unwind` barrier
//! ([`crate::guarded`]): a panic returns `LR_ERR_PANIC` and sets the
//! thread-local last-error string.

// The closure body passed to `guarded` is wrapped in a single `unsafe`
// block to mirror the `pub unsafe extern "C" fn` shape — the inner
// `unsafe { ... }` blocks would otherwise trip `unused_unsafe` under
// the crate's `-D warnings` clippy gate.
#![allow(unused_unsafe)]

use lr_core::addr::{Asn, IpAddr, Prefix};
use lr_mrt::{
    encode_peer_index_table, encode_rib_table, Bgp4MpCommon, Bgp4MpMessage, Bgp4MpStateChange,
    MrtReader, MrtRecord, MrtRibDump, PeerEntry, PeerIndexTable, RibEntry, RibTable,
};

use crate::error::{set_last_error, LrError, LR_ERR_PANIC};
use crate::guarded;
use crate::handle::lr_bytes_t;

const LR_ERR_NULL: i32 = LrError::Null as i32;
const LR_ERR_OTHER: i32 = LrError::Other as i32;

/// Opaque `MrtRecord` handle.
#[repr(C)]
pub struct OpaqueMrtRecord {
    _private: [u8; 0],
}

pub type lr_mrt_record_t = *mut OpaqueMrtRecord;

pub(crate) fn box_record(r: MrtRecord) -> lr_mrt_record_t {
    Box::into_raw(Box::new(r)) as lr_mrt_record_t
}

/// Reclaim a record handle.
///
/// # Safety
/// `r` must have been produced by [`box_record`] and not freed.
unsafe fn unbox_record(r: lr_mrt_record_t) -> Option<Box<MrtRecord>> {
    if r.is_null() {
        return None;
    }
    Some(unsafe { Box::from_raw(r as *mut MrtRecord) })
}

/// Borrow a record handle as `&MrtRecord` for read-only access.
///
/// # Safety
/// `r` must have been produced by [`box_record`] and not be freed while
/// the returned reference is live.
unsafe fn borrow_record(r: lr_mrt_record_t) -> Option<&'static MrtRecord> {
    if r.is_null() {
        return None;
    }
    Some(unsafe { &*(r as *const MrtRecord) })
}

// ---- Record-type constants ----

pub const LR_MRT_RECORD_PEER_INDEX_TABLE: u8 = 1;
pub const LR_MRT_RECORD_RIB: u8 = 2;
pub const LR_MRT_RECORD_BGP4MP_STATE_CHANGE: u8 = 3;
pub const LR_MRT_RECORD_BGP4MP_MESSAGE: u8 = 4;
pub const LR_MRT_RECORD_UNKNOWN: u8 = 5;

// ---- Decode / encode ----

/// Decode one MRT record from `data`. On success, writes a freshly-
/// allocated `lr_mrt_record_t` to `*out`. The decoder is stateful
/// (carryover survives across calls when bytes are partial); this FFI
/// entry creates a fresh `MrtReader` per call, so partial records
/// return `LR_ERR_OTHER` — embedders should feed one complete record
/// at a time.
///
/// # Safety
/// `data` must point to `len` readable bytes. `out` must point to a
/// writable `lr_mrt_record_t`.
#[no_mangle]
pub unsafe extern "C" fn lr_mrt_decode(
    data: *const u8,
    len: usize,
    out: *mut lr_mrt_record_t,
) -> i32 {
    guarded(
        || unsafe {
            if data.is_null() || out.is_null() {
                return LR_ERR_NULL;
            }
            let slice = unsafe { std::slice::from_raw_parts(data, len) };
            let mut reader = MrtReader::new();
            match reader.decode_slice(slice) {
                Ok(Some(r)) => {
                    unsafe { *out = box_record(r) }
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

/// Encode a Peer Index Table record to wire bytes (RFC 6396 §4.3 +
/// RFC 8050). The peer list is a flat array of `lr_mrt_peer_entry_t`
/// passed through `peers` / `peer_count`.
///
/// # Safety
/// `view_name` must be a NUL-terminated C string (NULL = empty view).
/// `peers` must point to `peer_count` readable `lr_mrt_peer_entry_t`.
#[no_mangle]
pub unsafe extern "C" fn lr_mrt_encode_peer_index_table(
    timestamp: u32,
    collector_bgp_id: u32,
    view_name: *const std::os::raw::c_char,
    peers: *const lr_mrt_peer_entry_t,
    peer_count: usize,
    out: *mut lr_bytes_t,
) -> i32 {
    guarded(
        || unsafe {
            if out.is_null() {
                return LR_ERR_NULL;
            }
            let view = if view_name.is_null() {
                String::new()
            } else {
                let s = unsafe { std::ffi::CStr::from_ptr(view_name) };
                s.to_string_lossy().into_owned()
            };
            let peer_vec: Vec<PeerEntry> = if peers.is_null() || peer_count == 0 {
                Vec::new()
            } else {
                let slice = unsafe { std::slice::from_raw_parts(peers, peer_count) };
                slice
                    .iter()
                    .map(|p| PeerEntry {
                        bgp_id: p.bgp_id,
                        ip: decode_addr(p.ip_addr, p.is_ipv6),
                        asn: Asn::new(p.asn),
                    })
                    .collect()
            };
            let pit = PeerIndexTable {
                collector_bgp_id,
                view_name: view,
                peers: peer_vec,
            };
            let pit_view = pit.view_name.as_str();
            match encode_peer_index_table(timestamp, collector_bgp_id, pit_view, &pit.peers) {
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

/// Encode a RIB table record (RFC 6396 §4.3 + RFC 8050 subtype 2).
/// The entries are a flat array of `lr_mrt_rib_entry_t`.
///
/// # Safety
/// `entries` must point to `entry_count` readable `lr_mrt_rib_entry_t`.
#[no_mangle]
pub unsafe extern "C" fn lr_mrt_encode_rib_table(
    timestamp: u32,
    sequence: u32,
    prefix_addr: *const u8,
    prefix_len: u8,
    is_ipv6: u8,
    add_path: u8,
    entries: *const lr_mrt_rib_entry_t,
    entry_count: usize,
    out: *mut lr_bytes_t,
) -> i32 {
    guarded(
        || unsafe {
            if out.is_null() || prefix_addr.is_null() {
                return LR_ERR_NULL;
            }
            let prefix = if is_ipv6 != 0 {
                let mut buf = [0u8; 16];
                let src = unsafe { std::slice::from_raw_parts(prefix_addr, 16) };
                buf.copy_from_slice(src);
                Prefix::new_v6(buf, prefix_len)
            } else {
                let mut buf = [0u8; 4];
                let src = unsafe { std::slice::from_raw_parts(prefix_addr, 4) };
                buf.copy_from_slice(src);
                Prefix::new_v4(buf, prefix_len)
            };
            let entry_vec: Vec<RibEntry> = if entries.is_null() || entry_count == 0 {
                Vec::new()
            } else {
                let slice = unsafe { std::slice::from_raw_parts(entries, entry_count) };
                slice
                    .iter()
                    .map(|e| RibEntry {
                        peer_index: e.peer_index,
                        originated_time: e.originated_time,
                        path_id: e.path_id,
                        attributes: if e.attributes.is_null() || e.attr_len == 0 {
                            Vec::new()
                        } else {
                            unsafe { std::slice::from_raw_parts(e.attributes, e.attr_len) }.to_vec()
                        },
                    })
                    .collect()
            };
            let table = RibTable {
                sequence,
                prefix,
                add_path: add_path != 0,
                entries: entry_vec,
            };
            match encode_rib_table(timestamp, &table) {
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

/// One peer of a Peer Index Table. Mirrors `lr_mrt::PeerEntry`. The
/// `ip_addr` pointer must point to 4 bytes for IPv4, 16 bytes for IPv6.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct lr_mrt_peer_entry_t {
    pub bgp_id: u32,
    /// 4 or 16 bytes, depending on `is_ipv6`.
    pub ip_addr: *const u8,
    pub is_ipv6: u8,
    pub asn: u32,
}

/// One RIB entry. Mirrors `lr_mrt::RibEntry`. The `attributes` pointer
/// is borrowed for the duration of the encode call.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct lr_mrt_rib_entry_t {
    pub peer_index: u16,
    pub originated_time: u32,
    pub path_id: u32,
    pub attributes: *const u8,
    pub attr_len: usize,
}

// ---- Record readers ----

/// Read the record type (`LR_MRT_RECORD_*`).
///
/// # Safety
/// `record` must be a valid handle.
#[no_mangle]
pub unsafe extern "C" fn lr_mrt_record_type(record: lr_mrt_record_t) -> u8 {
    guarded(
        || unsafe {
            let Some(r) = borrow_record(record) else {
                return 0;
            };
            match r {
                MrtRecord::PeerIndexTable(_) => LR_MRT_RECORD_PEER_INDEX_TABLE,
                MrtRecord::Rib(_) => LR_MRT_RECORD_RIB,
                MrtRecord::Bgp4MpStateChange(_) => LR_MRT_RECORD_BGP4MP_STATE_CHANGE,
                MrtRecord::Bgp4MpMessage(_) => LR_MRT_RECORD_BGP4MP_MESSAGE,
                MrtRecord::Unknown { .. } => LR_MRT_RECORD_UNKNOWN,
            }
        },
        0,
    )
}

/// 1 when this record is a RIB record, 0 otherwise.
///
/// # Safety
/// `record` must be a valid handle.
#[no_mangle]
pub unsafe extern "C" fn lr_mrt_record_is_rib(record: lr_mrt_record_t) -> u8 {
    guarded(
        || unsafe { borrow_record(record).map(|r| r.is_rib() as u8).unwrap_or(0) },
        0,
    )
}

/// For an Unknown record, write the `(msg_type, subtype)` pair to the
/// given out-pointers. Returns 0 on success, `LR_ERR_INVALID_HANDLE`
/// (-2) when the record is not the Unknown variant.
///
/// # Safety
/// `record` must be a valid handle. Both out-pointers must be writable
/// `uint16_t*`.
#[no_mangle]
pub unsafe extern "C" fn lr_mrt_record_unknown_subtype(
    record: lr_mrt_record_t,
    out_msg_type: *mut u16,
    out_subtype: *mut u16,
) -> i32 {
    guarded(
        || unsafe {
            let Some(r) = borrow_record(record) else {
                return LR_ERR_NULL;
            };
            if out_msg_type.is_null() || out_subtype.is_null() {
                return LR_ERR_NULL;
            }
            match r {
                MrtRecord::Unknown { msg_type, subtype } => {
                    unsafe {
                        *out_msg_type = *msg_type;
                        *out_subtype = *subtype;
                    }
                    0
                }
                _ => LrError::InvalidHandle as i32,
            }
        },
        LR_ERR_PANIC,
    )
}

/// Drop a boxed `MrtRecord`. Safe to call with NULL.
///
/// # Safety
/// `record` must have been produced by a `lr_mrt_record_*` constructor
/// and must not be used after this call.
#[no_mangle]
pub unsafe extern "C" fn lr_mrt_record_free(record: lr_mrt_record_t) {
    guarded(
        || unsafe {
            drop(unbox_record(record));
        },
        (),
    )
}

// ---- Helpers ----

fn decode_addr(addr: *const u8, is_ipv6: u8) -> IpAddr {
    if addr.is_null() {
        return IpAddr::V4([0; 4]);
    }
    if is_ipv6 != 0 {
        let mut buf = [0u8; 16];
        let src = unsafe { std::slice::from_raw_parts(addr, 16) };
        buf.copy_from_slice(src);
        IpAddr::V6(buf)
    } else {
        let mut buf = [0u8; 4];
        let src = unsafe { std::slice::from_raw_parts(addr, 4) };
        buf.copy_from_slice(src);
        IpAddr::V4(buf)
    }
}

// Allow callers to keep constructing the dump writer without going
// through the encode functions above. Mirrors `lr_mrt::MrtRibDump`.
//
// This is intentionally a thin pass-through: the heavy lifting
// (peer index table + per-RIB record encoding) lives in
// `lr_mrt_encode_peer_index_table` and `lr_mrt_encode_rib_table`.

/// Opaque `MrtRibDump` handle. Wraps a boxed `lr_mrt::MrtRibDump` so
/// embedders can incrementally build a dump without re-encoding every
/// record on every add.
#[repr(C)]
pub struct OpaqueMrtRibDump {
    _private: [u8; 0],
}

pub type lr_mrt_rib_dump_t = *mut OpaqueMrtRibDump;

fn box_dump(d: MrtRibDump) -> lr_mrt_rib_dump_t {
    Box::into_raw(Box::new(d)) as lr_mrt_rib_dump_t
}

/// Borrow a dump handle as `&MrtRibDump` for read-only access.
///
/// # Safety
/// `d` must have been produced by [`box_dump`] and not be freed while
/// the returned reference is live.
unsafe fn borrow_dump(d: lr_mrt_rib_dump_t) -> Option<&'static MrtRibDump> {
    if d.is_null() {
        return None;
    }
    Some(unsafe { &*(d as *const MrtRibDump) })
}

/// Borrow a dump handle mutably.
///
/// # Safety
/// See [`borrow_dump`]; caller must not race the mutation.
unsafe fn borrow_dump_mut(d: lr_mrt_rib_dump_t) -> Option<&'static mut MrtRibDump> {
    if d.is_null() {
        return None;
    }
    Some(unsafe { &mut *(d as *mut MrtRibDump) })
}

/// Construct an empty MrtRibDump. The collector's BGP ID is the
/// BGP identifier of the BMP/MRT collector emitting the dump; the
/// view name is the BIRD table name (may be empty).
#[no_mangle]
pub extern "C" fn lr_mrt_rib_dump_new(
    collector_bgp_id: u32,
    view_name: *const std::os::raw::c_char,
) -> lr_mrt_rib_dump_t {
    guarded(
        || {
            let view = if view_name.is_null() {
                String::new()
            } else {
                let s = unsafe { std::ffi::CStr::from_ptr(view_name) };
                s.to_string_lossy().into_owned()
            };
            box_dump(MrtRibDump::new(collector_bgp_id, view))
        },
        std::ptr::null_mut(),
    )
}

/// Add a peer to the dump. Returns the peer index assigned (0-based).
///
/// # Safety
/// `peer.ip_addr` must point to 4 or 16 bytes (per `is_ipv6`).
#[no_mangle]
pub unsafe extern "C" fn lr_mrt_rib_dump_add_peer(
    dump: lr_mrt_rib_dump_t,
    peer: lr_mrt_peer_entry_t,
) -> u16 {
    guarded(
        || unsafe {
            let Some(d) = borrow_dump_mut(dump) else {
                return 0;
            };
            let p = PeerEntry {
                bgp_id: peer.bgp_id,
                ip: decode_addr(peer.ip_addr, peer.is_ipv6),
                asn: Asn::new(peer.asn),
            };
            d.add_peer(p)
        },
        0,
    )
}

/// Add a RIB table record to the dump (RFC 6396 §4.3). The table is
/// built from the raw parameters the same way
/// [`lr_mrt_encode_rib_table`] builds the wire bytes — but here the
/// table is appended to the dump's in-memory list, encoded only when
/// [`lr_mrt_rib_dump_encode`] runs.
///
/// # Safety
/// `dump` must be a valid handle. `prefix_addr` must point to 4 or 16
/// bytes per `is_ipv6`. `entries` must point to `entry_count`
/// readable `lr_mrt_rib_entry_t`.
#[no_mangle]
pub unsafe extern "C" fn lr_mrt_rib_dump_add_table(
    dump: lr_mrt_rib_dump_t,
    sequence: u32,
    prefix_addr: *const u8,
    prefix_len: u8,
    is_ipv6: u8,
    add_path: u8,
    entries: *const lr_mrt_rib_entry_t,
    entry_count: usize,
) -> i32 {
    guarded(
        || unsafe {
            let Some(d) = borrow_dump_mut(dump) else {
                return LR_ERR_NULL;
            };
            if prefix_addr.is_null() {
                return LR_ERR_NULL;
            }
            let prefix = if is_ipv6 != 0 {
                let mut buf = [0u8; 16];
                let src = unsafe { std::slice::from_raw_parts(prefix_addr, 16) };
                buf.copy_from_slice(src);
                Prefix::new_v6(buf, prefix_len)
            } else {
                let mut buf = [0u8; 4];
                let src = unsafe { std::slice::from_raw_parts(prefix_addr, 4) };
                buf.copy_from_slice(src);
                Prefix::new_v4(buf, prefix_len)
            };
            let entry_vec: Vec<RibEntry> = if entries.is_null() || entry_count == 0 {
                Vec::new()
            } else {
                let slice = unsafe { std::slice::from_raw_parts(entries, entry_count) };
                slice
                    .iter()
                    .map(|e| RibEntry {
                        peer_index: e.peer_index,
                        originated_time: e.originated_time,
                        path_id: e.path_id,
                        attributes: if e.attributes.is_null() || e.attr_len == 0 {
                            Vec::new()
                        } else {
                            unsafe { std::slice::from_raw_parts(e.attributes, e.attr_len) }.to_vec()
                        },
                    })
                    .collect()
            };
            d.add_table(RibTable {
                sequence,
                prefix,
                add_path: add_path != 0,
                entries: entry_vec,
            });
            0
        },
        LR_ERR_PANIC,
    )
}

/// Encode the entire dump as a sequence of MRT records, returning
/// the concatenated wire bytes in `*out`.
///
/// # Safety
/// `dump` must be a valid handle. `out` must point to a writable
/// `lr_bytes_t`.
#[no_mangle]
pub unsafe extern "C" fn lr_mrt_rib_dump_encode(
    dump: lr_mrt_rib_dump_t,
    timestamp: u32,
    out: *mut lr_bytes_t,
) -> i32 {
    guarded(
        || unsafe {
            let Some(d) = borrow_dump(dump) else {
                return LR_ERR_NULL;
            };
            if out.is_null() {
                return LR_ERR_NULL;
            }
            match d.encode(timestamp) {
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

/// Drop a boxed `MrtRibDump`. Safe to call with NULL.
///
/// # Safety
/// `dump` must have been produced by [`lr_mrt_rib_dump_new`] and not
/// used after this call.
#[no_mangle]
pub unsafe extern "C" fn lr_mrt_rib_dump_free(dump: lr_mrt_rib_dump_t) {
    guarded(
        || unsafe {
            if !dump.is_null() {
                let boxed: Box<MrtRibDump> = Box::from_raw(dump as *mut MrtRibDump);
                drop(boxed);
            }
        },
        (),
    )
}

// ---- Bgp4Mp records ----

/// Construct a `Bgp4MpMessage` record from raw bytes (subtype
/// BGP4MP_MESSAGE_AS4). The result is ready for encode via the dump
/// machinery or as a standalone record.
#[no_mangle]
pub unsafe extern "C" fn lr_mrt_record_bgp4mp_message(
    peer_as: u32,
    local_as: u32,
    ifindex: u16,
    af: u16,
    peer_addr: *const u8,
    peer_addr_len: usize,
    local_addr: *const u8,
    local_addr_len: usize,
    message: *const u8,
    message_len: usize,
) -> lr_mrt_record_t {
    guarded(
        || unsafe {
            let common = build_bgp4mp_common(
                peer_as,
                local_as,
                ifindex,
                af,
                peer_addr,
                peer_addr_len,
                local_addr,
                local_addr_len,
            );
            let msg = if message.is_null() || message_len == 0 {
                Vec::new()
            } else {
                unsafe { std::slice::from_raw_parts(message, message_len) }.to_vec()
            };
            box_record(MrtRecord::Bgp4MpMessage(Bgp4MpMessage {
                common,
                message: msg,
            }))
        },
        std::ptr::null_mut(),
    )
}

/// Construct a `Bgp4MpStateChange` record (subtype
/// BGP4MP_STATE_CHANGE_AS4). Returns an opaque handle.
#[no_mangle]
pub unsafe extern "C" fn lr_mrt_record_bgp4mp_state_change(
    peer_as: u32,
    local_as: u32,
    ifindex: u16,
    af: u16,
    peer_addr: *const u8,
    peer_addr_len: usize,
    local_addr: *const u8,
    local_addr_len: usize,
    old_state: u16,
    new_state: u16,
) -> lr_mrt_record_t {
    guarded(
        || unsafe {
            let common = build_bgp4mp_common(
                peer_as,
                local_as,
                ifindex,
                af,
                peer_addr,
                peer_addr_len,
                local_addr,
                local_addr_len,
            );
            box_record(MrtRecord::Bgp4MpStateChange(Bgp4MpStateChange {
                common,
                old_state,
                new_state,
            }))
        },
        std::ptr::null_mut(),
    )
}

#[allow(clippy::too_many_arguments)]
unsafe fn build_bgp4mp_common(
    peer_as: u32,
    local_as: u32,
    ifindex: u16,
    af: u16,
    peer_addr: *const u8,
    peer_addr_len: usize,
    local_addr: *const u8,
    local_addr_len: usize,
) -> Bgp4MpCommon {
    let peer_ip = if peer_addr.is_null() || peer_addr_len == 0 {
        IpAddr::V4([0; 4])
    } else if peer_addr_len == 16 {
        let mut buf = [0u8; 16];
        let src = unsafe { std::slice::from_raw_parts(peer_addr, 16) };
        buf.copy_from_slice(src);
        IpAddr::V6(buf)
    } else {
        let mut buf = [0u8; 4];
        let src = unsafe { std::slice::from_raw_parts(peer_addr, 4) };
        buf.copy_from_slice(src);
        IpAddr::V4(buf)
    };
    let local_ip = if local_addr.is_null() || local_addr_len == 0 {
        IpAddr::V4([0; 4])
    } else if local_addr_len == 16 {
        let mut buf = [0u8; 16];
        let src = unsafe { std::slice::from_raw_parts(local_addr, 16) };
        buf.copy_from_slice(src);
        IpAddr::V6(buf)
    } else {
        let mut buf = [0u8; 4];
        let src = unsafe { std::slice::from_raw_parts(local_addr, 4) };
        buf.copy_from_slice(src);
        IpAddr::V4(buf)
    };
    Bgp4MpCommon {
        peer_as: Asn(peer_as),
        local_as: Asn(local_as),
        ifindex,
        af,
        peer_ip,
        local_ip,
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
    fn ffi_constants_match_rfc_6396() {
        assert_eq!(LR_MRT_RECORD_PEER_INDEX_TABLE, 1);
        assert_eq!(LR_MRT_RECORD_RIB, 2);
        assert_eq!(LR_MRT_RECORD_BGP4MP_STATE_CHANGE, 3);
        assert_eq!(LR_MRT_RECORD_BGP4MP_MESSAGE, 4);
        assert_eq!(LR_MRT_RECORD_UNKNOWN, 5);
    }

    #[test]
    fn ffi_encode_peer_index_table_roundtrip() {
        let view = std::ffi::CString::new("master4").unwrap();
        let ip = [10u8, 0, 0, 1];
        let peers = [lr_mrt_peer_entry_t {
            bgp_id: 0x0a000001,
            ip_addr: ip.as_ptr(),
            is_ipv6: 0,
            asn: 64512,
        }];
        let mut out = lr_bytes_t {
            ptr: std::ptr::null_mut(),
            len: 0,
            cap: 0,
        };
        let rc = unsafe {
            lr_mrt_encode_peer_index_table(
                1_700_000_000,
                0x0a000001,
                view.as_ptr(),
                peers.as_ptr(),
                peers.len(),
                &raw mut out,
            )
        };
        assert_eq!(rc, 0);
        let bytes = unsafe { bytes_to_vec(&mut out) };
        assert!(bytes.len() > 12); // header + body.

        // Decode the bytes back.
        let mut rec: lr_mrt_record_t = std::ptr::null_mut();
        let rc = unsafe { lr_mrt_decode(bytes.as_ptr(), bytes.len(), &raw mut rec) };
        assert_eq!(rc, 0);
        assert!(!rec.is_null());
        assert_eq!(
            unsafe { lr_mrt_record_type(rec) },
            LR_MRT_RECORD_PEER_INDEX_TABLE
        );
        unsafe { lr_mrt_record_free(rec) };
    }

    #[test]
    fn ffi_encode_rib_table_roundtrip() {
        let prefix = [10u8, 0, 0, 0];
        let attrs = [0x40u8, 1, 0, 0, 4, 0]; // ORIGIN=IGP
        let entries = [lr_mrt_rib_entry_t {
            peer_index: 0,
            originated_time: 1_700_000_000,
            path_id: 0,
            attributes: attrs.as_ptr(),
            attr_len: attrs.len(),
        }];
        let mut out = lr_bytes_t {
            ptr: std::ptr::null_mut(),
            len: 0,
            cap: 0,
        };
        let rc = unsafe {
            lr_mrt_encode_rib_table(
                1_700_000_001,
                1,
                prefix.as_ptr(),
                24,
                0,
                0,
                entries.as_ptr(),
                entries.len(),
                &raw mut out,
            )
        };
        assert_eq!(rc, 0);
        let bytes = unsafe { bytes_to_vec(&mut out) };
        assert!(bytes.len() > 12);

        let mut rec: lr_mrt_record_t = std::ptr::null_mut();
        let rc = unsafe { lr_mrt_decode(bytes.as_ptr(), bytes.len(), &raw mut rec) };
        assert_eq!(rc, 0);
        assert_eq!(unsafe { lr_mrt_record_type(rec) }, LR_MRT_RECORD_RIB);
        assert_eq!(unsafe { lr_mrt_record_is_rib(rec) }, 1);
        unsafe { lr_mrt_record_free(rec) };
    }

    #[test]
    fn ffi_decode_rejects_null_input() {
        let mut rec: lr_mrt_record_t = std::ptr::null_mut();
        let rc = unsafe { lr_mrt_decode(std::ptr::null(), 0, &raw mut rec) };
        assert_eq!(rc, LR_ERR_NULL);
    }

    #[test]
    fn ffi_decode_rejects_too_short() {
        let bytes = [0u8; 5]; // less than the 12-byte header
        let mut rec: lr_mrt_record_t = std::ptr::null_mut();
        let rc = unsafe { lr_mrt_decode(bytes.as_ptr(), bytes.len(), &raw mut rec) };
        assert!(rc < 0);
    }

    #[test]
    fn ffi_free_handles_null_safely() {
        unsafe {
            lr_mrt_record_free(std::ptr::null_mut());
            lr_mrt_rib_dump_free(std::ptr::null_mut());
        }
    }

    #[test]
    fn ffi_rib_dump_lifecycle() {
        let view = std::ffi::CString::new("master4").unwrap();
        let d = unsafe { lr_mrt_rib_dump_new(0x0a000001, view.as_ptr()) };
        assert!(!d.is_null());
        let ip = [10u8, 0, 0, 1];
        let peer = lr_mrt_peer_entry_t {
            bgp_id: 0x0a000001,
            ip_addr: ip.as_ptr(),
            is_ipv6: 0,
            asn: 64512,
        };
        let idx = unsafe { lr_mrt_rib_dump_add_peer(d, peer) };
        assert_eq!(idx, 0);

        let mut out = lr_bytes_t {
            ptr: std::ptr::null_mut(),
            len: 0,
            cap: 0,
        };
        let rc = unsafe { lr_mrt_rib_dump_encode(d, 1_700_000_000, &raw mut out) };
        assert_eq!(rc, 0);
        let bytes = unsafe { bytes_to_vec(&mut out) };
        assert!(bytes.len() > 12);
        unsafe { lr_mrt_rib_dump_free(d) };
    }

    #[test]
    fn ffi_bgp4mp_state_change_construct() {
        let peer_ip = [10u8, 0, 0, 2];
        let local_ip = [10u8, 0, 0, 1];
        let r = unsafe {
            lr_mrt_record_bgp4mp_state_change(
                64513,
                64512,
                1,
                2, // AF_INET
                peer_ip.as_ptr(),
                peer_ip.len(),
                local_ip.as_ptr(),
                local_ip.len(),
                5, // OpenSent
                6, // OpenConfirm
            )
        };
        assert!(!r.is_null());
        assert_eq!(
            unsafe { lr_mrt_record_type(r) },
            LR_MRT_RECORD_BGP4MP_STATE_CHANGE
        );
        unsafe { lr_mrt_record_free(r) };
    }

    #[test]
    fn ffi_bgp4mp_message_construct() {
        let peer_ip = [10u8, 0, 0, 2];
        let local_ip = [10u8, 0, 0, 1];
        let msg = [0xffu8; 19]; // BGP KEEPALIVE marker
        let r = unsafe {
            lr_mrt_record_bgp4mp_message(
                64513,
                64512,
                1,
                2,
                peer_ip.as_ptr(),
                peer_ip.len(),
                local_ip.as_ptr(),
                local_ip.len(),
                msg.as_ptr(),
                msg.len(),
            )
        };
        assert!(!r.is_null());
        assert_eq!(
            unsafe { lr_mrt_record_type(r) },
            LR_MRT_RECORD_BGP4MP_MESSAGE
        );
        unsafe { lr_mrt_record_free(r) };
    }
}
