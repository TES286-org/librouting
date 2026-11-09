//! OSPF packet body accessors FFI — HelloBody, DbDescBody, LsUpdateBody.
//!
//! The existing `lr_ospf_packet_*` surface exposes header fields and
//! the `body_kind` tag, but embedders couldn't read the body content
//! (Hello params, DD flags, LSA list) without re-parsing the raw
//! bytes. This module adds typed readers for each body variant.

#![allow(unused_unsafe)]
#![allow(dead_code)]
#![allow(unused_imports)]

use lr_ospf::packet::{DbDescBody, HelloBody, LsUpdateBody, OspfBody, OspfPacket};

use crate::error::{LrError, LR_ERR_PANIC};
use crate::guarded;
use crate::ospf_lsdb::lr_ospf_lsa_hdr_t;

const LR_ERR_NULL: i32 = LrError::Null as i32;
const LR_ERR_INVALID_HANDLE: i32 = LrError::InvalidHandle as i32;

/// `lr_ospf_packet_t` — the opaque packet handle (re-exported from
/// ospf.rs so this module is self-contained).
pub type lr_ospf_packet_t = *mut crate::ospf::OpaqueOspfPacket;

unsafe fn borrow_packet(p: lr_ospf_packet_t) -> Option<&'static OspfPacket> {
    if p.is_null() {
        return None;
    }
    Some(unsafe { &*(p as *const OspfPacket) })
}

// ---- HelloBody readers ----

/// Read the Hello body's `network_mask` (v2) / Interface ID (v3).
/// Returns `LR_ERR_INVALID_HANDLE` (-2) when the packet body is not
/// a Hello.
///
/// # Safety
/// `p` must be a valid handle.
#[no_mangle]
pub unsafe extern "C" fn lr_ospf_hello_network_mask(p: lr_ospf_packet_t) -> u32 {
    guarded(
        || unsafe {
            borrow_packet(p)
                .and_then(|pkt| match &pkt.body {
                    OspfBody::Hello(h) => Some(h.network_mask()),
                    _ => None,
                })
                .unwrap_or(0)
        },
        0,
    )
}

/// Read the Hello body's Interface ID (RFC 5340 §A.3.2.1) — the
/// 4-byte wire slot v2 uses for the network mask. v3 has no network
/// mask; the slot identifies the interface the Hello was sent on, so
/// the receiver can correlate it with the matching Link-LSA (per
/// §A.4.9, the Link-LSA's Link State ID equals this Interface ID).
///
/// This is the v3-named alias of [`lr_ospf_hello_network_mask`]; the
/// two read the same wire slot. Embedders processing an OSPFv3 Hello
/// should call this accessor instead of `lr_ospf_hello_network_mask`
/// so the call site documents the v3 intent — reading
/// `lr_ospf_hello_network_mask` for v3 looks like "the network mask
/// is 7", which is misleading on its face.
///
/// Returns `0` when the packet body is not a Hello (matching the
/// `lr_ospf_hello_network_mask` contract).
///
/// # Safety
/// `p` must be a valid handle.
#[no_mangle]
pub unsafe extern "C" fn lr_ospf_hello_interface_id(p: lr_ospf_packet_t) -> u32 {
    guarded(
        || unsafe {
            borrow_packet(p)
                .and_then(|pkt| match &pkt.body {
                    OspfBody::Hello(h) => Some(h.interface_id()),
                    _ => None,
                })
                .unwrap_or(0)
        },
        0,
    )
}

#[no_mangle]
pub unsafe extern "C" fn lr_ospf_hello_interval(p: lr_ospf_packet_t) -> u16 {
    guarded(
        || unsafe {
            borrow_packet(p)
                .and_then(|pkt| match &pkt.body {
                    OspfBody::Hello(h) => Some(h.hello_interval),
                    _ => None,
                })
                .unwrap_or(0)
        },
        0,
    )
}

#[no_mangle]
pub unsafe extern "C" fn lr_ospf_hello_options(p: lr_ospf_packet_t) -> u32 {
    guarded(
        || unsafe {
            borrow_packet(p)
                .and_then(|pkt| match &pkt.body {
                    OspfBody::Hello(h) => Some(h.options),
                    _ => None,
                })
                .unwrap_or(0)
        },
        0,
    )
}

#[no_mangle]
pub unsafe extern "C" fn lr_ospf_hello_priority(p: lr_ospf_packet_t) -> u8 {
    guarded(
        || unsafe {
            borrow_packet(p)
                .and_then(|pkt| match &pkt.body {
                    OspfBody::Hello(h) => Some(h.priority),
                    _ => None,
                })
                .unwrap_or(0)
        },
        0,
    )
}

#[no_mangle]
pub unsafe extern "C" fn lr_ospf_hello_dead_interval(p: lr_ospf_packet_t) -> u32 {
    guarded(
        || unsafe {
            borrow_packet(p)
                .and_then(|pkt| match &pkt.body {
                    OspfBody::Hello(h) => Some(h.dead_interval),
                    _ => None,
                })
                .unwrap_or(0)
        },
        0,
    )
}

#[no_mangle]
pub unsafe extern "C" fn lr_ospf_hello_dr(p: lr_ospf_packet_t) -> u32 {
    guarded(
        || unsafe {
            borrow_packet(p)
                .and_then(|pkt| match &pkt.body {
                    OspfBody::Hello(h) => Some(h.dr),
                    _ => None,
                })
                .unwrap_or(0)
        },
        0,
    )
}

#[no_mangle]
pub unsafe extern "C" fn lr_ospf_hello_bdr(p: lr_ospf_packet_t) -> u32 {
    guarded(
        || unsafe {
            borrow_packet(p)
                .and_then(|pkt| match &pkt.body {
                    OspfBody::Hello(h) => Some(h.bdr),
                    _ => None,
                })
                .unwrap_or(0)
        },
        0,
    )
}

#[no_mangle]
pub unsafe extern "C" fn lr_ospf_hello_neighbor_count(p: lr_ospf_packet_t) -> usize {
    guarded(
        || unsafe {
            borrow_packet(p)
                .and_then(|pkt| match &pkt.body {
                    OspfBody::Hello(h) => Some(h.neighbors.len()),
                    _ => None,
                })
                .unwrap_or(0)
        },
        0,
    )
}

#[no_mangle]
pub unsafe extern "C" fn lr_ospf_hello_neighbor_at(p: lr_ospf_packet_t, index: usize) -> u32 {
    guarded(
        || unsafe {
            borrow_packet(p)
                .and_then(|pkt| match &pkt.body {
                    OspfBody::Hello(h) => h.neighbors.get(index).copied(),
                    _ => None,
                })
                .unwrap_or(0)
        },
        0,
    )
}

// ---- DbDescBody readers ----

#[no_mangle]
pub unsafe extern "C" fn lr_ospf_db_desc_mtu(p: lr_ospf_packet_t) -> u16 {
    guarded(
        || unsafe {
            borrow_packet(p)
                .and_then(|pkt| match &pkt.body {
                    OspfBody::DbDesc(d) => Some(d.mtu),
                    _ => None,
                })
                .unwrap_or(0)
        },
        0,
    )
}

#[no_mangle]
pub unsafe extern "C" fn lr_ospf_db_desc_options(p: lr_ospf_packet_t) -> u32 {
    guarded(
        || unsafe {
            borrow_packet(p)
                .and_then(|pkt| match &pkt.body {
                    OspfBody::DbDesc(d) => Some(d.options),
                    _ => None,
                })
                .unwrap_or(0)
        },
        0,
    )
}

#[no_mangle]
pub unsafe extern "C" fn lr_ospf_db_desc_flags(p: lr_ospf_packet_t) -> u8 {
    guarded(
        || unsafe {
            borrow_packet(p)
                .and_then(|pkt| match &pkt.body {
                    OspfBody::DbDesc(d) => Some(d.flags),
                    _ => None,
                })
                .unwrap_or(0)
        },
        0,
    )
}

#[no_mangle]
pub unsafe extern "C" fn lr_ospf_db_desc_seq(p: lr_ospf_packet_t) -> u32 {
    guarded(
        || unsafe {
            borrow_packet(p)
                .and_then(|pkt| match &pkt.body {
                    OspfBody::DbDesc(d) => Some(d.dd_seq),
                    _ => None,
                })
                .unwrap_or(0)
        },
        0,
    )
}

#[no_mangle]
pub unsafe extern "C" fn lr_ospf_db_desc_lsa_header_count(p: lr_ospf_packet_t) -> usize {
    guarded(
        || unsafe {
            borrow_packet(p)
                .and_then(|pkt| match &pkt.body {
                    OspfBody::DbDesc(d) => Some(d.lsa_headers.len()),
                    _ => None,
                })
                .unwrap_or(0)
        },
        0,
    )
}

/// Read one LSA header from a DbDesc body at `index`. Writes the
/// header fields to `*out`. Returns 0 on success,
/// `LR_ERR_INVALID_HANDLE` when the body is not a DbDesc or the
/// index is out of range.
///
/// # Safety
/// `p` must be a valid handle. `out` must point to a writable
/// `lr_ospf_lsa_hdr_t`.
#[no_mangle]
pub unsafe extern "C" fn lr_ospf_db_desc_lsa_header_at(
    p: lr_ospf_packet_t,
    index: usize,
    out: *mut lr_ospf_lsa_hdr_t,
) -> i32 {
    guarded(
        || unsafe {
            if out.is_null() {
                return LR_ERR_NULL;
            }
            let Some(pkt) = borrow_packet(p) else {
                return LR_ERR_NULL;
            };
            match &pkt.body {
                OspfBody::DbDesc(d) => {
                    let Some(h) = d.lsa_headers.get(index) else {
                        return LR_ERR_INVALID_HANDLE;
                    };
                    unsafe { *out = lr_ospf_lsa_hdr_t::from(h) };
                    0
                }
                _ => LR_ERR_INVALID_HANDLE,
            }
        },
        LR_ERR_PANIC,
    )
}

// ---- LsUpdateBody readers ----

#[no_mangle]
pub unsafe extern "C" fn lr_ospf_ls_update_lsa_count(p: lr_ospf_packet_t) -> u32 {
    guarded(
        || unsafe {
            borrow_packet(p)
                .and_then(|pkt| match &pkt.body {
                    OspfBody::LsUpdate(u) => Some(u.lsa_count),
                    _ => None,
                })
                .unwrap_or(0)
        },
        0,
    )
}

#[no_mangle]
pub unsafe extern "C" fn lr_ospf_ls_update_lsa_len(p: lr_ospf_packet_t) -> usize {
    guarded(
        || unsafe {
            borrow_packet(p)
                .and_then(|pkt| match &pkt.body {
                    OspfBody::LsUpdate(u) => Some(u.lsas.len()),
                    _ => None,
                })
                .unwrap_or(0)
        },
        0,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use lr_core::buf::ReadBuf;
    use lr_ospf::codec::OspfCodec;
    use lr_ospf::packet::*;

    fn make_hello_packet() -> lr_ospf_packet_t {
        let hello = HelloBody {
            network_mask: 0xffff_ff00,
            hello_interval: 10,
            options: 0x02,
            priority: 1,
            dead_interval: 40,
            dr: 0x0a000001,
            bdr: 0x0a000002,
            neighbors: vec![0x0a000003, 0x0a000004],
        };
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
            body: OspfBody::Hello(hello),
        };
        let mut codec = OspfCodec::v2();
        let mut bytes = codec.encode_vec(&pkt).unwrap();
        lr_ospf::origination::finalize_v2_stream(&mut bytes);
        let decoded = codec.decode_slice(&bytes).unwrap().unwrap();
        Box::into_raw(Box::new(decoded)) as lr_ospf_packet_t
    }

    /// Build a v3 Hello packet whose first 4 bytes carry the
    /// Interface ID (RFC 5340 §A.3.2.1 reuses the v2 network_mask
    /// slot). The two FFI accessors — `lr_ospf_hello_network_mask`
    /// (v2-named) and `lr_ospf_hello_interface_id` (v3-named) — read
    /// the same wire slot; this v3 fixture exercises the alias
    /// contract.
    fn make_v3_hello_packet(interface_id: u32) -> lr_ospf_packet_t {
        let hello = HelloBody {
            network_mask: 0,
            hello_interval: 10,
            options: 0x13, // RFC 5340 §A.2: V6|R|E
            priority: 1,
            dead_interval: 40,
            dr: 0,
            bdr: 0,
            neighbors: vec![],
        }
        .with_interface_id(interface_id);
        let pkt = OspfPacket {
            header: OspfHeader {
                version: 3,
                kind: OspfPacketType::Hello as u8,
                length: 0,
                router_id: 0x0a000001,
                area_id: 0,
                checksum: 0,
                au_type_or_instance: 0,
                auth_data: 0,
            },
            body: OspfBody::Hello(hello),
        };
        let mut codec = OspfCodec::v3();
        let bytes = codec.encode_vec(&pkt).unwrap();
        let decoded = codec.decode_slice(&bytes).unwrap().unwrap();
        Box::into_raw(Box::new(decoded)) as lr_ospf_packet_t
    }

    #[test]
    fn ffi_hello_body_readers() {
        let p = make_hello_packet();
        assert_eq!(unsafe { lr_ospf_hello_network_mask(p) }, 0xffff_ff00);
        // The v3-named alias reads the same wire slot as the v2
        // `network_mask` accessor — RFC 5340 §A.3.2.1 reuses the v2
        // slot for the Interface ID, so the two FFI functions agree
        // byte-for-byte on a v2 packet (the v3 caller should never
        // construct a v2 packet, but the alias contract is that the
        // two read the same byte).
        assert_eq!(unsafe { lr_ospf_hello_interface_id(p) }, 0xffff_ff00);
        assert_eq!(unsafe { lr_ospf_hello_interval(p) }, 10);
        assert_eq!(unsafe { lr_ospf_hello_options(p) }, 0x02);
        assert_eq!(unsafe { lr_ospf_hello_priority(p) }, 1);
        assert_eq!(unsafe { lr_ospf_hello_dead_interval(p) }, 40);
        assert_eq!(unsafe { lr_ospf_hello_dr(p) }, 0x0a000001);
        assert_eq!(unsafe { lr_ospf_hello_bdr(p) }, 0x0a000002);
        assert_eq!(unsafe { lr_ospf_hello_neighbor_count(p) }, 2);
        assert_eq!(unsafe { lr_ospf_hello_neighbor_at(p, 0) }, 0x0a000003);
        assert_eq!(unsafe { lr_ospf_hello_neighbor_at(p, 1) }, 0x0a000004);
        unsafe { crate::ospf::lr_ospf_packet_free(p) };
    }

    /// The v3-named `lr_ospf_hello_interface_id` accessor reads the
    /// Interface ID from a v3 Hello; the v2-named
    /// `lr_ospf_hello_network_mask` reads the same byte (the wire
    /// slot is shared per RFC 5340 §A.3.2.1). A v3 caller uses the
    /// v3-named accessor so the call site documents the v3 intent
    /// — `interface_id()` reads as "the Interface ID is 7", while
    /// `network_mask()` reads as "the network mask is 7", which is
    /// misleading on a v3 Hello.
    #[test]
    fn ffi_hello_interface_id_v3_alias_reads_v3_slot() {
        let p = make_v3_hello_packet(7);
        assert_eq!(unsafe { lr_ospf_hello_interface_id(p) }, 7);
        // The v2-named alias reads the same byte — the two FFI
        // functions are intentional mirrors so embedders that hold
        // a v3 packet and call the v2-named accessor (e.g. legacy
        // code that has not migrated) still see the correct value.
        assert_eq!(unsafe { lr_ospf_hello_network_mask(p) }, 7);
        unsafe { crate::ospf::lr_ospf_packet_free(p) };
    }

    /// The v3 Hello body uses the 24-bit options layout (RFC 5340
    /// §A.2) — V6|R|E. The FFI surfaces the decoded `options` field
    /// so the embedder does not need to walk the wire bytes.
    #[test]
    fn ffi_hello_options_v3_returns_24bit_options() {
        let p = make_v3_hello_packet(0);
        assert_eq!(unsafe { lr_ospf_hello_options(p) }, 0x13);
        unsafe { crate::ospf::lr_ospf_packet_free(p) };
    }

    #[test]
    fn ffi_hello_readers_on_non_hello_return_zero() {
        // Build a DbDesc packet and try to read Hello fields — should
        // return 0 (no panic, no error — just zero).
        let pkt = OspfPacket {
            header: OspfHeader {
                version: 2,
                kind: OspfPacketType::DatabaseDescription as u8,
                length: 0,
                router_id: 1,
                area_id: 0,
                checksum: 0,
                au_type_or_instance: 0,
                auth_data: 0,
            },
            body: OspfBody::DbDesc(DbDescBody {
                mtu: 1500,
                options: 0,
                flags: 0x07,
                dd_seq: 42,
                lsa_headers: Vec::new(),
            }),
        };
        let p = Box::into_raw(Box::new(pkt)) as lr_ospf_packet_t;
        assert_eq!(unsafe { lr_ospf_hello_interval(p) }, 0);
        assert_eq!(unsafe { lr_ospf_db_desc_mtu(p) }, 1500);
        assert_eq!(unsafe { lr_ospf_db_desc_flags(p) }, 0x07);
        assert_eq!(unsafe { lr_ospf_db_desc_seq(p) }, 42);
        assert_eq!(unsafe { lr_ospf_db_desc_lsa_header_count(p) }, 0);
        unsafe { crate::ospf::lr_ospf_packet_free(p) };
    }

    #[test]
    fn ffi_db_desc_lsa_header_at_out_of_range() {
        let pkt = OspfPacket {
            header: OspfHeader {
                version: 2,
                kind: OspfPacketType::DatabaseDescription as u8,
                length: 0,
                router_id: 1,
                area_id: 0,
                checksum: 0,
                au_type_or_instance: 0,
                auth_data: 0,
            },
            body: OspfBody::DbDesc(DbDescBody {
                mtu: 1500,
                options: 0,
                flags: 0,
                dd_seq: 0,
                lsa_headers: Vec::new(),
            }),
        };
        let p = Box::into_raw(Box::new(pkt)) as lr_ospf_packet_t;
        let mut hdr = lr_ospf_lsa_hdr_t::default();
        assert_eq!(
            unsafe { lr_ospf_db_desc_lsa_header_at(p, 0, &raw mut hdr) },
            LR_ERR_INVALID_HANDLE
        );
        unsafe { crate::ospf::lr_ospf_packet_free(p) };
    }

    #[test]
    fn ffi_hello_readers_on_null() {
        assert_eq!(unsafe { lr_ospf_hello_interval(std::ptr::null_mut()) }, 0);
        // The v3-named alias shares the v2-named accessor's null
        // contract: a null packet returns 0 (no panic).
        assert_eq!(
            unsafe { lr_ospf_hello_interface_id(std::ptr::null_mut()) },
            0
        );
        assert_eq!(
            unsafe { lr_ospf_hello_network_mask(std::ptr::null_mut()) },
            0
        );
    }
}
