//! OSPF Router-LSA / Network-LSA origination (RFC 2328 §12.4.1, §12.4.2).
//!
//! Mirrors the public Rust API of `lr_ospf::origination`:
//! - `RouterLsaLink` (the four variants Stub / PointToPoint / Transit / Raw)
//! - `RouterLsaFlags` (V/E/B body bits)
//! - `originate_router_lsa`
//! - `originate_network_lsa`
//!
//! The `finalize_v2_packet` / `_v2_stream` / `_v3_packet` / `_v3_stream`
//! helpers already have FFI in the ospf module; this module adds the
//! LSA-origination surface.

#![allow(unused_unsafe)]
#![allow(unused_imports)]
#![allow(dead_code)]

use lr_ospf::origination::{
    originate_network_lsa, originate_router_lsa, RouterLsaFlags, RouterLsaLink,
};

use crate::error::{set_last_error, LrError, LR_ERR_PANIC};
use crate::guarded;

const LR_ERR_NULL: i32 = LrError::Null as i32;
const LR_ERR_OTHER: i32 = LrError::Other as i32;

/// Link kind constants — mirror `RouterLsaLink::*` (the four
/// variants). Used by [`lr_ospf_router_lsa_link_new`] to select the
/// variant.
pub const LR_OSPF_ROUTER_LSA_LINK_STUB: i32 = 0;
pub const LR_OSPF_ROUTER_LSA_LINK_POINT_TO_POINT: i32 = 1;
pub const LR_OSPF_ROUTER_LSA_LINK_TRANSIT: i32 = 2;
pub const LR_OSPF_ROUTER_LSA_LINK_RAW: i32 = 3;

/// Router-LSA body flag bits (RFC 2328 §A.4.2) — `V` (virtual link
/// endpoint), `E` (ASBR), `B` (ABR).
pub const LR_OSPF_ROUTER_LSA_FLAG_V: u8 = 0x04;
pub const LR_OSPF_ROUTER_LSA_FLAG_E: u8 = 0x02;
pub const LR_OSPF_ROUTER_LSA_FLAG_B: u8 = 0x01;

/// Opaque `RouterLsaLink` handle.
#[repr(C)]
pub struct OpaqueOspfRouterLsaLink {
    _private: [u8; 0],
}
pub type lr_ospf_router_lsa_link_t = *mut OpaqueOspfRouterLsaLink;

fn box_link(l: RouterLsaLink) -> lr_ospf_router_lsa_link_t {
    Box::into_raw(Box::new(l)) as lr_ospf_router_lsa_link_t
}

/// Construct one Router-LSA link entry (RFC 2328 §A.4.2). The
/// `link_kind` selects the variant; the field slots are then
/// interpreted per the variant:
///
/// - `LR_OSPF_ROUTER_LSA_LINK_STUB`: `field1` = network address,
///   `field2` = network mask, `metric` = interface cost.
/// - `LR_OSPF_ROUTER_LSA_LINK_POINT_TO_POINT`: `field1` = neighbor
///   router-id, `field2` = our interface address, `metric` = cost.
/// - `LR_OSPF_ROUTER_LSA_LINK_TRANSIT`: `field1` = DR's IP interface
///   address, `field2` = our interface address, `metric` = cost.
/// - `LR_OSPF_ROUTER_LSA_LINK_RAW`: `field1` = link_id, `field2` =
///   link_data, `metric` = cost (no interpretation; used for virtual
///   links). `field3` carries the link type byte (1=ptp, 2=transit,
///   3=stub, 4=virtual).
///
/// Returns `NULL` for an unknown `link_kind`.
#[no_mangle]
pub extern "C" fn lr_ospf_router_lsa_link_new(
    link_kind: i32,
    field1: u32,
    field2: u32,
    field3: u8,
    metric: u16,
) -> lr_ospf_router_lsa_link_t {
    guarded(
        || {
            let link = match link_kind {
                LR_OSPF_ROUTER_LSA_LINK_STUB => RouterLsaLink::Stub {
                    network: field1,
                    mask: field2,
                    metric,
                },
                LR_OSPF_ROUTER_LSA_LINK_POINT_TO_POINT => RouterLsaLink::PointToPoint {
                    neighbor: field1,
                    local_addr: field2,
                    metric,
                },
                LR_OSPF_ROUTER_LSA_LINK_TRANSIT => RouterLsaLink::Transit {
                    dr_addr: field1,
                    local_addr: field2,
                    metric,
                },
                LR_OSPF_ROUTER_LSA_LINK_RAW => {
                    use lr_ospf::lsa::{RouterLink, RouterLinkType};
                    let link_type = match field3 {
                        1 => RouterLinkType::PointToPoint,
                        2 => RouterLinkType::TransitNetwork,
                        3 => RouterLinkType::StubNetwork,
                        4 => RouterLinkType::VirtualLink,
                        _ => return std::ptr::null_mut(),
                    };
                    RouterLsaLink::Raw(RouterLink {
                        link_id: field1,
                        link_data: field2,
                        link_type: link_type as u8,
                        tos: 0,
                        metric,
                    })
                }
                _ => return std::ptr::null_mut(),
            };
            box_link(link)
        },
        std::ptr::null_mut(),
    )
}

/// Drop a boxed `RouterLsaLink`. Safe to call with `NULL`.
///
/// # Safety
/// `l` must have been produced by [`lr_ospf_router_lsa_link_new`] and
/// not already freed.
#[no_mangle]
pub unsafe extern "C" fn lr_ospf_router_lsa_link_free(l: lr_ospf_router_lsa_link_t) {
    guarded(
        || unsafe {
            if l.is_null() {
                return;
            }
            drop(unsafe { Box::from_raw(l as *mut RouterLsaLink) });
        },
        (),
    )
}

/// Originate the router's own Router-LSA for an area (RFC 2328
/// §12.4.1). The `flags_byte` carries the V/E/B bits (use the
/// `LR_OSPF_ROUTER_LSA_FLAG_*` constants, OR'd together). `links` is
/// a flat array of `RouterLsaLink` handles; `count` is the link
/// count.
///
/// `prev_seq` is the previous instance's sequence number (`NULL` to
/// start fresh at `INITIAL_SEQUENCE_NUMBER`).
///
/// Writes a freshly-allocated `lr_ospf_lsa_box_t` to `*out` on success.
/// Returns 0 on success, `LR_ERR_OTHER` (-6) when the sequence space
/// is exhausted.
///
/// # Safety
/// `links` must point to `count` valid `lr_ospf_router_lsa_link_t`
/// handles (they are borrowed, not consumed); `out` must point to
/// writable `lr_ospf_lsa_box_t`.
#[no_mangle]
pub unsafe extern "C" fn lr_ospf_originate_router_lsa(
    router_id: u32,
    flags_byte: u8,
    links: *const lr_ospf_router_lsa_link_t,
    count: usize,
    prev_seq: *const u32,
    out: *mut crate::ospf_lsdb::lr_ospf_lsa_box_t,
) -> i32 {
    guarded(
        || unsafe {
            if out.is_null() || (links.is_null() && count != 0) {
                return LR_ERR_NULL;
            }
            let slice: &[lr_ospf_router_lsa_link_t] = if count == 0 {
                &[]
            } else {
                unsafe { std::slice::from_raw_parts(links, count) }
            };
            let mut rust_links = Vec::with_capacity(count);
            for h in slice {
                if (*h).is_null() {
                    set_last_error("lr_ospf_originate_router_lsa: NULL link in array".into());
                    return LR_ERR_NULL;
                }
                let l: &RouterLsaLink = unsafe { &*(*h as *const RouterLsaLink) };
                rust_links.push(l.clone());
            }
            let flags = RouterLsaFlags {
                virtual_link: flags_byte & LR_OSPF_ROUTER_LSA_FLAG_V != 0,
                asbr: flags_byte & LR_OSPF_ROUTER_LSA_FLAG_E != 0,
                border: flags_byte & LR_OSPF_ROUTER_LSA_FLAG_B != 0,
            };
            let prev = if prev_seq.is_null() {
                None
            } else {
                Some(unsafe { *prev_seq })
            };
            match originate_router_lsa(router_id, flags, &rust_links, prev) {
                Some(lsa) => {
                    unsafe {
                        *out = crate::ospf_lsdb::box_lsa(lsa);
                    }
                    0
                }
                None => {
                    set_last_error("lr_ospf_originate_router_lsa: sequence space exhausted".into());
                    LR_ERR_OTHER
                }
            }
        },
        LR_ERR_PANIC,
    )
}

/// Originate a Network-LSA for a transit broadcast/NBMA segment where
/// this router is the DR (RFC 2328 §12.4.2). `dr_router_id` is the
/// DR's OSPF router ID (the LSA's Advertising Router); `dr_addr` is
/// the DR's IP interface address on the segment (the Link State ID);
/// `mask` is the network's address mask; `attached_routers` is the
/// list of router-IDs of every router fully adjacent to the DR,
/// **including the DR itself**.
///
/// # Safety
/// `attached_routers` must point to `count` readable `uint32_t`
/// values; `out` must point to writable `lr_ospf_lsa_box_t`.
#[no_mangle]
pub unsafe extern "C" fn lr_ospf_originate_network_lsa(
    dr_router_id: u32,
    dr_addr: u32,
    mask: u32,
    attached_routers: *const u32,
    count: usize,
    prev_seq: *const u32,
    out: *mut crate::ospf_lsdb::lr_ospf_lsa_box_t,
) -> i32 {
    guarded(
        || unsafe {
            if out.is_null() || (attached_routers.is_null() && count != 0) {
                return LR_ERR_NULL;
            }
            let slice: &[u32] = if count == 0 {
                &[]
            } else {
                unsafe { std::slice::from_raw_parts(attached_routers, count) }
            };
            let prev = if prev_seq.is_null() {
                None
            } else {
                Some(unsafe { *prev_seq })
            };
            match originate_network_lsa(dr_router_id, dr_addr, mask, slice, prev) {
                Some(lsa) => {
                    unsafe {
                        *out = crate::ospf_lsdb::box_lsa(lsa);
                    }
                    0
                }
                None => {
                    set_last_error(
                        "lr_ospf_originate_network_lsa: sequence space exhausted".into(),
                    );
                    LR_ERR_OTHER
                }
            }
        },
        LR_ERR_PANIC,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ffi_router_lsa_link_stub() {
        let l = lr_ospf_router_lsa_link_new(
            LR_OSPF_ROUTER_LSA_LINK_STUB,
            0x0a000000,
            0xff000000,
            0,
            10,
        );
        assert!(!l.is_null());
        unsafe { lr_ospf_router_lsa_link_free(l) };
    }

    #[test]
    fn ffi_router_lsa_link_point_to_point() {
        let l = lr_ospf_router_lsa_link_new(
            LR_OSPF_ROUTER_LSA_LINK_POINT_TO_POINT,
            0x01020304,
            0xC0A80101,
            0,
            5,
        );
        assert!(!l.is_null());
        unsafe { lr_ospf_router_lsa_link_free(l) };
    }

    #[test]
    fn ffi_router_lsa_link_transit() {
        let l = lr_ospf_router_lsa_link_new(
            LR_OSPF_ROUTER_LSA_LINK_TRANSIT,
            0xC0A80101,
            0xC0A80102,
            0,
            1,
        );
        assert!(!l.is_null());
        unsafe { lr_ospf_router_lsa_link_free(l) };
    }

    #[test]
    fn ffi_router_lsa_link_raw() {
        let l = lr_ospf_router_lsa_link_new(
            LR_OSPF_ROUTER_LSA_LINK_RAW,
            0x01020304,
            0xC0A80101,
            4, // virtual
            5,
        );
        assert!(!l.is_null());
        unsafe { lr_ospf_router_lsa_link_free(l) };
    }

    #[test]
    fn ffi_router_lsa_link_raw_rejects_unknown_type() {
        let l = lr_ospf_router_lsa_link_new(
            LR_OSPF_ROUTER_LSA_LINK_RAW,
            0x01020304,
            0xC0A80101,
            99, // unknown link type
            5,
        );
        assert!(l.is_null());
    }

    #[test]
    fn ffi_router_lsa_link_unknown_kind_returns_null() {
        let l = lr_ospf_router_lsa_link_new(999, 0, 0, 0, 0);
        assert!(l.is_null());
    }

    #[test]
    fn ffi_originate_router_lsa() {
        // One stub link: 10.0.0.0/8, metric 10.
        let link = lr_ospf_router_lsa_link_new(
            LR_OSPF_ROUTER_LSA_LINK_STUB,
            0x0a000000,
            0xff000000,
            0,
            10,
        );
        let links = [link];
        let mut lsa: crate::ospf_lsdb::lr_ospf_lsa_box_t = std::ptr::null_mut();
        let rc = unsafe {
            lr_ospf_originate_router_lsa(
                0x01020304,
                LR_OSPF_ROUTER_LSA_FLAG_E,
                links.as_ptr(),
                1,
                std::ptr::null(),
                &raw mut lsa,
            )
        };
        assert_eq!(rc, 0);
        assert!(!lsa.is_null());
        unsafe {
            crate::ospf_lsdb::lr_ospf_lsa_free(lsa);
            lr_ospf_router_lsa_link_free(link);
        }
    }

    #[test]
    fn ffi_originate_network_lsa() {
        let attached = [0x01020304u32, 0x05060708];
        let mut lsa: crate::ospf_lsdb::lr_ospf_lsa_box_t = std::ptr::null_mut();
        let rc = unsafe {
            lr_ospf_originate_network_lsa(
                0x01020304,
                0xC0A80101,
                0xFFFFFF00,
                attached.as_ptr(),
                2,
                std::ptr::null(),
                &raw mut lsa,
            )
        };
        assert_eq!(rc, 0);
        assert!(!lsa.is_null());
        unsafe { crate::ospf_lsdb::lr_ospf_lsa_free(lsa) };
    }

    #[test]
    fn ffi_originate_router_lsa_null_link_in_array_returns_err() {
        let links: [lr_ospf_router_lsa_link_t; 1] = [std::ptr::null_mut()];
        let mut lsa: crate::ospf_lsdb::lr_ospf_lsa_box_t = std::ptr::null_mut();
        let rc = unsafe {
            lr_ospf_originate_router_lsa(
                0x01020304,
                0,
                links.as_ptr(),
                1,
                std::ptr::null(),
                &raw mut lsa,
            )
        };
        assert_eq!(rc, LR_ERR_NULL);
    }

    #[test]
    fn ffi_free_handles_null_safely() {
        unsafe { lr_ospf_router_lsa_link_free(std::ptr::null_mut()) };
    }
}
