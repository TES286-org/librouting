//! Foundational utilities FFI — `lr_core_*` exposes the smaller helpers
//! in `lr_core::addr`, `lr_core::nlri`, `lr_core::util` that round out
//! the C ABI coverage of `lr_core`'s public Rust API.

// The closure body passed to `guarded` is wrapped in a single `unsafe`
// block to mirror the `pub unsafe extern "C" fn` shape.
#![allow(unused_unsafe)]

use lr_core::addr::IpAddr;
use lr_core::nlri::NlriFamily;
use lr_core::util::{crc, fletcher};

use crate::error::LR_ERR_PANIC;
use crate::guarded;

const LR_ERR_NULL: i32 = crate::error::LrError::Null as i32;

// ---- IpAddr byte-form constructors ----

/// Construct an `IpAddr::V4` from 4 bytes. Returns NULL on a NULL pointer.
///
/// # Safety
/// `bytes` must point to 4 readable bytes.
#[no_mangle]
pub unsafe extern "C" fn lr_ip_addr_from_v4_bytes(bytes: *const u8) -> *mut lr_core::addr::IpAddr {
    guarded(
        || unsafe {
            if bytes.is_null() {
                return std::ptr::null_mut();
            }
            let mut b = [0u8; 4];
            std::ptr::copy_nonoverlapping(bytes, b.as_mut_ptr(), 4);
            Box::into_raw(Box::new(IpAddr::from_v4_bytes(b)))
        },
        std::ptr::null_mut(),
    )
}

/// Construct an `IpAddr::V6` from 16 bytes.
///
/// # Safety
/// `bytes` must point to 16 readable bytes.
#[no_mangle]
pub unsafe extern "C" fn lr_ip_addr_from_v6_bytes(bytes: *const u8) -> *mut lr_core::addr::IpAddr {
    guarded(
        || unsafe {
            if bytes.is_null() {
                return std::ptr::null_mut();
            }
            let mut b = [0u8; 16];
            std::ptr::copy_nonoverlapping(bytes, b.as_mut_ptr(), 16);
            Box::into_raw(Box::new(IpAddr::from_v6_bytes(b)))
        },
        std::ptr::null_mut(),
    )
}

/// Construct an `IpAddr` from a variable-length byte slice. Returns
/// NULL on a NULL pointer, or when the length is not 4 or 16.
///
/// # Safety
/// `bytes` must point to `len` readable bytes.
#[no_mangle]
pub unsafe extern "C" fn lr_ip_addr_from_bytes(
    bytes: *const u8,
    len: usize,
) -> *mut lr_core::addr::IpAddr {
    guarded(
        || unsafe {
            if bytes.is_null() {
                return std::ptr::null_mut();
            }
            let slice = unsafe { std::slice::from_raw_parts(bytes, len) };
            match IpAddr::from_bytes(slice) {
                Some(a) => Box::into_raw(Box::new(a)),
                None => std::ptr::null_mut(),
            }
        },
        std::ptr::null_mut(),
    )
}

/// Drop a boxed `IpAddr`. Safe to call with NULL.
///
/// # Safety
/// `a` must have been produced by [`lr_ip_addr_from_v4_bytes`] /
/// [`lr_ip_addr_from_v6_bytes`] / [`lr_ip_addr_from_bytes`] and not
/// already freed.
#[no_mangle]
pub unsafe extern "C" fn lr_ip_addr_free(a: *mut lr_core::addr::IpAddr) {
    guarded(
        || unsafe {
            if a.is_null() {
                return;
            }
            drop(Box::from_raw(a));
        },
        (),
    )
}

/// True when `a` is an IPv4-mapped IPv6 address (RFC 4291 §2.5.5.2):
/// `::ffff:a.b.c.d`. Returns 0 on a NULL handle.
///
/// # Safety
/// `a` must be a valid handle.
#[no_mangle]
pub unsafe extern "C" fn lr_ip_addr_is_ipv4_mapped_ipv6(a: *const lr_core::addr::IpAddr) -> u8 {
    guarded(
        || unsafe {
            if a.is_null() {
                return 0;
            }
            let addr = unsafe { &*a };
            addr.is_ipv4_mapped_ipv6() as u8
        },
        0,
    )
}

/// Convert an IPv4 address to its IPv4-mapped IPv6 form
/// (RFC 4291 §2.5.5.2: `::ffff:a.b.c.d`). The Rust API is named
/// `IpAddr::to_ipv4_mapped` and only converts V4 → V6-mapped.
///
/// Returns a freshly-allocated `IpAddr` (V6 form) when the input is
/// V4; returns NULL when the input is already V6 (the conversion is
/// a no-op, so no fresh allocation is needed), and on a NULL handle.
///
/// # Safety
/// `a` must be a valid handle.
#[no_mangle]
pub unsafe extern "C" fn lr_ip_addr_to_ipv4_mapped(
    a: *const lr_core::addr::IpAddr,
) -> *mut lr_core::addr::IpAddr {
    guarded(
        || unsafe {
            if a.is_null() {
                return std::ptr::null_mut();
            }
            let addr = unsafe { &*a };
            let mapped = addr.to_ipv4_mapped();
            if mapped == *addr {
                std::ptr::null_mut()
            } else {
                Box::into_raw(Box::new(mapped))
            }
        },
        std::ptr::null_mut(),
    )
}

// ---- Asn readers ----

/// Read the 32-bit AS value.
#[no_mangle]
pub extern "C" fn lr_asn_as_u32(asn: u32) -> u32 {
    guarded(|| lr_core::addr::Asn(asn).as_u32(), 0)
}

/// Read the 16-bit AS value, or 0 when the value does not fit in 16
/// bits (RFC 4893 AS_TRANS upgrade path).
#[no_mangle]
pub extern "C" fn lr_asn_as_u16(asn: u32) -> u16 {
    guarded(|| lr_core::addr::Asn(asn).as_u16().unwrap_or(0), 0)
}

// ---- NlriFamily ----

/// `lr_afi_safi_t` alias — the FFI view of `lr_core::nlri::NlriFamily`.
pub use crate::bgp_codec::lr_afi_safi_t as lr_nlri_family_t;

/// `NlriFamily::IPV4_UNICAST` = (afi=1, safi=1).
#[no_mangle]
pub extern "C" fn lr_nlri_family_ipv4_unicast() -> lr_nlri_family_t {
    lr_nlri_family_t { afi: 1, safi: 1 }
}

/// `NlriFamily::IPV6_UNICAST` = (afi=2, safi=1).
#[no_mangle]
pub extern "C" fn lr_nlri_family_ipv6_unicast() -> lr_nlri_family_t {
    lr_nlri_family_t { afi: 2, safi: 1 }
}

/// `NlriFamily::IPV4_MULTICAST` = (afi=1, safi=2).
#[no_mangle]
pub extern "C" fn lr_nlri_family_ipv4_multicast() -> lr_nlri_family_t {
    lr_nlri_family_t { afi: 1, safi: 2 }
}

/// `NlriFamily::IPV4_MPLS_VPN` = (afi=1, safi=128).
#[no_mangle]
pub extern "C" fn lr_nlri_family_ipv4_mpls_vpn() -> lr_nlri_family_t {
    lr_nlri_family_t { afi: 1, safi: 128 }
}

/// `NlriFamily::IPV6_MPLS_VPN` = (afi=2, safi=128).
#[no_mangle]
pub extern "C" fn lr_nlri_family_ipv6_mpls_vpn() -> lr_nlri_family_t {
    lr_nlri_family_t { afi: 2, safi: 128 }
}

/// `NlriFamily::IPV4_LABELED_UNICAST` = (afi=1, safi=4) (RFC 8277).
#[no_mangle]
pub extern "C" fn lr_nlri_family_ipv4_labeled_unicast() -> lr_nlri_family_t {
    lr_nlri_family_t { afi: 1, safi: 4 }
}

/// `NlriFamily::IPV6_LABELED_UNICAST` = (afi=2, safi=4) (RFC 8277).
#[no_mangle]
pub extern "C" fn lr_nlri_family_ipv6_labeled_unicast() -> lr_nlri_family_t {
    lr_nlri_family_t { afi: 2, safi: 4 }
}

/// `NlriFamily::BGP_LS` = (afi=16388, safi=71) (RFC 7752).
#[no_mangle]
pub extern "C" fn lr_nlri_family_bgp_ls() -> lr_nlri_family_t {
    lr_nlri_family_t {
        afi: 16388,
        safi: 71,
    }
}

/// `NlriFamily::BGP_LS_VPN` = (afi=16388, safi=72) (RFC 7752 §3).
#[no_mangle]
pub extern "C" fn lr_nlri_family_bgp_ls_vpn() -> lr_nlri_family_t {
    lr_nlri_family_t {
        afi: 16388,
        safi: 72,
    }
}

/// True when the family is IPv4 (afi=1).
#[no_mangle]
pub extern "C" fn lr_nlri_family_is_ipv4(f: lr_nlri_family_t) -> u8 {
    guarded(
        || {
            let fam = NlriFamily {
                afi: f.afi,
                safi: f.safi,
            };
            fam.is_ipv4() as u8
        },
        0,
    )
}

/// True when the family is IPv6 (afi=2).
#[no_mangle]
pub extern "C" fn lr_nlri_family_is_ipv6(f: lr_nlri_family_t) -> u8 {
    guarded(
        || {
            let fam = NlriFamily {
                afi: f.afi,
                safi: f.safi,
            };
            fam.is_ipv6() as u8
        },
        0,
    )
}

/// True when the family is labeled unicast (RFC 8277).
#[no_mangle]
pub extern "C" fn lr_nlri_family_is_labeled_unicast(f: lr_nlri_family_t) -> u8 {
    guarded(
        || {
            let fam = NlriFamily {
                afi: f.afi,
                safi: f.safi,
            };
            fam.is_labeled_unicast() as u8
        },
        0,
    )
}

/// True when the family is BGP-LS (RFC 7752).
#[no_mangle]
pub extern "C" fn lr_nlri_family_is_bgp_ls(f: lr_nlri_family_t) -> u8 {
    guarded(
        || {
            let fam = NlriFamily {
                afi: f.afi,
                safi: f.safi,
            };
            fam.is_bgp_ls() as u8
        },
        0,
    )
}

/// True when the family is BGP-LS VPN (RFC 7752 §3).
#[no_mangle]
pub extern "C" fn lr_nlri_family_is_bgp_ls_vpn(f: lr_nlri_family_t) -> u8 {
    guarded(
        || {
            let fam = NlriFamily {
                afi: f.afi,
                safi: f.safi,
            };
            fam.is_bgp_ls_vpn() as u8
        },
        0,
    )
}

/// Derive the `NlriFamily` for an `IpAddr` — V4 → (1, 1), V6 → (2, 1).
///
/// # Safety
/// `addr` must be a valid `*mut IpAddr`. `out` must be writable.
#[no_mangle]
pub unsafe extern "C" fn lr_nlri_family_from_addr(
    addr: *const lr_core::addr::IpAddr,
    out: *mut lr_nlri_family_t,
) -> i32 {
    guarded(
        || unsafe {
            if addr.is_null() || out.is_null() {
                return LR_ERR_NULL;
            }
            let a = unsafe { &*addr };
            let fam = NlriFamily::from_addr(a);
            unsafe {
                *out = lr_nlri_family_t {
                    afi: fam.afi,
                    safi: fam.safi,
                };
            }
            0
        },
        LR_ERR_PANIC,
    )
}

// ---- CRC / Fletcher ----

/// CRC-16/ARC (RFC 1952) over `bytes`. Returns the 16-bit checksum.
///
/// # Safety
/// `bytes` must point to `len` readable bytes.
#[no_mangle]
pub unsafe extern "C" fn lr_crc16_arc(bytes: *const u8, len: usize) -> u16 {
    guarded(
        || unsafe {
            if bytes.is_null() {
                return 0;
            }
            let slice = unsafe { std::slice::from_raw_parts(bytes, len) };
            crc::crc16_arc(slice)
        },
        0,
    )
}

/// CRC-32C / Castagnoli (RFC 3748) over `bytes`. Returns the 32-bit
/// checksum.
///
/// # Safety
/// See [`lr_crc16_arc`].
#[no_mangle]
pub unsafe extern "C" fn lr_crc32c(bytes: *const u8, len: usize) -> u32 {
    guarded(
        || unsafe {
            if bytes.is_null() {
                return 0;
            }
            let slice = unsafe { std::slice::from_raw_parts(bytes, len) };
            crc::crc32c(slice)
        },
        0,
    )
}

/// RFC 2328 §C.4 LSA checksum (Fletcher-16 over the LSA body, with
/// the two checksum bytes at offsets 16-17 of the LSA zeroed during
/// computation). Returns the 16-bit checksum value that would be
/// stored at offset 16-17.
///
/// # Safety
/// `lsa` must point to `len` readable bytes. The LSA must be at least
/// 20 bytes long (the LSA header); shorter inputs return 0.
#[no_mangle]
pub unsafe extern "C" fn lr_ospf_lsa_checksum(lsa: *const u8, len: usize) -> u16 {
    guarded(
        || unsafe {
            if lsa.is_null() {
                return 0;
            }
            let slice = unsafe { std::slice::from_raw_parts(lsa, len) };
            fletcher::ospf_lsa_checksum(slice)
        },
        0,
    )
}

/// True when the LSA's embedded checksum (offset 16-17) matches the
/// computed Fletcher-16 over the body.
///
/// # Safety
/// See [`lr_ospf_lsa_checksum`].
#[no_mangle]
pub unsafe extern "C" fn lr_ospf_lsa_checksum_ok(lsa: *const u8, len: usize) -> u8 {
    guarded(
        || unsafe {
            if lsa.is_null() {
                return 0;
            }
            let slice = unsafe { std::slice::from_raw_parts(lsa, len) };
            fletcher::ospf_lsa_checksum_ok(slice) as u8
        },
        0,
    )
}

/// Generic Fletcher-32 over `bytes` (RFC 2328 §C.4 / RFC 905 §A.3).
///
/// # Safety
/// See [`lr_crc16_arc`].
#[no_mangle]
pub unsafe extern "C" fn lr_fletcher32(bytes: *const u8, len: usize) -> u32 {
    guarded(
        || unsafe {
            if bytes.is_null() {
                return 0;
            }
            let slice = unsafe { std::slice::from_raw_parts(bytes, len) };
            fletcher::fletcher32(slice)
        },
        0,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ffi_ip_addr_from_v4_bytes_round_trip() {
        let bytes = [10u8, 0, 0, 1];
        let a = unsafe { lr_ip_addr_from_v4_bytes(bytes.as_ptr()) };
        assert!(!a.is_null());
        let addr = unsafe { &*a };
        assert!(matches!(addr, IpAddr::V4([10, 0, 0, 1])));
        unsafe { lr_ip_addr_free(a as *mut _) };
    }

    #[test]
    fn ffi_ip_addr_from_v6_bytes_round_trip() {
        let bytes = [0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let a = unsafe { lr_ip_addr_from_v6_bytes(bytes.as_ptr()) };
        assert!(!a.is_null());
        let addr = unsafe { &*a };
        assert!(matches!(addr, IpAddr::V6(_)));
        unsafe { lr_ip_addr_free(a as *mut _) };
    }

    #[test]
    fn ffi_ip_addr_from_bytes_rejects_wrong_length() {
        let bytes = [0u8; 5];
        let a = unsafe { lr_ip_addr_from_bytes(bytes.as_ptr(), 5) };
        assert!(a.is_null());
    }

    #[test]
    fn ffi_ip_addr_is_ipv4_mapped_ipv6() {
        let mapped = [0u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 10, 0, 0, 1];
        let a = unsafe { lr_ip_addr_from_v6_bytes(mapped.as_ptr()) };
        assert_eq!(unsafe { lr_ip_addr_is_ipv4_mapped_ipv6(a) }, 1);
        let bytes = [10u8, 0, 0, 1];
        let b = unsafe { lr_ip_addr_from_v4_bytes(bytes.as_ptr()) };
        assert_eq!(unsafe { lr_ip_addr_is_ipv4_mapped_ipv6(b) }, 0);
        unsafe {
            lr_ip_addr_free(a as *mut _);
            lr_ip_addr_free(b as *mut _);
        }
    }

    #[test]
    fn ffi_ip_addr_to_ipv4_mapped_v4_to_v6() {
        let bytes = [10u8, 0, 0, 1];
        let a = unsafe { lr_ip_addr_from_v4_bytes(bytes.as_ptr()) };
        let mapped = unsafe { lr_ip_addr_to_ipv4_mapped(a) };
        assert!(
            !mapped.is_null(),
            "V4 input must produce a V6-mapped output"
        );
        let addr = unsafe { &*mapped };
        match addr {
            IpAddr::V6(b) => {
                assert_eq!(b[10..12], [0xff, 0xff]);
                assert_eq!(b[12..16], [10, 0, 0, 1]);
            }
            _ => panic!("expected V6 mapped form, got V4"),
        }
        unsafe {
            lr_ip_addr_free(a as *mut _);
            lr_ip_addr_free(mapped as *mut _);
        }
    }

    #[test]
    fn ffi_ip_addr_to_ipv4_mapped_returns_null_for_v6() {
        let bytes = [0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let a = unsafe { lr_ip_addr_from_v6_bytes(bytes.as_ptr()) };
        assert_eq!(
            unsafe { lr_ip_addr_to_ipv4_mapped(a) },
            std::ptr::null_mut()
        );
        unsafe { lr_ip_addr_free(a as *mut _) };
    }

    #[test]
    fn ffi_ip_addr_free_null_safe() {
        unsafe { lr_ip_addr_free(std::ptr::null_mut()) };
    }

    #[test]
    fn ffi_asn_readers() {
        assert_eq!(lr_asn_as_u32(64512), 64512);
        assert_eq!(lr_asn_as_u16(64512), 64512);
        assert_eq!(lr_asn_as_u16(0x10000), 0);
    }

    #[test]
    fn ffi_nlri_family_constants() {
        assert_eq!(lr_nlri_family_ipv4_unicast().afi, 1);
        assert_eq!(lr_nlri_family_ipv4_unicast().safi, 1);
        assert_eq!(lr_nlri_family_ipv6_unicast().afi, 2);
        assert_eq!(lr_nlri_family_ipv4_mpls_vpn().safi, 128);
        assert_eq!(lr_nlri_family_ipv4_labeled_unicast().safi, 4);
        assert_eq!(lr_nlri_family_bgp_ls().afi, 16388);
        assert_eq!(lr_nlri_family_bgp_ls().safi, 71);
        assert_eq!(lr_nlri_family_bgp_ls_vpn().safi, 72);
    }

    #[test]
    fn ffi_nlri_family_predicates() {
        let v4 = lr_nlri_family_ipv4_unicast();
        assert_eq!(lr_nlri_family_is_ipv4(v4), 1);
        assert_eq!(lr_nlri_family_is_ipv6(v4), 0);
        let v6 = lr_nlri_family_ipv6_unicast();
        assert_eq!(lr_nlri_family_is_ipv6(v6), 1);
        let lu = lr_nlri_family_ipv4_labeled_unicast();
        assert_eq!(lr_nlri_family_is_labeled_unicast(lu), 1);
        let ls = lr_nlri_family_bgp_ls();
        assert_eq!(lr_nlri_family_is_bgp_ls(ls), 1);
        let lsv = lr_nlri_family_bgp_ls_vpn();
        assert_eq!(lr_nlri_family_is_bgp_ls_vpn(lsv), 1);
    }

    #[test]
    fn ffi_nlri_family_from_addr_v4() {
        let bytes = [10u8, 0, 0, 1];
        let a = unsafe { lr_ip_addr_from_v4_bytes(bytes.as_ptr()) };
        let mut fam = lr_nlri_family_t { afi: 0, safi: 0 };
        let rc = unsafe { lr_nlri_family_from_addr(a, &mut fam) };
        assert_eq!(rc, 0);
        assert_eq!(fam.afi, 1);
        assert_eq!(fam.safi, 1);
        unsafe { lr_ip_addr_free(a as *mut _) };
    }

    #[test]
    fn ffi_nlri_family_from_addr_v6() {
        let bytes = [0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let a = unsafe { lr_ip_addr_from_v6_bytes(bytes.as_ptr()) };
        let mut fam = lr_nlri_family_t { afi: 0, safi: 0 };
        let rc = unsafe { lr_nlri_family_from_addr(a, &mut fam) };
        assert_eq!(rc, 0);
        assert_eq!(fam.afi, 2);
        assert_eq!(fam.safi, 1);
        unsafe { lr_ip_addr_free(a as *mut _) };
    }

    #[test]
    fn ffi_crc16_arc_known_value() {
        let s = b"123456789";
        assert_eq!(unsafe { lr_crc16_arc(s.as_ptr(), s.len()) }, 0xBB3D);
    }

    #[test]
    fn ffi_crc32c_known_value() {
        let s = b"123456789";
        assert_eq!(unsafe { lr_crc32c(s.as_ptr(), s.len()) }, 0xE3069283);
    }

    #[test]
    fn ffi_crc_null_returns_zero() {
        assert_eq!(unsafe { lr_crc16_arc(std::ptr::null(), 0) }, 0);
        assert_eq!(unsafe { lr_crc32c(std::ptr::null(), 0) }, 0);
    }

    #[test]
    fn ffi_fletcher32_known_value() {
        let s = b"abcdefgh";
        let v1 = unsafe { lr_fletcher32(s.as_ptr(), s.len()) };
        let v2 = unsafe { lr_fletcher32(s.as_ptr(), s.len()) };
        assert_eq!(v1, v2);
        assert_ne!(v1, 0);
    }

    #[test]
    fn ffi_ospf_lsa_checksum_round_trip() {
        let mut lsa = [0u8; 24];
        lsa[0] = 1; // options
        lsa[1] = 1; // ls_type = Router-LSA
        lsa[20] = 0x12;
        lsa[21] = 0x34;
        lsa[22] = 0x56;
        lsa[23] = 0x78;
        let cs = unsafe { lr_ospf_lsa_checksum(lsa.as_ptr(), lsa.len()) };
        lsa[16] = (cs >> 8) as u8;
        lsa[17] = (cs & 0xff) as u8;
        assert_eq!(
            unsafe { lr_ospf_lsa_checksum_ok(lsa.as_ptr(), lsa.len()) },
            1
        );
    }

    #[test]
    fn ffi_ospf_lsa_checksum_null_returns_zero() {
        assert_eq!(unsafe { lr_ospf_lsa_checksum(std::ptr::null(), 0) }, 0);
        assert_eq!(unsafe { lr_ospf_lsa_checksum_ok(std::ptr::null(), 0) }, 0);
    }
}
