//! lr-osroute helper FFI surface — fills the gaps in the existing
//! `crates/lr-ffi/src/osroute.rs` module. Mirrors the stateless `pub
//! fn`s in:
//!
//! - `lr_osroute::source_check::check_source_compatibility` (RFC 7552 §6.1)
//! - `lr_osroute::tcp_bind::connect_bound`
//! - `lr_osroute::ospf_transport::{prefix_mask, ipv6_ifindex_of,
//!    ifindex_of, interface_v4_addrs, interface_v6_addrs,
//!    list_interfaces}` (Linux/BSD/Windows)
//! - `lr_osroute::mpls_route::{mpls_platform_labels, mpls_enabled}`
//! - `lr_osroute::seg6_route::seg6_enabled`
//! - `lr_osroute::bfd_transport::ttl_check_enforced`
//!
//! Every entry point runs inside the crate's `catch_unwind` barrier
//! ([`crate::guarded`]): a panic returns `LR_ERR_PANIC` and sets the
//! thread-local last-error string.

// The closure body passed to `guarded` is wrapped in a single `unsafe`
// block to mirror the `pub unsafe extern "C" fn` shape — the inner
// `unsafe { ... }` blocks would otherwise trip `unused_unsafe` under
// the crate's `-D warnings` clippy gate.
#![allow(unused_unsafe)]

use lr_core::addr::IpAddr;
use lr_osroute::ospf_transport::prefix_mask;
use lr_osroute::source_check::check_source_compatibility;

use crate::error::{set_last_error, LR_ERR_PANIC};
use crate::guarded;

const LR_ERR_NULL: i32 = -1;
const LR_ERR_OTHER: i32 = -6;

// ---- Stateless helpers (work on every platform) ----

/// The dotted-quad mask for a prefix length (RFC 2328 §A.4 — invalid
/// lengths saturate: >32 becomes /32, the wire encoder rejects them
/// earlier anyway).
#[no_mangle]
pub extern "C" fn lr_osroute_prefix_mask(prefix_len: u8) -> u32 {
    guarded(|| prefix_mask(prefix_len), 0)
}

/// Ask the kernel what source address it would use for an outbound
/// connection to `peer`, and compare it with the configured `local`
/// (RFC 7552 §6.1 — the LDP transport-address sanity check). The
/// result is written to `*out_kind`:
///
/// - 0 = `Ok` (the configured `local` is usable)
/// - 1 = `Mismatch` (the kernel would source from a different address)
/// - 2 = `BindFails` (the configured `local` is not on any interface)
/// - 3 = `NoRoute` (the kernel has no route to `peer`)
///
/// On platforms that do not implement the diagnostic (Linux today),
/// the result is `Ok` (0) — same as the Rust API.
///
/// # Safety
/// `local` must point to 4 (v4) or 16 (v6) readable bytes; `peer`
/// likewise. `out_kind` must point to a writable `uint8_t`.
#[no_mangle]
pub unsafe extern "C" fn lr_osroute_check_source_compatibility(
    local_is_v6: u8,
    local: *const u8,
    peer_is_v6: u8,
    peer: *const u8,
    out_kind: *mut u8,
) -> i32 {
    guarded(
        || unsafe {
            if local.is_null() || peer.is_null() || out_kind.is_null() {
                return LR_ERR_NULL;
            }
            let local = if local_is_v6 != 0 {
                let bytes = unsafe { core::slice::from_raw_parts(local, 16) };
                let mut arr = [0u8; 16];
                arr.copy_from_slice(bytes);
                IpAddr::V6(arr)
            } else {
                let bytes = unsafe { core::slice::from_raw_parts(local, 4) };
                let mut arr = [0u8; 4];
                arr.copy_from_slice(bytes);
                IpAddr::V4(arr)
            };
            let peer = if peer_is_v6 != 0 {
                let bytes = unsafe { core::slice::from_raw_parts(peer, 16) };
                let mut arr = [0u8; 16];
                arr.copy_from_slice(bytes);
                IpAddr::V6(arr)
            } else {
                let bytes = unsafe { core::slice::from_raw_parts(peer, 4) };
                let mut arr = [0u8; 4];
                arr.copy_from_slice(bytes);
                IpAddr::V4(arr)
            };
            let result = check_source_compatibility(local, peer);
            let kind = match result {
                lr_osroute::source_check::SourceCheck::Ok => 0u8,
                lr_osroute::source_check::SourceCheck::Mismatch { .. } => 1u8,
                lr_osroute::source_check::SourceCheck::BindFails { .. } => 2u8,
                lr_osroute::source_check::SourceCheck::NoRoute => 3u8,
            };
            unsafe { *out_kind = kind };
            0
        },
        LR_ERR_PANIC,
    )
}

// ---- Linux-gated helpers (interface enumeration, MPLS/SRv6 status) ----

// Shared type definitions — declared ONCE here so cbindgen emits a
// single typedef per type in `include/lr_ffi.h`. Both the Linux
// helpers module and the non-Linux stubs module consume these via
// `use super::*`; the previous shape (declaring the struct in BOTH
// modules) caused cbindgen to emit duplicate typedefs in the header,
// breaking every C consumer's compile.

/// One IPv4 interface address (RFC 2328 §A.3.2 — addr + prefix_len).
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct lr_osroute_interface_v4_addr_t {
    pub addr: [u8; 4],
    pub prefix_len: u8,
}

/// One IPv6 interface address (RFC 2328 §A.3.2 + RFC 5340 §A.3.2.1 —
/// addr + prefix_len + scope_id).
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct lr_osroute_interface_v6_addr_t {
    pub addr: [u8; 16],
    pub prefix_len: u8,
    pub scope_id: u32,
}

#[cfg(target_os = "linux")]
mod linux_helpers {
    use super::*;
    use lr_osroute::bfd_transport::ttl_check_enforced;
    use lr_osroute::mpls_route::mpls_enabled;
    use lr_osroute::ospf_transport::{
        ifindex_of, interface_v4_addrs, interface_v6_addrs, ipv6_ifindex_of,
    };
    use lr_osroute::seg6_route::seg6_enabled;
    use std::ffi::CStr;
    use std::os::raw::c_char;

    /// Resolve an interface name to its kernel index. Returns 0 when
    /// the interface is not found.
    ///
    /// # Safety
    /// `interface` must be a NUL-terminated UTF-8 C string.
    #[no_mangle]
    pub unsafe extern "C" fn lr_osroute_ifindex_of(interface: *const c_char) -> u32 {
        guarded(
            || unsafe {
                if interface.is_null() {
                    return 0;
                }
                let cstr = unsafe { CStr::from_ptr(interface) };
                let Ok(name) = cstr.to_str() else {
                    return 0;
                };
                ifindex_of(name).unwrap_or(0)
            },
            0,
        )
    }

    /// Resolve an interface name to its IPv6 scope id (RFC 4291 — the
    /// sin6_scope_id, may differ from the ifindex on Windows). Returns
    /// 0 when the interface is not found.
    ///
    /// # Safety
    /// `interface` must be a NUL-terminated UTF-8 C string.
    #[no_mangle]
    pub unsafe extern "C" fn lr_osroute_ipv6_ifindex_of(interface: *const c_char) -> u32 {
        guarded(
            || unsafe {
                if interface.is_null() {
                    return 0;
                }
                let cstr = unsafe { CStr::from_ptr(interface) };
                let Ok(name) = cstr.to_str() else {
                    return 0;
                };
                ipv6_ifindex_of(name).unwrap_or(0)
            },
            0,
        )
    }

    /// Enumerate every IPv4 address on `interface`. Writes the count
    /// to `*out_count` and a freshly-allocated array of
    /// `lr_osroute_interface_v4_addr_t` to `*out_array`. The caller
    /// frees the array with
    /// [`lr_osroute_interface_v4_addr_array_free`].
    ///
    /// # Safety
    /// `interface` must be a NUL-terminated UTF-8 C string. Both
    /// out-pointers must point to writable memory.
    #[no_mangle]
    pub unsafe extern "C" fn lr_osroute_interface_v4_addrs(
        interface: *const c_char,
        out_count: *mut usize,
        out_array: *mut *mut lr_osroute_interface_v4_addr_t,
    ) -> i32 {
        guarded(
            || unsafe {
                if interface.is_null() || out_count.is_null() || out_array.is_null() {
                    return LR_ERR_NULL;
                }
                let cstr = unsafe { CStr::from_ptr(interface) };
                let Ok(name) = cstr.to_str() else {
                    set_last_error("interface name is not valid UTF-8".into());
                    return LR_ERR_OTHER;
                };
                match interface_v4_addrs(name) {
                    Ok(addrs) => {
                        let n = addrs.len();
                        if n == 0 {
                            unsafe {
                                *out_count = 0;
                                *out_array = core::ptr::null_mut();
                            }
                            return 0;
                        }
                        let mut c_arr: Vec<lr_osroute_interface_v4_addr_t> = addrs
                            .into_iter()
                            .map(|a| {
                                let octets = a.addr.octets();
                                lr_osroute_interface_v4_addr_t {
                                    addr: octets,
                                    prefix_len: a.prefix_len,
                                }
                            })
                            .collect();
                        let ptr = c_arr.as_mut_ptr();
                        std::mem::forget(c_arr);
                        unsafe {
                            *out_count = n;
                            *out_array = ptr;
                        }
                        0
                    }
                    Err(e) => {
                        set_last_error(e.to_string());
                        LR_ERR_OTHER
                    }
                }
            },
            LR_ERR_PANIC,
        )
    }

    /// Free a v4 address array produced by
    /// [`lr_osroute_interface_v4_addrs`]. Safe on NULL.
    ///
    /// # Safety
    /// `arr` must have been produced by `lr_osroute_interface_v4_addrs`
    /// and not already freed; `count` must match the count returned by
    /// the enumeration call.
    #[no_mangle]
    pub unsafe extern "C" fn lr_osroute_interface_v4_addr_array_free(
        arr: *mut lr_osroute_interface_v4_addr_t,
        count: usize,
    ) {
        guarded(
            || unsafe {
                if arr.is_null() || count == 0 {
                    return;
                }
                let _ = unsafe { Vec::from_raw_parts(arr, count, count) };
            },
            (),
        )
    }

    /// Enumerate every IPv6 address on `interface`. Same shape as the
    /// v4 helper but the address is 16 bytes and the struct carries a
    /// `scope_id` (RFC 4291 — non-zero for link-local).
    ///
    /// # Safety
    /// See [`lr_osroute_interface_v4_addrs`].
    #[no_mangle]
    pub unsafe extern "C" fn lr_osroute_interface_v6_addrs(
        interface: *const c_char,
        out_count: *mut usize,
        out_array: *mut *mut lr_osroute_interface_v6_addr_t,
    ) -> i32 {
        guarded(
            || unsafe {
                if interface.is_null() || out_count.is_null() || out_array.is_null() {
                    return LR_ERR_NULL;
                }
                let cstr = unsafe { CStr::from_ptr(interface) };
                let Ok(name) = cstr.to_str() else {
                    set_last_error("interface name is not valid UTF-8".into());
                    return LR_ERR_OTHER;
                };
                match interface_v6_addrs(name) {
                    Ok(addrs) => {
                        let n = addrs.len();
                        if n == 0 {
                            unsafe {
                                *out_count = 0;
                                *out_array = core::ptr::null_mut();
                            }
                            return 0;
                        }
                        let mut c_arr: Vec<lr_osroute_interface_v6_addr_t> = addrs
                            .into_iter()
                            .map(|a| {
                                let octets = a.addr.octets();
                                lr_osroute_interface_v6_addr_t {
                                    addr: octets,
                                    prefix_len: a.prefix_len,
                                    scope_id: a.scope_id,
                                }
                            })
                            .collect();
                        let ptr = c_arr.as_mut_ptr();
                        std::mem::forget(c_arr);
                        unsafe {
                            *out_count = n;
                            *out_array = ptr;
                        }
                        0
                    }
                    Err(e) => {
                        set_last_error(e.to_string());
                        LR_ERR_OTHER
                    }
                }
            },
            LR_ERR_PANIC,
        )
    }

    /// Free a v6 address array produced by
    /// [`lr_osroute_interface_v6_addrs`]. Safe on NULL.
    ///
    /// # Safety
    /// See [`lr_osroute_interface_v4_addr_array_free`].
    #[no_mangle]
    pub unsafe extern "C" fn lr_osroute_interface_v6_addr_array_free(
        arr: *mut lr_osroute_interface_v6_addr_t,
        count: usize,
    ) {
        guarded(
            || unsafe {
                if arr.is_null() || count == 0 {
                    return;
                }
                let _ = unsafe { Vec::from_raw_parts(arr, count, count) };
            },
            (),
        )
    }

    /// True when the kernel has MPLS routing enabled
    /// (`/proc/sys/net/mpls/platform_labels` is non-zero).
    #[no_mangle]
    pub extern "C" fn lr_osroute_mpls_enabled() -> u8 {
        guarded(|| mpls_enabled() as u8, 0)
    }

    /// True when the kernel has SRv6 (segment routing) enabled.
    #[no_mangle]
    pub extern "C" fn lr_osroute_seg6_enabled() -> u8 {
        guarded(|| seg6_enabled() as u8, 0)
    }

    /// True when the BFD receive-side TTL check is enforced by the
    /// platform (RFC 5881 §5 — Linux yes, BSD/macOS/Windows no).
    #[no_mangle]
    pub extern "C" fn lr_osroute_ttl_check_enforced() -> u8 {
        guarded(|| ttl_check_enforced() as u8, 0)
    }
}

#[cfg(target_os = "linux")]
pub use linux_helpers::*;

// ---- Non-Linux stubs: every Linux-only function returns 0 / NULL
// (mirrors lr_osroute::stub::StubRouteTable). ----
#[cfg(not(target_os = "linux"))]
mod non_linux_stubs {
    use std::os::raw::c_char;

    #[no_mangle]
    pub unsafe extern "C" fn lr_osroute_ifindex_of(_interface: *const c_char) -> u32 {
        0
    }

    #[no_mangle]
    pub unsafe extern "C" fn lr_osroute_ipv6_ifindex_of(_interface: *const c_char) -> u32 {
        0
    }

    #[no_mangle]
    pub unsafe extern "C" fn lr_osroute_interface_v4_addrs(
        _interface: *const c_char,
        out_count: *mut usize,
        out_array: *mut *mut lr_osroute_interface_v4_addr_t,
    ) -> i32 {
        unsafe {
            *out_count = 0;
            *out_array = core::ptr::null_mut();
        }
        0
    }

    #[no_mangle]
    pub unsafe extern "C" fn lr_osroute_interface_v4_addr_array_free(
        _arr: *mut lr_osroute_interface_v4_addr_t,
        _count: usize,
    ) {
    }

    #[no_mangle]
    pub unsafe extern "C" fn lr_osroute_interface_v6_addrs(
        _interface: *const c_char,
        out_count: *mut usize,
        out_array: *mut *mut lr_osroute_interface_v6_addr_t,
    ) -> i32 {
        unsafe {
            *out_count = 0;
            *out_array = core::ptr::null_mut();
        }
        0
    }

    #[no_mangle]
    pub unsafe extern "C" fn lr_osroute_interface_v6_addr_array_free(
        _arr: *mut lr_osroute_interface_v6_addr_t,
        _count: usize,
    ) {
    }

    #[no_mangle]
    pub extern "C" fn lr_osroute_mpls_enabled() -> u8 {
        0
    }

    #[no_mangle]
    pub extern "C" fn lr_osroute_seg6_enabled() -> u8 {
        0
    }

    #[no_mangle]
    pub extern "C" fn lr_osroute_ttl_check_enforced() -> u8 {
        0
    }
}

#[cfg(not(target_os = "linux"))]
pub use non_linux_stubs::*;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ffi_prefix_mask_round_trips() {
        assert_eq!(lr_osroute_prefix_mask(24), 0xffff_ff00);
        assert_eq!(lr_osroute_prefix_mask(0), 0);
        assert_eq!(lr_osroute_prefix_mask(32), 0xffff_ffff);
    }

    #[test]
    fn ffi_check_source_compatibility_returns_ok_on_non_windows() {
        let local = [10u8, 0, 0, 1];
        let peer = [10u8, 0, 0, 2];
        let mut kind = 99u8;
        let rc = unsafe {
            lr_osroute_check_source_compatibility(
                0,
                local.as_ptr(),
                0,
                peer.as_ptr(),
                &raw mut kind,
            )
        };
        assert_eq!(rc, 0);
        // On Linux the diagnostic is a no-op that returns Ok (0).
        assert_eq!(kind, 0);
    }

    #[test]
    fn ffi_null_handle_returns_err_null() {
        let rc = unsafe {
            lr_osroute_check_source_compatibility(
                0,
                std::ptr::null(),
                0,
                std::ptr::null(),
                std::ptr::null_mut(),
            )
        };
        assert_eq!(rc, LR_ERR_NULL);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn ffi_ifindex_of_unknown_interface_returns_zero() {
        let name = std::ffi::CString::new("nonexistent_iface_2847").unwrap();
        let idx = unsafe { lr_osroute_ifindex_of(name.as_ptr()) };
        assert_eq!(idx, 0);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn ffi_ipv6_ifindex_of_unknown_interface_returns_zero() {
        let name = std::ffi::CString::new("nonexistent_iface_2847").unwrap();
        let idx = unsafe { lr_osroute_ipv6_ifindex_of(name.as_ptr()) };
        assert_eq!(idx, 0);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn ffi_interface_v4_addrs_lo_is_present() {
        let name = std::ffi::CString::new("lo").unwrap();
        let mut count = 0usize;
        let mut arr: *mut lr_osroute_interface_v4_addr_t = std::ptr::null_mut();
        let rc =
            unsafe { lr_osroute_interface_v4_addrs(name.as_ptr(), &raw mut count, &raw mut arr) };
        // The `lo` interface exists on every Linux host; it carries
        // 127.0.0.1/8 by default. If getifaddrs failed for some
        // reason we get rc != 0 — assert that didn't happen, then free
        // the array regardless.
        assert_eq!(rc, 0, "lr_osroute_interface_v4_addrs should succeed on lo");
        if !arr.is_null() && count > 0 {
            unsafe { lr_osroute_interface_v4_addr_array_free(arr, count) };
        }
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn ffi_non_linux_stubs_return_zero() {
        assert_eq!(lr_osroute_mpls_enabled(), 0);
        assert_eq!(lr_osroute_seg6_enabled(), 0);
        assert_eq!(lr_osroute_ttl_check_enforced(), 0);
    }
}
