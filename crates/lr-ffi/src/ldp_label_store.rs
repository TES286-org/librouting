//! LDP label-mapping store FFI — `lr_ldp_label_store_*`.
//!
//! Mirrors the public Rust API of `lr_ldp::mapping::LabelMappingStore`
//! (RFC 5036 §3.5.7 — the label information base that tracks learned
//! peer→FEC→label bindings + the locally-advertised bindings). The
//! store was previously only reachable through the daemon's
//! DefaultRouter; this module exposes the standalone shape so an
//! embedder can manage the LIB without going through the router.
//!
//! Every entry point runs inside the crate's `catch_unwind` barrier
//! ([`crate::guarded`]): a panic returns `LR_ERR_PANIC` and sets the
//! thread-local last-error string.

#![allow(unused_unsafe)]

use lr_core::addr::Prefix;
use lr_ldp::mapping::{FecKey, LabelMappingStore};
use lr_ldp::pdu::LdpId;
use lr_ldp::tlv::GenericLabel;

use crate::guarded;

/// Opaque `LabelMappingStore` handle.
#[repr(C)]
pub struct OpaqueLdpLabelStore {
    _private: [u8; 0],
}
pub type lr_ldp_label_store_t = *mut OpaqueLdpLabelStore;

fn box_store(s: LabelMappingStore) -> lr_ldp_label_store_t {
    Box::into_raw(Box::new(s)) as lr_ldp_label_store_t
}
unsafe fn borrow_store(s: lr_ldp_label_store_t) -> Option<&'static LabelMappingStore> {
    if s.is_null() {
        return None;
    }
    Some(unsafe { &*(s as *const LabelMappingStore) })
}
unsafe fn borrow_store_mut(s: lr_ldp_label_store_t) -> Option<&'static mut LabelMappingStore> {
    if s.is_null() {
        return None;
    }
    Some(unsafe { &mut *(s as *mut LabelMappingStore) })
}
unsafe fn unbox_store(s: lr_ldp_label_store_t) -> Option<Box<LabelMappingStore>> {
    if s.is_null() {
        return None;
    }
    Some(unsafe { Box::from_raw(s as *mut LabelMappingStore) })
}

unsafe fn build_prefix(addr: *const u8, is_ipv6: u8, prefix_len: u8) -> Prefix {
    if is_ipv6 == 0 {
        let mut o = [0u8; 4];
        unsafe { o.copy_from_slice(std::slice::from_raw_parts(addr, 4)) };
        Prefix::new_v4(o, prefix_len)
    } else {
        let mut o = [0u8; 16];
        unsafe { o.copy_from_slice(std::slice::from_raw_parts(addr, 16)) };
        Prefix::new_v6(o, prefix_len)
    }
}

#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct lr_ldp_prefix_t {
    pub addr_v4: [u8; 16],
    pub addr_v6: [u8; 16],
    pub is_ipv6: u8,
    pub prefix_len: u8,
}

// ---- LabelMappingStore surface ----

/// Construct an empty `LabelMappingStore`.
#[no_mangle]
pub extern "C" fn lr_ldp_label_store_new() -> lr_ldp_label_store_t {
    guarded(|| box_store(LabelMappingStore::new()), std::ptr::null_mut())
}

/// Drop a boxed `LabelMappingStore`. Safe to call with NULL.
///
/// # Safety
/// `s` must have been produced by `lr_ldp_label_store_new` and not
/// already freed.
#[no_mangle]
pub unsafe extern "C" fn lr_ldp_label_store_free(s: lr_ldp_label_store_t) {
    guarded(
        || unsafe {
            drop(unbox_store(s));
        },
        (),
    )
}

/// Learn a peer's label binding for a FEC (RFC 5036 §3.5.7). Returns
/// 1 when the binding is new or differs from the previous value, 0
/// when it duplicates the existing one.
///
/// `peer_lsr_id` is the peer's LSR ID (4 bytes); `peer_label_space`
/// is the 16-bit label space; `prefix_addr` / `is_ipv6` /
/// `prefix_len` carry the FEC's prefix; `label` is the learned
/// 20-bit label value.
///
/// # Safety
/// `s` must be a valid store handle. `prefix_addr` must point to 4
/// (v4) or 16 (v6) readable bytes.
#[no_mangle]
pub unsafe extern "C" fn lr_ldp_label_store_learn(
    s: lr_ldp_label_store_t,
    peer_lsr_id: u32,
    peer_label_space: u16,
    prefix_addr: *const u8,
    is_ipv6: u8,
    prefix_len: u8,
    label: u32,
) -> u8 {
    guarded(
        || unsafe {
            let Some(store) = borrow_store_mut(s) else {
                return 0;
            };
            if prefix_addr.is_null() {
                return 0;
            }
            let peer = LdpId::new(peer_lsr_id.to_be_bytes(), peer_label_space);
            let key = FecKey::new(build_prefix(prefix_addr, is_ipv6, prefix_len));
            store.learn(peer, key, GenericLabel(label)) as u8
        },
        0,
    )
}

/// Unlearn a peer's binding for a FEC (RFC 5036 §3.5.7 — label
/// release). Returns 1 and writes the released label to
/// `*out_label` when a binding existed, 0 otherwise.
///
/// # Safety
/// See [`lr_ldp_label_store_learn`]. `out_label` may be NULL when
/// the caller does not need the released value.
#[no_mangle]
pub unsafe extern "C" fn lr_ldp_label_store_unlearn(
    s: lr_ldp_label_store_t,
    peer_lsr_id: u32,
    peer_label_space: u16,
    prefix_addr: *const u8,
    is_ipv6: u8,
    prefix_len: u8,
    out_label: *mut u32,
) -> u8 {
    guarded(
        || unsafe {
            let Some(store) = borrow_store_mut(s) else {
                return 0;
            };
            if prefix_addr.is_null() {
                return 0;
            }
            let peer = LdpId::new(peer_lsr_id.to_be_bytes(), peer_label_space);
            let key = FecKey::new(build_prefix(prefix_addr, is_ipv6, prefix_len));
            match store.unlearn(peer, &key) {
                Some(label) => {
                    if !out_label.is_null() {
                        unsafe { *out_label = label.0 };
                    }
                    1
                }
                None => 0,
            }
        },
        0,
    )
}

/// Read the label binding a peer advertised for a FEC. Returns 1 and
/// writes the label to `*out_label` when present, 0 otherwise.
///
/// # Safety
/// See [`lr_ldp_label_store_learn`].
#[no_mangle]
pub unsafe extern "C" fn lr_ldp_label_store_label_from(
    s: lr_ldp_label_store_t,
    peer_lsr_id: u32,
    peer_label_space: u16,
    prefix_addr: *const u8,
    is_ipv6: u8,
    prefix_len: u8,
    out_label: *mut u32,
) -> u8 {
    guarded(
        || unsafe {
            let Some(store) = borrow_store(s) else {
                return 0;
            };
            if prefix_addr.is_null() || out_label.is_null() {
                return 0;
            }
            let peer = LdpId::new(peer_lsr_id.to_be_bytes(), peer_label_space);
            let key = FecKey::new(build_prefix(prefix_addr, is_ipv6, prefix_len));
            match store.label_from(peer, &key) {
                Some(label) => {
                    unsafe { *out_label = label.0 };
                    1
                }
                None => 0,
            }
        },
        0,
    )
}

#[no_mangle]
pub unsafe extern "C" fn lr_ldp_label_store_unlearn_peer(
    s: lr_ldp_label_store_t,
    peer_lsr_id: u32,
    peer_label_space: u16,
) -> usize {
    guarded(
        || unsafe {
            let Some(store) = borrow_store_mut(s) else {
                return 0;
            };
            store.unlearn_peer(LdpId::new(peer_lsr_id.to_be_bytes(), peer_label_space))
        },
        0,
    )
}

#[no_mangle]
pub unsafe extern "C" fn lr_ldp_label_store_unlearn_by_label(
    s: lr_ldp_label_store_t,
    peer_lsr_id: u32,
    peer_label_space: u16,
    label: u32,
    out_prefixes: *mut lr_ldp_prefix_t,
    cap: usize,
) -> usize {
    guarded(
        || unsafe {
            let Some(store) = borrow_store_mut(s) else {
                return 0;
            };
            let removed = store.unlearn_by_label(
                LdpId::new(peer_lsr_id.to_be_bytes(), peer_label_space),
                GenericLabel(label),
            );
            let n = removed.len().min(cap);
            if !out_prefixes.is_null() && n > 0 {
                for (i, key) in removed.iter().take(n).enumerate() {
                    let p = key.prefix;
                    let dst = unsafe { &mut *out_prefixes.add(i) };
                    match p.addr {
                        lr_core::addr::IpAddr::V4(b) => {
                            dst.addr_v4[..4].copy_from_slice(&b);
                            dst.is_ipv6 = 0;
                        }
                        lr_core::addr::IpAddr::V6(b) => {
                            dst.addr_v6 = b;
                            dst.is_ipv6 = 1;
                        }
                    }
                    dst.prefix_len = p.prefix_len;
                }
            }
            n
        },
        0,
    )
}

#[no_mangle]
pub unsafe extern "C" fn lr_ldp_label_store_unlearn_all_from(
    s: lr_ldp_label_store_t,
    peer_lsr_id: u32,
    peer_label_space: u16,
    out_prefixes: *mut lr_ldp_prefix_t,
    cap: usize,
) -> usize {
    guarded(
        || unsafe {
            let Some(store) = borrow_store_mut(s) else {
                return 0;
            };
            let removed =
                store.unlearn_all_from(LdpId::new(peer_lsr_id.to_be_bytes(), peer_label_space));
            let n = removed.len().min(cap);
            if !out_prefixes.is_null() && n > 0 {
                for (i, key) in removed.iter().take(n).enumerate() {
                    let p = key.prefix;
                    let dst = unsafe { &mut *out_prefixes.add(i) };
                    match p.addr {
                        lr_core::addr::IpAddr::V4(b) => {
                            dst.addr_v4[..4].copy_from_slice(&b);
                            dst.is_ipv6 = 0;
                        }
                        lr_core::addr::IpAddr::V6(b) => {
                            dst.addr_v6 = b;
                            dst.is_ipv6 = 1;
                        }
                    }
                    dst.prefix_len = p.prefix_len;
                }
            }
            n
        },
        0,
    )
}

/// Advertise a local label binding for a FEC (RFC 5036 §3.5.5).
/// Returns 1 and writes the previous label (if any) to
/// `*out_previous` when the call replaced an existing binding, 0
/// when the binding is new.
///
/// # Safety
/// See [`lr_ldp_label_store_learn`].
#[no_mangle]
pub unsafe extern "C" fn lr_ldp_label_store_advertise(
    s: lr_ldp_label_store_t,
    prefix_addr: *const u8,
    is_ipv6: u8,
    prefix_len: u8,
    label: u32,
    out_previous: *mut u32,
) -> u8 {
    guarded(
        || unsafe {
            let Some(store) = borrow_store_mut(s) else {
                return 0;
            };
            if prefix_addr.is_null() {
                return 0;
            }
            let key = FecKey::new(build_prefix(prefix_addr, is_ipv6, prefix_len));
            match store.advertise(key, GenericLabel(label)) {
                Some(prev) => {
                    if !out_previous.is_null() {
                        unsafe { *out_previous = prev.0 };
                    }
                    1
                }
                None => 0,
            }
        },
        0,
    )
}

/// Withdraw a locally-advertised label binding for a FEC. Returns 1
/// and writes the withdrawn label to `*out_label` when one existed,
/// 0 otherwise.
///
/// # Safety
/// See [`lr_ldp_label_store_learn`].
#[no_mangle]
pub unsafe extern "C" fn lr_ldp_label_store_withdraw_advertised(
    s: lr_ldp_label_store_t,
    prefix_addr: *const u8,
    is_ipv6: u8,
    prefix_len: u8,
    out_label: *mut u32,
) -> u8 {
    guarded(
        || unsafe {
            let Some(store) = borrow_store_mut(s) else {
                return 0;
            };
            if prefix_addr.is_null() {
                return 0;
            }
            let key = FecKey::new(build_prefix(prefix_addr, is_ipv6, prefix_len));
            match store.withdraw_advertised(&key) {
                Some(label) => {
                    if !out_label.is_null() {
                        unsafe { *out_label = label.0 };
                    }
                    1
                }
                None => 0,
            }
        },
        0,
    )
}

/// Read the locally-advertised label for a FEC. Returns 1 and writes
/// the label to `*out_label` when present, 0 otherwise.
///
/// # Safety
/// See [`lr_ldp_label_store_learn`].
#[no_mangle]
pub unsafe extern "C" fn lr_ldp_label_store_advertised_label(
    s: lr_ldp_label_store_t,
    prefix_addr: *const u8,
    is_ipv6: u8,
    prefix_len: u8,
    out_label: *mut u32,
) -> u8 {
    guarded(
        || unsafe {
            let Some(store) = borrow_store(s) else {
                return 0;
            };
            if prefix_addr.is_null() || out_label.is_null() {
                return 0;
            }
            let key = FecKey::new(build_prefix(prefix_addr, is_ipv6, prefix_len));
            match store.advertised_label(&key) {
                Some(label) => {
                    unsafe { *out_label = label.0 };
                    1
                }
                None => 0,
            }
        },
        0,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lsr_id_bytes(v: u32) -> [u8; 4] {
        v.to_be_bytes()
    }

    #[test]
    fn ffi_label_store_new_and_free() {
        let s = lr_ldp_label_store_new();
        assert!(!s.is_null());
        unsafe { lr_ldp_label_store_free(s) };
    }

    #[test]
    fn ffi_label_store_learn_and_label_from() {
        let s = lr_ldp_label_store_new();
        let prefix = [10u8, 0, 0, 0];

        let rc =
            unsafe { lr_ldp_label_store_learn(s, 0x01020304, 0, prefix.as_ptr(), 0, 24, 1001) };
        assert_eq!(rc, 1);

        let mut label = 0u32;
        let rc = unsafe {
            lr_ldp_label_store_label_from(s, 0x01020304, 0, prefix.as_ptr(), 0, 24, &raw mut label)
        };
        assert_eq!(rc, 1);
        assert_eq!(label, 1001);

        // Learning the same binding again returns 0 (no change).
        let rc =
            unsafe { lr_ldp_label_store_learn(s, 0x01020304, 0, prefix.as_ptr(), 0, 24, 1001) };
        assert_eq!(rc, 0);

        unsafe { lr_ldp_label_store_free(s) };
    }

    #[test]
    fn ffi_label_store_unlearn() {
        let s = lr_ldp_label_store_new();
        let prefix = [10u8, 0, 0, 0];
        let _ = unsafe { lr_ldp_label_store_learn(s, 0x01020304, 0, prefix.as_ptr(), 0, 24, 1001) };

        let mut released = 0u32;
        let rc = unsafe {
            lr_ldp_label_store_unlearn(s, 0x01020304, 0, prefix.as_ptr(), 0, 24, &raw mut released)
        };
        assert_eq!(rc, 1);
        assert_eq!(released, 1001);

        // label_from now returns 0.
        let mut label = 0u32;
        let rc = unsafe {
            lr_ldp_label_store_label_from(s, 0x01020304, 0, prefix.as_ptr(), 0, 24, &raw mut label)
        };
        assert_eq!(rc, 0);

        unsafe { lr_ldp_label_store_free(s) };
    }

    #[test]
    fn ffi_label_store_advertise_and_withdraw() {
        let s = lr_ldp_label_store_new();
        let prefix = [10u8, 0, 0, 0];

        // Advertise — new binding, returns 0.
        let mut dummy = 0u32;
        let rc = unsafe {
            lr_ldp_label_store_advertise(s, prefix.as_ptr(), 0, 24, 2001, &raw mut dummy)
        };
        assert_eq!(rc, 0);

        // advertised_label returns the value.
        let mut label = 0u32;
        let rc = unsafe {
            lr_ldp_label_store_advertised_label(s, prefix.as_ptr(), 0, 24, &raw mut label)
        };
        assert_eq!(rc, 1);
        assert_eq!(label, 2001);

        // Re-advertise with a new label — returns 1 (replaced).
        let mut previous = 0u32;
        let rc = unsafe {
            lr_ldp_label_store_advertise(s, prefix.as_ptr(), 0, 24, 2002, &raw mut previous)
        };
        assert_eq!(rc, 1);
        assert_eq!(previous, 2001);

        // Withdraw — returns 1 + the withdrawn label.
        let mut withdrawn = 0u32;
        let rc = unsafe {
            lr_ldp_label_store_withdraw_advertised(s, prefix.as_ptr(), 0, 24, &raw mut withdrawn)
        };
        assert_eq!(rc, 1);
        assert_eq!(withdrawn, 2002);

        unsafe { lr_ldp_label_store_free(s) };
    }

    #[test]
    fn ffi_label_store_ipv6_round_trip() {
        let s = lr_ldp_label_store_new();
        let prefix = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let rc =
            unsafe { lr_ldp_label_store_learn(s, 0x01020304, 0, prefix.as_ptr(), 1, 64, 3001) };
        assert_eq!(rc, 1);
        let mut label = 0u32;
        let rc = unsafe {
            lr_ldp_label_store_label_from(s, 0x01020304, 0, prefix.as_ptr(), 1, 64, &raw mut label)
        };
        assert_eq!(rc, 1);
        assert_eq!(label, 3001);
        unsafe { lr_ldp_label_store_free(s) };
    }

    #[test]
    fn ffi_label_store_handles_null_safely() {
        let prefix = [10u8, 0, 0, 0];
        assert_eq!(
            unsafe {
                lr_ldp_label_store_learn(std::ptr::null_mut(), 0, 0, prefix.as_ptr(), 0, 24, 100)
            },
            0
        );
        unsafe { lr_ldp_label_store_free(std::ptr::null_mut()) };
    }

    // Suppress unused warning on lsr_id_bytes helper.
    #[allow(dead_code)]
    fn _link_lsr_id_bytes(v: u32) -> [u8; 4] {
        lsr_id_bytes(v)
    }
}
