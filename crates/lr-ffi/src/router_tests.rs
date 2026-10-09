use super::*;
use crate::error::lr_last_error;
use crate::guard;
use std::ffi::CStr;

fn last_error() -> String {
    unsafe { CStr::from_ptr(lr_last_error()) }
        .to_string_lossy()
        .into_owned()
}

fn drain_all(r: lr_router_t, session: u64) -> Vec<u8> {
    let mut out = lr_bytes_t {
        ptr: std::ptr::null_mut(),
        len: 0,
        cap: 0,
    };
    assert_eq!(unsafe { lr_router_drain_output(r, session, &mut out) }, 0);
    let bytes = unsafe { std::slice::from_raw_parts(out.ptr, out.len) }.to_vec();
    unsafe { crate::bytes::lr_bytes_free(&mut out) };
    bytes
}

/// The `catch_unwind` barrier catches panics and the wrapper records the
/// documented panic error + last-error string instead of unwinding.
#[test]
fn guard_catches_panics_and_guarded_returns_fallback() {
    assert_eq!(guard(|| 42), Some(42));
    assert!(guard(|| -> i32 { panic!("boom") }).is_none());
    // The exact wrapper path used by every entry point:
    assert_eq!(
        guarded(|| -> i32 { panic!("boom") }, LR_ERR_PANIC),
        LR_ERR_PANIC
    );
    assert_eq!(last_error(), "panic caught in FFI");
}

#[test]
fn originate_v4_rejects_prefix_len_33() {
    let r = lr_router_new();
    let addr = [10u8, 0, 0, 1];
    // 33 > 32 must be rejected up front (no panic in the NLRI encoder).
    assert_eq!(
        unsafe { lr_router_originate_v4(r, addr.as_ptr(), 33, std::ptr::null()) },
        -3
    );
    assert!(last_error().contains("prefix length"), "{}", last_error());
    // 32 is the legal maximum.
    assert_eq!(
        unsafe { lr_router_originate_v4(r, addr.as_ptr(), 32, std::ptr::null()) },
        0
    );
    unsafe { unbox_router(r) };
}

#[test]
fn originate_v6_round_trip() {
    let r = lr_router_new();
    let v6 = [0x20u8, 1, 0xdb, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    assert_eq!(
        unsafe { lr_router_originate_v6(r, v6.as_ptr(), 32, std::ptr::null()) },
        0
    );
    assert_eq!(lr_router_rib_len(r), 1);
    // 129 > 128 must be rejected up front.
    assert_eq!(
        unsafe { lr_router_originate_v6(r, v6.as_ptr(), 129, std::ptr::null()) },
        -3
    );
    assert!(last_error().contains("prefix length"), "{}", last_error());
    unsafe { unbox_router(r) };
}

#[test]
fn withdraw_v4_lifecycle() {
    let r = lr_router_new();
    let addr = [203u8, 0, 113, 0];
    // Not originated yet: idempotent no-op (FRR `no network` on an
    // absent statement).
    assert_eq!(unsafe { lr_router_withdraw_v4(r, addr.as_ptr(), 24) }, 1);
    assert_eq!(
        unsafe { lr_router_originate_v4(r, addr.as_ptr(), 24, std::ptr::null()) },
        0
    );
    assert_eq!(lr_router_rib_len(r), 1);
    assert_eq!(unsafe { lr_router_withdraw_v4(r, addr.as_ptr(), 24) }, 0);
    assert_eq!(lr_router_rib_len(r), 0);
    // A second withdraw of the same prefix is a no-op again.
    assert_eq!(unsafe { lr_router_withdraw_v4(r, addr.as_ptr(), 24) }, 1);
    // Prefix-length validation mirrors originate.
    assert_eq!(unsafe { lr_router_withdraw_v4(r, addr.as_ptr(), 33) }, -3);
    unsafe { unbox_router(r) };
}

#[test]
fn withdraw_v6_lifecycle() {
    let r = lr_router_new();
    let v6 = [0x20u8, 1, 0xdb, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    assert_eq!(unsafe { lr_router_withdraw_v6(r, v6.as_ptr(), 32) }, 1);
    assert_eq!(
        unsafe { lr_router_originate_v6(r, v6.as_ptr(), 32, std::ptr::null()) },
        0
    );
    assert_eq!(unsafe { lr_router_withdraw_v6(r, v6.as_ptr(), 32) }, 0);
    assert_eq!(lr_router_rib_len(r), 0);
    assert_eq!(unsafe { lr_router_withdraw_v6(r, v6.as_ptr(), 129) }, -3);
    unsafe { unbox_router(r) };
}

#[test]
fn originate_labeled_rejects_out_of_range_prefix_lens() {
    let r = lr_router_new();
    let v4 = [10u8, 0, 0, 1];
    let labels = [100u32];
    assert_eq!(
        unsafe {
            lr_router_originate_labeled_v4(r, v4.as_ptr(), 33, labels.as_ptr(), 1, std::ptr::null())
        },
        -3
    );
    let v6 = [0x20u8, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
    assert_eq!(
        unsafe {
            lr_router_originate_labeled_v6(
                r,
                v6.as_ptr(),
                129,
                labels.as_ptr(),
                1,
                std::ptr::null(),
            )
        },
        -3
    );
    assert!(last_error().contains("prefix length"), "{}", last_error());
    assert_eq!(
        unsafe {
            lr_router_originate_labeled_v6(
                r,
                v6.as_ptr(),
                128,
                labels.as_ptr(),
                1,
                std::ptr::null(),
            )
        },
        0
    );
    unsafe { unbox_router(r) };
}

#[test]
fn set_local_address_rejects_bad_length_without_ub() {
    let r = lr_router_new();
    let bytes = [1u8, 2, 3]; // 3 bytes: neither 4 (v4) nor 16 (v6)
                             // Must fail with -3 before any slice of length 3 is constructed.
    assert_eq!(
        unsafe { lr_router_set_local_address(r, 0, 1, bytes.as_ptr(), 3) },
        -3
    );
    // Same for an unknown address family.
    assert_eq!(
        unsafe { lr_router_set_local_address(r, 0, 7, bytes.as_ptr(), 4) },
        -3
    );
    // A valid length reaches the router, which rejects the unknown
    // session handle with -2.
    assert_eq!(
        unsafe { lr_router_set_local_address(r, 0, 1, bytes.as_ptr(), 4) },
        -2
    );
    unsafe { unbox_router(r) };
}

#[test]
fn tuple_count_overflow_is_rejected_before_from_raw_parts() {
    let r = lr_router_new();
    let buf = [0u8; 8];
    // usize::MAX * 5 and usize::MAX * 4 would wrap; both must be
    // rejected before any slice is built.
    assert_eq!(
        unsafe { lr_router_set_extended_next_hop(r, 0, buf.as_ptr(), usize::MAX) },
        -3
    );
    assert_eq!(
        unsafe { lr_router_set_mp_families(r, 0, buf.as_ptr(), usize::MAX) },
        -3
    );
    assert!(last_error().contains("too large"), "{}", last_error());
    unsafe { unbox_router(r) };
}

#[test]
fn label_stack_depth_is_capped() {
    let r = lr_router_new();
    let v4 = [10u8, 0, 0, 1];
    let labels = [0u32; MAX_LABEL_STACK_DEPTH + 1];
    assert_eq!(
        unsafe {
            lr_router_originate_labeled_v4(
                r,
                v4.as_ptr(),
                24,
                labels.as_ptr(),
                labels.len(),
                std::ptr::null(),
            )
        },
        -3
    );
    assert!(last_error().contains("label stack"), "{}", last_error());
    unsafe { unbox_router(r) };
}

/// W2.1/BIRD: with the default `default_ipv4_unicast` on and no explicit
/// families, the OPEN must still advertise the IPv4-unicast MP-BGP
/// capability (BIRD 2 refuses sessions whose required capability is
/// missing).
#[test]
fn add_bgp_session_ext_advertises_ipv4_unicast_mp_by_default() {
    let r = lr_router_new();
    let mut h = 0u64;
    assert_eq!(
        unsafe {
            lr_router_add_bgp_session_ext(
                r,
                64512,
                64513,
                0x0a00_0001,
                90,
                30,
                1,
                1,
                120,
                0,
                0,
                0,
                &mut h,
            )
        },
        0
    );
    assert_ne!(h, 0);
    assert_eq!(lr_router_start_session(r, h), 0);
    let open = drain_all(r, h);
    // RFC 4760 multiprotocol capability for (AFI=1, SAFI=1):
    // cap-code 1, cap-len 4, value 00 01 00 01.
    let mp_v4: &[u8] = &[0x01, 0x04, 0x00, 0x01, 0x00, 0x01];
    assert!(
        open.windows(6).any(|w| w == mp_v4),
        "OPEN should advertise the IPv4-unicast MP capability, got {open:?}"
    );
    unsafe { unbox_router(r) };
}

/// The FRR `no bgp default ipv4-unicast` posture: with the default
/// flipped off and no explicit families, the OPEN must NOT advertise
/// the IPv4-unicast MP capability.
#[test]
fn add_bgp_session_ext_omits_ipv4_unicast_mp_when_disabled() {
    let r = lr_router_new();
    let mut h = 0u64;
    assert_eq!(
        unsafe {
            lr_router_add_bgp_session_ext(
                r,
                64512,
                64513,
                0x0a00_0002,
                90,
                30,
                1,
                1,
                120,
                0,
                0,
                0,
                &mut h,
            )
        },
        0
    );
    // Flip the default off and clear the family list (the embedder's
    // equivalent of FRR `no bgp default ipv4-unicast` with no
    // `neighbor X address-family`).
    assert_eq!(lr_router_set_default_ipv4_unicast(r, h, 0), 0);
    assert_eq!(
        unsafe { lr_router_set_mp_families(r, h, std::ptr::null(), 0) },
        0
    );
    assert_eq!(lr_router_start_session(r, h), 0);
    let open = drain_all(r, h);
    let mp_v4: &[u8] = &[0x01, 0x04, 0x00, 0x01, 0x00, 0x01];
    assert!(
        !open.windows(6).any(|w| w == mp_v4),
        "OPEN must not advertise the IPv4-unicast MP capability, got {open:?}"
    );
    unsafe { unbox_router(r) };
}
