//! Layer-1 codec FFI: `lr_bgp_decode`, `lr_bgp_encode`, `lr_ospf_decode`,
//! `lr_babel_decode`.
//!
//! Stateless. Accepts raw byte slices; returns `lr_bytes_t` of decoded JSON
//! (or some structured form — for now, the bytes of the parsed message).
//!
//! Every entry point runs inside the crate's `catch_unwind` barrier
//! ([`crate::guarded`]): a panic returns `LR_ERR_PANIC` and sets the
//! thread-local last-error string.

use lr_babel::BabelCodec as BabelC;
use lr_bgp::{BgpCodec as BgpC, BgpMessage};
use lr_ospf::OspfCodec as OspfC;

use crate::error::{set_last_error, LR_ERR_PANIC};
use crate::guarded;
use crate::handle::lr_bytes_t;
use crate::policy::lr_prefix_t;

/// Decode one BGP message from `data`. Returns 0 on success (and writes a
/// `lr_bytes_t` containing the message type byte at offset 0 + body to
/// `out`). Negative on error.
#[no_mangle]
pub extern "C" fn lr_bgp_decode(data: *const u8, len: usize, out: *mut lr_bytes_t) -> i32 {
    guarded(
        || {
            if data.is_null() || out.is_null() {
                return -1;
            }
            let slice = unsafe { std::slice::from_raw_parts(data, len) };
            let mut codec = BgpC::new();
            match codec.decode_slice(slice) {
                Ok(Some(m)) => {
                    // Encode the message back into bytes (round-trip) — this gives
                    // callers a canonical bytes form. The first byte is the type.
                    let bytes = match codec.encode_vec(&m) {
                        Ok(b) => b,
                        Err(e) => {
                            set_last_error(e.to_string());
                            return -4;
                        }
                    };
                    unsafe { *out = lr_bytes_t::from_vec(bytes) }
                    0
                }
                Ok(None) => {
                    set_last_error("truncated".into());
                    -3
                }
                Err(e) => {
                    set_last_error(format!("{:?}", e));
                    -5
                }
            }
        },
        LR_ERR_PANIC,
    )
}

/// Encode a KEEPALIVE message (RFC 4271 §4.4). Part of the D5.4
/// encoder surface: see also [`lr_bgp_encode_open`],
/// [`lr_bgp_encode_notification`], [`lr_bgp_encode_update_withdraw_v4`]
/// and [`lr_bgp_encode_update_announce_v4`].
#[no_mangle]
pub extern "C" fn lr_bgp_encode_keepalive(out: *mut lr_bytes_t) -> i32 {
    guarded(
        || {
            if out.is_null() {
                return -1;
            }
            let codec = BgpC::new();
            match codec.encode_vec(&BgpMessage::Keepalive(
                lr_bgp::message::keepalive::Keepalive,
            )) {
                Ok(b) => {
                    unsafe { *out = lr_bytes_t::from_vec(b) }
                    0
                }
                Err(e) => {
                    set_last_error(e.to_string());
                    -2
                }
            }
        },
        LR_ERR_PANIC,
    )
}

/// Encode an OPEN message (RFC 4271 §4.2, ROADMAP-v3 D5.4): version 4,
/// the given AS, hold time and BGP identifier. When `as4` is non-zero
/// the RFC 6793 four-octet-AS capability (code 65) is appended with the
/// full 32-bit AS — an AS above 65535 then travels as AS_TRANS (23456)
/// in the 16-bit field per RFC 4893 §7. An AS above 65535 with `as4`
/// unset is rejected (it cannot be represented on the wire).
///
/// Hold time 0 (use the negotiated default) or >= 3 per RFC 4271 §4.2;
/// the illegal 1-2 second values are rejected up front.
///
/// Returns 0 on success, negative on error.
///
/// # Safety
/// `bgp_id` must point to 4 readable bytes.
#[no_mangle]
pub unsafe extern "C" fn lr_bgp_encode_open(
    my_as: u32,
    hold_time: u16,
    bgp_id: *const u8,
    as4: u8,
    out: *mut lr_bytes_t,
) -> i32 {
    guarded(
        || {
            if bgp_id.is_null() || out.is_null() {
                return -1;
            }
            if hold_time == 1 || hold_time == 2 {
                set_last_error(format!(
                    "illegal hold time {hold_time}s: RFC 4271 §4.2 wants 0 or >= 3"
                ));
                return -3;
            }
            if my_as > 0xffff && as4 == 0 {
                set_last_error(format!(
                    "AS {my_as} exceeds 16 bits and as4 is off: the wire form is unrepresentable"
                ));
                return -3;
            }
            let mut id = [0u8; 4];
            unsafe { id.copy_from_slice(std::slice::from_raw_parts(bgp_id, 4)) };
            let mut open = lr_bgp::message::open::Open::new(
                lr_core::addr::Asn(my_as),
                hold_time,
                lr_core::addr::RouterId::from_v4(id),
            );
            if as4 != 0 {
                // RFC 6793: the four-octet AS capability carries the
                // real AS; the 16-bit field reads AS_TRANS when needed.
                let mut value = vec![65u8, 4];
                value.extend_from_slice(&my_as.to_be_bytes());
                open.params.push(lr_bgp::message::open::OpenParam {
                    param_type: lr_bgp::message::open::OpenParam::PARAM_TYPE_CAPABILITY,
                    value,
                });
            }
            let codec = BgpC::new();
            match codec.encode_vec(&BgpMessage::Open(open)) {
                Ok(b) => {
                    unsafe { *out = lr_bytes_t::from_vec(b) }
                    0
                }
                Err(e) => {
                    set_last_error(e.to_string());
                    -2
                }
            }
        },
        LR_ERR_PANIC,
    )
}

/// Encode a NOTIFICATION message (RFC 4271 §4.5): the error code, the
/// subcode and the optional data payload (NULL when `data_len` is 0).
/// Returns 0 on success, negative on error.
///
/// # Safety
/// `data` must point to `data_len` readable bytes (NULL only when
/// `data_len` is 0).
#[no_mangle]
pub unsafe extern "C" fn lr_bgp_encode_notification(
    error_code: u8,
    error_subcode: u8,
    data: *const u8,
    data_len: usize,
    out: *mut lr_bytes_t,
) -> i32 {
    guarded(
        || {
            if out.is_null() || (data.is_null() && data_len != 0) {
                return -1;
            }
            let payload = if data.is_null() {
                Vec::new()
            } else {
                unsafe { std::slice::from_raw_parts(data, data_len).to_vec() }
            };
            let codec = BgpC::new();
            let msg = BgpMessage::Notification(lr_bgp::error::BgpNotification::new(
                error_code,
                error_subcode,
                payload,
            ));
            match codec.encode_vec(&msg) {
                Ok(b) => {
                    unsafe { *out = lr_bytes_t::from_vec(b) }
                    0
                }
                Err(e) => {
                    set_last_error(e.to_string());
                    -2
                }
            }
        },
        LR_ERR_PANIC,
    )
}

/// Collect and validate an IPv4 prefix array from C. Returns `None`
/// after recording the error when any entry is IPv6 (the legacy NLRI
/// sections are IPv4-only; MP-BGP UPDATEs are a router-level concern)
/// or malformed.
unsafe fn collect_v4_prefixes(
    prefixes: *const lr_prefix_t,
    n: usize,
) -> Option<Vec<lr_core::addr::Prefix>> {
    if n == 0 {
        return Some(Vec::new());
    }
    if prefixes.is_null() {
        set_last_error("prefix array is NULL".to_string());
        return None;
    }
    let slice = unsafe { std::slice::from_raw_parts(prefixes, n) };
    let mut out = Vec::with_capacity(n);
    for (i, p) in slice.iter().enumerate() {
        if p.is_ipv6 != 0 {
            set_last_error(format!(
                "prefix {i} is IPv6: the legacy NLRI section carries IPv4 only"
            ));
            return None;
        }
        if p.prefix_len > 32 {
            set_last_error(format!(
                "prefix {i}: invalid IPv4 prefix length {} (must be <= 32)",
                p.prefix_len
            ));
            return None;
        }
        out.push(lr_core::addr::Prefix::new_v4(
            [p.addr[0], p.addr[1], p.addr[2], p.addr[3]],
            p.prefix_len,
        ));
    }
    Some(out)
}

/// Encode a withdraw-only UPDATE (RFC 4271 §4.3): every listed IPv4
/// prefix goes into the withdrawn-routes section; no path attributes,
/// no NLRI. Returns 0 on success, negative on error.
///
/// # Safety
/// `prefixes` must point to `n_prefixes` readable `lr_prefix_t` values.
#[no_mangle]
pub unsafe extern "C" fn lr_bgp_encode_update_withdraw_v4(
    prefixes: *const lr_prefix_t,
    n_prefixes: usize,
    out: *mut lr_bytes_t,
) -> i32 {
    guarded(
        || {
            if out.is_null() {
                return -1;
            }
            let list = match unsafe { collect_v4_prefixes(prefixes, n_prefixes) } {
                Some(l) => l,
                None => return -3,
            };
            let update = lr_bgp::message::update::Update::new().with_withdrawn(list);
            let codec = BgpC::new();
            match codec.encode_vec(&BgpMessage::Update(update)) {
                Ok(b) => {
                    unsafe { *out = lr_bytes_t::from_vec(b) }
                    0
                }
                Err(e) => {
                    set_last_error(e.to_string());
                    -2
                }
            }
        },
        LR_ERR_PANIC,
    )
}

/// Encode an announcement UPDATE (RFC 4271 §4.3): ORIGIN + AS_PATH +
/// NEXT_HOP attributes and the IPv4 prefixes in the NLRI section.
///
/// `origin` selects the ORIGIN value (0 = IGP, 1 = EGP, 2 = INCOMPLETE;
/// anything else is rejected). `as_path` is an AS_SEQUENCE in wire order
/// (the origin AS first); with `as4` set the segments use the RFC 6793
/// four-octet encoding. An empty AS_PATH (locally originated) is legal.
///
/// Returns 0 on success, negative on error.
///
/// # Safety
/// `prefixes` must point to `n_prefixes` readable `lr_prefix_t` values,
/// `next_hop` to 4 readable bytes and `as_path` to `as_path_len` readable
/// `uint32_t` values.
#[no_mangle]
pub unsafe extern "C" fn lr_bgp_encode_update_announce_v4(
    prefixes: *const lr_prefix_t,
    n_prefixes: usize,
    next_hop: *const u8,
    as_path: *const u32,
    as_path_len: usize,
    origin: u8,
    as4: u8,
    out: *mut lr_bytes_t,
) -> i32 {
    guarded(
        || {
            if out.is_null() || next_hop.is_null() || (as_path_len > 0 && as_path.is_null()) {
                return -1;
            }
            if origin > 2 {
                set_last_error(format!(
                    "invalid ORIGIN {origin}: RFC 4271 §5.1.1 defines 0 (IGP), 1 (EGP), 2 (INCOMPLETE)"
                ));
                return -3;
            }
            let list = match unsafe { collect_v4_prefixes(prefixes, n_prefixes) } {
                Some(l) => l,
                None => return -3,
            };
            let ases: Vec<lr_core::addr::Asn> = if as_path.is_null() {
                Vec::new()
            } else {
                unsafe { std::slice::from_raw_parts(as_path, as_path_len) }
                    .iter()
                    .map(|&a| lr_core::addr::Asn(a))
                    .collect()
            };
            for asn in &ases {
                if asn.0 > 0xffff && as4 == 0 {
                    set_last_error(format!(
                        "AS {} in the path exceeds 16 bits and as4 is off",
                        asn.0
                    ));
                    return -3;
                }
            }
            let mut nh = [0u8; 4];
            unsafe { nh.copy_from_slice(std::slice::from_raw_parts(next_hop, 4)) };
            let path = lr_bgp::path::AsPath::from_sequence(ases);
            let path_value = if as4 != 0 {
                path.encode_4()
            } else {
                path.encode_2()
            };
            let update = lr_bgp::message::update::Update::new()
                .with_attribute(lr_bgp::path::PathAttribute::new(
                    lr_bgp::path::PathAttrFlags::new().set_transitive(true),
                    lr_bgp::path::AttrType::Origin,
                    vec![origin],
                ))
                .with_attribute(lr_bgp::path::PathAttribute::new(
                    lr_bgp::path::PathAttrFlags::new().set_transitive(true),
                    lr_bgp::path::AttrType::AsPath,
                    path_value,
                ))
                .with_attribute(lr_bgp::path::PathAttribute::new(
                    lr_bgp::path::PathAttrFlags::new().set_transitive(true),
                    lr_bgp::path::AttrType::NextHop,
                    nh.to_vec(),
                ))
                .with_nlri(list);
            let codec = BgpC::new();
            match codec.encode_vec(&BgpMessage::Update(update)) {
                Ok(b) => {
                    unsafe { *out = lr_bytes_t::from_vec(b) }
                    0
                }
                Err(e) => {
                    set_last_error(e.to_string());
                    -2
                }
            }
        },
        LR_ERR_PANIC,
    )
}

#[no_mangle]
pub extern "C" fn lr_ospf_decode_v2(data: *const u8, len: usize, out: *mut lr_bytes_t) -> i32 {
    guarded(
        || {
            if data.is_null() || out.is_null() {
                return -1;
            }
            let slice = unsafe { std::slice::from_raw_parts(data, len) };
            let mut codec = OspfC::v2();
            match codec.decode_slice(slice) {
                Ok(Some(_p)) => {
                    // For FFI we just return the raw input bytes for now.
                    unsafe { *out = lr_bytes_t::from_vec(slice.to_vec()) }
                    0
                }
                Ok(None) => {
                    set_last_error("truncated".into());
                    -3
                }
                Err(e) => {
                    set_last_error(e.to_string());
                    -5
                }
            }
        },
        LR_ERR_PANIC,
    )
}

#[no_mangle]
pub extern "C" fn lr_babel_decode(data: *const u8, len: usize, out: *mut lr_bytes_t) -> i32 {
    guarded(
        || {
            if data.is_null() || out.is_null() {
                return -1;
            }
            let slice = unsafe { std::slice::from_raw_parts(data, len) };
            let mut codec = BabelC::new();
            match codec.decode_slice(slice) {
                Ok(Some(_f)) => {
                    unsafe { *out = lr_bytes_t::from_vec(slice.to_vec()) }
                    0
                }
                Ok(None) => {
                    set_last_error("truncated".into());
                    -3
                }
                Err(e) => {
                    set_last_error(e.to_string());
                    -5
                }
            }
        },
        LR_ERR_PANIC,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn take(b: &lr_bytes_t) -> Vec<u8> {
        unsafe { std::slice::from_raw_parts(b.ptr, b.len) }.to_vec()
    }

    fn drop_bytes(mut b: lr_bytes_t) {
        unsafe { crate::bytes::lr_bytes_free(&raw mut b) };
    }

    #[test]
    fn encode_open_round_trip() {
        let mut out = lr_bytes_t {
            ptr: std::ptr::null_mut(),
            len: 0,
            cap: 0,
        };
        let id = [10u8, 0, 0, 1];
        assert_eq!(
            unsafe { lr_bgp_encode_open(64512, 90, id.as_ptr(), 1, &raw mut out) },
            0
        );
        let bytes = take(&out);
        // Header: marker (16) + length (2) + type 1 (OPEN).
        assert_eq!(bytes[18], 1, "message type is OPEN");
        // Body: version 4, AS 64512, hold 90, id, opt-params len > 0
        // (the RFC 6793 capability), capability code 65 + 4-octet AS.
        assert_eq!(bytes[19], 4);
        assert_eq!(&bytes[20..22], &64512u16.to_be_bytes());
        assert_eq!(&bytes[22..24], &90u16.to_be_bytes());
        assert_eq!(&bytes[24..28], &id);
        let plen = bytes[28] as usize;
        assert!(plen > 0, "optional parameters present (ASN4 capability)");
        assert_eq!(bytes[29], 2, "param type 2 (capabilities, RFC 5492)");
        assert!(bytes.contains(&65), "capability code 65 present");
        // Decode with the library codec and verify the AS + capability.
        let mut codec = BgpC::new().with_asn4(true);
        let msg = codec.decode_slice(&bytes).unwrap().expect("full message");
        match msg {
            BgpMessage::Open(o) => {
                assert_eq!(o.my_as, lr_core::addr::Asn(64512));
                assert!(o
                    .params
                    .iter()
                    .any(|p| p.param_type == 2 && p.value.starts_with(&[65, 4])));
            }
            other => panic!("wrong message type: {other:?}"),
        }
        drop_bytes(out);
    }

    #[test]
    fn encode_open_rejects_bad_values() {
        let id = [10u8, 0, 0, 1];
        let mut out = lr_bytes_t {
            ptr: std::ptr::null_mut(),
            len: 0,
            cap: 0,
        };
        // Hold time 1 is illegal (RFC 4271 §4.2).
        assert_eq!(
            unsafe { lr_bgp_encode_open(64512, 1, id.as_ptr(), 0, &raw mut out) },
            -3
        );
        // A 4-byte AS without as4 cannot be represented.
        assert_eq!(
            unsafe { lr_bgp_encode_open(4200000000, 90, id.as_ptr(), 0, &raw mut out) },
            -3
        );
        // NULL BGP identifier.
        assert_eq!(
            unsafe { lr_bgp_encode_open(64512, 90, std::ptr::null(), 0, &raw mut out) },
            -1
        );
    }

    #[test]
    fn encode_open_as_trans_for_4byte_as() {
        let mut out = lr_bytes_t {
            ptr: std::ptr::null_mut(),
            len: 0,
            cap: 0,
        };
        let id = [10u8, 0, 0, 1];
        assert_eq!(
            unsafe { lr_bgp_encode_open(4200000000, 90, id.as_ptr(), 1, &raw mut out) },
            0
        );
        let bytes = take(&out);
        // The 16-bit field reads AS_TRANS (23456) per RFC 4893 §7...
        assert_eq!(&bytes[20..22], &23456u16.to_be_bytes());
        // ...and the RFC 6793 capability carries the real 4-octet AS.
        let needle: Vec<u8> = {
            let mut v = vec![65u8, 4];
            v.extend_from_slice(&4200000000u32.to_be_bytes());
            v
        };
        assert!(
            bytes.windows(needle.len()).any(|w| w == needle),
            "four-octet AS capability present"
        );
        drop_bytes(out);
    }

    #[test]
    fn encode_notification_round_trip() {
        let mut out = lr_bytes_t {
            ptr: std::ptr::null_mut(),
            len: 0,
            cap: 0,
        };
        assert_eq!(
            unsafe { lr_bgp_encode_notification(6, 3, std::ptr::null(), 0, &raw mut out) },
            0
        );
        let bytes = take(&out);
        assert_eq!(bytes[18], 3, "message type is NOTIFICATION");
        assert_eq!(&bytes[19..], &[6u8, 3], "code 6 (CEASE), subcode 3");
        assert_eq!(bytes.len(), 21, "no data payload");
        drop_bytes(out);
        out = lr_bytes_t {
            ptr: std::ptr::null_mut(),
            len: 0,
            cap: 0,
        };

        // With a data payload.
        let data = [1u8, 2, 3, 4];
        assert_eq!(
            unsafe { lr_bgp_encode_notification(3, 2, data.as_ptr(), data.len(), &raw mut out) },
            0
        );
        let bytes = take(&out);
        assert_eq!(&bytes[19..], &[3u8, 2, 1, 2, 3, 4]);
        drop_bytes(out);
    }

    #[test]
    fn encode_update_withdraw_v4_wire_form() {
        let mut out = lr_bytes_t {
            ptr: std::ptr::null_mut(),
            len: 0,
            cap: 0,
        };
        let prefixes = [
            lr_prefix_t {
                addr: [203, 0, 113, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                is_ipv6: 0,
                prefix_len: 24,
            },
            lr_prefix_t {
                addr: [198, 51, 100, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                is_ipv6: 0,
                prefix_len: 24,
            },
        ];
        assert_eq!(
            unsafe { lr_bgp_encode_update_withdraw_v4(prefixes.as_ptr(), 2, &raw mut out) },
            0
        );
        let bytes = take(&out);
        assert_eq!(bytes[18], 2, "message type is UPDATE");
        // Withdrawn length = 2 * (1 + 3) = 8, then zero attribute
        // length, then the two NLRI entries.
        assert_eq!(&bytes[19..21], &8u16.to_be_bytes(), "withdrawn length");
        assert_eq!(&bytes[21..29], &[24, 203, 0, 113, 24, 198, 51, 100]);
        assert_eq!(&bytes[29..31], &0u16.to_be_bytes(), "empty attributes");
        assert_eq!(bytes.len(), 31, "nothing follows the attribute section");
        drop_bytes(out);
        out = lr_bytes_t {
            ptr: std::ptr::null_mut(),
            len: 0,
            cap: 0,
        };

        // Zero prefixes is a legal (if useless) empty withdrawal.
        assert_eq!(
            unsafe { lr_bgp_encode_update_withdraw_v4(std::ptr::null(), 0, &raw mut out) },
            0
        );
        let bytes = take(&out);
        assert_eq!(&bytes[19..23], &[0, 0, 0, 0]);
        drop_bytes(out);
    }

    #[test]
    fn encode_update_announce_v4_wire_form() {
        let mut out = lr_bytes_t {
            ptr: std::ptr::null_mut(),
            len: 0,
            cap: 0,
        };
        let prefixes = [lr_prefix_t {
            addr: [203, 0, 113, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            is_ipv6: 0,
            prefix_len: 24,
        }];
        let nh = [192u8, 0, 2, 1];
        let ases = [64513u32, 64512];
        assert_eq!(
            unsafe {
                lr_bgp_encode_update_announce_v4(
                    prefixes.as_ptr(),
                    1,
                    nh.as_ptr(),
                    ases.as_ptr(),
                    2,
                    0,
                    0,
                    &raw mut out,
                )
            },
            0
        );
        let bytes = take(&out);
        assert_eq!(&bytes[19..21], &0u16.to_be_bytes(), "nothing withdrawn");
        // Decode back and verify the attributes semantically.
        let mut codec = BgpC::new().with_asn4(false);
        let msg = codec.decode_slice(&bytes).unwrap().expect("full message");
        match msg {
            BgpMessage::Update(u) => {
                assert!(u.withdrawn.is_empty());
                assert_eq!(u.nlri.len(), 1);
                let attrs: lr_bgp::path::PathAttributes = u.attributes.clone();
                assert_eq!(
                    attrs.origin().map(|o| o.0),
                    Some(lr_bgp::path::OriginKind::Igp),
                    "ORIGIN = IGP"
                );
                let path = attrs.as_path_wire(false).expect("AS_PATH present");
                assert_eq!(
                    path.as_sequence(),
                    vec![lr_core::addr::Asn(64513), lr_core::addr::Asn(64512)]
                );
                assert_eq!(
                    attrs.next_hop().map(|n| n.0),
                    Some(lr_bgp::path::NextHopKind::V4([192, 0, 2, 1]))
                );
            }
            other => panic!("wrong message type: {other:?}"),
        }
        drop_bytes(out);
    }

    #[test]
    fn encode_update_announce_v4_as4_path() {
        let mut out = lr_bytes_t {
            ptr: std::ptr::null_mut(),
            len: 0,
            cap: 0,
        };
        let prefixes = [lr_prefix_t {
            addr: [10, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            is_ipv6: 0,
            prefix_len: 8,
        }];
        let nh = [192u8, 0, 2, 1];
        let ases = [4200000000u32];
        assert_eq!(
            unsafe {
                lr_bgp_encode_update_announce_v4(
                    prefixes.as_ptr(),
                    1,
                    nh.as_ptr(),
                    ases.as_ptr(),
                    1,
                    0,
                    1,
                    &raw mut out,
                )
            },
            0
        );
        let bytes = take(&out);
        let mut codec = BgpC::new().with_asn4(true);
        let msg = codec.decode_slice(&bytes).unwrap().expect("full message");
        match msg {
            BgpMessage::Update(u) => {
                let attrs: lr_bgp::path::PathAttributes = u.attributes.clone();
                assert_eq!(
                    attrs.as_path().expect("AS_PATH").as_sequence(),
                    vec![lr_core::addr::Asn(4200000000)]
                );
            }
            other => panic!("wrong message type: {other:?}"),
        }
        // A 4-byte AS with as4 off is rejected.
        assert_eq!(
            unsafe {
                lr_bgp_encode_update_announce_v4(
                    prefixes.as_ptr(),
                    1,
                    nh.as_ptr(),
                    ases.as_ptr(),
                    1,
                    0,
                    0,
                    &raw mut out,
                )
            },
            -3
        );
        drop_bytes(out);
    }

    #[test]
    fn encode_update_announce_v4_rejects_bad_values() {
        let mut out = lr_bytes_t {
            ptr: std::ptr::null_mut(),
            len: 0,
            cap: 0,
        };
        let prefixes = [lr_prefix_t {
            addr: [203, 0, 113, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            is_ipv6: 0,
            prefix_len: 24,
        }];
        let nh = [192u8, 0, 2, 1];
        // ORIGIN 3 is not defined by RFC 4271 §5.1.1.
        assert_eq!(
            unsafe {
                lr_bgp_encode_update_announce_v4(
                    prefixes.as_ptr(),
                    1,
                    nh.as_ptr(),
                    std::ptr::null(),
                    0,
                    3,
                    0,
                    &raw mut out,
                )
            },
            -3
        );
        // IPv6 prefixes do not fit the legacy NLRI section.
        let v6 = [lr_prefix_t {
            addr: [0x20, 1, 0xd, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            is_ipv6: 1,
            prefix_len: 32,
        }];
        assert_eq!(
            unsafe { lr_bgp_encode_update_withdraw_v4(v6.as_ptr(), 1, &raw mut out) },
            -3
        );
        // Prefix length 33 is invalid for IPv4.
        let bad = [lr_prefix_t {
            addr: [203, 0, 113, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            is_ipv6: 0,
            prefix_len: 33,
        }];
        assert_eq!(
            unsafe { lr_bgp_encode_update_withdraw_v4(bad.as_ptr(), 1, &raw mut out) },
            -3
        );
        // NULL next-hop.
        assert_eq!(
            unsafe {
                lr_bgp_encode_update_announce_v4(
                    prefixes.as_ptr(),
                    1,
                    std::ptr::null(),
                    std::ptr::null(),
                    0,
                    0,
                    0,
                    &raw mut out,
                )
            },
            -1
        );
    }
}
