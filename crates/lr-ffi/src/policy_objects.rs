//! Policy objects over the C ABI (ROADMAP-v3 D5.3): route handles,
//! prefix-lists, route-maps and the match resolver.
//!
//! The route handle ([`lr_route_t`]) boxes a real
//! `lr_core::rib::Route`, so policy evaluation runs against the same
//! data model the library uses internally — attributes set through the
//! `lr_route_set_*` entries are the exact bytes the DSL and the
//! route-map engine read and mutate. It is the embedder-side companion
//! to D5.2's filter entries: describe a route, run a filter or a
//! route-map, read the mutations back.
//!
//! The route-map ([`lr_route_map_t`]) mirrors FRR `route-map` /
//! BIRD `pipe` policy: an ordered entry list where the first matching
//! entry applies its sets and decides (`permit` / `deny` /
//! `continue`). Match conditions resolve through the resolver
//! ([`lr_resolver_t`], a `lr_policy::PolicySet`): the named registry
//! of prefix-lists, AS-path filter lists and community lists. An
//! unknown list id denies (FRR semantics); a NULL resolver denies
//! every list-backed match — fail-closed either way.
//!
//! # Safety
//!
//! Same contract as the rest of the crate: `catch_unwind` barrier,
//! null checks, documented error codes. Handles must outlive no call
//! past their `_free`; `lr_resolver_add_*` consume the passed handle
//! (the caller's pointer is nulled where documented) or copy the
//! object, as stated per entry.

use crate::error::{set_last_error, LR_ERR_PANIC};
use crate::guarded;
use crate::handle::{lr_prefix_list_t, lr_resolver_t, lr_route_map_t, lr_route_t};
use crate::policy::{lr_prefix_t, LrProtocol};
use lr_core::addr::{Asn, IpAddr, Prefix};
use lr_core::attr::{AttrTag, Attribute};
use lr_core::nlri::NlriFamily;
use lr_core::rib::{Protocol, Route, RouteKey, RouteOrigin};
use lr_policy::action::{MatchCondition, SetAction};
use lr_policy::as_path_filter::AsPathFilter;
use lr_policy::bgp as policy_bgp;
use lr_policy::community_list::CommunityListEntry;
use lr_policy::prefix_list::{PrefixList, PrefixListEntry};
use lr_policy::route_map::RouteMapEntry;
use lr_policy::{PolicySet, RouteMap};
use std::ffi::CStr;

// ---- Well-known BGP path attribute tags + flags (RFC 4271 §4.2,
// RFC 1997 §4, RFC 4360 §2, RFC 8097 §2) — mirrors lr_policy::bgp. ----

const TAG_ORIGIN: u8 = 1;
const FLAGS_ORIGIN: u8 = 0x40; // well-known mandatory

// ---- C ABI constants. ----

/// ORIGIN values (RFC 4271 §5.1.1).
pub const LR_ORIGIN_IGP: u8 = 0;
pub const LR_ORIGIN_EGP: u8 = 1;
pub const LR_ORIGIN_INCOMPLETE: u8 = 2;

/// Route-map match condition kinds (`lr_match_t::kind`).
pub const LR_MATCH_PREFIX_IN: u8 = 0;
pub const LR_MATCH_AS_PATH_IN: u8 = 1;
pub const LR_MATCH_COMMUNITY_IN: u8 = 2;
pub const LR_MATCH_PROTOCOL_IS: u8 = 3;
pub const LR_MATCH_NEXT_HOP_IN: u8 = 4;

/// Route-map set action kinds (`lr_set_t::kind`).
pub const LR_SET_LOCAL_PREF: u8 = 0;
pub const LR_SET_MED: u8 = 1;
pub const LR_SET_NEXT_HOP: u8 = 2;
pub const LR_SET_PREPEND_AS: u8 = 3;
pub const LR_SET_ADD_COMMUNITY: u8 = 4;
pub const LR_SET_METRIC: u8 = 5;
pub const LR_SET_TAG: u8 = 6;

/// Route-map entry verdict (`lr_route_map_add_entry`).
pub const LR_VERDICT_CONTINUE: i32 = 0;
pub const LR_VERDICT_PERMIT: i32 = 1;
pub const LR_VERDICT_DENY: i32 = 2;

/// `lr_route_map_evaluate` verdict output.
pub const LR_EVAL_DENY: i32 = 0;
pub const LR_EVAL_PERMIT: i32 = 1;
pub const LR_EVAL_FALLTHROUGH: i32 = -1;

// ---- C struct surface ----

/// One RFC 4360 extended community, embedder-side.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct lr_ext_comm_t {
    pub kind: u8,
    pub subtype: u8,
    pub global: u32,
    pub local: u16,
}

/// One route-map match condition.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct lr_match_t {
    /// [`LR_MATCH_*`](LR_MATCH_PREFIX_IN) kind.
    pub kind: u8,
    /// List id for the `*_IN` kinds (as returned by the
    /// `lr_resolver_add_*` registrations).
    pub list_id: u32,
    /// [`LrProtocol`] id for [`LR_MATCH_PROTOCOL_IS`].
    pub protocol: u8,
}

/// One route-map set action.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct lr_set_t {
    /// [`LR_SET_*`](LR_SET_LOCAL_PREF) kind.
    pub kind: u8,
    /// IPv6 flag for [`LR_SET_NEXT_HOP`].
    pub is_ipv6: u8,
    /// Address for [`LR_SET_NEXT_HOP`] (first 4 bytes for IPv4).
    pub addr: [u8; 16],
    /// Payload: LOCAL_PREF / MED / the AS for PREPEND_AS / the ASN for
    /// ADD_COMMUNITY / METRIC / TAG.
    pub value: u32,
    /// Community value for [`LR_SET_ADD_COMMUNITY`].
    pub value2: u16,
}

/// One FRR-dialect AS-path access-list filter.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct lr_as_path_filter_t {
    /// NUL-terminated pattern (`_65001_`, `^65001$`, ...). Borrowed for
    /// the duration of the `lr_resolver_add_as_path_list` call only.
    pub pattern: *const std::ffi::c_char,
    /// Non-zero: permit, zero: deny.
    pub permit: u8,
}

/// One community-list entry (RFC 1997 standard list).
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct lr_community_entry_t {
    /// Packed `asn << 16 | value` communities. Borrowed for the
    /// duration of the `lr_resolver_add_community_list` call only.
    pub communities: *const u64,
    pub count: usize,
    /// Non-zero: permit, zero: deny.
    pub permit: u8,
}

// ---- helpers ----

fn protocol_from_i32(v: i32) -> Option<Protocol> {
    LrProtocol::from_i32(v).map(|p| match p {
        LrProtocol::Bgp => Protocol::Bgp,
        LrProtocol::Ospf => Protocol::Ospfv2,
        LrProtocol::Ospf3 => Protocol::Ospfv3,
        LrProtocol::Babel => Protocol::Babel,
        LrProtocol::Static => Protocol::Static,
        LrProtocol::Connected => Protocol::Connected,
    })
}

/// lr-policy's internal protocol id (crate::action::proto_id) — the
/// C ABI exposes [`LrProtocol`] and translates here, keeping the
/// internal numbering an implementation detail.
fn policy_proto_id(p: Protocol) -> u8 {
    match p {
        Protocol::Bgp => 1,
        Protocol::Ospfv2 => 2,
        Protocol::Ospfv3 => 3,
        Protocol::Babel => 4,
        Protocol::Static => 5,
        Protocol::Connected => 6,
        Protocol::Other(_) => 0xff,
    }
}

fn route_family(p: &Prefix) -> NlriFamily {
    match p.addr {
        IpAddr::V4(_) => NlriFamily::IPV4_UNICAST,
        IpAddr::V6(_) => NlriFamily::IPV6_UNICAST,
    }
}

fn as_route(r: lr_route_t) -> Option<&'static mut Route> {
    if r.is_null() {
        return None;
    }
    Some(unsafe { &mut *(r as *mut Route) })
}

/// # Safety
/// `p` must be a readable `lr_prefix_t`.
unsafe fn prefix_from_c(p: *const lr_prefix_t) -> Option<Prefix> {
    let raw = unsafe { *p };
    if raw.is_ipv6 == 0 {
        if raw.prefix_len > 32 {
            return None;
        }
        Some(Prefix::new_v4(
            [raw.addr[0], raw.addr[1], raw.addr[2], raw.addr[3]],
            raw.prefix_len,
        ))
    } else {
        if raw.prefix_len > 128 {
            return None;
        }
        Some(Prefix::new_v6(raw.addr, raw.prefix_len))
    }
}

unsafe fn read_str<'a>(ptr: *const std::ffi::c_char) -> Option<&'a str> {
    if ptr.is_null() {
        return None;
    }
    unsafe { CStr::from_ptr(ptr) }.to_str().ok()
}

// ============================================================
// Route handle
// ============================================================

/// Create a route handle for an IPv4 prefix. `protocol` is an
/// [`LrProtocol`] id. Returns NULL on a malformed prefix length or
/// unknown protocol id (the last-error string says which).
///
/// # Safety
/// `octets` must point to 4 readable bytes.
#[no_mangle]
pub unsafe extern "C" fn lr_route_new_v4(
    octets: *const u8,
    prefix_len: u8,
    protocol: i32,
) -> lr_route_t {
    guarded(
        || {
            if octets.is_null() {
                set_last_error("null prefix octets".to_string());
                return std::ptr::null_mut();
            }
            let Some(proto) = protocol_from_i32(protocol) else {
                set_last_error(format!("unknown protocol id {protocol}"));
                return std::ptr::null_mut();
            };
            if prefix_len > 32 {
                set_last_error(format!("invalid IPv4 prefix length {prefix_len}"));
                return std::ptr::null_mut();
            }
            let mut o = [0u8; 4];
            unsafe { std::ptr::copy_nonoverlapping(octets, o.as_mut_ptr(), 4) };
            let prefix = Prefix::new_v4(o, prefix_len);
            let route = Route {
                key: RouteKey::new(prefix, route_family(&prefix)),
                origin: RouteOrigin { proto: 0, peer: 0 },
                protocol: proto,
                preference: lr_core::rib::Preference::new(20, 0),
                next_hop: None,
                attributes: lr_core::attr::Attributes::new(),
                age_ms: 0,
                path_id: 0,
                tag: None,
            };
            Box::into_raw(Box::new(route)) as lr_route_t
        },
        std::ptr::null_mut(),
    )
}

/// Create a route handle for an IPv6 prefix. See
/// [`lr_route_new_v4`] for the contract.
///
/// # Safety
/// `octets` must point to 16 readable bytes.
#[no_mangle]
pub unsafe extern "C" fn lr_route_new_v6(
    octets: *const u8,
    prefix_len: u8,
    protocol: i32,
) -> lr_route_t {
    guarded(
        || {
            if octets.is_null() {
                set_last_error("null prefix octets".to_string());
                return std::ptr::null_mut();
            }
            let Some(proto) = protocol_from_i32(protocol) else {
                set_last_error(format!("unknown protocol id {protocol}"));
                return std::ptr::null_mut();
            };
            if prefix_len > 128 {
                set_last_error(format!("invalid IPv6 prefix length {prefix_len}"));
                return std::ptr::null_mut();
            }
            let mut o = [0u8; 16];
            unsafe { std::ptr::copy_nonoverlapping(octets, o.as_mut_ptr(), 16) };
            let prefix = Prefix::new_v6(o, prefix_len);
            let route = Route {
                key: RouteKey::new(prefix, route_family(&prefix)),
                origin: RouteOrigin { proto: 0, peer: 0 },
                protocol: proto,
                preference: lr_core::rib::Preference::new(20, 0),
                next_hop: None,
                attributes: lr_core::attr::Attributes::new(),
                age_ms: 0,
                path_id: 0,
                tag: None,
            };
            Box::into_raw(Box::new(route)) as lr_route_t
        },
        std::ptr::null_mut(),
    )
}

/// Free a route handle. NULL is a no-op.
///
/// # Safety
/// `route` must be null or a handle returned by `lr_route_new_*` that
/// has not been freed yet, and must not be used afterwards.
#[no_mangle]
pub unsafe extern "C" fn lr_route_free(route: lr_route_t) {
    guarded(
        || {
            if !route.is_null() {
                drop(unsafe { Box::from_raw(route as *mut Route) });
            }
        },
        (),
    )
}

/// Set the route's next hop (RFC 4271 §5.1.3). `addr` carries the
/// IPv4 octets in the first four bytes when `is_ipv6` is 0. Returns
/// 0, -1 on a null argument.
///
/// # Safety
/// `addr` must point to 4 (v4) / 16 (v6) readable bytes.
#[no_mangle]
pub unsafe extern "C" fn lr_route_set_next_hop(
    route: lr_route_t,
    addr: *const u8,
    is_ipv6: i32,
) -> i32 {
    guarded(
        || {
            let Some(r) = as_route(route) else { return -1 };
            if addr.is_null() {
                return -1;
            }
            if is_ipv6 != 0 {
                let mut a = [0u8; 16];
                unsafe { std::ptr::copy_nonoverlapping(addr, a.as_mut_ptr(), 16) };
                r.next_hop = Some(IpAddr::V6(a));
            } else {
                let mut a = [0u8; 4];
                unsafe { std::ptr::copy_nonoverlapping(addr, a.as_mut_ptr(), 4) };
                r.next_hop = Some(IpAddr::V4(a));
            }
            0
        },
        LR_ERR_PANIC,
    )
}

/// Read the route's next hop into `out` (16 bytes, IPv4 in the first
/// four) and its family into `out_is_ipv6`. Returns 0 when present,
/// 1 when absent, -1 on a null argument.
///
/// # Safety
/// `out` must be writable for 16 bytes; `out_is_ipv6` writable for one
/// `i32`.
#[no_mangle]
pub unsafe extern "C" fn lr_route_next_hop(
    route: lr_route_t,
    out: *mut u8,
    out_is_ipv6: *mut i32,
) -> i32 {
    guarded(
        || {
            let Some(r) = as_route(route) else { return -1 };
            if out.is_null() || out_is_ipv6.is_null() {
                return -1;
            }
            match r.next_hop {
                Some(IpAddr::V4(o)) => {
                    unsafe { *out_is_ipv6 = 0 };
                    unsafe { std::ptr::copy_nonoverlapping(o.as_ptr(), out, 4) };
                    0
                }
                Some(IpAddr::V6(o)) => {
                    unsafe { *out_is_ipv6 = 1 };
                    unsafe { std::ptr::copy_nonoverlapping(o.as_ptr(), out, 16) };
                    0
                }
                None => 1,
            }
        },
        LR_ERR_PANIC,
    )
}

/// Set the BGP LOCAL_PREF (RFC 4271 §5.1.5). Returns 0 / -1.
///
/// # Safety
/// `route` must be a live handle.
#[no_mangle]
pub unsafe extern "C" fn lr_route_set_local_pref(route: lr_route_t, value: u32) -> i32 {
    guarded(
        || {
            let Some(r) = as_route(route) else { return -1 };
            policy_bgp::set_local_pref(r, value);
            0
        },
        LR_ERR_PANIC,
    )
}

/// Read LOCAL_PREF into `out`. Returns 0 present, 1 absent, -1 null.
///
/// # Safety
/// `out` must be writable.
#[no_mangle]
pub unsafe extern "C" fn lr_route_local_pref(route: lr_route_t, out: *mut u32) -> i32 {
    guarded(
        || {
            let Some(r) = as_route(route) else { return -1 };
            if out.is_null() {
                return -1;
            }
            match policy_bgp::local_pref(r) {
                Some(v) => {
                    unsafe { *out = v };
                    0
                }
                None => 1,
            }
        },
        LR_ERR_PANIC,
    )
}

/// Set the BGP MULTI_EXIT_DISC (RFC 4271 §4.2.4). 0 / -1.
///
/// # Safety
/// `route` must be a live handle.
#[no_mangle]
pub unsafe extern "C" fn lr_route_set_med(route: lr_route_t, value: u32) -> i32 {
    guarded(
        || {
            let Some(r) = as_route(route) else { return -1 };
            policy_bgp::set_med(r, value);
            0
        },
        LR_ERR_PANIC,
    )
}

/// Read MULTI_EXIT_DISC. 0 present, 1 absent, -1 null.
///
/// # Safety
/// `out` must be writable.
#[no_mangle]
pub unsafe extern "C" fn lr_route_med(route: lr_route_t, out: *mut u32) -> i32 {
    guarded(
        || {
            let Some(r) = as_route(route) else { return -1 };
            if out.is_null() {
                return -1;
            }
            match policy_bgp::med(r) {
                Some(v) => {
                    unsafe { *out = v };
                    0
                }
                None => 1,
            }
        },
        LR_ERR_PANIC,
    )
}

/// Set the BGP ORIGIN (RFC 4271 §5.1.1): [`LR_ORIGIN_IGP`],
/// [`LR_ORIGIN_EGP`] or [`LR_ORIGIN_INCOMPLETE`]. Returns 0, -1 null,
/// -3 unknown origin value.
///
/// # Safety
/// `route` must be a live handle.
#[no_mangle]
pub unsafe extern "C" fn lr_route_set_origin(route: lr_route_t, origin: u8) -> i32 {
    guarded(
        || {
            let Some(r) = as_route(route) else { return -1 };
            if origin > LR_ORIGIN_INCOMPLETE {
                set_last_error(format!("unknown ORIGIN value {origin}"));
                return -3;
            }
            r.attributes.insert(Attribute {
                tag: AttrTag::raw(TAG_ORIGIN),
                flags: FLAGS_ORIGIN,
                value: vec![origin],
            });
            0
        },
        LR_ERR_PANIC,
    )
}

/// Read ORIGIN into `out`. 0 present, 1 absent, -1 null.
///
/// # Safety
/// `out` must be writable.
#[no_mangle]
pub unsafe extern "C" fn lr_route_origin(route: lr_route_t, out: *mut u8) -> i32 {
    guarded(
        || {
            let Some(r) = as_route(route) else { return -1 };
            if out.is_null() {
                return -1;
            }
            match r.attributes.get(AttrTag::raw(TAG_ORIGIN)) {
                Some(a) if !a.value.is_empty() => {
                    unsafe { *out = a.value[0] };
                    0
                }
                _ => 1,
            }
        },
        LR_ERR_PANIC,
    )
}

/// Replace the AS_PATH with a flat sequence (RFC 4271 §4.3). An empty
/// sequence drops the attribute. 0 ok, -1 null.
///
/// # Safety
/// `asns` must point to `count` readable `u32`s when non-null.
#[no_mangle]
pub unsafe extern "C" fn lr_route_set_as_path(
    route: lr_route_t,
    asns: *const u32,
    count: usize,
) -> i32 {
    guarded(
        || {
            let Some(r) = as_route(route) else { return -1 };
            let seq: Vec<Asn> = if asns.is_null() || count == 0 {
                Vec::new()
            } else {
                unsafe { std::slice::from_raw_parts(asns, count) }
                    .iter()
                    .map(|a| Asn(*a))
                    .collect()
            };
            policy_bgp::set_as_sequence(r, seq);
            0
        },
        LR_ERR_PANIC,
    )
}

/// Read the AS_PATH's flat sequence. Call with `out = NULL` to get the
/// required length; with a buffer, returns the number of ASes written.
/// Negative on null handle / buffer smaller than needed.
///
/// # Safety
/// `out` (when non-null) must be writable for `cap` `u32`s.
#[no_mangle]
pub unsafe extern "C" fn lr_route_as_path(route: lr_route_t, out: *mut u32, cap: usize) -> i64 {
    guarded(
        || {
            let Some(r) = as_route(route) else { return -1 };
            let seq = policy_bgp::as_sequence(r);
            let n = seq.len();
            if out.is_null() {
                return n as i64;
            }
            if cap < n {
                return -3;
            }
            for (i, a) in seq.iter().enumerate() {
                unsafe { *out.add(i) = a.0 };
            }
            n as i64
        },
        LR_ERR_PANIC as i64,
    )
}

/// Append one standard community (RFC 1997 §4). The ASN must fit 16
/// bits — 4-octet-AS communities ride LARGE_COMMUNITIES (RFC 8097).
/// 0 ok, -1 null, -3 ASN > 0xFFFF.
///
/// # Safety
/// `route` must be a live handle.
#[no_mangle]
pub unsafe extern "C" fn lr_route_add_community(route: lr_route_t, asn: u32, value: u16) -> i32 {
    guarded(
        || {
            let Some(r) = as_route(route) else { return -1 };
            let Ok(asn16) = u16::try_from(asn) else {
                set_last_error(format!("community ASN {asn} does not fit 16 bits"));
                return -3;
            };
            policy_bgp::add_community(r, lr_bgp::path::communities::Community::new(asn16, value));
            0
        },
        LR_ERR_PANIC,
    )
}

/// Replace the whole standard COMMUNITIES attribute from packed
/// `asn << 16 | value` items. An empty set drops the attribute.
///
/// # Safety
/// `items` must point to `count` readable `u64`s when non-null.
#[no_mangle]
pub unsafe extern "C" fn lr_route_set_communities(
    route: lr_route_t,
    items: *const u64,
    count: usize,
) -> i32 {
    guarded(
        || {
            let Some(r) = as_route(route) else { return -1 };
            let raw: Vec<u64> = if items.is_null() || count == 0 {
                Vec::new()
            } else {
                unsafe { std::slice::from_raw_parts(items, count) }.to_vec()
            };
            let mut cs = Vec::with_capacity(raw.len());
            for v in raw {
                let asn = (v >> 16) as u32;
                let val = (v & 0xFFFF) as u16;
                let Ok(asn16) = u16::try_from(asn) else {
                    set_last_error(format!("community ASN {asn} does not fit 16 bits"));
                    return -3;
                };
                cs.push(lr_bgp::path::communities::Community::new(asn16, val));
            }
            policy_bgp::set_communities(r, cs);
            0
        },
        LR_ERR_PANIC,
    )
}

/// Read the standard communities as packed `asn << 16 | value`.
/// `out = NULL` → required length; otherwise the count written.
///
/// # Safety
/// `out` (when non-null) must be writable for `cap` `u64`s.
#[no_mangle]
pub unsafe extern "C" fn lr_route_communities(route: lr_route_t, out: *mut u64, cap: usize) -> i64 {
    guarded(
        || {
            let Some(r) = as_route(route) else { return -1 };
            let cs = policy_bgp::communities(r);
            if out.is_null() {
                return cs.len() as i64;
            }
            if cap < cs.len() {
                return -3;
            }
            for (i, c) in cs.iter().enumerate() {
                unsafe { *out.add(i) = c.as_u32() as u64 };
            }
            cs.len() as i64
        },
        LR_ERR_PANIC as i64,
    )
}

/// Append one large community (RFC 8097).
///
/// # Safety
/// `route` must be a live handle.
#[no_mangle]
pub unsafe extern "C" fn lr_route_add_large_community(
    route: lr_route_t,
    global_admin: u32,
    local_data1: u32,
    local_data2: u32,
) -> i32 {
    guarded(
        || {
            let Some(r) = as_route(route) else { return -1 };
            policy_bgp::add_large_community(
                r,
                lr_bgp::path::communities::LargeCommunity::new(
                    global_admin,
                    local_data1,
                    local_data2,
                ),
            );
            0
        },
        LR_ERR_PANIC,
    )
}

/// Replace the whole LARGE_COMMUNITIES attribute from flat triples.
///
/// # Safety
/// `triples` must point to `count * 3` readable `u32`s when non-null.
#[no_mangle]
pub unsafe extern "C" fn lr_route_set_large_communities(
    route: lr_route_t,
    triples: *const u32,
    count: usize,
) -> i32 {
    guarded(
        || {
            let Some(r) = as_route(route) else { return -1 };
            let flat: Vec<u32> = if triples.is_null() || count == 0 {
                Vec::new()
            } else {
                unsafe { std::slice::from_raw_parts(triples, count * 3) }.to_vec()
            };
            let cs: Vec<lr_bgp::path::communities::LargeCommunity> = flat
                .as_chunks::<3>()
                .0
                .iter()
                .map(|t| lr_bgp::path::communities::LargeCommunity::new(t[0], t[1], t[2]))
                .collect();
            policy_bgp::set_large_communities(r, cs);
            0
        },
        LR_ERR_PANIC,
    )
}

/// Read the large communities as flat triples. `out = NULL` →
/// required `u32` count (3 * entries); otherwise the count written.
///
/// # Safety
/// `out` (when non-null) must be writable for `cap` `u32`s.
#[no_mangle]
pub unsafe extern "C" fn lr_route_large_communities(
    route: lr_route_t,
    out: *mut u32,
    cap: usize,
) -> i64 {
    guarded(
        || {
            let Some(r) = as_route(route) else { return -1 };
            let cs = policy_bgp::large_communities(r);
            let n = cs.len() * 3;
            if out.is_null() {
                return n as i64;
            }
            if cap < n {
                return -3;
            }
            for (i, c) in cs.iter().enumerate() {
                unsafe { *out.add(i * 3) = c.global_admin };
                unsafe { *out.add(i * 3 + 1) = c.local_data1 };
                unsafe { *out.add(i * 3 + 2) = c.local_data2 };
            }
            n as i64
        },
        LR_ERR_PANIC as i64,
    )
}

/// Append one extended community (RFC 4360).
///
/// # Safety
/// `route` must be a live handle.
#[no_mangle]
pub unsafe extern "C" fn lr_route_add_ext_community(
    route: lr_route_t,
    kind: u8,
    subtype: u8,
    global: u32,
    local: u16,
) -> i32 {
    guarded(
        || {
            let Some(r) = as_route(route) else { return -1 };
            policy_bgp::add_ext_community(
                r,
                lr_bgp::path::communities::ExtendedCommunity::new(kind, subtype, global, local),
            );
            0
        },
        LR_ERR_PANIC,
    )
}

/// Replace the whole EXTENDED_COMMUNITIES attribute.
///
/// # Safety
/// `items` must point to `count` readable `lr_ext_comm_t`s when
/// non-null.
#[no_mangle]
pub unsafe extern "C" fn lr_route_set_ext_communities(
    route: lr_route_t,
    items: *const lr_ext_comm_t,
    count: usize,
) -> i32 {
    guarded(
        || {
            let Some(r) = as_route(route) else { return -1 };
            let raw: Vec<lr_ext_comm_t> = if items.is_null() || count == 0 {
                Vec::new()
            } else {
                unsafe { std::slice::from_raw_parts(items, count) }.to_vec()
            };
            let cs = raw
                .into_iter()
                .map(|e| {
                    lr_bgp::path::communities::ExtendedCommunity::new(
                        e.kind, e.subtype, e.global, e.local,
                    )
                })
                .collect();
            policy_bgp::set_ext_communities(r, cs);
            0
        },
        LR_ERR_PANIC,
    )
}

/// Read the extended communities. `out = NULL` → required length,
/// otherwise the count written.
///
/// # Safety
/// `out` (when non-null) must be writable for `cap` `lr_ext_comm_t`s.
#[no_mangle]
pub unsafe extern "C" fn lr_route_ext_communities(
    route: lr_route_t,
    out: *mut lr_ext_comm_t,
    cap: usize,
) -> i64 {
    guarded(
        || {
            let Some(r) = as_route(route) else { return -1 };
            let cs = policy_bgp::ext_communities(r);
            if out.is_null() {
                return cs.len() as i64;
            }
            if cap < cs.len() {
                return -3;
            }
            for (i, c) in cs.iter().enumerate() {
                unsafe {
                    *out.add(i) = lr_ext_comm_t {
                        kind: c.kind,
                        subtype: c.subtype,
                        global: c.global,
                        local: c.local,
                    }
                };
            }
            cs.len() as i64
        },
        LR_ERR_PANIC as i64,
    )
}

/// Set the route's metric (the cross-protocol preference metric).
/// 0 / -1.
///
/// # Safety
/// `route` must be a live handle.
#[no_mangle]
pub unsafe extern "C" fn lr_route_set_metric(route: lr_route_t, value: u32) -> i32 {
    guarded(
        || {
            let Some(r) = as_route(route) else { return -1 };
            r.preference.metric = value;
            0
        },
        LR_ERR_PANIC,
    )
}

/// Read the route's metric. 0 / -1.
///
/// # Safety
/// `out` must be writable.
#[no_mangle]
pub unsafe extern "C" fn lr_route_metric(route: lr_route_t, out: *mut u32) -> i32 {
    guarded(
        || {
            let Some(r) = as_route(route) else { return -1 };
            if out.is_null() {
                return -1;
            }
            unsafe { *out = r.preference.metric };
            0
        },
        LR_ERR_PANIC,
    )
}

/// Set the operator route tag (`None` when `has_tag` is 0). 0 / -1.
///
/// # Safety
/// `route` must be a live handle.
#[no_mangle]
pub unsafe extern "C" fn lr_route_set_tag(route: lr_route_t, has_tag: i32, tag: u32) -> i32 {
    guarded(
        || {
            let Some(r) = as_route(route) else { return -1 };
            r.tag = if has_tag != 0 { Some(tag) } else { None };
            0
        },
        LR_ERR_PANIC,
    )
}

/// Read the route tag. 0 present, 1 absent, -1 null.
///
/// # Safety
/// `out` must be writable.
#[no_mangle]
pub unsafe extern "C" fn lr_route_tag(route: lr_route_t, out: *mut u32) -> i32 {
    guarded(
        || {
            let Some(r) = as_route(route) else { return -1 };
            if out.is_null() {
                return -1;
            }
            match r.tag {
                Some(t) => {
                    unsafe { *out = t };
                    0
                }
                None => 1,
            }
        },
        LR_ERR_PANIC,
    )
}

// ============================================================
// Prefix list
// ============================================================

/// Create an empty prefix-list. NULL on panic.
#[no_mangle]
pub extern "C" fn lr_prefix_list_new() -> lr_prefix_list_t {
    guarded(
        || Box::into_raw(Box::new(PrefixList::new())) as lr_prefix_list_t,
        std::ptr::null_mut(),
    )
}

/// Free a prefix-list. NULL is a no-op.
///
/// # Safety
/// `list` must be null or a handle from `lr_prefix_list_new` that has
/// not been freed or consumed by `lr_resolver_add_prefix_list`.
#[no_mangle]
pub unsafe extern "C" fn lr_prefix_list_free(list: lr_prefix_list_t) {
    guarded(
        || {
            if !list.is_null() {
                drop(unsafe { Box::from_raw(list as *mut PrefixList) });
            }
        },
        (),
    )
}

/// Append one entry: `prefix` with the ge/le length window (FRR
/// `ge`/`le`; `le = 255` means no upper bound) and `permit` (non-zero
/// = permit). First matching entry decides; no match denies.
/// 0 ok, -1 null, -3 malformed prefix.
///
/// # Safety
/// `list` must be a live handle; `prefix` a readable `lr_prefix_t`.
#[no_mangle]
pub unsafe extern "C" fn lr_prefix_list_add(
    list: lr_prefix_list_t,
    prefix: *const lr_prefix_t,
    ge: u8,
    le: u8,
    permit: i32,
) -> i32 {
    guarded(
        || {
            if list.is_null() || prefix.is_null() {
                return -1;
            }
            let Some(p) = (unsafe { prefix_from_c(prefix) }) else {
                set_last_error("invalid prefix length".to_string());
                return -3;
            };
            let mut entry = PrefixListEntry::new(p, permit != 0);
            entry.ge = ge;
            entry.le = le;
            let l = unsafe { &mut *(list as *mut PrefixList) };
            l.push(entry);
            0
        },
        LR_ERR_PANIC,
    )
}

/// Evaluate the list against `prefix`: 1 = permit, 0 = deny (implicit
/// deny included), -1 null.
///
/// # Safety
/// `list` must be a live handle; `prefix` a readable `lr_prefix_t`.
#[no_mangle]
pub unsafe extern "C" fn lr_prefix_list_match(
    list: lr_prefix_list_t,
    prefix: *const lr_prefix_t,
) -> i32 {
    guarded(
        || {
            if list.is_null() || prefix.is_null() {
                return -1;
            }
            let Some(p) = (unsafe { prefix_from_c(prefix) }) else {
                set_last_error("invalid prefix length".to_string());
                return -3;
            };
            let l = unsafe { &*(list as *const PrefixList) };
            if l.evaluate(&p) {
                1
            } else {
                0
            }
        },
        LR_ERR_PANIC,
    )
}

// ============================================================
// Route map
// ============================================================

/// Create an empty route-map. NULL on panic.
#[no_mangle]
pub extern "C" fn lr_route_map_new() -> lr_route_map_t {
    guarded(
        || Box::into_raw(Box::new(RouteMap::new())) as lr_route_map_t,
        std::ptr::null_mut(),
    )
}

/// Free a route-map. NULL is a no-op.
///
/// # Safety
/// `map` must be null or a handle from `lr_route_map_new` that has not
/// been freed.
#[no_mangle]
pub unsafe extern "C" fn lr_route_map_free(map: lr_route_map_t) {
    guarded(
        || {
            if !map.is_null() {
                drop(unsafe { Box::from_raw(map as *mut RouteMap) });
            }
        },
        (),
    )
}

/// Append one entry: all `matches` must hold, then all `sets` apply
/// and `verdict` decides ([`LR_VERDICT_CONTINUE`] falls through to the
/// next entry). Entries are tried in insertion order. 0 ok, -1 null,
/// -3 malformed match/set or prefix length.
///
/// # Safety
/// `map` must be a live handle; the arrays readable for `n_matches` /
/// `n_sets` items when non-null.
#[no_mangle]
pub unsafe extern "C" fn lr_route_map_add_entry(
    map: lr_route_map_t,
    matches: *const lr_match_t,
    n_matches: usize,
    sets: *const lr_set_t,
    n_sets: usize,
    verdict: i32,
) -> i32 {
    guarded(
        || {
            if map.is_null() {
                return -1;
            }
            let mut conds: Vec<MatchCondition> = Vec::new();
            if !matches.is_null() && n_matches > 0 {
                for m in unsafe { std::slice::from_raw_parts(matches, n_matches) } {
                    let cond = match m.kind {
                        LR_MATCH_PREFIX_IN => MatchCondition::PrefixIn { list_id: m.list_id },
                        LR_MATCH_AS_PATH_IN => MatchCondition::AsPathIn { list_id: m.list_id },
                        LR_MATCH_COMMUNITY_IN => MatchCondition::CommunityIn { list_id: m.list_id },
                        LR_MATCH_NEXT_HOP_IN => MatchCondition::NextHopIn { list_id: m.list_id },
                        LR_MATCH_PROTOCOL_IS => {
                            let Some(proto) = protocol_from_i32(m.protocol as i32) else {
                                set_last_error(format!("unknown protocol id {}", m.protocol));
                                return -3;
                            };
                            MatchCondition::ProtocolIs {
                                proto: policy_proto_id(proto),
                            }
                        }
                        other => {
                            set_last_error(format!("unknown match kind {other}"));
                            return -3;
                        }
                    };
                    conds.push(cond);
                }
            }
            let mut actions: Vec<SetAction> = Vec::new();
            if !sets.is_null() && n_sets > 0 {
                for s in unsafe { std::slice::from_raw_parts(sets, n_sets) } {
                    let action = match s.kind {
                        LR_SET_LOCAL_PREF => SetAction::SetLocalPref(s.value),
                        LR_SET_MED => SetAction::SetMed(s.value),
                        LR_SET_METRIC => SetAction::SetMetric(s.value),
                        LR_SET_TAG => SetAction::SetTag(s.value),
                        LR_SET_PREPEND_AS => SetAction::PrependAs(Asn(s.value)),
                        LR_SET_ADD_COMMUNITY => {
                            let Ok(asn16) = u16::try_from(s.value) else {
                                set_last_error(format!(
                                    "community ASN {} does not fit 16 bits",
                                    s.value
                                ));
                                return -3;
                            };
                            SetAction::AddCommunity(Asn(asn16 as u32), s.value2)
                        }
                        LR_SET_NEXT_HOP => {
                            if s.is_ipv6 != 0 {
                                SetAction::SetNextHop(IpAddr::V6(s.addr))
                            } else {
                                SetAction::SetNextHop(IpAddr::V4([
                                    s.addr[0], s.addr[1], s.addr[2], s.addr[3],
                                ]))
                            }
                        }
                        other => {
                            set_last_error(format!("unknown set kind {other}"));
                            return -3;
                        }
                    };
                    actions.push(action);
                }
            }
            let verdict = match verdict {
                LR_VERDICT_CONTINUE => None,
                LR_VERDICT_PERMIT => Some(true),
                LR_VERDICT_DENY => Some(false),
                other => {
                    set_last_error(format!("unknown verdict {other}"));
                    return -3;
                }
            };
            let m = unsafe { &mut *(map as *mut RouteMap) };
            m.push(RouteMapEntry {
                matches: conds,
                sets: actions,
                verdict,
            });
            0
        },
        LR_ERR_PANIC,
    )
}

/// FRR route-map evaluation over a live route handle: the first
/// matching entry applies its sets and its verdict lands in `out`
/// ([`LR_EVAL_PERMIT`] / [`LR_EVAL_DENY`] / [`LR_EVAL_FALLTHROUGH`]).
/// Mutations are visible to subsequent `lr_route_*` reads.
/// 0 ok, -1 null, -2 invalid handle.
///
/// `resolver` may be NULL: then every list-backed match fails
/// (fail-closed, FRR unknown-list semantics).
///
/// # Safety
/// `map` / `route` must be live handles; `resolver` null or live.
#[no_mangle]
pub unsafe extern "C" fn lr_route_map_evaluate(
    map: lr_route_map_t,
    route: lr_route_t,
    resolver: lr_resolver_t,
    out: *mut i32,
) -> i32 {
    guarded(
        || {
            if map.is_null() || route.is_null() || out.is_null() {
                return -1;
            }
            let m = unsafe { &*(map as *const RouteMap) };
            let r = unsafe { &mut *(route as *mut Route) };
            let verdict = if resolver.is_null() {
                m.evaluate(r, &DenyAllResolver)
            } else {
                let set = unsafe { &*(resolver as *const PolicySet) };
                m.evaluate(r, set)
            };
            unsafe {
                *out = match verdict {
                    Some(true) => LR_EVAL_PERMIT,
                    Some(false) => LR_EVAL_DENY,
                    None => LR_EVAL_FALLTHROUGH,
                }
            };
            0
        },
        LR_ERR_PANIC,
    )
}

/// Fail-closed stand-in for a missing resolver: every list-backed
/// match denies, `protocol is` still works (it needs no lists).
struct DenyAllResolver;

impl lr_policy::action::MatchResolver for DenyAllResolver {
    fn prefix_in(&self, _id: u32, _p: &Prefix) -> bool {
        false
    }
    fn as_path_in(&self, _id: u32, _r: &Route) -> bool {
        false
    }
    fn community_in(&self, _id: u32, _r: &Route) -> bool {
        false
    }
    fn next_hop_in(&self, _id: u32, _r: &Route) -> bool {
        false
    }
}

// ============================================================
// Resolver (PolicySet-backed)
// ============================================================

/// Create an empty policy resolver. NULL on panic.
#[no_mangle]
pub extern "C" fn lr_resolver_new() -> lr_resolver_t {
    guarded(
        || Box::into_raw(Box::new(PolicySet::new())) as lr_resolver_t,
        std::ptr::null_mut(),
    )
}

/// Free a resolver. Registered policy objects go with it.
///
/// # Safety
/// `resolver` must be null or a handle from `lr_resolver_new` that has
/// not been freed.
#[no_mangle]
pub unsafe extern "C" fn lr_resolver_free(resolver: lr_resolver_t) {
    guarded(
        || {
            if !resolver.is_null() {
                drop(unsafe { Box::from_raw(resolver as *mut PolicySet) });
            }
        },
        (),
    )
}

/// Register the prefix-list under `name` (NUL-terminated). The list is
/// COPIED into the resolver; the caller keeps ownership of the handle.
/// Returns the numeric list id for `lr_match_t.list_id` (>= 0), or
/// -1/-3 on null/malformed.
///
/// # Safety
/// `resolver` must be live; `name` a readable NUL-terminated string;
/// `list` a live handle.
#[no_mangle]
pub unsafe extern "C" fn lr_resolver_add_prefix_list(
    resolver: lr_resolver_t,
    name: *const std::ffi::c_char,
    list: lr_prefix_list_t,
) -> i32 {
    guarded(
        || {
            if resolver.is_null() || list.is_null() {
                return -1;
            }
            let Some(name) = (unsafe { read_str(name) }) else {
                set_last_error("null or non-UTF-8 prefix-list name".to_string());
                return -3;
            };
            let l = unsafe { &*(list as *const PrefixList) };
            let set = unsafe { &mut *(resolver as *mut PolicySet) };
            let id = set.add_prefix_list(name, l.clone());
            i32::try_from(id).unwrap_or(i32::MAX)
        },
        LR_ERR_PANIC,
    )
}

/// Register an AS-path access-list (FRR dialect) under `name`. Returns
/// the list id, or -1/-3.
///
/// # Safety
/// `resolver` must be live; `filters` readable for `count` items, each
/// `pattern` a readable NUL-terminated string.
#[no_mangle]
pub unsafe extern "C" fn lr_resolver_add_as_path_list(
    resolver: lr_resolver_t,
    name: *const std::ffi::c_char,
    filters: *const lr_as_path_filter_t,
    count: usize,
) -> i32 {
    guarded(
        || {
            if resolver.is_null() {
                return -1;
            }
            let Some(name) = (unsafe { read_str(name) }) else {
                set_last_error("null or non-UTF-8 as-path list name".to_string());
                return -3;
            };
            let mut list = Vec::with_capacity(count);
            if !filters.is_null() && count > 0 {
                for f in unsafe { std::slice::from_raw_parts(filters, count) } {
                    let Some(pattern) = (unsafe { read_str(f.pattern) }) else {
                        set_last_error("null or non-UTF-8 as-path pattern".to_string());
                        return -3;
                    };
                    list.push(AsPathFilter {
                        pattern: pattern.to_string(),
                        permit: f.permit != 0,
                    });
                }
            }
            let set = unsafe { &mut *(resolver as *mut PolicySet) };
            let id = set.add_as_path_list(name, list);
            i32::try_from(id).unwrap_or(i32::MAX)
        },
        LR_ERR_PANIC,
    )
}

/// Register a standard community list (RFC 1997) under `name`. Returns
/// the list id, or -1/-3.
///
/// # Safety
/// `resolver` must be live; `entries` readable for `count` items, each
/// `communities` array readable for its `count`.
#[no_mangle]
pub unsafe extern "C" fn lr_resolver_add_community_list(
    resolver: lr_resolver_t,
    name: *const std::ffi::c_char,
    entries: *const lr_community_entry_t,
    count: usize,
) -> i32 {
    guarded(
        || {
            if resolver.is_null() {
                return -1;
            }
            let Some(name) = (unsafe { read_str(name) }) else {
                set_last_error("null or non-UTF-8 community list name".to_string());
                return -3;
            };
            let mut list = Vec::with_capacity(count);
            if !entries.is_null() && count > 0 {
                for e in unsafe { std::slice::from_raw_parts(entries, count) } {
                    let comms: Vec<u32> = if e.communities.is_null() || e.count == 0 {
                        Vec::new()
                    } else {
                        unsafe { std::slice::from_raw_parts(e.communities, e.count) }
                            .iter()
                            .map(|v| *v as u32)
                            .collect()
                    };
                    list.push(CommunityListEntry {
                        communities: comms,
                        permit: e.permit != 0,
                    });
                }
            }
            let set = unsafe { &mut *(resolver as *mut PolicySet) };
            let id = set.add_community_list(name, {
                let mut cl = lr_policy::community_list::CommunityList::new();
                for e in list {
                    cl.push(e);
                }
                cl
            });
            i32::try_from(id).unwrap_or(i32::MAX)
        },
        LR_ERR_PANIC,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::handle::lr_route_t;

    fn v4_route(octets: [u8; 4], len: u8) -> lr_route_t {
        let mut addr = [0u8; 16];
        addr[..4].copy_from_slice(&octets);
        unsafe { lr_route_new_v4(addr.as_ptr(), len, LrProtocol::Bgp as i32) }
    }

    #[test]
    fn route_attribute_round_trip() {
        let r = v4_route([203, 0, 113, 0], 24);
        assert!(!r.is_null());

        // next hop both families
        let nh6: [u8; 16] = {
            let mut a = [0u8; 16];
            a[15] = 1;
            a
        };
        assert_eq!(unsafe { lr_route_set_next_hop(r, nh6.as_ptr(), 1) }, 0);
        let mut out = [0u8; 16];
        let mut is_v6: i32 = -1;
        assert_eq!(
            unsafe { lr_route_next_hop(r, out.as_mut_ptr(), &mut is_v6) },
            0
        );
        assert_eq!(is_v6, 1);
        assert_eq!(out, nh6);

        let v4 = [192u8, 0, 2, 1];
        assert_eq!(unsafe { lr_route_set_next_hop(r, v4.as_ptr(), 0) }, 0);
        assert_eq!(
            unsafe { lr_route_next_hop(r, out.as_mut_ptr(), &mut is_v6) },
            0
        );
        assert_eq!(is_v6, 0);

        // local pref / med / metric / tag / origin
        assert_eq!(unsafe { lr_route_set_local_pref(r, 250) }, 0);
        let mut v: u32 = 0;
        assert_eq!(unsafe { lr_route_local_pref(r, &mut v) }, 0);
        assert_eq!(v, 250);
        let mut m: u32 = 0;
        assert_eq!(unsafe { lr_route_med(r, &mut m) }, 1); // absent
        assert_eq!(unsafe { lr_route_set_med(r, 50) }, 0);
        assert_eq!(unsafe { lr_route_med(r, &mut m) }, 0);
        assert_eq!(m, 50);
        assert_eq!(unsafe { lr_route_set_metric(r, 42) }, 0);
        let mut v: u32 = 0;
        assert_eq!(unsafe { lr_route_metric(r, &mut v) }, 0);
        assert_eq!(v, 42);
        assert_eq!(unsafe { lr_route_set_tag(r, 1, 65000) }, 0);
        let mut v: u32 = 0;
        assert_eq!(unsafe { lr_route_tag(r, &mut v) }, 0);
        assert_eq!(v, 65000);
        assert_eq!(unsafe { lr_route_set_tag(r, 0, 0) }, 0);
        assert_eq!(unsafe { lr_route_tag(r, &mut v) }, 1);

        assert_eq!(unsafe { lr_route_set_origin(r, LR_ORIGIN_IGP) }, 0);
        let mut o: u8 = 9;
        assert_eq!(unsafe { lr_route_origin(r, &mut o) }, 0);
        assert_eq!(o, LR_ORIGIN_IGP);
        assert_eq!(unsafe { lr_route_set_origin(r, 7) }, -3);
        assert_eq!(unsafe { lr_route_set_origin(std::ptr::null_mut(), 0) }, -1);

        unsafe { lr_route_free(r) };
    }

    #[test]
    fn as_path_and_communities_round_trip() {
        let r = v4_route([198, 51, 100, 0], 24);

        // AS_PATH: set, size-probe, read back.
        let path: [u32; 3] = [64513, 65010, 64512];
        assert_eq!(unsafe { lr_route_set_as_path(r, path.as_ptr(), 3) }, 0);
        let n = unsafe { lr_route_as_path(r, std::ptr::null_mut(), 0) };
        assert_eq!(n, 3);
        let mut got = [0u32; 3];
        assert_eq!(unsafe { lr_route_as_path(r, got.as_mut_ptr(), 2) }, -3); // too small
        assert_eq!(unsafe { lr_route_as_path(r, got.as_mut_ptr(), 3) }, 3);
        assert_eq!(got, path);
        // Empty sequence drops the attribute.
        assert_eq!(unsafe { lr_route_set_as_path(r, std::ptr::null(), 0) }, 0);
        assert_eq!(unsafe { lr_route_as_path(r, std::ptr::null_mut(), 0) }, 0);

        // Standard communities (packed asn<<16|val).
        let comms: [u64; 2] = [(64512u64 << 16) | 100, (65000u64 << 16) | 7];
        assert_eq!(unsafe { lr_route_set_communities(r, comms.as_ptr(), 2) }, 0);
        assert_eq!(unsafe { lr_route_add_community(r, 64512, 100) }, 0); // duplicate: not added
        let n = unsafe { lr_route_communities(r, std::ptr::null_mut(), 0) };
        assert_eq!(n, 2);
        let mut got = [0u64; 2];
        assert_eq!(unsafe { lr_route_communities(r, got.as_mut_ptr(), 2) }, 2);
        assert_eq!(got, comms);
        assert_eq!(unsafe { lr_route_add_community(r, 4294967295, 1) }, -3); // ASN > 16 bits

        // Large communities (flat triples).
        let triples: [u32; 6] = [4200000000, 7, 9, 64512, 1, 2];
        assert_eq!(
            unsafe { lr_route_set_large_communities(r, triples.as_ptr(), 2) },
            0
        );
        assert_eq!(unsafe { lr_route_add_large_community(r, 1, 2, 3) }, 0);
        let n = unsafe { lr_route_large_communities(r, std::ptr::null_mut(), 0) };
        assert_eq!(n, 9);
        let mut got = [0u32; 9];
        assert_eq!(
            unsafe { lr_route_large_communities(r, got.as_mut_ptr(), 9) },
            9
        );
        assert_eq!(&got[..6], &triples);
        assert_eq!(&got[6..], &[1, 2, 3]);

        // Extended communities.
        assert_eq!(
            unsafe { lr_route_add_ext_community(r, 0x42, 0x02, 64512, 5) },
            0
        );
        let n = unsafe { lr_route_ext_communities(r, std::ptr::null_mut(), 0) };
        assert_eq!(n, 1);
        let mut got = [lr_ext_comm_t {
            kind: 0,
            subtype: 0,
            global: 0,
            local: 0,
        }; 1];
        assert_eq!(
            unsafe { lr_route_ext_communities(r, got.as_mut_ptr(), 1) },
            1
        );
        assert_eq!(got[0].kind, 0x42);
        assert_eq!(got[0].subtype, 0x02);
        assert_eq!(got[0].global, 64512);
        assert_eq!(got[0].local, 5);

        unsafe { lr_route_free(r) };
    }

    #[test]
    fn route_construction_rejections() {
        let mut addr = [0u8; 16];
        addr[0] = 203;
        // bad v4 length
        assert!(unsafe { lr_route_new_v4(addr.as_ptr(), 33, 0) }.is_null());
        // unknown protocol
        assert!(unsafe { lr_route_new_v4(addr.as_ptr(), 24, 77) }.is_null());
        // null octets
        assert!(unsafe { lr_route_new_v4(std::ptr::null(), 24, 0) }.is_null());
        // v6 with an illegal length (> 128)
        assert!(unsafe { lr_route_new_v6(addr.as_ptr(), 129, 0) }.is_null());
        let v6: [u8; 16] = {
            let mut a = [0u8; 16];
            a[0] = 0x20;
            a[1] = 0x01;
            a
        };
        assert!(!unsafe { lr_route_new_v6(v6.as_ptr(), 48, LrProtocol::Babel as i32) }.is_null());
        unsafe { lr_route_free(std::ptr::null_mut()) }; // no-op
    }

    #[test]
    fn prefix_list_match_semantics() {
        let l = lr_prefix_list_new();
        let p8 = {
            let mut p = lr_prefix_t {
                addr: [0u8; 16],
                is_ipv6: 0,
                prefix_len: 8,
            };
            p.addr[0] = 10;
            p
        };
        // permit 10.0.0.0/8 ge 16 le 24
        assert_eq!(unsafe { lr_prefix_list_add(l, &p8, 16, 24, 1) }, 0);
        let inside = {
            let mut p = lr_prefix_t {
                addr: [0u8; 16],
                is_ipv6: 0,
                prefix_len: 24,
            };
            p.addr[0] = 10;
            p.addr[1] = 1;
            p
        };
        let shorter = {
            let mut p = inside;
            p.prefix_len = 8;
            p
        };
        let longer = {
            let mut p = inside;
            p.prefix_len = 25;
            p
        };
        assert_eq!(unsafe { lr_prefix_list_match(l, &inside) }, 1);
        assert_eq!(unsafe { lr_prefix_list_match(l, &shorter) }, 0); // ge gate
        assert_eq!(unsafe { lr_prefix_list_match(l, &longer) }, 0); // le gate
                                                                    // implicit deny for a disjoint prefix
        let other = {
            let mut p = lr_prefix_t {
                addr: [0u8; 16],
                is_ipv6: 0,
                prefix_len: 24,
            };
            p.addr[0] = 192;
            p
        };
        assert_eq!(unsafe { lr_prefix_list_match(l, &other) }, 0);
        assert_eq!(
            unsafe { lr_prefix_list_add(l, std::ptr::null(), 0, 255, 1) },
            -1
        );
        unsafe { lr_prefix_list_free(l) };
        unsafe { lr_prefix_list_free(std::ptr::null_mut()) };
    }

    #[test]
    fn route_map_evaluate_with_resolver() {
        // Resolver: prefix-list "all-v4" (id 0) permits everything;
        // community list "rich" (id 0) permits 64512:100.
        let resolver = lr_resolver_new();
        let list = lr_prefix_list_new();
        let any = {
            let mut p = lr_prefix_t {
                addr: [0u8; 16],
                is_ipv6: 0,
                prefix_len: 0,
            };
            p.addr[0] = 10;
            p
        };
        assert_eq!(unsafe { lr_prefix_list_add(list, &any, 0, 32, 1) }, 0);
        let id = unsafe { lr_resolver_add_prefix_list(resolver, c"all-v4".as_ptr(), list) };
        assert_eq!(id, 0);

        let comm = [(64512u64 << 16) | 100];
        let comm_entry = lr_community_entry_t {
            communities: comm.as_ptr(),
            count: 1,
            permit: 1,
        };
        let cid =
            unsafe { lr_resolver_add_community_list(resolver, c"rich".as_ptr(), &comm_entry, 1) };
        assert_eq!(cid, 0);

        // Route-map: entry 10 = match prefix-list 0 -> set local-pref 250, permit.
        let map = lr_route_map_new();
        let m = [lr_match_t {
            kind: LR_MATCH_PREFIX_IN,
            list_id: 0,
            protocol: 0,
        }];
        let s = [lr_set_t {
            kind: LR_SET_LOCAL_PREF,
            is_ipv6: 0,
            addr: [0u8; 16],
            value: 250,
            value2: 0,
        }];
        assert_eq!(
            unsafe { lr_route_map_add_entry(map, m.as_ptr(), 1, s.as_ptr(), 1, LR_VERDICT_PERMIT) },
            0
        );

        let r = v4_route([203, 0, 113, 0], 24);
        let mut verdict: i32 = 9;
        assert_eq!(
            unsafe { lr_route_map_evaluate(map, r, resolver, &mut verdict) },
            0
        );
        assert_eq!(verdict, LR_EVAL_PERMIT);
        let mut lp: u32 = 0;
        assert_eq!(unsafe { lr_route_local_pref(r, &mut lp) }, 0);
        assert_eq!(lp, 250);

        // A protocol-is match (no lists needed) works even with a NULL resolver.
        let map2 = lr_route_map_new();
        let m2 = [lr_match_t {
            kind: LR_MATCH_PROTOCOL_IS,
            list_id: 0,
            protocol: LrProtocol::Bgp as u8,
        }];
        assert_eq!(
            unsafe {
                lr_route_map_add_entry(map2, m2.as_ptr(), 1, std::ptr::null(), 0, LR_VERDICT_DENY)
            },
            0
        );
        let mut verdict: i32 = 9;
        assert_eq!(
            unsafe { lr_route_map_evaluate(map2, r, std::ptr::null_mut(), &mut verdict) },
            0
        );
        assert_eq!(verdict, LR_EVAL_DENY);
        unsafe { lr_route_free(r) };

        // Fallthrough: empty map.
        let map3 = lr_route_map_new();
        let r = v4_route([203, 0, 113, 0], 24);
        let mut verdict: i32 = 9;
        assert_eq!(
            unsafe { lr_route_map_evaluate(map3, r, resolver, &mut verdict) },
            0
        );
        assert_eq!(verdict, LR_EVAL_FALLTHROUGH);

        // Rejection matrix: unknown match kind / set kind / verdict.
        let bad_m = [lr_match_t {
            kind: 99,
            list_id: 0,
            protocol: 0,
        }];
        assert_eq!(
            unsafe {
                lr_route_map_add_entry(
                    map3,
                    bad_m.as_ptr(),
                    1,
                    std::ptr::null(),
                    0,
                    LR_VERDICT_PERMIT,
                )
            },
            -3
        );
        let bad_s = [lr_set_t {
            kind: 99,
            is_ipv6: 0,
            addr: [0u8; 16],
            value: 0,
            value2: 0,
        }];
        assert_eq!(
            unsafe {
                lr_route_map_add_entry(
                    map3,
                    std::ptr::null(),
                    0,
                    bad_s.as_ptr(),
                    1,
                    LR_VERDICT_PERMIT,
                )
            },
            -3
        );
        assert_eq!(
            unsafe { lr_route_map_add_entry(map3, std::ptr::null(), 0, std::ptr::null(), 0, 5) },
            -3
        );

        unsafe { lr_route_free(r) };
        unsafe { lr_route_map_free(map) };
        unsafe { lr_route_map_free(map2) };
        unsafe { lr_route_map_free(map3) };
        unsafe { lr_resolver_free(resolver) };
        unsafe { lr_resolver_free(std::ptr::null_mut()) };
    }

    #[test]
    fn as_path_list_registration_and_match() {
        let resolver = lr_resolver_new();
        let filters = [
            lr_as_path_filter_t {
                pattern: c"^65001$".as_ptr(),
                permit: 0,
            },
            lr_as_path_filter_t {
                pattern: c"_65002_".as_ptr(),
                permit: 1,
            },
        ];
        let id = unsafe {
            lr_resolver_add_as_path_list(resolver, c"paths".as_ptr(), filters.as_ptr(), 2)
        };
        assert_eq!(id, 0);

        // Match via a route-map entry: match as-path list 0, permit.
        let map = lr_route_map_new();
        let m = [lr_match_t {
            kind: LR_MATCH_AS_PATH_IN,
            list_id: 0,
            protocol: 0,
        }];
        assert_eq!(
            unsafe {
                lr_route_map_add_entry(map, m.as_ptr(), 1, std::ptr::null(), 0, LR_VERDICT_PERMIT)
            },
            0
        );
        let r = v4_route([203, 0, 113, 0], 24);
        let path: [u32; 3] = [64513, 65002, 64512];
        assert_eq!(unsafe { lr_route_set_as_path(r, path.as_ptr(), 3) }, 0);
        let mut verdict: i32 = 9;
        assert_eq!(
            unsafe { lr_route_map_evaluate(map, r, resolver, &mut verdict) },
            0
        );
        assert_eq!(verdict, LR_EVAL_PERMIT); // _65002_ permits
        unsafe { lr_route_free(r) };
        unsafe { lr_route_map_free(map) };
        unsafe { lr_resolver_free(resolver) };
    }
}
