//! lr-core foundational types FFI.
//!
//! Stateless. Mirrors the public Rust API of `lr_core::addr::{IpAddr,
//! Prefix, Asn, RouterId}` and `lr_core::rib::{Protocol, RouteKey,
//! RouteOrigin}` so an embedder can construct and inspect the same
//! foundational values every other crate uses.
//!
//! The lr-core types are passed by value across the C ABI when small
//! enough (4 or 16 bytes for IpAddr-as-pointer), or as opaque handles
//! when boxed. The FFI uses small `lr_*_t` repr-C structs that mirror
//! the Rust types' bit layout where it is stable, and opaque pointers
//! otherwise.
//!
//! Every entry point runs inside the crate's `catch_unwind` barrier
//! ([`crate::guarded`]): a panic returns `LR_ERR_PANIC` and sets the
//! thread-local last-error string.

// The closure body passed to `guarded` is wrapped in a single `unsafe`
// block to mirror the `pub unsafe extern "C" fn` shape — the inner
// `unsafe { ... }` blocks would otherwise trip `unused_unsafe` under
// the crate's `-D warnings` clippy gate.
#![allow(unused_unsafe)]

use lr_core::addr::{Asn, IpAddr, Prefix, RouterId};
use lr_core::nlri::NlriFamily;
use lr_core::rib::{Protocol, RouteKey, RouteOrigin};

use crate::error::LR_ERR_PANIC;
use crate::guarded;

const LR_ERR_NULL: i32 = crate::error::LrError::Null as i32;

// ---- IpAddr ----

/// Repr-C IpAddr. Carries a `is_ipv6` flag plus 16 bytes (IPv4 occupies
/// the last 4; the first 12 are zero).
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct lr_ip_addr_t {
    pub is_ipv6: u8,
    /// Always 16 bytes; v4 occupies the last 4 (the first 12 are zero
    /// so the address reads as an IPv4-mapped IPv6 in the standard
    /// `::ffff:a.b.c.d` form when interpreted as IPv6).
    pub octets: [u8; 16],
}

impl From<IpAddr> for lr_ip_addr_t {
    fn from(addr: IpAddr) -> Self {
        match addr {
            IpAddr::V4(b) => {
                let mut octets = [0u8; 16];
                octets[12..16].copy_from_slice(&b);
                Self { is_ipv6: 0, octets }
            }
            IpAddr::V6(b) => Self {
                is_ipv6: 1,
                octets: b,
            },
        }
    }
}

impl From<lr_ip_addr_t> for IpAddr {
    fn from(c: lr_ip_addr_t) -> Self {
        if c.is_ipv6 != 0 {
            IpAddr::V6(c.octets)
        } else {
            let mut b = [0u8; 4];
            b.copy_from_slice(&c.octets[12..16]);
            IpAddr::V4(b)
        }
    }
}

/// Construct an IPv4 `lr_ip_addr_t` from 4 octets.
///
/// # Safety
/// `octets` must point to 4 readable bytes.
#[no_mangle]
pub unsafe extern "C" fn lr_ip_addr_v4(octets: *const u8) -> lr_ip_addr_t {
    guarded(
        || unsafe {
            if octets.is_null() {
                return lr_ip_addr_t::default();
            }
            let mut buf = [0u8; 4];
            let src = unsafe { std::slice::from_raw_parts(octets, 4) };
            buf.copy_from_slice(src);
            let mut o = [0u8; 16];
            o[12..16].copy_from_slice(&buf);
            lr_ip_addr_t {
                is_ipv6: 0,
                octets: o,
            }
        },
        lr_ip_addr_t::default(),
    )
}

/// Construct an IPv6 `lr_ip_addr_t` from 16 octets.
///
/// # Safety
/// `octets` must point to 16 readable bytes.
#[no_mangle]
pub unsafe extern "C" fn lr_ip_addr_v6(octets: *const u8) -> lr_ip_addr_t {
    guarded(
        || unsafe {
            if octets.is_null() {
                return lr_ip_addr_t::default();
            }
            let mut buf = [0u8; 16];
            let src = unsafe { std::slice::from_raw_parts(octets, 16) };
            buf.copy_from_slice(src);
            lr_ip_addr_t {
                is_ipv6: 1,
                octets: buf,
            }
        },
        lr_ip_addr_t::default(),
    )
}

/// 1 when `addr` is IPv4, 0 when IPv6 (or zero-initialized default).
#[no_mangle]
pub extern "C" fn lr_ip_addr_is_ipv4(addr: lr_ip_addr_t) -> u8 {
    guarded(|| (addr.is_ipv6 == 0) as u8, 0)
}

/// 1 when `addr` is IPv6.
#[no_mangle]
pub extern "C" fn lr_ip_addr_is_ipv6(addr: lr_ip_addr_t) -> u8 {
    guarded(|| addr.is_ipv6, 0)
}

/// 1 when `addr` is the unspecified address (0.0.0.0 or ::).
#[no_mangle]
pub extern "C" fn lr_ip_addr_is_unspecified(addr: lr_ip_addr_t) -> u8 {
    guarded(
        || {
            let a: IpAddr = addr.into();
            a.is_unspecified() as u8
        },
        0,
    )
}

/// 1 when `addr` is a multicast address (224.0.0.0/4 or ff00::/8).
#[no_mangle]
pub extern "C" fn lr_ip_addr_is_multicast(addr: lr_ip_addr_t) -> u8 {
    guarded(
        || {
            let a: IpAddr = addr.into();
            a.is_multicast() as u8
        },
        0,
    )
}

/// Copy the address's octets into the caller-supplied buffer. For IPv4
/// the buffer needs 4 bytes; for IPv6, 16 bytes. Returns the number of
/// bytes written.
///
/// # Safety
/// `out` must point to at least `cap` writable bytes.
#[no_mangle]
pub unsafe extern "C" fn lr_ip_addr_octets(addr: lr_ip_addr_t, out: *mut u8, cap: usize) -> usize {
    guarded(
        || unsafe {
            if out.is_null() || cap == 0 {
                return 0;
            }
            let a: IpAddr = addr.into();
            let octets = a.octets();
            let take = octets.len().min(cap);
            unsafe {
                std::ptr::copy_nonoverlapping(octets.as_ptr(), out, take);
            }
            take
        },
        0,
    )
}

// ---- Prefix ----

/// Repr-C Prefix. Mirrors `lr_core::addr::Prefix`.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct lr_core_prefix_t {
    pub addr: lr_ip_addr_t,
    pub prefix_len: u8,
}

impl From<Prefix> for lr_core_prefix_t {
    fn from(p: Prefix) -> Self {
        Self {
            addr: p.addr.into(),
            prefix_len: p.prefix_len,
        }
    }
}

impl From<lr_core_prefix_t> for Prefix {
    fn from(c: lr_core_prefix_t) -> Self {
        Self {
            addr: c.addr.into(),
            prefix_len: c.prefix_len,
        }
    }
}

/// Construct an IPv4 prefix from 4 octets + prefix length.
///
/// # Safety
/// `octets` must point to 4 readable bytes.
#[no_mangle]
pub unsafe extern "C" fn lr_core_prefix_v4(octets: *const u8, prefix_len: u8) -> lr_core_prefix_t {
    guarded(
        || unsafe {
            if octets.is_null() {
                return lr_core_prefix_t::default();
            }
            let mut buf = [0u8; 4];
            let src = unsafe { std::slice::from_raw_parts(octets, 4) };
            buf.copy_from_slice(src);
            let p = Prefix::new_v4(buf, prefix_len);
            p.into()
        },
        lr_core_prefix_t::default(),
    )
}

/// Construct an IPv6 prefix from 16 octets + prefix length.
///
/// # Safety
/// `octets` must point to 16 readable bytes.
#[no_mangle]
pub unsafe extern "C" fn lr_core_prefix_v6(octets: *const u8, prefix_len: u8) -> lr_core_prefix_t {
    guarded(
        || unsafe {
            if octets.is_null() {
                return lr_core_prefix_t::default();
            }
            let mut buf = [0u8; 16];
            let src = unsafe { std::slice::from_raw_parts(octets, 16) };
            buf.copy_from_slice(src);
            let p = Prefix::new_v6(buf, prefix_len);
            p.into()
        },
        lr_core_prefix_t::default(),
    )
}

/// 1 when `prefix` is IPv4.
#[no_mangle]
pub extern "C" fn lr_core_prefix_is_ipv4(prefix: lr_core_prefix_t) -> u8 {
    guarded(|| lr_ip_addr_is_ipv4(prefix.addr), 0)
}

/// 1 when `prefix` is IPv6.
#[no_mangle]
pub extern "C" fn lr_core_prefix_is_ipv6(prefix: lr_core_prefix_t) -> u8 {
    guarded(|| lr_ip_addr_is_ipv6(prefix.addr), 0)
}

/// 1 when `addr` falls within `prefix` (RFC 4632 §3.1 — bit-level
/// containment, not byte-level).
#[no_mangle]
pub extern "C" fn lr_core_prefix_contains(prefix: lr_core_prefix_t, addr: lr_ip_addr_t) -> u8 {
    guarded(
        || {
            let p: Prefix = prefix.into();
            let a: IpAddr = addr.into();
            p.contains(&a) as u8
        },
        0,
    )
}

/// 1 when `inner` falls within `outer` (bit-level containment).
#[no_mangle]
pub extern "C" fn lr_core_prefix_contains_prefix(
    outer: lr_core_prefix_t,
    inner: lr_core_prefix_t,
) -> u8 {
    guarded(
        || {
            let o: Prefix = outer.into();
            let i: Prefix = inner.into();
            o.contains_prefix(&i) as u8
        },
        0,
    )
}

/// Compute the network address (host bits zeroed). The result is
/// written into `*out`.
///
/// # Safety
/// `out` must point to a writable `lr_ip_addr_t`.
#[no_mangle]
pub unsafe extern "C" fn lr_core_prefix_network(
    prefix: lr_core_prefix_t,
    out: *mut lr_ip_addr_t,
) -> i32 {
    guarded(
        || unsafe {
            if out.is_null() {
                return LR_ERR_NULL;
            }
            let p: Prefix = prefix.into();
            unsafe { *out = p.network().into() }
            0
        },
        LR_ERR_PANIC,
    )
}

// ---- Asn ----

/// Repr-C Asn. Mirrors `lr_core::addr::Asn(pub u32)`.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct lr_asn_t {
    pub value: u32,
}

impl From<Asn> for lr_asn_t {
    fn from(a: Asn) -> Self {
        Self { value: a.as_u32() }
    }
}

impl From<lr_asn_t> for Asn {
    fn from(c: lr_asn_t) -> Self {
        Asn::new(c.value)
    }
}

/// Construct an Asn from a u32 value.
#[no_mangle]
pub extern "C" fn lr_asn_new(value: u32) -> lr_asn_t {
    guarded(|| Asn::new(value).into(), lr_asn_t::default())
}

/// 1 when the ASN is RFC 6996 private range (64512..=65534 or
/// 4200000000..=4294967294).
#[no_mangle]
pub extern "C" fn lr_asn_is_private(asn: lr_asn_t) -> u8 {
    guarded(
        || {
            let a: Asn = asn.into();
            a.is_private() as u8
        },
        0,
    )
}

/// 1 when the ASN is AS_TRANS (23456, RFC 6793 §4.2.3 — the
/// placeholder for 4-byte ASes on a 2-byte session).
#[no_mangle]
pub extern "C" fn lr_asn_is_as_trans(asn: lr_asn_t) -> u8 {
    guarded(
        || {
            let a: Asn = asn.into();
            a.is_as23456() as u8
        },
        0,
    )
}

// ---- RouterId ----

/// Repr-C RouterId. Mirrors `lr_core::addr::RouterId(pub u32)`.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct lr_router_id_t {
    pub value: u32,
}

impl From<RouterId> for lr_router_id_t {
    fn from(r: RouterId) -> Self {
        Self { value: r.as_u32() }
    }
}

impl From<lr_router_id_t> for RouterId {
    fn from(c: lr_router_id_t) -> Self {
        RouterId::from_u32(c.value)
    }
}

/// Construct a RouterId from a u32.
#[no_mangle]
pub extern "C" fn lr_router_id_from_u32(value: u32) -> lr_router_id_t {
    guarded(
        || RouterId::from_u32(value).into(),
        lr_router_id_t::default(),
    )
}

/// Construct a RouterId from 4 IPv4 octets (e.g. `[10, 0, 0, 1]`).
///
/// # Safety
/// `octets` must point to 4 readable bytes.
#[no_mangle]
pub unsafe extern "C" fn lr_router_id_from_v4(octets: *const u8) -> lr_router_id_t {
    guarded(
        || unsafe {
            if octets.is_null() {
                return lr_router_id_t::default();
            }
            let mut buf = [0u8; 4];
            let src = unsafe { std::slice::from_raw_parts(octets, 4) };
            buf.copy_from_slice(src);
            RouterId::from_v4(buf).into()
        },
        lr_router_id_t::default(),
    )
}

/// Write the RouterId's 4 IPv4 octets into `out_octets`.
///
/// # Safety
/// `out_octets` must point to 4 writable bytes.
#[no_mangle]
pub unsafe extern "C" fn lr_router_id_to_v4_bytes(rid: lr_router_id_t, out_octets: *mut u8) -> i32 {
    guarded(
        || unsafe {
            if out_octets.is_null() {
                return LR_ERR_NULL;
            }
            let r: RouterId = rid.into();
            let bytes = r.to_v4_bytes();
            unsafe {
                std::ptr::copy_nonoverlapping(bytes.as_ptr(), out_octets, 4);
            }
            0
        },
        LR_ERR_PANIC,
    )
}

// ---- Protocol ----

/// Repr-C Protocol constants (mirrors `lr_core::rib::Protocol`).
pub const LR_PROTOCOL_BGP: u8 = 0;
pub const LR_PROTOCOL_OSPFV2: u8 = 1;
pub const LR_PROTOCOL_OSPFV3: u8 = 2;
pub const LR_PROTOCOL_BABEL: u8 = 3;
pub const LR_PROTOCOL_STATIC: u8 = 4;
pub const LR_PROTOCOL_CONNECTED: u8 = 5;
pub const LR_PROTOCOL_OTHER: u8 = 6;

/// Convert a `Protocol` to its `LR_PROTOCOL_*` constant.
pub fn protocol_to_c(p: Protocol) -> u8 {
    match p {
        Protocol::Bgp => LR_PROTOCOL_BGP,
        Protocol::Ospfv2 => LR_PROTOCOL_OSPFV2,
        Protocol::Ospfv3 => LR_PROTOCOL_OSPFV3,
        Protocol::Babel => LR_PROTOCOL_BABEL,
        Protocol::Static => LR_PROTOCOL_STATIC,
        Protocol::Connected => LR_PROTOCOL_CONNECTED,
        Protocol::Other(_) => LR_PROTOCOL_OTHER,
    }
}

/// Convert an `LR_PROTOCOL_*` constant to a `Protocol`.
pub fn protocol_from_c(v: u8) -> Protocol {
    match v {
        LR_PROTOCOL_BGP => Protocol::Bgp,
        LR_PROTOCOL_OSPFV2 => Protocol::Ospfv2,
        LR_PROTOCOL_OSPFV3 => Protocol::Ospfv3,
        LR_PROTOCOL_BABEL => Protocol::Babel,
        LR_PROTOCOL_STATIC => Protocol::Static,
        LR_PROTOCOL_CONNECTED => Protocol::Connected,
        _ => Protocol::Other(v as u16),
    }
}

/// Read the BIRD-style name of a `LR_PROTOCOL_*` constant (e.g.
/// `"bgp"`, `"ospf"`). Writes a NUL-terminated string into `out_name`.
///
/// # Safety
/// `out_name` must point to at least `name_cap` writable bytes.
#[no_mangle]
pub unsafe extern "C" fn lr_protocol_bird_name(
    proto: u8,
    out_name: *mut std::os::raw::c_char,
    name_cap: usize,
) -> usize {
    guarded(
        || unsafe {
            if out_name.is_null() || name_cap == 0 {
                return 0;
            }
            let p = protocol_from_c(proto);
            let name = p.bird_name();
            let bytes = name.as_bytes();
            let take = bytes.len().min(name_cap - 1);
            unsafe {
                // `out_name` is `*mut c_char`; on platforms where c_char
                // is signed (x86_64, aarch64) the cast to `*mut u8`
                // changes the pointee type; on platforms where it is
                // unsigned (riscv64, powerpc64, s390x) it is a no-op
                // (and clippy::unnecessary_cast fires). Use `.cast()`
                // so the same source compiles on both without lint.
                std::ptr::copy_nonoverlapping(bytes.as_ptr(), out_name.cast::<u8>(), take);
                *out_name.cast::<u8>().add(take) = 0;
            }
            take
        },
        0,
    )
}

/// Read the default administrative distance for a `LR_PROTOCOL_*`
/// constant (e.g. 20 for BGP eBGP, 110 for OSPF).
#[no_mangle]
pub extern "C" fn lr_protocol_default_admin_distance(proto: u8) -> u32 {
    guarded(
        || {
            let p = protocol_from_c(proto);
            p.default_admin_distance()
        },
        0,
    )
}

// ---- RouteKey / RouteOrigin ----

/// Repr-C RouteKey. Mirrors `lr_core::rib::RouteKey`.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct lr_route_key_t {
    pub prefix: lr_core_prefix_t,
    /// AFI/SAFI packed as `afi << 8 | safi`. See lr_core::nlri::NlriFamily.
    pub afi_safi: u16,
    /// 1 when `source_prefix` carries a value, 0 otherwise.
    pub has_source: u8,
    pub source_prefix: lr_core_prefix_t,
}

/// Repr-C RouteOrigin. Mirrors `lr_core::rib::RouteOrigin`.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct lr_route_origin_t {
    /// `LR_PROTOCOL_*` constant.
    pub protocol: u8,
    /// Per-peer session handle (0 for locally originated routes).
    pub peer: u64,
}

impl From<RouteOrigin> for lr_route_origin_t {
    fn from(o: RouteOrigin) -> Self {
        Self {
            protocol: o.proto as u8,
            peer: o.peer,
        }
    }
}

impl From<lr_route_origin_t> for RouteOrigin {
    fn from(c: lr_route_origin_t) -> Self {
        Self {
            proto: c.protocol as u32,
            peer: c.peer,
        }
    }
}

/// `pub(crate)` helper so other FFI modules can convert a C-side
/// `lr_route_key_t` back to a Rust `RouteKey` without re-implementing
/// the field-by-field translation. Mirrors the `lr_core_prefix_t -> Prefix`
/// `From` impl on the prefix slot.
pub(crate) fn route_key_from_c(c: &lr_route_key_t) -> RouteKey {
    let prefix: Prefix = c.prefix.into();
    let family = NlriFamily {
        afi: c.afi_safi >> 8,
        safi: (c.afi_safi & 0xff) as u8,
    };
    if c.has_source != 0 {
        let source: Prefix = c.source_prefix.into();
        RouteKey::with_source(prefix, family, source)
    } else {
        RouteKey::new(prefix, family)
    }
}

// ---- Instant / Duration (RFC 5905 §3.2 logical millisecond clock) ----

#[no_mangle]
pub extern "C" fn lr_instant_from_millis(millis: u64) -> u64 {
    guarded(|| millis, 0)
}

#[no_mangle]
pub extern "C" fn lr_instant_from_secs(secs: u64) -> u64 {
    guarded(|| secs.saturating_mul(1000), 0)
}

#[no_mangle]
pub extern "C" fn lr_instant_as_millis(instant: u64) -> u64 {
    guarded(|| instant, 0)
}

#[no_mangle]
pub extern "C" fn lr_instant_as_secs(instant: u64) -> u64 {
    guarded(|| instant / 1000, 0)
}

#[no_mangle]
pub extern "C" fn lr_instant_saturating_sub(earlier: u64, later: u64) -> u64 {
    guarded(|| later.saturating_sub(earlier), 0)
}

#[no_mangle]
pub extern "C" fn lr_instant_checked_add(instant: u64, duration_ms: u64) -> u64 {
    guarded(|| instant.saturating_add(duration_ms), u64::MAX)
}

#[no_mangle]
pub extern "C" fn lr_duration_from_millis(millis: u64) -> u64 {
    guarded(|| millis, 0)
}

#[no_mangle]
pub extern "C" fn lr_duration_from_secs(secs: u64) -> u64 {
    guarded(|| secs.saturating_mul(1000), 0)
}

#[no_mangle]
pub extern "C" fn lr_duration_as_millis(duration_ms: u64) -> u64 {
    guarded(|| duration_ms, 0)
}

#[no_mangle]
pub extern "C" fn lr_duration_as_secs(duration_ms: u64) -> u64 {
    guarded(|| duration_ms / 1000, 0)
}

#[no_mangle]
pub extern "C" fn lr_duration_checked_add(a: u64, b: u64) -> u64 {
    guarded(|| a.saturating_add(b), u64::MAX)
}

// ---- TimerQueue ----

#[repr(C)]
pub struct OpaqueTimerQueue {
    _private: [u8; 0],
}
pub type lr_timer_queue_t = *mut OpaqueTimerQueue;

pub type lr_timer_id_t = u32;

#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct lr_timer_spec_t {
    pub after_ms: u64,
    pub periodic_ms: u64,
}

impl From<lr_timer_spec_t> for lr_core::fsm::TimerSpec {
    fn from(s: lr_timer_spec_t) -> Self {
        if s.periodic_ms == 0 {
            lr_core::fsm::TimerSpec::once(s.after_ms)
        } else {
            lr_core::fsm::TimerSpec::periodic(s.after_ms, s.periodic_ms)
        }
    }
}

fn box_queue(q: lr_core::timer::TimerQueue) -> lr_timer_queue_t {
    Box::into_raw(Box::new(q)) as lr_timer_queue_t
}

unsafe fn unbox_queue(q: lr_timer_queue_t) -> Option<Box<lr_core::timer::TimerQueue>> {
    if q.is_null() {
        return None;
    }
    Some(unsafe { Box::from_raw(q as *mut lr_core::timer::TimerQueue) })
}

unsafe fn borrow_queue(q: lr_timer_queue_t) -> Option<&'static lr_core::timer::TimerQueue> {
    if q.is_null() {
        return None;
    }
    Some(unsafe { &*(q as *const lr_core::timer::TimerQueue) })
}

unsafe fn borrow_queue_mut(q: lr_timer_queue_t) -> Option<&'static mut lr_core::timer::TimerQueue> {
    if q.is_null() {
        return None;
    }
    Some(unsafe { &mut *(q as *mut lr_core::timer::TimerQueue) })
}

#[no_mangle]
pub extern "C" fn lr_timer_queue_new() -> lr_timer_queue_t {
    guarded(
        || box_queue(lr_core::timer::TimerQueue::new()),
        std::ptr::null_mut(),
    )
}

#[no_mangle]
pub unsafe extern "C" fn lr_timer_queue_free(q: lr_timer_queue_t) {
    guarded(
        || unsafe {
            drop(unbox_queue(q));
        },
        (),
    )
}

#[no_mangle]
pub unsafe extern "C" fn lr_timer_queue_arm(
    q: lr_timer_queue_t,
    now_ms: u64,
    id: lr_timer_id_t,
    spec: lr_timer_spec_t,
) -> i32 {
    guarded(
        || unsafe {
            let Some(queue) = borrow_queue_mut(q) else {
                return LR_ERR_NULL;
            };
            queue.arm(
                lr_core::time::Instant(now_ms),
                lr_core::fsm::TimerId(id),
                spec.into(),
            );
            0
        },
        LR_ERR_PANIC,
    )
}

#[no_mangle]
pub unsafe extern "C" fn lr_timer_queue_cancel(q: lr_timer_queue_t, id: lr_timer_id_t) -> i32 {
    guarded(
        || unsafe {
            let Some(queue) = borrow_queue_mut(q) else {
                return LR_ERR_NULL;
            };
            queue.cancel(lr_core::fsm::TimerId(id));
            0
        },
        LR_ERR_PANIC,
    )
}

#[no_mangle]
pub unsafe extern "C" fn lr_timer_queue_cancel_all(q: lr_timer_queue_t) -> i32 {
    guarded(
        || unsafe {
            let Some(queue) = borrow_queue_mut(q) else {
                return LR_ERR_NULL;
            };
            queue.cancel_all();
            0
        },
        LR_ERR_PANIC,
    )
}

#[no_mangle]
pub unsafe extern "C" fn lr_timer_queue_tick(
    q: lr_timer_queue_t,
    now_ms: u64,
    out_array: *mut *mut lr_timer_id_t,
    out_count: *mut usize,
) -> i32 {
    guarded(
        || unsafe {
            let Some(queue) = borrow_queue_mut(q) else {
                return LR_ERR_NULL;
            };
            if out_array.is_null() || out_count.is_null() {
                return LR_ERR_NULL;
            }
            let fired = queue.tick(lr_core::time::Instant(now_ms));
            let n = fired.len();
            if n == 0 {
                unsafe {
                    *out_array = std::ptr::null_mut();
                    *out_count = 0;
                }
                return 0;
            }
            let ids: Vec<u32> = fired.into_iter().map(|t| t.0).collect();
            let mut boxed = ids.into_boxed_slice();
            let ptr = boxed.as_mut_ptr();
            std::mem::forget(boxed);
            unsafe {
                *out_array = ptr;
                *out_count = n;
            }
            0
        },
        LR_ERR_PANIC,
    )
}

#[no_mangle]
pub unsafe extern "C" fn lr_timer_queue_is_empty(q: lr_timer_queue_t) -> u8 {
    guarded(
        || unsafe {
            borrow_queue(q)
                .map(|queue| queue.is_empty() as u8)
                .unwrap_or(1)
        },
        1,
    )
}

#[no_mangle]
pub unsafe extern "C" fn lr_timer_queue_len(q: lr_timer_queue_t) -> usize {
    guarded(
        || unsafe { borrow_queue(q).map(|queue| queue.len()).unwrap_or(0) },
        0,
    )
}

#[no_mangle]
pub unsafe extern "C" fn lr_timer_queue_next_fire_ms(q: lr_timer_queue_t) -> u64 {
    guarded(
        || unsafe {
            borrow_queue(q)
                .and_then(|queue| queue.next_fire())
                .map(|i| i.0)
                .unwrap_or(u64::MAX)
        },
        u64::MAX,
    )
}

#[no_mangle]
pub unsafe extern "C" fn lr_timer_queue_drain_free(array: *mut lr_timer_id_t, count: usize) {
    guarded(
        || unsafe {
            if array.is_null() || count == 0 {
                return;
            }
            let _ = unsafe { Vec::from_raw_parts(array, count, count) };
        },
        (),
    )
}

#[no_mangle]
pub extern "C" fn lr_timer_spec_once(after_ms: u64) -> lr_timer_spec_t {
    guarded(
        || lr_timer_spec_t {
            after_ms,
            periodic_ms: 0,
        },
        lr_timer_spec_t::default(),
    )
}

#[no_mangle]
pub extern "C" fn lr_timer_spec_periodic(after_ms: u64, periodic_ms: u64) -> lr_timer_spec_t {
    guarded(
        || lr_timer_spec_t {
            after_ms,
            periodic_ms,
        },
        lr_timer_spec_t::default(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ffi_ip_addr_v4() {
        let bytes = [10u8, 0, 0, 1];
        let a = unsafe { lr_ip_addr_v4(bytes.as_ptr()) };
        assert_eq!(lr_ip_addr_is_ipv4(a), 1);
        assert_eq!(lr_ip_addr_is_ipv6(a), 0);
        assert_eq!(lr_ip_addr_is_unspecified(a), 0);
        let mut out = [0u8; 4];
        unsafe {
            assert_eq!(lr_ip_addr_octets(a, out.as_mut_ptr(), 4), 4);
            assert_eq!(out, [10, 0, 0, 1]);
        }
    }

    #[test]
    fn ffi_ip_addr_v6() {
        let octets = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let a = unsafe { lr_ip_addr_v6(octets.as_ptr()) };
        assert_eq!(lr_ip_addr_is_ipv6(a), 1);
        assert_eq!(lr_ip_addr_is_ipv4(a), 0);
        let mut out = [0u8; 16];
        unsafe {
            assert_eq!(lr_ip_addr_octets(a, out.as_mut_ptr(), 16), 16);
            assert_eq!(out, octets);
        }
    }

    #[test]
    fn ffi_ip_addr_unspecified() {
        let zeros = [0u8; 4];
        let a = unsafe { lr_ip_addr_v4(zeros.as_ptr()) };
        assert_eq!(lr_ip_addr_is_unspecified(a), 1);
        let zeros6 = [0u8; 16];
        let b = unsafe { lr_ip_addr_v6(zeros6.as_ptr()) };
        assert_eq!(lr_ip_addr_is_unspecified(b), 1);
    }

    #[test]
    fn ffi_ip_addr_multicast() {
        let mcast_bytes = [224u8, 0, 0, 1];
        let mcast = unsafe { lr_ip_addr_v4(mcast_bytes.as_ptr()) };
        assert_eq!(lr_ip_addr_is_multicast(mcast), 1);
        let unicast_bytes = [10u8, 0, 0, 1];
        let unicast = unsafe { lr_ip_addr_v4(unicast_bytes.as_ptr()) };
        assert_eq!(lr_ip_addr_is_multicast(unicast), 0);
    }

    #[test]
    fn ffi_prefix_v4_and_contains() {
        let p_bytes = [10u8, 0, 0, 0];
        let p = unsafe { lr_core_prefix_v4(p_bytes.as_ptr(), 24) };
        assert_eq!(lr_core_prefix_is_ipv4(p), 1);
        let inside_bytes = [10u8, 0, 0, 5];
        let inside = unsafe { lr_ip_addr_v4(inside_bytes.as_ptr()) };
        let outside_bytes = [192u8, 168, 1, 1];
        let outside = unsafe { lr_ip_addr_v4(outside_bytes.as_ptr()) };
        assert_eq!(lr_core_prefix_contains(p, inside), 1);
        assert_eq!(lr_core_prefix_contains(p, outside), 0);
    }

    #[test]
    fn ffi_prefix_v6_and_contains() {
        let octets = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let p = unsafe { lr_core_prefix_v6(octets.as_ptr(), 32) };
        let inside_octets = [
            0x20, 0x01, 0x0d, 0xb8, 0xbe, 0xef, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
        ];
        let inside = unsafe { lr_ip_addr_v6(inside_octets.as_ptr()) };
        assert_eq!(lr_core_prefix_contains(p, inside), 1);
    }

    #[test]
    fn ffi_prefix_contains_prefix() {
        // 10.0.0.0/16 contains 10.0.1.0/24 (10.0.1.x falls in 10.0.0.0..10.0.255.255).
        let outer_bytes = [10u8, 0, 0, 0];
        let inner_bytes = [10u8, 0, 1, 0];
        let other_bytes = [192u8, 168, 0, 0];
        let outer = unsafe { lr_core_prefix_v4(outer_bytes.as_ptr(), 16) };
        let inner = unsafe { lr_core_prefix_v4(inner_bytes.as_ptr(), 24) };
        let other = unsafe { lr_core_prefix_v4(other_bytes.as_ptr(), 24) };
        assert_eq!(lr_core_prefix_contains_prefix(outer, inner), 1);
        assert_eq!(lr_core_prefix_contains_prefix(outer, other), 0);
    }

    #[test]
    fn ffi_prefix_network() {
        // 10.0.0.5/24 — network address is 10.0.0.0/24.
        let bytes = [10u8, 0, 0, 5];
        let p = unsafe { lr_core_prefix_v4(bytes.as_ptr(), 24) };
        let mut out = lr_ip_addr_t::default();
        unsafe {
            assert_eq!(lr_core_prefix_network(p, &raw mut out), 0);
            let mut bytes = [0u8; 4];
            assert_eq!(lr_ip_addr_octets(out, bytes.as_mut_ptr(), 4), 4);
            assert_eq!(bytes, [10, 0, 0, 0]);
        }
    }

    #[test]
    fn ffi_asn() {
        let a = lr_asn_new(64512);
        assert_eq!(lr_asn_is_private(a), 1);
        let b = lr_asn_new(65000);
        assert_eq!(lr_asn_is_private(b), 1);
        let c = lr_asn_new(64500);
        assert_eq!(lr_asn_is_private(c), 0);
        let trans = lr_asn_new(23456);
        assert_eq!(lr_asn_is_as_trans(trans), 1);
    }

    #[test]
    fn ffi_router_id() {
        let bytes = [10u8, 0, 0, 1];
        let rid = unsafe { lr_router_id_from_v4(bytes.as_ptr()) };
        let mut bytes_out = [0u8; 4];
        unsafe {
            assert_eq!(lr_router_id_to_v4_bytes(rid, bytes_out.as_mut_ptr()), 0);
            assert_eq!(bytes_out, [10, 0, 0, 1]);
        }
        let rid2 = lr_router_id_from_u32(0x0a000001);
        assert_eq!(rid.value, rid2.value);
    }

    #[test]
    fn ffi_protocol_constants() {
        assert_eq!(LR_PROTOCOL_BGP, 0);
        assert_eq!(LR_PROTOCOL_OSPFV2, 1);
        assert_eq!(LR_PROTOCOL_OSPFV3, 2);
        assert_eq!(LR_PROTOCOL_BABEL, 3);
        assert_eq!(LR_PROTOCOL_STATIC, 4);
        assert_eq!(LR_PROTOCOL_CONNECTED, 5);
    }

    #[test]
    fn ffi_protocol_bird_name() {
        let mut name = [0u8; 32];
        let n = unsafe {
            lr_protocol_bird_name(
                LR_PROTOCOL_BGP,
                name.as_mut_ptr() as *mut std::os::raw::c_char,
                name.len(),
            )
        };
        assert_eq!(n, 3);
        assert_eq!(&name[..n], b"bgp");

        let n = unsafe {
            lr_protocol_bird_name(
                LR_PROTOCOL_OSPFV2,
                name.as_mut_ptr() as *mut std::os::raw::c_char,
                name.len(),
            )
        };
        assert_eq!(&name[..n], b"ospf");
    }

    #[test]
    fn ffi_protocol_default_admin_distance() {
        // BGP's default admin distance is 20 (eBGP) per RFC 4271 §9.
        assert_eq!(lr_protocol_default_admin_distance(LR_PROTOCOL_BGP), 20);
    }

    #[test]
    fn ffi_route_origin_roundtrip() {
        let c = lr_route_origin_t {
            protocol: LR_PROTOCOL_BGP,
            peer: 0xdeadbeef,
        };
        let r: RouteOrigin = c.into();
        assert_eq!(r.proto, LR_PROTOCOL_BGP as u32);
        assert_eq!(r.peer, 0xdeadbeef);
        let c2: lr_route_origin_t = r.into();
        assert_eq!(c.protocol, c2.protocol);
        assert_eq!(c.peer, c2.peer);
    }

    // ---- Instant / Duration / TimerQueue ----

    #[test]
    fn ffi_instant_round_trip() {
        assert_eq!(lr_instant_from_millis(12345), 12345);
        assert_eq!(lr_instant_as_millis(12345), 12345);
        assert_eq!(lr_instant_as_secs(12345), 12);
        assert_eq!(lr_instant_from_secs(10), 10_000);
        assert_eq!(lr_instant_saturating_sub(100, 200), 100);
        assert_eq!(lr_instant_saturating_sub(200, 100), 0);
        assert_eq!(lr_instant_checked_add(100, 200), 300);
        assert_eq!(lr_instant_checked_add(u64::MAX, 1), u64::MAX);
    }

    #[test]
    fn ffi_duration_round_trip() {
        assert_eq!(lr_duration_from_millis(5000), 5000);
        assert_eq!(lr_duration_as_secs(5000), 5);
        assert_eq!(lr_duration_from_secs(7), 7000);
        assert_eq!(lr_duration_checked_add(100, 200), 300);
        assert_eq!(lr_duration_checked_add(u64::MAX, 1), u64::MAX);
    }

    #[test]
    fn ffi_timer_queue_new_is_empty() {
        let q = lr_timer_queue_new();
        assert_eq!(unsafe { lr_timer_queue_is_empty(q) }, 1);
        assert_eq!(unsafe { lr_timer_queue_len(q) }, 0);
        assert_eq!(unsafe { lr_timer_queue_next_fire_ms(q) }, u64::MAX);
        unsafe { lr_timer_queue_free(q) };
    }

    #[test]
    fn ffi_timer_queue_arm_tick_fires() {
        let q = lr_timer_queue_new();
        let spec = lr_timer_spec_once(100);
        assert_eq!(unsafe { lr_timer_queue_arm(q, 0, 7, spec) }, 0);
        assert_eq!(unsafe { lr_timer_queue_len(q) }, 1);
        assert_eq!(unsafe { lr_timer_queue_next_fire_ms(q) }, 100);

        let mut array: *mut lr_timer_id_t = std::ptr::null_mut();
        let mut count: usize = 0;
        assert_eq!(
            unsafe { lr_timer_queue_tick(q, 99, &raw mut array, &raw mut count) },
            0
        );
        assert_eq!(count, 0);

        assert_eq!(
            unsafe { lr_timer_queue_tick(q, 100, &raw mut array, &raw mut count) },
            0
        );
        assert_eq!(count, 1);
        assert_eq!(unsafe { *array.add(0) }, 7);
        assert_eq!(unsafe { lr_timer_queue_is_empty(q) }, 1);
        unsafe { lr_timer_queue_drain_free(array, count) };
        unsafe { lr_timer_queue_free(q) };
    }

    #[test]
    fn ffi_timer_queue_cancel() {
        let q = lr_timer_queue_new();
        let spec = lr_timer_spec_once(100);
        unsafe {
            assert_eq!(lr_timer_queue_arm(q, 0, 1, spec), 0);
            assert_eq!(lr_timer_queue_arm(q, 0, 2, spec), 0);
            assert_eq!(lr_timer_queue_len(q), 2);
            assert_eq!(lr_timer_queue_cancel(q, 1), 0);
            assert_eq!(lr_timer_queue_len(q), 1);
            assert_eq!(lr_timer_queue_cancel_all(q), 0);
            assert_eq!(lr_timer_queue_is_empty(q), 1);
        }
        unsafe { lr_timer_queue_free(q) };
    }

    #[test]
    fn ffi_timer_queue_periodic_fires_repeatedly() {
        let q = lr_timer_queue_new();
        let spec = lr_timer_spec_periodic(100, 100);
        unsafe {
            assert_eq!(lr_timer_queue_arm(q, 0, 5, spec), 0);
            let mut array: *mut lr_timer_id_t = std::ptr::null_mut();
            let mut count: usize = 0;
            assert_eq!(
                lr_timer_queue_tick(q, 100, &raw mut array, &raw mut count),
                0
            );
            assert_eq!(count, 1);
            lr_timer_queue_drain_free(array, count);

            let mut array2: *mut lr_timer_id_t = std::ptr::null_mut();
            let mut count2: usize = 0;
            assert_eq!(
                lr_timer_queue_tick(q, 199, &raw mut array2, &raw mut count2),
                0
            );
            assert_eq!(count2, 0);

            assert_eq!(
                lr_timer_queue_tick(q, 200, &raw mut array2, &raw mut count2),
                0
            );
            assert_eq!(count2, 1);
            lr_timer_queue_drain_free(array2, count2);
        }
        unsafe { lr_timer_queue_free(q) };
    }

    #[test]
    fn ffi_timer_queue_null_safety() {
        let spec = lr_timer_spec_once(100);
        assert_eq!(
            unsafe { lr_timer_queue_arm(std::ptr::null_mut(), 0, 1, spec) },
            LR_ERR_NULL
        );
        unsafe { lr_timer_queue_free(std::ptr::null_mut()) };
        unsafe { lr_timer_queue_drain_free(std::ptr::null_mut(), 0) };
    }

    #[test]
    fn ffi_timer_spec_constructors() {
        let once = lr_timer_spec_once(100);
        assert_eq!(once.after_ms, 100);
        assert_eq!(once.periodic_ms, 0);
        let per = lr_timer_spec_periodic(100, 1000);
        assert_eq!(per.after_ms, 100);
        assert_eq!(per.periodic_ms, 1000);
    }
}
