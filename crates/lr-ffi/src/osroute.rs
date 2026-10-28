//! OS route-table FFI (lr-osroute pub API mirror).
//!
//! Mirrors the public Rust API of `lr_osroute::{OsRouteTable, KernelRoute,
//! OsRouteError, RtNetlink, StubRouteTable}` so an embedder can install,
//! delete and list kernel routes from C without going through the daemon.
//!
//! # Surface
//!
//! - `lr_osroute_connect` — open the platform's native route-table backend.
//!   On Linux this opens a `NETLINK_ROUTE` socket; on the BSDs/macOS it
//!   opens a `route(4)` socket; on Windows it uses IP Helper; everywhere
//!   else (or when the OS denies the syscall) it returns an
//!   [`lr_osroute_error_t`].
//! - `lr_osroute_connect_stub` — open the stub backend (always succeeds;
//!   all ops return errors). Useful for testing the FFI surface on
//!   platforms without a kernel route table.
//! - `lr_osroute_add_route` / `_add_route_tagged` / `_add_blackhole_route` /
//!   `_delete_route` — install/delete routes.
//! - `lr_osroute_list_routes` / `_list_routes_count` — read the kernel
//!   FIB. The count call lets the embedder size its buffer first.
//! - `lr_osroute_has_route` — convenience predicate.
//! - `lr_osroute_platform_name` — the human-readable backend name
//!   (e.g. `"linux-rtnetlink"`, `"freebsd-route-socket"`, `"stub"`).
//! - `lr_osroute_destroy` — drop the boxed backend.
//!
//! The kernel route projection `lr_kernel_route_t` mirrors
//! [`lr_osroute::KernelRoute`] field-for-field (prefix, next_hop, if_index,
//! metric, protocol).
//!
//! Every entry point runs inside the crate's `catch_unwind` barrier
//! ([`crate::guarded`]); a panic returns `LR_ERR_PANIC` and sets the
//! thread-local last-error string.

// The closure body passed to `guarded` is wrapped in a single `unsafe`
// block to mirror the `pub unsafe extern "C" fn` shape — the inner
// `unsafe { ... }` blocks would otherwise trip `unused_unsafe` under the
// crate's `-D warnings` clippy gate.
#![allow(unused_unsafe)]

use lr_core::addr::IpAddr;
use lr_core::rib::Protocol;
use lr_osroute::gtsm::Gtsm;
use lr_osroute::stub::StubRouteTable;
use lr_osroute::tcp_auth::{TcpAoAlgorithm, TcpAoKey, TcpAuth};
use lr_osroute::{KernelRoute, OsRouteTable, SystemRouteTable};

use crate::error::{set_last_error, LrError, LR_ERR_PANIC};
use crate::guarded;
use crate::policy::lr_prefix_t;

/// `LR_ERR_NULL` (-1) — null pointer or null handle.
const LR_ERR_NULL: i32 = LrError::Null as i32;
/// `LR_ERR_OTHER` (-6) — backend error / malformed argument.
const LR_ERR_OTHER: i32 = LrError::Other as i32;

/// Opaque route-table handle. C side never touches internals.
#[repr(C)]
pub struct OpaqueOsRouteTable {
    _private: [u8; 0],
}

pub type lr_osroute_t = *mut OpaqueOsRouteTable;

/// One kernel route entry — mirrors [`KernelRoute`] field-for-field.
///
/// The next_hop is flattened into a 16-byte buffer + `is_ipv6` flag +
/// `next_hop_present` flag (the kernel route may carry no next hop —
/// blackhole routes).
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct lr_kernel_route_t {
    /// Network prefix (IPv4 in the low 4 bytes when `prefix.is_ipv6 == 0`).
    pub prefix: lr_prefix_t,
    /// 16-byte next-hop buffer (IPv4 in the low 4 bytes when
    /// `next_hop_is_ipv6 == 0`).
    pub next_hop: [u8; 16],
    /// 1 when `next_hop_is_ipv6` carries an IPv6 address, 0 for IPv4.
    pub next_hop_is_ipv6: u8,
    /// 1 when the route carries a next hop, 0 for blackhole routes.
    pub next_hop_present: u8,
    /// 1 when `if_index` carries a value, 0 otherwise.
    pub if_index_present: u8,
    /// Interface index (OS-specific; resolved via `if_nametoindex`).
    pub if_index: u32,
    /// Route metric / priority (lower wins on Linux).
    pub metric: u32,
    /// Source protocol identifier (one of the `LR_PROTO_*` constants).
    pub protocol: i32,
}

impl lr_kernel_route_t {
    fn from_kernel(r: &KernelRoute) -> Self {
        let (nh_buf, nh_is_v6, nh_present) = match r.next_hop {
            None => ([0u8; 16], 0u8, 0u8),
            Some(IpAddr::V4(b)) => {
                let mut buf = [0u8; 16];
                buf[..4].copy_from_slice(&b);
                (buf, 0u8, 1u8)
            }
            Some(IpAddr::V6(b)) => (b, 1u8, 1u8),
        };
        let (pfx_buf, pfx_is_v6) = match r.prefix.addr {
            IpAddr::V4(b) => {
                let mut buf = [0u8; 16];
                buf[..4].copy_from_slice(&b);
                (buf, 0u8)
            }
            IpAddr::V6(b) => (b, 1u8),
        };
        Self {
            prefix: lr_prefix_t {
                addr: pfx_buf,
                is_ipv6: pfx_is_v6,
                prefix_len: r.prefix.prefix_len,
            },
            next_hop: nh_buf,
            next_hop_is_ipv6: nh_is_v6,
            next_hop_present: nh_present,
            if_index_present: r.if_index.is_some() as u8,
            if_index: r.if_index.unwrap_or(0),
            metric: r.metric,
            protocol: protocol_to_i32(r.protocol),
        }
    }
}

fn protocol_to_i32(p: Protocol) -> i32 {
    match p {
        Protocol::Bgp => 0,
        Protocol::Ospfv2 => 1,
        Protocol::Ospfv3 => 2,
        Protocol::Babel => 3,
        Protocol::Static => 4,
        Protocol::Connected => 5,
        Protocol::Other(v) => 0x10000 | (v as i32),
    }
}

fn i32_to_protocol(v: i32) -> Option<Protocol> {
    match v {
        0 => Some(Protocol::Bgp),
        1 => Some(Protocol::Ospfv2),
        2 => Some(Protocol::Ospfv3),
        3 => Some(Protocol::Babel),
        4 => Some(Protocol::Static),
        5 => Some(Protocol::Connected),
        n if n >= 0x10000 => Some(Protocol::Other((n & 0xffff) as u16)),
        _ => None,
    }
}

/// The boxed backend carries an enum of the supported concrete types
/// (`SystemRouteTable` on Linux/BSD/Windows; `StubRouteTable` elsewhere).
/// The trait method dispatch happens inside the FFI entry points.
enum Backend {
    Native(SystemRouteTable),
    Stub(StubRouteTable),
}

impl Backend {
    fn connect() -> Result<Self, String> {
        // SystemRouteTable::connect is the same shape on every target
        // (the type alias swaps to RtNetlink / RouteSocket / IpHelper /
        // StubRouteTable). On non-supported targets StubRouteTable::connect
        // returns Err; we fall back to a fresh StubRouteTable::new() so
        // the embedder still gets a working handle whose ops return
        // documented errors.
        match SystemRouteTable::connect() {
            Ok(b) => Ok(Backend::Native(b)),
            Err(e) => Err(e.0),
        }
    }
    fn connect_stub() -> Self {
        Backend::Stub(StubRouteTable::new())
    }
}

impl OsRouteTable for Backend {
    type Error = lr_osroute::OsRouteError;
    fn add_route(
        &mut self,
        prefix: lr_core::addr::Prefix,
        gw: IpAddr,
        if_index: u32,
    ) -> Result<(), Self::Error> {
        match self {
            Backend::Native(b) => b.add_route(prefix, gw, if_index),
            Backend::Stub(b) => b.add_route(prefix, gw, if_index),
        }
    }
    fn add_route_tagged(
        &mut self,
        prefix: lr_core::addr::Prefix,
        gw: IpAddr,
        if_index: u32,
        proto: Protocol,
    ) -> Result<(), Self::Error> {
        match self {
            Backend::Native(b) => b.add_route_tagged(prefix, gw, if_index, proto),
            Backend::Stub(b) => b.add_route_tagged(prefix, gw, if_index, proto),
        }
    }
    fn add_blackhole_route(&mut self, prefix: lr_core::addr::Prefix) -> Result<(), Self::Error> {
        match self {
            Backend::Native(b) => b.add_blackhole_route(prefix),
            Backend::Stub(b) => b.add_blackhole_route(prefix),
        }
    }
    fn delete_route(&mut self, prefix: lr_core::addr::Prefix) -> Result<(), Self::Error> {
        match self {
            Backend::Native(b) => b.delete_route(prefix),
            Backend::Stub(b) => b.delete_route(prefix),
        }
    }
    fn list_routes(&mut self) -> Result<Vec<KernelRoute>, Self::Error> {
        match self {
            Backend::Native(b) => b.list_routes(),
            Backend::Stub(b) => b.list_routes(),
        }
    }
}

fn box_backend(b: Backend) -> lr_osroute_t {
    Box::into_raw(Box::new(b)) as lr_osroute_t
}

/// Reclaim a backend handle back into its boxed form.
///
/// # Safety
/// `t` must have been produced by [`box_backend`] and not already freed.
unsafe fn unbox_backend(t: lr_osroute_t) -> Option<Box<Backend>> {
    if t.is_null() {
        return None;
    }
    Some(unsafe { Box::from_raw(t as *mut Backend) })
}

/// Borrow a backend handle as `&mut Backend` for in-place mutation.
///
/// # Safety
/// `t` must have been produced by [`box_backend`] and not be freed while
/// the returned reference is live.
unsafe fn borrow_backend_mut(t: lr_osroute_t) -> Option<&'static mut Backend> {
    if t.is_null() {
        return None;
    }
    Some(unsafe { &mut *(t as *mut Backend) })
}

/// Open the platform's native route-table backend.
///
/// On Linux this opens a `NETLINK_ROUTE` socket; on the BSDs/macOS a
/// `route(4)` socket; on Windows IP Helper. Everywhere else (or when the
/// OS denies the syscall) it returns `NULL` and sets the last-error
/// string — call [`lr_last_error`] for details.
///
/// Returns a non-NULL handle on success.
#[no_mangle]
pub extern "C" fn lr_osroute_connect() -> lr_osroute_t {
    guarded(
        || match Backend::connect() {
            Ok(b) => box_backend(b),
            Err(e) => {
                set_last_error(e);
                std::ptr::null_mut()
            }
        },
        std::ptr::null_mut(),
    )
}

/// Open the stub backend — always succeeds; every operation returns
/// `LR_ERR_OTHER` with the documented stub message. Useful for testing
/// the FFI surface on platforms without a kernel route table.
#[no_mangle]
pub extern "C" fn lr_osroute_connect_stub() -> lr_osroute_t {
    guarded(
        || box_backend(Backend::connect_stub()),
        std::ptr::null_mut(),
    )
}

/// Returns the human-readable backend name compiled in (e.g.
/// `"linux-rtnetlink"`, `"freebsd-route-socket"`, `"windows-ip-helper"`,
/// `"stub"`). The pointer is valid for the lifetime of the process —
/// do not free it. Returns `NULL` only on a panic.
#[no_mangle]
pub extern "C" fn lr_osroute_platform_name() -> *const std::os::raw::c_char {
    // lr_osroute::PLATFORM_NAME is a &'static str — copy into a
    // thread-local NUL-terminated buffer so the caller sees a stable
    // C string.
    thread_local! {
        static BUF: std::cell::RefCell<Vec<u8>> = const { std::cell::RefCell::new(Vec::new()) };
    }
    guarded(
        || {
            BUF.with(|b| {
                let mut b = b.borrow_mut();
                b.clear();
                b.extend_from_slice(lr_osroute::PLATFORM_NAME.as_bytes());
                b.push(0);
                b.as_ptr() as *const std::os::raw::c_char
            })
        },
        std::ptr::null(),
    )
}

/// Add a route: "to reach `prefix`, send via `next_hop` on `if_index`".
/// Returns 0 on success, negative on error:
/// - `LR_ERR_NULL` (-1): null handle / null prefix.
/// - `LR_ERR_INVALID_HANDLE` (-2): malformed prefix length.
/// - `LR_ERR_OTHER` (-6): backend error (see `lr_last_error`).
/// - `LR_ERR_PANIC` (-4): panic.
///
/// # Safety
/// `t` must be a valid handle. `prefix` must point to a readable
/// `lr_prefix_t`. `next_hop` (when non-null) must point to 4 (IPv4) or
/// 16 (IPv6) readable bytes.
#[no_mangle]
pub unsafe extern "C" fn lr_osroute_add_route(
    t: lr_osroute_t,
    prefix: *const lr_prefix_t,
    next_hop: *const u8,
    next_hop_len: usize,
    if_index: u32,
) -> i32 {
    guarded(
        || unsafe {
            let Some(table) = borrow_backend_mut(t) else {
                return LR_ERR_NULL;
            };
            if prefix.is_null() {
                return LR_ERR_NULL;
            }
            let Some(p) = (unsafe { (*prefix).to_prefix() }) else {
                set_last_error("invalid prefix length".into());
                return LR_ERR_OTHER;
            };
            let gw = match decode_next_hop(next_hop, next_hop_len) {
                Some(g) => g,
                None => {
                    set_last_error("next_hop must be 4 (IPv4) or 16 (IPv6) bytes".into());
                    return LR_ERR_OTHER;
                }
            };
            match table.add_route(p, gw, if_index) {
                Ok(()) => 0,
                Err(e) => {
                    set_last_error(e.to_string());
                    LR_ERR_OTHER
                }
            }
        },
        LR_ERR_PANIC,
    )
}

/// Add a route carrying the originating protocol's tag — the `RTPROT_*` /
/// `RouteProtocol*` kernel identifier shown by `ip route` / `route print`
/// and `lr routes list`. Backends that cannot tag fall back to
/// [`lr_osroute_add_route`].
///
/// `protocol` is one of the `LR_PROTO_*` constants (see `lr_ffi.h`).
///
/// # Safety
/// See [`lr_osroute_add_route`].
#[no_mangle]
pub unsafe extern "C" fn lr_osroute_add_route_tagged(
    t: lr_osroute_t,
    prefix: *const lr_prefix_t,
    next_hop: *const u8,
    next_hop_len: usize,
    if_index: u32,
    protocol: i32,
) -> i32 {
    guarded(
        || unsafe {
            let Some(table) = borrow_backend_mut(t) else {
                return LR_ERR_NULL;
            };
            if prefix.is_null() {
                return LR_ERR_NULL;
            }
            let Some(p) = (unsafe { (*prefix).to_prefix() }) else {
                set_last_error("invalid prefix length".into());
                return LR_ERR_OTHER;
            };
            let gw = match decode_next_hop(next_hop, next_hop_len) {
                Some(g) => g,
                None => {
                    set_last_error("next_hop must be 4 (IPv4) or 16 (IPv6) bytes".into());
                    return LR_ERR_OTHER;
                }
            };
            let Some(proto) = i32_to_protocol(protocol) else {
                set_last_error(format!("unknown protocol id {protocol}"));
                return LR_ERR_OTHER;
            };
            match table.add_route_tagged(p, gw, if_index, proto) {
                Ok(()) => 0,
                Err(e) => {
                    set_last_error(e.to_string());
                    LR_ERR_OTHER
                }
            }
        },
        LR_ERR_PANIC,
    )
}

/// Add a *blackhole* (discard) route: packets matching `prefix` are
/// silently dropped by the kernel.
///
/// # Safety
/// `t` must be a valid handle. `prefix` must point to a readable
/// `lr_prefix_t`.
#[no_mangle]
pub unsafe extern "C" fn lr_osroute_add_blackhole_route(
    t: lr_osroute_t,
    prefix: *const lr_prefix_t,
) -> i32 {
    guarded(
        || unsafe {
            let Some(table) = borrow_backend_mut(t) else {
                return LR_ERR_NULL;
            };
            if prefix.is_null() {
                return LR_ERR_NULL;
            }
            let Some(p) = (unsafe { (*prefix).to_prefix() }) else {
                set_last_error("invalid prefix length".into());
                return LR_ERR_OTHER;
            };
            match table.add_blackhole_route(p) {
                Ok(()) => 0,
                Err(e) => {
                    set_last_error(e.to_string());
                    LR_ERR_OTHER
                }
            }
        },
        LR_ERR_PANIC,
    )
}

/// Delete a route matching the prefix.
///
/// # Safety
/// See [`lr_osroute_add_blackhole_route`].
#[no_mangle]
pub unsafe extern "C" fn lr_osroute_delete_route(
    t: lr_osroute_t,
    prefix: *const lr_prefix_t,
) -> i32 {
    guarded(
        || unsafe {
            let Some(table) = borrow_backend_mut(t) else {
                return LR_ERR_NULL;
            };
            if prefix.is_null() {
                return LR_ERR_NULL;
            }
            let Some(p) = (unsafe { (*prefix).to_prefix() }) else {
                set_last_error("invalid prefix length".into());
                return LR_ERR_OTHER;
            };
            match table.delete_route(p) {
                Ok(()) => 0,
                Err(e) => {
                    set_last_error(e.to_string());
                    LR_ERR_OTHER
                }
            }
        },
        LR_ERR_PANIC,
    )
}

/// Returns the number of routes currently in the kernel FIB.
/// Returns -1 (`LR_ERR_NULL`) on a NULL handle, or `LR_ERR_OTHER` (-6)
/// on a backend error.
///
/// # Safety
/// `t` must be a valid handle.
#[no_mangle]
pub unsafe extern "C" fn lr_osroute_list_routes_count(t: lr_osroute_t) -> i64 {
    guarded(
        || unsafe {
            let Some(table) = borrow_backend_mut(t) else {
                return LR_ERR_NULL as i64;
            };
            match table.list_routes() {
                Ok(routes) => routes.len() as i64,
                Err(e) => {
                    set_last_error(e.to_string());
                    LR_ERR_OTHER as i64
                }
            }
        },
        LR_ERR_PANIC as i64,
    )
}

/// Dump all routes currently in the kernel FIB into `out` (caller-
/// allocated, at most `cap` entries). Returns the number of entries
/// written; a return value greater than `cap` means the buffer was too
/// small — call [`lr_osroute_list_routes_count`] first to size it.
///
/// # Safety
/// `t` must be a valid handle. `out` (when non-null) must point to `cap`
/// writable `lr_kernel_route_t` values.
#[no_mangle]
pub unsafe extern "C" fn lr_osroute_list_routes(
    t: lr_osroute_t,
    out: *mut lr_kernel_route_t,
    cap: usize,
) -> i64 {
    guarded(
        || unsafe {
            let Some(table) = borrow_backend_mut(t) else {
                return LR_ERR_NULL as i64;
            };
            match table.list_routes() {
                Ok(routes) => {
                    let n = routes.len();
                    if !out.is_null() && cap > 0 {
                        let to_write = n.min(cap);
                        for (i, r) in routes.iter().take(to_write).enumerate() {
                            unsafe {
                                *out.add(i) = lr_kernel_route_t::from_kernel(r);
                            }
                        }
                    }
                    n as i64
                }
                Err(e) => {
                    set_last_error(e.to_string());
                    LR_ERR_OTHER as i64
                }
            }
        },
        LR_ERR_PANIC as i64,
    )
}

/// Convenience: does the kernel currently have a route to this prefix?
/// Returns 1 (true), 0 (false), or a negative error code.
///
/// # Safety
/// `t` must be a valid handle. `prefix` must point to a readable
/// `lr_prefix_t`.
#[no_mangle]
pub unsafe extern "C" fn lr_osroute_has_route(t: lr_osroute_t, prefix: *const lr_prefix_t) -> i32 {
    guarded(
        || unsafe {
            let Some(table) = borrow_backend_mut(t) else {
                return LR_ERR_NULL;
            };
            if prefix.is_null() {
                return LR_ERR_NULL;
            }
            let Some(p) = (unsafe { (*prefix).to_prefix() }) else {
                set_last_error("invalid prefix length".into());
                return LR_ERR_OTHER;
            };
            match table.has_route(p) {
                Ok(true) => 1,
                Ok(false) => 0,
                Err(e) => {
                    set_last_error(e.to_string());
                    LR_ERR_OTHER
                }
            }
        },
        LR_ERR_PANIC,
    )
}

/// Drop a boxed route-table handle. Safe to call with NULL.
///
/// # Safety
/// `t` must have been produced by [`lr_osroute_connect`] or
/// [`lr_osroute_connect_stub`] and must not be used after this call.
#[no_mangle]
pub unsafe extern "C" fn lr_osroute_destroy(t: lr_osroute_t) {
    guarded(
        || unsafe {
            drop(unbox_backend(t));
        },
        (),
    )
}

/// Decode a next-hop pointer+len into an `IpAddr`. Returns `None` when
/// the length is not 4 or 16.
unsafe fn decode_next_hop(p: *const u8, len: usize) -> Option<IpAddr> {
    if p.is_null() {
        return None;
    }
    match len {
        4 => {
            let mut b = [0u8; 4];
            b.copy_from_slice(unsafe { std::slice::from_raw_parts(p, 4) });
            Some(IpAddr::V4(b))
        }
        16 => {
            let mut b = [0u8; 16];
            b.copy_from_slice(unsafe { std::slice::from_raw_parts(p, 16) });
            Some(IpAddr::V6(b))
        }
        _ => None,
    }
}

// ===========================================================================
// GTSM (RFC 5082) — Generalized TTL Security Mechanism.
//
// Pure data type — the kernel socket operations are platform-specific
// and live behind `arm_listener_gtsm` / `connect_gtsm` re-exports in
// lr_osroute. The FFI surface below exposes the constructors + readers
// so an embedder can build a Gtsm value programmatically and pass it
// to a daemon or another consumer of the lr-osroute API.
// ===========================================================================

/// `LR_GTSM_MODE_*` constants — discriminant for [`lr_gtsm_mode`].
pub const LR_GTSM_MODE_DISABLED: i32 = 0;
pub const LR_GTSM_MODE_SINGLE_HOP: i32 = 1;
pub const LR_GTSM_MODE_MULTIHOP: i32 = 2;

/// One GTSM configuration (RFC 5082). The struct carries the outbound
/// TTL the kernel stamps on every segment and the minimum TTL the
/// kernel requires on inbound segments.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct lr_gtsm_t {
    /// TTL set on every outbound segment. 255 for single-hop; the
    /// configured hop count for multihop. 0 when GTSM is disabled.
    pub outbound_ttl: u8,
    /// Minimum TTL required on inbound segments. 255 for single-hop;
    /// `255 - hops + 1` for multihop. 0 when GTSM is disabled.
    pub min_ttl: u8,
}

impl From<Gtsm> for lr_gtsm_t {
    fn from(g: Gtsm) -> Self {
        Self {
            outbound_ttl: g.outbound_ttl,
            min_ttl: g.min_ttl,
        }
    }
}

impl From<lr_gtsm_t> for Gtsm {
    fn from(c: lr_gtsm_t) -> Self {
        Gtsm {
            outbound_ttl: c.outbound_ttl,
            min_ttl: c.min_ttl,
        }
    }
}

/// Construct a single-hop GTSM (RFC 5082 §4.1): TTL=255 both
/// directions. This is the standard configuration for directly
/// connected eBGP.
#[no_mangle]
pub extern "C" fn lr_gtsm_single_hop() -> lr_gtsm_t {
    guarded(|| lr_gtsm_t::from(Gtsm::single_hop()), lr_gtsm_t::default())
}

/// Construct a multihop GTSM (RFC 5082 §4.2). `hops` must be in
/// `1..=254` (255 is single-hop; 0 is meaningless). Returns the
/// zero-default struct and sets the last-error string when `hops`
/// is out of range — callers that want to validate up front should
/// check the returned `outbound_ttl` is non-zero.
#[no_mangle]
pub extern "C" fn lr_gtsm_multihop(hops: u8) -> lr_gtsm_t {
    guarded(
        || {
            // Gtsm::multihop panics on out-of-range — clamp here so the
            // FFI entry point never panics across the C boundary.
            if !(1..=254).contains(&hops) {
                set_last_error(format!("multihop TTL must be 1..=254 (got {hops})"));
                return lr_gtsm_t::default();
            }
            lr_gtsm_t::from(Gtsm::multihop(hops))
        },
        lr_gtsm_t::default(),
    )
}

/// Construct a disabled GTSM (no TTL enforcement). Equivalent to the
/// default `lr_gtsm_t`.
#[no_mangle]
pub extern "C" fn lr_gtsm_disabled() -> lr_gtsm_t {
    guarded(lr_gtsm_t::default, lr_gtsm_t::default())
}

/// Read the outbound TTL field. Returns 0 on a disabled GTSM.
#[no_mangle]
pub extern "C" fn lr_gtsm_outbound_ttl(g: lr_gtsm_t) -> u8 {
    g.outbound_ttl
}

/// Read the minimum inbound TTL field. Returns 0 on a disabled GTSM.
#[no_mangle]
pub extern "C" fn lr_gtsm_min_ttl(g: lr_gtsm_t) -> u8 {
    g.min_ttl
}

/// True when GTSM is effectively a no-op (both fields are zero).
/// Returns 1 (true) or 0 (false).
#[no_mangle]
pub extern "C" fn lr_gtsm_is_disabled(g: lr_gtsm_t) -> u8 {
    Gtsm::from(g).is_disabled() as u8
}

/// Categorise the GTSM as one of the `LR_GTSM_MODE_*` constants.
#[no_mangle]
pub extern "C" fn lr_gtsm_mode(g: lr_gtsm_t) -> i32 {
    let inner = Gtsm::from(g);
    if inner.is_disabled() {
        LR_GTSM_MODE_DISABLED
    } else if inner.outbound_ttl == 255 && inner.min_ttl == 255 {
        LR_GTSM_MODE_SINGLE_HOP
    } else {
        LR_GTSM_MODE_MULTIHOP
    }
}

// ===========================================================================
// TCP authentication (RFC 2385 TCP-MD5 / RFC 5925 TCP-AO).
//
// Pure data type — the kernel socket operations live behind
// `arm_listener` / `connect_auth` in lr_osroute. The FFI surface
// exposes the constructors + readers so an embedder can build a
// TcpAuth value programmatically.
// ===========================================================================

/// `LR_TCP_AUTH_*` constants — discriminant for [`lr_tcp_auth_kind`].
pub const LR_TCP_AUTH_NONE: i32 = 0;
pub const LR_TCP_AUTH_MD5: i32 = 1;
pub const LR_TCP_AUTH_AO: i32 = 2;

/// `LR_TCP_AO_ALG_*` constants — mirrors [`TcpAoAlgorithm`].
pub const LR_TCP_AO_ALG_HMAC_SHA1: i32 = 0;
pub const LR_TCP_AO_ALG_CMAC_AES128: i32 = 1;

/// Maximum key length accepted by [`lr_tcp_ao_key_new`] (RFC 5925
/// §2 / RFC 5926: 80 octets).
pub const LR_TCP_AUTH_MAX_KEY_LEN: usize = 80;

/// One TCP-AO Master Key Tuple (RFC 5925 §3.1).
///
/// The kernel consumes the raw key bytes; the FFI surface exposes
/// `send_id`, `recv_id` and a length-prefixed key buffer so the
/// embedder can build an MKT without copying through a Rust `Vec`.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct lr_tcp_ao_key_t {
    /// KeyID placed in the TCP-AO option of outgoing segments
    /// (`sndid`).
    pub send_id: u8,
    /// KeyID that must appear in the peer's segments to select this
    /// MKT (`rcvid`).
    pub recv_id: u8,
    /// Length of the raw key bytes in `key_buf` (1..=
    /// [`LR_TCP_AUTH_MAX_KEY_LEN`]).
    pub key_len: usize,
    /// Raw key bytes (the first `key_len` bytes are read; the rest is
    /// zero-padded). Keeping the buffer at the maximum length avoids
    /// a heap allocation per MKT.
    pub key_buf: [u8; LR_TCP_AUTH_MAX_KEY_LEN],
}

impl Default for lr_tcp_ao_key_t {
    fn default() -> Self {
        Self {
            send_id: 0,
            recv_id: 0,
            key_len: 0,
            key_buf: [0; LR_TCP_AUTH_MAX_KEY_LEN],
        }
    }
}

impl TryFrom<lr_tcp_ao_key_t> for TcpAoKey {
    type Error = &'static str;
    fn try_from(c: lr_tcp_ao_key_t) -> Result<Self, Self::Error> {
        if c.key_len == 0 || c.key_len > LR_TCP_AUTH_MAX_KEY_LEN {
            return Err("key length out of range");
        }
        Ok(TcpAoKey {
            send_id: c.send_id,
            recv_id: c.recv_id,
            key: c.key_buf[..c.key_len].to_vec(),
        })
    }
}

/// Construct a symmetric MKT (`send_id == recv_id`, the common case).
/// `id` is the KeyID placed in both directions; `key` points to
/// `key_len` raw key bytes (1..=80). Returns 0 on success and writes
/// the MKT to `*out`; returns `LR_ERR_NULL` (-1) on a null key/out
/// pointer, `LR_ERR_OTHER` (-6) when the key length is out of range.
///
/// # Safety
/// `key` must point to `key_len` readable bytes (NULL only when
/// `key_len == 0`). `out` must point to a writable
/// `lr_tcp_ao_key_t`.
#[no_mangle]
pub unsafe extern "C" fn lr_tcp_ao_key_symmetric(
    id: u8,
    key: *const u8,
    key_len: usize,
    out: *mut lr_tcp_ao_key_t,
) -> i32 {
    guarded(
        || unsafe {
            if out.is_null() {
                return LR_ERR_NULL;
            }
            if key.is_null() && key_len != 0 {
                return LR_ERR_NULL;
            }
            if key_len == 0 || key_len > LR_TCP_AUTH_MAX_KEY_LEN {
                set_last_error(format!(
                    "key length {key_len} out of range (1..={})",
                    LR_TCP_AUTH_MAX_KEY_LEN
                ));
                return LR_ERR_OTHER;
            }
            let mut c = lr_tcp_ao_key_t {
                send_id: id,
                recv_id: id,
                key_len,
                key_buf: [0; LR_TCP_AUTH_MAX_KEY_LEN],
            };
            if !key.is_null() {
                unsafe {
                    std::ptr::copy_nonoverlapping(key, c.key_buf.as_mut_ptr(), key_len);
                }
            }
            unsafe { *out = c };
            0
        },
        LR_ERR_PANIC,
    )
}

/// Construct an MKT with distinct send/receive KeyIDs. Same contract
/// as [`lr_tcp_ao_key_symmetric`] but `send_id` and `recv_id` can
/// differ.
///
/// # Safety
/// See [`lr_tcp_ao_key_symmetric`].
#[no_mangle]
pub unsafe extern "C" fn lr_tcp_ao_key_new(
    send_id: u8,
    recv_id: u8,
    key: *const u8,
    key_len: usize,
    out: *mut lr_tcp_ao_key_t,
) -> i32 {
    guarded(
        || unsafe {
            if out.is_null() {
                return LR_ERR_NULL;
            }
            if key.is_null() && key_len != 0 {
                return LR_ERR_NULL;
            }
            if key_len == 0 || key_len > LR_TCP_AUTH_MAX_KEY_LEN {
                set_last_error(format!(
                    "key length {key_len} out of range (1..={})",
                    LR_TCP_AUTH_MAX_KEY_LEN
                ));
                return LR_ERR_OTHER;
            }
            let mut c = lr_tcp_ao_key_t {
                send_id,
                recv_id,
                key_len,
                key_buf: [0; LR_TCP_AUTH_MAX_KEY_LEN],
            };
            if !key.is_null() {
                unsafe {
                    std::ptr::copy_nonoverlapping(key, c.key_buf.as_mut_ptr(), key_len);
                }
            }
            unsafe { *out = c };
            0
        },
        LR_ERR_PANIC,
    )
}

/// Read the send_id / recv_id / key_len from an MKT. Returns 0 on
/// success, `LR_ERR_NULL` on a null key/out pointer.
///
/// # Safety
/// `key` must point to a readable `lr_tcp_ao_key_t`. The three out
/// pointers must be non-null.
#[no_mangle]
pub unsafe extern "C" fn lr_tcp_ao_key_read(
    key: *const lr_tcp_ao_key_t,
    out_send_id: *mut u8,
    out_recv_id: *mut u8,
    out_key_len: *mut usize,
) -> i32 {
    guarded(
        || unsafe {
            if key.is_null()
                || out_send_id.is_null()
                || out_recv_id.is_null()
                || out_key_len.is_null()
            {
                return LR_ERR_NULL;
            }
            let k = unsafe { &*key };
            unsafe {
                *out_send_id = k.send_id;
                *out_recv_id = k.recv_id;
                *out_key_len = k.key_len;
            }
            0
        },
        LR_ERR_PANIC,
    )
}

/// Copy the raw key bytes from an MKT into `out_buf`. Writes at most
/// `cap` bytes; returns the total key length (>= 0) — a return value
/// greater than `cap` means the buffer was too small.
///
/// # Safety
/// `key` must point to a readable `lr_tcp_ao_key_t`. `out_buf` (when
/// non-null) must point to `cap` writable bytes.
#[no_mangle]
pub unsafe extern "C" fn lr_tcp_ao_key_copy(
    key: *const lr_tcp_ao_key_t,
    out_buf: *mut u8,
    cap: usize,
) -> i64 {
    guarded(
        || unsafe {
            if key.is_null() {
                return LR_ERR_NULL as i64;
            }
            let k = unsafe { &*key };
            let n = k.key_len;
            if !out_buf.is_null() && cap > 0 {
                let to_write = n.min(cap);
                unsafe {
                    std::ptr::copy_nonoverlapping(k.key_buf.as_ptr(), out_buf, to_write);
                }
            }
            n as i64
        },
        LR_ERR_PANIC as i64,
    )
}

/// Categorise a [`TcpAuth`] value as one of the `LR_TCP_AUTH_*`
/// constants.
///
/// # Safety
/// `auth` must be a valid `lr_tcp_auth_t` pointer.
#[no_mangle]
pub unsafe extern "C" fn lr_tcp_auth_kind(auth: lr_tcp_auth_t) -> i32 {
    guarded(
        || unsafe {
            if auth.is_null() {
                return LR_ERR_NULL;
            }
            let inner: &lr_tcp_auth_t_inner = unsafe { &*(auth as *const lr_tcp_auth_t_inner) };
            match &inner.inner {
                TcpAuth::None => LR_TCP_AUTH_NONE,
                TcpAuth::Md5 { .. } => LR_TCP_AUTH_MD5,
                TcpAuth::Ao { .. } => LR_TCP_AUTH_AO,
            }
        },
        LR_ERR_PANIC,
    )
}

/// True (1) when the auth configuration is `None` (plain TCP).
///
/// # Safety
/// `auth` must be a valid `lr_tcp_auth_t` pointer.
#[no_mangle]
pub unsafe extern "C" fn lr_tcp_auth_is_none(auth: lr_tcp_auth_t) -> u8 {
    guarded(
        || unsafe {
            if auth.is_null() {
                return 0;
            }
            let inner: &lr_tcp_auth_t_inner = unsafe { &*(auth as *const lr_tcp_auth_t_inner) };
            match &inner.inner {
                TcpAuth::None => 1,
                _ => 0,
            }
        },
        0,
    )
}

/// Construct a `TcpAuth::None` (plain TCP, no authentication). The
/// returned handle is owned by the caller; free with
/// [`lr_tcp_auth_free`].
#[no_mangle]
pub extern "C" fn lr_tcp_auth_new_none() -> lr_tcp_auth_t {
    guarded(|| box_tcp_auth(TcpAuth::None), std::ptr::null_mut())
}

/// Construct a `TcpAuth::Md5` (RFC 2385) with one shared secret.
/// `key` points to `key_len` raw key bytes (1..=80). Returns NULL on
/// error (the last-error string is set).
///
/// # Safety
/// `key` must point to `key_len` readable bytes (NULL only when
/// `key_len == 0`).
#[no_mangle]
pub unsafe extern "C" fn lr_tcp_auth_new_md5(key: *const u8, key_len: usize) -> lr_tcp_auth_t {
    guarded(
        || unsafe {
            if key.is_null() && key_len != 0 {
                set_last_error("null key with non-zero length".into());
                return std::ptr::null_mut();
            }
            let key_vec = if key.is_null() {
                Vec::new()
            } else {
                unsafe { std::slice::from_raw_parts(key, key_len).to_vec() }
            };
            match TcpAuth::md5(key_vec) {
                Ok(a) => box_tcp_auth(a),
                Err(e) => {
                    set_last_error(e.to_string());
                    std::ptr::null_mut()
                }
            }
        },
        std::ptr::null_mut(),
    )
}

/// Construct a `TcpAuth::Ao` (RFC 5925). `keys` is an array of
/// `lr_tcp_ao_key_t` (at least one entry required). `algorithm` is
/// one of the `LR_TCP_AO_ALG_*` constants. `mac_len` is the MAC
/// length in bytes (0 selects the algorithm default). Returns NULL
/// on error.
///
/// # Safety
/// `keys` must point to `keys_count` readable `lr_tcp_ao_key_t`
/// values. The caller retains ownership of the array; the FFI copies
/// the values into a Rust `Vec<TcpAoKey>`.
#[no_mangle]
pub unsafe extern "C" fn lr_tcp_auth_new_ao(
    keys: *const lr_tcp_ao_key_t,
    keys_count: usize,
    algorithm: i32,
    mac_len: u8,
) -> lr_tcp_auth_t {
    guarded(
        || unsafe {
            if keys.is_null() && keys_count != 0 {
                set_last_error("null keys array with non-zero count".into());
                return std::ptr::null_mut();
            }
            let alg = match algorithm {
                LR_TCP_AO_ALG_HMAC_SHA1 => TcpAoAlgorithm::HmacSha1,
                LR_TCP_AO_ALG_CMAC_AES128 => TcpAoAlgorithm::CmacAes128,
                _ => {
                    set_last_error(format!("unknown TCP-AO algorithm id {algorithm}"));
                    return std::ptr::null_mut();
                }
            };
            let mut key_vec = Vec::with_capacity(keys_count);
            if !keys.is_null() {
                for i in 0..keys_count {
                    let c = unsafe { *keys.add(i) };
                    match TcpAoKey::try_from(c) {
                        Ok(k) => key_vec.push(k),
                        Err(e) => {
                            set_last_error(format!("key {i}: {e}"));
                            return std::ptr::null_mut();
                        }
                    }
                }
            }
            match TcpAuth::tcp_ao(key_vec, alg, mac_len) {
                Ok(a) => box_tcp_auth(a),
                Err(e) => {
                    set_last_error(e.to_string());
                    std::ptr::null_mut()
                }
            }
        },
        std::ptr::null_mut(),
    )
}

/// Drop a boxed `TcpAuth`. Safe to call with NULL.
///
/// # Safety
/// `auth` must have been produced by `lr_tcp_auth_new_*` and not
/// already freed.
#[no_mangle]
pub unsafe extern "C" fn lr_tcp_auth_free(auth: lr_tcp_auth_t) {
    guarded(
        || unsafe {
            drop(unbox_tcp_auth(auth));
        },
        (),
    )
}

/// Opaque `TcpAuth` handle. C side never touches internals.
#[repr(C)]
pub struct OpaqueTcpAuth {
    _private: [u8; 0],
}

pub type lr_tcp_auth_t = *mut OpaqueTcpAuth;

/// Boxed `TcpAuth` shape — owns the inner `TcpAuth` value.
struct lr_tcp_auth_t_inner {
    inner: TcpAuth,
}

fn box_tcp_auth(a: TcpAuth) -> lr_tcp_auth_t {
    Box::into_raw(Box::new(lr_tcp_auth_t_inner { inner: a })) as lr_tcp_auth_t
}

/// Reclaim a `TcpAuth` handle back into its boxed form.
///
/// # Safety
/// `a` must have been produced by [`box_tcp_auth`] and not already
/// freed.
unsafe fn unbox_tcp_auth(a: lr_tcp_auth_t) -> Option<Box<lr_tcp_auth_t_inner>> {
    if a.is_null() {
        return None;
    }
    Some(unsafe { Box::from_raw(a as *mut lr_tcp_auth_t_inner) })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v4_prefix(a: [u8; 4], len: u8) -> lr_prefix_t {
        let mut buf = [0u8; 16];
        buf[..4].copy_from_slice(&a);
        lr_prefix_t {
            addr: buf,
            is_ipv6: 0,
            prefix_len: len,
        }
    }

    #[test]
    fn ffi_osroute_platform_name_is_non_empty() {
        let name = lr_osroute_platform_name();
        assert!(!name.is_null());
        let s = unsafe { std::ffi::CStr::from_ptr(name) }
            .to_string_lossy()
            .into_owned();
        assert!(!s.is_empty(), "platform name should not be empty: {s}");
    }

    #[test]
    fn ffi_osroute_stub_returns_empty_list() {
        let t = lr_osroute_connect_stub();
        assert!(!t.is_null());
        let n = unsafe { lr_osroute_list_routes_count(t) };
        assert_eq!(n, 0, "stub backend should report 0 routes");

        // list_routes writes 0 entries into a 4-entry buffer.
        let mut out = [lr_kernel_route_t::default(); 4];
        let n = unsafe { lr_osroute_list_routes(t, out.as_mut_ptr(), 4) };
        assert_eq!(n, 0);

        unsafe { lr_osroute_destroy(t) };
    }

    #[test]
    fn ffi_osroute_stub_rejects_add() {
        let t = lr_osroute_connect_stub();
        let p = v4_prefix([10, 0, 0, 0], 8);
        let nh = [1u8, 2, 3, 4];
        let rc = unsafe { lr_osroute_add_route(t, &raw const p, nh.as_ptr(), 4, 1) };
        assert_eq!(rc, LR_ERR_OTHER);

        // has_route on the stub should report false (empty list).
        let rc = unsafe { lr_osroute_has_route(t, &raw const p) };
        assert_eq!(rc, 0);

        // delete_route on the stub also errors.
        let rc = unsafe { lr_osroute_delete_route(t, &raw const p) };
        assert_eq!(rc, LR_ERR_OTHER);

        // add_blackhole_route also errors.
        let rc = unsafe { lr_osroute_add_blackhole_route(t, &raw const p) };
        assert_eq!(rc, LR_ERR_OTHER);

        unsafe { lr_osroute_destroy(t) };
    }

    #[test]
    fn ffi_osroute_null_handle_returns_lr_err_null() {
        let p = v4_prefix([10, 0, 0, 0], 8);
        let nh = [1u8, 2, 3, 4];
        unsafe {
            assert_eq!(
                lr_osroute_add_route(std::ptr::null_mut(), &raw const p, nh.as_ptr(), 4, 1),
                LR_ERR_NULL
            );
            assert_eq!(
                lr_osroute_delete_route(std::ptr::null_mut(), &raw const p),
                LR_ERR_NULL
            );
            assert_eq!(
                lr_osroute_list_routes_count(std::ptr::null_mut()),
                LR_ERR_NULL as i64
            );
            assert_eq!(
                lr_osroute_has_route(std::ptr::null_mut(), &raw const p),
                LR_ERR_NULL
            );
        }
    }

    #[test]
    fn ffi_osroute_null_prefix_returns_lr_err_null() {
        let t = lr_osroute_connect_stub();
        let nh = [1u8, 2, 3, 4];
        unsafe {
            assert_eq!(
                lr_osroute_add_route(t, std::ptr::null(), nh.as_ptr(), 4, 1),
                LR_ERR_NULL
            );
            assert_eq!(lr_osroute_delete_route(t, std::ptr::null()), LR_ERR_NULL);
            assert_eq!(lr_osroute_has_route(t, std::ptr::null()), LR_ERR_NULL);
        }
        unsafe { lr_osroute_destroy(t) };
    }

    #[test]
    fn ffi_osroute_bad_prefix_length_returns_lr_err_other() {
        let t = lr_osroute_connect_stub();
        // v4 prefix length 200 is invalid.
        let mut p = v4_prefix([10, 0, 0, 0], 200);
        let nh = [1u8, 2, 3, 4];
        unsafe {
            assert_eq!(
                lr_osroute_add_route(t, &raw const p, nh.as_ptr(), 4, 1),
                LR_ERR_OTHER
            );
        }
        let _ = &mut p;
        unsafe { lr_osroute_destroy(t) };
    }

    #[test]
    fn ffi_osroute_bad_next_hop_length_returns_lr_err_other() {
        let t = lr_osroute_connect_stub();
        let p = v4_prefix([10, 0, 0, 0], 8);
        let nh = [1u8, 2, 3]; // wrong length
        unsafe {
            assert_eq!(
                lr_osroute_add_route(t, &raw const p, nh.as_ptr(), 3, 1),
                LR_ERR_OTHER
            );
        }
        unsafe { lr_osroute_destroy(t) };
    }

    #[test]
    fn ffi_osroute_unknown_protocol_returns_lr_err_other() {
        let t = lr_osroute_connect_stub();
        let p = v4_prefix([10, 0, 0, 0], 8);
        let nh = [1u8, 2, 3, 4];
        unsafe {
            assert_eq!(
                lr_osroute_add_route_tagged(t, &raw const p, nh.as_ptr(), 4, 1, 9999),
                LR_ERR_OTHER
            );
        }
        unsafe { lr_osroute_destroy(t) };
    }

    #[test]
    fn ffi_osroute_destroy_handles_null_safely() {
        unsafe { lr_osroute_destroy(std::ptr::null_mut()) };
    }

    #[test]
    fn ffi_kernel_route_from_blackhole() {
        // A blackhole route has no next hop and no if_index.
        let r = KernelRoute {
            prefix: lr_core::addr::Prefix::new_v4([10, 0, 0, 0], 8),
            next_hop: None,
            if_index: None,
            metric: 0,
            protocol: Protocol::Static,
        };
        let c = lr_kernel_route_t::from_kernel(&r);
        assert_eq!(c.next_hop_present, 0);
        assert_eq!(c.if_index_present, 0);
        assert_eq!(c.protocol, 4); // LR_PROTO_STATIC
    }

    #[test]
    fn ffi_kernel_route_from_ipv6_unicast() {
        let r = KernelRoute {
            prefix: lr_core::addr::Prefix::new_v6(
                [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                32,
            ),
            next_hop: Some(IpAddr::V6([
                0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
            ])),
            if_index: Some(2),
            metric: 100,
            protocol: Protocol::Bgp,
        };
        let c = lr_kernel_route_t::from_kernel(&r);
        assert_eq!(c.next_hop_present, 1);
        assert_eq!(c.next_hop_is_ipv6, 1);
        assert_eq!(&c.next_hop[..2], &[0xfe, 0x80]);
        assert_eq!(c.if_index_present, 1);
        assert_eq!(c.if_index, 2);
        assert_eq!(c.metric, 100);
        assert_eq!(c.protocol, 0); // LR_PROTO_BGP
    }

    #[test]
    fn ffi_osroute_protocol_round_trip() {
        for p in [
            Protocol::Bgp,
            Protocol::Ospfv2,
            Protocol::Ospfv3,
            Protocol::Babel,
            Protocol::Static,
            Protocol::Connected,
            Protocol::Other(123),
        ] {
            let v = protocol_to_i32(p);
            let p2 = i32_to_protocol(v).unwrap();
            assert_eq!(p, p2, "protocol {p:?} did not round-trip via {v}");
        }
        // Unknown id returns None.
        assert!(i32_to_protocol(9999).is_none());
        assert!(i32_to_protocol(-1).is_none());
    }

    // ---- GTSM tests ----

    #[test]
    fn ffi_gtsm_single_hop() {
        let g = lr_gtsm_single_hop();
        assert_eq!(g.outbound_ttl, 255);
        assert_eq!(g.min_ttl, 255);
        assert_eq!(lr_gtsm_is_disabled(g), 0);
        assert_eq!(lr_gtsm_mode(g), LR_GTSM_MODE_SINGLE_HOP);
    }

    #[test]
    fn ffi_gtsm_multihop() {
        let g = lr_gtsm_multihop(5);
        assert_eq!(g.outbound_ttl, 5);
        // min_ttl = 255 - 5 + 1 = 251.
        assert_eq!(g.min_ttl, 251);
        assert_eq!(lr_gtsm_is_disabled(g), 0);
        assert_eq!(lr_gtsm_mode(g), LR_GTSM_MODE_MULTIHOP);
    }

    #[test]
    fn ffi_gtsm_multihop_rejects_out_of_range() {
        // 0 is invalid — returns the disabled struct.
        let g = lr_gtsm_multihop(0);
        assert_eq!(g.outbound_ttl, 0);
        assert_eq!(lr_gtsm_is_disabled(g), 1);
        assert_eq!(lr_gtsm_mode(g), LR_GTSM_MODE_DISABLED);

        // 255 is single-hop, not multihop — also returns disabled.
        let g = lr_gtsm_multihop(255);
        assert_eq!(g.outbound_ttl, 0);
        assert_eq!(lr_gtsm_is_disabled(g), 1);
    }

    #[test]
    fn ffi_gtsm_disabled() {
        let g = lr_gtsm_disabled();
        assert_eq!(g.outbound_ttl, 0);
        assert_eq!(g.min_ttl, 0);
        assert_eq!(lr_gtsm_is_disabled(g), 1);
        assert_eq!(lr_gtsm_mode(g), LR_GTSM_MODE_DISABLED);
    }

    #[test]
    fn ffi_gtsm_outbound_and_min_ttl_readers() {
        let g = lr_gtsm_multihop(10);
        assert_eq!(lr_gtsm_outbound_ttl(g), 10);
        // min_ttl = 255 - 10 + 1 = 246.
        assert_eq!(lr_gtsm_min_ttl(g), 246);
    }

    // ---- TCP-AO key tests ----

    #[test]
    fn ffi_tcp_ao_key_symmetric_round_trip() {
        let key = [0u8; 20]; // 20-byte HMAC-SHA1 key
        let mut out = lr_tcp_ao_key_t::default();
        let rc = unsafe { lr_tcp_ao_key_symmetric(42, key.as_ptr(), 20, &raw mut out) };
        assert_eq!(rc, 0);
        assert_eq!(out.send_id, 42);
        assert_eq!(out.recv_id, 42);
        assert_eq!(out.key_len, 20);

        // Read back.
        let mut send_id = 0u8;
        let mut recv_id = 0u8;
        let mut key_len = 0usize;
        let rc = unsafe {
            lr_tcp_ao_key_read(
                &raw const out,
                &raw mut send_id,
                &raw mut recv_id,
                &raw mut key_len,
            )
        };
        assert_eq!(rc, 0);
        assert_eq!(send_id, 42);
        assert_eq!(recv_id, 42);
        assert_eq!(key_len, 20);

        // Copy the key bytes back.
        let mut buf = [0u8; 20];
        let n = unsafe { lr_tcp_ao_key_copy(&raw const out, buf.as_mut_ptr(), 20) };
        assert_eq!(n, 20);
        assert_eq!(buf, key);
    }

    #[test]
    fn ffi_tcp_ao_key_new_with_distinct_ids() {
        let key = [1u8, 2, 3, 4];
        let mut out = lr_tcp_ao_key_t::default();
        let rc = unsafe { lr_tcp_ao_key_new(10, 20, key.as_ptr(), 4, &raw mut out) };
        assert_eq!(rc, 0);
        assert_eq!(out.send_id, 10);
        assert_eq!(out.recv_id, 20);
        assert_eq!(out.key_len, 4);
    }

    #[test]
    fn ffi_tcp_ao_key_rejects_zero_length() {
        let mut out = lr_tcp_ao_key_t::default();
        let rc = unsafe { lr_tcp_ao_key_symmetric(1, std::ptr::null(), 0, &raw mut out) };
        assert_eq!(rc, LR_ERR_OTHER);
    }

    #[test]
    fn ffi_tcp_ao_key_rejects_oversize() {
        let key = [0u8; 81]; // > MAX_KEY_LEN (80)
        let mut out = lr_tcp_ao_key_t::default();
        let rc = unsafe { lr_tcp_ao_key_symmetric(1, key.as_ptr(), 81, &raw mut out) };
        assert_eq!(rc, LR_ERR_OTHER);
    }

    #[test]
    fn ffi_tcp_ao_key_read_handles_null() {
        let mut send_id = 0u8;
        let mut recv_id = 0u8;
        let mut key_len = 0usize;
        let rc = unsafe {
            lr_tcp_ao_key_read(
                std::ptr::null(),
                &raw mut send_id,
                &raw mut recv_id,
                &raw mut key_len,
            )
        };
        assert_eq!(rc, LR_ERR_NULL);
    }

    #[test]
    fn ffi_tcp_ao_key_copy_handles_null() {
        let n = unsafe { lr_tcp_ao_key_copy(std::ptr::null(), std::ptr::null_mut(), 0) };
        assert_eq!(n, LR_ERR_NULL as i64);
    }

    // ---- TcpAuth tests ----

    #[test]
    fn ffi_tcp_auth_none_round_trip() {
        let a = lr_tcp_auth_new_none();
        assert!(!a.is_null());
        assert_eq!(unsafe { lr_tcp_auth_kind(a) }, LR_TCP_AUTH_NONE);
        assert_eq!(unsafe { lr_tcp_auth_is_none(a) }, 1);
        unsafe { lr_tcp_auth_free(a) };
    }

    #[test]
    fn ffi_tcp_auth_md5_round_trip() {
        let key = [0u8; 16]; // 16-byte MD5 key
        let a = unsafe { lr_tcp_auth_new_md5(key.as_ptr(), 16) };
        assert!(!a.is_null());
        assert_eq!(unsafe { lr_tcp_auth_kind(a) }, LR_TCP_AUTH_MD5);
        assert_eq!(unsafe { lr_tcp_auth_is_none(a) }, 0);
        unsafe { lr_tcp_auth_free(a) };
    }

    #[test]
    fn ffi_tcp_auth_md5_rejects_zero_length() {
        let a = unsafe { lr_tcp_auth_new_md5(std::ptr::null(), 0) };
        assert!(a.is_null());
    }

    #[test]
    fn ffi_tcp_auth_ao_round_trip() {
        // Build one MKT.
        let key = [0u8; 20];
        let mut mkt = lr_tcp_ao_key_t::default();
        unsafe { lr_tcp_ao_key_symmetric(1, key.as_ptr(), 20, &raw mut mkt) };
        let mkts = [mkt];
        let a = unsafe {
            lr_tcp_auth_new_ao(
                mkts.as_ptr(),
                1,
                LR_TCP_AO_ALG_HMAC_SHA1,
                0, // default mac_len
            )
        };
        assert!(!a.is_null());
        assert_eq!(unsafe { lr_tcp_auth_kind(a) }, LR_TCP_AUTH_AO);
        assert_eq!(unsafe { lr_tcp_auth_is_none(a) }, 0);
        unsafe { lr_tcp_auth_free(a) };
    }

    #[test]
    fn ffi_tcp_auth_ao_rejects_empty_keys() {
        let a = unsafe { lr_tcp_auth_new_ao(std::ptr::null(), 0, LR_TCP_AO_ALG_HMAC_SHA1, 0) };
        assert!(a.is_null());
    }

    #[test]
    fn ffi_tcp_auth_ao_rejects_unknown_algorithm() {
        let key = [0u8; 20];
        let mut mkt = lr_tcp_ao_key_t::default();
        unsafe { lr_tcp_ao_key_symmetric(1, key.as_ptr(), 20, &raw mut mkt) };
        let mkts = [mkt];
        let a = unsafe { lr_tcp_auth_new_ao(mkts.as_ptr(), 1, 999, 0) };
        assert!(a.is_null());
    }

    #[test]
    fn ffi_tcp_auth_kind_handles_null() {
        assert_eq!(
            unsafe { lr_tcp_auth_kind(std::ptr::null_mut()) },
            LR_ERR_NULL
        );
        assert_eq!(unsafe { lr_tcp_auth_is_none(std::ptr::null_mut()) }, 0);
    }

    #[test]
    fn ffi_tcp_auth_free_handles_null_safely() {
        unsafe { lr_tcp_auth_free(std::ptr::null_mut()) };
    }
}
