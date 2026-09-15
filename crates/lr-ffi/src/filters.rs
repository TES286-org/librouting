//! Filter DSL over the C ABI (ROADMAP-v3 D5.2).
//!
//! `lr_filter_compile` parses a BIRD-like filter body and compiles it
//! to the D3.7 stack VM — the same hot path the daemon executes on
//! every import/export. `lr_filter_evaluate` runs the compiled filter
//! against a route handle ([`lr_route_t`], D5.3) and reports the
//! verdict; an optional reject reason comes back as an owned byte
//! buffer.
//!
//! # The context problem
//!
//! The DSL reads and mutates route attributes through the
//! `FilterContext` trait. Over the C ABI that trait is served two
//! ways:
//!
//! * The **built-in route-backed context** (the default, used when
//!   `ctx` is NULL): attribute reads and writes go through the same
//!   `lr_policy::bgp` accessors the daemon's context uses, i.e. they
//!   operate directly on the route handle's path attributes.
//!   `roa.state` is `not-found` by default — the route handle carries
//!   no RPKI data.
//! * A **C callback table** ([`lr_filter_context_t`]): every field may
//!   be NULL, which keeps the built-in behaviour; a non-NULL callback
//!   overrides exactly that aspect (e.g. resolve `roa.state` from a
//!   live ROA store, or serve attributes from the embedder's own
//!   data plane).
//!
//! Runtime evaluation errors (type mismatches, unknown functions,
//! runaway recursion, ...) abort the filter and surface as
//! `LR_FILTER_FALLTHROUGH` — identical to the daemon's behaviour;
//! configuration mistakes are caught by `lr_filter_compile` instead.
//!
//! # Safety
//!
//! Same contract as the rest of the crate: `catch_unwind` barrier,
//! null checks, documented error codes. Callback pointers must stay
//! valid for the duration of the `lr_filter_evaluate` call only.

use crate::error::{set_last_error, LR_ERR_PANIC};
use crate::guarded;
use crate::handle::lr_bytes_t;
use crate::handle::{lr_filter_t, lr_route_t};
use crate::policy_objects::lr_ext_comm_t;
use crate::roa_store::{LR_ROA_INVALID, LR_ROA_VALID};
use lr_core::addr::{Asn, IpAddr};
use lr_core::rib::Route;
use lr_policy::filter::bytecode::{self, CompiledFilter};
use lr_policy::filter::{FilterContext, RoaStateLit};
use std::ffi::CStr;

/// Verdict codes (`lr_filter_evaluate` out parameter).
pub const LR_FILTER_ACCEPT: i32 = 0;
pub const LR_FILTER_REJECT: i32 = 1;
pub const LR_FILTER_FALLTHROUGH: i32 = 2;

/// The C callback table backing a [`FilterContext`]. Every field may
/// be NULL to keep the built-in route-backed behaviour.
///
/// Accessor conventions: `out = NULL` / `out_cap = 0` asks for the
/// required element count; with a buffer the return value is the
/// number of elements written; a negative return means "absent" for
/// the accessor (evaluation continues with the attribute missing).
///
/// # Safety
///
/// Each function pointer, when non-NULL, is invoked synchronously
/// from `lr_filter_evaluate` with the `user_data` pointer and the
/// route handle being evaluated. Implementations must not destroy the
/// route handle or call back into the same filter.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct lr_filter_context_t {
    pub user_data: *mut std::ffi::c_void,
    /// LOCAL_PREF: return 1 with `out` written when present, 0 when
    /// absent.
    pub bgp_local_pref: Option<
        unsafe extern "C" fn(
            user_data: *mut std::ffi::c_void,
            route: lr_route_t,
            out: *mut u32,
        ) -> i32,
    >,
    /// MULTI_EXIT_DISC: 1 present / 0 absent.
    pub bgp_med: Option<
        unsafe extern "C" fn(
            user_data: *mut std::ffi::c_void,
            route: lr_route_t,
            out: *mut u32,
        ) -> i32,
    >,
    /// NEXT_HOP: 1 present (out_is_v6 + 16-byte out written) / 0 absent.
    pub bgp_next_hop: Option<
        unsafe extern "C" fn(
            user_data: *mut std::ffi::c_void,
            route: lr_route_t,
            out_is_v6: *mut i32,
            out: *mut u8,
        ) -> i32,
    >,
    /// AS_PATH sequence.
    pub bgp_as_path: Option<
        unsafe extern "C" fn(
            user_data: *mut std::ffi::c_void,
            route: lr_route_t,
            out: *mut u32,
            cap: usize,
        ) -> i64,
    >,
    /// Standard communities as packed `asn << 16 | value`.
    pub bgp_communities: Option<
        unsafe extern "C" fn(
            user_data: *mut std::ffi::c_void,
            route: lr_route_t,
            out: *mut u64,
            cap: usize,
        ) -> i64,
    >,
    /// Large communities as flat triples.
    pub bgp_large_communities: Option<
        unsafe extern "C" fn(
            user_data: *mut std::ffi::c_void,
            route: lr_route_t,
            out: *mut u32,
            cap: usize,
        ) -> i64,
    >,
    /// Extended communities.
    pub bgp_ext_communities: Option<
        unsafe extern "C" fn(
            user_data: *mut std::ffi::c_void,
            route: lr_route_t,
            out: *mut lr_ext_comm_t,
            cap: usize,
        ) -> i64,
    >,
    /// ORIGIN: 1 present / 0 absent.
    pub bgp_origin: Option<
        unsafe extern "C" fn(
            user_data: *mut std::ffi::c_void,
            route: lr_route_t,
            out: *mut u8,
        ) -> i32,
    >,
    /// RFC 6811 validation state: [`LR_ROA_VALID`],
    /// [`LR_ROA_NOT_FOUND`] or [`LR_ROA_INVALID`].
    pub roa_state:
        Option<unsafe extern "C" fn(user_data: *mut std::ffi::c_void, route: lr_route_t) -> u8>,
    pub set_bgp_local_pref: Option<
        unsafe extern "C" fn(user_data: *mut std::ffi::c_void, route: lr_route_t, value: u32),
    >,
    pub set_bgp_med: Option<
        unsafe extern "C" fn(user_data: *mut std::ffi::c_void, route: lr_route_t, value: u32),
    >,
    pub set_bgp_next_hop: Option<
        unsafe extern "C" fn(
            user_data: *mut std::ffi::c_void,
            route: lr_route_t,
            is_v6: i32,
            addr: *const u8,
        ),
    >,
    pub bgp_as_path_prepend:
        Option<unsafe extern "C" fn(user_data: *mut std::ffi::c_void, route: lr_route_t, asn: u32)>,
    pub bgp_communities_add: Option<
        unsafe extern "C" fn(
            user_data: *mut std::ffi::c_void,
            route: lr_route_t,
            asn: u32,
            value: u16,
        ),
    >,
    pub set_bgp_communities: Option<
        unsafe extern "C" fn(
            user_data: *mut std::ffi::c_void,
            route: lr_route_t,
            items: *const u64,
            count: usize,
        ),
    >,
    pub set_bgp_as_path: Option<
        unsafe extern "C" fn(
            user_data: *mut std::ffi::c_void,
            route: lr_route_t,
            seq: *const u32,
            count: usize,
        ),
    >,
    pub set_bgp_large_communities: Option<
        unsafe extern "C" fn(
            user_data: *mut std::ffi::c_void,
            route: lr_route_t,
            triples: *const u32,
            count: usize,
        ),
    >,
    pub set_bgp_ext_communities: Option<
        unsafe extern "C" fn(
            user_data: *mut std::ffi::c_void,
            route: lr_route_t,
            items: *const lr_ext_comm_t,
            count: usize,
        ),
    >,
}

impl Default for lr_filter_context_t {
    fn default() -> Self {
        // A fully-NULL table: every aspect keeps the built-in
        // route-backed behaviour.
        Self {
            user_data: std::ptr::null_mut(),
            bgp_local_pref: None,
            bgp_med: None,
            bgp_next_hop: None,
            bgp_as_path: None,
            bgp_communities: None,
            bgp_large_communities: None,
            bgp_ext_communities: None,
            bgp_origin: None,
            roa_state: None,
            set_bgp_local_pref: None,
            set_bgp_med: None,
            set_bgp_next_hop: None,
            bgp_as_path_prepend: None,
            bgp_communities_add: None,
            set_bgp_communities: None,
            set_bgp_as_path: None,
            set_bgp_large_communities: None,
            set_bgp_ext_communities: None,
        }
    }
}

/// Compile `body` under `name` to the D3.7 stack VM. Returns NULL on
/// a parse error (the last-error string carries the 1-indexed
/// line/column diagnostic) or null arguments.
///
/// # Safety
/// `name` / `body` must be readable NUL-terminated strings.
#[no_mangle]
pub unsafe extern "C" fn lr_filter_compile(
    name: *const std::ffi::c_char,
    body: *const std::ffi::c_char,
) -> lr_filter_t {
    guarded(
        || {
            let (Some(name), Some(body)) = (
                if name.is_null() {
                    None
                } else {
                    unsafe { CStr::from_ptr(name) }.to_str().ok()
                },
                if body.is_null() {
                    None
                } else {
                    unsafe { CStr::from_ptr(body) }.to_str().ok()
                },
            ) else {
                set_last_error("null or non-UTF-8 filter name/body".to_string());
                return std::ptr::null_mut();
            };
            match lr_policy::filter::compile(name, body) {
                Ok(filter) => {
                    let compiled = bytecode::compile(&filter);
                    Box::into_raw(Box::new(compiled)) as lr_filter_t
                }
                Err(e) => {
                    set_last_error(format!("filter '{name}': {e}"));
                    std::ptr::null_mut()
                }
            }
        },
        std::ptr::null_mut(),
    )
}

/// Free a compiled filter. NULL is a no-op.
///
/// # Safety
/// `filter` must be null or a handle from `lr_filter_compile` that has
/// not been freed yet, and must not be used afterwards.
#[no_mangle]
pub unsafe extern "C" fn lr_filter_free(filter: lr_filter_t) {
    guarded(
        || {
            if !filter.is_null() {
                drop(unsafe { Box::from_raw(filter as *mut CompiledFilter) });
            }
        },
        (),
    )
}

/// The compiled filter's name (NUL-terminated, probe-then-read:
/// `out = NULL` returns the required buffer size including the NUL).
/// Negative on null handle / short buffer.
///
/// # Safety
/// `out` (when non-null) must be writable for `cap` bytes.
#[no_mangle]
pub unsafe extern "C" fn lr_filter_name(filter: lr_filter_t, out: *mut u8, cap: usize) -> i64 {
    guarded(
        || {
            if filter.is_null() {
                return -1;
            }
            let f = unsafe { &*(filter as *const CompiledFilter) };
            let name = f.name.as_bytes();
            if out.is_null() {
                return (name.len() + 1) as i64;
            }
            if cap < name.len() + 1 {
                return -3;
            }
            unsafe {
                std::ptr::copy_nonoverlapping(name.as_ptr(), out, name.len());
                *out.add(name.len()) = 0;
            }
            (name.len() + 1) as i64
        },
        LR_ERR_PANIC as i64,
    )
}

/// Run the compiled filter against the route handle. `ctx` may be NULL
/// (built-in route-backed context). On [`LR_FILTER_REJECT`] the
/// optional `reject with "reason"` payload is written to `out_reason`
/// as a NUL-terminated byte buffer the caller frees with
/// `lr_bytes_free`; pass NULL to ignore it.
///
/// Returns 0 on a completed evaluation, -1 on null arguments, -2 on
/// invalid handles.
///
/// # Safety
/// `filter` / `route` must be live handles. The callbacks in `ctx`
/// must be valid for the duration of the call.
#[no_mangle]
pub unsafe extern "C" fn lr_filter_evaluate(
    filter: lr_filter_t,
    route: lr_route_t,
    ctx: *const lr_filter_context_t,
    out_verdict: *mut i32,
    out_reason: *mut lr_bytes_t,
) -> i32 {
    guarded(
        || {
            if filter.is_null() || route.is_null() || out_verdict.is_null() {
                return -1;
            }
            let f = unsafe { &*(filter as *const CompiledFilter) };
            let r = unsafe { &mut *(route as *mut Route) };
            let result = if ctx.is_null() {
                bytecode::execute(f, r, &RouteFilterContext)
            } else {
                let table = unsafe { &*ctx };
                bytecode::execute(f, r, &FfiFilterContext { table })
            };
            let verdict = match &result {
                EvalResult::Accept => LR_FILTER_ACCEPT,
                EvalResult::Reject(_) => LR_FILTER_REJECT,
                EvalResult::Fallthrough => LR_FILTER_FALLTHROUGH,
            };
            unsafe { *out_verdict = verdict };
            if let EvalResult::Reject(Some(reason)) = result {
                if !out_reason.is_null() {
                    let mut bytes = reason.into_bytes();
                    bytes.push(0);
                    unsafe { *out_reason = lr_bytes_t::from_vec(bytes) };
                }
            }
            0
        },
        LR_ERR_PANIC,
    )
}

use lr_policy::filter::EvalResult;

/// The built-in route-backed context: reads and writes the route
/// handle's own path attributes through `lr_policy::bgp` — the same
/// accessors the daemon's context uses. `roa.state` is
/// [`RoaStateLit::NotFound`] (the route handle carries no RPKI data;
/// override it via the callback table).
struct RouteFilterContext;

impl FilterContext for RouteFilterContext {
    fn bgp_local_pref(&self, route: &Route) -> Option<u32> {
        lr_policy::bgp::local_pref(route)
    }
    fn bgp_med(&self, route: &Route) -> Option<u32> {
        lr_policy::bgp::med(route)
    }
    fn bgp_next_hop(&self, route: &Route) -> Option<IpAddr> {
        route.next_hop
    }
    fn bgp_as_path(&self, route: &Route) -> Vec<Asn> {
        lr_policy::bgp::as_sequence(route)
    }
    fn bgp_communities(&self, route: &Route) -> Vec<(Asn, u16)> {
        lr_policy::bgp::communities(route)
            .into_iter()
            .map(|c| {
                let raw = c.as_u32();
                (Asn(raw >> 16), (raw & 0xFFFF) as u16)
            })
            .collect()
    }
    fn bgp_large_communities(&self, route: &Route) -> Vec<(u32, u32, u32)> {
        lr_policy::bgp::large_communities(route)
            .into_iter()
            .map(|c| (c.global_admin, c.local_data1, c.local_data2))
            .collect()
    }
    fn bgp_ext_communities(&self, route: &Route) -> Vec<(u8, u8, u32, u16)> {
        lr_policy::bgp::ext_communities(route)
            .into_iter()
            .map(|c| (c.kind, c.subtype, c.global, c.local))
            .collect()
    }
    fn bgp_origin(&self, route: &Route) -> Option<u8> {
        route
            .attributes
            .get(lr_core::attr::AttrTag::raw(1))
            .and_then(|a| a.value.first().copied())
    }
    fn roa_state(&self, _route: &Route) -> RoaStateLit {
        RoaStateLit::NotFound
    }
    fn set_bgp_local_pref(&self, route: &mut Route, value: u32) {
        lr_policy::bgp::set_local_pref(route, value)
    }
    fn set_bgp_med(&self, route: &mut Route, value: u32) {
        lr_policy::bgp::set_med(route, value)
    }
    fn set_bgp_next_hop(&self, route: &mut Route, value: IpAddr) {
        route.next_hop = Some(value);
    }
    fn bgp_as_path_prepend(&self, route: &mut Route, asn: Asn) {
        lr_policy::bgp::prepend_as(route, asn)
    }
    fn bgp_communities_add(&self, route: &mut Route, asn: Asn, value: u16) {
        if let Ok(asn16) = u16::try_from(asn.0) {
            lr_policy::bgp::add_community(
                route,
                lr_bgp::path::communities::Community::new(asn16, value),
            );
        }
    }
    fn set_bgp_communities(&self, route: &mut Route, set: Vec<(Asn, u16)>) {
        let cs = set
            .into_iter()
            .filter_map(|(asn, val)| {
                u16::try_from(asn.0)
                    .ok()
                    .map(|a| lr_bgp::path::communities::Community::new(a, val))
            })
            .collect();
        lr_policy::bgp::set_communities(route, cs)
    }
    fn set_bgp_as_path(&self, route: &mut Route, seq: Vec<Asn>) {
        lr_policy::bgp::set_as_sequence(route, seq)
    }
    fn set_bgp_large_communities(&self, route: &mut Route, set: Vec<(u32, u32, u32)>) {
        let cs = set
            .into_iter()
            .map(|(g, d1, d2)| lr_bgp::path::communities::LargeCommunity::new(g, d1, d2))
            .collect();
        lr_policy::bgp::set_large_communities(route, cs)
    }
    fn set_bgp_ext_communities(&self, route: &mut Route, set: Vec<(u8, u8, u32, u16)>) {
        let cs = set
            .into_iter()
            .map(|(k, s, g, l)| lr_bgp::path::communities::ExtendedCommunity::new(k, s, g, l))
            .collect();
        lr_policy::bgp::set_ext_communities(route, cs)
    }
}

/// The callback-table context: non-NULL fields override the built-in
/// behaviour; NULL fields delegate to [`RouteFilterContext`].
struct FfiFilterContext<'a> {
    table: &'a lr_filter_context_t,
}

impl FfiFilterContext<'_> {
    fn ud(&self) -> *mut std::ffi::c_void {
        self.table.user_data
    }
}

impl FilterContext for FfiFilterContext<'_> {
    fn bgp_local_pref(&self, route: &Route) -> Option<u32> {
        match self.table.bgp_local_pref {
            Some(cb) => {
                let mut out: u32 = 0;
                let rc = unsafe { cb(self.ud(), route as *const Route as lr_route_t, &mut out) };
                if rc != 0 {
                    Some(out)
                } else {
                    None
                }
            }
            None => RouteFilterContext.bgp_local_pref(route),
        }
    }
    fn bgp_med(&self, route: &Route) -> Option<u32> {
        match self.table.bgp_med {
            Some(cb) => {
                let mut out: u32 = 0;
                let rc = unsafe { cb(self.ud(), route as *const Route as lr_route_t, &mut out) };
                if rc != 0 {
                    Some(out)
                } else {
                    None
                }
            }
            None => RouteFilterContext.bgp_med(route),
        }
    }
    fn bgp_next_hop(&self, route: &Route) -> Option<IpAddr> {
        match self.table.bgp_next_hop {
            Some(cb) => {
                let mut is_v6: i32 = 0;
                let mut buf = [0u8; 16];
                let rc = unsafe {
                    cb(
                        self.ud(),
                        route as *const Route as lr_route_t,
                        &mut is_v6,
                        buf.as_mut_ptr(),
                    )
                };
                if rc != 0 {
                    Some(if is_v6 != 0 {
                        IpAddr::V6(buf)
                    } else {
                        IpAddr::V4([buf[0], buf[1], buf[2], buf[3]])
                    })
                } else {
                    None
                }
            }
            None => RouteFilterContext.bgp_next_hop(route),
        }
    }
    fn bgp_as_path(&self, route: &Route) -> Vec<Asn> {
        match self.table.bgp_as_path {
            Some(cb) => unsafe { collect_cb(cb, self.ud(), route) }
                .into_iter()
                .map(Asn)
                .collect(),
            None => RouteFilterContext.bgp_as_path(route),
        }
    }
    fn bgp_communities(&self, route: &Route) -> Vec<(Asn, u16)> {
        match self.table.bgp_communities {
            Some(cb) => unsafe { collect_cb_u64(cb, self.ud(), route) }
                .into_iter()
                .map(|raw| (Asn((raw >> 16) as u32), (raw & 0xFFFF) as u16))
                .collect(),
            None => RouteFilterContext.bgp_communities(route),
        }
    }
    fn bgp_large_communities(&self, route: &Route) -> Vec<(u32, u32, u32)> {
        match self.table.bgp_large_communities {
            Some(cb) => unsafe { collect_cb(cb, self.ud(), route) }
                .as_chunks::<3>()
                .0
                .iter()
                .map(|t| (t[0], t[1], t[2]))
                .collect(),
            None => RouteFilterContext.bgp_large_communities(route),
        }
    }
    fn bgp_ext_communities(&self, route: &Route) -> Vec<(u8, u8, u32, u16)> {
        match self.table.bgp_ext_communities {
            Some(cb) => {
                // Two-pass: probe, then read.
                let n = unsafe {
                    cb(
                        self.ud(),
                        route as *const Route as lr_route_t,
                        std::ptr::null_mut(),
                        0,
                    )
                };
                if n <= 0 {
                    return Vec::new();
                }
                let mut out = vec![
                    lr_ext_comm_t {
                        kind: 0,
                        subtype: 0,
                        global: 0,
                        local: 0,
                    };
                    n as usize
                ];
                let written = unsafe {
                    cb(
                        self.ud(),
                        route as *const Route as lr_route_t,
                        out.as_mut_ptr(),
                        out.len(),
                    )
                };
                if written < 0 {
                    return Vec::new();
                }
                out.truncate(written as usize);
                out.into_iter()
                    .map(|e| (e.kind, e.subtype, e.global, e.local))
                    .collect()
            }
            None => RouteFilterContext.bgp_ext_communities(route),
        }
    }
    fn bgp_origin(&self, route: &Route) -> Option<u8> {
        match self.table.bgp_origin {
            Some(cb) => {
                let mut out: u8 = 0;
                let rc = unsafe { cb(self.ud(), route as *const Route as lr_route_t, &mut out) };
                if rc != 0 {
                    Some(out)
                } else {
                    None
                }
            }
            None => RouteFilterContext.bgp_origin(route),
        }
    }
    fn roa_state(&self, route: &Route) -> RoaStateLit {
        match self.table.roa_state {
            Some(cb) => match unsafe { cb(self.ud(), route as *const Route as lr_route_t) } {
                LR_ROA_VALID => RoaStateLit::Valid,
                LR_ROA_INVALID => RoaStateLit::Invalid,
                _ => RoaStateLit::NotFound,
            },
            None => RouteFilterContext.roa_state(route),
        }
    }
    fn set_bgp_local_pref(&self, route: &mut Route, value: u32) {
        match self.table.set_bgp_local_pref {
            Some(cb) => unsafe { cb(self.ud(), route as *mut Route as lr_route_t, value) },
            None => RouteFilterContext.set_bgp_local_pref(route, value),
        }
    }
    fn set_bgp_med(&self, route: &mut Route, value: u32) {
        match self.table.set_bgp_med {
            Some(cb) => unsafe { cb(self.ud(), route as *mut Route as lr_route_t, value) },
            None => RouteFilterContext.set_bgp_med(route, value),
        }
    }
    fn set_bgp_next_hop(&self, route: &mut Route, value: IpAddr) {
        match self.table.set_bgp_next_hop {
            Some(cb) => {
                let (is_v6, bytes) = match value {
                    IpAddr::V4(o) => (0, {
                        let mut b = [0u8; 16];
                        b[..4].copy_from_slice(&o);
                        b
                    }),
                    IpAddr::V6(o) => (1, o),
                };
                unsafe {
                    cb(
                        self.ud(),
                        route as *mut Route as lr_route_t,
                        is_v6,
                        bytes.as_ptr(),
                    )
                }
            }
            None => RouteFilterContext.set_bgp_next_hop(route, value),
        }
    }
    fn bgp_as_path_prepend(&self, route: &mut Route, asn: Asn) {
        match self.table.bgp_as_path_prepend {
            Some(cb) => unsafe { cb(self.ud(), route as *mut Route as lr_route_t, asn.0) },
            None => RouteFilterContext.bgp_as_path_prepend(route, asn),
        }
    }
    fn bgp_communities_add(&self, route: &mut Route, asn: Asn, value: u16) {
        match self.table.bgp_communities_add {
            Some(cb) => unsafe { cb(self.ud(), route as *mut Route as lr_route_t, asn.0, value) },
            None => RouteFilterContext.bgp_communities_add(route, asn, value),
        }
    }
    fn set_bgp_communities(&self, route: &mut Route, set: Vec<(Asn, u16)>) {
        match self.table.set_bgp_communities {
            Some(cb) => {
                let packed: Vec<u64> = set
                    .iter()
                    .map(|(asn, val)| ((asn.0 as u64) << 16) | u64::from(*val))
                    .collect();
                unsafe {
                    cb(
                        self.ud(),
                        route as *mut Route as lr_route_t,
                        packed.as_ptr(),
                        packed.len(),
                    )
                }
            }
            None => RouteFilterContext.set_bgp_communities(route, set),
        }
    }
    fn set_bgp_as_path(&self, route: &mut Route, seq: Vec<Asn>) {
        match self.table.set_bgp_as_path {
            Some(cb) => {
                let flat: Vec<u32> = seq.iter().map(|a| a.0).collect();
                unsafe {
                    cb(
                        self.ud(),
                        route as *mut Route as lr_route_t,
                        flat.as_ptr(),
                        flat.len(),
                    )
                }
            }
            None => RouteFilterContext.set_bgp_as_path(route, seq),
        }
    }
    fn set_bgp_large_communities(&self, route: &mut Route, set: Vec<(u32, u32, u32)>) {
        match self.table.set_bgp_large_communities {
            Some(cb) => {
                let flat: Vec<u32> = set.iter().flat_map(|(g, d1, d2)| [*g, *d1, *d2]).collect();
                unsafe {
                    cb(
                        self.ud(),
                        route as *mut Route as lr_route_t,
                        flat.as_ptr(),
                        set.len(),
                    )
                }
            }
            None => RouteFilterContext.set_bgp_large_communities(route, set),
        }
    }
    fn set_bgp_ext_communities(&self, route: &mut Route, set: Vec<(u8, u8, u32, u16)>) {
        match self.table.set_bgp_ext_communities {
            Some(cb) => {
                let items: Vec<lr_ext_comm_t> = set
                    .iter()
                    .map(|(k, s, g, l)| lr_ext_comm_t {
                        kind: *k,
                        subtype: *s,
                        global: *g,
                        local: *l,
                    })
                    .collect();
                unsafe {
                    cb(
                        self.ud(),
                        route as *mut Route as lr_route_t,
                        items.as_ptr(),
                        items.len(),
                    )
                }
            }
            None => RouteFilterContext.set_bgp_ext_communities(route, set),
        }
    }
}

/// Two-pass array callback: probe for the count, then read. A
/// negative probe or read means "absent".
unsafe fn collect_cb(
    cb: unsafe extern "C" fn(*mut std::ffi::c_void, lr_route_t, *mut u32, usize) -> i64,
    ud: *mut std::ffi::c_void,
    route: &Route,
) -> Vec<u32> {
    let rp = route as *const Route as lr_route_t;
    let n = unsafe { cb(ud, rp, std::ptr::null_mut(), 0) };
    if n <= 0 {
        return Vec::new();
    }
    let mut out = vec![0u32; n as usize];
    let written = unsafe { cb(ud, rp, out.as_mut_ptr(), out.len()) };
    if written < 0 {
        return Vec::new();
    }
    out.truncate(written as usize);
    out
}

/// Same two-pass pattern for `u64`-valued arrays.
unsafe fn collect_cb_u64(
    cb: unsafe extern "C" fn(*mut std::ffi::c_void, lr_route_t, *mut u64, usize) -> i64,
    ud: *mut std::ffi::c_void,
    route: &Route,
) -> Vec<u64> {
    let rp = route as *const Route as lr_route_t;
    let n = unsafe { cb(ud, rp, std::ptr::null_mut(), 0) };
    if n <= 0 {
        return Vec::new();
    }
    let mut out = vec![0u64; n as usize];
    let written = unsafe { cb(ud, rp, out.as_mut_ptr(), out.len()) };
    if written < 0 {
        return Vec::new();
    }
    out.truncate(written as usize);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::handle::lr_route_t;
    use crate::policy::LrProtocol;
    use crate::policy_objects::{
        lr_route_free, lr_route_new_v4, lr_route_set_as_path, lr_route_set_communities,
        lr_route_set_local_pref,
    };
    use std::ffi::CString;

    fn compile(body: &str) -> lr_filter_t {
        let name = CString::new("test").unwrap();
        let body = CString::new(body).unwrap();
        let f = unsafe { lr_filter_compile(name.as_ptr(), body.as_ptr()) };
        assert!(!f.is_null(), "compile failed");
        f
    }

    fn last_error_str() -> String {
        let ptr = crate::error::lr_last_error();
        if ptr.is_null() {
            String::new()
        } else {
            unsafe { CStr::from_ptr(ptr) }
                .to_string_lossy()
                .into_owned()
        }
    }

    fn v4_route(octets: [u8; 4], len: u8) -> lr_route_t {
        let mut addr = [0u8; 16];
        addr[..4].copy_from_slice(&octets);
        unsafe { lr_route_new_v4(addr.as_ptr(), len, LrProtocol::Bgp as i32) }
    }

    fn run(f: lr_filter_t, r: lr_route_t) -> (i32, Option<String>) {
        let mut verdict: i32 = -9;
        let mut reason: lr_bytes_t = lr_bytes_t {
            ptr: std::ptr::null_mut(),
            len: 0,
            cap: 0,
        };
        let rc = unsafe { lr_filter_evaluate(f, r, std::ptr::null(), &mut verdict, &mut reason) };
        assert_eq!(rc, 0);
        if verdict == LR_FILTER_REJECT && !reason.ptr.is_null() {
            let bytes = unsafe { reason.reclaim_into_vec() };
            let s = String::from_utf8(bytes).unwrap();
            let s = s.trim_end_matches('\0').to_string();
            (verdict, Some(s))
        } else {
            (verdict, None)
        }
    }

    #[test]
    fn compile_parse_error_is_null_with_diagnostic() {
        let name = CString::new("broken").unwrap();
        let body = CString::new("if bgp.local_pref = ").unwrap();
        let f = unsafe { lr_filter_compile(name.as_ptr(), body.as_ptr()) };
        assert!(f.is_null());
        let err = last_error_str();
        assert!(err.contains("filter 'broken'"), "diagnostic: {err}");
        // Null arguments.
        assert!(unsafe { lr_filter_compile(std::ptr::null(), body.as_ptr()) }.is_null());
        assert!(unsafe { lr_filter_compile(name.as_ptr(), std::ptr::null()) }.is_null());
    }

    #[test]
    fn accept_reject_and_fallthrough() {
        let f =
            compile("if bgp.local_pref >= 200 then { accept; } else { reject with \"too low\"; }");
        let r = v4_route([203, 0, 113, 0], 24);
        unsafe { lr_route_set_local_pref(r, 250) };
        let (v, reason) = run(f, r);
        assert_eq!(v, LR_FILTER_ACCEPT);
        assert!(reason.is_none());

        unsafe { lr_route_set_local_pref(r, 100) };
        let (v, reason) = run(f, r);
        assert_eq!(v, LR_FILTER_REJECT);
        assert_eq!(reason.as_deref(), Some("too low"));

        // Fallthrough: no terminal statement hit.
        let f2 = compile("bgp.local_pref = 77;");
        let (v, _) = run(f2, r);
        assert_eq!(v, LR_FILTER_FALLTHROUGH);
        let mut lp: u32 = 0;
        assert_eq!(
            unsafe { crate::policy_objects::lr_route_local_pref(r, &mut lp) },
            0
        );
        assert_eq!(lp, 77); // mutation still applied

        unsafe { lr_filter_free(f) };
        unsafe { lr_filter_free(f2) };
        unsafe { lr_route_free(r) };
        unsafe { lr_filter_free(std::ptr::null_mut()) };
    }

    #[test]
    fn prefix_and_community_filters() {
        // Prefix set membership (BIRD syntax).
        let f = compile("if net ~ [ 203.0.113.0/24{24,32} ] then { accept; } reject;");
        let r = v4_route([203, 0, 113, 7], 28);
        assert_eq!(run(f, r).0, LR_FILTER_ACCEPT);
        let r2 = v4_route([198, 51, 100, 0], 24);
        assert_eq!(run(f, r2).0, LR_FILTER_REJECT);

        // Community membership via packed values.
        let f2 = compile("if bgp.communities ~ [ 64512:100 ] then { accept; } reject;");
        let r3 = v4_route([203, 0, 113, 0], 24);
        let packed: [u64; 2] = [(64512u64 << 16) | 100, (65000u64 << 16) | 1];
        unsafe { lr_route_set_communities(r3, packed.as_ptr(), 2) };
        assert_eq!(run(f2, r3).0, LR_FILTER_ACCEPT);

        unsafe { lr_route_free(r) };
        unsafe { lr_route_free(r2) };
        unsafe { lr_route_free(r3) };
        unsafe { lr_filter_free(f) };
        unsafe { lr_filter_free(f2) };
    }

    #[test]
    fn as_path_and_user_function() {
        let f = compile(concat!(
            "function tag_transit() { bgp.communities += [ 64512:999 ]; return true; }\n",
            "if len(bgp.as_path) > 2 then { tag_transit(); accept; }\n",
            "reject;\n"
        ));
        let r = v4_route([203, 0, 113, 0], 24);
        let path: [u32; 3] = [64513, 65010, 64512];
        unsafe { lr_route_set_as_path(r, path.as_ptr(), 3) };
        let (v, _) = run(f, r);
        assert_eq!(v, LR_FILTER_ACCEPT);
        // The user function's community append is visible on the route.
        let n = unsafe { crate::policy_objects::lr_route_communities(r, std::ptr::null_mut(), 0) };
        assert_eq!(n, 1);
        let mut out: [u64; 1] = [0];
        unsafe { crate::policy_objects::lr_route_communities(r, out.as_mut_ptr(), 1) };
        assert_eq!(out[0], (64512u64 << 16) | 999);

        unsafe { lr_route_free(r) };
        unsafe { lr_filter_free(f) };
    }

    #[test]
    fn callback_table_overrides_roa_state() {
        // A filter consulting roa.state: the built-in context has no
        // ROA data (not-found), the callback table injects invalid.
        let f = compile("if roa.state == \"invalid\" then { reject with \"rpki\"; } accept;");
        let r = v4_route([203, 0, 113, 0], 24);

        // Built-in: not-found -> accept.
        let mut verdict: i32 = -9;
        assert_eq!(
            unsafe {
                lr_filter_evaluate(f, r, std::ptr::null(), &mut verdict, std::ptr::null_mut())
            },
            0
        );
        assert_eq!(verdict, LR_FILTER_ACCEPT);

        unsafe extern "C" fn roa_invalid(_ud: *mut std::ffi::c_void, _r: lr_route_t) -> u8 {
            LR_ROA_INVALID
        }
        let table: lr_filter_context_t = lr_filter_context_t {
            roa_state: Some(roa_invalid),
            ..Default::default()
        };
        let mut reason: lr_bytes_t = lr_bytes_t {
            ptr: std::ptr::null_mut(),
            len: 0,
            cap: 0,
        };
        assert_eq!(
            unsafe { lr_filter_evaluate(f, r, &table, &mut verdict, &mut reason) },
            0
        );
        assert_eq!(verdict, LR_FILTER_REJECT);
        let bytes = unsafe { reason.reclaim_into_vec() };
        assert_eq!(
            String::from_utf8_lossy(&bytes).trim_end_matches('\0'),
            "rpki"
        );

        unsafe { lr_route_free(r) };
        unsafe { lr_filter_free(f) };
    }

    #[test]
    fn callback_table_overrides_attribute_access() {
        // The DSL reads bgp.local_pref through the table, not the route.
        let f = compile("if bgp.local_pref > 500 then { accept; } reject;");
        let r = v4_route([203, 0, 113, 0], 24);

        unsafe extern "C" fn lp_from_ud(
            ud: *mut std::ffi::c_void,
            _r: lr_route_t,
            out: *mut u32,
        ) -> i32 {
            let v = unsafe { *(ud as *const u32) };
            unsafe { *out = v };
            1
        }
        let six_hundred: u32 = 600;
        let table: lr_filter_context_t = lr_filter_context_t {
            user_data: &six_hundred as *const u32 as *mut std::ffi::c_void,
            bgp_local_pref: Some(lp_from_ud),
            ..Default::default()
        };

        let mut verdict: i32 = -9;
        assert_eq!(
            unsafe { lr_filter_evaluate(f, r, &table, &mut verdict, std::ptr::null_mut()) },
            0
        );
        assert_eq!(verdict, LR_FILTER_ACCEPT); // table said 600 > 500

        // The route itself never had a LOCAL_PREF.
        let mut out: u32 = 0;
        assert_eq!(
            unsafe { crate::policy_objects::lr_route_local_pref(r, &mut out) },
            1
        );

        unsafe { lr_route_free(r) };
        unsafe { lr_filter_free(f) };
    }

    #[test]
    fn filter_name_probe_and_read() {
        let name = CString::new("my-export").unwrap();
        let body = CString::new("accept;").unwrap();
        let f = unsafe { lr_filter_compile(name.as_ptr(), body.as_ptr()) };
        assert!(!f.is_null());
        let need = unsafe { lr_filter_name(f, std::ptr::null_mut(), 0) };
        assert_eq!(need, "my-export".len() as i64 + 1);
        let mut buf = vec![0u8; need as usize];
        assert_eq!(
            unsafe { lr_filter_name(f, buf.as_mut_ptr(), buf.len()) },
            need
        );
        assert_eq!(&buf[..buf.len() - 1], b"my-export");
        assert_eq!(buf[buf.len() - 1], 0);
        assert_eq!(unsafe { lr_filter_name(f, buf.as_mut_ptr(), 3) }, -3);
        unsafe { lr_filter_free(f) };
    }
}
