//! FFI surface for the daemon-wired cross-protocol features
//! (ROADMAP-v3 D4.4): redistribution pipes, BGP aggregates and RFC
//! 2439 route damping.
//!
//! These entry points give C/C++/Go/Python embedders the same
//! capabilities the TOML daemon surface (`[[redistribute]]`,
//! `[[aggregate]]`, `[damping]`) wires at start-up:
//!
//! * [`lr_router_add_redistribution_pipe`] — install a
//!   [`RedistributionPipe`](lr_router::redistribution::RedistributionPipe)
//!   (BIRD `pipe` / FRR `redistribute`).
//! * [`lr_router_add_aggregate`] / [`lr_router_remove_aggregate`] —
//!   RFC 4271 §9.2.2.2 aggregates.
//! * [`lr_router_set_damping`] — install the RFC 2439 damping import
//!   hook and hand back a shared [`lr_damping_t`] handle the embedder
//!   drives with [`lr_damping_decay`] (the daemon's
//!   `lr-damping-decay` thread is the in-process analogue).
//!
//! # Safety
//!
//! Same contract as the rest of the crate: `catch_unwind` barrier,
//! null checks, and handles that must outlive no call after
//! `_destroy`.

use crate::error::set_last_error;
use crate::error::LR_ERR_PANIC;
use crate::guarded;
use crate::handle::{lock_router, lr_damping_t, lr_router_t, OpaqueDamping};
use lr_core::addr::{Asn, Prefix};
use lr_core::rib::Protocol;
use lr_router::redistribution::{MetricPolicy, RedistributionPipe};
use std::sync::{Arc, Mutex};

/// Wire protocol identifier for FFI entry points. Mirrors
/// `lr_core::rib::Protocol`'s named variants (`Other(u16)` is not
/// reachable through the C ABI).
#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LrProtocol {
    Bgp = 0,
    Ospf = 1,
    Ospf3 = 2,
    Babel = 3,
    Static = 4,
    Connected = 5,
}

impl LrProtocol {
    pub(crate) fn from_i32(v: i32) -> Option<Self> {
        match v {
            0 => Some(Self::Bgp),
            1 => Some(Self::Ospf),
            2 => Some(Self::Ospf3),
            3 => Some(Self::Babel),
            4 => Some(Self::Static),
            5 => Some(Self::Connected),
            _ => None,
        }
    }

    fn to_protocol(self) -> Protocol {
        match self {
            Self::Bgp => Protocol::Bgp,
            Self::Ospf => Protocol::Ospfv2,
            Self::Ospf3 => Protocol::Ospfv3,
            Self::Babel => Protocol::Babel,
            Self::Static => Protocol::Static,
            Self::Connected => Protocol::Connected,
        }
    }
}

/// Metric transformation for a redistribution pipe. Mirrors
/// `lr_router::redistribution::MetricPolicy`.
#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LrMetricPolicy {
    /// Use the source route's metric unchanged.
    Inherit = 0,
    /// Always advertise `metric`.
    Fixed = 1,
    /// Add `metric` to the source metric (saturating).
    Add = 2,
}

impl LrMetricPolicy {
    fn from_i32(v: i32) -> Option<Self> {
        match v {
            0 => Some(Self::Inherit),
            1 => Some(Self::Fixed),
            2 => Some(Self::Add),
            _ => None,
        }
    }
}

/// One IPv4/IPv6 prefix (embedder-side). IPv4 addresses go in the
/// first four bytes of `addr` with `is_ipv6 = 0`; IPv6 uses all
/// sixteen bytes with `is_ipv6 = 1` — the same convention as
/// `lr_roa_entry_t`.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct lr_prefix_t {
    pub addr: [u8; 16],
    pub is_ipv6: u8,
    pub prefix_len: u8,
}

impl lr_prefix_t {
    fn to_prefix(self) -> Option<Prefix> {
        if self.is_ipv6 == 0 {
            if self.prefix_len > 32 {
                return None;
            }
            Some(Prefix::new_v4(
                [self.addr[0], self.addr[1], self.addr[2], self.addr[3]],
                self.prefix_len,
            ))
        } else {
            if self.prefix_len > 128 {
                return None;
            }
            Some(Prefix::new_v6(self.addr, self.prefix_len))
        }
    }
}

/// RFC 2439 §4.7 damping tunables. Mirrors
/// `lr_damping::DampingConfig` field-for-field.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct lr_damping_config_t {
    pub additive_incr: u32,
    pub suppress_threshold: u32,
    pub reuse_threshold: u32,
    pub upper_limit: u32,
    pub decay_interval_s: u64,
    pub decay_factor_active: f64,
    pub decay_factor_withdrawn: f64,
}

impl lr_damping_config_t {
    fn to_config(self) -> lr_damping::DampingConfig {
        lr_damping::DampingConfig {
            additive_incr: self.additive_incr,
            suppress_threshold: self.suppress_threshold,
            reuse_threshold: self.reuse_threshold,
            upper_limit: self.upper_limit,
            decay_interval_s: self.decay_interval_s,
            decay_factor_active: self.decay_factor_active,
            decay_factor_withdrawn: self.decay_factor_withdrawn,
        }
    }
}

/// Install one redistribution pipe on the router.
///
/// `source` / `target` are [`LrProtocol`] values, `metric_policy` a
/// [`LrMetricPolicy`]. `has_tag` gates `tag` (any non-zero installs
/// the tag). `allow` / `allow_count` carry an optional allow-list of
/// prefixes (NULL / 0 = redistribute everything). Returns 0 on
/// success, -1 on a null argument, -2 on an invalid router handle,
/// -3 on a malformed argument (unknown protocol id, bad prefix
/// length), and [`LR_ERR_PANIC`] if the body panics.
///
/// # Safety
/// `r` must be a live router handle. `allow` (when non-null) must
/// point to `allow_count` readable `lr_prefix_t` values.
#[no_mangle]
pub unsafe extern "C" fn lr_router_add_redistribution_pipe(
    r: lr_router_t,
    source: i32,
    target: i32,
    metric_policy: i32,
    metric: u32,
    has_tag: i32,
    tag: u32,
    allow: *const lr_prefix_t,
    allow_count: usize,
) -> i32 {
    guarded(
        || {
            let Some(src) = LrProtocol::from_i32(source) else {
                set_last_error(format!("unknown source protocol id {source}"));
                return -3;
            };
            let Some(dst) = LrProtocol::from_i32(target) else {
                set_last_error(format!("unknown target protocol id {target}"));
                return -3;
            };
            let Some(mp) = LrMetricPolicy::from_i32(metric_policy) else {
                set_last_error(format!("unknown metric policy id {metric_policy}"));
                return -3;
            };
            let allow_prefixes = if allow.is_null() || allow_count == 0 {
                Vec::new()
            } else {
                let mut out = Vec::with_capacity(allow_count);
                for i in 0..allow_count {
                    let p = unsafe { *allow.add(i) };
                    match p.to_prefix() {
                        Some(prefix) => {
                            let ip = prefix.network();
                            out.push((ip, prefix.prefix_len));
                        }
                        None => {
                            set_last_error(format!(
                                "allow prefix {i}: invalid prefix length {}",
                                p.prefix_len
                            ));
                            return -3;
                        }
                    }
                }
                out
            };
            let mut pipe = RedistributionPipe::new(src.to_protocol(), dst.to_protocol())
                .with_metric(match mp {
                    LrMetricPolicy::Inherit => MetricPolicy::Inherit,
                    LrMetricPolicy::Fixed => MetricPolicy::Fixed(metric),
                    LrMetricPolicy::Add => MetricPolicy::Add(metric),
                })
                .with_allow_prefixes(allow_prefixes);
            if has_tag != 0 {
                pipe = pipe.with_tag(tag);
            }
            let mut router = match unsafe { lock_router(r) } {
                Some(g) => g,
                None => return -2,
            };
            router.add_redistribution_pipe(pipe);
            0
        },
        LR_ERR_PANIC,
    )
}

/// Register an RFC 4271 §9.2.2.2 aggregate. The aggregate is
/// originated while a more-specific exists and withdrawn when the
/// last one disappears. Returns 0 on success, -1 / -2 / -3 on
/// null / invalid-handle / malformed-prefix.
///
/// # Safety
/// `r` must be a live router handle; `prefix` must be a readable
/// `lr_prefix_t`.
#[no_mangle]
pub unsafe extern "C" fn lr_router_add_aggregate(
    r: lr_router_t,
    prefix: *const lr_prefix_t,
) -> i32 {
    guarded(
        || {
            if prefix.is_null() {
                return -1;
            }
            let p = unsafe { *prefix };
            let Some(prefix) = p.to_prefix() else {
                set_last_error(format!("invalid aggregate prefix length {}", p.prefix_len));
                return -3;
            };
            let mut router = match unsafe { lock_router(r) } {
                Some(g) => g,
                None => return -2,
            };
            router.add_aggregate(prefix);
            0
        },
        LR_ERR_PANIC,
    )
}

/// Withdraw a previously registered aggregate. Removing an unknown
/// prefix is a no-op that still returns 0 (the router treats it the
/// same way).
///
/// # Safety
/// See [`lr_router_add_aggregate`].
#[no_mangle]
pub unsafe extern "C" fn lr_router_remove_aggregate(
    r: lr_router_t,
    prefix: *const lr_prefix_t,
) -> i32 {
    guarded(
        || {
            if prefix.is_null() {
                return -1;
            }
            let p = unsafe { *prefix };
            let Some(prefix) = p.to_prefix() else {
                set_last_error(format!("invalid aggregate prefix length {}", p.prefix_len));
                return -3;
            };
            let mut router = match unsafe { lock_router(r) } {
                Some(g) => g,
                None => return -2,
            };
            router.remove_aggregate(&prefix);
            0
        },
        LR_ERR_PANIC,
    )
}

/// Install the RFC 2439 damping import hook with the supplied
/// tunables and return a shared [`lr_damping_t`] handle. The embedder
/// drives decay with [`lr_damping_decay`] (the in-process analogue of
/// the daemon's `lr-damping-decay` thread) and frees the handle with
/// [`lr_damping_destroy`]. Installing damping twice replaces nothing —
/// the second hook simply chains after the first; call this once per
/// router.
///
/// Returns NULL on null/invalid arguments (the last-error string says
/// which) and the handle otherwise.
///
/// # Safety
/// `r` must be a live router handle; `cfg` must be a readable
/// `lr_damping_config_t`.
#[no_mangle]
pub unsafe extern "C" fn lr_router_set_damping(
    r: lr_router_t,
    cfg: *const lr_damping_config_t,
) -> lr_damping_t {
    guarded(
        || {
            if cfg.is_null() {
                set_last_error("null damping config".to_string());
                return std::ptr::null_mut();
            }
            let raw = unsafe { &*cfg };
            let table = Arc::new(Mutex::new(lr_damping::DampingTable::new(
                (*raw).to_config(),
            )));
            let hook = lr_policy::hooks::DampingImportHook::new(Arc::clone(&table));
            let mut router = match unsafe { lock_router(r) } {
                Some(g) => g,
                None => {
                    set_last_error("invalid router handle".to_string());
                    return std::ptr::null_mut();
                }
            };
            router.hooks_mut().import.push(Box::new(hook));
            box_damping(table)
        },
        std::ptr::null_mut(),
    )
}

/// Drive one damping decay pass at wall-clock `now_s` (seconds).
/// Returns the number of prefixes that re-emerged from suppression
/// (>= 0), or negative error codes on null / invalid handles.
///
/// # Safety
/// `d` must be a live damping handle from [`lr_router_set_damping`].
#[no_mangle]
pub unsafe extern "C" fn lr_damping_decay(d: *mut OpaqueDamping, now_s: u64) -> i32 {
    guarded(
        || {
            if d.is_null() {
                return -1;
            }
            let t = unsafe { &*(d as *const Arc<Mutex<lr_damping::DampingTable>>) };
            let mut table = match t.lock() {
                Ok(g) => g,
                Err(_) => return -2,
            };
            let re_emerged = table.decay_all(now_s);
            i32::try_from(re_emerged.len()).unwrap_or(i32::MAX)
        },
        LR_ERR_PANIC,
    )
}

/// Free a damping handle. The hook installed on the router keeps its
/// own `Arc`, so damping continues until the router is destroyed;
/// destroying the handle only releases the embedder's decay access.
///
/// # Safety
/// `d` must be null or a handle returned by [`lr_router_set_damping`]
/// that has not been destroyed yet, and must not be used afterwards.
#[no_mangle]
pub unsafe extern "C" fn lr_damping_destroy(d: *mut OpaqueDamping) {
    guarded(
        || {
            if !d.is_null() {
                drop(unsafe { Box::from_raw(d as *mut Arc<Mutex<lr_damping::DampingTable>>) });
            }
        },
        (),
    )
}

fn box_damping(t: Arc<Mutex<lr_damping::DampingTable>>) -> lr_damping_t {
    Box::into_raw(Box::new(t)) as lr_damping_t
}

/// Keep the Asn import referenced when feature combinations trim the
/// surface (the aggregation path does not use it today, but the
/// pipe/allow-list machinery will grow tag-aware filtering).
#[allow(dead_code)]
fn _asn_witness(a: Asn) -> u32 {
    a.0
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::router::{lr_router_destroy, lr_router_new};

    fn r() -> lr_router_t {
        lr_router_new()
    }

    fn v4_prefix(a: [u8; 4], len: u8) -> lr_prefix_t {
        let mut addr = [0u8; 16];
        addr[..4].copy_from_slice(&a);
        lr_prefix_t {
            addr,
            is_ipv6: 0,
            prefix_len: len,
        }
    }

    #[test]
    fn add_redistribution_pipe_round_trip() {
        let r = r();
        let allow = [v4_prefix([10, 0, 0, 0], 8)];
        let rc = unsafe {
            lr_router_add_redistribution_pipe(
                r,
                LrProtocol::Ospf as i32,
                LrProtocol::Bgp as i32,
                LrMetricPolicy::Fixed as i32,
                100,
                1,
                65000,
                allow.as_ptr(),
                1,
            )
        };
        assert_eq!(rc, 0);
        unsafe { lr_router_destroy(r) };
    }

    #[test]
    fn add_redistribution_pipe_rejects_unknown_protocol() {
        let r = r();
        let rc = unsafe {
            lr_router_add_redistribution_pipe(
                r,
                99,
                LrProtocol::Bgp as i32,
                LrMetricPolicy::Inherit as i32,
                0,
                0,
                0,
                std::ptr::null(),
                0,
            )
        };
        assert_eq!(rc, -3);
        unsafe { lr_router_destroy(r) };
    }

    #[test]
    fn add_aggregate_accepts_and_rejects_bad_lengths() {
        let r = r();
        assert_eq!(
            unsafe { lr_router_add_aggregate(r, &v4_prefix([203, 0, 113, 0], 24)) },
            0
        );
        let mut bad = v4_prefix([0, 0, 0, 0], 0);
        bad.prefix_len = 33;
        assert_eq!(unsafe { lr_router_add_aggregate(r, &bad) }, -3);
        assert_eq!(unsafe { lr_router_add_aggregate(r, std::ptr::null()) }, -1);
        // remove is a no-op returning 0 even for an unknown prefix
        assert_eq!(
            unsafe { lr_router_remove_aggregate(r, &v4_prefix([10, 0, 0, 0], 8)) },
            0
        );
        unsafe { lr_router_destroy(r) };
    }

    #[test]
    fn damping_install_decay_and_destroy() {
        let r = r();
        let cfg = lr_damping_config_t {
            additive_incr: lr_damping::DEFAULT_ADDITIVE_INCR,
            suppress_threshold: lr_damping::DEFAULT_SUPPRESS_THRESHOLD,
            reuse_threshold: lr_damping::DEFAULT_REUSE_THRESHOLD,
            upper_limit: lr_damping::DEFAULT_UPPER_LIMIT,
            decay_interval_s: lr_damping::DEFAULT_DECAY_INTERVAL_S,
            decay_factor_active: lr_damping::DEFAULT_DECAY_FACTOR_ACTIVE,
            decay_factor_withdrawn: lr_damping::DEFAULT_DECAY_FACTOR_WITHDRAWN,
        };
        let d = unsafe { lr_router_set_damping(r, &cfg) };
        assert!(!d.is_null());
        // A decay pass on an idle table re-emerges nothing.
        assert_eq!(unsafe { lr_damping_decay(d, 1000) }, 0);
        unsafe { lr_damping_destroy(d) };
        unsafe { lr_router_destroy(r) };
    }

    #[test]
    fn damping_null_arguments_are_errors() {
        let r = r();
        assert!(unsafe { lr_router_set_damping(r, std::ptr::null()) }.is_null());
        let cfg = lr_damping_config_t {
            additive_incr: 1000,
            suppress_threshold: 2000,
            reuse_threshold: 750,
            upper_limit: 8000,
            decay_interval_s: 10,
            decay_factor_active: 0.5,
            decay_factor_withdrawn: 0.6,
        };
        let d = unsafe { lr_router_set_damping(std::ptr::null_mut(), &cfg) };
        assert!(d.is_null());
        assert_eq!(unsafe { lr_damping_decay(std::ptr::null_mut(), 0) }, -1);
        unsafe { lr_router_destroy(r) };
    }
}
