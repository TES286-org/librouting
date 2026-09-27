//! Source-address compatibility diagnostic for outbound TCP connections.
//!
//! When a BGP/Babel daemon binds an outbound connection to a configured
//! `local_address` that is *not* on the kernel's chosen egress interface
//! for the peer, the kernel may silently override the source address
//! (Windows Strong Host Model) or fail the bind entirely. Either way the
//! peer sees a connection from an address it does not expect, the
//! session fails to match its `neighbor <ip>` configuration, and the
//! operator is left looking at a NOTIFICATION storm with no clue why.
//!
//! This module asks the kernel the same question `connect()` will ask
//! at TCP-open time — "what source address would you use to reach this
//! destination?" — and reports back so the daemon can warn *at startup*,
//! before the first dial, instead of after the peer has already sent a
//! Cease / Connection Collision Resolution NOTIFICATION.
//!
//! ## Platform support
//!
//! | Platform | Status |
//! |----------|--------|
//! | Windows  | yes — `GetBestRoute2` returns the kernel's chosen source |
//! | Linux    | yes (no-op) — the rtnetlink helper is not yet factored out |
//! | other    | yes (no-op) — the diagnostic returns `Ok` so the daemon still runs |
//!
//! The function is safe to call at startup; it performs one syscall per
//! peer and never blocks.

use lr_core::addr::IpAddr;

/// The kernel's answer to "what source address would you use to reach
/// `peer`?" — `None` when the kernel has no opinion (the diagnostic
/// falls back to "no warning").
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KernelSource {
    /// The source IP the kernel would select for an outbound
    /// connection to `peer`.
    pub source: IpAddr,
    /// The interface index the kernel would egress through.
    pub if_index: u32,
}

/// The result of [`check_source_compatibility`]. `Ok` means the
/// configured `local` matches the kernel's choice; the `Mismatch` and
/// `NoRoute` variants carry the detail the daemon should log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SourceCheck {
    /// The configured source matches the kernel's choice (or the
    /// kernel has no opinion / the platform does not implement the
    /// diagnostic).
    Ok,
    /// The kernel would source the connection from a different
    /// address than the configured `local`. The daemon should warn
    /// the operator — on Windows this typically means the Strong
    /// Host Model is in effect and the peer will not recognise the
    /// connection (the production report's `peer sent NOTIFICATION
    /// code=6 sub=7` storm).
    Mismatch {
        configured: IpAddr,
        kernel_choice: KernelSource,
    },
    /// The kernel reported no route to the peer at all. The daemon
    /// should warn — the connection will fail with `ENETUNREACH` /
    /// `WSAENETUNREACH` at TCP-open time.
    NoRoute,
}

/// Ask the kernel what source address it would use for an outbound
/// connection to `peer`, and compare it with the configured `local`.
///
/// This is a *hint*, not a gate: the daemon still attempts the
/// connection (the kernel's answer may change between this call and
/// `connect()`, and some platforms permit `IP_FREEBIND` /
/// `SO_REUSEADDR` overrides the diagnostic cannot see). The returned
/// [`SourceCheck`] is purely for the operator's log.
///
/// Returns [`SourceCheck::Ok`] on platforms that do not implement the
/// diagnostic, so callers can run unconditionally without a platform
/// explosion.
pub fn check_source_compatibility(local: IpAddr, peer: IpAddr) -> SourceCheck {
    imp::check_source_compatibility(local, peer)
}

#[cfg(all(feature = "std", target_os = "windows"))]
mod imp {
    use super::*;
    use windows_sys::Win32::Foundation::NO_ERROR;
    use windows_sys::Win32::NetworkManagement::IpHelper::{GetBestRoute2, MIB_IPFORWARD_ROW2};
    use windows_sys::Win32::Networking::WinSock::{
        AF_INET, AF_INET6, SOCKADDR_IN, SOCKADDR_IN6, SOCKADDR_INET,
    };

    /// Windows IP Helper's `GetBestRoute2` returns both the best route
    /// and the best source address — exactly the question this
    /// diagnostic needs to answer. The Strong Host Model is the
    /// default on Windows; when `local` is on a different interface
    /// than the egress, `GetBestRoute2` reports the egress interface's
    /// address as the source, not the configured `local`.
    pub fn check_source_compatibility(local: IpAddr, peer: IpAddr) -> SourceCheck {
        let destination = sockaddr_for(&peer);
        let mut best_route: MIB_IPFORWARD_ROW2 = unsafe { core::mem::zeroed() };
        let mut best_source: SOCKADDR_INET = unsafe { core::mem::zeroed() };
        // SAFETY: null InterfaceLuid/source select the current
        // compartment and any source; both output pointers refer to
        // live stack values. The struct layouts are
        // machine-generated from the Windows SDK metadata by the
        // `windows-sys` crate (same FFI surface `windows.rs` uses).
        let rc = unsafe {
            GetBestRoute2(
                core::ptr::null(),
                0,
                core::ptr::null(),
                &destination,
                0,
                &mut best_route,
                &mut best_source,
            )
        };
        if rc != NO_ERROR {
            return SourceCheck::NoRoute;
        }
        if best_route.InterfaceIndex == 0 {
            return SourceCheck::NoRoute;
        }
        // SAFETY: `best_source` was initialised by `GetBestRoute2`; the
        // family tag and the appropriate arm are valid. The read pattern
        // matches `windows.rs::inet_addr_of`.
        let kernel_source = unsafe { inet_addr_of(&best_source) };
        if kernel_source == local {
            return SourceCheck::Ok;
        }
        SourceCheck::Mismatch {
            configured: local,
            kernel_choice: KernelSource {
                source: kernel_source,
                if_index: best_route.InterfaceIndex,
            },
        }
    }

    /// Build a `SOCKADDR_INET` from an `IpAddr`. Mirrors
    /// `windows.rs::sockaddr_for` minus the scope-id handling (the
    /// diagnostic does not need link-local scoping — `GetBestRoute2`
    /// resolves it from the destination's interface).
    fn sockaddr_for(addr: &IpAddr) -> SOCKADDR_INET {
        let mut sa: SOCKADDR_INET = unsafe { core::mem::zeroed() };
        match addr {
            IpAddr::V4(b) => {
                // SAFETY: writing the Ipv4 arm of the union. The
                // union is zeroed so unused fields are 0.
                let v4 = unsafe { &mut *core::ptr::addr_of_mut!(sa).cast::<SOCKADDR_IN>() };
                v4.sin_family = AF_INET;
                v4.sin_addr.S_un.S_un_b.s_b1 = b[0];
                v4.sin_addr.S_un.S_un_b.s_b2 = b[1];
                v4.sin_addr.S_un.S_un_b.s_b3 = b[2];
                v4.sin_addr.S_un.S_un_b.s_b4 = b[3];
            }
            IpAddr::V6(b) => {
                // SAFETY: writing the Ipv6 arm of the union.
                let v6 = unsafe { &mut *core::ptr::addr_of_mut!(sa).cast::<SOCKADDR_IN6>() };
                v6.sin6_family = AF_INET6;
                v6.sin6_addr.u.Byte = *b;
            }
        }
        sa
    }

    /// # Safety
    /// The caller must guarantee `sa` holds a valid SOCKADDR_INET
    /// initialised by the IP Helper API (or by `sockaddr_for`). The
    /// read pattern matches `windows.rs::inet_addr_of`.
    unsafe fn inet_addr_of(sa: &SOCKADDR_INET) -> IpAddr {
        // SAFETY: `si_family` aliases the first two bytes of both
        // arms — reading it before deciding which arm to read is the
        // documented SOCKADDR_INET access pattern.
        let family = unsafe { sa.si_family };
        if family == AF_INET6 {
            // SAFETY: reading the Ipv6 arm.
            let v6 = unsafe { &*core::ptr::addr_of!(*sa).cast::<SOCKADDR_IN6>() };
            IpAddr::V6(v6.sin6_addr.u.Byte)
        } else {
            // SAFETY: reading the Ipv4 arm.
            let v4 = unsafe { &*core::ptr::addr_of!(*sa).cast::<SOCKADDR_IN>() };
            let s = &v4.sin_addr.S_un.S_un_b;
            IpAddr::V4([s.s_b1, s.s_b2, s.s_b3, s.s_b4])
        }
    }
}

#[cfg(all(feature = "std", target_os = "linux"))]
mod imp {
    use super::*;

    /// Linux `RTM_GETROUTE` with `RTA_PREFSRC` reports the kernel's
    /// preferred source address for a destination. When the daemon
    /// binds to a `local` that is not on the egress interface, the
    /// kernel's `connect()` would either fail (Strong Host Model is
    /// the default for routed output) or silently use the egress
    /// interface's address — this diagnostic surfaces the mismatch
    /// before the dial.
    ///
    /// The full rtnetlink RTM_GETROUTE flow lives in `linux.rs`;
    /// re-implementing it here would duplicate the FFI surface. The
    /// diagnostic is a hint — fall back to Ok on Linux until the
    /// rtnetlink helper is factored out. The Windows path is the
    /// high-value one (Strong Host Model is the default and the
    /// production report comes from Windows).
    pub fn check_source_compatibility(local: IpAddr, peer: IpAddr) -> SourceCheck {
        let _ = (local, peer);
        SourceCheck::Ok
    }
}

#[cfg(all(feature = "std", not(any(target_os = "linux", target_os = "windows"))))]
mod imp {
    use super::*;

    /// Platforms without a native source-resolution helper: return
    /// `Ok` so the daemon still runs. The diagnostic is purely
    /// informational; its absence does not block the connection.
    pub fn check_source_compatibility(_local: IpAddr, _peer: IpAddr) -> SourceCheck {
        SourceCheck::Ok
    }
}

#[cfg(all(not(feature = "std"), not(target_os = "windows")))]
mod imp {
    use super::*;

    pub fn check_source_compatibility(_local: IpAddr, _peer: IpAddr) -> SourceCheck {
        SourceCheck::Ok
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The no-op platform (the cfg branch that compiles when no
    /// native helper is available) returns `Ok` — the diagnostic is
    /// a hint, not a gate, so callers can run unconditionally.
    #[cfg(not(target_os = "windows"))]
    #[test]
    fn non_windows_returns_ok() {
        let local = IpAddr::V4([172, 23, 10, 102]);
        let peer = IpAddr::V4([172, 23, 10, 98]);
        assert!(matches!(
            check_source_compatibility(local, peer),
            SourceCheck::Ok
        ));
    }

    /// A loopback-to-loopback check on Windows must agree (the kernel
    /// sources loopback-to-loopback from the loopback address).
    /// Skipped on platforms that do not implement the diagnostic.
    #[cfg(target_os = "windows")]
    #[test]
    fn loopback_matches() {
        let local = IpAddr::V4([127, 0, 0, 1]);
        let peer = IpAddr::V4([127, 0, 0, 1]);
        assert!(matches!(
            check_source_compatibility(local, peer),
            SourceCheck::Ok
        ));
    }
}
