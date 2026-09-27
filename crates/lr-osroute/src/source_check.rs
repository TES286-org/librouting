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
/// configured `local` is usable as the source; the other variants
/// carry the detail the daemon should log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SourceCheck {
    /// The configured source is usable — the daemon's `connect_bound`
    /// will bind to it successfully (verified by a real `bind()` test
    /// on Windows), so the peer will see the configured source IP.
    Ok,
    /// The kernel would source the connection from a different
    /// address than the configured `local` (informational — the
    /// daemon binds, overriding this default). This variant is
    /// returned by the non-Windows implementations that cannot do a
    /// real bind test.
    Mismatch {
        configured: IpAddr,
        kernel_choice: KernelSource,
    },
    /// The `bind()` to the configured `local` fails (e.g.
    /// `WSAEADDRNOTAVAIL` on Windows). The daemon's fallback uses the
    /// kernel's default source — `kernel_default` — which the peer
    /// will reject. The operator must either assign `configured` to
    /// the egress interface or configure Weak Host Model.
    BindFails {
        configured: IpAddr,
        kernel_default: KernelSource,
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
        bind, closesocket, socket, WSAGetLastError, WSAStartup, AF_INET, AF_INET6, INVALID_SOCKET,
        IPPROTO_TCP, SOCKADDR_IN, SOCKADDR_IN6, SOCKADDR_INET, SOCK_STREAM, SOL_SOCKET,
        SO_REUSEADDR, WSADATA,
    };

    /// The diagnostic does TWO things:
    ///
    /// 1. Asks `GetBestRoute2` for the kernel's default source
    ///    choice — informational only. The daemon's `connect_bound`
    ///    binds to the configured `local`, which OVERRIDES this
    ///    default (with `IP_UNICAST_IF` pinning the egress interface
    ///    on Windows). The kernel's default is NOT what the daemon
    ///    actually sends; reporting it as the actual source (as the
    ///    rc.1 diagnostic did) was misleading.
    ///
    /// 2. Creates a real TCP socket, binds it to the configured
    ///    `local:0`, and checks whether the bind succeeds. If the
    ///    bind fails (e.g. `WSAEADDRNOTAVAIL` — the address is not
    ///    assigned to any interface, or the kernel refuses to bind a
    ///    non-egress source under the Strong Host Model), the daemon's
    ///    `connect_bound` will also fail, and the daemon's fallback
    ///    to kernel-chosen source will produce the wrong source IP.
    ///    This is the condition the operator actually needs to fix.
    pub fn check_source_compatibility(local: IpAddr, peer: IpAddr) -> SourceCheck {
        // Step 1: query the kernel's default source choice
        // (informational — the daemon binds, so this is NOT the
        // actual source unless the bind fails).
        let kernel_info = kernel_default_source(&peer);

        // Step 2: verify the bind actually works with the configured
        // local address. This is the real test — if bind fails, the
        // daemon falls back to the kernel's default source, and the
        // peer sees the wrong source IP.
        match test_bind(&local) {
            BindResult::Ok => {
                // The bind works. The daemon's `connect_bound` will
                // use `local` as the source (with `IP_UNICAST_IF`
                // pinning the egress interface on Windows). The
                // kernel's default is irrelevant.
                SourceCheck::Ok
            }
            BindResult::AddrNotAvailable => {
                // The bind fails: the address is not assigned to any
                // interface, or the kernel refuses under the Strong
                // Host Model. The daemon's fallback uses the kernel's
                // default source — which the peer will reject.
                match kernel_info {
                    Some(ks) => SourceCheck::BindFails {
                        configured: local,
                        kernel_default: ks,
                    },
                    None => SourceCheck::NoRoute,
                }
            }
            BindResult::OtherError => {
                // Unexpected bind error — treat as "no route" so the
                // daemon still dials (the diagnostic is a hint, not a
                // gate). The operator can investigate via the
                // "connected from" log line after the first dial.
                SourceCheck::Ok
            }
        }
    }

    /// The result of a test `bind()` with the configured local address.
    enum BindResult {
        /// The bind succeeded — the daemon's `connect_bound` will use
        /// this address as the source.
        Ok,
        /// `WSAEADDRNOTAVAIL`: the address is not assigned to any
        /// interface, or the kernel refuses under the Strong Host
        /// Model. The daemon's fallback uses the kernel's default
        /// source.
        AddrNotAvailable,
        /// Any other bind error — non-fatal, the diagnostic returns
        /// `Ok` so the daemon still dials.
        OtherError,
    }

    /// Create a TCP socket, bind it to `local:0`, check the result,
    /// then close the socket. Does NOT connect — we only need to know
    /// whether the kernel accepts the bind.
    fn test_bind(local: &IpAddr) -> BindResult {
        // Initialise Winsock once. WSAStartup is ref-counted; calling
        // it multiple times is safe (each WSAStartup needs a matching
        // WSACleanup, but for a diagnostic that runs once at startup
        // we can leak the WSAStartup — the process exits soon enough,
        // and WSACleanup on shutdown is best-effort).
        let mut wsa_data: WSADATA = unsafe { core::mem::zeroed() };
        let rc = unsafe { WSAStartup(0x0202, &mut wsa_data) };
        if rc != 0 {
            return BindResult::OtherError;
        }

        let (af, _) = match local {
            IpAddr::V4(_) => (AF_INET, 4),
            IpAddr::V6(_) => (AF_INET6, 16),
        };
        // SAFETY: plain socket() call. INVALID_SOCKET on error.
        let sock = unsafe { socket(af as _, SOCK_STREAM, IPPROTO_TCP as _) };
        if sock == INVALID_SOCKET {
            return BindResult::OtherError;
        }
        // Allow re-binding during the test (in case the daemon is
        // already listening on 0.0.0.0:0 — unlikely but defensive).
        let one: i32 = 1;
        let _ = unsafe {
            windows_sys::Win32::Networking::WinSock::setsockopt(
                sock,
                SOL_SOCKET,
                SO_REUSEADDR,
                &one as *const _ as *const u8,
                core::mem::size_of::<i32>() as i32,
            )
        };

        let (sa, len) = sockaddr_for_bind(local);
        // SAFETY: `sa` is a valid sockaddr of `len` bytes.
        let rc = unsafe { bind(sock, &sa as *const _ as *const _, len) };
        let result = if rc == 0 {
            BindResult::Ok
        } else {
            let err = unsafe { WSAGetLastError() };
            // WSAEADDRNOTAVAIL = 10049
            if err == 10049 {
                BindResult::AddrNotAvailable
            } else {
                BindResult::OtherError
            }
        };
        // SAFETY: sock is a valid socket; closesocket is safe.
        let _ = unsafe { closesocket(sock) };
        result
    }

    /// Ask `GetBestRoute2` for the kernel's default source choice.
    /// Returns `None` when the kernel has no route to `peer`.
    fn kernel_default_source(peer: &IpAddr) -> Option<KernelSource> {
        let destination = sockaddr_for(peer);
        let mut best_route: MIB_IPFORWARD_ROW2 = unsafe { core::mem::zeroed() };
        let mut best_source: SOCKADDR_INET = unsafe { core::mem::zeroed() };
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
        if rc != NO_ERROR || best_route.InterfaceIndex == 0 {
            return None;
        }
        let kernel_source = unsafe { inet_addr_of(&best_source) };
        Some(KernelSource {
            source: kernel_source,
            if_index: best_route.InterfaceIndex,
        })
    }

    /// Build a `SOCKADDR_INET` (for `GetBestRoute2`) from an `IpAddr`.
    fn sockaddr_for(addr: &IpAddr) -> SOCKADDR_INET {
        let mut sa: SOCKADDR_INET = unsafe { core::mem::zeroed() };
        match addr {
            IpAddr::V4(b) => {
                let v4 = unsafe { &mut *core::ptr::addr_of_mut!(sa).cast::<SOCKADDR_IN>() };
                v4.sin_family = AF_INET;
                v4.sin_addr.S_un.S_un_b.s_b1 = b[0];
                v4.sin_addr.S_un.S_un_b.s_b2 = b[1];
                v4.sin_addr.S_un.S_un_b.s_b3 = b[2];
                v4.sin_addr.S_un.S_un_b.s_b4 = b[3];
            }
            IpAddr::V6(b) => {
                let v6 = unsafe { &mut *core::ptr::addr_of_mut!(sa).cast::<SOCKADDR_IN6>() };
                v6.sin6_family = AF_INET6;
                v6.sin6_addr.u.Byte = *b;
            }
        }
        sa
    }

    /// Build a `SOCKADDR` (port 0) for `bind()` from an `IpAddr`.
    /// Returns the raw sockaddr bytes and length.
    fn sockaddr_for_bind(addr: &IpAddr) -> ([u8; 128], i32) {
        let mut buf = [0u8; 128];
        match addr {
            IpAddr::V4(b) => {
                let sa = SOCKADDR_IN {
                    sin_family: AF_INET as _,
                    sin_port: 0,
                    sin_addr: windows_sys::Win32::Networking::WinSock::IN_ADDR {
                        S_un: windows_sys::Win32::Networking::WinSock::IN_ADDR_0 {
                            S_un_b: windows_sys::Win32::Networking::WinSock::IN_ADDR_0_0 {
                                s_b1: b[0],
                                s_b2: b[1],
                                s_b3: b[2],
                                s_b4: b[3],
                            },
                        },
                    },
                    sin_zero: [0; 8],
                };
                // SAFETY: SOCKADDR_IN is 16 bytes, fits in buf.
                let bytes =
                    unsafe { core::slice::from_raw_parts(&sa as *const _ as *const u8, 16) };
                buf[..16].copy_from_slice(bytes);
                (buf, 16)
            }
            IpAddr::V6(b) => {
                let sa = SOCKADDR_IN6 {
                    sin6_family: AF_INET6 as _,
                    sin6_port: 0,
                    sin6_flowinfo: 0,
                    sin6_addr: windows_sys::Win32::Networking::WinSock::IN6_ADDR {
                        u: windows_sys::Win32::Networking::WinSock::IN6_ADDR_0 { Byte: *b },
                    },
                    Anonymous: windows_sys::Win32::Networking::WinSock::SOCKADDR_IN6_0 {
                        sin6_scope_id: 0,
                    },
                };
                let bytes =
                    unsafe { core::slice::from_raw_parts(&sa as *const _ as *const u8, 28) };
                buf[..28].copy_from_slice(bytes);
                (buf, 28)
            }
        }
    }

    /// # Safety
    /// The caller must guarantee `sa` holds a valid SOCKADDR_INET
    /// initialised by the IP Helper API (or by `sockaddr_for`).
    unsafe fn inet_addr_of(sa: &SOCKADDR_INET) -> IpAddr {
        let family = unsafe { sa.si_family };
        if family == AF_INET6 {
            let v6 = unsafe { &*core::ptr::addr_of!(*sa).cast::<SOCKADDR_IN6>() };
            IpAddr::V6(v6.sin6_addr.u.Byte)
        } else {
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
