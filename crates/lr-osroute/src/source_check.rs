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
//! | Windows  | yes — `GetBestRoute2` + a real `bind()` test |
//! | Linux    | yes — `RTM_GETROUTE` with `RTA_PREFSRC` reports the kernel's preferred source |
//! | other    | partial (no-op) — returns `Ok` so the daemon still runs; the diagnostic does not fire |
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
    /// The implementation opens a `NETLINK_ROUTE` socket, issues a
    /// single `RTM_GETROUTE` request carrying `RTA_DST = peer` (the
    /// same shape `ip route get <addr>` produces), and parses the
    /// kernel's reply for `RTA_PREFSRC` and `RTA_OIF`. The diagnostic
    /// is a *hint*: any failure to consult the kernel (socket open,
    /// send, recv, parse) returns `SourceCheck::Ok` so the daemon
    /// still dials — the operator's fallback log line ("outbound TCP
    /// established from <addr>") is the source of truth once the
    /// connection lands.
    pub fn check_source_compatibility(local: IpAddr, peer: IpAddr) -> SourceCheck {
        match resolve_kernel_source(peer) {
            KernelResolve::Route(kernel) => {
                if kernel.source == local {
                    SourceCheck::Ok
                } else {
                    SourceCheck::Mismatch {
                        configured: local,
                        kernel_choice: kernel,
                    }
                }
            }
            KernelResolve::NoRoute => SourceCheck::NoRoute,
            // The diagnostic is a hint, not a gate: any failure to
            // consult the kernel (unprivileged container without
            // netlink access, transient ENOMEM, malformed reply)
            // falls back to `Ok` so the daemon still dials. The
            // operator's "outbound TCP established" log line is the
            // source of truth once the connection lands.
            KernelResolve::Unavailable => SourceCheck::Ok,
        }
    }

    /// The kernel's answer to the `RTM_GETROUTE` query.
    enum KernelResolve {
        /// The kernel returned a route with a preferred source.
        Route(KernelSource),
        /// The kernel reported no route to the peer (`NLMSG_ERROR`
        /// carrying a negative `ENETUNREACH` / `EHOSTUNREACH` /
        /// `ENOTSUP`).
        NoRoute,
        /// The kernel could not be consulted (socket open / send /
        /// recv / parse failure). The diagnostic falls back to `Ok`.
        Unavailable,
    }

    /// Issue one `RTM_GETROUTE` for `peer` and extract the kernel's
    /// preferred source + egress interface index.
    fn resolve_kernel_source(peer: IpAddr) -> KernelResolve {
        let fd = match open_netlink_socket() {
            Some(fd) => fd,
            None => return KernelResolve::Unavailable,
        };
        // `CloseGuard` closes the fd on drop so every early return
        // below stays leak-free even on parse failure.
        let _guard = CloseGuard(fd);
        let req = match build_getroute_request(peer) {
            Some(req) => req,
            None => return KernelResolve::Unavailable,
        };
        if send_request(fd, &req).is_err() {
            return KernelResolve::Unavailable;
        }
        let reply = match recv_reply(fd) {
            Some(reply) => reply,
            None => return KernelResolve::Unavailable,
        };
        parse_getroute_reply(&reply, peer)
    }

    /// Open an `AF_NETLINK / SOCK_RAW / NETLINK_ROUTE` socket bound
    /// to the kernel (pid 0, no groups). Returns the raw fd on
    /// success; `None` on any syscall failure (the diagnostic then
    /// falls back to `Ok`).
    fn open_netlink_socket() -> Option<i32> {
        let fd = unsafe { libc_socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE) };
        if fd < 0 {
            return None;
        }
        let addr = libc_sockaddr_nl {
            nl_family: AF_NETLINK as u16,
            nl_pad: 0,
            nl_pid: 0,
            nl_groups: 0,
        };
        let rc = unsafe {
            libc_bind(
                fd,
                (&raw const addr) as *const core::ffi::c_void,
                core::mem::size_of::<libc_sockaddr_nl>() as u32,
            )
        };
        if rc < 0 {
            unsafe { libc_close(fd) };
            return None;
        }
        Some(fd)
    }

    /// Build the `RTM_GETROUTE` request for `peer`:
    /// `nlmsghdr (16) + rtmsg (12) + RTA_DST (4 + addr_len)`, padded
    /// to 4-byte alignment. No `NLM_F_DUMP` — the kernel answers with
    /// the single route it would use, including `RTA_PREFSRC` and
    /// `RTA_OIF` (the shape `ip route get <addr>` produces).
    fn build_getroute_request(peer: IpAddr) -> Option<Vec<u8>> {
        let (family, dst, dst_len) = match peer {
            IpAddr::V4(b) => (AF_INET as u8, b.to_vec(), 32u8),
            IpAddr::V6(b) => (AF_INET6 as u8, b.to_vec(), 128u8),
        };
        let mut attrs = build_rta_attribute(RTA_DST, &dst);
        while !attrs.len().is_multiple_of(4) {
            attrs.push(0);
        }
        let total_len = 16 + 12 + attrs.len();
        let aligned = (total_len + 3) & !3;
        let mut buf = vec![0u8; aligned];
        buf[0..4].copy_from_slice(&(total_len as u32).to_ne_bytes());
        buf[4..6].copy_from_slice(&RTM_GETROUTE.to_ne_bytes());
        buf[6..8].copy_from_slice(&NLM_F_REQUEST.to_ne_bytes());
        // seq + pid: zero is fine for a one-shot RTM_GETROUTE; the
        // kernel does not echo them back when no `NLM_F_ACK` is set.
        buf[16] = family;
        buf[17] = dst_len;
        buf[28..28 + attrs.len()].copy_from_slice(&attrs);
        Some(buf)
    }

    /// Send the request on the netlink socket. `sendmsg` with a
    /// `sockaddr_nl` destination of pid 0 (the kernel).
    fn send_request(fd: i32, buf: &[u8]) -> Result<(), ()> {
        let dest = libc_sockaddr_nl {
            nl_family: AF_NETLINK as u16,
            nl_pad: 0,
            nl_pid: 0,
            nl_groups: 0,
        };
        let iov = libc_iovec {
            iov_base: buf.as_ptr() as *mut core::ffi::c_void,
            iov_len: buf.len(),
        };
        let msg = libc_msghdr {
            msg_name: (&raw const dest) as *const core::ffi::c_void as *mut core::ffi::c_void,
            msg_namelen: core::mem::size_of::<libc_sockaddr_nl>() as u32,
            msg_iov: (&raw const iov) as *const core::ffi::c_void as *mut core::ffi::c_void,
            msg_iovlen: 1,
            msg_control: core::ptr::null_mut(),
            msg_controllen: 0,
            msg_flags: 0,
        };
        let sent = unsafe { libc_sendmsg(fd, &msg, 0) };
        if sent < 0 {
            return Err(());
        }
        Ok(())
    }

    /// Receive the kernel's reply. A single `recv` is enough for a
    /// one-shot `RTM_GETROUTE`: the kernel's answer fits in 8 KiB
    /// (the largest route the kernel would return carries a handful
    /// of attributes — `RTA_PREFSRC`, `RTA_OIF`, optionally
    /// `RTA_GATEWAY` / `RTA_MULTIPATH`).
    fn recv_reply(fd: i32) -> Option<Vec<u8>> {
        let mut out = vec![0u8; 8192];
        let n = unsafe { libc_recv(fd, out.as_mut_ptr() as *mut core::ffi::c_void, out.len(), 0) };
        if n <= 0 {
            return None;
        }
        out.truncate(n as usize);
        Some(out)
    }

    /// Parse the netlink reply to a `RTM_GETROUTE`. The kernel
    /// answers with either:
    /// - a single `RTM_NEWROUTE` message carrying `RTA_PREFSRC` and
    ///   `RTA_OIF`, or
    /// - an `NLMSG_ERROR` carrying a negative errno (e.g.
    ///   `ENETUNREACH` for no route, `ENOTSUP` for an unsupported
    ///   family).
    ///
    /// Returns [`KernelResolve::Route`] with the parsed
    /// `(source, if_index)` on success, [`KernelResolve::NoRoute`]
    /// when the kernel reported an error that means "no route", and
    /// [`KernelResolve::Unavailable`] for any parse failure (so the
    /// diagnostic falls back to `Ok`).
    fn parse_getroute_reply(resp: &[u8], queried: IpAddr) -> KernelResolve {
        if resp.len() < 16 {
            return KernelResolve::Unavailable;
        }
        let nlmsg_type = u16::from_ne_bytes([resp[4], resp[5]]);
        if nlmsg_type == NLMSG_ERROR {
            // nlmsgerr: <error:i32> at offset 16. Negative errno on
            // failure, zero on ack. We did not set NLM_F_ACK so zero
            // should not appear here; treat any non-zero as "no
            // route" (the common `ENETUNREACH` / `EHOSTUNREACH`
            // cases), any zero as a malformed reply.
            let errno = i32::from_ne_bytes([resp[16], resp[17], resp[18], resp[19]]);
            if errno == 0 {
                return KernelResolve::Unavailable;
            }
            return KernelResolve::NoRoute;
        }
        if nlmsg_type != RTM_NEWROUTE {
            return KernelResolve::Unavailable;
        }
        // Walk the attributes after the 16-byte nlmsghdr + 12-byte
        // rtmsg. The reply may carry `RTA_MULTIPATH` (a nested
        // `RTA_GATEWAY` / `RTA_OIF` per next-hop) — for the diagnostic
        // we only need `RTA_PREFSRC` and `RTA_OIF` on the top-level
        // message, which the kernel stamps for the chosen egress.
        let mut source: Option<IpAddr> = None;
        let mut if_index: u32 = 0;
        let mut cursor = 28;
        while cursor + 4 <= resp.len() {
            let rta_len = u16::from_ne_bytes([resp[cursor], resp[cursor + 1]]) as usize;
            let rta_type = u16::from_ne_bytes([resp[cursor + 2], resp[cursor + 3]]);
            if rta_len < 4 || cursor + rta_len > resp.len() {
                break;
            }
            let data = &resp[cursor + 4..cursor + rta_len];
            match rta_type {
                RTA_PREFSRC => match queried {
                    IpAddr::V4(_) if data.len() >= 4 => {
                        source = Some(IpAddr::V4([data[0], data[1], data[2], data[3]]));
                    }
                    IpAddr::V6(_) if data.len() >= 16 => {
                        let mut o = [0u8; 16];
                        o.copy_from_slice(&data[..16]);
                        source = Some(IpAddr::V6(o));
                    }
                    _ => {}
                },
                RTA_OIF if data.len() >= 4 => {
                    if_index = u32::from_ne_bytes([data[0], data[1], data[2], data[3]]);
                }
                _ => {}
            }
            cursor += (rta_len + 3) & !3;
        }
        match source {
            Some(source) => KernelResolve::Route(KernelSource { source, if_index }),
            None => {
                // The kernel returned a route without a preferred
                // source (e.g. `RTN_BLACKHOLE` / `RTN_UNREACHABLE`).
                // That is not a "no route" answer, but it is also not
                // a usable egress — fall back to `Ok` so the daemon
                // still dials and the operator's log line is the
                // source of truth.
                KernelResolve::Unavailable
            }
        }
    }

    /// Build one netlink route attribute: `nla_len (2) | nla_type (2)
    /// | data`, padded to 4-byte alignment with zero bytes.
    fn build_rta_attribute(rta_type: u16, data: &[u8]) -> Vec<u8> {
        let rta_len = (4 + data.len()) as u16;
        let aligned = (rta_len as usize + 3) & !3;
        let mut buf = vec![0u8; aligned];
        buf[0..2].copy_from_slice(&rta_len.to_ne_bytes());
        buf[2..4].copy_from_slice(&rta_type.to_ne_bytes());
        buf[4..4 + data.len()].copy_from_slice(data);
        buf
    }

    /// RAII close guard so early returns from `resolve_kernel_source`
    /// do not leak the netlink fd on parse / syscall failure.
    struct CloseGuard(i32);
    impl Drop for CloseGuard {
        fn drop(&mut self) {
            unsafe { libc_close(self.0) };
        }
    }

    // Netlink message types (uapi/linux/netlink.h).
    const NLMSG_ERROR: u16 = 0x2;

    // rtnetlink message types (uapi/linux/rtnetlink.h).
    const RTM_GETROUTE: u16 = 26;
    const RTM_NEWROUTE: u16 = 24;

    // rtnetlink RTA types (uapi/linux/rtnetlink.h).
    const RTA_DST: u16 = 1;
    const RTA_OIF: u16 = 4;
    const RTA_PREFSRC: u16 = 7;

    // Address families.
    const AF_INET: u16 = 2;
    const AF_INET6: u16 = 10;

    // Netlink socket constants.
    const NETLINK_ROUTE: i32 = 0;
    const AF_NETLINK: i32 = 16;
    const SOCK_RAW: i32 = 3;

    // Netlink flags (uapi/linux/netlink.h).
    const NLM_F_REQUEST: u16 = 0x01;

    // FFI shims — same approach as `mpls_route.rs` (no `libc` crate
    // dependency; raw `extern "C"` to the C library).
    #[repr(C)]
    #[allow(non_camel_case_types)]
    struct libc_sockaddr_nl {
        nl_family: u16,
        nl_pad: u16,
        nl_pid: u32,
        nl_groups: u32,
    }

    #[repr(C)]
    #[allow(non_camel_case_types)]
    struct libc_iovec {
        iov_base: *mut core::ffi::c_void,
        iov_len: usize,
    }

    #[repr(C)]
    #[allow(non_camel_case_types)]
    struct libc_msghdr {
        msg_name: *mut core::ffi::c_void,
        msg_namelen: u32,
        msg_iov: *mut core::ffi::c_void,
        msg_iovlen: usize,
        msg_control: *mut core::ffi::c_void,
        msg_controllen: usize,
        msg_flags: i32,
    }

    extern "C" {
        fn socket(domain: i32, ty: i32, protocol: i32) -> i32;
        fn bind(fd: i32, addr: *const core::ffi::c_void, len: u32) -> i32;
        fn sendmsg(fd: i32, msg: *const libc_msghdr, flags: i32) -> isize;
        fn recv(fd: i32, buf: *mut core::ffi::c_void, len: usize, flags: i32) -> isize;
        fn close(fd: i32) -> i32;
    }

    unsafe fn libc_socket(d: i32, t: i32, p: i32) -> i32 {
        socket(d, t, p)
    }
    unsafe fn libc_bind(fd: i32, addr: *const core::ffi::c_void, len: u32) -> i32 {
        bind(fd, addr, len)
    }
    unsafe fn libc_sendmsg(fd: i32, msg: *const libc_msghdr, flags: i32) -> isize {
        sendmsg(fd, msg, flags)
    }
    unsafe fn libc_recv(fd: i32, buf: *mut core::ffi::c_void, len: usize, flags: i32) -> isize {
        recv(fd, buf, len, flags)
    }
    unsafe fn libc_close(fd: i32) -> i32 {
        close(fd)
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

    /// Loopback is universally routed by the kernel: `ip route get
    /// 127.0.0.1` returns `RTA_PREFSRC = 127.0.0.1`. The diagnostic
    /// therefore agrees with a `local = 127.0.0.1` configuration on
    /// every Linux host (the test environment included).
    #[cfg(target_os = "linux")]
    #[test]
    fn loopback_v4_matches() {
        let local = IpAddr::V4([127, 0, 0, 1]);
        let peer = IpAddr::V4([127, 0, 0, 1]);
        let r = check_source_compatibility(local, peer);
        assert!(
            matches!(r, SourceCheck::Ok),
            "loopback v4 must agree, got {r:?}"
        );
    }

    /// IPv6 loopback mirrors the v4 case: `ip -6 route get ::1`
    /// returns `RTA_PREFSRC = ::1`.
    #[cfg(target_os = "linux")]
    #[test]
    fn loopback_v6_matches() {
        let mut lo = [0u8; 16];
        lo[15] = 1;
        let local = IpAddr::V6(lo);
        let peer = IpAddr::V6(lo);
        let r = check_source_compatibility(local, peer);
        assert!(
            matches!(r, SourceCheck::Ok),
            "loopback v6 must agree, got {r:?}"
        );
    }

    /// A hermetic smoke test for the `NoRoute` branch on Linux. The
    /// kernel's `NLMSG_ERROR` reply is hard to provoke in a sandbox
    /// that carries a default route (any destination matches
    /// `0.0.0.0/0`), so we instead assert the diagnostic returns
    /// one of the documented `SourceCheck` variants without panicking
    /// — the helper's contract is "never block the daemon on a kernel
    /// query that might fail", and any of the four arms is a valid
    /// outcome when the route table is unknown to the test.
    #[cfg(target_os = "linux")]
    #[test]
    fn diagnostic_is_total_on_any_peer() {
        let local = IpAddr::V4([127, 0, 0, 1]);
        // 198.51.100.0/24 is RFC 5737 documentation range — never
        // routed in any production network, so the kernel's answer is
        // environment-dependent (sandbox default route vs. hermetic
        // CI). The diagnostic must not panic either way.
        let peer = IpAddr::V4([198, 51, 100, 1]);
        let r = check_source_compatibility(local, peer);
        assert!(
            matches!(
                r,
                SourceCheck::Ok | SourceCheck::Mismatch { .. } | SourceCheck::NoRoute
            ),
            "diagnostic must return a documented variant, got {r:?}"
        );
    }

    /// A loopback `local` against a routable `peer` whose egress is
    /// NOT loopback must mismatch: the kernel sources the dial from
    /// the egress interface's address, not 127.0.0.1. This pins the
    /// `Mismatch` branch on every host with a default route. When
    /// the sandbox has no default route (a hermetic CI) the kernel
    /// returns `NoRoute`, so accept both.
    #[cfg(target_os = "linux")]
    #[test]
    fn loopback_against_routable_peer_is_not_ok() {
        let local = IpAddr::V4([127, 0, 0, 1]);
        // 1.1.1.1 is a stable, globally routed anycast address.
        let peer = IpAddr::V4([1, 1, 1, 1]);
        let r = check_source_compatibility(local, peer);
        assert!(
            matches!(r, SourceCheck::Mismatch { .. } | SourceCheck::NoRoute),
            "loopback-local vs routable peer must not be Ok, got {r:?}"
        );
    }

    /// The no-op platform (the cfg branch that compiles when no
    /// native helper is available) returns `Ok` — the diagnostic is
    /// a hint, not a gate, so callers can run unconditionally.
    #[cfg(not(any(target_os = "windows", target_os = "linux")))]
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
