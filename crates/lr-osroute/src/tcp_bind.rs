//! Source-bound TCP connect — sourcing an outbound connection from a
//! configured local address.
//!
//! BGP daemons on multihomed (or loopback-lab) systems need the TCP
//! connection to originate from the configured `local` address, both so
//! the peer can match it against its expectations (strict inbound
//! source matching, `neighbor <ip>` style configs) and so BFD peers
//! agree on the address pair. `std::net::TcpStream` cannot bind before
//! connecting, so this module does it the classic way on Linux:
//! `socket()` → `bind(local)` → non-blocking `connect()` → poll →
//! `SO_ERROR`.
//!
//! ## Platform support
//!
//! | Platform | Status |
//! |----------|--------|
//! | Linux    | yes — full bind + connect + poll |
//! | other    | fallback: plain `connect_timeout` without the bind (the connection is sourced by the kernel's default choice) |

use std::net::{SocketAddr, TcpStream};
use std::time::Duration;

/// Connect to `peer` with the connection sourced from `local` (the
/// port in `local` is ignored; the kernel picks an ephemeral one).
pub fn connect_bound(
    local: SocketAddr,
    peer: SocketAddr,
    timeout: Duration,
) -> Result<TcpStream, std::io::Error> {
    imp::connect_bound(local, peer, timeout)
}

#[cfg(all(feature = "std", target_os = "linux"))]
mod imp {
    use std::net::{SocketAddr, TcpStream};
    use std::os::fd::FromRawFd;
    use std::time::{Duration, Instant};

    const AF_INET: i32 = 2;
    const AF_INET6: i32 = 10;
    const SOCK_STREAM: i32 = 1;
    const SOL_SOCKET: i32 = 1;
    const SO_ERROR: i32 = 4;
    const F_GETFL: i32 = 3;
    const F_SETFL: i32 = 4;
    const O_NONBLOCK: i32 = 0o4000;
    const POLL_OUT: i16 = 0x004;
    const EINPROGRESS: i32 = 115;

    #[repr(C)]
    struct SockaddrIn {
        sin_family: u16,
        sin_port: u16,
        sin_addr: [u8; 4],
        sin_zero: [u8; 8],
    }

    #[repr(C)]
    struct SockaddrIn6 {
        sin6_family: u16,
        sin6_port: u16,
        sin6_flowinfo: u32,
        sin6_addr: [u8; 16],
        sin6_scope_id: u32,
    }

    #[repr(C)]
    #[derive(Clone, Copy)]
    struct SockaddrStorage {
        ss_family: u16,
        __pad: [u8; 126],
    }

    #[repr(C)]
    struct PollFd {
        fd: i32,
        events: i16,
        revents: i16,
    }

    extern "C" {
        fn socket(domain: i32, ty: i32, protocol: i32) -> i32;
        // Signature matches the sibling modules (gtsm/tcp_auth): the
        // linker merges extern declarations, so they must agree.
        fn connect(fd: i32, addr: *const SockaddrStorage, addrlen: u32) -> i32;
        fn close(fd: i32) -> i32;
        fn fcntl(fd: i32, cmd: i32, ...) -> i32;
        fn poll(fds: *mut PollFd, nfds: u64, timeout: i32) -> i32;
        fn getsockopt(
            fd: i32,
            level: i32,
            optname: i32,
            optval: *mut core::ffi::c_void,
            optlen: *mut u32,
        ) -> i32;
    }

    // bind lives in linux.rs with this exact signature; redeclaring
    // it differently would be UB at link time, so route through it.
    // socklen_t is u32 on Linux — keep the declaration in sync with
    // linux.rs.
    extern "C" {
        fn bind(fd: i32, addr: *const core::ffi::c_void, len: u32) -> i32;
    }

    fn errno() -> i32 {
        std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
    }

    fn sockaddr_bytes(addr: SocketAddr) -> (SockaddrStorage, u32) {
        let mut sa = SockaddrStorage {
            ss_family: if addr.is_ipv6() {
                AF_INET6 as u16
            } else {
                AF_INET as u16
            },
            __pad: [0; 126],
        };
        let len = match addr {
            SocketAddr::V4(a) => {
                let v4 = SockaddrIn {
                    sin_family: AF_INET as u16,
                    sin_port: a.port().to_be(),
                    sin_addr: a.ip().octets(),
                    sin_zero: [0; 8],
                };
                // SAFETY: v4 is a plain repr(C) struct of 16 bytes.
                let bytes =
                    unsafe { core::slice::from_raw_parts(&v4 as *const _ as *const u8, 16) };
                sa.__pad[..14].copy_from_slice(&bytes[2..]);
                16
            }
            SocketAddr::V6(a) => {
                let v6 = SockaddrIn6 {
                    sin6_family: AF_INET6 as u16,
                    sin6_port: a.port().to_be(),
                    sin6_flowinfo: a.flowinfo(),
                    sin6_addr: a.ip().octets(),
                    sin6_scope_id: a.scope_id(),
                };
                // SAFETY: v6 is a plain repr(C) struct of exactly 28
                // bytes.
                let bytes =
                    unsafe { core::slice::from_raw_parts(&v6 as *const _ as *const u8, 28) };
                sa.__pad[..26].copy_from_slice(&bytes[2..]);
                28
            }
        };
        (sa, len)
    }

    pub fn connect_bound(
        local: SocketAddr,
        peer: SocketAddr,
        timeout: Duration,
    ) -> Result<TcpStream, std::io::Error> {
        if local.is_ipv4() != peer.is_ipv4() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "local and peer address families differ",
            ));
        }
        let domain = if peer.is_ipv6() { AF_INET6 } else { AF_INET };
        // SAFETY: plain socket(2); no protocol-specific options.
        let fd = unsafe { socket(domain, SOCK_STREAM, 0) };
        if fd < 0 {
            return Err(std::io::Error::from_raw_os_error(errno()));
        }
        let finish = |fd: i32| -> Result<TcpStream, std::io::Error> {
            // Back to blocking mode for the TcpStream consumer.
            unsafe {
                let flags = fcntl(fd, F_GETFL);
                if flags >= 0 {
                    fcntl(fd, F_SETFL, flags & !O_NONBLOCK);
                }
            }
            Ok(unsafe { TcpStream::from_raw_fd(fd) })
        };
        // Bind the source address (port 0 = ephemeral).
        let (local_sa, local_len) = sockaddr_bytes(match local {
            SocketAddr::V4(mut a) => {
                a.set_port(0);
                SocketAddr::V4(a)
            }
            SocketAddr::V6(mut a) => {
                a.set_port(0);
                SocketAddr::V6(a)
            }
        });
        // SAFETY: local_sa holds a valid sockaddr of local_len.
        let rc = unsafe { bind(fd, &local_sa as *const _ as *const _, local_len) };
        if rc < 0 {
            let e = std::io::Error::from_raw_os_error(errno());
            unsafe { close(fd) };
            return Err(e);
        }
        // Non-blocking connect.
        // SAFETY: fcntl(F_SETFL) with an integer flag.
        unsafe { fcntl(fd, F_SETFL, O_NONBLOCK) };
        let (peer_sa, peer_len) = sockaddr_bytes(peer);
        // SAFETY: peer_sa holds a valid sockaddr of peer_len.
        let rc = unsafe { connect(fd, &peer_sa, peer_len) };
        if rc < 0 && errno() != EINPROGRESS {
            let e = std::io::Error::from_raw_os_error(errno());
            unsafe { close(fd) };
            return Err(e);
        }
        // Wait for writability.
        let deadline = Instant::now() + timeout;
        loop {
            let now = Instant::now();
            if now >= deadline {
                unsafe { close(fd) };
                return Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "connect timed out",
                ));
            }
            let mut pfd = PollFd {
                fd,
                events: POLL_OUT,
                revents: 0,
            };
            let ms = (deadline - now).as_millis().min(i32::MAX as u128) as i32;
            // SAFETY: pfd is a valid single-element pollfd array.
            let rc = unsafe { poll(&mut pfd, 1, ms.max(0)) };
            if rc < 0 {
                if errno() == 4 {
                    continue; // EINTR
                }
                let e = std::io::Error::from_raw_os_error(errno());
                unsafe { close(fd) };
                return Err(e);
            }
            if rc == 0 {
                continue; // timeout handled by the deadline check
            }
            break;
        }
        // Check the connection result.
        let mut so_err: i32 = 0;
        let mut so_len = core::mem::size_of::<i32>() as u32;
        // SAFETY: so_err is a valid int out-param.
        let rc = unsafe {
            getsockopt(
                fd,
                SOL_SOCKET,
                SO_ERROR,
                (&raw mut so_err) as *mut core::ffi::c_void,
                &mut so_len,
            )
        };
        if rc < 0 || so_err != 0 {
            let e = if rc < 0 {
                std::io::Error::from_raw_os_error(errno())
            } else {
                std::io::Error::from_raw_os_error(so_err)
            };
            unsafe { close(fd) };
            return Err(e);
        }
        finish(fd)
    }
}

#[cfg(all(feature = "std", target_os = "windows"))]
mod imp {
    use std::net::{SocketAddr, TcpStream};
    use std::time::Duration;

    use socket2::{Domain, Protocol, Socket, Type};

    /// Source-bound TCP connect on Windows.
    ///
    /// Windows' Strong Host Model can silently override a `bind()` to
    /// a source address that is not on the kernel's chosen egress
    /// interface. The `IP_UNICAST_IF` socket option pins the egress
    /// interface so `bind()` + `connect()` use a consistent interface
    /// and source IP.
    ///
    /// **Race condition**: at daemon startup, before Babel converges,
    /// the kernel's route table does not yet have the Babel-learned
    /// `/32` routes. `GetBestRoute2` returns the DEFAULT route's
    /// interface (e.g. interface 7, the LAN), not the Babel tunnel
    /// (interface 58). `IP_UNICAST_IF` is pinned to interface 7, but
    /// the configured `local_address` (172.23.10.102) is on interface
    /// 58 — `bind()` fails with `WSAEADDRNOTAVAIL`. The daemon's
    /// fallback to kernel-chosen source then produces a bogus source
    /// IP (the production report showed `127.0.0.1` — Windows source
    /// selection under a blackhole route).
    ///
    /// The fix: when `bind()` fails with `AddrNotAvailable` AFTER
    /// `IP_UNICAST_IF` was set, DISABLE `IP_UNICAST_IF` (set to 0) and
    /// RETRY `bind()`. The address IS local (on a different interface);
    /// with Weak Host Send enabled (the operator's configuration), the
    /// kernel accepts the bind and routes the packet correctly via the
    /// route table. This handles the Babel-convergence race without
    /// requiring the operator to wait for Babel before starting BGP.
    ///
    /// On Windows the `IP_UNICAST_IF` value is the interface index in
    /// **network byte order** for IPv4 and in **host byte order** for
    /// IPv6 (per Microsoft's `IP_UNICAST_IF` documentation).
    pub fn connect_bound(
        local: SocketAddr,
        peer: SocketAddr,
        timeout: Duration,
    ) -> Result<TcpStream, std::io::Error> {
        if local.is_ipv4() != peer.is_ipv4() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "local and peer address families differ",
            ));
        }
        let domain = if peer.is_ipv6() {
            Domain::IPV6
        } else {
            Domain::IPV4
        };
        let sock = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?;

        // Resolve the egress interface for the peer via GetBestRoute2,
        // then pin it with IP_UNICAST_IF so the kernel does not pick a
        // different interface (and a different source IP) at connect
        // time.
        let if_index = resolve_egress_if(&peer);
        if let Some(if_index) = if_index {
            pin_unicast_if(&sock, if_index, peer.is_ipv6());
        }

        // Bind the source address (port 0 = ephemeral).
        let local_bind = match local {
            SocketAddr::V4(mut a) => {
                a.set_port(0);
                SocketAddr::V4(a)
            }
            SocketAddr::V6(mut a) => {
                a.set_port(0);
                SocketAddr::V6(a)
            }
        };
        // Retry logic: if bind() fails with AddrNotAvailable while
        // IP_UNICAST_IF is pinned, the pinned egress interface does
        // not have the bound source assigned (the Babel-convergence
        // race). Disable IP_UNICAST_IF and retry — the bind alone
        // succeeds because the address IS local, and Weak Host Send
        // lets the kernel route via the correct interface.
        match sock.bind(&local_bind.into()) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::AddrNotAvailable && if_index.is_some() => {
                unpin_unicast_if(&sock, peer.is_ipv6());
                sock.bind(&local_bind.into())?;
            }
            Err(e) => return Err(e),
        }

        // Connect with a timeout. `socket2`'s `connect_timeout`
        // handles the non-blocking + poll internally.
        sock.set_nonblocking(false)?;
        sock.connect_timeout(&peer.into(), timeout)?;

        Ok(sock.into())
    }

    /// Ask the kernel which interface it would use to reach `peer`,
    /// via `GetBestRoute2`. Returns `None` when the kernel has no
    /// route (the caller's `connect()` will then fail with
    /// `WSAENETUNREACH` — the operator's problem, not ours).
    fn resolve_egress_if(peer: &SocketAddr) -> Option<u32> {
        use windows_sys::Win32::Foundation::NO_ERROR;
        use windows_sys::Win32::NetworkManagement::IpHelper::{GetBestRoute2, MIB_IPFORWARD_ROW2};
        use windows_sys::Win32::Networking::WinSock::SOCKADDR_INET;

        let destination = sockaddr_for(peer);
        let mut best_route: MIB_IPFORWARD_ROW2 = unsafe { core::mem::zeroed() };
        let mut best_source: SOCKADDR_INET = unsafe { core::mem::zeroed() };
        // SAFETY: null InterfaceLuid/source select the current
        // compartment and any source; both output pointers refer to
        // live stack values.
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
        Some(best_route.InterfaceIndex)
    }

    /// Build a `SOCKADDR_INET` from a `SocketAddr` for use with
    /// `GetBestRoute2`. Mirrors the pattern in `windows.rs` /
    /// `source_check.rs`.
    fn sockaddr_for(addr: &SocketAddr) -> windows_sys::Win32::Networking::WinSock::SOCKADDR_INET {
        use windows_sys::Win32::Networking::WinSock::{
            AF_INET, AF_INET6, SOCKADDR_IN, SOCKADDR_IN6, SOCKADDR_INET,
        };
        let mut sa: SOCKADDR_INET = unsafe { core::mem::zeroed() };
        match addr {
            SocketAddr::V4(a) => {
                let v4 = unsafe { &mut *core::ptr::addr_of_mut!(sa).cast::<SOCKADDR_IN>() };
                v4.sin_family = AF_INET;
                v4.sin_port = a.port().to_be();
                v4.sin_addr.S_un.S_un_b.s_b1 = a.ip().octets()[0];
                v4.sin_addr.S_un.S_un_b.s_b2 = a.ip().octets()[1];
                v4.sin_addr.S_un.S_un_b.s_b3 = a.ip().octets()[2];
                v4.sin_addr.S_un.S_un_b.s_b4 = a.ip().octets()[3];
            }
            SocketAddr::V6(a) => {
                let v6 = unsafe { &mut *core::ptr::addr_of_mut!(sa).cast::<SOCKADDR_IN6>() };
                v6.sin6_family = AF_INET6;
                v6.sin6_port = a.port().to_be();
                v6.sin6_addr.u.Byte = a.ip().octets();
                v6.Anonymous.sin6_scope_id = a.scope_id();
            }
        }
        sa
    }

    /// Set `IP_UNICAST_IF` (IPv4) or `IPV6_UNICAST_IF` (IPv6) on the
    /// socket, pinning the egress interface for outgoing packets.
    ///
    /// The IPv4 option value is the interface index in **network byte
    /// order** (`htonl(if_index)`); the IPv6 option value is in **host
    /// byte order** (per Microsoft's `IP_UNICAST_IF` documentation).
    /// Getting this wrong is silent — the kernel accepts the option
    /// but routes via the wrong interface — so the byte-order
    /// convention is load-bearing.
    fn pin_unicast_if(sock: &Socket, if_index: u32, ipv6: bool) {
        use std::os::windows::io::AsRawSocket;
        use windows_sys::Win32::Networking::WinSock::{
            setsockopt, IPPROTO_IP, IPPROTO_IPV6, IPV6_UNICAST_IF, IP_UNICAST_IF,
        };
        let raw = sock.as_raw_socket() as usize;
        let value: u32 = if ipv6 {
            // IPv6: host byte order.
            if_index
        } else {
            // IPv4: network byte order.
            if_index.to_be()
        };
        // SAFETY: `value` is a u32 on the stack; the pointer is valid
        // for the duration of the call. The socket is a live TCP
        // socket created by socket2.
        let rc = unsafe {
            setsockopt(
                raw,
                if ipv6 { IPPROTO_IPV6 } else { IPPROTO_IP },
                if ipv6 { IPV6_UNICAST_IF } else { IP_UNICAST_IF },
                &value as *const u32 as *const u8,
                core::mem::size_of::<u32>() as i32,
            )
        };
        if rc != 0 {
            // Non-fatal: the kernel may not support IP_UNICAST_IF
            // (older Windows), or the option may require elevation.
            eprintln!(
                "daemon: warning: IP_UNICAST_IF({}) failed (rc={}); \
                 relying on bind() alone for source selection",
                if_index, rc
            );
        }
    }

    /// Disable `IP_UNICAST_IF` (or `IPV6_UNICAST_IF`) by setting the
    /// interface index to 0. Per Microsoft's documentation: "If the
    /// interface index is 0, the option is disabled and the system
    /// will select the appropriate interface." Used when the pinned
    /// egress interface does not have the bound source address (the
    /// Babel-convergence race) — disabling lets the kernel route via
    /// the bound source's interface under Weak Host Send.
    fn unpin_unicast_if(sock: &Socket, ipv6: bool) {
        use std::os::windows::io::AsRawSocket;
        use windows_sys::Win32::Networking::WinSock::{
            setsockopt, IPPROTO_IP, IPPROTO_IPV6, IPV6_UNICAST_IF, IP_UNICAST_IF,
        };
        let raw = sock.as_raw_socket() as usize;
        let value: u32 = 0;
        // SAFETY: same as pin_unicast_if — value is a u32 on the
        // stack, the socket is live.
        let rc = unsafe {
            setsockopt(
                raw,
                if ipv6 { IPPROTO_IPV6 } else { IPPROTO_IP },
                if ipv6 { IPV6_UNICAST_IF } else { IP_UNICAST_IF },
                &value as *const u32 as *const u8,
                core::mem::size_of::<u32>() as i32,
            )
        };
        if rc != 0 {
            // Non-fatal: if we cannot unpin, the bind retry will also
            // fail and the daemon's fallback takes over. Log for
            // diagnostics.
            eprintln!(
                "daemon: warning: unpin IP_UNICAST_IF failed (rc={}); \
                 bind retry may also fail",
                rc
            );
        }
    }
}

#[cfg(all(feature = "std", not(target_os = "linux"), not(target_os = "windows")))]
mod imp {
    use std::net::{SocketAddr, TcpStream};
    use std::time::Duration;

    use socket2::{Domain, Protocol, Socket, Type};

    /// Source-bound TCP connect using the `socket2` crate.
    ///
    /// On non-Linux, non-Windows platforms (macOS, BSD), the
    /// hand-rolled `socket()` + `bind()` + `connect()` path is not
    /// available because it depends on POSIX libc FFI. The `socket2`
    /// crate provides a portable abstraction that works on every
    /// platform the project compiles for.
    ///
    /// Without source binding, BGP peers that match inbound
    /// connections by source IP (the standard `neighbor <ip>` pattern)
    /// would reject the daemon's outbound connections on multihomed
    /// hosts where the kernel's default source-address choice differs
    /// from the configured `local_address`.
    pub fn connect_bound(
        local: SocketAddr,
        peer: SocketAddr,
        timeout: Duration,
    ) -> Result<TcpStream, std::io::Error> {
        if local.is_ipv4() != peer.is_ipv4() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "local and peer address families differ",
            ));
        }
        let domain = if peer.is_ipv6() {
            Domain::IPV6
        } else {
            Domain::IPV4
        };
        let sock = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?;

        // Bind the source address (port 0 = ephemeral).
        let local_bind = match local {
            SocketAddr::V4(mut a) => {
                a.set_port(0);
                SocketAddr::V4(a)
            }
            SocketAddr::V6(mut a) => {
                a.set_port(0);
                SocketAddr::V6(a)
            }
        };
        sock.bind(&local_bind.into())?;

        // Connect with a timeout. `socket2`'s `connect_timeout`
        // handles the non-blocking + poll internally.
        sock.set_nonblocking(false)?;
        sock.connect_timeout(&peer.into(), timeout)?;

        Ok(sock.into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, TcpListener};

    /// A source-bound connection really carries the bound source
    /// address (Linux; other platforms exercise the fallback).
    #[test]
    fn bound_connection_sources_from_local() {
        // 127.0.0.9 is a valid loopback alias on Linux. On macOS it
        // is NOT configured on lo0 by default (only 127.0.0.1 is),
        // so binding to it returns EADDRNOTAVAIL — the test must
        // skip cleanly without leaving a background thread blocked
        // on `listener.accept()` (which never returns because no
        // connection ever arrives).
        let local = SocketAddr::new(std::net::IpAddr::V4(Ipv4Addr::new(127, 0, 0, 9)), 0);
        let listener = match TcpListener::bind("127.0.0.1:0") {
            Ok(l) => l,
            Err(e) => {
                eprintln!("skipped (loopback listen): {e}");
                return;
            }
        };
        let peer = listener.local_addr().unwrap();

        // Call connect_bound BEFORE spawning the accept thread.
        // The kernel queues any inbound connection in the listener's
        // accept backlog, so the accept thread dequeues it later
        // without a race. If connect_bound fails (the macOS
        // EADDRNOTAVAIL path), the test skips here — no thread is
        // spawned, no `t.join()` blocks forever, no 5-minute
        // slow-timeout from nextest's `.config/nextest.toml`.
        let stream = match connect_bound(local, peer, Duration::from_secs(3)) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("skipped (bound connect): {e}");
                return;
            }
        };

        let got = std::sync::Arc::new(std::sync::Mutex::new(None));
        let got2 = std::sync::Arc::clone(&got);
        let t = std::thread::spawn(move || {
            if let Ok((s, addr)) = listener.accept() {
                *got2.lock().unwrap() = Some(addr);
                drop(s);
            }
        });
        let addr = stream.peer_addr().unwrap();
        assert_eq!(addr, peer);
        drop(stream);
        t.join().unwrap();
        let seen = got.lock().unwrap().take();
        match seen {
            Some(src) => {
                if cfg!(target_os = "linux") {
                    assert_eq!(
                        src.ip(),
                        std::net::IpAddr::V4(Ipv4Addr::new(127, 0, 0, 9)),
                        "connection sourced from {src}, expected 127.0.0.9"
                    );
                }
            }
            None if !cfg!(target_os = "linux") => {}
            None => panic!("accept never saw the connection"),
        }
    }

    /// `connect_bound` must not panic when the local address is not
    /// assigned to any interface — the daemon's caller handles the
    /// `AddrNotAvailable` error with a fallback. This pins the
    /// "hint, not a gate" contract on every platform.
    #[test]
    fn connect_bound_unassigned_address_returns_error_not_panic() {
        // 192.0.2.1 is TEST-NET-1 (RFC 5737) — never assigned to any
        // interface. The bind must fail cleanly with AddrNotAvail
        // (or similar), not panic.
        let local = SocketAddr::new(std::net::IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)), 0);
        let listener = match TcpListener::bind("127.0.0.1:0") {
            Ok(l) => l,
            Err(e) => {
                eprintln!("skipped (loopback listen): {e}");
                return;
            }
        };
        let peer = listener.local_addr().unwrap();
        drop(listener);
        match connect_bound(local, peer, Duration::from_secs(1)) {
            Ok(_) => {
                // On some platforms the bind may succeed (IP_FREEBIND
                // equivalent) — that's fine, the contract is "no panic".
            }
            Err(e) => {
                // Expected: bind fails with AddrNotAvail or similar.
                eprintln!("expected bind error (ok): {e}");
            }
        }
    }
}
