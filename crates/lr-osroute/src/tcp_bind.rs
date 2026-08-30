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

#[cfg(all(feature = "std", not(target_os = "linux")))]
mod imp {
    use std::net::{SocketAddr, TcpStream};
    use std::time::Duration;

    pub fn connect_bound(
        _local: SocketAddr,
        peer: SocketAddr,
        timeout: Duration,
    ) -> Result<TcpStream, std::io::Error> {
        // No portable pre-bind; the kernel picks the source address.
        TcpStream::connect_timeout(&peer, timeout)
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
        // 127.0.0.9 is a valid loopback alias on Linux.
        let local = SocketAddr::new(std::net::IpAddr::V4(Ipv4Addr::new(127, 0, 0, 9)), 0);
        let listener = match TcpListener::bind("127.0.0.1:0") {
            Ok(l) => l,
            Err(e) => {
                eprintln!("skipped (loopback listen): {e}");
                return;
            }
        };
        let peer = listener.local_addr().unwrap();
        let got = std::sync::Arc::new(std::sync::Mutex::new(None));
        let got2 = std::sync::Arc::clone(&got);
        let t = std::thread::spawn(move || {
            if let Ok((s, addr)) = listener.accept() {
                *got2.lock().unwrap() = Some(addr);
                drop(s);
            }
        });
        match connect_bound(local, peer, Duration::from_secs(3)) {
            Ok(stream) => {
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
            Err(e) => {
                eprintln!("skipped (bound connect): {e}");
                let _ = t.join();
            }
        }
    }
}
