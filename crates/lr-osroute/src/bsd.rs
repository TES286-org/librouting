//! BSD `route(4)` socket route table implementation.
//!
//! The PF_ROUTE routing socket is the canonical userspace interface to the
//! BSD kernel routing table. It exchanges versioned messages (`struct
//! rt_msghdr` + a sequence of sockaddrs selected by the `rtm_addrs`
//! bitmask) and supports route dumps via `sysctl(CTL_NET, PF_ROUTE, 0, 0,
//! NET_RT_DUMP, 0)`.
//!
//! ## Per-OS layout table (LP64: FreeBSD/amd64·arm64, OpenBSD, NetBSD, macOS)
//!
//! The `rt_msghdr` layout drifted between the BSDs, so the header size and
//! field offsets are compile-time constants verified against each system's
//! `sys/net/route.h`:
//!
//! | OS        | header size | RTM_VERSION | AF_INET6 | notes                          |
//! |-----------|-------------|-------------|----------|--------------------------------|
//! | FreeBSD   | 152         | 5           | 28       | `_rtm_spare1`, `rtm_fmask`    |
//! | OpenBSD   | 96          | 5           | 24       | `rtm_hdrlen` must be set       |
//! | NetBSD    | 120         | 4           | 24       | `__align64` fields             |
//! | macOS     | 92          | 5           | 30       | classic 4.4BSD layout         |
//!
//! Sockaddrs inside a message are padded to a multiple of `sizeof(long)`
//! (8 bytes on 64-bit): `ROUNDUP(a) = 1 + ((a - 1) | 7)` — `sockaddr_in`
//! (16 bytes) stays 16, `sockaddr_in6` (28 bytes) becomes 32.
//!
//! ## Wire format for RTM_ADD / RTM_DELETE
//!
//! ```text
//! struct rt_msghdr {          // platform-specific size, see table above
//!     u_short rtm_msglen;     // total message length
//!     u_char  rtm_version;    // RTM_VERSION
//!     u_char  rtm_type;       // RTM_ADD=1 / RTM_DELETE=2 / RTM_GET=4
//!     ...                     // index/pid/seq/errno/flags/addrs
//! };
//! struct sockaddr_in  dst;    // RTA_DST    (bit 0x1)
//! struct sockaddr_in  gw;     // RTA_GATEWAY(bit 0x2)
//! struct sockaddr_in  mask;   // RTA_NETMASK(bit 0x4)
//! ```
//!
//! ## Implementation notes
//!
//! * No external crates: raw `socket(2)`/`send(2)`/`recv(2)`/`sysctl(3)`
//!   calls via the platform libc, mirroring the Linux backend's approach.
//! * Writes carry `rtm_seq`; the reply is matched on it so unrelated
//!   asynchronous route-change messages are skipped.
//! * `RTF_STATIC` marks the route manually-added so operators can
//!   distinguish librouting-installed entries from kernel/RA ones.

use crate::{KernelRoute, OsRouteError, OsRouteTable};
use lr_core::addr::{IpAddr, Prefix};
use lr_core::rib::Protocol;

use std::sync::atomic::{AtomicI32, Ordering};

// ===== routing message constants (identical across the BSDs) =====
const RTM_ADD: u8 = 0x1;
const RTM_DELETE: u8 = 0x2;
const RTM_GET: u8 = 0x4;

const RTA_DST: u32 = 0x1;
const RTA_GATEWAY: u32 = 0x2;
const RTA_NETMASK: u32 = 0x4;

const RTF_UP: u32 = 0x1;
const RTF_GATEWAY: u32 = 0x2;
const RTF_HOST: u32 = 0x4;
const RTF_STATIC: u32 = 0x800;

const RTF_PROTO1: u32 = 0x8000; // protocol-specific flag (unused, documented)

const AF_INET: u8 = 2;
const AF_LINK: u8 = 18;

// sysctl(3) constants.
const CTL_NET: i32 = 4;
const NET_RT_DUMP: i32 = 1;

// Platform layout: field offsets within `struct rt_msghdr`.
// Verified against sys/net/route.h of each base system.
#[cfg(target_os = "freebsd")]
mod layout {
    /// `sizeof(struct rt_msghdr)` on FreeBSD/amd64.
    pub const HDR: usize = 152;
    pub const RTM_VERSION: u8 = 5;
    pub const AF_INET6: u8 = 28;
    pub const OFF_FLAGS: usize = 8;
    pub const OFF_ADDRS: usize = 12;
    pub const OFF_SEQ: usize = 20;
    pub const OFF_ERRNO: usize = 24;
}
#[cfg(target_os = "netbsd")]
mod layout {
    /// `sizeof(struct rt_msghdr)` on NetBSD/amd64 (`__align64` members).
    pub const HDR: usize = 120;
    pub const RTM_VERSION: u8 = 4;
    pub const AF_INET6: u8 = 24;
    pub const OFF_FLAGS: usize = 8;
    pub const OFF_ADDRS: usize = 12;
    pub const OFF_SEQ: usize = 20;
    pub const OFF_ERRNO: usize = 24;
}
#[cfg(target_os = "openbsd")]
mod layout {
    /// `sizeof(struct rt_msghdr)` on OpenBSD/amd64.
    pub const HDR: usize = 96;
    pub const RTM_VERSION: u8 = 5;
    pub const AF_INET6: u8 = 24;
    pub const OFF_FLAGS: usize = 16;
    pub const OFF_ADDRS: usize = 12;
    pub const OFF_SEQ: usize = 28;
    pub const OFF_ERRNO: usize = 32;
    /// Offset of `rtm_hdrlen` — OpenBSD requires it to hold the header
    /// size so the kernel knows where the sockaddrs start.
    pub const OFF_HDRLEN: usize = 4;
}
#[cfg(target_os = "macos")]
mod layout {
    /// `sizeof(struct rt_msghdr)` on macOS (xnu bsd/net/route.h).
    pub const HDR: usize = 92;
    pub const RTM_VERSION: u8 = 5;
    pub const AF_INET6: u8 = 30;
    pub const OFF_FLAGS: usize = 8;
    pub const OFF_ADDRS: usize = 12;
    pub const OFF_SEQ: usize = 20;
    pub const OFF_ERRNO: usize = 24;
}

const AF_ROUTE: i32 = 17;
const SOCK_RAW: i32 = 3;

// setsockopt(2) constants (BSD values).
const SOL_SOCKET: i32 = 0xffff;
const SO_RCVTIMEO: i32 = 0x1006;

#[repr(C)]
#[derive(Default, Clone, Copy)]
struct Timeval {
    tv_sec: isize,
    tv_usec: isize,
}

/// Round a sockaddr length up to the routing-socket alignment
/// (`sizeof(long)` = 8 on all supported 64-bit BSDs).
const fn roundup(a: usize) -> usize {
    if a > 0 {
        (a + 7) & !7
    } else {
        8
    }
}

/// PF_ROUTE socket backed implementation of [`OsRouteTable`].
pub struct RouteSocket {
    fd: i32,
    seq: AtomicI32,
}

impl RouteSocket {
    /// Open the routing socket. Requires privileges to *modify* the table
    /// (route additions are superuser-only on stock BSDs); dumping works
    /// unprivileged.
    pub fn connect() -> Result<Self, OsRouteError> {
        // SAFETY: plain socket(2) syscall; the fd is validity-checked and
        // owned by Self (closed on drop).
        let fd = unsafe { libc_socket(AF_ROUTE, SOCK_RAW, 0) };
        if fd < 0 {
            return Err(OsRouteError(format!(
                "socket(PF_ROUTE): {}",
                std::io::Error::last_os_error()
            )));
        }
        // Bound every recv() so a kernel that never answers cannot hang the
        // caller (5 seconds is far above any sane reply latency).
        let tv = Timeval {
            tv_sec: 5,
            tv_usec: 0,
        };
        // SAFETY: setsockopt(2) with a valid fd and a correctly-sized value.
        let rc = unsafe {
            libc_setsockopt(
                fd,
                SOL_SOCKET,
                SO_RCVTIMEO,
                (&raw const tv) as *const core::ffi::c_void,
                core::mem::size_of::<Timeval>(),
            )
        };
        if rc < 0 {
            let e = std::io::Error::last_os_error();
            // SAFETY: close the fd we own before returning the error.
            unsafe { libc_close(fd) };
            return Err(OsRouteError(format!("setsockopt(SO_RCVTIMEO): {}", e)));
        }
        Ok(Self {
            fd,
            seq: AtomicI32::new(1),
        })
    }

    fn next_seq(&self) -> i32 {
        self.seq.fetch_add(1, Ordering::SeqCst)
    }

    /// Build a routing message for one prefix.
    fn build_message(
        &self,
        msg_type: u8,
        flags: u32,
        addrs_mask: u32,
        prefix: &Prefix,
        next_hop: Option<&IpAddr>,
    ) -> Vec<u8> {
        let mut buf = vec![0u8; layout::HDR];
        // sockaddrs appended after the header.
        let dst = sockaddr_v4_or_v6(&prefix.addr);
        buf.extend_from_slice(&dst);
        if let Some(gw) = next_hop {
            buf.extend_from_slice(&sockaddr_v4_or_v6(gw));
        }
        buf.extend_from_slice(&sockaddr_netmask(prefix.prefix_len, &prefix.addr));

        // Header fields.
        let total = buf.len();
        buf[0..2].copy_from_slice(&(total as u16).to_ne_bytes());
        buf[2] = layout::RTM_VERSION;
        buf[3] = msg_type;
        let seq = self.next_seq();
        buf[layout::OFF_FLAGS..layout::OFF_FLAGS + 4].copy_from_slice(&flags.to_ne_bytes());
        buf[layout::OFF_ADDRS..layout::OFF_ADDRS + 4].copy_from_slice(&addrs_mask.to_ne_bytes());
        buf[layout::OFF_SEQ..layout::OFF_SEQ + 4].copy_from_slice(&seq.to_ne_bytes());
        #[cfg(target_os = "openbsd")]
        {
            // OpenBSD: rtm_hdrlen tells the kernel where sockaddrs start.
            buf[layout::OFF_HDRLEN..layout::OFF_HDRLEN + 2]
                .copy_from_slice(&(layout::HDR as u16).to_ne_bytes());
        }
        buf
    }

    /// Send a message and wait for the reply with the matching sequence
    /// number. Returns the reply's `rtm_errno`.
    fn roundtrip(&self, msg: &[u8]) -> Result<i32, OsRouteError> {
        let seq = i32::from_ne_bytes([
            msg[layout::OFF_SEQ],
            msg[layout::OFF_SEQ + 1],
            msg[layout::OFF_SEQ + 2],
            msg[layout::OFF_SEQ + 3],
        ]);
        let msg_type = msg[3];
        // SAFETY: send(2) with a valid fd and buffer; length passed through.
        let n = unsafe {
            libc_send(
                self.fd,
                msg.as_ptr() as *const core::ffi::c_void,
                msg.len(),
                0,
            )
        };
        if n < 0 {
            return Err(OsRouteError(format!(
                "send(PF_ROUTE): {}",
                std::io::Error::last_os_error()
            )));
        }
        // Read replies until the sequence matches; routing sockets also
        // deliver asynchronous route-change notifications which we skip.
        let mut buf = vec![0u8; 2048];
        for _ in 0..8 {
            // SAFETY: recv(2) into an owned buffer with a valid fd.
            let n = unsafe {
                libc_recv(
                    self.fd,
                    buf.as_mut_ptr() as *mut core::ffi::c_void,
                    buf.len(),
                    0,
                )
            };
            if n < 0 {
                let e = std::io::Error::last_os_error();
                return Err(OsRouteError(format!("recv(PF_ROUTE): {}", e)));
            }
            let n = n as usize;
            if n < layout::HDR {
                continue; // runt / notification — keep reading
            }
            if !is_reply(&buf, seq, msg_type) {
                continue;
            }
            let errno = i32::from_ne_bytes([
                buf[layout::OFF_ERRNO],
                buf[layout::OFF_ERRNO + 1],
                buf[layout::OFF_ERRNO + 2],
                buf[layout::OFF_ERRNO + 3],
            ]);
            return Ok(errno);
        }
        // No matching reply after 8 reads (each bounded by SO_RCVTIMEO).
        // All four BSDs echo RTM_ADD/RTM_DELETE with rtm_errno, so silence
        // means the reply was lost or never sent (e.g. a queue flooded
        // with notifications) — report it rather than swallowing
        // EPERM/EEXIST/etc. and letting the caller believe the route was
        // installed.
        Err(OsRouteError(
            "PF_ROUTE: no reply with matching rtm_seq".to_string(),
        ))
    }
}

/// True when a received buffer is the echo for `seq`/`msg_type` (and not an
/// asynchronous route-change notification). Pure so the reply-matching logic
/// is unit-testable without a routing socket.
fn is_reply(buf: &[u8], seq: i32, msg_type: u8) -> bool {
    if buf.len() < layout::HDR {
        return false;
    }
    let rtm_seq = i32::from_ne_bytes([
        buf[layout::OFF_SEQ],
        buf[layout::OFF_SEQ + 1],
        buf[layout::OFF_SEQ + 2],
        buf[layout::OFF_SEQ + 3],
    ]);
    rtm_seq == seq && buf[3] == msg_type
}

impl Drop for RouteSocket {
    fn drop(&mut self) {
        // SAFETY: closing a fd we own.
        unsafe { libc_close(self.fd) };
    }
}

impl OsRouteTable for RouteSocket {
    type Error = OsRouteError;

    fn add_route(
        &mut self,
        prefix: Prefix,
        next_hop: IpAddr,
        _if_index: u32,
    ) -> Result<(), Self::Error> {
        let host = prefix.prefix_len == prefix_len_max(&prefix.addr);
        let mut flags = RTF_UP | RTF_GATEWAY | RTF_STATIC;
        if host {
            flags |= RTF_HOST;
        }
        let msg = self.build_message(
            RTM_ADD,
            flags,
            RTA_DST | RTA_GATEWAY | RTA_NETMASK,
            &prefix,
            Some(&next_hop),
        );
        let errno = self.roundtrip(&msg)?;
        if errno != 0 {
            return Err(OsRouteError(format!(
                "RTM_ADD {}: {}",
                prefix,
                std::io::Error::from_raw_os_error(errno)
            )));
        }
        Ok(())
    }

    fn delete_route(&mut self, prefix: Prefix) -> Result<(), Self::Error> {
        let host = prefix.prefix_len == prefix_len_max(&prefix.addr);
        let mut flags = RTF_UP | RTF_STATIC;
        if host {
            flags |= RTF_HOST;
        }
        let msg = self.build_message(RTM_DELETE, flags, RTA_DST | RTA_NETMASK, &prefix, None);
        let errno = self.roundtrip(&msg)?;
        // ESRCH: the route is already gone — idempotent delete is a success
        // for a reconciliation-driven caller.
        if errno != 0 && errno != ERR_ESRCH {
            return Err(OsRouteError(format!(
                "RTM_DELETE {}: {}",
                prefix,
                std::io::Error::from_raw_os_error(errno)
            )));
        }
        Ok(())
    }

    fn list_routes(&mut self) -> Result<Vec<KernelRoute>, Self::Error> {
        // Dump the whole table via sysctl — a single buffer of RTM_GET
        // messages. Two-step: probe the size, then fetch.
        let mib: [i32; 6] = [CTL_NET, AF_ROUTE, 0, 0, NET_RT_DUMP, 0];
        let mut len: usize = 0;
        // SAFETY: standard sysctl(3) size probe with a null old pointer.
        let rc = unsafe {
            libc_sysctl(
                mib.as_ptr(),
                6,
                core::ptr::null_mut(),
                &mut len,
                core::ptr::null_mut(),
                0,
            )
        };
        if rc != 0 {
            return Err(OsRouteError(format!(
                "sysctl(NET_RT_DUMP size): {}",
                std::io::Error::last_os_error()
            )));
        }
        if len == 0 {
            return Ok(Vec::new());
        }
        let mut buf = vec![0u8; len];
        // SAFETY: standard sysctl(3) fetch into an owned, sized buffer.
        let rc = unsafe {
            libc_sysctl(
                mib.as_ptr(),
                6,
                buf.as_mut_ptr() as *mut core::ffi::c_void,
                &mut len,
                core::ptr::null_mut(),
                0,
            )
        };
        if rc != 0 {
            return Err(OsRouteError(format!(
                "sysctl(NET_RT_DUMP): {}",
                std::io::Error::last_os_error()
            )));
        }
        buf.truncate(len);
        parse_route_dump(&buf)
    }
}

fn prefix_len_max(addr: &IpAddr) -> u8 {
    match addr {
        IpAddr::V4(_) => 32,
        IpAddr::V6(_) => 128,
    }
}

/// Encode an address as a padded routing-socket sockaddr.
fn sockaddr_v4_or_v6(addr: &IpAddr) -> Vec<u8> {
    match addr {
        IpAddr::V4(b) => {
            let mut s = vec![0u8; 16]; // sockaddr_in, no extra padding needed
            s[0] = 16; // sin_len
            s[1] = AF_INET;
            s[4..8].copy_from_slice(b);
            s
        }
        IpAddr::V6(b) => {
            let mut s = vec![0u8; 32]; // sockaddr_in6 (28) padded to 32
            s[0] = 28; // sin6_len
            s[1] = layout::AF_INET6;
            s[8..24].copy_from_slice(b);
            s
        }
    }
}

/// Encode a netmask sockaddr for the given prefix length.
fn sockaddr_netmask(prefix_len: u8, addr: &IpAddr) -> Vec<u8> {
    match addr {
        IpAddr::V4(_) => {
            let mut s = vec![0u8; 16];
            s[0] = 16;
            s[1] = AF_INET;
            let bits = prefix_len.min(32) as u32;
            if bits > 0 {
                let mask = u32::MAX << (32 - bits);
                s[4..8].copy_from_slice(&mask.to_be_bytes());
            }
            s
        }
        IpAddr::V6(_) => {
            let mut s = vec![0u8; 32];
            s[0] = 28;
            s[1] = layout::AF_INET6;
            let bits = prefix_len.min(128) as usize;
            for i in 0..bits {
                s[8 + i / 8] |= 0x80 >> (i % 8);
            }
            s
        }
    }
}

/// Walk one sockaddr out of a message at `cursor`; returns `(family, copied
/// address bytes block, advanced cursor)`.
fn next_sockaddr(buf: &[u8], cursor: &mut usize) -> Option<(u8, usize)> {
    if *cursor + 2 > buf.len() {
        return None;
    }
    let sa_len = buf[*cursor] as usize;
    let family = buf[*cursor + 1];
    let step = roundup(sa_len).max(4);
    let start = *cursor;
    *cursor += step;
    Some((family, start))
}

/// Count the leading contiguous 1-bits of a netmask byte slice.
fn mask_to_prefix_len(bytes: &[u8]) -> u8 {
    let mut len = 0u8;
    for b in bytes {
        let mut bit = 0x80;
        while bit != 0 && (b & bit) != 0 {
            len += 1;
            bit >>= 1;
        }
        if bit != 0 {
            break; // hit a 0 — mask ended
        }
    }
    len
}

/// Parse a `NET_RT_DUMP` buffer into kernel routes.
fn parse_route_dump(buf: &[u8]) -> Result<Vec<KernelRoute>, OsRouteError> {
    let mut out = Vec::new();
    let mut off = 0usize;
    while off + layout::HDR <= buf.len() {
        let msg_len = u16::from_ne_bytes([buf[off], buf[off + 1]]) as usize;
        if msg_len < layout::HDR || off + msg_len > buf.len() {
            break;
        }
        let msg = &buf[off..off + msg_len];
        off += roundup(msg_len);
        if msg[3] != RTM_GET {
            continue; // only route entries carry RTM_GET in a dump
        }
        let addrs = u32::from_ne_bytes([msg[12], msg[13], msg[14], msg[15]]);
        // sockaddrs start after the header (OpenBSD: rtm_hdrlen may extend it).
        #[cfg(target_os = "openbsd")]
        let hdr = u16::from_ne_bytes([msg[4], msg[5]]) as usize;
        #[cfg(not(target_os = "openbsd"))]
        let hdr = layout::HDR;
        let hdr = hdr.max(layout::HDR).min(msg_len);
        let mut cursor = hdr;

        let mut dst: Option<IpAddr> = None;
        let mut gw: Option<IpAddr> = None;
        let mut mask: Option<Vec<u8>> = None;
        for bit in [RTA_DST, RTA_GATEWAY, RTA_NETMASK] {
            if addrs & bit == 0 {
                continue;
            }
            let Some((family, start)) = next_sockaddr(msg, &mut cursor) else {
                break;
            };
            let sa_len = msg[start] as usize;
            match (bit, family) {
                (RTA_DST, 2) if sa_len >= 8 && start + 8 <= msg.len() => {
                    let mut a = [0u8; 4];
                    a.copy_from_slice(&msg[start + 4..start + 8]);
                    dst = Some(IpAddr::V4(a));
                }
                (RTA_DST, f)
                    if f == layout::AF_INET6 && sa_len >= 24 && start + 24 <= msg.len() =>
                {
                    let mut a = [0u8; 16];
                    a.copy_from_slice(&msg[start + 8..start + 24]);
                    dst = Some(IpAddr::V6(a));
                }
                (RTA_GATEWAY, 2) if sa_len >= 8 && start + 8 <= msg.len() => {
                    let mut a = [0u8; 4];
                    a.copy_from_slice(&msg[start + 4..start + 8]);
                    gw = Some(IpAddr::V4(a));
                }
                (RTA_GATEWAY, f)
                    if f == layout::AF_INET6 && sa_len >= 24 && start + 24 <= msg.len() =>
                {
                    let mut a = [0u8; 16];
                    a.copy_from_slice(&msg[start + 8..start + 24]);
                    gw = Some(IpAddr::V6(a));
                }
                (RTA_GATEWAY, AF_LINK) => { /* interface route: no gateway IP */ }
                (RTA_NETMASK, 2) => {
                    let n = sa_len.saturating_sub(4).min(4);
                    mask = Some(msg[start + 4..start + 4 + n].to_vec());
                }
                (RTA_NETMASK, f) if f == layout::AF_INET6 => {
                    let n = sa_len.saturating_sub(8).min(16);
                    mask = Some(msg[start + 8..start + 8 + n].to_vec());
                }
                (RTA_NETMASK, 0) => {
                    // AF_UNSPEC netmask (default route): zero-length mask.
                    mask = Some(Vec::new());
                }
                _ => {}
            }
        }
        let Some(addr) = dst else { continue };
        let plen = mask.as_deref().map(mask_to_prefix_len).unwrap_or(0);
        let prefix = match addr {
            IpAddr::V4(b) => Prefix::new_v4(b, plen.min(32)),
            IpAddr::V6(b) => Prefix::new_v6(b, plen.min(128)),
        };
        out.push(KernelRoute {
            prefix,
            next_hop: gw,
            if_index: None,
            metric: 0,
            protocol: Protocol::Other(0), // route(4) exposes no protocol origin
        });
    }
    Ok(out)
}

// ===== FFI shims (no libc crate dependency) =====

extern "C" {
    fn socket(domain: i32, ty: i32, protocol: i32) -> i32;
    fn send(fd: i32, buf: *const core::ffi::c_void, len: usize, flags: i32) -> isize;
    fn recv(fd: i32, buf: *mut core::ffi::c_void, len: usize, flags: i32) -> isize;
    fn close(fd: i32) -> i32;
    fn setsockopt(
        fd: i32,
        level: i32,
        name: i32,
        value: *const core::ffi::c_void,
        len: usize,
    ) -> i32;
    fn sysctl(
        name: *const i32,
        namelen: u32,
        oldp: *mut core::ffi::c_void,
        oldlenp: *mut usize,
        newp: *mut core::ffi::c_void,
        newlen: usize,
    ) -> i32;
}

unsafe fn libc_socket(d: i32, t: i32, p: i32) -> i32 {
    socket(d, t, p)
}
unsafe fn libc_send(fd: i32, buf: *const core::ffi::c_void, len: usize, flags: i32) -> isize {
    send(fd, buf, len, flags)
}
unsafe fn libc_recv(fd: i32, buf: *mut core::ffi::c_void, len: usize, flags: i32) -> isize {
    recv(fd, buf, len, flags)
}
unsafe fn libc_close(fd: i32) -> i32 {
    close(fd)
}
unsafe fn libc_setsockopt(
    fd: i32,
    level: i32,
    name: i32,
    value: *const core::ffi::c_void,
    len: usize,
) -> i32 {
    setsockopt(fd, level, name, value, len)
}
unsafe fn libc_sysctl(
    name: *const i32,
    namelen: u32,
    oldp: *mut core::ffi::c_void,
    oldlenp: *mut usize,
    newp: *mut core::ffi::c_void,
    newlen: usize,
) -> i32 {
    sysctl(name, namelen, oldp, oldlenp, newp, newlen)
}

// ESRCH: "no such process" doubles as "no such route" on the BSDs.
const ERR_ESRCH: i32 = 3;

#[allow(dead_code)]
const UNUSED_RT_FLAGS_DOC: u32 = RTF_PROTO1;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sockaddr_v4_layout() {
        let s = sockaddr_v4_or_v6(&IpAddr::V4([203, 0, 113, 1]));
        assert_eq!(s.len(), 16);
        assert_eq!(s[0], 16); // sin_len
        assert_eq!(s[1], AF_INET);
        assert_eq!(&s[4..8], &[203, 0, 113, 1]);
    }

    #[test]
    fn sockaddr_v6_layout() {
        let s = sockaddr_v4_or_v6(&IpAddr::V6([
            0x20, 0x01, 0xd, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
        ]));
        assert_eq!(s.len(), 32); // 28 bytes padded to alignment
        assert_eq!(s[0], 28);
        assert_eq!(s[1], layout::AF_INET6);
        assert_eq!(s[8], 0x20);
    }

    #[test]
    fn netmask_prefix_lengths() {
        let m = sockaddr_netmask(24, &IpAddr::V4([0, 0, 0, 0]));
        assert_eq!(mask_to_prefix_len(&m[4..8]), 24);
        let m = sockaddr_netmask(0, &IpAddr::V4([0, 0, 0, 0]));
        assert_eq!(mask_to_prefix_len(&m[4..8]), 0);
        let m = sockaddr_netmask(32, &IpAddr::V4([0, 0, 0, 0]));
        assert_eq!(mask_to_prefix_len(&m[4..8]), 32);
    }

    #[test]
    fn roundup_alignments() {
        assert_eq!(roundup(16), 16);
        assert_eq!(roundup(28), 32);
        assert_eq!(roundup(8), 8);
        assert_eq!(roundup(0), 8);
    }

    /// Reply matching used by `roundtrip`: the echo must carry both the
    /// same rtm_seq and the same message type as the request.
    #[test]
    fn is_reply_matches_seq_and_type() {
        let mut buf = vec![0u8; layout::HDR];
        buf[3] = RTM_ADD;
        buf[layout::OFF_SEQ..layout::OFF_SEQ + 4].copy_from_slice(&42i32.to_ne_bytes());
        assert!(is_reply(&buf, 42, RTM_ADD));
        assert!(!is_reply(&buf, 43, RTM_ADD)); // wrong seq
        assert!(!is_reply(&buf, 42, RTM_DELETE)); // wrong type
        assert!(!is_reply(&buf[..layout::HDR - 1], 42, RTM_ADD)); // runt
    }

    #[test]
    fn dump_parser_synthetic_v4() {
        // Build one synthetic RTM_GET entry: header + dst + gw + mask.
        let mut buf = vec![0u8; layout::HDR];
        let mut total = layout::HDR;
        let dst = sockaddr_v4_or_v6(&IpAddr::V4([10, 2, 0, 0]));
        let gw = sockaddr_v4_or_v6(&IpAddr::V4([192, 0, 2, 1]));
        let mask = sockaddr_netmask(16, &IpAddr::V4([0, 0, 0, 0]));
        total += dst.len() + gw.len() + mask.len();
        buf[0..2].copy_from_slice(&(total as u16).to_ne_bytes());
        buf[2] = layout::RTM_VERSION;
        buf[3] = RTM_GET;
        let addrs = RTA_DST | RTA_GATEWAY | RTA_NETMASK;
        buf[layout::OFF_ADDRS..layout::OFF_ADDRS + 4].copy_from_slice(&addrs.to_ne_bytes());
        buf.extend_from_slice(&dst);
        buf.extend_from_slice(&gw);
        buf.extend_from_slice(&mask);

        let routes = parse_route_dump(&buf).unwrap();
        assert_eq!(routes.len(), 1);
        assert_eq!(routes[0].prefix.to_string(), "10.2.0.0/16");
        assert_eq!(routes[0].next_hop, Some(IpAddr::V4([192, 0, 2, 1])));
    }
}
