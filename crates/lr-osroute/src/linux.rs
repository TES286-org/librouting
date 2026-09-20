//! Linux `rtnetlink` route table reference implementation.
//!
//! rtnetlink (RFC 3549 §2, the Linux AF_NETLINK family) is the primary
//! mechanism for reading and modifying the kernel routing table from
//! userspace. It exposes a UDP-like socket (`AF_NETLINK`, `NETLINK_ROUTE`)
//! through which the kernel sends and receives the following message types:
//!
//! - `RTM_NEWROUTE` — add a route.
//! - `RTM_DELROUTE` — delete a route.
//! - `RTM_GETROUTE` — list routes.
//!
//! Each message has a fixed header (`struct rtmsg`, 12 bytes) followed by a
//! set of RTA attributes (TLV-style: `rta_type:2`, `rta_len:2`,
//! `rta_data:N`). The TLV format mirrors BGP's path-attribute encoding
//! almost exactly.
//!
//! ## Wire layout for `struct rtmsg` (Linux `uapi/linux/rtnetlink.h`)
//!
//! ```text
//! struct rtmsg {
//!     unsigned char rtm_family;    // AF_INET / AF_INET6
//!     unsigned char rtm_dst_len;   // prefix length
//!     unsigned char rtm_src_len;    // 0
//!     unsigned char rtm_tos;       // 0
//!     unsigned char rtm_table;     // RT_TABLE_MAIN (254)
//!     unsigned char rtm_protocol;  // RTPROT_*
//!     unsigned char rtm_scope;     // RT_SCOPE_UNIVERSE
//!     unsigned char rtm_type;      // RTN_UNICAST
//!     unsigned rtm_flags;          // 0
//! };
//! ```
//!
//! ## Implementation notes
//!
//! We use **syscalls directly** via `libc::socket(AF_NETLINK, SOCK_RAW,
//! NETLINK_ROUTE)` to avoid pulling in heavy dependencies like `nix` or
//! `netlink-sys`. The actual send/recv loop is platform-specific; this is a
//! *reference* implementation and not a production-grade rtnetlink library.

use crate::{KernelRoute, OsRouteError, OsRouteTable};
use lr_core::addr::{IpAddr, Prefix};
use lr_core::rib::Protocol;

use std::os::unix::io::RawFd;
use std::sync::atomic::{AtomicU32, Ordering};

// Netlink message types (Linux `uapi/linux/netlink.h`).
const NLMSG_NOOP: u16 = 0x1;
const NLMSG_ERROR: u16 = 0x2;
const NLMSG_DONE: u16 = 0x3;

// rtnetlink message types (`uapi/linux/rtnetlink.h`).
const RTM_NEWROUTE: u16 = 24;
const RTM_DELROUTE: u16 = 25;
const RTM_GETROUTE: u16 = 26;

// Route attribute types.
const RTA_DST: u16 = 1;
const RTA_GATEWAY: u16 = 5;
const RTA_OIF: u16 = 4;
const RTA_PRIORITY: u16 = 6;

// Route protocol origins (RTPROT_*).
#[allow(dead_code)]
const RTPROT_UNSPEC: u8 = 0;
#[allow(dead_code)]
const RTPROT_REDIRECT: u8 = 1;
const RTPROT_KERNEL: u8 = 2;
#[allow(dead_code)]
const RTPROT_BOOT: u8 = 3;
const RTPROT_STATIC: u8 = 4;
// RTPROT_BGP is 186 in uapi/linux/rtnetlink.h (14 is RTPROT_XORP). FRR
// also uses 186, so routes installed here display as "bgp" in `ip route`.
const RTPROT_BGP: u8 = 186;

// Address families.
const AF_UNSPEC: u8 = 0;
const AF_INET: u8 = 2;
const AF_INET6: u8 = 10;

// Netlink flags.
const NLM_F_REQUEST: u16 = 0x01;
const NLM_F_ACK: u16 = 0x04;
const NLM_F_REPLACE: u16 = 0x100;
const NLM_F_CREATE: u16 = 0x400;
const NLM_F_DUMP: u16 = 0x300;

const NETLINK_ROUTE: i32 = 0;
const AF_NETLINK: i32 = 16;
const SOCK_RAW: i32 = 3;

// poll(2) constants.
const POLLIN: i16 = 0x1;
const EINTR: i32 = 4;
/// Dump-read timeout: a real kernel always terminates a dump with
/// NLMSG_DONE, so any wait longer than this means the reply was lost.
const DUMP_TIMEOUT_MS: i32 = 2000;

/// rtnetlink-backed implementation of [`OsRouteTable`].
pub struct RtNetlink {
    fd: RawFd,
    seq: AtomicU32,
    pid: u32,
}

impl RtNetlink {
    /// Open a `NETLINK_ROUTE` socket. Returns an error if the host doesn't
    /// support AF_NETLINK or the process lacks permission.
    pub fn connect() -> Result<Self, OsRouteError> {
        // SAFETY: `socket(2)` is a well-known syscall; the returned fd is
        // checked for negativity (which would indicate an error). The
        // `socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE)` triple is the
        // canonical way to open a rtnetlink socket.
        let fd = unsafe { libc_socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE) };
        if fd < 0 {
            return Err(OsRouteError(format!(
                "socket(AF_NETLINK): {}",
                std::io::Error::last_os_error()
            )));
        }
        // Bind to an arbitrary local address; kernel will assign a unique pid.
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
            let e = std::io::Error::last_os_error();
            unsafe { libc_close(fd) };
            return Err(OsRouteError(format!("bind(AF_NETLINK): {}", e)));
        }
        // Query the kernel-assigned pid (which is the local "address" on
        // the netlink socket). We use it for our outbound messages.
        let mut local = libc_sockaddr_nl {
            nl_family: 0,
            nl_pad: 0,
            nl_pid: 0,
            nl_groups: 0,
        };
        let mut len = core::mem::size_of::<libc_sockaddr_nl>() as u32;
        let rc =
            unsafe { libc_getsockname(fd, (&raw mut local) as *mut core::ffi::c_void, &mut len) };
        if rc < 0 {
            let e = std::io::Error::last_os_error();
            unsafe { libc_close(fd) };
            return Err(OsRouteError(format!("getsockname: {}", e)));
        }
        Ok(Self {
            fd,
            seq: AtomicU32::new(1),
            pid: local.nl_pid,
        })
    }

    fn next_seq(&self) -> u32 {
        self.seq.fetch_add(1, Ordering::SeqCst)
    }

    /// Send a raw netlink message to the kernel.
    fn sendmsg(&self, buf: &[u8]) -> Result<(), OsRouteError> {
        let dest = libc_sockaddr_nl {
            nl_family: AF_NETLINK as u16,
            nl_pad: 0,
            nl_pid: 0, // kernel
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
        let sent = unsafe { libc_sendmsg(self.fd, &msg, 0) };
        if sent < 0 {
            return Err(OsRouteError(format!(
                "sendmsg: {}",
                std::io::Error::last_os_error()
            )));
        }
        Ok(())
    }

    /// Send a raw netlink message and read a single response datagram.
    /// Suited to ACK-style requests (add/delete), where the kernel answers
    /// with exactly one `NLMSG_ERROR` message.
    fn sendmsg_and_recv(&self, buf: &[u8]) -> Result<Vec<u8>, OsRouteError> {
        self.sendmsg(buf)?;
        // Read response. Allocate a generous buffer.
        let mut out = vec![0u8; 8192];
        let n = unsafe {
            libc_recv(
                self.fd,
                out.as_mut_ptr() as *mut core::ffi::c_void,
                out.len(),
                0,
            )
        };
        if n < 0 {
            return Err(OsRouteError(format!(
                "recv: {}",
                std::io::Error::last_os_error()
            )));
        }
        out.truncate(n as usize);
        Ok(out)
    }

    /// Send a raw netlink message and read the *full* multi-datagram
    /// response, looping until `NLMSG_DONE` arrives (or a timeout expires)
    /// and accumulating the datagrams into one buffer. A kernel dump is
    /// delivered as several datagrams; reading only the first truncates the
    /// FIB for any table larger than one datagram (~8 KB).
    fn sendmsg_and_recv_dump(&self, buf: &[u8]) -> Result<Vec<u8>, OsRouteError> {
        self.sendmsg(buf)?;
        let mut out = Vec::with_capacity(8192);
        loop {
            // Poll first so a kernel that never sends NLMSG_DONE (or a
            // wedged peer) cannot hang the caller indefinitely.
            let mut pfd = libc_pollfd {
                fd: self.fd,
                events: POLLIN,
                revents: 0,
            };
            // SAFETY: `pfd` is a valid single-element pollfd array.
            let rc = unsafe { libc_poll(&mut pfd, 1, DUMP_TIMEOUT_MS) };
            if rc < 0 {
                let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
                if errno == EINTR {
                    continue;
                }
                return Err(OsRouteError(format!(
                    "poll: {}",
                    std::io::Error::last_os_error()
                )));
            }
            if rc == 0 {
                return Err(OsRouteError(
                    "rtnetlink dump timed out waiting for NLMSG_DONE".to_string(),
                ));
            }
            let mut chunk = vec![0u8; 8192];
            let n = unsafe {
                libc_recv(
                    self.fd,
                    chunk.as_mut_ptr() as *mut core::ffi::c_void,
                    chunk.len(),
                    0,
                )
            };
            if n < 0 {
                return Err(OsRouteError(format!(
                    "recv: {}",
                    std::io::Error::last_os_error()
                )));
            }
            if n == 0 {
                // Netlink has no EOF semantics; a zero-length datagram is
                // malformed — bail rather than spin.
                return Err(OsRouteError(
                    "recv: zero-length netlink datagram".to_string(),
                ));
            }
            out.extend_from_slice(&chunk[..n as usize]);
            if dump_contains_done(&out) {
                return Ok(out);
            }
        }
    }

    fn build_request(
        &self,
        msg_type: u16,
        flags: u16,
        rtm_family: u8,
        rtm_dst_len: u8,
        rtm_protocol: u8,
        attributes: &[u8],
    ) -> Vec<u8> {
        let total_len = 16 + 12 + attributes.len();
        let aligned = (total_len + 3) & !3;
        let mut buf = vec![0u8; aligned];
        // nlmsghdr (16 bytes):
        //   nlmsg_len: u32 (total message length, including header)
        //   nlmsg_type: u16
        //   nlmsg_flags: u16
        //   nlmsg_seq: u32
        //   nlmsg_pid: u32
        buf[0..4].copy_from_slice(&(total_len as u32).to_ne_bytes());
        buf[4..6].copy_from_slice(&msg_type.to_ne_bytes());
        buf[6..8].copy_from_slice(&flags.to_ne_bytes());
        let seq = self.next_seq();
        buf[8..12].copy_from_slice(&seq.to_ne_bytes());
        buf[12..16].copy_from_slice(&self.pid.to_ne_bytes());
        // rtmsg (12 bytes):
        //   rtm_family: u8
        //   rtm_dst_len: u8
        //   rtm_src_len: u8
        //   rtm_tos: u8
        //   rtm_table: u8
        //   rtm_protocol: u8
        //   rtm_scope: u8
        //   rtm_type: u8
        //   rtm_flags: u32
        buf[16] = rtm_family;
        buf[17] = rtm_dst_len;
        buf[18] = 0; // rtm_src_len
        buf[19] = 0; // rtm_tos
        buf[20] = 254; // RT_TABLE_MAIN
        buf[21] = rtm_protocol;
        buf[22] = 0; // RT_SCOPE_UNIVERSE
        buf[23] = 1; // RTN_UNICAST
        buf[24..28].copy_from_slice(&0u32.to_ne_bytes()); // rtm_flags
                                                          // Attributes
        buf[28..28 + attributes.len()].copy_from_slice(attributes);
        buf
    }

    fn build_rta_attribute(rta_type: u16, data: &[u8]) -> Vec<u8> {
        // rta_len = sizeof(rta_attr_header) + data.len()
        let rta_len = (4 + data.len()) as u16;
        let aligned = (rta_len as usize + 3) & !3;
        let mut buf = vec![0u8; aligned];
        buf[0..2].copy_from_slice(&rta_len.to_ne_bytes());
        buf[2..4].copy_from_slice(&rta_type.to_ne_bytes());
        buf[4..4 + data.len()].copy_from_slice(data);
        buf
    }
}

impl Drop for RtNetlink {
    fn drop(&mut self) {
        unsafe { libc_close(self.fd) };
    }
}

impl OsRouteTable for RtNetlink {
    type Error = OsRouteError;

    fn add_route(
        &mut self,
        prefix: Prefix,
        next_hop: IpAddr,
        if_index: u32,
    ) -> Result<(), Self::Error> {
        let (family, addr, dst_len, addr_len) = match prefix.addr {
            IpAddr::V4(b) => (AF_INET, b.to_vec(), prefix.prefix_len, 4),
            IpAddr::V6(b) => (AF_INET6, b.to_vec(), prefix.prefix_len, 16),
        };
        let mut attrs = Vec::new();
        attrs.extend(Self::build_rta_attribute(RTA_DST, &addr));
        attrs.extend(Self::build_rta_attribute(RTA_GATEWAY, next_hop.octets()));
        // With no explicit output interface the kernel resolves the gateway
        // against the existing table (`ip route add ... via GW` semantics).
        // Passing RTA_OIF=0 would be rejected with EINVAL, so omit it.
        if if_index != 0 {
            attrs.extend(Self::build_rta_attribute(RTA_OIF, &if_index.to_ne_bytes()));
        }
        // Pad to 4-byte alignment
        while attrs.len() % 4 != 0 {
            attrs.push(0);
        }
        let _ = (addr_len, dst_len); // for documentation
        let buf = self.build_request(
            RTM_NEWROUTE,
            // Create a missing route and atomically replace an existing
            // route for the same prefix. Without CREATE, a first install is
            // an update-only request and the kernel returns ENOENT.
            NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_REPLACE,
            family,
            prefix.prefix_len,
            RTPROT_BGP,
            &attrs,
        );
        let resp = self.sendmsg_and_recv(&buf)?;
        // For RTM_NEWROUTE with NLM_F_ACK, kernel sends NLMSG_ERROR with
        // error=0 on success.
        check_ack(&resp)
    }

    fn delete_route(&mut self, prefix: Prefix) -> Result<(), Self::Error> {
        let (family, addr) = match prefix.addr {
            IpAddr::V4(b) => (AF_INET, b.to_vec()),
            IpAddr::V6(b) => (AF_INET6, b.to_vec()),
        };
        let mut attrs = Vec::new();
        attrs.extend(Self::build_rta_attribute(RTA_DST, &addr));
        while attrs.len() % 4 != 0 {
            attrs.push(0);
        }
        let buf = self.build_request(
            RTM_DELROUTE,
            NLM_F_REQUEST | NLM_F_ACK,
            family,
            prefix.prefix_len,
            0,
            &attrs,
        );
        let resp = self.sendmsg_and_recv(&buf)?;
        check_ack(&resp)
    }

    fn list_routes(&mut self) -> Result<Vec<KernelRoute>, Self::Error> {
        let buf = self.build_request(
            RTM_GETROUTE,
            NLM_F_REQUEST | NLM_F_DUMP,
            AF_UNSPEC, // we want both v4 and v6
            0,
            0,
            &[],
        );
        let resp = self.sendmsg_and_recv_dump(&buf)?;
        parse_dump_response(&resp)
    }
}

/// True when `buf` contains a complete `NLMSG_DONE` message. Walks the
/// accumulated messages so a datagram that ends mid-message (its tail
/// arrives in the next recv) is not mistaken for the dump terminator.
fn dump_contains_done(buf: &[u8]) -> bool {
    let mut cursor = 0;
    while cursor + 16 <= buf.len() {
        let nlmsg_len = u32::from_ne_bytes([
            buf[cursor],
            buf[cursor + 1],
            buf[cursor + 2],
            buf[cursor + 3],
        ]) as usize;
        if nlmsg_len < 16 || cursor + nlmsg_len > buf.len() {
            break; // incomplete message — wait for more data
        }
        let nlmsg_type = u16::from_ne_bytes([buf[cursor + 4], buf[cursor + 5]]);
        if nlmsg_type == NLMSG_DONE {
            return true;
        }
        cursor += nlmsg_len;
        // Align to 4 bytes.
        while cursor % 4 != 0 {
            cursor += 1;
        }
    }
    false
}

/// Parse a complete (NLMSG_DONE-terminated) rtnetlink dump into routes.
fn parse_dump_response(resp: &[u8]) -> Result<Vec<KernelRoute>, OsRouteError> {
    let mut out = Vec::new();
    let mut cursor = 0;
    while cursor + 16 <= resp.len() {
        let nlmsg_len = u32::from_ne_bytes([
            resp[cursor],
            resp[cursor + 1],
            resp[cursor + 2],
            resp[cursor + 3],
        ]) as usize;
        if nlmsg_len < 16 || cursor + nlmsg_len > resp.len() {
            break;
        }
        let nlmsg_type = u16::from_ne_bytes([resp[cursor + 4], resp[cursor + 5]]);
        match nlmsg_type {
            // Skip (the advance below still runs — a `continue` here would
            // spin forever on the same message).
            NLMSG_NOOP => {}
            NLMSG_ERROR => {
                // An error payload is nlmsgerr (16 bytes) + optional
                // original request; never read past a short message.
                if nlmsg_len < 20 {
                    return Err(OsRouteError(format!(
                        "rtnetlink: short error message (nlmsg_len={})",
                        nlmsg_len
                    )));
                }
                let err = i32::from_ne_bytes([
                    resp[cursor + 16],
                    resp[cursor + 17],
                    resp[cursor + 18],
                    resp[cursor + 19],
                ]);
                if err != 0 {
                    return Err(OsRouteError(format!("rtnetlink error: {}", err)));
                }
            }
            NLMSG_DONE => break,
            RTM_NEWROUTE => {
                if let Some(route) = parse_route_message(&resp[cursor..cursor + nlmsg_len]) {
                    out.push(route);
                }
            }
            _ => {}
        }
        cursor += nlmsg_len;
        // Align to 4 bytes.
        while cursor % 4 != 0 {
            cursor += 1;
        }
    }
    Ok(out)
}

fn check_ack(resp: &[u8]) -> Result<(), OsRouteError> {
    if resp.len() < 20 {
        return Err(OsRouteError(format!(
            "rtnetlink: short ack response (len={})",
            resp.len()
        )));
    }
    let nlmsg_type = u16::from_ne_bytes([resp[4], resp[5]]);
    if nlmsg_type != NLMSG_ERROR {
        return Err(OsRouteError(format!(
            "rtnetlink: unexpected response type {}",
            nlmsg_type
        )));
    }
    let err = i32::from_ne_bytes([resp[16], resp[17], resp[18], resp[19]]);
    if err != 0 {
        return Err(OsRouteError(format!("rtnetlink: error {}", err)));
    }
    Ok(())
}

fn parse_route_message(buf: &[u8]) -> Option<KernelRoute> {
    // buf layout: nlmsghdr(16) + rtmsg(12) + [rta_attrs...]
    if buf.len() < 28 {
        return None;
    }
    let rtm_family = buf[16];
    let rtm_dst_len = buf[17];
    let rtm_protocol = buf[21];
    // Walk the attributes.
    let mut prefix_addr: Option<Vec<u8>> = None;
    let mut gateway: Option<Vec<u8>> = None;
    let mut if_index: Option<u32> = None;
    let mut priority: u32 = 0;
    let mut cursor = 28;
    while cursor + 4 <= buf.len() {
        let rta_len = u16::from_ne_bytes([buf[cursor], buf[cursor + 1]]) as usize;
        let rta_type = u16::from_ne_bytes([buf[cursor + 2], buf[cursor + 3]]);
        if rta_len < 4 || cursor + rta_len > buf.len() {
            break;
        }
        let data_len = rta_len - 4;
        let data = &buf[cursor + 4..cursor + 4 + data_len];
        match rta_type {
            RTA_DST => prefix_addr = Some(data.to_vec()),
            RTA_GATEWAY => gateway = Some(data.to_vec()),
            RTA_OIF => {
                if data.len() == 4 {
                    if_index = Some(u32::from_ne_bytes([data[0], data[1], data[2], data[3]]));
                }
            }
            RTA_PRIORITY if data.len() == 4 => {
                priority = u32::from_ne_bytes([data[0], data[1], data[2], data[3]]);
            }
            _ => {}
        }
        // Advance (aligned to 4 bytes).
        cursor += (rta_len + 3) & !3;
    }
    let prefix = match (rtm_family, prefix_addr) {
        (AF_INET, Some(d)) if d.len() == 4 || d.is_empty() => {
            let mut b = [0u8; 4];
            if !d.is_empty() {
                b.copy_from_slice(&d[..4]);
            }
            Prefix::new_v4(b, rtm_dst_len)
        }
        (AF_INET6, Some(d)) if d.len() == 16 || d.is_empty() => {
            let mut b = [0u8; 16];
            if !d.is_empty() {
                b.copy_from_slice(&d[..16]);
            }
            Prefix::new_v6(b, rtm_dst_len)
        }
        _ => return None,
    };
    let next_hop = gateway.and_then(|d| IpAddr::from_bytes(&d));
    let protocol = match rtm_protocol {
        RTPROT_KERNEL => Protocol::Connected,
        RTPROT_STATIC => Protocol::Static,
        RTPROT_BGP => Protocol::Bgp,
        _ => Protocol::Other(rtm_protocol as u16),
    };
    Some(KernelRoute {
        prefix,
        next_hop,
        if_index,
        metric: priority,
        protocol,
    })
}

// ===== FFI shims (avoid pulling in the `libc` crate) =====

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
struct libc_pollfd {
    fd: i32,
    events: i16,
    revents: i16,
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
    fn getsockname(fd: i32, addr: *mut core::ffi::c_void, len: *mut u32) -> i32;
    fn sendmsg(fd: i32, msg: *const libc_msghdr, flags: i32) -> isize;
    fn recv(fd: i32, buf: *mut core::ffi::c_void, len: usize, flags: i32) -> isize;
    fn poll(fds: *mut libc_pollfd, nfds: u64, timeout_ms: i32) -> i32;
    fn close(fd: i32) -> i32;
}

unsafe fn libc_socket(d: i32, t: i32, p: i32) -> i32 {
    socket(d, t, p)
}
unsafe fn libc_bind(fd: i32, addr: *const core::ffi::c_void, len: u32) -> i32 {
    bind(fd, addr, len)
}
unsafe fn libc_getsockname(fd: i32, addr: *mut core::ffi::c_void, len: *mut u32) -> i32 {
    getsockname(fd, addr, len)
}
unsafe fn libc_sendmsg(fd: i32, msg: *const libc_msghdr, flags: i32) -> isize {
    sendmsg(fd, msg, flags)
}
unsafe fn libc_recv(fd: i32, buf: *mut core::ffi::c_void, len: usize, flags: i32) -> isize {
    recv(fd, buf, len, flags)
}
unsafe fn libc_poll(fds: *mut libc_pollfd, nfds: u64, timeout_ms: i32) -> i32 {
    poll(fds, nfds, timeout_ms)
}
unsafe fn libc_close(fd: i32) -> i32 {
    close(fd)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Wrap `payload` in an nlmsghdr (flags/seq/pid zeroed).
    fn nlmsg(msg_type: u16, payload: &[u8]) -> Vec<u8> {
        let mut buf = vec![0u8; 16 + payload.len()];
        let total = 16 + payload.len();
        buf[0..4].copy_from_slice(&(total as u32).to_ne_bytes());
        buf[4..6].copy_from_slice(&msg_type.to_ne_bytes());
        buf[16..].copy_from_slice(payload);
        buf
    }

    /// A full RTM_NEWROUTE message: rtmsg + RTA_DST + RTA_GATEWAY.
    fn route_msg(protocol: u8) -> Vec<u8> {
        let mut payload = vec![0u8; 12];
        payload[0] = AF_INET; // rtm_family
        payload[1] = 24; // rtm_dst_len
        payload[5] = protocol;
        payload[7] = 1; // RTN_UNICAST
        payload.extend_from_slice(&RtNetlink::build_rta_attribute(RTA_DST, &[192, 0, 2, 0]));
        payload.extend_from_slice(&RtNetlink::build_rta_attribute(
            RTA_GATEWAY,
            &[198, 51, 100, 1],
        ));
        nlmsg(RTM_NEWROUTE, &payload)
    }

    #[test]
    fn attr_attribute_roundtrip_v4() {
        // Build an RTA_DST attribute for 10.0.0.0/8.
        let addr = [10u8, 0, 0, 0];
        let enc = RtNetlink::build_rta_attribute(RTA_DST, &addr);
        // rta_len = 4 + 4 = 8
        assert_eq!(u16::from_ne_bytes([enc[0], enc[1]]), 8);
        assert_eq!(u16::from_ne_bytes([enc[2], enc[3]]), RTA_DST);
        assert_eq!(&enc[4..8], &addr);
    }

    #[test]
    fn connect_fails_gracefully_in_unpriv_container() {
        // In most CI containers, AF_NETLINK sockets are available, but in
        // some sandboxed environments they are not. Either way, we expect
        // `connect` to either succeed or return an `OsRouteError`.
        let result = RtNetlink::connect();
        match result {
            Ok(_) => { /* OK */ }
            Err(e) => {
                assert!(
                    e.0.contains("socket") || e.0.contains("bind") || e.0.contains("getsockname")
                );
            }
        }
    }

    /// RTPROT_BGP is 186 in uapi/linux/rtnetlink.h — 14 is RTPROT_XORP.
    #[test]
    fn rtprot_bgp_is_186() {
        assert_eq!(RTPROT_BGP, 186);
        assert_ne!(RTPROT_BGP, 14); // 14 = RTPROT_XORP
    }

    #[test]
    fn route_install_flags_create_or_replace() {
        let flags = NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_REPLACE;
        assert_eq!(flags, 0x0505);
        assert_ne!(flags & NLM_F_CREATE, 0);
        assert_ne!(flags & NLM_F_REPLACE, 0);
    }

    /// The parse loop must advance past NLMSG_NOOP — a `continue` before
    /// the cursor advance spun forever on any NOOP in a dump.
    #[test]
    fn parse_dump_advances_past_noop() {
        let mut buf = nlmsg(NLMSG_NOOP, &[]);
        buf.extend_from_slice(&route_msg(RTPROT_BGP));
        buf.extend_from_slice(&nlmsg(NLMSG_DONE, &[]));
        let routes = parse_dump_response(&buf).unwrap();
        assert_eq!(routes.len(), 1);
        assert_eq!(routes[0].prefix.to_string(), "192.0.2.0/24");
        assert_eq!(routes[0].next_hop, Some(IpAddr::V4([198, 51, 100, 1])));
        // protocol round-trips as Bgp with the corrected constant (186).
        assert_eq!(routes[0].protocol, Protocol::Bgp);
    }

    /// A 16-byte NLMSG_ERROR must be rejected, not read past the buffer
    /// (the old guard only required nlmsg_len >= 16).
    #[test]
    fn parse_dump_rejects_short_error_message() {
        let buf = nlmsg(NLMSG_ERROR, &[]); // 16-byte message, no payload
        let e = parse_dump_response(&buf).unwrap_err();
        assert!(e.0.contains("short error"), "{}", e.0);
    }

    /// A normal 20-byte NLMSG_ERROR with error=0 is not an error.
    #[test]
    fn parse_dump_accepts_zero_error() {
        let buf = nlmsg(NLMSG_ERROR, &0i32.to_ne_bytes());
        let routes = parse_dump_response(&buf).unwrap();
        assert!(routes.is_empty());
    }

    /// A non-zero netlink error aborts the dump parse.
    #[test]
    fn parse_dump_surfaces_netlink_error() {
        let buf = nlmsg(NLMSG_ERROR, &(-22i32).to_ne_bytes()); // EINVAL
        let e = parse_dump_response(&buf).unwrap_err();
        assert!(e.0.contains("rtnetlink error"), "{}", e.0);
    }

    #[test]
    fn dump_contains_done_detects_terminator() {
        // No DONE yet: only a NOOP.
        assert!(!dump_contains_done(&nlmsg(NLMSG_NOOP, &[])));
        // DONE after a route message.
        let mut buf = route_msg(RTPROT_BGP);
        buf.extend_from_slice(&nlmsg(NLMSG_DONE, &[]));
        assert!(dump_contains_done(&buf));
        // A message that claims to be longer than the bytes present must
        // not be treated as done (its tail may arrive in a later recv).
        let mut cut = vec![0u8; 20];
        cut[0..4].copy_from_slice(&40u32.to_ne_bytes());
        cut[4..6].copy_from_slice(&NLMSG_DONE.to_ne_bytes());
        assert!(!dump_contains_done(&cut));
    }

    #[test]
    fn check_ack_accepts_zero_error() {
        let ack = nlmsg(NLMSG_ERROR, &0i32.to_ne_bytes());
        assert!(check_ack(&ack).is_ok());
    }

    #[test]
    fn check_ack_rejects_short_response() {
        assert!(check_ack(&[0u8; 16]).is_err());
        assert!(check_ack(&[0u8; 10]).is_err());
    }

    #[test]
    fn check_ack_rejects_nonzero_error() {
        let ack = nlmsg(NLMSG_ERROR, &(-17i32).to_ne_bytes()); // EEXIST
        let e = check_ack(&ack).unwrap_err();
        assert!(e.0.contains("error"), "{}", e.0);
    }
}
