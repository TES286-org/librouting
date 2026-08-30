//! Linux MPLS route table — `AF_MPLS` netlink.
//!
//! Linux exposes MPLS label-switched-path operations through the same
//! `NETLINK_ROUTE` family used for IP routes, but with
//! `rtm_family = AF_MPLS` (28). The kernel MPLS stack is gated on the
//! `mpls_router` module and the `/proc/sys/net/mpls/platform_labels`
//! sysctl — see [`mpls_platform_labels`] for capability detection.
//!
//! ## MPLS route semantics
//!
//! An MPLS route is keyed by the incoming label (`RTA_DST`). The action
//! taken on a packet carrying that label depends on the attributes
//! present:
//!
//! | Action                  | RTA_DST | RTA_VIA | RTA_NEWDST | RTA_OIF |
//! |-------------------------|---------|---------|------------|---------|
//! | Pop  (label → IP)       | in-label | gw     | —          | ifindex |
//! | Swap (label → label)    | in-label | gw     | new-stack  | ifindex |
//!
//! `RTA_VIA` is the gateway as a `struct rtvia` payload: 2-byte family
//! (`sa_family_t`, network byte order) + address (6 bytes total for
//! IPv4, 18 for IPv6). `RTA_NEWDST` is the new label stack to push, in
//! the 4-octet-per-entry wire form of RFC 3032 §2.1. Push (IP → label)
//! is configured differently — via `ip route add <prefix> encap mpls
//! <stack>` on the IP route, not through `AF_MPLS`. The router layer
//! handles the IP-route side via [`crate::RtNetlink`]; this module owns
//! the LSP side.
//!
//! References: Linux `uapi/linux/mpls.h`, `net/mpls/mpls_routes.c`,
//! `Documentation/networking/mpls-sysctl.rst`.

use std::fs;
use std::os::unix::io::RawFd;
use std::sync::atomic::{AtomicU32, Ordering};

use lr_core::addr::IpAddr;
use lr_mpls::{Label, LabelStack};

// Netlink message types and constants — same family as `linux::RtNetlink`
// but duplicated here to keep the MPLS module self-contained.
// Netlink message types (uapi/linux/netlink.h).
#[allow(dead_code)]
const NLMSG_NOOP: u16 = 0x1;
const NLMSG_ERROR: u16 = 0x2;
#[allow(dead_code)]
const NLMSG_DONE: u16 = 0x3;

// rtnetlink message types (uapi/linux/rtnetlink.h).
const RTM_NEWROUTE: u16 = 24;
const RTM_DELROUTE: u16 = 25;
#[allow(dead_code)]
const RTM_GETROUTE: u16 = 26;

// rtnetlink RTA types (uapi/linux/rtnetlink.h).
const RTA_DST: u16 = 1;
const RTA_OIF: u16 = 4;
const RTA_VIA: u16 = 18;
const RTA_NEWDST: u16 = 19;

// Address families (2-byte `sa_family_t` in `struct rtvia`).
const AF_INET: u16 = 2;
const AF_INET6: u16 = 10;
const AF_MPLS: u8 = 28;

// Netlink flags.
const NLM_F_REQUEST: u16 = 0x01;
const NLM_F_ACK: u16 = 0x04;
const NLM_F_REPLACE: u16 = 0x100;
const NLM_F_CREATE: u16 = 0x400;

/// Flags for route installation: CREATE + REPLACE so that installing over
/// an existing in-label *replaces* it (`mpls_route_add()` in
/// `net/mpls/af_mpls.c` returns -EEXIST without NLM_F_REPLACE).
const ADD_ROUTE_FLAGS: u16 = NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_REPLACE;

// Netlink socket constants.
const NETLINK_ROUTE: i32 = 0;
const AF_NETLINK: i32 = 16;
const SOCK_RAW: i32 = 3;

/// MPLS label bit-width on the wire (`rtm_dst_len` for AF_MPLS routes).
const MPLS_LABEL_LEN: u8 = 20;

/// Error returned by MPLS netlink operations.
#[derive(Debug, Clone)]
pub enum MplsRouteError {
    /// The platform does not implement AF_MPLS (non-Linux builds).
    Unsupported,
    /// MPLS routing is not enabled in the kernel — load `mpls_router`
    /// and set `/proc/sys/net/mpls/platform_labels` to a non-zero value.
    NotEnabled,
    /// A netlink syscall failed.
    Syscall(String),
    /// The kernel rejected the request (e.g. label already installed).
    Kernel(String),
    /// The label stack is empty — MPLS routes need at least one label.
    EmptyLabelStack,
}

impl std::fmt::Display for MplsRouteError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unsupported => f.write_str("AF_MPLS is not supported on this platform"),
            Self::NotEnabled => f.write_str(
                "MPLS routing is not enabled (load mpls_router, set net.mpls.platform_labels)",
            ),
            Self::Syscall(s) => write!(f, "mpls netlink syscall: {}", s),
            Self::Kernel(s) => write!(f, "mpls kernel error: {}", s),
            Self::EmptyLabelStack => f.write_str("MPLS route requires a non-empty label stack"),
        }
    }
}

impl std::error::Error for MplsRouteError {}

impl From<std::io::Error> for MplsRouteError {
    fn from(e: std::io::Error) -> Self {
        Self::Syscall(e.to_string())
    }
}

/// The action an MPLS route takes on a packet carrying the in-label.
///
/// Matches the kernel's `RTA_VIA` + `RTA_NEWDST` matrix:
/// - [`MplsRouteAction::Pop`] — pop the label, forward the IP packet
///   to the gateway. (`RTA_VIA` + `RTA_OIF`, no `RTA_NEWDST`.)
/// - [`MplsRouteAction::Swap`] — replace the top label with a new stack
///   and forward to the gateway. (`RTA_VIA` + `RTA_OIF` + `RTA_NEWDST`.)
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MplsRouteAction {
    Pop {
        next_hop: IpAddr,
        if_index: u32,
    },
    Swap {
        new_stack: LabelStack,
        next_hop: IpAddr,
        if_index: u32,
    },
}

impl MplsRouteAction {
    pub fn next_hop(&self) -> IpAddr {
        match self {
            Self::Pop { next_hop, .. } | Self::Swap { next_hop, .. } => *next_hop,
        }
    }
    pub fn if_index(&self) -> u32 {
        match self {
            Self::Pop { if_index, .. } | Self::Swap { if_index, .. } => *if_index,
        }
    }
}

/// A kernel MPLS route entry — keyed by the incoming label.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MplsRoute {
    pub in_label: Label,
    pub action: MplsRouteAction,
}

impl MplsRoute {
    /// Convenience: pop-and-forward.
    pub fn pop(in_label: Label, next_hop: IpAddr, if_index: u32) -> Self {
        Self {
            in_label,
            action: MplsRouteAction::Pop { next_hop, if_index },
        }
    }

    /// Convenience: swap-and-forward.
    pub fn swap(in_label: Label, new_stack: LabelStack, next_hop: IpAddr, if_index: u32) -> Self {
        Self {
            in_label,
            action: MplsRouteAction::Swap {
                new_stack,
                next_hop,
                if_index,
            },
        }
    }
}

/// Read `/proc/sys/net/mpls/platform_labels` and return the label-bit
/// width the kernel supports (typically 16 or 20). Returns 0 when MPLS
/// routing is not enabled or the platform is not Linux.
///
/// Load the `mpls_router` module and write a non-zero value
/// (`echo 16 > /proc/sys/net/mpls/platform_labels`) to enable MPLS.
pub fn mpls_platform_labels() -> u32 {
    match fs::read_to_string("/proc/sys/net/mpls/platform_labels") {
        Ok(s) => s.trim().parse().unwrap_or(0),
        Err(_) => 0,
    }
}

/// True when the kernel has MPLS routing enabled.
pub fn mpls_enabled() -> bool {
    mpls_platform_labels() > 0
}

/// `AF_MPLS` netlink backend for MPLS LSP installation.
#[derive(Debug)]
pub struct MplsNetlink {
    fd: RawFd,
    seq: AtomicU32,
    pid: u32,
}

impl MplsNetlink {
    /// Open a `NETLINK_ROUTE` socket. Returns
    /// [`MplsRouteError::NotEnabled`] when MPLS routing is not enabled in
    /// the kernel — callers should check [`mpls_enabled`] first.
    pub fn connect() -> Result<Self, MplsRouteError> {
        if !mpls_enabled() {
            return Err(MplsRouteError::NotEnabled);
        }
        let fd = unsafe { libc_socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE) };
        if fd < 0 {
            return Err(MplsRouteError::Syscall(format!(
                "socket(AF_NETLINK): {}",
                std::io::Error::last_os_error()
            )));
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
            let e = std::io::Error::last_os_error();
            unsafe { libc_close(fd) };
            return Err(MplsRouteError::Syscall(format!("bind(AF_NETLINK): {}", e)));
        }
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
            return Err(MplsRouteError::Syscall(format!("getsockname: {}", e)));
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

    fn sendmsg_and_recv(&self, buf: &[u8]) -> Result<Vec<u8>, MplsRouteError> {
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
        let sent = unsafe { libc_sendmsg(self.fd, &msg, 0) };
        if sent < 0 {
            return Err(MplsRouteError::Syscall(format!(
                "sendmsg: {}",
                std::io::Error::last_os_error()
            )));
        }
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
            return Err(MplsRouteError::Syscall(format!(
                "recv: {}",
                std::io::Error::last_os_error()
            )));
        }
        out.truncate(n as usize);
        Ok(out)
    }

    /// Build the rtnetlink request body for an MPLS route operation.
    /// `msg_type` is `RTM_NEWROUTE` or `RTM_DELROUTE`; `flags` carries the
    /// NLM_F_* bits. `route` is the route to install (ignored for delete,
    /// which only needs the in-label).
    fn build_request(
        &self,
        msg_type: u16,
        flags: u16,
        route: &MplsRoute,
    ) -> Result<Vec<u8>, MplsRouteError> {
        // RTA_DST = 4-byte in-label (top of stack, S=1).
        let in_label_bytes = route.in_label.encode_4octet(true);
        let mut attrs = Vec::new();
        attrs.extend(Self::build_rta_attribute(RTA_DST, &in_label_bytes));

        match &route.action {
            MplsRouteAction::Pop { next_hop, if_index } => {
                attrs.extend(Self::build_rta_via(*next_hop));
                if *if_index != 0 {
                    attrs.extend(Self::build_rta_attribute(RTA_OIF, &if_index.to_ne_bytes()));
                }
            }
            MplsRouteAction::Swap {
                new_stack,
                next_hop,
                if_index,
            } => {
                if new_stack.is_empty() {
                    return Err(MplsRouteError::EmptyLabelStack);
                }
                let new_dst = new_stack.encode_4octet();
                attrs.extend(Self::build_rta_attribute(RTA_NEWDST, &new_dst));
                attrs.extend(Self::build_rta_via(*next_hop));
                if *if_index != 0 {
                    attrs.extend(Self::build_rta_attribute(RTA_OIF, &if_index.to_ne_bytes()));
                }
            }
        }

        // Pad to 4-byte alignment.
        while attrs.len() % 4 != 0 {
            attrs.push(0);
        }

        let total_len = 16 + 12 + attrs.len();
        let aligned = (total_len + 3) & !3;
        let mut buf = vec![0u8; aligned];
        // nlmsghdr (16 bytes):
        buf[0..4].copy_from_slice(&(total_len as u32).to_ne_bytes());
        buf[4..6].copy_from_slice(&msg_type.to_ne_bytes());
        buf[6..8].copy_from_slice(&flags.to_ne_bytes());
        let seq = self.next_seq();
        buf[8..12].copy_from_slice(&seq.to_ne_bytes());
        buf[12..16].copy_from_slice(&self.pid.to_ne_bytes());
        // rtmsg (12 bytes):
        buf[16] = AF_MPLS; // rtm_family
        buf[17] = MPLS_LABEL_LEN; // rtm_dst_len
        buf[18] = 0; // rtm_src_len
        buf[19] = 0; // rtm_tos
        buf[20] = 254; // RT_TABLE_MAIN
        buf[21] = 4; // RTPROT_STATIC — MPLS routes are admin-configured
        buf[22] = 0; // RT_SCOPE_UNIVERSE
        buf[23] = 1; // RTN_UNICAST
        buf[24..28].copy_from_slice(&0u32.to_ne_bytes()); // rtm_flags
        buf[28..28 + attrs.len()].copy_from_slice(&attrs);
        Ok(buf)
    }

    /// Build a `RTA_VIA` attribute: `<family:2> <addr:4 or 16>`. The
    /// family is the kernel's `struct rtvia { __kernel_sa_family_t
    /// rtvia_family; __u8 rtvia_addr[]; }` — a 2-byte `sa_family_t`,
    /// encoded in network byte order (AF_INET=2, AF_INET6=10), followed
    /// by the raw address bytes (6 bytes total for IPv4, 18 for IPv6).
    fn build_rta_via(next_hop: IpAddr) -> Vec<u8> {
        let (family, addr) = match next_hop {
            IpAddr::V4(b) => (AF_INET, b.to_vec()),
            IpAddr::V6(b) => (AF_INET6, b.to_vec()),
        };
        let mut data = Vec::with_capacity(2 + addr.len());
        data.extend_from_slice(&family.to_be_bytes());
        data.extend_from_slice(&addr);
        Self::build_rta_attribute(RTA_VIA, &data)
    }

    /// Build a single RTA attribute: `<rta_len:2> <rta_type:2> <data:N>`,
    /// padded to 4-byte alignment.
    fn build_rta_attribute(rta_type: u16, data: &[u8]) -> Vec<u8> {
        let rta_len = (4 + data.len()) as u16;
        let aligned = (rta_len as usize + 3) & !3;
        let mut buf = vec![0u8; aligned];
        buf[0..2].copy_from_slice(&rta_len.to_ne_bytes());
        buf[2..4].copy_from_slice(&rta_type.to_ne_bytes());
        buf[4..4 + data.len()].copy_from_slice(data);
        buf
    }

    /// Install an MPLS route. Replaces any existing route for the same
    /// in-label.
    pub fn add_route(&mut self, route: &MplsRoute) -> Result<(), MplsRouteError> {
        let buf = self.build_request(RTM_NEWROUTE, ADD_ROUTE_FLAGS, route)?;
        let resp = self.sendmsg_and_recv(&buf)?;
        check_ack(&resp)
    }

    /// Delete the MPLS route keyed by `in_label`.
    pub fn delete_route(&mut self, in_label: Label) -> Result<(), MplsRouteError> {
        let placeholder = MplsRoute {
            in_label,
            action: MplsRouteAction::Pop {
                next_hop: IpAddr::V4([0, 0, 0, 0]),
                if_index: 0,
            },
        };
        let buf = self.build_request(RTM_DELROUTE, NLM_F_REQUEST | NLM_F_ACK, &placeholder)?;
        let resp = self.sendmsg_and_recv(&buf)?;
        check_ack(&resp)
    }
}

impl Drop for MplsNetlink {
    fn drop(&mut self) {
        unsafe { libc_close(self.fd) };
    }
}

fn check_ack(resp: &[u8]) -> Result<(), MplsRouteError> {
    if resp.len() < 20 {
        return Err(MplsRouteError::Kernel(format!(
            "short ack response (len={})",
            resp.len()
        )));
    }
    let nlmsg_type = u16::from_ne_bytes([resp[4], resp[5]]);
    if nlmsg_type != NLMSG_ERROR {
        return Err(MplsRouteError::Kernel(format!(
            "unexpected response type {}",
            nlmsg_type
        )));
    }
    let err = i32::from_ne_bytes([resp[16], resp[17], resp[18], resp[19]]);
    if err != 0 {
        return Err(MplsRouteError::Kernel(format!(
            "netlink error {} ({})",
            err,
            errno_str(err)
        )));
    }
    Ok(())
}

fn errno_str(err: i32) -> &'static str {
    match err {
        -1 => "EPERM (insufficient privileges)",
        -2 => "ENOENT (no such label)",
        -17 => "EEXIST (label already installed)",
        -22 => "EINVAL (malformed request)",
        -95 => "EOPNOTSUPP (MPLS not supported)",
        _ => "unknown error",
    }
}

// ===== FFI shims (mirror the `linux` module's libc-free approach) =====

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
    fn getsockname(fd: i32, addr: *mut core::ffi::c_void, len: *mut u32) -> i32;
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
unsafe fn libc_getsockname(fd: i32, addr: *mut core::ffi::c_void, len: *mut u32) -> i32 {
    getsockname(fd, addr, len)
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

#[cfg(test)]
mod tests {
    use super::*;

    /// A `MplsNetlink` with no live socket — enough to exercise
    /// `build_request`, which only touches `seq`/`pid` (never `fd`).
    fn test_netlink() -> MplsNetlink {
        MplsNetlink {
            fd: -1,
            seq: AtomicU32::new(7),
            pid: 123,
        }
    }

    /// Walk the RTA attributes of a built request (they start at offset 28)
    /// and return the payload of the one with type `want`, if present.
    fn find_attr(req: &[u8], want: u16) -> Option<&[u8]> {
        let msg_len = u32::from_ne_bytes(req[0..4].try_into().unwrap()) as usize;
        let mut cursor = 28;
        while cursor + 4 <= msg_len.min(req.len()) {
            let rta_len = u16::from_ne_bytes([req[cursor], req[cursor + 1]]) as usize;
            if rta_len < 4 || cursor + rta_len > req.len() {
                return None;
            }
            let rta_type = u16::from_ne_bytes([req[cursor + 2], req[cursor + 3]]);
            if rta_type == want {
                return Some(&req[cursor + 4..cursor + rta_len]);
            }
            cursor += (rta_len + 3) & !3;
        }
        None
    }

    #[test]
    fn platform_labels_reads_without_panic() {
        // In CI without mpls_router loaded this returns 0; in a
        // privileged lab it returns 16 or 20. Either way it must not
        // panic.
        let _ = mpls_platform_labels();
    }

    #[test]
    fn connect_returns_not_enabled_when_sysctl_is_zero() {
        // Skip when MPLS is actually enabled (lab/CI with mpls_router).
        if mpls_enabled() {
            return;
        }
        match MplsNetlink::connect() {
            Err(MplsRouteError::NotEnabled) => { /* expected */ }
            other => panic!("expected NotEnabled, got {:?}", other),
        }
    }

    /// The kernel `struct rtvia` has a 2-byte `sa_family_t` — the RTA_VIA
    /// payload must be `<family:2 BE> <addr>`, not `<family:1> <addr>`.
    #[test]
    fn build_rta_via_ipv4_layout() {
        let via = MplsNetlink::build_rta_via(IpAddr::V4([192, 0, 2, 1]));
        // rta_len (2) + rta_type (2) + family (2) + addr (4) = 10, padded to 12
        assert_eq!(via.len(), 12);
        assert_eq!(u16::from_ne_bytes([via[0], via[1]]), 10);
        assert_eq!(u16::from_ne_bytes([via[2], via[3]]), RTA_VIA);
        // family is a 2-byte sa_family_t in network byte order
        assert_eq!(u16::from_be_bytes([via[4], via[5]]), AF_INET);
        assert_eq!(&via[6..10], &[192, 0, 2, 1]);
    }

    #[test]
    fn build_rta_via_ipv6_layout() {
        let addr = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let via = MplsNetlink::build_rta_via(IpAddr::V6(addr));
        // rta_len (2) + rta_type (2) + family (2) + addr (16) = 22, padded to 24
        assert_eq!(via.len(), 24);
        assert_eq!(u16::from_ne_bytes([via[0], via[1]]), 22);
        assert_eq!(u16::from_ne_bytes([via[2], via[3]]), RTA_VIA);
        assert_eq!(u16::from_be_bytes([via[4], via[5]]), AF_INET6);
        assert_eq!(&via[6..22], &addr);
    }

    /// `build_request` for a Pop action: RTA_DST in-label, RTA_VIA with a
    /// 2-byte family, RTA_OIF. Exercises the full request encoder, not a
    /// hand-mirrored layout.
    #[test]
    fn build_request_pop_route_encodes_via() {
        let nl = test_netlink();
        let route = MplsRoute::pop(Label::new(100), IpAddr::V4([192, 0, 2, 1]), 2);
        let req = nl
            .build_request(RTM_NEWROUTE, NLM_F_REQUEST | NLM_F_ACK, &route)
            .unwrap();
        // nlmsghdr + rtmsg fields.
        assert_eq!(req[16], AF_MPLS); // rtm_family
        assert_eq!(req[17], MPLS_LABEL_LEN); // rtm_dst_len
                                             // RTA_DST: 4-octet in-label (kernel `nla_get_labels` shifts >> 12).
        let dst = find_attr(&req, RTA_DST).expect("RTA_DST");
        assert_eq!(dst.len(), 4);
        assert_eq!(u32::from_be_bytes(dst.try_into().unwrap()) >> 12, 100);
        // RTA_VIA: 2-byte BE family + 4 address bytes.
        let via = find_attr(&req, RTA_VIA).expect("RTA_VIA");
        assert_eq!(via.len(), 6);
        assert_eq!(u16::from_be_bytes([via[0], via[1]]), AF_INET);
        assert_eq!(&via[2..6], &[192, 0, 2, 1]);
        // RTA_OIF present.
        assert_eq!(find_attr(&req, RTA_OIF).expect("RTA_OIF").len(), 4);
    }

    /// `build_request` for a Swap action: RTA_NEWDST carries the new stack
    /// and RTA_VIA the gateway.
    #[test]
    fn build_request_swap_route_encodes_newdst_and_via() {
        let nl = test_netlink();
        let route = MplsRoute::swap(
            Label::new(100),
            LabelStack::from_values([200]),
            IpAddr::V6([0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]),
            3,
        );
        let req = nl
            .build_request(RTM_NEWROUTE, NLM_F_REQUEST | NLM_F_ACK, &route)
            .unwrap();
        let new_dst = find_attr(&req, RTA_NEWDST).expect("RTA_NEWDST");
        assert_eq!(new_dst.len(), 4);
        assert_eq!(u32::from_be_bytes(new_dst.try_into().unwrap()) >> 12, 200);
        let via = find_attr(&req, RTA_VIA).expect("RTA_VIA");
        assert_eq!(via.len(), 18);
        assert_eq!(u16::from_be_bytes([via[0], via[1]]), AF_INET6);
    }

    #[test]
    fn build_request_swap_route_rejects_empty_stack() {
        let nl = test_netlink();
        let route = MplsRoute::swap(
            Label::new(100),
            LabelStack::new(),
            IpAddr::V4([192, 0, 2, 1]),
            2,
        );
        match nl.build_request(RTM_NEWROUTE, NLM_F_REQUEST | NLM_F_ACK, &route) {
            Err(MplsRouteError::EmptyLabelStack) => { /* expected */ }
            other => panic!("expected EmptyLabelStack, got {:?}", other),
        }
    }

    /// `add_route` must carry NLM_F_REPLACE — the kernel's
    /// `mpls_route_add()` returns -EEXIST for an existing in-label
    /// without it, contradicting the "replaces any existing route" doc.
    #[test]
    fn add_route_flags_include_replace() {
        assert_ne!(ADD_ROUTE_FLAGS & NLM_F_REQUEST, 0);
        assert_ne!(ADD_ROUTE_FLAGS & NLM_F_ACK, 0);
        assert_ne!(ADD_ROUTE_FLAGS & NLM_F_CREATE, 0);
        assert_ne!(ADD_ROUTE_FLAGS & NLM_F_REPLACE, 0);
    }
}
