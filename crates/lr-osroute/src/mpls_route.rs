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
//! | Pop  (label → local)    | in-label | —      | —          | ifindex |
//! | Swap (label → label)    | in-label | gw     | new-stack  | ifindex |
//!
//! A Pop route *without* `RTA_VIA` forwards the decapsulated packet to
//! the output device's own link address (`af_mpls.c`: "If via wasn't
//! specified then send out using device address") — on `lo` that is
//! local delivery, the same shape the kernel uses for its reserved
//! explicit-null routes (labels 0/2, `mpls_init_klabels`).
//!
//! `RTA_VIA` is the gateway as a `struct rtvia` payload: 2-byte family
//! (`sa_family_t`, host byte order — the kernel's `nla_put_via` /
//! `nla_get_via` treat it as a plain C assignment with no `ntohs`) +
//! address (6 bytes total for IPv4, 18 for IPv6). `RTA_NEWDST` is the
//! new label stack to push, in
//! the 4-octet-per-entry wire form of RFC 3032 §2.1. Push (IP → label)
//! rides on an ordinary IP route with an MPLS lightweight tunnel —
//! `ip route add <prefix> encap mpls <stack> via ...` — encoded as
//! `RTA_ENCAP_TYPE = LWTUNNEL_ENCAP_MPLS` plus a nested `RTA_ENCAP`
//! carrying `MPLS_IPTUNNEL_DST`; [`MplsNetlink::add_encap_route`]
//! builds that form.
//!
//! Label attributes (`RTA_DST`, `RTA_NEWDST`, `MPLS_IPTUNNEL_DST`) all
//! go through the kernel's `nla_get_labels()`: 4 bytes per entry, the
//! bottom-of-stack bit set on the *last* entry only, TTL and TC clear,
//! and label 3 (implicit null) rejected outright.
//!
//! References: Linux `uapi/linux/mpls.h`, `uapi/linux/mpls_iptunnel.h`,
//! `net/mpls/af_mpls.c`, `net/mpls/mpls_iptunnel.c`,
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
const RTA_GATEWAY: u16 = 5;
const RTA_VIA: u16 = 18;
const RTA_NEWDST: u16 = 19;
const RTA_ENCAP_TYPE: u16 = 21;
const RTA_ENCAP: u16 = 22;

// Address families (2-byte `sa_family_t` in `struct rtvia`).
const AF_INET: u16 = 2;
const AF_INET6: u16 = 10;
const AF_MPLS: u8 = 28;

// rtmsg fields shared by the AF_MPLS and IP-encap request builders
// (values match `linux::RtNetlink`).
const RTN_UNICAST: u8 = 1;
const RT_TABLE_MAIN: u8 = 254;
const RTPROT_BGP: u8 = 186;

// Lightweight-tunnel encap (uapi/linux/lwtunnel.h, mpls_iptunnel.h).
const LWTUNNEL_ENCAP_MPLS: u32 = 1;
const MPLS_IPTUNNEL_DST: u16 = 1;

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
    /// The stack contains label 3 (implicit null) — the kernel's
    /// `nla_get_labels()` rejects it: implicit null never appears in an
    /// encapsulation (RFC 3032 §2.1).
    ImplicitNullLabel,
    /// A Pop route without a `RTA_VIA` gateway needs an output device:
    /// the kernel forwards the decapsulated packet to the device's own
    /// link address, so `RTA_OIF` is mandatory in that shape.
    MissingOutputInterface,
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
            Self::ImplicitNullLabel => {
                f.write_str("implicit null label (3) cannot appear in a label encapsulation")
            }
            Self::MissingOutputInterface => {
                f.write_str("an MPLS pop route without a via gateway requires an output interface")
            }
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
///   to the gateway (`RTA_VIA` + `RTA_OIF`, no `RTA_NEWDST`), or —
///   with `next_hop: None` — to the output device's own link address
///   (local delivery on `lo`; `RTA_OIF` required).
/// - [`MplsRouteAction::Swap`] — replace the top label with a new stack
///   and forward to the gateway. (`RTA_VIA` + `RTA_OIF` + `RTA_NEWDST`.)
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MplsRouteAction {
    Pop {
        next_hop: Option<IpAddr>,
        if_index: u32,
    },
    Swap {
        new_stack: LabelStack,
        next_hop: IpAddr,
        if_index: u32,
    },
}

impl MplsRouteAction {
    pub fn next_hop(&self) -> Option<IpAddr> {
        match self {
            Self::Pop { next_hop, .. } => *next_hop,
            Self::Swap { next_hop, .. } => Some(*next_hop),
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
    /// Convenience: pop-and-forward to a gateway.
    pub fn pop(in_label: Label, next_hop: IpAddr, if_index: u32) -> Self {
        Self {
            in_label,
            action: MplsRouteAction::Pop {
                next_hop: Some(next_hop),
                if_index,
            },
        }
    }

    /// Convenience: pop-and-deliver — no `RTA_VIA`, the kernel forwards
    /// the decapsulated packet to the output device's own link address
    /// (`af_mpls.c`). On `lo` this is local delivery, the tail-side LSP
    /// shape for an egress PE. `if_index` must be non-zero.
    pub fn pop_local(in_label: Label, if_index: u32) -> Self {
        Self {
            in_label,
            action: MplsRouteAction::Pop {
                next_hop: None,
                if_index,
            },
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

/// The kernel's answer to a FIB lookup (`ip route get <addr>` shape):
/// the output interface the traffic leaves on and — when the
/// destination is behind a gateway rather than directly connected —
/// that gateway. MPLS swap programming needs the interface; the
/// gateway distinguishes an on-link LDP peer from a routed one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NexthopInfo {
    pub if_index: u32,
    pub gateway: Option<IpAddr>,
    /// The source address the kernel would pick for this destination.
    pub prefsrc: Option<IpAddr>,
}

/// Parse the kernel's reply to a `resolve_nexthop` FIB lookup: a
/// single `RTM_NEWROUTE` message carrying `RTA_OIF` (and optionally
/// `RTA_GATEWAY` / `RTA_PREFSRC`), or an `NLMSG_ERROR` (e.g.
/// `ENETUNREACH` for no route). Exposed for unit tests.
fn parse_getroute_reply(resp: &[u8], queried: IpAddr) -> Result<NexthopInfo, MplsRouteError> {
    if resp.len() < 16 {
        return Err(MplsRouteError::Syscall(format!(
            "getroute: short reply ({})",
            resp.len()
        )));
    }
    let nlmsg_type = u16::from_ne_bytes([resp[4], resp[5]]);
    if nlmsg_type == NLMSG_ERROR {
        // nlmsgerr: <error:i32> — negative errno on failure.
        let errno = i32::from_ne_bytes([resp[16], resp[17], resp[18], resp[19]]);
        let kind = if errno == 0 { "ack" } else { "error" };
        return Err(MplsRouteError::Syscall(format!(
            "getroute {}: {} (no route to {queried}?)",
            kind,
            std::io::Error::from_raw_os_error(-errno)
        )));
    }
    // Walk the attributes after the 16-byte nlmsghdr + 12-byte rtmsg.
    let mut if_index = 0;
    let mut gateway = None;
    let mut prefsrc = None;
    let mut cursor = 28;
    while cursor + 4 <= resp.len() {
        let rta_len = u16::from_ne_bytes([resp[cursor], resp[cursor + 1]]) as usize;
        let rta_type = u16::from_ne_bytes([resp[cursor + 2], resp[cursor + 3]]);
        if rta_len < 4 || cursor + rta_len > resp.len() {
            break;
        }
        let data = &resp[cursor + 4..cursor + rta_len];
        match rta_type {
            RTA_OIF if data.len() >= 4 => {
                if_index = u32::from_ne_bytes([data[0], data[1], data[2], data[3]]);
            }
            RTA_GATEWAY => match queried {
                IpAddr::V4(_) if data.len() >= 4 => {
                    gateway = Some(IpAddr::V4([data[0], data[1], data[2], data[3]]))
                }
                IpAddr::V6(_) if data.len() >= 16 => {
                    let mut o = [0u8; 16];
                    o.copy_from_slice(&data[..16]);
                    gateway = Some(IpAddr::V6(o));
                }
                _ => {}
            },
            7 if data.len() >= 4 => {
                // RTA_PREFSRC (not named above — lookup replies carry it
                // for directly connected destinations).
                prefsrc = Some(IpAddr::V4([data[0], data[1], data[2], data[3]]));
            }
            _ => {}
        }
        cursor += (rta_len + 3) & !3;
    }
    if if_index == 0 {
        return Err(MplsRouteError::Syscall(format!(
            "getroute: reply carries no output interface ({queried})",
        )));
    }
    Ok(NexthopInfo {
        if_index,
        gateway,
        prefsrc,
    })
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

/// A netlink label attribute carries only the label value and the
/// bottom-of-stack bit: the kernel's `nla_get_labels()` rejects any
/// nonzero TTL ("TTL in label must be 0") or TC ("Traffic class in
/// label must be 0") — netlink is the control plane, the kernel owns
/// the data-plane TTL (it propagates or sets it per route policy).
/// Labels built for the data plane (e.g. `Label::new`, TTL 64) are
/// therefore re-encoded control-plane style here.
fn nl_label_entry(l: Label, bottom: bool) -> [u8; 4] {
    Label {
        value: l.value,
        tc: 0,
        ttl: 0,
    }
    .encode_4octet(bottom)
}

/// Encode a whole stack in the kernel's `nla_get_labels()` form:
/// 4 bytes per entry, bottom-of-stack on the last entry only.
fn nl_label_stack(stack: &LabelStack) -> Vec<u8> {
    let mut out = Vec::with_capacity(stack.len() * 4);
    let last = stack.len().saturating_sub(1);
    for (i, l) in stack.labels().iter().enumerate() {
        out.extend_from_slice(&nl_label_entry(*l, i == last));
    }
    out
}

/// True when the stack carries label 3 anywhere — implicit null never
/// appears in an encapsulation (RFC 3032 §2.1) and the kernel's
/// `nla_get_labels()` rejects the attribute. Compared on the label
/// VALUE: `Label` equality includes the data-plane TTL field, which is
/// irrelevant here.
fn stack_has_implicit_null(stack: &LabelStack) -> bool {
    stack
        .labels()
        .iter()
        .any(|l| l.value == Label::IMPLICIT_NULL.value)
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
        // RTA_DST = 4-byte in-label (top of stack, S=1, TTL/TC clear).
        let in_label_bytes = nl_label_entry(route.in_label, true);
        let mut attrs = Vec::new();
        attrs.extend(Self::build_rta_attribute(RTA_DST, &in_label_bytes));

        match &route.action {
            MplsRouteAction::Pop { next_hop, if_index } => {
                match next_hop {
                    Some(nh) => attrs.extend(Self::build_rta_via(*nh)),
                    // No via: the kernel sends the decapsulated packet to
                    // the output device's own link address, so the device
                    // is mandatory (`mpls_nh_assign_dev` fails without).
                    None if *if_index == 0 => return Err(MplsRouteError::MissingOutputInterface),
                    None => {}
                }
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
                if stack_has_implicit_null(new_stack) {
                    return Err(MplsRouteError::ImplicitNullLabel);
                }
                let new_dst = nl_label_stack(new_stack);
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
        buf[20] = RT_TABLE_MAIN;
        buf[21] = 4; // RTPROT_STATIC — MPLS routes are admin-configured
        buf[22] = 0; // RT_SCOPE_UNIVERSE
        buf[23] = RTN_UNICAST;
        buf[24..28].copy_from_slice(&0u32.to_ne_bytes()); // rtm_flags
        buf[28..28 + attrs.len()].copy_from_slice(&attrs);
        Ok(buf)
    }

    /// Build the rtnetlink request for an IP route with an MPLS push
    /// encapsulation — the LSP head-end (`ip route add <prefix> encap
    /// mpls <stack> via <nh> dev <oif>`).
    ///
    /// Wire shape: an ordinary `AF_INET`/`AF_INET6` `RTM_NEWROUTE` with
    /// `RTA_ENCAP_TYPE = LWTUNNEL_ENCAP_MPLS` and a nested `RTA_ENCAP`
    /// carrying `MPLS_IPTUNNEL_DST` — the label stack in the kernel's
    /// `nla_get_labels()` form (4 bytes per entry, bottom-of-stack on the
    /// last entry, TTL/TC clear, label 3 rejected).
    fn build_encap_request(
        &self,
        msg_type: u16,
        flags: u16,
        prefix: &lr_core::addr::Prefix,
        stack: &LabelStack,
        next_hop: IpAddr,
        if_index: u32,
    ) -> Result<Vec<u8>, MplsRouteError> {
        if stack.is_empty() {
            return Err(MplsRouteError::EmptyLabelStack);
        }
        if stack_has_implicit_null(stack) {
            return Err(MplsRouteError::ImplicitNullLabel);
        }
        let (family, addr) = match prefix.addr {
            IpAddr::V4(b) => (AF_INET, b.to_vec()),
            IpAddr::V6(b) => (AF_INET6, b.to_vec()),
        };
        let mut attrs = Vec::new();
        attrs.extend(Self::build_rta_attribute(RTA_DST, &addr));
        attrs.extend(Self::build_rta_attribute(RTA_GATEWAY, next_hop.octets()));
        // With no explicit output interface the kernel resolves the
        // gateway against the existing table (`ip route add ... via GW`
        // semantics); passing RTA_OIF=0 would be rejected with EINVAL.
        if if_index != 0 {
            attrs.extend(Self::build_rta_attribute(RTA_OIF, &if_index.to_ne_bytes()));
        }
        attrs.extend(Self::build_rta_attribute(
            RTA_ENCAP_TYPE,
            &LWTUNNEL_ENCAP_MPLS.to_ne_bytes(),
        ));
        // RTA_ENCAP is nested: the payload is itself a list of netlink
        // attributes (here a single MPLS_IPTUNNEL_DST label-stack entry).
        let encap = Self::build_rta_attribute(MPLS_IPTUNNEL_DST, &nl_label_stack(stack));
        attrs.extend(Self::build_rta_attribute(RTA_ENCAP, &encap));

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
        buf[16] = family as u8; // rtm_family
        buf[17] = prefix.prefix_len; // rtm_dst_len
        buf[18] = 0; // rtm_src_len
        buf[19] = 0; // rtm_tos
        buf[20] = RT_TABLE_MAIN;
        buf[21] = RTPROT_BGP; // routes mirrored from BGP-LU
        buf[22] = 0; // RT_SCOPE_UNIVERSE
        buf[23] = RTN_UNICAST;
        buf[24..28].copy_from_slice(&0u32.to_ne_bytes()); // rtm_flags
        buf[28..28 + attrs.len()].copy_from_slice(&attrs);
        Ok(buf)
    }

    /// Build a `RTA_VIA` attribute: `<family:2> <addr:4 or 16>`. The
    /// family is the kernel's `struct rtvia { __kernel_sa_family_t
    /// rtvia_family; __u8 rtvia_addr[]; }` — a 2-byte `sa_family_t` in
    /// **host** byte order (AF_INET=2, AF_INET6=10), followed by the raw
    /// address bytes (6 bytes total for IPv4, 18 for IPv6).
    ///
    /// Byte order is host, not network: the kernel writes the family with
    /// a plain C assignment in `nla_put_via()` (`via->rtvia_family =
    /// family`, net/mpls/af_mpls.c) and reads it back with a plain
    /// `switch (via->rtvia_family)` in `nla_get_via()` — no `ntohs()` on
    /// either side. iproute2 does the same when parsing `via inet ...`.
    fn build_rta_via(next_hop: IpAddr) -> Vec<u8> {
        let (family, addr) = match next_hop {
            IpAddr::V4(b) => (AF_INET, b.to_vec()),
            IpAddr::V6(b) => (AF_INET6, b.to_vec()),
        };
        let mut data = Vec::with_capacity(2 + addr.len());
        data.extend_from_slice(&family.to_ne_bytes());
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

    /// Resolve the L3 path toward `addr` with a FIB lookup — the
    /// rtnetlink equivalent of `ip route get <addr>` (RTM_GETROUTE
    /// without NLM_F_DUMP: the kernel answers with the route it would
    /// use, including the output interface and, for routed
    /// destinations, the gateway). MPLS swap actions need the output
    /// interface (`RTA_VIA` without `RTA_OIF` is rejected by
    /// `mpls_build_route`), so a transit LSR resolves it once per next
    /// hop instead of guessing.
    pub fn resolve_nexthop(&mut self, addr: IpAddr) -> Result<NexthopInfo, MplsRouteError> {
        let (family, dst, dst_len) = match addr {
            IpAddr::V4(b) => (AF_INET as u8, b.to_vec(), 32u8),
            IpAddr::V6(b) => (AF_INET6 as u8, b.to_vec(), 128u8),
        };
        let mut attrs = Self::build_rta_attribute(RTA_DST, &dst);
        while attrs.len() % 4 != 0 {
            attrs.push(0);
        }
        let total_len = 16 + 12 + attrs.len();
        let aligned = (total_len + 3) & !3;
        let mut buf = vec![0u8; aligned];
        buf[0..4].copy_from_slice(&(total_len as u32).to_ne_bytes());
        buf[4..6].copy_from_slice(&RTM_GETROUTE.to_ne_bytes());
        buf[6..8].copy_from_slice(&NLM_F_REQUEST.to_ne_bytes());
        let seq = self.next_seq();
        buf[8..12].copy_from_slice(&seq.to_ne_bytes());
        buf[12..16].copy_from_slice(&self.pid.to_ne_bytes());
        buf[16] = family;
        buf[17] = dst_len;
        // rtm_table/protocol/scope/type: zeros are fine for a lookup.
        buf[28..28 + attrs.len()].copy_from_slice(&attrs);
        let resp = self.sendmsg_and_recv(&buf)?;
        parse_getroute_reply(&resp, addr)
    }

    /// Delete the MPLS route keyed by `in_label`.
    pub fn delete_route(&mut self, in_label: Label) -> Result<(), MplsRouteError> {
        let placeholder = MplsRoute {
            in_label,
            action: MplsRouteAction::Pop {
                next_hop: Some(IpAddr::V4([0, 0, 0, 0])),
                if_index: 0,
            },
        };
        let buf = self.build_request(RTM_DELROUTE, NLM_F_REQUEST | NLM_F_ACK, &placeholder)?;
        let resp = self.sendmsg_and_recv(&buf)?;
        check_ack(&resp)
    }

    /// Install the LSP head-end: route `prefix` via `next_hop`, pushing
    /// `stack` — `ip route add <prefix> encap mpls <stack> via <nh>`.
    /// Replaces any existing route for the same prefix (CREATE+REPLACE).
    ///
    /// This is what an LER programs when a labelled BGP route (RFC 8277)
    /// becomes the best route: IP packets toward `prefix` enter the LSP.
    pub fn add_encap_route(
        &mut self,
        prefix: &lr_core::addr::Prefix,
        stack: &LabelStack,
        next_hop: IpAddr,
        if_index: u32,
    ) -> Result<(), MplsRouteError> {
        let buf = self.build_encap_request(
            RTM_NEWROUTE,
            ADD_ROUTE_FLAGS,
            prefix,
            stack,
            next_hop,
            if_index,
        )?;
        let resp = self.sendmsg_and_recv(&buf)?;
        check_ack(&resp)
    }

    /// Delete the IP route (encap or plain) for `prefix`. Deletion keys
    /// on the destination prefix alone — the kernel matches on
    /// `(family, dst_len, dst)` the same way `ip route del <prefix>` does.
    pub fn delete_encap_route(
        &mut self,
        prefix: &lr_core::addr::Prefix,
    ) -> Result<(), MplsRouteError> {
        let (family, addr) = match prefix.addr {
            IpAddr::V4(b) => (AF_INET, b.to_vec()),
            IpAddr::V6(b) => (AF_INET6, b.to_vec()),
        };
        let mut attrs = Vec::new();
        attrs.extend(Self::build_rta_attribute(RTA_DST, &addr));
        while attrs.len() % 4 != 0 {
            attrs.push(0);
        }
        let total_len = 16 + 12 + attrs.len();
        let aligned = (total_len + 3) & !3;
        let mut buf = vec![0u8; aligned];
        buf[0..4].copy_from_slice(&(total_len as u32).to_ne_bytes());
        buf[4..6].copy_from_slice(&RTM_DELROUTE.to_ne_bytes());
        buf[6..8].copy_from_slice(&(NLM_F_REQUEST | NLM_F_ACK).to_ne_bytes());
        let seq = self.next_seq();
        buf[8..12].copy_from_slice(&seq.to_ne_bytes());
        buf[12..16].copy_from_slice(&self.pid.to_ne_bytes());
        buf[16] = family as u8;
        buf[17] = prefix.prefix_len;
        buf[20] = RT_TABLE_MAIN;
        buf[23] = RTN_UNICAST;
        buf[28..28 + attrs.len()].copy_from_slice(&attrs);
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
    /// payload must be `<family:2> <addr>`, not `<family:1> <addr>`. The
    /// family is in HOST byte order (kernel `nla_put_via`/`nla_get_via`
    /// treat it as a plain `sa_family_t`, no `ntohs`), matching how
    /// sockaddr families are read everywhere else in the socket API.
    #[test]
    fn build_rta_via_ipv4_layout() {
        let via = MplsNetlink::build_rta_via(IpAddr::V4([192, 0, 2, 1]));
        // rta_len (2) + rta_type (2) + family (2) + addr (4) = 10, padded to 12
        assert_eq!(via.len(), 12);
        assert_eq!(u16::from_ne_bytes([via[0], via[1]]), 10);
        assert_eq!(u16::from_ne_bytes([via[2], via[3]]), RTA_VIA);
        // family is a 2-byte sa_family_t in host byte order
        assert_eq!(u16::from_ne_bytes([via[4], via[5]]), AF_INET);
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
        assert_eq!(u16::from_ne_bytes([via[4], via[5]]), AF_INET6);
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
        // RTA_VIA: 2-byte host-order family + 4 address bytes.
        let via = find_attr(&req, RTA_VIA).expect("RTA_VIA");
        assert_eq!(via.len(), 6);
        assert_eq!(u16::from_ne_bytes([via[0], via[1]]), AF_INET);
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
        assert_eq!(u16::from_ne_bytes([via[0], via[1]]), AF_INET6);
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

    /// Pop *without* a via gateway (`pop_local`): no RTA_VIA, RTA_OIF
    /// present. The kernel forwards the decapsulated packet to the
    /// output device's own link address — local delivery on `lo`.
    #[test]
    fn build_request_pop_local_route_omits_via() {
        let nl = test_netlink();
        let route = MplsRoute::pop_local(Label::new(100), 1);
        let req = nl
            .build_request(RTM_NEWROUTE, NLM_F_REQUEST | NLM_F_ACK, &route)
            .unwrap();
        assert!(find_attr(&req, RTA_VIA).is_none(), "no RTA_VIA expected");
        let oif = find_attr(&req, RTA_OIF).expect("RTA_OIF");
        assert_eq!(u32::from_ne_bytes(oif.try_into().unwrap()), 1);
    }

    /// The kernel assigns the output device in `mpls_nh_assign_dev` —
    /// with no via and no device there is nothing to assign, so the
    /// request builder must refuse the shape before the syscall.
    #[test]
    fn build_request_pop_local_requires_oif() {
        let nl = test_netlink();
        let route = MplsRoute::pop_local(Label::new(100), 0);
        match nl.build_request(RTM_NEWROUTE, NLM_F_REQUEST | NLM_F_ACK, &route) {
            Err(MplsRouteError::MissingOutputInterface) => { /* expected */ }
            other => panic!("expected MissingOutputInterface, got {:?}", other),
        }
    }

    /// LSP head-end request for an IPv4 prefix: an AF_INET route with
    /// RTA_DST + RTA_GATEWAY + RTA_ENCAP_TYPE=MPLS + a nested RTA_ENCAP
    /// carrying MPLS_IPTUNNEL_DST.
    #[test]
    fn build_encap_request_ipv4_layout() {
        let nl = test_netlink();
        let prefix: lr_core::addr::Prefix = "198.51.100.0/24".parse().unwrap();
        let req = nl
            .build_encap_request(
                RTM_NEWROUTE,
                ADD_ROUTE_FLAGS,
                &prefix,
                &LabelStack::from_values([100]),
                IpAddr::V4([192, 0, 2, 1]),
                0,
            )
            .unwrap();
        assert_eq!(req[16], 2); // rtm_family = AF_INET
        assert_eq!(req[17], 24); // rtm_dst_len
        assert_eq!(req[21], RTPROT_BGP);
        let dst = find_attr(&req, RTA_DST).expect("RTA_DST");
        assert_eq!(dst, &[198, 51, 100, 0]);
        let gw = find_attr(&req, RTA_GATEWAY).expect("RTA_GATEWAY");
        assert_eq!(gw, &[192, 0, 2, 1]);
        assert!(find_attr(&req, RTA_OIF).is_none(), "OIF=0 must be omitted");
        let encap_type = find_attr(&req, RTA_ENCAP_TYPE).expect("RTA_ENCAP_TYPE");
        assert_eq!(
            u32::from_ne_bytes(encap_type.try_into().unwrap()),
            LWTUNNEL_ENCAP_MPLS
        );
        // The nested RTA_ENCAP payload is itself a netlink attribute list:
        // MPLS_IPTUNNEL_DST with the 4-byte label entry.
        let encap = find_attr(&req, RTA_ENCAP).expect("RTA_ENCAP");
        let inner_len = u16::from_ne_bytes([encap[0], encap[1]]) as usize;
        assert_eq!(u16::from_ne_bytes([encap[2], encap[3]]), MPLS_IPTUNNEL_DST);
        let label_entry = &encap[4..inner_len];
        assert_eq!(label_entry.len(), 4);
        let entry = u32::from_be_bytes(label_entry.try_into().unwrap());
        assert_eq!(entry >> 12, 100); // label value
        assert_eq!(entry & 0x100, 0x100); // bottom-of-stack set on the last entry
        assert_eq!(entry & 0xff, 0); // TTL clear
    }

    /// Same shape for IPv6, with a two-label stack: 8 bytes in
    /// MPLS_IPTUNNEL_DST, bottom-of-stack only on the last entry.
    #[test]
    fn build_encap_request_ipv6_multilabel_layout() {
        let nl = test_netlink();
        let prefix: lr_core::addr::Prefix = "2001:db8:1::/48".parse().unwrap();
        let req = nl
            .build_encap_request(
                RTM_NEWROUTE,
                ADD_ROUTE_FLAGS,
                &prefix,
                &LabelStack::from_values([100, 200]),
                IpAddr::V6([0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]),
                0,
            )
            .unwrap();
        assert_eq!(req[16], 10); // rtm_family = AF_INET6
        assert_eq!(req[17], 48); // rtm_dst_len
        let dst = find_attr(&req, RTA_DST).expect("RTA_DST");
        assert_eq!(dst.len(), 16);
        let encap = find_attr(&req, RTA_ENCAP).expect("RTA_ENCAP");
        let inner_len = u16::from_ne_bytes([encap[0], encap[1]]) as usize;
        let label_entry = &encap[4..inner_len];
        assert_eq!(label_entry.len(), 8);
        let first = u32::from_be_bytes(label_entry[0..4].try_into().unwrap());
        let last = u32::from_be_bytes(label_entry[4..8].try_into().unwrap());
        assert_eq!(first >> 12, 100);
        assert_eq!(first & 0x100, 0, "non-bottom label must not carry BOS");
        assert_eq!(last >> 12, 200);
        assert_eq!(last & 0x100, 0x100, "last label must carry BOS");
    }

    /// Label 3 never appears in an encapsulation (kernel `nla_get_labels`
    /// rejects it outright; RFC 3032 §2.1) — fail before the syscall.
    #[test]
    fn build_encap_request_rejects_implicit_null() {
        let nl = test_netlink();
        let prefix: lr_core::addr::Prefix = "198.51.100.0/24".parse().unwrap();
        match nl.build_encap_request(
            RTM_NEWROUTE,
            ADD_ROUTE_FLAGS,
            &prefix,
            &LabelStack::from_values([Label::IMPLICIT_NULL.value]),
            IpAddr::V4([192, 0, 2, 1]),
            0,
        ) {
            Err(MplsRouteError::ImplicitNullLabel) => { /* expected */ }
            other => panic!("expected ImplicitNullLabel, got {:?}", other),
        }
    }

    /// RTA_NEWDST (swap) goes through the same `nla_get_labels()` —
    /// implicit null is rejected there too.
    #[test]
    fn build_request_swap_rejects_implicit_null() {
        let nl = test_netlink();
        let route = MplsRoute::swap(
            Label::new(100),
            LabelStack::from_values([Label::IMPLICIT_NULL.value]),
            IpAddr::V4([192, 0, 2, 1]),
            2,
        );
        match nl.build_request(RTM_NEWROUTE, NLM_F_REQUEST | NLM_F_ACK, &route) {
            Err(MplsRouteError::ImplicitNullLabel) => { /* expected */ }
            other => panic!("expected ImplicitNullLabel, got {:?}", other),
        }
    }

    /// Build a synthetic `RTM_GETROUTE` reply (nlmsghdr + rtmsg +
    /// attributes) the way the kernel answers a FIB lookup.
    fn getroute_reply(attrs: &[(&u16, &[u8])]) -> Vec<u8> {
        let mut body = Vec::new();
        for (t, data) in attrs {
            body.extend(MplsNetlink::build_rta_attribute(**t, data));
        }
        let total_len = 16 + 12 + body.len();
        let mut buf = vec![0u8; total_len];
        buf[0..4].copy_from_slice(&(total_len as u32).to_ne_bytes());
        buf[4..6].copy_from_slice(&RTM_NEWROUTE.to_ne_bytes());
        buf[16] = AF_INET as u8;
        buf[17] = 32;
        buf[28..].copy_from_slice(&body);
        buf
    }

    #[test]
    fn parse_getroute_reply_reads_oif_gateway_prefsrc() {
        let oif = 5u32.to_ne_bytes();
        let gw = [10u8, 0, 0, 1];
        let prefsrc = [192u8, 0, 2, 254];
        let reply = getroute_reply(&[
            (&RTA_OIF, &oif),
            (&RTA_GATEWAY, &gw),
            (&7, &prefsrc), // RTA_PREFSRC
        ]);
        let info = parse_getroute_reply(&reply, IpAddr::V4([10, 0, 0, 9])).unwrap();
        assert_eq!(info.if_index, 5);
        assert_eq!(info.gateway, Some(IpAddr::V4([10, 0, 0, 1])));
        assert_eq!(info.prefsrc, Some(IpAddr::V4([192, 0, 2, 254])));
    }

    #[test]
    fn parse_getroute_reply_directly_connected_has_no_gateway() {
        let oif = 7u32.to_ne_bytes();
        let reply = getroute_reply(&[(&RTA_OIF, &oif)]);
        let info = parse_getroute_reply(&reply, IpAddr::V4([10, 0, 0, 9])).unwrap();
        assert_eq!(info.if_index, 7);
        assert_eq!(info.gateway, None);
    }

    #[test]
    fn parse_getroute_reply_error_message_is_an_error() {
        // NLMSG_ERROR with EINVAL.
        let mut buf = vec![0u8; 28];
        buf[0..4].copy_from_slice(&28u32.to_ne_bytes());
        buf[4..6].copy_from_slice(&NLMSG_ERROR.to_ne_bytes());
        buf[16..20].copy_from_slice(&(-22i32).to_ne_bytes());
        assert!(parse_getroute_reply(&buf, IpAddr::V4([10, 0, 0, 9])).is_err());
    }

    #[test]
    fn parse_getroute_reply_requires_an_oif() {
        let prefsrc = [192u8, 0, 2, 254];
        let reply = getroute_reply(&[(&7, &prefsrc)]);
        assert!(parse_getroute_reply(&reply, IpAddr::V4([10, 0, 0, 9])).is_err());
    }

    #[test]
    fn parse_getroute_reply_handles_v6_gateway() {
        let oif = 3u32.to_ne_bytes();
        let gw: [u8; 16] = core::array::from_fn(|i| i as u8);
        let reply = getroute_reply(&[(&RTA_OIF, &oif), (&RTA_GATEWAY, &gw)]);
        let queried = IpAddr::V6([0x20, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        let info = parse_getroute_reply(&reply, queried).unwrap();
        assert_eq!(info.if_index, 3);
        assert_eq!(info.gateway, Some(IpAddr::V6(gw)));
    }
}
