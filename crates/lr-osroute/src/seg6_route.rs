//! Linux SRv6 route tables — `seg6` (encap) and `seg6local` (endpoint)
//! netlink.
//!
//! Linux exposes SRv6 through two lwtunnel encap types, both riding on
//! `RTM_NEWROUTE`/`RTM_DELROUTE` over `NETLINK_ROUTE`:
//!
//! - **`seg6`** (lwtunnel encap type 5, `LWTUNNEL_ENCAP_SEG6`): an IPv6
//!   route whose packets get an outer IPv6 header + SRH pushed at the
//!   head-end. The `ip route add <prefix> encap seg6 mode encap segs
//!   <SID,...> dev <oif>` form. The encap attribute carries a single
//!   `SEG6_IPTUNNEL_SRH` (type 1) sub-attribute whose payload is the
//!   binary SRH (RFC 8754 §2 wire format, `struct
//!   seg6_iptunnel_encap` in `uapi/linux/seg6_iptunnel.h`).
//!
//! - **`seg6local`** (lwtunnel encap type 6,
//!   `LWTUNNEL_ENCAP_SEG6_LOCAL`): the endpoint table — what a node
//!   does when a packet's destination address equals a locally-owned
//!   SID. The `ip route add <SID> encap seg6local action End` form.
//!   The encap attribute carries a `SEG6LOCAL_ACTION` (type 1)
//!   sub-attribute whose payload is `struct seg6_local_arg` (a u32
//!   action + a list of (u16 param, nla) pairs).
//!
//! ## Capability detection
//!
//! The kernel gates SRv6 on `CONFIG_IPV6_SEG6_LWTUNNEL` and the per-
//! interface `seg6_enabled` sysctl (`/proc/sys/net/conf/<iface>/
//! seg6_enabled`). The crate exposes [`seg6_enabled`] for the global
//! check — operators should set `net.ipv6.conf.all.seg6_enabled=1`
//! before installing routes. The `seg6local` table additionally
//! requires `CONFIG_IPV6_SEG6_LWTUNNEL` (built into most distribution
//! kernels since 4.14).
//!
//! ## References
//!
//! - Linux `uapi/linux/seg6.h`, `uapi/linux/seg6_iptunnel.h`,
//!   `uapi/linux/seg6_local.h`, `uapi/linux/lwtunnel.h`.
//! - `net/ipv6/seg6_iptunnel.c`, `net/ipv6/seg6_local.c`.
//! - `Documentation/networking/seg6-sysctl.rst`.
//! - RFC 8754 §2 (SRH wire format), RFC 8986 §4 (behaviors).

use std::fs;
use std::os::unix::io::RawFd;
use std::sync::atomic::{AtomicU32, Ordering};

use lr_core::addr::IpAddr;
use lr_srv6::{Behavior, Sid, Srh};

// Netlink message types (uapi/linux/netlink.h).
#[allow(dead_code)]
const NLMSG_NOOP: u16 = 0x1;
const NLMSG_ERROR: u16 = 0x2;
#[allow(dead_code)]
const NLMSG_DONE: u16 = 0x3;

// rtnetlink message types (uapi/linux/rtnetlink.h).
const RTM_NEWROUTE: u16 = 24;
const RTM_DELROUTE: u16 = 25;

// rtnetlink RTA types (uapi/linux/rtnetlink.h).
const RTA_DST: u16 = 1;
const RTA_OIF: u16 = 4;
const RTA_ENCAP_TYPE: u16 = 21;
const RTA_ENCAP: u16 = 22;
#[allow(dead_code)]
const RTA_TABLE: u16 = 15;

// Address families.
const AF_INET6: u16 = 10;

// rtmsg fields.
const RTN_UNICAST: u8 = 1;
const RT_TABLE_MAIN: u8 = 254;
const RT_TABLE_LOCAL: u8 = 255;
const RTPROT_BGP: u8 = 186;

// Lightweight-tunnel encap (uapi/linux/lwtunnel.h, seg6_iptunnel.h,
// seg6_local.h).
const LWTUNNEL_ENCAP_SEG6: u32 = 5;
const LWTUNNEL_ENCAP_SEG6_LOCAL: u32 = 6;
const SEG6_IPTUNNEL_SRH: u16 = 1;
const SEG6LOCAL_ACTION: u16 = 1;

// seg6_iptunnel encap modes (uapi/linux/seg6_iptunnel.h).
const SEG6_IPTUN_MODE_INLINE: u32 = 0;
const SEG6_IPTUN_MODE_ENCAP: u32 = 1;

// seg6_local action param types (uapi/linux/seg6_local.h).
const SEG6_LOCAL_NH4: u16 = 2;
const SEG6_LOCAL_NH6: u16 = 3;
const SEG6_LOCAL_IIF: u16 = 4;
const SEG6_LOCAL_OIF: u16 = 5;
const SEG6_LOCAL_TABLE: u16 = 6;

// Netlink flags.
const NLM_F_REQUEST: u16 = 0x01;
const NLM_F_ACK: u16 = 0x04;
const NLM_F_REPLACE: u16 = 0x100;
const NLM_F_CREATE: u16 = 0x400;

/// Flags for route installation: CREATE + REPLACE so that installing
/// over an existing entry *replaces* it (mirrors `mpls_route`).
const ADD_ROUTE_FLAGS: u16 = NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_REPLACE;

// Netlink socket constants.
const NETLINK_ROUTE: i32 = 0;
const AF_NETLINK: i32 = 16;
const SOCK_RAW: i32 = 3;

/// Error returned by SRv6 netlink operations.
#[derive(Debug, Clone)]
pub enum Seg6RouteError {
    /// The platform does not implement SRv6 (non-Linux builds).
    Unsupported,
    /// SRv6 is not enabled in the kernel — set
    /// `/proc/sys/net/conf/all/seg6_enabled` to 1.
    NotEnabled,
    /// A netlink syscall failed.
    Syscall(String),
    /// The kernel rejected the request (e.g. SID already installed).
    Kernel(String),
    /// The SRH encode failed (RFC 8754 §2 validation: empty segment
    /// list, reserved flag bits, out-of-range segments_left, etc.).
    BadSrh(String),
}

impl std::fmt::Display for Seg6RouteError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unsupported => f.write_str("SRv6 is not supported on this platform"),
            Self::NotEnabled => {
                f.write_str("SRv6 is not enabled (set net.ipv6.conf.all.seg6_enabled=1)")
            }
            Self::Syscall(s) => write!(f, "seg6 netlink syscall: {}", s),
            Self::Kernel(s) => write!(f, "seg6 kernel error: {}", s),
            Self::BadSrh(s) => write!(f, "bad SRH: {}", s),
        }
    }
}

impl std::error::Error for Seg6RouteError {}

impl From<std::io::Error> for Seg6RouteError {
    fn from(e: std::io::Error) -> Self {
        Self::Syscall(e.to_string())
    }
}

impl From<lr_srv6::SrhError> for Seg6RouteError {
    fn from(e: lr_srv6::SrhError) -> Self {
        Self::BadSrh(e.to_string())
    }
}

/// The encap mode for `seg6` routes (uapi/linux/seg6_iptunnel.h).
///
/// - `Inline` (`SEG6_IPTUN_MODE_INLINE`): insert the SRH into the
///   existing IPv6 packet without adding an outer header. The
///   destination address is set to the first segment.
/// - `Encap` (`SEG6_IPTUN_MODE_ENCAP`): wrap the original packet in
///   an outer IPv6 header carrying the SRH. This is the default for
///   tunneled traffic.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Seg6EncapMode {
    Inline,
    Encap,
}

impl Seg6EncapMode {
    const fn wire_value(self) -> u32 {
        match self {
            Self::Inline => SEG6_IPTUN_MODE_INLINE,
            Self::Encap => SEG6_IPTUN_MODE_ENCAP,
        }
    }
}

/// A `seg6` encap route: "to reach `prefix`, push an SRH onto the
/// packet". The route is installed into the main routing table.
///
/// Wire shape: an ordinary IPv6 `RTM_NEWROUTE` with
/// `RTA_ENCAP_TYPE = LWTUNNEL_ENCAP_SEG6` and a nested `RTA_ENCAP`
/// carrying `SEG6_IPTUNNEL_SRH`. The `SEG6_IPTUNNEL_SRH` payload is
/// `struct seg6_iptunnel_encap` (a u32 mode + the SRH bytes — see
/// `uapi/linux/seg6_iptunnel.h`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Seg6Route {
    /// The IPv6 prefix this route applies to (RFC 4271 §5.1.1 — the
    /// destination of the inner packet).
    pub prefix: lr_core::addr::Prefix,
    /// The SRH to push. RFC 8754 §2 wire format.
    pub srh: Srh,
    /// Inline (insert SRH) vs Encap (outer IPv6 + SRH). Default is
    /// `Encap` — that matches `ip route add ... encap seg6 mode
    /// encap ...` and is what most operators want.
    pub mode: Seg6EncapMode,
    /// Output interface index (0 to let the kernel resolve via the
    /// gateway).
    pub if_index: u32,
}

impl Seg6Route {
    /// Build a `seg6` encap route with the given SRH and default mode
    /// `Encap`.
    pub fn new(prefix: lr_core::addr::Prefix, srh: Srh) -> Self {
        Self {
            prefix,
            srh,
            mode: Seg6EncapMode::Encap,
            if_index: 0,
        }
    }

    /// Set the encap mode. Builder-style.
    #[must_use]
    pub fn with_mode(mut self, mode: Seg6EncapMode) -> Self {
        self.mode = mode;
        self
    }

    /// Set the output interface index. Builder-style.
    #[must_use]
    pub fn with_if_index(mut self, if_index: u32) -> Self {
        self.if_index = if_index;
        self
    }
}

/// A `seg6local` route: "when a packet's destination equals `sid`,
/// execute `behavior`". The route is installed into the local table
/// (RT_TABLE_LOCAL) — the kernel matches it against the IPv6
/// destination and runs the SID behavior.
///
/// Wire shape: an IPv6 `RTM_NEWROUTE` with `RTA_ENCAP_TYPE =
/// LWTUNNEL_ENCAP_SEG6_LOCAL` and a nested `RTA_ENCAP` carrying
/// `SEG6LOCAL_ACTION`. The action payload is a u32 action code
/// followed by zero or more (param type, param value) pairs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Seg6LocalRoute {
    /// The SID this endpoint matches (RFC 8754 §3 — becomes the IPv6
    /// destination address, /128).
    pub sid: Sid,
    /// The behavior the kernel runs when the SID is hit (RFC 8986 §4).
    pub behavior: Behavior,
    /// Optional next-hop IPv4 address (for End.DX4 / End.X.PS, etc.).
    pub nh4: Option<[u8; 4]>,
    /// Optional next-hop IPv6 address (for End.DX6 / End.X, etc.).
    pub nh6: Option<[u8; 16]>,
    /// Optional input interface index (for End.DX2 etc.).
    pub iif: Option<u32>,
    /// Optional output interface index (for End.X, End.DX2, etc.).
    pub oif: Option<u32>,
    /// Optional table ID (for End.DT4 / End.DT6 / End.DT46, etc.).
    pub table: Option<u32>,
}

impl Seg6LocalRoute {
    /// Build a `seg6local` route with no extra parameters. The kernel
    /// rejects behaviors that require parameters (End.DX6 needs NH6,
    /// End.DT6 needs TABLE, etc.) — the caller adds them via the
    /// builder methods.
    pub fn new(sid: Sid, behavior: Behavior) -> Self {
        Self {
            sid,
            behavior,
            nh4: None,
            nh6: None,
            iif: None,
            oif: None,
            table: None,
        }
    }

    /// Set the IPv4 next-hop. Builder-style.
    #[must_use]
    pub fn with_nh4(mut self, nh4: [u8; 4]) -> Self {
        self.nh4 = Some(nh4);
        self
    }

    /// Set the IPv6 next-hop. Builder-style.
    #[must_use]
    pub fn with_nh6(mut self, nh6: [u8; 16]) -> Self {
        self.nh6 = Some(nh6);
        self
    }

    /// Set the input interface index. Builder-style.
    #[must_use]
    pub fn with_iif(mut self, iif: u32) -> Self {
        self.iif = Some(iif);
        self
    }

    /// Set the output interface index. Builder-style.
    #[must_use]
    pub fn with_oif(mut self, oif: u32) -> Self {
        self.oif = Some(oif);
        self
    }

    /// Set the routing table ID. Builder-style.
    #[must_use]
    pub fn with_table(mut self, table: u32) -> Self {
        self.table = Some(table);
        self
    }
}

/// True when the kernel has SRv6 enabled. Reads
/// `/proc/sys/net/ipv6/conf/all/seg6_enabled` (Linux 4.10+). Returns
/// `false` on non-Linux platforms.
pub fn seg6_enabled() -> bool {
    fs::read_to_string("/proc/sys/net/ipv6/conf/all/seg6_enabled")
        .ok()
        .and_then(|s| s.trim().parse::<u32>().ok())
        .map(|v| v != 0)
        .unwrap_or(false)
}

/// `NETLINK_ROUTE` backend for SRv6 route installation.
#[derive(Debug)]
pub struct Seg6Netlink {
    fd: RawFd,
    seq: AtomicU32,
    pid: u32,
}

impl Seg6Netlink {
    /// Open a `NETLINK_ROUTE` socket. Returns
    /// [`Seg6RouteError::NotEnabled`] when SRv6 is not enabled in the
    /// kernel — callers should check [`seg6_enabled`] first.
    pub fn connect() -> Result<Self, Seg6RouteError> {
        if !seg6_enabled() {
            return Err(Seg6RouteError::NotEnabled);
        }
        let fd = unsafe { libc_socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE) };
        if fd < 0 {
            return Err(Seg6RouteError::Syscall(format!(
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
            return Err(Seg6RouteError::Syscall(format!("bind(AF_NETLINK): {}", e)));
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
            return Err(Seg6RouteError::Syscall(format!("getsockname: {}", e)));
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

    fn sendmsg_and_recv(&self, buf: &[u8]) -> Result<Vec<u8>, Seg6RouteError> {
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
            return Err(Seg6RouteError::Syscall(format!(
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
            return Err(Seg6RouteError::Syscall(format!(
                "recv: {}",
                std::io::Error::last_os_error()
            )));
        }
        out.truncate(n as usize);
        Ok(out)
    }

    /// Install a `seg6` encap route (the LSP head-end: push an SRH on
    /// packets matching `prefix`).
    pub fn add_seg6_route(&mut self, route: &Seg6Route) -> Result<(), Seg6RouteError> {
        let buf = self.build_seg6_request(RTM_NEWROUTE, ADD_ROUTE_FLAGS, route)?;
        let resp = self.sendmsg_and_recv(&buf)?;
        check_ack(&resp)
    }

    /// Delete a `seg6` encap route.
    pub fn delete_seg6_route(
        &mut self,
        prefix: lr_core::addr::Prefix,
    ) -> Result<(), Seg6RouteError> {
        let route = Seg6Route::new(prefix, Srh::new(vec![Sid::UNSPECIFIED])?);
        let buf = self.build_seg6_request(RTM_DELROUTE, NLM_F_REQUEST | NLM_F_ACK, &route)?;
        let resp = self.sendmsg_and_recv(&buf)?;
        check_ack(&resp)
    }

    /// Install a `seg6local` endpoint route (the LSP tail-end: run
    /// `behavior` when a packet arrives addressed to `sid`).
    pub fn add_seg6local_route(&mut self, route: &Seg6LocalRoute) -> Result<(), Seg6RouteError> {
        let buf = self.build_seg6local_request(RTM_NEWROUTE, ADD_ROUTE_FLAGS, route)?;
        let resp = self.sendmsg_and_recv(&buf)?;
        check_ack(&resp)
    }

    /// Delete a `seg6local` endpoint route.
    pub fn delete_seg6local_route(&mut self, sid: Sid) -> Result<(), Seg6RouteError> {
        let route = Seg6LocalRoute::new(sid, Behavior::EndUn);
        let buf = self.build_seg6local_request(RTM_DELROUTE, NLM_F_REQUEST | NLM_F_ACK, &route)?;
        let resp = self.sendmsg_and_recv(&buf)?;
        check_ack(&resp)
    }

    /// Build the rtnetlink request body for a `seg6` encap route
    /// operation. The wire shape is:
    ///
    /// ```text
    /// RTM_NEWROUTE / RTM_DELROUTE
    ///   rtm_family = AF_INET6
    ///   rtm_dst_len = prefix.prefix_len
    ///   rtm_table  = RT_TABLE_MAIN
    ///   RTA_DST = prefix.addr (16 bytes)
    ///   RTA_OIF  = if_index (optional, 4 bytes)
    ///   RTA_ENCAP_TYPE = LWTUNNEL_ENCAP_SEG6 (5)
    ///   RTA_ENCAP = nested {
    ///     SEG6_IPTUNNEL_SRH (type 1) = <u32 mode> + <SRH bytes>
    ///   }
    /// ```
    fn build_seg6_request(
        &self,
        msg_type: u16,
        flags: u16,
        route: &Seg6Route,
    ) -> Result<Vec<u8>, Seg6RouteError> {
        let addr = match route.prefix.addr {
            IpAddr::V4(_) => {
                return Err(Seg6RouteError::BadSrh(
                    "seg6 encap routes require an IPv6 prefix".into(),
                ));
            }
            IpAddr::V6(b) => b.to_vec(),
        };
        let srh_bytes = route.srh.encode_vec()?;
        let mut srh_attr_payload = Vec::with_capacity(4 + srh_bytes.len());
        srh_attr_payload.extend_from_slice(&route.mode.wire_value().to_ne_bytes());
        srh_attr_payload.extend_from_slice(&srh_bytes);

        let mut encap = Vec::new();
        encap.extend(Self::build_rta_attribute(
            SEG6_IPTUNNEL_SRH,
            &srh_attr_payload,
        ));
        while encap.len() % 4 != 0 {
            encap.push(0);
        }

        let mut attrs = Vec::new();
        attrs.extend(Self::build_rta_attribute(RTA_DST, &addr));
        if route.if_index != 0 {
            attrs.extend(Self::build_rta_attribute(
                RTA_OIF,
                &route.if_index.to_ne_bytes(),
            ));
        }
        attrs.extend(Self::build_rta_attribute(
            RTA_ENCAP_TYPE,
            &LWTUNNEL_ENCAP_SEG6.to_ne_bytes(),
        ));
        attrs.extend(Self::build_rta_attribute(RTA_ENCAP, &encap));
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
        buf[16] = AF_INET6 as u8; // rtm_family
        buf[17] = route.prefix.prefix_len; // rtm_dst_len
        buf[18] = 0; // rtm_src_len
        buf[19] = 0; // rtm_tos
        buf[20] = RT_TABLE_MAIN;
        buf[21] = RTPROT_BGP;
        buf[22] = 0; // RT_SCOPE_UNIVERSE
        buf[23] = RTN_UNICAST;
        buf[24..28].copy_from_slice(&0u32.to_ne_bytes()); // rtm_flags
        buf[28..28 + attrs.len()].copy_from_slice(&attrs);
        Ok(buf)
    }

    /// Build the rtnetlink request body for a `seg6local` endpoint
    /// route operation. The wire shape is:
    ///
    /// ```text
    /// RTM_NEWROUTE / RTM_DELROUTE
    ///   rtm_family = AF_INET6
    ///   rtm_dst_len = 128
    ///   rtm_table  = RT_TABLE_LOCAL
    ///   RTA_DST = sid (16 bytes)
    ///   RTA_ENCAP_TYPE = LWTUNNEL_ENCAP_SEG6_LOCAL (6)
    ///   RTA_ENCAP = nested {
    ///     SEG6_LOCAL_ACTION (type 1) = <u32 action code>   (4-byte payload)
    ///     SEG6_LOCAL_NH4   (type 2) = <IPv4 next-hop>      (4-byte payload, optional)
    ///     SEG6_LOCAL_NH6   (type 3) = <IPv6 next-hop>      (16-byte payload, optional)
    ///     SEG6_LOCAL_IIF   (type 4) = <input ifindex>      (4-byte payload, optional)
    ///     SEG6_LOCAL_OIF   (type 5) = <output ifindex>    (4-byte payload, optional)
    ///     SEG6_LOCAL_TABLE (type 6) = <routing table id>  (4-byte payload, optional)
    ///   }
    /// ```
    ///
    /// The kernel's `seg6_local_cmp_lwtunnel` /
    /// `parse_nla_action` walks `RTA_ENCAP` as a list of nested
    /// attributes — the action code is one attribute (with a 4-byte
    /// `u32` payload), each parameter is its own attribute. iproute2
    /// does the same: `addattr32(nlh, RTA_ENCAP, SEG6_LOCAL_ACTION,
    /// action); ...; addattr_l(nlh, RTA_ENCAP, SEG6_LOCAL_OIF, ...)`.
    fn build_seg6local_request(
        &self,
        msg_type: u16,
        flags: u16,
        route: &Seg6LocalRoute,
    ) -> Result<Vec<u8>, Seg6RouteError> {
        let mut encap = Vec::new();
        // SEG6_LOCAL_ACTION: 4-byte u32 action code (the only attribute
        // with a fixed-width payload; everything else is a separate
        // netlink attribute). The behavior's `wire_value()` is a u16
        // because the IANA registry assigns 16-bit values, but the
        // kernel's `struct seg6_local_arg` carries the action as a
        // u32 (uapi/linux/seg6_local.h) — widen here.
        encap.extend(Self::build_rta_attribute(
            SEG6LOCAL_ACTION,
            &(route.behavior.wire_value() as u32).to_ne_bytes(),
        ));
        if let Some(nh4) = route.nh4 {
            encap.extend(Self::build_rta_attribute(SEG6_LOCAL_NH4, &nh4));
        }
        if let Some(nh6) = route.nh6 {
            encap.extend(Self::build_rta_attribute(SEG6_LOCAL_NH6, &nh6));
        }
        if let Some(iif) = route.iif {
            encap.extend(Self::build_rta_attribute(
                SEG6_LOCAL_IIF,
                &iif.to_ne_bytes(),
            ));
        }
        if let Some(oif) = route.oif {
            encap.extend(Self::build_rta_attribute(
                SEG6_LOCAL_OIF,
                &oif.to_ne_bytes(),
            ));
        }
        if let Some(table) = route.table {
            encap.extend(Self::build_rta_attribute(
                SEG6_LOCAL_TABLE,
                &table.to_ne_bytes(),
            ));
        }
        while encap.len() % 4 != 0 {
            encap.push(0);
        }

        let mut attrs = Vec::new();
        attrs.extend(Self::build_rta_attribute(RTA_DST, route.sid.as_bytes()));
        attrs.extend(Self::build_rta_attribute(
            RTA_ENCAP_TYPE,
            &LWTUNNEL_ENCAP_SEG6_LOCAL.to_ne_bytes(),
        ));
        attrs.extend(Self::build_rta_attribute(RTA_ENCAP, &encap));
        while attrs.len() % 4 != 0 {
            attrs.push(0);
        }

        let total_len = 16 + 12 + attrs.len();
        let aligned = (total_len + 3) & !3;
        let mut buf = vec![0u8; aligned];
        buf[0..4].copy_from_slice(&(total_len as u32).to_ne_bytes());
        buf[4..6].copy_from_slice(&msg_type.to_ne_bytes());
        buf[6..8].copy_from_slice(&flags.to_ne_bytes());
        let seq = self.next_seq();
        buf[8..12].copy_from_slice(&seq.to_ne_bytes());
        buf[12..16].copy_from_slice(&self.pid.to_ne_bytes());
        // rtmsg (12 bytes):
        buf[16] = AF_INET6 as u8; // rtm_family
        buf[17] = 128; // rtm_dst_len — /128, a SID is one address
        buf[18] = 0; // rtm_src_len
        buf[19] = 0; // rtm_tos
        buf[20] = RT_TABLE_LOCAL;
        buf[21] = RTPROT_BGP;
        buf[22] = 0; // RT_SCOPE_UNIVERSE
        buf[23] = RTN_UNICAST;
        buf[24..28].copy_from_slice(&0u32.to_ne_bytes()); // rtm_flags
        buf[28..28 + attrs.len()].copy_from_slice(&attrs);
        Ok(buf)
    }

    /// Build a single RTA attribute: `<rta_len:2> <rta_type:2>
    /// <data:N>`, padded to 4-byte alignment.
    fn build_rta_attribute(rta_type: u16, data: &[u8]) -> Vec<u8> {
        let rta_len = (4 + data.len()) as u16;
        let aligned = (rta_len as usize + 3) & !3;
        let mut buf = vec![0u8; aligned];
        buf[0..2].copy_from_slice(&rta_len.to_ne_bytes());
        buf[2..4].copy_from_slice(&rta_type.to_ne_bytes());
        buf[4..4 + data.len()].copy_from_slice(data);
        buf
    }
}

impl Drop for Seg6Netlink {
    fn drop(&mut self) {
        if self.fd >= 0 {
            unsafe {
                libc_close(self.fd);
            }
        }
    }
}

/// Parse the netlink ACK/NAK response. The kernel replies to a
/// `NLM_F_ACK`-flagged request with either a `NLMSG_DONE` (success)
/// or a `NLMSG_ERROR` carrying a non-zero errno (failure). The errno
/// is in host byte order (it's a plain `int`).
fn check_ack(resp: &[u8]) -> Result<(), Seg6RouteError> {
    if resp.len() < 20 {
        return Err(Seg6RouteError::Kernel(format!(
            "short netlink response ({} bytes)",
            resp.len()
        )));
    }
    let msg_type = u16::from_ne_bytes([resp[4], resp[5]]);
    if msg_type == NLMSG_DONE {
        return Ok(());
    }
    if msg_type != NLMSG_ERROR {
        return Err(Seg6RouteError::Kernel(format!(
            "unexpected netlink message type {}",
            msg_type
        )));
    }
    let err = i32::from_ne_bytes([resp[16], resp[17], resp[18], resp[19]]);
    if err == 0 {
        // NLMSG_ERROR with errno=0 is an ACK.
        return Ok(());
    }
    Err(Seg6RouteError::Kernel(format!(
        "netlink error {} ({})",
        err,
        errno_str(err)
    )))
}

fn errno_str(err: i32) -> &'static str {
    match err {
        -1 => "EPERM (insufficient privileges)",
        -2 => "ENOENT (no such entry)",
        -17 => "EEXIST (entry already installed)",
        -22 => "EINVAL (malformed request)",
        -95 => "EOPNOTSUPP (SRv6 not supported)",
        _ => "unknown error",
    }
}

// ===== FFI shims (mirror the `mpls_route` module's libc-free approach) =====

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
    use core::str::FromStr;
    use lr_srv6::Sid;

    /// A `Seg6Netlink` with no live socket — enough to exercise
    /// `build_request`, which only touches `seq`/`pid` (never `fd`).
    fn test_netlink() -> Seg6Netlink {
        Seg6Netlink {
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
        while cursor + 4 <= msg_len {
            let attr_len = u16::from_ne_bytes([req[cursor], req[cursor + 1]]) as usize;
            if attr_len < 4 || cursor + attr_len > msg_len {
                return None;
            }
            let attr_type = u16::from_ne_bytes([req[cursor + 2], req[cursor + 3]]);
            if attr_type == want {
                return Some(&req[cursor + 4..cursor + attr_len]);
            }
            let aligned = (attr_len + 3) & !3;
            cursor += aligned;
        }
        None
    }

    /// Decode a nested RTA_ENCAP payload (a list of inner RTAs) and
    /// return the payload of the inner attribute with type `want`.
    fn find_encap_attr(encap_payload: &[u8], want: u16) -> Option<&[u8]> {
        let mut cursor = 0;
        while cursor + 4 <= encap_payload.len() {
            let attr_len =
                u16::from_ne_bytes([encap_payload[cursor], encap_payload[cursor + 1]]) as usize;
            if attr_len < 4 || cursor + attr_len > encap_payload.len() {
                return None;
            }
            let attr_type =
                u16::from_ne_bytes([encap_payload[cursor + 2], encap_payload[cursor + 3]]);
            if attr_type == want {
                return Some(&encap_payload[cursor + 4..cursor + attr_len]);
            }
            let aligned = (attr_len + 3) & !3;
            cursor += aligned;
        }
        None
    }

    #[test]
    fn seg6_route_build_request_shape() {
        let sid1 = Sid::from_str("fcbb:bb00:0:0:0:0:0:1").unwrap();
        let sid2 = Sid::from_str("fcbb:bb01:0:0:0:0:0:1").unwrap();
        let srh = Srh::new(vec![sid1, sid2]).unwrap();
        let prefix: lr_core::addr::Prefix = "2001:db8:1::/48".parse().unwrap();
        let route = Seg6Route::new(prefix, srh).with_mode(Seg6EncapMode::Encap);
        let req = test_netlink()
            .build_seg6_request(RTM_NEWROUTE, ADD_ROUTE_FLAGS, &route)
            .unwrap();
        // Message type.
        assert_eq!(u16::from_ne_bytes([req[4], req[5]]), RTM_NEWROUTE);
        // Family.
        assert_eq!(req[16], AF_INET6 as u8);
        // Prefix length.
        assert_eq!(req[17], 48);
        // RT_TABLE_MAIN.
        assert_eq!(req[20], RT_TABLE_MAIN);
        // RTA_DST = the prefix's IPv6 address (16 bytes).
        let dst = find_attr(&req, RTA_DST).unwrap();
        assert_eq!(dst.len(), 16);
        assert_eq!(&dst[..8], &[0x20, 0x01, 0x0d, 0xb8, 0, 1, 0, 0]);
        // RTA_ENCAP_TYPE = LWTUNNEL_ENCAP_SEG6 (5).
        let encap_type = find_attr(&req, RTA_ENCAP_TYPE).unwrap();
        assert_eq!(encap_type, &LWTUNNEL_ENCAP_SEG6.to_ne_bytes());
        // RTA_ENCAP is nested, contains SEG6_IPTUNNEL_SRH (type 1).
        let encap = find_attr(&req, RTA_ENCAP).unwrap();
        let srh_attr = find_encap_attr(encap, SEG6_IPTUNNEL_SRH).unwrap();
        // The SRH attribute payload is: 4-byte mode + SRH bytes.
        let mode = u32::from_ne_bytes([srh_attr[0], srh_attr[1], srh_attr[2], srh_attr[3]]);
        assert_eq!(mode, SEG6_IPTUN_MODE_ENCAP);
        // The SRH starts at offset 4 — verify the routing type byte.
        assert_eq!(srh_attr[4 + 2], lr_srv6::SRH_ROUTING_TYPE);
    }

    #[test]
    fn seg6_route_inline_mode_uses_zero_mode_value() {
        let sid1 = Sid::from_str("fcbb:bb00::1").unwrap();
        let srh = Srh::new(vec![sid1]).unwrap();
        let prefix: lr_core::addr::Prefix = "2001:db8:1::/48".parse().unwrap();
        let route = Seg6Route::new(prefix, srh).with_mode(Seg6EncapMode::Inline);
        let req = test_netlink()
            .build_seg6_request(RTM_NEWROUTE, ADD_ROUTE_FLAGS, &route)
            .unwrap();
        let encap = find_attr(&req, RTA_ENCAP).unwrap();
        let srh_attr = find_encap_attr(encap, SEG6_IPTUNNEL_SRH).unwrap();
        let mode = u32::from_ne_bytes([srh_attr[0], srh_attr[1], srh_attr[2], srh_attr[3]]);
        assert_eq!(mode, SEG6_IPTUN_MODE_INLINE);
    }

    #[test]
    fn seg6_route_rejects_ipv4_prefix() {
        let sid1 = Sid::from_str("fcbb:bb00::1").unwrap();
        let srh = Srh::new(vec![sid1]).unwrap();
        let prefix: lr_core::addr::Prefix = "192.0.2.0/24".parse().unwrap();
        let route = Seg6Route::new(prefix, srh);
        let err = test_netlink()
            .build_seg6_request(RTM_NEWROUTE, ADD_ROUTE_FLAGS, &route)
            .unwrap_err();
        assert!(matches!(err, Seg6RouteError::BadSrh(_)));
    }

    #[test]
    fn seg6local_route_build_request_shape() {
        let sid = Sid::from_str("fcbb:bb00:0:0:0:0:0:1").unwrap();
        let route = Seg6LocalRoute::new(sid, Behavior::End).with_oif(2);
        let req = test_netlink()
            .build_seg6local_request(RTM_NEWROUTE, ADD_ROUTE_FLAGS, &route)
            .unwrap();
        // Family / prefix length.
        assert_eq!(req[16], AF_INET6 as u8);
        assert_eq!(req[17], 128, "seg6local SIDs are always /128");
        // RT_TABLE_LOCAL — seg6local routes live in the local table.
        assert_eq!(req[20], RT_TABLE_LOCAL);
        // RTA_DST = the SID's 16 bytes.
        let dst = find_attr(&req, RTA_DST).unwrap();
        assert_eq!(dst.len(), 16);
        assert_eq!(dst, sid.as_bytes());
        // RTA_ENCAP_TYPE = LWTUNNEL_ENCAP_SEG6_LOCAL (6).
        let encap_type = find_attr(&req, RTA_ENCAP_TYPE).unwrap();
        assert_eq!(encap_type, &LWTUNNEL_ENCAP_SEG6_LOCAL.to_ne_bytes());
        // The SEG6_LOCAL_ACTION attribute lives directly inside
        // RTA_ENCAP (not nested inside another attribute), with a
        // 4-byte u32 payload = the behavior's wire value.
        let encap = find_attr(&req, RTA_ENCAP).unwrap();
        let action_attr = find_encap_attr(encap, SEG6LOCAL_ACTION).unwrap();
        assert_eq!(
            action_attr.len(),
            4,
            "SEG6_LOCAL_ACTION payload is a single u32"
        );
        let action = u32::from_ne_bytes([
            action_attr[0],
            action_attr[1],
            action_attr[2],
            action_attr[3],
        ]);
        assert_eq!(action, Behavior::End.wire_value() as u32);
        // The OIF parameter is a sibling attribute inside RTA_ENCAP.
        let oif_attr = find_encap_attr(encap, SEG6_LOCAL_OIF).unwrap();
        assert_eq!(oif_attr.len(), 4);
        let oif = u32::from_ne_bytes([oif_attr[0], oif_attr[1], oif_attr[2], oif_attr[3]]);
        assert_eq!(oif, 2);
    }

    #[test]
    fn seg6local_route_attaches_nh4_for_end_dx4() {
        let sid = Sid::from_str("fcbb:bb00::1").unwrap();
        let nh4 = [192, 0, 2, 1];
        let route = Seg6LocalRoute::new(sid, Behavior::EndDX4).with_nh4(nh4);
        let req = test_netlink()
            .build_seg6local_request(RTM_NEWROUTE, ADD_ROUTE_FLAGS, &route)
            .unwrap();
        let encap = find_attr(&req, RTA_ENCAP).unwrap();
        // SEG6_LOCAL_NH4 is a sibling attribute inside RTA_ENCAP.
        let nh4_attr = find_encap_attr(encap, SEG6_LOCAL_NH4).unwrap();
        assert_eq!(nh4_attr, &nh4);
    }

    #[test]
    fn seg6local_route_attaches_nh6_for_end_dx6() {
        let sid = Sid::from_str("fcbb:bb00::1").unwrap();
        let nh6 = Sid::from_str("2001:db8::1").unwrap().octets();
        let route = Seg6LocalRoute::new(sid, Behavior::EndDX6).with_nh6(nh6);
        let req = test_netlink()
            .build_seg6local_request(RTM_NEWROUTE, ADD_ROUTE_FLAGS, &route)
            .unwrap();
        let encap = find_attr(&req, RTA_ENCAP).unwrap();
        let nh6_attr = find_encap_attr(encap, SEG6_LOCAL_NH6).unwrap();
        assert_eq!(nh6_attr, &nh6);
    }

    #[test]
    fn seg6local_route_attaches_table_for_end_dt6() {
        let sid = Sid::from_str("fcbb:bb00::1").unwrap();
        let route = Seg6LocalRoute::new(sid, Behavior::EndDT6).with_table(100);
        let req = test_netlink()
            .build_seg6local_request(RTM_NEWROUTE, ADD_ROUTE_FLAGS, &route)
            .unwrap();
        let encap = find_attr(&req, RTA_ENCAP).unwrap();
        let table_attr = find_encap_attr(encap, SEG6_LOCAL_TABLE).unwrap();
        let table =
            u32::from_ne_bytes([table_attr[0], table_attr[1], table_attr[2], table_attr[3]]);
        assert_eq!(table, 100);
    }

    #[test]
    fn check_ack_parses_done() {
        // Build a NLMSG_DONE response: nlmsghdr (16) + 4 bytes of zero.
        let mut resp = vec![0u8; 20];
        // nlmsg_len = 20
        resp[0..4].copy_from_slice(&20u32.to_ne_bytes());
        // nlmsg_type = NLMSG_DONE (3)
        resp[4..6].copy_from_slice(&NLMSG_DONE.to_ne_bytes());
        assert!(check_ack(&resp).is_ok());
    }

    #[test]
    fn check_ack_parses_error_zero() {
        // NLMSG_ERROR with errno=0 is an ACK.
        let mut resp = vec![0u8; 20];
        resp[0..4].copy_from_slice(&20u32.to_ne_bytes());
        resp[4..6].copy_from_slice(&NLMSG_ERROR.to_ne_bytes());
        // errno at offset 16: 0
        resp[16..20].copy_from_slice(&0i32.to_ne_bytes());
        assert!(check_ack(&resp).is_ok());
    }

    #[test]
    fn check_ack_returns_error_on_nonzero_errno() {
        let mut resp = vec![0u8; 20];
        resp[0..4].copy_from_slice(&20u32.to_ne_bytes());
        resp[4..6].copy_from_slice(&NLMSG_ERROR.to_ne_bytes());
        resp[16..20].copy_from_slice(&(-1i32).to_ne_bytes());
        let err = check_ack(&resp).unwrap_err();
        match err {
            Seg6RouteError::Kernel(s) => assert!(s.contains("EPERM")),
            other => panic!("expected Kernel error, got {:?}", other),
        }
    }

    #[test]
    fn seg6_route_helpers_are_idempotent() {
        // Build the same route twice — the requests should be byte-
        // identical (modulo the netlink sequence number).
        let sid1 = Sid::from_str("fcbb:bb00::1").unwrap();
        let sid2 = Sid::from_str("fcbb:bb01::1").unwrap();
        let srh = Srh::new(vec![sid1, sid2]).unwrap();
        let prefix: lr_core::addr::Prefix = "2001:db8:1::/48".parse().unwrap();
        let route = Seg6Route::new(prefix, srh);
        let nl = test_netlink();
        let req1 = nl
            .build_seg6_request(RTM_NEWROUTE, ADD_ROUTE_FLAGS, &route)
            .unwrap();
        let req2 = nl
            .build_seg6_request(RTM_NEWROUTE, ADD_ROUTE_FLAGS, &route)
            .unwrap();
        // Same length, same content except for the seq number (bytes 8-12).
        assert_eq!(req1.len(), req2.len());
        assert_eq!(&req1[0..8], &req2[0..8]);
        assert_eq!(&req1[12..], &req2[12..]);
    }
}
