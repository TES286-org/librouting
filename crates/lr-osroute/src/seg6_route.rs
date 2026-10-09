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
//! - **`seg6local`** (lwtunnel encap type 7,
//!   `LWTUNNEL_ENCAP_SEG6_LOCAL`): the endpoint table — what a node
//!   does when a packet's destination address equals a locally-owned
//!   SID. The `ip route add <SID> encap seg6local action End` form.
//!   The encap attribute carries a `SEG6_LOCAL_ACTION` (type 1)
//!   sub-attribute whose payload is a u32 action code in the
//!   **kernel's** `SEG6_LOCAL_ACTION_*` numbering, followed by the
//!   action's parameters as sibling nested attributes
//!   (`SEG6_LOCAL_NH4`/`NH6`/`IIF`/`OIF`/`TABLE`). The IANA registry
//!   values `lr_srv6::Behavior` carries are a DIFFERENT numbering —
//!   see the translation table in [`kernel_action_for`] — and the
//!   kernel's uapi enum order (UNSPEC, ACTION, SRH, TABLE, NH4, NH6,
//!   IIF, OIF, …) positions the parameter attributes differently
//!   than a doc-order reading suggests.
//!
//! ## Egress device requirement
//!
//! Linux's `fib6_nh_init` (net/ipv6/route.c) refuses every IPv6 route
//! that names neither an egress device (`RTA_OIF`) nor a gateway with
//! `ENODEV` — there is no implicit device pick. `iproute2` commands
//! and FRR (`zclient_send_localsid`, which pins every local SID to a
//! real interface) therefore always carry a device. Callers must do
//! the same: `Seg6Route::with_if_index` /
//! `Seg6LocalRoute::with_if_index`. The loopback index resolves via
//! `ospf_transport::ifindex_of("lo")` (`if_nametoindex`), which is
//! netns-aware for rootless namespace use.
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
/// `NLA_F_NESTED` — the flag bit marking an attribute whose payload
/// is itself a list of attributes. iproute2's `rta_nest()` sets it on
/// `RTA_ENCAP` for every encap route; the kernel's nested parsers
/// read it (strict contexts require it), so the canonical wire form
/// carries it.
const NLA_F_NESTED: u16 = 0x8000;
/// The attribute-type mask: the top two bits of the type field are
/// flags (`NLA_F_NESTED`, `NLA_F_NET_BYTEORDER`), not type bits.
#[allow(dead_code)]
const NLA_TYPE_MASK: u16 = 0x3fff;
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
/// `LWTUNNEL_ENCAP_SEG6_LOCAL` — 7 in the kernel's uapi enum
/// (`NONE, MPLS, IP, ILA, IP6, SEG6, BPF, SEG6_LOCAL, …`). The value
/// 6 in that same position is `LWTUNNEL_ENCAP_BPF`: sending it makes
/// the kernel hand the nested `RTA_ENCAP` payload to the BPF parser,
/// whose `LWT_BPF_IN` (attr 1, the same number as
/// `SEG6_LOCAL_ACTION`) rejects the 4-byte action payload with
/// `EINVAL` — exactly the run-36153545939 failure this constant got
/// wrong for.
const LWTUNNEL_ENCAP_SEG6_LOCAL: u32 = 7;
const SEG6_IPTUNNEL_SRH: u16 = 1;
const SEG6LOCAL_ACTION: u16 = 1;

// seg6_iptunnel encap modes (uapi/linux/seg6_iptunnel.h).
const SEG6_IPTUN_MODE_INLINE: u32 = 0;
const SEG6_IPTUN_MODE_ENCAP: u32 = 1;

// seg6_local action param types (uapi/linux/seg6_local.h — the enum
// order is UNSPEC, ACTION, SRH, TABLE, NH4, NH6, IIF, OIF, BPF,
// VRFTABLE, COUNTERS, FLAVORS).
const SEG6_LOCAL_TABLE: u16 = 3;
const SEG6_LOCAL_NH4: u16 = 4;
const SEG6_LOCAL_NH6: u16 = 5;
const SEG6_LOCAL_IIF: u16 = 6;
const SEG6_LOCAL_OIF: u16 = 7;

/// The kernel's `SEG6_LOCAL_ACTION_*` code for a behavior, plus the
/// parameter attributes the kernel's `seg6_action_table`
/// (net/ipv6/seg6_local.c) requires and tolerates for it.
///
/// The kernel numbers its actions in its OWN uapi order (End=1,
/// End.X=2, End.T=3, End.DX2=4, …) — deliberately different from
/// the IANA registry values [`lr_srv6::Behavior`] carries (End=1,
/// End.X=5, End.T=9, …). The two tables must never be conflated:
/// the IANA value rides in control-plane identifiers, the kernel
/// value only inside the `SEG6_LOCAL_ACTION` netlink attribute.
/// Behaviors the kernel does not implement (the PSP/USP/USD flavor
/// combinations, End.B6.Red variants, End.MAP, …) map to `Err` —
/// encoding them would be a silent kernel `EINVAL` at install time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct KernelAction {
    /// `SEG6_LOCAL_ACTION_*` value (uapi/linux/seg6_local.h).
    code: u32,
    /// Param attributes the kernel REQUIRES (missing → `EINVAL`).
    requires: ParamSet,
    /// Param attributes the kernel TOLERATES in addition (present but
    /// not in requires ∪ tolerates → `EINVAL`, per `parse_nla_action`).
    tolerates: ParamSet,
}

/// The `SEG6_LOCAL_*` parameter attributes a route may carry.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct ParamSet {
    nh4: bool,
    nh6: bool,
    iif: bool,
    oif: bool,
    table: bool,
}

impl ParamSet {
    const NONE: Self = Self {
        nh4: false,
        nh6: false,
        iif: false,
        oif: false,
        table: false,
    };
    const NH4: Self = Self {
        nh4: true,
        ..Self::NONE
    };
    const NH6: Self = Self {
        nh6: true,
        ..Self::NONE
    };
    const OIF: Self = Self {
        oif: true,
        ..Self::NONE
    };
    const TABLE: Self = Self {
        table: true,
        ..Self::NONE
    };
    /// Union of two sets (builder-friendly).
    const fn union(self, other: Self) -> Self {
        Self {
            nh4: self.nh4 || other.nh4,
            nh6: self.nh6 || other.nh6,
            iif: self.iif || other.iif,
            oif: self.oif || other.oif,
            table: self.table || other.table,
        }
    }
}

/// Translate an IANA behavior to the kernel's action code and its
/// parameter contract (net/ipv6/seg6_local.c `seg6_action_table`):
///
/// - End: no params.
/// - End.X: requires NH6; OIF tolerated (optional steering).
/// - End.T: requires TABLE.
/// - End.DX2: requires OIF.
/// - End.DX6: requires NH6.
/// - End.DX4: requires NH4.
/// - End.DT6: TABLE tolerated (required on pre-6.x kernels that
///   lacked the L3-master-dev form, so emitters should always set it).
/// - End.B6.Insert / End.B6.Encaps: require SRH — not representable
///   through `Seg6LocalRoute` (no SRH parameter exists), so they are
///   rejected here rather than mis-encoded.
/// - Everything else (flavor combinations, .Red variants, the L2
///   table family, kernel-only actions like End.S): the kernel either
///   has no descriptor or a parameter this API does not model —
///   rejected with a descriptive error instead of a wire-level EINVAL.
fn kernel_action_for(behavior: Behavior) -> Result<KernelAction, Seg6RouteError> {
    let action = match behavior {
        Behavior::End => KernelAction {
            code: 1, // SEG6_LOCAL_ACTION_END
            requires: ParamSet::NONE,
            tolerates: ParamSet::NONE,
        },
        Behavior::EndX => KernelAction {
            code: 2, // SEG6_LOCAL_ACTION_END_X
            requires: ParamSet::NH6,
            tolerates: ParamSet::OIF,
        },
        Behavior::EndT => KernelAction {
            code: 3, // SEG6_LOCAL_ACTION_END_T
            requires: ParamSet::TABLE,
            tolerates: ParamSet::NONE,
        },
        Behavior::EndDX2 => KernelAction {
            code: 4, // SEG6_LOCAL_ACTION_END_DX2
            requires: ParamSet::OIF,
            tolerates: ParamSet::NONE,
        },
        Behavior::EndDX6 => KernelAction {
            code: 5, // SEG6_LOCAL_ACTION_END_DX6
            requires: ParamSet::NH6,
            tolerates: ParamSet::NONE,
        },
        Behavior::EndDX4 => KernelAction {
            code: 6, // SEG6_LOCAL_ACTION_END_DX4
            requires: ParamSet::NH4,
            tolerates: ParamSet::NONE,
        },
        Behavior::EndDT6 => KernelAction {
            code: 7, // SEG6_LOCAL_ACTION_END_DT6
            requires: ParamSet::NONE,
            tolerates: ParamSet::TABLE,
        },
        other => {
            return Err(Seg6RouteError::UnsupportedAction(format!(
                "the Linux kernel's seg6local table has no parameter contract for {other} \
                 (IANA value {}); only End, End.X, End.T, End.DX2, End.DX6, End.DX4 and \
                 End.DT6 install via netlink",
                other.wire_value()
            )));
        }
    };
    Ok(action)
}

// Netlink flags. NB: the flag bits are NAMESPACED per message kind —
// for RTM_NEWROUTE, 0x100/0x200/0x400 read as REPLACE/EXCL/CREATE,
// while the same bits in an *ack* mean CAPPED/ACK_TLVS. Requesting
// extended acks therefore belongs on the SOCKET (NETLINK_EXT_ACK /
// NETLINK_CAP_ACK via setsockopt), never in nlmsg_flags — setting
// 0x200 "for extack" on a route add silently demands exclusivity and
// every re-install over an existing row returns EEXIST.
const NLM_F_REQUEST: u16 = 0x01;
const NLM_F_ACK: u16 = 0x04;
const NLM_F_REPLACE: u16 = 0x100;
const NLM_F_CREATE: u16 = 0x400;

/// Flags for route installation: CREATE + REPLACE so that installing
/// over an existing entry *replaces* it (mirrors `mpls_route`).
const ADD_ROUTE_FLAGS: u16 = NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_REPLACE;

/// Flags for route deletion.
const DEL_ROUTE_FLAGS: u16 = NLM_F_REQUEST | NLM_F_ACK;

// Netlink socket constants.
const NETLINK_ROUTE: i32 = 0;
const AF_NETLINK: i32 = 16;
const SOCK_RAW: i32 = 3;
/// setsockopt level for netlink socket options (uapi/linux/netlink.h).
const SOL_NETLINK: i32 = 270;
/// Include extended-ack attributes in acks (uapi/linux/netlink.h).
const NETLINK_EXT_ACK: i32 = 11;
/// Cap the original message echo in acks to the bare header
/// (uapi/linux/netlink.h) — fixes the extack TLVs' offset at 36.
const NETLINK_CAP_ACK: i32 = 10;

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
    /// The behavior cannot be encoded as a `seg6local` action: either
    /// the Linux kernel's `seg6_action_table` has no descriptor for it
    /// (flavor combinations, .Red variants, End.MAP, …), or the route's
    /// parameter set does not satisfy the kernel's contract for it
    /// (missing a required parameter, or carrying one the action
    /// rejects — `parse_nla_action` answers both with `EINVAL`).
    UnsupportedAction(String),
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
            Self::UnsupportedAction(s) => write!(f, "unsupported seg6local action: {}", s),
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
/// LWTUNNEL_ENCAP_SEG6_LOCAL` (7) and a nested `RTA_ENCAP` carrying
/// `SEG6_LOCAL_ACTION` (a u32 action code in the KERNEL's numbering —
/// translated from the behavior's IANA value) followed by the
/// action's parameter attributes as siblings inside the same nested
/// payload.
///
/// Not every [`Behavior`] is installable: the kernel's
/// `seg6_action_table` implements a subset with per-action parameter
/// contracts, and [`Seg6Netlink::add_seg6local_route`] fails fast
/// with [`Seg6RouteError::UnsupportedAction`] for behaviors or
/// parameter sets the kernel would reject with a bare `EINVAL`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Seg6LocalRoute {
    /// The SID this endpoint matches (RFC 8754 §3 — becomes the IPv6
    /// destination address, /128).
    pub sid: Sid,
    /// The behavior the kernel runs when the SID is hit (RFC 8986 §4).
    pub behavior: Behavior,
    /// Route-level egress interface index (`RTA_OIF`). The kernel's
    /// `fib6_nh_init` refuses every IPv6 route that names neither an
    /// egress device nor a gateway with `ENODEV`, so a seg6local
    /// install needs one. FRR's `zclient_send_localsid` pins every
    /// local SID to a real interface for the same reason.
    ///
    /// This is the *route's* device, distinct from the `oif` action
    /// parameter (the `End.X`/`End.DX2` forwarding interface, which
    /// rides inside `RTA_ENCAP` as `SEG6_LOCAL_OIF`).
    pub if_index: u32,
    /// Optional next-hop IPv4 address (the `End.DX4` parameter).
    pub nh4: Option<[u8; 4]>,
    /// Optional next-hop IPv6 address (the `End.X` / `End.DX6`
    /// parameter).
    pub nh6: Option<[u8; 16]>,
    /// Optional input interface index. The kernel uapi defines
    /// `SEG6_LOCAL_IIF`, but no mainline `seg6_action_table`
    /// descriptor consumes it — a route that sets `iif` is rejected
    /// by the encoder with a descriptive error (the kernel would
    /// answer a bare `EINVAL` after the round trip) rather than
    /// silently mis-encoded. The field stays so a future kernel
    /// action can adopt it with one mapping entry.
    pub iif: Option<u32>,
    /// Optional output interface index (the `End.DX2` parameter; an
    /// optional `End.X` steering parameter).
    pub oif: Option<u32>,
    /// Optional table ID (the `End.T` / `End.DT6` parameter).
    pub table: Option<u32>,
}

impl Seg6LocalRoute {
    /// Build a `seg6local` route with no extra parameters. The kernel
    /// rejects behaviors that require parameters (End.DX6 needs NH6,
    /// End.DT6 needs TABLE, etc.) — the caller adds them via the
    /// builder methods. Set the egress device with
    /// [`Seg6LocalRoute::with_if_index`] unless the environment
    /// guarantees one is already implied (it never is on Linux: the
    /// kernel returns `ENODEV` for a device-less, gateway-less IPv6
    /// route).
    pub fn new(sid: Sid, behavior: Behavior) -> Self {
        Self {
            sid,
            behavior,
            if_index: 0,
            nh4: None,
            nh6: None,
            iif: None,
            oif: None,
            table: None,
        }
    }

    /// Set the route-level egress interface index (`RTA_OIF`).
    /// Required for the install to be accepted: the kernel's
    /// `fib6_nh_init` (net/ipv6/route.c) fails a route with neither an
    /// egress device nor a gateway with `ENODEV`. Builder-style.
    #[must_use]
    pub fn with_if_index(mut self, if_index: u32) -> Self {
        self.if_index = if_index;
        self
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

    /// Set the input interface index. Builder-style. Note: no
    /// mainline kernel `seg6local` action consumes the IIF parameter
    /// today — see the `iif` field's documentation; the install will
    /// fail with a descriptive error until a kernel action adopts it.
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
    /// The most recent request sent (for diagnostics: a failed
    /// install's exact bytes, printable by the caller).
    last_req: std::cell::RefCell<Option<Vec<u8>>>,
    /// The most recent response received (diagnostics, as above).
    last_resp: std::cell::RefCell<Option<Vec<u8>>>,
}

impl Seg6Netlink {
    /// Open a `NETLINK_ROUTE` socket. Returns
    /// [`Seg6RouteError::NotEnabled`] when SRv6 is not enabled in the
    /// kernel — callers should check [`seg6_enabled`] first.
    ///
    /// The socket opts `NETLINK_EXT_ACK` + `NETLINK_CAP_ACK` (the same
    /// pair iproute2 sets, lib/libnetlink.c) request the kernel's
    /// extended-ack attributes on error replies and cap the echoed
    /// request to its bare header — the correct mechanism for extacks,
    /// since the 0x100/0x200 bits in `nlmsg_flags` are namespaced to
    /// the route operation (REPLACE/EXCL), not to ack shaping.
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
        // Best effort: an unsupported opt leaves diagnostics degraded,
        // not broken.
        let one: i32 = 1;
        unsafe {
            libc_setsockopt(
                fd,
                SOL_NETLINK,
                NETLINK_EXT_ACK,
                (&raw const one) as *const core::ffi::c_void,
                core::mem::size_of::<i32>() as u32,
            );
            libc_setsockopt(
                fd,
                SOL_NETLINK,
                NETLINK_CAP_ACK,
                (&raw const one) as *const core::ffi::c_void,
                core::mem::size_of::<i32>() as u32,
            );
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
            last_req: std::cell::RefCell::new(None),
            last_resp: std::cell::RefCell::new(None),
        })
    }

    /// The exact bytes of the most recent request sent — the
    /// diagnostic for "the kernel rejected this and I need to see
    /// what \"this\" was" (hex-dump it on failure and compare against
    /// a reference implementation's bytes).
    pub fn last_request_bytes(&self) -> Option<Vec<u8>> {
        self.last_req.borrow().clone()
    }

    /// The exact bytes of the most recent response received — the
    /// raw NAK, extack attributes included, for the same purpose as
    /// [`Seg6Netlink::last_request_bytes`].
    pub fn last_response_bytes(&self) -> Option<Vec<u8>> {
        self.last_resp.borrow().clone()
    }

    fn next_seq(&self) -> u32 {
        self.seq.fetch_add(1, Ordering::SeqCst)
    }

    fn sendmsg_and_recv(&self, buf: &[u8]) -> Result<Vec<u8>, Seg6RouteError> {
        if let Ok(mut slot) = self.last_req.try_borrow_mut() {
            *slot = Some(buf.to_vec());
        }
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
        if let Ok(mut slot) = self.last_resp.try_borrow_mut() {
            *slot = Some(out.clone());
        }
        Ok(out)
    }

    /// Install a `seg6` encap route (the LSP head-end: push an SRH on
    /// packets matching `prefix`).
    pub fn add_seg6_route(&mut self, route: &Seg6Route) -> Result<(), Seg6RouteError> {
        let buf = self.build_seg6_request(RTM_NEWROUTE, ADD_ROUTE_FLAGS, route)?;
        let resp = self.sendmsg_and_recv(&buf)?;
        check_ack(&resp)
    }

    /// Delete a `seg6` encap route. The request is the minimal
    /// prefix-shaped delete iproute2 sends (`ip route del PREFIX`):
    /// matching in `ip6_route_del` is by table + prefix (+ optional
    /// metric/protocol/oif filters) — the encap attributes are not
    /// part of the delete key, and carrying them would run the request
    /// through `lwtunnel_valid_encap_type` needlessly (and fail on
    /// kernels without SRv6 compiled in).
    pub fn delete_seg6_route(
        &mut self,
        prefix: lr_core::addr::Prefix,
    ) -> Result<(), Seg6RouteError> {
        let buf = self.build_prefix_delete(RTM_DELROUTE, prefix, RT_TABLE_MAIN)?;
        let resp = self.sendmsg_and_recv(&buf)?;
        check_ack_idempotent(&resp)
    }

    /// Install a `seg6local` endpoint route (the LSP tail-end: run
    /// `behavior` when a packet arrives addressed to `sid`).
    pub fn add_seg6local_route(&mut self, route: &Seg6LocalRoute) -> Result<(), Seg6RouteError> {
        let buf = self.build_seg6local_request(RTM_NEWROUTE, ADD_ROUTE_FLAGS, route)?;
        let resp = self.sendmsg_and_recv(&buf)?;
        check_ack(&resp)
    }

    /// Delete a `seg6local` endpoint route — the same minimal
    /// prefix-shaped delete as [`Seg6Netlink::delete_seg6_route`],
    /// against the local table (seg6local rows are /128 SIDs).
    pub fn delete_seg6local_route(&mut self, sid: Sid) -> Result<(), Seg6RouteError> {
        let prefix = lr_core::addr::Prefix {
            addr: IpAddr::V6(sid.octets()),
            prefix_len: 128,
        };
        let buf = self.build_prefix_delete(RTM_DELROUTE, prefix, RT_TABLE_LOCAL)?;
        let resp = self.sendmsg_and_recv(&buf)?;
        check_ack_idempotent(&resp)
    }

    /// Build the minimal `RTM_DELROUTE` request for `prefix` in
    /// `table`: nlmsghdr + rtmsg + RTA_DST (+ nothing else — the
    /// kernel's delete matcher walks table → prefix, and every extra
    /// attribute is either ignored or, for encap attributes, an
    /// avoidable validation pass).
    fn build_prefix_delete(
        &self,
        msg_type: u16,
        prefix: lr_core::addr::Prefix,
        table: u8,
    ) -> Result<Vec<u8>, Seg6RouteError> {
        let addr = match prefix.addr {
            IpAddr::V4(_) => {
                return Err(Seg6RouteError::BadSrh(
                    "IPv6 prefixes only (SRv6 is an IPv6 facility)".into(),
                ));
            }
            IpAddr::V6(b) => b.to_vec(),
        };
        let mut attrs = Vec::new();
        attrs.extend(Self::build_rta_attribute(RTA_DST, &addr));
        let total_len = 16 + 12 + attrs.len();
        let aligned = (total_len + 3) & !3;
        let mut buf = vec![0u8; aligned];
        buf[0..4].copy_from_slice(&(total_len as u32).to_ne_bytes());
        buf[4..6].copy_from_slice(&msg_type.to_ne_bytes());
        buf[6..8].copy_from_slice(&DEL_ROUTE_FLAGS.to_ne_bytes());
        let seq = self.next_seq();
        buf[8..12].copy_from_slice(&seq.to_ne_bytes());
        buf[12..16].copy_from_slice(&self.pid.to_ne_bytes());
        buf[16] = AF_INET6 as u8;
        buf[17] = prefix.prefix_len;
        buf[18] = 0;
        buf[19] = 0;
        buf[20] = table;
        buf[21] = 0; // RTPROT_UNSPEC — no protocol filter on delete
        buf[22] = 0; // scope: not part of the v6 delete matcher
        buf[23] = 0; // RTN_UNSPEC — no type filter
        buf[24..28].copy_from_slice(&0u32.to_ne_bytes());
        buf[28..28 + attrs.len()].copy_from_slice(&attrs);
        Ok(buf)
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
        // NLA_U16 payload — the rtnetlink policy for RTA_ENCAP_TYPE is
        // `.type = NLA_U16`; iproute2 sends the two-byte form.
        attrs.extend(Self::build_rta_attribute(
            RTA_ENCAP_TYPE,
            &(LWTUNNEL_ENCAP_SEG6 as u16).to_ne_bytes(),
        ));
        attrs.extend(Self::build_rta_attribute(RTA_ENCAP | NLA_F_NESTED, &encap));
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
    ///   RTA_OIF  = if_index (4 bytes — the egress device, fib6_nh_init
    ///              refuses a device-less route with ENODEV)
    ///   RTA_ENCAP_TYPE = LWTUNNEL_ENCAP_SEG6_LOCAL (7)
    ///   RTA_ENCAP = nested {
    ///     SEG6_LOCAL_ACTION (type 1) = <u32 action code>   (4-byte payload, KERNEL numbering)
    ///     SEG6_LOCAL_NH4   (type 4) = <IPv4 next-hop>      (4-byte payload, optional)
    ///     SEG6_LOCAL_NH6   (type 5) = <IPv6 next-hop>      (16-byte payload, optional)
    ///     SEG6_LOCAL_IIF   (type 6) = <input ifindex>      (4-byte payload, optional)
    ///     SEG6_LOCAL_OIF   (type 7) = <output ifindex>    (4-byte payload, optional)
    ///     SEG6_LOCAL_TABLE (type 3) = <routing table id>  (4-byte payload, optional)
    ///   }
    /// ```
    ///
    /// The attribute numbers follow the kernel uapi enum order
    /// (uapi/linux/seg6_local.h: UNSPEC, ACTION, SRH, TABLE, NH4,
    /// NH6, IIF, OIF, BPF, VRFTABLE, COUNTERS, FLAVORS). The ACTION
    /// code is the kernel's own numbering, translated from the IANA
    /// registry value the behavior carries — see [`kernel_action_for`].
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
        // Translate the IANA behavior into the kernel's ACTION code
        // and check the parameter set against the kernel's contract
        // BEFORE encoding — `parse_nla_action` (net/ipv6/seg6_local.c)
        // rejects a missing required parameter and an unrecognised one
        // with the same bare EINVAL, so surfacing the contract here
        // turns a kernel round-trip into a local, descriptive error.
        let action = kernel_action_for(route.behavior)?;
        let present = ParamSet {
            nh4: route.nh4.is_some(),
            nh6: route.nh6.is_some(),
            iif: route.iif.is_some(),
            oif: route.oif.is_some(),
            table: route.table.is_some(),
        };
        let allowed = action.requires.union(action.tolerates);
        let required = action.requires;
        for (set, allowed_here, required_here, name) in [
            (present.nh4, allowed.nh4, required.nh4, "nh4"),
            (present.nh6, allowed.nh6, required.nh6, "nh6"),
            (present.iif, allowed.iif, required.iif, "iif"),
            (present.oif, allowed.oif, required.oif, "oif"),
            (present.table, allowed.table, required.table, "table"),
        ] {
            if set && !allowed_here {
                return Err(Seg6RouteError::UnsupportedAction(format!(
                    "{} carries the {name} parameter, but the kernel's action descriptor \
                     for it does not accept {name} (parse_nla_action answers EINVAL)",
                    route.behavior
                )));
            }
            if required_here && !set {
                return Err(Seg6RouteError::UnsupportedAction(format!(
                    "{} requires the {name} parameter the kernel's action descriptor \
                     mandates (parse_nla_action answers EINVAL without it)",
                    route.behavior
                )));
            }
        }

        let mut encap = Vec::new();
        // SEG6_LOCAL_ACTION: 4-byte u32 action code — the KERNEL's
        // numbering (uapi/linux/seg6_local.h), translated from the
        // IANA registry value the behavior carries (see
        // `kernel_action_for`; iproute2 emits this same u32 via
        // addattr32(RTA_ENCAP, SEG6_LOCAL_ACTION, action)).
        encap.extend(Self::build_rta_attribute(
            SEG6LOCAL_ACTION,
            &action.code.to_ne_bytes(),
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
        if route.if_index != 0 {
            attrs.extend(Self::build_rta_attribute(
                RTA_OIF,
                &route.if_index.to_ne_bytes(),
            ));
        }
        // NLA_U16 payload — the rtnetlink policy for RTA_ENCAP_TYPE is
        // `.type = NLA_U16`; iproute2 sends the two-byte form.
        attrs.extend(Self::build_rta_attribute(
            RTA_ENCAP_TYPE,
            &(LWTUNNEL_ENCAP_SEG6_LOCAL as u16).to_ne_bytes(),
        ));
        attrs.extend(Self::build_rta_attribute(RTA_ENCAP | NLA_F_NESTED, &encap));
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
/// is in host byte order (it's a plain `int`). When the socket opts
/// of [`Seg6Netlink::connect`] were honoured, the error reply also
/// carries the kernel's extended-ack attributes —
/// `NLMSGERR_ATTR_MSG` is the netlink-level reason in the kernel's
/// own words ("Egress device not specified", "Nexthop device is not
/// up", …), which the bare errno cannot convey. Folding it into the
/// error string turns a bare `EINVAL` into an actionable diagnostic.
fn check_ack(resp: &[u8]) -> Result<(), Seg6RouteError> {
    match ack_errno(resp)? {
        0 => Ok(()),
        err => Err(nak_error(resp, err)),
    }
}

/// The delete-path variant of [`check_ack`]: `-ESRCH` (no such
/// entry) maps to success, mirroring the Linux route backend's
/// idempotent-withdrawal contract — deleting an already-gone row is
/// not an error.
fn check_ack_idempotent(resp: &[u8]) -> Result<(), Seg6RouteError> {
    match ack_errno(resp)? {
        // -ESRCH: already withdrawn.
        0 | -3 => Ok(()),
        err => Err(nak_error(resp, err)),
    }
}

/// The raw errno of the kernel's reply: `Ok(0)` for an ACK/DONE,
/// `Ok(err)` (negative) for a NAK, `Err` for a malformed reply.
fn ack_errno(resp: &[u8]) -> Result<i32, Seg6RouteError> {
    if resp.len() < 20 {
        return Err(Seg6RouteError::Kernel(format!(
            "short netlink response ({} bytes)",
            resp.len()
        )));
    }
    let msg_type = u16::from_ne_bytes([resp[4], resp[5]]);
    if msg_type == NLMSG_DONE {
        return Ok(0);
    }
    if msg_type != NLMSG_ERROR {
        return Err(Seg6RouteError::Kernel(format!(
            "unexpected netlink message type {}",
            msg_type
        )));
    }
    Ok(i32::from_ne_bytes([resp[16], resp[17], resp[18], resp[19]]))
}

/// Render a non-zero errno (plus the extended-ack message, when the
/// socket opts of [`Seg6Netlink::connect`] were honoured) as the
/// error value.
fn nak_error(resp: &[u8], err: i32) -> Seg6RouteError {
    let extack = extack_msg(resp)
        .map(|m| format!(": {m}"))
        .unwrap_or_default();
    Seg6RouteError::Kernel(format!(
        "netlink error {} ({}){}",
        err,
        errno_str(err),
        extack
    ))
}

/// Extract `NLMSGERR_ATTR_MSG` (the extended-ack human-readable
/// reason) from an `NLMSG_ERROR` reply. The kernel marks the *reply's*
/// own `nlmsg_flags` with `NLM_F_CAPPED` when it capped the echoed
/// request to the bare header (TLVs then start at offset 36);
/// otherwise the echo carries the original payload too and the TLVs
/// start after it (20 + echoed length, aligned). The socket opts set
/// in [`Seg6Netlink::connect`] request the capped shape, but the
/// uncapped branch keeps the parser correct for any socket.
fn extack_msg(resp: &[u8]) -> Option<String> {
    const NLMSGERR_ATTR_MSG: u16 = 1;
    const NLM_F_CAPPED_ACK: u16 = 0x100;
    if resp.len() < 36 {
        return None;
    }
    let msg_len = u32::from_ne_bytes([resp[0], resp[1], resp[2], resp[3]]) as usize;
    let reply_capped = u16::from_ne_bytes([resp[6], resp[7]]) & NLM_F_CAPPED_ACK != 0;
    let tlv_off = if reply_capped {
        36
    } else {
        let orig_len = u32::from_ne_bytes([resp[20], resp[21], resp[22], resp[23]]) as usize;
        (20 + orig_len + 3) & !3
    };
    let bound = msg_len.min(resp.len());
    let mut cur = tlv_off;
    while cur + 4 <= bound {
        let alen = u16::from_ne_bytes([resp[cur], resp[cur + 1]]) as usize;
        if alen < 4 {
            break;
        }
        let atype = u16::from_ne_bytes([resp[cur + 2], resp[cur + 3]]);
        if atype == NLMSGERR_ATTR_MSG {
            let end = (cur + alen).min(bound);
            return Some(
                String::from_utf8_lossy(&resp[cur + 4..end])
                    .trim_end_matches('\0')
                    .to_string(),
            );
        }
        cur += (alen + 3) & !3;
    }
    None
}

fn errno_str(err: i32) -> &'static str {
    match err {
        -1 => "EPERM (insufficient privileges)",
        -2 => "ENOENT (no such entry)",
        -13 => "EACCES (IPv6 is disabled on the egress device)",
        -17 => "EEXIST (entry already installed)",
        -19 => "ENODEV (egress device not specified or does not exist — set the route's if_index)",
        -22 => "EINVAL (malformed request)",
        -95 => "EOPNOTSUPP (SRv6 not supported)",
        -99 => "EADDRNOTAVAIL",
        -101 => "ENETUNREACH (egress device has no route)",
        -119 => "ENETDOWN (egress device is down)",
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
    fn setsockopt(
        fd: i32,
        level: i32,
        optname: i32,
        optval: *const core::ffi::c_void,
        optlen: u32,
    ) -> i32;
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
unsafe fn libc_setsockopt(
    fd: i32,
    level: i32,
    optname: i32,
    optval: *const core::ffi::c_void,
    optlen: u32,
) -> i32 {
    setsockopt(fd, level, optname, optval, optlen)
}

#[cfg(test)]
#[path = "seg6_route_tests.rs"]
mod tests;
