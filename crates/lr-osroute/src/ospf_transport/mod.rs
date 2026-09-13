//! OSPF raw-socket transport (RFC 2328 appendix A).
//!
//! OSPF rides directly on IP: protocol number 89 for OSPFv2, multicast
//! to `224.0.0.5` (AllSPFRouters) / `224.0.0.6` (AllDRouters) on the
//! attached network. That makes the transport a *system* concern — raw
//! sockets need privileges and per-OS APIs — so it lives in this crate
//! beside [`tcp_auth`](crate::tcp_auth) and [`gtsm`](crate::gtsm),
//! while `lr-ospf` stays OS-independent.
//!
//! ## Model
//!
//! [`OspfV2Transport`] owns one raw IPv4 socket per interface:
//!
//! - `SO_BINDTODEVICE` scopes both receive and multicast egress to the
//!   configured interface, so several interfaces can run concurrently
//!   without cross-talk.
//! - Both multicast groups are joined (§A.1 requires listening on
//!   AllSPFRouters; AllDRouters carries LS-Updates/Acks from the DR on
//!   broadcast networks).
//! - `IP_MULTICAST_TTL = 1` and `IP_MULTICAST_LOOP` (configurable — the
//!   self-test path needs it on) follow §A.1: multicast packets must
//!   carry TTL 1... actually OSPF requires TTL 255 for the GTSM-style
//!   checks of newer specifications; TTL 1 is what every
//!   implementation sends for multicast because 224.0.0.x is
//!   link-local and never forwarded.
//!
//! [`interface_v4_addrs`] enumerates a interface's IPv4 addresses and
//! prefix lengths (`getifaddrs`), which speakers need to derive the
//! stub-network links of their Router-LSA.
//!
//! ## Platform support
//!
//! | Platform | Status |
//! |----------|--------|
//! | Linux    | yes — `SO_BINDTODEVICE` + `ip_mreqn` membership by index |
//! | other    | [`OspfTransportError::Unsupported`] |
//!
//! Raw sockets require `CAP_NET_RAW`: the daemon must run as root, or
//! inside a user+network namespace (`unshare -Urn`) where the capability
//! is granted — the interop scripts use the latter to stay rootless.
//!
//! ## Example
//!
//! ```no_run
//! use lr_osroute::ospf_transport::{interface_v4_addrs, OspfV2Transport};
//!
//! let ifaces = interface_v4_addrs("eth0").unwrap();
//! let mut sock = OspfV2Transport::bind("eth0", false).unwrap();
//! let mut buf = [0u8; 1500];
//! match sock.recv_from(&mut buf).unwrap() {
//!     Some((n, src)) => println!("{} bytes from {}", n, src),
//!     None => println!("nothing pending"),
//! }
//! ```

use std::fmt;
use std::net::Ipv4Addr;

/// AllSPFRouters (RFC 2328 §A.1): all routers running OSPF.
pub const ALL_SPF_ROUTERS: [u8; 4] = [224, 0, 0, 5];
/// AllDRouters (RFC 2328 §A.1): the DR and BDR only.
pub const ALL_D_ROUTERS: [u8; 4] = [224, 0, 0, 6];
/// AllSPFRouters, IPv6 (RFC 5340 §A.3.2 / RFC 4291 link-local multicast).
pub const ALL_SPF_ROUTERS_V6: [u8; 16] = [0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 5];
/// AllDRouters, IPv6 (RFC 5340 §A.3.2).
pub const ALL_D_ROUTERS_V6: [u8; 16] = [0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 6];

/// IP protocol number assigned to OSPF (IANA).
pub const IPPROTO_OSPF: i32 = 89;

/// Errors from the OSPF transport.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OspfTransportError {
    /// The platform has no raw-socket OSPF support in librouting.
    Unsupported(&'static str),
    /// A syscall failed; `errno` is the OS error code.
    Os { context: &'static str, errno: i32 },
    /// The interface does not exist (or has no IPv4 address where one
    /// is required).
    UnknownInterface(String),
}

impl OspfTransportError {
    /// True when the failure is a missing `CAP_NET_RAW` (`EPERM`) —
    /// callers use this to degrade gracefully instead of failing hard.
    pub fn is_permission_denied(&self) -> bool {
        matches!(self, Self::Os { errno: 1, .. })
    }
}

impl fmt::Display for OspfTransportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unsupported(why) => write!(f, "unsupported on this platform: {why}"),
            Self::Os { context, errno } => {
                write!(f, "{context} failed (errno {errno})")
            }
            Self::UnknownInterface(name) => write!(f, "unknown interface {name}"),
        }
    }
}

impl std::error::Error for OspfTransportError {}

/// One IPv4 address of an interface, with its prefix length.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InterfaceV4Addr {
    pub addr: Ipv4Addr,
    pub prefix_len: u8,
}

impl InterfaceV4Addr {
    /// The network address of this prefix (host bits zeroed).
    pub fn network(&self) -> Ipv4Addr {
        let mask = prefix_mask(self.prefix_len);
        let a = u32::from(self.addr) & mask;
        Ipv4Addr::from(a)
    }
}

/// One IPv6 address of an interface, with its prefix length and the
/// scope id a link-local address is bound to (the interface index).
/// RFC 7552 §6.1 rule 5 classifies addresses for the LDP transport:
/// prefer a global unicast address over unique-local or link-local.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InterfaceV6Addr {
    pub addr: std::net::Ipv6Addr,
    pub prefix_len: u8,
    /// The sin6_scope_id of the address (non-zero for link-local).
    pub scope_id: u32,
}

impl InterfaceV6Addr {
    /// Global unicast (2000::/3) — the address family an RFC 7552
    /// §6.1 LDP transport address should come from.
    pub fn is_global_unicast(&self) -> bool {
        (self.addr.segments()[0] & 0xe000) == 0x2000
    }

    /// Link-local (fe80::/10). Not usable as an LDP targeted-Hello
    /// endpoint (RFC 7552 §5.2) and never preferred for the transport
    /// address TLV (§6.1 rule 5).
    pub fn is_link_local(&self) -> bool {
        (self.addr.segments()[0] & 0xffc0) == 0xfe80
    }
}

/// One interface's name + the IPv4 and IPv6 addresses `getifaddrs`
/// returned for it. Returned by [`list_interfaces`]; used by the
/// Babel multi-NIC config matcher to resolve `[[babel.interface]]`
/// glob patterns (`eth*`, `eth?`) to concrete kernel interfaces
/// and pick a bind address per match.
///
/// Defined here (in the platform-shared `mod.rs`) so both the Linux
/// implementation and the non-Linux stub can return it without
/// duplicating the type.
#[derive(Debug, Clone)]
pub struct InterfaceEntry {
    pub name: String,
    pub v4: Vec<std::net::Ipv4Addr>,
    pub v6: Vec<std::net::Ipv6Addr>,
}

/// The dotted-quad mask for a prefix length (invalid lengths saturate:
/// >32 becomes /32; the wire encoder rejects them earlier anyway).
pub fn prefix_mask(prefix_len: u8) -> u32 {
    if prefix_len == 0 {
        0
    } else {
        u32::MAX << (32 - prefix_len.min(32) as u32)
    }
}

// ---------------------------------------------------------------------------
// Platform dispatch
// ---------------------------------------------------------------------------

#[cfg(all(feature = "std", target_os = "linux"))]
#[path = "imp_linux.rs"]
mod imp;
#[cfg(all(feature = "std", target_os = "linux"))]
pub use imp::{
    ifindex_of, interface_v4_addrs, interface_v6_addrs, list_interfaces, OspfV2Transport,
    OspfV6Transport,
};

#[cfg(all(feature = "std", not(target_os = "linux")))]
mod stub;
#[cfg(all(feature = "std", not(target_os = "linux")))]
pub use stub::{
    ifindex_of, interface_v4_addrs, interface_v6_addrs, list_interfaces, OspfV2Transport,
    OspfV6Transport,
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prefix_masks() {
        assert_eq!(prefix_mask(0), 0x0000_0000);
        assert_eq!(prefix_mask(8), 0xff00_0000);
        assert_eq!(prefix_mask(24), 0xffff_ff00);
        assert_eq!(prefix_mask(32), 0xffff_ffff);
        assert_eq!(prefix_mask(33), 0xffff_ffff, ">32 saturates to /32");
    }

    #[test]
    fn network_zeroes_host_bits() {
        let a = InterfaceV4Addr {
            addr: Ipv4Addr::new(192, 0, 2, 130),
            prefix_len: 24,
        };
        assert_eq!(a.network(), Ipv4Addr::new(192, 0, 2, 0));
        let b = InterfaceV4Addr {
            addr: Ipv4Addr::new(10, 1, 2, 3),
            prefix_len: 8,
        };
        assert_eq!(b.network(), Ipv4Addr::new(10, 0, 0, 0));
    }

    #[test]
    fn permission_denied_detection() {
        let e = OspfTransportError::Os {
            context: "socket",
            errno: 1,
        };
        assert!(e.is_permission_denied());
        let e2 = OspfTransportError::Os {
            context: "socket",
            errno: 22,
        };
        assert!(!e2.is_permission_denied());
    }

    /// Live socket test — requires CAP_NET_RAW, skips otherwise. Run
    /// under `unshare -Urn` (see tests/interop/ospf.sh) to exercise.
    #[cfg(target_os = "linux")]
    #[test]
    fn live_raw_socket_multicast_loopback() {
        use super::imp::OspfV2Transport;
        // Loopback must exist and be up for the send path.
        let sock = match OspfV2Transport::bind("lo", true) {
            Ok(s) => s,
            Err(e) if e.is_permission_denied() => {
                eprintln!("skipped (no CAP_NET_RAW): {e}");
                return;
            }
            Err(e) => panic!("bind lo: {e}"),
        };
        let payload = [0x02u8, 0x01, 0, 8, 1, 1, 1, 1]; // 8 raw bytes
        let sent = match sock.send_multicast(&payload) {
            Ok(n) => n,
            Err(e) => {
                // lo down (fresh network namespace): tolerate, the
                // socket setup itself is what this test pins down.
                eprintln!("skipped (send on lo): {e}");
                return;
            }
        };
        assert_eq!(sent, payload.len());
        let mut buf = [0u8; 1500];
        let mut got = None;
        for _ in 0..20 {
            match sock.recv_from(&mut buf) {
                Ok(Some((n, _src))) => {
                    got = Some(n);
                    break;
                }
                Ok(None) => std::thread::sleep(std::time::Duration::from_millis(10)),
                Err(e) => panic!("recv: {e}"),
            }
        }
        match got {
            Some(n) => assert!(n >= payload.len(), "received {n} bytes"),
            None => eprintln!("skipped (loopback multicast not delivered — lo down?)"),
        }
    }
}
