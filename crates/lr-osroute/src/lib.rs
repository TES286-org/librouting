//! OS routing table interaction — reference implementation.
//!
//! This crate provides a *reference* implementation for installing routes
//! computed by [`lr-rib`] into the kernel routing table and for reading the
//! current state of the kernel routing table back into the library's RIB.
//!
//! ## What this crate is (and isn't)
//!
//! - **It is**: a portable abstraction ([`OsRouteTable`] trait) over the
//!   platform-specific route-table manipulation API (Linux `rtnetlink`,
//!   BSD/FreeBSD `route` socket, Windows `IPHelper`).
//! - **It is**: a **reference** implementation with three native
//!   backends — Linux `rtnetlink`, the BSD/macOS `route(4)` socket and
//!   the Windows IP Helper API — each exposing the same trait surface
//!   (cross-compile checked; see `docs/OS-INTEGRATION.md`). Other
//!   platforms compile against a stub.
//!
//! The crate is **opt-in**: it pulls in OS-specific syscalls. Embedders
//! running `librouting` inside a sandbox or on a platform without a kernel
//! routing table (e.g. inside a CI container) should not pull in this
//! crate — or should implement the [`OsRouteTable`] trait themselves.
//!
//! ## Architecture
//!
//! ```text
//! +--------------------+
//! |   lr-rib (Loc-RIB) |
//! +--------------------+
//!           |
//!           v
//! +--------------------+
//! |   lr-osroute       |  <-- this crate
//! |   OsRouteTable     |
//! +--------------------+
//!           |
//!           v
//! +--------------------+
//! |  Platform kernel   |
//! |  (rtnetlink/rtsock)|
//! +--------------------+
//! ```
//!
//! ## Usage
//!
//! ```no_run
//! # // pseudo-code — see the `examples/` directory for a runnable sample.
//! use lr_osroute::OsRouteTable;
//! use lr_core::addr::{Prefix, IpAddr};
//!
//! let mut rt = lr_osroute::RtNetlink::connect().unwrap();
//! let prefix: Prefix = "203.0.113.0/24".parse().unwrap();
//! let gw: IpAddr = "198.51.100.1".parse().unwrap();
//! rt.add_route(prefix, gw, 0).unwrap();
//! ```

// SAFETY: this crate necessarily performs FFI to platform syscalls. unsafe
// code is contained to the `linux` module which is only compiled when the
// `std` feature is enabled (the default).
#![cfg_attr(not(feature = "std"), forbid(unsafe_code))]

// Platform backends:
// - Linux      → rtnetlink        (`linux`)
// - *BSD/macOS → route(4) socket  (`bsd`)
// - Windows    → IP Helper API    (`windows`)
// - other      → compile-only stub so the trait surface stays identical.
#[cfg(feature = "std")]
pub mod stub;

/// TCP session authentication (RFC 2385 MD5, RFC 5925 TCP-AO) — key
/// installation on listener/connect sockets. Linux implements both; other
/// platforms return [`tcp_auth::TcpAuthError::Unsupported`] while keeping
/// the configuration model portable.
#[cfg(feature = "std")]
pub mod tcp_auth;

/// RFC 5082 Generalized TTL Security Mechanism (GTSM) — TTL arming on
/// listener/connect sockets. Linux enforces both outbound TTL and the
/// min-TTL receive filter; other platforms set outbound TTL only.
#[cfg(feature = "std")]
pub mod gtsm;

/// OSPF raw-socket transport (RFC 2328 appendix A) — one `IPPROTO_OSPF`
/// socket per interface with multicast scoping, plus interface address
/// enumeration. Linux only; other platforms return
/// [`ospf_transport::OspfTransportError::Unsupported`].
#[cfg(feature = "std")]
pub mod ospf_transport;

#[cfg(all(
    feature = "std",
    any(
        target_os = "freebsd",
        target_os = "netbsd",
        target_os = "openbsd",
        target_os = "macos"
    )
))]
pub mod bsd;
#[cfg(all(feature = "std", target_os = "linux"))]
pub mod linux;
#[cfg(all(feature = "std", target_os = "windows"))]
pub mod windows;

#[cfg(all(
    feature = "std",
    not(target_os = "linux"),
    any(
        target_os = "freebsd",
        target_os = "netbsd",
        target_os = "openbsd",
        target_os = "macos"
    )
))]
pub use bsd::RouteSocket as RtNetlink;
/// The rtnetlink backend (Linux). Historically exported under this name;
/// on non-Linux platforms it aliases the platform's native backend so
/// embedders written against old code keep compiling.
#[cfg(all(feature = "std", target_os = "linux"))]
pub use linux::RtNetlink;
#[cfg(all(
    feature = "std",
    not(any(
        target_os = "linux",
        target_os = "freebsd",
        target_os = "netbsd",
        target_os = "openbsd",
        target_os = "macos",
        target_os = "windows"
    ))
))]
pub use stub::StubRouteTable as RtNetlink;
#[cfg(all(feature = "std", target_os = "windows"))]
pub use windows::IpHelper as RtNetlink;

#[cfg(all(
    feature = "std",
    any(
        target_os = "freebsd",
        target_os = "netbsd",
        target_os = "openbsd",
        target_os = "macos"
    )
))]
pub use bsd::RouteSocket as SystemRouteTable;
/// The native OS route-table backend for the compilation target:
/// [`linux::RtNetlink`] on Linux, [`bsd::RouteSocket`] on the BSDs/macOS,
/// [`windows::IpHelper`] on Windows and [`stub::StubRouteTable`] anywhere
/// else. Prefer this alias in new code.
#[cfg(all(feature = "std", target_os = "linux"))]
pub use linux::RtNetlink as SystemRouteTable;
#[cfg(all(
    feature = "std",
    not(any(
        target_os = "linux",
        target_os = "freebsd",
        target_os = "netbsd",
        target_os = "openbsd",
        target_os = "macos",
        target_os = "windows"
    ))
))]
pub use stub::StubRouteTable as SystemRouteTable;
#[cfg(all(feature = "std", target_os = "windows"))]
pub use windows::IpHelper as SystemRouteTable;

/// Human-readable name of the backend compiled in — for logs and banners.
#[cfg(all(feature = "std", target_os = "linux"))]
pub const PLATFORM_NAME: &str = "linux-rtnetlink";
#[cfg(all(feature = "std", target_os = "freebsd"))]
pub const PLATFORM_NAME: &str = "freebsd-route-socket";
#[cfg(all(feature = "std", target_os = "netbsd"))]
pub const PLATFORM_NAME: &str = "netbsd-route-socket";
#[cfg(all(feature = "std", target_os = "openbsd"))]
pub const PLATFORM_NAME: &str = "openbsd-route-socket";
#[cfg(all(feature = "std", target_os = "macos"))]
pub const PLATFORM_NAME: &str = "macos-route-socket";
#[cfg(all(feature = "std", target_os = "windows"))]
pub const PLATFORM_NAME: &str = "windows-ip-helper";
#[cfg(all(
    feature = "std",
    not(any(
        target_os = "linux",
        target_os = "freebsd",
        target_os = "netbsd",
        target_os = "openbsd",
        target_os = "macos",
        target_os = "windows"
    ))
))]
pub const PLATFORM_NAME: &str = "stub";

use lr_core::addr::{IpAddr, Prefix};
use lr_core::rib::Protocol;

/// A kernel route entry. Maps to a single row in the OS's FIB.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KernelRoute {
    pub prefix: Prefix,
    pub next_hop: Option<IpAddr>,
    /// Interface index (OS-specific; resolved via `if_nametoindex`).
    pub if_index: Option<u32>,
    /// Route metric / priority (lower wins on Linux).
    pub metric: u32,
    /// Source protocol identifier.
    pub protocol: Protocol,
}

/// Trait abstracting the OS routing table. Implementors are responsible for
/// platform-specific syscall details.
#[cfg(feature = "std")]
pub trait OsRouteTable {
    type Error: std::error::Error;

    /// Add a route: "to reach `prefix`, send via `next_hop` on `if_index`".
    fn add_route(
        &mut self,
        prefix: Prefix,
        next_hop: IpAddr,
        if_index: u32,
    ) -> Result<(), Self::Error>;

    /// Delete a route matching the prefix.
    fn delete_route(&mut self, prefix: Prefix) -> Result<(), Self::Error>;

    /// Dump all routes currently in the kernel FIB.
    fn list_routes(&mut self) -> Result<Vec<KernelRoute>, Self::Error>;

    /// Convenience: does the kernel currently have a route to this prefix?
    fn has_route(&mut self, prefix: Prefix) -> Result<bool, Self::Error> {
        Ok(self.list_routes()?.into_iter().any(|r| r.prefix == prefix))
    }
}

/// A simple error type wrapping a string. Used by [`StubRouteTable`] and the
/// Linux implementation when a syscall fails outside of an explicit error
/// category.
#[cfg(feature = "std")]
#[derive(Debug, Clone)]
pub struct OsRouteError(pub String);

#[cfg(feature = "std")]
impl std::fmt::Display for OsRouteError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for OsRouteError {}

#[cfg(feature = "std")]
impl From<std::io::Error> for OsRouteError {
    fn from(e: std::io::Error) -> Self {
        Self(e.to_string())
    }
}
