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
//! - **It is**: a **reference** implementation: Linux `rtnetlink` is
//!   implemented; other platforms have a minimal stub so they at least
//!   compile and expose the same trait surface.
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

#[cfg(feature = "std")]
pub mod stub;

// The rtnetlink backend only exists on Linux. On every other platform we
// fall back to the stub so the trait surface stays identical and the crate
// still cross-compiles (e.g. to Windows/other Unixes).
#[cfg(all(feature = "std", target_os = "linux"))]
pub mod linux;

#[cfg(all(feature = "std", target_os = "linux"))]
pub use linux::RtNetlink;
#[cfg(all(feature = "std", not(target_os = "linux")))]
pub use stub::StubRouteTable as RtNetlink;

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
