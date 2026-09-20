//! librouting core: shared types, traits, error model and utilities.
//!
//! This crate contains no protocol-specific logic. It provides the foundation
//! that `lr-bgp`, `lr-ospf`, `lr-babel`, `lr-rib`, `lr-policy` and `lr-router`
//! build on:
//!
//! - Addressing primitives ([`addr`])
//! - Error model ([`error`])
//! - Wire codec traits ([`codec`])
//! - Generic finite-state machine engine ([`fsm`])
//! - RIB trait surface ([`rib`])
//! - Logical timer queue ([`timer`])
//! - Injectable clock ([`time`])
//! - Wire utilities: checksums, bitflags ([`util`])
//!
//! Everything here is platform-independent. No `std::net`, no `tokio`, no
//! netlink. The embedder drives I/O and time.
//!
//! `no_std` is partially supported; some helpers (e.g. the timer queue) require
//! `alloc`.

#![forbid(unsafe_code)]
#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(not(feature = "std"))]
extern crate alloc;

pub mod addr;
pub mod attr;
pub mod buf;
pub mod codec;
pub mod error;
pub mod event;
pub mod fsm;
pub mod nlri;
pub mod rib;
pub mod time;
pub mod timer;
pub mod util;

/// Common prelude.
pub mod prelude {
    pub use crate::addr::{Asn, IpAddr, IpNet, Prefix, RouterId};
    pub use crate::buf::{ReadBuf, WriteBuf};
    pub use crate::codec::{Codec, Decoder, Encoder};
    pub use crate::error::{EncodeError, Error, ParseError, Result};
    pub use crate::fsm::{Action, StateId, StateMachine};
    pub use crate::fsm::{TimerId, TimerSpec};
    pub use crate::rib::{Route, RouteKey, RouteOrigin};
    pub use crate::time::{Clock, Duration, Instant};
    pub use crate::timer::TimerQueue;
}

/// Library version string.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// ABI version packed into a u32 (major << 16 | minor << 8 | patch).
/// Bumped to 2 when `lr_router_install_static_v4`/`_v6` and
/// `lr_router_uninstall_static_v4`/`_v6` were added (the static-route
/// FFI surface). Existing callers see the same surface plus the new
/// functions — no breaking change.
pub const ABI_VERSION: u32 = 2;
