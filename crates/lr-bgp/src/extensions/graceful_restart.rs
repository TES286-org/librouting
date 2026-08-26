//! BGP Graceful Restart (RFC 4724).
//!
//! Wire support lives in [`crate::capabilities::Capability::graceful_restart`]
//! (capability 64, per-address-family tuples with the Forwarding State bit);
//! the retention procedures run in `lr-router`:
//!
//! | RFC section | Requirement | Implementation |
//! |-------------|-------------|-----------------|
//! | §3 | Capability with restart flags/time + per-family F bits | `Capability::graceful_restart` |
//! | §4.1 | Restarting speaker defers selection until EoR | embedder policy; the FSM emits `EndOfRib` |
//! | §4.1 | EoR marker sent after the initial table dump | `BgpPeer::send_end_of_rib` |
//! | §4.2 | Helper retains routes of the listed families on session loss | `lr-router` retention state |
//! | §4.2 | Routes are deleted when the advertised Restart Time elapses | `DefaultRouter::tick` retention expiry |
//! | §4.2 | Stale routes the peer did not refresh are removed at EoR | `lr-router::on_end_of_rib` |
//!
//! The RFC 9494 Long-Lived Graceful Restart extension (a second, longer
//! retention window with `LLGR_STALE` marking) builds on this module — see
//! [`crate::extensions::long_lived`].

#![allow(dead_code)]
