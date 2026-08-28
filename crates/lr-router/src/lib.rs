//! Layer-3 router instance.
//!
//! [`DefaultRouter`] ties together protocol sessions, the Loc-RIB, the policy
//! engine, and the timer queue. The embedder drives it via
//! [`DefaultRouter::tick`] + [`DefaultRouter::feed_input`] +
//! [`DefaultRouter::poll_events`].

pub mod connection;
pub mod event;
pub mod instance;
pub mod redistribution;
pub mod session;

pub use event::{EventSink, RouterEvent};
pub use instance::{DefaultRouter, RouterInstance};
pub use redistribution::{MetricPolicy, RedistributionPipe};
pub use session::{
    OspfAreaType, Session, SessionConfig, SessionHandle, SessionKind, SessionSummary,
};
