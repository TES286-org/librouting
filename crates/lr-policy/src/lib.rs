//! Routing policy framework.
//!
//! FRR-style route-maps + prefix-lists + AS-path filters + community-lists.
//! The policy engine evaluates a chain against a route and produces a
//! verdict: Accept, Reject, or Continue.
//!
//! ## Hook surface
//!
//! Three trait-based hook points let the embedder inject non-default
//! behavior at the import, selection, and export stages. See [`hooks`].
//!
//! ## Safety net
//!
//! Protocol-level invariants (AS loop, NEXT_HOP sanity, martian prefix, etc.)
//! are checked by [`safety::SafetyNet`]. Each check can be toggled via
//! [`safety::SafetyConfig`]; defaults match common operator expectations.

pub mod action;
pub mod as_path_filter;
#[cfg(feature = "bgp")]
pub mod bgp;
pub mod community_list;
pub mod filter;
pub mod hooks;
pub mod policy;
pub mod prefix_list;
pub mod route_map;
pub mod safety;
pub mod set;

pub use hooks::{ExportHook, HookChain, HookVerdict, ImportHook, SelectionHook};
pub use policy::{Policy, PolicyChain, PolicyVerdict};
pub use route_map::{RouteMap, RouteMapEntry};
pub use safety::{SafetyConfig, SafetyNet, SafetyViolation};
pub use set::{ListKind, PolicyHooks, PolicySet};
