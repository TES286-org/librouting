//! Routing policy framework.
//!
//! FRR-style route-maps + prefix-lists + AS-path filters + community-lists.
//! The policy engine evaluates a chain against a route and produces a
//! verdict: Accept, Reject, or Continue.

pub mod action;
pub mod as_path_filter;
pub mod community_list;
pub mod policy;
pub mod prefix_list;
pub mod route_map;

pub use policy::{Policy, PolicyChain, PolicyVerdict};
pub use route_map::{RouteMap, RouteMapEntry};
