//! Cross-protocol redistribution engine (BIRD `pipe` / FRR `redistribute`).
//!
//! A [`RedistributionPipe`] bridges routes from one protocol to another:
//! when a route enters the Loc-RIB from the source protocol, the pipe
//! re-originates it into the target protocol with an optional metric
//! override, protocol tag, and prefix-list filter.
//!
//! # Supported pipes
//!
//! | Source     | Target | Mechanism |
//! |-----------|--------|-----------|
//! | BGP       | OSPF   | `ospf_redistribute` (type-5 AS-external LSA) |
//! | BGP       | BGP    | `originate_family` (re-originate as locally originated) |
//! | OSPF      | BGP    | `originate_family` |
//! | Babel     | BGP    | `originate_family` |
//! | Connected | BGP    | `originate_family` |
//! | Static    | BGP    | `originate_family` |
//!
//! OSPF → OSPF and Babel → OSPF pipes are also supported via
//! `ospf_redistribute`. The router tracks which pipes contributed each
//! redistributed route so withdrawals propagate correctly.
//!
//! # Metric policy
//!
//! Each pipe can override the metric:
//! - `MetricPolicy::Inherit` — use the source route's metric.
//! - `MetricPolicy::Fixed(N)` — always advertise N.
//! - `MetricPolicy::Add(N)` — source metric + N (saturating at u32::MAX).
//!
//! # Example
//!
//! ```rust,no_run
//! use lr_router::{DefaultRouter, RedistributionPipe, MetricPolicy};
//! use lr_core::rib::Protocol;
//!
//! let mut r = DefaultRouter::new();
//! // Redistribute BGP routes into OSPF with metric 100.
//! r.add_redistribution_pipe(RedistributionPipe::new(
//!     Protocol::Bgp,
//!     Protocol::Ospfv2,
//! ).with_metric(MetricPolicy::Fixed(100)));
//! // Redistribute OSPF routes into BGP, inheriting the metric.
//! r.add_redistribution_pipe(RedistributionPipe::new(
//!     Protocol::Ospfv2,
//!     Protocol::Bgp,
//! ));
//! ```

use lr_core::rib::Protocol;

/// Metric transformation applied during redistribution.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum MetricPolicy {
    /// Use the source route's metric unchanged.
    #[default]
    Inherit,
    /// Always advertise the given metric, regardless of the source.
    Fixed(u32),
    /// Add the given offset to the source metric (saturating at u32::MAX).
    Add(u32),
}

impl MetricPolicy {
    /// Apply the policy to a source metric.
    pub fn apply(self, source_metric: u32) -> u32 {
        match self {
            Self::Inherit => source_metric,
            Self::Fixed(m) => m,
            Self::Add(offset) => source_metric.saturating_add(offset),
        }
    }
}

/// One redistribution pipe: routes from `source` are re-originated into
/// `target` with the configured metric policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RedistributionPipe {
    /// Source protocol whose Loc-RIB routes are exported.
    pub source: Protocol,
    /// Target protocol into which routes are re-originated.
    pub target: Protocol,
    /// Metric transformation.
    pub metric: MetricPolicy,
    /// Optional protocol tag (BGP community, OSPF route tag, etc.).
    /// Currently informational; the embedder can read it from the pipe.
    pub tag: u32,
    /// Optional prefix-list filter — only routes matching the list are
    /// redistributed. `None` = accept all. The actual filtering is done
    /// by the caller (the router checks `matches` before re-originating).
    /// Stored as a list of `(prefix, prefix_len)` pairs; a route matches
    /// when its prefix is within one of these.
    pub allow_prefixes: Vec<(lr_core::addr::IpAddr, u8)>,
}

impl RedistributionPipe {
    /// Create a new pipe from `source` to `target` with the default
    /// metric policy (inherit).
    pub fn new(source: Protocol, target: Protocol) -> Self {
        Self {
            source,
            target,
            metric: MetricPolicy::Inherit,
            tag: 0,
            allow_prefixes: Vec::new(),
        }
    }

    /// Set the metric policy.
    pub fn with_metric(mut self, metric: MetricPolicy) -> Self {
        self.metric = metric;
        self
    }

    /// Set the protocol tag.
    pub fn with_tag(mut self, tag: u32) -> Self {
        self.tag = tag;
        self
    }

    /// Restrict the pipe to a set of prefixes. A route matches when its
    /// network address falls within one of the listed prefixes.
    pub fn with_allow_prefixes(mut self, prefixes: Vec<(lr_core::addr::IpAddr, u8)>) -> Self {
        self.allow_prefixes = prefixes;
        self
    }

    /// True when `route_prefix` matches the pipe's allow-list (or when
    /// no allow-list is configured).
    pub fn matches(&self, route_prefix: &lr_core::addr::Prefix) -> bool {
        if self.allow_prefixes.is_empty() {
            return true;
        }
        for (addr, plen) in &self.allow_prefixes {
            // Simple containment: the route prefix is within the allow
            // prefix when the allow prefix is shorter and the high bits
            // match.
            if *plen <= route_prefix.prefix_len {
                // Check the high `plen` bits of both addresses match.
                let n = (*plen as usize).div_ceil(8);
                let a = match addr {
                    lr_core::addr::IpAddr::V4(b) => &b[..n.min(4)],
                    lr_core::addr::IpAddr::V6(b) => &b[..n.min(16)],
                };
                let b = match &route_prefix.addr {
                    lr_core::addr::IpAddr::V4(b) => &b[..n.min(4)],
                    lr_core::addr::IpAddr::V6(b) => &b[..n.min(16)],
                };
                if a == b {
                    return true;
                }
            }
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lr_core::addr::{IpAddr, Prefix};

    #[test]
    fn metric_inherit() {
        assert_eq!(MetricPolicy::Inherit.apply(42), 42);
    }

    #[test]
    fn metric_fixed() {
        assert_eq!(MetricPolicy::Fixed(100).apply(42), 100);
        assert_eq!(MetricPolicy::Fixed(0).apply(42), 0);
    }

    #[test]
    fn metric_add() {
        assert_eq!(MetricPolicy::Add(10).apply(42), 52);
        assert_eq!(MetricPolicy::Add(u32::MAX).apply(42), u32::MAX);
    }

    #[test]
    fn pipe_construction() {
        let p = RedistributionPipe::new(Protocol::Bgp, Protocol::Ospfv2)
            .with_metric(MetricPolicy::Fixed(100))
            .with_tag(42);
        assert_eq!(p.source, Protocol::Bgp);
        assert_eq!(p.target, Protocol::Ospfv2);
        assert_eq!(p.metric, MetricPolicy::Fixed(100));
        assert_eq!(p.tag, 42);
    }

    #[test]
    fn matches_no_filter() {
        let p = RedistributionPipe::new(Protocol::Bgp, Protocol::Ospfv2);
        let prefix = Prefix::new_v4([203, 0, 113, 0], 24);
        assert!(p.matches(&prefix));
    }

    #[test]
    fn matches_allow_list() {
        let p = RedistributionPipe::new(Protocol::Bgp, Protocol::Ospfv2)
            .with_allow_prefixes(vec![(IpAddr::V4([203, 0, 113, 0]), 24)]);
        // 203.0.113.0/24 → matches
        assert!(p.matches(&Prefix::new_v4([203, 0, 113, 0], 24)));
        // 203.0.113.128/25 → matches (within /24)
        assert!(p.matches(&Prefix::new_v4([203, 0, 113, 128], 25)));
        // 198.51.100.0/24 → does not match
        assert!(!p.matches(&Prefix::new_v4([198, 51, 100, 0], 24)));
    }

    #[test]
    fn matches_ipv6() {
        let p =
            RedistributionPipe::new(Protocol::Bgp, Protocol::Ospfv2).with_allow_prefixes(vec![(
                IpAddr::V6([0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
                32,
            )]);
        // 2001:db8::/32 → matches
        assert!(p.matches(&Prefix::new_v6(
            [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
            64,
        )));
        // 2001:db9::/32 → does not match
        assert!(!p.matches(&Prefix::new_v6(
            [0x20, 0x01, 0x0d, 0xb9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
            64,
        )));
    }
}
