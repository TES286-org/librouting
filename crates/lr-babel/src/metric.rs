//! Babel metric algebra (RFC 8966 §3.1).
//!
//! Metrics are 16-bit "small" and 32-bit "large" values. The link cost is
//! derived from rxcost (RFC 8966 §3.4.3). Realisability is the feasibility
//! condition from §3.2.2.

/// Compute the link cost from a peer's RX cost at our interface.
pub fn link_cost(rxcost: u16) -> u32 {
    // RFC 8966 §3.4.2 defines link cost as the smaller of rxcost and 0xffff;
    // in practice we just use rxcost as a 16-bit metric.
    rxcost as u32
}

/// The RTT-based extra link cost (RFC 8966 §A.2.4, BABEL-RTT): a linear
/// ramp from 0 at `rtt_min_us` to `max_penalty` at `rtt_max_us`, clamped
/// at `max_penalty` above it. `max_penalty == 0` disables the feature
/// (babeld's `max-rtt-penalty 0`); degenerate `rtt_min_us == rtt_max_us`
/// saturates instead of dividing by zero.
pub fn rtt_penalty(rtt_us: u32, rtt_min_us: u32, rtt_max_us: u32, max_penalty: u16) -> u16 {
    if max_penalty == 0 {
        return 0;
    }
    if rtt_us <= rtt_min_us {
        0
    } else if rtt_us >= rtt_max_us {
        max_penalty
    } else {
        u32::from(max_penalty)
            .saturating_mul(rtt_us - rtt_min_us)
            .checked_div(rtt_max_us - rtt_min_us)
            .map(|v| v.min(u32::from(u16::MAX)) as u16)
            .unwrap_or(max_penalty)
    }
}

/// Compute the total route metric: cost to destination = sum of link costs.
pub fn route_metric(link_metrics: &[u32]) -> u32 {
    link_metrics.iter().sum()
}

/// Feasibility condition (RFC 8966 §3.2.2): a route is feasible iff its
/// (seqno, metric) pair is strictly better than the current best-known
/// feasible metric for the same source.
pub fn feasible(
    route_seqno: u16,
    route_metric: u32,
    feasible_seqno: u16,
    feasible_metric: u32,
) -> bool {
    let seqno_cmp = (route_seqno as i16).wrapping_sub(feasible_seqno as i16);
    if seqno_cmp > 0 {
        return true;
    }
    if seqno_cmp == 0 {
        return route_metric < feasible_metric;
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn feasibility_basics() {
        // Route with newer seqno is feasible regardless of metric.
        assert!(feasible(10, 1000, 9, 100));
        // Same seqno, lower metric is feasible.
        assert!(feasible(10, 50, 10, 100));
        // Same seqno, equal or higher metric is NOT feasible.
        assert!(!feasible(10, 100, 10, 100));
        assert!(!feasible(10, 200, 10, 100));
        // Older seqno is not feasible regardless of metric.
        assert!(!feasible(9, 50, 10, 100));
    }

    #[test]
    fn rtt_penalty_ramp() {
        // §A.2.4: linear between the bounds, zero below min, saturating
        // at the penalty above max.
        assert_eq!(rtt_penalty(0, 10_000, 120_000, 96), 0);
        assert_eq!(rtt_penalty(10_000, 10_000, 120_000, 96), 0);
        assert_eq!(rtt_penalty(65_000, 10_000, 120_000, 96), 48); // 96*55/110
        assert_eq!(rtt_penalty(120_000, 10_000, 120_000, 96), 96);
        assert_eq!(rtt_penalty(500_000, 10_000, 120_000, 96), 96);
        // Penalty 0 disables the feature entirely.
        assert_eq!(rtt_penalty(500_000, 10_000, 120_000, 0), 0);
        // Degenerate bounds saturate rather than divide by zero. The
        // `rtt <= min` branch wins at exactly the bound (babeld's
        // ordering); one microsecond above it saturates.
        assert_eq!(rtt_penalty(50_000, 50_000, 50_000, 96), 0);
        assert_eq!(rtt_penalty(49_999, 50_000, 50_000, 96), 0);
        assert_eq!(rtt_penalty(50_001, 50_000, 50_000, 96), 96);
    }
}
