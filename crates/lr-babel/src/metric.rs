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
}
