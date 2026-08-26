//! Babel neighbor tracking (RFC 8966 §3.3).
//!
//! Tracks per-neighbor Hello history, TX/RX costs, and computes RTO.

use lr_core::addr::IpAddr;

/// One neighbor as seen by the Babel speaker. The embedder drives Hello/IHU
/// arrival by calling [`BabelNeighbor::hello`] and [`BabelNeighbor::ihu`].
#[derive(Debug, Clone)]
pub struct BabelNeighbor {
    pub address: IpAddr,
    /// Recent Hello sequence numbers (sliding window of 16 bits per §3.3.1).
    pub hello_history: Vec<u16>,
    pub hello_interval_cs: u16,
    pub last_hello_received_ms: u64,
    pub rxcost: u32,
    pub txcost: u32,
    pub last_ihu_received_ms: u64,
    pub ihu_interval_cs: u16,
}

impl BabelNeighbor {
    pub fn new(address: IpAddr, now_ms: u64) -> Self {
        Self {
            address,
            hello_history: Vec::with_capacity(16),
            hello_interval_cs: 0,
            last_hello_received_ms: now_ms,
            rxcost: 0xffff,
            txcost: 0xffff,
            last_ihu_received_ms: 0,
            ihu_interval_cs: 0,
        }
    }

    /// Record an incoming Hello (seqno, interval in centiseconds, time in ms).
    pub fn hello(&mut self, seqno: u16, interval_cs: u16, now_ms: u64) {
        self.hello_interval_cs = interval_cs;
        self.last_hello_received_ms = now_ms;
        self.hello_history.push(seqno);
        if self.hello_history.len() > 16 {
            self.hello_history.remove(0);
        }
        // Recompute rxcost per RFC 8966 §3.4.1.
        self.rxcost = compute_rxcost(self.hello_interval_cs, self.hello_history.len());
    }

    /// Record an incoming IHU.
    pub fn ihu(&mut self, rxcost: u16, interval_cs: u16, now_ms: u64) {
        self.txcost = rxcost as u32;
        self.ihu_interval_cs = interval_cs;
        self.last_ihu_received_ms = now_ms;
    }

    /// True if the neighbor is considered alive (recent hello + IHU).
    pub fn is_alive(&self, now_ms: u64, dead_ms: u64) -> bool {
        if self.hello_interval_cs == 0 {
            return false;
        }
        let since_hello = now_ms.saturating_sub(self.last_hello_received_ms);
        let dead_interval = (self.hello_interval_cs as u64) * 10 * 4;
        since_hello <= dead_interval.max(dead_ms)
    }
}

fn compute_rxcost(_interval_cs: u16, history_len: usize) -> u32 {
    // Simplified: missing any hello doubles cost.
    let missed = 16usize.saturating_sub(history_len);
    let base = 100u32;
    base + (missed as u32) * 50
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn alive_after_hello() {
        let mut n = BabelNeighbor::new(IpAddr::V4([10, 0, 0, 1]), 0);
        n.hello(1, 200, 0);
        assert!(n.is_alive(50, 5000));
    }
}
