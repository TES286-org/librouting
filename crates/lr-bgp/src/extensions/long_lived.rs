//! Long-Lived Graceful Restart (RFC 9494).
//!
//! LLGR extends RFC 4724 graceful restart with a *second*, usually much
//! longer retention window per address family. Wire support lives in
//! [`crate::capabilities::Capability::long_lived_gr`] (capability 71);
//! this module maps the RFC 9494 procedures onto the librouting pipeline:
//!
//! | RFC section | Requirement | Implementation |
//! |-------------|-------------|-----------------|
//! | §3.1 | LLGR capability, 7-byte `<AFI, SAFI, Flags(F), LLST>` tuples | `Capability::long_lived_gr` / `as_long_lived_gr` |
//! | §3.2 | `LLGR_STALE` (0xFFFF0006) marks long-lived stale routes | `Community::LLGR_STALE`, attached by `lr-router` |
//! | §3.3 | `NO_LLGR` (0xFFFF0007) opts a route out of LLGR | `Community::NO_LLGR`, honoured at retention time |
//! | §4.1 | LLGR without GR capability is ignored | [`crate::fsm::BgpPeer::llgr_negotiated`] |
//! | §4.2 | Retention = Restart Time + LLST, applied serially | `lr-router` retention state machine |
//! | §4.2 | After Restart Time, attach LLGR_STALE + readvertise | `lr-router` marks the session's Adj-RIB-In routes |
//! | §4.2 | NO_LLGR routes are never retained | `lr-router` drops them when LLGR begins |
//! | §4.2 | LLST timer survives re-establishment until EoR | `lr-router` clears retention on End-of-RIB |
//! | §4.3 | LLGR_STALE routes are least preferred | `lr-bgp::best_path` first comparison |
//! | §4.3 | No LLGR_STALE advertisement to non-LLGR neighbors | `lr-bgp::advertise` egress gate |
//! | §4.3 | LLGR_STALE is never stripped on readvertisement | egress passes COMMUNITIES through |
//!
//! The restarting speaker advertises its Restart Time (RFC 4724) and LLST
//! in OPEN; helpers retain the speaker's routes for the sum of both
//! timers, marking routes with LLGR_STALE once the GR window elapses.

#![allow(dead_code)]

use crate::capabilities::Capability;
use crate::peer::PeerConfig;

use lr_core::nlri::NlriFamily;

/// F bit (RFC 9494 §3.1): set when the speaker preserved its forwarding
/// state across the restart being signalled.
pub const FLAG_FORWARDING: u8 = 0x80;

/// Families a restart-related capability (RFC 4724 §3 GR, RFC 9494 §3.1
/// LLGR) should list for a peer: the negotiated MP-BGP families, or
/// implicit `<IPv4, Unicast>` when the session uses RFC 4271 encoding
/// only (RFC 9494 §3.1).
pub fn advertised_families(cfg: &PeerConfig) -> Vec<NlriFamily> {
    if cfg.mp_families.is_empty() {
        vec![NlriFamily::IPV4_UNICAST]
    } else {
        cfg.mp_families.clone()
    }
}

/// Build the LLGR capability for a configured peer. Returns `None` when
/// LLGR is not usable: RFC 9494 §4.1 requires the Graceful Restart
/// capability to accompany LLGR, so a session with `long_lived` set but
/// graceful restart disabled must not advertise it.
pub fn open_capability(cfg: &PeerConfig) -> Option<Capability> {
    if !cfg.long_lived || !cfg.graceful_restart {
        return None;
    }
    let families: Vec<(u16, u8, bool, u32)> = advertised_families(cfg)
        .into_iter()
        .map(|f| (f.afi, f.safi, true, cfg.long_lived_stale_time))
        .collect();
    Some(Capability::long_lived_gr(&families))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capabilities::CapabilityCode;
    use crate::peer::PeerConfig;
    use lr_core::addr::{Asn, RouterId};

    fn cfg() -> PeerConfig {
        PeerConfig::new(Asn(64512), Asn(64513), RouterId::from_v4([10, 0, 0, 1]))
    }

    #[test]
    fn llgr_requires_graceful_restart() {
        // RFC 9494 §4.1: no GR capability ⇒ no LLGR capability.
        let mut c = cfg();
        c.long_lived = true;
        c.long_lived_stale_time = 3600;
        assert!(open_capability(&c).is_none());
        c.graceful_restart = true;
        assert!(open_capability(&c).is_some());
    }

    #[test]
    fn implicit_ipv4_family_when_no_mp_families() {
        let mut c = cfg();
        c.graceful_restart = true;
        c.long_lived = true;
        c.long_lived_stale_time = 3600;
        let cap = open_capability(&c).unwrap();
        assert_eq!(cap.code, CapabilityCode::LongLivedGracefulRestart);
        let tuples = cap.as_long_lived_gr().unwrap();
        assert_eq!(tuples, vec![(1, 1, true, 3600)]);
    }

    #[test]
    fn mp_families_listed_per_family() {
        let mut c = cfg();
        c.graceful_restart = true;
        c.long_lived = true;
        c.long_lived_stale_time = 60;
        c.mp_families = vec![NlriFamily::IPV4_UNICAST, NlriFamily::IPV6_UNICAST];
        let tuples = open_capability(&c).unwrap().as_long_lived_gr().unwrap();
        assert_eq!(tuples.len(), 2);
        assert_eq!(tuples[0].0, 1);
        assert_eq!(tuples[1].0, 2);
    }
}
