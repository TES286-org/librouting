//! Label Information Base: FEC-label bindings per peer.
//!
//! Tracks the two halves of the label distribution control plane:
//! bindings *received* from each peer (the LIB's "remote" half, fed by
//! Label Mapping messages) and bindings *advertised* to peers (fed by
//! the embedder's local label allocation). Withdrawals and releases
//! keep both halves in step; a session teardown purges everything
//! learned from that peer.
//!
//! Bindings are keyed by prefix FEC. Wildcard withdrawals (RFC 5036
//! §3.5.10.1) remove either every binding for a label or every binding
//! received from the peer.

use crate::pdu::LdpId;
use crate::tlv::GenericLabel;
use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use lr_core::addr::Prefix;

/// The key for a binding: the prefix FEC element. The local/remote
/// distinction comes from which map the key lives in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct FecKey {
    pub prefix: Prefix,
}

impl FecKey {
    pub fn new(prefix: Prefix) -> Self {
        Self { prefix }
    }
}

/// The label information base.
#[derive(Debug, Clone, Default)]
pub struct LabelMappingStore {
    /// Bindings received from peers: peer → (FEC → label).
    received: BTreeMap<LdpId, BTreeMap<FecKey, GenericLabel>>,
    /// Locally advertised bindings: FEC → label.
    advertised: BTreeMap<FecKey, GenericLabel>,
}

impl LabelMappingStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a binding learned from a peer (Label Mapping). Returns
    /// `true` when the binding is new for that (peer, FEC) pair.
    pub fn learn(&mut self, peer: LdpId, key: FecKey, label: GenericLabel) -> bool {
        self.received
            .entry(peer)
            .or_default()
            .insert(key, label)
            .is_none()
    }

    /// Remove a binding learned from a peer (Label Withdraw / Release).
    /// Returns the removed label when a binding existed.
    pub fn unlearn(&mut self, peer: LdpId, key: &FecKey) -> Option<GenericLabel> {
        self.received.get_mut(&peer)?.remove(key)
    }

    /// Remove every binding learned from a peer (session teardown).
    /// Returns the removed count.
    pub fn unlearn_peer(&mut self, peer: LdpId) -> usize {
        self.received.remove(&peer).map(|m| m.len()).unwrap_or(0)
    }

    /// Remove every binding for a label learned from a peer (wildcard
    /// withdraw with a Label TLV, §3.5.10.1). Returns the removed FECs.
    pub fn unlearn_by_label(&mut self, peer: LdpId, label: GenericLabel) -> Vec<FecKey> {
        let mut removed = Vec::new();
        if let Some(bindings) = self.received.get_mut(&peer) {
            removed.extend(
                bindings
                    .iter()
                    .filter(|(_, l)| **l == label)
                    .map(|(k, _)| *k),
            );
            for k in &removed {
                bindings.remove(k);
            }
        }
        removed
    }

    /// Remove every binding learned from a peer (wildcard withdraw
    /// without a Label TLV). Returns the removed FECs.
    pub fn unlearn_all_from(&mut self, peer: LdpId) -> Vec<FecKey> {
        let mut removed = Vec::new();
        if let Some(bindings) = self.received.get_mut(&peer) {
            removed.extend(bindings.keys().copied());
            bindings.clear();
        }
        removed
    }

    /// The label a peer bound to a FEC, when known.
    pub fn label_from(&self, peer: LdpId, key: &FecKey) -> Option<GenericLabel> {
        self.received.get(&peer)?.get(key).copied()
    }

    /// Record a locally advertised binding (the embedder's label
    /// allocation). Returns the previous binding for the FEC, if any.
    pub fn advertise(&mut self, key: FecKey, label: GenericLabel) -> Option<GenericLabel> {
        self.advertised.insert(key, label)
    }

    /// Remove a locally advertised binding (Label Withdraw side).
    pub fn withdraw_advertised(&mut self, key: &FecKey) -> Option<GenericLabel> {
        self.advertised.remove(key)
    }

    /// The locally advertised label for a FEC, when any.
    pub fn advertised_label(&self, key: &FecKey) -> Option<GenericLabel> {
        self.advertised.get(key).copied()
    }

    /// All locally advertised bindings.
    pub fn advertised_bindings(&self) -> impl Iterator<Item = (&FecKey, &GenericLabel)> {
        self.advertised.iter()
    }

    /// All bindings received from one peer.
    pub fn bindings_from(&self, peer: LdpId) -> impl Iterator<Item = (&FecKey, &GenericLabel)> {
        self.received.get(&peer).into_iter().flat_map(|m| m.iter())
    }

    /// The peers with at least one learned binding.
    pub fn peers(&self) -> impl Iterator<Item = LdpId> + '_ {
        self.received.keys().copied()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn peer(v: u8) -> LdpId {
        LdpId::new([v, 0, 0, 1], 0)
    }

    fn fec(octet: u8) -> FecKey {
        FecKey::new(Prefix::new_v4([10, 0, 0, octet], 24))
    }

    #[test]
    fn learn_and_unlearn() {
        let mut lib = LabelMappingStore::new();
        assert!(lib.learn(peer(2), fec(1), GenericLabel(100)));
        // Re-learning the same binding is not "new".
        assert!(!lib.learn(peer(2), fec(1), GenericLabel(100)));
        assert_eq!(lib.label_from(peer(2), &fec(1)), Some(GenericLabel(100)));
        assert_eq!(lib.unlearn(peer(2), &fec(1)), Some(GenericLabel(100)));
        assert_eq!(lib.label_from(peer(2), &fec(1)), None);
        assert_eq!(lib.unlearn(peer(2), &fec(1)), None);
    }

    #[test]
    fn per_peer_isolation() {
        let mut lib = LabelMappingStore::new();
        let _ = lib.learn(peer(2), fec(1), GenericLabel(100));
        let _ = lib.learn(peer(3), fec(1), GenericLabel(200));
        assert_eq!(lib.label_from(peer(2), &fec(1)), Some(GenericLabel(100)));
        assert_eq!(lib.label_from(peer(3), &fec(1)), Some(GenericLabel(200)));
        assert_eq!(lib.unlearn_peer(peer(2)), 1);
        assert_eq!(lib.label_from(peer(2), &fec(1)), None);
        assert_eq!(lib.label_from(peer(3), &fec(1)), Some(GenericLabel(200)));
    }

    #[test]
    fn wildcard_by_label() {
        let mut lib = LabelMappingStore::new();
        let _ = lib.learn(peer(2), fec(1), GenericLabel(100));
        let _ = lib.learn(peer(2), fec(2), GenericLabel(100));
        let _ = lib.learn(peer(2), fec(3), GenericLabel(101));
        let removed = lib.unlearn_by_label(peer(2), GenericLabel(100));
        assert_eq!(removed.len(), 2);
        assert!(removed.contains(&fec(1)));
        assert!(removed.contains(&fec(2)));
        assert_eq!(lib.label_from(peer(2), &fec(3)), Some(GenericLabel(101)));
    }

    #[test]
    fn wildcard_all_from_peer() {
        let mut lib = LabelMappingStore::new();
        let _ = lib.learn(peer(2), fec(1), GenericLabel(100));
        let _ = lib.learn(peer(2), fec(2), GenericLabel(101));
        let _ = lib.learn(peer(3), fec(3), GenericLabel(102));
        let removed = lib.unlearn_all_from(peer(2));
        assert_eq!(removed.len(), 2);
        assert_eq!(lib.bindings_from(peer(2)).count(), 0);
        assert_eq!(lib.bindings_from(peer(3)).count(), 1);
    }

    #[test]
    fn advertised_half() {
        let mut lib = LabelMappingStore::new();
        assert_eq!(lib.advertise(fec(1), GenericLabel(16)), None);
        assert_eq!(lib.advertised_label(&fec(1)), Some(GenericLabel(16)));
        // Re-advertising replaces.
        assert_eq!(
            lib.advertise(fec(1), GenericLabel(17)),
            Some(GenericLabel(16))
        );
        assert_eq!(lib.withdraw_advertised(&fec(1)), Some(GenericLabel(17)));
        assert_eq!(lib.advertised_label(&fec(1)), None);
    }

    #[test]
    fn peers_listing() {
        let mut lib = LabelMappingStore::new();
        let _ = lib.learn(peer(2), fec(1), GenericLabel(100));
        let _ = lib.learn(peer(3), fec(1), GenericLabel(100));
        let peers: Vec<_> = lib.peers().collect();
        assert_eq!(peers, Vec::from([peer(2), peer(3)]));
    }
}
