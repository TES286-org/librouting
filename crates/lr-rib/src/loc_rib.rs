//! Loc-RIB — post-policy best routes.

use std::collections::BTreeMap;

use lr_core::rib::{Route, RouteKey};

/// Generation counter — callers can ask "what changed since generation X?"
#[derive(Debug, Default, Clone)]
pub struct RibDiff {
    pub added: Vec<Route>,
    pub removed: Vec<RouteKey>,
    pub modified: Vec<Route>,
}

/// Local RIB after policy. Stores best route per key.
#[derive(Default)]
pub struct LocRib {
    inner: BTreeMap<RouteKey, Route>,
    gen: u64,
    /// History of (gen, change) — keeps last 16 diffs.
    history: std::collections::VecDeque<(u64, RibDiff)>,
}

impl LocRib {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn install(&mut self, route: Route) {
        let key = route.key.clone();
        let prev = self.inner.insert(key.clone(), route.clone());
        self.gen += 1;
        let diff = match prev {
            None => RibDiff {
                added: vec![route],
                removed: vec![],
                modified: vec![],
            },
            Some(_) => RibDiff {
                added: vec![],
                removed: vec![],
                modified: vec![route],
            },
        };
        self.push_history(diff);
    }

    pub fn uninstall(&mut self, key: &RouteKey) -> Option<Route> {
        let r = self.inner.remove(key);
        if r.is_some() {
            self.gen += 1;
            self.push_history(RibDiff {
                added: vec![],
                removed: vec![key.clone()],
                modified: vec![],
            });
        }
        r
    }

    fn push_history(&mut self, diff: RibDiff) {
        if self.history.len() >= 16 {
            self.history.pop_front();
        }
        self.history.push_back((self.gen, diff));
    }

    pub fn best(&self, key: &RouteKey) -> Option<&Route> {
        self.inner.get(key)
    }

    pub fn iter_best(&self) -> impl Iterator<Item = &Route> {
        self.inner.values()
    }

    pub fn len(&self) -> usize {
        self.inner.len()
    }
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }
    pub fn generation(&self) -> u64 {
        self.gen
    }

    /// All changes since `gen`.
    pub fn diff_since(&self, gen: u64) -> RibDiff {
        let mut out = RibDiff::default();
        for (g, d) in self.history.iter().rev() {
            if *g <= gen {
                break;
            }
            out.added.extend(d.added.iter().cloned());
            out.removed.extend(d.removed.iter().cloned());
            out.modified.extend(d.modified.iter().cloned());
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lr_core::addr::Prefix;
    use lr_core::nlri::NlriFamily;
    use lr_core::rib::{Preference, Protocol, Route, RouteOrigin};

    fn route(p: [u8; 4], pl: u8) -> Route {
        Route {
            key: RouteKey::new(Prefix::new_v4(p, pl), NlriFamily::IPV4_UNICAST),
            origin: RouteOrigin { proto: 1, peer: 1 },
            protocol: Protocol::Bgp,
            preference: Preference::new(20, 0),
            next_hop: None,
            attributes: lr_core::attr::Attributes::new(),
            age_ms: 0,
        }
    }

    #[test]
    fn install_and_diff() {
        let mut rib = LocRib::new();
        let before = rib.generation();
        rib.install(route([10, 0, 0, 0], 8));
        rib.install(route([192, 168, 0, 0], 24));
        let diff = rib.diff_since(before);
        assert_eq!(diff.added.len(), 2);
        rib.uninstall(&route([10, 0, 0, 0], 8).key);
        let diff2 = rib.diff_since(rib.generation() - 1);
        assert_eq!(diff2.removed.len(), 1);
    }
}
