//! Community list — matches a set of communities.

use lr_core::rib::Route;

#[derive(Debug, Clone)]
pub struct CommunityListEntry {
    pub communities: Vec<u32>,
    pub permit: bool,
}

#[derive(Default)]
pub struct CommunityList {
    entries: Vec<CommunityListEntry>,
}

impl CommunityList {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn push(&mut self, e: CommunityListEntry) {
        self.entries.push(e);
    }
    pub fn evaluate(&self, _route: &Route) -> bool {
        // TODO: extract route communities from path attrs; simplified.
        true
    }
}

#[derive(Default)]
pub struct CommunityListBank {
    lists: Vec<CommunityList>,
}

impl CommunityListBank {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn add(&mut self, list: CommunityList) {
        self.lists.push(list);
    }
    pub fn evaluate(&self, _id: u32, route: &Route) -> bool {
        // Simplified: always permit (full impl in future revision).
        let _ = route;
        true
    }
}
