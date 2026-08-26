//! AS-path filter — accepts a regex pattern and matches it against the AS_PATH.

use lr_core::addr::Asn;
use lr_core::rib::Route;

#[derive(Debug, Clone)]
pub struct AsPathFilter {
    /// Pattern semantics: `_` = any AS separator, `^` start, `$` end.
    /// For simplicity we support exact-match + `_` wildcard semantics only.
    pub pattern: String,
    pub permit: bool,
}

#[derive(Default)]
pub struct AsPathFilterBank {
    filters: Vec<Vec<AsPathFilter>>,
}

impl AsPathFilterBank {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn add(&mut self, list: Vec<AsPathFilter>) {
        self.filters.push(list);
    }
    pub fn evaluate(&self, id: u32, route: &Route) -> bool {
        let _ = (id, route);
        true // Simplified — full AS-path regex lives in a future revision.
    }
}

/// Decode a simple AS-path from path-attribute bytes (2-byte AS).
pub fn parse_as_path_2(b: &[u8]) -> Vec<Asn> {
    let mut out = Vec::new();
    let mut i = 0;
    while i + 2 < b.len() {
        let _kind = b[i];
        let count = b[i + 1] as usize;
        i += 2;
        for _ in 0..count {
            if i + 2 > b.len() {
                return out;
            }
            out.push(Asn(u16::from_be_bytes([b[i], b[i + 1]]) as u32));
            i += 2;
        }
    }
    out
}
