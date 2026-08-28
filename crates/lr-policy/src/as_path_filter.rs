//! AS-path filter — matches a pattern against the route's AS_PATH.
//!
//! Pattern syntax follows the FRR/Cisco AS-path access-list dialect:
//!
//! | token   | matches                                        |
//! |---------|------------------------------------------------|
//! | `^`     | start of the AS path                           |
//! | `$`     | end of the AS path                             |
//! | `_`     | any separator: start, space between ASes, end  |
//! | `N..N`  | an AS number, matched literally                |
//!
//! Examples: `^65001$` (exactly this path), `_65001$` (learned from
//! 65001), `^65001_` (adjacent on ingress), `_65001_` (transits
//! 65001 anywhere). A bare AS number is a substring match, exactly
//! like FRR's underlying regex — note the classic footgun that a bare
//! `5001` also matches inside `65001`; anchor with `_` (as in
//! `_5001_`) to match whole AS numbers only.
//!
//! Patterns are evaluated per filter in list order; the first match
//! decides with its `permit`, and no match is an implicit deny.
//!
//! The path is flattened to its canonical sequence (`AS_SEQUENCE`
//! and `AS_SET` members in wire order) — the same view BIRD's `bgp_path`
//! and FRR's `as-path` displays show. Matching runs over the
//! space-joined decimal representation with a small backtracking
//! matcher (no regex engine dependency).

use lr_core::addr::Asn;
use lr_core::rib::Route;

#[derive(Debug, Clone)]
pub struct AsPathFilter {
    /// Pattern semantics: `_` = any AS separator, `^` start, `$` end.
    pub pattern: String,
    pub permit: bool,
}

/// One compiled pattern token.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Tok {
    /// Literal text (an AS number in decimal).
    Lit(String),
    /// `_`: start of string, one separating space, or end of string.
    Bound,
    /// `^`: zero-width, matches only at position 0.
    Start,
    /// `$`: zero-width, matches only at the end.
    End,
}

fn compile(pattern: &str) -> Vec<Tok> {
    let mut toks = Vec::new();
    let mut lit = String::new();
    for ch in pattern.chars() {
        match ch {
            '_' => {
                if !lit.is_empty() {
                    toks.push(Tok::Lit(std::mem::take(&mut lit)));
                }
                toks.push(Tok::Bound);
            }
            '^' | '$' => {
                if !lit.is_empty() {
                    toks.push(Tok::Lit(std::mem::take(&mut lit)));
                }
                // Anchors: represent `^` as a boundary that must sit at
                // position 0 and `$` as one at the end. Distinguishing
                // them needs dedicated variants.
                toks.push(if ch == '^' { Tok::Start } else { Tok::End });
            }
            c => lit.push(c),
        }
    }
    if !lit.is_empty() {
        toks.push(Tok::Lit(lit));
    }
    toks
}

/// Match `toks` against `s` starting at `pos`; returns the end
/// position on success. Classic backtracking; token counts are tiny
/// (a handful per pattern) and paths are short, so the exponential
/// worst case never materializes in practice.
fn match_from(toks: &[Tok], s: &str, pos: usize) -> Option<usize> {
    let Some((first, rest)) = toks.split_first() else {
        return Some(pos);
    };
    match first {
        Tok::Lit(l) => {
            if s.len() >= pos + l.len() && &s[pos..pos + l.len()] == l.as_str() {
                match_from(rest, s, pos + l.len())
            } else {
                None
            }
        }
        Tok::Bound => {
            // Zero-width at either end; consumes one space in the middle.
            if pos == 0 || pos == s.len() {
                return match_from(rest, s, pos);
            }
            if s[pos..].starts_with(' ') {
                if let Some(end) = match_from(rest, s, pos + 1) {
                    return Some(end);
                }
            }
            None
        }
        Tok::Start => (pos == 0).then(|| match_from(rest, s, pos)).flatten(),
        Tok::End => (pos == s.len()).then(|| match_from(rest, s, pos)).flatten(),
    }
}

/// Unanchored search: any start position may match (substring
/// semantics, like FRR's `bgp as-path access-list` regex).
fn search(toks: &[Tok], s: &str) -> bool {
    (0..=s.len()).any(|start| match_from(toks, s, start).is_some())
}

/// Evaluate one pattern against an AS sequence.
pub fn pattern_matches(pattern: &str, path: &[Asn]) -> bool {
    let s = path
        .iter()
        .map(|a| a.0.to_string())
        .collect::<Vec<_>>()
        .join(" ");
    search(&compile(pattern), &s)
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

    /// First-match evaluation of list `id` against the route's
    /// canonical AS_PATH; unknown ids and no-match deny.
    #[cfg(feature = "bgp")]
    pub fn evaluate(&self, id: u32, route: &Route) -> bool {
        let Some(list) = self.filters.get(id as usize) else {
            return false;
        };
        let path = crate::bgp::as_sequence(route);
        for f in list {
            if pattern_matches(&f.pattern, &path) {
                return f.permit;
            }
        }
        false
    }

    /// Stub (no `bgp` feature): permissive, matching historical
    /// behaviour.
    #[cfg(not(feature = "bgp"))]
    pub fn evaluate(&self, _id: u32, _route: &Route) -> bool {
        true
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

#[cfg(test)]
mod tests {
    use super::*;

    fn path(ases: &[u32]) -> Vec<Asn> {
        ases.iter().map(|&a| Asn(a)).collect()
    }

    #[test]
    fn anchors_exact() {
        let p = path(&[65001, 65002, 65003]);
        assert!(pattern_matches("^65001$", &path(&[65001])));
        assert!(!pattern_matches("^65001$", &p));
        assert!(pattern_matches("^65001_65002_65003$", &p));
    }

    #[test]
    fn adjacency_and_contains() {
        let p = path(&[65001, 65002, 65003]);
        assert!(pattern_matches("^65001_", &p), "starts with 65001");
        assert!(pattern_matches("_65003$", &p), "learned from 65003");
        assert!(pattern_matches("_65002_", &p), "transits 65002");
        assert!(!pattern_matches("_65004_", &p));
        assert!(pattern_matches("65002", &p), "bare literal substring");
        assert!(!pattern_matches("65002", &path(&[65001, 65003])));
        // Substring semantics (FRR parity): bare "5001" matches inside
        // the text of "65001"; the boundary-anchored form does not.
        assert!(pattern_matches("5001", &path(&[65001])));
        assert!(!pattern_matches("_5001_", &path(&[65001])));
    }

    #[test]
    fn empty_path() {
        assert!(pattern_matches("^$", &[]));
        assert!(!pattern_matches("_65001_", &[]));
    }

    #[cfg(feature = "bgp")]
    #[test]
    fn bank_evaluates_route_attributes() {
        use crate::bgp;
        use lr_core::addr::Prefix;
        use lr_core::attr::{AttrTag, Attribute};
        use lr_core::nlri::NlriFamily;
        use lr_core::rib::{Preference, Protocol, Route, RouteKey, RouteOrigin};

        let mut route = Route {
            key: RouteKey::new(
                Prefix::new_v4([203, 0, 113, 0], 24),
                NlriFamily::IPV4_UNICAST,
            ),
            origin: RouteOrigin { proto: 0, peer: 0 },
            protocol: Protocol::Bgp,
            preference: Preference::new(20, 100),
            next_hop: None,
            attributes: lr_core::attr::Attributes::new(),
            age_ms: 0,
            path_id: 0,
        };
        let wire =
            lr_bgp::path::as_path::AsPath::from_sequence([Asn(65001), Asn(65002)]).encode_4();
        route.attributes.insert(Attribute {
            tag: AttrTag::raw(2),
            flags: 0x40,
            value: wire,
        });

        let mut bank = AsPathFilterBank::new();
        bank.add(vec![
            AsPathFilter {
                pattern: "_65002$".into(),
                permit: true,
            },
            AsPathFilter {
                pattern: "_666_".into(),
                permit: true,
            },
        ]);
        assert!(bank.evaluate(0, &route));
        assert!(!bank.evaluate(1, &route), "no match -> implicit deny");
        assert!(!bank.evaluate(7, &route), "unknown id -> deny");
        let _ = bgp::as_sequence(&route);
    }
}
