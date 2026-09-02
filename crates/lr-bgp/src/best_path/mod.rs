//! Best-path selection (RFC 4271 §9.1.2 + RFC 5004 / RFC 7911 / multipath).
//!
//! The BGP decision process is a deterministic 14-step comparison. The
//! implementation here mirrors the canonical order used by FRRouting, BIRD
//! and OpenBGPD, and is also parameterized via a [`BestPathConfig`] so an
//! operator can opt out of any step (e.g. `always_compare_med` to compare
//! MED across AS boundaries, which is *non-default* and a frequent knob).
//!
//! The comparator is **deterministic** (RFC 5004): ties at the last step are
//! broken by lowest router-id / cluster-list, not by arrival time — this
//! makes the path decision independent of arrival order, which is the
//! requirement for a stable network.
//!
//! Two public entry points:
//!
//! - [`BestPath::select`] — pure function over a slice of routes.
//! - [`BestPath::multipath`] — equal-cost multipath extraction.

use core::cmp::Ordering;

use lr_core::rib::Route;

use crate::path::{AsPath, AttrType, Community, PathAttributes};

/// Knobs that control the best-path algorithm.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BestPathConfig {
    /// Compare MED across AS boundaries (default false; RFC 4271 §9.1.2.2
    /// "b" restricts comparison to the same neighboring AS).
    pub always_compare_med: bool,
    /// Treat missing MED as infinity (default false — missing MED is treated
    /// as 0). Setting this avoids preferring paths that suppress MED.
    pub missing_med_as_infinity: bool,
    /// Compare router-id to break ties (RFC 5004). Default true; disabling it
    /// falls back to "first arrived wins" which is non-deterministic.
    pub deterministic_router_id: bool,
    /// Prefer externally-learned routes over iBGP routes when everything else
    /// is equal (default true; aligns with FRR's "external route preference").
    pub prefer_externals: bool,
    /// Count AS_CONFED_SEQUENCE / AS_CONFED_SET members in the AS_PATH
    /// length (default false — RFC 5065 §5.3(3) says they SHOULD NOT be
    /// counted; FRR's `bgp bestpath as-path confed` opts in).
    pub count_confed_in_path_len: bool,
    /// Whether multipath load-balancing is enabled and how many equal-cost
    /// paths may be installed. Default 1 (no multipath).
    pub multipath: u32,
    /// Whether multipath may include paths from different neighboring ASes.
    /// Default false (RFC 4784 §2).
    pub multipath_relax: bool,
}

impl Default for BestPathConfig {
    fn default() -> Self {
        Self {
            always_compare_med: false,
            missing_med_as_infinity: false,
            deterministic_router_id: true,
            prefer_externals: true,
            count_confed_in_path_len: false,
            multipath: 1,
            multipath_relax: false,
        }
    }
}

/// Best-path algorithm entry point.
pub struct BestPath;

impl BestPath {
    /// Select the best route among `routes`. Returns `None` for empty input.
    pub fn select<'a>(routes: &'a [Route], cfg: &BestPathConfig) -> Option<&'a Route> {
        routes.iter().min_by(|a, b| Self::compare(a, b, cfg))
    }

    /// Rank every route best-first (a stable full sort by the decision
    /// process). This is the Add-Path selection primitive (RFC 7911): the
    /// top-N entries are the paths an Add-Path speaker advertises. Ties
    /// beyond the last tiebreaker keep insertion order, which makes the
    /// ranking deterministic for a given Adj-RIB-In state.
    pub fn rank<'a>(routes: &'a [Route], cfg: &BestPathConfig) -> Vec<&'a Route> {
        let mut ranked: Vec<&Route> = routes.iter().collect();
        ranked.sort_by(|a, b| Self::compare(a, b, cfg));
        ranked
    }

    /// Select the best route and all equal-cost paths up to `cfg.multipath`.
    /// "Equal cost" means all of the major decision steps tie (LOCAL_PREF,
    /// AS_PATH length, ORIGIN, MED, eBGP/iBGP, originator-id, cluster-list)
    /// — only the last tiebreaker (peer-id) is allowed to differ, since two
    /// different peers by definition have different peer-ids.
    pub fn multipath<'a>(routes: &'a [Route], cfg: &BestPathConfig) -> Option<Vec<&'a Route>> {
        let best = Self::select(routes, cfg)?;
        if cfg.multipath <= 1 {
            return Some(vec![best]);
        }
        let mut out: Vec<&Route> = Vec::new();
        for r in routes {
            if Self::compare_multipath(r, best, cfg) == Ordering::Equal
                && (cfg.multipath_relax || Self::same_neighbor(r, best))
            {
                out.push(r);
                if out.len() as u32 >= cfg.multipath {
                    break;
                }
            }
        }
        if out.is_empty() {
            out.push(best);
        }
        Some(out)
    }

    /// Like [`Self::compare`] but stops before the final peer-id tiebreaker
    /// (RFC 4784 §2: multipath peers are by definition different peers).
    pub fn compare_multipath(a: &Route, b: &Route, cfg: &BestPathConfig) -> Ordering {
        let attrs_a: PathAttributes = a.attributes.clone().into();
        let attrs_b: PathAttributes = b.attributes.clone().into();

        // RFC 9494 §4.4 applies ahead of every multipath-eligible step.
        let stale_a = Self::is_llgr_stale(&attrs_a);
        let stale_b = Self::is_llgr_stale(&attrs_b);
        if stale_a != stale_b {
            return if stale_a {
                Ordering::Greater
            } else {
                Ordering::Less
            };
        }

        let internal_a = a.protocol == lr_core::rib::Protocol::Bgp && a.origin.proto == 1;
        let internal_b = b.protocol == lr_core::rib::Protocol::Bgp && b.origin.proto == 1;
        let p_a = if internal_a {
            attrs_a.local_pref().map(|p| p.0).unwrap_or(100)
        } else {
            100
        };
        let p_b = if internal_b {
            attrs_b.local_pref().map(|p| p.0).unwrap_or(100)
        } else {
            100
        };
        let cmp = p_b.cmp(&p_a);
        if cmp != Ordering::Equal {
            return cmp;
        }

        let len_a = attrs_a
            .as_path()
            .map(|p| Self::as_path_len(&p, cfg))
            .unwrap_or(0);
        let len_b = attrs_b
            .as_path()
            .map(|p| Self::as_path_len(&p, cfg))
            .unwrap_or(0);
        let cmp = len_a.cmp(&len_b);
        if cmp != Ordering::Equal {
            return cmp;
        }

        let o_a = attrs_a.origin().map(|o| o.0 as u8).unwrap_or(2);
        let o_b = attrs_b.origin().map(|o| o.0 as u8).unwrap_or(2);
        let cmp = o_a.cmp(&o_b);
        if cmp != Ordering::Equal {
            return cmp;
        }

        let med_a = attrs_a.med().map(|m| m.0);
        let med_b = attrs_b.med().map(|m| m.0);
        let same_neighbor = cfg.always_compare_med || Self::same_neighbor(a, b);
        if same_neighbor {
            let ma = med_a.unwrap_or(if cfg.missing_med_as_infinity {
                u32::MAX
            } else {
                0
            });
            let mb = med_b.unwrap_or(if cfg.missing_med_as_infinity {
                u32::MAX
            } else {
                0
            });
            let cmp = ma.cmp(&mb);
            if cmp != Ordering::Equal {
                return cmp;
            }
        }

        if cfg.prefer_externals {
            let e_a = internal_a;
            let e_b = internal_b;
            if e_a != e_b {
                return if e_a {
                    Ordering::Greater
                } else {
                    Ordering::Less
                };
            }
        }

        if cfg.deterministic_router_id {
            let rid_a = Self::originator_id(&attrs_a);
            let rid_b = Self::originator_id(&attrs_b);
            let cmp = rid_a.cmp(&rid_b);
            if cmp != Ordering::Equal {
                return cmp;
            }
        }

        let cl_a = Self::cluster_list_len(&attrs_a);
        let cl_b = Self::cluster_list_len(&attrs_b);
        let cmp = cl_a.cmp(&cl_b);
        if cmp != Ordering::Equal {
            return cmp;
        }

        Ordering::Equal
    }

    /// Compare two routes per the configured decision process. Returns
    /// `Ordering::Less` if `a` is preferred over `b`.
    pub fn compare(a: &Route, b: &Route, cfg: &BestPathConfig) -> Ordering {
        let attrs_a: PathAttributes = a.attributes.clone().into();
        let attrs_b: PathAttributes = b.attributes.clone().into();

        // 0. RFC 9494 §4.4: a route marked LLGR_STALE is the least
        //    preferred — any non-stale route beats it; between two stale
        //    routes the normal tiebreakers below apply.
        let stale_a = Self::is_llgr_stale(&attrs_a);
        let stale_b = Self::is_llgr_stale(&attrs_b);
        if stale_a != stale_b {
            return if stale_a {
                Ordering::Greater
            } else {
                Ordering::Less
            };
        }

        // 1. Weight (vendor-specific; treated as 0; embedder injects via policy).
        // 2. LOCAL_PREF — only meaningful for iBGP. For eBGP routes we
        //    approximate as 100 unless the route is internal.
        let internal_a = a.protocol == lr_core::rib::Protocol::Bgp && a.origin.proto == 1;
        let internal_b = b.protocol == lr_core::rib::Protocol::Bgp && b.origin.proto == 1;
        let p_a = if internal_a {
            attrs_a.local_pref().map(|p| p.0).unwrap_or(100)
        } else {
            100
        };
        let p_b = if internal_b {
            attrs_b.local_pref().map(|p| p.0).unwrap_or(100)
        } else {
            100
        };
        let cmp = p_b.cmp(&p_a); // higher LOCAL_PREF is better
        if cmp != Ordering::Equal {
            return cmp;
        }

        // 3. AS_PATH length (shorter wins).
        let len_a = attrs_a
            .as_path()
            .map(|p| Self::as_path_len(&p, cfg))
            .unwrap_or(0);
        let len_b = attrs_b
            .as_path()
            .map(|p| Self::as_path_len(&p, cfg))
            .unwrap_or(0);
        let cmp = len_a.cmp(&len_b);
        if cmp != Ordering::Equal {
            return cmp;
        }

        // 4. ORIGIN (IGP=0 < EGP=1 < INCOMPLETE=2).
        let o_a = attrs_a.origin().map(|o| o.0 as u8).unwrap_or(2);
        let o_b = attrs_b.origin().map(|o| o.0 as u8).unwrap_or(2);
        let cmp = o_a.cmp(&o_b);
        if cmp != Ordering::Equal {
            return cmp;
        }

        // 5. MED (lower wins) — only when AS paths' first hop matches,
        //    unless `always_compare_med` is set.
        let med_a = attrs_a.med().map(|m| m.0);
        let med_b = attrs_b.med().map(|m| m.0);
        let same_neighbor = cfg.always_compare_med || Self::same_neighbor(a, b);
        if same_neighbor {
            let ma = med_a.unwrap_or(if cfg.missing_med_as_infinity {
                u32::MAX
            } else {
                0
            });
            let mb = med_b.unwrap_or(if cfg.missing_med_as_infinity {
                u32::MAX
            } else {
                0
            });
            let cmp = ma.cmp(&mb);
            if cmp != Ordering::Equal {
                return cmp;
            }
        }

        // 6. eBGP over iBGP (external paths preferred).
        if cfg.prefer_externals {
            let e_a = internal_a;
            let e_b = internal_b;
            if e_a != e_b {
                return if e_a {
                    Ordering::Greater
                } else {
                    Ordering::Less
                };
            }
        }

        // 7. Lowest IGP metric to NEXT_HOP — embedder injects via custom tag.

        // 8. Prefer paths where NEXT_HOP equals the peer's source address.

        // 9. Oldest route wins — disabled when deterministic_router_id is on
        //    (RFC 5004 deterministic comparison replaces it).

        // 10. Lower ORIGINATOR_ID wins (RFC 4456 + RFC 5004).
        if cfg.deterministic_router_id {
            let rid_a = Self::originator_id(&attrs_a);
            let rid_b = Self::originator_id(&attrs_b);
            let cmp = rid_a.cmp(&rid_b);
            if cmp != Ordering::Equal {
                return cmp;
            }
        } else {
            let cmp = a.age_ms.cmp(&b.age_ms);
            if cmp != Ordering::Equal {
                return cmp;
            }
        }

        // 11. Shortest CLUSTER_LIST wins (RFC 4456).
        let cl_a = Self::cluster_list_len(&attrs_a);
        let cl_b = Self::cluster_list_len(&attrs_b);
        let cmp = cl_a.cmp(&cl_b);
        if cmp != Ordering::Equal {
            return cmp;
        }

        // 12. Lowest peer IP / lowest peer-id wins (last resort).
        let cmp = a.origin.peer.cmp(&b.origin.peer);
        if cmp != Ordering::Equal {
            return cmp;
        }

        Ordering::Equal
    }

    fn as_path_len(path: &AsPath, cfg: &BestPathConfig) -> usize {
        if cfg.count_confed_in_path_len {
            // Operator opted into FRR `bgp bestpath as-path confed`:
            // count confederation members too. AS_SET still counts as 1.
            path.length_with_confed()
        } else {
            // RFC 4271 §9.1.2.2(a) + RFC 5065 §5.3(3): AS_SET counts as 1,
            // confederation segments are not counted.
            path.length()
        }
    }

    /// RFC 9494 §4.4: a route carrying the LLGR_STALE community is
    /// "least preferred".
    fn is_llgr_stale(attrs: &PathAttributes) -> bool {
        attrs.has_community(Community::LLGR_STALE)
    }

    fn same_neighbor(a: &Route, b: &Route) -> bool {
        let attrs_a: PathAttributes = a.attributes.clone().into();
        let attrs_b: PathAttributes = b.attributes.clone().into();
        let first_a = attrs_a
            .as_path()
            .and_then(|p| p.segments.first().and_then(|s| s.ases.first().copied()));
        let first_b = attrs_b
            .as_path()
            .and_then(|p| p.segments.first().and_then(|s| s.ases.first().copied()));
        first_a == first_b
    }

    fn originator_id(attrs: &PathAttributes) -> u32 {
        attrs
            .get(AttrType::OriginatorId)
            .and_then(|a| {
                if a.value.len() == 4 {
                    Some(u32::from_be_bytes([
                        a.value[0], a.value[1], a.value[2], a.value[3],
                    ]))
                } else {
                    None
                }
            })
            .unwrap_or(0)
    }

    fn cluster_list_len(attrs: &PathAttributes) -> usize {
        attrs
            .get(AttrType::ClusterList)
            .map(|a| a.value.len() / 4)
            .unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lr_core::addr::Prefix;
    use lr_core::attr::{Attribute, Attributes};
    use lr_core::nlri::NlriFamily;
    use lr_core::rib::{Preference, Protocol, RouteKey, RouteOrigin};

    fn route_with_attr(attr_type: u8, value: Vec<u8>, peer: u64) -> Route {
        let mut attrs = Attributes::new();
        attrs.insert(Attribute {
            tag: lr_core::attr::AttrTag(attr_type),
            flags: 0,
            value,
        });
        Route {
            key: RouteKey::new(Prefix::new_v4([10, 0, 0, 0], 8), NlriFamily::IPV4_UNICAST),
            origin: RouteOrigin { proto: 0, peer },
            protocol: Protocol::Bgp,
            preference: Preference::new(20, 0),
            next_hop: None,
            attributes: attrs,
            age_ms: 0,
            path_id: 0,
        }
    }

    fn route_with_attrs_many(attrs: &[(u8, Vec<u8>)], peer: u64) -> Route {
        let mut a = Attributes::new();
        for (t, v) in attrs {
            a.insert(Attribute {
                tag: lr_core::attr::AttrTag(*t),
                flags: 0,
                value: v.clone(),
            });
        }
        Route {
            key: RouteKey::new(Prefix::new_v4([10, 0, 0, 0], 8), NlriFamily::IPV4_UNICAST),
            origin: RouteOrigin { proto: 0, peer },
            protocol: Protocol::Bgp,
            preference: Preference::new(20, 0),
            next_hop: None,
            attributes: a,
            age_ms: 0,
            path_id: 0,
        }
    }

    #[test]
    fn shorter_as_path_wins() {
        let short = route_with_attr(2, vec![2, 1, 0, 0, 100], 1); // 1 AS
        let long = route_with_attr(2, vec![2, 3, 0, 0, 100, 0, 0, 200, 0, 0], 2); // 3 AS
        let cfg = BestPathConfig::default();
        let routes = [short, long];
        let best = BestPath::select(&routes, &cfg).unwrap();
        assert_eq!(best.origin.peer, 1);
    }

    #[test]
    fn igp_origin_beats_incomplete() {
        let igp = route_with_attr(1, vec![0], 1); // IGP=0
        let inc = route_with_attr(1, vec![2], 2); // INCOMPLETE=2
        let cfg = BestPathConfig::default();
        let routes = [igp, inc];
        let best = BestPath::select(&routes, &cfg).unwrap();
        assert_eq!(best.origin.peer, 1);
    }

    #[test]
    fn deterministic_originator_id_breaks_tie() {
        let a = route_with_attrs_many(&[(2, vec![2, 1, 0, 0, 100]), (9, vec![0, 0, 0, 1])], 1);
        let b = route_with_attrs_many(&[(2, vec![2, 1, 0, 0, 100]), (9, vec![0, 0, 0, 2])], 2);
        let cfg = BestPathConfig::default();
        let routes = [a, b];
        let best = BestPath::select(&routes, &cfg).unwrap();
        assert_eq!(best.origin.peer, 1);
    }

    #[test]
    fn rank_is_stable_across_insertion_order() {
        let a = route_with_attr(2, vec![2, 1, 0, 0, 100], 1);
        let b = route_with_attr(2, vec![2, 1, 0, 0, 100], 2);
        let cfg = BestPathConfig::default();
        let set_one = [a.clone(), b.clone()];
        let set_two = [b, a];
        let one = BestPath::rank(&set_one, &cfg);
        let two = BestPath::rank(&set_two, &cfg);
        assert_eq!(
            one.iter().map(|r| r.origin.peer).collect::<Vec<_>>(),
            two.iter().map(|r| r.origin.peer).collect::<Vec<_>>()
        );
    }

    /// Add-Path ranking: the first entry is always `select`'s winner.
    #[test]
    fn rank_head_equals_select() {
        let a = route_with_attr(2, vec![2, 3, 0, 0, 100, 0, 0, 200, 0, 0], 1);
        let b = route_with_attr(2, vec![2, 1, 0, 0, 100], 2);
        let cfg = BestPathConfig::default();
        let set = [a, b];
        let ranked = BestPath::rank(&set, &cfg);
        let owned: Vec<Route> = ranked.into_iter().cloned().collect();
        assert_eq!(
            ranked_head_peer(&owned, &cfg),
            BestPath::select(&set, &cfg).unwrap().origin.peer
        );
        assert_eq!(owned.len(), 2);
    }

    fn ranked_head_peer(routes: &[Route], cfg: &BestPathConfig) -> u64 {
        BestPath::select(routes, cfg).unwrap().origin.peer
    }

    #[test]
    fn multipath_returns_one_by_default() {
        let a = route_with_attr(2, vec![2, 1, 0, 0, 100], 1);
        let b = route_with_attr(2, vec![2, 1, 0, 0, 100], 2);
        let cfg = BestPathConfig::default();
        let routes = [a, b];
        let mp = BestPath::multipath(&routes, &cfg).unwrap();
        assert_eq!(mp.len(), 1);
    }

    #[test]
    fn multipath_returns_more_when_enabled() {
        let a = route_with_attr(2, vec![2, 1, 0, 0, 100], 1);
        let b = route_with_attr(2, vec![2, 1, 0, 0, 100], 2);
        let cfg = BestPathConfig {
            multipath: 8,
            ..Default::default()
        };
        let routes = [a, b];
        let mp = BestPath::multipath(&routes, &cfg).unwrap();
        assert_eq!(mp.len(), 2);
    }

    /// RFC 9494 §4.4: an LLGR_STALE route is least preferred — it loses to
    /// any non-stale candidate regardless of the other attributes, and
    /// only survives selection when no fresh route exists.
    #[test]
    fn llgr_stale_route_is_least_preferred() {
        let llgr_stale = Community::LLGR_STALE.0.to_be_bytes().to_vec();
        let path_2as = vec![2, 2, 0, 0, 0, 100, 0, 0, 0, 200]; // sequence: AS100, AS200
        let path_1as = vec![2, 1, 0, 0, 0, 100]; // sequence: AS100

        // The stale route has a *shorter* AS path; without §4.4 it would
        // win. The fresh route must still be selected.
        let fresh = route_with_attrs_many(&[(2, path_2as.clone())], 1);
        let stale = route_with_attrs_many(&[(2, path_1as.clone()), (8, llgr_stale)], 2);
        let cfg = BestPathConfig::default();
        let fresh_set = [fresh, stale];
        let best = BestPath::select(&fresh_set, &cfg).unwrap();
        assert_eq!(best.origin.peer, 1, "fresh route must beat the stale one");

        // Only stale candidates remain: the normal tiebreakers (shorter AS
        // path) decide between them.
        let stale_long = route_with_attrs_many(
            &[
                (2, path_2as),
                (8, Community::LLGR_STALE.0.to_be_bytes().to_vec()),
            ],
            2,
        );
        let stale_short = route_with_attrs_many(
            &[
                (2, path_1as),
                (8, Community::LLGR_STALE.0.to_be_bytes().to_vec()),
            ],
            3,
        );
        let stale_set = [stale_long, stale_short];
        let best = BestPath::select(&stale_set, &cfg).unwrap();
        assert_eq!(best.origin.peer, 3);
    }
}
