//! Best-path selection (RFC 4271 §9.1.2 + RFC 5004 / RFC 7911 / multipath
//! + RFC 8326 graceful shutdown).
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
    /// Default false, which is the conservative reading of RFC 4271 §9.1.2.2:
    /// two paths to the same prefix are only comparable when they were learned
    /// from the same neighbor AS. FRR exposes the relaxation as
    /// `bgp bestpath as-path multipath-relax`; there is no RFC for it.
    pub multipath_relax: bool,
    /// RFC 8326 §4: a route carrying the `GRACEFUL_SHUTDOWN` community
    /// (`0xFFFF:0000`) is the least preferred amongst all other routes
    /// for the same prefix. Default true — the community's whole purpose
    /// is to signal "de-preference me before the session goes away", so
    /// an untagged path always beats a tagged one while two tagged paths
    /// fall back to the normal tiebreakers. Disabling this restores the
    /// plain RFC 4271 decision process (the community is then inert for
    /// selection, and the operator is expected to implement RFC 8326
    /// §4.1 as an explicit inbound policy instead).
    pub graceful_shutdown_least_preferred: bool,
    /// RFC 4271 §9.1.2.2 step (g): the path with the lowest IGP metric
    /// to the NEXT_HOP wins. The metric is read from the route's
    /// private [`crate::path::AttrType::LrIgpMetric`] tag (the embedder
    /// injects it at route learn time from its IGP RIB — the daemon's
    /// `lr-osroute` FIB lookup, or an out-of-band OSPF/Babel route
    /// table walk). Absent tag is treated as `u32::MAX` (worst), so a
    /// route with no IGP metric never beats a route with a real metric.
    /// Default true — the RFC mandates the step; operators can disable
    /// it for test scenarios without an IGP (e.g. an FFI-driven
    /// two-router test that does not run OSPF/Babel and so cannot
    /// supply the metric).
    pub compare_igp_metric: bool,
    /// RFC 4271 §9.1.2.2 step (h): prefer the path whose NEXT_HOP
    /// equals the peer's source address — a route whose NEXT_HOP is
    /// the peer's own transport source is the route the peer
    /// originated (IGP cost zero by construction), winning over a
    /// route the peer re-advertises (NEXT_HOP points elsewhere). The
    /// peer source is read from the route's private
    /// [`crate::path::AttrType::LrPeerSourceAddress`] tag (the daemon
    /// injects it at route learn time from the session's transport
    /// address; FFI sessions without a configured peer address leave
    /// it absent). Default true — the RFC mandates the step;
    /// operators can disable it for test scenarios where the peer
    /// transport address is not known.
    pub prefer_next_hop_self: bool,
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
            graceful_shutdown_least_preferred: true,
            compare_igp_metric: true,
            prefer_next_hop_self: true,
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

    /// Like [`Self::compare`] but stops before the final peer-id tiebreaker:
    /// two paths from the same peer are the same path, so the router-ID step
    /// can never separate multipath-eligible candidates.
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

        // RFC 8326 §4: the same least-preferred treatment for paths
        // carrying the GRACEFUL_SHUTDOWN community.
        if cfg.graceful_shutdown_least_preferred {
            let gshut_a = Self::is_graceful_shutdown(&attrs_a);
            let gshut_b = Self::is_graceful_shutdown(&attrs_b);
            if gshut_a != gshut_b {
                return if gshut_a {
                    Ordering::Greater
                } else {
                    Ordering::Less
                };
            }
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

        // RFC 4271 §9.1.2.2 step (g) — IGP metric to NEXT_HOP. Same
        // shape as `compare`'s step 7; see that step for the rationale.
        if cfg.compare_igp_metric {
            let igp_a = attrs_a.igp_metric().unwrap_or(u32::MAX);
            let igp_b = attrs_b.igp_metric().unwrap_or(u32::MAX);
            let cmp = igp_a.cmp(&igp_b);
            if cmp != Ordering::Equal {
                return cmp;
            }
        }

        // RFC 4271 §9.1.2.2 step (h) — NEXT_HOP equals peer's source.
        // Same shape as `compare`'s step 8.
        if cfg.prefer_next_hop_self {
            let nh_a_matches = a
                .next_hop
                .is_some_and(|nh| attrs_a.peer_source_address() == Some(nh));
            let nh_b_matches = b
                .next_hop
                .is_some_and(|nh| attrs_b.peer_source_address() == Some(nh));
            if nh_a_matches != nh_b_matches {
                return if nh_a_matches {
                    Ordering::Less
                } else {
                    Ordering::Greater
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

        // 0b. RFC 8326 §4: a route carrying the GRACEFUL_SHUTDOWN
        //     community is likewise the least preferred — the sender
        //     attached it precisely so receivers move traffic onto
        //     alternatives before the session goes away. The step sits
        //     ahead of LOCAL_PREF because the comparator pins eBGP
        //     LOCAL_PREF at 100, so the RFC §4.1 low-LOCAL_PREF inbound
        //     policy alone could not de-preference an eBGP path against
        //     another eBGP path (FRR closes the same gap by forcing
        //     LOCAL_PREF to 0 on GS-tagged eBGP routes and comparing
        //     LOCAL_PREF unconditionally).
        if cfg.graceful_shutdown_least_preferred {
            let gshut_a = Self::is_graceful_shutdown(&attrs_a);
            let gshut_b = Self::is_graceful_shutdown(&attrs_b);
            if gshut_a != gshut_b {
                return if gshut_a {
                    Ordering::Greater
                } else {
                    Ordering::Less
                };
            }
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

        // 7. Lowest IGP metric to NEXT_HOP (RFC 4271 §9.1.2.2 step (g)).
        //    The metric is the embedder's IGP RIB distance to the
        //    route's NEXT_HOP, stored under the private `LrIgpMetric`
        //    tag. An absent tag is treated as `u32::MAX` (worst) so a
        //    route with no IGP metric never beats a route with a real
        //    metric — when both are absent they tie through to step 8.
        if cfg.compare_igp_metric {
            let igp_a = attrs_a.igp_metric().unwrap_or(u32::MAX);
            let igp_b = attrs_b.igp_metric().unwrap_or(u32::MAX);
            let cmp = igp_a.cmp(&igp_b);
            if cmp != Ordering::Equal {
                return cmp;
            }
        }

        // 8. Prefer paths where NEXT_HOP equals the peer's source
        //    address (RFC 4271 §9.1.2.2 step (h)). The peer's transport
        //    source is stored under the private `LrPeerSourceAddress`
        //    tag — a route whose `next_hop` matches its peer's source
        //    is the route the peer originated (IGP cost zero by
        //    construction), winning over a route the peer re-advertises
        //    (NEXT_HOP points elsewhere). The asymmetry (`true > false`
        //    for "matched wins") makes the matched path `Ordering::Less`.
        if cfg.prefer_next_hop_self {
            let nh_a_matches = a
                .next_hop
                .is_some_and(|nh| attrs_a.peer_source_address() == Some(nh));
            let nh_b_matches = b
                .next_hop
                .is_some_and(|nh| attrs_b.peer_source_address() == Some(nh));
            if nh_a_matches != nh_b_matches {
                return if nh_a_matches {
                    Ordering::Less
                } else {
                    Ordering::Greater
                };
            }
        }

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

    /// RFC 8326 §4: a route carrying the GRACEFUL_SHUTDOWN community is
    /// "least preferred" (when
    /// [`BestPathConfig::graceful_shutdown_least_preferred`] is set).
    fn is_graceful_shutdown(attrs: &PathAttributes) -> bool {
        attrs.has_community(Community::GRACEFUL_SHUTDOWN)
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
            tag: None,
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
            tag: None,
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

    /// RFC 8326 §4: a route carrying GRACEFUL_SHUTDOWN is the least
    /// preferred — it loses to any untagged candidate regardless of the
    /// other attributes, and only survives selection when every
    /// candidate carries the community (the normal tiebreakers then
    /// decide between them).
    #[test]
    fn graceful_shutdown_route_is_least_preferred() {
        let gshut = Community::GRACEFUL_SHUTDOWN.0.to_be_bytes().to_vec();
        let path_2as = vec![2, 2, 0, 0, 0, 100, 0, 0, 0, 200]; // sequence: AS100, AS200
        let path_1as = vec![2, 1, 0, 0, 0, 100]; // sequence: AS100

        // The shutdown route has a *shorter* AS path; without the §4
        // step it would win. The fresh route must be selected.
        let fresh = route_with_attrs_many(&[(2, path_2as.clone())], 1);
        let shutdown = route_with_attrs_many(&[(2, path_1as.clone()), (8, gshut.clone())], 2);
        let cfg = BestPathConfig::default();
        let fresh_set = [fresh, shutdown];
        let best = BestPath::select(&fresh_set, &cfg).unwrap();
        assert_eq!(
            best.origin.peer, 1,
            "fresh route must beat the shutdown one"
        );

        // Only shutdown candidates remain: the normal tiebreakers
        // (shorter AS path) decide between them.
        let shutdown_long = route_with_attrs_many(
            &[
                (2, path_2as),
                (8, Community::GRACEFUL_SHUTDOWN.0.to_be_bytes().to_vec()),
            ],
            2,
        );
        let shutdown_short = route_with_attrs_many(&[(2, path_1as), (8, gshut)], 3);
        let shutdown_set = [shutdown_long, shutdown_short];
        let best = BestPath::select(&shutdown_set, &cfg).unwrap();
        assert_eq!(best.origin.peer, 3);
    }

    /// RFC 8326 §4 de-preference is a SHOULD: `BestPathConfig` lets an
    /// embedder opt out, restoring the plain RFC 4271 decision process
    /// where the community is inert for selection.
    #[test]
    fn graceful_shutdown_de_preference_can_be_disabled() {
        let gshut = Community::GRACEFUL_SHUTDOWN.0.to_be_bytes().to_vec();
        let fresh = route_with_attr(2, vec![2, 2, 0, 0, 0, 100, 0, 0, 0, 200], 1); // 2 AS
        let shutdown = route_with_attrs_many(&[(2, vec![2, 1, 0, 0, 0, 100]), (8, gshut)], 2); // 1 AS
        let cfg = BestPathConfig {
            graceful_shutdown_least_preferred: false,
            ..Default::default()
        };
        let routes = [fresh, shutdown];
        let best = BestPath::select(&routes, &cfg).unwrap();
        assert_eq!(
            best.origin.peer, 2,
            "with the step disabled the shorter AS path wins even though it carries GS"
        );
    }

    /// RFC 8326 §4 in the multipath comparator: a GS-tagged path never
    /// joins an equal-cost set alongside a fresh path (it only ties with
    /// another GS-tagged path when `multipath_relax` bridges the neighbor
    /// check).
    #[test]
    fn graceful_shutdown_excluded_from_multipath() {
        let gshut = Community::GRACEFUL_SHUTDOWN.0.to_be_bytes().to_vec();
        let a = route_with_attr(2, vec![2, 1, 0, 0, 100], 1);
        let b = route_with_attrs_many(&[(2, vec![2, 1, 0, 0, 100]), (8, gshut)], 2);
        let cfg = BestPathConfig {
            multipath: 8,
            multipath_relax: true,
            ..Default::default()
        };
        let routes = [a, b];
        let mp = BestPath::multipath(&routes, &cfg).unwrap();
        assert_eq!(mp.len(), 1, "the GS-tagged path must stay out of the set");
        assert_eq!(mp[0].origin.peer, 1);
    }

    // ===========================================================================
    // Step 7 — Lowest IGP metric to NEXT_HOP (RFC 4271 §9.1.2.2 step (g))
    // ===========================================================================

    /// Helper: build a route carrying the same AS_PATH but a different
    /// private `LrIgpMetric` tag. The metric is encoded as a 4-byte
    /// big-endian u32 (matching `PathAttributes::set_igp_metric`'s wire
    /// shape — the test goes through the same `Attributes` insert so
    /// `PathAttributes::igp_metric()` decodes it back symmetrically).
    fn route_with_igp_metric(as_path: Vec<u8>, metric: Option<u32>, peer: u64) -> Route {
        let mut attrs = Attributes::new();
        attrs.insert(Attribute {
            tag: lr_core::attr::AttrTag(2),
            flags: 0,
            value: as_path,
        });
        if let Some(m) = metric {
            attrs.insert(Attribute {
                tag: lr_core::attr::AttrTag(AttrType::LrIgpMetric.to_u8()),
                flags: 0,
                value: m.to_be_bytes().to_vec(),
            });
        }
        Route {
            key: RouteKey::new(Prefix::new_v4([10, 0, 0, 0], 8), NlriFamily::IPV4_UNICAST),
            origin: RouteOrigin { proto: 0, peer },
            protocol: Protocol::Bgp,
            preference: Preference::new(20, 0),
            next_hop: None,
            attributes: attrs,
            age_ms: 0,
            path_id: 0,
            tag: None,
        }
    }

    /// RFC 4271 §9.1.2.2 step (g): a path whose IGP metric to NEXT_HOP
    /// is lower wins over one whose metric is higher. Both routes carry
    /// the same AS_PATH so the upstream steps (LOCAL_PREF / AS_PATH
    /// length / ORIGIN / MED / eBGP-over-iBGP) all tie; step 7 is the
    /// deciding factor.
    #[test]
    fn lower_igp_metric_wins() {
        let near = route_with_igp_metric(vec![2, 1, 0, 0, 100], Some(50), 1);
        let far = route_with_igp_metric(vec![2, 1, 0, 0, 100], Some(500), 2);
        let cfg = BestPathConfig::default();
        let routes = [near, far];
        let best = BestPath::select(&routes, &cfg).unwrap();
        assert_eq!(
            best.origin.peer, 1,
            "lower IGP metric to NEXT_HOP wins at step 7"
        );
    }

    /// An absent `LrIgpMetric` tag is treated as `u32::MAX` (worst), so
    /// a route with no metric loses to one with a real metric; both
    /// absent ties through to step 8.
    #[test]
    fn absent_igp_metric_is_treated_as_worst() {
        let with_metric = route_with_igp_metric(vec![2, 1, 0, 0, 100], Some(99), 1);
        let no_metric = route_with_igp_metric(vec![2, 1, 0, 0, 100], None, 2);
        let cfg = BestPathConfig::default();
        let routes = [with_metric, no_metric];
        let best = BestPath::select(&routes, &cfg).unwrap();
        assert_eq!(
            best.origin.peer, 1,
            "an absent IGP metric (u32::MAX) loses to any real metric"
        );
    }

    /// Disabling `compare_igp_metric` skips the step entirely — both
    /// routes tie at step 7 and fall through to step 8 and beyond; the
    /// tiebreaker (router-id / peer-id) picks the lower peer-id (peer 1).
    /// This mirrors FRR's `bgp bestpath as-path ignore-igp-metric` knob
    /// (there is no RFC for the skip — the RFC mandates the step, the
    /// skip is a test-scenario opt-out).
    #[test]
    fn compare_igp_metric_can_be_disabled() {
        let near = route_with_igp_metric(vec![2, 1, 0, 0, 100], Some(50), 2);
        let far = route_with_igp_metric(vec![2, 1, 0, 0, 100], Some(500), 1);
        let cfg = BestPathConfig {
            compare_igp_metric: false,
            ..Default::default()
        };
        let routes = [near, far];
        let best = BestPath::select(&routes, &cfg).unwrap();
        assert_eq!(
            best.origin.peer, 1,
            "step 7 skipped — lower peer-id wins via step 12's tiebreaker"
        );
    }

    // ===========================================================================
    // Step 8 — Prefer paths whose NEXT_HOP equals the peer's source address
    // (RFC 4271 §9.1.2.2 step (h))
    // ===========================================================================

    /// Helper: build a route with the same AS_PATH but a different
    /// private `LrPeerSourceAddress` tag and `next_hop`. The peer source
    /// is encoded as a 4-byte (IPv4) or 16-byte (IPv6) raw `IpAddr` —
    /// matching `PathAttributes::set_peer_source_address`'s wire shape.
    fn route_with_peer_source(
        as_path: Vec<u8>,
        next_hop: Option<lr_core::addr::IpAddr>,
        peer_source: Option<lr_core::addr::IpAddr>,
        peer: u64,
    ) -> Route {
        let mut attrs = Attributes::new();
        attrs.insert(Attribute {
            tag: lr_core::attr::AttrTag(2),
            flags: 0,
            value: as_path,
        });
        if let Some(src) = peer_source {
            let value: Vec<u8> = match src {
                lr_core::addr::IpAddr::V4(b) => b.to_vec(),
                lr_core::addr::IpAddr::V6(b) => b.to_vec(),
            };
            attrs.insert(Attribute {
                tag: lr_core::attr::AttrTag(AttrType::LrPeerSourceAddress.to_u8()),
                flags: 0,
                value,
            });
        }
        Route {
            key: RouteKey::new(Prefix::new_v4([10, 0, 0, 0], 8), NlriFamily::IPV4_UNICAST),
            origin: RouteOrigin { proto: 0, peer },
            protocol: Protocol::Bgp,
            preference: Preference::new(20, 0),
            next_hop,
            attributes: attrs,
            age_ms: 0,
            path_id: 0,
            tag: None,
        }
    }

    /// RFC 4271 §9.1.2.2 step (h): a path whose NEXT_HOP equals its
    /// peer's source address wins over one whose NEXT_HOP points
    /// elsewhere — the matched path is the route the peer originated
    /// (IGP cost zero by construction); the unmatched path is one the
    /// peer re-advertises.
    #[test]
    fn next_hop_equal_to_peer_source_wins() {
        // Peer 1's transport source is 192.0.2.1; the route's NEXT_HOP
        // matches it — peer 1 originated the route.
        let originated = route_with_peer_source(
            vec![2, 1, 0, 0, 100],
            Some(lr_core::addr::IpAddr::V4([192, 0, 2, 1])),
            Some(lr_core::addr::IpAddr::V4([192, 0, 2, 1])),
            1,
        );
        // Peer 2's transport source is 192.0.2.2; the route's NEXT_HOP
        // is 192.0.2.254 — peer 2 re-advertises a route whose NEXT_HOP
        // points at a different router.
        let re_advertised = route_with_peer_source(
            vec![2, 1, 0, 0, 100],
            Some(lr_core::addr::IpAddr::V4([192, 0, 2, 254])),
            Some(lr_core::addr::IpAddr::V4([192, 0, 2, 2])),
            2,
        );
        let cfg = BestPathConfig::default();
        let routes = [originated, re_advertised];
        let best = BestPath::select(&routes, &cfg).unwrap();
        assert_eq!(
            best.origin.peer, 1,
            "a route whose NEXT_HOP equals its peer's source address wins at step 8"
        );
    }

    /// Step 8 also fires for IPv6 next-hops: a route whose NEXT_HOP is
    /// the IPv6 peer source wins over one whose NEXT_HOP differs.
    #[test]
    fn next_hop_equal_to_peer_source_wins_ipv6() {
        let v6_originated = route_with_peer_source(
            vec![2, 1, 0, 0, 100],
            Some(lr_core::addr::IpAddr::V6([
                0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
            ])),
            Some(lr_core::addr::IpAddr::V6([
                0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
            ])),
            1,
        );
        let v6_re_advertised = route_with_peer_source(
            vec![2, 1, 0, 0, 100],
            Some(lr_core::addr::IpAddr::V6([
                0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xfe,
            ])),
            Some(lr_core::addr::IpAddr::V6([
                0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2,
            ])),
            2,
        );
        let cfg = BestPathConfig::default();
        let routes = [v6_originated, v6_re_advertised];
        let best = BestPath::select(&routes, &cfg).unwrap();
        assert_eq!(
            best.origin.peer, 1,
            "IPv6 NEXT_HOP matching the IPv6 peer source wins at step 8"
        );
    }

    /// An absent `LrPeerSourceAddress` tag makes the match check
    /// false for both routes — neither matches, so step 8 ties
    /// through to the remaining tiebreakers. The lower peer-id (peer
    /// 1) wins via step 12's last-resort tiebreaker.
    #[test]
    fn absent_peer_source_skips_step_8() {
        let a = route_with_peer_source(
            vec![2, 1, 0, 0, 100],
            Some(lr_core::addr::IpAddr::V4([192, 0, 2, 1])),
            None,
            2,
        );
        let b = route_with_peer_source(
            vec![2, 1, 0, 0, 100],
            Some(lr_core::addr::IpAddr::V4([192, 0, 2, 1])),
            None,
            1,
        );
        let cfg = BestPathConfig::default();
        let routes = [a, b];
        let best = BestPath::select(&routes, &cfg).unwrap();
        assert_eq!(
            best.origin.peer, 1,
            "absent peer source on both routes — step 8 ties; lower peer-id wins"
        );
    }

    /// Disabling `prefer_next_hop_self` skips step 8 entirely — both
    /// routes tie at step 8 and fall through to step 9+, where the
    /// lower peer-id wins (peer 1).
    #[test]
    fn prefer_next_hop_self_can_be_disabled() {
        let matched = route_with_peer_source(
            vec![2, 1, 0, 0, 100],
            Some(lr_core::addr::IpAddr::V4([192, 0, 2, 1])),
            Some(lr_core::addr::IpAddr::V4([192, 0, 2, 1])),
            2,
        );
        let unmatched = route_with_peer_source(
            vec![2, 1, 0, 0, 100],
            Some(lr_core::addr::IpAddr::V4([192, 0, 2, 254])),
            Some(lr_core::addr::IpAddr::V4([192, 0, 2, 2])),
            1,
        );
        let cfg = BestPathConfig {
            prefer_next_hop_self: false,
            ..Default::default()
        };
        let routes = [matched, unmatched];
        let best = BestPath::select(&routes, &cfg).unwrap();
        assert_eq!(
            best.origin.peer, 1,
            "step 8 disabled — lower peer-id wins via step 12's tiebreaker"
        );
    }

    /// Step 8 in the multipath comparator: a path whose NEXT_HOP does
    /// not match its peer source cannot join an equal-cost set with one
    /// that does. The matched path wins outright at step 8, so the
    /// unmatched one stays out of the multipath group.
    #[test]
    fn next_hop_self_excludes_unmatched_from_multipath() {
        let matched = route_with_peer_source(
            vec![2, 1, 0, 0, 100],
            Some(lr_core::addr::IpAddr::V4([192, 0, 2, 1])),
            Some(lr_core::addr::IpAddr::V4([192, 0, 2, 1])),
            1,
        );
        let unmatched = route_with_peer_source(
            vec![2, 1, 0, 0, 100],
            Some(lr_core::addr::IpAddr::V4([192, 0, 2, 254])),
            Some(lr_core::addr::IpAddr::V4([192, 0, 2, 2])),
            2,
        );
        let cfg = BestPathConfig {
            multipath: 8,
            multipath_relax: true,
            ..Default::default()
        };
        let routes = [matched, unmatched];
        let mp = BestPath::multipath(&routes, &cfg).unwrap();
        assert_eq!(mp.len(), 1, "the unmatched path stays out of the set");
        assert_eq!(mp[0].origin.peer, 1);
    }
}
