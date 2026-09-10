//! SPF (Dijkstra) over the LSDB.
//!
//! Produces [`SpfResult`] entries that the router installs into Loc-RIB.
//! [`run_spf`] computes the intra-area shortest-path tree (RFC 2328 §16.1);
//! [`summary_routes`] derives inter-area candidates from summary-LSAs on
//! top of an intra-area result (RFC 2328 §16.2).

use std::collections::{BTreeMap, BTreeSet, BinaryHeap};

use crate::lsa::{
    decode_summary_lsa_body, mask_to_prefix_len, LsaTypeV2, RouterLink, RouterLinkType,
};
use crate::lsdb::Lsdb;
use lr_core::addr::{IpAddr, Prefix};

/// One vertex in the SPF tree.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum VertexId {
    Router(u32),  // Router-ID
    Network(u32), // Link-state ID (DR's IP)
}

#[derive(Debug, Clone)]
pub struct SpfVertex {
    pub id: VertexId,
    pub distance: u64,
}

#[derive(Debug, Clone, Default)]
pub struct SpfResult {
    /// Best distances to each vertex.
    pub vertices: BTreeMap<VertexId, u64>,
    /// RFC 2328 §16.1.1: the next hop toward each vertex — the IP
    /// interface address of the first-hop neighbour on the shortest
    /// path — wherever the LSDB carries it. A direct p2p neighbour
    /// contributes the Link Data of the p2p link pointing back at the
    /// root (its own address on the shared link, §16.1.1 (5)); a router
    /// attached to a directly reachable transit network contributes its
    /// address on that network (§16.1.1 (4)); deeper vertices inherit
    /// their parent's next hop (§16.1.1 (2)-(3)). Vertices whose next
    /// hop the LSDB cannot resolve (unnumbered, Link Data 0) are absent.
    pub next_hops: BTreeMap<VertexId, IpAddr>,
    /// Router vertices one hop from the root: a direct p2p adjacency or
    /// a router on a directly attached transit network. Segment Routing
    /// uses this for the RFC 8665 §5 PHP rule — the penultimate hop
    /// pops when a Prefix-SID does not carry the NP flag, and a router
    /// in this set *is* the penultimate hop for its own prefix-SIDs.
    pub adjacent_routers: BTreeSet<u32>,
    /// Best next-hop IP for each prefix reachable through a stub network.
    pub stub_routes: Vec<SpfRoute>,
    /// Best next-hop IP for each transit network.
    pub transit_routes: Vec<SpfRoute>,
}

#[derive(Debug, Clone)]
pub struct SpfRoute {
    pub prefix: Prefix,
    pub metric: u64,
    pub next_hop: Option<IpAddr>,
    /// For inter-area routes derived from summary-LSAs: the advertising
    /// border router. `None` for intra-area routes.
    pub border_router: Option<u32>,
}

impl Ord for SpfVertex {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        // Reverse so BinaryHeap (max-heap) behaves as min-heap on distance.
        other
            .distance
            .cmp(&self.distance)
            .then(other.id.cmp(&self.id))
    }
}

impl PartialOrd for SpfVertex {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Eq for SpfVertex {}

impl PartialEq for SpfVertex {
    fn eq(&self, other: &Self) -> bool {
        self.distance == other.distance && self.id == other.id
    }
}

/// Run Dijkstra starting at `root` (a Router vertex). Uses Router-LSAs and
/// Network-LSAs from `lsdb` to construct the shortest-path tree.
///
/// The LSDB is pre-scanned into per-type link maps once (one Router-LSA
/// per advertising router, §12.4.1; one Network-LSA per link-state ID,
/// §12.4.2) so the relaxation loop never re-walks the whole database per
/// popped vertex. First-instance wins for duplicate Network-LSA link-state
/// IDs — the iteration order of [`Lsdb::iter`] and `or_insert` reproduce
/// the previous first-match-in-database-order rule.
pub fn run_spf(lsdb: &Lsdb, root: u32) -> SpfResult {
    // Pre-scan the database into link maps.
    let mut router_lsas: BTreeMap<u32, Vec<RouterLink>> = BTreeMap::new();
    // link-state ID (the DR's IP) → (network mask, attached router IDs).
    let mut network_lsas: BTreeMap<u32, (u32, Vec<u32>)> = BTreeMap::new();
    for (key, entry) in lsdb.iter() {
        if key.ls_type == LsaTypeV2::RouterLsa as u16 {
            router_lsas
                .entry(key.advertising_router)
                .or_default()
                .extend(decode_router_links(&entry.lsa.body));
        } else if key.ls_type == LsaTypeV2::NetworkLsa as u16 && entry.lsa.body.len() >= 4 {
            let mask = u32::from_be_bytes([
                entry.lsa.body[0],
                entry.lsa.body[1],
                entry.lsa.body[2],
                entry.lsa.body[3],
            ]);
            let attached = decode_network_attached_routers(&entry.lsa.body);
            network_lsas
                .entry(key.link_state_id)
                .or_insert((mask, attached));
        }
    }

    let mut result = SpfResult::default();
    let mut heap: BinaryHeap<SpfVertex> = BinaryHeap::new();
    // First parent on the shortest path — decides next-hop inheritance
    // and (indirectly, via the root check) adjacency.
    let mut parents: BTreeMap<VertexId, VertexId> = BTreeMap::new();
    let root_id = VertexId::Router(root);
    heap.push(SpfVertex {
        id: root_id,
        distance: 0,
    });
    result.vertices.insert(root_id, 0);

    while let Some(v) = heap.pop() {
        let Some(&current_dist) = result.vertices.get(&v.id) else {
            continue;
        };
        if v.distance > current_dist {
            continue;
        }
        match v.id {
            VertexId::Router(rid) => {
                // Process this router's Router-LSA links.
                for link in router_lsas.get(&rid).into_iter().flatten() {
                    match link.link_type {
                        x if x == RouterLinkType::PointToPoint as u8
                            || x == RouterLinkType::VirtualLink as u8 =>
                        {
                            // Link-ID is the neighbor's Router-ID. A
                            // virtual link (type 4, RFC 2328 §A.4.2)
                            // only appears in backbone router-LSAs and
                            // behaves as a point-to-point adjacency —
                            // its metric is the transit-area path cost
                            // the endpoint maintains (§15).
                            let target = VertexId::Router(link.link_id);
                            // §16.1.1 (5): a direct neighbour's address
                            // is the Link Data of the p2p link it
                            // points back at us with. Deeper vertices
                            // inherit the parent's next hop (§16.1.1
                            // (2)-(3)).
                            let next_hop = if rid == root {
                                router_address_towards(&router_lsas, link.link_id, root)
                            } else {
                                result.next_hops.get(&v.id).copied()
                            };
                            relax(
                                &mut result,
                                &mut parents,
                                &mut heap,
                                v.id,
                                target,
                                current_dist + link.metric as u64,
                                next_hop,
                            );
                            if rid == root && link.link_type == RouterLinkType::PointToPoint as u8 {
                                // One hop away: the penultimate hop for
                                // this neighbour's own prefix-SIDs
                                // (RFC 8665 §5 PHP rule).
                                result.adjacent_routers.insert(link.link_id);
                            }
                        }
                        x if x == RouterLinkType::TransitNetwork as u8 => {
                            // Link-ID is the DR's IP.
                            let target = VertexId::Network(link.link_id);
                            // A directly attached transit network is
                            // connected: no IP next hop toward the
                            // network itself. Deeper networks inherit.
                            let next_hop = if rid == root {
                                None
                            } else {
                                result.next_hops.get(&v.id).copied()
                            };
                            relax(
                                &mut result,
                                &mut parents,
                                &mut heap,
                                v.id,
                                target,
                                current_dist + link.metric as u64,
                                next_hop,
                            );
                        }
                        x if x == RouterLinkType::StubNetwork as u8 => {
                            // Stub network: link-id is the network/subnet; link-data is the mask.
                            let mask = link.link_data;
                            let pl = mask_to_pl(mask);
                            let prefix = Prefix::new_v4(link.link_id.to_be_bytes(), pl);
                            // The path toward the stub is the path
                            // toward the router advertising it — the
                            // next hop mapping-server labels ride
                            // (RFC 8661 §3.2.2: installed exactly as
                            // if the owner advertised the SID).
                            let next_hop = if rid == root {
                                None // connected: no gateway
                            } else {
                                result.next_hops.get(&VertexId::Router(rid)).copied()
                            };
                            result.stub_routes.push(SpfRoute {
                                prefix,
                                metric: current_dist + link.metric as u64,
                                next_hop,
                                border_router: None,
                            });
                        }
                        _ => {}
                    }
                }
            }
            VertexId::Network(ls_id) => {
                // Network-LSA: list of attached routers. The transit
                // network itself is a destination: its prefix is the
                // DR's interface address masked by the network mask
                // (§12.4.2) at the vertex distance — the broadcast
                // counterpart of a stub link, which §12.4.1.2 no longer
                // advertises once the transit link appears (BIRD
                // spfa_process_net parity).
                if let Some((mask, attached)) = network_lsas.get(&ls_id) {
                    let net = ls_id & *mask;
                    // The path toward the transit network is the path
                    // toward the network vertex (the same one a
                    // mapping-server label for its prefix rides).
                    let next_hop = result.next_hops.get(&VertexId::Network(ls_id)).copied();
                    result.transit_routes.push(SpfRoute {
                        prefix: Prefix::new_v4(net.to_be_bytes(), mask_to_pl(*mask)),
                        metric: current_dist,
                        next_hop,
                        border_router: None,
                    });
                    // §16.1.1 (4): routers attached to a directly
                    // reachable transit network are one hop away —
                    // their address on that network (the Link Data of
                    // the transit link pointing at the DR) is the next
                    // hop. Routers behind a deeper network inherit it.
                    let direct_net = parents.get(&v.id) == Some(&root_id);
                    for &r in attached {
                        let target = VertexId::Router(r);
                        let next_hop = if direct_net {
                            router_address_on_network(&router_lsas, r, ls_id)
                        } else {
                            result.next_hops.get(&v.id).copied()
                        };
                        // Transit networks have zero metric (§16.1).
                        relax(
                            &mut result,
                            &mut parents,
                            &mut heap,
                            v.id,
                            target,
                            current_dist,
                            next_hop,
                        );
                        if direct_net {
                            result.adjacent_routers.insert(r);
                        }
                    }
                }
            }
        }
    }
    result
}

/// Relax the edge `from → target` at `new_dist`: strictly better paths
/// update the distance, the parent (for next-hop inheritance) and the
/// resolved next hop; equal-distance paths keep the first parent, so the
/// result is deterministic for a given LSDB.
fn relax(
    result: &mut SpfResult,
    parents: &mut BTreeMap<VertexId, VertexId>,
    heap: &mut BinaryHeap<SpfVertex>,
    from: VertexId,
    target: VertexId,
    new_dist: u64,
    next_hop: Option<IpAddr>,
) {
    let prev = result.vertices.get(&target).copied().unwrap_or(u64::MAX);
    if new_dist < prev {
        result.vertices.insert(target, new_dist);
        parents.insert(target, from);
        match next_hop {
            Some(nh) => {
                result.next_hops.insert(target, nh);
            }
            None => {
                result.next_hops.remove(&target);
            }
        }
        heap.push(SpfVertex {
            id: target,
            distance: new_dist,
        });
    }
}

/// The address `neighbor` uses on the link back to `towards`: the Link
/// Data of `neighbor`'s point-to-point or virtual link whose Link ID is
/// `towards` (RFC 2328 §A.4.2). Link Data 0 (unnumbered, or the link
/// absent from the neighbour's LSA) yields `None` — the next hop is then
/// unresolvable from the database alone.
fn router_address_towards(
    router_lsas: &BTreeMap<u32, Vec<RouterLink>>,
    neighbor: u32,
    towards: u32,
) -> Option<IpAddr> {
    for link in router_lsas.get(&neighbor)?.iter() {
        if (link.link_type == RouterLinkType::PointToPoint as u8
            || link.link_type == RouterLinkType::VirtualLink as u8)
            && link.link_id == towards
            && link.link_data != 0
        {
            return Some(IpAddr::V4(link.link_data.to_be_bytes()));
        }
    }
    None
}

/// The address `router` uses on the transit network whose Designated
/// Router address is `dr_ip`: the Link Data of its transit link whose
/// Link ID is the DR's address (RFC 2328 §A.4.2). Link Data 0 or a
/// missing transit link yields `None`.
fn router_address_on_network(
    router_lsas: &BTreeMap<u32, Vec<RouterLink>>,
    router: u32,
    dr_ip: u32,
) -> Option<IpAddr> {
    for link in router_lsas.get(&router)?.iter() {
        if link.link_type == RouterLinkType::TransitNetwork as u8
            && link.link_id == dr_ip
            && link.link_data != 0
        {
            return Some(IpAddr::V4(link.link_data.to_be_bytes()));
        }
    }
    None
}

fn mask_to_pl(mask: u32) -> u8 {
    mask_to_prefix_len(mask)
}

/// RFC 2328 §16.2: inter-area route calculation from summary-LSAs.
///
/// Every type-3 summary-LSA whose advertising border router is reachable
/// through the intra-area tree contributes a candidate route with metric
/// `dist(border router) + summary metric`. Candidates with a metric of
/// LSInfinity (`0x00ff_ffff`) are unreachable and skipped. The best
/// candidate per prefix wins — lowest metric, ties broken by the lowest
/// border router ID for determinism.
///
/// Callers must merge the result with the intra-area routes of the same
/// area so that intra-area paths always win for an identical prefix
/// (§16.2 (b)).
pub fn summary_routes(lsdb: &Lsdb, result: &SpfResult) -> Vec<SpfRoute> {
    /// LSInfinity — a summary metric that means "unreachable" (§16.2).
    const LS_INFINITY: u32 = 0x00ff_ffff;
    // (route, advertising border router) — the router ID breaks ties.
    let mut best: BTreeMap<Prefix, (SpfRoute, u32)> = BTreeMap::new();
    for (key, entry) in lsdb.iter() {
        if key.ls_type != LsaTypeV2::SummaryIpLsa as u16 {
            continue;
        }
        // (a) The border router must be reachable via intra-area paths.
        let Some(&dist) = result
            .vertices
            .get(&VertexId::Router(key.advertising_router))
        else {
            continue;
        };
        let Some(body) = decode_summary_lsa_body(&entry.lsa.body) else {
            continue;
        };
        let Some(metric) = body.tos0_metric() else {
            continue;
        };
        if metric >= LS_INFINITY {
            continue;
        }
        let prefix_len = mask_to_prefix_len(body.network_mask);
        let network = entry.lsa.header.link_state_id & body.network_mask;
        let prefix = Prefix::new_v4(network.to_be_bytes(), prefix_len);
        let candidate = SpfRoute {
            prefix,
            metric: dist + u64::from(metric),
            next_hop: None, // resolved from the border router's next hop by the caller
            border_router: Some(key.advertising_router),
        };
        let replace = match best.get(&prefix) {
            None => true,
            Some((cur, cur_border)) => {
                candidate.metric < cur.metric
                    || (candidate.metric == cur.metric && key.advertising_router < *cur_border)
            }
        };
        if replace {
            best.insert(prefix, (candidate, key.advertising_router));
        }
    }
    best.into_values().map(|(route, _)| route).collect()
}

/// Decode Router-LSA links from the body. RFC 2328 §A.4.2. Public:
/// graceful-restart code (RFC 3623 §2.2) walks the pre-restart
/// router-LSA's links to decide whether every adjacency is back.
pub fn decode_router_links(body: &[u8]) -> Vec<RouterLink> {
    let mut out = Vec::new();
    if body.len() < 4 {
        return out;
    }
    // Skip 2-byte flags + 2-byte # of links (v2).
    // Body layout: flags:2, #links:2, then 12-byte links.
    let n = u16::from_be_bytes([body[2], body[3]]) as usize;
    let mut i = 4;
    for _ in 0..n {
        if i + 12 > body.len() {
            break;
        }
        let link_id = u32::from_be_bytes([body[i], body[i + 1], body[i + 2], body[i + 3]]);
        let link_data = u32::from_be_bytes([body[i + 4], body[i + 5], body[i + 6], body[i + 7]]);
        let link_type = body[i + 8];
        let tos = body[i + 9];
        let metric = u16::from_be_bytes([body[i + 10], body[i + 11]]);
        out.push(RouterLink {
            link_id,
            link_data,
            link_type,
            tos,
            metric,
        });
        i += 12;
        // Skip any TOS entries (12 bytes per TOS).
        // (Simplified — assumes no TOS.)
    }
    out
}

fn decode_network_attached_routers(body: &[u8]) -> Vec<u32> {
    let mut out = Vec::new();
    if body.len() < 4 {
        return out;
    }
    // Body: mask:4, then 4-byte attached router-IDs.
    let mut i = 4;
    while i + 4 <= body.len() {
        out.push(u32::from_be_bytes([
            body[i],
            body[i + 1],
            body[i + 2],
            body[i + 3],
        ]));
        i += 4;
    }
    out
}

/// Encode a router-LSA body (RFC 2328 §A.4.2): 2-byte link flags, 2-byte
/// link count, then one 12-byte block per link. Used by tests and by
/// embedders originating router-LSAs.
pub fn encode_router_lsa_body(flags: u16, links: Vec<RouterLink>) -> Vec<u8> {
    let mut v = Vec::with_capacity(4 + 12 * links.len());
    v.extend_from_slice(&flags.to_be_bytes());
    v.extend_from_slice(&(links.len() as u16).to_be_bytes());
    for l in links {
        v.extend_from_slice(&l.link_id.to_be_bytes());
        v.extend_from_slice(&l.link_data.to_be_bytes());
        v.push(l.link_type);
        v.push(l.tos);
        v.extend_from_slice(&l.metric.to_be_bytes());
    }
    v
}

/// Test fixture shared by sibling modules' unit tests (srdb, router
/// integration tests): a minimal Router-LSA with (link_id, link_data,
/// link_type, metric) tuples.
#[cfg(test)]
pub(crate) mod tests_util {
    use crate::lsa::{Lsa, LsaHeader, LsaTypeV2};

    pub(crate) fn router_lsa(rid: u32, links: Vec<(u32, u32, u8, u16)>) -> Lsa {
        let mut body = Vec::new();
        body.extend_from_slice(&0u16.to_be_bytes()); // flags
        body.extend_from_slice(&(links.len() as u16).to_be_bytes());
        for (lid, ldata, ltype, metric) in links {
            body.extend_from_slice(&lid.to_be_bytes());
            body.extend_from_slice(&ldata.to_be_bytes());
            body.push(ltype);
            body.push(0); // tos
            body.extend_from_slice(&metric.to_be_bytes());
        }
        Lsa {
            header: LsaHeader {
                ls_age: 0,
                options: 0,
                ls_type: LsaTypeV2::RouterLsa as u16,
                link_state_id: rid,
                advertising_router: rid,
                ls_sequence_number: 0x80000001,
                ls_checksum: 0,
                length: (LsaHeader::LEN + body.len()) as u16,
            },
            body,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lsa::{Lsa, LsaHeader};
    use lr_core::addr::Prefix;

    fn router_lsa(rid: u32, links: Vec<(u32, u32, u8, u16)>) -> Lsa {
        let mut body = Vec::new();
        body.extend_from_slice(&0u16.to_be_bytes()); // flags
        body.extend_from_slice(&(links.len() as u16).to_be_bytes());
        for (lid, ldata, ltype, metric) in links {
            body.extend_from_slice(&lid.to_be_bytes());
            body.extend_from_slice(&ldata.to_be_bytes());
            body.push(ltype);
            body.push(0); // tos
            body.extend_from_slice(&metric.to_be_bytes());
        }
        Lsa {
            header: LsaHeader {
                ls_age: 0,
                options: 0,
                ls_type: 1,
                link_state_id: rid,
                advertising_router: rid,
                ls_sequence_number: 0x80000001,
                ls_checksum: 0,
                length: (LsaHeader::LEN + body.len()) as u16,
            },
            body,
        }
    }

    #[allow(dead_code)]
    fn stub_lsa(rid: u32, network: u32, mask: u32, metric: u16) -> Lsa {
        router_lsa(
            rid,
            vec![(network, mask, RouterLinkType::StubNetwork as u8, metric)],
        )
    }

    #[test]
    fn dijkstra_basic() {
        let mut db = Lsdb::new();
        // A (1.2.3.4) — link to B (5.6.7.8), metric 10
        db.install(
            router_lsa(
                0x01020304,
                vec![(0x05060708, 0, RouterLinkType::PointToPoint as u8, 10)],
            ),
            0,
        );
        // B (5.6.7.8) — link back to A, stub 10.0.0.0/8 metric 0
        db.install(
            router_lsa(
                0x05060708,
                vec![
                    (0x01020304, 0, RouterLinkType::PointToPoint as u8, 10),
                    (0x0a000000, 0xff000000, RouterLinkType::StubNetwork as u8, 0),
                ],
            ),
            0,
        );
        let res = run_spf(&db, 0x01020304);
        assert_eq!(res.vertices.get(&VertexId::Router(0x05060708)), Some(&10));
        assert_eq!(res.stub_routes.len(), 1);
        let expected = Prefix::new_v4([10, 0, 0, 0], 8);
        assert_eq!(res.stub_routes[0].prefix, expected);
        assert_eq!(res.stub_routes[0].metric, 10);
    }

    #[test]
    fn mask_to_pl_known() {
        assert_eq!(mask_to_pl(0xff000000), 8);
        assert_eq!(mask_to_pl(0xffffff00), 24);
        assert_eq!(mask_to_pl(0xffffffff), 32);
    }

    const P2P: u8 = RouterLinkType::PointToPoint as u8;
    const STUB: u8 = RouterLinkType::StubNetwork as u8;
    const TRANSIT: u8 = RouterLinkType::TransitNetwork as u8;

    fn ip(octets: [u8; 4]) -> IpAddr {
        IpAddr::V4(octets)
    }

    #[test]
    fn next_hops_resolve_from_the_back_link_and_inherit() {
        // A (1.1.1.1) —10— B (2.2.2.2) —10— C (3.3.3.3); B's and C's
        // p2p links carry their own interface addresses as Link Data
        // (RFC 2328 §A.4.2), A's stay 0 (its own address is not a next
        // hop for anyone). RFC 2328 §16.1.1 (5)/(2): nh(B) = B's
        // address on the shared link; nh(C) = nh(B) (inheritance).
        let mut db = Lsdb::new();
        db.install(router_lsa(0x01010101, vec![(0x02020202, 0, P2P, 10)]), 0);
        db.install(
            router_lsa(
                0x02020202,
                vec![
                    // Back-link toward A: Link Data = B's address on A-B.
                    (0x01010101, 0x0a000001, P2P, 10),
                    // Link toward C: Link Data = B's address on B-C.
                    (0x03030303, 0x0a000102, P2P, 10),
                    (0x0a140000, 0xffff0000, STUB, 5),
                ],
            ),
            0,
        );
        db.install(
            // C's back-link toward B: Link Data = C's address on B-C.
            router_lsa(0x03030303, vec![(0x02020202, 0x0a000102, P2P, 10)]),
            0,
        );
        let res = run_spf(&db, 0x01010101);
        assert_eq!(
            res.next_hops.get(&VertexId::Router(0x02020202)),
            Some(&ip([10, 0, 0, 1]))
        );
        assert_eq!(
            res.next_hops.get(&VertexId::Router(0x03030303)),
            Some(&ip([10, 0, 0, 1]))
        );
        // B's stub network routes forward through B (RFC 2328 §16.1.1:
        // a stub network inherits the advertising router vertex's next
        // hop) — the path a mapping-server label rides (RFC 8661
        // §3.2.2).
        assert!(res
            .stub_routes
            .iter()
            .all(|r| r.next_hop == Some(ip([10, 0, 0, 1]))));
        assert!(res.adjacent_routers.contains(&0x02020202));
        assert!(!res.adjacent_routers.contains(&0x03030303));
    }

    #[test]
    fn next_hops_via_transit_network_use_the_attached_router_address() {
        // A (1.1.1.1) has a transit link to the DR address 10.0.0.1;
        // the Network-LSA (ls_id 10.0.0.1, mask /24) attaches A and
        // B (2.2.2.2). §16.1.1 (4): nh(B) = B's address on that
        // network = the Link Data of B's transit link (10.0.0.2).
        let mut db = Lsdb::new();
        db.install(
            router_lsa(0x01010101, vec![(0x0a000001, 0, TRANSIT, 10)]),
            0,
        );
        // B: transit link back to the same DR (its addr 10.0.0.2) plus
        // a deeper p2p neighbor C whose back-link carries C's address.
        db.install(
            router_lsa(
                0x02020202,
                vec![
                    (0x0a000001, 0x0a000002, TRANSIT, 10),
                    (0x03030303, 0x0a000202, P2P, 10),
                ],
            ),
            0,
        );
        db.install(
            router_lsa(0x03030303, vec![(0x02020202, 0x0a000202, P2P, 10)]),
            0,
        );
        let mut net_body = Vec::new();
        net_body.extend_from_slice(&0xffff_ff00u32.to_be_bytes());
        net_body.extend_from_slice(&0x01010101u32.to_be_bytes());
        net_body.extend_from_slice(&0x02020202u32.to_be_bytes());
        db.install(
            Lsa {
                header: LsaHeader {
                    ls_age: 0,
                    options: 2,
                    ls_type: LsaTypeV2::NetworkLsa as u16,
                    link_state_id: 0x0a000001,
                    advertising_router: 0x01010101,
                    ls_sequence_number: 0x80000001,
                    ls_checksum: 0,
                    length: (LsaHeader::LEN + net_body.len()) as u16,
                },
                body: net_body,
            },
            0,
        );
        let res = run_spf(&db, 0x01010101);
        assert_eq!(
            res.next_hops.get(&VertexId::Router(0x02020202)),
            Some(&ip([10, 0, 0, 2]))
        );
        // C hangs off B: inherits B's next hop (§16.1.1 (2)).
        assert_eq!(
            res.next_hops.get(&VertexId::Router(0x03030303)),
            Some(&ip([10, 0, 0, 2]))
        );
        // B is one hop away (via the shared network) — penultimate for
        // its prefix-SIDs; C is not.
        assert!(res.adjacent_routers.contains(&0x02020202));
        assert!(!res.adjacent_routers.contains(&0x03030303));
        // The transit prefix route is still present with no next hop.
        let net = res
            .transit_routes
            .iter()
            .find(|r| r.prefix == Prefix::new_v4([10, 0, 0, 0], 24))
            .expect("transit route");
        assert_eq!(net.metric, 10);
        assert!(net.next_hop.is_none());
    }

    #[test]
    fn zero_link_data_keeps_the_next_hop_unresolved() {
        // B's back-link carries Link Data 0 (unnumbered): no next hop
        // can be resolved from the database, so the vertex has none.
        let mut db = Lsdb::new();
        db.install(router_lsa(0x01010101, vec![(0x02020202, 0, P2P, 10)]), 0);
        db.install(router_lsa(0x02020202, vec![(0x01010101, 0, P2P, 10)]), 0);
        let res = run_spf(&db, 0x01010101);
        assert!(!res.next_hops.contains_key(&VertexId::Router(0x02020202)));
        // Topology itself is unaffected.
        assert_eq!(res.vertices.get(&VertexId::Router(0x02020202)), Some(&10));
    }

    #[test]
    fn virtual_links_act_as_router_adjacencies() {
        // Backbone repair (RFC 2328 §15): R1 reaches R3 only through the
        // virtual adjacency R1 == R2 (metric 7, the transit-area path
        // cost); R2 also has a physical p2p link to R3 (metric 3).
        let mut db = Lsdb::new();
        db.install(
            router_lsa(
                0x01010101,
                vec![(0x02020202, 0, RouterLinkType::VirtualLink as u8, 7)],
            ),
            0,
        );
        db.install(
            router_lsa(
                0x02020202,
                vec![
                    (0x01010101, 0, RouterLinkType::VirtualLink as u8, 7),
                    (0x03030303, 0, RouterLinkType::PointToPoint as u8, 3),
                ],
            ),
            0,
        );
        db.install(
            router_lsa(
                0x03030303,
                vec![
                    (0x02020202, 0, RouterLinkType::PointToPoint as u8, 3),
                    (0x0a646400, 0xffffff00, RouterLinkType::StubNetwork as u8, 2),
                ],
            ),
            0,
        );
        // From the far side of the virtual link: R3 is 7 + 3 away and its
        // stub network adds 2 more.
        let res = run_spf(&db, 0x01010101);
        assert_eq!(res.vertices.get(&VertexId::Router(0x03030303)), Some(&10));
        assert_eq!(res.vertices.get(&VertexId::Router(0x02020202)), Some(&7));
        assert_eq!(res.stub_routes.len(), 1);
        assert_eq!(res.stub_routes[0].metric, 12);
        // And in the other direction the virtual link is symmetric.
        let res = run_spf(&db, 0x03030303);
        assert_eq!(res.vertices.get(&VertexId::Router(0x01010101)), Some(&10));
    }

    fn summary_lsa(adv: u32, network: u32, mask: u32, metric: u32, seq: u32) -> Lsa {
        let body = crate::lsa::encode_summary_lsa_body(mask, metric);
        Lsa {
            header: LsaHeader {
                ls_age: 0,
                options: 0x02,
                ls_type: LsaTypeV2::SummaryIpLsa as u16,
                link_state_id: network,
                advertising_router: adv,
                ls_sequence_number: seq,
                ls_checksum: 0,
                length: (LsaHeader::LEN + body.len()) as u16,
            },
            body,
        }
    }

    /// Area-0 topology: root (1.1.1.1) --10-- BR-a (2.2.2.2),
    /// root --20-- BR-b (3.3.3.3); BR-a and BR-b are border routers
    /// advertising summaries.
    fn two_border_routers() -> Lsdb {
        let mut db = Lsdb::new();
        let root = 0x01010101;
        let br_a = 0x02020202;
        let br_b = 0x03030303;
        db.install(
            router_lsa(
                root,
                vec![(br_a, 0, RouterLinkType::PointToPoint as u8, 10)],
            ),
            0,
        );
        db.install(
            router_lsa(
                br_a,
                vec![(root, 0, RouterLinkType::PointToPoint as u8, 10)],
            ),
            0,
        );
        db.install(
            router_lsa(
                root,
                vec![(br_b, 0, RouterLinkType::PointToPoint as u8, 20)],
            ),
            0,
        );
        db.install(
            router_lsa(
                br_b,
                vec![(root, 0, RouterLinkType::PointToPoint as u8, 20)],
            ),
            0,
        );
        db
    }

    #[test]
    fn summary_route_requires_reachable_border() {
        let mut db = two_border_routers();
        let spf = run_spf(&db, 0x01010101);
        // Summary from unreachable border router 9.9.9.9: ignored.
        db.install(
            summary_lsa(0x09090909, 0x0a000000, 0xff000000, 5, 0x80000001),
            0,
        );
        assert!(summary_routes(&db, &spf).is_empty());
    }

    #[test]
    fn summary_metric_adds_border_distance() {
        let mut db = two_border_routers();
        let spf = run_spf(&db, 0x01010101);
        // BR-a (dist 10) advertises 10.0.0.0/8 metric 7 → 17.
        db.install(
            summary_lsa(0x02020202, 0x0a000000, 0xff000000, 7, 0x80000001),
            0,
        );
        let routes = summary_routes(&db, &spf);
        assert_eq!(routes.len(), 1);
        assert_eq!(routes[0].prefix, Prefix::new_v4([10, 0, 0, 0], 8));
        assert_eq!(routes[0].metric, 17);
    }

    #[test]
    fn summary_prefers_lower_total_metric_then_lower_border() {
        let mut db = two_border_routers();
        let spf = run_spf(&db, 0x01010101);
        // BR-a: dist 10 + 7 = 17; BR-b: dist 20 + 5 = 25 → BR-a wins.
        db.install(
            summary_lsa(0x02020202, 0x0a000000, 0xff000000, 7, 0x80000001),
            0,
        );
        db.install(
            summary_lsa(0x03030303, 0x0a000000, 0xff000000, 5, 0x80000001),
            0,
        );
        let routes = summary_routes(&db, &spf);
        assert_eq!(routes.len(), 1);
        assert_eq!(routes[0].metric, 17);

        // Equal total metric → lower border router ID (BR-a) wins.
        let mut db2 = two_border_routers();
        let spf2 = run_spf(&db2, 0x01010101);
        db2.install(
            summary_lsa(0x02020202, 0x0a000000, 0xff000000, 10, 0x80000001),
            0,
        );
        db2.install(
            summary_lsa(0x03030303, 0x0a000000, 0xff000000, 0, 0x80000001),
            0,
        );
        let routes2 = summary_routes(&db2, &spf2);
        assert_eq!(routes2.len(), 1);
        assert_eq!(routes2[0].metric, 20); // both 20 — deterministic winner
    }

    #[test]
    fn summary_ls_infinity_and_garbage_ignored() {
        let mut db = two_border_routers();
        let spf = run_spf(&db, 0x01010101);
        // LSInfinity means unreachable.
        db.install(
            summary_lsa(0x02020202, 0x0a000000, 0xff000000, 0x00ff_ffff, 0x80000001),
            0,
        );
        // Truncated body (no TOS entry).
        let mut bad = summary_lsa(0x02020202, 0x0b000000, 0xff000000, 1, 0x80000001);
        bad.body.truncate(4);
        db.install(bad, 0);
        assert!(summary_routes(&db, &spf).is_empty());
    }
}

// ---------------------------------------------------------------------------
// OSPFv3 SPF (RFC 5340 §4.8)
// ---------------------------------------------------------------------------

use crate::lsa::{
    V3IntraAreaPrefixBody, V3LinkLsaBody, V3NetworkLsaBody, V3Prefix, V3RouterLsaBody,
    LINK_TYPE_POINTTOPOINT, LINK_TYPE_TRANSIT, LINK_TYPE_VIRTUAL, LS_TYPE_INTRA_PREFIX,
    LS_TYPE_LINK, LS_TYPE_NETWORK, LS_TYPE_ROUTER, PREFIX_OPT_LA, PREFIX_OPT_NU,
};

/// One vertex in the v3 SPF tree. Unlike v2, the Network vertex needs
/// the full (DR Router ID, DR Interface ID) pair: the v3 Network-LSA is
/// keyed by the DR's Interface ID as its Link State ID (§A.4.4), and
/// several transit networks may share the same DR.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum V3VertexId {
    Router(u32),
    /// (DR Router ID, DR Interface ID).
    Network(u32, u32),
}

/// A resolved IPv6 first hop: the neighbor's link-local address (the
/// only legal unicast next hop for OSPFv3, RFC 5340 §4.2.1) plus the
/// Interface ID of *our* interface toward it — the value the kernel
/// mirror needs as the outgoing interface (RTA_OIF for a link-local
/// gateway). Interface IDs are the kernel ifindex by daemon convention.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct V3NextHop {
    pub link_local: IpAddr,
    pub interface_id: u32,
}

/// The result of the v3 intra-area calculation. `routes` reuses
/// [`SpfRoute`] — every v3 intra-area prefix is intra-area by
/// definition, so `border_router` is always `None`.
#[derive(Debug, Clone, Default)]
pub struct SpfResultV3 {
    pub vertices: BTreeMap<V3VertexId, u64>,
    /// The resolved first hop per vertex where the LSDB carries one.
    pub next_hops: BTreeMap<V3VertexId, V3NextHop>,
    /// Routers one hop from the root (direct p2p adjacency, or routers
    /// on a directly attached transit network).
    pub adjacent_routers: BTreeSet<u32>,
    /// Intra-area prefixes from Intra-Area-Prefix-LSAs (§4.4.3.5),
    /// deduplicated per prefix keeping the lowest metric.
    pub routes: Vec<SpfRoute>,
}

/// The LSDB pre-scan for the v3 calculation: per-type maps built once so
/// the relaxation loop never re-walks the database.
struct V3Topology {
    /// Router-LSAs (0x2001) by advertising router. One LSA per router:
    /// the first instance in database order wins (fragmented
    /// Router-LSAs — multiple per router — are not split apart here).
    router_lsas: BTreeMap<u32, V3RouterLsaBody>,
    /// Network-LSAs (0x2002) keyed (DR Router ID, DR Interface ID).
    network_lsas: BTreeMap<(u32, u32), V3NetworkLsaBody>,
    /// Link-LSAs (0x0008) keyed (Advertising Router, Interface ID) →
    /// the link-local address. The Interface ID is the Link State ID
    /// (§A.4.9).
    link_locals: BTreeMap<(u32, u32), [u8; 16]>,
    /// Intra-Area-Prefix-LSAs (0x2009), decoded:
    /// (ref type, ref LS ID, ref Adv Router, prefixes).
    intra_prefixes: Vec<(u16, u32, u32, Vec<V3Prefix>)>,
}

impl V3Topology {
    fn from_lsdb(lsdb: &Lsdb) -> Self {
        let mut t = Self {
            router_lsas: BTreeMap::new(),
            network_lsas: BTreeMap::new(),
            link_locals: BTreeMap::new(),
            intra_prefixes: Vec::new(),
        };
        for (key, entry) in lsdb.iter() {
            match key.ls_type {
                x if x == LS_TYPE_ROUTER => {
                    if let Some(body) = V3RouterLsaBody::decode(&entry.lsa.body) {
                        t.router_lsas.entry(key.advertising_router).or_insert(body);
                    }
                }
                x if x == LS_TYPE_NETWORK => {
                    if let Some(body) = V3NetworkLsaBody::decode(&entry.lsa.body) {
                        t.network_lsas
                            .entry((key.advertising_router, key.link_state_id))
                            .or_insert(body);
                    }
                }
                x if x == LS_TYPE_LINK => {
                    if let Some(body) = V3LinkLsaBody::decode(&entry.lsa.body) {
                        t.link_locals
                            .entry((key.advertising_router, key.link_state_id))
                            .or_insert(body.link_local);
                    }
                }
                x if x == LS_TYPE_INTRA_PREFIX => {
                    if let Some(body) = V3IntraAreaPrefixBody::decode(&entry.lsa.body) {
                        t.intra_prefixes.push((
                            body.ref_type,
                            body.ref_ls_id,
                            body.ref_adv_router,
                            body.prefixes,
                        ));
                    }
                }
                _ => {}
            }
        }
        t
    }

    /// The neighbor's link-local on the link where it uses interface
    /// `neighbor_interface_id` (§16.1.1 for v3: read from the
    /// neighbor's Link-LSA whose Link State ID is that Interface ID).
    fn link_local_of(&self, router: u32, interface_id: u32) -> Option<[u8; 16]> {
        self.link_locals.get(&(router, interface_id)).copied()
    }

    /// The Interface ID `router` uses on the transit network whose DR
    /// is (`dr_router`, `dr_ifid`): the Interface ID field of the
    /// transit link in `router`'s own Router-LSA pointing back at the
    /// network — the v3 counterpart of the v2 `router_address_on_network`
    /// resolution, and unambiguous where per-link LSDBs are not
    /// available (an area-LSDB SPF sees every Link-LSA of a shared
    /// router; the back-link picks the right one).
    fn interface_on_network(&self, router: u32, dr_router: u32, dr_ifid: u32) -> Option<u32> {
        self.router_lsas.get(&router)?.links.iter().find_map(|l| {
            (l.link_type == LINK_TYPE_TRANSIT
                && l.neighbor_router_id == dr_router
                && l.neighbor_interface_id == dr_ifid)
                .then_some(l.interface_id)
        })
    }

    /// Bidirectional check (FRR `ospf6_lsdesc_backlink`): a p2p/virtual
    /// edge R→N counts only when N's Router-LSA has a p2p/virtual link
    /// back to R.
    fn has_backlink(&self, neighbor: u32, towards: u32) -> bool {
        self.router_lsas
            .get(&neighbor)
            .map(|b| {
                b.links.iter().any(|l| {
                    (l.link_type == LINK_TYPE_POINTTOPOINT || l.link_type == LINK_TYPE_VIRTUAL)
                        && l.neighbor_router_id == towards
                })
            })
            .unwrap_or(false)
    }
}

/// Run the OSPFv3 intra-area shortest-path calculation (RFC 5340 §4.8)
/// starting at the Router vertex `root`.
///
/// The tree is built from Router-LSAs (0x2001) and Network-LSAs (0x2002)
/// exactly as in v2; the differences are the next-hop model and the
/// prefix attachment:
///
/// - the next hop of a direct p2p neighbor is the neighbor's link-local
///   address, read from its Link-LSA with Link State ID = the Neighbor
///   Interface ID of our p2p link (§16.1.1 v3 form), and the outgoing
///   Interface ID is the Interface ID field of our own p2p link;
/// - routers on a directly attached transit network resolve their
///   link-local through their back-link: their Router-LSA transit link
///   pointing at the network carries the Interface ID they use there,
///   which indexes their Link-LSA;
/// - deeper vertices inherit their parent's next hop (§16.1.1 (2)-(3));
/// - the prefixes themselves arrive via Intra-Area-Prefix-LSAs attached
///   to Router- or Network-LSAs (§4.4.3.5) — prefixes with the NU or LA
///   bit set take no part in the unicast calculation (§A.4.1).
///
/// Unresolvable next hops (missing Link-LSAs) still admit the vertex to
/// the tree but leave the route without a gateway — the embedder
/// decides whether to keep it.
pub fn run_spf_v3(lsdb: &Lsdb, root: u32) -> SpfResultV3 {
    let topo = V3Topology::from_lsdb(lsdb);
    let mut result = SpfResultV3::default();
    let mut parents: BTreeMap<V3VertexId, V3VertexId> = BTreeMap::new();
    let root_id = V3VertexId::Router(root);
    // Distances keyed by the v3 vertex id.
    let mut dist: BTreeMap<V3VertexId, u64> = BTreeMap::new();
    dist.insert(root_id, 0);

    // Min-heap over (distance, vertex) pairs.
    let mut queue: BinaryHeap<(std::cmp::Reverse<u64>, V3VertexId)> = BinaryHeap::new();
    queue.push((std::cmp::Reverse(0), root_id));

    let relax = |dist: &mut BTreeMap<V3VertexId, u64>,
                 result: &mut SpfResultV3,
                 parents: &mut BTreeMap<V3VertexId, V3VertexId>,
                 queue: &mut BinaryHeap<(std::cmp::Reverse<u64>, V3VertexId)>,
                 from: V3VertexId,
                 target: V3VertexId,
                 new_dist: u64,
                 next_hop: Option<V3NextHop>| {
        let prev = dist.get(&target).copied().unwrap_or(u64::MAX);
        if new_dist < prev {
            dist.insert(target, new_dist);
            result.vertices.insert(target, new_dist);
            parents.insert(target, from);
            match next_hop {
                Some(nh) => {
                    result.next_hops.insert(target, nh);
                }
                None => {
                    result.next_hops.remove(&target);
                }
            }
            queue.push((std::cmp::Reverse(new_dist), target));
        }
    };

    while let Some((_, v_id)) = queue.pop() {
        let Some(&current_dist) = dist.get(&v_id) else {
            continue;
        };
        match v_id {
            V3VertexId::Router(rid) => {
                let Some(body) = topo.router_lsas.get(&rid) else {
                    continue;
                };
                for link in &body.links {
                    match link.link_type {
                        x if x == LINK_TYPE_POINTTOPOINT || x == LINK_TYPE_VIRTUAL => {
                            let target = V3VertexId::Router(link.neighbor_router_id);
                            if !topo.has_backlink(link.neighbor_router_id, rid) {
                                continue;
                            }
                            let next_hop = if rid == root {
                                topo.link_local_of(
                                    link.neighbor_router_id,
                                    link.neighbor_interface_id,
                                )
                                .map(|ll| V3NextHop {
                                    link_local: IpAddr::V6(ll),
                                    interface_id: link.interface_id,
                                })
                            } else {
                                result.next_hops.get(&v_id).copied()
                            };
                            relax(
                                &mut dist,
                                &mut result,
                                &mut parents,
                                &mut queue,
                                v_id,
                                target,
                                current_dist + u64::from(link.metric),
                                next_hop,
                            );
                            if rid == root && x == LINK_TYPE_POINTTOPOINT {
                                result.adjacent_routers.insert(link.neighbor_router_id);
                            }
                        }
                        x if x == LINK_TYPE_TRANSIT => {
                            let target = V3VertexId::Network(
                                link.neighbor_router_id,
                                link.neighbor_interface_id,
                            );
                            // Backlink: the Network-LSA must exist and
                            // list this router as attached (§16.1 for
                            // v3 — bidirectional connectivity).
                            let listed = topo
                                .network_lsas
                                .get(&(link.neighbor_router_id, link.neighbor_interface_id))
                                .map(|net| net.routers.contains(&rid))
                                .unwrap_or(false);
                            if !listed {
                                continue;
                            }
                            let next_hop = if rid == root {
                                None // directly connected
                            } else {
                                result.next_hops.get(&v_id).copied()
                            };
                            relax(
                                &mut dist,
                                &mut result,
                                &mut parents,
                                &mut queue,
                                v_id,
                                target,
                                current_dist + u64::from(link.metric),
                                next_hop,
                            );
                        }
                        _ => {}
                    }
                }
            }
            V3VertexId::Network(dr_rid, dr_ifid) => {
                let Some(net) = topo.network_lsas.get(&(dr_rid, dr_ifid)) else {
                    continue;
                };
                // §4.8: transit networks cost nothing to traverse —
                // attached routers relax at the network's distance.
                let direct_net = parents.get(&v_id) == Some(&V3VertexId::Router(root));
                for &r in &net.routers {
                    let target = V3VertexId::Router(r);
                    let next_hop = if direct_net && r != root {
                        // Resolve through the back-link transit entry,
                        // then the Link-LSA (see `interface_on_network`).
                        topo.interface_on_network(r, dr_rid, dr_ifid)
                            .and_then(|iface| topo.link_local_of(r, iface))
                            .map(|ll| V3NextHop {
                                link_local: IpAddr::V6(ll),
                                // Our outgoing interface is the Interface
                                // ID of the ROOT's transit link toward
                                // this network — recovered from the
                                // root's own Router-LSA below.
                                interface_id: topo
                                    .router_lsas
                                    .get(&root)
                                    .and_then(|b| {
                                        b.links.iter().find_map(|l| {
                                            (l.link_type == LINK_TYPE_TRANSIT
                                                && l.neighbor_router_id == dr_rid
                                                && l.neighbor_interface_id == dr_ifid)
                                                .then_some(l.interface_id)
                                        })
                                    })
                                    .unwrap_or(0),
                            })
                    } else {
                        result.next_hops.get(&v_id).copied()
                    };
                    relax(
                        &mut dist,
                        &mut result,
                        &mut parents,
                        &mut queue,
                        v_id,
                        target,
                        current_dist,
                        next_hop,
                    );
                    if direct_net && r != root {
                        result.adjacent_routers.insert(r);
                    }
                }
            }
        }
    }

    // Attach the Intra-Area-Prefix-LSA prefixes (§4.8.1): the metric of
    // a prefix is the distance of its referenced vertex, deduplicated
    // per prefix keeping the lowest metric (lowest advertising router on
    // ties, for determinism).
    let mut best: BTreeMap<Prefix, (SpfRoute, u32)> = BTreeMap::new();
    for (ref_type, ref_ls_id, ref_adv, prefixes) in &topo.intra_prefixes {
        let vertex = match *ref_type {
            x if x == LS_TYPE_ROUTER => V3VertexId::Router(*ref_adv),
            x if x == LS_TYPE_NETWORK => V3VertexId::Network(*ref_adv, *ref_ls_id),
            _ => continue,
        };
        let Some(&d) = dist.get(&vertex) else {
            continue;
        };
        let next_hop = result.next_hops.get(&vertex).copied();
        for p in prefixes {
            // §A.4.1: NU-marked prefixes are excluded from the unicast
            // calculation; LA-marked prefixes are the advertising
            // router's own local address, never a forwarding target.
            if p.options & (PREFIX_OPT_NU | PREFIX_OPT_LA) != 0 {
                continue;
            }
            let prefix = Prefix::new_v6(p.addr, p.prefix_len);
            let route = SpfRoute {
                prefix,
                metric: d,
                next_hop: next_hop.map(|nh| nh.link_local),
                border_router: None,
            };
            let replace = match best.get(&prefix) {
                None => true,
                Some((cur, cur_adv)) => {
                    route.metric < cur.metric || (route.metric == cur.metric && *ref_adv < *cur_adv)
                }
            };
            if replace {
                best.insert(prefix, (route, *ref_adv));
            }
        }
    }
    result.routes = best.into_values().map(|(r, _)| r).collect();
    result
}

#[cfg(test)]
mod v3_tests {
    use super::*;
    use crate::lsa::v3::{
        originate_v3_intra_area_prefix_lsa, originate_v3_link_lsa, originate_v3_network_lsa,
        originate_v3_router_lsa, LINK_TYPE_POINTTOPOINT, LINK_TYPE_TRANSIT, LS_TYPE_ROUTER,
        ROUTER_BIT_V6,
    };

    /// Two routers on a p2p link (interface ids 5 and 3), each with one
    /// /64 on the link. r1 must learn r2's prefix via r2's link-local,
    /// with our outgoing interface id 5.
    #[test]
    fn v3_p2p_two_routers_exchange_prefixes() {
        let mut db = Lsdb::new();
        let ll2 = fe80(2);
        let ll1 = fe80(1);
        // r1's Router-LSA: one p2p link to r2 (metric 10).
        db.install(
            originate_v3_router_lsa(
                0x0a00_0001,
                ROUTER_BIT_V6,
                0x13,
                &[crate::lsa::v3::V3RouterLink {
                    link_type: LINK_TYPE_POINTTOPOINT,
                    metric: 10,
                    interface_id: 5,
                    neighbor_interface_id: 3,
                    neighbor_router_id: 0x0a00_0002,
                }],
                None,
            )
            .unwrap(),
            0,
        );
        // r2's Router-LSA: the back-link.
        db.install(
            originate_v3_router_lsa(
                0x0a00_0002,
                ROUTER_BIT_V6,
                0x13,
                &[crate::lsa::v3::V3RouterLink {
                    link_type: LINK_TYPE_POINTTOPOINT,
                    metric: 10,
                    interface_id: 3,
                    neighbor_interface_id: 5,
                    neighbor_router_id: 0x0a00_0001,
                }],
                None,
            )
            .unwrap(),
            0,
        );
        // Link-LSAs: each router's link-local on the shared link, LS ID
        // = its interface id there.
        db.install(
            originate_v3_link_lsa(0x0a00_0001, 5, 1, 0x13, ll1, vec![], None).unwrap(),
            0,
        );
        db.install(
            originate_v3_link_lsa(0x0a00_0002, 3, 1, 0x13, ll2, vec![], None).unwrap(),
            0,
        );
        // Intra-Area-Prefix-LSAs: each router's own /64 (the addresses
        // of the link, NU/LA clear).
        let p1 = net64(1);
        let p2 = net64(2);
        db.install(
            originate_v3_intra_area_prefix_lsa(
                0x0a00_0001,
                1,
                LS_TYPE_ROUTER,
                0,
                0x0a00_0001,
                vec![p1.clone()],
                None,
            )
            .unwrap(),
            0,
        );
        db.install(
            originate_v3_intra_area_prefix_lsa(
                0x0a00_0002,
                1,
                LS_TYPE_ROUTER,
                0,
                0x0a00_0002,
                vec![p2.clone()],
                None,
            )
            .unwrap(),
            0,
        );

        let spf = run_spf_v3(&db, 0x0a00_0001);
        // r2 is reachable at cost 10 with r2's link-local as next hop
        // and our interface 5 as oif.
        let r2 = V3VertexId::Router(0x0a00_0002);
        assert_eq!(spf.vertices.get(&r2), Some(&10));
        let nh = spf.next_hops.get(&r2).expect("next hop resolved");
        assert_eq!(nh.link_local, IpAddr::V6(ll2));
        assert_eq!(nh.interface_id, 5, "our p2p link's interface id");
        assert!(spf.adjacent_routers.contains(&0x0a00_0002));
        // Routes: r1's own prefix (connected, metric 0) and r2's prefix
        // (metric 10 via r2's link-local).
        let find = |p: &Prefix| {
            spf.routes
                .iter()
                .find(|r| r.prefix == *p)
                .cloned()
                .unwrap_or_else(|| panic!("route {} missing", p))
        };
        let own = find(&route_of(&p1));
        assert_eq!(own.metric, 0);
        assert_eq!(own.next_hop, None, "own prefixes are connected");
        let remote = find(&route_of(&p2));
        assert_eq!(remote.metric, 10);
        assert_eq!(remote.next_hop, Some(IpAddr::V6(ll2)));
    }

    /// A three-router chain r1 - r2 - r3 (p2p): r1 must reach r3 through
    /// r2's link-local (inherited next hop), at cost 20.
    #[test]
    fn v3_three_hop_chain_inherits_next_hop() {
        let mut db = Lsdb::new();
        let (r1, r2, r3) = (0x0a00_0001, 0x0a00_0002, 0x0a00_0003);
        let link = |metric: u16, ifid: u32, nifid: u32, nrid: u32| crate::lsa::v3::V3RouterLink {
            link_type: LINK_TYPE_POINTTOPOINT,
            metric,
            interface_id: ifid,
            neighbor_interface_id: nifid,
            neighbor_router_id: nrid,
        };
        db.install(
            originate_v3_router_lsa(r1, ROUTER_BIT_V6, 0x13, &[link(10, 5, 3, r2)], None).unwrap(),
            0,
        );
        db.install(
            originate_v3_router_lsa(
                r2,
                ROUTER_BIT_V6,
                0x13,
                &[link(10, 3, 5, r1), link(10, 6, 7, r3)],
                None,
            )
            .unwrap(),
            0,
        );
        db.install(
            originate_v3_router_lsa(r3, ROUTER_BIT_V6, 0x13, &[link(10, 7, 6, r2)], None).unwrap(),
            0,
        );
        // Link-LSAs for every interface.
        db.install(
            originate_v3_link_lsa(r1, 5, 1, 0x13, fe80(1), vec![], None).unwrap(),
            0,
        );
        db.install(
            originate_v3_link_lsa(r2, 3, 1, 0x13, fe80(2), vec![], None).unwrap(),
            0,
        );
        db.install(
            originate_v3_link_lsa(r2, 6, 1, 0x13, fe80(22), vec![], None).unwrap(),
            0,
        );
        db.install(
            originate_v3_link_lsa(r3, 7, 1, 0x13, fe80(3), vec![], None).unwrap(),
            0,
        );
        // r3's own /64.
        let p3 = net64(3);
        db.install(
            originate_v3_intra_area_prefix_lsa(
                r3,
                1,
                LS_TYPE_ROUTER,
                0,
                r3,
                vec![p3.clone()],
                None,
            )
            .unwrap(),
            0,
        );

        let spf = run_spf_v3(&db, r1);
        let v3v = V3VertexId::Router(r3);
        assert_eq!(spf.vertices.get(&v3v), Some(&20), "10 + 10");
        let nh = spf.next_hops.get(&v3v).expect("inherited next hop");
        assert_eq!(nh.link_local, IpAddr::V6(fe80(2)), "via r2");
        let route = spf
            .routes
            .iter()
            .find(|r| r.prefix == route_of(&p3))
            .expect("r3's prefix");
        assert_eq!(route.metric, 20);
        assert_eq!(route.next_hop, Some(IpAddr::V6(fe80(2))));
    }

    /// A transit segment with an elected DR: the DR originates the
    /// Network-LSA and the segment's Intra-Area-Prefix-LSA. A router on
    /// the segment (r1) resolves the other member's (r3's) link-local
    /// through the back-link, without a p2p adjacency.
    #[test]
    fn v3_transit_network_resolves_members() {
        let mut db = Lsdb::new();
        let (r1, r2, r3) = (0x0a00_0001, 0x0a00_0002, 0x0a00_0003);
        // r2 is the DR; its interface id on the segment is 9; r1's is 5,
        // r3's is 7. r1 and r3 are fully adjacent to r2 only.
        db.install(
            originate_v3_router_lsa(
                r1,
                ROUTER_BIT_V6,
                0x13,
                &[crate::lsa::v3::V3RouterLink {
                    link_type: LINK_TYPE_TRANSIT,
                    metric: 10,
                    interface_id: 5,
                    neighbor_interface_id: 9,
                    neighbor_router_id: r2,
                }],
                None,
            )
            .unwrap(),
            0,
        );
        db.install(
            originate_v3_router_lsa(
                r2,
                ROUTER_BIT_V6,
                0x13,
                &[crate::lsa::v3::V3RouterLink {
                    link_type: LINK_TYPE_TRANSIT,
                    metric: 10,
                    interface_id: 9,
                    neighbor_interface_id: 9,
                    neighbor_router_id: r2,
                }],
                None,
            )
            .unwrap(),
            0,
        );
        db.install(
            originate_v3_router_lsa(
                r3,
                ROUTER_BIT_V6,
                0x13,
                &[crate::lsa::v3::V3RouterLink {
                    link_type: LINK_TYPE_TRANSIT,
                    metric: 10,
                    interface_id: 7,
                    neighbor_interface_id: 9,
                    neighbor_router_id: r2,
                }],
                None,
            )
            .unwrap(),
            0,
        );
        // Network-LSA: DR r2, LS ID = its interface id 9, all three
        // attached.
        db.install(
            originate_v3_network_lsa(r2, 9, 0x13, &[r1, r2, r3], None).unwrap(),
            0,
        );
        // Link-LSAs on the segment.
        db.install(
            originate_v3_link_lsa(r1, 5, 1, 0x13, fe80(1), vec![], None).unwrap(),
            0,
        );
        db.install(
            originate_v3_link_lsa(r2, 9, 1, 0x13, fe80(2), vec![], None).unwrap(),
            0,
        );
        db.install(
            originate_v3_link_lsa(r3, 7, 1, 0x13, fe80(3), vec![], None).unwrap(),
            0,
        );
        // The segment's prefix, attached to the Network-LSA.
        let seg = net64(9);
        let seg_prefix = Prefix::new_v6(seg.addr, seg.prefix_len);
        db.install(
            originate_v3_intra_area_prefix_lsa(
                r2,
                1,
                crate::lsa::v3::LS_TYPE_NETWORK,
                9,
                r2,
                vec![seg.clone()],
                None,
            )
            .unwrap(),
            0,
        );

        let spf = run_spf_v3(&db, r1);
        // The network vertex: cost 10.
        let net = V3VertexId::Network(r2, 9);
        assert_eq!(spf.vertices.get(&net), Some(&10));
        // r2 and r3 ride the segment: both at cost 10, r3's link-local
        // resolved via its back-link transit entry (interface id 7 →
        // Link-LSA 7).
        for (rid, ll) in [(r2, fe80(2)), (r3, fe80(3))] {
            let v = V3VertexId::Router(rid);
            assert_eq!(spf.vertices.get(&v), Some(&10));
            let nh = spf
                .next_hops
                .get(&v)
                .unwrap_or_else(|| panic!("nh for {rid}"));
            assert_eq!(nh.link_local, IpAddr::V6(ll));
            assert_eq!(nh.interface_id, 5, "our interface on the segment");
            assert!(spf.adjacent_routers.contains(&rid));
        }
        // The segment prefix is connected for r1 (directly attached).
        let route = spf.routes.iter().find(|r| r.prefix == seg_prefix).unwrap();
        assert_eq!(route.metric, 10);
        assert_eq!(route.next_hop, None);
    }

    /// Prefixes carrying the NU or LA bit are excluded from the unicast
    /// calculation (§A.4.1).
    #[test]
    fn v3_nu_and_la_prefixes_excluded() {
        let mut db = Lsdb::new();
        let (r1, r2) = (0x0a00_0001, 0x0a00_0002);
        let link = crate::lsa::v3::V3RouterLink {
            link_type: LINK_TYPE_POINTTOPOINT,
            metric: 10,
            interface_id: 5,
            neighbor_interface_id: 3,
            neighbor_router_id: r2,
        };
        db.install(
            originate_v3_router_lsa(r1, ROUTER_BIT_V6, 0x13, &[link], None).unwrap(),
            0,
        );
        let back = crate::lsa::v3::V3RouterLink {
            link_type: LINK_TYPE_POINTTOPOINT,
            metric: 10,
            interface_id: 3,
            neighbor_interface_id: 5,
            neighbor_router_id: r1,
        };
        db.install(
            originate_v3_router_lsa(r2, ROUTER_BIT_V6, 0x13, &[back], None).unwrap(),
            0,
        );
        db.install(
            originate_v3_link_lsa(r1, 5, 1, 0x13, fe80(1), vec![], None).unwrap(),
            0,
        );
        db.install(
            originate_v3_link_lsa(r2, 3, 1, 0x13, fe80(2), vec![], None).unwrap(),
            0,
        );
        // r2 advertises three prefixes: normal, NU, LA.
        let normal = net64(3);
        let mut nu = net64(4);
        nu.options = crate::lsa::v3::PREFIX_OPT_NU;
        let mut la = net64(5);
        la.options = crate::lsa::v3::PREFIX_OPT_LA;
        db.install(
            originate_v3_intra_area_prefix_lsa(
                r2,
                1,
                LS_TYPE_ROUTER,
                0,
                r2,
                vec![normal.clone(), nu, la],
                None,
            )
            .unwrap(),
            0,
        );
        let spf = run_spf_v3(&db, r1);
        assert!(spf.routes.iter().any(|r| r.prefix == route_of(&normal)));
        assert!(!spf.routes.iter().any(|r| r.prefix == route_of(&net64(4))));
        assert!(!spf.routes.iter().any(|r| r.prefix == route_of(&net64(5))));
    }

    /// A missing Link-LSA leaves the vertex reachable but without a
    /// next hop — the route survives without a gateway.
    #[test]
    fn v3_missing_link_lsa_yields_no_next_hop() {
        let mut db = Lsdb::new();
        let (r1, r2) = (0x0a00_0001, 0x0a00_0002);
        let link = crate::lsa::v3::V3RouterLink {
            link_type: LINK_TYPE_POINTTOPOINT,
            metric: 10,
            interface_id: 5,
            neighbor_interface_id: 3,
            neighbor_router_id: r2,
        };
        db.install(
            originate_v3_router_lsa(r1, ROUTER_BIT_V6, 0x13, &[link], None).unwrap(),
            0,
        );
        let back = crate::lsa::v3::V3RouterLink {
            link_type: LINK_TYPE_POINTTOPOINT,
            metric: 10,
            interface_id: 3,
            neighbor_interface_id: 5,
            neighbor_router_id: r1,
        };
        db.install(
            originate_v3_router_lsa(r2, ROUTER_BIT_V6, 0x13, &[back], None).unwrap(),
            0,
        );
        // Only r1's Link-LSA: r2's link-local is unknown.
        db.install(
            originate_v3_link_lsa(r1, 5, 1, 0x13, fe80(1), vec![], None).unwrap(),
            0,
        );
        let p2 = net64(2);
        db.install(
            originate_v3_intra_area_prefix_lsa(
                r2,
                1,
                LS_TYPE_ROUTER,
                0,
                r2,
                vec![p2.clone()],
                None,
            )
            .unwrap(),
            0,
        );
        let spf = run_spf_v3(&db, r1);
        let v2v = V3VertexId::Router(r2);
        assert_eq!(spf.vertices.get(&v2v), Some(&10), "reachable");
        assert!(spf.next_hops.get(&v2v).is_none(), "no Link-LSA, no nh");
        let route = spf
            .routes
            .iter()
            .find(|r| r.prefix == route_of(&p2))
            .unwrap();
        assert_eq!(route.next_hop, None);
    }

    fn route_of(p: &crate::lsa::v3::V3Prefix) -> Prefix {
        Prefix::new_v6(p.addr, p.prefix_len)
    }

    fn fe80(host: u8) -> [u8; 16] {
        let mut a = [0u8; 16];
        a[0] = 0xfe;
        a[1] = 0x80;
        a[15] = host;
        a
    }

    fn prefix_from(addr: &[u8; 16], len: u8) -> crate::lsa::v3::V3Prefix {
        crate::lsa::v3::V3Prefix {
            prefix_len: len,
            options: 0,
            metric: 0,
            addr: *addr,
        }
    }

    /// A /64 whose significant bits fit the 8 wire bytes: 2001:db8:0:hn::/64.
    fn net64(host: u8) -> crate::lsa::v3::V3Prefix {
        let mut a = [0u8; 16];
        a[0] = 0x20;
        a[1] = 0x01;
        a[2] = 0x0d;
        a[3] = 0xb8;
        a[7] = host;
        crate::lsa::v3::V3Prefix {
            prefix_len: 64,
            options: 0,
            metric: 0,
            addr: a,
        }
    }
}
// quick debug harness appended temporarily
