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
