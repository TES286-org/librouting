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

#[derive(Debug, Clone, PartialEq, Eq)]
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
#[path = "spf_tests.rs"]
mod tests;

// ---------------------------------------------------------------------------
// OSPFv3 SPF (RFC 5340 §4.8)
// ---------------------------------------------------------------------------

use crate::lsa::srv6::locator_route_type;
use crate::lsa::{
    decode_v3_inter_area_prefix_body, EIntraAreaPrefixLsaBody, ELinkLsaBody, ENetworkLsaBody,
    ERouterLsaBody, V3IntraAreaPrefixBody, V3LinkLsaBody, V3NetworkLsaBody, V3Prefix,
    V3RouterLsaBody, LINK_TYPE_POINTTOPOINT, LINK_TYPE_TRANSIT, LINK_TYPE_VIRTUAL,
    LS_TYPE_E_INTER_PREFIX, LS_TYPE_E_INTRA_PREFIX, LS_TYPE_E_LINK, LS_TYPE_E_NETWORK,
    LS_TYPE_E_ROUTER, LS_TYPE_INTER_PREFIX, LS_TYPE_INTRA_PREFIX, LS_TYPE_LINK, LS_TYPE_NETWORK,
    LS_TYPE_ROUTER, PREFIX_OPT_NU,
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
    /// The 24-bit options each router's Router-LSA advertises (§A.2) —
    /// the value an ABR mirrors into a 0x2004 inter-area-router-LSA
    /// describing that router (§4.4.3.5).
    pub router_options: BTreeMap<u32, u32>,
    /// Intra-area prefixes from Intra-Area-Prefix-LSAs (§4.4.3.5),
    /// deduplicated per prefix keeping the lowest metric.
    pub routes: Vec<SpfRoute>,
    /// SRv6 locators (RFC 9513 §5) reachable through their advertising
    /// router — intra-area route type only, deduplicated per locator
    /// prefix by the §7.1 preference. The router layer gates these on
    /// the algorithms it supports (the receiver's algorithm set is not
    /// LSDB data) and on the §5 preference for prefix reachability
    /// advertisements covering the same prefix.
    pub locators: Vec<SpfLocatorRoute>,
}

/// One SRv6 locator route (RFC 9513 §5): the locator of one advertising
/// router with the SPF distance and first hop of that router. The
/// locator metric itself is the router distance — the TLV metric is
/// meaningful for inter-area/external propagation (a later slice) and
/// a 0xFFFFFFFF (unreachable) TLV metric never reaches here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpfLocatorRoute {
    pub prefix: Prefix,
    /// The IGP algorithm the locator is bound to (0 = SPF).
    pub algorithm: u8,
    /// The SPF distance to the advertising router.
    pub metric: u64,
    /// The advertising router's resolved first hop; `None` when the
    /// router is the root itself (directly connected).
    pub next_hop: Option<IpAddr>,
    pub advertising_router: u32,
}

/// The LSDB pre-scan for the v3 calculation: per-type maps built once so
/// the relaxation loop never re-walks the database.
struct V3Topology {
    /// Router-LSAs (0x2001) by advertising router. One LSA per router:
    /// the first instance in database order wins (fragmented
    /// Router-LSAs — multiple per router — are not split apart here).
    router_lsas: BTreeMap<u32, V3RouterLsaBody>,
    /// The 24-bit options each Router-LSA advertises (§A.2) — what a
    /// 0x2004 originator mirrors for that router (§4.4.3.5).
    router_options: BTreeMap<u32, u32>,
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
    /// Scan the area LSDB into the per-type maps. `extended` selects
    /// the RFC 8362 reception mode: in full Extended-LSA mode a
    /// speaker's E-Router/E-Network/E-Link/E-Intra-Area-Prefix LSA
    /// overrides its legacy counterpart (§6.1 — the topology rides the
    /// E-LSAs); a legacy-mode receiver ignores the E-LSAs for the
    /// calculation entirely (§6.2 — it still stores and re-floods
    /// them, and the SRv6 database still projects from them).
    fn from_lsdb(lsdb: &Lsdb, extended: bool) -> Self {
        let mut t = Self {
            router_lsas: BTreeMap::new(),
            router_options: BTreeMap::new(),
            network_lsas: BTreeMap::new(),
            link_locals: BTreeMap::new(),
            intra_prefixes: Vec::new(),
        };
        if extended {
            // E-LSA pre-pass: the BTreeMap key order visits the legacy
            // types (0x2001…) before the Extended ones (0xA021…), so
            // the Extended shapes are collected first and the legacy
            // pass below defers to them.
            let mut e_routers: BTreeSet<u32> = BTreeSet::new();
            for (key, entry) in lsdb.iter() {
                match key.ls_type {
                    x if x == LS_TYPE_E_ROUTER => {
                        let Some(body) = ERouterLsaBody::decode(&entry.lsa.body) else {
                            continue;
                        };
                        // First E-Router-LSA per router wins (fragmented
                        // E-Router-LSAs concatenate, RFC 5340 §A.4.3
                        // semantics carried over by RFC 8362 §4.1 — the
                        // same first-instance rule the legacy scan uses).
                        if e_routers.insert(key.advertising_router) {
                            t.router_options
                                .insert(key.advertising_router, body.options);
                            t.router_lsas.insert(
                                key.advertising_router,
                                V3RouterLsaBody {
                                    bits: body.bits,
                                    options: body.options,
                                    links: body
                                        .links
                                        .iter()
                                        .map(|l| crate::lsa::v3::V3RouterLink {
                                            link_type: l.link_type,
                                            metric: l.metric,
                                            interface_id: l.interface_id,
                                            neighbor_interface_id: l.neighbor_interface_id,
                                            neighbor_router_id: l.neighbor_router_id,
                                        })
                                        .collect(),
                                },
                            );
                        }
                    }
                    x if x == LS_TYPE_E_NETWORK => {
                        if let Some(body) = ENetworkLsaBody::decode(&entry.lsa.body) {
                            t.network_lsas
                                .entry((key.advertising_router, key.link_state_id))
                                .or_insert(V3NetworkLsaBody {
                                    options: body.options,
                                    routers: body.routers,
                                });
                        }
                    }
                    x if x == LS_TYPE_E_LINK => {
                        if let Some(body) = ELinkLsaBody::decode(&entry.lsa.body) {
                            t.link_locals
                                .entry((key.advertising_router, key.link_state_id))
                                .or_insert(body.link_local);
                        }
                    }
                    x if x == LS_TYPE_E_INTRA_PREFIX => {
                        if let Some(body) = EIntraAreaPrefixLsaBody::decode(&entry.lsa.body) {
                            t.intra_prefixes.push((
                                body.ref_type,
                                body.ref_ls_id,
                                body.ref_adv_router,
                                body.prefixes.iter().map(|p| p.prefix.clone()).collect(),
                            ));
                        }
                    }
                    _ => {}
                }
            }
            // Legacy pass with Extended preference: a speaker that
            // also (or only) originated legacy LSAs keeps them when it
            // has no Extended counterpart.
            for (key, entry) in lsdb.iter() {
                match key.ls_type {
                    x if x == LS_TYPE_ROUTER => {
                        if e_routers.contains(&key.advertising_router) {
                            continue;
                        }
                        if let Some(body) = V3RouterLsaBody::decode(&entry.lsa.body) {
                            t.router_options
                                .entry(key.advertising_router)
                                .or_insert(body.options);
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
            return t;
        }
        for (key, entry) in lsdb.iter() {
            match key.ls_type {
                x if x == LS_TYPE_ROUTER => {
                    if let Some(body) = V3RouterLsaBody::decode(&entry.lsa.body) {
                        t.router_options
                            .entry(key.advertising_router)
                            .or_insert(body.options);
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
/// starting at the Router vertex `root` — legacy-LSA reception mode
/// (RFC 8362 §6.2: Extended LSAs in the database are stored and
/// re-flooded but take no part in the calculation). See
/// [`run_spf_v3_extended`] for the full Extended-LSA mode.
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
///   to Router- or Network-LSAs (§4.4.3.9) — only the NU bit excludes
///   prefixes from the unicast calculation (§4.8.1).
///
/// Unresolvable next hops (missing Link-LSAs) still admit the vertex to
/// the tree but leave the route without a gateway — the embedder
/// decides whether to keep it.
pub fn run_spf_v3(lsdb: &Lsdb, root: u32) -> SpfResultV3 {
    run_spf_v3_mode(lsdb, root, false)
}

/// The full Extended-LSA reception mode of [`run_spf_v3`] (RFC 8362
/// §6.1): a speaker's E-Router-LSA (0xA021) supplies its vertex links,
/// E-Network-LSAs (0xA022) the transit vertices, E-Link-LSAs (0x8028)
/// the link-local resolution and E-Intra-Area-Prefix-LSAs (0xA029) the
/// prefixes — each overriding the same speaker's legacy LSA when both
/// exist, so an area migrates router by router. Speakers without
/// Extended LSAs keep their legacy topology.
pub fn run_spf_v3_extended(lsdb: &Lsdb, root: u32) -> SpfResultV3 {
    run_spf_v3_mode(lsdb, root, true)
}

fn run_spf_v3_mode(lsdb: &Lsdb, root: u32, extended: bool) -> SpfResultV3 {
    let topo = V3Topology::from_lsdb(lsdb, extended);
    let mut result = SpfResultV3 {
        router_options: topo.router_options.clone(),
        ..SpfResultV3::default()
    };
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
            x if x == LS_TYPE_ROUTER || x == LS_TYPE_E_ROUTER => V3VertexId::Router(*ref_adv),
            x if x == LS_TYPE_NETWORK || x == LS_TYPE_E_NETWORK => {
                V3VertexId::Network(*ref_adv, *ref_ls_id)
            }
            _ => continue,
        };
        let Some(&d) = dist.get(&vertex) else {
            continue;
        };
        let next_hop = result.next_hops.get(&vertex).copied();
        for p in prefixes {
            // §4.8.1: only NU excludes a prefix from unicast calculation.
            if p.options & PREFIX_OPT_NU != 0 {
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

    // Attach the SRv6 locators (RFC 9513 §5): a locator is reachable
    // through its advertising router, so an intra-area locator's
    // metric is the router's SPF distance and its first hop the
    // router's. The Srv6Database projection applies the §7.1
    // duplicate preference; locators with the unreachable TLV metric
    // or an unsupported route type never become routes here.
    let srv6 = crate::srv6db::Srv6Database::from_lsdb(lsdb);
    let mut locators = Vec::new();
    for (&adv, node) in &srv6.nodes {
        for loc in &node.locators {
            if loc.route_type != locator_route_type::INTRA_AREA || loc.is_unreachable() {
                continue;
            }
            let vertex = V3VertexId::Router(adv);
            let Some(&metric) = dist.get(&vertex) else {
                continue;
            };
            let next_hop = if adv == root {
                None
            } else {
                result.next_hops.get(&vertex).map(|nh| nh.link_local)
            };
            locators.push(SpfLocatorRoute {
                prefix: loc.prefix,
                algorithm: loc.algorithm,
                metric,
                next_hop,
                advertising_router: adv,
            });
        }
    }
    result.locators = locators;
    result
}

/// RFC 5340 §4.8.3: inter-area route calculation from
/// inter-area-prefix-LSAs (0x2003) — the v3 form of RFC 2328 §16.2 —
/// in legacy-LSA reception mode (RFC 8362 §6.2). See
/// [`summary_routes_v3_extended`].
///
/// Every 0x2003 LSA whose advertising border router is reachable
/// through the intra-area v3 tree contributes a candidate route with
/// metric `dist(border router) + summary metric`. The v3 deviations
/// from the v2 calculation (§4.8.3):
///
/// - the prefix travels in the LSA body (the Link State ID has lost
///   its addressing semantics);
/// - prefixes carrying the NU bit in their PrefixOptions are ignored
///   by the calculation;
/// - the LSInfinity metric (`0x00ff_ffff`) still marks unreachable.
///
/// The best candidate per prefix wins — lowest metric, ties broken by
/// the lowest border router ID for determinism. The candidate's next
/// hop is the advertising border router's resolved link-local first
/// hop (the only legal unicast next hop for OSPFv3, RFC 5340 §4.2.1);
/// `None` when the border router itself has no resolved first hop.
/// Callers must merge the result with the intra-area routes of the
/// same area so that intra-area paths always win for an identical
/// prefix (§16.2 (b)).
pub fn summary_routes_v3(lsdb: &Lsdb, result: &SpfResultV3) -> Vec<SpfRoute> {
    summary_routes_v3_mode(lsdb, result, false)
}

/// The full Extended-LSA mode of [`summary_routes_v3`] (RFC 8362 §6.1):
/// E-Inter-Area-Prefix-LSAs (0xA023) contribute alongside the legacy
/// 0x2003 summaries under the same best-per-prefix rule (a border
/// router advertises each prefix in exactly one form; a same-prefix
/// dual advertisement yields an identical route).
pub fn summary_routes_v3_extended(lsdb: &Lsdb, result: &SpfResultV3) -> Vec<SpfRoute> {
    summary_routes_v3_mode(lsdb, result, true)
}

pub(crate) fn summary_routes_v3_mode(
    lsdb: &Lsdb,
    result: &SpfResultV3,
    extended: bool,
) -> Vec<SpfRoute> {
    // LSInfinity — a summary metric that means "unreachable" (§16.2,
    // §4.8.3 carries it over). Same constant the v2 calculation uses.
    const LS_INFINITY: u32 = 0x00ff_ffff;
    let mut best: BTreeMap<Prefix, (SpfRoute, u32)> = BTreeMap::new();
    for (key, entry) in lsdb.iter() {
        let e_type = key.ls_type == LS_TYPE_E_INTER_PREFIX;
        if key.ls_type != LS_TYPE_INTER_PREFIX && !(extended && e_type) {
            continue;
        }
        // (a) The border router must be reachable via intra-area paths.
        let Some(&dist) = result
            .vertices
            .get(&V3VertexId::Router(key.advertising_router))
        else {
            continue;
        };
        let body = if e_type {
            match crate::lsa::EInterAreaPrefixLsaBody::decode(&entry.lsa.body) {
                Some(b) => (
                    b.0.metric,
                    b.0.prefix.prefix_len,
                    b.0.prefix.options,
                    b.0.prefix.addr,
                ),
                None => continue,
            }
        } else {
            match decode_v3_inter_area_prefix_body(&entry.lsa.body) {
                Some(b) => (b.metric, b.prefix_len, b.prefix_options, {
                    let mut addr = [0u8; 16];
                    let n = b.prefix_bytes.len().min(16);
                    addr[..n].copy_from_slice(&b.prefix_bytes[..n]);
                    addr
                }),
                None => continue,
            }
        };
        let (metric, prefix_len, prefix_options, addr) = body;
        if metric >= LS_INFINITY {
            continue;
        }
        // (b) §4.8.3: NU-marked prefixes take no part in the
        // inter-area calculation.
        if prefix_options & PREFIX_OPT_NU != 0 {
            continue;
        }
        let prefix = Prefix::new_v6(addr, prefix_len);
        let candidate = SpfRoute {
            prefix,
            metric: dist + u64::from(metric),
            next_hop: result
                .next_hops
                .get(&V3VertexId::Router(key.advertising_router))
                .map(|nh| nh.link_local),
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

#[cfg(test)]
#[path = "spf_v3_tests.rs"]
mod v3_tests;
