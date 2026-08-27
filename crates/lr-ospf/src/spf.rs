//! SPF (Dijkstra) over the LSDB.
//!
//! Produces [`SpfResult`] entries that the router installs into Loc-RIB.
//! [`run_spf`] computes the intra-area shortest-path tree (RFC 2328 §16.1);
//! [`summary_routes`] derives inter-area candidates from summary-LSAs on
//! top of an intra-area result (RFC 2328 §16.2).

use std::collections::{BTreeMap, BinaryHeap};

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
pub fn run_spf(lsdb: &Lsdb, root: u32) -> SpfResult {
    let mut result = SpfResult::default();
    let mut heap: BinaryHeap<SpfVertex> = BinaryHeap::new();
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
                // Process this router's Router-LSA.
                for (key, entry) in lsdb.iter() {
                    if key.ls_type != LsaTypeV2::RouterLsa as u8 || key.advertising_router != rid {
                        continue;
                    }
                    // Parse router-LSA body for links.
                    for link in decode_router_links(&entry.lsa.body) {
                        match link.link_type {
                            x if x == RouterLinkType::PointToPoint as u8
                                || x == RouterLinkType::TransitNetwork as u8 =>
                            {
                                // Link-ID is neighbor's Router-ID (P2P) or DR's IP (Transit).
                                let target = if x == RouterLinkType::PointToPoint as u8 {
                                    VertexId::Router(link.link_id)
                                } else {
                                    VertexId::Network(link.link_id)
                                };
                                let new_dist = current_dist + link.metric as u64;
                                let prev =
                                    result.vertices.get(&target).copied().unwrap_or(u64::MAX);
                                if new_dist < prev {
                                    result.vertices.insert(target, new_dist);
                                    heap.push(SpfVertex {
                                        id: target,
                                        distance: new_dist,
                                    });
                                }
                            }
                            x if x == RouterLinkType::StubNetwork as u8 => {
                                // Stub network: link-id is the network/subnet; link-data is the mask.
                                let mask = link.link_data;
                                let pl = mask_to_pl(mask);
                                let prefix = Prefix::new_v4(link.link_id.to_be_bytes(), pl);
                                result.stub_routes.push(SpfRoute {
                                    prefix,
                                    metric: current_dist + link.metric as u64,
                                    next_hop: None,
                                    border_router: None,
                                });
                            }
                            _ => {}
                        }
                    }
                }
            }
            VertexId::Network(ls_id) => {
                // Network-LSA: list of attached routers.
                for (key, entry) in lsdb.iter() {
                    if key.ls_type != LsaTypeV2::NetworkLsa as u8 || key.link_state_id != ls_id {
                        continue;
                    }
                    for attached in decode_network_attached_routers(&entry.lsa.body) {
                        let target = VertexId::Router(attached);
                        let new_dist = current_dist; // transit network has zero metric
                        let prev = result.vertices.get(&target).copied().unwrap_or(u64::MAX);
                        if new_dist < prev {
                            result.vertices.insert(target, new_dist);
                            heap.push(SpfVertex {
                                id: target,
                                distance: new_dist,
                            });
                        }
                    }
                }
            }
        }
    }
    result
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
        if key.ls_type != LsaTypeV2::SummaryIpLsa as u8 {
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

/// Decode Router-LSA links from the body. RFC 2328 §A.4.2.
fn decode_router_links(body: &[u8]) -> Vec<RouterLink> {
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

    fn summary_lsa(adv: u32, network: u32, mask: u32, metric: u32, seq: u32) -> Lsa {
        let body = crate::lsa::encode_summary_lsa_body(mask, metric);
        Lsa {
            header: LsaHeader {
                ls_age: 0,
                options: 0x02,
                ls_type: LsaTypeV2::SummaryIpLsa as u8,
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
