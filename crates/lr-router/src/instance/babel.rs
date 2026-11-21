//! Babel protocol runtime types for the router instance.
//!
//! These types live in a sibling module so [`super::DefaultRouter`] stays
//! readable. Every field is `pub(super)` so the parent module (and its
//! test submodules) can access them without qualification. The `impl`
//! block lives here too — Rust allows impl blocks for a type in any
//! module within the same crate.

use std::collections::BTreeMap;

use lr_babel::{
    dest_of, BabelCodec, BabelFrame, BabelNeighbor, BabelRoute, BabelRouteCache, PeerRoute,
    RouteDest,
};
use lr_core::addr::{IpAddr, Prefix};
use lr_core::nlri::NlriFamily;
use lr_core::rib::{Protocol, Route, RouteKey, RouteOrigin};

/// One neighbour on a Babel interface.
///
/// BIRD (`struct babel_neighbor`) and FRR (`struct neighbour`) key neighbour
/// state by the source address of incoming datagrams. An interface normally
/// has several neighbours, each with its own cost, Router-Id and next hops.
/// Keeping one of each for the whole interface made the last datagram heard
/// decide every route's metric and next hop — the "last announcement wins"
/// symptom.
#[derive(Debug, Clone)]
pub(super) struct PeerState {
    pub(super) neighbor: BabelNeighbor,
    pub(super) router_id: [u8; 8],
    pub(super) next_hop_v4: Option<IpAddr>,
    pub(super) next_hop_v6: Option<IpAddr>,
    /// Set once a Hello or IHU arrived. BIRD ignores Updates from a source
    /// it has not heard from (`babel_find_neighbor` returning NULL).
    pub(super) announced: bool,
}

impl PeerState {
    fn new(address: IpAddr, now_ms: u64) -> Self {
        Self {
            neighbor: BabelNeighbor::new(address, now_ms),
            router_id: [0; 8],
            next_hop_v4: None,
            next_hop_v6: None,
            announced: false,
        }
    }
}

/// Babel protocol runtime for one adjacency: neighbour table + route cache.
pub(super) struct BabelRuntime {
    /// Per-source-address state. `BabelNeighbor::address` is the neighbour's
    /// source address here, not our local address.
    pub(super) peers: BTreeMap<IpAddr, PeerState>,
    /// Last neighbour heard. The daemon uses it for the outgoing BABEL-RTT
    /// echo and egress pinning; route selection uses `peers` instead.
    pub(super) neighbor: BabelNeighbor,
    /// Source address of the datagram currently being processed, set by
    /// `babel_note_peer` on the receive path. `None` for direct embedders
    /// that drive the runtime without a transport.
    pub(super) current_peer: Option<IpAddr>,
    /// Per-neighbour routes and best-path selection (RFC 8966 §3.5).
    pub(super) routes: BabelRouteCache,
    /// Selected neighbour per destination, used to keep the incumbent on a
    /// metric tie (BIRD `babel_select_route`).
    pub(super) selected: BTreeMap<RouteDest, IpAddr>,
    /// Per-session streaming decoder (carryover must never leak between
    /// different peers' transports).
    pub(super) codec: BabelCodec,
    /// Reception-side link-cost ramp (RFC 8966 §A.2.4): the RTT penalty
    /// bounds applied on top of the IHU-learned txcost when an Update's
    /// advertised metric is folded into the local route metric. Set by
    /// the embedder through [`RouterApi::set_babel_link_cost_params`];
    /// `rtt_cost` 0 (babeld's default) keeps the feature off.
    pub(super) rtt_min_us: u32,
    pub(super) rtt_max_us: u32,
    pub(super) rtt_cost: u16,
    /// Router-id of this speaker. Updates echoing it back (a peer
    /// re-advertising our own claims) are ignored — BIRD's
    /// `babel_handle_update` guard.
    pub(super) own_router_id: Option<[u8; 8]>,
    /// A Route Request (RFC 8966 §3.2.6) arrived — the embedder should
    /// trigger an immediate announcement. Set by any request (wildcard
    /// or specific); drained through
    /// [`RouterApi::babel_take_route_request`].
    pub(super) route_request: bool,
    /// A Seqno Request (RFC 8966 §3.2.6.2) for *our own* router-id
    /// arrived — a peer holds a higher seqno than our fresh boot value
    /// (the classic restart-staleness recovery). Carries the seqno the
    /// peer asked for; the embedder bumps its announcement seqno to at
    /// least that value and re-announces; drained through
    /// [`RouterApi::babel_take_own_seqno_request`].
    pub(super) own_seqno_request: Option<u16>,
    /// Routes previously published to Loc-RIB — used to compute deltas.
    pub(super) published: BTreeMap<RouteKey, Route>,
    /// Structured record of the withdrawal that happened during this
    /// frame's `apply_update` calls, consumed by `handle_frame`'s
    /// trailing `self.diff()` so the delta can be annotated with a
    /// precise, operator-actionable reason BEFORE it surfaces as a
    /// `RouterEvent::Log`. One record per withdrawal: a 29-route
    /// retraction frame names all 29 prefixes, and the wildcard
    /// branch (AE 0, metric 0xFFFF) records its own reason instead of
    /// falling back to "babel best-path displacement".
    pub(super) last_withdraw: LastWithdraw,
}

/// What kind of withdrawal happened in one Babel frame, set
/// incrementally by `apply_update` and rendered into a reason string
/// by `handle_frame` after `diff()` produces the delta.
#[derive(Default)]
pub(super) struct LastWithdraw {
    pub(super) kind: WithdrawKind,
    /// For a single per-prefix retraction, the prefix that was
    /// retracted — rendered into the reason so the operator can
    /// `grep` for the exact prefix. `None` for wildcard retractions
    /// (no single prefix to name) and for multi-prefix frames (the
    /// count is what matters, not one prefix).
    pub(super) first_prefix: Option<Prefix>,
}

#[derive(Default, PartialEq, Eq)]
pub(super) enum WithdrawKind {
    /// No retraction TLV seen this frame — any `delta.withdrawn` entries
    /// came from `diff()`'s best-path displacement.
    #[default]
    None,
    /// One or more per-prefix retractions (metric=infinity, AE ≠ 0).
    PerPrefix,
    /// A wildcard retraction (AE 0, metric 0xFFFF — RFC 8966 §4.6.9):
    /// the peer asked us to drop every route it taught us.
    Wildcard,
}

/// Result of one protocol-runtime step: routes to install into / withdraw
/// from Loc-RIB. The `withdraw_reason` is a human-readable string carried
/// on the first withdrawal's `RouterEvent::Log` so the operator can see
/// WHY a Babel route disappeared (expiry, explicit retraction, link-down,
/// or best-path displacement).
#[derive(Default)]
pub(super) struct RuntimeDelta {
    pub(super) installed: Vec<Route>,
    pub(super) withdrawn: Vec<RouteKey>,
    pub(super) withdraw_reason: String,
}

impl BabelRuntime {
    pub(super) fn new(local: IpAddr, now_ms: u64) -> Self {
        Self {
            peers: BTreeMap::new(),
            neighbor: BabelNeighbor::new(local, now_ms),
            current_peer: None,
            routes: BabelRouteCache::new(),
            selected: BTreeMap::new(),
            codec: BabelCodec::new(),
            rtt_min_us: 10_000,
            rtt_max_us: 120_000,
            rtt_cost: 0,
            own_router_id: None,
            route_request: false,
            own_seqno_request: None,
            published: BTreeMap::new(),
            last_withdraw: LastWithdraw::default(),
        }
    }

    /// The transport noted the source address of an incoming datagram.
    /// Keep both the last-heard summary (RTT echo, egress pinning) and the
    /// per-neighbour state keyed by that address.
    pub(super) fn note_peer(&mut self, peer: IpAddr) {
        self.current_peer = Some(peer);
        self.neighbor.address = peer;
        self.peers
            .entry(peer)
            .or_insert_with(|| PeerState::new(peer, 0));
    }

    /// Reception-side link cost toward `peer` (RFC 8966 §3.4.3, babeld
    /// `neighbour_cost`, BIRD `babel_update_cost`): the txcost learned from
    /// that neighbour's IHU plus the measured-RTT penalty. `None` while no
    /// IHU has arrived — babeld treats such a neighbour's routes as
    /// unusable (cost INFINITY), so Updates from it are not accepted.
    pub(super) fn link_cost(&self, peer: IpAddr, now_ms: u64) -> Option<u32> {
        let state = self.peers.get(&peer)?;
        if state.neighbor.txcost >= 0xffff {
            return None;
        }
        let rtt = u32::from(state.neighbor.rtt_cost(
            now_ms,
            self.rtt_min_us,
            self.rtt_max_us,
            self.rtt_cost,
        ));
        Some(state.neighbor.txcost.saturating_add(rtt))
    }

    /// The source address the current frame belongs to.
    fn frame_peer(&self) -> IpAddr {
        self.current_peer.unwrap_or(self.neighbor.address)
    }

    /// Feed one decoded Babel frame; returns the Loc-RIB delta.
    pub(super) fn handle_frame(
        &mut self,
        frame: &BabelFrame,
        now_ms: u64,
        now_us: u32,
    ) -> RuntimeDelta {
        use lr_babel::message::{
            Hello, Ihu, NextHop, PrefixCache, RouteRequest, RouterId as RouterIdTlv, SeqnoRequest,
            Update,
        };
        use lr_babel::tlv::TlvType;

        let peer = self.frame_peer();
        // BIRD `babel_get_neighbor` / FRR `find_neighbour`: the first packet
        // from a source address creates the neighbour entry.
        if !self.peers.contains_key(&peer) {
            let mut state = PeerState::new(peer, now_ms);
            if self.neighbor.address == peer {
                state.neighbor = self.neighbor.clone();
            }
            self.peers.insert(peer, state);
        }
        // RFC 8966 §4.5.2 prefix-compression state — one per packet.
        let mut cache = PrefixCache::default();
        for tlv in &frame.body {
            match tlv.kind {
                TlvType::Hello => {
                    if let Some(h) = Hello::decode(&tlv.value) {
                        let state = self.peers.get_mut(&peer).expect("peer inserted above");
                        match h.timestamp {
                            Some(ts) => state.neighbor.hello_timestamped(
                                h.seqno,
                                h.interval_cs,
                                ts,
                                now_ms,
                                now_us,
                            ),
                            None => state.neighbor.hello(h.seqno, h.interval_cs, now_ms),
                        }
                        state.announced = true;
                    }
                }
                TlvType::Ihu => {
                    if let Some(ihu) = Ihu::decode(&tlv.value) {
                        let old_cost = self.link_cost(peer, now_ms);
                        let state = self.peers.get_mut(&peer).expect("peer inserted above");
                        match ihu.timestamp_echo {
                            Some((ts1, ts2)) => state.neighbor.ihu_echo(
                                ihu.rxcost,
                                ihu.interval_cs,
                                ts1,
                                ts2,
                                now_ms,
                            ),
                            None => state.neighbor.ihu(ihu.rxcost, ihu.interval_cs, now_ms),
                        }
                        state.announced = true;
                        // BIRD `babel_update_cost`: a cost change recomputes
                        // this neighbour's routes' metrics and reselects.
                        let new_cost = self.link_cost(peer, now_ms);
                        if old_cost != new_cost {
                            match new_cost {
                                Some(cost) => {
                                    self.routes.set_neighbor_cost(peer, cost);
                                }
                                None => {
                                    // The neighbour declared its link
                                    // unusable (rxcost = INFINITY). BIRD
                                    // sets `r->metric = BABEL_INFINITY` and
                                    // lets `babel_select_route` skip the
                                    // route; the route stays in the cache
                                    // and is refreshed or expired by the
                                    // normal hold timer. Immediately
                                    // retracting all routes when the peer's
                                    // IHU flips between 96 and 65535
                                    // caused the production "71 routes
                                    // withdrawn → re-installed → withdrawn"
                                    // churn — every IHU flip mass-withdrew
                                    // and re-learned 71 routes. Marking
                                    // them unreachable loses the election
                                    // without removing them, so a brief
                                    // IHU flip no longer churns the Loc-RIB.
                                    self.routes.mark_neighbor_unreachable(peer);
                                }
                            }
                        }
                    }
                }
                TlvType::RouterId => {
                    if let Some(rid) = RouterIdTlv::decode(&tlv.value) {
                        self.peers
                            .get_mut(&peer)
                            .expect("peer inserted above")
                            .router_id = rid.id;
                    }
                }
                TlvType::NextHop => {
                    if let Some(nh) = NextHop::decode(&tlv.value) {
                        // Per-family next-hop state (RFC 8966 §3.5.3) belongs
                        // to the neighbour that advertised it.
                        let state = self.peers.get_mut(&peer).expect("peer inserted above");
                        match nh.ae {
                            1 => state.next_hop_v4 = Some(nh.address),
                            _ => state.next_hop_v6 = Some(nh.address),
                        }
                    }
                }
                TlvType::Update => {
                    if let Some(u) = Update::decode(&tlv.value) {
                        if let Some(u) = cache.expand(&u) {
                            self.apply_update(&u, now_ms, peer);
                        }
                    }
                }
                TlvType::RouteRequest => {
                    // RFC 8966 §3.2.6: answer any request (wildcard or
                    // specific) with the routes we announce.
                    if RouteRequest::decode(&tlv.value).is_some() {
                        self.route_request = true;
                    }
                }
                TlvType::SeqnoRequest => {
                    if let Some(req) = SeqnoRequest::decode(&tlv.value) {
                        if let Some(own) = self.own_router_id {
                            if req.router_id == own {
                                self.own_seqno_request =
                                    Some(self.own_seqno_request.map_or(req.seqno, |prev| {
                                        let a = prev as i16;
                                        let b = req.seqno as i16;
                                        if b.wrapping_sub(a) > 0 {
                                            req.seqno
                                        } else {
                                            prev
                                        }
                                    }));
                            }
                        }
                    }
                }
                _ => {}
            }
        }
        // Keep the last-heard summary in step with the neighbour just read
        // so the outgoing RTT echo and egress pinning see fresh state.
        if let Some(state) = self.peers.get(&peer) {
            self.neighbor = state.neighbor.clone();
        }
        let mut delta = self.diff();
        if !delta.withdrawn.is_empty() {
            let lw = std::mem::take(&mut self.last_withdraw);
            delta.withdraw_reason = match lw.kind {
                WithdrawKind::None => format!(
                    "babel best-path displacement ({} route(s) lost the best-path election)",
                    delta.withdrawn.len()
                ),
                WithdrawKind::PerPrefix => {
                    if delta.withdrawn.len() == 1 {
                        format!(
                            "babel peer retraction (metric=infinity) for {}",
                            lw.first_prefix
                                .expect("first_prefix is set on the first per-prefix retraction")
                        )
                    } else {
                        format!(
                            "babel peer retraction (metric=infinity) for {} route(s)",
                            delta.withdrawn.len()
                        )
                    }
                }
                WithdrawKind::Wildcard => format!(
                    "babel peer wildcard retraction (AE 0, metric=infinity) — {} route(s) flushed",
                    delta.withdrawn.len()
                ),
            };
        }
        delta
    }

    pub(super) fn apply_update(
        &mut self,
        u: &lr_babel::message::Update,
        now_ms: u64,
        peer: IpAddr,
    ) {
        // A peer re-advertising our own claims back at us: ignore (BIRD's
        // `msg->router_id == p->router_id` guard).
        let (peer_rid, peer_v4_nh, peer_v6_nh, announced) = match self.peers.get(&peer) {
            Some(state) => (
                state.router_id,
                state.next_hop_v4,
                state.next_hop_v6,
                state.announced,
            ),
            None => return,
        };
        if let Some(own) = self.own_router_id {
            if u.metric != 0xffff && peer_rid == own {
                return;
            }
        }
        // BIRD ignores Updates from a source it has not heard from via a
        // Hello or IHU. Accepting them lets a silent node inject routes
        // with no measured link cost.
        if !announced {
            return;
        }
        // AE 0 = wildcard retraction; AE 1 = IPv4; AE 2 = IPv6;
        // AE 4 = IPv4-via-IPv6 (RFC 9229 §2.4).
        let prefix = match u.ae {
            1 | 4 => {
                if u.prefix.is_empty() || u.prefix.len() > 4 {
                    return;
                }
                let mut addr = [0u8; 4];
                addr[..u.prefix.len()].copy_from_slice(&u.prefix);
                Prefix::new_v4(addr, u.prefix_len)
            }
            2 => {
                if u.prefix.is_empty() || u.prefix.len() > 16 {
                    return;
                }
                let mut addr = [0u8; 16];
                addr[..u.prefix.len()].copy_from_slice(&u.prefix);
                Prefix::new_v6(addr, u.prefix_len)
            }
            0 => {
                // RFC 8966 §4.6.9: retract every route THIS neighbour
                // taught us (BIRD WALK_LIST(nbr->routes), FRR
                // retract_neighbour_routes). A shared table must not be
                // cleared — other neighbours' routes stay valid.
                if u.metric == 0xFFFF {
                    let removed = self.routes.retract_all(peer);
                    if !removed.is_empty() {
                        self.last_withdraw.kind = WithdrawKind::Wildcard;
                        self.last_withdraw.first_prefix = None;
                    }
                }
                return;
            }
            _ => return,
        };
        let source = if u.src_prefix_len > 0 && !u.src_prefix.is_empty() {
            match u.ae {
                1 | 4 if u.src_prefix.len() <= 4 => {
                    let mut s = [0u8; 4];
                    s[..u.src_prefix.len()].copy_from_slice(&u.src_prefix);
                    Some(lr_babel::source::SourcePrefix::new(Prefix::new_v4(
                        s,
                        u.src_prefix_len,
                    )))
                }
                2 if u.src_prefix.len() <= 16 => {
                    let mut s = [0u8; 16];
                    s[..u.src_prefix.len()].copy_from_slice(&u.src_prefix);
                    Some(lr_babel::source::SourcePrefix::new(Prefix::new_v6(
                        s,
                        u.src_prefix_len,
                    )))
                }
                _ => None,
            }
        } else {
            None
        };
        let key = lr_babel::route::RouteKey {
            destination: prefix,
            source,
            router_id: peer_rid,
        };
        // metric 0xFFFF (infinity) → retraction (RFC 8966 §3.5.5). The
        // route is indexed by (destination, neighbour), so retracting one
        // neighbour cannot displace another's copy of the prefix.
        if u.metric == 0xFFFF {
            let removed = self
                .routes
                .retract((prefix, key.source.map(|s| s.prefix)), peer);
            if removed.is_some() && self.last_withdraw.kind != WithdrawKind::Wildcard {
                if self.last_withdraw.kind == WithdrawKind::None {
                    self.last_withdraw.first_prefix = Some(prefix);
                }
                self.last_withdraw.kind = WithdrawKind::PerPrefix;
            }
            return;
        }
        // Per-family next-hop resolution (RFC 8966 §3.5.3): an AE 1 Update
        // rides the AE 1 NextHop TLV (or its neighbour's own v4 address);
        // AE 2/3 and AE 4 ride the v6 next hop (or the neighbour's address).
        let peer_v4 = match peer {
            IpAddr::V4(_) => Some(peer),
            IpAddr::V6(_) => None,
        };
        let peer_v6 = match peer {
            IpAddr::V6(_) => Some(peer),
            IpAddr::V4(_) => None,
        };
        let nh = match u.ae {
            1 => match peer_v4_nh.or(peer_v4) {
                Some(nh) => nh,
                None => return,
            },
            _ => peer_v6_nh.or(peer_v6).unwrap_or(peer),
        };
        // The receiver folds THIS neighbour's link cost into the route
        // metric (babeld `route_metric + neighbour_cost`, BIRD
        // `babel_compute_metric`). Until its first IHU arrives the cost is
        // infinite and no Update from this neighbour is accepted.
        let Some(link) = self.link_cost(peer, now_ms) else {
            return;
        };
        let advert_metric = u32::from(u.metric);
        let metric = advert_metric.saturating_add(link).min(0xfffe);
        self.routes.update(PeerRoute {
            key,
            neighbor: peer,
            seqno: u.seqno,
            advert_metric,
            metric,
            next_hop: nh,
            feasible: false,
            interval_cs: u.interval_cs,
            last_seen_ms: now_ms,
        });
    }

    /// One expiry sweep (RFC 8966 §3.2.5): routes whose re-announcement
    /// hold time lapsed are dropped, and the diff against `published`
    /// becomes the Loc-RIB withdrawal delta. Each neighbour's routes age
    /// out independently — a shared timer produced the batch withdrawal /
    /// re-install cycle in the production report.
    pub(super) fn gc(&mut self, now_ms: u64) -> RuntimeDelta {
        let expired = self.routes.expire(now_ms);
        if !expired.is_empty() {
            let mut delta = self.diff();
            if delta.withdrawn.is_empty() {
                return RuntimeDelta::default();
            }
            delta.withdraw_reason = format!(
                "babel route hold time expired ({} route(s) aged out at {} ms)",
                expired.len(),
                now_ms
            );
            return delta;
        }
        RuntimeDelta::default()
    }

    /// Diff the current feasible best set against the previously published
    /// set: new/changed routes are installed, disappeared ones withdrawn.
    pub(super) fn diff(&mut self) -> RuntimeDelta {
        let best = self.routes.best_routes(&self.selected);
        let current: BTreeMap<RouteKey, Route> = best
            .iter()
            .map(|r| {
                let route = self.to_rib_route(r);
                (route.key.clone(), route)
            })
            .collect();
        let new_selected: BTreeMap<RouteDest, IpAddr> =
            best.iter().map(|r| (dest_of(&r.key), r.neighbor)).collect();
        let mut delta = RuntimeDelta {
            installed: Vec::new(),
            withdrawn: Vec::new(),
            withdraw_reason: String::new(),
        };
        for (k, r) in &current {
            match self.published.get(k) {
                Some(prev) if prev == r => {}
                _ => delta.installed.push(r.clone()),
            }
        }
        for k in self.published.keys() {
            if !current.contains_key(k) {
                delta.withdrawn.push(k.clone());
            }
        }
        self.published = current;
        self.selected = new_selected;
        delta
    }

    /// The per-neighbour best set for re-advertisement on other interfaces.
    pub(super) fn reachable_routes(&self) -> Vec<BabelRoute> {
        self.routes
            .best_routes(&self.selected)
            .into_iter()
            .map(|r| r.to_babel_route())
            .collect()
    }

    /// Next hops of last resort for the current neighbour's TLVs, used by
    /// the transport to pin egress interfaces.
    pub(super) fn egress_nexthops(&self) -> (Option<IpAddr>, Option<IpAddr>) {
        let peer = self.frame_peer();
        let state = self.peers.get(&peer);
        let peer_v4 = matches!(peer, IpAddr::V4(_)).then_some(peer);
        let peer_v6 = matches!(peer, IpAddr::V6(_)).then_some(peer);
        (
            state.and_then(|s| s.next_hop_v4).or(peer_v4),
            state.and_then(|s| s.next_hop_v6).or(peer_v6),
        )
    }

    fn to_rib_route(&self, r: &PeerRoute) -> Route {
        // The Loc-RIB key family follows the destination's address family.
        let family = match r.key.destination.addr {
            IpAddr::V4(_) => NlriFamily::IPV4_UNICAST,
            IpAddr::V6(_) => NlriFamily::IPV6_UNICAST,
        };
        let peer = self.peers.get(&r.neighbor);
        let peer_v4 = matches!(r.neighbor, IpAddr::V4(_)).then_some(r.neighbor);
        let peer_v6 = matches!(r.neighbor, IpAddr::V6(_)).then_some(r.neighbor);
        let nh_v4_default = peer
            .and_then(|s| s.next_hop_v4)
            .or(peer_v4)
            .unwrap_or(r.neighbor);
        let nh_v6_default = peer
            .and_then(|s| s.next_hop_v6)
            .or(peer_v6)
            .unwrap_or(r.neighbor);
        let next_hop = match r.next_hop {
            IpAddr::V4([0, 0, 0, 0]) => nh_v4_default,
            IpAddr::V6(b) if b == [0u8; 16] => nh_v6_default,
            other => other,
        };
        // The two private path-attribute tags let the filter DSL's
        // `babel.seqno` / `babel.router_id` fields surface the source's
        // sequence number and Router-ID inside the Loc-RIB only.
        let mut attributes = lr_core::attr::Attributes::new();
        attributes.insert(lr_core::attr::Attribute {
            tag: lr_core::attr::AttrTag::raw(lr_bgp::path::AttrType::LrBabelSeqno.to_u8()),
            flags: 0x80,
            value: (u32::from(r.seqno)).to_be_bytes().to_vec(),
        });
        attributes.insert(lr_core::attr::Attribute {
            tag: lr_core::attr::AttrTag::raw(lr_bgp::path::AttrType::LrBabelRouterId.to_u8()),
            flags: 0x80,
            value: u64::from_be_bytes(r.key.router_id).to_be_bytes().to_vec(),
        });
        Route {
            key: RouteKey::new(r.key.destination, family),
            origin: RouteOrigin {
                proto: 4, // Babel adjacency tag
                peer: u64::from(u32::from_be_bytes([
                    r.key.router_id[4],
                    r.key.router_id[5],
                    r.key.router_id[6],
                    r.key.router_id[7],
                ])),
            },
            protocol: Protocol::Babel,
            preference: lr_core::rib::Preference::new(
                Protocol::Babel.default_admin_distance(),
                r.metric,
            ),
            next_hop: Some(next_hop),
            attributes,
            age_ms: 0,
            path_id: 0,
            tag: None,
        }
    }
}
