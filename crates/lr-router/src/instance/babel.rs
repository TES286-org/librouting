//! Babel protocol runtime types for the router instance.
//!
//! These types live in a sibling module so [`super::DefaultRouter`] stays
//! readable. Every field is `pub(super)` so the parent module (and its
//! test submodules) can access them without qualification. The `impl`
//! block lives here too — Rust allows impl blocks for a type in any
//! module within the same crate.

use std::collections::BTreeMap;

use lr_babel::{BabelCodec, BabelFrame, BabelNeighbor, BabelRoute, BabelRouteTable};
use lr_core::addr::{IpAddr, Prefix};
use lr_core::nlri::NlriFamily;
use lr_core::rib::{Protocol, Route, RouteKey, RouteOrigin};

/// Babel protocol runtime for one adjacency: neighbor table + route table.
pub(super) struct BabelRuntime {
    pub(super) neighbor: BabelNeighbor,
    pub(super) routes: BabelRouteTable,
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
    /// Current IPv4 next hop (learned from AE 1 NextHop TLVs,
    /// RFC 8966 §4.6.4).
    pub(super) next_hop_v4: Option<IpAddr>,
    /// Current IPv6 next hop (AE 2 / AE 3 NextHop TLVs; the AE 4
    /// IPv4-via-IPv6 encoding resolves against this one).
    pub(super) next_hop_v6: Option<IpAddr>,
    /// Router-id of the peer (learned from Router-Id TLVs).
    pub(super) router_id: [u8; 8],
    /// Our own router-id, when the embedder pinned one
    /// ([`RouterApi::set_babel_own_router_id`]). Updates echoing it back
    /// (a peer re-advertising our own claims) are ignored — BIRD's
    /// `babel_handle_update` guard, and the cheap half of RFC 8966's
    /// loop prevention.
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
    /// `RouterEvent::Log`. Replaces the previous single `String`:
    /// the string was overwritten on every per-prefix retraction TLV,
    /// so a 29-route retraction frame logged only the LAST prefix;
    /// and the wildcard-retraction branch (AE 0, metric 0xFFFF) never
    /// set it at all, so the misleading fallback "babel best-path
    /// displacement" fired — the production-report symptom where an
    /// operator with one upstream saw "best-path displacement" and
    /// (correctly) concluded the message was wrong.
    pub(super) last_withdraw: LastWithdraw,
}

/// What kind of withdrawal happened in one Babel frame, set
/// incrementally by `apply_update` and rendered into a reason string
/// by `handle_frame` after `diff()` produces the delta.
///
/// The count of routes affected comes from `delta.withdrawn.len()` at
/// render time — not tracked here — so a frame that retracts a prefix
/// not in `published` (a no-op retraction) does not inflate the
/// logged count.
#[derive(Default)]
pub(super) struct LastWithdraw {
    pub(super) kind: WithdrawKind,
    /// For a single per-prefix retraction, the prefix that was
    /// retracted — rendered into the reason so the operator can
    /// `grep` for the exact prefix. `None` for wildcard retractions
    /// (no single prefix to name) and for multi-prefix frames (the
    /// count is what matters, not one prefix).
    pub(super) first_prefix: Option<lr_core::addr::Prefix>,
}

#[derive(Default, PartialEq, Eq)]
pub(super) enum WithdrawKind {
    /// No retraction TLV seen this frame — any `delta.withdrawn`
    /// entries came from `diff()`'s best-path displacement (a better
    /// route pushed the previous best out of the feasible set). The
    /// fallback "best-path displacement" message is correct here.
    #[default]
    None,
    /// One or more per-prefix retractions (metric=infinity, AE ≠ 0).
    /// The first prefix is recorded for the single-prefix message;
    /// multi-prefix frames get a count-annotated message.
    PerPrefix,
    /// A wildcard retraction (AE 0, metric 0xFFFF — RFC 8966 §4.6.9):
    /// the peer asked us to drop every route it taught us. Distinct
    /// from `PerPrefix` so the operator sees "wildcard retraction"
    /// (an explicit peer-side event) rather than the misleading
    /// "best-path displacement" (a local-decision event).
    Wildcard,
}

/// Result of one protocol-runtime step: routes to install into / withdraw
/// from Loc-RIB. The `withdraw_reason` is a human-readable string carried
/// on the first withdrawal's `RouterEvent::Log` so the operator can see
/// WHY a Babel route disappeared (expiry, explicit retraction, link-down,
/// or best-path displacement) — essential for diagnosing the
/// install/withdraw cycle in the Windows production report.
#[derive(Default)]
pub(super) struct RuntimeDelta {
    pub(super) installed: Vec<Route>,
    pub(super) withdrawn: Vec<RouteKey>,
    /// Human-readable reason for the withdrawals (empty when the delta
    /// carries installs only). Surfaced as a `RouterEvent::Log` line
    /// in `apply_runtime_delta` so the operator can correlate the
    /// withdrawal with its cause.
    pub(super) withdraw_reason: String,
}

impl BabelRuntime {
    pub(super) fn new(local: IpAddr, now_ms: u64) -> Self {
        Self {
            neighbor: BabelNeighbor::new(local, now_ms),
            routes: BabelRouteTable::new(),
            codec: BabelCodec::new(),
            rtt_min_us: 10_000,
            rtt_max_us: 120_000,
            rtt_cost: 0,
            next_hop_v4: None,
            next_hop_v6: None,
            router_id: [0; 8],
            own_router_id: None,
            route_request: false,
            own_seqno_request: None,
            published: BTreeMap::new(),
            last_withdraw: LastWithdraw::default(),
        }
    }

    /// The reception-side link cost toward this peer (RFC 8966 §3.4.3,
    /// babeld `neighbour_cost`, BIRD `babel_update_cost`): the
    /// transmission cost learned from the peer's IHU (its receive cost
    /// for our packets) plus the measured-RTT penalty. `None` while no
    /// IHU has arrived — babeld treats such a neighbour's routes as
    /// unusable (cost INFINITY), so Updates from it are not accepted
    /// yet.
    pub(super) fn link_cost(&self, now_ms: u64) -> Option<u32> {
        if self.neighbor.txcost >= 0xffff {
            return None;
        }
        let rtt = u32::from(self.neighbor.rtt_cost(
            now_ms,
            self.rtt_min_us,
            self.rtt_max_us,
            self.rtt_cost,
        ));
        Some(self.neighbor.txcost.saturating_add(rtt))
    }

    /// Feed one decoded Babel frame; returns the Loc-RIB delta.
    ///
    /// `now_us` is the transport's 32-bit microsecond clock at frame
    /// reception — the BABEL-RTT reference clock for timestamp bookkeeping
    /// (RFC 8966 §A.2.4). Passing the same clock the outgoing Hello/IHU
    /// timestamps are drawn from keeps the round-trip differences
    /// single-clock.
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

        // RFC 8966 §4.5.2 prefix-compression state — one per packet,
        // exactly like BIRD's parse state.
        let mut cache = PrefixCache::default();
        for tlv in &frame.body {
            match tlv.kind {
                TlvType::Hello => {
                    if let Some(h) = Hello::decode(&tlv.value) {
                        match h.timestamp {
                            Some(ts) => {
                                self.neighbor.hello_timestamped(
                                    h.seqno,
                                    h.interval_cs,
                                    ts,
                                    now_ms,
                                    now_us,
                                );
                            }
                            None => self.neighbor.hello(h.seqno, h.interval_cs, now_ms),
                        }
                    }
                }
                TlvType::Ihu => {
                    if let Some(ihu) = Ihu::decode(&tlv.value) {
                        match ihu.timestamp_echo {
                            Some((ts1, ts2)) => self.neighbor.ihu_echo(
                                ihu.rxcost,
                                ihu.interval_cs,
                                ts1,
                                ts2,
                                now_ms,
                            ),
                            None => self.neighbor.ihu(ihu.rxcost, ihu.interval_cs, now_ms),
                        }
                    }
                }
                TlvType::RouterId => {
                    if let Some(rid) = RouterIdTlv::decode(&tlv.value) {
                        self.router_id = rid.id;
                    }
                }
                TlvType::NextHop => {
                    if let Some(nh) = NextHop::decode(&tlv.value) {
                        // Per-family next-hop state (RFC 8966 §3.5.3):
                        // AE 1 feeds the IPv4 Updates, AE 2/3 the IPv6
                        // ones (and AE 4 v4-over-v6 resolution).
                        match nh.ae {
                            1 => self.next_hop_v4 = Some(nh.address),
                            _ => self.next_hop_v6 = Some(nh.address),
                        }
                    }
                }
                TlvType::Update => {
                    if let Some(u) = Update::decode(&tlv.value) {
                        if let Some(u) = cache.expand(&u) {
                            self.apply_update(&u, now_ms);
                        }
                    }
                }
                TlvType::RouteRequest => {
                    // RFC 8966 §3.2.6: answer any request (wildcard or
                    // specific) with the routes we announce — the
                    // embedder drains the flag and announces immediately.
                    if RouteRequest::decode(&tlv.value).is_some() {
                        self.route_request = true;
                    }
                }
                TlvType::SeqnoRequest => {
                    if let Some(req) = SeqnoRequest::decode(&tlv.value) {
                        // §3.2.6.2: a request naming our own router-id
                        // means a peer remembers a higher seqno than our
                        // boot value — bump and re-announce so its
                        // feasibility check accepts our routes again.
                        if let Some(own) = self.own_router_id {
                            if req.router_id == own {
                                self.own_seqno_request =
                                    Some(self.own_seqno_request.map_or(req.seqno, |prev| {
                                        // Several requests: serve the highest.
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
        let mut delta = self.diff();
        if !delta.withdrawn.is_empty() {
            // Render the structured `last_withdraw` record into the
            // delta's `withdraw_reason`. The kind tells the operator
            // WHAT peer-side event caused the withdrawal (a per-prefix
            // retraction, a wildcard retraction, or — when kind is None
            // — a local best-path displacement); the count of affected
            // routes comes from `delta.withdrawn.len()`, the actual
            // number that left the Loc-RIB. `std::mem::take` resets
            // the record for the next frame.
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

    pub(super) fn apply_update(&mut self, u: &lr_babel::message::Update, now_ms: u64) {
        // A peer re-advertising our own claims back at us: ignore (BIRD's
        // `msg->router_id == p->router_id` guard). Without this, our own
        // /64s echoed by a no-split-horizon peer would be learned as
        // Babel routes and — pre-fix — displaced the static routes we
        // originate them from.
        if let Some(own) = self.own_router_id {
            if u.metric != 0xFFFF && self.router_id == own {
                return;
            }
        }
        // AE 0 = wildcard retraction; AE 1 = IPv4; AE 2 = IPv6;
        // AE 4 = IPv4-via-IPv6 (RFC 9229 §2.4 — an IPv4 destination
        // reached over the IPv6 next hop). AE 3 (link-local IPv6) is not
        // a destination encoding and is ignored like BIRD does.
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
                // Wildcard retraction (§4.6.9): flush everything this
                // neighbour taught us — babeld's `retract_neighbour_routes`.
                if u.metric == 0xFFFF && !self.routes.is_empty() {
                    self.routes = lr_babel::BabelRouteTable::new();
                    // Record the kind so `handle_frame` renders the
                    // "wildcard retraction" reason instead of the
                    // misleading fallback "best-path displacement".
                    // Wildcard takes precedence over any per-prefix
                    // retractions in the same frame (the wildcard
                    // supersedes them — it retracts EVERY route this
                    // neighbour taught us, not just the named ones).
                    self.last_withdraw.kind = WithdrawKind::Wildcard;
                    self.last_withdraw.first_prefix = None;
                }
                return;
            }
            _ => return, // AE 3 and unknown AEs are ignored.
        };
        // Source-specific destination (RFC 9079) — tracked in the route key.
        // The source prefix uses the same AE as the destination.
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
            router_id: self.router_id,
        };
        // metric 0xFFFF (infinity) → retraction (RFC 8966 §3.5.5).
        if u.metric == 0xFFFF {
            self.routes.withdraw(&key);
            // Record the retraction so `handle_frame` can render the
            // "peer retraction (metric=infinity)" reason. The FIRST
            // per-prefix retraction in a frame records its prefix; a
            // subsequent retraction in the same frame (or a wildcard
            // retraction, which sets `Wildcard`) leaves `first_prefix`
            // alone — `handle_frame` switches to the count-annotated
            // form when `delta.withdrawn.len() > 1`. A wildcard
            // retraction already set `kind = Wildcard`, which takes
            // precedence — do not downgrade it.
            if self.last_withdraw.kind != WithdrawKind::Wildcard {
                if self.last_withdraw.kind == WithdrawKind::None {
                    self.last_withdraw.first_prefix = Some(key.destination);
                }
                self.last_withdraw.kind = WithdrawKind::PerPrefix;
            }
            return;
        }
        // Per-family next-hop resolution (RFC 8966 §3.5.3): an AE 1
        // Update rides the AE 1 NextHop TLV (or, in its absence, the
        // neighbour's own v4 address — the v4-transport shape); AE 2/3
        // and the AE 4 IPv4-via-IPv6 encoding ride the v6 next hop (or
        // the neighbour's address). An AE 1 Update with no usable v4
        // next hop is dropped exactly like BIRD's "Update must have
        // next hop" PARSE_ERROR.
        let peer_v4 = match self.neighbor.address {
            IpAddr::V4(_) => Some(self.neighbor.address),
            IpAddr::V6(_) => None,
        };
        let peer_v6 = match self.neighbor.address {
            IpAddr::V6(_) => Some(self.neighbor.address),
            IpAddr::V4(_) => None,
        };
        let nh = match u.ae {
            1 => match self.next_hop_v4.or(peer_v4) {
                Some(nh) => nh,
                None => return,
            },
            _ => self
                .next_hop_v6
                .or(peer_v6)
                .unwrap_or(self.neighbor.address),
        };
        // RFC 8966 §3.4.3 (babeld `route_metric + neighbour_cost`, BIRD
        // `babel_compute_metric`): the RECEIVER folds the link cost
        // toward the announcer into the route metric — the txcost
        // learned from the peer's IHU plus the RTT penalty. The
        // advertised metric never carries the announcer's own interface
        // cost: adding it there *and* here double-counts the link, the
        // production symptom where BIRD displayed metric 394 for
        // lr-originated routes (192 announced + 192 re-added) while
        // every BIRD peer's route showed just the link cost. Until the
        // first IHU arrives the txcost is infinite and no Update from
        // this neighbour is accepted (babeld parity).
        let Some(link) = self.link_cost(now_ms) else {
            return;
        };
        let metric = u32::from(u.metric).saturating_add(link).min(0xfffe);
        self.routes.insert_timed(
            BabelRoute {
                key,
                seqno: u.seqno,
                metric,
                next_hop: nh,
                feasible: true,
                installed: false,
            },
            u.interval_cs,
            now_ms,
        );
    }

    /// One expiry sweep (RFC 8966 §3.2.5): routes whose re-announcement
    /// hold time lapsed are dropped, and the diff against `published`
    /// becomes the Loc-RIB withdrawal delta.
    ///
    /// Unlike the previous implementation, this does NOT drop all routes
    /// immediately when the neighbour's Hello hold window (4× the Hello
    /// interval) lapses. On tunnel interfaces (WireGuard, etc.) a 4 s
    /// Hello gap is common — latency spikes, packet reordering, or
    /// scheduler hiccups all produce it. Dropping every route on a
    /// brief blip caused the "flaky Babel" symptom: routes withdrawn,
    /// then re-installed a second later when the next Hello arrived,
    /// with a brief outage during the gap. babeld does not have this
    /// path — it relies on each route's own hold timer (6× the Update
    /// interval, 15 s minimum) and the neighbour's retraction Updates.
    /// lr now matches that behaviour: a dead neighbour's routes expire
    /// through `routes.expire(now_ms)` within 15–18 s, which is fast
    /// enough for production and avoids the flap.
    pub(super) fn gc(&mut self, now_ms: u64) -> RuntimeDelta {
        let expired = self.routes.expire(now_ms);
        if !expired.is_empty() {
            let mut delta = self.diff();
            if delta.withdrawn.is_empty() {
                // expire() removed routes from the table but they were
                // not in `published` (already displaced by a better
                // route). No delta to emit.
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
        let current: BTreeMap<RouteKey, Route> = self
            .best_routes()
            .into_iter()
            .map(|r| (r.key.clone(), r))
            .collect();
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
        delta
    }

    /// Convert the Babel route table's feasible best routes into RIB routes.
    pub(super) fn best_routes(&mut self) -> Vec<Route> {
        // The per-family "next hop of last resort" for a 0.0.0.0 / ::
        // next hop announced on the wire: the family's NextHop TLV value
        // when seen, else the neighbour's own address.
        let peer_v4 = match self.neighbor.address {
            IpAddr::V4(_) => Some(self.neighbor.address),
            IpAddr::V6(_) => None,
        };
        let peer_v6 = match self.neighbor.address {
            IpAddr::V6(_) => Some(self.neighbor.address),
            IpAddr::V4(_) => None,
        };
        let nh_v4_default = self
            .next_hop_v4
            .or(peer_v4)
            .unwrap_or(self.neighbor.address);
        let nh_v6_default = self
            .next_hop_v6
            .or(peer_v6)
            .unwrap_or(self.neighbor.address);
        self.routes
            .best_routes()
            .into_iter()
            .map(|r| {
                // The Loc-RIB key family depends on the destination's
                // address family: IPv4 destinations → IPV4_UNICAST,
                // IPv6 destinations → IPV6_UNICAST.
                let family = match r.key.destination.addr {
                    lr_core::addr::IpAddr::V4(_) => NlriFamily::IPV4_UNICAST,
                    lr_core::addr::IpAddr::V6(_) => NlriFamily::IPV6_UNICAST,
                };
                let next_hop = match r.next_hop {
                    lr_core::addr::IpAddr::V4([0, 0, 0, 0]) => nh_v4_default,
                    lr_core::addr::IpAddr::V6(b) if b == [0u8; 16] => nh_v6_default,
                    other => other,
                };
                Route {
                    key: RouteKey::new(r.key.destination, family),
                    origin: RouteOrigin {
                        proto: 4, // Babel adjacency tag
                        peer: u64::from(u32::from_be_bytes([
                            self.router_id[4],
                            self.router_id[5],
                            self.router_id[6],
                            self.router_id[7],
                        ])),
                    },
                    protocol: Protocol::Babel,
                    preference: lr_core::rib::Preference::new(
                        Protocol::Babel.default_admin_distance(),
                        r.metric,
                    ),
                    next_hop: Some(next_hop),
                    attributes: lr_core::attr::Attributes::new(),
                    age_ms: 0,
                    path_id: 0,
                    tag: None,
                }
            })
            .collect()
    }
}
