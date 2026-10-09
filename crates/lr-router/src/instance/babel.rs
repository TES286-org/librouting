//! Babel protocol runtime types for the router instance.
//!
//! These types live in a sibling module so [`super::DefaultRouter`] stays
//! readable. Every field is `pub(super)` so the parent module (and its
//! test submodules) can access them without qualification. The `impl`
//! blocks stay in `mod.rs` — Rust allows impl blocks for a type in any
//! module within the same crate.

use std::collections::BTreeMap;

use lr_babel::{BabelCodec, BabelNeighbor, BabelRouteTable};
use lr_core::addr::IpAddr;
use lr_core::rib::{Route, RouteKey};

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
