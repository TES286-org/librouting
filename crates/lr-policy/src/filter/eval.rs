//! Tree-walking evaluator for the filter DSL.
//!
//! The evaluator is a `match` over [`crate::filter::ast::Stmt`] and
//! [`crate::filter::ast::Expr`] with a scoped variable stack. A
//! [`FilterContext`] provides the route-attribute accessors and the
//! ROA table — the evaluator does not depend on `lr-bgp` directly so
//! it can run on routes from any protocol.

use core::fmt;

use lr_core::addr::{Asn, IpAddr};
use lr_core::rib::Route;

use crate::filter::ast::{
    BinaryOp, Expr, Filter, FunctionDecl, RouteField, RouteFieldKind, Stmt, UnaryOp, Value,
};
use crate::filter::bytecode::{CompiledFilter, DefinedTarget, Instr, MatchItem, MatchRhs};
use crate::filter::span::{LineIndex, Span};

/// The result of evaluating a filter against a route.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EvalResult {
    /// Filter accepted the route (any mutations applied).
    Accept,
    /// Filter rejected the route. The optional reason is the
    /// `reject with "reason"` payload; `None` for bare `reject;`.
    Reject(Option<String>),
    /// Filter fell through with no terminal statement. Callers
    /// decide the implicit verdict — typically reject (BIRD
    /// behaviour) but a route-map-wrapped filter might use Continue.
    Fallthrough,
}

/// Evaluation error — always fatal for this route (the daemon logs
/// and falls back to the configured `roa_invalid_action` / the
/// route-map's verdict). Never panics.
///
/// Errors carry the byte [`Span`] of the offending AST node plus its
/// 1-indexed start line/column (derived from the filter's
/// [`LineIndex`] at construction), so log lines read "line 3 col 12"
/// instead of the pre-Phase-0 "line 0 col 0".
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvalError {
    pub kind: EvalErrorKind,
    /// Byte span of the offending node in the filter source.
    pub span: Span,
    /// 1-indexed line of the error position.
    pub line: u32,
    /// 1-indexed byte column of the error position.
    pub col: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EvalErrorKind {
    /// Undefined variable referenced.
    UndefinedVar(String),
    /// Assigning to a variable that was not introduced by `let`.
    AssignToUndefined(String),
    /// Type mismatch — e.g. `int + string`. The two type names are
    /// included for diagnostics.
    TypeMismatch {
        op: String,
        lhs: String,
        rhs: String,
    },
    /// Integer division by zero.
    DivByZero,
    /// Integer shift by a negative or out-of-range amount.
    BadShift(i64),
    /// Unknown function name.
    UnknownFunction(String),
    /// Wrong argument count for a known function.
    BadArgCount {
        name: String,
        expected: usize,
        got: usize,
    },
    /// Unknown method on a route field.
    UnknownMethod { field: String, method: String },
    /// Division / modulo producing a result outside `i64`.
    Overflow,
    /// An `i64` to `u32` narrowing failure (AS_PATH prepend with
    /// negative AS, etc.).
    AsnOutOfRange(i64),
    /// A community value (asn, val) where asn > u16::MAX or val > u16::MAX.
    CommunityOutOfRange { asn: i64, val: i64 },
    /// A user-function call chain exceeded [`MAX_CALL_DEPTH`] —
    /// runaway recursion is rejected instead of exhausting the stack.
    CallDepthExceeded(u32),
}

impl fmt::Display for EvalError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "filter eval error at line {} col {}: {}",
            self.line, self.col, self.kind
        )
    }
}

impl fmt::Display for EvalErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EvalErrorKind::UndefinedVar(s) => write!(f, "undefined variable '{s}'"),
            EvalErrorKind::AssignToUndefined(s) => {
                write!(
                    f,
                    "cannot assign to undefined variable '{s}' (use `let` first)"
                )
            }
            EvalErrorKind::TypeMismatch { op, lhs, rhs } => {
                write!(f, "{op} expects compatible types, got {lhs} and {rhs}")
            }
            EvalErrorKind::DivByZero => write!(f, "division by zero"),
            EvalErrorKind::BadShift(n) => write!(f, "shift amount {n} out of range 0..=63"),
            EvalErrorKind::UnknownFunction(s) => write!(f, "unknown function '{s}'"),
            EvalErrorKind::BadArgCount {
                name,
                expected,
                got,
            } => {
                write!(f, "function '{name}' expects {expected} arg(s), got {got}")
            }
            EvalErrorKind::UnknownMethod { field, method } => {
                write!(f, "unknown method '{method}' on field '{field}'")
            }
            EvalErrorKind::Overflow => write!(f, "arithmetic overflow"),
            EvalErrorKind::AsnOutOfRange(n) => write!(f, "ASN {n} out of u32 range"),
            EvalErrorKind::CommunityOutOfRange { asn, val } => {
                write!(f, "community {asn}:{val} has a component out of u16 range")
            }
            EvalErrorKind::CallDepthExceeded(d) => {
                write!(f, "user-function call depth exceeded {d}")
            }
        }
    }
}

/// A literal ROA state — the enum used inside `Value::RoaState`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RoaStateLit {
    Valid,
    NotFound,
    Invalid,
}

impl RoaStateLit {
    pub fn as_str(self) -> &'static str {
        match self {
            RoaStateLit::Valid => "valid",
            RoaStateLit::NotFound => "not-found",
            RoaStateLit::Invalid => "invalid",
        }
    }
}

/// Context the evaluator needs to read route attributes and run ROA
/// checks. The daemon implements this; tests use a stub.
pub trait FilterContext {
    /// BGP LOCAL_PREF (`bgp.local_pref`); `None` when absent.
    fn bgp_local_pref(&self, route: &Route) -> Option<u32>;
    /// BGP MULTI_EXIT_DISC (`bgp.med`); `None` when absent.
    fn bgp_med(&self, route: &Route) -> Option<u32>;
    /// BGP NEXT_HOP (`bgp.next_hop`); `None` when absent.
    fn bgp_next_hop(&self, route: &Route) -> Option<IpAddr>;
    /// BGP AS_PATH (`bgp.as_path`); empty when absent.
    fn bgp_as_path(&self, route: &Route) -> Vec<Asn>;
    /// BGP COMMUNITIES (`bgp.communities`); empty when absent.
    fn bgp_communities(&self, route: &Route) -> Vec<(Asn, u16)>;
    /// BGP LARGE_COMMUNITIES (`bgp.large_communities`, RFC 8092) as
    /// `(global_admin, local_data1, local_data2)` triples; empty when
    /// absent.
    fn bgp_large_communities(&self, route: &Route) -> Vec<(u32, u32, u32)>;
    /// BGP EXTENDED_COMMUNITIES (`bgp.ext_communities`, RFC 4360) as
    /// raw `(type, subtype, global, local)` records; empty when absent.
    fn bgp_ext_communities(&self, route: &Route) -> Vec<(u8, u8, u32, u16)>;
    /// BGP ORIGIN (`bgp.origin`): `0 = IGP`, `1 = EGP`, `2 = INCOMPLETE`.
    fn bgp_origin(&self, route: &Route) -> Option<u8>;
    /// BGP ATOMIC_AGGREGATE (`bgp.atomic_aggregate`, RFC 4271 §5.1.6):
    /// `true` when the marker is present, `false` when absent. The
    /// default delegates to [`lr_policy::bgp::atomic_aggregate`] so
    /// every context that backs its reads with `Route.attributes`
    /// (the daemon, the FFI built-in, the benches, the test stubs)
    /// inherits the correct behaviour without re-implementing it.
    fn bgp_atomic_aggregate(&self, route: &Route) -> bool {
        crate::bgp::atomic_aggregate(route)
    }
    /// BGP ORIGINATOR_ID (`bgp.originator_id`, RFC 4456 §8) as an
    /// `IpAddr::V4`; `None` when absent. The default delegates to
    /// [`lr_policy::bgp::originator_id`].
    fn bgp_originator_id(&self, route: &Route) -> Option<IpAddr> {
        crate::bgp::originator_id(route)
    }
    /// BGP CLUSTER_LIST (`bgp.cluster_list`, RFC 4456 §8) as a
    /// `Vec<IpAddr>` in reflection order; empty when absent. The
    /// default delegates to [`lr_policy::bgp::cluster_list`].
    fn bgp_cluster_list(&self, route: &Route) -> Vec<IpAddr> {
        crate::bgp::cluster_list(route)
    }
    /// True when a CLUSTER_LIST attribute is physically present on
    /// the route (RFC 4456 §8). Used by `defined(bgp.cluster_list)`
    /// to distinguish "no attribute" from "present but empty".
    fn bgp_has_cluster_list(&self, route: &Route) -> bool {
        crate::bgp::has_cluster_list(route)
    }
    /// BGP OTC (`bgp.otc`, RFC 9234 §3.1) — the 4-byte AS number
    /// that last tagged the route for customer-only propagation.
    /// `None` when the attribute is absent or malformed; `Some(0)`
    /// when present but zero. The default delegates to
    /// [`lr_policy::bgp::otc`].
    fn bgp_otc(&self, route: &Route) -> Option<u32> {
        crate::bgp::otc(route)
    }
    /// True when an OTC attribute is physically present on the route
    /// (RFC 9234 §3.1). Used by `defined(bgp.otc)` to distinguish
    /// "absent" from "set to zero".
    fn bgp_has_otc(&self, route: &Route) -> bool {
        crate::bgp::has_otc(route)
    }
    /// BGP AIGP (`bgp.aigp`, RFC 7311) — the Accumulated IGP Metric
    /// (the sum of every type-1 TLV's 8-byte value in the
    /// attribute's TLV stream). `None` when the attribute is absent
    /// or malformed; `Some(0)` when present but zero or when the
    /// value field is empty. The default delegates to
    /// [`lr_policy::bgp::aigp`].
    fn bgp_aigp(&self, route: &Route) -> Option<u64> {
        crate::bgp::aigp(route)
    }
    /// True when an AIGP attribute is physically present on the route
    /// (RFC 7311). Used by `defined(bgp.aigp)` to distinguish
    /// "absent" from "set to zero".
    fn bgp_has_aigp(&self, route: &Route) -> bool {
        crate::bgp::has_aigp(route)
    }
    /// BGP AGGREGATOR AS number (`bgp.aggregator.asn`, RFC 4271
    /// §5.1.7) — the AS of the BGP speaker that performed route
    /// aggregation. `None` when the attribute is absent or malformed;
    /// `Some(0)` when present but zero. The default delegates to
    /// [`lr_policy::bgp::aggregator_asn`].
    fn bgp_aggregator_asn(&self, route: &Route) -> Option<u32> {
        crate::bgp::aggregator_asn(route)
    }
    /// BGP AGGREGATOR speaker IP (`bgp.aggregator.speaker`,
    /// RFC 4271 §5.1.7) — the IPv4 address of the BGP speaker that
    /// performed route aggregation. `None` when the attribute is
    /// absent or malformed. The default delegates to
    /// [`lr_policy::bgp::aggregator_speaker`].
    fn bgp_aggregator_speaker(&self, route: &Route) -> Option<IpAddr> {
        crate::bgp::aggregator_speaker(route)
    }
    /// True when an AGGREGATOR attribute is physically present on the
    /// route (RFC 4271 §5.1.7). Used by `defined(bgp.aggregator.asn)`
    /// to distinguish "absent" from "set to zero". Both `asn` and
    /// `speaker` share the same presence, so this probe serves
    /// either field.
    fn bgp_has_aggregator(&self, route: &Route) -> bool {
        crate::bgp::has_aggregator(route)
    }
    /// BGP PMSI Tunnel attribute (`bgp.pmsi_tunnel`, RFC 6514 §5) —
    /// the typed view the policy layer surfaces (Flags, Tunnel
    /// Type, the 20-bit MPLS label, the variable-length Tunnel
    /// Identifier). `None` when the attribute is absent or
    /// malformed. The default delegates to
    /// [`lr_policy::bgp::pmsi_tunnel`].
    ///
    /// The filter DSL surfaces this attribute as a `Bool`
    /// (`bgp.pmsi_tunnel`) read through [`Self::bgp_has_pmsi_tunnel`],
    /// not through this accessor — the latter collapses "absent"
    /// and "malformed" together, but the former keeps "present but
    /// malformed" defined so a partial-bit UPDATE from a non-MVPN
    /// peer does not get a false `defined()` read.
    fn bgp_pmsi_tunnel(&self, route: &Route) -> Option<lr_bgp::path::PmsiTunnel> {
        crate::bgp::pmsi_tunnel(route)
    }
    /// True when a PMSI Tunnel attribute is physically present on
    /// the route (RFC 6514 §5). Used by `defined(bgp.pmsi_tunnel)`
    /// to distinguish "absent" from "present but malformed".
    fn bgp_has_pmsi_tunnel(&self, route: &Route) -> bool {
        crate::bgp::has_pmsi_tunnel(route)
    }
    /// The route's primary OSPF metric (`ospf.metric1`, RFC 2328 §16 /
    /// RFC 5340 §4.1) — the SPF cost for intra-area and inter-area
    /// routes, the cost-plus-external-metric for type-1 external
    /// routes, and the cost alone for type-2 external routes.
    /// `None` when the route is not OSPF (so the canonical BIRD idiom
    /// `if ospf_metric1 > 100 then reject;` no-ops on non-OSPF
    /// routes). `Some(0)` for an OSPF route with cost 0. The
    /// default delegates to [`crate::ospf::metric1`].
    fn ospf_metric1(&self, route: &Route) -> Option<u32> {
        crate::ospf::metric1(route)
    }
    /// True when the route is an OSPFv2 / OSPFv3 route and therefore
    /// carries a primary OSPF metric (RFC 2328 §16 / RFC 5340 §4.1).
    /// Used by `defined(ospf.metric1)` to distinguish "non-OSPF
    /// route" from "OSPF route with metric 0" (the latter is
    /// defined). The default delegates to [`crate::ospf::has_metric1`].
    fn ospf_has_metric1(&self, route: &Route) -> bool {
        crate::ospf::has_metric1(route)
    }
    /// The route's type-2 external OSPF metric (`ospf.metric2`, RFC
    /// 2328 §16.4 / RFC 5340 §4.8.5) — the E-bit-set LSA metric the
    /// §16.4 (6) type-2 preference ranks against. `None` when the
    /// route is not a type-2 external — non-OSPF routes, OSPF
    /// intra-area / inter-area routes, and OSPF type-1 external
    /// routes (the OSPF route computation only attaches the
    /// `LrOspfMetric2` attribute for type-2 externals). `Some(0)`
    /// for a type-2 external with metric 0. The default delegates
    /// to [`crate::ospf::metric2`].
    fn ospf_metric2(&self, route: &Route) -> Option<u32> {
        crate::ospf::metric2(route)
    }
    /// True when the route is an OSPFv2 / OSPFv3 type-2 external
    /// route (RFC 2328 §16.4 / RFC 5340 §4.8.5) and therefore
    /// carries a secondary OSPF metric. Used by
    /// `defined(ospf.metric2)` to distinguish "not a type-2
    /// external" from "type-2 external with metric 0" (the latter
    /// is defined). The default delegates to
    /// [`crate::ospf::has_metric2`].
    fn ospf_has_metric2(&self, route: &Route) -> bool {
        crate::ospf::has_metric2(route)
    }
    /// The route's external route tag (`ospf.tag`, RFC 2328 §A.4.5
    /// bullet h / RFC 3101 §2.3 / RFC 5340 §A.4.7 T bit / RFC 8362
    /// §3.6 External-Prefix sub-TLV 3) — the 32-bit tag carried in
    /// type-5 / type-7 AS-external-LSA bodies. `None` when the
    /// route carries no tag — a non-OSPF route, an OSPF intra-area
    /// / inter-area route, or a v3 external without the T bit set.
    /// `Some(0)` for a v2 external with a zero tag (the v2 LSA
    /// body always carries a 4-byte tag field, zero being
    /// well-formed per RFC 2328 §A.4.5) or a v3 external with the
    /// T bit set and a zero tag. The default delegates to
    /// [`crate::ospf::tag`].
    fn ospf_tag(&self, route: &Route) -> Option<u32> {
        crate::ospf::tag(route)
    }
    /// True when the route is an OSPFv2 / OSPFv3 external route and
    /// therefore carries an external route tag. Used by
    /// `defined(ospf.tag)` to distinguish "no tag" from "tag of
    /// zero" (the latter is defined for the v2 form, and for the
    /// v3 form when the T bit is set). The default delegates to
    /// [`crate::ospf::has_tag`].
    fn ospf_has_tag(&self, route: &Route) -> bool {
        crate::ospf::has_tag(route)
    }
    /// The route's OSPF advertising-router ID (`ospf.router_id`,
    /// RFC 2328 §A.4 `Advertising Router` field / RFC 5340 §A.4
    /// the same field on every v3 LSA) — the 32-bit OSPF
    /// Router-ID of the router that originated the LSA the route
    /// was computed from (the Router-LSA's advertising router
    /// for intra-area stub routes; the Network-LSA's advertising
    /// router — the DR — for intra-area transit routes; the
    /// summary-LSA's advertising router — the ABR — for
    /// inter-area routes; the AS-external-LSA's advertising
    /// router — the ASBR — for external routes). `None` when the
    /// route is not OSPF, or the OSPF route computation could not
    /// identify the originating LSA's advertising router (a
    /// defensive fallback; the LSA header always carries the
    /// field per RFC 2328 §A.4, so the OSPF route computation
    /// populates it for every received OSPF route). `Some(0)`
    /// is a meaningful value (a router may legally carry
    /// Router-ID 0.0.0.0, though RFC 2328 §3.1.b recommends a
    /// non-zero value). The default delegates to
    /// [`crate::ospf::router_id`].
    fn ospf_router_id(&self, route: &Route) -> Option<u32> {
        crate::ospf::router_id(route)
    }
    /// True when the route is an OSPFv2 / OSPFv3 route with a
    /// known originating LSA's advertising router (RFC 2328 §A.4 /
    /// RFC 5340 §A.4). Used by `defined(ospf.router_id)` to
    /// distinguish "no attribute" (a non-OSPF route, or an OSPF
    /// route whose computation could not identify the
    /// originating LSA's advertising router) from "attribute
    /// present but zero" (an OSPF route whose originator carries
    /// Router-ID 0.0.0.0 — RFC 2328 §3.1.b recommends non-zero
    /// but does not forbid it). The default delegates to
    /// [`crate::ospf::has_router_id`].
    fn ospf_has_router_id(&self, route: &Route) -> bool {
        crate::ospf::has_router_id(route)
    }
    /// Issue #81 — LRXP exchange-plane surface. True when the route
    /// carries a verified LRXP record set (tag-checked at ingress).
    /// The default delegates to [`crate::lrxp::verified`]; only
    /// compiled when the `exchange-plane` feature is on.
    #[cfg(feature = "exchange-plane")]
    fn lrxp_verified(&self, route: &Route) -> bool {
        crate::lrxp::verified(route)
    }
    /// Issue #81 — true when the route carries partial-transit LRXP
    /// forwarding material (the attribute crossed a non-lr hop,
    /// design §7).
    #[cfg(feature = "exchange-plane")]
    fn lrxp_partial_transit(&self, route: &Route) -> bool {
        crate::lrxp::partial_transit(route)
    }
    /// Issue #81 — the sender's best-path rank for this path among
    /// its alternates (design §5.1: 1 = the path the sender itself
    /// uses). `0` when the route carries no verified hint record.
    #[cfg(feature = "exchange-plane")]
    fn lrxp_hint_rank(&self, route: &Route) -> u8 {
        crate::lrxp::hint_rank(route)
    }
    /// Issue #81 — the sender's route-flap figure of merit (design
    /// §5.1: 0 when damping is off). `0` when absent.
    #[cfg(feature = "exchange-plane")]
    fn lrxp_hint_damp_fom(&self, route: &Route) -> u16 {
        crate::lrxp::hint_damp_fom(route)
    }
    /// Issue #81 — the sender's IGP cost to this path's next hop
    /// (design §5.1). `0` when absent.
    #[cfg(feature = "exchange-plane")]
    fn lrxp_hint_igp_cost(&self, route: &Route) -> u32 {
        crate::lrxp::hint_igp_cost(route)
    }
    /// Issue #81 — the sender's RFC 9234 role claim for this session
    /// (design §5.2: advisory). `255` (unspecified) when absent.
    #[cfg(feature = "exchange-plane")]
    fn lrxp_policy_role(&self, route: &Route) -> u8 {
        crate::lrxp::policy_role(route)
    }
    /// Issue #81 — the sender's SipHash-2-4 import-filter digest as a
    /// lowercase hex string (design §5.2). Empty string when absent.
    #[cfg(feature = "exchange-plane")]
    fn lrxp_policy_import_digest_hex(&self, route: &Route) -> String {
        crate::lrxp::policy_import_digest_hex(route)
    }
    /// Issue #81 — the sender's SipHash-2-4 export-filter digest as a
    /// lowercase hex string (design §5.2). Empty string when absent.
    #[cfg(feature = "exchange-plane")]
    fn lrxp_policy_export_digest_hex(&self, route: &Route) -> String {
        crate::lrxp::policy_export_digest_hex(route)
    }
    /// Issue #81 — the origin AS the attestation authorises (design
    /// §5.3). `0` when absent.
    #[cfg(feature = "exchange-plane")]
    fn lrxp_origin_as(&self, route: &Route) -> u32 {
        crate::lrxp::origin_as(route)
    }
    /// Issue #81 — the maximum prefix length the origin authorises
    /// (design §5.3). `0` when absent.
    #[cfg(feature = "exchange-plane")]
    fn lrxp_origin_max_valid_len(&self, route: &Route) -> u8 {
        crate::lrxp::origin_max_valid_len(route)
    }
    /// Issue #81 — the absolute timestamp after which the record
    /// expires (design §5.3). `0` when absent.
    #[cfg(feature = "exchange-plane")]
    fn lrxp_origin_expiry(&self, route: &Route) -> u32 {
        crate::lrxp::origin_expiry(route)
    }
    /// RFC 6811 validation outcome (`roa.state`) for the route's
    /// prefix + origin AS.
    fn roa_state(&self, route: &Route) -> RoaStateLit;

    // --- Mutators ---
    /// Set the BGP LOCAL_PREF (RFC 4271 §5.1.5).
    fn set_bgp_local_pref(&self, route: &mut Route, value: u32);
    /// Set the BGP MULTI_EXIT_DISC (RFC 4271 §4.2.4).
    fn set_bgp_med(&self, route: &mut Route, value: u32);
    /// Set the BGP NEXT_HOP.
    fn set_bgp_next_hop(&self, route: &mut Route, value: IpAddr);
    /// Prepend one AS to the AS_PATH (RFC 4271 §4.3).
    fn bgp_as_path_prepend(&self, route: &mut Route, asn: Asn);
    /// Add one community (RFC 1997 §4). Duplicates are not added.
    fn bgp_communities_add(&self, route: &mut Route, asn: Asn, value: u16);
    /// Replace the whole COMMUNITIES attribute. An empty set drops the
    /// attribute entirely (BIRD semantics for `delete` leaving
    /// nothing behind). Used by `bgp.communities.delete/filter`.
    fn set_bgp_communities(&self, route: &mut Route, set: Vec<(Asn, u16)>);
    /// Replace the AS_PATH with a flat sequence. An empty sequence
    /// drops the attribute. Used by `bgp.as_path.delete/filter`.
    fn set_bgp_as_path(&self, route: &mut Route, seq: Vec<Asn>);
    /// Replace the whole LARGE_COMMUNITIES attribute (RFC 8092);
    /// an empty set drops it.
    fn set_bgp_large_communities(&self, route: &mut Route, set: Vec<(u32, u32, u32)>);
    /// Replace the whole EXTENDED_COMMUNITIES attribute (RFC 4360);
    /// an empty set drops it.
    fn set_bgp_ext_communities(&self, route: &mut Route, set: Vec<(u8, u8, u32, u16)>);
}

/// Internal control-flow signal — `Continue` keeps evaluating the
/// current statement list; `Accept` / `Reject(reason)` short-circuits
/// to the filter's outermost verdict.
enum ControlFlow {
    Continue,
    Accept,
    Reject(Option<String>),
    /// `return expr;` inside a user-defined function (D3.1). The
    /// payload is the returned value; `None` is a bare `return;`.
    Return(Option<Value>),
}

/// Variable stack entry — `let` introduces one; `Block` pushes a
/// new scope frame.
struct Scope {
    vars: std::collections::BTreeMap<String, Value>,
}

impl Scope {
    fn new() -> Self {
        Self {
            vars: std::collections::BTreeMap::new(),
        }
    }
}

/// Maximum user-function call depth. A call chain deeper than this
/// aborts evaluation with [`EvalErrorKind::CallDepthExceeded`] —
/// runaway recursion must not exhaust the thread stack.
pub const MAX_CALL_DEPTH: u32 = 64;

/// The evaluator state — a scope stack, the route under evaluation
/// and the user functions (D3.1) declared on the same filter.
struct Evaluator<'a, C: FilterContext + ?Sized> {
    ctx: &'a C,
    scopes: Vec<Scope>,
    functions: std::collections::BTreeMap<String, FunctionDecl>,
    call_depth: u32,
    /// Verdict latched by `accept` / `reject` inside a user-function
    /// body (BIRD: terminates the whole filter). Consumed by the
    /// top-level loop after the current statement.
    pending_verdict: Option<ControlFlow>,
    /// Offset → (line, col) table for the filter source — eval errors
    /// are built with real positions instead of `line 0 col 0`.
    line_index: &'a LineIndex,
}

impl<'a, C: FilterContext + ?Sized> Evaluator<'a, C> {
    /// Build an [`EvalError`] with the position derived from `span`.
    fn err(&self, span: Span, kind: EvalErrorKind) -> EvalError {
        let (line, col) = self.line_index.line_col(span.start);
        EvalError {
            kind,
            span,
            line,
            col,
        }
    }
}

/// Evaluate a compiled filter against a route.
pub fn evaluate(filter: &Filter, route: &mut Route, ctx: &dyn FilterContext) -> EvalResult {
    let mut ev = Evaluator {
        ctx,
        scopes: vec![Scope::new()],
        functions: filter
            .functions
            .iter()
            .map(|f| (f.name.clone(), f.clone()))
            .collect(),
        call_depth: 0,
        pending_verdict: None,
        line_index: &filter.line_index,
    };
    for stmt in &filter.body.stmts {
        if let Some(v) = ev.pending_verdict.take() {
            return match v {
                ControlFlow::Accept => EvalResult::Accept,
                ControlFlow::Reject(reason) => EvalResult::Reject(reason),
                _ => EvalResult::Fallthrough,
            };
        }
        match ev.eval_stmt(stmt, route) {
            Ok(ControlFlow::Continue) => {}
            Ok(ControlFlow::Accept) => return EvalResult::Accept,
            Ok(ControlFlow::Reject(reason)) => return EvalResult::Reject(reason),
            Ok(ControlFlow::Return(_)) => {
                tracing::debug!(
                    "filter '{}': return outside a user function — no verdict",
                    filter.name
                );
                return EvalResult::Fallthrough;
            }
            Err(e) => {
                tracing::debug!("filter '{}' eval error: {}", filter.name, e);
                return EvalResult::Fallthrough;
            }
        }
    }
    EvalResult::Fallthrough
}

impl<'a, C: FilterContext + ?Sized> Evaluator<'a, C> {
    fn lookup(&self, name: &str, span: Span) -> Result<Value, EvalError> {
        for scope in self.scopes.iter().rev() {
            if let Some(v) = scope.vars.get(name) {
                return Ok(v.clone());
            }
        }
        if name == "_" {
            return Ok(Value::Bool(true));
        }
        Err(self.err(span, EvalErrorKind::UndefinedVar(name.to_string())))
    }

    fn assign(&mut self, name: &str, value: Value, span: Span) -> Result<(), EvalError> {
        for scope in self.scopes.iter_mut().rev() {
            if scope.vars.contains_key(name) {
                scope.vars.insert(name.to_string(), value);
                return Ok(());
            }
        }
        Err(self.err(span, EvalErrorKind::AssignToUndefined(name.to_string())))
    }

    fn push_scope(&mut self) {
        self.scopes.push(Scope::new());
    }

    fn pop_scope(&mut self) {
        self.scopes.pop();
    }

    fn eval_stmt(&mut self, stmt: &Stmt, route: &mut Route) -> Result<ControlFlow, EvalError> {
        match stmt {
            Stmt::Return(value, _) => {
                let v = match value {
                    Some(e) => Some(self.eval_expr(e, route)?),
                    None => None,
                };
                Ok(ControlFlow::Return(v))
            }
            Stmt::Accept(_) => Ok(ControlFlow::Accept),
            Stmt::Reject(reason, _) => {
                let reason_str = if let Some(r) = reason {
                    match self.eval_expr(r, route)? {
                        Value::Str(s) => Some(s),
                        other => Some(format!("{other}")),
                    }
                } else {
                    None
                };
                Ok(ControlFlow::Reject(reason_str))
            }
            Stmt::If {
                cond, then, els, ..
            } => {
                let c = self.eval_expr(cond, route)?;
                if c.truthy() {
                    self.eval_stmt(then, route)
                } else if let Some(e) = els {
                    self.eval_stmt(e, route)
                } else {
                    Ok(ControlFlow::Continue)
                }
            }
            Stmt::Case {
                scrutinee, arms, ..
            } => {
                let v = self.eval_expr(scrutinee, route)?;
                for arm in arms {
                    if arm.patterns.is_empty() {
                        // default arm
                        self.push_scope();
                        for s in &arm.body {
                            match self.eval_stmt(s, route)? {
                                ControlFlow::Continue => {}
                                other => {
                                    self.pop_scope();
                                    return Ok(other);
                                }
                            }
                        }
                        self.pop_scope();
                        return Ok(ControlFlow::Continue);
                    }
                    for p in &arm.patterns {
                        let pv = self.eval_expr(p, route)?;
                        if value_eq(&v, &pv) {
                            self.push_scope();
                            for s in &arm.body {
                                match self.eval_stmt(s, route)? {
                                    ControlFlow::Continue => {}
                                    other => {
                                        self.pop_scope();
                                        return Ok(other);
                                    }
                                }
                            }
                            self.pop_scope();
                            return Ok(ControlFlow::Continue);
                        }
                    }
                }
                Ok(ControlFlow::Continue)
            }
            Stmt::Let { name, value, .. } => {
                let v = self.eval_expr(value, route)?;
                self.scopes.last_mut().unwrap().vars.insert(name.clone(), v);
                Ok(ControlFlow::Continue)
            }
            Stmt::Assign { name, value, span } => {
                let v = self.eval_expr(value, route)?;
                self.assign(name, v, *span)?;
                Ok(ControlFlow::Continue)
            }
            Stmt::AssignRouteField { field, value, span } => {
                let v = self.eval_expr(value, route)?;
                self.assign_route_field(field, v, route, *span)?;
                Ok(ControlFlow::Continue)
            }
            Stmt::AppendRouteField { field, value, span } => {
                let v = self.eval_expr(value, route)?;
                self.append_route_field(field, v, route, *span)?;
                Ok(ControlFlow::Continue)
            }
            Stmt::Expr(e, _) => {
                let _ = self.eval_expr(e, route)?;
                Ok(ControlFlow::Continue)
            }
            Stmt::Block(body, _) => {
                self.push_scope();
                for s in body {
                    match self.eval_stmt(s, route)? {
                        ControlFlow::Continue => {}
                        other => {
                            self.pop_scope();
                            return Ok(other);
                        }
                    }
                }
                self.pop_scope();
                Ok(ControlFlow::Continue)
            }
        }
    }

    fn eval_expr(&mut self, expr: &Expr, route: &mut Route) -> Result<Value, EvalError> {
        match expr {
            Expr::Lit(v, _) => Ok(v.clone()),
            Expr::Var(name, span) => self.lookup(name, *span),
            Expr::RouteField(field, _) => self.read_route_field(field, route),
            Expr::Defined(inner, _) => Ok(Value::Bool(self.is_defined(inner, route))),
            Expr::Call { name, args, span } => {
                let mut argv: Vec<Value> = Vec::with_capacity(args.len());
                for a in args {
                    argv.push(self.eval_expr(a, route)?);
                }
                self.eval_call(name, &argv, route, *span)
            }
            Expr::Method {
                receiver,
                method,
                args,
                span,
            } => {
                if let Expr::RouteField(field, _) = receiver.as_ref() {
                    let mut argv: Vec<Value> = Vec::with_capacity(args.len());
                    for a in args {
                        argv.push(self.eval_expr(a, route)?);
                    }
                    return self.eval_method(field, method, &argv, route, *span);
                }
                Err(self.err(
                    *span,
                    EvalErrorKind::UnknownMethod {
                        field: "<expr>".to_string(),
                        method: method.clone(),
                    },
                ))
            }
            Expr::Binary { op, lhs, rhs, span } => {
                // Short-circuit for && and ||.
                if *op == BinaryOp::And {
                    let l = self.eval_expr(lhs, route)?;
                    if !l.truthy() {
                        return Ok(Value::Bool(false));
                    }
                    let r = self.eval_expr(rhs, route)?;
                    return Ok(Value::Bool(r.truthy()));
                }
                if *op == BinaryOp::Or {
                    let l = self.eval_expr(lhs, route)?;
                    if l.truthy() {
                        return Ok(Value::Bool(true));
                    }
                    let r = self.eval_expr(rhs, route)?;
                    return Ok(Value::Bool(r.truthy()));
                }
                // Membership tests (`~` / `!~`) defer RHS evaluation
                // so prefix-set ranges (carried in the AST, not the
                // Value) are applied.
                if *op == BinaryOp::Match || *op == BinaryOp::NotMatch {
                    let l = self.eval_expr(lhs, route)?;
                    let m = self.eval_match(&l, rhs, route)?;
                    return Ok(Value::Bool(if *op == BinaryOp::Match { m } else { !m }));
                }
                let l = self.eval_expr(lhs, route)?;
                let r = self.eval_expr(rhs, route)?;
                self.eval_binary(*op, l, r, *span)
            }
            Expr::Unary { op, expr, span } => {
                let v = self.eval_expr(expr, route)?;
                match op {
                    UnaryOp::Not => Ok(Value::Bool(!v.truthy())),
                    UnaryOp::Neg => match v {
                        Value::Int(n) => Ok(Value::Int(-n)),
                        other => Err(type_mismatch("neg", &other, "int", *span, self.line_index)),
                    },
                }
            }
            Expr::Set(items, _) => {
                let mut v = Vec::with_capacity(items.len());
                for it in items {
                    v.push(self.eval_expr(it, route)?);
                }
                Ok(Value::Set(v))
            }
            Expr::PrefixSet { prefix, ge, le, .. } => {
                let _ = (ge, le);
                Ok(Value::Prefix(*prefix))
            }
        }
    }

    fn eval_match(
        &mut self,
        lhs: &Value,
        rhs: &Expr,
        route: &mut Route,
    ) -> Result<bool, EvalError> {
        match rhs {
            Expr::Set(items, _) => {
                for it in items {
                    if let Expr::PrefixSet { prefix, ge, le, .. } = it {
                        if let Value::Prefix(p) = lhs {
                            if prefix_set_matches(prefix, *ge, *le, p) {
                                return Ok(true);
                            }
                        }
                        continue;
                    }
                    let v = self.eval_expr(it, route)?;
                    if value_match(lhs, &v) {
                        return Ok(true);
                    }
                }
                Ok(false)
            }
            Expr::PrefixSet { prefix, ge, le, .. } => {
                if let Value::Prefix(p) = lhs {
                    Ok(prefix_set_matches(prefix, *ge, *le, p))
                } else {
                    Ok(false)
                }
            }
            _ => {
                let v = self.eval_expr(rhs, route)?;
                Ok(value_match(lhs, &v))
            }
        }
    }

    /// Attribute presence for one route-field kind — the single
    /// source both the tree-walking `defined()` and the bytecode VM
    /// consult.
    fn field_present(&self, kind: RouteFieldKind, route: &Route) -> bool {
        match kind {
            // Always carried by the route model itself.
            RouteFieldKind::Net | RouteFieldKind::Proto | RouteFieldKind::Source => true,
            // Computed on demand — always resolvable.
            RouteFieldKind::RoaState => true,
            RouteFieldKind::BgpLocalPref => self.ctx.bgp_local_pref(route).is_some(),
            RouteFieldKind::BgpMed => self.ctx.bgp_med(route).is_some(),
            RouteFieldKind::BgpNextHop => self.ctx.bgp_next_hop(route).is_some(),
            RouteFieldKind::BgpOrigin => self.ctx.bgp_origin(route).is_some(),
            // List-valued accessors lose the absent/empty
            // distinction; BIRD parity here is "present = at least
            // one element".
            RouteFieldKind::BgpAsPath => !self.ctx.bgp_as_path(route).is_empty(),
            RouteFieldKind::BgpCommunities => !self.ctx.bgp_communities(route).is_empty(),
            RouteFieldKind::BgpLargeCommunities => {
                !self.ctx.bgp_large_communities(route).is_empty()
            }
            RouteFieldKind::BgpExtCommunities => !self.ctx.bgp_ext_communities(route).is_empty(),
            // RFC 4271 §5.1.6: ATOMIC_AGGREGATE is a presence marker.
            RouteFieldKind::BgpAtomicAggregate => self.ctx.bgp_atomic_aggregate(route),
            // RFC 4456 §8: ORIGINATOR_ID is present iff the accessor
            // returns Some(_). CLUSTER_LIST distinguishes "no
            // attribute" from "present but empty" via the
            // bgp_has_cluster_list helper — an empty-but-present list
            // still counts as defined (matches BIRD's `defined()`
            // on a `clist`).
            RouteFieldKind::BgpOriginatorId => self.ctx.bgp_originator_id(route).is_some(),
            RouteFieldKind::BgpClusterList => self.ctx.bgp_has_cluster_list(route),
            // RFC 9234 §3.1: OTC presence is `has_otc` (the
            // attribute is on the route), not `otc().is_some()` —
            // the latter collapses "absent" and "malformed" together
            // but the former keeps "present but zero" defined.
            RouteFieldKind::BgpOtc => self.ctx.bgp_has_otc(route),
            // RFC 7311: AIGP presence is `has_aigp` (the attribute
            // is on the route), not `aigp().is_some()` — the latter
            // collapses "absent" and "malformed" together but the
            // former keeps "present but zero" (and the empty-value
            // field case) defined.
            RouteFieldKind::BgpAigp => self.ctx.bgp_has_aigp(route),
            // RFC 4271 §5.1.7: AGGREGATOR presence is
            // `has_aggregator` (the attribute is on the route), not
            // `aggregator_asn().is_some()` — the latter collapses
            // "absent" and "malformed" together but the former keeps
            // "present but zero" defined. Both `asn` and `speaker`
            // share the same physical presence, so one probe serves
            // either field.
            RouteFieldKind::BgpAggregatorAsn | RouteFieldKind::BgpAggregatorSpeaker => {
                self.ctx.bgp_has_aggregator(route)
            }
            // RFC 6514 §5: PMSI Tunnel presence is
            // `has_pmsi_tunnel` (the attribute is on the route),
            // not `pmsi_tunnel().is_some()` — the latter collapses
            // "absent" and "malformed" together but the former
            // keeps "present but malformed" defined (matches
            // BIRD's `defined(bgp_pmsi_tunnel)` on a partial-bit
            // UPDATE from a non-MVPN peer).
            RouteFieldKind::BgpPmsiTunnel => self.ctx.bgp_has_pmsi_tunnel(route),
            // RFC 2328 §16 / RFC 5340 §4.1: `ospf.metric1` presence
            // is `has_metric1` (the route is an OSPFv2 / OSPFv3
            // route), not `metric1().is_some()` — the two agree on
            // the OSPF case (both true), but `has_metric1` keeps an
            // OSPF route with cost 0 defined so the canonical idiom
            // `if defined(ospf.metric1) then accept;` does not drop
            // a cost-0 OSPF route.
            RouteFieldKind::OspfMetric1 => self.ctx.ospf_has_metric1(route),
            // RFC 2328 §16.4 / RFC 5340 §4.8.5: `ospf.metric2` presence
            // is `has_metric2` (the route is an OSPFv2 / OSPFv3
            // type-2 external route), not `metric2().is_some()` — the
            // two agree on the type-2-external case (both true), but
            // `has_metric2` keeps a type-2 external with metric 0
            // defined so the canonical idiom `if defined(ospf.metric2)
            // then accept;` does not drop a metric-0 type-2 external.
            RouteFieldKind::OspfMetric2 => self.ctx.ospf_has_metric2(route),
            // RFC 2328 §A.4.5 bullet h / RFC 3101 §2.3 / RFC 5340 §A.4.7
            // T bit / RFC 8362 §3.6 External-Prefix sub-TLV 3:
            // `ospf.tag` presence is `has_tag` (the route is an OSPFv2
            // / OSPFv3 external route with a non-`None` `Route::tag`),
            // not `tag().is_some()` — the two agree, but `has_tag`
            // spells the contract: a v2 external always surfaces
            // `Some(t)` (the v2 LSA body always carries a 4-byte tag
            // field, zero being well-formed per RFC 2328 §A.4.5), so
            // `defined(ospf.tag)` is true even when the tag is zero;
            // a v3 external surfaces `Some(t)` only when the T bit /
            // sub-TLV is present, so `defined(ospf.tag)` distinguishes
            // "no tag" (T bit clear) from "tag of zero" (T bit set,
            // value 0). For non-OSPF routes, `has_tag` is false.
            RouteFieldKind::OspfTag => self.ctx.ospf_has_tag(route),
            // RFC 2328 §A.4 `Advertising Router` field / RFC 5340
            // §A.4 the same field on every v3 LSA: `ospf.router_id`
            // presence is `has_router_id` (the route is an OSPFv2 /
            // OSPFv3 route with a known originating LSA's
            // advertising router), not `router_id().is_some()` —
            // the two agree on the present-with-non-zero case
            // (both true), but the distinction matters when a
            // router carries Router-ID 0.0.0.0 (RFC 2328 §3.1.b
            // recommends non-zero but does not forbid it):
            // `has_router_id` keeps "OSPF route with Router-ID 0"
            // defined so the canonical idiom `if
            // defined(ospf.router_id) && ospf.router_id == 0
            // then accept;` does not drop such a route. For
            // non-OSPF routes, `has_router_id` is false.
            RouteFieldKind::OspfRouterId => self.ctx.ospf_has_router_id(route),
            // Issue #81 — LRXP `defined()` semantics. The two bare
            // predicates (`verified`, `partial_transit`) are defined
            // iff the route carries an LRXP store of any kind. The
            // per-record fields (`hint.rank`, `policy.role`, etc.)
            // are defined iff the route carries a verified store AND
            // the corresponding record class is present in it — a
            // partial-transit store or a verified store without the
            // record class reads as absent.
            #[cfg(feature = "exchange-plane")]
            RouteFieldKind::LrxpVerified | RouteFieldKind::LrxpPartialTransit => {
                crate::lrxp::store_kind(route).is_some()
            }
            #[cfg(feature = "exchange-plane")]
            RouteFieldKind::LrxpHintRank
            | RouteFieldKind::LrxpHintDampFom
            | RouteFieldKind::LrxpHintIgpCost => crate::lrxp::hint(route).is_some(),
            #[cfg(feature = "exchange-plane")]
            RouteFieldKind::LrxpPolicyRole
            | RouteFieldKind::LrxpPolicyImportDigest
            | RouteFieldKind::LrxpPolicyExportDigest => crate::lrxp::policy(route).is_some(),
            #[cfg(feature = "exchange-plane")]
            RouteFieldKind::LrxpOriginAs
            | RouteFieldKind::LrxpOriginMaxValidLen
            | RouteFieldKind::LrxpOriginExpiry => crate::lrxp::origin(route).is_some(),
            // Feature-less build: the LRXP variants are unreachable
            // (the parser rejects `bgp.lrxp.*` with
            // `UnknownBgpField`). The wildcard keeps the match
            // exhaustive over the full variant set without pulling
            // the codec into a feature-less build.
            #[cfg(not(feature = "exchange-plane"))]
            _ => false,
        }
    }

    /// Presence check for `defined(expr)` / `exists(expr)`.
    ///
    /// Never fails and never mutates the caller's route: an absent
    /// attribute or an undefined variable is simply "not defined".
    /// Distinguishes "absent" from "set to the default value" — the
    /// read path collapses both to `0` / `false` / empty, which is
    /// exactly what BIRD's `defined()` exists to avoid.
    fn is_defined(&mut self, expr: &Expr, route: &Route) -> bool {
        match expr {
            Expr::RouteField(field, _) => self.field_present(field.kind, route),
            Expr::Var(name, _) => self.scopes.iter().rev().any(|s| s.vars.contains_key(name)),
            // A literal is always defined.
            Expr::Lit(..) => true,
            // Any other expression is "defined" when it evaluates
            // without error. Evaluation runs against a route copy, so
            // a `defined()` argument can never write through (no
            // side effects leak from a presence probe).
            _ => {
                let mut probe = route.clone();
                self.eval_expr(expr, &mut probe).is_ok()
            }
        }
    }

    fn read_route_field(&self, field: &RouteField, route: &Route) -> Result<Value, EvalError> {
        match field.kind {
            RouteFieldKind::Net => Ok(Value::Prefix(route.key.prefix)),
            RouteFieldKind::Proto => Ok(Value::Str(route.protocol.bird_name().to_string())),
            RouteFieldKind::Source => Ok(Value::Int(i64::from(route.origin.proto))),
            RouteFieldKind::BgpLocalPref => Ok(Value::Int(
                self.ctx.bgp_local_pref(route).unwrap_or(0) as i64,
            )),
            RouteFieldKind::BgpMed => Ok(Value::Int(self.ctx.bgp_med(route).unwrap_or(0) as i64)),
            RouteFieldKind::BgpNextHop => Ok(self
                .ctx
                .bgp_next_hop(route)
                .map(Value::Ip)
                .unwrap_or(Value::Bool(false))),
            RouteFieldKind::BgpAsPath => Ok(Value::AsPath(self.ctx.bgp_as_path(route))),
            RouteFieldKind::BgpCommunities => {
                Ok(Value::Communities(self.ctx.bgp_communities(route)))
            }
            RouteFieldKind::BgpLargeCommunities => Ok(Value::LargeCommunities(
                self.ctx.bgp_large_communities(route),
            )),
            RouteFieldKind::BgpExtCommunities => {
                Ok(Value::ExtCommunities(self.ctx.bgp_ext_communities(route)))
            }
            RouteFieldKind::BgpOrigin => Ok(Value::Int(i64::from(
                self.ctx.bgp_origin(route).unwrap_or(0),
            ))),
            // RFC 4271 §5.1.6: ATOMIC_AGGREGATE is a boolean marker.
            RouteFieldKind::BgpAtomicAggregate => {
                Ok(Value::Bool(self.ctx.bgp_atomic_aggregate(route)))
            }
            // RFC 4456 §8: ORIGINATOR_ID is an IPv4 BGP Identifier;
            // mirror `bgp.next_hop`'s `Bool(false)` sentinel for the
            // absent case so a direct `==` comparison does not crash
            // (callers should gate with `defined(bgp.originator_id)`).
            RouteFieldKind::BgpOriginatorId => Ok(self
                .ctx
                .bgp_originator_id(route)
                .map(Value::Ip)
                .unwrap_or(Value::Bool(false))),
            // RFC 4456 §8: CLUSTER_LIST is a Vec<IpAddr> surfaced as
            // a generic `Set` so BIRD's `~` membership test works
            // directly (`local_cluster ~ bgp.cluster_list`).
            RouteFieldKind::BgpClusterList => Ok(Value::Set(
                self.ctx
                    .bgp_cluster_list(route)
                    .into_iter()
                    .map(Value::Ip)
                    .collect(),
            )),
            // RFC 9234 §3.1: OTC is a 4-byte AS number surfaced as
            // an `Int` (`0` when absent or set to zero). Callers
            // that need to distinguish "absent" from "set to zero"
            // gate with `defined(bgp.otc)`.
            RouteFieldKind::BgpOtc => Ok(Value::Int(self.ctx.bgp_otc(route).unwrap_or(0) as i64)),
            // RFC 7311: AIGP is an 8-byte accumulated metric
            // surfaced as an `Int` (`0` when absent or set to zero).
            // The wire value is `u64`; the DSL's `Value::Int` is
            // `i64`, so a value exceeding `i64::MAX` saturates —
            // practical IGP metrics are far below `i64::MAX`.
            // Callers that need to distinguish "absent" from "set
            // to zero" gate with `defined(bgp.aigp)`.
            RouteFieldKind::BgpAigp => Ok(Value::Int(
                self.ctx.bgp_aigp(route).unwrap_or(0).min(i64::MAX as u64) as i64,
            )),
            // RFC 4271 §5.1.7: AGGREGATOR AS is a 4-byte AS number
            // surfaced as an `Int` (`0` when absent or set to zero).
            // Callers that need to distinguish "absent" from "set to
            // zero" gate with `defined(bgp.aggregator.asn)`.
            RouteFieldKind::BgpAggregatorAsn => Ok(Value::Int(
                self.ctx.bgp_aggregator_asn(route).unwrap_or(0) as i64,
            )),
            // RFC 4271 §5.1.7: AGGREGATOR speaker is an IPv4 address
            // surfaced as an `Ip`; mirror `bgp.next_hop`'s /
            // `bgp.originator_id`'s `Bool(false)` sentinel for the
            // absent case so a direct `==` comparison does not crash
            // (callers should gate with `defined(bgp.aggregator.asn)`).
            RouteFieldKind::BgpAggregatorSpeaker => Ok(self
                .ctx
                .bgp_aggregator_speaker(route)
                .map(Value::Ip)
                .unwrap_or(Value::Bool(false))),
            // RFC 6514 §5: PMSI Tunnel is a presence-probe `Bool`
            // mirroring BIRD's `EAF_TYPE_OPAQUE` + `T_ENUM_EMPTY`
            // exposure (`defined(bgp_pmsi_tunnel)` is the only
            // meaningful test). `true` when the attribute is on the
            // route (present, well-formed or malformed — the
            // physical presence probe); `false` when absent. Callers
            // that need the malformed distinction gate with
            // `defined(bgp.pmsi_tunnel)`, which consults
            // `has_pmsi_tunnel` (the same physical presence check),
            // not `pmsi_tunnel()` (which collapses "absent" and
            // "malformed" together).
            RouteFieldKind::BgpPmsiTunnel => Ok(Value::Bool(self.ctx.bgp_has_pmsi_tunnel(route))),
            // RFC 2328 §16 / RFC 5340 §4.1: `ospf.metric1` is the
            // primary OSPF metric, surfaced as an `Int` (`0` when
            // the route is not OSPF, mirroring BIRD's eattr default
            // for an unattached `ospf_metric1` reference). Callers
            // that need to distinguish "non-OSPF route" from "OSPF
            // route with metric 0" gate with `defined(ospf.metric1)`
            // — the predicate consults `has_metric1` (the protocol
            // is OSPF), not `metric1().is_some()` (which collapses
            // the two cases via the `0` read). Cheaper than any
            // `bgp_*` accessor: one `match` on `route.protocol` plus
            // one field read, no BTreeMap lookup, no allocation.
            RouteFieldKind::OspfMetric1 => {
                Ok(Value::Int(self.ctx.ospf_metric1(route).unwrap_or(0) as i64))
            }
            // RFC 2328 §16.4 / RFC 5340 §4.8.5: `ospf.metric2` is the
            // type-2 external OSPF metric, surfaced as an `Int` (`0`
            // when the route is not a type-2 external, mirroring
            // BIRD's eattr default for an unattached `ospf_metric2`
            // reference — non-OSPF routes, OSPF intra-area /
            // inter-area routes, and OSPF type-1 external routes all
            // read as `0`). Callers that need to distinguish "not a
            // type-2 external" from "type-2 external with metric 0"
            // gate with `defined(ospf.metric2)` — the predicate
            // consults `has_metric2` (the `LrOspfMetric2` attribute
            // is present), not `metric2().is_some()` (which
            // collapses "absent" and "malformed" together via the
            // `None` read). One BTreeMap lookup plus one 4-byte
            // read on the route's `attributes` bag — cheaper than
            // any `bgp_*` accessor that decodes a multi-byte TLV
            // stream, more expensive than `ospf.metric1` (which
            // reads a struct field, no lookup).
            RouteFieldKind::OspfMetric2 => {
                Ok(Value::Int(self.ctx.ospf_metric2(route).unwrap_or(0) as i64))
            }
            // RFC 2328 §A.4.5 bullet h / RFC 3101 §2.3 / RFC 5340
            // §A.4.7 T bit / RFC 8362 §3.6 External-Prefix sub-TLV 3:
            // `ospf.tag` is the route's external route tag, surfaced
            // as an `Int` (`0` when the route carries no tag,
            // mirroring BIRD's eattr default for an unattached
            // `ospf_tag` reference — non-OSPF routes, OSPF
            // intra-area / inter-area routes, and v3 externals
            // without the T bit all read as `0`). Callers that need
            // to distinguish "no tag" from "tag of zero" gate with
            // `defined(ospf.tag)` — the predicate consults
            // `has_tag` (the route is an OSPF external with a
            // non-`None` `Route::tag`), not `tag().is_some()` (the
            // two agree, but `has_tag` spells the contract). One
            // `match` on `route.protocol` plus one `Option<u32>`
            // field read off `route.tag` — cheaper than
            // `ospf.metric2` (which pays a BTreeMap lookup plus a
            // 4-byte read) and the same shape as `ospf.metric1`
            // (which reads a struct field, no lookup). The v2 form
            // always surfaces `Some(t)` (the v2 LSA body always
            // carries a 4-byte tag, zero being well-formed), so a
            // v2 external reads as `0` for `ospf.tag == 0` and
            // `defined(ospf.tag)` is true; the v3 form surfaces
            // `Some(t)` only when the T bit / sub-TLV is present.
            RouteFieldKind::OspfTag => Ok(Value::Int(self.ctx.ospf_tag(route).unwrap_or(0) as i64)),
            // RFC 2328 §A.4 `Advertising Router` field / RFC 5340
            // §A.4 the same field on every v3 LSA: `ospf.router_id`
            // is the route's OSPF advertising-router ID, surfaced
            // as an `Int` (`0` when the route carries no OSPF
            // router-id attribute — a non-OSPF route, or an OSPF
            // route whose computation could not identify the
            // originating LSA's advertising router — mirroring
            // BIRD's eattr default for an unattached
            // `ospf_router_id` reference). Callers that need to
            // distinguish "no attribute" from "attribute present
            // but zero" gate with `defined(ospf.router_id)` — the
            // predicate consults `has_router_id` (the route is an
            // OSPF route with the LrOspfRouterId attribute
            // physically present), not `router_id().is_some()`
            // (which collapses "absent" and "malformed" together
            // via the `None` read). One BTreeMap lookup plus one
            // 4-byte read on `route.attributes` — the same shape
            // as `ospf.metric2` (which reads a different private
            // tag), cheaper than any `bgp_*` accessor that
            // decodes a multi-byte TLV stream, more expensive
            // than `ospf.metric1` / `ospf.tag` (which read struct
            // fields, no lookup). RFC 2328 §3.1.b recommends a
            // non-zero Router-ID but does not forbid 0.0.0.0, so
            // an OSPF route with Router-ID 0.0.0.0 reads as `0`
            // and `defined(ospf.router_id)` is true.
            RouteFieldKind::OspfRouterId => Ok(Value::Int(
                self.ctx.ospf_router_id(route).unwrap_or(0) as i64,
            )),
            // Issue #81 — LRXP exchange-plane surface. The two bare
            // predicates read as `Bool`; the per-record fields read
            // as `Int` (ints default to 0) or `Str` (digests default
            // to empty string). The fallback (no LRXP attribute) is
            // built into the accessors — a non-LRXP peer's route
            // reads as `false` / `0` / `""` so a filter that adjusts
            // `local-pref` based on `bgp.lrxp.hint.rank` no-ops.
            #[cfg(feature = "exchange-plane")]
            RouteFieldKind::LrxpVerified => Ok(Value::Bool(self.ctx.lrxp_verified(route))),
            #[cfg(feature = "exchange-plane")]
            RouteFieldKind::LrxpPartialTransit => {
                Ok(Value::Bool(self.ctx.lrxp_partial_transit(route)))
            }
            #[cfg(feature = "exchange-plane")]
            RouteFieldKind::LrxpHintRank => {
                Ok(Value::Int(i64::from(self.ctx.lrxp_hint_rank(route))))
            }
            #[cfg(feature = "exchange-plane")]
            RouteFieldKind::LrxpHintDampFom => {
                Ok(Value::Int(i64::from(self.ctx.lrxp_hint_damp_fom(route))))
            }
            #[cfg(feature = "exchange-plane")]
            RouteFieldKind::LrxpHintIgpCost => {
                Ok(Value::Int(i64::from(self.ctx.lrxp_hint_igp_cost(route))))
            }
            #[cfg(feature = "exchange-plane")]
            RouteFieldKind::LrxpPolicyRole => {
                Ok(Value::Int(i64::from(self.ctx.lrxp_policy_role(route))))
            }
            #[cfg(feature = "exchange-plane")]
            RouteFieldKind::LrxpPolicyImportDigest => {
                Ok(Value::Str(self.ctx.lrxp_policy_import_digest_hex(route)))
            }
            #[cfg(feature = "exchange-plane")]
            RouteFieldKind::LrxpPolicyExportDigest => {
                Ok(Value::Str(self.ctx.lrxp_policy_export_digest_hex(route)))
            }
            #[cfg(feature = "exchange-plane")]
            RouteFieldKind::LrxpOriginAs => {
                Ok(Value::Int(i64::from(self.ctx.lrxp_origin_as(route))))
            }
            #[cfg(feature = "exchange-plane")]
            RouteFieldKind::LrxpOriginMaxValidLen => Ok(Value::Int(i64::from(
                self.ctx.lrxp_origin_max_valid_len(route),
            ))),
            #[cfg(feature = "exchange-plane")]
            RouteFieldKind::LrxpOriginExpiry => {
                Ok(Value::Int(i64::from(self.ctx.lrxp_origin_expiry(route))))
            }
            RouteFieldKind::RoaState => Ok(Value::RoaState(self.ctx.roa_state(route))),
            // Feature-less build: the LRXP variants are unreachable
            // (the parser rejects `bgp.lrxp.*` with
            // `UnknownBgpField`). The wildcard keeps the match
            // exhaustive over the full variant set without pulling
            // the codec into a feature-less build. Placed last so
            // the explicit `RoaState` arm above stays reachable on
            // both feature configurations.
            #[cfg(not(feature = "exchange-plane"))]
            _ => Ok(Value::Bool(false)),
        }
    }

    /// Read an integer-typed route field directly as an `i64`,
    /// skipping the `Value::Int` construction. Used by the fused
    /// `Instr::BranchFieldIntCmp` (GitHub #19 P6) to avoid the
    /// 32-byte `Value` allocation + `Vec::push` the unfused
    /// `LoadField; Push; Bin; JumpIf*` sequence pays. Only the
    /// six integer kinds (`Source`, `BgpLocalPref`, `BgpMed`,
    /// `BgpOrigin`, `BgpOtc`, `OspfMetric1`) reach this path — the
    /// peephole pass's `is_int_field` gate guarantees it. The LRXP
    /// int-typed fields (`bgp.lrxp.hint.rank`, etc.) are deliberately
    /// NOT in `is_int_field`: their read decodes a TLV stream (not a
    /// single `get_u32_be`), so fusing would not save the allocation the
    /// fast path exists to avoid. `bgp.aigp` (RFC 7311) is also
    /// deliberately NOT fused for the same reason — its read parses
    /// the AIGP attribute's TLV stream. The `unwrap_or(0)` semantics
    /// for absent attributes mirror `read_route_field` exactly so the
    /// fused and unfused paths agree for every route.
    fn read_int_route_field(&self, field: &RouteField, route: &Route) -> Result<i64, EvalError> {
        Ok(match field.kind {
            RouteFieldKind::Source => i64::from(route.origin.proto),
            RouteFieldKind::BgpLocalPref => self.ctx.bgp_local_pref(route).unwrap_or(0) as i64,
            RouteFieldKind::BgpMed => self.ctx.bgp_med(route).unwrap_or(0) as i64,
            RouteFieldKind::BgpOrigin => i64::from(self.ctx.bgp_origin(route).unwrap_or(0)),
            RouteFieldKind::BgpOtc => self.ctx.bgp_otc(route).unwrap_or(0) as i64,
            // `ospf.metric1` reads `route.preference.metric` for OSPF
            // routes and 0 for non-OSPF routes — a single `match` on
            // `route.protocol` plus one field read, no BTreeMap lookup,
            // no allocation. The fast path pays the same `match` the
            // unfused `read_route_field` path pays, but skips the
            // `Value::Int` construction + `Vec::push` on the
            // comparison-branch hot path.
            RouteFieldKind::OspfMetric1 => self.ctx.ospf_metric1(route).unwrap_or(0) as i64,
            // `ospf.metric2` reads the private `LrOspfMetric2`
            // path-attribute tag the OSPF route computation attaches to
            // type-2 external routes — one BTreeMap lookup plus one
            // 4-byte read on `route.attributes`, no allocation. The
            // fast path pays the same lookup the unfused
            // `read_route_field` path pays, but skips the
            // `Value::Int` construction + `Vec::push` on the
            // comparison-branch hot path. Cheaper than any `bgp_*`
            // accessor that decodes a multi-byte TLV stream (the
            // peephole pass refuses to fuse those, so they fall
            // through to the unreachable arm).
            RouteFieldKind::OspfMetric2 => self.ctx.ospf_metric2(route).unwrap_or(0) as i64,
            // `ospf.tag` reads `route.tag` for OSPF routes and 0
            // for non-OSPF routes — a single `match` on
            // `route.protocol` plus one `Option<u32>` field read,
            // no BTreeMap lookup, no allocation. The fast path
            // pays the same `match` the unfused `read_route_field`
            // path pays, but skips the `Value::Int` construction +
            // `Vec::push` on the comparison-branch hot path. The
            // v2 form always surfaces `Some(t)` (the v2 LSA body
            // always carries a 4-byte tag, zero being well-formed);
            // the v3 form surfaces `Some(t)` only when the T bit /
            // sub-TLV is present.
            RouteFieldKind::OspfTag => self.ctx.ospf_tag(route).unwrap_or(0) as i64,
            // `ospf.router_id` reads the private `LrOspfRouterId`
            // path-attribute tag the OSPF route computation
            // attaches to every OSPFv2 / OSPFv3 route with a known
            // originating LSA — one BTreeMap lookup plus one
            // 4-byte read on `route.attributes`, no allocation.
            // The fast path pays the same lookup the unfused
            // `read_route_field` path pays, but skips the
            // `Value::Int` construction + `Vec::push` on the
            // comparison-branch hot path. The same shape as
            // `ospf.metric2` (which reads a different private tag),
            // cheaper than any `bgp_*` accessor that decodes a
            // multi-byte TLV stream. RFC 2328 §3.1.b recommends a
            // non-zero Router-ID but does not forbid 0.0.0.0, so
            // an OSPF route with Router-ID 0.0.0.0 reads as `0`
            // and `defined(ospf.router_id)` is true.
            RouteFieldKind::OspfRouterId => self.ctx.ospf_router_id(route).unwrap_or(0) as i64,
            // The peephole pass's `is_int_field` gate guarantees
            // one of the arms above; the LRXP int-typed fields
            // and `bgp.aigp` fall through to the unreachable arm
            // (the gate refuses to fuse them) and run the unfused
            // `read_route_field` path instead.
            _ => unreachable!("peephole is_int_field gates this"),
        })
    }

    fn assign_route_field(
        &self,
        field: &RouteField,
        value: Value,
        route: &mut Route,
        span: Span,
    ) -> Result<(), EvalError> {
        match field.kind {
            RouteFieldKind::BgpLocalPref => {
                let n = as_int(&value)
                    .ok_or_else(|| type_mismatch("=", &value, "int", span, self.line_index))?;
                if !(0..=u32::MAX as i64).contains(&n) {
                    return Err(self.err(span, EvalErrorKind::AsnOutOfRange(n)));
                }
                self.ctx.set_bgp_local_pref(route, n as u32);
            }
            RouteFieldKind::BgpMed => {
                let n = as_int(&value)
                    .ok_or_else(|| type_mismatch("=", &value, "int", span, self.line_index))?;
                if !(0..=u32::MAX as i64).contains(&n) {
                    return Err(self.err(span, EvalErrorKind::AsnOutOfRange(n)));
                }
                self.ctx.set_bgp_med(route, n as u32);
            }
            RouteFieldKind::BgpNextHop => {
                let ip = match value {
                    Value::Ip(ip) => ip,
                    other => return Err(type_mismatch("=", &other, "ip", span, self.line_index)),
                };
                self.ctx.set_bgp_next_hop(route, ip);
            }
            // `bgp.communities = <set>` — the canonical BIRD idiom
            // (`bgp.community = delete(bgp.community, [65000:1]);`).
            RouteFieldKind::BgpCommunities => {
                let cs = self.communities_from_value(&value, "=", span)?;
                self.ctx.set_bgp_communities(route, cs);
            }
            // `bgp.large_communities = <set>` (RFC 8092).
            RouteFieldKind::BgpLargeCommunities => {
                let cs = self.large_communities_from_value(&value, "=", span)?;
                self.ctx.set_bgp_large_communities(route, cs);
            }
            // `bgp.ext_communities = <set>` (RFC 4360).
            RouteFieldKind::BgpExtCommunities => {
                let cs = self.ext_communities_from_value(&value, "=", span)?;
                self.ctx.set_bgp_ext_communities(route, cs);
            }
            // `bgp.as_path = <sequence>` — BIRD assigns `bgp_path`
            // values the same way.
            RouteFieldKind::BgpAsPath => {
                let seq = match value {
                    Value::AsPath(p) => p,
                    other => {
                        return Err(type_mismatch("=", &other, "as-path", span, self.line_index))
                    }
                };
                self.ctx.set_bgp_as_path(route, seq);
            }
            other => {
                return Err(self.err(
                    span,
                    EvalErrorKind::UnknownMethod {
                        field: other.to_string(),
                        method: "=".to_string(),
                    },
                ));
            }
        }
        Ok(())
    }

    /// Normalize a community-set RHS: a bare `Communities` value, a
    /// set literal (`CommPattern` items — wildcards are rejected,
    /// nothing concrete to write) or a single pattern element.
    fn communities_from_value(
        &self,
        value: &Value,
        op: &str,
        span: Span,
    ) -> Result<Vec<(Asn, u16)>, EvalError> {
        let mut out = Vec::new();
        let mut push_item = |it: &Value| -> Result<(), EvalError> {
            match it {
                Value::Communities(cs) => out.extend(cs.iter().map(|(a, v)| (*a, *v))),
                Value::CommPattern {
                    asn: Some(a),
                    val: Some(v),
                } => out.push((Asn(*a), *v)),
                Value::CommPattern { .. } => {
                    return Err(self.err(
                        span,
                        EvalErrorKind::TypeMismatch {
                            op: op.to_string(),
                            lhs: "community-set".to_string(),
                            rhs: "community-pattern wildcard".to_string(),
                        },
                    ));
                }
                other => {
                    return Err(type_mismatch(
                        op,
                        other,
                        "community-set",
                        span,
                        self.line_index,
                    ))
                }
            }
            Ok(())
        };
        match value {
            Value::Set(items) => {
                for it in items {
                    push_item(it)?;
                }
            }
            other => push_item(other)?,
        }
        Ok(out)
    }

    /// Normalize a large-community-set RHS (RFC 8092): a bare
    /// `LargeCommunities` value, a set literal of triples, or one
    /// triple.
    fn large_communities_from_value(
        &self,
        value: &Value,
        op: &str,
        span: Span,
    ) -> Result<Vec<(u32, u32, u32)>, EvalError> {
        let mut out = Vec::new();
        let mut push_item = |it: &Value| -> Result<(), EvalError> {
            match it {
                Value::LargeCommunities(cs) => out.extend(cs.iter().copied()),
                other => {
                    return Err(type_mismatch(
                        op,
                        other,
                        "large-community-set",
                        span,
                        self.line_index,
                    ))
                }
            }
            Ok(())
        };
        match value {
            Value::Set(items) => {
                for it in items {
                    push_item(it)?;
                }
            }
            other => push_item(other)?,
        }
        Ok(out)
    }

    /// Normalize an extended-community-set RHS (RFC 4360): a bare
    /// `ExtCommunities` value, a set literal of tuples, or one tuple.
    fn ext_communities_from_value(
        &self,
        value: &Value,
        op: &str,
        span: Span,
    ) -> Result<Vec<(u8, u8, u32, u16)>, EvalError> {
        let mut out = Vec::new();
        let mut push_item = |it: &Value| -> Result<(), EvalError> {
            match it {
                Value::ExtCommunities(cs) => out.extend(cs.iter().copied()),
                other => {
                    return Err(type_mismatch(
                        op,
                        other,
                        "ext-community-set",
                        span,
                        self.line_index,
                    ))
                }
            }
            Ok(())
        };
        match value {
            Value::Set(items) => {
                for it in items {
                    push_item(it)?;
                }
            }
            other => push_item(other)?,
        }
        Ok(out)
    }

    fn append_route_field(
        &self,
        field: &RouteField,
        value: Value,
        route: &mut Route,
        span: Span,
    ) -> Result<(), EvalError> {
        match field.kind {
            RouteFieldKind::BgpCommunities => {
                let cs: Vec<(Asn, u16)> = match value {
                    Value::Communities(cs) => cs,
                    Value::Set(items) => {
                        let mut out = Vec::new();
                        for it in items {
                            match it {
                                Value::Communities(c) => out.extend(c),
                                Value::CommPattern {
                                    asn: Some(a),
                                    val: Some(v),
                                } => out.push((Asn(a), v)),
                                Value::CommPattern { .. } => {
                                    return Err(self.err(
                                        span,
                                        EvalErrorKind::TypeMismatch {
                                            op: "+=".to_string(),
                                            lhs: "community-set".to_string(),
                                            rhs: "community-pattern wildcard".to_string(),
                                        },
                                    ));
                                }
                                Value::Int(n) => {
                                    if !(0..=u16::MAX as i64).contains(&n) {
                                        return Err(self.err(
                                            span,
                                            EvalErrorKind::CommunityOutOfRange { asn: n, val: 0 },
                                        ));
                                    }
                                    out.push((Asn(n as u32), 0));
                                }
                                other => {
                                    return Err(type_mismatch(
                                        "+=",
                                        &other,
                                        "community-set",
                                        span,
                                        self.line_index,
                                    ))
                                }
                            }
                        }
                        out
                    }
                    other => {
                        return Err(type_mismatch(
                            "+=",
                            &other,
                            "community-set",
                            span,
                            self.line_index,
                        ))
                    }
                };
                for (asn, val) in cs {
                    self.ctx.bgp_communities_add(route, asn, val);
                }
            }
            RouteFieldKind::BgpLargeCommunities => {
                let cs = self.large_communities_from_value(&value, "+=", span)?;
                let mut cur = self.ctx.bgp_large_communities(route);
                for c in cs {
                    if !cur.contains(&c) {
                        cur.push(c);
                    }
                }
                self.ctx.set_bgp_large_communities(route, cur);
            }
            RouteFieldKind::BgpExtCommunities => {
                let cs = self.ext_communities_from_value(&value, "+=", span)?;
                let mut cur = self.ctx.bgp_ext_communities(route);
                for c in cs {
                    if !cur.contains(&c) {
                        cur.push(c);
                    }
                }
                self.ctx.set_bgp_ext_communities(route, cur);
            }
            other => {
                return Err(self.err(
                    span,
                    EvalErrorKind::UnknownMethod {
                        field: other.to_string(),
                        method: "+=".to_string(),
                    },
                ));
            }
        }
        Ok(())
    }

    fn eval_call(
        &mut self,
        name: &str,
        args: &[Value],
        route: &mut Route,
        span: Span,
    ) -> Result<Value, EvalError> {
        // D3.1: user-defined functions shadow nothing (the parser
        // rejects shadowing a built-in), so look the name up first
        // and fall through to the built-ins otherwise.
        if let Some(f) = self.functions.get(name).cloned() {
            return self.call_user_function(&f, args, route, span);
        }
        match name {
            "len" => {
                if args.len() != 1 {
                    return Err(bad_arg_count("len", 1, args.len(), span, self.line_index));
                }
                match &args[0] {
                    Value::AsPath(p) => Ok(Value::Int(p.len() as i64)),
                    Value::Communities(c) => Ok(Value::Int(c.len() as i64)),
                    Value::LargeCommunities(c) => Ok(Value::Int(c.len() as i64)),
                    Value::ExtCommunities(c) => Ok(Value::Int(c.len() as i64)),
                    Value::Str(s) => Ok(Value::Int(s.len() as i64)),
                    other => Err(type_mismatch(
                        "len",
                        other,
                        "as-path|community-set|string",
                        span,
                        self.line_index,
                    )),
                }
            }
            // D3.4 — BIRD set operations (filter/config.Y `f_pair`
            // delete/filter + set introspection).
            "delete" | "filter" => {
                if args.len() != 2 {
                    return Err(bad_arg_count(name, 2, args.len(), span, self.line_index));
                }
                apply_set_op(
                    name,
                    &args[0],
                    &args[1],
                    name == "filter",
                    span,
                    self.line_index,
                )
            }
            "empty" => {
                if args.len() != 1 {
                    return Err(bad_arg_count("empty", 1, args.len(), span, self.line_index));
                }
                match &args[0] {
                    Value::AsPath(p) => Ok(Value::Bool(p.is_empty())),
                    Value::Communities(c) => Ok(Value::Bool(c.is_empty())),
                    Value::LargeCommunities(c) => Ok(Value::Bool(c.is_empty())),
                    Value::ExtCommunities(c) => Ok(Value::Bool(c.is_empty())),
                    Value::Set(s) => Ok(Value::Bool(s.is_empty())),
                    Value::Str(s) => Ok(Value::Bool(s.is_empty())),
                    other => Err(type_mismatch(
                        "empty",
                        other,
                        "set-like",
                        span,
                        self.line_index,
                    )),
                }
            }
            "count" => {
                if args.len() != 1 {
                    return Err(bad_arg_count("count", 1, args.len(), span, self.line_index));
                }
                match &args[0] {
                    Value::AsPath(p) => Ok(Value::Int(p.len() as i64)),
                    Value::Communities(c) => Ok(Value::Int(c.len() as i64)),
                    Value::LargeCommunities(c) => Ok(Value::Int(c.len() as i64)),
                    Value::ExtCommunities(c) => Ok(Value::Int(c.len() as i64)),
                    Value::Set(s) => Ok(Value::Int(s.len() as i64)),
                    other => Err(type_mismatch(
                        "count",
                        other,
                        "set-like",
                        span,
                        self.line_index,
                    )),
                }
            }
            "first" => {
                if args.len() != 1 {
                    return Err(bad_arg_count("first", 1, args.len(), span, self.line_index));
                }
                match &args[0] {
                    Value::AsPath(p) => Ok(p
                        .first()
                        .map(|a| Value::Asn(*a))
                        .unwrap_or(Value::Bool(false))),
                    other => Err(type_mismatch(
                        "first",
                        other,
                        "as-path",
                        span,
                        self.line_index,
                    )),
                }
            }
            "last" => {
                if args.len() != 1 {
                    return Err(bad_arg_count("last", 1, args.len(), span, self.line_index));
                }
                match &args[0] {
                    Value::AsPath(p) => Ok(p
                        .last()
                        .map(|a| Value::Asn(*a))
                        .unwrap_or(Value::Bool(false))),
                    other => Err(type_mismatch(
                        "last",
                        other,
                        "as-path",
                        span,
                        self.line_index,
                    )),
                }
            }
            other => Err(self.err(span, EvalErrorKind::UnknownFunction(other.to_string()))),
        }
    }

    /// D3.1: bind arguments to formal parameters in a fresh scope
    /// frame and execute the body until `return` (or the end of the
    /// body — both yield `false` when no value is produced).
    ///
    /// The body runs against the caller's route (BIRD parity:
    /// functions are the primary way to structure route mutation).
    /// `accept` / `reject` inside a function body terminate the whole
    /// filter (BIRD `filter/config.Y` `f_cmd` semantics) — they latch
    /// a pending verdict on the evaluator, which the top-level loop
    /// consumes after the current statement.
    fn call_user_function(
        &mut self,
        f: &FunctionDecl,
        args: &[Value],
        route: &mut Route,
        span: Span,
    ) -> Result<Value, EvalError> {
        if self.call_depth >= MAX_CALL_DEPTH {
            return Err(self.err(span, EvalErrorKind::CallDepthExceeded(MAX_CALL_DEPTH)));
        }
        if args.len() != f.params.len() {
            return Err(self.err(
                span,
                EvalErrorKind::BadArgCount {
                    name: f.name.clone(),
                    expected: f.params.len(),
                    got: args.len(),
                },
            ));
        }
        self.call_depth += 1;
        self.push_scope();
        for (param, arg) in f.params.iter().zip(args.iter()) {
            self.scopes
                .last_mut()
                .unwrap()
                .vars
                .insert(param.clone(), arg.clone());
        }
        let mut outcome = Ok(Value::Bool(false));
        for stmt in &f.body.stmts {
            match self.eval_stmt(stmt, route) {
                Ok(ControlFlow::Continue) => {}
                Ok(ControlFlow::Return(v)) => {
                    outcome = Ok(v.unwrap_or(Value::Bool(false)));
                    break;
                }
                // BIRD: accept / reject inside a function terminate
                // the enclosing filter, even mid-expression. Latch
                // the verdict; the caller finishes for value purposes.
                Ok(ControlFlow::Accept) => {
                    self.pending_verdict = Some(ControlFlow::Accept);
                    outcome = Ok(Value::Bool(true));
                    break;
                }
                Ok(ControlFlow::Reject(reason)) => {
                    self.pending_verdict = Some(ControlFlow::Reject(reason));
                    outcome = Ok(Value::Bool(false));
                    break;
                }
                Err(e) => {
                    outcome = Err(e);
                    break;
                }
            }
        }
        self.pop_scope();
        self.call_depth -= 1;
        outcome
    }

    fn eval_method(
        &self,
        field: &RouteField,
        method: &str,
        args: &[Value],
        route: &mut Route,
        span: Span,
    ) -> Result<Value, EvalError> {
        match (field.kind, method) {
            (RouteFieldKind::BgpAsPath, "prepend") => {
                if args.len() != 1 {
                    return Err(bad_arg_count(
                        "bgp.as_path.prepend",
                        1,
                        args.len(),
                        span,
                        self.line_index,
                    ));
                }
                let n = as_int(&args[0]).ok_or_else(|| {
                    type_mismatch("prepend", &args[0], "int", span, self.line_index)
                })?;
                if !(0..=u32::MAX as i64).contains(&n) {
                    return Err(self.err(span, EvalErrorKind::AsnOutOfRange(n)));
                }
                self.ctx.bgp_as_path_prepend(route, Asn(n as u32));
                Ok(Value::AsPath(self.ctx.bgp_as_path(route)))
            }
            (RouteFieldKind::BgpCommunities, "add") => {
                if args.len() != 1 {
                    return Err(bad_arg_count(
                        "bgp.communities.add",
                        1,
                        args.len(),
                        span,
                        self.line_index,
                    ));
                }
                // Accept both a bare community-set value and a set
                // literal (whose items are CommPattern elements).
                let to_add: Vec<(Asn, u16)> = pattern_items(&args[0])
                    .into_iter()
                    .filter_map(|item| match item {
                        Value::Communities(cs) => {
                            Some(cs.iter().map(|(a, v)| (*a, *v)).collect::<Vec<_>>())
                        }
                        Value::CommPattern {
                            asn: Some(a),
                            val: Some(v),
                        } => Some(vec![(Asn(*a), *v)]),
                        Value::CommPattern { .. } => None,
                        _ => None,
                    })
                    .flatten()
                    .collect();
                if to_add.is_empty() && !matches!(args[0], Value::Communities(_) | Value::Set(_)) {
                    return Err(type_mismatch(
                        "bgp.communities.add",
                        &args[0],
                        "community-set",
                        span,
                        self.line_index,
                    ));
                }
                for (asn, val) in to_add {
                    self.ctx.bgp_communities_add(route, asn, val);
                }
                Ok(Value::Communities(self.ctx.bgp_communities(route)))
            }
            (RouteFieldKind::BgpCommunities, "delete" | "filter") => {
                if args.len() != 1 {
                    return Err(bad_arg_count(
                        "bgp.communities.delete",
                        1,
                        args.len(),
                        span,
                        self.line_index,
                    ));
                }
                let keep = method == "filter";
                let items = pattern_items(&args[0]);
                let cur = self.ctx.bgp_communities(route);
                let out: Vec<(Asn, u16)> = cur
                    .into_iter()
                    .filter(|e| {
                        let m = community_elem_matches(e, &items);
                        if keep {
                            m
                        } else {
                            !m
                        }
                    })
                    .collect();
                self.ctx.set_bgp_communities(route, out.clone());
                Ok(Value::Communities(out))
            }
            (RouteFieldKind::BgpAsPath, "delete" | "filter") => {
                if args.len() != 1 {
                    return Err(bad_arg_count(
                        "bgp.as_path.delete",
                        1,
                        args.len(),
                        span,
                        self.line_index,
                    ));
                }
                let keep = method == "filter";
                let items = pattern_items(&args[0]);
                let cur = self.ctx.bgp_as_path(route);
                let out: Vec<Asn> = cur
                    .into_iter()
                    .filter(|a| {
                        let m = as_path_elem_matches(a, &items);
                        if keep {
                            m
                        } else {
                            !m
                        }
                    })
                    .collect();
                self.ctx.set_bgp_as_path(route, out.clone());
                Ok(Value::AsPath(out))
            }
            (RouteFieldKind::BgpLargeCommunities, "add" | "delete" | "filter") => {
                if args.len() != 1 {
                    return Err(bad_arg_count(
                        "bgp.large_communities.add",
                        1,
                        args.len(),
                        span,
                        self.line_index,
                    ));
                }
                let items = self.large_communities_from_value(&args[0], method, span)?;
                let cur = self.ctx.bgp_large_communities(route);
                let out: Vec<(u32, u32, u32)> = match method {
                    "add" => {
                        let mut out = cur;
                        for c in items {
                            if !out.contains(&c) {
                                out.push(c);
                            }
                        }
                        out
                    }
                    "delete" => cur.into_iter().filter(|c| !items.contains(c)).collect(),
                    _ => cur.into_iter().filter(|c| items.contains(c)).collect(),
                };
                self.ctx.set_bgp_large_communities(route, out.clone());
                Ok(Value::LargeCommunities(out))
            }
            (RouteFieldKind::BgpExtCommunities, "add" | "delete" | "filter") => {
                if args.len() != 1 {
                    return Err(bad_arg_count(
                        "bgp.ext_communities.add",
                        1,
                        args.len(),
                        span,
                        self.line_index,
                    ));
                }
                let items = self.ext_communities_from_value(&args[0], method, span)?;
                let cur = self.ctx.bgp_ext_communities(route);
                let out: Vec<(u8, u8, u32, u16)> = match method {
                    "add" => {
                        let mut out = cur;
                        for c in items {
                            if !out.contains(&c) {
                                out.push(c);
                            }
                        }
                        out
                    }
                    "delete" => cur.into_iter().filter(|c| !items.contains(c)).collect(),
                    _ => cur.into_iter().filter(|c| items.contains(c)).collect(),
                };
                self.ctx.set_bgp_ext_communities(route, out.clone());
                Ok(Value::ExtCommunities(out))
            }
            (kind, m) => Err(self.err(
                span,
                EvalErrorKind::UnknownMethod {
                    field: kind.to_string(),
                    method: m.to_string(),
                },
            )),
        }
    }

    fn eval_binary(
        &self,
        op: BinaryOp,
        l: Value,
        r: Value,
        span: Span,
    ) -> Result<Value, EvalError> {
        match op {
            BinaryOp::Eq => Ok(Value::Bool(value_eq(&l, &r))),
            BinaryOp::Ne => Ok(Value::Bool(!value_eq(&l, &r))),
            BinaryOp::Lt | BinaryOp::Le | BinaryOp::Gt | BinaryOp::Ge => {
                let li = as_int(&l)
                    .ok_or_else(|| type_mismatch(op_name(op), &l, "int", span, self.line_index))?;
                let ri = as_int(&r)
                    .ok_or_else(|| type_mismatch(op_name(op), &r, "int", span, self.line_index))?;
                let b = match op {
                    BinaryOp::Lt => li < ri,
                    BinaryOp::Le => li <= ri,
                    BinaryOp::Gt => li > ri,
                    BinaryOp::Ge => li >= ri,
                    _ => unreachable!(),
                };
                Ok(Value::Bool(b))
            }
            BinaryOp::Add | BinaryOp::Sub | BinaryOp::Mul | BinaryOp::Div | BinaryOp::Mod => {
                let li = as_int(&l)
                    .ok_or_else(|| type_mismatch(op_name(op), &l, "int", span, self.line_index))?;
                let ri = as_int(&r)
                    .ok_or_else(|| type_mismatch(op_name(op), &r, "int", span, self.line_index))?;
                let v = match op {
                    BinaryOp::Add => li.checked_add(ri),
                    BinaryOp::Sub => li.checked_sub(ri),
                    BinaryOp::Mul => li.checked_mul(ri),
                    BinaryOp::Div => {
                        if ri == 0 {
                            return Err(self.err(span, EvalErrorKind::DivByZero));
                        }
                        li.checked_div(ri)
                    }
                    BinaryOp::Mod => {
                        if ri == 0 {
                            return Err(self.err(span, EvalErrorKind::DivByZero));
                        }
                        Some(li.checked_rem(ri).unwrap_or(0))
                    }
                    _ => unreachable!(),
                };
                v.map(Value::Int)
                    .ok_or_else(|| self.err(span, EvalErrorKind::Overflow))
            }
            BinaryOp::BitAnd | BinaryOp::BitOr | BinaryOp::BitXor => {
                let li = as_int(&l)
                    .ok_or_else(|| type_mismatch(op_name(op), &l, "int", span, self.line_index))?;
                let ri = as_int(&r)
                    .ok_or_else(|| type_mismatch(op_name(op), &r, "int", span, self.line_index))?;
                let v = match op {
                    BinaryOp::BitAnd => li & ri,
                    BinaryOp::BitOr => li | ri,
                    BinaryOp::BitXor => li ^ ri,
                    _ => unreachable!(),
                };
                Ok(Value::Int(v))
            }
            BinaryOp::Shl | BinaryOp::Shr => {
                let li = as_int(&l)
                    .ok_or_else(|| type_mismatch(op_name(op), &l, "int", span, self.line_index))?;
                let ri = as_int(&r)
                    .ok_or_else(|| type_mismatch(op_name(op), &r, "int", span, self.line_index))?;
                if !(0..=63).contains(&ri) {
                    return Err(self.err(span, EvalErrorKind::BadShift(ri)));
                }
                let v = match op {
                    BinaryOp::Shl => li << ri,
                    BinaryOp::Shr => li >> ri,
                    _ => unreachable!(),
                };
                Ok(Value::Int(v))
            }
            BinaryOp::And | BinaryOp::Or => {
                // Already short-circuited in eval_expr; this branch
                // only runs when the operands were already evaluated.
                Ok(Value::Bool(l.truthy() && r.truthy()))
            }
            BinaryOp::Match | BinaryOp::NotMatch => {
                let m = value_match(&l, &r);
                Ok(Value::Bool(if op == BinaryOp::Match { m } else { !m }))
            }
        }
    }
}

fn as_int(v: &Value) -> Option<i64> {
    match v {
        Value::Int(n) => Some(*n),
        Value::Bool(true) => Some(1),
        Value::Bool(false) => Some(0),
        _ => None,
    }
}

fn op_name(op: BinaryOp) -> &'static str {
    match op {
        BinaryOp::Add => "+",
        BinaryOp::Sub => "-",
        BinaryOp::Mul => "*",
        BinaryOp::Div => "/",
        BinaryOp::Mod => "%",
        BinaryOp::Eq => "==",
        BinaryOp::Ne => "!=",
        BinaryOp::Lt => "<",
        BinaryOp::Le => "<=",
        BinaryOp::Gt => ">",
        BinaryOp::Ge => ">=",
        BinaryOp::And => "&&",
        BinaryOp::Or => "||",
        BinaryOp::BitAnd => "&",
        BinaryOp::BitOr => "|",
        BinaryOp::BitXor => "^",
        BinaryOp::Shl => "<<",
        BinaryOp::Shr => ">>",
        BinaryOp::Match => "~",
        BinaryOp::NotMatch => "!~",
    }
}

fn type_mismatch(op: &str, v: &Value, expected: &str, span: Span, index: &LineIndex) -> EvalError {
    let (line, col) = index.line_col(span.start);
    EvalError {
        kind: EvalErrorKind::TypeMismatch {
            op: op.to_string(),
            lhs: v.type_name().to_string(),
            rhs: expected.to_string(),
        },
        span,
        line,
        col,
    }
}

fn bad_arg_count(
    name: &str,
    expected: usize,
    got: usize,
    span: Span,
    index: &LineIndex,
) -> EvalError {
    let (line, col) = index.line_col(span.start);
    EvalError {
        kind: EvalErrorKind::BadArgCount {
            name: name.to_string(),
            expected,
            got,
        },
        span,
        line,
        col,
    }
}

fn value_eq(a: &Value, b: &Value) -> bool {
    match (a, b) {
        (Value::Int(x), Value::Int(y)) => x == y,
        (Value::Bool(x), Value::Bool(y)) => x == y,
        (Value::Str(x), Value::Str(y)) => x == y,
        (Value::Ip(x), Value::Ip(y)) => x == y,
        (Value::Prefix(x), Value::Prefix(y)) => x == y,
        (Value::Asn(x), Value::Asn(y)) => x == y,
        (Value::AsPath(x), Value::AsPath(y)) => x == y,
        (Value::Communities(x), Value::Communities(y)) => x == y,
        (Value::RoaState(x), Value::RoaState(y)) => x == y,
        // RoaState vs Str — `roa.state == "invalid"` form. The
        // string must match the RoaState's as_str() representation.
        (Value::RoaState(s), Value::Str(t)) => s.as_str() == t.as_str(),
        (Value::Str(t), Value::RoaState(s)) => s.as_str() == t.as_str(),
        (Value::Int(x), Value::Bool(y)) => (*x != 0) == *y,
        (Value::Bool(x), Value::Int(y)) => *x == (*y != 0),
        (Value::Set(x), Value::Set(y)) => {
            x.len() == y.len() && x.iter().zip(y.iter()).all(|(a, b)| value_eq(a, b))
        }
        _ => false,
    }
}

/// Membership test — `~` operator. Supports:
/// - prefix `~` prefix-set (covers route's `net`)
/// - as-path `~` asn literal (any AS in path)
/// - community-set `~` community literal (any community in route)
/// - string `~` string (equality)
fn value_match(l: &Value, r: &Value) -> bool {
    match (l, r) {
        (Value::Prefix(p), Value::Prefix(set)) => set.contains_prefix(p),
        (Value::AsPath(path), Value::Int(n)) => path.iter().any(|a| a.0 as i64 == *n),
        (Value::AsPath(path), Value::Asn(a)) => path.iter().any(|x| x == a),
        (Value::AsPath(path), Value::Communities(cs)) => {
            cs.iter().any(|(a, _)| path.iter().any(|x| x == a))
        }
        (Value::Communities(route_cs), Value::Communities(set_cs)) => {
            set_cs.iter().any(|c| route_cs.contains(c))
        }
        // Wildcard-aware community pattern (D3.4): `[ 65000:*, *:1 ]`.
        (Value::Communities(route_cs), Value::CommPattern { asn, val }) => route_cs
            .iter()
            .any(|(a, v)| asn.is_none_or(|p| p == a.0) && val.is_none_or(|p| p == *v)),
        // RFC 8092 large communities: exact triple membership.
        (Value::LargeCommunities(route_cs), Value::LargeCommunities(set_cs)) => {
            set_cs.iter().any(|c| route_cs.contains(c))
        }
        // RFC 4360 extended communities: exact record membership.
        (Value::ExtCommunities(route_cs), Value::ExtCommunities(set_cs)) => {
            set_cs.iter().any(|c| route_cs.contains(c))
        }
        (Value::RoaState(s), Value::Str(t)) => s.as_str() == t.as_str(),
        (Value::Str(a), Value::Str(b)) => a == b,
        (Value::Ip(a), Value::Ip(b)) => a == b,
        // Set membership — walk the items.
        (l, Value::Set(items)) => items.iter().any(|i| value_match(l, i)),
        _ => false,
    }
}

/// Flatten a set-pattern value into its items — a bare item is a
/// single-item pattern (`delete(c, 65000:1)` works like BIRD).
fn pattern_items(pat: &Value) -> Vec<&Value> {
    match pat {
        Value::Set(items) => items.iter().collect(),
        other => vec![other],
    }
}

/// D3.4 element matching for community `delete` / `filter`: a pattern
/// item matches when both components match-or-wildcard
/// (`65000:*` matches every value of AS 65000; `*:100` every ASN
/// carrying value 100; `65000:1` is the exact form).
fn community_elem_matches(elem: &(Asn, u16), items: &[&Value]) -> bool {
    items.iter().any(|p| match p {
        Value::CommPattern { asn, val } => {
            asn.is_none_or(|a| a == elem.0 .0) && val.is_none_or(|v| v == elem.1)
        }
        Value::Communities(cs) => cs.iter().any(|(a, v)| *a == elem.0 && *v == elem.1),
        _ => false,
    })
}

/// D3.4 element matching for AS-path `delete` / `filter`: pattern
/// items are AS numbers (`[ 65001, 65002 ]`).
fn as_path_elem_matches(asn: &Asn, items: &[&Value]) -> bool {
    items.iter().any(|p| match p {
        Value::Int(n) => *n == asn.0 as i64,
        Value::Asn(a) => a == asn,
        Value::Communities(cs) => cs.iter().any(|(a, _)| a == asn),
        _ => false,
    })
}

/// Value-level BIRD set operation (D3.4): remove (`delete`) or keep
/// (`filter`) the elements of `coll` matching the pattern. Works on
/// community sets, AS-paths and generic sets.
fn apply_set_op(
    op: &str,
    coll: &Value,
    pat: &Value,
    keep_matching: bool,
    span: Span,
    index: &LineIndex,
) -> Result<Value, EvalError> {
    let items = pattern_items(pat);
    match coll {
        Value::Communities(cs) => {
            let out: Vec<(Asn, u16)> = cs
                .iter()
                .filter(|e| {
                    let m = community_elem_matches(e, &items);
                    if keep_matching {
                        m
                    } else {
                        !m
                    }
                })
                .copied()
                .collect();
            Ok(Value::Communities(out))
        }
        Value::AsPath(p) => {
            let out: Vec<Asn> = p
                .iter()
                .filter(|a| {
                    let m = as_path_elem_matches(a, &items);
                    if keep_matching {
                        m
                    } else {
                        !m
                    }
                })
                .copied()
                .collect();
            Ok(Value::AsPath(out))
        }
        Value::Set(s) => {
            let out: Vec<Value> = s
                .iter()
                .filter(|e| {
                    let m = items.iter().any(|p| value_eq(e, p));
                    if keep_matching {
                        m
                    } else {
                        !m
                    }
                })
                .cloned()
                .collect();
            Ok(Value::Set(out))
        }
        Value::LargeCommunities(cs) => {
            let out: Vec<(u32, u32, u32)> = cs
                .iter()
                .filter(|c| {
                    let m = items.iter().any(|p| match p {
                        Value::LargeCommunities(s) => s.contains(c),
                        _ => false,
                    });
                    if keep_matching {
                        m
                    } else {
                        !m
                    }
                })
                .copied()
                .collect();
            Ok(Value::LargeCommunities(out))
        }
        Value::ExtCommunities(cs) => {
            let out: Vec<(u8, u8, u32, u16)> = cs
                .iter()
                .filter(|c| {
                    let m = items.iter().any(|p| match p {
                        Value::ExtCommunities(s) => s.contains(c),
                        _ => false,
                    });
                    if keep_matching {
                        m
                    } else {
                        !m
                    }
                })
                .copied()
                .collect();
            Ok(Value::ExtCommunities(out))
        }
        other => Err(type_mismatch(
            op,
            other,
            "community-set|as-path|set",
            span,
            index,
        )),
    }
}

/// BIRD-style prefix-set membership: `prefix{ge,le}` matches `p`
/// when `prefix` covers `p` (same family, network bits match) AND
/// `p.prefix_len` falls in the inclusive range
/// `[max(prefix.prefix_len, ge), le]`.
fn prefix_set_matches(
    set: &lr_core::addr::Prefix,
    ge: Option<u8>,
    le: Option<u8>,
    p: &lr_core::addr::Prefix,
) -> bool {
    if !set.contains_prefix(p) {
        return false;
    }
    let pl = p.prefix_len;
    let family_max = if set.is_ipv4() { 32 } else { 128 };
    let lo = ge.unwrap_or(set.prefix_len).max(set.prefix_len);
    let hi = le.unwrap_or(family_max);
    pl >= lo && pl <= hi
}

/// Execute a compiled filter (ROADMAP-v3 D3.7). Semantically
/// identical to [`evaluate`] — the two engines share the scope
/// stack, user-function bookkeeping and matching helpers — but runs
/// a flat instruction loop with pre-lifted constants instead of
/// re-walking the AST per route.
pub fn execute(cf: &CompiledFilter, route: &mut Route, ctx: &dyn FilterContext) -> EvalResult {
    let mut ev = Evaluator {
        ctx,
        scopes: vec![Scope::new()],
        functions: std::collections::BTreeMap::new(),
        call_depth: 0,
        pending_verdict: None,
        line_index: &cf.line_index,
    };
    match ev.run_code(&cf.code, &cf.spans, cf, route) {
        Ok(VmFlow::Continue) => EvalResult::Fallthrough,
        Ok(VmFlow::Accept) => EvalResult::Accept,
        Ok(VmFlow::Reject(reason)) => EvalResult::Reject(reason),
        Ok(VmFlow::Return(_)) => EvalResult::Fallthrough,
        Err(e) => {
            tracing::debug!("filter '{}' bytecode error: {}", cf.name, e);
            EvalResult::Fallthrough
        }
    }
}

/// VM control flow out of one code slice.
#[derive(Debug)]
enum VmFlow {
    /// Fell off the end without a verdict.
    Continue,
    Accept,
    Reject(Option<String>),
    /// `return` inside a user-function body.
    Return(Value),
}

impl<'a, C: FilterContext + ?Sized> Evaluator<'a, C> {
    /// The stack-VM loop. Any runtime error aborts the whole filter
    /// (the caller maps it to Fallthrough) exactly like the
    /// tree-walking evaluator.
    fn run_code(
        &mut self,
        code: &[Instr],
        spans: &[Span],
        cf: &CompiledFilter,
        route: &mut Route,
    ) -> Result<VmFlow, EvalError> {
        debug_assert_eq!(code.len(), spans.len());
        let mut ip = 0usize;
        // No upfront capacity: trivial filters (bare accept/reject)
        // run zero stack operations, so eager allocation would be a
        // pure malloc on the hot path.
        let mut stack: Vec<Value> = Vec::new();
        let mut tmp: Option<Value> = None;
        while ip < code.len() {
            // GitHub #19 P7: the source span is read lazily inside
            // the fallible arms, not at the dispatch top. The spans
            // table is parallel to `code` (verified by the
            // debug_assert above), and `ip` is bounds-checked by the
            // loop, so a direct index is safe and infallible arms
            // (Push, Jump, Accept, ...) pay zero span cost. The lazy
            // read preserves the issue #18 Phase 0 contract — every
            // error still carries the span of the instruction that
            // produced it. Passing `spans` as a parameter (instead
            // of reading `cf.spans`) also fixes the latent bug where
            // a user-function body would index the *outer filter's*
            // span table — `call_compiled_function` now passes
            // `&f.spans`, so errors inside a function body point at
            // the function's own source.
            match &code[ip] {
                Instr::Push(v) => stack.push(v.clone()),
                Instr::LoadVar(name) => {
                    let span = spans[ip];
                    let v = self.lookup(name, span)?;
                    stack.push(v);
                }
                Instr::LoadField(field) => {
                    let v = self.read_route_field(field, route)?;
                    stack.push(v);
                }
                Instr::StoreVar(name) => {
                    let v = stack.pop().ok_or_else(vm_stack_error)?;
                    self.scopes
                        .last_mut()
                        .ok_or_else(vm_stack_error)?
                        .vars
                        .insert(name.clone(), v);
                }
                Instr::AssignVar(name) => {
                    let v = stack.pop().ok_or_else(vm_stack_error)?;
                    let span = spans[ip];
                    self.assign(name, v, span)?;
                }
                Instr::StoreTmp => {
                    tmp = stack.pop();
                }
                Instr::LoadTmp => {
                    stack.push(tmp.clone().ok_or_else(vm_stack_error)?);
                }
                Instr::Bin(op) => {
                    let r = stack.pop().ok_or_else(vm_stack_error)?;
                    let l = stack.pop().ok_or_else(vm_stack_error)?;
                    let span = spans[ip];
                    let v = self.eval_binary(*op, l, r, span)?;
                    stack.push(v);
                }
                Instr::Not => {
                    let v = stack.pop().ok_or_else(vm_stack_error)?;
                    stack.push(Value::Bool(!v.truthy()));
                }
                Instr::Neg => {
                    let v = stack.pop().ok_or_else(vm_stack_error)?;
                    match v {
                        Value::Int(n) => stack.push(Value::Int(-n)),
                        other => {
                            let span = spans[ip];
                            return Err(type_mismatch("neg", &other, "int", span, self.line_index));
                        }
                    }
                }
                Instr::JumpIfFalse(t) => {
                    let c = stack.pop().ok_or_else(vm_stack_error)?;
                    if !c.truthy() {
                        ip = *t;
                        continue;
                    }
                }
                Instr::JumpIfTrue(t) => {
                    let c = stack.pop().ok_or_else(vm_stack_error)?;
                    if c.truthy() {
                        ip = *t;
                        continue;
                    }
                }
                Instr::Jump(t) => {
                    ip = *t;
                    continue;
                }
                Instr::Truthy => {
                    let v = stack.pop().ok_or_else(vm_stack_error)?;
                    stack.push(Value::Bool(v.truthy()));
                }
                Instr::Match { negated, rhs } => {
                    let l = stack.pop().ok_or_else(vm_stack_error)?;
                    let m = self.run_match(rhs, &l, route)?;
                    stack.push(Value::Bool(if *negated { !m } else { m }));
                }
                // P6: fused `LoadField(int); Push(Int); Bin(Cmp);
                // JumpIf*(t)`. Reads the integer field directly,
                // compares against the constant, branches — zero
                // stack traffic. The peephole pass only emits this
                // for the four int-typed fields
                // (`BgpLocalPref`/`BgpMed`/`BgpOrigin`/`Source`)
                // and the six comparison ops, so the `match op`
                // body's `unreachable!` arms are genuinely
                // unreachable.
                Instr::BranchFieldIntCmp {
                    field,
                    op,
                    val,
                    target,
                    jump_if_true,
                } => {
                    let n = self.read_int_route_field(field, route)?;
                    let r = match op {
                        BinaryOp::Eq => n == *val,
                        BinaryOp::Ne => n != *val,
                        BinaryOp::Lt => n < *val,
                        BinaryOp::Le => n <= *val,
                        BinaryOp::Gt => n > *val,
                        BinaryOp::Ge => n >= *val,
                        _ => unreachable!("peephole is_int_cmp_op gates this"),
                    };
                    let take = if *jump_if_true { r } else { !r };
                    if take {
                        ip = *target;
                        continue;
                    }
                }
                Instr::Defined(target) => {
                    let present = match target {
                        DefinedTarget::Field(field) => self.field_present(field.kind, route),
                        DefinedTarget::Var(name) => {
                            self.scopes.iter().rev().any(|s| s.vars.contains_key(name))
                        }
                        DefinedTarget::Literal => true,
                        DefinedTarget::Dynamic(e) => {
                            let mut probe = route.clone();
                            self.eval_expr(e, &mut probe).is_ok()
                        }
                    };
                    stack.push(Value::Bool(present));
                }
                // P2: `Call { name, argc }` now only handles built-in
                // functions. User-function calls are resolved to
                // `CallFn { idx, argc }` at compile time. The built-in
                // dispatch goes through `eval_call`.
                Instr::Call { name, argc } => {
                    let args: Vec<Value> =
                        stack.split_off(stack.len().checked_sub(*argc).ok_or_else(vm_stack_error)?);
                    let span = spans[ip];
                    let v = self.eval_call(name, &args, route, span)?;
                    stack.push(v);
                    if let Some(verdict) = self.pending_verdict.take() {
                        return Ok(match verdict {
                            ControlFlow::Accept => VmFlow::Accept,
                            ControlFlow::Reject(reason) => VmFlow::Reject(reason),
                            _ => VmFlow::Continue,
                        });
                    }
                }
                // P2: user-function call by index — direct Vec access,
                // no BTreeMap lookup per call.
                Instr::CallFn { idx, argc } => {
                    let args: Vec<Value> =
                        stack.split_off(stack.len().checked_sub(*argc).ok_or_else(vm_stack_error)?);
                    let span = spans[ip];
                    let f = cf.functions.get(*idx).ok_or_else(|| EvalError {
                        kind: EvalErrorKind::UnknownFunction(format!(
                            "function index {idx} out of range"
                        )),
                        span,
                        line: 0,
                        col: 0,
                    })?;
                    let v = self.call_compiled_function(f, args, cf, route, span)?;
                    stack.push(v);
                    if let Some(verdict) = self.pending_verdict.take() {
                        return Ok(match verdict {
                            ControlFlow::Accept => VmFlow::Accept,
                            ControlFlow::Reject(reason) => VmFlow::Reject(reason),
                            _ => VmFlow::Continue,
                        });
                    }
                }
                Instr::Method {
                    field,
                    method,
                    argc,
                } => {
                    let args: Vec<Value> =
                        stack.split_off(stack.len().checked_sub(*argc).ok_or_else(vm_stack_error)?);
                    let span = spans[ip];
                    let v = self.eval_method(field, method, &args, route, span)?;
                    stack.push(v);
                }
                Instr::AssignField(field) => {
                    let v = stack.pop().ok_or_else(vm_stack_error)?;
                    let span = spans[ip];
                    self.assign_route_field(field, v, route, span)?;
                }
                Instr::AppendField(field) => {
                    let v = stack.pop().ok_or_else(vm_stack_error)?;
                    let span = spans[ip];
                    self.append_route_field(field, v, route, span)?;
                }
                Instr::Pop => {
                    stack.pop();
                }
                Instr::PushScope => self.push_scope(),
                Instr::PopScope => {
                    self.pop_scope();
                }
                Instr::Accept => return Ok(VmFlow::Accept),
                Instr::Reject { from_stack } => {
                    let reason = if *from_stack {
                        let v = stack.pop().ok_or_else(vm_stack_error)?;
                        match v {
                            Value::Str(s) => Some(s),
                            other => Some(format!("{other}")),
                        }
                    } else {
                        None
                    };
                    return Ok(VmFlow::Reject(reason));
                }
                Instr::Return => {
                    let v = stack.pop().unwrap_or(Value::Bool(false));
                    return Ok(VmFlow::Return(v));
                }
                Instr::EvalTree(e) => {
                    let v = self.eval_expr(e, route)?;
                    stack.push(v);
                }
            }
            ip += 1;
        }
        Ok(VmFlow::Continue)
    }

    /// Compiled-function call: bind args in a fresh scope, run the
    /// body code, map accept/reject to the latched pending verdict
    /// (interpreter parity) and return the call value.
    ///
    /// P2: the `name` parameter was removed — `CallFn { idx, argc }`
    /// carries the function index, not the name. The `BadArgCount`
    /// error uses an empty name string (the error message is less
    /// informative but the error is rare — the compiler validates
    /// arg counts at the call site via the parser).
    fn call_compiled_function(
        &mut self,
        f: &crate::filter::bytecode::CompiledFunction,
        args: Vec<Value>,
        cf: &CompiledFilter,
        route: &mut Route,
        span: Span,
    ) -> Result<Value, EvalError> {
        if self.call_depth >= MAX_CALL_DEPTH {
            return Err(self.err(span, EvalErrorKind::CallDepthExceeded(MAX_CALL_DEPTH)));
        }
        if args.len() != f.params.len() {
            return Err(self.err(
                span,
                EvalErrorKind::BadArgCount {
                    name: String::new(),
                    expected: f.params.len(),
                    got: args.len(),
                },
            ));
        }
        self.call_depth += 1;
        self.push_scope();
        for (param, arg) in f.params.iter().zip(args.iter()) {
            self.scopes
                .last_mut()
                .ok_or_else(vm_stack_error)?
                .vars
                .insert(param.clone(), arg.clone());
        }
        let result = self.run_code(&f.code, &f.spans, cf, route);
        self.pop_scope();
        self.call_depth -= 1;
        let outcome = match result? {
            VmFlow::Return(v) => v,
            VmFlow::Accept => {
                self.pending_verdict = Some(ControlFlow::Accept);
                Value::Bool(true)
            }
            VmFlow::Reject(reason) => {
                self.pending_verdict = Some(ControlFlow::Reject(reason));
                Value::Bool(false)
            }
            VmFlow::Continue => Value::Bool(false),
        };
        Ok(outcome)
    }

    /// Compiled `~` matching. Constant patterns run without touching
    /// the tree walker; dynamic pieces fall back to it.
    fn run_match(
        &mut self,
        rhs: &MatchRhs,
        lhs: &Value,
        route: &mut Route,
    ) -> Result<bool, EvalError> {
        match rhs {
            MatchRhs::Value(v) => Ok(value_match(lhs, v)),
            MatchRhs::Expr(e) => self.eval_match(lhs, e, route),
            MatchRhs::Set(items) => {
                for item in items {
                    match item {
                        MatchItem::Value(v) => {
                            if value_match(lhs, v) {
                                return Ok(true);
                            }
                        }
                        MatchItem::PrefixSet { prefix, ge, le } => {
                            if let Value::Prefix(p) = lhs {
                                if prefix_set_matches(prefix, *ge, *le, p) {
                                    return Ok(true);
                                }
                            }
                        }
                        MatchItem::Expr(e) => {
                            let v = self.eval_expr(e, route)?;
                            if value_match(lhs, &v) {
                                return Ok(true);
                            }
                        }
                    }
                }
                Ok(false)
            }
            MatchRhs::PrefixSet { trie, others } => {
                // #19 P4: prefix patterns are indexed in the trie;
                // one O(prefix_len) walk replaces the O(n) linear
                // scan over every `MatchItem::PrefixSet` entry.
                if let Value::Prefix(p) = lhs {
                    if trie.matches(p) {
                        return Ok(true);
                    }
                }
                // Non-prefix items (values, dynamic exprs) stay in
                // a linear scan — the trie cannot index them.
                for item in others {
                    match item {
                        MatchItem::Value(v) => {
                            if value_match(lhs, v) {
                                return Ok(true);
                            }
                        }
                        MatchItem::PrefixSet { .. } => {
                            // Already covered by the trie above; skip.
                            // (The trie built from `PrefixSetTrie::build`
                            // indexed every prefix item in the original
                            // set, so this arm is unreachable in
                            // practice — `others` filters them out at
                            // compile time. Kept for exhaustiveness.)
                        }
                        MatchItem::Expr(e) => {
                            let v = self.eval_expr(e, route)?;
                            if value_match(lhs, &v) {
                                return Ok(true);
                            }
                        }
                    }
                }
                Ok(false)
            }
        }
    }
}

/// VM invariant violation: the stack was empty where a value was
/// required. Not attributable to user source (well-formed bytecode
/// from the total compiler never underflows), so the error carries
/// the default span / zero position.
fn vm_stack_error() -> EvalError {
    EvalError {
        kind: EvalErrorKind::TypeMismatch {
            op: "vm".to_string(),
            lhs: "empty stack".to_string(),
            rhs: "value".to_string(),
        },
        span: Span::default(),
        line: 0,
        col: 0,
    }
}

#[cfg(test)]
#[path = "eval_tests.rs"]
mod tests;
