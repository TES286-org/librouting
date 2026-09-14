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
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvalError {
    pub kind: EvalErrorKind,
    pub line: u32,
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
    /// BGP LARGE_COMMUNITIES (`bgp.large_communities`, RFC 8097) as
    /// `(global_admin, local_data1, local_data2)` triples; empty when
    /// absent.
    fn bgp_large_communities(&self, route: &Route) -> Vec<(u32, u32, u32)>;
    /// BGP EXTENDED_COMMUNITIES (`bgp.ext_communities`, RFC 4360) as
    /// raw `(type, subtype, global, local)` records; empty when absent.
    fn bgp_ext_communities(&self, route: &Route) -> Vec<(u8, u8, u32, u16)>;
    /// BGP ORIGIN (`bgp.origin`): `0 = IGP`, `1 = EGP`, `2 = INCOMPLETE`.
    fn bgp_origin(&self, route: &Route) -> Option<u8>;
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
    /// Replace the whole LARGE_COMMUNITIES attribute (RFC 8097);
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
    fn lookup(&self, name: &str) -> Result<Value, EvalError> {
        for scope in self.scopes.iter().rev() {
            if let Some(v) = scope.vars.get(name) {
                return Ok(v.clone());
            }
        }
        if name == "_" {
            return Ok(Value::Bool(true));
        }
        Err(EvalError {
            kind: EvalErrorKind::UndefinedVar(name.to_string()),
            line: 0,
            col: 0,
        })
    }

    fn assign(&mut self, name: &str, value: Value) -> Result<(), EvalError> {
        for scope in self.scopes.iter_mut().rev() {
            if scope.vars.contains_key(name) {
                scope.vars.insert(name.to_string(), value);
                return Ok(());
            }
        }
        Err(EvalError {
            kind: EvalErrorKind::AssignToUndefined(name.to_string()),
            line: 0,
            col: 0,
        })
    }

    fn push_scope(&mut self) {
        self.scopes.push(Scope::new());
    }

    fn pop_scope(&mut self) {
        self.scopes.pop();
    }

    fn eval_stmt(&mut self, stmt: &Stmt, route: &mut Route) -> Result<ControlFlow, EvalError> {
        match stmt {
            Stmt::Return(value) => {
                let v = match value {
                    Some(e) => Some(self.eval_expr(e, route)?),
                    None => None,
                };
                Ok(ControlFlow::Return(v))
            }
            Stmt::Accept => Ok(ControlFlow::Accept),
            Stmt::Reject(reason) => {
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
            Stmt::If { cond, then, els } => {
                let c = self.eval_expr(cond, route)?;
                if c.truthy() {
                    self.eval_stmt(then, route)
                } else if let Some(e) = els {
                    self.eval_stmt(e, route)
                } else {
                    Ok(ControlFlow::Continue)
                }
            }
            Stmt::Case { scrutinee, arms } => {
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
            Stmt::Let { name, value } => {
                let v = self.eval_expr(value, route)?;
                self.scopes.last_mut().unwrap().vars.insert(name.clone(), v);
                Ok(ControlFlow::Continue)
            }
            Stmt::Assign { name, value } => {
                let v = self.eval_expr(value, route)?;
                self.assign(name, v)?;
                Ok(ControlFlow::Continue)
            }
            Stmt::AssignRouteField { field, value } => {
                let v = self.eval_expr(value, route)?;
                self.assign_route_field(field, v, route)?;
                Ok(ControlFlow::Continue)
            }
            Stmt::AppendRouteField { field, value } => {
                let v = self.eval_expr(value, route)?;
                self.append_route_field(field, v, route)?;
                Ok(ControlFlow::Continue)
            }
            Stmt::Expr(e) => {
                let _ = self.eval_expr(e, route)?;
                Ok(ControlFlow::Continue)
            }
            Stmt::Block(body) => {
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
            Expr::Lit(v) => Ok(v.clone()),
            Expr::Var(name) => self.lookup(name),
            Expr::RouteField(field) => self.read_route_field(field, route),
            Expr::Defined(inner) => Ok(Value::Bool(self.is_defined(inner, route))),
            Expr::Call { name, args } => {
                let mut argv: Vec<Value> = Vec::with_capacity(args.len());
                for a in args {
                    argv.push(self.eval_expr(a, route)?);
                }
                self.eval_call(name, &argv, route)
            }
            Expr::Method {
                receiver,
                method,
                args,
            } => {
                if let Expr::RouteField(field) = receiver.as_ref() {
                    let mut argv: Vec<Value> = Vec::with_capacity(args.len());
                    for a in args {
                        argv.push(self.eval_expr(a, route)?);
                    }
                    return self.eval_method(field, method, &argv, route);
                }
                Err(EvalError {
                    kind: EvalErrorKind::UnknownMethod {
                        field: "<expr>".to_string(),
                        method: method.clone(),
                    },
                    line: 0,
                    col: 0,
                })
            }
            Expr::Binary { op, lhs, rhs } => {
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
                self.eval_binary(*op, l, r)
            }
            Expr::Unary { op, expr } => {
                let v = self.eval_expr(expr, route)?;
                match op {
                    UnaryOp::Not => Ok(Value::Bool(!v.truthy())),
                    UnaryOp::Neg => match v {
                        Value::Int(n) => Ok(Value::Int(-n)),
                        other => Err(type_mismatch("neg", &other, "int")),
                    },
                }
            }
            Expr::Set(items) => {
                let mut v = Vec::with_capacity(items.len());
                for it in items {
                    v.push(self.eval_expr(it, route)?);
                }
                Ok(Value::Set(v))
            }
            Expr::PrefixSet { prefix, ge, le } => {
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
            Expr::Set(items) => {
                for it in items {
                    if let Expr::PrefixSet { prefix, ge, le } = it {
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
            Expr::PrefixSet { prefix, ge, le } => {
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

    /// Presence check for `defined(expr)` / `exists(expr)`.
    ///
    /// Never fails and never mutates the caller's route: an absent
    /// attribute or an undefined variable is simply "not defined".
    /// Distinguishes "absent" from "set to the default value" — the
    /// read path collapses both to `0` / `false` / empty, which is
    /// exactly what BIRD's `defined()` exists to avoid.
    fn is_defined(&mut self, expr: &Expr, route: &Route) -> bool {
        match expr {
            Expr::RouteField(field) => match field.kind {
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
                RouteFieldKind::BgpExtCommunities => {
                    !self.ctx.bgp_ext_communities(route).is_empty()
                }
            },
            Expr::Var(name) => self.scopes.iter().rev().any(|s| s.vars.contains_key(name)),
            // A literal is always defined.
            Expr::Lit(_) => true,
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
            RouteFieldKind::RoaState => Ok(Value::RoaState(self.ctx.roa_state(route))),
        }
    }

    fn assign_route_field(
        &self,
        field: &RouteField,
        value: Value,
        route: &mut Route,
    ) -> Result<(), EvalError> {
        match field.kind {
            RouteFieldKind::BgpLocalPref => {
                let n = as_int(&value).ok_or_else(|| type_mismatch("=", &value, "int"))?;
                if !(0..=u32::MAX as i64).contains(&n) {
                    return Err(EvalError {
                        kind: EvalErrorKind::AsnOutOfRange(n),
                        line: 0,
                        col: 0,
                    });
                }
                self.ctx.set_bgp_local_pref(route, n as u32);
            }
            RouteFieldKind::BgpMed => {
                let n = as_int(&value).ok_or_else(|| type_mismatch("=", &value, "int"))?;
                if !(0..=u32::MAX as i64).contains(&n) {
                    return Err(EvalError {
                        kind: EvalErrorKind::AsnOutOfRange(n),
                        line: 0,
                        col: 0,
                    });
                }
                self.ctx.set_bgp_med(route, n as u32);
            }
            RouteFieldKind::BgpNextHop => {
                let ip = match value {
                    Value::Ip(ip) => ip,
                    other => return Err(type_mismatch("=", &other, "ip")),
                };
                self.ctx.set_bgp_next_hop(route, ip);
            }
            // `bgp.communities = <set>` — the canonical BIRD idiom
            // (`bgp.community = delete(bgp.community, [65000:1]);`).
            RouteFieldKind::BgpCommunities => {
                let cs = self.communities_from_value(&value, "=")?;
                self.ctx.set_bgp_communities(route, cs);
            }
            // `bgp.large_communities = <set>` (RFC 8097).
            RouteFieldKind::BgpLargeCommunities => {
                let cs = self.large_communities_from_value(&value, "=")?;
                self.ctx.set_bgp_large_communities(route, cs);
            }
            // `bgp.ext_communities = <set>` (RFC 4360).
            RouteFieldKind::BgpExtCommunities => {
                let cs = self.ext_communities_from_value(&value, "=")?;
                self.ctx.set_bgp_ext_communities(route, cs);
            }
            // `bgp.as_path = <sequence>` — BIRD assigns `bgp_path`
            // values the same way.
            RouteFieldKind::BgpAsPath => {
                let seq = match value {
                    Value::AsPath(p) => p,
                    other => return Err(type_mismatch("=", &other, "as-path")),
                };
                self.ctx.set_bgp_as_path(route, seq);
            }
            other => {
                return Err(EvalError {
                    kind: EvalErrorKind::UnknownMethod {
                        field: other.to_string(),
                        method: "=".to_string(),
                    },
                    line: 0,
                    col: 0,
                });
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
                    return Err(EvalError {
                        kind: EvalErrorKind::TypeMismatch {
                            op: op.to_string(),
                            lhs: "community-set".to_string(),
                            rhs: "community-pattern wildcard".to_string(),
                        },
                        line: 0,
                        col: 0,
                    });
                }
                other => return Err(type_mismatch(op, other, "community-set")),
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

    /// Normalize a large-community-set RHS (RFC 8097): a bare
    /// `LargeCommunities` value, a set literal of triples, or one
    /// triple.
    fn large_communities_from_value(
        &self,
        value: &Value,
        op: &str,
    ) -> Result<Vec<(u32, u32, u32)>, EvalError> {
        let mut out = Vec::new();
        let mut push_item = |it: &Value| -> Result<(), EvalError> {
            match it {
                Value::LargeCommunities(cs) => out.extend(cs.iter().copied()),
                other => return Err(type_mismatch(op, other, "large-community-set")),
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
    ) -> Result<Vec<(u8, u8, u32, u16)>, EvalError> {
        let mut out = Vec::new();
        let mut push_item = |it: &Value| -> Result<(), EvalError> {
            match it {
                Value::ExtCommunities(cs) => out.extend(cs.iter().copied()),
                other => return Err(type_mismatch(op, other, "ext-community-set")),
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
                                    return Err(EvalError {
                                        kind: EvalErrorKind::TypeMismatch {
                                            op: "+=".to_string(),
                                            lhs: "community-set".to_string(),
                                            rhs: "community-pattern wildcard".to_string(),
                                        },
                                        line: 0,
                                        col: 0,
                                    });
                                }
                                Value::Int(n) => {
                                    if !(0..=u16::MAX as i64).contains(&n) {
                                        return Err(EvalError {
                                            kind: EvalErrorKind::CommunityOutOfRange {
                                                asn: n,
                                                val: 0,
                                            },
                                            line: 0,
                                            col: 0,
                                        });
                                    }
                                    out.push((Asn(n as u32), 0));
                                }
                                other => return Err(type_mismatch("+=", &other, "community-set")),
                            }
                        }
                        out
                    }
                    other => return Err(type_mismatch("+=", &other, "community-set")),
                };
                for (asn, val) in cs {
                    self.ctx.bgp_communities_add(route, asn, val);
                }
            }
            RouteFieldKind::BgpLargeCommunities => {
                let cs = self.large_communities_from_value(&value, "+=")?;
                let mut cur = self.ctx.bgp_large_communities(route);
                for c in cs {
                    if !cur.contains(&c) {
                        cur.push(c);
                    }
                }
                self.ctx.set_bgp_large_communities(route, cur);
            }
            RouteFieldKind::BgpExtCommunities => {
                let cs = self.ext_communities_from_value(&value, "+=")?;
                let mut cur = self.ctx.bgp_ext_communities(route);
                for c in cs {
                    if !cur.contains(&c) {
                        cur.push(c);
                    }
                }
                self.ctx.set_bgp_ext_communities(route, cur);
            }
            other => {
                return Err(EvalError {
                    kind: EvalErrorKind::UnknownMethod {
                        field: other.to_string(),
                        method: "+=".to_string(),
                    },
                    line: 0,
                    col: 0,
                });
            }
        }
        Ok(())
    }

    fn eval_call(
        &mut self,
        name: &str,
        args: &[Value],
        route: &mut Route,
    ) -> Result<Value, EvalError> {
        // D3.1: user-defined functions shadow nothing (the parser
        // rejects shadowing a built-in), so look the name up first
        // and fall through to the built-ins otherwise.
        if let Some(f) = self.functions.get(name).cloned() {
            return self.call_user_function(&f, args, route);
        }
        match name {
            "len" => {
                if args.len() != 1 {
                    return Err(bad_arg_count("len", 1, args.len()));
                }
                match &args[0] {
                    Value::AsPath(p) => Ok(Value::Int(p.len() as i64)),
                    Value::Communities(c) => Ok(Value::Int(c.len() as i64)),
                    Value::LargeCommunities(c) => Ok(Value::Int(c.len() as i64)),
                    Value::ExtCommunities(c) => Ok(Value::Int(c.len() as i64)),
                    Value::Str(s) => Ok(Value::Int(s.len() as i64)),
                    other => Err(type_mismatch("len", other, "as-path|community-set|string")),
                }
            }
            // D3.4 — BIRD set operations (filter/config.Y `f_pair`
            // delete/filter + set introspection).
            "delete" | "filter" => {
                if args.len() != 2 {
                    return Err(bad_arg_count(name, 2, args.len()));
                }
                apply_set_op(name, &args[0], &args[1], name == "filter")
            }
            "empty" => {
                if args.len() != 1 {
                    return Err(bad_arg_count("empty", 1, args.len()));
                }
                match &args[0] {
                    Value::AsPath(p) => Ok(Value::Bool(p.is_empty())),
                    Value::Communities(c) => Ok(Value::Bool(c.is_empty())),
                    Value::LargeCommunities(c) => Ok(Value::Bool(c.is_empty())),
                    Value::ExtCommunities(c) => Ok(Value::Bool(c.is_empty())),
                    Value::Set(s) => Ok(Value::Bool(s.is_empty())),
                    Value::Str(s) => Ok(Value::Bool(s.is_empty())),
                    other => Err(type_mismatch("empty", other, "set-like")),
                }
            }
            "count" => {
                if args.len() != 1 {
                    return Err(bad_arg_count("count", 1, args.len()));
                }
                match &args[0] {
                    Value::AsPath(p) => Ok(Value::Int(p.len() as i64)),
                    Value::Communities(c) => Ok(Value::Int(c.len() as i64)),
                    Value::LargeCommunities(c) => Ok(Value::Int(c.len() as i64)),
                    Value::ExtCommunities(c) => Ok(Value::Int(c.len() as i64)),
                    Value::Set(s) => Ok(Value::Int(s.len() as i64)),
                    other => Err(type_mismatch("count", other, "set-like")),
                }
            }
            "first" => {
                if args.len() != 1 {
                    return Err(bad_arg_count("first", 1, args.len()));
                }
                match &args[0] {
                    Value::AsPath(p) => Ok(p
                        .first()
                        .map(|a| Value::Asn(*a))
                        .unwrap_or(Value::Bool(false))),
                    other => Err(type_mismatch("first", other, "as-path")),
                }
            }
            "last" => {
                if args.len() != 1 {
                    return Err(bad_arg_count("last", 1, args.len()));
                }
                match &args[0] {
                    Value::AsPath(p) => Ok(p
                        .last()
                        .map(|a| Value::Asn(*a))
                        .unwrap_or(Value::Bool(false))),
                    other => Err(type_mismatch("last", other, "as-path")),
                }
            }
            other => Err(EvalError {
                kind: EvalErrorKind::UnknownFunction(other.to_string()),
                line: 0,
                col: 0,
            }),
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
    ) -> Result<Value, EvalError> {
        if self.call_depth >= MAX_CALL_DEPTH {
            return Err(EvalError {
                kind: EvalErrorKind::CallDepthExceeded(MAX_CALL_DEPTH),
                line: 0,
                col: 0,
            });
        }
        if args.len() != f.params.len() {
            return Err(EvalError {
                kind: EvalErrorKind::BadArgCount {
                    name: f.name.clone(),
                    expected: f.params.len(),
                    got: args.len(),
                },
                line: 0,
                col: 0,
            });
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
    ) -> Result<Value, EvalError> {
        match (field.kind, method) {
            (RouteFieldKind::BgpAsPath, "prepend") => {
                if args.len() != 1 {
                    return Err(bad_arg_count("bgp.as_path.prepend", 1, args.len()));
                }
                let n =
                    as_int(&args[0]).ok_or_else(|| type_mismatch("prepend", &args[0], "int"))?;
                if !(0..=u32::MAX as i64).contains(&n) {
                    return Err(EvalError {
                        kind: EvalErrorKind::AsnOutOfRange(n),
                        line: 0,
                        col: 0,
                    });
                }
                self.ctx.bgp_as_path_prepend(route, Asn(n as u32));
                Ok(Value::AsPath(self.ctx.bgp_as_path(route)))
            }
            (RouteFieldKind::BgpCommunities, "add") => {
                if args.len() != 1 {
                    return Err(bad_arg_count("bgp.communities.add", 1, args.len()));
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
                    ));
                }
                for (asn, val) in to_add {
                    self.ctx.bgp_communities_add(route, asn, val);
                }
                Ok(Value::Communities(self.ctx.bgp_communities(route)))
            }
            (RouteFieldKind::BgpCommunities, "delete" | "filter") => {
                if args.len() != 1 {
                    return Err(bad_arg_count("bgp.communities.delete", 1, args.len()));
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
                    return Err(bad_arg_count("bgp.as_path.delete", 1, args.len()));
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
                    return Err(bad_arg_count("bgp.large_communities.add", 1, args.len()));
                }
                let items = self.large_communities_from_value(&args[0], method)?;
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
                    return Err(bad_arg_count("bgp.ext_communities.add", 1, args.len()));
                }
                let items = self.ext_communities_from_value(&args[0], method)?;
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
            (kind, m) => Err(EvalError {
                kind: EvalErrorKind::UnknownMethod {
                    field: kind.to_string(),
                    method: m.to_string(),
                },
                line: 0,
                col: 0,
            }),
        }
    }

    fn eval_binary(&self, op: BinaryOp, l: Value, r: Value) -> Result<Value, EvalError> {
        match op {
            BinaryOp::Eq => Ok(Value::Bool(value_eq(&l, &r))),
            BinaryOp::Ne => Ok(Value::Bool(!value_eq(&l, &r))),
            BinaryOp::Lt | BinaryOp::Le | BinaryOp::Gt | BinaryOp::Ge => {
                let li = as_int(&l).ok_or_else(|| type_mismatch(op_name(op), &l, "int"))?;
                let ri = as_int(&r).ok_or_else(|| type_mismatch(op_name(op), &r, "int"))?;
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
                let li = as_int(&l).ok_or_else(|| type_mismatch(op_name(op), &l, "int"))?;
                let ri = as_int(&r).ok_or_else(|| type_mismatch(op_name(op), &r, "int"))?;
                let v = match op {
                    BinaryOp::Add => li.checked_add(ri),
                    BinaryOp::Sub => li.checked_sub(ri),
                    BinaryOp::Mul => li.checked_mul(ri),
                    BinaryOp::Div => {
                        if ri == 0 {
                            return Err(EvalError {
                                kind: EvalErrorKind::DivByZero,
                                line: 0,
                                col: 0,
                            });
                        }
                        li.checked_div(ri)
                    }
                    BinaryOp::Mod => {
                        if ri == 0 {
                            return Err(EvalError {
                                kind: EvalErrorKind::DivByZero,
                                line: 0,
                                col: 0,
                            });
                        }
                        Some(li.checked_rem(ri).unwrap_or(0))
                    }
                    _ => unreachable!(),
                };
                v.map(Value::Int).ok_or(EvalError {
                    kind: EvalErrorKind::Overflow,
                    line: 0,
                    col: 0,
                })
            }
            BinaryOp::BitAnd | BinaryOp::BitOr | BinaryOp::BitXor => {
                let li = as_int(&l).ok_or_else(|| type_mismatch(op_name(op), &l, "int"))?;
                let ri = as_int(&r).ok_or_else(|| type_mismatch(op_name(op), &r, "int"))?;
                let v = match op {
                    BinaryOp::BitAnd => li & ri,
                    BinaryOp::BitOr => li | ri,
                    BinaryOp::BitXor => li ^ ri,
                    _ => unreachable!(),
                };
                Ok(Value::Int(v))
            }
            BinaryOp::Shl | BinaryOp::Shr => {
                let li = as_int(&l).ok_or_else(|| type_mismatch(op_name(op), &l, "int"))?;
                let ri = as_int(&r).ok_or_else(|| type_mismatch(op_name(op), &r, "int"))?;
                if !(0..=63).contains(&ri) {
                    return Err(EvalError {
                        kind: EvalErrorKind::BadShift(ri),
                        line: 0,
                        col: 0,
                    });
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

fn type_mismatch(op: &str, v: &Value, expected: &str) -> EvalError {
    EvalError {
        kind: EvalErrorKind::TypeMismatch {
            op: op.to_string(),
            lhs: v.type_name().to_string(),
            rhs: expected.to_string(),
        },
        line: 0,
        col: 0,
    }
}

fn bad_arg_count(name: &str, expected: usize, got: usize) -> EvalError {
    EvalError {
        kind: EvalErrorKind::BadArgCount {
            name: name.to_string(),
            expected,
            got,
        },
        line: 0,
        col: 0,
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
        // RFC 8097 large communities: exact triple membership.
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
        other => Err(type_mismatch(op, other, "community-set|as-path|set")),
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::filter::compile;
    use lr_core::addr::{Asn, IpAddr, Prefix};
    use lr_core::attr::{AttrTag, Attribute, Attributes};
    use lr_core::nlri::NlriFamily;
    use lr_core::rib::{Preference, Protocol, Route, RouteKey, RouteOrigin};

    /// A minimal context for tests — pulls LOCAL_PREF / MED / etc.
    /// from the route's attribute bag using the same tag encoding as
    /// `lr_policy::bgp` (so a filter compiled in tests sees the
    /// same values the daemon would surface).
    struct StubCtx;

    const TAG_AS_PATH: u8 = 2;
    const TAG_MED: u8 = 4;
    const TAG_LOCAL_PREF: u8 = 5;
    const TAG_COMMUNITIES: u8 = 8;
    const TAG_EXT_COMMUNITIES: u8 = 16;
    const TAG_LARGE_COMMUNITIES: u8 = 32;

    fn attr(route: &Route, tag: u8) -> Option<Vec<u8>> {
        route
            .attributes
            .get(AttrTag::raw(tag))
            .map(|a| a.value.clone())
    }

    impl FilterContext for StubCtx {
        fn bgp_local_pref(&self, route: &Route) -> Option<u32> {
            attr(route, TAG_LOCAL_PREF).and_then(|b| b.try_into().ok().map(u32::from_be_bytes))
        }
        fn bgp_med(&self, route: &Route) -> Option<u32> {
            attr(route, TAG_MED).and_then(|b| b.try_into().ok().map(u32::from_be_bytes))
        }
        fn bgp_next_hop(&self, _route: &Route) -> Option<IpAddr> {
            None
        }
        fn bgp_as_path(&self, route: &Route) -> Vec<Asn> {
            let Some(b) = attr(route, TAG_AS_PATH) else {
                return Vec::new();
            };
            if b.is_empty() {
                return Vec::new();
            }
            // segment: type (1B) + length (1B) + N*4 bytes
            let mut out = Vec::new();
            let mut i = 0;
            while i + 2 <= b.len() {
                let _seg_type = b[i];
                let count = b[i + 1] as usize;
                i += 2;
                for _ in 0..count {
                    if i + 4 > b.len() {
                        break;
                    }
                    let asn = u32::from_be_bytes(b[i..i + 4].try_into().unwrap());
                    out.push(Asn(asn));
                    i += 4;
                }
            }
            out
        }
        fn bgp_communities(&self, route: &Route) -> Vec<(Asn, u16)> {
            let Some(b) = attr(route, TAG_COMMUNITIES) else {
                return Vec::new();
            };
            let mut out = Vec::new();
            // RFC 1997 §4: communities are 4 bytes — the high two
            // bytes are the ASN, the low two are the value.
            // `array_chunks::<4>()` would be the clippy-preferred
            // form, but it is not stable on the project's MSRV
            // (Rust 1.88). `chunks_exact(4)` is the portable choice.
            #[allow(clippy::chunks_exact_to_as_chunks)]
            for chunk in b.chunks_exact(4) {
                let asn = u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
                let val = u16::from_be_bytes([chunk[2], chunk[3]]);
                out.push((Asn(asn), val));
            }
            out
        }
        fn bgp_origin(&self, _route: &Route) -> Option<u8> {
            Some(0)
        }
        fn roa_state(&self, _route: &Route) -> RoaStateLit {
            RoaStateLit::NotFound
        }
        fn set_bgp_local_pref(&self, route: &mut Route, value: u32) {
            route.attributes.insert(Attribute {
                tag: AttrTag::raw(TAG_LOCAL_PREF),
                flags: 0x40,
                value: value.to_be_bytes().to_vec(),
            });
        }
        fn set_bgp_med(&self, route: &mut Route, value: u32) {
            route.attributes.insert(Attribute {
                tag: AttrTag::raw(TAG_MED),
                flags: 0x80,
                value: value.to_be_bytes().to_vec(),
            });
        }
        fn set_bgp_next_hop(&self, _route: &mut Route, _value: IpAddr) {}
        fn bgp_as_path_prepend(&self, route: &mut Route, asn: Asn) {
            let mut path = self.bgp_as_path(route);
            path.insert(0, asn);
            let mut v = vec![2u8, path.len() as u8];
            for a in &path {
                v.extend_from_slice(&a.0.to_be_bytes());
            }
            route.attributes.insert(Attribute {
                tag: AttrTag::raw(TAG_AS_PATH),
                flags: 0x40,
                value: v,
            });
        }
        fn bgp_communities_add(&self, route: &mut Route, asn: Asn, val: u16) {
            let mut set = self.bgp_communities(route);
            let new = (asn, val);
            if set.contains(&new) {
                return;
            }
            set.push(new);
            Self::put_communities(route, &set);
        }
        fn set_bgp_communities(&self, route: &mut Route, set: Vec<(Asn, u16)>) {
            Self::put_communities(route, &set);
        }
        fn bgp_large_communities(&self, route: &Route) -> Vec<(u32, u32, u32)> {
            attr(route, TAG_LARGE_COMMUNITIES)
                .map(|b| {
                    lr_bgp::path::communities::LargeCommunity::decode_set(&b)
                        .into_iter()
                        .map(|c| (c.global_admin, c.local_data1, c.local_data2))
                        .collect()
                })
                .unwrap_or_default()
        }
        fn bgp_ext_communities(&self, route: &Route) -> Vec<(u8, u8, u32, u16)> {
            attr(route, TAG_EXT_COMMUNITIES)
                .map(|b| {
                    lr_bgp::path::communities::ExtendedCommunity::decode_set(&b)
                        .into_iter()
                        .map(|c| (c.kind, c.subtype, c.global, c.local))
                        .collect()
                })
                .unwrap_or_default()
        }
        fn set_bgp_large_communities(&self, route: &mut Route, set: Vec<(u32, u32, u32)>) {
            let cs: Vec<lr_bgp::path::communities::LargeCommunity> = set
                .into_iter()
                .map(|(g, d1, d2)| lr_bgp::path::communities::LargeCommunity::new(g, d1, d2))
                .collect();
            if cs.is_empty() {
                route.attributes.remove(AttrTag::raw(TAG_LARGE_COMMUNITIES));
                return;
            }
            route.attributes.insert(Attribute {
                tag: AttrTag::raw(TAG_LARGE_COMMUNITIES),
                flags: 0xC0,
                value: lr_bgp::path::communities::LargeCommunity::encode_set(&cs),
            });
        }
        fn set_bgp_ext_communities(&self, route: &mut Route, set: Vec<(u8, u8, u32, u16)>) {
            let cs: Vec<lr_bgp::path::communities::ExtendedCommunity> = set
                .into_iter()
                .map(|(k, s, g, l)| lr_bgp::path::communities::ExtendedCommunity::new(k, s, g, l))
                .collect();
            if cs.is_empty() {
                route.attributes.remove(AttrTag::raw(TAG_EXT_COMMUNITIES));
                return;
            }
            route.attributes.insert(Attribute {
                tag: AttrTag::raw(TAG_EXT_COMMUNITIES),
                flags: 0xC0,
                value: lr_bgp::path::communities::ExtendedCommunity::encode_set(&cs),
            });
        }
        fn set_bgp_as_path(&self, route: &mut Route, seq: Vec<Asn>) {
            if seq.is_empty() {
                route.attributes.remove(AttrTag::raw(TAG_AS_PATH));
                return;
            }
            let mut v = Vec::with_capacity(2 + seq.len() * 4);
            v.push(2u8); // AS_SEQUENCE
            v.push(seq.len() as u8);
            for a in &seq {
                v.extend_from_slice(&a.0.to_be_bytes());
            }
            route.attributes.insert(Attribute {
                tag: AttrTag::raw(TAG_AS_PATH),
                flags: 0x40,
                value: v,
            });
        }
    }

    impl StubCtx {
        fn put_communities(route: &mut Route, set: &[(Asn, u16)]) {
            if set.is_empty() {
                route.attributes.remove(AttrTag::raw(TAG_COMMUNITIES));
                return;
            }
            let mut v = Vec::with_capacity(set.len() * 4);
            for (a, val) in set {
                v.extend_from_slice(&(a.0 as u16).to_be_bytes());
                v.extend_from_slice(&val.to_be_bytes());
            }
            route.attributes.insert(Attribute {
                tag: AttrTag::raw(TAG_COMMUNITIES),
                flags: 0xC0,
                value: v,
            });
        }
    }

    fn route_with(prefix: &str, local_pref: u32, med: u32) -> Route {
        let prefix: Prefix = prefix.parse().unwrap();
        let mut attrs = Attributes::new();
        attrs.insert(Attribute {
            tag: AttrTag::raw(TAG_LOCAL_PREF),
            flags: 0x40,
            value: local_pref.to_be_bytes().to_vec(),
        });
        attrs.insert(Attribute {
            tag: AttrTag::raw(TAG_MED),
            flags: 0x80,
            value: med.to_be_bytes().to_vec(),
        });
        Route {
            key: RouteKey::new(prefix, NlriFamily::IPV4_UNICAST),
            origin: RouteOrigin { proto: 1, peer: 0 },
            protocol: Protocol::Bgp,
            preference: Preference::new(20, 100),
            next_hop: None,
            attributes: attrs,
            age_ms: 0,
            path_id: 0,
            tag: None,
        }
    }

    fn run(filter_src: &str, route: &mut Route) -> EvalResult {
        let f = compile("test", filter_src).unwrap_or_else(|e| panic!("{e}"));
        evaluate(&f, route, &StubCtx)
    }

    #[test]
    fn accept_unconditionally() {
        let mut r = route_with("203.0.113.0/24", 100, 0);
        assert_eq!(run("accept;", &mut r), EvalResult::Accept);
    }

    #[test]
    fn reject_unconditionally() {
        let mut r = route_with("203.0.113.0/24", 100, 0);
        assert_eq!(run("reject;", &mut r), EvalResult::Reject(None));
    }

    #[test]
    fn reject_with_reason() {
        let mut r = route_with("203.0.113.0/24", 100, 0);
        assert_eq!(
            run("reject with \"too short\";", &mut r),
            EvalResult::Reject(Some("too short".to_string()))
        );
    }

    #[test]
    fn if_local_pref_high_accepts() {
        let mut r = route_with("203.0.113.0/24", 200, 0);
        let src = "if bgp.local_pref > 100 then accept; reject;";
        assert_eq!(run(src, &mut r), EvalResult::Accept);
    }

    #[test]
    fn if_local_pref_low_rejects() {
        let mut r = route_with("203.0.113.0/24", 50, 0);
        let src = "if bgp.local_pref > 100 then accept; reject;";
        assert_eq!(run(src, &mut r), EvalResult::Reject(None));
    }

    #[test]
    fn if_else_branches() {
        let mut r = route_with("203.0.113.0/24", 50, 0);
        let src = "if bgp.local_pref > 100 then accept; else reject;";
        assert_eq!(run(src, &mut r), EvalResult::Reject(None));
    }

    #[test]
    fn let_and_arithmetic() {
        let mut r = route_with("203.0.113.0/24", 100, 0);
        let src = "let x = 50; let y = x * 2; if bgp.local_pref == y then accept; reject;";
        assert_eq!(run(src, &mut r), EvalResult::Accept);
    }

    #[test]
    fn assignment_to_bgp_local_pref() {
        let mut r = route_with("203.0.113.0/24", 100, 0);
        let src = "bgp.local_pref = 250; accept;";
        assert_eq!(run(src, &mut r), EvalResult::Accept);
        assert_eq!(StubCtx.bgp_local_pref(&r), Some(250));
    }

    #[test]
    fn prefix_membership_match() {
        let mut r = route_with("203.0.113.0/24", 100, 0);
        let src = "if net ~ 203.0.113.0/24 then accept; reject;";
        assert_eq!(run(src, &mut r), EvalResult::Accept);
    }

    #[test]
    fn prefix_membership_no_match() {
        let mut r = route_with("198.51.100.0/24", 100, 0);
        let src = "if net ~ 203.0.113.0/24 then accept; reject;";
        assert_eq!(run(src, &mut r), EvalResult::Reject(None));
    }

    #[test]
    fn prefix_set_membership() {
        let mut r = route_with("203.0.113.0/24", 100, 0);
        let src = "if net ~ [ 10.0.0.0/8, 203.0.113.0/24 ] then accept; reject;";
        assert_eq!(run(src, &mut r), EvalResult::Accept);
    }

    #[test]
    fn prefix_set_with_range_matches_more_specific() {
        let mut r = route_with("10.1.2.0/24", 100, 0);
        let src = "if net ~ [ 10.0.0.0/8{16,24} ] then accept; reject;";
        assert_eq!(run(src, &mut r), EvalResult::Accept);
    }

    #[test]
    fn prefix_set_with_range_rejects_too_specific() {
        let mut r = route_with("10.1.2.0/25", 100, 0);
        let src = "if net ~ [ 10.0.0.0/8{16,24} ] then accept; reject;";
        assert_eq!(run(src, &mut r), EvalResult::Reject(None));
    }

    #[test]
    fn boolean_short_circuit_and() {
        let mut r = route_with("203.0.113.0/24", 100, 0);
        let src = "if net ~ 203.0.113.0/24 && bgp.local_pref >= 100 then accept; reject;";
        assert_eq!(run(src, &mut r), EvalResult::Accept);
    }

    #[test]
    fn boolean_short_circuit_or() {
        let mut r = route_with("203.0.113.0/24", 50, 0);
        let src = "if bgp.local_pref > 100 || net ~ 203.0.113.0/24 then accept; reject;";
        assert_eq!(run(src, &mut r), EvalResult::Accept);
    }

    #[test]
    fn case_statement_routes_to_default() {
        let mut r = route_with("203.0.113.0/24", 100, 0);
        let src = "case proto { \"ospfv2\" => accept; default => reject; }";
        assert_eq!(run(src, &mut r), EvalResult::Reject(None));
    }

    #[test]
    fn method_prepend_adds_to_as_path() {
        let mut r = route_with("203.0.113.0/24", 100, 0);
        let src = "bgp.as_path.prepend(65001); accept;";
        assert_eq!(run(src, &mut r), EvalResult::Accept);
        let path = StubCtx.bgp_as_path(&r);
        assert_eq!(path, vec![Asn(65001)]);
    }

    #[test]
    fn communities_append() {
        let mut r = route_with("203.0.113.0/24", 100, 0);
        let src = "bgp.communities += [ 64512:100 ]; accept;";
        assert_eq!(run(src, &mut r), EvalResult::Accept);
        let cs = StubCtx.bgp_communities(&r);
        assert!(cs.contains(&(Asn(64512), 100)), "{cs:?}");
    }

    #[test]
    fn function_len_on_as_path() {
        let mut r = route_with("203.0.113.0/24", 100, 0);
        let src = "bgp.as_path.prepend(65001); bgp.as_path.prepend(65002); \
                   if len(bgp.as_path) == 2 then accept; reject;";
        assert_eq!(run(src, &mut r), EvalResult::Accept);
    }

    #[test]
    fn undefined_variable_is_an_error_fallthrough() {
        let mut r = route_with("203.0.113.0/24", 100, 0);
        assert_eq!(
            run("if undefined_var > 0 then accept; reject;", &mut r),
            EvalResult::Fallthrough
        );
    }

    #[test]
    fn fallthrough_when_no_terminal() {
        let mut r = route_with("203.0.113.0/24", 100, 0);
        assert_eq!(run("let x = 5;", &mut r), EvalResult::Fallthrough);
    }

    #[test]
    fn arithmetic_precedence() {
        let mut r = route_with("203.0.113.0/24", 100, 0);
        let src = "let x = 1 + 2 * 3; if x == 7 then accept; reject;";
        assert_eq!(run(src, &mut r), EvalResult::Accept);
    }

    #[test]
    fn division_by_zero_is_fallthrough() {
        let mut r = route_with("203.0.113.0/24", 100, 0);
        let src = "let x = 1 / 0; accept;";
        assert_eq!(run(src, &mut r), EvalResult::Fallthrough);
    }

    #[test]
    fn nested_blocks_have_separate_scope() {
        let mut r = route_with("203.0.113.0/24", 100, 0);
        let src = "let x = 1; { let x = 2; } if x == 1 then accept; reject;";
        assert_eq!(run(src, &mut r), EvalResult::Accept);
    }

    #[test]
    fn roa_state_string_equality() {
        // Verify `roa.state == "invalid"` form works — the StubCtx
        // returns NotFound for every route, so the equality test
        // checks that branch.
        let mut r = route_with("203.0.113.0/24", 100, 0);
        let src = "if roa.state == \"not-found\" then accept; reject;";
        assert_eq!(run(src, &mut r), EvalResult::Accept);
    }

    #[test]
    fn roa_state_string_inequality_rejects() {
        let mut r = route_with("203.0.113.0/24", 100, 0);
        let src = "if roa.state == \"invalid\" then accept; reject;";
        // StubCtx returns NotFound, so the equality fails and we
        // fall through to `reject;`.
        assert_eq!(run(src, &mut r), EvalResult::Reject(None));
    }

    /// Build a route with an explicit protocol kind, for `proto` field
    /// tests. The default `route_with` helper hard-codes
    /// `Protocol::Bgp`, which is fine for everything except the
    /// `proto` string surface.
    fn route_with_proto(prefix: &str, protocol: Protocol) -> Route {
        let prefix: Prefix = prefix.parse().unwrap();
        let mut attrs = Attributes::new();
        attrs.insert(Attribute {
            tag: AttrTag::raw(TAG_LOCAL_PREF),
            flags: 0x40,
            value: 100u32.to_be_bytes().to_vec(),
        });
        attrs.insert(Attribute {
            tag: AttrTag::raw(TAG_MED),
            flags: 0x80,
            value: 0u32.to_be_bytes().to_vec(),
        });
        Route {
            key: RouteKey::new(prefix, NlriFamily::IPV4_UNICAST),
            origin: RouteOrigin { proto: 1, peer: 0 },
            protocol,
            preference: Preference::new(protocol.default_admin_distance(), 100),
            next_hop: None,
            attributes: attrs,
            age_ms: 0,
            path_id: 0,
            tag: None,
        }
    }

    #[test]
    fn proto_field_returns_bird_style_lowercase_name() {
        // Regression for the Filter DSL `proto` string form: the
        // previous implementation returned Rust Debug strings
        // (`"Bgp"`, `"Ospfv2"`, …). BIRD and the lr docs use the
        // lowercase form, so `proto == "bgp"` must hold for a BGP
        // route. Mirrors the docstring on `RouteFieldKind::Proto`.
        let mut r = route_with("203.0.113.0/24", 100, 0);
        assert_eq!(
            run("if proto == \"bgp\" then accept; reject;", &mut r),
            EvalResult::Accept,
        );
    }

    #[test]
    fn proto_field_does_not_match_rust_debug_form() {
        // The buggy Debug form (`"Bgp"`) must no longer match.
        let mut r = route_with("203.0.113.0/24", 100, 0);
        assert_eq!(
            run("if proto == \"Bgp\" then accept; reject;", &mut r),
            EvalResult::Reject(None),
        );
    }

    #[test]
    fn proto_field_matches_each_protocol_bird_name() {
        for (proto, name) in [
            (Protocol::Bgp, "bgp"),
            (Protocol::Ospfv2, "ospf"),
            (Protocol::Ospfv3, "ospf3"),
            (Protocol::Babel, "babel"),
            (Protocol::Static, "static"),
            (Protocol::Connected, "direct"),
            (Protocol::Other(99), "unknown"),
        ] {
            let mut r = route_with_proto("203.0.113.0/24", proto);
            let src = format!("if proto == \"{name}\" then accept; reject;");
            assert_eq!(
                run(&src, &mut r),
                EvalResult::Accept,
                "proto {proto:?} did not match bird-name {name:?}",
            );
        }
    }

    #[test]
    fn proto_field_case_statement_routes_bird_names() {
        // Replaces the legacy `case proto { "ospfv2" => accept; … }`
        // form: BIRD-style names are lowercase without the `v2`
        // suffix for OSPFv2.
        let mut r = route_with_proto("203.0.113.0/24", Protocol::Ospfv2);
        let src = "case proto { \"ospf\" => accept; default => reject; }";
        assert_eq!(run(src, &mut r), EvalResult::Accept);
    }

    // ===== D3.5 — defined() / exists() =====

    #[test]
    fn defined_distinguishes_absent_from_zero_med() {
        // `route_with` always stamps LOCAL_PREF + MED, so both are
        // defined here; strip MED and only LOCAL_PREF stays defined.
        let mut r = route_with("203.0.113.0/24", 100, 0);
        r.attributes.remove(AttrTag::raw(TAG_MED));
        assert_eq!(
            run("if defined(bgp.med) then accept; reject;", &mut r),
            EvalResult::Reject(None),
        );
        assert_eq!(
            run("if defined(bgp.local_pref) then accept; reject;", &mut r),
            EvalResult::Accept,
        );
    }

    #[test]
    fn defined_zero_med_is_still_defined() {
        // MED present with value 0 must not read as absent — the
        // whole point of the check.
        let mut r = route_with("203.0.113.0/24", 100, 0);
        assert_eq!(
            run("if defined(bgp.med) then accept; reject;", &mut r),
            EvalResult::Accept,
        );
    }

    #[test]
    fn exists_alias_behaves_like_defined() {
        let mut r = route_with("203.0.113.0/24", 100, 0);
        assert_eq!(
            run("if exists(bgp.local_pref) then accept; reject;", &mut r),
            EvalResult::Accept,
        );
        r.attributes.remove(AttrTag::raw(TAG_COMMUNITIES));
        assert_eq!(
            run("if exists(bgp.communities) then accept; reject;", &mut r),
            EvalResult::Reject(None),
        );
    }

    #[test]
    fn defined_list_fields_present_only_when_nonempty() {
        // No AS_PATH / COMMUNITIES on a fresh route -> absent.
        let mut r = route_with("203.0.113.0/24", 100, 0);
        assert_eq!(
            run("if defined(bgp.as_path) then accept; reject;", &mut r),
            EvalResult::Reject(None),
        );
        // Prepending an AS makes the path present.
        assert_eq!(
            run(
                "bgp.as_path.prepend(65000); if defined(bgp.as_path) then accept; reject;",
                &mut r
            ),
            EvalResult::Accept,
        );
    }

    #[test]
    fn defined_never_false_for_readonly_core_fields() {
        let mut r = route_with("203.0.113.0/24", 100, 0);
        assert_eq!(
            run(
                "if defined(net) && defined(proto) then accept; reject;",
                &mut r
            ),
            EvalResult::Accept,
        );
    }

    #[test]
    fn defined_on_undefined_variable_is_false() {
        let mut r = route_with("203.0.113.0/24", 100, 0);
        // A variable never bound must report not-defined instead of
        // aborting the evaluation (which would fall through).
        assert_eq!(
            run("if defined(no_such_var) then accept; reject;", &mut r),
            EvalResult::Reject(None),
        );
        assert_eq!(
            run("let x = 1; if defined(x) then accept; reject;", &mut r),
            EvalResult::Accept,
        );
    }

    #[test]
    fn defined_requires_exactly_one_argument() {
        let f = compile("test", "if defined(bgp.med, bgp.local_pref) then accept;");
        assert!(f.is_err(), "two-arg defined() must fail to compile");
        let f = compile("test", "if defined() then accept;");
        assert!(f.is_err(), "zero-arg defined() must fail to compile");
    }

    // ===== D3.4 — delete / filter / empty / count =====

    fn communities_to(set: &[(u32, u16)]) -> Vec<(Asn, u16)> {
        set.iter().map(|(a, v)| (Asn(*a), *v)).collect()
    }

    /// Stamp a COMMUNITIES attribute onto a route (test helper).
    fn with_communities(mut r: Route, set: &[(u32, u16)]) -> Route {
        let cs = communities_to(set);
        let mut v = Vec::with_capacity(cs.len() * 4);
        for (a, val) in &cs {
            v.extend_from_slice(&(a.0 as u16).to_be_bytes());
            v.extend_from_slice(&val.to_be_bytes());
        }
        r.attributes.insert(Attribute {
            tag: AttrTag::raw(TAG_COMMUNITIES),
            flags: 0xC0,
            value: v,
        });
        r
    }

    #[test]
    fn method_delete_removes_exact_community() {
        let mut r = with_communities(
            route_with("203.0.113.0/24", 100, 0),
            &[(64512, 100), (64512, 200), (65000, 1)],
        );
        assert_eq!(
            run("bgp.communities.delete([64512:100]); accept;", &mut r),
            EvalResult::Accept,
        );
        let cs = StubCtx.bgp_communities(&r);
        assert_eq!(cs, communities_to(&[(64512, 200), (65000, 1)]));
    }

    #[test]
    fn method_delete_wildcard_removes_whole_asn() {
        let mut r = with_communities(
            route_with("203.0.113.0/24", 100, 0),
            &[(64512, 100), (64512, 200), (65000, 1)],
        );
        assert_eq!(
            run("bgp.communities.delete([64512:*]); accept;", &mut r),
            EvalResult::Accept,
        );
        assert_eq!(StubCtx.bgp_communities(&r), communities_to(&[(65000, 1)]));
    }

    #[test]
    fn method_filter_keeps_only_matches() {
        let mut r = with_communities(
            route_with("203.0.113.0/24", 100, 0),
            &[(64512, 100), (64512, 200), (65000, 1)],
        );
        assert_eq!(
            run("bgp.communities.filter([*:1]); accept;", &mut r),
            EvalResult::Accept,
        );
        assert_eq!(StubCtx.bgp_communities(&r), communities_to(&[(65000, 1)]));
    }

    #[test]
    fn delete_last_community_drops_attribute() {
        let mut r = with_communities(route_with("203.0.113.0/24", 100, 0), &[(64512, 100)]);
        assert_eq!(
            run(
                "bgp.communities.delete([64512:*]); if empty(bgp.communities) then accept; reject;",
                &mut r
            ),
            EvalResult::Accept,
        );
        assert!(r.attributes.get(AttrTag::raw(TAG_COMMUNITIES)).is_none());
    }

    #[test]
    fn bird_assignment_idiom_delete_into_attribute() {
        let mut r = with_communities(
            route_with("203.0.113.0/24", 100, 0),
            &[(64512, 100), (65000, 2)],
        );
        assert_eq!(
            run(
                "bgp.communities = delete(bgp.communities, [64512:*]); accept;",
                &mut r
            ),
            EvalResult::Accept,
        );
        assert_eq!(StubCtx.bgp_communities(&r), communities_to(&[(65000, 2)]));
    }

    #[test]
    fn as_path_delete_and_filter() {
        let mut r = route_with("203.0.113.0/24", 100, 0);
        assert_eq!(
            run(
                "bgp.as_path.prepend(65001); bgp.as_path.prepend(65002); bgp.as_path.prepend(65001); accept;",
                &mut r
            ),
            EvalResult::Accept,
        );
        assert_eq!(
            StubCtx.bgp_as_path(&r),
            vec![Asn(65001), Asn(65002), Asn(65001)]
        );
        assert_eq!(
            run("bgp.as_path.delete([65001]); accept;", &mut r),
            EvalResult::Accept,
        );
        assert_eq!(StubCtx.bgp_as_path(&r), vec![Asn(65002)]);
        assert_eq!(
            run(
                "bgp.as_path.filter([65003]); if empty(bgp.as_path) then accept; reject;",
                &mut r
            ),
            EvalResult::Accept,
        );
        assert!(StubCtx.bgp_as_path(&r).is_empty());
    }

    #[test]
    fn function_style_delete_filter_count_on_values() {
        let mut r = with_communities(
            route_with("203.0.113.0/24", 100, 0),
            &[(64512, 100), (64512, 200)],
        );
        // Pure-value form on a local variable (BIRD: `delete(x, [..])`).
        assert_eq!(
            run(
                "let cs = bgp.communities; let kept = delete(cs, [64512:100]); if count(kept) == 1 then accept; reject;",
                &mut r
            ),
            EvalResult::Accept,
        );
        assert_eq!(
            run(
                "let cs = bgp.communities; let kept = filter(cs, [64512:*]); if count(kept) == 2 then accept; reject;",
                &mut r
            ),
            EvalResult::Accept,
        );
        assert_eq!(
            run(
                "if count(bgp.communities) == 2 then accept; reject;",
                &mut r
            ),
            EvalResult::Accept,
        );
        assert_eq!(
            run(
                "let cs = bgp.communities; if empty(delete(cs, [64512:*])) then accept; reject;",
                &mut r
            ),
            EvalResult::Accept,
        );
    }

    #[test]
    fn wildcard_membership_now_matches() {
        // The `~` operator gained wildcard-pattern support alongside
        // the D3.4 pattern machinery.
        let mut r = with_communities(route_with("203.0.113.0/24", 100, 0), &[(64512, 100)]);
        assert_eq!(
            run(
                "if bgp.communities ~ [64512:*] then accept; reject;",
                &mut r
            ),
            EvalResult::Accept,
        );
        assert_eq!(
            run(
                "if bgp.communities ~ [65000:*] then accept; reject;",
                &mut r
            ),
            EvalResult::Reject(None),
        );
    }

    #[test]
    fn append_rejects_wildcard_pattern() {
        let mut r = route_with("203.0.113.0/24", 100, 0);
        assert_eq!(
            run("bgp.communities += [64512:*]; accept;", &mut r),
            EvalResult::Fallthrough,
        );
    }

    #[test]
    fn append_accepts_exact_pattern_literal() {
        // The set-literal shape changed to CommPattern items; `+=`
        // must keep accepting `asn:val` literals.
        let mut r = route_with("203.0.113.0/24", 100, 0);
        assert_eq!(
            run("bgp.communities += [64512:100]; accept;", &mut r),
            EvalResult::Accept,
        );
        assert_eq!(StubCtx.bgp_communities(&r), communities_to(&[(64512, 100)]));
    }

    // ===== D3.2 — large communities (RFC 8097) =====

    /// Stamp a LARGE_COMMUNITIES attribute onto a route (test helper).
    fn with_large(mut r: Route, set: &[(u32, u32, u32)]) -> Route {
        let cs: Vec<lr_bgp::path::communities::LargeCommunity> = set
            .iter()
            .map(|(g, d1, d2)| lr_bgp::path::communities::LargeCommunity::new(*g, *d1, *d2))
            .collect();
        r.attributes.insert(Attribute {
            tag: AttrTag::raw(TAG_LARGE_COMMUNITIES),
            flags: 0xC0,
            value: lr_bgp::path::communities::LargeCommunity::encode_set(&cs),
        });
        r
    }

    #[test]
    fn large_communities_append_and_read_back() {
        let mut r = route_with("203.0.113.0/24", 100, 0);
        assert_eq!(
            run("bgp.large_communities += [64512:100:200]; accept;", &mut r),
            EvalResult::Accept,
        );
        assert_eq!(StubCtx.bgp_large_communities(&r), vec![(64512, 100, 200)]);
        // Wire form must be the 12-byte RFC 8097 record.
        let raw = r
            .attributes
            .get(AttrTag::raw(TAG_LARGE_COMMUNITIES))
            .unwrap();
        assert_eq!(raw.value.len(), 12);
        assert_eq!(raw.value[..4], [0x00, 0x00, 0xFC, 0x00]);
    }

    #[test]
    fn large_communities_dedup_and_delete_filter() {
        let mut r = route_with("203.0.113.0/24", 100, 0);
        assert_eq!(
            run(
                "bgp.large_communities += [64512:100:200, 64512:100:200, 65000:1:2]; accept;",
                &mut r
            ),
            EvalResult::Accept,
        );
        assert_eq!(
            StubCtx.bgp_large_communities(&r),
            vec![(64512, 100, 200), (65000, 1, 2)],
        );
        assert_eq!(
            run(
                "bgp.large_communities.delete([64512:100:200]); accept;",
                &mut r
            ),
            EvalResult::Accept,
        );
        assert_eq!(StubCtx.bgp_large_communities(&r), vec![(65000, 1, 2)]);
        assert_eq!(
            run(
                "bgp.large_communities.filter([65000:1:2]); if empty(bgp.large_communities) == false then accept; reject;",
                &mut r
            ),
            EvalResult::Accept,
        );
        assert_eq!(StubCtx.bgp_large_communities(&r), vec![(65000, 1, 2)]);
    }

    #[test]
    fn large_communities_membership_and_4octet_asn() {
        // 4-octet ASNs fit without AS_TRANS (RFC 8097 §1 motivation).
        let mut r = route_with("203.0.113.0/24", 100, 0);
        assert_eq!(
            run(
                "bgp.large_communities += [4200000000:7:9]; if bgp.large_communities ~ [4200000000:7:9] then accept; reject;",
                &mut r
            ),
            EvalResult::Accept,
        );
        assert_eq!(StubCtx.bgp_large_communities(&r), vec![(4200000000, 7, 9)],);
    }

    #[test]
    fn large_communities_assignment_idiom() {
        let mut r = with_large(
            route_with("203.0.113.0/24", 100, 0),
            &[(64512, 100, 200), (65000, 1, 2)],
        );
        assert_eq!(
            run(
                "bgp.large_communities = delete(bgp.large_communities, [64512:100:200]); accept;",
                &mut r
            ),
            EvalResult::Accept,
        );
        assert_eq!(StubCtx.bgp_large_communities(&r), vec![(65000, 1, 2)]);
    }

    // ===== D3.3 — extended communities (RFC 4360) =====

    #[test]
    fn ext_communities_tuple_literal_appends() {
        let mut r = route_with("203.0.113.0/24", 100, 0);
        assert_eq!(
            run(
                "bgp.ext_communities += [(rt, 4200000000, 100)]; accept;",
                &mut r
            ),
            EvalResult::Accept,
        );
        // Route Target: transitive (0x40) 4-octet-AS specific (0x02),
        // subtype 0x02 — the canonical BIRD wire form.
        assert_eq!(
            StubCtx.bgp_ext_communities(&r),
            vec![(0x42, 0x02, 4200000000, 100)],
        );
        // IPv4 administrator form.
        assert_eq!(
            run(
                "bgp.ext_communities += [(rt, 192.0.2.1, 5)]; accept;",
                &mut r
            ),
            EvalResult::Accept,
        );
        assert_eq!(
            StubCtx.bgp_ext_communities(&r)[1],
            (0x41, 0x02, 0xC000_0201, 5),
        );
    }

    #[test]
    fn ext_communities_ro_soo_names_map_to_subtype_3() {
        let mut r = route_with("203.0.113.0/24", 100, 0);
        assert_eq!(
            run(
                "bgp.ext_communities += [(ro, 65000, 1), (soo, 65001, 2)]; accept;",
                &mut r
            ),
            EvalResult::Accept,
        );
        let cs = StubCtx.bgp_ext_communities(&r);
        assert_eq!(cs[0], (0x42, 0x03, 65000, 1));
        assert_eq!(cs[1], (0x42, 0x03, 65001, 2));
    }

    #[test]
    fn ext_communities_delete_filter_membership() {
        let mut r = route_with("203.0.113.0/24", 100, 0);
        assert_eq!(
            run(
                "bgp.ext_communities += [(rt, 65000, 1), (rt, 65001, 2)]; if bgp.ext_communities ~ [(rt, 65000, 1)] then accept; reject;",
                &mut r
            ),
            EvalResult::Accept,
        );
        assert_eq!(
            run(
                "bgp.ext_communities.delete([(rt, 65000, 1)]); accept;",
                &mut r
            ),
            EvalResult::Accept,
        );
        assert_eq!(
            StubCtx.bgp_ext_communities(&r),
            vec![(0x42, 0x02, 65001, 2)],
        );
        assert_eq!(
            run(
                "bgp.ext_communities.filter([(rt, 65009, 9)]); if empty(bgp.ext_communities) then accept; reject;",
                &mut r
            ),
            EvalResult::Accept,
        );
        assert!(StubCtx.bgp_ext_communities(&r).is_empty());
    }

    #[test]
    fn ext_communities_reject_v6_admin_and_bad_local() {
        let f = compile("test", "bgp.ext_communities += [(rt, 2001:db8::1, 1)];");
        assert!(f.is_err(), "IPv6 administrator form must be rejected");
        let f = compile("test", "bgp.ext_communities += [(rt, 65000, 70000)];");
        assert!(f.is_err(), "local part above u16::MAX must be rejected");
    }

    #[test]
    fn defined_works_for_community_attributes() {
        // D3.5 interplay: the new list attributes report presence.
        let mut r = route_with("203.0.113.0/24", 100, 0);
        assert_eq!(
            run(
                "if defined(bgp.large_communities) then accept; reject;",
                &mut r
            ),
            EvalResult::Reject(None),
        );
        assert_eq!(
            run(
                "bgp.large_communities += [64512:1:2]; if defined(bgp.large_communities) then accept; reject;",
                &mut r
            ),
            EvalResult::Accept,
        );
    }

    // ===== D3.1 — user-defined functions =====

    #[test]
    fn user_function_returns_value() {
        let mut r = route_with("203.0.113.0/24", 100, 0);
        assert_eq!(
            run(
                "function double(n) { return n * 2; } if bgp.local_pref >= double(50) then accept; reject;",
                &mut r
            ),
            EvalResult::Accept,
        );
        assert_eq!(
            run(
                "function double(n) { return n * 2; } if bgp.local_pref >= double(51) then accept; reject;",
                &mut r
            ),
            EvalResult::Reject(None),
        );
    }

    #[test]
    fn user_function_multiple_params_and_scoping() {
        let mut r = route_with("203.0.113.0/24", 100, 0);
        assert_eq!(
            run(
                "function clamp(v, lo, hi) { if v < lo then return lo; if v > hi then return hi; return v; } bgp.local_pref = clamp(bgp.local_pref, 150, 200); if bgp.local_pref == 150 then accept; reject;",
                &mut r
            ),
            EvalResult::Accept,
        );
    }

    #[test]
    fn user_function_mutates_route_bird_parity() {
        let mut r = route_with("203.0.113.0/24", 100, 0);
        // BIRD functions are the primary structuring tool for route
        // mutation; the body must run on the caller's route.
        assert_eq!(
            run(
                "function tag_transit() { bgp.local_pref = 50; bgp.communities += [64512:100]; } tag_transit(); if bgp.local_pref == 50 && bgp.communities ~ [64512:100] then accept; reject;",
                &mut r
            ),
            EvalResult::Accept,
        );
    }

    #[test]
    fn accept_inside_function_terminates_filter() {
        let mut r = route_with("203.0.113.0/24", 100, 0);
        assert_eq!(
            run(
                "function gated() { if bgp.local_pref > 50 then accept; return false; } gated(); reject;",
                &mut r
            ),
            EvalResult::Accept,
        );
        // reject inside a function likewise wins.
        let mut r2 = route_with("203.0.113.0/24", 10, 0);
        assert_eq!(
            run(
                "function gated() { if bgp.local_pref < 50 then reject; return true; } gated(); accept;",
                &mut r2
            ),
            EvalResult::Reject(None),
        );
    }

    #[test]
    fn bare_return_and_fallthrough_yield_false() {
        let mut r = route_with("203.0.113.0/24", 100, 0);
        assert_eq!(
            run(
                "function bare() { return; } if bare() == false then accept; reject;",
                &mut r
            ),
            EvalResult::Accept,
        );
        assert_eq!(
            run(
                "function no_return() { let x = 1; } if no_return() == false then accept; reject;",
                &mut r
            ),
            EvalResult::Accept,
        );
    }

    #[test]
    fn runaway_recursion_is_bounded() {
        let mut r = route_with("203.0.113.0/24", 100, 0);
        // spin() calls itself forever; the depth limiter must abort
        // evaluation (Fallthrough), not smash the stack.
        assert_eq!(
            run("function spin() { return spin(); } spin(); accept;", &mut r),
            EvalResult::Fallthrough,
        );
    }

    #[test]
    fn top_level_return_is_fallthrough() {
        let mut r = route_with("203.0.113.0/24", 100, 0);
        assert_eq!(run("return true;", &mut r), EvalResult::Fallthrough);
    }

    #[test]
    fn duplicate_or_shadowing_functions_rejected() {
        let f = compile(
            "test",
            "function f() { return 1; } function f() { return 2; } accept;",
        );
        assert!(f.is_err(), "duplicate function name must fail");
        let f = compile("test", "function len(x) { return 1; } accept;");
        assert!(f.is_err(), "shadowing a built-in must fail");
    }

    #[test]
    fn unknown_call_fails_at_compile_time() {
        let f = compile("test", "if no_such_fn(1) then accept; reject;");
        assert!(f.is_err(), "undeclared call must fail to compile");
        // ...including inside function bodies.
        let f = compile("test", "function g() { return also_missing(); } accept;");
        assert!(f.is_err(), "undeclared call in a function body must fail");
    }

    #[test]
    fn builtin_function_list_matches_evaluator() {
        // The parser's BUILTIN_FUNCTIONS gate and the evaluator's
        // built-in table must agree: every listed name must compile
        // with a plausible arity (here: via a call that survives
        // compilation).
        for name in crate::filter::parser::BUILTIN_FUNCTIONS {
            let src = format!("if {name}(1) then accept; reject;");
            let compiled = compile("test", &src);
            // arity errors are runtime (BadArgCount), so compilation
            // must succeed for every built-in name.
            assert!(compiled.is_ok(), "built-in '{name}' rejected by the parser");
        }
    }
}
