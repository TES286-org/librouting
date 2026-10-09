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
            RouteFieldKind::RoaState => Ok(Value::RoaState(self.ctx.roa_state(route))),
        }
    }

    /// Read an integer-typed route field directly as an `i64`,
    /// skipping the `Value::Int` construction. Used by the fused
    /// `Instr::BranchFieldIntCmp` (GitHub #19 P6) to avoid the
    /// 32-byte `Value` allocation + `Vec::push` the unfused
    /// `LoadField; Push; Bin; JumpIf*` sequence pays. Only the
    /// four integer kinds (`Source`, `BgpLocalPref`, `BgpMed`,
    /// `BgpOrigin`) reach this path — the peephole pass's
    /// `is_int_field` gate guarantees it. The `unwrap_or(0)`
    /// semantics for absent attributes mirror `read_route_field`
    /// exactly so the fused and unfused paths agree for every
    /// route.
    fn read_int_route_field(&self, field: &RouteField, route: &Route) -> Result<i64, EvalError> {
        Ok(match field.kind {
            RouteFieldKind::Source => i64::from(route.origin.proto),
            RouteFieldKind::BgpLocalPref => self.ctx.bgp_local_pref(route).unwrap_or(0) as i64,
            RouteFieldKind::BgpMed => self.ctx.bgp_med(route).unwrap_or(0) as i64,
            RouteFieldKind::BgpOrigin => i64::from(self.ctx.bgp_origin(route).unwrap_or(0)),
            // The peephole pass's `is_int_field` gate guarantees
            // one of the four arms above; the unreachable arms
            // are listed so the match is exhaustive over
            // `RouteFieldKind` and stays compilable if a new
            // field kind is added later (the gate would still
            // refuse to fuse it).
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
