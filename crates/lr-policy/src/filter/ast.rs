//! AST types for the BIRD-like filter DSL.
//!
//! The AST is the contract between the parser and the evaluator.
//! Every node is `Clone + Send + Sync` so a compiled [`Filter`] can
//! be shared across sessions.

use core::fmt;

use lr_core::addr::{Asn, IpAddr, Prefix};
use lr_core::rib::Protocol;

use crate::filter::eval::RoaStateLit;

/// A compiled filter: its name (referenced by `[[peer]] import_filter`
/// / `export_filter`) and the body AST.
#[derive(Debug, Clone)]
pub struct Filter {
    /// Filter name — the key the operator references from peers.
    pub name: String,
    /// Body — the top-level statement list.
    pub body: FilterBody,
}

/// A list of statements executed in order; the first `accept` /
/// `reject` exits with that verdict, otherwise the filter falls
/// through (returns [`crate::filter::eval::EvalResult::Fallthrough`]).
#[derive(Debug, Clone, Default)]
pub struct FilterBody {
    pub stmts: Vec<Stmt>,
}

/// A statement — the imperative side of the DSL.
#[derive(Debug, Clone)]
pub enum Stmt {
    /// `if cond { ... }` or `if cond { ... } else { ... }`.
    If {
        cond: Expr,
        then: Box<Stmt>,
        els: Option<Box<Stmt>>,
    },
    /// `case expr { pat => stmt; ... default => stmt; }`.
    Case { scrutinee: Expr, arms: Vec<CaseArm> },
    /// `let name = expr;` — introduce a new variable in scope.
    Let { name: String, value: Expr },
    /// `name = expr;` — reassign a variable introduced by `let`.
    Assign { name: String, value: Expr },
    /// `route.attr = expr;` — write a settable route attribute.
    AssignRouteField { field: RouteField, value: Expr },
    /// `route.attr += expr;` — append to a settable list-like
    /// attribute (currently only `bgp.communities`).
    AppendRouteField { field: RouteField, value: Expr },
    /// `expr;` — evaluate the expression for side effects (e.g. a
    /// method call like `bgp.as_path.prepend(65001)`).
    Expr(Expr),
    /// A nested block `{ ... }` — introduces a new scope.
    Block(Vec<Stmt>),
    /// `accept;` — terminate the filter with `Accept`.
    Accept,
    /// `reject;` or `reject "reason";` — terminate with `Reject(reason)`.
    Reject(Option<Expr>),
}

/// One arm of a `case` statement: the pattern(s) and the body.
#[derive(Debug, Clone)]
pub struct CaseArm {
    /// Pattern values; `None` means the `default` arm. Multiple
    /// patterns separated by `,` share one body.
    pub patterns: Vec<Expr>,
    pub body: Vec<Stmt>,
}

/// An expression — the functional side of the DSL.
#[derive(Debug, Clone)]
pub enum Expr {
    /// A literal value: integer, string, IP, prefix, boolean, ASN.
    Lit(Value),
    /// A variable reference — looked up in the current scope.
    Var(String),
    /// A route field access: `net`, `bgp.local_pref`, `proto`, etc.
    RouteField(RouteField),
    /// A function call: `name(arg, arg, ...)`.
    Call { name: String, args: Vec<Expr> },
    /// A method call: `obj.method(arg, arg, ...)`. Used for
    /// `bgp.as_path.prepend(...)`, `bgp.communities.add(...)`.
    Method {
        receiver: Box<Expr>,
        method: String,
        args: Vec<Expr>,
    },
    /// Binary operator application: `a + b`, `a == b`, `a && b`, etc.
    Binary {
        op: BinaryOp,
        lhs: Box<Expr>,
        rhs: Box<Expr>,
    },
    /// Unary operator application: `!x`, `-x`.
    Unary { op: UnaryOp, expr: Box<Expr> },
    /// A set literal: `[ 10.0.0.0/8, 192.0.2.0/24 ]`. Used with
    /// `~` for prefix / AS-path / community membership.
    Set(Vec<Expr>),
    /// A prefix with optional range: `10.0.0.0/8{16,24}`. The
    /// range is `[ge, le]` — BIRD's `{minlen, maxlen}` syntax. When
    /// `None` the prefix length is exact.
    PrefixSet {
        prefix: Prefix,
        ge: Option<u8>,
        le: Option<u8>,
    },
}

/// A literal value — what every expression reduces to at evaluation
/// time.
#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    /// 64-bit signed integer — covers BGP local-pref, MED, prefix
    /// lengths, AS numbers (the DSL treats AS as integers; the
    /// evaluator narrows to u32 when calling into `lr-bgp`).
    Int(i64),
    /// Boolean — `true` / `false`.
    Bool(bool),
    /// String literal — e.g. a reject reason or a protocol name.
    Str(String),
    /// An IP address — `bgp.next_hop`, `bgp.local_address`, etc.
    Ip(IpAddr),
    /// A prefix — `net`, `prefix.set`, etc.
    Prefix(Prefix),
    /// An ASN — `bgp.as_path.first`, `bgp.origin`, etc.
    Asn(Asn),
    /// An AS_PATH — a flat sequence of AS numbers (sets flattened).
    AsPath(Vec<Asn>),
    /// A community set — list of `(asn, value)` pairs.
    Communities(Vec<(Asn, u16)>),
    /// A generic set — used for prefix sets and AS-path sets in
    /// membership tests (`net ~ [ 10.0.0.0/8, 192.0.2.0/24 ]`).
    /// Each element retains its original type (Prefix, Asn, Int).
    Set(Vec<Value>),
    /// A protocol kind — `proto == "bgp"`.
    Protocol(Protocol),
    /// A ROA state — `roa.state`.
    RoaState(RoaStateLit),
}

impl Value {
    /// Type name used in error messages.
    pub fn type_name(&self) -> &'static str {
        match self {
            Value::Int(_) => "int",
            Value::Bool(_) => "bool",
            Value::Str(_) => "string",
            Value::Ip(_) => "ip",
            Value::Prefix(_) => "prefix",
            Value::Asn(_) => "asn",
            Value::AsPath(_) => "as-path",
            Value::Communities(_) => "community-set",
            Value::Set(_) => "set",
            Value::Protocol(_) => "protocol",
            Value::RoaState(_) => "roa-state",
        }
    }

    /// Truthiness for `if` conditions and `&&` / `||`. `int != 0`,
    /// `bool`, non-empty `string`/`as-path`/`community-set`/`set`,
    /// any `ip`/`prefix`/`asn`/`protocol`/`roa-state` are truthy.
    pub fn truthy(&self) -> bool {
        match self {
            Value::Int(i) => *i != 0,
            Value::Bool(b) => *b,
            Value::Str(s) => !s.is_empty(),
            Value::Ip(_) | Value::Prefix(_) | Value::Asn(_) | Value::Protocol(_) => true,
            Value::RoaState(_) => true,
            Value::AsPath(v) => !v.is_empty(),
            Value::Communities(v) => !v.is_empty(),
            Value::Set(v) => !v.is_empty(),
        }
    }
}

impl fmt::Display for Value {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Value::Int(i) => write!(f, "{i}"),
            Value::Bool(b) => write!(f, "{b}"),
            Value::Str(s) => write!(f, "\"{s}\""),
            Value::Ip(ip) => write!(f, "{ip}"),
            Value::Prefix(p) => write!(f, "{p}"),
            Value::Asn(a) => write!(f, "AS{}", a.0),
            Value::AsPath(v) => {
                write!(f, "[")?;
                for (i, a) in v.iter().enumerate() {
                    if i > 0 {
                        write!(f, " ")?;
                    }
                    write!(f, "AS{}", a.0)?;
                }
                write!(f, "]")
            }
            Value::Communities(v) => {
                write!(f, "[")?;
                for (i, (asn, val)) in v.iter().enumerate() {
                    if i > 0 {
                        write!(f, " ")?;
                    }
                    write!(f, "{}:{}", asn.0, val)?;
                }
                write!(f, "]")
            }
            Value::Set(v) => {
                write!(f, "[")?;
                for (i, x) in v.iter().enumerate() {
                    if i > 0 {
                        write!(f, " ")?;
                    }
                    write!(f, "{x}")?;
                }
                write!(f, "]")
            }
            Value::Protocol(p) => write!(f, "{:?}", p),
            Value::RoaState(s) => write!(f, "{}", s.as_str()),
        }
    }
}

/// A binary operator. Precedence follows the BIRD filter grammar:
/// `||` < `&&` < `==`/`!=` < `<`/`<=`/`>`/`>=`/`~` < `|` < `^` < `&`
/// < `<<`/`>>` < `+`/`-` < `*`/`/`/`%`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BinaryOp {
    Add,
    Sub,
    Mul,
    Div,
    Mod,
    /// `==` — equality.
    Eq,
    /// `!=` — inequality.
    Ne,
    Lt,
    Le,
    Gt,
    Ge,
    /// `&&` — logical AND (short-circuit).
    And,
    /// `||` — logical OR (short-circuit).
    Or,
    /// `&` — bitwise AND on integers.
    BitAnd,
    /// `|` — bitwise OR on integers.
    BitOr,
    /// `^` — bitwise XOR on integers.
    BitXor,
    /// `<<` — left shift.
    Shl,
    /// `>>` — arithmetic right shift.
    Shr,
    /// `~` — set membership / regex match.
    Match,
    /// `!~` — negation of `~`.
    NotMatch,
}

impl BinaryOp {
    /// Precedence level — higher binds tighter. Matches BIRD's
    /// `filter/config.Y` rule layering.
    pub fn precedence(self) -> u8 {
        match self {
            BinaryOp::Or => 1,
            BinaryOp::And => 2,
            BinaryOp::Eq | BinaryOp::Ne => 3,
            BinaryOp::Lt
            | BinaryOp::Le
            | BinaryOp::Gt
            | BinaryOp::Ge
            | BinaryOp::Match
            | BinaryOp::NotMatch => 4,
            BinaryOp::BitOr => 5,
            BinaryOp::BitXor => 6,
            BinaryOp::BitAnd => 7,
            BinaryOp::Shl | BinaryOp::Shr => 8,
            BinaryOp::Add | BinaryOp::Sub => 9,
            BinaryOp::Mul | BinaryOp::Div | BinaryOp::Mod => 10,
        }
    }

    /// Right-associative operators (currently none — the DSL has no
    /// `**` exponent). Left-associativity is the default in
    /// [`crate::filter::parser::Parser::parse_binary`].
    pub fn right_associative(self) -> bool {
        false
    }
}

/// Unary operators: `!` (logical not) and `-` (numeric negation).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnaryOp {
    Not,
    Neg,
}

/// A route field reference — what `bgp.local_pref`, `net`,
/// `bgp.as_path`, etc. compile down to. The evaluator matches on
/// this enum to dispatch to the typed accessor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RouteField {
    pub kind: RouteFieldKind,
}

impl RouteField {
    pub const fn new(kind: RouteFieldKind) -> Self {
        Self { kind }
    }
}

/// The kind of a route field. The other variants directly name the
/// field; assignment is restricted by the parser to the settable
/// subset (see [`RouteFieldKind::is_settable`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RouteFieldKind {
    /// `net` — the route's prefix. Read-only.
    Net,
    /// `proto` — the route's protocol kind (BGP, OSPF, Babel, ...).
    /// Read-only.
    Proto,
    /// `source` — the route's source. Read-only.
    Source,
    /// `bgp.local_pref` — the BGP LOCAL_PREF path attribute.
    /// Settable via `bgp.local_pref = N;`.
    BgpLocalPref,
    /// `bgp.med` — the BGP MULTI_EXIT_DISC path attribute.
    /// Settable.
    BgpMed,
    /// `bgp.next_hop` — the BGP NEXT_HOP. Settable.
    BgpNextHop,
    /// `bgp.as_path` — the BGP AS_PATH (read-only as a sequence;
    /// use `bgp.as_path.prepend(asn)` to mutate).
    BgpAsPath,
    /// `bgp.communities` — the BGP community set. Appendable via
    /// `bgp.communities += [ asn:value ];`.
    BgpCommunities,
    /// `bgp.origin` — the BGP ORIGIN attribute.
    BgpOrigin,
    /// `roa.state` — the RFC 6811 validation outcome for the
    /// route's prefix + origin AS. Read-only.
    RoaState,
}

impl RouteFieldKind {
    /// True when the field is writable from the DSL.
    pub fn is_settable(self) -> bool {
        matches!(
            self,
            RouteFieldKind::BgpLocalPref
                | RouteFieldKind::BgpMed
                | RouteFieldKind::BgpNextHop
                | RouteFieldKind::BgpCommunities
        )
    }
}

impl fmt::Display for RouteFieldKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            RouteFieldKind::Net => "net",
            RouteFieldKind::Proto => "proto",
            RouteFieldKind::Source => "source",
            RouteFieldKind::BgpLocalPref => "bgp.local_pref",
            RouteFieldKind::BgpMed => "bgp.med",
            RouteFieldKind::BgpNextHop => "bgp.next_hop",
            RouteFieldKind::BgpAsPath => "bgp.as_path",
            RouteFieldKind::BgpCommunities => "bgp.communities",
            RouteFieldKind::BgpOrigin => "bgp.origin",
            RouteFieldKind::RoaState => "roa.state",
        };
        f.write_str(s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn value_type_names() {
        assert_eq!(Value::Int(0).type_name(), "int");
        assert_eq!(Value::Bool(false).type_name(), "bool");
        assert_eq!(Value::Str("x".into()).type_name(), "string");
    }

    #[test]
    fn value_truthiness() {
        assert!(Value::Int(1).truthy());
        assert!(!Value::Int(0).truthy());
        assert!(Value::Bool(true).truthy());
        assert!(!Value::Bool(false).truthy());
        assert!(Value::Str("nonempty".into()).truthy());
        assert!(!Value::Str("".into()).truthy());
        assert!(!Value::AsPath(vec![]).truthy());
        assert!(Value::AsPath(vec![Asn(65000)]).truthy());
    }

    #[test]
    fn binary_op_precedence_increases_through_arithmetic() {
        assert!(BinaryOp::Mul.precedence() > BinaryOp::Add.precedence());
        assert!(BinaryOp::Add.precedence() > BinaryOp::Eq.precedence());
        assert!(BinaryOp::Eq.precedence() > BinaryOp::And.precedence());
        assert!(BinaryOp::And.precedence() > BinaryOp::Or.precedence());
    }

    #[test]
    fn settable_fields_are_a_subset() {
        assert!(RouteFieldKind::BgpLocalPref.is_settable());
        assert!(RouteFieldKind::BgpMed.is_settable());
        assert!(RouteFieldKind::BgpNextHop.is_settable());
        assert!(RouteFieldKind::BgpCommunities.is_settable());
        assert!(!RouteFieldKind::Net.is_settable());
        assert!(!RouteFieldKind::Proto.is_settable());
        assert!(!RouteFieldKind::BgpAsPath.is_settable());
        assert!(!RouteFieldKind::RoaState.is_settable());
    }

    #[test]
    fn route_field_kind_display_matches_dsl_syntax() {
        assert_eq!(RouteFieldKind::Net.to_string(), "net");
        assert_eq!(RouteFieldKind::BgpLocalPref.to_string(), "bgp.local_pref");
        assert_eq!(RouteFieldKind::RoaState.to_string(), "roa.state");
    }
}
