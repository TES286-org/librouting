//! BIRD-like filter DSL — lexer, AST, parser, evaluator.
//!
//! The grammar targets a subset of BIRD's filter language expressive
//! enough for production import/export policy:
//!
//! - `if`/`then`/`else` conditionals with block statements,
//! - `let` variable bindings (mutable `let`),
//! - arithmetic (`+ - * / %`), comparison (`== != < <= > >=`),
//!   boolean (`&& || !`), bitwise (`& | ^ << >>`) operators,
//! - prefix set membership (`net ~ [ 10.0.0.0/8{8,24} ]`),
//! - AS-path / community set membership,
//! - route attribute access (`net`, `bgp.local_pref`, `bgp.as_path`,
//!   `bgp.communities`, `bgp.next_hop`, `bgp.med`, `proto`,
//!   `roa.state`, ...),
//! - assignment to settable attributes (`bgp.local_pref = 200`,
//!   `bgp.communities += [ 64512:100 ]`, `bgp.as_path.prepend(65001)`),
//! - `accept`, `reject` (with optional reason) terminal statements,
//! - `case`/`switch` over scalar types,
//! - function calls: `len(bgp.as_path)`, `bgp.first_as`, `bgp.contains(65000)`.
//!
//! The lexer is hand-rolled (no regex dependency) and the parser is
//! a Pratt-style expression parser with recursive descent for
//! statements. The evaluator is a tree-walking interpreter with a
//! scoped variable stack.

pub mod ast;
pub mod bytecode;
pub mod eval;
pub mod lexer;
pub mod parser;
pub mod peephole;

pub use ast::{
    BinaryOp, Expr, Filter, FilterBody, RouteField, RouteFieldKind, Stmt, UnaryOp, Value,
};
pub use eval::{EvalError, EvalResult, FilterContext, RoaStateLit};
pub use lexer::{Lexer, LexerError, Token, TokenKind};
pub use parser::{ParseError, Parser};

/// Compile a filter source string into an executable [`Filter`].
///
/// Convenience entry point used by `daemon_policy::build_policy_set`
/// and the FFI layer. Returns the compiled filter on success or the
/// first parse error (with a 1-indexed line/column) on failure.
pub fn compile(name: &str, body: &str) -> Result<Filter, ParseError> {
    let mut p = Parser::new(body);
    p.parse_filter(name)
}

/// Evaluate a compiled filter against a route through the supplied
/// [`FilterContext`]. Returns `Accept`, `Reject` (with an optional
/// reason string), or `Fallthrough` (no terminal statement hit).
pub fn evaluate(
    filter: &Filter,
    route: &mut lr_core::rib::Route,
    ctx: &dyn FilterContext,
) -> EvalResult {
    eval::evaluate(filter, route, ctx)
}
