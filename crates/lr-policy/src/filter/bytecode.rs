//! Bytecode compiler + stack VM for the filter DSL (ROADMAP-v3 D3.7).
//!
//! The tree-walking interpreter re-dispatches on the AST for every
//! import/export evaluation. BIRD compiles its filters to `f_line`
//! bytecode for the same reason this module exists: the hot path is a
//! flat `Vec<Instruction>` executed by a stack VM loop with
//! pre-lifted constants and direct jumps, which avoids the recursive
//! enum dispatch entirely for the common shapes.
//!
//! Design notes:
//!
//! * Compilation is *total* — every AST shape compiles. Shapes with
//!   dynamic behaviour that has no bytecode representation (non-constant
//!   match patterns, `defined()` over arbitrary expressions) compile to
//!   a fallback instruction that calls the tree-walking helper on that
//!   subtree, so the two engines can never disagree.
//! * The VM shares the [`crate::filter::eval::Evaluator`] state (scope
//!   stack, user functions, call-depth counter), so `let` scoping,
//!   D3.1 call semantics and the route-mutation behaviour are
//!   bit-identical with the interpreter.
//! * `accept` / `reject` inside a user-function body latch a pending
//!   verdict exactly like the interpreter (BIRD `f_cmd` semantics).

use std::collections::BTreeMap;

use lr_core::addr::Prefix;

use crate::filter::ast::{BinaryOp, Expr, Filter, RouteField, Stmt, UnaryOp, Value};

pub use crate::filter::eval::execute;

/// A compiled user function: parameter names plus a flat code slice.
#[derive(Debug, Clone)]
pub struct CompiledFunction {
    pub params: Vec<String>,
    pub code: Vec<Instr>,
}

/// One match-pattern item — the right-hand side of `~`.
#[derive(Debug, Clone)]
pub enum MatchItem {
    /// A constant item (community literal, AS number, ...).
    Value(Value),
    /// `10.0.0.0/8{16,24}` — the range lives in the AST, not the Value.
    PrefixSet {
        prefix: Prefix,
        ge: Option<u8>,
        le: Option<u8>,
    },
    /// A dynamic item the compiler could not lift — evaluated by the
    /// tree-walker at run time.
    Expr(Expr),
}

/// The compiled right-hand side of a `~` / `!~` test.
#[derive(Debug, Clone)]
pub enum MatchRhs {
    /// A single constant pattern.
    Value(Value),
    /// A set literal (the common BIRD shape: `[ 10.0.0.0/8, ... ]`).
    Set(Vec<MatchItem>),
    /// Fully dynamic fallback — the tree-walking `eval_match`.
    Expr(Expr),
}

/// `defined()` targets. `defined()` must observe *presence*, not the
/// (default-collapsed) value, so its argument is never evaluated in
/// the ordinary sense.
#[derive(Debug, Clone)]
pub enum DefinedTarget {
    /// A route attribute — presence via the typed accessors.
    Field(RouteField),
    /// A scope variable — presence via the scope stack.
    Var(String),
    /// A literal is always defined.
    Literal,
    /// Any other expression — probed against a route copy by the
    /// tree-walker (identical to the interpreter's fallback).
    Dynamic(Expr),
}

/// One VM instruction.
#[derive(Debug, Clone)]
pub enum Instr {
    /// Push a constant.
    Push(Value),
    /// Look up a variable (runtime error when unbound).
    LoadVar(String),
    /// Read a route attribute.
    LoadField(RouteField),
    /// `let name = expr;` — bind in the current scope.
    StoreVar(String),
    /// `name = expr;` — reassign through the scope stack.
    AssignVar(String),
    /// Store the case scrutinee in the temp slot.
    StoreTmp,
    /// Load the case scrutinee from the temp slot.
    LoadTmp,
    /// Apply a binary operator to the top two stack values.
    Bin(BinaryOp),
    /// `!x` — truthiness negation.
    Not,
    /// `-x` — integer negation.
    Neg,
    /// Pop a condition, jump when falsy.
    JumpIfFalse(usize),
    /// Pop a condition, jump when truthy.
    JumpIfTrue(usize),
    /// Unconditional jump.
    Jump(usize),
    /// Pop a value, push its truthiness as a `Bool`.
    Truthy,
    /// `~` / `!~` — membership test against a compiled pattern.
    Match { negated: bool, rhs: MatchRhs },
    /// `defined(x)` / `exists(x)`.
    Defined(DefinedTarget),
    /// Call a built-in or user function with `argc` stack arguments.
    Call { name: String, argc: usize },
    /// Method call on a route field (`bgp.as_path.prepend`, ...).
    Method {
        field: RouteField,
        method: String,
        argc: usize,
    },
    /// `route.attr = expr;` — the value is on the stack.
    AssignField(RouteField),
    /// `route.attr += expr;` — the value is on the stack.
    AppendField(RouteField),
    /// Discard the top of the stack (expression statements).
    Pop,
    /// Open a block scope.
    PushScope,
    /// Close a block scope.
    PopScope,
    /// Terminate with `Accept`.
    Accept,
    /// Terminate with `Reject`. `from_stack` pops the reason value.
    Reject { from_stack: bool },
    /// Return from a user function with the popped value.
    Return,
    /// Tree-walking fallback for a dynamic expression subtree: pushes
    /// the evaluated value.
    EvalTree(Expr),
}

/// A compiled filter: flat code plus compiled user functions.
#[derive(Debug, Clone)]
pub struct CompiledFilter {
    pub name: String,
    pub code: Vec<Instr>,
    pub functions: BTreeMap<String, CompiledFunction>,
}

/// Compile a parsed filter to bytecode. Infallible: every AST shape
/// has a bytecode representation or a tree-walking fallback.
pub fn compile(filter: &Filter) -> CompiledFilter {
    let c = Compiler;
    let mut code = Vec::new();
    c.compile_stmts(&filter.body.stmts, &mut code);
    let mut functions = BTreeMap::new();
    for f in &filter.functions {
        let mut code = Vec::new();
        c.compile_stmts(&f.body.stmts, &mut code);
        code.push(Instr::Return);
        functions.insert(
            f.name.clone(),
            CompiledFunction {
                params: f.params.clone(),
                code,
            },
        );
    }
    CompiledFilter {
        name: filter.name.clone(),
        code,
        functions,
    }
}

#[derive(Default)]
struct Compiler;

impl Compiler {
    fn compile_stmts(&self, stmts: &[Stmt], out: &mut Vec<Instr>) {
        for s in stmts {
            self.compile_stmt(s, out);
        }
    }

    fn compile_stmt(&self, stmt: &Stmt, out: &mut Vec<Instr>) {
        match stmt {
            Stmt::Return(value) => match value {
                Some(e) => {
                    self.compile_expr(e, out);
                    out.push(Instr::Return);
                }
                None => {
                    out.push(Instr::Push(Value::Bool(false)));
                    out.push(Instr::Return);
                }
            },
            Stmt::Accept => out.push(Instr::Accept),
            Stmt::Reject(reason) => match reason {
                Some(e) => {
                    self.compile_expr(e, out);
                    out.push(Instr::Reject { from_stack: true });
                }
                None => out.push(Instr::Reject { from_stack: false }),
            },
            Stmt::If { cond, then, els } => {
                self.compile_expr(cond, out);
                if let Some(e) = els {
                    // cond? then : else
                    let jf = out.len();
                    out.push(Instr::JumpIfFalse(usize::MAX)); // patched
                    self.compile_stmt(then, out);
                    let j = out.len();
                    out.push(Instr::Jump(usize::MAX));
                    out[jf] = Instr::JumpIfFalse(out.len());
                    self.compile_stmt(e, out);
                    out[j] = Instr::Jump(out.len());
                } else {
                    let jf = out.len();
                    out.push(Instr::JumpIfFalse(usize::MAX));
                    self.compile_stmt(then, out);
                    out[jf] = Instr::JumpIfFalse(out.len());
                }
            }
            Stmt::Case { scrutinee, arms } => {
                self.compile_expr(scrutinee, out);
                out.push(Instr::StoreTmp);
                let mut arm_jumps = Vec::new();
                for arm in arms {
                    if arm.patterns.is_empty() {
                        // default arm
                        self.compile_stmts(&arm.body, out);
                        arm_jumps.push(out.len());
                        out.push(Instr::Jump(usize::MAX));
                        continue;
                    }
                    let mut pattern_jumps = Vec::new();
                    for (i, p) in arm.patterns.iter().enumerate() {
                        if i > 0 {
                            // Only jump into pattern i when the previous
                            // ones did not match — chained by fall-through.
                        }
                        out.push(Instr::LoadTmp);
                        self.compile_expr(p, out);
                        out.push(Instr::Bin(BinaryOp::Eq));
                        let jf = out.len();
                        out.push(Instr::JumpIfFalse(usize::MAX));
                        pattern_jumps.push(jf);
                    }
                    self.compile_stmts(&arm.body, out);
                    arm_jumps.push(out.len());
                    out.push(Instr::Jump(usize::MAX));
                    for j in pattern_jumps {
                        out[j] = Instr::JumpIfFalse(out.len());
                    }
                }
                let end = out.len();
                for j in arm_jumps {
                    out[j] = Instr::Jump(end);
                }
            }
            Stmt::Let { name, value } => {
                self.compile_expr(value, out);
                out.push(Instr::StoreVar(name.clone()));
            }
            Stmt::Assign { name, value } => {
                self.compile_expr(value, out);
                out.push(Instr::AssignVar(name.clone()));
            }
            Stmt::AssignRouteField { field, value } => {
                self.compile_expr(value, out);
                out.push(Instr::AssignField(*field));
            }
            Stmt::AppendRouteField { field, value } => {
                self.compile_expr(value, out);
                out.push(Instr::AppendField(*field));
            }
            Stmt::Expr(e) => {
                self.compile_expr(e, out);
                out.push(Instr::Pop);
            }
            Stmt::Block(body) => {
                out.push(Instr::PushScope);
                self.compile_stmts(body, out);
                out.push(Instr::PopScope);
            }
        }
    }

    fn compile_expr(&self, expr: &Expr, out: &mut Vec<Instr>) {
        match expr {
            Expr::Lit(v) => out.push(Instr::Push(v.clone())),
            Expr::Var(name) => out.push(Instr::LoadVar(name.clone())),
            Expr::RouteField(f) => out.push(Instr::LoadField(*f)),
            Expr::Call { name, args } => {
                for a in args {
                    self.compile_expr(a, out);
                }
                out.push(Instr::Call {
                    name: name.clone(),
                    argc: args.len(),
                });
            }
            Expr::Method {
                receiver,
                method,
                args,
            } => {
                if let Expr::RouteField(field) = receiver.as_ref() {
                    for a in args {
                        self.compile_expr(a, out);
                    }
                    out.push(Instr::Method {
                        field: *field,
                        method: method.clone(),
                        argc: args.len(),
                    });
                } else {
                    // The interpreter errors on this shape; keep the
                    // same behaviour by routing through the tree walk.
                    out.push(Instr::EvalTree(expr.clone()));
                }
            }
            Expr::Defined(inner) => {
                let target = match inner.as_ref() {
                    Expr::RouteField(f) => DefinedTarget::Field(*f),
                    Expr::Var(n) => DefinedTarget::Var(n.clone()),
                    Expr::Lit(_) => DefinedTarget::Literal,
                    other => DefinedTarget::Dynamic(other.clone()),
                };
                out.push(Instr::Defined(target));
            }
            Expr::Binary { op, lhs, rhs } => match op {
                // Short-circuit operators compile to jumps; everything
                // else is a plain three-address stack op.
                BinaryOp::And => {
                    // <a>; JumpIfFalse(Lf); <b>; Truthy; Jump(Le);
                    // Lf: Push(false); Le:
                    self.compile_expr(lhs, out);
                    let jf = out.len();
                    out.push(Instr::JumpIfFalse(usize::MAX));
                    self.compile_expr(rhs, out);
                    out.push(Instr::Truthy);
                    let j = out.len();
                    out.push(Instr::Jump(usize::MAX));
                    let lf = out.len();
                    out.push(Instr::Push(Value::Bool(false)));
                    out[jf] = Instr::JumpIfFalse(lf);
                    out[j] = Instr::Jump(out.len());
                }
                BinaryOp::Or => {
                    // <a>; JumpIfTrue(Lt); <b>; Truthy; Jump(Le);
                    // Lt: Push(true); Le:
                    self.compile_expr(lhs, out);
                    let jt = out.len();
                    out.push(Instr::JumpIfTrue(usize::MAX));
                    self.compile_expr(rhs, out);
                    out.push(Instr::Truthy);
                    let j = out.len();
                    out.push(Instr::Jump(usize::MAX));
                    let lt = out.len();
                    out.push(Instr::Push(Value::Bool(true)));
                    out[jt] = Instr::JumpIfTrue(lt);
                    out[j] = Instr::Jump(out.len());
                }
                BinaryOp::Match | BinaryOp::NotMatch => {
                    self.compile_expr(lhs, out);
                    let rhs_c = self.compile_match_rhs(rhs);
                    out.push(Instr::Match {
                        negated: matches!(op, BinaryOp::NotMatch),
                        rhs: rhs_c,
                    });
                }
                other => {
                    self.compile_expr(lhs, out);
                    self.compile_expr(rhs, out);
                    out.push(Instr::Bin(*other));
                }
            },
            Expr::Unary { op, expr } => {
                self.compile_expr(expr, out);
                match op {
                    UnaryOp::Not => out.push(Instr::Not),
                    UnaryOp::Neg => out.push(Instr::Neg),
                }
            }
            Expr::Set(_) => {
                // Non-constant sets are only consumed by `~` in
                // practice; as a plain value they compile to the
                // tree walk so `Value::Set` construction semantics
                // stay identical.
                out.push(Instr::EvalTree(expr.clone()));
            }
            Expr::PrefixSet { prefix, .. } => {
                // As a bare value a prefix range evaluates to the
                // prefix itself (interpreter parity); the range only
                // matters inside a `~` pattern, handled there.
                out.push(Instr::Push(Value::Prefix(*prefix)));
            }
        }
    }

    fn compile_match_rhs(&self, rhs: &Expr) -> MatchRhs {
        match rhs {
            Expr::Set(items) => MatchRhs::Set(
                items
                    .iter()
                    .map(|i| match i {
                        Expr::PrefixSet { prefix, ge, le } => MatchItem::PrefixSet {
                            prefix: *prefix,
                            ge: *ge,
                            le: *le,
                        },
                        Expr::Lit(v) => MatchItem::Value(v.clone()),
                        other => MatchItem::Expr(other.clone()),
                    })
                    .collect(),
            ),
            Expr::PrefixSet { prefix, ge, le } => MatchRhs::Set(vec![MatchItem::PrefixSet {
                prefix: *prefix,
                ge: *ge,
                le: *le,
            }]),
            Expr::Lit(v) => MatchRhs::Value(v.clone()),
            other => MatchRhs::Expr(other.clone()),
        }
    }
}
