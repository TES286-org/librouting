//! Peephole optimisation passes for the compiled bytecode
//! (ROADMAP-v3 D6 follow-up, GitHub #19 P5).
//!
//! The bytecode VM runs a flat instruction stream per route; cutting
//! the instruction count is the cheapest lever for filters that
//! contain constants the compiler can pre-compute. Three passes run
//! in sequence after the AST-to-bytecode compiler emits the code:
//!
//! * **Constant propagation + literal folding** — a forward pass
//!   that tracks `let`-bound constants and folds `Push; Push; Bin`
//!   (and `Push; Not` / `Push; Neg`) sequences into a single `Push`
//!   when the result is statically known and cannot error at
//!   runtime. The pass also rewrites `LoadVar(name)` to `Push(v)`
//!   when `name` is a known constant — turning a hash-map lookup
//!   into a literal push. Constant tracking is invalidated at every
//!   control-flow join (`Jump`, `JumpIfFalse`, `JumpIfTrue`,
//!   `PushScope`, `PopScope`) and every side-effecting instruction
//!   (`Call`, `Method`, `EvalTree`, `AssignField`, `AppendField`,
//!   `Defined`, `AssignVar`) so the analysis is a single forward
//!   walk, not a full data-flow fixpoint.
//! * **Dead-branch elimination** — after folding produces
//!   `Push(Bool(c)); JumpIfFalse(X)` or `Push(Bool(c));
//!   JumpIfTrue(X)`, the branch direction is known at compile time.
//!   `Push(Bool(true)); JumpIfFalse(X)` always falls through (drop
//!   both); `Push(Bool(false)); JumpIfFalse(X)` always jumps
//!   (replace with `Jump(X)`). The branch body that becomes
//!   unreachable stays in the code array (the VM never executes
//!   it) — pruning unreachable instructions is a separate
//!   reachability analysis left for a later phase.
//! * **Jump threading** — `Jump(X)` where `code[X]` is `Jump(Y)`
//!   can be rewritten to `Jump(Y)`. Same for `JumpIfFalse(X)` and
//!   `JumpIfTrue(X)` when `code[X]` is an unconditional `Jump`.
//!   Conditional-jump-to-conditional-jump is NOT threaded: the
//!   target conditional pops a stack value, so redirecting would
//!   skip the pop and corrupt the stack. Threads through chains
//!   of unconditional jumps until a fixed point per instruction.
//!
//! All three passes preserve the VM's contract: the verdict (Accept
//! / Reject / Fallthrough) and the post-evaluation route state must
//! be bit-identical to the unoptimised code for every route. The
//! existing `vm_matches_interpreter_on_policy_table`,
//! `vm_matches_interpreter_on_bench_shapes`, and
//! `prefix_trie_matches_linear_scan_across_set_shapes` tests in
//! `crates/lr-policy/src/filter/eval.rs` pin that contract; the
//! peephole pass runs transparently inside `bytecode::compile`, so
//! every existing test exercises the optimised code path.
//!
//! The pass is conservative on purpose: every fold checks the
//! interpreter's `eval_binary` semantics (overflow, division by
//! zero, shift range) and refuses to fold when the runtime would
//! error — the error must surface at runtime exactly as the
//! unoptimised code surfaces it, otherwise the Fallthrough-on-error
//! contract diverges. See `safe_fold` for the exact rules.

use std::collections::HashMap;

use crate::filter::ast::{BinaryOp, Value};
use crate::filter::bytecode::Instr;

/// Run all peephole passes on a compiled instruction stream. The
/// input is the verbatim output of `Compiler::compile_stmts`; the
/// output is semantically equivalent and at most as long.
///
/// The passes iterate to a fixed point: constant propagation can
/// expose new fold patterns, and folding can expose new
/// dead-branches, so the outer loop runs until no pass reports a
/// change.
pub fn optimize(code: Vec<Instr>) -> Vec<Instr> {
    let mut current = code;
    loop {
        let (next, changed) = pass_propagate_and_fold(&current);
        current = next;
        if !changed {
            break;
        }
    }
    let (next, _) = pass_dead_branch(&current);
    current = next;
    pass_thread_jumps(&mut current);
    current
}

// ----- helpers ----------------------------------------------------------

/// Compute the set of indices that are targets of any jump
/// instruction (`Jump`, `JumpIfFalse`, `JumpIfTrue`). The peephole
/// passes use this to skip optimizations that would consume an
/// instruction that is a jump target — collapsing such an
/// instruction would change the stack state seen by the jump.
fn collect_jump_targets(code: &[Instr]) -> Vec<bool> {
    let mut targets = vec![false; code.len()];
    for instr in code {
        match instr {
            Instr::Jump(t) | Instr::JumpIfFalse(t) | Instr::JumpIfTrue(t) if *t < targets.len() => {
                targets[*t] = true;
            }
            _ => {}
        }
    }
    targets
}

// ----- pass 1: constant propagation + literal folding ---------------------

/// One iteration of constant propagation + literal folding. Returns
/// the rewritten code and a flag indicating whether any change was
/// made (so the caller can iterate to a fixed point).
fn pass_propagate_and_fold(code: &[Instr]) -> (Vec<Instr>, bool) {
    // Compute the set of indices that are jump targets — these
    // cannot be consumed by the fold (a jump into the middle of
    // `Push; Push; Bin` would land on a different stack state
    // after the fold collapses the three instructions into one).
    let jump_targets = collect_jump_targets(code);

    let mut out: Vec<Instr> = Vec::with_capacity(code.len());
    // Map from each old instruction index to its index in `out`.
    // Consumed instructions (the `Push` and `Bin` of a folded
    // `Push; Push; Bin` triple) map to the same `out` index as the
    // fold's `Push`, so any jump that targeted them lands on the
    // fold result. Well-formed compiler-emitted bytecode never
    // targets the middle of a foldable triple, but the mapping is
    // defensive.
    let mut old_to_new: Vec<usize> = vec![usize::MAX; code.len()];
    // Known `let`-bound constants in the current scope. Cleared at
    // every control-flow join and every side-effecting instruction
    // (see module docs).
    let mut var_map: HashMap<String, Value> = HashMap::new();
    let mut changed = false;

    let mut i = 0;
    while i < code.len() {
        old_to_new[i] = out.len();
        // Peek at the last emitted instruction without keeping the
        // borrow alive across the match below (the match may need
        // to mutate `out`).
        let last_is_push_bool = matches!(out.last(), Some(Instr::Push(Value::Bool(_))));
        let last_is_push_int = matches!(out.last(), Some(Instr::Push(Value::Int(_))));
        let last_push_value: Option<Value> = match out.last() {
            Some(Instr::Push(v)) => Some(v.clone()),
            _ => None,
        };
        let (new_instr, advance) = match &code[i] {
            Instr::Push(v) => {
                // Try to fold `Push(L1); Push(L2); Bin(Op)` into
                // `Push(folded)` when both are constants, the fold
                // cannot error, AND neither of the consumed
                // instructions (i+1, i+2) is a jump target from
                // elsewhere. A jump into the middle of the triple
                // would land on a different stack state after the
                // fold collapses the three instructions into one.
                if i + 2 < code.len() && !jump_targets[i + 1] && !jump_targets[i + 2] {
                    if let (Instr::Push(l2), Instr::Bin(op)) = (&code[i + 1], &code[i + 2]) {
                        if let Some(folded) = safe_fold(op, v, l2) {
                            old_to_new[i + 1] = out.len();
                            old_to_new[i + 2] = out.len();
                            changed = true;
                            (Instr::Push(folded), 3)
                        } else {
                            (Instr::Push(v.clone()), 1)
                        }
                    } else {
                        (Instr::Push(v.clone()), 1)
                    }
                } else {
                    (Instr::Push(v.clone()), 1)
                }
            }
            Instr::Not => {
                // Try to fold `Push(Bool(b)); Not` into `Push(Bool(!b))`.
                // Skip when `i` (the Not) is a jump target — a jump
                // to the Not would skip the Push and operate on a
                // different stack value.
                if last_is_push_bool && !jump_targets[i] {
                    if let Some(Value::Bool(b)) = last_push_value.as_ref() {
                        let folded = Value::Bool(!*b);
                        out.pop();
                        changed = true;
                        (Instr::Push(folded), 1)
                    } else {
                        unreachable!("last_is_push_bool guarantees Value::Bool")
                    }
                } else {
                    (Instr::Not, 1)
                }
            }
            Instr::Neg => {
                // Try to fold `Push(Int(n)); Neg` into `Push(Int(-n))`
                // (with overflow check). Skip when `i` is a jump target.
                if last_is_push_int && !jump_targets[i] {
                    if let Some(Value::Int(n)) = last_push_value.as_ref() {
                        if let Some(neg) = n.checked_neg() {
                            out.pop();
                            changed = true;
                            (Instr::Push(Value::Int(neg)), 1)
                        } else {
                            (Instr::Neg, 1)
                        }
                    } else {
                        unreachable!("last_is_push_int guarantees Value::Int")
                    }
                } else {
                    (Instr::Neg, 1)
                }
            }
            Instr::LoadVar(name) => {
                // Constant propagation: if `name` is a known `let`
                // constant, replace `LoadVar(name)` with `Push(v)`.
                if let Some(v) = var_map.get(name) {
                    changed = true;
                    (Instr::Push(v.clone()), 1)
                } else {
                    (Instr::LoadVar(name.clone()), 1)
                }
            }
            Instr::StoreVar(name) => {
                // `let name = expr;` — record the constant when the
                // value being stored is a known literal (the previous
                // `out` instruction is a `Push`). Otherwise, drop the
                // name from the map (it's now bound to a dynamic
                // value, so future LoadVars cannot propagate).
                if let Some(v) = last_push_value {
                    var_map.insert(name.clone(), v);
                } else {
                    var_map.remove(name);
                }
                (Instr::StoreVar(name.clone()), 1)
            }
            Instr::AssignVar(name) => {
                // `name = expr;` — the assignment may change `name`'s
                // value. Drop it from the constant map; if the new
                // value is also a known literal, re-add it.
                var_map.remove(name);
                if let Some(v) = last_push_value {
                    var_map.insert(name.clone(), v);
                }
                (Instr::AssignVar(name.clone()), 1)
            }
            // Control-flow joins and side-effecting instructions
            // invalidate the entire constant map.
            Instr::Jump(_)
            | Instr::JumpIfFalse(_)
            | Instr::JumpIfTrue(_)
            | Instr::PushScope
            | Instr::PopScope
            | Instr::Call { .. }
            | Instr::CallFn { .. }
            | Instr::Method { .. }
            | Instr::EvalTree(_)
            | Instr::AssignField(_)
            | Instr::AppendField(_)
            | Instr::Defined(_) => {
                var_map.clear();
                (code[i].clone(), 1)
            }
            _ => (code[i].clone(), 1),
        };
        out.push(new_instr);
        i += advance;
    }

    // Rewrite jump targets through the index mapping. Any jump
    // that targeted a consumed instruction now targets the fold
    // result (or, for instructions past the end, the end of the
    // code — clamped defensively).
    let out_len = out.len();
    for instr in out.iter_mut() {
        match instr {
            Instr::Jump(t) | Instr::JumpIfFalse(t) | Instr::JumpIfTrue(t) => {
                if *t < old_to_new.len() {
                    let mapped = old_to_new[*t];
                    *t = if mapped == usize::MAX {
                        out_len
                    } else {
                        mapped
                    };
                } else {
                    *t = out_len;
                }
            }
            _ => {}
        }
    }

    (out, changed)
}

// ----- pass 2: dead-branch elimination -----------------------------------

/// Eliminate branches whose direction is known at compile time
/// after constant folding. `Push(Bool(true)); JumpIfFalse(X)` always
/// falls through (drop both); `Push(Bool(false)); JumpIfFalse(X)`
/// always jumps (replace with `Jump(X)`); and the symmetric
/// `Push(Bool(c)); JumpIfTrue(X)` cases.
///
/// The pass is only applied when the `JumpIfFalse` / `JumpIfTrue`
/// (at index `i+1`) is NOT a jump target from elsewhere. The `&&`
/// / `||` short-circuit compilation emits `Jump(Le)` that targets
/// the `JumpIfFalse` directly (skipping the `Push(Bool(false))`),
/// so the `JumpIfFalse` sees a different stack value depending on
/// the path. Eliminating the branch in that case would change
/// semantics — see the `vm_matches_interpreter_on_policy_table`
/// equivalence table for the `&&` / `||` cases that pin this.
///
/// Like the fold pass, this builds a new `out` array and tracks an
/// old-to-new index mapping so jump targets stay valid.
fn pass_dead_branch(code: &[Instr]) -> (Vec<Instr>, bool) {
    let jump_targets = collect_jump_targets(code);

    let mut out: Vec<Instr> = Vec::with_capacity(code.len());
    let mut old_to_new: Vec<usize> = vec![usize::MAX; code.len()];
    let mut changed = false;

    let mut i = 0;
    while i < code.len() {
        old_to_new[i] = out.len();
        let (emit, advance): (Option<Instr>, usize) = match &code[i] {
            Instr::Push(Value::Bool(c)) if i + 1 < code.len() && !jump_targets[i + 1] => {
                match &code[i + 1] {
                    Instr::JumpIfFalse(t) => {
                        if *c {
                            // Always falls through. Drop both the Push
                            // and the JumpIfFalse.
                            old_to_new[i + 1] = out.len();
                            changed = true;
                            (None, 2)
                        } else {
                            // Always jumps. Drop the Push, replace
                            // JumpIfFalse with Jump(t).
                            old_to_new[i + 1] = out.len();
                            changed = true;
                            (Some(Instr::Jump(*t)), 2)
                        }
                    }
                    Instr::JumpIfTrue(t) => {
                        if *c {
                            // Always jumps. Drop the Push, replace
                            // JumpIfTrue with Jump(t).
                            old_to_new[i + 1] = out.len();
                            changed = true;
                            (Some(Instr::Jump(*t)), 2)
                        } else {
                            // Always falls through. Drop both.
                            old_to_new[i + 1] = out.len();
                            changed = true;
                            (None, 2)
                        }
                    }
                    _ => (Some(Instr::Push(Value::Bool(*c))), 1),
                }
            }
            other => (Some(other.clone()), 1),
        };
        if let Some(instr) = emit {
            out.push(instr);
        }
        i += advance;
    }

    let out_len = out.len();
    for instr in out.iter_mut() {
        match instr {
            Instr::Jump(t) | Instr::JumpIfFalse(t) | Instr::JumpIfTrue(t) => {
                if *t < old_to_new.len() {
                    let mapped = old_to_new[*t];
                    *t = if mapped == usize::MAX {
                        out_len
                    } else {
                        mapped
                    };
                } else {
                    *t = out_len;
                }
            }
            _ => {}
        }
    }

    (out, changed)
}

// ----- pass 3: jump threading --------------------------------------------

/// Thread unconditional-jump chains. For each `Jump`, `JumpIfFalse`,
/// or `JumpIfTrue` targeting an unconditional `Jump`, redirect to
/// that Jump's target. Iterates per-instruction through chains
/// (bounded by the code length to defend against pathological
/// cycles).
fn pass_thread_jumps(code: &mut [Instr]) {
    // Compute the new targets first, then apply — this avoids
    // borrow-checker conflicts between `code.iter()` and
    // `code.iter_mut()`.
    let code_len = code.len();
    let new_targets: Vec<usize> = code
        .iter()
        .map(|instr| {
            let target = match instr {
                Instr::Jump(t) | Instr::JumpIfFalse(t) | Instr::JumpIfTrue(t) => *t,
                _ => return usize::MAX, // sentinel: not a jump
            };
            let mut cur = target;
            // Bound by the code length: a chain longer than the
            // code would have to revisit a node, which means a
            // cycle.
            for _ in 0..code_len {
                if cur >= code_len {
                    break;
                }
                match &code[cur] {
                    Instr::Jump(n) => {
                        if *n == cur {
                            // Self-loop — stop, don't infinite-loop.
                            break;
                        }
                        cur = *n;
                    }
                    _ => break,
                }
            }
            cur
        })
        .collect();

    for (i, instr) in code.iter_mut().enumerate() {
        let new_t = new_targets[i];
        if new_t == usize::MAX {
            continue;
        }
        match instr {
            Instr::Jump(t) | Instr::JumpIfFalse(t) | Instr::JumpIfTrue(t) => *t = new_t,
            _ => unreachable!("new_targets[i] == usize::MAX only for non-jumps"),
        }
    }
}

// ----- constant folding (mirrors eval_binary's semantics) ----------------

/// Fold `op(l, r)` to a `Value` when both operands are known
/// constants and the fold is *semantically exact* — i.e. the
/// folded value matches what the interpreter's `eval_binary`
/// would produce, including not folding when the runtime would
/// error (division by zero, overflow, bad shift). Returns `None`
/// when the fold is unsafe or the operand types are not handled.
///
/// Only `Int`-`Int` arithmetic / comparison and `Bool`-`Bool`
/// equality are folded. The interpreter's `as_int` accepts `Bool`
/// for arithmetic, but folding `Bool(true) + Int(1)` would
/// silently change the value's type (`Int(2)` vs the runtime's
/// `Int(2)` — same value, but we'd diverge from the
/// tree-walker's `Value::Bool` provenance for any downstream
/// `value_eq` that distinguishes them). Conservatively refuse to
/// cross types.
fn safe_fold(op: &BinaryOp, l: &Value, r: &Value) -> Option<Value> {
    use BinaryOp::*;
    match (op, l, r) {
        // Integer arithmetic — match eval_binary's checked semantics.
        (Add, Value::Int(a), Value::Int(b)) => a.checked_add(*b).map(Value::Int),
        (Sub, Value::Int(a), Value::Int(b)) => a.checked_sub(*b).map(Value::Int),
        (Mul, Value::Int(a), Value::Int(b)) => a.checked_mul(*b).map(Value::Int),
        // Division by zero is a runtime error — do NOT fold.
        (Div, Value::Int(a), Value::Int(b)) if *b != 0 => a.checked_div(*b).map(Value::Int),
        // Modulo by zero is a runtime error — do NOT fold. The
        // interpreter's `checked_rem` returns `None` only for
        // `MIN % -1` (overflow), which it maps to `0`; mirror that.
        (Mod, Value::Int(a), Value::Int(b)) if *b != 0 => {
            Some(Value::Int(a.checked_rem(*b).unwrap_or(0)))
        }
        // Bitwise ops — no overflow possible.
        (BitAnd, Value::Int(a), Value::Int(b)) => Some(Value::Int(a & b)),
        (BitOr, Value::Int(a), Value::Int(b)) => Some(Value::Int(a | b)),
        (BitXor, Value::Int(a), Value::Int(b)) => Some(Value::Int(a ^ b)),
        // Shifts — `BadShift` (shift amount out of 0..=63) is a
        // runtime error, do NOT fold.
        (Shl, Value::Int(a), Value::Int(b)) if (0..=63).contains(b) => Some(Value::Int(a << b)),
        (Shr, Value::Int(a), Value::Int(b)) if (0..=63).contains(b) => Some(Value::Int(a >> b)),
        // Integer comparison.
        (Eq, Value::Int(a), Value::Int(b)) => Some(Value::Bool(a == b)),
        (Ne, Value::Int(a), Value::Int(b)) => Some(Value::Bool(a != b)),
        (Lt, Value::Int(a), Value::Int(b)) => Some(Value::Bool(a < b)),
        (Le, Value::Int(a), Value::Int(b)) => Some(Value::Bool(a <= b)),
        (Gt, Value::Int(a), Value::Int(b)) => Some(Value::Bool(a > b)),
        (Ge, Value::Int(a), Value::Int(b)) => Some(Value::Bool(a >= b)),
        // Boolean equality.
        (Eq, Value::Bool(a), Value::Bool(b)) => Some(Value::Bool(a == b)),
        (Ne, Value::Bool(a), Value::Bool(b)) => Some(Value::Bool(a != b)),
        // And / Or are short-circuited at the AST level and never
        // reach `Bin`; Match / NotMatch need runtime context. Do
        // not fold.
        _ => None,
    }
}

// ----- tests -------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::filter::ast::{BinaryOp, RouteField, RouteFieldKind};
    use crate::filter::bytecode::Instr;

    // Build a `RouteField` for the test (the constructor is private
    // to the `ast` module, but we can reach it through the `RouteField`
    // re-export and its `new` method via the parent path).
    fn field(kind: RouteFieldKind) -> RouteField {
        RouteField::new(kind)
    }

    /// `let a = 6; let b = 7; if a * b == 42 then accept; reject;`
    /// folds all the way to `Push(6); StoreVar(a); Push(7);
    /// StoreVar(b); Accept; Reject` (the dead `Push`/`StoreVar`
    /// pairs remain — dead-store elimination is a later phase).
    #[test]
    fn folds_let_constants_through_arithmetic_and_comparison() {
        let code = vec![
            Instr::Push(Value::Int(6)),
            Instr::StoreVar("a".to_string()),
            Instr::Push(Value::Int(7)),
            Instr::StoreVar("b".to_string()),
            Instr::LoadVar("a".to_string()),
            Instr::LoadVar("b".to_string()),
            Instr::Bin(BinaryOp::Mul),
            Instr::Push(Value::Int(42)),
            Instr::Bin(BinaryOp::Eq),
            Instr::JumpIfFalse(11),
            Instr::Accept,
            Instr::Reject { from_stack: false },
        ];
        let opt = optimize(code);
        // The dead `Push/StoreVar` pair for `a` and `b` remains
        // (dead-store elimination is out of scope), but the
        // `LoadVar; LoadVar; Bin(Mul); Push(42); Bin(Eq); JumpIfFalse`
        // chain folds to `Push(Bool(true))` and the dead-branch pass
        // removes the `Push(Bool(true)); JumpIfFalse`, leaving the
        // `Accept` to fall through.
        let expected = vec![
            Instr::Push(Value::Int(6)),
            Instr::StoreVar("a".to_string()),
            Instr::Push(Value::Int(7)),
            Instr::StoreVar("b".to_string()),
            Instr::Accept,
            Instr::Reject { from_stack: false },
        ];
        assert_eq!(opt, expected);
    }

    /// `if true then accept; reject;` folds to `Accept; Reject` —
    /// the constant `true` is a literal Push, not a `let` constant.
    #[test]
    fn folds_constant_true_branch_to_accept() {
        let code = vec![
            Instr::Push(Value::Bool(true)),
            Instr::JumpIfFalse(3),
            Instr::Accept,
            Instr::Reject { from_stack: false },
        ];
        let opt = optimize(code);
        let expected = vec![Instr::Accept, Instr::Reject { from_stack: false }];
        assert_eq!(opt, expected);
    }

    /// `if false then accept; reject;` folds to `Jump(reject); accept;
    /// reject;` — the dead-branch pass turns `Push(Bool(false));
    /// JumpIfFalse(X)` into `Jump(X)`, skipping the `Accept`. The
    /// unreachable `Accept` stays in the code array (dead-code
    /// elimination is a later phase); the VM never executes it.
    #[test]
    fn folds_constant_false_branch_to_reject() {
        let code = vec![
            Instr::Push(Value::Bool(false)),
            Instr::JumpIfFalse(3),
            Instr::Accept,
            Instr::Reject { from_stack: false },
        ];
        let opt = optimize(code);
        // The `Push(Bool(false)); JumpIfFalse(3)` becomes `Jump(2)`
        // (targeting the Reject at index 2 after the Accept at
        // index 1). The Accept is unreachable but still in the code.
        let expected = vec![
            Instr::Jump(2),
            Instr::Accept,
            Instr::Reject { from_stack: false },
        ];
        assert_eq!(opt, expected);
    }

    /// `1 / 0` must NOT fold — the runtime DivByZero error must
    /// surface exactly as the unoptimised code surfaces it.
    #[test]
    fn does_not_fold_division_by_zero() {
        let code = vec![
            Instr::Push(Value::Int(1)),
            Instr::Push(Value::Int(0)),
            Instr::Bin(BinaryOp::Div),
            Instr::Pop,
            Instr::Accept,
        ];
        let opt = optimize(code);
        // The Push; Push; Bin stays intact so the VM hits the
        // DivByZero error at runtime.
        assert_eq!(
            opt,
            vec![
                Instr::Push(Value::Int(1)),
                Instr::Push(Value::Int(0)),
                Instr::Bin(BinaryOp::Div),
                Instr::Pop,
                Instr::Accept,
            ]
        );
    }

    /// `i64::MIN * -1` overflows — must NOT fold.
    #[test]
    fn does_not_fold_arithmetic_overflow() {
        let min = i64::MIN;
        let code = vec![
            Instr::Push(Value::Int(min)),
            Instr::Push(Value::Int(-1)),
            Instr::Bin(BinaryOp::Mul),
            Instr::Pop,
            Instr::Accept,
        ];
        let opt = optimize(code);
        assert_eq!(
            opt,
            vec![
                Instr::Push(Value::Int(min)),
                Instr::Push(Value::Int(-1)),
                Instr::Bin(BinaryOp::Mul),
                Instr::Pop,
                Instr::Accept,
            ]
        );
    }

    /// `1 << 64` is a BadShift — must NOT fold.
    #[test]
    fn does_not_fold_bad_shift() {
        let code = vec![
            Instr::Push(Value::Int(1)),
            Instr::Push(Value::Int(64)),
            Instr::Bin(BinaryOp::Shl),
            Instr::Pop,
            Instr::Accept,
        ];
        let opt = optimize(code);
        assert_eq!(
            opt,
            vec![
                Instr::Push(Value::Int(1)),
                Instr::Push(Value::Int(64)),
                Instr::Bin(BinaryOp::Shl),
                Instr::Pop,
                Instr::Accept,
            ]
        );
    }

    /// `Push(Bool(true)); Not` folds to `Push(Bool(false))`.
    #[test]
    fn folds_not_on_bool_literal() {
        let code = vec![
            Instr::Push(Value::Bool(true)),
            Instr::Not,
            Instr::Pop,
            Instr::Accept,
        ];
        let opt = optimize(code);
        assert_eq!(
            opt,
            vec![Instr::Push(Value::Bool(false)), Instr::Pop, Instr::Accept,]
        );
    }

    /// `Push(Int(5)); Neg` folds to `Push(Int(-5))`.
    #[test]
    fn folds_neg_on_int_literal() {
        let code = vec![
            Instr::Push(Value::Int(5)),
            Instr::Neg,
            Instr::Pop,
            Instr::Accept,
        ];
        let opt = optimize(code);
        assert_eq!(
            opt,
            vec![Instr::Push(Value::Int(-5)), Instr::Pop, Instr::Accept,]
        );
    }

    /// `i64::MIN; Neg` overflows — must NOT fold.
    #[test]
    fn does_not_fold_neg_overflow() {
        let min = i64::MIN;
        let code = vec![
            Instr::Push(Value::Int(min)),
            Instr::Neg,
            Instr::Pop,
            Instr::Accept,
        ];
        let opt = optimize(code);
        assert_eq!(
            opt,
            vec![
                Instr::Push(Value::Int(min)),
                Instr::Neg,
                Instr::Pop,
                Instr::Accept,
            ]
        );
    }

    /// Jump threading: `Jump(X); Jump(Y); Jump(Z); Accept`
    /// collapses the leading `Jump` to target `Accept` directly.
    #[test]
    fn threads_chained_unconditional_jumps() {
        let code = vec![
            Instr::Jump(1),
            Instr::Jump(2),
            Instr::Jump(3),
            Instr::Accept,
        ];
        let opt = optimize(code);
        assert_eq!(
            opt,
            vec![
                Instr::Jump(3),
                Instr::Jump(3),
                Instr::Jump(3),
                Instr::Accept,
            ]
        );
    }

    /// Constant propagation is invalidated at control-flow joins:
    /// `let a = 1; JumpIfFalse(X); LoadVar(a)` — after the
    /// `JumpIfFalse`, the constant map is cleared, so the
    /// `LoadVar(a)` stays a `LoadVar` (not propagated to
    /// `Push(1)`).
    #[test]
    fn invalidates_constants_at_control_flow_join() {
        let code = vec![
            Instr::Push(Value::Int(1)),
            Instr::StoreVar("a".to_string()),
            Instr::Push(Value::Bool(true)),
            Instr::JumpIfFalse(5),
            Instr::LoadVar("a".to_string()),
            Instr::Accept,
        ];
        let opt = optimize(code);
        // The `Push(Bool(true)); JumpIfFalse(5)` is a dead branch
        // (always falls through), so the dead-branch pass drops
        // both. After that, the `LoadVar(a)` is preceded by
        // `StoreVar(a)` which recorded `a -> 1`, BUT the
        // propagation pass runs *before* the dead-branch pass, so
        // at the time propagation sees the code the `JumpIfFalse`
        // is still there and clears the map. The `LoadVar(a)`
        // stays a `LoadVar`.
        //
        // The dead-branch pass then removes the `Push(Bool(true));
        // JumpIfFalse(5)`, leaving the `LoadVar(a)` to fall
        // through to `Accept`.
        assert_eq!(
            opt,
            vec![
                Instr::Push(Value::Int(1)),
                Instr::StoreVar("a".to_string()),
                Instr::LoadVar("a".to_string()),
                Instr::Accept,
            ]
        );
    }

    /// A pure `LoadField` filter (`if bgp.local_pref > 100 then
    /// accept; reject;`) has no constants to fold — the pass
    /// should be a no-op.
    #[test]
    fn no_op_on_dynamic_filter() {
        let code = vec![
            Instr::LoadField(field(RouteFieldKind::BgpLocalPref)),
            Instr::Push(Value::Int(100)),
            Instr::Bin(BinaryOp::Gt),
            Instr::JumpIfFalse(5),
            Instr::Accept,
            Instr::Reject { from_stack: false },
        ];
        let opt = optimize(code.clone());
        assert_eq!(opt, code);
    }

    /// Empty filter — optimize is a no-op.
    #[test]
    fn no_op_on_empty_code() {
        let code: Vec<Instr> = vec![];
        let opt = optimize(code.clone());
        assert_eq!(opt, code);
    }

    /// Self-loop jump threading: `Jump(0)` at index 0 is a
    /// self-loop; threading must not infinite-loop.
    #[test]
    fn threads_self_loop_safely() {
        let code = vec![Instr::Jump(0), Instr::Accept];
        let opt = optimize(code.clone());
        // Self-loop is preserved (the threading pass detects the
        // self-loop and stops).
        assert_eq!(opt, code);
    }
}
