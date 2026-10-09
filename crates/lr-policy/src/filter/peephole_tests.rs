
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

/// `if bgp.local_pref > 100 then accept; reject;` — the canonical
/// import-policy shape and the documented `#19` hotspot. P6 fuses
/// the four-instruction pattern `LoadField(int); Push(Int(c));
/// Bin(Cmp); JumpIf*(t)` into one `BranchFieldIntCmp { .. }`
/// that reads the field, compares, and branches with zero stack
/// traffic. The fused `target` is the original `JumpIfFalse`'s
/// target (the `Reject` at index 2 in the rewritten stream).
#[test]
fn fuses_local_pref_branch_pattern() {
    let code = vec![
        Instr::LoadField(field(RouteFieldKind::BgpLocalPref)),
        Instr::Push(Value::Int(100)),
        Instr::Bin(BinaryOp::Gt),
        Instr::JumpIfFalse(5),
        Instr::Accept,
        Instr::Reject { from_stack: false },
    ];
    let opt = optimize(code);
    let expected = vec![
        Instr::BranchFieldIntCmp {
            field: field(RouteFieldKind::BgpLocalPref),
            op: BinaryOp::Gt,
            val: 100,
            target: 2,
            jump_if_true: false,
        },
        Instr::Accept,
        Instr::Reject { from_stack: false },
    ];
    assert_eq!(opt, expected);
}

/// The fusion pass only fires on the four int-typed fields.
/// `if proto == "bgp" then accept; reject;` reads the `Proto`
/// field which returns `Value::Str(_)` — `is_int_field` rejects
/// it, and the unfused four-instruction sequence stays.
#[test]
fn does_not_fuse_non_int_field_branch() {
    let code = vec![
        Instr::LoadField(field(RouteFieldKind::Proto)),
        Instr::Push(Value::Str("bgp".to_string())),
        Instr::Bin(BinaryOp::Eq),
        Instr::JumpIfFalse(5),
        Instr::Accept,
        Instr::Reject { from_stack: false },
    ];
    let opt = optimize(code.clone());
    // Pass-through — no fold, no fusion.
    assert_eq!(opt, code);
}

/// The fusion pass only fires on the six comparison ops. A branch
/// whose operator is `Match` (membership test) is not a
/// comparison; refuse to fuse.
#[test]
fn does_not_fuse_non_comparison_op() {
    // The pattern would not typecheck at the AST level (the
    // match operator binds an Expr on the rhs, not an int
    // constant), but the safety check defends against any
    // future lowering that emits it.
    let code = vec![
        Instr::LoadField(field(RouteFieldKind::BgpLocalPref)),
        Instr::Push(Value::Int(100)),
        Instr::Bin(BinaryOp::BitAnd),
        Instr::JumpIfFalse(5),
        Instr::Accept,
        Instr::Reject { from_stack: false },
    ];
    let opt = optimize(code.clone());
    // Pass-through — no fold, no fusion.
    assert_eq!(opt, code);
}

/// The fusion pass refuses to fire when an external jump lands
/// inside the four-instruction pattern. The `Push(Int(c))` at
/// index 1 is the target of an external `Jump(1)` at the end —
/// fusing it would skip the stack push the external jump expects.
#[test]
fn does_not_fuse_when_jump_lands_in_pattern() {
    // LoadField(0); Push(Int(100))(1); Bin(Gt)(2); JumpIfFalse(5)(3);
    // Accept(4); Reject(5); Jump(1)(6) — the trailing Jump
    // targets `Push`, blocking the fuse.
    let code = vec![
        Instr::LoadField(field(RouteFieldKind::BgpLocalPref)),
        Instr::Push(Value::Int(100)),
        Instr::Bin(BinaryOp::Gt),
        Instr::JumpIfFalse(5),
        Instr::Accept,
        Instr::Reject { from_stack: false },
        Instr::Jump(1),
    ];
    let opt = optimize(code.clone());
    // The pattern is unfused because `Push` at index 1 is a
    // jump target. The rest of the pass is also a no-op
    // (nothing else to fold or thread).
    assert_eq!(opt, code);
}

/// `JumpIfTrue` direction: the fused instruction sets
/// `jump_if_true: true` so the VM inverts the comparison's
/// result correctly. The fused `target` is the
/// `Reject`'s new index (1) after the pattern's four
/// instructions collapse to one — the pass's old-to-new
/// index map rewrites the original `JumpIfTrue(4)` target
/// through the consumed-instruction remap.
#[test]
fn fuses_jump_if_true_direction() {
    let code = vec![
        Instr::LoadField(field(RouteFieldKind::BgpMed)),
        Instr::Push(Value::Int(50)),
        Instr::Bin(BinaryOp::Le),
        Instr::JumpIfTrue(4),
        Instr::Reject { from_stack: false },
    ];
    let opt = optimize(code);
    let expected = vec![
        Instr::BranchFieldIntCmp {
            field: field(RouteFieldKind::BgpMed),
            op: BinaryOp::Le,
            val: 50,
            target: 1,
            jump_if_true: true,
        },
        Instr::Reject { from_stack: false },
    ];
    assert_eq!(opt, expected);
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
