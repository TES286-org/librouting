use super::*;

fn parse_ok(src: &str) -> Filter {
    let mut p = Parser::new(src);
    p.parse_filter("test").unwrap_or_else(|e| panic!("{e}"))
}

fn parse_err(src: &str) -> ParseError {
    let mut p = Parser::new(src);
    p.parse_filter("test").unwrap_err()
}

#[test]
fn empty_filter_body_is_rejected() {
    let e = parse_err("{}");
    assert!(matches!(e.kind, ParseErrorKind::EmptyFilterBody), "{e:?}");
}

#[test]
fn accept_statement_parses() {
    let f = parse_ok("accept;");
    assert_eq!(f.body.stmts.len(), 1);
    assert!(matches!(f.body.stmts[0], Stmt::Accept(_)));
}

#[test]
fn reject_statement_parses() {
    let f = parse_ok("reject;");
    assert_eq!(f.body.stmts.len(), 1);
    assert!(matches!(f.body.stmts[0], Stmt::Reject(None, _)));
}

#[test]
fn reject_with_reason_parses() {
    let f = parse_ok("reject with \"bad route\";");
    assert!(matches!(f.body.stmts[0], Stmt::Reject(Some(_), _)));
}

#[test]
fn if_then_parses() {
    let f = parse_ok("if net ~ 10.0.0.0/8 then accept;");
    assert!(matches!(f.body.stmts[0], Stmt::If { .. }));
}

#[test]
fn if_then_else_parses() {
    let f = parse_ok("if bgp.local_pref > 100 then accept; else reject;");
    let s = &f.body.stmts[0];
    assert!(matches!(s, Stmt::If { els: Some(_), .. }));
}

#[test]
fn let_and_assign_parse() {
    let f = parse_ok("let x = 100; x = 200; accept;");
    assert_eq!(f.body.stmts.len(), 3);
    assert!(matches!(f.body.stmts[0], Stmt::Let { .. }));
    assert!(matches!(f.body.stmts[1], Stmt::Assign { .. }));
}

#[test]
fn bgp_local_pref_assignment() {
    let f = parse_ok("bgp.local_pref = 200;");
    assert!(matches!(f.body.stmts[0], Stmt::AssignRouteField { .. }));
}

#[test]
fn bgp_communities_append() {
    let f = parse_ok("bgp.communities += [ 64512:100 ];");
    assert!(matches!(f.body.stmts[0], Stmt::AppendRouteField { .. }));
}

#[test]
fn read_only_field_rejects_assignment() {
    let e = parse_err("net = 10.0.0.0/8;");
    assert!(matches!(e.kind, ParseErrorKind::ReadOnlyField(_)), "{e}");
}

#[test]
fn unknown_bgp_field_rejected() {
    let e = parse_err("bgp.unknown = 5;");
    assert!(matches!(e.kind, ParseErrorKind::UnknownBgpField(_)), "{e}");
}

#[test]
fn case_statement_parses() {
    let f = parse_ok("case proto { \"bgp\" => accept; default => reject; }");
    assert!(matches!(f.body.stmts[0], Stmt::Case { .. }));
}

#[test]
fn not_match_operator_parses() {
    // `!~` is the negation of `~` (BIRD/RFC spelling). Both
    // sides share Match precedence (4) so a sequence like
    // `a ~ b && c !~ d` parses left-to-right at the AND level.
    let f = parse_ok("if net !~ 10.0.0.0/8 then accept; reject;");
    if let Stmt::If { cond, .. } = &f.body.stmts[0] {
        assert!(
            matches!(
                cond,
                Expr::Binary {
                    op: BinaryOp::NotMatch,
                    ..
                }
            ),
            "{cond:?}"
        );
    } else {
        panic!("expected If");
    }
}

#[test]
fn not_match_and_match_share_precedence() {
    // `a ~ b && c !~ d` should parse as `(a ~ b) && (c !~ d)`.
    let f = parse_ok("let r = net ~ 10.0.0.0/8 && bgp.as_path !~ [ 65000 ]; accept;");
    if let Stmt::Let { value, .. } = &f.body.stmts[0] {
        assert!(
            matches!(
                value,
                Expr::Binary {
                    op: BinaryOp::And,
                    ..
                }
            ),
            "{value:?}"
        );
    } else {
        panic!("expected Let");
    }
}

#[test]
fn arithmetic_precedence() {
    // 1 + 2 * 3 should parse as 1 + (2 * 3)
    let f = parse_ok("let x = 1 + 2 * 3; accept;");
    if let Stmt::Let { value, .. } = &f.body.stmts[0] {
        assert!(matches!(
            value,
            Expr::Binary {
                op: BinaryOp::Add,
                ..
            }
        ));
    } else {
        panic!("expected Let");
    }
}

#[test]
fn boolean_short_circuit_precedence() {
    // a || b && c should parse as a || (b && c)
    let f = parse_ok("let x = true || false && true; accept;");
    if let Stmt::Let { value, .. } = &f.body.stmts[0] {
        assert!(matches!(
            value,
            Expr::Binary {
                op: BinaryOp::Or,
                ..
            }
        ));
    }
}

#[test]
fn prefix_set_with_range_parses() {
    let f = parse_ok("if net ~ [ 10.0.0.0/8{16,24} ] then accept;");
    assert!(matches!(f.body.stmts[0], Stmt::If { .. }));
}

#[test]
fn method_call_parses() {
    let f = parse_ok("bgp.as_path.prepend(65001);");
    assert!(matches!(
        f.body.stmts[0],
        Stmt::Expr(Expr::Method { .. }, _)
    ));
}

#[test]
fn function_call_parses() {
    let f = parse_ok("let x = len(bgp.as_path); accept;");
    if let Stmt::Let { value, .. } = &f.body.stmts[0] {
        assert!(matches!(value, Expr::Call { .. }));
    } else {
        panic!("expected Let");
    }
}

#[test]
fn block_introduces_scope() {
    // The outer `{ }` is the filter body delimiter; the inner
    // `{ accept; }` is a Stmt::Block.
    let f = parse_ok("{ { accept; } }");
    assert!(matches!(f.body.stmts[0], Stmt::Block(..)));
}

#[test]
fn unbraced_body_form() {
    let f = parse_ok("accept;");
    assert_eq!(f.body.stmts.len(), 1);
}

#[test]
fn unterminated_if_is_an_error() {
    let e = parse_err("if true then");
    assert!(
        matches!(
            e.kind,
            ParseErrorKind::UnexpectedEof | ParseErrorKind::UnexpectedToken { .. }
        ),
        "{e}"
    );
}

#[test]
fn trailing_tokens_are_rejected() {
    let e = parse_err("accept; junk");
    assert!(
        matches!(e.kind, ParseErrorKind::UnexpectedToken { .. }),
        "{e}"
    );
}

// --- Recursion-limit regression tests --------------------------------
//
// The nightly `filter_parser` fuzz target found an
// AddressSanitizer stack-overflow on a 3 911-byte input of nested
// `[` set opens: the recursive-descent parser had no depth bound.
// These tests pin the fix at every recursive shape of the grammar.

#[test]
fn deeply_nested_set_literals_are_rejected() {
    // The exact fuzz-crasher shape: thousands of `[` opens.
    let src = "[".repeat(4_000);
    let e = parse_err(&src);
    assert!(
        matches!(e.kind, ParseErrorKind::RecursionLimitExceeded),
        "{e}"
    );
}

#[test]
fn deeply_nested_unary_ops_are_rejected() {
    let src = format!("{}true", "!".repeat(4_000));
    let e = parse_err(&src);
    assert!(
        matches!(e.kind, ParseErrorKind::RecursionLimitExceeded),
        "{e}"
    );
}

#[test]
fn deeply_nested_negation_is_rejected() {
    let src = format!("{}1", "-".repeat(4_000));
    let e = parse_err(&src);
    assert!(
        matches!(e.kind, ParseErrorKind::RecursionLimitExceeded),
        "{e}"
    );
}

#[test]
fn deeply_nested_parens_are_rejected() {
    let src = format!("{}true{}", "(".repeat(4_000), ")".repeat(4_000));
    let e = parse_err(&src);
    assert!(
        matches!(e.kind, ParseErrorKind::RecursionLimitExceeded),
        "{e}"
    );
}

#[test]
fn deeply_nested_ifs_are_rejected() {
    let src = "if true then ".repeat(1_000) + "accept;";
    let e = parse_err(&src);
    assert!(
        matches!(e.kind, ParseErrorKind::RecursionLimitExceeded),
        "{e}"
    );
}

#[test]
fn mixed_nesting_still_hits_the_limit() {
    // Alternating set / unary / paren levels — the interleaved
    // shape the fuzzer actually converges on (`[[[!![[[...`).
    let mut src = String::new();
    for _ in 0..1_000 {
        src.push('[');
        src.push_str("!!");
        src.push('(');
    }
    let e = parse_err(&src);
    assert!(
        matches!(e.kind, ParseErrorKind::RecursionLimitExceeded),
        "{e}"
    );
}

#[test]
fn nesting_just_under_the_limit_still_parses() {
    // 100 levels of parens sit exactly at `MAX_EXPR_DEPTH` (100;
    // the guard rejects depth > 100) and must parse cleanly — the
    // limit rejects pathological input, not legitimate deep
    // filters.
    let depth = 100;
    let src = format!("{}true{};", "(".repeat(depth), ")".repeat(depth));
    let f = parse_ok(&src);
    assert!(matches!(f.body.stmts[0], Stmt::Expr(..)));
}

#[test]
fn recursion_error_reports_location() {
    // The error should point at the token that tripped the limit,
    // not a generic (1, 1) position.
    let mut src = String::new();
    src.push_str("accept;\n");
    src.push_str(&"[".repeat(MAX_EXPR_DEPTH + 4));
    let e = parse_err(&src);
    assert!(matches!(e.kind, ParseErrorKind::RecursionLimitExceeded));
    assert_eq!(e.line, 2, "{e:?}");
    assert!(e.col > 1, "{e:?}");
}

#[test]
fn parse_error_span_points_at_offending_token() {
    // `bgp.unknown` — the unknown-field identifier is at line 1,
    // bytes 4..10.
    let src = "bgp.unknown = 5; accept;";
    let e = parse_err(src);
    assert!(matches!(e.kind, ParseErrorKind::UnknownBgpField(_)));
    assert_eq!(e.span.slice(src), Some("unknown"), "{e:?}");
    assert_eq!((e.line, e.col), (1, 5));
}

#[test]
fn parse_error_span_multiline() {
    let src = "accept;\nbgp.typo = 1;";
    let e = parse_err(src);
    assert_eq!(e.span.slice(src), Some("typo"), "{e:?}");
    assert_eq!((e.line, e.col), (2, 5));
}

#[test]
fn unknown_function_call_error_points_at_the_call() {
    let src = "accept; oops(1);";
    let e = parse_err(src);
    assert!(matches!(e.kind, ParseErrorKind::UnknownFunctionCall));
    // The span covers the whole call expression.
    assert_eq!(e.span.slice(src), Some("oops(1)"), "{e:?}");
    assert_eq!((e.line, e.col), (1, 9));
}

#[test]
fn ast_spans_cover_statements_and_expressions() {
    let src = "let x = 10.0.0.0/8;\nif net ~ [ 192.0.2.0/24 ] then { accept; }";
    let f = parse_ok(src);
    // `let` statement spans from `let` to the closing `;`.
    let let_span = f.body.stmts[0].span();
    assert_eq!(let_span.slice(src), Some("let x = 10.0.0.0/8;"));
    // The `if` statement spans from `if` to the closing `}`.
    let if_stmt = &f.body.stmts[1];
    assert!(matches!(if_stmt, Stmt::If { .. }));
    let if_span = if_stmt.span();
    assert_eq!(
        if_span.slice(src),
        Some("if net ~ [ 192.0.2.0/24 ] then { accept; }")
    );
    // The `if`'s condition expression covers `net ~ [ ... ]`.
    let Stmt::If { cond, .. } = if_stmt else {
        unreachable!()
    };
    assert_eq!(cond.span().slice(src), Some("net ~ [ 192.0.2.0/24 ]"));
    // The set literal inside the match RHS carries its own span.
    let Expr::Binary { rhs, .. } = cond else {
        unreachable!()
    };
    assert_eq!(rhs.span().slice(src), Some("[ 192.0.2.0/24 ]"));
    // The `let`'s value expression covers just the prefix.
    let Stmt::Let { value, .. } = &f.body.stmts[0] else {
        unreachable!()
    };
    assert_eq!(value.span().slice(src), Some("10.0.0.0/8"));
}

#[test]
fn expr_equality_ignores_spans() {
    // Compare two `Var` expressions from different positions:
    // structural equality must ignore the span fields.
    let f1 = parse_ok("let zzz = 1; accept;");
    let f2 = parse_ok("\n\nlet zzz = 1; accept;");
    let Stmt::Let { value: v1, .. } = &f1.body.stmts[0] else {
        unreachable!()
    };
    let Stmt::Let { value: v2, .. } = &f2.body.stmts[0] else {
        unreachable!()
    };
    assert_eq!(v1, v2, "equal content at different spans must be equal");
    assert_ne!(v1.span(), v2.span(), "spans themselves differ");
}
