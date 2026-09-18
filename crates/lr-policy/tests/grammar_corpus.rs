//! Pins every example in [`docs/filter_dsl_grammar.md`] (ROADMAP-v3 D9)
//! through `lr_policy::filter::compile`.
//!
//! The grammar document is the canonical filter DSL reference. This
//! test is the contract: every snippet the doc claims *parses* must
//! compile to `Ok`, and every snippet the doc claims is a *parse
//! error* must fail with the documented `ParseErrorKind`. If a future
//! grammar change drifts from the doc, this test fails first —
//! silently shipping a doc/source mismatch is worse than failing CI.
//!
//! Each test references the section number from the grammar doc so a
//! reader can cross-reference the prose. The snippets are duplicated
//! verbatim from the doc; if you edit the doc, edit the test in the
//! same commit (the CI step `cargo test -p lr-policy --test
//! grammar_corpus` enforces it).

use lr_policy::filter::compile;
use lr_policy::filter::parser::ParseErrorKind;

/// §7.1 — accept-on-prefix, reject-otherwise.
#[test]
fn s7_1_accept_on_prefix() {
    let body = "if net ~ 10.0.0.0/8 then accept; reject;";
    let f = compile("s7_1", body).expect("must compile");
    assert_eq!(f.body.stmts.len(), 2);
}

/// §7.2 — prefix-set range membership (BIRD `{ge,le}` syntax).
#[test]
fn s7_2_prefix_set_range_membership() {
    let body = "if net ~ [ 10.0.0.0/8{16,24} ] then accept; reject;";
    compile("s7_2", body).expect("must compile");
}

/// §7.3 — LOCAL_PREF policy with arithmetic and short-circuit AND.
#[test]
fn s7_3_local_pref_arithmetic() {
    let body = r#"
        let pref_floor = 100;
        let pref_cap = pref_floor * 2;
        if bgp.local_pref < pref_cap && net ~ 10.0.0.0/8 then {
            bgp.local_pref = pref_cap;
            bgp.communities += [ 64512:100 ];
            accept;
        }
        reject;
    "#;
    compile("s7_3", body).expect("must compile");
}

/// §7.4 — ROA-gated import.
#[test]
fn s7_4_roa_gated_import() {
    let body = r#"
        if roa.state == "invalid" then reject with "roa-invalid";
        if roa.state == "valid" then {
            bgp.local_pref = 200;
            accept;
        }
        reject;
    "#;
    compile("s7_4", body).expect("must compile");
}

/// §7.5 — `case` over BGP ORIGIN.
#[test]
fn s7_5_case_over_origin() {
    let body = r#"
        case bgp.origin {
            0 => accept;
            1 => { bgp.local_pref = 50; accept; }
            default => reject;
        }
    "#;
    compile("s7_5", body).expect("must compile");
}

/// §7.6 — user-defined function with optional `=> type` annotation.
#[test]
fn s7_6_user_defined_function() {
    let body = r#"
        function is_internal(asn) => bool {
            return asn == 64500;
        }
        if is_internal(bgp.as_path.first) then {
            bgp.local_pref = 200;
            accept;
        }
        reject;
    "#;
    compile("s7_6", body).expect("must compile");
}

/// §7.6 negative — the C-style `->` arrow is NOT a DSL token; the
/// return-type annotation uses `=>` (same token as `case` arms).
#[test]
fn s7_6_arrow_must_be_fat_arrow() {
    let body = r#"
        function is_internal(asn) -> bool { return asn; }
        if is_internal(1) then accept; reject;
    "#;
    let err = compile("s7_6_neg", body).unwrap_err();
    // The `->` lexes as Minus + Gt, so the parser sees `Minus` where
    // it expected `{` for the function body.
    assert!(
        matches!(
            err.kind,
            lr_policy::filter::parser::ParseErrorKind::UnexpectedToken { .. }
        ),
        "expected UnexpectedToken for `->` arrow, got {:?}",
        err.kind
    );
}

/// §7.7 — community-set mutation via `delete` and `filter` plus
/// `empty()` check.
#[test]
fn s7_7_community_set_mutation() {
    let body = r#"
        bgp.communities = delete(bgp.communities, [ 64512:* ]);
        bgp.communities = filter(bgp.communities, [ 65000:100 ]);
        if empty(bgp.communities) then reject;
        accept;
    "#;
    compile("s7_7", body).expect("must compile");
}

/// §7.8 — AS-path membership via comma-separated set.
///
/// The matcher is flat set-membership, not BIRD regex — `_` is parsed
/// by the lexer but does not yet carry meaning inside `~` patterns.
#[test]
fn s7_8_as_path_membership() {
    let body = "if bgp.as_path ~ [ 64500, 64502 ] then accept; reject;";
    compile("s7_8", body).expect("must compile");
}

/// §7.8 negative — bare `_` between items inside a `[ … ]` set literal
/// is a parse error. Set literals are comma-separated.
#[test]
fn s7_8_underscore_in_set_literal_rejected() {
    let body = "if bgp.as_path ~ [ 64500 _ 64502 ] then accept; reject;";
    let err = compile("s7_8_neg", body).unwrap_err();
    assert!(
        matches!(
            err.kind,
            lr_policy::filter::parser::ParseErrorKind::UnexpectedToken { .. }
        ),
        "expected UnexpectedToken for bare `_` in set, got {:?}",
        err.kind
    );
}

/// §7.9 — extended-community tuple `(rt, asn, value)`.
///
/// The local part is a concrete integer — there is no `*` wildcard
/// for extended-community locals (unlike community pairs).
#[test]
fn s7_9_extended_community_tuple() {
    let body = r#"
        bgp.ext_communities += [ (rt, 64512, 100) ];
        if bgp.ext_communities ~ [ (rt, 64512, 100) ] then accept;
        reject;
    "#;
    compile("s7_9", body).expect("must compile");
}

/// §7.9 negative — `*` is NOT a valid extended-community local part.
/// Only community pairs accept the `*` wildcard.
#[test]
fn s7_9_wildcard_local_part_rejected() {
    let body = "bgp.ext_communities += [ (rt, 64512, *) ];";
    let err = compile("s7_9_neg", body).unwrap_err();
    assert!(
        matches!(
            err.kind,
            lr_policy::filter::parser::ParseErrorKind::InvalidCommunity(_)
        ),
        "expected InvalidCommunity for `*` local part, got {:?}",
        err.kind
    );
}

/// §7.10 — large-community triple `g:d1:d2`.
#[test]
fn s7_10_large_community_triple() {
    let body = r#"
        bgp.large_communities += [ 64512:100:200 ];
        if bgp.large_communities ~ [ 64512:100:200 ] then accept;
        reject;
    "#;
    compile("s7_10", body).expect("must compile");
}

/// §7.11 — empty body is a parse error.
#[test]
fn s7_11_empty_body_rejected() {
    let err = compile("s7_11", "{}").unwrap_err();
    assert!(
        matches!(err.kind, ParseErrorKind::EmptyFilterBody),
        "expected EmptyFilterBody, got {:?}",
        err.kind
    );
}

/// §7.12 — undeclared function call is a parse error.
#[test]
fn s7_12_undeclared_function_call_rejected() {
    let body = "if typo_function(net) then accept; reject;";
    let err = compile("s7_12", body).unwrap_err();
    assert!(
        matches!(err.kind, ParseErrorKind::UnknownFunctionCall),
        "expected UnknownFunctionCall, got {:?}",
        err.kind
    );
}

/// §7.13 — `+=` on a scalar field is a parse error.
#[test]
fn s7_13_plus_eq_on_scalar_field_rejected() {
    let body = "bgp.local_pref += 1;";
    let err = compile("s7_13", body).unwrap_err();
    match err.kind {
        ParseErrorKind::ReadOnlyField(s) => {
            assert_eq!(s, "bgp.local_pref", "wrong field name in error");
        }
        other => panic!("expected ReadOnlyField, got {other:?}"),
    }
}

/// §7.14 — deep nesting exceeds `MAX_EXPR_DEPTH = 128`.
///
/// 200 unclosed `[` characters must be rejected as
/// `RecursionLimitExceeded`. The exact fuzzer crasher is pinned in
/// `filter_corpus.rs`; this is the in-doc form (an even count of 200
/// is well above the 128 bound and produces the same error).
#[test]
fn s7_14_recursion_limit_exceeded() {
    let body: String = "[".repeat(200);
    let err = compile("s7_14", &body).unwrap_err();
    assert!(
        matches!(err.kind, ParseErrorKind::RecursionLimitExceeded),
        "expected RecursionLimitExceeded, got {:?}",
        err.kind
    );
}

/// §4 — operator precedence: `*` binds tighter than `+`, which binds
/// tighter than `==`, which binds tighter than `&&`, which binds
/// tighter than `||`. Encoded in `BinaryOp::precedence`.
#[test]
fn s4_operator_precedence_chain() {
    // `a || b && c == d + e * f` parses as `a || (b && (c == (d + (e * f))))`.
    let body = r#"
        let a = true;
        let b = true;
        let c = 1;
        let d = 1;
        let e = 2;
        let f = 3;
        if a || b && c == d + e * f then accept;
        reject;
    "#;
    compile("s4", body).expect("must compile");
}

/// §3.2 — every built-in function name is accepted by the call
/// validator. Arity / type errors are runtime concerns; the parser
/// must accept each name with one argument.
#[test]
fn s3_2_builtin_function_names_compile() {
    for name in ["len", "delete", "filter", "empty", "count", "first", "last"] {
        let body = format!("if {name}(bgp.as_path) then accept; reject;");
        compile("s3_2", &body).unwrap_or_else(|e| panic!("built-in {name} must compile: {e}"));
    }
}

/// §3.2 — `defined()` and `exists()` accept exactly one argument;
/// zero or two is a parse error.
#[test]
fn s3_2_defined_and_exists_arity_enforced() {
    for name in ["defined", "exists"] {
        let zero = format!("if {name}() then accept; reject;");
        let err = compile("arity0", &zero).unwrap_err();
        assert!(
            matches!(err.kind, ParseErrorKind::BadArgCount { .. }),
            "expected BadArgCount for {name}(), got {:?}",
            err.kind
        );

        let two = format!("if {name}(net, net) then accept; reject;");
        let err = compile("arity2", &two).unwrap_err();
        assert!(
            matches!(err.kind, ParseErrorKind::BadArgCount { .. }),
            "expected BadArgCount for {name}(a, b), got {:?}",
            err.kind
        );
    }
}

/// §2.3 — set literal element forms. Every kind the grammar lists
/// must compile inside a `[ … ]` set.
#[test]
fn s2_3_set_literal_forms_compile() {
    let body = r#"
        let pfx = [ 10.0.0.0/8, 192.0.2.0/24{16,32} ];
        let ints = [ 1, 2, 3 ];
        let pairs = [ 64512:100, 64512:200 ];
        let wild_asn = [ 64512:* ];
        let wild_val = [ *:100 ];
        let wild_both = [ *:* ];
        let triple = [ 64512:100:200 ];
        let ext = [ (rt, 64512, 100) ];
        if net ~ pfx && bgp.as_path ~ ints then accept;
        reject;
    "#;
    compile("s2_3", body).expect("must compile");
}

/// §2.3 — extended community with IPv6 administrator is a parse
/// error (`InvalidCommunity`).
#[test]
fn s2_3_ext_community_ipv6_administrator_rejected() {
    let body = "bgp.ext_communities += [ (rt, 2001:db8::1, 100) ];";
    let err = compile("s2_3_v6", body).unwrap_err();
    assert!(
        matches!(err.kind, ParseErrorKind::InvalidCommunity(_)),
        "expected InvalidCommunity for IPv6 admin, got {:?}",
        err.kind
    );
}

/// §2.4 — every route field the grammar lists must compile.
/// Read-only fields used in expression position; settable fields on
/// the left of `=`; community-set fields on the left of `+=`.
#[test]
fn s2_4_route_fields_compile() {
    let body = r#"
        if defined(net) && defined(proto) && defined(source) then {
            if defined(bgp.as_path) && defined(bgp.origin) && defined(roa.state) then {
                bgp.local_pref = 100;
                bgp.med = 50;
                bgp.next_hop = 10.0.0.1;
                bgp.communities += [ 64512:100 ];
                bgp.ext_communities += [ (rt, 64512, 100) ];
                bgp.large_communities += [ 64512:100:200 ];
                accept;
            }
        }
        reject;
    "#;
    compile("s2_4", body).expect("must compile");
}

/// §2.4 — assigning to a read-only field is a parse error.
#[test]
fn s2_4_readonly_field_assignment_rejected() {
    let body = "net = 10.0.0.0/8;";
    let err = compile("s2_4_ro", body).unwrap_err();
    assert!(
        matches!(err.kind, ParseErrorKind::ReadOnlyField(_)),
        "expected ReadOnlyField, got {:?}",
        err.kind
    );
}

/// §1.3 — `function` is a contextual keyword: recognised at filter
/// top level only, usable as a variable name inside an expression.
#[test]
fn s1_3_function_is_contextual_keyword() {
    let body = r#"
        let function = 100;
        if bgp.local_pref < function then accept;
        reject;
    "#;
    compile("s1_3_ctx", body).expect("must compile");
}

/// §1.3 — `return` is a contextual keyword at statement position.
/// Inside an expression it is an ordinary identifier (a variable
/// reference).
#[test]
fn s1_3_return_is_contextual_keyword() {
    let body = r#"
        let return = 1;
        if return == 1 then accept;
        reject;
    "#;
    compile("s1_3_ret", body).expect("must compile");
}

/// §1.4 — the string escape set is `\\`, `\"`, `\n`, `\t`, `\r`, `\0`.
/// Unknown escapes (e.g. `\x41`) are fatal lexer errors.
///
/// Implementation note: `Parser::new` swallows the lexer error and
/// substitutes a single `[Eof]` token stream, so the parser surfaces
/// it as `EmptyFilterBody` rather than wrapping the original
/// `LexerError`. The grammar doc §7.14 records this limitation; a
/// follow-up may surface the original lexer error for better UX.
#[test]
fn s1_4_unknown_string_escape_rejected() {
    // The unknown `\x` causes `tokenize()` to return `Err`, which
    // `Parser::new` replaces with `[Eof]`. `parse_filter` then sees
    // the single-Eof stream and reports `EmptyFilterBody`.
    let err = compile("s1_4_esc", r#"reject with "bad\x41escape";"#);
    assert!(err.is_err(), "unknown escape must be fatal");
    let err = err.unwrap_err();
    assert!(
        matches!(
            err.kind,
            lr_policy::filter::parser::ParseErrorKind::EmptyFilterBody
        ),
        "expected EmptyFilterBody (current lexer-error collapse), got {:?}",
        err.kind
    );
}

/// §1.5 — `!~` is one token; `! ~` (with whitespace) is two tokens
/// and produces a different parse. The doc's §1.5 specifies
/// "longest match wins" — the lexer test in `lexer.rs::tests`
/// already pins this at the token level; here we pin it at the
/// parser level.
#[test]
fn s1_5_bang_tilde_is_one_token() {
    // `bgp.as_path !~ [ 64500 ]` parses as a NotMatch binary op.
    let body = "if bgp.as_path !~ [ 64500 ] then accept; reject;";
    let f = compile("s1_5_bt", body).expect("must compile");
    assert_eq!(f.body.stmts.len(), 2);
}

/// §6 — `MAX_EXPR_DEPTH = 108`. The parser's `enter()` increments
/// depth on every statement descent (`parse_stmt`) and every
/// expression descent (`parse_unary`); the bound is checked with
/// `> MAX_EXPR_DEPTH` (so depth exactly 108 is allowed, 109 errors).
///
/// For a body like `let x = ((...1...));` with `N` parenthesized
/// groups, the depth sequence is: 1 (the `let` stmt) + 1 (the outer
/// `parse_unary`) + N (each nested paren). So `N = 106` lands at
/// depth exactly 108 (allowed) and `N = 107` lands at 109 (rejected).
#[test]
fn s6_max_expr_depth_boundary() {
    // 106 nested parens around `1` inside a `let` statement → depth = 108 (allowed).
    let body = format!("let x = {}1{}; accept;", "(".repeat(106), ")".repeat(106));
    compile("s6_boundary", &body).expect("depth == MAX_EXPR_DEPTH must compile");
}

/// §6 — `MAX_EXPR_DEPTH = 108`. A 107-deep nesting must fail.
#[test]
fn s6_max_expr_depth_exceeded() {
    let body = format!("let x = {}1{}; accept;", "(".repeat(107), ")".repeat(107));
    let err = compile("s6_exceeded", &body).unwrap_err();
    assert!(
        matches!(err.kind, ParseErrorKind::RecursionLimitExceeded),
        "expected RecursionLimitExceeded, got {:?}",
        err.kind
    );
}
