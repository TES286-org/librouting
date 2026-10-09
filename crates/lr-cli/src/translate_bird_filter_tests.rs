use super::*;

fn ctx(defines: &[(&str, &str)], roa_tables: usize) -> Ctx {
    Ctx {
        defines: defines
            .iter()
            .map(|(a, b)| (a.to_string(), b.to_string()))
            .collect(),
        roa_tables,
    }
}

fn body_ok(body: &str, c: &Ctx) -> String {
    translate_body(body, c).expect("translation succeeds")
}

fn body_fails(body: &str, c: &Ctx) -> Vec<String> {
    translate_body(body, c).expect_err("translation fails")
}

#[test]
fn empty_body_translates_to_empty() {
    // Placeholder guard: the module must stay importable.
    let c = ctx(&[], 0);
    let (out, notes) = translate_body_inner("", &c);
    assert!(out.is_empty());
    assert!(notes.is_empty());
}

#[test]
fn boolean_operators_pass_through_symbols_only() {
    // BIRD 2 has no and/or/not keywords (verified against
    // filter/config.Y) — the symbols are shared with lr. BIRD `=`
    // is equality and becomes lr's `==`.
    let c = ctx(&[], 0);
    let out = body_ok("if 1 = 1 && 2 = 2 || !false then accept;", &c);
    assert_eq!(out, "if 1 == 1 && 2 == 2 || !false then accept;");
}

#[test]
fn bgp_attribute_renames() {
    let c = ctx(&[], 0);
    let out = body_ok("bgp_local_pref := 200; bgp_med := 10;", &c);
    assert!(out.contains("bgp.local_pref = 200;"));
    assert!(out.contains("bgp.med = 10;"));
}

#[test]
fn path_method_calls_rename() {
    let c = ctx(&[], 0);
    let out = body_ok("bgp_path.prepend(64512);", &c);
    assert!(out.contains("bgp.as_path.prepend(64512);"));
}

#[test]
fn path_accessors_are_unfaithful() {
    let c = ctx(&[], 0);
    let notes = body_fails("if bgp_path.first = 64512 then accept;", &c);
    assert!(notes.iter().any(|n| n.contains("bgp_path.first")));
}

#[test]
fn community_sets_pass_through() {
    let c = ctx(&[], 0);
    let out = body_ok("if net ~ [ 10.0.0.0/8, 192.0.2.0/24 ] then accept;", &c);
    // Untouched tokens keep their original spelling and spacing.
    assert!(out.contains("net ~ [ 10.0.0.0/8, 192.0.2.0/24 ]"));
}

#[test]
fn community_literals_keep_colons() {
    let c = ctx(&[], 0);
    let out = body_ok("bgp_community.add(64512:100);", &c);
    assert!(out.contains("bgp.communities.add(64512:100);"));
}

#[test]
fn typed_declarations_become_let() {
    let c = ctx(&[], 0);
    let out = body_ok("int x := 5; x := x + 1;", &c);
    assert!(out.contains("let x = 5;"));
    assert!(out.contains("x = x + 1;"));
    // Bare declaration: typed zero value.
    let out = body_ok("bool flag; flag := true;", &c);
    assert!(out.contains("let flag = false;"));
    // Two-word type.
    let out = body_ok("ip prefix p := 10.0.0.0/8;", &c);
    assert!(out.contains("let p = 10.0.0.0/8;"));
}

#[test]
fn uninitialised_non_scalar_is_unfaithful() {
    let c = ctx(&[], 0);
    let notes = body_fails("clist l; l := -empty-;", &c);
    assert!(notes
        .iter()
        .any(|n| n.contains("has no lr default") && n.contains("`l`")));
}

#[test]
fn proto_comparisons_are_unfaithful() {
    // BIRD's proto is the protocol instance name; lr's is the
    // protocol type — a comparison would silently change meaning.
    let c = ctx(&[], 0);
    let notes = body_fails("if proto = \"uplink\" then accept;", &c);
    assert!(notes.iter().any(|n| n.contains("`proto`")));
}

#[test]
fn bird_only_attributes_are_unfaithful() {
    let c = ctx(&[], 0);
    for snippet in [
        "if from = 192.0.2.9 then accept;",
        "if gw = 192.0.2.1 then accept;",
        "if ifname = \"eth0\" then accept;",
        "if preference = 100 then accept;",
        "if ospf_router_id = 1.2.3.4 then accept;",
        "if krt_source = 0 then accept;",
        "if source = RTS_BGP then accept;",
    ] {
        let notes = body_fails(snippet, &c);
        assert!(
            notes.iter().any(|n| n.contains("no faithful lr mapping")),
            "{snippet} should be unfaithful"
        );
    }
}

#[test]
fn print_remains_unfaithful_but_case_translates() {
    // `print` is still unfaithful — lr has no side-effecting
    // print statement. `case` now translates (the structural
    // rewrite pass converts `:` → `=>` and `else:` →
    // `default =>`), so it must NOT appear in the unfaithful
    // set anymore.
    let c = ctx(&[], 0);
    assert!(body_fails("print \"x\";", &c)
        .iter()
        .any(|n| n.contains("`print`")));
    let out = body_ok("case net { 10.0.0.0/8: accept; else: reject; }", &c);
    assert!(out.contains("case net {"));
    assert!(out.contains("=>"));
    assert!(out.contains("default"));
}

#[test]
fn not_match_passes_through() {
    // `!~` now passes through verbatim — lr's filter DSL gained
    // `!~` (BinaryOp::NotMatch) as a peer of `~` in commit
    // 1b09aa7. BIRD and lr spell it identically.
    let c = ctx(&[], 0);
    let out = body_ok("if net !~ 10.0.0.0/8 then accept;", &c);
    assert!(out.contains("!~"), "expected `!~` in output, got: {out}");
}

#[test]
fn defines_are_substituted() {
    let c = ctx(&[("MY_ASN", "64512"), ("CUST_NETS", "[ 10.0.0.0/8 ]")], 0);
    let out = body_ok(
        "bgp_path.prepend(MY_ASN); if net ~ CUST_NETS then accept;",
        &c,
    );
    assert!(out.contains("bgp.as_path.prepend(64512);"));
    assert!(out.contains("if net ~ [ 10.0.0.0/8 ] then accept;"));
}

#[test]
fn single_table_roa_check_maps() {
    let c = ctx(&[], 1);
    let out = body_ok("if roa_check(t4) = ROA_INVALID then reject; accept;", &c);
    assert!(out.contains("if roa.state == \"invalid\" then reject;"));
}

#[test]
fn multi_table_roa_check_is_unfaithful() {
    let c = ctx(&[], 2);
    let notes = body_fails("if roa_check(t4) = ROA_INVALID then reject;", &c);
    assert!(notes.iter().any(|n| n.contains("roa_check")));
}

#[test]
fn explicit_arg_roa_check_is_unfaithful() {
    let c = ctx(&[], 1);
    let notes = body_fails(
        "if roa_check(t4, net, 64512) = ROA_INVALID then reject;",
        &c,
    );
    assert!(notes.iter().any(|n| n.contains("roa_check")));
}

#[test]
fn origin_literals_map_to_integers() {
    let c = ctx(&[], 0);
    let out = body_ok("if bgp_origin = ORIGIN_IGP then accept;", &c);
    assert!(out.contains("if bgp.origin == 0 then accept;"));
}

#[test]
fn reject_reason_strings_pass_through() {
    let c = ctx(&[], 0);
    let out = body_ok("reject \"policy says no\";", &c);
    assert!(out.contains("reject \"policy says no\";"));
}

#[test]
fn functions_strip_parameter_types() {
    let c = ctx(&[], 0);
    let decl = translate_function(
        "function tag_routes(int cost, ip prefix p) { bgp_med := cost; return true; }",
        &c,
    )
    .expect("function translates");
    assert!(decl.starts_with("function tag_routes(cost, p)"));
    assert!(decl.contains("bgp.med = cost;"));
}

#[test]
fn where_expressions_wrap_into_accept_reject() {
    let src = BirdFilterSource::default();
    let body = translate_where("net ~ 10.0.0.0/8", &src).expect("where translates");
    assert_eq!(body, "if net ~ 10.0.0.0/8 then accept;\nreject;");
}

#[test]
fn full_pipeline_emits_compiling_filters() {
    let src = BirdFilterSource {
        defines: vec![("MY_ASN".into(), "64512".into())],
        functions: vec![(
            "set_pref".into(),
            "function set_pref(int p) { bgp_local_pref := p; return true; }".into(),
        )],
        filters: vec![(
            "export_to_lr".into(),
            vec![
                "if net ~ [ 10.0.0.0/8 ] then {".to_string(),
                "    bgp_path.prepend(MY_ASN);".to_string(),
                "    set_pref(200);".to_string(),
                "    accept;".to_string(),
                "}".to_string(),
                "reject;".to_string(),
            ],
        )],
        roa_tables: vec![vec![RoaRow {
            prefix: "203.0.113.0/24".into(),
            max_length: Some(24),
            asn: 64512,
        }]],
    };
    let (out, roas) = translate(&src);
    assert_eq!(roas.len(), 1);
    assert_eq!(out.ok.len(), 1, "failed: {:?}", out.failed);
    let f = &out.ok[0];
    assert_eq!(f.name, "export_to_lr");
    assert!(f.body.contains("function set_pref(p)"));
    assert!(f.body.contains("bgp.as_path.prepend(64512);"));
    assert!(f.body.contains("set_pref(200);"));
}

#[test]
fn unfaithful_function_blocks_the_filter() {
    let src = BirdFilterSource {
        defines: vec![],
        functions: vec![("debug".into(), "function debug() { print \"hi\"; }".into())],
        filters: vec![("f".into(), vec!["debug(); accept;".to_string()])],
        roa_tables: vec![],
    };
    let (out, _) = translate(&src);
    assert!(out.ok.is_empty());
    assert!(out.failed.iter().any(|(n, _)| n == "f" || n == "debug"));
}

// --- D14.5/D14.6: case + !~ translation ------------------------
//
// BIRD's `case` syntax (`pat: body; else: body;`) and `!~`
// operator now translate faithfully. These tests pin the
// mapping verified against BIRD's `filter/config.Y` §`switch_body`
// and `conf/cf-lex.l` (the `else:` ELSECOL token).

#[test]
fn case_with_single_stmt_arms_translates() {
    let c = ctx(&[], 0);
    let out = body_ok(
        "case bgp_local_pref { 100: accept; 200: reject; else: accept; }",
        &c,
    );
    // Every arm separator became `=>`; the default arm became
    // `default =>`. The bare-stmt arm bodies are wrapped in `{ … }`
    // because lr DSL case arm bodies parse a single statement.
    assert!(out.contains("100 => { accept; }"));
    assert!(out.contains("200 => { reject; }"));
    assert!(out.contains("default => { accept; }"));
}

#[test]
fn case_with_block_arms_translates() {
    let c = ctx(&[], 0);
    let out = body_ok(
        "case bgp_local_pref {\
             \n  100: { bgp_local_pref := 200; accept; }\
             \n  else: { reject; }\
             \n}",
        &c,
    );
    // Block arm bodies are left as `{ … }` (no double-wrapping).
    // `bgp_local_pref := 200` becomes `bgp.local_pref = 200`.
    assert!(out.contains("100 => { bgp.local_pref = 200; accept; }"));
    assert!(out.contains("default => { reject; }"));
}

#[test]
fn case_with_parenthesised_pattern_translates() {
    // BIRD's `filter/test.conf` uses `(2+2):` as a pattern —
    // parenthesised expressions are valid arm patterns.
    let c = ctx(&[], 0);
    let out = body_ok("case bgp_local_pref { (2+2): accept; else: reject; }", &c);
    assert!(out.contains("(2+2) => { accept; }"));
    assert!(out.contains("default => { reject; }"));
}

#[test]
fn case_with_multiple_patterns_translates() {
    // `1, 2, 3: body;` — comma-separated patterns share one arm.
    let c = ctx(&[], 0);
    let out = body_ok("case bgp_local_pref { 1, 2, 3: accept; else: reject; }", &c);
    assert!(out.contains("1, 2, 3 => { accept; }"));
}

#[test]
fn case_range_arm_is_unfaithful() {
    // `1 .. 5:` — lr DSL case arms match exact values only;
    // there is no range-arm equivalent.
    let c = ctx(&[], 0);
    let notes = body_fails("case bgp_local_pref { 1 .. 5: accept; else: reject; }", &c);
    assert!(
        notes.iter().any(|n| n.contains("case arm range")),
        "expected range-arm note, got: {notes:?}"
    );
}

#[test]
fn not_match_in_complex_expression_translates() {
    let c = ctx(&[], 0);
    let out = body_ok(
        "if net ~ 10.0.0.0/8 && net !~ 10.1.0.0/16 then accept; reject;",
        &c,
    );
    assert!(out.contains("net ~ 10.0.0.0/8"));
    assert!(out.contains("net !~ 10.1.0.0/16"));
}

#[test]
fn not_match_against_set_translates() {
    let c = ctx(&[], 0);
    let out = body_ok(
        "if net !~ [ 10.0.0.0/8, 192.168.0.0/16 ] then accept; reject;",
        &c,
    );
    assert!(out.contains("net !~ [ 10.0.0.0/8, 192.168.0.0/16 ]"));
}

#[test]
fn case_and_not_match_together_compile() {
    // End-to-end: a filter mixing `case` and `!~` must compile
    // in the lr DSL (the `translate` backstop runs `compile`).
    let src = BirdFilterSource {
        defines: vec![],
        functions: vec![],
        filters: vec![(
            "classify".into(),
            vec![
                "case bgp_local_pref {".to_string(),
                "  100: accept;".to_string(),
                "  200: { bgp_med := 50; accept; }".to_string(),
                "  else: reject;".to_string(),
                "}".to_string(),
                "if net !~ 10.0.0.0/8 then reject;".to_string(),
                "accept;".to_string(),
            ],
        )],
        roa_tables: vec![],
    };
    let (out, _) = translate(&src);
    assert_eq!(out.ok.len(), 1, "failed: {:?}", out.failed);
    let f = &out.ok[0];
    assert!(f.body.contains("case bgp.local_pref {"));
    assert!(f.body.contains("=> { accept; }"));
    assert!(f.body.contains("default => { reject; }"));
    assert!(f.body.contains("net !~ 10.0.0.0/8"));
}
