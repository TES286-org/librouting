//! BIRD 2 filter-language translation to the lr filter DSL
//! (ROADMAP-v3 D14.1).
//!
//! # Source of truth
//!
//! The mapping below was verified against BIRD's grammar and lexer
//! first-hand (`filter/config.Y` + `conf/cf-lex.l`, CZ-NIC sources):
//!
//! * Boolean operators are **only** the symbolic `&&` / `||` / `!` —
//!   there are no `and` / `or` / `not` keywords in BIRD 2 (the
//!   `CF_KEYWORDS` block in `filter/config.Y` does not declare them).
//!   BIRD spells equality `=` and assignment `:=`; lr spells
//!   equality `==` and assignment `=` — the translator swaps the
//!   two. `~` / `!=` / `<=` / `>=` are shared.
//! * BGP attributes are `bgp_path`, `bgp_local_pref`, `bgp_med`,
//!   `bgp_next_hop`, `bgp_origin`, `bgp_community`,
//!   `bgp_ext_community`, `bgp_large_community`; lr spells them
//!   `bgp.as_path`, `bgp.local_pref`, … — a word-level rename.
//! * Variables are typed (`int x := 5;`); lr's `let` is untyped.
//! * `roa_check(table)` returns `ROA_VALID` / `ROA_UNKNOWN` /
//!   `ROA_INVALID`; lr exposes the merged store as `roa.state`
//!   compared against `"valid"` / `"not-found"` / `"invalid"`.
//! * `define NAME = value;` is BIRD's constant machinery — lr has
//!   none, so constants are substituted textually before translation.
//! * `function name(int a, …) { … }` — lr's user functions (D3.1)
//!   take untyped parameters, so parameter types are stripped.
//!
//! # Fail-closed translation
//!
//! BIRD filters are behaviour-critical. When a body contains ANY
//! construct without a faithful lr mapping (`case` statements,
//! `print`, BIRD route attributes lr does not model — `from`, `gw`,
//! `ifname`, …, `proto` comparisons (BIRD's `proto` is the protocol
//! *instance* name while lr's is the protocol *type*), `!~`, as-path
//! accessors beyond the method calls, multi-table `roa_check`, …) the
//! filter is **not emitted at all** and the offending constructs are
//! reported. A silently re-filtered policy would be worse than a
//! visible conversion gap. Every emitted body is additionally
//! validated by running it through `lr_policy::filter::compile`, so
//! an emitted filter is always a filter the lr daemon can actually
//! load.

use lr_policy::filter;
use lr_policy::filter::ast::{Expr, Filter, Stmt};

/// One faithfully translated filter: the BIRD name plus the lr DSL
/// body (functions it depends on are embedded ahead of the body).
#[derive(Debug, Clone)]
pub(super) struct FilterRow {
    pub name: String,
    pub body: String,
}

/// One `roa` entry captured from a BIRD `roa table` block.
#[derive(Debug, Clone)]
pub(super) struct RoaRow {
    pub prefix: String,
    pub max_length: Option<u8>,
    pub asn: u32,
}

/// Raw BIRD captures handed over by `translate.rs` after its
/// line-based scan: define constants, function and filter bodies
/// (verbatim, comments already stripped), ROA table entries.
#[derive(Debug, Default)]
pub(super) struct BirdFilterSource {
    /// `(name, value_text)` in source order.
    pub defines: Vec<(String, String)>,
    /// `(name, header_and_body)` — everything from the `function`
    /// header line through the closing brace.
    pub functions: Vec<(String, String)>,
    /// `(name, body_lines)` — the inside of `filter NAME { … }`.
    pub filters: Vec<(String, Vec<String>)>,
    /// Per-`roa table` entry lists, in source order.
    pub roa_tables: Vec<Vec<RoaRow>>,
}

/// Result of translating the captured filter set.
#[derive(Debug, Default)]
pub(super) struct TranslatedFilters {
    /// Filters that translated faithfully, in source order.
    pub ok: Vec<FilterRow>,
    /// Filters that could not be translated faithfully:
    /// `(bird name, per-construct notes)`.
    pub failed: Vec<(String, Vec<String>)>,
}

/// Translate the whole captured filter set. Returns the emitted
/// filters plus the ROA rows extracted from `roa table` blocks (the
/// entries carry over regardless of filter outcomes — they feed the
/// daemon's `[[roa]]` tables).
pub(super) fn translate(src: &BirdFilterSource) -> (TranslatedFilters, Vec<RoaRow>) {
    let mut roa_rows: Vec<RoaRow> = Vec::new();
    for table in &src.roa_tables {
        roa_rows.extend(table.iter().cloned());
    }
    let ctx = Ctx {
        defines: src.defines.clone(),
        roa_tables: src.roa_tables.len(),
    };
    let mut out = TranslatedFilters::default();

    // Functions first (filters embed the ones they call).
    let mut clean_functions: Vec<(String, String)> = Vec::new();
    let mut failed_functions: Vec<String> = Vec::new();
    for (name, text) in &src.functions {
        match translate_function(text, &ctx) {
            Ok(decl) => clean_functions.push((name.clone(), decl)),
            Err(notes) => {
                failed_functions.push(name.clone());
                out.failed.push((
                    name.clone(),
                    notes
                        .iter()
                        .map(|n| format!("function {name}: {n}"))
                        .collect(),
                ));
            }
        }
    }

    for (name, lines) in &src.filters {
        let body = lines.join("\n");
        // Functions this filter calls, transitively.
        let mut needed: Vec<String> = Vec::new();
        let mut frontier = called_functions(&body, &clean_functions);
        while let Some(f) = frontier.pop() {
            if needed.contains(&f) {
                continue;
            }
            needed.push(f.clone());
            if let Some((_, text)) = clean_functions.iter().find(|(n, _)| *n == f) {
                for dep in called_functions(text, &clean_functions) {
                    if !needed.contains(&dep) {
                        frontier.push(dep);
                    }
                }
            }
        }
        if needed.iter().any(|f| failed_functions.contains(f)) {
            out.failed.push((
                name.clone(),
                vec!["filter calls a function that has no faithful lr translation".to_string()],
            ));
            continue;
        }

        match translate_body(&body, &ctx) {
            Ok(translated) => {
                let mut full = String::new();
                for f in &needed {
                    let decl = &clean_functions
                        .iter()
                        .find(|(n, _)| n == f)
                        .expect("needed function recorded")
                        .1;
                    full.push_str(decl);
                    full.push('\n');
                }
                full.push_str(&translated);
                // Backstop: an emitted filter must compile in lr.
                if let Err(e) = filter::compile(name, &full) {
                    out.failed.push((
                        name.clone(),
                        vec![format!(
                            "translated body does not compile in the lr filter DSL: {e}"
                        )],
                    ));
                } else if let Ok(parsed) = filter::compile(name, &full) {
                    // Backstop 2: compile() does not check variable
                    // references; a leftover BIRD constant or attribute
                    // word would only fail at route-eval time. Walk the
                    // AST and reject bodies referencing names nothing
                    // introduced.
                    let unknown = verify_vars(&parsed);
                    if unknown.is_empty() {
                        out.ok.push(FilterRow {
                            name: name.clone(),
                            body: full,
                        });
                    } else {
                        out.failed.push((name.clone(), unknown));
                    }
                } else {
                    unreachable!("compile succeeded above but failed here");
                }
            }
            Err(notes) => out.failed.push((name.clone(), notes)),
        }
    }
    (out, roa_rows)
}

/// Translate `import where EXPR` / `export where EXPR`: BIRD's
/// semantics are "accept iff EXPR holds", so the lr body wraps the
/// translated expression in `if … then accept; reject;`. Returns the
/// lr body or the unfaithful-construct notes.
pub(super) fn translate_where(expr: &str, src: &BirdFilterSource) -> Result<String, Vec<String>> {
    let ctx = Ctx {
        defines: src.defines.clone(),
        roa_tables: src.roa_tables.len(),
    };
    let translated = translate_body(expr, &ctx)?;
    let body = format!("if {translated} then accept;\nreject;");
    // The wrapper only adds statements around a validated expression;
    // compile once to keep the "emitted filters always compile"
    // guarantee uniform.
    match filter::compile("where", &body) {
        Ok(_) => Ok(body),
        Err(e) => Err(vec![format!(
            "translated `where` expression does not compile in the lr filter DSL: {e}"
        )]),
    }
}

// ---------------------------------------------------------------------------
// Translation context
// ---------------------------------------------------------------------------

struct Ctx {
    defines: Vec<(String, String)>,
    roa_tables: usize,
}

/// BIRD type keywords for variable declarations. `ip prefix` and
/// friends are two-word types.
const TYPE_WORDS: &[&str] = &[
    "int",
    "bool",
    "ip",
    "prefix",
    "pair",
    "quad",
    "ec",
    "lc",
    "string",
    "bytestring",
    "bgppath",
    "bgpmask",
    "clist",
    "eclist",
    "lclist",
    "enum",
    "rd",
    "mac",
];

/// BIRD route attributes (and friends) with no faithful lr meaning —
/// any occurrence marks the filter unfaithful. `proto` is listed for
/// a different reason: BIRD's `proto` is the protocol *instance*
/// name while lr's `proto` is the protocol *type*, so a comparison
/// would silently change meaning. `case` is NOT listed here — it has
/// a structural translation handled by `rewrite_cases` below.
const UNMAPPABLE_WORDS: &[&str] = &[
    "from",
    "gw",
    "scope",
    "dest",
    "ifname",
    "ifindex",
    "weight",
    "preference",
    "proto",
    "print",
    "printn",
    "putn",
    "eval",
    "bt_assert",
    "bt_test_suite",
    "bt_test_same",
    "bt_check_assign",
];

/// BIRD attribute-word prefixes with no lr equivalent (per-protocol
/// attributes: `ospf_router_id`, `krt_source`, …).
const UNMAPPABLE_PREFIXES: &[&str] = &[
    "krt_",
    "ospf_",
    "rip_",
    "babel_",
    "static_",
    "direct_",
    "device_",
    "pipe_",
    "aggregated_",
    // BIRD route-source enum literals (RTS_BGP, RTS_STATIC, …).
    "RTS_",
];

/// BIRD attribute renames → lr DSL spellings.
const RENAMES: &[(&str, &str)] = &[
    ("bgp_path", "bgp.as_path"),
    ("bgp_local_pref", "bgp.local_pref"),
    ("bgp_med", "bgp.med"),
    ("bgp_next_hop", "bgp.next_hop"),
    ("bgp_origin", "bgp.origin"),
    ("bgp_community", "bgp.communities"),
    ("bgp_ext_community", "bgp.ext_communities"),
    ("bgp_large_community", "bgp.large_communities"),
    // RFC 6811 outcome literals → lr's roa.state strings.
    ("ROA_VALID", "\"valid\""),
    ("ROA_UNKNOWN", "\"not-found\""),
    ("ROA_INVALID", "\"invalid\""),
    // BIRD ORIGIN_* enums are lr integers (0 = IGP, 1 = EGP, 2 = INCOMPLETE).
    ("ORIGIN_IGP", "0"),
    ("ORIGIN_EGP", "1"),
    ("ORIGIN_INCOMPLETE", "2"),
];

/// BIRD words that legitimately continue an attribute/method chain.
const CHAIN_METHODS: &[&str] = &["prepend", "delete", "filter", "add"];

// ---------------------------------------------------------------------------
// Token machinery
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq)]
enum Tok {
    /// `[A-Za-z_][A-Za-z0-9_]*`
    Word(String),
    /// A `"…"` string literal (verbatim, quotes included).
    Str(String),
    /// One punctuation token; multi-char operators (`&&`, `||`, `!=`,
    /// `!~`, `==`, `<=`, `>=`, `:=`) stay together, everything else
    /// splits per character.
    Sym(String),
}

#[derive(Debug)]
struct Token {
    tok: Tok,
    start: usize,
    end: usize,
}

fn tokenize(text: &str) -> Vec<Token> {
    let bytes = text.as_bytes();
    let mut toks = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        let c = bytes[i];
        match c {
            b'"' => {
                let start = i;
                i += 1;
                while i < bytes.len() {
                    if bytes[i] == b'\\' && i + 1 < bytes.len() {
                        i += 2;
                        continue;
                    }
                    if bytes[i] == b'"' {
                        i += 1;
                        break;
                    }
                    i += 1;
                }
                toks.push(Token {
                    tok: Tok::Str(text[start..i.min(text.len())].to_string()),
                    start,
                    end: i.min(text.len()),
                });
            }
            c if c.is_ascii_alphabetic() || c == b'_' => {
                let start = i;
                while i < bytes.len() && (bytes[i].is_ascii_alphanumeric() || bytes[i] == b'_') {
                    i += 1;
                }
                toks.push(Token {
                    tok: Tok::Word(text[start..i].to_string()),
                    start,
                    end: i,
                });
            }
            c if c.is_ascii_whitespace() => i += 1,
            _ => {
                let start = i;
                let two = &text[i..(i + 2).min(text.len())];
                let len = match two {
                    "&&" | "||" | "!=" | "!~" | "==" | "<=" | ">=" | "->" | "++" | ":=" | ".." => 2,
                    _ => 1,
                };
                i += len;
                toks.push(Token {
                    tok: Tok::Sym(text[start..i].to_string()),
                    start,
                    end: i,
                });
            }
        }
    }
    toks
}

/// Rebuild text from tokens: verbatim gaps preserved, rewritten
/// tokens substituted, dropped tokens (empty replacement) elided.
fn emit(text: &str, toks: &[Token], rewritten: &[Option<String>]) -> String {
    let mut out = String::new();
    let mut pos = 0usize;
    for (idx, t) in toks.iter().enumerate() {
        let gap = &text[pos..t.start];
        let repl = rewritten.get(idx).and_then(|r| r.as_deref());
        // A dropped token takes its leading gap with it, so elided
        // type words leave no stray runs (a replacement token that
        // needs its own spacing carries it inside the replacement).
        let keep_gap = !(repl == Some(""));
        if keep_gap {
            out.push_str(gap);
        }
        match repl {
            Some("") => {}
            Some(repl) => out.push_str(repl),
            None => out.push_str(&text[t.start..t.end]),
        }
        pos = t.end;
    }
    out.push_str(&text[pos..]);
    out
}

/// Words a token scan should consult a function table for: `name(`
/// call shapes.
fn called_functions(body: &str, known: &[(String, String)]) -> Vec<String> {
    let toks = tokenize(body);
    let mut out = Vec::new();
    for (i, t) in toks.iter().enumerate() {
        if let Tok::Word(w) = &t.tok {
            let next_is_paren = matches!(
                toks.get(i + 1).map(|n| &n.tok),
                Some(Tok::Sym(s)) if s == "("
            );
            if next_is_paren && known.iter().any(|(n, _)| n == w) && !out.contains(w) {
                out.push(w.clone());
            }
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Body translation
// ---------------------------------------------------------------------------

/// Translate one BIRD filter/function body. Errors carry the
/// unfaithful-construct notes.
fn translate_body(body: &str, ctx: &Ctx) -> Result<String, Vec<String>> {
    let (out, notes) = translate_body_inner(body, ctx);
    if notes.is_empty() {
        Ok(out)
    } else {
        Err(notes)
    }
}

/// Translate a `function name(types…) { … }` capture: strip the
/// parameter types, translate the body, rebuild the lr declaration.
fn translate_function(text: &str, ctx: &Ctx) -> Result<String, Vec<String>> {
    // Split header from body at the first `{`.
    let Some(brace) = text.find('{') else {
        return Err(vec!["function has no body".to_string()]);
    };
    let header = &text[..brace];
    let rest = &text[brace..];
    // Body ends at the LAST `}` — BIRD function captures carry the
    // full brace-matched block, so the final `}` closes the function.
    let trimmed = rest.trim_end();
    let Some(close_rel) = trimmed.rfind('}') else {
        return Err(vec!["function body is not brace-terminated".to_string()]);
    };
    let body = &trimmed[..close_rel];
    let tail = &trimmed[close_rel..];

    let toks = tokenize(header);
    // Rewrite `function f(int a, ip prefix b)` → `function f(a, b)`:
    // type words before a parameter name are dropped.
    let mut rewritten: Vec<Option<String>> = vec![None; toks.len()];
    let mut i = 0;
    while i < toks.len() {
        if matches!(&toks[i].tok, Tok::Word(w) if w == "function") {
            i += 1;
            continue;
        }
        // Parameter type run: 1–2 type words followed by a param name.
        if matches!(&toks[i].tok, Tok::Word(_)) {
            let mut j = i;
            let mut words = 0;
            while j < toks.len() {
                match &toks[j].tok {
                    Tok::Word(w2) if TYPE_WORDS.contains(&w2.as_str()) && words < 2 => {
                        j += 1;
                        words += 1;
                    }
                    _ => break,
                }
            }
            if words > 0 {
                if let Some(Tok::Word(name)) = toks.get(j).map(|t| &t.tok) {
                    // `j` is the parameter name — it moves into the
                    // first type word's slot (keeping the type run's
                    // leading gap), everything else in the run drops.
                    rewritten[i] = Some(name.clone());
                    for slot in rewritten.iter_mut().take(j + 1).skip(i + 1) {
                        *slot = Some(String::new());
                    }
                    i = j + 1;
                    continue;
                }
            }
        }
        i += 1;
    }
    let header_lr = emit(header, &toks, &rewritten);
    let (body_lr, notes) = translate_body_inner(body, ctx);
    if !notes.is_empty() {
        return Err(notes);
    }
    Ok(format!("{} {body_lr}{tail}", header_lr.trim_end()))
}

// ---------------------------------------------------------------------------
// Case-statement structural rewrite
// ---------------------------------------------------------------------------

/// The current replacement text for token `idx` (or its original
/// source slice when no replacement is set). Used by the case-rewrite
/// pass to prepend/append bracket characters to a token's replacement.
fn token_text(body: &str, toks: &[Token], rewritten: &[Option<String>], idx: usize) -> String {
    match &rewritten[idx] {
        Some(s) => s.clone(),
        None => body[toks[idx].start..toks[idx].end].to_string(),
    }
}

/// Ensure `replacement` begins with a space when the source gap
/// before token `idx` is empty. BIRD writes `pat:body` (no space
/// before `:`); lr's `=>` needs a separator so it does not glue to
/// the preceding pattern. When the gap already contains whitespace
/// the `emit` pass preserves it, so we return `replacement` as-is.
fn with_leading_space(body: &str, toks: &[Token], idx: usize, replacement: &str) -> String {
    let prev_char = toks[idx]
        .start
        .checked_sub(1)
        .and_then(|p| body.as_bytes().get(p).copied());
    match prev_char {
        Some(c) if c.is_ascii_whitespace() => replacement.to_string(),
        _ => format!(" {replacement}"),
    }
}

/// Pre-pass: rewrite every BIRD `case … { … }` block in the token
/// stream into lr DSL syntax. BIRD (verified against `filter/config.Y`
/// §`switch_body`) spells an arm as `switch_items ':' cmds_scoped`
/// and the default arm as `ELSECOL cmds_scoped` (where `ELSECOL` is
/// the lexer's `else:` token); lr DSL spells them `pat => stmt` and
/// `default => stmt` (commit `f1fc747`'s D14.1 audit trail). The
/// shape diverges in three places the regular token-rewriting pass
/// cannot handle:
///
/// 1. The arm separator `:` (at the top of the case body, depth 1)
///    becomes `=>`. A `:` inside `()` / `[]` / `{}` is a pair or
///    set literal and is left alone — depth tracking distinguishes
///    the two.
/// 2. `else :` (two tokens in lr's tokenizer; BIRD's lexer collapses
///    them to `ELSECOL`) becomes `default =>`.
/// 3. lr DSL case arm bodies are a single statement (which may be a
///    `Block`); BIRD arm bodies are a `cmds_scoped` list. A bare
///    `pat: cmd1; cmd2;` in BIRD (multi-statement, no braces) would
///    parse wrongly in lr (the second `cmd2;` would be read as the
///    start of a new arm). The rewrite wraps every non-block arm
///    body in `{ … }` so the body always parses as one `Block`.
///
/// Range arms (`a .. b:`) have no lr equivalent — lr case arms match
/// exact values only — and are reported as unfaithful. Nested cases
/// are handled recursively.
fn rewrite_cases(
    body: &str,
    toks: &[Token],
    rewritten: &mut [Option<String>],
    notes: &mut Vec<String>,
) {
    let mut i = 0;
    while i < toks.len() {
        if let Tok::Word(w) = &toks[i].tok {
            if w == "case" {
                i = rewrite_one_case(body, toks, rewritten, notes, i);
                continue;
            }
        }
        i += 1;
    }
}

/// Rewrite one `case` block starting at `start` (pointing at the
/// `case` keyword). Returns the index after the closing `}` of the
/// case body.
fn rewrite_one_case(
    body: &str,
    toks: &[Token],
    rewritten: &mut [Option<String>],
    notes: &mut Vec<String>,
    start: usize,
) -> usize {
    // Find the opening `{` of the case body, skipping the scrutinee
    // expression. Track `()` / `[]` so a `{` inside a parenthesised
    // scrutinee is not mistaken for the case body open.
    let mut j = start + 1;
    let mut paren_depth: i32 = 0;
    while j < toks.len() {
        match &toks[j].tok {
            Tok::Sym(s) if s == "{" && paren_depth == 0 => break,
            Tok::Sym(s) if s == "(" || s == "[" => paren_depth += 1,
            Tok::Sym(s) if s == ")" || s == "]" => paren_depth -= 1,
            _ => {}
        }
        j += 1;
    }
    if j >= toks.len() {
        return start + 1; // Malformed — let the regular pass report.
    }
    // `j` is the `{` opening the case body. Step inside.
    let mut depth: i32 = 1;
    j += 1;

    #[derive(PartialEq)]
    enum State {
        Pattern,
        Body,
    }
    let mut state = State::Pattern;
    // True when the current arm body is a `{ cmds }` block (BIRD
    // already braces it) — we do not inject an extra `{`.
    let mut arm_body_is_block = false;
    // True when we injected a `{` to wrap a non-block arm body.
    let mut arm_body_open = false;

    while j < toks.len() {
        let tok = &toks[j].tok;
        match (tok, &state) {
            // --- Pattern state: scanning arm patterns ---------------
            (Tok::Word(w), State::Pattern) if w == "else" && depth == 1 => {
                // `else :` → `default =>`. The `:` is the next token.
                if let Some(arm) = start_arm_body(body, toks, rewritten, j, false) {
                    arm_body_open = arm.open;
                    arm_body_is_block = arm.is_block;
                    state = State::Body;
                    j = arm.next;
                    continue;
                }
                // Malformed `else` without `:` — leave as-is.
            }
            (Tok::Word(w), State::Pattern) if w == "case" => {
                // Nested case inside the scrutinee or pattern (rare).
                j = rewrite_one_case(body, toks, rewritten, notes, j);
                continue;
            }
            (Tok::Sym(s), State::Pattern) if s == ":" && depth == 1 => {
                // Arm separator `:` → `=>`. Wrap the arm body if it
                // is not already a `{ cmds }` block. Use
                // `with_leading_space` so `100:` (no space before
                // `:`) becomes `100 =>` not `100=>`.
                rewritten[j] = Some(with_leading_space(body, toks, j, "=>"));
                if let Some(arm) = start_arm_body(body, toks, rewritten, j + 1, false) {
                    arm_body_open = arm.open;
                    arm_body_is_block = arm.is_block;
                    state = State::Body;
                    j = arm.next;
                    continue;
                }
                state = State::Body;
            }
            (Tok::Sym(s), State::Pattern) if s == ".." && depth == 1 => {
                notes.push(
                    "case arm range (`a .. b`) has no lr equivalent — \
                     lr case arms match exact values only"
                        .to_string(),
                );
            }
            (Tok::Sym(s), State::Pattern) if s == "{" => depth += 1,
            (Tok::Sym(s), State::Pattern) if s == "}" => {
                depth -= 1;
                if depth == 0 {
                    return j + 1;
                }
            }
            (Tok::Sym(s), State::Pattern) if s == "(" || s == "[" => depth += 1,
            (Tok::Sym(s), State::Pattern) if s == ")" || s == "]" => depth -= 1,

            // --- Body state: scanning an arm body --------------------
            (Tok::Word(w), State::Body) if w == "case" => {
                // Nested case as a cmd in the arm body.
                j = rewrite_one_case(body, toks, rewritten, notes, j);
                continue;
            }
            (Tok::Word(w), State::Body) if w == "else" && depth == 1 => {
                // The arm body ends without a `;` (e.g. it was a
                // nested case). Close the injected `{` first, then
                // process `else :` as `default =>`.
                if let Some(arm) = start_arm_body(body, toks, rewritten, j, arm_body_open) {
                    arm_body_open = arm.open;
                    arm_body_is_block = arm.is_block;
                    state = State::Body;
                    j = arm.next;
                    continue;
                }
            }
            (Tok::Sym(s), State::Body) if s == ";" && depth == 1 => {
                if arm_body_open {
                    let t = token_text(body, toks, rewritten, j);
                    rewritten[j] = Some(format!("{t} }}"));
                    arm_body_open = false;
                }
                state = State::Pattern;
            }
            (Tok::Sym(s), State::Body) if s == "{" => depth += 1,
            (Tok::Sym(s), State::Body) if s == "}" => {
                depth -= 1;
                if depth == 0 {
                    // End of case body. Close any open arm body.
                    if arm_body_open {
                        let t = token_text(body, toks, rewritten, j);
                        rewritten[j] = Some(format!("}} {t}"));
                    }
                    return j + 1;
                }
                if depth == 1 && arm_body_is_block {
                    // This `}` closes the `{ cmds }` block that was
                    // the arm body. Back to Pattern state.
                    arm_body_is_block = false;
                    state = State::Pattern;
                }
            }
            (Tok::Sym(s), State::Body) if s == "(" || s == "[" => depth += 1,
            (Tok::Sym(s), State::Body) if s == ")" || s == "]" => depth -= 1,
            _ => {}
        }
        j += 1;
    }
    j
}

/// Result of [`start_arm_body`]: how the arm body was opened and
/// where to resume scanning.
struct ArmBody {
    /// `true` when we injected a `{` to wrap a non-block arm body.
    open: bool,
    /// `true` when the arm body is a `{ cmds }` block (BIRD already
    /// braces it) and we did not inject an extra `{`.
    is_block: bool,
    /// Token index to resume at (just past the `=>` / injected `{`).
    next: usize,
}

/// Common logic for opening an arm body after rewriting the separator
/// to `=>`. Handles two shapes:
///
/// * `pat : { cmds }` — the arm body is already a block. We leave it
///   alone (`is_block = true`, `open = false`).
/// * `pat : cmd;` — the arm body is a bare command. We inject a `{`
///   before the command token (`open = true`); the matching `}` is
///   appended by the Body-state scan when it hits `;` or `}`.
///
/// `at` points at the token that will become `default` (for the
/// `else` shape) or the token after `:` (for the `:` shape). When
/// `close_prev_arm` is true, a `} ` prefix is prepended to close a
/// still-open injected `{` from the previous arm (the arm body ended
/// without a `;`, e.g. a nested case).
fn start_arm_body(
    body: &str,
    toks: &[Token],
    rewritten: &mut [Option<String>],
    at: usize,
    close_prev_arm: bool,
) -> Option<ArmBody> {
    let prefix = if close_prev_arm { "} " } else { "" };

    // Peek the next significant token to decide the body shape.
    // `at` is either the `else` keyword (followed by `:`) or the
    // token after `:`. Detect which by looking at `toks[at]`.
    let (name_idx, colon_idx, body_idx) = match &toks.get(at)?.tok {
        Tok::Word(w) if w == "else" => {
            // `else : <body>` — the `:` is at `at + 1`.
            let colon = at + 1;
            if !matches!(&toks.get(colon)?.tok, Tok::Sym(s) if s == ":") {
                return None;
            }
            (at, colon, colon + 1)
        }
        _ => {
            // Already past the `:`; `at` is the first body token.
            (at, at, at)
        }
    };

    // Rewrite `else` → `default` (with prefix) and `:` → `=>`.
    if name_idx != colon_idx {
        let name_repl = format!("{prefix}default");
        rewritten[name_idx] = Some(with_leading_space(body, toks, name_idx, &name_repl));
        rewritten[colon_idx] = Some(with_leading_space(body, toks, colon_idx, "=>"));
    }

    let after = toks.get(body_idx)?;
    let is_block = matches!(&after.tok, Tok::Sym(s) if s == "{");
    if is_block {
        Some(ArmBody {
            open: false,
            is_block: true,
            next: body_idx,
        })
    } else {
        let t = token_text(body, toks, rewritten, body_idx);
        rewritten[body_idx] = Some(format!("{{ {t}"));
        Some(ArmBody {
            open: true,
            is_block: false,
            next: body_idx,
        })
    }
}

/// Core token-stream rewrite. Errors carry the unfaithful-construct
/// notes; the result is only meaningful when they are empty.
fn translate_body_inner(body: &str, ctx: &Ctx) -> (String, Vec<String>) {
    let toks = tokenize(body);
    let mut rewritten: Vec<Option<String>> = vec![None; toks.len()];
    let mut notes: Vec<String> = Vec::new();

    // Structural pre-pass: rewrite BIRD `case … { … }` blocks into
    // lr DSL syntax (`:` → `=>`, `else:` → `default =>`, multi-stmt
    // arm bodies wrapped in `{ … }`). See `rewrite_cases`.
    rewrite_cases(body, &toks, &mut rewritten, &mut notes);

    let mut prev_significant: Option<&Tok> = None;
    let mut i = 0;
    while i < toks.len() {
        let tok = &toks[i].tok;
        match tok {
            Tok::Str(_) => {}
            Tok::Sym(s) => {
                // `!~` now passes through verbatim: lr's filter DSL
                // gained `!~` (BinaryOp::NotMatch) as a peer of `~`
                // in commit 1b09aa7, sharing Match precedence (4)
                // with BIRD's `filter/config.Y` rule layering. No
                // re-parenthesisation needed — BIRD spells both
                // forms identically.
                // Operator spelling: BIRD writes equality `=` and
                // assignment `:=`; lr writes equality `==` and
                // assignment `=`. Every BIRD `=` inside a body is an
                // equality — BIRD's assignments ride `:=`.
                if s == "=" {
                    rewritten[i] = Some("==".to_string());
                } else if s == ":=" {
                    rewritten[i] = Some("=".to_string());
                }
                prev_significant = Some(tok);
                i += 1;
                continue;
            }
            Tok::Word(w) => {
                // 1. Constant substitution (BIRD `define`).
                if let Some((_, value)) = ctx.defines.iter().find(|(n, _)| n == w) {
                    rewritten[i] = Some(value.clone());
                    prev_significant = Some(tok);
                    i += 1;
                    continue;
                }
                // 2. BIRD attributes / constructs lr cannot express.
                if UNMAPPABLE_WORDS.contains(&w.as_str())
                    || UNMAPPABLE_PREFIXES.iter().any(|p| w.starts_with(p))
                {
                    notes.push(format!(
                        "BIRD route attribute or statement `{w}` has no faithful lr mapping"
                    ));
                    prev_significant = Some(tok);
                    i += 1;
                    continue;
                }
                // 3. `roa_check(table)` — maps to `roa.state` only for
                //    the single-table zero-argument form.
                if w == "roa_check" {
                    match parse_roa_check(&toks, i) {
                        Some((end, table_arg)) if table_arg.is_none() && ctx.roa_tables == 1 => {
                            rewritten[i] = Some("roa.state".to_string());
                            for slot in rewritten.iter_mut().take(end + 1).skip(i + 1) {
                                *slot = Some(String::new());
                            }
                            i = end + 1;
                            continue;
                        }
                        Some(_) => notes.push(format!(
                            "`roa_check` with explicit arguments or multiple ROA tables \
                             ({} tables in the config) has no single-store lr equivalent",
                            ctx.roa_tables
                        )),
                        None => notes.push("malformed `roa_check` call".to_string()),
                    }
                    prev_significant = Some(tok);
                    i += 1;
                    continue;
                }
                // 4. Typed variable declarations → `let name = …;`.
                if let Some((name_idx, eq_idx, is_init)) = parse_decl(&toks, i) {
                    // `int x := 5;` → `let x = 5;`; `int x;` → a typed
                    // zero value (lr has no undefined).
                    let name = match &toks[name_idx].tok {
                        Tok::Word(n) => n.clone(),
                        _ => unreachable!("parse_decl guarantees a name"),
                    };
                    rewritten[i] = Some("let".to_string());
                    // Two-word types (`ip prefix p`): drop the tail.
                    for slot in rewritten.iter_mut().take(name_idx).skip(i + 1) {
                        *slot = Some(String::new());
                    }
                    if !is_init {
                        let zero = match &toks[i].tok {
                            Tok::Word(t) if t == "int" || t == "enum" => "0".to_string(),
                            Tok::Word(t) if t == "bool" => "false".to_string(),
                            Tok::Word(t) if t == "string" => "\"\"".to_string(),
                            other => {
                                let ty = match other {
                                    Tok::Word(t) => t.clone(),
                                    _ => String::new(),
                                };
                                notes.push(format!(
                                    "BIRD variable `{name}` of type `{ty}` has no lr default — \
                                     initialize it explicitly in the source filter"
                                ));
                                String::new()
                            }
                        };
                        if !zero.is_empty() {
                            rewritten[name_idx] = Some(format!("{name} = {zero}"));
                        }
                    }
                    // Resume at the `:=` / `;` token (verbatim from here).
                    i = eq_idx;
                    prev_significant = Some(&toks[name_idx].tok);
                    continue;
                }
                // 5. Attribute chains: `bgp_path.first`, `net.len`,
                //    `set.empty` etc. have no lr equivalent; the method
                //    calls that DO map pass through. Name the receiver
                //    in the note (the word two tokens back).
                if prev_significant.and_then(|t| t.as_sym()) == Some(".")
                    && !CHAIN_METHODS.contains(&w.as_str())
                {
                    let receiver = match i.checked_sub(2).and_then(|k| toks.get(k)) {
                        Some(Token {
                            tok: Tok::Word(r), ..
                        }) => format!("{r}."),
                        _ => String::new(),
                    };
                    notes.push(format!(
                        "attribute accessor `{receiver}{w}` has no lr equivalent"
                    ));
                }
                // 6. Plain renames.
                if let Some((_, lr)) = RENAMES.iter().find(|(b, _)| b == w) {
                    rewritten[i] = Some((*lr).to_string());
                }
            }
        }
        prev_significant = Some(tok);
        i += 1;
    }
    (emit(body, &toks, &rewritten), notes)
}

/// Recognise a variable declaration starting at `idx` (a type word).
/// Returns `(name_index, separator_index, is_initialised)` — the
/// caller rewrites the type word to `let` and, for bare declarations,
/// splices a zero value into the name token.
fn parse_decl(toks: &[Token], idx: usize) -> Option<(usize, usize, bool)> {
    let type_word = match &toks.get(idx)?.tok {
        Tok::Word(w) if TYPE_WORDS.contains(&w.as_str()) => w.clone(),
        _ => return None,
    };
    let mut j = idx + 1;
    // Two-word types (`ip prefix`, `ip pair`, …).
    if type_word == "ip" {
        if let Some(Tok::Word(w2)) = toks.get(j).map(|t| &t.tok) {
            if ["prefix", "pair", "quad", "ec", "lc"].contains(&w2.as_str()) {
                j += 1;
            }
        }
    }
    // The variable name must be an identifier.
    if !matches!(toks.get(j).map(|t| &t.tok), Some(Tok::Word(_))) {
        return None;
    }
    match toks.get(j + 1).map(|t| &t.tok) {
        // `TYPE name := …` — BIRD's initialised declaration.
        Some(Tok::Sym(s)) if s == ":=" => Some((j, j + 1, true)),
        // `TYPE name;` — bare declaration.
        Some(Tok::Sym(s)) if s == ";" => Some((j, j + 1, false)),
        _ => None,
    }
}

/// Recognise `roa_check ( table )` at `idx`. Returns the index of the
/// closing `)` plus the table argument when extra arguments were
/// present (`roa_check(t, net, asn)` — the explicit-argument form).
fn parse_roa_check(toks: &[Token], idx: usize) -> Option<(usize, Option<String>)> {
    if !matches!(toks.get(idx + 1).map(|t| &t.tok), Some(Tok::Sym(s)) if s == "(") {
        return None;
    }
    let table = match toks.get(idx + 2).map(|t| &t.tok) {
        Some(Tok::Word(w)) => w.clone(),
        _ => return None,
    };
    match toks.get(idx + 3).map(|t| &t.tok) {
        Some(Tok::Sym(s)) if s == ")" => Some((idx + 3, None)),
        Some(Tok::Sym(s)) if s == "," => {
            // Explicit (prefix, asn) arguments: find the closing paren.
            let mut k = idx + 4;
            while k < toks.len() {
                if matches!(&toks[k].tok, Tok::Sym(s) if s == ")") {
                    return Some((k, Some(table)));
                }
                k += 1;
            }
            None
        }
        _ => None,
    }
}

impl Tok {
    fn as_sym(&self) -> Option<&str> {
        match self {
            Tok::Sym(s) => Some(s.as_str()),
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------
// Variable-verification backstop
// ---------------------------------------------------------------------------

/// Collect every variable reference the parsed filter makes that no
/// `let` or function parameter introduced. lr's compiler does not
/// check variable names (they resolve at eval time), so a leftover
/// BIRD constant or attribute word would only surface as a per-route
/// evaluation error — fail the translation instead.
fn verify_vars(filter: &Filter) -> Vec<String> {
    let mut unknown: Vec<String> = Vec::new();
    let mut scope: Vec<String> = Vec::new();
    for f in &filter.functions {
        // Each function is a fresh scope frame (D3.1): its parameters
        // and lets never leak into the next function or the body.
        let base = scope.len();
        scope.extend(f.params.iter().cloned());
        for stmt in &f.body.stmts {
            walk_stmt(stmt, &mut scope, &mut unknown);
        }
        scope.truncate(base);
    }
    for stmt in &filter.body.stmts {
        walk_stmt(stmt, &mut scope, &mut unknown);
    }
    unknown.sort();
    unknown.dedup();
    unknown
}

fn walk_expr(e: &Expr, scope: &mut Vec<String>, unknown: &mut Vec<String>) {
    match e {
        Expr::Lit(..) => {}
        Expr::Var(name, _) => {
            if !scope.iter().any(|s| s == name) {
                unknown.push(format!(
                    "variable or constant `{name}` is never introduced — a BIRD \
                     `define`/local that did not translate"
                ));
            }
        }
        Expr::RouteField(..) => {}
        Expr::Call { args, .. } => {
            for a in args {
                walk_expr(a, scope, unknown);
            }
        }
        Expr::Defined(inner, _) => walk_expr(inner, scope, unknown),
        Expr::Method { receiver, args, .. } => {
            walk_expr(receiver, scope, unknown);
            for a in args {
                walk_expr(a, scope, unknown);
            }
        }
        Expr::Binary { lhs, rhs, .. } => {
            walk_expr(lhs, scope, unknown);
            walk_expr(rhs, scope, unknown);
        }
        Expr::Unary { expr, .. } => walk_expr(expr, scope, unknown),
        Expr::Set(items, _) => {
            for it in items {
                walk_expr(it, scope, unknown);
            }
        }
        _ => {}
    }
}

fn walk_stmt(stmt: &Stmt, scope: &mut Vec<String>, unknown: &mut Vec<String>) {
    match stmt {
        Stmt::If {
            cond, then, els, ..
        } => {
            walk_expr(cond, scope, unknown);
            walk_stmt(then, scope, unknown);
            if let Some(e) = els {
                walk_stmt(e, scope, unknown);
            }
        }
        Stmt::Case {
            scrutinee, arms, ..
        } => {
            walk_expr(scrutinee, scope, unknown);
            for arm in arms {
                for pat in &arm.patterns {
                    walk_expr(pat, scope, unknown);
                }
                for s in &arm.body {
                    walk_stmt(s, scope, unknown);
                }
            }
        }
        Stmt::Let { name, value, .. } => {
            walk_expr(value, scope, unknown);
            scope.push(name.clone());
        }
        Stmt::Assign { name, value, .. } => {
            walk_expr(value, scope, unknown);
            if !scope.iter().any(|s| s == name) {
                unknown.push(format!(
                    "assignment to `{name}` which nothing introduced — a BIRD \
                     `define`/local that did not translate"
                ));
            }
        }
        Stmt::AssignRouteField { value, .. } | Stmt::AppendRouteField { value, .. } => {
            walk_expr(value, scope, unknown);
        }
        Stmt::Expr(e, _) => walk_expr(e, scope, unknown),
        Stmt::Block(stmts, _) => {
            let base = scope.len();
            for s in stmts {
                walk_stmt(s, scope, unknown);
            }
            scope.truncate(base);
        }
        Stmt::Return(Some(e), _) => walk_expr(e, scope, unknown),
        Stmt::Return(None, _) | Stmt::Accept(_) | Stmt::Reject(None, _) => {}
        Stmt::Reject(Some(e), _) => walk_expr(e, scope, unknown),
    }
}

#[cfg(test)]
#[path = "translate_bird_filter_tests.rs"]
mod tests;
