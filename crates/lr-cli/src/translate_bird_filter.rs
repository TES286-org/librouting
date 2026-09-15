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
/// would silently change meaning.
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
    "case",
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
                    "&&" | "||" | "!=" | "!~" | "==" | "<=" | ">=" | "->" | "++" | ":=" => 2,
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

/// Core token-stream rewrite. Errors carry the unfaithful-construct
/// notes; the result is only meaningful when they are empty.
fn translate_body_inner(body: &str, ctx: &Ctx) -> (String, Vec<String>) {
    let toks = tokenize(body);
    let mut rewritten: Vec<Option<String>> = vec![None; toks.len()];
    let mut notes: Vec<String> = Vec::new();

    let mut prev_significant: Option<&Tok> = None;
    let mut i = 0;
    while i < toks.len() {
        let tok = &toks[i].tok;
        match tok {
            Tok::Str(_) => {}
            Tok::Sym(s) => {
                // `!~` has no lr spelling (lr lacks a not-match token);
                // rewriting it needs expression-level re-parenthesising.
                if s == "!~" {
                    notes.push(
                        "`!~` (not-match) operator: no lr equivalent — \
                                rewrite as `!(a ~ b)` by hand"
                            .to_string(),
                    );
                }
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
        Expr::Lit(_) => {}
        Expr::Var(name) => {
            if !scope.iter().any(|s| s == name) {
                unknown.push(format!(
                    "variable or constant `{name}` is never introduced — a BIRD \
                     `define`/local that did not translate"
                ));
            }
        }
        Expr::RouteField(_) => {}
        Expr::Call { args, .. } => {
            for a in args {
                walk_expr(a, scope, unknown);
            }
        }
        Expr::Defined(inner) => walk_expr(inner, scope, unknown),
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
        Expr::Set(items) => {
            for it in items {
                walk_expr(it, scope, unknown);
            }
        }
        _ => {}
    }
}

fn walk_stmt(stmt: &Stmt, scope: &mut Vec<String>, unknown: &mut Vec<String>) {
    match stmt {
        Stmt::If { cond, then, els } => {
            walk_expr(cond, scope, unknown);
            walk_stmt(then, scope, unknown);
            if let Some(e) = els {
                walk_stmt(e, scope, unknown);
            }
        }
        Stmt::Case { scrutinee, arms } => {
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
        Stmt::Let { name, value } => {
            walk_expr(value, scope, unknown);
            scope.push(name.clone());
        }
        Stmt::Assign { name, value } => {
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
        Stmt::Expr(e) => walk_expr(e, scope, unknown),
        Stmt::Block(stmts) => {
            let base = scope.len();
            for s in stmts {
                walk_stmt(s, scope, unknown);
            }
            scope.truncate(base);
        }
        Stmt::Return(Some(e)) => walk_expr(e, scope, unknown),
        Stmt::Return(None) | Stmt::Accept | Stmt::Reject(None) => {}
        Stmt::Reject(Some(e)) => walk_expr(e, scope, unknown),
    }
}

#[cfg(test)]
mod tests {
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
    fn print_and_case_are_unfaithful() {
        let c = ctx(&[], 0);
        assert!(body_fails("print \"x\";", &c)
            .iter()
            .any(|n| n.contains("`print`")));
        assert!(body_fails("case net { else: accept; }", &c)
            .iter()
            .any(|n| n.contains("`case`")));
    }

    #[test]
    fn not_match_is_unfaithful() {
        let c = ctx(&[], 0);
        let notes = body_fails("if net !~ 10.0.0.0/8 then accept;", &c);
        assert!(notes.iter().any(|n| n.contains("`!~`")));
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
}
