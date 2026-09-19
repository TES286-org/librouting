//! Lexer for the native `.lr` configuration DSL (ROADMAP-v3 D16
//! Phase 2, GitHub #18).
//!
//! The grammar this feeds is specified in `docs/config_dsl_grammar.md`.
//! Lexical rules in one place:
//!
//! - whitespace and `#` line comments are insignificant;
//! - strings are double-quoted, escapes `\"` `\\` `\n` `\t` `\r`
//!   (unknown escapes are preserved verbatim — the same relaxation
//!   `daemon_config::unescape_toml_string` applies, so the escape
//!   channel round-trips);
//! - bare words lex as [`TokKind::Ident`]; the character set covers
//!   names (`customer-space`), addresses (`10.0.0.1`), prefixes
//!   (`203.0.113.0/24`) and socket addresses (`192.0.2.2:179`);
//! - numbers may carry a unit suffix (`90s`, `5m`, `2h`, `100ms`,
//!   `50us`, `100k`, `2M`); the suffix is *not* expanded here — the
//!   lowering layer validates it against the per-key whitelist;
//! - structural punctuation: `{ } [ ] , ;`.
//!
//! Anything else lexes as [`TokKind::Other`] instead of failing: the
//! token stream must stay complete because `filter` blocks capture
//! their bodies verbatim from the raw source between braces, and the
//! matching-brace scan rides this same token stream (`=`, `~` and
//! friends only occur inside filter bodies).

#[derive(Debug, Clone, PartialEq)]
pub(super) enum Unit {
    Ms,
    /// seconds
    S,
    /// minutes
    M,
    /// hours
    H,
    /// microseconds
    Us,
    /// kilo (×1000)
    K,
    /// mega (×1_000_000)
    BigM,
}

impl Unit {
    /// Parse a unit suffix token. Case-sensitive: `M` is mega while
    /// `m` is minutes, per the grammar spec.
    pub(super) fn from_suffix(suffix: &str) -> Option<Unit> {
        match suffix {
            "ms" => Some(Unit::Ms),
            "s" => Some(Unit::S),
            "m" => Some(Unit::M),
            "h" => Some(Unit::H),
            "us" => Some(Unit::Us),
            "k" => Some(Unit::K),
            "M" => Some(Unit::BigM),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub(super) enum TokKind {
    /// Bare word: names, addresses, prefixes, socket addresses.
    Ident(String),
    /// Double-quoted string, escapes processed.
    Str(String),
    /// Integer or float literal, raw text preserved (`0.5` stays
    /// `"0.5"`; the parser hands raw text to the shared dispatch
    /// which owns numeric parsing).
    Number(String),
    /// Number with a unit suffix (`90s`) — expansion is the
    /// lowering layer's job.
    Suffixed {
        digits: String,
        unit: Unit,
    },
    Bool(bool),
    LBrace,
    RBrace,
    LBracket,
    RBracket,
    Comma,
    Semi,
    /// Any other character. Valid only inside `filter` bodies, whose
    /// raw text the parser slices between braces; anywhere else it is
    /// a parse error ("unexpected character").
    Other(char),
}

#[derive(Debug, Clone)]
pub(super) struct Tok {
    pub kind: TokKind,
    /// 1-based source line.
    pub line: usize,
    /// Byte offset of the token's first character in the frame's
    /// source — filter-body slices key off this.
    pub offset: usize,
}

/// Lex one configuration file's text into tokens.
pub(super) fn lex(text: &str) -> Result<Vec<Tok>, String> {
    let bytes = text;
    let mut toks = Vec::new();
    let mut line = 1usize;
    let mut i = 0usize;
    let n = bytes.len();
    while i < n {
        let c = bytes[i..].chars().next().unwrap();
        match c {
            '\n' => {
                line += 1;
                i += 1;
            }
            ' ' | '\t' | '\r' => {
                i += 1;
            }
            '#' => {
                // Line comment — skip to end of line (the newline
                // itself is consumed by the loop above). Comments may
                // carry non-ASCII text (em-dashes, CJK notes), so the
                // scan must move in whole characters: `find` returns
                // the byte offset of the newline, which always lands
                // on a char boundary — stepping `i += 1` here would
                // panic the `bytes[i..]` slice on a multi-byte char.
                match bytes[i..].find('\n') {
                    Some(rel) => i += rel,
                    None => i = n,
                }
            }
            '{' => {
                toks.push(Tok {
                    kind: TokKind::LBrace,
                    line,
                    offset: i,
                });
                i += 1;
            }
            '}' => {
                toks.push(Tok {
                    kind: TokKind::RBrace,
                    line,
                    offset: i,
                });
                i += 1;
            }
            '[' => {
                toks.push(Tok {
                    kind: TokKind::LBracket,
                    line,
                    offset: i,
                });
                i += 1;
            }
            ']' => {
                toks.push(Tok {
                    kind: TokKind::RBracket,
                    line,
                    offset: i,
                });
                i += 1;
            }
            ',' => {
                toks.push(Tok {
                    kind: TokKind::Comma,
                    line,
                    offset: i,
                });
                i += 1;
            }
            ';' => {
                toks.push(Tok {
                    kind: TokKind::Semi,
                    line,
                    offset: i,
                });
                i += 1;
            }
            '"' => {
                let (s, next_i, next_line) = lex_string(bytes, i, line)?;
                toks.push(Tok {
                    kind: TokKind::Str(s),
                    line,
                    offset: i,
                });
                i = next_i;
                line = next_line;
            }
            _ => {
                let start = i;
                // Bare word / number: extend over the ident charset
                // (digits included — classification happens below).
                while i < n {
                    let ch = bytes[i..].chars().next().unwrap();
                    if ch.is_ascii_alphanumeric()
                        || ch == '_'
                        || ch == '-'
                        || ch == '.'
                        || ch == '/'
                        || ch == ':'
                    {
                        i += ch.len_utf8();
                    } else {
                        break;
                    }
                }
                if i == start {
                    // Not part of any token the grammar knows.
                    toks.push(Tok {
                        kind: TokKind::Other(c),
                        line,
                        offset: i,
                    });
                    i += c.len_utf8();
                    continue;
                }
                let word = &bytes[start..i];
                toks.push(Tok {
                    kind: classify_word(word),
                    line,
                    offset: start,
                });
            }
        }
    }
    Ok(toks)
}

/// Classify a bare word: bool, number, suffixed number or ident.
///
/// Number shapes: `123`, `-4`, `1.5`. Suffixed shapes append one of
/// the unit suffixes (`ms` `s` `m` `h` `us` `k` `M`). Words that
/// merely *contain* digits (`10.0.0.1`, `203.0.113.0/24`, `5g`) are
/// idents — only a leading numeric part followed by end-of-word or a
/// known unit classifies as a number.
fn classify_word(word: &str) -> TokKind {
    match word {
        "true" => return TokKind::Bool(true),
        "false" => return TokKind::Bool(false),
        _ => {}
    }
    let (digits, rest) = split_number_prefix(word);
    if digits.is_empty() {
        return TokKind::Ident(word.to_string());
    }
    if rest.is_empty() {
        return TokKind::Number(word.to_string());
    }
    if let Some(unit) = Unit::from_suffix(rest) {
        return TokKind::Suffixed {
            digits: digits.to_string(),
            unit,
        };
    }
    // `1.5` (float) or trailing junk (`1.2.3` → ident).
    TokKind::Ident(word.to_string())
}

/// Split `90s` into `("90", "s")`, `1.5` into `("1.5", "")`,
/// `10.0.0.1` into `("", ...)` (not a number: two dots).
fn split_number_prefix(word: &str) -> (&str, &str) {
    let mut chars = word.char_indices();
    let mut saw_digit = false;
    let mut saw_dot = false;
    let mut end = 0usize;
    loop {
        match chars.next() {
            Some((idx, c)) if c.is_ascii_digit() => {
                saw_digit = true;
                end = idx + 1;
            }
            Some((idx, '.')) if !saw_dot => {
                // A dot only belongs to the number if digits follow;
                // `1.` alone is not a number shape we accept.
                let rest = &word[idx + 1..];
                if rest.chars().next().is_some_and(|c| c.is_ascii_digit()) {
                    saw_dot = true;
                    end = idx + 1;
                } else {
                    break;
                }
            }
            _ => break,
        }
    }
    if !saw_digit {
        return ("", word);
    }
    // The numeric prefix must cover the whole word or end exactly at
    // a unit suffix — `1.2.3` has a second dot after the numeric run.
    let (num, rest) = word.split_at(end);
    if rest.starts_with('.') || (rest.contains('.') && !is_unit(rest)) {
        return ("", word);
    }
    (num, rest)
}

fn is_unit(rest: &str) -> bool {
    Unit::from_suffix(rest).is_some()
}

/// Lex a double-quoted string starting at `start` (which points at
/// the opening quote). Returns the unescaped content and the index /
/// line just past the closing quote.
fn lex_string(
    text: &str,
    start: usize,
    start_line: usize,
) -> Result<(String, usize, usize), String> {
    let mut out = String::new();
    let mut line = start_line;
    let mut i = start + 1; // skip the opening quote
    let n = text.len();
    while i < n {
        let c = text[i..].chars().next().unwrap();
        match c {
            '"' => {
                return Ok((out, i + 1, line));
            }
            '\\' => {
                let Some(next) = text[i + 1..].chars().next() else {
                    return Err(format!("line {line}: unterminated escape in string"));
                };
                match next {
                    '"' => out.push('"'),
                    '\\' => out.push('\\'),
                    'n' => out.push('\n'),
                    't' => out.push('\t'),
                    'r' => out.push('\r'),
                    // Unknown escapes are preserved verbatim, matching
                    // daemon_config::unescape_toml_string, so
                    // escape ∘ lex = identity for any content.
                    other => {
                        out.push('\\');
                        out.push(other);
                    }
                }
                i += 1 + next.len_utf8();
            }
            '\n' => {
                line += 1;
                out.push('\n');
                i += 1;
            }
            _ => {
                out.push(c);
                i += c.len_utf8();
            }
        }
    }
    Err(format!("line {start_line}: unterminated string"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn kinds(text: &str) -> Vec<TokKind> {
        lex(text).unwrap().into_iter().map(|t| t.kind).collect()
    }

    #[test]
    fn lexes_structure_and_words() {
        let toks = kinds("bgp {\n  hold_time 90;\n}");
        assert_eq!(
            toks,
            vec![
                TokKind::Ident("bgp".into()),
                TokKind::LBrace,
                TokKind::Ident("hold_time".into()),
                TokKind::Number("90".into()),
                TokKind::Semi,
                TokKind::RBrace,
            ]
        );
    }

    #[test]
    fn addresses_and_prefixes_are_idents() {
        for word in [
            "10.0.0.1",
            "203.0.113.0/24",
            "192.0.2.2:179",
            "0.0.0.1",
            "peer-template",
        ] {
            assert_eq!(classify_word(word), TokKind::Ident(word.into()), "{word}");
        }
    }

    #[test]
    fn units_are_case_sensitive() {
        assert_eq!(
            classify_word("90s"),
            TokKind::Suffixed {
                digits: "90".into(),
                unit: Unit::S
            }
        );
        assert_eq!(
            classify_word("5m"),
            TokKind::Suffixed {
                digits: "5".into(),
                unit: Unit::M
            }
        );
        assert_eq!(
            classify_word("2M"),
            TokKind::Suffixed {
                digits: "2".into(),
                unit: Unit::BigM
            }
        );
        assert_eq!(
            classify_word("100ms"),
            TokKind::Suffixed {
                digits: "100".into(),
                unit: Unit::Ms
            }
        );
        assert_eq!(
            classify_word("50us"),
            TokKind::Suffixed {
                digits: "50".into(),
                unit: Unit::Us
            }
        );
        assert_eq!(classify_word("5H"), TokKind::Ident("5H".into()));
        assert_eq!(classify_word("5g"), TokKind::Ident("5g".into()));
    }

    #[test]
    fn floats_keep_raw_text() {
        assert_eq!(classify_word("0.5"), TokKind::Number("0.5".into()));
        assert_eq!(classify_word("1.25"), TokKind::Number("1.25".into()));
        // Trailing dot without digits is not a number.
        assert_eq!(classify_word("1."), TokKind::Ident("1.".into()));
    }

    #[test]
    fn strings_unescape_known_and_preserve_unknown() {
        let toks = lex(r#" "a\"b\\c\nd\te\q" "#).unwrap();
        assert_eq!(toks.len(), 1);
        assert_eq!(toks[0].kind, TokKind::Str("a\"b\\c\nd\te\\q".into()));
    }

    #[test]
    fn comments_are_dropped() {
        let toks = kinds("# whole line\nbgp { # trailing\n} # tail");
        assert_eq!(
            toks,
            vec![
                TokKind::Ident("bgp".into()),
                TokKind::LBrace,
                TokKind::RBrace,
            ]
        );
    }

    /// Regression: the comment scanner used to step one *byte* per
    /// iteration, so a multi-byte character inside a comment (an
    /// em-dash, a CJK note) landed the cursor mid-char and the next
    /// `text[i..]` slice panicked. Comments are documentation — they
    /// must accept any UTF-8 text.
    #[test]
    fn comments_accept_non_ascii_text() {
        let toks = kinds("# em-dash — and café naïve ✓\nbgp { # — } [ ] ;\n}");
        assert_eq!(
            toks,
            vec![
                TokKind::Ident("bgp".into()),
                TokKind::LBrace,
                TokKind::RBrace,
            ]
        );
        // A trailing comment without a newline (EOF comment) too.
        assert_eq!(
            kinds("bgp; # — tail"),
            vec![TokKind::Ident("bgp".into()), TokKind::Semi]
        );
    }

    /// Offsets stay byte-true across non-ASCII comments: filter-body
    /// slicing rides these offsets, so a token after a multi-byte
    /// comment must still slice the raw source correctly.
    #[test]
    fn offsets_survive_non_ascii_comments() {
        let text = "# —\nbgp;";
        let toks = lex(text).unwrap();
        assert_eq!(toks.len(), 2);
        assert_eq!(&text[toks[0].offset..], "bgp;");
    }

    #[test]
    fn filter_operators_lex_as_other() {
        let toks = kinds("{ if proto == \"bgp\" then accept; }");
        assert!(toks.contains(&TokKind::Other('=')));
        assert!(toks.iter().any(|t| *t == TokKind::Str("bgp".into())));
    }

    #[test]
    fn spans_carry_lines_and_offsets() {
        let text = "bgp {\n  peer_as 1;\n}";
        let toks = lex(text).unwrap();
        let peer_as = &toks[2];
        assert_eq!(peer_as.line, 2);
        assert_eq!(peer_as.offset, 8);
        assert_eq!(&text[peer_as.offset..], "peer_as 1;\n}");
    }

    #[test]
    fn unterminated_string_is_an_error() {
        assert!(lex("name \"oops").is_err());
    }
}
