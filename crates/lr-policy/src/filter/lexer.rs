//! Hand-rolled lexer for the filter DSL.
//!
//! No regex dependency. The lexer is `&[u8]`-based and produces a
//! flat `Vec<Token>` for the parser; the parser handles Pratt
//! precedence. Whitespace and `#` line comments are dropped at lex
//! time. String literals support `\\`, `\"`, `\n`, `\t` escapes
//! (BIRD's filter DSL strings use the same conventions as C).

use core::fmt;
use core::str::FromStr;

use lr_core::addr::{IpAddr, Prefix};

/// A lexed token: kind + byte offset in the source (1-indexed line
/// and column for diagnostics).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Token {
    pub kind: TokenKind,
    /// 1-indexed line in the source.
    pub line: u32,
    /// 1-indexed column in the source.
    pub col: u32,
}

/// Token kinds. `Int`, `Str`, `Ip`, `Prefix` carry the parsed
/// literal; punctuation and keywords are bare variants.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TokenKind {
    // --- Literals ---
    Int(i64),
    Str(String),
    Ip(IpAddr),
    Prefix(Prefix),
    Ident(String),

    // --- Punctuation ---
    LParen,     // (
    RParen,     // )
    LBrace,     // {
    RBrace,     // }
    LBracket,   // [
    RBracket,   // ]
    Comma,      // ,
    Semicolon,  // ;
    Colon,      // :
    Dot,        // .
    Plus,       // +
    Minus,      // -
    Star,       // *
    Slash,      // /
    Percent,    // %
    Bang,       // !
    Tilde,      // ~
    Amp,        // &
    Pipe,       // |
    Caret,      // ^
    Lt,         // <
    Gt,         // >
    Eq,         // =
    Underscore, // _ (BIRD AS-path wildcard)

    // Multi-char
    EqEq,      // ==
    NotEq,     // !=
    LtEq,      // <=
    GtEq,      // >=
    AndAnd,    // &&
    OrOr,      // ||
    Shl,       // <<
    Shr,       // >>
    PlusEq,    // +=
    Arrow,     // =>
    BangTilde, // !~ (BIRD/RFC-style non-match operator)

    // --- Keywords ---
    If,
    Then,
    Else,
    Let,
    Var,
    Accept,
    Reject,
    With,
    Case,
    Default,
    True,
    False,
    Net,
    Proto,
    Source,
    Bgp,
    Roa,

    Eof,
}

/// Lexer error: always fatal — the parser does not try to recover.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LexerError {
    pub line: u32,
    pub col: u32,
    pub kind: LexerErrorKind,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LexerErrorKind {
    UnterminatedString,
    UnknownEscape(char),
    InvalidNumber(String),
    UnexpectedChar(char),
}

impl fmt::Display for LexerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "lexer error at line {} col {}: {}",
            self.line, self.col, self.kind
        )
    }
}

impl fmt::Display for LexerErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LexerErrorKind::UnterminatedString => write!(f, "unterminated string literal"),
            LexerErrorKind::UnknownEscape(c) => write!(f, "unknown escape \\{c}"),
            LexerErrorKind::InvalidNumber(s) => write!(f, "invalid number '{s}'"),
            LexerErrorKind::UnexpectedChar(c) => write!(f, "unexpected character '{c}'"),
        }
    }
}

/// The lexer: a `&[u8]` cursor.
pub struct Lexer<'a> {
    src: &'a [u8],
    pos: usize,
    line: u32,
    col: u32,
}

impl<'a> Lexer<'a> {
    pub fn new(src: &'a str) -> Self {
        Self {
            src: src.as_bytes(),
            pos: 0,
            line: 1,
            col: 1,
        }
    }

    /// Lex the entire source into a flat token list. The final token
    /// is always `TokenKind::Eof` so the parser can loop without an
    /// off-by-one.
    pub fn tokenize(mut self) -> Result<Vec<Token>, LexerError> {
        let mut out = Vec::new();
        loop {
            let tok = self.next_token()?;
            let is_eof = tok.kind == TokenKind::Eof;
            out.push(tok);
            if is_eof {
                break;
            }
        }
        Ok(out)
    }

    fn peek(&self) -> Option<u8> {
        self.src.get(self.pos).copied()
    }

    fn advance(&mut self) -> Option<u8> {
        let b = self.src.get(self.pos).copied()?;
        self.pos += 1;
        if b == b'\n' {
            self.line += 1;
            self.col = 1;
        } else {
            self.col += 1;
        }
        Some(b)
    }

    fn skip_whitespace_and_comments(&mut self) {
        loop {
            match self.peek() {
                Some(b' ') | Some(b'\t') | Some(b'\r') | Some(b'\n') => {
                    self.advance();
                }
                Some(b'#') => {
                    // Line comment — skip to end of line.
                    while let Some(b) = self.peek() {
                        if b == b'\n' {
                            break;
                        }
                        self.advance();
                    }
                }
                _ => break,
            }
        }
    }

    fn next_token(&mut self) -> Result<Token, LexerError> {
        self.skip_whitespace_and_comments();
        let line = self.line;
        let col = self.col;
        let Some(b) = self.peek() else {
            return Ok(self.token(TokenKind::Eof, line, col));
        };

        // Identifiers / keywords (start with letter or underscore).
        if b == b'_' || b.is_ascii_alphabetic() {
            return self.lex_ident(line, col);
        }

        // Numbers — integers, possibly followed by an address / prefix
        // (e.g. `10.0.0.0` or `2001:db8::/32`). The lexer is greedy
        // here: it collects the whole run of digits / dots / colons /
        // hex digits / `/` so the parser gets one token; the value
        // decides whether it's an Int, Ip, Prefix, or Asn literal.
        if b.is_ascii_digit() {
            return self.lex_numeric_or_address(line, col);
        }

        // String literals.
        if b == b'"' {
            return self.lex_string(line, col);
        }

        // Multi-char operators and single-char punctuation.
        self.lex_punctuation(line, col)
    }

    fn token(&self, kind: TokenKind, line: u32, col: u32) -> Token {
        Token { kind, line, col }
    }

    fn lex_ident(&mut self, line: u32, col: u32) -> Result<Token, LexerError> {
        let start = self.pos;
        while let Some(b) = self.peek() {
            if b == b'_' || b.is_ascii_alphanumeric() {
                self.advance();
            } else {
                break;
            }
        }
        let text = std::str::from_utf8(&self.src[start..self.pos]).map_err(|_| LexerError {
            line,
            col,
            kind: LexerErrorKind::UnexpectedChar('\0'),
        })?;
        let kind = match text {
            "if" => TokenKind::If,
            "then" => TokenKind::Then,
            "else" => TokenKind::Else,
            "let" => TokenKind::Let,
            "var" => TokenKind::Var,
            "accept" => TokenKind::Accept,
            "reject" => TokenKind::Reject,
            "with" => TokenKind::With,
            "case" => TokenKind::Case,
            "default" => TokenKind::Default,
            "true" => TokenKind::True,
            "false" => TokenKind::False,
            "net" => TokenKind::Net,
            "proto" => TokenKind::Proto,
            "source" => TokenKind::Source,
            "bgp" => TokenKind::Bgp,
            "roa" => TokenKind::Roa,
            "_" => TokenKind::Underscore,
            other => TokenKind::Ident(other.to_string()),
        };
        Ok(self.token(kind, line, col))
    }

    fn lex_numeric_or_address(&mut self, line: u32, col: u32) -> Result<Token, LexerError> {
        // Collect the run that could be a number, an IPv4 address,
        // an IPv6 address (with `:`), or a prefix (`/`).
        // The run stops at the FIRST `:` when no `.` has been seen
        // yet AND the segment after the `:` is purely decimal — that
        // distinguishes a community pair `64512:100` from an IPv6
        // address `2001:db8::1`.
        let start = self.pos;
        let mut saw_dot = false;
        let mut saw_colon = false;
        while let Some(b) = self.peek() {
            if b.is_ascii_hexdigit() || b == b'/' {
                self.advance();
                continue;
            }
            if b == b'.' {
                saw_dot = true;
                self.advance();
                continue;
            }
            if b == b':' {
                if !saw_dot && !saw_colon {
                    // Peek the segment after the `:`. If it's purely
                    // decimal digits terminated by a non-hex /
                    // non-address char (`,`, `]`, `;`, ...), treat
                    // this as a community pair — stop here.
                    // `64512:*` (D3.4 wildcard pattern) is a pair
                    // too — the value component is the `*`.
                    if self.src.get(self.pos + 1) == Some(&b'*') {
                        break;
                    }
                    let mut p = self.pos + 1;
                    let mut all_decimal = true;
                    let mut any_digit = false;
                    while let Some(nb) = self.src.get(p).copied() {
                        if nb.is_ascii_digit() {
                            any_digit = true;
                            p += 1;
                        } else if nb.is_ascii_hexdigit() && nb.is_ascii_alphabetic() {
                            // a-f → could be IPv6
                            all_decimal = false;
                            break;
                        } else {
                            break;
                        }
                    }
                    if all_decimal && any_digit {
                        // Community pair — break before `:`.
                        break;
                    }
                }
                saw_colon = true;
                self.advance();
                continue;
            }
            break;
        }
        let raw = std::str::from_utf8(&self.src[start..self.pos]).map_err(|_| LexerError {
            line,
            col,
            kind: LexerErrorKind::UnexpectedChar('\0'),
        })?;

        // Try as prefix (`a.b.c.d/n` or `2001:db8::/n`).
        if let Ok(prefix) = Prefix::from_str(raw) {
            return Ok(self.token(TokenKind::Prefix(prefix), line, col));
        }
        // Try as bare IP address (no `/`).
        if let Ok(ip) = IpAddr::from_str(raw) {
            return Ok(self.token(TokenKind::Ip(ip), line, col));
        }
        // The DSL accepts bare integers as AS numbers in context;
        // the evaluator coerces to `Asn` when needed.
        if let Ok(n) = raw.parse::<i64>() {
            return Ok(self.token(TokenKind::Int(n), line, col));
        }
        Err(LexerError {
            line,
            col,
            kind: LexerErrorKind::InvalidNumber(raw.to_string()),
        })
    }

    fn lex_string(&mut self, line: u32, col: u32) -> Result<Token, LexerError> {
        // Opening `"` already at self.pos.
        self.advance(); // consume `"`
        let mut buf = String::new();
        loop {
            match self.peek() {
                None => {
                    return Err(LexerError {
                        line,
                        col,
                        kind: LexerErrorKind::UnterminatedString,
                    });
                }
                Some(b'"') => {
                    self.advance();
                    break;
                }
                Some(b'\\') => {
                    self.advance();
                    let Some(esc) = self.peek() else {
                        return Err(LexerError {
                            line,
                            col,
                            kind: LexerErrorKind::UnterminatedString,
                        });
                    };
                    self.advance();
                    match esc {
                        b'\\' => buf.push('\\'),
                        b'"' => buf.push('"'),
                        b'n' => buf.push('\n'),
                        b't' => buf.push('\t'),
                        b'r' => buf.push('\r'),
                        b'0' => buf.push('\0'),
                        other => {
                            return Err(LexerError {
                                line,
                                col,
                                kind: LexerErrorKind::UnknownEscape(other as char),
                            });
                        }
                    }
                }
                Some(b) => {
                    self.advance();
                    // Bytes are ASCII / UTF-8 — push as a char. UTF-8
                    // multi-byte sequences are accumulated byte by
                    // byte into the buffer; Rust strings are UTF-8
                    // so this is a no-op for ASCII and reconstructs
                    // the original bytes for non-ASCII.
                    buf.push(b as char);
                }
            }
        }
        Ok(self.token(TokenKind::Str(buf), line, col))
    }

    fn lex_punctuation(&mut self, line: u32, col: u32) -> Result<Token, LexerError> {
        let b = self.advance().unwrap();
        let kind = match b {
            b'(' => TokenKind::LParen,
            b')' => TokenKind::RParen,
            b'{' => TokenKind::LBrace,
            b'}' => TokenKind::RBrace,
            b'[' => TokenKind::LBracket,
            b']' => TokenKind::RBracket,
            b',' => TokenKind::Comma,
            b';' => TokenKind::Semicolon,
            b':' => TokenKind::Colon,
            b'.' => TokenKind::Dot,
            b'+' => match self.peek() {
                Some(b'=') => {
                    self.advance();
                    TokenKind::PlusEq
                }
                _ => TokenKind::Plus,
            },
            b'-' => TokenKind::Minus,
            b'*' => TokenKind::Star,
            b'/' => TokenKind::Slash,
            b'%' => TokenKind::Percent,
            b'!' => match self.peek() {
                Some(b'=') => {
                    self.advance();
                    TokenKind::NotEq
                }
                Some(b'~') => {
                    self.advance();
                    TokenKind::BangTilde
                }
                _ => TokenKind::Bang,
            },
            b'~' => TokenKind::Tilde,
            b'&' => match self.peek() {
                Some(b'&') => {
                    self.advance();
                    TokenKind::AndAnd
                }
                _ => TokenKind::Amp,
            },
            b'|' => match self.peek() {
                Some(b'|') => {
                    self.advance();
                    TokenKind::OrOr
                }
                _ => TokenKind::Pipe,
            },
            b'^' => TokenKind::Caret,
            b'<' => match self.peek() {
                Some(b'<') => {
                    self.advance();
                    TokenKind::Shl
                }
                Some(b'=') => {
                    self.advance();
                    TokenKind::LtEq
                }
                _ => TokenKind::Lt,
            },
            b'>' => match self.peek() {
                Some(b'>') => {
                    self.advance();
                    TokenKind::Shr
                }
                Some(b'=') => {
                    self.advance();
                    TokenKind::GtEq
                }
                _ => TokenKind::Gt,
            },
            b'=' => match self.peek() {
                Some(b'=') => {
                    self.advance();
                    TokenKind::EqEq
                }
                Some(b'>') => {
                    self.advance();
                    TokenKind::Arrow
                }
                _ => TokenKind::Eq,
            },
            b'?' => TokenKind::Underscore, // unused — keep for completeness
            other => {
                return Err(LexerError {
                    line,
                    col,
                    kind: LexerErrorKind::UnexpectedChar(other as char),
                });
            }
        };
        Ok(self.token(kind, line, col))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn kinds(src: &str) -> Vec<TokenKind> {
        Lexer::new(src)
            .tokenize()
            .unwrap()
            .into_iter()
            .map(|t| t.kind)
            .collect()
    }

    #[test]
    fn simple_punctuation() {
        assert_eq!(
            kinds("(){}[];:,."),
            vec![
                TokenKind::LParen,
                TokenKind::RParen,
                TokenKind::LBrace,
                TokenKind::RBrace,
                TokenKind::LBracket,
                TokenKind::RBracket,
                TokenKind::Semicolon,
                TokenKind::Colon,
                TokenKind::Comma,
                TokenKind::Dot,
                TokenKind::Eof,
            ]
        );
    }

    #[test]
    fn operators_two_char() {
        assert_eq!(
            kinds("== != <= >= && || << >> += => !~"),
            vec![
                TokenKind::EqEq,
                TokenKind::NotEq,
                TokenKind::LtEq,
                TokenKind::GtEq,
                TokenKind::AndAnd,
                TokenKind::OrOr,
                TokenKind::Shl,
                TokenKind::Shr,
                TokenKind::PlusEq,
                TokenKind::Arrow,
                TokenKind::BangTilde,
                TokenKind::Eof,
            ]
        );
    }

    #[test]
    fn bang_tilde_distinguished_from_bang() {
        // `! ~` (with whitespace) is two tokens; `!~` is one. BIRD
        // spells both forms and the lexer must mirror it so the
        // parser can build a `NotMatch` node only when the user
        // actually meant non-match.
        assert_eq!(
            kinds("!~ ! ~"),
            vec![
                TokenKind::BangTilde,
                TokenKind::Bang,
                TokenKind::Tilde,
                TokenKind::Eof,
            ]
        );
    }

    #[test]
    fn operators_single_char() {
        assert_eq!(
            kinds("+ - * / % ! ~ & | ^ < > ="),
            vec![
                TokenKind::Plus,
                TokenKind::Minus,
                TokenKind::Star,
                TokenKind::Slash,
                TokenKind::Percent,
                TokenKind::Bang,
                TokenKind::Tilde,
                TokenKind::Amp,
                TokenKind::Pipe,
                TokenKind::Caret,
                TokenKind::Lt,
                TokenKind::Gt,
                TokenKind::Eq,
                TokenKind::Eof,
            ]
        );
    }

    #[test]
    fn keywords() {
        assert_eq!(
            kinds("if then else let var accept reject with case default true false net proto source bgp roa"),
            vec![
                TokenKind::If,
                TokenKind::Then,
                TokenKind::Else,
                TokenKind::Let,
                TokenKind::Var,
                TokenKind::Accept,
                TokenKind::Reject,
                TokenKind::With,
                TokenKind::Case,
                TokenKind::Default,
                TokenKind::True,
                TokenKind::False,
                TokenKind::Net,
                TokenKind::Proto,
                TokenKind::Source,
                TokenKind::Bgp,
                TokenKind::Roa,
                TokenKind::Eof,
            ]
        );
    }

    #[test]
    fn identifiers() {
        let toks = kinds("foo bar_1 myVar");
        assert_eq!(
            toks,
            vec![
                TokenKind::Ident("foo".into()),
                TokenKind::Ident("bar_1".into()),
                TokenKind::Ident("myVar".into()),
                TokenKind::Eof,
            ]
        );
    }

    #[test]
    fn integer_literals() {
        let toks = kinds("0 42 65535 -7");
        // Negative numbers are lexed as Minus + Int — the parser
        // folds them via UnaryOp::Neg.
        assert_eq!(
            toks,
            vec![
                TokenKind::Int(0),
                TokenKind::Int(42),
                TokenKind::Int(65535),
                TokenKind::Minus,
                TokenKind::Int(7),
                TokenKind::Eof,
            ]
        );
    }

    #[test]
    fn ipv4_address_literal() {
        let toks = kinds("10.0.0.1");
        match toks.as_slice() {
            [TokenKind::Ip(ip), TokenKind::Eof] => {
                assert!(matches!(ip, IpAddr::V4([10, 0, 0, 1])));
            }
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn ipv6_address_literal() {
        let toks = kinds("2001:db8::1");
        match toks.as_slice() {
            [TokenKind::Ip(_), TokenKind::Eof] => {}
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn prefix_literal_v4() {
        let toks = kinds("10.0.0.0/8");
        match toks.as_slice() {
            [TokenKind::Prefix(p), TokenKind::Eof] => {
                assert_eq!(p.prefix_len, 8);
                assert!(matches!(p.addr, IpAddr::V4([10, 0, 0, 0])));
            }
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn prefix_literal_v6() {
        let toks = kinds("2001:db8::/32");
        match toks.as_slice() {
            [TokenKind::Prefix(_), TokenKind::Eof] => {}
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn string_literal_basic() {
        let toks = kinds("\"hello world\"");
        match toks.as_slice() {
            [TokenKind::Str(s), TokenKind::Eof] => assert_eq!(s, "hello world"),
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn string_literal_escapes() {
        let toks = kinds("\"a\\nb\\\"c\"");
        match toks.as_slice() {
            [TokenKind::Str(s), TokenKind::Eof] => assert_eq!(s, "a\nb\"c"),
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn unterminated_string_is_an_error() {
        let err = Lexer::new("\"oops").tokenize().unwrap_err();
        assert_eq!(err.kind, LexerErrorKind::UnterminatedString);
    }

    #[test]
    fn unknown_escape_is_an_error() {
        let err = Lexer::new("\"a\\xb\"").tokenize().unwrap_err();
        assert_eq!(err.kind, LexerErrorKind::UnknownEscape('x'));
    }

    #[test]
    fn line_comments_are_dropped() {
        let toks = kinds("foo # this is a comment\nbar");
        assert_eq!(
            toks,
            vec![
                TokenKind::Ident("foo".into()),
                TokenKind::Ident("bar".into()),
                TokenKind::Eof,
            ]
        );
    }

    #[test]
    fn underscore_token() {
        // BIRD uses `_` in AS-path patterns to mean "any separator".
        // The lexer treats a bare `_` as the Underscore token so the
        // parser can build AS-path patterns.
        let toks = kinds("_");
        assert_eq!(toks, vec![TokenKind::Underscore, TokenKind::Eof]);
    }
}
