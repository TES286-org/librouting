//! Pratt-style parser for the filter DSL.
//!
//! The parser consumes a flat `Vec<Token>` from [`crate::filter::lexer::Lexer`]
//! and produces a [`crate::filter::ast::Filter`]. Statement parsing is
//! recursive descent (with `;` separators); expression parsing is a
//! Pratt loop driven by [`crate::filter::ast::BinaryOp::precedence`].

use core::fmt;

use lr_core::addr::IpAddr;

use crate::filter::ast::{
    BinaryOp, CaseArm, Expr, Filter, FilterBody, FunctionDecl, RouteField, RouteFieldKind, Stmt,
    UnaryOp, Value,
};
use crate::filter::lexer::{Lexer, LexerError, Token, TokenKind};
use crate::filter::span::{LineIndex, Span};

/// Parse error — always fatal. Carries the source span of the
/// offending token for diagnostics (plus its 1-indexed start
/// line/column for callers that never see the source text).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseError {
    /// Byte span of the offending construct in the filter source.
    pub span: Span,
    /// 1-indexed line of the error position.
    pub line: u32,
    /// 1-indexed byte column of the error position.
    pub col: u32,
    pub kind: ParseErrorKind,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseErrorKind {
    Lexer(LexerError),
    UnexpectedToken {
        expected: &'static str,
        found: TokenKind,
    },
    UnexpectedEof,
    /// The filter nests expressions or statements deeper than
    /// [`MAX_EXPR_DEPTH`]. Rejected instead of overflowing the stack
    /// (the nightly fuzz target found the unbounded-recursion crash).
    RecursionLimitExceeded,
    UnknownRouteField(String),
    ReadOnlyField(String),
    UnknownBgpField(String),
    InvalidPrefixRange(String),
    InvalidCommunity(String),
    EmptyFilterBody,
    DuplicateArm,
    /// A function-style construct was given the wrong number of
    /// arguments at parse time (currently `defined` / `exists`, which
    /// take exactly one).
    BadArgCount {
        name: String,
        got: usize,
    },
    /// Two user functions share a name, or a user function shadows a
    /// built-in (ROADMAP-v3 D3.1).
    DuplicateFunction(String),
    /// A call names neither a built-in nor a declared user function.
    /// Caught at compile time so a typo fails at startup instead of
    /// silently falling through at route time (D3.1).
    UnknownFunctionCall,
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "parse error at line {} col {}: {}",
            self.line, self.col, self.kind
        )
    }
}

impl fmt::Display for ParseErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ParseErrorKind::BadArgCount { name, got } => {
                write!(f, "function '{name}' takes exactly one argument, got {got}")
            }
            ParseErrorKind::DuplicateFunction(name) => {
                write!(
                    f,
                    "function '{name}' is declared twice or shadows a built-in"
                )
            }
            ParseErrorKind::UnknownFunctionCall => {
                write!(
                    f,
                    "call to an undeclared function (not a built-in, not user-defined)"
                )
            }
            ParseErrorKind::Lexer(e) => write!(f, "{e}"),
            ParseErrorKind::UnexpectedToken { expected, found } => {
                write!(f, "expected {expected}, found {found:?}")
            }
            ParseErrorKind::UnexpectedEof => write!(f, "unexpected end of input"),
            ParseErrorKind::RecursionLimitExceeded => write!(
                f,
                "expression nests deeper than the maximum of {MAX_EXPR_DEPTH} levels"
            ),
            ParseErrorKind::UnknownRouteField(s) => write!(f, "unknown route field '{s}'"),
            ParseErrorKind::ReadOnlyField(s) => {
                write!(f, "field '{s}' is read-only (cannot assign)")
            }
            ParseErrorKind::UnknownBgpField(s) => write!(f, "unknown bgp field '{s}'"),
            ParseErrorKind::InvalidPrefixRange(s) => write!(f, "invalid prefix range '{s}'"),
            ParseErrorKind::InvalidCommunity(s) => write!(f, "invalid community '{s}'"),
            ParseErrorKind::EmptyFilterBody => write!(f, "filter body is empty"),
            ParseErrorKind::DuplicateArm => write!(f, "duplicate case arm pattern"),
        }
    }
}

impl From<LexerError> for ParseError {
    fn from(e: LexerError) -> Self {
        ParseError {
            span: e.span,
            line: e.line,
            col: e.col,
            kind: ParseErrorKind::Lexer(e),
        }
    }
}

/// Maximum expression / statement nesting depth the parser will
/// descend before bailing out with
/// [`ParseErrorKind::RecursionLimitExceeded`].
///
/// Every real-world BIRD-style filter nests a handful of levels deep
/// (parens, `if` chains, set literals); the bound leaves two orders
/// of magnitude of head-room while keeping the parser's and the
/// evaluator's recursive walk comfortably inside the thread stack in
/// *every* build profile (debug frames are several times fatter than
/// release ones — the limit must be safe under `cargo test` too).
/// Without this bound an input like `[[[[[...` (thousands of set
/// opens) or `!!!!...` overflows the stack — found by the nightly
/// `filter_parser` fuzz target (AddressSanitizer stack-overflow on a
/// 3 911-byte input of nested `[`). The limit bounds parse recursion,
/// the built AST's height (so recursive `Drop` glue is safe too) and
/// the evaluator's recursive walk, which mirrors the tree shape. The
/// value is calibrated against the worst-case per-level frame chain
/// (a nested set literal descends through six parser frames per
/// level) measured on the debug build; the statement funnel shares
/// the same counter, so a 100-level parenthesised expression plus
/// its statement entry lands at 101.
pub const MAX_EXPR_DEPTH: usize = 108;

/// The parser — a token cursor.
pub struct Parser {
    tokens: Vec<Token>,
    pos: usize,
    /// Current nesting depth, shared by [`Self::parse_unary`] (every
    /// expression descent passes through it) and [`Self::parse_stmt`]
    /// (every statement descent passes through it). Bounded by
    /// [`MAX_EXPR_DEPTH`].
    depth: usize,
    /// Offset → (line, col) table for the parsed source, attached to
    /// the produced [`Filter`] so evaluation errors can render
    /// positions without the source text.
    line_index: LineIndex,
    /// Byte length of the parsed source — the EOF position.
    src_len: usize,
}

impl Parser {
    pub fn new(src: &str) -> Self {
        let line_index = LineIndex::new(src);
        let src_len = src.len();
        let tokens = Lexer::new(src).tokenize().unwrap_or_else(|e| {
            // Tokenize failed — surface a single-token Eof so the
            // parser produces a clear ParseError on the first call.
            vec![Token {
                kind: TokenKind::Eof,
                span: e.span,
                line: e.line,
                col: e.col,
            }]
        });
        Self {
            tokens,
            pos: 0,
            depth: 0,
            line_index,
            src_len,
        }
    }

    /// The span of the most recently consumed token (point at 0
    /// before the first token is consumed).
    fn last_consumed_span(&self) -> Span {
        if self.pos == 0 {
            Span::default()
        } else {
            self.tokens[self.pos - 1].span
        }
    }

    /// The end-of-input span (a point at the source end).
    fn eof_span(&self) -> Span {
        Span::point(self.src_len)
    }

    /// Build a [`ParseError`] with line/col derived from the span.
    fn err(&self, span: Span, kind: ParseErrorKind) -> ParseError {
        let (line, col) = self.line_index.line_col(span.start);
        ParseError {
            span,
            line,
            col,
            kind,
        }
    }

    /// Enter one level of nested parsing. Every recursive-descent
    /// funnel (expressions via `parse_unary`, statements via
    /// `parse_stmt`) calls this on entry and
    /// [`Self::leave`] on the way out.
    fn enter(&mut self, span: Span) -> Result<(), ParseError> {
        self.depth += 1;
        if self.depth > MAX_EXPR_DEPTH {
            return Err(self.err(span, ParseErrorKind::RecursionLimitExceeded));
        }
        Ok(())
    }

    /// Leave one level of nested parsing (mirrors [`Self::enter`]).
    fn leave(&mut self) {
        self.depth = self.depth.saturating_sub(1);
    }

    /// Entry point: parse a filter body (with or without outer braces).
    pub fn parse_filter(&mut self, name: &str) -> Result<Filter, ParseError> {
        // The lexer failed in `new` — surface a clean error.
        if self.tokens.len() == 1 {
            if let TokenKind::Eof = self.tokens[0].kind {
                let t = &self.tokens[0];
                return Err(self.err(t.span, ParseErrorKind::EmptyFilterBody));
            }
        }
        // ROADMAP-v3 D3.1: user-defined functions come first, BIRD
        // style (`function name(...) { ... }`), before the filter body.
        let mut functions = Vec::new();
        let mut fn_names = std::collections::BTreeSet::new();
        loop {
            if let Some(TokenKind::Ident(n)) = self.peek_kind().cloned() {
                if n == "function" {
                    let kw_span = self.peek().map(|t| t.span).unwrap_or_default();
                    let decl = self.parse_function_decl()?;
                    if fn_names.contains(&decl.name)
                        || BUILTIN_FUNCTIONS.contains(&decl.name.as_str())
                    {
                        return Err(self.err(
                            kw_span,
                            ParseErrorKind::DuplicateFunction(decl.name.clone()),
                        ));
                    }
                    fn_names.insert(decl.name.clone());
                    functions.push(decl);
                    continue;
                }
            }
            break;
        }
        let body = if matches!(self.peek_kind(), Some(TokenKind::LBrace)) {
            self.parse_block_body()?
        } else {
            self.parse_stmt_list_until_eof()?
        };
        if body.stmts.is_empty() {
            let span = self
                .peek()
                .map(|t| t.span)
                .unwrap_or_else(|| self.eof_span());
            return Err(self.err(span, ParseErrorKind::EmptyFilterBody));
        }
        if !matches!(self.peek_kind(), Some(TokenKind::Eof) | None) {
            let tok = self.peek().cloned().unwrap();
            return Err(self.err(
                tok.span,
                ParseErrorKind::UnexpectedToken {
                    expected: "end of input",
                    found: tok.kind.clone(),
                },
            ));
        }
        // Compile-time call validation: every call in the filter body
        // and every function body must name a built-in or a declared
        // user function — a typo must fail at startup, not silently
        // fall through at route time.
        validate_calls(&body, &fn_names, &self.line_index)?;
        for f in &functions {
            validate_calls(&f.body, &fn_names, &self.line_index)?;
        }
        Ok(Filter {
            name: name.to_string(),
            body,
            functions,
            line_index: self.line_index.clone(),
        })
    }

    /// Parse one `function name(a, b) -> ret { ... }` declaration.
    fn parse_function_decl(&mut self) -> Result<FunctionDecl, ParseError> {
        let tok = self.advance().cloned().unwrap(); // `function`
        let name_tok = self.peek().cloned();
        let Some(Token {
            kind: TokenKind::Ident(name),
            ..
        }) = name_tok
        else {
            return Err(self.err(
                tok.span,
                ParseErrorKind::UnexpectedToken {
                    expected: "function name",
                    found: self
                        .peek()
                        .map(|t| t.kind.clone())
                        .unwrap_or(TokenKind::Eof),
                },
            ));
        };
        self.advance();
        self.expect(TokenKind::LParen, "`(`")?;
        let mut params = Vec::new();
        if !matches!(self.peek_kind(), Some(TokenKind::RParen)) {
            loop {
                let p = self.peek().cloned();
                match p.map(|t| t.kind) {
                    Some(TokenKind::Ident(pn)) => {
                        self.advance();
                        params.push(pn);
                    }
                    _ => {
                        let t = self.peek().cloned();
                        let span = t
                            .as_ref()
                            .map(|t| t.span)
                            .unwrap_or_else(|| self.eof_span());
                        return Err(self.err(
                            span,
                            ParseErrorKind::UnexpectedToken {
                                expected: "parameter name",
                                found: t.map(|t| t.kind).unwrap_or(TokenKind::Eof),
                            },
                        ));
                    }
                }
                if matches!(self.peek_kind(), Some(TokenKind::Comma)) {
                    self.advance();
                } else {
                    break;
                }
            }
        }
        self.expect(TokenKind::RParen, "`)`")?;
        // Optional `-> type` documentation annotation.
        let return_type = if matches!(self.peek_kind(), Some(TokenKind::Arrow)) {
            self.advance();
            let t = self.peek().cloned();
            let t_span = t.as_ref().map(|t| t.span);
            match t.map(|t| t.kind) {
                Some(TokenKind::Ident(ty)) => {
                    self.advance();
                    Some(ty)
                }
                _ => {
                    let span = t_span.unwrap_or_else(|| self.eof_span());
                    return Err(self.err(
                        span,
                        ParseErrorKind::UnexpectedToken {
                            expected: "return type name",
                            found: self
                                .peek()
                                .map(|t| t.kind.clone())
                                .unwrap_or(TokenKind::Eof),
                        },
                    ));
                }
            }
        } else {
            None
        };
        let body = self.parse_block_body()?;
        Ok(FunctionDecl {
            name,
            params,
            return_type,
            body,
        })
    }

    fn peek(&self) -> Option<&Token> {
        self.tokens.get(self.pos)
    }

    fn peek_kind(&self) -> Option<&TokenKind> {
        self.tokens.get(self.pos).map(|t| &t.kind)
    }

    fn advance(&mut self) -> Option<&Token> {
        let tok = self.tokens.get(self.pos);
        if tok.is_some() {
            self.pos += 1;
        }
        tok
    }

    fn expect(&mut self, expected_kind: TokenKind, label: &'static str) -> Result<(), ParseError> {
        let tok = self.peek().cloned();
        match tok {
            None => Err(self.err(self.eof_span(), ParseErrorKind::UnexpectedEof)),
            Some(t) if t.kind == expected_kind => {
                self.advance();
                Ok(())
            }
            Some(t) => Err(self.err(
                t.span,
                ParseErrorKind::UnexpectedToken {
                    expected: label,
                    found: t.kind.clone(),
                },
            )),
        }
    }

    fn parse_block_body(&mut self) -> Result<FilterBody, ParseError> {
        self.expect(TokenKind::LBrace, "`{`")?;
        let stmts = self.parse_stmts_until(TokenKind::RBrace)?;
        self.expect(TokenKind::RBrace, "`}`")?;
        Ok(FilterBody { stmts })
    }

    fn parse_stmt_list_until_eof(&mut self) -> Result<FilterBody, ParseError> {
        let stmts = self.parse_stmts_until(TokenKind::Eof)?;
        Ok(FilterBody { stmts })
    }

    fn parse_stmts_until(&mut self, end: TokenKind) -> Result<Vec<Stmt>, ParseError> {
        let mut stmts = Vec::new();
        loop {
            match self.peek_kind() {
                None => break,
                Some(k) if *k == end => break,
                _ => stmts.push(self.parse_stmt()?),
            }
        }
        Ok(stmts)
    }

    fn parse_stmt(&mut self) -> Result<Stmt, ParseError> {
        let tok = self.peek().cloned();
        let Some(tok) = tok else {
            return Err(self.err(self.eof_span(), ParseErrorKind::UnexpectedEof));
        };
        // Guard the statement-recursion funnel (`if ... then if ...`,
        // nested `{ ... }` blocks, `case` arms). See `MAX_EXPR_DEPTH`.
        self.enter(tok.span)?;
        let out = self.parse_stmt_inner();
        self.leave();
        out
    }

    fn parse_stmt_inner(&mut self) -> Result<Stmt, ParseError> {
        let tok = self.peek().cloned();
        let Some(tok) = tok else {
            return Err(self.err(self.eof_span(), ParseErrorKind::UnexpectedEof));
        };
        match tok.kind {
            TokenKind::If => self.parse_if(),
            TokenKind::Case => self.parse_case(),
            TokenKind::Let | TokenKind::Var => self.parse_let(),
            TokenKind::Ident(name) if name == "return" => {
                // D3.1: `return expr;` / `return;` inside user
                // functions.
                self.advance();
                let value = if matches!(self.peek_kind(), Some(TokenKind::Semicolon)) {
                    None
                } else {
                    Some(self.parse_expr()?)
                };
                self.expect(TokenKind::Semicolon, "`;`")?;
                let span = tok.span.merge(self.last_consumed_span());
                Ok(Stmt::Return(value, span))
            }
            TokenKind::Accept => {
                self.advance();
                self.expect(TokenKind::Semicolon, "`;`")?;
                Ok(Stmt::Accept(tok.span))
            }
            TokenKind::Reject => {
                self.advance();
                let reason = if matches!(self.peek_kind(), Some(TokenKind::Str(_))) {
                    if let Some(Token {
                        kind: TokenKind::Str(s),
                        span: s_span,
                        ..
                    }) = self.advance().cloned()
                    {
                        self.expect(TokenKind::Semicolon, "`;`")?;
                        Some(Expr::Lit(Value::Str(s), s_span))
                    } else {
                        unreachable!()
                    }
                } else if matches!(self.peek_kind(), Some(TokenKind::With)) {
                    self.advance();
                    let e = self.parse_expr()?;
                    self.expect(TokenKind::Semicolon, "`;`")?;
                    Some(e)
                } else {
                    self.expect(TokenKind::Semicolon, "`;`")?;
                    None
                };
                let span = tok.span.merge(self.last_consumed_span());
                Ok(Stmt::Reject(reason, span))
            }
            TokenKind::LBrace => {
                let body = self.parse_block_body()?;
                let span = tok.span.merge(self.last_consumed_span());
                Ok(Stmt::Block(body.stmts, span))
            }
            _ => self.parse_expr_or_assign(),
        }
    }

    fn parse_if(&mut self) -> Result<Stmt, ParseError> {
        let start = self.advance().map(|t| t.span).unwrap_or_default(); // `if`
        let cond = self.parse_expr()?;
        self.expect(TokenKind::Then, "`then`")?;
        let then = self.parse_stmt()?;
        let els = if matches!(self.peek_kind(), Some(TokenKind::Else)) {
            self.advance();
            let s = self.parse_stmt()?;
            Some(Box::new(s))
        } else {
            None
        };
        let span = start.merge(self.last_consumed_span());
        Ok(Stmt::If {
            cond,
            then: Box::new(then),
            els,
            span,
        })
    }

    fn parse_case(&mut self) -> Result<Stmt, ParseError> {
        let start = self.advance().map(|t| t.span).unwrap_or_default(); // `case`
        let scrutinee = self.parse_expr()?;
        self.expect(TokenKind::LBrace, "`{`")?;
        let mut arms = Vec::new();
        while !matches!(self.peek_kind(), Some(TokenKind::RBrace) | None) {
            let patterns: Vec<Expr> = if matches!(self.peek_kind(), Some(TokenKind::Default)) {
                self.advance();
                Vec::new()
            } else {
                let mut v = vec![self.parse_expr()?];
                while matches!(self.peek_kind(), Some(TokenKind::Comma)) {
                    self.advance();
                    v.push(self.parse_expr()?);
                }
                v
            };
            self.expect(TokenKind::Arrow, "`=>`")?;
            let body_stmt = self.parse_stmt()?;
            let body = match body_stmt {
                Stmt::Block(inner, _) => inner,
                other => vec![other],
            };
            arms.push(CaseArm { patterns, body });
            if matches!(self.peek_kind(), Some(TokenKind::Semicolon)) {
                self.advance();
            }
        }
        self.expect(TokenKind::RBrace, "`}`")?;
        let span = start.merge(self.last_consumed_span());
        Ok(Stmt::Case {
            scrutinee,
            arms,
            span,
        })
    }

    fn parse_let(&mut self) -> Result<Stmt, ParseError> {
        let start = self.advance().map(|t| t.span).unwrap_or_default(); // `let` or `var`
        let name = self.parse_ident()?;
        self.expect(TokenKind::Eq, "`=`")?;
        let value = self.parse_expr()?;
        self.expect(TokenKind::Semicolon, "`;`")?;
        let span = start.merge(self.last_consumed_span());
        Ok(Stmt::Let { name, value, span })
    }

    fn parse_ident(&mut self) -> Result<String, ParseError> {
        let tok = self.peek().cloned();
        match tok {
            Some(Token {
                kind: TokenKind::Ident(s),
                ..
            }) => {
                let name = s.clone();
                self.advance();
                Ok(name)
            }
            Some(t) => Err(self.err(
                t.span,
                ParseErrorKind::UnexpectedToken {
                    expected: "identifier",
                    found: t.kind.clone(),
                },
            )),
            None => Err(self.err(self.eof_span(), ParseErrorKind::UnexpectedEof)),
        }
    }

    fn parse_expr_or_assign(&mut self) -> Result<Stmt, ParseError> {
        let tok = self.peek().cloned();
        let Some(tok) = tok else {
            return Err(self.err(self.eof_span(), ParseErrorKind::UnexpectedEof));
        };
        let saved_pos = self.pos;
        // Try to parse as a route field. If successful and the next
        // token is `=` or `+=`, this is an assignment to the field.
        // Otherwise we backtrack and parse as an expression.
        if let Some(field) = self.try_parse_route_field()? {
            match self.peek_kind() {
                Some(TokenKind::Eq) => {
                    self.advance();
                    if !field.kind.is_settable() {
                        return Err(self.err(
                            tok.span,
                            ParseErrorKind::ReadOnlyField(field.kind.to_string()),
                        ));
                    }
                    let value = self.parse_expr()?;
                    self.expect(TokenKind::Semicolon, "`;`")?;
                    let span = tok.span.merge(self.last_consumed_span());
                    return Ok(Stmt::AssignRouteField { field, value, span });
                }
                Some(TokenKind::PlusEq) => {
                    self.advance();
                    if !matches!(
                        field.kind,
                        RouteFieldKind::BgpCommunities
                            | RouteFieldKind::BgpLargeCommunities
                            | RouteFieldKind::BgpExtCommunities
                    ) {
                        return Err(self.err(
                            tok.span,
                            ParseErrorKind::ReadOnlyField(field.kind.to_string()),
                        ));
                    }
                    let value = self.parse_expr()?;
                    self.expect(TokenKind::Semicolon, "`;`")?;
                    let span = tok.span.merge(self.last_consumed_span());
                    return Ok(Stmt::AppendRouteField { field, value, span });
                }
                _ => {
                    self.pos = saved_pos;
                }
            }
        } else {
            self.pos = saved_pos;
        }
        // Variable assignment: `ident = expr;`
        if let Some(Token {
            kind: TokenKind::Ident(name),
            span: name_span,
            ..
        }) = self.peek().cloned()
        {
            if matches!(
                self.tokens.get(self.pos + 1).map(|t| &t.kind),
                Some(TokenKind::Eq)
            ) {
                self.advance(); // ident
                self.advance(); // =
                let value = self.parse_expr()?;
                self.expect(TokenKind::Semicolon, "`;`")?;
                let span = name_span.merge(self.last_consumed_span());
                return Ok(Stmt::Assign {
                    name: name.clone(),
                    value,
                    span,
                });
            }
        }
        // Plain expression statement.
        let e = self.parse_expr()?;
        self.expect(TokenKind::Semicolon, "`;`")?;
        let span = e.span();
        Ok(Stmt::Expr(e, span))
    }

    fn try_parse_route_field(&mut self) -> Result<Option<RouteField>, ParseError> {
        let tok = self.peek().cloned();
        let Some(tok) = tok else {
            return Ok(None);
        };
        let field = match tok.kind {
            TokenKind::Net => {
                self.advance();
                RouteField::new(RouteFieldKind::Net)
            }
            TokenKind::Proto => {
                self.advance();
                RouteField::new(RouteFieldKind::Proto)
            }
            TokenKind::Source => {
                self.advance();
                RouteField::new(RouteFieldKind::Source)
            }
            TokenKind::Bgp => {
                self.advance();
                self.expect(TokenKind::Dot, "`.`")?;
                let field_tok = self.peek().cloned();
                let Some(field_tok) = field_tok else {
                    return Err(self.err(tok.span, ParseErrorKind::UnexpectedEof));
                };
                let kind = match field_tok.kind {
                    TokenKind::Ident(s) => match s.as_str() {
                        "local_pref" => RouteFieldKind::BgpLocalPref,
                        "med" => RouteFieldKind::BgpMed,
                        "next_hop" => RouteFieldKind::BgpNextHop,
                        "as_path" => RouteFieldKind::BgpAsPath,
                        "communities" => RouteFieldKind::BgpCommunities,
                        "ext_communities" => RouteFieldKind::BgpExtCommunities,
                        "large_communities" => RouteFieldKind::BgpLargeCommunities,
                        "origin" => RouteFieldKind::BgpOrigin,
                        other => {
                            return Err(self.err(
                                field_tok.span,
                                ParseErrorKind::UnknownBgpField(other.to_string()),
                            ));
                        }
                    },
                    other => {
                        return Err(self.err(
                            field_tok.span,
                            ParseErrorKind::UnexpectedToken {
                                expected: "bgp field name",
                                found: other.clone(),
                            },
                        ));
                    }
                };
                self.advance();
                RouteField::new(kind)
            }
            TokenKind::Roa => {
                self.advance();
                self.expect(TokenKind::Dot, "`.`")?;
                let state_tok = self.peek().cloned();
                let Some(state_tok) = state_tok else {
                    return Err(self.err(tok.span, ParseErrorKind::UnexpectedEof));
                };
                match &state_tok.kind {
                    TokenKind::Ident(s) if s == "state" => {
                        self.advance();
                        RouteField::new(RouteFieldKind::RoaState)
                    }
                    other => {
                        return Err(self.err(
                            state_tok.span,
                            ParseErrorKind::UnexpectedToken {
                                expected: "roa.state",
                                found: other.clone(),
                            },
                        ));
                    }
                }
            }
            _ => return Ok(None),
        };
        Ok(Some(field))
    }

    // --- Expression parsing (Pratt) ---

    fn parse_expr(&mut self) -> Result<Expr, ParseError> {
        self.parse_binary(0)
    }

    fn parse_binary(&mut self, min_prec: u8) -> Result<Expr, ParseError> {
        let mut lhs = self.parse_unary()?;
        // The loop has multiple break paths inside the match (`_ => break`
        // and `if prec < min_prec { break; }`), so a `while let` form
        // would be less readable. Keep the explicit `loop`.
        #[allow(clippy::while_let_loop)]
        loop {
            // Peek the operator kind without cloning the whole token:
            // this frame stays live across the recursive descent, and
            // its stack slot is part of the recursion guard's budget.
            let op = match self.peek_kind() {
                Some(TokenKind::Plus) => BinaryOp::Add,
                Some(TokenKind::Minus) => BinaryOp::Sub,
                Some(TokenKind::Star) => BinaryOp::Mul,
                Some(TokenKind::Slash) => BinaryOp::Div,
                Some(TokenKind::Percent) => BinaryOp::Mod,
                Some(TokenKind::EqEq) => BinaryOp::Eq,
                Some(TokenKind::NotEq) => BinaryOp::Ne,
                Some(TokenKind::Lt) => BinaryOp::Lt,
                Some(TokenKind::LtEq) => BinaryOp::Le,
                Some(TokenKind::Gt) => BinaryOp::Gt,
                Some(TokenKind::GtEq) => BinaryOp::Ge,
                Some(TokenKind::AndAnd) => BinaryOp::And,
                Some(TokenKind::OrOr) => BinaryOp::Or,
                Some(TokenKind::Amp) => BinaryOp::BitAnd,
                Some(TokenKind::Pipe) => BinaryOp::BitOr,
                Some(TokenKind::Caret) => BinaryOp::BitXor,
                Some(TokenKind::Shl) => BinaryOp::Shl,
                Some(TokenKind::Shr) => BinaryOp::Shr,
                Some(TokenKind::Tilde) => BinaryOp::Match,
                Some(TokenKind::BangTilde) => BinaryOp::NotMatch,
                _ => break,
            };
            let prec = op.precedence();
            if prec < min_prec {
                break;
            }
            self.advance();
            let next_min = if op.right_associative() {
                prec
            } else {
                prec + 1
            };
            let rhs = self.parse_binary(next_min)?;
            let span = lhs.span().merge(rhs.span());
            lhs = Expr::Binary {
                op,
                lhs: Box::new(lhs),
                rhs: Box::new(rhs),
                span,
            };
        }
        Ok(lhs)
    }

    fn parse_unary(&mut self) -> Result<Expr, ParseError> {
        let tok_span = self.peek().map(|t| t.span).unwrap_or_default();
        let tok_kind = self.peek_kind().cloned();
        let Some(tok_kind) = tok_kind else {
            return Err(self.err(self.eof_span(), ParseErrorKind::UnexpectedEof));
        };
        // Guard the expression-recursion funnel. Every nested
        // expression (parens, set literals, unary chains, call args)
        // descends through `parse_binary` into `parse_unary`, so one
        // counter here bounds the whole expression grammar. See
        // `MAX_EXPR_DEPTH`.
        self.enter(tok_span)?;
        // The unary body is inlined here (not a separate function):
        // this frame sits on the stack once per nesting level of
        // every deep expression, and the debug-build stack margin of
        // the recursion guard is computed against this shape.
        let out = match tok_kind {
            TokenKind::Bang => {
                self.advance();
                let e = self.parse_unary()?;
                let span = tok_span.merge(e.span());
                Ok(Expr::Unary {
                    op: UnaryOp::Not,
                    expr: Box::new(e),
                    span,
                })
            }
            TokenKind::Minus => {
                self.advance();
                let e = self.parse_unary()?;
                let span = tok_span.merge(e.span());
                Ok(Expr::Unary {
                    op: UnaryOp::Neg,
                    expr: Box::new(e),
                    span,
                })
            }
            _ => self.parse_postfix(),
        };
        self.leave();
        out
    }

    fn parse_postfix(&mut self) -> Result<Expr, ParseError> {
        let mut expr = self.parse_primary()?;
        // The span of the whole postfix chain (`a.b(c).d(e)`) —
        // extended by every `.` suffix in the loop below.
        let receiver_start = expr.span();
        // The loop has a `_ => break` inside the match, so a `while let`
        // form would be less readable. Keep the explicit `loop`.
        #[allow(clippy::while_let_loop)]
        loop {
            match self.peek_kind() {
                Some(TokenKind::Dot) => {
                    self.advance();
                    let method_tok = self.peek().cloned();
                    let Some(method_tok) = method_tok else {
                        return Err(self.err(self.eof_span(), ParseErrorKind::UnexpectedEof));
                    };
                    let method = match method_tok.kind {
                        TokenKind::Ident(s) => s,
                        other => {
                            return Err(self.err(
                                method_tok.span,
                                ParseErrorKind::UnexpectedToken {
                                    expected: "method name",
                                    found: other.clone(),
                                },
                            ));
                        }
                    };
                    self.advance();
                    let args = if matches!(self.peek_kind(), Some(TokenKind::LParen)) {
                        self.advance();
                        let mut v = Vec::new();
                        if !matches!(self.peek_kind(), Some(TokenKind::RParen)) {
                            v.push(self.parse_expr()?);
                            while matches!(self.peek_kind(), Some(TokenKind::Comma)) {
                                self.advance();
                                v.push(self.parse_expr()?);
                            }
                        }
                        self.expect(TokenKind::RParen, "`)`")?;
                        v
                    } else {
                        Vec::new()
                    };
                    expr = Expr::Method {
                        receiver: Box::new(expr),
                        method,
                        args,
                        span: receiver_start.merge(self.last_consumed_span()),
                    };
                }
                _ => break,
            }
        }
        Ok(expr)
    }

    fn parse_primary(&mut self) -> Result<Expr, ParseError> {
        let tok = self.peek().cloned();
        let Some(tok) = tok else {
            return Err(self.err(self.eof_span(), ParseErrorKind::UnexpectedEof));
        };
        match tok.kind {
            TokenKind::Int(n) => {
                self.advance();
                Ok(Expr::Lit(Value::Int(n), tok.span))
            }
            TokenKind::True => {
                self.advance();
                Ok(Expr::Lit(Value::Bool(true), tok.span))
            }
            TokenKind::False => {
                self.advance();
                Ok(Expr::Lit(Value::Bool(false), tok.span))
            }
            TokenKind::Str(s) => {
                self.advance();
                Ok(Expr::Lit(Value::Str(s), tok.span))
            }
            TokenKind::Ip(ip) => {
                self.advance();
                Ok(Expr::Lit(Value::Ip(ip), tok.span))
            }
            TokenKind::Prefix(p) => {
                self.advance();
                // Optional `{ge,le}` range — only valid inside a set
                // literal but we accept it here too for ergonomic use.
                if matches!(self.peek_kind(), Some(TokenKind::LBrace)) {
                    let brace_tok = self.peek().cloned().unwrap();
                    self.advance();
                    let start = self.pos;
                    while let Some(t) = self.tokens.get(self.pos) {
                        if matches!(t.kind, TokenKind::RBrace) {
                            break;
                        }
                        self.pos += 1;
                    }
                    let range_tokens: Vec<Token> = self.tokens[start..self.pos].to_vec();
                    let (ge, le) = parse_range_from_tokens(&range_tokens).map_err(|e| {
                        self.err(brace_tok.span, ParseErrorKind::InvalidPrefixRange(e))
                    })?;
                    self.expect(TokenKind::RBrace, "`}`")?;
                    let span = tok.span.merge(self.last_consumed_span());
                    Ok(Expr::PrefixSet {
                        prefix: p,
                        ge,
                        le,
                        span,
                    })
                } else {
                    Ok(Expr::PrefixSet {
                        prefix: p,
                        ge: None,
                        le: None,
                        span: tok.span,
                    })
                }
            }
            TokenKind::LParen => {
                self.advance();
                let e = self.parse_expr()?;
                self.expect(TokenKind::RParen, "`)`")?;
                Ok(e)
            }
            TokenKind::LBracket => {
                self.advance();
                let mut items = Vec::new();
                if !matches!(self.peek_kind(), Some(TokenKind::RBracket)) {
                    items.push(self.parse_set_item()?);
                    while matches!(self.peek_kind(), Some(TokenKind::Comma)) {
                        self.advance();
                        items.push(self.parse_set_item()?);
                    }
                }
                self.expect(TokenKind::RBracket, "`]`")?;
                let span = tok.span.merge(self.last_consumed_span());
                Ok(Expr::Set(items, span))
            }
            TokenKind::Ident(name) => {
                self.advance();
                if matches!(self.peek_kind(), Some(TokenKind::LParen)) {
                    self.advance();
                    let mut args = Vec::new();
                    if !matches!(self.peek_kind(), Some(TokenKind::RParen)) {
                        args.push(self.parse_expr()?);
                        while matches!(self.peek_kind(), Some(TokenKind::Comma)) {
                            self.advance();
                            args.push(self.parse_expr()?);
                        }
                    }
                    self.expect(TokenKind::RParen, "`)`")?;
                    let span = tok.span.merge(self.last_consumed_span());
                    // `defined(x)` / `exists(x)` are structural, not
                    // ordinary calls: the evaluator needs the argument
                    // *expression* (unevaluated) to decide presence.
                    if name == "defined" || name == "exists" {
                        if args.len() != 1 {
                            return Err(self.err(
                                tok.span,
                                ParseErrorKind::BadArgCount {
                                    name,
                                    got: args.len(),
                                },
                            ));
                        }
                        return Ok(Expr::Defined(
                            Box::new(args.into_iter().next().unwrap()),
                            span,
                        ));
                    }
                    Ok(Expr::Call { name, args, span })
                } else {
                    Ok(Expr::Var(name, tok.span))
                }
            }
            TokenKind::Net
            | TokenKind::Proto
            | TokenKind::Source
            | TokenKind::Bgp
            | TokenKind::Roa => {
                let field = self.try_parse_route_field()?.ok_or_else(|| {
                    self.err(
                        tok.span,
                        ParseErrorKind::UnexpectedToken {
                            expected: "route field",
                            found: tok.kind.clone(),
                        },
                    )
                })?;
                Ok(Expr::RouteField(field, tok.span))
            }
            TokenKind::Underscore => {
                // BIRD AS-path wildcard — appears in `[ 65000 _ ]`
                // patterns. Lift to a `Var("_")` so the evaluator's
                // AS-path matcher treats it as a separator wildcard.
                self.advance();
                Ok(Expr::Var("_".to_string(), tok.span))
            }
            other => Err(self.err(
                tok.span,
                ParseErrorKind::UnexpectedToken {
                    expected: "expression",
                    found: other.clone(),
                },
            )),
        }
    }

    fn parse_set_item(&mut self) -> Result<Expr, ParseError> {
        // A set item can be a prefix, an integer, a community pair
        // (`asn:value`), or an `_` wildcard. The primary parser
        // handles prefixes and integers; communities are detected
        // by the `:` after an integer literal.
        let tok_span = self.peek().map(|t| t.span).unwrap_or_default();
        let tok_kind = self.peek_kind().cloned();
        let Some(tok_kind) = tok_kind else {
            return Err(self.err(self.eof_span(), ParseErrorKind::UnexpectedEof));
        };
        // Large community triple FIRST: `int : int : int` (RFC 8097;
        // roadmap D3.2 syntax `bgp.large_communities += [ 64512:100:200 ]`).
        // The pair arm below would otherwise swallow `a:b` from the
        // triple and leave `:c` dangling.
        if matches!(tok_kind, TokenKind::Int(_))
            && matches!(
                self.tokens.get(self.pos + 1).map(|t| &t.kind),
                Some(TokenKind::Colon)
            )
            && matches!(
                self.tokens.get(self.pos + 2).map(|t| &t.kind),
                Some(TokenKind::Int(_))
            )
            && matches!(
                self.tokens.get(self.pos + 3).map(|t| &t.kind),
                Some(TokenKind::Colon)
            )
            && matches!(
                self.tokens.get(self.pos + 4).map(|t| &t.kind),
                Some(TokenKind::Int(_))
            )
        {
            let comps: Vec<i64> = (0..3)
                .map(
                    |i| match self.tokens.get(self.pos + i * 2).map(|t| &t.kind) {
                        Some(TokenKind::Int(n)) => *n,
                        _ => unreachable!("shape checked above"),
                    },
                )
                .collect();
            if !comps.iter().all(|n| (0..=u32::MAX as i64).contains(n)) {
                return Err(self.err(
                    tok_span,
                    ParseErrorKind::InvalidCommunity(format!(
                        "large community {}:{}:{} has a component out of u32 range",
                        comps[0], comps[1], comps[2]
                    )),
                ));
            }
            let triple_span = self
                .tokens
                .get(self.pos)
                .map(|t| t.span)
                .unwrap_or_default()
                .merge(
                    self.tokens
                        .get(self.pos + 4)
                        .map(|t| t.span)
                        .unwrap_or_default(),
                );
            self.pos += 5; // 3 ints + 2 colons
            return Ok(Expr::Lit(
                Value::LargeCommunities(vec![(comps[0] as u32, comps[1] as u32, comps[2] as u32)]),
                triple_span,
            ));
        }
        // Community pair: `int : int`, plus the wildcard forms
        // `int : *`, `* : int`, `* : *` used by delete / filter
        // patterns (BIRD `f_pair` semantics — `None` = wildcard).
        let wildcard_asn = matches!(tok_kind, TokenKind::Star);
        if (matches!(tok_kind, TokenKind::Int(_)) || wildcard_asn)
            && matches!(
                self.tokens.get(self.pos + 1).map(|t| &t.kind),
                Some(TokenKind::Colon)
            )
        {
            let asn_tok = self.advance().cloned().unwrap();
            self.advance(); // colon
            let val_tok = self.peek().cloned();
            let Some(val_tok) = val_tok else {
                return Err(self.err(
                    asn_tok.span,
                    ParseErrorKind::InvalidCommunity("(missing value)".to_string()),
                ));
            };
            // Value component: integer, or `*` wildcard.
            let val: Option<u16> = match val_tok.kind {
                TokenKind::Int(n) if (0..=u16::MAX as i64).contains(&n) => Some(n as u16),
                TokenKind::Star => None,
                _ => {
                    return Err(self.err(
                        val_tok.span,
                        ParseErrorKind::InvalidCommunity(format!(
                            "expected integer value or '*', found {:?}",
                            val_tok.kind
                        )),
                    ));
                }
            };
            self.advance();
            // ASN component: integer within u32, or the `*` wildcard
            // that opened the pattern.
            let asn: Option<u32> = match (asn_tok.kind, wildcard_asn) {
                (TokenKind::Star, true) => None,
                (TokenKind::Int(asn), false) => {
                    if asn > u32::MAX as i64 {
                        return Err(self.err(
                            asn_tok.span,
                            ParseErrorKind::InvalidCommunity(format!("ASN {asn} exceeds u32")),
                        ));
                    }
                    Some(asn as u32)
                }
                _ => {
                    return Err(self.err(
                        asn_tok.span,
                        ParseErrorKind::InvalidCommunity("(mixed wildcard)".to_string()),
                    ));
                }
            };
            let span = asn_tok.span.merge(self.last_consumed_span());
            return Ok(Expr::Lit(Value::CommPattern { asn, val }, span));
        }
        // Extended community tuple (RFC 4360, BIRD syntax):
        // `(rt, <asn|ip>, <local>)` / `(ro, ...)` / `(soo, ...)`.
        if matches!(tok_kind, TokenKind::LParen) {
            let save = self.pos;
            self.advance(); // (
            let name_tok = self.peek().cloned();
            if let Some(TokenKind::Ident(name)) = name_tok.map(|t| t.kind) {
                let subtype = match name.as_str() {
                    "rt" | "target" => 0x02u8,         // Route Target
                    "ro" | "soo" | "origin" => 0x03u8, // Route Origin / SoO
                    _ => {
                        self.pos = save;
                        return self.parse_expr();
                    }
                };
                self.advance(); // name
                if matches!(self.peek_kind(), Some(TokenKind::Comma)) {
                    self.advance();
                    // Global administrator: integer (4-octet AS) or IP.
                    let global_tok = self.peek().cloned();
                    let (kind, global) = match global_tok.map(|t| t.kind) {
                        Some(TokenKind::Int(n)) if (0..=u32::MAX as i64).contains(&n) => {
                            // 4-octet AS specific, transitive
                            // (RFC 4360 §2 — RT/RO are transitive
                            // types; BIRD emits 0x42/0x43).
                            (0x02u8 | 0x40, n as u32)
                        }
                        Some(TokenKind::Ip(IpAddr::V4(octets))) => {
                            // IPv4 specific, transitive
                            (0x01u8 | 0x40, u32::from_be_bytes(octets))
                        }
                        Some(TokenKind::Ip(IpAddr::V6(_))) => {
                            return Err(self.err(
                                tok_span,
                                ParseErrorKind::InvalidCommunity(
                                    "extended communities have no IPv6 administrator form"
                                        .to_string(),
                                ),
                            ));
                        }
                        _ => {
                            self.pos = save;
                            return self.parse_expr();
                        }
                    };
                    self.advance();
                    if matches!(self.peek_kind(), Some(TokenKind::Comma)) {
                        self.advance();
                        let local_tok = self.peek().cloned();
                        let local = match local_tok.map(|t| t.kind) {
                            Some(TokenKind::Int(n)) if (0..=u16::MAX as i64).contains(&n) => {
                                n as u16
                            }
                            _ => {
                                return Err(self.err(
                                    tok_span,
                                    ParseErrorKind::InvalidCommunity(
                                        "extended community local part must be 0..=65535"
                                            .to_string(),
                                    ),
                                ));
                            }
                        };
                        self.advance();
                        if matches!(self.peek_kind(), Some(TokenKind::RParen)) {
                            self.advance(); // )
                            let span = tok_span.merge(self.last_consumed_span());
                            return Ok(Expr::Lit(
                                Value::ExtCommunities(vec![(kind, subtype, global, local)]),
                                span,
                            ));
                        }
                    }
                }
            }
            // Not an extended-community tuple — rewind and parse as
            // a grouped expression.
            self.pos = save;
        }
        self.parse_expr()
    }
}

/// Built-in function names the evaluator resolves in
/// `eval_call` (ROADMAP-v3 D3.4 + earlier). User functions must not
/// shadow these, and call validation accepts either set.
pub(crate) const BUILTIN_FUNCTIONS: &[&str] =
    &["len", "delete", "filter", "empty", "count", "first", "last"];

/// Compile-time call validation (D3.1): walk the statement tree and
/// reject `Call { name }` nodes that name neither a built-in nor a
/// declared user function. The error carries the offending call's
/// span so a typo fails with a position.
fn validate_calls(
    body: &FilterBody,
    user_functions: &std::collections::BTreeSet<String>,
    index: &LineIndex,
) -> Result<(), ParseError> {
    const MAX_DEPTH: u32 = 512;
    fn go_expr(e: &Expr, uf: &std::collections::BTreeSet<String>, d: u32) -> Result<(), Span> {
        if d > MAX_DEPTH {
            return Err(e.span());
        }
        match e {
            Expr::Call { name, args, span } => {
                if !BUILTIN_FUNCTIONS.contains(&name.as_str()) && !uf.contains(name) {
                    return Err(*span);
                }
                for a in args {
                    go_expr(a, uf, d + 1)?;
                }
                Ok(())
            }
            Expr::Defined(inner, _) => go_expr(inner, uf, d + 1),
            Expr::Method { receiver, args, .. } => {
                go_expr(receiver, uf, d + 1)?;
                for a in args {
                    go_expr(a, uf, d + 1)?;
                }
                Ok(())
            }
            Expr::Binary { lhs, rhs, .. } => {
                go_expr(lhs, uf, d + 1)?;
                go_expr(rhs, uf, d + 1)
            }
            Expr::Unary { expr, .. } => go_expr(expr, uf, d + 1),
            Expr::Set(items, _) => {
                for i in items {
                    go_expr(i, uf, d + 1)?;
                }
                Ok(())
            }
            _ => Ok(()),
        }
    }
    fn go_stmt(st: &Stmt, uf: &std::collections::BTreeSet<String>, d: u32) -> Result<(), Span> {
        if d > MAX_DEPTH {
            return Err(st.span());
        }
        match st {
            Stmt::If {
                cond, then, els, ..
            } => {
                go_expr(cond, uf, d + 1)?;
                go_stmt(then, uf, d + 1)?;
                if let Some(e) = els {
                    go_stmt(e, uf, d + 1)?;
                }
                Ok(())
            }
            Stmt::Case {
                scrutinee, arms, ..
            } => {
                go_expr(scrutinee, uf, d + 1)?;
                for arm in arms {
                    for pat in &arm.patterns {
                        go_expr(pat, uf, d + 1)?;
                    }
                    for s in &arm.body {
                        go_stmt(s, uf, d + 1)?;
                    }
                }
                Ok(())
            }
            Stmt::Let { value, .. } | Stmt::Assign { value, .. } => go_expr(value, uf, d + 1),
            Stmt::AssignRouteField { value, .. } | Stmt::AppendRouteField { value, .. } => {
                go_expr(value, uf, d + 1)
            }
            Stmt::Expr(e, _) => go_expr(e, uf, d + 1),
            Stmt::Block(body, _) => {
                for s in body {
                    go_stmt(s, uf, d + 1)?;
                }
                Ok(())
            }
            Stmt::Return(Some(e), _) => go_expr(e, uf, d + 1),
            Stmt::Return(None, _) | Stmt::Accept(_) | Stmt::Reject(..) => Ok(()),
        }
    }
    for st in &body.stmts {
        if let Err(span) = go_stmt(st, user_functions, 0) {
            let (line, col) = index.line_col(span.start);
            return Err(ParseError {
                span,
                line,
                col,
                kind: ParseErrorKind::UnknownFunctionCall,
            });
        }
    }
    Ok(())
}

/// Reconstruct a `(ge, le)` pair from the tokens between `{` and `}`.
fn parse_range_from_tokens(tokens: &[Token]) -> Result<(Option<u8>, Option<u8>), String> {
    if tokens.is_empty() {
        return Err("empty range".to_string());
    }
    let mut iter = tokens.iter();
    let mut ge: Option<u8> = None;
    let mut le: Option<u8> = None;
    if let Some(Token {
        kind: TokenKind::Int(n),
        ..
    }) = iter.next()
    {
        if !(*n >= 0 && *n <= u8::MAX as i64) {
            return Err(format!("range bound {n} out of u8"));
        }
        ge = Some(*n as u8);
    }
    match iter.next() {
        Some(Token {
            kind: TokenKind::Comma,
            ..
        }) => {}
        None => {
            le = ge;
            return Ok((ge, le));
        }
        Some(other) => {
            return Err(format!("expected `,`, found {:?}", other.kind));
        }
    }
    if let Some(Token {
        kind: TokenKind::Int(n),
        ..
    }) = iter.next()
    {
        if !(*n >= 0 && *n <= u8::MAX as i64) {
            return Err(format!("range bound {n} out of u8"));
        }
        le = Some(*n as u8);
    }
    if iter.next().is_some() {
        return Err("trailing tokens after range".to_string());
    }
    Ok((ge, le))
}

#[cfg(test)]
mod tests {
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
}
