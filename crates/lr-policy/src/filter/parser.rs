//! Pratt-style parser for the filter DSL.
//!
//! The parser consumes a flat `Vec<Token>` from [`crate::filter::lexer::Lexer`]
//! and produces a [`crate::filter::ast::Filter`]. Statement parsing is
//! recursive descent (with `;` separators); expression parsing is a
//! Pratt loop driven by [`crate::filter::ast::BinaryOp::precedence`].

use core::fmt;

use crate::filter::ast::{
    BinaryOp, CaseArm, Expr, Filter, FilterBody, RouteField, RouteFieldKind, Stmt, UnaryOp, Value,
};
use crate::filter::lexer::{Lexer, LexerError, Token, TokenKind};

/// Parse error — always fatal. Carries the source location of the
/// offending token for diagnostics.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseError {
    pub line: u32,
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
    UnknownRouteField(String),
    ReadOnlyField(String),
    UnknownBgpField(String),
    InvalidPrefixRange(String),
    InvalidCommunity(String),
    EmptyFilterBody,
    DuplicateArm,
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
            ParseErrorKind::Lexer(e) => write!(f, "{e}"),
            ParseErrorKind::UnexpectedToken { expected, found } => {
                write!(f, "expected {expected}, found {found:?}")
            }
            ParseErrorKind::UnexpectedEof => write!(f, "unexpected end of input"),
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
            line: e.line,
            col: e.col,
            kind: ParseErrorKind::Lexer(e),
        }
    }
}

/// The parser — a token cursor.
pub struct Parser {
    tokens: Vec<Token>,
    pos: usize,
}

impl Parser {
    pub fn new(src: &str) -> Self {
        let tokens = Lexer::new(src).tokenize().unwrap_or_else(|e| {
            // Tokenize failed — surface a single-token Eof so the
            // parser produces a clear ParseError on the first call.
            vec![Token {
                kind: TokenKind::Eof,
                line: e.line,
                col: e.col,
            }]
        });
        Self { tokens, pos: 0 }
    }

    /// Entry point: parse a filter body (with or without outer braces).
    pub fn parse_filter(&mut self, name: &str) -> Result<Filter, ParseError> {
        // The lexer failed in `new` — surface a clean error.
        if self.tokens.len() == 1 {
            if let TokenKind::Eof = self.tokens[0].kind {
                let t = &self.tokens[0];
                return Err(ParseError {
                    line: t.line,
                    col: t.col,
                    kind: ParseErrorKind::EmptyFilterBody,
                });
            }
        }
        let body = if matches!(self.peek_kind(), Some(TokenKind::LBrace)) {
            self.parse_block_body()?
        } else {
            self.parse_stmt_list_until_eof()?
        };
        if body.stmts.is_empty() {
            let tok = self.peek().cloned().unwrap_or_else(|| Token {
                kind: TokenKind::Eof,
                line: 1,
                col: 1,
            });
            return Err(ParseError {
                line: tok.line,
                col: tok.col,
                kind: ParseErrorKind::EmptyFilterBody,
            });
        }
        if !matches!(self.peek_kind(), Some(TokenKind::Eof) | None) {
            let tok = self.peek().cloned().unwrap();
            return Err(ParseError {
                line: tok.line,
                col: tok.col,
                kind: ParseErrorKind::UnexpectedToken {
                    expected: "end of input",
                    found: tok.kind.clone(),
                },
            });
        }
        Ok(Filter {
            name: name.to_string(),
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
            None => Err(ParseError {
                line: 1,
                col: 1,
                kind: ParseErrorKind::UnexpectedEof,
            }),
            Some(t) if t.kind == expected_kind => {
                self.advance();
                Ok(())
            }
            Some(t) => Err(ParseError {
                line: t.line,
                col: t.col,
                kind: ParseErrorKind::UnexpectedToken {
                    expected: label,
                    found: t.kind.clone(),
                },
            }),
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
            return Err(ParseError {
                line: 1,
                col: 1,
                kind: ParseErrorKind::UnexpectedEof,
            });
        };
        match tok.kind {
            TokenKind::If => self.parse_if(),
            TokenKind::Case => self.parse_case(),
            TokenKind::Let | TokenKind::Var => self.parse_let(),
            TokenKind::Accept => {
                self.advance();
                self.expect(TokenKind::Semicolon, "`;`")?;
                Ok(Stmt::Accept)
            }
            TokenKind::Reject => {
                self.advance();
                let reason = if matches!(self.peek_kind(), Some(TokenKind::Str(_))) {
                    if let Some(Token {
                        kind: TokenKind::Str(s),
                        ..
                    }) = self.advance().cloned()
                    {
                        self.expect(TokenKind::Semicolon, "`;`")?;
                        Some(Expr::Lit(Value::Str(s)))
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
                Ok(Stmt::Reject(reason))
            }
            TokenKind::LBrace => {
                let body = self.parse_block_body()?;
                Ok(Stmt::Block(body.stmts))
            }
            _ => self.parse_expr_or_assign(),
        }
    }

    fn parse_if(&mut self) -> Result<Stmt, ParseError> {
        self.expect(TokenKind::If, "`if`")?;
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
        Ok(Stmt::If {
            cond,
            then: Box::new(then),
            els,
        })
    }

    fn parse_case(&mut self) -> Result<Stmt, ParseError> {
        self.expect(TokenKind::Case, "`case`")?;
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
                Stmt::Block(inner) => inner,
                other => vec![other],
            };
            arms.push(CaseArm { patterns, body });
            if matches!(self.peek_kind(), Some(TokenKind::Semicolon)) {
                self.advance();
            }
        }
        self.expect(TokenKind::RBrace, "`}`")?;
        Ok(Stmt::Case { scrutinee, arms })
    }

    fn parse_let(&mut self) -> Result<Stmt, ParseError> {
        self.advance(); // `let` or `var`
        let name = self.parse_ident()?;
        self.expect(TokenKind::Eq, "`=`")?;
        let value = self.parse_expr()?;
        self.expect(TokenKind::Semicolon, "`;`")?;
        Ok(Stmt::Let { name, value })
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
            Some(t) => Err(ParseError {
                line: t.line,
                col: t.col,
                kind: ParseErrorKind::UnexpectedToken {
                    expected: "identifier",
                    found: t.kind.clone(),
                },
            }),
            None => Err(ParseError {
                line: 1,
                col: 1,
                kind: ParseErrorKind::UnexpectedEof,
            }),
        }
    }

    fn parse_expr_or_assign(&mut self) -> Result<Stmt, ParseError> {
        let tok = self.peek().cloned();
        let Some(tok) = tok else {
            return Err(ParseError {
                line: 1,
                col: 1,
                kind: ParseErrorKind::UnexpectedEof,
            });
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
                        return Err(ParseError {
                            line: tok.line,
                            col: tok.col,
                            kind: ParseErrorKind::ReadOnlyField(field.kind.to_string()),
                        });
                    }
                    let value = self.parse_expr()?;
                    self.expect(TokenKind::Semicolon, "`;`")?;
                    return Ok(Stmt::AssignRouteField { field, value });
                }
                Some(TokenKind::PlusEq) => {
                    self.advance();
                    if !matches!(field.kind, RouteFieldKind::BgpCommunities) {
                        return Err(ParseError {
                            line: tok.line,
                            col: tok.col,
                            kind: ParseErrorKind::ReadOnlyField(field.kind.to_string()),
                        });
                    }
                    let value = self.parse_expr()?;
                    self.expect(TokenKind::Semicolon, "`;`")?;
                    return Ok(Stmt::AppendRouteField { field, value });
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
                return Ok(Stmt::Assign {
                    name: name.clone(),
                    value,
                });
            }
        }
        // Plain expression statement.
        let e = self.parse_expr()?;
        self.expect(TokenKind::Semicolon, "`;`")?;
        Ok(Stmt::Expr(e))
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
                    return Err(ParseError {
                        line: tok.line,
                        col: tok.col,
                        kind: ParseErrorKind::UnexpectedEof,
                    });
                };
                let kind = match field_tok.kind {
                    TokenKind::Ident(s) => match s.as_str() {
                        "local_pref" => RouteFieldKind::BgpLocalPref,
                        "med" => RouteFieldKind::BgpMed,
                        "next_hop" => RouteFieldKind::BgpNextHop,
                        "as_path" => RouteFieldKind::BgpAsPath,
                        "communities" => RouteFieldKind::BgpCommunities,
                        "origin" => RouteFieldKind::BgpOrigin,
                        other => {
                            return Err(ParseError {
                                line: field_tok.line,
                                col: field_tok.col,
                                kind: ParseErrorKind::UnknownBgpField(other.to_string()),
                            });
                        }
                    },
                    other => {
                        return Err(ParseError {
                            line: field_tok.line,
                            col: field_tok.col,
                            kind: ParseErrorKind::UnexpectedToken {
                                expected: "bgp field name",
                                found: other.clone(),
                            },
                        });
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
                    return Err(ParseError {
                        line: tok.line,
                        col: tok.col,
                        kind: ParseErrorKind::UnexpectedEof,
                    });
                };
                match &state_tok.kind {
                    TokenKind::Ident(s) if s == "state" => {
                        self.advance();
                        RouteField::new(RouteFieldKind::RoaState)
                    }
                    other => {
                        return Err(ParseError {
                            line: state_tok.line,
                            col: state_tok.col,
                            kind: ParseErrorKind::UnexpectedToken {
                                expected: "roa.state",
                                found: other.clone(),
                            },
                        });
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
        loop {
            let Some(tok) = self.peek().cloned() else {
                break;
            };
            let op = match tok.kind {
                TokenKind::Plus => BinaryOp::Add,
                TokenKind::Minus => BinaryOp::Sub,
                TokenKind::Star => BinaryOp::Mul,
                TokenKind::Slash => BinaryOp::Div,
                TokenKind::Percent => BinaryOp::Mod,
                TokenKind::EqEq => BinaryOp::Eq,
                TokenKind::NotEq => BinaryOp::Ne,
                TokenKind::Lt => BinaryOp::Lt,
                TokenKind::LtEq => BinaryOp::Le,
                TokenKind::Gt => BinaryOp::Gt,
                TokenKind::GtEq => BinaryOp::Ge,
                TokenKind::AndAnd => BinaryOp::And,
                TokenKind::OrOr => BinaryOp::Or,
                TokenKind::Amp => BinaryOp::BitAnd,
                TokenKind::Pipe => BinaryOp::BitOr,
                TokenKind::Caret => BinaryOp::BitXor,
                TokenKind::Shl => BinaryOp::Shl,
                TokenKind::Shr => BinaryOp::Shr,
                TokenKind::Tilde => BinaryOp::Match,
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
            lhs = Expr::Binary {
                op,
                lhs: Box::new(lhs),
                rhs: Box::new(rhs),
            };
        }
        Ok(lhs)
    }

    fn parse_unary(&mut self) -> Result<Expr, ParseError> {
        let tok = self.peek().cloned();
        let Some(tok) = tok else {
            return Err(ParseError {
                line: 1,
                col: 1,
                kind: ParseErrorKind::UnexpectedEof,
            });
        };
        match tok.kind {
            TokenKind::Bang => {
                self.advance();
                let e = self.parse_unary()?;
                Ok(Expr::Unary {
                    op: UnaryOp::Not,
                    expr: Box::new(e),
                })
            }
            TokenKind::Minus => {
                self.advance();
                let e = self.parse_unary()?;
                Ok(Expr::Unary {
                    op: UnaryOp::Neg,
                    expr: Box::new(e),
                })
            }
            _ => self.parse_postfix(),
        }
    }

    fn parse_postfix(&mut self) -> Result<Expr, ParseError> {
        let mut expr = self.parse_primary()?;
        loop {
            match self.peek_kind() {
                Some(TokenKind::Dot) => {
                    self.advance();
                    let method_tok = self.peek().cloned();
                    let Some(method_tok) = method_tok else {
                        return Err(ParseError {
                            line: 1,
                            col: 1,
                            kind: ParseErrorKind::UnexpectedEof,
                        });
                    };
                    let method = match method_tok.kind {
                        TokenKind::Ident(s) => s,
                        other => {
                            return Err(ParseError {
                                line: method_tok.line,
                                col: method_tok.col,
                                kind: ParseErrorKind::UnexpectedToken {
                                    expected: "method name",
                                    found: other.clone(),
                                },
                            });
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
            return Err(ParseError {
                line: 1,
                col: 1,
                kind: ParseErrorKind::UnexpectedEof,
            });
        };
        match tok.kind {
            TokenKind::Int(n) => {
                self.advance();
                Ok(Expr::Lit(Value::Int(n)))
            }
            TokenKind::True => {
                self.advance();
                Ok(Expr::Lit(Value::Bool(true)))
            }
            TokenKind::False => {
                self.advance();
                Ok(Expr::Lit(Value::Bool(false)))
            }
            TokenKind::Str(s) => {
                self.advance();
                Ok(Expr::Lit(Value::Str(s)))
            }
            TokenKind::Ip(ip) => {
                self.advance();
                Ok(Expr::Lit(Value::Ip(ip)))
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
                    let (ge, le) =
                        parse_range_from_tokens(&range_tokens).map_err(|e| ParseError {
                            line: brace_tok.line,
                            col: brace_tok.col,
                            kind: ParseErrorKind::InvalidPrefixRange(e),
                        })?;
                    self.expect(TokenKind::RBrace, "`}`")?;
                    Ok(Expr::PrefixSet { prefix: p, ge, le })
                } else {
                    Ok(Expr::PrefixSet {
                        prefix: p,
                        ge: None,
                        le: None,
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
                Ok(Expr::Set(items))
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
                    Ok(Expr::Call { name, args })
                } else {
                    Ok(Expr::Var(name))
                }
            }
            TokenKind::Net
            | TokenKind::Proto
            | TokenKind::Source
            | TokenKind::Bgp
            | TokenKind::Roa => {
                let field = self.try_parse_route_field()?.ok_or_else(|| ParseError {
                    line: tok.line,
                    col: tok.col,
                    kind: ParseErrorKind::UnexpectedToken {
                        expected: "route field",
                        found: tok.kind.clone(),
                    },
                })?;
                Ok(Expr::RouteField(field))
            }
            TokenKind::Underscore => {
                // BIRD AS-path wildcard — appears in `[ 65000 _ ]`
                // patterns. Lift to a `Var("_")` so the evaluator's
                // AS-path matcher treats it as a separator wildcard.
                self.advance();
                Ok(Expr::Var("_".to_string()))
            }
            other => Err(ParseError {
                line: tok.line,
                col: tok.col,
                kind: ParseErrorKind::UnexpectedToken {
                    expected: "expression",
                    found: other.clone(),
                },
            }),
        }
    }

    fn parse_set_item(&mut self) -> Result<Expr, ParseError> {
        // A set item can be a prefix, an integer, a community pair
        // (`asn:value`), or an `_` wildcard. The primary parser
        // handles prefixes and integers; communities are detected
        // by the `:` after an integer literal.
        let tok = self.peek().cloned();
        let Some(tok) = tok else {
            return Err(ParseError {
                line: 1,
                col: 1,
                kind: ParseErrorKind::UnexpectedEof,
            });
        };
        // Community pair: `int : int`.
        if matches!(tok.kind, TokenKind::Int(_)) {
            if matches!(
                self.tokens.get(self.pos + 1).map(|t| &t.kind),
                Some(TokenKind::Colon)
            ) {
                let asn_tok = self.advance().cloned().unwrap();
                self.advance(); // colon
                let val_tok = self.peek().cloned();
                let Some(val_tok) = val_tok else {
                    return Err(ParseError {
                        line: asn_tok.line,
                        col: asn_tok.col,
                        kind: ParseErrorKind::InvalidCommunity("(missing value)".to_string()),
                    });
                };
                let val = match val_tok.kind {
                    TokenKind::Int(n) if (0..=u16::MAX as i64).contains(&n) => n as u16,
                    _ => {
                        return Err(ParseError {
                            line: val_tok.line,
                            col: val_tok.col,
                            kind: ParseErrorKind::InvalidCommunity(format!(
                                "expected integer value, found {:?}",
                                val_tok.kind
                            )),
                        });
                    }
                };
                self.advance();
                if let TokenKind::Int(asn) = asn_tok.kind {
                    if asn > u32::MAX as i64 {
                        return Err(ParseError {
                            line: asn_tok.line,
                            col: asn_tok.col,
                            kind: ParseErrorKind::InvalidCommunity(format!(
                                "ASN {asn} exceeds u32"
                            )),
                        });
                    }
                    return Ok(Expr::Lit(Value::Communities(vec![(
                        lr_core::addr::Asn(asn as u32),
                        val,
                    )])));
                }
            }
        }
        self.parse_expr()
    }
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
        assert!(matches!(f.body.stmts[0], Stmt::Accept));
    }

    #[test]
    fn reject_statement_parses() {
        let f = parse_ok("reject;");
        assert_eq!(f.body.stmts.len(), 1);
        assert!(matches!(f.body.stmts[0], Stmt::Reject(None)));
    }

    #[test]
    fn reject_with_reason_parses() {
        let f = parse_ok("reject with \"bad route\";");
        assert!(matches!(f.body.stmts[0], Stmt::Reject(Some(_))));
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
        assert!(matches!(f.body.stmts[0], Stmt::Expr(Expr::Method { .. })));
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
        assert!(matches!(f.body.stmts[0], Stmt::Block(_)));
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
}
