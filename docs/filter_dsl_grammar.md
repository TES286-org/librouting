# Filter DSL — formal grammar

This document is the canonical reference for the librouting filter DSL: the
expression language written inside a `filter NAME { ... }` block of the native
`.lr` daemon configuration (see
[`config_dsl_grammar.md`](config_dsl_grammar.md)) and, on the legacy TOML
path, inside a `[[filter]]` table's `body` string.

The implementation is `crates/lr-policy/src/filter/`: a hand-rolled lexer, a
Pratt parser, a tree-walking evaluator and a bytecode VM that share the
matching helpers. The DSL's consumers are the daemon's `filter` blocks, the
FFI `lr_filter_compile` entry point, the BIRD compat translator
(`crates/lr-cli/src/translate_bird_filter.rs`) and the tutorial snippets
pinned by `crates/lr-tests/tests/tutorial_snippets.rs`.

The grammar below is derived directly from the source. When the prose and the
source disagree, the source wins; please open a PR that fixes whichever is
wrong. The companion test `crates/lr-policy/tests/grammar_corpus.rs` pins every
example in this file through `lr_policy::filter::compile`, so a doc/source
drift fails CI rather than shipping.

The DSL targets a subset of BIRD 2's `filter` language expressive enough for
production import/export policy. See
[`docs/examples/filter_dsl_roa.md`](examples/filter_dsl_roa.md) for an
end-to-end recipe and [`docs/COMPAT.md`](COMPAT.md) for the BIRD/FRR
translation surface.

---

## 1. Lexical structure

### 1.1 Character set

The lexer operates on `&[u8]` and is byte-oriented. Source files are UTF-8.
Identifiers are ASCII-only, matching BIRD. A string literal accepts any byte,
but the lexer widens each byte to a `char` as it builds the `String`, so a
multi-byte character inside a literal does not survive byte-for-byte; keep
non-ASCII text out of a filter.

### 1.2 Whitespace and comments

```ebnf
whitespace := ? ASCII space (U+0020) ? | ? ASCII tab (U+0009) ?
           | ? ASCII CR (U+000D) ? | ? ASCII LF (U+000A) ? ;
comment    := '#' { ? any byte except ASCII LF ? } ? ASCII LF ? ;
```

Whitespace and `#` line comments are dropped at lex time. There is no block
comment form.

### 1.3 Identifiers and keywords

```ebnf
ident          := ident_start { ident_continue } ;
ident_start    := "A" | "B" | … | "Z" | "a" | "b" | … | "z" | "_" ;
ident_continue := ident_start | "0" | "1" | … | "9" ;
```

The reserved words below are recognised in identifier position and never lex as
`Ident`:

| Keyword   | Role                           |
| --------- | ------------------------------ |
| `if`      | conditional statement          |
| `then`    | conditional separator          |
| `else`    | conditional alternative        |
| `let`     | variable declaration (mutable) |
| `var`     | alias of `let`                 |
| `accept`  | terminal statement             |
| `reject`  | terminal statement             |
| `with`    | `reject with EXPR` form        |
| `case`    | switch statement               |
| `default` | catch-all arm in `case`        |
| `true`    | boolean literal                |
| `false`   | boolean literal                |
| `net`     | route field                    |
| `proto`   | route field                    |
| `source`  | route field                    |
| `bgp`     | route field prefix             |
| `roa`     | route field prefix             |

A lone `_` lexes as the `Underscore` token (BIRD's AS-path wildcard); the bare
`?` byte is accepted as its synonym and is otherwise unused.

`function` is recognised contextually at the top of a filter body as a function
declaration — it is not a reserved word and may still be used as a variable
name inside expressions. The same applies to `return` (a contextual keyword
recognised only at statement position, never inside an expression).

### 1.4 Literals

```ebnf
integer    := ["-"] dec_digit { dec_digit } ;
dec_digit  := "0" | "1" | … | "9" ;
string     := '"' { char_escape | unescaped } '"' ;
unescaped  := ? any byte except '"' (U+0022) and '\\' (U+005C) ? ;
char_escape := "\\\""
             | "\\\\"
             | "\\n"
             | "\\t"
             | "\\r"
             | "\\0" ;
ip         := ipv4 | ipv6 ;   (* RFC 4001 text form *)
prefix     := ip "/" dec_digit { dec_digit } ;   (* family length: 0..=32, 0..=128 *)
```

Notes:

- Negative integers are lexed as `Minus` followed by `Int`; the parser folds
  them via `UnaryOp::Neg`. The lexer itself never produces a negative `Int`
  token.
- The lexer is greedy on numeric input: it collects the whole run of digits,
  `.`, `:`, hex digits and `/` and then disambiguates the result as `Prefix`
  (when `from_str` succeeds), bare `Ip`, or `Int`. A run that parses as none of
  the three is a fatal `InvalidNumber` lexer error. Community patterns
  `asn:value` are detected contextually — see §2.3 — and the lexer stops the
  run at the `:` so a pattern stays two tokens.
- A raw newline is allowed inside a string literal (only `"` and `\` end it).
- String literals do not accept `\xHH` hex escapes. Unknown escapes are fatal
  `UnknownEscape` lexer errors, and an unterminated string is a fatal
  `UnterminatedString`.
- AS numbers are not first-class literals: they are plain integers whose value
  the evaluator narrows to `Asn` (a `u32` wrapper) at the call site. An integer
  literal outside `0..=u32::MAX` used in ASN context is a runtime
  `TypeMismatch`, not a parse error.

### 1.5 Operators and punctuation

```ebnf
operator := "+"  | "-"  | "*"  | "/"  | "%"
          | "!"  | "~"  | "&"  | "|"  | "^"
          | "<"  | ">"  | "="  | "_"
          | "==" | "!=" | "<=" | ">="
          | "&&" | "||" | "<<" | ">>"
          | "+=" | "=>" | "!~" ;
punct    := "("  | ")"  | "{"  | "}"  | "["  | "]"
          | ","  | ";"  | ":"  | "." ;
```

The lexer prefers the longest match: `==` beats `=`, `=>` beats `=`, `!=` beats
`!`, `!~` beats `!`, `<=` beats `<`, `<<` beats `<`, etc. Every other byte is a
fatal `UnexpectedChar` lexer error.

### 1.6 Token summary

The lexer produces a flat `Vec<Token>` terminated by `Eof`. Every token carries
its 1-indexed line and column for diagnostics. The full enum lives at
[`crates/lr-policy/src/filter/lexer.rs`](../crates/lr-policy/src/filter/lexer.rs)
(`TokenKind`).

---

## 2. Grammar

The grammar below uses ISO/IEC 14977 EBNF. Concatenation is implicit, `|` is
alternation, `[ … ]` is optionality, `{ … }` is repetition (zero or more),
`( … )` is grouping, `"…"` is a terminal string.

A _filter_ is the top-level production. The lexer is invoked once on the whole
body; the parser consumes the resulting token stream through
[`Parser::parse_filter`](../crates/lr-policy/src/filter/parser.rs).

```ebnf
filter        := { function_decl } filter_body ;
function_decl := "function" ident "(" [ param_list ] ")" [ "=>" ident ] block ;
param_list    := ident { "," ident } ;
filter_body   := block | stmt_list ;
stmt_list     := stmt { stmt } ;
block         := "{" [ stmt_list ] "}" ;
```

### 2.1 Statements

```ebnf
stmt     := "if" expr "then" stmt [ "else" stmt ]
          | "case" expr "{" { case_arm } "}"
          | "let" ident "=" expr ";"
          | "var" ident "=" expr ";"
          | "return" [ expr ] ";"
          | "accept" ";"
          | "reject" [ "with" expr | string ] ";"
          | lvalue "=" expr ";"
          | lvalue "+=" expr ";"
          | expr ";"
          | block ;
case_arm := ( expr { "," expr } | "default" ) "=>" stmt [ ";" ] ;
lvalue   := route_field | ident ;
```

Notes:

- `if`/`else` is a statement, not an expression — the DSL has no ternary. The
  `else` arm parses another `stmt`, so `else if` chains work via right-nesting.
- `case` arms accept a comma-separated list of patterns sharing one body. A bare
  `default` arm carries no pattern. The body of an arm is a single statement and
  is required: a brace-delimited block is the usual form, parsed as
  `Stmt::Block`. An optional trailing `;` is allowed after the arm body.
- `accept` and `reject` terminate the filter immediately. A bare `reject;`
  carries no reason; `reject "bad";` and `reject with EXPR;` are equivalent and
  produce a reason string at evaluation time.
- `return;` and `return EXPR;` exit the enclosing _user-defined function_. At
  filter top level `return` terminates the filter without a verdict
  (Fallthrough). A function body that falls off the end yields `false` (BIRD
  parity).
- `let`/`var` introduce a new variable in the current scope. A bare
  `name = expr;` _reassigns_ an existing variable — using `=` on an undeclared
  name is a runtime `AssignToUndefined` error (BIRD semantics: every variable
  must be declared first).
- `lvalue = expr;` and `lvalue += expr;` cover route-field mutation (see §2.4)
  and variable reassignment. The `+=` form is only valid on the three
  community-set fields; assigning a scalar with `+=` fails at parse time as
  `ReadOnlyField`.

### 2.2 Expressions

Expressions use a Pratt parser driven by the precedence table in §4. All binary
operators are left-associative; there are no right-associative operators in the
language (no `**` exponent).

```ebnf
expr        := or_expr ;
or_expr     := and_expr { "||" and_expr } ;
and_expr    := eq_expr { "&&" eq_expr } ;
eq_expr     := cmp_expr { ( "==" | "!=" ) cmp_expr } ;
cmp_expr    := bitor_expr { ( "<" | "<=" | ">" | ">=" | "~" | "!~" ) bitor_expr } ;
bitor_expr  := bitxor_expr { "|" bitxor_expr } ;
bitxor_expr := bitand_expr { "^" bitand_expr } ;
bitand_expr := shift_expr { "&" shift_expr } ;
shift_expr  := add_expr { ( "<<" | ">>" ) add_expr } ;
add_expr    := mul_expr { ( "+" | "-" ) mul_expr } ;
mul_expr    := unary { ( "*" | "/" | "%" ) unary } ;
unary       := ( "!" | "-" ) unary | postfix ;
postfix     := primary { "." ident [ "(" [ arg_list ] ")" ] } ;
primary     := literal
             | ident [ "(" [ arg_list ] ")" ]
             | route_field
             | "[" [ set_item { "," set_item } ] "]"
             | "(" expr ")"
             | "_" ;
arg_list    := expr { "," expr } ;
literal     := integer | string | "true" | "false" | ip | prefix_set ;
prefix_set  := prefix [ "{" range "}" ] ;
range       := integer [ "," [ integer ] ] ;
```

Notes:

- `defined(EXPR)` and `exists(EXPR)` are parsed as ordinary calls and then
  reified as the structural `Expr::Defined` node — the argument is left
  unevaluated so the evaluator can probe presence without triggering
  `UndefinedVar`. Both take exactly one argument; passing any other count fails
  at parse time as `BadArgCount`.
- `prefix_set` is `Expr::PrefixSet` in the AST: a prefix with BIRD's optional
  range, e.g. `10.0.0.0/8{16,24}`. The single-integer form `{N}` is sugar for
  `{N,N}` (exact match at length `N`); either bound may be omitted (`{16,}`
  leaves the upper bound open, `{,24}` the lower). `{}` is rejected, and any
  bound above 255 fails as `InvalidPrefixRange`. A prefix without a range is
  equally a `prefix_set`, so the form is accepted both inside set literals and
  as a bare expression.
- `_` is BIRD's AS-path separator wildcard, lifted to `Var("_")`. The matcher
  gives it no meaning: `~` on an AS-path is flat set membership (see §3.4).
- Set literals accept the heterogeneous element forms enumerated in §2.3. A set
  literal may be empty (`[]`).
- Method calls are pure syntactic sugar for
  `Expr::Method { receiver, method, args }`. They are dispatched on the _route
  field_ of the receiver at evaluation time; calling a method on a
  non-route-field expression is a runtime `UnknownMethod` error with
  `field = "<expr>"`.

### 2.3 Set items

A set literal element is one of:

```ebnf
set_item     := prefix_set      (* a prefix, optionally ranged    *)
              | integer         (* a bare AS number, port, …      *)
              | comm_pattern    (* "asn:value" and its wildcards  *)
              | large_comm      (* "g:d1:d2" RFC 8097 triple      *)
              | ext_comm        (* "(rt, asn|ip, local)"          *)
              | expr ;          (* anything else, e.g. a variable *)
comm_pattern := ( integer | "*" ) ":" ( integer | "*" ) ;
large_comm   := integer ":" integer ":" integer ;
ext_comm     := "(" ext_kind "," ext_global "," integer ")" ;
ext_kind     := "rt" | "target" | "ro" | "soo" | "origin" ;
ext_global   := integer | ipv4 ;   (* 4-octet AS or IPv4 administrator *)
```

The parser dispatches on the leading tokens, in this order:

- A leading `Int` followed by `:` `Int` `:` `Int` is a large-community triple
  (RFC 8097). Every component must fit `u32`.
- A leading `Int` or `*` followed by `:` is a community pattern (`asn:value`,
  `asn:*`, `*:value`, `*:*`), producing one `Value::CommPattern` node. The ASN
  component must fit `u32` and the value component `u16`. Wildcards apply only
  to community patterns; large-community triples and extended-community tuples
  require concrete integers in every field.
- A leading `(` followed by `rt`/`target`/`ro`/`soo`/`origin` and a comma is an
  extended-community tuple. The global administrator is a 4-octet AS (`u32`) or
  an IPv4 address; the local part must be a plain integer in `0..=65535`, with
  no `*` wildcard. IPv6 administrators are rejected: extended communities have
  no IPv6 form (use RFC 9256 large communities for that).
- Anything else falls through to `parse_expr`, so `[ 1, 2 ]`, `[ "x" ]` and
  `[ ( 42 ) ]` are all allowed. Elements are comma-separated: a bare `_` is a
  primary expression, so `[ _ ]` parses as a one-element set, but
  `[ 64500 _ 64502 ]` is a parse error (`expected ']'`).

### 2.4 Route fields

```ebnf
route_field := "net"
             | "proto"
             | "source"
             | "bgp" "." bgp_field
             | "roa" "." "state" ;
bgp_field   := "local_pref" | "med" | "next_hop"
             | "as_path" | "communities"
             | "ext_communities" | "large_communities"
             | "origin" ;
```

The settable subset (allowed on the left-hand side of `=`) is: `bgp.local_pref`,
`bgp.med`, `bgp.next_hop`, `bgp.communities`, `bgp.ext_communities`,
`bgp.large_communities`.

The `+=` form is restricted further: only the three community-set fields
(`bgp.communities`, `bgp.ext_communities`, `bgp.large_communities`) accept `+=`.
Assigning with `+=` to a scalar field (e.g. `bgp.local_pref += 1;`) fails at
parse time as `ReadOnlyField`.

The complete field reference lives in §5.

---

## 3. Semantics

### 3.1 Filter structure

A filter is the optional function declarations followed by a body. The body is
either a brace-delimited block (`{ … }`) or a bare statement list terminated by
end-of-input. An empty body is a parse error (`EmptyFilterBody`) — every filter
must do at least one thing. A body is also required after the function
declarations.

If the body falls off the end without hitting `accept` or `reject`, the filter
returns `Fallthrough`. The daemon maps every `EvalResult` through
`daemon_policy::map_verdict`, which turns both `Accept` and `Fallthrough` into
`HookVerdict::Keep` and `Reject` into `HookVerdict::Drop`; a `Fallthrough` in
either direction therefore keeps the route rather than dropping it.

### 3.2 Built-in functions

The parser accepts any `ident "(" args ")"` as a call. At compile time the call
validator (`validate_calls` in `parser.rs`) rejects calls that name neither a
built-in nor a declared user function. The built-in set is:

| Name     | Arity | Argument types                        | Returns  |
| -------- | ----- | ------------------------------------- | -------- |
| `len`    | 1     | `as-path`, `community-set`, `string`  | `int`    |
| `delete` | 2     | set-like, pattern-set                 | the first argument's type |
| `filter` | 2     | set-like, pattern-set                 | the first argument's type |
| `empty`  | 1     | set-like, `string`                    | `bool`   |
| `count`  | 1     | set-like                              | `int`    |
| `first`  | 1     | `as-path`                             | `asn`, or `false` when the path is empty |
| `last`   | 1     | `as-path`                             | `asn`, or `false` when the path is empty |

"set-like" means `as-path`, `community-set`, `large-community-set`,
`ext-community-set` or a generic `set`; in the `len` row `community-set`
covers the large- and extended-community sets too. Arity and argument types
are checked when the call runs (`EvalError::BadArgCount` / `TypeMismatch`);
only `defined`/`exists` are arity-checked at parse time. Note that `len` does
not accept a generic `set`, and `count` does not accept a `string`.

`delete(set, patterns)` returns a copy of `set` with every element matching any
pattern in `patterns` removed. `filter(set, patterns)` is the dual: only
matching elements survive. When the result is empty, writing it back drops the
attribute entirely (`lr_policy::bgp::set_communities` and its siblings remove
it), so assigning an empty set to `bgp.communities` leaves a route with no
community attribute, not one with an empty list.

### 3.3 Route-field methods

Method dispatch is keyed on `(RouteFieldKind, method_name)`:

| Receiver                | Method                      | Args  | Effect                                       |
| ----------------------- | --------------------------- | ----- | -------------------------------------------- |
| `bgp.as_path`           | `prepend`                   | `int` | Prepends the AS to the route's AS_PATH       |
| `bgp.as_path`           | `delete`                    | set   | Removes matching ASes from the AS_PATH       |
| `bgp.as_path`           | `filter`                    | set   | Keeps only matching ASes in the AS_PATH      |
| `bgp.communities`       | `add`                       | set   | Adds the communities                         |
| `bgp.communities`       | `delete`                    | set   | Removes matching communities                 |
| `bgp.communities`       | `filter`                    | set   | Keeps only matching communities              |
| `bgp.large_communities` | `add` / `delete` / `filter` | set   | Same shape as `bgp.communities`              |
| `bgp.ext_communities`   | `add` / `delete` / `filter` | set   | Same shape as `bgp.communities`              |

Every method mutates the route's attribute in place and also returns the new
value, so the statement form is enough:
`bgp.as_path.prepend(65001);` and
`bgp.communities.delete([ 64512:* ]);` both write through. That is the
difference from the `delete` / `filter` _built-ins_ of §3.2, which are pure and
return a new value that a `=` assignment has to store back:

```text
bgp.communities = delete(bgp.communities, [ 64512:* ]);
```

Any other `(field, method)` pair — including any method on a non-route-field
receiver — is a runtime `UnknownMethod` error.

### 3.4 The `~` and `!~` operators

The match operator `~` is overloaded on the type of its left-hand side:

| LHS type              | RHS                                   | Semantics                                     |
| --------------------- | ------------------------------------- | --------------------------------------------- |
| `prefix`              | `prefix-set`                          | Sub-prefix match, with the `{ge,le}` range when the RHS carries one |
| `as-path`             | `int` / `asn` / a set of them         | Any AS in the path is in the set              |
| `community-set`       | `community-set` / community pattern    | Any pattern matches any community             |
| `large-community-set` | `large-community-set`                 | Exact triple membership                       |
| `ext-community-set`   | `ext-community-set`                   | Exact record membership                       |
| `string`              | `string`                              | Equality                                      |
| `ip`                  | `ip` / a set of `ip`                  | Equality / membership                         |
| `roa-state`           | `string`                              | Equality with `"valid"` / `"invalid"` / `"not-found"` |
| any                   | `set`                                 | The match succeeds when any element matches   |

A `set` RHS is walked element by element, so the type of each element decides
which row applies. Two combinations do not match and do not error:

- `int ~ set of int` — there is no integer arm in `value_match`, so the test is
  always false. Compare integers with `==` or dispatch with `case`.
- A `prefix` on the left only matches `prefix` elements; an element of another
  type in the same set is simply skipped.

The AS-path row is a flat membership test, not BIRD's AS-path regex: there is no
`_` separator pattern, no `*` any-AS and no `..` range. Write
`bgp.as_path ~ [ 64500, 64502 ]` to mean "any AS in the path is one of these".

`!~` is the negation of `~` for every overload. Both share precedence level 4
(see §4).

### 3.5 Truthiness

`if` and `&&`/`||` apply the following truthiness rules:

| Type                                                 | Truthy when                |
| ---------------------------------------------------- | -------------------------- |
| `bool`                                               | the value is `true`        |
| `int`                                                | non-zero                   |
| `string`                                             | non-empty                  |
| `ip`, `prefix`, `asn`, `roa-state`, community pattern | always (presence is truth) |
| `as-path`, `community-set`, `large-community-set`, `ext-community-set`, `set` | non-empty |

The "presence is truth" rule for `ip`/`prefix`/`asn`/`roa-state` is what makes
`if bgp.next_hop then …` work without an explicit `defined()` check. A read of
`bgp.next_hop` on a route without one yields `false`, which is falsy.

---

## 4. Operator precedence and associativity

Precedence is encoded in
[`BinaryOp::precedence`](../crates/lr-policy/src/filter/ast.rs). Higher binds
tighter. All operators are left-associative.

| Level | Operators                      | Category         |
| ----- | ------------------------------ | ---------------- |
| 10    | `*` `/` `%`                    | multiplicative   |
| 9     | `+` `-`                        | additive         |
| 8     | `<<` `>>`                      | shift            |
| 7     | `&`                            | bitwise AND      |
| 6     | `^`                            | bitwise XOR      |
| 5     | `\|`                           | bitwise OR       |
| 4     | `<` `<=` `>` `>=` `~` `!~`     | comparison/match |
| 3     | `==` `!=`                      | equality         |
| 2     | `&&`                           | logical AND      |
| 1     | `\|\|`                         | logical OR       |

Unary `!` and `-` bind tighter than every binary operator (they apply before any
binary). The parser's `parse_unary` is the only funnel that descends past
`parse_binary`, so `!a && b` parses as `(!a) && b` and `-a * b` parses as
`(-a) * b`.

The Pratt loop is in
[`Parser::parse_binary`](../crates/lr-policy/src/filter/parser.rs). The
right-associative table is empty (`BinaryOp::right_associative` always returns
`false`); adding `**` would flip one row.

---

## 5. Route field reference

The complete list of route fields. _Settable_ fields accept `=`; the `+=` column
lists fields accepting the append form.

| Field                   | Type                  | Settable | `+=` | Notes                                                  |
| ----------------------- | --------------------- | :------: | :--: | ------------------------------------------------------ |
| `net`                   | `prefix`              |    no    |  no  | The route's prefix. Read-only.                         |
| `proto`                 | `string`              |    no    |  no  | The protocol name, e.g. `"bgp"`.                       |
| `source`                | `int`                 |    no    |  no  | Protocol-source id (kernel-dependent).                 |
| `bgp.local_pref`        | `int`                 |   yes    |  no  | BGP LOCAL_PREF (RFC 4271 §5.1.5).                      |
| `bgp.med`               | `int`                 |   yes    |  no  | BGP MULTI_EXIT_DISC.                                   |
| `bgp.next_hop`          | `ip`                  |   yes    |  no  | BGP NEXT_HOP; `false` when the route carries none.     |
| `bgp.as_path`           | `as-path`             |    no    |  no  | BGP AS_PATH. Mutate via `.prepend(int)`.               |
| `bgp.communities`       | `community-set`       |   yes    | yes  | RFC 1997 32-bit communities.                           |
| `bgp.ext_communities`   | `ext-community-set`   |   yes    | yes  | RFC 4360 transitive 8-byte communities.                |
| `bgp.large_communities` | `large-community-set` |   yes    | yes  | RFC 8097 12-byte communities.                          |
| `bgp.origin`            | `int`                 |    no    |  no  | BGP ORIGIN (0=IGP, 1=EGP, 2=INCOMPLETE).               |
| `roa.state`             | `roa-state`           |    no    |  no  | RFC 6811 outcome: `valid` / `invalid` / `not-found`.   |

`proto` reads a string, not a protocol object: compare it with
`proto == "bgp"` (the spelling the BIRD translator also produces). The value
comes from `Protocol::bird_name` — `"bgp"`, `"ospf"`, `"ospf3"`, `"babel"`,
`"static"`, `"direct"`, or `"unknown"`.

`roa.state` is read-only because the validation outcome is computed from the
route's prefix and origin AS at read time. The value reflects the cache state at
evaluation time — if the RTR client has applied a delta since the filter was
compiled, the new state is observed (the `FilterContext` reads the live
snapshot, not a captured one).

---

## 6. Limits

Two compile-time limits bound the parser and evaluator:

| Limit            | Value | Where defined                           | Effect when exceeded                 |
| ---------------- | ----- | --------------------------------------- | ------------------------------------ |
| `MAX_EXPR_DEPTH` | 108   | `crates/lr-policy/src/filter/parser.rs` | Parse error `RecursionLimitExceeded` |
| `MAX_CALL_DEPTH` | 64    | `crates/lr-policy/src/filter/eval.rs`   | Runtime error `CallDepthExceeded`    |

`MAX_EXPR_DEPTH` bounds every statement descent (`parse_stmt`) and every
expression descent (`parse_unary`) of the recursive-descent parser. It exists
because a deeply nested input (thousands of unclosed `[`, or a long `!!!!`
chain) would otherwise overflow the thread stack — the nightly `filter_parser`
fuzz target found a 3 911-byte input of nested `[` that did. Bounding the parse
also bounds the built AST's height, so the evaluator's recursive walk over that
AST is bounded by the same limit. The bound is checked as `depth > 108`, so a
depth of exactly 108 is accepted.

`MAX_CALL_DEPTH` bounds the nesting of user-defined function calls (64 frames);
it is unrelated to expression depth.

---

## 7. Worked examples

Every example below is pinned by `crates/lr-policy/tests/grammar_corpus.rs` —
the test compiles the body through `lr_policy::filter::compile` and asserts `Ok`
(or `Err` where noted). If the grammar changes, the test breaks first. Between
them the examples cover prefix-set ranges (§7.2), `reject` with a reason (§7.4),
`case` (§7.5), user-defined functions (§7.6) and the set operations (§7.7).

### 7.1 Accept-on-prefix, reject-otherwise

```text
if net ~ 10.0.0.0/8 then accept;
reject;
```

### 7.2 Prefix-set range membership (BIRD `{ge,le}` syntax)

```text
if net ~ [ 10.0.0.0/8{16,24} ] then accept;
reject;
```

### 7.3 LOCAL_PREF policy with arithmetic and short-circuit AND

```text
let pref_floor = 100;
let pref_cap = pref_floor * 2;
if bgp.local_pref < pref_cap && net ~ 10.0.0.0/8 then {
    bgp.local_pref = pref_cap;
    bgp.communities += [ 64512:100 ];
    accept;
}
reject;
```

### 7.4 ROA-gated import

```text
if roa.state == "invalid" then reject with "roa-invalid";
if roa.state == "valid" then {
    bgp.local_pref = 200;
    accept;
}
reject;
```

### 7.5 `case` over BGP ORIGIN

```text
case bgp.origin {
    0 => accept;
    1 => { bgp.local_pref = 50; accept; }
    default => reject;
}
```

### 7.6 User-defined function

```text
function is_internal(asn) => bool {
    return asn == 64500;
}
if is_internal(bgp.as_path.first) then {
    bgp.local_pref = 200;
    accept;
}
reject;
```

The `=> bool` after the parameter list is a _documentation-only_ return-type
annotation — the DSL is dynamically typed, so the annotation is parsed but never
enforced. The `=>` token is the same one used by `case` arms; there is no `->`
form in the DSL.

### 7.7 Community-set mutation via `delete` and `filter`

```text
bgp.communities = delete(bgp.communities, [ 64512:* ]);
bgp.communities = filter(bgp.communities, [ 65000:100 ]);
if empty(bgp.communities) then reject;
accept;
```

### 7.8 AS-path membership

```text
if bgp.as_path ~ [ 64500, 64502 ] then accept;
reject;
```

The `~` operator on an AS-path is a flat set-membership test: the route matches
if any AS in its AS_PATH is one of the listed values. BIRD-style AS-path regex
is not implemented in the matcher — see §3.4. Note that a bare `_` inside a set
literal is a parse error; the elements are comma-separated.

### 7.9 Extended-community tuple

```text
bgp.ext_communities += [ (rt, 64512, 100) ];
if bgp.ext_communities ~ [ (rt, 64512, 100) ] then accept;
reject;
```

The local part of an extended community is always a concrete integer; there is
no `*` wildcard form for the local part. Matching is exact record membership —
every field (kind, subtype, global, local) must match byte-for-byte.

### 7.10 Large-community triple

```text
bgp.large_communities += [ 64512:100:200 ];
if bgp.large_communities ~ [ 64512:100:200 ] then accept;
reject;
```

### 7.11 Reject parse error: empty body

```text
{}
```

Parses as `Err(ParseError { kind: EmptyFilterBody, … })`.

### 7.12 Reject parse error: undeclared function call

```text
if typo_function(net) then accept;
reject;
```

Parses as `Err(ParseError { kind: UnknownFunctionCall, … })` because
`typo_function` is neither a built-in nor a declared user function.

### 7.13 Reject parse error: `+=` on a scalar field

```text
bgp.local_pref += 1;
```

Parses as `Err(ParseError { kind: ReadOnlyField("bgp.local_pref"), … })`.

### 7.14 Reject parse error: recursion-depth exceeded

A literal of 200 unclosed `[` characters parses as
`Err(ParseError { kind: RecursionLimitExceeded, … })` because the nesting
exceeds `MAX_EXPR_DEPTH = 108`. (The exact 3 911-byte crasher from the nightly
fuzzer is pinned by
`crates/lr-policy/tests/filter_corpus.rs::nightly_nested_set_crasher_is_now_rejected_not_fatal`.)

Note: the parser also collapses any lexer error into `EmptyFilterBody` because
`Lexer::tokenize` returns `Err` as a single failure and `Parser::new`
substitutes a one-element `[Eof]` token stream — a typo in a string escape
therefore surfaces as "filter body is empty" rather than "lexer error at line N
col M". The companion corpus test pins this behaviour.

---

## 8. Relationship to BIRD

The DSL is intentionally a _subset_ of BIRD 2's `filter` grammar. The material
divergences are:

| Construct                | BIRD 2                          | librouting                        |
| ------------------------ | ------------------------------- | --------------------------------- |
| Boolean operators        | `&&`, `\|\|`, `!`               | identical                         |
| Equality / assignment    | `=` / `:=`                      | `==` / `=`                        |
| Match / non-match        | `~` / `!~`                      | identical                         |
| Attribute names          | `bgp_path`, `bgp_local_pref`, … | `bgp.as_path`, `bgp.local_pref`, … |
| Variables                | typed (`int x := 5;`)           | untyped (`let x = 5;`)            |
| `case` arm separator     | `:`                             | `=>`                              |
| `case` else arm          | `else:`                         | `default =>`                      |
| `case` range arm `a..b:` | supported                       | not supported (fail-closed)       |
| `define NAME = value;`   | constant, substituted textually | no equivalent; the translator substitutes the text |
| Function declaration     | `function name(int a, …) { … }` | `function name(a, …) { … }`; the optional `=> type` annotation is documentation |
| `roa_check(table)`       | `ROA_VALID` / `ROA_UNKNOWN` / `ROA_INVALID` | `roa.state == "valid"` / `"not-found"` / `"invalid"` |

BIRD spells the operators symbolically too — there are no `and` / `or` / `not`
keywords in BIRD 2 — and it keeps `~` / `!~` / `!=` / `<=` / `>=` shared with
this DSL.

The BIRD → lr translator is
[`crates/lr-cli/src/translate_bird_filter.rs`](../crates/lr-cli/src/translate_bird_filter.rs).
It rewrites `case` arms, passes `!~` through, strips the parameter and return
types of functions, and refuses to emit any filter whose body contains a
construct it cannot map faithfully. `crates/lr-cli/src/compat.rs` owns dialect
detection and the load path that routes a BIRD file through the translator.

---

## 9. References

- Source of truth:
  [`crates/lr-policy/src/filter/`](../crates/lr-policy/src/filter/) —
  `lexer.rs`, `parser.rs`, `ast.rs`, `eval.rs`, `bytecode.rs`,
  `peephole.rs`, `span.rs`.
- Operator precedence: `BinaryOp::precedence` in
  [`crates/lr-policy/src/filter/ast.rs`](../crates/lr-policy/src/filter/ast.rs).
- Limits: `MAX_EXPR_DEPTH` in `parser.rs`, `MAX_CALL_DEPTH` in `eval.rs`.
- Companion test:
  [`crates/lr-policy/tests/grammar_corpus.rs`](../crates/lr-policy/tests/grammar_corpus.rs).
- End-to-end recipe:
  [`docs/examples/filter_dsl_roa.md`](examples/filter_dsl_roa.md).
- BIRD compat translator:
  [`crates/lr-cli/src/translate_bird_filter.rs`](../crates/lr-cli/src/translate_bird_filter.rs).
- BIRD 2 grammar (reference):
  [`filter/config.Y`](https://gitlab.nic.cz/labs/bird/-/blob/master/filter/config.Y)
  and
  [`conf/cf-lex.l`](https://gitlab.nic.cz/labs/bird/-/blob/master/conf/cf-lex.l)
  in the BIRD source tree.
