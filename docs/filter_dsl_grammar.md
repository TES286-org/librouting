# Filter DSL — formal grammar

This document is the canonical reference for the librouting filter DSL
syntax. It is the contract between the implementation
(`crates/lr-policy/src/filter/`, hand-rolled lexer + Pratt parser +
tree-walking evaluator and bytecode VM) and every consumer of the DSL:
the `[[filter]]` TOML body, the FFI `lr_filter_compile` entry point,
the BIRD compat translator (`crates/lr-cli/src/compat.rs`) and the
tutorial snippets pinned by `crates/lr-tests/tests/tutorial_snippets.rs`.

The grammar below is derived directly from the source. When the prose
and the source disagree, the source wins; please open a PR that fixes
whichever is wrong. The companion test
`crates/lr-policy/tests/grammar_corpus.rs` pins every example in this
file through `lr_policy::filter::compile`, so a doc/source drift fails
CI rather than shipping.

The DSL targets a subset of BIRD 2's `filter` language expressive
enough for production import/export policy. See
[`docs/examples/filter_dsl_roa.md`](examples/filter_dsl_roa.md) for an
end-to-end recipe and [`docs/COMPAT.md`](COMPAT.md) for the BIRD/FRR
translation surface.

---

## 1. Lexical structure

### 1.1 Character set

The lexer operates on `&[u8]` and is byte-oriented. Source files are
UTF-8; multi-byte sequences are passed through verbatim inside string
literals and identifiers do not accept non-ASCII bytes (the identifier
rule below is ASCII-only, matching BIRD).

### 1.2 Whitespace and comments

```ebnf
whitespace := ? ASCII space (U+0020) ? | ? ASCII tab (U+0009) ?
           | ? ASCII CR (U+000D) ? | ? ASCII LF (U+000A) ? ;
comment    := '#' { ? any byte except ASCII LF ? } ? ASCII LF ? ;
```

Whitespace and `#` line comments are dropped at lex time. There is no
block comment form.

### 1.3 Identifiers and keywords

```ebnf
ident     := ident_start { ident_continue } ;
ident_start   := "A" | "B" | … | "Z" | "a" | "b" | … | "z" | "_" ;
ident_continue := ident_start | "0" | "1" | … | "9" ;
```

The reserved words below are recognised in identifier position and
never lex as `Ident`:

| Keyword     | Role                                                            |
| ----------- | --------------------------------------------------------------- |
| `if`        | conditional statement                                           |
| `then`      | conditional separator                                            |
| `else`      | conditional alternative                                          |
| `let`       | variable declaration (mutable)                                  |
| `var`       | alias of `let`                                                  |
| `accept`    | terminal statement                                               |
| `reject`    | terminal statement                                               |
| `with`      | `reject with EXPR` form                                         |
| `case`      | switch statement                                                 |
| `default`   | catch-all arm in `case`                                          |
| `true`      | boolean literal                                                 |
| `false`     | boolean literal                                                 |
| `net`       | route field                                                     |
| `proto`     | route field                                                     |
| `source`    | route field                                                     |
| `bgp`       | route field prefix                                              |
| `roa`       | route field prefix                                               |
The identifier `function` is recognised contextually at the top of a
filter body as a function declaration — it is not a reserved word and
may still be used as a variable name inside expressions. The same
applies to `return` (a contextual keyword recognised only at statement
position, never inside an expression).

### 1.4 Literals

```ebnf
integer  := ["-"] dec_digit { dec_digit } ;
dec_digit := "0" | "1" | … | "9" ;
string   := '"' { char_escape | unescaped } '"' ;
unescaped := ? any byte except '"' (U+0022), '\\' (U+005C) or ASCII LF ? ;
char_escape := "\\\""
            | "\\\\"
            | "\\n"
            | "\\t"
            | "\\r"
            | "\\0" ;
ip       := ipv4 | ipv6 ;   (* RFC 4001 text form *)
prefix   := ip "/" dec_digit { dec_digit } ;   (* prefix length 0..=128 *)
```

Notes:

* Negative integers are lexed as `Minus` followed by `Int`; the parser
  folds them via `UnaryOp::Neg`. The lexer itself never produces a
  negative `Int` token.
* The lexer is greedy on numeric input: it collects the whole run of
  digits, `.`, `:`, hex digits and `/` and then disambiguates the
  result as `Prefix` (when `from_str` succeeds), bare `Ip`, or `Int`.
  Community pairs `asn:value` are detected contextually — see
  §3.2 — and the lexer stops the run at the `:` so a pair stays two
  tokens.
* String literals do not accept `\xHH` hex escapes. Unknown escapes
  are fatal lexer errors.
* AS numbers are not first-class literals: they are plain integers
  whose value the evaluator narrows to `Asn` (a `u32` wrapper) at the
  call site. An integer literal outside `0..=u32::MAX` used in ASN
  context is a runtime `TypeMismatch`, not a parse error.

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

The lexer prefers the longest match: `==` beats `=`, `=>` beats `=`,
`!=` beats `!`, `!~` beats `!`, `<=` beats `<`, `<<` beats `<`, etc.
The bare `?` byte is accepted as a synonym of `_` (the AS-path
wildcard); it is kept only for completeness and is unused in real
filters. Every other byte is a fatal `UnexpectedChar` lexer error.

### 1.6 Token summary

The lexer produces a flat `Vec<Token>` terminated by `Eof`. Every
token carries its 1-indexed line and column for diagnostics. The full
enum lives at
[`crates/lr-policy/src/filter/lexer.rs`](../crates/lr-policy/src/filter/lexer.rs)
(`TokenKind`).

---

## 2. Grammar

The grammar below uses ISO/IEC 14977 EBNF. Concatenation is implicit,
`|` is alternation, `[ … ]` is optionality, `{ … }` is repetition
(zero or more), `( … )` is grouping, `"…"` is a terminal string.

A *filter* is the top-level production. The lexer is invoked once on
the whole body; the parser consumes the resulting token stream through
[`Parser::parse_filter`](../crates/lr-policy/src/filter/parser.rs).

```ebnf
filter   := { function_decl } filter_body ;
function_decl := "function" ident "(" [ param_list ] ")" [ "=>" ident ] block ;
param_list := ident { "," ident } ;
filter_body := block | stmt_list ;
stmt_list := stmt { stmt } ;
block    := "{" [ stmt_list ] "}" ;
```

### 2.1 Statements

```ebnf
stmt := "if" expr "then" stmt [ "else" stmt ]
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
case_arm := ( expr { "," expr } | "default" ) "=>" [ stmt ] [ ";" ] ;
lvalue   := route_field | ident ;
```

Notes:

* `if`/`else` is a statement, not an expression — the DSL has no
  ternary. The `else` arm parses another `stmt`, so `else if` chains
  work via right-nesting.
* `case` arms accept a comma-separated list of patterns sharing one
  body. A bare `default` arm carries no pattern. The body of an arm is
  a single statement; a brace-delimited block is the usual form,
  parsed as `Stmt::Block`. An optional trailing `;` is allowed after
  the arm body.
* `accept` and `reject` terminate the filter immediately. A bare
  `reject;` carries no reason; `reject "bad";` and
  `reject with EXPR;` are equivalent and produce a reason string at
  evaluation time.
* `return;` and `return EXPR;` exit the enclosing *user-defined
  function*. At filter top level `return` terminates the filter
  without a verdict (Fallthrough). A function body that falls off the
  end yields `false` (BIRD parity).
* `let`/`var` introduce a new variable in the current scope. A bare
  `name = expr;` *reassigns* an existing variable — using `=` on an
  undeclared name is a runtime `AssignToUndefined` error (BIRD
  semantics: every variable must be declared first).
* `lvalue = expr;` and `lvalue += expr;` cover route-field mutation
  (see §3.4) and variable reassignment. The `+=` form is only valid
  on the three community-set fields; assigning a scalar with `+=`
  fails at parse time as `ReadOnlyField`.

### 2.2 Expressions

Expressions use a Pratt parser driven by the precedence table in §4.
All binary operators are left-associative; there are no
right-associative operators in the language (no `**` exponent).

```ebnf
expr      := or_expr ;
or_expr   := and_expr { "||" and_expr } ;
and_expr  := eq_expr { "&&" eq_expr } ;
eq_expr   := cmp_expr { ( "==" | "!=" ) cmp_expr } ;
cmp_expr  := bitor_expr { ( "<" | "<=" | ">" | ">=" | "~" | "!~" ) bitor_expr } ;
bitor_expr:= bitxor_expr { "|" bitxor_expr } ;
bitxor_expr := bitand_expr { "^" bitand_expr } ;
bitand_expr:= shift_expr { "&" shift_expr } ;
shift_expr:= add_expr { ( "<<" | ">>" ) add_expr } ;
add_expr  := mul_expr { ( "+" | "-" ) mul_expr } ;
mul_expr  := unary { ( "*" | "/" | "%" ) unary } ;
unary     := ( "!" | "-" ) unary | postfix ;
postfix  := primary { "." ident [ "(" [ arg_list ] ")" ] } ;
primary  := literal
          | ident [ "(" [ arg_list ] ")" ]
          | route_field
          | "[" [ set_item { "," set_item } ] "]"
          | "(" expr ")"
          | "_" ;
arg_list := expr { "," expr } ;
literal := integer | string | "true" | "false" | ip | prefix_range ;
prefix_range := prefix [ "{" range "}" ] ;
range   := integer [ "," integer ] ;
```

Notes:

* `defined(EXPR)` and `exists(EXPR)` are parsed as ordinary calls and
  then reified as the structural `Expr::Defined` node — the argument
  is left unevaluated so the evaluator can probe presence without
  triggering `UndefinedVar`. Both take exactly one argument; passing
  any other count fails at parse time as `BadArgCount`.
* `prefix { range }` — e.g. `10.0.0.0/8{16,24}` — is BIRD's
  prefix-set range syntax. The single-integer form `{N}` is sugar
  for `{N,N}` (exact match at length `N`). Out-of-range bounds
  (`> 255`) are rejected at parse time as `InvalidPrefixRange`. The
  range form is accepted both inside set literals and as a bare
  expression.
* `_` is BIRD's AS-path separator wildcard. It is lifted to a
  `Var("_")` so a future evaluator extension can recognise it inside
  AS-path patterns. The current matcher treats `~` on an AS-path as
  flat set-membership — `[ 64500, 64502 ]` means "any AS in the path
  is one of these" — so `_` does not yet carry semantic weight in a
  set literal. The token exists for forward compatibility with a
  future BIRD-style regex matcher.
* Set literals accept the heterogeneous element forms enumerated in
  §3.3. A set literal may be empty (`[]`).
* Method calls are pure syntactic sugar for
  `Expr::Method { receiver, method, args }`. They are dispatched on
  the *route field* of the receiver at evaluation time; calling a
  method on a non-route-field expression is a runtime
  `TypeMismatch`.

### 2.3 Set items

A set literal element is one of:

```ebnf
set_item := prefix_range      (* a prefix, optionally ranged *)
          | integer            (* a bare AS number, port, etc. *)
          | comm_pair          (* "asn:value" RFC 1997 pair *)
          | comm_pair_wild     (* "asn:*" | "*:value" | "*:*"   *)
          | large_comm         (* "g:d1:d2" RFC 8097 triple    *)
          | ext_comm           (* "(rt, asn|ip, local)"       *)
          | "_"                (* AS-path wildcard            *)
          | "(" expr ")" ;     (* grouped scalar              *)
comm_pair    := integer ":" integer ;
comm_pair_wild := ( integer | "*" ) ":" ( integer | "*" ) ;
large_comm   := integer ":" integer ":" integer ;
ext_comm     := "(" ext_kind "," ext_global "," integer ")" ;
ext_kind     := "rt" | "target" | "ro" | "soo" | "origin" ;
ext_global   := integer | ip ;    (* 4-octet AS or IPv4 administrator *)
```

The parser dispatches on the leading tokens:

* A leading `Int` followed by `:` `Int` `:` `Int` is a large community
  triple (RFC 8097). Components are validated to fit `u32`.
* A leading `Int` or `*` followed by `:` is a community pair or pair
  wildcard (`asn:*`, `*:val`, `*:*`). The value component must fit
  `u16`. Wildcards apply only to community pairs; large-community
  triples and extended-community tuples require concrete integers in
  every field.
* A leading `(` followed by `rt`/`ro`/`soo` (or their long forms)
  is an extended-community tuple. The local part must be a plain
  integer (`0..=u16::MAX`); there is no `*` wildcard for it.
  IPv6 administrators are rejected: extended communities have no
  IPv6 form (use RFC 9256 large communities for that).
* Anything else falls through to `parse_expr`, so a parenthesised
  scalar `( 42 )` is allowed but pointless — it parses as a `Set`
  containing one `Int`.

### 2.4 Route fields

```ebnf
route_field := "net"
             | "proto"
             | "source"
             | "bgp" "." bgp_field
             | "roa" "." "state" ;
bgp_field := "local_pref" | "med" | "next_hop"
           | "as_path" | "communities"
           | "ext_communities" | "large_communities"
           | "origin" ;
```

The settable subset (allowed on the left-hand side of `=`) is:
`bgp.local_pref`, `bgp.med`, `bgp.next_hop`, `bgp.communities`,
`bgp.ext_communities`, `bgp.large_communities`.

The `+=` form is restricted further: only the three community-set
fields (`bgp.communities`, `bgp.ext_communities`,
`bgp.large_communities`) accept `+=`. Assigning with `+=` to a scalar
field (e.g. `bgp.local_pref += 1;`) fails at parse time as
`ReadOnlyField`.

The complete field reference lives in §5.

---

## 3. Semantics

### 3.1 Filter structure

A filter is the optional function declarations followed by a body.
The body is either a brace-delimited block (`{ … }`) or a bare
statement list terminated by end-of-input. An empty body is a parse
error (`EmptyFilterBody`) — every filter must do at least one thing.

If the body falls off the end without hitting `accept` or `reject`,
the filter returns `Fallthrough` — the route is treated as if no
filter matched. The daemon's import hook chain treats Fallthrough as
"continue to the next hook"; the daemon's export hook chain treats
Fallthrough as "deny" (BIRD parity).

### 3.2 Built-in functions

The parser accepts any `ident "(" args ")"` as a call. At compile
time the call validator (`validate_calls` in `parser.rs`) rejects
calls that name neither a built-in nor a declared user function. The
built-in set is:

| Name     | Arity | Argument types                                  | Returns  |
| -------- | ----- | ----------------------------------------------- | -------- |
| `len`    | 1     | `as-path` \| `community-set` \| `string` \| `set` | `int`    |
| `delete` | 2     | `set-like`, `pattern-set`                       | set-like |
| `filter` | 2     | `set-like`, `pattern-set`                       | set-like |
| `empty`  | 1     | any set-like                                    | `bool`   |
| `count`  | 1     | any set-like                                    | `int`    |
| `first`  | 1     | `as-path`                                       | `int`    |
| `last`   | 1     | `as-path`                                       | `int`    |

`delete(set, patterns)` returns a copy of `set` with every element
matching any pattern in `patterns` removed. `filter(set, patterns)` is
the dual: only matching elements survive. Both return *empty results
drop the attribute* — assigning to `bgp.communities` produces a route
with no community attribute at all, not a community attribute with an
empty list.

### 3.3 Route-field methods

Method dispatch is keyed on `(RouteFieldKind, method_name)`:

| Receiver               | Method       | Args  | Effect                                            |
| ---------------------- | ------------ | ----- | ------------------------------------------------- |
| `bgp.as_path`          | `prepend`    | `int` | Returns a new AS_PATH with the AS prepended       |
| `bgp.communities`      | `add`        | set   | Returns the union                                 |
| `bgp.communities`      | `delete`     | set   | Returns the difference                            |
| `bgp.communities`      | `filter`     | set   | Returns the intersection                          |
| `bgp.as_path`          | `delete`     | set   | Removes matching ASes                             |
| `bgp.as_path`          | `filter`     | set   | Keeps only matching ASes                          |
| `bgp.large_communities`| `add` / `delete` / `filter` | set | Same shape as `bgp.communities`        |
| `bgp.ext_communities`  | `add` / `delete` / `filter` | set | Same shape as `bgp.communities`        |

Methods are pure on the route attribute: they return a new value but
do not mutate the route. To write the result back, assign it:
`bgp.communities = delete(bgp.communities, [ 64512:* ]);`.

### 3.4 The `~` and `!~` operators

The match operator `~` is overloaded on the type of its left-hand
side:

| LHS type           | RHS                       | Semantics                                                   |
| ------------------ | ------------------------- | ----------------------------------------------------------- |
| `prefix`           | `prefix-set`              | RFC 4271 sub-prefix match with optional `{ge,le}` range     |
| `as-path`          | `set` of `int`            | Set membership: any AS in the path is in the set             |
| `community-set`    | `pattern-set`             | Set membership with wildcard `asn:*` / `*:val` / `*:*`      |
| `string`           | `string`                 | Equality                                                    |
| `int`              | `set` of `int`            | Set membership                                              |
| `ip`               | `set` of `ip`            | Set membership                                              |

The AS-path `~` is currently a flat membership test, not BIRD's
AS-path regex (no `_` separator, no `*` any-AS, no `..` range). A
future D14 follow-up may add the regex form once the parser and the
evaluator agree on the pattern AST — until then, write
`bgp.as_path ~ [ 64500, 64502 ]` to mean "any AS in the path is one
of these".

`!~` is the negation of `~` for every overload. Both share precedence
level 4 (see §4).

### 3.5 Truthiness

`if` and `&&`/`||` apply the following truthiness rules:

| Type              | Truthy when                          |
| ----------------- | ------------------------------------ |
| `bool`            | the value is `true`                  |
| `int`             | non-zero                             |
| `string`          | non-empty                            |
| `ip`, `prefix`, `asn`, `proto`, `roa-state` | always (presence is truth) |
| `as-path`, `*communities`, `set` | non-empty                  |

The "presence is truth" rule for `ip`/`prefix`/`asn`/`proto`/`roa-state`
is what makes `if bgp.next_hop then …` work without an explicit
`defined()` check.

---

## 4. Operator precedence and associativity

Precedence is encoded in
[`BinaryOp::precedence`](../crates/lr-policy/src/filter/ast.rs). Higher
binds tighter. All operators are left-associative.

| Level | Operators                                                       | Category        |
| ----- | --------------------------------------------------------------- | --------------- |
| 10    | `*`  `/`  `%`                                                   | multiplicative  |
| 9     | `+`  `-`                                                        | additive        |
| 8     | `<<`  `>>`                                                      | shift           |
| 7     | `&`                                                             | bitwise AND     |
| 6     | `^`                                                             | bitwise XOR     |
| 5     | `|`                                                             | bitwise OR      |
| 4     | `<`  `<=`  `>`  `>=`  `~`  `!~`                                 | comparison/match|
| 3     | `==`  `!=`                                                      | equality        |
| 2     | `&&`                                                            | logical AND     |
| 1     | `||`                                                            | logical OR      |

Unary `!` and `-` bind tighter than every binary operator (they
apply before any binary). The parser's `parse_unary` is the only
funnel that descends past `parse_binary`, so `!a && b` parses as
`(!a) && b` and `-a * b` parses as `(-a) * b`.

The Pratt loop is in
[`Parser::parse_binary`](../crates/lr-policy/src/filter/parser.rs). The
right-associative table is currently empty (`BinaryOp::right_associative`
always returns `false`); adding `**` would flip one row.

---

## 5. Route field reference

The complete list of route fields. *Settable* fields accept `=`; the
`+=` column lists fields accepting the append form.

| Field                    | Type              | Settable | `+=` | Notes                                              |
| ------------------------ | ----------------- | :------: | :--: | -------------------------------------------------- |
| `net`                    | `prefix`          | no       | no   | The route's prefix. Read-only.                    |
| `proto`                 | `protocol`        | no       | no   | One of `Bgp`, `Ospfv2`, `Ospfv3`, `Babel`, `Static`, … |
| `source`                | `int`             | no       | no   | Protocol-source id (kernel-dependent).             |
| `bgp.local_pref`        | `int`             | yes      | no   | BGP LOCAL_PREF (RFC 4271 §5.1.5).                  |
| `bgp.med`               | `int`             | yes      | no   | BGP MULTI_EXIT_DISC.                              |
| `bgp.next_hop`          | `ip`              | yes      | no   | BGP NEXT_HOP.                                     |
| `bgp.as_path`           | `as-path`         | no       | no   | BGP AS_PATH. Mutate via `.prepend(int)`.          |
| `bgp.communities`       | `community-set`   | yes      | yes  | RFC 1997 32-bit communities.                       |
| `bgp.ext_communities`   | `ext-community-set`| yes     | yes  | RFC 4360 transitive 8-byte communities.           |
| `bgp.large_communities` | `large-community-set` | yes  | yes  | RFC 8097 12-byte communities.                     |
| `bgp.origin`            | `int`             | no       | no   | BGP ORIGIN (0=IGP, 1=EGP, 2=INCOMPLETE).           |
| `roa.state`             | `roa-state`       | no       | no   | RFC 6811 outcome: `valid` / `invalid` / `not-found`. |

`roa.state` is read-only because the validation outcome is computed
once per route at import time against the live `RoaStore`. The
`roa.state` value reflects the cache state at evaluation time — if the
RTR client has applied a delta since the filter was compiled, the new
state is observed (the `FilterContext` reads the live snapshot, not a
captured one).

---

## 6. Limits

Two compile-time limits bound the parser and evaluator:

| Limit              | Value | Where defined                          | Effect when exceeded               |
| ------------------ | ----- | -------------------------------------- | --------------------------------- |
| `MAX_EXPR_DEPTH`   | 108   | `crates/lr-policy/src/filter/parser.rs`| Parse error `RecursionLimitExceeded` |
| `MAX_CALL_DEPTH`   | 64    | `crates/lr-policy/src/filter/eval.rs`   | Runtime error `CallDepthExceeded` |

The depth bound exists because the parser is recursive-descent and a
deeply nested input (e.g. thousands of unclosed `[`) would overflow
the thread stack — the nightly `filter_parser` fuzz target found a
3 911-byte crashing input before the bound was added. The bound is
shared by the parser and the evaluator (the AST is bounded in height
by the parser, so the evaluator's recursive walk is also bounded).

---

## 7. Worked examples

Every example below is pinned by
`crates/lr-policy/tests/grammar_corpus.rs` — the test compiles the
body through `lr_policy::filter::compile` and asserts `Ok` (or `Err`
where noted). If the grammar changes, the test breaks first.

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

The `=> bool` after the parameter list is a *documentation-only*
return-type annotation — the DSL is dynamically typed, so the
annotation is parsed but never enforced. The `=>` token is the same
one used by `case` arms; there is no `->` form in the DSL.

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

The `~` operator on an AS-path is currently a flat set-membership test:
the route matches if any AS in its AS_PATH is one of the listed values.
BIRD-style AS-path regex (with the `_` separator wildcard) is not yet
implemented in the matcher — see §3.5.

### 7.9 Extended-community tuple

```text
bgp.ext_communities += [ (rt, 64512, 100) ];
if bgp.ext_communities ~ [ (rt, 64512, 100) ] then accept;
reject;
```

The local part of an extended community is always a concrete integer;
there is no `*` wildcard form for the local part. Matching is exact
record membership — every field (kind, subtype, global, local) must
match byte-for-byte.

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
`Err(ParseError { kind: RecursionLimitExceeded, … })` because the
nesting exceeds `MAX_EXPR_DEPTH = 108`. (The exact 3 911-byte crasher
from the nightly fuzzer is pinned by
`crates/lr-policy/tests/filter_corpus.rs::nightly_nested_set_crasher_is_now_rejected_not_fatal`.)

Note: the parser also collapses any lexer error into `EmptyFilterBody`
because `Lexer::tokenize` returns `Err` as a single failure and
`Parser::new` substitutes a one-element `[Eof]` token stream — a
typo in a string escape therefore surfaces as "filter body is empty"
rather than "lexer error at line N col M". The companion corpus test
pins this current behaviour; a follow-up may surface the original
`LexerError` for better diagnostics.

---

## 8. Relationship to BIRD

The DSL is intentionally a *subset* of BIRD 2's `filter` grammar.
The major divergences are:

| Construct                  | BIRD                  | librouting                |
| -------------------------- | --------------------- | ------------------------- |
| Boolean operators          | `&&`, `\|\|`, `!`     | identical                 |
| Equality / assignment      | `=` / `:=`            | `==` / `=`                |
| Match / non-match          | `~` / `!~`            | identical                 |
| Boolean keywords           | `and`, `or`, `not`    | not supported (use symbols) |
| `case` arm separator       | `:`                   | `=>`                      |
| `case` else arm            | `else:`               | `default =>`              |
| `case` range arm `a..b:`   | supported             | not supported (fail-closed) |
| `define` constant          | textual substitution  | textual substitution       |
| Function declaration        | `function name(...) int { … }` | `function name(...) => int { … }` |
| `switch` keyword           | `switch`              | `case`                    |

The BIRD → lr translator lives at
[`crates/lr-cli/src/compat.rs`](../crates/lr-cli/src/compat.rs) and is
the source of truth for the table above. The `!~` operator and the
`case` statement are the most recent (D14.5 + D14.6) additions;
the translator now passes them through verbatim instead of fail-closing
on them.

---

## 9. References

* Source of truth: [`crates/lr-policy/src/filter/`](../crates/lr-policy/src/filter/)
  — `lexer.rs`, `parser.rs`, `ast.rs`, `eval.rs`, `bytecode.rs`.
* Operator precedence: `BinaryOp::precedence` in
  [`crates/lr-policy/src/filter/ast.rs`](../crates/lr-policy/src/filter/ast.rs).
* Limits: `MAX_EXPR_DEPTH` in `parser.rs`, `MAX_CALL_DEPTH` in
  `eval.rs`.
* Companion test: [`crates/lr-policy/tests/grammar_corpus.rs`](../crates/lr-policy/tests/grammar_corpus.rs).
* End-to-end recipe: [`docs/examples/filter_dsl_roa.md`](examples/filter_dsl_roa.md).
* BIRD compat translator: [`crates/lr-cli/src/compat.rs`](../crates/lr-cli/src/compat.rs).
* BIRD 2 grammar (reference): [`filter/config.Y`](https://gitlab.nic.cz/labs/bird/-/blob/master/filter/config.Y)
  and [`conf/cf-lex.l`](https://gitlab.nic.cz/labs/bird/-/blob/master/conf/cf-lex.l)
  in the BIRD source tree.
