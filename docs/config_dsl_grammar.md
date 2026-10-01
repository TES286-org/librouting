# The librouting native configuration DSL (`.lr`)

The `.lr` DSL is the configuration dialect `lr-daemon` reads when it is
selected with `--config-dialect lr` or recognised from the file content.
This document specifies that grammar, the block vocabulary and the
`lr-daemon config check` / `lr-daemon config to-dsl` commands. Read it
before writing a daemon configuration by hand, or before extending
`crates/lr-cli/src/config_dsl/`.

The fully commented reference file is
[`templates/daemon.lr`](../templates/daemon.lr); the grammar below is
derived from `crates/lr-cli/src/config_dsl/` (`lexer.rs`, `parser.rs`,
`emit.rs`). When the two disagree, the code wins.

The TOML dialect is the legacy input. It is deprecated and planned for
removal; `lr-daemon config to-dsl` converts a TOML file into the DSL.

Design ground rules:

- **One language for structure and policy.** Filter bodies are written
  directly between braces — no TOML string escaping, no `body = "..."`
  quoting games. The filter language itself
  ([`filter_dsl_grammar.md`](filter_dsl_grammar.md)) is embedded
  verbatim; its grammar does not change here.
- **Independent, not a BIRD replica.** BIRD's one-language model and
  brace/semicolon style are the inspiration; the block names, the key
  vocabulary and the semantics are lr's own. Keys keep their exact TOML
  spelling, so both frontends share one dispatch and cannot drift.
- **Declarative and non-Turing-complete.** Sections, typed key-value
  options (with duration/scale unit suffixes), named-object blocks and
  `include`. Deliberately absent: loops, arbitrary expressions,
  variables, side effects.
- **Fail closed where it matters.** Unknown keys inside the protocol
  and policy sections (`ospf`, `babel`, `ldp`, `damping`, `bgp.rpki`,
  `roa`, `filter`, `redistribute`, `aggregate`, `static.route`,
  `peer-template` and the policy bank) are hard errors (typo
  protection). Unknown keys under `bgp`, inside a `peer` block and at
  top level stay tolerated-with-warning for forward compatibility — the
  exact posture of the TOML frontend, because it is the same code.
  Unknown block names are always errors.

## Lexical structure

```ebnf
file         = { statement } ;
statement    = block | key_stmt | include_stmt ;

block        = block_name [ identity ] "{" { statement } "}" ;
key_stmt     = key_name value ";" ;
include_stmt = "include" string ";" ;

block_name   = ident ;
key_name     = ident ;
identity     = string | ident | number ;

value        = string | word | list ;
list         = "[" [ list_item { "," list_item } [ "," ] ] "]" ;
list_item    = string | word ;

word         = "true" | "false"          (* bool    *)
             | number unit               (* suffixed *)
             | number                    (* number  *)
             | ident ;                   (* bare word *)
ident        = word_char { word_char } ;
word_char    = alpha | digit | "_" | "-" | "." | ":" | "/" ;

number       = digit { digit } [ "." digit { digit } ] ;
unit         = "ms" | "us" | "s" | "m" | "h" | "k" | "M" ;

string       = '"' { string_char | escape } '"' ;
escape       = "\\" ? any character ? ;
comment      = "#" { ? any character except newline ? } ;
```

- Blank space (space, tab, CR, LF) and `#` comments are insignificant.
- A bare word is a maximal run of `word_char`; it is classified by
  shape, in this order: `true`/`false`, a number followed by a unit
  suffix, a number, otherwise an identifier. So `10.0.0.1`,
  `192.0.2.2:179`, `203.0.113.0/24` and `-4` are all bare words whose
  text is handed to the shared key dispatch unchanged. A block name or
  key name must classify as an identifier; `90s` is a suffixed number
  and cannot name a key.
- Unit suffixes are case-sensitive: `M` is mega, `m` is minutes, `H` is
  not a suffix at all. The suffix is *not* expanded by the lexer.
- Strings are double-quoted. `\"`, `\\`, `\n`, `\t` and `\r` are
  translated; any other escape is kept verbatim (backslash included),
  matching `daemon_config::unescape_toml_string` so the escape channel
  round-trips. A newline inside a string is kept. An unterminated
  string, or a backslash at the end of the file, is an error.
- A list element is a string or a bare word only: booleans and
  suffixed numbers are rejected, and lists do not nest.
- Any other character (for example `=`, `~`) is a token the grammar
  rejects outside a filter body — only filter syntax contains them.
  Inside a filter body the raw source is sliced, so anything goes.

## Blocks and sections

One DSL block corresponds to one TOML section or array-of-tables entry.
The block name, its optional identity argument and the TOML section it
lowers to:

| DSL block                       | identity lowers to | TOML section              |
| ------------------------------- | ------------------ | ------------------------- |
| `bgp { }`                       | —                  | `[bgp]`                   |
| `bgp { rpki { } }`              | —                  | `[bgp.rpki]`              |
| `ospf { }`                      | —                  | `[ospf]`                  |
| `ospf { area ID { } }`          | `id`               | `[[ospf.area]]`           |
| `ospf { interface NAME { } }`   | `name`             | `[[ospf.interface]]`      |
| `ospf { prefix-sid P { } }`     | `prefix`           | `[[ospf.prefix_sid]]`     |
| `ospf { mapping-server P { } }` | `prefix`           | `[[ospf.mapping_server]]` |
| `ospf { srv6-locator P { } }`   | `prefix`           | `[[ospf.srv6_locator]]`   |
| `babel { }`                     | —                  | `[babel]`                 |
| `babel { key { } }`             | —                  | `[[babel.key]]`           |
| `babel { interface NAME { } }`  | `name`             | `[[babel.interface]]`     |
| `static { }`                    | —                  | none (container only)     |
| `static { route P { } }`        | `prefix`           | `[[static.route]]`        |
| `ldp { }`                       | —                  | `[ldp]`                   |
| `ldp { interface NAME { } }`    | `name`             | `[[ldp.interface]]`       |
| `ldp { targeted ADDR { } }`     | `address`          | `[[ldp.targeted]]`        |
| `ldp { bind P { } }`            | `prefix`           | `[[ldp.bind]]`            |
| `damping { }`                   | —                  | `[damping]`               |
| `peer NAME { }`                 | `name`             | `[[peer]]`                |
| `peer-template NAME { }`        | template name      | `[peer-template.NAME]`    |
| `prefix-list NAME { }`          | `name`             | `[[prefix-list]]`         |
| `as-path-list NAME { }`         | `name`             | `[[as-path-list]]`        |
| `community-list NAME { }`       | `name`             | `[[community-list]]`      |
| `route-map NAME { }`            | `name`             | `[[route-map]]`           |
| `filter NAME { }`               | `name`             | `[[filter]]`              |
| `roa { }`                       | —                  | `[[roa]]`                 |
| `redistribute { }`              | —                  | `[[redistribute]]`        |
| `aggregate { }`                 | —                  | `[[aggregate]]`           |

- The identity argument is sugar for the identity key: `peer "core-1"`
  behaves exactly as if `name "core-1";` were the first statement of the
  block. An explicit inner key of the same name overrides it.
- The dotted section vocabulary of TOML (`ospf.prefix_sid`) becomes
  nesting or kebab-case block names; the _keys_ inside keep their exact
  TOML spelling (`hello_interval_ms`, `origin_as`, `match_prefix`, …).
  This is what makes one shared dispatch possible.
- Every block may appear more than once. A single-section block
  (`bgp`, `ospf`, `babel`, `ldp`, `damping`, `bgp.rpki`) merges its keys
  in file order, exactly like repeated TOML tables; an array block
  (`peer`, `roa`, `route-map`, …) appends a new entry each time, so two
  `route-map "x"` blocks are two entries of one map.
- Sub-blocks (`area`, `interface`, `key`, `rpki`, `route`, …) are only
  valid inside their parent block; at top level they are errors.
- `static` is a container for its `route` blocks: it has no TOML section
  and no keys of its own, so a key directly inside it is warned about
  and ignored.
- `peer-template` needs a non-empty name without a `.`; `filter` needs a
  name (`DaemonConfig::finalize` rejects an unnamed filter);
  `babel { key { } }` takes no identity.
- A block statement is recognised by lookahead: `name {` or
  `name STRING|IDENT|NUMBER {`. Anything else is a `key value;`
  statement.

## Keys and values

Every key of the TOML schema is accepted verbatim:

```lr
bgp {
    local_as 64512;
    peer_as 64513;
    router_id 10.0.0.1;
    hold_time 90s;                      # unit suffix: 90 seconds
    mp_families [ipv4-unicast, ipv6-unicast];
    install_kernel true;
    networks [203.0.113.0/24, 198.51.100.0/24];
}
```

Value lowering to the shared dispatch:

| DSL value           | string handed to the dispatch         |
| ------------------- | ------------------------------------- |
| `string`            | unescaped content                     |
| `123` / `-4`        | decimal text                          |
| `1.5`               | decimal text (float keys)             |
| `true` / `false`    | `true` / `false`                      |
| bare ident          | the token text                        |
| `[a, b]`            | `["a","b"]` (TOML array text form)    |
| `90s` / `5m` / `2h` | expanded seconds (duration keys only) |
| `100ms`             | expanded milliseconds (duration keys) |
| `50us`              | expanded microseconds (RTT keys only) |
| `100k` / `2M`       | expanded count (scale keys only)      |

Top-level keys select the protocol set: `protocol bgp;` (one name) or
`protocol "bgp,ospf";` (quoted list) or `protocols [bgp, ospf];` (list
form). Omitting them keeps BGP.

### Unit suffixes

The whitelist lives in the parser, keyed by _(section, key)_ — the same
key name may carry different units in different sections
(`hello_interval` is seconds under `ospf`, but an alias of
`hello_interval_ms` inside a `babel interface` block):

- **Seconds** (`s` ×1, `m` ×60, `h` ×3600): `hold_time`,
  `graceful_restart_time`, `llgr_stale_time`, `llgr_max_stale_time`,
  `grace_period`, `helper_grace_cap`, `dead_interval`, `hello_interval`
  (OSPF — hello/dead intervals are seconds per RFC 2328),
  `keepalive_time`, `link_hold_time`, `targeted_hold_time`,
  `decay_interval_s`.
- **Milliseconds** (`ms` ×1, `s` ×1000): `bfd_min_rx_ms`, `bfd_min_tx_ms`,
  `gr_reconnect_ms`, `gr_recovery_ms`, `hello_interval_ms`,
  `update_interval_ms`, and the `hello_interval` / `update_interval`
  aliases inside `babel interface` blocks.
- **Microseconds** (`us` ×1, `ms` ×1000): `rtt_min`, `rtt_max` (Babel RTT,
  RFC 8966 §3.4.2).
- **Scale** (`k` ×1000, `M` ×1_000_000): `max_prefixes`,
  `add_path_max_paths`, `label_max`, `label_min`.

A suffixed literal on a key outside the whitelist is a hard parse error
naming the key — the DSL never guesses a unit.

## Filter blocks

`filter NAME { ... }` embeds the filter DSL (a BIRD-syntax subset, see
[`filter_dsl_grammar.md`](filter_dsl_grammar.md)) natively:

```lr
filter customer-in {
    if roa.state == "not-found" then reject with "roa-unknown";
    if net ~ [ 203.0.113.0/24 ] then accept;
    reject;
}
```

The body is captured **verbatim** — the exact source text between the
braces is what `FilterSpec::body` stores, and what `config to-dsl`
re-emits. Brace matching rides the token stream, so a `}` inside `"..."`
or after `#` does not close the block and filter syntax needs no
escaping. Filter syntax is not validated at config-parse time: the body
reaches the filter compiler at daemon startup, exactly where a TOML
`body = "..."` string would, keeping both frontends byte-for-byte
comparable. `finalize` requires the name and a non-empty body.

## Includes

```lr
include "peers/lab.lr";
```

- The path must be a quoted string; `include` takes no other form.
- A relative path resolves against the directory of the _including_
  file; an absolute path is used as-is.
- An include is spliced where it appears, not expanded up front: an
  `include` inside `bgp { }` contributes its statements to that block,
  and the parser keeps a per-file display name and line so diagnostics
  name the real file and line.
- A path containing `*`, `?` or `[` is a glob: the parent directory is
  enumerated, and every matching file is spliced in lexicographic
  order. Subdirectories are skipped. A glob that matches nothing in an
  existing directory records a warning
  (`include 'peers/*.lr' matched 0 files`) and parsing continues; a
  directory that cannot be read is an error.
- Cycle detection (via canonical paths) and an include stack capped at 16
  frames fail closed.

## Name resolution

`DaemonConfig::finalize` is the shared post-parse pass that startup,
reload and `config check` all run. It synthesises the legacy single peer
from `peer_addr`/`listen_addr`, resolves every `extends` chain against
`peer-template` blocks (unknown names and cycles are errors) and checks
each section's invariants (duplicate filter and ROA names, OSPF areas,
Babel RTT bounds and key scopes, static routes, redistribution pipes,
aggregates).

The references between policy objects are resolved later, when the
daemon builds its policy set: `daemon_policy::build_policy_set` resolves
route-map → prefix-list / as-path-list / community-list,
`daemon_policy::bind_peer_policies` resolves peer → route-map,
`daemon_policy::build_filters` compiles every filter body, and the
startup wiring in `daemon.rs` resolves peer → filter. All of them fail
closed. `config check` does not run these steps (see below).

## The `config` subcommands

### `lr-daemon config check [--dialect lr|toml|bird|frr] <file>`

Loads the file through `daemon_config::load_config_file` — the same
entry point startup and reload use — and then runs
`DaemonConfig::finalize`. It validates:

- the dialect (from `--dialect`/`--config-dialect`, else recognised from
  the content);
- the whole block and key schema, including unknown block names, unit
  suffixes and `include` resolution;
- everything `finalize` checks (peer-template inheritance, duplicate
  names, per-section invariants);
- the parse-warning list, which it reports rather than rejects.

It then prints the resolved IR: the dialect, the protocol set, the peer
and template counts, originated and labelled networks, the policy
counts, the per-protocol counts and every warning. When the resolved
dialect is `toml` it also prints the deprecation notice.

It does **not** compile filter bodies and does not resolve
route-map → list or peer → filter / route-map references: those are
checked when the daemon builds its policy set, so a config that passes
`config check` can still fail at startup.

Exit codes:

| Code | Meaning                                     |
| ---- | ------------------------------------------- |
| 0    | Loads and finalizes; warnings are printed   |
| 1    | Read, parse or `finalize` failure           |
| 2    | Usage error (bad arguments or `--dialect`)  |

Content detection keys on block headers only the DSL opens (`bgp {`,
`peer "x" {`, …) and on `.lr` include lines. A file whose top-level
statements are only `filter` blocks is ambiguous with a BIRD file and
needs `--dialect lr`.

### `lr-daemon config to-dsl [--dialect lr|toml|bird|frr] <file>`

Loads the file the same way, but deliberately does **not** finalize: the
converter works on the pre-finalize IR, because finalization merges peer
templates and would destroy source-level structure. It prints the
equivalent `.lr` program on stdout.

- **Deterministic**: one fixed block order (top-level keys, `bgp` with
  its nested `rpki`, `peer`s in IR order, `peer-template`s sorted by
  name, the policy bank, `filter`s, `roa`, `redistribute`, `aggregate`,
  `static`, `ospf`, `babel`, `ldp`, `damping`); keys inside a block in
  schema order; unset fields omitted. Rendering the same IR twice is
  byte-identical.
- **Never silent**: it refuses with exit code 1 and writes nothing to
  stdout when the IR cannot be represented faithfully. Refusals are:
  any parse warning (the emitted file would mean less than the input); a
  filter with a `description`; a filter without a body; and a list
  element that cannot round-trip through the array channel (empty, or
  containing a comma, a quote, a backslash or surrounding whitespace).
- **Round-trip property**: `parse(TOML) → to-dsl → parse(.lr)` produces
  an IR equal (`PartialEq`) to the original, for every file the
  converter accepts. `config_path`, `config_dialect` and `warnings` are
  load bookkeeping and are never emitted.

Exit codes are the same three as `config check`: 0 on success, 1 when
the load or the conversion fails, 2 for a usage error. `to-dsl` stays
silent about the TOML deprecation notice, because it is the migration
tool itself.

## Example

The active statements of [`templates/daemon.lr`](../templates/daemon.lr),
which produce the same IR as
[`templates/daemon.toml`](../templates/daemon.toml):

```lr
bgp {
    local_as 64512;
    peer_as 64513;
    router_id "10.0.0.1";
    peer_addr "192.0.2.2:179";
    local_address "192.0.2.1";
    hold_time 90s;
    graceful_restart_time 120s;
    networks ["203.0.113.0/24"];
}

prefix-list "customer-space" {
    prefix "203.0.113.0/24";
}

route-map "to-customer" {
    entry 10;
    match_prefix "customer-space";
    permit true;
}

route-map "to-customer" {
    entry 20;      # everything else stays internal
    permit false;
}
```
