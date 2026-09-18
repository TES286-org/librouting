# The librouting native configuration DSL (`.lr`)

ROADMAP-v3 D16 Phase 2 (GitHub #18). This document specifies the
declarative configuration grammar: the file format the daemon will
accept natively as `--config-dialect lr`, and the output format of
`lr-daemon config to-dsl <file>`.

Design ground rules (issue #18, maintainer guidance 2026-09-15):

- **One language for structure and policy.** Filter bodies are written
  directly between braces — no TOML string escaping, no `body = "..."`
  quoting games. The filter language itself (see
  `filter_dsl_grammar.md`) is embedded verbatim; its grammar does not
  change here.
- **Independent, not a BIRD replica.** BIRD's one-language model and
  brace/semicolon style are the inspiration; the block names, the
  key vocabulary and the semantics are lr's own (they are the
  `daemon_config.rs` schema, renamed from `snake_case` keys only where
  the two differ — see the mapping below: **keys keep their exact
  TOML spelling** so both frontends share one dispatch and cannot
  drift).
- **Declarative and non-Turing-complete.** Sections, typed key-value
  options (with duration/scale unit suffixes), named-object blocks and
  `include`. Deliberately absent: loops, arbitrary expressions,
  variables, side effects.
- **Fail closed.** Unknown keys inside a known section are errors
  (typo protection), exactly like the TOML frontend. Unknown block
  names are errors too — the TOML frontend tolerates unknown sections
  with a warning for forward compatibility, but a brand-new DSL has no
  legacy files to keep loadable, so it can afford strictness from day
  one.

## Lexical structure

```ebnf
file        = { statement } ;
statement   = block | key_stmt | include_stmt ;

block       = block_name [ string ] "{" { statement } "}" ;
key_stmt    = key_name ( value | value_list ) ";" ;
include_stmt= "include" string ";" ;

block_name  = ident ;          (* kebab-case, see block table *)
key_name    = ident ;          (* exact TOML key spelling *)
value       = string | number | bool | ident ;
value_list  = "[" [ value { "," value } [ "," ] ] "]" ;

ident       = ( alpha | "_" ) { alpha | digit | "_" | "-" | "." | ":" | "/" } ;
number      = [ "-" ] digit { digit } [ "." digit { digit } ] [ unit ] ;
unit        = "ms" | "s" | "m" | "h" | "k" | "M" ;
bool        = "true" | "false" ;
string      = '"' { any - '"' | escape } '"' ;
escape      = "\\" ( '"' | "\\" | "n" | "t" | "r" ) ;

comment     = "#" ... end-of-line ;   (* dropped by the lexer *)
```

- Whitespace and `#` comments are insignificant.
- Strings are double-quoted with the escape set above (a superset of
  what the TOML subset parser accepts: `\"` `\\` `\n` `\t` `\r`).
- A bare `ident` value is string sugar: `protocol bgp;` and
  `protocol "bgp";` are the same statement. Bare words cover the
  common unquoted shapes (AS numbers, addresses, protocol names);
  anything containing spaces or punctuation outside the `ident` set
  needs quotes.
- Numbers may carry a **unit suffix**. The suffix is expanded before
  the value reaches the shared key dispatch, and only for keys
  registered as accepting that unit (see "Unit suffixes"); elsewhere a
  suffixed literal is a parse error, so `max_prefixes 100k;` cannot
  silently become something unexpected.

## Blocks and sections

One DSL block corresponds to one TOML section or array-of-tables
entry. The block name, its optional string argument (the *identity*)
and the TOML section it lowers to:

| DSL block                     | identity lowers to          | TOML section            |
| ----------------------------- | --------------------------- | ----------------------- |
| `bgp { }`                     | —                           | `[bgp]`                 |
| `bgp { rpki { } }`            | —                           | `[bgp.rpki]`            |
| `ospf { }`                    | —                           | `[ospf]`                |
| `ospf { area ID { } }`        | `id`                        | `[[ospf.area]]`         |
| `ospf { interface NAME { } }` | `name`                      | `[[ospf.interface]]`    |
| `ospf { prefix-sid P { } }`   | `prefix`                    | `[[ospf.prefix_sid]]`   |
| `ospf { mapping-server P { } }` | `prefix`                  | `[[ospf.mapping_server]]` |
| `ospf { srv6-locator P { } }` | `prefix`                    | `[[ospf.srv6_locator]]` |
| `babel { }`                   | —                           | `[babel]`               |
| `babel { key { } }`          | —                           | `[[babel.key]]`         |
| `babel { interface NAME { } }`| `name`                      | `[[babel.interface]]`   |
| `ldp { }`                     | —                           | `[ldp]`                 |
| `ldp { interface NAME { } }`  | `name`                      | `[[ldp.interface]]`     |
| `ldp { targeted ADDR { } }`   | `address`                   | `[[ldp.targeted]]`      |
| `ldp { bind P { } }`          | `prefix`                    | `[[ldp.bind]]`          |
| `damping { }`                 | —                           | `[damping]`             |
| `peer NAME { }`               | `name`                      | `[[peer]]`              |
| `peer-template NAME { }`      | template name               | `[peer-template.NAME]`  |
| `prefix-list NAME { }`        | `name`                      | `[[prefix-list]]`       |
| `as-path-list NAME { }`       | `name`                      | `[[as-path-list]]`      |
| `community-list NAME { }`     | `name`                      | `[[community-list]]`    |
| `route-map NAME { }`          | `name`                      | `[[route-map]]`         |
| `filter NAME { }`             | `name`                      | `[[filter]]`            |
| `roa { }`                     | —                           | `[[roa]]`               |
| `redistribute { }`            | —                           | `[[redistribute]]`      |
| `aggregate { }`               | —                           | `[[aggregate]]`         |

- The identity argument is sugar for the identity key: `peer "core-1"`
  behaves exactly as if `name "core-1";` were the first statement of
  the block. An explicit inner key of the same name overrides it
  (later assignment wins, matching TOML's re-assignment semantics).
- The dotted section vocabulary of TOML (`ospf.prefix_sid`) becomes
  nesting or kebab-case block names; the *keys* inside keep their
  exact TOML spelling (`hello_interval_ms`, `origin_as`, `match_prefix`,
  ...). This is what makes one shared dispatch possible.
- `ospf { }`, `babel { }`, `ldp { }`, `bgp { }` may appear more than
  once; blocks of the same kind merge in file order, exactly like
  repeated TOML tables.
- Sub-blocks (`area`, `interface`, `key`, `rpki`, ...) are only valid
  inside their parent block; at top level they are errors.

## Keys and values

Every key of the TOML schema is accepted verbatim:

```lr
bgp {
    local_as 64512;
    peer_as 64513;
    router_id 10.0.0.1;
    hold_time 90s;                      # unit suffix: 90
    mp_families [ipv4-unicast, ipv6-unicast];
    install_kernel true;
    networks [203.0.113.0/24, 198.51.100.0/24];
}
```

Value lowering to the shared dispatch:

| DSL value            | string handed to the dispatch        |
| -------------------- | ------------------------------------ |
| `string`             | unescaped content                    |
| `123` / `-4`         | decimal text                         |
| `1.5`                | decimal text (float keys)            |
| `true` / `false`     | `true` / `false`                     |
| bare ident           | the token text                       |
| `[a, b]`             | `["a","b"]` (TOML array text form)   |
| `90s` / `5m` / `2h`  | expanded seconds (duration keys only)|
| `100ms`              | expanded milliseconds (duration keys)|
| `100k` / `2M`        | expanded count (scale keys only)     |

### Unit suffixes

The whitelist lives in the lowering layer (`config_dsl`), keyed by
*(section, key)* — the same key name may carry different units in
different sections (`hello_interval` is seconds under `ospf`, but an
alias of `hello_interval_ms` inside a `babel interface` block):

- **Seconds** (`s` ×1, `m` ×60, `h` ×3600): `hold_time`,
  `graceful_restart_time`, `llgr_stale_time`, `llgr_max_stale_time`,
  `grace_period`, `helper_grace_cap`, `dead_interval`,
  `hello_interval` (OSPF — hello/dead intervals are seconds per
  RFC 2328), `keepalive_time`, `link_hold_time`,
  `targeted_hold_time`, `decay_interval_s`.
- **Milliseconds** (`ms` ×1, `s` ×1000): `bfd_min_rx_ms`,
  `bfd_min_tx_ms`, `gr_reconnect_ms`, `gr_recovery_ms`,
  `hello_interval_ms`, `update_interval_ms`, and the
  `hello_interval` / `update_interval` aliases inside
  `babel interface` blocks.
- **Microseconds** (`us` ×1, `ms` ×1000): `rtt_min`, `rtt_max`
  (Babel RTT, RFC 8966 §3.4.2).
- **Scale** (`k` ×1000, `M` ×1_000_000): `max_prefixes`,
  `add_path_max_paths`, `label_max`, `label_min`.

A suffixed literal on a key outside the whitelist is a hard parse
error naming the key — the DSL never guesses a unit.

## Filter blocks

`filter NAME { ... }` embeds the filter DSL (BIRD-syntax subset, see
`filter_dsl_grammar.md`) natively:

```lr
filter customer-in {
    if roa.state == ROA_UNKNOWN then accept;
    else reject;
}
```

The body is captured **verbatim** — the exact source text between the
braces is what `FilterSpec.body` stores, and what `config to-dsl`
re-emits. Brace matching inside a filter body is string- and
comment-aware (a `}` inside `"..."` or after `#` does not close the
block), so filter syntax needs no escaping at all. Filter syntax is
not validated at config-parse time — the body reaches the filter
compiler exactly where and when a TOML `body = "..."` string would,
keeping both frontends byte-for-byte comparable.

## Includes

```lr
include "peers/lab.lr";
```

- Relative paths resolve against the directory of the *including*
  file; absolute paths are used as-is.
- Includes expand before parsing; the parser keeps a per-line source
  map so diagnostics name the real file and line.
- Cycle detection (via canonical paths) and a depth limit (16) fail
  closed.

## Name resolution

Cross-section references (`import_filter` → `filter`, `match_prefix`
→ `prefix-list`, `extends` → `peer-template`, route-map → lists) are
resolved by `DaemonConfig::finalize` — the same checked resolution
both frontends share. The DSL adds no second resolver.

## The `lr-daemon config to-dsl` converter

`lr-daemon config to-dsl <file>` loads any accepted config (TOML,
BIRD, FRR, or `.lr`), finalizes it like `config check` does not (the
converter works on the pre-finalize IR: finalization *merges* peer
templates and would destroy source-level structure) and prints the
equivalent `.lr` program on stdout.

- **Deterministic**: blocks are emitted in a fixed order (top-level
  keys, `bgp` with nested `rpki`, `peer`s in IR order, templates, the
  policy bank, `filter`s, `roa`, `redistribute`, `aggregate`, `ospf`,
  `babel`, `ldp`, `damping`); keys inside a block in schema order;
  unset fields are omitted.
- **Never silent**: if the IR carries parse warnings (unknown sections
  or keys the TOML frontend tolerated), the converter refuses with a
  non-zero exit instead of emitting a file that means less than the
  input. `config_path` / `config_dialect` / `warnings` are load
  bookkeeping and never emitted.
- **Round-trip property** (the migration's correctness contract, test
  pinned): `parse(TOML) → to-dsl → parse(lr)` produces an IR equal
  (`PartialEq`) to the original — for every file the converter
  accepts.

## Example

```lr
# lab-router.lr — mirrors templates/daemon.toml
protocol bgp;

bgp {
    local_as 64512;
    peer_as 64513;
    router_id 10.0.0.1;
    peer_addr 192.0.2.2:179;
    local_address 192.0.2.1;
    hold_time 90s;
    graceful_restart_time 120s;
    networks [203.0.113.0/24];
}

prefix-list customer-space {
    prefix 203.0.113.0/24;
}

route-map to-customer {
    entry 10;
    match_prefix customer-space;
    permit true;
}

route-map to-customer {
    entry 20;      # everything else stays internal
    permit false;
}
```
