# BIRD-like filter DSL + ROA validation

This example demonstrates the BIRD-like filter DSL (`filter` blocks in
the native `.lr` config) combined with RFC 6811 prefix-origin validation
(ROA). The filter language targets a subset of BIRD's filter grammar,
providing conditionals, variables, arithmetic, prefix-set membership,
and route attribute mutation — enough for production import/export
policy.

## Configuration

```lr
bgp {
    local_as 64512;
    peer_as 64513;
    router_id "10.0.0.1";
    listen_addr "127.0.0.1:1179";
    local_address "127.0.0.1";
    hold_time 9s;
    ebgp_policy "accept-all";

    # RFC 6811 prefix-origin validation: when on, every received BGP
    # UPDATE is validated against the `roa` blocks at import time.
    # Invalid routes are rejected before the user-supplied import hook
    # chain runs.
    roa_validate true;
    roa_invalid_action "reject";   # "reject" | "warn" | "accept"
}

# ROA: 198.51.100.0/24 is authorized for AS 64513 (the peer's AS).
# A route for 198.51.100.0/24 from AS 64513 → Valid.
roa {
    prefix "198.51.100.0/24";
    asn 64513;
}

# ROA: 203.0.113.0/24 is authorized for AS 65000 only.
# A route for 203.0.113.0/24 from AS 64513 → Invalid (wrong origin).
roa {
    prefix "203.0.113.0/24";
    asn 65000;
}

# A BIRD-like filter body, embedded verbatim between braces — no
# string escaping. The filter language supports:
#   - if/then/else with block statements
#   - let bindings and arithmetic
#   - prefix-set membership: net ~ [ prefix{ge,le}, ... ]
#   - route attribute access: bgp.local_pref, bgp.med, bgp.as_path,
#     bgp.communities, bgp.next_hop, proto, roa.state
#   - assignment: bgp.local_pref = 200
#   - append: bgp.communities += [ 64512:100 ]
#   - method calls: bgp.as_path.prepend(65001)
#   - accept / reject (with optional reason)
#   - case/switch
#   - function calls: len(bgp.as_path), first(bgp.as_path), ...
filter "customer-in" {
    if roa.state == "invalid" then { reject; }
    if net ~ 198.51.100.0/24 then {
        bgp.local_pref = 200;
        bgp.communities += [ 64512:100 ];
        accept;
    }
    accept;
}

# A second filter using prefix-set ranges and arithmetic.
filter "transit-in" {
    let p = 100;
    let q = p * 2;
    if bgp.local_pref < q && net ~ [ 10.0.0.0/8{16,24} ] then {
        bgp.local_pref = q;
        accept;
    }
    reject;
}

peer "customer" {
    remote "192.0.2.2:179";
    import_filter "customer-in";
}
```

## How it works

1. At startup, `daemon_policy::build_roa_table()` compiles the
   `roa` blocks into an `lr_bgp::RoaTable`.
2. When `roa_validate true;` is set in the bgp block, the daemon
   installs a built-in
   import hook whose body is `if roa.state == "invalid" then { reject; } accept;`
   — implemented as a tiny DSL filter so the same code path runs as
   user-supplied filters.
3. `daemon_policy::build_filters()` compiles each `filter` body
   via `lr_policy::filter::compile()`, surfacing parse errors at
   startup (fail-closed).
4. When a peer has `import_filter "name"`, the daemon attaches a
   `FilterImportHook` that runs the compiled filter on every received
   route before it enters Adj-RIB-In.

## DSL grammar

```text
filter   := name? '{' stmts '}' | stmts
stmts    := stmt*
stmt     := 'if' expr 'then' stmt ('else' stmt)?
         | 'case' expr '{' arm+ '}'
         | 'let' ident '=' expr ';'
         | 'accept' ';'
         | 'reject' ('with' expr)? ';'
         | lvalue '=' expr ';'
         | lvalue '+=' expr ';'
         | expr ';'
         | '{' stmts '}'
arm      := (expr (',' expr)*)? '=>' stmts
         | 'default' '=>' stmts
lvalue   := ident | route_field
expr     := or_expr
or_expr  := and_expr ('||' and_expr)*
and_expr := eq_expr ('&&' eq_expr)*
eq_expr  := cmp_expr (('==' | '!=') cmp_expr)*
cmp_expr := bit_or_expr (('<' | '<=' | '>' | '>=' | '~') bit_or_expr)*
bit_or   := bit_xor ('|' bit_xor)*
bit_xor  := bit_and ('^' bit_and)*
bit_and  := shift ('&' shift)*
shift    := add (('<<' | '>>') add)*
add      := mul (('+' | '-') mul)*
mul      := unary (('*' | '/' | '%') unary)*
unary    := ('!' | '-') unary | postfix
postfix  := primary ('.' ident ('(' args ')')?)*
primary  := literal | ident | route_field | ident '(' args ')'
         | '[' set_items ']' | '(' expr ')'
route_field := 'net' | 'proto' | 'source'
             | 'bgp' '.' ident
             | 'roa' '.' 'state'
```

## Route attributes

| Field              | Type     | Settable | Description                          |
|--------------------|----------|----------|--------------------------------------|
| `net`              | prefix   | no       | The route's prefix                   |
| `proto`            | string   | no       | Protocol kind (`"Bgp"`, `"Ospfv2"`)  |
| `source`           | int      | no       | Route source (proto id)              |
| `bgp.local_pref`   | int      | yes      | BGP LOCAL_PREF (RFC 4271 §5.1.5)     |
| `bgp.med`          | int      | yes      | BGP MULTI_EXIT_DISC                  |
| `bgp.next_hop`     | ip       | yes      | BGP NEXT_HOP                         |
| `bgp.as_path`      | as-path  | no       | BGP AS_PATH (use `.prepend()`)       |
| `bgp.communities`  | comm-set | +=       | BGP COMMUNITIES (RFC 1997)          |
| `bgp.origin`       | int      | no       | BGP ORIGIN (0=IGP, 1=EGP, 2=INC)    |
| `roa.state`        | roa-state| no       | RFC 6811 validation outcome          |

## Interop

The `tests/interop/filter_dsl_bird.sh` test runs the full filter DSL
+ ROA validation pipeline against a real BIRD 2 router. It verifies
that:

1. A route authorized by a ROA (`Valid`) is accepted by the filter.
2. A route not authorized (`Invalid`) is rejected by the built-in
   ROA validation hook before the user filter sees it.
3. The daemon prints `filters: N compiled, M import / K export
   bindings` and `roa: N entries, validate=true` on startup.

## References

- RFC 6482 — Route Origin Authorization (ROA) structure
- RFC 6811 — BGP Prefix Origin Validation (§2 validation algorithm)
- BIRD `filter/config.Y` — filter grammar reference
- BIRD `filter/data.h` — Value types reference
