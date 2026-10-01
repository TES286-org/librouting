# Filter DSL and ROA validation

This page wires a BIRD-style `filter` block to a peer and turns on
RFC 6811 prefix-origin validation, so a received route is dropped when
its origin AS is not authorized. Read it if you are writing import
policy for the daemon.

The filter language itself is specified in
[`../filter_dsl_grammar.md`](../filter_dsl_grammar.md); this page only
shows how the daemon loads and attaches filters.

## Configuration

```lr
protocol bgp;

bgp {
    local_as 64512;
    peer_as 64513;
    router_id "10.0.0.1";
    peer_addr "192.0.2.2:179";
    local_address "127.0.0.1";
    hold_time 9s;
    ebgp_policy "accept-all";

    # Every received UPDATE is validated against the `roa` blocks
    # before the user import hook chain runs.
    roa_validate true;
    roa_invalid_action "reject";   # "reject" | "warn" | "accept"
}

# 198.51.100.0/24 is authorized for our peer, AS 64513.
roa {
    prefix "198.51.100.0/24";
    asn 64513;
}

# 203.0.113.0/24 is authorized for AS 65000 only, so a route for it
# from AS 64513 validates as invalid.
roa {
    prefix "203.0.113.0/24";
    asn 65000;
    max_length 24;
}

# The body sits between the braces verbatim: no string escaping, and a
# `}` inside a comment or a string does not close the block.
filter "customer-in" {
    if roa.state == "invalid" then { reject with "roa-invalid"; }
    if net ~ 198.51.100.0/24 then {
        bgp.local_pref = 200;
        bgp.communities += [ 64512:100 ];
        accept;
    }
    accept;
}

peer "customer" {
    remote "192.0.2.2:179";
    peer_as 64513;
    import_filter "customer-in";
}
```

`max_length` defaults to the prefix length (exact match). A value below
the prefix length or above 32 (v4) / 128 (v6) is a startup error.

## What the daemon does

1. `daemon_policy::build_roa_table` compiles the `roa` blocks into an
   `lr_bgp::RoaTable`.
2. With `roa_validate true` and a non-empty table, the daemon installs a
   built-in import hook whose body is
   `if roa.state == "invalid" then { reject; } accept;`. It is compiled
   as a DSL filter, so it runs on the same path as your filters and is
   registered under the name `__roa_validate`.
3. `daemon_policy::build_filters` compiles each `filter` body with
   `lr_policy::filter::compile`. A parse error fails startup — filters
   never silently pass traffic.
4. A peer with `import_filter "name"` gets a `FilterImportHook` that runs
   the compiled filter on every received route before Adj-RIB-In.

Unknown filter names fail at startup, as do duplicate filter names.

## Verify

Startup reports both halves:

```text
  roa:         2 entries, validate=true (action: reject)
  filters:     1 compiled, 1 import / 0 export bindings
```

Then confirm the verdicts on live routes. `proto` renders as a
BIRD-style lowercase name, so match it as `"bgp"`, `"ospf"`, `"ospf3"`,
`"babel"`, `"static"`, `"direct"` or `"unknown"`:

```sh
lrctl --socket /run/lr-daemon.api routes show 203.0.113.0/24
lrctl filter compile 'if proto == "bgp" then accept; reject;'
```

The `routes show` output lists only routes that survived the import
chain, so a rejected ROA-invalid prefix is absent. `lrctl filter compile`
validates a body without touching a running daemon.

## Test a filter before deploying it

Filter bodies are the unit under test, and `roa.state` is read-only:

```text
if net ~ [ 10.0.0.0/8{16,24} ] then { bgp.local_pref = 200; accept; }
if bgp.local_pref < 200 then reject with "low-pref";
accept;
```

Compile it with `lrctl filter compile '<body>'`. Working examples for
every construct — prefix-set ranges, `case`, community mutation,
user-defined functions — live in
[`../filter_dsl_grammar.md`](../filter_dsl_grammar.md) §7.

## Reference

- RFC 6482 — A Profile for Route Origin Authorizations
- RFC 6811 §2 — prefix-origin validation
- RFC 1997 — BGP Communities Attribute
- [`../filter_dsl_grammar.md`](../filter_dsl_grammar.md) — the grammar and
  the route-field reference
