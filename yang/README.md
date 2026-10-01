# YANG data models

`yang/*.yang` holds the standards-track YANG modules that `lr-daemon yang
render` validates its output against. `lr-daemon yang render <config-file>
[--model babel|keychain|all]` emits XML instance data for the Babel subset of
a daemon configuration, and `tests/interop/yang.sh` checks it with libyang's
`yanglint` when that tool is available.

| File | Module | RFC |
| --- | --- | --- |
| `ietf-babel@2024-10-10.yang` | `ietf-babel` | 9647 |
| `ietf-key-chain@2017-06-15.yang` | `ietf-key-chain` | 8177 |

The mapping is configuration → instance data only. `lr` implements no YANG
validator and no NETCONF/RESTCONF management plane; an embedder that needs
one feeds the rendered data into its own stack.

## `--model babel` — `ietf-babel` (RFC 9647)

The `babel` container augments the RFC 8349 (NMDA) `control-plane-protocol`
node instead of standing alone, so the renderer emits the full envelope.

```xml
<routing xmlns="urn:ietf:params:xml:ns:yang:ietf-routing"
         xmlns:babel="urn:ietf:params:xml:ns:yang:ietf-babel">
  <control-plane-protocols>
    <control-plane-protocol>
      <type>babel:babel</type>
      <name>lr-babel</name>
      <babel xmlns="urn:ietf:params:xml:ns:yang:ietf-babel">...</babel>
    </control-plane-protocol>
  </control-plane-protocols>
</routing>
```

| lr TOML | ietf-babel node |
| --- | --- |
| (the daemon is running) | `/babel/enable` = `true` |
| `[babel] port` (default 6696) | `/babel/constants/udp-port` |
| `[babel] group` (or address-family default) | `/babel/constants/mcast-group` |
| `[[babel.key]] secret` | `/babel/mac-key-set[name=lr]/keys[name=key-N]/value` |
| `[[babel.key]] algorithm` | `.../algorithm` = `babel:hmac-sha256` or `babel:blake2s` |
| `use-send` / `use-verify` | always `true` |

The `value` leaf is the base64 of the raw secret bytes, the same bytes the
daemon signs with. `[babel] accept_unauthenticated` relaxes the RFC 8967 §5
unauthenticated-absence case. `metric-algorithm`, the `dtls` subtree, every
`config false` state object and the `interfaces` list are not rendered: lr
names no interface in the config to key a `reference` leaf with.

## `--model keychain` — `ietf-key-chain` (RFC 8177)

The same `[[babel.key]]` tables as one key chain named `lr-babel`:

| lr TOML | ietf-key-chain node |
| --- | --- |
| `[[babel.key]]` index | `/key-chains/key-chain[name=lr-babel]/key[key-id=N]` |
| `[[babel.key]] algorithm` = `hmac-sha256` | `.../crypto-algorithm` = `key-chain:hmac-sha-256` |
| `[[babel.key]] secret` | `.../key-string/keystring`, raw string |
| (lr has no lifetime scoping) | `.../lifetime/send-accept-lifetime/always` |

A `blake2s` key is a hard error here: RFC 8177 defines no `crypto-algorithm`
identity for BLAKE2s, so the renderer fails closed. Use `--model babel`.

## `--model all` (default)

Both documents inside a NETCONF `<config>` wrapper carrying the `xmlns:babel`
/ `xmlns:key-chain` prefixes, so every identityref value resolves in one
document.

## Validation

`tests/interop/yang.sh` runs `yanglint` over the shipped modules and the
rendered instance data, writing its output under `/tmp/lr_yang_gate`; it
skips when the tool is absent. The unit tests in `crates/lr-cli/src/yang.rs`
pin the wire shapes.

The shipped modules import `ietf-routing` (RFC 8349), `ietf-interfaces`
(RFC 8343), `ietf-crypto-types` (RFC 9640), `ietf-netconf-acm` (RFC 8341)
and `ietf-inet-types` / `ietf-yang-types` (RFC 6991).
