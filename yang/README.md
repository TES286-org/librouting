# YANG data models

This directory ships the standards-track YANG data models that
`lr-daemon` renders configuration into, plus the two modules themselves
(verbatim from the RFCs, including their license headers):

| File                              | Module            | Source        |
| --------------------------------- | ----------------- | ------------- |
| `ietf-babel@2024-10-10.yang`      | `ietf-babel`      | RFC 9647      |
| `ietf-key-chain@2017-06-15.yang`  | `ietf-key-chain`  | RFC 8177      |

`lr-daemon yang render <config.toml> [--model babel|keychain|all]`
emits XML instance data for the Babel subset of a daemon configuration,
validated in CI (and by `tests/interop/yang.sh`) against these modules
with libyang's `yanglint` when the tool is available.

## Rendering scope

The mapping is config → instance data only. `lr` does not implement a
YANG validator or a NETCONF/RESTCONF management plane; embedders that
need one can feed the rendered instance data into their own stack.

### `--model babel` — `ietf-babel` (RFC 9647)

The `babel` container of RFC 9647 does not stand alone: it augments
`/rt:routing/rt:control-plane-protocols/rt:control-plane-protocol`
(RFC 8349, NMDA). The renderer therefore emits the full envelope:

```xml
<routing xmlns="urn:ietf:params:xml:ns:yang:ietf-routing"
         xmlns:babel="urn:ietf:params:xml:ns:yang:ietf-babel">
  <control-plane-protocols>
    <control-plane-protocol>
      <type>babel:babel</type>
      <name>lr-babel</name>
      <babel xmlns="urn:ietf:params:xml:ns:yang:ietf-babel">
        ...
      </babel>
    </control-plane-protocol>
  </control-plane-protocols>
</routing>
```

| lr TOML                              | ietf-babel node                              |
| ------------------------------------ | -------------------------------------------- |
| (implicit; the daemon is running)    | `/babel/enable` = `true`                     |
| `[babel] port` (default 6696)        | `/babel/constants/udp-port`                  |
| `[babel] group` (or AF default)      | `/babel/constants/mcast-group`               |
| `[[babel.key]] secret`               | `/babel/mac-key-set[name=lr]/keys[name=key-N]/value` (base64 of the raw secret bytes — the same bytes the daemon signs with) |
| `[[babel.key]] algorithm` = `hmac-sha256` | `.../algorithm` = `babel:hmac-sha256`   |
| `[[babel.key]] algorithm` = `blake2s` | `.../algorithm` = `babel:blake2s`           |
| `use-send` / `use-verify`            | always `true` (the daemon signs and verifies; `[babel] accept_unauthenticated` only relaxes the RFC 8967 §5 unauthenticated-absence case, which the model expresses through `mac-verify` on interface objects lr does not name) |

The `interfaces` list is not rendered: the babel transport binds one
local address (`--local-address`) and resolves the interface at runtime,
so there is no interface name in the config to key a `reference` leaf
with. The `metric-algorithm` identity (`babel:two-out-of-three`), the
`dtls` subtree and all `config false` state objects are likewise not
rendered.

### `--model keychain` — `ietf-key-chain` (RFC 8177)

The same `[[babel.key]]` tables rendered as a generic key chain named
`lr-babel`:

| lr TOML                              | ietf-key-chain node                          |
| ------------------------------------ | -------------------------------------------- |
| `[[babel.key]]` index                | `/key-chains/key-chain[name=lr-babel]/key[key-id=N]` |
| `[[babel.key]] algorithm` = `hmac-sha256` | `.../crypto-algorithm` = `key-chain:hmac-sha-256` |
| `[[babel.key]] secret`               | `.../key-string/keystring` (raw string)      |
| (no lifetime scoping in lr)          | `.../lifetime/send-accept-lifetime/always`   |

Keys configured as `blake2s` are a **hard error** in this view: RFC 8177
defines no `crypto-algorithm` identity for BLAKE2s, and inventing one
would produce instance data other tools cannot understand. Render those
keys through `--model babel` instead (the `ietf-babel` module defines the
`blake2s` MAC identity natively).

### `--model all` (default)

Both documents inside a NETCONF-style `<config>` wrapper with the
`xmlns:babel` / `xmlns:key-chain` prefixes declared on it, so the
identityref values (`babel:babel`, `key-chain:hmac-sha-256`, …) resolve
in one document. The wrapper itself is the NETCONF payload container —
validators that want a pure data tree should use the single-model views.

## Validation

`tests/interop/yang.sh` runs libyang's `yanglint` over the shipped
modules and the rendered instance data when the tool is available (it
skips otherwise, like the other environment-gated interop scripts). The
unit tests in `crates/lr-cli/src/yang.rs` pin the exact wire shapes.

Import chain of the shipped modules (fetched by the gate script into
`/tmp/lr_yang_deps`, from the canonical RFC copies): `ietf-routing`
(RFC 8349), `ietf-interfaces` (RFC 8343), `ietf-crypto-types`
(RFC 9640), `ietf-netconf-acm` (RFC 8341), `ietf-inet-types` /
`ietf-yang-types` (RFC 6991).
