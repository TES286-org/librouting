# cargo-fuzz targets

`fuzz/` is a standalone Cargo workspace (it is not a member of the
librouting workspace) holding the sanitizer-driven fuzz targets. They
complement the property tests in `crates/lr-policy/tests/proptest.rs`: those
run inside `cargo test` and assert structural invariants, while these run
under `cargo +nightly fuzz` with AddressSanitizer and LibFuzzer's
coverage-guided input generation and assert one contract — the codec or
parser under test must not panic or exhibit undefined behaviour on arbitrary
input.

Read this page to run a target or to add one.

The targets are:

- `bgp_decode` (`BgpCodec::decode_slice`) — BGP message framing +
  OPEN/UPDATE/KEEPALIVE/NOTIFICATION codec.
- `bgp_ls_decode` (RFC 7752 / RFC 9514 BGP-LS NLRI codec) —
  Node/Link/Prefix/SRv6 SID NLRI parsing under arbitrary wire input;
  landed in 1.3.0.
- `bgp_ls_attr_decode` (BGP-LS Attribute TLV codec,
  RFC 7752 §3.3 + RFC 9514 §7-§8) — Node/Link/Prefix Attribute TLVs,
  SRv6 Endpoint Behavior / BGP PeerNode SID / SID Structure TLVs;
  landed in 1.3.0.
- `filter_parser` (`lr_policy::filter::compile`) — the `.lr` filter
  DSL parser.
- `roa_validate` (`RoaTableBuilder::add` + `RoaTable::validate`) —
  RFC 6811 §2 prefix-origin validation.
- `bfd_auth` (`BfdKeyedAuth::verify_inbound` + the BFD Control packet
  codec) — RFC 5880 keyed-MD5/SHA1 authentication.

## Layout

| Path | Contents |
| --- | --- |
| `fuzz/Cargo.toml` | The fuzz workspace; one `[[bin]]` per target |
| `fuzz/fuzz_targets/` | One file per target |
| `fuzz/seeds/` | Committed starting inputs, one directory per target |

`fuzz/corpus/`, `fuzz/artifacts/` and `fuzz/coverage/` are generated at run
time and ignored by the root `.gitignore`, so a fresh checkout starts from
`fuzz/seeds/` alone.

## Running locally

```bash
# Install the subcommand (one-time).
cargo +nightly install cargo-fuzz --locked

# Seed fuzz/corpus/<target>/ from the committed inputs (one-time per
# checkout): cargo-fuzz reads fuzz/corpus/<target>/ at run time.
for t in bgp_decode bgp_ls_decode bgp_ls_attr_decode filter_parser roa_validate bfd_auth; do
  mkdir -p "fuzz/corpus/$t"
  cp "fuzz/seeds/$t/"* "fuzz/corpus/$t/"
done

# One target.
cargo +nightly fuzz run bgp_decode -- -max_total_time=60
```

## CI

`.github/workflows/nightly.yml` runs each target for five minutes and
uploads `fuzz/artifacts/` as an artifact. The job is non-blocking: a crash
does not fail the build.

## Adding a target

1. Add `fuzz/fuzz_targets/<name>.rs` with the `#![no_main]` +
   `fuzz_target!(...)` boilerplate (`bgp_decode.rs` is the canonical shape).
2. Add the matching `[[bin]]` entry to `fuzz/Cargo.toml`.
3. Add a step to the fuzz job in `.github/workflows/nightly.yml`.
