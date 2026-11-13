//! Unit tests for the ROA loader format parsers (issue #100).
//!
//! The `jq` and `awk` transform formats are exercised end-to-end in
//! `daemon_roa_loader_tests.rs` (they require the daemon's subprocess
//! dispatch). This module covers the pure parsers (`native`, `bird`)
//! and the format dispatch logic.

use super::*;
use lr_core::addr::{Asn, Prefix};

fn p4(o: [u8; 4], len: u8) -> Prefix {
    Prefix::new_v4(o, len)
}

fn p6(o: [u8; 16], len: u8) -> Prefix {
    Prefix::new_v6(o, len)
}

fn entry(prefix: Prefix, max: u8, asn: u32) -> RoaEntry {
    RoaEntry {
        prefix,
        max_length: max,
        asn: Asn(asn),
    }
}

// ============================================================
// Format dispatch
// ============================================================

#[test]
fn format_from_name_round_trips() {
    for (name, expected) in [
        ("native", RoaFormat::Native),
        ("NATIVE", RoaFormat::Native),
        ("lr", RoaFormat::Native),
        ("toml", RoaFormat::Native),
        ("bird", RoaFormat::Bird),
        ("bird2", RoaFormat::Bird),
        ("jq", RoaFormat::Jq),
        ("json", RoaFormat::Jq),
        ("awk", RoaFormat::Awk),
        ("csv", RoaFormat::Awk),
        ("tsv", RoaFormat::Awk),
        ("text", RoaFormat::Awk),
        ("plain", RoaFormat::Awk),
    ] {
        assert_eq!(RoaFormat::from_name(name), Some(expected), "name: {name}");
    }
    assert_eq!(RoaFormat::from_name("xml"), None);
}

#[test]
fn format_from_extension_common_paths() {
    assert_eq!(
        RoaFormat::from_extension("foo.toml"),
        Some(RoaFormat::Native)
    );
    assert_eq!(RoaFormat::from_extension("foo.lr"), Some(RoaFormat::Native));
    assert_eq!(
        RoaFormat::from_extension("roas.bird"),
        Some(RoaFormat::Bird)
    );
    assert_eq!(RoaFormat::from_extension("roas.roa"), Some(RoaFormat::Bird));
    assert_eq!(RoaFormat::from_extension("roas.json"), Some(RoaFormat::Jq));
    assert_eq!(RoaFormat::from_extension("roas.csv"), Some(RoaFormat::Awk));
    assert_eq!(RoaFormat::from_extension("roas.txt"), Some(RoaFormat::Awk));
    assert_eq!(RoaFormat::from_extension("roas.bin"), None);
    assert_eq!(RoaFormat::from_extension("noext"), None);
}

#[test]
fn format_requires_program_for_transforms() {
    assert!(!RoaFormat::Native.requires_program());
    assert!(!RoaFormat::Bird.requires_program());
    assert!(RoaFormat::Jq.requires_program());
    assert!(RoaFormat::Awk.requires_program());
}

#[test]
fn format_as_str_round_trips() {
    assert_eq!(RoaFormat::Native.as_str(), "native");
    assert_eq!(RoaFormat::Bird.as_str(), "bird");
    assert_eq!(RoaFormat::Jq.as_str(), "jq");
    assert_eq!(RoaFormat::Awk.as_str(), "awk");
}

#[test]
fn dispatch_picks_native_parser() {
    let text = "[[roa]]\nprefix = \"203.0.113.0/24\"\nasn = 64512\n";
    let entries = parse(text, RoaFormat::Native).unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0], entry(p4([203, 0, 113, 0], 24), 24, 64512));
}

#[test]
fn dispatch_picks_bird_parser() {
    let text = "roa 203.0.113.0/24 max 24 as 64512;\n";
    let entries = parse(text, RoaFormat::Bird).unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0], entry(p4([203, 0, 113, 0], 24), 24, 64512));
}

#[test]
fn dispatch_jq_format_rejects_direct_parse() {
    // The jq transform format requires the daemon's loader thread
    // to run the program first; the pure `parse` function refuses
    // to handle it directly so the FFI surface cannot bypass the
    // daemon's subprocess discipline.
    let err = parse("anything", RoaFormat::Jq).unwrap_err();
    assert!(
        matches!(err, RoaLoaderError::TransformFormatDirect("jq")),
        "expected TransformFormatDirect, got {err:?}"
    );
}

#[test]
fn dispatch_awk_format_rejects_direct_parse() {
    let err = parse("anything", RoaFormat::Awk).unwrap_err();
    assert!(
        matches!(err, RoaLoaderError::TransformFormatDirect("awk")),
        "expected TransformFormatDirect, got {err:?}"
    );
}

// ============================================================
// parse_native — TOML `[[roa]]` subset
// ============================================================

#[test]
fn native_parses_two_entries() {
    let text = r#"
[[roa]]
prefix = "203.0.113.0/24"
max_length = 24
asn = 64512

[[roa]]
prefix = "198.51.100.0/24"
asn = 64513
"#;
    let entries = parse_native(text).unwrap();
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0], entry(p4([203, 0, 113, 0], 24), 24, 64512));
    // Second entry: no max_length → defaults to prefix length (exact match).
    assert_eq!(entries[1], entry(p4([198, 51, 100, 0], 24), 24, 64513));
}

#[test]
fn native_accepts_aliases() {
    let text = r#"
[[roa]]
prefix = "203.0.113.0/24"
max_len = 26
origin_as = 64512
"#;
    let entries = parse_native(text).unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0], entry(p4([203, 0, 113, 0], 24), 26, 64512));
}

#[test]
fn native_skips_comments_and_blanks() {
    let text = r#"
# A comment line

[[roa]]  # trailing comment
prefix = "203.0.113.0/24"  # inline comment
asn = 64512
"#;
    let entries = parse_native(text).unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0], entry(p4([203, 0, 113, 0], 24), 24, 64512));
}

#[test]
fn native_preserves_hash_in_quoted_string() {
    // A `#` inside a quoted string is NOT a comment — the value
    // passed to the prefix parser retains the `#`, which then
    // fails as a bad prefix (proving the `#` was not stripped as
    // a comment). Parity with `daemon_config::parse_toml_subset`.
    let text = r#"
[[roa]]
prefix = "203.0.113.0/24 # not a comment"
asn = 64512
"#;
    let err = parse_native(text).unwrap_err();
    match err {
        RoaLoaderError::BadPrefix { prefix, .. } => {
            assert!(
                prefix.contains('#'),
                "prefix value should retain the '#': {prefix}"
            );
        }
        _ => panic!("expected BadPrefix, got {err:?}"),
    }
}

#[test]
fn native_rejects_missing_asn() {
    let text = r#"
[[roa]]
prefix = "203.0.113.0/24"
"#;
    let err = parse_native(text).unwrap_err();
    assert!(err.to_string().contains("'asn'"), "err: {err}");
}

#[test]
fn native_rejects_bad_prefix() {
    let text = r#"
[[roa]]
prefix = "not-a-prefix"
asn = 64512
"#;
    let err = parse_native(text).unwrap_err();
    assert!(err.to_string().contains("bad prefix"), "err: {err}");
}

#[test]
fn native_rejects_max_length_below_prefix() {
    let text = r#"
[[roa]]
prefix = "203.0.113.0/24"
max_length = 20
asn = 64512
"#;
    let err = parse_native(text).unwrap_err();
    // The error mentions max_length (RFC 6482 §3.3 invariant).
    assert!(
        err.to_string().contains("max_length") || err.to_string().contains("maxLength"),
        "err: {err}"
    );
}

#[test]
fn native_ipv6_prefix_parses() {
    let text = r#"
[[roa]]
prefix = "2001:db8::/32"
max_length = 48
asn = 64512
"#;
    let entries = parse_native(text).unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(
        entries[0],
        entry(
            p6(
                [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                32
            ),
            48,
            64512
        )
    );
}

#[test]
fn native_skips_unknown_array_tables_in_same_file() {
    // The daemon's `daemon.toml` may carry `[bgp]` and `[[peer]]`
    // tables alongside `[[roa]]` — the parser must skip them
    // silently (forward compatibility).
    let text = r#"
[bgp]
local_as = 64512

[[peer]]
name = "upstream"
remote_as = 64513

[[roa]]
prefix = "203.0.113.0/24"
asn = 64512
"#;
    let entries = parse_native(text).unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0], entry(p4([203, 0, 113, 0], 24), 24, 64512));
}

#[test]
fn native_empty_input_yields_empty_vec() {
    assert_eq!(parse_native("").unwrap(), vec![]);
}

// ============================================================
// parse_bird — BIRD 2 `roa table` body
// ============================================================

#[test]
fn bird_parses_roa_lines() {
    let text = "roa 192.0.2.0/24 max 24 as 64512;\nroa 198.51.100.0/24 max 26 as 64513;\n";
    let entries = parse_bird(text).unwrap();
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0], entry(p4([192, 0, 2, 0], 24), 24, 64512));
    assert_eq!(entries[1], entry(p4([198, 51, 100, 0], 24), 26, 64513));
}

#[test]
fn bird_parses_roa6_lines() {
    let text = "roa6 2001:db8::/32 max 48 as 64512;\n";
    let entries = parse_bird(text).unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(
        entries[0],
        entry(
            p6(
                [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                32
            ),
            48,
            64512
        )
    );
}

#[test]
fn bird_accepts_table_wrapper_lines() {
    let text = r#"
roa table my_roas {
roa 192.0.2.0/24 max 24 as 64512;
}
"#;
    let entries = parse_bird(text).unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0], entry(p4([192, 0, 2, 0], 24), 24, 64512));
}

#[test]
fn bird_optional_semicolon() {
    let text = "roa 192.0.2.0/24 max 24 as 64512\n";
    let entries = parse_bird(text).unwrap();
    assert_eq!(entries.len(), 1);
}

#[test]
fn bird_optional_max_means_exact() {
    let text = "roa 192.0.2.0/24 as 64512;\n";
    let entries = parse_bird(text).unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0], entry(p4([192, 0, 2, 0], 24), 24, 64512));
}

#[test]
fn bird_accepts_as_prefix() {
    let text = "roa 192.0.2.0/24 max 24 as AS64512;\n";
    let entries = parse_bird(text).unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].asn, Asn(64512));
}

#[test]
fn bird_skips_comments() {
    let text = "# comment\n// also comment\nroa 192.0.2.0/24 max 24 as 64512;\n";
    let entries = parse_bird(text).unwrap();
    assert_eq!(entries.len(), 1);
}

#[test]
fn bird_rejects_missing_prefix() {
    let text = "roa max 24 as 64512;\n";
    let err = parse_bird(text).unwrap_err();
    assert!(err.to_string().contains("without a prefix"), "err: {err}");
}

#[test]
fn bird_rejects_missing_asn() {
    let text = "roa 192.0.2.0/24 max 24;\n";
    let err = parse_bird(text).unwrap_err();
    assert!(err.to_string().contains("'asn'"), "err: {err}");
}

#[test]
fn bird_empty_input_yields_empty_vec() {
    assert_eq!(parse_bird("").unwrap(), vec![]);
}

// ============================================================
// Cross-format determinism
// ============================================================

#[test]
fn native_and_bird_produce_same_entries() {
    // The same record expressed in native and BIRD format must
    // produce the same `RoaEntry`. This is the determinism invariant
    // that makes hot-reload safe: a switch from `format = "bird"`
    // to `format = "jq"` (whose program emits BIRD lines) does not
    // change the merged entry set.
    let native = r#"
[[roa]]
prefix = "203.0.113.0/24"
max_length = 24
asn = 64512
"#;
    let bird = "roa 203.0.113.0/24 max 24 as 64512;\n";
    let n = parse_native(native).unwrap();
    let b = parse_bird(bird).unwrap();
    assert_eq!(n, b);
}
