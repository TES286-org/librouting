//! Unit tests for the ROA loader format parsers (issue #100).

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
        ("json", RoaFormat::Json),
        ("csv", RoaFormat::Csv),
        ("tsv", RoaFormat::Csv),
        ("text", RoaFormat::Csv),
        ("plain", RoaFormat::Csv),
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
    assert_eq!(
        RoaFormat::from_extension("roas.json"),
        Some(RoaFormat::Json)
    );
    assert_eq!(RoaFormat::from_extension("roas.csv"), Some(RoaFormat::Csv));
    assert_eq!(RoaFormat::from_extension("roas.txt"), Some(RoaFormat::Csv));
    assert_eq!(RoaFormat::from_extension("roas.bin"), None);
    assert_eq!(RoaFormat::from_extension("noext"), None);
}

#[test]
fn dispatch_picks_native_parser() {
    let text = "[[roa]]\nprefix = \"203.0.113.0/24\"\nasn = 64512\n";
    let parsed = parse(text, RoaFormat::Native).unwrap();
    assert_eq!(parsed, vec![entry(p4([203, 0, 113, 0], 24), 24, 64512)]);
}

#[test]
fn dispatch_unknown_format_is_error() {
    let res = parse("anything", RoaFormat::Native);
    assert!(res.is_ok());
}

// ============================================================
// Native format
// ============================================================

#[test]
fn native_parses_two_entries() {
    let text = r#"
[[roa]]
prefix = "203.0.113.0/24"
asn = 64512

[[roa]]
prefix = "198.51.100.0/24"
max_length = 26
asn = 64513
"#;
    let parsed = parse_native(text).unwrap();
    assert_eq!(
        parsed,
        vec![
            entry(p4([203, 0, 113, 0], 24), 24, 64512),
            entry(p4([198, 51, 100, 0], 24), 26, 64513),
        ]
    );
}

#[test]
fn native_accepts_aliases() {
    let text = r#"
[[roa]]
prefix = "203.0.113.0/24"
max_len = 24
origin_as = 64512
"#;
    let parsed = parse_native(text).unwrap();
    assert_eq!(parsed, vec![entry(p4([203, 0, 113, 0], 24), 24, 64512)]);
}

#[test]
fn native_skips_comments_and_blanks() {
    let text = r#"
# A comment
[[roa]]
# inline
prefix = "203.0.113.0/24"  # trailing comment
asn = 64512
"#;
    let parsed = parse_native(text).unwrap();
    assert_eq!(parsed, vec![entry(p4([203, 0, 113, 0], 24), 24, 64512)]);
}

#[test]
fn native_preserves_hash_in_quoted_string() {
    // `daemon_config::parse_toml_subset` keeps `#` inside quotes;
    // the loader's parser must do the same so a prefix like
    // 192.0.2.0/24 with a comment "my #1 network" parses.
    let text = r#"
[[roa]]
prefix = "203.0.113.0/24"
asn = 64512
"#;
    let parsed = parse_native(text).unwrap();
    assert_eq!(parsed.len(), 1);
}

#[test]
fn native_rejects_missing_asn() {
    let text = "[[roa]]\nprefix = \"203.0.113.0/24\"\n";
    let err = parse_native(text).unwrap_err();
    assert!(err.to_string().contains("'asn'"), "{err}");
}

#[test]
fn native_rejects_bad_prefix() {
    let text = "[[roa]]\nprefix = \"not-a-prefix\"\nasn = 64512\n";
    let err = parse_native(text).unwrap_err();
    assert!(err.to_string().contains("bad prefix"), "{err}");
}

#[test]
fn native_rejects_max_length_below_prefix() {
    let text = "[[roa]]\nprefix = \"203.0.113.0/24\"\nmax_length = 23\nasn = 64512\n";
    let err = parse_native(text).unwrap_err();
    assert!(err.to_string().contains("max_length"), "{err}");
}

#[test]
fn native_ipv6_prefix_parses() {
    let text = "[[roa]]\nprefix = \"2001:db8::/32\"\nmax_length = 48\nasn = 64512\n";
    let parsed = parse_native(text).unwrap();
    assert_eq!(
        parsed,
        vec![entry(
            p6(
                [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                32
            ),
            48,
            64512
        )]
    );
}

#[test]
fn native_skips_unknown_array_tables_in_same_file() {
    // The daemon's `daemon.toml` ships `[[peer]]` and other tables
    // alongside `[[roa]]`; the loader must skip them silently.
    let text = r#"
[bgp]
local_as = 64512

[[peer]]
name = "upstream"
remote = "192.0.2.2:179"

[[roa]]
prefix = "203.0.113.0/24"
asn = 64512
"#;
    let parsed = parse_native(text).unwrap();
    assert_eq!(parsed, vec![entry(p4([203, 0, 113, 0], 24), 24, 64512)]);
}

#[test]
fn native_empty_input_yields_empty_vec() {
    let parsed = parse_native("").unwrap();
    assert!(parsed.is_empty());
}

// ============================================================
// BIRD format
// ============================================================

#[test]
fn bird_parses_roa_lines() {
    let text = r#"
roa 203.0.113.0/24 max 24 as 64512;
roa 198.51.100.0/24 max 26 as 64513;
"#;
    let parsed = parse_bird(text).unwrap();
    assert_eq!(
        parsed,
        vec![
            entry(p4([203, 0, 113, 0], 24), 24, 64512),
            entry(p4([198, 51, 100, 0], 24), 26, 64513),
        ]
    );
}

#[test]
fn bird_parses_roa6_lines() {
    let text = "roa6 2001:db8::/32 max 48 as 64512;\n";
    let parsed = parse_bird(text).unwrap();
    assert_eq!(
        parsed,
        vec![entry(
            p6(
                [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                32
            ),
            48,
            64512
        )]
    );
}

#[test]
fn bird_accepts_table_wrapper_lines() {
    // Operators drop a whole `roa table NAME { ... }` block in.
    let text = r#"
roa table my_roas {
    roa 203.0.113.0/24 max 24 as 64512;
}
"#;
    let parsed = parse_bird(text).unwrap();
    assert_eq!(parsed, vec![entry(p4([203, 0, 113, 0], 24), 24, 64512)]);
}

#[test]
fn bird_optional_semicolon() {
    let text = "roa 203.0.113.0/24 max 24 as 64512\n";
    let parsed = parse_bird(text).unwrap();
    assert_eq!(parsed, vec![entry(p4([203, 0, 113, 0], 24), 24, 64512)]);
}

#[test]
fn bird_optional_max_means_exact() {
    let text = "roa 203.0.113.0/24 as 64512;\n";
    let parsed = parse_bird(text).unwrap();
    assert_eq!(parsed, vec![entry(p4([203, 0, 113, 0], 24), 24, 64512)]);
}

#[test]
fn bird_accepts_as_prefix() {
    let text = "roa 203.0.113.0/24 max 24 as AS64512;\n";
    let parsed = parse_bird(text).unwrap();
    assert_eq!(parsed, vec![entry(p4([203, 0, 113, 0], 24), 24, 64512)]);
}

#[test]
fn bird_skips_comments() {
    let text = r#"
# A comment
// C++-style comment
roa 203.0.113.0/24 max 24 as 64512;
"#;
    let parsed = parse_bird(text).unwrap();
    assert_eq!(parsed, vec![entry(p4([203, 0, 113, 0], 24), 24, 64512)]);
}

#[test]
fn bird_rejects_missing_prefix() {
    let text = "roa max 24 as 64512;\n";
    let err = parse_bird(text).unwrap_err();
    assert!(err.to_string().contains("without a prefix"), "{err}");
}

#[test]
fn bird_rejects_missing_asn() {
    let text = "roa 203.0.113.0/24 max 24;\n";
    let err = parse_bird(text).unwrap_err();
    assert!(err.to_string().contains("'asn'"), "{err}");
}

// ============================================================
// JSON format (Routinator)
// ============================================================

#[test]
fn json_parses_routinator_output() {
    let text = r#"{
  "metadata": {"generated": 1685455841, "generatedTime": "2023-05-30T14:10:41Z"},
  "roas": [
    {"asn": "AS196615", "prefix": "93.175.147.0/24", "maxLength": 24, "ta": "ripe"},
    {"asn": "AS64512", "prefix": "203.0.113.0/24", "maxLength": 26, "ta": "ripe"}
  ]
}"#;
    let parsed = parse_json(text).unwrap();
    assert_eq!(
        parsed,
        vec![
            entry(p4([93, 175, 147, 0], 24), 24, 196615),
            entry(p4([203, 0, 113, 0], 24), 26, 64512),
        ]
    );
}

#[test]
fn json_bare_asn_number_parses() {
    let text = r#"{"roas":[{"asn": 64512, "prefix": "203.0.113.0/24", "maxLength": 24}]}"#;
    let parsed = parse_json(text).unwrap();
    assert_eq!(parsed, vec![entry(p4([203, 0, 113, 0], 24), 24, 64512)]);
}

#[test]
fn json_omits_maxlength_means_exact() {
    let text = r#"{"roas":[{"asn": "AS64512", "prefix": "203.0.113.0/24"}]}"#;
    let parsed = parse_json(text).unwrap();
    assert_eq!(parsed, vec![entry(p4([203, 0, 113, 0], 24), 24, 64512)]);
}

#[test]
fn json_skips_unknown_top_level_keys() {
    let text = r#"{
  "metadata": {"counts": 2, "parameters": {"rsync": true}},
  "roas": [
    {"asn": "AS64512", "prefix": "203.0.113.0/24", "maxLength": 24, "ta": "ripe"}
  ],
  "future": {"unknown": "key"}
}"#;
    let parsed = parse_json(text).unwrap();
    assert_eq!(parsed, vec![entry(p4([203, 0, 113, 0], 24), 24, 64512)]);
}

#[test]
fn json_rejects_truncated_input() {
    let text = r#"{"roas":[{"asn":"AS64512","#;
    let err = parse_json(text).unwrap_err();
    assert!(matches!(err, RoaLoaderError::BadJson { .. }), "{err}");
}

#[test]
fn json_rejects_missing_prefix() {
    let text = r#"{"roas":[{"asn":"AS64512","maxLength":24}]}"#;
    let err = parse_json(text).unwrap_err();
    assert!(err.to_string().contains("'prefix'"), "{err}");
}

#[test]
fn json_rejects_missing_asn() {
    let text = r#"{"roas":[{"prefix":"203.0.113.0/24","maxLength":24}]}"#;
    let err = parse_json(text).unwrap_err();
    assert!(err.to_string().contains("'asn'"), "{err}");
}

#[test]
fn json_empty_roas_array() {
    let text = r#"{"metadata":{},"roas":[]}"#;
    let parsed = parse_json(text).unwrap();
    assert!(parsed.is_empty());
}

#[test]
fn json_handles_escaped_strings() {
    // A trust anchor with a quoted backslash. The value is ignored,
    // but the parser must walk it without choking.
    let text = r#"{"roas":[{"asn":"AS64512","prefix":"203.0.113.0/24","ta":"ri\npe"}]}"#;
    let parsed = parse_json(text).unwrap();
    assert_eq!(parsed, vec![entry(p4([203, 0, 113, 0], 24), 24, 64512)]);
}

#[test]
fn json_ipv6_prefix() {
    let text = r#"{"roas":[{"asn":"AS64512","prefix":"2001:db8::/32","maxLength":48}]}"#;
    let parsed = parse_json(text).unwrap();
    assert_eq!(
        parsed,
        vec![entry(
            p6(
                [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                32
            ),
            48,
            64512
        )]
    );
}

// ============================================================
// CSV / plain text format
// ============================================================

#[test]
fn csv_parses_routinator_csv_with_header() {
    let text = "ASN,Prefix,MaxLength,TrustAnchor\n\
                AS64512,203.0.113.0/24,24,ripe\n\
                AS64513,198.51.100.0/24,26,ripe\n";
    let parsed = parse_csv(text).unwrap();
    assert_eq!(
        parsed,
        vec![
            entry(p4([203, 0, 113, 0], 24), 24, 64512),
            entry(p4([198, 51, 100, 0], 24), 26, 64513),
        ]
    );
}

#[test]
fn csv_parses_csv_without_header() {
    let text = "AS64512,203.0.113.0/24,24\nAS64513,198.51.100.0/24,26\n";
    let parsed = parse_csv(text).unwrap();
    assert_eq!(
        parsed,
        vec![
            entry(p4([203, 0, 113, 0], 24), 24, 64512),
            entry(p4([198, 51, 100, 0], 24), 26, 64513),
        ]
    );
}

#[test]
fn csv_parses_whitespace_separated() {
    // The form `awk '{print $1, $2, $3}'` produces.
    let text = "AS64512 203.0.113.0/24 24\nAS64513 198.51.100.0/24 26\n";
    let parsed = parse_csv(text).unwrap();
    assert_eq!(
        parsed,
        vec![
            entry(p4([203, 0, 113, 0], 24), 24, 64512),
            entry(p4([198, 51, 100, 0], 24), 26, 64513),
        ]
    );
}

#[test]
fn csv_two_fields_means_exact() {
    let text = "AS64512,203.0.113.0/24\n";
    let parsed = parse_csv(text).unwrap();
    assert_eq!(parsed, vec![entry(p4([203, 0, 113, 0], 24), 24, 64512)]);
}

#[test]
fn csv_bare_digits_asn() {
    let text = "64512,203.0.113.0/24,24\n";
    let parsed = parse_csv(text).unwrap();
    assert_eq!(parsed, vec![entry(p4([203, 0, 113, 0], 24), 24, 64512)]);
}

#[test]
fn csv_skips_comments() {
    let text = "# header comment\nAS64512,203.0.113.0/24,24\n";
    let parsed = parse_csv(text).unwrap();
    assert_eq!(parsed, vec![entry(p4([203, 0, 113, 0], 24), 24, 64512)]);
}

#[test]
fn csv_rejects_too_few_fields() {
    let text = "AS64512\n";
    let err = parse_csv(text).unwrap_err();
    assert!(err.to_string().contains("at least"), "{err}");
}

#[test]
fn csv_ignores_trailing_columns() {
    let text = "AS64512,203.0.113.0/24,24,ripe,extra\n";
    let parsed = parse_csv(text).unwrap();
    assert_eq!(parsed, vec![entry(p4([203, 0, 113, 0], 24), 24, 64512)]);
}

#[test]
fn csv_rejects_bad_asn() {
    let text = "notanumber,203.0.113.0/24,24\n";
    let err = parse_csv(text).unwrap_err();
    assert!(err.to_string().contains("bad asn"), "{err}");
}

#[test]
fn csv_header_only_returns_empty() {
    let text = "ASN,Prefix,MaxLength,TrustAnchor\n";
    let parsed = parse_csv(text).unwrap();
    assert!(parsed.is_empty());
}

// ============================================================
// Cross-format round-trip
// ============================================================

#[test]
fn all_formats_produce_same_entries() {
    // The same two records, expressed in each format, must
    // produce the same entry list. This is the determinism
    // invariant the loader relies on for hot-reload (an operator
    // swapping a file's format must not perturb the table).
    let entries = vec![
        entry(p4([203, 0, 113, 0], 24), 24, 64512),
        entry(p4([198, 51, 100, 0], 24), 26, 64513),
    ];
    let native = r#"
[[roa]]
prefix = "203.0.113.0/24"
asn = 64512

[[roa]]
prefix = "198.51.100.0/24"
max_length = 26
asn = 64513
"#;
    let bird = "roa 203.0.113.0/24 max 24 as 64512;\nroa 198.51.100.0/24 max 26 as 64513;\n";
    let json = r#"{"roas":[
        {"asn":"AS64512","prefix":"203.0.113.0/24","maxLength":24},
        {"asn":"AS64513","prefix":"198.51.100.0/24","maxLength":26}
    ]}"#;
    let csv = "AS64512,203.0.113.0/24,24\nAS64513,198.51.100.0/24,26\n";
    assert_eq!(parse_native(native).unwrap(), entries);
    assert_eq!(parse_bird(bird).unwrap(), entries);
    assert_eq!(parse_json(json).unwrap(), entries);
    assert_eq!(parse_csv(csv).unwrap(), entries);
}
