//! Corpus-driven parser regression tests (ROADMAP-v3 D6.4).
//!
//! The committed fuzz seed corpus under `fuzz/seeds/filter_parser/`
//! doubles as a deterministic regression suite for the filter DSL
//! parser. Every seed must run through
//! [`lr_policy::filter::compile`] without panicking — `Ok` or `Err`
//! are both acceptable, an abort is not.
//!
//! The `nested_set_fuzz_crash_2026_09_14.bin` seed is the crashing
//! input the nightly `filter_parser` cargo-fuzz target found
//! (AddressSanitizer stack-overflow: ~3 900 nested `[` set opens,
//! the recursive-descent parser had no depth bound). It is now
//! rejected by the [`lr_policy::filter::parser::MAX_EXPR_DEPTH`]
//! recursion limit instead of overflowing the stack; this test pins
//! that contract against the exact bytes the fuzzer produced.

use std::path::PathBuf;

fn seed_dir() -> Option<PathBuf> {
    // `crates/lr-policy/tests/` -> repo root -> `fuzz/seeds/…`.
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let dir = manifest
        .join("..")
        .join("..")
        .join("fuzz")
        .join("seeds")
        .join("filter_parser");
    dir.canonicalize().ok()
}

#[test]
fn every_fuzz_seed_compiles_without_panicking() {
    let Some(dir) = seed_dir() else {
        // The fuzz workspace is optional in a trimmed checkout —
        // nothing to do when the corpus is absent.
        eprintln!("fuzz/seeds/filter_parser not found; skipping corpus test");
        return;
    };

    let mut checked = 0usize;
    let mut rejected = 0usize;
    for entry in std::fs::read_dir(&dir).expect("read seed dir") {
        let path = entry.expect("seed entry").path();
        if path.extension().and_then(|e| e.to_str()) != Some("bin") {
            continue;
        }
        let bytes = std::fs::read(&path).expect("read seed");
        let body = String::from_utf8_lossy(&bytes);
        // Same contract as the fuzz target: Ok or Err, never a panic.
        let result = lr_policy::filter::compile("corpus", &body);
        if result.is_err() {
            rejected += 1;
        }
        checked += 1;
    }
    assert!(checked >= 6, "expected the committed corpus, got {checked}");
    // The nested-set crasher and the reject/garbage seeds are
    // expected to be *rejected*, not accepted.
    assert!(rejected >= 2, "expected some seeds to be rejected");
}

#[test]
fn nightly_nested_set_crasher_is_now_rejected_not_fatal() {
    let Some(dir) = seed_dir() else {
        eprintln!("fuzz/seeds/filter_parser not found; skipping crasher test");
        return;
    };
    let crasher = dir.join("nested_set_fuzz_crash_2026_09_14.bin");
    let bytes = std::fs::read(&crasher).expect("the nightly crasher seed is committed");
    let body = String::from_utf8_lossy(&bytes);
    let result = lr_policy::filter::compile("corpus", &body);
    assert!(result.is_err(), "the stack-overflow input must be rejected");
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("nests deeper than the maximum"),
        "unexpected error: {err}"
    );
}
