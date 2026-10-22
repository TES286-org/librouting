//! Golden-file corpus for `lr translate bird|frr`.
//!
//! Each `.conf` file under `tests/corpus/{bird,frr}/` is a real-world
//! BIRD or FRR configuration covering one shape the converter maps
//! today. The matching `.expected.toml` file is the converter's exact
//! output, committed to the repository. A new dialect quirk adds a
//! corpus case (input + expected) instead of a bespoke assertion —
//! the corpus is the regression net.
//!
//! Run `LR_CORPUS_UPDATE=1 cargo test -p lr-cli --bin lr-daemon
//! translate::corpus_tests` to regenerate the `.expected.toml` files
//! after an intentional converter change; otherwise the harness
//! golden-diffs every case and fails on the first mismatch with a
//! unified diff.

use super::{render, translate_bird, translate_frr};
use crate::daemon_config::DaemonConfig;
use std::path::{Path, PathBuf};

/// The repository's `tests/corpus/` directory, resolved from the
/// `lr-cli` crate manifest so the test works under `cargo test` run
/// from the workspace root or the crate root alike.
fn corpus_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("tests")
        .join("corpus")
}

/// One corpus case: the input config path, the dialect, and the
/// matching `.expected.toml` path.
struct Case {
    input: PathBuf,
    expected: PathBuf,
    dialect: Dialect,
}

#[derive(Copy, Clone)]
enum Dialect {
    Bird,
    Frr,
}

impl Dialect {
    fn convert(self, text: &str) -> String {
        match self {
            Dialect::Bird => render(translate_bird(text)),
            Dialect::Frr => render(translate_frr(text)),
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Dialect::Bird => "bird",
            Dialect::Frr => "frr",
        }
    }
}

/// Walk `tests/corpus/{bird,frr}/` and collect one [`Case`] per
/// `.conf` file. Returns the cases sorted by (dialect, name) so a
/// failure report is stable across runs and platforms.
fn collect_cases() -> Vec<Case> {
    let root = corpus_root();
    let mut cases = Vec::new();
    for (sub, dialect) in [("bird", Dialect::Bird), ("frr", Dialect::Frr)] {
        let dir = root.join(sub);
        let entries = match std::fs::read_dir(&dir) {
            Ok(e) => e,
            Err(_) => continue,
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) == Some("conf") {
                let expected = path.with_extension("expected.toml");
                cases.push(Case {
                    input: path,
                    expected,
                    dialect,
                });
            }
        }
    }
    cases.sort_by(|a, b| {
        (a.dialect.as_str(), a.input.file_name()).cmp(&(b.dialect.as_str(), b.input.file_name()))
    });
    cases
}

/// Round-trip the rendered TOML through the daemon loader so the
/// corpus also locks in the "the generated TOML is always loadable"
/// contract. OSPF cases load with `protocol = "ospf"` (the OSPF
/// tables are validated, not warned about); everything else loads as
/// the default BGP protocol (Babel interface tables are tolerated as
/// data under any protocol).
fn roundtrip(toml: &str) {
    let mut cfg = DaemonConfig::with_defaults();
    cfg.protocol = if toml.contains("[[ospf.") {
        "ospf".to_string()
    } else {
        "bgp".to_string()
    };
    crate::daemon_config::parse_toml_subset(toml, &mut cfg)
        .expect("corpus: generated TOML must load");
    cfg.finalize()
        .expect("corpus: generated TOML must finalize");
}

/// Normalise line endings to `\n`. The `.expected.toml` files are
/// committed with LF endings, but Git for Windows checks them out as
/// CRLF under the default `core.autocrlf=true` — so a string compare
/// of the converter's LF output against the file read from disk would
/// fail on every case even though the line content is identical.
/// Normalising both sides (and on regen) makes the gate
/// platform-independent without depending on a per-repo `.gitattributes`.
fn normalize_eol(text: &str) -> String {
    text.replace("\r\n", "\n").replace('\r', "\n")
}

/// A minimal unified diff between two texts, built on a longest-common-
/// subsequence so the failure report stays readable for a multi-section
/// TOML. Returns the diff text (empty when the inputs are identical).
fn unified_diff(expected: &str, actual: &str) -> String {
    let exp: Vec<&str> = expected.lines().collect();
    let act: Vec<&str> = actual.lines().collect();
    let lcs = lcs_table(&exp, &act);
    let mut out = String::new();
    let (mut i, mut j) = (0usize, 0usize);
    while i < exp.len() || j < act.len() {
        if i < exp.len() && j < act.len() && exp[i] == act[j] {
            i += 1;
            j += 1;
        } else if j < act.len() && (i == exp.len() || lcs[i + 1][j] >= lcs[i][j + 1]) {
            out.push_str(&format!("+ {}\n", act[j]));
            j += 1;
        } else {
            out.push_str(&format!("- {}\n", exp[i]));
            i += 1;
        }
    }
    out
}

/// LCS dynamic-programming table used by [`unified_diff`].
fn lcs_table(a: &[&str], b: &[&str]) -> Vec<Vec<usize>> {
    let (n, m) = (a.len(), b.len());
    let mut dp = vec![vec![0usize; m + 1]; n + 1];
    for i in (0..n).rev() {
        for j in (0..m).rev() {
            dp[i][j] = if a[i] == b[j] {
                dp[i + 1][j + 1] + 1
            } else {
                dp[i + 1][j].max(dp[i][j + 1])
            };
        }
    }
    dp
}

#[test]
fn corpus_translates_without_regression() {
    let update = std::env::var("LR_CORPUS_UPDATE").is_ok();
    let cases = collect_cases();
    assert!(
        !cases.is_empty(),
        "corpus: no .conf files found under {} — the corpus is empty",
        corpus_root().display()
    );
    let mut failures = Vec::new();
    for case in &cases {
        let input = match std::fs::read_to_string(&case.input) {
            Ok(t) => t,
            Err(e) => {
                failures.push(format!("{}: cannot read input: {e}", case.input.display()));
                continue;
            }
        };
        let actual = case.dialect.convert(&input);
        // Every corpus case must round-trip through the daemon loader.
        if let Err(e) = std::panic::catch_unwind(|| roundtrip(&actual)) {
            failures.push(format!(
                "{}: generated TOML does not round-trip through the daemon loader\n{e:?}",
                case.input.display()
            ));
            continue;
        }
        let expected = normalize_eol(&std::fs::read_to_string(&case.expected).unwrap_or_default());
        let actual = normalize_eol(&actual);
        if update {
            std::fs::write(&case.expected, &actual).unwrap_or_else(|e| {
                panic!("corpus: cannot write {}: {e}", case.expected.display())
            });
            continue;
        }
        if actual != expected {
            failures.push(format!(
                "{}:\n{}",
                case.input.display(),
                unified_diff(&expected, &actual)
            ));
        }
    }
    if update {
        eprintln!("corpus: regenerated {} .expected.toml file(s)", cases.len());
        return;
    }
    if !failures.is_empty() {
        panic!(
            "corpus golden-file mismatch ({} case(s) differ; run with \
             LR_CORPUS_UPDATE=1 to regenerate after an intentional change):\n\n{}",
            failures.len(),
            failures.join("\n---\n")
        );
    }
}
