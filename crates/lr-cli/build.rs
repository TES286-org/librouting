//! Emits the workspace crate list that `lr version` prints.
//!
//! The list used to be a hand-typed literal in `main.rs` and had already
//! drifted: it named 15 crates while the workspace had 18 members. It is
//! derived from the workspace manifest instead, so adding a member is
//! enough to make it appear.

use std::env;
use std::fs;
use std::path::PathBuf;

fn main() {
    // crates/lr-cli/ -> crates/ -> workspace root.
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let workspace = manifest_dir.join("..").join("..").join("Cargo.toml");
    println!("cargo:rerun-if-changed={}", workspace.display());

    let text = fs::read_to_string(&workspace)
        .unwrap_or_else(|e| panic!("cannot read {}: {e}", workspace.display()));
    let names = workspace_members(&text);
    assert!(
        !names.is_empty(),
        "no workspace members found in {}",
        workspace.display()
    );
    println!("cargo:rustc-env=LR_CRATE_LIST={}", names.join(", "));
}

/// The crate names in the workspace's `members` array, in manifest order.
fn workspace_members(text: &str) -> Vec<String> {
    let Some(anchor) = text.find("members") else {
        return Vec::new();
    };
    let rest = &text[anchor..];
    let Some(open) = rest.find('[') else {
        return Vec::new();
    };
    let rest = &rest[open..];
    let Some(close) = rest.find(']') else {
        return Vec::new();
    };
    rest[1..close]
        .split(',')
        .filter_map(|entry| {
            let entry = entry.trim().trim_matches('"').trim();
            if entry.is_empty() {
                return None;
            }
            // "crates/lr-bgp" -> "lr-bgp"
            entry.rsplit('/').next().map(str::to_string)
        })
        .collect()
}
