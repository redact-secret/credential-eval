//! Canonical code, schemas and the canonical smoke fixtures must not carry
//! source-project coordinates of the legacy benchmark (suite labels such as
//! `beta<N>`, `milestone-<N>`, `issue-<N>`, `redact-secret-<N>`). Those belong
//! only to the parity projection and the migration tooling: the
//! `credential-eval-compat` crate, `compat` modules, `tools/legacy-export/`,
//! `tools/parity/` and test fixtures (docs/parity/parity-report.md).

use std::fs;
use std::path::{Path, PathBuf};

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// Allowed locations: compat code and test fixtures.
fn exempt(path: &Path) -> bool {
    let text = path.to_string_lossy().replace('\\', "/");
    text.contains("/crates/credential-eval-compat/")
        || text.contains("/compat/")
        || text.ends_with("/compat.rs")
        || text.contains("/tests/fixtures/")
        || text.contains("/target/")
}

fn files(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            files(&path, out);
        } else if !exempt(&path) {
            out.push(path);
        }
    }
}

/// Coordinates: `beta` + digit, or `milestone-`/`issue-`/`redact-secret-` + digit.
fn coordinates(text: &str) -> Vec<String> {
    let bytes = text.as_bytes();
    let mut found = Vec::new();
    for prefix in ["beta", "milestone-", "issue-", "redact-secret-"] {
        let mut from = 0;
        while let Some(i) = text[from..].find(prefix) {
            let at = from + i;
            let next = at + prefix.len();
            if bytes.get(next).is_some_and(u8::is_ascii_digit) {
                let end = text[next..]
                    .find(|c: char| !(c.is_ascii_alphanumeric() || c == '-'))
                    .map_or(text.len(), |e| next + e);
                found.push(text[at..end].to_owned());
            }
            from = next;
        }
    }
    found
}

#[test]
fn canonical_sources_carry_no_legacy_coordinates() {
    let root = root();
    let mut paths = Vec::new();
    files(&root.join("crates"), &mut paths);
    files(&root.join("schemas"), &mut paths);
    let smoke = root.join("tests/fixtures/contracts-smoke");
    for entry in fs::read_dir(&smoke).expect("smoke fixtures").flatten() {
        paths.push(entry.path());
    }
    let mut violations = Vec::new();
    for path in paths {
        let Ok(text) = fs::read_to_string(&path) else {
            continue;
        };
        for hit in coordinates(&text) {
            violations.push(format!("{}: {hit}", path.display()));
        }
    }
    assert!(
        violations.is_empty(),
        "legacy coordinates outside compat/parity tooling: {violations:?}"
    );
}

#[test]
fn the_detector_matches_coordinates_only() {
    let p = |s: &str| format!("{s}{}", 7);
    assert_eq!(coordinates(&p("suite beta")), vec![p("beta")]);
    assert_eq!(coordinates(&format!("{}-a", p("milestone-"))).len(), 1);
    assert_eq!(coordinates(&p("issue-")).len(), 1);
    assert_eq!(coordinates(&p("redact-secret-")).len(), 1);
    assert!(coordinates("0.1.0-beta.11 betamax issue-tracker redact-secret-only").is_empty());
}
