//! The npm registry pin of an official run (contract revision v1.4, ADR 0006):
//! exact version, `sha512` integrity and resolved tarball, checked against the
//! lockfile, the record npm wrote at install time, and run provenance.

use std::fs;
use std::path::Path;

use credential_eval_cli::official::check_package_pin;
use credential_eval_contracts::config::{NetworkPolicy, ScannerPin, ScannerSpec};
use credential_eval_contracts::observation::{
    ProvenanceComponent, ProvenanceKind, ScannerProvenance,
};
use serde_json::{Value, json};

const PACKAGE: &str = "@redact-secret/core";
const VERSION: &str = "0.1.0-beta.13";
const INTEGRITY: &str = "sha512-AAAA";
const RESOLVED: &str = "https://registry.npmjs.org/@redact-secret/core/-/core-0.1.0-beta.13.tgz";

fn lock(version: &str, integrity: &str, resolved: &str) -> String {
    json!({"lockfileVersion": 3, "packages": {format!("node_modules/{PACKAGE}"): {
        "version": version, "integrity": integrity, "resolved": resolved}}})
    .to_string()
}

fn root(locked: &str, installed: Option<&str>) -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join("package-lock.json"), locked).unwrap();
    if let Some(installed) = installed {
        fs::create_dir_all(dir.path().join("node_modules")).unwrap();
        fs::write(
            dir.path().join("node_modules/.package-lock.json"),
            installed,
        )
        .unwrap();
    }
    dir
}

fn spec(pin: ScannerPin, source: &str) -> ScannerSpec {
    let mut spec = credential_eval_adapters::find("redact-secret")
        .unwrap()
        .default_spec();
    spec.network = NetworkPolicy::Disabled;
    spec.configuration
        .insert("package_source".into(), Value::from(source));
    spec.pin = Some(pin);
    spec
}

fn pin() -> ScannerPin {
    ScannerPin {
        version: VERSION.into(),
        sha256: None,
        integrity: Some(INTEGRITY.into()),
        resolved: Some(RESOLVED.into()),
    }
}

fn provenance(integrity: &str) -> ScannerProvenance {
    ScannerProvenance {
        network: NetworkPolicy::Disabled,
        network_controls: Vec::new(),
        components: vec![ProvenanceComponent {
            kind: ProvenanceKind::NpmPackage,
            name: PACKAGE.into(),
            version: Some(VERSION.into()),
            sha256: None,
            integrity: Some(integrity.into()),
        }],
    }
}

fn check(dir: &Path, pin: ScannerPin, integrity: &str) -> Result<(), String> {
    check_package_pin(&spec(pin, "published"), dir, &provenance(integrity))
}

#[test]
fn a_matching_install_passes_and_executable_pins_are_not_checked() {
    let good = lock(VERSION, INTEGRITY, RESOLVED);
    let dir = root(&good, Some(&good));
    assert_eq!(check(dir.path(), pin(), INTEGRITY), Ok(()));
    let bare = ScannerPin {
        integrity: None,
        resolved: None,
        ..pin()
    };
    assert_eq!(check(Path::new("/nonexistent"), bare, "x"), Ok(()));
}

#[test]
fn every_disagreement_is_refused() {
    let good = lock(VERSION, INTEGRITY, RESOLVED);
    let refuse = |locked: &str, installed: Option<&str>, pin, integrity: &str, needle: &str| {
        let dir = root(locked, installed);
        let error = check(dir.path(), pin, integrity).unwrap_err();
        assert!(error.contains(needle), "{error}");
    };
    // The lockfile is another build (beta.12 against a beta.13 pin).
    let older_core = lock(
        "0.1.0-beta.12",
        "sha512-BBBB",
        "https://registry.npmjs.org/x-beta.12.tgz",
    );
    refuse(
        &older_core,
        Some(&older_core),
        pin(),
        INTEGRITY,
        "lockfile version 0.1.0-beta.12",
    );
    // Same version, different bytes.
    let forged = lock(VERSION, "sha512-CCCC", RESOLVED);
    refuse(
        &forged,
        Some(&forged),
        pin(),
        INTEGRITY,
        "lockfile integrity sha512-CCCC",
    );
    // Same version and integrity from another registry.
    let mirror = lock(VERSION, INTEGRITY, "https://mirror.example/core.tgz");
    refuse(
        &mirror,
        Some(&mirror),
        pin(),
        INTEGRITY,
        "lockfile resolved",
    );
    // node_modules was installed from something else, or not by npm ci.
    refuse(
        &good,
        Some(&forged),
        pin(),
        INTEGRITY,
        "install record integrity",
    );
    refuse(&good, None, pin(), INTEGRITY, "no install record");
    // Provenance disagrees with the pin.
    refuse(
        &good,
        Some(&good),
        pin(),
        "sha512-DDDD",
        "provenance integrity",
    );
    // The lockfile lacks the package.
    let dir = root("{}", Some("{}"));
    assert!(
        check(dir.path(), pin(), INTEGRITY)
            .unwrap_err()
            .contains("not in the lockfile")
    );
}

#[test]
fn a_candidate_package_cannot_carry_a_registry_pin() {
    let good = lock(VERSION, INTEGRITY, RESOLVED);
    let dir = root(&good, Some(&good));
    let error = check_package_pin(
        &spec(pin(), "candidate"),
        dir.path(),
        &provenance(INTEGRITY),
    )
    .unwrap_err();
    assert!(error.contains("published only"), "{error}");
}
