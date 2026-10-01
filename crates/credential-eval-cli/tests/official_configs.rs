//! The committed official run configurations under `configs/official/`
//! (`docs/official-runs.md`, "Official configuration"). They are inputs of the
//! official measurement, so they must stay schema-valid, fully pinned,
//! network-off, and consistent with each other and with the Node shim
//! lockfile.

mod common;

use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

use common::repo;
use credential_eval_cli::official;
use credential_eval_contracts::config::{NetworkPolicy, RunConfig};
use serde_json::Value;

/// Canonical (linux-x64) configuration of the public credential population.
const CANONICAL: &str = "configs/official/credential-public-v1.json";
/// Platform variants: identical to the canonical file except `pin.sha256`.
const VARIANTS: &[&str] = &["configs/official/credential-public-v1.darwin-arm64.json"];

const SCANNERS: &[&str] = &[
    "flare-redact",
    "gitleaks",
    "openredaction",
    "redact-secret",
    "trufflehog",
];
const EXECUTABLES: &[&str] = &["gitleaks", "trufflehog"];

fn read_json(path: &str) -> Value {
    serde_json::from_slice(&fs::read(repo().join(path)).expect(path)).expect(path)
}

fn all_configs() -> Vec<&'static str> {
    let mut all = vec![CANONICAL];
    all.extend_from_slice(VARIANTS);
    all
}

#[test]
fn official_configs_are_listed() {
    let dir: PathBuf = repo().join("configs/official");
    let on_disk: BTreeSet<String> = fs::read_dir(&dir)
        .expect("configs/official")
        .map(|e| e.expect("entry").file_name().to_string_lossy().into_owned())
        .filter(|name| name.ends_with(".json"))
        .collect();
    let listed: BTreeSet<String> = all_configs()
        .iter()
        .map(|p| p.rsplit('/').next().unwrap().to_owned())
        .collect();
    assert_eq!(on_disk, listed, "every official config is covered here");
}

#[test]
fn official_configs_validate_and_are_fully_pinned() {
    let schema = read_json("schemas/run-config-v1.schema.json");
    let validator = jsonschema::validator_for(&schema).expect("schema compiles");
    for path in all_configs() {
        let instance = read_json(path);
        let errors: Vec<String> = validator
            .iter_errors(&instance)
            .map(|e| e.to_string())
            .collect();
        assert!(errors.is_empty(), "{path}: {errors:?}");

        let config: RunConfig = serde_json::from_value(instance).expect(path);
        official::check_official_config(&config).expect(path);
        assert!(config.methods.is_empty(), "{path}: corpus measurement only");
        let ids: Vec<&str> = config.scanners.iter().map(|s| s.id.as_str()).collect();
        assert_eq!(ids, SCANNERS, "{path}");
        for spec in &config.scanners {
            let id = spec.id.as_str();
            assert_eq!(spec.network, NetworkPolicy::Disabled, "{path}: {id}");
            let pin = spec.pin.as_ref().expect("pinned");
            assert_eq!(
                pin.sha256.is_some(),
                EXECUTABLES.contains(&id),
                "{path}: {id} has an executable digest exactly when it is a binary"
            );
            if let Some(required) = spec.configuration.get("required_version") {
                assert_eq!(
                    required.as_str(),
                    Some(pin.version.as_str()),
                    "{path}: {id}"
                );
            }
            if let Some(source) = spec.configuration.get("package_source") {
                assert_eq!(source, "published", "{path}: {id} is a released build");
            }
        }
    }
}

/// Platform variants may differ from the canonical file only in the
/// executable digests, so both measure the same thing.
#[test]
fn platform_variants_differ_only_in_executable_digests() {
    fn strip(mut config: Value) -> Value {
        for scanner in config["scanners"].as_array_mut().expect("scanners") {
            if let Some(pin) = scanner.get_mut("pin").and_then(Value::as_object_mut) {
                pin.remove("sha256");
            }
        }
        config
    }
    let canonical = read_json(CANONICAL);
    for path in VARIANTS {
        let variant = read_json(path);
        assert_ne!(canonical, variant, "{path} pins its own digests");
        assert_eq!(strip(canonical.clone()), strip(variant), "{path}");
    }
}

/// npm scanners are pinned by version here and by integrity in the Node shim
/// lockfile; the two must agree.
#[test]
fn npm_pins_match_the_node_shim_lockfile() {
    let lock = read_json("adapters/node/package-lock.json");
    let config: RunConfig = serde_json::from_value(read_json(CANONICAL)).expect("config");
    for spec in &config.scanners {
        let Some(package) = spec.configuration.get("package").and_then(Value::as_str) else {
            continue;
        };
        let entry = &lock["packages"][format!("node_modules/{package}")];
        assert_eq!(
            entry["version"].as_str(),
            Some(spec.pin.as_ref().expect("pinned").version.as_str()),
            "{package}"
        );
        assert!(
            entry["integrity"]
                .as_str()
                .is_some_and(|i| i.starts_with("sha512-")),
            "{package} has an integrity"
        );
    }
}
