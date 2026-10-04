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
/// Attribution configurations (ADR 0006): the canonical file and its platform
/// variant with `@redact-secret/core` 0.1.0-beta.12, run with
/// `--node-dir adapters/node-core-beta.12`. They differ from their counterpart only
/// in the `redact-secret` pin.
const BETA12: &[(&str, &str)] = &[
    (
        "configs/official/credential-public-v1.core-beta.12.json",
        CANONICAL,
    ),
    (
        "configs/official/credential-public-v1.core-beta.12.darwin-arm64.json",
        "configs/official/credential-public-v1.darwin-arm64.json",
    ),
];
/// Node shim directory (lockfile) each configuration family is run with.
const NODE_DIR: &str = "adapters/node";
const NODE_DIR_BETA12: &str = "adapters/node-core-beta.12";

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
    all.extend(BETA12.iter().map(|(path, _)| *path));
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
            let npm = spec.configuration.contains_key("package");
            assert_eq!(
                (pin.integrity.is_some(), pin.resolved.is_some()),
                (npm, npm),
                "{path}: {id} has a registry integrity and tarball exactly when it is an npm package"
            );
            if let Some(integrity) = &pin.integrity {
                assert!(integrity.starts_with("sha512-"), "{path}: {id}");
            }
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

/// Configurations that differ from another one only in the `redact-secret`
/// pin: the beta.12 attribution runs.
#[test]
fn attribution_configs_differ_only_in_the_redact_secret_pin() {
    fn strip(mut config: Value) -> Value {
        for scanner in config["scanners"].as_array_mut().expect("scanners") {
            if scanner["id"] == "redact-secret" {
                scanner.as_object_mut().expect("scanner").remove("pin");
            }
        }
        config
    }
    for (path, counterpart) in BETA12 {
        let (alt, base) = (read_json(path), read_json(counterpart));
        assert_ne!(alt, base, "{path}");
        assert_eq!(strip(alt.clone()), strip(base.clone()), "{path}");
        let pin = |config: &Value| {
            config["scanners"]
                .as_array()
                .expect("scanners")
                .iter()
                .find(|s| s["id"] == "redact-secret")
                .expect("redact-secret")["pin"]["version"]
                .clone()
        };
        assert_eq!(pin(&base), "0.1.0-beta.13", "{counterpart}");
        assert_eq!(pin(&alt), "0.1.0-beta.12", "{path}");
    }
}

/// npm scanners are pinned by exact version, registry integrity and resolved
/// tarball here; each must equal the lockfile of the shim directory the
/// configuration is run with.
#[test]
fn npm_pins_match_the_node_shim_lockfile() {
    for path in all_configs() {
        let dir = if BETA12.iter().any(|(alt, _)| *alt == path) {
            NODE_DIR_BETA12
        } else {
            NODE_DIR
        };
        let lock = read_json(&format!("{dir}/package-lock.json"));
        let config: RunConfig = serde_json::from_value(read_json(path)).expect("config");
        for spec in &config.scanners {
            let Some(package) = spec.configuration.get("package").and_then(Value::as_str) else {
                continue;
            };
            let entry = &lock["packages"][format!("node_modules/{package}")];
            let pin = spec.pin.as_ref().expect("pinned");
            assert_eq!(
                entry["version"].as_str(),
                Some(pin.version.as_str()),
                "{path}: {package}"
            );
            assert_eq!(
                entry["integrity"].as_str(),
                pin.integrity.as_deref(),
                "{path}: {package}"
            );
            assert_eq!(
                entry["resolved"].as_str(),
                pin.resolved.as_deref(),
                "{path}: {package}"
            );
            assert!(
                pin.integrity
                    .as_deref()
                    .is_some_and(|i| i.starts_with("sha512-")),
                "{path}: {package} has a sha512 integrity"
            );
            assert_eq!(
                pin.resolved
                    .as_deref()
                    .map(|r| r.starts_with("https://registry.npmjs.org/")),
                Some(true),
                "{path}: {package} resolves from the npm registry"
            );
        }
    }
}

/// The two shim directories run one shim over two lockfiles that differ only
/// in the `@redact-secret/core` family, so the beta.12 attribution run changes
/// nothing but the product build.
#[test]
fn the_attribution_node_dir_shares_the_shim_and_differs_only_in_the_core_family() {
    let shim = |dir: &str| fs::read(repo().join(dir).join("shim.mjs")).expect("shim");
    assert_eq!(
        shim(NODE_DIR),
        shim(NODE_DIR_BETA12),
        "one shim, byte for byte"
    );
    let packages = |dir: &str| {
        read_json(&format!("{dir}/package-lock.json"))["packages"]
            .as_object()
            .expect("packages")
            .clone()
    };
    let (current, old) = (packages(NODE_DIR), packages(NODE_DIR_BETA12));
    assert_eq!(
        current.keys().collect::<Vec<_>>(),
        old.keys().collect::<Vec<_>>()
    );
    for (name, entry) in &current {
        let core = name.starts_with("node_modules/@redact-secret/") || name.is_empty();
        assert_eq!(entry == &old[name], !core, "{name}");
    }
    for (dir, version) in [
        (NODE_DIR, "0.1.0-beta.13"),
        (NODE_DIR_BETA12, "0.1.0-beta.12"),
    ] {
        let package = read_json(&format!("{dir}/package.json"));
        assert_eq!(
            package["dependencies"]["@redact-secret/core"], version,
            "{dir}"
        );
    }
}

/// The official measurement runs over decoded and percent-encoded evidence
/// that two binary scanners report where the adapter cannot place a finding,
/// and over 35,322 methods variants where OpenRedaction's stdout is several
/// hundred MiB (ADR 0003, ADR 0004). Dropping either choice makes the
/// official methods run refuse again.
#[test]
fn official_configs_choose_per_case_handling_and_a_sufficient_stdout_bound() {
    for path in all_configs() {
        let config: RunConfig = serde_json::from_value(read_json(path)).expect(path);
        for spec in &config.scanners {
            let id = spec.id.as_str();
            let policy = spec.configuration.get("unmappable_findings");
            if ["gitleaks", "trufflehog"].contains(&id) {
                assert_eq!(
                    policy,
                    Some(&Value::from("unmeasured-case")),
                    "{path}: {id}"
                );
            } else {
                assert_eq!(policy, None, "{path}: {id} implements no per-case handling");
            }
            // The representation contract (ADR 0005): both binary scanners place
            // decoded findings on the original bytes when the rule can prove it.
            let decoded = spec.configuration.get("decoded_mapping");
            if ["gitleaks", "trufflehog"].contains(&id) {
                assert_eq!(
                    decoded,
                    Some(&Value::from("source-segment")),
                    "{path}: {id}"
                );
            } else {
                assert_eq!(decoded, None, "{path}: {id} implements no decoded mapping");
            }
            if id == "openredaction" {
                assert!(
                    spec.limits.max_stdout_bytes >= 1 << 30,
                    "{path}: openredaction methods output exceeds 256 MiB"
                );
            }
        }
    }
}
