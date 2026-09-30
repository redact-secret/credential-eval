//! Shared helpers for the orchestration tests: the contracts-smoke corpus,
//! fake scanner executables, and schema validation.

#![allow(dead_code)]

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use credential_eval_adapters::AdapterEnv;
use credential_eval_adapters::process::CancelToken;
use credential_eval_cli::orchestrate::{self, RunOutput, RunRequest};
use credential_eval_contracts::artifact::RunArtifact;
use credential_eval_contracts::config::{RunConfig, ScannerSpec};
use credential_eval_contracts::corpus::CorpusSnapshot;
use credential_eval_contracts::ids::ScannerId;
use serde_json::{Value, json};

pub fn repo() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

pub fn smoke_corpus() -> CorpusSnapshot {
    let bytes = fs::read(repo().join("tests/fixtures/contracts-smoke/corpus-snapshot.json"))
        .expect("corpus");
    CorpusSnapshot::from_json(&bytes).expect("valid corpus")
}

/// Write an executable `#!/bin/sh` script.
pub fn script(dir: &Path, name: &str, body: &str) -> PathBuf {
    let path = dir.join(name);
    fs::write(&path, format!("#!/bin/sh\n{body}\n")).expect("write script");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).expect("chmod");
    }
    path
}

/// A fake Gitleaks: `version` prints `version`; `dir <root> ...` runs `scan`
/// with `$root` set to the materialized root.
pub fn fake_gitleaks(dir: &Path, name: &str, version: &str, scan: &str) -> PathBuf {
    script(
        dir,
        name,
        &format!(
            "case \"$1\" in\n  version) echo '{version}'; exit 0;;\n  dir) root=\"$2\";;\n  *) exit 9;;\nesac\n{scan}"
        ),
    )
}

/// A Gitleaks-adapter scanner spec that runs `binary`.
pub fn gitleaks_spec(id: &str, binary: &Path) -> ScannerSpec {
    let adapter = credential_eval_adapters::find("gitleaks").expect("gitleaks adapter");
    let mut spec = adapter.default_spec();
    spec.id = ScannerId::new(id).expect("id");
    spec.configuration
        .insert("binary".into(), json!(binary.to_str().expect("utf-8 path")));
    spec.limits.timeout_ms = 10_000;
    spec
}

pub fn config(scanners: Vec<ScannerSpec>, jobs: u32) -> RunConfig {
    let mut config =
        credential_eval_cli::default_config(&["gitleaks".to_owned()], jobs).expect("config");
    config.scanners = scanners;
    config
}

pub fn env() -> AdapterEnv {
    AdapterEnv {
        path: Some("/usr/bin:/bin".into()),
        node_dir: repo().join("adapters/node"),
        candidate_roots: BTreeMap::new(),
        cwd: std::env::temp_dir(),
    }
}

pub fn run_with(corpus: &CorpusSnapshot, config: &RunConfig, env: &AdapterEnv) -> RunOutput {
    orchestrate::run(&RunRequest {
        corpus,
        config,
        env,
        work_dir: None,
        cancel: &CancelToken::new(),
    })
    .expect("run")
}

pub fn run(corpus: &CorpusSnapshot, config: &RunConfig) -> RunOutput {
    run_with(corpus, config, &env())
}

/// Validate a serialized artifact against the committed schema.
pub fn assert_schema_valid(artifact: &RunArtifact) {
    let schema: Value = serde_json::from_slice(
        &fs::read(repo().join("schemas/run-artifact-v1.schema.json")).expect("schema"),
    )
    .expect("schema json");
    let validator = jsonschema::validator_for(&schema).expect("schema compiles");
    let instance = serde_json::to_value(artifact).expect("artifact json");
    let errors: Vec<String> = validator
        .iter_errors(&instance)
        .map(|e| e.to_string())
        .collect();
    assert!(errors.is_empty(), "schema errors: {errors:?}");
}

/// The artifact as canonical text with non-semantic metadata cleared.
pub fn semantic_text(artifact: &RunArtifact) -> String {
    let mut copy = artifact.clone();
    copy.non_semantic = Default::default();
    serde_json::to_string_pretty(&copy).expect("serialize")
}
