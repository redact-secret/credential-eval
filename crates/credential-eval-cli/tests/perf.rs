//! End-to-end tests of `credential-eval perf run` and of the committed
//! performance configuration template (ADR 0002).

#![cfg(unix)]

use std::fs;
use std::path::PathBuf;
use std::process::Command;

use credential_eval_contracts::performance::{
    Direction, PerformanceArtifact, PerformanceConfig, WorkloadId,
};
use credential_eval_contracts::schema::all_schemas;
use serde_json::{Value, json};

fn bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_credential-eval"))
}

fn repo() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn subject(id: &str, script: &str) -> Value {
    json!({
        "id": id, "version": "test", "program": "/bin/sh",
        "args": ["-c", script], "delivery": "stdin", "ok_exit_codes": [0],
    })
}

fn config(candidate: &str) -> Value {
    json!({
        "schema": "credential-eval/performance-config/v1",
        "baseline": subject("scanner-a", "cat >/dev/null"),
        "candidate": subject("scanner-b", candidate),
        "workloads": [{"id": "repeated-short-log-lines", "units": 40}],
        "shapes": ["whole", "chunked"], "chunk_bytes": 1024,
        "rounds": 3, "batch_invocations": 1, "warmup_invocations": 1,
        "limits": {"timeout_ms": 10000, "max_input_bytes": 1048576,
                   "max_response_bytes": 65536, "max_diagnostic_bytes": 4096},
        "toolchain": [],
    })
}

fn validator() -> jsonschema::Validator {
    let schema = all_schemas()
        .into_iter()
        .find(|(file, _)| *file == "performance-artifact-v1.schema.json")
        .map(|(_, schema)| serde_json::to_value(&schema).unwrap())
        .unwrap();
    jsonschema::validator_for(&schema).unwrap()
}

#[test]
fn perf_run_writes_a_schema_valid_sanitized_artifact() {
    let dir = tempfile::tempdir().unwrap();
    let config_path = dir.path().join("config.json");
    let out = dir.path().join("artifact.json");
    fs::write(
        &config_path,
        config("sleep 0.4; cat >/dev/null").to_string(),
    )
    .unwrap();
    let output = bin()
        .args(["perf", "run", "--config"])
        .arg(&config_path)
        .arg("--out")
        .arg(&out)
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(output.status.success(), "{stderr}");
    assert!(stderr.contains("semantic digest sha256:"));

    let text = fs::read_to_string(&out).unwrap();
    let value: Value = serde_json::from_str(&text).unwrap();
    let errors: Vec<String> = validator()
        .iter_errors(&value)
        .map(|e| e.to_string())
        .collect();
    assert!(errors.is_empty(), "{errors:?}");
    let artifact: PerformanceArtifact = serde_json::from_str(&text).unwrap();
    assert_eq!(artifact.latency.len(), 2);
    let whole = artifact
        .latency
        .iter()
        .find(|r| r.workload == WorkloadId::RepeatedShortLogLines)
        .unwrap();
    assert_eq!(whole.direction, Direction::Slower, "{whole:?}");
    // Sanitized: the artifact records neither the generated lines nor the
    // scripts that were run.
    assert!(!text.contains("GET /health"));
    assert!(!text.contains("sleep 0.4"));
    assert!(!stderr.contains("GET /health"));
}

#[test]
fn perf_run_refuses_bad_input_with_distinct_exit_codes() {
    let dir = tempfile::tempdir().unwrap();
    let run = |config: Value| {
        let path = dir.path().join("config.json");
        let out = dir.path().join("artifact.json");
        let _ = fs::remove_file(&out);
        fs::write(&path, config.to_string()).unwrap();
        let output = bin()
            .args(["perf", "run", "--config"])
            .arg(&path)
            .arg("--out")
            .arg(&out)
            .output()
            .unwrap();
        (output.status.code(), out.exists())
    };
    // An out-of-bounds configuration: usage/config error, nothing written.
    let mut invalid = config("cat >/dev/null");
    invalid["rounds"] = json!(1);
    assert_eq!(run(invalid), (Some(2), false));
    // A pin that does not match the executable: refused before any run.
    let mut pinned = config("cat >/dev/null");
    pinned["candidate"]["sha256"] = json!(format!("sha256:{}", "0".repeat(64)));
    assert_eq!(run(pinned), (Some(4), false));
    // A workload beyond its bound: run failure, nothing written.
    let mut oversize = config("cat >/dev/null");
    oversize["limits"]["max_input_bytes"] = json!(10);
    assert_eq!(run(oversize), (Some(1), false));
    // Missing arguments and unknown fields are usage errors.
    let status = bin().args(["perf", "run"]).output().unwrap().status;
    assert_eq!(status.code(), Some(2));
    let mut unknown = config("cat >/dev/null");
    unknown["extra"] = json!(true);
    assert_eq!(run(unknown), (Some(2), false));
}

#[test]
fn the_latency_template_is_valid_once_its_placeholders_are_filled() {
    let template =
        fs::read_to_string(repo().join("configs/performance/redact-secret-latency.template.json"))
            .unwrap();
    let sha = |c: char| c.to_string().repeat(40);
    let filled = [
        ("__BASELINE_ID__", "scanner-a".to_owned()),
        ("__CANDIDATE_ID__", "scanner-b".to_owned()),
        ("__BASELINE_VERSION__", "0.1.0".to_owned()),
        ("__CANDIDATE_VERSION__", "0.1.0".to_owned()),
        ("__BASELINE_REVISION__", sha('a')),
        ("__CANDIDATE_REVISION__", sha('b')),
        ("__BASELINE_BIN__", "/bin/cat".to_owned()),
        ("__CANDIDATE_BIN__", "/bin/cat".to_owned()),
        ("__LLVM_VERSION__", "20.1.5".to_owned()),
        ("__RUSTC_VERSION__", "1.88.0".to_owned()),
    ]
    .iter()
    .fold(template, |text, (key, value)| text.replace(key, value));
    assert!(!filled.contains("__"), "every placeholder is filled");
    let config: PerformanceConfig = serde_json::from_str(&filled).unwrap();
    config.validate().unwrap();
    // It covers every workload the cards name for latency: normalization
    // (sparse/dense, invisible/Unicode), overlap, seams, repeated short lines,
    // long single-line assignments and dense early exhaustion.
    let ids: Vec<WorkloadId> = config.workloads.iter().map(|w| w.id).collect();
    for required in [
        WorkloadId::SparseUnicode,
        WorkloadId::DenseUnicode,
        WorkloadId::SparseInvisible,
        WorkloadId::DenseInvisible,
        WorkloadId::OverlapClusters,
        WorkloadId::SeamHeavy,
        WorkloadId::RepeatedShortLogLines,
        WorkloadId::LongSingleLineAssignments,
        WorkloadId::DenseEarlyExhaustion,
    ] {
        assert!(ids.contains(&required), "{required:?}");
    }
}
