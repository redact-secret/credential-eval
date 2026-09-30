//! End-to-end tests of the `credential-eval` binary with a fake scanner.

#![cfg(unix)]

mod common;

use std::fs;
use std::process::Command;

use common::*;
use credential_eval_contracts::artifact::RunArtifact;
use credential_eval_contracts::config::RunConfig;
use credential_eval_contracts::observation::ObservationSet;

fn bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_credential-eval"))
}

#[test]
fn run_writes_identical_artifacts_for_any_job_count() {
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    let rows = r#"echo "[{\"RuleID\":\"generic-api-key\",\"File\":\"$root/contracts-smoke/positive-exact.txt\",\"Secret\":\"EXAMPLE_FAKE_KEY_0123456789abcdef\",\"StartLine\":2}]""#;
    let config = config(
        vec![
            gitleaks_spec("gitleaks", &fake_gitleaks(d, "g1", "8.30.1", rows)),
            gitleaks_spec("gitleaks-copy", &fake_gitleaks(d, "g2", "8.30.1", rows)),
            gitleaks_spec("broken", &fake_gitleaks(d, "g3", "8.30.1", "echo nope")),
        ],
        1,
    );
    let config_path = d.join("run-config.json");
    fs::write(&config_path, serde_json::to_vec_pretty(&config).unwrap()).unwrap();
    let corpus = repo().join("tests/fixtures/contracts-smoke/corpus-snapshot.json");

    let mut texts = Vec::new();
    for jobs in ["1", "8"] {
        let out = d.join(format!("artifact-{jobs}.json"));
        let observations = d.join(format!("observations-{jobs}.json"));
        let status = bin()
            .args(["run", "--corpus"])
            .arg(&corpus)
            .arg("--config")
            .arg(&config_path)
            .args(["--jobs", jobs, "--out"])
            .arg(&out)
            .arg("--observations-out")
            .arg(&observations)
            .output()
            .unwrap();
        assert!(
            status.status.success(),
            "{}",
            String::from_utf8_lossy(&status.stderr)
        );
        let stderr = String::from_utf8_lossy(&status.stderr);
        assert!(stderr.contains("semantic digest sha256:"));
        assert!(
            !stderr.contains("EXAMPLE_FAKE"),
            "stderr must not echo values"
        );
        let artifact: RunArtifact = serde_json::from_slice(&fs::read(&out).unwrap()).unwrap();
        assert_schema_valid(&artifact);
        let _: ObservationSet = serde_json::from_slice(&fs::read(&observations).unwrap()).unwrap();
        texts.push(semantic_text(&artifact));
    }
    assert_eq!(texts[0], texts[1]);

    // --require-complete turns the broken scanner into exit code 3.
    let status = bin()
        .args(["run", "--corpus"])
        .arg(&corpus)
        .arg("--config")
        .arg(&config_path)
        .args(["--require-complete", "--out"])
        .arg(d.join("artifact-strict.json"))
        .status()
        .unwrap();
    assert_eq!(status.code(), Some(3));

    // --scanner filters the configured scanners.
    let out = d.join("artifact-one.json");
    let status = bin()
        .args(["run", "--corpus"])
        .arg(&corpus)
        .arg("--config")
        .arg(&config_path)
        .args(["--scanner", "gitleaks", "--require-complete", "--out"])
        .arg(&out)
        .status()
        .unwrap();
    assert_eq!(status.code(), Some(0));
    let artifact: RunArtifact = serde_json::from_slice(&fs::read(&out).unwrap()).unwrap();
    assert_eq!(artifact.scanners.len(), 1);
}

#[test]
fn usage_errors_exit_2_and_default_config_round_trips() {
    let status = bin().args(["run", "--corpus", "x.json"]).status().unwrap();
    assert_eq!(status.code(), Some(2));
    let status = bin().args(["run", "--jobs", "0"]).status().unwrap();
    assert_eq!(status.code(), Some(2));
    let status = bin()
        .args([
            "run",
            "--corpus",
            "x.json",
            "--out",
            "y.json",
            "--scanner",
            "nope",
        ])
        .status()
        .unwrap();
    assert_eq!(status.code(), Some(2));

    let output = bin().args(["default-config"]).output().unwrap();
    assert!(output.status.success());
    let config: RunConfig = serde_json::from_slice(&output.stdout).unwrap();
    let ids: Vec<&str> = config.scanners.iter().map(|s| s.id.as_str()).collect();
    assert_eq!(
        ids,
        [
            "flare-redact",
            "gitleaks",
            "openredaction",
            "redact-secret",
            "trufflehog"
        ]
    );
    let trufflehog = config
        .scanners
        .iter()
        .find(|s| s.id.as_str() == "trufflehog")
        .unwrap();
    assert_eq!(trufflehog.configuration["required_version"], "3.97.4");
}
