//! End-to-end smoke test of the input/output contracts.
//!
//! Loads the synthetic snapshot, run configuration and canned scanner
//! observations from `tests/fixtures/contracts-smoke`, scores them with the
//! ported lattice, and serializes a run artifact that must
//! (1) equal the committed golden artifact byte for byte,
//! (2) validate against `schemas/run-artifact-v1.schema.json`, and
//! (3) be interpretable by a consumer holding only JSON and the schema.
//!
//! Regenerate the golden artifact after an intentional change with:
//! `UPDATE_GOLDEN=1 cargo test -p credential-eval-kernel --test contracts_smoke`

use std::path::PathBuf;

use credential_eval_contracts::artifact::{CaseMeasurement, Outcome, RunArtifact};
use credential_eval_contracts::config::RunConfig;
use credential_eval_contracts::corpus::CorpusSnapshot;
use credential_eval_contracts::observation::{ObservationSet, ScannerStatus};
use credential_eval_kernel::score::build_artifact;
use serde_json::Value;

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn fixture(name: &str) -> Vec<u8> {
    std::fs::read(root().join("tests/fixtures/contracts-smoke").join(name)).expect("fixture")
}

fn inputs() -> (CorpusSnapshot, RunConfig, ObservationSet) {
    let corpus = CorpusSnapshot::from_json(&fixture("corpus-snapshot.json")).expect("snapshot");
    let config: RunConfig = serde_json::from_slice(&fixture("run-config.json")).expect("config");
    let observations: ObservationSet =
        serde_json::from_slice(&fixture("observation-set.json")).expect("observations");
    (corpus, config, observations)
}

fn render(artifact: &RunArtifact) -> String {
    let mut text = serde_json::to_string_pretty(artifact).expect("serialize");
    text.push('\n');
    text
}

#[test]
fn artifact_matches_golden_and_is_deterministic() {
    let (corpus, config, observations) = inputs();
    let artifact = build_artifact(&corpus, &config, &observations).expect("artifact");
    let text = render(&artifact);

    // Input order must not affect the artifact.
    let (mut corpus2, config2, mut observations2) = inputs();
    corpus2.cases.reverse();
    observations2.observations.reverse();
    if let Some(credential_eval_contracts::observation::ObservationResult::Complete {
        findings,
        ..
    }) = observations2
        .observations
        .iter_mut()
        .map(|o| &mut o.result)
        .find(|r| r.status() == ScannerStatus::Complete)
    {
        findings.reverse();
    }
    let again = build_artifact(&corpus2, &config2, &observations2).expect("artifact");
    assert_eq!(render(&again), text, "artifact depends on input order");
    assert_eq!(again.semantic_digest(), artifact.semantic_digest());

    let golden = root().join("tests/fixtures/contracts-smoke/expected-run-artifact.json");
    if std::env::var_os("UPDATE_GOLDEN").is_some() {
        std::fs::write(&golden, &text).expect("write golden");
    }
    let committed = std::fs::read_to_string(&golden).expect("golden artifact");
    assert_eq!(
        text, committed,
        "run artifact differs from the committed golden file"
    );

    // Round trip through the typed contract.
    let parsed: RunArtifact = serde_json::from_str(&committed).expect("parse golden");
    assert_eq!(parsed, artifact);
}

#[test]
fn smoke_outcomes_follow_the_lattice() {
    let (corpus, config, observations) = inputs();
    let artifact = build_artifact(&corpus, &config, &observations).expect("artifact");
    let run = artifact
        .scanners
        .iter()
        .find(|s| s.scanner.as_str() == "fake-scanner-a")
        .expect("scanner a");
    let measurement = |id: &str| {
        &run.cases
            .iter()
            .find(|c| c.case_id.as_str() == id)
            .expect("case")
            .measurement
    };
    let outcome = |id: &str| match measurement(id) {
        CaseMeasurement::Positive { span_outcomes, .. } => span_outcomes.clone(),
        other => panic!("{id} is not positive: {other:?}"),
    };
    assert_eq!(outcome("positive-exact"), [Outcome::Exact]);
    assert_eq!(outcome("positive-envelope"), [Outcome::Covered]);
    assert_eq!(outcome("positive-overbroad"), [Outcome::Overbroad]);
    assert_eq!(outcome("positive-partial"), [Outcome::Partial]);
    assert_eq!(outcome("positive-miss-companion"), [Outcome::Miss]);
    assert!(matches!(
        measurement("benign-placeholder"),
        CaseMeasurement::Control {
            flagged: true,
            findings: 1,
            ..
        }
    ));
    // The twin's only finding is attributed to a different known family.
    assert!(matches!(
        measurement("twin-length"),
        CaseMeasurement::Control {
            flagged: false,
            co_detected: true,
            ..
        }
    ));
    assert_eq!(measurement("pending-review"), &CaseMeasurement::Pending);
    // The duplicate finding was deduplicated.
    assert_eq!(run.findings.len(), 8);

    // A timed-out scanner is never scored as MISS.
    let failed = artifact
        .scanners
        .iter()
        .find(|s| s.scanner.as_str() == "fake-scanner-b")
        .expect("scanner b");
    assert_eq!(failed.status, ScannerStatus::Timeout);
    assert!(failed.findings.is_empty());
    assert!(failed.cases.iter().all(|c| c.measurement
        == CaseMeasurement::NotMeasured {
            status: ScannerStatus::Timeout
        }));
}

/// A consumer that knows only JSON and the committed schema file: no contract
/// types, no kernel, no product code.
#[test]
fn consumer_can_interpret_artifact_with_only_the_schema() {
    let schema: Value = serde_json::from_slice(
        &std::fs::read(root().join("schemas/run-artifact-v1.schema.json")).expect("schema"),
    )
    .expect("schema json");
    let artifact: Value =
        serde_json::from_slice(&fixture("expected-run-artifact.json")).expect("artifact json");

    let validator = jsonschema::validator_for(&schema).expect("schema compiles");
    let errors: Vec<String> = validator
        .iter_errors(&artifact)
        .map(|e| e.to_string())
        .collect();
    assert!(errors.is_empty(), "artifact does not validate: {errors:?}");

    // Interpret: count span outcomes and measured/unmeasured scanners.
    let mut exact = 0;
    let mut leaked = 0;
    let mut not_measured = 0;
    for scanner in artifact["scanners"].as_array().expect("scanners") {
        for case in scanner["cases"].as_array().expect("cases") {
            let m = &case["measurement"];
            match m["type"].as_str().expect("type") {
                "positive" => {
                    for o in m["span_outcomes"].as_array().expect("outcomes") {
                        match o.as_str().expect("outcome") {
                            "EXACT" => exact += 1,
                            "PARTIAL" | "MISS" => leaked += 1,
                            _ => {}
                        }
                    }
                }
                "not-measured" => not_measured += 1,
                _ => {}
            }
        }
    }
    assert_eq!((exact, leaked, not_measured), (1, 2, 8));

    // The schema rejects artifacts that smuggle in extra fields (e.g. a
    // product support status) or turn a failure into an unknown state.
    let mut tampered = artifact.clone();
    tampered["scanners"][0]["support_status"] = "stable".into();
    assert!(!validator.is_valid(&tampered));
    let mut tampered = artifact;
    tampered["scanners"][1]["status"] = "skipped".into();
    assert!(!validator.is_valid(&tampered));
}

#[test]
fn artifact_contains_no_fixture_content() {
    let (corpus, _, _) = inputs();
    let artifact = String::from_utf8(fixture("expected-run-artifact.json")).expect("utf-8");
    for case in &corpus.cases {
        for span in &case.expected {
            let value = &case.content[span.start as usize..span.end as usize];
            assert!(
                !artifact.contains(value),
                "artifact leaks expected span bytes of {}",
                case.id
            );
        }
    }
}
