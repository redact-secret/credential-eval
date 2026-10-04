//! The representation contract through the whole pipeline with a fake
//! Gitleaks: a snapshot that carries decoded, fragmented and rejected inputs,
//! a scanner that reports findings in decoded coordinates, and the
//! `decoded_mapping` choice that places them on the original bytes. No real
//! scanner is needed (`real_scanners.rs` covers those).

#![cfg(unix)]

mod common;

use std::fs;

use common::*;
use credential_eval_contracts::artifact::{CaseMeasurement, Outcome};
use credential_eval_contracts::corpus::CorpusSnapshot;
use credential_eval_contracts::observation::{ObservationResult, ScannerStatus};
use credential_eval_contracts::representation::{Codec, MappingBound};
use serde_json::{Value, json};

const SECRET: &str = "SYNTHETIC_EXAMPLE_KEY_NEVER_ISSUED_01";

fn corpus() -> CorpusSnapshot {
    let bytes = fs::read(repo().join("tests/fixtures/representation-smoke/corpus-snapshot.json"))
        .expect("corpus");
    CorpusSnapshot::from_json(&bytes).expect("valid corpus")
}

/// A fake Gitleaks that reports the three encoded cases the way the real one
/// does: the decoded value as `Secret`, plus `decoded:*` and `decode-depth`
/// tags. The values are absent from the files, so no locate rule can place
/// them.
fn decoded_report() -> String {
    let row = |file: &str, tags: Value| {
        json!({"RuleID": "generic-api-key", "File": format!("$root/{file}"),
               "Secret": SECRET, "StartLine": 1, "StartColumn": 1, "Tags": tags})
    };
    let rows = json!([
        row(
            "rep/enc-b64-whole.txt",
            json!(["decoded:base64", "decode-depth:1"])
        ),
        row(
            "rep/enc-hex-json.txt",
            json!(["decoded:hex", "decode-depth:1"])
        ),
        row(
            "rep/enc-nested.txt",
            json!(["decoded:base64", "decode-depth:2"])
        ),
    ]);
    format!("cat <<EOF\n{rows}\nEOF")
}

fn result_of(out: &credential_eval_cli::orchestrate::RunOutput) -> ObservationResult {
    out.observations.observations[0].result.clone()
}

fn spec(
    bin: &std::path::Path,
    per_case: bool,
    decoded: Option<&str>,
) -> credential_eval_contracts::config::ScannerSpec {
    let mut spec = gitleaks_spec("gitleaks", bin);
    if per_case {
        spec.configuration
            .insert("unmappable_findings".into(), json!("unmeasured-case"));
    }
    if let Some(value) = decoded {
        spec.configuration
            .insert("decoded_mapping".into(), json!(value));
    }
    spec
}

fn run_report(
    per_case: bool,
    decoded: Option<&str>,
) -> credential_eval_cli::orchestrate::RunOutput {
    let dir = tempfile::tempdir().unwrap();
    let bin = fake_gitleaks(dir.path(), "gitleaks", "8.30.1", &decoded_report());
    run(&corpus(), &config(vec![spec(&bin, per_case, decoded)], 2))
}

#[test]
fn without_the_choice_a_decoded_finding_is_unplaceable_exactly_as_before() {
    // Default: the scanner is malformed, never a zero detection.
    let out = run_report(false, None);
    assert!(matches!(
        result_of(&out),
        ObservationResult::Malformed { .. }
    ));
    // Per-case handling alone (alpha.2/alpha.3): the depth-one base64 finding
    // is placed by the rule that predates the contract, with no mapping
    // record; the hex and the nested findings are unmeasured, in no
    // denominator, never a zero detection.
    let out = run_report(true, None);
    let ObservationResult::Complete {
        findings,
        unmeasured,
        ..
    } = result_of(&out)
    else {
        panic!("complete expected");
    };
    assert_eq!(findings.len(), 1);
    assert!(
        findings[0].mapping.is_none(),
        "the old rule records no mapping"
    );
    assert_eq!(unmeasured.len(), 2);
    let run = &out.artifact.scanners[0];
    assert_eq!(run.unmeasured_cases.len(), 2);
    for id in ["enc-hex-json", "enc-nested"] {
        let case = run.cases.iter().find(|c| c.case_id.as_str() == id).unwrap();
        assert!(matches!(
            case.measurement,
            CaseMeasurement::NotMeasured { .. }
        ));
    }
}

#[test]
fn with_the_choice_provable_findings_are_placed_and_scored() {
    for per_case in [false, true] {
        let out = run_report(per_case, Some("source-segment"));
        assert_schema_valid(&out.artifact);
        let ObservationResult::Complete {
            findings,
            unmeasured,
            ..
        } = result_of(&out)
        else {
            panic!("complete expected");
        };
        assert!(unmeasured.is_empty(), "nothing was left unmeasured");
        assert_eq!(findings.len(), 3);
        let run = &out.artifact.scanners[0];
        assert_eq!(run.status, ScannerStatus::Complete);
        assert!(run.unmeasured_cases.is_empty());
        let case = |id: &str| run.cases.iter().find(|c| c.case_id.as_str() == id).unwrap();
        for id in ["enc-b64-whole", "enc-hex-json", "enc-nested"] {
            let CaseMeasurement::Positive { span_outcomes, .. } = &case(id).measurement else {
                panic!("{id} is not positive");
            };
            assert_eq!(span_outcomes, &[Outcome::Exact], "{id}");
        }
        let mapping = |id: &str| case(id).actual[0].mapping.clone().expect("mapped");
        assert_eq!(
            (
                mapping("enc-b64-whole").layers,
                mapping("enc-b64-whole").codecs
            ),
            (1, vec![Codec::Base64])
        );
        assert_eq!(mapping("enc-hex-json").codecs, vec![Codec::Hex]);
        assert_eq!(mapping("enc-nested").layers, 2);
        assert_eq!(mapping("enc-nested").bound, MappingBound::SourceSegment);
        // A case that was never reported stays what it was: a miss is a
        // measurement, because the scanner ran.
        assert!(matches!(
            case("strip-zero-width").measurement,
            CaseMeasurement::Positive { .. }
        ));
        // The manifest says which representation facts the snapshot carried.
        assert!(out.artifact.manifest.representation.is_some());
    }
}

#[test]
fn the_choice_is_part_of_the_configuration_hash() {
    let dir = tempfile::tempdir().unwrap();
    let bin = fake_gitleaks(dir.path(), "gitleaks", "8.30.1", "echo '[]'");
    let hash = |decoded: Option<&str>| {
        let out = run(&corpus(), &config(vec![spec(&bin, false, decoded)], 1));
        out.observations.observations[0]
            .scanner
            .configuration_hash
            .clone()
    };
    assert_ne!(hash(None), hash(Some("source-segment")));
    // "off" is a recorded choice too, distinct from absence.
    assert_ne!(hash(None), hash(Some("off")));
}

#[test]
fn an_invalid_choice_is_a_configuration_error_not_a_measurement() {
    let dir = tempfile::tempdir().unwrap();
    let bin = fake_gitleaks(dir.path(), "gitleaks", "8.30.1", "echo '[]'");
    for bad in ["on", "segment", ""] {
        let out = run(&corpus(), &config(vec![spec(&bin, false, Some(bad))], 1));
        let ObservationResult::Error { reason } = result_of(&out) else {
            panic!("an invalid decoded_mapping must be an error");
        };
        assert!(reason.contains("decoded_mapping"), "{reason}");
    }
}

#[test]
fn a_finding_the_rule_cannot_prove_stays_unmeasured_not_guessed() {
    // The decoded secret is not what the segment decodes to.
    let dir = tempfile::tempdir().unwrap();
    let row = json!([{"RuleID": "generic-api-key", "File": "$root/rep/enc-b64-whole.txt",
        "Secret": "NOT_WHAT_THE_SEGMENT_DECODES_TO", "StartLine": 1, "Tags": ["decoded:base64", "decode-depth:1"]}]);
    let bin = fake_gitleaks(
        dir.path(),
        "gitleaks",
        "8.30.1",
        &format!("cat <<EOF\n{row}\nEOF"),
    );
    let out = run(
        &corpus(),
        &config(vec![spec(&bin, true, Some("source-segment"))], 1),
    );
    let ObservationResult::Complete {
        unmeasured,
        findings,
        ..
    } = result_of(&out)
    else {
        panic!("complete expected");
    };
    assert!(findings.is_empty());
    assert_eq!(unmeasured.len(), 1);
    assert_eq!(unmeasured[0].path.as_str(), "rep/enc-b64-whole.txt");
    // Without per-case handling the same finding fails the scanner closed.
    let out = run(
        &corpus(),
        &config(vec![spec(&bin, false, Some("source-segment"))], 1),
    );
    assert!(matches!(
        result_of(&out),
        ObservationResult::Malformed { .. }
    ));
}

#[test]
fn the_mapped_artifact_is_deterministic_across_job_counts() {
    let dir = tempfile::tempdir().unwrap();
    let bin = fake_gitleaks(dir.path(), "gitleaks", "8.30.1", &decoded_report());
    let one = run(
        &corpus(),
        &config(vec![spec(&bin, true, Some("source-segment"))], 1),
    );
    let four = run(
        &corpus(),
        &config(vec![spec(&bin, true, Some("source-segment"))], 4),
    );
    assert_eq!(semantic_text(&one.artifact), semantic_text(&four.artifact));
    assert_eq!(
        one.artifact.semantic_digest(),
        four.artifact.semantic_digest()
    );
}
