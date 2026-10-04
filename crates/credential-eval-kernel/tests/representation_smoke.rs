//! End-to-end test of the representation contract (revision v1.3) over
//! `tests/fixtures/representation-smoke`: a snapshot that carries decoded,
//! fragmented and rejected inputs, canned observations with mapped findings and
//! a per-case gap, and a golden artifact.
//!
//! Regenerate the golden artifact after an intentional change with:
//! `UPDATE_GOLDEN=1 cargo test -p credential-eval-kernel --test representation_smoke`

use std::path::PathBuf;

use credential_eval_contracts::artifact::{CaseMeasurement, Outcome, RunArtifact};
use credential_eval_contracts::config::RunConfig;
use credential_eval_contracts::corpus::CorpusSnapshot;
use credential_eval_contracts::observation::{NormalizedFinding, ObservationSet};
use credential_eval_contracts::representation::{Codec, MappingBound};
use credential_eval_kernel::evaluation::MethodId;
use credential_eval_kernel::evaluation::cases::{build_cases, case_id_seed};
use credential_eval_kernel::score::{build_artifact, dedupe};

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn fixture(name: &str) -> Vec<u8> {
    std::fs::read(
        root()
            .join("tests/fixtures/representation-smoke")
            .join(name),
    )
    .expect("fixture")
}

fn inputs() -> (CorpusSnapshot, RunConfig, ObservationSet) {
    let corpus = CorpusSnapshot::from_json(&fixture("corpus-snapshot.json")).expect("snapshot");
    let config: RunConfig = serde_json::from_slice(&fixture("run-config.json")).expect("config");
    let observations: ObservationSet =
        serde_json::from_slice(&fixture("observation-set.json")).expect("observations");
    observations
        .validate_against(&corpus)
        .expect("observations");
    (corpus, config, observations)
}

fn artifact() -> RunArtifact {
    let (corpus, config, observations) = inputs();
    build_artifact(&corpus, &config, &observations).expect("artifact")
}

fn render(artifact: &RunArtifact) -> String {
    let mut text = serde_json::to_string_pretty(artifact).expect("serialize");
    text.push('\n');
    text
}

#[test]
fn artifact_matches_golden_and_is_deterministic() {
    let artifact = artifact();
    let text = render(&artifact);
    let (mut corpus, config, mut observations) = inputs();
    corpus.cases.reverse();
    observations.observations.reverse();
    let again = build_artifact(&corpus, &config, &observations).expect("artifact");
    assert_eq!(render(&again), text, "artifact depends on input order");
    assert_eq!(again.semantic_digest(), artifact.semantic_digest());

    let golden = root().join("tests/fixtures/representation-smoke/expected-run-artifact.json");
    if std::env::var_os("UPDATE_GOLDEN").is_some() {
        std::fs::write(&golden, &text).expect("write golden");
    }
    let committed = std::fs::read_to_string(&golden).expect("golden artifact");
    assert_eq!(text, committed, "run artifact differs from the golden file");
    let parsed: RunArtifact = serde_json::from_str(&committed).expect("parse golden");
    assert_eq!(parsed, artifact);

    // The artifact validates against the generated schema.
    let (_, schema) = credential_eval_contracts::schema::all_schemas()
        .into_iter()
        .find(|(name, _)| *name == "run-artifact-v1.schema.json")
        .expect("schema");
    let validator =
        jsonschema::validator_for(&serde_json::to_value(schema).unwrap()).expect("compiles");
    let instance: serde_json::Value = serde_json::from_str(&committed).unwrap();
    let errors: Vec<String> = validator
        .iter_errors(&instance)
        .map(|e| e.to_string())
        .collect();
    assert!(errors.is_empty(), "{errors:?}");
}

#[test]
fn the_manifest_proves_which_facts_were_received() {
    let artifact = artifact();
    let report = artifact
        .manifest
        .representation
        .as_ref()
        .expect("representation report");
    let (corpus, ..) = inputs();
    assert_eq!(report, &corpus.representation_report().unwrap());
    assert_eq!(
        report.facts_digest,
        credential_eval_contracts::representation::facts_digest(&corpus.cases)
    );
    assert_eq!(
        artifact.manifest.evidence.representation,
        corpus.identity.representation
    );
    assert_eq!(
        (
            report.cases,
            report.fragmented_spans,
            report.decoded_spans,
            report.expected_rejections
        ),
        (7, 1, 4, 1)
    );
}

#[test]
fn mapped_findings_score_against_the_source_range_and_say_so() {
    let artifact = artifact();
    let run = artifact
        .scanners
        .iter()
        .find(|s| s.scanner.as_str() == "fake-scanner-a")
        .unwrap();
    let case = |id: &str| run.cases.iter().find(|c| c.case_id.as_str() == id).unwrap();
    let outcome = |id: &str| match &case(id).measurement {
        CaseMeasurement::Positive { span_outcomes, .. } => span_outcomes.clone(),
        other => panic!("{id}: {other:?}"),
    };
    // A decoded finding mapped to the span's source range is EXACT, at any depth.
    assert_eq!(outcome("enc-b64-whole"), [Outcome::Exact]);
    assert_eq!(outcome("enc-hex-json"), [Outcome::Exact]);
    assert_eq!(outcome("enc-nested"), [Outcome::Exact]);
    // A fragmented secret reported as one range is scored on the whole range.
    assert_eq!(outcome("frag-shell"), [Outcome::Exact]);
    // No finding is a MISS, not an unmeasured case: the scanner ran.
    assert_eq!(outcome("strip-zero-width"), [Outcome::Miss]);
    // The mapping is on the row and on the finding, and only on mapped ones.
    let nested = &case("enc-nested").actual[0];
    let mapping = nested.mapping.as_ref().expect("mapped");
    assert_eq!(
        (mapping.bound, mapping.layers, mapping.codecs.clone()),
        (MappingBound::SourceSegment, 2, vec![Codec::Base64])
    );
    assert!(case("frag-shell").actual[0].mapping.is_none());
    assert_eq!(
        run.findings.iter().filter(|f| f.mapping.is_some()).count(),
        4
    );
}

#[test]
fn rejections_and_pending_projections_never_enter_a_denominator() {
    let artifact = artifact();
    for run in &artifact.scanners {
        let case = |id: &str| run.cases.iter().find(|c| c.case_id.as_str() == id).unwrap();
        for id in ["reject-surrogate", "enc-pending"] {
            assert_eq!(case(id).measurement, CaseMeasurement::Pending, "{id}");
        }
    }
    // The expected rejection is in the pending group, which has no rate.
    let run = &artifact.scanners[0];
    assert!(run.aggregates.groups.contains_key("pending/T0"));
}

#[test]
fn an_unmeasured_case_is_not_measured_and_never_a_zero_detection() {
    let artifact = artifact();
    let run = artifact
        .scanners
        .iter()
        .find(|s| s.scanner.as_str() == "fake-scanner-b")
        .unwrap();
    assert_eq!(run.unmeasured_cases.len(), 1);
    assert_eq!(run.unmeasured_cases[0].case_id.as_str(), "enc-hex-json");
    let row = run
        .cases
        .iter()
        .find(|c| c.case_id.as_str() == "enc-hex-json")
        .unwrap();
    assert!(matches!(
        row.measurement,
        CaseMeasurement::NotMeasured { .. }
    ));
    // The cases the scanner did measure are scored as usual.
    let b64 = run
        .cases
        .iter()
        .find(|c| c.case_id.as_str() == "enc-b64-whole")
        .unwrap();
    assert!(matches!(b64.measurement, CaseMeasurement::Positive { .. }));
}

#[test]
fn a_plain_duplicate_does_not_hide_a_mapping_and_order_does_not_matter() {
    let (_, _, observations) = inputs();
    let findings: Vec<NormalizedFinding> = observations
        .observations
        .iter()
        .find_map(|o| match &o.result {
            credential_eval_contracts::observation::ObservationResult::Complete {
                findings,
                ..
            } if o.scanner.id.as_str() == "fake-scanner-a" => Some(findings.clone()),
            _ => None,
        })
        .unwrap();
    let mapped = findings
        .iter()
        .find(|f| f.mapping.is_some())
        .unwrap()
        .clone();
    let mut plain = mapped.clone();
    plain.mapping = None;
    let forward = dedupe(&[mapped.clone(), plain.clone()]);
    let backward = dedupe(&[plain, mapped.clone()]);
    assert_eq!(forward.len(), 1);
    // (The family of duplicates still follows "last wins", unchanged; the
    // mapping, which is new, must not depend on emission order.)
    assert_eq!(forward, backward, "dedupe depends on emission order");
    assert_eq!(forward[0].mapping, mapped.mapping);
}

#[test]
fn methods_start_from_seeds_without_representation_facts() {
    let (corpus, ..) = inputs();
    let with = build_cases(&corpus, &MethodId::ALL, &case_id_seed).expect("cases");
    let mut stripped = corpus.clone();
    stripped.cases = stripped
        .cases
        .iter()
        .map(|c| c.without_representation())
        .collect();
    let without = build_cases(&stripped, &MethodId::ALL, &case_id_seed).expect("cases");
    assert_eq!(with.len(), without.len());
    for (a, b) in with.iter().zip(&without) {
        assert_eq!(a.seed, b.seed, "{}", a.id);
        assert_eq!(a.source_hash, b.source_hash, "{}", a.id);
        assert!(a.seed.representation.is_none());
        assert!(
            a.seed
                .expected
                .iter()
                .all(|s| s.decoded.is_none() && s.fragments.is_none())
        );
    }
}
