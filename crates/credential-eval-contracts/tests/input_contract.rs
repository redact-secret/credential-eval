//! Input contract tests over the synthetic `tests/fixtures/contracts-smoke` set.

use std::path::PathBuf;

use credential_eval_contracts::ContractError;
use credential_eval_contracts::config::RunConfig;
use credential_eval_contracts::corpus::{CorpusSnapshot, corpus_digest};
use credential_eval_contracts::ids::CaseId;
use credential_eval_contracts::observation::ObservationSet;
use credential_eval_contracts::schema::all_schemas;

fn fixture(name: &str) -> Vec<u8> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/contracts-smoke")
        .join(name);
    std::fs::read(path).expect("fixture")
}

fn snapshot() -> CorpusSnapshot {
    CorpusSnapshot::from_json(&fixture("corpus-snapshot.json")).expect("valid snapshot")
}

fn schema(file: &str) -> serde_json::Value {
    let (_, schema) = all_schemas()
        .into_iter()
        .find(|(name, _)| *name == file)
        .expect("schema");
    serde_json::to_value(schema).expect("json")
}

#[test]
fn smoke_inputs_validate_against_types_and_schemas() {
    let corpus = snapshot();
    let config: RunConfig = serde_json::from_slice(&fixture("run-config.json")).expect("config");
    let observations: ObservationSet =
        serde_json::from_slice(&fixture("observation-set.json")).expect("observations");
    observations
        .validate_against(&corpus)
        .expect("observations match corpus");

    for (file, doc) in [
        ("corpus-snapshot-v1.schema.json", "corpus-snapshot.json"),
        ("run-config-v1.schema.json", "run-config.json"),
        ("observation-set-v1.schema.json", "observation-set.json"),
    ] {
        let instance: serde_json::Value = serde_json::from_slice(&fixture(doc)).expect("json");
        let validator = jsonschema::validator_for(&schema(file)).expect("schema compiles");
        let errors: Vec<String> = validator
            .iter_errors(&instance)
            .map(|e| e.to_string())
            .collect();
        assert!(errors.is_empty(), "{doc}: {errors:?}");
    }

    // The recorded configuration hash of each observed scanner is the
    // canonical digest of its configured `configuration`.
    for spec in &config.scanners {
        let observed = observations
            .observations
            .iter()
            .find(|o| o.scanner.id == spec.id)
            .expect("observed scanner");
        assert_eq!(
            observed.scanner.configuration_hash,
            spec.configuration_hash()
        );
    }
}

#[test]
fn corpus_digest_is_order_independent_and_content_sensitive() {
    let corpus = snapshot();
    let mut reversed = corpus.cases.clone();
    reversed.reverse();
    assert_eq!(corpus_digest(&reversed), corpus.identity.corpus_digest);

    let mut tampered = corpus.clone();
    tampered.cases[0].content.push(' ');
    assert!(matches!(
        tampered.validate(),
        Err(ContractError::CorpusDigestMismatch { .. })
    ));
}

#[test]
fn stale_observations_are_rejected() {
    let mut corpus = snapshot();
    corpus.cases[0].content.push(' ');
    let resealed = CorpusSnapshot::seal(
        corpus.identity.source.clone(),
        corpus.identity.revision.clone(),
        corpus.identity.evidence_schema.clone(),
        corpus.cases,
    );
    let observations: ObservationSet =
        serde_json::from_slice(&fixture("observation-set.json")).expect("observations");
    assert!(matches!(
        observations.validate_against(&resealed),
        Err(ContractError::StaleObservations { .. })
    ));
}

#[test]
fn ranges_must_fall_on_utf8_boundaries() {
    let corpus = snapshot();
    // `positive-exact` starts with "# café"; "é" is bytes 5..7, so 6 is inside it.
    let mut cases = corpus.cases.clone();
    let case = cases
        .iter_mut()
        .find(|c| c.id.as_str() == "positive-exact")
        .expect("case");
    case.expected[0].start = 6;
    let bad = CorpusSnapshot::seal("s".into(), "r".into(), "e".into(), cases);
    assert!(matches!(
        bad.validate(),
        Err(ContractError::InvalidRange { .. })
    ));
}

#[test]
fn twin_lineage_is_checked() {
    let corpus = snapshot();
    let mut cases = corpus.cases.clone();
    let twin = cases
        .iter_mut()
        .find(|c| c.twin.is_some())
        .expect("twin case");
    twin.twin.as_mut().expect("lineage").twin_of = CaseId::new("benign-placeholder").expect("id");
    let bad = CorpusSnapshot::seal("s".into(), "r".into(), "e".into(), cases);
    assert!(matches!(
        bad.validate(),
        Err(ContractError::InvalidTwin { .. })
    ));
}

#[test]
fn unknown_fields_and_wrong_schema_tags_fail_closed() {
    let mut value: serde_json::Value =
        serde_json::from_slice(&fixture("corpus-snapshot.json")).expect("json");
    value["cases"][0]["support_status"] = "stable".into();
    assert!(serde_json::from_value::<CorpusSnapshot>(value).is_err());

    let mut value: serde_json::Value =
        serde_json::from_slice(&fixture("corpus-snapshot.json")).expect("json");
    value["schema"] = "credential-eval/corpus-snapshot/v2".into();
    assert!(serde_json::from_value::<CorpusSnapshot>(value).is_err());
}
