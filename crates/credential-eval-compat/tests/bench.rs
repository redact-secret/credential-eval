//! The legacy `bench` writer on the contracts-smoke corpus, re-keyed the way
//! the legacy exporter keys cases (`<category>--<fixtureId>`).

use std::collections::BTreeMap;
use std::path::PathBuf;

use credential_eval_compat::bench::{LegacyIndex, render};
use credential_eval_contracts::config::RunConfig;
use credential_eval_contracts::corpus::CorpusSnapshot;
use credential_eval_contracts::ids::CaseId;
use credential_eval_contracts::observation::ObservationSet;
use credential_eval_kernel::score::build_artifact;
use serde_json::json;

const CATEGORY: &str = "contracts-smoke";

fn fixture(name: &str) -> Vec<u8> {
    let root =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/contracts-smoke");
    std::fs::read(root.join(name)).expect("fixture")
}

fn inputs() -> (CorpusSnapshot, RunConfig, ObservationSet, LegacyIndex) {
    let smoke = CorpusSnapshot::from_json(&fixture("corpus-snapshot.json")).unwrap();
    let order: Vec<String> = smoke.cases.iter().map(|c| c.id.to_string()).collect();
    let mut cases = smoke.cases.clone();
    for case in &mut cases {
        case.id = CaseId::new(format!("{CATEGORY}--{}", case.id)).unwrap();
        if let Some(twin) = &mut case.twin {
            twin.twin_of = CaseId::new(format!("{CATEGORY}--{}", twin.twin_of)).unwrap();
        }
    }
    let corpus = CorpusSnapshot::seal(
        smoke.identity.source,
        smoke.identity.revision,
        smoke.identity.evidence_schema,
        cases,
    );
    let config: RunConfig = serde_json::from_slice(&fixture("run-config.json")).unwrap();
    let mut observations: ObservationSet =
        serde_json::from_slice(&fixture("observation-set.json")).unwrap();
    observations.corpus_digest = corpus.identity.corpus_digest.clone();
    let index: LegacyIndex = serde_json::from_value(json!({
        "schema": "credential-eval/legacy-index/v1",
        "corpus_digest": corpus.identity.corpus_digest,
        "categories": [{ "id": CATEGORY, "corpusHash": "0".repeat(64), "fixtures": order }],
        "groups": order.iter().map(|id| (format!("{CATEGORY}--{id}"), "Smoke")).collect::<BTreeMap<_, _>>(),
        "bench_assignments": {
            format!("{CATEGORY}--positive-exact"): ["example-api-key"],
            format!("{CATEGORY}--twin-length"): ["example-api-key"],
            format!("{CATEGORY}--benign-placeholder"): ["example-api-key"],
            format!("{CATEGORY}--calibration-only--elsewhere"): ["unrelated"],
        },
    }))
    .unwrap();
    (corpus, config, observations, index)
}

#[test]
fn renders_legacy_bench_rows_groups_and_summary() {
    let (corpus, config, observations, index) = inputs();
    let artifact = build_artifact(&corpus, &config, &observations).unwrap();
    let out = render(&artifact, &index).unwrap();
    let report = &out.categories[CATEGORY];
    assert_eq!(report["category"], CATEGORY);
    assert_eq!(report["fixtureCount"], 8);
    let scanners = report["scanners"].as_array().unwrap();

    // A timed-out scanner folds into `error` and carries no rows or groups.
    let failed = scanners
        .iter()
        .find(|s| s["id"] == "fake-scanner-b")
        .unwrap();
    assert_eq!(failed["status"], "error");
    assert!(failed.get("rows").is_none() && failed.get("groups").is_none());

    let ok = scanners
        .iter()
        .find(|s| s["id"] == "fake-scanner-a")
        .unwrap();
    assert_eq!(ok["status"], "complete");
    let rows = ok["rows"].as_array().unwrap();
    // Legacy fixture order, category-local ids and paths.
    let ids: Vec<&str> = rows.iter().map(|r| r["id"].as_str().unwrap()).collect();
    assert_eq!(ids[0], "positive-exact");
    assert_eq!(rows[0]["path"], "positive-exact.txt");
    assert_eq!(rows[0]["group"], "Smoke");
    let twin = rows.iter().find(|r| r["id"] == "twin-length").unwrap();
    assert_eq!(twin["twinOf"], "positive-exact");
    assert!(twin.get("coDetected").is_none_or(|v| v == true));
    let benign = rows
        .iter()
        .find(|r| r["id"] == "benign-placeholder")
        .unwrap();
    assert!(benign["flagged"].is_boolean());
    assert!(
        benign.get("coDetected").is_none(),
        "legacy omits coDetected: false"
    );
    let pending = rows.iter().find(|r| r["id"] == "pending-review").unwrap();
    for field in ["spanOutcomes", "flagged", "findings", "leakedBytes"] {
        assert!(
            pending.get(field).is_none(),
            "T0 rows carry no score fields"
        );
    }
    // Group JSON in legacy spelling.
    let groups = &ok["groups"];
    assert_eq!(groups["pending/T0"]["scored"], false);
    let control = &groups["must-not-flag/T1"];
    assert_eq!(control["diagnostics"]["comparable"], false);
    assert!(control["diagnostics"]["exact"]["tn"].is_u64());
    assert!(control.get("population").is_none());
    assert!(groups["must-redact/T1"]["twins"]["coDetected"].is_u64());
    assert_eq!(ok["accountingDelta"]["version"], "1.0 -> 1.1");

    // summary.json: every scanner, and a key for every assigned detector.
    let summary = &out.summary;
    assert_eq!(summary["overall"]["fake-scanner-b"], json!({}));
    assert!(
        summary["overall"]["fake-scanner-a"]
            .as_object()
            .unwrap()
            .len()
            > 1
    );
    assert!(summary["byDetector"]["example-api-key"]["fake-scanner-a"].is_object());
    assert_eq!(summary["byDetector"]["unrelated"], json!({}));
}

#[test]
fn refuses_an_index_that_does_not_describe_the_artifact() {
    let (corpus, config, observations, mut index) = inputs();
    let artifact = build_artifact(&corpus, &config, &observations).unwrap();
    let digest = index.corpus_digest.clone();
    index.corpus_digest = format!("sha256:{}", "1".repeat(64));
    assert!(render(&artifact, &index).is_err());
    index.corpus_digest = digest;
    index.categories[0]
        .fixtures
        .push("not-in-the-corpus".into());
    assert!(render(&artifact, &index).is_err());
    index.categories[0].fixtures.pop();
    index.schema = "other".into();
    assert!(render(&artifact, &index).is_err());
}
