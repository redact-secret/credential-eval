//! Golden oracle tests: the kernel must reproduce the legacy TypeScript engine
//! (`redact-secret-benchmarks@c403475`) on synthetic inputs.
//!
//! The goldens in `tests/fixtures/oracle/` hold the raw legacy outputs,
//! produced by `tools/oracle/generate.mts` (see the README there). These tests
//! replay the same inputs through the Rust kernel and compare. Legacy shapes
//! are mapped to the contract here, following `docs/migration/legacy-map.md`
//! §4.5; the goldens themselves are never edited.

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

use credential_eval_contracts::artifact::{
    AccountedCounts, BoundDirection, CaseMeasurement, CaseResult, GroupAggregate, ObservedRange,
    Outcome, Published, ScoredSpan,
};
use credential_eval_contracts::canonical::sha256_canonical;
use credential_eval_contracts::config::{AccountingConfig, AdapterIdentity, Floor};
use credential_eval_contracts::corpus::{
    Case, CaseKind, CorpusSnapshot, EvidenceTier, ExpectedSpan, Grouping, SpanRole, TwinLineage,
};
use credential_eval_contracts::ids::{CaseId, ComponentId, FixturePath, ScannerId};
use credential_eval_contracts::observation::{
    NormalizedFinding, ObservationResult, ObservationSet, Replays, ScannerIdentity,
    ScannerObservation,
};
use credential_eval_contracts::range::{ByteRange, Envelope};
use credential_eval_contracts::schema::ObservationSetSchema;
use credential_eval_kernel::accounting::{
    self, StatusCounts, SuiteCase, account_counts, account_groups, summarize_selections,
    unresolved_groups,
};
use credential_eval_kernel::compat;
use credential_eval_kernel::evaluation::cases::build_cases;
use credential_eval_kernel::evaluation::model::seeded_choice;
use credential_eval_kernel::evaluation::{
    EvaluateOptions, EvaluationEvidence, FamilyContract, FamilyContracts, GenerationLimits,
    MethodId, SegmentRule, evaluate, plan_evaluation,
};
use credential_eval_kernel::jsnum::round_to_fixed;
use credential_eval_kernel::lattice::{bytes_outside, score_row, union};
use credential_eval_kernel::score::score_scanner;
use credential_eval_kernel::twin_probe::{ProbeFixture, UnprobeableRecord, twin_probe};
use serde_json::{Value, json};

// ---------------------------------------------------------------------------
// Loading and generic comparison.

fn golden(name: &str) -> Value {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/oracle")
        .join(name);
    let value: Value =
        serde_json::from_slice(&std::fs::read(&path).expect("golden")).expect("json");
    assert_eq!(
        value["provenance"]["legacyCommit"], "c403475476647bc98cc5864bccd7265eddebeb91",
        "golden {name} was not generated from the pinned legacy commit"
    );
    value
}

/// JSON equality with numbers compared as `f64` (legacy integers and Rust
/// floats serialize differently but must be the same value).
fn json_eq(a: &Value, b: &Value) -> bool {
    match (a, b) {
        (Value::Number(x), Value::Number(y)) => x.as_f64() == y.as_f64(),
        (Value::Array(x), Value::Array(y)) => {
            x.len() == y.len() && x.iter().zip(y).all(|(p, q)| json_eq(p, q))
        }
        (Value::Object(x), Value::Object(y)) => {
            x.len() == y.len()
                && x.iter()
                    .all(|(k, v)| y.get(k).is_some_and(|w| json_eq(v, w)))
        }
        _ => a == b,
    }
}

#[track_caller]
fn assert_json(ours: &Value, legacy: &Value, context: &str) {
    assert!(
        json_eq(ours, legacy),
        "{context}\n  ours:   {ours}\n  legacy: {legacy}"
    );
}

fn camel_to_snake(key: &str) -> String {
    if !key.starts_with(|c: char| c.is_ascii_lowercase()) {
        return key.to_owned();
    }
    let mut out = String::new();
    for c in key.chars() {
        if c.is_ascii_uppercase() {
            out.push('_');
            out.push(c.to_ascii_lowercase());
        } else {
            out.push(c);
        }
    }
    out
}

fn snake_keys(v: &Value) -> Value {
    match v {
        Value::Object(m) => Value::Object(
            m.iter()
                .map(|(k, v)| (camel_to_snake(k), snake_keys(v)))
                .collect(),
        ),
        Value::Array(a) => Value::Array(a.iter().map(snake_keys).collect()),
        other => other.clone(),
    }
}

fn u(v: &Value) -> u64 {
    v.as_u64().expect("integer")
}

fn s(v: &Value) -> &str {
    v.as_str().expect("string")
}

fn opt_published(v: &Value) -> Option<Published> {
    serde_json::from_value(v.clone()).expect("published")
}

fn accounting_config(v: &Value) -> AccountingConfig {
    let floor = |f: &Value| -> Floor { serde_json::from_value(f.clone()).expect("floor") };
    AccountingConfig {
        min_denominator: u(&v["minDenominator"]) as u32,
        resolved_rate_floor: floor(&v["resolvedRateFloor"]),
        measurable_share_floor: floor(&v["measurableShareFloor"]),
        twin_coverage_floor: floor(&v["twinCoverageFloor"]),
        replays: u(&v["replays"]) as u32,
        interval_z: v["intervalZ"].as_f64().unwrap(),
        interval_precision: u(&v["intervalPrecision"]) as u32,
    }
}

fn mechanics(v: &Value) -> AccountingConfig {
    AccountingConfig {
        min_denominator: u(&v["minDenominator"]) as u32,
        resolved_rate_floor: Floor::Uniform(0.0),
        measurable_share_floor: Floor::Uniform(0.0),
        twin_coverage_floor: Floor::Uniform(0.0),
        replays: u(&v["replays"]) as u32,
        interval_z: v["intervalZ"].as_f64().unwrap(),
        interval_precision: u(&v["intervalPrecision"]) as u32,
    }
}

// ---------------------------------------------------------------------------
// Legacy fixture → contract case.

fn kind(v: &Value) -> CaseKind {
    serde_json::from_value(v.clone()).expect("kind")
}

fn tier(v: &Value) -> EvidenceTier {
    serde_json::from_value(v.clone()).expect("tier")
}

fn expected_spans(v: &Value) -> Vec<ExpectedSpan> {
    v.as_array()
        .unwrap()
        .iter()
        .map(|e| ExpectedSpan {
            start: u(&e["start"]),
            end: u(&e["end"]),
            role: if e["role"] == "companion" {
                SpanRole::Companion
            } else {
                SpanRole::Secret
            },
            envelope: e.get("envelope").map(|en| Envelope {
                start: u(&en["start"]),
                end: u(&en["end"]),
                reason: en["reason"].as_str().unwrap_or("synthetic").to_owned(),
            }),
        })
        .collect()
}

/// `prefix` re-keys ids as `<prefix>--<id>` (the multi-category snapshot rule).
fn case_of(f: &Value, prefix: Option<&str>) -> Case {
    let id = |raw: &str| match prefix {
        Some(p) => format!("{p}--{raw}"),
        None => raw.to_owned(),
    };
    let a = &f["assessment"];
    let mut targets: Vec<String> = f["detectors"]
        .as_array()
        .map(|d| d.iter().map(|x| s(x).to_owned()).collect())
        .unwrap_or_default();
    targets.sort();
    targets.dedup();
    Case {
        id: CaseId::new(id(s(&f["id"]))).unwrap(),
        path: FixturePath::new(s(&f["path"])).unwrap(),
        content: s(&f["content"]).to_owned(),
        expected: expected_spans(&f["expected"]),
        grouping: Grouping {
            kind: kind(&a["kind"]),
            tier: tier(&a["tier"]),
            family: a.get("contract").map(|c| s(c).to_owned()),
            group: s(&f["group"]).to_owned(),
            evidence_class: None,
            targets,
            taxonomy: f.get("axis").map(|x| s(x).to_owned()),
        },
        twin: f.get("twinOf").map(|t| TwinLineage {
            twin_of: CaseId::new(id(s(t))).unwrap(),
            mutation: s(&f["mutation"]).to_owned(),
            mutation_kind: s(&f["mutationKind"]).to_owned(),
        }),
    }
}

fn snapshot(cases: Vec<Case>) -> CorpusSnapshot {
    CorpusSnapshot::seal(
        "oracle".into(),
        "c403475".into(),
        "legacy-schema-2".into(),
        cases,
    )
}

fn finding(v: &Value) -> NormalizedFinding {
    NormalizedFinding {
        path: FixturePath::new(s(&v["path"])).unwrap(),
        start: u(&v["start"]),
        end: u(&v["end"]),
        family: v.get("family").map(|x| s(x).to_owned()),
        action: v.get("action").map(|x| s(x).to_owned()),
    }
}

fn identity(id: &str, version: Option<&str>, configuration: &Value) -> ScannerIdentity {
    ScannerIdentity {
        id: ScannerId::new(id).unwrap(),
        version: version.map(str::to_owned),
        mode: "oracle".into(),
        adapter: AdapterIdentity {
            id: ComponentId::new("oracle").unwrap(),
            version: "1".into(),
        },
        configuration_hash: sha256_canonical(configuration),
        provenance: None,
        build: None,
    }
}

fn complete(findings: Vec<NormalizedFinding>) -> ScannerObservation {
    ScannerObservation {
        scanner: identity("sc", Some("1"), &json!({})),
        result: ObservationResult::Complete {
            findings,
            replays: Replays {
                count: 2,
                agreed: true,
            },
        },
        duration_ms: None,
    }
}

/// Compare one case result with one legacy scored row.
#[track_caller]
fn assert_row(ours: &CaseResult, row: &Value, context: &str) {
    let mut actual: Vec<ObservedRange> = row["actual"]
        .as_array()
        .unwrap()
        .iter()
        .map(|a| ObservedRange {
            start: u(&a["start"]),
            end: u(&a["end"]),
            family: a.get("family").map(|x| s(x).to_owned()),
            action: a.get("action").map(|x| s(x).to_owned()),
        })
        .collect();
    actual.sort();
    assert_eq!(ours.actual, actual, "{context}: actual");
    let expected: Vec<ScoredSpan> = row["expected"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| ScoredSpan {
            start: u(&e["start"]),
            end: u(&e["end"]),
            role: if e["role"] == "companion" {
                SpanRole::Companion
            } else {
                SpanRole::Secret
            },
            envelope: e
                .get("envelope")
                .map(|x| ByteRange::new(u(&x["start"]), u(&x["end"]))),
        })
        .collect();
    assert_eq!(ours.expected, expected, "{context}: expected");
    let legacy = if let Some(outcomes) = row.get("spanOutcomes") {
        CaseMeasurement::Positive {
            span_outcomes: serde_json::from_value(outcomes.clone()).unwrap(),
            leaked_bytes: u(&row["leakedBytes"]),
            collateral_bytes: u(&row["collateralBytes"]),
        }
    } else if let Some(flagged) = row.get("flagged") {
        CaseMeasurement::Control {
            flagged: flagged.as_bool().unwrap(),
            findings: u(&row["findings"]),
            co_detected: row
                .get("coDetected")
                .and_then(Value::as_bool)
                .unwrap_or(false),
            action_counts: row
                .get("actionCounts")
                .map(|c| serde_json::from_value(c.clone()).unwrap())
                .unwrap_or_default(),
        }
    } else {
        CaseMeasurement::Pending
    };
    assert_eq!(ours.measurement, legacy, "{context}: measurement");
}

/// Legacy `AccountedGroup` → contract `GroupAggregate` (legacy-map §4.5).
fn legacy_group(key: &str, g: &Value) -> GroupAggregate {
    let mut m = snake_keys(g).as_object().unwrap().clone();
    m.remove("scored");
    let population = if key == "pending/T0" {
        "pending"
    } else if key.starts_with("must-not-flag/") {
        "control"
    } else {
        "positive"
    };
    if let Some(d) = m.get("diagnostics").cloned() {
        m.insert("diagnostics".into(), d["exact"].clone());
    }
    m.insert("population".into(), json!(population));
    serde_json::from_value(Value::Object(m)).expect("legacy group maps onto the contract")
}

// ---------------------------------------------------------------------------
// 1. Mechanical primitives.

#[test]
fn primitives_match_legacy() {
    let g = golden("primitives.json");
    for r in g["round"].as_array().unwrap() {
        let (v, p, out) = (
            r[0].as_f64().unwrap(),
            u(&r[1]) as u32,
            r[2].as_f64().unwrap(),
        );
        assert_eq!(
            round_to_fixed(v, p).to_bits(),
            out.to_bits(),
            "round({v}, {p})"
        );
    }
    for r in g["wilson"].as_array().unwrap() {
        let dir: BoundDirection = serde_json::from_value(r[2].clone()).unwrap();
        let ours = accounting::wilson(
            r[0].as_f64().unwrap(),
            u(&r[1]),
            dir,
            r[3].as_f64().unwrap(),
            u(&r[4]) as u32,
        );
        assert_eq!(
            ours.to_bits(),
            r[5].as_f64().unwrap().to_bits(),
            "wilson {r}"
        );
    }
    for r in g["proportion"].as_array().unwrap() {
        let dir: BoundDirection = serde_json::from_value(r["dir"].clone()).unwrap();
        let ours = accounting::proportion(
            u(&r["num"]),
            u(&r["den"]),
            dir,
            &mechanics(&r["config"]),
            r["n"].as_u64(),
        );
        assert_eq!(ours, opt_published(&r["out"]), "proportion {r}");
    }
    for r in g["ratio"].as_array().unwrap() {
        let ours = accounting::ratio(
            u(&r["num"]),
            u(&r["den"]),
            &mechanics(&r["config"]),
            r["n"].as_u64(),
        );
        assert_eq!(ours, opt_published(&r["out"]), "ratio {r}");
    }
    for r in g["accountCounts"].as_array().unwrap() {
        let counts: StatusCounts = serde_json::from_value(r["counts"].clone()).unwrap();
        let ours = serde_json::to_value(account_counts(&counts, &mechanics(&r["config"]))).unwrap();
        assert_json(&ours, &snake_keys(&r["out"]), "accountCounts");
    }
    for r in g["unresolvedGroups"].as_array().unwrap() {
        let summary: BTreeMap<String, StatusCounts> =
            serde_json::from_value(r["summary"].clone()).unwrap();
        let ours = unresolved_groups(&summary, &accounting_config(&r["config"]));
        let legacy: Vec<String> = serde_json::from_value(r["out"].clone()).unwrap();
        assert_eq!(ours, legacy, "unresolvedGroups {}", r["summary"]);
    }
}

// ---------------------------------------------------------------------------
// 2. Lattice rows.

#[test]
fn lattice_rows_match_legacy() {
    let g = golden("lattice.json");
    for (i, r) in g["rows"].as_array().unwrap().iter().enumerate() {
        let expected: Vec<ScoredSpan> = expected_spans(&r["expected"])
            .into_iter()
            .map(|e| ScoredSpan {
                start: e.start,
                end: e.end,
                role: e.role,
                envelope: e.envelope.map(|x| x.range()),
            })
            .collect();
        let actual: Vec<ObservedRange> = r["actual"]
            .as_array()
            .unwrap()
            .iter()
            .map(|a| ObservedRange {
                start: u(&a["start"]),
                end: u(&a["end"]),
                family: a.get("family").map(|x| s(x).to_owned()),
                action: a.get("action").map(|x| s(x).to_owned()),
            })
            .collect();
        let ranges: Vec<ByteRange> = actual
            .iter()
            .map(|a| ByteRange::new(a.start, a.end))
            .collect();
        let ours = score_row(&expected, &actual, r["scope"].as_str());
        let row = json!({
            "expected": r["expected"], "actual": r["actual"],
            "spanOutcomes": r["out"].get("spanOutcomes"), "leakedBytes": r["out"].get("leakedBytes"),
            "collateralBytes": r["out"].get("collateralBytes"), "flagged": r["out"].get("flagged"),
            "findings": r["out"].get("findings"), "coDetected": r["out"].get("coDetected"),
            "actionCounts": r["out"].get("actionCounts"),
        });
        let row: Value = Value::Object(
            row.as_object()
                .unwrap()
                .iter()
                .filter(|(_, v)| !v.is_null())
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect(),
        );
        let result = CaseResult {
            case_id: CaseId::new("row").unwrap(),
            path: FixturePath::new("row.txt").unwrap(),
            kind: CaseKind::MustRedact,
            tier: EvidenceTier::T1,
            family: None,
            twin_of: None,
            group: "g".into(),
            targets: vec![],
            taxonomy: None,
            evidence_class: None,
            twin_mutation_kind: None,
            expected: expected.clone(),
            actual: {
                let mut a = actual.clone();
                a.sort();
                a
            },
            measurement: ours,
        };
        assert_row(&result, &row, &format!("lattice row {i}"));
        let legacy_union: Vec<ByteRange> = serde_json::from_value(r["union"].clone()).unwrap();
        assert_eq!(union(&ranges), legacy_union, "union {i}");
        let cover: Vec<ByteRange> = expected
            .iter()
            .map(|e| e.envelope.unwrap_or(ByteRange::new(e.start, e.end)))
            .collect();
        assert_eq!(
            bytes_outside(&ranges, &cover),
            u(&r["bytesOutside"]),
            "bytesOutside {i}"
        );
    }
}

// ---------------------------------------------------------------------------
// 3. Bench scoring, v1.1 accounting, v1.0 aggregation and the delta.

fn scored_suite(fixtures: &Value, findings: &Value) -> (CorpusSnapshot, Vec<CaseResult>) {
    let corpus = snapshot(
        fixtures
            .as_array()
            .unwrap()
            .iter()
            .map(|f| case_of(f, None))
            .collect(),
    );
    corpus
        .validate()
        .expect("synthetic suite is a valid snapshot");
    let observation = complete(findings.as_array().unwrap().iter().map(finding).collect());
    let set = ObservationSet {
        schema: ObservationSetSchema,
        corpus_digest: corpus.identity.corpus_digest.clone(),
        observations: vec![observation.clone()],
    };
    set.validate_against(&corpus).expect("findings valid");
    let run = score_scanner(&corpus, &observation);
    (corpus, run.cases)
}

fn v10_value(g: &compat::GroupV10) -> Value {
    match g {
        compat::GroupV10::Pending { files } => json!({ "files": files, "scored": false }),
        compat::GroupV10::Control {
            files,
            flagged_files,
            findings,
            false_alarm_rate,
            mean_findings_per_flagged,
            fp,
            tn,
        } => json!({
            "files": files, "flaggedFiles": flagged_files, "falseAlarmRate": false_alarm_rate, "findings": findings,
            "meanFindingsPerFlagged": mean_findings_per_flagged, "diagnostics": { "exact": { "fp": fp, "tn": tn }, "comparable": false },
        }),
        compat::GroupV10::Positive {
            files,
            spans,
            secret_bytes,
            outcomes,
            leaked_spans,
            leaked_span_rate,
            leaked_bytes,
            leaked_byte_rate,
            collateral_bytes,
            collateral_ratio,
            positives,
            pairs,
            discriminated,
            co_detected,
            twin_rate,
            tp,
            fp,
            fn_,
        } => json!({
            "files": files, "spans": spans, "secretBytes": secret_bytes,
            "outcomes": { "EXACT": outcomes[0], "COVERED": outcomes[1], "OVERBROAD": outcomes[2], "PARTIAL": outcomes[3], "MISS": outcomes[4] },
            "leakedSpans": leaked_spans, "leakedSpanRate": leaked_span_rate, "leakedBytes": leaked_bytes, "leakedByteRate": leaked_byte_rate,
            "collateralBytes": collateral_bytes, "collateralRatio": collateral_ratio,
            "twins": { "positives": positives, "pairs": pairs, "discriminated": discriminated, "coDetected": co_detected, "rate": twin_rate },
            "diagnostics": { "exact": { "tp": tp, "fp": fp, "fn": fn_ }, "comparable": false },
        }),
    }
}

#[test]
fn bench_accounting_matches_legacy() {
    let g = golden("accounting.json");
    for (i, suite) in g["suites"].as_array().unwrap().iter().enumerate() {
        let config = accounting_config(&suite["config"]);
        let (_, cases) = scored_suite(&suite["fixtures"], &suite["findings"]);
        let by_id: BTreeMap<&str, &CaseResult> =
            cases.iter().map(|c| (c.case_id.as_str(), c)).collect();
        for (row, encoded) in suite["rows"]
            .as_array()
            .unwrap()
            .iter()
            .zip(suite["encoded"].as_array().unwrap())
        {
            let ours = by_id[s(&row["id"])];
            assert_row(ours, row, &format!("suite {i} row {}", row["id"]));
            assert_eq!(
                compat::encode_outcome(ours).as_deref(),
                encoded.as_str(),
                "suite {i} encodeOutcome"
            );
        }
        // v1.1 groups.
        let groups = account_groups(&cases, &config);
        match (&groups, suite["groups"].get("ok")) {
            (Ok(ours), Some(legacy)) => {
                let legacy: BTreeMap<String, GroupAggregate> = legacy
                    .as_object()
                    .unwrap()
                    .iter()
                    .map(|(k, v)| (k.clone(), legacy_group(k, v)))
                    .collect();
                assert_eq!(ours, &legacy, "suite {i} accountGroups");
            }
            (ours, legacy) => panic!("suite {i}: accountGroups diverged: {ours:?} vs {legacy:?}"),
        }
        // v1.0 aggregation.
        let v10 = compat::aggregate_groups_v10(&cases).expect("v1.0");
        let ours: serde_json::Map<String, Value> =
            v10.iter().map(|(k, v)| (k.clone(), v10_value(v))).collect();
        assert_json(
            &Value::Object(ours),
            &suite["v10"]["ok"],
            &format!("suite {i} aggregateGroups"),
        );
        // Delta.
        match (
            compat::accounting_delta(&cases, &config),
            suite["delta"].get("ok"),
        ) {
            (Ok(ours), Some(legacy)) => {
                let ours = serde_json::to_value(ours).unwrap();
                assert_json(
                    &ours,
                    &legacy["groups"],
                    &format!("suite {i} accountingDelta"),
                );
            }
            (Err(_), None) => {}
            (ours, legacy) => panic!("suite {i}: accountingDelta diverged: {ours:?} vs {legacy:?}"),
        }
    }
}

#[test]
fn selection_groups_match_legacy() {
    let g = golden("selection.json");
    for (i, run) in g["runs"].as_array().unwrap().iter().enumerate() {
        let config = accounting_config(&run["config"]);
        let mut all_cases: Vec<CaseResult> = Vec::new();
        for (k, cat) in run["categories"].as_array().unwrap().iter().enumerate() {
            let name = format!("c{i}x{k}");
            let fixtures: Vec<Case> = cat["fixtures"]
                .as_array()
                .unwrap()
                .iter()
                .map(|f| {
                    let mut c = case_of(f, Some(&name));
                    c.grouping.group = name.clone();
                    c
                })
                .collect();
            let corpus = snapshot(fixtures);
            let observation = complete(
                cat["findings"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(finding)
                    .collect(),
            );
            all_cases.extend(score_scanner(&corpus, &observation).cases);
        }
        let suites: Vec<SuiteCase<'_>> = all_cases
            .iter()
            .map(|c| SuiteCase {
                suite: c.group.as_str(),
                case: c,
            })
            .collect();
        let assignments: BTreeMap<CaseId, Vec<String>> =
            serde_json::from_value(run["assignments"].clone()).unwrap();
        let ours = summarize_selections(&suites, &assignments, &config).expect("selection");
        let legacy = &run["summary"]["ok"];
        let map = |groups: &Value| -> BTreeMap<String, GroupAggregate> {
            groups
                .as_object()
                .unwrap()
                .iter()
                .map(|(k, v)| (k.clone(), legacy_group(k, v)))
                .collect()
        };
        assert_eq!(
            ours.overall,
            map(&legacy["overall"]["sc"]),
            "run {i} overall"
        );
        let mut legacy_by: BTreeMap<String, BTreeMap<String, GroupAggregate>> = BTreeMap::new();
        for (target, scanners) in legacy["byDetector"].as_object().unwrap() {
            if let Some(groups) = scanners.get("sc") {
                legacy_by.insert(target.clone(), map(groups));
            }
        }
        assert_eq!(ours.by_target, legacy_by, "run {i} byDetector");
    }
}

#[test]
fn twin_probe_matches_legacy() {
    let g = golden("twin-probe.json");
    for (i, p) in g["probes"].as_array().unwrap().iter().enumerate() {
        let families: Vec<String> = serde_json::from_value(p["families"].clone()).unwrap();
        let fixtures: Vec<ProbeFixture> = p["fixtures"]
            .as_array()
            .unwrap()
            .iter()
            .map(|f| ProbeFixture {
                id: CaseId::new(s(&f["id"])).unwrap(),
                family: f["detectors"].get(0).map(|d| s(d).to_owned()),
                twin_of: f.get("twinOf").map(|t| CaseId::new(s(t)).unwrap()),
            })
            .collect();
        let unprobeable: BTreeMap<String, UnprobeableRecord> = p["unprobeable"]
            .as_object()
            .unwrap()
            .iter()
            .map(|(k, v)| {
                (
                    k.clone(),
                    serde_json::from_value(v["unprobeable"].clone()).unwrap(),
                )
            })
            .collect();
        let cases = p["rowsPresent"]
            .as_bool()
            .unwrap()
            .then(|| scored_suite(&p["fixtures"], &p["findings"]).1);
        let ours = twin_probe(&families, &fixtures, cases.as_deref(), &unprobeable);
        match (ours, p["out"].get("ok")) {
            (Ok(ours), Some(legacy)) => assert_json(
                &serde_json::to_value(ours).unwrap(),
                legacy,
                &format!("probe {i}"),
            ),
            (Err(_), None) => {}
            (ours, legacy) => panic!("probe {i}: diverged: {ours:?} vs {legacy:?}"),
        }
    }
}

// ---------------------------------------------------------------------------
// 4. Evaluation methods end to end.

const AXES: [&str; 13] = [
    "public-identifier",
    "placeholder",
    "reference",
    "ordinary-prose",
    "near-miss",
    "encoded-value",
    "pending",
    "realworld-config",
    "realworld-logs",
    "realworld-lockfile",
    "realworld-source",
    "realworld-docs",
    "realworld-agent-output",
];

fn evidence(contracts: &Value) -> EvaluationEvidence {
    // The two families legacy `structural.remove-segment` hard-codes, as data.
    let segments = BTreeMap::from([
        (
            "sendgrid-token",
            SegmentRule {
                delimiter: ".".into(),
                removable: vec![1, 2],
            },
        ),
        (
            "slack-token",
            SegmentRule {
                delimiter: "-".into(),
                removable: vec![1, 2, 3],
            },
        ),
    ]);
    let families = contracts
        .as_object()
        .unwrap()
        .iter()
        .map(|(k, v)| {
            (
                k.clone(),
                FamilyContract {
                    pattern: v.get("pattern").map(|p| s(p).to_owned()),
                    segments: segments.get(k.as_str()).cloned(),
                    unprobeable: None,
                },
            )
        })
        .collect();
    EvaluationEvidence {
        contracts: FamilyContracts::new(families).unwrap(),
        benign_taxonomies: Some(AXES.iter().map(|a| (*a).to_owned()).collect()),
    }
}

fn transformation_value(t: &credential_eval_kernel::evaluation::model::Transformation) -> Value {
    let mut v = snake_to_camel(&serde_json::to_value(t).unwrap());
    // Legacy leaves `parameters` undefined on the canonical variant.
    if t.operator.as_str() == "identity" {
        v.as_object_mut().unwrap().remove("parameters");
    }
    v
}

fn snake_to_camel(v: &Value) -> Value {
    match v {
        Value::Object(m) => Value::Object(
            m.iter()
                .map(|(k, v)| {
                    let mut out = String::new();
                    let mut up = false;
                    for c in k.chars() {
                        if c == '_' {
                            up = true;
                        } else if up {
                            out.push(c.to_ascii_uppercase());
                            up = false;
                        } else {
                            out.push(c);
                        }
                    }
                    (out, snake_to_camel(v))
                })
                .collect(),
        ),
        Value::Array(a) => Value::Array(a.iter().map(snake_to_camel).collect()),
        other => other.clone(),
    }
}

#[test]
fn evaluation_matches_legacy() {
    let g = golden("evaluation.json");
    let config = accounting_config(&g["accounting"]);
    let evidence = evidence(&g["contracts"]);

    // Snapshot of the synthetic categories (ids `<category>--<fixture>`).
    let mut cases = Vec::new();
    for cat in g["categories"].as_array().unwrap() {
        for f in cat["fixtures"].as_array().unwrap() {
            cases.push(case_of(f, Some(s(&cat["id"]))));
        }
    }
    let corpus = snapshot(cases);
    corpus.validate().expect("valid snapshot");

    // Case construction (loadCases) with the legacy seed convention.
    let built = build_cases(&corpus, &MethodId::ALL, &compat::legacy_seed).expect("cases");
    let ours: BTreeSet<(String, String, String)> = built
        .iter()
        .map(|c| {
            (
                c.id.to_string(),
                c.method.as_str().to_owned(),
                c.seed_key.clone(),
            )
        })
        .collect();
    let legacy: BTreeSet<(String, String, String)> = g["cases"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| {
            (
                s(&c["id"]).to_owned(),
                s(&c["method"]).to_owned(),
                s(&c["seed"]).to_owned(),
            )
        })
        .collect();
    assert_eq!(ours, legacy, "evaluation cases");

    // Generation.
    let plan = plan_evaluation(built, &evidence, &GenerationLimits::default()).expect("plan");
    let planned: BTreeMap<&str, &credential_eval_kernel::evaluation::GeneratedCase> =
        plan.cases.iter().map(|c| (c.case.id.as_str(), c)).collect();
    assert_eq!(planned.len(), g["plan"].as_array().unwrap().len());
    for lp in g["plan"].as_array().unwrap() {
        let ours = planned[s(&lp["case"])];
        let lv = lp["variants"].as_array().unwrap();
        assert_eq!(
            ours.variants.len(),
            lv.len(),
            "{}: variant count",
            lp["case"]
        );
        for (v, l) in ours.variants.iter().zip(lv) {
            let ctx = format!("{} {}", lp["case"], l["id"]);
            assert_eq!(v.id.as_str(), s(&l["id"]), "{ctx}");
            assert_eq!(v.fixture.path.as_str(), s(&l["path"]), "{ctx}: path");
            assert_eq!(v.fixture.content, s(&l["content"]), "{ctx}: content");
            let expected: Vec<ExpectedSpan> = expected_spans(&l["expected"]);
            let strip = |e: &[ExpectedSpan]| -> Vec<(u64, u64, SpanRole, Option<ByteRange>)> {
                e.iter()
                    .map(|x| {
                        (
                            x.start,
                            x.end,
                            x.role,
                            x.envelope.as_ref().map(Envelope::range),
                        )
                    })
                    .collect()
            };
            assert_eq!(
                strip(&v.fixture.expected),
                strip(&expected),
                "{ctx}: expected"
            );
            assert_eq!(v.fixture.grouping.kind, kind(&l["kind"]), "{ctx}: kind");
            assert_eq!(v.fixture.grouping.tier, tier(&l["tier"]), "{ctx}: tier");
            assert_eq!(
                v.fixture.grouping.family.as_deref(),
                l["contract"].as_str(),
                "{ctx}: family"
            );
            assert_eq!(
                serde_json::to_value(v.strategy).unwrap(),
                l["strategy"],
                "{ctx}: strategy"
            );
            let mut lt = l["transformation"].clone();
            // `relation: null` and an absent relation are the same record.
            lt.as_object_mut().unwrap().retain(|_, x| !x.is_null());
            assert_json(
                &transformation_value(&v.transformation),
                &lt,
                &format!("{ctx}: transformation"),
            );
        }
        let attempts: Vec<Value> = ours
            .attempts
            .iter()
            .map(|a| {
                let mut v = snake_to_camel(&serde_json::to_value(a).unwrap());
                v.as_object_mut().unwrap().remove("parametersHash");
                v
            })
            .collect();
        assert_json(
            &Value::Array(attempts),
            &lp["attempts"],
            &format!("{}: attempts", lp["case"]),
        );
    }

    // Observations recorded by the legacy runtime over the variant corpus.
    let variant_corpus = plan.variant_corpus(&corpus.identity);
    let observations = ObservationSet {
        schema: ObservationSetSchema,
        corpus_digest: variant_corpus.identity.corpus_digest.clone(),
        observations: g["observations"]
            .as_array()
            .unwrap()
            .iter()
            .map(|o| {
                let result = match s(&o["status"]) {
                    "complete" => ObservationResult::Complete {
                        findings: o["findings"]
                            .as_array()
                            .unwrap()
                            .iter()
                            .map(finding)
                            .collect(),
                        replays: Replays {
                            count: u(&o["replays"]["count"]) as u32,
                            agreed: true,
                        },
                    },
                    "unstable" => ObservationResult::Unstable {
                        replays: Replays {
                            count: u(&o["replays"]["count"]) as u32,
                            agreed: false,
                        },
                        divergent_paths: serde_json::from_value(
                            o["replays"]["divergentPaths"].clone(),
                        )
                        .unwrap(),
                    },
                    "unavailable" => ObservationResult::Unavailable {
                        reason: "unavailable".into(),
                    },
                    "unsupported" => ObservationResult::Unsupported {
                        reason: "no ranges".into(),
                    },
                    _ => ObservationResult::Error {
                        reason: "error".into(),
                    },
                };
                ScannerObservation {
                    scanner: identity(s(&o["id"]), o["version"].as_str(), &o["configuration"]),
                    result,
                    duration_ms: None,
                }
            })
            .collect(),
    };
    let reference = ScannerId::new("redact-secret").unwrap();
    let report = evaluate(
        &plan,
        &corpus.identity,
        &observations,
        EvaluateOptions {
            reference: Some(&reference),
            accounting: &config,
        },
    )
    .expect("evaluate");

    // Per-case assertions, rows, comparisons and differential observations.
    let results: BTreeMap<&str, &credential_eval_kernel::evaluation::CaseEvaluation> = report
        .results
        .iter()
        .map(|r| (r.generated.case.id.as_str(), r))
        .collect();
    for lr in g["results"].as_array().unwrap() {
        let id = s(&lr["id"]);
        let ours = results[id];
        let mut targets = ours.generated.case.targets.clone();
        targets.sort();
        let mut lt: Vec<String> = serde_json::from_value(lr["targets"].clone()).unwrap();
        lt.sort();
        assert_eq!(targets, lt, "{id}: targets");
        assert_eq!(
            ours.generated.case.taxonomy.as_deref(),
            lr["taxonomy"].as_str(),
            "{id}: taxonomy"
        );
        let ls = lr["scanners"].as_array().unwrap();
        assert_eq!(ours.scanners.len(), ls.len(), "{id}: scanners");
        for l in ls {
            let sc = ours
                .scanners
                .iter()
                .find(|x| x.scanner.as_str() == s(&l["scanner"]))
                .expect("scanner");
            assert_eq!(
                serde_json::to_value(sc.status).unwrap(),
                l["status"],
                "{id}: status"
            );
            let assertions: Vec<Value> = sc
                .assertions
                .iter()
                .map(|a| {
                    let mut v = json!({ "type": a.assertion, "status": a.status });
                    let m = v.as_object_mut().unwrap();
                    for (k, x) in [
                        ("variant", &a.variant),
                        ("baseline", &a.baseline),
                        ("candidate", &a.candidate),
                    ] {
                        if let Some(x) = x {
                            m.insert(k.into(), json!(x));
                        }
                    }
                    if let Some(r) = &a.reason {
                        m.insert("reason".into(), json!(r));
                    }
                    v
                })
                .collect();
            let legacy_assertions: Vec<Value> = l["assertions"]
                .as_array()
                .unwrap()
                .iter()
                .map(|a| {
                    let mut a = a.clone();
                    // Legacy spells the non-complete reason as its status; the
                    // contract folds nothing here, so compare as is.
                    a.as_object_mut().unwrap().retain(|_, v| !v.is_null());
                    a
                })
                .collect();
            assert_json(
                &Value::Array(assertions),
                &Value::Array(legacy_assertions),
                &format!("{id} {}: assertions", l["scanner"]),
            );
            let lvs = l["variants"].as_array().unwrap();
            assert_eq!(sc.rows.len(), lvs.len(), "{id}: rows");
            for (row, lv) in sc.rows.iter().zip(lvs) {
                assert_row(
                    row,
                    &lv["row"],
                    &format!("{id} {} {}", l["scanner"], lv["id"]),
                );
            }
        }
        match (&ours.differential, lr["comparisons"].as_array()) {
            (Some(d), Some(lc)) => {
                let ours: BTreeSet<String> = d
                    .comparisons
                    .iter()
                    .map(|c| {
                        json!({
                            "variant": c.variant, "peer": c.peer, "status": c.status,
                            "disagreement": c.disagreement.map(compat::legacy_disagreement),
                            "classification": c.classification_compared.map(|b| if b { "compared" } else { "unsupported" }),
                        })
                        .to_string()
                    })
                    .collect();
                let legacy: BTreeSet<String> = lc
                    .iter()
                    .map(|c| {
                        json!({
                            "variant": c["variant"], "peer": c["peer"], "status": c["status"],
                            "disagreement": c.get("disagreement"), "classification": c.get("classification"),
                        })
                        .to_string()
                    })
                    .collect();
                assert_eq!(ours, legacy, "{id}: comparisons");
                assert_eq!(Some(d.complete), lr["complete"].as_bool(), "{id}: complete");
                for lo in lr["observations"].as_array().unwrap() {
                    let (status, seen) =
                        &d.observations[&ScannerId::new(s(&lo["scanner"])).unwrap()];
                    assert_eq!(serde_json::to_value(status).unwrap(), lo["status"]);
                    let mut legacy = lo["variants"].clone();
                    for v in legacy.as_array_mut().unwrap() {
                        let mut actual: Vec<ObservedRange> =
                            serde_json::from_value(v["actual"].clone()).unwrap();
                        actual.sort();
                        v["actual"] = serde_json::to_value(actual).unwrap();
                    }
                    assert_json(
                        &serde_json::to_value(seen).unwrap(),
                        &legacy,
                        &format!("{id}: differential observations"),
                    );
                }
            }
            (None, None) => {}
            (ours, legacy) => panic!("{id}: differential presence differs: {ours:?} vs {legacy:?}"),
        }
    }

    // Review queue (membership; legacy ids hash legacy fixture objects and
    // are compared by #5 through the compatibility exporter).
    let ours_queue: BTreeSet<String> = report
        .review_queue
        .iter()
        .map(|e| {
            let mut targets = e.targets.clone();
            targets.sort();
            json!({
                "caseId": e.case_id, "method": e.method, "targets": targets, "variant": e.variant,
                "peer": e.peer, "disagreement": e.disagreement.map(compat::legacy_disagreement),
                "observations": e.observations, "classifications": e.classifications, "reason": e.reason,
            })
            .to_string()
        })
        .collect();
    let legacy_queue: BTreeSet<String> = g["reviewQueue"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| {
            let mut targets: Vec<String> = serde_json::from_value(e["targets"].clone()).unwrap();
            targets.sort();
            // BTreeMap order for the per-scanner maps, as ours serialize.
            let sorted = |v: Option<&Value>| -> Value {
                v.map_or(Value::Null, |m| {
                    let m: BTreeMap<String, Value> = serde_json::from_value(m.clone()).unwrap();
                    serde_json::to_value(m).unwrap()
                })
            };
            json!({
                "caseId": e["caseId"], "method": e["method"], "targets": targets, "variant": e["variant"],
                "peer": e.get("peer"), "disagreement": e.get("disagreement"),
                "observations": sorted(e.get("observations")), "classifications": sorted(e.get("classifications")),
                "reason": e.get("reason"),
            })
            .to_string()
        })
        .collect();
    assert_eq!(
        ours_queue.len(),
        report.review_queue.len(),
        "queue entries are unique"
    );
    assert_eq!(ours_queue, legacy_queue, "review queue");

    // Summaries, resolution, unresolved groups and the assertion delta.
    let sums = &g["summaries"];
    assert_json(
        &serde_json::to_value(&report.summaries.by_method).unwrap(),
        &sums["byMethod"],
        "byMethod",
    );
    assert_json(
        &serde_json::to_value(&report.summaries.by_target).unwrap(),
        &sums["byDetector"],
        "byDetector",
    );
    assert_json(
        &serde_json::to_value(&report.summaries.by_taxonomy).unwrap(),
        &sums["byTaxonomy"],
        "byTaxonomy",
    );
    assert_json(
        &serde_json::to_value(&report.summaries.by_operator).unwrap(),
        &sums["byOperator"],
        "byOperator",
    );
    assert_json(
        &serde_json::to_value(&report.summaries.axes_by_target).unwrap(),
        &sums["axesByDetector"],
        "axesByDetector",
    );
    let resolution: BTreeMap<String, AccountedCounts> = g["resolution"]
        .as_object()
        .unwrap()
        .iter()
        .map(|(k, v)| (k.clone(), serde_json::from_value(snake_keys(v)).unwrap()))
        .collect();
    assert_eq!(report.resolution, resolution, "resolution");
    let unresolved: Vec<String> = serde_json::from_value(g["unresolvedGroups"].clone()).unwrap();
    assert_eq!(report.unresolved_groups, unresolved, "unresolvedGroups");
    let unstable: BTreeSet<String> = report
        .statuses
        .iter()
        .filter(|(_, s)| **s == credential_eval_contracts::observation::ScannerStatus::Unstable)
        .map(|(k, _)| k.to_string())
        .collect();
    let delta = compat::assertion_delta(&report.summaries.by_method, &unstable, &config);
    let mut delta = serde_json::to_value(delta).unwrap();
    for group in delta.as_object_mut().unwrap().values_mut() {
        group["v10"].as_object_mut().unwrap().remove("not-measured");
        let v11 = group["v11"].take();
        group["v11"] = snake_to_camel(&v11);
    }
    let mut legacy_delta = g["accountingDelta"]["groups"].clone();
    for group in legacy_delta.as_object_mut().unwrap().values_mut() {
        let v11 = group["v11"].take();
        group["v11"] = snake_to_camel(&snake_keys(&v11));
    }
    assert_json(&delta, &legacy_delta, "assertion accountingDelta");

    // Failures and the exit code.
    assert_eq!(
        report.failures.len(),
        g["failures"].as_array().unwrap().len(),
        "failures"
    );
    assert_eq!(
        i64::from(report.exit_code(false, false)),
        g["exitCode"].as_i64().unwrap(),
        "exitCode"
    );

    // Seeded choices.
    for c in g["seededChoices"].as_array().unwrap() {
        assert_eq!(
            seeded_choice(s(&c["seed"]), s(&c["operator"]), u(&c["size"])),
            u(&c["out"]),
            "seededChoice {c}"
        );
    }

    // The artifact projection is well formed and deterministic.
    let parts = report.artifact_parts(&plan);
    assert_eq!(
        parts.variants.len(),
        plan.cases.iter().map(|c| c.variants.len()).sum::<usize>()
    );
    assert!(parts.review_queue.windows(2).all(|w| w[0] < w[1]));
    let again = evaluate(
        &plan,
        &corpus.identity,
        &observations,
        EvaluateOptions {
            reference: Some(&reference),
            accounting: &config,
        },
    )
    .unwrap();
    assert_eq!(again, report, "evaluation is deterministic");
    let _ = Outcome::ALL;
}
