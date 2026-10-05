//! Output contract tests: every artifact variant serializes to JSON that the
//! committed schema accepts, and round-trips through the types.

use std::collections::BTreeMap;

use credential_eval_contracts::artifact::*;
use credential_eval_contracts::config::{AccountingConfig, AdapterIdentity, Floor};
use credential_eval_contracts::corpus::{
    CaseKind, EvidenceRelease, EvidenceTier, SnapshotIdentity, SpanRole,
};
use credential_eval_contracts::ids::{
    CaseId, ComponentId, FixturePath, ReleaseTag, ScannerId, Sha256Digest,
};
use credential_eval_contracts::observation::{ScannerBuild, ScannerIdentity, ScannerStatus};
use credential_eval_contracts::range::ByteRange;
use credential_eval_contracts::schema::{RunArtifactSchema, all_schemas};
use credential_eval_contracts::{ENGINE_NAME, PROTOCOL_VERSION};

fn digest(c: char) -> Sha256Digest {
    Sha256Digest::new(format!("sha256:{}", c.to_string().repeat(64))).unwrap()
}

fn rate(point: f64, bound: f64, n: u64, direction: BoundDirection) -> Option<Published> {
    Some(Published::Rate(Rate {
        point,
        bound: Some(bound),
        n,
        direction: Some(direction),
    }))
}

fn sample() -> RunArtifact {
    let scanner = ScannerId::new("example-scanner").unwrap();
    let case_id = CaseId::new("case-one").unwrap();
    let mut groups = BTreeMap::new();
    groups.insert(
        "pending/T0".to_owned(),
        GroupAggregate::Pending {
            files: 1,
            candidate_kinds: BTreeMap::from([("must-redact".to_owned(), 1)]),
        },
    );
    groups.insert(
        "must-not-flag/T1".to_owned(),
        GroupAggregate::Control {
            files: 10,
            flagged_files: 1,
            findings: 2,
            false_alarm_rate: rate(0.1, 0.404155, 10, BoundDirection::Upper),
            mean_findings_per_flagged: Some(Published::Withheld(Withheld::InsufficientEvidence)),
            diagnostics: ControlDiagnostics { fp: 2, tn: 9 },
        },
    );
    groups.insert(
        "must-redact/T1".to_owned(),
        GroupAggregate::Positive {
            files: 5,
            spans: 5,
            secret_bytes: 160,
            outcomes: OutcomeCounts {
                exact: 2,
                covered: 1,
                overbroad: 1,
                partial: 0,
                miss: 1,
            },
            pending_files: 1,
            measurable_share: rate(0.833333, 0.436497, 6, BoundDirection::Lower),
            envelope_width: EnvelopeWidth { spans: 1, bytes: 7 },
            leaked_spans: 1,
            leaked_span_rate: rate(0.2, 0.624465, 5, BoundDirection::Upper),
            leaked_bytes: 32,
            leaked_byte_rate: rate(0.2, 0.624465, 5, BoundDirection::Upper),
            collateral_bytes: 12,
            collateral_ratio: Some(Published::Rate(Rate {
                point: 0.075,
                bound: None,
                n: 160,
                direction: None,
            })),
            twins: TwinMeasurement {
                positives: 5,
                pairs: 1,
                discriminated: 1,
                co_detected: 0,
                coverage: rate(0.2, 0.036224, 5, BoundDirection::Lower),
                rate: Some(Published::Withheld(Withheld::InsufficientCoverage)),
            },
            diagnostics: PositiveDiagnostics {
                tp: 2,
                fp: 2,
                fn_: 3,
            },
        },
    );
    RunArtifact {
        schema: RunArtifactSchema,
        manifest: RunManifest {
            engine: EngineIdentity {
                name: ENGINE_NAME.into(),
                version: "0.0.0".into(),
            },
            protocol_version: PROTOCOL_VERSION.into(),
            evidence: SnapshotIdentity {
                source: "synthetic".into(),
                revision: "r1".into(),
                evidence_schema: "synthetic-v1".into(),
                corpus_digest: digest('a'),
                release: Some(EvidenceRelease {
                    tag: ReleaseTag::new("snapshot-2026.10.01").unwrap(),
                    manifest_digest: digest('d'),
                }),
                representation: None,
            },
            config_hash: digest('b'),
            accounting: AccountingConfig {
                min_denominator: 5,
                resolved_rate_floor: Floor::Keyed {
                    default: 0.9,
                    overrides: BTreeMap::from([("differential".into(), 0.0)]),
                },
                measurable_share_floor: Floor::Uniform(0.7),
                twin_coverage_floor: Floor::Uniform(0.5),
                replays: 2,
                interval_z: 1.96,
                interval_precision: 6,
            },
            methods: vec![MethodIdentity {
                id: ComponentId::new("twin").unwrap(),
                version: 1,
            }],
            scanners: vec![ScannerIdentity {
                id: scanner.clone(),
                version: Some("1.2.3".into()),
                mode: "default".into(),
                adapter: AdapterIdentity {
                    id: ComponentId::new("example").unwrap(),
                    version: "1".into(),
                },
                configuration_hash: digest('c'),
                provenance: None,
                build: Some(ScannerBuild::Released),
            }],
            run_class: Some(RunClass::Official),
            publication: Some(Publication::Public),
            representation: None,
        },
        scanners: vec![ScannerRun {
            scanner: scanner.clone(),
            status: ScannerStatus::Complete,
            detail: None,
            replays: None,
            findings: vec![],
            cases: vec![CaseResult {
                case_id: case_id.clone(),
                path: FixturePath::new("a/b.txt").unwrap(),
                kind: CaseKind::MustRedact,
                tier: EvidenceTier::T1,
                family: Some("example".into()),
                twin_of: None,
                group: "synthetic".into(),
                targets: vec!["example".into()],
                taxonomy: None,
                evidence_class: None,
                twin_mutation_kind: None,
                expected: vec![ScoredSpan {
                    start: 0,
                    end: 4,
                    role: SpanRole::Secret,
                    envelope: Some(ByteRange::new(0, 6)),
                }],
                actual: vec![],
                measurement: CaseMeasurement::Positive {
                    span_outcomes: vec![Outcome::Miss],
                    leaked_bytes: 4,
                    collateral_bytes: 0,
                },
            }],
            assertions: vec![Assertion {
                case_id: case_id.clone(),
                method: ComponentId::new("mutation").unwrap(),
                variant: None,
                baseline: Some(ComponentId::new("canonical").unwrap()),
                candidate: Some(ComponentId::new("lexical.length-plus-one").unwrap()),
                assertion: AssertionType::SameDetection,
                status: AssertionStatus::ReviewRequired,
                reason: None,
            }],
            aggregates: Aggregates {
                groups,
                resolution: BTreeMap::from([(
                    "mutation/must-redact:T1/same-detection".to_owned(),
                    AccountedCounts {
                        pass: 0,
                        fail: 0,
                        review_required: 1,
                        not_measured: 0,
                        total: 1,
                        resolved: 0,
                        unresolved: 1,
                        resolved_rate: Some(Published::Withheld(Withheld::InsufficientEvidence)),
                    },
                )]),
                by_target: BTreeMap::new(),
                resolution_by_target: BTreeMap::new(),
            },
            unmeasured_cases: vec![],
            scope_accounting: None,
        }],
        variants: vec![VariantRecord {
            case_id: case_id.clone(),
            variant: ComponentId::new("lexical.length-plus-one").unwrap(),
            path: FixturePath::new("cases/case-one/lexical.length-plus-one.txt").unwrap(),
            method: MethodIdentity {
                id: ComponentId::new("mutation").unwrap(),
                version: 1,
            },
            operator: ComponentId::new("lexical.length-plus-one").unwrap(),
            operator_version: 1,
            parameters: BTreeMap::new(),
            strategy: VariantStrategy::Derived,
            relation: Some(Relation::SameDetection),
            property: Some("length".into()),
            content_digest: digest('d'),
        }],
        comparisons: vec![DifferentialComparison {
            case_id: case_id.clone(),
            variant: ComponentId::new("canonical").unwrap(),
            reference: scanner.clone(),
            peer: ScannerId::new("other-scanner").unwrap(),
            status: ComparisonStatus::Complete,
            disagreement: Some(Disagreement::ReferenceOnly),
            classification_compared: Some(false),
        }],
        review_queue: vec![ReviewOccurrence {
            id: digest('e'),
            case_id,
            method: ComponentId::new("differential").unwrap(),
            variant: ComponentId::new("canonical").unwrap(),
            baseline: None,
            candidate: None,
            reference: Some(scanner),
            peer: Some(ScannerId::new("other-scanner").unwrap()),
            disagreement: Some(Disagreement::ReferenceOnly),
        }],
        non_semantic: NonSemantic {
            run_id: Some("run-1".into()),
            started_at: Some("2026-01-01T00:00:00Z".into()),
            ..NonSemantic::default()
        },
    }
}

#[test]
fn every_variant_validates_and_round_trips() {
    let artifact = sample();
    let value = serde_json::to_value(&artifact).unwrap();
    let (_, schema) = all_schemas()
        .into_iter()
        .find(|(file, _)| *file == "run-artifact-v1.schema.json")
        .unwrap();
    let validator = jsonschema::validator_for(&serde_json::to_value(schema).unwrap()).unwrap();
    let errors: Vec<String> = validator
        .iter_errors(&value)
        .map(|e| e.to_string())
        .collect();
    assert!(errors.is_empty(), "{errors:?}");
    let back: RunArtifact = serde_json::from_value(value.clone()).unwrap();
    assert_eq!(back, artifact);

    // Wire spellings consumers rely on.
    let group = &value["scanners"][0]["aggregates"]["groups"]["must-redact/T1"];
    assert_eq!(group["population"], "positive");
    assert_eq!(group["outcomes"]["OVERBROAD"], 1);
    assert_eq!(group["twins"]["rate"], "insufficient-coverage");
    assert_eq!(group["diagnostics"]["fn"], 3);
    assert_eq!(
        value["scanners"][0]["cases"][0]["measurement"]["span_outcomes"][0],
        "MISS"
    );
}

#[test]
fn semantic_digest_ignores_non_semantic_metadata() {
    let a = sample();
    let mut b = sample();
    b.non_semantic = NonSemantic::default();
    b.non_semantic
        .durations_ms
        .insert("example-scanner".into(), 12);
    assert_eq!(a.semantic_digest(), b.semantic_digest());
    let mut c = sample();
    c.scanners[0].cases[0].measurement = CaseMeasurement::NotMeasured {
        status: ScannerStatus::Error,
    };
    assert_ne!(a.semantic_digest(), c.semantic_digest());
}
