//! One focused test per semantic rule of the kernel (accounting withholding,
//! twin discrimination, differential observation, review ids, operators,
//! generation bounds, artifact aggregates).

use std::collections::BTreeMap;

use credential_eval_contracts::artifact::{
    AssertionStatus, AssertionType, CaseMeasurement, CaseResult, ComparisonStatus, Disagreement,
    GroupAggregate, ObservedRange, Outcome, Published, ScoredSpan, VariantStrategy, Withheld,
};
use credential_eval_contracts::config::{AccountingConfig, AdapterIdentity, Floor};
use credential_eval_contracts::corpus::{
    Case, CaseKind, CorpusSnapshot, EvidenceTier, ExpectedSpan, Grouping, SpanRole, TwinLineage,
};
use credential_eval_contracts::ids::{CaseId, ComponentId, FixturePath, ScannerId, Sha256Digest};
use credential_eval_contracts::observation::{
    NormalizedFinding, ObservationResult, ObservationSet, Replays, ScannerIdentity,
    ScannerObservation, ScannerStatus,
};
use credential_eval_contracts::schema::ObservationSetSchema;
use credential_eval_kernel::KernelError;
use credential_eval_kernel::accounting::{account_groups, proportion, ratio};
use credential_eval_kernel::evaluation::cases::{build_cases, case_id_seed};
use credential_eval_kernel::evaluation::model::AttemptStatus;
use credential_eval_kernel::evaluation::{
    EvaluateOptions, EvaluationEvidence, FamilyContract, FamilyContracts, GenerationLimits,
    MethodId, OperatorId, SegmentRule, evaluate, plan_evaluation,
};
use credential_eval_kernel::twin_probe::{
    ProbeFixture, TwinProbeStatus, UnprobeableRecord, twin_probe,
};

fn config() -> AccountingConfig {
    AccountingConfig {
        min_denominator: 1,
        resolved_rate_floor: Floor::Uniform(0.9),
        measurable_share_floor: Floor::Uniform(0.7),
        twin_coverage_floor: Floor::Uniform(0.5),
        replays: 2,
        interval_z: 1.96,
        interval_precision: 6,
    }
}

fn result(
    id: &str,
    kind: CaseKind,
    tier: EvidenceTier,
    measurement: CaseMeasurement,
) -> CaseResult {
    CaseResult {
        case_id: CaseId::new(id).unwrap(),
        path: FixturePath::new(format!("{id}.txt")).unwrap(),
        kind,
        tier,
        family: Some("fam".into()),
        twin_of: None,
        group: "g".into(),
        targets: vec![],
        taxonomy: None,
        evidence_class: None,
        twin_mutation_kind: None,
        expected: if matches!(measurement, CaseMeasurement::Positive { .. }) {
            vec![ScoredSpan {
                start: 0,
                end: 10,
                role: SpanRole::Secret,
                envelope: None,
            }]
        } else {
            vec![]
        },
        actual: vec![],
        measurement,
    }
}

fn positive(id: &str, outcome: Outcome) -> CaseResult {
    result(
        id,
        CaseKind::MustRedact,
        EvidenceTier::T1,
        CaseMeasurement::Positive {
            span_outcomes: vec![outcome],
            leaked_bytes: 0,
            collateral_bytes: 0,
        },
    )
}

fn twin(id: &str, of: &str, flagged: bool) -> CaseResult {
    let mut r = result(
        id,
        CaseKind::MustNotFlag,
        EvidenceTier::T1,
        CaseMeasurement::Control {
            flagged,
            findings: u64::from(flagged),
            co_detected: false,
            action_counts: BTreeMap::new(),
        },
    );
    r.twin_of = Some(CaseId::new(of).unwrap());
    r
}

fn positive_group(groups: &BTreeMap<String, GroupAggregate>) -> &GroupAggregate {
    &groups["must-redact/T1"]
}

// --- accounting -------------------------------------------------------------

#[test]
fn zero_denominator_is_null_and_small_n_is_withheld() {
    let mut c = config();
    assert_eq!(
        proportion(
            0,
            0,
            credential_eval_contracts::artifact::BoundDirection::Upper,
            &c,
            None
        ),
        None
    );
    c.min_denominator = 5;
    assert_eq!(
        proportion(
            1,
            4,
            credential_eval_contracts::artifact::BoundDirection::Upper,
            &c,
            None
        ),
        Some(Published::Withheld(Withheld::InsufficientEvidence))
    );
}

#[test]
fn ratio_emits_denominator_as_n() {
    let Some(Published::Rate(r)) = ratio(3, 2, &config(), Some(7)) else {
        panic!()
    };
    assert_eq!((r.point, r.bound, r.n, r.direction), (1.5, None, 2, None));
}

#[test]
fn overbroad_positive_does_not_discriminate_under_v11() {
    let cases = vec![positive("p", Outcome::Overbroad), twin("t", "p", false)];
    let groups = account_groups(&cases, &config()).unwrap();
    let GroupAggregate::Positive { twins, .. } = positive_group(&groups) else {
        panic!()
    };
    assert_eq!((twins.pairs, twins.discriminated), (1, 0));
    let v10 = credential_eval_kernel::compat::aggregate_groups_v10(&cases).unwrap();
    let credential_eval_kernel::compat::GroupV10::Positive { discriminated, .. } =
        &v10["must-redact/T1"]
    else {
        panic!()
    };
    assert_eq!(*discriminated, 1, "v1.0 counted OVERBROAD as discriminated");
}

#[test]
fn low_measurable_share_withholds_rates() {
    let mut cases = vec![positive("p", Outcome::Exact)];
    for i in 0..3 {
        cases.push(result(
            &format!("q{i}"),
            CaseKind::MustRedact,
            EvidenceTier::T0,
            CaseMeasurement::Pending,
        ));
    }
    cases.push(twin("t", "p", false));
    let groups = account_groups(&cases, &config()).unwrap();
    let GroupAggregate::Positive {
        pending_files,
        leaked_span_rate,
        collateral_ratio,
        twins,
        ..
    } = positive_group(&groups)
    else {
        panic!()
    };
    let ie = Some(Published::Withheld(Withheld::InsufficientEvidence));
    assert_eq!(*pending_files, 3);
    assert_eq!(leaked_span_rate, &ie);
    assert_eq!(collateral_ratio, &ie);
    assert_eq!(twins.rate, ie);
    let GroupAggregate::Pending {
        candidate_kinds, ..
    } = &groups["pending/T0"]
    else {
        panic!()
    };
    assert_eq!(candidate_kinds["must-redact"], 3);
}

#[test]
fn low_twin_coverage_withholds_twin_rate() {
    let cases = vec![
        positive("a", Outcome::Exact),
        positive("b", Outcome::Exact),
        positive("c", Outcome::Exact),
        twin("t", "a", false),
    ];
    let groups = account_groups(&cases, &config()).unwrap();
    let GroupAggregate::Positive { twins, .. } = positive_group(&groups) else {
        panic!()
    };
    assert_eq!(
        twins.rate,
        Some(Published::Withheld(Withheld::InsufficientCoverage))
    );
    // No pairs: null, not withheld.
    let groups = account_groups(&cases[..3], &config()).unwrap();
    let GroupAggregate::Positive { twins, .. } = positive_group(&groups) else {
        panic!()
    };
    assert_eq!(twins.rate, None);
}

#[test]
fn several_twins_per_positive_publish_a_null_coverage_bound() {
    let cases = vec![
        positive("p", Outcome::Exact),
        twin("t1", "p", false),
        twin("t2", "p", true),
    ];
    let groups = account_groups(&cases, &config()).unwrap();
    let GroupAggregate::Positive { twins, .. } = positive_group(&groups) else {
        panic!()
    };
    let Some(Published::Rate(r)) = &twins.coverage else {
        panic!()
    };
    assert_eq!((r.point, r.bound), (2.0, None));
}

#[test]
fn inconsistent_population_is_refused() {
    let bad = result(
        "x",
        CaseKind::MustRedact,
        EvidenceTier::T1,
        CaseMeasurement::Control {
            flagged: false,
            findings: 0,
            co_detected: false,
            action_counts: BTreeMap::new(),
        },
    );
    assert!(matches!(
        account_groups(&[bad], &config()),
        Err(KernelError::InconsistentCase { .. })
    ));
}

#[test]
fn invalid_accounting_is_refused() {
    let mut c = config();
    c.interval_precision = 13;
    assert!(credential_eval_kernel::accounting::validate_accounting(&c).is_err());
    let mut c = config();
    c.measurable_share_floor = Floor::Uniform(1.5);
    assert!(credential_eval_kernel::accounting::validate_accounting(&c).is_err());
}

// --- twin probe ---------------------------------------------------------------

#[test]
fn twin_probe_states() {
    let cases = vec![
        positive("p", Outcome::Exact),
        twin("t", "p", false),
        positive("q", Outcome::Covered),
        twin("u", "q", true),
    ];
    let fixtures = vec![
        ProbeFixture {
            id: CaseId::new("t").unwrap(),
            family: Some("a".into()),
            twin_of: Some(CaseId::new("p").unwrap()),
        },
        ProbeFixture {
            id: CaseId::new("u").unwrap(),
            family: Some("b".into()),
            twin_of: Some(CaseId::new("q").unwrap()),
        },
    ];
    let unprobeable = BTreeMap::from([(
        "c".to_owned(),
        UnprobeableRecord {
            reason: "no mutable property".into(),
            observed_at: "2026-09-20".into(),
        },
    )]);
    let families: Vec<String> = ["a", "b", "c", "d"].map(String::from).to_vec();
    let probe = twin_probe(&families, &fixtures, Some(&cases), &unprobeable).unwrap();
    let statuses: Vec<TwinProbeStatus> = probe.entries.iter().map(|e| e.status).collect();
    assert_eq!(
        statuses,
        [
            TwinProbeStatus::Discriminated,
            TwinProbeStatus::NotDiscriminated,
            TwinProbeStatus::UnProbeable,
            TwinProbeStatus::Unrecorded
        ]
    );
    let probe = twin_probe(&families, &fixtures, None, &unprobeable).unwrap();
    assert_eq!(probe.entries[0].status, TwinProbeStatus::NotMeasured);
    let conflict = BTreeMap::from([("a".to_owned(), unprobeable["c"].clone())]);
    assert!(matches!(
        twin_probe(&families, &fixtures, Some(&cases), &conflict),
        Err(KernelError::UnprobeableWithTwins(_))
    ));
}

// --- evaluation ---------------------------------------------------------------

fn corpus_case(
    id: &str,
    content: &str,
    secret: Option<(u64, u64)>,
    family: &str,
    tier: EvidenceTier,
) -> Case {
    Case {
        id: CaseId::new(id).unwrap(),
        path: FixturePath::new(format!("g/{id}.txt")).unwrap(),
        content: content.into(),
        expected: secret
            .map(|(s, e)| {
                vec![ExpectedSpan {
                    start: s,
                    end: e,
                    role: SpanRole::Secret,
                    envelope: None,
                }]
            })
            .unwrap_or_default(),
        grouping: Grouping {
            kind: if secret.is_some() {
                CaseKind::MustRedact
            } else {
                CaseKind::MustNotFlag
            },
            tier,
            family: Some(family.into()),
            group: "g".into(),
            evidence_class: None,
            targets: vec![family.into()],
            taxonomy: secret.is_none().then(|| "placeholder".into()),
        },
        twin: None,
    }
}

fn evidence() -> EvaluationEvidence {
    let families = BTreeMap::from([
        (
            "seg".to_owned(),
            FamilyContract {
                pattern: Some("^sy\\.[a-z]{3}\\.[a-z]{3}$".into()),
                segments: Some(SegmentRule {
                    delimiter: ".".into(),
                    removable: vec![1, 2],
                }),
                unprobeable: None,
            },
        ),
        (
            "plain".to_owned(),
            FamilyContract {
                pattern: Some("^zq_[a-z]{4,8}$".into()),
                segments: None,
                unprobeable: None,
            },
        ),
    ]);
    EvaluationEvidence {
        contracts: FamilyContracts::new(families).unwrap(),
        benign_taxonomies: None,
    }
}

fn snapshot() -> CorpusSnapshot {
    let mut twin = corpus_case(
        "pos-twin",
        "key = sy.abc.abX\n",
        None,
        "seg",
        EvidenceTier::T1,
    );
    twin.twin = Some(TwinLineage {
        twin_of: CaseId::new("pos").unwrap(),
        mutation: "alphabet".into(),
        mutation_kind: "alphabet".into(),
    });
    twin.grouping.taxonomy = None;
    CorpusSnapshot::seal(
        "test".into(),
        "r".into(),
        "v".into(),
        vec![
            corpus_case(
                "pos",
                "key = sy.abc.abc\n",
                Some((6, 16)),
                "seg",
                EvidenceTier::T1,
            ),
            corpus_case(
                "plain",
                "\"zq_abcde\"",
                Some((1, 9)),
                "plain",
                EvidenceTier::T2,
            ),
            corpus_case("ctl", "nothing here", None, "plain", EvidenceTier::T2),
            twin,
        ],
    )
}

fn identity(id: &str, version: &str) -> ScannerIdentity {
    ScannerIdentity {
        id: ScannerId::new(id).unwrap(),
        version: Some(version.into()),
        mode: "m".into(),
        adapter: AdapterIdentity {
            id: ComponentId::new("a").unwrap(),
            version: "1".into(),
        },
        configuration_hash: Sha256Digest::new(format!("sha256:{}", "0".repeat(64))).unwrap(),
        provenance: None,
        build: None,
    }
}

fn observe_all(
    plan: &credential_eval_kernel::evaluation::EvaluationPlan,
    base: &CorpusSnapshot,
    scanners: Vec<(ScannerIdentity, ObservationResult)>,
) -> ObservationSet {
    ObservationSet {
        schema: ObservationSetSchema,
        corpus_digest: plan.variant_corpus(&base.identity).identity.corpus_digest,
        observations: scanners
            .into_iter()
            .map(|(scanner, result)| ScannerObservation {
                scanner,
                result,
                duration_ms: None,
            })
            .collect(),
    }
}

/// Findings exactly on every variant's secret spans.
fn exact(
    plan: &credential_eval_kernel::evaluation::EvaluationPlan,
    family: Option<&str>,
) -> ObservationResult {
    let findings = plan
        .cases
        .iter()
        .flat_map(|g| &g.variants)
        .flat_map(|v| {
            v.fixture
                .expected
                .iter()
                .filter(|e| e.role == SpanRole::Secret)
                .map(|e| NormalizedFinding {
                    path: v.fixture.path.clone(),
                    start: e.start,
                    end: e.end,
                    family: family.map(str::to_owned),
                    action: None,
                })
        })
        .collect();
    ObservationResult::Complete {
        findings,
        replays: Replays {
            count: 2,
            agreed: true,
        },
    }
}

#[test]
fn generation_is_deterministic_and_data_driven() {
    let snap = snapshot();
    let cases = build_cases(&snap, &MethodId::ALL, &case_id_seed).unwrap();
    let plan = plan_evaluation(cases.clone(), &evidence(), &GenerationLimits::default()).unwrap();
    assert_eq!(
        plan,
        plan_evaluation(cases.clone(), &evidence(), &GenerationLimits::default()).unwrap()
    );
    let mutation = plan
        .cases
        .iter()
        .find(|c| c.case.id.as_str() == "pos--mutation")
        .unwrap();
    let segment = mutation
        .attempts
        .iter()
        .find(|a| a.operator == OperatorId::RemoveSegment)
        .unwrap();
    assert_eq!(
        segment.status,
        AttemptStatus::Generated,
        "segment rule comes from evidence data"
    );
    let plain = plan
        .cases
        .iter()
        .find(|c| c.case.id.as_str() == "plain--mutation")
        .unwrap();
    let segment = plain
        .attempts
        .iter()
        .find(|a| a.operator == OperatorId::RemoveSegment)
        .unwrap();
    assert_eq!(
        segment.status,
        AttemptStatus::Unsupported,
        "no segment rule, no structural operator"
    );
    // The authored twin joins the mutation case of its positive.
    assert!(mutation.attempts.iter().any(|a| a.operator == OperatorId::AuthoredTwin && a.status == AttemptStatus::Generated));
    // Context operators refuse inputs that would need escaping.
    let meta = plan
        .cases
        .iter()
        .find(|c| c.case.id.as_str() == "plain--metamorphic")
        .unwrap();
    let json = meta
        .attempts
        .iter()
        .find(|a| a.operator == OperatorId::Json)
        .unwrap();
    assert_eq!(json.status, AttemptStatus::Unsupported);
    // CRLF remaps spans through the inserted bytes.
    let pos_meta = plan
        .cases
        .iter()
        .find(|c| c.case.id.as_str() == "pos--metamorphic")
        .unwrap();
    let crlf = pos_meta
        .variants
        .iter()
        .find(|v| v.id.as_str() == "encoding.crlf")
        .unwrap();
    assert_eq!(crlf.fixture.content, "key = sy.abc.abc\r\n");
    assert_eq!(
        (crlf.fixture.expected[0].start, crlf.fixture.expected[0].end),
        (6, 16)
    );
    // A lexical edit that breaks the family pattern needs review, never a derived negative.
    let bang = mutation
        .variants
        .iter()
        .find(|v| v.id.as_str() == "lexical.invalid-alphabet")
        .unwrap();
    assert_eq!(bang.strategy, VariantStrategy::ReviewRequired);
    assert_eq!(bang.fixture.grouping.tier, EvidenceTier::T0);
    // Explicit bounds.
    let tight = GenerationLimits {
        max_variants_per_case: 2,
        ..GenerationLimits::default()
    };
    assert!(matches!(
        plan_evaluation(cases, &evidence(), &tight),
        Err(KernelError::GenerationLimit { .. })
    ));
}

#[test]
fn scanner_aggregates_fill_groups_and_targets_only_when_complete() {
    use credential_eval_kernel::score::{scanner_aggregates, score_scanner};
    let snap = snapshot();
    let findings = vec![NormalizedFinding {
        path: FixturePath::new("g/pos.txt").unwrap(),
        start: 6,
        end: 16,
        family: Some("seg".into()),
        action: None,
    }];
    let observation = ScannerObservation {
        scanner: identity("s", "1"),
        result: ObservationResult::Complete {
            findings,
            replays: Replays {
                count: 2,
                agreed: true,
            },
        },
        duration_ms: None,
    };
    let run = score_scanner(&snap, &observation);
    let aggregates = scanner_aggregates(&run, &config()).unwrap();
    assert!(aggregates.groups.contains_key("must-redact/T1"));
    assert_eq!(
        aggregates.by_target.keys().collect::<Vec<_>>(),
        ["plain", "seg"]
    );
    let GroupAggregate::Positive { twins, .. } = &aggregates.by_target["seg"]["must-redact/T1"]
    else {
        panic!()
    };
    assert_eq!(
        (twins.pairs, twins.discriminated),
        (1, 1),
        "a selected positive's twin travels with it"
    );
    let case = run
        .cases
        .iter()
        .find(|c| c.case_id.as_str() == "pos-twin")
        .unwrap();
    assert_eq!(
        (case.group.as_str(), case.twin_mutation_kind.as_deref()),
        ("g", Some("alphabet"))
    );
    let failed = ScannerObservation {
        result: ObservationResult::Error {
            reason: "error".into(),
        },
        ..observation
    };
    let run = score_scanner(&snap, &failed);
    assert_eq!(run.status, ScannerStatus::Error);
    assert_eq!(
        scanner_aggregates(&run, &config()).unwrap(),
        Default::default()
    );
}

#[test]
fn differential_reference_is_a_run_parameter() {
    let snap = snapshot();
    let cases = build_cases(&snap, &[MethodId::Differential], &case_id_seed).unwrap();
    let plan = plan_evaluation(cases, &evidence(), &GenerationLimits::default()).unwrap();
    let empty = ObservationResult::Complete {
        findings: vec![],
        replays: Replays {
            count: 2,
            agreed: true,
        },
    };
    let obs = observe_all(
        &plan,
        &snap,
        vec![
            (identity("gitleaks", "8"), exact(&plan, Some("seg"))),
            (identity("peer-silent", "1"), empty),
            (identity("peer-same", "1"), exact(&plan, Some("seg"))),
            (identity("peer-other", "1"), exact(&plan, Some("plain"))),
            (
                identity("peer-down", "1"),
                ObservationResult::Unavailable {
                    reason: "unavailable".into(),
                },
            ),
            (
                identity("peer-norange", "1"),
                ObservationResult::Unsupported {
                    reason: "no ranges".into(),
                },
            ),
        ],
    );
    let reference = ScannerId::new("gitleaks").unwrap();
    let report = evaluate(
        &plan,
        &snap.identity,
        &obs,
        EvaluateOptions {
            reference: Some(&reference),
            accounting: &config(),
        },
    )
    .unwrap();
    let pos = report
        .results
        .iter()
        .find(|r| r.generated.case.id.as_str() == "pos--differential")
        .unwrap();
    let d = pos.differential.as_ref().unwrap();
    let of = |peer: &str| {
        d.comparisons
            .iter()
            .find(|c| c.peer.as_str() == peer)
            .unwrap()
    };
    assert_eq!(
        of("peer-silent").disagreement,
        Some(Disagreement::ReferenceOnly)
    );
    assert_eq!(of("peer-same").disagreement, Some(Disagreement::None));
    assert_eq!(
        of("peer-other").disagreement,
        Some(Disagreement::ClassificationDisagreement)
    );
    assert_eq!(of("peer-down").status, ComparisonStatus::Incomplete);
    assert_eq!(of("peer-norange").status, ComparisonStatus::Unsupported);
    assert!(d.comparisons.iter().all(|c| c.reference == reference));
    // Differential cases produce no assertions, only observations.
    assert!(pos.scanners.is_empty());
    // Queue: one entry per disagreement, keyed without the reference version.
    let entries: Vec<_> = report
        .review_queue
        .iter()
        .filter(|e| e.case_id.as_str() == "pos--differential")
        .collect();
    assert_eq!(entries.len(), 2);
    let mut bumped = obs.clone();
    bumped.observations[0].scanner.version = Some("9".into());
    let again = evaluate(
        &plan,
        &snap.identity,
        &bumped,
        EvaluateOptions {
            reference: Some(&reference),
            accounting: &config(),
        },
    )
    .unwrap();
    assert_eq!(
        again.review_queue.iter().map(|e| &e.id).collect::<Vec<_>>(),
        report
            .review_queue
            .iter()
            .map(|e| &e.id)
            .collect::<Vec<_>>(),
        "reference release must not re-key reviews"
    );
    let mut peer_bumped = obs.clone();
    peer_bumped.observations[1].scanner.version = Some("2".into());
    let moved = evaluate(
        &plan,
        &snap.identity,
        &peer_bumped,
        EvaluateOptions {
            reference: Some(&reference),
            accounting: &config(),
        },
    )
    .unwrap();
    assert_ne!(
        moved.review_queue, report.review_queue,
        "a peer release is part of the observation"
    );
    // Without a reference, no comparisons are made.
    let none = evaluate(
        &plan,
        &snap.identity,
        &obs,
        EvaluateOptions {
            reference: None,
            accounting: &config(),
        },
    )
    .unwrap();
    assert!(none.results.iter().all(|r| r.differential.is_none()) && none.review_queue.is_empty());
}

#[test]
fn assertions_follow_the_protocol() {
    let snap = snapshot();
    let cases = build_cases(
        &snap,
        &[MethodId::Twin, MethodId::Metamorphic, MethodId::Benign],
        &case_id_seed,
    )
    .unwrap();
    let plan = plan_evaluation(cases, &evidence(), &GenerationLimits::default()).unwrap();
    let obs = observe_all(
        &plan,
        &snap,
        vec![
            (identity("exact", "1"), exact(&plan, Some("seg"))),
            (
                identity("gone", "1"),
                ObservationResult::Timeout { timeout_ms: 5 },
            ),
        ],
    );
    let report = evaluate(
        &plan,
        &snap.identity,
        &obs,
        EvaluateOptions {
            reference: None,
            accounting: &config(),
        },
    )
    .unwrap();
    let twin = report
        .results
        .iter()
        .find(|r| r.generated.case.id.as_str() == "pos-twin--twin")
        .unwrap();
    let exact_run = twin
        .scanners
        .iter()
        .find(|s| s.scanner.as_str() == "exact")
        .unwrap();
    let flip = exact_run
        .assertions
        .iter()
        .find(|a| a.assertion == AssertionType::MustFlip)
        .unwrap();
    assert_eq!(flip.status, AssertionStatus::Pass);
    let gone = twin
        .scanners
        .iter()
        .find(|s| s.scanner.as_str() == "gone")
        .unwrap();
    assert!(gone.assertions.iter().all(
        |a| a.status == AssertionStatus::NotMeasured && a.reason.as_deref() == Some("timeout")
    ));
    assert!(
        gone.rows.is_empty(),
        "a non-complete scanner is never scored as MISS"
    );
    assert_eq!(
        report.exit_code(false, false),
        1,
        "timeout folds into the legacy error exit"
    );
    let parts = report.artifact_parts(&plan);
    assert!(
        parts
            .resolution_by_target
            .contains_key(&ScannerId::new("exact").unwrap())
    );
    assert!(
        parts
            .assertions
            .values()
            .all(|a| a.windows(2).all(|w| w[0] <= w[1]))
    );
    let _ = ObservedRange {
        start: 0,
        end: 1,
        family: None,
        action: None,
    };
}

// Regression (#5 parity): two pinned legacy contracts use ECMAScript
// look-ahead (`composio-api-key`, `travisci-api-token`). The `regex` crate
// refused them, so no evaluation over the full legacy contract table could
// start. Patterns now compile with look-around support.
#[test]
fn look_ahead_contract_patterns_compile_and_match() {
    let pattern = "^zq_(?=[A-Za-z0-9_-]*[A-Z])(?=[A-Za-z0-9_-]*[a-z])[A-Za-z0-9_-]{20}$";
    let contracts = FamilyContracts::new(BTreeMap::from([(
        "synthetic-mixed-case".to_owned(),
        FamilyContract {
            pattern: Some(pattern.to_owned()),
            ..FamilyContract::default()
        },
    )]))
    .expect("look-ahead patterns compile");
    let valid = |v: String| contracts.is_valid("synthetic-mixed-case", &v);
    assert!(valid(format!("zq_{}", "aB".repeat(10))));
    assert!(!valid(format!("zq_{}", "ab".repeat(10))));
    assert!(!valid(format!("zq_{}", "AB".repeat(10))));
    assert!(!valid(format!("zq_{}", "aB".repeat(11))));
}
