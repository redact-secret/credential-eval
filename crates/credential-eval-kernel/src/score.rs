//! Per-case scoring of one scanner observation over a snapshot.
//!
//! Mirrors legacy `score()` (`benchmarks/lib/scoring.ts:87-126`): findings are
//! deduplicated by `(path, start, end)` (a later duplicate's family/action
//! wins, as with the legacy `Map.set`), grouped by path, and each case is
//! scored with [`crate::lattice::score_row`]; `T0` cases are observed but not
//! scored. A twin's reading is scoped to its declared family.
//!
//! [`build_artifact`] then accounts every complete scanner's cases
//! ([`scanner_aggregates`]): v1.1 groups over the whole snapshot and
//! per-target groups under the legacy selection rule. A scanner that did not
//! complete has no aggregates.

use std::collections::BTreeMap;

use credential_eval_contracts::artifact::{
    Aggregates, CaseMeasurement, CaseResult, EngineIdentity, NonSemantic, ObservedRange,
    RunArtifact, RunManifest, ScannerRun, ScoredSpan, UnmeasuredCase,
};
use credential_eval_contracts::config::{AccountingConfig, RunConfig};
use credential_eval_contracts::corpus::{Case, CorpusSnapshot, EvidenceTier};
use credential_eval_contracts::ids::{CaseId, FixturePath, NativeLabel};
use credential_eval_contracts::observation::{
    MAX_NATIVE_LABELS, NormalizedFinding, ObservationResult, ObservationSet, ScannerObservation,
    ScannerStatus,
};
use credential_eval_contracts::schema::RunArtifactSchema;
use credential_eval_contracts::{ENGINE_NAME, PROTOCOL_VERSION};

use crate::KernelError;
use crate::accounting::{SuiteCase, account_groups, summarize_selections, validate_accounting};
use crate::lattice::score_row_scoped;

/// Implementation version of the kernel, recorded as the engine version.
pub const ENGINE_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Deduplicate findings by `(path, start, end)`; the last duplicate's
/// classification wins. Output is sorted by `(path, start, end)`.
///
/// The native labels of every duplicate are merged into one sorted set (at
/// most [`MAX_NATIVE_LABELS`], smallest kept), so a range reported under
/// several labels is still one finding.
///
/// A range that any duplicate reports as a mapped decoded finding keeps that
/// mapping (the smallest one, so the result does not depend on emission
/// order): a plain finding on the same bytes must not hide that the range is
/// also a bound for a decoded one.
pub fn dedupe(findings: &[NormalizedFinding]) -> Vec<NormalizedFinding> {
    let mut unique: BTreeMap<(&FixturePath, u64, u64), NormalizedFinding> = BTreeMap::new();
    for finding in findings {
        let key = (&finding.path, finding.start, finding.end);
        let mapping = match (
            &finding.mapping,
            unique.get(&key).and_then(|f| f.mapping.as_ref()),
        ) {
            (Some(new), Some(old)) => Some(new.min(old).clone()),
            (Some(new), None) => Some(new.clone()),
            (None, old) => old.cloned(),
        };
        // Labels are a set over the range: every duplicate contributes, so the
        // result does not depend on emission order and the finding count of
        // the range stays one.
        let mut native_labels: Vec<NativeLabel> = unique
            .get(&key)
            .map(|f| f.native_labels.clone())
            .unwrap_or_default();
        native_labels.extend(finding.native_labels.iter().cloned());
        native_labels.sort();
        native_labels.dedup();
        native_labels.truncate(MAX_NATIVE_LABELS);
        unique.insert(
            key,
            NormalizedFinding {
                mapping,
                native_labels,
                ..finding.clone()
            },
        );
    }
    unique.into_values().collect()
}

fn expected_of(case: &Case) -> Vec<ScoredSpan> {
    case.expected
        .iter()
        .map(|e| ScoredSpan {
            start: e.start,
            end: e.end,
            role: e.role,
            envelope: e.envelope.as_ref().map(|envelope| envelope.range()),
        })
        .collect()
}

fn case_result(
    case: &Case,
    actual: Vec<ObservedRange>,
    measurement: CaseMeasurement,
) -> CaseResult {
    CaseResult {
        case_id: case.id.clone(),
        path: case.path.clone(),
        kind: case.grouping.kind,
        tier: case.grouping.tier,
        family: case.grouping.family.clone(),
        twin_of: case.twin.as_ref().map(|t| t.twin_of.clone()),
        group: case.grouping.group.clone(),
        targets: case.grouping.targets.clone(),
        taxonomy: case.grouping.taxonomy.clone(),
        evidence_class: case.grouping.evidence_class.clone(),
        twin_mutation_kind: case.twin.as_ref().map(|t| t.mutation_kind.clone()),
        expected: expected_of(case),
        actual,
        measurement,
    }
}

/// Score one scanner observation against every case of `corpus`.
pub fn score_scanner(corpus: &CorpusSnapshot, observation: &ScannerObservation) -> ScannerRun {
    let status = observation.result.status();
    let mut cases: Vec<&Case> = corpus.cases.iter().collect();
    cases.sort_by(|a, b| a.id.cmp(&b.id));
    let (findings, replays, detail) = match &observation.result {
        ObservationResult::Complete {
            findings, replays, ..
        } => (dedupe(findings), Some(*replays), None),
        ObservationResult::Unstable { replays, .. } => (
            Vec::new(),
            Some(*replays),
            Some("replays disagreed; findings discarded".to_owned()),
        ),
        ObservationResult::Unsupported { reason }
        | ObservationResult::Unavailable { reason }
        | ObservationResult::Malformed { reason }
        | ObservationResult::Error { reason } => (Vec::new(), None, Some(reason.clone())),
        ObservationResult::Timeout { timeout_ms } => (
            Vec::new(),
            None,
            Some(format!("timed out after {timeout_ms} ms")),
        ),
    };
    let mut by_path: BTreeMap<&FixturePath, Vec<ObservedRange>> = BTreeMap::new();
    for f in &findings {
        by_path.entry(&f.path).or_default().push(ObservedRange {
            start: f.start,
            end: f.end,
            family: f.family.clone(),
            action: f.action.clone(),
            mapping: f.mapping.clone(),
            native_labels: f.native_labels.clone(),
        });
    }
    let complete = matches!(observation.result, ObservationResult::Complete { .. });
    // Paths a complete scanner could not map (per-case handling chosen by the
    // run configuration). Their cases are not measured, never a miss.
    let unmeasured: BTreeMap<&FixturePath, &str> = match &observation.result {
        ObservationResult::Complete { unmeasured, .. } => unmeasured
            .iter()
            .map(|u| (&u.path, u.reason.as_str()))
            .collect(),
        _ => BTreeMap::new(),
    };
    let mut unmeasured_cases = Vec::new();
    let results = cases
        .into_iter()
        .map(|case| {
            let actual = by_path.get(&case.path).cloned().unwrap_or_default();
            let measurement = if !complete {
                CaseMeasurement::NotMeasured { status }
            } else if let Some(reason) = unmeasured.get(&case.path) {
                unmeasured_cases.push(UnmeasuredCase {
                    case_id: case.id.clone(),
                    reason: (*reason).to_owned(),
                });
                CaseMeasurement::NotMeasured {
                    status: ScannerStatus::Malformed,
                }
            } else if case.grouping.tier == EvidenceTier::T0 {
                CaseMeasurement::Pending
            } else {
                let scope = case.twin.as_ref().and(case.grouping.family.as_deref());
                let sibling = case.twin.as_ref().and_then(|t| t.sibling_family.as_deref());
                score_row_scoped(&expected_of(case), &actual, scope, sibling)
            };
            case_result(case, actual, measurement)
        })
        .collect();
    let scope_accounting = if complete {
        credential_eval_contracts::scope::ScopeTable::for_scanner(&observation.scanner.id)
            .map(|table| credential_eval_contracts::scope::account(table, &findings))
    } else {
        None
    };
    ScannerRun {
        scanner: observation.scanner.id.clone(),
        status,
        detail,
        replays,
        findings,
        cases: results,
        assertions: Vec::new(),
        aggregates: Aggregates::default(),
        unmeasured_cases,
        scope_accounting,
    }
}

/// Aggregates of one scanner run: v1.1 groups over every case
/// ([`account_groups`]) and, for every target family, the groups of the cases
/// that target it under the legacy cross-suite selection rule
/// ([`summarize_selections`]; suites are `CaseResult.group`). Empty for a
/// scanner that did not complete.
pub fn scanner_aggregates(
    run: &ScannerRun,
    config: &AccountingConfig,
) -> Result<Aggregates, KernelError> {
    if run.status != ScannerStatus::Complete {
        return Ok(Aggregates::default());
    }
    // Cases a complete scanner could not map are not measured: they are in no
    // group, denominator or target. `unmeasured_cases` reports them.
    let measured: Vec<CaseResult> = run
        .cases
        .iter()
        .filter(|c| !matches!(c.measurement, CaseMeasurement::NotMeasured { .. }))
        .cloned()
        .collect();
    let groups = account_groups(&measured, config)?;
    let suites: Vec<SuiteCase<'_>> = measured
        .iter()
        .map(|case| SuiteCase {
            suite: &case.group,
            case,
        })
        .collect();
    let assignments: BTreeMap<CaseId, Vec<String>> = measured
        .iter()
        .filter(|c| !c.targets.is_empty())
        .map(|c| (c.case_id.clone(), c.targets.clone()))
        .collect();
    let by_target = summarize_selections(&suites, &assignments, config)?.by_target;
    Ok(Aggregates {
        groups,
        by_target,
        ..Aggregates::default()
    })
}

/// Build a canonical run artifact from validated inputs.
///
/// `observations` must already be validated against `corpus`
/// ([`ObservationSet::validate_against`]); this re-checks and fails closed.
pub fn build_artifact(
    corpus: &CorpusSnapshot,
    config: &RunConfig,
    observations: &ObservationSet,
) -> Result<RunArtifact, KernelError> {
    corpus.validate()?;
    observations.validate_against(corpus)?;
    validate_accounting(&config.accounting)?;
    let mut scanners = Vec::with_capacity(observations.observations.len());
    for o in &observations.observations {
        let mut run = score_scanner(corpus, o);
        run.aggregates = scanner_aggregates(&run, &config.accounting)?;
        scanners.push(run);
    }
    let mut durations_ms = BTreeMap::new();
    for o in &observations.observations {
        if let Some(ms) = o.duration_ms {
            durations_ms.insert(o.scanner.id.to_string(), ms);
        }
    }
    let mut artifact = RunArtifact {
        schema: RunArtifactSchema,
        manifest: RunManifest {
            engine: EngineIdentity {
                name: ENGINE_NAME.to_owned(),
                version: ENGINE_VERSION.to_owned(),
            },
            protocol_version: PROTOCOL_VERSION.to_owned(),
            evidence: corpus.identity.clone(),
            config_hash: config.config_hash(),
            accounting: config.accounting.clone(),
            methods: Vec::new(),
            scanners: observations
                .observations
                .iter()
                .map(|o| o.scanner.clone())
                .collect(),
            run_class: None,
            publication: None,
            representation: corpus.representation_report(),
        },
        scanners,
        variants: Vec::new(),
        comparisons: Vec::new(),
        review_queue: Vec::new(),
        non_semantic: NonSemantic {
            durations_ms,
            ..NonSemantic::default()
        },
    };
    artifact.canonicalize();
    Ok(artifact)
}

#[cfg(test)]
mod native_label_tests {
    use super::*;

    fn finding(start: u64, end: u64, family: Option<&str>, labels: &[&str]) -> NormalizedFinding {
        NormalizedFinding {
            path: FixturePath::new("a.txt").unwrap(),
            start,
            end,
            family: family.map(str::to_owned),
            action: None,
            mapping: None,
            native_labels: labels
                .iter()
                .map(|l| NativeLabel::new(*l).unwrap())
                .collect(),
        }
    }

    #[test]
    fn same_range_labels_merge_without_changing_multiplicity() {
        let a = finding(0, 5, None, &["EMAIL"]);
        let b = finding(0, 5, Some("jwt"), &["JWT_TOKEN"]);
        let c = finding(0, 5, None, &["EMAIL"]);
        let elsewhere = finding(6, 9, None, &["PHONE"]);
        let forward = dedupe(&[a.clone(), b.clone(), c.clone(), elsewhere.clone()]);
        let backward = dedupe(&[elsewhere, c, b, a]);
        assert_eq!(forward.len(), 2);
        assert_eq!(
            forward[0]
                .native_labels
                .iter()
                .map(|l| l.as_str())
                .collect::<Vec<_>>(),
            ["EMAIL", "JWT_TOKEN"]
        );
        assert_eq!(forward[0].native_labels, backward[0].native_labels);
        assert_eq!(forward[1].native_labels, backward[1].native_labels);
    }

    #[test]
    fn labels_do_not_change_range_or_family_outcomes() {
        let plain = vec![finding(0, 5, Some("jwt"), &[]), finding(7, 9, None, &[])];
        let labelled = vec![
            finding(0, 5, Some("jwt"), &["JWT_TOKEN"]),
            finding(7, 9, None, &["EMAIL", "PHONE"]),
        ];
        let strip = |v: Vec<NormalizedFinding>| -> Vec<(u64, u64, Option<String>)> {
            dedupe(&v)
                .into_iter()
                .map(|f| (f.start, f.end, f.family))
                .collect()
        };
        assert_eq!(strip(plain), strip(labelled));
    }

    #[test]
    fn a_mapped_range_keeps_its_mapping_and_gains_the_labels() {
        use credential_eval_contracts::representation::FindingMapping;
        let mut mapped = finding(0, 5, None, &["JWT_TOKEN"]);
        let sample: FindingMapping = serde_json::from_value(serde_json::json!({
            "bound": "source-segment", "layers": 1, "codecs": ["base64"],
        }))
        .unwrap();
        mapped.mapping = Some(sample.clone());
        let plain = finding(0, 5, None, &["EMAIL"]);
        for order in [[mapped.clone(), plain.clone()], [plain, mapped]] {
            let merged = dedupe(&order);
            assert_eq!(merged.len(), 1);
            assert_eq!(merged[0].mapping, Some(sample.clone()));
            assert_eq!(merged[0].native_labels.len(), 2);
        }
    }

    #[test]
    fn merged_labels_are_capped_deterministically() {
        let many: Vec<_> = ["H", "G", "F", "E", "D", "C", "B", "A", "Z"]
            .iter()
            .map(|l| finding(0, 1, None, &[l]))
            .collect();
        let merged = dedupe(&many);
        assert_eq!(merged.len(), 1);
        assert_eq!(merged[0].native_labels.len(), MAX_NATIVE_LABELS);
        assert_eq!(merged[0].native_labels[0].as_str(), "A");
    }
}
