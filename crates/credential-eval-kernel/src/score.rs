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
    RunArtifact, RunManifest, ScannerRun, ScoredSpan,
};
use credential_eval_contracts::config::{AccountingConfig, RunConfig};
use credential_eval_contracts::corpus::{Case, CorpusSnapshot, EvidenceTier};
use credential_eval_contracts::ids::{CaseId, FixturePath};
use credential_eval_contracts::observation::{
    NormalizedFinding, ObservationResult, ObservationSet, ScannerObservation, ScannerStatus,
};
use credential_eval_contracts::schema::RunArtifactSchema;
use credential_eval_contracts::{ENGINE_NAME, PROTOCOL_VERSION};

use crate::KernelError;
use crate::accounting::{SuiteCase, account_groups, summarize_selections, validate_accounting};
use crate::lattice::score_row;

/// Implementation version of the kernel, recorded as the engine version.
pub const ENGINE_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Deduplicate findings by `(path, start, end)`; the last duplicate's
/// classification wins. Output is sorted by `(path, start, end)`.
pub fn dedupe(findings: &[NormalizedFinding]) -> Vec<NormalizedFinding> {
    let mut unique: BTreeMap<(&FixturePath, u64, u64), &NormalizedFinding> = BTreeMap::new();
    for finding in findings {
        unique.insert((&finding.path, finding.start, finding.end), finding);
    }
    unique.into_values().cloned().collect()
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
        ObservationResult::Complete { findings, replays } => {
            (dedupe(findings), Some(*replays), None)
        }
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
        });
    }
    let complete = matches!(observation.result, ObservationResult::Complete { .. });
    let results = cases
        .into_iter()
        .map(|case| {
            let actual = by_path.get(&case.path).cloned().unwrap_or_default();
            let measurement = if !complete {
                CaseMeasurement::NotMeasured { status }
            } else if case.grouping.tier == EvidenceTier::T0 {
                CaseMeasurement::Pending
            } else {
                let scope = case.twin.as_ref().and(case.grouping.family.as_deref());
                score_row(&expected_of(case), &actual, scope)
            };
            case_result(case, actual, measurement)
        })
        .collect();
    ScannerRun {
        scanner: observation.scanner.id.clone(),
        status,
        detail,
        replays,
        findings,
        cases: results,
        assertions: Vec::new(),
        aggregates: Aggregates::default(),
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
    let groups = account_groups(&run.cases, config)?;
    let suites: Vec<SuiteCase<'_>> = run
        .cases
        .iter()
        .map(|case| SuiteCase {
            suite: &case.group,
            case,
        })
        .collect();
    let assignments: BTreeMap<CaseId, Vec<String>> = run
        .cases
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
