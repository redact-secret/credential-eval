//! Per-case scoring of one scanner observation over a snapshot.
//!
//! Mirrors legacy `score()` (`benchmarks/lib/scoring.ts:87-126`): findings are
//! deduplicated by `(path, start, end)` (a later duplicate's family/action
//! wins, as with the legacy `Map.set`), grouped by path, and each case is
//! scored with [`crate::lattice::score_row`]; `T0` cases are observed but not
//! scored. A twin's reading is scoped to its declared family.
//!
//! Aggregation and accounting are not implemented here yet (issue #3):
//! [`build_artifact`] emits empty `aggregates`.

use std::collections::BTreeMap;

use credential_eval_contracts::artifact::{
    Aggregates, CaseMeasurement, CaseResult, EngineIdentity, NonSemantic, ObservedRange,
    RunArtifact, RunManifest, ScannerRun, ScoredSpan,
};
use credential_eval_contracts::config::RunConfig;
use credential_eval_contracts::corpus::{Case, CorpusSnapshot, EvidenceTier};
use credential_eval_contracts::ids::FixturePath;
use credential_eval_contracts::observation::{
    NormalizedFinding, ObservationResult, ObservationSet, ScannerObservation,
};
use credential_eval_contracts::schema::RunArtifactSchema;
use credential_eval_contracts::{ContractError, ENGINE_NAME, PROTOCOL_VERSION};

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

/// Build a canonical run artifact from validated inputs.
///
/// `observations` must already be validated against `corpus`
/// ([`ObservationSet::validate_against`]); this re-checks and fails closed.
pub fn build_artifact(
    corpus: &CorpusSnapshot,
    config: &RunConfig,
    observations: &ObservationSet,
) -> Result<RunArtifact, ContractError> {
    corpus.validate()?;
    observations.validate_against(corpus)?;
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
        scanners: observations
            .observations
            .iter()
            .map(|o| score_scanner(corpus, o))
            .collect(),
        variants: Vec::new(),
        comparisons: Vec::new(),
        non_semantic: NonSemantic {
            durations_ms,
            ..NonSemantic::default()
        },
    };
    artifact.canonicalize();
    Ok(artifact)
}
