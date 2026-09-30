//! Legacy `bench` writer: a canonical `RunArtifact` of the exported legacy
//! corpus → `public/results/<category>.json` and `summary.json`
//! (legacy-map §4.1-4.2, cutover plan §4).
//!
//! The artifact must come from a plain corpus run (no methods) over a
//! snapshot written by `tools/legacy-export/export.mts`: case ids
//! `<category>--<fixtureId>`, paths `<category>/<fixture path>`,
//! `grouping.group` = category. The legacy index sidecar supplies what the
//! canonical snapshot deliberately does not carry: legacy row `group`
//! labels, fixture order, raw corpus-file hashes and the bench summary
//! assignments.
//!
//! Volatile legacy fields (`runId`, timestamps, `durationMs`, `observation`,
//! `revision`, `dirty`, `lockHash`, `runtime`) and presentation fields
//! (`name`, `mode`, `matching`, `reviewStatus`, `scope`, ...) are not
//! rendered; parity excludes them (legacy-map §4.1).

use std::collections::{BTreeMap, BTreeSet};

use credential_eval_contracts::artifact::{
    CaseMeasurement, CaseResult, GroupAggregate, RunArtifact, ScannerRun,
};
use credential_eval_contracts::ids::CaseId;
use credential_eval_contracts::observation::ScannerStatus;
use credential_eval_kernel::KernelError;
use credential_eval_kernel::accounting::{SuiteCase, account_groups, selection_groups};
use credential_eval_kernel::compat::{accounting_delta, legacy_status};
use serde::Deserialize;
use serde_json::{Map, Value, json};

/// Schema tag of the legacy index sidecar.
pub const INDEX_SCHEMA: &str = "credential-eval/legacy-index/v1";

/// The legacy index sidecar written by the exporter.
#[derive(Debug, Clone, Deserialize)]
pub struct LegacyIndex {
    /// `credential-eval/legacy-index/v1`.
    pub schema: String,
    /// Corpus digest of the snapshot the index belongs to.
    pub corpus_digest: String,
    /// Categories in legacy registry order.
    pub categories: Vec<IndexCategory>,
    /// Legacy row `group` label by case id.
    pub groups: BTreeMap<String, String>,
    /// `benchmarks/fixture-detectors.json`: case id → detectors.
    pub bench_assignments: BTreeMap<String, Vec<String>>,
}

/// One legacy category.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IndexCategory {
    /// Category id.
    pub id: String,
    /// SHA-256 hex of the raw corpus file (legacy `corpusHash`).
    pub corpus_hash: String,
    /// Fixture ids in corpus order.
    pub fixtures: Vec<String>,
}

/// A rendering failure.
#[derive(Debug)]
pub enum RenderError {
    /// The index does not describe the artifact's corpus.
    Mismatch(String),
    /// Accounting refused the cases.
    Kernel(KernelError),
}

impl std::fmt::Display for RenderError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Mismatch(m) => write!(f, "legacy index does not match the artifact: {m}"),
            Self::Kernel(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for RenderError {}

impl From<KernelError> for RenderError {
    fn from(e: KernelError) -> Self {
        Self::Kernel(e)
    }
}

/// Legacy `AccountedGroup` JSON of a contract group (legacy-map §4.5, reversed).
pub fn legacy_group(group: &GroupAggregate) -> Value {
    let mut value = crate::camel(serde_json::to_value(group).expect("groups serialize"));
    let map = value.as_object_mut().expect("group object");
    map.remove("population");
    if matches!(group, GroupAggregate::Pending { .. }) {
        map.insert("scored".into(), json!(false));
    }
    if let Some(d) = map.remove("diagnostics") {
        map.insert(
            "diagnostics".into(),
            json!({ "exact": d, "comparable": false }),
        );
    }
    value
}

fn legacy_groups(groups: &BTreeMap<String, GroupAggregate>) -> Value {
    Value::Object(
        groups
            .iter()
            .map(|(k, g)| (k.clone(), legacy_group(g)))
            .collect(),
    )
}

fn strip<'a>(id: &'a str, category: &str) -> &'a str {
    id.strip_prefix(category)
        .and_then(|rest| rest.strip_prefix("--").or_else(|| rest.strip_prefix('/')))
        .unwrap_or(id)
}

/// Legacy scored row (`benchmarks/lib/scoring.ts:103-124`). `id`, `path`
/// and `twinOf` are given in the legacy (category-local) spelling.
pub fn legacy_row(
    case: &CaseResult,
    id: &str,
    path: &str,
    group: Option<&str>,
    twin_of: Option<&str>,
) -> Value {
    let mut row = Map::new();
    row.insert("id".into(), json!(id));
    row.insert("path".into(), json!(path));
    if let Some(group) = group {
        row.insert("group".into(), json!(group));
    }
    row.insert("kind".into(), json!(case.kind));
    row.insert("tier".into(), json!(case.tier));
    if let Some(family) = &case.family {
        row.insert("contract".into(), json!(family));
    }
    if let Some(t) = twin_of {
        row.insert("twinOf".into(), json!(t));
    }
    row.insert("expected".into(), json!(case.expected));
    row.insert("actual".into(), json!(case.actual));
    match &case.measurement {
        CaseMeasurement::Positive {
            span_outcomes,
            leaked_bytes,
            collateral_bytes,
        } => {
            row.insert("spanOutcomes".into(), json!(span_outcomes));
            row.insert("leakedBytes".into(), json!(leaked_bytes));
            row.insert("collateralBytes".into(), json!(collateral_bytes));
        }
        CaseMeasurement::Control {
            flagged,
            findings,
            co_detected,
            action_counts,
        } => {
            row.insert("flagged".into(), json!(flagged));
            row.insert("findings".into(), json!(findings));
            // Legacy sets `coDetected` only when true (lattice.ts:89).
            if *co_detected {
                row.insert("coDetected".into(), json!(true));
            }
            if !action_counts.is_empty() {
                row.insert("actionCounts".into(), json!(action_counts));
            }
        }
        CaseMeasurement::Pending | CaseMeasurement::NotMeasured { .. } => {}
    }
    Value::Object(row)
}

/// The rendered legacy `bench` outputs.
#[derive(Debug, Clone, PartialEq)]
pub struct BenchOutputs {
    /// `<category>.json` bodies by category id (legacy registry order kept in
    /// [`LegacyIndex::categories`]).
    pub categories: BTreeMap<String, Value>,
    /// `summary.json` (`overall`, `byDetector`).
    pub summary: Value,
}

fn scanner_version(artifact: &RunArtifact, run: &ScannerRun) -> Value {
    artifact
        .manifest
        .scanners
        .iter()
        .find(|s| s.id == run.scanner)
        .and_then(|s| s.version.clone())
        .map_or(Value::Null, Value::String)
}

/// Render `artifact` into the legacy `bench` files.
pub fn render(artifact: &RunArtifact, index: &LegacyIndex) -> Result<BenchOutputs, RenderError> {
    if index.schema != INDEX_SCHEMA {
        return Err(RenderError::Mismatch(format!(
            "unknown index schema {:?}",
            index.schema
        )));
    }
    if index.corpus_digest != artifact.manifest.evidence.corpus_digest.as_str() {
        return Err(RenderError::Mismatch("corpus digest differs".into()));
    }
    if !artifact.variants.is_empty() {
        return Err(RenderError::Mismatch(
            "the artifact is an evaluation-method run; bench renders corpus runs".into(),
        ));
    }
    let config = &artifact.manifest.accounting;
    let mut categories = BTreeMap::new();
    for category in &index.categories {
        let mut scanners = Vec::new();
        let mut header: Option<(usize, u64)> = None;
        for run in &artifact.scanners {
            let by_id: BTreeMap<&str, &CaseResult> = run
                .cases
                .iter()
                .filter(|c| c.group == category.id)
                .map(|c| (c.case_id.as_str(), c))
                .collect();
            if by_id.len() != category.fixtures.len() {
                return Err(RenderError::Mismatch(format!(
                    "category {} has {} cases, index lists {}",
                    category.id,
                    by_id.len(),
                    category.fixtures.len()
                )));
            }
            let mut ordered: Vec<&CaseResult> = Vec::with_capacity(by_id.len());
            for fixture in &category.fixtures {
                let slug = format!("{}--{fixture}", category.id);
                let case = by_id.get(slug.as_str()).ok_or_else(|| {
                    RenderError::Mismatch(format!("case {slug} is missing from the artifact"))
                })?;
                ordered.push(case);
            }
            header.get_or_insert((
                ordered.len(),
                ordered.iter().map(|c| c.expected.len() as u64).sum(),
            ));
            let mut entry = Map::new();
            entry.insert("id".into(), json!(run.scanner));
            entry.insert("version".into(), scanner_version(artifact, run));
            entry.insert("status".into(), json!(legacy_status(run.status)));
            if let Some(replays) = &run.replays {
                entry.insert("replays".into(), json!(replays));
            }
            if run.status == ScannerStatus::Complete {
                let cases: Vec<CaseResult> = ordered.iter().map(|c| (*c).clone()).collect();
                let groups = account_groups(&cases, config)?;
                let delta = accounting_delta(&cases, config)?;
                entry.insert("groups".into(), legacy_groups(&groups));
                entry.insert(
                    "accountingDelta".into(),
                    json!({ "version": "1.0 -> 1.1", "groups": delta }),
                );
                let rows: Vec<Value> = ordered
                    .iter()
                    .map(|c| {
                        let id = c.case_id.as_str();
                        legacy_row(
                            c,
                            strip(id, &category.id),
                            strip(c.path.as_str(), &category.id),
                            index.groups.get(id).map(String::as_str),
                            c.twin_of.as_ref().map(|t| strip(t.as_str(), &category.id)),
                        )
                    })
                    .collect();
                entry.insert("rows".into(), Value::Array(rows));
            }
            scanners.push(Value::Object(entry));
        }
        let (fixture_count, expected_count) = header.unwrap_or((category.fixtures.len(), 0));
        categories.insert(
            category.id.clone(),
            json!({
                "category": category.id,
                "corpusHash": category.corpus_hash,
                "fixtureCount": fixture_count,
                "expectedCount": expected_count,
                "scanners": scanners,
            }),
        );
    }
    Ok(BenchOutputs {
        categories,
        summary: summary(artifact, index)?,
    })
}

/// `summary.json` (`run-summary.ts:52-77`) over the bench assignments.
fn summary(artifact: &RunArtifact, index: &LegacyIndex) -> Result<Value, RenderError> {
    let config = &artifact.manifest.accounting;
    let everything: BTreeSet<CaseId> = index
        .bench_assignments
        .keys()
        .filter_map(|k| CaseId::new(k.clone()).ok())
        .collect();
    let detectors: BTreeSet<&String> = index.bench_assignments.values().flatten().collect();
    let mut overall = Map::new();
    let mut by_detector: BTreeMap<String, Map<String, Value>> = detectors
        .iter()
        .map(|d| ((*d).clone(), Map::new()))
        .collect();
    for run in &artifact.scanners {
        if run.status != ScannerStatus::Complete {
            overall.insert(run.scanner.to_string(), json!({}));
            continue;
        }
        let all: Vec<SuiteCase<'_>> = run
            .cases
            .iter()
            .map(|case| SuiteCase {
                suite: &case.group,
                case,
            })
            .collect();
        overall.insert(
            run.scanner.to_string(),
            legacy_groups(&selection_groups(&all, &everything, config)?),
        );
        for detector in &detectors {
            let selected: BTreeSet<CaseId> = index
                .bench_assignments
                .iter()
                .filter(|(_, ds)| ds.contains(detector))
                .filter_map(|(k, _)| CaseId::new(k.clone()).ok())
                .collect();
            let groups = selection_groups(&all, &selected, config)?;
            if !groups.is_empty() {
                by_detector
                    .get_mut(*detector)
                    .expect("detector entry")
                    .insert(run.scanner.to_string(), legacy_groups(&groups));
            }
        }
    }
    Ok(json!({ "overall": overall, "byDetector": by_detector }))
}
