//! Evaluation methods (legacy `evaluation-v1` pipeline): twin discrimination,
//! benign controls, mutation and metamorphic variants, and differential
//! observation.
//!
//! The flow is two-phase so that scanners only ever see validated inputs:
//!
//! 1. [`plan_evaluation`] builds and generates every case before any scanner
//!    runs (legacy `evaluationInputs`, `case-lifecycle.ts:4-14`). Its
//!    [`EvaluationPlan::variant_corpus`] is an ordinary [`CorpusSnapshot`] of
//!    every generated variant; adapters scan it like any corpus.
//! 2. [`evaluate`] consumes the observation set recorded over that variant
//!    corpus and produces assertions, comparisons, the review queue,
//!    summaries and resolution accounting (legacy `executeEvaluation`,
//!    `execution.ts:69-114`).
//!
//! Generation is deterministic (seeded choices only) and bounded
//! ([`GenerationLimits`]).

pub mod assertions;
pub mod cases;
pub mod differential;
pub mod evidence;
pub mod model;
pub mod operators;
pub mod reporting;
pub mod review;

use std::collections::{BTreeMap, BTreeSet};

use credential_eval_contracts::artifact::{
    AccountedCounts, Assertion, AssertionStatus, DifferentialComparison, MethodIdentity,
    ReviewOccurrence, VariantRecord,
};
use credential_eval_contracts::canonical::sha256_bytes;
use credential_eval_contracts::config::AccountingConfig;
use credential_eval_contracts::corpus::{CorpusSnapshot, SnapshotIdentity};
use credential_eval_contracts::ids::{CaseId, FixturePath, ScannerId};
use credential_eval_contracts::observation::{
    NormalizedFinding, ObservationResult, ObservationSet, ScannerIdentity, ScannerStatus,
};
use serde::Serialize;

use crate::KernelError;
use crate::accounting::{account_counts, unresolved_groups, validate_accounting};
use assertions::{ScannerAssertions, ScannerView, evaluate_assertions};
use differential::{DifferentialResult, evaluate_differential};
pub use evidence::{EvaluationEvidence, FamilyContract, FamilyContracts, SegmentRule};
pub use model::{
    EvaluationCase, GeneratedCase, GeneratedVariant, GenerationLimits, MethodId, OperatorSpec,
};
pub use operators::OperatorId;
use reporting::{Summaries, summaries};
use review::{ReviewEntry, disagreement_entry, pending_expectation_entry};

/// Evidence schema label of a generated variant corpus.
pub const VARIANT_CORPUS_SCHEMA: &str = "credential-eval/generated-variants/v1";

/// Every generated case, ready to be scanned.
#[derive(Debug, Clone, PartialEq)]
pub struct EvaluationPlan {
    /// Generated cases, sorted by case id.
    pub cases: Vec<GeneratedCase>,
}

/// Generate every case. Fails closed on an invalid case, a duplicate case id
/// or generated path, or an exceeded bound.
pub fn plan_evaluation(
    cases: Vec<EvaluationCase>,
    evidence: &EvaluationEvidence,
    limits: &GenerationLimits,
) -> Result<EvaluationPlan, KernelError> {
    if cases.is_empty() {
        return Err(KernelError::InvalidInputs("empty evaluation cases"));
    }
    if cases.len() > limits.max_cases {
        return Err(KernelError::GenerationLimit {
            limit: "max_cases",
            value: limits.max_cases,
        });
    }
    let ids: BTreeSet<&CaseId> = cases.iter().map(|c| &c.id).collect();
    if ids.len() != cases.len() {
        return Err(KernelError::InvalidInputs("duplicate evaluation cases"));
    }
    let mut generated = Vec::with_capacity(cases.len());
    let mut total = 0_usize;
    for case in cases {
        let g = model::generate_case(case, evidence, limits)?;
        total += g.variants.len();
        if total > limits.max_total_variants {
            return Err(KernelError::GenerationLimit {
                limit: "max_total_variants",
                value: limits.max_total_variants,
            });
        }
        generated.push(g);
    }
    generated.sort_by(|a, b| a.case.id.cmp(&b.case.id));
    let mut paths = BTreeSet::new();
    for v in generated.iter().flat_map(|g| &g.variants) {
        if !paths.insert(&v.fixture.path) {
            return Err(KernelError::InvalidInputs("duplicate generated path"));
        }
    }
    Ok(EvaluationPlan { cases: generated })
}

impl EvaluationPlan {
    /// Every generated variant fixture as one corpus snapshot. Its source is
    /// the base snapshot's source, its revision the base corpus digest.
    pub fn variant_corpus(&self, base: &SnapshotIdentity) -> CorpusSnapshot {
        CorpusSnapshot::seal(
            base.source.clone(),
            base.corpus_digest.to_string(),
            VARIANT_CORPUS_SCHEMA.to_owned(),
            self.cases
                .iter()
                .flat_map(|g| g.variants.iter().map(|v| v.fixture.clone()))
                .collect(),
        )
    }

    /// Methods present in the plan.
    pub fn methods(&self) -> Vec<MethodIdentity> {
        let set: BTreeSet<MethodId> = self.cases.iter().map(|g| g.case.method).collect();
        set.into_iter()
            .map(|m| MethodIdentity {
                id: m.component(),
                version: m.version(),
            })
            .collect()
    }
}

/// Options of [`evaluate`].
#[derive(Debug, Clone, Copy)]
pub struct EvaluateOptions<'a> {
    /// Reference scanner of differential comparisons. `None` skips
    /// comparisons (every differential case records none).
    pub reference: Option<&'a ScannerId>,
    /// Accounting parameters.
    pub accounting: &'a AccountingConfig,
}

/// Results of one evaluation case.
#[derive(Debug, Clone, PartialEq)]
pub struct CaseEvaluation {
    /// The generated case.
    pub generated: GeneratedCase,
    /// Per-scanner assertions and rows (empty for `differential`).
    pub scanners: Vec<ScannerAssertions>,
    /// Differential result (`differential` only).
    pub differential: Option<DifferentialResult>,
}

/// A failed assertion (legacy `failures`, `execution.ts:102-104`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Failure {
    /// Scanner.
    pub scanner: ScannerId,
    /// The assertion.
    pub assertion: Assertion,
}

/// The evaluation report.
#[derive(Debug, Clone, PartialEq)]
pub struct EvaluationReport {
    /// Per-case results, sorted by case id.
    pub results: Vec<CaseEvaluation>,
    /// Scanner statuses by id.
    pub statuses: BTreeMap<ScannerId, ScannerStatus>,
    /// Assertion summaries.
    pub summaries: Summaries,
    /// Accounted resolution per `by_method` key.
    pub resolution: BTreeMap<String, AccountedCounts>,
    /// Strata below their resolved-rate floor.
    pub unresolved_groups: Vec<String>,
    /// Review queue, sorted by `(case_id, variant, peer, id)`.
    pub review_queue: Vec<ReviewEntry>,
    /// Failed assertions, sorted.
    pub failures: Vec<Failure>,
    /// Accounting parameters the report was computed with.
    pub accounting: AccountingConfig,
}

/// Group each complete scanner's findings by path, keeping emission order.
fn findings_by_path(
    observations: &ObservationSet,
) -> BTreeMap<&ScannerId, BTreeMap<&FixturePath, Vec<&NormalizedFinding>>> {
    observations
        .observations
        .iter()
        .filter_map(|o| match &o.result {
            ObservationResult::Complete { findings, .. } => {
                let mut by_path: BTreeMap<&FixturePath, Vec<&NormalizedFinding>> = BTreeMap::new();
                for f in findings {
                    by_path.entry(&f.path).or_default().push(f);
                }
                Some((&o.scanner.id, by_path))
            }
            _ => None,
        })
        .collect()
}

/// Evaluate a plan against observations recorded over its variant corpus.
pub fn evaluate(
    plan: &EvaluationPlan,
    base: &SnapshotIdentity,
    observations: &ObservationSet,
    options: EvaluateOptions<'_>,
) -> Result<EvaluationReport, KernelError> {
    validate_accounting(options.accounting)?;
    let corpus = plan.variant_corpus(base);
    observations.validate_against(&corpus)?;
    let by_path = findings_by_path(observations);
    let mut ordered: Vec<&credential_eval_contracts::observation::ScannerObservation> =
        observations.observations.iter().collect();
    ordered.sort_by(|a, b| a.scanner.id.cmp(&b.scanner.id));
    let views: Vec<ScannerView<'_>> = ordered
        .iter()
        .map(|o| ScannerView {
            id: &o.scanner.id,
            status: o.result.status(),
            findings: by_path.get(&o.scanner.id),
        })
        .collect();
    let identities: BTreeMap<&ScannerId, &ScannerIdentity> = ordered
        .iter()
        .map(|o| (&o.scanner.id, &o.scanner))
        .collect();
    let mut results = Vec::with_capacity(plan.cases.len());
    let mut queue = Vec::new();
    for g in &plan.cases {
        let case = &g.case;
        let (scanners, differential) = if case.method == MethodId::Differential {
            let result = options
                .reference
                .map(|r| evaluate_differential(&case.id, &g.variants, &views, r));
            if let (Some(result), Some(reference)) = (&result, options.reference) {
                for entry in &result.queue {
                    let (Some(ri), Some(pi)) =
                        (identities.get(reference), identities.get(&entry.peer))
                    else {
                        continue;
                    };
                    queue.push(disagreement_entry(
                        &case.id,
                        &case.source_hash,
                        &case.targets,
                        entry,
                        reference,
                        ri,
                        pi,
                    ));
                }
            }
            (Vec::new(), result)
        } else {
            (
                evaluate_assertions(&case.id, case.method, &g.variants, &views),
                None,
            )
        };
        for v in g.variants.iter().filter(|v| {
            v.strategy == credential_eval_contracts::artifact::VariantStrategy::ReviewRequired
        }) {
            queue.push(pending_expectation_entry(
                &case.id,
                case.method,
                &case.targets,
                v,
            ));
        }
        results.push(CaseEvaluation {
            generated: g.clone(),
            scanners,
            differential,
        });
    }
    queue.sort_by(|a, b| {
        (&a.case_id, &a.variant, &a.peer, &a.id).cmp(&(&b.case_id, &b.variant, &b.peer, &b.id))
    });
    let summaries = summaries(
        results
            .iter()
            .map(|r| (&r.generated, r.scanners.as_slice())),
    );
    let resolution = summaries
        .by_method
        .iter()
        .map(|(k, c)| (k.clone(), account_counts(c, options.accounting)))
        .collect();
    let unresolved = unresolved_groups(&summaries.by_method, options.accounting);
    let mut failures: Vec<Failure> = results
        .iter()
        .flat_map(|r| {
            r.scanners.iter().flat_map(|s| {
                s.assertions
                    .iter()
                    .filter(|a| a.status == AssertionStatus::Fail)
                    .map(|a| Failure {
                        scanner: s.scanner.clone(),
                        assertion: a.clone(),
                    })
            })
        })
        .collect();
    failures.sort_by(|a, b| (&a.assertion, &a.scanner).cmp(&(&b.assertion, &b.scanner)));
    Ok(EvaluationReport {
        results,
        statuses: ordered
            .iter()
            .map(|o| (o.scanner.id.clone(), o.result.status()))
            .collect(),
        summaries,
        resolution,
        unresolved_groups: unresolved,
        review_queue: queue,
        failures,
        accounting: options.accounting.clone(),
    })
}

/// The parts of a [`credential_eval_contracts::artifact::RunArtifact`] that an
/// evaluation fills.
#[derive(Debug, Clone, PartialEq)]
pub struct ArtifactParts {
    /// `manifest.methods`.
    pub methods: Vec<MethodIdentity>,
    /// `variants`.
    pub variants: Vec<VariantRecord>,
    /// `comparisons`.
    pub comparisons: Vec<DifferentialComparison>,
    /// `scanners[].assertions`, by scanner.
    pub assertions: BTreeMap<ScannerId, Vec<Assertion>>,
    /// `scanners[].aggregates.resolution`, by scanner, keyed
    /// `<method>/<stratum>/<assertion>`.
    pub resolution: BTreeMap<ScannerId, BTreeMap<String, AccountedCounts>>,
    /// `scanners[].aggregates.resolution_by_target`, by scanner then target.
    pub resolution_by_target:
        BTreeMap<ScannerId, BTreeMap<String, BTreeMap<String, AccountedCounts>>>,
    /// `review_queue`, sorted by id.
    pub review_queue: Vec<ReviewOccurrence>,
}

/// Split `<method>/<scanner>/<rest>` keys by scanner into `<method>/<rest>`.
fn by_scanner(
    statuses: &BTreeMap<ScannerId, ScannerStatus>,
    rows: &BTreeMap<String, AccountedCounts>,
) -> BTreeMap<ScannerId, BTreeMap<String, AccountedCounts>> {
    let mut out: BTreeMap<ScannerId, BTreeMap<String, AccountedCounts>> = BTreeMap::new();
    for (key, counts) in rows {
        let mut parts = key.splitn(3, '/');
        let (Some(method), Some(scanner), Some(rest)) = (parts.next(), parts.next(), parts.next())
        else {
            continue;
        };
        let Some(id) = statuses.keys().find(|s| s.as_str() == scanner) else {
            continue;
        };
        out.entry(id.clone())
            .or_default()
            .insert(format!("{method}/{rest}"), counts.clone());
    }
    out
}

impl EvaluationReport {
    /// Project the report onto the run-artifact contract.
    pub fn artifact_parts(&self, plan: &EvaluationPlan) -> ArtifactParts {
        let variants = plan
            .cases
            .iter()
            .flat_map(|g| {
                g.variants.iter().map(|v| VariantRecord {
                    case_id: g.case.id.clone(),
                    variant: v.id.clone(),
                    path: v.fixture.path.clone(),
                    method: MethodIdentity {
                        id: g.case.method.component(),
                        version: g.case.method.version(),
                    },
                    operator: v.transformation.operator.clone(),
                    operator_version: v.transformation.operator_version,
                    parameters: model::safe_parameters(&v.transformation.parameters),
                    strategy: v.strategy,
                    relation: v.transformation.relation,
                    property: v.transformation.property.clone(),
                    content_digest: sha256_bytes(v.fixture.content.as_bytes()),
                })
            })
            .collect();
        let mut comparisons: Vec<DifferentialComparison> = self
            .results
            .iter()
            .filter_map(|r| r.differential.as_ref())
            .flat_map(|d| d.comparisons.iter().cloned())
            .collect();
        comparisons.sort();
        let mut assertions: BTreeMap<ScannerId, Vec<Assertion>> = self
            .statuses
            .keys()
            .map(|s| (s.clone(), Vec::new()))
            .collect();
        for r in &self.results {
            for s in &r.scanners {
                assertions
                    .entry(s.scanner.clone())
                    .or_default()
                    .extend(s.assertions.iter().cloned());
            }
        }
        for list in assertions.values_mut() {
            list.sort();
        }
        let resolution = by_scanner(&self.statuses, &self.resolution);
        let mut resolution_by_target: BTreeMap<
            ScannerId,
            BTreeMap<String, BTreeMap<String, AccountedCounts>>,
        > = BTreeMap::new();
        for (target, rows) in &self.summaries.by_target {
            let accounted = rows
                .iter()
                .map(|(k, c)| (k.clone(), account_counts(c, &self.accounting)))
                .collect();
            for (scanner, rows) in by_scanner(&self.statuses, &accounted) {
                resolution_by_target
                    .entry(scanner)
                    .or_default()
                    .insert(target.clone(), rows);
            }
        }
        let mut review_queue: Vec<ReviewOccurrence> = self
            .review_queue
            .iter()
            .map(ReviewEntry::occurrence)
            .collect();
        review_queue.sort();
        review_queue.dedup();
        ArtifactParts {
            methods: plan.methods(),
            variants,
            comparisons,
            assertions,
            resolution,
            resolution_by_target,
            review_queue,
        }
    }

    /// Process exit code (legacy `exitCode`, `engine/runner.ts:11-14`): `1`
    /// when a scanner errored (or, with `strict`, did not complete), or when
    /// `fail_on_assertions` and an assertion failed. Generation errors are
    /// refused earlier by [`plan_evaluation`] or recorded as attempts.
    pub fn exit_code(&self, strict: bool, fail_on_assertions: bool) -> i32 {
        let generation_errors = self.results.iter().any(|r| {
            r.generated
                .attempts
                .iter()
                .any(|a| a.status == model::AttemptStatus::Error)
        });
        let scanner_failed = self.statuses.values().any(|s| {
            matches!(
                s,
                ScannerStatus::Error | ScannerStatus::Timeout | ScannerStatus::Malformed
            ) || (strict && *s != ScannerStatus::Complete)
        });
        i32::from(
            generation_errors
                || scanner_failed
                || (fail_on_assertions && !self.failures.is_empty()),
        )
    }
}
