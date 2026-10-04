//! Variant observation and method assertions
//! (legacy `evaluation/domains/credential/assertions.ts`).

use credential_eval_contracts::artifact::{
    Assertion, AssertionStatus, AssertionType, CaseMeasurement, CaseResult, ObservedRange, Outcome,
    Relation, ScoredSpan, VariantStrategy,
};
use credential_eval_contracts::corpus::EvidenceTier;
use credential_eval_contracts::ids::{CaseId, FixturePath, ScannerId};
use credential_eval_contracts::observation::{NormalizedFinding, ScannerStatus};
use serde::Serialize;

use super::model::{GeneratedVariant, MethodId, secrets};
use crate::lattice::{is_acceptable, score_row};

/// Reason recorded on review-required absolute assertions (`assertions.ts:23`).
pub const PENDING_REVIEW: &str = "Expectation is pending review.";

fn expected_of(v: &GeneratedVariant) -> Vec<ScoredSpan> {
    v.fixture
        .expected
        .iter()
        .map(|e| ScoredSpan {
            start: e.start,
            end: e.end,
            role: e.role,
            envelope: e.envelope.as_ref().map(|en| en.range()),
        })
        .collect()
}

/// Deduplicate one path's findings by `(start, end)` with the last
/// classification winning, then sort (legacy `score` over one fixture,
/// `benchmarks/lib/scoring.ts:92-110`).
pub fn actual_on_path(findings: &[&NormalizedFinding]) -> Vec<ObservedRange> {
    let mut unique: std::collections::BTreeMap<(u64, u64), &NormalizedFinding> =
        std::collections::BTreeMap::new();
    for f in findings {
        unique.insert((f.start, f.end), f);
    }
    unique
        .into_values()
        .map(|f| ObservedRange {
            start: f.start,
            end: f.end,
            family: f.family.clone(),
            action: f.action.clone(),
            mapping: f.mapping.clone(),
        })
        .collect()
}

/// Score one variant against the findings on its path (`assertions.ts:8-19`).
///
/// `T0` variants are unscored unless the variant is an authored twin
/// (`must-flip`) with a family: its reading is then scoped to that family,
/// exactly as legacy re-scores it.
pub fn observe(v: &GeneratedVariant, findings: &[&NormalizedFinding]) -> CaseResult {
    let expected = expected_of(v);
    let actual = actual_on_path(findings);
    let family = v.fixture.grouping.family.as_deref();
    let measurement = if v.transformation.relation == Some(Relation::MustFlip) && family.is_some() {
        score_row(&expected, &actual, family)
    } else if v.fixture.grouping.tier == EvidenceTier::T0 {
        CaseMeasurement::Pending
    } else {
        score_row(&expected, &actual, None)
    };
    CaseResult {
        case_id: v.fixture.id.clone(),
        path: v.fixture.path.clone(),
        kind: v.fixture.grouping.kind,
        tier: v.fixture.grouping.tier,
        family: v.fixture.grouping.family.clone(),
        twin_of: None,
        group: v.fixture.grouping.group.clone(),
        targets: v.fixture.grouping.targets.clone(),
        taxonomy: v.fixture.grouping.taxonomy.clone(),
        evidence_class: v.fixture.grouping.evidence_class.clone(),
        twin_mutation_kind: None,
        expected,
        actual,
        measurement,
    }
}

/// The row of a variant a scanner could not map to ranges: its findings are
/// unknown, so it carries no actual ranges and reads `not_measured`, never a
/// miss (ADR 0004).
pub fn unmeasured_row(v: &GeneratedVariant) -> CaseResult {
    CaseResult {
        measurement: CaseMeasurement::NotMeasured {
            status: ScannerStatus::Malformed,
        },
        ..observe(v, &[])
    }
}

/// An absolute or relation verdict before it is keyed to a case and method.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verdict {
    /// Assertion type.
    pub assertion: AssertionType,
    /// Status.
    pub status: AssertionStatus,
    /// Fixed reason.
    pub reason: Option<String>,
}

/// Absolute assertion of one variant (`assertions.ts:21-29`). A positive
/// passes when every span is EXACT/COVERED **and** there are zero collateral
/// bytes; a control passes when not flagged.
pub fn absolute(v: &GeneratedVariant, row: &CaseResult) -> Verdict {
    if v.strategy == VariantStrategy::ReviewRequired || v.fixture.grouping.tier == EvidenceTier::T0
    {
        return Verdict {
            assertion: AssertionType::Absolute,
            status: AssertionStatus::ReviewRequired,
            reason: Some(PENDING_REVIEW.to_owned()),
        };
    }
    let positive = !secrets(&v.fixture).is_empty();
    let pass = match (&row.measurement, positive) {
        (
            CaseMeasurement::Positive {
                span_outcomes,
                collateral_bytes,
                ..
            },
            true,
        ) => span_outcomes.iter().all(|o| is_acceptable(*o)) && *collateral_bytes == 0,
        (CaseMeasurement::Control { flagged, .. }, false) => !flagged,
        _ => false,
    };
    Verdict {
        assertion: if positive {
            AssertionType::PresentWithinEnvelope
        } else {
            AssertionType::Absent
        },
        status: if pass {
            AssertionStatus::Pass
        } else {
            AssertionStatus::Fail
        },
        reason: None,
    }
}

#[derive(PartialEq, Eq)]
enum Reading<'a> {
    Outcomes(&'a [Outcome]),
    Flagged(Option<bool>),
}

fn reading(row: &CaseResult) -> Reading<'_> {
    match &row.measurement {
        CaseMeasurement::Positive { span_outcomes, .. } => Reading::Outcomes(span_outcomes),
        CaseMeasurement::Control { flagged, .. } => Reading::Flagged(Some(*flagged)),
        _ => Reading::Flagged(None),
    }
}

/// Relation assertion between the canonical baseline and a candidate
/// (`assertions.ts:31-40`). Two missed positives never pass an invariance.
pub fn relation(
    baseline: (&GeneratedVariant, &CaseResult),
    candidate: (&GeneratedVariant, &CaseResult),
    relation: Relation,
) -> Verdict {
    let assertion = match relation {
        Relation::SameDetection => AssertionType::SameDetection,
        Relation::MustFlip => AssertionType::MustFlip,
    };
    let a = absolute(baseline.0, baseline.1);
    let b = absolute(candidate.0, candidate.1);
    if a.status == AssertionStatus::ReviewRequired || b.status == AssertionStatus::ReviewRequired {
        return Verdict {
            assertion,
            status: AssertionStatus::ReviewRequired,
            reason: None,
        };
    }
    let mut pass = a.status == AssertionStatus::Pass && b.status == AssertionStatus::Pass;
    match relation {
        Relation::MustFlip => {
            pass &= !secrets(&baseline.0.fixture).is_empty()
                && secrets(&candidate.0.fixture).is_empty();
        }
        Relation::SameDetection => pass &= reading(baseline.1) == reading(candidate.1),
    }
    Verdict {
        assertion,
        status: if pass {
            AssertionStatus::Pass
        } else {
            AssertionStatus::Fail
        },
        reason: None,
    }
}

/// One scanner's assertions and variant rows for one case.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ScannerAssertions {
    /// Scanner id.
    pub scanner: ScannerId,
    /// Scanner status.
    pub status: ScannerStatus,
    /// Assertions: one absolute per variant, then one relation per non-canonical
    /// variant that declares a relation.
    pub assertions: Vec<Assertion>,
    /// Variant rows (empty when the scanner did not complete).
    pub rows: Vec<CaseResult>,
}

/// A scanner's findings on the variant corpus, or its non-complete status.
#[derive(Debug, Clone, Copy)]
pub struct ScannerView<'a> {
    /// Scanner id.
    pub id: &'a ScannerId,
    /// Status.
    pub status: ScannerStatus,
    /// Findings by path (emission order kept), when complete.
    pub findings: Option<
        &'a std::collections::BTreeMap<
            &'a credential_eval_contracts::ids::FixturePath,
            Vec<&'a NormalizedFinding>,
        >,
    >,
    /// Variant paths a complete scanner could not map to ranges (ADR 0004).
    /// A variant on one of them is not measured by this scanner: it has no
    /// assertion and no comparison, so it is in no denominator and is never
    /// read as a missed detection.
    pub unmeasured: Option<&'a std::collections::BTreeSet<&'a FixturePath>>,
}

impl ScannerView<'_> {
    /// Whether this scanner left the variant unmeasured (ADR 0004).
    pub fn is_unmeasured(&self, v: &GeneratedVariant) -> bool {
        self.unmeasured
            .is_some_and(|set| set.contains(&v.fixture.path))
    }

    pub(crate) fn on(&self, v: &GeneratedVariant) -> Vec<&NormalizedFinding> {
        self.findings
            .and_then(|m| m.get(&v.fixture.path))
            .cloned()
            .unwrap_or_default()
    }
}

/// Evaluate assertions for every scanner (`assertions.ts:42-56`). A scanner
/// that did not complete yields one `not-measured` absolute per variant.
pub fn evaluate_assertions(
    case_id: &CaseId,
    method: MethodId,
    variants: &[GeneratedVariant],
    scanners: &[ScannerView<'_>],
) -> Vec<ScannerAssertions> {
    let keyed = |v: Option<&GeneratedVariant>,
                 b: Option<&GeneratedVariant>,
                 c: Option<&GeneratedVariant>,
                 verdict: Verdict| Assertion {
        case_id: case_id.clone(),
        method: method.component(),
        variant: v.map(|v| v.id.clone()),
        baseline: b.map(|v| v.id.clone()),
        candidate: c.map(|v| v.id.clone()),
        assertion: verdict.assertion,
        status: verdict.status,
        reason: verdict.reason,
    };
    scanners
        .iter()
        .map(|scanner| {
            if scanner.status != ScannerStatus::Complete {
                let reason = serde_json::to_value(scanner.status)
                    .ok()
                    .and_then(|v| v.as_str().map(str::to_owned));
                return ScannerAssertions {
                    scanner: scanner.id.clone(),
                    status: scanner.status,
                    assertions: variants
                        .iter()
                        .map(|v| {
                            keyed(
                                Some(v),
                                None,
                                None,
                                Verdict {
                                    assertion: AssertionType::Absolute,
                                    status: AssertionStatus::NotMeasured,
                                    reason: reason.clone(),
                                },
                            )
                        })
                        .collect(),
                    rows: Vec::new(),
                };
            }
            // A variant the scanner could not map is neither passed nor failed:
            // its row is `not_measured`, and it carries no assertion (ADR 0004).
            let rows: Vec<CaseResult> = variants
                .iter()
                .map(|v| {
                    if scanner.is_unmeasured(v) {
                        unmeasured_row(v)
                    } else {
                        observe(v, &scanner.on(v))
                    }
                })
                .collect();
            let mut assertions: Vec<Assertion> = variants
                .iter()
                .zip(&rows)
                .filter(|(v, _)| !scanner.is_unmeasured(v))
                .map(|(v, row)| keyed(Some(v), None, None, absolute(v, row)))
                .collect();
            for i in 1..variants.len() {
                if scanner.is_unmeasured(&variants[0]) || scanner.is_unmeasured(&variants[i]) {
                    continue;
                }
                if let Some(r) = variants[i].transformation.relation {
                    let verdict = relation((&variants[0], &rows[0]), (&variants[i], &rows[i]), r);
                    assertions.push(keyed(None, Some(&variants[0]), Some(&variants[i]), verdict));
                }
            }
            ScannerAssertions {
                scanner: scanner.id.clone(),
                status: ScannerStatus::Complete,
                assertions,
                rows,
            }
        })
        .collect()
}
