//! Assertion summaries (legacy `summaries`,
//! `evaluation/domains/credential/reporting.ts:26-66`).
//!
//! Counts are keyed `<method>/<scanner>/<stratum>/<assertion>` where the
//! stratum is `<kind>:<tier>` of the asserted variant, or
//! `<baseline stratum>-><candidate stratum>` for relations. Nothing is summed
//! across strata.

use std::collections::{BTreeMap, BTreeSet};

use credential_eval_contracts::artifact::{Assertion, AssertionType};
use serde::Serialize;

use super::assertions::ScannerAssertions;
use super::model::{AttemptStatus, GeneratedCase, MethodId};
use crate::accounting::StatusCounts;

/// Summary rows by key.
pub type Summary = BTreeMap<String, StatusCounts>;

/// Operator attempt and assertion counts.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct OperatorSummary {
    /// Generated attempts.
    pub generated: u64,
    /// Unsupported attempts.
    pub unsupported: u64,
    /// Failed attempts.
    pub error: u64,
    /// Assertions on the operator's variants.
    pub assertions: Summary,
}

/// All summaries of an evaluation.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct Summaries {
    /// By method.
    pub by_method: Summary,
    /// By target family (`unassigned` for cases without targets).
    pub by_target: BTreeMap<String, Summary>,
    /// By benign taxonomy.
    pub by_taxonomy: BTreeMap<String, Summary>,
    /// By operator.
    pub by_operator: BTreeMap<String, OperatorSummary>,
    /// Distinct benign taxonomy axes per target.
    pub axes_by_target: BTreeMap<String, Vec<String>>,
}

fn assertion_name(t: AssertionType) -> &'static str {
    match t {
        AssertionType::Absolute => "absolute",
        AssertionType::PresentWithinEnvelope => "present-within-envelope",
        AssertionType::Absent => "absent",
        AssertionType::SameDetection => "same-detection",
        AssertionType::MustFlip => "must-flip",
    }
}

/// Summarize the assertions of every generated case.
pub fn summaries<'a>(
    results: impl IntoIterator<Item = (&'a GeneratedCase, &'a [ScannerAssertions])>,
) -> Summaries {
    let mut out = Summaries::default();
    let mut axes: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for (generated, scanners) in results {
        let case = &generated.case;
        let targets: Vec<String> = if case.targets.is_empty() {
            vec!["unassigned".to_owned()]
        } else {
            case.targets.clone()
        };
        if case.method == MethodId::Benign {
            if let Some(taxonomy) = &case.taxonomy {
                for t in &targets {
                    axes.entry(t.clone()).or_default().insert(taxonomy.clone());
                }
            }
        }
        for attempt in &generated.attempts {
            let row = out
                .by_operator
                .entry(attempt.operator.as_str().to_owned())
                .or_default();
            match attempt.status {
                AttemptStatus::Generated => row.generated += 1,
                AttemptStatus::Unsupported => row.unsupported += 1,
                AttemptStatus::Error => row.error += 1,
            }
        }
        let variants: BTreeMap<&str, &super::model::GeneratedVariant> = generated
            .variants
            .iter()
            .map(|v| (v.id.as_str(), v))
            .collect();
        let stratum = |id: &str| {
            let v = variants[id];
            format!(
                "{}:{}",
                v.fixture.grouping.kind.as_str(),
                v.fixture.grouping.tier.as_str()
            )
        };
        for scanner in scanners {
            for a in &scanner.assertions {
                let group = group_of(a, &stratum);
                let key = format!(
                    "{}/{}/{}/{}",
                    case.method.as_str(),
                    scanner.scanner,
                    group,
                    assertion_name(a.assertion)
                );
                out.by_method.entry(key.clone()).or_default().add(a.status);
                let operator_variant = a.variant.as_ref().or(a.candidate.as_ref());
                if let Some(v) = operator_variant.and_then(|id| variants.get(id.as_str())) {
                    if let Some(row) = out.by_operator.get_mut(v.transformation.operator.as_str()) {
                        row.assertions.entry(key.clone()).or_default().add(a.status);
                    }
                }
                if let Some(taxonomy) = &case.taxonomy {
                    out.by_taxonomy
                        .entry(taxonomy.clone())
                        .or_default()
                        .entry(key.clone())
                        .or_default()
                        .add(a.status);
                }
                for t in &targets {
                    out.by_target
                        .entry(t.clone())
                        .or_default()
                        .entry(key.clone())
                        .or_default()
                        .add(a.status);
                }
            }
        }
    }
    out.axes_by_target = axes
        .into_iter()
        .map(|(k, v)| (k, v.into_iter().collect()))
        .collect();
    out
}

fn group_of(a: &Assertion, stratum: &impl Fn(&str) -> String) -> String {
    match &a.variant {
        Some(v) => stratum(v.as_str()),
        None => format!(
            "{}->{}",
            stratum(a.baseline.as_ref().map_or("", |b| b.as_str())),
            stratum(a.candidate.as_ref().map_or("", |c| c.as_str()))
        ),
    }
}
