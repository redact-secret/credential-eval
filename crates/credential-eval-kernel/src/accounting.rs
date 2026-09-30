//! Engine v1.1 accounting (protocol 1).
//!
//! Ports the mechanical primitives of `accounting/shared/primitives.ts` and the
//! credential group accounting of `evaluation/domains/credential/accounting.ts`
//! at the pinned legacy commit. Counts come from the per-case measurements
//! only, so every aggregate reconciles with `cases[]`: a consumer can recompute
//! any group from the artifact alone.
//!
//! Floors (`measurable_share_floor`, `twin_coverage_floor`,
//! `resolved_rate_floor`) withhold figures; they are measurement rules, not
//! support thresholds. Nothing here ranks scanners or sums across groups.

use std::collections::{BTreeMap, BTreeSet};

use credential_eval_contracts::artifact::{
    AccountedCounts, BoundDirection, CaseMeasurement, CaseResult, ControlDiagnostics,
    EnvelopeWidth, GroupAggregate, OutcomeCounts, PositiveDiagnostics, Published, Rate,
    TwinMeasurement, Withheld,
};
use credential_eval_contracts::config::{AccountingConfig, Floor};
use credential_eval_contracts::corpus::{CaseKind, EvidenceTier, SpanRole};
use credential_eval_contracts::ids::CaseId;
use serde::{Deserialize, Serialize};

use crate::KernelError;
use crate::jsnum::round_to_fixed;
use crate::lattice::{is_acceptable, is_leaked};

/// Group key of a case: `pending/T0` for every `T0` case, else `<kind>/<tier>`
/// (`benchmarks/lib/lattice.ts:99`).
pub fn group_key(kind: CaseKind, tier: EvidenceTier) -> String {
    if tier == EvidenceTier::T0 {
        "pending/T0".to_owned()
    } else {
        format!("{}/{}", kind.as_str(), tier.as_str())
    }
}

/// The pending group key.
pub const PENDING_GROUP: &str = "pending/T0";

/// Validate accounting parameters (legacy `validateMechanicalAccounting` and
/// `validateAccounting`, `accounting/shared/primitives.ts:27-33`,
/// `evaluation/domains/credential/accounting.ts:43-54`).
pub fn validate_accounting(config: &AccountingConfig) -> Result<(), KernelError> {
    let unit = |v: f64| (0.0..=1.0).contains(&v);
    let floor = |f: &Floor| match f {
        Floor::Uniform(v) => unit(*v),
        Floor::Keyed { default, overrides } => {
            unit(*default) && overrides.values().all(|v| unit(*v))
        }
    };
    if config.min_denominator < 1 {
        return Err(KernelError::InvalidAccounting(
            "min_denominator must be >= 1",
        ));
    }
    if config.replays < 2 {
        return Err(KernelError::InvalidAccounting("replays must be >= 2"));
    }
    if config.interval_z.is_nan() || config.interval_z <= 0.0 {
        return Err(KernelError::InvalidAccounting("interval_z must be > 0"));
    }
    if !(1..=12).contains(&config.interval_precision) {
        return Err(KernelError::InvalidAccounting(
            "interval_precision must be in 1..=12",
        ));
    }
    if !floor(&config.resolved_rate_floor)
        || !floor(&config.measurable_share_floor)
        || !floor(&config.twin_coverage_floor)
    {
        return Err(KernelError::InvalidAccounting("floors must lie in [0, 1]"));
    }
    Ok(())
}

/// Wilson score interval endpoint on the pessimistic side, clamped to
/// `[0, 1]` and rounded (`accounting/shared/primitives.ts:36-41`). The
/// arithmetic follows the legacy expression order so results agree bit for bit.
pub fn wilson(p: f64, n: u64, direction: BoundDirection, z: f64, precision: u32) -> f64 {
    let n = n as f64;
    let scale = 1.0 + (z * z) / n;
    let centre = (p + (z * z) / (2.0 * n)) / scale;
    let spread = (z / scale) * ((p * (1.0 - p)) / n + (z * z) / (4.0 * n * n)).sqrt();
    let endpoint = match direction {
        BoundDirection::Upper => centre + spread,
        BoundDirection::Lower => centre - spread,
    };
    round_to_fixed(endpoint.clamp(0.0, 1.0), precision)
}

/// A proportion with its Wilson bound (`primitives.ts:43-48`).
///
/// `null` when the denominator (or `n`) is zero; `insufficient-evidence` when
/// `n < min_denominator`. The bound is computed from the **unrounded** point.
/// `n` defaults to the denominator.
pub fn proportion(
    numerator: u64,
    denominator: u64,
    direction: BoundDirection,
    config: &AccountingConfig,
    n: Option<u64>,
) -> Option<Published> {
    let n = n.unwrap_or(denominator);
    if denominator == 0 || n == 0 {
        return None;
    }
    if n < u64::from(config.min_denominator) {
        return Some(Published::Withheld(Withheld::InsufficientEvidence));
    }
    let point = numerator as f64 / denominator as f64;
    // A point above 1 (e.g. twin coverage with several twins per positive)
    // makes the Wilson spread NaN; legacy serializes that bound as `null`.
    let bound = wilson(
        point,
        n,
        direction,
        config.interval_z,
        config.interval_precision,
    );
    Some(Published::Rate(Rate {
        point: round_to_fixed(point, config.interval_precision),
        bound: (!bound.is_nan()).then_some(bound),
        n,
        direction: Some(direction),
    }))
}

/// An unbounded ratio (`primitives.ts:50-54`). Same guards as [`proportion`],
/// but the emitted `n` is the **denominator**, not the guard `n` (a legacy
/// quirk preserved as protocol).
pub fn ratio(
    numerator: u64,
    denominator: u64,
    config: &AccountingConfig,
    n: Option<u64>,
) -> Option<Published> {
    let n = n.unwrap_or(denominator);
    if denominator == 0 || n == 0 {
        return None;
    }
    if n < u64::from(config.min_denominator) {
        return Some(Published::Withheld(Withheld::InsufficientEvidence));
    }
    Some(Published::Rate(Rate {
        point: round_to_fixed(
            numerator as f64 / denominator as f64,
            config.interval_precision,
        ),
        bound: None,
        n: denominator,
        direction: None,
    }))
}

/// Assertion status tallies of one stratum (legacy `Summary` rows).
#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
#[serde(deny_unknown_fields)]
pub struct StatusCounts {
    /// Passed assertions.
    pub pass: u64,
    /// Failed assertions.
    pub fail: u64,
    /// Assertions awaiting an authored decision.
    #[serde(rename = "review-required")]
    pub review_required: u64,
    /// Assertions never observed.
    #[serde(rename = "not-measured")]
    pub not_measured: u64,
}

impl StatusCounts {
    /// Increment the counter for `status`.
    pub fn add(&mut self, status: credential_eval_contracts::artifact::AssertionStatus) {
        use credential_eval_contracts::artifact::AssertionStatus as S;
        match status {
            S::Pass => self.pass += 1,
            S::Fail => self.fail += 1,
            S::ReviewRequired => self.review_required += 1,
            S::NotMeasured => self.not_measured += 1,
        }
    }

    /// `pass + fail`.
    pub const fn resolved(&self) -> u64 {
        self.pass + self.fail
    }

    /// All assertions.
    pub const fn total(&self) -> u64 {
        self.resolved() + self.review_required + self.not_measured
    }
}

/// Resolution accounting of one stratum (`primitives.ts:57-61`).
pub fn account_counts(counts: &StatusCounts, config: &AccountingConfig) -> AccountedCounts {
    let resolved = counts.resolved();
    let total = counts.total();
    AccountedCounts {
        pass: counts.pass,
        fail: counts.fail,
        review_required: counts.review_required,
        not_measured: counts.not_measured,
        total,
        resolved,
        unresolved: total - resolved,
        resolved_rate: proportion(resolved, total, BoundDirection::Lower, config, None),
    }
}

/// Strata whose resolved share is below the floor of their method
/// (`evaluation/domains/credential/accounting.ts:173-185`).
///
/// Keys are `<method>/<scanner>/<stratum>/<assertion>`. `:T0` strata are
/// skipped (they are charged through measurable share and the review queue),
/// and a method that resolved nothing although its floor is positive is listed
/// as `<method>/*`. The result is sorted.
pub fn unresolved_groups(
    summary: &BTreeMap<String, StatusCounts>,
    config: &AccountingConfig,
) -> Vec<String> {
    let mut below = Vec::new();
    let mut methods: BTreeMap<&str, (u64, u64)> = BTreeMap::new();
    for (key, counts) in summary {
        let mut parts = key.split('/');
        let method = parts.next().unwrap_or("");
        let stratum = parts.nth(1).unwrap_or("");
        let (total, resolved) = (counts.total(), counts.resolved());
        let m = methods.entry(method).or_default();
        m.0 += total;
        m.1 += resolved;
        if stratum.contains(":T0") || total == 0 {
            continue;
        }
        if (resolved as f64) / (total as f64) < config.resolved_rate_floor.for_key(method) {
            below.push(key.clone());
        }
    }
    for (method, (total, resolved)) in methods {
        if total > 0 && resolved == 0 && config.resolved_rate_floor.for_key(method) > 0.0 {
            below.push(format!("{method}/*"));
        }
    }
    below.sort();
    below
}

/// Per-group counts shared by the v1.0 aggregation and the v1.1 accounting
/// (legacy `aggregateGroups`, `benchmarks/lib/lattice.ts:113-182`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum GroupCounts {
    Pending {
        files: u64,
    },
    Control {
        files: u64,
        flagged_files: u64,
        findings: u64,
        fp: u64,
        tn: u64,
    },
    Positive(Box<PositiveCounts>),
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct PositiveCounts {
    pub files: u64,
    pub spans: u64,
    pub secret_bytes: u64,
    pub outcomes: OutcomeCounts,
    pub leaked_spans: u64,
    pub leaked_bytes: u64,
    pub collateral_bytes: u64,
    pub positives: u64,
    pub pairs: u64,
    /// v1.0 lenient discrimination: every span non-leaking (OVERBROAD counts).
    pub discriminated_lenient: u64,
    /// v1.1 strict discrimination: every span EXACT/COVERED.
    pub discriminated_strict: u64,
    pub co_detected: u64,
    pub tp: u64,
    pub fp: u64,
    pub fn_: u64,
    pub envelope: EnvelopeWidth,
}

fn is_twin_positive(positive: &CaseResult) -> bool {
    positive.kind != CaseKind::MustNotFlag && positive.tier != EvidenceTier::T0
}

/// Count every group. Errors when a case's measurement contradicts its
/// population (legacy would crash or produce `NaN`).
pub(crate) fn group_counts(
    cases: &[&CaseResult],
) -> Result<BTreeMap<String, GroupCounts>, KernelError> {
    let by_id: BTreeMap<&CaseId, &CaseResult> = cases.iter().map(|c| (&c.case_id, *c)).collect();
    // Twins paired with a scored, non-control positive (lattice.ts:117-123).
    let mut twins_for: BTreeMap<&CaseId, Vec<&CaseResult>> = BTreeMap::new();
    for twin in cases {
        let Some(twin_of) = &twin.twin_of else {
            continue;
        };
        if twin.tier == EvidenceTier::T0 {
            continue;
        }
        match by_id.get(twin_of) {
            Some(positive) if is_twin_positive(positive) => {
                twins_for.entry(&positive.case_id).or_default().push(twin);
            }
            _ => {}
        }
    }
    let inconsistent = |case: &CaseResult, reason| KernelError::InconsistentCase {
        case: case.case_id.to_string(),
        reason,
    };
    let mut groups: BTreeMap<String, GroupCounts> = BTreeMap::new();
    let mut positive_population = 0_u64;
    for case in cases {
        let key = group_key(case.kind, case.tier);
        if case.tier == EvidenceTier::T0 {
            if let GroupCounts::Pending { files } = groups
                .entry(key)
                .or_insert(GroupCounts::Pending { files: 0 })
            {
                *files += 1;
            }
            continue;
        }
        if case.kind == CaseKind::MustNotFlag {
            let CaseMeasurement::Control {
                flagged, findings, ..
            } = &case.measurement
            else {
                return Err(inconsistent(case, "must-not-flag case is not a control"));
            };
            if let GroupCounts::Control {
                files,
                flagged_files,
                findings: total,
                fp,
                tn,
            } = groups.entry(key).or_insert(GroupCounts::Control {
                files: 0,
                flagged_files: 0,
                findings: 0,
                fp: 0,
                tn: 0,
            }) {
                *files += 1;
                *total += findings;
                *fp += findings;
                if *flagged {
                    *flagged_files += 1;
                } else {
                    *tn += 1;
                }
            }
            continue;
        }
        positive_population += 1;
        let CaseMeasurement::Positive {
            span_outcomes,
            leaked_bytes,
            collateral_bytes,
        } = &case.measurement
        else {
            return Err(inconsistent(
                case,
                "scored positive case has no secret span",
            ));
        };
        let entry = groups
            .entry(key)
            .or_insert_with(|| GroupCounts::Positive(Box::default()));
        let GroupCounts::Positive(g) = entry else {
            return Err(inconsistent(case, "group key collision"));
        };
        let secrets: Vec<_> = case
            .expected
            .iter()
            .filter(|e| e.role == SpanRole::Secret)
            .collect();
        g.files += 1;
        g.spans += span_outcomes.len() as u64;
        g.secret_bytes += secrets.iter().map(|e| e.end - e.start).sum::<u64>();
        for outcome in span_outcomes {
            g.outcomes.add(*outcome);
            if is_leaked(*outcome) {
                g.leaked_spans += 1;
            }
        }
        g.leaked_bytes += leaked_bytes;
        g.collateral_bytes += collateral_bytes;
        let tp = span_outcomes
            .iter()
            .filter(|o| **o == credential_eval_contracts::artifact::Outcome::Exact)
            .count() as u64;
        g.tp += tp;
        g.fn_ += secrets.len() as u64 - tp;
        g.fp += case
            .actual
            .iter()
            .filter(|a| !secrets.iter().any(|e| e.start == a.start && e.end == a.end))
            .count() as u64;
        // Envelope widening (accounting.ts:79-83).
        for s in &secrets {
            if let Some(envelope) = s.envelope {
                g.envelope.spans += 1;
                g.envelope.bytes += (envelope.end - envelope.start) - (s.end - s.start);
            }
        }
        g.positives += 1;
        let lenient = span_outcomes.iter().all(|o| !is_leaked(*o));
        let strict = span_outcomes.iter().all(|o| is_acceptable(*o));
        for twin in twins_for
            .get(&case.case_id)
            .map(Vec::as_slice)
            .unwrap_or(&[])
        {
            let CaseMeasurement::Control {
                flagged,
                co_detected,
                ..
            } = &twin.measurement
            else {
                return Err(inconsistent(twin, "twin is not a control"));
            };
            g.pairs += 1;
            if lenient && !flagged {
                g.discriminated_lenient += 1;
            }
            if strict && !flagged {
                g.discriminated_strict += 1;
            }
            if *co_detected {
                g.co_detected += 1;
            }
        }
    }
    // The twin denominator is the positive population (lattice.ts:178-180).
    let counted: u64 = groups
        .values()
        .map(|g| match g {
            GroupCounts::Positive(p) => p.positives,
            _ => 0,
        })
        .sum();
    if counted != positive_population {
        return Err(KernelError::TwinDenominator);
    }
    Ok(groups)
}

/// T0 cases by the kind their evidence proposes (`accounting.ts:69-70`).
pub(crate) fn pending_by_kind(cases: &[&CaseResult]) -> BTreeMap<String, u64> {
    let mut pending = BTreeMap::new();
    for case in cases.iter().filter(|c| c.tier == EvidenceTier::T0) {
        *pending.entry(case.kind.as_str().to_owned()).or_insert(0) += 1;
    }
    pending
}

/// Whether a positive group's measurable share meets its kind's floor
/// (`accounting.ts:97`).
pub(crate) fn is_measurable(
    files: u64,
    pending: u64,
    kind: &str,
    config: &AccountingConfig,
) -> bool {
    files as f64 / (files + pending) as f64 >= config.measurable_share_floor.for_key(kind)
}

/// v1.1 group accounting (`evaluation/domains/credential/accounting.ts:65-115`).
///
/// `cases` are one complete scanner's case results. Counts are those of the
/// v1.0 aggregation except `twins.discriminated`, which is strict: an
/// `OVERBROAD` positive has not demonstrated discrimination.
pub fn account_groups(
    cases: &[CaseResult],
    config: &AccountingConfig,
) -> Result<BTreeMap<String, GroupAggregate>, KernelError> {
    let refs: Vec<&CaseResult> = cases.iter().collect();
    account_group_refs(&refs, config)
}

pub(crate) fn account_group_refs(
    cases: &[&CaseResult],
    config: &AccountingConfig,
) -> Result<BTreeMap<String, GroupAggregate>, KernelError> {
    let counts = group_counts(cases)?;
    let pending = pending_by_kind(cases);
    let mut groups = BTreeMap::new();
    for (key, g) in counts {
        let aggregate = match g {
            GroupCounts::Pending { files } => GroupAggregate::Pending {
                files,
                candidate_kinds: pending.clone(),
            },
            GroupCounts::Control {
                files,
                flagged_files,
                findings,
                fp,
                tn,
            } => GroupAggregate::Control {
                files,
                flagged_files,
                findings,
                false_alarm_rate: proportion(
                    flagged_files,
                    files,
                    BoundDirection::Upper,
                    config,
                    None,
                ),
                mean_findings_per_flagged: ratio(findings, flagged_files, config, Some(files)),
                diagnostics: ControlDiagnostics { fp, tn },
            },
            GroupCounts::Positive(g) => {
                let kind = key.split('/').next().unwrap_or("");
                let pending_files = pending.get(kind).copied().unwrap_or(0);
                let measurable_share = proportion(
                    g.files,
                    g.files + pending_files,
                    BoundDirection::Lower,
                    config,
                    None,
                );
                let measurable = is_measurable(g.files, pending_files, kind, config);
                let withheld = |rate: Option<Published>| {
                    if measurable {
                        rate
                    } else {
                        Some(Published::Withheld(Withheld::InsufficientEvidence))
                    }
                };
                let coverage =
                    proportion(g.pairs, g.positives, BoundDirection::Lower, config, None);
                let covered = g.positives > 0
                    && g.pairs as f64 / g.positives as f64
                        >= config.twin_coverage_floor.for_key(kind);
                let rate = if g.pairs == 0 {
                    None
                } else if !measurable {
                    Some(Published::Withheld(Withheld::InsufficientEvidence))
                } else if !covered {
                    Some(Published::Withheld(Withheld::InsufficientCoverage))
                } else {
                    proportion(
                        g.discriminated_strict,
                        g.pairs,
                        BoundDirection::Lower,
                        config,
                        None,
                    )
                };
                GroupAggregate::Positive {
                    files: g.files,
                    spans: g.spans,
                    secret_bytes: g.secret_bytes,
                    outcomes: g.outcomes,
                    pending_files,
                    measurable_share,
                    envelope_width: g.envelope,
                    leaked_spans: g.leaked_spans,
                    leaked_span_rate: withheld(proportion(
                        g.leaked_spans,
                        g.spans,
                        BoundDirection::Upper,
                        config,
                        None,
                    )),
                    leaked_bytes: g.leaked_bytes,
                    leaked_byte_rate: withheld(proportion(
                        g.leaked_bytes,
                        g.secret_bytes,
                        BoundDirection::Upper,
                        config,
                        Some(g.spans),
                    )),
                    collateral_bytes: g.collateral_bytes,
                    collateral_ratio: withheld(ratio(
                        g.collateral_bytes,
                        g.secret_bytes,
                        config,
                        Some(g.spans),
                    )),
                    twins: TwinMeasurement {
                        positives: g.positives,
                        pairs: g.pairs,
                        discriminated: g.discriminated_strict,
                        co_detected: g.co_detected,
                        coverage,
                        rate,
                    },
                    diagnostics: PositiveDiagnostics {
                        tp: g.tp,
                        fp: g.fp,
                        fn_: g.fn_,
                    },
                }
            }
        };
        groups.insert(key, aggregate);
    }
    Ok(groups)
}

/// A case result tagged with the suite (corpus group / category) it came from.
#[derive(Debug, Clone, Copy)]
pub struct SuiteCase<'a> {
    /// Suite (legacy category; `Case.grouping.group`).
    pub suite: &'a str,
    /// The case result. Ids must be unique across suites.
    pub case: &'a CaseResult,
}

/// Groups of a selection of cases for one scanner, accounted over the suites
/// that hold each group (legacy `selectionGroups`,
/// `evaluation/domains/credential/run-summary.ts:39-50`).
///
/// Within those suites a selected positive's twin and the selection's T0
/// cases travel with the group. T0 cases held only by other suites do not
/// consume this group's measurable share.
pub fn selection_groups(
    all: &[SuiteCase<'_>],
    selected: &BTreeSet<CaseId>,
    config: &AccountingConfig,
) -> Result<BTreeMap<String, GroupAggregate>, KernelError> {
    let mine: Vec<&SuiteCase<'_>> = all
        .iter()
        .filter(|r| selected.contains(&r.case.case_id))
        .collect();
    let pending: BTreeSet<&CaseId> = mine
        .iter()
        .filter(|r| r.case.tier == EvidenceTier::T0)
        .map(|r| &r.case.case_id)
        .collect();
    let keys: BTreeSet<String> = mine
        .iter()
        .map(|r| group_key(r.case.kind, r.case.tier))
        .collect();
    let mut groups = BTreeMap::new();
    for key in keys {
        let members: Vec<&&SuiteCase<'_>> = mine
            .iter()
            .filter(|r| group_key(r.case.kind, r.case.tier) == key)
            .collect();
        let own: BTreeSet<&CaseId> = members.iter().map(|r| &r.case.case_id).collect();
        let suites: BTreeSet<&str> = members.iter().map(|r| r.suite).collect();
        let pool: Vec<&CaseResult> = all
            .iter()
            .filter(|r| {
                suites.contains(r.suite)
                    && (own.contains(&r.case.case_id)
                        || pending.contains(&r.case.case_id)
                        || r.case.twin_of.as_ref().is_some_and(|t| own.contains(t)))
            })
            .map(|r| r.case)
            .collect();
        if let Some(group) = account_group_refs(&pool, config)?.remove(&key) {
            groups.insert(key, group);
        }
    }
    Ok(groups)
}

/// Cross-suite groups for one scanner (legacy `summarizeRun`,
/// `run-summary.ts:52-77`): `overall` accounts every assigned case, and
/// `by_target` accounts each target's cases. Targets with no groups are omitted.
pub fn summarize_selections(
    all: &[SuiteCase<'_>],
    assignments: &BTreeMap<CaseId, Vec<String>>,
    config: &AccountingConfig,
) -> Result<SelectionSummary, KernelError> {
    let everything: BTreeSet<CaseId> = assignments.keys().cloned().collect();
    let overall = selection_groups(all, &everything, config)?;
    let targets: BTreeSet<&String> = assignments.values().flatten().collect();
    let mut by_target = BTreeMap::new();
    for target in targets {
        let selected: BTreeSet<CaseId> = assignments
            .iter()
            .filter(|(_, ts)| ts.contains(target))
            .map(|(id, _)| id.clone())
            .collect();
        let groups = selection_groups(all, &selected, config)?;
        if !groups.is_empty() {
            by_target.insert(target.clone(), groups);
        }
    }
    Ok(SelectionSummary { overall, by_target })
}

/// Output of [`summarize_selections`] for one scanner.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct SelectionSummary {
    /// Groups over every assigned case.
    pub overall: BTreeMap<String, GroupAggregate>,
    /// Groups per target (legacy `byDetector`).
    pub by_target: BTreeMap<String, BTreeMap<String, GroupAggregate>>,
}
