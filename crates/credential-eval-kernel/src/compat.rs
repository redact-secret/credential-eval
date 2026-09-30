//! Legacy-compatibility views (isolated and removable).
//!
//! Nothing in the canonical kernel depends on this module. It reproduces
//! legacy-only figures and labels so issue #5 can prove parity against the
//! TypeScript oracle at `redact-secret-benchmarks@c403475`:
//!
//! * the frozen v1.0 group aggregation (`aggregateGroups`,
//!   `benchmarks/lib/lattice.ts:113-182`), which the canonical artifact does
//!   not publish;
//! * the dual-scorer transition record `accountingDelta`
//!   (`evaluation/domains/credential/accounting.ts:124-153`) and its assertion
//!   counterpart (`execution.ts:44-60`);
//! * `encodeOutcome` baselines (`lattice.ts:185-190`);
//! * legacy status and disagreement labels, and the legacy variant seed
//!   convention (`cases.ts:73`).
//!
//! Delete this module once the migration is complete.

use std::collections::{BTreeMap, BTreeSet};

use credential_eval_contracts::artifact::{CaseMeasurement, CaseResult, Disagreement, Published};
use credential_eval_contracts::config::AccountingConfig;
use credential_eval_contracts::corpus::Case;
use credential_eval_contracts::observation::ScannerStatus;
use serde::Serialize;

use crate::KernelError;
use crate::accounting::{GroupCounts, StatusCounts, account_counts, account_groups, group_counts};
use crate::jsnum::round_to_fixed;
use credential_eval_contracts::artifact::{AccountedCounts, GroupAggregate, Withheld};

/// A v1.0 figure: a raw rate or `null` (never withheld).
pub type V10Rate = Option<f64>;

/// One v1.0 group (legacy `Group`, `benchmarks/types.ts:45-52`). Rates are
/// unrounded `n / d` or `None` for a zero denominator.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(untagged)]
pub enum GroupV10 {
    /// `pending/T0`.
    Pending {
        /// T0 cases.
        files: u64,
    },
    /// `must-not-flag/*`.
    Control {
        /// Controls.
        files: u64,
        /// Flagged controls.
        flagged_files: u64,
        /// Findings on controls.
        findings: u64,
        /// flagged / files.
        false_alarm_rate: V10Rate,
        /// findings / flagged.
        mean_findings_per_flagged: V10Rate,
        /// Exact diagnostics `fp`.
        fp: u64,
        /// Exact diagnostics `tn`.
        tn: u64,
    },
    /// Positive groups.
    Positive {
        /// Scored cases.
        files: u64,
        /// Secret spans.
        spans: u64,
        /// Secret bytes.
        secret_bytes: u64,
        /// Outcome counts `[EXACT, COVERED, OVERBROAD, PARTIAL, MISS]`.
        outcomes: [u64; 5],
        /// Leaking spans.
        leaked_spans: u64,
        /// leaked_spans / spans.
        leaked_span_rate: V10Rate,
        /// Leaked bytes.
        leaked_bytes: u64,
        /// leaked_bytes / secret_bytes.
        leaked_byte_rate: V10Rate,
        /// Collateral bytes.
        collateral_bytes: u64,
        /// collateral_bytes / secret_bytes.
        collateral_ratio: V10Rate,
        /// Twin positives.
        positives: u64,
        /// Twin pairs.
        pairs: u64,
        /// Lenient (v1.0) discrimination: OVERBROAD counts.
        discriminated: u64,
        /// Co-detected twins.
        co_detected: u64,
        /// discriminated / pairs.
        twin_rate: V10Rate,
        /// Exact diagnostics.
        tp: u64,
        /// Exact diagnostics.
        fp: u64,
        /// Exact diagnostics.
        fn_: u64,
    },
}

fn rate(n: u64, d: u64) -> V10Rate {
    (d != 0).then(|| n as f64 / d as f64)
}

/// The frozen v1.0 aggregation (`lattice.ts:113-182`).
pub fn aggregate_groups_v10(
    cases: &[CaseResult],
) -> Result<BTreeMap<String, GroupV10>, KernelError> {
    let refs: Vec<&CaseResult> = cases.iter().collect();
    Ok(group_counts(&refs)?
        .into_iter()
        .map(|(key, g)| {
            let v = match g {
                GroupCounts::Pending { files } => GroupV10::Pending { files },
                GroupCounts::Control {
                    files,
                    flagged_files,
                    findings,
                    fp,
                    tn,
                } => GroupV10::Control {
                    files,
                    flagged_files,
                    findings,
                    false_alarm_rate: rate(flagged_files, files),
                    mean_findings_per_flagged: rate(findings, flagged_files),
                    fp,
                    tn,
                },
                GroupCounts::Positive(g) => GroupV10::Positive {
                    files: g.files,
                    spans: g.spans,
                    secret_bytes: g.secret_bytes,
                    outcomes: [
                        g.outcomes.exact,
                        g.outcomes.covered,
                        g.outcomes.overbroad,
                        g.outcomes.partial,
                        g.outcomes.miss,
                    ],
                    leaked_spans: g.leaked_spans,
                    leaked_span_rate: rate(g.leaked_spans, g.spans),
                    leaked_bytes: g.leaked_bytes,
                    leaked_byte_rate: rate(g.leaked_bytes, g.secret_bytes),
                    collateral_bytes: g.collateral_bytes,
                    collateral_ratio: rate(g.collateral_bytes, g.secret_bytes),
                    positives: g.positives,
                    pairs: g.pairs,
                    discriminated: g.discriminated_lenient,
                    co_detected: g.co_detected,
                    twin_rate: rate(g.discriminated_lenient, g.pairs),
                    tp: g.tp,
                    fp: g.fp,
                    fn_: g.fn_,
                },
            };
            (key, v)
        })
        .collect())
}

/// Why a figure moved between v1.0 and v1.1 (`benchmarks/types.ts:72`).
/// Variants are declared in wire-name order so sorted causes match legacy
/// `[...cause].sort()`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum DeltaCause {
    /// A small denominator withheld a figure.
    Interval,
    /// A scanner did not observe.
    NotMeasured,
    /// OVERBROAD positives no longer discriminate.
    OverbroadTwin,
    /// T0 share withheld the group.
    T0Share,
    /// Twin coverage below its floor.
    TwinCoverage,
    /// A method stratum left assertions unresolved.
    Unresolved,
    /// A scanner's replays disagreed.
    Unstable,
}

/// One group of the v1.0 → v1.1 delta.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct GroupDelta {
    /// v1.0 figures rounded to the interval precision, by legacy field name.
    pub v10: BTreeMap<String, V10Rate>,
    /// v1.1 published figures, by legacy field name.
    pub v11: BTreeMap<String, Option<Published>>,
    /// Causes, sorted.
    pub cause: Vec<DeltaCause>,
}

fn point_of(p: &Option<Published>) -> Option<f64> {
    match p {
        Some(Published::Rate(r)) => Some(r.point),
        _ => None,
    }
}

const IE: Option<Published> = Some(Published::Withheld(Withheld::InsufficientEvidence));

/// The dual-scorer transition record (`accounting.ts:124-153`), keyed by group.
pub fn accounting_delta(
    cases: &[CaseResult],
    config: &AccountingConfig,
) -> Result<BTreeMap<String, GroupDelta>, KernelError> {
    let v10 = aggregate_groups_v10(cases)?;
    let v11 = account_groups(cases, config)?;
    let p = config.interval_precision;
    let round = |r: V10Rate| r.map(|v| round_to_fixed(v, p));
    let mut groups = BTreeMap::new();
    for (key, before) in v10 {
        let after = &v11[&key];
        let mut old: BTreeMap<String, V10Rate> = BTreeMap::new();
        let mut next: BTreeMap<String, Option<Published>> = BTreeMap::new();
        let mut cause: BTreeSet<DeltaCause> = BTreeSet::new();
        match (&before, after) {
            (GroupV10::Pending { .. }, _) => continue,
            (
                GroupV10::Control {
                    false_alarm_rate,
                    mean_findings_per_flagged,
                    ..
                },
                GroupAggregate::Control {
                    false_alarm_rate: fa,
                    mean_findings_per_flagged: mf,
                    ..
                },
            ) => {
                old.insert("falseAlarmRate".into(), round(*false_alarm_rate));
                next.insert("falseAlarmRate".into(), fa.clone());
                old.insert(
                    "meanFindingsPerFlagged".into(),
                    round(*mean_findings_per_flagged),
                );
                next.insert("meanFindingsPerFlagged".into(), mf.clone());
            }
            (
                GroupV10::Positive {
                    leaked_span_rate,
                    leaked_byte_rate,
                    collateral_ratio,
                    discriminated,
                    twin_rate,
                    ..
                },
                GroupAggregate::Positive {
                    leaked_span_rate: ls,
                    leaked_byte_rate: lb,
                    collateral_ratio: cr,
                    measurable_share,
                    pending_files,
                    twins,
                    ..
                },
            ) => {
                old.insert("leakedSpanRate".into(), round(*leaked_span_rate));
                next.insert("leakedSpanRate".into(), ls.clone());
                old.insert("leakedByteRate".into(), round(*leaked_byte_rate));
                next.insert("leakedByteRate".into(), lb.clone());
                old.insert("collateralRatio".into(), round(*collateral_ratio));
                next.insert("collateralRatio".into(), cr.clone());
                old.insert("twins.rate".into(), round(*twin_rate));
                next.insert("twins.rate".into(), twins.rate.clone());
                next.insert("twins.coverage".into(), twins.coverage.clone());
                next.insert("measurableShare".into(), measurable_share.clone());
                if twins.discriminated != *discriminated {
                    cause.insert(DeltaCause::OverbroadTwin);
                }
                if twins.rate == Some(Published::Withheld(Withheld::InsufficientCoverage)) {
                    cause.insert(DeltaCause::TwinCoverage);
                }
                let kind = key.split('/').next().unwrap_or("");
                if *ls == IE
                    && *pending_files > 0
                    && point_of(measurable_share)
                        .is_some_and(|s| s < config.measurable_share_floor.for_key(kind))
                {
                    cause.insert(DeltaCause::T0Share);
                }
            }
            _ => {
                return Err(KernelError::InconsistentCase {
                    case: key,
                    reason: "v1.0 and v1.1 group populations differ",
                });
            }
        }
        for (k, v) in &old {
            if v.is_some() && next[k] == IE && !cause.contains(&DeltaCause::T0Share) {
                cause.insert(DeltaCause::Interval);
            }
        }
        for (k, v) in &old {
            if let Some(point) = point_of(&next[k]) {
                if Some(point) != *v && cause.is_empty() {
                    return Err(KernelError::UnattributedDelta(key));
                }
            }
        }
        groups.insert(
            key,
            GroupDelta {
                v10: old,
                v11: next,
                cause: cause.into_iter().collect(),
            },
        );
    }
    Ok(groups)
}

/// One stratum of the assertion delta (`execution.ts:44-60`).
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct AssertionGroupDelta {
    /// v1.0 counts (`not-measured` omitted).
    pub v10: StatusCounts,
    /// v1.1 accounted counts.
    pub v11: AccountedCounts,
    /// Causes, sorted.
    pub cause: Vec<DeltaCause>,
}

/// Assertion accounting delta: per `<kind>/<tier>` of the baseline stratum
/// (`execution.ts:44-60`). `unstable` lists scanners whose replays disagreed.
pub fn assertion_delta(
    by_method: &BTreeMap<String, StatusCounts>,
    unstable: &BTreeSet<String>,
    config: &AccountingConfig,
) -> BTreeMap<String, AssertionGroupDelta> {
    let mut totals: BTreeMap<String, StatusCounts> = BTreeMap::new();
    let mut causes: BTreeMap<String, BTreeSet<DeltaCause>> = BTreeMap::new();
    for (key, counts) in by_method {
        let parts: Vec<&str> = key.split('/').collect();
        let (method, scanner, stratum) = (parts[0], parts[1], parts[2]);
        let group = stratum
            .split("->")
            .next()
            .unwrap_or("")
            .replacen(':', "/", 1);
        let t = totals.entry(group.clone()).or_default();
        t.pass += counts.pass;
        t.fail += counts.fail;
        t.review_required += counts.review_required;
        t.not_measured += counts.not_measured;
        let c = causes.entry(group).or_default();
        if counts.review_required > 0 && config.resolved_rate_floor.for_key(method) > 0.0 {
            c.insert(DeltaCause::Unresolved);
        }
        if counts.not_measured > 0 {
            c.insert(if unstable.contains(scanner) {
                DeltaCause::Unstable
            } else {
                DeltaCause::NotMeasured
            });
        }
    }
    totals
        .into_iter()
        .map(|(group, t)| {
            let cause = causes
                .remove(&group)
                .unwrap_or_default()
                .into_iter()
                .collect();
            let v10 = StatusCounts {
                not_measured: 0,
                ..t
            };
            (
                group,
                AssertionGroupDelta {
                    v10,
                    v11: account_counts(&t, config),
                    cause,
                },
            )
        })
        .collect()
}

/// Compact baseline encoding of one case result (`lattice.ts:185-190`).
pub fn encode_outcome(case: &CaseResult) -> Option<String> {
    Some(match &case.measurement {
        CaseMeasurement::Positive { span_outcomes, .. } => span_outcomes
            .iter()
            .map(|o| match o {
                credential_eval_contracts::artifact::Outcome::Exact => "EXACT",
                credential_eval_contracts::artifact::Outcome::Covered => "COVERED",
                credential_eval_contracts::artifact::Outcome::Overbroad => "OVERBROAD",
                credential_eval_contracts::artifact::Outcome::Partial => "PARTIAL",
                credential_eval_contracts::artifact::Outcome::Miss => "MISS",
            })
            .collect::<Vec<_>>()
            .join(","),
        CaseMeasurement::Control {
            flagged, findings, ..
        } => {
            if *flagged {
                format!("flagged:{findings}")
            } else {
                "clean".to_owned()
            }
        }
        CaseMeasurement::Pending => format!("observed:{}", case.actual.len()),
        CaseMeasurement::NotMeasured { .. } => return None,
    })
}

/// Legacy scanner status label: `timeout` and `malformed` fold into `error`
/// (`scanners/index.mjs:54-58`).
pub const fn legacy_status(status: ScannerStatus) -> &'static str {
    match status {
        ScannerStatus::Complete => "complete",
        ScannerStatus::Unstable => "unstable",
        ScannerStatus::Unsupported => "unsupported",
        ScannerStatus::Unavailable => "unavailable",
        ScannerStatus::Timeout | ScannerStatus::Malformed | ScannerStatus::Error => "error",
    }
}

/// Legacy disagreement label. The legacy reference scanner was always
/// `redact-secret`, so `reference-only` maps back to `redact-secret-only`
/// (`methods/differential.ts:43`).
pub const fn legacy_disagreement(disagreement: Disagreement) -> &'static str {
    match disagreement {
        Disagreement::None => "none",
        Disagreement::ReferenceOnly => "redact-secret-only",
        Disagreement::PeerOnly => "peer-only",
        Disagreement::RangeDisagreement => "range-disagreement",
        Disagreement::ClassificationDisagreement => "classification-disagreement",
    }
}

/// Legacy variant seed `<category>/<fixtureId>` (`cases.ts:73`), recovered
/// from a migration snapshot whose case ids are `<category>--<fixtureId>`
/// and whose `grouping.group` is the category. Operators draw their seeded
/// choices from this string, so parity runs must use it.
pub fn legacy_seed(case: &Case) -> String {
    let group = &case.grouping.group;
    let id = case.id.as_str();
    let local = id
        .strip_prefix(group.as_str())
        .and_then(|rest| rest.strip_prefix("--"))
        .unwrap_or(id);
    format!("{group}/{local}")
}
