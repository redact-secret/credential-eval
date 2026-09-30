//! Property tests for the protocol invariants: lattice, union/sweep,
//! accounting reconciliation, order independence and determinism.

use std::collections::BTreeMap;

use credential_eval_contracts::artifact::{
    BoundDirection, CaseMeasurement, CaseResult, GroupAggregate, ObservedRange, Outcome, Published,
    ScoredSpan,
};
use credential_eval_contracts::config::{AccountingConfig, Floor};
use credential_eval_contracts::corpus::{CaseKind, EvidenceTier, SpanRole};
use credential_eval_contracts::ids::{CaseId, FixturePath};
use credential_eval_contracts::range::ByteRange;
use credential_eval_kernel::accounting::{account_groups, proportion};
use credential_eval_kernel::jsnum::round_to_fixed;
use credential_eval_kernel::lattice::{bytes_outside, is_leaked, score_row, span_outcome, union};
use proptest::prelude::*;

fn range() -> impl Strategy<Value = ByteRange> {
    (0_u64..60, 1_u64..20).prop_map(|(s, w)| ByteRange::new(s, s + w))
}

fn covered_bytes(ranges: &[ByteRange]) -> std::collections::BTreeSet<u64> {
    ranges.iter().flat_map(|r| r.start..r.end).collect()
}

fn rank(o: Outcome) -> usize {
    Outcome::ALL.iter().position(|x| *x == o).unwrap()
}

fn config(min: u32, precision: u32) -> AccountingConfig {
    AccountingConfig {
        min_denominator: min,
        resolved_rate_floor: Floor::Uniform(0.9),
        measurable_share_floor: Floor::Uniform(0.5),
        twin_coverage_floor: Floor::Uniform(0.3),
        replays: 2,
        interval_z: 1.96,
        interval_precision: precision,
    }
}

/// Disjoint sorted spans in `[0, 100)` with optional envelopes.
fn spans() -> impl Strategy<Value = Vec<ScoredSpan>> {
    prop::collection::vec(
        (
            1_u64..6,
            1_u64..8,
            any::<bool>(),
            0_u64..3,
            0_u64..3,
            any::<bool>(),
        ),
        0..4,
    )
    .prop_map(|parts| {
        let mut cursor = 0;
        let mut out = Vec::new();
        for (gap, width, secret, left, right, envelope) in parts {
            let start = cursor + gap + 3;
            let end = start + width;
            cursor = end + 3;
            out.push(ScoredSpan {
                start,
                end,
                role: if secret {
                    SpanRole::Secret
                } else {
                    SpanRole::Companion
                },
                envelope: envelope.then(|| ByteRange::new(start - left, end + right)),
            });
        }
        out
    })
}

fn findings() -> impl Strategy<Value = Vec<ObservedRange>> {
    prop::collection::vec((range(), prop::option::of(0_u8..3)), 0..6).prop_map(|v| {
        let mut unique: BTreeMap<(u64, u64), ObservedRange> = BTreeMap::new();
        for (r, f) in v {
            unique.insert(
                (r.start, r.end),
                ObservedRange {
                    start: r.start,
                    end: r.end,
                    family: f.map(|x| format!("fam-{x}")),
                    action: None,
                },
            );
        }
        unique.into_values().collect()
    })
}

proptest! {
    #[test]
    fn union_is_sorted_disjoint_and_exact(ranges in prop::collection::vec(range(), 0..10)) {
        let merged = union(&ranges);
        for w in merged.windows(2) {
            prop_assert!(w[0].end < w[1].start, "touching or overlapping output");
        }
        prop_assert_eq!(covered_bytes(&merged), covered_bytes(&ranges));
        let mut reversed = ranges.clone();
        reversed.reverse();
        prop_assert_eq!(union(&reversed), merged);
    }

    #[test]
    fn bytes_outside_is_set_difference(a in prop::collection::vec(range(), 0..8), c in prop::collection::vec(range(), 0..8)) {
        let expected = covered_bytes(&a).difference(&covered_bytes(&c)).count() as u64;
        prop_assert_eq!(bytes_outside(&a, &c), expected);
        prop_assert_eq!(bytes_outside(&a, &a), 0);
    }

    #[test]
    fn adding_a_finding_never_worsens_an_outcome(
        span in range(), left in 0_u64..4, right in 0_u64..4,
        base in prop::collection::vec(range(), 0..6), extra in range(),
    ) {
        let envelope = Some(ByteRange::new(span.start.saturating_sub(left), span.end + right));
        let before = span_outcome(span, envelope, &base);
        let mut more = base.clone();
        more.push(extra);
        let after = span_outcome(span, envelope, &more);
        prop_assert!(rank(after) <= rank(before), "{before:?} -> {after:?}");
        // Widening the envelope never worsens an outcome either.
        let wider = Some(ByteRange::new(span.start.saturating_sub(left + 1), span.end + right + 1));
        prop_assert!(rank(span_outcome(span, wider, &base)) <= rank(before));
    }

    #[test]
    fn score_row_is_order_independent_and_consistent(expected in spans(), actual in findings(), scoped in any::<bool>()) {
        let scope = scoped.then_some("fam-1");
        let a = score_row(&expected, &actual, scope);
        let mut reversed = actual.clone();
        reversed.reverse();
        prop_assert_eq!(&score_row(&expected, &reversed, scope), &a);
        match a {
            CaseMeasurement::Positive { span_outcomes, leaked_bytes, collateral_bytes } => {
                let secrets: Vec<&ScoredSpan> = expected.iter().filter(|e| e.role == SpanRole::Secret).collect();
                prop_assert_eq!(span_outcomes.len(), secrets.len());
                let secret_bytes: u64 = secrets.iter().map(|e| e.end - e.start).sum();
                prop_assert!(leaked_bytes <= secret_bytes);
                // Leaked bytes only come from leaking spans. (A PARTIAL span can
                // leak zero bytes when overlapping findings jointly cover it.)
                if leaked_bytes > 0 {
                    prop_assert!(span_outcomes.iter().any(|o| is_leaked(*o)));
                }
                let missed: u64 = secrets.iter().zip(&span_outcomes)
                    .filter(|(_, o)| **o == Outcome::Miss).map(|(e, _)| e.end - e.start).sum();
                prop_assert!(leaked_bytes >= missed);
                let finding_bytes = covered_bytes(&actual.iter().map(|r| ByteRange::new(r.start, r.end)).collect::<Vec<_>>()).len() as u64;
                prop_assert!(collateral_bytes <= finding_bytes);
            }
            CaseMeasurement::Control { flagged, findings, co_detected, .. } => {
                prop_assert_eq!(findings, actual.len() as u64);
                if scope.is_none() {
                    prop_assert_eq!(flagged, !actual.is_empty());
                    prop_assert!(!co_detected);
                }
                if actual.is_empty() {
                    prop_assert!(!flagged && !co_detected);
                }
            }
            _ => prop_assert!(false, "unexpected measurement"),
        }
    }

    #[test]
    fn round_to_fixed_is_close_and_idempotent(v in 0.0_f64..1000.0, p in 1_u32..10) {
        let r = round_to_fixed(v, p);
        prop_assert!((r - v).abs() <= 0.5 * 10_f64.powi(-(p as i32)) + 1e-9);
        prop_assert_eq!(round_to_fixed(r, p), r);
    }

    #[test]
    fn bounds_are_pessimistic(num in 0_u64..50, extra in 0_u64..50, min in 1_u32..6) {
        let den = num + extra;
        let c = config(min, 6);
        for (direction, pessimistic) in [(BoundDirection::Upper, true), (BoundDirection::Lower, false)] {
            match proportion(num, den, direction, &c, None) {
                None => prop_assert_eq!(den, 0),
                Some(Published::Withheld(_)) => prop_assert!(den < u64::from(min)),
                Some(Published::Rate(r)) => {
                    let bound = r.bound.unwrap();
                    prop_assert!((0.0..=1.0).contains(&bound));
                    if pessimistic { prop_assert!(bound >= r.point) } else { prop_assert!(bound <= r.point) }
                }
            }
        }
    }

    #[test]
    fn aggregates_reconcile_with_cases(cases in prop::collection::vec(case(), 1..25), seed in any::<u64>()) {
        let cases = with_ids(cases);
        let c = config(2, 6);
        let groups = account_groups(&cases, &c).expect("consistent cases");
        // Order independence.
        let mut shuffled = cases.clone();
        let len = shuffled.len();
        for i in 0..len {
            shuffled.swap(i, (seed as usize).wrapping_mul(31).wrapping_add(i * 7) % len);
        }
        prop_assert_eq!(&account_groups(&shuffled, &c).unwrap(), &groups);
        // Reconciliation with per-case measurements.
        let mut files = 0;
        let mut spans = 0;
        let mut leaked = 0;
        let mut control_findings = 0;
        for (key, g) in &groups {
            match g {
                GroupAggregate::Pending { files: f, candidate_kinds } => {
                    files += f;
                    prop_assert_eq!(candidate_kinds.values().sum::<u64>(), *f);
                }
                GroupAggregate::Control { files: f, flagged_files, findings, .. } => {
                    files += f;
                    prop_assert!(flagged_files <= f);
                    control_findings += findings;
                }
                GroupAggregate::Positive { files: f, spans: s, outcomes, leaked_bytes, secret_bytes, leaked_spans, twins, .. } => {
                    files += f;
                    spans += s;
                    leaked += leaked_bytes;
                    prop_assert_eq!(outcomes.total(), *s);
                    prop_assert_eq!(*leaked_spans, outcomes.partial + outcomes.miss);
                    prop_assert!(leaked_bytes <= secret_bytes);
                    prop_assert!(twins.discriminated <= twins.pairs);
                    prop_assert_eq!(twins.positives, *f, "{}", key);
                }
            }
        }
        prop_assert_eq!(files, cases.len() as u64);
        let (mut s2, mut l2, mut f2) = (0, 0, 0);
        for case in &cases {
            match &case.measurement {
                CaseMeasurement::Positive { span_outcomes, leaked_bytes, .. } => { s2 += span_outcomes.len() as u64; l2 += leaked_bytes; }
                CaseMeasurement::Control { findings, .. } if case.tier != EvidenceTier::T0 => f2 += findings,
                _ => {}
            }
        }
        prop_assert_eq!(spans, s2);
        prop_assert_eq!(leaked, l2);
        prop_assert_eq!(control_findings, f2);
    }
}

/// A case consistent with its population.
fn case() -> impl Strategy<Value = CaseResult> {
    (
        0_u8..3,
        0_u8..4,
        spans(),
        findings(),
        prop::option::of(0_usize..30),
    )
        .prop_map(|(k, t, spans, actual, twin)| {
            let kind = [
                CaseKind::MustRedact,
                CaseKind::MustNotFlag,
                CaseKind::Policy,
            ][k as usize];
            let tier = [
                EvidenceTier::T0,
                EvidenceTier::T1,
                EvidenceTier::T2,
                EvidenceTier::T3,
            ][t as usize];
            let mut expected = if kind == CaseKind::MustNotFlag {
                Vec::new()
            } else {
                spans
            };
            if kind != CaseKind::MustNotFlag && !expected.iter().any(|e| e.role == SpanRole::Secret)
            {
                expected.push(ScoredSpan {
                    start: 200,
                    end: 210,
                    role: SpanRole::Secret,
                    envelope: None,
                });
            }
            let measurement = if tier == EvidenceTier::T0 {
                CaseMeasurement::Pending
            } else {
                score_row(&expected, &actual, twin.map(|_| "fam-1"))
            };
            CaseResult {
                case_id: CaseId::new("placeholder").unwrap(),
                path: FixturePath::new("p.txt").unwrap(),
                kind,
                tier,
                family: None,
                twin_of: twin
                    .filter(|_| kind == CaseKind::MustNotFlag)
                    .map(|i| CaseId::new(format!("c{i}")).unwrap()),
                group: "g".into(),
                targets: vec![],
                taxonomy: None,
                evidence_class: None,
                twin_mutation_kind: None,
                expected,
                actual,
                measurement,
            }
        })
}

fn with_ids(mut cases: Vec<CaseResult>) -> Vec<CaseResult> {
    for (i, c) in cases.iter_mut().enumerate() {
        c.case_id = CaseId::new(format!("c{i}")).unwrap();
        c.path = FixturePath::new(format!("c{i}.txt")).unwrap();
        if c.twin_of.as_ref().is_some_and(|t| t == &c.case_id) {
            c.twin_of = None;
        }
    }
    cases
}
