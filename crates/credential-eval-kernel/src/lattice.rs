//! Span outcome lattice and row scorer.
//!
//! Exact port of the legacy measurement-v4 lattice
//! (`benchmarks/lib/lattice.ts:10-97` at the pinned legacy commit). Pure
//! integer interval arithmetic over half-open UTF-8 byte ranges. Any change to
//! the behavior of this module is a protocol revision, not a refactor.

use std::collections::BTreeMap;

use credential_eval_contracts::artifact::{CaseMeasurement, ObservedRange, Outcome, ScoredSpan};
use credential_eval_contracts::corpus::SpanRole;
use credential_eval_contracts::range::ByteRange;

/// `a` and `b` share at least one byte (`lattice.ts:10`).
pub const fn overlaps(a: ByteRange, b: ByteRange) -> bool {
    a.start < b.end && b.start < a.end
}

/// `outer` contains `inner` (`lattice.ts:11`).
pub const fn contains(outer: ByteRange, inner: ByteRange) -> bool {
    outer.start <= inner.start && outer.end >= inner.end
}

/// Merge ranges into a sorted list of disjoint intervals. Touching ranges
/// merge (`lattice.ts:15-24`).
pub fn union(ranges: &[ByteRange]) -> Vec<ByteRange> {
    let mut sorted = ranges.to_vec();
    sorted.sort_by(|a, b| a.start.cmp(&b.start).then(a.end.cmp(&b.end)));
    let mut merged: Vec<ByteRange> = Vec::with_capacity(sorted.len());
    for r in sorted {
        match merged.last_mut() {
            Some(last) if r.start <= last.end => last.end = last.end.max(r.end),
            _ => merged.push(r),
        }
    }
    merged
}

/// Bytes of `ranges` that fall outside the union of `cover` (`lattice.ts:27-41`).
pub fn bytes_outside(ranges: &[ByteRange], cover: &[ByteRange]) -> u64 {
    let kept = union(cover);
    let mut total = 0;
    for r in union(ranges) {
        let mut cursor = r.start;
        for c in &kept {
            if c.end <= cursor {
                continue;
            }
            if c.start >= r.end {
                break;
            }
            if c.start > cursor {
                total += c.start - cursor;
            }
            cursor = cursor.max(c.end);
        }
        if cursor < r.end {
            total += r.end - cursor;
        }
    }
    total
}

/// Outcome of one secret span against the deduplicated findings on its file
/// (`lattice.ts:44-50`). `envelope` defaults to the span itself.
pub fn span_outcome(
    span: ByteRange,
    envelope: Option<ByteRange>,
    findings: &[ByteRange],
) -> Outcome {
    let envelope = envelope.unwrap_or(span);
    if findings.contains(&span) {
        return Outcome::Exact;
    }
    let mut covering = findings.iter().filter(|f| contains(**f, span)).peekable();
    if covering.peek().is_some() {
        return if covering.any(|f| contains(envelope, *f)) {
            Outcome::Covered
        } else {
            Outcome::Overbroad
        };
    }
    if findings.iter().any(|f| overlaps(*f, span)) {
        Outcome::Partial
    } else {
        Outcome::Miss
    }
}

/// PARTIAL and MISS leak secret bytes (`lattice.ts:52`).
pub const fn is_leaked(outcome: Outcome) -> bool {
    matches!(outcome, Outcome::Partial | Outcome::Miss)
}

/// Leak-axis complement only: true for EXACT, COVERED and OVERBROAD
/// (`lattice.ts:58`). Not an acceptability predicate; see [`is_acceptable`].
pub const fn is_covered(outcome: Outcome) -> bool {
    !is_leaked(outcome)
}

/// Acceptable outcomes: EXACT or COVERED (engine v1.1 §3;
/// `evaluation/domains/credential/accounting.ts:58`).
pub const fn is_acceptable(outcome: Outcome) -> bool {
    matches!(outcome, Outcome::Exact | Outcome::Covered)
}

/// Score one case's deduplicated findings (`lattice.ts:76-97`).
///
/// Cases without a secret span are controls and only count findings. When
/// `scope_family` is given (a twin with a declared family), a finding
/// attributed to a *different*, known family is co-detection rather than a
/// flag; a finding with no family still flags (fails closed).
pub fn score_row(
    expected: &[ScoredSpan],
    actual: &[ObservedRange],
    scope_family: Option<&str>,
) -> CaseMeasurement {
    let secrets: Vec<&ScoredSpan> = expected
        .iter()
        .filter(|e| e.role == SpanRole::Secret)
        .collect();
    let ranges: Vec<ByteRange> = actual
        .iter()
        .map(|a| ByteRange::new(a.start, a.end))
        .collect();
    if secrets.is_empty() {
        let mut action_counts = BTreeMap::new();
        for action in actual.iter().filter_map(|a| a.action.as_ref()) {
            *action_counts.entry(action.clone()).or_insert(0) += 1;
        }
        let findings = actual.len() as u64;
        return match scope_family {
            Some(scope) => {
                let other = actual
                    .iter()
                    .filter(|a| a.family.as_deref().is_some_and(|family| family != scope))
                    .count();
                CaseMeasurement::Control {
                    flagged: other < actual.len(),
                    findings,
                    co_detected: other > 0,
                    action_counts,
                }
            }
            None => CaseMeasurement::Control {
                flagged: !actual.is_empty(),
                findings,
                co_detected: false,
                action_counts,
            },
        };
    }
    let span_outcomes: Vec<Outcome> = secrets
        .iter()
        .map(|e| span_outcome(ByteRange::new(e.start, e.end), e.envelope, &ranges))
        .collect();
    let leaked_bytes = secrets
        .iter()
        .zip(&span_outcomes)
        .filter(|(_, outcome)| is_leaked(**outcome))
        .map(|(e, _)| bytes_outside(&[ByteRange::new(e.start, e.end)], &ranges))
        .sum();
    let acceptable: Vec<ByteRange> = expected
        .iter()
        .map(|e| e.envelope.unwrap_or(ByteRange::new(e.start, e.end)))
        .collect();
    CaseMeasurement::Positive {
        span_outcomes,
        leaked_bytes,
        collateral_bytes: bytes_outside(&ranges, &acceptable),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const fn r(start: u64, end: u64) -> ByteRange {
        ByteRange::new(start, end)
    }

    fn secret(start: u64, end: u64, envelope: Option<ByteRange>) -> ScoredSpan {
        ScoredSpan {
            start,
            end,
            role: SpanRole::Secret,
            envelope,
        }
    }

    fn found(start: u64, end: u64, family: Option<&str>) -> ObservedRange {
        ObservedRange {
            start,
            end,
            family: family.map(str::to_owned),
            action: None,
            mapping: None,
            native_labels: Vec::new(),
        }
    }

    #[test]
    fn lattice_outcomes() {
        let span = r(10, 20);
        let envelope = Some(r(5, 25));
        assert_eq!(span_outcome(span, envelope, &[r(10, 20)]), Outcome::Exact);
        assert_eq!(span_outcome(span, envelope, &[r(8, 22)]), Outcome::Covered);
        assert_eq!(span_outcome(span, envelope, &[r(5, 25)]), Outcome::Covered);
        assert_eq!(
            span_outcome(span, envelope, &[r(4, 25)]),
            Outcome::Overbroad
        );
        // Without an envelope any strictly wider finding is overbroad.
        assert_eq!(span_outcome(span, None, &[r(9, 20)]), Outcome::Overbroad);
        // One covering finding inside the envelope suffices.
        assert_eq!(
            span_outcome(span, envelope, &[r(0, 30), r(9, 21)]),
            Outcome::Covered
        );
        assert_eq!(span_outcome(span, envelope, &[r(12, 30)]), Outcome::Partial);
        // Half-open: touching is not overlapping.
        assert_eq!(
            span_outcome(span, envelope, &[r(20, 30), r(0, 10)]),
            Outcome::Miss
        );
        assert_eq!(span_outcome(span, envelope, &[]), Outcome::Miss);
    }

    #[test]
    fn union_merges_touching() {
        assert_eq!(
            union(&[r(5, 8), r(0, 5), r(10, 12)]),
            vec![r(0, 8), r(10, 12)]
        );
    }

    #[test]
    fn bytes_outside_counts_uncovered() {
        assert_eq!(bytes_outside(&[r(0, 10)], &[r(2, 4), r(6, 8)]), 6);
        assert_eq!(bytes_outside(&[r(0, 10)], &[]), 10);
        assert_eq!(bytes_outside(&[r(0, 10), r(5, 15)], &[r(0, 15)]), 0);
    }

    #[test]
    fn positive_row() {
        let expected = [secret(10, 20, None)];
        let measurement = score_row(&expected, &[found(12, 25, None)], None);
        assert_eq!(
            measurement,
            CaseMeasurement::Positive {
                span_outcomes: vec![Outcome::Partial],
                leaked_bytes: 2,
                collateral_bytes: 5,
            }
        );
    }

    #[test]
    fn companion_is_acceptable_coverage() {
        let expected = [
            ScoredSpan {
                start: 0,
                end: 4,
                role: SpanRole::Companion,
                envelope: None,
            },
            secret(5, 9, None),
        ];
        let measurement = score_row(&expected, &[found(0, 4, None), found(5, 9, None)], None);
        assert_eq!(
            measurement,
            CaseMeasurement::Positive {
                span_outcomes: vec![Outcome::Exact],
                leaked_bytes: 0,
                collateral_bytes: 0,
            }
        );
    }

    #[test]
    fn scoped_twin_control() {
        // A different known family is co-detection, not a flag.
        let m = score_row(&[], &[found(0, 3, Some("other"))], Some("mine"));
        assert!(matches!(
            m,
            CaseMeasurement::Control {
                flagged: false,
                co_detected: true,
                ..
            }
        ));
        // Unattributed findings fail closed.
        let m = score_row(&[], &[found(0, 3, None)], Some("mine"));
        assert!(matches!(
            m,
            CaseMeasurement::Control {
                flagged: true,
                co_detected: false,
                ..
            }
        ));
        // Unscoped controls flag on any finding.
        let m = score_row(&[], &[found(0, 3, Some("other"))], None);
        assert!(matches!(m, CaseMeasurement::Control { flagged: true, .. }));
    }
}
