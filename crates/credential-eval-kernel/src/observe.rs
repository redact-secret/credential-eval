//! Pure observation helpers for adapters and run orchestration.
//!
//! These are the measurement rules of the legacy runtime
//! (`evaluation/substrate/runtime.ts`) and finding normalization
//! (`evaluation/domains/credential/normalization.ts`) without any I/O, so the
//! CLI can execute scanners however it schedules them and still reach the
//! same verdicts.

use std::collections::BTreeSet;

use credential_eval_contracts::ids::FixturePath;
use credential_eval_contracts::observation::{
    NormalizedFinding, ObservationResult, ObservationSet,
};

/// Replay agreement verdict.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReplayVerdict {
    /// Every replay produced the same set of normalized findings.
    Agreed,
    /// Replays disagreed on these paths (sorted, unique).
    Diverged(Vec<FixturePath>),
}

/// Compare stability replays (`runtime.ts:95-105`).
///
/// Each replay is reduced to the **set** of complete normalized findings
/// (path, range, family, action); every later replay is compared with the
/// first, and the paths of findings in the symmetric difference diverge.
/// Legacy `eval` compares complete findings while `bench` compares ranges
/// only (`run.ts:150-152`); the kernel adopts the stricter `eval` rule.
pub fn compare_replays(replays: &[Vec<NormalizedFinding>]) -> ReplayVerdict {
    let Some((first, rest)) = replays.split_first() else {
        return ReplayVerdict::Agreed;
    };
    let first: BTreeSet<&NormalizedFinding> = first.iter().collect();
    let mut divergent: BTreeSet<FixturePath> = BTreeSet::new();
    for other in rest {
        let other: BTreeSet<&NormalizedFinding> = other.iter().collect();
        for f in first.symmetric_difference(&other) {
            divergent.insert(f.path.clone());
        }
    }
    if divergent.is_empty() {
        ReplayVerdict::Agreed
    } else {
        ReplayVerdict::Diverged(divergent.into_iter().collect())
    }
}

/// Keep a finding's family only when classification is supported and the
/// family is in `allowlist` (`normalization.ts:5-9`, the `eval` pipeline
/// rule). Actions pass through unchanged. `bench` applies no allowlist; pass
/// `None` for that behavior.
pub fn restrict_family(
    finding: NormalizedFinding,
    classification: bool,
    allowlist: Option<&BTreeSet<String>>,
) -> NormalizedFinding {
    let keep = |family: &String| {
        classification && !family.is_empty() && allowlist.is_none_or(|a| a.contains(family))
    };
    NormalizedFinding {
        family: finding.family.filter(keep),
        ..finding
    }
}

/// Apply [`restrict_family`] to every finding of every complete observation
/// (the legacy `eval` rule applies it at observation time, `runtime.ts:88-94`).
/// Every adapter here reports classifications, so `classification` is `true`.
/// Order and every other field are kept.
pub fn restrict_observations(set: &ObservationSet, allowlist: &BTreeSet<String>) -> ObservationSet {
    let mut out = set.clone();
    for observation in &mut out.observations {
        if let ObservationResult::Complete { findings, .. } = &mut observation.result {
            for finding in findings.iter_mut() {
                *finding = restrict_family(finding.clone(), true, Some(allowlist));
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn f(path: &str, start: u64, family: Option<&str>) -> NormalizedFinding {
        NormalizedFinding {
            path: FixturePath::new(path).unwrap(),
            start,
            end: start + 1,
            family: family.map(str::to_owned),
            action: None,
            mapping: None,
        }
    }

    #[test]
    fn replays_are_set_compared() {
        let a = vec![f("a.txt", 0, None), f("a.txt", 0, None)];
        let b = vec![f("a.txt", 0, None)];
        assert_eq!(compare_replays(&[a.clone(), b]), ReplayVerdict::Agreed);
        let c = vec![f("a.txt", 0, Some("x")), f("b.txt", 1, None)];
        assert_eq!(
            compare_replays(&[a, c]),
            ReplayVerdict::Diverged(vec![
                FixturePath::new("a.txt").unwrap(),
                FixturePath::new("b.txt").unwrap()
            ])
        );
    }

    #[test]
    fn families_outside_the_allowlist_are_dropped() {
        let allow = BTreeSet::from(["x".to_owned()]);
        assert_eq!(
            restrict_family(f("a.txt", 0, Some("x")), true, Some(&allow))
                .family
                .as_deref(),
            Some("x")
        );
        assert_eq!(
            restrict_family(f("a.txt", 0, Some("y")), true, Some(&allow)).family,
            None
        );
        assert_eq!(
            restrict_family(f("a.txt", 0, Some("x")), false, Some(&allow)).family,
            None
        );
        assert_eq!(
            restrict_family(f("a.txt", 0, Some("y")), true, None)
                .family
                .as_deref(),
            Some("y")
        );
    }
}
