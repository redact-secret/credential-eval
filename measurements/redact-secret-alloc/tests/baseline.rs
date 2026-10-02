//! The beta.13 acceptance gate of issue #1121: the harness reproduces the
//! card's allocation-request baseline, per 1,000 assignments, on generated
//! synthetic fixtures through the public API of pinned core builds:
//!
//! | fixture    | before | after |
//! |------------|-------:|------:|
//! | ordinary   | 18,451 | 5,451 |
//! | diverse    | 18,459 | 4,274 |
//! | references | 12,155 | 1,054 |
//!
//! Counts are defined for optimized builds (the card's harness ran release;
//! debug builds do not elide the same temporaries), so the assertions run
//! under `cargo test --release` and the debug run only says so.
//! `harness = false`: the counters are process-wide.

use credential_eval_contracts::performance::WorkloadId;
use redact_secret_alloc::report::{comparisons, run};

fn main() {
    if cfg!(debug_assertions) {
        println!("baseline: skipped (allocation counts are defined for release builds)");
        return;
    }
    let card: Vec<_> = comparisons()
        .into_iter()
        .filter(|c| c.card == "card-1121")
        .collect();
    assert_eq!(card.len(), 1);
    let artifact = run(&card);
    let expected = [
        (WorkloadId::AssignmentsOrdinary, 18_451, 5_451),
        (WorkloadId::AssignmentsDiverse, 18_459, 4_274),
        (WorkloadId::AssignmentsReferences, 12_155, 1_054),
    ];
    assert_eq!(artifact.allocation.len(), expected.len());
    for (workload, before, after) in expected {
        let result = artifact
            .allocation
            .iter()
            .find(|r| r.workload == workload)
            .expect("workload measured");
        assert_eq!(
            result.baseline_counts.requests, before,
            "{workload:?} before"
        );
        assert_eq!(
            result.candidate_counts.requests, after,
            "{workload:?} after"
        );
        assert!(
            result.findings_identical,
            "{workload:?}: the builds must return identical findings"
        );
    }
    // Counts are deterministic: a second run reproduces the first exactly.
    assert_eq!(run(&card).allocation, artifact.allocation);
    println!("baseline: ok");
}
