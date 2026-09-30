//! Legacy `eval` writer: an evaluation report → the semantic subset of
//! `results-output/evaluation.json` (schemaVersion 3, legacy-map §4.3).
//!
//! It renders from the in-memory [`EvaluationReport`] and its plan, because
//! the legacy file carries per-case generation attempts (unsupported and
//! error operators) that the canonical artifact deliberately does not
//! publish. Rendered: scanner statuses, case/variant counts, the five
//! summaries, resolution, unresolved groups, the assertion accounting delta,
//! per-case results (variant lineage, generation attempts, assertions,
//! variant rows, differential comparisons and observations), failures,
//! generation errors and review-queue membership.
//!
//! Not rendered (volatile or legacy-digest fields that parity excludes,
//! kernel-deltas H1): run ids, timestamps, provenance, `parametersHash`,
//! variant `provenance.*Hash`, review entry `id` and `evidence`, the review
//! ledger state, and presentation fields (`visibility`, `source`).

use std::collections::{BTreeMap, BTreeSet};

use credential_eval_contracts::artifact::{Assertion, AssertionStatus, ComparisonStatus};
use credential_eval_contracts::observation::{ObservationSet, ScannerStatus};
use credential_eval_kernel::compat::{assertion_delta, legacy_disagreement, legacy_status};
use credential_eval_kernel::evaluation::model::{AttemptStatus, safe_parameters};
use credential_eval_kernel::evaluation::{EvaluationPlan, EvaluationReport};
use serde_json::{Map, Value, json};

use crate::bench::legacy_row;
use crate::camel;

fn status_name(status: ScannerStatus) -> &'static str {
    legacy_status(status)
}

/// Legacy assertion record (`{type, status, variant?, baseline?, candidate?, reason?}`).
/// A not-measured reason is the scanner status, folded like the status.
pub fn legacy_assertion(a: &Assertion) -> Value {
    let mut m = Map::new();
    m.insert("type".into(), json!(a.assertion));
    m.insert("status".into(), json!(a.status));
    for (k, v) in [
        ("variant", &a.variant),
        ("baseline", &a.baseline),
        ("candidate", &a.candidate),
    ] {
        if let Some(v) = v {
            m.insert(k.into(), json!(v));
        }
    }
    if let Some(reason) = &a.reason {
        let folded = if a.status == AssertionStatus::NotMeasured {
            serde_json::from_value::<ScannerStatus>(json!(reason))
                .map_or_else(|_| reason.clone(), |s| status_name(s).to_owned())
        } else {
            reason.clone()
        };
        m.insert("reason".into(), json!(folded));
    }
    Value::Object(m)
}

fn accounted(v: &impl serde::Serialize) -> Value {
    let mut value = serde_json::to_value(v).expect("counts serialize");
    if let Some(m) = value.as_object_mut() {
        for (from, to) in [
            ("review_required", "review-required"),
            ("not_measured", "not-measured"),
            ("resolved_rate", "resolvedRate"),
        ] {
            if let Some(x) = m.remove(from) {
                m.insert(to.into(), x);
            }
        }
    }
    value
}

/// Render the legacy evaluation view.
pub fn render(
    plan: &EvaluationPlan,
    report: &EvaluationReport,
    observations: &ObservationSet,
) -> Value {
    let scanners: Vec<Value> = {
        let mut list: Vec<_> = observations.observations.iter().collect();
        list.sort_by(|a, b| a.scanner.id.cmp(&b.scanner.id));
        list.iter()
            .map(|o| {
                json!({
                    "id": o.scanner.id,
                    "version": o.scanner.version,
                    "status": status_name(o.result.status()),
                })
            })
            .collect()
    };
    let unstable: BTreeSet<String> = report
        .statuses
        .iter()
        .filter(|(_, s)| **s == ScannerStatus::Unstable)
        .map(|(k, _)| k.to_string())
        .collect();
    let delta = assertion_delta(&report.summaries.by_method, &unstable, &report.accounting);
    let delta: Map<String, Value> = delta
        .into_iter()
        .map(|(k, g)| {
            let mut v10 = serde_json::to_value(g.v10).expect("counts serialize");
            v10.as_object_mut()
                .expect("counts object")
                .remove("not-measured");
            (
                k,
                json!({ "v10": v10, "v11": accounted(&g.v11), "cause": g.cause }),
            )
        })
        .collect();
    let resolution: Map<String, Value> = report
        .resolution
        .iter()
        .map(|(k, c)| (k.clone(), accounted(c)))
        .collect();

    let results: Vec<Value> = report
        .results
        .iter()
        .map(|r| {
            let g = &r.generated;
            let case = &g.case;
            let variants: Vec<Value> = g
                .variants
                .iter()
                .map(|v| {
                    let mut t = serde_json::to_value(&v.transformation).expect("serialize");
                    t["parameters"] = json!(safe_parameters(&v.transformation.parameters));
                    json!({
                        "id": v.id, "path": v.fixture.path, "strategy": v.strategy,
                        "kind": v.fixture.grouping.kind, "tier": v.fixture.grouping.tier,
                        "transformation": camel(t),
                    })
                })
                .collect();
            let generation: Vec<Value> = g
                .attempts
                .iter()
                .map(|a| {
                    let mut v = camel(serde_json::to_value(a).expect("serialize"));
                    let m = v.as_object_mut().expect("attempt object");
                    m.remove("parametersHash");
                    m.insert("parameters".into(), json!(safe_parameters(&a.parameters)));
                    v
                })
                .collect();
            let scanner_results: Vec<Value> = r
                .scanners
                .iter()
                .map(|s| {
                    json!({
                        "scanner": s.scanner,
                        "status": status_name(s.status),
                        "assertions": s.assertions.iter().map(legacy_assertion).collect::<Vec<_>>(),
                        "variants": g.variants.iter().zip(&s.rows).map(|(v, row)| json!({
                            "id": v.id,
                            "row": legacy_row(row, row.case_id.as_str(), row.path.as_str(), None, None),
                        })).collect::<Vec<_>>(),
                    })
                })
                .collect();
            let mut out = json!({
                "id": case.id, "method": case.method, "targets": case.targets,
                "taxonomy": case.taxonomy, "variants": variants, "generation": generation,
                "scanners": scanner_results,
            });
            if let Some(d) = &r.differential {
                let status_of = |id: &credential_eval_contracts::ids::ScannerId| {
                    report
                        .statuses
                        .get(id)
                        .map_or("not-selected", |s| status_name(*s))
                };
                out["comparisons"] = Value::Array(
                    d.comparisons
                        .iter()
                        .map(|c| {
                            let mut m = Map::new();
                            m.insert("variant".into(), json!(c.variant));
                            m.insert("peer".into(), json!(c.peer));
                            m.insert("status".into(), json!(c.status));
                            if let Some(x) = c.disagreement {
                                m.insert("disagreement".into(), json!(legacy_disagreement(x)));
                            }
                            if let Some(x) = c.classification_compared {
                                m.insert(
                                    "classification".into(),
                                    json!(if x { "compared" } else { "unsupported" }),
                                );
                            }
                            if c.status != ComparisonStatus::Complete {
                                m.insert(
                                    "reason".into(),
                                    json!(format!(
                                        "{}: {}; {}: {}",
                                        c.reference,
                                        status_of(&c.reference),
                                        c.peer,
                                        status_of(&c.peer)
                                    )),
                                );
                            }
                            Value::Object(m)
                        })
                        .collect(),
                );
                out["complete"] = json!(d.complete);
                out["observations"] = Value::Array(
                    d.observations
                        .iter()
                        .map(|(id, (status, seen))| {
                            json!({ "scanner": id, "status": status_name(*status), "variants": seen })
                        })
                        .collect(),
                );
            }
            out
        })
        .collect();

    let failures: Vec<Value> = report
        .failures
        .iter()
        .map(|f| {
            json!({ "caseId": f.assertion.case_id, "scanner": f.scanner, "assertion": legacy_assertion(&f.assertion) })
        })
        .collect();
    let generation_errors: Vec<Value> = report
        .results
        .iter()
        .flat_map(|r| {
            r.generated
                .attempts
                .iter()
                .filter(|a| a.status == AttemptStatus::Error)
                .map(|a| {
                    json!({ "caseId": r.generated.case.id, "operator": a.operator, "status": "error", "reason": a.reason })
                })
        })
        .collect();
    let review_queue: Vec<Value> = report
        .review_queue
        .iter()
        .map(|e| {
            let mut targets = e.targets.clone();
            targets.sort();
            let mut m = Map::new();
            m.insert("caseId".into(), json!(e.case_id));
            m.insert("method".into(), json!(e.method));
            m.insert("targets".into(), json!(targets));
            m.insert("variant".into(), json!(e.variant));
            m.insert("status".into(), json!("review-required"));
            if let Some(p) = &e.peer {
                m.insert("peer".into(), json!(p));
            }
            if let Some(d) = e.disagreement {
                m.insert("disagreement".into(), json!(legacy_disagreement(d)));
            }
            if let Some(o) = &e.observations {
                m.insert("observations".into(), json!(o));
            }
            if let Some(c) = &e.classifications {
                m.insert("classifications".into(), json!(c));
            }
            if let Some(r) = &e.reason {
                m.insert("reason".into(), json!(r));
            }
            Value::Object(m)
        })
        .collect();

    let summaries = &report.summaries;
    let by_operator: BTreeMap<&String, Value> = summaries
        .by_operator
        .iter()
        .map(|(k, v)| (k, serde_json::to_value(v).expect("serialize")))
        .collect();
    json!({
        "view": "credential-eval/legacy-evaluation-view/v1",
        "scanners": scanners,
        "caseCount": plan.cases.len(),
        "variantCount": plan.cases.iter().map(|c| c.variants.len()).sum::<usize>(),
        "byMethod": summaries.by_method,
        "byDetector": summaries.by_target,
        "byTaxonomy": summaries.by_taxonomy,
        "byOperator": by_operator,
        "axesByDetector": summaries.axes_by_target,
        "resolution": resolution,
        "unresolvedGroups": report.unresolved_groups,
        "accountingDelta": { "version": "1.0 -> 1.1", "groups": delta },
        "results": results,
        "failures": failures,
        "generationErrors": generation_errors,
        "reviewQueue": review_queue,
    })
}
