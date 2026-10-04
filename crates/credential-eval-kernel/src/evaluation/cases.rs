//! Snapshot → evaluation cases (legacy `loadCases`,
//! `evaluation/domains/credential/cases.ts:22-103`).
//!
//! Corpus reading, category manifests, assessment re-derivation and
//! calibration-only filtering are evidence concerns and stay with the
//! snapshot producer. What remains is the case construction rule.

use credential_eval_contracts::canonical::sha256_canonical;
use credential_eval_contracts::corpus::{Case, CorpusSnapshot, EvidenceTier};
use credential_eval_contracts::ids::CaseId;

use super::model::{EvaluationCase, MethodId, OperatorSpec, secrets};
use super::operators::OperatorId;
use crate::KernelError;

/// How case seeds are named. Operators derive seeded choices from the seed
/// string, so it is part of a run's identity.
pub type SeedKey<'a> = &'a dyn Fn(&Case) -> String;

/// Canonical seed: the corpus case id.
pub fn case_id_seed(case: &Case) -> String {
    case.id.to_string()
}

/// Build the evaluation cases of `snapshot` for the selected `methods`.
///
/// For every corpus case, in case-id order:
///
/// * `differential` always;
/// * `twin` when the case is an authored twin (seed = its positive, one
///   `authored.twin` operator); otherwise `benign` when it has no secret span
///   (taxonomy `pending` for `T0`, else `grouping.taxonomy`, required);
/// * for non-twin cases, `metamorphic` with every context/encoding operator
///   and `mutation` with every lexical/boundary/structural operator, plus
///   `authored.twin` when the case has an authored twin (the first by id).
///
/// Case ids are `<corpus case id>--<method>`.
pub fn build_cases(
    snapshot: &CorpusSnapshot,
    methods: &[MethodId],
    seed_key: SeedKey<'_>,
) -> Result<Vec<EvaluationCase>, KernelError> {
    // A variant is a different input: the representation facts of its seed
    // (fragments, decoded values, validity) do not hold for it, so seeds are
    // taken without them. This also keeps `source_hash` a function of the
    // seed's bytes and spans, as before revision v1.3.
    let stripped: Vec<Case>;
    let source: &[Case] = if snapshot.uses_representation() {
        stripped = snapshot
            .cases
            .iter()
            .map(Case::without_representation)
            .collect();
        &stripped
    } else {
        &snapshot.cases
    };
    let mut corpus: Vec<&Case> = source.iter().collect();
    corpus.sort_by(|a, b| a.id.cmp(&b.id));
    let wants = |m: MethodId| methods.contains(&m);
    let mut cases = Vec::new();
    for f in &corpus {
        let base = |method: MethodId, seed: &Case| -> Result<EvaluationCase, KernelError> {
            Ok(EvaluationCase {
                id: CaseId::new(format!("{}--{}", f.id, method.as_str()))?,
                method,
                seed: seed.clone(),
                twin: None,
                targets: f.grouping.targets.clone(),
                taxonomy: None,
                operators: Vec::new(),
                seed_key: seed_key(f),
                source_hash: sha256_canonical(seed),
            })
        };
        if wants(MethodId::Differential) {
            cases.push(base(MethodId::Differential, f)?);
        }
        if let Some(lineage) = &f.twin {
            if wants(MethodId::Twin) {
                let positive =
                    corpus
                        .iter()
                        .find(|p| p.id == lineage.twin_of)
                        .ok_or_else(|| KernelError::InvalidEvaluationCase {
                            case: f.id.to_string(),
                            reason: "twin names an unknown positive",
                        })?;
                let mut c = base(MethodId::Twin, positive)?;
                c.twin = Some((*f).clone());
                c.operators = vec![spec(OperatorId::AuthoredTwin)];
                cases.push(c);
            }
        } else if secrets(f).is_empty() && wants(MethodId::Benign) {
            let taxonomy = if f.grouping.tier == EvidenceTier::T0 {
                "pending".to_owned()
            } else {
                f.grouping
                    .taxonomy
                    .clone()
                    .ok_or_else(|| KernelError::InvalidEvaluationCase {
                        case: f.id.to_string(),
                        reason: "no reviewed taxonomy for control",
                    })?
            };
            let mut c = base(MethodId::Benign, f)?;
            c.taxonomy = Some(taxonomy);
            cases.push(c);
        }
        if f.twin.is_none() {
            if wants(MethodId::Metamorphic) {
                let mut c = base(MethodId::Metamorphic, f)?;
                c.operators = OperatorId::ALL
                    .into_iter()
                    .filter(|o| o.is_context())
                    .map(spec)
                    .collect();
                cases.push(c);
            }
            if wants(MethodId::Mutation) {
                let twin = corpus
                    .iter()
                    .find(|t| t.twin.as_ref().is_some_and(|l| l.twin_of == f.id));
                let mut c = base(MethodId::Mutation, f)?;
                c.twin = twin.map(|t| (*t).clone());
                c.operators = OperatorId::ALL
                    .into_iter()
                    .filter(|o| {
                        o.is_lexical() || (*o == OperatorId::AuthoredTwin && twin.is_some())
                    })
                    .map(spec)
                    .collect();
                cases.push(c);
            }
        }
    }
    Ok(cases)
}

fn spec(id: OperatorId) -> OperatorSpec {
    OperatorSpec {
        id,
        parameters: Default::default(),
    }
}
