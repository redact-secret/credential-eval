//! Evaluation cases, generated variants and generation (legacy
//! `benchmarks/engine/model.ts`, `engine/types.ts`, `methods/common.ts`).
//!
//! A case wraps one corpus case without changing its truth. A generated
//! variant adds a transformation, an expectation strategy and provenance. All
//! offsets stay UTF-8 byte offsets, including operator-generated spans.

use std::collections::{BTreeMap, BTreeSet};

use credential_eval_contracts::artifact::{Relation, VariantStrategy};
use credential_eval_contracts::canonical::{sha256_bytes, sha256_canonical};
use credential_eval_contracts::corpus::{Case, CaseKind, CorpusSnapshot, EvidenceTier, SpanRole};
use credential_eval_contracts::ids::{CaseId, ComponentId, FixturePath, Sha256Digest};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::evidence::EvaluationEvidence;
use super::operators::{GenerationFailed, OperatorId, OperatorOutput};
use crate::KernelError;

/// An evaluation method (legacy `createMethods`, `methods/index.ts:8-12`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum MethodId {
    /// Authored negative twin (`methods/twin.ts`).
    Twin,
    /// Benign control (`methods/benign.ts`).
    Benign,
    /// Context/encoding metamorphic relations (`methods/metamorphic.ts`).
    Metamorphic,
    /// Lexical/boundary/structural mutations (`methods/mutation.ts`).
    Mutation,
    /// Cross-scanner differential observation (`methods/differential.ts`).
    Differential,
}

impl MethodId {
    /// Registration order.
    pub const ALL: [Self; 5] = [
        Self::Twin,
        Self::Benign,
        Self::Metamorphic,
        Self::Mutation,
        Self::Differential,
    ];

    /// Wire id.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Twin => "twin",
            Self::Benign => "benign",
            Self::Metamorphic => "metamorphic",
            Self::Mutation => "mutation",
            Self::Differential => "differential",
        }
    }

    /// Method version (differential is 2, `methods/differential.ts:22`).
    pub const fn version(self) -> u32 {
        match self {
            Self::Differential => 2,
            _ => 1,
        }
    }

    /// Parse a wire id.
    pub fn parse(id: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|m| m.as_str() == id)
    }

    /// As a contract component id.
    pub fn component(self) -> ComponentId {
        ComponentId::new(self.as_str()).expect("method ids are component ids")
    }
}

/// An operator selected for a case, with its parameters.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OperatorSpec {
    /// Operator id.
    pub id: OperatorId,
    /// Operator parameters (scalar values only are replay-safe).
    #[serde(default)]
    pub parameters: BTreeMap<String, Value>,
}

/// One evaluation case (legacy `EvaluationCase`, `engine/types.ts:7-13`).
#[derive(Debug, Clone, PartialEq)]
pub struct EvaluationCase {
    /// `<corpus case id>--<method>`.
    pub id: CaseId,
    /// Method.
    pub method: MethodId,
    /// Seed case (for twin cases, the paired positive).
    pub seed: Case,
    /// Authored twin, for twin cases and mutation cases whose seed has one.
    pub twin: Option<Case>,
    /// Families the case targets (reporting strata only).
    pub targets: Vec<String>,
    /// Benign-control taxonomy.
    pub taxonomy: Option<String>,
    /// Operators to apply, in order.
    pub operators: Vec<OperatorSpec>,
    /// Seed string that seeded operator choices derive from (legacy
    /// `provenance.seed`).
    pub seed_key: String,
    /// Canonical digest of the seed case.
    pub source_hash: Sha256Digest,
}

/// How a variant changes its expectation relative to the canonical input.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ExpectationEffect {
    /// Expectation preserved.
    Preserve,
    /// Expectation inverted (authored twin).
    Invalidate,
    /// Expectation deferred to review.
    Defer,
}

/// Integrity claim of an authored transformation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Integrity {
    /// Claim kind (`authored-single-property`).
    pub kind: String,
    /// Property the claim is about.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub property: Option<String>,
}

/// A variant's transformation (legacy `Transformation`, `engine/types.ts:22-27`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Transformation {
    /// Method.
    pub method: MethodId,
    /// Method version.
    pub method_version: u32,
    /// Operator id (`identity` for the canonical variant).
    pub operator: ComponentId,
    /// Operator version.
    pub operator_version: u32,
    /// Resolved parameters.
    #[serde(default)]
    pub parameters: BTreeMap<String, Value>,
    /// Property the operator changes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub property: Option<String>,
    /// Relation to the canonical variant.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relation: Option<Relation>,
    /// Integrity claim.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub integrity: Option<Integrity>,
    /// Whether a lexical replacement still satisfies its family contract.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub contract_match: Option<bool>,
    /// Effect on the expectation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expectation_effect: Option<ExpectationEffect>,
}

/// Variant provenance (`evaluation/substrate/variant-lifecycle.ts:1-29`),
/// with canonical digests.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VariantProvenance {
    /// Case seed string.
    pub seed: String,
    /// Digest of the seed case.
    pub source_hash: Sha256Digest,
    /// Digest of the variant fixture.
    pub fixture_hash: Sha256Digest,
    /// Digest of the variant content bytes.
    pub content_hash: Sha256Digest,
    /// Digest of the transformation.
    pub transformation_hash: Sha256Digest,
}

/// A generated variant.
#[derive(Debug, Clone, PartialEq)]
pub struct GeneratedVariant {
    /// Variant id (`canonical` or the operator id).
    pub id: ComponentId,
    /// Parent evaluation case.
    pub case_id: CaseId,
    /// The variant fixture (a corpus case in the generated variant corpus).
    pub fixture: Case,
    /// Expectation strategy.
    pub strategy: VariantStrategy,
    /// Transformation.
    pub transformation: Transformation,
    /// Provenance.
    pub provenance: VariantProvenance,
}

/// Status of one generation attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AttemptStatus {
    /// A variant was generated.
    Generated,
    /// Input or parameters are outside the operator contract.
    Unsupported,
    /// Generation or validation failed (reason suppressed).
    Error,
}

/// One operator attempt (legacy `GenerationAttempt`, `engine/types.ts:17-20`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GenerationAttempt {
    /// Operator id.
    pub operator: OperatorId,
    /// Operator version.
    pub operator_version: u32,
    /// Replay-safe scalar parameters.
    pub parameters: BTreeMap<String, Value>,
    /// Digest of the full parameters.
    pub parameters_hash: Sha256Digest,
    /// Status.
    pub status: AttemptStatus,
    /// Variant id, when generated.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub variant: Option<ComponentId>,
    /// Fixed reason, when not generated.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// Explicit generation bounds. Legacy has none; these are safety limits that
/// never change a result below them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GenerationLimits {
    /// Maximum evaluation cases.
    pub max_cases: usize,
    /// Maximum variants of one case (including `canonical`).
    pub max_variants_per_case: usize,
    /// Maximum variants of a run.
    pub max_total_variants: usize,
    /// Maximum content bytes of one variant.
    pub max_variant_bytes: usize,
}

impl Default for GenerationLimits {
    fn default() -> Self {
        Self {
            max_cases: 1_000_000,
            max_variants_per_case: 64,
            max_total_variants: 4_000_000,
            max_variant_bytes: 16 * 1024 * 1024,
        }
    }
}

/// Secret spans of a case (`engine/model.ts:10`).
pub fn secrets(case: &Case) -> Vec<&credential_eval_contracts::corpus::ExpectedSpan> {
    case.expected
        .iter()
        .filter(|e| e.role == SpanRole::Secret)
        .collect()
}

/// Replay-safe parameters (`evaluation/substrate/hash.ts:9-12`): keys
/// `^[a-zA-Z][a-zA-Z0-9]*$` with boolean or finite number values.
pub fn safe_parameters(parameters: &BTreeMap<String, Value>) -> BTreeMap<String, Value> {
    parameters
        .iter()
        .filter(|(k, v)| {
            let mut chars = k.chars();
            chars.next().is_some_and(|c| c.is_ascii_alphabetic())
                && chars.all(|c| c.is_ascii_alphanumeric())
                && matches!(v, Value::Bool(_) | Value::Number(_))
        })
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect()
}

/// Stable seed-to-choice mapping (`operators/lexical.ts:41-43`):
/// `parseInt(sha256(JSON.stringify({seed, operator})).slice(0, 12), 16) % size`.
///
/// The JSON is the legacy insertion-order serialization, so choices are
/// identical to the legacy engine for the same seed string. `size` must be
/// positive.
pub fn seeded_choice(seed: &str, operator: &str, size: u64) -> u64 {
    let json = format!(
        "{{\"seed\":{},\"operator\":{}}}",
        serde_json::to_string(seed).expect("string serializes"),
        serde_json::to_string(operator).expect("string serializes"),
    );
    let digest = sha256_bytes(json.as_bytes());
    let hex = &digest.as_str()["sha256:".len()..][..12];
    u64::from_str_radix(hex, 16).expect("hex digest") % size
}

fn invalid(case: &str, reason: &'static str) -> KernelError {
    KernelError::InvalidEvaluationCase {
        case: case.to_owned(),
        reason,
    }
}

/// Validate one case's ranges and envelopes with the corpus rules
/// (legacy `validateCorpus` over a single fixture).
pub(crate) fn validate_fixture(case: &Case) -> Result<(), KernelError> {
    let mut single = case.clone();
    single.twin = None;
    let snapshot = CorpusSnapshot::seal(String::new(), String::new(), String::new(), vec![single]);
    snapshot.validate().map_err(KernelError::from)
}

/// Build a generated variant (`engine/model.ts:33-50`).
///
/// The fixture's twin lineage is dropped (`independentFixture`), its id and
/// path are re-keyed into the case's namespace, and a `review-required`
/// variant is re-assessed as `T0` without a family.
pub fn variant(
    case: &EvaluationCase,
    id: &str,
    fixture: &Case,
    transformation: Transformation,
    strategy: VariantStrategy,
) -> Result<GeneratedVariant, KernelError> {
    let variant_id =
        ComponentId::new(id).map_err(|_| invalid(case.id.as_str(), "invalid variant id"))?;
    let mut f = fixture.clone();
    f.twin = None;
    f.id = CaseId::new(format!("{}--{}", case.id, id.replace('.', "-")))
        .map_err(|_| invalid(case.id.as_str(), "invalid variant fixture id"))?;
    f.path = FixturePath::new(format!("cases/{}/{id}.txt", case.id))
        .map_err(|_| invalid(case.id.as_str(), "invalid variant path"))?;
    if strategy == VariantStrategy::ReviewRequired {
        f.grouping.kind = if f.expected.is_empty() {
            CaseKind::MustNotFlag
        } else {
            CaseKind::MustRedact
        };
        f.grouping.tier = EvidenceTier::T0;
        f.grouping.family = None;
    }
    validate_fixture(&f)?;
    let provenance = VariantProvenance {
        seed: case.seed_key.clone(),
        source_hash: sha256_canonical(&case.seed),
        fixture_hash: sha256_canonical(&f),
        content_hash: sha256_bytes(f.content.as_bytes()),
        transformation_hash: sha256_canonical(&transformation),
    };
    Ok(GeneratedVariant {
        id: variant_id,
        case_id: case.id.clone(),
        fixture: f,
        strategy,
        transformation,
        provenance,
    })
}

/// Generic case validation (`engine/model.ts:21-31`): slug targets and valid
/// seed ranges. Assessment re-derivation is an evidence-authoring check and
/// is not repeated here.
pub fn validate_case(case: &EvaluationCase) -> Result<(), KernelError> {
    let slug = |t: &str| {
        !t.is_empty()
            && t.bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
    };
    if case.targets.iter().any(|t| !slug(t)) || case.seed_key.is_empty() {
        return Err(invalid(case.id.as_str(), "invalid evaluation case"));
    }
    validate_fixture(&case.seed)
}

/// Method-specific validation (`methods/*.ts` `validateCase`).
pub fn validate_method(
    case: &EvaluationCase,
    evidence: &EvaluationEvidence,
) -> Result<(), KernelError> {
    let id = case.id.as_str();
    let has_secret = !secrets(&case.seed).is_empty();
    match case.method {
        MethodId::Twin => {
            if !has_secret || case.operators.len() != 1 {
                return Err(invalid(id, "twin needs a positive seed and one operator"));
            }
        }
        MethodId::Benign => {
            let taxonomy_ok = case.taxonomy.as_deref().is_some_and(|t| {
                !t.trim().is_empty()
                    && evidence
                        .benign_taxonomies
                        .as_ref()
                        .is_none_or(|vocabulary| vocabulary.contains(t))
            });
            if has_secret || case.seed.grouping.kind != CaseKind::MustNotFlag || !taxonomy_ok {
                return Err(invalid(
                    id,
                    "benign needs a classified control and taxonomy",
                ));
            }
        }
        MethodId::Metamorphic | MethodId::Mutation => {
            if case.operators.is_empty() {
                return Err(invalid(id, "method needs an operator"));
            }
        }
        MethodId::Differential => {
            if !case.operators.is_empty() {
                return Err(invalid(id, "differential observes the canonical input"));
            }
        }
    }
    Ok(())
}

/// Variants and attempts of one case.
#[derive(Debug, Clone, PartialEq)]
pub struct GeneratedCase {
    /// The case.
    pub case: EvaluationCase,
    /// Variants; `variants[0]` is `canonical`.
    pub variants: Vec<GeneratedVariant>,
    /// Operator attempts, in operator order.
    pub attempts: Vec<GenerationAttempt>,
}

const UNSUPPORTED: &str = "Input or parameters are outside the operator contract.";
const GENERATION_ERROR: &str =
    "Transformation generation or validation failed; raw error suppressed.";

/// Generate one case (`engine/model.ts:52-62` with `methods/common.ts:5-35`).
///
/// The canonical variant is always first. Each operator either reports
/// `unsupported`, generates a variant, or records an `error` attempt with a
/// suppressed reason. Duplicate operators and invalid cases are refused.
pub fn generate_case(
    case: EvaluationCase,
    evidence: &EvaluationEvidence,
    limits: &GenerationLimits,
) -> Result<GeneratedCase, KernelError> {
    validate_case(&case)?;
    validate_method(&case, evidence)?;
    let canonical = Transformation {
        method: case.method,
        method_version: case.method.version(),
        operator: ComponentId::new("identity").expect("component id"),
        operator_version: 1,
        parameters: BTreeMap::new(),
        property: None,
        relation: None,
        integrity: None,
        contract_match: None,
        expectation_effect: None,
    };
    let mut variants = vec![variant(
        &case,
        "canonical",
        &case.seed,
        canonical,
        VariantStrategy::Authored,
    )?];
    let ids: BTreeSet<OperatorId> = case.operators.iter().map(|s| s.id).collect();
    if ids.len() != case.operators.len() {
        return Err(invalid(
            case.id.as_str(),
            "duplicate operator specification",
        ));
    }
    let mut attempts = Vec::with_capacity(case.operators.len());
    for spec in &case.operators {
        let operator = spec.id;
        let mut attempt = GenerationAttempt {
            operator,
            operator_version: operator.version(),
            parameters: safe_parameters(&spec.parameters),
            parameters_hash: sha256_canonical(&spec.parameters),
            status: AttemptStatus::Generated,
            variant: None,
            reason: None,
        };
        if !operator.supports(&case, &spec.parameters, evidence) {
            attempt.status = AttemptStatus::Unsupported;
            attempt.reason = Some(UNSUPPORTED.to_owned());
            attempts.push(attempt);
            continue;
        }
        let generated = operator
            .generate(&case, &spec.parameters, evidence)
            .and_then(|output| build_operator_variant(&case, spec, output, limits));
        match generated {
            Ok((v, resolved)) => {
                attempt.variant = Some(v.id.clone());
                attempt.parameters = safe_parameters(&resolved);
                attempt.parameters_hash = sha256_canonical(&resolved);
                variants.push(v);
            }
            Err(GenerationFailed) => {
                attempt.status = AttemptStatus::Error;
                attempt.reason = Some(GENERATION_ERROR.to_owned());
            }
        }
        attempts.push(attempt);
        if variants.len() > limits.max_variants_per_case {
            return Err(KernelError::GenerationLimit {
                limit: "max_variants_per_case",
                value: limits.max_variants_per_case,
            });
        }
    }
    let unique: BTreeSet<&ComponentId> = variants.iter().map(|v| &v.id).collect();
    if unique.len() != variants.len() {
        return Err(invalid(case.id.as_str(), "empty or duplicate variants"));
    }
    Ok(GeneratedCase {
        case,
        variants,
        attempts,
    })
}

fn build_operator_variant(
    case: &EvaluationCase,
    spec: &OperatorSpec,
    output: OperatorOutput,
    limits: &GenerationLimits,
) -> Result<(GeneratedVariant, BTreeMap<String, Value>), GenerationFailed> {
    if output.fixture.content.len() > limits.max_variant_bytes {
        return Err(GenerationFailed);
    }
    let resolved = output.parameters.unwrap_or_else(|| spec.parameters.clone());
    let effect = output
        .expectation_effect
        .unwrap_or(match (output.strategy, output.relation) {
            (VariantStrategy::ReviewRequired, _) => ExpectationEffect::Defer,
            (_, Some(Relation::MustFlip)) => ExpectationEffect::Invalidate,
            _ => ExpectationEffect::Preserve,
        });
    let transformation = Transformation {
        method: case.method,
        method_version: case.method.version(),
        operator: spec.id.component(),
        operator_version: spec.id.version(),
        parameters: resolved.clone(),
        property: output.property,
        relation: output.relation,
        integrity: output.integrity,
        contract_match: output.contract_match,
        expectation_effect: Some(effect),
    };
    let v = variant(
        case,
        spec.id.as_str(),
        &output.fixture,
        transformation,
        output.strategy,
    )
    .map_err(|_| GenerationFailed)?;
    Ok((v, resolved))
}
