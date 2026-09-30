//! Input contract: the versioned corpus snapshot.
//!
//! A [`CorpusSnapshot`] is the evaluator's only source of expected behavior.
//! It is produced by `credential-evidence` (or, during migration, exported
//! from the legacy fixture corpus) and is never modified by the evaluator.
//! Grouping metadata is used to partition measurements only; it never changes
//! an outcome.

use std::collections::BTreeSet;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::ContractError;
use crate::canonical::sha256_canonical;
use crate::ids::{CaseId, FixturePath, Sha256Digest};
use crate::range::{ByteRange, Envelope};
use crate::schema::CorpusSnapshotSchema;

/// A complete, immutable evaluation corpus.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CorpusSnapshot {
    /// Document tag: `credential-eval/corpus-snapshot/v1`.
    pub schema: CorpusSnapshotSchema,
    /// Where the snapshot came from and the digest of its cases.
    pub identity: SnapshotIdentity,
    /// Cases. Order is not semantic; consumers sort by `id`.
    pub cases: Vec<Case>,
}

/// Identity of the evidence a snapshot was taken from.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SnapshotIdentity {
    /// Evidence source, e.g. `credential-evidence` or
    /// `legacy:redact-secret-benchmarks` during migration.
    pub source: String,
    /// Immutable revision of the source (commit SHA or release tag).
    pub revision: String,
    /// Schema/revision label of the source evidence format.
    pub evidence_schema: String,
    /// Digest of the cases; see [`corpus_digest`].
    pub corpus_digest: Sha256Digest,
}

/// One evaluation case: a fixture file plus its authored expectations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Case {
    /// Stable case id, unique within the snapshot.
    pub id: CaseId,
    /// Relative path the fixture is materialized at, unique within the snapshot.
    pub path: FixturePath,
    /// Exact fixture text. Ranges index its UTF-8 bytes.
    pub content: String,
    /// Authored spans, sorted by `start` and pairwise disjoint (touching is allowed).
    /// Empty for controls.
    pub expected: Vec<ExpectedSpan>,
    /// Grouping metadata (kind, tier, family, ...). Never changes an outcome.
    pub grouping: Grouping,
    /// Present when this case is an authored negative twin of a positive case.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub twin: Option<TwinLineage>,
}

/// An authored expected span.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ExpectedSpan {
    /// Inclusive start byte offset.
    pub start: u64,
    /// Exclusive end byte offset.
    pub end: u64,
    /// Whether the span is the credential itself or an acceptable companion.
    pub role: SpanRole,
    /// Optional wider acceptable range with an authored reason.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub envelope: Option<Envelope>,
}

impl ExpectedSpan {
    /// The span as a plain range.
    pub const fn range(&self) -> ByteRange {
        ByteRange::new(self.start, self.end)
    }

    /// The acceptable range: the envelope when present, else the span itself.
    pub fn acceptable(&self) -> ByteRange {
        self.envelope
            .as_ref()
            .map_or_else(|| self.range(), Envelope::range)
    }
}

/// Role of an expected span.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "kebab-case")]
pub enum SpanRole {
    /// Credential bytes that must be covered. Scored by the lattice.
    Secret,
    /// Bytes that may be covered without collateral (e.g. a paired key id).
    /// Not scored as a span; counts as acceptable coverage.
    Companion,
}

/// Measurement population of a case.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "kebab-case")]
pub enum CaseKind {
    /// Contains secret spans that must be covered.
    MustRedact,
    /// A control: any (scoped) finding is a false alarm.
    MustNotFlag,
    /// Contains spans whose handling is a policy matter; scored like
    /// `must-redact` but grouped separately.
    Policy,
}

impl CaseKind {
    /// Wire name (`must-redact`, `must-not-flag`, `policy`).
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::MustRedact => "must-redact",
            Self::MustNotFlag => "must-not-flag",
            Self::Policy => "policy",
        }
    }
}

/// Evidence tier of a case's expectation. `T0` means the expectation is
/// pending review: the case is observed but never scored.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
pub enum EvidenceTier {
    /// Pending review; unscored.
    T0,
    /// Tier 1 evidence.
    T1,
    /// Tier 2 evidence.
    T2,
    /// Tier 3 evidence.
    T3,
}

impl EvidenceTier {
    /// Wire name (`T0`..`T3`).
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::T0 => "T0",
            Self::T1 => "T1",
            Self::T2 => "T2",
            Self::T3 => "T3",
        }
    }
}

/// Grouping metadata. Used to partition measurements, never to decide them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Grouping {
    /// Measurement population.
    pub kind: CaseKind,
    /// Evidence tier.
    pub tier: EvidenceTier,
    /// Credential family (format contract) the case exercises, if any. A twin's
    /// false-alarm reading is scoped to this family.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub family: Option<String>,
    /// Corpus group / category the case belongs to.
    pub group: String,
    /// Evidence class label from the evidence source, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence_class: Option<String>,
    /// Families the case targets (reporting strata only). Sorted, unique.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub targets: Vec<String>,
    /// Benign-control taxonomy axis, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub taxonomy: Option<String>,
}

/// Lineage of an authored negative twin.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TwinLineage {
    /// The positive case this control is paired with.
    pub twin_of: CaseId,
    /// Authored description of the single semantic change. Non-blank.
    pub mutation: String,
    /// Mutated property (e.g. `length`, `alphabet`, `prefix`, `context`).
    pub mutation_kind: String,
}

/// Compute the corpus digest: SHA-256 of the canonical JSON of the case array
/// sorted by `id` (see `docs/contracts/identity.md`).
pub fn corpus_digest(cases: &[Case]) -> Sha256Digest {
    let mut sorted: Vec<&Case> = cases.iter().collect();
    sorted.sort_by(|a, b| a.id.cmp(&b.id));
    sha256_canonical(&sorted)
}

impl CorpusSnapshot {
    /// Build a snapshot, computing its corpus digest.
    pub fn seal(
        source: String,
        revision: String,
        evidence_schema: String,
        cases: Vec<Case>,
    ) -> Self {
        let corpus_digest = corpus_digest(&cases);
        Self {
            schema: CorpusSnapshotSchema,
            identity: SnapshotIdentity {
                source,
                revision,
                evidence_schema,
                corpus_digest,
            },
            cases,
        }
    }

    /// Parse and fully validate a snapshot from JSON.
    pub fn from_json(bytes: &[u8]) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let snapshot: Self = serde_json::from_slice(bytes)?;
        snapshot.validate()?;
        Ok(snapshot)
    }

    /// Validate structure, ranges, twin lineage and the declared digest.
    ///
    /// Ports the legacy `validateCorpus` rules (`benchmarks/lib/scoring.ts:42-84`).
    pub fn validate(&self) -> Result<(), ContractError> {
        if self.cases.is_empty() {
            return Err(ContractError::EmptyCorpus);
        }
        let mut ids = BTreeSet::new();
        let mut paths = BTreeSet::new();
        for case in &self.cases {
            if !ids.insert(&case.id) {
                return Err(ContractError::DuplicateCaseId(case.id.to_string()));
            }
            if !paths.insert(&case.path) {
                return Err(ContractError::UnsafeOrDuplicatePath {
                    case: case.id.to_string(),
                });
            }
            validate_spans(case)?;
        }
        for case in &self.cases {
            let Some(twin) = &case.twin else { continue };
            let invalid = |reason| ContractError::InvalidTwin {
                case: case.id.to_string(),
                reason,
            };
            let positive = self
                .cases
                .iter()
                .find(|c| c.id == twin.twin_of)
                .ok_or_else(|| invalid("twin_of names an unknown case"))?;
            if positive.id == case.id {
                return Err(invalid("twin_of names itself"));
            }
            if !positive.expected.iter().any(|s| s.role == SpanRole::Secret) {
                return Err(invalid("paired case has no secret span"));
            }
            if case.expected.iter().any(|s| s.role == SpanRole::Secret) {
                return Err(invalid("twin carries a secret span"));
            }
            if twin.mutation.trim().is_empty() {
                return Err(invalid("twin without mutation"));
            }
        }
        let computed = corpus_digest(&self.cases);
        if computed != self.identity.corpus_digest {
            return Err(ContractError::CorpusDigestMismatch {
                declared: self.identity.corpus_digest.to_string(),
                computed: computed.to_string(),
            });
        }
        Ok(())
    }

    /// Look up a case by id.
    pub fn case(&self, id: &CaseId) -> Option<&Case> {
        self.cases.iter().find(|c| &c.id == id)
    }
}

fn validate_spans(case: &Case) -> Result<(), ContractError> {
    let id = || case.id.to_string();
    let mut previous_end = 0;
    for span in &case.expected {
        let range = span.range();
        if !range.is_valid_in(&case.content) {
            return Err(ContractError::InvalidRange {
                case: id(),
                start: span.start,
                end: span.end,
            });
        }
        if span.start < previous_end {
            return Err(ContractError::UnorderedSpans { case: id() });
        }
        if let Some(envelope) = &span.envelope {
            let outer = envelope.range();
            if !outer.is_valid_in(&case.content)
                || envelope.start > span.start
                || envelope.end < span.end
                || envelope.reason.trim().is_empty()
            {
                return Err(ContractError::InvalidEnvelope { case: id() });
            }
            let overlaps_other = case.expected.iter().any(|other| {
                !std::ptr::eq(other, span)
                    && other.start < envelope.end
                    && envelope.start < other.end
            });
            if overlaps_other {
                return Err(ContractError::InvalidEnvelope { case: id() });
            }
        }
        previous_end = span.end;
    }
    Ok(())
}
