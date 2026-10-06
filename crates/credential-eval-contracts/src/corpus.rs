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
use crate::canonical::{sha256_bytes, sha256_canonical};
use crate::ids::{CaseId, FixturePath, ReleaseTag, Sha256Digest};
use crate::range::{ByteRange, Envelope};
use crate::representation::{DecodedFact, Representation, case_has_facts, check_case};
use crate::schema::{CorpusSnapshotSchema, RepresentationContract};

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
    /// The pinned evidence release the snapshot file was verified against
    /// (revision v1.1). The evaluator writes it into a run manifest only after
    /// it has checked the snapshot bytes against the release manifest; a
    /// snapshot input must not declare it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub release: Option<EvidenceRelease>,
    /// The representation contract the snapshot uses (revision v1.3). Required
    /// when any case carries a representation fact; absent otherwise, so a
    /// snapshot without facts is byte-for-byte what it was. Declaring it with
    /// no facts is allowed and means the exporter supports the contract.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub representation: Option<RepresentationContract>,
}

/// Identity of a verified evidence release: the tag a consumer pinned and the
/// digest of the release manifest whose snapshot entry matched the snapshot
/// file byte for byte.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EvidenceRelease {
    /// Release tag (e.g. `snapshot-2026.10.01`).
    pub tag: ReleaseTag,
    /// SHA-256 of the release manifest file's bytes.
    pub manifest_digest: Sha256Digest,
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
    /// Facts about the input as a whole (revision v1.3): validity, derivation,
    /// transformation lineage and chunking. Absent for an ordinary raw input.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub representation: Option<Representation>,
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
    /// The authored base this span's value comes from (revision v1.3).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub base: Option<CaseId>,
    /// The secret bytes inside `[start, end)` when the value is not
    /// contiguous (revision v1.3). At least two, sorted, disjoint, separated
    /// by at least one byte, the first starting at `start` and the last ending
    /// at `end`. Bytes of the range outside them are separators.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fragments: Option<Vec<ByteRange>>,
    /// How the source bytes decode to the value (revision v1.3): the decode
    /// steps, the decoded length and its digest. Never the decoded value.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decoded: Option<DecodedFact>,
}

impl Case {
    /// This case without any representation fact (revision v1.3): the same
    /// bytes, spans and grouping as before the facts existed. A generated
    /// variant starts from this, because its bytes differ from the original's.
    pub fn without_representation(&self) -> Self {
        let mut out = self.clone();
        out.representation = None;
        for span in &mut out.expected {
            span.base = None;
            span.fragments = None;
            span.decoded = None;
        }
        out
    }
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
    /// The family whose contract owns this twin's value, when the twin is a
    /// real credential of another class of the same provider (revision v1.9,
    /// ADR 0020). Absent for an ordinary near-miss twin. A finding that is the
    /// same family as this one is co-detection, even when the same finding also
    /// covers the scope family (a provider-wide legacy id). Never read from a
    /// scanner; never relabels an expected family.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sibling_family: Option<String>,
}

/// Compute the corpus digest: SHA-256 of the canonical JSON of the case array
/// sorted by `id` (see `docs/contracts/identity.md`).
pub fn corpus_digest(cases: &[Case]) -> Sha256Digest {
    let mut sorted: Vec<&Case> = cases.iter().collect();
    sorted.sort_by(|a, b| a.id.cmp(&b.id));
    sha256_canonical(&sorted)
}

/// Compute the input digest: SHA-256 of the canonical JSON of
/// `{path, sha256(content)}` for every case, sorted by path (see
/// `docs/contracts/identity.md`).
///
/// It covers exactly what a scanner is shown (fixture paths and bytes) and
/// nothing a scanner is not shown: expected spans, envelopes, grouping, twin
/// lineage and the snapshot identity are all outside it. Two corpora with the
/// same input digest feed every scanner the same files, so a scanner's
/// observations of one are the observations of the other (revision v1.6).
pub fn input_digest(cases: &[Case]) -> Sha256Digest {
    #[derive(Serialize)]
    struct Input<'a> {
        path: &'a FixturePath,
        sha256: Sha256Digest,
    }
    let mut inputs: Vec<Input<'_>> = cases
        .iter()
        .map(|c| Input {
            path: &c.path,
            sha256: sha256_bytes(c.content.as_bytes()),
        })
        .collect();
    inputs.sort_by(|a, b| a.path.cmp(b.path));
    sha256_canonical(&inputs)
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
                release: None,
                representation: None,
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
            check_case(case)?;
        }
        if self.identity.representation.is_none() && self.cases.iter().any(case_has_facts) {
            return Err(ContractError::RepresentationUndeclared);
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
            if let Some(sibling) = &twin.sibling_family {
                let scope = case.grouping.family.as_deref();
                if sibling.trim().is_empty() || sibling.trim() != sibling {
                    return Err(invalid("sibling_family is blank or padded"));
                }
                if scope.is_none() {
                    return Err(invalid("sibling_family without a scope family"));
                }
                if scope == Some(sibling.as_str()) {
                    return Err(invalid("sibling_family equals the scope family"));
                }
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
