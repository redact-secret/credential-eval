//! Output contract: the sanitized, reproducible run artifact.
//!
//! A [`RunArtifact`] is self-describing: a consumer holding only the artifact
//! and `schemas/run-artifact-v1.schema.json` can re-verify every per-case
//! outcome (expected and actual ranges are embedded) and interpret every
//! aggregate, without fixture bytes and without importing product code.
//!
//! Determinism: after [`RunArtifact::canonicalize`], every collection is sorted
//! by its semantic key, and everything except [`NonSemantic`] is a pure
//! function of (engine, protocol, snapshot, scanners, adapters, config).

use std::collections::BTreeMap;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::canonical::sha256_canonical;
use crate::config::AccountingConfig;
use crate::corpus::{CaseKind, EvidenceTier, SnapshotIdentity, SpanRole};
use crate::ids::{CaseId, ComponentId, FixturePath, ScannerId, Sha256Digest};
use crate::observation::{NormalizedFinding, Replays, ScannerIdentity, ScannerStatus};
use crate::range::ByteRange;
use crate::schema::RunArtifactSchema;

/// The complete result of one evaluation run.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RunArtifact {
    /// Document tag: `credential-eval/run-artifact/v1`.
    pub schema: RunArtifactSchema,
    /// Every identity needed to reproduce the run.
    pub manifest: RunManifest,
    /// Per-scanner results, sorted by scanner id.
    pub scanners: Vec<ScannerRun>,
    /// Generated variants (mutation/metamorphic/twin methods), sorted by
    /// `(case_id, variant)`. Empty when no generating method ran.
    #[serde(default)]
    pub variants: Vec<VariantRecord>,
    /// Cross-scanner differential observations, sorted by
    /// `(case_id, variant, reference, peer)`.
    #[serde(default)]
    pub comparisons: Vec<DifferentialComparison>,
    /// Occurrences that need an authored decision (differential
    /// disagreements and variants whose expectation could not be derived),
    /// sorted by `id`. Never a verdict on any scanner.
    #[serde(default)]
    pub review_queue: Vec<ReviewOccurrence>,
    /// Timestamps and host diagnostics. Excluded from the semantic digest.
    pub non_semantic: NonSemantic,
}

/// Reproduction identities of a run.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RunManifest {
    /// Engine name and implementation version.
    pub engine: EngineIdentity,
    /// Measurement protocol version (independent of the engine version).
    pub protocol_version: String,
    /// Identity of the evidence snapshot, including its corpus digest.
    pub evidence: SnapshotIdentity,
    /// Canonical digest of the run configuration.
    pub config_hash: Sha256Digest,
    /// Accounting parameters the aggregates were computed with.
    pub accounting: AccountingConfig,
    /// Evaluation methods applied, sorted by id.
    #[serde(default)]
    pub methods: Vec<MethodIdentity>,
    /// Scanner identities, sorted by id. Includes failed/unavailable scanners.
    pub scanners: Vec<ScannerIdentity>,
}

/// Engine identity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EngineIdentity {
    /// Engine name (`credential-eval`).
    pub name: String,
    /// Engine implementation version.
    pub version: String,
}

/// An evaluation method and its version.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MethodIdentity {
    /// Method id (e.g. `twin`).
    pub id: ComponentId,
    /// Method version.
    pub version: u32,
}

/// One scanner's results.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ScannerRun {
    /// Scanner id (identity is in the manifest).
    pub scanner: ScannerId,
    /// Execution status. Anything but `complete` means not measured.
    pub status: ScannerStatus,
    /// Sanitized status detail for non-complete scanners.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    /// Replay record, when replays ran.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub replays: Option<Replays>,
    /// Deduplicated normalized findings, sorted by `(path, start, end)`.
    /// Empty unless `status` is `complete`.
    pub findings: Vec<NormalizedFinding>,
    /// One result per corpus case, sorted by case id.
    pub cases: Vec<CaseResult>,
    /// Method assertions, sorted by `(case_id, method, variant, baseline, candidate, assertion)`.
    #[serde(default)]
    pub assertions: Vec<Assertion>,
    /// Aggregates over `cases` and `assertions`.
    pub aggregates: Aggregates,
}

/// The outcome of one case for one scanner. Self-verifying: `expected` and
/// `actual` suffice to recompute `measurement` under the protocol.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CaseResult {
    /// Case id.
    pub case_id: CaseId,
    /// Fixture path.
    pub path: FixturePath,
    /// Measurement population.
    pub kind: CaseKind,
    /// Evidence tier.
    pub tier: EvidenceTier,
    /// Family (format contract) of the case, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub family: Option<String>,
    /// Positive case this control is a twin of, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub twin_of: Option<CaseId>,
    /// Corpus group / category of the case (`Case.grouping.group`).
    pub group: String,
    /// Families the case targets (`Case.grouping.targets`; reporting strata
    /// only). Sorted, unique; omitted when empty.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub targets: Vec<String>,
    /// Benign-control taxonomy axis (`Case.grouping.taxonomy`), if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub taxonomy: Option<String>,
    /// Evidence class label (`Case.grouping.evidence_class`), if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence_class: Option<String>,
    /// Mutated property of an authored twin (`Case.twin.mutation_kind`), if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub twin_mutation_kind: Option<String>,
    /// Authored spans (envelope reasons omitted).
    pub expected: Vec<ScoredSpan>,
    /// Findings on this case's path, sorted by `(start, end)`.
    pub actual: Vec<ObservedRange>,
    /// The measurement.
    pub measurement: CaseMeasurement,
}

/// An expected span as embedded in results.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ScoredSpan {
    /// Inclusive start byte offset.
    pub start: u64,
    /// Exclusive end byte offset.
    pub end: u64,
    /// Span role.
    pub role: SpanRole,
    /// Acceptable envelope, if authored.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub envelope: Option<ByteRange>,
}

/// A finding range on one case.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ObservedRange {
    /// Inclusive start byte offset.
    pub start: u64,
    /// Exclusive end byte offset.
    pub end: u64,
    /// Mapped family, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub family: Option<String>,
    /// Scanner-reported action, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub action: Option<String>,
}

/// Span-level outcome lattice (protocol semantics; see `docs/contracts/outcomes.md`).
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Outcome {
    /// A finding equals the span exactly.
    Exact,
    /// A finding contains the span and lies within the acceptable envelope.
    Covered,
    /// Findings contain the span but every containing finding exceeds the envelope.
    Overbroad,
    /// Findings overlap the span without containing it. Leaks.
    Partial,
    /// No finding overlaps the span. Leaks.
    Miss,
}

impl Outcome {
    /// Every outcome in lattice order.
    pub const ALL: [Self; 5] = [
        Self::Exact,
        Self::Covered,
        Self::Overbroad,
        Self::Partial,
        Self::Miss,
    ];
}

/// Per-case measurement. The variant is decided by the case, not the scanner:
/// cases with a secret span are positives, cases without are controls, `T0`
/// cases are pending, and a non-complete scanner yields `not-measured`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "type", rename_all = "kebab-case", deny_unknown_fields)]
pub enum CaseMeasurement {
    /// A case with at least one secret span.
    Positive {
        /// One outcome per secret span, in span order.
        span_outcomes: Vec<Outcome>,
        /// Secret bytes not covered by any finding, summed over leaked spans.
        leaked_bytes: u64,
        /// Finding bytes outside every acceptable range (spans or envelopes).
        collateral_bytes: u64,
    },
    /// A case without secret spans (benign control or twin).
    Control {
        /// Whether the case counts as flagged (scoped to the twin's family
        /// for twins; any finding for other controls).
        flagged: bool,
        /// Number of deduplicated findings on the case.
        findings: u64,
        /// Twin only: a finding attributed to a different, known family fired.
        co_detected: bool,
        /// Tally of scanner-reported actions on the case's findings.
        #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
        action_counts: BTreeMap<String, u64>,
    },
    /// `T0`: expectation pending review; observed but never scored.
    Pending,
    /// The scanner produced no usable observation. Never a `MISS`.
    NotMeasured {
        /// The scanner status that prevented measurement.
        status: ScannerStatus,
    },
}

/// Status of a method assertion.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "kebab-case")]
pub enum AssertionStatus {
    /// Assertion held.
    Pass,
    /// Assertion failed.
    Fail,
    /// Expectation pending an authored decision.
    ReviewRequired,
    /// The scanner never observed the variant; consumes denominator.
    NotMeasured,
}

/// Kind of a method assertion.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "kebab-case")]
pub enum AssertionType {
    /// Placeholder type for review-required / not-measured absolute assertions.
    Absolute,
    /// Positive: every span EXACT/COVERED and zero collateral bytes.
    PresentWithinEnvelope,
    /// Control: not flagged.
    Absent,
    /// Relation: baseline and candidate both pass with identical readings.
    SameDetection,
    /// Relation: positive baseline passes and secret-free candidate passes.
    MustFlip,
}

/// A method assertion for one scanner.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Assertion {
    /// Case the assertion belongs to.
    pub case_id: CaseId,
    /// Method that produced it.
    pub method: ComponentId,
    /// Variant, for absolute assertions.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub variant: Option<ComponentId>,
    /// Baseline variant, for relation assertions.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub baseline: Option<ComponentId>,
    /// Candidate variant, for relation assertions.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub candidate: Option<ComponentId>,
    /// Assertion kind.
    pub assertion: AssertionType,
    /// Result.
    pub status: AssertionStatus,
    /// Sanitized reason.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// How a generated variant's expectation was obtained.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "kebab-case")]
pub enum VariantStrategy {
    /// Authored in the evidence (e.g. an authored twin).
    Authored,
    /// Derived by a semantics-preserving operator.
    Derived,
    /// Expectation cannot be derived; the variant is `T0`.
    ReviewRequired,
}

/// Expected relation between a variant and its canonical baseline.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "kebab-case")]
pub enum Relation {
    /// Detection must be unchanged.
    SameDetection,
    /// Detection must disappear.
    MustFlip,
}

/// Lineage and identity of one generated variant.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct VariantRecord {
    /// Case the variant was generated from.
    pub case_id: CaseId,
    /// Variant id within the case (`canonical` or the operator id).
    pub variant: ComponentId,
    /// Materialized path of the variant.
    pub path: FixturePath,
    /// Method and version.
    pub method: MethodIdentity,
    /// Operator id (`identity` for the canonical variant).
    pub operator: ComponentId,
    /// Operator version.
    pub operator_version: u32,
    /// Replay-safe scalar operator parameters.
    #[serde(default)]
    pub parameters: BTreeMap<String, Value>,
    /// Expectation strategy.
    pub strategy: VariantStrategy,
    /// Expected relation to the canonical variant, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relation: Option<Relation>,
    /// Property the operator changes (e.g. `length`, `context`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub property: Option<String>,
    /// Digest of the variant's content bytes.
    pub content_digest: Sha256Digest,
}

/// Status of one differential comparison.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "kebab-case")]
pub enum ComparisonStatus {
    /// Both scanners observed the variant.
    Complete,
    /// At least one scanner did not complete.
    Incomplete,
    /// At least one scanner is unsupported.
    Unsupported,
}

/// Kind of disagreement between a reference scanner and a peer.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "kebab-case")]
pub enum Disagreement {
    /// Identical ranges (and classifications, where comparable).
    None,
    /// Only the reference scanner reported ranges.
    ReferenceOnly,
    /// Only the peer reported ranges.
    PeerOnly,
    /// Both reported ranges, and they differ.
    RangeDisagreement,
    /// Ranges agree; mapped families differ.
    ClassificationDisagreement,
}

/// A differential observation between two scanners on one variant. Neither
/// scanner is ground truth; a disagreement is an observation, not a failure.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DifferentialComparison {
    /// Case id.
    pub case_id: CaseId,
    /// Variant id.
    pub variant: ComponentId,
    /// Reference scanner (run configuration choice, not a truth claim).
    pub reference: ScannerId,
    /// Peer scanner.
    pub peer: ScannerId,
    /// Comparison status.
    pub status: ComparisonStatus,
    /// Disagreement, when `status` is `complete`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub disagreement: Option<Disagreement>,
    /// Whether classifications were comparable (`true`) or not (`false`),
    /// when `status` is `complete`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub classification_compared: Option<bool>,
}

/// One entry of the review queue: an occurrence that needs an authored
/// decision. Neither scanner of a disagreement is ground truth.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ReviewOccurrence {
    /// Stable canonical id. It binds the case, its source digest and the
    /// observation, and excludes every part of the reference scanner's
    /// identity except its id, so reference releases do not re-key reviews.
    pub id: Sha256Digest,
    /// Evaluation case id.
    pub case_id: CaseId,
    /// Method that queued the occurrence.
    pub method: ComponentId,
    /// Variant the occurrence is about.
    pub variant: ComponentId,
    /// Baseline variant, for relation occurrences.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub baseline: Option<ComponentId>,
    /// Candidate variant, for relation occurrences.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub candidate: Option<ComponentId>,
    /// Reference scanner, for differential disagreements.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reference: Option<ScannerId>,
    /// Peer scanner, for differential disagreements.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub peer: Option<ScannerId>,
    /// Disagreement kind, for differential disagreements.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub disagreement: Option<Disagreement>,
}

/// Aggregates for one scanner.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Aggregates {
    /// Case groups keyed `<kind>/<tier>` (e.g. `must-redact/T1`), with all
    /// `T0` cases in `pending/T0`. No cross-group totals.
    pub groups: BTreeMap<String, GroupAggregate>,
    /// Assertion resolution per stratum key `<method>/<kind>:<tier>/<assertion>`.
    #[serde(default)]
    pub resolution: BTreeMap<String, AccountedCounts>,
    /// Per-target groups: for each target family, the `<kind>/<tier>` groups
    /// of the cases that target it, accounted over the corpus groups that
    /// hold them (a selected positive's twin and the selection's `T0` cases
    /// travel with the group; legacy `selectionGroups`).
    #[serde(default)]
    pub by_target: BTreeMap<String, BTreeMap<String, GroupAggregate>>,
    /// Per-target assertion resolution, keyed like `resolution`
    /// (cases without targets count under `unassigned`).
    #[serde(default)]
    pub resolution_by_target: BTreeMap<String, BTreeMap<String, AccountedCounts>>,
}

/// One aggregate group.
// A serialized record held a few per scanner; variant size is irrelevant and
// boxing would only complicate the wire mapping.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "population", rename_all = "kebab-case", deny_unknown_fields)]
pub enum GroupAggregate {
    /// `pending/T0`: counted, never scored.
    Pending {
        /// Number of T0 cases.
        files: u64,
        /// T0 cases by the kind their evidence proposes.
        candidate_kinds: BTreeMap<String, u64>,
    },
    /// `must-not-flag/<tier>`: false-alarm measurement.
    Control {
        /// Control cases.
        files: u64,
        /// Controls counted as flagged.
        flagged_files: u64,
        /// Findings on controls.
        findings: u64,
        /// flagged_files / files, upper Wilson bound.
        false_alarm_rate: Option<Published>,
        /// findings / flagged_files (ratio; no bound).
        mean_findings_per_flagged: Option<Published>,
        /// Exact-match diagnostics.
        diagnostics: ControlDiagnostics,
    },
    /// `must-redact/<tier>` or `policy/<tier>`: span measurements.
    Positive {
        /// Scored cases in the group.
        files: u64,
        /// Secret spans.
        spans: u64,
        /// Secret bytes.
        secret_bytes: u64,
        /// Span outcome counts.
        outcomes: OutcomeCounts,
        /// T0 cases whose proposed kind is this group's kind.
        pending_files: u64,
        /// files / (files + pending_files), lower bound.
        measurable_share: Option<Published>,
        /// Authored envelope widening over secret spans.
        envelope_width: EnvelopeWidth,
        /// Spans with a leaking outcome (PARTIAL or MISS).
        leaked_spans: u64,
        /// leaked_spans / spans, upper bound.
        leaked_span_rate: Option<Published>,
        /// Leaked secret bytes.
        leaked_bytes: u64,
        /// leaked_bytes / secret_bytes, upper bound.
        leaked_byte_rate: Option<Published>,
        /// Collateral finding bytes.
        collateral_bytes: u64,
        /// collateral_bytes / secret_bytes (ratio; no bound).
        collateral_ratio: Option<Published>,
        /// Twin discrimination.
        twins: TwinMeasurement,
        /// Exact-match diagnostics.
        diagnostics: PositiveDiagnostics,
    },
}

/// Span outcome counts, keyed by outcome name.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OutcomeCounts {
    /// EXACT spans.
    #[serde(rename = "EXACT")]
    pub exact: u64,
    /// COVERED spans.
    #[serde(rename = "COVERED")]
    pub covered: u64,
    /// OVERBROAD spans.
    #[serde(rename = "OVERBROAD")]
    pub overbroad: u64,
    /// PARTIAL spans.
    #[serde(rename = "PARTIAL")]
    pub partial: u64,
    /// MISS spans.
    #[serde(rename = "MISS")]
    pub miss: u64,
}

impl OutcomeCounts {
    /// Increment the counter for `outcome`.
    pub fn add(&mut self, outcome: Outcome) {
        match outcome {
            Outcome::Exact => self.exact += 1,
            Outcome::Covered => self.covered += 1,
            Outcome::Overbroad => self.overbroad += 1,
            Outcome::Partial => self.partial += 1,
            Outcome::Miss => self.miss += 1,
        }
    }

    /// Total spans counted.
    pub const fn total(&self) -> u64 {
        self.exact + self.covered + self.overbroad + self.partial + self.miss
    }
}

/// Envelope widening statistics.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EnvelopeWidth {
    /// Secret spans carrying an envelope.
    pub spans: u64,
    /// Sum of (envelope length - span length).
    pub bytes: u64,
}

/// Twin discrimination measurement for a positive group.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TwinMeasurement {
    /// Scored positives in the group (the twin denominator population).
    pub positives: u64,
    /// Scored (positive, twin) pairs.
    pub pairs: u64,
    /// Pairs where every positive span is EXACT/COVERED and the twin is not flagged.
    pub discriminated: u64,
    /// Pairs whose twin was co-detected by a different known family.
    pub co_detected: u64,
    /// pairs / positives, lower bound.
    pub coverage: Option<Published>,
    /// discriminated / pairs, lower bound; withheld when unmeasurable or under-covered.
    pub rate: Option<Published>,
}

/// Exact-match diagnostics for controls.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ControlDiagnostics {
    /// Findings on controls.
    pub fp: u64,
    /// Controls not flagged.
    pub tn: u64,
}

/// Exact-match diagnostics for positives (not comparable across scanners).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PositiveDiagnostics {
    /// EXACT spans.
    pub tp: u64,
    /// Findings not exactly equal to any secret span.
    pub fp: u64,
    /// Secret spans not EXACT.
    #[serde(rename = "fn")]
    pub fn_: u64,
}

/// Resolution counts for a stratum of assertions.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AccountedCounts {
    /// Passed assertions.
    pub pass: u64,
    /// Failed assertions.
    pub fail: u64,
    /// Assertions awaiting review.
    #[serde(rename = "review-required")]
    pub review_required: u64,
    /// Assertions never observed.
    #[serde(rename = "not-measured")]
    pub not_measured: u64,
    /// All assertions.
    pub total: u64,
    /// pass + fail.
    pub resolved: u64,
    /// total - resolved.
    pub unresolved: u64,
    /// resolved / total, lower bound.
    pub resolved_rate: Option<Published>,
}

/// A published figure: a rate with its pessimistic bound, or an explicit
/// withholding. Where a figure is nullable, `null` means a zero denominator.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(untagged)]
pub enum Published {
    /// A computed figure.
    Rate(Rate),
    /// A withheld figure.
    Withheld(Withheld),
}

/// A computed proportion or ratio.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Rate {
    /// Point estimate, rounded to `interval_precision`.
    pub point: f64,
    /// Pessimistic Wilson endpoint; `null` for unbounded ratios.
    pub bound: Option<f64>,
    /// Sample size the bound was computed with.
    pub n: u64,
    /// Which side is pessimistic; `null` for ratios.
    pub direction: Option<BoundDirection>,
}

/// Side of a Wilson bound.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum BoundDirection {
    /// Upper bound (lower is better).
    Upper,
    /// Lower bound (higher is better).
    Lower,
}

/// Why a figure is withheld.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum Withheld {
    /// Denominator below `min_denominator`, or measurable share below its floor.
    InsufficientEvidence,
    /// Twin coverage below its floor.
    InsufficientCoverage,
}

/// Non-semantic run metadata. Two runs of identical inputs may differ here
/// and nowhere else.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct NonSemantic {
    /// Run identifier.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub run_id: Option<String>,
    /// RFC 3339 start time.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub started_at: Option<String>,
    /// RFC 3339 finish time.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub finished_at: Option<String>,
    /// Host diagnostics (OS/arch); never paths or usernames.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    /// Scanner wall-clock durations in milliseconds, by scanner id.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub durations_ms: BTreeMap<String, u64>,
    /// How the run was scheduled and where its time went.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub execution: Option<ExecutionDiagnostics>,
}

/// Scheduling and timing diagnostics of a run. Never measurements.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ExecutionDiagnostics {
    /// Effective global job bound the run was scheduled with.
    pub jobs: u32,
    /// Scanner process invocations that ran (version probes and scans).
    pub processes: u64,
    /// Wall-clock time of the whole run, in milliseconds.
    pub wall_ms: u64,
    /// Sum of scanner process wall-clock times, in milliseconds. With
    /// parallel jobs this can exceed `wall_ms`.
    pub scanner_process_ms: u64,
    /// Evaluator-owned time, in milliseconds: corpus loading, materialization,
    /// output normalization, scoring and serialization (summed over jobs).
    pub evaluator_ms: u64,
}

impl RunArtifact {
    /// Sort every collection by its semantic key (the determinism rule).
    pub fn canonicalize(&mut self) {
        self.manifest.methods.sort();
        self.manifest.scanners.sort_by(|a, b| a.id.cmp(&b.id));
        self.scanners.sort_by(|a, b| a.scanner.cmp(&b.scanner));
        for run in &mut self.scanners {
            run.findings.sort();
            run.findings.dedup();
            run.cases.sort_by(|a, b| a.case_id.cmp(&b.case_id));
            for case in &mut run.cases {
                case.actual.sort();
            }
            run.assertions.sort();
        }
        self.variants
            .sort_by(|a, b| (&a.case_id, &a.variant).cmp(&(&b.case_id, &b.variant)));
        self.comparisons.sort();
        self.review_queue.sort();
        self.review_queue.dedup();
    }

    /// Digest of the semantic content: the canonical JSON of the artifact with
    /// [`NonSemantic`] cleared. Identical inputs must yield identical digests.
    pub fn semantic_digest(&self) -> Sha256Digest {
        let mut copy = self.clone();
        copy.canonicalize();
        copy.non_semantic = NonSemantic::default();
        sha256_canonical(&copy)
    }
}
