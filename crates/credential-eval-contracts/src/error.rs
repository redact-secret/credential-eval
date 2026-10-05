//! Contract validation errors.
//!
//! Messages identify cases, paths and offsets only. They never echo fixture
//! content or scanner output, so they are safe to log.

use std::fmt;

/// A violation of the input or output contract.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ContractError {
    /// An identifier does not match its documented grammar.
    InvalidId { kind: &'static str, value: String },
    /// A document declared a schema tag other than the expected one.
    SchemaMismatch {
        expected: &'static str,
        found: String,
    },
    /// A snapshot contains no cases.
    EmptyCorpus,
    /// Two cases share an id.
    DuplicateCaseId(String),
    /// A fixture path is unsafe (absolute, traversal, bad characters) or duplicated.
    UnsafeOrDuplicatePath { case: String },
    /// A range is empty, out of bounds, or not on a UTF-8 code point boundary.
    InvalidRange { case: String, start: u64, end: u64 },
    /// Expected spans are not sorted and disjoint.
    UnorderedSpans { case: String },
    /// An envelope does not contain its span, has no reason, or overlaps another span.
    InvalidEnvelope { case: String },
    /// Twin lineage is inconsistent.
    InvalidTwin { case: String, reason: &'static str },
    /// The declared corpus digest does not match the recomputed one.
    CorpusDigestMismatch { declared: String, computed: String },
    /// Observations were recorded against a different corpus.
    StaleObservations { expected: String, found: String },
    /// Observations were made over different fixture paths or bytes.
    StaleInputs { expected: String, found: String },
    /// Observations record no measurement binding (written before v1.6).
    UnboundObservations,
    /// A normalized finding names an unknown path or an invalid range.
    InvalidFinding { path: String, start: u64, end: u64 },
    /// An unmeasured path is unknown, unsorted or duplicated, or a finding is
    /// reported on a path the same observation declares unmeasured.
    InvalidUnmeasured { path: String },
    /// Scanner ids are duplicated or empty.
    DuplicateScanner(String),
    /// A representation fact is malformed or inconsistent (revision v1.3).
    InvalidRepresentation { case: String, reason: &'static str },
    /// A snapshot carries representation facts without declaring the contract.
    RepresentationUndeclared,
}

impl fmt::Display for ContractError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidId { kind, value } => write!(f, "invalid {kind} id: {value:?}"),
            Self::SchemaMismatch { expected, found } => {
                write!(f, "schema mismatch: expected {expected}, found {found}")
            }
            Self::EmptyCorpus => write!(f, "corpus snapshot has no cases"),
            Self::DuplicateCaseId(id) => write!(f, "duplicate case id: {id}"),
            Self::UnsafeOrDuplicatePath { case } => {
                write!(f, "unsafe or duplicate fixture path in case {case}")
            }
            Self::InvalidRange { case, start, end } => {
                write!(
                    f,
                    "invalid UTF-8 byte range [{start}, {end}) in case {case}"
                )
            }
            Self::UnorderedSpans { case } => {
                write!(
                    f,
                    "expected spans are not sorted and disjoint in case {case}"
                )
            }
            Self::InvalidEnvelope { case } => write!(f, "invalid envelope in case {case}"),
            Self::InvalidTwin { case, reason } => write!(f, "invalid twin {case}: {reason}"),
            Self::CorpusDigestMismatch { declared, computed } => {
                write!(
                    f,
                    "corpus digest mismatch: declared {declared}, computed {computed}"
                )
            }
            Self::StaleObservations { expected, found } => write!(
                f,
                "observations were recorded for corpus {found}, expected {expected}"
            ),
            Self::StaleInputs { expected, found } => write!(
                f,
                "observations were made over fixture inputs {found}, expected {expected}"
            ),
            Self::UnboundObservations => {
                write!(
                    f,
                    "observations record no measurement binding (input digest)"
                )
            }
            Self::InvalidFinding { path, start, end } => {
                write!(f, "invalid normalized finding {path}:[{start}, {end})")
            }
            Self::InvalidUnmeasured { path } => {
                write!(f, "invalid unmeasured path {path}")
            }
            Self::DuplicateScanner(id) => write!(f, "duplicate or empty scanner id: {id}"),
            Self::InvalidRepresentation { case, reason } => {
                write!(f, "invalid representation in case {case}: {reason}")
            }
            Self::RepresentationUndeclared => write!(
                f,
                "the snapshot carries representation facts but does not declare identity.representation"
            ),
        }
    }
}

impl std::error::Error for ContractError {}
