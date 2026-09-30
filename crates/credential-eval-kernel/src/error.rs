//! Kernel errors. Every error is a fail-closed refusal with a fixed,
//! sanitized message: no fixture bytes, matched values or scanner output.

use std::fmt;

use credential_eval_contracts::ContractError;

/// A refusal raised by the measurement kernel.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KernelError {
    /// An input violated its contract.
    Contract(ContractError),
    /// Accounting parameters are outside their documented domain
    /// (legacy `validateAccounting`, `evaluation/domains/credential/accounting.ts:43-54`).
    InvalidAccounting(&'static str),
    /// A case's measurement is inconsistent with its population (e.g. a
    /// `must-redact` case without a secret span). Legacy crashes or emits
    /// `NaN` here; the kernel refuses.
    InconsistentCase {
        /// Case id.
        case: String,
        /// Fixed reason.
        reason: &'static str,
    },
    /// The twin denominator did not reconcile with the positive population
    /// (`lattice.ts:178-180`).
    TwinDenominator,
    /// An unattributed v1.0 → v1.1 accounting delta (`accounting.ts:149`).
    UnattributedDelta(String),
    /// A family has authored twins and an un-probeable record (`twin-probe.ts:30`).
    UnprobeableWithTwins(String),
    /// Evaluation case or generated variant refused (legacy `validateCase`,
    /// `variant`, `generateCase`; `engine/model.ts:21-62`).
    InvalidEvaluationCase {
        /// Evaluation case id (or seed id when the case id is not built yet).
        case: String,
        /// Fixed reason.
        reason: &'static str,
    },
    /// Generation exceeded an explicit bound.
    GenerationLimit {
        /// Which bound.
        limit: &'static str,
        /// Its configured value.
        value: usize,
    },
    /// Two evaluation inputs share a path, or the case list is empty/duplicated
    /// (`evaluation/substrate/case-lifecycle.ts:4-14`).
    InvalidInputs(&'static str),
    /// An operator or method id is not registered.
    Unknown {
        /// `operator` or `method`.
        kind: &'static str,
        /// The id.
        id: String,
    },
}

impl fmt::Display for KernelError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Contract(error) => write!(f, "{error}"),
            Self::InvalidAccounting(reason) => {
                write!(f, "invalid accounting configuration: {reason}")
            }
            Self::InconsistentCase { case, reason } => {
                write!(f, "inconsistent case {case}: {reason}")
            }
            Self::TwinDenominator => {
                f.write_str("twin denominator does not agree with the positive population")
            }
            Self::UnattributedDelta(group) => write!(f, "unattributed accounting delta: {group}"),
            Self::UnprobeableWithTwins(family) => {
                write!(f, "un-probeable family with twins: {family}")
            }
            Self::InvalidEvaluationCase { case, reason } => {
                write!(f, "invalid evaluation case {case}: {reason}")
            }
            Self::GenerationLimit { limit, value } => {
                write!(f, "generation exceeded {limit} (limit {value})")
            }
            Self::InvalidInputs(reason) => write!(f, "invalid evaluation inputs: {reason}"),
            Self::Unknown { kind, id } => write!(f, "unknown {kind}: {id}"),
        }
    }
}

impl std::error::Error for KernelError {}

impl From<ContractError> for KernelError {
    fn from(error: ContractError) -> Self {
        Self::Contract(error)
    }
}
