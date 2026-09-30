//! Scanner adapters for `credential-eval`.
//!
//! Status: placeholder (issue #2). The adapter API and the ports of the legacy
//! adapters (`scanners/index.mjs`) arrive with issue #4. An adapter's output
//! is a [`credential_eval_contracts::observation::ScannerObservation`]:
//! normalized half-open UTF-8 byte ranges, an explicit execution status, and
//! the scanner/adapter identity. Adapters never score.

#![forbid(unsafe_code)]

pub use credential_eval_contracts::observation::{
    NormalizedFinding, ObservationResult, ScannerIdentity, ScannerObservation,
};
