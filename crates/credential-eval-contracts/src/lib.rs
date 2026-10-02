//! Scanner-neutral input/output contracts for `credential-eval`.
//!
//! This crate owns the serialized boundary of the evaluator and nothing else:
//!
//! * **Input**: [`corpus::CorpusSnapshot`] (cases, authored ranges, envelopes,
//!   grouping metadata, twin lineage, corpus identity),
//!   [`config::RunConfig`] (scanner execution inputs and accounting
//!   parameters) and [`observation::ObservationSet`] (normalized scanner
//!   observations, as produced by an adapter or replayed from a snapshot).
//! * **Output**: [`artifact::RunArtifact`] (run manifest/provenance, normalized
//!   findings, per-case outcomes, measurements, aggregates and explicit
//!   scanner failure states).
//!
//! Measurement semantics (the outcome lattice, accounting and evaluation
//! methods) live in `credential-eval-kernel`; scanner-specific execution and
//! parsing live in `credential-eval-adapters`. No type here carries a product
//! support status or release decision.
//!
//! All ranges are half-open `[start, end)` UTF-8 byte offsets into the case
//! content; see [`range`] and `docs/contracts/ranges.md`.

#![forbid(unsafe_code)]

pub mod artifact;
pub mod canonical;
pub mod config;
pub mod corpus;
pub mod error;
pub mod ids;
pub mod observation;
pub mod performance;
pub mod range;
pub mod schema;

pub use error::ContractError;

/// Version of the measurement protocol: the outcome lattice, byte-range
/// convention, accounting rules and failure-state semantics.
///
/// This is deliberately independent of the crate (implementation) version.
/// Changing it requires a reviewed protocol revision; refactors never do.
/// Protocol 1 is the faithful port of the legacy `measurement-v4` lattice and
/// engine v1.1 accounting (see `docs/migration/legacy-map.md`).
pub const PROTOCOL_VERSION: &str = "credential-eval-protocol/1";

/// Legacy measurement lineage that [`PROTOCOL_VERSION`] 1 reproduces. Recorded
/// so parity artifacts can name the oracle semantics they were compared with.
pub const LEGACY_MEASUREMENT_PROFILE: &str = "measurement-v4";
/// Legacy accounting version reproduced by protocol 1.
pub const LEGACY_ACCOUNTING_VERSION: &str = "1.1";

/// Engine name recorded in run manifests.
pub const ENGINE_NAME: &str = "credential-eval";

/// Implementation version of this contracts crate (not a protocol version).
pub const CONTRACTS_CRATE_VERSION: &str = env!("CARGO_PKG_VERSION");
