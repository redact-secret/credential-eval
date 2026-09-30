//! Measurement kernel for `credential-eval`.
//!
//! A faithful port of the legacy measurement engine
//! (`redact-secret-benchmarks@c403475`, see `docs/migration/legacy-map.md`),
//! made scanner-neutral:
//!
//! * [`lattice`]: the span outcome lattice and row scorer (protocol 1).
//! * [`score`]: per-case scoring of one scanner observation and the
//!   canonical run artifact.
//! * [`accounting`]: engine v1.1 group accounting, Wilson bounds,
//!   withholding floors, resolution and the cross-suite selection rule.
//! * [`twin_probe`]: per-family twin discrimination states.
//! * [`evaluation`]: twin, benign, mutation, metamorphic and differential
//!   methods, deterministic bounded variant generation, assertions and the
//!   scanner-neutral review queue.
//! * [`observe`]: pure helpers for adapters and orchestration (replay
//!   agreement, classification allowlist).
//! * [`compat`]: isolated legacy-only views for parity (v1.0 figures,
//!   accounting delta, legacy labels). Removable.
//!
//! Intentional deviations from legacy are listed in
//! `docs/migration/kernel-deltas.md`.

#![forbid(unsafe_code)]

pub mod accounting;
pub mod compat;
mod error;
pub mod evaluation;
pub mod jsnum;
pub mod lattice;
pub mod observe;
pub mod score;
pub mod twin_probe;

pub use error::KernelError;
