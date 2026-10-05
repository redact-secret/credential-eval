//! Scanner-neutral performance measurement support (ADR 0002).
//!
//! * [`workloads`]: deterministic, bounded, synthetic inputs;
//! * [`stats`]: timing summaries and the direction rule;
//! * [`confirm`]: combining independent latency runs into confirmed directions;
//! * [`reuse`]: performance reuse identity, evidence lookup and dry-run planning
//!   (ADR 0010);
//! * [`host`]: host and load-average diagnostics.
//!
//! Nothing here executes a scanner or counts allocations: the latency runner
//! lives in `credential-eval-cli`, and allocation counting lives in the
//! separate `measurements/redact-secret-alloc` package, outside this
//! workspace. This crate contains no `unsafe` and no scanner-specific code.

#![forbid(unsafe_code)]

pub mod confirm;
pub mod host;
pub mod reuse;
pub mod stats;
pub mod workloads;
