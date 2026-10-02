//! Scanner-neutral performance measurement support (ADR 0002).
//!
//! * [`workloads`]: deterministic, bounded, synthetic inputs;
//! * [`stats`]: timing summaries and the direction rule;
//! * [`host`]: host and load-average diagnostics.
//!
//! Nothing here executes a scanner or counts allocations: the latency runner
//! lives in `credential-eval-cli`, and allocation counting lives in the
//! separate `measurements/redact-secret-alloc` package, outside this
//! workspace. This crate contains no `unsafe` and no scanner-specific code.

#![forbid(unsafe_code)]

pub mod host;
pub mod stats;
pub mod workloads;
