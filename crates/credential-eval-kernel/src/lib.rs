//! Measurement kernel for `credential-eval`.
//!
//! Status: foundation only (issue #2). [`lattice`] is an exact port of the
//! legacy span lattice and row scorer (`benchmarks/lib/lattice.ts`), and
//! [`score`] applies it to a snapshot and one scanner observation so the
//! output contract can be exercised end to end. Accounting (`accountGroups`),
//! twin probes, the evaluation methods and bounded orchestration arrive with
//! issue #3; see `docs/migration/legacy-map.md` for the porting inventory.

#![forbid(unsafe_code)]

pub mod lattice;
pub mod score;
