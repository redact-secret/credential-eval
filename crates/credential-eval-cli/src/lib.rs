//! Library side of the `credential-eval` CLI: run orchestration and the
//! built-in default configuration. The binary in `main.rs` only parses
//! arguments and writes files.

#![forbid(unsafe_code)]

pub mod evidence;
pub mod orchestrate;
pub mod time;

use std::collections::BTreeMap;

use credential_eval_contracts::config::{AccountingConfig, ExecutionBounds, Floor, RunConfig};
use credential_eval_contracts::schema::RunConfigSchema;

/// Legacy engine v1.1 accounting parameters (`qualification/suite-v1.json`
/// at the pinned oracle commit). Measurement rules, not support thresholds.
pub fn default_accounting() -> AccountingConfig {
    let keyed = |default: f64, key: &str, value: f64| Floor::Keyed {
        default,
        overrides: BTreeMap::from([(key.to_owned(), value)]),
    };
    AccountingConfig {
        min_denominator: 5,
        resolved_rate_floor: keyed(0.9, "differential", 0.0),
        measurable_share_floor: keyed(0.7, "policy", 0.0),
        twin_coverage_floor: keyed(0.5, "policy", 0.0),
        replays: 2,
        interval_z: 1.96,
        interval_precision: 6,
    }
}

/// A run configuration with each built-in adapter's default spec, for the
/// given scanner ids (all built-in scanners when empty).
pub fn default_config(scanners: &[String], jobs: u32) -> Result<RunConfig, String> {
    let adapters = credential_eval_adapters::builtin();
    let specs = if scanners.is_empty() {
        adapters.iter().map(|a| a.default_spec()).collect()
    } else {
        scanners
            .iter()
            .map(|id| {
                adapters
                    .iter()
                    .find(|a| a.identity().id.as_str() == id)
                    .map(|a| a.default_spec())
                    .ok_or_else(|| {
                        format!(
                            "unknown scanner {id:?}; built-in scanners: {}",
                            builtin_ids()
                        )
                    })
            })
            .collect::<Result<Vec<_>, _>>()?
    };
    Ok(RunConfig {
        schema: RunConfigSchema,
        scanners: specs,
        methods: Vec::new(),
        execution: ExecutionBounds { jobs },
        accounting: default_accounting(),
        evaluation: None,
    })
}

/// Comma-separated built-in adapter ids.
pub fn builtin_ids() -> String {
    credential_eval_adapters::builtin()
        .iter()
        .map(|a| a.identity().id.to_string())
        .collect::<Vec<_>>()
        .join(", ")
}
