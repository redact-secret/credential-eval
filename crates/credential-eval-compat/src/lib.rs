//! Legacy compatibility for the credential-eval migration (issue #5).
//!
//! **Migration-only and removable.** Nothing in the contracts, kernel or
//! adapters depends on this crate; only the CLI's `compat` surface does
//! (`credential-eval compat ...`, `run --legacy-eval-out`, and the
//! `legacy:*` validator names an evidence file may reference). Delete the
//! crate and that surface once nothing reads the legacy result schemas of
//! `redact-secret-benchmarks@c403475` any more
//! (`docs/migration/redact-secret-cutover.md` §4-§5).
//!
//! * [`validators`]: the value validators of the legacy format-contract table,
//!   ported so a migration evidence file can name them.
//! * [`bench`]: renders a canonical `RunArtifact` of the exported legacy corpus
//!   into the legacy `bench` result files (`public/results/<category>.json`
//!   and `summary.json`, legacy-map §4.1-4.2).
//! * [`eval`]: renders an evaluation report into the legacy `eval` result
//!   shape (`results-output/evaluation.json`, legacy-map §4.3), restricted to
//!   the semantic fields parity compares.
//!
//! The canonical artifact is never folded or reshaped by this crate; it only
//! reads kernel and contract types.

#![forbid(unsafe_code)]

pub mod bench;
pub mod eval;
pub mod validators;

use serde_json::{Map, Value};

/// Legacy field spelling: `snake_case` object keys become `camelCase`
/// (recursively). Map keys that are data (families, group keys, operator
/// ids) never contain `_` in the legacy corpus, so they pass unchanged.
pub(crate) fn camel(value: Value) -> Value {
    match value {
        Value::Object(map) => Value::Object(
            map.into_iter()
                .map(|(k, v)| (camel_key(&k), camel(v)))
                .collect::<Map<String, Value>>(),
        ),
        Value::Array(items) => Value::Array(items.into_iter().map(camel).collect()),
        other => other,
    }
}

fn camel_key(key: &str) -> String {
    let mut out = String::with_capacity(key.len());
    let mut upper = false;
    for c in key.chars() {
        if c == '_' {
            upper = true;
        } else if upper {
            out.push(c.to_ascii_uppercase());
            upper = false;
        } else {
            out.push(c);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn keys_are_camel_cased_recursively() {
        assert_eq!(
            camel(
                json!({"false_alarm_rate": 1, "twins": [{"co_detected": 2}], "must-redact/T1": {}})
            ),
            json!({"falseAlarmRate": 1, "twins": [{"coDetected": 2}], "must-redact/T1": {}})
        );
    }
}
