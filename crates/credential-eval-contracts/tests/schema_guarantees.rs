//! Schema-level guarantees of the v1 contracts:
//!
//! 1. **No plaintext, no raw output.** No property of any v1 schema is named
//!    like something that would carry a matched value or raw scanner output
//!    (`value`, `match`, `secret`, `raw`, `stdout`, `stderr`, `line`, `text`,
//!    ...), and no property is a free-form string or free-form JSON value,
//!    unless it is listed in [`ALLOWLIST`] with the reason it cannot carry
//!    either. The allowlist is the documented exception list
//!    (`docs/contracts/README.md`, "No plaintext or raw output"); a new
//!    property that matches neither rule fails here until it is reviewed and
//!    listed.
//! 2. **Reproduction identities are present.** The run artifact schema requires
//!    every identity listed in `docs/contracts/identity.md`.

use std::collections::BTreeSet;

use credential_eval_contracts::schema::all_schemas;
use serde_json::{Value, json};

/// Name tokens (split on `_` and `-`) that suggest matched values or raw
/// scanner output.
const FORBIDDEN_TOKENS: [&str; 20] = [
    "value",
    "values",
    "match",
    "matched",
    "matches",
    "secret",
    "secrets",
    "raw",
    "stdout",
    "stderr",
    "plaintext",
    "snippet",
    "excerpt",
    "line",
    "text",
    "content",
    "output",
    "password",
    "token",
    "redacted",
];

const INPUTS: &[&str] = &[
    "corpus-snapshot-v1.schema.json",
    "run-config-v1.schema.json",
];
const OBSERVATIONS_AND_ARTIFACT: &[&str] = &[
    "observation-set-v1.schema.json",
    "run-artifact-v1.schema.json",
];
const CORPUS: &[&str] = &["corpus-snapshot-v1.schema.json"];
const CONFIG: &[&str] = &["run-config-v1.schema.json"];
const CORPUS_AND_ARTIFACT: &[&str] = &[
    "corpus-snapshot-v1.schema.json",
    "run-artifact-v1.schema.json",
];
const ARTIFACT: &[&str] = &["run-artifact-v1.schema.json"];
const CONFIG_OBSERVATIONS_ARTIFACT: &[&str] = &[
    "run-config-v1.schema.json",
    "observation-set-v1.schema.json",
    "run-artifact-v1.schema.json",
];

/// `(definition.property, schema files it may appear in, reason)`.
///
/// Reasons fall into five sources: evidence input (synthetic or documented
/// public-test material owned by `credential-evidence`), run configuration
/// (operator input, recorded verbatim), engine or adapter code (fixed
/// strings and identifiers), byte counts or digests (a name hit, not a
/// value), and scanner-reported labels mapped or passed through by adapters.
const ALLOWLIST: &[(&str, &[&str], &str)] = &[
    // Evidence input. Fixture text exists only in the corpus snapshot input;
    // the run artifact never embeds it (it embeds ranges and digests).
    (
        "Case.content",
        CORPUS,
        "evidence input: the synthetic fixture text the ranges index; never copied into observations or artifacts",
    ),
    (
        "Envelope.reason",
        CORPUS,
        "evidence input: authored envelope rationale; artifacts drop it (ScoredSpan carries ranges only)",
    ),
    (
        "TwinLineage.mutation",
        CORPUS,
        "evidence input: authored description of the twin mutation; not copied into artifacts",
    ),
    (
        "TwinLineage.mutation_kind",
        CORPUS,
        "evidence input: authored mutation-kind label",
    ),
    (
        "Grouping.group",
        CORPUS,
        "evidence input: corpus group label",
    ),
    (
        "Grouping.family",
        CORPUS,
        "evidence input: format-contract family label",
    ),
    (
        "Grouping.targets",
        CORPUS,
        "evidence input: target family labels",
    ),
    (
        "Grouping.taxonomy",
        CORPUS,
        "evidence input: benign taxonomy axis label",
    ),
    (
        "Grouping.evidence_class",
        CORPUS,
        "evidence input: evidence class label",
    ),
    (
        "CaseResult.group",
        ARTIFACT,
        "copied from evidence input Grouping.group (P1)",
    ),
    (
        "CaseResult.family",
        ARTIFACT,
        "copied from evidence input Grouping.family",
    ),
    (
        "CaseResult.targets",
        ARTIFACT,
        "copied from evidence input Grouping.targets (P1)",
    ),
    (
        "CaseResult.taxonomy",
        ARTIFACT,
        "copied from evidence input Grouping.taxonomy (P1)",
    ),
    (
        "CaseResult.evidence_class",
        ARTIFACT,
        "copied from evidence input Grouping.evidence_class (P1)",
    ),
    (
        "CaseResult.twin_mutation_kind",
        ARTIFACT,
        "copied from evidence input TwinLineage.mutation_kind (P1)",
    ),
    (
        "SnapshotIdentity.source",
        CORPUS_AND_ARTIFACT,
        "evidence identity: source name",
    ),
    (
        "SnapshotIdentity.revision",
        CORPUS_AND_ARTIFACT,
        "evidence identity: commit or tag",
    ),
    (
        "SnapshotIdentity.evidence_schema",
        CORPUS_AND_ARTIFACT,
        "evidence identity: format label",
    ),
    // Run configuration (operator input, recorded verbatim and hashed).
    (
        "ScannerSpec.configuration",
        CONFIG,
        "run configuration: adapter settings; must not contain credentials (config.rs); only its digest reaches artifacts",
    ),
    (
        "ScannerSpec.mode",
        CONFIG,
        "run configuration: human-readable mode label",
    ),
    (
        "ScannerIdentity.mode",
        OBSERVATIONS_AND_ARTIFACT,
        "copied from run configuration ScannerSpec.mode",
    ),
    (
        "AdapterIdentity.version",
        CONFIG_OBSERVATIONS_ARTIFACT,
        "adapter implementation version, fixed in adapter code and checked against the configuration",
    ),
    (
        "ScannerLimits.max_stdout_bytes",
        CONFIG,
        "a byte limit, not output",
    ),
    (
        "ScannerLimits.max_stderr_bytes",
        CONFIG,
        "a byte limit, not output",
    ),
    // Engine and adapter code.
    (
        "EngineIdentity.name",
        ARTIFACT,
        "engine code: constant ENGINE_NAME",
    ),
    (
        "EngineIdentity.version",
        ARTIFACT,
        "engine code: crate version",
    ),
    (
        "RunManifest.protocol_version",
        ARTIFACT,
        "engine code: constant PROTOCOL_VERSION",
    ),
    (
        "ObservationResult.reason",
        &["observation-set-v1.schema.json"],
        "adapter code: fixed sanitized reason strings; raw output is dropped before a reason is chosen",
    ),
    (
        "ScannerRun.detail",
        ARTIFACT,
        "engine code: the fixed sanitized reason of a non-complete scanner",
    ),
    (
        "Assertion.reason",
        ARTIFACT,
        "engine code: fixed reason text composed with ids, never finding text",
    ),
    (
        "VariantRecord.property",
        ARTIFACT,
        "engine code: the operator's property label (e.g. length, context)",
    ),
    (
        "VariantRecord.parameters",
        ARTIFACT,
        "engine code: replay-safe operator parameters; the kernel keeps boolean and number values only (safe_parameters), never text",
    ),
    (
        "ScannerProvenance.network_controls",
        OBSERVATIONS_AND_ARTIFACT,
        "adapter code: the fixed flags the adapter passed",
    ),
    (
        "ProvenanceComponent.name",
        OBSERVATIONS_AND_ARTIFACT,
        "adapter code: configured program name or npm package name, never a host path",
    ),
    (
        "ProvenanceComponent.version",
        OBSERVATIONS_AND_ARTIFACT,
        "declared or probed component version",
    ),
    (
        "ProvenanceComponent.integrity",
        OBSERVATIONS_AND_ARTIFACT,
        "npm lockfile Subresource Integrity string (a digest)",
    ),
    (
        "ScannerIdentity.version",
        OBSERVATIONS_AND_ARTIFACT,
        "scanner version: the first semantic-version match of the version probe (version_number) or the package's declared version; never raw probe output",
    ),
    (
        "NonSemantic.run_id",
        ARTIFACT,
        "non-semantic run identifier",
    ),
    (
        "NonSemantic.started_at",
        ARTIFACT,
        "non-semantic RFC 3339 timestamp",
    ),
    (
        "NonSemantic.finished_at",
        ARTIFACT,
        "non-semantic RFC 3339 timestamp",
    ),
    (
        "NonSemantic.host",
        ARTIFACT,
        "non-semantic OS-arch pair; never paths or user names",
    ),
    // Counts and digests whose names hit a forbidden token.
    (
        "GroupAggregate.secret_bytes",
        ARTIFACT,
        "a byte count, not a value",
    ),
    (
        "VariantRecord.content_digest",
        ARTIFACT,
        "a SHA-256 digest of the variant bytes, not the bytes",
    ),
    // Scanner-reported labels on findings.
    (
        "NormalizedFinding.family",
        OBSERVATIONS_AND_ARTIFACT,
        "adapter-mapped family from the adapter's fixed family tables; unmapped rules carry none",
    ),
    (
        "ObservedRange.family",
        ARTIFACT,
        "copied from NormalizedFinding.family",
    ),
    (
        "NormalizedFinding.action",
        OBSERVATIONS_AND_ARTIFACT,
        "scanner-reported disposition label (e.g. redact, warn, block) passed through by the adapter; residual risk documented in docs/contracts/README.md",
    ),
    (
        "ObservedRange.action",
        ARTIFACT,
        "copied from NormalizedFinding.action",
    ),
];

/// Whether `schema` admits arbitrary strings or arbitrary JSON.
fn free_form(schema: &Value) -> bool {
    let Some(map) = schema.as_object() else {
        return schema == &Value::Bool(true);
    };
    if map.contains_key("$ref") {
        return false;
    }
    let constrained = |s: &serde_json::Map<String, Value>| {
        ["pattern", "enum", "const"]
            .iter()
            .any(|k| s.contains_key(*k))
    };
    let types: BTreeSet<&str> = match map.get("type") {
        Some(Value::String(t)) => BTreeSet::from([t.as_str()]),
        Some(Value::Array(list)) => list.iter().filter_map(Value::as_str).collect(),
        _ => BTreeSet::new(),
    };
    let branches: Vec<&Value> = ["oneOf", "anyOf"]
        .iter()
        .filter_map(|k| map.get(*k).and_then(Value::as_array))
        .flatten()
        .collect();
    if types.is_empty() && branches.is_empty() && !constrained(map) {
        return true;
    }
    if types.contains("string") && !constrained(map) {
        return true;
    }
    if types.contains("array") && map.get("items").is_some_and(free_form) {
        return true;
    }
    if types.contains("object") && !map.contains_key("properties") {
        match map.get("additionalProperties") {
            None | Some(Value::Bool(true)) => return true,
            Some(values) if values.is_object() && free_form(values) => return true,
            _ => {}
        }
    }
    branches.into_iter().any(free_form)
}

fn forbidden_name(name: &str) -> bool {
    name.to_ascii_lowercase()
        .split(['_', '-'])
        .any(|token| FORBIDDEN_TOKENS.contains(&token))
}

/// Every `(definition.property)` of `schema` that needs an allowlist entry.
fn flagged(schema: &Value) -> BTreeSet<String> {
    fn walk(location: &str, node: &Value, out: &mut BTreeSet<String>) {
        let Some(map) = node.as_object() else { return };
        if let Some(properties) = map.get("properties").and_then(Value::as_object) {
            for (name, property) in properties {
                if forbidden_name(name) || free_form(property) {
                    out.insert(format!("{location}.{name}"));
                }
                walk(location, property, out);
            }
        }
        for key in ["oneOf", "anyOf"] {
            for branch in map.get(key).and_then(Value::as_array).into_iter().flatten() {
                walk(location, branch, out);
            }
        }
        for key in ["items", "additionalProperties"] {
            if let Some(inner) = map.get(key) {
                walk(location, inner, out);
            }
        }
    }
    let mut out = BTreeSet::new();
    walk("<root>", schema, &mut out);
    if let Some(defs) = schema.get("$defs").and_then(Value::as_object) {
        for (name, def) in defs {
            walk(name, def, &mut out);
        }
    }
    out
}

#[test]
fn no_property_can_carry_matched_values_or_raw_output() {
    let mut unreviewed = Vec::new();
    let mut used = BTreeSet::new();
    for (file, schema) in all_schemas() {
        let schema = serde_json::to_value(&schema).expect("schema json");
        for location in flagged(&schema) {
            match ALLOWLIST
                .iter()
                .find(|(entry, files, _)| *entry == location && files.contains(&file))
            {
                Some((entry, _, _)) => {
                    used.insert((*entry, file));
                }
                None => unreviewed.push(format!("{file}: {location}")),
            }
        }
    }
    assert!(
        unreviewed.is_empty(),
        "properties that could carry matched values or raw scanner output; \
         constrain them or review and add them to ALLOWLIST (and the contracts README):\n{}",
        unreviewed.join("\n")
    );
    let stale: Vec<String> = ALLOWLIST
        .iter()
        .flat_map(|(entry, files, _)| files.iter().map(move |f| (*entry, *f)))
        .filter(|key| !used.contains(key))
        .map(|(entry, file)| format!("{file}: {entry}"))
        .collect();
    assert!(stale.is_empty(), "stale ALLOWLIST entries: {stale:?}");
}

#[test]
fn fixture_text_never_reaches_observations_or_artifacts() {
    for (file, schema) in all_schemas() {
        if INPUTS.contains(&file) {
            continue;
        }
        let schema = serde_json::to_value(&schema).expect("schema json");
        for location in flagged(&schema) {
            let property = location.rsplit('.').next().expect("property");
            assert_ne!(property, "content", "{file}: {location}");
        }
    }
}

#[test]
fn walker_catches_value_names_and_free_strings() {
    let schema = json!({
        "type": "object",
        "properties": { "findings": { "type": "array", "items": { "$ref": "#/$defs/Finding" } } },
        "$defs": {
            "Finding": {
                "type": "object",
                "properties": {
                    "start": { "type": "integer" },
                    "rule": { "type": "string", "pattern": "^[a-z-]+$" },
                    "matched_value": { "$ref": "#/$defs/Id" },
                    "line_text": { "type": ["string", "null"] },
                    "note": { "type": "string" },
                    "extra": { "type": "object", "additionalProperties": true },
                    "labels": { "type": "array", "items": { "type": "string" } },
                    "kind": { "oneOf": [{ "type": "string", "const": "a" }, { "type": "string" }] },
                    "stdout_bytes": { "type": "integer" }
                }
            },
            "Id": { "type": "string", "pattern": "^[a-z]+$" }
        }
    });
    let found: Vec<String> = flagged(&schema).into_iter().collect();
    assert_eq!(
        found,
        [
            "Finding.extra",
            "Finding.kind",
            "Finding.labels",
            "Finding.line_text",
            "Finding.matched_value",
            "Finding.note",
            "Finding.stdout_bytes",
        ]
    );
}

fn required(schema: &Value, def: &str) -> BTreeSet<String> {
    let node = if def == "<root>" {
        schema
    } else {
        &schema["$defs"][def]
    };
    node["required"]
        .as_array()
        .unwrap_or_else(|| panic!("{def} has no required list"))
        .iter()
        .map(|v| v.as_str().expect("name").to_owned())
        .collect()
}

#[test]
fn run_artifact_requires_every_reproduction_identity() {
    let schema = all_schemas()
        .into_iter()
        .find(|(file, _)| *file == "run-artifact-v1.schema.json")
        .map(|(_, schema)| serde_json::to_value(&schema).expect("schema json"))
        .expect("run artifact schema");
    // docs/contracts/identity.md, "Reproduction identities in a run artifact".
    let expectations: [(&str, &[&str]); 7] = [
        ("<root>", &["schema", "manifest"]),
        (
            "RunManifest",
            &[
                "engine",
                "protocol_version",
                "evidence",
                "config_hash",
                "accounting",
                "scanners",
            ],
        ),
        ("EngineIdentity", &["name", "version"]),
        (
            "SnapshotIdentity",
            &["source", "revision", "evidence_schema", "corpus_digest"],
        ),
        (
            "ScannerIdentity",
            &["id", "mode", "adapter", "configuration_hash"],
        ),
        ("AdapterIdentity", &["id", "version"]),
        ("MethodIdentity", &["id", "version"]),
    ];
    for (def, fields) in expectations {
        let present = required(&schema, def);
        for field in fields {
            assert!(
                present.contains(*field),
                "{def}.{field} must be a required identity"
            );
        }
    }
    // The scanner version is always written, as `null` when it could not be
    // determined (an unavailable scanner); the schema declares it nullable.
    let version = &schema["$defs"]["ScannerIdentity"]["properties"]["version"]["type"];
    assert_eq!(version, &json!(["string", "null"]));
    // `methods` defaults to empty for a plain corpus run, and `provenance` is
    // absent only for replayed observations; both are still declared.
    assert!(schema["$defs"]["RunManifest"]["properties"]["methods"].is_object());
    assert!(schema["$defs"]["ScannerIdentity"]["properties"]["provenance"].is_object());
}
