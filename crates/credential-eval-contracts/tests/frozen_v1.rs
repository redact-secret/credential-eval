//! Compatibility guard for the frozen v1 schemas
//! (`docs/decisions/0001-freeze-v1-contracts.md`).
//!
//! `tests/frozen-v1/` holds the schemas exactly as they were frozen: the four
//! documents of ADR 0001 and, from their first revision, the two performance
//! documents of ADR 0002. The
//! schemas generated from the current contract types must accept every
//! document the frozen schemas accept. The checker below approximates that
//! conservatively: it refuses a removed definition or property, a changed
//! `$ref`, a narrowed or changed type, a newly required property, a removed
//! enum value or `oneOf`/`anyOf` branch, a tightened constraint, and any
//! keyword it does not know. New optional properties, new definitions, new
//! enum values and widened types pass.
//!
//! The frozen files are never edited. Their SHA-256 digests are pinned below so
//! that an edit fails here and needs a deliberate, reviewed change to this
//! test as well. A breaking change is a new major version (v2) with new
//! schema files, not an edit of v1.

use std::collections::BTreeSet;
use std::path::PathBuf;

use credential_eval_contracts::schema::all_schemas;
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};

/// Frozen baseline files and the SHA-256 of their bytes.
const FROZEN: [(&str, &str); 6] = [
    (
        "corpus-snapshot-v1.schema.json",
        "54e8bafff0b05df27f360913ebd97e220e3ed8d6b2ba81fd7c0a28d6be24e89b",
    ),
    (
        "run-config-v1.schema.json",
        "a28c634dd88d6e8415c4351e273f08e26414c9e2dcc77689d2c558be5274b2b9",
    ),
    (
        "observation-set-v1.schema.json",
        "424dd8209233b2488c44b6587c5be90c5c3e351fa81ca9d6e288fbb9c0affc58",
    ),
    (
        "run-artifact-v1.schema.json",
        "5cfa0e4926500e18b9febb2f165fba78ad6a7308d627358b7b477cbf3d74c887",
    ),
    // ADR 0002: the performance documents are frozen at their first revision.
    (
        "performance-config-v1.schema.json",
        "967d568fde7c4c2680f3e14253f6686f4667230af83bd1068b9bd3ed275940ad",
    ),
    (
        "performance-artifact-v1.schema.json",
        "7c2c59883d7fb3c574d890e4a8fc56d9eac45bd7ee0ad2467ebbd2434be0fdb0",
    ),
];

fn frozen_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/frozen-v1")
}

/// Keywords that never change which documents a schema accepts.
const ANNOTATIONS: [&str; 6] = [
    "description",
    "title",
    "default",
    "examples",
    "$comment",
    "$schema",
];

/// Keywords the checker understands. Anything else fails loudly, so a new
/// generator feature cannot slip past the guard unchecked.
const KNOWN: [&str; 19] = [
    "$id",
    "$ref",
    "$defs",
    "type",
    "const",
    "enum",
    "format",
    "pattern",
    "minLength",
    "maxLength",
    "minimum",
    "maximum",
    "minItems",
    "maxItems",
    "required",
    "properties",
    "additionalProperties",
    "items",
    "oneOf",
];

fn known(keyword: &str) -> bool {
    KNOWN.contains(&keyword) || keyword == "anyOf" || ANNOTATIONS.contains(&keyword)
}

/// Every incompatibility of `new` with `old` (empty when `new` accepts every
/// document `old` accepts, as far as the checker can tell).
fn incompatibilities(old: &Value, new: &Value) -> Vec<String> {
    let mut out = Vec::new();
    if old.get("$id") != new.get("$id") {
        out.push("$id changed".to_owned());
    }
    let empty = Map::new();
    let old_defs = old
        .get("$defs")
        .and_then(Value::as_object)
        .unwrap_or(&empty);
    let new_defs = new
        .get("$defs")
        .and_then(Value::as_object)
        .unwrap_or(&empty);
    for (name, old_def) in old_defs {
        match new_defs.get(name) {
            None => out.push(format!("$defs/{name}: definition removed")),
            Some(new_def) => compare(&format!("$defs/{name}"), old_def, new_def, &mut out),
        }
    }
    compare("#", old, new, &mut out);
    out
}

fn types(schema: &Value) -> Option<BTreeSet<String>> {
    match schema.get("type")? {
        Value::String(t) => Some(BTreeSet::from([t.clone()])),
        Value::Array(list) => Some(
            list.iter()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect(),
        ),
        _ => None,
    }
}

fn branches(schema: &Value) -> Vec<&Value> {
    ["oneOf", "anyOf"]
        .iter()
        .filter_map(|k| schema.get(*k).and_then(Value::as_array))
        .flatten()
        .collect()
}

fn compare(path: &str, old: &Value, new: &Value, out: &mut Vec<String>) {
    if old == new {
        return;
    }
    let (Some(old_map), Some(new_map)) = (old.as_object(), new.as_object()) else {
        out.push(format!("{path}: schema is not an object"));
        return;
    };
    for key in old_map.keys().chain(new_map.keys()) {
        if !known(key) {
            out.push(format!("{path}: unsupported keyword {key}"));
        }
    }

    if old.get("$ref") != new.get("$ref") {
        out.push(format!("{path}: $ref changed"));
    }

    match (types(old), types(new)) {
        (Some(old_types), Some(new_types)) => {
            for t in &old_types {
                let widened_integer = t == "integer" && new_types.contains("number");
                if !new_types.contains(t) && !widened_integer {
                    out.push(format!("{path}: type {t} no longer accepted"));
                }
            }
        }
        (None, Some(_)) => out.push(format!("{path}: type constraint added")),
        _ => {}
    }

    for keyword in ["const", "pattern", "format"] {
        match (old.get(keyword), new.get(keyword)) {
            (None, Some(_)) => out.push(format!("{path}: {keyword} added")),
            (Some(a), Some(b)) if a != b => out.push(format!("{path}: {keyword} changed")),
            _ => {}
        }
    }

    match (old.get("enum"), new.get("enum")) {
        (None, Some(_)) => out.push(format!("{path}: enum added")),
        (Some(a), Some(b)) => {
            let b = b.as_array().cloned().unwrap_or_default();
            for value in a.as_array().into_iter().flatten() {
                if !b.contains(value) {
                    out.push(format!("{path}: enum value {value} removed"));
                }
            }
        }
        _ => {}
    }

    // Upper bounds may only grow, lower bounds may only shrink.
    for (keyword, upper) in [
        ("maxLength", true),
        ("maxItems", true),
        ("maximum", true),
        ("minLength", false),
        ("minItems", false),
        ("minimum", false),
    ] {
        match (
            old.get(keyword).and_then(Value::as_f64),
            new.get(keyword).and_then(Value::as_f64),
        ) {
            (None, Some(_)) => out.push(format!("{path}: {keyword} added")),
            (Some(a), Some(b)) if (upper && b < a) || (!upper && b > a) => {
                out.push(format!("{path}: {keyword} tightened"));
            }
            _ => {}
        }
    }

    let required = |s: &Value| -> BTreeSet<String> {
        s.get("required")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .map(str::to_owned)
            .collect()
    };
    let old_required = required(old);
    for name in required(new).difference(&old_required) {
        out.push(format!("{path}: property {name} newly required"));
    }

    let empty = Map::new();
    let old_props = old
        .get("properties")
        .and_then(Value::as_object)
        .unwrap_or(&empty);
    let new_props = new
        .get("properties")
        .and_then(Value::as_object)
        .unwrap_or(&empty);
    for (name, old_prop) in old_props {
        match new_props.get(name) {
            None => out.push(format!("{path}: property {name} removed")),
            Some(new_prop) => compare(&format!("{path}/{name}"), old_prop, new_prop, out),
        }
    }

    match (
        old.get("additionalProperties"),
        new.get("additionalProperties"),
    ) {
        (Some(Value::Bool(false)), _) | (_, None | Some(Value::Bool(true))) => {}
        (None | Some(Value::Bool(true)), Some(_)) => {
            out.push(format!("{path}: additionalProperties restricted"));
        }
        (Some(a), Some(b)) => compare(&format!("{path}/additionalProperties"), a, b, out),
    }

    match (old.get("items"), new.get("items")) {
        (None, Some(_)) => out.push(format!("{path}: items constraint added")),
        (Some(a), Some(b)) => compare(&format!("{path}/items"), a, b, out),
        _ => {}
    }

    let old_branches = branches(old);
    let new_branches = branches(new);
    if old_branches.is_empty() && !new_branches.is_empty() {
        out.push(format!("{path}: oneOf/anyOf added"));
    }
    for (i, old_branch) in old_branches.iter().enumerate() {
        let accepted = new_branches.iter().any(|candidate| {
            let mut scratch = Vec::new();
            compare(path, old_branch, candidate, &mut scratch);
            scratch.is_empty()
        });
        if !accepted {
            out.push(format!(
                "{path}: branch {i} ({}) has no compatible branch",
                old_branch
                    .get("const")
                    .or_else(|| old_branch.get("$ref"))
                    .map_or_else(|| "inline".to_owned(), ToString::to_string)
            ));
        }
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

#[test]
fn frozen_baselines_are_untouched() {
    let mut names: Vec<String> = std::fs::read_dir(frozen_dir())
        .expect("frozen-v1 dir")
        .map(|e| e.expect("entry").file_name().into_string().expect("utf-8"))
        .collect();
    names.sort();
    let mut expected: Vec<String> = FROZEN.iter().map(|(f, _)| (*f).to_owned()).collect();
    expected.sort();
    assert_eq!(
        names, expected,
        "tests/frozen-v1 must hold exactly the v1 baselines"
    );
    for (file, digest) in FROZEN {
        let bytes = std::fs::read(frozen_dir().join(file)).expect("baseline");
        assert_eq!(
            sha256_hex(&bytes),
            digest,
            "{file}: a frozen v1 baseline was edited; v1 never changes incompatibly (ADR 0001)"
        );
    }
}

#[test]
fn every_contract_schema_has_a_frozen_baseline() {
    let generated: BTreeSet<&str> = all_schemas().into_iter().map(|(f, _)| f).collect();
    let frozen: BTreeSet<&str> = FROZEN.iter().map(|(f, _)| *f).collect();
    assert_eq!(generated, frozen);
}

#[test]
fn current_schemas_are_compatible_with_frozen_v1() {
    let mut failures = Vec::new();
    for (file, schema) in all_schemas() {
        let old: Value = serde_json::from_slice(
            &std::fs::read(frozen_dir().join(file)).expect("frozen baseline"),
        )
        .expect("baseline json");
        let new = serde_json::to_value(&schema).expect("schema json");
        failures.extend(
            incompatibilities(&old, &new)
                .into_iter()
                .map(|e| format!("{file}: {e}")),
        );
    }
    assert!(
        failures.is_empty(),
        "incompatible change to a frozen v1 schema (ADR 0001: add optional fields, or make v2):\n{}",
        failures.join("\n")
    );
}

// ---- unit tests of the checker itself ----

fn base() -> Value {
    json!({
        "$id": "x",
        "type": "object",
        "properties": {
            "id": { "$ref": "#/$defs/Id" },
            "kind": { "$ref": "#/$defs/Kind" },
            "count": { "type": "integer", "minimum": 0 },
            "note": { "type": ["string", "null"] },
            "tags": { "type": "array", "items": { "type": "string" } }
        },
        "additionalProperties": false,
        "required": ["id", "kind", "count"],
        "$defs": {
            "Id": { "type": "string", "pattern": "^[a-z]+$", "maxLength": 8 },
            "Kind": { "oneOf": [
                { "type": "string", "const": "a" },
                { "type": "string", "const": "b" }
            ] },
            "Level": { "type": "string", "enum": ["low", "high"] }
        }
    })
}

fn edited(edit: impl FnOnce(&mut Value)) -> Vec<String> {
    let mut new = base();
    edit(&mut new);
    incompatibilities(&base(), &new)
}

fn assert_refused(errors: &[String], needle: &str) {
    assert!(
        errors.iter().any(|e| e.contains(needle)),
        "expected an error containing {needle:?}, got {errors:?}"
    );
}

#[test]
fn checker_accepts_identical_and_additive_changes() {
    assert!(incompatibilities(&base(), &base()).is_empty());
    let additive = edited(|s| {
        s["properties"]["extra"] = json!({ "type": "string" });
        s["$defs"]["New"] = json!({ "type": "boolean" });
        s["properties"]["note"]["description"] = json!("reworded");
        s["$defs"]["Kind"]["oneOf"]
            .as_array_mut()
            .unwrap()
            .push(json!({ "type": "string", "const": "c" }));
        s["$defs"]["Level"]["enum"]
            .as_array_mut()
            .unwrap()
            .push(json!("mid"));
        s["$defs"]["Id"]["maxLength"] = json!(16);
        s["properties"]["count"]["type"] = json!(["integer", "null"]);
        s["required"] = json!(["id", "kind"]);
    });
    assert!(additive.is_empty(), "{additive:?}");
}

#[test]
fn checker_refuses_removed_property() {
    assert_refused(
        &edited(|s| {
            s["properties"].as_object_mut().unwrap().remove("note");
        }),
        "property note removed",
    );
}

#[test]
fn checker_refuses_changed_type() {
    assert_refused(
        &edited(|s| s["properties"]["count"]["type"] = json!("string")),
        "type integer no longer accepted",
    );
    assert_refused(
        &edited(|s| s["properties"]["note"]["type"] = json!("string")),
        "type null no longer accepted",
    );
    assert_refused(
        &edited(|s| s["properties"]["id"] = json!({ "type": "string" })),
        "$ref changed",
    );
}

#[test]
fn checker_refuses_newly_required_fields() {
    assert_refused(
        &edited(|s| {
            s["properties"]["extra"] = json!({ "type": "string" });
            s["required"].as_array_mut().unwrap().push(json!("extra"));
        }),
        "property extra newly required",
    );
    assert_refused(
        &edited(|s| s["required"].as_array_mut().unwrap().push(json!("note"))),
        "property note newly required",
    );
}

#[test]
fn checker_refuses_narrowed_enums() {
    assert_refused(
        &edited(|s| {
            s["$defs"]["Kind"]["oneOf"].as_array_mut().unwrap().pop();
        }),
        "has no compatible branch",
    );
    assert_refused(
        &edited(|s| s["$defs"]["Level"]["enum"] = json!(["low"])),
        "enum value \"high\" removed",
    );
}

#[test]
fn checker_refuses_removed_definition() {
    assert_refused(
        &edited(|s| {
            s["$defs"].as_object_mut().unwrap().remove("Level");
        }),
        "$defs/Level: definition removed",
    );
}

#[test]
fn checker_refuses_tightened_constraints() {
    assert_refused(
        &edited(|s| s["$defs"]["Id"]["maxLength"] = json!(4)),
        "maxLength tightened",
    );
    assert_refused(
        &edited(|s| s["$defs"]["Id"]["pattern"] = json!("^[a-c]+$")),
        "pattern changed",
    );
    assert_refused(
        &edited(|s| s["properties"]["tags"]["items"]["pattern"] = json!("^x$")),
        "pattern added",
    );
    assert_refused(
        &edited(|s| s["properties"]["count"]["maximum"] = json!(10)),
        "maximum added",
    );
}

#[test]
fn checker_refuses_unknown_keywords_and_changed_ids() {
    assert_refused(
        &edited(|s| s["properties"]["note"]["not"] = json!({ "const": "x" })),
        "unsupported keyword not",
    );
    assert_refused(&edited(|s| s["$id"] = json!("y")), "$id changed");
}
