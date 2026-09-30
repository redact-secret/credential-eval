//! Fails when the committed JSON Schemas under `schemas/` drift from the types.
//!
//! Regenerate after an intentional contract change with:
//! `UPDATE_SCHEMAS=1 cargo test -p credential-eval-contracts --test schema_drift`

use std::path::PathBuf;

use credential_eval_contracts::schema::{all_schemas, render};

fn schemas_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../schemas")
}

#[test]
fn committed_schemas_match_types() {
    let update = std::env::var_os("UPDATE_SCHEMAS").is_some();
    let mut drift = Vec::new();
    for (file, schema) in all_schemas() {
        let path = schemas_dir().join(file);
        let rendered = render(&schema);
        if update {
            std::fs::write(&path, &rendered).expect("write schema");
            continue;
        }
        match std::fs::read_to_string(&path) {
            Ok(committed) if committed == rendered => {}
            Ok(_) => drift.push(format!("{file} differs from the generated schema")),
            Err(_) => drift.push(format!("{file} is missing")),
        }
    }
    assert!(
        drift.is_empty(),
        "schema drift: {drift:?}\nrun `UPDATE_SCHEMAS=1 cargo test -p credential-eval-contracts --test schema_drift` and review the diff"
    );
}

#[test]
fn no_unexpected_schema_files() {
    let expected: Vec<&str> = all_schemas().into_iter().map(|(file, _)| file).collect();
    for entry in std::fs::read_dir(schemas_dir()).expect("schemas dir") {
        let name = entry
            .expect("entry")
            .file_name()
            .into_string()
            .expect("utf-8 name");
        assert!(
            expected.contains(&name.as_str()),
            "schemas/{name} is not generated from a contract type"
        );
    }
}

#[test]
fn schemas_are_valid_draft_2020_12() {
    for (file, schema) in all_schemas() {
        let value = serde_json::to_value(&schema).expect("schema json");
        jsonschema::draft202012::meta::validate(&value)
            .unwrap_or_else(|e| panic!("{file} is not a valid 2020-12 schema: {e}"));
        jsonschema::validator_for(&value)
            .unwrap_or_else(|e| panic!("{file} does not compile: {e}"));
    }
}
