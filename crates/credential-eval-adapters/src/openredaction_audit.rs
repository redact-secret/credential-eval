//! Consistency of the reviewed OpenRedaction 1.1.5 dispositions with the
//! adapter's label tables and with the recorded probe (ADR 0012). Test-only:
//! the data lives in `docs/measurements/` and `tools/openredaction-audit/`.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::Value;

use crate::families::{LabelTable, finding_family};
use crate::openredaction_labels::OPEN_REDACTION_1_1_5_TYPES;

const DISPOSITIONS: &str = include_str!("../../../tools/openredaction-audit/dispositions.json");
const PROBE: &str = include_str!("../../../tools/openredaction-audit/expected.json");
const CASES: &str = include_str!("../../../tools/openredaction-audit/cases.json");

fn dispositions() -> Vec<Value> {
    let doc: Value = serde_json::from_str(DISPOSITIONS).unwrap();
    doc["types"].as_array().unwrap().clone()
}

fn text<'a>(v: &'a Value, key: &str) -> &'a str {
    v[key].as_str().unwrap_or_default()
}

#[test]
fn every_native_type_has_exactly_one_disposition() {
    let listed: Vec<String> = dispositions()
        .iter()
        .map(|d| text(d, "type").to_owned())
        .collect();
    let reviewed: Vec<String> = OPEN_REDACTION_1_1_5_TYPES
        .iter()
        .map(|t| (*t).to_owned())
        .collect();
    assert_eq!(listed, reviewed, "dispositions and reviewed labels differ");
    for d in dispositions() {
        assert!(
            ["mapped", "unresolved", "not-credential"].contains(&text(&d, "status")),
            "{d}"
        );
        assert!(
            !text(&d, "reason").is_empty(),
            "{} has no reason",
            text(&d, "type")
        );
    }
}

#[test]
fn the_counts_match_the_audited_package() {
    let all = dispositions();
    let in_category = all
        .iter()
        .filter(|d| d["in_credentials_category"] == Value::Bool(true))
        .count();
    let by = |status: &str| all.iter().filter(|d| text(d, "status") == status).count();
    assert_eq!(in_category, 32);
    // 17 of the category map, plus URL_WITH_AUTH from outside it.
    assert_eq!(by("mapped"), 18);
    // 15 category types stay unmapped, each with its reason.
    let unmapped_in_category = all
        .iter()
        .filter(|d| {
            d["in_credentials_category"] == Value::Bool(true) && d["current_family"].is_null()
        })
        .count();
    assert_eq!(unmapped_in_category, 15);
}

#[test]
fn mapped_means_the_adapter_table_maps_it_and_nothing_else_does() {
    for d in dispositions() {
        let label = text(&d, "type");
        let family = finding_family(LabelTable::OpenRedaction, Some(label), None);
        match text(&d, "status") {
            "mapped" => {
                assert_eq!(family.as_deref(), d["current_family"].as_str(), "{label}");
                assert!(family.is_some(), "{label}");
            }
            _ => {
                // No unsupported family invention, no automatic classification.
                assert_eq!(family, None, "{label} is mapped but not marked mapped");
                assert!(d["current_family"].is_null(), "{label}");
            }
        }
    }
}

#[test]
fn identifiers_and_ambiguous_scopes_never_carry_a_family() {
    let by_type: BTreeMap<String, Value> = dispositions()
        .into_iter()
        .map(|d| (text(&d, "type").to_owned(), d))
        .collect();
    for resource in ["AWS_ARN", "AZURE_RESOURCE_ID"] {
        let d = &by_type[resource];
        assert_eq!(text(d, "scope"), "resource-identifier");
        assert_eq!(text(d, "status"), "not-credential");
        assert!(d["current_family"].is_null());
    }
    for open in [
        "SESSION_ID",
        "COOKIE_SESSION",
        "CART_SESSION_ID",
        "PAYMENT_TOKEN",
    ] {
        assert_eq!(text(&by_type[open], "status"), "unresolved", "{open}");
    }
    // A candidate is only ever a `provider:family` evidence id, and is never a
    // mapping: the status stays unresolved.
    for d in by_type.values() {
        if let Some(candidate) = d["evidence_family_candidate"].as_str() {
            assert!(candidate.contains(':'), "{candidate}");
            assert_eq!(text(d, "status"), "unresolved");
        }
    }
}

#[test]
fn recorded_probe_spans_agree_with_the_dispositions() {
    let probe: Value = serde_json::from_str(PROBE).unwrap();
    assert_eq!(probe["version"], "1.1.5");
    let by_type: BTreeMap<String, Value> = dispositions()
        .into_iter()
        .map(|d| (text(&d, "type").to_owned(), d))
        .collect();
    let cases: Value = serde_json::from_str(CASES).unwrap();
    let case_ids: BTreeSet<&str> = cases["cases"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c["id"].as_str().unwrap())
        .collect();
    let rows = probe["profiles"]["default"].as_array().unwrap();
    assert_eq!(rows.len(), case_ids.len());
    for row in rows {
        assert!(case_ids.contains(text(row, "id")));
        let disposition = &by_type[text(row, "type")];
        if text(row, "polarity") != "positive" || row["own_span"].is_null() {
            continue;
        }
        // The reported range is the capture group when the pattern has one and
        // the whole match otherwise: exact against the marked secret, or wider.
        let observed = text(row, "own_span");
        match text(disposition, "span") {
            "capture" => assert_eq!(observed, "exact", "{}", text(row, "id")),
            "whole-match" => assert!(
                ["exact", "wider"].contains(&observed),
                "{}",
                text(row, "id")
            ),
            other => panic!("{}: unexpected span {other}", text(row, "id")),
        }
    }
    // Under the default profile a PEM public key is never a private key type.
    let public = rows
        .iter()
        .find(|r| text(r, "id") == "public-key-benign")
        .unwrap();
    let types: Vec<&str> = public["all_types"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(Value::as_str)
        .collect();
    assert!(!types.contains(&"PRIVATE_KEY") && !types.contains(&"SSH_PRIVATE_KEY"));
    // A publishable Stripe key is reported with the same type as a secret one.
    let pk = rows
        .iter()
        .find(|r| text(r, "id") == "stripe-publishable")
        .unwrap();
    assert!(
        pk["all_types"]
            .as_array()
            .unwrap()
            .iter()
            .any(|t| t == "STRIPE_API_KEY")
    );
}

#[test]
fn diagnostic_profiles_are_separate_identities_outside_the_default_set() {
    use crate::{builtin, diagnostic, find};

    let default_ids: Vec<String> = builtin()
        .iter()
        .map(|a| a.identity().id.to_string())
        .collect();
    let default = find("openredaction").unwrap().default_spec();
    for id in [
        "openredaction-credentials",
        "openredaction-mapped",
        "openredaction-credential-bearing",
    ] {
        assert!(
            !default_ids.contains(&id.to_owned()),
            "{id} must not be a default scanner"
        );
        let adapter = find(id).unwrap();
        let spec = adapter.default_spec();
        assert_eq!(spec.id.as_str(), id);
        // A new configuration identity: neither the id, the options nor the
        // hash can be confused with the default-options scanner's.
        assert_ne!(spec.configuration_hash(), default.configuration_hash());
        assert_eq!(spec.configuration["package"], "@openredaction/core");
        assert_ne!(
            spec.configuration["options"],
            default.configuration["options"]
        );
    }
    assert_eq!(diagnostic().len(), 3);
    assert_eq!(default.configuration["options"], serde_json::json!({}));
}

#[test]
fn the_mapped_allowlist_is_exactly_the_mapped_dispositions() {
    let spec = crate::find("openredaction-mapped").unwrap().default_spec();
    let listed: Vec<&str> = spec.configuration["options"]["patterns"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(Value::as_str)
        .collect();
    let mapped: Vec<String> = dispositions()
        .iter()
        .filter(|d| text(d, "status") == "mapped")
        .map(|d| text(d, "type").to_owned())
        .collect();
    assert_eq!(listed, mapped);
    let credentials = crate::find("openredaction-credentials")
        .unwrap()
        .default_spec();
    assert_eq!(
        credentials.configuration["options"],
        serde_json::json!({"categories": ["credentials"]})
    );
}

#[test]
fn the_credential_bearing_profile_is_the_category_plus_url_with_auth() {
    let spec = crate::find("openredaction-credential-bearing")
        .unwrap()
        .default_spec();
    let listed: Vec<&str> = spec.configuration["options"]["patterns"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(Value::as_str)
        .collect();
    let mut expected: Vec<String> = dispositions()
        .iter()
        .filter(|d| {
            d["in_credentials_category"] == Value::Bool(true) || text(d, "type") == "URL_WITH_AUTH"
        })
        .map(|d| text(d, "type").to_owned())
        .collect();
    expected.sort();
    assert_eq!(listed, expected);
    assert_eq!(listed.len(), 33);
}
