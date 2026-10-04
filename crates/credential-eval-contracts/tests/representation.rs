//! Representation contract (revision v1.3): carrying, validating and
//! reporting the facts of encoded and fragmented inputs, and leaving every
//! earlier document untouched. All content is synthetic.

use std::path::PathBuf;

use credential_eval_contracts::ContractError;
use credential_eval_contracts::canonical::sha256_bytes;
use credential_eval_contracts::corpus::{Case, CorpusSnapshot};
use credential_eval_contracts::representation::{REPRESENTATION_CONTRACT, facts_digest};
use credential_eval_contracts::schema::{RepresentationContract, all_schemas};
use serde_json::{Value, json};

const SECRET: &str = "SYNTHETIC_EXAMPLE_KEY_NEVER_ISSUED_01";

fn b64(bytes: &[u8], url: bool, padded: bool) -> String {
    const STD: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    const URL: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let table = if url { URL } else { STD };
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let n = chunk
            .iter()
            .enumerate()
            .fold(0u32, |acc, (i, b)| acc | (u32::from(*b) << (16 - 8 * i)));
        for i in 0..=chunk.len() {
            out.push(char::from(table[((n >> (18 - 6 * i)) & 63) as usize]));
        }
        if padded {
            for _ in chunk.len() + 1..4 {
                out.push('=');
            }
        }
    }
    out
}

fn hex(bytes: &[u8], upper: bool) -> String {
    bytes
        .iter()
        .map(|b| {
            if upper {
                format!("{b:02X}")
            } else {
                format!("{b:02x}")
            }
        })
        .collect()
}

fn digest(bytes: &[u8]) -> String {
    sha256_bytes(bytes).to_string()
}

fn case(v: Value) -> Case {
    serde_json::from_value(v).expect("case")
}

fn grouping(tier: &str) -> Value {
    json!({"kind": "must-redact", "tier": tier, "group": "representation-smoke", "family": "example-api-key"})
}

/// Whole-value standard padded base64: `ENCODED=<b64>\n` with a decoded fact.
fn b64_case() -> Case {
    let enc = b64(SECRET.as_bytes(), false, true);
    let content = format!("ENCODED={enc}\n");
    case(json!({
        "id": "enc-b64-whole", "path": "rep/enc-b64-whole.txt", "content": content,
        "expected": [{"start": 8, "end": 8 + enc.len(), "role": "secret",
            "base": "enc-base",
            "decoded": {"via": [{"codec": "base64", "alphabet": "standard", "padding": "padded"}],
                        "sha256": digest(SECRET.as_bytes()), "bytes": SECRET.len()}}],
        "grouping": grouping("T1"),
        "representation": {
            "derivation": {"kind": "projection", "bases": ["enc-base"]},
            "transformation": {"steps": [
                {"op": "encode", "codec": "base64", "alphabet": "standard", "padding": "padded"},
                {"op": "embed", "mode": "whole-value", "carrier": "shell-assignment"}]}}
    }))
}

/// Upper-case hex embedded in JSON.
fn hex_case() -> Case {
    let enc = hex(SECRET.as_bytes(), true);
    let content = format!("{{\"k\": \"{enc}\"}}\n");
    case(json!({
        "id": "enc-hex-json", "path": "rep/enc-hex-json.txt", "content": content,
        "expected": [{"start": 7, "end": 7 + enc.len(), "role": "secret",
            "decoded": {"via": [{"codec": "hex", "case": "upper"}],
                        "sha256": digest(SECRET.as_bytes()), "bytes": SECRET.len()}}],
        "grouping": grouping("T1")
    }))
}

/// URL-safe unpadded base64 of standard padded base64 (decode order: outer
/// layer first).
fn nested_case() -> Case {
    let inner = b64(SECRET.as_bytes(), false, true);
    let outer = b64(inner.as_bytes(), true, false);
    let content = format!("v={outer}\n");
    case(json!({
        "id": "enc-nested", "path": "rep/enc-nested.txt", "content": content,
        "expected": [{"start": 2, "end": 2 + outer.len(), "role": "secret",
            "decoded": {"via": [
                {"codec": "base64", "alphabet": "url-safe", "padding": "unpadded"},
                {"codec": "base64", "alphabet": "standard", "padding": "padded"}],
                "sha256": digest(SECRET.as_bytes()), "bytes": SECRET.len()}}],
        "grouping": grouping("T1")
    }))
}

/// A shell continuation: the secret split over two lines, after multi-byte
/// text, so the fragment offsets are byte offsets and not characters.
fn fragment_case() -> Case {
    let (a, b) = SECRET.split_at(10);
    let prefix = "# café 密钥\nKEY=";
    let content = format!("{prefix}{a}\\\n{b}\n");
    let start = prefix.len();
    let first_end = start + a.len();
    let second_start = first_end + 2;
    let end = second_start + b.len();
    case(json!({
        "id": "frag-shell", "path": "rep/frag-shell.txt", "content": content,
        "expected": [{"start": start, "end": end, "role": "secret",
            "fragments": [{"start": start, "end": first_end}, {"start": second_start, "end": end}]}],
        "grouping": grouping("T2"),
        "representation": {"transformation": {"steps": [
            {"op": "fragment", "mechanism": "shell-line-continuation", "line_break": "lf",
             "reconstruction": "reconstructs-original"}]}}
    }))
}

/// Zero-width spaces inside the key, removed by `strip-codepoints`.
fn strip_case() -> Case {
    let spaced: String = SECRET
        .chars()
        .enumerate()
        .flat_map(|(i, c)| {
            if i == 5 || i == 20 {
                vec!['\u{200B}', c]
            } else {
                vec![c]
            }
        })
        .collect();
    let content = format!("é={spaced}\n");
    let start = "é=".len();
    case(json!({
        "id": "strip-zero-width", "path": "rep/strip.txt", "content": content,
        "expected": [{"start": start, "end": start + spaced.len(), "role": "secret",
            "decoded": {"via": [{"codec": "strip-codepoints", "code_points": ["U+200B"]}],
                        "sha256": digest(SECRET.as_bytes()), "bytes": SECRET.len()}}],
        "grouping": grouping("T3")
    }))
}

/// An expected rejection: a UTF-16 chunk boundary inside an emoji.
fn rejection_case() -> Case {
    case(json!({
        "id": "reject-surrogate", "path": "rep/reject.txt", "content": "🔑KEY=EXAMPLE\n",
        "expected": [],
        "grouping": {"kind": "must-not-flag", "tier": "T0", "group": "representation-smoke"},
        "representation": {
            "input_validity": "unpaired-surrogate-split",
            "chunking": {"unit": "utf16-code-unit", "boundaries": [1]}}
    }))
}

/// A pending base64 projection: no span, only its lineage.
fn pending_case() -> Case {
    let enc = b64(SECRET.as_bytes(), false, true);
    case(json!({
        "id": "enc-pending", "path": "rep/pending.txt", "content": format!("X={enc}\n"),
        "expected": [],
        "grouping": {"kind": "must-not-flag", "tier": "T0", "group": "representation-smoke"},
        "representation": {"derivation": {"kind": "projection", "bases": ["enc-base"]},
            "transformation": {"steps": [
                {"op": "encode", "codec": "base64", "alphabet": "standard", "padding": "padded"}]}}
    }))
}

fn raw_case() -> Case {
    case(json!({
        "id": "raw-control", "path": "rep/raw.txt", "content": "nothing to see\n",
        "expected": [],
        "grouping": {"kind": "must-not-flag", "tier": "T1", "group": "representation-smoke",
                     "taxonomy": "prose"}
    }))
}

fn all_cases() -> Vec<Case> {
    vec![
        b64_case(),
        hex_case(),
        nested_case(),
        fragment_case(),
        strip_case(),
        rejection_case(),
        pending_case(),
        raw_case(),
    ]
}

fn snapshot_of(cases: Vec<Case>) -> CorpusSnapshot {
    let mut s = CorpusSnapshot::seal(
        "synthetic:representation".into(),
        "r1".into(),
        "synthetic-v1".into(),
        cases,
    );
    s.identity.representation = Some(RepresentationContract);
    s
}

/// Seal after mutating one case, so only the representation rules can object.
fn mutate(id: &str, f: impl FnOnce(&mut Value)) -> Result<CorpusSnapshot, ContractError> {
    let mut cases = all_cases();
    let at = cases
        .iter()
        .position(|c| c.id.as_str() == id)
        .expect("case");
    let mut v = serde_json::to_value(&cases[at]).unwrap();
    f(&mut v);
    cases[at] = serde_json::from_value(v).expect("case parses");
    let s = snapshot_of(cases);
    s.validate().map(|()| s)
}

fn reason(result: Result<CorpusSnapshot, ContractError>) -> String {
    match result.expect_err("must be refused") {
        ContractError::InvalidRepresentation { reason, .. } => reason.to_owned(),
        other => panic!("not a representation error: {other}"),
    }
}

#[test]
fn a_snapshot_with_every_kind_of_fact_validates_and_is_reported() {
    let s = snapshot_of(all_cases());
    s.validate().expect("valid");
    let json = serde_json::to_string(&s).unwrap();
    let parsed = CorpusSnapshot::from_json(json.as_bytes()).expect("round trip");
    assert_eq!(parsed, s);
    let report = s.representation_report().expect("report");
    assert_eq!(report.contract, RepresentationContract);
    assert_eq!(REPRESENTATION_CONTRACT, "credential-eval/representation/1");
    assert_eq!(report.cases, 7, "the raw control carries nothing");
    assert_eq!(report.transformed_cases, 3);
    assert_eq!(report.chunked_cases, 1);
    assert_eq!(report.expected_rejections, 1);
    assert_eq!((report.fragmented_spans, report.fragments), (1, 2));
    assert_eq!(report.decoded_spans, 4);
    assert_eq!(report.decoded_verified, 4, "base64, hex, nested, strip");
    assert_eq!(report.decoded_unverified, 0);
}

#[test]
fn earlier_snapshots_are_untouched() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/contracts-smoke/corpus-snapshot.json");
    let bytes = std::fs::read(path).unwrap();
    let s = CorpusSnapshot::from_json(&bytes).expect("an old snapshot still loads");
    assert!(!s.uses_representation());
    assert!(s.identity.representation.is_none());
    assert!(s.representation_report().is_none());
    // Serializing adds no key, so every digest stays what it was.
    let text = serde_json::to_string(&s).unwrap();
    for key in ["representation", "fragments", "decoded", "\"base\""] {
        assert!(!text.contains(key), "{key} appeared in an old document");
    }
    let before: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(serde_json::to_value(&s).unwrap(), before);
}

#[test]
fn facts_need_the_declaration_and_the_digest_covers_them() {
    let mut s = snapshot_of(all_cases());
    s.identity.representation = None;
    assert_eq!(s.validate(), Err(ContractError::RepresentationUndeclared));
    // Declaring the contract with no facts is allowed (a supporting exporter).
    let mut plain = snapshot_of(vec![raw_case()]);
    plain.validate().unwrap();
    assert!(plain.representation_report().is_some());
    plain.identity.representation = None;
    assert!(plain.representation_report().is_none());
    // A changed fact changes the corpus digest, so a stale one is refused.
    let mut cases = all_cases();
    let before = CorpusSnapshot::seal("s".into(), "r".into(), "e".into(), cases.clone());
    cases[0].representation = None;
    let after = CorpusSnapshot::seal("s".into(), "r".into(), "e".into(), cases);
    assert_ne!(before.identity.corpus_digest, after.identity.corpus_digest);
}

#[test]
fn the_facts_digest_is_order_independent_and_changes_with_a_fact() {
    let cases = all_cases();
    let mut reversed = cases.clone();
    reversed.reverse();
    assert_eq!(facts_digest(&cases), facts_digest(&reversed));
    // Cases without facts do not contribute.
    let mut with_raw = cases.clone();
    with_raw.push(case(json!({
        "id": "another-raw", "path": "rep/another.txt", "content": "x\n", "expected": [],
        "grouping": {"kind": "must-not-flag", "tier": "T1", "group": "g", "taxonomy": "prose"}})));
    assert_eq!(facts_digest(&cases), facts_digest(&with_raw));
    let mut changed = cases.clone();
    changed[3].expected[0].fragments = None;
    assert_ne!(facts_digest(&cases), facts_digest(&changed));
}

#[test]
fn fragments_are_checked_against_the_content() {
    let ok = fragment_case();
    let f = ok.expected[0].fragments.clone().unwrap();
    let span = (ok.expected[0].start, ok.expected[0].end);
    let with = |fragments: Value| {
        mutate("frag-shell", |v| {
            v["expected"][0]["fragments"] = fragments;
        })
    };
    // Fewer than two.
    assert!(
        reason(with(json!([{"start": span.0, "end": span.1}]))).contains("two or more fragments")
    );
    // Touching fragments have no separator.
    assert!(
        reason(with(
            json!([{"start": span.0, "end": f[0].end}, {"start": f[0].end, "end": span.1}])
        ))
        .contains("separated")
    );
    // Unsorted.
    assert!(
        reason(with(json!([
            {"start": f[1].start, "end": f[1].end},
            {"start": f[0].start, "end": f[0].end}
        ])))
        .contains("separated")
    );
    // Not starting at the span start / not ending at the span end.
    assert!(
        reason(with(
            json!([{"start": span.0 + 1, "end": f[0].end}, {"start": f[1].start, "end": span.1}])
        ))
        .contains("start at the span start")
    );
    assert!(
        reason(with(
            json!([{"start": span.0, "end": f[0].end}, {"start": f[1].start, "end": span.1 - 1}])
        ))
        .contains("end at the span end")
    );
    // A fragment inside a multi-byte character is not a UTF-8 range: the
    // prefix is `# café`, and byte 6 is the second byte of `é`.
    let r = mutate("frag-shell", |v| {
        v["expected"][0]["start"] = json!(6);
        v["expected"][0]["fragments"] =
            json!([{"start": 6, "end": 8}, {"start": 10, "end": span.1}]);
    });
    assert!(matches!(
        r,
        Err(ContractError::InvalidRange { .. }) | Err(ContractError::InvalidRepresentation { .. })
    ));
    // Fragments belong to a secret span only.
    assert!(
        reason(mutate("frag-shell", |v| v["expected"][0]["role"] =
            json!("companion")))
        .contains("secret span")
    );
}

#[test]
fn multibyte_offsets_are_utf8_bytes() {
    // The fragment case starts after `é` (2 bytes) and `密钥` (6 bytes).
    let c = fragment_case();
    let start = c.expected[0].start as usize;
    assert_eq!(&c.content[start..start + 10], "SYNTHETIC_");
    assert_ne!(
        start,
        c.content.chars().take_while(|ch| *ch != 'S').count(),
        "byte offset differs from the character offset"
    );
    snapshot_of(vec![c]).validate().unwrap();
}

#[test]
fn decoded_facts_are_rederived_from_the_original_bytes() {
    // A wrong digest, a wrong length and a zero length.
    assert!(
        reason(mutate(
            "enc-b64-whole",
            |v| v["expected"][0]["decoded"]["sha256"] = json!(digest(b"other"))
        ))
        .contains("length or digest")
    );
    assert!(
        reason(mutate(
            "enc-b64-whole",
            |v| v["expected"][0]["decoded"]["bytes"] = json!(3)
        ))
        .contains("length or digest")
    );
    assert!(
        reason(mutate(
            "enc-b64-whole",
            |v| v["expected"][0]["decoded"]["bytes"] = json!(0)
        ))
        .contains("length is zero")
    );
    // The declared alphabet, padding and case must be the text's own.
    let step = |v: &mut Value, step: Value| v["expected"][0]["decoded"]["via"] = json!([step]);
    assert!(
        reason(mutate("enc-b64-whole", |v| step(
            v,
            json!({"codec": "base64", "alphabet": "standard", "padding": "unpadded"})
        )))
        .contains("does not re-derive")
    );
    assert!(
        reason(mutate("enc-hex-json", |v| step(
            v,
            json!({"codec": "hex", "case": "lower"})
        )))
        .contains("does not re-derive")
    );
    assert!(
        reason(mutate("enc-hex-json", |v| step(
            v,
            json!({"codec": "hex", "case": "mixed"})
        )))
        .contains("does not re-derive")
    );
    // A nested chain must be in decode order.
    assert!(
        reason(mutate(
            "enc-nested",
            |v| v["expected"][0]["decoded"]["via"] = json!([
            {"codec": "base64", "alphabet": "standard", "padding": "padded"},
            {"codec": "base64", "alphabet": "url-safe", "padding": "unpadded"}])
        ))
        .contains("does not re-derive")
    );
    // Stripping a code point the text does not contain is not a derivation.
    assert!(
        reason(mutate("strip-zero-width", |v| v["expected"][0]["decoded"]
            ["via"] = json!([{"codec": "strip-codepoints", "code_points": ["U+200C"]}])))
        .contains("does not re-derive")
    );
    // Step bounds.
    assert!(
        reason(mutate(
            "enc-b64-whole",
            |v| v["expected"][0]["decoded"]["via"] = json!([])
        ))
        .contains("step count")
    );
    let nine: Vec<Value> = (0..9)
        .map(|_| json!({"codec": "base64", "alphabet": "standard", "padding": "padded"}))
        .collect();
    assert!(
        reason(mutate(
            "enc-b64-whole",
            |v| v["expected"][0]["decoded"]["via"] = json!(nine)
        ))
        .contains("step count")
    );
}

#[test]
fn normalization_is_carried_but_reported_unverified() {
    let s = mutate("enc-b64-whole", |v| {
        v["expected"][0]["decoded"]["via"] = json!([
            {"codec": "base64", "alphabet": "standard", "padding": "padded"},
            {"codec": "normalize", "form": "nfc"}]);
        // The digest and length are not re-derivable past a normalization, so
        // whatever the exporter states is carried as stated.
    })
    .expect("carried");
    let report = s.representation_report().unwrap();
    assert_eq!((report.decoded_spans, report.decoded_unverified), (4, 1));
    assert_eq!(report.decoded_verified, 3);
}

#[test]
fn input_validity_and_chunking_are_verified_both_ways() {
    // An expected rejection is non-asserting: no spans, tier T0.
    let s = snapshot_of(all_cases());
    s.validate().unwrap();
    assert!(
        reason(mutate("reject-surrogate", |v| {
            v["expected"] = json!([{"start": 4, "end": 7, "role": "secret"}]);
        }))
        .contains("carries no spans")
    );
    assert!(
        reason(mutate("reject-surrogate", |v| v["grouping"]["tier"] = json!("T1")))
            .contains("tier T0")
    );
    // Labelled rejected without a boundary that splits a pair, and the other
    // way round: a valid label on a splitting boundary.
    assert!(
        reason(mutate(
            "reject-surrogate",
            |v| v["representation"]["chunking"]["boundaries"] = json!([5])
        ))
        .contains("inside a surrogate pair")
    );
    assert!(
        reason(mutate("reject-surrogate", |v| {
            v["representation"]
                .as_object_mut()
                .unwrap()
                .remove("input_validity");
        }))
        .contains("declared valid")
    );
    // A UTF-8 byte boundary inside a multi-byte sequence is still valid input.
    mutate("reject-surrogate", |v| {
        v["representation"] = json!({"chunking": {"unit": "utf8-byte", "boundaries": [2]}});
        v["grouping"]["tier"] = json!("T1");
    })
    .expect("a byte boundary inside an emoji is a valid byte stream");
    // Invalid UTF-8 cannot be carried by a string.
    assert!(
        reason(mutate("reject-surrogate", |v| {
            v["representation"] = json!({"input_validity": "invalid-utf8"});
        }))
        .contains("cannot be carried")
    );
    // Boundaries: strictly increasing, inside the content, and bounded.
    for boundaries in [
        json!([2, 2]),
        json!([3, 2]),
        json!([0]),
        json!([1000]),
        json!([]),
    ] {
        assert!(
            reason(mutate(
                "reject-surrogate",
                |v| v["representation"]["chunking"]["boundaries"] = boundaries.clone()
            ))
            .contains("chunk boundar"),
            "{boundaries}"
        );
    }
}

#[test]
fn lineage_is_shape_checked_and_never_asserts() {
    // A representation with nothing in it.
    assert!(
        reason(mutate("raw-control", |v| v["representation"] = json!({})))
            .contains("carries no fact")
    );
    // encode steps fit their codec.
    let enc = |step: Value| {
        mutate("enc-pending", |v| {
            v["representation"]["transformation"]["steps"] = json!([step]);
        })
    };
    assert!(
        reason(enc(
            json!({"op": "encode", "codec": "base64", "case": "lower"})
        ))
        .contains("encode step")
    );
    assert!(
        reason(enc(
            json!({"op": "encode", "codec": "hex", "alphabet": "standard", "padding": "padded"})
        ))
        .contains("encode step")
    );
    assert!(enc(json!({"op": "encode", "codec": "hex", "case": "mixed"})).is_ok());
    // Projections name bases; an authored base names none; no duplicates.
    let derive = |d: Value| mutate("enc-pending", |v| v["representation"]["derivation"] = d);
    assert!(reason(derive(json!({"kind": "projection"}))).contains("bases"));
    assert!(reason(derive(json!({"kind": "authored-base", "bases": ["a"]}))).contains("no bases"));
    assert!(
        reason(derive(json!({"kind": "projection", "bases": ["a", "a"]}))).contains("duplicate")
    );
    // Zero counts and widths.
    assert!(reason(enc(json!({"op": "repeat", "count": 0}))).contains("zero"));
    assert!(
        reason(enc(
            json!({"op": "fragment", "mechanism": "wrap", "line_break": "lf",
                "width": 0, "reconstruction": "unresolved"})
        ))
        .contains("zero")
    );
    // The transformation list is bounded.
    let many: Vec<Value> = (0..17)
        .map(|_| json!({"op": "repeat", "count": 2}))
        .collect();
    assert!(
        reason(mutate(
            "enc-pending",
            |v| v["representation"]["transformation"]["steps"] = json!(many)
        ))
        .contains("step count")
    );
}

#[test]
fn unknown_vocabulary_is_refused_not_ignored() {
    let mut v = serde_json::to_value(pending_case()).unwrap();
    v["representation"]["transformation"]["steps"][0]["op"] = json!("rot13");
    assert!(serde_json::from_value::<Case>(v).is_err());
    let mut v = serde_json::to_value(pending_case()).unwrap();
    v["representation"]["color"] = json!("red");
    assert!(serde_json::from_value::<Case>(v).is_err());
    let mut v = serde_json::to_value(b64_case()).unwrap();
    v["expected"][0]["decoded"]["value"] = json!("not carried");
    assert!(serde_json::from_value::<Case>(v).is_err());
    // A decoded value has no place to live: only its length and digest.
    let mut v = serde_json::to_value(b64_case()).unwrap();
    v["expected"][0]["decoded"]["sha256"] = json!("not-a-digest");
    assert!(serde_json::from_value::<Case>(v).is_err());
}

#[test]
fn the_snapshot_validates_against_the_generated_schema() {
    let (_, schema) = all_schemas()
        .into_iter()
        .find(|(name, _)| *name == "corpus-snapshot-v1.schema.json")
        .unwrap();
    let schema = serde_json::to_value(schema).unwrap();
    let validator = jsonschema::validator_for(&schema).expect("schema compiles");
    let instance = serde_json::to_value(snapshot_of(all_cases())).unwrap();
    let errors: Vec<String> = validator
        .iter_errors(&instance)
        .map(|e| e.to_string())
        .collect();
    assert!(errors.is_empty(), "{errors:?}");
    // And the schema refuses what the types refuse.
    let mut bad = instance.clone();
    bad["cases"][0]["representation"]["transformation"]["steps"][0]["op"] = json!("rot13");
    assert!(!validator.is_valid(&bad));
}

fn fixture_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/representation-smoke/corpus-snapshot.json")
}

/// The committed `representation-smoke` snapshot is exactly the snapshot these
/// tests build, so the kernel's golden artifact and the real-scanner test read
/// the same cases. Regenerate with
/// `UPDATE_GOLDEN=1 cargo test -p credential-eval-contracts --test representation`.
#[test]
fn the_committed_representation_snapshot_is_current() {
    let mut text = serde_json::to_string_pretty(&snapshot_of(all_cases())).unwrap();
    text.push('\n');
    if std::env::var_os("UPDATE_GOLDEN").is_some() {
        std::fs::write(fixture_path(), &text).expect("write fixture");
    }
    let committed = std::fs::read_to_string(fixture_path()).expect("committed snapshot");
    assert_eq!(text, committed, "representation-smoke snapshot is stale");
    CorpusSnapshot::from_json(committed.as_bytes()).expect("the committed snapshot is valid");
}
