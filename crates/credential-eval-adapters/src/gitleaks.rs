//! Gitleaks adapter: port of the legacy `gitleaks` scanner entry and its
//! normalizers (`scanners/index.mjs:112-192, 366-387`).

use std::ffi::OsString;
use std::path::Path;
use std::sync::LazyLock;

use credential_eval_contracts::config::{AdapterIdentity, ScannerSpec};
use credential_eval_contracts::ids::FixturePath;
use credential_eval_contracts::observation::ObservationResult;
use regex::Regex;
use serde_json::{Value, json};

use crate::families::{FAMILY_MAPPING_VERSION, LabelTable, finding_family};
use crate::locate::{Claims, Fixtures, Line, Located, MapError, locate, utf16_prefix_bytes};
use crate::process::CancelToken;
use crate::{
    Adapter, AdapterEnv, Invocation, Measured, NormalizedFinding, PrepareFailure, Prepared,
    ScannerBuild, adapter_identity, default_limits, spec,
};

/// Optional configuration key choosing what an unmappable finding does.
/// Absent or `"fail"`: the whole scanner is `malformed` (the default). The
/// value [`UNMEASURED_CASE`]: the fixture the finding is in is reported
/// unmeasured and the scan stays complete (ADR 0003).
pub const UNMAPPABLE_FINDINGS_KEY: &str = "unmappable_findings";
/// The per-case value of [`UNMAPPABLE_FINDINGS_KEY`].
pub const UNMEASURED_CASE: &str = "unmeasured-case";

/// Adapter id.
pub const ID: &str = "gitleaks";
/// Adapter version (legacy `adapterVersion: 2`).
pub const VERSION: &str = "2";
/// The pinned Gitleaks release the legacy suite measured.
pub const PINNED_VERSION: &str = "8.30.1";
/// Scan arguments; `<input-root>` is replaced by the materialized root.
pub const ARGUMENTS: &[&str] = &[
    "dir",
    "<input-root>",
    "--no-banner",
    "--no-color",
    "--exit-code",
    "0",
    "--report-format",
    "json",
    "--report-path",
    "-",
];

/// The Gitleaks adapter.
#[derive(Debug, Clone, Copy, Default)]
pub struct Gitleaks;

impl Adapter for Gitleaks {
    fn identity(&self) -> AdapterIdentity {
        adapter_identity(ID, VERSION)
    }

    fn build(&self, _spec: &ScannerSpec) -> ScannerBuild {
        // A standalone executable resolved from the configured program. Its
        // exact bytes are bound by a `pin.sha256` in an official run.
        ScannerBuild::Released
    }

    fn default_spec(&self) -> ScannerSpec {
        spec(
            ID,
            self.identity(),
            "Directory scan · default rules",
            json!({
                "binary": "gitleaks",
                "arguments": ARGUMENTS,
                "rules": "default",
                "environment_rule_overrides": false,
                "family_mapping_version": FAMILY_MAPPING_VERSION,
                "required_version": PINNED_VERSION,
            }),
            // Legacy gives Gitleaks a 64 MiB buffer (index.mjs:8-11).
            default_limits(64 * 1024 * 1024),
        )
    }

    fn prepare(
        &self,
        spec: &ScannerSpec,
        env: &AdapterEnv,
        cancel: &CancelToken,
    ) -> Result<Prepared, Box<PrepareFailure>> {
        let mut prepared = crate::binary::prepare(
            spec,
            env,
            cancel,
            &crate::binary::BinaryAdapter {
                allowed: &[
                    "binary",
                    "arguments",
                    "rules",
                    "environment_rule_overrides",
                    "family_mapping_version",
                    "required_version",
                    UNMAPPABLE_FINDINGS_KEY,
                ],
                fixed: &[
                    ("arguments", json!(ARGUMENTS)),
                    ("rules", json!("default")),
                    ("environment_rule_overrides", json!(false)),
                    ("family_mapping_version", json!(FAMILY_MAPPING_VERSION)),
                ],
                version_args: &["version"],
                network_controls: &[],
            },
        )?;
        let per_case = match spec.configuration.get(UNMAPPABLE_FINDINGS_KEY) {
            None => false,
            Some(Value::String(v)) if v == "fail" => false,
            Some(Value::String(v)) if v == UNMEASURED_CASE => true,
            Some(_) => {
                return Err(Box::new(PrepareFailure {
                    result: ObservationResult::Error {
                        reason: format!("invalid scanner configuration: {UNMAPPABLE_FINDINGS_KEY}"),
                    },
                    version: prepared.version,
                    provenance: prepared.provenance,
                    processes: prepared.processes,
                    process_time: prepared.process_time,
                }));
            }
        };
        prepared.settings = json!({ "per_case": per_case });
        Ok(prepared)
    }

    fn scan_invocation(&self, prepared: &Prepared, root: &Path, _paths: &[&str]) -> Invocation {
        Invocation {
            program: prepared.program.clone(),
            args: substitute(ARGUMENTS, root),
            stdin: None,
        }
    }

    fn normalize(
        &self,
        _prepared: &Prepared,
        stdout: &[u8],
        fixtures: &Fixtures<'_>,
    ) -> Result<Vec<NormalizedFinding>, MapError> {
        normalize(stdout, fixtures)
    }

    fn normalize_measured(
        &self,
        prepared: &Prepared,
        stdout: &[u8],
        fixtures: &Fixtures<'_>,
    ) -> Result<Measured, MapError> {
        if prepared.settings.get("per_case") == Some(&Value::Bool(true)) {
            normalize_per_case(stdout, fixtures)
        } else {
            normalize(stdout, fixtures).map(|findings| Measured {
                findings,
                unmeasured: Vec::new(),
            })
        }
    }
}

pub(crate) fn substitute(arguments: &[&str], root: &Path) -> Vec<OsString> {
    arguments
        .iter()
        .map(|arg| {
            if *arg == "<input-root>" {
                root.as_os_str().to_owned()
            } else {
                OsString::from(arg)
            }
        })
        .collect()
}

/// Normalize a Gitleaks JSON report (legacy `scan`, `index.mjs:375-386`).
///
/// Deviation: rows are processed in canonical (serialized) order instead of
/// report order, which Gitleaks does not keep stable between runs.
pub fn normalize(
    stdout: &[u8],
    fixtures: &Fixtures<'_>,
) -> Result<Vec<NormalizedFinding>, MapError> {
    let rows = canonical_rows(stdout)?;
    let mut claims = Claims::default();
    let rows = without_decoded_duplicates(&rows);
    rows.into_iter()
        .map(|row| map_row(fixtures, row, &mut claims))
        .collect()
}

/// [`normalize`] where a row that cannot be mapped makes its fixture
/// unmeasured instead of failing the scan (ADR 0003).
///
/// A failure is attributed to the fixture the row names, and only when that
/// names a known fixture; otherwise it still fails closed. Every finding on an
/// unmeasured fixture is discarded, so the fixture reads as not measured and
/// never as a zero detection. Other fixtures are mapped exactly as in
/// [`normalize`]. Rows are processed in the same canonical order, so the
/// result does not depend on report order.
pub fn normalize_per_case(stdout: &[u8], fixtures: &Fixtures<'_>) -> Result<Measured, MapError> {
    let rows = canonical_rows(stdout)?;
    let mut claims = Claims::default();
    let rows = without_decoded_duplicates(&rows);
    let mut findings: Vec<(String, NormalizedFinding)> = Vec::new();
    let mut unmeasured: std::collections::BTreeMap<String, &'static str> =
        std::collections::BTreeMap::new();
    for row in rows {
        match map_row(fixtures, row, &mut claims) {
            Ok(finding) => findings.push((finding.path.to_string(), finding)),
            Err(error) => {
                let reason = error.0;
                let file = row
                    .get("File")
                    .and_then(Value::as_str)
                    .ok_or(MapError(reason))?;
                let (path, _) = fixtures.resolve(file).map_err(|_| MapError(reason))?;
                unmeasured.entry(path.to_owned()).or_insert(reason);
            }
        }
    }
    let findings = findings
        .into_iter()
        .filter(|(path, _)| !unmeasured.contains_key(path))
        .map(|(_, finding)| finding)
        .collect();
    let unmeasured = unmeasured
        .into_iter()
        .map(|(path, reason)| {
            FixturePath::new(path)
                .map(|p| (p, reason))
                .map_err(|_| MapError("Unknown scanner path"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(Measured {
        findings,
        unmeasured,
    })
}

/// Parse the report and put its rows in canonical (serialized) order.
fn canonical_rows(stdout: &[u8]) -> Result<Vec<Value>, MapError> {
    let parsed: Value =
        serde_json::from_slice(stdout).map_err(|_| MapError("Invalid scanner output"))?;
    let Value::Array(mut rows) = parsed else {
        return Err(MapError("Invalid scanner output"));
    };
    // Gitleaks scans files concurrently and its report order varies between
    // runs. Map rows in a canonical order so claim resolution and the
    // kernel's last-duplicate-wins classification are deterministic.
    rows.sort_by_cached_key(ToString::to_string);
    Ok(rows)
}

fn map_row(
    fixtures: &Fixtures<'_>,
    row: &Value,
    claims: &mut Claims,
) -> Result<NormalizedFinding, MapError> {
    let located = normalize_row(fixtures, row, claims)?;
    let family = finding_family(
        LabelTable::Gitleaks,
        row.get("RuleID").and_then(Value::as_str),
        None,
    );
    finding(located, family)
}

pub(crate) fn finding(
    located: Located,
    family: Option<String>,
) -> Result<NormalizedFinding, MapError> {
    Ok(NormalizedFinding {
        path: FixturePath::new(located.path).map_err(|_| MapError("Unknown scanner path"))?,
        start: located.start as u64,
        end: located.end as u64,
        family,
        action: None,
    })
}

fn has_tag(row: &Value, tag: &str) -> bool {
    row.get("Tags")
        .and_then(Value::as_array)
        .is_some_and(|tags| tags.iter().any(|t| t.as_str() == Some(tag)))
}

/// Legacy `withoutDecodedDuplicates` (`index.mjs:119-123`): drop a
/// `decoded:base64` row that starts where a plain row of the same rule starts,
/// except `private-key` rows.
pub fn without_decoded_duplicates(rows: &[Value]) -> Vec<&Value> {
    let at = |r: &Value| {
        ["RuleID", "File", "StartLine", "EndLine", "StartColumn"]
            .map(|k| r.get(k).cloned().unwrap_or(Value::Null))
    };
    let plain: Vec<[Value; 5]> = rows
        .iter()
        .filter(|r| !has_tag(r, "decoded:base64"))
        .map(at)
        .collect();
    rows.iter()
        .filter(|r| {
            !has_tag(r, "decoded:base64")
                || r.get("RuleID").and_then(Value::as_str) == Some("private-key")
                || !plain.contains(&at(r))
        })
        .collect()
}

/// Legacy `normalizeGitleaks` (`index.mjs:128-153`).
pub fn normalize_row(
    fixtures: &Fixtures<'_>,
    row: &Value,
    claims: &mut Claims,
) -> Result<Located, MapError> {
    let file = row.get("File").and_then(Value::as_str);
    let secret = row.get("Secret").and_then(Value::as_str);
    if !has_tag(row, "decoded:base64") {
        return locate(
            fixtures,
            file,
            secret,
            Line::from_json(row.get("StartLine")),
            claims,
        );
    }
    let (true, Some(file), Some(secret)) = (has_tag(row, "decode-depth:1"), file, secret) else {
        return Err(MapError("Unsupported decoded Gitleaks finding"));
    };
    if row.get("RuleID").and_then(Value::as_str) != Some("private-key") {
        return locate_decoded_base64(fixtures, file, secret, row.get("StartLine"));
    }
    let (path, content) = fixtures.resolve(file)?;
    let start_line = Line::from_json(row.get("StartLine"));
    let mut matches = Vec::new();
    for caps in PEM.captures_iter(content) {
        let whole = caps.get(0).expect("group 0");
        let (kind, nl1, body, nl2, end_kind) = (&caps[1], &caps[2], &caps[3], &caps[4], &caps[5]);
        if kind != end_kind {
            continue; // legacy back-reference `-----END \1-----`
        }
        let decoded = base64_decode_lenient(body);
        if base64_encode(&decoded) != body {
            continue;
        }
        let Ok(text) = std::str::from_utf8(&decoded) else {
            continue;
        };
        let transformed = format!("-----BEGIN {kind}-----{nl1}{text}{nl2}-----END {kind}-----");
        let line = crate::locate::line_of(content, whole.start());
        #[allow(clippy::cast_precision_loss)]
        let same_line = matches!(start_line, Line::Number(n) if n == line as f64);
        if transformed != secret || !same_line {
            continue;
        }
        matches.push(Located {
            path: path.to_owned(),
            start: whole.start(),
            end: whole.end(),
        });
    }
    match <[Located; 1]>::try_from(matches) {
        Ok([located]) => Ok(located),
        Err(_) => Err(MapError("Ambiguous or unmappable decoded PEM finding")),
    }
}

static PEM: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(concat!(
        r"-----BEGIN ((?:(?:RSA|DSA|EC|OPENSSH|ENCRYPTED) )?PRIVATE KEY)-----(\r?\n)",
        r"([A-Za-z0-9+/]+={0,2})(\r?\n)",
        r"-----END ((?:(?:RSA|DSA|EC|OPENSSH|ENCRYPTED) )?PRIVATE KEY)-----"
    ))
    .expect("static regex")
});

static BASE64_RUN: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"[A-Za-z0-9+/_-]{8,}={0,2}").expect("static regex"));

/// Legacy `locateDecodedBase64` (`index.mjs:163-192`). Offsets inside the
/// line are computed in UTF-16 code units, as the legacy JavaScript does, and
/// converted to bytes with `Buffer.byteLength` semantics.
pub fn locate_decoded_base64(
    fixtures: &Fixtures<'_>,
    file: &str,
    secret: &str,
    start_line: Option<&Value>,
) -> Result<Located, MapError> {
    const UNMAPPABLE: MapError = MapError("Unmappable decoded Gitleaks finding");
    let (path, content) = fixtures.resolve(file).map_err(|_| UNMAPPABLE)?;
    if secret.is_empty() {
        return Err(UNMAPPABLE);
    }
    // `lines[row.StartLine - 1]`: only a positive integer line indexes a line.
    let index = start_line
        .and_then(Value::as_f64)
        .filter(|n| n.fract() == 0.0 && *n >= 1.0)
        .ok_or(UNMAPPABLE)?;
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    let index = index as usize - 1;
    let lines: Vec<&str> = content.split('\n').collect();
    let line_text = *lines.get(index).ok_or(UNMAPPABLE)?;
    let line_start: usize = lines[..index].iter().map(|l| l.len() + 1).sum();
    let line16: Vec<u16> = line_text.encode_utf16().collect();
    let secret16: Vec<u16> = secret.encode_utf16().collect();
    let mut matches = Vec::new();
    for m in BASE64_RUN.find_iter(line_text) {
        // The run is ASCII, so its UTF-16 offsets follow from the prefix.
        let run_start = line_text[..m.start()].encode_utf16().count();
        let run_end = run_start + m.as_str().len();
        let standard: String = m
            .as_str()
            .chars()
            .map(|c| match c {
                '-' => '+',
                '_' => '/',
                c => c,
            })
            .collect();
        let bytes = base64_decode_lenient(&standard);
        if base64_encode(&bytes).trim_end_matches('=') != standard.trim_end_matches('=') {
            continue;
        }
        let Ok(decoded) = std::str::from_utf8(&bytes) else {
            continue;
        };
        let decoded16: Vec<u16> = decoded.encode_utf16().collect();
        let mut substituted = line16[..run_start].to_vec();
        substituted.extend_from_slice(&decoded16);
        substituted.extend_from_slice(&line16[run_end..]);
        let decoded_end = run_start + decoded16.len();
        let mut from = 0;
        while let Some(at) = find_u16(&substituted, &secret16, from) {
            from = at + 1;
            let secret_end = at + secret16.len();
            if secret_end <= run_start || at >= decoded_end {
                continue; // must overlap the decoded text
            }
            let end = if secret_end > decoded_end {
                run_end + (secret_end - decoded_end)
            } else {
                run_end
            };
            let start = line_start + utf16_prefix_bytes(&line16, run_start.min(at));
            matches.push(Located {
                path: path.to_owned(),
                start,
                end: line_start + utf16_prefix_bytes(&line16, end),
            });
        }
    }
    match <[Located; 1]>::try_from(matches) {
        Ok([located]) => Ok(located),
        Err(_) => Err(MapError("Ambiguous or unmappable decoded Gitleaks finding")),
    }
}

fn find_u16(haystack: &[u16], needle: &[u16], from: usize) -> Option<usize> {
    if needle.is_empty() || from > haystack.len() || needle.len() > haystack.len() - from {
        return None;
    }
    (from..=haystack.len() - needle.len()).find(|&i| haystack[i..i + needle.len()] == *needle)
}

const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Node's lenient `Buffer.from(s, "base64")` for the characters the callers
/// pass (`[A-Za-z0-9+/]` optionally followed by `=`): decoding stops at the
/// first `=`, a trailing group of 2 or 3 characters yields 1 or 2 bytes, and
/// a lone trailing character is dropped.
pub fn base64_decode_lenient(input: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(input.len() * 3 / 4);
    let mut acc = 0u32;
    let mut bits = 0;
    for c in input.bytes() {
        if c == b'=' {
            break;
        }
        let Some(value) = B64.iter().position(|b| *b == c) else {
            continue;
        };
        #[allow(clippy::cast_possible_truncation)]
        {
            acc = (acc << 6) | value as u32;
        }
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            #[allow(clippy::cast_possible_truncation)]
            out.push((acc >> bits) as u8);
            acc &= (1 << bits) - 1;
        }
    }
    out
}

/// Standard padded base64 (`buffer.toString("base64")`).
pub fn base64_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let n = match chunk.len() {
            3 => (u32::from(chunk[0]) << 16) | (u32::from(chunk[1]) << 8) | u32::from(chunk[2]),
            2 => (u32::from(chunk[0]) << 16) | (u32::from(chunk[1]) << 8),
            _ => u32::from(chunk[0]) << 16,
        };
        let symbols = chunk.len() + 1;
        for i in 0..4 {
            if i < symbols {
                out.push(char::from(B64[((n >> (18 - 6 * i)) & 63) as usize]));
            } else {
                out.push('=');
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const ROOT: &str = "/tmp/root";

    fn fx<'a>(files: &[(&'a str, &'a str)]) -> Fixtures<'a> {
        Fixtures::new(ROOT, files.iter().copied())
    }

    fn report(rows: Value) -> Vec<u8> {
        serde_json::to_vec(&rows).unwrap()
    }

    #[test]
    fn plain_rows_map_to_utf8_ranges_with_families() {
        let content = "héllo\ntoken = EXAMPLEFAKETOKEN1234\n";
        let fixtures = fx(&[("a/f.txt", content)]);
        let out = report(json!([
            {"RuleID": "generic-api-key", "File": "/tmp/root/a/f.txt", "Secret": "EXAMPLEFAKETOKEN1234",
             "Match": "token = EXAMPLEFAKETOKEN1234", "StartLine": 2, "EndLine": 2, "StartColumn": 9, "Tags": []},
            {"RuleID": "not-mapped", "File": "a/f.txt", "Secret": "héllo", "StartLine": 1}
        ]));
        let findings = normalize(&out, &fixtures).unwrap();
        assert_eq!(findings.len(), 2);
        let start = content.find("EXAMPLE").unwrap() as u64;
        assert_eq!((findings[0].start, findings[0].end), (start, start + 20));
        assert_eq!(findings[0].family.as_deref(), Some("generic-token"));
        assert_eq!((findings[1].start, findings[1].end), (0, 6));
        assert_eq!(findings[1].family, None);
    }

    #[test]
    fn invalid_output_and_unknown_paths_fail_closed() {
        let fixtures = fx(&[("f", "x")]);
        assert_eq!(
            normalize(b"not json", &fixtures).unwrap_err().0,
            "Invalid scanner output"
        );
        assert_eq!(
            normalize(b"{}", &fixtures).unwrap_err().0,
            "Invalid scanner output"
        );
        assert_eq!(
            normalize(b"", &fixtures).unwrap_err().0,
            "Invalid scanner output"
        );
        let out =
            report(json!([{"RuleID": "jwt", "File": "/other/f", "Secret": "x", "StartLine": 1}]));
        assert_eq!(
            normalize(&out, &fixtures).unwrap_err().0,
            "Unknown scanner path"
        );
        assert!(normalize(b"[]", &fixtures).unwrap().is_empty());
    }

    #[test]
    fn same_value_twice_on_a_line_claims_ascending_occurrences() {
        let content = "a=SAMEFAKEVALUE01 b=SAMEFAKEVALUE01\n";
        let fixtures = fx(&[("f", content)]);
        let row = json!({"RuleID": "generic-api-key", "File": "f", "Secret": "SAMEFAKEVALUE01", "StartLine": 1});
        let out = report(json!([row, row]));
        let findings = normalize(&out, &fixtures).unwrap();
        assert_eq!(findings[0].start, 2);
        assert_eq!(findings[1].start, 20);
        // A third report has no occurrence left and fails closed.
        let out = report(json!([row, row, row]));
        assert!(normalize(&out, &fixtures).is_err());
    }

    #[test]
    fn decoded_duplicates_are_dropped_unless_private_key() {
        let plain = json!({"RuleID": "r", "File": "f", "StartLine": 1, "EndLine": 1, "StartColumn": 3, "Tags": []});
        let dup = json!({"RuleID": "r", "File": "f", "StartLine": 1, "EndLine": 1, "StartColumn": 3,
                         "EndColumn": 0, "Tags": ["decoded:base64", "decode-depth:1"]});
        let other = json!({"RuleID": "r", "File": "f", "StartLine": 1, "EndLine": 1, "StartColumn": 4,
                           "Tags": ["decoded:base64"]});
        let pk_plain = json!({"RuleID": "private-key", "File": "f", "StartLine": 1, "EndLine": 1, "StartColumn": 3, "Tags": []});
        let pk = json!({"RuleID": "private-key", "File": "f", "StartLine": 1, "EndLine": 1, "StartColumn": 3,
                        "Tags": ["decoded:base64"]});
        let rows = vec![plain, dup, other.clone(), pk_plain, pk.clone()];
        let kept = without_decoded_duplicates(&rows);
        assert_eq!(kept.len(), 4);
        assert!(kept.contains(&&other));
        assert!(kept.contains(&&pk));
    }

    #[test]
    fn decoded_rows_need_depth_one() {
        let fixtures = fx(&[("f", "x")]);
        let out = report(
            json!([{"RuleID": "r", "File": "f", "Secret": "x", "StartLine": 1, "Tags": ["decoded:base64"]}]),
        );
        assert_eq!(
            normalize(&out, &fixtures).unwrap_err().0,
            "Unsupported decoded Gitleaks finding"
        );
    }

    #[test]
    fn per_case_handling_drops_only_the_unmappable_fixture() {
        let fixtures = fx(&[("ok.txt", "key = AAAA1111\n"), ("enc.txt", "x")]);
        let out = report(json!([
            {"RuleID": "generic-api-key", "File": "ok.txt", "Secret": "AAAA1111", "StartLine": 1, "Tags": []},
            {"RuleID": "r", "File": "enc.txt", "Secret": "x", "StartLine": 1,
             "Tags": ["decoded:base64", "decode-depth:2"]},
            {"RuleID": "generic-api-key", "File": "enc.txt", "Secret": "x", "StartLine": 1, "Tags": []}
        ]));
        // The whole-scan reading still fails closed.
        assert!(normalize(&out, &fixtures).is_err());
        let measured = normalize_per_case(&out, &fixtures).unwrap();
        assert_eq!(measured.findings.len(), 1);
        assert_eq!(measured.findings[0].path.as_str(), "ok.txt");
        assert_eq!(measured.unmeasured.len(), 1);
        assert_eq!(measured.unmeasured[0].0.as_str(), "enc.txt");
        assert_eq!(
            measured.unmeasured[0].1,
            "Unsupported decoded Gitleaks finding"
        );
        // A failure that names no known fixture, or unparseable output, still fails closed.
        let unknown = report(
            json!([{"RuleID": "r", "File": "nope.txt", "Secret": "x", "StartLine": 1, "Tags": []}]),
        );
        assert!(normalize_per_case(&unknown, &fixtures).is_err());
        assert!(normalize_per_case(b"not json", &fixtures).is_err());
    }

    #[test]
    fn decoded_pem_recovers_the_whole_block() {
        // Body is base64 of a single-line synthetic PEM body.
        let inner = "FAKEPEMBODYEXAMPLE";
        let body = base64_encode(inner.as_bytes());
        let content =
            format!("x\n-----BEGIN RSA PRIVATE KEY-----\n{body}\n-----END RSA PRIVATE KEY-----\n");
        let fixtures = fx(&[("k.pem", content.as_str())]);
        let secret =
            format!("-----BEGIN RSA PRIVATE KEY-----\n{inner}\n-----END RSA PRIVATE KEY-----");
        let out = report(
            json!([{"RuleID": "private-key", "File": "k.pem", "Secret": secret, "StartLine": 2,
                                 "Tags": ["decoded:base64", "decode-depth:1"]}]),
        );
        let findings = normalize(&out, &fixtures).unwrap();
        assert_eq!(findings[0].start, 2);
        assert_eq!(findings[0].end as usize, content.len() - 1);
        assert_eq!(findings[0].family.as_deref(), Some("private-key"));
        // Wrong line fails closed.
        let out = report(
            json!([{"RuleID": "private-key", "File": "k.pem", "Secret": secret, "StartLine": 1,
                                 "Tags": ["decoded:base64", "decode-depth:1"]}]),
        );
        assert!(normalize(&out, &fixtures).is_err());
    }

    #[test]
    fn decoded_base64_run_maps_to_the_source_run_plus_trailing_bytes() {
        // "FAKEPART" base64-encodes to "RkFLRVBBUlQ="; the rule matched the
        // decoded text plus ".tail" after it.
        let run = base64_encode(b"FAKEPART");
        let content = format!("é key: {run}.tail rest\n");
        let fixtures = fx(&[("d.txt", content.as_str())]);
        let out = report(
            json!([{"RuleID": "generic-api-key", "File": "d.txt", "Secret": "FAKEPART.tail",
                                 "StartLine": 1, "Tags": ["decoded:base64", "decode-depth:1"]}]),
        );
        let findings = normalize(&out, &fixtures).unwrap();
        let start = content.find(&run).unwrap();
        assert_eq!(findings[0].start as usize, start);
        assert_eq!(
            &content[start..findings[0].end as usize],
            format!("{run}.tail")
        );
        // A secret that does not overlap the decoded text fails closed.
        let out = report(
            json!([{"RuleID": "generic-api-key", "File": "d.txt", "Secret": "rest",
                                 "StartLine": 1, "Tags": ["decoded:base64", "decode-depth:1"]}]),
        );
        assert!(normalize(&out, &fixtures).is_err());
    }

    #[test]
    fn base64_helpers_match_node() {
        assert_eq!(base64_encode(b"a"), "YQ==");
        assert_eq!(base64_encode(b"ab"), "YWI=");
        assert_eq!(base64_decode_lenient("YQ"), b"a");
        assert_eq!(base64_decode_lenient("YQ=="), b"a");
        assert_eq!(base64_decode_lenient("YWJj"), b"abc");
        assert_eq!(base64_decode_lenient("YWJjZ"), b"abc"); // lone char dropped
        // Non-canonical trailing bits are rejected by the round trip.
        assert_ne!(
            base64_encode(&base64_decode_lenient("YR")).trim_end_matches('='),
            "YR"
        );
    }
}
