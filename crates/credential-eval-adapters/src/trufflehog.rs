//! TruffleHog adapter: port of the legacy `trufflehog` scanner entry and its
//! normalizers (`scanners/index.mjs:194-333, 388-412`). Verification and
//! self-update are always disabled.
//!
//! The pinned release is **3.97.4**: 3.97.6 re-keys results, so the default
//! configuration requires 3.97.4 and reports any other version as
//! `unavailable` (set `required_version` to `null` for exploratory runs).

use std::path::Path;
use std::sync::LazyLock;

use credential_eval_contracts::config::{AdapterIdentity, ScannerSpec};
use regex::Regex;
use serde_json::{Value, json};

use crate::families::{FAMILY_MAPPING_VERSION, LabelTable, finding_family};
use crate::gitleaks::{finding, substitute};
use crate::locate::{
    Claims, Fixtures, Line, Located, MapError, has_percent_escape, line_of, locate,
    locate_percent_encoded,
};
use crate::process::CancelToken;
use crate::{
    Adapter, AdapterEnv, Invocation, NormalizedFinding, PrepareFailure, Prepared, adapter_identity,
    default_limits, spec,
};

/// Adapter id.
pub const ID: &str = "trufflehog";
/// Adapter version (legacy `adapterVersion: 2`).
pub const VERSION: &str = "2";
/// The pinned TruffleHog release.
pub const PINNED_VERSION: &str = "3.97.4";
/// Scan arguments; `<input-root>` is replaced by the materialized root.
pub const ARGUMENTS: &[&str] = &[
    "filesystem",
    "<input-root>",
    "--json",
    "--no-verification",
    "--no-update",
    "--results=verified,unknown,unverified",
];

/// The TruffleHog adapter.
#[derive(Debug, Clone, Copy, Default)]
pub struct Trufflehog;

impl Adapter for Trufflehog {
    fn identity(&self) -> AdapterIdentity {
        adapter_identity(ID, VERSION)
    }

    fn default_spec(&self) -> ScannerSpec {
        spec(
            ID,
            self.identity(),
            "Filesystem scan · verification disabled",
            json!({
                "binary": "trufflehog",
                "arguments": ARGUMENTS,
                "verification": false,
                "update": false,
                "family_mapping_version": FAMILY_MAPPING_VERSION,
                "required_version": PINNED_VERSION,
            }),
            default_limits(16 * 1024 * 1024),
        )
    }

    fn prepare(
        &self,
        spec: &ScannerSpec,
        env: &AdapterEnv,
        cancel: &CancelToken,
    ) -> Result<Prepared, Box<PrepareFailure>> {
        crate::binary::prepare(
            spec,
            env,
            cancel,
            &crate::binary::BinaryAdapter {
                allowed: &[
                    "binary",
                    "arguments",
                    "verification",
                    "update",
                    "family_mapping_version",
                    "required_version",
                ],
                fixed: &[
                    ("arguments", json!(ARGUMENTS)),
                    ("verification", json!(false)),
                    ("update", json!(false)),
                    ("family_mapping_version", json!(FAMILY_MAPPING_VERSION)),
                ],
                version_args: &["--version", "--no-update"],
                network_controls: &["--no-update", "--no-verification"],
            },
        )
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
}

/// Normalize TruffleHog NDJSON output (legacy `scan`, `index.mjs:397-411`).
///
/// Deviation: lines are processed in byte order instead of emission order,
/// which TruffleHog does not keep stable between runs.
pub fn normalize(
    stdout: &[u8],
    fixtures: &Fixtures<'_>,
) -> Result<Vec<NormalizedFinding>, MapError> {
    let text = std::str::from_utf8(stdout).map_err(|_| MapError("Invalid scanner output"))?;
    let mut claims = Claims::default();
    let mut out = Vec::new();
    // TruffleHog emits results as its workers finish, so the order varies
    // between runs. Process lines in byte order for deterministic claims and
    // last-duplicate-wins classification.
    let mut lines: Vec<&str> = text.split('\n').filter(|l| !l.trim().is_empty()).collect();
    lines.sort_unstable();
    for line in lines {
        let row: Value =
            serde_json::from_str(line).map_err(|_| MapError("Invalid scanner output"))?;
        let family = finding_family(
            LabelTable::Trufflehog,
            row.get("DetectorName").and_then(Value::as_str),
            None,
        );
        for located in normalize_findings(fixtures, &row, &mut claims)? {
            out.push(finding(located, family.clone())?);
        }
    }
    Ok(out)
}

fn filesystem(row: &Value) -> Option<&Value> {
    row.get("SourceMetadata")?.get("Data")?.get("Filesystem")
}

fn meta_file(row: &Value) -> Option<&str> {
    filesystem(row)?.get("file")?.as_str()
}

fn meta_line(row: &Value) -> Line {
    Line::from_json(filesystem(row).and_then(|m| m.get("line")))
}

static AWS_PAIR: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^((?:AKIA|ABIA|ACCA)[A-Z0-9]{16}):([A-Za-z0-9/+]{40})$").expect("static regex")
});
static SHOPIFY: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^(shp(?:at|pa)_[a-fA-F0-9]{32})([a-zA-Z0-9-]+\.myshopify\.com)$")
        .expect("static regex")
});

/// Legacy `normalizeTrufflehogFindings` (`index.mjs:324-333`): an AWS
/// credential pair yields both the key id and the secret.
pub fn normalize_findings(
    fixtures: &Fixtures<'_>,
    row: &Value,
    claims: &mut Claims,
) -> Result<Vec<Located>, MapError> {
    if row.get("DetectorName").and_then(Value::as_str) != Some("AWS") {
        return Ok(vec![normalize_row(fixtures, row, claims)?]);
    }
    let raw_v2 = row.get("RawV2").and_then(Value::as_str).unwrap_or("");
    let pair = AWS_PAIR
        .captures(raw_v2)
        .filter(|caps| row.get("Raw").and_then(Value::as_str) == Some(&caps[1]))
        .ok_or(MapError("Unsupported AWS composite finding"))?;
    let file = meta_file(row);
    Ok(vec![
        locate(fixtures, file, Some(&pair[1]), meta_line(row), claims)?,
        locate(fixtures, file, Some(&pair[2]), Line::Undefined, claims)?,
    ])
}

/// Legacy `normalizeTrufflehog` (`index.mjs:257-320`).
pub fn normalize_row(
    fixtures: &Fixtures<'_>,
    row: &Value,
    claims: &mut Claims,
) -> Result<Located, MapError> {
    let file = meta_file(row);
    let raw = row.get("Raw").and_then(Value::as_str);
    if row.get("DetectorName").and_then(Value::as_str) == Some("Shopify") {
        // v3.97.4 Shopify Raw concatenates token + shop domain: not a
        // contiguous source span. Recover only the token component.
        let parts = raw
            .and_then(|r| SHOPIFY.captures(r))
            .ok_or(MapError("Unsupported Shopify composite finding"))?;
        locate(fixtures, file, Some(&parts[2]), Line::Undefined, claims)?;
        return locate(fixtures, file, Some(&parts[1]), meta_line(row), claims);
    }
    if row.get("DetectorType").and_then(Value::as_f64) != Some(968.0) {
        return locate_trufflehog(fixtures, file, raw, meta_line(row), claims);
    }
    locate_postgres(fixtures, row, file, raw)
}

/// Legacy `locateTrufflehog` (`index.mjs:244-252`).
fn locate_trufflehog(
    fixtures: &Fixtures<'_>,
    file: Option<&str>,
    raw: Option<&str>,
    line: Line,
    claims: &mut Claims,
) -> Result<Located, MapError> {
    if let (Some(f), Some(r)) = (file, raw) {
        if has_percent_escape(r) {
            if let Ok((_, content)) = fixtures.resolve(f) {
                if !content.contains(r) {
                    return locate_percent_encoded(fixtures, file, raw, line, claims);
                }
            }
        }
    }
    locate(fixtures, file, raw, line, claims)
}

/// `\bpostgres(?:ql)?:\/\/\S+\b` with JavaScript (non-`u`) semantics: `\b`
/// over ASCII word characters and `\S` excluding the ECMAScript whitespace set.
static POSTGRES: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(concat!(
        r"(?i:postgres(?:ql)?)://",
        r"[^\t\n\x0B\x0C\r \x{A0}\x{1680}\x{2000}-\x{200A}\x{2028}\x{2029}\x{202F}\x{205F}\x{3000}\x{FEFF}]+"
    ))
    .expect("static regex")
});

fn is_word(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

/// All matches of the legacy Postgres URI regex, as byte ranges.
fn postgres_matches(content: &str) -> Vec<(usize, usize)> {
    let bytes = content.as_bytes();
    let mut out = Vec::new();
    let mut from = 0;
    while from <= content.len() {
        let Some(m) = POSTGRES.find_at(content, from) else {
            break;
        };
        // Leading `\b`: "p" is a word char, so the previous byte must not be.
        if m.start() > 0 && is_word(bytes[m.start() - 1]) {
            from = next_char(content, m.start());
            continue;
        }
        // Trailing `\b` after a greedy `\S+`: backtrack to the longest end
        // (past "://" plus at least one character) at a word boundary.
        let body_start = m.start() + content[m.start()..].find("://").expect("scheme") + 3;
        let mut end = m.end();
        let found = loop {
            if end <= body_start {
                break None;
            }
            let before = is_word(bytes[end - 1]);
            let after = end < bytes.len() && is_word(bytes[end]);
            if before != after {
                break Some(end);
            }
            end = prev_char(content, end);
        };
        match found {
            Some(end) => {
                out.push((m.start(), end));
                from = end.max(m.start() + 1);
                from = if content.is_char_boundary(from) {
                    from
                } else {
                    next_char(content, from)
                };
            }
            None => from = next_char(content, m.start()),
        }
    }
    out
}

fn next_char(s: &str, at: usize) -> usize {
    s[at..]
        .chars()
        .next()
        .map_or(s.len() + 1, |c| at + c.len_utf8())
}

fn prev_char(s: &str, at: usize) -> usize {
    s[..at].chars().next_back().map_or(0, |c| at - c.len_utf8())
}

/// Strict `decodeURIComponent`: `None` where JavaScript throws `URIError`.
fn decode_uri_component(s: &str) -> Option<String> {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            let hex = s.get(i + 1..i + 3)?;
            out.push(u8::from_str_radix(hex, 16).ok()?);
            if !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
                return None;
            }
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8(out).ok()
}

/// `(key, database)` of a Postgres URI with a password, as legacy `parse`.
fn parse_postgres(value: &str) -> Option<(Vec<String>, String)> {
    let url = url::Url::parse(value).ok()?;
    if !matches!(url.scheme(), "postgres" | "postgresql") {
        return None;
    }
    let password = url.password().filter(|p| !p.is_empty())?;
    let key = vec![
        decode_uri_component(url.username())?,
        decode_uri_component(password)?,
        url.host_str().unwrap_or("").to_owned(),
        url.port()
            .map_or_else(|| "5432".to_owned(), |p| p.to_string()),
    ];
    let path = url.path();
    let database = decode_uri_component(path.strip_prefix('/').unwrap_or(path))?;
    Some((key, database))
}

/// Legacy Postgres (DetectorType 968) recovery (`index.mjs:269-319`):
/// TruffleHog exports a normalized URI, so the original whole URI with the
/// same user, password, host and port (and database, when reported) on the
/// reported line is located. Never an expected range.
fn locate_postgres(
    fixtures: &Fixtures<'_>,
    row: &Value,
    file: Option<&str>,
    raw: Option<&str>,
) -> Result<Located, MapError> {
    let (Some(file), Some(raw)) = (file, raw) else {
        return Err(MapError("Unmappable Postgres finding"));
    };
    let (path, content) = fixtures.resolve(file)?;
    let (key, _) = parse_postgres(raw).ok_or(MapError("Unmappable Postgres finding"))?;
    let line = meta_line(row);
    let database = row.get("ExtraData").and_then(|e| e.get("database"));
    let mut matches = Vec::new();
    for (start, end) in postgres_matches(content) {
        let Some((candidate_key, candidate_db)) = parse_postgres(&content[start..end]) else {
            continue;
        };
        let line_ok = match line {
            Line::Undefined | Line::Null => true,
            #[allow(clippy::cast_precision_loss)]
            Line::Number(n) => n == line_of(content, start) as f64,
            Line::Other => false,
        };
        let db_ok = match database {
            None | Some(Value::Null) => true,
            Some(Value::String(db)) => *db == candidate_db,
            Some(_) => false,
        };
        if candidate_key == key && line_ok && db_ok {
            matches.push(Located {
                path: path.to_owned(),
                start,
                end,
            });
        }
    }
    match <[Located; 1]>::try_from(matches) {
        Ok([located]) => Ok(located),
        Err(_) => Err(MapError("Ambiguous or unmappable Postgres finding")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const ROOT: &str = "/tmp/th";

    fn fx<'a>(files: &[(&'a str, &'a str)]) -> Fixtures<'a> {
        Fixtures::new(ROOT, files.iter().copied())
    }

    fn row(detector: &str, detector_type: u64, raw: &str, file: &str, line: u64) -> Value {
        json!({
            "SourceMetadata": {"Data": {"Filesystem": {"file": file, "line": line}}},
            "DetectorType": detector_type, "DetectorName": detector, "Raw": raw, "Verified": false
        })
    }

    fn ndjson(rows: &[Value]) -> Vec<u8> {
        let mut out = String::new();
        for r in rows {
            out.push_str(&serde_json::to_string(r).unwrap());
            out.push('\n');
        }
        out.push('\n');
        out.into_bytes()
    }

    #[test]
    fn plain_rows_and_families() {
        let content = "ü\nkey: FAKEGITHUBTOKENEXAMPLE0001\n";
        let fixtures = fx(&[("x/y.txt", content)]);
        let out = ndjson(&[row(
            "Github",
            8,
            "FAKEGITHUBTOKENEXAMPLE0001",
            "/tmp/th/x/y.txt",
            2,
        )]);
        let f = normalize(&out, &fixtures).unwrap();
        let start = content.find("FAKE").unwrap() as u64;
        assert_eq!((f[0].start, f[0].end), (start, start + 26));
        assert_eq!(f[0].family.as_deref(), Some("github-token"));
        assert!(normalize(b"", &fixtures).unwrap().is_empty());
        assert!(normalize(b"{not json}\n", &fixtures).is_err());
    }

    #[test]
    fn aws_pair_yields_both_components() {
        let id = "AKIAFAKEEXAMPLE00001";
        let secret = "FAKEexampleSECRETkey0000000000000000000/+";
        assert_eq!(secret.len(), 41);
        let secret = &secret[..40];
        let content = format!("aws_access_key_id={id}\naws_secret_access_key={secret}\n");
        let fixtures = fx(&[("aws.env", content.as_str())]);
        let mut r = row("AWS", 2, id, "aws.env", 1);
        r["RawV2"] = json!(format!("{id}:{secret}"));
        let f = normalize(&ndjson(&[r.clone()]), &fixtures).unwrap();
        assert_eq!(f.len(), 2);
        assert_eq!(&content[f[0].start as usize..f[0].end as usize], id);
        assert_eq!(&content[f[1].start as usize..f[1].end as usize], secret);
        assert!(
            f.iter()
                .all(|x| x.family.as_deref() == Some("aws-access-key"))
        );
        // Raw that is not the pair's key id fails closed.
        r["Raw"] = json!("AKIAFAKEEXAMPLE00002");
        assert_eq!(
            normalize(&ndjson(&[r]), &fixtures).unwrap_err().0,
            "Unsupported AWS composite finding"
        );
    }

    #[test]
    fn shopify_composite_keeps_only_the_token() {
        let token = format!("shpat_{}", "0123456789abcdef0123456789abcdef");
        let content = format!("shop=fake-shop.myshopify.com\ntoken={token}\n");
        let fixtures = fx(&[("s.txt", content.as_str())]);
        let raw = format!("{token}fake-shop.myshopify.com");
        let f = normalize(&ndjson(&[row("Shopify", 9, &raw, "s.txt", 2)]), &fixtures).unwrap();
        assert_eq!(f.len(), 1);
        assert_eq!(&content[f[0].start as usize..f[0].end as usize], token);
        let bad = normalize(
            &ndjson(&[row("Shopify", 9, "shpat_nothex", "s.txt", 2)]),
            &fixtures,
        );
        assert_eq!(bad.unwrap_err().0, "Unsupported Shopify composite finding");
        // The domain must be present in the file.
        let other = format!("token={token}\n");
        let fixtures = fx(&[("s.txt", other.as_str())]);
        assert!(normalize(&ndjson(&[row("Shopify", 9, &raw, "s.txt", 1)]), &fixtures).is_err());
    }

    #[test]
    fn percent_encoded_fallback() {
        let content = "db = https://fakeuser:p!ss@example.invalid/x\n";
        let fixtures = fx(&[("u.txt", content)]);
        let raw = "https://fakeuser:p%21ss@example.invalid";
        let f = normalize(&ndjson(&[row("URI", 17, raw, "u.txt", 1)]), &fixtures).unwrap();
        assert_eq!(
            &content[f[0].start as usize..f[0].end as usize],
            "https://fakeuser:p!ss@example.invalid"
        );
    }

    #[test]
    fn postgres_recovers_the_original_uri() {
        let content = "x\nDATABASE_URL=postgresql://fakeuser:fakepass@db.example.invalid/appdb?sslmode=off end\n";
        let fixtures = fx(&[("p.env", content)]);
        let mut r = row(
            "Postgres",
            968,
            "postgresql://fakeuser:fakepass@db.example.invalid:5432",
            "p.env",
            2,
        );
        r["ExtraData"] = json!({"database": "appdb"});
        let f = normalize(&ndjson(&[r.clone()]), &fixtures).unwrap();
        assert_eq!(
            &content[f[0].start as usize..f[0].end as usize],
            "postgresql://fakeuser:fakepass@db.example.invalid/appdb?sslmode=off"
        );
        r["ExtraData"] = json!({"database": "other"});
        assert!(normalize(&ndjson(&[r]), &fixtures).is_err());
    }

    #[test]
    fn postgres_regex_word_boundaries() {
        assert_eq!(postgres_matches("xpostgres://a:b@h"), vec![]);
        assert_eq!(postgres_matches("postgres://a:b@h/db."), vec![(0, 19)]);
        assert_eq!(postgres_matches("POSTGRESQL://a:b@h:1 x"), vec![(0, 20)]);
        assert_eq!(postgres_matches("postgres://..."), vec![]);
    }

    #[test]
    fn decode_uri_component_is_strict() {
        assert_eq!(decode_uri_component("a%20b").as_deref(), Some("a b"));
        assert_eq!(decode_uri_component("%C3%A9").as_deref(), Some("é"));
        assert_eq!(decode_uri_component("%zz"), None);
        assert_eq!(decode_uri_component("%C3"), None);
        assert_eq!(decode_uri_component("%"), None);
    }
}
