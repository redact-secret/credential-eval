//! Adapters for npm-published scanners, run through the Node shim in
//! `adapters/node/shim.mjs` using only each package's public API.
//!
//! Ports the legacy in-process adapters (`scanners/index.mjs:336-365,
//! 413-467`): each fixture is read as UTF-8, scanned, and the scanner's
//! UTF-16 offsets are converted to UTF-8 byte offsets exactly as
//! `Buffer.byteLength(text.slice(0, i))` does. The shim reports positions and
//! labels only, never matched values. Offset conversion and family mapping
//! happen here, in Rust.
//!
//! Package source: `published` (default) resolves the package from the shim
//! directory, whose `package.json` and `package-lock.json` pin the versions the
//! legacy suite used. `candidate` resolves it from a root supplied at run
//! time (`AdapterEnv::candidate_roots`); provenance then records the
//! candidate's versions, integrity and tree digest.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::time::Duration;

use credential_eval_contracts::config::{AdapterIdentity, NetworkPolicy, ScannerSpec};
use credential_eval_contracts::ids::FixturePath;
use credential_eval_contracts::observation::{
    ObservationResult, ProvenanceComponent, ProvenanceKind, ScannerProvenance,
};
use serde_json::{Value, json};

use crate::families::{FAMILY_MAPPING_VERSION, LabelTable, finding_family};
use crate::locate::{Fixtures, MapError, Utf16Offsets};
use crate::process::{self, CancelToken, ProcessRequest};
use crate::provenance::{self, PackageProblem};
use crate::{
    Adapter, AdapterEnv, Invocation, NormalizedFinding, PrepareFailure, Prepared, ScannerBuild,
    adapter_identity, check_configuration, classify_probe, config_str, default_limits, fail,
    invalid_config, spec,
};

/// Shim exit code for "package not installed".
const EXIT_UNAVAILABLE: i32 = 3;
const PROBE_STDOUT: u64 = 64 * 1024;

/// One npm-package scanner.
#[derive(Debug, Clone)]
pub struct NodeAdapter {
    id: &'static str,
    version: &'static str,
    package: &'static str,
    mode: &'static str,
    table: LabelTable,
    /// Scanner options passed to the package (fixed by the adapter).
    options: Option<Value>,
    /// Extra fixed configuration entries recorded for identity.
    extra: &'static [(&'static str, &'static str)],
}

impl NodeAdapter {
    /// `@redact-secret/core`, default detectors (legacy `adapterVersion: 3`).
    pub fn redact_secret() -> Self {
        Self {
            id: "redact-secret",
            version: "3",
            package: "@redact-secret/core",
            mode: "Published npm package · default detectors",
            table: LabelTable::RedactSecret,
            options: None,
            extra: &[("detectors", "default"), ("runtime", "node")],
        }
    }

    /// `flare-redact`, secrets only (legacy `adapterVersion: 1`).
    pub fn flare_redact() -> Self {
        Self {
            id: "flare-redact",
            version: "1",
            package: "flare-redact",
            mode: "Published npm package · secrets-only (pii, generic_assignment disabled) · JavaScript engine",
            table: LabelTable::FlareRedact,
            options: Some(
                json!({"disable": ["pii", "generic_assignment"], "includeValues": false}),
            ),
            extra: &[("engine", "javascript")],
        }
    }

    /// `@openredaction/core`, constructor defaults (legacy `adapterVersion: 1`).
    pub fn openredaction() -> Self {
        Self {
            id: "openredaction",
            version: "1",
            package: "@openredaction/core",
            mode: "Published npm package · default patterns (PII enabled) · pattern coverage only",
            table: LabelTable::OpenRedaction,
            options: Some(json!({})),
            extra: &[],
        }
    }

    fn fixed(&self) -> Vec<(&'static str, Value)> {
        let mut fixed = vec![
            ("package", json!(self.package)),
            ("family_mapping_version", json!(FAMILY_MAPPING_VERSION)),
        ];
        fixed.extend(self.extra.iter().map(|(k, v)| (*k, json!(v))));
        if let Some(options) = &self.options {
            fixed.push(("options", options.clone()));
        }
        fixed
    }
}

impl Adapter for NodeAdapter {
    fn identity(&self) -> AdapterIdentity {
        adapter_identity(self.id, self.version)
    }

    fn default_spec(&self) -> ScannerSpec {
        let mut configuration: serde_json::Map<String, Value> = self
            .fixed()
            .into_iter()
            .map(|(k, v)| (k.to_owned(), v))
            .collect();
        configuration.insert("node".into(), json!("node"));
        configuration.insert("package_source".into(), json!("published"));
        spec(
            self.id,
            self.identity(),
            self.mode,
            Value::Object(configuration),
            default_limits(16 * 1024 * 1024),
        )
    }

    fn build(&self, spec: &ScannerSpec) -> ScannerBuild {
        // Only the published packages pinned by the shim lockfile are
        // released builds; a candidate root (or anything else) is not.
        match spec
            .configuration
            .get("package_source")
            .and_then(Value::as_str)
        {
            Some("published") => ScannerBuild::Released,
            _ => ScannerBuild::Candidate,
        }
    }

    fn prepare(
        &self,
        spec: &ScannerSpec,
        env: &AdapterEnv,
        cancel: &CancelToken,
    ) -> Result<Prepared, Box<PrepareFailure>> {
        let mut provenance = ScannerProvenance {
            network: spec.network,
            network_controls: Vec::new(),
            components: Vec::new(),
        };
        if spec.network != NetworkPolicy::Disabled {
            return Err(fail(
                ObservationResult::Unsupported {
                    reason: "adapter runs scanners with network disabled only".into(),
                },
                provenance,
            ));
        }
        let mut allowed: Vec<&'static str> = self.fixed().iter().map(|(k, _)| *k).collect();
        allowed.extend(["node", "package_source"]);
        let settings = check_configuration(spec, &allowed, &self.fixed()).and_then(|()| {
            Ok((
                config_str(spec, "node")?,
                config_str(spec, "package_source")?,
            ))
        });
        let (node, source) = settings.map_err(|r| fail(r, provenance.clone()))?;
        let package_root: PathBuf = match source {
            "published" => env.node_dir.clone(),
            "candidate" => match env.candidate_roots.get(spec.id.as_str()) {
                Some(root) => root.clone(),
                None => {
                    return Err(fail(
                        ObservationResult::Unavailable {
                            reason: "candidate package root was not provided".into(),
                        },
                        provenance,
                    ));
                }
            },
            _ => return Err(fail(invalid_config("package_source"), provenance)),
        };
        let shim = env.node_dir.join("shim.mjs");
        let Some(program) = provenance::which(node, env.path.as_deref()) else {
            return Err(fail(
                ObservationResult::Unavailable {
                    reason: "node runtime not found".into(),
                },
                provenance,
            ));
        };
        let unavailable = |reason: &str| ObservationResult::Unavailable {
            reason: reason.to_owned(),
        };
        match provenance::file_component(ProvenanceKind::Shim, "shim.mjs", &shim) {
            Ok(component) => provenance.components.push(component),
            Err(_) => return Err(fail(unavailable("node shim not found"), provenance)),
        }
        match provenance::npm_package(&package_root, self.package) {
            Ok(components) => provenance.components.extend(components),
            Err(PackageProblem::NotInstalled) => {
                return Err(fail(
                    unavailable("scanner package is not installed"),
                    provenance,
                ));
            }
            Err(PackageProblem::LockMismatch) => {
                return Err(fail(
                    ObservationResult::Error {
                        reason: "installed scanner package does not match its lockfile".into(),
                    },
                    provenance,
                ));
            }
            Err(PackageProblem::Unreadable) => {
                return Err(fail(
                    ObservationResult::Error {
                        reason: "scanner package could not be digested".into(),
                    },
                    provenance,
                ));
            }
        }

        let mut processes = 0;
        let mut process_time = Duration::ZERO;
        let mut probe = |args: Vec<OsString>| {
            let run = process::run(
                &ProcessRequest {
                    program: program.clone(),
                    args,
                    cwd: env.cwd.clone(),
                    stdin: None,
                    timeout: Duration::from_millis(spec.limits.timeout_ms),
                    max_stdout: PROBE_STDOUT.min(spec.limits.max_stdout_bytes),
                    max_stderr: spec.limits.max_stderr_bytes,
                },
                cancel,
            );
            processes += 1;
            process_time += run.elapsed;
            let unavailable = matches!(
                run.outcome,
                process::ProcessOutcome::Exited {
                    code: Some(EXIT_UNAVAILABLE),
                    ..
                }
            );
            if unavailable {
                return Err(ObservationResult::Unavailable {
                    reason: "scanner package is not installed".into(),
                });
            }
            classify_probe(run, &spec.limits)
        };
        let runtime = probe(vec!["--version".into()])
            .map(|out| String::from_utf8_lossy(&out).trim().to_owned());
        let version = runtime.and_then(|runtime_version| {
            provenance.components.push(ProvenanceComponent {
                kind: ProvenanceKind::Runtime,
                name: provenance::program_name(node),
                version: Some(runtime_version),
                sha256: provenance::sha256_file(&program).ok(),
                integrity: None,
            });
            let out = probe(vec![
                shim.clone().into_os_string(),
                "version".into(),
                self.id.into(),
                package_root.clone().into_os_string(),
            ])?;
            serde_json::from_slice::<Value>(out.trim_ascii_end())
                .ok()
                .and_then(|v| v.get("version").and_then(Value::as_str).map(str::to_owned))
                .ok_or(ObservationResult::Malformed {
                    reason: "scanner version could not be read".into(),
                })
        });
        provenance.components.sort();
        match version {
            Ok(version) => Ok(Prepared {
                version: Some(version),
                provenance,
                program,
                prefix_args: vec![
                    shim.into_os_string(),
                    "scan".into(),
                    self.id.into(),
                    package_root.into_os_string(),
                ],
                settings: json!({"options": self.options}),
                processes,
                process_time,
            }),
            Err(result) => Err(Box::new(PrepareFailure {
                result,
                version: None,
                provenance,
                processes,
                process_time,
            })),
        }
    }

    fn scan_invocation(&self, prepared: &Prepared, root: &Path, paths: &[&str]) -> Invocation {
        let request = json!({
            "root": root.to_string_lossy(),
            "paths": paths,
            "options": prepared.settings.get("options").cloned().unwrap_or(Value::Null),
        });
        Invocation {
            program: prepared.program.clone(),
            args: prepared.prefix_args.clone(),
            stdin: Some(serde_json::to_vec(&request).expect("request serializes")),
        }
    }

    fn normalize(
        &self,
        _prepared: &Prepared,
        stdout: &[u8],
        fixtures: &Fixtures<'_>,
    ) -> Result<Vec<NormalizedFinding>, MapError> {
        normalize(self.table, stdout, fixtures)
    }

    fn exit_failure(&self, code: Option<i32>) -> ObservationResult {
        if code == Some(EXIT_UNAVAILABLE) {
            ObservationResult::Unavailable {
                reason: "scanner package is not installed".into(),
            }
        } else {
            ObservationResult::Error {
                reason: "scanner exited with a non-zero status; output suppressed".into(),
            }
        }
    }
}

/// Normalize shim output: one JSON object per line with UTF-16 `start`/`end`,
/// a native `label`, optional `type` and `action`, terminated by
/// `{"done": true, "findings": n}`. Missing or inconsistent termination,
/// unknown paths, non-integer offsets, offsets inside a surrogate pair and
/// empty or invalid ranges all fail closed.
pub fn normalize(
    table: LabelTable,
    stdout: &[u8],
    fixtures: &Fixtures<'_>,
) -> Result<Vec<NormalizedFinding>, MapError> {
    const INVALID: MapError = MapError("Invalid scanner output");
    let text = std::str::from_utf8(stdout).map_err(|_| INVALID)?;
    let mut offsets: BTreeMap<&str, Utf16Offsets> = BTreeMap::new();
    let mut findings = Vec::new();
    let mut done = None;
    for line in text.split('\n').filter(|l| !l.trim().is_empty()) {
        if done.is_some() {
            return Err(INVALID);
        }
        let row: Value = serde_json::from_str(line).map_err(|_| INVALID)?;
        if row.get("done") == Some(&Value::Bool(true)) {
            done = Some(row.get("findings").and_then(Value::as_u64).ok_or(INVALID)?);
            continue;
        }
        let path = row.get("path").and_then(Value::as_str).ok_or(INVALID)?;
        let (path, content) = fixtures.resolve(path)?;
        let table16 = offsets
            .entry(path)
            .or_insert_with(|| Utf16Offsets::new(content));
        let index = |key| row.get(key).and_then(Value::as_u64).ok_or(INVALID);
        let (start, end) = (index("start")?, index("end")?);
        let unmappable = MapError("Unmappable scanner offset");
        let start = table16.byte(start).ok_or(unmappable.clone())?;
        let end = table16.byte(end).ok_or(unmappable.clone())?;
        if start >= end {
            return Err(unmappable);
        }
        let label = row.get("label").and_then(Value::as_str);
        let kind = row.get("type").and_then(Value::as_str);
        let action = match row.get("action") {
            None => None,
            Some(Value::String(action)) => Some(action.clone()),
            Some(_) => return Err(INVALID),
        };
        findings.push(NormalizedFinding {
            path: FixturePath::new(path).map_err(|_| MapError("Unknown scanner path"))?,
            start: start as u64,
            end: end as u64,
            family: finding_family(table, label, kind),
            action,
        });
    }
    if done != Some(findings.len() as u64) {
        return Err(MapError("Incomplete scanner output"));
    }
    Ok(findings)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fx<'a>(files: &[(&'a str, &'a str)]) -> Fixtures<'a> {
        Fixtures::new("/r", files.iter().copied())
    }

    #[test]
    fn utf16_offsets_become_utf8_bytes() {
        // "密钥=" is 3 UTF-16 units but 7 bytes; 😀 is 2 units / 4 bytes.
        let content = "密钥=FAKE😀TOKEN\n";
        let fixtures = fx(&[("a.txt", content)]);
        let out = b"{\"path\":\"a.txt\",\"start\":3,\"end\":14,\"label\":\"github-token\",\"type\":\"github_token\",\"action\":\"redact\"}\n{\"done\":true,\"findings\":1}\n";
        let f = normalize(LabelTable::RedactSecret, out, &fixtures).unwrap();
        assert_eq!((f[0].start, f[0].end), (7, 20));
        assert_eq!(&content[7..20], "FAKE😀TOKEN");
        assert_eq!(f[0].family.as_deref(), Some("github-token"));
        assert_eq!(f[0].action.as_deref(), Some("redact"));
    }

    #[test]
    fn labels_map_through_the_adapter_table() {
        let fixtures = fx(&[("a", "AKIAFAKEEXAMPLE")]);
        let out = b"{\"path\":\"a\",\"start\":0,\"end\":4,\"label\":\"aws_secret_key\"}\n{\"done\":true,\"findings\":1}\n";
        let f = normalize(LabelTable::FlareRedact, out, &fixtures).unwrap();
        assert_eq!(f[0].family.as_deref(), Some("aws-access-key"));
        let f = normalize(LabelTable::OpenRedaction, out, &fixtures).unwrap();
        assert_eq!(f[0].family, None);
    }

    #[test]
    fn fails_closed() {
        let fixtures = fx(&[("a", "x😀y")]);
        let cases: [(&[u8], &str); 7] = [
            (b"", "Incomplete scanner output"),
            (b"{\"path\":\"a\",\"start\":0,\"end\":1,\"label\":\"l\"}\n", "Incomplete scanner output"),
            (b"{\"done\":true,\"findings\":2}\n", "Incomplete scanner output"),
            (b"{\"path\":\"a\",\"start\":2,\"end\":3,\"label\":\"l\"}\n{\"done\":true,\"findings\":1}\n", "Unmappable scanner offset"),
            (b"{\"path\":\"b\",\"start\":0,\"end\":1}\n{\"done\":true,\"findings\":1}\n", "Unknown scanner path"),
            (b"{\"path\":\"a\",\"start\":1.5,\"end\":3}\n{\"done\":true,\"findings\":1}\n", "Invalid scanner output"),
            (b"{\"path\":\"a\",\"start\":1,\"end\":1}\n{\"done\":true,\"findings\":1}\n", "Unmappable scanner offset"),
        ];
        for (out, expected) in cases {
            assert_eq!(
                normalize(LabelTable::FlareRedact, out, &fixtures)
                    .unwrap_err()
                    .0,
                expected
            );
        }
        // Offsets past the end clamp like String.prototype.slice.
        let out = b"{\"path\":\"a\",\"start\":0,\"end\":99}\n{\"done\":true,\"findings\":1}\n";
        let f = normalize(LabelTable::FlareRedact, out, &fixtures).unwrap();
        assert_eq!(f[0].end, 6);
    }
}
