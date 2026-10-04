//! Official-run inputs: evidence-release verification, scanner pins, and the
//! run and publication classes recorded in the manifest
//! (`docs/official-runs.md`).
//!
//! Nothing here measures. These checks decide whether a run may proceed and
//! how its artifact may be consumed; they never change an outcome.

use credential_eval_adapters::provenance::npm_records;
use credential_eval_contracts::artifact::{Publication, RunArtifact, RunClass};
use credential_eval_contracts::canonical::sha256_bytes;
use credential_eval_contracts::config::{RunConfig, ScannerSpec};
use credential_eval_contracts::corpus::EvidenceRelease;
use credential_eval_contracts::ids::{ReleaseTag, Sha256Digest};
use credential_eval_contracts::observation::{
    ProvenanceKind, ScannerBuild, ScannerIdentity, ScannerProvenance,
};
use serde_json::Value;
use std::path::Path;

/// Path of the corpus snapshot inside an evidence release.
pub const SNAPSHOT_ENTRY: &str = "credential-eval/corpus-snapshot.json";

/// Largest release manifest read.
pub const MAX_RELEASE_MANIFEST_BYTES: u64 = 1024 * 1024;

/// Parse a run class name.
pub fn parse_run_class(name: &str) -> Option<RunClass> {
    match name {
        "official" => Some(RunClass::Official),
        "exploratory" => Some(RunClass::Exploratory),
        _ => None,
    }
}

/// Accept `sha256:<hex>` or bare 64-character lowercase hex.
fn parse_digest(text: &str) -> Option<Sha256Digest> {
    let full = if text.starts_with("sha256:") {
        text.to_owned()
    } else {
        format!("sha256:{text}")
    };
    Sha256Digest::new(full).ok()
}

/// Verify that `snapshot_bytes` are the corpus snapshot of the evidence
/// release `tag`, as described by the release manifest `manifest_bytes`
/// whose digest the caller pinned (`expected_manifest_digest`).
///
/// The manifest is a JSON object with a `tag` string and a `files` array of
/// `{path, sha256}` entries. Exactly one entry must have the path
/// [`SNAPSHOT_ENTRY`], and its digest must equal the snapshot file's. Other
/// fields are ignored. Every failure names only tags, paths and digests.
pub fn verify_release(
    tag: &str,
    expected_manifest_digest: &str,
    manifest_bytes: &[u8],
    snapshot_bytes: &[u8],
) -> Result<EvidenceRelease, String> {
    let tag = ReleaseTag::new(tag).map_err(|e| format!("--evidence-release: {e}"))?;
    let expected = parse_digest(expected_manifest_digest)
        .ok_or("--evidence-manifest-digest must be a SHA-256 digest")?;
    let actual = sha256_bytes(manifest_bytes);
    if actual != expected {
        return Err(format!(
            "release manifest digest {actual} does not match the pinned {expected}"
        ));
    }
    let manifest: Value = serde_json::from_slice(manifest_bytes)
        .map_err(|_| "release manifest is not valid JSON".to_owned())?;
    match manifest.get("tag").and_then(Value::as_str) {
        Some(found) if found == tag.as_str() => {}
        Some(found) => {
            return Err(format!(
                "release manifest is for tag {found:?}, not the pinned {:?}",
                tag.as_str()
            ));
        }
        None => return Err("release manifest has no tag".into()),
    }
    let files = manifest
        .get("files")
        .and_then(Value::as_array)
        .ok_or("release manifest has no files list")?;
    let mut entries = files
        .iter()
        .filter(|f| f.get("path").and_then(Value::as_str) == Some(SNAPSHOT_ENTRY));
    let (Some(entry), None) = (entries.next(), entries.next()) else {
        return Err(format!(
            "release manifest must list {SNAPSHOT_ENTRY} exactly once"
        ));
    };
    let listed = entry
        .get("sha256")
        .and_then(Value::as_str)
        .and_then(parse_digest)
        .ok_or_else(|| format!("release manifest entry {SNAPSHOT_ENTRY} has no valid sha256"))?;
    let snapshot = sha256_bytes(snapshot_bytes);
    if snapshot != listed {
        return Err(format!(
            "corpus snapshot digest {snapshot} does not match {listed} in release {}",
            tag.as_str()
        ));
    }
    Ok(EvidenceRelease {
        tag,
        manifest_digest: actual,
    })
}

/// Configuration errors that make an official run impossible before
/// anything runs: every scanner needs a pin.
pub fn check_official_config(config: &RunConfig) -> Result<(), String> {
    let unpinned: Vec<&str> = config
        .scanners
        .iter()
        .filter(|s| s.pin.is_none())
        .map(|s| s.id.as_str())
        .collect();
    if unpinned.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "an official run needs a pin on every scanner; unpinned: {}",
            unpinned.join(", ")
        ))
    }
}

/// Check one prepared scanner against its pin. `version` and `provenance`
/// are what the adapter resolved (also when preparation failed).
pub fn check_pin(
    spec: &ScannerSpec,
    version: Option<&str>,
    provenance: &ScannerProvenance,
) -> Result<(), String> {
    let id = spec.id.as_str();
    let pin = spec
        .pin
        .as_ref()
        .ok_or_else(|| format!("scanner {id} has no pin"))?;
    match version {
        Some(found) if found == pin.version => {}
        Some(found) => {
            return Err(format!(
                "scanner {id}: resolved version {found} does not match pin {}",
                pin.version
            ));
        }
        None => {
            return Err(format!(
                "scanner {id}: version could not be resolved (pin {})",
                pin.version
            ));
        }
    }
    if let Some(expected) = &pin.sha256 {
        let executables: Vec<Option<&Sha256Digest>> = provenance
            .components
            .iter()
            .filter(|c| c.kind == ProvenanceKind::Executable)
            .map(|c| c.sha256.as_ref())
            .collect();
        match executables.as_slice() {
            [Some(found)] if *found == expected => {}
            [Some(found)] => {
                return Err(format!(
                    "scanner {id}: executable digest {found} does not match pin {expected}"
                ));
            }
            _ => {
                return Err(format!(
                    "scanner {id}: a sha256 pin needs exactly one digested executable"
                ));
            }
        }
    }
    Ok(())
}

/// Check an npm scanner's registry pin (revision v1.4): the exact version, the
/// registry `sha512` integrity and the resolved tarball. `node_dir` is the
/// directory the published package is installed under (`--node-dir`).
///
/// Three records must agree with the pin: the lockfile entry, the entry npm
/// wrote when it installed the package (so a `node_modules` that was not
/// installed from this lockfile is refused), and the `npm-package` provenance
/// component the artifact carries. A pin without `integrity` and `resolved`
/// (an executable scanner) is not checked here. Failures name only versions,
/// integrity strings and URLs.
pub fn check_package_pin(
    spec: &ScannerSpec,
    node_dir: &Path,
    provenance: &ScannerProvenance,
) -> Result<(), String> {
    let id = spec.id.as_str();
    let Some(pin) = spec.pin.as_ref() else {
        return Ok(());
    };
    if pin.integrity.is_none() && pin.resolved.is_none() {
        return Ok(());
    }
    let package = spec
        .configuration
        .get("package")
        .and_then(Value::as_str)
        .ok_or_else(|| format!("scanner {id}: an npm pin needs a package scanner"))?;
    if spec
        .configuration
        .get("package_source")
        .and_then(Value::as_str)
        != Some("published")
    {
        return Err(format!(
            "scanner {id}: an npm pin applies to package_source published only"
        ));
    }
    let (locked, installed) = npm_records(node_dir, package);
    let locked = locked.ok_or_else(|| format!("scanner {id}: {package} is not in the lockfile"))?;
    let installed = installed.ok_or_else(|| {
        format!("scanner {id}: {package} has no install record (node_modules/.package-lock.json); install with npm ci")
    })?;
    let recorded = provenance
        .components
        .iter()
        .find(|c| c.kind == ProvenanceKind::NpmPackage && c.name == package)
        .ok_or_else(|| format!("scanner {id}: {package} is not in the run provenance"))?;
    let records = [
        (
            "lockfile",
            &locked.version,
            &locked.integrity,
            &locked.resolved,
        ),
        (
            "install record",
            &installed.version,
            &installed.integrity,
            &installed.resolved,
        ),
    ];
    for (source, version, integrity, resolved) in records {
        if version.as_deref() != Some(pin.version.as_str()) {
            return Err(format!(
                "scanner {id}: {source} version {} does not match pin {}",
                version.as_deref().unwrap_or("(none)"),
                pin.version
            ));
        }
        if let Some(expected) = &pin.integrity {
            if integrity.as_ref() != Some(expected) {
                return Err(format!(
                    "scanner {id}: {source} integrity {} does not match pin {expected}",
                    integrity.as_deref().unwrap_or("(none)")
                ));
            }
        }
        if let Some(expected) = &pin.resolved {
            if resolved.as_ref() != Some(expected) {
                return Err(format!(
                    "scanner {id}: {source} resolved {} does not match pin {expected}",
                    resolved.as_deref().unwrap_or("(none)")
                ));
            }
        }
    }
    if let Some(expected) = &pin.integrity {
        if recorded.integrity.as_ref() != Some(expected)
            || recorded.version.as_deref() != Some(pin.version.as_str())
        {
            return Err(format!(
                "scanner {id}: provenance integrity {} does not match pin {expected}",
                recorded.integrity.as_deref().unwrap_or("(none)")
            ));
        }
    }
    Ok(())
}

/// The publication class: `public` only for an official run in which every
/// scanner reports a released build.
pub fn publication(run_class: RunClass, scanners: &[ScannerIdentity]) -> Publication {
    let released = scanners
        .iter()
        .all(|s| s.build == Some(ScannerBuild::Released));
    if run_class == RunClass::Official && released && !scanners.is_empty() {
        Publication::Public
    } else {
        Publication::Internal
    }
}

/// Record the run class and the derived publication class on `artifact`.
pub fn stamp(artifact: &mut RunArtifact, run_class: RunClass) {
    artifact.manifest.run_class = Some(run_class);
    artifact.manifest.publication = Some(publication(run_class, &artifact.manifest.scanners));
}

#[cfg(test)]
mod tests {
    use super::*;
    use credential_eval_contracts::config::{NetworkPolicy, ScannerPin};
    use credential_eval_contracts::observation::ProvenanceComponent;

    const SNAPSHOT: &[u8] = b"{\"schema\":\"credential-eval/corpus-snapshot/v1\"}";

    fn manifest(tag: &str, snapshot_digest: &str) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({
            "tag": tag,
            "source_revision": "0123abc",
            "files": [
                { "path": "records/bundle.json", "sha256": "0".repeat(64) },
                { "path": SNAPSHOT_ENTRY, "sha256": snapshot_digest },
            ]
        }))
        .unwrap()
    }

    fn snapshot_digest() -> String {
        sha256_bytes(SNAPSHOT).to_string()
    }

    #[test]
    fn verified_release_records_tag_and_manifest_digest() {
        // Bare hex is accepted for both the pin and the manifest entry.
        let bare = snapshot_digest().trim_start_matches("sha256:").to_owned();
        let bytes = manifest("snapshot-2026.10.01", &bare);
        let pinned = sha256_bytes(&bytes);
        let release = verify_release(
            "snapshot-2026.10.01",
            pinned.as_str().trim_start_matches("sha256:"),
            &bytes,
            SNAPSHOT,
        )
        .unwrap();
        assert_eq!(release.tag.as_str(), "snapshot-2026.10.01");
        assert_eq!(release.manifest_digest, pinned);
    }

    #[test]
    fn release_verification_refuses_every_mismatch() {
        let good = manifest("snapshot-1", &snapshot_digest());
        let pinned = sha256_bytes(&good).to_string();
        let refuse = |tag: &str, digest: &str, bytes: &[u8], snapshot: &[u8], needle: &str| {
            let error = verify_release(tag, digest, bytes, snapshot).unwrap_err();
            assert!(error.contains(needle), "{error}");
        };
        // The manifest is not the pinned one.
        let other = manifest("snapshot-2", &snapshot_digest());
        refuse(
            "snapshot-1",
            &pinned,
            &other,
            SNAPSHOT,
            "does not match the pinned",
        );
        // The pinned manifest names another tag.
        let pinned_other = sha256_bytes(&other).to_string();
        refuse("snapshot-1", &pinned_other, &other, SNAPSHOT, "is for tag");
        // The snapshot bytes differ from the manifest entry.
        refuse("snapshot-1", &pinned, &good, b"{}", "does not match");
        // No snapshot entry, or two of them.
        let none =
            serde_json::to_vec(&serde_json::json!({"tag": "snapshot-1", "files": []})).unwrap();
        refuse(
            "snapshot-1",
            sha256_bytes(&none).as_ref(),
            &none,
            SNAPSHOT,
            "exactly once",
        );
        let entry = serde_json::json!({ "path": SNAPSHOT_ENTRY, "sha256": snapshot_digest() });
        let twice = serde_json::to_vec(
            &serde_json::json!({"tag": "snapshot-1", "files": [entry.clone(), entry]}),
        )
        .unwrap();
        refuse(
            "snapshot-1",
            sha256_bytes(&twice).as_ref(),
            &twice,
            SNAPSHOT,
            "exactly once",
        );
        // Malformed inputs.
        refuse("bad tag", &pinned, &good, SNAPSHOT, "--evidence-release");
        refuse(
            "snapshot-1",
            "md5:00",
            &good,
            SNAPSHOT,
            "--evidence-manifest-digest",
        );
        let garbage = b"not json".to_vec();
        refuse(
            "snapshot-1",
            sha256_bytes(&garbage).as_ref(),
            &garbage,
            SNAPSHOT,
            "not valid JSON",
        );
    }

    fn spec(pin: Option<ScannerPin>) -> ScannerSpec {
        let adapter = credential_eval_adapters::find("gitleaks").unwrap();
        let mut spec = adapter.default_spec();
        spec.network = NetworkPolicy::Disabled;
        spec.pin = pin;
        spec
    }

    fn provenance(sha: Option<Sha256Digest>) -> ScannerProvenance {
        ScannerProvenance {
            network: NetworkPolicy::Disabled,
            network_controls: Vec::new(),
            components: vec![ProvenanceComponent {
                kind: ProvenanceKind::Executable,
                name: "gitleaks".into(),
                version: Some("8.30.1".into()),
                sha256: sha,
                integrity: None,
            }],
        }
    }

    #[test]
    fn pins_bind_version_and_executable_digest() {
        let digest = sha256_bytes(b"binary");
        let pinned = |sha256| {
            spec(Some(ScannerPin {
                version: "8.30.1".into(),
                sha256,
                integrity: None,
                resolved: None,
            }))
        };
        let with_sha = pinned(Some(digest.clone()));
        assert!(check_pin(&with_sha, Some("8.30.1"), &provenance(Some(digest.clone()))).is_ok());
        assert!(check_pin(&pinned(None), Some("8.30.1"), &provenance(None)).is_ok());

        let error = check_pin(&with_sha, Some("8.30.2"), &provenance(Some(digest.clone())));
        assert!(error.unwrap_err().contains("does not match pin 8.30.1"));
        let error = check_pin(&with_sha, None, &provenance(Some(digest.clone())));
        assert!(error.unwrap_err().contains("could not be resolved"));
        let other = sha256_bytes(b"other");
        let error = check_pin(&with_sha, Some("8.30.1"), &provenance(Some(other)));
        assert!(error.unwrap_err().contains("executable digest"));
        let mut none = provenance(None);
        none.components.clear();
        let error = check_pin(&with_sha, Some("8.30.1"), &none);
        assert!(
            error
                .unwrap_err()
                .contains("exactly one digested executable")
        );
        assert!(check_pin(&spec(None), Some("8.30.1"), &none).is_err());
    }

    #[test]
    fn official_runs_need_a_pin_on_every_scanner() {
        let mut config = crate::default_config(&["gitleaks".into()], 1).unwrap();
        assert!(
            check_official_config(&config)
                .unwrap_err()
                .contains("gitleaks")
        );
        config.scanners[0].pin = Some(ScannerPin {
            version: "8.30.1".into(),
            sha256: None,
            integrity: None,
            resolved: None,
        });
        assert!(check_official_config(&config).is_ok());
    }

    fn identity(build: Option<ScannerBuild>) -> ScannerIdentity {
        ScannerIdentity {
            id: credential_eval_contracts::ids::ScannerId::new("s").unwrap(),
            version: Some("1".into()),
            mode: "m".into(),
            adapter: spec(None).adapter,
            configuration_hash: sha256_bytes(b"c"),
            provenance: None,
            build,
        }
    }

    #[test]
    fn only_official_runs_of_released_builds_are_public() {
        let released = identity(Some(ScannerBuild::Released));
        let candidate = identity(Some(ScannerBuild::Candidate));
        let unknown = identity(None);
        let official = RunClass::Official;
        assert_eq!(
            publication(official, &[released.clone(), released.clone()]),
            Publication::Public
        );
        assert_eq!(
            publication(official, &[released.clone(), candidate]),
            Publication::Internal
        );
        assert_eq!(
            publication(official, &[released.clone(), unknown]),
            Publication::Internal
        );
        assert_eq!(publication(official, &[]), Publication::Internal);
        assert_eq!(
            publication(RunClass::Exploratory, &[released]),
            Publication::Internal
        );
    }
}
