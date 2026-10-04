//! Setup provenance: executable resolution and digests, npm package identity.
//!
//! Provenance names bytes by digest and versions, never by host path, so it
//! is reproducible across machines. Resolved paths are available to the
//! caller (e.g. for stderr diagnostics) but are not recorded in artifacts.

use std::collections::BTreeSet;
use std::ffi::OsStr;
use std::fs::{self, File};
use std::io::Read;
use std::path::{Path, PathBuf};

use credential_eval_contracts::canonical::sha256_bytes;
use credential_eval_contracts::ids::Sha256Digest;
use credential_eval_contracts::observation::{ProvenanceComponent, ProvenanceKind};
use serde_json::Value;
use sha2::{Digest, Sha256};

/// Upper bounds for package tree digests.
const TREE_MAX_FILES: usize = 20_000;
const TREE_MAX_BYTES: u64 = 512 * 1024 * 1024;

/// Resolve a configured program: a name without `/` is searched on `path`
/// (the first executable regular file wins); anything else is a path.
pub fn which(program: &str, path: Option<&OsStr>) -> Option<PathBuf> {
    if program.contains('/') {
        let candidate = PathBuf::from(program);
        return is_executable(&candidate).then_some(candidate);
    }
    std::env::split_paths(path?)
        .filter(|dir| dir.is_absolute())
        .map(|dir| dir.join(program))
        .find(|candidate| is_executable(candidate))
}

fn is_executable(path: &Path) -> bool {
    let Ok(meta) = fs::metadata(path) else {
        return false;
    };
    if !meta.is_file() {
        return false;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        meta.permissions().mode() & 0o111 != 0
    }
    #[cfg(not(unix))]
    {
        true
    }
}

fn hex_digest(hasher: Sha256) -> Sha256Digest {
    let digest = hasher.finalize();
    let mut hex = String::with_capacity(71);
    hex.push_str("sha256:");
    for byte in digest {
        hex.push_str(&format!("{byte:02x}"));
    }
    Sha256Digest::new(hex).expect("well-formed digest")
}

/// Streaming SHA-256 of a file.
pub fn sha256_file(path: &Path) -> std::io::Result<Sha256Digest> {
    let mut file = File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; 256 * 1024];
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(hex_digest(hasher))
}

/// Deterministic digest of a directory tree: for every regular file in
/// byte-order of its relative path, `path NUL length NUL bytes`; symlinks
/// contribute `path NUL "->" target`. Bounded by file count and total bytes.
pub fn tree_digest(root: &Path) -> std::io::Result<Sha256Digest> {
    let mut entries = Vec::new();
    collect(root, root, &mut entries)?;
    entries.sort();
    let mut hasher = Sha256::new();
    let mut total = 0u64;
    for rel in entries {
        let path = root.join(&rel);
        let meta = fs::symlink_metadata(&path)?;
        hasher.update(rel.as_bytes());
        hasher.update([0]);
        if meta.file_type().is_symlink() {
            hasher.update(b"->");
            hasher.update(fs::read_link(&path)?.to_string_lossy().as_bytes());
        } else {
            total += meta.len();
            if total > TREE_MAX_BYTES {
                return Err(std::io::Error::other("package tree too large"));
            }
            hasher.update(meta.len().to_string().as_bytes());
            hasher.update([0]);
            hasher.update(fs::read(&path)?);
        }
        hasher.update([0]);
    }
    Ok(hex_digest(hasher))
}

fn collect(root: &Path, dir: &Path, out: &mut Vec<String>) -> std::io::Result<()> {
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let kind = entry.file_type()?;
        let path = entry.path();
        if kind.is_dir() {
            collect(root, &path, out)?;
        } else {
            let rel = path
                .strip_prefix(root)
                .map_err(std::io::Error::other)?
                .components()
                .map(|c| c.as_os_str().to_string_lossy().into_owned())
                .collect::<Vec<_>>()
                .join("/");
            out.push(rel);
            if out.len() > TREE_MAX_FILES {
                return Err(std::io::Error::other("package tree has too many files"));
            }
        }
    }
    Ok(())
}

/// The file name of a configured program (`/opt/bin/gitleaks` → `gitleaks`),
/// so provenance never records host paths; the digest pins the bytes.
pub fn program_name(program: &str) -> String {
    Path::new(program).file_name().map_or_else(
        || program.to_owned(),
        |name| name.to_string_lossy().into_owned(),
    )
}

/// Component for a resolved executable.
pub fn executable(
    name: &str,
    version: Option<String>,
    path: &Path,
) -> std::io::Result<ProvenanceComponent> {
    Ok(ProvenanceComponent {
        kind: ProvenanceKind::Executable,
        name: name.to_owned(),
        version,
        sha256: Some(sha256_file(path)?),
        integrity: None,
    })
}

/// A package-identity problem, reported as a fixed reason.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PackageProblem {
    /// The package is not installed under the root.
    NotInstalled,
    /// The installed package does not match the lockfile.
    LockMismatch,
    /// The package tree could not be read or digested.
    Unreadable,
}

/// Identity of an installed npm package and the packages it depends on:
/// a lockfile component (when `package-lock.json` exists), one component per
/// installed package in the dependency closure (version and integrity from
/// the lockfile, checked against the installed `package.json`), and a tree
/// digest of the main package's installed bytes.
pub fn npm_package(root: &Path, name: &str) -> Result<Vec<ProvenanceComponent>, PackageProblem> {
    let dir = package_dir(root, name);
    let installed = read_json(&dir.join("package.json")).ok_or(PackageProblem::NotInstalled)?;
    let installed_version = installed
        .get("version")
        .and_then(Value::as_str)
        .map(str::to_owned);
    let mut components = Vec::new();
    let lock_path = root.join("package-lock.json");
    let tree = tree_digest(&dir).map_err(|_| PackageProblem::Unreadable)?;
    if let Some(lock) = read_json(&lock_path) {
        components.push(ProvenanceComponent {
            kind: ProvenanceKind::Lockfile,
            name: "package-lock.json".into(),
            version: lock.get("lockfileVersion").map(Value::to_string),
            sha256: Some(sha256_file(&lock_path).map_err(|_| PackageProblem::Unreadable)?),
            integrity: None,
        });
        let packages = lock.get("packages").and_then(Value::as_object);
        let mut seen = BTreeSet::new();
        let mut queue = vec![name.to_owned()];
        while let Some(current) = queue.pop() {
            if !seen.insert(current.clone()) {
                continue;
            }
            let key = format!("node_modules/{current}");
            let Some(entry) = packages.and_then(|p| p.get(&key)) else {
                if current == name {
                    return Err(PackageProblem::LockMismatch);
                }
                continue;
            };
            let current_dir = package_dir(root, &current);
            let Some(on_disk) = read_json(&current_dir.join("package.json")) else {
                // Optional platform packages for other hosts are not installed.
                continue;
            };
            let lock_version = entry.get("version").and_then(Value::as_str);
            if lock_version != on_disk.get("version").and_then(Value::as_str) {
                return Err(PackageProblem::LockMismatch);
            }
            components.push(ProvenanceComponent {
                kind: ProvenanceKind::NpmPackage,
                name: current.clone(),
                version: lock_version.map(str::to_owned),
                sha256: (current == name).then(|| tree.clone()),
                integrity: entry
                    .get("integrity")
                    .and_then(Value::as_str)
                    .map(str::to_owned),
            });
            for field in ["dependencies", "optionalDependencies"] {
                if let Some(deps) = entry.get(field).and_then(Value::as_object) {
                    queue.extend(deps.keys().cloned());
                }
            }
        }
    } else {
        components.push(ProvenanceComponent {
            kind: ProvenanceKind::NpmPackage,
            name: name.to_owned(),
            version: installed_version,
            sha256: Some(tree),
            integrity: None,
        });
    }
    components.sort();
    Ok(components)
}

/// What one npm lockfile entry records about a package.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct NpmRecord {
    /// Locked version.
    pub version: Option<String>,
    /// Resolved tarball URL.
    pub resolved: Option<String>,
    /// Registry Subresource Integrity string.
    pub integrity: Option<String>,
}

/// The lockfile record of `name` under `root`, and the record npm wrote about
/// the package it installed (`node_modules/.package-lock.json`, the hidden
/// lockfile). Either is `None` when absent. The second is what makes the
/// check an install check: npm fetched the tarball, verified its bytes against
/// the lockfile integrity, and recorded what it extracted.
pub fn npm_records(root: &Path, name: &str) -> (Option<NpmRecord>, Option<NpmRecord>) {
    let key = format!("node_modules/{name}");
    let record = |path: PathBuf| {
        let entry = read_json(&path)?.get("packages")?.get(&key)?.clone();
        let text = |field: &str| entry.get(field).and_then(Value::as_str).map(str::to_owned);
        Some(NpmRecord {
            version: text("version"),
            resolved: text("resolved"),
            integrity: text("integrity"),
        })
    };
    (
        record(root.join("package-lock.json")),
        record(root.join("node_modules").join(".package-lock.json")),
    )
}

fn package_dir(root: &Path, name: &str) -> PathBuf {
    let mut dir = root.join("node_modules");
    for part in name.split('/') {
        dir.push(part);
    }
    dir
}

fn read_json(path: &Path) -> Option<Value> {
    let bytes = fs::read(path).ok()?;
    serde_json::from_slice(&bytes).ok()
}

/// Digest of a small file's bytes (e.g. a shim script).
pub fn file_component(
    kind: ProvenanceKind,
    name: &str,
    path: &Path,
) -> std::io::Result<ProvenanceComponent> {
    let bytes = fs::read(path)?;
    Ok(ProvenanceComponent {
        kind,
        name: name.to_owned(),
        version: None,
        sha256: Some(sha256_bytes(&bytes)),
        integrity: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn which_rejects_relative_path_entries_and_missing_programs() {
        assert!(
            which(
                "definitely-not-a-scanner-xyz",
                Some(OsStr::new("/usr/bin:/bin"))
            )
            .is_none()
        );
        assert!(which("sh", Some(OsStr::new("relative/dir"))).is_none());
        assert!(which("sh", None).is_none());
        #[cfg(unix)]
        assert!(which("sh", Some(OsStr::new("/usr/bin:/bin"))).is_some());
    }
}
