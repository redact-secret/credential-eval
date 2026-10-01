# Official and exploratory runs

The official measurement is run by `redact-secret-benchmarks` CI, not in this
repository. This repository owns what makes that run reproducible and safe to
publish: verified evidence input, enforced scanner pins, and two classes
recorded in every artifact (contract revision v1.1, issue #14):

- the **run class** (`manifest.run_class`): how the run was invoked;
- the **publication class** (`manifest.publication`): who may consume the
  artifact. It is derived and cannot be chosen.

Neither class is a measurement. Both leave every outcome and aggregate
unchanged. They are part of the manifest, so they enter the semantic digest:
an official and an exploratory run of the same inputs have different digests.

## Run classes

```bash
# Official: every input verified, or nothing is written.
credential-eval run --run-class official \
  --corpus corpus-snapshot.json \
  --evidence-release snapshot-2026.10.01 \
  --evidence-manifest release-manifest.json \
  --evidence-manifest-digest sha256:<pinned manifest digest> \
  --config run-config.json --out artifact.json

# Exploratory (the default): local and development runs.
credential-eval run --corpus corpus-snapshot.json --scanner gitleaks \
  --out results/local/artifact.json
```

| | `official` | `exploratory` (default) |
|---|---|---|
| Evidence release | required and verified | optional; verified when given |
| Scanner pins | required on every scanner, enforced before any scan | ignored |
| Publication class | `public` when every scanner is a released build, else `internal` | always `internal` |
| Publishable | `public` artifacts only (below) | **never** |

Exploratory artifacts are marked `run_class: exploratory` and
`publication: internal`. They are for local work and must not be published,
attached to a release, or used as evidence outside the run that produced
them.

## Evidence input

A consumer pins an evidence **release**: a tag plus the SHA-256 of that
release's manifest file. It fetches the release assets itself, then hands the
snapshot and the manifest to the CLI, which verifies them before it runs:

1. the SHA-256 of the manifest file's bytes equals
   `--evidence-manifest-digest` (`sha256:<hex>` or bare hex);
2. the manifest's `tag` equals `--evidence-release`;
3. the manifest lists `credential-eval/corpus-snapshot.json` exactly once, and
   that entry's `sha256` equals the SHA-256 of the `--corpus` file's bytes.

The snapshot is also validated as usual: schema, case rules, and the
declared corpus digest against the recomputed one. On success the release identity is
recorded as `manifest.evidence.release {tag, manifest_digest}` next to the
snapshot's `source`, `revision`, `evidence_schema` and `corpus_digest`.

Any failure is refused with exit code 4 and no artifact. This holds for any
run class: an exploratory run that is given release flags verifies them too.
A snapshot whose own `identity.release` is set is rejected (exit 1). Only the
evaluator writes that field, after verification.

The verifier reads only `tag` and `files[] {path, sha256}` from the manifest
and ignores everything else. The release format belongs to
`credential-evidence` (redact-secret/credential-evidence#17) and is not
defined there yet. If #17 settles on different field names, the verifier
follows it. That is a CLI change, not a contract change.

## Scanner pins

Pins are fixed in the run configuration, never on the command line. Each
`scanners[]` entry may carry an optional `pin` (run-config revision v1.1):

```json
"pin": {
  "version": "3.97.4",
  "sha256": "sha256:8c7af13e84f217bffd10aec09780fb7bbe59892187c99006291cef9c6f001beb"
}
```

- `version` must equal the version the adapter resolved
  (`manifest.scanners[].version`).
- `sha256` (optional) must equal the digest of the scanner's executable (the
  provenance component of kind `executable`). It applies to executable
  scanners. npm-package scanners are bound by their version, the shim
  lockfile and the package integrity recorded in provenance.

An official run refuses a configuration with an unpinned scanner (exit 2).
After preparing every scanner, and before any scan, it checks each one
against its pin. A different version (for example, a TruffleHog that
updated itself from 3.97.4 to 3.97.6), a different executable digest, or a
version that could not be resolved (an uninstalled scanner) is refused with
exit code 4 and no artifact. The check never warns and continues.

The adapter-level `required_version` key of the Gitleaks and TruffleHog
configurations is separate. In any run class it marks a mismatched scanner
`unavailable` (not measured). The `pin` is the run-level guarantee that an
official artifact never contains another version.

## Publication class

```text
publication = public    if run_class = official
                        and every manifest.scanners[].build = released
            = internal  otherwise
```

Each scanner's `build` (`released` | `candidate`) is reported by its adapter
from the configuration. A Redact Secret scanner whose `package_source` is
`candidate` (packages from `--candidate-root`) is a `candidate` build.
Anything an adapter cannot classify is reported as `candidate`, so it fails
safe. A missing `build` never counts as `released`.

**Only `public` artifacts may be consumed outside product qualification**:
for example, by an optional scanner-observation view on
`credential-evidence-site`, or by anyone outside the Redact Secret release
process. `internal` artifacts, which are every exploratory run and every run
with a candidate build, are for Redact Secret product qualification only.
An artifact written before v1.1 has neither field, and readers must treat it
as `exploratory` and `internal`.

## Local runs

Local runs are temporary. Write them under `results/local/`, which is
gitignored. They are never committed or published. A local run is
exploratory unless every official input is supplied and verifies, and even
then it is not the official measurement. That measurement is the one
`redact-secret-benchmarks` CI produces from its pinned release, pinned
configuration and pinned engine version.

## Exit codes added

| Code | Meaning |
|---|---|
| 2 | Also: `--run-class official` without the evidence release flags, a partial set of those flags, or an unpinned scanner |
| 4 | Refused: the evidence snapshot did not verify against the pinned release, or (official run) a scanner did not match its pin. No artifact is written. |
