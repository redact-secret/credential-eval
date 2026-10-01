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
and ignores everything else. It does not check who published the release, so
a product-owned corpus is pinned the same way when its owner publishes a
manifest in this shape
([multi-corpus-qualification.md](multi-corpus-qualification.md) §2). The release format belongs to
`credential-evidence`: its ADR 0011 and `docs/releases.md` define it
(`release-manifest.json`, format `credential-evidence/release-manifest` v1).
The corpus snapshot is published as the release asset
`credential-eval-corpus-snapshot.json` and listed in the manifest under the
path `credential-eval/corpus-snapshot.json`; the manifest digest ships as
`release-manifest.json.sha256`. The first release is `snapshot-2026.10.01`.
For example:

```bash
gh release download snapshot-2026.10.01 -R redact-secret/credential-evidence
credential-eval run --run-class official \
  --corpus credential-eval-corpus-snapshot.json \
  --evidence-release snapshot-2026.10.01 \
  --evidence-manifest release-manifest.json \
  --evidence-manifest-digest "$(cut -c1-64 release-manifest.json.sha256)" \
  --config <run-config.json> --out results/local/artifact.json
```

If the release format changes field names, the verifier follows it. That is a
CLI change, not a contract change.

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

## Official configuration

The public credential population is measured with a committed
configuration:

| File | Platform |
|---|---|
| [`configs/official/credential-public-v1.json`](../configs/official/credential-public-v1.json) | linux-x64, the `redact-secret-benchmarks` CI platform (canonical) |
| [`configs/official/credential-public-v1.darwin-arm64.json`](../configs/official/credential-public-v1.darwin-arm64.json) | darwin-arm64, for local reproduction |

Both are `tools/parity/run-config.json` (the configuration parity was proven
with: same adapters, scanner configurations, bounds and accounting) plus a
`pin` on every scanner, with `execution.jobs` 4 and no `methods`. Every
scanner has `network: disabled`.

| Scanner | `pin.version` | `pin.sha256` linux-x64 | `pin.sha256` darwin-arm64 |
|---|---|---|---|
| `gitleaks` | 8.30.1 | `sha256:88f91962aa2f93ac6ab281d553b9e125f5197bbbce38f9f2437f7299c32e5509` | `sha256:ba52fb1bfabbcde42f032afad3d6e0b19dff8ed105229a16e7caa338bbc0e84f` |
| `trufflehog` | 3.97.4 | `sha256:95c2a42bce979fce6dd73cc629b37ae4d72731b0dc16e047fba41a77bc765620` | `sha256:8c7af13e84f217bffd10aec09780fb7bbe59892187c99006291cef9c6f001beb` |
| `redact-secret` | 0.1.0-beta.12 | n/a (npm) | n/a (npm) |
| `flare-redact` | 1.6.1 | n/a (npm) | n/a (npm) |
| `openredaction` | 1.1.5 | n/a (npm) | n/a (npm) |

A `pin.sha256` is the SHA-256 of the extracted executable, not of the
release archive. Its source is the upstream release archive, checked against
the upstream checksum file before extraction:

| Archive | Archive SHA-256 | Checksum file |
|---|---|---|
| `gitleaks_8.30.1_linux_x64.tar.gz` | `551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb` | <https://github.com/gitleaks/gitleaks/releases/download/v8.30.1/gitleaks_8.30.1_checksums.txt> |
| `trufflehog_3.97.4_linux_amd64.tar.gz` | `dc24007c2f233bd61c05beabeb44aa27ea9b43288166279209abe0458c5ce76b` | <https://github.com/trufflesecurity/trufflehog/releases/download/v3.97.4/trufflehog_3.97.4_checksums.txt> |
| `gitleaks_8.30.1_darwin_arm64.tar.gz` | `b40ab0ae55c505963e365f271a8d3846efbc170aa17f2607f13df610a9aeb6a5` | same file as linux |
| `trufflehog_3.97.4_darwin_arm64.tar.gz` | `57e2a41c1e196cf96cae49ca2151f5e9207be2f5c41349b5ea49cb5dcfc606b7` | same file as linux |

The darwin archive digests also equal the legacy `scanners/peer-checksums.json`
that parity used. The npm scanners are pinned by version here. Their
`sha512` integrity is pinned by `adapters/node/package-lock.json`
(`@redact-secret/core` `sha512-fDVwt2U7VFSK…`, `flare-redact`
`sha512-13Htu6VPk2tt…`, `@openredaction/core` `sha512-SpQTBhVV4p3r…`), and
the run records the integrity and an installed-tree digest in provenance.
The lockfile also pins the platform packages of `@redact-secret/core`
(`node-linux-x64-gnu`, `node-darwin-arm64`, ...). npm installs the one for
the host.

A pin holds one digest, and the pin is part of the configuration, so it
enters `config_hash` and the semantic digest. That is why each platform has
its own file. The files differ only in the two `pin.sha256` values
(`crates/credential-eval-cli/tests/official_configs.rs` enforces that, plus
schema validity, a pin on every scanner, `network: disabled`, and npm pin
versions equal to the lockfile). Compare official artifacts across releases
only when they come from the same file. The CI steps are in
[consumers/benchmarks-quickstart.md](consumers/benchmarks-quickstart.md).

## Verified official run

One end-to-end official run of the committed configuration, made before
`redact-secret-benchmarks` started its official-run phase. It is a local
verification, not the official measurement (see [Local runs](#local-runs)),
and the artifact was not committed. Only this sanitized summary is recorded.

| Input | Identity |
|---|---|
| credential-eval | `0.1.0-alpha.1` at `d5f2fb2` plus this change (no engine or adapter code changed), protocol `credential-eval-protocol/1`, release build |
| Evidence release | `snapshot-2026.10.01.2` (credential-evidence `a5362d6`), manifest `sha256:2557a72ae8dec3ca6d734a6c87b6db9cb4881543541693a4555fdfd9f7ba26d8` |
| Corpus | `source: credential-evidence`, `revision: records-tree-sha256:4cd72141c1deec4aef21c0f5b2d751c51eb3d7abe5088756219d99c93f464f50`, evidence schema `credential-evidence/schema/1.5.0`, 5,950 cases, `corpus_digest: sha256:1bc5a07b49dab7b8182f51bf11a65a9bb8a220adbd5216b364bc15b2d8e6a5af` |
| Configuration | `configs/official/credential-public-v1.darwin-arm64.json`, `config_hash: sha256:042691470c89d6ae4b088dcb1ed941be33c499bb2269b18e60ffb137e19aa5d7` |
| Host | darwin-arm64, Node v22.16.0, `--jobs 4`, `--require-complete`, shared host (load average about 50) |

```bash
credential-eval run --run-class official \
  --corpus credential-eval-corpus-snapshot.json \
  --evidence-release snapshot-2026.10.01.2 \
  --evidence-manifest release-manifest.json \
  --evidence-manifest-digest sha256:2557a72ae8dec3ca6d734a6c87b6db9cb4881543541693a4555fdfd9f7ba26d8 \
  --config configs/official/credential-public-v1.darwin-arm64.json \
  --node-dir adapters/node --jobs 4 --require-complete --out results/local/artifact.json
```

Result: exit 0, `run_class: official`, `publication: public`, artifact valid
against `schemas/run-artifact-v1.schema.json`, semantic digest
`sha256:babea44c2c5b79b13cefe32fec39534f24b593dc0da5279dbb2c940965e5410f`.

| Scanner | Version (pin) | Build | Status | Replays | Findings | Scanner time |
|---|---|---|---|---|---|---|
| `flare-redact` | 1.6.1 | released | complete | 2, agreed | 1,111 | 46 s |
| `gitleaks` | 8.30.1, executable `sha256:ba52fb1b…` | released | complete | 2, agreed | 2,410 | 36 s |
| `openredaction` | 1.1.5 | released | complete | 2, agreed | 27,253 | 445 s |
| `redact-secret` | 0.1.0-beta.12 | released | complete | 2, agreed | 3,156 | 45 s |
| `trufflehog` | 3.97.4, executable `sha256:8c7af13e…` | released | complete | 2, agreed | 1,046 | 122 s |

The finding counts equal those of credential-evidence's five-scanner dual run
over the same corpus
([parity report](parity/parity-report.md#coverage-at-1020d2b5)).

Durations (indicative only, shared host): wall 287 s for the run (291 s
including process start), 694 s of scanner process time over 18 processes,
evaluator 12 s. Release build 924 s with `CARGO_BUILD_JOBS=2`.

Before it, a cheap validation. The configurations parse and validate
against the schema (`tests/official_configs.rs`), the release manifest
digest and the snapshot entry digest match, `trufflehog --version` and
`gitleaks version` match the pins, and a 25-case exploratory smoke (20 cases
spread over the sorted ids plus their twins) completed for all five scanners
in 89 s. Then refusals were checked. Each exited 4, before any scan, with no
artifact:

| Refusal | Message (sanitized) | Time |
|---|---|---|
| wrong `--evidence-manifest-digest` | release manifest digest … does not match the pinned … | 1 s |
| TruffleHog `pin.sha256` set to the linux-x64 digest on darwin | scanner trufflehog: executable digest … does not match pin … | 57 s |
| TruffleHog `pin.version` 3.97.6 | scanner trufflehog: resolved version 3.97.4 does not match pin 3.97.6 | 48 s |

A pin refusal comes after every scanner is prepared (version probes and
installed-tree digests of the npm packages), which takes most of that time
on a loaded host. No corpus file is scanned.

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

The publication class does not look at the corpus. An official run of
released scanners over a protected or holdout corpus is `public` by this
derivation. Its consumer still keeps it inside qualification unless the
corpus owner allows publication
([multi-corpus-qualification.md](multi-corpus-qualification.md) §5).

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
