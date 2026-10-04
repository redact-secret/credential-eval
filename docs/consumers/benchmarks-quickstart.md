# Official runs from redact-secret-benchmarks CI

These are the exact steps the `redact-secret-benchmarks` CI follows to
produce an official credential-eval artifact for one population
(redact-secret-benchmarks#603, #604). The rules behind each step are in
[official-runs.md](../official-runs.md) and
[multi-corpus-qualification.md](../multi-corpus-qualification.md). This page
only orders them.

The example measures the public credential population: credential-evidence
release `snapshot-2026.10.01.2` with
[`configs/official/credential-public-v1.json`](../../configs/official/credential-public-v1.json).
The run that verified these steps is recorded in
[official-runs.md](../official-runs.md#verified-official-run).

## Pins

The CI pins every input in its own files. Nothing is resolved at run time.

| Input | Pin |
|---|---|
| credential-eval | tag `v0.1.0-alpha.5` (`credential-eval --version` prints `credential-eval 0.1.0-alpha.5`) |
| Run configuration | `configs/official/credential-public-v1.json` at that tag (linux-x64 executable digests) |
| Evidence release | `redact-secret/credential-evidence` tag `snapshot-2026.10.01.2`, manifest digest `sha256:2557a72ae8dec3ca6d734a6c87b6db9cb4881543541693a4555fdfd9f7ba26d8` |
| Corpus | 5,950 cases, corpus digest `sha256:1bc5a07b49dab7b8182f51bf11a65a9bb8a220adbd5216b364bc15b2d8e6a5af` |
| Gitleaks 8.30.1 | `gitleaks_8.30.1_linux_x64.tar.gz` `sha256:551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb`; binary `sha256:88f91962aa2f93ac6ab281d553b9e125f5197bbbce38f9f2437f7299c32e5509` |
| TruffleHog 3.97.4 | `trufflehog_3.97.4_linux_amd64.tar.gz` `sha256:dc24007c2f233bd61c05beabeb44aa27ea9b43288166279209abe0458c5ce76b`; binary `sha256:95c2a42bce979fce6dd73cc629b37ae4d72731b0dc16e047fba41a77bc765620` |
| npm scanners | `adapters/node/package-lock.json` at the tag: `@redact-secret/core` 0.1.0-beta.13, `flare-redact` 1.6.1, `@openredaction/core` 1.1.5, each with its `sha512` integrity and tarball URL, also pinned in the configuration |
| Node | 22 (the run that verified this used v22.16.0) |

The archive digests come from the upstream release checksum files:
<https://github.com/gitleaks/gitleaks/releases/download/v8.30.1/gitleaks_8.30.1_checksums.txt>
and
<https://github.com/trufflesecurity/trufflehog/releases/download/v3.97.4/trufflehog_3.97.4_checksums.txt>.
The binary digests are the SHA-256 of the executable extracted from those
archives. They are what the `pin.sha256` in the configuration checks
(official-runs.md, "Official configuration").

## Steps

```bash
set -euo pipefail
TAG=snapshot-2026.10.01.2
MANIFEST_DIGEST=2557a72ae8dec3ca6d734a6c87b6db9cb4881543541693a4555fdfd9f7ba26d8
CE=v0.1.0-alpha.5

# 1. Fetch the evidence release by tag and verify the manifest digest.
#    credential-eval verifies it again (step 5); checking here fails earlier.
gh release download "$TAG" -R redact-secret/credential-evidence -D evidence \
  -p release-manifest.json -p release-manifest.json.sha256 \
  -p credential-eval-corpus-snapshot.json
echo "$MANIFEST_DIGEST  evidence/release-manifest.json" | sha256sum -c -

# 2. Build credential-eval at the pinned tag. The configuration and the Node
#    shim come from the same checkout. While the repository is private, the
#    clone needs a token with read access to redact-secret/credential-eval.
#    Record the tag's commit SHA with the artifact.
git clone --depth 1 --branch "$CE" https://github.com/redact-secret/credential-eval ce
cargo build --release --locked -p credential-eval-cli --manifest-path ce/Cargo.toml
ce/target/release/credential-eval --version   # credential-eval 0.1.0-alpha.5

# 3. Provision the binary scanners at their pins (linux-x64), read-only.
mkdir -p peer-bin dl
curl -fsSL -o dl/gitleaks.tgz \
  https://github.com/gitleaks/gitleaks/releases/download/v8.30.1/gitleaks_8.30.1_linux_x64.tar.gz
curl -fsSL -o dl/trufflehog.tgz \
  https://github.com/trufflesecurity/trufflehog/releases/download/v3.97.4/trufflehog_3.97.4_linux_amd64.tar.gz
sha256sum -c - <<'EOF'
551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb  dl/gitleaks.tgz
dc24007c2f233bd61c05beabeb44aa27ea9b43288166279209abe0458c5ce76b  dl/trufflehog.tgz
EOF
tar -xzf dl/gitleaks.tgz -C peer-bin gitleaks
tar -xzf dl/trufflehog.tgz -C peer-bin trufflehog
chmod 555 peer-bin/* peer-bin
export PATH="$PWD/peer-bin:$PATH"
test "$(trufflehog --version 2>&1)" = "trufflehog 3.97.4"
test "$(gitleaks version)" = "8.30.1"

# 4. Install the npm scanners from the lockfile, without install scripts.
(cd ce/adapters/node && npm ci --ignore-scripts --no-audit --no-fund)

# 5. Run official. Any unverified input exits 4 with no artifact.
ce/target/release/credential-eval run --run-class official \
  --corpus evidence/credential-eval-corpus-snapshot.json \
  --evidence-release "$TAG" \
  --evidence-manifest evidence/release-manifest.json \
  --evidence-manifest-digest "sha256:$MANIFEST_DIGEST" \
  --config ce/configs/official/credential-public-v1.json \
  --node-dir ce/adapters/node --jobs 4 --require-complete \
  --out artifact.json
```

Step 3 also works without the tarball checks, because the run refuses a
binary whose digest differs from the configuration's `pin.sha256`. The
early check gives a clearer failure.

Exit codes: 0 artifact written; 2 configuration or usage error (for example a
missing release flag or an unpinned scanner); 3 artifact written but a scanner
did not complete (`--require-complete`); 4 refused: the evidence did not
verify or a scanner did not match its pin. Treat anything but 0 as a failed
job, and never publish an artifact from a non-zero exit.

## After the run

6. **Validate the artifact** against `ce/schemas/run-artifact-v1.schema.json`
   before reading any field (multi-corpus-qualification.md §6, rule 1). Any
   draft 2020-12 validator works. The dependency-free reference validator
   needs no install:

   ```bash
   node --input-type=module -e '
     import { readFileSync } from "node:fs";
     import { validate } from "./ce/examples/qualification-consumer/validate.mjs";
     const schema = JSON.parse(readFileSync("ce/schemas/run-artifact-v1.schema.json"));
     const errors = validate(schema, JSON.parse(readFileSync("artifact.json")));
     if (errors.length) { console.error(errors.join("\n")); process.exit(1); }'
   ```

7. **Check the classes.** `manifest.run_class` must be `official` and
   `manifest.publication` `public`. Every `scanners[]` entry must have
   `status: complete` (`--require-complete` already enforces it), and every
   `manifest.scanners[]` must report `build: released` and the pinned
   version. A `public` artifact is still published only if the population is
   publishable in the consumer's registry (§5).

8. **Bind the population identity** (§6, rule 2). Look up the population in
   the consumer's registry and require `manifest.evidence` to equal it:

   | Field | Expected for the public credential population |
   |---|---|
   | `source` | `credential-evidence` |
   | `revision` | `records-tree-sha256:4cd72141c1deec4aef21c0f5b2d751c51eb3d7abe5088756219d99c93f464f50` |
   | `corpus_digest` | `sha256:1bc5a07b49dab7b8182f51bf11a65a9bb8a220adbd5216b364bc15b2d8e6a5af` |
   | `release.tag` | `snapshot-2026.10.01.2` |
   | `release.manifest_digest` | `sha256:2557a72ae8dec3ca6d734a6c87b6db9cb4881543541693a4555fdfd9f7ba26d8` |

   Key every derived record by `(population, case_id)`, and keep the artifact
   digest and its reproduction identities (`engine`, `protocol_version`,
   `config_hash`, scanner identities and provenance) with each record.

## Platforms and the configuration hash

A pin holds one executable digest, and the pin is part of the configuration,
so it is part of `config_hash` and the semantic digest. The committed
configurations are:

| File | Platform | Use |
|---|---|---|
| `configs/official/credential-public-v1.json` | linux-x64 | the CI run (canonical) |
| `configs/official/credential-public-v1.darwin-arm64.json` | darwin-arm64 | local reproduction |

They differ only in the two `pin.sha256` values (a test enforces this). A
linux and a darwin run of the same inputs therefore have different
`config_hash` and semantic digests. Compare official artifacts across releases
only when they come from the same configuration file. A CI on another
platform adds its own variant the same way: download the upstream archive,
check it against the upstream checksum file, and pin the SHA-256 of the
extracted executable.

## Scanning another `@redact-secret/core` build

Step 4 installs whatever the shim directory's lockfile pins, and step 5
refuses the run when the configuration's pin disagrees with it. To scan
`@redact-secret/core` 0.1.0-beta.12 on the same engine (the attribution run),
change two inputs together and nothing else:

```bash
(cd ce/adapters/node-core-beta.12 && npm ci --ignore-scripts --no-audit --no-fund)
ce/target/release/credential-eval run --run-class official \
  ... \
  --config ce/configs/official/credential-public-v1.core-beta.12.json \
  --node-dir ce/adapters/node-core-beta.12 --jobs 4 --require-complete \
  --out artifact-core-beta.12.json
```

The darwin-arm64 pair is `credential-public-v1.core-beta.12.darwin-arm64.json`.
Expect `manifest.scanners[id=redact-secret].version` `0.1.0-beta.12`, its
provenance `npm-package` `@redact-secret/core` integrity
`sha512-fDVwt2U7VFSKb/0ixSuU5e+TOGVaUnyR1sIYwgS4S6gMndFnaq0M7ikaqac8wnTMYfYO/LS12JayXXeKbhE4aw==`,
and a `config_hash` different from the beta.13 run's (the pin is part of the
configuration). See official-runs.md, "npm package pins".

## Product-owned populations

Regression, policy and other product-owned populations run the same way, one
run and one artifact per population (multi-corpus-qualification.md §3). Each
needs:

- a corpus snapshot and a release manifest in the shape the verifier reads
  (`tag`, `files[] {path, sha256}` with one `credential-eval/corpus-snapshot.json`
  entry), whose manifest digest the CI pins;
- its own run configuration with a `pin` on every scanner (often only
  `redact-secret`), kept next to the population in the product repository or
  added under `configs/official/`;
- its own registry entry (source, revision, corpus digest, release tag,
  manifest digest, publishable).

Steps 1 and 5 then take that population's tag, manifest and digest instead
of the credential-evidence ones. Steps 2-4 and 6-8 are unchanged. Artifacts of
different populations are never merged or compared case by case.
