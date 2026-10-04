# ADR 0006: Pin the product build by registry integrity, and keep the previous build as an explicit alternative

- Status: accepted
- Date: 2026-10-04
- Issue: redact-secret-benchmarks#697 (replay `snapshot-2026.10.04.3` against published beta.13)
- Amends: nothing frozen. Adds two optional fields to a v1 document (revision v1.4, [ADR 0001](0001-freeze-v1-contracts.md)). The engine behavior and the measurement protocol (`credential-eval-protocol/1`) are unchanged.

## Context

The accepted `v0.1.0-alpha.4` replay of `snapshot-2026.10.04.3` scanned
`@redact-secret/core` 0.1.0-beta.12, while the benchmark's published product
measurements refer to 0.1.0-beta.13. The product build was identified by three
things that were not one input:

| Where | What | Weakness |
|---|---|---|
| `adapters/node/package.json` and `package-lock.json` | version and `sha512` integrity | an engine-tag-wide choice: a different product build meant a different engine tag |
| `configs/official/*.json` `scanners[].pin` | version only | the pin could not tell two tarballs of one version apart |
| artifact `manifest.scanners[].provenance` | version, lockfile `integrity`, installed tree digest, lockfile digest | recorded, never checked against a pin |

The tag `v0.1.0-alpha.4` is immutable and stays at beta.12. Re-tagging, or
publishing a different lockfile under an existing tag, would change what an
accepted receipt means.

## Decision

1. **The product build is a pinned, configurable input.** The official
   configuration names it (exact `version`, registry `integrity`, resolved
   tarball) and `--node-dir` selects the lockfile that installs it. The
   canonical configurations pin beta.13; the beta.12 build stays available as
   an explicit alternative pair (decision 4). No engine tag changes.
2. **`pin` gains `integrity` and `resolved` (revision v1.4).** Both are
   optional in the schema (a v1.1 pin stays valid) and required, by test, on
   every npm scanner in the committed official configurations
   (`@redact-secret/core`, `flare-redact`, `@openredaction/core`).
3. **An official run verifies the pin before any scan.** For each npm scanner
   with an `integrity` or `resolved` pin it compares the pin with the lockfile
   entry, with the entry npm recorded when it installed the package
   (`node_modules/.package-lock.json`; npm verifies the downloaded tarball
   against the lockfile `sha512` first) and with the provenance component. Any
   difference, a missing install record, or a non-`published` package source is
   refused (exit 4, no artifact). The values are written to the artifact by the
   provenance that already existed (version, `integrity`, tree digest, lockfile
   digest) and by `config_hash` (the pin). No artifact field is added, so an
   artifact differs from an alpha.4 one only in `manifest.engine.version` when
   the configuration is the same.
4. **The previous build is a committed alternative, not a flag.**
   `adapters/node-core-beta.12/` holds the `package.json` and
   `package-lock.json` of `v0.1.0-alpha.4` byte for byte and links `shim.mjs`
   to the shim of `adapters/node`. `credential-public-v1.core-beta.12.json` and
   `credential-public-v1.core-beta.12.darwin-arm64.json` equal their beta.13
   counterparts except for the `redact-secret` pin. Tests enforce the file
   identities, the pin-versus-lockfile agreement and the one-pin difference. A
   configuration and node directory that do not belong together are refused by
   the version pin.
5. **Configuration pairs, not a runtime switch.** The pin is part of
   `config_hash`, so each product build has its own configuration hash and
   semantic digest; the two are never compared as one.
6. **Engine `v0.1.0-alpha.5`, contract revision v1.4.** The engine version
   changes only because the configurations, the lockfile and the pin check
   shipped together need a tag. `credential-eval capabilities` reports
   `contract_revision` `1.4`.

## Rejected

- Re-pointing `v0.1.0-alpha.4`, or a lockfile that differs per run without a
  tag: it changes the meaning of an accepted receipt.
- A `--product-version` flag: the version would not be part of the
  configuration hash unless duplicated, and an unpinned input is the problem.
- Adding `resolved` to provenance: the integrity is the content address of the
  tarball; the URL is its registry origin, which the pin and `config_hash`
  already fix. A new artifact field would also make every alpha.4 and alpha.5
  artifact differ, removing the clean equivalence in "Evidence".

## Evidence

Host: darwin-arm64, Node v22.16.0, `--run-class official --jobs 4
--require-complete`, evidence `snapshot-2026.10.04.3` (manifest digest
`sha256:690ed57312d576fd6a614d40de10efe8bbc89431693aa4fbaa99979d69c0da8a`,
verified by the engine; corpus `sha256:fdce9df7611a1c8be927c1bad3ec8fa85a57373187c2f5b51cc9dc09195d9e8f`),
Gitleaks 8.30.1 (`sha256:ba52fb1b…`) and TruffleHog 3.97.4 (`sha256:8c7af13e…`)
from the upstream archives, plain mode (no methods). Artifacts were built in a
scratch directory and deleted; only the identities are recorded.

Four official runs. `old` is the `v0.1.0-alpha.4` darwin configuration
(version-only pins); `new` is the alpha.5 darwin configuration of this change.

| Run | Engine | Configuration | `--node-dir` | `redact-secret` | `config_hash` | Semantic digest |
|---|---|---|---|---|---|---|
| A | alpha.4 | old | alpha.4 `adapters/node` | 0.1.0-beta.12 | `sha256:1babac53…` | `sha256:a17c3064…52c` |
| B | alpha.5 | old | `adapters/node-core-beta.12` | 0.1.0-beta.12 | `sha256:1babac53…` | `sha256:c40d92de…fcb` |
| C | alpha.5 | new, `core-beta.12` | `adapters/node-core-beta.12` | 0.1.0-beta.12 | `sha256:f5f31a97…` | `sha256:eb391a3b…eee` |
| D | alpha.5 | new, canonical | `adapters/node` | 0.1.0-beta.13 | `sha256:2664d205…` | `sha256:d831f9f2…563` |

All four: `official`, `public`, five scanners `complete` (`--require-complete`),
evidence release verified, corpus `sha256:fdce9df7…`. Per scanner findings:
flare-redact 1,418, gitleaks 2,676, openredaction 360,606, redact-secret 3,510
(beta.12 and beta.13), trufflehog 1,068.

**New engine on beta.12 reproduces alpha.4 (A against B).** The semantic
digests differ, because `manifest.engine.version` is part of the digest and
is `0.1.0-alpha.4` against `0.1.0-alpha.5`. Compared as JSON (everything
except the excluded `non_semantic` block: manifest, provenance, every
scanner's cases, findings, assertions, aggregates), exactly one path differs:
`/manifest/engine/version`. Same `config_hash`, same lockfile, shim, package
and tree digests, same outcomes. A digest computed with the engine version
held equal is therefore equal. This is verified equivalence, not an assumed one.

**The pin additions change nothing measured (B against C).** Exactly one path
differs: `/manifest/config_hash`.

**beta.12 against beta.13 on this snapshot (C against D).** Twelve paths
differ and every one is identity: `config_hash`; `redact-secret` `version`; the
`@redact-secret/core`, `@redact-secret/node-darwin-arm64` and
`@redact-secret/wasm` provenance `version`, `integrity` and tree `sha256`;
and the lockfile digest in the provenance of every npm scanner (the lockfile
changed). No case, finding, outcome or aggregate of any scanner differs:
`redact-secret` reports the same 3,510 findings on the same cases under both
builds in plain mode. A failure first seen in the alpha.4 replay is therefore
not an effect of the beta.12 to beta.13 change, at least in plain mode. Methods,
policy and regression populations are not covered by this check; the
benchmark owns them (#697).

**Refusals** (exit 4, before any scan, no artifact):

- beta.13 configuration with `adapters/node-core-beta.12`: `scanner
  redact-secret: resolved version 0.1.0-beta.12 does not match pin
  0.1.0-beta.13`;
- beta.13 configuration with the integrity changed: `scanner redact-secret:
  lockfile integrity sha512-qZkqRN7C… does not match pin sha512-AAAA…`.

Unit tests (`crates/credential-eval-cli/tests/npm_pin.rs`) cover every
disagreement: lockfile version, integrity and resolved URL, install record
integrity, a missing install record, provenance, and a candidate source.

**Determinism.** Runs A and B were independent and agree exactly. One
additional run of the canonical configuration (D) made while another run
shared the host was `exit 3`: OpenRedaction's two replays disagreed and the
engine discarded its findings (`unstable`); every other scanner agreed. The
same run repeated alone completed with all five `complete` (the digest above).
An `unstable` scanner is never published (`--require-complete`); a consumer
repeats the run.

Host timings are not recorded (shared host).

## Consequences

- A benchmark replay of beta.13 pins `credential-eval` `v0.1.0-alpha.5` and
  `configs/official/credential-public-v1.json`; the beta.12 attribution run on
  the same engine uses the `core-beta.12` pair
  ([benchmarks-quickstart.md](../consumers/benchmarks-quickstart.md)).
- A new product build is a lockfile bump, an updated pin and, if the history of
  builds should stay reproducible, a new `node-core-<version>` directory and
  configuration pair, shipped under a new tag.
- The accepted alpha.4 receipts keep meaning beta.12 and are reproduced by the
  `v0.1.0-alpha.4` tag, or by alpha.5 with the `core-beta.12` pair.
