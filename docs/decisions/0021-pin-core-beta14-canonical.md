# ADR 0021: Pin `@redact-secret/core` 0.1.0-beta.14 as the canonical product build

- Status: accepted
- Date: 2026-10-07
- Issue: redact-secret-benchmarks#808 (repin to the published beta.14; the credential new path
  measured beta.13, so the authority could not be re-authorised at beta.14)
- Amends: ADR 0006 (the canonical configurations pin beta.14 instead of beta.13). Engine
  `0.1.0-alpha.16`. Protocol `credential-eval-protocol/1`, contract revision 1.9 and the
  run-artifact schema are unchanged.

## Context

ADR 0006 pins the product build by registry integrity, and the official run refuses a scanner
whose lockfile, install record or provenance disagrees with the configuration pin (exit 4, no
artifact). `v0.1.0-alpha.15` pins beta.13, so the engine cannot measure the published beta.14.
An existing tag must not be moved (ADR 0006, "Rejected").

## Decision

`v0.1.0-alpha.16` is alpha.15 with one change of product pin and nothing else:

- `@redact-secret/core` `0.1.0-beta.14`, integrity
  `sha512-1h5NxUto2ZEqQD5hfIgbzwDZkmu6WXdlmtF0waG3FcKDhpCEoUphgj4B4VGRyhVhjJOFT58/TrER+3EL1bCnag==`,
  tarball `https://registry.npmjs.org/@redact-secret/core/-/core-0.1.0-beta.14.tgz`, in the four
  canonical configurations (`credential-public-v1`, its darwin-arm64 counterpart and both
  `without-openredaction` files) and in `adapters/node` (`package.json`, `package-lock.json`;
  the platform packages and `@redact-secret/wasm` follow the lockfile).
- The engine version is `0.1.0-alpha.16` (Cargo manifests, the two smoke-test goldens).
- No kernel, adapter, scoring, schema or contract change. `core-beta.12` configurations and
  `adapters/node-core-beta.12` stay as they are. No `core-beta.13` pair is added: alpha.15
  reproduces the beta.13 runs.

## Consequences

- A benchmark replay of beta.14 pins `credential-eval` `v0.1.0-alpha.16`.
- alpha.15 keeps meaning beta.13; accepted beta.13 receipts stay reproducible at that tag.
- Equivalence of the engine apart from the pin rests on the diff (no source file under
  `crates/*/src` changes) and the test suite; a measured effect of the product change belongs to
  the benchmark replay.
