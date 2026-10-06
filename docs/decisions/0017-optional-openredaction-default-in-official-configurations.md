# ADR 0017: The OpenRedaction default profile is optional in the official configurations

- Status: accepted
- Date: 2026-10-06
- Issue: redact-secret-benchmarks#763 (parent: #723; follows ADR 0013, ADR 0015 and ADR 0016)
- Amends: nothing frozen. Adds two official configuration files. No contract field,
  protocol rule, adapter, scoring or existing configuration changes.

## Context

The official configurations run `openredaction` with `options: {}` (every built-in
pattern, personal data included). On the accepted snapshot that is hundreds of
thousands of findings, almost all out of scope (ADR 0016), and a methods run of
40+ minutes. As a required scanner it blocked or delayed the results of every other
scanner and of core verification. The consumer's evaluation contract
(redact-secret-benchmarks, scanner roster) now treats the default profile as an
optional, manual measurement whose absence is stated, not hidden.

## Decision

1. Add `configs/official/credential-public-v1.without-openredaction.json` and its
   `darwin-arm64` variant. Each is its counterpart with the `openredaction` scanner
   entry removed and nothing else changed (a test compares them entry for entry).
2. Leave every existing configuration, including the two `core-beta.12` attribution
   files, untouched. The configurations of earlier runs stay reproducible: a run
   selects its configuration by file, and a run that wants the default profile still
   passes the existing file.
3. The selection is explicit. The engine has no implicit default; the consumer names
   the file (`--config`), so including or omitting the default profile is always a
   visible input of the run, and the artifact's `config_hash` differs between the two.
4. Nothing here measures anything or claims a score. The credential-scoped profiles
   (ADR 0013, ADR 0015) are separate scanners and remain diagnostics.

## Consequences

- An official run of the without-OpenRedaction configuration measures four scanners
  and completes without the slow, noisy profile; its `config_hash` and semantic digest
  are its own and are never compared with a run of the full configuration.
- A consumer pins the new files only through a tagged release; this change adds files
  and does not tag.
