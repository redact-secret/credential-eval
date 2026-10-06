# ADR 0018: Family id namespaces and twin scoping

- Status: accepted
- Date: 2026-10-06
- Issue: #56 (found in #49; parent: redact-secret-benchmarks#723).
- Amends: scoped twin scoring (`docs/contracts/outcomes.md`). Engine
  `0.1.0-alpha.13`. No schema change; no adapter output change, so adapter
  versions, `FAMILY_MAPPING_VERSION` and accuracy observation reuse are
  unaffected. **Measured twin outcomes change** for any run on an evidence
  snapshot with `provider:family` twin families (`snapshot-2026.10.01.2` and
  later); this is a reviewed protocol revision, not a refactor.

## Context

Adapter tables label findings with legacy `bench` ids (`github-token`). Evidence
snapshots label cases with `provider:family` ids (`github:classic-personal-access-token`).
The scoped twin rule treats a finding with a known family other than the
twin's as co-detection, so with two namespaces every mapped finding on an
evidence twin was "another family". The issue measured 112 twin controls that
were covered by a mapped finding but not flagged (OpenRedaction default,
`snapshot-2026.10.01.2`).

## Decision

1. **Adapters keep emitting legacy ids.** Legacy parity corpora keep legacy
   ids; rewriting the tables would change every adapter and break parity, and a
   legacy id is coarser than an evidence id (`github-token` spans six GitHub
   families), so a rewrite cannot be done per label.
2. **One protocol-owned comparison.** `credential_eval_contracts::family_ids::same_family`
   is the only family comparison in scoring. Ids are the same family when equal,
   or when a legacy id *covers* an evidence id. The coverage table
   (`FAMILY_COVERAGE_VERSION` `1`) gives each legacy id either a whole provider
   (`github:`) or exact evidence families; specific legacy ids (for example
   `github-fine-grained-pat`) never widen to the provider.
3. **Fail-safe defaults.** A legacy id absent from the table covers nothing,
   which is the previous behavior. Evidence ids are compared exactly. No expected
   family is relabelled and no scanner output is read by the table.
4. **Scanner neutral.** The table is keyed by family ids, never by scanner.
   Every table entry resolves to a family present in `snapshot-2026.10.06`
   (checked when written; a unit test checks shape and ordering).

## Not decided here

How many twin controls flip on each scanner (gitleaks, trufflehog, redact-secret,
flare-redact, OpenRedaction) is a measurement and needs a scanner run. It was
not run for this change; the next official run on an evidence snapshot reports
it, and should be compared with the previous run as a protocol delta. Coverage
at provider level is deliberately broad where the legacy id never named a
sub-family; a narrower reading would count more co-detection.

## Tests

`family_ids` unit tests (sorted and unique, entry shape, equality in both
namespaces, provider coverage, exact entries do not widen, provider prefix
`aws:` does not match `aws-bedrock:`, unknown legacy id) and a lattice test for
scoped twins with a covering legacy id, another provider and an evidence id.
