# ADR 0001: Freeze the v1 contracts

- Status: accepted
- Issue: #13
- Scope: the four v1 documents and their schemas: `CorpusSnapshot`
  (`schemas/corpus-snapshot-v1.schema.json`), `RunConfig`
  (`schemas/run-config-v1.schema.json`), `ObservationSet`
  (`schemas/observation-set-v1.schema.json`) and `RunArtifact`
  (`schemas/run-artifact-v1.schema.json`).

## Context

The v1 schemas were published unfrozen while the kernel (#3), the adapters
(#4) and parity (#5) could still add fields. Those issues are closed, and the
three additive proposals from the qualification boundary have landed:
P1 (grouping passthrough on `CaseResult`), P2 (`review_queue`) and P3
(per-target aggregates). See [../qualification-boundary.md](../qualification-boundary.md) §5.

Redact Secret qualification in `redact-secret-benchmarks` is the first
consumer that will replace its in-process engine with "read a run artifact".
It cannot do that against a schema that may still change shape. The same
promise applies to `credential-evidence`, which produces `CorpusSnapshot`
documents, and to anyone who writes run configurations or replays
observation sets. `credential-evidence` made the same kind of promise for its
own formats in its ADR 0002.

## Decision

1. **v1 never changes incompatibly.** Every document that is valid under a v1
   schema as frozen stays valid under every later v1 schema, and keeps its
   meaning. No property, definition, enum value or variant is removed or
   renamed; no type is narrowed; no constraint is tightened; no existing
   optional property becomes required; no field changes meaning.
2. **New optional fields are minor revisions.** A v1 revision may add
   optional properties, new definitions, new enum values and new variants,
   and may widen a type. A new field is optional in the schema and absent
   from documents that do not use it. Its absence must keep the meaning the
   document had before the field existed. Every revision is listed in
   [../contracts/README.md](../contracts/README.md) ("Revisions").
3. **A breaking change is v2.** It gets new schema tags
   (`credential-eval/<document>/v2`), new schema files next to the v1 files,
   and a migration note. v1 files and readers stay until their consumers have
   moved.
4. **The measurement protocol is separate.** `PROTOCOL_VERSION`
   (`credential-eval-protocol/1`) changes only through a reviewed protocol
   revision. A schema revision never changes an outcome, and a protocol
   revision does not by itself change a schema.

### Reader guidance

Every struct in the v1 schemas sets `additionalProperties: false`. A reader
that validates with an older v1 schema therefore rejects a document that
uses a newer optional field. Readers validate with the schema file of the
engine version that produced the document, or with any later v1 schema; a
later v1 schema accepts every earlier v1 document. A consumer that needs a
new field pins an engine version that writes it.

### Enforcement

- `crates/credential-eval-contracts/tests/frozen-v1/` holds the four schemas
  exactly as frozen. They live outside `schemas/` because
  `schema_drift::no_unexpected_schema_files` allows only generated files
  there.
- `crates/credential-eval-contracts/tests/frozen_v1.rs` checks that the
  schemas generated from the current types accept everything the frozen
  baselines accept. It refuses a removed definition or property, a changed
  `$ref`, a narrowed or changed type, a newly required property, a removed
  enum value or variant, a tightened constraint and any schema keyword it
  does not know. It pins the SHA-256 of every baseline file, so editing a
  baseline also requires a reviewed edit of the test. The checker has its own
  unit tests in the same file.
- `crates/credential-eval-contracts/tests/schema_guarantees.rs` checks two
  invariants that hold for every revision. No property can carry matched
  values or raw scanner output unless it is on a reviewed allowlist. The run
  artifact requires every reproduction identity in
  [../contracts/identity.md](../contracts/identity.md).
- CI runs both as part of `cargo test --workspace` (`.github/workflows/ci.yml`).

The checker is conservative: it may refuse a change that is in fact
compatible (for example, restructuring an inline schema into a `$ref`). Such
a change is then made differently, or it waits for v2.

## Consequences

- Consumers can build on v1 now. Qualification can read the artifact
  through its schema without tracking engine internals.
- Every later field addition, including the run-class and evidence-release
  fields planned in #14, must be optional and documented as a revision.
- Mistakes in v1 cannot be fixed in place. They are documented, and they are
  fixed in v2 if they matter.
- Proposal P4 (the sanitized scanner `configuration` object in the
  manifest) was not taken into v1.0. If it is accepted later, it lands as an
  optional field in a minor revision.
