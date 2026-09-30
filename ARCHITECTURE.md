# ARCHITECTURE

## Purpose

`credential-eval` is the generic measurement engine in the credential evidence ecosystem.

It consumes scanner-neutral cases from `credential-evidence`, executes one or more scanners, normalizes their findings, and produces reproducible measurement artifacts.

It does not own credential truth and it does not own product qualification.

## Architectural boundary

```text
credential-evidence
        │
        ▼
credential-eval
        │
        ├─ scanner adapters
        │
        ▼
measurement artifacts
        │
        ├──────────▶ credential-evidence-site
        │
        └──────────▶ product-specific qualification
```

The evaluator must not require Redact Secret internals.

## Measurement kernel

The preferred implementation is a Rust kernel/CLI.

Responsibilities:

- load versioned corpus input;
- materialize fixture files;
- schedule scanner work;
- normalize scanner findings;
- score authored ranges;
- compute measurement groups;
- generate mutation/metamorphic variants;
- preserve deterministic result ordering;
- emit sanitized result artifacts.

The measurement kernel should be usable without the public site.

## Outcome lattice

The canonical span relationship is:

```text
EXACT
COVERED
OVERBROAD
PARTIAL
MISS
```

The engine must preserve the existing semantics proven in the legacy benchmark implementation until a separately reviewed measurement revision changes them.

A measurement revision is a protocol change, not an implementation refactor.

## Inputs

The engine should consume explicit, versioned inputs:

```text
CorpusSnapshot
  ├─ cases / fixture projections
  ├─ authored ranges
  ├─ envelopes
  ├─ benign controls
  ├─ twin lineage
  ├─ mutation/metamorphic metadata
  └─ corpus identity
```

Inputs should carry enough identity to prevent stale scanner results from being applied to changed fixture bytes.

## Outputs

A run artifact should identify:

- engine version;
- measurement protocol version;
- credential-evidence revision/schema;
- scanner identity/version/mode;
- scanner adapter version;
- corpus digest;
- run configuration;
- normalized findings;
- per-case outcomes;
- aggregate measurements;
- explicit scanner failures/unavailable states.

Public artifacts must not contain matched secret values or unbounded raw scanner stdout/stderr.

## Scanner adapter API

The adapter layer is intentionally narrow.

Conceptually:

```text
prepare()
identity()
scan(fixtures)
normalize(raw)
```

The exact API may differ, but the ownership should not.

Adapters may call:

- external binaries;
- Node programs;
- Python programs;
- native libraries;
- package CLIs.

An adapter is not allowed to redefine scoring.

## Process orchestration

Scanner execution is often the dominant cost.

The engine must distinguish:

```text
scanner execution time
vs
evaluation overhead
```

Resource controls should include:

- configurable job count;
- per-scanner concurrency;
- timeout;
- output size limit;
- bounded buffering;
- deterministic result collation;
- explicit cancellation/failure semantics.

Unbounded subprocess fan-out is prohibited.

## Rust / JS boundary

Rust should own deterministic hot-path semantics.

JS/TS may remain for:

- compatibility tooling;
- migration scripts;
- convenient scanner shims;
- report shaping;
- developer tooling.

Do not reimplement the outcome lattice in multiple runtimes without a strong reason.

## Determinism

Parallel execution must not change semantic output.

Given the same:

- evidence snapshot;
- engine protocol version;
- scanner versions/modes;
- adapter versions;
- config;

the normalized measurement artifact must be identical except for explicitly non-semantic metadata such as timestamps or host diagnostics.

## Performance migration

The TypeScript engine is the parity oracle until cutover.

Migration sequence:

```text
1. define input/output contracts
2. baseline TypeScript runtime/memory
3. implement Rust kernel
4. run current scanner adapters
5. dual-run pinned corpus
6. explain all differences
7. stress/scale evaluation
8. cut over downstream consumers
```

Performance success must be measured on representative workloads.

Microbenchmarks alone are insufficient.

## Stress architecture

Stress evaluation may generate very large variant sets.

Prefer streaming or bounded-batch processing where possible.

The engine should avoid retaining:

- every scanner raw output;
- every generated input simultaneously;
- redundant copies of fixture bytes.

Stress generation must remain attributable to an authored case or generation contract.

## Security

The evaluator processes secret-shaped data.

Rules:

- only safe synthetic/public-test inputs;
- raw scanner output is treated as sensitive;
- public artifacts contain normalized safe metadata;
- stdout/stderr are bounded and suppressed from public output;
- temporary materialization is cleaned up;
- scanner network behavior is explicit in adapter metadata;
- verification/network calls are off unless a test explicitly requires and authorizes them.

## Product qualification separation

The engine may produce facts such as:

```text
family X:
  20 positive cases
  20 benign controls
  19 covered
  1 partial
  0 false alarms
```

It must not conclude:

```text
family X is stable
```

That conclusion belongs to a consumer policy.

The Redact Secret product qualification layer currently remains with the Redact Secret benchmark/release tooling.

No new `redact-secret-qualification` repository is required by this architecture.

## Compatibility

During migration, compatibility exporters may produce legacy result schemas.

Compatibility code should be isolated and removable.

The generic internal model must not be permanently shaped around old Redact Secret benchmark JSON.

## Future use

A healthy architecture should allow:

```text
credential-eval run --scanner new-scanner
```

without modifying:

- credential-evidence schemas;
- Redact Secret;
- the evidence site;
- other scanner adapters.

That is the main extensibility test for this repository.
