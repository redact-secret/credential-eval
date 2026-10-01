# Credential Identify Evaluation (Cieval)

A scanner-neutral credential evaluation engine focused on reproducibility, large-scale stress testing, and high-performance range evaluation.

`credential-eval` is being extracted from `redact-secret/redact-secret-benchmarks` and rebuilt around a high-performance Rust kernel and CLI.

The goal is not “benchmark Redact Secret.”

The goal is:

> Evaluate any credential scanner against versioned credential evidence using reproducible, inspectable measurement semantics.

## Core idea

```text
corpus snapshot (a credential-evidence release, or any other versioned corpus)
          +
scanner adapters
          ↓
    credential-eval
          ↓
normalized observations
          ↓
measurement artifacts (one per corpus)
```

The public `credential-evidence` snapshot is one input, not the only one. A
product may measure several separately identified corpora (the public
snapshot, its own regression, policy or protected corpora), each into its own
artifact, and combine them in its own policy. See
[docs/multi-corpus-qualification.md](docs/multi-corpus-qualification.md).

The engine does not decide whether a product is `stable`, `provisional`, `pending`, “better,” or release-ready.

It measures.

## What this repository owns

- scanner adapter interface;
- corpus loading and fixture materialization;
- scanner execution orchestration;
- normalized file/range findings;
- EXACT / COVERED / OVERBROAD / PARTIAL / MISS lattice;
- benign and false-alarm evaluation;
- twin discrimination;
- mutation evaluation;
- metamorphic evaluation;
- differential observations;
- accounting;
- bounded parallel execution;
- reproducible run manifests;
- sanitized public result artifacts;
- stress and scale evaluation.

## What it does not own

- canonical credential facts and expectations — `credential-evidence` for
  the public snapshot, the corpus author for any other corpus;
- which corpora a product qualifies against, and how their results are
  combined or counted;
- Redact Secret support policy;
- product release blockers;
- public site content;
- scanner marketing claims;
- independent ground truth.

## Why Rust

The existing TypeScript benchmark/evaluation engine has already proved the measurement model.

This migration is therefore an opportunity to optimize the hot path rather than only relocate it.

Target architecture:

```text
credential-eval
├─ Rust engine / CLI
│  ├─ corpus loader
│  ├─ materialization
│  ├─ process orchestration
│  ├─ range normalization
│  ├─ outcome lattice
│  ├─ accounting
│  ├─ mutation / metamorphic generation
│  ├─ bounded parallel execution
│  └─ result writer
│
├─ scanner adapters
│  ├─ external process adapters
│  ├─ Node/Python shims where useful
│  └─ native adapters where justified
│
└─ thin JS/TS tooling
   ├─ migration compatibility
   ├─ configuration
   └─ report/developer utilities
```

Rust is not the goal by itself.

The acceptance target is:

```text
same semantics
+ same normalized results
+ lower evaluator overhead
+ larger stress-test capacity
+ lower CI/time cost
```

## CLI direction

The command-line interface is not frozen (the v1 documents it reads and writes are). Today:

```bash
# Corpus measurement (per-case lattice, v1.1 group accounting)
credential-eval run --corpus snapshot.json --out artifact.json \
  --scanner redact-secret --scanner gitleaks --scanner trufflehog --jobs 12

# Evaluation methods over generated variants, with a differential reference
credential-eval run --corpus snapshot.json --out artifact.json \
  --scanner redact-secret --scanner gitleaks --scanner trufflehog --jobs 12 \
  --methods twin,benign,mutation,metamorphic,differential \
  --reference redact-secret --evidence evidence.json [--strict]
```

A run is reproducible from explicit input identities: the snapshot's corpus
digest, the config hash (scanners, limits, methods, reference, seed
convention, evidence digest, accounting) and each scanner's identity and
provenance, all recorded in the artifact.

`--run-class official` verifies the snapshot against a pinned evidence
release (`--evidence-release`, `--evidence-manifest`,
`--evidence-manifest-digest`) and every scanner against its `pin` in the run
configuration, and refuses to run (exit 4) on any mismatch. Runs are
`exploratory` by default. Every artifact records its run class and a derived
publication class, and only `public` artifacts may be consumed outside
product qualification. Local runs go to the gitignored `results/local/` and
are never published. See [docs/official-runs.md](docs/official-runs.md).
The committed official configuration of the public credential population is
`configs/official/credential-public-v1.json`, and
[docs/consumers/benchmarks-quickstart.md](docs/consumers/benchmarks-quickstart.md)
lists the exact steps `redact-secret-benchmarks` CI follows for an official run.

## Scanner adapters

A scanner does not have to be implemented in Rust.

Adapters may:

- invoke external binaries;
- launch Node/Python shims;
- call a package CLI;
- normalize structured scanner output.

The engine owns the adapter protocol and normalized result model.

The adapter owns scanner-specific execution and parsing.

## Measurement, not ranking

The engine should answer questions such as:

- was the required span fully covered?
- was only part of it covered?
- was the scanner overbroad?
- did a benign twin remain clean?
- how did a mutation change behavior?
- did two scanners disagree?

It should not collapse those observations into a single universal “best scanner” score.

## Performance and stress

The Rust kernel should make larger evaluations practical.

Target workload classes include:

- 10k+ cases;
- 100k+ mutations;
- Unicode and invisible-character perturbations;
- chunk-boundary sweeps;
- prefix/length/alphabet mutation matrices;
- large-file adversarial inputs;
- repeated short-input/log-line workloads;
- high detector-count ruleset scenarios;
- scanner timeout/failure pressure;
- multi-version differential evaluation.

Parallelism must remain bounded and deterministic.

## Migration

Current work is tracked under:

- #1 — migration epic
- #2 — input/output contracts
- #3 — lattice/accounting/evaluation extraction
- #4 — scanner adapter API
- #5 — legacy dual-run parity
- #6 — product qualification separation
- #7 — high-performance Rust CLI/kernel

The current TypeScript engine remains the behavioral oracle until parity is proven.

## Relationship to Redact Secret

Redact Secret is one scanner that can be evaluated by this engine.

Product-specific qualification remains outside the generic evaluator.

```text
credential-eval run artifacts (public evidence, product regression, policy, protected ...)
        ↓
Redact Secret qualification policy (combines and counts per population)
        ↓
support matrix / release decision
```

That interpretation currently remains in the Redact Secret benchmark/product qualification layer.
Evidence class, scanner behavior and support status are separate axes: the
engine copies a case's evidence class as a label, measures every case with
the same protocol, and never emits a support status.

[docs/qualification-boundary.md](docs/qualification-boundary.md) lists the
policy that stays outside this repository and defines the consumer API: the
schema-validated run artifact, nothing else.
[docs/multi-corpus-qualification.md](docs/multi-corpus-qualification.md)
defines qualification over several corpora and the consumer contract for
combining their artifacts.
[docs/migration/redact-secret-cutover.md](docs/migration/redact-secret-cutover.md)
is the plan for the Redact Secret tooling to consume it.
`examples/qualification-consumer/` is a dependency-free reference consumer
with an illustrative toy policy.

## Status

The repository is private and in its migration and architecture phase.

What exists today:

- The v1 input/output contracts (#2), with their Rust types and generated
  JSON Schemas, frozen by ADR 0001 (#13).
- The measurement kernel (#3): lattice, v1.1 accounting, twin, benign,
  mutation, metamorphic and differential methods, and the review queue.
- Scanner adapters (#4) for Gitleaks, TruffleHog, Redact Secret,
  flare-redact and OpenRedaction, ported from the legacy adapters, and a
  `credential-eval run` command with bounded parallel execution
  ([docs/adapters.md](docs/adapters.md)). `run --methods ...` runs the
  evaluation methods end to end.
- Dual-run parity with the legacy TypeScript engine on the pinned legacy
  corpus (#5): [docs/parity/parity-report.md](docs/parity/parity-report.md).
  The legacy exporter, the compatibility writers and the comparator are
  migration-only and removable (`tools/legacy-export/`, `tools/parity/`,
  `crates/credential-eval-compat/`).

The v1 schemas are frozen
([ADR 0001](docs/decisions/0001-freeze-v1-contracts.md)): v1 never changes
incompatibly, new optional fields are minor revisions, and a breaking change
is v2. Build on the documents and their schemas, not on the internal crate
APIs, which are not a contract.

## Layout

```text
Cargo.toml                         Cargo workspace
crates/
  credential-eval-contracts/       serde types for every input/output document; schema generation
  credential-eval-kernel/          measurement kernel: lattice, accounting, methods, review queue
  credential-eval-adapters/        scanner adapters: execution, provenance, normalization
  credential-eval-cli/             `credential-eval` binary and run orchestration
  credential-eval-compat/          migration-only legacy validators and legacy result writers (removable)
adapters/node/                     Node shim + pinned npm scanner packages (npm ci --ignore-scripts)
schemas/                           generated JSON Schemas (*-v1.schema.json)
configs/official/                  committed official run configurations (pinned scanners, per platform)
docs/contracts/                    contract, range, identity, outcome and determinism rules
docs/decisions/                    architecture decision records (ADR 0001: v1 contract freeze)
docs/adapters.md                   adapter protocol, built-in adapters, adding a scanner
docs/official-runs.md              official vs exploratory runs, evidence release, pins, publication class
docs/consumers/benchmarks-quickstart.md  the official-run steps redact-secret-benchmarks CI follows
docs/multi-corpus-qualification.md one artifact per corpus; consumer contract for combining artifacts
docs/migration/legacy-map.md       inventory of the legacy TypeScript engine
docs/migration/redact-secret-cutover.md  handoff plan for Redact Secret tooling
docs/parity/                       dual-run parity report and sanitized summary (#5)
docs/qualification-boundary.md     what stays outside the engine; the consumer API
examples/qualification-consumer/   reference artifact consumer (Node 22, toy policy)
tools/legacy-export/               migration-only legacy corpus exporter (tsx, imports the pinned legacy TS)
tools/parity/                      migration-only parity comparator, run script and parity run config
tests/fixtures/contracts-smoke/    synthetic end-to-end fixtures and golden run artifact
```

## Development

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

`cargo test` also checks that `schemas/` still matches the contract types,
that the schemas stay compatible with the frozen v1 baselines in
`crates/credential-eval-contracts/tests/frozen-v1/` (ADR 0001), and that no
schema property can carry matched values or raw scanner output. It also
checks the golden artifact in `tests/fixtures/contracts-smoke/`. After an
intentional contract change, regenerate both and review the diff:

```bash
UPDATE_SCHEMAS=1 cargo test -p credential-eval-contracts --test schema_drift
UPDATE_GOLDEN=1 cargo test -p credential-eval-kernel --test contracts_smoke
```

The real-scanner integration test is skipped unless enabled. It needs
Gitleaks 8.30.1 and TruffleHog 3.97.4 first on `PATH` and the Node shim
packages installed (`cd adapters/node && npm ci --ignore-scripts`):

```bash
CREDENTIAL_EVAL_REAL_SCANNERS=1 cargo test -p credential-eval-cli --test real_scanners -- --nocapture
```

