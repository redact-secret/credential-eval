# Contributing

`credential-eval` is a scanner-neutral measurement engine. Read
`README.md`, `ARCHITECTURE.md`, and `CONVENTIONS.md` before proposing a change.

## Good contributions

- measurement-protocol tests and clarified semantics;
- scanner adapters that normalize findings without redefining scoring;
- deterministic corpus loading and fixture materialization;
- bounded orchestration, cancellation, and failure handling;
- mutation, metamorphic, twin, and benign-control evaluation;
- reproducible and sanitized result artifacts;
- performance improvements demonstrated on representative workloads;
- migration or compatibility work with explicit parity evidence.

Credential facts and expected semantic outcomes belong in
`credential-evidence`. Product support decisions belong in product-specific
qualification tooling. Public presentation belongs in
`credential-evidence-site`.

## Design first

Open an issue or design note before changing the outcome lattice, accounting,
input/output contracts, failure semantics, or adapter protocol. State the
measurement problem, whether semantics change, compatibility effects,
determinism/performance implications, and how correctness will be shown.

## Implementing a change

- Add tests at the narrowest stable boundary.
- Keep scanner-specific parsing inside the adapter.
- Distinguish scanner execution time from evaluator overhead.
- Make unavailable scanners, timeouts, malformed output, and partial runs
  explicit rather than silently treating them as misses.
- Avoid retaining unbounded raw outputs or generated inputs in memory.
- Do not add network verification unless a test explicitly requires and
  authorizes it.

## Pull requests

Describe the affected contract or component, tests run, compatibility impact,
and any performance evidence. A protocol change must be labeled as such and
must not be presented as a refactor. Do not include live credentials, matched
secret values, unsanitized logs, or unrelated generated artifacts.

The repository is in an early migration phase. Do not document commands,
directories, or stability guarantees until they exist in the tree.
