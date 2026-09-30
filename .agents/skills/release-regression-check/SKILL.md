---
name: release-regression-check
description: Compare a pinned credential-eval candidate with a pinned baseline on the same evidence snapshot and scanner identities, producing a deterministic sanitized regression report. Use for evaluator release regression checks.
---

# Release regression check

Require immutable baseline and candidate revisions plus one evidence snapshot.
If scanner binaries, adapter versions, protocol version, or configuration
differ, report the comparison as confounded and stop unless the user explicitly
requests that experiment.

Run the repository's actual build and test commands from its manifests. Execute
both revisions with identical inputs and bounded settings. Compare normalized
per-case outcomes, failure states, aggregates, and artifact schemas. Also
compare evaluator overhead separately from scanner execution time.

Classify differences as semantic regression, intended protocol change,
serialization-only change, performance change, or unexplained. Re-run any
semantic difference to exclude nondeterminism.

The report must include all pinned identities, completeness/failure status,
changed case IDs without secret text, reconciliation totals, performance
conditions, and artifact locations. This skill supplies measurement evidence;
it does not approve a product release or assign support status.

