# Reference qualification consumer

This directory shows how a downstream qualification tool consumes
credential-eval output. It reads a run artifact, validates it against
`schemas/run-artifact-v1.schema.json`, builds the per-family view from
[docs/qualification-boundary.md](../../docs/qualification-boundary.md) §4.1,
and applies a policy loaded from a separate file.

> **The policy here is an illustrative toy.** It is not the Redact Secret
> support policy, not a release policy and not a recommendation. Its labels
> (`toy-meets-bar`, `toy-below-bar`, `toy-no-scored-evidence`,
> `toy-not-measured`) and thresholds are arbitrary. The real Redact Secret
> policy stays in `redact-secret-benchmarks`.

It needs Node 22 and nothing else: no npm install, and no import from any
credential-eval crate.

```bash
node examples/qualification-consumer/consume.mjs \
  --artifact tests/fixtures/contracts-smoke/expected-run-artifact.json \
  --policy examples/qualification-consumer/toy-policy.json

node --test examples/qualification-consumer/consumer.test.mjs
```

| File | Role |
|---|---|
| `consume.mjs` | CLI: schema tag check, schema validation, family view, policy, report on stdout |
| `validate.mjs` | Small JSON Schema validator for the keywords the generated schemas use; unknown keywords fail |
| `family-view.mjs` | The per-scanner, per-family projection; it counts engine measurements and never re-scores |
| `toy-policy.mjs`, `toy-policy.json` | The toy policy logic and its thresholds |
| `consumer.test.mjs` | Shows that changing the policy file changes verdicts while the artifact and view stay identical |
