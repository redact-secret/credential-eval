# ADR 0003: An unmappable finding leaves its case unmeasured

- Status: accepted
- Date: 2026-10-03
- Issue: redact-secret-benchmarks#680 (official run of `snapshot-2026.10.04`), related credential-eval#34 and credential-evidence#150
- Amends: nothing frozen. Adds optional fields to two v1 documents (a minor revision, [ADR 0001](0001-freeze-v1-contracts.md))

## Context

The official plain run of the public population over `snapshot-2026.10.04`
(6,449 cases) failed for Gitleaks 8.30.1: `Malformed - scanner output could not
be mapped to ranges: Unsupported decoded Gitleaks finding`, exit 3 under
`--require-complete`, no artifact accepted. The other two populations were fine.

An adapter that cannot map one finding fails closed, and the only state the
engine had for that was the whole scanner: one unmappable row made all 6,449
cases `not_measured`. Re-running the real adapter over the real snapshot with
the failing rows attributed to their fixtures shows what they are. Ten fixtures
are affected, none with a detection the adapter could place:

| Fixtures | Tier | Why Gitleaks reports them | Adapter message |
| --- | --- | --- | --- |
| 4 of `base64-hex-representation-projections` | T0 (not-assertable) | decoded finding at depth 2 or 3 (nested layers) | Unsupported decoded Gitleaks finding |
| 5 of `base64-hex-representation-projections` | T0 (not-assertable) | hex-encoded value: the finding's secret is the decoded text, absent from the file | Ambiguous or unmappable scanner finding |
| `structured-credential-files-authored/kubeconfig-client-key-data-encoded-pem` | T1 must-redact | a base64 PEM inside a base64 value, decoded at depth 2 | Unsupported decoded Gitleaks finding |

Nine are representation-dependent cases that credential-evidence exports as
pending (T0). The tenth is an authored raw-input case in the TP/FN population.
Taking the nine out of the snapshot would not unblock the run and would not be
honest about the tenth: the failure is the adapter's inability to place a
decoded finding, not a property of the evidence.

## Decision

1. **The unit of "could not be measured" is the case, when the run says so.**
   An adapter may report a finding it cannot map as the fixture it is in being
   *unmeasured*, instead of failing the scanner. The fixture's findings are all
   discarded, so it can never read as a zero detection.
2. **It is a deliberate, hashed choice.** The Gitleaks adapter takes an optional
   scanner configuration key `unmappable_findings`: absent or `"fail"` keeps
   the old behavior; `"unmeasured-case"` enables 1. The key is part of the
   scanner configuration, so it is part of `config_hash`. The two official
   configurations set it for Gitleaks. Other adapters do not implement it and
   still fail closed.
3. **It never hides a case.** The attribution is conservative: only a row whose
   `File` resolves to a known fixture is attributed; an unparseable report or an
   unknown path still makes the scanner `malformed`. The observation records
   each unmeasured path with the adapter's fixed reason (`complete.unmeasured[]`),
   the artifact records each unmeasured case (`scanners[].unmeasured_cases[]`),
   each such case is `not_measured` in `cases[]`, and the run prints
   `N of M cases could not be mapped to ranges and are in no denominator`.
   Unmeasured cases are in no group, target or denominator (not a TP, FN, FP or
   TN, and not a pending T0 case either). Replays must agree on the unmeasured
   set, or the scanner is `unstable`.
4. **`--require-complete` keeps its meaning** (every scanner is `complete`), and
   a new `--require-fully-measured` exits 3 when any scanner left a case
   unmeasured, so a consumer can choose either gate.
5. **Evaluation methods do not read it.** Methods score whole scanners, not
   single fixtures. A scanner that reports unmeasured paths in a methods run is
   `malformed` for that run, as before. Per-case handling for methods is a
   separate protocol decision.
6. **Scope is unchanged.** The raw-input scope is kept: nothing here maps a
   decoded finding to a range or claims that decoded or fragment semantics were
   measured. Mapping them is credential-eval#34.

## Consequences

- The Gitleaks plain run over `snapshot-2026.10.04` completes with 10 cases
  unmeasured (9 T0, 1 T1) and `--require-complete` passes. One T1 case is out of
  Gitleaks's denominator; a consumer must show that count next to the result.
- `adapter.version` stays `"2"`: with the key absent, output is byte for byte
  what it was. The new key changes `config_hash`, which is where the policy is
  recorded.
- The schemas gain the optional fields listed under v1.2 in
  [../contracts/README.md](../contracts/README.md). Readers pin the engine
  version that writes them (ADR 0001, "Reader guidance").
- credential-evidence needs no new release for this decision.
