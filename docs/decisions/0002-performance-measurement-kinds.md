# ADR 0002: Performance measurement kinds and where they live

- Status: accepted
- Issue: #23
- Scope: non-outcome measurements (latency, throughput, allocation request
  counts). Does not touch the four frozen v1 documents
  ([0001](0001-freeze-v1-contracts.md)) or the measurement protocol.

## Context

The Redact Secret core crates (`secret-scan-core`, `secret-scan-cli`) are
going to contain no `unsafe`, tooling included. The beta.13 perf cards
(#1121, #1131–#1135 in `redact-secret/redact-secret`) decided detector
changes with in-repo harnesses that must now leave the core crate. They
measured two different things:

1. latency/throughput of a scanner on a workload, whole-input and chunked;
2. allocation request counts inside the core, which need a counting
   `#[global_allocator]` linked into the process that runs the core.

`credential-eval` is scanner-neutral and today measures detection outcomes
(EXACT, COVERED, OVERBROAD, PARTIAL, MISS). These two kinds fit it
differently, so they are decided separately.

`redact-secret-benchmarks#608` closed on 2026-10-02 (PR #645). Its
disposition of the legacy credential evaluator classifies the performance
domain (`benchmarks/lib/performance-*.ts`, `scripts/measure-*`,
`scripts/*performance*`, the runtime and performance pages) as
**other-domain**: not part of that cutover, kept where it is, and not retired
or moved by it. Nothing in it is ported here. The measurement modes in this
record are new engine features, which is where new measurement work belongs.

## Decision

### 1. Latency/throughput is an engine measurement mode

Accepted and implemented as `credential-eval perf run`
([../performance-measurement.md](../performance-measurement.md)). It is scanner-neutral: it runs a scanner through an external-process
adapter on a generated synthetic workload, the same way the stress/scale class
does, and it needs nothing from the scanner's internals.

- **Design.** Alternating A/B batches against two pinned scanner builds, plus
  an A/A control of the same build against itself. Record minimum and median
  per workload, load average, toolchain and host. Report a direction
  (faster, slower, indistinguishable from the A/A noise band), never a frozen
  budget.
- **Workloads.** sparse vs dense invisible/Unicode normalization, overlap
  clusters, seam-heavy ranges, repeated short log lines, long single-line
  assignments, dense early-exhaustion. Inputs are synthetic, generated from a
  recorded generation contract, and bounded in size, count and duration.
- **Bounds.** Concurrency, batch count, subprocess output and per-run timeout
  all have explicit limits. Timed runs execute serially so that parallel
  scheduling cannot change the numbers; semantic ordering of the artifact does
  not depend on wall-clock results.
- **Kernel boundary.** The outcome lattice and accounting rules are not
  involved. Timing code stays out of outcome scoring.

### 2. Allocation request counting stays out of the neutral kernel

Allocation counting is scanner-specific: it needs a counting
`#[global_allocator]` linked into the process that runs the core. It must not
enter `credential-eval-kernel`, `credential-eval-contracts` or any neutral
adapter.

`unsafe` is acceptable in a measurement tool, but it is the last resort, not
the plan. The workspace sets `unsafe_code = "forbid"` (`Cargo.toml`), and this
decision keeps it:

- **No `unsafe` in this repository.** The global allocator is `stats_alloc`
  (`StatsAlloc` over the system allocator), exactly pinned. The `unsafe`
  `GlobalAlloc` implementation lives in that dependency, reviewed upstream and
  audited here like any other dependency; our package sets
  `unsafe_code = "forbid"`. Counters expose request counts and sizes only,
  never pointers or plaintext.
- **Counting semantics are matched, not assumed.** #1121 counted allocation
  *requests*. `requests = alloc_requests + realloc_requests`, with
  `alloc_zeroed` counted as an alloc and deallocation not counted, reproduces
  the #1121 baseline exactly on the generated fixtures (ordinary 18,451 →
  5,451, diverse 18,459 → 4,274, references 12,155 → 1,054 requests per 1,000
  assignments), asserted by a release test. `stats_alloc` reports a `realloc`
  as a size difference instead of the new size, so the byte columns are
  `allocated_bytes` and `realloc_net_bytes` rather than the old harness's single
  total. The request counts, the metric the cards use, are unaffected.
- **The fallback was not needed.** A reviewed hand-written allocator (one
  module, a documented safety argument, the only `unsafe` in the workspace)
  would have been the alternative had the crate failed to reproduce the
  baseline or the dependency audit. It remains the answer only if a later
  card needs the exact old byte total.

Shape: a separate package, `measurements/redact-secret-alloc`, with its own
workspace and lockfile, excluded from the neutral workspace. It links three
pinned core builds (the #1121 baseline, the PR #1136 merge and the PR #1150
merge) through their public API in one process, so a difference is the code.
The artifact kind is `allocation`. #608 did not decide this, so the choice is
this record's.

### 3. Public API only

Both kinds work through the scanner's public API or CLI. Where a card relied on
a crate-private helper, the isolated reproduction path is recorded as lost
instead of widening the core API.

### 4. Artifacts

- Performance results are a **new artifact kind**, `PerformanceArtifact`, with
  its own schema tag `credential-eval/performance-artifact/v1` and its own
  schema file. It is not part of the four frozen v1 documents, and no existing
  v1 schema changes. Adding it is a new document, not a v1 revision.
- It carries the full reproduction identity (engine, protocol, scanner A and B
  builds, adapter, configuration, workload generation contract and digest),
  load average and toolchain.
- It is sanitized: counts, sizes, timings and identities only. No matched
  values, no raw scanner output, no generated input text.
- The schema, the frozen-baseline test and the sanitization allowlist test
  from ADR 0001 apply to it from its first revision. Its input document,
  `PerformanceConfig` (`credential-eval/performance-config/v1`), is a second new
  document kind and is frozen the same way. Both baselines live next to the four
  of ADR 0001 in `tests/frozen-v1/`.
- The workload generator is a versioned contract (`WORKLOAD_CONTRACT_VERSION`);
  an artifact records each workload's id, units, size and SHA-256, never its
  text.

### 5. Re-measurement

#1131 (Azure) and #1135 (overlap DP) allocation counts were not measured in the
original PRs. They are measured end to end through the public API and recorded
in `docs/measurements/redact-secret-allocation-counts.json`, with the numbers in
[../performance-measurement.md](../performance-measurement.md) for attachment to
their evidence files. The isolated probes those cards used (`azure-probe`,
`overlap-probe`) reach crate-private functions, so they are recorded in the
artifact's `lost_paths` and not reproduced.

## Consequences

- The neutral kernel gains no `unsafe`, no allocator and no Redact
  Secret-specific code, and the workspace keeps `unsafe_code = "forbid"`
  everywhere, including the allocation package.
- Core-side cleanup (#1152) can ship: the #1121 numbers reproduce, #1131 and
  #1135 have allocation numbers, and the lost paths are recorded.
- Latency directions are produced on a quiet hosted runner by the manual
  `perf-latency` workflow, not on a developer machine. A busy host only widens
  the A/A band.
- A later card that needs a different workload adds a `WorkloadId`, which is an
  additive enum change in the frozen schemas and bumps
  `WORKLOAD_CONTRACT_VERSION` only if existing bytes change.

## Amendment: instruction counts (#26)

Wall-clock latency of per-invocation processes proved unreliable on shared
hosts: with identical executables, one hosted-runner run reported a direction
that a second run did not (#23, #25), and process startup swamps scan-time
differences. A third measurement kind, **instructions**, is accepted.

- **Evidence (feasibility, #26).** Under `valgrind --tool=callgrind` on hosted
  Linux runners, repeats of one build had a spread of exactly 0 on all 11
  workloads, and the `be5fee95` executable built and run on two different VMs
  gave identical counts for all 11. The directions matched the allocation
  results: #1121's assignment workloads fell 4.6% to 8.0% in instructions,
  #1131's duplicate-key workload fell to 22.7% of the baseline, and `azure-duplicate-keys`
  was unchanged for the #1121 pair, as expected. The same
  run showed `dense-invisible` +1.9% and `seam-heavy` +0.6% for the
  `be5fee95` to `ad877c03` pair, small but exact increases that no timing run
  could have resolved.
- **Where it lives.** The neutral engine, `credential-eval perf instructions`:
  it needs only an external process and valgrind, and nothing from the
  scanner's internals.
- **Artifact.** `MeasurementKind::Instructions` and
  `PerformanceArtifact.instructions` are additive, optional revisions of the
  frozen performance schema (ADR 0001 rules). The counts are part of the
  artifact's semantic digest because, unlike timings, they are reproducible.
- **Limits.** Instructions are a proxy for work, not for wall time. They are
  Linux-only (valgrind), whole-input only, and the direction floor is 0.1%.
  Latency stays as the reality check, quoted only when confirmed (#25).
