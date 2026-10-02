# Performance measurement

`credential-eval` measures two things that are not detection outcomes
([ADR 0002](decisions/0002-performance-measurement-kinds.md)). Both write a
`PerformanceArtifact` (`schemas/performance-artifact-v1.schema.json`), a
document kind of its own. It does not change any of the four documents of
[ADR 0001](decisions/0001-freeze-v1-contracts.md), and it is frozen from its
first revision in the same way (`tests/frozen-v1/`).

| Kind | What it measures | Where it lives | `unsafe` |
|---|---|---|---|
| **latency** | wall time of an external-process scanner on a synthetic workload, whole-input and chunked, as an A/B direction | the neutral engine: `credential-eval perf run` | none |
| **allocation** | allocation requests of in-process scanner builds on the same workloads | a separate package, `measurements/redact-secret-alloc/` | none (the counting allocator is the pinned crate `stats_alloc`) |
| **instructions** | executed instructions of an external-process scanner under `valgrind --tool=callgrind`, a deterministic proxy for scan cost | the neutral engine: `credential-eval perf instructions` | none |

None produces a score, a budget or a ranking. Latency reports a **direction**
(and only a `confirmed` one is a result); allocation reports **counts**;
instructions report **exact counts and a direction** that is a function of the
counts alone.

**Which to use.** Wall-clock latency of per-invocation processes is noisy on
shared hosts and cannot resolve scan-time differences below process startup
(~3 ms on a hosted runner). Instruction counts are exact and reproduce bit for
bit across machines, so they are the primary timing proxy; latency is the
check that the proxy matches reality, and it is only quoted when confirmed.

## Workloads

All inputs are synthetic and generated (`crates/credential-eval-perf`,
`workloads::generate`), deterministic for a given `(id, units)`, and bounded:
generation stops and the run is refused when the input would exceed
`limits.max_input_bytes`. An artifact records each workload's `id`, `units`,
`bytes` and `sha256` digest, never its text. A generator change bumps
`WORKLOAD_CONTRACT_VERSION`.

| Workload | A unit is | What it exercises |
|---|---|---|
| `sparse-unicode`, `dense-unicode` | a line | UTF-8 normalization with one, or on every, non-ASCII line |
| `sparse-invisible`, `dense-invisible` | a line | one, or many, zero-width characters |
| `overlap-clusters` | a line | assignments whose value is also a standalone token shape |
| `seam-heavy` | a secret-bearing line | invisible characters inside the value, so every range crosses a seam |
| `repeated-short-log-lines` | a line | the same short log line repeated |
| `long-single-line-assignments` | an 8 KiB assignment | very long single lines |
| `dense-early-exhaustion` | an assignment | a dense burst at the start of the input, then benign lines |
| `assignments-ordinary`, `-diverse`, `-references` | an assignment | the #1121 fixtures (seeds 1, 7, 11), byte for byte |
| `otp-dense`, `otp-sparse` | a URI / a padding line | the #1145 fixtures (seed 13) |
| `azure-single`, `-repeated-records`, `-duplicate-keys`, `-benign` | one record / a record / a repeated field / a log line | the #1131 storage connection strings |
| `overlap-disjoint`, `-sparse`, `-pairs`, `-dense` | a line | end-to-end proxies for the #1135 overlap cases (see "Lost paths") |

## Latency: `credential-eval perf run`

```bash
credential-eval perf run --config performance-config.json --out performance-artifact.json
```

The configuration (`credential-eval/performance-config/v1`) names two
subjects (an executable, its arguments, how it receives input, the exit codes
that mean "scanned"), the workloads, the shapes, and every bound. See
`configs/performance/redact-secret-latency.template.json`.

**Protocol.** Per workload and shape: an untimed warm-up of both builds, then
`rounds` rounds. Each round runs three arms, one batch each: the baseline (A),
the candidate (B) and the baseline again as the **A/A control**. The arm order
rotates every round, so each arm takes each position and drifting host load
cannot favour one build. A batch is `batch_invocations` passes over the
workload; a pass is one process (`whole`) or one process per chunk of at most
`chunk_bytes`, split at line boundaries (`chunked`). A sample is the summed
spawn-to-reap time of the passes' processes, per pass. Generation, file
writes and bookkeeping are outside the clock. Scheduling is serial.

**Direction.** The noise band is the larger of the A/A control's median and
minimum deviation from the baseline and a 5% floor. The candidate is `faster`
(or `slower`) only when its median **and** its minimum both clear the band in
that direction **and** it beat its own round's baseline in at least 80% of the
rounds (a transient load spike moves a few rounds, not most of them).
Everything else is `indistinguishable`, and so is any result with a failed
invocation. The artifact keeps every sample, the minimum and the
median per arm, both ratios and the band.

**Confirmed directions.** A direction from one run is not a result. The A/A
control sees the noise inside a run, not what changes between runs (neighbouring
VMs, a different CPU generation), and two runs of identical executables on
hosted runners have disagreed. `credential-eval perf confirm --artifact A
--artifact B --out confirmation.json` combines independent runs of one
configuration (it refuses different configurations, subjects, workloads or
cells, and the same artifact twice) into a `DirectionConfirmation`
(`credential-eval/direction-confirmation/v1`):

| Status | Meaning |
|---|---|
| `confirmed-faster` / `confirmed-slower` | every run reported that direction |
| `unconfirmed` | the runs disagree, or only some reported a direction: not a result |
| `no-evidence` | every run was `indistinguishable`: the measurement could not resolve a difference, which is not the same as no difference |

The confirmation records `same_cpu_model` (hosted runners of one name mix CPU
generations; directions from different models are less comparable) and does not
depend on the order of its inputs. Quote a latency direction only when it is
`confirmed-*`. The `perf-latency` workflow runs the measurement as two
independent jobs (separate VMs) and a third job runs `perf confirm`.

**Identity.** The artifact records both executables' SHA-256 (and refuses the
run when a configured pin does not match), the source revisions, the config
hash, the toolchain, the load average before and after, CPU model (sanitized, when the host reports
one) and count, OS and
architecture. Never paths, user names or host names.

**Bounds.** `rounds` 3–200, `batch_invocations` 1–100, `warmup_invocations`
at most 20, at most 32 workloads, input at most 16 MiB, at most 200,000
process invocations per run (counted before anything starts), a timeout and a
response and diagnostic cap on every invocation. A configuration beyond them
exits 2; a pin mismatch exits 4; a workload over its limit exits 1. Nothing is
written in any of those cases. Scanner output is read up to its cap and
dropped.

**Where to run it.** A quiet host is part of the protocol. A busy developer
machine widens the A/A band until nothing is distinguishable, which is the
rule working, not a result. The `perf-latency` workflow
(`.github/workflows/perf-latency.yml`, manual dispatch) builds two pinned
Redact Secret CLI commits on a hosted runner, fills the template and uploads
the artifact:

```bash
gh workflow run perf-latency.yml \
  -f baseline_revision=be5fee9597311ee01cb33bcdc5c064d5cbb667ff \
  -f candidate_revision=ad877c036825a926f93478c2104e675d9c301326
```

## Instructions: `credential-eval perf instructions`

```bash
credential-eval perf instructions --config performance-config.json \
  --out performance-artifact.json [--valgrind /path/to/valgrind]
```

Each subject runs under `valgrind --tool=callgrind` on every workload, `rounds`
times as the baseline, the candidate and the baseline again (control), plus
`rounds` runs on an empty input per subject to measure process startup. The
count is the `summary:` total of callgrind's output header (the `Ir` event).
`net = min(counts) - startup`, and the **direction** compares the two builds'
net counts: faster or slower when `candidate.net / baseline.net` leaves the
band of the largest spread, the control's difference and a 0.1% floor,
`indistinguishable` otherwise, and `indistinguishable` for any failed
invocation. Whole-input only; `batch_invocations` and `warmup_invocations` are
not used. The configuration is the same document as for latency
(`configs/performance/redact-secret-instructions.template.json`).

Counts are exact on a deterministic build, so the spread is 0 and a single run
is a result, with no confirmation step. In the feasibility run (#26) the same
executable gave identical counts across repeats and on two different hosted
VMs for all 11 workloads. Instruction counts are a **proxy**: fewer
instructions do not guarantee less wall time (cache and branch behaviour), so a
direction here is a statement about executed work. Run it on Linux
(`perf-instructions` workflow); valgrind is not a macOS arm64 target.

Bounds are those of the latency mode, applied to `5 x rounds` invocations per
workload (counted before anything starts), with the per-invocation timeout of
the configuration (callgrind runs a scan about 50x slower). The callgrind file
is read up to 64 KiB of header and deleted; it is never published.

## Allocation: `measurements/redact-secret-alloc`

```bash
cd measurements/redact-secret-alloc
cargo test --release            # counting semantics + the #1121 baseline gate
cargo run --release -- --out allocation-counts.json
```

It is a separate package with its own workspace and lockfile because it links
a scanner core. Three pinned core builds are dependencies under renamed keys
(`core_before`, `core_mid`, `core_after`), driven only through the public API
(`DetectorRegistry`, `DefaultPolicy`, `scan`) in one process on the same
generated inputs, so every difference is the code. Each scan is run once to
warm lazily initialised statics and counted on the second.

The process allocator is `stats_alloc` over the system allocator. The package
contains no `unsafe` and sets `unsafe_code = "forbid"`; the one `GlobalAlloc`
implementation is the pinned third-party crate's. Counters hold request
counts and sizes, never a pointer or the bytes of an allocation, and the
artifact records a findings digest, never a finding.

**Counting semantics** match #1121's harness: `requests = alloc_requests +
realloc_requests`, with `alloc_zeroed` counted as an alloc and deallocation
not counted. `stats_alloc` reports a `realloc` as a size difference instead of
the new size, so the byte columns differ from the old harness's single total:
`allocated_bytes` is fresh requests plus realloc growth, and
`realloc_net_bytes` is the signed net of reallocs. The request counts, which
the cards use as their metric, have the same meaning, and the test
`tests/baseline.rs` asserts the #1121 numbers exactly:

| fixture (per 1,000 assignments) | before | after |
|---|---:|---:|
| ordinary | 18,451 | 5,451 |
| diverse | 18,459 | 4,274 |
| references | 12,155 | 1,054 |

Counts are deterministic: repeated runs give identical counters. They are
defined for release builds (debug builds do not elide the same temporaries),
as in the card.

### Results

Builds: `44382b3f` (baseline of #1121), `be5fee95` (PR #1136 merge, cards
#1121–#1130) and `ad877c03` (PR #1150 merge, cards #1131–#1135). Recorded in
[measurements/redact-secret-allocation-counts.json](measurements/redact-secret-allocation-counts.json)
(rustc and LLVM versions, host and generator version are in its manifest).
Every row returned identical findings in both builds.

| Card | Workload | Requests, before → after | Bytes requested, before → after |
|---|---|---|---|
| #1121 | `assignments-ordinary` | 18,451 → 5,451 (−13,000) | 1,175,960 → 567,960 |
| #1121 | `assignments-diverse` | 18,459 → 4,274 (−14,185) | 1,178,165 → 504,900 |
| #1121 | `assignments-references` | 12,155 → 1,054 (−11,101) | 661,657 → 148,715 |
| #1131 | `azure-single` | 17 → 16 (−1) | 4,702 → 4,542 |
| #1131 | `azure-repeated-records` (100 records) | 636 → 536 (−100) | 79,832 → 63,832 |
| #1131 | `azure-duplicate-keys` (100 repeats) | 966 → 402 (−564) | 524,464 → 43,184 |
| #1131 | `azure-benign` | 3 → 3 (0) | 2,944 → 2,944 |
| #1135 | `overlap-disjoint` | 5,081 → 5,081 (0) | 3,309,576 → 3,309,576 |
| #1135 | `overlap-sparse` | 5,090 → 5,090 (0) | 3,840,153 → 3,355,352 |
| #1135 | `overlap-pairs` | 20,106 → 20,106 (0) | 5,879,044 → 4,909,340 |
| #1135 | `overlap-dense` | 30,107 → 30,107 (0) | 10,637,792 → 8,698,184 |

Reading them:

- **#1121 reproduces exactly** from the pinned commits, through the public API
  and with no `unsafe` in this repository.
- **#1131** shows the card's shape. The duplicate-key case, the one the card
  targets, falls from 966 to 402 requests (the card's isolated probe saw 946 →
  382; the 20 requests of difference are the rest of the scan). The ordinary
  cases move by one request per record, and the benign case does not move.
  These end-to-end counts are the allocation numbers to attach to #1131's
  evidence file.
- **#1135** adds no allocation requests. PR #1150 adopted a reworked form of
  the card's partitioning (independent components over one reused table
  workspace, no per-cluster allocation) after the card rejected the first
  prototype: its `pairs` case rose from 5 to 15,003 requests because every
  component built its own tables. End to end, the request counts are identical
  for `disjoint`, `sparse`, `pairs` and `dense` before and after (the bytes
  fall with the other cards of the same PR), so the adopted form does not
  reintroduce per-cluster allocation. The isolated probe is lost (below), so
  these are proxies: they bound the allocation cost of the adopted form but do
  not reproduce the card's 5 → 9 and 5 → 15,003 isolated figures.

## Lost paths

Cards #1131 and #1135 measured crate-private functions through exported probe
hooks (`azure-probe`, `overlap-probe`). Reproducing that would mean widening
the core's public API, which the issue forbids. They are recorded in the
artifact's `lost_paths` (`reason: crate-private-helper`) and measured
end-to-end through `scan` instead. The overlap workloads create competing
candidates with public input only: a bare token is claimed by one detector,
and a token inside an assignment is claimed by that detector and by the generic
assignment detector.

## Reproduction

Everything needed is in the manifest: engine and performance protocol
versions, the workload generator version, each subject's version, source
revision (and executable digest for latency), the config hash, the toolchain
and the host. Artifacts differ between runs only in `non_semantic` and in the
latency timings; `PerformanceArtifact::semantic_digest` ignores exactly those.

## Public tracker coordination

The core-side cleanup (`redact-secret#1152`) can ship once the numbers above
are accepted: step 5 of that card deletes `examples/alloc_attribution.rs` and
its five baseline entries, step 6 repoints the evidence READMEs of #1121,
#1131, #1133, #1134 and #1135 at this harness, and step 7 amends
`docs/rust-workspace.md`. The `perf-latency` workflow produces the timing
direction for each card from pinned commits on a quiet runner.
