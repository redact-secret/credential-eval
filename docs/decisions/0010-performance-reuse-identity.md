# ADR 0010: Performance reuse identity, separate from accuracy

- Status: accepted
- Date: 2026-10-05
- Issue: #42 (parent: redact-secret-benchmarks#704; accuracy reuse is #40, ADR 0008)
- Amends: nothing frozen. Adds two optional fields to `SubjectIdentity` of the
  v1 `PerformanceArtifact` (`invocation_digest`, `role`; a minor revision under
  [ADR 0002](0002-performance-measurement-kinds.md)) and a `perf plan` command.
  The performance protocol (`credential-eval-performance/1`), the direction
  rules, A/B/A control, confirmation and every existing result field are unchanged.

## Context

Performance and accuracy are separate axes with separate invalidation. An
accuracy corpus release, a label or a policy change must not make anyone
re-measure a competitor's speed, and an unchanged scanner, workload and
protocol should not be re-measured at all. Nothing recorded *which* of a
measurement's inputs mattered, so every consumer had to rerun to be safe.

## Decision

1. **Cell identity.** A *cell* is one subject on one workload in one shape.
   Its `CellKey` (`credential_eval_perf::reuse`, identity version
   `credential-eval-performance-identity/1`) holds exactly:
   - the build and its invocation: executable digest, revision, version label,
     and `invocation_digest` (arguments, input delivery, scan-success exit
     codes: the activation and options, never the executable path);
   - the workload: generator id and version, workload id, units, input bytes
     and input digest, and the shape;
   - the kind, performance protocol and schedule (latency: rounds, batch,
     warm-up, and chunk size for the chunked shape; instructions: rounds);
   - the toolchain and instrumentation (rustc, valgrind, ...), the target
     (OS, architecture) and, for wall-clock latency only, the host class (CPU
     model and logical CPU count). Instruction and allocation counts are host
     independent in the target sense, so the CPU model is not part of them.
   Not in the key: the accuracy corpus, evidence release, labels, expectations,
   policy, the engine version, the subject's name, the consumer view, load
   averages and timestamps. They are provenance. Changing a field of the key
   (`IDENTITY_VERSION` included) is an explicit invalidation.
2. **Incomplete identity is never matched.** A key without an executable digest
   or invocation digest (external-process kinds), without a revision or
   toolchain (allocation), without a schedule, or, for latency, without a CPU
   model has no reusable cell. Artifacts written before this revision lack the
   invocation digest and the subjects' roles, so they are not reusable as
   independent cells.
3. **Evidence quality.** A stored cell is usable only if its run had no failed
   invocation and recorded every round (latency), or exact counts (instruction
   spread 0, repeats equal to the rounds, control equal to the baseline).
   An artifact whose results contradict its kind, or name a workload with no
   recorded identity, or that does not parse, is rejected whole and reported,
   never used. Identical content counts once.
4. **Pairwise conclusions are not per-subject cells.** A direction is a
   statement about two builds measured together. The engine therefore reuses a
   *comparison* only when a stored run measured exactly this pair, both cells
   unchanged (`reuse-comparison`):
   - latency: at least two independent stored runs (distinct content), usable,
     agreeing (`confirmed-faster`/`-slower`, or `no-evidence`), as `perf confirm`
     requires; one run, or disagreeing runs, is measured again with the missing
     independent runs (`insufficient-independent-runs`, `unconfirmed-evidence`);
   - instructions: one usable exact run, as before.
   Anything else is `measure-fresh` as a controlled same-run comparison (A/B/A
   for latency, then independent confirmation). A stored measurement of one
   unchanged subject is listed as `historical` with its artifact digest, date
   and host and `claim: none`: a view may show it as an independent, dated
   measurement, but the engine never turns it into a faster/slower claim
   against a new build, and never certifies a comparison that mixes origins.
5. **Dry-run planning.** `credential-eval perf plan --kind latency|instructions
   --config <c> --store <artifact-or-dir>... [--fresh-all] [--fresh <id>]...`
   hashes the executables, generates the workloads and prints a plan: per cell
   the decision, reason, `invalidated_by` (the key fields that differ from the
   nearest stored cell), the stored runs a reused comparison stands on, the
   fresh runs required and the process invocations they would launch, and
   the artifacts rejected as evidence. It launches no measurement process
   (instruction planning probes `valgrind --version`, as `perf instructions`
   does). `--fresh-all` and `--fresh <subject>` force a fresh controlled
   measurement. Nothing is cached or rewritten: the store is the set of
   artifacts the operator passes, content-addressed by their canonical digest,
   and each keeps its original host, date and engine version.
6. **Kinds stay separate.** Latency keeps its A/A control, noise rule and
   confirmation; instructions keep instrumentation (valgrind version) and
   build identity; allocation remains its own package with its own harness
   identity (toolchain, protocol, generator, source revision). `cells_of`
   already derives allocation cells; planning for it belongs to that package
   and is not exposed by `perf plan`.
7. **Accuracy telemetry is not evidence.** Elapsed times of `run`
   (issue #39) and the durations of reused observations (ADR 0008) are cost
   telemetry. `perf plan` reads only performance artifacts.

## Consequences

- Changing an accuracy fixture or expectation cannot invalidate a performance
  cell: neither is in the key, and `run` never starts a performance process.
- A new core build against the same baseline needs a new controlled
  comparison; the baseline's old timings stay visible, labeled as history.
- A latency result recorded without a CPU model (some containers) can be read
  but not reused.
- A cell matched across hosts of one model with a different CPU *count* is
  invalidated; this is deliberately stricter than `perf confirm`, which only
  records `same_cpu_model`.

## Verification

`crates/credential-eval-perf/src/reuse.rs` unit tests: unchanged confirmed pair
reuses with zero invocations; engine version and subject name are not
identity; one run and disagreeing runs are not results; a new candidate is
never certified from historical peers; workload bytes/digest, options,
executable, host class and schedule invalidate the affected cell; instruction
counts ignore host class; failed, truncated, pre-digest, kind-inconsistent and
exact-spread-violating evidence is never promoted; force-fresh; deterministic
planning; allocation cells.
`crates/credential-eval-cli/tests/perf_plan.rs`: end to end over real
artifacts, a scanner that records every launch proves planning launches none;
corrupt, foreign and duplicate files.
