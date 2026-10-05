# ADR 0007: Per-scanner timings and bounded progress for long runs

- Status: accepted
- Date: 2026-10-04
- Issue: #39 (parent: redact-secret-benchmarks#704)
- Amends: nothing frozen. Adds optional fields inside `non_semantic.execution` of a v1 run artifact (revision v1.5, [ADR 0001](0001-freeze-v1-contracts.md)). The measurement protocol (`credential-eval-protocol/1`), scoring and every semantic field are unchanged.

## Context

A five-scanner plain or methods run showed one number for scanner time and one
for evaluator time, and nothing on stderr until it finished. A slow run could
not be told apart from a hung one, and "OpenRedaction is slow" was assumed
rather than shown: queueing, the process, stdout transfer, parsing, variant
generation and evaluation were all folded together.

## Decision

1. **Record phases and scanners separately, in `non_semantic.execution`.**
   `phases` (materialize, generate, prepare, scan, evaluate, with case and
   fixture counts) and `scanners.<id>` (prepare, queue, start/end offsets,
   process, normalize, tasks, fixtures, received bytes, findings, completion,
   `failed_phase`). Stdout transfer is part of `process_ms`: the pipe is
   drained concurrently with the process, so it cannot be timed apart without
   a second clock that would not mean anything.
2. **Emit bounded progress to stderr.** One `progress ...` line per phase
   boundary and per scan task start/end, plus one heartbeat per running task
   every `--progress-interval` seconds (default 10). Lines are fixed
   vocabulary and numbers; scanner stdout/stderr, fixture text and matched
   values cannot reach them. stdout is unchanged.
3. **Keep it out of the semantic digest.** Everything above sits in
   `NonSemantic`, which `semantic_digest()` clears. The engine version moves to
   `0.1.0-alpha.6` and the contract revision to 1.5; both are identity, so the
   digest of a replay under alpha.6 differs from alpha.5 only by that.
4. **Serialization is reported on stderr, not in the artifact.** It happens
   after the artifact exists; writing a measurement of it into the artifact
   would mean serializing twice.

## Consumers

- Readers that deserialize `non_semantic.execution` strictly (the schema has
  `additionalProperties: false`) must accept `phases` and `scanners`. The
  Rust types here do; the committed `run-artifact-v1` schema is regenerated.
- Anything parsing stderr should treat `progress ...` lines as a separate,
  additive stream; existing lines (`semantic digest ...`, per-scanner status)
  are unchanged. `--no-progress` restores the previous stderr.

## Verification

`crates/credential-eval-cli/tests/progress.rs` drives slow, hung, garbled and
missing fake scanners: phases and `failed_phase` are named, heartbeats appear
during a slow scan, volume stays bounded, lines carry no fixture text or
values, and two runs with different timings and job counts share one semantic
digest. `tests/methods.rs` checks `generate_ms`, `fixtures` and per-scanner
sizes on a methods run.
