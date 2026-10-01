# Agent instructions

@\~/.codex/RTK.md

Read `README.md` and `ARCHITECTURE.md` before changing this repository. They
define the repository boundary and take precedence over inherited conventions
or assumptions from predecessor repositories.

## Repository boundary

`credential-eval` measures scanner behavior. It consumes versioned corpus
snapshots (public `credential-evidence` releases or separately identified
product-owned corpora, one population per run), runs scanners through
adapters, normalizes file/range findings, applies the measurement protocol,
and emits reproducible artifacts. See `docs/multi-corpus-qualification.md`.

This repository does not own credential truth, Redact Secret support status,
release policy, public-site content, or scanner rankings. Never change an
expected result merely to match a scanner's output.

## Working rules

- Preserve scanner neutrality. Product-specific behavior belongs in an adapter
  or downstream qualification policy, not the measurement kernel.
- Treat the outcome lattice and accounting rules as protocol semantics.
  Refactors must preserve them; intentional changes require an explicit,
  reviewed protocol revision.
- Keep execution bounded: concurrency, subprocess output, timeouts, buffers,
  and generated variants must all have explicit limits.
- Keep results deterministic. Parallel scheduling may not alter semantic
  output ordering or aggregate results.
- Record all identities needed for reproduction: engine, protocol, evidence
  snapshot, scanner, adapter, configuration, and corpus digest.
- Use only synthetic or documented public-test credential material. Never log
  matched values or copy raw scanner output into public artifacts.
- Keep compatibility code isolated and removable. Do not shape the canonical
  model around a legacy benchmark schema.

## Work discipline

- Before proposing any command that takes more than five minutes, read and
  validate its inputs first. If validation costs two orders of magnitude less
  than the run, always validate first.
- In test and verification work, separate what is being measured from what
  inputs it needs. Inputs must be the smallest size that still satisfies the
  measurement.
- Do not assume that choosing among existing assets (issues, branches, files)
  is the only option. If creating something new is cheaper, propose that
  first.
- When challenged, answer the objection actually raised, not an easier one.
- Before benchmark measurements check that `trufflehog --version` matches the pin(3.97.4). A self-update that bumps only the patch version changes the stable count. If it differs, do not report the numbers; put the pinned binary first on `PATH` and rerun.
  Always state the mode (published or candidate) alongside a stable count.

## Before finishing

Run the repository's documented format, lint, test, schema, and parity checks
that exist at the time of the change. If the implementation is not present yet,
say which checks could not run instead of inventing commands. For changes to
scoring, normalization, accounting, or serialization, add focused tests and
verify deterministic output across repeated runs where practical.

## Local skills

Repository-specific workflows live in `.agents/skills/`. Security-review
skills inspect this evaluator's own attack surface; they do not assess whether
any scanner is good or bad.
