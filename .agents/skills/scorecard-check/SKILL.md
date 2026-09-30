---
name: scorecard-check
description: Run OpenSSF Scorecard for redact-secret/credential-eval and translate low scores into repository-specific supply-chain actions. Use for supply-chain posture reviews. Report-only.
---

# Scorecard check

Run Scorecard against `github.com/redact-secret/credential-eval` with the
required authentication. Record Scorecard version, date, repository revision,
and whether the repository is public enough for each check to be meaningful.

For every below-target result, inspect the actual repository evidence. Focus on
pinned CI actions, least-privilege workflow permissions, branch protection,
review requirements, dependency update practice, SAST, fuzzing for parsers and
range logic, release provenance, signed artifacts, and maintained status.

Distinguish controls that are not yet applicable because the repository has no
release or workflow from actual failures. Route dependency findings to
`dependency-audit`, code-analysis gaps to `sast-sweep`, and executable
security hypotheses to `vulnerability-test`.

Do not change settings or fabricate scores when the tool or access is missing.

