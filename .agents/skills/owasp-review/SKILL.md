---
name: owasp-review
description: Review credential-eval's corpus ingestion, scanner orchestration, adapters, and result publication against applicable OWASP guidance. Use for an OWASP or secure-design review. Read-only.
---

# OWASP review

Review this evaluator's attack surface, not scanner detection quality. Begin
with `README.md`, `ARCHITECTURE.md`, `SECURITY.md`, and the scoped code.

Cover applicable controls for untrusted input validation, path containment,
command/argument construction, archive extraction, temporary files, resource
limits, error handling, log redaction, artifact integrity, dependency
provenance, and CI permissions. Pay special attention to adapters that execute
external binaries and parsers that consume scanner-controlled output.

For each applicable control report `pass`, `fail`, or `not assessable`,
with a file/line reference and concrete evidence. Documented design intent is
not implementation evidence. Treat intentionally offline synthetic evaluation
as reducing exposure, not eliminating the need for containment and bounds.

Do not modify code or reinterpret measurement outcomes.

