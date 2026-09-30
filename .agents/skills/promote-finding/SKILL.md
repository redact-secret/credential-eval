---
name: promote-finding
description: Turn a reproducible credential-eval observation into a well-scoped handoff to its owning repository without converting measurement into product policy. Use when asked to promote or escalate an evaluator finding.
---

# Promote a finding

A finding starts as a reproducible evaluator observation. Determine its owner
before changing anything:

- incorrect credential fact or expectation -> `credential-evidence`;
- scoring, normalization, adapter, orchestration, or artifact defect ->
  `credential-eval`;
- rendering or explanatory-copy defect -> `credential-evidence-site`;
- scanner implementation or product policy -> that product's repository.

Capture the evidence snapshot, protocol and engine versions, scanner/adapter
identity, run configuration, fixture/case IDs, expected and observed ranges,
and a sanitized minimal reproduction. Confirm the run completed and reproduce
once from pinned inputs.

Create or update only the local tracking artifact explicitly requested by the
user. The handoff must state what was measured, what remains interpretation,
and acceptance criteria for a rerun. Never include matched values or raw
scanner output, never change ground truth to fit the observation, and never
label a product stable or release-blocking from this workflow alone.

