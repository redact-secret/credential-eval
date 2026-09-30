---
name: sast-sweep
description: Run static analysis over credential-eval's Rust and optional JS/TS code, focused on unsafe process execution, path handling, parser boundaries, resource exhaustion, and secret leakage. Report-only unless fixes are requested.
---

# SAST sweep

Read the architecture and security policy, then inspect the current manifests
to select analyzers; do not assume a language or directory that is not present.
Use maintained rules for the detected languages and record analyzer versions.

Prioritize:

- shell invocation, argument injection, environment inheritance, and executable
  resolution in scanner adapters;
- path traversal, symlink escape, unsafe temporary files, and archive extraction;
- unchecked parsing, integer/range conversion, panics across untrusted inputs,
  and unsafe Rust;
- missing bounds on concurrency, file sizes, subprocess output, and variants;
- matched credential material reaching logs or public artifacts;
- digest or identity checks performed after use rather than before it.

Triage every tool hit in context. Report severity, rule, file/line, data flow,
existing guard, and recommended regression test. Do not report a scanner's
failure to detect a fixture as a SAST issue.

