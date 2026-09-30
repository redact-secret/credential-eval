---
name: dependency-audit
description: Audit credential-eval's Rust and optional JS/TS dependency graph for known vulnerabilities, provenance problems, and risky runtime capabilities. Use for dependency or supply-chain audits. Report-only unless fixes are requested.
---

# Dependency audit

Read `README.md`, `ARCHITECTURE.md`, and the current manifests/lockfiles.
Do not assume Cargo or npm files exist during the migration phase.

## Procedure

1. Inventory every manifest, lockfile, toolchain pin, vendored component, and
   scanner adapter dependency.
2. Use the ecosystem-native locked-graph audit tools that are installed (for
   example `cargo audit`/`cargo deny` and OSV-Scanner for Cargo, npm, or
   Python locks). Record tool versions and database timestamps.
3. Separate engine/runtime dependencies from development tooling and external
   scanners invoked through adapters.
4. For each finding, confirm reachability and whether the vulnerable capability
   is used in corpus parsing, process execution, archive handling, or output
   serialization.
5. Report exact package, locked version, advisory, reachability, severity, and
   the smallest compatible remediation.

Do not run or install arbitrary scanner packages merely to audit them. A
scanner executable's own vulnerabilities are not automatically vulnerabilities
of the evaluator; explain the trust boundary and invocation exposure.

