# ADR 0024 — Conservative compatibility report schema

Status: Accepted for local untrusted `.deb` inspection, schema version 1.

`dich inspect --json` emits a `compatibility_report` with `supported`, `unsupported`, or `review_required` and a bounded list of evidence records (`code`, optional package path, and detail). This report is evidence about the local archive only; the top-level trust stays `unverified` and `installable` stays false.

The schema includes all three states. `supported` is restricted to the standalone shared-object policy in ADR 0025; no package activation follows from that status. Explicit maintainer scripts, triggers, service units and selected host-mutating commands are `unsupported`; ambiguous paths, ELF dependencies, loader paths, symbol versions, configuration and related integration are `review_required`. The vocabulary is conservative but heuristic. Absence of a finding is not evidence of compatibility, and unknown behaviors may remain undetected. Findings are capped at 512 with an explicit truncation record; the status is still computed across all observations.

Acceptance covers JSON schema/status, representative unsupported and review-required packages, bounded finding count, and no script execution. This is not an installation permit, ABI proof, relocation plan or source-authenticity statement.
