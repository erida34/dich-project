# ADR 0040 — Beta Testing Framework, Issue Triage Taxonomy, Threat Model Review, and Compatibility Limitations

Status: Accepted beta policy; external tester evidence remains pending.

## Context

Phase 7 of the Dich roadmap mandates:
> External beta testers, issue triage, threat model review, compatibility limitations explicit.

Dich is a security-first versioned package store. Ensuring long-term stability and user trust requires formalizing external feedback channels, defining a clear triage taxonomy for reported bugs, conducting a comprehensive review of the threat model and defense implementations, and making runtime compatibility boundaries transparent.

## Decision

### 1. External Beta Program and Feedback
- Establish clear guidelines for beta testers in `docs/beta-testing-and-triage.md`.
- Target key user scenarios: disposable rootless stores, authenticated single-source metadata, the explicitly supported single-root DSO closure, profile rollback, safe garbage collection, and concurrency behavior. Multi-source profile resolution is unsupported.
- Require structured bug reports with environment details, exact CLI invocations, reproducible test cases, machine-readable error codes, and redacted logs.

### 2. Issue Triage Taxonomy
Define an explicit four-tier priority taxonomy to guide maintainer attention. It is not a response or resolution SLA; the project makes no acknowledgement or fix-time guarantee during the experimental beta:
- **P0 - Critical Security**: Trust violations, signature bypass, path escapes, arbitrary code execution.
- **P1 - Data Corruption / Hang**: Database corruption, broken profile generations, GC deletion of live objects, deadlocks.
- **P2 - Resolver / Compatibility**: Incorrect behavior within the allowed DSO subset, resolver failures, valid control parse failures.
- **P3 - Minor / UX / Docs**: CLI formatting, documentation, non-blocking edge cases.
- Security vulnerabilities must be disclosed responsibly according to `SECURITY.md`.

### 3. Threat Model Review
Conduct and document a comprehensive threat review covering:
- Repository metadata integrity (GPG signatures, InRelease validation, digest chaining).
- Network and transport security (TLS enforcement, expiration checks, anti-rollback floor checks).
- Archive envelope and payload containment (`openat2` traversal restrictions, size/byte limits, rate limits, `prlimit` bounds).
- Package lifecycle isolation (maintainer scripts are never executed).
- Filesystem and database durability (0700/0600 modes, 0400 object trees, exclusive `flock`, WAL mode, `synchronous = FULL`).
- Host isolation (no modifications to host `/etc`, `/usr`, or `/var/lib/dpkg`).

An internal repository-grounded review is recorded in [`dich-project-threat-model.md`](../../dich-project-threat-model.md), dated 2026-11-04. It is not an independent penetration test. It identifies signing-key and release-tag compromise, same-UID state tampering, parser resource exhaustion and the limits of DSO symbol isolation. It assumes a single trusted operator pending confirmation. External beta results and issue-triage records remain outstanding.

### 4. Explicit Compatibility Boundaries
- Declare explicitly what Dich is and is not: Dich is **not** a general-purpose replacement for `dpkg`/`apt`, does **not** perform arbitrary binary relocation, and does **not** manage system services/daemons.
- The supported selection class is strictly bounded to authenticated **x86-64 glibc DSO closures** under ADR 0027/0029. A profile returns explicit object paths; the `dlmopen` fixture demonstrates symbol-namespace separation only, not a sandbox. Loading a DSO runs publisher code with caller privileges.
- Unsupported packages (maintainer scripts, system files, cross-distribution mixing, unauthenticated sources) fail closed with clear machine-readable diagnostic errors.

## Consequences

- Beta testers have a clear framework for exercising Dich safely and reporting issues effectively.
- Triage priorities ensure security and integrity defects receive immediate attention.
- Users are not misled by false assumptions regarding arbitrary `.deb` compatibility.
- GitHub private vulnerability reporting is enabled, so beta recruitment has a private disclosure route; `SECURITY.md` records that no separate maintainer email is configured.
